# mu_sim.py
from math import ceil
from random import randint, random
import asyncio
import json
import time
from dataclasses import dataclass
from typing import Any, Dict, Tuple, List, Optional, Set
import ipaddress
import struct
import argparse
from datetime import datetime

REQ_PORT = 5000
PX_GROUP = "239.1.1.1"  # can be any multicast-ish group IP you use as "cluster id"


def ts():
    return f"{time.perf_counter_ns():>18}"


def px_pack(group_ip_str: str, seq: int) -> bytes:
    group_ip = int(ipaddress.IPv4Address(group_ip_str))
    return struct.pack("!IH", group_ip, seq & 0xFFFF)  # 4 bytes + 2 bytes


def px_unpack(buf: bytes):
    if len(buf) < 6:
        raise ValueError("payload too short for px")
    group_ip_int, seq = struct.unpack("!IH", buf[:6])
    group_ip_str = str(ipaddress.IPv4Address(group_ip_int))
    return group_ip_str, seq, buf[6:]

def build_px_seq(leader_id: int, local_seq: int) -> int:
    leader_tag = leader_id & 0x7          # 3 bits (0..7)
    local_seq = local_seq & 0x1FFF        # 13 bits
    return (leader_tag << 13) | local_seq


# -----------------------------
# Data structures
# -----------------------------
@dataclass
class Slot:
    prop: int
    val: Any  # ["JOIN", group, host] or ["LEAVE", group, host] or any JSON-serializable payload


# ============================================================
# Replica (Mu follower / acceptor-like with permission gating)
# ============================================================
class MuReplica(asyncio.DatagramProtocol):
    def __init__(self, rid: int, bind: Tuple[str, int], peers: Dict[int, Tuple[str, int]]):
        self.id = rid
        self.bind = bind
        self.peers = peers

        # Mu log fields
        self.minProposal: int = 0  # smallest proposal number acceptable
        self.FUO: int = 0  # First Undecided Offset (leader-managed)
        self.slots: Dict[int, Slot] = {}  # slot index -> Slot(prop, val)

        # Permission model (Mu: only one writer at a time per replica)
        self.permission_holder: Optional[int] = None
        # set of leader ids that requested permission (serialized by permission_thread)
        self.permission_requests: Set[int] = set()
        # leader_id -> last req_id seen (used to include req_id in ACK)
        self.permission_request_ids: Dict[int, str] = {}
        # leader_id -> sender addr (bind) captured from PERM_REQ
        self.leader_addrs: Dict[int, Tuple[str, int]] = {}

        # Execution/apply state (for piggyback commit)
        self.transport: Optional[asyncio.DatagramTransport] = None
        self.last_executed: int = -1
        self.state: Dict[str, Set[str]] = {}  # group -> set(host)
        # heartbeat / liveness counter (pull-based)
        self.hb_counter = 0
        self.leader_last_seen = time.time()
        self.leader_timeout = 1.0

        self.seq_ctr = 0
        self.promised_ballot = -1
        self.permission_ballots: Dict[int, int] = {}

    # -----------------------------
    # Networking helpers
    # -----------------------------
    def _next_seq(self) -> int:
        self.seq_ctr = (self.seq_ctr + 1) & 0xFFFF
        return self.seq_ctr

    def sendto(self, addr, msg: dict):
        assert self.transport is not None
        seq = self._next_seq()
        local_seq = self._next_seq()
        seq = build_px_seq(self.id, local_seq)
        payload = px_pack(PX_GROUP, seq) + json.dumps(msg).encode()
        self.transport.sendto(payload, addr)

    def send(self, pid: int, msg: dict):
        self.sendto(self.peers[pid], msg)

    # -----------------------------
    # Application state machine
    # -----------------------------
    def apply_command(self, cmd: Any):
        if not isinstance(cmd, list) or len(cmd) < 3:
            return
        op, group, host = cmd[0], cmd[1], cmd[2]
        g = self.state.setdefault(group, set())
        if op == "JOIN":
            g.add(host)
        elif op == "LEAVE":
            g.discard(host)

    # -----------------------------
    # Asyncio callbacks
    # -----------------------------
    def on_leader_hb(self, msg):
        leader = int(msg["from"])
        if self.permission_holder == leader:
            self.last_leader_hb = time.time()

    def datagram_received(self, data, addr):
        try:
            _, _, rest = px_unpack(data)
            msg = json.loads(rest.decode())
        except Exception:
            return

        t = msg.get("t")
        if t == "PERM_REQ":
            self.on_perm_req(msg, addr)
        elif t == "READ":
            self.on_read(msg, addr)
        elif t == "WRITE":
            self.on_write(msg, addr)
        elif t == "LEADER_HB":
            self.on_leader_hb(msg)
        else:
            pass

    # -----------------------------
    # Permission handling (Mu)
    # -----------------------------
    def on_perm_req(self, msg, addr):
        # register a permission request (no immediate ACK)
        leader = int(msg["from"])
        req_id = msg.get("req_id")
        ballot = msg.get("ballot", -1)
        if not req_id:
            return
        if ballot < self.promised_ballot:
            print(f"[{ts()}] [replica {self.id}] REJECT PERM_REQ from {leader} req_id={req_id} (ballot={ballot} < promised_ballot={self.promised_ballot})")
            return
        print(f"[{ts()}] [replica {self.id}] ACCEPT PERM_REQ from {leader} req_id={req_id} ballot={ballot}")
        self.promised_ballot = ballot
        self.permission_requests.add(leader)
        self.permission_request_ids[leader] = req_id
        self.permission_ballots[leader] = ballot
        # capture the leader's bind/address so we reply to the correct address
        self.leader_addrs[leader] = tuple(addr)
        # track sender addr for potential debugging (not required; peers mapping used for replies)
        try:
            print(f"[{ts()}] [replica {self.id}] queued PERM_REQ from {leader} req_id={req_id}")
        except Exception:
            pass

    async def permission_thread(self):
        try:
            while True:
                if not self.permission_requests:
                    await asyncio.sleep(0.02)
                    continue

                winner = max(self.permission_requests, key=lambda l: self.permission_ballots[l])
                ballot = self.permission_ballots.get(winner)
                # compute req_id to ACK (last seen for that leader)
                req_id = self.permission_request_ids.get(winner)

                # grant permission (revokes previous holder implicitly)
                old = self.permission_holder
                if old is not None and old != winner:
                    print(
                        f"[{ts()}] [replica {self.id}] REVOKE permission from leader {old} -> leader {winner}"
                    )

                self.permission_holder = winner
                # reset heartbeat tracking for new holder

                try:
                    if old is None:
                        old_str = "None"
                    elif old == winner:
                        old_str = f"{old} (unchanged)"
                    else:
                        old_str = str(old)
                    print(
                        f"[{ts()}] [replica {self.id}] GRANTED PERMISSION to leader {winner} (prev={old_str}) req_id={req_id}"
                    )
                except Exception:
                    pass

                # send exactly one ACK for this grant to the leader's bind address
                if req_id is not None:
                    # reply to the captured leader bind address (set in on_perm_req)
                    reply_addr = self.leader_addrs.get(winner)
                    if reply_addr is not None:
                        self.sendto(
                            reply_addr,
                            {
                                "t": "PERM_ACK",
                                "from": self.id,
                                "ballot": ballot,
                                "req_id": req_id,
                            },
                        )

                # clear all pending requests (serialize handling)
                self.permission_requests.clear()
                self.permission_request_ids.clear()
                self.permission_ballots.clear()

        except asyncio.CancelledError:
            return

    # -----------------------------
    # Piggyback apply thread
    # -----------------------------
    async def commit_piggyback_thread(self, interval: float = 0.05):
        """
        Piggyback execution:
        - Let h be the highest non-empty slot index in local log.
        - Apply commands up to (h-1), contiguously, in order.
        This matches the paper paragraph: commit info is folded into the next replicated value.
        """
        try:
            while True:
                await asyncio.sleep(interval)

                if not self.slots:
                    continue

                target = self.FUO - 1
                if target < 0:
                    continue

                while self.last_executed < target:
                    nxt = self.last_executed + 1
                    s = self.slots.get(nxt)
                    if s is None:
                        break  # hole blocks execution
                    self.apply_command(s.val)
                    self.last_executed = nxt
                    print(f"[{ts()}] [replica {self.id}] executed slot {nxt} cmd={s.val}")

        except asyncio.CancelledError:
            return

    # -----------------------------
    # READ / WRITE "RDMA-like"
    # -----------------------------
    def on_read(self, msg, addr):
        key = msg.get("key")
        req_id = msg.get("req_id")

        if key == "minProposal":
            val = self.minProposal
        elif key == "hb":
            # heartbeat counter read for pull-score leader election
            val = self.hb_counter
        elif key == "FUO":
            val = self.FUO
        elif key == "permission_holder":
            val = self.permission_holder
        elif key == "last_executed":
            val = self.last_executed
        elif isinstance(key, list) and len(key) == 2 and key[0] == "slot":
            i = int(key[1])
            s = self.slots.get(i)
            val = None if s is None else [s.prop, s.val]
        else:
            self.sendto(
                addr,
                {
                    "t": "FAIL",
                    "from": self.id,
                    "req_id": req_id,
                    "reason": "bad_key",
                },
            )
            return

        self.sendto(addr, {"t": "OK", "from": self.id, "req_id": req_id, "val": val})

    async def hb_thread(self, interval: float = 0.2):
        """Increment local heartbeat counter periodically (pull-based liveness)."""
        try:
            while True:
                await asyncio.sleep(interval)
                # simple monotonic counter
                self.hb_counter += 1
                # print(f"[{ts()}] [replica {self.id}] HB increment → {self.hb_counter}")
                if random() < 0.05:
                    await asyncio.sleep(1.5)
        except asyncio.CancelledError:
            return

    async def leader_watchdog(self):
        try:
            while True:
                await asyncio.sleep(0.2)

                if self.permission_holder is None:
                    continue

                if time.time() - self.leader_last_seen > 1.0:
                    print(f"[{ts()}] [replica {self.id}] leader {self.permission_holder} timeout")
                    self.permission_holder = None
                    self.promised_ballot = -1
                    self.permission_requests.clear()
        except asyncio.CancelledError:
            return

    def on_write(self, msg, addr):
        src = int(msg.get("from", -1))
        req_id = msg.get("req_id")

        # permission check (Mu: only current permission holder can write)
        if self.permission_holder != src:
            print(
                f"[{ts()}] [replica {self.id}] DENY WRITE from leader {src} "
                f"(holder={self.permission_holder}) key={msg.get('key')}"
            )
            self.sendto(
                addr,
                {
                    "t": "FAIL",
                    "from": self.id,
                    "req_id": req_id,
                    "reason": "no_permission",
                    "holder": self.permission_holder,
                },
            )
            return

        key = msg.get("key")
        val = msg.get("val")

        if key == "minProposal":
            self.minProposal = int(val)
            self.sendto(addr, {"t": "OK", "from": self.id, "req_id": req_id})
            return

        if key == "FUO":
            # leader-managed FUO (Listing 4)
            new_fuo = int(val)
            # FUO should never go backwards in normal Mu
            if new_fuo < self.FUO:
                self.sendto(
                    addr,
                    {
                        "t": "FAIL",
                        "from": self.id,
                        "req_id": req_id,
                        "reason": "FUO_regression",
                    },
                )
                return
            self.FUO = new_fuo
            self.sendto(addr, {"t": "OK", "from": self.id, "req_id": req_id})
            return

        if key == "hb_leader":
            self.leader_last_seen = time.time()
            self.sendto(addr, {"t": "OK", "from": self.id, "req_id": req_id})
            return

        if isinstance(key, list) and len(key) == 2 and key[0] == "slot":
            i = int(key[1])
            prop = int(val[0])
            v = val[1]

            # --------- Fix #1: enforce minProposal promise ----------
            if prop < self.minProposal:
                self.sendto(
                    addr,
                    {
                        "t": "FAIL",
                        "from": self.id,
                        "req_id": req_id,
                        "reason": "below_minProposal",
                        "minProposal": self.minProposal,
                    },
                )
                return

            # --------- Fix #2: enforce slot-order writes (Mu invariant) ----------
            # Allow:
            # - writing at i == FUO (normal forward progress)
            # - rewriting existing i < FUO (recovery) if proposal is higher
            # Reject:
            # - creating a new slot at i > FUO (future hole)
            if i > self.FUO and i not in self.slots:
                self.sendto(
                    addr,
                    {
                        "t": "FAIL",
                        "from": self.id,
                        "req_id": req_id,
                        "reason": "out_of_order_slot",
                        "FUO": self.FUO,
                        "slot": i,
                    },
                )
                return

            cur = self.slots.get(i)
            if cur is None or prop >= cur.prop:
                self.slots[i] = Slot(prop=prop, val=v)

            self.sendto(addr, {"t": "OK", "from": self.id, "req_id": req_id})
            return

        self.sendto(
            addr, {"t": "FAIL", "from": self.id, "req_id": req_id, "reason": "bad_key"}
        )


# ============================================================
# Leader client (Mu proposer-like) — implements Propose
# ============================================================
class MuLeaderClient(asyncio.DatagramProtocol):
    def __init__(
        self,
        my_id: int,
        bind: Tuple[str, int],
        peers: Dict[int, Tuple[str, int]],
        local_replica: MuReplica,
    ):
        self.id = my_id
        self.bind = bind
        self.peers = peers
        self.N = len(peers)
        self.quorum = (self.N // 2) + 1
        self.replica = local_replica

        self.transport: Optional[asyncio.DatagramTransport] = None
        self.pending: Dict[str, asyncio.Future] = {}
        self.perm_waiters: Dict[str, asyncio.Queue] = {}
        self.req_ctr = 0

        # leader state
        self.confirmed: Set[int] = set()  # confirmed followers (permission-granted)
        self.myFUO: int = 0  # leader next index (protocol FUO)

        self.local_log: Dict[int, Tuple[int, Any]] = {}
        self.catchup_source: Optional[int] = None

        self.epoch = 0
        self.ballot = -1

        # election/pull-score state
        self.score_min = 0
        self.score_max = 15
        self.failure_threshold = 2
        self.recovery_threshold = 6
        self.scores = {pid: (self.score_max // 2) for pid in peers if pid != self.id}
        self._election_task = None
        self._hb_monitor_interval = 0.2

        self.seq_ctr = 0
        self.epoch = 0
        self.ballot = -1

        self.is_leader = False
        self.fast_path = False
        self.request_queue: asyncio.Queue = asyncio.Queue()
        

    # ------------- Transport hooks -------------

    def _next_seq(self) -> int:
        self.seq_ctr = (self.seq_ctr + 1) & 0xFFFF
        return self.seq_ctr

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        try:
            _, _, rest = px_unpack(data)
            msg = json.loads(rest.decode())
        except Exception:
            return

        t = msg.get("t")
        req_id = msg.get("req_id")

        # Permission ACK path
        if t == "PERM_ACK" and req_id:
            q = self.perm_waiters.get(req_id)
            if q is not None:
                q.put_nowait(msg)
            return

        # Generic RPC path
        if req_id and req_id in self.pending:
            fut = self.pending.pop(req_id)
            if not fut.done():
                fut.set_result(msg)

    # ------------- Helpers -------------
    def _rid(self) -> str:
        self.req_ctr += 1
        return f"{self.id}-{int(time.time() * 1000)}-{self.req_ctr}"

    def sendto(self, addr, msg: dict):
        assert self.transport is not None
        local_seq = self._next_seq()
        seq = build_px_seq(self.id, local_seq)
        payload = px_pack(PX_GROUP, seq) + json.dumps(msg).encode()
        self.transport.sendto(payload, addr)

    async def start(self):
        loop = asyncio.get_running_loop()
        self.transport, _ = await loop.create_datagram_endpoint(
            lambda: self, local_addr=self.bind
        )

    async def read_hb(self, pid: int) -> Optional[int]:
        r = await self.rpc(pid, {"t": "READ", "key": "hb"})
        if r.get("t") == "OK":
            try:
                return int(r["val"])
            except Exception:
                return None
        return None

    async def leader_main_loop(self):
        while self.is_leader:
            request = await self.request_queue.get()
            res = await self.propose(request)
            print(f"[{ts()}] [leader {self.id}] propose {request} → {res}")

    async def _inject_requests(self):
        #await asyncio.sleep(0.1)

        commands = [
            ["JOIN", "grp1", f"host-{self.id}"],
            ["JOIN", "grp2", f"host-{self.id}"],
            ["LEAVE", "grp1", f"host-{self.id}"],
            ["JOIN", "grp3", f"host-{self.id}"],
        ]
        for cmd in commands:
            if not self.is_leader:
                return
            print(f"[{ts()}] [leader {self.id}] injecting request {cmd}")
            await self.request_queue.put(cmd)
            await asyncio.sleep(2)


    async def election_thread(self, replica_proto: MuReplica, interval: float = 0.2):
        """Pull-score leader election: read heartbeat counters and maintain scores."""
        print(
            f"[{ts()}] [leader {self.id}]  starting election thread with initial scores: {self.scores}"
        )
        try:
            while True:
                await asyncio.sleep(interval)
                for pid in list(self.peers.keys()):
                    if pid == self.id:
                        continue
                    hb = await self.read_hb(pid)
                    if hb is None:
                        old_score = self.scores.get(pid, 0)
                        self.scores[pid] = max(self.score_min, old_score - 1)

                        #print(
                         #   f"[{ts()}] [leader {self.id}] read HB from {pid} = FAIL "
                         #   f"(score {old_score} → {self.scores[pid]})"
                        #)

                        continue
                    # compare with last seen stored in scores (we store a tuple in scores? use positive change)
                    # For simplicity, treat any read as 'updated' in this demo if hb increased since last stored value
                    # We'll keep last seen hb in a separate dict attached to this client
                    if not hasattr(self, "_last_hb_seen"):
                        self._last_hb_seen = {}
                    last = self._last_hb_seen.get(pid, -1)
                    old_score = self.scores.get(pid, 0)
                    if hb > last:
                        # increment score
                        new_score = min(
                            self.score_max, old_score + 1
                        )
                        self.scores[pid] = new_score
                        #print(
                        #    f"[{ts()}] [leader {self.id}] HB from {pid} advanced "
                        #    f"{last} → {hb} (score {old_score} → {self.scores[pid]})"
                        #)
                    else:
                        # decrement score
                        new_score = max(
                            self.score_min, old_score - 1
                        )   
                        self.scores[pid] = new_score
                        #print(
                        #    f"[{ts()}] [leader {self.id}] HB from {pid} stalled "
                        #    f"{last} → {hb} (score {old_score} → {self.scores[pid]})"
                        #)
                    self._last_hb_seen[pid] = hb

                alive = self.alive_replicas()
                #print(f"[{ts()}] [leader {self.id}] alive replicas = {alive}")
                if not alive:
                    continue

                elected = min(alive)
                #print(f"[{ts()}] [leader {self.id}] elected leader = {elected}")
                if elected == self.id:
                    if not self.is_leader:
                        print(f"[leader {self.id}] I am elected")
                        ok = await self.request_permissions()
                        if not ok:
                            self.is_leader = False
                            continue
                        
                        self.is_leader = True
                        asyncio.create_task(self.leader_heartbeat())
                        asyncio.create_task(self.leader_main_loop())
                        asyncio.create_task(self._inject_requests())

        except asyncio.CancelledError:
            return

    async def leader_heartbeat(self, interval=0.2):
        try:
            while self.is_leader:
                if not await self.still_have_permission():
                    self.is_leader = False
                    return
                self.replica.leader_last_seen = time.time()
                for pid in self.confirmed:
                    await self.rpc(
                        pid,
                        {
                            "t": "WRITE",
                            "key": "hb_leader",
                            "val": time.time(),
                        },
                    )
                await asyncio.sleep(interval)
        except asyncio.CancelledError:
            return

    async def rpc(self, pid: int, msg: dict, timeout: float = 0.5) -> dict:
        """
        UDP RPC with retry/backoff.
        Uses a new req_id per attempt to avoid late-reply confusion.
        """
        attempts = 3
        backoff = 0.02
        for attempt in range(attempts):
            req_id = self._rid()
            m = dict(msg)
            m["req_id"] = req_id
            m["from"] = self.id

            fut = asyncio.get_running_loop().create_future()
            self.pending[req_id] = fut

            self.sendto(self.peers[pid], m)
            try:
                return await asyncio.wait_for(fut, timeout)
            except asyncio.TimeoutError:
                self.pending.pop(req_id, None)
                if attempt < attempts - 1:
                    await asyncio.sleep(backoff * (2**attempt))

        return {"t": "TIMEOUT"}

    # ------------- Mu building blocks -------------
    def new_propnum(self, seen_max: int) -> int:
        self.epoch = max(self.epoch + 1, seen_max + 1)
        self.ballot = self.epoch * len(self.peers) + self.id
        return self.ballot

    def alive_replicas(self):
        return [pid for pid, score in self.scores.items() if score >= self.recovery_threshold] + [
            self.id
        ]

    async def request_permissions(self, timeout_total: float = 1.5) -> bool:
        self.confirmed.clear()

        req_id = self._rid()
        q = asyncio.Queue()
        self.perm_waiters[req_id] = q

        self.ballot = self.new_propnum(self.replica.minProposal)

        for pid in self.peers:
            if pid != self.id:
                self.sendto(
                    self.peers[pid],
                    {
                        "t": "PERM_REQ",
                        "ballot": self.ballot,
                        "from": self.id,
                        "req_id": req_id,
                    },
                )

        need = self.quorum - 1
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout_total

        try:
            # Phase 1: collect ACKs
            while len(self.confirmed) < need:
                remaining = deadline - loop.time()
                if remaining <= 0:
                    break

                try:
                    msg = await asyncio.wait_for(q.get(), timeout=remaining)
                except asyncio.TimeoutError:
                    break  # stop waiting, treat as failure

                rid = int(msg["from"])

                if msg.get("ballot") == self.ballot:
                    self.confirmed.add(rid)

            if len(self.confirmed) < need:
                return False

            # Phase 2: verify SAME replicas still grant permission
            holders = 0
            for pid in list(self.confirmed):
                r = await self.rpc(pid, {"t": "READ", "key": "permission_holder"})
                if r.get("t") == "OK" and r.get("val") == self.id:
                    holders += 1

            return holders >= need

        finally:
            self.perm_waiters.pop(req_id, None)

    async def read_slot(self, pid: int, i: int):
        r = await self.rpc(pid, {"t": "READ", "key": ["slot", i]})
        if r.get("t") == "OK":
            return r["val"]
        return "FAIL"

    async def write_slot(self, pid: int, i: int, prop: int, value: Any) -> bool:
        r = await self.rpc(
            pid, {"t": "WRITE", "key": ["slot", i], "val": [prop, value]}
        )
        if r.get("t") == "OK":
            return True

        if r.get("reason") == "no_permission":
            print(
                f"[{ts()}] [leader {self.id}] LOST PERMISSION on replica {pid}, aborting"
            )
            self.confirmed.clear()

        return False

    async def read_minProposal(self, pid: int) -> Optional[int]:
        r = await self.rpc(pid, {"t": "READ", "key": "minProposal"})
        if r.get("t") == "OK":
            return int(r["val"])
        return None

    async def write_minProposal(self, pid: int, prop: int) -> bool:
        # SELF write
        if pid == self.id:
            self.replica.minProposal = prop
            return True

        # REMOTE write
        r = await self.rpc(pid, {"t": "WRITE", "key": "minProposal", "val": prop})

        if r.get("t") == "OK":
            return True

        if r.get("reason") == "no_permission":
            print(
                f"[{ts()}] [leader {self.id}] LOST PERMISSION during PREPARE on replica {pid}"
            )
            self.confirmed.clear()

        return False

    async def read_FUO(self, pid: int) -> Optional[int]:
        r = await self.rpc(pid, {"t": "READ", "key": "FUO"})
        if r.get("t") == "OK":
            return int(r["val"])
        return None

    async def write_FUO(self, pid: int, fuo: int) -> bool:
        # SELF write
        if pid == self.id:
            if fuo < self.replica.FUO:
                return False
            self.replica.FUO = fuo
            return True

        # REMOTE write
        r = await self.rpc(pid, {"t": "WRITE", "key": "FUO", "val": fuo})

        if r.get("t") == "OK":
            return True

        if r.get("reason") == "no_permission":
            print(
                f"[{ts()}] [leader {self.id}] LOST PERMISSION during FUO update on replica {pid}"
            )
            self.confirmed.clear()

        return False

    async def still_have_permission(self) -> bool:
        for p in list(self.confirmed):
            r = await self.rpc(p, {"t": "READ", "key": "permission_holder"})
            if r.get("t") != "OK" or r.get("val") != self.id:
                print(f"[{ts()}] [leader {self.id}] LOST permission at replica {p}")
                return False
        return True

    # ------------- Listing 3: leader catch-up -------------
    async def leader_catch_up(self, confirmed: List[int]) -> bool:
        print(
            f"[{ts()}] [leader {self.id}] CATCH-UP begin "
            f"myFUO={self.myFUO} followers={confirmed}"
        )
        fuos: Dict[int, int] = {}
        for p in confirmed:
            v = await self.read_FUO(p)
            if v is None:
                return False
            fuos[p] = v

        if not fuos:
            return True

        F = max(fuos, key=lambda pid: fuos[pid])
        self.catchup_source = F
        max_fuo = fuos[F]
        if max_fuo == self.myFUO:
            return True
        print(
            f"[{ts()}] [leader {self.id}] CATCH-UP source={F} "
            f"maxFUO={max_fuo}"
        )
        if max_fuo > self.myFUO:
            # Copy F.LOG[myFUO : max_fuo]
            self.fast_path = False  # if we need catch-up, we can't trust fast path assumptions
            for i in range(self.myFUO, max_fuo):
                slot_val = await self.read_slot(F, i)
                if slot_val == "FAIL":
                    return False
                if slot_val is not None:
                    prop, val = int(slot_val[0]), slot_val[1]
                    self.local_log[i] = (prop, val)

            self.myFUO = max_fuo
            print(
                f"[{ts()}] [leader {self.id}] CATCH-UP done new_myFUO={self.myFUO}"
            )

        return True

    # ------------- Listing 4: update followers -------------
    async def update_followers(self, confirmed: List[int]) -> bool:
        print(
            f"[{ts()}] [leader {self.id}] UPDATE-FOLLOWERS begin "
            f"myFUO={self.myFUO} followers={confirmed}"
        )
        for p in confirmed:
            p_fuo = await self.read_FUO(p)
            if p_fuo is None:
                return False

            # Copy myLog[p.FUO : myFUO] into p.LOG
            for i in range(p_fuo, self.myFUO):
                if i not in self.local_log:
                    # pull from catchup_source if missing
                    F = self.catchup_source
                    if F is None:
                        return False
                    slot_val = await self.read_slot(F, i)
                    if slot_val in ("FAIL", None):
                        return False
                    prop, val = int(slot_val[0]), slot_val[1]
                    self.local_log[i] = (prop, val)

                prop, val = self.local_log[i]
                ok = await self.write_slot(p, i, prop, val)
                if not ok:
                    return False

            # Listing 4: p.FUO = myFUO
            ok = await self.write_FUO(p, self.myFUO)

            if not ok:
                return False
            print(
                f"[{ts()}] [leader {self.id}] UPDATE follower={p} "
                f"from FUO={p_fuo} → {self.myFUO}"
            )
        self.replica.FUO = self.myFUO
        return True

    # ------------- Full Propose (Mu basic + Listing 3/4) -------------
    async def propose(self, myValue: Any):
        print(
            f"[{ts()}] [leader {self.id}] PROPOSE start value={myValue} "
            f"myFUO={self.myFUO} confirmed={self.confirmed}"
        )
        # Must already be leader
        if not self.confirmed:
            self.fast_path = False
            return ("ABORT", "lost_permission")

        if not await self.still_have_permission():
                self.confirmed.clear()
                self.is_leader = False
                self.fast_path = False
                return ("ABORT", "lost_permission")

        # ---------- Phase 0: snapshot followers ----------
        confirmed = list(self.confirmed)

        # ---------- Listing 3: Leader catch-up ----------
        ok = await self.leader_catch_up(confirmed)
        if not ok:
            self.confirmed.clear()
            self.is_leader = False
            self.fast_path = False
            return ("ABORT", "leader_catch_up_failed")

        # ---------- Listing 4: Update followers ----------
        ok = await self.update_followers(confirmed)
        if not ok:
            self.confirmed.clear()
            self.is_leader = False
            self.fast_path = False
            return ("ABORT", "update_followers_failed")

      
        # ---------- Phase 1+: Mu propose loop ----------
        done = False
        slot_idx = None

        while not done:

            # Mu invariant: abort immediately if permission lost
            if not await self.still_have_permission():
                self.confirmed.clear()
                self.is_leader = False
                self.fast_path = False
                return ("ABORT", "lost_permission")

            # fresh snapshot per iteration
            confirmed = list(self.confirmed)

            # ----- Prepare phase -----
            if self.fast_path:
                propNum = self.new_propnum(self.replica.minProposal)
                value = myValue
            else:
                mins = []
                for p in confirmed + [self.id]:
                    if p == self.id:
                        mp = self.replica.minProposal
                    else:
                        mp = await self.read_minProposal(p)

                    if mp is None:
                        self.confirmed.clear()
                        self.is_leader = False
                        self.fast_path = False
                        return ("ABORT", "read_minProposal_failed")
                    print(
                    f"[{ts()}] [leader {self.id}] PREPARE read minProposal={mp} from follower {p}"
                    )

                    mins.append(mp)

                
                propNum = self.new_propnum(max(mins) if mins else 0)
                print(
                    f"[{ts()}] [leader {self.id}] PREPARE propose minProposal={propNum}"
                    )
                for p in confirmed + [self.id]:
                    ok = await self.write_minProposal(p, propNum)
                    if not ok:
                        self.confirmed.clear()
                        self.is_leader = False
                        self.fast_path = False
                        return ("ABORT", "write_minProposal_failed")

                reads = []
                for p in confirmed:
                    v = await self.read_slot(p, self.myFUO)
                    if v == "FAIL":
                        self.confirmed.clear()
                        self.is_leader = False
                        self.fast_path = False
                        return ("ABORT", "read_slot_failed")
                    reads.append(v)
                print(f"[{ts()}] [leader {self.id}] PREPARE read values={reads}")

                nonempty = [(x[0], x[1]) for x in reads if x is not None]
                if not nonempty:
                    print(f"[{ts()}] [leader {self.id}] FAST PATH ENABLED")
                    self.fast_path = True
                    value = myValue
                else:
                    value = max(nonempty, key=lambda t: int(t[0]))[1]
                
                print(f"[{ts()}] [leader {self.id}] PREPARE chosen value={value}")
            # ----- Accept phase -----
            slot_idx = self.myFUO
            for p in confirmed + [self.id]:
                if p == self.id:
                    # local accept
                    if propNum < self.replica.minProposal:
                        self.confirmed.clear()
                        self.is_leader = False
                        self.fast_path = False
                        return ("ABORT", "below_minProposal")

                    self.replica.slots[slot_idx] = Slot(prop=propNum, val=value)
                else:
                    ok = await self.write_slot(p, slot_idx, propNum, value)
                    if not ok:
                        self.confirmed.clear()
                        self.is_leader = False
                        self.fast_path = False
                        return ("ABORT", "write_slot_failed")

            print(f"[{ts()}] [leader {self.id}] ACCEPT success slot={slot_idx}")
            self.local_log[slot_idx] = (propNum, value)

            if value == myValue:
                done = True

            self.myFUO += 1
            #self.fast_path = False
            for p in confirmed + [self.id]:
                await self.write_FUO(p, self.myFUO) # self.id en tant que replica

        return ("OK", slot_idx)

    async def run(self, values_to_propose):
        """
        Full Mu leader lifecycle:
        - permission election
        - catch-up
        - propose loop
        - abort & retry
        """
        i = 0
        while True:
            print(f"[leader {self.id}] trying to acquire permissions...")
            ok = await self.request_permissions()
            if not ok:
                await asyncio.sleep(0.2)
                continue

            print(f"[{ts()}] [leader {self.id}] elected with followers {self.confirmed}")

            try:
                while i < len(values_to_propose):
                    v = values_to_propose[i]
                    print(f"[leader {self.id}] proposing {v}")
                    res = await self.propose(v)

                    if res[0] == "OK":
                        print(f"[leader {self.id}] committed at slot {res[1]}")
                        i += 1
                    else:
                        print(f"[leader {self.id}] abort: {res}")
                        break  # lost permission → re-elect

            except Exception as e:
                print(f"[leader {self.id}] crash: {e}")

                # stay leader until failure — do not immediately clear confirmed and re-elect
                # keep the task alive so heartbeats continue; exit only if an abort/exception occurs
                while True:
                    await asyncio.sleep(0.2)


def build_peers(peers_csv: str, port: int = REQ_PORT) -> Dict[int, Tuple[str, int]]:
    ips = [ip.strip() for ip in peers_csv.split(",") if ip.strip()]
    d: Dict[int, Tuple[str, int]] = {}
    for i, ip in enumerate(ips, start=1):
        d[i] = (ip, port)
    return d


async def main():
    # ---------------- Simulation parameters ----------------
    N = 4
    ips = [f"10.0.0.{i}" for i in range(1, N + 1)]
    peers = build_peers(",".join(ips), REQ_PORT)

    addr_to_pid = {peers[pid]: pid for pid in peers}

    # ---------------- Simulation network ----------------
    class SimulationNetwork:
        def __init__(self):
            self.replicas = {}
            self.leaders = {}

        def register_replica(self, pid, rep):
            self.replicas[pid] = rep

        def register_leader(self, pid, leader):
            self.leaders[pid] = leader

        def deliver(self, sender_pid, dest_addr, msg):
            dst = addr_to_pid.get(tuple(dest_addr))
            if dst is None:
                return

            # ---- leader destination ----
            if dst in self.leaders:
                l = self.leaders[dst]
                t = msg.get("t")
                req_id = msg.get("req_id")

                if t == "PERM_ACK" and req_id:
                    q = l.perm_waiters.get(req_id)
                    if q:
                        q.put_nowait(msg)
                    return

                if req_id and req_id in l.pending:
                    fut = l.pending.pop(req_id)
                    if not fut.done():
                        fut.set_result(msg)
                    return

            # ---- replica destination ----
            if dst in self.replicas:
                r = self.replicas[dst]
                t = msg.get("t")

                sender_addr = (
                    self.leaders[sender_pid].bind
                    if sender_pid in self.leaders
                    else peers[sender_pid]
                )

                if t == "PERM_REQ":
                    r.on_perm_req(msg, sender_addr)
                elif t == "READ":
                    r.on_read(msg, sender_addr)
                elif t == "WRITE":
                    r.on_write(msg, sender_addr)
                elif t == "LEADER_HB":
                    r.on_leader_hb(msg)

    sim = SimulationNetwork()

    async def concurrent_leader_storm(leaders):
        print("\n[TEST] === CONCURRENT LEADER STORM ===")

        async def try_lead(leader):
            try:
                ok = await leader.request_permissions()
                print(f"[TEST] leader {leader.id} request_permissions -> {ok}")
                return ok
            except Exception as e:
                print(f"[TEST] leader {leader.id} exception -> {e}")
                return False

        results = await asyncio.gather(
            *[try_lead(l) for l in leaders.values()], return_exceptions=False
        )

        return results

    def assert_mu_quorum_safety(replicas, leaders, quorum_size):
        """
        Mu safety invariant:
        At most ONE leader may hold permission on a quorum of replicas.
        """

        leader_quorum_counts = {}

        for leader_id in leaders:
            count = 0
            for r in replicas.values():
                if r.permission_holder == leader_id:
                    count += 1
            leader_quorum_counts[leader_id] = count

        # Print diagnostic info
        print("[TEST] permission counts per leader:")
        for lid, c in leader_quorum_counts.items():
            print(f"  leader {lid}: {c} replicas")

        # Leaders that *could* commit
        leaders_with_quorum = [
            lid for lid, c in leader_quorum_counts.items() if c >= quorum_size
        ]

        assert len(leaders_with_quorum) <= 1, (
            f"❌ Mu safety violation: multiple leaders have quorum permissions: "
            f"{leaders_with_quorum}"
        )

        print("✅ Mu quorum safety invariant holds\n")

    # ---------------- Create replicas ----------------
    replicas = {}
    replica_tasks = []

    for pid in peers:
        r = MuReplica(pid, peers[pid], peers)

        def make_rep_send(pid):
            def send(addr, msg, pid=pid):
                sim.deliver(pid, addr, msg)

            return send

        r.sendto = make_rep_send(pid)
        sim.register_replica(pid, r)
        replicas[pid] = r

        replica_tasks += [
            asyncio.create_task(r.permission_thread()),
            asyncio.create_task(r.commit_piggyback_thread()),
            asyncio.create_task(r.hb_thread()),
            asyncio.create_task(r.leader_watchdog()),
        ]

    print("[sim] replicas started")

    # ---------------- Create leaders ----------------
    leaders = {}
    leader_tasks = []

    for pid in peers:
        leader = MuLeaderClient(
            my_id=pid,
            bind=(peers[pid][0], 7000 + pid),
            peers=peers,
            local_replica=replicas[pid],
        )

        def make_leader_send(pid):
            def send(addr, msg, pid=pid):
                sim.deliver(pid, addr, msg)

            return send

        leader.sendto = make_leader_send(pid)
        sim.register_leader(pid, leader)
        addr_to_pid[(peers[pid][0], 7000 + pid)] = pid

        leaders[pid] = leader

        # start election thread for this leader
        leader_tasks.append(asyncio.create_task(leader.election_thread(replicas[pid])))

        # await concurrent_leader_storm(leaders)

        # assert_mu_quorum_safety(
        #    replicas=replicas,
        #    leaders=leaders.keys(),
        #    quorum_size=(len(replicas) // 2) + 1
        # )

    # ---------------- Run simulation ----------------
    await asyncio.sleep(11)

    # ---------------- Inspect final state ----------------
    print("\n[sim] final replica states:")
    for pid, r in replicas.items():
        print(
            f"[{ts()}] [replica {pid}] "
            f"FUO={r.FUO} "
            f"minProposal={r.minProposal} "
            f"last_executed={r.last_executed} "
            f"state={r.state}"
        )

    # ---------------- Cleanup ----------------
    for t in replica_tasks + leader_tasks:
        t.cancel()
    await asyncio.gather(*replica_tasks, *leader_tasks, return_exceptions=True)

    # Wait for tasks to complete with a timeout
    await asyncio.sleep(0.5)  # Give them time to cancel

    # Force exit
    print("[sim] simulation complete")
    raise SystemExit(0)  # Force exit


if __name__ == "__main__":
    asyncio.run(main())
