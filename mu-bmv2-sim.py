#mu_sim.py
from math import ceil
from random import randint, random
import asyncio, json, time
from dataclasses import dataclass
from typing import Any, Dict, Tuple, List, Optional, Set
import ipaddress, struct
import argparse
from datetime import datetime
import socket
from enum import Enum, auto
from scapy.all import Ether, IP, UDP, sendp, Raw, send, get_if_addr, get_if_hwaddr, sniff

REQ_PORT   = 5000   # optimized multicast (after discovery)
FLOOD_PORT = 5003   # PERM_REQ discovery flood
REPLY_PORT = 5004   # PERM_ACK
CTRL_PORT  = 5005   # READ/WRITE/OK/FAIL/hb_leader unicast
PX_GROUP = "239.1.1.1"  # can be any multicast-ish group IP you use as “cluster id”
NETWORK_PARTITION = None

def ip_to_mac(ip):
        host_id = int(ip.split(".")[-1])
        return f"08:00:00:00:01:{host_id:02x}"


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

class DpMaskState(Enum):
    IDLE = auto()
    DISCOVERING = auto()
    READY = auto()
# ============================================================
# Replica (Mu follower / acceptor-like with permission gating)
# ============================================================
class MuReplica:
    def __init__(self, rid: int, bind: Tuple[str, int], peers: Dict[int, Tuple[str, int]]):
        self.id = rid
        self.bind = bind
        self.peers = peers

        # Mu log fields
        self.minProposal: int = 0               # smallest proposal number acceptable
        self.FUO: int = 0                       # First Undecided Offset (leader-managed)
        self.slots: Dict[int, Slot] = {}        # slot index -> Slot(prop, val)

        # Permission model (Mu: only one writer at a time per replica)
        self.permission_holder: Optional[int] = None
        # set of leader ids that requested permission (serialized by permission_thread)
        self.permission_requests: Set[int] = set()
        # leader_id -> last req_id seen (used to include req_id in ACK)
        self.permission_request_ids: Dict[int, str] = {}
        # leader_id -> sender addr (bind) captured from PERM_REQ
        self.leader_addrs: Dict[int, Tuple[str, int]] = {}

        self.permission_request_px: Dict[int, Tuple[str, int]] = {}   # leader_id -> (group_ip, px_seq)
        # Execution/apply state (for piggyback commit)
        self.transport: Optional[asyncio.DatagramTransport] = None
        self.last_executed: int = -1
        self.state: Dict[str, Set[str]] = {}    # group -> set(host)
        # heartbeat / liveness counter (pull-based)
        self.hb_counter = 0
        self.leader_last_seen = time.time()
        self.leader_timeout = 1.0

        self.seq_ctr = 0
        self.promised_ballot = -1
        self.permission_ballots: Dict[int, int] = {}
        self.loop = asyncio.get_event_loop()
        #self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        #self.sock.bind(self.bind)
        #self.sock.setblocking(False)


    # -----------------------------
    # Networking helpers
    # -----------------------------
    async def start(self):
        loop = asyncio.get_running_loop()
        self.transport, _ = await loop.create_datagram_endpoint(
            lambda: self,
            local_addr=self.bind
        )

    def _next_seq(self) -> int:
        # 3 bits pour l'ID du noeud (max 8), 13 bits compteur
        # tag = 0..7 pour ids 1..8
        tag = ((self.id - 1) & 0x7)
        self.seq_ctr = (self.seq_ctr + 1) & 0x1FFF  # 13 bits
        return ((tag << 13) | self.seq_ctr) & 0xFFFF

    def ip_to_mac(ip):
        host_id = int(ip.split(".")[-1])
        return f"08:00:00:00:01:{host_id:02x}"

    def _handle_packet(self, pkt):
        if UDP not in pkt or IP not in pkt or Ether not in pkt:
            return

        my_ip = get_if_addr("eth0")
        my_mac = get_if_hwaddr("eth0").lower()

        # ignore self-sent packets (sendp is visible to sniff)
        if pkt[IP].src == my_ip:
            return
        if pkt[Ether].src.lower() == my_mac:
            return
        # For control traffic (CTRL_PORT), process only packets really addressed to me
        if pkt[UDP].dport == CTRL_PORT and pkt[IP].dst != my_ip:
            return
        try:
            data = bytes(pkt[UDP].payload)
            group, seq, rest = px_unpack(data)
            msg = json.loads(rest.decode())
        except Exception as e:
            print("Parse error:", e)
            return

        print("Replica received:", msg)

        t = msg.get("t")
        addr = (
            pkt[IP].src,
            pkt[UDP].sport,
            pkt[Ether].src
        )

        if t == "PERM_REQ":
            self.on_perm_req(msg, addr, group, seq)
        elif t == "READ":
            self.on_read(msg, addr)
        elif t == "WRITE":
            self.on_write(msg, addr)


    def start_sniffing(self):
        print("STARTING SNIFF ON", self.id)
        sniff(
            iface="eth0",
            prn=self._handle_packet,
            #filter=f"udp and (dst port {FLOOD_PORT} or dst port {REQ_PORT} or dst port {CTRL_PORT})",
            store=False
        )
        print("Replica sniffing started")

    def sendto(self, addr, msg, px_group: str = PX_GROUP, px_seq: Optional[int] = None):

        my_ip = get_if_addr("eth0")
        my_mac = get_if_hwaddr("eth0")

        dst_ip = addr[0]

        if len(addr) == 3:
            dst_mac = addr[2]
        else:
            dst_mac = "ff:ff:ff:ff:ff:ff"

        t = msg.get("t")

        if t == "PERM_REQ":
            dport = FLOOD_PORT
            dst_mac = "ff:ff:ff:ff:ff:ff"
            print("Replica sending PERM_REQ (FLOOD_PORT) to " + dst_ip)
        elif t == "PERM_ACK":
            dport = REPLY_PORT
            print("Replica sending PERM_ACK (REPLY_PORT)")
        elif t == "REQ_BCAST":
            dport = REQ_PORT
            dst_mac = "ff:ff:ff:ff:ff:ff"
            print("Replica sending REQ_BCAST (REQ_PORT optimized)")
        else:
            dport = CTRL_PORT   # READ/WRITE/OK/FAIL/hb_leader

        local_seq = self._next_seq()
        seq = build_px_seq(self.id, local_seq)
        wire_msg = dict(msg)
        if wire_msg.get("t") == "REQ_BCAST":
            wire_msg["t"] = wire_msg.pop("_inner_t", "WRITE")
        payload = px_pack(px_group, seq) + json.dumps(wire_msg).encode()

        pkt = (
            Ether(src=my_mac, dst=dst_mac) /
            IP(src=my_ip, dst=dst_ip) /
            UDP(sport=self.bind[1], dport=dport) /
            Raw(load=payload)
        )

        sendp(pkt, iface="eth0", verbose=False)



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
            self.leader_last_seen = time.time()

    def datagram_received(self, data, addr):
        try:
            _, _, rest = px_unpack(data)
            print("raw data:", data)
            msg = json.loads(rest.decode())
        except Exception as e:
            print("PX unpack error:", e)
            return
        print("Replica received:", msg)
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
    def on_perm_req(self, msg, addr, px_group=None, px_seq=None):
        leader = int(msg["from"])
        req_id = msg.get("req_id")
        ballot = msg.get("ballot", -1)

        if not req_id:
            return
        if ballot < self.promised_ballot:
            return

        def register_perm():
            # everything below now runs safely in asyncio thread
            if px_group is not None and px_seq is not None:
                self.permission_request_px[leader] = (px_group, int(px_seq))

            self.promised_ballot = ballot
            self.permission_requests.add(leader)
            self.permission_request_ids[leader] = req_id
            self.permission_ballots[leader] = ballot
            self.leader_addrs[leader] = tuple(addr)

            print(f"[{ts()}] [replica {self.id}] queued PERM_REQ from {leader} req_id={req_id}")

        self.loop.call_soon_threadsafe(register_perm)

    async def permission_thread(self):
        try:
            print(f"[replica {self.id}] permission_thread alive")
            while True:
                if not self.permission_requests:
                    await asyncio.sleep(0.02)
                    #print("self.permisison_requests is empty, waiting here...")
                    continue

                #if random() < 0.2:
                    #print(f"[{ts()}] [replica {self.id}] simulating delay in permission grant")
                    #await asyncio.sleep(0.3)

                # always pick the leader with the highest ballot (paper allows any deterministic rule)
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
                self.leader_last_seen = time.time()

                try:
                    if old is None:
                        old_str = "None"
                    elif old == winner:
                        old_str = f"{old} (unchanged)"
                    else:
                        old_str = str(old)
                    print(f"[{ts()}] [replica {self.id}] GRANTED PERMISSION to leader {winner} (prev={old_str}) req_id={req_id}")
                except Exception:
                    pass
                print("still in permission_thread about to enter to req_id if condition")
                if req_id is not None:
                    reply_addr = self.leader_addrs.get(winner)
                    print("reply_addr: ", reply_addr)
                    if reply_addr is not None:
                        entry = self.permission_request_px.get(winner)
                        if entry is None:
                            print("ERROR: no stored px_seq for leader", winner)
                            continue
                        px_group, px_seq = entry
                        print("PERM_ACK using px_seq =", px_seq)
                        self.sendto(
                            reply_addr,
                            {"t": "PERM_ACK", "from": self.id, "ballot": ballot, "req_id": req_id},
                            px_group=px_group,
                            px_seq=px_seq
                        )
                print("clearing everything...")
                # clear all pending requests (serialize handling)
                self.permission_requests.discard(winner)
                self.permission_request_ids.pop(winner, None)
                self.permission_ballots.pop(winner, None)
                self.permission_request_px.pop(winner, None)

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
    # READ / WRITE “RDMA-like”
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
            self.sendto(addr, {"t": "FAIL", "from": self.id, "req_id": req_id, "reason": "bad_key"})
            return

        self.sendto(addr, {"t": "OK", "from": self.id, "req_id": req_id, "val": val})

    async def hb_thread(self, interval: float = 0.2):
        """Increment local heartbeat counter periodically (pull-based liveness)."""
        try:
            while True:
                await asyncio.sleep(interval)
                # simple monotonic counter
                self.hb_counter += 1
                #print(f"[{ts()}] [replica {self.id}] HB increment → {self.hb_counter}")
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
                    self.permission_request_ids.clear()
                    self.permission_ballots.clear()
                    self.permission_request_px.clear()
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
            self.sendto(addr, {"t": "FAIL", "from": self.id, "req_id": req_id,
                               "reason": "no_permission", "holder": self.permission_holder})
            return

        key = msg.get("key")
        val = msg.get("val")

        if key == "minProposal":
            new_mp = int(val)
            if new_mp < self.minProposal:
                self.sendto(addr, {"t": "FAIL", "from": self.id, "req_id": req_id,
                                "reason": "minProposal_regression", "minProposal": self.minProposal})
                return
            self.minProposal = new_mp
            self.sendto(addr, {"t": "OK", "from": self.id, "req_id": req_id})
            return

        if key == "FUO":
            # leader-managed FUO (Listing 4)
            new_fuo = int(val)
            # FUO should never go backwards in normal Mu
            if new_fuo < self.FUO:
                self.sendto(addr, {"t": "FAIL", "from": self.id, "req_id": req_id, "reason": "FUO_regression"})
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
                self.sendto(addr, {"t": "FAIL", "from": self.id, "req_id": req_id,
                                   "reason": "below_minProposal", "minProposal": self.minProposal})
                return

            # --------- Fix #2: enforce slot-order writes (Mu invariant) ----------
            # Allow:
            # - writing at i == FUO (normal forward progress)
            # - rewriting existing i < FUO (recovery) if proposal is higher
            # Reject:
            # - creating a new slot at i > FUO (future hole)
            if i > self.FUO and i not in self.slots:
                self.sendto(addr, {"t": "FAIL", "from": self.id, "req_id": req_id,
                                   "reason": "out_of_order_slot", "FUO": self.FUO, "slot": i})
                return
            cur = self.slots.get(i)
            if cur is not None and prop < cur.prop:
                self.sendto(addr, {"t": "FAIL", "from": self.id, "req_id": req_id,
                                "reason": "slot_has_higher_prop", "cur_prop": cur.prop})
                return

            self.slots[i] = Slot(prop=prop, val=v)
            self.sendto(addr, {"t": "OK", "from": self.id, "req_id": req_id})
            return

        self.sendto(addr, {"t": "FAIL", "from": self.id, "req_id": req_id, "reason": "bad_key"})



# ============================================================
# Leader client (Mu proposer-like) — implements Propose
# ============================================================
class MuLeaderClient:
    def __init__(self, my_id: int, bind: Tuple[str, int], peers: Dict[int, Tuple[str, int]], local_replica: MuReplica):
        self.id = my_id
        self.bind = bind
        self.peers = peers
        self.N = len(peers)
        self.quorum = (self.N // 2) + 1
        self.replica = local_replica

        self.transport: Optional[asyncio.DatagramTransport] = None
        self.pending: Dict[str, asyncio.Future] = {}
        self.perm_waiters: Dict[str, asyncio.Queue] = {}
        self.bcast_waiters: Dict[str, asyncio.Queue] = {}
        self.req_ctr = 0

        # leader state
        self.confirmed: Set[int] = set()     # confirmed followers (permission-granted)
        self.myFUO: int = 0                  # leader next index (protocol FUO)

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
        self._leader_hb_task: Optional[asyncio.Task] = None

        # Data-plane optimized multicast state
        self.dp_state = DpMaskState.IDLE
        self.dp_mask_ready = False
        self.dp_group = PX_GROUP
        self.dp_permreq_seq: Optional[int] = None   # seq used for the last PERM_REQ flood

        self.loop = asyncio.get_event_loop()

    # ------------- Transport hooks -------------
    def _next_seq(self) -> int:
        # 3 bits pour l'ID du noeud (max 8), 13 bits compteur
        # tag = 0..7 pour ids 1..8
        tag = ((self.id - 1) & 0x7)
        self.seq_ctr = (self.seq_ctr + 1) & 0x1FFF  # 13 bits
        return ((tag << 13) | self.seq_ctr) & 0xFFFF

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        try:
            _, _, rest = px_unpack(data)
            msg = json.loads(rest.decode())
            print("raw data:", data)
        except Exception as e:
            print("PX unpack error:", e)
            return

        t = msg.get("t")
        req_id = msg.get("req_id")
        print("Received:", msg)
        # Permission ACK path
       
        if t == "PERM_ACK" and req_id:
            q = self.perm_waiters.get(req_id)
            if q is not None:
                q.put_nowait(msg)
            return

        if req_id and req_id in self.bcast_waiters and t in ("OK", "FAIL"):
            q = self.bcast_waiters[req_id]
            q.put_nowait(msg)
            return

        # Generic RPC path
        if req_id and req_id in self.pending:
            fut = self.pending.pop(req_id)
            if not fut.done():
                fut.set_result(msg)


    def _rid(self) -> str:
        self.req_ctr += 1
        return f"{self.id}-{int(time.time() * 1000)}-{self.req_ctr}"


    def ip_to_mac(ip):
        host_id = int(ip.split(".")[-1])
        return f"08:00:00:00:01:{host_id:02x}"


    def _handle_packet(self, pkt):
        if UDP not in pkt or IP not in pkt or Ether not in pkt:
            return

        my_ip = get_if_addr("eth0")
        my_mac = get_if_hwaddr("eth0").lower()

        # IMPORTANT: ignore self-sent packets (sendp is visible to sniff)
        if pkt[IP].src == my_ip:
            return
        if pkt[Ether].src.lower() == my_mac:
            return
        if pkt[UDP].dport == CTRL_PORT and pkt[IP].dst != my_ip:
            return
        try:
            data = bytes(pkt[UDP].payload)
            _, _, rest = px_unpack(data)
            msg = json.loads(rest.decode())
        except Exception as e:
            print("Leader parse error:", e)
            return

        t = msg.get("t")
        req_id = msg.get("req_id")
        print("Leader received:", msg)


        # 1) Permission ACK path
        if t == "PERM_ACK" and req_id:
            q = self.perm_waiters.get(req_id)
            if q is not None:
                self.loop.call_soon_threadsafe(q.put_nowait, msg)
            return

        # 2) Broadcast RPC replies path (multi-reply)
        if req_id and req_id in self.bcast_waiters and t in ("OK", "FAIL"):
            q = self.bcast_waiters[req_id]
            self.loop.call_soon_threadsafe(q.put_nowait, msg)
            return

        # 2) Generic RPC replies path (OK / FAIL / TIMEOUT-like replies)
        if req_id and req_id in self.pending:
            fut = self.pending.pop(req_id)
            if not fut.done():
                self.loop.call_soon_threadsafe(fut.set_result, msg)


    async def bcast_write_followers(self, followers: List[int], key: Any, val: Any, timeout: float = 0.4) -> bool:
        """
        Broadcast one WRITE over REQ_PORT and collect replies from the expected follower set.
        Assumes P4 active mask currently corresponds to the permission-confirmed followers.
        """
        if not followers:
            return True

        if not (self.dp_mask_ready and self.dp_state == DpMaskState.READY):
            # fallback to unicast
            for p in followers:
                r = await self.rpc(p, {"t": "WRITE", "key": key, "val": val})
                if r.get("t") != "OK":
                    self._clear_leadership_state()
                    return False
            return True

        req_id = self._rid()
        q = asyncio.Queue()
        self.bcast_waiters[req_id] = q

        expected = set(followers)
        got_ok: Set[int] = set()

        try:
            # Send one optimized multicast request (wrapped as REQ_BCAST -> WRITE on wire)
            self.send_req_broadcast({
                "t": "WRITE",
                "key": key,
                "val": val,
                "req_id": req_id,
                "from": self.id
            })

            deadline = asyncio.get_running_loop().time() + timeout

            while got_ok != expected:
                remaining = deadline - asyncio.get_running_loop().time()
                if remaining <= 0:
                    # timeout => treat as failure
                    self._clear_leadership_state()
                    return False

                try:
                    msg = await asyncio.wait_for(q.get(), timeout=remaining)
                except asyncio.TimeoutError:
                    self._clear_leadership_state()
                    return False

                rid = int(msg.get("from", -1))
                if rid not in expected:
                    continue

                if msg.get("t") == "FAIL":
                    # permission loss or slot/order violation, etc.
                    if msg.get("reason") == "no_permission":
                        print(f"[{ts()}] [leader {self.id}] LOST PERMISSION during bcast WRITE (replica {rid})")
                    self._clear_leadership_state()
                    return False

                if msg.get("t") == "OK":
                    got_ok.add(rid)

            return True

        finally:
            self.bcast_waiters.pop(req_id, None)

    def start_sniffing(self):
        print("STARTING SNIFF ON", self.id)
        sniff(
            iface="eth0",
            prn=self._handle_packet,
            #filter=f"udp and (dst port {REPLY_PORT} or dst port {CTRL_PORT})",
            store=False
        )
        print("Leader sniffing started")

    def sendto(self, addr, msg, px_group: str = PX_GROUP, px_seq: Optional[int] = None):

        my_ip = get_if_addr("eth0")
        my_mac = get_if_hwaddr("eth0")

        dst_ip = addr[0]

        # If MAC is known (reply case)
        if len(addr) == 3:
            dst_mac = addr[2]
        else:
            dst_mac = "ff:ff:ff:ff:ff:ff"

        t = msg.get("t")

        # --- Port mapping ---
        if t == "PERM_REQ":
            dport = FLOOD_PORT
            dst_mac = "ff:ff:ff:ff:ff:ff"   # discovery flood
            print("Leader sending PERM_REQ (FLOOD_PORT)")
        elif t == "PERM_ACK":
            dport = REPLY_PORT
            print("Leader sending PERM_ACK (REPLY_PORT)")
        elif t == "REQ_BCAST":
            # internal type for optimized multicast via P4 mask
            dport = REQ_PORT
            dst_mac = "ff:ff:ff:ff:ff:ff"
            print("Leader sending REQ_BCAST (REQ_PORT optimized)")
        else:
            # READ / WRITE / OK / FAIL / hb_leader => control unicast
            dport = CTRL_PORT

        local_seq = self._next_seq()
        seq = build_px_seq(self.id, local_seq)

        # If we used the internal wrapper type REQ_BCAST, convert to actual payload type
        wire_msg = dict(msg)
        if wire_msg.get("t") == "REQ_BCAST":
            wire_msg["t"] = wire_msg.pop("_inner_t", "WRITE")

        payload = px_pack(px_group, seq) + json.dumps(wire_msg).encode()
      
        pkt = (
            Ether(src=my_mac, dst=dst_mac) /
            IP(src=my_ip, dst=dst_ip) /
            UDP(sport=self.bind[1], dport=dport) /
            Raw(load=payload)
        )

        sendp(pkt, iface="eth0", verbose=False)

    async def start(self):
        loop = asyncio.get_running_loop()
        self.transport, _ = await loop.create_datagram_endpoint(
            lambda: self,
            local_addr=self.bind
        )

    async def read_hb(self, pid: int) -> Optional[int]:
        r = await self.rpc(pid, {"t": "READ", "key": "hb"})
        if r.get("t") == "OK":
            try:
                return int(r["val"])
            except Exception:
                return None

        return None

    async def election_thread(self, replica_proto: MuReplica, interval: float = 0.2):
        """Pull-score leader election: read heartbeat counters and maintain scores."""
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

                        #print(f"[{ts()}] [leader {self.id}] read HB from {pid} = FAIL "
                        #      f"(score {old_score} → {self.scores[pid]})")

                        continue
                    # compare with last seen stored in scores (we store a tuple in scores? use positive change)
                    # For simplicity, treat any read as 'updated' in this demo if hb increased since last stored value
                    # We'll keep last seen hb in a separate dict attached to this client
                    if not hasattr(self, '_last_hb_seen'):
                        self._last_hb_seen = {}
                    last = self._last_hb_seen.get(pid, -1)
                    old_score = self.scores.get(pid, 0)
                    if hb > last:
                        # increment score
                        self.scores[pid] = min(self.score_max, self.scores.get(pid, 0) + 1)
                        #print(f"[{ts()}] [leader {self.id}] HB from {pid} advanced "
                              #f"{last} → {hb} (score {old_score} → {self.scores[pid]})")
                    else:
                        # decrement score
                        self.scores[pid] = max(self.score_min, self.scores.get(pid, 0) - 1)
                        #print(f"[{ts()}] [leader {self.id}] HB from {pid} stalled "
                        #      f"{last} → {hb} (score {old_score} → {self.scores[pid]})")
                    self._last_hb_seen[pid] = hb


                alive = self.alive_replicas()
                #print(f"[{ts()}] [leader {self.id}] alive replicas = {alive}")
                if not alive:
                    continue

                elected = min(alive)
                #print(f"[{ts()}] [leader {self.id}] elected leader = {elected}")
                if elected != self.id and self.is_leader:
                    print(f"[leader {self.id}] stepping down; elected={elected}")
                    self._clear_leadership_state()
                if elected == self.id:
                    if not self.is_leader:
                        print(f"[leader {self.id}] I am elected")
                        ok = await self.request_permissions()
                        if not ok:
                            self.is_leader = False
                            continue
                        if self._leader_hb_task is None or self._leader_hb_task.done():
                            self._leader_hb_task = asyncio.create_task(self.leader_heartbeat())
                    self.is_leader = True


                if self.is_leader:
                        # we got a quorum; schedule a demo propose in background
                        try:
                            try:
                                request = await asyncio.wait_for(self.request_queue.get(), timeout=0.2)
                            except asyncio.TimeoutError:
                                continue
                            res = await self.propose(request)
                            if res[0] != "OK":
                                # optional: requeue request so it isn't lost
                                await self.request_queue.put(request)
                        except Exception as e:
                            print(f"[leader {self.id}] propose/election error: {e}")
                        # back off to avoid busy retry
                        await asyncio.sleep(1.0)
        except asyncio.CancelledError:
            return

    async def leader_heartbeat(self, interval=0.2):
        try:
            while self.is_leader:
                if not await self.still_have_permission():
                    self.is_leader = False
                    return
                #if self.replica.permission_holder == self.id:
                #    self.replica.leader_last_seen = time.time()
                for pid in list(self.confirmed):
                    await self.rpc(pid, {
                        "t": "WRITE",
                        "key": "hb_leader",
                        "val": time.time()
                    })
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
                    await asyncio.sleep(backoff * (2 ** attempt))

        return {"t": "TIMEOUT"}

    # ------------- Mu building blocks -------------
    def new_propnum(self, seen_max: int) -> int:
        self.epoch = max(self.epoch + 1, seen_max + 1)
        self.ballot = self.epoch * len(self.peers) + self.id
        return self.ballot

    def alive_replicas(self):
        return [
            pid for pid, score in self.scores.items()
            if score >= self.recovery_threshold
        ] + [self.id]

    async def request_permissions(self, timeout_total: float = 1.5) -> bool:
        self._clear_leadership_state()

        req_id = self._rid()
        q = asyncio.Queue()
        self.perm_waiters[req_id] = q

        self.ballot = self.new_propnum(self.replica.minProposal)
        self.dp_state = DpMaskState.DISCOVERING
        self.dp_mask_ready = False

        self.replica.promised_ballot = max(self.replica.promised_ballot, self.ballot)
        self.replica.permission_holder = self.id
        self.replica.leader_last_seen = time.time()
        # One seq for this discovery round (P4 REPLY checks exact seq)
        self.dp_permreq_seq = self._next_seq()
        print(f"[LEADER {self.id}] PERM_REQ using px_seq = {self.dp_permreq_seq}")
        #for pid in self.peers:
         #   if pid != self.id:
          #      self.sendto(self.peers[pid], {
          #          "t": "PERM_REQ",
          #          "ballot": self.ballot,
          #          "from": self.id,
          #          "req_id": req_id
          #      }, px_group=self.dp_group, px_seq=self.dp_permreq_seq)
        dst = next((self.peers[pid] for pid in self.peers if pid != self.id), None)
        if dst is None:
            return False

        self.sendto(dst, {
            "t": "PERM_REQ",
            "ballot": self.ballot,
            "from": self.id,
            "req_id": req_id
        }, px_group=self.dp_group, px_seq=self.dp_permreq_seq)
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
                    break   # stop waiting, treat as failure

                rid = int(msg["from"])


                if msg.get("ballot") == self.ballot:
                    self.confirmed.add(rid)

            if len(self.confirmed) < need:
                return False

            # Phase 2: verify SAME replicas still grant permission
            holders_set = set()
            for pid in list(self.confirmed):
                r = await self.rpc(pid, {"t": "READ", "key": "permission_holder"})
                if r.get("t") == "OK" and r.get("val") == self.id:
                    holders_set.add(pid)

            if len(holders_set) >= need:
                self.confirmed = holders_set
                self.dp_state = DpMaskState.READY
                self.dp_mask_ready = True
                ok = True
            else:
                self.dp_state = DpMaskState.IDLE
                self.dp_mask_ready = False
                ok = False
            return ok

        finally:
            self.perm_waiters.pop(req_id, None)
            if not self.dp_mask_ready:
                self.dp_state = DpMaskState.IDLE

    def send_req_broadcast(self, msg: dict, px_group: str = PX_GROUP):
        if not self.dp_mask_ready or self.dp_state != DpMaskState.READY:
            raise RuntimeError("P4 active mask not ready yet; run PERM_REQ/PERM_ACK first")

        some_peer = next((self.peers[pid] for pid in self.peers if pid != self.id), self.peers[self.id])

        wrapped = dict(msg)
        wrapped["_inner_t"] = wrapped.get("t", "WRITE")  # preserve original type
        wrapped["t"] = "REQ_BCAST"                       # force wrapper type

        self.sendto(some_peer, wrapped, px_group=px_group)

    async def read_slot(self, pid: int, i: int):
        r = await self.rpc(pid, {"t": "READ", "key": ["slot", i]})
        if r.get("t") == "OK":
            return r["val"]
        self._clear_leadership_state()
        return "FAIL"

    async def write_slot(self, pid: int, i: int, prop: int, value: Any) -> bool:
        r = await self.rpc(pid, {"t": "WRITE", "key": ["slot", i], "val": [prop, value]})
        if r.get("t") == "OK":
            return True

        if r.get("reason") == "no_permission":
            print(
                f"[{ts()}] [leader {self.id}] LOST PERMISSION on replica {pid}, aborting"
            )
            self._clear_leadership_state()
        self._clear_leadership_state()
        return False

    async def read_minProposal(self, pid: int) -> Optional[int]:
        r = await self.rpc(pid, {"t": "READ", "key": "minProposal"})
        if r.get("t") == "OK":
            return int(r["val"])
        self._clear_leadership_state()
        return None

    async def write_minProposal(self, pid: int, prop: int) -> bool:
        # SELF write
        if pid == self.id:
            self.replica.minProposal = prop
            return True

        # REMOTE write
        r = await self.rpc(pid, {
            "t": "WRITE",
            "key": "minProposal",
            "val": prop
        })

        if r.get("t") == "OK":
            return True

        if r.get("reason") == "no_permission":
            print(f"[{ts()}] [leader {self.id}] LOST PERMISSION during PREPARE on replica {pid}")
            self._clear_leadership_state()

        self._clear_leadership_state()
        return False


    async def read_FUO(self, pid: int) -> Optional[int]:
        r = await self.rpc(pid, {"t": "READ", "key": "FUO"})
        if r.get("t") == "OK":
            return int(r["val"])
        self._clear_leadership_state()
        return None

    async def write_FUO(self, pid: int, fuo: int) -> bool:
        # SELF write
        if pid == self.id:
            if fuo < self.replica.FUO:
                return False
            self.replica.FUO = fuo
            return True

        # REMOTE write
        r = await self.rpc(pid, {
            "t": "WRITE",
            "key": "FUO",
            "val": fuo
        })

        if r.get("t") == "OK":
            return True

        if r.get("reason") == "no_permission":
            print(f"[{ts()}] [leader {self.id}] LOST PERMISSION during FUO update on replica {pid}")
            self._clear_leadership_state()
        self._clear_leadership_state()
        return False

    def _clear_leadership_state(self):
        self.confirmed.clear()
        self.is_leader = False
        self.fast_path = False
        self.dp_state = DpMaskState.IDLE
        self.dp_mask_ready = False
        self.dp_permreq_seq = None

    async def still_have_permission(self) -> bool:
        if self.replica.permission_holder != self.id:
            self._clear_leadership_state()
            print(f"[{ts()}] [leader {self.id}] LOST permission locally")
            return False
        for p in list(self.confirmed):
            r = await self.rpc(p, {"t": "READ", "key": "permission_holder"})
            if r.get("t") != "OK" or r.get("val") != self.id:
                self._clear_leadership_state()
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
        print(
            f"[{ts()}] [leader {self.id}] CATCH-UP source={F} "
            f"maxFUO={max_fuo}"
        )
        if max_fuo > self.myFUO:
            # Copy F.LOG[myFUO : max_fuo]
            self.fast_path = False # if we need catch-up, we can't trust fast path anymore this epoch
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

        # ---------- Phase 0: snapshot followers ----------
        confirmed = list(self.confirmed)

        # ---------- Listing 3: Leader catch-up ----------
        ok = await self.leader_catch_up(confirmed)
        if not ok:
            self._clear_leadership_state()
            return ("ABORT", "leader_catch_up_failed")

        if not await self.still_have_permission():
            self._clear_leadership_state()
            return ("ABORT", "lost_permission")

        # ---------- Listing 4: Update followers ----------
        ok = await self.update_followers(confirmed)
        if not ok:
            self._clear_leadership_state()
            return ("ABORT", "update_followers_failed")

        if not await self.still_have_permission():
            self._clear_leadership_state()
            return ("ABORT", "lost_permission")

        # ---------- Phase 1+: Mu propose loop ----------
        done = False
        slot_idx = None

        while not done:

            # Mu invariant: abort immediately if permission lost
            if not await self.still_have_permission():
                self._clear_leadership_state()
                return ("ABORT", "lost_permission")

            # fresh snapshot per iteration
            confirmed = list(self.confirmed)

            # ----------------- Prepare phase -----------------

            # ----- FAST PATH CHECK -----
            if self.fast_path:
                propNum = self.new_propnum(self.replica.minProposal)
                value = myValue
            else:
                # ----- Prepare phase ----- (READ mins first)
                mins = []
                for p in confirmed + [self.id]:
                    if p == self.id:
                        mp = self.replica.minProposal
                    else:
                        mp = await self.read_minProposal(p)

                    if mp is None:
                        self._clear_leadership_state()
                        return ("ABORT", "read_minProposal_failed")

                    mins.append(mp)

                propNum = self.new_propnum(max(mins) if mins else 0)

                # self write
                self.replica.minProposal = propNum

                # followers write (optimized broadcast)
                ok = await self.bcast_write_followers(
                    followers=confirmed,
                    key="minProposal",
                    val=propNum
                )
                if not ok:
                    return ("ABORT", "write_minProposal_failed")

                # read slot at myFUO from followers
                reads = []
                for p in confirmed:
                    v = await self.read_slot(p, self.myFUO)
                    if v == "FAIL":
                        self._clear_leadership_state()
                        return ("ABORT", "read_slot_failed")
                    reads.append(v)

                nonempty = [(x[0], x[1]) for x in reads if x is not None]

                if not nonempty:
                    print(f"[{ts()}] [leader {self.id}] FAST PATH ENABLED")
                    self.fast_path = True
                    value = myValue
                else:
                    value = max(nonempty, key=lambda t: int(t[0]))[1]

                print("values read at slot {}: {}".format(self.myFUO, reads))

            # ----- Accept phase -----
            slot_idx = self.myFUO

            # local accept first
            if propNum < self.replica.minProposal:
                self._clear_leadership_state()
                return ("ABORT", "below_minProposal")


            cur = self.replica.slots.get(slot_idx)
            if cur is not None and propNum < cur.prop:
                self._clear_leadership_state()
                return ("ABORT", "local_slot_has_higher_prop")
            self.replica.slots[slot_idx] = Slot(prop=propNum, val=value)
            # remote accepts: optimized broadcast over REQ_PORT (once)
            ok = await self.bcast_write_followers(
                followers=confirmed,
                key=["slot", slot_idx],
                val=[propNum, value]
            )
            if not ok:
                return ("ABORT", "write_slot_failed")

            print(
                f"[{ts()}] [leader {self.id}] ACCEPT success slot={slot_idx}"
            )
            self.local_log[slot_idx] = (propNum, value)

            if value == myValue:
                done = True

            self.myFUO += 1
            #self.fast_path = False

            # self
            if self.myFUO < self.replica.FUO:
                self._clear_leadership_state()
                return ("ABORT", "FUO_regression_local")
            self.replica.FUO = self.myFUO

            # followers (broadcast once)
            ok = await self.bcast_write_followers(
                followers=confirmed,
                key="FUO",
                val=self.myFUO
            )
            if not ok:
                return ("ABORT", "write_FUO_failed")

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
                        break   # lost permission → re-elect

            except Exception as e:
                print(f"[leader {self.id}] crash: {e}")

                # stay leader until failure — do not immediately clear confirmed and re-elect
                # keep the task alive so heartbeats continue; exit only if an abort/exception occurs
                while True:
                    await asyncio.sleep(0.2)


def build_peers(peers_csv: str, port: int = REQ_PORT) -> Dict[int, Tuple[str,int]]:
    ips = [ip.strip() for ip in peers_csv.split(",") if ip.strip()]
    d: Dict[int, Tuple[str,int]] = {}
    for i, ip in enumerate(ips, start=1):
        d[i] = (ip, port)
    return d

async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--id", type=int, required=True,
                        help="Replica/Leader ID (1..N)")
    parser.add_argument("--peers", type=str, required=True,
                        help="Comma-separated peer IPs (e.g. 10.0.0.1,10.0.0.2,...)")
    args = parser.parse_args()

    my_id = args.id
    peers = build_peers(args.peers, REQ_PORT)

    if my_id not in peers:
        print("Invalid ID")
        return

    print(f"[node {my_id}] starting...")
    print(f"[node {my_id}] bind={peers[my_id]}")
    print(f"[node {my_id}] peers={peers}")

    # -----------------------------
    # Create Replica
    # -----------------------------
    replica = MuReplica(
        rid=my_id,
        bind=peers[my_id],
        peers=peers
    )

    # -----------------------------
    # Create Leader client
    # -----------------------------
    leader = MuLeaderClient(
        my_id=my_id,
        bind=(peers[my_id][0], 7000 + my_id),
        peers=peers,
        local_replica=replica
    )
    #await leader.start()
    #await replica.start()
    loop = asyncio.get_running_loop()
    replica.loop = loop
    leader.loop = loop
    # -----------------------------
    # Start recv loops
    # -----------------------------
    tasks = []

    #tasks.append(asyncio.create_task(replica.recv_loop()))
    tasks.append(asyncio.create_task(replica.permission_thread()))
    tasks.append(asyncio.create_task(replica.commit_piggyback_thread()))
    tasks.append(asyncio.create_task(replica.hb_thread()))
    tasks.append(asyncio.create_task(replica.leader_watchdog()))

    #tasks.append(asyncio.create_task(leader.recv_loop()))
    tasks.append(asyncio.create_task(leader.election_thread(replica)))

    # -----------------------------
    # Demo workload injection (optional)
    # Only leader 1 injects commands
    # -----------------------------
    if my_id == 1:
        async def inject():
            await asyncio.sleep(3)
            for i in range(2):
                cmd = ["JOIN", "grp-1", f"host-{i}"]
                print(f"[node {my_id}] injecting {cmd}")
                await leader.request_queue.put(cmd)
                await asyncio.sleep(2)

        tasks.append(asyncio.create_task(inject()))

    # -----------------------------
    # Run forever
    # -----------------------------

    try:
        loop = asyncio.get_running_loop()
        print("STARTING SNIFF ON... on  main")
        def unified_sniff():
         

            def handle(pkt):
                
                if UDP not in pkt or IP not in pkt or Ether not in pkt:
                    return

                dport = pkt[UDP].dport

                # Replica doit voir: PERM_REQ flood, REQ_BCAST/WRITE, CTRL (READ/WRITE)
                if dport in (FLOOD_PORT, REQ_PORT, CTRL_PORT):
                    replica._handle_packet(pkt)

                # Leader doit voir: PERM_ACK, réponses CTRL (OK/FAIL), éventuellement CTRL
                if dport in (REPLY_PORT, CTRL_PORT):
                    leader._handle_packet(pkt)

            sniff(
                iface="eth0",
                filter=f"udp and (port {FLOOD_PORT} or port {REQ_PORT} or port {REPLY_PORT} or port {CTRL_PORT})",
                prn=handle,
                store=False
            )

        loop.run_in_executor(None, unified_sniff)
        await asyncio.sleep(1)
        # maintenant seulement on peut envoyer
        
        await asyncio.gather(*tasks)
    except asyncio.CancelledError:
        pass

if __name__ == "__main__":
    asyncio.run(main())
