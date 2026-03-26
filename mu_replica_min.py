#!/usr/bin/env python3
import argparse, socket, json, time, random, struct, ipaddress, threading

REQ_PORT   = 5000
ACK_PORT   = 5001
JOIN_PORT  = 5002
FLOOD_PORT = 5003
REPLY_PORT = 5004

GROUP_IP = "239.0.0.1"   # what you want

def px_pack(group_ip_str: str, seq: int) -> bytes:
    group_ip = int(ipaddress.IPv4Address(group_ip_str))
    return struct.pack("!IH", group_ip, seq & 0xFFFF)  # 4 bytes + 2 bytes

def px_unpack(buf: bytes):
    if len(buf) < 6:
        raise ValueError("payload too short for px")
    group_ip_int, seq = struct.unpack("!IH", buf[:6])
    rest = buf[6:]
    return str(ipaddress.IPv4Address(group_ip_int)), seq, rest

class Node:
    def __init__(self, my_ip: str, is_leader: bool, leader_ip: str):
        self.my_ip = my_ip
        self.is_leader = is_leader
        self.leader_ip = leader_ip
        self.seq = random.randint(0, 65535)

        # simple kv store for READ/WRITE test
        self.kv = {}

        # sockets on the 3 ports we need
        self.sock_req   = self._bind_udp(REQ_PORT)
        self.sock_flood = self._bind_udp(FLOOD_PORT)
        self.sock_reply = self._bind_udp(REPLY_PORT)

        # leader counts replies (who is active)
        self.active_senders = set()

    def _bind_udp(self, port: int) -> socket.socket:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # useful in mininet when restarting
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((self.my_ip, port))
        return s

    def _next_seq(self) -> int:
        self.seq = (self.seq + 1) & 0xFFFF
        return self.seq

    def send_px(self, sock: socket.socket, dst_ip: str, dst_port: int, msg: dict):
        seq = self._next_seq()
        payload = px_pack(GROUP_IP, seq) + json.dumps(msg).encode()
        sock.sendto(payload, (dst_ip, dst_port))

    # ---------------- listeners ----------------
    def loop_flood(self):
        while True:
            data, addr = self.sock_flood.recvfrom(65535)
            try:
                g, seq, rest = px_unpack(data)
                msg = json.loads(rest.decode())
            except Exception:
                continue

            # follower reaction: upon receiving FLOOD, send REPLY to leader
            if not self.is_leader:
                # send REPLY to leader (dstPort=5004) with same group
                self.send_px(
                    self.sock_reply,
                    self.leader_ip,
                    REPLY_PORT,
                    {"t":"REPLY", "from": self.my_ip, "seen_seq": seq, "group": g}
                )

    def loop_reply(self):
        # leader listens on 5004 to learn who is active
        while True:
            data, addr = self.sock_reply.recvfrom(65535)
            try:
                g, seq, rest = px_unpack(data)
                msg = json.loads(rest.decode())
            except Exception:
                continue

            if self.is_leader:
                sender_ip = msg.get("from") or addr[0]
                self.active_senders.add(sender_ip)
                print(f"[LEADER] got REPLY from {sender_ip}, active now = {sorted(self.active_senders)}")

    def loop_req(self):
        while True:
            data, addr = self.sock_req.recvfrom(65535)
            try:
                g, seq, rest = px_unpack(data)
                msg = json.loads(rest.decode())
            except Exception:
                continue

            t = msg.get("t")
            req_id = msg.get("req_id")

            if t == "WRITE":
                key = str(msg.get("key"))
                self.kv[key] = msg.get("val")
                # reply back to sender (unicast)
                self.send_px(self.sock_req, addr[0], addr[1], {"t":"OK", "req_id": req_id, "from": self.my_ip})

            elif t == "READ":
                key = str(msg.get("key"))
                val = self.kv.get(key, None)
                self.send_px(self.sock_req, addr[0], addr[1], {"t":"OK", "req_id": req_id, "from": self.my_ip, "val": val})

    # ---------------- leader actions ----------------
    def leader_bootstrap(self, flood_dst_ip: str):
        """
        Step 1: send FLOOD (5003). Switch will flood it to all ports.
        Step 2: followers send REPLY (5004) -> switch records active ports in group_ports[idx]
        """
        assert self.is_leader
        print("[LEADER] sending FLOOD bootstrap...")
        self.send_px(self.sock_flood, flood_dst_ip, FLOOD_PORT, {"t":"FLOOD", "leader": self.my_ip, "group": GROUP_IP})
        # wait a bit for replies to come back
        time.sleep(0.7)

    def leader_test_rw(self, dst_ip: str):
        """
        After bootstrap, send REQ (5000) which will now replicate to active ports.
        For demo we send WRITE to dst_ip (any), but switch replication uses group_ports.
        """
        assert self.is_leader
        rid = f"{int(time.time()*1000)}-{random.randint(1,999999)}"
        print("[LEADER] sending WRITE on 5000 ...")
        self.send_px(self.sock_req, dst_ip, REQ_PORT, {"t":"WRITE", "req_id": rid, "key":"hello", "val":{"x":123}})

        time.sleep(0.5)

        rid = f"{int(time.time()*1000)}-{random.randint(1,999999)}"
        print("[LEADER] sending READ on 5000 ...")
        self.send_px(self.sock_req, dst_ip, REQ_PORT, {"t":"READ", "req_id": rid, "key":"hello"})

    def run(self, flood_dst_ip: str, test_dst_ip: str):
        # start listeners
        threading.Thread(target=self.loop_flood, daemon=True).start()
        threading.Thread(target=self.loop_reply, daemon=True).start()
        threading.Thread(target=self.loop_req, daemon=True).start()

        if self.is_leader:
            # bootstrap then test
            self.leader_bootstrap(flood_dst_ip)
            self.leader_test_rw(test_dst_ip)

        # keep alive
        while True:
            time.sleep(1)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ip", required=True, help="local host IP (10.0.0.X or 10.0.1.X in your topo)")
    ap.add_argument("--leader", action="store_true", help="run as leader")
    ap.add_argument("--leader-ip", required=True, help="leader IP (same as --ip if leader)")
    ap.add_argument("--flood-dst", required=True, help="any host IP reachable via switch (used as dst for FLOOD packet)")
    ap.add_argument("--test-dst", required=True, help="any host IP reachable (dst for REQ packets)")
    args = ap.parse_args()

    n = Node(my_ip=args.ip, is_leader=args.leader, leader_ip=args.leader_ip)
    n.run(args.flood_dst, args.test_dst)

if __name__ == "__main__":
    main()
