# send_flood.py
import argparse, socket, struct, time

ap = argparse.ArgumentParser()
ap.add_argument('--group', required=True)             # e.g. 239.1.1.1 (used BOTH as dst IP and PX.group_ip)
ap.add_argument('--iface', required=True)             # e.g. 10.0.1.1 (source interface IP)
ap.add_argument('--port', type=int, default=5003)     # FLOOD port = 5003
ap.add_argument('--ttl', type=int, default=4)
ap.add_argument('--seq', type=int, default=1)

# multi-send
ap.add_argument('--rounds', type=int, default=1)
ap.add_argument('--start_seq', type=int, default=None)
ap.add_argument('--delay', type=float, default=0.3)

# optional extra bytes after PX header
ap.add_argument('--msg', default="FLOOD", help="extra payload after PX")

args = ap.parse_args()

# ---------- TX (multicast) ----------
tx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
tx.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(args.iface))
tx.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, args.ttl)

def build_px(group_ip_str: str, seq: int, msg: bytes) -> bytes:
    # PX = group_ip (32 bits) + seq (16 bits) in network byte order
    return struct.pack("!4sH", socket.inet_aton(group_ip_str), seq) + msg

def send_one(seq: int):
    payload = build_px(args.group, seq, args.msg.encode("utf-8", errors="replace"))
    tx.sendto(payload, (args.group, args.port))
    print(f"[sender {args.iface}] sent FLOOD seq={seq} group={args.group} -> {args.group}:{args.port} len={len(payload)}")

base = args.seq if args.start_seq is None else args.start_seq

for i in range(args.rounds):
    cur_seq = base + i
    send_one(cur_seq)
    if i < args.rounds - 1:
        time.sleep(args.delay)

print("[sender] done.")
