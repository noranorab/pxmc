# send2.py - test FLOOD_PORT=5003 with PX header (group_ip + seq)
import argparse, socket, struct

ap = argparse.ArgumentParser()
ap.add_argument("--group", required=True)          # e.g. 239.1.1.1
ap.add_argument("--iface", required=True)          # e.g. 10.0.1.1
ap.add_argument("--port", type=int, default=5003)  # FLOOD_PORT
ap.add_argument("--ttl", type=int, default=4)
ap.add_argument("--seq", type=int, default=1)
args = ap.parse_args()

tx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
tx.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(args.iface))
tx.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, args.ttl)

# PX = group_ip(4 bytes) + seq(2 bytes)
payload = struct.pack("!4sH", socket.inet_aton(args.group), args.seq)

tx.sendto(payload, (args.group, args.port))
print(f"[send2] sent FLOOD group={args.group} seq={args.seq} -> {args.group}:{args.port} from {args.iface}")
