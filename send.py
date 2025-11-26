# send.py
import argparse, socket, struct, time

ap = argparse.ArgumentParser()
ap.add_argument('--group', required=True)     # 239.1.1.1
ap.add_argument('--iface', required=True)     # 10.0.1.1 (egress)
ap.add_argument('--port',  type=int, default=5000)
ap.add_argument('--ack_port', type=int, default=5001)
ap.add_argument('--ttl',   type=int, default=4)
ap.add_argument('--seq',   type=int, default=42)     # numéro de round
ap.add_argument('--timeout', type=float, default=5.0)
args = ap.parse_args()

# Socket TX multicast
tx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
tx.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(args.iface))
tx.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, args.ttl)

# Payload = 2 octets: seq (big-endian)
payload = struct.pack('!H', args.seq)

tx.sendto(payload, (args.group, args.port))
print(f"[leader {args.iface}] sent seq={args.seq} to {args.group}:{args.port}")

# Socket RX pour ACKs
rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
rx.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
rx.bind((args.iface, args.ack_port))
rx.settimeout(args.timeout)

t0 = time.time()
while True:
    try:
        d, a = rx.recvfrom(65535)
        if len(d) >= 2:
            ack_seq = struct.unpack('!H', d[:2])[0]
            rest    = d[2:]
            print(f"[leader] ACK from {a}: seq={ack_seq}, rest={rest!r}")
        else:
            print(f"[leader] ACK from {a}: {d!r}")
    except socket.timeout:
        break
    if time.time() - t0 > args.timeout:
        break

print("[leader] done listening.")
