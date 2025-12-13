# send.py (multi-round)
import argparse, socket, struct, time

ap = argparse.ArgumentParser()
ap.add_argument('--group',     required=True)        # 239.1.1.1
ap.add_argument('--iface',     required=True)        # 10.0.1.1 (egress)
ap.add_argument('--port',      type=int, default=5000)
ap.add_argument('--ack_port',  type=int, default=5001)
ap.add_argument('--ttl',       type=int, default=4)
ap.add_argument('--seq',       type=int, default=42)   # starting seq
ap.add_argument('--rounds',    type=int, default=3)    # number of rounds
ap.add_argument('--timeout',   type=float, default=5.0)
args = ap.parse_args()

# --- TX multicast socket ---
tx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
tx.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(args.iface))
tx.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, args.ttl)

# --- RX ACK socket (same for all rounds) ---
rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
rx.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
rx.bind((args.iface, args.ack_port))
rx.settimeout(args.timeout)

for i in range(args.rounds):
    seq = args.seq + i
    payload = struct.pack('!H', seq)

    # send one multicast for this round
    tx.sendto(payload, (args.group, args.port))
    print(f"\n[leader {args.iface}] ROUND {i} seq={seq} -> {args.group}:{args.port}")

    # listen for ACKs for this round during timeout
    t0 = time.time()
    while True:
        try:
            d, a = rx.recvfrom(65535)
        except socket.timeout:
            print(f"[leader] timeout for round seq={seq}")
            break

        if len(d) >= 2:
            ack_seq = struct.unpack('!H', d[:2])[0]
            rest    = d[2:]
            print(f"[leader] ACK from {a}: seq={ack_seq}, rest={rest!r}")
        else:
            print(f"[leader] ACK from {a}: {d!r}")

        # stop listening for this round after timeout seconds
        if time.time() - t0 > args.timeout:
            print(f"[leader] done listening for seq={seq}")
            break

print("\n[leader] all rounds done.")
