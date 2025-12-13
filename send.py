# send.py
import argparse, socket, struct, time

ap = argparse.ArgumentParser()
ap.add_argument('--group', required=True)          # 239.1.1.1
ap.add_argument('--iface', required=True)          # 10.0.1.1
ap.add_argument('--port', type=int, default=5000)  # REQ port
ap.add_argument('--ack_port', type=int, default=5001)
ap.add_argument('--ttl', type=int, default=4)
ap.add_argument('--seq', type=int, default=42)
ap.add_argument('--timeout', type=float, default=5.0)

# optionnel: pour tester plusieurs rounds
ap.add_argument('--rounds', type=int, default=1)
ap.add_argument('--start_seq', type=int, default=None)
ap.add_argument('--delay', type=float, default=0.3)

args = ap.parse_args()

# ---------- TX multicast ----------
tx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
tx.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(args.iface))
tx.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, args.ttl)

# ---------- RX acks ----------
rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
rx.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
rx.bind((args.iface, args.ack_port))
rx.settimeout(args.timeout)

def send_one(seq):
    payload = struct.pack('!H', seq)  # PX.seq
    tx.sendto(payload, (args.group, args.port))
    print(f"[leader {args.iface}] sent REQ seq={seq} -> {args.group}:{args.port}")

def listen_acks(seq):
    t0 = time.time()
    while True:
        try:
            data, addr = rx.recvfrom(65535)
            if len(data) >= 2:
                ack_seq = struct.unpack('!H', data[:2])[0]
                rest = data[2:]
                print(f"[leader] ACK from {addr}: seq={ack_seq}, rest={rest!r}")
            else:
                print(f"[leader] ACK from {addr}: {data!r}")
        except socket.timeout:
            break

        if time.time() - t0 > args.timeout:
            break

# --------- loop rounds (optional) ----------
base = args.seq if args.start_seq is None else args.start_seq

for i in range(args.rounds):
    cur_seq = base + i
    send_one(cur_seq)
    listen_acks(cur_seq)
    if i < args.rounds - 1:
        time.sleep(args.delay)

print("[leader] done.")
