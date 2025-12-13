# receive.py
import argparse, socket, struct

ap = argparse.ArgumentParser()
ap.add_argument('--group', required=True)          # 239.1.1.1
ap.add_argument('--iface', required=True)          # 10.0.1.2
ap.add_argument('--port', type=int, default=5000)  # RX REQ
ap.add_argument('--ack_port', type=int, default=5001)  # TX ACK (port fixe côté leader)
args = ap.parse_args()

# ---------- RX multicast ----------
rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
rx.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
rx.bind(('', args.port))

mreq = struct.pack('=4s4s',
                   socket.inet_aton(args.group),
                   socket.inet_aton(args.iface))
rx.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

print(f"[replica {args.iface}] joined {args.group}:{args.port}, ACK -> <REQ src>:{args.ack_port}")

# ---------- TX ACK ----------
tx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
tx.bind((args.iface, 0))  # force source IP

while True:
    data, addr = rx.recvfrom(65535)
    leader_ip = addr[0]

    if len(data) < 2:
        print(f"[replica {args.iface}] short packet from {addr}, ignore")
        continue

    # éviter de s'ACK soi-même si on devient leader aussi
    if leader_ip == args.iface:
        print(f"[replica {args.iface}] ignoring my own REQ")
        continue

    # REQ payload = 2 octets seq
    seq = struct.unpack('!H', data[:2])[0]
    print(f"[replica {args.iface}] got REQ seq={seq} from {leader_ip}")

    # ACK payload commence par PX.seq (2B) pour que ton P4 puisse parser/compter
    px_hdr = struct.pack('!H', seq)
    ack_payload = px_hdr + b'ACK'

    tx.sendto(ack_payload, (leader_ip, args.ack_port))
    print(f"[replica {args.iface}] sent ACK seq={seq} -> {leader_ip}:{args.ack_port}")
