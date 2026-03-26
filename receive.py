# receive.py
import argparse, socket, struct, time

REQ_PORT  = 5000
ACK_PORT  = 5001
JOIN_PORT = 5002

ap = argparse.ArgumentParser()
ap.add_argument('--group', required=True)          # ex: 239.1.1.1
ap.add_argument('--iface', required=True)          # ex: 10.0.1.2
ap.add_argument('--port', type=int, default=REQ_PORT)
ap.add_argument('--ack_port', type=int, default=ACK_PORT)
ap.add_argument('--join_port', type=int, default=JOIN_PORT)
args = ap.parse_args()

def px_pack(group_ip: str, seq: int) -> bytes:
    # PX = group_ip(4B) + seq(2B)
    return struct.pack("!4sH", socket.inet_aton(group_ip), seq)

# -------- RX multicast REQ --------
rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
rx.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
rx.bind(('', args.port))

mreq = struct.pack("=4s4s", socket.inet_aton(args.group), socket.inet_aton(args.iface))
rx.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

print(f"[replica {args.iface}] joined {args.group}:{args.port}")

# -------- TX socket (ACK + JOIN) --------
tx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
tx.bind((args.iface, 0))  # force l'IP source

# -------- Send JOIN once --------
join_payload = px_pack(args.group, 0) + b"JOIN"
tx.sendto(join_payload, (args.group, args.join_port))
print(f"[replica {args.iface}] sent JOIN -> {args.group}:{args.join_port}")

# -------- Loop: receive REQ then ACK leader --------
while True:
    data, addr = rx.recvfrom(65535)
    leader_ip = addr[0]

    # ignore our own multicasts if we ever act as leader
    if leader_ip == args.iface:
        continue

    if len(data) < 6:
        print(f"[replica {args.iface}] short REQ from {addr}, ignore")
        continue

    grp_raw, seq = struct.unpack("!4sH", data[:6])
    grp = socket.inet_ntoa(grp_raw)

    print(f"[replica {args.iface}] got REQ group={grp} seq={seq} from {leader_ip}")

    ack_payload = px_pack(grp, seq) + b"ACK"
    tx.sendto(ack_payload, (leader_ip, args.ack_port))
    print(f"[replica {args.iface}] sent ACK group={grp} seq={seq} -> {leader_ip}:{args.ack_port}")
