# receive.py
import argparse, socket, struct

ap = argparse.ArgumentParser()
ap.add_argument('--group',   required=True)           # 239.1.1.1
ap.add_argument('--iface',   required=True)           # ex: 10.0.1.2
ap.add_argument('--leader',  required=True)           # 10.0.1.1
ap.add_argument('--port',    type=int, default=5000)  # RX multicast
ap.add_argument('--ack_port',type=int, default=5001)  # TX ACK
args = ap.parse_args()

# 1) Socket RX multicast
rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
rx.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
rx.bind(('', args.port))

mreq = struct.pack('=4s4s',
                   socket.inet_aton(args.group),
                   socket.inet_aton(args.iface))
rx.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

print(f"[replica {args.iface}] joined {args.group}:{args.port}, ACKs -> {args.leader}:{args.ack_port}")

# 2) Socket TX pour les ACKs
tx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
tx.bind((args.iface, 0))  # source IP = iface

while True:
    data, addr = rx.recvfrom(65535)
    print(f"[rx {args.iface}] got {len(data)} B from {addr}: {data!r}")

    if len(data) < 2:
        print("[replica] packet too short, ignoring")
        continue

    # Les 2 premiers octets = seq (même format que PX.bit<16>)
    seq = struct.unpack('!H', data[:2])[0]
    print(f"[replica {args.iface}] seq={seq}")

    # Construire header PX : 16 bits seq → exactement ce que ton P4 attend
    px_hdr = struct.pack('!H', seq)

    # Optionnel : payload ACK (le switch s’en fiche, il ne regarde que PX)
    app = b'ACK'
    ack_pkt = px_hdr + app

    tx.sendto(ack_pkt, (args.leader, args.ack_port))
    print(f"[replica {args.iface}] sent ACK (PX+APP) -> {args.leader}:{args.ack_port}")
