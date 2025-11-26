# leader.py (verbose, robuste)
import argparse, socket, struct, time, sys, select

def strip_ipv4(pkt: bytes) -> bytes:
    # Linux raw IP fournit l'IP header + payload pour proto=X.
    # On enlève l'en-tête IPv4 si présent.
    if len(pkt) >= 20 and (pkt[0] >> 4) == 4:
        ihl = (pkt[0] & 0x0F) * 4
        if 20 <= ihl <= len(pkt):
            return pkt[ihl:]
    return pkt

def hexdump(b: bytes, n=32):
    return ' '.join(f'{x:02x}' for x in b[:n])

ap = argparse.ArgumentParser()
ap.add_argument('--group',   required=True)          # 239.1.1.1
ap.add_argument('--iface',   required=True)          # 10.0.1.1
ap.add_argument('--proto',   type=int, default=253)  # PX IP protocol
ap.add_argument('--seq',     type=int, required=True)
ap.add_argument('--expect',  type=int, default=1)
ap.add_argument('--timeout', type=float, default=5.0)
ap.add_argument('--ttl',     type=int, default=4)
ap.add_argument('--resend',  type=float, default=0.0) # ré-émission périodique
args = ap.parse_args()

grp_ip_be = struct.unpack('!I', socket.inet_aton(args.group))[0]
px_req = struct.pack('!IHBx', grp_ip_be, args.seq, 0)  # group | seq | type=0 | pad

# TX raw IP
tx = socket.socket(socket.AF_INET, socket.SOCK_RAW, args.proto)
tx.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(args.iface))
tx.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, args.ttl)
tx.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 1)

# RX raw IP
rx = socket.socket(socket.AF_INET, socket.SOCK_RAW, args.proto)
# Optionnel: lier à l'adresse du leader (évite des livraisons bizarres)
try:
    rx.bind((args.iface, 0))
except OSError:
    pass
rx.setblocking(False)

# Envoi initial
tx.sendto(px_req, (args.group, 0))
print(f"[leader] sent REQ seq={args.seq} proto={args.proto} to {args.group} from {args.iface}", flush=True)

got, seen = 0, set()
t0 = time.time()
last_send = t0

while got < args.expect and (time.time() - t0) < args.timeout:
    # Ré-émission si demandé
    if args.resend > 0 and (time.time() - last_send) >= args.resend:
        tx.sendto(px_req, (args.group, 0))
        last_send = time.time()
        print(f"[leader] re-sent REQ seq={args.seq}", flush=True)

    r, _, _ = select.select([rx], [], [], 0.25)
    if not r:
        continue

    try:
        pkt, src = rx.recvfrom(4096)
    except BlockingIOError:
        continue

    payload = strip_ipv4(pkt)
    print(f"[leader] rx len={len(payload)} from {src[0]} bytes={hexdump(payload)}", flush=True)

    if len(payload) < 8:
        # Au minimum: 4 (group) + 2 (seq) + 1 (type) + 1 (pad)
        continue

    g_be, seq, mtype = struct.unpack('!IHB', payload[:7])

    if mtype != 1:
        # Pas un ACK → ignorer
        continue
    if seq != args.seq or g_be != grp_ip_be:
        # Mauvaise séquence ou mauvais groupe → ignorer
        continue

    if src[0] in seen:
        continue
    seen.add(src[0])
    got += 1
    print(f"[leader] ACK {got}/{args.expect} from {src[0]} (seq={seq})", flush=True)

print(f"[leader] done: {got} ACK(s) in {time.time()-t0:.2f}s", flush=True)
