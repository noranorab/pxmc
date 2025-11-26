#!/usr/bin/env python3
# replica.py — join multicast group and ACK PX requests over raw IP (proto=253)

import argparse
import socket
import struct
import sys
import signal

def strip_ipv4(pkt: bytes) -> bytes:
    """Return IP payload (remove IPv4 header) for a raw IP packet."""
    if len(pkt) >= 20 and (pkt[0] >> 4) == 4:
        ihl = (pkt[0] & 0x0F) * 4
        if 20 <= ihl <= len(pkt):
            return pkt[ihl:]
    return pkt

def main():
    ap = argparse.ArgumentParser(description="Replica: join multicast and ACK PX REQ")
    ap.add_argument("--group",  required=True, help="Multicast group IP (e.g., 239.1.1.1)")
    ap.add_argument("--iface",  required=True, help="Replica's interface IP used to join (e.g., 10.0.2.2)")
    ap.add_argument("--leader", required=True, help="Leader's unicast IP (e.g., 10.0.1.1)")
    ap.add_argument("--proto",  type=int, default=253, help="PX IP protocol number (default: 253)")
    args = ap.parse_args()

    print(f"[replica {args.iface}] joined {args.group}, proto={args.proto}, waiting for REQ…", flush=True)

    # Raw RX socket on custom protocol (kernel delivers IP packets with proto=args.proto)
    rx = socket.socket(socket.AF_INET, socket.SOCK_RAW, args.proto)
    rx.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    # Bind to the multicast group (helps some kernels deliver only matching dst)
    try:
        rx.bind((args.group, 0))
    except OSError:
        # Not strictly required everywhere; safe to continue
        pass

    # Join multicast on the specific interface (use the interface's IP here)
    # mreq = struct.pack('=4s4s', group_addr, iface_addr)
    mreq = struct.pack('=4s4s',
                       socket.inet_aton(args.group),
                       socket.inet_aton(args.iface))
    rx.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

    # Optional: enable loopback so sender on same host can see its own multicasts
    rx.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 1)

    # Raw TX socket for ACKs (same protocol)
    tx = socket.socket(socket.AF_INET, socket.SOCK_RAW, args.proto)

    def _graceful_exit(_sig, _frm):
        try:
            rx.setsockopt(socket.IPPROTO_IP, socket.IP_DROP_MEMBERSHIP, mreq)
        except Exception:
            pass
        print("\n[replica] bye.", flush=True)
        sys.exit(0)

    signal.signal(signal.SIGINT, _graceful_exit)
    signal.signal(signal.SIGTERM, _graceful_exit)

    while True:
        pkt, src = rx.recvfrom(4096)
        payload = strip_ipv4(pkt)

        # PX layout we use:
        #   group_ip(4 bytes, big-endian) | seq(2 bytes, big-endian) | type(1) | pad(1)
        if len(payload) < 8:
            continue

        group_be, seq, mtype = struct.unpack('!IHB', payload[:7])

        # Only react to REQ (type == 0)
        if mtype != 0:
            continue

        # (Optional) Check group matches what we joined
        if group_be != struct.unpack('!I', socket.inet_aton(args.group))[0]:
            continue

        print(f"[replica {args.iface}] got REQ seq={seq} from {src[0]}", flush=True)

        # Build ACK: same group + seq, type=1, pad=0
        ack = struct.pack('!IHBx', group_be, seq, 1)
        tx.sendto(ack, (args.leader, 0))
        print(f"[replica {args.iface}] sent ACK seq={seq} -> {args.leader}", flush=True)

if __name__ == "__main__":
    main()
    
