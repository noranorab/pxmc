import socket
import struct
import ipaddress
import json

REQ_PORT = 5000

def px_unpack(buf: bytes):
    if len(buf) < 6:
        raise ValueError("too short")
    group_ip_int, seq = struct.unpack("!IH", buf[:6])
    group_ip = str(ipaddress.IPv4Address(group_ip_int))
    payload = buf[6:]
    return group_ip, seq, payload

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("", REQ_PORT))

print(f"[receiver] listening on UDP {REQ_PORT}")

while True:
    data, addr = sock.recvfrom(2048)
    try:
        group_ip, seq, payload = px_unpack(data)
        msg = json.loads(payload.decode())
    except Exception as e:
        print("parse error:", e)
        continue

    print("=" * 50)
    print("from      :", addr)
    print("group_ip  :", group_ip)
    print("seq       :", seq)
    print("json      :", msg)
