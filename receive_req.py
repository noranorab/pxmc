import socket
import struct

REQ_PORT = 5000

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("0.0.0.0", REQ_PORT))

print("Listening for REQ...")

while True:
    data, addr = sock.recvfrom(1024)
    group_raw, seq = struct.unpack("!IH", data[:6])
    group_ip = socket.inet_ntoa(struct.pack("!I", group_raw))
    print(f"Received REQ from {addr[0]} group={group_ip} seq={seq}")
