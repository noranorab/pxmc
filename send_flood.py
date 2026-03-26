from scapy.all import *

GROUP_IP = "239.0.0.1"
DST_MAC  = "ff:ff:ff:ff:ff:ff"   # L2 broadcast (simplest)
SRC_MAC  = "08:00:00:00:01:11"   # h1 MAC
SRC_IP   = "10.0.1.1"
DST_IP   = "10.0.1.2"            # send to s1 via h2 path
FLOOD_PORT = 5003

seq = 1

# PX header = group_ip (4 bytes) + seq (2 bytes)
px_payload = socket.inet_aton(GROUP_IP) + seq.to_bytes(2, byteorder="big")

pkt = (
    Ether(src=SRC_MAC, dst=DST_MAC) /
    IP(src=SRC_IP, dst=DST_IP) /
    UDP(sport=1234, dport=FLOOD_PORT) /
    px_payload
)

print("Sending FLOOD...")
sendp(pkt, iface="eth0")
print("Done")
