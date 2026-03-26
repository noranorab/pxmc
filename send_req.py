from scapy.all import *
import socket
import struct

REQ_PORT = 5000
GROUP_IP = "239.0.0.1"
SEQ = 10

px_payload = socket.inet_aton(GROUP_IP) + SEQ.to_bytes(2, "big")

pkt = (
    Ether(dst="ff:ff:ff:ff:ff:ff") /
    IP(src="10.0.1.1", dst="10.0.1.255") /
    UDP(sport=1234, dport=REQ_PORT) /
    Raw(load=px_payload)
)

print("Sending REQ")
sendp(pkt, iface="eth0")
