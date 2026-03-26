from scapy.all import *
import socket

REPLY_PORT = 5004
FLOOD_PORT = 5003

def handle(pkt):
    if UDP in pkt and pkt[UDP].dport == FLOOD_PORT:
        print("Got FLOOD")

        px = bytes(pkt[UDP].payload)
        group_ip = socket.inet_ntoa(px[:4])
        seq = int.from_bytes(px[4:6], "big")

        print("group:", group_ip, "seq:", seq)

        my_ip = get_if_addr("eth0")
        my_mac = get_if_hwaddr("eth0")

        reply = (
            Ether(src=my_mac, dst=pkt[Ether].src) /
            IP(src=my_ip, dst=pkt[IP].src) /
            UDP(sport=5000, dport=REPLY_PORT) /
            px
        )

        sendp(reply, iface="eth0")
        print("Reply sent")

print("Listening...")
sniff(iface="eth0", prn=handle)
