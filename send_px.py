#!/usr/bin/env python3
import socket
import struct
import time

def send_simple_test():
    """Send a simple test packet"""
    
    # Create socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("10.0.1.1", 40000))
    
    # PX header: group_ip (239.1.1.1 = 0xEF010101) and seq (1)
    # 239.1.1.1 in hex: 0xEF 0x01 0x01 0x01
    # In network byte order (big endian): 0xEF010101
    group_ip_int = 0xEF010101  # 239.1.1.1
    seq = 1
    
    # Pack PX header: 4 bytes group_ip + 2 bytes seq
    px_header = struct.pack("!IH", group_ip_int, seq)
    
    # Simple payload
    payload = px_header + b"TEST_PAYLOAD_12345"
    
    # Destination
    dst_ip = "10.0.1.2"
    dst_port = 5000  # REQ_PORT
    
    print(f"Sending test packet:")
    print(f"  From: 10.0.1.1:40000")
    print(f"  To: {dst_ip}:{dst_port}")
    print(f"  Group IP: 239.1.1.1 (0x{group_ip_int:08X})")
    print(f"  Sequence: {seq}")
    print(f"  Total size: {len(payload)} bytes")
    
    # Send multiple times to be sure
    for i in range(3):
        print(f"  Sending packet {i+1}/3...")
        sock.sendto(payload, (dst_ip, dst_port))
        time.sleep(0.5)
    
    sock.close()
    print("Done!")

if __name__ == "__main__":
    send_simple_test()
