import socket, json, time, random, struct, ipaddress, argparse

REQ_PORT = 5000
PX_GROUP = "239.1.1.1"

def px_pack(group_ip_str: str, seq: int) -> bytes:
    group_ip = int(ipaddress.IPv4Address(group_ip_str))
    return struct.pack("!IH", group_ip, seq & 0xFFFF)

def px_unpack(buf: bytes):
    if len(buf) < 6:
        raise ValueError("payload too short for px")
    return buf[6:]

def rpc(dst_ip: str, msg: dict, timeout=1.0):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    seq = random.randint(0, 65535)
    payload = px_pack(PX_GROUP, seq) + json.dumps(msg).encode()
    sock.sendto(payload, (dst_ip, REQ_PORT))
    data, _ = sock.recvfrom(65535)
    sock.close()
    return json.loads(px_unpack(data).decode())

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dst", required=True)  # 10.0.0.2
    args = ap.parse_args()

    rid = f"{int(time.time()*1000)}-{random.randint(1,999999)}"
    print("WRITE:", rpc(args.dst, {"t":"WRITE","req_id":rid,"key":"hello","val":{"x":123}}))

    rid = f"{int(time.time()*1000)}-{random.randint(1,999999)}"
    print("READ :", rpc(args.dst, {"t":"READ","req_id":rid,"key":"hello"}))

if __name__ == "__main__":
    main()
