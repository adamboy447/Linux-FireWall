#!/usr/bin/env python3
"""UDP receiver for manual firewall tests.

    python3 receiver.py [PORT]          (default 8000)
"""
import socket
import sys


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8000
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", port))
    print(f"UDP receiver listening on port {port}")
    while True:
        data, addr = sock.recvfrom(4096)
        print(f"received from {addr[0]}:{addr[1]}: {data.decode(errors='replace')}")


if __name__ == "__main__":
    main()
