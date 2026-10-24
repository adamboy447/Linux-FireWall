#!/usr/bin/env python3
"""UDP sender for manual firewall tests.

    python3 sender.py [IP] [PORT] [MESSAGE]     (default 127.0.0.1 8000 Hello!)

The original script sent to port 8080 while receiver.py listened on 8000,
so the pair never talked to each other; both now default to 8000.
"""
import socket
import sys


def main():
    ip = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 8000
    message = sys.argv[3] if len(sys.argv) > 3 else "Hello!"
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(message.encode(), (ip, port))
    print(f"sent {message!r} to {ip}:{port}")
    sock.close()


if __name__ == "__main__":
    main()
