#!/usr/bin/env python3

import os
import sys
import socket
import threading
import time

from scapy.all import *

TEST_IFACE = "eth0"

def add_ip(ip):
    # 为网卡添加测试ip
    os.system(f"ifconfig {TEST_IFACE} add {ip}")

def del_ip(ip):
    # 移除ip
    os.system(f"ifconfig {TEST_IFACE} del {ip}")

def sniff_handle(packet: IP):
    print(packet)

def sniff_listen(filter: str):
    print(f"[{filter}] listen")
    sniff(iface=TEST_IFACE, filter=filter, prn=sniff_handle)

def test_tcp(sip, sport, dip, dport):
    add_ip(sip)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind((sip, sport))
    sock.settimeout(1)
    try:
        sock.connect((dip, dport))
        sock.sendall(b"hello")
        data = sock.recv(1024)
    except:
        print("[TCP] No Reply")
    sock.close()
    del_ip(sip)


if __name__ == "__main__":
    if os.getuid() != 0:
        print("This script requires root privileges to run.")
        sys.exit(1)

    # 监听TCP报文
    sniff_thread = threading.Thread(target=sniff_listen, kwargs={"filter": "tcp"})
    sniff_thread.start()

    time.sleep(1)

    # 测试TCP
    test_tcp(sip="11.0.0.2", sport=1234, dip="11.0.0.1", dport=5001)
    time.sleep(1)
    test_tcp(sip="11.0.0.2", sport=1234, dip="11.0.0.1", dport=5002)
    time.sleep(1)
    test_tcp(sip="11.0.1.2", sport=1111, dip="11.0.0.1", dport=5001)

