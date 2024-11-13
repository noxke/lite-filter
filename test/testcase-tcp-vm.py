#!/usr/bin/env python3

"""
此脚本用于公网测试 监听测试报文 验证测试情况
"""

import os
import sys
import socket
import threading
import time

from scapy.all import *

TEST_IP1 = "11.0.0.1"
TEST_IP2 = "11.0.1.1"
TEST_IP3 = "11.0.2.1"
TEST_TCP1 = 5001
TEST_TCP2 = 5002

TEST_IFACE = "litefilter1"

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

def handle_tcp(ip, port):
    tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_socket.bind((ip, port))
    tcp_socket.listen(5)
    print(f"[TCP] listen {ip}:{port}")

    while True:
        conn, addr = tcp_socket.accept()
        with conn:
            data = conn.recv(1024)
            conn.sendall(b"hello world")

if __name__ == "__main__":
    if os.getuid() != 0:
        print("This script requires root privileges to run.")
        sys.exit(1)

    # 监听TCP报文
    sniff_thread = threading.Thread(target=sniff_listen, kwargs={"filter": "tcp"})
    sniff_thread.start()

    time.sleep(1)

     # 监听TCP
    tcp_thread1 = threading.Thread(target=handle_tcp, args=("0.0.0.0", TEST_TCP1))
    tcp_thread1.start()
    tcp_thread2 = threading.Thread(target=handle_tcp, args=("0.0.0.0", TEST_TCP2))
    tcp_thread2.start()
