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


if __name__ == "__main__":
    if os.getuid() != 0:
        print("This script requires root privileges to run.")
        sys.exit(1)

    # 监听ICMP报文
    sniff_thread = threading.Thread(target=sniff_listen, kwargs={"filter": "icmp"})
    sniff_thread.start()

    time.sleep(1)
