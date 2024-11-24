#!/usr/bin/env python3

import os
import sys
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

def test_icmp(src, dst):
    add_ip(src)
    packet = IP(src=src, dst=dst) / ICMP()
    reply = sr1(packet, timeout=1, verbose=False)
    del_ip(src)
    if reply is None:
        print("[ICMP] No Reply")


if __name__ == "__main__":
    if os.getuid() != 0:
        print("This script requires root privileges to run.")
        sys.exit(1)

    # 监听ICMP报文
    sniff_thread = threading.Thread(target=sniff_listen, kwargs={"filter": "icmp"})
    sniff_thread.start()

    time.sleep(1)

    # 测试ICMP
    test_icmp(src="11.0.0.2", dst="11.0.0.1")
    test_icmp(src="11.0.1.3", dst="11.0.0.1")
    test_icmp(src="11.0.1.3", dst="11.0.1.1")
    test_icmp(src="11.0.2.3", dst="11.0.2.1")
