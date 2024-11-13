#!/bin/bash

if [ $(id -u) -ne 0 ]; then
    echo "This script requires root privileges to run."
    exit
fi


# 清空iptables
# iptables -t nat -F
# iptables -F

# # 关闭iptables
iptables -S | grep 'litefilter0' | sed -r 's/^-A/iptables -D/' | bash
iptables -S | grep 'litefilter1' | sed -r 's/^-A/iptables -D/' | bash

iptables -t nat -S | grep 'litefilter0' | sed -r 's/^-A/iptables -t nat -D/' | bash
iptables -t nat -S | grep 'litefilter1' | sed -r 's/^-A/iptables -t nat -D/' | bash

# 允许两网卡间转发
iptables -A FORWARD -i litefilter0 -o litefilter1 -j ACCEPT
iptables -A FORWARD -i litefilter1 -o litefilter0 -j ACCEPT

# 配置主机公网侧ip
ifconfig litefilter1 add 11.0.1.1
ifconfig litefilter1 add 11.0.2.1


# client不需要删除默认路由
# docker exec intra-host bash -c ""
# server删除默认路由
docker exec extra-host bash -c "route del default"