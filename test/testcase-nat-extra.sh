#!/bin/bash

if [ $(id -u) -ne 0 ]; then
    echo "This script requires root privileges to run."
    exit
fi


# SNAT UDP
ncat -lu -i 1 4001

sleep 1

# SNAT TCP
echo SNAT_TCP_EXTRA | ncat -l 5001

sleep 1

# DNAT UDP
echo DNAT_UDP_EXTRA | ncat -u 11.0.0.1 4002

sleep 1

# DNAT TCP
echo DNAT_TCP_EXTRA | ncat 11.0.0.1 5002
