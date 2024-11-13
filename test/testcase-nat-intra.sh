#!/bin/bash

if [ $(id -u) -ne 0 ]; then
    echo "This script requires root privileges to run."
    exit
fi


# SNAT UDP
echo SNAT_UDP_INTRA | ncat -u 11.0.0.2 4001

sleep 1

# SNAT TCP
echo SNAT_TCP_INTRA | ncat 11.0.0.2 5001

sleep 1

# DNAT UDP
ncat -lu -i 1 4002

sleep 1

# DNAT TCP
echo DNAT_TCP_INTRA | ncat -l 5002
