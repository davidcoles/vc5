#!/bin/sh
set -x
set -e

if [ "$1" = "-b" ]; then
    shift
    bridge="$1"
    shift
fi

ip link del vc5_1 || true
ip netns del vc5 || true
ip link add vc5_1 type veth peer name vc5_2

ip l set vc5_1 up
ip a add 10.0.0.2/30 dev vc5_1

hwaddr=$(cat /sys/class/net/vc5_2/address)

ip netns add vc5
ip link set vc5_2 netns vc5
ip netns exec vc5 /bin/bash <<EOF
ip l set vc5_2 up
ip a add 10.0.0.1/30 dev vc5_2
ip r replace 10.1.0.0/16 via 10.0.0.2 dev vc5_2
ethtool -K vc5_2 tx off >/dev/null
EOF

ip4=$1
nic=$2

ip link set dev $nic xdpgeneric off >/dev/null 2>&1 || true
ip link set dev $nic xdpdrv     off >/dev/null 2>&1 || true

cleanup() {
    ip link del vc5_1 || true
    ip netns del vc5 || true
    ip link set dev $nic xdpgeneric off >/dev/null 2>&1 || true
    ip link set dev $nic xdpdrv     off >/dev/null 2>&1 || true
}

trap cleanup INT

VC5=vc5/vc5

if [ -f ./vc5 ]; then
    VC5=./vc5
fi

if [ "$bridge" != ""  ]; then
    brctl addif "$bridge" vc5_1
    $VC5 -n vc5.json vc5 vc5_1 $hwaddr $ip4 $nic || true
else
    $VC5 vc5.json vc5 vc5_1 $hwaddr $ip4 $nic || true
fi

cleanup
