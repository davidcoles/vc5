#!/bin/sh
set -x
set -e

native=
bridge=
ifname=

while true; do
    case "$1" in
	"-n")
	    shift
	    native="-n"
	    ;;
	"-b")
	    shift
	    bridge="-b"
	    ;;
	"-i")
	    shift
	    ifname="-i $1"
	    shift
	    ;;
	*)
	    break
	    ;;
    esac
done

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

vc5=$1
shift

json=$1
shift

ip4=$1
shift

for nic in $@; do
    ip link set dev $nic xdpgeneric off >/dev/null 2>&1 || true
    ip link set dev $nic xdpdrv     off >/dev/null 2>&1 || true
    ethtool -K $nic rxvlan off >/dev/null 2>&1 || true
done
 
cleanup() {
    ip link del vc5_1 || true
    ip netns del vc5 || true
    for nic in $@; do
	ip link set dev $nic xdpgeneric off >/dev/null 2>&1 || true
	ip link set dev $nic xdpdrv     off >/dev/null 2>&1 || true
    done
}

trap cleanup INT

tty=

if tty >/dev/null 2>&1; then
    tty=-t
fi

$vc5 $tty $native $bridge $ifname $json vc5 vc5_1 $hwaddr $ip4 $@ || true

cleanup
