# Notes

My scribblings - likely not useful to anyone else ...


https://wiki.nftables.org/wiki-nftables/index.php/Performing_Network_Address_Translation_(NAT)

https://unix.stackexchange.com/questions/429077/how-to-do-nat-based-on-port-number-in-stateless-nat


Set destination IP address on real server by DSCP - for L3 DSR

* `nft add table raw`
* `nft add chain raw prerouting { type filter hook prerouting priority raw \; }`
* `nft add rule raw prerouting ip dscp 0x04 ip daddr set 192.168.101.4 notrack`

https://lpc.events/event/11/contributions/950/attachments/889/1704/lpc_from_xdp_to_socket_fb.pdf

https://github.com/xdp-project/xdp-tutorial.git

https://lpc.events/event/2/contributions/71/attachments/17/9/presentation-lpc2018-xdp-tutorial.pdf

https://yhbt.net/lore/xdp-newbies/CANLN0e5_HtYC1XQ=Z=JRLe-+3bTqoEWdbHJEGhbF7ZT=gz=ynQ@mail.gmail.com/T/


Intel Xeon Gold 6314U CPU @ 2.30GHz
Intel Ethernet 10G 4P X710-T4L-t OCP
using percpu hash - not using LACP:

* 550K 1.5Gbps 3Mpps    1190ns 36Gbps
* 600K 1.7Gbps 3.25Mpps 1177ns 40Gbps   >90% idle
* 650K 1.8Gbps 3.4Mpps  1145ns 42.7Gbps >90% idle
* 675K 1.9Gbps 3.6Mpps  1303ns 44.7Gbps >90% idle
* 700K 2.0Gbps 3.8Mpps  1295ns 46.5Gbps >90% idle

## TODOs

* IPIP/GRE/DSCP L3 support
* Multicast status to help last conns check
* More complete BGP4 implementation
* BFD implementation (maybe no need for this with 3s hold time)

