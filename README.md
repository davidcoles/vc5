# VC5

Primarily a distributed Layer 2 Direct Server Return
([DSR](https://www.loadbalancer.org/blog/direct-server-return-is-simply-awesome-and-heres-why/))
Layer 4 load balancer (L4LB) for Linux using XDP/eBPF.

Consists of:

* A kernel-level load balancing scheduler (using eBPF/XDP) and userland library API to manipulate entries (data-plane).
* A library to perform checks on backend servers and mark nodes/VIPs as healthy, used to control the data-plane.
* A BGP implementation to advertise healthy VIPs to routers.
* A commannd line application which uses the above services to provide a redundant load balancing solution.

Currently, the main target is the command line application which can be used to create an out-of-the-box appliance: the `vc5` binary.

The BGP and health check libraries could be used with a separate
balancing solution such as IPVS to create a NAT-based balancer (see
https://github.com/davidcoles/stayinalived and
[docs/integration.md](docs/integration.md)) and development should
proceed to make this easier.

Currently you would be best advised to use the binary/code from the
latest release rather than HEAD.

If you think that this may be useful and have any
questions/suggestions, feel free to contact me at vc5lb@proton.me or raise a GitHub issue.

## Homepage

The code is hosted at GitHub, https://github.com/davidcoles/vc5

Clone with `git clone https://github.com/davidcoles/vc5.git`

[Documentation and quick start guide](docs/README.md) with a [video demonstration](docs/quickstart.md).

## Goals/status

* ✅ Simple deployment with a single binary
* ✅ Stable backend selection with Maglev hashing algorithm
* ✅ Route health injection handled automatically; no need to run other software such as ExaBGP
* ✅ Minimally invasive; does not require any modification of iptables rules on server
* ✅ No modification of backend servers beyond adding the VIP to a loopback device
* ✅ Health-checks run against the VIP on backend servers, not their real addresses
* ✅ HTTP/HTTPS, half-open SYN probe and UDP/TCP DNS healthchecks built in
* ✅ As close as possible to line-rate 10Gbps performance
* ✅ In-kernel code execution with XDP/eBGP; native mode drivers avoid sk_buff allocation
* ✅ (D)DoS mitigation with fast early drop rules
* ✅ Multiple VLAN support
* ✅ Multiple NIC support for lower bandwidth/development applications
* ✅ Works with bonded network devices to support high-availibility/high-bandwidth
* ✅ Observability via a web console and Prometheus metrics
* 🚧 Simple API to enable embedding into your own project
* 🚧 Extension to support LVS/IPVS for non-DRS operation

## Performance

This has mostly been tested using Icecast backend servers with clients
pulling a mix of low and high bitrate streams (48kbps - 192kbps).

It seems that a VMWare guest (4 core, 8GB) using the XDP generic
driver will support 100K concurrent clients, 380Mbps/700Kpps through
the load balancer and 8Gbps of traffic from the backends directly to
the clients.

On a single (non-virtualised) Intel Xeon Gold 6314U CPU (2.30GHz 32
physical cores, with hyperthreading enabled for 64 logical cores) and
an Intel 10G 4P X710-T4L-t ethernet card, I was able to run 700K
streams at 2Gbps/3.8Mpps ingress traffic and 46.5Gbps egress. The
server was more than 90% idle. Unfortunately I did not have the
resources available to create more clients/servers.

## About

VC5 is a network load balancer designed to work as replacement for
legacy hardware appliances. It allows a service with a Virtual IP
address (VIP) to be distributed over a set of real servers. Real
servers might run the service themselves or act as proxies for another
layer of servers (eg. HAProxy serving as a Layer 7 HTTP router/SSL
offload). The only requirement being that the VIP needs to be
configured on a loopback device on real server, eg.: `ip a add
192.168.101.1/32 dev lo`

One server with a 10Gbit/s network interface should be capable of
supporting an HTTP service in excess of 100Gbit/s egress bandwidth due
to the asymmetric nature of most internet traffic. For smaller
services a modest virtual machine or two will likely handle a service
generating a number of Gbit/s of egress traffic.

If one instance is not sufficient then more servers may be added to
horizontally scale capacity (and provide redundancy) using your
router's ECMP feature. 802.3ad bonded interfaces and 802.1Q VLAN
trunking is supported (see [examples/](examples/) directory).

No kernel modules or complex setups are required, although for best
performance a network card driver with XDP native mode support is
required (eg.: mlx4, mlx5, i40e, ixgbe, ixgbevf, nfp, bnxt, thunder,
dpaa2, qede). A full list is availble at [The XDP Project's driver
support page](https://github.com/xdp-project/xdp-project/blob/master/areas/drivers/README.org).

A good summary of the concepts in use are discussed in [Patrick
Shuff's "Building a Billion User Load Balancer"
talk](https://www.youtube.com/watch?v=bxhYNfFeVF4&t=1060s) and [Nitika
Shirokov's Katran talk](https://www.youtube.com/watch?v=da9Qw7v5qLM)

A basic web console and Prometheus metrics server is included: ![Console screenshot](docs/console.jpg)

A sample utility to render traffic from /20 prefixes going through the
load-balancer is in the [cmd/hilbert/](cmd/hilbert/) directory:
![cmd/hilbert/hilbert.png](cmd/hilbert/hilbert.png)

A good use for the traffic stats would be to track which prefixes are
usually active and to generate a table of which /20s to early drop
traffic from in the case of a DoS/DDoS (particularly spoofed source
addresses).

Initially this began as self-contained director/balancer
project. Recently, it seems that the healthchecking, route health
injection and observability portions could be re-used with a non-DSR
balancer such as Linux's virtual server. As such, I am currently
modifying the code to allow switching out the eBPF/XDP portion so that
a project using this library can bring its own implemention.

Consequently, the old configuration schema needs updating and old
versions will no longer work. For now I will maintain a backwards
compatible v0.1 branch with bugfixes, etc., but the main branch will
begin using a new updated config parser script.

## Operation

There are three modes of operation, simple, VLAN, and multi-NIC
based. In simple mode all hosts must be on the same subnet as the
primary address of the load balancer. In VLAN mode (enabled by
declaring entries under the "vlans" section of the YAML/JSON config
file), server entries should match a VLAN/CIDR subnet entry. VLAN
tagged interfaces need to be created in the OS and have an IP address
assigned within the subnet. In multi-NIC mode subnets are tagged in
the same manner as VLANs, but bpf_redirect() is used to send traffic
out of the appropriate interface (rather than changing the VLAN ID and
using XDP_TX).

In VLAN mode, traffic into the load balancer needs to be on a tagged VLAN (no
pushing or popping of 802.1Q is done - yet). The IP address specified on the
command line will be used to bind the connection to BGP peers, and so
should be on one of the VLAN tagged interfaces (with appropriate
routing for BGP egress if the router is not on the same subnet,
eg. route reflectors).

Sample netplan and VC5 configurations are in the
[examples/](examples/) directory.

A Multi-NIC mode has been added (-m flag) to `vc5ng`. Subnets matching
each (untagged) NIC should be declared with an arbitrary "VLAN ID" in
the config file. The code will discover the IP address/interface
bindings and use bpf_redirect() to forward packets out the correct
interface. This makes it possible to have multiple VLANs supported on
a VMWare virtual machine with multiple network interfaces - trunked
VLANs are not easily supported on VMWare as there is an all-or-nothing
approach, which may not be practical/desirable in a large installation.




## TODOs

* IPIP/GRE/DSCP L3 support
* Multicast status to help last conns check
* More complete BGP4 implementation
* BFD implementation (maybe no need for this with 3s hold time)


## Notes

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
