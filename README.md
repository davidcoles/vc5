# VC5

A distributed Layer 2 Direct Server Return (L2DSR) Layer 4 load balancer (L4LB) for Linux using XDP/eBPF.

This is very much a proof of concept at this stage - most everything is incomplete and poorly defined!

If you think that this may be useful and have any questions/suggestions, feel free to contact me at d4v1dc0l3s@protonmail.com

## Homepage

The code is hosted at GitHub, https://github.com/davidcoles/vc5

Clone with `git clone https://github.com/davidcoles/vc5.git`

## About

VC5 is a network load balancer designed to work as replacement for
legacy hardware appliances. It allows a service with a Virtual IP
address (VIP) to be distributed to a set of real servers. Real servers
might run the service themselves or work as proxies for another layer
of servers (eg. HAProxy serving as a Layer 7 router and SSL offload
for webservers). The VIP needs to be configured on a loopback device
on real server, eg.: `ip a add 192.168.101.1/32 dev lo`

One server with a 10Gbit/s network interface should be capable of
supporting a service of 100Gbit/s due to the asymmetric nature of most
internet traffic. For smaller services a modest virtual machine or two
will likely handle a few Gbit/s.

If one server is not sufficient then more servers may be added to
horizontally scale capacity (or provide redundancy) using the ECMP
feature of routing hardware. 802.3AD bonded interfaces and 802.1Q VLAN
trunking is supported (see [examples/](examples/) directory).

No kernel modules or complex setups are required, although for best
performance a network card driver with XDP native mode support is
needed (eg.: mlx4, mlx5, i40e, ixgbe, ixgbevf, nfp, bnxt, thunder,
dpaa2, qede). A full list is availble at [The XDP Project's driver
support page](https://github.com/xdp-project/xdp-project/blob/master/areas/drivers/README.org).

A basic web console and Prometheus metrics server is included: ![Console screenshot](docs/console.jpg)


## Quickstart

It would be recommended to start out using a fresh virtual machine.

First we need a development environment capable of building libbpf and
Go binaries. Go 1.16 or later is needed due to using go:embed
directives. On Ubuntu 20.04 this can be achieved with:

  `apt-get install git build-essential libelf-dev clang libc6-dev libc6-dev-i386 llvm golang-1.16 libyaml-perl libjson-perl ethtool`
  
  `ln -s /usr/lib/go-1.16/bin/go /usr/local/bin/go`

Copy the [examples/config.yaml](examples/config.yaml) file to
cmd/vc5.yaml and edit appropriately for your
routers/services/backends. Remember to configure the VIP on the
loopback interface on real servers.

Run `make`. This will pull a copy of
[libbpf](https://github.com/libbpf/libbpf), build the binary and
transform the YAML config file to a more verbose JSON config format.

Run the vc5 binary with arguments of the json file,
your IP address and network interface name, eg.:

  `cmd/vc5 cmd/vc5.json 10.10.100.200 ens192`

If this doesn't bomb out then you should have a load balancer up and
running. A virtual network device and net namespace will be created
for performing healthchecks to VIPs on the backend servers. A
webserver (running on port 80 by default) will display logs,
statistics and backend status. There is Prometheus metric endpoint for
collecting statistics.

To dynamically alter the services running on the load balancer, change
the YAML file appropriately and regenerate the JSON file (`make
vc5.json`). Sending a HUP signal to the main process will cause it to
reload the JSON configuration file and apply any changes. The new
configuration will be reflected in the web console.

You can add static routing to forward traffic for a VIP to the load
balancer, or configure BGP peers in the YAML file to have routes
automatically injected to your routing table when services are
healthy.

If you don't have a routed environment then you can test with a client
machine on the same VLAN. Either add a static route on the client
machine pointing to the load balancer, or run BIRD/Quagga on client
and add the client's IP address to the BGP section of the YAML config.

Sample bird.conf snippet:

```
protocol bgp loadbalancers {
     description "loadbalancers";
     local as 65304;
     neighbor range 10.10.100.0/24 as 65304;

     ipv4 {
          export none;
          import filter {
                 if net ~ 192.168.101.0/24 then accept;
                 else reject;
          };
          next hop self;
     };

     passive on;
     direct;
}
```

If you enable ECMP on your router/client ("merge paths on;" in BIRD's
kernel protocol) then you can load balance traffic to multiple load
balancers. VC5 uses multicast to share a flow state table so peers
will learn about each other's connections and take over in the case of
one load balancer going down.

If you wish to run the driver in native mode, but it does not support
XDP_REDIRECT then a slighly more involved network setup is needed at
this stage. Run your physical interface in a bridge (see sample
netplan config in bridge.yaml) and add the -n (native) -b (bridge
mode) and -i (interface) flags to vc5 like so:

  `cmd/vc5 -n -b -i br0 cmd/vc5.json 10.10.100.200 enp130s0f1`

## Operation

There are two modes of operation, simple and VLAN based. In simple
mode all hosts must be on the same subnet as the primary address of
the load balancer. In VLAN mode (enabled by declaring entries under
the "vlan" section), all server entries must match a VLAN/CIDR subnet
entry. VLAN tagged interfaces need to be created in the OS and have an
IP address assigned within the subnet, and the interface names must be
of the (printf) form "vlan%d" (vlan2, vlan53, vlan1356, etc.).

Traffic into the load balancer needs to be on a tagged VLAN (no
pushing or popping of 802.1Q is done). The IP address specified on the
command line will be used to bind the connection to BGP peers, so
should be on one of the VLAN tagged interfaces (with appropriate
routing for BGP egress if the router is not on the same subnet,
eg. route reflectors).

Sample netplan and VC5 configurations are in the
[examples/](examples/) directory.


## Performance

This has mostly been tested using Icecast backend servers with clients
pulling a mix of low and high bitrate streams (48kbps - 192kbps).

It seems that a VMWare guest (4 core, 8GB) using the XDP generic
driver will comfortably support 100K concurrent clients,
380Mbps/700Kpps through the load balancer and 8Gbps of traffic from
the backends directly to the clients.

A server with an Intel Xeon CPU (E52620 @ 2.40GHz) with 6 physical
cores and an Intel 10Gbps NIC (ixgbe driver) in native mode will
support upwards of 500K clients, 2Gbps/3.5Mpps and 40Gbps traffic back
to clients. This was at a load of ~25% on the CPU - clearly it can do
significantly more than this, but resources for running more client
and backend servers were not available at the time.



## TODOs

* IPIP/GRE/DSCP L3 support
* Least conns support / Take most loaded server out of pool
* Multicast status to help last conns check
* More complete BGP4 implementation
* BFD implementation

## Configuration

The [docs/config.yaml](docs/config.yaml) file should have a commentary
detailing the structure. To see the underlying JSON structure, you can
run `tools/config.pl docs/config.yaml`. The JSON format is significantly
more verbose and everything is explicitly specified.

The goal of the YAML format is to have a reasonably concise
human-readable configuration which is then rendered into an explcit
format. If the YAML format does not quite suit your needs then you can
write your own generator (eg. for a HAProxy L7 balancing layer behind the
L4 layer, with a single config format used to generate both HAProxy
and VC5 configurations).


## Notes

https://wiki.nftables.org/wiki-nftables/index.php/Performing_Network_Address_Translation_(NAT)

https://unix.stackexchange.com/questions/429077/how-to-do-nat-based-on-port-number-in-stateless-nat


Set destination IP address on real server by DSCP - for L3 DSR

* `nft add table raw`
* `nft add chain raw prerouting { type filter hook prerouting priority raw \; }`
* `nft add rule raw prerouting ip dscp 0x04 ip daddr set 192.168.101.4 notrack`

https://lpc.events/event/11/contributions/950/attachments/889/1704/lpc_from_xdp_to_socket_fb.pdf

https://github.com/xdp-project/xdp-tutorial.git

