# VC5

A distributed Layer 2 Direct Server Return (L2DSR) load balancer for Linux using XDP/eBPF

This is very much a proof of concept at this stage - most everything is incomplete and poorly defined!

## Homepage

The code is hosted at GitHub, https://github.com/davidcoles/vc5

Clone with `git clone https://github.com/davidcoles/vc5.git`


## Quickstart

It would be recommended to start out using a fresh virtual machine.

First we need a development environment capable of building libbpf and Go binaries. Go 1.16 or later is needed due to using go:embed directives. On Ubuntu 20.04 this can be achieved with:

  `apt-get install git build-essential libelf-dev clang libc6-dev libc6-dev-i386 llvm golang-1.16 libyaml-perl libjson-perl ethtool`
  
  `ln -s /usr/lib/go-1.16/bin/go /usr/local/bin/go`

Copy the config.yaml file to vc5.yaml and edit appropriately for your routers/services/backends.

Run `make`. This will build the binary and transform the YAML config file to an more verbose JSON config.

Run the vc5.sh shell script with arguments of your IP address and network interface name, eg.:

  `./vc5.sh 10.10.100.200 ens192`

If this doesn't bomb out then you should have a load balancer up and running, although by default it will wait for around one minute to learn from other instances via multicast before healthchecking backends and advertising routes. You can add static routing to forward traffic for a VIP to the load balancer, or configure BGP peers in the YAML file to have routes automatically injected. You will see that an virtual ethernet device and a net namespace has been added. These should be removed when the binary exists (use Ctrl-C).

If you don't have a routed environment then you can test with a client machine on the same VLAN. Either add a static route on the client machine pointing to the load balancer, or run BIRD/Quagga on client and add the client's IP address to the BGP section of the YAML config.

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

If you enable ECMP on your router/client ("merge paths on;" in BIRD's kernel protocol) then you can load balance traffic to multiple load balancers. VC5 uses multicast to share a flow state table so peers will learn about each other's connections and take over in the case of one load balancer going down.

To use native driver mode in XDP a slighly more involved network setup is needed at this stage. Run your physical interface in a bridge (see sample netplan config in bridge.yaml) and add the -b flag to vc5.sh as so:

  `./vc5.sh -b br0 10.10.100.200 enp130s0f1`

## Performance

This has mostly been tested using Icecast backend servers with clients pulling a mix of low and high bitrate streams (48kbps - 192kbps).

It seems that a VMWare guest (4 core, 8GB) using the XDP generic driver will comfortably support 100K concurrent clients, 380Mbps/700Kpps through the load balancer and 8Gbps of traffic from the backends directly to the clients.

A server with an Intel Xeon CPU (E52620 @ 2.40GHz) with 6 physical cores and an Intel 10Gbps NIC (ixgbe driver) in native mode will support upwards of 500K clients, 2Gbps/3.5Mpps and 40Gbps traffic back to clients. This was at a load of ~25% on the CPU - clearly it can do significantly more than this, but resources for running more client and backend servers were not available at the time.

## TODOs

* Better check flexibility - eg. 3 out of 5
* Least conns support
* Multicast status to help last conns check
* Take most loaded server out of pool
* More complete BGP4 implementation
* BFD implementation
* VLAN support
* GRE/DSCP L3 support

## Configuration

### Route Health Injection

The rhi section contains the AS number to use and a list of
peers. Currently, the BGP4 implementation does not listen on
port 179. The IP address specified on the command line will be used as
the router ID.

RHI will only advertise a service's IP address if all services on all ports using that IP address pass healthchecks. All healthchecks listed for a port (http/https/tcp) must pass if specified.


### Services

A service consist of 

* name - a string, the name of the service
* desc - a string, a description of the service
* addr - an VIP address, or list of VIP addresses, for the service
* port - an integer or list of integers, that the service consist of
* real - a name, or list of names, that references groups of real IP address in the "reals" section
* need - number of real servers that need to be available for the service to be declared healthy (default: 1)
* checks - a list of checks that must all pass for the service to be declared healthy.

### Checks

A check consists of

* name - a string describing the check
* type - http, https or tcp
* port - the port that the check will be run against, optional if there is only one port listed in the service
* path - the path to run http or https checks against, not needed for tcp


## Notes

https://wiki.nftables.org/wiki-nftables/index.php/Performing_Network_Address_Translation_(NAT)

https://unix.stackexchange.com/questions/429077/how-to-do-nat-based-on-port-number-in-stateless-nat


Set destination IP address on real server by DSCP - for L3 DSR

`nft add table raw`
`nft add chain raw prerouting { type filter hook prerouting priority raw \; }`
`nft add rule raw prerouting ip dscp 0x04 ip daddr set 192.168.101.4 notrack`

