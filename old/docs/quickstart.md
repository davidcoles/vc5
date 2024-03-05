# Quickstart

## Demonstration

From a freshly created VM to a fully functional load balancer in under three minutes:

 [![Load balancer from scratch](https://davidcoles.github.io/pages/videos/vc5-install-20231128.png)](https://davidcoles.github.io/pages/videos/vc5-install-20231128.webm)
 
([MP4 version if the WEBM doesn't work for you]( https://davidcoles.github.io/pages/videos/vc5-install-20231128.mp4)).

## Detailed steps

It would be recommended to start out using a fresh virtual machine.

First we need a development environment capable of building libbpf and
Go binaries. On Ubuntu 20.04 this can be achieved
with:

  `apt-get install git build-essential libelf-dev clang libc6-dev libc6-dev-i386 llvm golang-1.20 libyaml-perl libjson-perl ethtool`
  
  `ln -s /usr/lib/go-1.20/bin/go /usr/local/bin/go`
  
(or run `make ubuntu-dependencies` which will do this for you).


Edit the [cmd/vc5.yaml](../cmd/vc5.yaml) file appropriately for your
routers/services/backends. Remember to configure the VIP on the
loopback interface on real servers. The beckend servers will need to
be on the same VLAN as the load balancer. This is because the load
balancer operates at layer 2 (MAC address switching). Layer 3
balancing is planned for a later release. Multiple VLANs can be
handled if the load balancer has a tagged interface and an IP address
configured in each VLAN (and the are VLANs declared in the config
file).

Run `make`. This will pull a copy of
[libbpf](https://github.com/libbpf/libbpf), build the binary and
transform the YAML config file to a more verbose JSON config format.

Run the `vc5` binary with arguments of the JSON file,
your IP address and network interface name, eg.:

  `cmd/vc5 cmd/vc5.json 10.10.100.200 ens192`

If this doesn't bomb out then you should have a load balancer up and
running. A virtual network device pair and network namespace will be
created for performing NATed healthchecks to VIPs on the backend
servers. A webserver (running on port 80 by default) will display
logs, statistics and backend status. There is Prometheus metrics
endpoint for collecting statistics.

To dynamically alter the services running on the load balancer, change
the YAML file appropriately and regenerate the JSON file (`make
cmd/vc5.json`). Sending a USR2 signal to the main process will cause
it to reload the JSON configuration file and apply any changes. The
new configuration will be reflected in the web console.

VC5 uses multicast to share a flow state table so peers
will learn about each other's connections and take over in the case of
one load balancer going down.

