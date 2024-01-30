
## Introduction (Why? What? How?)

This software is intended to replace the need for medium-to-large load
balancing appliances handling tens-to-hundreds of Gbit/s levels of
outbound traffic. Depending on application, hundreds of thousands, to
millions, of concurrently connected clients is the target.

VC5 uses a high-speed data path in the Linux kernel to switch traffic
at somewhere near wire speed on 10Gbit/s interfaces. When a packet is
received for a target service, a routine (which is loaded into the
running kernel with XDP), will replace the destination MAC address of
the packet with the address of one of the real servers in the
load-balancing pool and then bounce the packet straight back out of
the same interface on which it was received (changing VLAN tag, if
necessary).

When the real server receives the packet it sees the VIP (which it has
configured on a loopback interface) directed to its own MAC address,
processes the packet appropriately and sends the reply directly back
to the client, short-circuiting the load balancer. This is the Direct
Server Return model of load-balancing. A similar layer-3 version of
this is possible too (eg. using DSCP signalling, GRE or IP-in-IP
encapsulation), but this is not yet implemented.

The majority of traffic is likely to be asymmetric, with just a small
amount of traffic being sent to the server as (eg.) an HTTP request
and a significantly larger response sent back as a webpage or media
file. Because of this asymmetry, a load-balancer - which is only
involved in the receive path - can support, say, 100Gbit/s per second
downstream connection by only dealing with 10Gbit/s of request traffic
(HTTP request headers and ACK packets).

The VIP for the service is advertised to routers with BGP. Adding a
second instance results in the same IP
address being reachable from two different paths. If the router
supports Equal Cost Multi-Path (ECMP) routing then the traffic to the
VIP is balanced across both load balancing instances. Adding more
instances will horizintally scale the amount of traffic which can be
handled.

This is all good until something fails. With a basic hashing scheme
for backend servers, the failure of a single server results in the
hash of the 4-tuple (src/dst IP and port numbers) identifying the
connection ending up pointing to a different backend server, breaking
the connection. VC5 uses a rendezvous hashing scheme, which doesn't
have this property. When a new server is added to the pool then 1-in-N
connections would be disrupted. To avoid this each connection's state
is tracked in a local table.

If one of the load balalncers in an ECMP group fails then traffic will
be redistributed to a surviving instance. Quite probably the
rendezvous hashing scheme will select the right backend (as all LBs
see the same backends), but if the backend servers have changed since
the connection was established then this may not be the case and the
connection will be reset.

To avoid this, each load-balancing instance periodically multicasts
state information about active connections. In the event of an LB
instance failure, short-lived connections whould be maintained by the
hashing scheme and longer-lived connections should be maintained by
distributing state.

When the VC5 binary is run, a small embedded eBPF program is loaded
into the kernel with XDP. VC5 continues to run and populates XDP data
structures from userspace according to the contents of the JSON
configuration file. Healthchecks are run against backend servers and
the results are written to data structures in the kernel via XDP. The
packet processing code in the kernel reads the XDP data structures and
steers the traffic accordingly.
