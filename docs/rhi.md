# Route Health Injection

Route Health Injection (RHI) is a mechanism by which a load balancer
advertises the availabilty of the virtual addresses for which it
provides services.

VC5 uses [BGP](https://en.wikipedia.org/wiki/Border_Gateway_Protocol)
to advertise VIPs as /32 prefixes to BGP enabled routers.

## Examples

A minimal example of the RHI configuration would be:

```yaml
rhi:
  as_number: 65000
  peers:
    - 10.1.2.1
    - 10.1.2.2
```

The above will advertise all healthy VIPs to suitably configured peers
at 10.1.2.1 and 10.1.2.2. There is no need to specify the remote AS
number; VC5 does not accept incoming BGP sessions and it ignores any
UPDATE messages from the peer.

Should you need a more complex setup, VC5 has settings for standard
BGP parameters, route filters and groups of peers.

Accept filters are checked first. If an address matches it is
immediately accepted. Otherwise if a reject rule matches then the VIP
is filtered out. If neither set of rules matches then the default
behaviour is to accept the VIP for advertisement.


```yaml
rhi:
  as_number: 65000
  hold_time: 8
  groups:
    - name: group-a
      local_pref: 200
      peers:
        - 10.1.2.1
        - 10.1.2.2
      reject:
        - 192.168.101.1
        - 192.168.101.2
        - foo
        - bar
      communities:
        - 65304:100
        - 65304:200

    - name: group-b
      as_number: 65123
      source_ip: 10.100.200.10
      hold_time: 20
      med: 200
      peers:
        - 10.100.200.1
        - 10.100.200.2
      accept:
        - 192.168.101.1
        - 192.168.101.2
      reject:
        - any
      communities:
        - 65123:300
        - 65123:400
                
prefixes:
  foo:
    - 192.168.102/24
    - 192.168.103/24
  bar:
    - 192.168.101.3
    - 192.168.101.4
```

Here, peers 10.1.2.1 and 10.1.2.2 will receive advertisements for all
VIPs *except* 192.168.101.1, 192.168.101.2, 192.168.101.3,
192.168.101.4 and any VIPs in the 192.168.102/24 and 192.168.103/24
ranges. The local AS number will be 65000, with a hold time of 8,
local preference value of 200 and communities of 65304:100 and
65304:200 will be attached.

Peers 10.100.200.1 and 10.100.200.2 will *only* advertise VIPs
192.168.101.1 and 192.168.101.2. The local AS number will be 65123,
the connection will be sourced from the local address of
10.100.200.10, and this will be the advertised next hop. A Multi Exit
Discriminator of 200 and communities 65123:300 and 65123:400 will be
present in the UPDATE messages.

Prefix lists can be declared in a `prefixes` block and referred to by
name. The value of `any` is pre-declared as 0.0.0.0/0.

## Reconfiguration

When the RHI configuration is changed and the reload signal sent to
the daemon any new peers are started and peers no longer confgured are
sent a cease message and are removed.

Any configuration changes to extant peers are made immediately and
network layer reachability information is sent in an UPDATE message to
update local preference, MED, communities, etc.

Currently, AS number (in AS_SEQUENCE) and NEXT_HOP address (from
source_ip) are not changed in any established connection. When the
session is re-established the new values will be used.


## BIRD sample configuration

If you don't have control over your routers then you can test with a
client machine on the same VLAN. Either add a static route on the
client machine pointing to the load balancer, or run BIRD/Quagga on
the client and add the client's IP address to the BGP section of the
YAML config.

Sample bird.conf snippet (BIRD v2):

```
protocol bgp loadbalancers {
     description "loadbalancers";
     local as 65000;
     neighbor range 10.10.100.0/24 as 65000;
     passive on;
     direct;

     ipv4 {
          export none;
          import filter {
                 if net ~ 192.168.101.0/24 then accept;
                 else reject;
          };
          next hop self;
     };
}
```

This will allow any load balancers in the 10.10.100.0/24 subnet to
connect as AS 65000 and advertise VIPs in 192.168.101.0/24 range;

If you enable ECMP on your router/client (`merge paths on;` in BIRD's
kernel protocol) then you can distribute traffic to multiple load
balancers.
