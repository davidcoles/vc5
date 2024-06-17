# BGP configuration

## Loopback BGP mode

If the `-A` flag is used to specify an autonomous system number then
loopback BGP mode is enabled. This will override the config file and
connect to a local BGP peer on the 127.0.0.1 address to advertise
VIPs. From there the prefixes can be re-advertised into your network
by your chosen implementation.

The following (complete) [BIRD](https://bird.network.cz/) v2.0
configuration file will work with the flag set to `-A 65001`, for
example.


```
log syslog all;
protocol device {}
protocol bfd {}

filter vips {
    bgp_community.add((65001,666));                   # mutate the prefixes that we re-advertise
    if net ~ [ 192.168.101.0/24{32,32} ] then accept; # accept /32 prefixes from 192.168.101.0/24
    reject;
}

protocol bgp core {
    local as 65001;
    neighbor as 65000;
    neighbor 10.12.34.56;
    ipv4 { export filter vips; import none; next hop self; };
    bfd on; # no need to use a low hold time with BFD
}

protocol bgp vc5 {
    local as 65001;
    neighbor as 65001;  # iBGP - we could use eBGP if we specify 'multihop'
    neighbor 127.0.0.1; # load balancer connects on the loopback interface
    passive;            # load balancer will only ever connect to us
    ipv4 { export none; import all; };
}
```

Because the network interfaces get briefly "stunned" when BPF code is
loaded, you may see BGP sessions to peer routers go down when the load
balancer is started. To overcome this in the case of bonded interfaces
I will add a delay option to the
[xvs](https://github.com/davidcoles/xvs) library which will prevent
all of the members being hit at the same time.

I have tried this locally (patches to follow), and it seems to work
well, although peer BFD may need to be tweaked slightly - this worked
for me on a peer talking to the BIRD load balancer config above:

```
protocol bfd {
    interface "ens*" {
        min rx interval 20 ms;
        min tx interval 50 ms;
        idle tx interval 300 ms;
        multiplier 8;
    };

    neighbor 10.12.34.99;
}
```
