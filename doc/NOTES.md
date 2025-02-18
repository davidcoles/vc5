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

## Elasticsearch

wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add -

echo "deb https://artifacts.elastic.co/packages/7.x/apt stable main" | \
	sudo tee -a /etc/apt/sources.list.d/elastic-7.x.list
	
apt update
apt install elasticsearch kibana

cat >>/etc/elasticsearch/elasticsearch.yml <<EOF
xpack.security.enabled: true
discovery.type: single-node
# default to false if ssl not enabled
xpack.security.authc.api_key.enabled: true
EOF

systemctl enable elasticsearch
systemctl start elasticsearch


/usr/share/elasticsearch/bin/elasticsearch-setup-passwords auto

# not the passwords somewhere ...
# edit /etc/kibana/kibana.yml and update:
#  elasticsearch.username: "kibana_system"
#  elasticsearch.password: "..."

systemctl enable kibana
systemctl start kibana



# to have index lifecycle management ...

# create index template (eg. "lbtemplate", index pattern "lb-*, tick "create data stream", ")

"Index settings" like:
{
  "index": {
    "lifecycle": {
      "name": "7-days-default"
    },
    "number_of_replicas": "0"
  }
}

Set mappings, (need to fully spec this out) eg.:
  "mappings": {
    "properties": {
      "@timestamp": {
        "type": "date"
      },
      "destintation": {
        "properties": {
          "ip": {
            "type": "ip"
          },
          "mac": {
            "type": "keyword"
          },
          "nat": {
            "properties": {
              "ip": {
                "type": "ip"
              }
            }
          },
          "port": {
            "type": "byte"
          }
        }
      },
      "event": {
        "properties": {
          "action": {
            "type": "keyword"
          },
          "module": {
            "type": "keyword"
          },
          "type": {
            "type": "keyword"
          }
        }
      }
    }
  },


Set aliases, eg.:
{
  "myindexname": {},
}

add permissions to lb user's role for "lb-myindexname" and "myindexname" to "write"

user=elastic
pass=...
index=myindexname

# remove previous copies if necessary
curl -u "$user:$pass" -X DELETE http://localhost:9200/lb-${index}/_alias/${index}
curl -u "$user:$pass" -X DELETE http://localhost:9200/_data_stream/lb-${index}

# create index
curl -u "$user:$pass" -X POST --header 'Content-Type: application/json' \
     --data @- http://localhost:9200/lb-${index}/_doc <<EOF
{
  "@timestamp": 0
}
EOF

# create the alias
curl -u "$user:$pass" -X POST --header 'Content-Type: application/json' \
     --data @- http://localhost:9200/_aliases <<EOF
{
 "actions": [
  {
   "add": {
    "index": "lb-${index}",
    "alias": "${index}",
    "is_write_index": true
   }
  }
 ]
}
EOF


create index pattern to match





regular non-templated index ...

curl -u "$user:$pass" -X DELETE http://localhost:9200/$index

curl -u "$user:$pass" -X PUT --header 'Content-Type: application/json' \
     --data @- http://localhost:9200/$index <<EOF
{
 "mappings": {
  "properties": {
   "date": {
    "type": "date"
   }
  }
 } 
}
EOF

in kibana:
stack management -> index patterns -> create index pattern
...
roles -> create role -> load-balancer : index perms on my-index-name
users -> create user -> load-balancer : roles->load-balancer

edit logging params ...

logging:
  elasticsearch:
    addresses:
      - http://10.9.8.7:9200/
	  # add more addresses if you have a cluster
    index: my-index-name
    username: load-balancer
    password: Rarkensh1droj



echo "deb [signed-by=/etc/apt/keyrings/elastic.gpg] https://artifacts.elastic.co/packages/7.x/apt stable main" >/etc/apt/sources.list.d/elastic-7.x.list

cat >/etc/apt/keyrings/elastic.gpg <<EOF
-----BEGIN PGP PUBLIC KEY BLOCK-----
mQENBFI3HsoBCADXDtbNJnxbPqB1vDNtCsqhe49vFYsZN9IOZsZXgp7aHjh6CJBD
A+bGFOwyhbd7at35jQjWAw1O3cfYsKAmFy+Ar3LHCMkV3oZspJACTIgCrwnkic/9
CUliQe324qvObU2QRtP4Fl0zWcfb/S8UYzWXWIFuJqMvE9MaRY1bwUBvzoqavLGZ
j3SF1SPO+TB5QrHkrQHBsmX+Jda6d4Ylt8/t6CvMwgQNlrlzIO9WT+YN6zS+sqHd
1YK/aY5qhoLNhp9G/HxhcSVCkLq8SStj1ZZ1S9juBPoXV1ZWNbxFNGwOh/NYGldD
2kmBf3YgCqeLzHahsAEpvAm8TBa7Q9W21C8vABEBAAG0RUVsYXN0aWNzZWFyY2gg
KEVsYXN0aWNzZWFyY2ggU2lnbmluZyBLZXkpIDxkZXZfb3BzQGVsYXN0aWNzZWFy
Y2gub3JnPokBTgQTAQgAOAIbAwIXgBYhBEYJWsyFSFgsGiaZqdJ9ZmzYjkK0BQJk
9vrZBQsJCAcDBRUKCQgLBRYCAwEAAh4FAAoJENJ9ZmzYjkK00hoH+wYXZKgVb3Wv
4AA/+T1IAf7edwgajr58bEyqds6/4v6uZBneUaqahUqMXgLFRX5dBSrAS7bvE/jx
+BBQx+rpFGxSwvFegRevE1zAGVtpgkFQX0RpRcKSmksucSBxikR/dPn9XdJSEVa8
vPcs11V+2E5tq3LEP14zJL4MkJKQF0VJl5UUmKLS7U2F/IB5aXry9UWdMTnwNntX
kl2iDaViYF4MC6xTS24uLwND2St0Jvjt+xGEwbdBVvp+UZ/kG6IGkYM5eWGPuok/
DHvjUdwTfyO9b5xGbqn5FJ3UFOwB/nOSFXHM8rsHRT/67gHcIl8YFqSQXpIkk9D3
dCY+KieW0ue5AQ0EUjceygEIAOSVJc3DFuf3LsmUfGpUmnCqoUm76Eqqm8xynFEG
ZpczTChkwARRtckcfa/sGv376j+jk0c0Q71Uv3MnMLPGF+w3bpu8fLiPeW/cntf1
8uZ6DxJvHA/oaZZ6VPjwUGSeVydiPtZfTYsceO8Dxl3gpS6nHZ9Gsnfr/kcH9/11
Ca73HBtmGVIkOI1mZKMbANO8cewY/i7fPxShu7B0Rb3jxVNGUuiRcfRiao0gWx0U
ZGpvuHplt7loFX2cbsHFAp9WsjYEbSohb/Y0K4NkyFhL82MfbcsEwsXPhRTFgJWw
s4vpuFg/kFFlnw0NNPVP1jNJLNCsMBMEpP1A7k6MRpylNnUAEQEAAYkBNgQYAQgA
IAIbDBYhBEYJWsyFSFgsGiaZqdJ9ZmzYjkK0BQJk9vsHAAoJENJ9ZmzYjkK0hWsH
/ArKtn12HM3+41zYo9qO4rTri7+IYTjSB/JDTOusZgZLd/HCp1xQo4SI2Eur3Rtx
USMWK1LEeBzsjwDT9yVceYekrBEqUVyRMSVYj+UeZK2s4LbXm9b4jxXVtaivmkMA
jtznndrD7kmm8ak+UsZplf6p6uZS9TZ9hjwoMmw5oMaS6TZkLT4KYGWeyzHJSUBX
YikY6vssDQu4SJ07m1f4Hz81J39QOcHln5I5HTK8Rh/VUFcxNnGg9360g55wWpiF
eUTeMyoXpOtffiUhiOtbRYsmSYC0D4Fd5yJnO3n1pwnVVVsM7RAC22rc5j/Dw8dR
GIHikRcYWeXTYW7veewK5Ss=
=ftS0
-----END PGP PUBLIC KEY BLOCK-----
EOF



Foo-over-UDP aplication server setup:

/etc/networkd-dispatcher/routable.d/50-ifup-hooks:
#!/bin/sh
ip fou add port 9999 ipproto 4
ip link set dev tunl0 up
sysctl -w net.ipv4.conf.tunl0.rp_filter=0
sysctl -w net.ipv4.conf.all.rp_filter=0

/etc/modules:
fou
ipip


CHEETAH: https://www.usenix.org/system/files/nsdi20-paper-barbette.pdf
https://blog.cloudflare.com/high-availability-load-balancers-with-maglev/
https://blog.cloudflare.com/path-mtu-discovery-in-practice/

https://datatracker.ietf.org/doc/html/draft-jaeggli-v6ops-pmtud-ecmp-problem-00
https://www.ietf.org/rfc/rfc4821.txt

https://github.com/netprickle/ipipou
https://developers.redhat.com/blog/2019/05/17/an-introduction-to-linux-virtual-interfaces-tunnels#
https://serverfault.com/questions/1167848/building-a-gre-tunnel-with-netplan
https://www.redhat.com/en/blog/what-geneve
https://www.iana.org/assignments/iana-ipv6-special-registry/iana-ipv6-special-registry.xhtml

https://fedepaol.github.io/blog/2023/09/06/ebpf-journey-by-examples-l4-load-balancing-with-xdp-and-katran/
https://github.com/fedepaol/ebpfexamples/tree/main/xdpkatransample

https://www.datadoghq.com/blog/xdp-intro/
https://www.mankier.com/8/xdpdump

https://fedepaol.github.io/blog/2023/09/11/xdp-ate-my-packets-and-how-i-debugged-it/
https://lore.kernel.org/xdp-newbies/eeb4f9da-d896-0806-80a6-c8ca3f7a285b@gmail.com/T/

https://medium.com/swlh/building-a-xdp-express-data-path-based-peering-router-20db4995da66
https://patchwork.ozlabs.org/project/netdev/patch/20180425183449.25134-9-dsahern@gmail.com/
