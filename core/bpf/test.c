/*
 * VC5 load balancer. Copyright (C) 2021-present David Coles
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <stdlib.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>

#include <linux/ipv6.h>
#include <linux/in6.h>

#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#include <net/if.h>
#include <linux/bpf.h>
#include <string.h>


#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>


struct tuple {
    __be32 src;
    __be32 dst;
    __be16 sport;
    __be16 dport;
    __u8 protocol;
    __u8 pad[3];
};

static inline void maccpy(unsigned char *dst, unsigned char *src) {
    dst[0] = src[0];
    dst[1] = src[1];
    dst[2] = src[2];
    dst[3] = src[3];
    dst[4] = src[4];
    dst[5] = src[5];
}

static inline int nulmac(unsigned char *mac) {
    return (mac[0] == 0 && mac[1] == 0 && mac[2] == 0 && mac[3] == 0 && mac[4] == 0 && mac[5] == 0);
}

static inline int equmac(unsigned char *a, unsigned char *b) {
    return (a[0] == b[0] && a[1] == b[1] && a[2] == b[2] && a[3] == b[3] && a[4] == b[4] && a[5] == b[5]);
}

#define MAX_TCP_SIZE 1480

static inline unsigned short generic_checksum(unsigned short *buf, void *data_end, unsigned long sum, int max) {
    
    for (int i = 0; i < max; i += 2) {
	if ((void *)(buf + 1) > data_end)
	    break;
        sum += *buf;
        buf++;
    }

    if((void *)buf +1 <= data_end) {
	sum +=  bpf_htons((*((unsigned char *)buf)) << 8);
    }

    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);
    return ~sum;
}


static inline unsigned short ipv4_checksum(unsigned short *buf, void *data_end)
{
    return generic_checksum(buf, data_end, 0, sizeof(struct iphdr));
}

static inline __u16 l4_checksum(struct iphdr *iph, void *l4, void *data_end)
{
    __u32 csum = 0;
    csum += *(((__u16 *) &(iph->saddr))+0); // 1st 2 bytes
    csum += *(((__u16 *) &(iph->saddr))+1); // 2nd 2 bytes
    csum += *(((__u16 *) &(iph->daddr))+0); // 1st 2 bytes
    csum += *(((__u16 *) &(iph->daddr))+1); // 2nd 2 bytes
    csum += bpf_htons((__u16)iph->protocol); // protocol is a u8
    csum += bpf_htons((__u16)(data_end - (void *)l4)); 
    return generic_checksum((unsigned short *) l4, data_end, csum, MAX_TCP_SIZE);
}


static inline __u16 sdbm(unsigned char *ptr, __u8 len) {
    unsigned long hash = 0;
    unsigned char c;
    unsigned int n;

    for(n = 0; n < len; n++) {
        c = ptr[n];
        hash = c + (hash << 6) + (hash << 16) - hash;
    }

    return hash & 0xffff;
}

struct backend {
    __be32 ip;
    __u8 mac[6];
    __u8 local;
    __u8 pad;
};

struct table {
    __u8 be[8192];
};

struct service {
    __be32 ip;
    __be16 port;
    __be16 pad;
};

struct vipmac {
    __be32 vip;
    __u8 mac[6];
};

struct nat {
    __be32 dstip;
    __u8 dstmac[6];
    __u8 srcmac[6];
    __be32 srcip;
    __u32 ifindex;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, unsigned int);
    __type(value, struct backend);
    __uint(max_entries, 256);
} backends SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct service);
    __type(value, struct table);
    __uint(max_entries, 256);
} services SEC(".maps");


/**********************************************************************/

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u8[4]);
    __type(value, struct nat);
    __uint(max_entries, 1024);
} nat_to_vip_mac SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u8[10]);
    __type(value, struct nat);
    __uint(max_entries, 1024);
} vip_mac_to_nat SEC(".maps");


/**********************************************************************/

SEC("xdp_main") int xdp_main_func(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;

    struct ethhdr *eth_hdr = data;
    __u32 nh_off = sizeof(struct ethhdr);
    __be16 eth_proto;
    
  if (data + nh_off > data_end) {
    return XDP_DROP;
  }

  eth_proto = eth_hdr->h_proto;

  if (eth_proto != bpf_ntohs(ETH_P_IP)) {
      return XDP_PASS;
  }
  
  struct iphdr *ipv4 = data + nh_off;
  
  nh_off += sizeof(struct iphdr);

  if (data + nh_off > data_end) {
      return XDP_DROP;
  }

  if (ipv4->protocol != IPPROTO_TCP) {
      return XDP_PASS;
  }

  struct tcphdr *tcp = data + nh_off;

  nh_off += sizeof(struct tcphdr);
  
  if (data + nh_off > data_end) {
      return XDP_DROP;
  }

  struct service s;
  memset(&s, 0, sizeof(s));
  s.ip = ipv4->daddr;
  s.port = tcp->dest;
      
  __u8 *table = NULL;
  
  if((table = bpf_map_lookup_elem(&services, &s))) {
      struct tuple t;
      memset(&t, 0, sizeof(t));
      t.src = ipv4->saddr;
      t.dst = ipv4->daddr;
      t.sport = tcp->source;
      t.dport = tcp->dest;
      t.protocol = IPPROTO_TCP;

      __u16 hash = sdbm((unsigned char *)&t, sizeof(t));
      
      unsigned int i = table[hash>>3];
      
      if(i == 0) {
	  return XDP_DROP;
      }
      
      struct backend *be = bpf_map_lookup_elem(&backends, &i);

      if(!be) {
	  return XDP_DROP;
      }
      
      if(be->local) {
	  return XDP_PASS;
      }

      if(nulmac(be->mac)) {
	  return XDP_DROP;
      }
      
      if(equmac(be->mac, eth_hdr->h_dest)) {
          return XDP_DROP; // looks like local NIC, but not declared as such
      }

      if(equmac(be->mac, eth_hdr->h_source)) {
          return XDP_DROP; // unlikely that we would want to echo packet back to source on an l2lb
      }
      
      maccpy(eth_hdr->h_source, eth_hdr->h_dest);
      maccpy(eth_hdr->h_dest, be->mac);
      
      return XDP_TX;
  }

  s.port = 0;
  if((table = bpf_map_lookup_elem(&services, &s))) {
      return XDP_DROP;
  }

  struct nat *vme = bpf_map_lookup_elem(&nat_to_vip_mac, &(ipv4->daddr));
  if (vme) {

      if(!(vme->ifindex)) {         // local backend
	  ipv4->daddr = vme->dstip; // vip addr, but keep 10.255.255.254 as src
	  ipv4->ttl = 1;            // prevent packet from escaping into the wild
      } else {
	  ipv4->saddr = vme->srcip;
	  ipv4->daddr = vme->dstip;
	  maccpy(eth_hdr->h_source, vme->srcmac);
	  maccpy(eth_hdr->h_dest, vme->dstmac);
      }
      
      ipv4->check = 0;
      ipv4->check = ipv4_checksum((void *) ipv4, (void *)tcp);
      
      tcp->check = 0;
      tcp->check = l4_checksum(ipv4, tcp, data_end);

      if(!(vme->ifindex)) {
	  return XDP_PASS;
      }
      
      return bpf_redirect(vme->ifindex, 0);
  }


  struct vipmac vm;
  vm.vip = ipv4->saddr;
  maccpy(vm.mac, eth_hdr->h_source);
  
  vme = bpf_map_lookup_elem(&vip_mac_to_nat, &vm);
  if (vme) {
      if(!(vme->ifindex)) {         // local backend
	  ipv4->saddr = vme->srcip; // change vip to nat, but dst should be unchanged
	  ipv4->ttl = 1;            // prevent packet from escaping into the wild	  
      } else {
	  ipv4->saddr = vme->srcip; // (nat addr)
	  ipv4->daddr = vme->dstip; // (vc5vb adr)
	  maccpy(eth_hdr->h_dest, vme->dstmac);
	  //maccpy(eth_hdr->h_source, vme->srcmac);
      }
      
      ipv4->check = 0;
      ipv4->check = ipv4_checksum((void *) ipv4, (void *)tcp);
      
      tcp->check = 0;
      tcp->check = l4_checksum(ipv4, tcp, data_end);

      if(!(vme->ifindex)) {
	  return XDP_PASS;
      }
      
      return bpf_redirect(vme->ifindex, 0);
  }
  
  return XDP_PASS;
}

char _license[] SEC("license") = "GPL";

/* Copied from: $KERNEL/include/uapi/linux/bpf.h
 *
 * User return codes for XDP prog type.
 * A valid XDP program must return one of these defined values. All other
 * return codes are reserved for future use. Unknown return codes will
 * result in packet drops and a warning via bpf_warn_invalid_xdp_action().
 *
enum xdp_action {
	XDP_ABORTED = 0,
	XDP_DROP,
	XDP_PASS,
	XDP_TX,
	XDP_REDIRECT,
};

 * user accessible metadata for XDP packet hook
 * new fields must be added to the end of this structure
 *
struct xdp_md {
	// (Note: type __u32 is NOT the real-type)
	__u32 data;
	__u32 data_end;
	__u32 data_meta;
	// Below access go through struct xdp_rxq_info
	__u32 ingress_ifindex; // rxq->dev->ifindex
	__u32 rx_queue_index;  // rxq->queue_index
};
*/
