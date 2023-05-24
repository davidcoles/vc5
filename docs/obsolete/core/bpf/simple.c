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

#define NBACKENDS 3

unsigned char s0[6] = {0x00,0x50,0x56,0x90,0xf9,0x47};
unsigned char s1[6] = {0x00,0x50,0x56,0x90,0x7a,0x37};
unsigned char s2[6] = {0x00,0x50,0x56,0x90,0x3a,0x82};
unsigned char s3[6] = {0x00,0x50,0x56,0x90,0xe8,0x9c};
unsigned char s4[6] = {0x00,0x50,0x56,0x90,0x75,0x7c};
unsigned char s5[6] = {0x00,0x50,0x56,0x90,0x8a,0x50};
unsigned char s6[6] = {0x00,0x50,0x56,0x90,0x60,0xec};
unsigned char s7[6] = {0x00,0x50,0x56,0x90,0x8d,0x92};
unsigned char s8[6] = {0x00,0x50,0x56,0x90,0x2e,0xb9};
unsigned char s9[6] = {0x00,0x50,0x56,0x90,0x5e,0x13};
unsigned char sa[6] = {0x00,0x50,0x56,0x90,0xbe,0x66};
unsigned char sb[6] = {0x00,0x50,0x56,0x90,0xde,0x65};
unsigned char sc[6] = {0x00,0x50,0x56,0x90,0xa6,0xf1};
unsigned char sd[6] = {0x00,0x50,0x56,0x90,0x69,0x98};
unsigned char se[6] = {0x00,0x50,0x56,0x90,0xf5,0xbf};
unsigned char sf[6] = {0x00,0x50,0x56,0x90,0x57,0x91};

struct counter {
    __u64 count;
    __u64 time;
};
struct bpf_map_def SEC("maps") stats = {
  .type        = BPF_MAP_TYPE_PERCPU_ARRAY,
  .key_size    = sizeof(unsigned int),
  .value_size  = sizeof(struct counter),
  .max_entries = 2,
};

SEC("xdp_main")
int  xdp_main_func(struct xdp_md *ctx)
{
    __u64 start = bpf_ktime_get_ns();
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
  
  struct tuple t;
  t.src = ipv4->saddr;
  t.dst = ipv4->daddr;
  t.sport = tcp->source;
  t.dport = tcp->dest;
  t.protocol = IPPROTO_TCP;
  t.pad[0] = 0;
  t.pad[1] = 0;
  t.pad[2] = 0;      
  
  if (ipv4->daddr == bpf_htonl((192<<24)|(168<<16)|(101<<8)|(1))) {

      maccpy(eth_hdr->h_source, eth_hdr->h_dest);
	    
      __u16 n = sdbm((unsigned char*) &t, sizeof(t));
      
      switch ((n%NBACKENDS)) {
      case 0: maccpy(eth_hdr->h_dest, s0); break;
      case 1: maccpy(eth_hdr->h_dest, s1); break;
      case 2: maccpy(eth_hdr->h_dest, s2); break;
      case 3: maccpy(eth_hdr->h_dest, s3); break;
      case 4: maccpy(eth_hdr->h_dest, s4); break;
      case 5: maccpy(eth_hdr->h_dest, s5); break;
      case 6: maccpy(eth_hdr->h_dest, s6); break;
      case 7: maccpy(eth_hdr->h_dest, s7); break;
      case 8: maccpy(eth_hdr->h_dest, s8); break;
      case 9: maccpy(eth_hdr->h_dest, s9); break;
      case 10: maccpy(eth_hdr->h_dest, sa); break;
      case 11: maccpy(eth_hdr->h_dest, sb); break;
      case 12: maccpy(eth_hdr->h_dest, sc); break;
      case 13: maccpy(eth_hdr->h_dest, sd); break;
      case 14: maccpy(eth_hdr->h_dest, se); break;
      case 15: maccpy(eth_hdr->h_dest, sf); break;
      default:
	  maccpy(eth_hdr->h_dest, s0);
      }


      int index0 = 0;
      struct counter *statsp = bpf_map_lookup_elem(&stats, &index0);
      if (!statsp) {
	  return XDP_PASS;
      }

      statsp->count++;
      statsp->time += (bpf_ktime_get_ns() - start);
      return XDP_TX;
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






/*
static inline unsigned short checksum_sum(unsigned short *buf, int bufsz, unsigned long sum) {
    //unsigned long sum = 0;

    while (bufsz > 1) {
        sum += *buf;
        buf++;
        bufsz -= 2;
    }

    if (bufsz == 1) {
        sum += *(unsigned char *)buf;
    }

    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);

    return ~sum;
}
*/
//static inline unsigned short checksum_ptr(unsigned short *buf, void *end, unsigned long sum) {
//    return checksum_sum(buf, (end - (void *)buf)+1, sum);
//}

/*
static inline unsigned short checksum(unsigned short *buf, int bufsz) {
    return checksum_ptr(buf, ((void *) buf) + (bufsz-1), 0);
}
*/
