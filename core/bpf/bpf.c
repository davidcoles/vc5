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

#ifndef lock_xadd
#define lock_xadd(ptr, val) ((void) __sync_fetch_and_add(ptr, val))
#endif

// nanoseconds ...
#define SECOND 1000000000

struct counter {
    __u64 new_flows;
    __u64 rx_packets;
    __u64 rx_bytes;
    __u64 fp_count;
    __u64 fp_time;
    __u64 qfailed;
};

struct viprip {
    __be32 vip;
    __be32 rip;
};

struct tuple {
    __be32 src;
    __be32 dst;
    __be16 sport;
    __be16 dport;
    __u8 protocol;
    __u8 pad[3];
};

struct flow {
    __be32 src;
    __be32 dst;
    __be16 sport;
    __be16 dport;
    //__u32 pad;
};

struct flow_state {
    __u8 hwaddr[6];
    __be16 vlan;
    __u64 time;
    __be32 rip;
    __u32 era;
    __u8 finrst;
    __u8 tx_port;
};

struct flow_flow_state {
    //struct flow f;
    //struct flow_state fs;
    __u8 data[sizeof(struct flow) + sizeof(struct flow_state)];
};

struct mac {
    __u8 hwaddr[6];
};


struct service {
    __be32 vip;
    __be16 ports;
    __u8 proto;
    __u8 pad;
    //__be16 pad;
};

struct vip_rip_port {
    __be32 vip;
    __be32 rip;
    __be16 port;
    __u16 pad;
};

struct interface {
    unsigned int ifindex;
    __be32 ipaddr;
    unsigned char hwaddr[6];
    unsigned char pad[2];
};

struct settings {
    __u64 era;
    __u64 time;
    __u8 pad[7];
    __u8 defcon;
};

struct clocks {
    __u64 era;
    __u64 time;
    __u8 defcon;
    __u8 pad[7];
};

struct vlan_hdr {
    __be16 h_tci;
    __be16 h_proto;
};


struct vip_rip_src_if {
    __be32 vip;
    __be32 rip;
    __be32 src;
    __u32 ifindex;
    unsigned char hwaddr[6];
    __be16 vlan;
};

struct backend_rec {
    unsigned char hwaddr[6];
    __u16 vlan;
    __be32 rip;
    // was "__be32 pad"    
    __u8 tx_port;
    __u8 pad1;  
    __u16 pad2;
};

/**********************************************************************/
/* MAPS */
/**********************************************************************/

//#define PHYSICAL 0
#define VIRTUAL  1

struct bpf_map_def SEC("maps") stats = {
  .type        = BPF_MAP_TYPE_PERCPU_ARRAY,
  .key_size    = sizeof(unsigned int),
  .value_size  = sizeof(struct counter),
  .max_entries = 2,
};


struct bpf_map_def SEC("maps") clocks = {
  .type        = BPF_MAP_TYPE_ARRAY,
  .key_size    = sizeof(unsigned int),
  .value_size  = sizeof(struct clocks),
  .max_entries = 2,
};

struct bpf_map_def SEC("maps") settings = {
  .type        = BPF_MAP_TYPE_PERCPU_ARRAY,
  .key_size    = sizeof(unsigned int),
  .value_size  = sizeof(struct settings),
  .max_entries = 1,
};

struct bpf_map_def SEC("maps") vip_rip_port_counters = {
  .type        = BPF_MAP_TYPE_PERCPU_HASH,
  .key_size    = sizeof(struct vip_rip_port),
  .value_size  = sizeof(struct counter),
  .max_entries = 1024,
};

struct bpf_map_def SEC("maps") vip_rip_port_concurrent = {
  .type        = BPF_MAP_TYPE_PERCPU_HASH,
  .key_size    = sizeof(struct vip_rip_port),
  .value_size  = sizeof(__s32),
  .max_entries = 1024,
};

struct bpf_map_def SEC("maps") interfaces = {
  .type        = BPF_MAP_TYPE_ARRAY,
  .key_size    = sizeof(unsigned int),
  .value_size  = sizeof(struct interface),
  .max_entries = 2,
};

struct bpf_map_def SEC("maps") flows = {
  .type        = BPF_MAP_TYPE_LRU_HASH,
  .key_size    = sizeof(struct flow),
  .value_size  = sizeof(struct flow_state),
  .max_entries = MAX_FLOWS,
};

struct bpf_map_def SEC("maps") flow_queue = {
  .type        = BPF_MAP_TYPE_QUEUE,
  .key_size    = 0,
  .value_size  = sizeof(struct flow_flow_state),  
  .max_entries = 10000,
};


struct bpf_map_def SEC("maps") rip_to_mac = {
        .type = BPF_MAP_TYPE_HASH,
        .key_size = 4,
        .value_size = 6,
        .max_entries = 1024,
        .map_flags = 0,
};

struct bpf_map_def SEC("maps") mac_to_rip = {
        .type = BPF_MAP_TYPE_HASH,
        .key_size = 6,
        .value_size = 4,
        .max_entries = 1024,
        .map_flags = 0,
};

struct bpf_map_def SEC("maps") nat_to_vip_rip = {
        .type = BPF_MAP_TYPE_HASH,
        .key_size = 4,
        .value_size = sizeof(struct vip_rip_src_if),
        .max_entries = 1024,
        .map_flags = 0,
};

struct bpf_map_def SEC("maps") vip_rip_to_nat = {
        .type = BPF_MAP_TYPE_HASH,
        .key_size = 8,
        .value_size = 4,
        .max_entries = 1024,
        .map_flags = 0,
};


#define IDX_BITS 13
struct bpf_map_def SEC("maps") backend_recs = {
  .type        = BPF_MAP_TYPE_PERCPU_ARRAY,
  .key_size    = sizeof(unsigned int),
  .value_size  = sizeof(struct backend_rec),
  .max_entries = 256,
};

struct bpf_map_def SEC("maps") backend_idx = {
  .type        = BPF_MAP_TYPE_PERCPU_HASH,
  .key_size    = sizeof(struct service),
  .value_size  = (1<<IDX_BITS),
  .max_entries = 256,
};

struct bpf_map_def SEC("maps") tx_port = {
	.type = BPF_MAP_TYPE_DEVMAP,
	.key_size = sizeof(int),
	.value_size = sizeof(int),
	.max_entries = 255,
};

/**********************************************************************/

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

#define MAX_TCP_SIZE 1480

static inline unsigned short generic_checksum(unsigned short *buf, void *data_end,  unsigned long sum, int max) {
    //unsigned long sum = 0;

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

static inline __u16 tcp_checksum(struct iphdr *iph, struct tcphdr *tcph, void *data_end)
{
    __u32 csum = 0;
    csum += *(((__u16 *) &(iph->saddr))+0); // 1st 2 bytes
    csum += *(((__u16 *) &(iph->saddr))+1); // 2nd 2 bytes
    csum += *(((__u16 *) &(iph->daddr))+0); // 1st 2 bytes
    csum += *(((__u16 *) &(iph->daddr))+1); // 2nd 2 bytes
    csum += bpf_htons((__u16)iph->protocol); // protocol is a u8
    csum += bpf_htons((__u16)(data_end - (void *)tcph)); 
    return generic_checksum((unsigned short *) tcph, data_end, csum, MAX_TCP_SIZE);
}

/**********************************************************************/

static inline void maccpy(unsigned char *dst, unsigned char *src) {
    dst[0] = src[0];
    dst[1] = src[1];
    dst[2] = src[2];
    dst[3] = src[3];
    dst[4] = src[4];
    dst[5] = src[5];

    //*((__u32 *) dst) = *((__u32 *) src);
    //*(((__u16 *) dst)+2) = *(((__u16 *) src)+2);
}

static inline int maccmp(unsigned char *m, unsigned char *s) {
    return !(m[0] == s[0] &&
	     m[1] == s[1] &&
	     m[2] == s[2] &&
	     m[3] == s[3] &&
	     m[4] == s[4] &&
	     m[5] == s[5]);
}

static inline void push_flow_queue(struct flow *f, struct flow_state *s, struct counter *statsp) {
      
      struct flow_flow_state fs;
      void *fsp = &fs;
      memcpy(fsp, f, sizeof(struct flow));
      memcpy(fsp+sizeof(struct flow), s, sizeof(struct flow_state)); 
      
      struct flow_state *fsp_fs = fsp+sizeof(struct flow);
      fsp_fs->era = 0;
      
      if ((bpf_map_push_elem(&flow_queue, &fs, 0) != 0) && statsp) {
        statsp->qfailed++;
       }
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

static __always_inline int vlan_pop(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;
    
    struct ethhdr *eth = data;
    struct vlan_hdr *vlan = data + sizeof(struct ethhdr);
    
    if (data + sizeof(struct ethhdr) + sizeof(struct vlan_hdr) > data_end) {
	return -1;
    }
    
    struct ethhdr eth_cpy;
    __builtin_memcpy(&eth_cpy, eth, sizeof(eth_cpy));
    
    
    struct vlan_hdr vh;
    __builtin_memcpy(&vh, vlan, sizeof(vh));
    
    eth_cpy.h_proto = vh.h_proto;
    
    if (bpf_xdp_adjust_head(ctx, 4)) {
	return -1;
    }
    
    data_end = (void *)(long)ctx->data_end;
    data = (void *)(long)ctx->data;
    
    eth = data;
    
    if ((data + sizeof(struct ethhdr)) > data_end)
	return -1;
    
    __builtin_memcpy(eth, &eth_cpy, sizeof(eth_cpy));
    
    return 0;
}



static __always_inline struct backend_rec *lookup_backend_udp(struct iphdr *ipv4, struct udphdr *udp) {
    struct service serv;
    serv.vip = ipv4->daddr;
    serv.ports = udp->dest;
    serv.proto = 1;
    serv.pad = 0;

    __u8 *idx = bpf_map_lookup_elem(&backend_idx, &serv);
    if(!idx) {
	return NULL;
    }
    struct tuple t;
    t.src = ipv4->saddr;
    t.dst = ipv4->daddr;
    t.sport = udp->source;
    t.dport = udp->dest;
    t.protocol = IPPROTO_UDP;
    t.pad[0] = 0;
    t.pad[1] = 0;
    t.pad[2] = 0;
    __u16 n = sdbm((unsigned char*) &t, sizeof(t));

    unsigned int rec_idx = idx[(n & ((1<<IDX_BITS)-1))];

    if(rec_idx == 0) {
        return NULL;
    }

    return bpf_map_lookup_elem(&backend_recs, &rec_idx);
}


static __always_inline struct backend_rec *lookup_backend(struct iphdr *ipv4, struct tcphdr *tcp) {
    struct service serv;
    serv.vip = ipv4->daddr;
    serv.ports = tcp->dest;
    serv.proto = 0;
    serv.pad = 0;
    
    __u8 *idx = bpf_map_lookup_elem(&backend_idx, &serv);
    if(!idx) {
	return NULL;
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
    __u16 n = sdbm((unsigned char*) &t, sizeof(t));
    
    unsigned int rec_idx = idx[(n & ((1<<IDX_BITS)-1))];
    
    if(rec_idx == 0) {
	return NULL;
    }
    
    return bpf_map_lookup_elem(&backend_recs, &rec_idx);
}

static __always_inline void update_counters(struct iphdr *ipv4, struct tcphdr *tcp, __be32 rip, int rx_bytes, int new) {
    struct vip_rip_port vrp;
    vrp.vip = ipv4->daddr;
    vrp.rip = rip;
    vrp.port = bpf_ntohs(tcp->dest);
    vrp.pad = 0;
    
    struct counter *counter = bpf_map_lookup_elem(&vip_rip_port_counters, &vrp);
    if (counter) {
	if(new) counter->new_flows++;
	counter->rx_packets++;
	counter->rx_bytes += rx_bytes;
    }
}

static __always_inline void save_state(struct iphdr *ipv4, struct tcphdr *tcp, struct backend_rec *rec) {
    struct flow f;
    f.src = ipv4->saddr;
    f.dst = ipv4->daddr;
    f.sport = tcp->source;
    f.dport = tcp->dest;
    
    struct flow_state s;
    memset(&s, 0, sizeof(s));
    s.vlan = rec->vlan;
    //s.era = era_now;
    s.rip = rec->rip;
    //s.time = wallclock_now;
    maccpy(s.hwaddr, rec->hwaddr);
    
    bpf_map_update_elem(&flows, &f, &s, BPF_ANY);


    struct flow_flow_state fs;
    void *fsp = &fs;
    memcpy(fsp, &f, sizeof(f));
    memcpy(fsp+sizeof(f), &s, sizeof(s));       
    push_flow_queue(&f, &s, NULL);
}


unsigned char nulmac[6] = {0,0,0,0,0,0};

__u64 era = 0;
__u64 era_last = 0;
__u64 wallclock = 0;
const __u32 index0 = 0;


// POSSIBILITIES FOR DOS MITIGATION
//DEFCON1: will switch traffic without referring to state
//DEFCON2: will switch traffic referencing existing state
//DEFCON3: will create new state if syn|rst|fin flag not set
//DEFCON4: will multicast state
//DEFCON5: 
static inline int xdp_main_func(struct xdp_md *ctx, int bridge, int redirect)
{
    __u64 start = bpf_ktime_get_ns();
    __u8 DEFCON = 0;

    {
	struct settings *setting = bpf_map_lookup_elem(&settings, &index0);
	if(!setting) {
	    return XDP_PASS;
	}
	DEFCON = setting->defcon;
    }
    
    if(DEFCON == 0) return XDP_PASS; // C'est ne pas une load-balancer
    
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;
    int rx_bytes = data_end - data;

    struct counter *statsp = bpf_map_lookup_elem(&stats, &index0);
    if (!statsp) {
	return XDP_PASS;
    }

    statsp->rx_packets++;
    statsp->rx_bytes += rx_bytes;

    if ((statsp->rx_packets % 1000000) == 0) {
	statsp->fp_time = 0;
	statsp->fp_count = 0;	
    }
    
    __u64 era_now = 0;
    __u64 wallclock_now = 0;


    if((era_last + (1 * SECOND)) < start) {
	//if((era_last + 1000000000) < start) {
	// 1s has passed since last era update - check for a new era
	//__u64 *ts = bpf_map_lookup_elem(&clock, &index0);
	struct clocks *c = bpf_map_lookup_elem(&clocks, &index0);
	if(!c) {
	    return XDP_PASS;
	}
	
	era_now = c->era;
	wallclock_now = c->time;
	
	era = era_now;
	wallclock = wallclock_now;
	
	era_last = start;
    } else {
	era_now = era;
	wallclock_now = wallclock;
    }
    
    struct ethhdr *eth_hdr = data;
    __u32 nh_off = sizeof(struct ethhdr);
    __be16 eth_proto;
    
    if (data + nh_off > data_end) {
	return XDP_DROP;
    }
    
    eth_proto = eth_hdr->h_proto;
    
    
    struct vlan_hdr *tag = NULL;
    if (eth_proto == bpf_ntohs(ETH_P_8021Q)) {
	if(data + nh_off + sizeof(struct vlan_hdr) > data_end) {
	    return XDP_DROP;
	}
	tag = data + nh_off;
	eth_proto = tag->h_proto;
	data += sizeof(struct vlan_hdr);
    }
    
    if (eth_proto != bpf_ntohs(ETH_P_IP)) {	
	return XDP_PASS;
    }
    
    struct iphdr *ipv4 = data + nh_off;
    
    nh_off += sizeof(struct iphdr);
    
    if (data + nh_off > data_end) {
	return XDP_DROP;
    }
    
    if (ipv4->protocol != IPPROTO_TCP) {

	if (ipv4->protocol == IPPROTO_UDP) {
	    goto udp_packet;
	}
	
	if (ipv4->protocol == IPPROTO_ICMP) {
	    return XDP_PASS;

	    
	    unsigned char *s = (unsigned char *) &(eth_hdr->h_source);
	    unsigned char *m = bpf_map_lookup_elem(&rip_to_mac, &(ipv4->saddr));
	    
	    /* TODO: check destination is my visible IP? */
	    
	    if(m) {
		/* if the current record for the real IP does not match this MAC */
		if(maccmp(m, s) != 0) {
		    
		    /* delete old MAC to RIP record*/
		    bpf_map_delete_elem(&mac_to_rip, m);
		    
		    /* create new MAC to RIPrecord */
		    bpf_map_update_elem(&mac_to_rip, s, &(ipv4->saddr), BPF_ANY);
		    
		    /* update RIP to MAC record in place */
		    maccpy(m, s);
		}
		
	    }
	    
	    return XDP_PASS;
	}
	
	
	return XDP_PASS;
    }
    
    struct tcphdr *tcp = data + nh_off;
    
    nh_off += sizeof(struct tcphdr);
    
    if (data + nh_off > data_end) {
	return XDP_DROP;
    }

    if(DEFCON <= 2) goto new_flow;
    
    struct flow f = {.src = ipv4->saddr, .dst = ipv4->daddr, .sport = tcp->source, .dport = tcp->dest };
    struct flow_state *fs = bpf_map_lookup_elem(&flows, &f);
    if (fs) {
	
	// If we receive a SYN then we should start a new flow
	// However, to prevent TCP sniping, the connection should
	// have been idle for some time (60s?)
	// NOTE: this could have an impact if running load tests (wth, eg. ab(1))
	// from a single IP as TCP ports will be reused very frequently so new
	// connections will be bound to a possibly dead backend
	if (tcp->syn == 1) {
	    //bpf_map_delete_elem(&flows, &f);
	    //goto new_flow;
	    if ((fs->time + 60) < wallclock_now) {
		bpf_map_delete_elem(&flows, &f);
		goto new_flow;
	    }
	    // otherwise clear conn tracking fields
	    fs->era = era_now - 1;
	    fs->finrst = 0;
	    statsp->new_flows++;
	}
	

	if (!maccmp(fs->hwaddr, nulmac)) {
	    return XDP_DROP;
	}
	maccpy(eth_hdr->h_source, eth_hdr->h_dest);
	maccpy(eth_hdr->h_dest, fs->hwaddr);
	
	if(tag != NULL) {
	    tag->h_tci = (tag->h_tci & bpf_htons(0xf000)) | (fs->vlan & bpf_htons(0x0fff));	  
	}
	
	struct vip_rip_port vrp;
	vrp.vip = ipv4->daddr;
	vrp.rip = fs->rip;
	vrp.port = bpf_ntohs(tcp->dest);
	vrp.pad = 0; // must be 0 for regular counters
	
	struct counter *counter = bpf_map_lookup_elem(&vip_rip_port_counters, &vrp);
	if (counter) {
	    counter->rx_packets++;
	    counter->rx_bytes += rx_bytes;
	    if (tcp->syn == 1) {
		counter->new_flows++;
	    }
	}
	
	// reuse pad field for concurrency counter selection
	vrp.pad = era_now % 2;
	
	if (fs->finrst == 0 && ((tcp->rst == 1) || (tcp->fin == 1))) {
	    fs->finrst = 10;
	} else {
	    if (fs->finrst > 0) {
		(fs->finrst)--;
	    }
	}
	
	__s32 *concurrent = NULL;      
	if (fs->era != era_now) {
	    if((fs->era + 1) != era_now) {
		// probably transferred from a peer lb - correct it
		fs->era = era_now;
	    } else {		  
		fs->era = era_now;
		
		switch(fs->finrst) {
		case 10:
		    break;
		case 0:
		    concurrent = bpf_map_lookup_elem(&vip_rip_port_concurrent, &vrp);
		    if(concurrent) (*concurrent)++;
		    break;
		}
	    }
	} else {
	    switch(fs->finrst) {
	    case 10:
		concurrent = bpf_map_lookup_elem(&vip_rip_port_concurrent, &vrp);
		if(concurrent) (*concurrent)--;
		break;
	    case 0:
		break;
	    }
	}
	
	
	if (fs->time > wallclock_now) {
	    fs->time = wallclock_now - (tcp->ack_seq % 11);
	} else if ((fs->time + 60) <  wallclock_now) {
	    fs->time = wallclock_now - (tcp->ack_seq % 7);
	    if(DEFCON > 4) push_flow_queue(&f, fs, statsp);	      
	}
	
	statsp->fp_count++;
	statsp->fp_time += (bpf_ktime_get_ns()-start);

	return XDP_TX;      
    }
    
  
    //struct backend *b;
    //struct service s;
    struct backend_rec *rec;    

 new_flow:
    
    rec = lookup_backend(ipv4, tcp);
    if(rec) {
	if (!maccmp(rec->hwaddr, nulmac)) {
	    return XDP_DROP;
	}
	maccpy(eth_hdr->h_source, eth_hdr->h_dest);
	maccpy(eth_hdr->h_dest, rec->hwaddr);

	// if tagged with a vlan, update it
	if(tag != NULL) tag->h_tci = (tag->h_tci & bpf_htons(0xf000))|(rec->vlan & bpf_htons(0x0fff));
	
	if(DEFCON >= 4) save_state(ipv4, tcp, rec);
	
	update_counters(ipv4, tcp, rec->rip, rx_bytes, (DEFCON >= 4));
	
	if(DEFCON >= 4) statsp->new_flows++;
	statsp->fp_count++;
	statsp->fp_time += (bpf_ktime_get_ns()-start);

	return XDP_TX;
    }
    goto nat_stuff;



    struct udphdr *udp;
 udp_packet:

    udp = data + nh_off;

    nh_off += sizeof(struct udphdr);
    
    if (data + nh_off > data_end) {
	return XDP_DROP;
    }

    rec = lookup_backend_udp(ipv4, udp);
    if(rec) {
	if (!maccmp(rec->hwaddr, nulmac)) {
            return XDP_DROP;
        }
        maccpy(eth_hdr->h_source, eth_hdr->h_dest);
        maccpy(eth_hdr->h_dest, rec->hwaddr);

	// if tagged with a vlan, update it
	if(tag != NULL) tag->h_tci = (tag->h_tci & bpf_htons(0xf000))|(rec->vlan & bpf_htons(0x0fff));

        //if(DEFCON >= 4) save_state(ipv4, tcp, rec);

        //update_counters(ipv4, tcp, rec->rip, rx_bytes, (DEFCON >= 4));
	
        //if(DEFCON >= 4) statsp->new_flows++;
        statsp->fp_count++;
        statsp->fp_time += (bpf_ktime_get_ns()-start);

	return XDP_TX;
    }
    return XDP_PASS;

































  

  __be32 *rip = NULL;

  goto nat_stuff;
  nat_stuff:
 
  
  rip = bpf_map_lookup_elem(&mac_to_rip, &(eth_hdr->h_source));


  struct interface *virif = bpf_map_lookup_elem(&interfaces, &index0);
  if (!virif || !maccmp(virif->hwaddr, nulmac)) {
      return XDP_PASS;
  }

  if (rip) {
      struct viprip vr0;
      vr0.vip = ipv4->saddr;
      vr0.rip = *rip;

      __be32 *nat = bpf_map_lookup_elem(&vip_rip_to_nat, &vr0);
      if (nat) {
  
	  ipv4->saddr = *nat;
	  ipv4->daddr = virif->ipaddr;
	  maccpy(eth_hdr->h_dest, virif->hwaddr);

	  //ipv4->check = 0;
	  //ipv4->check = checksum((unsigned short *) ipv4, (void *)tcp - (void *)ipv4);

	  ipv4->check = 0;
	  ipv4->check = ipv4_checksum((void *) ipv4, (void *)tcp);
	  
	  tcp->check = 0;
	  tcp->check = tcp_checksum(ipv4, tcp, data_end);
	  
	  /* if probe reply was received on a VLAN then remove the tag */
	  if(tag != NULL) {
	      if(vlan_pop(ctx) != 0) {
		  return XDP_DROP;
	      }
          }

	  /* if running in bridged mode (eg. because a native driver doesn't do bpf_redirect well) then PASS */
	  if (bridge) {
	      return XDP_PASS;
	  }

	  /* otherwise redirect the packet to the virtual nic which deals with natted probes */
	  return bpf_redirect(virif->ifindex, 0);
      }
  }
  
  struct vip_rip_src_if *vr = bpf_map_lookup_elem(&nat_to_vip_rip, &(ipv4->daddr));
  if (vr) {
      unsigned char *m = bpf_map_lookup_elem(&rip_to_mac, &(vr->rip));
      
      if (!m || !maccmp((unsigned char *)m, nulmac)) {
          return XDP_DROP;
       }
      
      ipv4->saddr = vr->src;
      ipv4->daddr = vr->vip;
      maccpy(eth_hdr->h_dest, m);
      maccpy(eth_hdr->h_source,  vr->hwaddr);
            
      //ipv4->check = 0;
      //ipv4->check = checksum((unsigned short *) ipv4, (void *)tcp - (void *)ipv4);
      
      ipv4->check = 0;
      ipv4->check = ipv4_checksum((void *) ipv4, (void *)tcp);
      
      tcp->check = 0;

      tcp->check = tcp_checksum(ipv4, tcp, data_end);

      // redirect probe packet out to either eth0, or vlanX
      return bpf_redirect(vr->ifindex, 0);
  }

  
  return XDP_PASS;
  
}


SEC("xdp_main_bridge")
int xdp_main_drv_func(struct xdp_md *ctx) {
    return xdp_main_func(ctx, 1, 0);
}

SEC("xdp_main")
int xdp_main_skb_func(struct xdp_md *ctx) {
    return xdp_main_func(ctx, 0, 0);
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