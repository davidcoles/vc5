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
#include <linux/icmp.h>

#include <net/if.h>
#include <linux/bpf.h>
#include <string.h>


#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#ifndef lock_xadd
#define lock_xadd(ptr, val) ((void) __sync_fetch_and_add(ptr, val))
#endif

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
};

struct flow {
    __be32 src;
    __be32 dst;
    __be16 sport;
    __be16 dport;
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
};

#define IDX_BITS 13

#define F_STICKY     0x01
//#define F_SOMETHING 0x02
//#define F_SOMETHING 0x04
//#define F_SOMETHING 0x08
//#define F_SOMETHING 0x10
//#define F_SOMETHING 0x20
//#define F_SOMETHING 0x40
//#define F_SOMETHING 0x80

struct backends {
    __u8 backend[(1<<IDX_BITS)];
    __u8 flags;
    __u8 leastconns;
    __u8 weight;
    __u8 padding[5];
    // needs to be aligned on 8 byte boundary
};

struct vip_rip_port {
    __be32 vip;
    __be32 rip;
    __be16 port;
    __u16 pad;
};


struct settings {
    __u64 era;
    __u64 time;
    __u8 pad[7];
    __u8 defcon;
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
    __u8 hwaddr[6];
    __be16 _vlan;
};

struct backend_rec {
    unsigned char hwaddr[6];
    __be16 vlan;
    __be32 rip;
    // conveniently, this needs to be padded with 4 bytes. we can use
    // this to hold an ifindex for the veth device in slot 0 of
    // backend_recs
    unsigned int ifindex;
};

struct vip_settings {
    __u8 up;
    __u8 pad[3];
};

/**********************************************************************/
/* MAPS */
/**********************************************************************/

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, unsigned int);
    __type(value, struct counter);
    __uint(max_entries, 2);
} stats SEC(".maps");


struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, unsigned int);
    __type(value, struct settings);
    __uint(max_entries, 1);
} settings SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __type(key, struct vip_rip_port);
    __type(value, struct counter);
    __uint(max_entries, 1024);
} vip_rip_port_counters  SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __type(key, struct vip_rip_port);
    __type(value, __s32);
    __uint(max_entries, 1024);
} vip_rip_port_concurrent SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct flow);
    __type(value, struct flow_state);
    __uint(max_entries, MAX_FLOWS);
} flows SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_QUEUE);
    __type(value, struct flow_flow_state);
    __uint(max_entries, 10000);
} flow_queue SEC(".maps");


struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __be32);
    __type(value, __u8[6]);
    __uint(max_entries, 1024);
} rip_to_mac SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u8[6]);
    __type(value, __be32);
    __uint(max_entries, 1024);
} mac_to_rip SEC(".maps");


struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u8[4]);
    __type(value, struct vip_rip_src_if);
    __uint(max_entries, 1024);
} nat_to_vip_rip SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u8[8]);
    __type(value, __u8[4]);
    __uint(max_entries, 1024);
} vip_rip_to_nat SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, unsigned int);
    __type(value, struct backend_rec);
    __uint(max_entries, 256);
} backend_recs SEC(".maps");
	

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __type(key, struct service);
    __type(value, struct backends);
    __uint(max_entries, 256);
} backend_idx SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __be32);
    __type(value, struct vip_settings);
    __uint(max_entries, 256);
} vip_settings SEC(".maps");


/**********************************************************************/

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

#define SAVE_STATE(defcon) (defcon >= 4)


static __always_inline struct backend_rec *lookup_backend_udp(struct iphdr *ipv4, struct udphdr *udp) {
    struct service serv;
    serv.vip = ipv4->daddr;
    serv.ports = udp->dest;
    serv.proto = IPPROTO_UDP;
    serv.pad = 0;

    //__u8 *idx = bpf_map_lookup_elem(&backend_idx, &serv);
    struct backends *idx = bpf_map_lookup_elem(&backend_idx, &serv);
    if(!idx) {
	return NULL;
    }

    struct tuple t;
    t.src = ipv4->saddr;
    t.dst = ipv4->daddr;
    if(idx->flags & F_STICKY) {
	t.sport = 0;
	t.dport = 0;
    } else {
	t.sport = udp->source;
	t.dport = udp->dest;
    }
    
    __u16 n = sdbm((unsigned char*) &t, sizeof(t));

    //unsigned int rec_idx = idx[(n & ((1<<IDX_BITS)-1))];
    unsigned int rec_idx = idx->backend[(n & ((1<<IDX_BITS)-1))];

    if(rec_idx == 0) {
        return NULL;
    }

    return bpf_map_lookup_elem(&backend_recs, &rec_idx);
}


static __always_inline struct backend_rec *lookup_backend_tcp(struct iphdr *ipv4, struct tcphdr *tcp, __u8 defcon) {
    struct service serv;
    serv.vip = ipv4->daddr;
    serv.ports = tcp->dest;
    serv.proto = IPPROTO_TCP;
    serv.pad = 0;
    
    //__u8 *idx = bpf_map_lookup_elem(&backend_idx, &serv);
    struct backends *idx = bpf_map_lookup_elem(&backend_idx, &serv);
    if(!idx) {
	return NULL;
    }
    struct tuple t;
    t.src = ipv4->saddr;
    t.dst = ipv4->daddr;
    if(idx->flags & F_STICKY) {
    	t.sport = 0;
        t.dport = 0;
    } else {
    	t.sport = tcp->source;
    	t.dport = tcp->dest;
    }

    __u16 n = sdbm((unsigned char*) &t, sizeof(t));

    //unsigned int rec_idx = idx[(n & ((1<<IDX_BITS)-1))];
    unsigned int rec_idx = idx->backend[(n & ((1<<IDX_BITS)-1))];

    if(idx->leastconns != 0 && (n & 0xff ) < idx->weight && SAVE_STATE(defcon)) {
	rec_idx = idx->leastconns;
    }    
    
    if(rec_idx == 0) {
	return NULL;
    }
    
    return bpf_map_lookup_elem(&backend_recs, &rec_idx);
}

static __always_inline void update_counters(struct iphdr *ipv4, struct tcphdr *tcp, __be32 rip, int rx_bytes, int new, __u64 era) {
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
    
    if(new) {
	__s32 *concurrent = NULL;
	vrp.pad = era % 2;
	concurrent = bpf_map_lookup_elem(&vip_rip_port_concurrent, &vrp);
	if(concurrent) (*concurrent)++;
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

const __u32 zero = 0;

static inline __u8 defcon(__u8 d) {
    switch(d) {
    case 0: return 5;
    case 1: return 1;
    case 2: return 2;
    case 3: return 3;
    case 4: return 4;
    case 5: return 5;
    }
    return 5;    
}



// POSSIBILITIES FOR DOS MITIGATION
//DEFCON1: will switch traffic without referring to state
//DEFCON2: will switch traffic referencing existing state
//DEFCON3: will create new state if syn|rst|fin flag not set
//DEFCON4: will multicast state
//DEFCON5: 
static inline int xdp_main_func(struct xdp_md *ctx, int bridge, int redirect)
{
    __u64 start = bpf_ktime_get_ns();
    
    struct settings *setting = bpf_map_lookup_elem(&settings, &zero);
    if(!setting) {
	return XDP_PASS;
    }
    __u8 DEFCON = defcon(setting->defcon);
    __u64 era = setting->era;
    __u64 wallclock = setting->time;
    
    if(DEFCON == 0) return XDP_PASS; // C'est ne pas une load-balancer
    
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;
    int rx_bytes = data_end - data;

    struct counter *statsp = bpf_map_lookup_elem(&stats, &zero);
    if (!statsp) {
	return XDP_PASS;
    }

    statsp->rx_packets++;
    statsp->rx_bytes += rx_bytes;

    if ((statsp->rx_packets % 1000000) == 0) {
	statsp->fp_time = 0;
	statsp->fp_count = 0;	
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

    switch(ipv4->protocol) {
    case IPPROTO_TCP:
	goto tcp_packet;
    case IPPROTO_UDP:
	goto udp_packet;
    case IPPROTO_ICMP:
	goto icmp_packet;
    }

    return XDP_PASS;
    



    /**********************************************************************/
    struct tcphdr *tcp;
 tcp_packet:

    tcp = data + nh_off;
    
    nh_off += sizeof(struct tcphdr);
    
    if (data + nh_off > data_end) {
	return XDP_DROP;
    }
    
    if(DEFCON <= 2) goto new_flow;


    // this lookup adds ~100ns
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
	    if ((fs->time + 60) < wallclock) {
		bpf_map_delete_elem(&flows, &f);
		goto new_flow;
	    }
	    // otherwise clear conn tracking fields
	    fs->era = era - 1;
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
	vrp.pad = era % 2;
	
	if (fs->finrst == 0 && ((tcp->rst == 1) || (tcp->fin == 1))) {
	    fs->finrst = 10;
	} else {
	    if (fs->finrst > 0) {
		(fs->finrst)--;
	    }
	}
	
	__s32 *concurrent = NULL;      
	if (fs->era != era) {
	    if((fs->era + 1) != era) {
		// probably transferred from a peer lb - correct it
		fs->era = era;
	    } else {		  
		fs->era = era;
		
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
	
	
	if (fs->time > wallclock) {
	    fs->time = wallclock - (tcp->ack_seq % 11);
	} else if ((fs->time + 60) <  wallclock) {
	    fs->time = wallclock - (tcp->ack_seq % 7);
	    if(DEFCON > 4) push_flow_queue(&f, fs, statsp);	      
	}
	
	statsp->fp_count++;
	statsp->fp_time += (bpf_ktime_get_ns()-start);

	return XDP_TX;      
    }



    /**********************************************************************/
    struct backend_rec *rec;    
 new_flow:

    rec = lookup_backend_tcp(ipv4, tcp, DEFCON);
    if(rec) {
	if (!maccmp(rec->hwaddr, nulmac)) {
	    return XDP_DROP;
	}
	maccpy(eth_hdr->h_source, eth_hdr->h_dest);
	maccpy(eth_hdr->h_dest, rec->hwaddr);

	// if tagged with a vlan, update it
	if(tag != NULL) tag->h_tci = (tag->h_tci & bpf_htons(0xf000))|(rec->vlan & bpf_htons(0x0fff));	
	
	if(SAVE_STATE(DEFCON)) save_state(ipv4, tcp, rec);
	
	update_counters(ipv4, tcp, rec->rip, rx_bytes, (DEFCON >= 4), era);
	
	if(SAVE_STATE(DEFCON)) statsp->new_flows++;
	statsp->fp_count++;
	statsp->fp_time += (bpf_ktime_get_ns()-start);

	return XDP_TX;
    }
    goto nat_stuff;


    
    /**********************************************************************/
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

        statsp->fp_count++;
        statsp->fp_time += (bpf_ktime_get_ns()-start);
	
	return XDP_TX;
    }
    return XDP_PASS;



    /**********************************************************************/
    struct icmphdr *icmp = data + nh_off;
 icmp_packet:
    icmp = data + nh_off;

    nh_off += sizeof(struct icmphdr);
    
    if (data + nh_off > data_end) {
	return XDP_DROP;
    }
    
    if(icmp->type != ICMP_ECHO || icmp->code != 0) {
	return XDP_PASS;
    }

    struct vip_settings *vip = bpf_map_lookup_elem(&vip_settings, &(ipv4->daddr));
    if(!vip) {
	return XDP_PASS;
    }
    
    __u8 mac[6];
    maccpy(mac, eth_hdr->h_dest);
    maccpy(eth_hdr->h_dest, eth_hdr->h_source);
    maccpy(eth_hdr->h_source, mac);
    
    __be32 addr;
    addr = ipv4->daddr;
    ipv4->daddr = ipv4->saddr;
    ipv4->saddr = addr;
    
    if(vip->up == 0) {
	XDP_DROP;
    }

    icmp->type = ICMP_ECHOREPLY;
    
    icmp->checksum = 0;
    icmp->checksum = generic_checksum((void *) icmp, data_end, 0, 64);
    
    ipv4->check = 0;
    ipv4->check = ipv4_checksum((void *) ipv4, (void *)icmp);
    
    return XDP_TX;

























  
   
    /**********************************************************************/
  __be32 *rip = NULL;
 nat_stuff:
  
  rip = bpf_map_lookup_elem(&mac_to_rip, &(eth_hdr->h_source));

  struct backend_rec *virif = bpf_map_lookup_elem(&backend_recs, &zero);
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
	  ipv4->daddr = virif->rip;
	  maccpy(eth_hdr->h_dest, virif->hwaddr);

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
      maccpy(eth_hdr->h_source, vr->hwaddr);
            
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
