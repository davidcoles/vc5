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

// trace-cmd clear; watch 'trace-cmd show | tail'

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

#include "vlan.c"
#include "helpers.c"

#define SECOND_NS  1000000000
#define SECOND_NSl 1000000000l

static __always_inline void maccpy(unsigned char *dst, unsigned char *src) {
    __builtin_memcpy(dst, src, 6);
}

static __always_inline int nulmac(unsigned char *mac) {
    return (mac[0] == 0 && mac[1] == 0 && mac[2] == 0 && mac[3] == 0 && mac[4] == 0 && mac[5] == 0);
}

static __always_inline int equmac(unsigned char *a, unsigned char *b) {
    return (a[0] == b[0] && a[1] == b[1] && a[2] == b[2] && a[3] == b[3] && a[4] == b[4] && a[5] == b[5]);
}


/**********************************************************************/

struct flow {
    __be32 src;
    __be32 dst;
    __be16 sport;
    __be16 dport;
};
#define VERSION 1
struct state {
    __u32 time;
    __be32 rip;
    __be16 vid;
    __u8 mac[6];
    __u8 finrst;
    __u8 era;
    __u8 _pad;
    __u8 version;    
};

#if PERCPU_FLOWS
struct {
    __type(key, struct flow);
    __type(value, struct state);
    __uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
    __uint(max_entries, PERCPU_FLOWS);
} flow_state SEC(".maps");
#else
struct {
    __type(key, struct flow);
    __type(value, struct state);
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_FLOWS);
} flow_state SEC(".maps");    
#endif    

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct flow);
    __type(value, struct state);
    __uint(max_entries, SHARED_FLOWS);
} flow_shared SEC(".maps");

struct flow_queue_entry {
    __u8 data[sizeof(struct flow) + sizeof(struct state)];
};

struct {
    __uint(type, BPF_MAP_TYPE_QUEUE);
    __type(value, struct flow_queue_entry);
    __uint(max_entries, FLOW_QUEUE);
} flow_queue SEC(".maps");

/**********************************************************************/

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1048576); // counters for each /20 network (16 /20s per /16)
} prefix_counters SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 16384);
} prefix_drop SEC(".maps");

/**********************************************************************/
struct real {
    __be32 rip;
    __be16 vid;
    __u8 mac[6];
    __u8 flag[4];
    // flag entry in backend.real[0]
    // [0] - flags 0|0|0|0|0|0|fallback|sticky(l3hash)
    // [1] - if non-zeo then n/255 chance to send conn to ip/mac/vid in backend.real[0] (leastconns)
};

#define F_STICKY     0x01
#define F_FALLBACK   0x02
// remember to update kernel/balancer.go

/**********************************************************************/

struct service {
    __be32 vip;
    __be16 port;
    __u8 protocol; // TCP=6 UDP=17 VIP-EXISTS?=255
    __u8 pad;
};

struct backend {
    struct real real[256];
    __u8 hash[8192];
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __type(key, struct service);
    __type(value, struct backend);
    __uint(max_entries, 256);
} service_backend SEC(".maps");

/**********************************************************************/

struct vrpp {
    __be32 vip;
    __be32 rip;
    __be16 port;
    __u8 protocol;
    __u8 pad;
};

struct counter {
    __u64 packets;
    __u64 octets;
    __u64 flows;
    __u64 pad;
};

struct active { //64bit values are *probably* overkill - but as a PERCPU_HASH, needs to be 8byte aligned (seemingly)
    __u64 _total;
    __s64 current;
};


struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __type(key, struct vrpp);
    __type(value, struct counter);
    __uint(max_entries, 1024);
} vrpp_counter SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __type(key, struct vrpp);
    __type(value, struct active);
    __uint(max_entries, 2048);
} vrpp_concurrent SEC(".maps");

struct global {
    __u64 rx_packets;
    __u64 rx_octets;
    __u64 perf_packets;
    __u64 perf_timens;
    __u64 perf_timer;
    __u64 settings_timer;
    __u64 new_flows; //__u64 defcon;
    __u64 dropped;
    __u64 qfailed;
    __u64 blocked;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, unsigned int);
    __type(value, struct global);
    __uint(max_entries, 1);
} globals SEC(".maps");


struct setting {
    __u32 heartbeat;
    __u8 defcon;
    __u8 era;
    __u8 multi;
    __u8 distributed;
};


struct context {
    struct xdp_md *xdp_md;
    struct ethhdr *ethhdr;
    struct vlan_hdr *vlan_hdr;
    struct iphdr *iphdr;
    struct icmphdr *icmphdr;
    struct tcphdr *tcphdr;
    struct udphdr *udphdr;
    struct global *global;
    struct setting setting;
    void * data_end;
    __u64 start;
    __u64 start_s;    
    __u64 octets;
};

#define DEFCON_(context) (context->setting.defcon)

struct {
    //__uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, unsigned int);
    __type(value, struct setting);
    __uint(max_entries, 1);
} settings SEC(".maps");

/**********************************************************************/

struct natkey {
    __be32 src_ip;
    __be32 dst_ip;
    __u8 src_mac[6];
    __u8 dst_mac[6];
};

struct natval {
    __u32 ifindex;
    __be32 src_ip;
    __be32 dst_ip;
    __u16 vlan;
    __u8 pad[2];
    __u8 src_mac[6];
    __u8 dst_mac[6];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct natkey);
    __type(value, struct natval);
    __uint(max_entries, 65536);
} nat SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_DEVMAP);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 4096);
} redirect_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u8[6]);
    __uint(max_entries, 4096);
} redirect_mac SEC(".maps");

/**********************************************************************/

#define DEFCON0 0 // LB disabled - XDP_PASS all traffic
#define DEFCON1 1 // only global stats and stateless forwarding done
#define DEFCON2 2 // per backend stats recorded
#define DEFCON3 3 // flow state table consulted
#define DEFCON4 4 // flow state table written to
#define DEFCON5 5 // flows shared via flow_queue/flow_shared

#define CONTINUE XDP_ABORTED

const int ZERO = 0;
__u8 DEFCON = DEFCON5;
__u8 MULTINIC = 0;

/*
static __always_inline void write_perf(struct context *context) {
    if(context->global) {
	context->global->perf_timens += (bpf_ktime_get_ns() - context->start);
	context->global->perf_packets++;
	context->global = NULL; // we can only write this once
    }
}
*/

static __always_inline int find_real(struct iphdr *ipv4, __be16 src, __be16 dst, struct real *r) {
    struct service s;
    memset(&s, 0, sizeof(s));
    s.vip = ipv4->daddr;
    s.port = dst;
    s.protocol = ipv4->protocol;
    
    struct backend *backend = bpf_map_lookup_elem(&service_backend, &s);

    if(!backend)
	return CONTINUE; // 0; // no entry found
    
    __u8 flags = backend->real[0].flag[0];
    __u8 leastconns = backend->real[0].flag[1];

    if(flags & F_FALLBACK) {
	return XDP_PASS; // 2; // fallback
    }

    __u16 hash = l4_hash(ipv4, (flags & F_STICKY) ? 0 : src, (flags & F_STICKY) ? 0 : dst);
    __u8 i = backend->hash[hash>>3];
    
    if(i == 0) {
	return XDP_DROP; // 3; // no suitable backend
    }
    
    if(leastconns != 0) {
	if((__u8)((hash >> 8) ^ (hash & 0xff)) <= leastconns) { // weighting
	    *r = backend->real[0];
	    return XDP_TX; //1;
	}
    }
    
    *r = backend->real[i];
    
    return XDP_TX;
}

static __always_inline void store_tcp_flow(struct iphdr *ipv4, __be16 src, __be16 dst, __be32 rip, __u8 *m, __u16 vid, struct global *global)
{
    __u64 time = bpf_ktime_get_ns() / SECOND_NSl;
    struct flow flow = {.src = ipv4->saddr, .dst = ipv4->daddr, .sport = src, .dport = dst }; 
    struct state state = { .rip = rip, .vid = vid, .time = time, .mac = { m[0], m[1], m[2], m[3], m[4], m[5] }, .era = 0 };
    bpf_map_update_elem(&flow_state, &flow, &state, BPF_ANY);
    if(global) global->new_flows++;
}

static __always_inline void be_tcp_counter(__be32 vip, __be16 port, __be32 rip, int octets, int new_flow)
{
    struct vrpp vr = { .vip = vip, .rip = rip, .port = port, .protocol = IPPROTO_TCP };
    struct counter *co = bpf_map_lookup_elem(&vrpp_counter, &vr);
    if(co) {
	co->octets += octets;
	co->packets++;
	if(new_flow) co->flows++;
    }
}


static __always_inline struct active * _be_tcp_concurrent(__be32 vip, __be16 port, __be32 rip, __u8 era)
{   
    struct vrpp vr = { .vip = vip, .rip = rip, .port = port, .protocol = IPPROTO_TCP, .pad = era%2 };
    return (struct active *) bpf_map_lookup_elem(&vrpp_concurrent, &vr);
}


static __always_inline void be_tcp_concurrent(struct context *context, struct state *state)
{
    struct iphdr *ipv4 = context->iphdr;
    struct tcphdr *tcp = context->tcphdr;
    __u8 era = context->setting.era;
    
    if(!tcp)
	return;
    
    struct active *concurrent = NULL;      

    if (tcp->syn == 1) {
	state->finrst = 0;
    }
    
    if (state->finrst == 0 && ((tcp->rst == 1) || (tcp->fin == 1))) {
	state->finrst = 10;
    } else {
	if (state->finrst > 0) {
	    (state->finrst)--;
	}
    }

    if (state->era != era || tcp->syn == 1) {
	state->era = era;
	
	switch(state->finrst) {
	case 10:
	    break;
	case 0:
	    concurrent = _be_tcp_concurrent(ipv4->daddr, tcp->dest, state->rip, era);
	    if(concurrent) concurrent->current++;
	    //if(concurrent) concurrent->total++;

	    break;
	}
    } else {
	switch(state->finrst) {
	case 10:
	    concurrent = _be_tcp_concurrent(ipv4->daddr, tcp->dest, state->rip, era);	    
	    if(concurrent) concurrent->current--;
	    break;
	case 0:
	    break;
	}
    }
}


static __always_inline int configured_vip(struct iphdr *ipv4, __u64 octets)
{
    struct vrpp vr = { .vip = ipv4->daddr };
    struct counter *co = bpf_map_lookup_elem(&vrpp_counter, &vr);
    if(co) {
	co->octets += octets;
	co->packets++;
	return 1;
    }

    return 0;
}

static __always_inline int handle_icmp(struct context *context)
{
    if(context->icmphdr->type != ICMP_ECHO || context->icmphdr->code != 0) {
	return XDP_DROP;
    }
    
    __u8 mac[6];
    maccpy(mac, context->ethhdr->h_dest);
    maccpy(context->ethhdr->h_dest, context->ethhdr->h_source);
    maccpy(context->ethhdr->h_source, mac);
    
    __be32 addr;
    addr = context->iphdr->daddr;
    context->iphdr->daddr = context->iphdr->saddr;
    context->iphdr->saddr = addr;
    
    context->icmphdr->type = ICMP_ECHOREPLY;
    
    context->iphdr->check = 0;
    context->iphdr->check = ipv4_checksum((void *) context->iphdr, (void *)context->icmphdr);

    context->icmphdr->checksum = 0;
    context->icmphdr->checksum = generic_checksum((void *) context->icmphdr, context->data_end, 0, 64);
    
    return XDP_TX;
}

static __always_inline int redirect_packet(struct context *context, char *dst, __u32 map_entry)
{
    struct ethhdr *eth = context->ethhdr;
    __u8 *mac = bpf_map_lookup_elem(&redirect_mac, &map_entry);
    
    if(!mac || nulmac(mac)) {
    	return XDP_DROP;
    }

    maccpy(eth->h_source, mac);
    maccpy(eth->h_dest, dst);

    return bpf_redirect_map(&redirect_map, map_entry, XDP_DROP);
}

static __always_inline int bounce_packet(struct context *context, char *dst)
{
    struct ethhdr *eth = context->ethhdr;
    maccpy(eth->h_source, eth->h_dest);
    maccpy(eth->h_dest, dst);
    return XDP_TX;
}

static __always_inline struct state *shared_tcp_flow(struct context *context, struct flow *flow, struct state *state)
{
     __u64 start_s = context->start_s;
    __u64 start_ns = context->start;
    
    struct state *s = bpf_map_lookup_elem(&flow_shared, flow);

    if(!s || s->version != VERSION)
	return NULL;

    if(s->time == 0 || (s->time + 110) < start_s)
	return NULL;

    *state = *s;
    
    state->era = context->setting.era;
    state->finrst = 0;
    state->time += (start_ns >> 8) % 10; // vary distribution of packets a little

    s->time = 0; // flag shared entry as already used
    
    return state;
}

static __always_inline int existing_tcp_flow(struct context *context)
{
    struct ethhdr *eth = context->ethhdr;
    struct vlan_hdr *tag = context->vlan_hdr;
    struct iphdr *ipv4 = context->iphdr;
    struct tcphdr *tcp = context->tcphdr;
    struct global *global = context->global;
    __u64 start_s = context->start_s;
    __u64 start_ns = context->start;
    __u64 octets = context->octets;
    
    if(tcp->syn)
	return CONTINUE;
    
    if(DEFCON_(context) < DEFCON3)
	return CONTINUE;
    
    struct flow flow = {.src = ipv4->saddr, .dst = ipv4->daddr, .sport = tcp->source, .dport = tcp->dest };
    struct state *state = bpf_map_lookup_elem(&flow_state, &flow); // failed lookup takes ~70ns
    struct state s = {};
    
    if(!state || (state->time + 120) < start_s) {
	if(!(context->setting.distributed))
	    return CONTINUE;
	
	if(DEFCON < DEFCON5)
	    return CONTINUE;
	
	state = shared_tcp_flow(context, &flow, &s);
	
	if(!state)
	    return CONTINUE;

	// any updates to the struct pointed to by state won't get persisted after here, but will with next packet
	state->era = context->setting.era; // saved struct won't trigger updates ...
	bpf_map_update_elem(&flow_state, &flow, state, BPF_ANY); // ...
	state->era -= 1; // ... but this one will
    }
    
    if((state->time + 60) < start_s) {
	state->time = start_s - ((start_ns >> 8) % 5); // vary distrbution of packets a little

	// write to queue
	if(context->setting.distributed && DEFCON == DEFCON5) {
	    state->version = VERSION;
	    struct flow_queue_entry fqe = {};
	    memcpy((void *)&fqe, &flow, sizeof(struct flow));
	    memcpy((void *)&fqe + sizeof(struct flow), state, sizeof(struct state));
	    if ((bpf_map_push_elem(&flow_queue, &fqe, 0) != 0) && global) {
		global->qfailed++;
	    }
	}
    }
    
    if(state->rip == 0) {
	goto invalid_state;
    }
    
    if(nulmac(state->mac)) {
	goto invalid_state;
    }
    
    if(equmac(state->mac, eth->h_dest)) {
	goto invalid_state; // looks like local NIC
    }
    
    if(equmac(state->mac, eth->h_source)) {
	goto invalid_state; // unlikely that we should echo packet back to source on l2lb
    }
    
    if(state->vid == 0) {
	if(tag) goto drop_packet; // traffic should be untagged - drop if not
    } else {
	// traffic should be tagged (or multi-nic mode)
	if(!tag) {
	    if(!MULTINIC) goto drop_packet;
	} else {
	    tag->h_vlan_TCI = (tag->h_vlan_TCI & bpf_htons(0xf000)) | (state->vid & bpf_htons(0x0fff));
	}
    }
    
    if(ip_decrease_ttl(ipv4) == 0) {
	goto drop_packet;
    }
    
    /**********************************************************************/
    be_tcp_concurrent(context, state);
    /**********************************************************************/
    
    be_tcp_counter(ipv4->daddr, tcp->dest, state->rip, octets, 0);
    
    __u32 prefix = bpf_ntohl(ipv4->saddr) >> 12; // obtain /20
    __u64 *traffic = bpf_map_lookup_elem(&prefix_counters, &prefix);
    if(traffic) (*traffic)++;	
    
    if(MULTINIC)
	return redirect_packet(context, state->mac, bpf_ntohs(state->vid));
    
    return bounce_packet(context, state->mac);
    
 invalid_state:
    bpf_map_delete_elem(&flow_state, &flow);
 drop_packet:
    if(global) global->dropped++;
    return XDP_DROP;
}

static __always_inline int new_flow(struct context *context, __be16 src, __be16 dst, __u64 octets)
{
    struct ethhdr *eth = context->ethhdr;
    struct vlan_hdr *tag = context->vlan_hdr;
    struct iphdr *ipv4 = context->iphdr;
    //struct tcphdr *tcp = context->tcphdr;
    struct global *global = context->global;
    
    struct real real_s;
    struct real *real = &real_s;

    switch(find_real(ipv4, src, dst, &real_s)) {
    case CONTINUE: //0: // no match - continue
	return CONTINUE;
	
    case XDP_PASS: //2: // fallback enabled - pass to local tcp stack
	return XDP_PASS;
	
    case XDP_TX: //1: // matched and backend available
	if(ip_decrease_ttl(ipv4) == 0) {
	    goto drop_packet;
	}
	
	if(real->rip == 0)
	    goto invalid_real;
	
	if(nulmac(real->mac))
	    goto invalid_real;
	
	if(equmac(real->mac, eth->h_dest))
	    goto invalid_real; // looks like local NIC

	if(equmac(real->mac, eth->h_source))
	    goto invalid_real; // unlikely we would want to echo packet back to source on an l2lb

	if(real->vid == 0) {
	    // traffic should be untagged - drop if not
	    if(tag != NULL) goto drop_packet;
	} else {
	    if(tag == NULL) {
		if(!MULTINIC)
		    goto drop_packet;
	    } else {
		tag->h_vlan_TCI = (tag->h_vlan_TCI & bpf_htons(0xf000)) | (real->vid & bpf_htons(0x0fff));
	    }
	}
	
	if(ipv4->protocol == IPPROTO_TCP) { // maybe don't store initial SYN?
	    if(DEFCON >= DEFCON4) store_tcp_flow(ipv4, src, dst, real->rip, real->mac, real->vid, global);
	    if(DEFCON >= DEFCON2) be_tcp_counter(ipv4->daddr, dst, real->rip, octets, DEFCON >= DEFCON4);
	}

	__u32 prefix = bpf_ntohl(ipv4->saddr) >> 12; // obtain /20
	__u64 *traffic = bpf_map_lookup_elem(&prefix_counters, &prefix);
	if(traffic) (*traffic)++;	

	if(MULTINIC)
	    return redirect_packet(context, real->mac, bpf_ntohs(real->vid));
	
	return bounce_packet(context, real->mac);

    invalid_real: // fall-through
    drop_packet:
	
    case XDP_DROP: //3: // matched, but no backends available - return XDP_DROP;

    default:
	if(global) global->dropped++;
	return XDP_DROP;
	
    }

    return CONTINUE;
}


static __always_inline void recompute(struct iphdr *iph, struct tcphdr *tcp, struct udphdr *udp, struct icmphdr *icmp, void *data_end)
{    
    iph->check = 0;
    if(tcp) {
	iph->check = ipv4_checksum((void *) iph, (void *)tcp);
	tcp->check = 0;
	tcp->check = l4_checksum(iph, tcp, data_end);
    } else if (udp) {
	iph->check = ipv4_checksum((void *) iph, (void *)udp);
	udp->check = 0;
	udp->check = l4_checksum(iph, udp, data_end);
    } else if (icmp) {
	iph->check = ipv4_checksum((void *) iph, (void *)icmp);	
    } else {
        iph->check = ipv4_checksum((void *) iph, (void *)(iph + sizeof(struct iphdr)));
    }
}

static __always_inline int nat_packet(struct context *context, int outgoing)
{
    struct xdp_md *ctx = context->xdp_md;
    struct ethhdr *eth = context->ethhdr;
    struct vlan_hdr *tag = context->vlan_hdr;
    struct iphdr *iph = context->iphdr;
    struct icmphdr *icmp = context->icmphdr;
    struct tcphdr *tcp = context->tcphdr;
    struct udphdr *udp = context->udphdr;
    void *data_end = context->data_end;
    
    struct natkey nkey = {.src_ip = iph->saddr, .dst_ip = iph->daddr };
    maccpy(nkey.src_mac, eth->h_source);
    maccpy(nkey.dst_mac, eth->h_dest);    

    if(nkey.src_ip == 0 || nkey.dst_ip == 0) {
	return XDP_DROP;
    }
    
    struct natval *nval = bpf_map_lookup_elem(&nat, &nkey);

    if(!nval) {
	if(outgoing) {
	    iph->ttl = 1; // prevent packets from running amok
	    recompute(iph, tcp, udp, icmp, data_end);
	}
	return CONTINUE;
    }

    if(nulmac(nval->src_mac) || nulmac(nval->dst_mac) || nval->src_ip == 0 || nval->dst_ip == 0) {
	return XDP_DROP;
    }
    
    if(iph->ttl == 1) {
	return XDP_DROP;
    }
    
    iph->saddr = nval->src_ip;
    iph->daddr = nval->dst_ip;
    maccpy(eth->h_source, nval->src_mac);
    maccpy(eth->h_dest, nval->dst_mac);
    
    iph->ttl = 1; // prevent packets from running amok
    
    if(tcp != NULL) {
	iph->check = 0;
	iph->check = ipv4_checksum((void *) iph, tcp);
	tcp->check = 0;
	tcp->check = l4_checksum(iph, tcp, data_end);
    } else if(udp != NULL) {
	iph->check = 0;
	iph->check = ipv4_checksum((void *) iph, udp);
	udp->check = 0;
	udp->check = l4_checksum(iph, udp, data_end);
    } else if (icmp) {
	iph->check = 0;
	iph->check = ipv4_checksum((void *) iph, (void *)icmp);	
    } else {
	return XDP_DROP;
    }
    
    if(outgoing) {
    } else {
	if(tag != NULL && vlan_tag_pop(ctx, eth) < 0) return XDP_DROP;
    }
        
    if(nval->ifindex == 0)
	return XDP_DROP;
    
    return bpf_redirect(nval->ifindex, 0);
}

static __always_inline int outgoing_nat(struct context *context)
    
{
    return nat_packet(context, 1);
}

static __always_inline int returning_nat(struct context *context)
    
{
    return nat_packet(context, 0);
}


// perl -e 'foreach(0..63) { printf "case %2d: return x & %016x;\n", $_, 2**$_ }'
static __always_inline __u64 pow(__u8 n) {
    switch(n) {
    case  0: return 0x0000000000000001;
    case  1: return 0x0000000000000002;
    case  2: return 0x0000000000000004;
    case  3: return 0x0000000000000008;
    case  4: return 0x0000000000000010;
    case  5: return 0x0000000000000020;
    case  6: return 0x0000000000000040;
    case  7: return 0x0000000000000080;
    case  8: return 0x0000000000000100;
    case  9: return 0x0000000000000200;
    case 10: return 0x0000000000000400;
    case 11: return 0x0000000000000800;
    case 12: return 0x0000000000001000;
    case 13: return 0x0000000000002000;
    case 14: return 0x0000000000004000;
    case 15: return 0x0000000000008000;
    case 16: return 0x0000000000010000;
    case 17: return 0x0000000000020000;
    case 18: return 0x0000000000040000;
    case 19: return 0x0000000000080000;
    case 20: return 0x0000000000100000;
    case 21: return 0x0000000000200000;
    case 22: return 0x0000000000400000;
    case 23: return 0x0000000000800000;
    case 24: return 0x0000000001000000;
    case 25: return 0x0000000002000000;
    case 26: return 0x0000000004000000;
    case 27: return 0x0000000008000000;
    case 28: return 0x0000000010000000;
    case 29: return 0x0000000020000000;
    case 30: return 0x0000000040000000;
    case 31: return 0x0000000080000000;
    case 32: return 0x0000000100000000;
    case 33: return 0x0000000200000000;
    case 34: return 0x0000000400000000;
    case 35: return 0x0000000800000000;
    case 36: return 0x0000001000000000;
    case 37: return 0x0000002000000000;
    case 38: return 0x0000004000000000;
    case 39: return 0x0000008000000000;
    case 40: return 0x0000010000000000;
    case 41: return 0x0000020000000000;
    case 42: return 0x0000040000000000;
    case 43: return 0x0000080000000000;
    case 44: return 0x0000100000000000;
    case 45: return 0x0000200000000000;
    case 46: return 0x0000400000000000;
    case 47: return 0x0000800000000000;
    case 48: return 0x0001000000000000;
    case 49: return 0x0002000000000000;
    case 50: return 0x0004000000000000;
    case 51: return 0x0008000000000000;
    case 52: return 0x0010000000000000;
    case 53: return 0x0020000000000000;
    case 54: return 0x0040000000000000;
    case 55: return 0x0080000000000000;
    case 56: return 0x0100000000000000;
    case 57: return 0x0200000000000000;
    case 58: return 0x0400000000000000;
    case 59: return 0x0800000000000000;
    case 60: return 0x1000000000000000;
    case 61: return 0x2000000000000000;
    case 62: return 0x4000000000000000;
    case 63: return 0x8000000000000000;
    }
    return 0;
}

static __always_inline int blocked(struct iphdr *ipv4) {
    __u32 source = bpf_ntohl(ipv4->saddr);
    
    if((source & 0xff000000) == 0x0a000000) return 0; // 10.0.0.0/8
    if((source & 0xffff0000) == 0xc0800000) return 0; // 192.168.0.0/16
    if((source & 0xf0000000) == 0xe0000000) return 0; // 224.0.0.0/4
    
    __u32 s14 = source >> 18;
    __u64 *drop = bpf_map_lookup_elem(&prefix_drop, &s14);
    
    if(!drop)
	return 0;
    
    if(*drop & pow((source >> 12) & 0x3f)) // 0x3f = 63
	return 1;
    
    return 0;
}


static __always_inline int perf(struct context *context, int ret) {
    if(context && context->global) {
	context->global->perf_timens += (bpf_ktime_get_ns() - context->start);
	context->global->perf_packets++;
	context->global = NULL; // we can only write this once
    }
    return ret;
}

//SEC("xdp_main") int xdp_main_func(struct xdp_md *ctx)
int xdp_main_func(struct xdp_md *ctx, int outgoing)
{
    // ctx->ingress_ifindex;
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;
    
    __u64 start = bpf_ktime_get_ns();
    __u64 start_s = start / SECOND_NSl;
    __u64 octets = data_end - data;
    
    int action;
    
    struct global *global = bpf_map_lookup_elem(&globals, &ZERO);
    
    if(!global)
	return XDP_PASS;
    
    global->rx_packets++;
    global->rx_octets += (data_end - data);

    // if 10s since last perf reset ...
    if((global->perf_timer + (10l * SECOND_NS)) < start) {
	global->perf_timer = start;
	if(global->perf_packets > 1) {
	    global->perf_timens = (global->perf_timens / global->perf_packets) * 100;
	    global->perf_packets = 100;
	} else {
	    global->perf_timens = 500;
	    global->perf_packets = 1;
	}
    }

    struct context context = { .xdp_md = ctx, .start = start, .start_s = start_s, octets = data_end - data, .data_end = data_end, .global = global };

    /* PACKET DECODING BEGINS *********************************************************************/
    
    struct ethhdr *eth = context.ethhdr = data;
    __u32 nh_off = sizeof(struct ethhdr);
    __be16 eth_proto;

    if (data + nh_off > data_end)
	return XDP_DROP;

    eth_proto = eth->h_proto;

    struct vlan_hdr *tag = NULL;
    if (eth_proto == bpf_htons(ETH_P_8021Q)) {
	tag = context.vlan_hdr = data + nh_off;
	
	nh_off += sizeof(struct vlan_hdr);
	
	if (data + nh_off > data_end)
	    return XDP_DROP;
	
	eth_proto = tag->h_vlan_encapsulated_proto;
    }
    
    /* We don't deal wih any traffic that is not IPv4 */
    if (eth_proto != bpf_htons(ETH_P_IP))
	return XDP_PASS;
    
    struct iphdr *ipv4 = context.iphdr = data + nh_off;
    
    nh_off += sizeof(struct iphdr);
    
    if (data + nh_off > data_end)
	return XDP_DROP;
    
    // we don't support IP options
    if (ipv4->ihl != 5)
	return XDP_DROP;
    
    // ignore evil bit and DF, drop if more fragments flag set, or fragent offset is not 0
    if ((ipv4->frag_off & bpf_htons(0x3fff)) != 0)
	return XDP_DROP;

    /* IPv4 PACKET RECEIVED *********************************************************************/

    
    //perf(&context, 0); // ~110ns to here
	
    if (blocked(ipv4)) { // + ~30ns
	context.global->blocked++;
	return perf(&context, XDP_DROP);
    }
    
    struct setting *setting = bpf_map_lookup_elem(&settings, &ZERO); // + ~20ns
    
    if(!setting)
	return XDP_PASS;

    context.setting = *setting;
    
    DEFCON = setting->defcon;
    MULTINIC = setting->multi;
    
    switch(DEFCON) {
    case DEFCON0:
    case DEFCON1:	    
    case DEFCON2:
    case DEFCON3:
    case DEFCON4:
    case DEFCON5:
	break;
    default:
	DEFCON = context.setting.defcon = DEFCON5;
	break;
    }
    
    // check for heartbeat from userland - disable LB functionality
    __u64 hb = setting->heartbeat;	
    if (hb == 0) {
	setting->heartbeat = start_s + 60;
    } else if(hb < start_s) {
	return XDP_PASS;
    }
    
    /* If LB is disabled then pass all traffic unmolested */
    if (DEFCON == DEFCON0)
	return XDP_PASS; 

    /**********************************************************************/   
        
    //perf(&context, 0); // ~15
    
    struct tcphdr *tcp = NULL;
    struct udphdr *udp = NULL;
    struct icmphdr *icmp = NULL;

    switch(ipv4->protocol) {
    
    case IPPROTO_ICMP:
	icmp = context.icmphdr = data + nh_off;
	
	nh_off += sizeof(struct icmphdr);
	
	if (data + nh_off > data_end)
	    return XDP_DROP;
	
	if (outgoing)
	    goto OUTGOING_PROBE;
	
	// respond to pings to configured VIPs
	if(configured_vip(ipv4, octets))
	    return handle_icmp(&context);
	
	break;

    case IPPROTO_UDP:
	udp = context.udphdr = data + nh_off;
	
	nh_off += sizeof(struct udphdr);
	
	if (data + nh_off > data_end)
	    return XDP_DROP;
	
	if (outgoing)
	    goto OUTGOING_PROBE;
	
	switch ((action = new_flow(&context, udp->source, udp->dest, octets))) {
	case CONTINUE:
	    break;
	default:
	    return action;
	}
	
	/* drop any traffic to a configured vip not handled by a service */
	if(configured_vip(ipv4, octets))
	    return XDP_DROP;

	break;
	
    case IPPROTO_TCP:
	tcp = context.tcphdr = data + nh_off;
	
	nh_off += sizeof(struct tcphdr);
	
	if (data + nh_off > data_end)
	    return XDP_DROP;
	
	if (outgoing)
	    goto OUTGOING_PROBE;

	switch ((action = existing_tcp_flow(&context))) {
	case CONTINUE: // Did not match an existing flow
	    break;
	default:
	    return perf(&context, action);
	}

	// Try to match a configured service
	switch ((action = new_flow(&context, tcp->source, tcp->dest, octets))) {
	case CONTINUE: // Did not match a service
	    break;
	default:
	    return perf(&context, action);
	}
	
	// If matching a VIP then discard
	if (configured_vip(ipv4, octets))
	    return XDP_DROP;

	break;

    default:
	/* drop any other traffic to a configured vip */
	if (configured_vip(ipv4, octets))
	    return XDP_DROP;
	
	/* should be local traffic for the box */
	return XDP_PASS;
    }

    //CHECK_RETURNING_PROBE:
    switch (action = returning_nat(&context)) {
    case CONTINUE:
	break;
    default:
	return action;
    }
    
    return XDP_PASS;
    
 OUTGOING_PROBE:
    switch (action = outgoing_nat(&context)) {
    case CONTINUE:
	break;
    default:
	return action;
    }

    return XDP_PASS;
}


SEC("incoming") int xdp_main_func0(struct xdp_md *ctx)
{
    return xdp_main_func(ctx, 0);
}

SEC("outgoing") int xdp_main_func2(struct xdp_md *ctx)
{
    return xdp_main_func(ctx, 1);   
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
