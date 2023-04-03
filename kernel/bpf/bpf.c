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

#define SECOND_NS 1000000000

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

/**********************************************************************/

struct flow {
    __be32 src;
    __be32 dst;
    __be16 sport;
    __be16 dport;
};

struct state {
    __u64 time;
    __be32 rip;
    __be16 vid;
    __u8 mac[6];
    __u8 finrst;
    __u8 era;
    __u8 pad[2];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct flow);
    __type(value, struct state);
    __uint(max_entries, 3000000);
} flow_state SEC(".maps");

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

/*
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __type(key, struct vrpp);
    __type(value, struct active);
    __uint(max_entries, 1024);
} vrpp_concurrent_a SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __type(key, struct vrpp);
    __type(value, struct active);
    __uint(max_entries, 1024);
} vrpp_concurrent_b SEC(".maps");
*/

struct global {
    __u64 rx_packets;
    __u64 rx_octets;
    __u64 perf_packets;
    __u64 perf_timens;
    __u64 perf_timer;
    __u64 settings_timer;
    __u64 new_flows; //__u64 defcon;
    __u64 dropped;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, unsigned int);
    __type(value, struct global);
    __uint(max_entries, 1);
} globals SEC(".maps");


struct setting {
    __u64 heartbeat;
    __u8 defcon;
    __u8 era;
    __u8 multi;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, unsigned int);
    __type(value, struct setting);
    __uint(max_entries, 1);
} settings SEC(".maps");


struct {
    __uint(type, BPF_MAP_TYPE_DEVMAP);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 32);
} redirect_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_DEVMAP_HASH);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 4096);
} redirect_map_hash SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u8[6]);
    __uint(max_entries, 4096);
} redirect_mac SEC(".maps");



#define DEFCON0 0 // LB disabled - XDP_PASS all traffic
#define DEFCON1 1 // only global stats (and periodic check for settings) and stateless forwarding done
#define DEFCON2 2 // per backend stats recorded
#define DEFCON3 3 // flow state table consulted
#define DEFCON4 4 // flow state table written to
#define DEFCON5 5 // flow concurrency?

#define CONTINUE XDP_ABORTED

const int ZERO = 0;
__u8 DEFCON = DEFCON5;
//__u8 ERA = 0;
__u8 MULTINIC = 0;


static __always_inline void write_perf(struct global *global, __u64 start) {
    if(global) {
	global->perf_timens += (bpf_ktime_get_ns() - start);
	global->perf_packets++;
    }
}

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
    struct flow flow = {.src = ipv4->saddr, .dst = ipv4->daddr, .sport = src, .dport = dst }; 
    struct state state = { .rip = rip, .vid = vid, .time = bpf_ktime_get_ns(), .mac = { m[0], m[1], m[2], m[3], m[4], m[5] }, .era = 0 };
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


static __always_inline void be_tcp_concurrent(struct state *state, struct iphdr *ipv4, struct tcphdr *tcp, __u8 era)
{
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

static __always_inline int handle_icmp(struct ethhdr *eth, struct iphdr *ipv4, struct icmphdr *icmp, void *data_end)
{
    if(icmp->type != ICMP_ECHO || icmp->code != 0) {
	return XDP_DROP;
    }
    
    __u8 mac[6];
    maccpy(mac, eth->h_dest);
    maccpy(eth->h_dest, eth->h_source);
    maccpy(eth->h_source, mac);
    
    __be32 addr;
    addr = ipv4->daddr;
    ipv4->daddr = ipv4->saddr;
    ipv4->saddr = addr;
    
    icmp->type = ICMP_ECHOREPLY;
    
    ipv4->check = 0;
    ipv4->check = ipv4_checksum((void *) ipv4, (void *)icmp);

    icmp->checksum = 0;
    icmp->checksum = generic_checksum((void *) icmp, data_end, 0, 64);
    
    return XDP_TX;
}

static __always_inline int redirect_packet(struct ethhdr *eth, char *dst, __u32 map_entry, struct global *global, __u64 start)
{
    __u8 *mac = bpf_map_lookup_elem(&redirect_mac, &map_entry);
    
    if(!mac || nulmac(mac)) {
    	return XDP_DROP;
    }

    maccpy(eth->h_source, mac);
    maccpy(eth->h_dest, dst);
    write_perf(global, start);
    return bpf_redirect_map(&redirect_map_hash, map_entry, XDP_DROP);
    //return bpf_redirect_map(&redirect_map, map_entry, XDP_DROP);
}

static __always_inline int bounce_packet(struct ethhdr *eth, char *dst, struct global *global, __u64 start)
{ 
    maccpy(eth->h_source, eth->h_dest);
    maccpy(eth->h_dest, dst);
    write_perf(global, start);
    return XDP_TX;
}

static __always_inline int existing_tcp_flow(struct ethhdr *eth, struct vlan_hdr *tag, struct iphdr *ipv4, struct tcphdr *tcp, struct global *global, __u64 start, __u64 octets, __u8 era)
{
    if(DEFCON >= DEFCON3) {
	struct flow flow = {.src = ipv4->saddr, .dst = ipv4->daddr, .sport = tcp->source, .dport = tcp->dest };
	struct state *state = bpf_map_lookup_elem(&flow_state, &flow); 	// failed lookup takes ~70ns
	if(state != NULL) {
	    
	    if(tcp->syn)
		 return CONTINUE;

	    if((state->time + (60l * SECOND_NS)) < start) {
		// maybe delete?
		return CONTINUE; // drop through;
	    }
	    
	    if((state->time + (20l * SECOND_NS)) < start) {
		state->time = start;
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


	    /*
	    if(tag != NULL) {

		if(MODE != MODE_VLAN)
		    goto invalid_state; // We shouldn't be receiving tagged traffic in non-vlan mode
		
		if(state->vid == 0)
		    goto invalid_state; // VLAN ID of 0 not allowed if in VLAN mode
		
		tag->h_vlan_TCI = (tag->h_vlan_TCI & bpf_htons(0xf000)) | (state->vid & bpf_htons(0x0fff));
	    } else {
		if(MODE == MODE_VLAN)
                    goto invalid_state; // We must be receiving tagged traffic in vlan mode
		
		if(state->vid != 0)
		    goto invalid_state; // VLAN ID not allowed if in non-VLAN mode
	    }
	    */

	    if(state->vid == 0) {
		// traffic should be untagged - drop if not
		if(tag != NULL) goto drop_packet;
	    } else {
		// traffic should be tagged (or multi-nic mode - not yet implemented)
		if(tag == NULL) {
		    if(!MULTINIC)
			goto drop_packet;
		} else {
		    tag->h_vlan_TCI = (tag->h_vlan_TCI & bpf_htons(0xf000)) | (state->vid & bpf_htons(0x0fff));
		}
	    }

	    if(ip_decrease_ttl(ipv4) == 0) {
		goto drop_packet;
	    }

	    /**********************************************************************/
	    be_tcp_concurrent(state, ipv4, tcp, era);
	    /**********************************************************************/
	    
	    be_tcp_counter(ipv4->daddr, tcp->dest, state->rip, octets, 0);
	    
	    if(MULTINIC)
		return redirect_packet(eth, state->mac, bpf_ntohs(state->vid), global, start);

	    return bounce_packet(eth, state->mac, global, start);
	    
	invalid_state:
	    bpf_map_delete_elem(&flow_state, &flow);
	drop_packet:
	    if(global) global->dropped++;
	    write_perf(global, start);
	    return XDP_DROP;
	}
    }

    return CONTINUE;
}

static __always_inline int new_flow(struct ethhdr *eth, struct vlan_hdr *tag, struct iphdr *ipv4, __be16 src, __be16 dst, struct global *global, __u64 start, __u64 octets)
{
    struct real real_s;
    struct real *real = &real_s;

    switch(find_real(ipv4, src, dst, &real_s)) {
    case CONTINUE: //0: // no match - continue
	return CONTINUE;
	
    case XDP_PASS: //2: // fallback enabled - pass to local tcp stack
	write_perf(global, start);
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


	/*
	if(tag != NULL) {
	    if(MODE != MODE_VLAN)
		goto invalid_real; // We shouldn't be receiving tagged traffic in non-vlan mode
	    
	    if(real->vid == 0)
		goto invalid_real; // VLAN ID of 0 not allowed if in VLAN mode
	    
	    tag->h_vlan_TCI = (tag->h_vlan_TCI & bpf_htons(0xf000)) | (real->vid & bpf_htons(0x0fff));
	} else {

	    if(MODE == MODE_VLAN)
		goto invalid_real; // We must be receiving tagged traffic in vlan mode
	    
	    if(real->vid != 0)
		goto invalid_real; // VLAN ID not allowed if in non-VLAN mode
	}
	*/

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


	if(MULTINIC)
	    return redirect_packet(eth, real->mac, bpf_ntohs(real->vid), global, start);
	
	return bounce_packet(eth, real->mac, global, start);

    invalid_real: // fall-through
    drop_packet:
	
    case XDP_DROP: //3: // matched, but no backends available - return XDP_DROP;

    default:
	if(global) global->dropped++;
	write_perf(global, start);
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
        iph->check = ipv4_checksum((void *) iph, (void *)(iph+ sizeof(struct iphdr)));
    }
}

static __always_inline int nat_packet(struct xdp_md *ctx, struct ethhdr *eth, struct vlan_hdr *tag, struct iphdr *iph, struct tcphdr *tcp, struct udphdr *udp, struct icmphdr *icmp, void *data_end, int outgoing)
{
    struct natkey nkey = {.src_ip = iph->saddr, .dst_ip = iph->daddr };
    maccpy(nkey.src_mac, eth->h_source);
    maccpy(nkey.dst_mac, eth->h_dest);    
    
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

static __always_inline int outgoing_nat(struct xdp_md *ctx, struct ethhdr *eth, struct vlan_hdr *tag, struct iphdr *iph, struct tcphdr *tcp, struct udphdr *udp, struct icmphdr *icmp, void *data_end)
    
{
    return nat_packet(ctx, eth, tag, iph, tcp, udp, icmp, data_end, 1);
}

static __always_inline int returning_nat(struct xdp_md *ctx, struct ethhdr *eth, struct vlan_hdr *tag, struct iphdr *iph, struct tcphdr *tcp, struct udphdr *udp, struct icmphdr *icmp, void *data_end)
    
{
    return nat_packet(ctx, eth, tag, iph, tcp, udp, icmp, data_end, 0);
}





//SEC("xdp_main") int xdp_main_func(struct xdp_md *ctx)
int xdp_main_func(struct xdp_md *ctx, int outgoing)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;
    
    __u64 start = bpf_ktime_get_ns();
    __u64 octets = data_end - data;

    int action;

    struct global *global = bpf_map_lookup_elem(&globals, &ZERO);
    
    if(global) {
	global->rx_packets++;
	global->rx_octets += (data_end - data);
	
	// if 10s since last reset ...
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
    }

    __u8 era = 0;
    
    struct setting *setting = bpf_map_lookup_elem(&settings, &ZERO);
    if(setting) {
	era = setting->era;	
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
	    DEFCON = DEFCON5;
	    break;
	}
	
	// check for heartbeat from userland - disable LB functionality
	__u64 hb = setting->heartbeat;	
	if(hb == 0) {
	    setting->heartbeat = start + (60l * SECOND_NS);
	} else if(hb < start) {
	    return XDP_PASS;
	}
    }

    //write_perf(global, start); global = NULL; // ~75ns to here
    
    /* If LB is disabled then pass all traffic unmolested */
    if (DEFCON == DEFCON0)
	return XDP_PASS; 
    
    struct ethhdr *eth = data;
    __u32 nh_off = sizeof(struct ethhdr);
    __be16 eth_proto;

    if (data + nh_off > data_end)
	return XDP_DROP;

    eth_proto = eth->h_proto;

    struct vlan_hdr *tag = NULL;
    if (eth_proto == bpf_htons(ETH_P_8021Q)) {
	tag = data + nh_off;
	
	nh_off += sizeof(struct vlan_hdr);
	
	if (data + nh_off > data_end)
	    return XDP_DROP;
	
	eth_proto = tag->h_vlan_encapsulated_proto;
    }
    
    /* We don't deal wih any traffic that is not IPv4 */
    if (eth_proto != bpf_htons(ETH_P_IP))
	return XDP_PASS;
    
    struct iphdr *ipv4 = data + nh_off;
    
    nh_off += sizeof(struct iphdr);
    
    if (data + nh_off > data_end)
	return XDP_DROP;
    
    // we don't support IP options
    if (ipv4->ihl != 5)
	return XDP_DROP;
    
    // ignore evil bit and DF, drop if more fragments flag set, or fragent offset is not 0
    if ((ipv4->frag_off & bpf_htons(0x3fff)) != 0)
	return XDP_DROP;
    
    struct tcphdr *tcp = NULL;
    struct udphdr *udp = NULL;
    struct icmphdr *icmp = NULL;


    switch(ipv4->protocol) {
    
    case IPPROTO_ICMP:
	icmp = data + nh_off;
	
	nh_off += sizeof(struct icmphdr);
	
	if (data + nh_off > data_end)
	    return XDP_DROP;
	
	if (outgoing)
	    goto OUTGOING_PROBE;
	
	// respond to pings to configured VIPs
	if(configured_vip(ipv4, octets))
	    return handle_icmp(eth, ipv4, icmp, data_end);

	break;

    case IPPROTO_UDP:
	udp = data + nh_off;
	
	nh_off += sizeof(struct udphdr);
	
	if (data + nh_off > data_end)
	    return XDP_DROP;
	
	if (outgoing)
	    goto OUTGOING_PROBE;
	
	switch((action = new_flow(eth, tag, ipv4, udp->source, udp->dest, global, start, octets))) {
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
	tcp = data + nh_off;
	
	nh_off += sizeof(struct tcphdr);
	
	if (data + nh_off > data_end)
	    return XDP_DROP;
    
	if (outgoing)
	    goto OUTGOING_PROBE;
	
	switch((action = existing_tcp_flow(eth, tag, ipv4, tcp, global, start, octets, era))) {
	case CONTINUE: // Did not match an existing flow
	    break;
	default:
	    return action;
	}
	
	// Try to match a configured service
	switch((action = new_flow(eth, tag, ipv4, tcp->source, tcp->dest, global, start, octets))) {
	case CONTINUE: // Did not match a service
	    break;
	default:
	    return action;
	}
	
	// If matching a VIP then discard
	if(configured_vip(ipv4, octets))
	    return XDP_DROP;

	break;

    default:
	/* drop any traffic to a configured vip */
	if(configured_vip(ipv4, octets))
	    return XDP_DROP;
	
	/* should be local traffic for the box */
	return XDP_PASS;
    }
    
    //CHECK_RETURNING_PROBE:
    switch(action = returning_nat(ctx, eth, tag, ipv4, tcp, udp, icmp, data_end)) {
    case CONTINUE:
	break;
    default:
	return action;
    }
    
    return XDP_PASS;

    
 OUTGOING_PROBE:
    switch(action = outgoing_nat(ctx, eth, tag, ipv4, tcp, udp, icmp, data_end)) {
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
