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

#define SECOND_NS 1000000000

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


/**********************************************************************/

struct flow {
    __be32 src;
    __be32 dst;
    __be16 sport;
    __be16 dport;
};

struct state {
    __be32 rip;
    __u8 mac[6];
    __u8 finrst;
    __u8 era;
    __u8 pad[4];
    __u64 time;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    //__uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
    __type(key, struct flow);
    __type(value, struct state);
    __uint(max_entries, 30000000);
    //__uint(max_entries, 1000000);
} flow_state SEC(".maps");


/**********************************************************************/

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

struct real {
    __be32 rip;
    __u8 mac[6];
    __be16 vid;
    __u8 pad[4];
};
    
/**********************************************************************/

struct service {
    __be32 vip;
    __be16 port;
    __u8 protocol;
    __u8 pad;
};

struct backend {
    __u8 hash[8192];
    struct real real[256];
    __u8 flag[8];
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __type(key, struct service);
    __type(value, struct backend);
    __uint(max_entries, 128);
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
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
    __type(key, struct vrpp);
    __type(value, struct counter);
    __uint(max_entries, 1024);
} vrpp_counter SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
    __type(key, struct vrpp);
    __type(value, __s32);
    __uint(max_entries, 1024);
} vrpp_concurrent SEC(".maps");


struct global {
    __u64 rx_packets;
    __u64 rx_octets;
    __u64 perf_packets;
    __u64 perf_timens;
    __u64 perf_timer;
    __u64 settings_timer;
    __u64 defcon;
    __u64 dropped;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, unsigned int);
    __type(value, struct global);
    __uint(max_entries, 1);
} globals SEC(".maps");


struct setting {
    __u8 defcon;
    __u8 era;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, unsigned int);
    __type(value, struct setting);
    __uint(max_entries, 1);
} settings SEC(".maps");

/**********************************************************************/

__u8 DEFCON = 5;

static inline __u16 l4_hash(struct iphdr *ipv4, void *l4)
{
    struct tuple t;
    memset(&t, 0, sizeof(t));
    t.src = ipv4->saddr;
    t.dst = ipv4->daddr;
    t.sport = 0;
    t.dport = 0;
    t.protocol = ipv4->protocol;
    switch(ipv4->protocol) {
    case IPPROTO_TCP:
	t.sport = ((struct tcphdr *) l4)->source;
	t.dport = ((struct tcphdr *) l4)->dest;
	break;
	
    case IPPROTO_UDP:
	t.sport = ((struct udphdr *) l4)->source;
	t.dport = ((struct udphdr *) l4)->dest;
	break;
    }
    
    return sdbm((unsigned char *)&t, sizeof(t));
}

static inline void write_perf(struct global *global, __u64 start) {
    if(global) {
	global->perf_timens += (bpf_ktime_get_ns() - start);
	global->perf_packets++;
    }
}

//static inline void store_flow(struct flow *flow, __be32 rip, __u8 *mac)
//{
//    struct state new_state;
//    memset(&new_state, 0, sizeof(new_state));
//    new_state.rip = rip;
//    maccpy(new_state.mac, mac);
//    bpf_map_update_elem(&flow_state, flow, &new_state, BPF_ANY);
//}

static inline int find_real(struct iphdr *ipv4, void *l4, struct real *r) {
    struct service s;
    memset(&s, 0, sizeof(s));
    s.vip = ipv4->daddr;
    //s.port = tcp->dest;
    s.port = 0;
    s.protocol = ipv4->protocol;

    switch(ipv4->protocol) {
    case IPPROTO_TCP:
        s.port = ((struct tcphdr *) l4)->dest;
        break;

    case IPPROTO_UDP:
        s.port = ((struct udphdr *) l4)->dest;
        break;
    }
    
    struct backend *backend = bpf_map_lookup_elem(&service_backend, &s);

    if(!backend)
	return 0; //return NULL;
    
    if(backend->flag[0] != 0) {
	return 2;
    }
    
    __u16 hash = l4_hash(ipv4, l4);
    __u8 i = backend->hash[hash>>3];
    
    if(i == 0) {
	return 0; //return NULL;
    }

    *r = backend->real[i];
    
    //return r; //&(backend->real[i]);
    return 1;
}

static inline void store_tcp_flow(struct iphdr *ipv4, struct tcphdr *tcp, __be32 rip, __u8 *mac)
{
    struct flow flow;
    flow.src = ipv4->saddr;
    flow.dst = ipv4->daddr;
    flow.sport = tcp->source;
    flow.dport = tcp->dest;
    
    struct state new_state;
    memset(&new_state, 0, sizeof(new_state));
    new_state.rip = rip;
    maccpy(new_state.mac, mac);
    maccpy(new_state.pad, mac);
    new_state.time = bpf_ktime_get_ns();
    
    bpf_map_update_elem(&flow_state, &flow, &new_state, BPF_ANY);
}

static inline void be_tcp_counter(__be32 vip, __be16 port, __be32 rip, int n)
{
    struct vrpp vr;
    vr.vip = vip;
    vr.rip = rip;
    vr.port = port;
    vr.protocol = IPPROTO_TCP;
    vr.pad = 0;
    struct counter *co = bpf_map_lookup_elem(&vrpp_counter, &vr);
    if(co) {
	co->octets += n;
	co->packets++;
    }
}


static inline __s32 * _be_tcp_concurrent(__be32 vip, __be16 port, __be32 rip, __u8 era)
{   
    struct vrpp vr;
    vr.vip = vip;
    vr.rip = rip;
    vr.port = port;
    vr.protocol = IPPROTO_TCP;
    vr.pad = era;
    return (__s32 *) bpf_map_lookup_elem(&vrpp_concurrent, &vr);
}

static inline void be_tcp_concurrent(struct state *state, struct iphdr *ipv4, struct tcphdr *tcp, __u8 era)
{

    
    if (state->finrst == 0 && ((tcp->rst == 1) || (tcp->fin == 1))) {
	state->finrst = 10;
    } else {
	if (state->finrst > 0) {
	    (state->finrst)--;
	}
    }
    
    __s32 *concurrent = NULL;      
    if (state->era != era) {
	state->era = era;
	
	switch(state->finrst) {
	case 10:
	    break;
	case 0:
	    concurrent = _be_tcp_concurrent(ipv4->daddr, tcp->dest, state->rip, era);
	    //concurrent = bpf_map_lookup_elem(&vip_rip_port_concurrent, &vrp);
	    if(concurrent) (*concurrent)++;
	    break;
	}
    } else {
	switch(state->finrst) {
	case 10:
	    concurrent = _be_tcp_concurrent(ipv4->daddr, tcp->dest, state->rip, era);
	    //concurrent = bpf_map_lookup_elem(&vip_rip_port_concurrent, &vrp);
	    if(concurrent) (*concurrent)--;
	    break;
	case 0:
	    break;
	}
    }
}


const int zero = 0;

// DEFCON1 - only global stats (and periodic check for settings) and stateless forwarding done
// DEFCON2 - per backend stats recorded
// DEFCON3 - flow state table consulted
// DEFCON4 - flow state table written to
// DEFCON5 - flow conncurrency?

__u8 FOO[65536];

#define DEFCON1 1
#define DEFCON2 2
#define DEFCON3 3
#define DEFCON4 4
#define DEFCON5 5

__u8 ERA = 0;

SEC("xdp_main") int xdp_main_func(struct xdp_md *ctx)
{
    __u64 start = bpf_ktime_get_ns();

    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;

    struct global *global = bpf_map_lookup_elem(&globals, &zero);

    if(DEFCON == 0) DEFCON = 1; // 0 not allowed
    
    if(global) {
	
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
	
	// once per second load settings
	if((global->settings_timer - start) > ((__u64) 1 * SECOND_NS)) {
	    global->settings_timer = start;

	    struct setting *setting = bpf_map_lookup_elem(&settings, &zero);
	    if(setting) {
		ERA = setting->era % 2;
		
		switch(setting->defcon) {
		case DEFCON1:
		case DEFCON2:
		case DEFCON3:
		case DEFCON4:
		case DEFCON5:
		    DEFCON = setting->defcon;
		    break;
		default:
		    DEFCON = DEFCON5;
		    break;
		}
	    }
	}

	global->rx_packets++;
	global->rx_octets += (data_end - data);
	global->defcon = DEFCON;
	
	// ~90ns to here
	//write_perf(global, start); global = NULL;
    }

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
    
    // we don't support ip options
    if (ipv4->ihl != 5) {
	return XDP_DROP;
    }
    
    // ignore evil bit and DF, drop if more fragments flag set, or fragent offset is not 0
    if ((ipv4->frag_off & bpf_htons(0x3fff)) != 0) {
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
    
  
    // ~130ns to here ...
    //write_perf(global, start); global = NULL;
    
    if(DEFCON >= DEFCON3) {
	struct flow flow;
	flow.src = ipv4->saddr;
	flow.dst = ipv4->daddr;
	flow.sport = tcp->source;
	flow.dport = tcp->dest;
	
	// failed lookup takes ~70ns
	struct state *state = NULL;
	if((state = bpf_map_lookup_elem(&flow_state, &flow))) {
	    // ~230ns to here
	    //write_perf(global, start); global = NULL;
	    
	    if((state->time + (60l * SECOND_NS)) < start) {
		goto new_flow;
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
	    
	    if(equmac(state->mac, eth_hdr->h_dest)) {
		goto invalid_state; // looks like local NIC
	    }
	  
	    if(equmac(state->mac, eth_hdr->h_source)) {
		goto invalid_state; // unlikely that we should echo packet back to source on l2lb
	    }
	    
	    
	    /**********************************************************************/
	    if(0) be_tcp_concurrent(state, ipv4, tcp, ERA);
	    /**********************************************************************/
	    
	    maccpy(eth_hdr->h_source, eth_hdr->h_dest);
	    maccpy(eth_hdr->h_dest, state->mac);
	    
	    be_tcp_counter(ipv4->daddr, tcp->dest, state->rip, data_end - data);
	    
	    write_perf(global, start);
	    
	    return XDP_TX;
	    
	invalid_state:
	    bpf_map_delete_elem(&flow_state, &flow);
	    if(global) global->dropped++;
	    write_perf(global, start);
	    return XDP_DROP;
	}
    }
    global = NULL;
    struct real real_s;
    struct real *real = &real_s;
    
 new_flow:
    
    switch(find_real(ipv4, (void *) tcp, &real_s)) {
    case 0:
	break;
    case 2:
	return XDP_PASS;
    case 1:
	//return XDP_PASS;
	//if(real) {
	//write_perf(global, start); global = NULL;

	if(real->rip == 0) {
	    goto invalid_real;
	}
	
	if(nulmac(real->mac)) {
	    goto invalid_real;
	}
      
	if(equmac(real->mac, eth_hdr->h_dest)) {
	    goto invalid_real; // looks like local NIC, but not declared as such
	}

	if(equmac(real->mac, eth_hdr->h_source)) {
	    goto invalid_real; // unlikely that we would want to echo packet back to source on an l2lb
	}
      
	maccpy(eth_hdr->h_source, eth_hdr->h_dest);
	maccpy(eth_hdr->h_dest, real->mac);
      
	if(DEFCON >= DEFCON4) store_tcp_flow(ipv4, tcp, real->rip, real->mac);
	if(DEFCON >= DEFCON2) be_tcp_counter(ipv4->daddr, tcp->dest, real->rip, data_end - data);

	write_perf(global, start);
      
	return XDP_TX;

    invalid_real:
	if(global) global->dropped++;
	write_perf(global, start);
	return XDP_DROP;
    }



    global = NULL; // don't time-non-balanced traffic

    // DROP PACKETS TO PORTS ON VIPS WHICH HAVEN'T BEEN CAUGHT BY A SERVICE
    struct vrpp vr;
    vr.vip = ipv4->daddr;
    vr.rip = 0;
    vr.port = 0;
    vr.protocol = 0;
    vr.pad = 0;
    struct counter *co = bpf_map_lookup_elem(&vrpp_counter, &vr);
    if(co) {
	co->octets += data_end - data;
	co->packets++;
	return XDP_DROP;
    }
  

    //OUTGOING_PROBE:
  
    struct nat *vme = bpf_map_lookup_elem(&nat_to_vip_mac, &(ipv4->daddr));
    if (vme) {

	if(!(vme->ifindex)) {         // local backend
	    ipv4->daddr = vme->dstip; // vip addr, but keep x.y.255.254 as src
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

    //RETURNING_PROBE:
  
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
