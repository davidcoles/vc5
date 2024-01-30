#define MAX_TCP_SIZE 1480
#define MAX_ICMP_SIZE 64

static __always_inline unsigned short generic_checksum(unsigned short *buf, void *data_end, unsigned long sum, int max) {
    
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


static __always_inline unsigned short ipv4_checksum(unsigned short *buf, void *data_end)
{
    return generic_checksum(buf, data_end, 0, sizeof(struct iphdr));
}

static __always_inline __u16 l4_checksum(struct iphdr *iph, void *l4, void *data_end)
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

//static __always_inline __u16 csum_fold_helper(__u32 csum)
//{
//    __u32 sum;
//    sum = (csum >> 16) + (csum & 0xffff);
//    sum += (sum >> 16);
//    return ~sum;
//}

//static __always_inline void ip_set_ttl(struct iphdr *iph, __u8 ttl)
//{
//    __wsum csum = iph->check;
//    __be32 old = *((__be32 *) &(iph->ttl));
//    iph->ttl = ttl;
//    csum = bpf_csum_diff(&old, sizeof(old), (__be32 *) &(iph->ttl), sizeof(old), ~csum);
//    iph->check = csum_fold_helper(csum);
//}

static __always_inline int ip_decrease_ttl(struct iphdr *iph)
{
    __u32 check = iph->check;
    check += bpf_htons(0x0100);
    iph->check = (__u16)(check + (check >= 0xFFFF));
    return --(iph->ttl);
}

static __always_inline __u16 sdbm(unsigned char *ptr, __u8 len) {
    unsigned long hash = 0;
    unsigned char c;
    unsigned int n;

    for(n = 0; n < len; n++) {
        c = ptr[n];
        hash = c + (hash << 6) + (hash << 16) - hash;
    }

    return hash & 0xffff;
}

struct hash_s {
    __be32 src;
    __be32 dst;
    __be16 sport;
    __be16 dport;
};


static __always_inline __u16 l4_hash(struct iphdr *ipv4, __be16 s, __be16 d)
{
    struct hash_s h = { .src = ipv4->saddr, .dst = ipv4->daddr, .sport = s, .dport = d };
    return sdbm((unsigned char *)&h, sizeof(h));
}
