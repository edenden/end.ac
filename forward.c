#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <stddef.h>

#include "main.h"
#include "forward.h"
#include "thread.h"
#include "driver.h"

#ifdef SRV6_END_AC
#include <linux/seg6.h>
#include <pthread.h>

static inline uint16_t forward_endac_check_inc(uint16_t old_check,
	uint16_t old, uint16_t new);
static inline int forward_endac_ip(struct iphdr *ip, uint8_t tos);
static inline int forward_endac_ip6(struct ip6_hdr *ip6);
static inline int forward_endac_srv6(struct ip6_hdr *ip6,
	struct ipv6_sr_hdr *srv6);
static inline void forward_endac_eth(struct ethhdr *eth,
	void *dst, void *src, uint16_t proto);
static int forward_srv6_inner(struct xdpd_thread *thread,
	unsigned int port_index, struct xdp_packet *packet);
static int forward_srv6_outer(struct xdpd_thread *thread,
	unsigned int port_index, struct xdp_packet *packet);
#else
static int forward_ip_process(struct xdpd_thread *thread,
	unsigned int port_index, struct xdp_packet *packet);
static int forward_ip6_process(struct xdpd_thread *thread,
	unsigned int port_index, struct xdp_packet *packet);
#endif

#ifdef DEBUG
void forward_dump(struct xdp_packet *packet)
{
	struct ethhdr *eth;

	eth = (struct ethhdr *)packet->slot_buf;

	printf("packet dump:\n");
	printf("\tsrc %02x:%02x:%02x:%02x:%02x:%02x\n",
		eth->h_source[0], eth->h_source[1], eth->h_source[2],
		eth->h_source[3], eth->h_source[4], eth->h_source[5]);
	printf("\tdst %02x:%02x:%02x:%02x:%02x:%02x\n",
		eth->h_dest[0], eth->h_dest[1], eth->h_dest[2],
		eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
	printf("\ttype 0x%x\n", eth->h_proto);
	printf("\tsize %d bytes\n", packet->slot_size);
}
#endif

void forward_process(struct xdpd_thread *thread, unsigned int port_index)
{
	struct xdp_port *port;
	struct xdp_vec *vec, *vec_target;
	struct ethhdr *eth;
	int i, ret;

	port = &thread->plane->ports[port_index];
	vec = &port->vec;

	/* software prefetch is not needed when DDIO is available */
#ifdef DDIO_UNSUPPORTED
	for(i = 0; i < vec->num; i++){
		prefetchw(packet[i].slot_buf);
	}
#endif

	for(i = 0; i < vec->num; i++){
#ifdef DEBUG
		forward_dump(&vec->packets[i]);
#endif

		/* TBD: Support jumbo frame */
		eth = (struct ethhdr *)vec->packets[i].slot_buf;
		switch(ntohs(eth->h_proto)){
		case ETH_P_IP:
#ifdef SRV6_END_AC
			ret = forward_srv6_inner(thread,
				port_index, &vec->packets[i]);
#else
			ret = forward_ip_process(thread,
				port_index, &vec->packets[i]);
#endif
			break;
		case ETH_P_IPV6:
#ifdef SRV6_END_AC
			ret = forward_srv6_outer(thread,
				port_index, &vec->packets[i]);
#else
			ret = forward_ip6_process(thread,
				port_index, &vec->packets[i]);
#endif
			break;
		default:
			ret = -1;
			break;
		}

		if(ret < 0){
			xdp_slot_release(thread->buf,
				vec->packets[i].slot_index);
			continue;
		}

		vec_target = &thread->plane->ports[ret].vec;
		vec_target->packets[vec_target->num++] = vec->packets[i];
	}
	vec->num = 0;

	return;
}

#ifdef SRV6_END_AC
static inline uint16_t forward_endac_check_inc(uint16_t old_check,
	uint16_t old, uint16_t new)
{
	uint32_t check;

	old_check = ~ntohs(old_check);
	old = ~old;
	check = (uint32_t)old_check + old + new;
	return htons(~((uint16_t)(check >> 16) + (check & 0xffff)));
}

static inline int forward_endac_ip(struct iphdr *ip, uint8_t tos)
{
	uint32_t check;

	if(unlikely(ip->ttl == 1))
		goto drop;

	ip->ttl--;

	check = ip->check;
	check += htons(0x0100);
	ip->check = check + ((check >= 0xFFFF) ? 1 : 0);

	ip->check = forward_endac_check_inc(ip->check, ip->tos, tos);
	ip->tos = tos;

	return 0;

drop:
	return -1;
}

static inline int forward_endac_ip6(struct ip6_hdr *ip6)
{
	if(unlikely(ip6->ip6_hlim == 1))
		goto drop;

	ip6->ip6_hlim--;

	return 0;

drop:
	return -1;
}

static inline int forward_endac_srv6(struct ip6_hdr *ip6,
	struct ipv6_sr_hdr *srv6)
{
	if(unlikely(srv6->segments_left == 0))
		goto drop;

	if(srv6->hdrlen * 8 < srv6->segments_left * 16)
		goto drop;

	srv6->segments_left--;
	memcpy(&ip6->ip6_dst, &srv6->segments[srv6->segments_left], 16);

	if(srv6->nexthdr != IPPROTO_IPIP)
		goto drop;

	return 0;

drop:
	return -1;
}

static inline void forward_endac_eth(struct ethhdr *eth,
	void *dst, void *src, uint16_t proto)
{
	memcpy(eth->h_dest, dst, ETH_ALEN);
	memcpy(eth->h_source, src, ETH_ALEN);
	eth->h_proto = htons(proto);

	return;
}


static int forward_srv6_inner(struct xdpd_thread *thread,
	unsigned int port_index, struct xdp_packet *packet)
{
	struct xdp_port		*port;
	struct ethhdr		*eth;
	struct iphdr		*ip;
	struct ip6_hdr		*ip6;
	struct sr_cache_table	*sr_table;
	struct sr_cache		*sr_cache;
	uint8_t			sr_arg;
	unsigned int		len;
	int			ret, err;

printf("forward_srv6_inner\n");
	port = &thread->plane->ports[port_index];
	len = packet->slot_size;

	if(!(port->mode & SRV6_END_AC_MODE_INNER))
		goto packet_drop;

	if(len < sizeof(struct ethhdr))
		goto packet_drop;
	len -= sizeof(struct ethhdr);
	eth = (struct ethhdr *)packet->slot_buf;

	forward_endac_eth(eth,
		port->bound_mac_addr, port->mac_addr, ETH_P_IPV6);

	if(len < sizeof(struct iphdr))
		goto packet_drop;
	len -= sizeof(struct iphdr);
	ip = (struct iphdr *)(eth + 1);

	sr_arg = ip->tos;

	err = forward_endac_ip(ip, 0);
	if(err < 0)
		goto packet_drop;

	sr_table = &sr_cache_table[port->bound_table_idx];

	sr_cache = &sr_table->cache[sr_arg];
	pthread_rwlock_rdlock(&sr_cache->lock);
	if(!sr_cache->size){
		pthread_rwlock_unlock(&sr_cache->lock);
		goto packet_drop;
	}

	if(packet->slot_size + sr_cache->size > thread->buf->slot_size){
		pthread_rwlock_unlock(&sr_cache->lock);
		goto packet_drop;
	}

	memcpy((uint8_t *)(eth + 1) + sr_cache->size,
		(uint8_t *)(eth + 1),
		packet->slot_size - sizeof(struct ethhdr));
	memcpy((uint8_t *)(eth + 1), sr_cache->buf, sr_cache->size);
	pthread_rwlock_unlock(&sr_cache->lock);

	ip6 = (struct ip6_hdr *)(eth + 1);

	err = forward_endac_ip6(ip6);
	if(err < 0)
		goto packet_drop;

	packet->slot_size += sr_cache->size;
	ret = port->bound_port_idx;
	return ret;

packet_drop:
	return -1;
}

static int forward_srv6_outer(struct xdpd_thread *thread,
	unsigned int port_index, struct xdp_packet *packet)
{
	struct xdp_port		*port;
	struct ethhdr		*eth;
	struct iphdr		*ip;
	struct ip6_hdr		*ip6;
	struct ipv6_sr_hdr	*srv6;
	struct sr_cache_table	*sr_table;
	struct sr_cache		*sr_cache;
	struct sr_sid		*sr_sid;
	uint8_t			sr_arg;
	unsigned int		len, cache_len;
	int			ret, err;

printf("forward_srv6_outer\n");
	port = &thread->plane->ports[port_index];
	len = packet->slot_size;

	if(!(port->mode & SRV6_END_AC_MODE_OUTER))
		goto packet_drop;

	if(len < sizeof(struct ethhdr))
		goto packet_drop;
	len -= sizeof(struct ethhdr);
	eth = (struct ethhdr *)packet->slot_buf;

	forward_endac_eth(eth,
		port->bound_mac_addr, port->mac_addr, ETH_P_IP);

	if(len < sizeof(struct ip6_hdr))
		goto packet_drop;
	len -= sizeof(struct ip6_hdr);
	ip6 = (struct ip6_hdr *)(eth + 1);

	err = forward_endac_ip6(ip6);
	if(err < 0)
		goto packet_drop;

	if(ip6->ip6_nxt != IPPROTO_SRV6)
		goto packet_drop;

	sr_table = &sr_cache_table[port->bound_table_idx];

	sr_sid = &sr_table->sid;
	if(memcmp(&ip6->ip6_dst, sr_sid->sid, sr_sid->len))
		goto packet_drop;

	sr_arg = ip6->ip6_dst.s6_addr[sr_sid->arg_offset];
	sr_cache = &sr_table->cache[sr_arg];

	if(len < sizeof(struct ipv6_sr_hdr))
		goto packet_drop;
	len -= sizeof(struct ipv6_sr_hdr);
	srv6 = (struct ipv6_sr_hdr *)(ip6 + 1);

	if(len < (srv6->hdrlen * 8))
		goto packet_drop;
	len -= (srv6->hdrlen * 8);

	err = forward_endac_srv6(ip6, srv6);
	if(err < 0)
		goto packet_drop;

	cache_len = sizeof(struct ip6_hdr)
		+ sizeof(struct ipv6_sr_hdr) + (srv6->hdrlen * 8);

	pthread_rwlock_wrlock(&sr_cache->lock);
	memcpy(sr_cache->buf, (uint8_t *)(eth + 1), cache_len);
	sr_cache->size = cache_len;
	pthread_rwlock_unlock(&sr_cache->lock);
	memcpy((uint8_t *)(eth + 1), (uint8_t *)(eth + 1) + cache_len, len);

	if(len < sizeof(struct iphdr))
		goto packet_drop;
	len -= sizeof(struct iphdr);
	ip = (struct iphdr *)(eth + 1);

	err = forward_endac_ip(ip, sr_arg);
	if(err < 0)
		goto packet_drop;

	packet->slot_size -= cache_len;
	ret = port->bound_port_idx;
	return ret;

packet_drop:
	return -1;
}

#else
static int forward_ip_process(struct xdpd_thread *thread,
	unsigned int port_index, struct xdp_packet *packet)
{
	struct xdp_port		*port;
	struct ethhdr		*eth;
	struct iphdr		*ip;
	void			*dst_mac, *src_mac;
	uint32_t		check;
	int			ret;

	port = &thread->plane->ports[port_index];
	eth = (struct ethhdr *)packet->slot_buf;
	ip = (struct iphdr *)(eth + 1);

	if(unlikely(ip->ttl == 1))
		goto packet_drop;

	ip->ttl--;

	check = ip->check;
	check += htons(0x0100);
	ip->check = check + ((check >= 0xFFFF) ? 1 : 0);

	dst_mac = neigh_entry->dst_mac;
	src_mac = port->mac_addr;
	memcpy(eth->h_dest, dst_mac, ETH_ALEN);
	memcpy(eth->h_source, src_mac, ETH_ALEN);

	ret = fib_entry->port_index;
	return ret;

packet_drop:
	return -1;
}

static int forward_ip6_process(struct xdpd_thread *thread,
	unsigned int port_index, struct xdp_packet *packet)
{
	struct xdp_port		*port;
	struct ethhdr		*eth;
	struct ip6_hdr		*ip6;
	void			*dst_mac, *src_mac;
	int			ret;

	port = &thread->plane->ports[port_index];
	eth = (struct ethhdr *)packet->slot_buf;
	ip6 = (struct ip6_hdr *)(eth + 1);

	if(unlikely(ip6->ip6_hlim == 1))
		goto packet_drop;

	ip6->ip6_hlim--;

	dst_mac = neigh_entry->dst_mac;
	src_mac = port->mac_addr;
	memcpy(eth->h_dest, dst_mac, ETH_ALEN);
	memcpy(eth->h_source, src_mac, ETH_ALEN);

	ret = fib_entry->port_index;
	return ret;

packet_drop:
	return -1;
}
#endif
