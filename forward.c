#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <stddef.h>
#include <linux/seg6.h>

#include "main.h"
#include "forward.h"
#include "thread.h"
#include "driver.h"

#ifdef SRV6_END_AC
#include <pthread.h>

static inline uint16_t xdp_ip_check_inc(uint16_t old_check,
	uint16_t old, uint16_t new);
static void forward_endac4_in(struct xdp_plane *plane, unsigned int port_idx,
	struct xdp_vec_ref *vec);
static void forward_endac6_in(struct xdp_plane *plane, unsigned int port_idx,
	struct xdp_vec_ref *vec);
static void forward_endac4_out(struct xdp_plane *plane, unsigned int port_idx,
	struct xdp_vec_ref *vec);
static void forward_endac6_out(struct xdp_plane *plane, unsigned int port_idx,
	struct xdp_vec_ref *vec);
#endif

static inline unsigned int xdp_pkt_rest(struct xdp_packet *pkt);
static void forward_start(struct xdp_plane *plane, unsigned int port_idx,
	struct xdp_vec *vec);
static void forward_eth(struct xdp_plane *plane, unsigned int port_idx,
	struct xdp_vec_ref *vec);
static void forward_ip(struct xdp_plane *plane, unsigned int port_idx,
	struct xdp_vec_ref *vec);
static void forward_ip6(struct xdp_plane *plane, unsigned int port_idx,
	struct xdp_vec_ref *vec);
static void forward_ip6_ext(struct xdp_plane *plane, unsigned int port_idx,
	struct xdp_vec_ref *vec);
static int process_ip6_ext_sr(struct xdp_packet *pkt);
static int process_ip6_ext_gen(struct xdp_packet *pkt);

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

void forward_process(struct xdpd_thread *thread, unsigned int port_idx)
{
	struct xdp_plane *plane;
	struct xdp_port *port;
	struct xdp_vec *vec_rx;
	struct xdp_vec_ref *vec_tx;
	struct xdp_packet *pkt;
	int i;

	plane = thread->plane;
	port = &plane->ports[port_idx];
	vec_rx = &port->vec_rx;

	/* software prefetch is not needed when DDIO is available */
#ifdef DDIO_UNSUPPORTED
	for(i = 0; i < vec->num; i++){
		prefetchw(packet[i].slot_buf);
	}
#endif

	forward_start(plane, port_idx, vec_rx);

	for(i = 0; i < vec_rx->num; i++){
		pkt = &vec_rx->packets[i];
		if(pkt->out < 0){
			xdp_slot_release(thread->buf, pkt->slot_index);
			continue;
		}

		vec_tx = &thread->plane->ports[pkt->out].vec_tx;
		vec_tx->packets[vec_tx->num++] = &vec_rx->packets[i];
	}

	return;
}

static inline unsigned int xdp_pkt_rest(struct xdp_packet *pkt)
{
	return pkt->slot_size - (pkt->current - pkt->slot_buf);
}

#ifdef SRV6_END_AC
static inline uint16_t xdp_ip_check_inc(uint16_t old_check,
	uint16_t old, uint16_t new)
{
	uint32_t check;

	old_check = ~ntohs(old_check);
	old = ~old;
	check = (uint32_t)old_check + old + new;
	return htons(~((uint16_t)(check >> 16) + (check & 0xffff)));
}
#endif

static void forward_start(struct xdp_plane *plane, unsigned int port_idx,
	struct xdp_vec *vec)
{
	struct xdp_vec_ref vec_ref;
	struct xdp_packet *pkt;
	int i;

	for(i = 0; i < vec->num; i++){
#ifdef DEBUG
		forward_dump(&vec->packets[i]);
#endif

		vec_ref.packets[i] = &vec->packets[i];

		pkt = vec_ref.packets[i];
		pkt->out = -1;
		pkt->current = pkt->slot_buf;
		pkt->layer2 = NULL;
		pkt->layer3 = NULL;
		pkt->flag = 0;
		pkt->nexthdr = 0;
	}
	vec_ref.num = vec->num;
	forward_eth(plane, port_idx, &vec_ref);
	return;
}

static void forward_eth(struct xdp_plane *plane, unsigned int port_idx,
	struct xdp_vec_ref *vec)
{
	struct xdp_port *port;
	struct xdp_packet *pkt;
	struct xdp_vec_ref vec_ip, vec_ip6;
#ifdef SRV6_END_AC
	struct xdp_vec_ref vec_endac4_in;
	struct xdp_vec_ref vec_endac6_in;
#endif
	struct ethhdr *eth;
	int i;

	port = &plane->ports[port_idx];
	vec_ip.num = 0;
	vec_ip6.num = 0;
#ifdef SRV6_END_AC
	vec_endac4_in.num = 0;
	vec_endac6_in.num = 0;
#endif

	for(i = 0; i < vec->num; i++){
		pkt = vec->packets[i];

		if(xdp_pkt_rest(pkt) < sizeof(struct ethhdr))
			continue;

		eth = (struct ethhdr *)pkt->current;
		pkt->layer2 = eth;
		pkt->current = eth + 1;

		switch(ntohs(eth->h_proto)){
		case ETH_P_IP:
#ifdef SRV6_END_AC
			if(port->mode & SRV6_END_AC_MODE_INNER)
				vec_endac4_in.packets[vec_endac4_in.num++] = pkt;
			else
				vec_ip.packets[vec_ip.num++] = pkt;
#else
			vec_ip->packets[vec_ip->num++] = pkt;
#endif
			break;
		case ETH_P_IPV6:
#ifdef SRV6_END_AC
			if(port->mode & SRV6_END_AC_MODE_INNER)
				vec_endac6_in.packets[vec_endac6_in.num++] = pkt;
			else
				vec_ip6.packets[vec_ip6.num++] = pkt;
#else
			vec_ip6->packets[vec_ip6->num++] = pkt;
#endif
			break;
		default:
			break;
		}
	}

	if(vec_ip.num)
		forward_ip(plane, port_idx, &vec_ip);
	if(vec_ip6.num)
		forward_ip6(plane, port_idx, &vec_ip6);
#ifdef SRV6_END_AC
	if(vec_endac4_in.num)
		forward_endac4_in(plane, port_idx, &vec_endac4_in);
	if(vec_endac6_in.num)
		forward_endac6_in(plane, port_idx, &vec_endac6_in);
#endif
	return;
}

static void forward_ip(struct xdp_plane *plane, unsigned int port_idx,
	struct xdp_vec_ref *vec)
{
	struct xdp_port *port;
	struct xdp_packet *pkt;
#if 0
	struct ethhdr *eth;
#endif
	struct iphdr *ip;
	uint32_t check;
	int i;

	port = &plane->ports[port_idx];
	(void)port;

	for(i = 0; i < vec->num; i++){
		pkt = vec->packets[i];

		if(xdp_pkt_rest(pkt) < sizeof(struct iphdr))
			continue;

		ip = (struct iphdr *)pkt->current;
		pkt->layer3 = ip;
		pkt->current = ip + 1;

#if 0
		fib_entry[i] = fib_lookup(pkt);
#endif
	}

	for(i = 0; i < vec->num; i++){
		pkt = vec->packets[i];

#if 0
		if(!fib_entry[i])
			continue;

		neigh_entry = neigh_lookup(fib_entry[i]);
		if(!neigh_entry){
			/* XXX: Inject to kernel */
			continue;
		}
#endif

		ip = (struct iphdr *)pkt->layer3;

		if(ip->ttl == 1){
			/* XXX: Inject to kernel */
			continue;
		}

		ip->ttl--;

		check = ip->check;
		check += htons(0x0100);
		ip->check = check + ((check >= 0xFFFF) ? 1 : 0);

#if 0
		eth = (struct ethhdr *)pkt->layer2;
		memcpy(eth->h_dest, neigh_entry->dst_mac, ETH_ALEN);
		memcpy(eth->h_source, dst_port->mac_addr, ETH_ALEN);
#endif

		pkt->nexthdr = ip->protocol;
	}

	return;
}

static void forward_ip6(struct xdp_plane *plane, unsigned int port_idx,
	struct xdp_vec_ref *vec)
{
	struct xdp_port *port;
	struct xdp_packet *pkt;
	struct xdp_vec_ref vec_ip6_ext;
#ifdef SRV6_END_AC
	struct sr_cache_table	*sr_table;
	struct sr_sid		*sr_sid;
#endif
#if 0
	struct ethhdr *eth;
#endif
	struct ip6_hdr *ip6;
	int i;

	port = &plane->ports[port_idx];
	vec_ip6_ext.num = 0;
#ifdef SRV6_END_AC
	sr_table = &sr_cache_table[port->bound_table_idx];
	sr_sid = &sr_table->sid;
#endif

	for(i = 0; i < vec->num; i++){
		pkt = vec->packets[i];

		if(xdp_pkt_rest(pkt) < sizeof(struct ip6_hdr))
			continue;

		ip6 = (struct ip6_hdr *)pkt->current;
		pkt->layer3 = ip6;
		pkt->current = ip6 + 1;

#if 0
		fib_entry[i] = fib_lookup(pkt);
#endif

#ifdef SRV6_END_AC
		if(port->mode & SRV6_END_AC_MODE_OUTER
		&& !memcmp(&ip6->ip6_dst, sr_sid->sid, sr_sid->len)){
			pkt->flag |= PACKET_SRV6_MATCH;
			pkt->flag |= PACKET_SRV6_ENDAC_MATCH;
		}else{
			pkt->flag &= ~PACKET_SRV6_MATCH;
			pkt->flag &= ~PACKET_SRV6_ENDAC_MATCH;
		}
#endif
	}

	for(i = 0; i < vec->num; i++){
		pkt = vec->packets[i];

#if 0
		if(!fib_entry[i])
			continue;

		neigh_entry = neigh_lookup(fib_entry[i]);
		if(!neigh_entry){
			/* XXX: Inject to kernel */
			continue;
		}
#endif

		ip6 = (struct ip6_hdr *)pkt->layer3;

		if(ip6->ip6_hlim == 1){
			/* XXX: Inject to kernel */
			continue;
		}

		ip6->ip6_hlim--;

#if 0
		eth = (struct ethhdr *)pkt->layer2;
		memcpy(eth->h_dest, neigh_entry->dst_mac, ETH_ALEN);
		memcpy(eth->h_source, dst_port->mac_addr, ETH_ALEN);
#endif

		pkt->nexthdr = ip6->ip6_nxt;

		switch(pkt->nexthdr){
		case IPPROTO_ROUTING:
		case IPPROTO_HOPOPTS:
		case IPPROTO_FRAGMENT:
		case IPPROTO_DSTOPTS:
			vec_ip6_ext.packets[vec_ip6_ext.num++] = pkt;
			break;
		default:
			break;
		}
	}

	if(vec_ip6_ext.num)
		forward_ip6_ext(plane, port_idx, &vec_ip6_ext);
	return;
}

static void forward_ip6_ext(struct xdp_plane *plane, unsigned int port_idx,
	struct xdp_vec_ref *vec)
{
	struct xdp_port *port;
	struct xdp_packet *pkt;
	struct xdp_vec_ref vec_ip6;
	struct xdp_vec_ref vec_ip6_ext;
#ifdef SRV6_END_AC
	struct xdp_vec_ref vec_endac4_out;
	struct xdp_vec_ref vec_endac6_out;
#endif
	int i, ret;

	port = &plane->ports[port_idx];
	(void)port;
	vec_ip6.num = 0;
	vec_ip6_ext.num = 0;
#ifdef SRV6_END_AC
	vec_endac4_out.num = 0;
	vec_endac6_out.num = 0;
#endif

	for(i = 0; i < vec->num; i++){
		pkt = vec->packets[i];

		/*
		 * Still handle IPv6 Extension header by per packet processing
		 * for the aspect of code perspective.
		 */
		switch(pkt->nexthdr){
		case IPPROTO_ROUTING:
			/* Only SRv6 has been implemented for now. */
			if(pkt->flag & PACKET_SRV6_MATCH)
				ret = process_ip6_ext_sr(pkt);
			else
				ret = process_ip6_ext_gen(pkt);
			break;
		default:
			ret = process_ip6_ext_gen(pkt);
			break;
		}

		if(ret < 0)
			continue;

		switch(pkt->nexthdr){
		case IPPROTO_ROUTING:
		case IPPROTO_HOPOPTS:
		case IPPROTO_FRAGMENT:
		case IPPROTO_DSTOPTS:
			vec_ip6_ext.packets[vec_ip6_ext.num++] = pkt;
			break;
#ifdef SRV6_END_AC
		case IPPROTO_IPIP:
			if((pkt->flag & PACKET_SRV6_ENDAC_MATCH)
			&& (pkt->flag & PACKET_SRV6_UPDATED))
				vec_endac4_out.packets[vec_endac4_out.num++] = pkt;
			break;
		case IPPROTO_IPV6:
			if((pkt->flag & PACKET_SRV6_ENDAC_MATCH)
			&& (pkt->flag & PACKET_SRV6_UPDATED))
				vec_endac6_out.packets[vec_endac6_out.num++] = pkt;
			break;
#endif
		default:
			if(pkt->flag & PACKET_SRV6_UPDATED){
				pkt->flag &= ~PACKET_SRV6_UPDATED;
				pkt->current = pkt->layer3;
				pkt->nexthdr = 0;
				vec_ip6.packets[vec_ip6.num++] = pkt;
			}
			break;
		}
	}

	if(vec_ip6_ext.num)
		forward_ip6_ext(plane, port_idx, &vec_ip6_ext);
#ifdef SRV6_END_AC
	if(vec_endac4_out.num)
		forward_endac4_out(plane, port_idx, &vec_endac4_out);
	if(vec_endac6_out.num)
		forward_endac6_out(plane, port_idx, &vec_endac6_out);
#endif
	if(vec_ip6.num)
		forward_ip6(plane, port_idx, &vec_ip6);
	return;

}

static int process_ip6_ext_sr(struct xdp_packet *pkt)
{
	struct ip6_hdr *ip6;
	struct ipv6_sr_hdr *srv6;

	if(xdp_pkt_rest(pkt) < sizeof(struct ipv6_sr_hdr))
		goto err;

	srv6 = (struct ipv6_sr_hdr *)pkt->current;
	pkt->current = srv6 + 1;

	if(xdp_pkt_rest(pkt) < srv6->hdrlen * 8)
		goto err;

	pkt->current += srv6->hdrlen * 8;

	if(!(pkt->flag & PACKET_SRV6_UPDATED)
	&& (srv6->segments_left > 0)){
		ip6 = (struct ip6_hdr *)pkt->layer3;

		if(srv6->hdrlen * 8 < srv6->segments_left * 16)
			goto err;

		srv6->segments_left--;
		memcpy(&ip6->ip6_dst,
			&srv6->segments[srv6->segments_left], 16);

#ifdef SRV6_END_AC
		pkt->layer3_ext = srv6;
#endif
		pkt->flag |= PACKET_SRV6_UPDATED;
	}

	pkt->nexthdr = srv6->nexthdr;
	return 0;

err:
	return -1;
}

static int process_ip6_ext_gen(struct xdp_packet *pkt)
{
	struct ip6_ext *ip6_ext;

	if(xdp_pkt_rest(pkt) < 8)
		goto err;

	ip6_ext = (struct ip6_ext *)pkt->current;
	pkt->current += 8;

	if(xdp_pkt_rest(pkt) < ip6_ext->ip6e_len * 8)
		goto err;

	pkt->current += ip6_ext->ip6e_len * 8;

	pkt->nexthdr = ip6_ext->ip6e_nxt;
	return 0;

err:
	return -1;
}

#ifdef SRV6_END_AC
static void forward_endac4_in(struct xdp_plane *plane, unsigned int port_idx,
	struct xdp_vec_ref *vec)
{
	struct xdp_port *port, *dst_port;
	struct xdp_packet *pkt;
	struct xdp_vec_ref vec_ip6;
	struct ethhdr *eth;
	struct iphdr *ip;
	uint32_t check;
	struct sr_cache_table	*sr_table;
	struct sr_cache		*sr_cache;
	uint8_t			sr_arg;
	unsigned int		cache_len;
	int i;

	port = &plane->ports[port_idx];
	sr_table = &sr_cache_table[port->bound_table_idx];
	vec_ip6.num = 0;

	for(i = 0; i < vec->num; i++){
		pkt = vec->packets[i];

		if(xdp_pkt_rest(pkt) < sizeof(struct iphdr))
			continue;

		ip = (struct iphdr *)pkt->current;
		pkt->layer3 = ip;
		pkt->current = ip + 1;

		if(ip->ttl == 1){
			/* XXX: Inject to kernel */
			continue;
		}

		ip->ttl--;

		check = ip->check;
		check += htons(0x0100);
		ip->check = check + ((check >= 0xFFFF) ? 1 : 0);

		sr_arg = ip->tos;

		sr_cache = &sr_table->cache4[sr_arg];
		pthread_rwlock_rdlock(&sr_cache->lock);
		cache_len = sr_cache->size;

		if(!cache_len){
			pthread_rwlock_unlock(&sr_cache->lock);
			continue;
		}

		/* XXX: Size should be compared with outgoing port's MTU */
		if(pkt->slot_size + cache_len > port->mtu_frame){
			pthread_rwlock_unlock(&sr_cache->lock);
			continue;
		}

		memcpy(pkt->layer3 + cache_len, pkt->layer3,
			pkt->slot_size - (pkt->layer3 - pkt->layer2));
		memcpy(pkt->layer3, sr_cache->buf, cache_len);
		pthread_rwlock_unlock(&sr_cache->lock);

		pkt->slot_size += cache_len;

		ip = (struct iphdr *)(pkt->layer3 + cache_len);
		pkt->current = ip + 1;

		ip->check = xdp_ip_check_inc(ip->check, ip->tos, 0);
		ip->tos = 0;

		eth = (struct ethhdr *)pkt->layer2;
		/* XXX:
		 * ideally, dst port(src mac)/dst mac of inner->outer direction
		 * should be determined by FIB lookup
		 */
		memcpy(eth->h_dest, port->bound_mac_addr, ETH_ALEN);
		dst_port = &plane->ports[port->bound_port_idx];
		memcpy(eth->h_source, dst_port->mac_addr, ETH_ALEN);
		eth->h_proto = htons(ETH_P_IPV6);

		pkt->out = port->bound_port_idx;

		pkt->current = pkt->layer3;
		pkt->nexthdr = 0;
		vec_ip6.packets[vec_ip6.num++] = pkt;
	}

	if(vec_ip6.num)
		forward_ip6(plane, port_idx, &vec_ip6);
	return;
}

static void forward_endac6_in(struct xdp_plane *plane, unsigned int port_idx,
	struct xdp_vec_ref *vec)
{
	struct xdp_port *port, *dst_port;
	struct xdp_packet *pkt;
	struct xdp_vec_ref vec_ip6;
	struct ethhdr *eth;
	struct ip6_hdr *ip6;
	struct sr_cache_table	*sr_table;
	struct sr_cache		*sr_cache;
	uint8_t			sr_arg;
	unsigned int		cache_len;
	int i;

	port = &plane->ports[port_idx];
	sr_table = &sr_cache_table[port->bound_table_idx];
	vec_ip6.num = 0;

	for(i = 0; i < vec->num; i++){
		pkt = vec->packets[i];

		if(xdp_pkt_rest(pkt) < sizeof(struct ip6_hdr))
			continue;

		ip6 = (struct ip6_hdr *)pkt->current;
		pkt->layer3 = ip6;
		pkt->current = ip6 + 1;

		if(ip6->ip6_hlim == 1){
			/* XXX: Inject to kernel */
			continue;
		}

		ip6->ip6_hlim--;

		sr_arg = ((uint8_t *)&ip6->ip6_flow)[3];

		sr_cache = &sr_table->cache6[sr_arg];
		pthread_rwlock_rdlock(&sr_cache->lock);
		cache_len = sr_cache->size;

		if(!cache_len){
			pthread_rwlock_unlock(&sr_cache->lock);
			continue;
		}

		/* XXX: Size should be compared with outgoing port's MTU */
		if(pkt->slot_size + cache_len > port->mtu_frame){
			pthread_rwlock_unlock(&sr_cache->lock);
			continue;
		}

		memcpy(pkt->layer3 + cache_len, pkt->layer3,
			pkt->slot_size - (pkt->layer3 - pkt->layer2));
		memcpy(pkt->layer3, sr_cache->buf, cache_len);
		pthread_rwlock_unlock(&sr_cache->lock);

		pkt->slot_size += cache_len;

		ip6 = (struct ip6_hdr *)(pkt->layer3 + cache_len);
		pkt->current = ip6 + 1;

		((uint8_t *)&ip6->ip6_flow)[3] = 0;

		eth = (struct ethhdr *)pkt->layer2;
		/* XXX:
		 * ideally, dst port(src mac)/dst mac of inner->outer direction
		 * should be determined by FIB lookup
		 */
		memcpy(eth->h_dest, port->bound_mac_addr, ETH_ALEN);
		dst_port = &plane->ports[port->bound_port_idx];
		memcpy(eth->h_source, dst_port->mac_addr, ETH_ALEN);
		eth->h_proto = htons(ETH_P_IPV6);

		pkt->out = port->bound_port_idx;

		pkt->current = pkt->layer3;
		pkt->nexthdr = 0;
		vec_ip6.packets[vec_ip6.num++] = pkt;
	}

	if(vec_ip6.num)
		forward_ip6(plane, port_idx, &vec_ip6);
	return;
}

static void forward_endac4_out(struct xdp_plane *plane, unsigned int port_idx,
	struct xdp_vec_ref *vec)
{
	struct xdp_port *port, *dst_port;
	struct xdp_packet *pkt;
	struct ethhdr *eth;
	struct ipv6_sr_hdr *srv6;
	struct in6_addr *sid;
	struct iphdr *ip;
	struct sr_cache_table	*sr_table;
	struct sr_cache		*sr_cache;
	struct sr_sid		*sr_sid;
	uint8_t			sr_arg;
	struct xdp_packet	*sr_cache_pkt[256] = {};
	unsigned int		cache_len;
	int i;

	port = &plane->ports[port_idx];
	sr_table = &sr_cache_table[port->bound_table_idx];
	sr_sid = &sr_table->sid;

	for(i = 0; i < vec->num; i++){
		pkt = vec->packets[i];

		srv6 = (struct ipv6_sr_hdr *)pkt->layer3_ext;
		sid = &srv6->segments[srv6->segments_left + 1];

		sr_arg = sid->s6_addr[sr_sid->arg_offset];
		sr_cache_pkt[sr_arg] = pkt;
	}

	for(i = 0; i < vec->num; i++){
		pkt = vec->packets[i];

		srv6 = (struct ipv6_sr_hdr *)pkt->layer3_ext;
		sid = &srv6->segments[srv6->segments_left + 1];

		sr_arg = sid->s6_addr[sr_sid->arg_offset];
		cache_len = pkt->current - pkt->layer3;

		if(sr_cache_pkt[sr_arg] == pkt){
			sr_cache = &sr_table->cache4[sr_arg];

			pthread_rwlock_wrlock(&sr_cache->lock);
			memcpy(sr_cache->buf, pkt->layer3, cache_len);
			sr_cache->size = cache_len;
			pthread_rwlock_unlock(&sr_cache->lock);
		}

		memcpy(pkt->layer3, pkt->current, xdp_pkt_rest(pkt));
		pkt->slot_size -= cache_len;
		pkt->current = pkt->layer3;

		if(xdp_pkt_rest(pkt) < sizeof(struct iphdr))
			continue;

		ip = (struct iphdr *)pkt->current;
		pkt->current = ip + 1;

		ip->check = xdp_ip_check_inc(ip->check, ip->tos, sr_arg);
		ip->tos = sr_arg;

		eth = (struct ethhdr *)pkt->layer2;
		memcpy(eth->h_dest, port->bound_mac_addr, ETH_ALEN);
		dst_port = &plane->ports[port->bound_port_idx];
		memcpy(eth->h_source, dst_port->mac_addr, ETH_ALEN);
		eth->h_proto = htons(ETH_P_IP);

		pkt->out = port->bound_port_idx;

		pkt->nexthdr = ip->protocol;
	}

	return;
}

static void forward_endac6_out(struct xdp_plane *plane, unsigned int port_idx,
	struct xdp_vec_ref *vec)
{
	struct xdp_port *port, *dst_port;
	struct xdp_packet *pkt;
	struct ethhdr *eth;
	struct ipv6_sr_hdr *srv6;
	struct in6_addr *sid;
	struct ip6_hdr *ip6;
	struct sr_cache_table	*sr_table;
	struct sr_cache		*sr_cache;
	struct sr_sid		*sr_sid;
	uint8_t			sr_arg;
	struct xdp_packet	*sr_cache_pkt[256] = {};
	unsigned int		cache_len;
	int i;

	port = &plane->ports[port_idx];
	sr_table = &sr_cache_table[port->bound_table_idx];
	sr_sid = &sr_table->sid;

	for(i = 0; i < vec->num; i++){
		pkt = vec->packets[i];

		srv6 = (struct ipv6_sr_hdr *)pkt->layer3_ext;
		sid = &srv6->segments[srv6->segments_left + 1];

		sr_arg = sid->s6_addr[sr_sid->arg_offset];
		sr_cache_pkt[sr_arg] = pkt;
	}

	for(i = 0; i < vec->num; i++){
		pkt = vec->packets[i];

		srv6 = (struct ipv6_sr_hdr *)pkt->layer3_ext;
		sid = &srv6->segments[srv6->segments_left + 1];

		sr_arg = sid->s6_addr[sr_sid->arg_offset];
		cache_len = pkt->current - pkt->layer3;

		if(sr_cache_pkt[sr_arg] == pkt){
			sr_cache = &sr_table->cache6[sr_arg];

			pthread_rwlock_wrlock(&sr_cache->lock);
			memcpy(sr_cache->buf, pkt->layer3, cache_len);
			sr_cache->size = cache_len;
			pthread_rwlock_unlock(&sr_cache->lock);
		}

		memcpy(pkt->layer3, pkt->current, xdp_pkt_rest(pkt));
		pkt->slot_size -= cache_len;
		pkt->current = pkt->layer3;

		if(xdp_pkt_rest(pkt) < sizeof(struct ip6_hdr))
			continue;

		ip6 = (struct ip6_hdr *)pkt->current;
		pkt->current = ip6 + 1;

		((uint8_t *)&ip6->ip6_flow)[3] = sr_arg;

		eth = (struct ethhdr *)pkt->layer2;
		memcpy(eth->h_dest, port->bound_mac_addr, ETH_ALEN);
		dst_port = &plane->ports[port->bound_port_idx];
		memcpy(eth->h_source, dst_port->mac_addr, ETH_ALEN);
		eth->h_proto = htons(ETH_P_IP);

		pkt->out = port->bound_port_idx;

		pkt->nexthdr = ip6->ip6_nxt;
	}

	return;
}

#endif
