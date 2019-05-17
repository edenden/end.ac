#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <sys/epoll.h>
#include <net/ethernet.h>
#include <signal.h>
#include <sys/signalfd.h>
#include <pthread.h>

#include <linux/if_link.h>
#include <linux/if_xdp.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "main.h"
#include "lib.h"
#include "driver.h"

static inline uint64_t xdp_slot_addr_rel(struct xdp_buf *buf,
	unsigned int slot_index);
static inline void *xdp_slot_addr_virt(struct xdp_buf *buf,
	unsigned int slot_index);
static inline unsigned int xdp_slot_index(struct xdp_buf *buf,
	uint64_t addr_rel);

void xdp_rx_fill(struct xdp_plane *plane, unsigned int port_idx,
	struct xdp_buf *buf)
{
	struct xdp_port *port;
	struct xdp_ring *fq_ring;
	unsigned int total_fill;
	uint16_t next_to_use, desc_idx;
	uint64_t *desc;
	int slot_index;

	port = &plane->ports[port_idx];
	fq_ring = &port->fq_ring;

	desc_idx = *fq_ring->producer;
	total_fill = 0;

	while(1){
		if(((desc_idx + 1) & (XDPD_RX_DESC - 1))
			== (*fq_ring->consumer & (XDPD_RX_DESC - 1)))
			break;

		slot_index = xdp_slot_assign(buf, plane, port_idx);
		if(unlikely(slot_index < 0)){
			port->count_rx_alloc_failed++;
			break;
		}

		next_to_use = desc_idx & (XDPD_RX_DESC - 1);
		desc = &((uint64_t *)fq_ring->descs)[next_to_use];
		*desc = xdp_slot_addr_rel(buf, slot_index);

		desc_idx++;
		total_fill++;
	}

	if(total_fill){
		wmb();
		*fq_ring->producer = desc_idx;
	}

	return;
}

void xdp_tx_fill(struct xdp_plane *plane, unsigned int port_idx,
	struct xdp_buf *buf)
{
	struct xdp_port *port;
	struct xdp_vec *vec;
	struct xdp_ring *tx_ring;
	uint16_t next_to_use, desc_idx;
	unsigned int total_fill;
	struct xdp_desc *desc;
	int i, err;

	port = &plane->ports[port_idx];
	vec = &port->vec;
	tx_ring = &port->tx_ring;

	desc_idx = *tx_ring->producer;
	total_fill = 0;
	i = 0;

	while(i++ < vec->num){
		if(((desc_idx + 1) & (XDPD_TX_DESC - 1))
			== (*tx_ring->consumer & (XDPD_TX_DESC - 1))){
			port->count_tx_xmit_failed++;
			xdp_slot_release(buf,
				vec->packets[total_fill].slot_index);
			continue;
		}

		next_to_use = desc_idx & (XDPD_TX_DESC - 1);
		desc = &((struct xdp_desc *)tx_ring->descs)[next_to_use];
		desc->addr = xdp_slot_addr_rel(buf,
			vec->packets[total_fill].slot_index);
		desc->len = vec->packets[total_fill].slot_size;

		xdp_print("Tx: addr = %p size = %d port_idx = %d\n",
			(void *)desc->addr, desc->len, port_idx);

		desc_idx++;
		total_fill++;
	}

	if(total_fill){
		wmb();
		*tx_ring->producer = desc_idx;

		err = sendto(port->xfd, NULL, 0, MSG_DONTWAIT, NULL, 0);
		if (err < 0){
			xdp_print("Tx: packet sending error = %d\n", err);
			return;
		}
	}

	vec->num = 0;
	return;
}

unsigned int xdp_rx_pull(struct xdp_plane *plane, unsigned int port_idx,
	struct xdp_buf *buf)
{
	struct xdp_port *port;
	struct xdp_vec *vec;
	struct xdp_ring *rx_ring;
	uint16_t next_to_clean, desc_idx;
	struct xdp_desc *desc;
	unsigned int total_pull;
	unsigned int slot_index;

	port = &plane->ports[port_idx];
	vec = &port->vec;
	rx_ring = &port->rx_ring;

	desc_idx = *rx_ring->consumer;
	total_pull = 0;

	while(total_pull < XDPD_RX_BUDGET){
		if(desc_idx == *rx_ring->producer){
			break;
		}

		next_to_clean = desc_idx & (XDPD_RX_DESC - 1);
		desc = &((struct xdp_desc *)rx_ring->descs)[next_to_clean];
		slot_index = xdp_slot_index(buf, desc->addr);

		vec->packets[total_pull].slot_buf =
			xdp_slot_addr_virt(buf, slot_index);
		vec->packets[total_pull].slot_size = desc->len;
		vec->packets[total_pull].slot_index = slot_index;

		xdp_print("Rx: packet received slot = %d, size = %d\n",
			vec->packets[total_pull].slot_index,
			vec->packets[total_pull].slot_size);

		desc_idx++;
		total_pull++;
	}

	if(total_pull){
		wmb();
		*rx_ring->consumer = desc_idx;
	}

	port->count_rx_clean_total += total_pull;
	vec->num = total_pull;
	return total_pull;
}

void xdp_tx_pull(struct xdp_plane *plane, unsigned int port_idx,
	struct xdp_buf *buf)
{
	struct xdp_port *port;
	struct xdp_ring *cq_ring;
	uint16_t next_to_clean, desc_idx;
	uint64_t *desc;
	unsigned int total_pull;
	unsigned int slot_index;

	port = &plane->ports[port_idx];
	cq_ring = &port->cq_ring;

	desc_idx = *cq_ring->consumer;
	total_pull = 0;

	while(total_pull < XDPD_TX_BUDGET){
printf("Tx pull desc_idx = %d, producer = %d\n", desc_idx, *cq_ring->producer);
		if(desc_idx == *cq_ring->producer){
			break;
		}

		next_to_clean = desc_idx & (XDPD_TX_DESC - 1);
		desc = &((uint64_t *)cq_ring->descs)[next_to_clean];
		slot_index = xdp_slot_index(buf, *desc);

		xdp_slot_release(buf, slot_index);

		desc_idx++;
		total_pull++;
	}

printf("Tx-pull total_pull = %d\n", total_pull);

	if(total_pull){
		wmb();
		*cq_ring->consumer = desc_idx;
	}

	port->count_tx_clean_total += total_pull;
	return;
}

int xdp_slot_assign(struct xdp_buf *buf,
	struct xdp_plane *plane, unsigned int port_idx)
{
	struct xdp_port *port;
	int slot_next, slot_index, i;

	port = &plane->ports[port_idx];
	slot_next = port->rx_slot_next;

	for(i = 0; i < buf->count_devbuf; i++){
		slot_index = port->rx_slot_offset + slot_next;
		if(!(buf->slots[slot_index] & XDP_SLOT_INFLIGHT)){
			goto out;
		}

		slot_next++;
		if(slot_next == buf->count_devbuf)
			slot_next = 0;
	}

	return -1;

out:
	port->rx_slot_next = slot_next + 1;
	if(port->rx_slot_next == buf->count_devbuf)
		port->rx_slot_next = 0;

	buf->slots[slot_index] |= XDP_SLOT_INFLIGHT;
	return slot_index;
}

void xdp_slot_release(struct xdp_buf *buf,
	unsigned int slot_index)
{
	buf->slots[slot_index] = 0;
	return;
}

static inline uint64_t xdp_slot_addr_rel(struct xdp_buf *buf,
	unsigned int slot_index)
{
	return (buf->slot_size * slot_index);
}

static inline void *xdp_slot_addr_virt(struct xdp_buf *buf,
	unsigned int slot_index)
{
	return buf->addr + (buf->slot_size * slot_index);
}

static inline unsigned int xdp_slot_index(struct xdp_buf *buf,
	uint64_t addr_rel)
{
	return (addr_rel / buf->slot_size);
}
