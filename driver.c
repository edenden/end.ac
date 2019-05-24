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
	uint32_t next_to_use, desc_idx;
	uint32_t cons;
	uint64_t *desc;
	int slot_index;

	port = &plane->ports[port_idx];
	fq_ring = &port->fq_ring;

	desc_idx = *fq_ring->producer;
	total_fill = 0;

	cons = *fq_ring->consumer;

	while(1){
		if(((desc_idx + 1) & (XDPD_RX_DESC - 1))
			== (cons & (XDPD_RX_DESC - 1)))
			break;

		slot_index = xdp_slot_assign(buf, plane, port_idx);
		if(slot_index < 0){
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

	xdp_print("Rx-fill: port_idx = %d, total_fill = %d, prod = %d, cons = %d\n",
		port_idx, total_fill, *fq_ring->producer, *fq_ring->consumer);
	return;
}

void xdp_tx_fill(struct xdp_plane *plane, unsigned int port_idx,
	struct xdp_buf *buf)
{
	struct xdp_port *port;
	struct xdp_vec_ref *vec;
	struct xdp_ring *tx_ring;
	uint32_t next_to_use, desc_idx;
	uint32_t cons;
	unsigned int total_fill;
	struct xdp_desc *desc;
	int i;

	port = &plane->ports[port_idx];
	vec = &port->vec_tx;
	tx_ring = &port->tx_ring;

	desc_idx = *tx_ring->producer;
	total_fill = 0;

	cons = *tx_ring->consumer;

	while(total_fill < vec->num){
		if(((desc_idx + 1) & (XDPD_TX_DESC - 1))
			== (cons & (XDPD_TX_DESC - 1)))
			break;

		next_to_use = desc_idx & (XDPD_TX_DESC - 1);
		desc = &((struct xdp_desc *)tx_ring->descs)[next_to_use];
		desc->addr = xdp_slot_addr_rel(buf,
			vec->packets[total_fill]->slot_index);
		desc->len = vec->packets[total_fill]->slot_size;

		desc_idx++;
		total_fill++;
	}

	for(i = total_fill; i < vec->num; i++){
		port->count_tx_xmit_failed++;
		xdp_slot_release(buf, vec->packets[i]->slot_index);
	}

	if(total_fill){
		wmb();
		*tx_ring->producer = desc_idx;
	}

	vec->num = 0;
	xdp_print("Tx-fill: port_idx = %d, total_fill = %d, prod = %d, cons = %d\n",
		port_idx, total_fill, *tx_ring->producer, *tx_ring->consumer);
	return;
}

void xdp_rx_pull(struct xdp_plane *plane, unsigned int port_idx,
	struct xdp_buf *buf)
{
	struct xdp_port *port;
	struct xdp_vec *vec;
	struct xdp_ring *rx_ring;
	uint32_t next_to_clean, desc_idx;
	uint32_t prod;
	struct xdp_desc *desc;
	unsigned int total_pull;
	unsigned int slot_index;

	port = &plane->ports[port_idx];
	vec = &port->vec_rx;
	rx_ring = &port->rx_ring;

	desc_idx = *rx_ring->consumer;
	total_pull = 0;

	prod = *rx_ring->producer;
	rmb();

	while(total_pull < XDPD_RX_BUDGET){
		if(desc_idx == prod){
			break;
		}

		next_to_clean = desc_idx & (XDPD_RX_DESC - 1);
		desc = &((struct xdp_desc *)rx_ring->descs)[next_to_clean];
		slot_index = xdp_slot_index(buf, desc->addr);

		vec->packets[total_pull].slot_buf =
			xdp_slot_addr_virt(buf, slot_index);
		vec->packets[total_pull].slot_size = desc->len;
		vec->packets[total_pull].slot_index = slot_index;

		desc_idx++;
		total_pull++;
	}

	if(total_pull){
		*rx_ring->consumer = desc_idx;
	}

	port->count_rx_clean_total += total_pull;
	vec->num = total_pull;
	xdp_print("Rx-pull: port_idx = %d, total_pull = %d, prod = %d, cons = %d\n",
		port_idx, total_pull, *rx_ring->producer, *rx_ring->consumer);
	return;
}

void xdp_tx_pull(struct xdp_plane *plane, unsigned int port_idx,
	struct xdp_buf *buf)
{
	struct xdp_port *port;
	struct xdp_ring *cq_ring;
	uint32_t next_to_clean, desc_idx;
	uint32_t prod;
	uint64_t *desc;
	unsigned int total_pull;
	unsigned int slot_index;

	port = &plane->ports[port_idx];
	cq_ring = &port->cq_ring;

	desc_idx = *cq_ring->consumer;
	total_pull = 0;

	prod = *cq_ring->producer;
	rmb();

	while(total_pull < XDPD_TX_BUDGET){
		if(desc_idx == prod){
			break;
		}

		next_to_clean = desc_idx & (XDPD_TX_DESC - 1);
		desc = &((uint64_t *)cq_ring->descs)[next_to_clean];
		slot_index = xdp_slot_index(buf, *desc);

		xdp_slot_release(buf, slot_index);

		desc_idx++;
		total_pull++;
	}

	if(total_pull){
		*cq_ring->consumer = desc_idx;
	}

	port->count_tx_clean_total += total_pull;
	xdp_print("Tx-pull: port_idx = %d, total_pull = %d, prod = %d, cons = %d\n",
		port_idx, total_pull, *cq_ring->producer, *cq_ring->consumer);
	return;
}

void xdp_tx_kick(struct xdp_plane *plane, unsigned int port_idx)
{
	struct xdp_port *port;
	int err;

	port = &plane->ports[port_idx];

	err = sendto(port->xfd, NULL, 0, MSG_DONTWAIT, NULL, 0);
	if (err < 0){
		xdp_print("Tx: packet sending error = %d\n", errno);

/*
printf("This is port %d Tx sending error = %d\n", port_idx, errno);
printf("statistics dump:\n");
int i;
for(i = 0; i < plane->num_ports; i++){
struct xdp_port *dump_port;
dump_port = &plane->ports[i];
printf("port[%d] rx prod = %d, cons = %d\n", i,
	*(dump_port->rx_ring.producer), *(dump_port->rx_ring.consumer));
printf("port[%d] tx prod = %d, cons = %d\n", i,
	*(dump_port->tx_ring.producer), *(dump_port->tx_ring.consumer));
printf("port[%d] fq prod = %d, cons = %d\n", i,
	*(dump_port->fq_ring.producer), *(dump_port->fq_ring.consumer));
printf("port[%d] cq prod = %d, cons = %d\n", i,
	*(dump_port->cq_ring.producer), *(dump_port->cq_ring.consumer));
}
*/

	}

}

int xdp_slot_assign(struct xdp_buf *buf,
	struct xdp_plane *plane, unsigned int port_idx)
{
	struct xdp_port *port;
	int slot_index, i;

	port = &plane->ports[port_idx];

	for(i = 0; i < buf->slot_count_devbuf; i++){
		slot_index = port->rx_slot_offset + port->rx_slot_next;

		port->rx_slot_next++;
		port->rx_slot_next &= buf->slot_mask_devbuf;

		if(!(buf->slots[slot_index] & XDP_SLOT_INFLIGHT)){
			goto out;
		}
	}

	return -1;

out:
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
