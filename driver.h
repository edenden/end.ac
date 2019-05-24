#ifndef _DRIVER_H
#define _DRIVER_H

#include "main.h"

#define barrier()	asm volatile("" ::: "memory")

#if defined(__x86_64__) || defined(__i386__) || defined(__amd64__)
#define mb()		asm volatile("mfence" ::: "memory")
#define rmb()		asm volatile("lfence" ::: "memory")
#define wmb()		asm volatile("sfence" ::: "memory")
#define dma_rmb()	barrier()
#define dma_wmb()	barrier()
#else
#define mb()		barrier()
#define rmb()		mb()
#define wmb()		mb()
#define dma_rmb()	rmb()
#define dma_wmb()	wmb()
#endif

void xdp_rx_fill(struct xdp_plane *plane, unsigned int port_idx,
	struct xdp_buf *buf);
void xdp_tx_fill(struct xdp_plane *plane, unsigned int port_idx,
	struct xdp_buf *buf);
void xdp_rx_pull(struct xdp_plane *plane, unsigned int port_idx,
	struct xdp_buf *buf);
void xdp_tx_pull(struct xdp_plane *plane, unsigned int port_idx,
	struct xdp_buf *buf);
int xdp_slot_assign(struct xdp_buf *buf,
	struct xdp_plane *plane, unsigned int port_idx);
void xdp_slot_release(struct xdp_buf *buf,
	unsigned int slot_index);

#endif /* _DRIVER_H */
