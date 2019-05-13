#ifndef _LIB_MAIN_H
#define _LIB_MAIN_H

#include "main.h"

struct xdp_plane *xdp_plane_alloc(struct xdp_dev **devs, int num_devs,
	struct xdp_buf *buf, unsigned int thread_id, unsigned int core_id);
void xdp_plane_release(struct xdp_plane *plane);
struct xdp_buf *xdp_alloc_buf(unsigned int slot_size, unsigned int buf_count);
void xdp_release_buf(struct xdp_buf *buf);
int xdp_up(struct xdp_dev *dev,
	unsigned int num_qps, unsigned int buf_size, unsigned int mtu_frame);
void xdp_down(struct xdp_dev *dev);
struct xdp_dev *xdp_open(const char *name);
void xdp_close(struct xdp_dev *dev);

#endif /* _LIB_MAIN_H */
