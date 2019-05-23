#define _GNU_SOURCE
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <endian.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/eventfd.h>
#include <signal.h>
#include <pthread.h>

#include <linux/if_link.h>
#include <linux/if_xdp.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "main.h"
#include "lib.h"

static int xdp_alloc_port(struct xdp_dev **devs, struct xdp_plane *plane,
	struct xdp_buf *buf, unsigned int thread_id, unsigned int dev_idx,
	unsigned int xdp_bind_flags);
static void xdp_release_port(struct xdp_port *port);
static int xdp_alloc_ring(int fd, struct xdp_ring *ring,
	unsigned long size_desc, int num_desc, off_t mmap_offset, int sock_flag,
	struct xdp_ring_offset *offset);
static void xdp_release_ring(struct xdp_ring *ring);

#ifdef SRV6_END_AC
static int xdp_configure_srv6(struct xdp_port *port);
#endif

struct xdp_plane *xdp_plane_alloc(struct xdp_dev **devs, int num_devs,
	struct xdp_buf *buf, unsigned int thread_id, unsigned int core_id,
	unsigned int xdp_bind_flags)
{
	struct xdp_plane *plane;
	int port_done, i, err;

	plane = malloc(sizeof(struct xdp_plane));
	if(!plane)
		goto err_alloc_plane;

	plane->num_ports = num_devs;
	plane->ports = malloc(sizeof(struct xdp_port) * plane->num_ports);
	if(!plane->ports)
		goto err_alloc_ports;

	for(i = 0, port_done = 0; i < num_devs; i++, port_done++){
		err = xdp_alloc_port(devs, plane, buf, thread_id, i,
			xdp_bind_flags);
		if(err < 0)
			goto err_alloc_port;

#ifdef SRV6_END_AC
		err = xdp_configure_srv6(&plane->ports[i]);
		if(err < 0){
			printf("Invalid SID port assign\n");
			goto err_configure_srv6;
		}
#endif

		continue;

#ifdef SRV6_END_AC
err_configure_srv6:
#endif
		xdp_release_port(&plane->ports[i]);
err_alloc_port:
		goto err_port;
	}

	return plane;

err_port:
	for(i = 0; i < port_done; i++){
		xdp_release_port(&plane->ports[i]);
	}
	free(plane->ports);
err_alloc_ports:
	free(plane);
err_alloc_plane:
	return NULL;
}

void xdp_plane_release(struct xdp_plane *plane)
{
	int i;

	for(i = 0; i < plane->num_ports; i++){
		xdp_release_port(&plane->ports[i]);
	}
	free(plane->ports);
	free(plane);

	return;
}

#ifdef SRV6_END_AC
static int xdp_configure_srv6(struct xdp_port *port)
{
	struct sr_cache_table *cache_table;
	int i, j;

	port->mode = 0;

	for(i = 0; i < 2; i++){
		cache_table = &sr_cache_table[i];

		for(j = 0; j < 4; j++){
			if(port->dev_idx != cache_table->ifidx[j])
				continue;

			if(j == 0){ /* This interface is v6in */
				if(port->mode)
					goto err_configure_srv6;

				port->mode = SRV6_END_AC_MODE_OUTER;
				port->bound_port_idx = cache_table->ifidx[1];
				port->bound_table_idx = i;
				memcpy(port->bound_mac_addr,
					cache_table->mac_addr[0], ETH_ALEN);
			}else if(j == 1){ /* This interface is v4out */
			}else if(j == 2){ /* This interface is v4in */
				if(port->mode)
					goto err_configure_srv6;

				port->mode = SRV6_END_AC_MODE_INNER;
				port->bound_port_idx = cache_table->ifidx[3];
				port->bound_table_idx = i;
				memcpy(port->bound_mac_addr,
					cache_table->mac_addr[1], ETH_ALEN);
			}else if(j == 3){ /* This interface is v6out */
			}
		}
	}
	return 0;

err_configure_srv6:
	return -1;
}
#endif

static int xdp_alloc_port(struct xdp_dev **devs, struct xdp_plane *plane,
	struct xdp_buf *buf, unsigned int thread_id, unsigned int dev_idx,
	unsigned int xdp_bind_flags)
{
	struct xdp_dev *dev;
	struct xdp_port *port;
	struct xdp_umem_reg mr;
	struct xdp_mmap_offsets off;
	socklen_t optlen;
	struct sockaddr_xdp sxdp;
	int err;

	dev = devs[dev_idx];
	port = &plane->ports[dev_idx];

	port->dev_idx			= dev_idx;
	port->num_qps			= dev->num_qps;
	port->mtu_frame			= dev->mtu_frame;
	memcpy(port->mac_addr, dev->mac_addr, ETH_ALEN);

	port->rx_slot_next		= 0;
	port->rx_slot_offset		=
		port->dev_idx * buf->slot_count_devbuf;

	port->count_rx_alloc_failed	= 0;
	port->count_rx_clean_total	= 0;
	port->count_tx_xmit_failed	= 0;
	port->count_tx_clean_total	= 0;
	port->vec_rx.num = 0;
	port->vec_tx.num = 0;

	port->xfd = socket(AF_XDP, SOCK_RAW, 0);
	if(port->xfd < 0)
		goto err_open_socket;

	mr.addr		= (uint64_t)buf->addr;
	mr.len		= ALIGN(buf->slot_size * buf->slot_count,
				getpagesize());
	mr.chunk_size	= buf->slot_size;
	mr.headroom	= 0;

	err = setsockopt(port->xfd, SOL_XDP, XDP_UMEM_REG, &mr, sizeof(mr));
	if(err < 0)
		goto err_umem_reg;

	optlen = sizeof(off);
	err = getsockopt(port->xfd, SOL_XDP,
		XDP_MMAP_OFFSETS, &off, &optlen);
	if(err < 0)
		goto err_get_offset;

	err = xdp_alloc_ring(port->xfd, &port->fq_ring,
		XDPD_RX_DESC * sizeof(uint64_t), XDPD_RX_DESC,
		XDP_UMEM_PGOFF_FILL_RING,
		XDP_UMEM_FILL_RING,
		&off.fr);
	if(err < 0)
		goto err_fq_alloc;

	err = xdp_alloc_ring(port->xfd, &port->cq_ring,
		XDPD_TX_DESC * sizeof(uint64_t), XDPD_TX_DESC,
		XDP_UMEM_PGOFF_COMPLETION_RING,
		XDP_UMEM_COMPLETION_RING,
		&off.cr);
	if(err < 0)
		goto err_cq_alloc;

	err = xdp_alloc_ring(port->xfd, &port->rx_ring,
		XDPD_RX_DESC * sizeof(struct xdp_desc), XDPD_RX_DESC,
		XDP_PGOFF_RX_RING,
		XDP_RX_RING,
		&off.rx);
	if(err < 0)
		goto err_rx_alloc;

	err = xdp_alloc_ring(port->xfd, &port->tx_ring,
		XDPD_TX_DESC * sizeof(struct xdp_desc), XDPD_TX_DESC,
		XDP_PGOFF_TX_RING,
		XDP_TX_RING,
		&off.tx);
	if(err < 0)
		goto err_tx_alloc;

	sxdp.sxdp_family = PF_XDP;
	sxdp.sxdp_ifindex = dev->ifindex;
	sxdp.sxdp_queue_id = thread_id;
	sxdp.sxdp_flags = xdp_bind_flags;

	err = bind(port->xfd, (struct sockaddr *)&sxdp, sizeof(sxdp));
	if(err < 0)
		goto err_bind;

	err = bpf_map_update_elem(dev->xsks_map,
		&thread_id, &port->xfd, 0);
	if(err)
		goto err_map_update;

	xdp_print("bpf_map_update_elem: dev_id = %d, thread_id(queue id) = %d, xfd(xsk id) = %d\n",
		port->dev_idx, thread_id, port->xfd);

	return 0;

err_map_update:
err_bind:
	xdp_release_ring(&port->tx_ring);
err_tx_alloc:
	xdp_release_ring(&port->rx_ring);
err_rx_alloc:
	xdp_release_ring(&port->cq_ring);
err_cq_alloc:
	xdp_release_ring(&port->fq_ring);
err_fq_alloc:
err_get_offset:
err_umem_reg:
	close(port->xfd);
err_open_socket:
	return -1;
}

static void xdp_release_port(struct xdp_port *port)
{
	xdp_release_ring(&port->tx_ring);
	xdp_release_ring(&port->rx_ring);
	xdp_release_ring(&port->cq_ring);
	xdp_release_ring(&port->fq_ring);
	close(port->xfd);

	return;
}

static int xdp_alloc_ring(int fd, struct xdp_ring *ring,
	unsigned long size_desc, int num_desc, off_t mmap_offset, int sock_flag,
	struct xdp_ring_offset *offset)
{
	void *addr;
	unsigned int size;
	int err;

	err = setsockopt(fd, SOL_XDP, sock_flag, &num_desc, sizeof(int));
	if(err < 0)
		goto err_setsockopt;

	size = offset->desc + size_desc;
	addr = mmap(0, size,
		PROT_READ | PROT_WRITE,
		MAP_SHARED | MAP_POPULATE, fd, mmap_offset);
	if(addr == MAP_FAILED)
		goto err_alloc;

	ring->addr = addr;
	ring->producer = ring->addr + offset->producer;
	ring->consumer = ring->addr + offset->consumer;
	ring->descs = ring->addr + offset->desc;
	ring->size = size;
	return 0;

err_alloc:
err_setsockopt:
	return -1;
}

static void xdp_release_ring(struct xdp_ring *ring)
{
	munmap(ring->addr, ring->size);
	return;
}

struct xdp_buf *xdp_alloc_buf(unsigned int slot_size, unsigned int num_devs,
	unsigned int num_devbuf)
{
	struct xdp_buf *buf;
	size_t size_buf_align;
	int i, err;

	buf = malloc(sizeof(struct xdp_buf));
	if(!buf)
		goto err_alloc_buf;

	/*
	 * XXX: Should we add buffer padding for memory interleaving?
	 * DPDK does so in rte_mempool.c/optimize_object_size().
	 */
	buf->slot_size = slot_size;
	buf->slot_count_devbuf = 1;
	while(buf->slot_count_devbuf < num_devbuf){
		buf->slot_count_devbuf <<= 1;
	}
	buf->slot_mask_devbuf = buf->slot_count_devbuf - 1;
	buf->slot_count = num_devs * buf->slot_count_devbuf;

	size_buf_align = ALIGN(buf->slot_size * buf->slot_count,
		getpagesize());

	err = posix_memalign(&buf->addr, getpagesize(), size_buf_align);
	if(err < 0)
		goto err_mem_alloc;

	buf->slots = malloc(sizeof(int) * buf->slot_count);
	if(!buf->slots)
		goto err_alloc_slots;

	for(i = 0; i < buf->slot_count; i++){
		buf->slots[i] = 0;
	}

	return buf;

err_alloc_slots:
	free(buf->addr);
err_mem_alloc:
	free(buf);
err_alloc_buf:
	return NULL;
}

void xdp_release_buf(struct xdp_buf *buf)
{
	free(buf->slots);
	free(buf->addr);
	free(buf);
	return;
}

struct xdp_dev *xdp_open(const char *name,
	unsigned int num_qps, unsigned int buf_size, unsigned int mtu_frame,
	unsigned int xdp_flags)
{
	struct xdp_dev *dev;
	struct bpf_object *obj;
	struct bpf_map *map;
	struct bpf_prog_load_attr prog_load_attr = {
		.prog_type	= BPF_PROG_TYPE_XDP,
		.file		= "bpf.o"
	};
	struct ifreq ifreq;
	int fd, prog_fd, err;

	dev = malloc(sizeof(struct xdp_dev));
	if (!dev)
		goto err_alloc_dev;

	strncpy(dev->name, name, sizeof(dev->name));
	dev->buf_size = buf_size;
	dev->mtu_frame = mtu_frame;
	dev->num_qps = num_qps;

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if(fd < 0)
		goto err_socket;

	strncpy(ifreq.ifr_name, dev->name, sizeof(ifreq.ifr_name));
	err = ioctl(fd, SIOCGIFINDEX, &ifreq);
	if(err < 0)
		goto err_get_ifidx;

	dev->ifindex = ifreq.ifr_ifindex;

	err = ioctl(fd, SIOCGIFHWADDR, &ifreq);
	if(err < 0)
		goto err_get_mac;
	memcpy(dev->mac_addr, ifreq.ifr_hwaddr.sa_data, ETH_ALEN);

	err = bpf_prog_load_xattr(&prog_load_attr, &obj, &prog_fd);
	if(err < 0)
		goto err_bpf_prog_load;

	map = bpf_object__find_map_by_name(obj, "xsks_map");
	dev->xsks_map = bpf_map__fd(map);
	if (dev->xsks_map < 0)
		goto err_bpf_map_fd;

	err = bpf_set_link_xdp_fd(dev->ifindex, prog_fd, xdp_flags);
	if(err < 0)
		goto err_bpf_set_link;

	close(fd);
	return dev;

err_bpf_set_link:
err_bpf_map_fd:
err_bpf_prog_load:
err_get_mac:
err_get_ifidx:
	close(fd);
err_socket:
	free(dev);
err_alloc_dev:
	return NULL;
}

void xdp_close(struct xdp_dev *dev, unsigned int xdp_flags)
{
	bpf_set_link_xdp_fd(dev->ifindex, -1, xdp_flags);
	free(dev);
	return;
}
