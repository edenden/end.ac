#ifndef _XDPD_EPOLL_H
#define _XDPD_EPOLL_H

#include <signal.h>
#include "list.h"

#define EPOLL_MAXEVENTS 16

enum {
	EPOLL_IRQ = 0,
	EPOLL_SIGNAL
};

struct epoll_desc {
	int			fd;
	int			type;
	unsigned int		port_index;
	struct list_node	list;
};

int epoll_add(int fd_ep, void *ptr, int fd);
int epoll_del(int fd_ep, int fd);
struct epoll_desc *epoll_desc_alloc_irq(struct xdp_plane *plane,
	unsigned int port_index);
void epoll_desc_release_irq(struct epoll_desc *ep_desc);
struct epoll_desc *epoll_desc_alloc_signalfd(sigset_t *sigset);
void epoll_desc_release_signalfd(struct epoll_desc *ep_desc);

#endif /* _XDPD_EPOLL_H */
