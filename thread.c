#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <net/ethernet.h>
#include <signal.h>
#include <sys/signalfd.h>
#include <pthread.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <stddef.h>
#include <syslog.h>

#include "main.h"
#include "thread.h"
#include "driver.h"
#include "forward.h"
#include "epoll.h"
#include "list.h"

static int thread_fd_prepare(struct list_head *ep_desc_head,
	struct xdpd_thread *thread);
static void thread_fd_destroy(struct list_head *ep_desc_head,
	int fd_ep);
static int thread_wait(struct xdpd_thread *thread, int fd_ep);
static inline int thread_process_irq(struct xdpd_thread *thread,
	struct epoll_desc *ep_desc);
static inline int thread_process_signal(struct xdpd_thread *thread,
	struct epoll_desc *ep_desc);
static void thread_print_result(struct xdpd_thread *thread);

void *thread_process_interrupt(void *data)
{
	struct xdpd_thread	*thread = data;
	struct list_head	ep_desc_head;
	int			fd_ep, i, ret;

	xdpd_log(LOG_INFO, "thread %d started", thread->id);
	list_init(&ep_desc_head);

	/* Prepare each fd in epoll */
	fd_ep = thread_fd_prepare(&ep_desc_head, thread);
	if(fd_ep < 0){
		xdpd_log(LOG_ERR, "failed to epoll prepare");
		goto err_ixgbe_epoll_prepare;
	}

	/* Prepare initial RX buffer */
	for(i = 0; i < thread->plane->num_ports; i++){
		xdp_rx_fill(thread->plane, i, thread->buf);
	}

	ret = thread_wait(thread, fd_ep);
	if(ret < 0)
		goto err_wait;

err_wait:
	thread_fd_destroy(&ep_desc_head, fd_ep);
err_ixgbe_epoll_prepare:
	thread_print_result(thread);
	pthread_kill(thread->ptid, SIGINT);
	return NULL;
}

static int thread_fd_prepare(struct list_head *ep_desc_head,
	struct xdpd_thread *thread)
{
	struct epoll_desc 	*ep_desc;
	sigset_t		sigset;
	int			fd_ep, i, ret;

	/* epoll fd preparing */
	fd_ep = epoll_create(EPOLL_MAXEVENTS);
	if(fd_ep < 0){
		perror("failed to make epoll fd");
		goto err_epoll_open;
	}

	for(i = 0; i < thread->plane->num_ports; i++){
		/* Register RX interrupt fd */
		ep_desc = epoll_desc_alloc_irq(thread->plane, i);
		if(!ep_desc)
			goto err_assign_port;

		list_add_last(ep_desc_head, &ep_desc->list);

		ret = epoll_add(fd_ep, ep_desc, ep_desc->fd);
		if(ret < 0){
			perror("failed to add fd in epoll");
			goto err_assign_port;
		}
	}

	/* signalfd preparing */
	sigemptyset(&sigset);
	sigaddset(&sigset, SIGUSR1);
	ep_desc = epoll_desc_alloc_signalfd(&sigset);
	if(!ep_desc)
		goto err_epoll_desc_signalfd;

	list_add_last(ep_desc_head, &ep_desc->list);

	ret = epoll_add(fd_ep, ep_desc, ep_desc->fd);
	if(ret < 0){
		perror("failed to add fd in epoll");
		goto err_epoll_add_signalfd;
	}

	return fd_ep;

err_epoll_add_signalfd:
err_epoll_desc_signalfd:
err_assign_port:
	thread_fd_destroy(ep_desc_head, fd_ep);
err_epoll_open:
	return -1;
}

static void thread_fd_destroy(struct list_head *ep_desc_head,
	int fd_ep)
{
	struct epoll_desc *ep_desc, *temp;

	list_for_each_safe(ep_desc_head, ep_desc, list, temp){
		list_del(&ep_desc->list);
		epoll_del(fd_ep, ep_desc->fd);

		switch(ep_desc->type){
		case EPOLL_IRQ:
			epoll_desc_release_irq(ep_desc);
			break;
		case EPOLL_SIGNAL:
			epoll_desc_release_signalfd(ep_desc);
			break;
		default:
			break;
		}
	}

	close(fd_ep);
	return;
}

static int thread_wait(struct xdpd_thread *thread, int fd_ep)
{
        struct epoll_desc *ep_desc;
        struct epoll_event events[EPOLL_MAXEVENTS];
        int i, err, num_fd;

	while(1){
		num_fd = epoll_wait(fd_ep, events, EPOLL_MAXEVENTS, -1);
		if(num_fd < 0)
			goto err_wait;

		for(i = 0; i < num_fd; i++){
			ep_desc = (struct epoll_desc *)events[i].data.ptr;

			switch(ep_desc->type){
			case EPOLL_IRQ:
				err = thread_process_irq(thread, ep_desc);
				if(err < 0)
					goto err_process;
				break;
			case EPOLL_SIGNAL:
				err = thread_process_signal(thread, ep_desc);
				if(err < 0)
					goto err_process;
				goto out;
				break;
			default:
				break;
			}
		}
	}

out:
	return 0;

err_process:
err_wait:
	return -1;
}

static inline int thread_process_irq(struct xdpd_thread *thread,
	struct epoll_desc *ep_desc)
{
	unsigned int port_index;
	int i;

	port_index = ep_desc->port_index;

	/* Rx/Tx queues */
	xdp_rx_pull(thread->plane, port_index, thread->buf);

	forward_process(thread, port_index);

	for(i = 0; i < thread->plane->num_ports; i++){
		xdp_tx_fill(thread->plane, i, thread->buf);
	}

	/* Umem queues */
	/* XXX: To be revised
	 * FQ-empty/CQ-full notification feature will be introduced
	 * in the future.
	 * Ref: https://www.spinics.net/lists/netdev/msg556499.html
	 */
	for(i = 0; i < thread->plane->num_ports; i++){
		xdp_tx_pull(thread->plane, i, thread->buf);
		xdp_rx_fill(thread->plane, i, thread->buf);
	}

	return 0;
}

static inline int thread_process_signal(struct xdpd_thread *thread,
	struct epoll_desc *ep_desc)
{
	int ret;
	char read_buf[READ_SIZE];

	ret = read(ep_desc->fd, read_buf, sizeof(read_buf));
	if(ret < 0)
		goto err_read;
	return 0;

err_read:
	return -1;
}

static void thread_print_result(struct xdpd_thread *thread)
{
	int i;

	for(i = 0; i < thread->plane->num_ports; i++){
		xdpd_log(LOG_INFO, "thread %d port %d statictis:", thread->id, i);
		xdpd_log(LOG_INFO, "  Rx allocation failed = %lu",
			thread->plane->ports[i].count_rx_alloc_failed);
		xdpd_log(LOG_INFO, "  Rx packetes received = %lu",
			thread->plane->ports[i].count_rx_clean_total);
		xdpd_log(LOG_INFO, "  Tx xmit failed = %lu",
			thread->plane->ports[i].count_tx_xmit_failed);
		xdpd_log(LOG_INFO, "  Tx packetes transmitted = %lu",
			thread->plane->ports[i].count_tx_clean_total);
	}
	return;
}
