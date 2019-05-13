#ifndef _UFPD_THREAD_H
#define _UFPD_THREAD_H

#include <pthread.h>

struct xdpd_thread {
	struct xdp_plane	*plane;
	struct xdp_buf		*buf;
	unsigned int		id;
	pthread_t		tid;
	pthread_t		ptid;
};

void *thread_process_interrupt(void *data);

#endif /* _UFPD_THREAD_H */
