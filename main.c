#define _GNU_SOURCE
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <endian.h>
#include <signal.h>
#include <sys/signalfd.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <linux/mempolicy.h>
#include <stdarg.h>
#include <syslog.h>

#include <linux/if_link.h>
#include <linux/if_xdp.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "main.h"
#include "lib.h"
#include "thread.h"

static void usage();
static int xdpd_device_init(struct xdpd *xdpd, int dev_idx);
static void xdpd_device_destroy(struct xdpd *xdpd, int dev_idx);
static int xdpd_thread_create(struct xdpd *xdpd,
	struct xdpd_thread *thread, unsigned int thread_id,
	unsigned int core_id);
static void xdpd_thread_kill(struct xdpd_thread *thread);
static int xdpd_set_signal(sigset_t *sigset);
static int xdpd_set_mempolicy(unsigned int node);
static int xdpd_parse_args(struct xdpd *xdpd, int argc, char **argv);
static int xdpd_parse_range(const char *str, char *result, int max_len);
static int xdpd_parse_list(const char *str, char **result, int max_len,
	int max_count);
static int xdpd_convert_list(const char **str, int str_count,
	const char *format, void *result, int elem, int max_count);

char *optarg;

#ifdef SRV6_END_AC
#include <arpa/inet.h>
static int xdpd_parse_srv6(char **srv6_opts);
struct sr_cache_table	sr_cache_table[2] = {};
int table_index = 0;
#endif

static void usage()
{
	printf("\n");
	printf("Usage:\n");
	printf("  -c [cpulist] : CPU cores to use\n");
	printf("  -p [ifnamelist] : Interfaces to use\n");
	printf("  -n [n] : NUMA node (default=0)\n");
	printf("  -m [n] : MTU length (default=1522)\n");
	printf("  -b [n] : Number of packet buffer per port(default=8192)\n");
	printf("  -d : Force XDP Driver mode\n");
	printf("  -z : Force XDP Zero copy mode\n");
	printf("  -h : Show this help\n");
#ifdef SRV6_END_AC
	printf("  -s [v6in-ifidx],[v4out-ifidx],[v4in-ifidx],[v6out-ifidx],[v4out-dmac],[v6out-dmac],[sid],[sidlen],[argoffset]\n");
	printf("  -s 0,1,2,3,aa:aa:aa:aa:aa:aa,bb:bb:bb:bb:bb:bb,fd00::,64,80\n");
#endif
	printf("\n");
	return;
}

int main(int argc, char **argv)
{
	struct xdpd		xdpd;
	struct xdpd_thread	*threads;
	int			err, ret, i, signal;
	int			ifnames_done = 0,
				threads_done = 0,
				devices_done = 0;
	sigset_t		sigset;
#ifdef SRV6_END_AC
	int			j;
#endif

	/* set default values */
	xdpd.numa_node		= 0;
	xdpd.num_threads	= 0;
	xdpd.num_devices	= 0;
	/* 1500 + ETH_HLEN(14) + ETH_FCS_LEN(4) = 1518 */
	xdpd.mtu_frame		= 1518;
	/* size of packet buffer */
	xdpd.buf_size		= 2048;
	/* number of per port packet buffer */
	xdpd.buf_count		= 8192;

	xdpd.xdp_flags		= XDP_FLAGS_SKB_MODE;
	xdpd.xdp_bind_flags	= XDP_COPY;

	ret = -1;

	for(i = 0; i < XDPD_MAX_IFS; i++, ifnames_done++){
		xdpd.ifnames[i] = malloc(XDPD_MAX_ARGLEN);
		if(!xdpd.ifnames[i])
			goto err_alloc_ifnames;
	}

	err = xdpd_parse_args(&xdpd, argc, argv);
	if(err < 0)
		goto err_parse_args;

	openlog(PROCESS_NAME, LOG_CONS | LOG_PID, SYSLOG_FACILITY);

	err = xdpd_set_mempolicy(xdpd.numa_node);
	if(err < 0)
		goto err_set_mempolicy;

	xdpd.devs = malloc(sizeof(struct xdp_dev *) * xdpd.num_devices);
	if(!xdpd.devs)
		goto err_devs;

	threads = malloc(sizeof(struct xdpd_thread) * xdpd.num_threads);
	if(!threads)
		goto err_alloc_threads;

	for(i = 0; i < xdpd.num_devices; i++, devices_done++){
		err = xdpd_device_init(&xdpd, i);
		if(err < 0)
			goto err_init_device;
	}

	err = xdpd_set_signal(&sigset);
	if(err != 0)
		goto err_set_signal;

#ifdef SRV6_END_AC
	for(i = 0; i < 2; i++){
		for(j = 0; j < 256; j++){
			pthread_rwlock_init(
				&sr_cache_table[i].cache4[j].lock, NULL);
			sr_cache_table[i].cache4[j].size = 0;
			pthread_rwlock_init(
				&sr_cache_table[i].cache6[j].lock, NULL);
			sr_cache_table[i].cache6[j].size = 0;
		}
	}
#endif

	for(i = 0; i < xdpd.num_threads; i++, threads_done++){
		err = xdpd_thread_create(&xdpd, &threads[i], i, xdpd.cores[i]);
		if(err < 0)
			goto err_thread_create;
	}

	while(1){
		if(sigwait(&sigset, &signal) == 0){
			break;
		}
	}
	ret = 0;

err_thread_create:
	for(i = 0; i < threads_done; i++){
		xdpd_thread_kill(&threads[i]);
	}
err_set_signal:
err_init_device:
	for(i = 0; i < devices_done; i++){
		xdpd_device_destroy(&xdpd, i);
	}
	free(threads);
err_alloc_threads:
	free(xdpd.devs);
err_devs:
err_set_mempolicy:
	closelog();
err_parse_args:
err_alloc_ifnames:
	for(i = 0; i < ifnames_done; i++){
		free(xdpd.ifnames[i]);
	}
	return ret;
}

static int xdpd_device_init(struct xdpd *xdpd, int dev_idx)
{
	xdpd->devs[dev_idx] = xdp_open(xdpd->ifnames[dev_idx],
		xdpd->num_threads, xdpd->buf_size, xdpd->mtu_frame,
		xdpd->xdp_flags);
	if(!xdpd->devs[dev_idx]){
		xdpd_log(LOG_ERR, "failed to xdp_open, idx = %d", dev_idx);
		goto err_open;
	}

	return 0;

err_open:
	return -1;
}

static void xdpd_device_destroy(struct xdpd *xdpd, int dev_idx)
{
	xdp_close(xdpd->devs[dev_idx], xdpd->xdp_flags);
}

static int xdpd_thread_create(struct xdpd *xdpd,
	struct xdpd_thread *thread, unsigned int thread_id,
	unsigned int core_id)
{
	cpu_set_t cpuset;
	int err;

	thread->id		= thread_id;
	thread->ptid		= pthread_self();

	thread->buf = xdp_alloc_buf(xdpd->buf_size,
		xdpd->num_devices, xdpd->buf_count);
	if(!thread->buf){
		xdpd_log(LOG_ERR,
			"failed to xdp_alloc_buf, idx = %d", thread->id);
		goto err_buf_alloc;
	}

	thread->plane = xdp_plane_alloc(xdpd->devs, xdpd->num_devices,
		thread->buf, thread->id, xdpd->cores[thread->id],
		xdpd->xdp_bind_flags);
	if(!thread->plane){
		xdpd_log(LOG_ERR,
			"failed to xdp_plane_alloc, idx = %d", thread->id);
		goto err_plane_alloc;
	}

	err = pthread_create(&thread->tid,
		NULL, thread_process_interrupt, thread);
	if(err < 0){
		xdpd_log(LOG_ERR, "failed to create thread");
		goto err_pthread_create;
	}

	CPU_ZERO(&cpuset);
	CPU_SET(core_id, &cpuset);
	err = pthread_setaffinity_np(thread->tid,
		sizeof(cpu_set_t), &cpuset);
	if(err < 0){
		xdpd_log(LOG_ERR, "failed to set affinity");
		goto err_set_affinity;
	}

	return 0;

err_set_affinity:
	xdpd_thread_kill(thread);
err_pthread_create:
	xdp_plane_release(thread->plane);
err_plane_alloc:
	xdp_release_buf(thread->buf);
err_buf_alloc:
	return -1;
}

void xdpd_log(int level, char *fmt, ...){
	va_list args;
	va_start(args, fmt);

	vsyslog(level, fmt, args);

	va_end(args);
}

static void xdpd_thread_kill(struct xdpd_thread *thread)
{
	int err;

	err = pthread_kill(thread->tid, SIGUSR1);
	if(err != 0)
		xdpd_log(LOG_ERR, "failed to kill thread");

	err = pthread_join(thread->tid, NULL);
	if(err != 0)
		xdpd_log(LOG_ERR, "failed to join thread");

	xdp_plane_release(thread->plane);
	xdp_release_buf(thread->buf);
	return;
}

static int xdpd_set_signal(sigset_t *sigset)
{
	int err;

	sigemptyset(sigset);
	err = sigaddset(sigset, SIGUSR1);
	if(err != 0)
		goto err_sigaddset;

	err = sigaddset(sigset, SIGHUP);
	if(err != 0)
		goto err_sigaddset;

	err = sigaddset(sigset, SIGINT);
	if(err != 0)
		goto err_sigaddset;

	err = sigaddset(sigset, SIGTERM);
	if(err != 0)
		goto err_sigaddset;

	err = pthread_sigmask(SIG_BLOCK, sigset, NULL);
	if(err != 0)
		goto err_sigmask;

	return 0;

err_sigmask:
err_sigaddset:
	return -1;
}

static int xdpd_set_mempolicy(unsigned int node)
{
	int err;
	unsigned long node_mask;

	node_mask = 1UL << node;

	err = syscall(SYS_set_mempolicy, MPOL_BIND, &node_mask,
		sizeof(unsigned long) * 8);
	if(err < 0){
		return -1;
	}

	return 0;
}

static int xdpd_parse_args(struct xdpd *xdpd, int argc, char **argv)
{
	int err, opt, i;
	char strbuf[XDPD_MAX_ARGLEN];
	char *argbuf[XDPD_MAX_ARGS];
	unsigned int argbuf_done = 0;
#ifdef SRV6_END_AC
	char *srv6_opts[10];
	unsigned int srv6_opts_done = 0;
#endif

	for(i = 0; i < XDPD_MAX_ARGS; i++, argbuf_done++){
		argbuf[i] = malloc(XDPD_MAX_ARGLEN);
		if(!argbuf[i])
			goto err_alloc_buf;
	}

#ifdef SRV6_END_AC
	for(i = 0; i < 10; i++, srv6_opts_done++){
		srv6_opts[i] = malloc(XDPD_MAX_ARGLEN);
		if(!srv6_opts[i])
			goto err_alloc_srv6_buf;
	}
#endif

#ifdef SRV6_END_AC
	while((opt = getopt(argc, argv, "c:p:n:m:b:s:dzh")) != -1){
#else
	while((opt = getopt(argc, argv, "c:p:n:m:b:dzh")) != -1){
#endif
		switch(opt){
		case 'c':
			err = xdpd_parse_range(optarg,
				strbuf, sizeof(strbuf));
			if(err < 0){
				printf("Invalid argument\n");
				goto err_arg;
			}

			xdpd->num_threads = xdpd_parse_list(strbuf,
				argbuf, XDPD_MAX_ARGLEN, XDPD_MAX_ARGS);
			if(xdpd->num_threads < 0){
				printf("Invalid CPU cores to use\n");
				goto err_arg;
			}

			err = xdpd_convert_list((const char **)argbuf,
				xdpd->num_threads,
				"%u", xdpd->cores,
				sizeof(unsigned int), XDPD_MAX_CORES);
			if(err < 0){
				printf("Invalid argument\n");
				goto err_arg;
			}

			break;
		case 'p':
			xdpd->num_devices = xdpd_parse_list(optarg,
				xdpd->ifnames, XDPD_MAX_ARGLEN, XDPD_MAX_IFS);
			if(xdpd->num_devices < 0){
				printf("Invalid Interfaces to use\n");
				goto err_arg;
			}
			break;
		case 'n':
			if(sscanf(optarg, "%u", &xdpd->numa_node) != 1){
				printf("Invalid NUMA node\n");
				goto err_arg;
			}
			break;
		case 'm':
			if(sscanf(optarg, "%u", &xdpd->mtu_frame) != 1){
				printf("Invalid MTU length\n");
				goto err_arg;
			}
			break;
		case 'b':
			if(sscanf(optarg, "%u", &xdpd->buf_count) != 1){
				printf("Invalid number of packet buffer\n");
				goto err_arg;
			}
			break;
		case 'd':
			xdpd->xdp_flags |= XDP_FLAGS_DRV_MODE;
			break;
		case 'z':
			xdpd->xdp_bind_flags |= XDP_ZEROCOPY;
			break;
		case 'h':
			usage();
			goto err_arg;
			break;
#ifdef SRV6_END_AC
		case 's':
			if(table_index > 1){
				printf("too many SID configuration\n");
				goto err_arg;
			}

			err = xdpd_parse_list(optarg,
				srv6_opts, XDPD_MAX_ARGLEN, 10);
			if(err < 0){
				printf("Invalid SID configuration\n");
				goto err_arg;
			}

			err = xdpd_parse_srv6(srv6_opts);
			if(err < 0)
				goto err_arg;

			table_index++;
			break;
#endif
		default:
			usage();
			goto err_arg;
		}
	}

#ifdef SRV6_END_AC
	if(xdpd->num_devices < 4){
		printf("You must specify at least 4 Interfaces for End.AC.\n");
		goto err_arg;
	}

	if(table_index != 2){
		printf("You must specify 2 SID configuration for End.AC.\n");
		goto err_arg;
	}
#else
	if(!xdpd->num_devices){
		printf("You must specify PCI Interfaces to use.\n");
		goto err_arg;
	}
#endif

	if(!xdpd->num_threads){
		printf("You must specify CPU cores to use.\n");
		goto err_arg;
	}

#ifdef SRV6_END_AC
	for(i = 0; i < 10; i++){
		free(srv6_opts[i]);
	}
#endif

	for(i = 0; i < XDPD_MAX_ARGS; i++){
		free(argbuf[i]);
	}
	return 0;

err_arg:
#ifdef SRV6_END_AC
err_alloc_srv6_buf:
	for(i = 0; i < srv6_opts_done; i++){
		free(srv6_opts[i]);
	}
#endif
err_alloc_buf:
	for(i = 0; i < argbuf_done; i++){
		free(argbuf[i]);
	}
	return -1;
}

#ifdef SRV6_END_AC
static int xdpd_parse_srv6(char **srv6_opts)
{
	int i, j;
	int err;
	unsigned int mac_buf[6];
	unsigned int num_buf;
	struct sr_cache_table *cache_table;

	cache_table = &sr_cache_table[table_index];

	for(i = 0; i < 4; i++){
		if(sscanf(srv6_opts[i], "%u", &num_buf) != 1){
			printf("Invalid configuration of IF index\n");
			goto err_parse;
		}

		if(num_buf > 3){
			printf("Invalid configuration of IF index\n");
			goto err_parse;
		}

		cache_table->ifidx[i] = num_buf;
	}

	for(i = 0; i < 2; i++){
		if(sscanf(srv6_opts[i + 4], "%x:%x:%x:%x:%x:%x",
			&mac_buf[0], &mac_buf[1], &mac_buf[2],
			&mac_buf[3], &mac_buf[4], &mac_buf[5]) != 6){
			printf("Invalid configuration of MAC address\n");
			goto err_parse;
		}

		for(j = 0; j < 6; j++){
			cache_table->mac_addr[i][j] = mac_buf[j];
		}
	}

	err = inet_pton(AF_INET6, srv6_opts[6], cache_table->sid.sid);
	if(err < 1){
		printf("Invalid configuration of SID prefix\n");
		goto err_parse;
	}

	if(sscanf(srv6_opts[7], "%u", &num_buf) != 1){
		printf("Invalid configuration of SID length\n");
		goto err_parse;
	}
	if(num_buf & 0x7){
		printf("Invalid configuration of SID length\n");
		goto err_parse;
	}
	cache_table->sid.len = num_buf >> 3;

	if(sscanf(srv6_opts[8], "%u", &num_buf) != 1){
		printf("Invalid configuration of Arg offset\n");
		goto err_parse;
	}
	if(num_buf & 0x7){
		printf("Invalid configuration of Arg offset\n");
		goto err_parse;
	}
	cache_table->sid.arg_offset = num_buf >> 3;

	return 0;

err_parse:
	return -1;
}
#endif

static int xdpd_parse_range(const char *str, char *result, int max_len)
{
	unsigned int range[2];
	int err, i, num, offset, ranged;
	char buf[XDPD_MAX_ARGLEN];

	result[0] = '\0';
	offset = 0;
	ranged = 0;
	for(i = 0; i < strlen(str) + 1; i++){
		switch(str[i]){
		case ',':
		case '\0':
			buf[offset] = '\0';

			if(sscanf(buf, "%u", &range[1]) != 1)
				goto err_parse;

			if(!ranged)
				range[0] = range[1];

			for(num = range[0]; num <= range[1]; num++){
				err = snprintf(&(result)[strlen(result)],
					max_len - strlen(result),
					strlen(result) ? ",%d" : "%d", num);
				if(err < 0)
					goto err_parse;
			}

			offset = 0;
			ranged = 0;
			break;
		case '-':
			buf[offset] = '\0';

			if(sscanf(buf, "%u", &range[0]) != 1)
				goto err_parse;

			offset = 0;
			ranged = 1;
			break;
		default:
			if(offset == sizeof(buf) - 1)
				goto err_parse;

			buf[offset++] = str[i];
		}
	}
	return 0;

err_parse:
	return -1;
}

static int xdpd_parse_list(const char *str, char **result, int max_len,
	int max_count)
{
	int i, offset, count;
	char buf[XDPD_MAX_ARGLEN];

	offset = 0;
	count = 0;
	for(i = 0; i < strlen(str) + 1; i++){
		switch(str[i]){
		case ',':
		case '\0':
			buf[offset] = '\0';

			if(count >= max_count)
				goto err_parse;

			strncpy(result[count++], buf, max_len);
			offset = 0;
			break;
		default:
			if(offset == sizeof(buf) - 1)
				goto err_parse;

			buf[offset++] = str[i];
		}
	}
	return count;

err_parse:
	return -1;
}

static int xdpd_convert_list(const char **str, int str_count,
	const char *format, void *result, int size, int max_count)
{
	int i;

	for(i = 0; (i < str_count) && (i < max_count); i++){
		if(sscanf(str[i], format,
			((char *)result) + (size * i)) != 1){
			goto err_parse;
		}
	}
	return 0;

err_parse:
	return -1;
}
