#ifndef _XDPD_MAIN_H
#define _XDPD_MAIN_H

#include <sys/socket.h>
#include <linux/if.h>
#include <linux/if_ether.h>

#define ALIGN(x,a)		__ALIGN_MASK(x,(typeof(x))(a)-1)
#define __ALIGN_MASK(x,mask)	(((x)+(mask))&~(mask))

#define SRV6_END_AC

#ifdef SRV6_END_AC
#include <pthread.h>
#endif

//#define DEBUG
#ifdef DEBUG
#define xdp_print(args...) printf("xdp: " args)
#else
#define xdp_print(args...)
#endif

#define min(x, y) ({				\
	typeof(x) _min1 = (x);			\
	typeof(y) _min2 = (y);			\
	(void) (&_min1 == &_min2);		\
	_min1 < _min2 ? _min1 : _min2; })

#define max(x, y) ({				\
	typeof(x) _max1 = (x);			\
	typeof(y) _max2 = (y);			\
	(void) (&_max1 == &_max2);		\
	_max1 > _max2 ? _max1 : _max2; })

#define likely(x)	__builtin_expect(!!(x), 1)
#define unlikely(x)	__builtin_expect(!!(x), 0)
#define prefetch(x)	__builtin_prefetch(x, 0)
#define prefetchw(x)	__builtin_prefetch(x, 1)

#define PROCESS_NAME "xdp"
#define SYSLOG_FACILITY LOG_DAEMON
#define XDPD_RX_DESC 1024
#define XDPD_TX_DESC 4096
#define XDPD_RX_BUDGET 1024
#define XDPD_TX_BUDGET 4096
#define XDPD_MAX_CORES 16
#define XDPD_MAX_ARGS 128
#define XDPD_MAX_ARGLEN 1024
#define XDPD_MAX_IFS 64

#ifndef SOL_XDP
#define SOL_XDP 283
#endif

#ifndef AF_XDP
#define AF_XDP 44
#endif

#ifndef PF_XDP
#define PF_XDP AF_XDP
#endif

#define READ_SIZE 4096

struct xdp_ring {
	void			*addr;
	uint32_t		*producer;
	uint32_t		*consumer;
	void			*descs;
	unsigned int		size;
};

#define XDP_SLOT_INFLIGHT 0x1

struct xdp_buf {
	void			*addr;
	unsigned int		slot_size;
	unsigned int		slot_count;
	unsigned int		slot_count_devbuf;
	unsigned int		slot_mask_devbuf;
	unsigned int		*slots;
};

struct xdp_dev {
	int			xsks_map;

	unsigned int		num_qps;
	unsigned int		buf_size;
	unsigned int		mtu_frame;
	char			mac_addr[ETH_ALEN];

	int			ifindex;
	char			name[IFNAMSIZ];
	void			*drv_data;
};

struct xdp_packet {
	void			*slot_buf;
	unsigned int		slot_size;
	unsigned int		slot_index;
	int			out;
	void			*current;
	void			*layer2;
	void			*layer3;
	unsigned int		flag;
	uint8_t			nexthdr;
};

#define PACKET_SRV6_MATCH	0x0001
#define PACKET_SRV6_UPDATED	0x0002

#ifdef SRV6_END_AC
#define PACKET_SRV6_ENDAC_MATCH	0x0010
#endif

struct xdp_vec {
	int			num;
	struct xdp_packet	packets[XDPD_RX_BUDGET];
};

struct xdp_vec_ref {
	int			num;
	struct xdp_packet	*packets[XDPD_RX_BUDGET];
};

#ifdef SRV6_END_AC
struct sr_cache {
	char			buf[2048];
	unsigned int		size;
	pthread_rwlock_t	lock;
};

struct sr_sid {
	char			sid[16];
	unsigned int		len;
	unsigned int		arg_offset;
};

struct sr_cache_table {
	struct sr_cache		cache4[256];
	struct sr_cache		cache6[256];
	struct sr_sid		sid;
	unsigned int		ifidx[4];
	char			mac_addr[2][ETH_ALEN];
};

extern struct sr_cache_table	sr_cache_table[2];
#endif

struct xdp_port {
	/* struct dev specific parameters */
	unsigned int		dev_idx;

	int			xfd;
	struct xdp_ring		rx_ring;
	struct xdp_ring		tx_ring;
	struct xdp_ring		cq_ring;
	struct xdp_ring		fq_ring;

	struct xdp_vec		vec_rx;
	struct xdp_vec_ref	vec_tx;

	unsigned int		num_qps;
	unsigned int		mtu_frame;
	char			mac_addr[ETH_ALEN];

	unsigned int		rx_slot_next;
	unsigned int		rx_slot_offset;

	unsigned long		count_rx_alloc_failed;
	unsigned long		count_rx_clean_total;
	unsigned long		count_tx_xmit_failed;
	unsigned long		count_tx_clean_total;
#ifdef SRV6_END_AC
#define SRV6_END_AC_MODE_OUTER 0x0001
#define SRV6_END_AC_MODE_INNER 0x0002
	unsigned int		mode;
	unsigned int		bound_table_idx;
	unsigned int		bound_port_idx;
	char			bound_mac_addr[ETH_ALEN];
#endif
};

struct xdp_plane {
	struct xdp_port 	*ports;
	unsigned short		num_ports;
};

struct xdpd {
	struct xdp_dev		**devs;
	int			num_threads;
	unsigned int		cores[XDPD_MAX_CORES];
	int			num_devices;
	char			*ifnames[XDPD_MAX_IFS];
	unsigned int		mtu_frame;
	unsigned int		buf_size;
	unsigned int		buf_count;
	unsigned int		numa_node;
	unsigned int		xdp_flags;
	unsigned int		xdp_bind_flags;
};

void xdpd_log(int level, char *fmt, ...);
extern char *optarg;

#endif /* _XDPD_MAIN_H */
