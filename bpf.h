#ifndef XDPSOCK_H_
#define XDPSOCK_H_

//#define DEBUG
#ifdef DEBUG
/* Only use this for debug output. Notice output from bpf_trace_printk()
 * end-up in /sys/kernel/debug/tracing/trace_pipe
 */
#define bpf_debug(fmt, ...)						\
		({							\
			char ____fmt[] = fmt;				\
			bpf_trace_printk(____fmt, sizeof(____fmt),	\
				     ##__VA_ARGS__);			\
		})
#else
#define bpf_debug(fmt, ...) { } while (0)
#endif

#ifndef htons
#define htons(X) __constant_htons((X))
#endif

#ifndef ntohs
#define ntohs(X) __constant_ntohs((X))
#endif

#endif /* XDPSOCK_H_ */
