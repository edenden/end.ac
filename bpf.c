#define KBUILD_MODNAME "foo"
#include <linux/bpf.h>

#define SRV6_END_AC
#ifdef SRV6_END_AC
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#endif

#include "bpf_helpers.h"
#include "bpf.h"

struct bpf_map_def SEC("maps") xsks_map = {
	.type = BPF_MAP_TYPE_XSKMAP,
	.key_size = sizeof(int),
	.value_size = sizeof(int),
	.max_entries = 128,
};

SEC("prog")
int xdp_sock_prog(struct xdp_md *ctx)
{
#ifdef SRV6_END_AC
	void *data = (void *)(long)ctx->data;
	void* data_end = (void *)(long)ctx->data_end;
	struct ethhdr *eth;
	struct iphdr *ip;
	struct ipv6hdr *ip6;
	int ret;
#endif

	bpf_debug("packet arrived, queue_index = %d\n",
		ctx->rx_queue_index);

#ifdef SRV6_END_AC
	ret = XDP_PASS;

	if(data + sizeof(struct ethhdr) > data_end)
		goto out;
	eth = data;

	switch(ntohs(eth->h_proto)){
	case ETH_P_ARP:
		break;
	case ETH_P_IP:
		if((void *)(eth + 1) + sizeof(struct iphdr) > data_end)
			goto out;
		ip = (struct iphdr *)(eth + 1);

		if(ip->ttl == 1)
			goto out;

		if(ip->tos){
			ret = bpf_redirect_map(&xsks_map,
				ctx->rx_queue_index, 0);
		}
		break;
	case ETH_P_IPV6:
		if((void *)(eth + 1) + sizeof(struct ipv6hdr) > data_end)
			goto out;
		ip6 = (struct ipv6hdr *)(eth + 1);

		if(ip6->hop_limit == 1)
			goto out;

		if(ip6->flow_lbl[2]){
			ret = bpf_redirect_map(&xsks_map,
				ctx->rx_queue_index, 0);
		}

		if(ip6->nexthdr == IPPROTO_ROUTING){
			ret = bpf_redirect_map(&xsks_map,
				ctx->rx_queue_index, 0);
		}
		break;
	}

out:
	return ret;
#else
	return bpf_redirect_map(&xsks_map, ctx->rx_queue_index, 0);
#endif
}

char _license[] SEC("license") = "GPL";
