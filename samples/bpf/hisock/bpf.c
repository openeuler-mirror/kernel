// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 *
 * Description: End-to-End HiSock Redirect sample.
 */
#define KBUILD_MODNAME "foo"
#include <uapi/linux/in.h>
#include <uapi/linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/filter.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/bpf.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#define IP_MF           0x2000
#define IP_OFFSET       0x1FFF
#define CSUM_SHIFT_BITS	16

#define MAX_NUMA	8
#define MAX_CONN_NUMA	4096
#define MAX_CONN	(MAX_CONN_NUMA * MAX_NUMA * 2)

#define MAX_COMM_NUM	8

struct sock_tuple {
	u32 saddr;
	u32 daddr;
	u16 sport;
	u16 dport;
};

struct sock_value {
	void *sk;
	void *egress_dev;
	void *ingress_dev;
	struct ethhdr ingress_eth;
	bool eth_updated;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(struct sock_tuple));
	__uint(value_size, sizeof(struct sock_value));
	__uint(max_entries, MAX_CONN);
} connmap SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(u16));
	__uint(value_size, sizeof(u8));
	__uint(max_entries, 128);
} speed_port SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(char[TASK_COMM_LEN]));
	__uint(value_size, sizeof(u8));
	__uint(max_entries, MAX_COMM_NUM);
} target_comm SEC(".maps");

static inline bool is_speed_flow(u16 port)
{
	u8 *val;

	val = bpf_map_lookup_elem(&speed_port, &port);
	if (val && *val == 1)
		return true;

	return false;
}

static inline bool is_ipv6_addr_mapped(u32 *addr6)
{
	return addr6[0] == 0 && addr6[1] == 0 &&
	       addr6[2] == bpf_htonl(0x0000ffff);
}

static inline void *parse_ingress_dev(struct bpf_sock_ops *skops)
{
	struct sk_buff *skb;
	struct net_device *dev;

	skb = BPF_CORE_READ((struct bpf_sock_ops_kern *)skops, skb);
	dev = BPF_CORE_READ(skb, dev);

	return dev;
}

static inline void *parse_egress_dev(struct __sk_buff *skb)
{
	struct net_device *dev;

	dev = BPF_CORE_READ((struct sk_buff *)skb, dev);

	return dev;
}

static void handle_listen_cb(struct bpf_sock_ops *skops)
{
	char comm[TASK_COMM_LEN] = { 0 };
	u8 *comm_val;

	bpf_get_current_comm(comm, sizeof(comm));

	comm_val = bpf_map_lookup_elem(&target_comm, comm);
	if (comm_val && *comm_val == 1) {
		u16 key = skops->local_port;
		u8 val = 1;

		bpf_map_update_elem(&speed_port, &key, &val, BPF_ANY);
	}
}

static void
handle_remote_estd_cb(struct bpf_sock_ops *skops, u32 *laddr, u32 *raddr)
{
	struct sock_tuple key = { 0 };
	struct sock_value val = { 0 };

	key.saddr = *raddr;
	key.daddr = *laddr;
	key.sport = bpf_ntohl(skops->remote_port);
	key.dport = skops->local_port;

	val.sk = skops->sk;
	val.ingress_dev = parse_ingress_dev(skops);

	bpf_map_update_elem(&connmap, &key, &val, BPF_ANY);

	bpf_sock_ops_cb_flags_set(skops, BPF_SOCK_OPS_STATE_CB_FLAG);
}

static inline void handle_passive_estd_inet_cb(struct bpf_sock_ops *skops)
{
	handle_remote_estd_cb(skops, &skops->local_ip4, &skops->remote_ip4);
}

static inline void handle_passive_estd_inet6_cb(struct bpf_sock_ops *skops)
{
	handle_remote_estd_cb(skops, &skops->local_ip6[3], &skops->remote_ip6[3]);
}

static void
handle_terminate_cb(struct bpf_sock_ops *skops, u32 *laddr, u32 *raddr)
{
	struct sock_tuple key = { 0 };

	if (skops->args[1] != BPF_TCP_CLOSE_WAIT &&
	    skops->args[1] != BPF_TCP_FIN_WAIT1 &&
	    skops->args[1] != BPF_TCP_CLOSE)
		return;

	key.saddr = *raddr;
	key.daddr = *laddr;
	key.sport = bpf_ntohl(skops->remote_port);
	key.dport = skops->local_port;

	bpf_map_delete_elem(&connmap, &key);

	bpf_sock_ops_cb_flags_set(skops,
		skops->bpf_sock_ops_cb_flags & ~BPF_SOCK_OPS_STATE_CB_FLAG);
}

static inline void handle_terminate_inet_cb(struct bpf_sock_ops *skops)
{
	handle_terminate_cb(skops, &skops->local_ip4, &skops->remote_ip4);
}

static inline void handle_terminate_inet6_cb(struct bpf_sock_ops *skops)
{
	handle_terminate_cb(skops, &skops->local_ip6[3], &skops->remote_ip6[3]);
}

SEC("hisock_sockops")
int hisock_sockops_prog(struct bpf_sock_ops *skops)
{
	if (skops->op == BPF_SOCK_OPS_TCP_LISTEN_CB) {
		handle_listen_cb(skops);
		return 1;
	}

	if (skops->family == AF_INET) {
		switch (skops->op) {
		case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
			if (!is_speed_flow(skops->local_port))
				break;
			handle_passive_estd_inet_cb(skops);
			break;
		case BPF_SOCK_OPS_STATE_CB:
			handle_terminate_inet_cb(skops);
			break;
		default:
			break;
		}
	} else if (skops->family == AF_INET6 &&
		   is_ipv6_addr_mapped(skops->local_ip6)) {
		switch (skops->op) {
		case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
			if (!is_speed_flow(skops->local_port))
				break;
			handle_passive_estd_inet6_cb(skops);
			break;
		case BPF_SOCK_OPS_STATE_CB:
			handle_terminate_inet6_cb(skops);
			break;
		default:
			break;
		}
	}

	return 1;
}

SEC("hisock_ingress")
int hisock_ingress_prog(struct __sk_buff *skb)
{
	void *data_end = (void *)(long)skb->data_end;
	void *data = (void *)(long)skb->data;
	struct sock_tuple key = { 0 };
	struct sock_value *val;
	struct tcphdr *thdr;
	struct iphdr *ihdr;
	struct ethhdr ehdr;

	if (skb->protocol != bpf_htons(ETH_P_IP))
		return HISOCK_PASS;

	ihdr = (struct iphdr *)data;
	if (ihdr + 1 > data_end)
		return HISOCK_PASS;

	if (ihdr->ihl != 5 || ihdr->protocol != IPPROTO_TCP)
		return HISOCK_PASS;

	if (ihdr->frag_off & bpf_htons(IP_MF | IP_OFFSET))
		return HISOCK_PASS;

	thdr = (struct tcphdr *)(ihdr + 1);
	if (thdr + 1 > data_end)
		return HISOCK_PASS;

	if (thdr->syn || thdr->fin || thdr->rst)
		return HISOCK_PASS;

	key.saddr = ihdr->saddr;
	key.sport = bpf_ntohs(thdr->source);
	key.daddr = ihdr->daddr;
	key.dport = bpf_ntohs(thdr->dest);

	val = bpf_map_lookup_elem(&connmap, &key);
	if (!val)
		return HISOCK_PASS;

	if (!val->eth_updated) {
		if (!(bpf_get_skb_ethhdr(skb, &ehdr, sizeof(ehdr)))) {
			memcpy(val->ingress_eth.h_source, ehdr.h_dest, ETH_ALEN);
			memcpy(val->ingress_eth.h_dest, ehdr.h_source, ETH_ALEN);
			val->ingress_eth.h_proto = ehdr.h_proto;
			val->eth_updated = true;
		}
	}

	if (!val->egress_dev)
		val->egress_dev = parse_egress_dev(skb);

	bpf_set_ingress_dev(skb, val->ingress_dev);
	bpf_handle_ingress_ptype(skb);
	bpf_set_ingress_dst(skb, val->sk);

	return HISOCK_REDIRECT;
}

static inline void ipv4_csum(struct iphdr *ihdr)
{
	u32 csum = 0;
	u16 *next_ip_u16 = (u16 *)ihdr;

	ihdr->check = 0;
	for (size_t i = 0; i < sizeof(struct iphdr) >> 1; i++)
		csum += *next_ip_u16++;

	ihdr->check = ~((csum & 0xffff) + (csum >> CSUM_SHIFT_BITS));
}

SEC("hisock_egress")
int hisock_egress_prog(struct __sk_buff *skb)
{
	void *data_end = (void *)(long)skb->data_end;
	void *data = (void *)(long)skb->data;
	struct sock_tuple key = { 0 };
	struct sock_value *val;
	struct ethhdr *ehdr;
	struct tcphdr *thdr;
	struct iphdr *ihdr;

	ihdr = (struct iphdr *)data;
	if (ihdr + 1 > data_end)
		return HISOCK_PASS;

	thdr = (struct tcphdr *)(ihdr + 1);
	if (thdr + 1 > data_end)
		return HISOCK_PASS;

	if (thdr->syn || thdr->fin || thdr->rst)
		return HISOCK_PASS;

	key.saddr = skb->remote_ip4;
	key.sport = bpf_ntohl(skb->remote_port);
	key.daddr = skb->local_ip4;
	key.dport = skb->local_port;

	val = bpf_map_lookup_elem(&connmap, &key);
	if (!val)
		return HISOCK_PASS;

	if (!val->eth_updated)
		goto redirect;

	ihdr->tot_len = bpf_htons(skb->len);
	ipv4_csum(ihdr);

	if (bpf_skb_change_head(skb, ETH_HLEN, 0) < 0)
		goto redirect;

	data = (void *)(long)skb->data;
	data_end = (void *)(long)skb->data_end;

	ehdr = (struct ethhdr *)data;
	if (ehdr + 1 > data_end)
		return HISOCK_DROP;

	memcpy(ehdr, &val->ingress_eth, ETH_HLEN);
	bpf_handle_egress_ptype(skb);
redirect:
	bpf_set_egress_dev(skb, val->egress_dev);

	return HISOCK_REDIRECT;
}

char _license[] SEC("license") = "GPL";
