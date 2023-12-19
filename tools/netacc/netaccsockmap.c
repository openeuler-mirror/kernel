// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2023 Huawei Technologies Co., Ltd
 */

#include "bpf_sockmap.h"

#define NETACC_BIND_MAP_SIZE 100

#define CHECK_ACC_SOCK 1

struct ipaddr_port {
	__u32 ip4;
	__u32 port;
} __attribute__((packed));

#if CHECK_ACC_SOCK
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct ipaddr_port);
	__type(value, int);
	__uint(max_entries, NETACC_BIND_MAP_SIZE);
	__uint(map_flags, 0);
} netacc_bind_map SEC(".maps");

static inline int __is_netacc_sock(struct ipaddr_port *key)
{
	int *pv = NULL;

	pv = bpf_map_lookup_elem(&netacc_bind_map, key);
	if (pv)
		return 1;

	return 0;
}

static inline int is_netacc_sock(struct ipaddr_port *key1, struct ipaddr_port *key10)
{
	net_dbg("is_netacc, ip1:0x%x, port1:0x%x\n", key1->ip4, key1->port);

	if (__is_netacc_sock(key1))
		return 1;

	if (__is_netacc_sock(key10))
		return 1;

	return 0;
}

static inline void extract_dst_ipaddrport_from_ops(struct bpf_sock_ops *skops,
		struct ipaddr_port *key)
{
	if (skops->op == BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB) {
		key->ip4 = skops->remote_ip4;
		// remote_port is in network byte order
		key->port = bpf_ntohl(skops->remote_port);
	} else if (skops->op == BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB) {
		key->ip4 = skops->local_ip4;
		// local_port is in host byte order
		key->port = skops->local_port;
	}
}

static inline int is_netacc_interested_tcp(struct bpf_sock_ops *skops)
{
	struct ipaddr_port key = {0};
	struct ipaddr_port key0;

	// only test server's port
	extract_dst_ipaddrport_from_ops(skops, &key);
	key0.ip4 = 0;
	key0.port = key.port;

	if (!is_netacc_sock(&key, &key0))
		return 0;
	net_dbg("this is netacc sock\n");

	net_dbg("the sock is netacc loopback sock\n");
	return 1;
}

static inline int update_netacc_info(struct bpf_sock_ops *skops)
{
	struct ipaddr_port key;
	int value = 1;
	char comm[16] = {0};

	bpf_get_current_comm(comm, sizeof(comm));

	if (bpf_strncmp(comm, 12, "redis-server"))
		return 0;

	key.ip4 = skops->local_ip4;
	key.port = skops->local_port; // host order

	bpf_map_update_elem(&netacc_bind_map, &key, &value, BPF_NOEXIST);
	net_dbg("%s, update netaccinfo: sip:0x%x, sport:%d\n", comm, key.ip4, key.port);
	return 1;
}

static inline void clean_netacc_info(struct bpf_sock_ops *skops)
{
	struct ipaddr_port key;

	key.ip4 = skops->local_ip4;
	key.port = skops->local_port; // host order
	net_dbg("clean netaccinfo, 0x%x:%d\n", key.ip4, key.port);
	bpf_map_delete_elem(&netacc_bind_map, &key);
}
#else
static inline int is_netacc_interested_tcp(struct bpf_sock_ops *skops)
{
	return 1;
}
static inline int update_netacc_info(struct bpf_sock_ops *skops)
{
	return 0;
}
static inline void clean_netacc_info(struct bpf_sock_ops *skops)
{}
#endif

SEC("sockops")
int netacc_sockops(struct bpf_sock_ops *skops)
{
	switch (skops->op) {
	case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
	case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
		if (skops->family == 2 && skops->local_skb) {// AF_INET
			if (is_netacc_interested_tcp(skops)) {
				net_dbg("bpf_sockops, sockmap, op:%d, sk:%p\n",
					skops->op, skops->sk);
				bpf_sock_ops_cb_flags_set(skops, BPF_SOCK_OPS_STATE_CB_FLAG);
				bpf_sockmap_ipv4_insert(skops);
			} else {
				bpf_sock_ops_cb_flags_set(skops, 0);
			}
		}
		break;
	case  BPF_SOCK_OPS_STATE_CB:
		if (skops->family == 2 && skops->args[0] == BPF_TCP_LISTEN &&
				skops->args[1] == BPF_TCP_CLOSE) {
			clean_netacc_info(skops);
		} else if (skops->family == 2 && (skops->args[1] == BPF_TCP_CLOSE ||
					skops->args[1] == BPF_TCP_CLOSE_WAIT ||
					skops->args[1] == BPF_TCP_FIN_WAIT1)) {
			bpf_sockmap_ipv4_cleanup(skops, NULL);
		}
		break;
	case BPF_SOCK_OPS_TCP_LISTEN_CB:
		if (skops->family == 2 && update_netacc_info(skops))
			bpf_sock_ops_cb_flags_set(skops, BPF_SOCK_OPS_STATE_CB_FLAG);
		break;
	default:
		break;
	}
	return 1;
}

char _license[] SEC("license") = "GPL";
int _version SEC("version") = 1;
