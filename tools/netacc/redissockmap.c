// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2023 Huawei Technologies Co., Ltd
 */

#include "bpf_sockmap.h"

#define REDIS_BIND_MAP_SIZE 100
#define BLOCKLIST_SIZE 1000

#define ENABLE_BLOCKLIST 0
#define SHORT_THR 10
#define BLOCK_THR 10000

struct local_ip {
	__u32 ip4;
};

struct ipaddr_port {
	__u32 ip4;
	__u32 port;
} __attribute__((packed));

#if ENABLE_BLOCKLIST
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct ipaddr_port);
	__type(value, int);
	__uint(max_entries, BLOCKLIST_SIZE);
	__uint(map_flags, 0);
} blocklist_map SEC(".maps");
#endif

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct ipaddr_port);
	__type(value, int);
	__uint(max_entries, REDIS_BIND_MAP_SIZE);
	__uint(map_flags, 0);
} redis_bind_map SEC(".maps");


static inline void extract_ipaddrport_from_ops(struct bpf_sock_ops *skops,
		struct ipaddr_port *key1, struct ipaddr_port *key2)
{
	key1->ip4 = skops->remote_ip4;
	// remote_port is in network byte order
	key1->port = bpf_ntohl(skops->remote_port);

	key2->ip4 = skops->local_ip4;
	// local_port is in host byte order
	key2->port = skops->local_port;
}

static inline int __is_redis_sock(struct ipaddr_port *key)
{
	int *pv = NULL;

	pv = bpf_map_lookup_elem(&redis_bind_map, key);
	if (pv)
		return 1;

	return 0;
}

static inline int is_redis_sock(struct ipaddr_port *key1, struct ipaddr_port *key2,
		struct ipaddr_port *key10, struct ipaddr_port *key20)
{
	net_dbg("is_redis, ip1:0x%x, port1:0x%x\n", key1->ip4, key1->port);
	net_dbg("is_redis, ip2:0x%x, port2:0x%x\n", key2->ip4, key2->port);

	if (__is_redis_sock(key1))
		return 1;

	if (__is_redis_sock(key2))
		return 1;

	if (__is_redis_sock(key10))
		return 1;

	if (__is_redis_sock(key20))
		return 1;

	return 0;
}

static inline int is_localip_sock(struct bpf_sock_ops *skops)
{
	struct local_ip remoteip;

	net_dbg("is_localip, ip1:0x%x, ip2:0x%x\n",
			skops->local_ip4, skops->remote_ip4);

	// skops->local_ip4 must be the local IP address
	remoteip.ip4 = skops->remote_ip4;

	if ((remoteip.ip4 & 0xff) == 0x7f)
		return 1;

	if (!bpf_is_local_ipaddr(remoteip.ip4))
		return 0;

	return 1;
}

#if ENABLE_BLOCKLIST
static inline int __is_in_block_list(struct ipaddr_port *key)
{
	int *pv = NULL;

	pv = bpf_map_lookup_elem(&blocklist_map, key);
	if (pv && *pv > BLOCK_THR)
		return 1;

	return 0;
}

static inline int is_in_block_list(struct ipaddr_port *key1, struct ipaddr_port *key2,
		struct ipaddr_port *key10, struct ipaddr_port *key20)
{

	if (__is_in_block_list(key1))
		return 1;
	if (__is_in_block_list(key2))
		return 1;
	if (__is_in_block_list(key10))
		return 1;
	if (__is_in_block_list(key20))
		return 1;

	return 0;
}

static inline int __add_task2block_list(struct ipaddr_port *block)
{
	int *pv = NULL;
	int value = 1;

	pv = bpf_map_lookup_elem(&blocklist_map, block);
	if (pv == NULL) {
		bpf_map_update_elem(&blocklist_map, block, &value, BPF_NOEXIST);
		return 0;
	}

	if (*pv > BLOCK_THR)
		return 0;

	*pv += 1;
	return 0;
}

static inline int add_task2block_list(struct bpf_sock_ops *skops)
{
	struct ipaddr_port block1;
	struct ipaddr_port block2;

	extract_ipaddrport_from_ops(skops, &block1, &block2);

	if (__is_redis_sock(&block1))
		return __add_task2block_list(&block1);

	if (__is_redis_sock(&block2))
		return __add_task2block_list(&block2);

	block1.ip4 = 0;
	if (__is_redis_sock(&block1))
		return __add_task2block_list(&block1);

	block2.ip4 = 0;
	if (__is_redis_sock(&block2))
		return __add_task2block_list(&block2);

	return 0;
}
#else
static inline int add_task2block_list(struct bpf_sock_ops *skops)
{
	return 0;
}
static inline int is_in_block_list(struct ipaddr_port *key1, struct ipaddr_port *key2,
		struct ipaddr_port *key10, struct ipaddr_port *key20)
{
	return 0;
}
#endif

static inline int is_redis_loopback_tcp(struct bpf_sock_ops *skops)
{
	struct ipaddr_port key10;
	struct ipaddr_port key20;
	struct ipaddr_port key1;
	struct ipaddr_port key2;

	if (!is_localip_sock(skops))
		return 0;
	net_dbg("this is localip\n");

	extract_ipaddrport_from_ops(skops, &key1, &key2);
	key10.ip4 = 0;
	key10.port = key1.port;
	key20.ip4 = 0;
	key20.port = key2.port;

	if (!is_redis_sock(&key1, &key2, &key10, &key20))
		return 0;
	net_dbg("this is redis sock\n");

	if (is_in_block_list(&key1, &key2, &key10, &key20))
		return 0;

	net_dbg("the sock is redis loopback sock\n");
	return 1;
}

static inline int update_redis_info(struct bpf_sock_ops *skops)
{
	struct ipaddr_port key;
	int value = 1;
	char comm[16] = {0};

	bpf_get_current_comm(comm, sizeof(comm));
	if (comm[0] != 'r' || comm[1] != 'e' || comm[2] != 'd' || comm[3] != 'i' ||
	    comm[4] != 's' || comm[5] != '-' ||  comm[6] != 's' ||  comm[7] != 'e' ||
	    comm[8] != 'r' || comm[9] != 'v' ||  comm[10] != 'e' ||  comm[11] != 'r')
		return 0;

	key.ip4 = skops->local_ip4;
	key.port = skops->local_port; // host order

	bpf_map_update_elem(&redis_bind_map, &key, &value, BPF_NOEXIST);
	net_dbg("%s, update redisinfo: sip:0x%x, sport:%d\n", comm, key.ip4, key.port);
	return 1;
}

static inline void clean_redis_info(struct bpf_sock_ops *skops)
{
	struct ipaddr_port key;

	key.ip4 = skops->local_ip4;
	key.port = skops->local_port; // host order
	net_dbg("clean redisinfo, 0x%x:%d\n", key.ip4, key.port);
	bpf_map_delete_elem(&redis_bind_map, &key);
}

SEC("sockops") int redis_sockops(struct bpf_sock_ops *skops)
{
	switch (skops->op) {
	case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
	case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
		if (skops->family == 2) {// AF_INET
			if (is_redis_loopback_tcp(skops)) {
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
			clean_redis_info(skops);
		} else if (skops->family == 2 && (skops->args[1] == BPF_TCP_CLOSE ||
					skops->args[1] == BPF_TCP_CLOSE_WAIT ||
					skops->args[1] == BPF_TCP_FIN_WAIT1)) {
			__u64 tx_cnt = SHORT_THR;

			bpf_sockmap_ipv4_cleanup(skops, &tx_cnt);
			net_dbg("sockops sk:%p, state:%d, tx_cnt:%llu\n",
				skops->sk, skops->args[1], tx_cnt);
			if (tx_cnt < SHORT_THR)
				add_task2block_list(skops);
		}
		break;
	case BPF_SOCK_OPS_TCP_LISTEN_CB:
		if (skops->family == 2 && update_redis_info(skops))
			bpf_sock_ops_cb_flags_set(skops, BPF_SOCK_OPS_STATE_CB_FLAG);
		break;
	default:
		break;
	}
	return 1;
}

char _license[] SEC("license") = "GPL";
int _version SEC("version") = 1;
