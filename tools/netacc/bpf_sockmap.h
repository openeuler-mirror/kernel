/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2023 Huawei Technologies Co., Ltd
 */

#ifndef __BPF_SOCKMAP_H__
#define __BPF_SOCKMAP_H__

#include <stddef.h>
#include <stdbool.h>
#include <linux/types.h>
#include <linux/bpf.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define LOG_DEBUG 0
#define SOCKMAP_SIZE 100000

#if LOG_DEBUG
#define net_dbg bpf_printk
#define net_err bpf_printk
#else
#define net_dbg(fmt, ...) do {} while (0)
#define net_err bpf_printk
#endif

/* Unless otherwise specified, change ipaddr to network byte order */
struct sock_key {
	__u32 sip4;
	__u32 dip4;
	__u32 sport;
	__u32 dport;
	__u64 netns_cookie;
} __attribute__((packed));

struct {
	__uint(type, BPF_MAP_TYPE_SOCKHASH);
	__type(key, struct sock_key);
	__type(value, int);
	__uint(max_entries, SOCKMAP_SIZE);
	__uint(map_flags, 0);
} netaccsock_map SEC(".maps");

struct sock_info {
	__u64 redir_rx_cnt;
	__u64 redir_tx_cnt;
	int sk_flags;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct sock_key);
	__type(value, struct sock_info);
	__uint(max_entries, SOCKMAP_SIZE);
	__uint(map_flags, 0);
} sockflag_map SEC(".maps");

/* in network byte order */
#define IS_LOOPBACK(a)		((((__u32) (a)) & 0x000000ff) == 0x0000007f)
#define IS_NOT_LOOPBACK(a)	((((__u32) (a)) & 0x000000ff) != 0x0000007f)

static inline void sock_key_add_netnsinfo(void *const ctx, struct sock_key *key)
{
	if (IS_NOT_LOOPBACK(key->sip4) || IS_NOT_LOOPBACK(key->dip4))
		key->netns_cookie = 0;
	else
		key->netns_cookie = bpf_get_netns_cookie(ctx);
}

static inline void sock_key2peerkey(struct sock_key *key, struct sock_key *peer_key)
{
	peer_key->sip4 = key->dip4;
	peer_key->sport = key->dport;
	peer_key->dip4 = key->sip4;
	peer_key->dport = key->sport;
}

static inline void extract_key4_from_ops(struct bpf_sock_ops *ops, struct sock_key *key)
{
	key->dip4 = ops->remote_ip4;
	key->sip4 = ops->local_ip4;

	// local_port is in host byte order
	// and remote_port is in network byte order
	key->sport = ops->local_port;
	key->dport = bpf_ntohl(ops->remote_port);
}

static inline void bpf_sock_ops_ipv4(struct bpf_sock_ops *skops)
{
	struct sock_key key = {};

	extract_key4_from_ops(skops, &key);
	sock_key_add_netnsinfo(skops, &key);

	bpf_sock_hash_update(skops, &netaccsock_map, &key, BPF_NOEXIST);
}

static inline void bpf_sockmap_ipv4_insert(struct bpf_sock_ops *skops)
{
	if (bpf_ntohl(skops->remote_port) == 22 || skops->local_port == 22)
		return;

	bpf_sock_ops_ipv4(skops);
}

static inline void bpf_sockmap_ipv4_cleanup(struct bpf_sock_ops *skops, __u64 *cnt)
{
	struct sock_info *p_skinfo = NULL;
	struct sock_key key = {};

	extract_key4_from_ops(skops, &key);
	sock_key_add_netnsinfo(skops, &key);
	p_skinfo = bpf_map_lookup_elem(&sockflag_map, &key);
	if (p_skinfo) {
		if (cnt)
			*cnt = p_skinfo->redir_tx_cnt;
		bpf_map_delete_elem(&sockflag_map, &key);
	}
}

static inline void extract_key4_from_msg(struct sk_msg_md *msg, struct sock_key *key)
{
	key->sip4 = msg->local_ip4;
	key->dip4 = msg->remote_ip4;

	// local_port is in host byte order
	// and remote_port is in network byte order
	key->sport = msg->local_port;
	key->dport = bpf_ntohl(msg->remote_port);
}

SEC("sk_msg") int netacc_redir(struct sk_msg_md *msg)
{
	struct sock_info *p_skinfo = NULL;
	struct sock_info skinfo = {0};
	struct sock_key peer_key = {};
	struct sock_key key = {};
	int ret, addinfo = 0;

	extract_key4_from_msg(msg, &key);
	sock_key_add_netnsinfo(msg, &key);
	sock_key2peerkey(&key, &peer_key);
	sock_key_add_netnsinfo(msg, &peer_key);

	p_skinfo = bpf_map_lookup_elem(&sockflag_map, &key);
	if (p_skinfo != NULL && p_skinfo->sk_flags == 1)
		return SK_PASS;

	if (p_skinfo == NULL) {
		addinfo = 1;
		p_skinfo = &skinfo;
	}

	ret = bpf_msg_redirect_hash(msg, &netaccsock_map, &peer_key, BPF_F_INGRESS);
	if (ret == SK_DROP) {
		if (p_skinfo->sk_flags != 1)
			p_skinfo->sk_flags = 1;
	}

	p_skinfo->redir_tx_cnt++;
	if (addinfo)
		bpf_map_update_elem(&sockflag_map, &key, p_skinfo, BPF_ANY);

	return SK_PASS;
}
#endif
