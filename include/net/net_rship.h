/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Common code for task relationship aware
 *
 * Copyright (C) 2024 Huawei Technologies Co., Ltd
 *
 */

#ifndef __LINUX_NET_RSHIP_H__
#define __LINUX_NET_RSHIP_H__

#include <linux/types.h>
#include <linux/jiffies.h>
#include <linux/socket.h>
#include <linux/sched.h>
#include <linux/timer.h>
#include <linux/net.h>
#include <linux/interrupt.h>
#include <linux/static_key.h>

#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <net/sock.h>
#include <linux/filter.h>

#ifdef CONFIG_SCHED_TASK_RELATIONSHIP

struct sched_net_rship_skb {
	/* for loopback traffic */
	pid_t alloc_tid;

	/* for phy nic */
	union {
		u32 rx_dev_idx; /* rx */
		int dev_numa_node; /* tx */
	};
	u16 alloc_cpu;
	u16 rx_queue_idx;
	u64 rx_dev_net_cookie;
};

struct sk_buff_fclones_net_rship {
	struct sk_buff_fclones fclones;
	struct sched_net_rship_skb ext1;
	struct sched_net_rship_skb ext2;
};

struct sk_buff_net_rship {
	struct sk_buff skb;
	struct sched_net_rship_skb ext;
};

struct sched_net_rship_sock {
	/* for loopback traffic */
	pid_t sk_peer_tid;
	u64 tid_rx_bytes;
	unsigned long last_rx_update;

	/* for recv from phy nic */
	int rcv_numa_node;
	u64 rcv_numa_node_bytes;
	unsigned long last_rcv_numa_node_update;

	/* for send to phy nic */
	pid_t sk_send_tid;
	int send_numa_node;
	u64 send_numa_node_bytes;
	unsigned long last_send_numa_node_update;
};
#endif

#if defined(CONFIG_SCHED_TASK_RELATIONSHIP) && defined(CONFIG_BPF_NET_GLOBAL_PROG)

#define NET_RSHIP_HEAD_RESERVE	40
extern unsigned long net_numa_rship_jiffies;

static inline void net_rship_sock_init(struct sock *sk, unsigned int offset)
{
	sk->net_rship = (void *)(((char *)sk) + offset);
	memset(sk->net_rship, 0, sizeof(struct sched_net_rship_sock));
	sk->net_rship->rcv_numa_node = NUMA_NO_NODE;
	sk->net_rship->send_numa_node = NUMA_NO_NODE;
}

static inline struct sched_net_rship_skb *__get_skb_net_rship(struct sk_buff *skb)
{
	return skb->net_rship;
}

static inline bool net_rship_refresh_timeout(unsigned long last_update)
{
	return time_after(jiffies, net_numa_rship_jiffies + last_update);
}

static inline void net_rship_sk_dst_set(struct sock *sk, struct dst_entry *dst)
{
	if (!gnet_bpf_enabled(GNET_SK_DST_SET))
		return;

	if (!in_task() || !dst)
		return;

	if (dev_to_node(&dst->dev->dev) != NUMA_NO_NODE) {
		struct bpf_gnet_ctx_kern ctx = {0};

		ctx.numa_node = dev_to_node(&dst->dev->dev);
		if (sk->net_rship->sk_send_tid)
			ctx.curr_tid = sk->net_rship->sk_send_tid;
		else
			ctx.curr_tid = task_pid_nr(current);
		ctx.sk = sk;
		run_gnet_bpf(GNET_SK_DST_SET, &ctx);
	}
}

static inline void __net_rship_tcp_rcvmsg(struct sock *sk, pid_t tid)
{
	struct bpf_gnet_ctx_kern ctx = {0};

	ctx.sk = sk;
	ctx.curr_tid = task_pid_nr(current);
	ctx.peer_tid = tid;
	ctx.rxtx_bytes = sk->net_rship->tid_rx_bytes;
	sk->net_rship->last_rx_update = jiffies;
	run_gnet_bpf(GNET_TCP_RECVMSG, &ctx);
	sk->net_rship->tid_rx_bytes = 0;
}

static inline void net_rship_tcp_local(struct sock *sk, struct sk_buff *skb)
{
	struct sched_net_rship_skb *ext;

	if (!gnet_bpf_enabled(GNET_TCP_RECVMSG))
		return;

	ext = __get_skb_net_rship(skb);
	if (!ext->alloc_tid)
		return;

	if (sk->net_rship->sk_peer_tid != ext->alloc_tid) {
		sk->net_rship->sk_peer_tid = ext->alloc_tid;
		sk->net_rship->tid_rx_bytes = skb->len + NET_RSHIP_HEAD_RESERVE;
		__net_rship_tcp_rcvmsg(sk, ext->alloc_tid);
	} else {
		sk->net_rship->tid_rx_bytes += (skb->len + NET_RSHIP_HEAD_RESERVE);
		if (net_rship_refresh_timeout(sk->net_rship->last_rx_update))
			__net_rship_tcp_rcvmsg(sk, ext->alloc_tid);
	}
}

static inline void net_rship_recv_nic_node(struct sock *sk, struct sk_buff *skb)
{
	struct sched_net_rship_skb *ext;

	if (!gnet_bpf_enabled(GNET_RCV_NIC_NODE))
		return;

	ext = __get_skb_net_rship(skb);
	if (ext->alloc_tid || ext->rx_dev_idx == -1)
		return;

	sk->net_rship->rcv_numa_node_bytes += (skb->len + NET_RSHIP_HEAD_RESERVE);
	if (net_rship_refresh_timeout(sk->net_rship->last_rcv_numa_node_update)) {
		struct bpf_gnet_ctx_kern ctx = {0};

		ctx.sk = sk;
		ctx.curr_tid = task_pid_nr(current);
		ctx.numa_node = cpu_to_node(ext->alloc_cpu);
		ctx.rxtx_bytes = sk->net_rship->rcv_numa_node_bytes;
		ctx.rx_dev_idx = ext->rx_dev_idx;
		ctx.rx_dev_queue_idx = skb_get_rx_queue(skb);
		ctx.rx_dev_netns_cookie = ext->rx_dev_net_cookie;
		run_gnet_bpf(GNET_RCV_NIC_NODE, &ctx);
		sk->net_rship->last_rcv_numa_node_update = jiffies;
		sk->net_rship->rcv_numa_node_bytes = 0;
	}
}

static inline void net_rship_tcp_recvmsg(struct sock *sk, struct sk_buff *skb)
{
	net_rship_tcp_local(sk, skb);
	net_rship_recv_nic_node(sk, skb);
}

static inline void net_rship_send_nic_node(struct sock *sk, struct sk_buff *skb)
{
	struct sched_net_rship_skb *ext;

	if (!gnet_bpf_enabled(GNET_SEND_NIC_NODE))
		return;

	ext = __get_skb_net_rship(skb);
	if ((ext->dev_numa_node != NUMA_NO_NODE) &&
			sk->net_rship->sk_send_tid) {
		sk->net_rship->send_numa_node_bytes += skb->len;
		if (net_rship_refresh_timeout(sk->net_rship->last_send_numa_node_update)) {
			struct bpf_gnet_ctx_kern ctx = {0};

			ctx.sk = sk;
			ctx.curr_tid = sk->net_rship->sk_send_tid;
			ctx.rxtx_bytes = sk->net_rship->send_numa_node_bytes;
			ctx.numa_node = ext->dev_numa_node;

			run_gnet_bpf(GNET_SEND_NIC_NODE, &ctx);
			sk->net_rship->send_numa_node_bytes = 0;
			sk->net_rship->last_send_numa_node_update = jiffies;
		}
	}
}

static inline void net_rship_skb_record_dev_numa_node(struct sk_buff *skb, struct net_device *dev)
{
	if (gnet_bpf_enabled(GNET_SEND_NIC_NODE)) {
		struct sched_net_rship_skb *ext = __get_skb_net_rship(skb);

		ext->dev_numa_node = dev_to_node(&dev->dev);
	}
}

static inline void net_rship_skb_record_dev_rxinfo(struct sk_buff *skb, struct net_device *dev)
{
	if (gnet_bpf_enabled(GNET_RCV_NIC_NODE)) {
		struct sched_net_rship_skb *ext = __get_skb_net_rship(skb);

		ext->rx_dev_idx = dev->ifindex;
		ext->rx_dev_net_cookie = dev_net(dev)->net_cookie;
	}
}

static inline void __net_rship_skb_clear(struct sched_net_rship_skb *ext)
{
	ext->alloc_tid = 0;
	/* dev_name_node and rx_dev_idx */
	ext->dev_numa_node = NUMA_NO_NODE;
}

static inline void net_rship_skb_clear(struct sk_buff *skb)
{
	struct sched_net_rship_skb *ext = __get_skb_net_rship(skb);

	__net_rship_skb_clear(ext);
}

static inline void __net_rship_skb_init(struct sk_buff *skb)
{
	__net_rship_skb_clear(skb->net_rship);
	skb->net_rship->alloc_cpu = raw_smp_processor_id();
}

static inline void net_rship_skb_init(struct sk_buff *skb)
{
	struct sk_buff_net_rship *rskb = (void *)skb;

	skb->net_rship = &rskb->ext;
	__net_rship_skb_init(skb);
}

static inline void net_rship_skb_init_flags(struct sk_buff *skb, int flags)
{
	if (flags & SKB_ALLOC_FCLONE) {
		struct sk_buff_fclones_net_rship *rskbs;

		rskbs = (void *)container_of(skb, struct sk_buff_fclones, skb1);
		skb->net_rship = &rskbs->ext1;
		rskbs->fclones.skb2.net_rship = &rskbs->ext2;

		__net_rship_skb_init(skb);
		__net_rship_skb_init(&rskbs->fclones.skb2);
	} else
		net_rship_skb_init(skb);
}

static inline void net_rship_skb_clone(struct sk_buff *n, struct sk_buff *skb)
{
	n->net_rship->alloc_tid = skb->net_rship->alloc_tid;
}

/* Make sure it is a process context */
static inline void net_rship_record_sendmsginfo(struct sk_buff *skb, struct sock *sk)
{
	if (gnet_bpf_enabled(GNET_TCP_RECVMSG) || gnet_bpf_enabled(GNET_RCV_NIC_NODE)) {
		struct sched_net_rship_skb *ext = __get_skb_net_rship(skb);

		ext->alloc_tid = task_pid_nr(current);
	}
	if (gnet_bpf_enabled(GNET_SK_DST_SET) || gnet_bpf_enabled(GNET_SEND_NIC_NODE))
		sk->net_rship->sk_send_tid = task_pid_nr(current);
}

#else

static inline void net_rship_sock_init(struct sock *sk, unsigned int offset)
{}

static inline void net_rship_sk_dst_set(struct sock *sk, struct dst_entry *dst)
{}

static inline void net_rship_tcp_recvmsg(struct sock *sk, struct sk_buff *skb)
{}

static inline void net_rship_send_nic_node(struct sock *sk, struct sk_buff *skb)
{}

static inline void net_rship_skb_record_rx_queue(struct sk_buff *skb, u16 rx_queue)
{}

static inline void net_rship_skb_record_dev_numa_node(struct sk_buff *skb, struct net_device *dev)
{}

static inline void net_rship_skb_record_dev_rxinfo(struct sk_buff *skb, struct net_device *dev)
{}

static inline void net_rship_skb_clear(struct sk_buff *skb)
{}

static inline void net_rship_skb_init(struct sk_buff *skb)
{}

static inline void net_rship_skb_init_flags(struct sk_buff *skb, int flags)
{}

static inline void net_rship_skb_clone(struct sk_buff *n, struct sk_buff *skb)
{}

static inline void net_rship_record_sendmsginfo(struct sk_buff *skb, struct sock *sk)
{}
#endif

#endif
