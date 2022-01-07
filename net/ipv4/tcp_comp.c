// SPDX-License-Identifier: GPL-2.0-only
/*
 * TCP compression support
 *
 * Copyright(c) 2021 Huawei Technologies Co., Ltd
 */

#include <net/tcp.h>

static unsigned long tcp_compression_ports[65536 / 8];

unsigned long *sysctl_tcp_compression_ports = tcp_compression_ports;
int sysctl_tcp_compression_local __read_mostly;

static struct proto tcp_prot_override;

struct tcp_comp_context {
	struct proto *sk_proto;
	struct rcu_head rcu;
};

static bool tcp_comp_enabled(__be32 saddr, __be32 daddr, int port)
{
	if (!sysctl_tcp_compression_local &&
	    (saddr == daddr || ipv4_is_loopback(daddr)))
		return false;

	return test_bit(port, sysctl_tcp_compression_ports);
}

bool tcp_syn_comp_enabled(const struct sock *sk)
{
	struct inet_sock *inet = inet_sk(sk);

	return tcp_comp_enabled(inet->inet_saddr, inet->inet_daddr,
				ntohs(inet->inet_dport));
}

bool tcp_synack_comp_enabled(const struct sock *sk,
			     const struct inet_request_sock *ireq)
{
	struct inet_sock *inet = inet_sk(sk);

	if (!ireq->comp_ok)
		return false;

	return tcp_comp_enabled(ireq->ir_loc_addr, ireq->ir_rmt_addr,
				ntohs(inet->inet_sport));
}

static struct tcp_comp_context *comp_get_ctx(const struct sock *sk)
{
	struct inet_connection_sock *icsk = inet_csk(sk);

	return (__force void *)icsk->icsk_ulp_data;
}

static int tcp_comp_sendmsg(struct sock *sk, struct msghdr *msg, size_t size)
{
	struct tcp_comp_context *ctx = comp_get_ctx(sk);

	return ctx->sk_proto->sendmsg(sk, msg, size);
}

static int tcp_comp_recvmsg(struct sock *sk, struct msghdr *msg, size_t len,
			    int nonblock, int flags, int *addr_len)
{
	struct tcp_comp_context *ctx = comp_get_ctx(sk);

	return ctx->sk_proto->recvmsg(sk, msg, len, nonblock, flags, addr_len);
}

void tcp_init_compression(struct sock *sk)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct tcp_comp_context *ctx = NULL;
	struct tcp_sock *tp = tcp_sk(sk);

	if (!tp->rx_opt.comp_ok)
		return;

	ctx = kzalloc(sizeof(*ctx), GFP_ATOMIC);
	if (!ctx)
		return;

	ctx->sk_proto = sk->sk_prot;
	WRITE_ONCE(sk->sk_prot, &tcp_prot_override);

	rcu_assign_pointer(icsk->icsk_ulp_data, ctx);

	sock_set_flag(sk, SOCK_COMP);
}

static void tcp_comp_context_free(struct rcu_head *head)
{
	struct tcp_comp_context *ctx;

	ctx = container_of(head, struct tcp_comp_context, rcu);

	kfree(ctx);
}

void tcp_cleanup_compression(struct sock *sk)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct tcp_comp_context *ctx = comp_get_ctx(sk);

	if (!ctx || !sock_flag(sk, SOCK_COMP))
		return;

	rcu_assign_pointer(icsk->icsk_ulp_data, NULL);
	call_rcu(&ctx->rcu, tcp_comp_context_free);
}

int tcp_comp_init(void)
{
	tcp_prot_override = tcp_prot;
	tcp_prot_override.sendmsg = tcp_comp_sendmsg;
	tcp_prot_override.recvmsg = tcp_comp_recvmsg;

	return 0;
}
