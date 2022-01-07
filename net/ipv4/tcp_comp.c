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

void tcp_init_compression(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);

	if (!tp->rx_opt.comp_ok)
		return;

	sock_set_flag(sk, SOCK_COMP);
}

void tcp_cleanup_compression(struct sock *sk)
{
}
