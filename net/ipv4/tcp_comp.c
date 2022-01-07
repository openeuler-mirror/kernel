// SPDX-License-Identifier: GPL-2.0-only
/*
 * TCP compression support
 *
 * Copyright(c) 2021 Huawei Technologies Co., Ltd
 */

#include <net/tcp.h>

static unsigned long tcp_compression_ports[65536 / 8];

unsigned long *sysctl_tcp_compression_ports = tcp_compression_ports;

bool tcp_syn_comp_enabled(const struct sock *sk, bool active)
{
	struct inet_sock *inet = inet_sk(sk);
	int port;

	if (active)
		port = ntohs(inet->inet_dport);
	else
		port = ntohs(inet->inet_sport);

	return test_bit(port, sysctl_tcp_compression_ports);
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
