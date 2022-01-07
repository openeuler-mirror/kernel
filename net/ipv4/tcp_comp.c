// SPDX-License-Identifier: GPL-2.0-only
/*
 * TCP compression support
 *
 * Copyright(c) 2021 Huawei Technologies Co., Ltd
 */

#include <net/tcp.h>

static unsigned long tcp_compression_ports[65536 / 8];

unsigned long *sysctl_tcp_compression_ports = tcp_compression_ports;

bool tcp_syn_comp_enabled(const struct tcp_sock *tp)
{
	return true;
}

void tcp_init_compression(struct sock *sk)
{
}

void tcp_cleanup_compression(struct sock *sk)
{
}
