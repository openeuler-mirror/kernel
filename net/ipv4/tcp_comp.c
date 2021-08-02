// SPDX-License-Identifier: GPL-2.0-only
/*
 * TCP compression support
 *
 * Copyright(c) 2021 Huawei Technologies Co., Ltd
 */

#include <net/tcp.h>

bool tcp_syn_comp_enabled(const struct tcp_sock *tp)
{
	return true;
}
