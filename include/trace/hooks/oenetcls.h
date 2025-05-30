/* SPDX-License-Identifier: GPL-2.0 */
/*
 * oenetcls driver Hooks
 *
 * Copyright (c) 2025, Huawei Tech. Co., Ltd.
 */

#ifdef CONFIG_OENETCLS_HOOKS

#undef TRACE_SYSTEM
#define TRACE_SYSTEM oenetcls

#define TRACE_INCLUDE_PATH trace/hooks
#if !defined(_TRACE_OENETCLS_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_OENETCLS_H
#include <linux/tracepoint.h>
#include <trace/hooks/vendor_hooks.h>

struct sock;
struct sk_buff;
struct net_device;

DECLARE_HOOK(oecls_flow_update,
TP_PROTO(struct sock *sk),
TP_ARGS(sk));

DECLARE_HOOK(oecls_set_cpu,
TP_PROTO(struct sk_buff *skb),
TP_ARGS(skb));

DECLARE_HOOK(oecls_timeout,
TP_PROTO(struct net_device *dev, u16 rxq_index, u32 flow_id, u16 filter_id, bool *ret),
TP_ARGS(dev, rxq_index, flow_id, filter_id, ret));

DECLARE_HOOK(ethtool_cfg_rxcls,
TP_PROTO(struct sock *sk, int is_del),
TP_ARGS(sk, is_del));

#endif
/* This part must be outside protection */
#include <trace/define_trace.h>

#endif

