/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#ifndef ESWITCH_OFFLOADS_H
#define ESWITCH_OFFLOADS_H

#include "common/tc_flow.h"

void esw_offloads_disable(struct xsc_eswitch *esw);
int esw_offloads_enable(struct xsc_eswitch *esw);
int esw_offloads_start(struct xsc_eswitch *esw);
int esw_offloads_rep_load(struct xsc_eswitch *esw, u16 vport_num);
void esw_offloads_unload_rep(struct xsc_eswitch *esw, u16 vport_num);
void xsc_eswitch_register_vport_reps(struct xsc_core_device *xdev,
				     const struct xsc_eswitch_rep_ops *ops,
				     u8 rep_type);
void xsc_eswitch_unregister_vport_reps(struct xsc_core_device *xdev, u8 rep_type);
void *xsc_eswitch_get_uplink_priv(struct xsc_eswitch *esw, u8 rep_type);
void *xsc_eswitch_uplink_get_proto_dev(struct xsc_eswitch *esw, u8 rep_type);

struct xsc_flow_handle *
xsc_eswitch_add_offloaded_rule(struct xsc_eswitch *esw,
			       struct xsc_flow_spec *spec,
			       struct xsc_flow_attr *attr);
void xsc_eswitch_del_offloaded_rule(struct xsc_eswitch *esw,
				    struct xsc_flow_handle *rule,
				    struct xsc_flow_attr *attr);
void xsc_eswitch_del_fwd_rule(struct xsc_eswitch *esw,
			      struct xsc_flow_handle *rule,
			      struct xsc_flow_attr *attr);
struct xsc_flow_handle *xsc_eswitch_add_fwd_rule(struct xsc_eswitch *esw,
						 struct xsc_flow_spec *spec,
						 struct xsc_flow_attr *attr);
void *xsc_eswitch_get_proto_dev(struct xsc_eswitch *esw,
				u16 vport, u8 rep_type);

#endif /* ESWITCH_OFFLOADS_H */

