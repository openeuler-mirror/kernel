/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#ifndef __POST_ACT_H__
#define __POST_ACT_H__

#include "common/xsc_fs.h"
#include "common/xsc_core.h"

struct xsc_flow_attr;
struct xsc_adapter;
struct xsc_tc_mod_hdr_acts;
struct xsc_fs_chains;
enum xsc_flow_namespace_type;

struct xsc_post_act *xsc_tc_post_act_init(struct xsc_adapter *adapter,
					  struct xsc_fs_chains *chains,
					  enum xsc_flow_namespace_type ns_type);

void xsc_tc_post_act_destroy(struct xsc_post_act *post_act);

struct xsc_post_act_handle *xsc_tc_post_act_add(struct xsc_post_act *post_act,
						struct xsc_flow_attr *post_attr);

void xsc_tc_post_act_del(struct xsc_post_act *post_act,
			 struct xsc_post_act_handle *handle);

int xsc_tc_post_act_offload(struct xsc_post_act *post_act,
			    struct xsc_post_act_handle *handle);

void xsc_tc_post_act_unoffload(struct xsc_post_act *post_act,
			       struct xsc_post_act_handle *handle);

struct xsc_flow_table *xsc_tc_post_act_get_ft(struct xsc_post_act *post_act);

int xsc_tc_post_act_set_handle(struct xsc_core_device *dev,
			       struct xsc_post_act_handle *handle,
			       struct xsc_tc_mod_hdr_acts *acts);

#endif /* __POST_ACT_H__ */
