/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2024 Huawei Technologies Co., Ltd */

#ifndef ROCE_SYSFS_H
#define ROCE_SYSFS_H

#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/device.h>
#include <linux/netdevice.h>
#include <linux/kobject.h>

#define ROCE_MIN_QPN 2
#define BYTE_TO_BIT 8

#define PRI_ARRAY_LEN 8

#define ROCE_MAX_PORT_CNT 8

#define HRN0_K_MAGIC_NUM_3_SYSFS 3
#define HRN0_K_MAGIC_NUM_7_SYSFS 7
#define HRN0_K_MAGIC_NUM_8_SYSFS 8
#define HRN0_K_MAGIC_NUM_M_SYSFS 1000000

struct roce3_prio_enable_ctx {
	struct kobj_attribute enable;
	void *ecn_enable_ctx;
	u32 prio_en;
	u32 prio;
};
struct roce3_ip_prio_enable_ctx {
	struct kobj_attribute ip_enable;
	void *ecn_ip_enable_ctx;
	u32 prio_en;
	u32 prio;
};

struct roce3_ecn_ip_enable_ctx {
	struct kobject *ip_enable_root;
	struct roce3_ip_prio_enable_ctx ip_prio_enable[PRI_ARRAY_LEN];
};

struct roce3_ecn_enable_ctx {
	struct kobject *enable_root;
	struct roce3_prio_enable_ctx prio_enable[PRI_ARRAY_LEN];
	u32 np_rp;
};

struct roce3_dfx_qpc_ctx {
	struct kobj_attribute kattr;
};

struct roce3_dfx_cqc_ctx {
	struct kobj_attribute kattr;
};

struct roce3_dfx_srqc_ctx {
	struct kobj_attribute kattr;
};

struct roce3_dfx_ctx {
	struct kobject *dfx_root;
	struct roce3_dfx_qpc_ctx qpc_ctx;
	struct roce3_dfx_cqc_ctx cqc_ctx;
	struct roce3_dfx_srqc_ctx srqc_ctx;
};

struct roce3_ecn_rp_ctx {
	struct kobject ecn_rp_root;
	u32 alpha_dec_period;
	u32 rate_dec_period;
	u32 rate_inc_period;
	u32 alpha_threshold;
	u32 cnp_cnt_threshold;
	u32 factor_gita;
	u32 initial_alpha;
	u32 rate_inc_ai;
	u32 rate_inc_hai;
	u32 rate_first_set;
	u32 rate_target_clamp;
	u32 token_period;
	u32 min_rate;
	struct roce3_ecn_enable_ctx enable_ctx;
};

struct roce3_ecn_np_ctx {
	struct kobject ecn_np_root;
	u32 min_cnp_period;
	u32 quick_adjust_en;
	u32 port_mode;
	u32 cnp_prio_enable;
	u32 cnp_prio;
	struct roce3_ecn_enable_ctx enable_ctx;
};

struct roce3_ecn_ctx {
	struct kobject ecn_root;
	struct mutex ecn_mutex;
	u32 ecn_ver;
	u32 cc_algo;
	struct roce3_ecn_np_ctx np_ctx;
	struct roce3_ecn_rp_ctx rp_ctx;
	struct roce3_ecn_ip_enable_ctx ip_enable_ctx;
};

int roce3_update_ecn_param(const struct roce3_ecn_ctx *ecn_ctx);

#endif // ROCE_SYSFS_H
