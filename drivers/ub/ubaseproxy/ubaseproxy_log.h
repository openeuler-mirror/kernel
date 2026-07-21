/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (c) 2026 HiSilicon Technologies Co., Ltd. All rights reserved.
 *
 */

#ifndef __UBASEPROXY_LOG_H__
#define __UBASEPROXY_LOG_H__

#include <linux/dev_printk.h>
#include <linux/ratelimit_types.h>

#ifdef pr_fmt
#undef pr_fmt
#endif

#define pr_fmt(fmt) "ubaseproxy: (pid %d) " fmt, current->pid

#ifdef dev_fmt
#undef dev_fmt
#endif

#define dev_fmt(fmt) "ubaseproxy: (pid %d) " fmt, current->pid

#define ubaseproxy_dbg(udev, fmt, ...)                                         \
	do {                                                                   \
		if (ubaseproxy_dbg_log())                                      \
			dev_info((udev)->comdev.adev->dev.parent, fmt,         \
				 ##__VA_ARGS__);                               \
	} while (0)

#define ubaseproxy_err(udev, fmt, ...)                                         \
	dev_err((udev)->comdev.adev->dev.parent, fmt, ##__VA_ARGS__)

#define ubaseproxy_info(udev, fmt, ...)                                        \
	dev_info((udev)->comdev.adev->dev.parent, fmt, ##__VA_ARGS__)

#define ubaseproxy_warn(udev, fmt, ...)                                        \
	dev_warn((udev)->comdev.adev->dev.parent, fmt, ##__VA_ARGS__)

#define ubaseproxy_risk_rl(udev, ue_id, name, fmt, ...)                        \
	do {                                                                   \
		struct ubaseproxy_ue_res_info *_res =                          \
			&((udev)->ue_res_info[(ue_id) - 1]);                   \
		if (__ratelimit(&(_res->rl_state)))                            \
			ubaseproxy_err((udev), fmt, ##__VA_ARGS__);            \
		else                                                           \
			ubaseproxy_dbg((udev), fmt, ##__VA_ARGS__);            \
		(_res->risk_stats.name)++;                                     \
	} while (0)

#define UBASEPROXY_RATELIMIT_INTERVAL (60 * HZ)
#define UBASEPROXY_RATELIMIT_BURST 2

#define UBASEPROXY_RATELIMIT_INIT(udev, ue_id)                                 \
	do {                                                                   \
		struct ratelimit_state *_rs =                                  \
			&((udev)->ue_res_info[(ue_id)].rl_state);              \
		raw_spin_lock_init(&_rs->lock);                                \
		_rs->interval = UBASEPROXY_RATELIMIT_INTERVAL;                 \
		_rs->burst    = UBASEPROXY_RATELIMIT_BURST;                    \
	} while (0)

struct ubaseproxy_ue_risk_stats {
	u64 jfc_req_len;
	u64 jfc_req_tag;
	u64 jfc_ctx_fixed;
	u64 jfc_field_cnt;
	u64 jfc_field_shift;
	u64 jfc_field_cqe_coalesce_cnt;
	u64 jfc_modify_cqe_coalesce_cnt;
	u64 jfc_create_jfc_already_exists;
	u64 jfc_create_eq_inc;
	u64 jfc_destroy_jfc_not_exists;
	u64 jfc_destroy_eq_dec;
	u64 jfc_modify_jfc_not_exists;
	u64 jfc_query_jfc_not_exists;
	u64 jfc_ref_inc;
	u64 jfc_ref_dec;
	u64 jfc_mask_arm_st;
	u64 jfc_mask_cqe_coalesce_cn;
	u64 jfc_mask_cqe_coalesce_period;

	u64 jfs_req_len;
	u64 jfs_req_tag;
	u64 jfs_ctx_fixed;
	u64 jfs_field_type;
	u64 jfs_field_sqe_bb_shift;
	u64 jfs_field_state;
	u64 jfs_field_mode;
	u64 jfs_create_jetty_already_exists;
	u64 jfs_destroy_jetty_not_exists;
	u64 jfs_modify_jetty_not_exists;
	u64 jfs_modify_check_state;
	u64 jfs_query_jetty_not_exists;
	u64 jfs_bind_jetty_not_exists;
	u64 jfs_bind_not_in_jetty_mode;
	u64 jfs_bind_already_bound_group;
	u64 jfs_unbind_jetty_not_exists;
	u64 jfs_check_tx_jfc_not_exists;
	u64 jfs_check_rx_jfc_not_exists;
	u64 jfs_check_sl_not_valid;
	u64 jfs_check_jfs_seid;
	u64 jfs_check_jfr_not_exists;
	u64 jfs_check_jfr_type_not_match;
	u64 jfs_tx_jfc_ref_inc;
	u64 jfs_rx_jfc_ref_inc;
	u64 jfs_init_load_tx_jfc;
	u64 jfs_init_load_rx_jfc;
	u64 jfs_init_load_jfr_xa;
	u64 jfs_reduce_tx_jfc_dec;
	u64 jfs_reduce_rx_jfc_dec;
	u64 jfs_mask_state;

	u64 jfr_req_len;
	u64 jfr_req_tag;
	u64 jfr_ctx_fixed;
	u64 jfr_field_rqe_shift;
	u64 jfr_field_rqe_size_shift;
	u64 jfr_field_rnr_timer;
	u64 jfr_field_type;
	u64 jfr_field_cqeie;
	u64 jfr_field_state;
	u64 jfr_rqe_depth_limit;
	u64 jfr_create_jfr_already_exists;
	u64 jfr_create_jfc_not_exists;
	u64 jfr_create_jfc_inc;
	u64 jfr_destroy_jfr_not_exists;
	u64 jfr_destroy_jfc_dec;
	u64 jfr_modify_jfr_not_exists;
	u64 jfr_modify_state_ctx_mask;
	u64 jfr_modify_state_check;
	u64 jfr_modify_limit_wl_ctx_mask;
	u64 jfr_modify_limit_wl_check;
	u64 jfr_query_jfr_not_exists;

	u64 rc_req_len;
	u64 rc_req_tag;
	u64 rc_ctx_fixed;
	u64 rc_field_rce_shift;
	u64 rc_create_rc_already_exists;
	u64 rc_destroy_rc_not_exists;
	u64 rc_query_rc_not_exists;

	u64 jtg_req_len;
	u64 jtg_req_tag;
	u64 jtg_ctx_fixed;
	u64 jtg_field_start_jetty_id;
	u64 jtg_field_rsv;
	u64 jtg_field_jetty_number;
	u64 jtg_create_jtg_already_exists;
	u64 jtg_destroy_jtg_not_exists;
	u64 jtg_modify_jtg_not_exists;
	u64 jtg_query_jtg_not_exists;
	u64 jtg_check_jetty_group_valid;
	u64 jtg_check_jetty_num_mask;
	u64 jtg_check_jetty_num;
	u64 jtg_check_jtg_valid_mask;
	u64 jtg_check_jtg_valid;
	u64 jtg_bound_add;
	u64 jtg_bound_del;
	u64 jtg_del_jetty_bound;
	u64 jtg_add_jetty_bound;
	u64 jtg_evt_added_jetty;
	u64 jtg_evt_deled_jetty;

	u64 eq_req_len;
	u64 eq_req_tag;
	u64 eq_ctx_fixed;
	u64 eq_field_shift;
	u64 eq_field_eqe_coalesce_period;
	u64 eq_field_eqe_coalesce_cnt;
	u64 eq_field_eqn;
	u64 eq_create_eq_already_exists;
	u64 eq_destroy_eq_not_exists;
	u64 eq_destroy_jfc_not_empty;
	u64 eq_query_eq_not_exists;
	u64 eq_ceq_ref_dec;
	u64 eq_ceq_ref_inc;

	u64 reset_len;
	u64 mbx_opcode;
	u64 crq_msg_len;
	u64 crq_data_len;
	u64 crq_req_module;
	u64 ctx_msg_len;
	u64 ctx_ctx_type;
};

#endif /* __UBASEPROXY_LOG_H__ */
