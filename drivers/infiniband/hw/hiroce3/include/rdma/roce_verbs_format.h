/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2024 Huawei Technologies Co., Ltd */

#ifndef ROCE_VERBS_FORMAT_H
#define ROCE_VERBS_FORMAT_H

#include "roce_verbs_pub.h"
#include "roce_verbs_attr.h"


/* ********************************************************************************** */
/* * verbs struct */
struct tag_roce_uni_cmd_gid {
	struct tag_roce_verbs_cmd_header com;
	struct tag_roce_verbs_gid_attr gid_attr;
};

struct tag_roce_uni_cmd_clear_gid {
	struct tag_roce_verbs_cmd_header com;
	struct tag_roce_verbs_clear_gid_info gid_clear;
};

struct tag_roce_uni_cmd_qurey_gid {
	struct tag_roce_verbs_cmd_header com;
};

struct tag_roce_uni_cmd_flush_mpt {
	struct tag_roce_verbs_cmd_header com;
};

struct tag_roce_uni_cmd_mpt_query {
	struct tag_roce_verbs_cmd_header com;
};

struct tag_roce_uni_cmd_sw2hw_mpt {
	struct tag_roce_verbs_cmd_header com;
	/* When creating a MR/MW, you need to enter the content of the MPT Context. */
	struct tag_roce_verbs_mr_attr mr_attr;
};

struct tag_roce_uni_cmd_modify_mpt {
	struct tag_roce_verbs_cmd_header com;
	struct tag_roce_verbs_mr_sge mr_sge;
};

struct tag_roce_uni_cmd_mpt_hw2sw {
	struct tag_roce_verbs_cmd_header com;
	struct tag_roce_verbs_mtt_cacheout_info dmtt_cache;
};

struct tag_roce_uni_cmd_query_mtt {
	struct tag_roce_verbs_cmd_header com;
	struct tag_roce_verbs_query_mtt_info mtt_query;
};

struct tag_roce_uni_cmd_creat_cq {
	struct tag_roce_verbs_cmd_header com;
	struct roce_verbs_cq_attr cq_attr;
};

struct tag_roce_uni_cmd_resize_cq {
	struct tag_roce_verbs_cmd_header com;
	struct tag_roce_verbs_cq_resize_info cq_resize;
};

struct tag_roce_uni_cmd_modify_cq {
	struct tag_roce_verbs_cmd_header com;
	struct tag_roce_verbs_modify_cq_info cq_modify;
};

struct tag_roce_uni_cmd_cq_hw2sw {
	struct tag_roce_verbs_cmd_header com;
	struct tag_roce_verbs_mtt_cacheout_info cmtt_cache;
};

struct tag_roce_uni_cmd_roce_cq_query {
	struct tag_roce_verbs_cmd_header com;
};

struct tag_roce_uni_cmd_creat_srq {
	struct tag_roce_verbs_cmd_header com;
	struct tag_roce_verbs_srq_attr srq_attr;
};

struct tag_roce_uni_cmd_srq_arm {
	struct tag_roce_verbs_cmd_header com;
	union tag_roce_verbs_arm_srq_info srq_arm;
};

struct tag_roce_uni_cmd_srq_hw2sw {
	struct tag_roce_verbs_cmd_header com;
	struct tag_roce_verbs_srq_hw2sw_info srq_cache;
};

struct tag_roce_uni_cmd_srq_query {
	struct tag_roce_verbs_cmd_header com;
};

struct tag_roce_uni_cmd_modify_qpc {
	struct tag_roce_verbs_cmd_header com;
	struct tag_roce_verbs_qp_attr qp_attr;
};

struct tag_roce_uni_cmd_qp_modify2rst {
	struct tag_roce_verbs_cmd_header com;
};

struct tag_roce_uni_cmd_qp_modify_rts2sqd {
	struct tag_roce_verbs_cmd_header com;
	u32 sqd_event_en;
};

struct tag_roce_uni_cmd_qp_query {
	struct tag_roce_verbs_cmd_header com;
};

struct tag_roce_uni_cmd_qp_cache_invalid {
	struct tag_roce_verbs_cmd_header com;
	struct tag_roce_verbs_qp_hw2sw_info qp_cache;
};

struct tag_roce_uni_cmd_modify_ctx {
	struct tag_roce_verbs_cmd_header com;
	struct tag_roce_verbs_modify_ctx_info ctx_modify;
};

struct tag_roce_uni_cmd_cap_pkt {
	struct tag_roce_verbs_cmd_header com;
};


#endif /* ROCE_VERBS_FORMAT_H */
