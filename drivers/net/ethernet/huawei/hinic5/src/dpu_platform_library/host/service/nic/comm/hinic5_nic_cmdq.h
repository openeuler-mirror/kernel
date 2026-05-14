/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hinic5_nic_cmdq.h
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   :
 */

#ifndef HINIC5_NIC_CMDQ_H
#define HINIC5_NIC_CMDQ_H

#include "ossl_knl.h"
#include "hinic5_hw.h"
#include "hinic5_nic.h"

#define HINIC5_Q_CTXT_MAX		31U /* (2048 - 8) / 64 */
#define HINIC5_QP_CTXT_HEADER_SIZE	16U

#define HINIC5_DEAULT_DROP_THD_ON        		(0xFFFF)

#define SQ_CTXT_PKT_DROP_THD_ON_SHIFT			0
#define SQ_CTXT_PKT_DROP_THD_OFF_SHIFT			16

#define SQ_CTXT_PKT_DROP_THD_ON_MASK			0xFFFFU
#define SQ_CTXT_PKT_DROP_THD_OFF_MASK			0xFFFFU

#define SQ_CTXT_PKT_DROP_THD_SET(val, member)		(((val) & \
					SQ_CTXT_PKT_DROP_##member##_MASK) \
					<< SQ_CTXT_PKT_DROP_##member##_SHIFT)

#define SQ_CTXT_PREF_CACHE_THRESHOLD_SHIFT		0
#define SQ_CTXT_PREF_CACHE_MAX_SHIFT			14
#define SQ_CTXT_PREF_CACHE_MIN_SHIFT			25

#define SQ_CTXT_PREF_CACHE_THRESHOLD_MASK		0x3FFFU
#define SQ_CTXT_PREF_CACHE_MAX_MASK			0x7FFU
#define SQ_CTXT_PREF_CACHE_MIN_MASK			0x7FU

#define SQ_CTXT_PREF_SET(val, member)			(((val) & \
					SQ_CTXT_PREF_##member##_MASK) \
					<< SQ_CTXT_PREF_##member##_SHIFT)

#define RQ_CTXT_PREF_CACHE_THRESHOLD_SHIFT		0
#define RQ_CTXT_PREF_CACHE_MAX_SHIFT			14
#define RQ_CTXT_PREF_CACHE_MIN_SHIFT			25

#define RQ_CTXT_PREF_CACHE_THRESHOLD_MASK		0x3FFFU
#define RQ_CTXT_PREF_CACHE_MAX_MASK			0x7FFU
#define RQ_CTXT_PREF_CACHE_MIN_MASK			0x7FU

#define RQ_CTXT_PREF_SET(val, member)			(((val) & \
					RQ_CTXT_PREF_##member##_MASK) << \
					RQ_CTXT_PREF_##member##_SHIFT)

#define RQ_CTXT_CEQ_ATTR_SET(val, member)		(((val) & \
					RQ_CTXT_CEQ_ATTR_##member##_MASK) \
					<< RQ_CTXT_CEQ_ATTR_##member##_SHIFT)

enum hinic5_qp_ctxt_type {
	HINIC5_QP_CTXT_TYPE_SQ,
	HINIC5_QP_CTXT_TYPE_RQ,
};

struct hinic5_sq_ctxt {
	u32	ci_pi;
	u32	drop_mode_sp;
	u32	wq_pfn_hi_owner;
	u32	wq_pfn_lo;

	u32	rsvd0;
	u32	pkt_drop_thd;
	u32	global_sq_id;
	u32	vlan_ceq_attr;

	u32	pref_cache;
	u32	pref_ci_owner;
	u32	pref_wq_pfn_hi_ci;
	u32	pref_wq_pfn_lo;

	u32	rsvd8;
	u32	rsvd9;
	u32	wq_block_pfn_hi;
	u32	wq_block_pfn_lo;
};

struct hinic5_rq_ctxt {
	u32	ci_pi;
	u32	ceq_attr;
	u32	wq_pfn_hi_type_owner;
	u32	wq_pfn_lo;

	u32	rsvd[3];
	u32	cqe_sge_len;

	u32	pref_cache;
	u32	pref_ci_owner;
	u32	pref_wq_pfn_hi_ci;
	u32	pref_wq_pfn_lo;

	u32	pi_paddr_hi;
	u32	pi_paddr_lo;
	u32	wq_block_pfn_hi;
	u32	wq_block_pfn_lo;
};

struct hinic5_nic_cmdq_ops {
	u8 (*prepare_cmd_buf_clean_tso_lro_space)(struct hinic5_nic_io *nic_io,
						  struct hinic5_cmd_buf *cmd_buf,
						  enum hinic5_qp_ctxt_type ctxt_type);
	u8 (*prepare_cmd_buf_qp_context_multi_store)(struct hinic5_nic_io *nic_io,
						     struct hinic5_cmd_buf *cmd_buf,
						     enum hinic5_qp_ctxt_type ctxt_type,
						     u16 start_qid, u16 max_ctxts);
	u8 (*prepare_cmd_buf_modify_svlan)(struct hinic5_cmd_buf *cmd_buf,
					   u16 func_id, u16 vlan_tag, u16 q_id, u8 vlan_mode);
	u8 (*prepare_cmd_buf_set_rss_indir_table)(const struct hinic5_nic_io *nic_io,
						  const u32 *indir_table,
						  struct hinic5_cmd_buf *cmd_buf);
	u8 (*prepare_cmd_buf_get_rss_indir_table)(const struct hinic5_nic_io *nic_io,
						  const struct hinic5_cmd_buf *cmd_buf);
	void (*cmd_buf_to_rss_indir_table)(const struct hinic5_cmd_buf *cmd_buf, u32 *indir_table);
	void (*cmd_buf_to_vport_stats)(const struct hinic5_cmd_buf *cmd_buf,
				       struct hinic5_vport_stats *stats);
	u8 (*prepare_cmd_buf_get_vport_stats)(const struct hinic5_nic_io *nic_io,
					      const struct hinic5_cmd_buf *cmd_buf, u16 func_id);
	u8 (*prepare_cmd_buf_clear_vport_stats)(const struct hinic5_nic_io *nic_io,
						const struct hinic5_cmd_buf *cmd_buf, u16 func_id);
	void (*prepare_sq_ctxt_drop_and_prefetch)(struct hinic5_sq_ctxt *sq_ctxt);
	void (*prepare_rq_ctxt_ceq_and_prefetch)(struct hinic5_io_queue *rq,
						 struct hinic5_rq_ctxt *rq_ctxt,
						 bool support_rq_sw_compact_wqe);
};

struct hinic5_nic_cmdq_ops *hinic5_nic_cmdq_get_182x_ops(void);
struct hinic5_nic_cmdq_ops *hinic5_nic_cmdq_get_187x_ops(void);

void hinic5_nic_cmdq_adapt_init(struct hinic5_nic_io *nic_io);
void hinic5_sq_prepare_ctxt(struct hinic5_nic_io *nic_io, struct hinic5_io_queue *sq, u16 sq_id,
			    struct hinic5_sq_ctxt *sq_ctxt);
void hinic5_rq_prepare_ctxt(struct hinic5_nic_io *nic_io, struct hinic5_io_queue *rq,
			    struct hinic5_rq_ctxt *rq_ctxt);
#endif
