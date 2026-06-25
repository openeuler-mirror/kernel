/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : 182x_cmdq_ops.c
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   :
 */

#include "nic_npu_cmd.h"
#include "hinic5_nic_cmdq.h"
#include "182x_cmdq_ops.h"

#define HINIC5_DEAULT_DROP_THD_OFF           0

#define WQ_PREFETCH_MAX						 4
#define WQ_PREFETCH_MIN						 1
#define WQ_PREFETCH_THRESHOLD				 256

#define RQ_CTXT_CEQ_ATTR_CI_WR_SHIFT		 0
#define RQ_CTXT_CEQ_ATTR_INTR_SHIFT			 21
#define RQ_CTXT_CEQ_ATTR_CEQ_ARM_SHIFT		 30
#define RQ_CTXT_CEQ_ATTR_EN_SHIFT			 31

#define RQ_CTXT_CEQ_ATTR_CI_WR_MASK			 0x1U
#define RQ_CTXT_CEQ_ATTR_INTR_MASK			 0x3FFU
#define RQ_CTXT_CEQ_ATTR_CEQ_ARM_MASK		 0x1U
#define RQ_CTXT_CEQ_ATTR_EN_MASK			 0x1U

static void hinic5_qp_prepare_cmdq_header(struct hinic5_qp_ctxt_header *qp_ctxt_hdr,
					  enum hinic5_qp_ctxt_type ctxt_type, u16 num_queues,
					  u16 q_id)
{
	qp_ctxt_hdr->queue_type = ctxt_type;
	qp_ctxt_hdr->num_queues = num_queues;
	qp_ctxt_hdr->start_qid = q_id;
	qp_ctxt_hdr->rsvd = 0;

	hinic5_cpu_to_be32(qp_ctxt_hdr, sizeof(*qp_ctxt_hdr));
}

static u8 prepare_cmd_buf_qp_context_multi_store(struct hinic5_nic_io *nic_io,
						 struct hinic5_cmd_buf *cmd_buf,
						 enum hinic5_qp_ctxt_type ctxt_type,
	u16 start_qid, u16 max_ctxts)
{
	struct hinic5_qp_ctxt_block *qp_ctxt_block = NULL;
	u16 i;

	qp_ctxt_block = cmd_buf->buf;

	hinic5_qp_prepare_cmdq_header(&qp_ctxt_block->cmdq_hdr, ctxt_type,
				      max_ctxts, start_qid);

	for (i = 0; i < max_ctxts; i++) {
		if (ctxt_type == HINIC5_QP_CTXT_TYPE_RQ)
			hinic5_rq_prepare_ctxt(nic_io, &nic_io->rq[start_qid + i],
					       &qp_ctxt_block->rq_ctxt[i]);
		else
			hinic5_sq_prepare_ctxt(nic_io, &nic_io->sq[start_qid + i],
					       start_qid + i, &qp_ctxt_block->sq_ctxt[i]);
	}

	return (u8)HINIC5_UCODE_CMD_MODIFY_QUEUE_CTX;
}

static u8 prepare_cmd_buf_clean_tso_lro_space(struct hinic5_nic_io *nic_io,
					      struct hinic5_cmd_buf *cmd_buf,
					      enum hinic5_qp_ctxt_type ctxt_type)
{
	struct hinic5_clean_queue_ctxt *ctxt_block = NULL;

	ctxt_block = cmd_buf->buf;
	ctxt_block->cmdq_hdr.num_queues = nic_io->max_qps;
	ctxt_block->cmdq_hdr.queue_type = ctxt_type;
	ctxt_block->cmdq_hdr.start_qid = 0;

	hinic5_cpu_to_be32(ctxt_block, sizeof(*ctxt_block));

	cmd_buf->size = sizeof(*ctxt_block);
	return (u8)HINIC5_UCODE_CMD_CLEAN_QUEUE_CONTEXT;
}

static u8 prepare_cmd_buf_set_rss_indir_table(const struct hinic5_nic_io *nic_io,
					      const u32 *indir_table,
					      struct hinic5_cmd_buf *cmd_buf)
{
	u32 i, size;
	u32 *temp = NULL;
	struct nic_rss_indirect_tbl *indir_tbl = NULL;

	indir_tbl = (struct nic_rss_indirect_tbl *)cmd_buf->buf;
	cmd_buf->size = sizeof(struct nic_rss_indirect_tbl);
	memset(indir_tbl, 0, sizeof(*indir_tbl));

	for (i = 0; i < NIC_RSS_INDIR_SIZE; i++)
		indir_tbl->entry[i] = (u16)(*(indir_table + i));
	size = sizeof(indir_tbl->entry) / sizeof(u32);
	temp = (u32 *)indir_tbl->entry;
	for (i = 0; i < size; i++)
		temp[i] = cpu_to_be32(temp[i]);

	return (u8)HINIC5_UCODE_CMD_SET_RSS_INDIR_TABLE;
}

static u8 prepare_cmd_buf_get_rss_indir_table(const struct hinic5_nic_io *nic_io,
					      const struct hinic5_cmd_buf *cmd_buf)
{
	(void)nic_io;
	memset(cmd_buf->buf, 0, cmd_buf->size);

	return (u8)HINIC5_UCODE_CMD_GET_RSS_INDIR_TABLE;
}

static void cmd_buf_to_rss_indir_table(const struct hinic5_cmd_buf *cmd_buf, u32 *indir_table)
{
	u32 i;
	u16 *indir_tbl = NULL;

	indir_tbl = (u16 *)cmd_buf->buf;
	for (i = 0; i < NIC_RSS_INDIR_SIZE; i++)
		indir_table[i] = *(indir_tbl + i);
}

static u8 prepare_cmd_buf_modify_svlan(struct hinic5_cmd_buf *cmd_buf,
				       u16 func_id, u16 vlan_tag, u16 q_id, u8 vlan_mode)
{
	struct nic_vlan_ctx *vlan_ctx = NULL;

	cmd_buf->size = sizeof(struct nic_vlan_ctx);
	vlan_ctx = (struct nic_vlan_ctx *)cmd_buf->buf;

	vlan_ctx->func_id = func_id;
	vlan_ctx->qid = q_id;
	vlan_ctx->vlan_tag = vlan_tag;
	vlan_ctx->vlan_sel = 0; /* TPID0 in IPSU */
	vlan_ctx->vlan_mode = vlan_mode;

	hinic5_cpu_to_be32(vlan_ctx, sizeof(struct nic_vlan_ctx));
	return (u8)HINIC5_UCODE_CMD_MODIFY_VLAN_CTX;
}

static u8 prepare_cmd_buf_clear_vport_stats(const struct hinic5_nic_io *nic_io,
					    const struct hinic5_cmd_buf *cmd_buf, u16 func_id)
{
	return (u8)HINIC5_UCODE_CMD_CLEAR_VPORT_STATS;
}

static u8 prepare_cmd_buf_get_vport_stats(const struct hinic5_nic_io *nic_io,
					  const struct hinic5_cmd_buf *cmd_buf, u16 func_id)
{
	(void)nic_io;
	memset(cmd_buf->buf, 0, cmd_buf->size);

	return (u8)HINIC5_UCODE_CMD_GET_VPORT_STATS;
}

static void cmd_buf_to_vport_stats(const struct hinic5_cmd_buf *cmd_buf,
				   struct hinic5_vport_stats *stats)
{
	/* Microcode cmdq command word copy,
		Later modification needs to consider hinic5_vport_stats and nic_cmdq_vport_stats differences */

	memcpy(stats, cmd_buf->buf, sizeof(struct hinic5_vport_stats));
}

static void prepare_sq_ctxt_drop_and_prefetch(struct hinic5_sq_ctxt *sq_ctxt)
{
	sq_ctxt->pkt_drop_thd =
		SQ_CTXT_PKT_DROP_THD_SET(HINIC5_DEAULT_DROP_THD_ON, THD_ON) |
		SQ_CTXT_PKT_DROP_THD_SET(HINIC5_DEAULT_DROP_THD_OFF, THD_OFF);

	sq_ctxt->pref_cache =
		SQ_CTXT_PREF_SET(WQ_PREFETCH_MIN, CACHE_MIN) |
		SQ_CTXT_PREF_SET(WQ_PREFETCH_MAX, CACHE_MAX) |
		SQ_CTXT_PREF_SET(WQ_PREFETCH_THRESHOLD, CACHE_THRESHOLD);
}

static void prepare_rq_ctxt_ceq_and_prefetch
	(struct hinic5_io_queue *rq, struct hinic5_rq_ctxt *rq_ctxt, bool support_rq_sw_compact_wqe)
{
	u16 wqe_type = rq->wqe_type;

	rq_ctxt->ceq_attr = RQ_CTXT_CEQ_ATTR_SET(0, EN) |
		RQ_CTXT_CEQ_ATTR_SET(rq->msix_entry_idx, INTR);

	if (wqe_type == HINIC5_COMPACT_RQ_WQE && support_rq_sw_compact_wqe) {
		rq_ctxt->ceq_attr |= RQ_CTXT_CEQ_ATTR_SET(1, EN);
		rq_ctxt->ceq_attr |= RQ_CTXT_CEQ_ATTR_SET(1, CI_WR);
		rq_ctxt->ceq_attr |= RQ_CTXT_CEQ_ATTR_SET(1, CEQ_ARM);
	}

	rq_ctxt->pref_cache =
		RQ_CTXT_PREF_SET(WQ_PREFETCH_MIN, CACHE_MIN) |
		RQ_CTXT_PREF_SET(WQ_PREFETCH_MAX, CACHE_MAX) |
		RQ_CTXT_PREF_SET(WQ_PREFETCH_THRESHOLD, CACHE_THRESHOLD);
}

struct hinic5_nic_cmdq_ops *hinic5_nic_cmdq_get_182x_ops(void)
{
	static struct hinic5_nic_cmdq_ops cmdq_182x_ops = {
		.prepare_cmd_buf_clean_tso_lro_space = prepare_cmd_buf_clean_tso_lro_space,
		.prepare_cmd_buf_qp_context_multi_store = prepare_cmd_buf_qp_context_multi_store,
		.prepare_cmd_buf_modify_svlan = prepare_cmd_buf_modify_svlan,
		.prepare_cmd_buf_set_rss_indir_table = prepare_cmd_buf_set_rss_indir_table,
		.prepare_cmd_buf_get_rss_indir_table = prepare_cmd_buf_get_rss_indir_table,
		.prepare_cmd_buf_get_vport_stats = prepare_cmd_buf_get_vport_stats,
		.prepare_cmd_buf_clear_vport_stats = prepare_cmd_buf_clear_vport_stats,
		.cmd_buf_to_vport_stats = cmd_buf_to_vport_stats,
		.cmd_buf_to_rss_indir_table = cmd_buf_to_rss_indir_table,
		.prepare_sq_ctxt_drop_and_prefetch = prepare_sq_ctxt_drop_and_prefetch,
		.prepare_rq_ctxt_ceq_and_prefetch = prepare_rq_ctxt_ceq_and_prefetch,
	};

	return &cmdq_182x_ops;
}
