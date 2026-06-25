/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : 187x_cmdq_ops.c
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   :
 */

#include "hinic5_nic_cmdq.h"
#include "187x_cmdq_ops.h"

#define HINIC5_DEAULT_DROP_THD_OFF          0xFFFF

#define SQ_PREFETCH_MAX						5
#define SQ_PREFETCH_MIN						4
#define SQ_PREFETCH_THRESHOLD				48

#define RQ_PREFETCH_MAX						4
#define RQ_PREFETCH_MIN						2
#define RQ_PREFETCH_THRESHOLD				32

#define RQ_PFH_TH							7

#define RQ_CTXT_CEQ_ATTR_PFH_TH_SHIFT		0
#define RQ_CTXT_CEQ_ATTR_INTR_SHIFT			21
#define RQ_CTXT_CEQ_ATTR_EN_SHIFT			31

#define RQ_CTXT_CEQ_ATTR_PFH_TH_MASK		0x1FU
#define RQ_CTXT_CEQ_ATTR_EN_MASK			0x1U
#define RQ_CTXT_CEQ_ATTR_INTR_MASK			0x3FFU

#define HI187X_BASE_VF_QUE_ID(nic_io) (4 * (nic_io)->max_qps)

static void hinic5_qp_prepare_cmdq_header(struct hinic5_qp_ctxt_header *qp_ctxt_hdr,
					  enum hinic5_qp_ctxt_type ctxt_type, u16 num_queues,
					  u16 q_id, u16 func_id)
{
	qp_ctxt_hdr->queue_type = ctxt_type;
	qp_ctxt_hdr->num_queues = num_queues;
	qp_ctxt_hdr->start_qid = q_id;
	qp_ctxt_hdr->dest_func_id = func_id;

	hinic5_cpu_to_be32(qp_ctxt_hdr, sizeof(*qp_ctxt_hdr));
}

static u8 prepare_cmd_buf_qp_context_multi_store(struct hinic5_nic_io *nic_io,
						 struct hinic5_cmd_buf *cmd_buf,
						 enum hinic5_qp_ctxt_type ctxt_type,
	u16 start_qid, u16 max_ctxts)
{
	struct hinic5_qp_ctxt_block *qp_ctxt_block = NULL;
	u16 func_id;
	u16 i;

	qp_ctxt_block = cmd_buf->buf;
	func_id = hinic5_global_func_id(nic_io->hwdev);
	hinic5_qp_prepare_cmdq_header(&qp_ctxt_block->cmdq_hdr, ctxt_type,
				      max_ctxts, start_qid, func_id);

	for (i = 0; i < max_ctxts; i++) {
		if (ctxt_type == HINIC5_QP_CTXT_TYPE_RQ)
			hinic5_rq_prepare_ctxt(nic_io, &nic_io->rq[start_qid + i],
					       &qp_ctxt_block->rq_ctxt[i]);
		else
			hinic5_sq_prepare_ctxt(nic_io, &nic_io->sq[start_qid + i],
					       start_qid + i,
					       &qp_ctxt_block->sq_ctxt[i]);
	}

	return (u8)HINIC5_HTN_CMD_SQ_RQ_CONTEXT_MULTI_ST;
}

static u8 prepare_cmd_buf_clean_tso_lro_space(struct hinic5_nic_io *nic_io,
					      struct hinic5_cmd_buf *cmd_buf,
	enum hinic5_qp_ctxt_type ctxt_type)
{
	struct hinic5_clean_queue_ctxt *ctxt_block = NULL;

	ctxt_block = cmd_buf->buf;
	ctxt_block->cmdq_hdr.dest_func_id = hinic5_global_func_id(nic_io->hwdev);
	ctxt_block->cmdq_hdr.num_queues = nic_io->max_qps;
	ctxt_block->cmdq_hdr.queue_type = ctxt_type;
	ctxt_block->cmdq_hdr.start_qid = 0;

	hinic5_cpu_to_be32(ctxt_block, sizeof(*ctxt_block));

	cmd_buf->size = sizeof(*ctxt_block);
	return (u8)HINIC5_HTN_CMD_TSO_LRO_SPACE_CLEAN;
}

static void prepare_rss_indir_table_cmd_header(const struct hinic5_nic_io *nic_io,
					       const struct hinic5_cmd_buf *cmd_buf)
{
	struct hinic5_rss_cmd_header *header = cmd_buf->buf;

	header->dest_func_id = hinic5_global_func_id(nic_io->hwdev);
	hinic5_cpu_to_be32(header, sizeof(*header));
}

static u8 prepare_cmd_buf_set_rss_indir_table(const struct hinic5_nic_io *nic_io,
					      const u32 *indir_table,
					      struct hinic5_cmd_buf *cmd_buf)
{
	u32 i;
	u8 *indir_tbl = NULL;

	indir_tbl = (u8 *)cmd_buf->buf + sizeof(struct hinic5_rss_cmd_header);
	cmd_buf->size = sizeof(struct hinic5_rss_cmd_header) + NIC_RSS_INDIR_SIZE;
	memset(indir_tbl, 0, NIC_RSS_INDIR_SIZE);

	prepare_rss_indir_table_cmd_header(nic_io, cmd_buf);

	for (i = 0; i < NIC_RSS_INDIR_SIZE; i++)
		indir_tbl[i] = (u8)(*(indir_table + i));
	hinic5_cpu_to_be32(indir_tbl, NIC_RSS_INDIR_SIZE);

	return (u8)HINIC5_HTN_CMD_SET_RSS_INDIR_TABLE;
}

static u8 prepare_cmd_buf_get_rss_indir_table(const struct hinic5_nic_io *nic_io,
					      const struct hinic5_cmd_buf *cmd_buf)
{
	memset(cmd_buf->buf, 0, cmd_buf->size);
	prepare_rss_indir_table_cmd_header(nic_io, cmd_buf);

	return (u8)HINIC5_HTN_CMD_GET_RSS_INDIR_TABLE;
}

static void cmd_buf_to_rss_indir_table(const struct hinic5_cmd_buf *cmd_buf, u32 *indir_table)
{
	u32 i;
	u8 *indir_tbl = NULL;

	indir_tbl = (u8 *)cmd_buf->buf;
	hinic5_be32_to_cpu(cmd_buf->buf, NIC_RSS_INDIR_SIZE);
	for (i = 0; i < NIC_RSS_INDIR_SIZE; i++)
		indir_table[i] = *(indir_tbl + i);
}

static u8 prepare_cmd_buf_modify_svlan(struct hinic5_cmd_buf *cmd_buf,
				       u16 func_id, u16 vlan_tag, u16 q_id, u8 vlan_mode)
{
	struct hinic5_vlan_ctx *vlan_ctx = NULL;

	cmd_buf->size = sizeof(struct hinic5_vlan_ctx);
	vlan_ctx = (struct hinic5_vlan_ctx *)cmd_buf->buf;

	vlan_ctx->dest_func_id = func_id;
	vlan_ctx->start_qid = q_id;
	vlan_ctx->vlan_tag = vlan_tag;
	vlan_ctx->vlan_sel = 0; /* TPID0 in IPSU */
	vlan_ctx->vlan_mode = vlan_mode;

	hinic5_cpu_to_be32(vlan_ctx, sizeof(struct hinic5_vlan_ctx));
	return (u8)HINIC5_HTN_CMD_SVLAN_MODIFY;
}

static void prepare_sq_ctxt_drop_and_prefetch(struct hinic5_sq_ctxt *sq_ctxt)
{
	sq_ctxt->pkt_drop_thd =
		SQ_CTXT_PKT_DROP_THD_SET(HINIC5_DEAULT_DROP_THD_ON, THD_ON) |
		SQ_CTXT_PKT_DROP_THD_SET(HINIC5_DEAULT_DROP_THD_OFF, THD_OFF);

	sq_ctxt->pref_cache =
		SQ_CTXT_PREF_SET(SQ_PREFETCH_MIN, CACHE_MIN) |
		SQ_CTXT_PREF_SET(SQ_PREFETCH_MAX, CACHE_MAX) |
		SQ_CTXT_PREF_SET(SQ_PREFETCH_THRESHOLD, CACHE_THRESHOLD);
}

static void prepare_rq_ctxt_ceq_and_prefetch
	(struct hinic5_io_queue *rq, struct hinic5_rq_ctxt *rq_ctxt, bool support_rq_sw_compact_wqe)
{
	rq_ctxt->ceq_attr = RQ_CTXT_CEQ_ATTR_SET(0, EN) |
		RQ_CTXT_CEQ_ATTR_SET(RQ_PFH_TH, PFH_TH) |
		RQ_CTXT_CEQ_ATTR_SET(rq->msix_entry_idx, INTR);

	rq_ctxt->pref_cache =
		RQ_CTXT_PREF_SET(RQ_PREFETCH_MIN, CACHE_MIN) |
		RQ_CTXT_PREF_SET(RQ_PREFETCH_MAX, CACHE_MAX) |
		RQ_CTXT_PREF_SET(RQ_PREFETCH_THRESHOLD, CACHE_THRESHOLD);
}

struct hinic5_nic_cmdq_ops *hinic5_nic_cmdq_get_187x_ops(void)
{
	static struct hinic5_nic_cmdq_ops cmdq_187x_ops = {
		.prepare_cmd_buf_clean_tso_lro_space = prepare_cmd_buf_clean_tso_lro_space,
		.prepare_cmd_buf_qp_context_multi_store = prepare_cmd_buf_qp_context_multi_store,
		.prepare_cmd_buf_modify_svlan = prepare_cmd_buf_modify_svlan,
		.prepare_cmd_buf_set_rss_indir_table = prepare_cmd_buf_set_rss_indir_table,
		.prepare_cmd_buf_get_rss_indir_table = prepare_cmd_buf_get_rss_indir_table,
		.cmd_buf_to_rss_indir_table = cmd_buf_to_rss_indir_table,
		.prepare_sq_ctxt_drop_and_prefetch = prepare_sq_ctxt_drop_and_prefetch,
		.prepare_rq_ctxt_ceq_and_prefetch = prepare_rq_ctxt_ceq_and_prefetch,
	};

	return &cmdq_187x_ops;
}
