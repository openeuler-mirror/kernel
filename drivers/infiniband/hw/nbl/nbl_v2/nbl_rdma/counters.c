// SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB
/* Copyright (c) 2021, NEBULARMATRIX */
#include <linux/fs.h>
#include <linux/debugfs.h>
#include <linux/list.h>
#include <linux/time.h>
#include "counters.h"
#include "qp.h"
#include "grc.h"
#include "mem.h"

static const struct rdma_stat_desc nbl_hw_counters_names[] = {
	{"packet_seq_err", 0, NULL},
	{"out_of_sequence", 0, NULL},
	{"np_cnp_sent", 0, NULL},
	{"rp_cnp_handled", 0, NULL},
	{"roce_retrans", 0, NULL},
	{"np_ecn_marked_roce_packets", 0, NULL},
};

int get_hw_status_v2(struct nbl_pci_f *rf, u32 *status)
{
	rf->hw.hw_ops->get_hw_stat_status(&rf->hw, status);
	nbl_pr_dbg("op_info:0x%x, op_st:%lld, waining:%lld\r\n", *status,
		RS_32(*status, NBL_STATS_OP_STATUS), RS_32(*status, NBL_STATS_OP_ERR_WARN));

	return RS_32(*status, NBL_STATS_OP_STATUS);
}

int nbl_grc_hw_stat_read_v2(struct nbl_pci_f *rf, struct nbl_stats_reg_info *reg_info)
{
	u32 op_info = reg_info->op_info.data;
	u32 pa_l = U64_LO(reg_info->mem->pa);
	u32 pa_h = U64_HI(reg_info->mem->pa);
	u16 func_id = rf->sc_dev.function_id;
	u32 before_cnt = 0;
	u32 after_cnt = 0;
	unsigned long flags;
	u32 status = 0;

	while (1) {
		spin_lock_irqsave(&rf->hw_stat_lock, flags);
		if (get_hw_status_v2(rf, &status) == 0)
			break;

		spin_unlock_irqrestore(&rf->hw_stat_lock, flags);
		if (before_cnt >= NBL_MAX_TRY_DUMP_CNT) {
			nbl_dev_err(&rf->pcidev->dev, "HW is busy, please try again later.\n");
			nbl_pr_err("busy before read! op_info:0x%x, func_id:%d\r\n",
				status, func_id);
			nbl_pr_err("read pa_l:0x%x, pa_h:0x%x, status:%d, rc:%d\n",
				pa_l, pa_h,
				reg_info->op_info.v2.op_status, reg_info->op_info.v2.op_rc);
			nbl_pr_err("table_sel:%d, id:%d, len:%d, start:%d\n",
				reg_info->op_info.v2.op_table_sel, reg_info->op_info.v2.op_id,
				reg_info->op_info.v2.op_len, reg_info->op_info.v2.op_addr_sel);
			return -EBUSY;
		}
		before_cnt++;
		udelay(NBL_STATS_RETRY_WAIT * 1000);
	}

	rf->hw.hw_ops->get_hw_stat(&rf->hw, op_info, pa_l, pa_h, func_id);
	spin_unlock_irqrestore(&rf->hw_stat_lock, flags);

	while (1) {
		udelay(NBL_STATS_RETRY_WAIT * 1000);
		spin_lock_irqsave(&rf->hw_stat_lock, flags);
		if (get_hw_status_v2(rf, &status) == 0)
			break;

		spin_unlock_irqrestore(&rf->hw_stat_lock, flags);

		if (after_cnt >= NBL_MAX_TRY_DUMP_CNT) {
			nbl_dev_err(&rf->pcidev->dev, "HW is busy, please try again later.\n");
			nbl_pr_err("busy after read! op_info:0x%x, func_id:%d\r\n",
				status, func_id);
			nbl_pr_err("read pa_l:0x%x, pa_h:0x%x, status:%d, rc:%d\n",
				pa_l, pa_h,
				reg_info->op_info.v2.op_status, reg_info->op_info.v2.op_rc);
			nbl_pr_err("table_sel:%d, id:%d, len:%d, start:%d\n",
				reg_info->op_info.v2.op_table_sel, reg_info->op_info.v2.op_id,
				reg_info->op_info.v2.op_len, reg_info->op_info.v2.op_addr_sel);
			return -EBUSY;
		}
		after_cnt++;
	}
	spin_unlock_irqrestore(&rf->hw_stat_lock, flags);

	return 0;
}

int nbl_grc_hw_stat_clear_v2(struct nbl_pci_f *rf, struct nbl_stats_reg_info *reg_info)
{
	u32 op_info = reg_info->op_info.data;
	u32 cnt = 0;
	unsigned long flags;
	u32 status = 0;

	while (1) {
		spin_lock_irqsave(&rf->hw_stat_lock, flags);
		if (get_hw_status_v2(rf, &status) == 0)
			break;

		if (cnt >= NBL_MAX_TRY_DUMP_CNT) {
			nbl_dev_err(&rf->pcidev->dev, "clear has try cnt:%d op_info:0x%x.\n",
				cnt, op_info);
			spin_unlock_irqrestore(&rf->hw_stat_lock, flags);
			return -EBUSY;
		}
		cnt++;
		spin_unlock_irqrestore(&rf->hw_stat_lock, flags);
		udelay(NBL_STATS_RETRY_WAIT * 1000);
	}

	rf->hw.hw_ops->set_hw_stat(&rf->hw, op_info);
	spin_unlock_irqrestore(&rf->hw_stat_lock, flags);

	return 0;
}

int nbl_grc_hw_stat_errcode_enable_v2(struct nbl_pci_f *rf, bool enable)
{
	u32 cnt = 0;
	unsigned long flags;
	u32 status = 0;

	while (1) {
		spin_lock_irqsave(&rf->hw_stat_lock, flags);
		if (get_hw_status_v2(rf, &status) == 0)
			break;

		if (cnt >= NBL_MAX_TRY_DUMP_CNT) {
			nbl_dev_err(&rf->pcidev->dev, "errop_en has try cnt:%d.\n", cnt);
			spin_unlock_irqrestore(&rf->hw_stat_lock, flags);
			return -EBUSY;
		}
		cnt++;
		spin_unlock_irqrestore(&rf->hw_stat_lock, flags);
		udelay(NBL_STATS_RETRY_WAIT * 1000);
	}

	rf->hw.hw_ops->enable_errcode_hw_stat(&rf->hw, (u32)enable);
	spin_unlock_irqrestore(&rf->hw_stat_lock, flags);

	return 0;
}


static int nbl_grc_exec_wait(struct nbl_pci_f *rf, void *in, int in_size,
		void *out, int out_size)
{
	int cnt = 0;
	int ret = 0;

	while (cnt < NBL_MAX_TRY_DUMP_CNT) {
		ret = nbl_exec_cmd(rf, in, in_size, out, out_size);
		if (ret == 0)
			break;
		else if (ret != EBUSY && ret != -EAGAIN)
			break;
		cnt++;
		msleep(NBL_STATS_RETRY_WAIT);
	}

	return ret;
}

static int nbl_grc_hw_stat_read(struct nbl_pci_f *rf, struct nbl_stats_reg_info *reg_info)
{
	u16 function_id = rf->sc_dev.function_id;
	u32 pa_l = U64_LO(reg_info->mem->pa);
	u32 pa_h = U64_HI(reg_info->mem->pa);
	u32 op_info = reg_info->op_info.data;
	uint8_t in[64];
	uint8_t out[64];
	int data_len = 0;
	int ret;
	struct grc_cache_msg_header *head;

	nbl_pr_dbg("read op_info:0x%x, pa_l:0x%x, pa_h:0x%x, status:%d, rc:%d\n",
		op_info, pa_l, pa_h, reg_info->op_info.v2.op_status, reg_info->op_info.v2.op_rc);
	nbl_pr_dbg("table_sel:%d, id:%d, len:%d, start:%d, function_id:%d\n",
		reg_info->op_info.v2.op_table_sel, reg_info->op_info.v2.op_id,
		reg_info->op_info.v2.op_len, reg_info->op_info.v2.op_addr_sel, function_id);

	if (rf->dev_ops && rf->dev_ops->stat_read) {
		ret = rf->dev_ops->stat_read(rf, reg_info);
		msleep(NBL_STATS_WAIT_DMA);
		return ret;
	}

	/* nbl_grc_exec IN: pa_l + pa_h + op_info OUT:ret */
	head = (struct grc_cache_msg_header *)in;
	head->op_code = GRC_MSG_OP_HW_STAT_GET;
	head->payload_len = sizeof(op_info) + sizeof(pa_l) + sizeof(pa_h) +
						sizeof(function_id);
	data_len += sizeof(struct grc_cache_msg_header);

	memcpy(in + data_len, &op_info, sizeof(op_info));
	data_len += sizeof(op_info);

	memcpy(in + data_len, &pa_l, sizeof(pa_l));
	data_len += sizeof(pa_l);

	memcpy(in + data_len, &pa_h, sizeof(pa_h));
	data_len += sizeof(pa_h);

	memcpy(in + data_len, &function_id, sizeof(function_id));
	data_len += sizeof(function_id);

	ret = nbl_grc_exec_wait(rf, in, data_len, out, sizeof(out));
	if (ret == EBUSY || ret == -EAGAIN)
		nbl_pr_err("HW is busy, please try again later\n");
	else if (ret != 0)
		nbl_pr_err("read hw stat cmd err=%d\n", ret);

	msleep(NBL_STATS_WAIT_DMA);

	return ret;
}

void nbl_stats_mem_clear(struct nbl_device *nbl_dev, struct nbl_stats_reg_info *reg_info)
{
	int table_id = reg_info->op_info.v2.op_id;
	int table_type = reg_info->op_info.v2.op_table_sel;
	unsigned long flags;

	nbl_pr_dbg("clear sw stats table:%d, id:%d\n", table_type, table_id);
	switch (table_type) {
	case NBL_VF_TABLE:
		spin_lock_irqsave(&nbl_dev->func_stat->stat_mem_lock, flags);
		memset(nbl_dev->func_stat->vf_mem, 0,
			sizeof(nbl_dev->func_stat->vf_mem));
		spin_unlock_irqrestore(&nbl_dev->func_stat->stat_mem_lock, flags);
		break;
	case NBL_STATS_ID_TABLE:
		spin_lock_irqsave(&nbl_dev->func_stat->stat_mem_lock, flags);
		memset(nbl_dev->func_stat->stat_id_mem[table_id], 0,
			sizeof(nbl_dev->func_stat->stat_id_mem[table_id]));
		spin_unlock_irqrestore(&nbl_dev->func_stat->stat_mem_lock, flags);
		break;
	case NBL_CLEAR_ALL:
		spin_lock_irqsave(&nbl_dev->func_stat->stat_mem_lock, flags);
		memset(nbl_dev->func_stat->vf_mem, 0,
			sizeof(nbl_dev->func_stat->vf_mem));
		memset(nbl_dev->func_stat->stat_id_mem, 0,
			sizeof(nbl_dev->func_stat->stat_id_mem));
		spin_unlock_irqrestore(&nbl_dev->func_stat->stat_mem_lock, flags);
		msleep(NBL_STATS_WAIT_DMA);
		break;
	default:
		nbl_pr_err("clear sw stats table error.\n");
		break;
	}
}

static inline u64 nbl_stats_delta(u64 new_val, u64 old_val, u64 max_val)
{
	new_val = (new_val & max_val);
	return (new_val >= old_val) ? (new_val - old_val) :
				      (max_val - old_val + new_val + 1);
}

static void nbl_stats_mem_update(struct nbl_device *nbl_dev, struct nbl_stats_reg_info *reg_info)
{
	int i;
	int start;
	int cnt;
	int table_id = reg_info->op_info.v2.op_id;
	int table_type = reg_info->op_info.v2.op_table_sel;
	struct nbl_stats_info *table;
	u64 max_val = NBL_MAX_STATS_60;
	u64 *va = (u64 *)reg_info->mem->va;
	unsigned long flags;
	u64 cur_val = 0;

	start = reg_info->op_info.v2.op_addr_sel;
	cnt = reg_info->op_info.v2.op_len;

	nbl_pr_dbg("update stats table:%d, id:%d, start:%d, va:0x%p, pa:0x%llx\n",
		table_type, table_id, start, va, (u64)reg_info->mem->pa);

	table = nbl_dev->func_stat->stat_id_mem[table_id];
	switch (table_type) {
	case NBL_VF_TABLE:
		table = nbl_dev->func_stat->vf_mem;
		fallthrough;
	case NBL_STATS_ID_TABLE:
		spin_lock_irqsave(&nbl_dev->func_stat->stat_mem_lock, flags);
		for (i = 0; i < cnt; i++) {
			cur_val = be64_to_cpu(va[i]);
			if (cur_val & NBL_STATS_VLD)
				cur_val &= max_val;
			else {
				nbl_pr_notice("stat[%d]:%llx Hw not write ready\r\n",
					i+start, cur_val);
				continue;
			}

			if (cur_val || table[i+start].last_stats)
				nbl_pr_dbg("%d:%llx\n", i+start, cur_val);
			table[i+start].total_stats += nbl_stats_delta(
				cur_val, table[i+start].last_stats, max_val);
			table[i+start].last_stats = (cur_val & max_val);
		}
		spin_unlock_irqrestore(&nbl_dev->func_stat->stat_mem_lock, flags);
		break;
	default:
		break;
	}

}

int update_vf_stats(struct nbl_device *nbl_dev)
{
	struct nbl_pci_f *rf = nbl_dev->rf;
	struct nbl_stats_reg_info reg_info = {};
	int ret;
	u16 func_id = rf->sc_dev.function_id;

	/* 1.gather statistics */
	reg_info.op_info.v2.op_status = 1;
	reg_info.op_info.v2.op_rc = OP_STATS_READ;
	reg_info.op_info.v2.op_table_sel = NBL_VF_TABLE;
	reg_info.op_info.v2.op_id = func_id;
	reg_info.op_info.v2.op_len = NBL_VF_CNTS;
	memset(nbl_dev->func_stat->dma_vf_mem.va, 0, nbl_dev->func_stat->dma_vf_mem.size);
	reg_info.mem = &nbl_dev->func_stat->dma_vf_mem;
	ret = nbl_grc_hw_stat_read(rf, &reg_info);
	if (ret)
		return ret;

	/* 2.update stat memory */
	nbl_stats_mem_update(nbl_dev, &reg_info);

	return ret;
}

static int update_qp_opcode_stats(struct nbl_device *nbl_dev, int stat_id)
{
	struct nbl_pci_f *rf = nbl_dev->rf;
	struct nbl_stats_reg_info reg_info = {};
	int ret;
	int i;
	int cnt = rf->product->stats->opcode_count / NBL_DUMP_STATS_MAX_CNT;

	reg_info.op_info.v2.op_status = 1;
	reg_info.op_info.v2.op_rc = OP_STATS_READ;
	reg_info.op_info.v2.op_table_sel = NBL_STATS_ID_TABLE;
	reg_info.op_info.v2.op_id = stat_id;
	for (i = 0; i < cnt; i++) {
		reg_info.op_info.v2.op_len = NBL_DUMP_STATS_MAX_CNT;
		reg_info.op_info.v2.op_addr_sel = i * NBL_DUMP_STATS_MAX_CNT;

		memset(nbl_dev->func_stat->dma_stat_id_mem[stat_id][i].va, 0,
			nbl_dev->func_stat->dma_stat_id_mem[stat_id][i].size);
		reg_info.mem = &nbl_dev->func_stat->dma_stat_id_mem[stat_id][i];
		ret = nbl_grc_hw_stat_read(rf, &reg_info);
		if (ret)
			return ret;

		nbl_stats_mem_update(nbl_dev, &reg_info);
	}

	return ret;
}

static int update_qp_errorcode_stats(struct nbl_device *nbl_dev, int stat_id)
{
	struct nbl_pci_f *rf = nbl_dev->rf;
	struct nbl_stats_reg_info reg_info = {};
	int opcode_cnt = rf->product->stats->opcode_count;
	int errcode_cnt = rf->product->stats->error_count;
	int cnt = errcode_cnt / NBL_DUMP_STATS_MAX_CNT;
	int ret, start, i, err_dma_cnt;

	reg_info.op_info.v2.op_status = 1;
	reg_info.op_info.v2.op_rc = OP_STATS_READ;
	reg_info.op_info.v2.op_table_sel = NBL_STATS_ID_TABLE;
	reg_info.op_info.v2.op_id = stat_id;
	for (i = 0; i < cnt; i++) {
		start = opcode_cnt + i * NBL_DUMP_STATS_MAX_CNT;
		reg_info.op_info.v2.op_len = NBL_DUMP_STATS_MAX_CNT;
		reg_info.op_info.v2.op_addr_sel = start;

		err_dma_cnt = i + NBL_ERRCODE_DMA_START_CNT;
		memset(nbl_dev->func_stat->dma_stat_id_mem[stat_id][err_dma_cnt].va, 0,
			nbl_dev->func_stat->dma_stat_id_mem[stat_id][err_dma_cnt].size);
		reg_info.mem = &nbl_dev->func_stat->dma_stat_id_mem[stat_id][err_dma_cnt];
		ret = nbl_grc_hw_stat_read(rf, &reg_info);
		if (ret)
			return ret;

		nbl_stats_mem_update(nbl_dev, &reg_info);
	}

	return ret;
}

int update_qp_stats(struct nbl_device *nbl_dev, int stat_id)
{
	int ret;

	ret = update_qp_opcode_stats(nbl_dev, stat_id);
	if (ret)
		return ret;

	ret = update_qp_errorcode_stats(nbl_dev, stat_id);

	return ret;
}

int update_all_stats(struct nbl_device *nbl_dev)
{
	int i, ret, stat_group_num;

	ret = update_vf_stats(nbl_dev);
	if (ret)
		return ret;

	stat_group_num = nbl_dev->rf->product->stats->group_count;
	for (i = NBL_STATS_GROUP_START_NUM; i < stat_group_num; i++) {
		ret = update_qp_stats(nbl_dev, i);
		if (ret)
			return ret;
	}

	return ret;
}

int grc_stat_clear(struct nbl_pci_f *rf, struct nbl_stats_reg_info *reg_info)
{
	u32 op_info = 0;
	uint8_t in[64];
	uint8_t out[64];
	int data_len = 0;
	int ret;
	struct grc_cache_msg_header *head;

	if (rf->dev_ops && rf->dev_ops->stat_clear)
		return rf->dev_ops->stat_clear(rf, reg_info);

	op_info = reg_info->op_info.data;

	/* nbl_grc_exec IN:op_info */
	head = (struct grc_cache_msg_header *)in;
	head->op_code = GRC_MSG_OP_HW_STAT_CLEAR;
	head->payload_len = sizeof(op_info);
	data_len += sizeof(struct grc_cache_msg_header);

	memcpy(in + data_len, &op_info, sizeof(op_info));
	data_len += sizeof(op_info);

	ret = nbl_grc_exec_wait(rf, in, data_len, out, sizeof(out));
	if (ret == EBUSY || ret == -EAGAIN)
		nbl_pr_err("HW is busy, please try again later\n");
	else if (ret != 0)
		nbl_pr_err("clear hw stat cmd err=%d\n", ret);

	return ret;
}

int grc_stat_errcode_enable(struct nbl_pci_f *rf, bool enable)
{
	uint8_t in[64];
	uint8_t out[64];
	int data_len = 0;
	int ret;
	struct grc_cache_msg_header *head;

	if (rf->dev_ops && rf->dev_ops->hw_stat_errcode_enable)
		return rf->dev_ops->hw_stat_errcode_enable(rf, enable);

	/* nbl_grc_exec IN:op_info */
	head = (struct grc_cache_msg_header *)in;
	head->op_code = GRC_MSG_OP_ERRCODE_EN;
	head->payload_len = sizeof(enable);
	data_len += sizeof(struct grc_cache_msg_header);

	memcpy(in + data_len, &enable, sizeof(enable));
	data_len += sizeof(enable);

	ret = nbl_grc_exec_wait(rf, in, data_len, out, sizeof(out));
	if (ret == EBUSY || ret == -EAGAIN)
		nbl_pr_err("HW is busy, please try again later\n");
	else if (ret != 0)
		nbl_pr_err("enable hw errcode statistics cmd err=%d\n", ret);

	return ret;
}

/**
 * nbl_alloc_hw_stats - Allocate a hw stats structure
 * @ibdev: device pointer from stack
 * @port_num: port number
 */
struct rdma_hw_stats *nbl_alloc_hw_stats(struct ib_device *ibdev, u32 port_num)
{
	int num_counters = NBL_HW_COUNTERS_CNT;
	unsigned long lifespan = RDMA_HW_STATS_DEFAULT_LIFESPAN;

	return rdma_alloc_hw_stats_struct(nbl_hw_counters_names, num_counters,
					  lifespan);
}

/**
 * nbl_get_hw_stats - Populates the rdma_hw_stats structure
 * @ibdev: device pointer from stack
 * @stats: stats pointer from stack
 * @port_num: port number
 * @index: which hw counter the stack is requesting we update
 */
int nbl_get_hw_stats(struct ib_device *ibdev, struct rdma_hw_stats *stats,
			u32 port_num, int index)
{
	struct nbl_device *nbl_dev = to_nbl_dev(ibdev);
	u8 stat_id = nbl_dev->rf->sc_dev.stat_id;
	struct nbl_rdma_stat *func_stat = nbl_dev->func_stat;
	int ret;
	int stat_id_max = nbl_dev->rf->product->stats->group_count;
	int opcode_cnt = nbl_dev->rf->product->stats->opcode_count;

	if (stat_id < NBL_STATS_GROUP_START_NUM || stat_id > stat_id_max)
		return stats->num_counters;

	ret = update_qp_stats(nbl_dev, stat_id);
	/* return the success value in this way. */
	/* avoid the impact of concurrent statistics on driver load. */
	if (ret)
		return stats->num_counters;

	stats->value[0] =
		func_stat->stat_id_mem[stat_id][NBL_PACKET_SEQ_ERR+opcode_cnt].total_stats;
	stats->value[1] =
		func_stat->stat_id_mem[stat_id][NBL_OUT_OF_SEQUENCE_LOW+opcode_cnt].total_stats +
		func_stat->stat_id_mem[stat_id][NBL_OUT_OF_SEQUENCE_HIGH+opcode_cnt].total_stats;
	stats->value[2] =
		func_stat->stat_id_mem[stat_id][NBL_STATS_TX_CNP].total_stats;
	stats->value[3] =
		func_stat->stat_id_mem[stat_id][NBL_STATS_RX_CNP].total_stats;
	stats->value[4] =
		func_stat->stat_id_mem[stat_id][NBL_ROCE_ADP_RETRANS+opcode_cnt].total_stats;
	stats->value[5] =
		func_stat->stat_id_mem[stat_id][NBL_STATS_RX_ECN].total_stats;

	return stats->num_counters;
}

static void nbl_set_default_stat_id(struct nbl_pci_f *rf)
{
	u16 function_id;

	function_id = rf->sc_dev.function_id;

	if (!nbl_product_flag_enabled(rf, NBL_PRODUCT_F_CTRL_DEV))
		rf->sc_dev.stat_id = NBL_DEFAULT_VF_STAT_ID;
	else
		rf->sc_dev.stat_id = NBL_DEFAULT_PF_STAT_ID(function_id);
}

int nbl_counters_func_init(struct nbl_device *nbl_dev)
{
	int i, j;
	struct nbl_rdma_stat *func_stat;
	struct nbl_hw *hw = &nbl_dev->rf->hw;

	spin_lock_init(&nbl_dev->rf->hw_stat_lock);

	func_stat = kzalloc(sizeof(struct nbl_rdma_stat), GFP_KERNEL);
	if (!func_stat)
		return -ENOMEM;

	func_stat->nbldev = nbl_dev;
	spin_lock_init(&func_stat->stat_mem_lock);

	/* 1. to alloc dma vf memory */
	func_stat->dma_vf_mem.size = NBL_DUMP_VF_SIZE;
	func_stat->dma_vf_mem.va = nbl_dma_alloc_coherent(hw,
		func_stat->dma_vf_mem.size,
		&func_stat->dma_vf_mem.pa,
		GFP_KERNEL);
	if (!func_stat->dma_vf_mem.va) {
		nbl_pr_err("failed to alloc dma buffer, STAT modoule is not ready!\n");
		return -ENOMEM;
	}
	nbl_pr_dbg("va:0x%p, pa:0x%llx, len:%d\r\n",
		func_stat->dma_vf_mem.va,
		(u64)func_stat->dma_vf_mem.pa,
		func_stat->dma_vf_mem.size);

	/* 2. to alloc dma stat-id memory */
	for (i = 0; i < NBL_STATS_GROUP_NUM_V1; i++) {
		for (j = 0; j < NBL_MAX_DMA_CNT_PER_STAT_ID; j++) {
			func_stat->dma_stat_id_mem[i][j].size = NBL_DUMP_STATS_MAX_SIZE;
			func_stat->dma_stat_id_mem[i][j].va = nbl_dma_alloc_coherent(hw,
				func_stat->dma_stat_id_mem[i][j].size,
				&func_stat->dma_stat_id_mem[i][j].pa,
				GFP_KERNEL);
			if (!func_stat->dma_stat_id_mem[i][j].va) {
				nbl_pr_err("failed to alloc dma buffer, STAT modoule is not ready!\n");
				return -ENOMEM;
			}
			nbl_pr_dbg("va:0x%p, pa:0x%llx, len:%d\r\n",
				func_stat->dma_stat_id_mem[i][j].va,
				(u64)func_stat->dma_stat_id_mem[i][j].pa,
				func_stat->dma_stat_id_mem[i][j].size);
		}
	}

	nbl_dev->func_stat = func_stat;
	nbl_pr_dbg("init statistics module successfully\n");
	nbl_set_default_stat_id(nbl_dev->rf);

	return 0;
}

void nbl_counters_func_deinit(struct nbl_device *nbl_dev)
{
	int i, j;
	struct nbl_rdma_stat *func_stat = nbl_dev->func_stat;
	struct nbl_hw *hw = &nbl_dev->rf->hw;

	if (func_stat->dma_vf_mem.va)
		dma_free_coherent(hw->device,
						func_stat->dma_vf_mem.size,
						func_stat->dma_vf_mem.va,
						func_stat->dma_vf_mem.pa);

	for (i = 0; i < NBL_STATS_GROUP_NUM_V1; i++) {
		for (j = 0; j < NBL_MAX_DMA_CNT_PER_STAT_ID; j++) {
			if (!func_stat->dma_stat_id_mem[i][j].va)
				continue;
			dma_free_coherent(hw->device,
							func_stat->dma_stat_id_mem[i][j].size,
							func_stat->dma_stat_id_mem[i][j].va,
							func_stat->dma_stat_id_mem[i][j].pa);
		}
	}

	kfree(nbl_dev->func_stat);
}
