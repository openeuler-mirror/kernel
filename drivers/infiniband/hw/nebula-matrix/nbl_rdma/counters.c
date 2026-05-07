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

const struct rdma_stat_desc nbl_hw_counters_names[] = {
	{"packet_seq_err", 0, NULL},
	{"out_of_sequence", 0, NULL},
	{"np_cnp_sent", 0, NULL},
	{"rp_cnp_handled", 0, NULL},
	{"roce_retrans", 0, NULL},
	{"tx_rdma_unicast_bytes", 0, NULL},
	{"rx_rdma_unicast_bytes", 0, NULL},
	{"np_ecn_marked_roce_packets", 0, NULL},
};


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

int nbl_grc_add_stat_id(struct nbl_pci_f *rf,
					u16 func_id, u32 qp_id, u8 *req_stat_id)
{
	int ret;
	uint8_t in[64];
	uint8_t out[64];
	uint8_t stat_id;
	int data_len = 0;
	struct grc_cache_msg_header *head;

	head = (struct grc_cache_msg_header *)in;
	head->op_code = GRC_MSG_OP_STAT_ID_ADD;
	head->payload_len = sizeof(func_id) + sizeof(qp_id);
	data_len += sizeof(struct grc_cache_msg_header);

	memcpy(in + data_len, &func_id, sizeof(func_id));
	data_len += sizeof(func_id);

	memcpy(in + data_len, &qp_id, sizeof(qp_id));
	data_len += sizeof(qp_id);

	ret = nbl_exec_cmd(rf, in, data_len, out, sizeof(out));
	if (ret) {
		nbl_pr_err("add stat_id cmd err=%d\n", ret);
		return ret;
	}

	memcpy(&stat_id, out + 1, sizeof(stat_id));
	*req_stat_id = stat_id;

	return 0;
}

int nbl_grc_del_stat_id(struct nbl_pci_f *rf, u8 stat_id, u16 func_id, u32 qp_id)
{
	int ret;
	uint8_t in[64];
	uint8_t out[64];
	int data_len = 0;
	struct grc_cache_msg_header *head;

	head = (struct grc_cache_msg_header *)in;
	head->op_code = GRC_MSG_OP_STAT_ID_DEL;
	head->payload_len = sizeof(stat_id) + sizeof(func_id) + sizeof(qp_id);
	data_len += sizeof(struct grc_cache_msg_header);

	memcpy(in + data_len, &stat_id, sizeof(stat_id));
	data_len += sizeof(stat_id);

	memcpy(in + data_len, &func_id, sizeof(func_id));
	data_len += sizeof(func_id);

	memcpy(in + data_len, &qp_id, sizeof(qp_id));
	data_len += sizeof(qp_id);

	ret = nbl_exec_cmd(rf, in, data_len, out, sizeof(out));
	if (ret)
		nbl_pr_err("del stat_id cmd err=%d\n", ret);

	return ret;
}

int nbl_grc_mod_stat_id(struct nbl_pci_f *rf,
					u8 stat_id_old, u8 stat_id_new, u16 func_id, u32 qp_id)
{
	int ret;
	uint8_t in[64];
	uint8_t out[64];
	int data_len = 0;
	struct grc_cache_msg_header *head;

	head = (struct grc_cache_msg_header *)in;
	head->op_code = GRC_MSG_OP_STAT_ID_MOD;
	head->payload_len = sizeof(stat_id_old) + sizeof(stat_id_new) +
		sizeof(func_id) + sizeof(qp_id);
	data_len += sizeof(struct grc_cache_msg_header);

	memcpy(in + data_len, &stat_id_old, sizeof(stat_id_old));
	data_len += sizeof(stat_id_old);

	memcpy(in + data_len, &stat_id_new, sizeof(stat_id_new));
	data_len += sizeof(stat_id_new);

	memcpy(in + data_len, &func_id, sizeof(func_id));
	data_len += sizeof(func_id);

	memcpy(in + data_len, &qp_id, sizeof(qp_id));
	data_len += sizeof(qp_id);

	ret = nbl_exec_cmd(rf, in, data_len, out, sizeof(out));
	if (ret)
		nbl_pr_err("mod stat_id cmd err=%d\n", ret);

	return ret;
}

int nbl_grc_get_used_cnt(struct nbl_pci_f *rf, u8 stat_id, u32 *req_used_cnt)
{
	int ret;
	uint8_t in[64];
	uint8_t out[64];
	int data_len = 0;
	struct grc_cache_msg_header *head;

	head = (struct grc_cache_msg_header *)in;
	head->op_code = GRC_MSG_OP_USED_CNT_GET;
	head->payload_len = sizeof(stat_id);
	data_len += sizeof(struct grc_cache_msg_header);

	memcpy(in + data_len, &stat_id, sizeof(stat_id));
	data_len += sizeof(stat_id);

	ret = nbl_exec_cmd(rf, in, data_len, out, sizeof(out));
	if (ret) {
		nbl_pr_err("mod stat_id cmd err=%d\n", ret);
		return ret;
	}

	memcpy(req_used_cnt, out + 1, sizeof(*req_used_cnt));

	return 0;
}

static int nbl_grc_hw_stat_read(struct nbl_pci_f *rf,
			struct nbl_stats_reg_info *reg_info)
{
	u16 function_id = rf->sc_dev.function_id;
	u32 pa_l = U64_LO(reg_info->mem->pa);
	u32 pa_h = U64_HI(reg_info->mem->pa);
	u32 op_info = 0;
	uint8_t in[64];
	uint8_t out[64];
	int data_len = 0;
	int ret;
	struct grc_cache_msg_header *head;

	op_info = LS_32(reg_info->op_status, NBL_STATS_OP_STATUS) |
		  LS_32(reg_info->op_rc, NBL_STATS_OP_RC) |
		  LS_32(reg_info->op_table_sel, NBL_STATS_OP_TABLE_SEL) |
		  LS_32(reg_info->op_id, NBL_STATS_OP_ID) |
		  LS_32(reg_info->op_len, NBL_STATS_OP_LEN) |
		  LS_32(reg_info->op_addr_sel, NBL_STATS_OP_ADD_SEL);

	nbl_pr_dbg("read op_info:0x%x, pa_l:0x%x, pa_h:0x%x, status:%d, rc:%d\n",
		op_info, pa_l, pa_h, reg_info->op_status, reg_info->op_rc);
	nbl_pr_dbg("table_sel:%d, id:%d, len:%d, add_sel:%d, function_id:%d\n",
		reg_info->op_table_sel, reg_info->op_id,
		reg_info->op_len, reg_info->op_addr_sel, function_id);

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

void nbl_stats_mem_clear(struct nbl_device *nbl_dev,
				 struct nbl_stats_reg_info *reg_info)
{
	int table_id = reg_info->op_id;
	unsigned long flags;

	nbl_pr_dbg("clear sw stats table:%d, id:%d\n",
		reg_info->op_table_sel, table_id);
	switch (reg_info->op_table_sel) {
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
	case NBL_ERR_QPN_TABLE:
		spin_lock_irqsave(&nbl_dev->func_stat->stat_mem_lock, flags);
		memset(nbl_dev->func_stat->err_qpn_mem, 0,
			sizeof(nbl_dev->func_stat->err_qpn_mem));
		spin_unlock_irqrestore(&nbl_dev->func_stat->stat_mem_lock, flags);
		break;
	case NBL_CLEAR_ALL:
		spin_lock_irqsave(&nbl_dev->func_stat->stat_mem_lock, flags);
		memset(nbl_dev->func_stat->vf_mem, 0,
			sizeof(nbl_dev->func_stat->vf_mem));
		memset(nbl_dev->func_stat->stat_id_mem, 0,
			sizeof(nbl_dev->func_stat->stat_id_mem));
		memset(nbl_dev->func_stat->err_qpn_mem, 0,
			sizeof(nbl_dev->func_stat->err_qpn_mem));
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

static void nbl_stats_mem_update(struct nbl_device *nbl_dev,
				 struct nbl_stats_reg_info *reg_info)
{
	int i;
	int start = reg_info->op_addr_sel;
	int cnt = reg_info->op_len;
	int table_id = reg_info->op_id;
	struct nbl_stats_info *table;
	u64 max_val = NBL_MAX_STATS_48;
	u64 *va = (u64 *)reg_info->mem->va;
	u32 *tmp_va;
	unsigned long flags;
	u64 cur_val = 0;

	nbl_pr_dbg("update stats table:%d, id:%d, start:%d, va:0x%p, pa:0x%llx\n",
		reg_info->op_table_sel, table_id, start, va, reg_info->mem->pa);
	table = nbl_dev->func_stat->stat_id_mem[table_id];
	switch (reg_info->op_table_sel) {
	case NBL_VF_TABLE:
		table = nbl_dev->func_stat->vf_mem;
		fallthrough;
	case NBL_STATS_ID_TABLE:
		spin_lock_irqsave(&nbl_dev->func_stat->stat_mem_lock, flags);
		for (i = 0; i < cnt; i++) {
			cur_val = be64_to_cpu(va[i]);
			if (cur_val || table[i+start].last_stats)
				nbl_pr_dbg("%d:%lld\n", i+start, cur_val);
			table[i+start].total_stats += nbl_stats_delta(
				cur_val,
				table[i+start].last_stats,
				max_val);
			table[i+start].last_stats = (cur_val & max_val);
		}
		spin_unlock_irqrestore(&nbl_dev->func_stat->stat_mem_lock, flags);
		break;
	case NBL_ERR_QPN_TABLE:
		max_val = NBL_MAX_STATS_24;
		tmp_va = (u32 *)reg_info->mem->va;
		table = nbl_dev->func_stat->err_qpn_mem;
		spin_lock_irqsave(&nbl_dev->func_stat->stat_mem_lock, flags);
		for (i = 0; i < cnt; i++) {
			cur_val = (u64)be32_to_cpu(tmp_va[i]);
			if (cur_val || table[i+start].last_stats)
				nbl_pr_dbg("%d:%lld\n", i+start, cur_val);
			table[i+start].total_stats += nbl_stats_delta(
				cur_val,
				table[i+start].last_stats,
				max_val);
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
	struct nbl_hw *hw = &rf->hw;
	struct nbl_stats_reg_info reg_info = { 0 };
	struct nbl_dma_mem mem = { 0 };
	int ret;
	u16 func_id = rf->sc_dev.function_id;

	/* 1.allocated memory */
	mem.size = NBL_DUMP_VF_SIZE;
	mem.va = nbl_dma_alloc_coherent(hw->device, mem.size, &mem.pa,
					GFP_KERNEL);
	nbl_pr_dbg("va:0x%p, pa:0x%llx, len:%d\r\n", mem.va, mem.pa, mem.size);
	if (!mem.va) {
		nbl_pr_err("failed to alloc dma buffer\n");
		return -ENOMEM;
	}
	memset(mem.va, 0, mem.size);

	/* 2.gather statistics */
	reg_info.op_status = 1;
	reg_info.op_rc = OP_STATS_READ;
	reg_info.op_table_sel = NBL_VF_TABLE;
	reg_info.op_id = func_id;
	reg_info.op_len = NBL_VF_CNTS;
	reg_info.mem = &mem;
	ret = nbl_grc_hw_stat_read(rf, &reg_info);
	if (ret)
		goto dma_free;

	/* 3.update stat memory */
	nbl_stats_mem_update(nbl_dev, &reg_info);

dma_free:
	dma_free_coherent(hw->device, mem.size, mem.va, mem.pa);
	return ret;
}

static int update_qp_opcode_stats(struct nbl_device *nbl_dev, int stat_id)
{
	struct nbl_pci_f *rf = nbl_dev->rf;
	struct nbl_hw *hw = &rf->hw;
	struct nbl_stats_reg_info reg_info = { 0 };
	struct nbl_dma_mem mem = { 0 };
	int ret;

	/* 1.allocated memory */
	mem.size = NBL_DUMP_STATS_MAX_SIZE;
	mem.va = nbl_dma_alloc_coherent(hw->device, mem.size, &mem.pa,
					GFP_KERNEL);
	nbl_pr_dbg("va:0x%p, pa:0x%llx, len:%d\r\n", mem.va, mem.pa, mem.size);
	if (!mem.va) {
		nbl_pr_err("failed to alloc dma buffer\n");
		return -ENOMEM;
	}
	memset(mem.va, 0, mem.size);

	/* 2.gather statistics for first 64*/
	reg_info.op_status = 1;
	reg_info.op_rc = OP_STATS_READ;
	reg_info.op_table_sel = NBL_STATS_ID_TABLE;
	reg_info.op_id = stat_id;
	reg_info.op_len = NBL_DUMP_STATS_MAX_CNT;
	reg_info.op_addr_sel = 0;
	reg_info.mem = &mem;
	ret = nbl_grc_hw_stat_read(rf, &reg_info);
	if (ret)
		goto dma_free;

	/* 3.update stat memory */
	nbl_stats_mem_update(nbl_dev, &reg_info);

	/* 4.gather statistics for last 64 and update */
	reg_info.op_addr_sel = NBL_DUMP_STATS_MAX_CNT;
	memset(reg_info.mem->va, 0, NBL_DUMP_STATS_MAX_SIZE);
	ret = nbl_grc_hw_stat_read(rf, &reg_info);
	if (ret)
		goto dma_free;
	nbl_stats_mem_update(nbl_dev, &reg_info);

dma_free:
	dma_free_coherent(hw->device, mem.size, mem.va, mem.pa);
	return ret;
}

static int update_qp_errorcode_stats(struct nbl_device *nbl_dev, int stat_id)
{
	struct nbl_pci_f *rf = nbl_dev->rf;
	struct nbl_hw *hw = &rf->hw;
	struct nbl_stats_reg_info reg_info = { 0 };
	struct nbl_dma_mem mem = { 0 };
	int ret;

	/* 1.allocated memory */
	mem.size = NBL_DUMP_STATS_MAX_SIZE;
	mem.va = nbl_dma_alloc_coherent(hw->device, mem.size, &mem.pa,
					GFP_KERNEL);
	nbl_pr_dbg("va:0x%p, pa:0x%llx, len:%d\r\n", mem.va, mem.pa, mem.size);
	if (!mem.va) {
		nbl_pr_err("failed to alloc dma buffer\n");
		return -ENOMEM;
	}
	memset(mem.va, 0, mem.size);

	/* 2.gather statistics for first 64*/
	reg_info.op_status = 1;
	reg_info.op_rc = OP_STATS_READ;
	reg_info.op_table_sel = NBL_STATS_ID_TABLE;
	reg_info.op_id = stat_id;
	reg_info.op_len = NBL_DUMP_STATS_MAX_CNT;
	reg_info.op_addr_sel = NBL_STATS_GROUP_OPCODE_CNTS;
	reg_info.mem = &mem;
	ret = nbl_grc_hw_stat_read(rf, &reg_info);
	if (ret)
		goto dma_free;

	/* 3.update stat memory */
	nbl_stats_mem_update(nbl_dev, &reg_info);

	/* 4.gather statistics for last 64 and update */
	reg_info.op_addr_sel =
		NBL_STATS_GROUP_OPCODE_CNTS + NBL_DUMP_STATS_MAX_CNT;
	memset(reg_info.mem->va, 0, NBL_DUMP_STATS_MAX_SIZE);
	ret = nbl_grc_hw_stat_read(rf, &reg_info);
	if (ret)
		goto dma_free;
	nbl_stats_mem_update(nbl_dev, &reg_info);

dma_free:
	dma_free_coherent(hw->device, mem.size, mem.va, mem.pa);
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

int update_err_qpn_stats(struct nbl_device *nbl_dev)
{
	struct nbl_pci_f *rf = nbl_dev->rf;
	struct nbl_hw *hw = &rf->hw;
	struct nbl_stats_reg_info reg_info = { 0 };
	struct nbl_dma_mem mem = { 0 };
	int ret;
	u16 function_id = rf->sc_dev.function_id;

	/* 1.allocated memory */
	mem.size = NBL_DUMP_STATS_MAX_SIZE;
	mem.va = nbl_dma_alloc_coherent(hw->device, mem.size, &mem.pa,
					GFP_KERNEL);
	nbl_pr_dbg("va:0x%p, pa:0x%llx, len:%d\r\n", mem.va, mem.pa, mem.size);
	if (!mem.va) {
		nbl_pr_err("failed to alloc dma buffer\n");
		return -ENOMEM;
	}
	memset(mem.va, 0, mem.size);

	/* 2.gather statistics for first 64*/
	reg_info.op_status = 1;
	reg_info.op_rc = OP_STATS_READ;
	reg_info.op_table_sel = NBL_ERR_QPN_TABLE;
	reg_info.op_id = function_id;
	reg_info.op_len = NBL_ERR_QPN_CNTS_PER_VF;
	reg_info.op_addr_sel = 0;
	reg_info.mem = &mem;
	ret = nbl_grc_hw_stat_read(rf, &reg_info);
	if (ret)
		goto dma_free;

	/* 3.update stat memory */
	nbl_stats_mem_update(nbl_dev, &reg_info);

dma_free:
	dma_free_coherent(hw->device, mem.size, mem.va, mem.pa);
	return ret;
}

int update_all_stats(struct nbl_device *nbl_dev)
{
	int i, ret;

	ret = update_vf_stats(nbl_dev);
	if (ret)
		return ret;

	for (i = NBL_STATS_GROUP_START_NUM; i < NBL_STATS_GROUP_NUM; i++) {
		if (nbl_dev->func_stat->stat_id_used_cnt[i] == 0)
			continue;
		ret = update_qp_stats(nbl_dev, i);
		if (ret)
			return ret;
	}

	ret = update_err_qpn_stats(nbl_dev);

	return ret;
}

int nbl_grc_hw_stat_clear(struct nbl_pci_f *rf,
			  struct nbl_stats_reg_info *reg_info)
{
	u32 op_info = 0;
	uint8_t in[64];
	uint8_t out[64];
	int data_len = 0;
	int ret;
	struct grc_cache_msg_header *head;

	op_info = LS_32(reg_info->op_status, NBL_STATS_OP_STATUS) |
		  LS_32(reg_info->op_rc, NBL_STATS_OP_RC) |
		  LS_32(reg_info->op_table_sel, NBL_STATS_OP_TABLE_SEL) |
		  LS_32(reg_info->op_id, NBL_STATS_OP_ID) |
		  LS_32(reg_info->op_len, NBL_STATS_OP_LEN) |
		  LS_32(reg_info->op_addr_sel, NBL_STATS_OP_ADD_SEL);
	nbl_pr_dbg("clear hw stat. op_info:%d, status:%d, rc:%d,",
		op_info, reg_info->op_status, reg_info->op_rc);
	nbl_pr_dbg("table_sel:%d, id:%d, len:%d, add_sel:%d\n",
		reg_info->op_table_sel, reg_info->op_id,
		reg_info->op_len, reg_info->op_addr_sel);

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

int nbl_grc_hw_stat_errcode_enable(struct nbl_pci_f *rf, bool enable)
{
	uint8_t in[64];
	uint8_t out[64];
	int data_len = 0;
	int ret;
	struct grc_cache_msg_header *head;

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

static void nbl_stats_worker(struct work_struct *work)
{
	struct stat_work *swork = container_of(work, struct stat_work, work);
	struct nbl_device *nbl_dev = swork->nbl_dev;
	u64 start;

	start = ktime_get_ns();
	nbl_pr_dbg("Scheduled update start(%lldns).\n", start);

	(void)update_all_stats(nbl_dev);
}

static inline void nbl_update_stat_work(struct nbl_device *nbl_dev)
{
	nbl_dev->rf->swork->nbl_dev = nbl_dev;

	INIT_WORK(&nbl_dev->rf->swork->work, nbl_stats_worker);

	if (!queue_work(nbl_dev->rf->updatestat_wq, &nbl_dev->rf->swork->work))
		nbl_pr_err("update stat failed to queue work\n");
}

static void nbl_hw_stats_timeout(struct timer_list *t)
{
	struct nbl_rdma_stat *func_stat = from_timer(func_stat, t, stats_timer);
	struct nbl_device *nbl_dev = func_stat->nbldev;

	nbl_update_stat_work(nbl_dev);

	mod_timer(&func_stat->stats_timer,
		jiffies + msecs_to_jiffies(func_stat->period));
}

void nbl_hw_stats_start_timer(struct nbl_device *nbl_dev, u32 time)
{
	nbl_dev->func_stat->period = time;
	timer_setup(&nbl_dev->func_stat->stats_timer, nbl_hw_stats_timeout, 0);
	mod_timer(&nbl_dev->func_stat->stats_timer,
		jiffies + msecs_to_jiffies(nbl_dev->func_stat->period));
}

void nbl_hw_stats_stop_timer(struct nbl_device *nbl_dev)
{
	del_timer_sync(&nbl_dev->func_stat->stats_timer);
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

int nbl_grc_read_ecn_stat(struct nbl_pci_f *rf, struct get_ecn_cnt_tbl_resp *grc_resp)
{
	uint8_t in[NBL_GRC_INPUT_SIZE];
	uint8_t out[NBL_GRC_OUTPUT_SIZE];
	uint8_t resp_rst;
	int data_len = 0;
	int ret;
	struct get_ecn_cnt_tbl_req grc_req;
	struct grc_cache_msg_header *head;
	struct nbl_core_dev_info *cdev_info = (struct nbl_core_dev_info *)rf->cdev;

	head = (struct grc_cache_msg_header *)in;
	head->op_code = GRC_MSG_OP_GET_ECN_STAT;
	head->payload_len = sizeof(grc_req);
	data_len += sizeof(struct grc_cache_msg_header);

	grc_req.rss_lag_en = rf->sc_dev.rss_lag_en;
	if (rf->sc_dev.rss_lag_en) {
		grc_req.lag_dport_id[0] = cdev_info->lag_info.lag_mem[0].eth_id;
		grc_req.lag_dport_id[1] = cdev_info->lag_info.lag_mem[1].eth_id;
	} else {
		grc_req.dport_id = rf->sc_dev.dport_id;
	}

	memcpy(in + data_len, &grc_req, sizeof(grc_req));
	data_len += sizeof(grc_req);

	ret = nbl_exec_cmd(rf, in, data_len, out, sizeof(out));
	if (ret != 0)
		nbl_pr_err("read reg err=%d\n", ret);

	/* get operation result */
	memcpy(&resp_rst, out, sizeof(resp_rst));
	if (resp_rst) {
		nbl_pr_err("read reg err resp_rst=%d\n",
			resp_rst);
		return -ENODATA;
	}

	memcpy(grc_resp,
		out + 1,
		sizeof(*grc_resp));
	nbl_pr_dbg("read reg OK. var:%llx\n",
		grc_resp->pkt_cnt);

	return ret;
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
	u32 tx_low, tx_high, rx_low, rx_high;
	u64 tx_flow_bytes, rx_flow_bytes;
	int ret;

	if (stat_id < NBL_STATS_GROUP_START_NUM || stat_id >= NBL_STATS_GROUP_NUM)
		return stats->num_counters;

	ret = update_qp_stats(nbl_dev, stat_id);
	if (ret)
		return ret;

	stats->value[0] = func_stat->stat_id_mem[stat_id][NBL_PACKET_SEQ_ERR].total_stats;
	stats->value[1] = func_stat->stat_id_mem[stat_id][NBL_OUT_OF_SEQUENCE_LOW].total_stats +
		func_stat->stat_id_mem[stat_id][NBL_OUT_OF_SEQUENCE_HIGH].total_stats;
	stats->value[2] = func_stat->stat_id_mem[stat_id][NBL_STATS_TX_CNP].total_stats;
	stats->value[3] = func_stat->stat_id_mem[stat_id][NBL_STATS_RX_CNP].total_stats;
	stats->value[4] = func_stat->stat_id_mem[stat_id][NBL_ROCE_ADP_RETRANS].total_stats;
	ret = nbl_grc_read_reg(nbl_dev->rf, NBL_REG_ADPT_DTRANS_CNT_OUTPUT_BYTE_LOW, &tx_low);
	if (ret) {
		nbl_pr_err("failed to read adpt dtrans cnt low into reg:%#x\n",
			NBL_REG_ADPT_DTRANS_CNT_OUTPUT_BYTE_LOW);
		return ret;
	}
	ret = nbl_grc_read_reg(nbl_dev->rf, NBL_REG_ADPT_DTRANS_CNT_OUTPUT_BYTE_HIGH, &tx_high);
	if (ret) {
		nbl_pr_err("failed to read adpt dtrans cnt high into reg:%#x\n",
			NBL_REG_ADPT_DTRANS_CNT_OUTPUT_BYTE_HIGH);
		return ret;
	}
	tx_flow_bytes = ((u64)tx_high << 32) + tx_low;
	stats->value[5] = tx_flow_bytes;

	ret = nbl_grc_read_reg(nbl_dev->rf, NBL_REG_ADPT_UTRANS_CNT_INPUT_BYTE_LOW, &rx_low);
	if (ret) {
		nbl_pr_err("failed to read adpt utrans cnt low into reg:%#x\n",
			NBL_REG_ADPT_UTRANS_CNT_INPUT_BYTE_LOW);
		return ret;
	}
	ret = nbl_grc_read_reg(nbl_dev->rf, NBL_REG_ADPT_UTRANS_CNT_INPUT_BYTE_HIGH, &rx_high);
	if (ret) {
		nbl_pr_err("failed to read adpt utrans cnt high into reg:%#x\n",
			NBL_REG_ADPT_UTRANS_CNT_INPUT_BYTE_HIGH);
		return ret;
	}
	rx_flow_bytes = ((u64)rx_high << 32) + rx_low;
	stats->value[6] = rx_flow_bytes;

	return stats->num_counters;
}

static void nbl_set_default_stat_id(struct nbl_pci_f *rf)
{
	u16 function_id;

	function_id = rf->sc_dev.function_id;

	if (rf->pcidev->is_virtfn)
		rf->sc_dev.stat_id = 0;
	else
		rf->sc_dev.stat_id = NBL_DEFAULT_STAT_ID(function_id);
}

int nbl_counters_func_init(struct nbl_device *nbl_dev)
{
	nbl_dev->func_stat = kzalloc(sizeof(struct nbl_rdma_stat), GFP_KERNEL);
	if (!nbl_dev->func_stat)
		return -ENOMEM;
	nbl_dev->func_stat->nbldev = nbl_dev;

	nbl_dev->rf->updatestat_wq = alloc_workqueue("nbl_updatestat_wq",
						WQ_UNBOUND, WQ_UNBOUND_MAX_ACTIVE);
	if (!nbl_dev->rf->updatestat_wq) {
		nbl_ib_err(&nbl_dev->rf->sc_dev, "alloc updatestat_wq failed\n");
		return NBL_ERR_NO_MEMORY;
	}

	nbl_dev->rf->swork = kzalloc(sizeof(struct stat_work), GFP_ATOMIC);
	if (!nbl_dev->rf->swork)
		return NBL_ERR_NO_MEMORY;

	spin_lock_init(&nbl_dev->func_stat->stat_mem_lock);

	/* init statistics timer */
	nbl_hw_stats_start_timer(nbl_dev, NBL_STATS_INTERVAL_MAX);
	nbl_pr_dbg("init statistics module successfully\n");
	nbl_set_default_stat_id(nbl_dev->rf);

	return 0;
}

void nbl_counters_func_deinit(struct nbl_device *nbl_dev)
{
	struct nbl_qp_func *cur_node;
	struct nbl_qp_func *tmp_node;
	unsigned long flags;
	int i;
	struct nbl_rdma_stat *func_stat = nbl_dev->func_stat;

	nbl_hw_stats_stop_timer(nbl_dev);
	for (i = 2; i < 128; i++) {
		if (func_stat->stat_id_used_cnt[i] == 0)
			continue;

		func_stat->stat_id_used_cnt[i] = 0;

		spin_lock_irqsave(&func_stat->stat_head_lock[i], flags);
		list_for_each_entry_safe(cur_node, tmp_node,
								&func_stat->stat_head[i], list) {
			list_del(&cur_node->list);
			kfree(cur_node);
		}
		spin_unlock_irqrestore(&func_stat->stat_head_lock[i], flags);
	}

	kfree(func_stat);
	destroy_workqueue(nbl_dev->rf->updatestat_wq);
	kfree(nbl_dev->rf->swork);
}
