// SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB
/* Copyright (c) 2021, NEBULARMATRIX */

#include "main.h"
#include <linux/dma-direct.h>
#include <linux/bitfield.h>
#include <linux/vmalloc.h>
#include "debug.h"
#include "cqp.h"
#include "defs.h"
#include "hmc.h"
#include "grc.h"
#include "mem.h"

static int nbl_update_hw_sdtbl_with_buf(struct nbl_pci_f *rf, u8 sd_type, u16 sd_entry_num,
					u32 hw_sd_idx, dma_addr_t buf_pa, u64 *buf_va)
{
	int err_code = 0;
	__be64 *in;
	u64 sd_entry;
	int i;
	u32 sd_offset = SD_ENTRY_BYTE_OFFSET / SD_ENTRY_SIZE;

	in = kzalloc(NBL_CMD_INPUT_SIZE, GFP_KERNEL);
	if (!in)
		return -ENOMEM;

	nbl_64bit_write(in, NBL_CQPSQ_OPCODE_T, NBL_CQP_OP_UPDATE_SD);
	nbl_64bit_write(in, NBL_CQPSQ_SD_TYPE, sd_type);
	nbl_64bit_write(in, NBL_CQPSQ_SD_NUM, sd_entry_num);
	nbl_64bit_write(in, NBL_CQPSQ_SD_START, hw_sd_idx);

	nbl_64bit_write(in, NBL_CQPSQ_SD_BUF_ADDR, buf_pa);

	if (sd_entry_num <= MAX_INLINE_SD_NUM_PER_CMD && buf_va) {
		for (i = 0; i < sd_entry_num; i++) {
			sd_entry = *(buf_va + i);
			nbl_64bit_write(in + sd_offset + i,
					NBL_CQPSQ_SD_ENTRY, be64_to_cpu(sd_entry));
		}
	}

	err_code = nbl_cmd_exec(rf, in, NBL_CMD_INPUT_SIZE, NULL, 0);
	if (err_code)
		nbl_ib_err(&rf->sc_dev, "update sd_cmd failed,err=%d,hw_sd_idx=%d",
			   err_code, hw_sd_idx);
	kfree(in);
	return err_code;
}

static int nbl_hmc_create_level0_sds(struct nbl_pci_f *rf)
{
	int err_code = 0;
	int idx;
	u64 sd_entry = 0;
	struct nbl_sc_dev *sc_dev = &rf->sc_dev;
	u32 hw_sd_idx = 0;
	u16 sd_entry_num = 0;
	struct nbl_dma_mem sd_buf;
	u64 *sd_addr_buf;
	struct nbl_dma_mem *mem;
	struct nbl_hmc_sd_entry *sd_ent;
	struct nbl_hmc_info *hmc_info = rf->sc_dev.hmc_info;

	sd_buf.size = SZ_4K;
	sd_buf.va = nbl_dma_alloc_coherent(sc_dev->hw,
						sd_buf.size, &sd_buf.pa, GFP_KERNEL | __GFP_ZERO);
	if (!sd_buf.va)
		return -ENOMEM;

	sd_addr_buf = sd_buf.va;

	hmc_info->sd_tbl.sd_cnt = rf->hmc_sd_range[rf->sc_dev.function_id].cnt;
	sd_ent = kcalloc(hmc_info->sd_tbl.sd_cnt, sizeof(struct nbl_hmc_sd_entry), GFP_KERNEL);
	if (!sd_ent) {
		dma_free_coherent(sc_dev->hw->device, sd_buf.size, sd_buf.va, sd_buf.pa);
		return -ENOMEM;
	}

	hmc_info->sd_tbl.sd_entry = sd_ent;
	for (idx = 0; idx < hmc_info->sd_tbl.sd_cnt; idx++) {
		sd_ent[idx].entry_type = NBL_SD_TYPE_DIRECT;
		mem = &sd_ent[idx].pd_tbl.pd_page;
		mem->size = rf->addr_mode == LEVEL0_WITH_SZ_2M ? SZ_2M : SZ_4K;
		mem->va = nbl_dma_alloc_coherent(sc_dev->hw, mem->size,
						&mem->pa, GFP_KERNEL | __GFP_ZERO);
		if (!mem->va) {
			err_code = -ENOMEM;
			goto free_sd;
		}

		sd_entry = mem->pa | NBL_SD_VALID;
		sd_entry = cpu_to_be64(sd_entry);
		nbl_pr_dbg("std sw_add sd_entry[index:%d, pa=0x%llx,be 0x%llx]", idx,
			(u64)(mem->pa | NBL_SD_VALID), sd_entry);
		memcpy(sd_addr_buf + sd_entry_num, &sd_entry, sizeof(dma_addr_t));
		sd_entry_num++;
		if (sd_entry_num == 64) {
			err_code = nbl_update_hw_sdtbl_with_buf(rf, NBL_CQP_CMD_SD_TYPE_HMC,
						sd_entry_num, hw_sd_idx, sd_buf.pa, NULL);
			if (err_code)
				goto free_sd;
			hw_sd_idx += sd_entry_num;
			sd_entry_num = 0;
			memset(sd_buf.va, 0, sd_buf.size);
		}
	}

	if (sd_entry_num) {
		err_code = nbl_update_hw_sdtbl_with_buf(rf, NBL_CQP_CMD_SD_TYPE_HMC,
						sd_entry_num, hw_sd_idx, sd_buf.pa, sd_addr_buf);
		if (err_code)
			goto free_sd;
	}

	goto exit_sd;
free_sd:
	while (idx--) {
		mem = &sd_ent[idx].pd_tbl.pd_page;
		dma_free_coherent(sc_dev->hw->device, mem->size, mem->va, mem->pa);
	}
	kfree(sd_ent);
exit_sd:
	dma_free_coherent(sc_dev->hw->device, sd_buf.size, sd_buf.va, sd_buf.pa);
	return err_code;
}

static int nbl_hmc_del_level0_sds(struct nbl_pci_f *rf)
{
	int err_code = 0;
	int idx, idy;
	u64 sd_entry = 0;
	u16 del_sd_cnt = 0;
	struct nbl_sc_dev *sc_dev = &rf->sc_dev;
	u32 hw_sd_idx = 0;
	u16 sd_entry_num = 0;
	struct nbl_dma_mem sd_buf;
	u64 *sd_addr_buf;
	struct nbl_dma_mem *mem;
	struct nbl_hmc_info *hmc_info = rf->sc_dev.hmc_info;
	struct nbl_hmc_sd_entry *sd_ent = hmc_info->sd_tbl.sd_entry;

	sd_buf.size = SZ_4K;
	sd_buf.va = nbl_dma_alloc_coherent(sc_dev->hw,
						sd_buf.size, &sd_buf.pa, GFP_KERNEL | __GFP_ZERO);
	if (!sd_buf.va)
		return -ENOMEM;

	sd_addr_buf = sd_buf.va;

	nbl_pr_dbg("begin,sd_cnt=%d", hmc_info->sd_tbl.sd_cnt);
	for (idx = 0; idx < hmc_info->sd_tbl.sd_cnt; idx++) {
		memcpy(sd_addr_buf + sd_entry_num, &sd_entry, sizeof(dma_addr_t));
		sd_entry_num++;
		if (sd_entry_num == NBL_HMC_SD_CNT_PER_CMD) {
			err_code = nbl_update_hw_sdtbl_with_buf(rf, NBL_CQP_CMD_SD_TYPE_HMC,
						sd_entry_num, hw_sd_idx, sd_buf.pa, NULL);
			if (err_code)
				nbl_ib_err(&rf->sc_dev, "failed,err=%d", err_code);

			for (idy = del_sd_cnt * NBL_HMC_SD_CNT_PER_CMD; idy <= idx; idy++) {
				mem = &sd_ent[idy].pd_tbl.pd_page;
				dma_free_coherent(sc_dev->hw->device, mem->size,
					mem->va, mem->pa);
			}
			del_sd_cnt++;
			hw_sd_idx += sd_entry_num;
			sd_entry_num = 0;
		}
	}

	if (sd_entry_num) {
		err_code = nbl_update_hw_sdtbl_with_buf(rf, NBL_CQP_CMD_SD_TYPE_HMC,
						sd_entry_num, hw_sd_idx, sd_buf.pa, sd_addr_buf);
		if (err_code)
			nbl_ib_err(&rf->sc_dev, "failed,err=%d,hw_sd_idx=%u,sd_entry_num=%u",
				err_code, hw_sd_idx, sd_entry_num);
		idy = del_sd_cnt * NBL_HMC_SD_CNT_PER_CMD;
		for ( ; idy < idx; idy++) {
			mem = &sd_ent[idy].pd_tbl.pd_page;
			dma_free_coherent(sc_dev->hw->device, mem->size,
				mem->va, mem->pa);
		}
	}

	kfree(sd_ent);
	dma_free_coherent(sc_dev->hw->device, sd_buf.size, sd_buf.va, sd_buf.pa);
	return err_code;
}

/* alloc n 4k page to fill in pd */
static int nbl_add_pd_entry(struct nbl_pci_f *rf, struct nbl_hmc_pdtbl *pd_tbl)
{
	int idx;
	struct nbl_dma_mem *bp_mem;
	int bp_cnt = pd_tbl->pd_page.size / sizeof(dma_addr_t);
	struct nbl_sc_dev *sc_dev = &rf->sc_dev;
	u64 *pd_addr = pd_tbl->pd_page.va;
	u64 pd_entry;

	bp_mem = kcalloc(bp_cnt, sizeof(struct nbl_dma_mem), GFP_KERNEL);
	if (!bp_mem)
		return -ENOMEM;
	pd_tbl->bp_ent = bp_mem;
	for (idx = 0; idx < bp_cnt; idx++) {
		bp_mem[idx].size = SZ_4K;
		bp_mem[idx].va = nbl_dma_alloc_coherent(sc_dev->hw, bp_mem[idx].size,
						&bp_mem[idx].pa, GFP_KERNEL | __GFP_ZERO);
		if (!bp_mem[idx].va)
			goto free_pd_ent;

		pd_entry = bp_mem[idx].pa | NBL_PD_VALID;
		pd_entry = cpu_to_be64(pd_entry);
		if (idx % NBL_PD_PRINT_PERIOD == 0)
			nbl_pr_dbg("fill sd with pd_entry[%d: pd_pa 0x%llx be 0x%llx]", idx,
				(u64)(bp_mem[idx].pa | NBL_PD_VALID), pd_entry);
		memcpy(pd_addr + idx, &pd_entry, sizeof(pd_entry));
	}
	pd_tbl->bp_cnt = bp_cnt;
	return 0;
free_pd_ent:
	while (idx--)
		dma_free_coherent(sc_dev->hw->device, bp_mem[idx].size,
				bp_mem[idx].va, bp_mem[idx].pa);

	kfree(bp_mem);
	memset(pd_tbl->pd_page.va, 0, pd_tbl->pd_page.size);
	return -ENOMEM;
}

static void nbl_del_pd_entry(struct nbl_sc_dev *sc_dev, struct nbl_hmc_pdtbl *pd_tbl)
{
	int idx;
	struct nbl_dma_mem *bp_mem = pd_tbl->bp_ent;
	u32 bp_cnt = pd_tbl->bp_cnt;

	for (idx = 0; idx < bp_cnt; idx++)
		dma_free_coherent(sc_dev->hw->device, bp_mem[idx].size,
			bp_mem[idx].va, bp_mem[idx].pa);

	kfree(bp_mem);
}

static u16 nbl_hmc_get_rel_pd_idx(u32 dump_mask)
{
	u16 rel_pd_idx;

	rel_pd_idx = (dump_mask >> HMC_SD_MASK_BITS) & (BIT(PD_MASK_BITS) - 1);

	return rel_pd_idx;
}

static void nbl_get_pd_entry(struct nbl_pci_f *rf, struct nbl_hmc_pdtbl *pd_tbl, u32 dump_mask)
{
	int idx;
	struct nbl_dma_mem *bp_mem;
	u64 *pd_addr = pd_tbl->pd_page.va;
	u32 pd_rel_idx;
	u32 pd_mask;

	pd_mask = pd_tbl->bp_cnt - 1;
	pd_rel_idx = nbl_hmc_get_rel_pd_idx(dump_mask);
	for (idx = 0; idx < pd_tbl->bp_cnt; idx++) {
		bp_mem = &pd_tbl->bp_ent[idx];

		if (dump_mask & PRINT_ALL_PD_WITH_ONE_SD)
			nbl_pr_notice("pd_rel_idx=%d,hw_addr=0x%llx,cpu_addr 0x%llx",
				idx, *(pd_addr + idx), be64_to_cpu(*(pd_addr + idx)));

		if ((dump_mask & PRINT_ONE_PD_PAGE_WITH_ONE_SD) && (idx == pd_rel_idx)) {
			nbl_pr_notice("pd_rel_idx=%d,hw_addr=0x%llx,cpu_addr 0x%llx,back page content:",
				idx, *(pd_addr + idx), be64_to_cpu(*(pd_addr + idx)));

			nbl_dump_hex(rf, bp_mem->va, bp_mem->size);
		}
	}
}

static int nbl_add_level1_sds(struct nbl_pci_f *rf)
{
	int err_code = 0;
	int idx;
	u64 sd_entry = 0;
	struct nbl_sc_dev *sc_dev = &rf->sc_dev;
	u32 hw_sd_idx = 0;
	u16 sd_entry_num = 0;
	struct nbl_dma_mem sd_buf;
	u64 *sd_addr_buf;
	struct nbl_dma_mem *mem;
	struct nbl_hmc_info *hmc_info = sc_dev->hmc_info;
	struct nbl_hmc_sd_entry *sd_ent;
	struct nbl_hmc_pdtbl *pdtbl;
	u32 sd_cnt = rf->hmc_sd_range[rf->sc_dev.function_id].cnt;

	nbl_pr_dbg("allocating sd start=%u,cnt=%u for function_id=%u",
		   hw_sd_idx, sd_cnt, rf->sc_dev.function_id);
	sd_buf.size = SZ_4K;
	sd_buf.va = nbl_dma_alloc_coherent(sc_dev->hw,
						sd_buf.size, &sd_buf.pa, GFP_KERNEL | __GFP_ZERO);
	if (!sd_buf.va)
		return -ENOMEM;

	hmc_info->sd_tbl.sd_cnt = sd_cnt;
	sd_ent = kcalloc(hmc_info->sd_tbl.sd_cnt, sizeof(struct nbl_hmc_sd_entry), GFP_KERNEL);
	if (!sd_ent) {
		dma_free_coherent(sc_dev->hw->device, sd_buf.size, sd_buf.va, sd_buf.pa);
		return -ENOMEM;
	}

	hmc_info->sd_tbl.sd_entry = sd_ent;
	sd_addr_buf = sd_buf.va;
	for (idx = 0; idx < hmc_info->sd_tbl.sd_cnt; idx++) {
		sd_ent[idx].entry_type = NBL_SD_TYPE_PAGED;
		pdtbl = &sd_ent[idx].pd_tbl;
		mem = &sd_ent[idx].pd_tbl.pd_page;
		mem->size = SZ_4K;
		mem->va = nbl_dma_alloc_coherent(sc_dev->hw, mem->size,
								&mem->pa, GFP_KERNEL | __GFP_ZERO);
		if (!mem->va) {
			err_code = -ENOMEM;
			goto free_sd_ent;
		}

		err_code = nbl_add_pd_entry(rf, pdtbl);
		if (err_code) {
			dma_free_coherent(sc_dev->hw->device, mem->size, mem->va, mem->pa);
			goto free_sd_ent;
		}
		sd_entry = mem->pa | NBL_SD_VALID;
		sd_entry = cpu_to_be64(sd_entry);
		nbl_pr_dbg("sw_add sd_entry[index:%d, pa=0x%llx,be 0x%llx]", idx,
			(u64)(mem->pa | NBL_SD_VALID), sd_entry);
		memcpy(sd_addr_buf + sd_entry_num, &sd_entry, sizeof(sd_entry));
		sd_entry_num++;
		if (sd_entry_num == NBL_HMC_SD_CNT_PER_CMD) {
			err_code = nbl_update_hw_sdtbl_with_buf(rf, NBL_CQP_CMD_SD_TYPE_HMC,
							sd_entry_num, hw_sd_idx, sd_buf.pa, NULL);
			if (err_code) {
				nbl_ib_err(sc_dev, "%s failed,err=%d,hw_sd_idx=%d",
							__func__, err_code, hw_sd_idx);
				nbl_del_pd_entry(sc_dev, pdtbl);
				dma_free_coherent(sc_dev->hw->device, mem->size, mem->va, mem->pa);
				goto free_sd_ent;
			}
			hw_sd_idx += sd_entry_num;
			sd_entry_num = 0;
			memset(sd_buf.va, 0, sd_buf.size);
		}
	}

	if (sd_entry_num) {
		nbl_pr_dbg("end sd_entry_num=%u", sd_entry_num);
		err_code = nbl_update_hw_sdtbl_with_buf(rf, NBL_CQP_CMD_SD_TYPE_HMC, sd_entry_num,
							hw_sd_idx, sd_buf.pa, sd_addr_buf);
		if (err_code) {
			nbl_ib_err(sc_dev, "end failed,err=%d,hw_sd_idx=%d", err_code, hw_sd_idx);
			goto free_sd_ent;
		}
	}

	goto exit_add_sd;
free_sd_ent:
	while (idx--) {
		pdtbl = &sd_ent[idx].pd_tbl;
		nbl_del_pd_entry(sc_dev, pdtbl);
		mem = &sd_ent[idx].pd_tbl.pd_page;
		dma_free_coherent(sc_dev->hw->device, mem->size, mem->va, mem->pa);
	}

	kfree(sd_ent);
exit_add_sd:
	dma_free_coherent(sc_dev->hw->device, sd_buf.size, sd_buf.va, sd_buf.pa);
	return err_code;
}

static int nbl_del_level1_sds(struct nbl_pci_f *rf)
{
	int idx, idy;
	int err_code = 0;
	u64 sd_entry = 0;
	u32 sd_entry_num = 0;
	u64 *sd_addr_buf;
	struct nbl_dma_mem sd_buf;
	struct nbl_sc_dev *sc_dev = &rf->sc_dev;
	struct nbl_hmc_sd_tbl *sdtbl = &sc_dev->hmc_info->sd_tbl;
	struct nbl_hmc_pdtbl *pdtbl;
	u32 hw_sd_idx = 0;
	u16 del_sd_cnt = 0;

	sd_buf.size = SZ_4K;
	sd_buf.va = nbl_dma_alloc_coherent(sc_dev->hw,
					sd_buf.size, &sd_buf.pa, GFP_KERNEL | __GFP_ZERO);
	if (!sd_buf.va)
		return -ENOMEM;

	sd_addr_buf = sd_buf.va;
	nbl_pr_dbg("free sds(start=%u,cnt=%u) for function_id=%u\n", hw_sd_idx,
		   sdtbl->sd_cnt, rf->sc_dev.function_id);
	for (idx = 0; idx < sdtbl->sd_cnt; idx++) {
		memcpy(sd_addr_buf + sd_entry_num, &sd_entry, sizeof(sd_entry));
		sd_entry_num++;
		if (sd_entry_num == NBL_HMC_SD_CNT_PER_CMD) {
			err_code = nbl_update_hw_sdtbl_with_buf(rf, NBL_CQP_CMD_SD_TYPE_HMC,
				sd_entry_num, hw_sd_idx, sd_buf.pa, NULL);
			if (err_code) {
				nbl_ib_err(sc_dev, "%s failed,err=%d,hw_sd_idx=%d",
							__func__, err_code, hw_sd_idx);
			}

			idy = del_sd_cnt * NBL_HMC_SD_CNT_PER_CMD;
			for (; idy <= idx; idy++) {
				pdtbl = &sdtbl->sd_entry[idy].pd_tbl;
				nbl_del_pd_entry(sc_dev, pdtbl);
				dma_free_coherent(sc_dev->hw->device, pdtbl->pd_page.size,
					pdtbl->pd_page.va, pdtbl->pd_page.pa);
			}
			del_sd_cnt++;
			hw_sd_idx += sd_entry_num;
			sd_entry_num = 0;
			memset(sd_buf.va, 0, sd_buf.size);
		}
	}

	if (sd_entry_num) {
		err_code = nbl_update_hw_sdtbl_with_buf(rf, NBL_CQP_CMD_SD_TYPE_HMC, sd_entry_num,
							hw_sd_idx, sd_buf.pa, sd_addr_buf);
		if (err_code) {
			nbl_ib_err(sc_dev, "%s end failed,err=%d,hw_sd_idx=%d",
							__func__, err_code, hw_sd_idx);
		}

		idy = del_sd_cnt * NBL_HMC_SD_CNT_PER_CMD;
		for (; idy < idx; idy++) {
			pdtbl = &sdtbl->sd_entry[idy].pd_tbl;
			nbl_del_pd_entry(sc_dev, pdtbl);
			dma_free_coherent(sc_dev->hw->device, pdtbl->pd_page.size,
				pdtbl->pd_page.va, pdtbl->pd_page.pa);
		}
	}

	kfree(sdtbl->sd_entry);
	dma_free_coherent(sc_dev->hw->device, sd_buf.size, sd_buf.va, sd_buf.pa);
	return 0;
}

static int nbl_hmc_sdres_init(struct nbl_pci_f *rf)
{
	int ret_val = 0;

	if (rf->addr_mode == LEVEL1_WITH_SZ_4K) {
		ret_val = nbl_add_level1_sds(rf);
		if (ret_val) {
			nbl_ib_err(&rf->sc_dev, "create level1 sd err=%d", ret_val);
			return ret_val;
		}
	} else {
		ret_val = nbl_hmc_create_level0_sds(rf);
		if (ret_val) {
			nbl_ib_err(&rf->sc_dev, "create level0 sd err=%d", ret_val);
			return ret_val;
		}
	}

	return ret_val;
}

static void nbl_hmc_sdres_deinit(struct nbl_pci_f *rf)
{
	int ret_val = 0;

	if (rf->addr_mode == LEVEL1_WITH_SZ_4K) {
		ret_val = nbl_del_level1_sds(rf);
		if (ret_val) {
			nbl_ib_err(&rf->sc_dev, "del level1 sd err=%d", ret_val);
			return;
		}
	} else {
		ret_val = nbl_hmc_del_level0_sds(rf);
		if (ret_val) {
			nbl_ib_err(&rf->sc_dev, "del level0 sd err=%d", ret_val);
			return;
		}
	}
}

void nbl_set_sd_range(struct nbl_pci_f *rf, bool valid)
{
	struct nbl_hmc_sd_range *sd_range = &rf->hmc_sd_range[rf->sc_dev.function_id];

	rf->hw.hw_ops->set_hw_sd_range(&rf->hw, rf->sc_dev.function_id,
				       sd_range->start, sd_range->cnt, valid);
}

static int nbl_setup_sdreg(struct nbl_pci_f *rf)
{
	int ret_val;
	uint8_t in[64];
	uint8_t out[64];
	int data_len = 0;
	struct grc_cache_msg_header *head;

	if (rf->product->resource_ops->set_sd_range) {
		rf->product->resource_ops->set_sd_range(rf, true);
		return 0;
	}

	head = (struct grc_cache_msg_header *)in;
	head->op_code = GRC_MSG_OP_SET_SD_RANGE;
	head->payload_len = sizeof(rf->sc_dev.function_id);
	data_len += sizeof(struct grc_cache_msg_header);

	memcpy(in + data_len, &rf->sc_dev.function_id, sizeof(rf->sc_dev.function_id));
	data_len += sizeof(rf->sc_dev.function_id);

	ret_val = nbl_exec_cmd(rf, in, data_len, out, sizeof(out));
	if (ret_val)
		nbl_ib_err(&rf->sc_dev, " fun_id=%u set sd register cmd err=%d",
			   rf->sc_dev.function_id, ret_val);

	return ret_val;
}

void nbl_get_sd_range_tbl(void)
{
	/* df200 ecpu and asic_v2r1 pf no need process */
}

static int nbl_get_sd_range(struct nbl_pci_f *rf)
{
	int ret_val;
	uint8_t in[64];
	uint8_t out[64];
	int data_len = 0;
	struct grc_cache_msg_header *head;
	struct nbl_hmc_sd_range *sd_range = &rf->hmc_sd_range[rf->sc_dev.function_id];

	if (rf->product->resource_ops->get_sd_range) {
		rf->product->resource_ops->get_sd_range();
		return 0;
	}

	head = (struct grc_cache_msg_header *)in;
	head->op_code = GRC_MSG_OP_GET_SD_RANGE;
	head->payload_len = sizeof(rf->sc_dev.function_id);
	data_len += sizeof(struct grc_cache_msg_header);

	memcpy(in + data_len, &rf->sc_dev.function_id, sizeof(rf->sc_dev.function_id));
	data_len += sizeof(rf->sc_dev.function_id);

	ret_val = nbl_exec_cmd(rf, in, data_len, out, sizeof(out));
	if (ret_val) {
		nbl_ib_err(&rf->sc_dev, "get sd range cmd err=%d", ret_val);
		return ret_val;
	}

	memcpy(sd_range, out + 1, sizeof(*sd_range));

	nbl_pr_dbg("got sd range,start=%u,cnt=%u", sd_range->start, sd_range->cnt);
	return ret_val;
}

static uint8_t *nbl_get_obj_name(int obj_type)
{
	switch (obj_type) {
	case NBL_HMC_QP:
		return "qp";
	case NBL_HMC_CQ:
		return "cq";
	case NBL_HMC_PBL:
		return "pble";
	case NBL_HMC_MR:
		return "mr";
	case NBL_HMC_SRQ:
		return "srq";
	default:
		return "unknown obj type";
	}
}

void nbl_get_pf_voa_tbl_v2(struct nbl_pci_f *rf)
{
	int i;
	union nbl_hmc_voa_entry_v2 *voa_ent = rf->voa_tbl_v2[rf->sc_dev.function_id];

	for (i = 0; i < NBL_HMC_MAX; i++)
		rf->sc_dev.hmc_info->hmc_obj[i].cnt = voa_ent[i].key.obj_max_cnt;
}

static void nbl_parse_voa_tbl_from_mgmt_v2(struct nbl_pci_f *rf, u8 *src, u16 src_len)
{
	int i;
	u32 len = min_t(u32, src_len - 1, sizeof(rf->voa_tbl_v2[rf->sc_dev.function_id]));
	union nbl_hmc_voa_entry_v2 *voa_ent = rf->voa_tbl_v2[rf->sc_dev.function_id];

	memcpy(voa_ent, src + 1, len);

	nbl_pr_dbg("get voa_tbl info:");
	for (i = 0; i < NBL_HMC_MAX; i++) {
		nbl_pr_dbg("[%s] addr_mode=%u,ba=0x%x,max_cnt=%#x,%#x,sz=%u,pgsz=%u,valid=%u",
			nbl_get_obj_name(i), voa_ent[i].key.page_mode, voa_ent[i].key.obj_ba,
			voa_ent[i].key.obj_max_cnt, voa_ent[i].key.obj_idx_start,
			voa_ent[i].key.obj_sz, voa_ent[i].key.page_sz,
			voa_ent[i].key.valid);

		rf->sc_dev.hmc_info->hmc_obj[i].cnt = voa_ent[i].key.obj_max_cnt;
	}
}

static int nbl_get_voa_tbl(struct nbl_pci_f *rf)
{
	int ret_val;
	u8 in[NBL_CMD_INPUT_SIZE];
	u8 out[NBL_CMD_OUTPUT_SIZE];
	int data_len = 0;
	struct grc_cache_msg_header *head;

	if (rf->product->resource_ops->get_voa_tbl) {
		rf->product->resource_ops->get_voa_tbl(rf);
		return 0;
	}

	head = (struct grc_cache_msg_header *)in;
	head->op_code = GRC_MSG_OP_GET_VOA_TBL;
	head->payload_len = sizeof(rf->sc_dev.function_id);
	data_len += sizeof(struct grc_cache_msg_header);

	memcpy(in + data_len, &rf->sc_dev.function_id, sizeof(rf->sc_dev.function_id));
	data_len += sizeof(rf->sc_dev.function_id);

	ret_val = nbl_exec_cmd(rf, in, data_len, out, sizeof(out));
	if (ret_val) {
		nbl_ib_err(&rf->sc_dev, "get voa tbl cmd err=%d", ret_val);
		return ret_val;
	}

	nbl_parse_voa_tbl_from_mgmt_v2(rf, out, sizeof(out));

	return 0;
}

int nbl_hmc_setup(struct nbl_pci_f *rf)
{
	int err_code;

	err_code = nbl_setup_voa(rf);
	if (err_code)
		return err_code;

	err_code = nbl_setup_sdreg(rf);
	if (err_code)
		return err_code;

	err_code = nbl_get_sd_range(rf);
	if (err_code)
		return err_code;

	err_code = nbl_get_voa_tbl(rf);
	if (err_code)
		return err_code;

	err_code = nbl_hmc_sdres_init(rf);
	if (err_code)
		return err_code;

	return 0;
}

/**
 * nbl_flush_s2_cache - flush all qpcc/mrtc/cqcc when vf exit
 * @rf: RDMA PCI function
 */
int nbl_flush_s2_cache(struct nbl_pci_f *rf, u16 flush_vfid)
{
	int err_code = 0;
	__be64 *in;

	in = kzalloc(NBL_CMD_INPUT_SIZE, GFP_KERNEL);
	if (!in)
		return -ENOMEM;

	nbl_64bit_write(in, NBL_CQPSQ_OPCODE_T, NBL_CQP_OP_FLUSH_CACHE);
	nbl_64bit_write(in, NBL_CQP_V2_FLUASH_CACHE_TYPE, FLUSH_CACHE_S2);
	nbl_64bit_write(in, NBL_CQP_V2_FLUASH_CACHE_VFID, flush_vfid);

	err_code = nbl_cmd_exec(rf, in, NBL_CMD_INPUT_SIZE, NULL, 0);
	if (err_code)
		nbl_ib_err(&rf->sc_dev, "flush s2_cache cmd err=%d", err_code);

	kfree(in);
	return err_code;
}

int nbl_flush_pdc_cache(struct nbl_pci_f *rf, u16 flush_vfid)
{
	int ret = 0;
	__be64 *in;

	in = kzalloc(NBL_CMD_INPUT_SIZE, GFP_KERNEL);
	if (!in)
		return NBL_ERR_ALLOCMEM_FAILED;

	nbl_64bit_write(in, NBL_CQPSQ_OPCODE_T, NBL_CQP_OP_FLUSH_CACHE);
	nbl_64bit_write(in, NBL_CQP_V2_FLUASH_CACHE_TYPE, FLUSH_CACHE_PDC);
	nbl_64bit_write(in, NBL_CQP_V2_FLUASH_CACHE_VFID, flush_vfid);

	ret = nbl_cmd_exec(rf, in, NBL_CMD_INPUT_SIZE, NULL, 0);
	if (ret)
		nbl_ib_err(&rf->sc_dev, "CQP QP FLUSH CACHE PDC failed(%u)\n", ret);
	kfree(in);
	return ret;
}

void nbl_hmc_destroy(struct nbl_pci_f *rf)
{
	int ret;

	ret = nbl_flush_s2_cache(rf, rf->sc_dev.function_id);
	if (ret)
		nbl_ib_err(&rf->sc_dev, "flush s2_cache err=%d", ret);
	ret = nbl_flush_pdc_cache(rf, rf->sc_dev.function_id);
	if (ret)
		nbl_ib_err(&rf->sc_dev, "flush pdc cache err=%d", ret);
	nbl_hmc_sdres_deinit(rf);
	ret = nbl_destroy_voa(rf);
	if (ret)
		nbl_ib_err(&rf->sc_dev, "destroy voa failed ret:%d", ret);
}

int nbl_obj_sd_init_v2(struct nbl_pci_f *rf, enum nbl_hmc_rsrc_type obj_type,
		       struct nbl_hmc_obj_sd_info *obj_sd_info, u8 obj_type_max)
{
	int idx;
	u32 sd_offset;
	u32 obj_size;
	u32 sd_cnt;
	u32 obj_sd_size = rf->addr_mode == LEVEL0_WITH_SZ_2M ? SZ_2M : SZ_4K;
	u32 sd_sz = nbl_get_sd_alignment(rf);
	union nbl_hmc_voa_entry_v2 *ent_v2 = rf->voa_tbl_v2[rf->sc_dev.function_id];

	for (idx = 0; idx < obj_type_max; idx++) {
		if (idx == obj_type) {
			sd_offset = (ent_v2[idx].key.obj_ba << NBL_HMC_MAX_OBJ_LOG_SZ) % sd_sz;
			obj_sd_info->pg_idx = sd_offset / SZ_4K;
			break;
		}

		if (rf->addr_mode == LEVEL0_WITH_SZ_2M)
			/* in this case pble sd need align with 2M size */
			sd_cnt = DIV_ROUND_UP(
				(1 << ent_v2[idx].key.obj_sz) * ent_v2[idx].key.obj_max_cnt, sd_sz);
		else
			sd_cnt =
				(1 << ent_v2[idx].key.obj_sz) * ent_v2[idx].key.obj_max_cnt / sd_sz;

		obj_sd_info->obj_sd_idx += sd_cnt;
	}

	if (idx >= obj_type_max) {
		nbl_ib_err(&rf->sc_dev, "invalid obj_type=%d", obj_type);
		return -EINVAL;
	}

	obj_size = (1 << ent_v2[idx].key.obj_sz) * ent_v2[idx].key.obj_max_cnt;
	obj_sd_info->cnt = DIV_ROUND_UP(obj_size, obj_sd_size);
	nbl_dev_dbg(&rf->pcidev->dev, "sd_cnt=%u,type=%u,obj_sz=%u,max_cnt=%#x",
		    obj_sd_info->cnt, obj_type, ent_v2[idx].key.obj_sz,
		    ent_v2[idx].key.obj_max_cnt);
	obj_sd_info->page_sz = obj_sd_size;
	return 0;
}

static int nbl_get_level0_sdpgs(struct nbl_pci_f *rf, enum nbl_hmc_rsrc_type obj_type,
				struct nbl_hmc_obj_sd_info *obj_sd_info)
{
	int idx;
	u32 pg_num = 0;
	u32 obj_sd_idx = 0;
	struct nbl_hmc_info *hmc_info = rf->sc_dev.hmc_info;
	int ret_val;
	u32 vmem_size;

	ret_val = rf->product->resource_ops->obj_sd_init(rf, obj_type,
							obj_sd_info, NBL_HMC_MAX);
	if (ret_val)
		return ret_val;

	obj_sd_idx = obj_sd_info->obj_sd_idx;
	vmem_size = obj_sd_info->cnt * sizeof(struct nbl_hmc_obj_sd_addr);
	obj_sd_info->sd_addr = vmalloc(vmem_size);
	if (!obj_sd_info->sd_addr) {
		nbl_ib_err(&rf->sc_dev, "alloc sd_addr fail,obj_sd_info->cnt=%#x,vmem_size=%#x",
			   obj_sd_info->cnt, vmem_size);
		return -ENOMEM;
	}

	for (idx = obj_sd_idx; idx < hmc_info->sd_tbl.sd_cnt; idx++) {
		if (pg_num >= obj_sd_info->cnt) {
			nbl_ib_dbg(&rf->sc_dev, "hmc obj_type=%u,cnt=%u,pg_sz=%#x,sd_idx=%u",
				    obj_type, pg_num, obj_sd_info->page_sz, obj_sd_idx);
			break;
		}

		obj_sd_info->sd_addr[pg_num].dma_addr =
			hmc_info->sd_tbl.sd_entry[idx].pd_tbl.pd_page.pa;
		obj_sd_info->sd_addr[pg_num].va =
			hmc_info->sd_tbl.sd_entry[idx].pd_tbl.pd_page.va;
		pg_num++;
	}

	return 0;
}

static int nbl_get_level1_sdpgs(struct nbl_pci_f *rf, enum nbl_hmc_rsrc_type obj_type,
				struct nbl_hmc_obj_sd_info *obj_sd_info)
{
	int idx, idy;
	u32 pg_num = 0;
	u32 obj_sd_idx = 0;
	struct nbl_hmc_info *hmc_info = rf->sc_dev.hmc_info;
	struct nbl_hmc_pdtbl *pdtbl;
	int pg_idx = 0;
	int ret_val;
	u32 vmem_size;

	ret_val = rf->product->resource_ops->obj_sd_init(rf, obj_type,
							obj_sd_info, NBL_HMC_MAX);
	if (ret_val)
		return ret_val;

	obj_sd_idx = obj_sd_info->obj_sd_idx;
	pg_idx = obj_sd_info->pg_idx;
	vmem_size = obj_sd_info->cnt * sizeof(struct nbl_hmc_obj_sd_addr);
	obj_sd_info->sd_addr = vmalloc(vmem_size);
	if (!obj_sd_info->sd_addr)
		return -ENOMEM;

	for (idx = obj_sd_idx; idx < hmc_info->sd_tbl.sd_cnt; idx++) {
		pdtbl = &hmc_info->sd_tbl.sd_entry[idx].pd_tbl;
		if (idx == obj_sd_idx && pg_idx)
			idy = pg_idx;
		else
			idy = 0;

		for (; idy < pdtbl->bp_cnt; idy++) {
			obj_sd_info->sd_addr[pg_num].dma_addr = pdtbl->bp_ent[idy].pa;
			obj_sd_info->sd_addr[pg_num].va = pdtbl->bp_ent[idy].va;
			pg_num++;

			if (pg_num >= obj_sd_info->cnt) {
				nbl_ib_dbg(
					&rf->sc_dev,
					"success got level1 pg cnt=%u,obj_type=%u,obj_sd_idx=%u,pg_idx=%d",
					pg_num, obj_type, obj_sd_idx, pg_idx);
				return 0;
			}
		}
	}

	return 0;
}

/**
 * nbl_get_obj_sd_addr - get hmc pages for objects
 * @rf:
 * @obj_type: hmc obj type
 * @obj_sd_info: hmc pages info for obj
 * if this function return 0, user need to free obj_sd_info->sd_ent
 * use nbl_free_obj_sd_addr function.
 */
int nbl_get_obj_sd_addr(struct nbl_pci_f *rf, enum nbl_hmc_rsrc_type obj_type,
				struct nbl_hmc_obj_sd_info *obj_sd_info)
{
	int ret_val;

	if (rf->addr_mode == LEVEL1_WITH_SZ_4K)
		ret_val = nbl_get_level1_sdpgs(rf, obj_type, obj_sd_info);
	else
		ret_val = nbl_get_level0_sdpgs(rf, obj_type, obj_sd_info);

	return ret_val;
}

void nbl_free_obj_sd_addr(struct nbl_hmc_obj_sd_info *obj_sd_info)
{
	vfree(obj_sd_info->sd_addr);
}

static int nbl_hmc_query_sdtbl_with_buf(struct nbl_pci_f *rf, u8 sd_type, u16 sd_start,
								u16 cnt, dma_addr_t buf_pa)
{
	int err_code = 0;
	__be64 *in;
	__be64 *out;
	u64 sd_entry = 0;
	int i;
	u32 sd_offset = SD_ENTRY_BYTE_OFFSET / SD_ENTRY_SIZE;

	in = kzalloc(NBL_CMD_INPUT_SIZE, GFP_KERNEL);
	if (!in)
		return -ENOMEM;

	out = kzalloc(NBL_CMD_OUTPUT_SIZE, GFP_KERNEL);
	if (!out) {
		err_code = -ENOMEM;
		goto kzalloc_out_err;
	}

	nbl_64bit_write(in, NBL_CQPSQ_OPCODE_T, NBL_CQP_OP_QUERY_SD);
	nbl_64bit_write(in, NBL_CQPSQ_SD_TYPE, sd_type);
	nbl_64bit_write(in, NBL_CQPSQ_SD_NUM, cnt);
	nbl_64bit_write(in, NBL_CQPSQ_SD_START, sd_start);
	nbl_64bit_write(in, NBL_CQPSQ_SD_BUF_ADDR, buf_pa);
	err_code = nbl_cmd_exec(rf, in, NBL_CMD_INPUT_SIZE, out, NBL_CMD_OUTPUT_SIZE);
	if (err_code)
		nbl_ib_err(&rf->sc_dev, "query sdtbl err=%d,sd_start=%u",
					err_code, sd_start);
	else if (cnt <= MAX_INLINE_SD_NUM_PER_CMD) {
		for (i = 0; i < cnt; i++) {
			sd_entry = nbl_64bit_read(out + sd_offset + i, NBL_CQPSQ_SD_ENTRY);
			nbl_ib_err(&rf->sc_dev, "inline sd_index=%u,sd_val=0x%llx\n", i, sd_entry);
			sd_entry = 0;
		}
	}
	kfree(out);
kzalloc_out_err:
	kfree(in);
	return err_code;
}

static u16 nbl_hmc_get_rel_sd_idx(u32 dump_mask)
{
	u16 rel_sd_idx;

	rel_sd_idx = dump_mask & (BIT(HMC_SD_MASK_BITS) - 1);
	return rel_sd_idx;
}

static int nbl_hmc_query_sd_tbl(struct nbl_pci_f *rf, u8 sd_type,
				u16 sd_start, u16 sd_cnt, u32 dump_mask)
{
	int i, j;
	int err_code;
	u64 *sd_addr;
	u16 cnt;
	u16 sd_idx;
	u16 print_sd_idx;
	u16 query_cnt = DIV_ROUND_UP(sd_cnt, NBL_HMC_SD_CNT_PER_CMD);
	struct nbl_dma_mem sd_buf;
	struct nbl_sc_dev *sc_dev = &rf->sc_dev;

	nbl_ib_dbg(sc_dev, "query sd_type=%u,start=%u,cnt=%u", sd_type, sd_start, sd_cnt);
	sd_buf.size = SZ_4K;
	sd_buf.va = nbl_dma_alloc_coherent(sc_dev->hw,
						sd_buf.size, &sd_buf.pa, GFP_KERNEL | __GFP_ZERO);
	if (!sd_buf.va)
		return -ENOMEM;

	print_sd_idx = nbl_hmc_get_rel_sd_idx(dump_mask);
	for (i = 0; i < query_cnt; i++) {
		memset(sd_buf.va, 0, sd_buf.size);
		sd_addr = (u64 *)sd_buf.va;
		if (sd_cnt > NBL_HMC_SD_CNT_PER_CMD) {
			cnt = NBL_HMC_SD_CNT_PER_CMD;
			sd_cnt -= NBL_HMC_SD_CNT_PER_CMD;
		} else
			cnt = sd_cnt;
		err_code = nbl_hmc_query_sdtbl_with_buf(rf, sd_type,
			i * NBL_HMC_SD_CNT_PER_CMD, cnt, sd_buf.pa);
		if (err_code)
			goto query_sdtbl_err;

		for (j = 0; j < cnt; j++) {
			sd_idx = sd_start + j + i * NBL_HMC_SD_CNT_PER_CMD;
			if ((dump_mask & PRINT_ONE_PD_PAGE_WITH_ONE_SD) ||
				(dump_mask & PRINT_ALL_PD_WITH_ONE_SD)) {
				if (sd_start + print_sd_idx == sd_idx)
					nbl_pr_notice("sd_r_i=%u,a_i=%u,h_a=0x%llx,c_a=0x%llx",
						print_sd_idx, sd_idx,
						*sd_addr, be64_to_cpu(*sd_addr));
				}
			sd_addr++;
		}
	}

query_sdtbl_err:
	dma_free_coherent(sc_dev->hw->device, sd_buf.size, sd_buf.va, sd_buf.pa);

	return err_code;
}

static void nbl_query_sw_hmc_sd(struct nbl_pci_f *rf)
{
	int idx;
	struct nbl_dma_mem *mem;
	u32 sd_start = rf->hmc_sd_range[rf->sc_dev.function_id].start;
	struct nbl_hmc_info *hmc_info = rf->sc_dev.hmc_info;
	struct nbl_hmc_sd_entry *sd_ent = hmc_info->sd_tbl.sd_entry;

	for (idx = 0; idx < hmc_info->sd_tbl.sd_cnt; idx++) {
		mem = &sd_ent[idx].pd_tbl.pd_page;
		dev_warn(&rf->pcidev->dev, "[sw] hmc sd[%u]:0x%llx\n",
			 sd_start + idx, (u64)mem->pa);
	}
}

static int nbl_query_hw_sd_tbl(struct nbl_pci_f *rf, u8 sd_type, u16 sd_start, u16 sd_cnt)
{
	int i, j;
	int err_code;
	u64 *sd_addr;
	u16 cnt;
	u16 abs_sd_idx;
	u16 rel_sd_idx;
	u16 query_cnt = DIV_ROUND_UP(sd_cnt, NBL_HMC_SD_CNT_PER_CMD);
	struct nbl_dma_mem sd_buf;
	struct nbl_sc_dev *sc_dev = &rf->sc_dev;

	nbl_ib_warn(sc_dev, "query %s sd,start=%u,cnt=%u",
		    sd_type == NBL_SD_TYPE_GLOBAL ? "[GLOBAL]" : "[HMC]", sd_start, sd_cnt);
	sd_buf.size = SZ_4K;
	sd_buf.va = nbl_dma_alloc_coherent(sc_dev->hw,
						sd_buf.size, &sd_buf.pa, GFP_KERNEL | __GFP_ZERO);
	if (!sd_buf.va)
		return -ENOMEM;

	for (i = 0; i < query_cnt; i++) {
		memset(sd_buf.va, 0, sd_buf.size);
		sd_addr = (u64 *)sd_buf.va;
		if (sd_cnt > NBL_HMC_SD_CNT_PER_CMD) {
			cnt = NBL_HMC_SD_CNT_PER_CMD;
			sd_cnt -= NBL_HMC_SD_CNT_PER_CMD;
		} else
			cnt = sd_cnt;
		err_code = nbl_hmc_query_sdtbl_with_buf(rf, sd_type,
			sd_start + i * NBL_HMC_SD_CNT_PER_CMD, cnt, sd_buf.pa);
		if (err_code)
			goto query_sdtbl_err;

		for (j = 0; j < cnt; j++) {
			rel_sd_idx = j + i * NBL_HMC_SD_CNT_PER_CMD;
			abs_sd_idx = sd_start + rel_sd_idx;
			nbl_pr_notice("sd_r_i=%u,a_i=%u,sd_addr=0x%llx,cpu_addr=0x%llx",
				      rel_sd_idx, abs_sd_idx, *sd_addr, be64_to_cpu(*sd_addr));
			sd_addr++;
		}
	}

query_sdtbl_err:
	dma_free_coherent(sc_dev->hw->device, sd_buf.size, sd_buf.va, sd_buf.pa);

	return err_code;
}

static void nbl_query_sw_glo_sd(struct nbl_pci_f *rf)
{
	int idx, j = 0;
	struct nbl_dma_mem *mem;
	u32 sd_start = rf->sc_dev.function_id * NBL_MAX_GLOBAL_SD_CNT;
	struct nbl_hmc_info *hmc_info = rf->sc_dev.hmc_info;
	struct nbl_hmc_sd_tbl *glo_sd_tbl;
	struct nbl_hmc_sd_entry *sd_ent;

	for (idx = 0; idx < NBL_SD_TYPE_MAX; idx++) {
		glo_sd_tbl = &hmc_info->glo_sd_tbl[idx];
		sd_ent = glo_sd_tbl->sd_entry;

		for (j = 0; j < glo_sd_tbl->sd_cnt; j++) {
			mem = &sd_ent[j].pd_tbl.pd_page;
			dev_warn(&rf->pcidev->dev, "[sw] global sd[%u]:0x%llx\n",
				 sd_start + j, (u64)mem->pa);
		}

		sd_start += glo_sd_tbl->sd_cnt;
	}
}

static void nbl_query_all_pd_within_one_sd(struct nbl_pci_f *rf, u32 dst_sd_idx)
{
	int idx, j = 0;
	struct nbl_dma_mem *mem;
	struct nbl_hmc_info *hmc_info = rf->sc_dev.hmc_info;
	struct nbl_hmc_sd_tbl *glo_sd_tbl;
	struct nbl_hmc_sd_entry *sd_ent;
	u32 src_sd_idx = 0;

	for (idx = 0; idx < NBL_SD_TYPE_MAX; idx++) {
		glo_sd_tbl = &hmc_info->glo_sd_tbl[idx];
		sd_ent = glo_sd_tbl->sd_entry;

		for (j = 0; j < glo_sd_tbl->sd_cnt; j++) {
			mem = &sd_ent[j].pd_tbl.pd_page;
			if (j + src_sd_idx == dst_sd_idx) {
				print_hex_dump(KERN_ERR, "dump global sw pd in one sd ",
					       DUMP_PREFIX_OFFSET, DFX_HMC_PRINT_LEN,
					       DFX_HMC_PRINT_GRP, mem->va, mem->size, 0);
				break;
			}
		}

		src_sd_idx += glo_sd_tbl->sd_cnt;
	}
}

static void nbl_query_sw_pds_one_sd(struct nbl_pci_f *rf, u32 dump_mask)
{
	int idx;
	u16 sd_idx;
	int pd_cnt;
	struct nbl_dma_mem *pd_ent;
	struct nbl_hmc_info *hmc_info = rf->sc_dev.hmc_info;
	struct nbl_hmc_sd_entry *sd_ent = hmc_info->sd_tbl.sd_entry;
	struct nbl_dma_mem hmc_buf = {0};

	sd_idx = nbl_hmc_get_rel_sd_idx(dump_mask);
	pd_ent = sd_ent[sd_idx].pd_tbl.bp_ent;
	hmc_buf.size = sd_ent[sd_idx].pd_tbl.pd_page.size;
	pd_cnt = hmc_buf.size / sizeof(dma_addr_t);

	hmc_buf.va = nbl_dma_alloc_coherent(&rf->hw, hmc_buf.size, &hmc_buf.pa, GFP_KERNEL);
	if (!hmc_buf.va) {
		dev_err(&rf->pcidev->dev, "alloc dma buf failed for query hmc sd\n");
		return;
	}

	dev_warn(&rf->pcidev->dev, "begin print all pds of one sd[%u, 0x%llx] in sw\n",
		 sd_idx + rf->hmc_sd_range[rf->sc_dev.function_id].start,
		 (u64)sd_ent[sd_idx].pd_tbl.pd_page.pa);

	for (idx = 0; idx < pd_cnt; idx++)
		memcpy(hmc_buf.va + sizeof(dma_addr_t) * idx, &pd_ent[idx].pa, sizeof(dma_addr_t));

	print_hex_dump(KERN_ERR, "dump sw pd ", DUMP_PREFIX_OFFSET, DFX_HMC_PRINT_LEN,
		       DFX_HMC_PRINT_GRP, hmc_buf.va, hmc_buf.size, 0);

	dma_free_coherent(rf->sc_dev.hw->device, hmc_buf.size, hmc_buf.va, hmc_buf.pa);
}

static void nbl_query_sw_pd_page(struct nbl_pci_f *rf, u32 dump_mask)
{
	int idx;
	u16 sd_idx;
	u16 pd_idx;
	u64 *entry;
	u64 tmp_addr;
	int dma_ent_cnt;
	struct nbl_dma_mem *pd_ent;
	struct nbl_hmc_info *hmc_info = rf->sc_dev.hmc_info;
	struct nbl_hmc_sd_entry *sd_ent = hmc_info->sd_tbl.sd_entry;
	struct nbl_dma_mem hmc_buf = {0};

	sd_idx = nbl_hmc_get_rel_sd_idx(dump_mask);
	pd_idx = nbl_hmc_get_rel_pd_idx(dump_mask);
	pd_ent = &sd_ent[sd_idx].pd_tbl.bp_ent[pd_idx];
	hmc_buf.size = sd_ent[sd_idx].pd_tbl.pd_page.size;
	dma_ent_cnt = hmc_buf.size / sizeof(dma_addr_t);

	hmc_buf.va = nbl_dma_alloc_coherent(&rf->hw, hmc_buf.size, &hmc_buf.pa, GFP_KERNEL);
	if (!hmc_buf.va) {
		dev_err(&rf->pcidev->dev, "alloc dma buf failed for query hmc sd\n");
		return;
	}

	pr_notice("begin print all content of ond pd[%u, 0x%llx] in one sd[%u, 0x%llx]\n",
		  pd_idx, (u64)pd_ent->pa,
		  sd_idx + rf->hmc_sd_range[rf->sc_dev.function_id].start,
		  (u64)sd_ent[sd_idx].pd_tbl.pd_page.pa);

	entry = pd_ent->va;
	for (idx = 0; idx < dma_ent_cnt; idx++) {
		tmp_addr = be64_to_cpu(entry[idx]);
		memcpy(hmc_buf.va + idx * sizeof(tmp_addr), &tmp_addr, sizeof(tmp_addr));
	}

	print_hex_dump(KERN_ERR, "dump sw pd content ", DUMP_PREFIX_OFFSET, DFX_HMC_PRINT_LEN,
		       DFX_HMC_PRINT_GRP, hmc_buf.va, hmc_buf.size, 0);
	dma_free_coherent(rf->sc_dev.hw->device, hmc_buf.size, hmc_buf.va, hmc_buf.pa);
}

static void nbl_query_sd_data(struct nbl_pci_f *rf, u32 dump_mask)
{
	u32 idx;
	u16 rel_sd_idx;
	struct nbl_dma_mem *mem;
	struct nbl_hmc_sd_entry *sd_ent;
	struct nbl_hmc_info *hmc_info = rf->sc_dev.hmc_info;

	rel_sd_idx = nbl_hmc_get_rel_sd_idx(dump_mask);

	for (idx = 0; idx < hmc_info->sd_tbl.sd_cnt; idx++) {
		sd_ent = &hmc_info->sd_tbl.sd_entry[idx];
		mem = &sd_ent->pd_tbl.pd_page;
		if (rel_sd_idx == idx) {
			nbl_dev_err(&rf->pcidev->dev, "rel_sd_idx=%u,sd_pa=%llx",
				    rel_sd_idx, (u64)mem->pa);
			print_hex_dump(KERN_ERR, "dump level0 sd data ", DUMP_PREFIX_OFFSET,
				       DFX_HMC_PRINT_LEN, DFX_HMC_PRINT_GRP, mem->va, mem->size, 0);
			break;
		}
	}
}

void nbl_query_global_sd(struct nbl_pci_f *rf, u32 dump_mask)
{
	int ret_val;
	u32 sd_idx = 0;
	u32 glo_sd_start;

	if (!nbl_product_flag_enabled(rf, NBL_PRODUCT_F_CTRL_DEV))
		return;

	if (dump_mask & PRINT_SW_GLO_SD) {
		nbl_query_sw_glo_sd(rf);
		return;
	}

	if (dump_mask & PRINT_SW_GLO_ALL_PD_WITH_ONE_SD) {
		sd_idx = dump_mask & 0xFF;
		nbl_query_all_pd_within_one_sd(rf, sd_idx);
	}

	if (dump_mask & PRINT_HW_GLOBAL_SD) {
		glo_sd_start = rf->sc_dev.function_id * NBL_MAX_GLOBAL_SD_CNT;
		ret_val = nbl_query_hw_sd_tbl(rf, NBL_SD_TYPE_GLOBAL,
					      glo_sd_start, NBL_MAX_GLOBAL_SD_CNT);
		if (ret_val) {
			nbl_ib_err(&rf->sc_dev, "query global sd_tbl err=%d", ret_val);
			return;
		}
	}
}

void nbl_hmc_query_sd(struct nbl_pci_f *rf, u32 dump_mask)
{
	int ret_val;
	int idx;
	struct nbl_hmc_info *hmc_info = rf->sc_dev.hmc_info;
	struct nbl_hmc_sd_entry *sd_ent;
	struct nbl_hmc_pdtbl *pd_tbl;
	u16 rel_sd_idx;
	struct nbl_hmc_sd_range *sd_range = &rf->hmc_sd_range[rf->sc_dev.function_id];

	if (dump_mask & PRINT_SW_HMC_SD) {
		if (dump_mask & PRINT_ALL_PD_WITH_ONE_SD && rf->addr_mode == LEVEL1_WITH_SZ_4K) {
			nbl_query_sw_pds_one_sd(rf, dump_mask);
			return;
		}

		if (dump_mask & PRINT_ONE_PD_PAGE_WITH_ONE_SD &&
		    rf->addr_mode == LEVEL1_WITH_SZ_4K) {
			nbl_query_sw_pd_page(rf, dump_mask);
			return;
		}

		if (dump_mask & PRINT_ONE_SD_DATA &&
		    (rf->addr_mode == LEVEL0_WITH_SZ_2M || rf->addr_mode == LEVEL0_WITH_SZ_4K)) {
			nbl_query_sd_data(rf, dump_mask);
			return;
		}

		nbl_query_sw_hmc_sd(rf);
		return;
	}

	if (dump_mask & PRINT_HW_HMC_SD) {
		ret_val = nbl_query_hw_sd_tbl(rf, NBL_SD_TYPE_HMC, 0, sd_range->cnt);
		if (ret_val) {
			nbl_ib_err(&rf->sc_dev, "query global sd_tbl err=%d", ret_val);
			return;
		}
		return;
	}

	ret_val = nbl_hmc_query_sd_tbl(rf, 0, sd_range->start, sd_range->cnt, dump_mask);
	if (ret_val) {
		nbl_ib_err(&rf->sc_dev, "query sd_tbl err=%d", ret_val);
		return;
	}

	rel_sd_idx = nbl_hmc_get_rel_sd_idx(dump_mask);
	for (idx = 0; idx < hmc_info->sd_tbl.sd_cnt; idx++) {
		sd_ent = &hmc_info->sd_tbl.sd_entry[idx];
		pd_tbl = &sd_ent->pd_tbl;

		if (rel_sd_idx == idx)
			nbl_get_pd_entry(rf, pd_tbl, dump_mask);
	}
}

u32 glo_q_len[NBL_SD_TYPE_MAX] = {
	NBL_RQDB_ARM_SIZE,
	NBL_TQ_RTO_SIZE,
	NBL_DBQ_SIZE,
	NBL_TQ_RNR_SIZE
};

static int nbl_alloc_global_queue_mem_v2(struct nbl_pci_f *rf, u8 sd_type, u32 queue_len,
					 struct nbl_gl_sdtbl_info *sd_info)
{
	u16 idx;
	int err_code;
	u32 alloc_len = SZ_2M;
	u32 len = ALIGN(queue_len, SZ_2M);
	struct nbl_hw *hw = rf->sc_dev.hw;
	struct nbl_hmc_sd_tbl *sd_tbl = &rf->sc_dev.hmc_info->glo_sd_tbl[sd_type];

	sd_info->sd_buf_idx = 0;
	sd_info->pd_buf_idx = 0;
	sd_info->max_num = len / SZ_2M;
	sd_info->list = kcalloc(sd_info->max_num, sizeof(struct nbl_dma_mem), GFP_KERNEL);
	if (!sd_info->list)
		return -ENOMEM;

	sd_tbl->sd_cnt = DIV_ROUND_UP(queue_len, SZ_2M);
	for (idx = 0; idx < sd_info->max_num; idx++) {
		sd_info->list[idx].va = nbl_dma_alloc_coherent(hw, SZ_2M,
							   &sd_info->list[idx].pa, GFP_KERNEL);
		if (!sd_info->list[idx].va) {
			err_code = -ENOMEM;
			goto free_sd_list;
		}

		nbl_ib_dbg(&rf->sc_dev, "[%u]alloc_len=0x%x,va=%p,pa=0x%llx\n",
			   idx, alloc_len, sd_info->list[idx].va,
			   (u64)sd_info->list[idx].pa);
		sd_info->list[idx].size = alloc_len;
	}

	sd_info->cnt = sd_info->max_num;

	return 0;

free_sd_list:
	while (idx--) {
		struct nbl_dma_mem *mem = &sd_info->list[idx];

		dma_free_coherent(hw->device, mem->size, mem->va, mem->pa);
	}
	kfree(sd_info->list);
	return err_code;
}

static void nbl_free_global_queue_mem(struct nbl_pci_f *rf, struct nbl_gl_sdtbl_info *sd_info)
{
	u16 idx;
	struct nbl_dma_mem *mem;
	struct device *dma_dev = &rf->pcidev->dev;

	for (idx = 0; idx < sd_info->cnt; idx++) {
		mem = &sd_info->list[idx];
		dma_free_coherent(dma_dev, mem->size, mem->va, mem->pa);
	}

	kfree(sd_info->list);
	memset(sd_info, 0, sizeof(struct nbl_gl_sdtbl_info));
}

static int nbl_fill_glo_sd_tbl_v2(struct nbl_pci_f *rf, u8 sd_type)
{
	struct nbl_sc_dev *sc_dev = &rf->sc_dev;
	struct nbl_hmc_sd_tbl *glo_sd_tbl = &sc_dev->hmc_info->glo_sd_tbl[sd_type];
	struct nbl_gl_sdtbl_info *glo_sd_res = &sc_dev->hmc_info->glo_sd_res[sd_type];
	struct nbl_hmc_sd_entry *sd_ent;
	int i;
	struct nbl_dma_mem *pd_page;

	sd_ent = kcalloc(glo_sd_tbl->sd_cnt, sizeof(struct nbl_hmc_sd_entry), GFP_KERNEL);
	if (!sd_ent)
		return -ENOMEM;

	glo_sd_tbl->sd_entry = sd_ent;

	for (i = 0; i < glo_sd_tbl->sd_cnt; i++) {
		pd_page = &sd_ent[i].pd_tbl.pd_page;
		pd_page->pa = glo_sd_res->list[i].pa;
	}

	return 0;
}

static void nbl_clear_glo_sd_tbl(struct nbl_pci_f *rf, u8 sd_type)
{
	struct nbl_hmc_sd_tbl *glo_sd_tbl = &rf->sc_dev.hmc_info->glo_sd_tbl[sd_type];

	kfree(glo_sd_tbl->sd_entry);
}

static int nbl_fill_glo_sd_buf(struct nbl_pci_f *rf, u64 *sd_addr_buf, u16 *filled_sd_cnt)
{
	int i, j;
	u16 k = 0;
	u16 hw_sd_idx;
	u64 sd_entry;
	struct nbl_hmc_sd_tbl *glo_sd_tbl;
	struct nbl_sc_dev *sc_dev = &rf->sc_dev;
	struct nbl_dma_mem *pd_page;

	for (i = 0; i < NBL_SD_TYPE_MAX; i++) {
		glo_sd_tbl = &sc_dev->hmc_info->glo_sd_tbl[i];
		for (j = 0; j < glo_sd_tbl->sd_cnt; j++) {
			hw_sd_idx = j + k;
			pd_page = &glo_sd_tbl->sd_entry[j].pd_tbl.pd_page;
			sd_entry = cpu_to_be64(pd_page->pa | NBL_SD_VALID);
			memcpy(sd_addr_buf + hw_sd_idx, &sd_entry, sizeof(sd_entry));
			nbl_ib_dbg(&rf->sc_dev, "[%u] big_endian sd_entry=0x%llx",
				   hw_sd_idx, sd_entry);
			if (hw_sd_idx > NBL_MAX_GLOBAL_SD_CNT) {
				nbl_ib_err(&rf->sc_dev, "global sd should not over than hw tbl(%u)",
					NBL_MAX_GLOBAL_SD_CNT);
				return -ENOMEM;
			}
		}

		k += NBL_HW_MAX_GLO_QUEUE_SD_NUM;
	}

	*filled_sd_cnt = k;
	return 0;
}

static int nbl_set_hw_glo_sdtbl(struct nbl_pci_f *rf, bool is_add)
{
	u16 k = NBL_MAX_GLOBAL_SD_CNT;
	u32 sd_num;
	int err_code;
	u64 *sd_addr_buf;
	struct nbl_dma_mem sd_buf;
	struct nbl_hw *hw = rf->sc_dev.hw;
	u16 hw_sd_idx = rf->sc_dev.function_id * NBL_MAX_GLOBAL_SD_CNT;

	sd_buf.size = SZ_4K;
	sd_buf.va = nbl_dma_alloc_coherent(hw, sd_buf.size, &sd_buf.pa, GFP_KERNEL);
	if (!sd_buf.va)
		return -ENOMEM;

	sd_addr_buf = sd_buf.va;
	sd_num = sd_buf.size / sizeof(u64);

	if (is_add) {
		err_code = nbl_fill_glo_sd_buf(rf, sd_addr_buf, &k);
		if (err_code)
			goto fill_sd_err;
	}

	err_code = nbl_update_hw_sdtbl_with_buf(rf, NBL_CQP_CMD_SD_TYPE_GLOBAL, k, hw_sd_idx,
						sd_buf.pa, sd_buf.va);
	if (err_code) {
		nbl_ib_err(&rf->sc_dev, "update global sd_tbl err=%d", err_code);
		goto fill_sd_err;
	}

	dma_free_coherent(hw->device, sd_buf.size, sd_buf.va, sd_buf.pa);
	return 0;

fill_sd_err:
	dma_free_coherent(hw->device, sd_buf.size, sd_buf.va, sd_buf.pa);
	return err_code;
}

static int nbl_setup_global_sdtbl(struct nbl_pci_f *rf, u8 sd_type, u32 queue_len,
				  struct nbl_gl_sdtbl_info *sd_info)
{
	int err_code = 0;

	nbl_ib_dbg(&rf->sc_dev, "begin init global queue,sd_type=%u,len=0x%x\n",
		   sd_type, queue_len);
	/* 1.alloc dma mem block by queue_len */
	err_code = nbl_alloc_global_queue_mem_v2(rf, sd_type, queue_len, sd_info);
	if (err_code)
		return err_code;

	/* 2.reassign dma mem block into global sd tbl with level1 4kB page */
	err_code =  nbl_fill_glo_sd_tbl_v2(rf, sd_type);
	if (err_code)
		nbl_free_global_queue_mem(rf, sd_info);

	return err_code;
}

static void nbl_free_global_sdtbl(struct nbl_pci_f *rf, u8 sd_type,
				  struct nbl_gl_sdtbl_info *glo_sd_res)
{
	nbl_clear_glo_sd_tbl(rf, sd_type);
	nbl_free_global_queue_mem(rf, glo_sd_res);
}

int nbl_global_sd_init(struct nbl_pci_f *rf)
{
	int idx;
	int err_code = 0;
	struct nbl_gl_sdtbl_info *glo_sd_res;

	for (idx = 0; idx < NBL_SD_TYPE_MAX; idx++) {
		glo_sd_res = &rf->sc_dev.hmc_info->glo_sd_res[idx];
		err_code = nbl_setup_global_sdtbl(rf, idx, glo_q_len[idx], glo_sd_res);
		if (err_code)
			goto free_gl_sd;
	}

	/* 3. update hw global sd tbl by cqp cmd */
	err_code = nbl_set_hw_glo_sdtbl(rf, true);
	if (err_code)
		goto free_gl_sd;

	return 0;
free_gl_sd:
	while (idx--) {
		glo_sd_res = &rf->sc_dev.hmc_info->glo_sd_res[idx];
		nbl_free_global_sdtbl(rf, idx, glo_sd_res);
	}
	return err_code;
}

void nbl_global_sd_deinit(struct nbl_pci_f *rf)
{
	int idx;
	int err_code;
	struct nbl_gl_sdtbl_info *glo_sd_res;

	err_code = nbl_set_hw_glo_sdtbl(rf, false);
	if (err_code)
		nbl_ib_err(&rf->sc_dev, "free hw global sdtbl err=%d\n", err_code);

	for (idx = 0; idx < NBL_SD_TYPE_MAX; idx++) {
		glo_sd_res = &rf->sc_dev.hmc_info->glo_sd_res[idx];
		nbl_free_global_sdtbl(rf, idx, glo_sd_res);
	}
}

int nbl_global_q_init(struct nbl_pci_f *rf)
{
	if (nbl_product_flag_enabled(rf, NBL_PRODUCT_F_CTRL_DEV) &&
	    rf->product->resource_ops->global_sd_init)
		return rf->product->resource_ops->global_sd_init(rf);

	return 0;
}

void nbl_global_q_deinit(struct nbl_pci_f *rf)
{
	if (nbl_product_flag_enabled(rf, NBL_PRODUCT_F_CTRL_DEV) &&
	    rf->product->resource_ops->global_sd_deinit)
		rf->product->resource_ops->global_sd_deinit(rf);
}

void nbl_direct_set_vf_pf_map(struct nbl_pci_f *rf)
{
	rf->hw.hw_ops->set_hw_pf_tbl(&rf->hw, rf->sc_dev.function_id,
				    rf->sc_dev.function_id);
}

void nbl_set_vf_pf_map(struct nbl_pci_f *rf)
{
	int ret_val;
	uint8_t in[NBL_CMD_INPUT_SIZE];
	uint8_t out[NBL_CMD_OUTPUT_SIZE];
	int data_len = 0;
	struct grc_cache_msg_header *head;

	if (rf->product->resource_ops->set_vf_pf_map) {
		rf->product->resource_ops->set_vf_pf_map(rf);
		return;
	}

	/* 1.df200 ecpu pf2/pf3 set pf_id=0 */
	/* 2.df200 host pf/vf set pf_id=0 by grc */
	/* 3.asic_v2r1 pf set pf_id=self_pf_id */
	/* 4.asic_v2r1 vf set pf_id=master_pf_id by mailbox */

	head = (struct grc_cache_msg_header *)in;
	head->op_code = GRC_MSG_OP_SET_GLO_Q_VF_PF_MAP;
	head->payload_len = sizeof(rf->sc_dev.function_id);
	data_len += sizeof(struct grc_cache_msg_header);

	memcpy(in + data_len, &rf->sc_dev.function_id, sizeof(rf->sc_dev.function_id));
	data_len += sizeof(rf->sc_dev.function_id);

	nbl_ib_dbg(&rf->sc_dev, "[vf] fun_id=%u set global q vf_pf map cmd begin",
		   rf->sc_dev.function_id);
	ret_val = nbl_exec_cmd(rf, in, data_len, out, sizeof(out));
	if (ret_val)
		nbl_ib_err(&rf->sc_dev, " fun_id=%u set global q vf_pf map cmd err=%d",
			   rf->sc_dev.function_id, ret_val);
}
