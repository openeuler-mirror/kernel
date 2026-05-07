// SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB
/* Copyright (c) 2021, NEBULARMATRIX */

#include "main.h"
#include <linux/dma-direct.h>
#include <linux/bitfield.h>
#include <linux/vmalloc.h>
#include "ctrl.h"
#include "debug.h"
#include "cqp.h"
#include "defs.h"
#include "hmc.h"
#include "ctrl.h"
#include "grc.h"
#include "mem.h"

static int nbl_update_hw_sdtbl_with_buf(struct nbl_pci_f *rf, u16 sd_entry_num,
					u32 hw_sd_idx, dma_addr_t buf_pa, u64 *buf_va)
{
	int err_code = 0;
	__be64 *in;
	u64 sd_entry;
	int i;

	in = kzalloc(NBL_CMD_INPUT_SIZE, GFP_KERNEL);
	if (!in)
		return -ENOMEM;

	set_64bit_val(in, 0, FIELD_PREP(NBL_CQPSQ_OPCODE, NBL_CQP_OP_UPDATE_SD) |
			FIELD_PREP(NBL_CQPSQ_SD_TYPE, 0) |
			FIELD_PREP(NBL_CQPSQ_SD_NUM, sd_entry_num) |
			FIELD_PREP(NBL_CQPSQ_SD_START, hw_sd_idx));
	set_64bit_val(in, 8, buf_pa);

	if (sd_entry_num <= MAX_INLINE_SD_NUM_PER_CMD && buf_va) {
		for (i = 0; i < sd_entry_num; i++) {
			sd_entry = *(buf_va + i);
			set_64bit_val(in, START_OFFSET_IN_SD_CMD + i * SD_ENTRY_SIZE,
				      be64_to_cpu(sd_entry));
		}
	}

	err_code = nbl_cmd_exec(rf, in, NBL_CMD_INPUT_SIZE, NULL, 0);
	if (err_code)
		nbl_ib_err(&rf->sc_dev, "%s cmd failed,err=%d,hw_sd_idx=%d", __func__,
					err_code, hw_sd_idx);
	kfree(in);
	return err_code;
}

static void nbl_calc_extend_buf_cnt(struct nbl_pci_f *rf)
{
	struct nbl_hmc_voa_entry *voa_ent = rf->voa_tbl;
	u32 buf_num = 0;
	u32 obj_total_sz;
	u32 buf_sz = rf->addr_mode == NBL_HMC_PROFILE_HUGEPAGE ? SZ_2M : SZ_4K;

	obj_total_sz = voa_ent[NBL_HMC_QP].obj_max_cnt * BIT(voa_ent[NBL_HMC_QP].obj_sz);
	obj_total_sz = ALIGN(obj_total_sz, NBL_HMC_QPC_SZ);
	buf_num += DIV_ROUND_UP(obj_total_sz, buf_sz);

	obj_total_sz = voa_ent[NBL_HMC_CQ].obj_max_cnt * BIT(voa_ent[NBL_HMC_CQ].obj_sz);
	obj_total_sz = ALIGN(obj_total_sz, NBL_HMC_QPC_SZ);
	buf_num += DIV_ROUND_UP(obj_total_sz, buf_sz);

	rf->sc_dev.hmc_info->sd_tbl.ext_buf_num = buf_num;
}

static bool nbl_need_split_sys_page(struct nbl_pci_f *rf)
{
	u32 sys_page_size = PAGE_SIZE;

	if (sys_page_size > SZ_4K &&
	    (rf->addr_mode == NBL_HMC_PROFILE_LOW_SPEC_HIGH_EFFICIENCY ||
	     rf->addr_mode == NBL_HMC_PROFILE_FULL_SPEC_LOW_EFFICIENCY))
		return true;

	return false;
}

static void nbl_free_split_page(struct nbl_pci_f *rf)
{
	struct nbl_sc_dev *sc_dev = &rf->sc_dev;
	struct sys_page_node *sys_page, *tmp;
	struct sys_page_list *hmc_pages = &rf->sc_dev.hmc_info->sys_pages;

	if (list_empty(&hmc_pages->pg_list))
		return;

	list_for_each_entry_safe(sys_page, tmp, &hmc_pages->pg_list, node) {
		nbl_dev_dbg(&rf->pcidev->dev, "free sys_page=%p\n", sys_page);
		list_del(&sys_page->node);
		dma_free_coherent(sc_dev->hw->device, sys_page->mem.size,
				  sys_page->mem.va, sys_page->mem.pa);
		kfree(sys_page);
	}
}

static int nbl_get_split_page(struct nbl_pci_f *rf, struct nbl_dma_mem *mem)
{
	struct sys_page_node *sys_page;
	struct nbl_sc_dev *sc_dev = &rf->sc_dev;
	struct sys_page_list *hmc_pages = &rf->sc_dev.hmc_info->sys_pages;

	/* find match node from list head */
	list_for_each_entry(sys_page, &hmc_pages->pg_list, node) {
		if (sys_page->mem.size - sys_page->offset >= mem->size) {
			mem->va = sys_page->mem.va + sys_page->offset;
			mem->pa = sys_page->mem.pa + sys_page->offset;
			sys_page->offset += mem->size;
			hmc_pages->used_size += mem->size;
			nbl_dev_dbg(&rf->pcidev->dev, "found page=%p,offset=%#x,mem.size=%#x",
				    sys_page, sys_page->offset, mem->size);
			return 0;
		}

		break;
	}

	sys_page = kcalloc(1, sizeof(struct sys_page_node), GFP_KERNEL);
	if (!sys_page)
		goto exit;

	sys_page->offset = 0;
	sys_page->mem.size = PAGE_SIZE;
	sys_page->mem.va = nbl_dma_alloc_coherent(sc_dev->hw->device, sys_page->mem.size,
							&sys_page->mem.pa, GFP_KERNEL);
	if (!sys_page->mem.va) {
		kfree(sys_page);
		goto exit;
	}

	/* insert new page node in the list head */
	list_add(&sys_page->node, &hmc_pages->pg_list);

	mem->va = sys_page->mem.va;
	mem->pa = sys_page->mem.pa;
	sys_page->offset += mem->size;

	hmc_pages->total_size += sys_page->mem.size;
	hmc_pages->used_size += mem->size;
	hmc_pages->page_cnt++;

	nbl_dev_dbg(&rf->pcidev->dev, "new page=%p,mem.size=%#x,page_cnt=%u\n",
		    sys_page, mem->size, hmc_pages->page_cnt);

	return 0;
exit:
	nbl_free_split_page(rf);
	return -ENOMEM;
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
	u32 used_buf_num = 0;
	u32 *ext_buf_num = &rf->sc_dev.hmc_info->sd_tbl.ext_buf_num;

	sd_buf.size = SZ_4K;
	sd_buf.va = dma_alloc_coherent(sc_dev->hw->device,
						sd_buf.size, &sd_buf.pa, GFP_KERNEL | __GFP_ZERO);
	if (!sd_buf.va)
		return -ENOMEM;

	sd_addr_buf = sd_buf.va;

	nbl_calc_extend_buf_cnt(rf);
	hmc_info->sd_tbl.sd_cnt = rf->hmc_sd_range.cnt;
	sd_ent = kcalloc(hmc_info->sd_tbl.sd_cnt, sizeof(struct nbl_hmc_sd_entry), GFP_KERNEL);
	if (!sd_ent) {
		dma_free_coherent(sc_dev->hw->device, sd_buf.size, sd_buf.va, sd_buf.pa);
		return -ENOMEM;
	}

	hmc_info->sd_tbl.sd_entry = sd_ent;
	for (idx = 0; idx < hmc_info->sd_tbl.sd_cnt; idx++) {
		sd_ent[idx].entry_type = NBL_SD_TYPE_DIRECT;
		mem = &sd_ent[idx].pd_tbl.pd_page;
		mem->size = rf->addr_mode == NBL_HMC_PROFILE_HUGEPAGE ? SZ_2M : SZ_4K;
		if (used_buf_num < *ext_buf_num) {
			mem->size += NBL_QP_CQ_RESV_MEM_SZ;
			used_buf_num++;
		}
		mem->va = nbl_dma_alloc_coherent(sc_dev->hw->device, mem->size,
						 &mem->pa,
						 GFP_KERNEL | __GFP_ZERO);
		if (!mem->va) {
			err_code = -ENOMEM;
			goto free_sd;
		}

		sd_entry = mem->pa | NBL_SD_VALID;
		sd_entry = cpu_to_be64(sd_entry);
		nbl_pr_dbg("std sw_add sd_entry[index:%d, pa=0x%llx,be 0x%llx]", idx,
			mem->pa | NBL_SD_VALID, sd_entry);
		memcpy(sd_addr_buf + sd_entry_num, &sd_entry, sizeof(dma_addr_t));
		sd_entry_num++;
		if (sd_entry_num == 64) {
			err_code = nbl_update_hw_sdtbl_with_buf(rf,
						sd_entry_num, hw_sd_idx, sd_buf.pa, NULL);
			if (err_code)
				goto free_sd;
			hw_sd_idx += sd_entry_num;
			sd_entry_num = 0;
			memset(sd_buf.va, 0, sd_buf.size);
		}
	}

	if (sd_entry_num) {
		err_code = nbl_update_hw_sdtbl_with_buf(rf,
						sd_entry_num, hw_sd_idx, sd_buf.pa, sd_addr_buf);
		if (err_code)
			goto free_sd;
	}

	rf->sc_dev.hmc_info->sd_tbl.used_buf_num = used_buf_num;
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
	sd_buf.va = nbl_dma_alloc_coherent(sc_dev->hw->device, sd_buf.size,
					   &sd_buf.pa, GFP_KERNEL | __GFP_ZERO);
	if (!sd_buf.va)
		return -ENOMEM;

	sd_addr_buf = sd_buf.va;

	nbl_pr_dbg("begin,sd_cnt=%d", hmc_info->sd_tbl.sd_cnt);
	for (idx = 0; idx < hmc_info->sd_tbl.sd_cnt; idx++) {
		memcpy(sd_addr_buf + sd_entry_num, &sd_entry, sizeof(dma_addr_t));
		sd_entry_num++;
		if (sd_entry_num == NBL_HMC_SD_CNT_PER_CMD) {
			err_code = nbl_update_hw_sdtbl_with_buf(rf,
						sd_entry_num, hw_sd_idx, sd_buf.pa, NULL);
			if (err_code)
				nbl_ib_err(&rf->sc_dev, "failed,err=%d", err_code);

			if (nbl_need_split_sys_page(rf)) {
				hw_sd_idx += sd_entry_num;
				sd_entry_num = 0;
				continue;
			}

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
		err_code = nbl_update_hw_sdtbl_with_buf(rf,
						sd_entry_num, hw_sd_idx, sd_buf.pa, sd_addr_buf);
		if (err_code)
			nbl_ib_err(&rf->sc_dev, "failed,err=%d,hw_sd_idx=%u,sd_entry_num=%u",
				err_code, hw_sd_idx, sd_entry_num);
		idy = del_sd_cnt * NBL_HMC_SD_CNT_PER_CMD;
		if (nbl_need_split_sys_page(rf))
			goto exit;

		for ( ; idy < idx; idy++) {
			mem = &sd_ent[idy].pd_tbl.pd_page;
			dma_free_coherent(sc_dev->hw->device, mem->size,
				mem->va, mem->pa);
		}
	}

exit:
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
	int err_code = 0;
	u32 *ext_buf_num = &rf->sc_dev.hmc_info->sd_tbl.ext_buf_num;
	u32 used_buf_num = rf->sc_dev.hmc_info->sd_tbl.used_buf_num;

	bp_mem = kcalloc(bp_cnt, sizeof(struct nbl_dma_mem), GFP_KERNEL);
	if (!bp_mem)
		return -ENOMEM;
	pd_tbl->bp_ent = bp_mem;
	for (idx = 0; idx < bp_cnt; idx++) {
		bp_mem[idx].size = SZ_4K;
		if (used_buf_num < *ext_buf_num) {
			bp_mem[idx].size += NBL_QP_CQ_RESV_MEM_SZ;
			used_buf_num++;
		}

		if (nbl_need_split_sys_page(rf))
			err_code = nbl_get_split_page(rf, &bp_mem[idx]);
		else
			bp_mem[idx].va = nbl_dma_alloc_coherent(
				sc_dev->hw->device, bp_mem[idx].size, &bp_mem[idx].pa,
				GFP_KERNEL | __GFP_ZERO);
		if (!bp_mem[idx].va || err_code)
			goto free_pd_ent;

		pd_entry = bp_mem[idx].pa | NBL_PD_VALID;
		pd_entry = cpu_to_be64(pd_entry);
		if (idx % NBL_PD_PRINT_PERIOD == 0)
			nbl_pr_dbg("fill sd with pd_entry[%d: pd_pa 0x%llx be 0x%llx]", idx,
				bp_mem[idx].pa | NBL_PD_VALID, pd_entry);
		memcpy(pd_addr + idx, &pd_entry, sizeof(pd_entry));
	}
	pd_tbl->bp_cnt = bp_cnt;
	rf->sc_dev.hmc_info->sd_tbl.used_buf_num = used_buf_num;
	return 0;
free_pd_ent:
	if (nbl_need_split_sys_page(rf))
		nbl_free_split_page(rf);
	else
		while (idx--)
			dma_free_coherent(sc_dev->hw->device, bp_mem[idx].size,
					bp_mem[idx].va, bp_mem[idx].pa);

	kfree(bp_mem);
	memset(pd_tbl->pd_page.va, 0, pd_tbl->pd_page.size);
	return -ENOMEM;
}

static void nbl_del_pd_entry(struct nbl_pci_f *rf, struct nbl_hmc_pdtbl *pd_tbl)
{
	int idx;
	struct nbl_dma_mem *bp_mem = pd_tbl->bp_ent;
	u32 bp_cnt = pd_tbl->bp_cnt;

	if (nbl_need_split_sys_page(rf))
		goto exit;

	for (idx = 0; idx < bp_cnt; idx++)
		dma_free_coherent(rf->sc_dev.hw->device, bp_mem[idx].size,
			bp_mem[idx].va, bp_mem[idx].pa);
exit:
	kfree(bp_mem);
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

	nbl_pr_dbg("allocating sd start=%u,cnt=%u for function_id=%u",
		   hw_sd_idx, rf->hmc_sd_range.cnt, rf->sc_dev.function_id);
	sd_buf.size = SZ_4K;
	sd_buf.va = nbl_dma_alloc_coherent(sc_dev->hw->device, sd_buf.size,
					   &sd_buf.pa, GFP_KERNEL | __GFP_ZERO);
	if (!sd_buf.va)
		return -ENOMEM;

	hmc_info->sd_tbl.sd_cnt = rf->hmc_sd_range.cnt;
	sd_ent = kcalloc(hmc_info->sd_tbl.sd_cnt, sizeof(struct nbl_hmc_sd_entry), GFP_KERNEL);
	if (!sd_ent) {
		dma_free_coherent(sc_dev->hw->device, sd_buf.size, sd_buf.va, sd_buf.pa);
		return -ENOMEM;
	}

	nbl_calc_extend_buf_cnt(rf);
	hmc_info->sd_tbl.sd_entry = sd_ent;
	sd_addr_buf = sd_buf.va;
	for (idx = 0; idx < hmc_info->sd_tbl.sd_cnt; idx++) {
		sd_ent[idx].entry_type = NBL_SD_TYPE_PAGED;
		pdtbl = &sd_ent[idx].pd_tbl;
		mem = &sd_ent[idx].pd_tbl.pd_page;
		mem->size = SZ_4K;

		if (nbl_need_split_sys_page(rf))
			err_code = nbl_get_split_page(rf, mem);
		else
			mem->va = nbl_dma_alloc_coherent(sc_dev->hw->device, mem->size,
							&mem->pa,
							GFP_KERNEL | __GFP_ZERO);
		if (!mem->va || err_code) {
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
			mem->pa | NBL_SD_VALID, sd_entry);
		memcpy(sd_addr_buf + sd_entry_num, &sd_entry, sizeof(sd_entry));
		sd_entry_num++;
		if (sd_entry_num == NBL_HMC_SD_CNT_PER_CMD) {
			err_code = nbl_update_hw_sdtbl_with_buf(rf, sd_entry_num,
								hw_sd_idx, sd_buf.pa, NULL);
			if (err_code) {
				nbl_ib_err(sc_dev, "%s failed,err=%d,hw_sd_idx=%d",
							__func__, err_code, hw_sd_idx);
				nbl_del_pd_entry(rf, pdtbl);
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
		err_code = nbl_update_hw_sdtbl_with_buf(rf, sd_entry_num, hw_sd_idx,
							sd_buf.pa, sd_addr_buf);
		if (err_code) {
			nbl_ib_err(sc_dev, "end failed,err=%d,hw_sd_idx=%d", err_code, hw_sd_idx);
			goto free_sd_ent;
		}
	}

	goto exit_add_sd;
free_sd_ent:
	if (nbl_need_split_sys_page(rf))
		nbl_free_split_page(rf);
	else
		while (idx--) {
			pdtbl = &sd_ent[idx].pd_tbl;
			nbl_del_pd_entry(rf, pdtbl);
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
	sd_buf.va = nbl_dma_alloc_coherent(sc_dev->hw->device, sd_buf.size,
					   &sd_buf.pa, GFP_KERNEL | __GFP_ZERO);
	if (!sd_buf.va)
		return -ENOMEM;

	sd_addr_buf = sd_buf.va;
	nbl_pr_dbg("free sds(start=%u,cnt=%u) for function_id=%u\n", hw_sd_idx,
		   sdtbl->sd_cnt, rf->sc_dev.function_id);
	for (idx = 0; idx < sdtbl->sd_cnt; idx++) {
		memcpy(sd_addr_buf + sd_entry_num, &sd_entry, sizeof(sd_entry));
		sd_entry_num++;
		if (sd_entry_num == NBL_HMC_SD_CNT_PER_CMD) {
			err_code = nbl_update_hw_sdtbl_with_buf(rf,
				sd_entry_num, hw_sd_idx, sd_buf.pa, NULL);
			if (err_code) {
				nbl_ib_err(sc_dev, "%s failed,err=%d,hw_sd_idx=%d",
							__func__, err_code, hw_sd_idx);
			}

			idy = del_sd_cnt * NBL_HMC_SD_CNT_PER_CMD;
			for (; idy <= idx; idy++) {
				pdtbl = &sdtbl->sd_entry[idy].pd_tbl;
				nbl_del_pd_entry(rf, pdtbl);
				if (nbl_need_split_sys_page(rf))
					continue;
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
		err_code = nbl_update_hw_sdtbl_with_buf(rf, sd_entry_num, hw_sd_idx,
							sd_buf.pa, sd_addr_buf);
		if (err_code) {
			nbl_ib_err(sc_dev, "%s end failed,err=%d,hw_sd_idx=%d",
							__func__, err_code, hw_sd_idx);
		}

		idy = del_sd_cnt * NBL_HMC_SD_CNT_PER_CMD;
		for (; idy < idx; idy++) {
			pdtbl = &sdtbl->sd_entry[idy].pd_tbl;
			nbl_del_pd_entry(rf, pdtbl);
			if (nbl_need_split_sys_page(rf))
				continue;
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
	struct sys_page_list *hmc_pages = &rf->sc_dev.hmc_info->sys_pages;

	if (rf->addr_mode != NBL_HMC_PROFILE_HUGEPAGE) {
		INIT_LIST_HEAD(&hmc_pages->pg_list);
		hmc_pages->total_size = 0;
		hmc_pages->used_size = 0;
		hmc_pages->page_cnt = 0;
	}

	if (rf->addr_mode == NBL_HMC_PROFILE_FULL_SPEC_LOW_EFFICIENCY) {
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

void nbl_hmc_sdres_deinit(struct nbl_pci_f *rf)
{
	int ret_val = 0;

	if (rf->addr_mode == NBL_HMC_PROFILE_FULL_SPEC_LOW_EFFICIENCY) {
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

	if (nbl_need_split_sys_page(rf))
		nbl_free_split_page(rf);
}

static int nbl_setup_sdreg(struct nbl_pci_f *rf)
{
	int ret_val;
	uint8_t in[64];
	uint8_t out[64];
	int data_len = 0;
	struct grc_cache_msg_header *head;

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

static int nbl_get_sd_range(struct nbl_pci_f *rf)
{
	int ret_val;
	uint8_t in[64];
	uint8_t out[64];
	int data_len = 0;
	struct grc_cache_msg_header *head;

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

	memcpy(&rf->hmc_sd_range, out + 1, sizeof(rf->hmc_sd_range));

	nbl_pr_dbg("got sd range,start=%u,cnt=%u", rf->hmc_sd_range.start, rf->hmc_sd_range.cnt);
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
	default:
		return "unknown obj type";
	}
}

static int nbl_get_voa_tbl(struct nbl_pci_f *rf)
{
	int ret_val;
	uint8_t in[64];
	uint8_t out[64];
	int data_len = 0;
	int i;
	struct grc_cache_msg_header *head;

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

	memcpy(rf->voa_tbl, out + 1, sizeof(rf->voa_tbl));

	nbl_pr_dbg("get voa_tbl info:");
	for (i = 0; i < NBL_HMC_MAX; i++) {
		nbl_pr_dbg("[%s] addr_mode=%u,ba=0x%x,max_cnt=%u,sz=%u,pgsz=%u,valid=%u",
			nbl_get_obj_name(i), rf->voa_tbl[i].addr_mode, rf->voa_tbl[i].obj_ba,
			rf->voa_tbl[i].obj_max_cnt, rf->voa_tbl[i].obj_sz, rf->voa_tbl[i].page_sz,
			rf->voa_tbl[i].valid);

		rf->sc_dev.hmc_info->hmc_obj[i].cnt = rf->voa_tbl[i].obj_max_cnt;
	}

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
static int nbl_flush_s2_cache(struct nbl_pci_f *rf)
{
	int err_code = 0;
	__be64 *in;

	in = kzalloc(NBL_CMD_INPUT_SIZE, GFP_KERNEL);
	if (!in)
		return -ENOMEM;

	set_64bit_val(in, 0, FIELD_PREP(NBL_CQPSQ_OPCODE, NBL_CQP_OP_FLUSH_CACHE) |
			FIELD_PREP(NBL_CQP_FLUASH_CACHE_TYPE, FLUSH_CACHE_S2));

	set_64bit_val(in, 8, FIELD_PREP(NBL_CQP_FLUASH_CACHE_VFID, rf->sc_dev.function_id));

	err_code = nbl_cmd_exec(rf, in, NBL_CMD_INPUT_SIZE, NULL, 0);
	if (err_code)
		nbl_ib_err(&rf->sc_dev, "flush s2_cache cmd err=%d", err_code);

	kfree(in);
	return err_code;
}

void nbl_hmc_destroy(struct nbl_pci_f *rf)
{
	int ret;

	ret = nbl_flush_s2_cache(rf);
	if (ret)
		nbl_ib_err(&rf->sc_dev, "flush s2_cache err=%d", ret);
	nbl_hmc_sdres_deinit(rf);
	ret = nbl_destroy_voa(rf);
	if (ret)
		nbl_ib_err(&rf->sc_dev, "destroy voa failed ret:%d", ret);
}

static int nbl_get_level0_sdpgs(struct nbl_pci_f *rf, enum nbl_hmc_rsrc_type obj_type,
				struct nbl_hmc_obj_sd_info *obj_sd_info)
{
	int idx;
	u32 pg_num = 0;
	u32 obj_sd_idx = 0;
	u32 sd_sz = nbl_get_sd_alignment(rf);
	struct nbl_hmc_info *hmc_info = rf->sc_dev.hmc_info;
	struct nbl_hmc_voa_entry *ent = rf->voa_tbl;
	u32 obj_total_sz = 0;

	for (idx = 0; idx < NBL_HMC_MAX; idx++) {
		if (idx == obj_type)
			break;
		obj_total_sz = (1 << ent[idx].obj_sz) * ent[idx].obj_max_cnt;
		obj_sd_idx += DIV_ROUND_UP(obj_total_sz, sd_sz);
	}

	if (idx >= NBL_HMC_MAX) {
		nbl_ib_err(&rf->sc_dev, "invalid obj_type=%d", obj_type);
		return -EINVAL;
	}

	obj_total_sz = (1 << ent[idx].obj_sz) * ent[idx].obj_max_cnt;
	obj_sd_info->cnt = DIV_ROUND_UP(obj_total_sz, sd_sz);
	obj_sd_info->page_sz = sd_sz;

	obj_sd_info->sd_addr = vzalloc(obj_sd_info->cnt * sizeof(struct nbl_hmc_obj_sd_addr));
	if (!obj_sd_info->sd_addr)
		return -ENOMEM;

	for (idx = obj_sd_idx; idx < hmc_info->sd_tbl.sd_cnt; idx++) {
		if (pg_num >= obj_sd_info->cnt) {
			nbl_ib_warn(&rf->sc_dev, "hmc obj_type=%u,cnt=%u,pg_sz=%#x,sd_idx=%u",
				    obj_type, pg_num, sd_sz, obj_sd_idx);
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
	u32 sd_sz = nbl_get_sd_alignment(rf);
	struct nbl_hmc_info *hmc_info = rf->sc_dev.hmc_info;
	struct nbl_hmc_voa_entry *ent = rf->voa_tbl;
	struct nbl_hmc_pdtbl *pdtbl;
	int pg_idx = 0;
	int sd_offset = 0;
	u32 obj_total_sz = 0;

	for (idx = 0; idx < NBL_HMC_MAX; idx++) {
		if (idx == obj_type) {
			sd_offset = (ent[idx].obj_ba << NBL_HMC_MAX_OBJ_LOG_SZ) % sd_sz;
			pg_idx = sd_offset / SZ_4K;
			break;
		}

		obj_total_sz = (1 << ent[idx].obj_sz) * ent[idx].obj_max_cnt;
		obj_sd_idx += obj_total_sz / sd_sz;
	}

	if (idx >= NBL_HMC_MAX) {
		nbl_ib_err(&rf->sc_dev, "invalid obj_type=%d", obj_type);
		return -EINVAL;
	}

	obj_total_sz = (1 << ent[idx].obj_sz) * ent[idx].obj_max_cnt;
	obj_sd_info->cnt = DIV_ROUND_UP(obj_total_sz, SZ_4K);
	obj_sd_info->page_sz = SZ_4K;

	obj_sd_info->sd_addr = vzalloc(obj_sd_info->cnt * sizeof(struct nbl_hmc_obj_sd_addr));
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

	if (rf->addr_mode == NBL_HMC_PROFILE_FULL_SPEC_LOW_EFFICIENCY)
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

	in = kzalloc(NBL_CMD_INPUT_SIZE, GFP_KERNEL);
	if (!in)
		return -ENOMEM;

	out = kzalloc(NBL_CMD_OUTPUT_SIZE, GFP_KERNEL);
	if (!out) {
		err_code = -ENOMEM;
		goto kzalloc_out_err;
	}

	set_64bit_val(in, 0, FIELD_PREP(NBL_CQPSQ_OPCODE, NBL_CQP_OP_QUERY_SD) |
			FIELD_PREP(NBL_CQPSQ_SD_TYPE, sd_type) |
			FIELD_PREP(NBL_CQPSQ_SD_NUM, cnt) |
			FIELD_PREP(NBL_CQPSQ_SD_START, sd_start));
	set_64bit_val(in, 8, buf_pa);
	err_code = nbl_cmd_exec(rf, in, NBL_CMD_INPUT_SIZE, out, NBL_CMD_OUTPUT_SIZE);
	if (err_code)
		nbl_ib_err(&rf->sc_dev, "query sdtbl err=%d,sd_start=%u",
					err_code, sd_start);
	else if (cnt <= MAX_INLINE_SD_NUM_PER_CMD) {
		for (i = 0; i < cnt; i++) {
			get_64bit_val(out, START_OFFSET_IN_SD_CMD + i * SD_ENTRY_SIZE, &sd_entry);
			nbl_ib_err(&rf->sc_dev, "inline sd_index=%u,sd_val=0x%llx\n", i, sd_entry);
			sd_entry = 0;
		}
	}
	kfree(out);
kzalloc_out_err:
	kfree(in);
	return err_code;
}

u16 nbl_hmc_get_rel_sd_idx(u32 dump_mask)
{
	u16 rel_sd_idx;

	rel_sd_idx = (dump_mask >> (PD_MASK_BITS + SD_PD_DUMP_MASK_USE_BITS)) &
					(BIT(HMC_SD_MASK_BITS) - 1);
	return rel_sd_idx;
}

u16 nbl_hmc_get_rel_pd_idx(u32 dump_mask)
{
	u16 rel_pd_idx;

	rel_pd_idx = (dump_mask >> SD_PD_DUMP_MASK_USE_BITS) & (BIT(PD_MASK_BITS) - 1);

	return rel_pd_idx;
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
	sd_buf.va = nbl_dma_alloc_coherent(sc_dev->hw->device, sd_buf.size,
					   &sd_buf.pa, GFP_KERNEL | __GFP_ZERO);
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
			if (dump_mask & PRINT_ALL_SD)
				nbl_ib_warn(sc_dev, "hw sd_tbl[sd_index:%u].sd_addr=0x%llx,cpu 0x%llx",
					sd_idx, *sd_addr, be64_to_cpu(*sd_addr));
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

void nbl_hmc_query_sd(struct nbl_pci_f *rf, u32 dump_mask)
{
	int ret_val;
	int idx;
	struct nbl_hmc_info *hmc_info = rf->sc_dev.hmc_info;
	struct nbl_hmc_sd_entry *sd_ent;
	struct nbl_hmc_pdtbl *pd_tbl;
	u16 rel_sd_idx;

	ret_val = nbl_hmc_query_sd_tbl(rf, 0, rf->hmc_sd_range.start,
								rf->hmc_sd_range.cnt, dump_mask);
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
