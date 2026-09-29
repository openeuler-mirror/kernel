// SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB
/* Copyright (c) 2015 - 2021 WangXun Corporation */
#include "osdep.h"
#include "hmc.h"
#include "defs.h"
#include "type.h"
#include "protos.h"
#include "vf.h"
#include "virtchnl.h"

/**
 * nser_find_sd_index_limit - finds segment descriptor index limit
 * @hmc_info: pointer to the HMC configuration information structure
 * @type: type of HMC resources we're searching
 * @idx: starting index for the object
 * @cnt: number of objects we're trying to create
 * @sd_idx: pointer to return index of the segment descriptor in question
 * @sd_limit: pointer to return the maximum number of segment descriptors
 *
 * This function calculates the segment descriptor index and index limit
 * for the resource defined by nser_hmc_rsrc_type.
 */

static void nser_find_sd_index_limit(struct nser_hmc_info *hmc_info, u32 type,
				      u32 idx, u32 cnt, u32 *sd_idx,
				      u32 *sd_limit)
{
	u64 fpm_addr, fpm_limit;

	fpm_addr = hmc_info->hmc_obj[(type)].base +
		   hmc_info->hmc_obj[type].size * idx;
	fpm_limit = fpm_addr + hmc_info->hmc_obj[type].size * cnt;
	*sd_idx = (u32)(fpm_addr / NSER_HMC_DIRECT_BP_SIZE);
	*sd_limit = (u32)((fpm_limit - 1) / NSER_HMC_DIRECT_BP_SIZE);
	*sd_limit += 1;
}

/**
 * nser_find_pd_index_limit - finds page descriptor index limit
 * @hmc_info: pointer to the HMC configuration information struct
 * @type: HMC resource type we're examining
 * @idx: starting index for the object
 * @cnt: number of objects we're trying to create
 * @pd_idx: pointer to return page descriptor index
 * @pd_limit: pointer to return page descriptor index limit
 *
 * Calculates the page descriptor index and index limit for the resource
 * defined by nser_hmc_rsrc_type.
 */

static void nser_find_pd_index_limit(struct nser_hmc_info *hmc_info, u32 type,
				      u32 idx, u32 cnt, u32 *pd_idx,
				      u32 *pd_limit)
{
	u64 fpm_adr, fpm_limit;

	fpm_adr = hmc_info->hmc_obj[type].base +
		  hmc_info->hmc_obj[type].size * idx;
	fpm_limit = fpm_adr + (hmc_info)->hmc_obj[(type)].size * (cnt);
	*pd_idx = (u32)(fpm_adr / NSER_HMC_PAGED_BP_SIZE);
	*pd_limit = (u32)((fpm_limit - 1) / NSER_HMC_PAGED_BP_SIZE);
	*pd_limit += 1;
}

/**
 * nser_set_sd_entry - setup entry for sd programming
 * @pa: physical addr
 * @idx: sd index
 * @type: paged or direct sd
 * @entry: sd entry ptr
 */
static void nser_set_sd_entry(u64 pa, u32 idx, enum nser_sd_entry_type type,
			       struct nser_update_sd_entry *entry)
{
	entry->data = pa |
		      FIELD_PREP(NSER_PFHMC_SDDATALOW_PMSDBPCOUNT, NSER_HMC_MAX_BP_COUNT) |
		      FIELD_PREP(NSER_PFHMC_SDDATALOW_PMSDTYPE,
				 type == NSER_SD_TYPE_PAGED ? 0 : 1) |
		      FIELD_PREP(NSER_PFHMC_SDDATALOW_PMSDVALID, 1);

	entry->cmd = idx | FIELD_PREP(NSER_PFHMC_SDCMD_PMSDWR, 1) |
		     NSER_PFHMC_SDCMD_PMSDPARTSEL;
}

/**
 * nser_clr_sd_entry - setup entry for sd clear
 * @idx: sd index
 * @type: paged or direct sd
 * @entry: sd entry ptr
 */
static void nser_clr_sd_entry(u32 idx, enum nser_sd_entry_type type,
			       struct nser_update_sd_entry *entry)
{
	entry->data = FIELD_PREP(NSER_PFHMC_SDDATALOW_PMSDBPCOUNT, NSER_HMC_MAX_BP_COUNT) |
		      FIELD_PREP(NSER_PFHMC_SDDATALOW_PMSDTYPE,
				 type == NSER_SD_TYPE_PAGED ? 0 : 1);

	entry->cmd = idx | FIELD_PREP(NSER_PFHMC_SDCMD_PMSDWR, 1) |
		     NSER_PFHMC_SDCMD_PMSDPARTSEL;
}

/**
 * nser_hmc_sd_one - setup 1 sd entry for cqp
 * @dev: pointer to the device structure
 * @hmc_fn_id: hmc's function id
 * @pa: physical addr
 * @sd_idx: sd index
 * @type: paged or direct sd
 * @setsd: flag to set or clear sd
 */
int nser_hmc_sd_one(struct nser_sc_dev *dev, u8 hmc_fn_id, u64 pa, u32 sd_idx,
		     enum nser_sd_entry_type type, bool setsd)
{
	struct nser_update_sds_info sdinfo;

	sdinfo.cnt = 1;
	sdinfo.hmc_fn_id = hmc_fn_id;
	if (setsd)
		nser_set_sd_entry(pa, sd_idx, type, sdinfo.entry);
	else
		nser_clr_sd_entry(sd_idx, type, sdinfo.entry);
	return dev->cqp->process_cqp_sds(dev, &sdinfo);
}

/**
 * nser_hmc_sd_grp - setup group of sd entries for cqp
 * @dev: pointer to the device structure
 * @hmc_info: pointer to the HMC configuration information struct
 * @sd_index: sd index
 * @sd_cnt: number of sd entries
 * @setsd: flag to set or clear sd
 */
static int nser_hmc_sd_grp(struct nser_sc_dev *dev,
			    struct nser_hmc_info *hmc_info, u32 sd_index,
			    u32 sd_cnt, bool setsd)
{
	struct nser_hmc_sd_entry *sd_entry;
	struct nser_update_sds_info sdinfo = {};
	u64 pa;
	u32 i;
	int ret_code = 0;

	sdinfo.hmc_fn_id = hmc_info->hmc_fn_id;
	for (i = sd_index; i < sd_index + sd_cnt; i++) {
		sd_entry = &hmc_info->sd_table.sd_entry[i];
		if (!sd_entry || (!sd_entry->valid && setsd) ||
		    (sd_entry->valid && !setsd))
			continue;
		if (setsd) {
			pa = (sd_entry->entry_type == NSER_SD_TYPE_PAGED) ?
				     sd_entry->u.pd_table.pd_page_addr.pa :
				     sd_entry->u.bp.addr.pa;
			nser_set_sd_entry(pa, i, sd_entry->entry_type,
					   &sdinfo.entry[sdinfo.cnt]);
		} else {
			nser_clr_sd_entry(i, sd_entry->entry_type,
					   &sdinfo.entry[sdinfo.cnt]);
		}
		sdinfo.cnt++;
		if (sdinfo.cnt == NSER_MAX_SD_ENTRIES) {
			ret_code = dev->cqp->process_cqp_sds(dev, &sdinfo);
			if (ret_code) {
				nser_dbg(dev,
					  "HMC: sd_programming failed err=%d\n",
					  ret_code);
				return ret_code;
			}

			sdinfo.cnt = 0;
		}
	}
	if (sdinfo.cnt)
		ret_code = dev->cqp->process_cqp_sds(dev, &sdinfo);

	return ret_code;
}

/**
 * nser_vfdev_from_fpm - return vf dev ptr for hmc function id
 * @dev: pointer to the device structure
 * @hmc_fn_id: hmc's function id
 */
struct nser_vfdev *nser_vfdev_from_fpm(struct nser_sc_dev *dev, u8 hmc_fn_id)
{
	struct nser_vfdev *vf_dev = NULL;
	u16 idx;

	for (idx = 0; idx < dev->num_vfs; idx++) {
		if (dev->vf_dev[idx] &&
		    ((u8)dev->vf_dev[idx]->pmf_index == hmc_fn_id)) {
			vf_dev = dev->vf_dev[idx];
			break;
		}
	}
	return vf_dev;
}

/**
 * nser_vf_hmcinfo_from_fpm - get ptr to hmc for func_id
 * @dev: pointer to the device structure
 * @hmc_fn_id: hmc's function id
 */
struct nser_hmc_info *nser_vf_hmcinfo_from_fpm(struct nser_sc_dev *dev,
						 u8 hmc_fn_id)
{
	struct nser_hmc_info *hmc_info = NULL;
	u16 idx;

	for (idx = 0; idx < dev->num_vfs; idx++) {
		if (dev->vf_dev[idx] &&
		    ((u8)dev->vf_dev[idx]->pmf_index == hmc_fn_id)) {
			hmc_info = &dev->vf_dev[idx]->hmc_info;
			break;
		}
	}
	return hmc_info;
}

/**
 * nser_hmc_finish_add_sd_reg - program sd entries for objects
 * @dev: pointer to the device structure
 * @info: create obj info
 */
static int nser_hmc_finish_add_sd_reg(struct nser_sc_dev *dev,
				       struct nser_hmc_create_obj_info *info)
{
	if (info->start_idx >= info->hmc_info->hmc_obj[info->rsrc_type].cnt)
		return -EINVAL;

	if ((info->start_idx + info->count) >
	    info->hmc_info->hmc_obj[info->rsrc_type].cnt)
		return -EINVAL;

	if (!info->add_sd_cnt)
		return 0;
	return nser_hmc_sd_grp(dev, info->hmc_info,
				info->hmc_info->sd_indexes[0], info->add_sd_cnt,
				true);
}

/**
 * nser_sc_create_hmc_obj - allocate backing store for hmc objects
 * @dev: pointer to the device structure
 * @info: pointer to nser_hmc_create_obj_info struct
 *
 * This will allocate memory for PDs and backing pages and populate
 * the sd and pd entries.
 */
int nser_sc_create_hmc_obj(struct nser_sc_dev *dev,
			    struct nser_hmc_create_obj_info *info)
{
	struct nser_hmc_sd_entry *sd_entry;
	u32 sd_idx, sd_lmt;
	u32 pd_idx = 0, pd_lmt = 0;
	u32 pd_idx1 = 0, pd_lmt1 = 0;
	u32 i, j;
	bool pd_error = false;
	int ret_code = 0;

	if (info->hmc_info->mem_type == NSER_CHIP_MEM)
		return 0;

	if (info->start_idx >= info->hmc_info->hmc_obj[info->rsrc_type].cnt)
		return -EINVAL;

	if ((info->start_idx + info->count) >
	    info->hmc_info->hmc_obj[info->rsrc_type].cnt) {
		nser_dbg(dev,
			  "HMC: error type %u, start = %u, req cnt %u, cnt = %u\n",
			  info->rsrc_type, info->start_idx, info->count,
			  info->hmc_info->hmc_obj[info->rsrc_type].cnt);
		return -EINVAL;
	}

	if (!dev->privileged)
		return nser_vchnl_vf_add_hmc_objs(dev, info->rsrc_type,
						   info->start_idx,
						   info->count);

	nser_find_sd_index_limit(info->hmc_info, info->rsrc_type,
				  info->start_idx, info->count, &sd_idx,
				  &sd_lmt);
	if (sd_idx >= info->hmc_info->sd_table.sd_cnt ||
	    sd_lmt > info->hmc_info->sd_table.sd_cnt) {
		return -EINVAL;
	}

	nser_find_pd_index_limit(info->hmc_info, info->rsrc_type,
				  info->start_idx, info->count, &pd_idx,
				  &pd_lmt);

	for (j = sd_idx; j < sd_lmt; j++) {
		ret_code = nser_add_sd_table_entry(dev->hw, info->hmc_info, j,
						    info->entry_type,
						    NSER_HMC_DIRECT_BP_SIZE);
		if (ret_code)
			goto exit_sd_error;

		sd_entry = &info->hmc_info->sd_table.sd_entry[j];
		if (sd_entry->entry_type == NSER_SD_TYPE_PAGED &&
		    (dev->hmc_info == info->hmc_info &&
		     info->rsrc_type != NSER_HMC_IW_PBLE)) {
			pd_idx1 = max(pd_idx, (j * NSER_HMC_MAX_BP_COUNT));
			pd_lmt1 = min(pd_lmt, (j + 1) * NSER_HMC_MAX_BP_COUNT);
			for (i = pd_idx1; i < pd_lmt1; i++) {
				/* update the pd table entry */
				ret_code = nser_add_pd_table_entry(dev,
								    info->hmc_info,
								    i, NULL);
				if (ret_code) {
					pd_error = true;
					break;
				}
			}
			if (pd_error) {
				while (i && (i > pd_idx1)) {
					nser_remove_pd_bp(dev, info->hmc_info,
							   i - 1);
					i--;
				}
			}
		}
		if (sd_entry->valid)
			continue;

		info->hmc_info->sd_indexes[info->add_sd_cnt] = (u16)j;
		info->add_sd_cnt++;
		sd_entry->valid = true;
	}
	return nser_hmc_finish_add_sd_reg(dev, info);

exit_sd_error:
	while (j && (j > sd_idx)) {
		sd_entry = &info->hmc_info->sd_table.sd_entry[j - 1];
		switch (sd_entry->entry_type) {
		case NSER_SD_TYPE_PAGED:
			pd_idx1 = max(pd_idx, (j - 1) * NSER_HMC_MAX_BP_COUNT);
			pd_lmt1 = min(pd_lmt, (j * NSER_HMC_MAX_BP_COUNT));
			for (i = pd_idx1; i < pd_lmt1; i++)
				nser_remove_pd_bp(dev, info->hmc_info, i);
			nser_prep_remove_pd_page(info->hmc_info, (j - 1));
			break;
		case NSER_SD_TYPE_DIRECT:
			nser_prep_remove_sd_bp(info->hmc_info, (j - 1));
			break;
		default:
			ret_code = -EINVAL;
			break;
		}
		j--;
	}

	return ret_code;
}

/**
 * nser_finish_del_sd_reg - delete sd entries for objects
 * @dev: pointer to the device structure
 * @info: dele obj info
 * @reset: true if called before reset
 */
static int nser_finish_del_sd_reg(struct nser_sc_dev *dev,
				   struct nser_hmc_del_obj_info *info,
				   bool reset)
{
	struct nser_hmc_sd_entry *sd_entry;
	int ret_code = 0;
	struct nser_dma_mem *mem;
	u32 i, sd_idx;

	for (i = 0; i < info->del_sd_cnt; i++) {
		sd_idx = info->hmc_info->sd_indexes[i];
		sd_entry = &info->hmc_info->sd_table.sd_entry[sd_idx];

		mem = (sd_entry->entry_type == NSER_SD_TYPE_PAGED) ?
		       &sd_entry->u.pd_table.pd_page_addr :
		       &sd_entry->u.bp.addr;

		if (!mem || !mem->va)
			nser_dbg(dev, "HMC: error cqp sd mem\n");
		else {
			dma_free_coherent(dev->hw->device, mem->size, mem->va,
					  mem->pa);
			mem->va = NULL;
		}
	}

	return ret_code;
}

/**
 * nser_sc_del_hmc_obj - remove pe hmc objects
 * @dev: pointer to the device structure
 * @info: pointer to nser_hmc_del_obj_info struct
 * @reset: true if called before reset
 *
 * This will de-populate the SDs and PDs.  It frees
 * the memory for PDS and backing storage.  After this function is returned,
 * caller should deallocate memory allocated previously for
 * book-keeping information about PDs and backing storage.
 */
int nser_sc_del_hmc_obj(struct nser_sc_dev *dev,
			 struct nser_hmc_del_obj_info *info, bool reset)
{
	struct nser_hmc_pd_table *pd_table;
	u32 sd_idx, sd_lmt;
	u32 pd_idx, pd_lmt, rel_pd_idx;
	u32 i, j;
	int ret_code = 0;

	if (info->hmc_info->mem_type == NSER_CHIP_MEM)
		return 0;

	if (info->start_idx >= info->hmc_info->hmc_obj[info->rsrc_type].cnt) {
		nser_dbg(dev,
			  "HMC: error start_idx[%04d]  >= [type %04d].cnt[%04d]\n",
			  info->start_idx, info->rsrc_type,
			  info->hmc_info->hmc_obj[info->rsrc_type].cnt);
		return -EINVAL;
	}

	if ((info->start_idx + info->count) >
	    info->hmc_info->hmc_obj[info->rsrc_type].cnt) {
		nser_dbg(dev,
			  "HMC: error start_idx[%04d] + count %04d  >= [type %04d].cnt[%04d]\n",
			  info->start_idx, info->count, info->rsrc_type,
			  info->hmc_info->hmc_obj[info->rsrc_type].cnt);
		return -EINVAL;
	}
	if (!dev->privileged) {
		if (!reset) {
			ret_code = nser_vchnl_vf_del_hmc_obj(dev, info->rsrc_type,
							      info->start_idx,
							      info->count);
		}
		if (info->rsrc_type != NSER_HMC_IW_PBLE)
			return ret_code;
	}

	nser_find_pd_index_limit(info->hmc_info, info->rsrc_type,
				  info->start_idx, info->count, &pd_idx,
				  &pd_lmt);

	for (j = pd_idx; j < pd_lmt; j++) {
		sd_idx = j / NSER_HMC_PD_CNT_IN_SD;

		if (!info->hmc_info->sd_table.sd_entry[sd_idx].valid)
			continue;

		if (info->hmc_info->sd_table.sd_entry[sd_idx].entry_type !=
		    NSER_SD_TYPE_PAGED)
			continue;

		rel_pd_idx = j % NSER_HMC_PD_CNT_IN_SD;
		pd_table = &info->hmc_info->sd_table.sd_entry[sd_idx].u.pd_table;
		if (pd_table->pd_entry &&
		    pd_table->pd_entry[rel_pd_idx].valid) {
			ret_code = nser_remove_pd_bp(dev, info->hmc_info, j);
			if (ret_code) {
				nser_dbg(dev, "HMC: remove_pd_bp error\n");
				return ret_code;
			}
		}
	}

	nser_find_sd_index_limit(info->hmc_info, info->rsrc_type,
				  info->start_idx, info->count, &sd_idx,
				  &sd_lmt);
	if (sd_idx >= info->hmc_info->sd_table.sd_cnt ||
	    sd_lmt > info->hmc_info->sd_table.sd_cnt) {
		nser_dbg(dev, "HMC: invalid sd_idx\n");
		return -EINVAL;
	}

	for (i = sd_idx; i < sd_lmt; i++) {
		pd_table = &info->hmc_info->sd_table.sd_entry[i].u.pd_table;
		if (!info->hmc_info->sd_table.sd_entry[i].valid)
			continue;
		switch (info->hmc_info->sd_table.sd_entry[i].entry_type) {
		case NSER_SD_TYPE_DIRECT:
			ret_code = nser_prep_remove_sd_bp(info->hmc_info, i);
			if (!ret_code) {
				info->hmc_info->sd_indexes[info->del_sd_cnt] =
					(u16)i;
				info->del_sd_cnt++;
			}
			break;
		case NSER_SD_TYPE_PAGED:
			ret_code = nser_prep_remove_pd_page(info->hmc_info, i);
			if (ret_code)
				break;
			if (dev->hmc_info != info->hmc_info &&
			    info->rsrc_type == NSER_HMC_IW_PBLE &&
			    pd_table->pd_entry) {
				kfree(pd_table->pd_entry_virt_mem.va);
				pd_table->pd_entry = NULL;
			}
			info->hmc_info->sd_indexes[info->del_sd_cnt] = (u16)i;
			info->del_sd_cnt++;
			break;
		default:
			break;
		}
	}
	return nser_finish_del_sd_reg(dev, info, reset);
}

/**
 * nser_add_sd_table_entry - Adds a segment descriptor to the table
 * @hw: pointer to our hw struct
 * @hmc_info: pointer to the HMC configuration information struct
 * @sd_index: segment descriptor index to manipulate
 * @type: what type of segment descriptor we're manipulating
 * @direct_mode_sz: size to alloc in direct mode
 */
int nser_add_sd_table_entry(struct nser_hw *hw,
			     struct nser_hmc_info *hmc_info, u32 sd_index,
			     enum nser_sd_entry_type type, u64 direct_mode_sz)
{
	struct nser_hmc_sd_entry *sd_entry;
	struct nser_dma_mem dma_mem;
	u64 alloc_len;

	sd_entry = &hmc_info->sd_table.sd_entry[sd_index];
	if (!sd_entry->valid) {
		if (type == NSER_SD_TYPE_PAGED)
			alloc_len = NSER_HMC_PAGED_BP_SIZE;
		else
			alloc_len = direct_mode_sz;

		/* allocate a 4K pd page or 2M backing page */
		dma_mem.size = ALIGN(alloc_len, NSER_HMC_PD_BP_BUF_ALIGNMENT);
		dma_mem.va = dma_alloc_coherent(hw->device, dma_mem.size,
						&dma_mem.pa, GFP_KERNEL);
		if (!dma_mem.va)
			return -ENOMEM;
		if (type == NSER_SD_TYPE_PAGED) {
			struct nser_virt_mem *vmem =
				&sd_entry->u.pd_table.pd_entry_virt_mem;

			vmem->size = sizeof(struct nser_hmc_pd_entry) * 512;
			vmem->va = kzalloc(vmem->size, GFP_KERNEL);
			if (!vmem->va) {
				dma_free_coherent(hw->device, dma_mem.size,
						  dma_mem.va, dma_mem.pa);
				dma_mem.va = NULL;
				return -ENOMEM;
			}
			sd_entry->u.pd_table.pd_entry = vmem->va;

			memcpy(&sd_entry->u.pd_table.pd_page_addr, &dma_mem,
			       sizeof(sd_entry->u.pd_table.pd_page_addr));
		} else {
			memcpy(&sd_entry->u.bp.addr, &dma_mem,
			       sizeof(sd_entry->u.bp.addr));

			sd_entry->u.bp.sd_pd_index = sd_index;
		}

		hmc_info->sd_table.sd_entry[sd_index].entry_type = type;
		hmc_info->sd_table.use_cnt++;
	}
	if (sd_entry->entry_type == NSER_SD_TYPE_DIRECT)
		sd_entry->u.bp.use_cnt++;

	return 0;
}

/**
 * nser_add_pd_table_entry - Adds page descriptor to the specified table
 * @dev: pointer to our device structure
 * @hmc_info: pointer to the HMC configuration information structure
 * @pd_index: which page descriptor index to manipulate
 * @rsrc_pg: if not NULL, use preallocated page instead of allocating new one.
 *
 * This function:
 *	1. Initializes the pd entry
 *	2. Adds pd_entry in the pd_table
 *	3. Mark the entry valid in nser_hmc_pd_entry structure
 *	4. Initializes the pd_entry's ref count to 1
 * assumptions:
 *	1. The memory for pd should be pinned down, physically contiguous and
 *	   aligned on 4K boundary and zeroed memory.
 *	2. It should be 4K in size.
 */
int nser_add_pd_table_entry(struct nser_sc_dev *dev,
			     struct nser_hmc_info *hmc_info, u32 pd_index,
			     struct nser_dma_mem *rsrc_pg)
{
	struct nser_hmc_pd_table *pd_table;
	struct nser_hmc_pd_entry *pd_entry;
	struct nser_dma_mem mem;
	struct nser_dma_mem *page = &mem;
	u32 sd_idx, rel_pd_idx;
	u64 *pd_addr;
	u64 page_desc;

	if (pd_index / NSER_HMC_PD_CNT_IN_SD >= hmc_info->sd_table.sd_cnt)
		return -EINVAL;

	sd_idx = (pd_index / NSER_HMC_PD_CNT_IN_SD);
	if (hmc_info->sd_table.sd_entry[sd_idx].entry_type !=
	    NSER_SD_TYPE_PAGED)
		return 0;

	rel_pd_idx = (pd_index % NSER_HMC_PD_CNT_IN_SD);
	pd_table = &hmc_info->sd_table.sd_entry[sd_idx].u.pd_table;
	pd_entry = &pd_table->pd_entry[rel_pd_idx];
	if (!pd_entry->valid) {
		if (rsrc_pg) {
			pd_entry->rsrc_pg = true;
			page = rsrc_pg;
		} else {
			page->size = ALIGN(NSER_HMC_PAGED_BP_SIZE,
					   NSER_HMC_PD_BP_BUF_ALIGNMENT);
			page->va = dma_alloc_coherent(dev->hw->device,
						      page->size, &page->pa,
						      GFP_KERNEL);
			if (!page->va)
				return -ENOMEM;

			pd_entry->rsrc_pg = false;
		}

		memcpy(&pd_entry->bp.addr, page, sizeof(pd_entry->bp.addr));
		pd_entry->bp.sd_pd_index = pd_index;
		pd_entry->bp.entry_type = NSER_SD_TYPE_PAGED;
		page_desc = page->pa | 0x1;
		pd_addr = pd_table->pd_page_addr.va;
		pd_addr += rel_pd_idx;
		memcpy(pd_addr, &page_desc, sizeof(*pd_addr));
		pd_entry->sd_index = sd_idx;
		pd_entry->valid = true;
		pd_table->use_cnt++;
	}
	pd_entry->bp.use_cnt++;

	return 0;
}

/**
 * nser_remove_pd_bp - remove a backing page from a page descriptor
 * @dev: pointer to our HW structure
 * @hmc_info: pointer to the HMC configuration information structure
 * @idx: the page index
 *
 * This function:
 *	1. Marks the entry in pd table (for paged address mode) or in sd table
 *	   (for direct address mode) invalid.
 *	2. Write to register PMPDINV to invalidate the backing page in FV cache
 *	3. Decrement the ref count for the pd _entry
 * assumptions:
 *	1. Caller can deallocate the memory used by backing storage after this
 *	   function returns.
 */
int nser_remove_pd_bp(struct nser_sc_dev *dev,
		       struct nser_hmc_info *hmc_info, u32 idx)
{
	struct nser_hmc_pd_entry *pd_entry;
	struct nser_hmc_pd_table *pd_table;
	struct nser_hmc_sd_entry *sd_entry;
	u32 sd_idx, rel_pd_idx;
	struct nser_dma_mem *mem;
	u64 *pd_addr;

	sd_idx = idx / NSER_HMC_PD_CNT_IN_SD;
	rel_pd_idx = idx % NSER_HMC_PD_CNT_IN_SD;
	if (sd_idx >= hmc_info->sd_table.sd_cnt)
		return -EINVAL;

	sd_entry = &hmc_info->sd_table.sd_entry[sd_idx];
	if (sd_entry->entry_type != NSER_SD_TYPE_PAGED)
		return -EINVAL;

	pd_table = &hmc_info->sd_table.sd_entry[sd_idx].u.pd_table;
	pd_entry = &pd_table->pd_entry[rel_pd_idx];
	if (--pd_entry->bp.use_cnt)
		return 0;

	pd_entry->valid = false;
	pd_table->use_cnt--;
	pd_addr = pd_table->pd_page_addr.va;
	pd_addr += rel_pd_idx;
	memset(pd_addr, 0, sizeof(u64));

	if (!pd_entry->rsrc_pg) {
		mem = &pd_entry->bp.addr;
		if (!mem || !mem->va)
			return -EINVAL;

		dma_free_coherent(dev->hw->device, mem->size, mem->va,
				  mem->pa);
		mem->va = NULL;
	}
	if (!pd_table->use_cnt)
		kfree(pd_table->pd_entry_virt_mem.va);

	return 0;
}

/**
 * nser_prep_remove_sd_bp - Prepares to remove a backing page from a sd entry
 * @hmc_info: pointer to the HMC configuration information structure
 * @idx: the page index
 */
int nser_prep_remove_sd_bp(struct nser_hmc_info *hmc_info, u32 idx)
{
	struct nser_hmc_sd_entry *sd_entry;

	sd_entry = &hmc_info->sd_table.sd_entry[idx];
	if (--sd_entry->u.bp.use_cnt)
		return -EBUSY;

	hmc_info->sd_table.use_cnt--;
	sd_entry->valid = false;

	return 0;
}

/**
 * nser_prep_remove_pd_page - Prepares to remove a PD page from sd entry.
 * @hmc_info: pointer to the HMC configuration information structure
 * @idx: segment descriptor index to find the relevant page descriptor
 */
int nser_prep_remove_pd_page(struct nser_hmc_info *hmc_info, u32 idx)
{
	struct nser_hmc_sd_entry *sd_entry;

	sd_entry = &hmc_info->sd_table.sd_entry[idx];

	if (sd_entry->u.pd_table.use_cnt)
		return -EBUSY;

	sd_entry->valid = false;
	hmc_info->sd_table.use_cnt--;

	return 0;
}

/**
 * nser_pf_init_vfhmc -
 * @dev: pointer to nser_dev struct
 * @vf_hmc_fn_id: hmc function id for vf driver
 *
 * Called by pf driver to initialize hmc_info for vf driver instance.
 */
int nser_pf_init_vfhmc(struct nser_sc_dev *dev, u8 vf_hmc_fn_id)
{
	return nser_sc_init_iw_hmc(dev, vf_hmc_fn_id);
}

