// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (C), 2020, sxe2rdma Technologies Co., Ltd.
 *
 * @file: sxe2_drv_rcms_debugfs.c
 * @author: sxe2rdma
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#include <linux/debugfs.h>
#include "sxe2_compat.h"
#ifdef NOT_SUPPORT_AUXILIARY_BUS
#include "auxiliary_bus.h"
#else
#include <linux/auxiliary_bus.h>
#endif
#include "sxe2_drv_rdma_log.h"
#include "sxe2_drv_rdma_debugfs.h"
#include "sxe2_drv_rdma_rcms.h"
#include "sxe2_drv_rcms_debugfs.h"

u64 sxe2_rcms_num_to_liner_addr(struct sxe2_rcms_info *rcms_info, u32 obj_type,
				u32 obj_num)
{
	u64 liner_addr;

	liner_addr = rcms_info->rcms_obj[obj_type].base +
		     obj_num * rcms_info->rcms_obj[obj_type].size;
	return liner_addr;
}

int sxe2_rcms_num_to_ctx_va_pointer(struct sxe2_rdma_device *rdma_dev,
				    u32 obj_type, u32 obj_num,
				    void **va_pointer)
{
	int ret = SXE2_OK;
	struct sxe2_rcms_info *rcms_info =
		rdma_dev->rdma_func->ctx_dev.rcms_info;
	u64 liner_addr;
	u32 fpte_idx;
	u32 spte_idx;
	struct sxe2_rcms_fpt_entry *fpte;
	struct sxe2_rcms_spt_entry *spte;
	u8 *byte_pointer;
	u32 cp_offset;

	if (obj_type >= SXE2_RCMS_OBJ_MAX) {
		DRV_RDMA_LOG_DEV_ERR(
			"rcms debugfs:num to ctx va input obj type err obj type=%u\n",
			obj_type);
		ret = -EINVAL;
		goto end;
	}

	if (obj_type == SXE2_RCMS_OBJ_RESP && obj_type == SXE2_RCMS_OBJ_SSNT &&
	    obj_type == SXE2_RCMS_OBJ_IRRL &&
	    obj_type == SXE2_RCMS_OBJ_ACK_TIMEOUT) {
		DRV_RDMA_LOG_DEV_ERR(
			"rcms debugfs:num to ctx va input obj type err obj type=%u\n",
			obj_type);
		ret = -EINVAL;
		goto end;
	}

	if (obj_num >= rcms_info->rcms_obj[obj_type].cnt) {
		DRV_RDMA_LOG_DEV_ERR(
			"rcms debugfs:num to ctx va input obj num err obj num=%u max num=%u\n",
			obj_num, rcms_info->rcms_obj[obj_type].cnt - 1);
		ret = -EINVAL;
		goto end;
	}

	liner_addr = sxe2_rcms_num_to_liner_addr(rcms_info, obj_type, obj_num);
	fpte_idx   = FPT_INDEX_GET(liner_addr);
	fpte	   = &(rcms_info->fpt.fpte[fpte_idx]);

	if (!fpte || !fpte->valid) {
		DRV_RDMA_LOG_DEV_ERR(
			"rcms debugfs:num to ctx va fpte valid err or fpte is null fpte idx=%u\n",
			fpte_idx);
		ret = -EINVAL;
		goto end;
	}

	if (fpte->entry_type == SXE2_RCMS_FPT_TYPE_FIRST) {
		cp_offset    = FIST_PAGE_TABLE_CP_OFFSET_GET(liner_addr);
		byte_pointer = (u8 *)(fpte->u.cp.page_addr.va);
		byte_pointer += cp_offset;
		DRV_RDMA_LOG_DEV_DEBUG(
			"rcms debugfs:obj %u num %u\n"
			"\tliner addr=%#llx fpte idx=%u entry type=%u va=%p\n",
			obj_type, obj_num, liner_addr, fpte_idx,
			fpte->entry_type, byte_pointer);
		*va_pointer = (void *)byte_pointer;
	} else {
		spte_idx = LINER_ADDR_TO_REL_SPT_IDX(liner_addr);
		spte	 = &(fpte->u.spt.spte[spte_idx]);
		if (!spte->valid) {
			DRV_RDMA_LOG_DEV_ERR(
				"rcms debugfs:num to ctx va spte valid err spte idx=%u\n",
				spte_idx);
			ret = -EINVAL;
			goto end;
		} else {
			cp_offset = SECOND_PAGE_TABLE_CP_OFFSET_GET(liner_addr);
			byte_pointer = (u8 *)(spte->cp.page_addr.va);
			byte_pointer += cp_offset;
			DRV_RDMA_LOG_DEV_DEBUG(
				"rcms debugfs:obj %u num %u\n"
				"\tliner addr=%#llx fpte idx=%u spte idx=%u va=%p\n",
				obj_type, obj_num, liner_addr, fpte_idx,
				spte_idx, byte_pointer);
			*va_pointer = (void *)byte_pointer;
		}
	}

end:
	return ret;
}

static ssize_t drv_rdma_rcms_info_read(struct file *filp, char __user *buf,
				       size_t count, loff_t *off)
{
	ssize_t ret	 = SXE2_OK;
	size_t len_total = 0;
	char *rsp	 = NULL;
	char *rsp_end;
	int i;
	struct sxe2_rdma_device *rdma_dev;
	struct sxe2_rdma_ctx_dev *dev;
	struct sxe2_rcms_info *rcms_info;

	if (*off != 0)
		goto end;

	rdma_dev = (struct sxe2_rdma_device *)filp->private_data;
	if (!rdma_dev) {
		ret = -ENXIO;
		DRV_RDMA_LOG_ERROR(
			"rcms debugfs:find dev struct from private_data failed err\n");
		goto end;
	}

	dev	  = &rdma_dev->rdma_func->ctx_dev;
	rcms_info = dev->rcms_info;

	rsp = kzalloc(sizeof(char) * SXE2_DEBUG_DUMP_BUF_SIZE,
			      GFP_KERNEL);
	if (!rsp) {
		ret = -ENOMEM;
		DRV_RDMA_LOG_DEV_ERR(
			"rcms debugfs:rcms info rsp kmalloc failed err\n");
		goto end;
	}
	rsp_end = rsp;

	len_total += dbg_vsnprintf(rsp_end, len_total, "rcms info:\n");
	len_total +=
		dbg_vsnprintf(rsp_end, len_total,
			      "privileged=%u rcms fn id=%u ctx init mode=%u\n",
			      dev->privileged, rcms_info->rcms_fn_id,
			      rdma_dev->rdma_func->rcms_mode.ctx_mode);
	len_total += dbg_vsnprintf(rsp_end, len_total, "first fpte index=%u\n",
				   rcms_info->first_fpte_index);
	len_total +=
		dbg_vsnprintf(rsp_end, len_total, "ctx max fpte index=%u\n",
			      rcms_info->max_fpte_index);
	len_total += dbg_vsnprintf(rsp_end, len_total, "func max fpte cnt=%u\n",
				   rcms_info->max_fpte_cnt);
	len_total +=
		dbg_vsnprintf(rsp_end, len_total, "ctx fpte needed cnt=%u\n",
			      rcms_info->fpte_needed);
	len_total += dbg_vsnprintf(rsp_end, len_total, "1GB fpte cnt=%u\n",
				   rcms_info->first_page_fpte);
	len_total += dbg_vsnprintf(rsp_end, len_total, "max ceqs=%u\n",
				   rcms_info->max_ceqs);
	len_total += dbg_vsnprintf(rsp_end, len_total, "max db page num=%u\n",
				   rcms_info->max_db_page_num);
	len_total += dbg_vsnprintf(rsp_end, len_total, "db bar addr=0x%x\n",
				   rcms_info->db_bar_addr);
	len_total += dbg_vsnprintf(rsp_end, len_total, "max cc qp=%u\n",
				   rcms_info->max_cc_qp_cnt);
	len_total += dbg_vsnprintf(rsp_end, len_total, "create mode=%u\n",
				   rcms_info->create_mode);
	for (i = SXE2_RCMS_OBJ_QP; i < SXE2_RCMS_OBJ_MAX; i++) {
		len_total += dbg_vsnprintf(
			rsp_end, len_total,
			"obj %u max cnt=%u cnt=%u size=%u liner addr base=0x%llx\n",
			i, rcms_info->rcms_obj[i].max_cnt,
			rcms_info->rcms_obj[i].cnt, rcms_info->rcms_obj[i].size,
			rcms_info->rcms_obj[i].base);
	}

	ret = (ssize_t)simple_read_from_buffer(buf, count, off, rsp,
					       (size_t)len_total);
	if (ret < 0) {
		DRV_RDMA_LOG_DEV_ERR("rcms debugfs:simple read error %zu\n",
				     ret);
	}

	kfree(rsp);
	rsp = NULL;

end:
	return ret;
}

static const struct file_operations sxe2_rdma_rcms_info_fops = {
	.owner = THIS_MODULE,
	.open  = simple_open,
	.read  = drv_rdma_rcms_info_read,
};

static ssize_t drv_rdma_pbl_info_read(struct file *filp, char __user *buf,
				      size_t count, loff_t *off)
{
	ssize_t ret	 = SXE2_OK;
	size_t len_total = 0;
	char *rsp	 = NULL;
	char *rsp_end;
	struct sxe2_rdma_device *rdma_dev;
	struct sxe2_pbl_pble_rsrc *pble_rsrc;

	if (*off != 0)
		goto end;

	rdma_dev = (struct sxe2_rdma_device *)filp->private_data;
	if (!rdma_dev) {
		ret = -ENXIO;
		DRV_RDMA_LOG_ERROR(
			"rcms debugfs:find dev struct from private_data failed err\n");
		goto end;
	}

	pble_rsrc = rdma_dev->rdma_func->pble_rsrc;

	rsp = kzalloc(sizeof(char) * SXE2_DEBUG_DUMP_BUF_SIZE,
			      GFP_KERNEL);
	if (!rsp) {
		ret = -ENOMEM;
		DRV_RDMA_LOG_DEV_ERR(
			"rcms debugfs:rcms info rsp kmalloc failed err\n");
		goto end;
	}
	rsp_end = rsp;

	len_total += dbg_vsnprintf(rsp_end, len_total, "pbl info:\n");
	len_total += dbg_vsnprintf(rsp_end, len_total,
				   "privileged=%u pbl init mode=%u\n",
				   pble_rsrc->dev->privileged,
				   rdma_dev->rdma_func->rcms_mode.pbl_mode);
	len_total +=
		dbg_vsnprintf(rsp_end, len_total, "alloced normal pble=%u\n",
			      pble_rsrc->allocated_pbles);
	len_total += dbg_vsnprintf(rsp_end, len_total,
				   "unallocated normal pble=%u\n",
				   pble_rsrc->unallocated_pble);
	len_total += dbg_vsnprintf(rsp_end, len_total, "pble base addr=%#llx\n",
				   pble_rsrc->pble_base_addr);
	len_total += dbg_vsnprintf(rsp_end, len_total,
				   "alloc pble base addr=%#llx\n",
				   pble_rsrc->alloc_pble_base_addr);
	len_total +=
		dbg_vsnprintf(rsp_end, len_total, "second type fpte cnt=%u\n",
			      pble_rsrc->second_type_fpte_cnt);
	len_total +=
		dbg_vsnprintf(rsp_end, len_total, "third type fpte cnt=%u\n",
			      pble_rsrc->third_type_fpte_cnt);
	if (pble_rsrc->first_page_en) {
		len_total += dbg_vsnprintf(
			rsp_end, len_total, "1GB fpte cnt=%u\n",
			pble_rsrc->first_page_bitmap.max_fpte_cnt);
		len_total += dbg_vsnprintf(
			rsp_end, len_total, "1GB fpte start fpte idx=%u\n",
			pble_rsrc->first_page_bitmap.first_fpte_idx);
		len_total +=
			dbg_vsnprintf(rsp_end, len_total,
				      "allocated 1GB fpte cnt=%u\n",
				      pble_rsrc->allocated_first_type_fpte_cnt);
		len_total += dbg_vsnprintf(
			rsp_end, len_total, "unallocated 1GB fpte cnt=%u\n",
			pble_rsrc->unallocated_first_type_fpte_cnt);
	} else {
		len_total += dbg_vsnprintf(rsp_end, len_total,
					   "not support 1 GB page\n");
	}
	ret = (ssize_t)simple_read_from_buffer(buf, count, off, rsp, len_total);
	if (ret < 0) {
		DRV_RDMA_LOG_DEV_ERR("rcms debugfs:simple read error %zu\n",
				     ret);
	}

	kfree(rsp);
	rsp = NULL;

end:
	return ret;
}

static const struct file_operations sxe2_rdma_pbl_info_fops = {
	.owner = THIS_MODULE,
	.open  = simple_open,
	.read  = drv_rdma_pbl_info_read,
};

#ifdef SXE2_CFG_DEBUG
static ssize_t drv_rdma_rcms_read_fpte_write(struct file *filp,
					     const char __user *buf,
					     size_t count, loff_t *off)
{
	ssize_t ret				 = SXE2_OK;
	char cmd[RCMS_DEBUGFS_WRITE_BUF_MAX_LEN] = { 0 };
	struct sxe2_rdma_device *rdma_dev;
	u32 fpte_idx;
	u32 fpte_cnt;
	struct sxe2_rcms_info *rcms_info;

	if (*off != 0)
		goto end;

	if (count >= RCMS_DEBUGFS_WRITE_BUF_MAX_LEN) {
		ret = -ENOSPC;
		DRV_RDMA_LOG_ERROR(
			"rcms debugfs:cmd exceeded length limit err\n");
		goto end;
	}

	rdma_dev = (struct sxe2_rdma_device *)filp->private_data;
	if (!rdma_dev) {
		ret = -ENXIO;
		DRV_RDMA_LOG_ERROR("rcms debugfs:dev find failed err\n");
		goto end;
	}
	rcms_info = rdma_dev->rdma_func->ctx_dev.rcms_info;

	if (copy_from_user(cmd, buf, count)) {
		ret = -EFAULT;
		DRV_RDMA_LOG_DEV_ERR(
			"rcms debugfs:Cmd copy from user failed err\n");
		goto end;
	}
	ret = sscanf(cmd, "%u:%u", &fpte_idx, &fpte_cnt);
	if (ret != 2) {
		ret = -ENODATA;
		DRV_RDMA_LOG_DEV_ERR(
			"rcms debugfs:analyze cmd err please input fpte_idx:cnt\n");
		goto end;
	}

	DRV_RDMA_LOG_DEV_DEBUG("rcms debugfs:input fpte idx=%u fpte cnt=%u\n",
			       fpte_idx, fpte_cnt);
	if (fpte_idx < rcms_info->first_fpte_index ||
	    fpte_idx > rcms_info->max_fpte_index) {
		DRV_RDMA_LOG_DEV_ERR(
			"rcms debugfs:input fpte idx err func idx range %u - %u\n,",
			rcms_info->first_fpte_index,
			fpte_idx > rcms_info->max_fpte_index);
		ret = -EINVAL;
		goto end;
	}
	rcms_info->read_fpte_input.fpte_idx = fpte_idx;

	if (fpte_cnt > rcms_info->fpte_needed) {
		DRV_RDMA_LOG_DEV_ERR(
			"rcms debugfs:input fpte cnt err func fpte needed=%u\n",
			rcms_info->fpte_needed);
		ret = -EINVAL;
		goto end;
	}

	if (fpte_cnt > RCMS_DEBUGFS_READ_FPTE_MAX_CNT) {
		DRV_RDMA_LOG_DEV_ERR(
			"rcms debugfs:input fpte cnt support cnt=%u\n",
			RCMS_DEBUGFS_READ_FPTE_MAX_CNT);
		fpte_cnt = RCMS_DEBUGFS_READ_FPTE_MAX_CNT;
	}
	rcms_info->read_fpte_input.fpte_cnt = fpte_cnt;

	ret  = (ssize_t)count;
	*off = (loff_t)count;

end:
	return ret;
}

static ssize_t drv_rdma_rcms_read_fpte_read(struct file *filp, char __user *buf,
					    size_t count, loff_t *off)
{
	ssize_t ret	 = SXE2_OK;
	size_t len_total = 0;
	char *rsp	 = NULL;
	char *rsp_end;
	u32 i;
	struct sxe2_rdma_device *rdma_dev;
	struct sxe2_rcms_info *rcms_info;
	u32 fpte_idx;
	u32 fpte_cnt;
	struct sxe2_rcms_fpt_entry *fpte;

	if (*off != 0)
		goto end;

	rdma_dev = (struct sxe2_rdma_device *)filp->private_data;
	if (!rdma_dev) {
		ret = -ENXIO;
		DRV_RDMA_LOG_ERROR(
			"rcms debugfs:find dev struct from private_data failed err\n");
		goto end;
	}

	rcms_info = rdma_dev->rdma_func->ctx_dev.rcms_info;
	fpte_idx  = rcms_info->read_fpte_input.fpte_idx;
	fpte_cnt  = rcms_info->read_fpte_input.fpte_cnt;

	rsp = kzalloc(sizeof(char) * SXE2_DEBUG_DUMP_BUF_SIZE,
			      GFP_KERNEL);
	if (!rsp) {
		ret = -ENOMEM;
		DRV_RDMA_LOG_DEV_ERR(
			"rcms debugfs:rcms info rsp kmalloc failed err\n");
		goto end;
	}
	rsp_end = rsp;
	for (i = 0; i < fpte_cnt; i++) {
		len_total += dbg_vsnprintf(rsp_end, len_total,
					   "fpte idx %u info:\n", fpte_idx);
		fpte = &(rcms_info->fpt.fpte[fpte_idx]);
		if (!fpte || !fpte->valid) {
			len_total += dbg_vsnprintf(
				rsp_end, len_total,
				"fpte is invalid or ptr is null\n");
		} else {
			len_total += dbg_vsnprintf(rsp_end, len_total,
						   "fpte entry type=%u\n",
						   fpte->entry_type);
			if (fpte->entry_type == SXE2_RCMS_FPT_TYPE_SECOND) {
				len_total += dbg_vsnprintf(
					rsp_end, len_total,
					"spt page pa=%#llx\n",
					fpte->u.spt.spt_page_addr.pa);
				len_total += dbg_vsnprintf(rsp_end, len_total,
							   "spt use cnt=%u\n",
							   fpte->u.spt.use_cnt);
			} else {
				len_total +=
					dbg_vsnprintf(rsp_end, len_total,
						      "cp page pa=%#llx\n",
						      fpte->u.cp.page_addr.pa);
				len_total += dbg_vsnprintf(rsp_end, len_total,
							   "cp use cnt=%u\n",
							   fpte->u.cp.use_cnt);
			}
		}
		len_total += dbg_vsnprintf(rsp_end, len_total,
					   "---------------------\n");
		fpte_idx++;
	}

	ret = (ssize_t)simple_read_from_buffer(buf, count, off, rsp, len_total);
	if (ret < 0) {
		DRV_RDMA_LOG_DEV_ERR("rcms debugfs:simple read error %zu\n",
				     ret);
	}

	kfree(rsp);
	rsp = NULL;

end:
	return ret;
}

static const struct file_operations sxe2_rdma_rcms_read_fpte_fops = {
	.owner = THIS_MODULE,
	.open  = simple_open,
	.read  = drv_rdma_rcms_read_fpte_read,
	.write = drv_rdma_rcms_read_fpte_write,
};

static ssize_t drv_rdma_rcms_read_spte_write(struct file *filp,
					     const char __user *buf,
					     size_t count, loff_t *off)
{
	ssize_t ret				 = SXE2_OK;
	char cmd[RCMS_DEBUGFS_WRITE_BUF_MAX_LEN] = { 0 };
	struct sxe2_rdma_device *rdma_dev;
	u32 fpte_idx;
	u32 spte_idx;
	u32 spte_cnt;
	struct sxe2_rcms_info *rcms_info;

	if (*off != 0)
		goto end;

	if (count >= RCMS_DEBUGFS_WRITE_BUF_MAX_LEN) {
		ret = -ENOSPC;
		DRV_RDMA_LOG_ERROR(
			"rcms debugfs:cmd exceeded length limit err\n");
		goto end;
	}

	rdma_dev = (struct sxe2_rdma_device *)filp->private_data;
	if (!rdma_dev) {
		ret = -ENXIO;
		DRV_RDMA_LOG_ERROR("rcms debugfs:dev find failed err\n");
		goto end;
	}
	rcms_info = rdma_dev->rdma_func->ctx_dev.rcms_info;

	if (copy_from_user(cmd, buf, count)) {
		ret = -EFAULT;
		DRV_RDMA_LOG_DEV_ERR(
			"rcms debugfs:Cmd copy from user failed err\n");
		goto end;
	}
	ret = sscanf(cmd, "%u:%u:%u", &fpte_idx, &spte_idx, &spte_cnt);
	if (ret != 3) {
		ret = -ENODATA;
		DRV_RDMA_LOG_DEV_ERR(
			"rcms debugfs:analyze cmd err please input fpte_idx=1 spte_idx=1 cnt=1\n");
		goto end;
	}
	DRV_RDMA_LOG_DEV_DEBUG(
		"rcms debugfs:input fpte idx=%u spte idx=%u spte cnt=%u\n",
		fpte_idx, spte_idx, spte_cnt);
	if (fpte_idx < rcms_info->first_fpte_index ||
	    fpte_idx > rcms_info->max_fpte_index) {
		DRV_RDMA_LOG_DEV_ERR(
			"rcms debugfs:input fpte idx err func idx range %u - %u\n,",
			rcms_info->first_fpte_index,
			fpte_idx > rcms_info->max_fpte_index);
		ret = -EINVAL;
		goto end;
	}
	rcms_info->read_spte_input.fpte_idx = fpte_idx;
	if (spte_idx > RCMS_DEBUGFS_SPTE_MAX_IDX) {
		DRV_RDMA_LOG_DEV_ERR(
			"rcms debugfs:input spte idx err func idx range 0 - 512\n");
		ret = -EINVAL;
		goto end;
	}
	rcms_info->read_spte_input.spte_idx = spte_idx;
	if (spte_cnt > RCMS_DEBUGFS_READ_SPTE_MAXCNT) {
		DRV_RDMA_LOG_DEV_ERR(
			"rcms debugfs:input fpte cnt support cnt=%u\n",
			RCMS_DEBUGFS_READ_SPTE_MAXCNT);
		spte_cnt = RCMS_DEBUGFS_READ_SPTE_MAXCNT;
	}

	rcms_info->read_spte_input.spte_cnt = spte_cnt;

	ret  = (ssize_t)count;
	*off = (loff_t)count;

end:
	return ret;
}

static ssize_t drv_rdma_rcms_read_spte_read(struct file *filp, char __user *buf,
					    size_t count, loff_t *off)
{
	ssize_t ret	 = SXE2_OK;
	size_t len_total = 0;
	char *rsp	 = NULL;
	char *rsp_end;
	u32 i;
	struct sxe2_rdma_device *rdma_dev;
	struct sxe2_rcms_info *rcms_info;
	u32 fpte_idx;
	u32 spte_idx;
	u32 spte_cnt;
	struct sxe2_rcms_fpt_entry *fpte;
	struct sxe2_rcms_spt_entry *spte;

	if (*off != 0)
		goto end;

	rdma_dev = (struct sxe2_rdma_device *)filp->private_data;
	if (!rdma_dev) {
		ret = -ENXIO;
		DRV_RDMA_LOG_ERROR(
			"rcms debugfs:find dev struct from private_data failed err\n");
		goto end;
	}

	rcms_info = rdma_dev->rdma_func->ctx_dev.rcms_info;
	fpte_idx  = rcms_info->read_spte_input.fpte_idx;
	spte_idx  = rcms_info->read_spte_input.spte_idx;
	spte_cnt  = rcms_info->read_spte_input.spte_cnt;

	rsp = kzalloc(sizeof(char) * SXE2_DEBUG_DUMP_BUF_SIZE,
			      GFP_KERNEL);
	if (!rsp) {
		ret = -ENOMEM;
		DRV_RDMA_LOG_DEV_ERR(
			"rcms debugfs:rcms info rsp kmalloc failed err\n");
		goto end;
	}
	rsp_end = rsp;
	fpte	= &(rcms_info->fpt.fpte[fpte_idx]);
	if (!fpte || !fpte->valid ||
	    fpte->entry_type != SXE2_RCMS_FPT_TYPE_SECOND) {
		len_total += dbg_vsnprintf(
			rsp_end, len_total,
			"fpte ptr is null or fpte is invalid or entry type is first type\n");
	} else {
		for (i = 0; i < spte_cnt; i++) {
			len_total +=
				dbg_vsnprintf(rsp_end, len_total,
					      "fpte idx %u spte idx %u info:\n",
					      fpte_idx, spte_idx);
			spte = &(fpte->u.spt.spte[i]);
			if (!spte->valid) {
				len_total += dbg_vsnprintf(rsp_end, len_total,
							   "spte is invalid\n");
			} else {
				len_total +=
					dbg_vsnprintf(rsp_end, len_total,
						      "cp page pa=%#llx\n",
						      spte->cp.page_addr.pa);
				len_total +=
					dbg_vsnprintf(rsp_end, len_total,
						      "cp page use cnt=%u\n",
						      spte->cp.use_cnt);
			}
			len_total += dbg_vsnprintf(rsp_end, len_total,
						   "---------------------\n");
			spte_idx++;
		}
	}
	ret = (ssize_t)simple_read_from_buffer(buf, count, off, rsp, len_total);
	if (ret < 0) {
		DRV_RDMA_LOG_DEV_ERR("rcms debugfs:simple read error %zu\n",
				     ret);
	}

	kfree(rsp);
	rsp = NULL;

end:
	return ret;
}

static const struct file_operations sxe2_rdma_rcms_read_spte_fops = {
	.owner = THIS_MODULE,
	.open  = simple_open,
	.read  = drv_rdma_rcms_read_spte_read,
	.write = drv_rdma_rcms_read_spte_write,
};

static ssize_t drv_rdma_rcms_read_liner_addr_write(struct file *filp,
						   const char __user *buf,
						   size_t count, loff_t *off)
{
	ssize_t ret				 = SXE2_OK;
	char cmd[RCMS_DEBUGFS_WRITE_BUF_MAX_LEN] = { 0 };
	struct sxe2_rdma_device *rdma_dev;
	u64 liner_addr;
	u32 size;
	u32 fpte_idx;
	struct sxe2_rcms_info *rcms_info;

	if (*off != 0)
		goto end;

	if (count >= RCMS_DEBUGFS_WRITE_BUF_MAX_LEN) {
		ret = -ENOSPC;
		DRV_RDMA_LOG_ERROR(
			"rcms debugfs:cmd exceeded length limit err\n");
		goto end;
	}

	rdma_dev = (struct sxe2_rdma_device *)filp->private_data;
	if (!rdma_dev) {
		ret = -ENXIO;
		DRV_RDMA_LOG_ERROR("rcms debugfs:dev find failed err\n");
		goto end;
	}
	rcms_info = rdma_dev->rdma_func->ctx_dev.rcms_info;

	if (copy_from_user(cmd, buf, count)) {
		ret = -EFAULT;
		DRV_RDMA_LOG_DEV_ERR(
			"rcms debugfs:cmd copy from user failed err\n");
		goto end;
	}

	ret = sscanf(cmd, "%llx:%u", &liner_addr, &size);
	if (ret != 2) {
		ret = -ENODATA;
		DRV_RDMA_LOG_DEV_ERR(
			"rcms debugfs:analyze cmd err please input liner_addr=0xFF size=1024\n");
		goto end;
	}
	DRV_RDMA_LOG_DEV_DEBUG("rcms debugfs:input liner addr=%#llx size=%u\n",
			       liner_addr, size);
	fpte_idx = FPT_INDEX_GET(liner_addr);

	if (fpte_idx < rcms_info->first_fpte_index ||
	    fpte_idx > rcms_info->max_fpte_index) {
		DRV_RDMA_LOG_DEV_ERR(
			"rcms debugfs:intput liner addr idx err fpte idx=%u func idx range %u - %u\n",
			fpte_idx, rcms_info->first_fpte_index,
			fpte_idx > rcms_info->max_fpte_index);
		ret = -EINVAL;
		goto end;
	}
	rcms_info->read_liner_addr_input.liner_addr = liner_addr;
	if (size > RCMS_DEBUGFS_READ_LINER_ADDR_MAX_SIZE) {
		DRV_RDMA_LOG_DEV_ERR(
			"rcms debugfs:input liner addr support 1024B\n");
		size = RCMS_DEBUGFS_READ_LINER_ADDR_MAX_SIZE;
	}

	rcms_info->read_liner_addr_input.size = size;

	ret  = (ssize_t)count;
	*off = (loff_t)count;

end:
	return ret;
}

static void drv_rdma_rcms_print_liner_addr(struct sxe2_rdma_device *rdma_dev,
					   u64 liner_addr,
					   struct sxe2_rcms_fpt_entry *fpte,
					   u32 *len_total, char *rsp_end)
{
	u32 i, j;
	u8 *byte_pointer;
	u32 cp_offset;
	u64 size;
	u32 fpte_idx;
	u32 spte_idx;
	struct sxe2_rcms_spt_entry *spte;

	size = rdma_dev->rdma_func->ctx_dev.rcms_info->read_liner_addr_input
		       .size;
	fpte_idx = FPT_INDEX_GET(liner_addr);
	if (fpte->entry_type == SXE2_RCMS_FPT_TYPE_FIRST) {
		*len_total += dbg_vsnprintf(
			rsp_end, *len_total,
			"liner addr to fpte idx=%u entry type=%u\n", fpte_idx,
			fpte->entry_type);
		cp_offset    = FIST_PAGE_TABLE_CP_OFFSET_GET(liner_addr);
		byte_pointer = (u8 *)(fpte->u.cp.page_addr.va);
		byte_pointer += cp_offset;
		*len_total +=
			dbg_vsnprintf(rsp_end, *len_total,
				      "cp offset=%x liner addr to pa=%#llx\n",
				      cp_offset,
				      fpte->u.cp.page_addr.pa + cp_offset);
		size = (RCMS_DEBUGFS_2M_PAGE_MAX_OFFSET - cp_offset) <= size ?
			       (RCMS_DEBUGFS_2M_PAGE_MAX_OFFSET - cp_offset) :
			       size;
		for (i = 0, j = 1; i < size; i++) {
			*len_total += dbg_vsnprintf(rsp_end, *len_total, "%#x ",
						    *byte_pointer);
			byte_pointer++;
			j++;
			if ((j % 32 == 0) || i == size - 1) {
				*len_total += dbg_vsnprintf(rsp_end, *len_total,
							    "\n");
				j = 1;
			}
		}
	} else {
		spte_idx = LINER_ADDR_TO_REL_SPT_IDX(liner_addr);
		*len_total += dbg_vsnprintf(
			rsp_end, *len_total,
			"liner addr to fpte idx=%u entry type=%u\n", fpte_idx,
			fpte->entry_type);
		spte = &(fpte->u.spt.spte[spte_idx]);
		if (!spte->valid) {
			*len_total += dbg_vsnprintf(
				rsp_end, *len_total,
				"liner addr to spte idx=%u is invalid\n",
				spte_idx);
			goto end;
		} else {
			cp_offset = SECOND_PAGE_TABLE_CP_OFFSET_GET(liner_addr);
			byte_pointer = (u8 *)(spte->cp.page_addr.va);
			byte_pointer += cp_offset;
			*len_total += dbg_vsnprintf(
				rsp_end, *len_total,
				"liner addr to spte idx=%u cp offset=%u liner to pa=%#llx\n",
				spte_idx, cp_offset,
				spte->cp.page_addr.pa + cp_offset);
			size = (RCMS_DEBUGFS_4K_PAGE_MAX_OFFSET - cp_offset) <=
					       size ?
				       (RCMS_DEBUGFS_4K_PAGE_MAX_OFFSET -
					cp_offset) :
				       size;
			for (i = 0, j = 1; i < size; i++) {
				*len_total +=
					dbg_vsnprintf(rsp_end, *len_total,
						      "%x ", *byte_pointer);
				byte_pointer++;
				j++;
				if ((j % 32 == 0) || i == size - 1) {
					*len_total += dbg_vsnprintf(
						rsp_end, *len_total, "\n");
					j = 1;
				}
			}
		}
	}

end:
	return;
}

static ssize_t drv_rdma_rcms_read_liner_addr_read(struct file *filp,
						  char __user *buf,
						  size_t count, loff_t *off)
{
	ssize_t ret   = SXE2_OK;
	u32 len_total = 0;
	char *rsp     = NULL;
	char *rsp_end;
	struct sxe2_rdma_device *rdma_dev;
	struct sxe2_rcms_info *rcms_info;
	u32 fpte_idx;
	u64 liner_addr;
	struct sxe2_rcms_fpt_entry *fpte;

	if (*off != 0)
		goto end;

	rdma_dev = (struct sxe2_rdma_device *)filp->private_data;
	if (!rdma_dev) {
		ret = -ENXIO;
		DRV_RDMA_LOG_ERROR(
			"rcms debugfs:find dev struct from private_data failed err\n");
		goto end;
	}

	rcms_info  = rdma_dev->rdma_func->ctx_dev.rcms_info;
	liner_addr = rcms_info->read_liner_addr_input.liner_addr;

	rsp = kzalloc(sizeof(char) * SXE2_DEBUG_DUMP_BUF_SIZE,
			      GFP_KERNEL);
	if (!rsp) {
		ret = -ENOMEM;
		DRV_RDMA_LOG_ERROR(
			"rcms debugfs:rcms info rsp kmalloc failed err\n");
		goto end;
	}
	rsp_end	 = rsp;
	fpte_idx = FPT_INDEX_GET(liner_addr);
	len_total += dbg_vsnprintf(rsp_end, len_total, "liner addr %#llx:\n",
				   liner_addr);
	fpte = &(rcms_info->fpt.fpte[fpte_idx]);
	if (!fpte || !fpte->valid) {
		len_total +=
			dbg_vsnprintf(rsp_end, len_total,
				      "fpte is invalid or fpte ptr is null\n");
		goto show_buffer;
	}

	drv_rdma_rcms_print_liner_addr(rdma_dev, liner_addr, fpte, &len_total,
				       rsp_end);

show_buffer:
	ret = (ssize_t)simple_read_from_buffer(buf, count, off, rsp, len_total);
	if (ret < 0) {
		DRV_RDMA_LOG_DEV_ERR("rcms debugfs:simple read error %zu\n",
				     ret);
	}

	kfree(rsp);
	rsp = NULL;
end:
	return ret;
}

static const struct file_operations sxe2_rdma_rcms_read_liner_addr_fops = {
	.owner = THIS_MODULE,
	.open  = simple_open,
	.read  = drv_rdma_rcms_read_liner_addr_read,
	.write = drv_rdma_rcms_read_liner_addr_write,
};

static ssize_t drv_rdma_rcms_read_obj_ctx_write(struct file *filp,
						const char __user *buf,
						size_t count, loff_t *off)
{
	ssize_t ret				 = SXE2_OK;
	char cmd[RCMS_DEBUGFS_WRITE_BUF_MAX_LEN] = { 0 };
	struct sxe2_rdma_device *rdma_dev;
	u32 obj_type;
	u32 obj_num;
	struct sxe2_rcms_info *rcms_info;

	if (*off != 0)
		goto end;

	if (count >= RCMS_DEBUGFS_WRITE_BUF_MAX_LEN) {
		ret = -ENOSPC;
		DRV_RDMA_LOG_ERROR(
			"rcms debugfs:cmd exceeded length limit err\n");
		goto end;
	}

	rdma_dev = (struct sxe2_rdma_device *)filp->private_data;
	if (!rdma_dev) {
		ret = -ENXIO;
		DRV_RDMA_LOG_ERROR("rcms debugfs:dev find failed err\n");
		goto end;
	}
	rcms_info = rdma_dev->rdma_func->ctx_dev.rcms_info;

	if (copy_from_user(cmd, buf, count)) {
		ret = -EFAULT;
		DRV_RDMA_LOG_DEV_ERR(
			"rcms debugfs:cmd copy from user failed err\n");
		goto end;
	}

	ret = sscanf(cmd, "%u:%u", &obj_type, &obj_num);
	if (ret != 2) {
		ret = -ENODATA;
		DRV_RDMA_LOG_DEV_ERR(
			"rcms debugfs:analyze cmd err please input liner_addr=0xFF size=1024\n");
		goto end;
	}
	DRV_RDMA_LOG_DEV_DEBUG("rcms debugfs:input obj type=%u num=%u\n",
			       obj_type, obj_num);

	if (obj_type >= SXE2_RCMS_OBJ_MAX) {
		DRV_RDMA_LOG_DEV_ERR(
			"rcms debugfs:intput obj type=%u err max obj type=%u\n",
			obj_type, SXE2_RCMS_OBJ_MAX);
		ret = -EINVAL;
		goto end;
	}
	rcms_info->read_obj_ctx_input.obj_type = obj_type;
	if (obj_num >= rcms_info->rcms_obj[obj_type].cnt) {
		DRV_RDMA_LOG_DEV_ERR(
			"rcms debugfs:input obj %u obj num %u err support max cnt=%u\n",
			obj_type, obj_num, rcms_info->rcms_obj[obj_type].cnt);
		ret = -EINVAL;
		goto end;
	}

	rcms_info->read_obj_ctx_input.obj_num = obj_num;

	ret  = (ssize_t)count;
	*off = (loff_t)count;

end:
	return ret;
}

static void drv_rdma_rcms_print_obj_ctx(struct sxe2_rdma_device *rdma_dev,
					u32 obj_type, u64 liner_addr,
					struct sxe2_rcms_fpt_entry *fpte,
					u32 *len_total, char *rsp_end)
{
	u32 spte_idx;
	u8 *byte_pointer;
	struct sxe2_rcms_spt_entry *spte;
	u32 fpte_idx;
	u32 cp_offset;
	u64 i, j;
	u64 size;

	size = rdma_dev->rdma_func->ctx_dev.rcms_info->rcms_obj[obj_type].size;
	fpte_idx = FPT_INDEX_GET(liner_addr);
	if (fpte->entry_type == SXE2_RCMS_FPT_TYPE_FIRST) {
		*len_total += dbg_vsnprintf(
			rsp_end, *len_total,
			"liner addr to fpte idx=%u entry type=%u\n", fpte_idx,
			fpte->entry_type);
		cp_offset    = FIST_PAGE_TABLE_CP_OFFSET_GET(liner_addr);
		byte_pointer = (u8 *)(fpte->u.cp.page_addr.va);
		byte_pointer += cp_offset;
		*len_total +=
			dbg_vsnprintf(rsp_end, *len_total,
				      "cp offset=%x liner addr to pa=%#llx\n",
				      cp_offset,
				      fpte->u.cp.page_addr.pa + cp_offset);
		if (obj_type != SXE2_RCMS_OBJ_RESP &&
		    obj_type != SXE2_RCMS_OBJ_SSNT &&
		    obj_type != SXE2_RCMS_OBJ_IRRL &&
		    obj_type != SXE2_RCMS_OBJ_ACK_TIMEOUT) {
			for (i = 0, j = 1; i < size; i++) {
				*len_total +=
					dbg_vsnprintf(rsp_end, *len_total,
						      "%#x ", *byte_pointer);
				byte_pointer++;
				j++;
				if ((j % 32 == 0) || i == size - 1) {
					*len_total += dbg_vsnprintf(
						rsp_end, *len_total, "\n");
					j = 1;
				}
			}
		}
	} else {
		spte_idx = LINER_ADDR_TO_REL_SPT_IDX(liner_addr);
		*len_total += dbg_vsnprintf(
			rsp_end, *len_total,
			"liner addr to fpte idx=%u entry type=%u\n", fpte_idx,
			fpte->entry_type);
		spte = &(fpte->u.spt.spte[spte_idx]);
		if (!spte->valid) {
			*len_total += dbg_vsnprintf(
				rsp_end, *len_total,
				"liner addr to spte idx=%u is invalid\n",
				spte_idx);
			goto end;
		} else {
			cp_offset = SECOND_PAGE_TABLE_CP_OFFSET_GET(liner_addr);
			byte_pointer = (u8 *)(spte->cp.page_addr.va);
			byte_pointer += cp_offset;
			*len_total += dbg_vsnprintf(
				rsp_end, *len_total,
				"liner addr to spte idx=%u cp offset=%u liner to pa=%#llx\n",
				spte_idx, cp_offset,
				spte->cp.page_addr.pa + cp_offset);
			if (obj_type != SXE2_RCMS_OBJ_RESP &&
			    obj_type != SXE2_RCMS_OBJ_SSNT &&
			    obj_type != SXE2_RCMS_OBJ_IRRL &&
			    obj_type != SXE2_RCMS_OBJ_ACK_TIMEOUT) {
				for (i = 0, j = 1; i < size; i++) {
					*len_total +=
						dbg_vsnprintf(rsp_end,
							      *len_total, "%x ",
							      *byte_pointer);
					byte_pointer++;
					j++;
					if ((j % 32 == 0) || i == size - 1) {
						*len_total += dbg_vsnprintf(
							rsp_end, *len_total,
							"\n");
						j = 1;
					}
				}
			}
		}
	}
end:
	return;
}

static ssize_t drv_rdma_rcms_read_obj_ctx_read(struct file *filp,
					       char __user *buf, size_t count,
					       loff_t *off)
{
	ssize_t ret	 = SXE2_OK;
	size_t len_total = 0;
	char *rsp	 = NULL;
	char *rsp_end;
	struct sxe2_rdma_device *rdma_dev;
	struct sxe2_rcms_info *rcms_info;
	u32 fpte_idx;
	u64 liner_addr;
	u32 obj_type;
	u32 obj_num;
	struct sxe2_rcms_fpt_entry *fpte;

	if (*off != 0)
		goto end;

	rdma_dev = (struct sxe2_rdma_device *)filp->private_data;
	if (!rdma_dev) {
		ret = -ENXIO;
		DRV_RDMA_LOG_ERROR(
			"rcms debugfs:find dev struct from private_data failed err\n");
		goto end;
	}

	rcms_info = rdma_dev->rdma_func->ctx_dev.rcms_info;

	obj_type = rcms_info->read_obj_ctx_input.obj_type;
	obj_num	 = rcms_info->read_obj_ctx_input.obj_num;

	rsp = kzalloc(sizeof(char) * SXE2_DEBUG_DUMP_BUF_SIZE,
			      GFP_KERNEL);
	if (!rsp) {
		ret = -ENOMEM;
		DRV_RDMA_LOG_DEV_ERR(
			"rcms debugfs:rcms info rsp kmalloc failed err\n");
		goto end;
	}
	rsp_end	   = rsp;
	liner_addr = sxe2_rcms_num_to_liner_addr(rcms_info, obj_type, obj_num);
	fpte_idx   = FPT_INDEX_GET(liner_addr);
	len_total += dbg_vsnprintf(rsp_end, len_total,
				   "obj %u num %u liner addr %#llx:\n",
				   obj_type, obj_num, liner_addr);
	fpte = &(rcms_info->fpt.fpte[fpte_idx]);
	if (!fpte || !fpte->valid) {
		len_total +=
			dbg_vsnprintf(rsp_end, len_total,
				      "fpte is invalid or fpte ptr is null\n");
		goto show_buffer;
	}

	drv_rdma_rcms_print_obj_ctx(rdma_dev, obj_type, liner_addr, fpte,
				    (u32 *)&len_total, rsp_end);

show_buffer:
	ret = (ssize_t)simple_read_from_buffer(buf, count, off, rsp, len_total);
	if (ret < 0) {
		DRV_RDMA_LOG_DEV_ERR("rcms debugfs:simple read error %zu\n",
				     ret);
	}

	kfree(rsp);
	rsp = NULL;

end:
	return ret;
}

static const struct file_operations sxe2_rdma_rcms_read_obj_ctx_fops = {
	.owner = THIS_MODULE,
	.open  = simple_open,
	.read  = drv_rdma_rcms_read_obj_ctx_read,
	.write = drv_rdma_rcms_read_obj_ctx_write,
};

static ssize_t drv_rdma_rcms_num_to_liner_addr_write(struct file *filp,
						     const char __user *buf,
						     size_t count, loff_t *off)
{
	ssize_t ret				 = SXE2_OK;
	char cmd[RCMS_DEBUGFS_WRITE_BUF_MAX_LEN] = { 0 };
	struct sxe2_rdma_device *rdma_dev;
	u32 obj_type;
	u32 obj_num;
	struct sxe2_rcms_info *rcms_info;

	if (*off != 0)
		goto end;

	if (count >= RCMS_DEBUGFS_WRITE_BUF_MAX_LEN) {
		ret = -ENOSPC;
		DRV_RDMA_LOG_ERROR(
			"rcms debugfs:cmd exceeded length limit err\n");
		goto end;
	}

	rdma_dev = (struct sxe2_rdma_device *)filp->private_data;
	if (!rdma_dev) {
		ret = -ENXIO;
		DRV_RDMA_LOG_ERROR("rcms debugfs:dev find failed err\n");
		goto end;
	}
	rcms_info = rdma_dev->rdma_func->ctx_dev.rcms_info;

	if (copy_from_user(cmd, buf, count)) {
		ret = -EFAULT;
		DRV_RDMA_LOG_DEV_ERR(
			"rcms debugfs:cmd copy from user failed err\n");
		goto end;
	}

	ret = sscanf(cmd, "%u:%u", &obj_type, &obj_num);
	if (ret != 2) {
		ret = -ENODATA;
		DRV_RDMA_LOG_DEV_ERR(
			"rcms debugfs:analyze cmd err please input liner_addr=0xFF size=1024\n");
		goto end;
	}
	DRV_RDMA_LOG_DEV_DEBUG("rcms debugfs:input obj type=%u num=%u\n",
			       obj_type, obj_num);

	if (obj_type >= SXE2_RCMS_OBJ_MAX) {
		DRV_RDMA_LOG_DEV_ERR(
			"rcms debugfs:intput obj type=%u err max obj type=%u\n",
			obj_type, SXE2_RCMS_OBJ_MAX);
		ret = -EINVAL;
		goto end;
	}
	rcms_info->num_to_la_input.obj_type = obj_type;
	if (obj_num >= rcms_info->rcms_obj[obj_type].cnt) {
		DRV_RDMA_LOG_DEV_ERR(
			"rcms debugfs:input obj %u obj num %u err support max cnt=%u\n",
			obj_type, obj_num, rcms_info->rcms_obj[obj_type].cnt);
		ret = -EINVAL;
		goto end;
	}

	rcms_info->num_to_la_input.obj_num = obj_num;

	ret  = (ssize_t)count;
	*off = (loff_t)count;

end:
	return ret;
}

static ssize_t drv_rdma_rcms_num_to_liner_addr_read(struct file *filp,
						    char __user *buf,
						    size_t count, loff_t *off)
{
	ssize_t ret	 = SXE2_OK;
	size_t len_total = 0;
	char *rsp	 = NULL;
	char *rsp_end;
	struct sxe2_rdma_device *rdma_dev;
	struct sxe2_rcms_info *rcms_info;
	u32 fpte_idx;
	u32 spte_idx;
	u64 liner_addr;
	u32 obj_type;
	u32 obj_num;
	u32 cp_offset;
	struct sxe2_rcms_fpt_entry *fpte;
	struct sxe2_rcms_spt_entry *spte;

	if (*off != 0)
		goto end;

	rdma_dev = (struct sxe2_rdma_device *)filp->private_data;
	if (!rdma_dev) {
		ret = -ENXIO;
		DRV_RDMA_LOG_ERROR(
			"rcms debugfs:find dev struct from private_data failed err\n");
		goto end;
	}

	rcms_info = rdma_dev->rdma_func->ctx_dev.rcms_info;
	obj_type  = rcms_info->num_to_la_input.obj_type;
	obj_num	  = rcms_info->num_to_la_input.obj_num;
	rsp	  = kzalloc(sizeof(char) * SXE2_DEBUG_DUMP_BUF_SIZE,
				    GFP_KERNEL);
	if (!rsp) {
		ret = -ENOMEM;
		DRV_RDMA_LOG_DEV_ERR(
			"rcms debugfs:rcms info rsp kmalloc failed err\n");
		goto end;
	}
	rsp_end	   = rsp;
	liner_addr = sxe2_rcms_num_to_liner_addr(rcms_info, obj_type, obj_num);
	fpte_idx   = FPT_INDEX_GET(liner_addr);
	len_total += dbg_vsnprintf(rsp_end, len_total,
				   "obj %u num %u liner addr %#llx:\n",
				   obj_type, obj_num, liner_addr);
	fpte = &(rcms_info->fpt.fpte[fpte_idx]);
	if (!fpte || !fpte->valid) {
		len_total +=
			dbg_vsnprintf(rsp_end, len_total,
				      "fpte is invalid or fpte ptr is null\n");
		goto show_buffer;
	}

	if (fpte->entry_type == SXE2_RCMS_FPT_TYPE_FIRST) {
		len_total += dbg_vsnprintf(
			rsp_end, len_total,
			"liner addr to fpte idx=%u entry type=%u\n", fpte_idx,
			fpte->entry_type);
		cp_offset = FIST_PAGE_TABLE_CP_OFFSET_GET(liner_addr);
		len_total +=
			dbg_vsnprintf(rsp_end, len_total,
				      "cp offset=%x liner addr to pa=%#llx\n",
				      cp_offset,
				      fpte->u.cp.page_addr.pa + cp_offset);
	} else {
		spte_idx = LINER_ADDR_TO_REL_SPT_IDX(liner_addr);
		len_total += dbg_vsnprintf(
			rsp_end, len_total,
			"liner addr to fpte idx=%u entry type=%u\n", fpte_idx,
			fpte->entry_type);
		spte = &(fpte->u.spt.spte[spte_idx]);
		if (!spte->valid) {
			len_total += dbg_vsnprintf(
				rsp_end, len_total,
				"liner addr to spte idx=%u is invalid\n",
				spte_idx);
			goto show_buffer;
		} else {
			cp_offset = SECOND_PAGE_TABLE_CP_OFFSET_GET(liner_addr);
			len_total += dbg_vsnprintf(
				rsp_end, len_total,
				"liner addr to spte idx=%u cp offset=%u liner to pa=%#llx\n",
				spte_idx, cp_offset,
				spte->cp.page_addr.pa + cp_offset);
		}
	}
show_buffer:
	ret = (ssize_t)simple_read_from_buffer(buf, count, off, rsp, len_total);
	if (ret < 0) {
		DRV_RDMA_LOG_DEV_ERR("rcms debugfs:simple read error %zu\n",
				     ret);
	}
	kfree(rsp);
	rsp = NULL;
end:
	return ret;
}

static const struct file_operations sxe2_rdma_rcms_num_to_liner_addr_fops = {
	.owner = THIS_MODULE,
	.open  = simple_open,
	.read  = drv_rdma_rcms_num_to_liner_addr_read,
	.write = drv_rdma_rcms_num_to_liner_addr_write,
};
#endif

int drv_rdma_debug_rcms_add(struct sxe2_rdma_device *rdma_dev,
			    struct sxe2_rcms_info *rcms_info)
{
	int ret = SXE2_OK;

	if (!sxe2_rdma_debugfs_get_dev_root(rdma_dev)) {
		ret = -EINVAL;
		DRV_RDMA_LOG_DEV_ERR(
			"rcms debugfs:debugfs root dir not exist ret=%d\n",
			ret);
		goto end;
	}

	if (!rdma_dev->hdl->rcms_debugfs) {
		ret = -EINVAL;
		DRV_RDMA_LOG_DEV_ERR("rcms debugfs:dir not exist ret=%d\n",
				     ret);
		goto end;
	}

	debugfs_create_file("rcms_info", SXE2_DEBUG_FILE_ONLY_READ,
			    rdma_dev->hdl->rcms_debugfs, rdma_dev,
			    &sxe2_rdma_rcms_info_fops);
	debugfs_create_file("pbl_info", SXE2_DEBUG_FILE_ONLY_READ,
			    rdma_dev->hdl->rcms_debugfs, rdma_dev,
			    &sxe2_rdma_pbl_info_fops);
#ifdef SXE2_CFG_DEBUG
	debugfs_create_file("rcms_read_fpte", SXE2_DEBUG_FILE_READ_WRITE,
			    rdma_dev->hdl->rcms_debugfs, rdma_dev,
			    &sxe2_rdma_rcms_read_fpte_fops);
	debugfs_create_file("rcms_read_spte", SXE2_DEBUG_FILE_READ_WRITE,
			    rdma_dev->hdl->rcms_debugfs, rdma_dev,
			    &sxe2_rdma_rcms_read_spte_fops);
	debugfs_create_file("rcms_read_liner_addr", SXE2_DEBUG_FILE_READ_WRITE,
			    rdma_dev->hdl->rcms_debugfs, rdma_dev,
			    &sxe2_rdma_rcms_read_liner_addr_fops);
	debugfs_create_file("rcms_read_obj_ctx", SXE2_DEBUG_FILE_READ_WRITE,
			    rdma_dev->hdl->rcms_debugfs, rdma_dev,
			    &sxe2_rdma_rcms_read_obj_ctx_fops);
	debugfs_create_file("rcms_num_to_liner_addr",
			    SXE2_DEBUG_FILE_READ_WRITE,
			    rdma_dev->hdl->rcms_debugfs, rdma_dev,
			    &sxe2_rdma_rcms_num_to_liner_addr_fops);
#endif

end:
	return ret;
}

