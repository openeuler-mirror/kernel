// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2021 Ramaxel Memory Technology, Ltd */

#include <linux/types.h>
#include <linux/sched.h>
#include <linux/pci.h>
#include <linux/module.h>
#include <linux/vmalloc.h>
#include <linux/device.h>
#include <linux/mm.h>
#include <linux/gfp.h>

#include "sphw_crm.h"
#include "sphw_hw.h"
#include "sphw_hwdev.h"
#include "sphw_hwif.h"

#include "spfc_cqm_object.h"
#include "spfc_cqm_bitmap_table.h"
#include "spfc_cqm_bat_cla.h"
#include "spfc_cqm_main.h"

#define common_section

void cqm_swab64(u8 *addr, u32 cnt)
{
	u64 *temp = (u64 *)addr;
	u64 value = 0;
	u32 i;

	for (i = 0; i < cnt; i++) {
		value = __swab64(*temp);
		*temp = value;
		temp++;
	}
}

void cqm_swab32(u8 *addr, u32 cnt)
{
	u32 *temp = (u32 *)addr;
	u32 value = 0;
	u32 i;

	for (i = 0; i < cnt; i++) {
		value = __swab32(*temp);
		*temp = value;
		temp++;
	}
}

s32 cqm_shift(u32 data)
{
	s32 shift = -1;

	do {
		data >>= 1;
		shift++;
	} while (data);

	return shift;
}

bool cqm_check_align(u32 data)
{
	if (data == 0)
		return false;

	do {
		/* When the value can be exactly divided by 2,
		 * the value of data is shifted right by one bit, that is,
		 * divided by 2.
		 */
		if ((data & 0x1) == 0)
			data >>= 1;
			/* If the value cannot be divisible by 2, the value is
			 * not 2^n-aligned and false is returned.
			 */
		else
			return false;
	} while (data != 1);

	return true;
}

void *cqm_kmalloc_align(size_t size, gfp_t flags, u16 align_order)
{
	void *orig_addr = NULL;
	void *align_addr = NULL;
	void *index_addr = NULL;

	orig_addr = kmalloc(size + ((u64)1 << align_order) + sizeof(void *),
			    flags);
	if (!orig_addr)
		return NULL;

	index_addr = (void *)((char *)orig_addr + sizeof(void *));
	align_addr =
	    (void *)((((u64)index_addr + ((u64)1 << align_order) - 1) >>
		      align_order) << align_order);

	/* Record the original memory address for memory release. */
	index_addr = (void *)((char *)align_addr - sizeof(void *));
	*(void **)index_addr = orig_addr;

	return align_addr;
}

void cqm_kfree_align(void *addr)
{
	void *index_addr = NULL;

	/* Release the original memory address. */
	index_addr = (void *)((char *)addr - sizeof(void *));

	kfree(*(void **)index_addr);
}

void cqm_write_lock(rwlock_t *lock, bool bh)
{
	if (bh)
		write_lock_bh(lock);
	else
		write_lock(lock);
}

void cqm_write_unlock(rwlock_t *lock, bool bh)
{
	if (bh)
		write_unlock_bh(lock);
	else
		write_unlock(lock);
}

void cqm_read_lock(rwlock_t *lock, bool bh)
{
	if (bh)
		read_lock_bh(lock);
	else
		read_lock(lock);
}

void cqm_read_unlock(rwlock_t *lock, bool bh)
{
	if (bh)
		read_unlock_bh(lock);
	else
		read_unlock(lock);
}

s32 cqm_buf_alloc_direct(struct cqm_handle *cqm_handle, struct cqm_buf *buf, bool direct)
{
	struct sphw_hwdev *handle = cqm_handle->ex_handle;
	struct page **pages = NULL;
	u32 i, j, order;

	order = get_order(buf->buf_size);

	if (!direct) {
		buf->direct.va = NULL;
		return CQM_SUCCESS;
	}

	pages = vmalloc(sizeof(struct page *) * buf->page_number);
	if (!pages) {
		cqm_err(handle->dev_hdl, CQM_ALLOC_FAIL(pages));
		return CQM_FAIL;
	}

	for (i = 0; i < buf->buf_number; i++) {
		for (j = 0; j < ((u32)1 << order); j++)
			pages[(ulong)(unsigned int)((i << order) + j)] =
			    (void *)virt_to_page((u8 *)(buf->buf_list[i].va) +
						 (PAGE_SIZE * j));
	}

	buf->direct.va = vmap(pages, buf->page_number, VM_MAP, PAGE_KERNEL);
	vfree(pages);
	if (!buf->direct.va) {
		cqm_err(handle->dev_hdl, CQM_MAP_FAIL(buf->direct.va));
		return CQM_FAIL;
	}

	return CQM_SUCCESS;
}

s32 cqm_buf_alloc_page(struct cqm_handle *cqm_handle, struct cqm_buf *buf)
{
	struct sphw_hwdev *handle = cqm_handle->ex_handle;
	struct page *newpage = NULL;
	u32 order;
	void *va = NULL;
	s32 i, node;

	order = get_order(buf->buf_size);
	/* Page for applying for each buffer for non-ovs */
	if (handle->board_info.service_mode != 0) {
		for (i = 0; i < (s32)buf->buf_number; i++) {
			va = (void *)__get_free_pages(GFP_KERNEL | __GFP_ZERO,
						      order);
			if (!va) {
				cqm_err(handle->dev_hdl,
					CQM_ALLOC_FAIL(buf_page));
				break;
			}
			/* Initialize the page after the page is applied for.
			 * If hash entries are involved, the initialization
			 * value must be 0.
			 */
			memset(va, 0, buf->buf_size);
			buf->buf_list[i].va = va;
		}
	} else {
		node = dev_to_node(handle->dev_hdl);
		for (i = 0; i < (s32)buf->buf_number; i++) {
			newpage = alloc_pages_node(node,
						   GFP_KERNEL | __GFP_ZERO,
						   order);
			if (!newpage) {
				cqm_err(handle->dev_hdl,
					CQM_ALLOC_FAIL(buf_page));
				break;
			}
			va = (void *)page_address(newpage);
			/* Initialize the page after the page is applied for.
			 * If hash entries are involved, the initialization
			 * value must be 0.
			 */
			memset(va, 0, buf->buf_size);
			buf->buf_list[i].va = va;
		}
	}

	if (i != buf->buf_number) {
		i--;
		for (; i >= 0; i--) {
			free_pages((ulong)(buf->buf_list[i].va), order);
			buf->buf_list[i].va = NULL;
		}
		return CQM_FAIL;
	}

	return CQM_SUCCESS;
}

s32 cqm_buf_alloc_map(struct cqm_handle *cqm_handle, struct cqm_buf *buf)
{
	struct sphw_hwdev *handle = cqm_handle->ex_handle;
	struct pci_dev *dev = cqm_handle->dev;
	void *va = NULL;
	s32 i;

	for (i = 0; i < (s32)buf->buf_number; i++) {
		va = buf->buf_list[i].va;
		buf->buf_list[i].pa = pci_map_single(dev, va, buf->buf_size,
						     PCI_DMA_BIDIRECTIONAL);
		if (pci_dma_mapping_error(dev, buf->buf_list[i].pa)) {
			cqm_err(handle->dev_hdl, CQM_MAP_FAIL(buf_list));
			break;
		}
	}

	if (i != buf->buf_number) {
		i--;
		for (; i >= 0; i--)
			pci_unmap_single(dev, buf->buf_list[i].pa,
					 buf->buf_size, PCI_DMA_BIDIRECTIONAL);
		return CQM_FAIL;
	}

	return CQM_SUCCESS;
}

s32 cqm_buf_alloc(struct cqm_handle *cqm_handle, struct cqm_buf *buf, bool direct)
{
	struct sphw_hwdev *handle = cqm_handle->ex_handle;
	struct pci_dev *dev = cqm_handle->dev;
	u32 order;
	s32 i;

	order = get_order(buf->buf_size);

	/* Applying for the buffer list descriptor space */
	buf->buf_list = vmalloc(buf->buf_number * sizeof(struct cqm_buf_list));
	CQM_PTR_CHECK_RET(buf->buf_list, CQM_FAIL,
			  CQM_ALLOC_FAIL(linux_buf_list));
	memset(buf->buf_list, 0, buf->buf_number * sizeof(struct cqm_buf_list));

	/* Page for applying for each buffer */
	if (cqm_buf_alloc_page(cqm_handle, buf) == CQM_FAIL) {
		cqm_err(handle->dev_hdl,
			CQM_FUNCTION_FAIL(linux_cqm_buf_alloc_page));
		goto err1;
	}

	/* PCI mapping of the buffer */
	if (cqm_buf_alloc_map(cqm_handle, buf) == CQM_FAIL) {
		cqm_err(handle->dev_hdl,
			CQM_FUNCTION_FAIL(linux_cqm_buf_alloc_map));
		goto err2;
	}

	/* direct remapping */
	if (cqm_buf_alloc_direct(cqm_handle, buf, direct) == CQM_FAIL) {
		cqm_err(handle->dev_hdl,
			CQM_FUNCTION_FAIL(cqm_buf_alloc_direct));
		goto err3;
	}

	return CQM_SUCCESS;

err3:
	for (i = 0; i < (s32)buf->buf_number; i++)
		pci_unmap_single(dev, buf->buf_list[i].pa, buf->buf_size,
				 PCI_DMA_BIDIRECTIONAL);
err2:
	for (i = 0; i < (s32)buf->buf_number; i++) {
		free_pages((ulong)(buf->buf_list[i].va), order);
		buf->buf_list[i].va = NULL;
	}
err1:
	vfree(buf->buf_list);
	buf->buf_list = NULL;
	return CQM_FAIL;
}

void cqm_buf_free(struct cqm_buf *buf, struct pci_dev *dev)
{
	u32 order;
	s32 i;

	order = get_order(buf->buf_size);

	if (buf->direct.va) {
		vunmap(buf->direct.va);
		buf->direct.va = NULL;
	}

	if (buf->buf_list) {
		for (i = 0; i < (s32)(buf->buf_number); i++) {
			if (buf->buf_list[i].va) {
				pci_unmap_single(dev, buf->buf_list[i].pa,
						 buf->buf_size,
						 PCI_DMA_BIDIRECTIONAL);

				free_pages((ulong)(buf->buf_list[i].va), order);
				buf->buf_list[i].va = NULL;
			}
		}

		vfree(buf->buf_list);
		buf->buf_list = NULL;
	}
}

s32 cqm_cla_cache_invalid_cmd(struct cqm_handle *cqm_handle, struct cqm_cmd_buf *buf_in,
			      struct cqm_cla_cache_invalid_cmd *cmd)
{
	struct sphw_hwdev *handle = cqm_handle->ex_handle;
	struct cqm_cla_cache_invalid_cmd *cla_cache_invalid_cmd = NULL;
	s32 ret;

	cla_cache_invalid_cmd = (struct cqm_cla_cache_invalid_cmd *)(buf_in->buf);
	cla_cache_invalid_cmd->gpa_h = cmd->gpa_h;
	cla_cache_invalid_cmd->gpa_l = cmd->gpa_l;
	cla_cache_invalid_cmd->cache_size = cmd->cache_size;
	cla_cache_invalid_cmd->smf_id = cmd->smf_id;
	cla_cache_invalid_cmd->func_id = cmd->func_id;

	cqm_swab32((u8 *)cla_cache_invalid_cmd,
		   /* shift 2 bits by right to get length of dw(4B) */
		   (sizeof(struct cqm_cla_cache_invalid_cmd) >> 2));

	/* Send the cmdq command. */
	ret = cqm3_send_cmd_box((void *)(cqm_handle->ex_handle), CQM_MOD_CQM,
				CQM_CMD_T_CLA_CACHE_INVALID, buf_in, NULL, NULL,
				CQM_CMD_TIMEOUT, SPHW_CHANNEL_DEFAULT);
	if (ret != CQM_SUCCESS) {
		cqm_err(handle->dev_hdl, CQM_FUNCTION_FAIL(cqm3_send_cmd_box));
		cqm_err(handle->dev_hdl,
			"Cla cache invalid: cqm3_send_cmd_box_ret=%d\n",
			ret);
		cqm_err(handle->dev_hdl,
			"Cla cache invalid: cla_cache_invalid_cmd: 0x%x 0x%x 0x%x\n",
			cmd->gpa_h, cmd->gpa_l, cmd->cache_size);
		return CQM_FAIL;
	}

	return CQM_SUCCESS;
}

s32 cqm_cla_cache_invalid(struct cqm_handle *cqm_handle, dma_addr_t gpa, u32 cache_size)
{
	struct sphw_hwdev *handle = cqm_handle->ex_handle;
	struct cqm_cmd_buf *buf_in = NULL;
	struct cqm_cla_cache_invalid_cmd cmd;
	s32 ret = CQM_FAIL;
	u32 i;

	buf_in = cqm3_cmd_alloc((void *)(cqm_handle->ex_handle));
	CQM_PTR_CHECK_RET(buf_in, CQM_FAIL, CQM_ALLOC_FAIL(buf_in));
	buf_in->size = sizeof(struct cqm_cla_cache_invalid_cmd);

	/* Fill command and convert it to big endian */
	cmd.cache_size = cache_size;
	cmd.gpa_h = CQM_ADDR_HI(gpa);
	cmd.gpa_l = CQM_ADDR_LW(gpa);

	/* In non-fake mode, set func_id to 0xffff. */
	cmd.func_id = 0xffff;

	/* Mode 0 is hashed to 4 SMF engines (excluding PPF) by func ID. */
	if (cqm_handle->func_capability.lb_mode == CQM_LB_MODE_NORMAL ||
	    (cqm_handle->func_capability.lb_mode == CQM_LB_MODE_0 &&
	     cqm_handle->func_attribute.func_type != CQM_PPF)) {
		cmd.smf_id = cqm_funcid2smfid(cqm_handle);
		ret = cqm_cla_cache_invalid_cmd(cqm_handle, buf_in, &cmd);
	}
	/* Mode 1/2 are allocated to 4 SMF engines by flow. Therefore,
	 * one function needs to be allocated to 4 SMF engines.
	 */
	/* The PPF in mode 0 needs to be configured on 4 engines,
	 * and the timer resources need to be shared by the 4 engines.
	 */
	else if (cqm_handle->func_capability.lb_mode == CQM_LB_MODE_1 ||
		 cqm_handle->func_capability.lb_mode == CQM_LB_MODE_2 ||
		 (cqm_handle->func_capability.lb_mode == CQM_LB_MODE_0 &&
		  cqm_handle->func_attribute.func_type == CQM_PPF)) {
		for (i = 0; i < CQM_LB_SMF_MAX; i++) {
			/* The smf_pg stored currently enabled SMF engine. */
			if (cqm_handle->func_capability.smf_pg & (1U << i)) {
				cmd.smf_id = i;
				ret = cqm_cla_cache_invalid_cmd(cqm_handle,
								buf_in, &cmd);
				if (ret != CQM_SUCCESS)
					goto out;
			}
		}
	} else {
		cqm_err(handle->dev_hdl, "Cla cache invalid: unsupport lb mode=%u\n",
			cqm_handle->func_capability.lb_mode);
		ret = CQM_FAIL;
	}

out:
	cqm3_cmd_free((void *)(cqm_handle->ex_handle), buf_in);
	return ret;
}

static void free_cache_inv(struct cqm_handle *cqm_handle, struct cqm_buf *buf,
			   s32 *inv_flag)
{
	struct sphw_hwdev *handle = cqm_handle->ex_handle;
	u32 order;
	s32 i;

	order = get_order(buf->buf_size);

	if (!handle->chip_present_flag)
		return;

	if (!buf->buf_list)
		return;

	for (i = 0; i < (s32)(buf->buf_number); i++) {
		if (!buf->buf_list[i].va)
			continue;

		if (*inv_flag != CQM_SUCCESS)
			continue;

		/* In the Pangea environment, if the cmdq times out,
		 * no subsequent message is sent.
		 */
		*inv_flag = cqm_cla_cache_invalid(cqm_handle, buf->buf_list[i].pa,
						  (u32)(PAGE_SIZE << order));
		if (*inv_flag != CQM_SUCCESS)
			cqm_err(handle->dev_hdl,
				"Buffer free: fail to invalid buf_list pa cache, inv_flag=%d\n",
				*inv_flag);
	}
}

void cqm_buf_free_cache_inv(struct cqm_handle *cqm_handle, struct cqm_buf *buf,
			    s32 *inv_flag)
{
	/* Send a command to the chip to kick out the cache. */
	free_cache_inv(cqm_handle, buf, inv_flag);

	/* Clear host resources */
	cqm_buf_free(buf, cqm_handle->dev);
}

#define bitmap_section

s32 cqm_single_bitmap_init(struct cqm_bitmap *bitmap)
{
	u32 bit_number;

	spin_lock_init(&bitmap->lock);

	/* Max_num of the bitmap is 8-aligned and then
	 * shifted rightward by 3 bits to obtain the number of bytes required.
	 */
	bit_number = (ALIGN(bitmap->max_num, CQM_NUM_BIT_BYTE) >> CQM_BYTE_BIT_SHIFT);
	bitmap->table = vmalloc(bit_number);
	CQM_PTR_CHECK_RET(bitmap->table, CQM_FAIL, CQM_ALLOC_FAIL(bitmap->table));
	memset(bitmap->table, 0, bit_number);

	return CQM_SUCCESS;
}

s32 cqm_bitmap_init(struct cqm_handle *cqm_handle)
{
	struct cqm_func_capability *capability = &cqm_handle->func_capability;
	struct cqm_bat_table *bat_table = &cqm_handle->bat_table;
	struct sphw_hwdev *handle = cqm_handle->ex_handle;
	struct cqm_cla_table *cla_table = NULL;
	struct cqm_bitmap *bitmap = NULL;
	s32 ret = CQM_SUCCESS;
	u32 i;

	for (i = 0; i < CQM_BAT_ENTRY_MAX; i++) {
		cla_table = &bat_table->entry[i];
		if (cla_table->obj_num == 0) {
			cqm_info(handle->dev_hdl,
				 "Cla alloc: cla_type %u, obj_num=0, don't init bitmap\n",
				 cla_table->type);
			continue;
		}

		bitmap = &cla_table->bitmap;

		switch (cla_table->type) {
		case CQM_BAT_ENTRY_T_QPC:
			bitmap->max_num = capability->qpc_number;
			bitmap->reserved_top = capability->qpc_reserved;
			bitmap->last = capability->qpc_reserved;
			cqm_info(handle->dev_hdl,
				 "Bitmap init: cla_table_type=%u, max_num=0x%x\n",
				 cla_table->type, bitmap->max_num);
			ret = cqm_single_bitmap_init(bitmap);
			break;
		case CQM_BAT_ENTRY_T_MPT:
			bitmap->max_num = capability->mpt_number;
			bitmap->reserved_top = capability->mpt_reserved;
			bitmap->last = capability->mpt_reserved;
			cqm_info(handle->dev_hdl,
				 "Bitmap init: cla_table_type=%u, max_num=0x%x\n",
				 cla_table->type, bitmap->max_num);
			ret = cqm_single_bitmap_init(bitmap);
			break;
		case CQM_BAT_ENTRY_T_SCQC:
			bitmap->max_num = capability->scqc_number;
			bitmap->reserved_top = capability->scq_reserved;
			bitmap->last = capability->scq_reserved;
			cqm_info(handle->dev_hdl,
				 "Bitmap init: cla_table_type=%u, max_num=0x%x\n",
				 cla_table->type, bitmap->max_num);
			ret = cqm_single_bitmap_init(bitmap);
			break;
		case CQM_BAT_ENTRY_T_SRQC:
			bitmap->max_num = capability->srqc_number;
			bitmap->reserved_top = capability->srq_reserved;
			bitmap->last = capability->srq_reserved;
			cqm_info(handle->dev_hdl,
				 "Bitmap init: cla_table_type=%u, max_num=0x%x\n",
				 cla_table->type, bitmap->max_num);
			ret = cqm_single_bitmap_init(bitmap);
			break;
		default:
			break;
		}

		if (ret != CQM_SUCCESS) {
			cqm_err(handle->dev_hdl,
				"Bitmap init: failed to init cla_table_type=%u, obj_num=0x%x\n",
				cla_table->type, cla_table->obj_num);
			goto err;
		}
	}

	return CQM_SUCCESS;

err:
	cqm_bitmap_uninit(cqm_handle);
	return CQM_FAIL;
}

void cqm_bitmap_uninit(struct cqm_handle *cqm_handle)
{
	struct cqm_bat_table *bat_table = &cqm_handle->bat_table;
	struct cqm_cla_table *cla_table = NULL;
	struct cqm_bitmap *bitmap = NULL;
	u32 i;

	for (i = 0; i < CQM_BAT_ENTRY_MAX; i++) {
		cla_table = &bat_table->entry[i];
		bitmap = &cla_table->bitmap;
		if (cla_table->type != CQM_BAT_ENTRY_T_INVALID) {
			if (bitmap->table) {
				vfree(bitmap->table);
				bitmap->table = NULL;
			}
		}
	}
}

u32 cqm_bitmap_check_range(const ulong *table, u32 step, u32 max_num, u32 begin,
			   u32 count)
{
	u32 end = (begin + (count - 1));
	u32 i;

	/* Single-bit check is not performed. */
	if (count == 1)
		return begin;

	/* The end value exceeds the threshold. */
	if (end >= max_num)
		return max_num;

	/* Bit check, the next bit is returned when a non-zero bit is found. */
	for (i = (begin + 1); i <= end; i++) {
		if (test_bit((s32)i, table))
			return i + 1;
	}

	/* Check whether it's in different steps. */
	if ((begin & (~(step - 1))) != (end & (~(step - 1))))
		return (end & (~(step - 1)));

	/* If the check succeeds, begin is returned. */
	return begin;
}

void cqm_bitmap_find(struct cqm_bitmap *bitmap, u32 *index, u32 last, u32 step, u32 count)
{
	u32 max_num = bitmap->max_num;
	ulong *table = bitmap->table;

	do {
		*index = (u32)find_next_zero_bit(table, max_num, last);
		if (*index < max_num)
			last = cqm_bitmap_check_range(table, step, max_num,
						      *index, count);
		else
			break;
	} while (last != *index);
}

u32 cqm_bitmap_alloc(struct cqm_bitmap *bitmap, u32 step, u32 count, bool update_last)
{
	u32 index = 0;
	u32 max_num = bitmap->max_num;
	u32 last = bitmap->last;
	ulong *table = bitmap->table;
	u32 i;

	spin_lock(&bitmap->lock);

	/* Search for an idle bit from the last position. */
	cqm_bitmap_find(bitmap, &index, last, step, count);

	/* The preceding search fails. Search for an idle bit
	 * from the beginning.
	 */
	if (index >= max_num) {
		last = bitmap->reserved_top;
		cqm_bitmap_find(bitmap, &index, last, step, count);
	}

	/* Set the found bit to 1 and reset last. */
	if (index < max_num) {
		for (i = index; i < (index + count); i++)
			set_bit(i, table);

		if (update_last) {
			bitmap->last = (index + count);
			if (bitmap->last >= bitmap->max_num)
				bitmap->last = bitmap->reserved_top;
		}
	}

	spin_unlock(&bitmap->lock);
	return index;
}

u32 cqm_bitmap_alloc_reserved(struct cqm_bitmap *bitmap, u32 count, u32 index)
{
	ulong *table = bitmap->table;
	u32 ret_index;

	if (index >= bitmap->reserved_top || index >= bitmap->max_num || count != 1)
		return CQM_INDEX_INVALID;

	spin_lock(&bitmap->lock);

	if (test_bit((s32)index, table)) {
		ret_index = CQM_INDEX_INVALID;
	} else {
		set_bit(index, table);
		ret_index = index;
	}

	spin_unlock(&bitmap->lock);
	return ret_index;
}

void cqm_bitmap_free(struct cqm_bitmap *bitmap, u32 index, u32 count)
{
	u32 i;

	spin_lock(&bitmap->lock);

	for (i = index; i < (index + count); i++)
		clear_bit((s32)i, bitmap->table);

	spin_unlock(&bitmap->lock);
}

#define obj_table_section
s32 cqm_single_object_table_init(struct cqm_object_table *obj_table)
{
	rwlock_init(&obj_table->lock);

	obj_table->table = vmalloc(obj_table->max_num * sizeof(void *));
	CQM_PTR_CHECK_RET(obj_table->table, CQM_FAIL, CQM_ALLOC_FAIL(table));
	memset(obj_table->table, 0, obj_table->max_num * sizeof(void *));
	return CQM_SUCCESS;
}

s32 cqm_object_table_init(struct cqm_handle *cqm_handle)
{
	struct cqm_func_capability *capability = &cqm_handle->func_capability;
	struct cqm_bat_table *bat_table = &cqm_handle->bat_table;
	struct sphw_hwdev *handle = cqm_handle->ex_handle;
	struct cqm_object_table *obj_table = NULL;
	struct cqm_cla_table *cla_table = NULL;
	s32 ret = CQM_SUCCESS;
	u32 i;

	for (i = 0; i < CQM_BAT_ENTRY_MAX; i++) {
		cla_table = &bat_table->entry[i];
		if (cla_table->obj_num == 0) {
			cqm_info(handle->dev_hdl,
				 "Obj table init: cla_table_type %u, obj_num=0, don't init obj table\n",
				 cla_table->type);
			continue;
		}

		obj_table = &cla_table->obj_table;

		switch (cla_table->type) {
		case CQM_BAT_ENTRY_T_QPC:
			obj_table->max_num = capability->qpc_number;
			ret = cqm_single_object_table_init(obj_table);
			break;
		case CQM_BAT_ENTRY_T_MPT:
			obj_table->max_num = capability->mpt_number;
			ret = cqm_single_object_table_init(obj_table);
			break;
		case CQM_BAT_ENTRY_T_SCQC:
			obj_table->max_num = capability->scqc_number;
			ret = cqm_single_object_table_init(obj_table);
			break;
		case CQM_BAT_ENTRY_T_SRQC:
			obj_table->max_num = capability->srqc_number;
			ret = cqm_single_object_table_init(obj_table);
			break;
		default:
			break;
		}

		if (ret != CQM_SUCCESS) {
			cqm_err(handle->dev_hdl,
				"Obj table init: failed to init cla_table_type=%u, obj_num=0x%x\n",
				cla_table->type, cla_table->obj_num);
			goto err;
		}
	}

	return CQM_SUCCESS;

err:
	cqm_object_table_uninit(cqm_handle);
	return CQM_FAIL;
}

void cqm_object_table_uninit(struct cqm_handle *cqm_handle)
{
	struct cqm_bat_table *bat_table = &cqm_handle->bat_table;
	struct cqm_object_table *obj_table = NULL;
	struct cqm_cla_table *cla_table = NULL;
	u32 i;

	for (i = 0; i < CQM_BAT_ENTRY_MAX; i++) {
		cla_table = &bat_table->entry[i];
		obj_table = &cla_table->obj_table;
		if (cla_table->type != CQM_BAT_ENTRY_T_INVALID) {
			if (obj_table->table) {
				vfree(obj_table->table);
				obj_table->table = NULL;
			}
		}
	}
}

s32 cqm_object_table_insert(struct cqm_handle *cqm_handle,
			    struct cqm_object_table *object_table,
			    u32 index, struct cqm_object *obj, bool bh)
{
	struct sphw_hwdev *handle = cqm_handle->ex_handle;

	if (index >= object_table->max_num) {
		cqm_err(handle->dev_hdl,
			"Obj table insert: index 0x%x exceeds max_num 0x%x\n",
			index, object_table->max_num);
		return CQM_FAIL;
	}

	cqm_write_lock(&object_table->lock, bh);

	if (!object_table->table[index]) {
		object_table->table[index] = obj;
		cqm_write_unlock(&object_table->lock, bh);
		return CQM_SUCCESS;
	}

	cqm_write_unlock(&object_table->lock, bh);
	cqm_err(handle->dev_hdl,
		"Obj table insert: object_table->table[0x%x] has been inserted\n",
		index);

	return CQM_FAIL;
}

void cqm_object_table_remove(struct cqm_handle *cqm_handle,
			     struct cqm_object_table *object_table,
			     u32 index, const struct cqm_object *obj, bool bh)
{
	struct sphw_hwdev *handle = cqm_handle->ex_handle;

	if (index >= object_table->max_num) {
		cqm_err(handle->dev_hdl,
			"Obj table remove: index 0x%x exceeds max_num 0x%x\n",
			index, object_table->max_num);
		return;
	}

	cqm_write_lock(&object_table->lock, bh);

	if (object_table->table[index] && object_table->table[index] == obj)
		object_table->table[index] = NULL;
	else
		cqm_err(handle->dev_hdl,
			"Obj table remove: object_table->table[0x%x] has been removed\n",
			index);

	cqm_write_unlock(&object_table->lock, bh);
}

struct cqm_object *cqm_object_table_get(struct cqm_handle *cqm_handle,
					struct cqm_object_table *object_table,
					u32 index, bool bh)
{
	struct sphw_hwdev *handle = cqm_handle->ex_handle;
	struct cqm_object *obj = NULL;

	if (index >= object_table->max_num) {
		cqm_err(handle->dev_hdl,
			"Obj table get: index 0x%x exceeds max_num 0x%x\n",
			index, object_table->max_num);
		return NULL;
	}

	cqm_read_lock(&object_table->lock, bh);

	obj = object_table->table[index];
	if (obj)
		atomic_inc(&obj->refcount);

	cqm_read_unlock(&object_table->lock, bh);

	return obj;
}
