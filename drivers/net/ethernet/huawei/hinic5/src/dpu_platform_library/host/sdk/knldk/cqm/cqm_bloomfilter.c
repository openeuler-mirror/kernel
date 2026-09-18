/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : cqm_bloomfilter.c
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/09/16
 * Description   : CQM bloom filter implementation
 */

#include <linux/types.h>
#include <linux/sched.h>
#include <linux/module.h>
#include <linux/vmalloc.h>

#include "ossl_knl.h"
#include "hinic5_crm.h"
#include "hinic5_hw.h"
#include "hinic5_hwdev.h"
#include "hinic5_typedef_inner.h"

#include "cqm_object.h"
#include "cqm_bitmap_table.h"
#include "cqm_bat_cla.h"
#include "cqm_cmd.h"
#include "cqm_main.h"
#include "cqm_bloomfilter.h"

#include "cqm_npu_cmd.h"
#include "cqm_npu_cmd_defs.h"

/**
 * Prototype    : bloomfilter_init_cmd
 * Description  : host send cmd to ucode to init bloomfilter mem
 * Input        : void *ex_handle
 * Output       : None
 * Return Value : s32
 * 1.Date         : 2016/8/13
 *   Modification : Created function
 */
static s32 bloomfilter_init_cmd(struct tag_cqm_handle *cqm_handle)
{
	struct tag_cqm_func_capability *capability = &cqm_handle->func_capability;
	cqm_bloomfilter_init_cmd_s *cmd = NULL;
	struct tag_cqm_cmd_buf *buf_in = NULL;
	s32 ret;

	buf_in = cqm5_cmd_alloc((void *)(cqm_handle->ex_handle));
	if (unlikely(buf_in == NULL)) {
		CQM_PTR_CHECK_ERR(CQM_ALLOC_FAIL(buf_in));
		return CQM_FAIL;
	}

	/* Fill the command format and convert it to big-endian. */
	buf_in->size = sizeof(cqm_bloomfilter_init_cmd_s);
	cmd = (cqm_bloomfilter_init_cmd_s *)(buf_in->buf);
	cmd->bloom_filter_addr = capability->bloomfilter_addr;
	cmd->bloom_filter_len = capability->bloomfilter_length;

	cqm_swab32((u8 *)cmd,
		   (sizeof(cqm_bloomfilter_init_cmd_s) >> CQM_DW_SHIFT));

	ret = cqm5_send_cmd_box((void *)(cqm_handle->ex_handle),
			       CQM_MOD_CQM, CQM_CMD_T_BLOOMFILTER_INIT, buf_in,
			       NULL, NULL, CQM_CMD_TIMEOUT,
			       HINIC5_CHANNEL_DEFAULT);
	if (ret != CQM_SUCCESS) {
		cqm_err(cqm_handle->ex_handle->dev_hdl, CQM_FUNCTION_FAIL(cqm5_send_cmd_box));
		cqm_err(cqm_handle->ex_handle->dev_hdl, "Bloomfilter: %s ret=%d\n", __func__,
			ret);
		cqm_err(cqm_handle->ex_handle->dev_hdl, "Bloomfilter: %s: 0x%x 0x%x\n",
			__func__, cmd->bloom_filter_addr,
			cmd->bloom_filter_len);
		cqm5_cmd_free((void *)(cqm_handle->ex_handle), buf_in);
		return CQM_FAIL;
	}
	cqm5_cmd_free((void *)(cqm_handle->ex_handle), buf_in);
	return CQM_SUCCESS;
}

static void cqm_func_bloomfilter_uninit(struct tag_cqm_handle *cqm_handle)
{
	struct tag_cqm_bloomfilter_table *bloomfilter_table = &cqm_handle->bloomfilter_table;

	if (bloomfilter_table->table) {
		mutex_deinit(&bloomfilter_table->lock);
		vfree(bloomfilter_table->table);
		bloomfilter_table->table = NULL;
	}
}

static s32 cqm_func_bloomfilter_init(struct tag_cqm_handle *cqm_handle)
{
	struct tag_cqm_bloomfilter_table *bloomfilter_table = NULL;
	struct tag_cqm_func_capability *capability = NULL;
	u32 array_size;
	s32 ret;

	bloomfilter_table = &cqm_handle->bloomfilter_table;
	capability = &cqm_handle->func_capability;

	if (capability->bloomfilter_length == 0) {
		cqm_info(cqm_handle->ex_handle->dev_hdl,
			 "Bloomfilter: bf_length=0, don't need to init bloomfilter\n");
		return CQM_SUCCESS;
	}

	/* The unit of bloomfilter_length is 64B(512bits). Each bit is a table
	 * node. Therefore the value must be shift 9 bits to the left.
	 */
	bloomfilter_table->table_size = capability->bloomfilter_length <<
					CQM_BF_LENGTH_UNIT;
	/* The unit of bloomfilter_length is 64B. The unit of array entryis 32B.
	 */
	array_size = capability->bloomfilter_length << 1;
	if (array_size == 0 || array_size > CQM_BF_BITARRAY_MAX) {
		cqm_err(cqm_handle->ex_handle->dev_hdl, CQM_WRONG_VALUE(array_size));
		return CQM_FAIL;
	}

	bloomfilter_table->array_mask = array_size - 1;
	/* This table is not a bitmap, it is the counter of corresponding bit.
	 */
	bloomfilter_table->table = vmalloc(bloomfilter_table->table_size *
					   (sizeof(u32)));
	if (unlikely(bloomfilter_table->table == NULL)) {
		CQM_PTR_CHECK_ERR(CQM_ALLOC_FAIL(table));
		return CQM_FAIL;
	}

	(void)memset(bloomfilter_table->table, 0,
	       (bloomfilter_table->table_size * sizeof(u32)));

	/* The the bloomfilter must be initialized to 0 by ucode,
	 * because the bloomfilter is mem mode
	 */
	if (cqm_handle->func_capability.bloomfilter_enable != 0) {
		ret = bloomfilter_init_cmd(cqm_handle);
		if (ret != CQM_SUCCESS) {
			cqm_err(cqm_handle->ex_handle->dev_hdl,
				"Bloomfilter: bloomfilter_init_cmd  ret=%d\n",
				ret);
			vfree(bloomfilter_table->table);
			bloomfilter_table->table = NULL;
			return CQM_FAIL;
		}
	}

	mutex_init(&bloomfilter_table->lock);

	cqm_dbg(cqm_handle->dev,
		"Bloomfilter: table_size=0x%x, array_size=0x%x\n",
		bloomfilter_table->table_size, array_size);
	return CQM_SUCCESS;
}

static void cqm_fake_bloomfilter_uninit(struct tag_cqm_handle *cqm_handle)
{
	u32 i, child_func_number = cqm_get_child_func_number(cqm_handle);

	if (!CQM_IS_FAKE_PARENT(cqm_handle))
		return;

	for (i = 0; i < child_func_number; i++) {
		cqm_func_bloomfilter_uninit(cqm_handle->fake_cqm_handle[i]);
	}
}

static s32 cqm_fake_bloomfilter_init(struct tag_cqm_handle *cqm_handle)
{
	struct hinic5_hwdev *handle = cqm_handle->ex_handle;
	struct tag_cqm_handle *fake_cqm_handle = NULL;
	u32 i, child_func_number;

	if (!CQM_IS_FAKE_PARENT(cqm_handle))
		return CQM_SUCCESS;

	child_func_number = cqm_get_child_func_number(cqm_handle);

	for (i = 0; i < child_func_number; i++) {
		fake_cqm_handle = cqm_handle->fake_cqm_handle[i];
		if (cqm_func_bloomfilter_init(fake_cqm_handle) != CQM_SUCCESS) {
			cqm_err(handle->dev_hdl,
				CQM_FUNCTION_FAIL(cqm_func_bloomfilter_init));
			goto bloomfilter_init_err;
		}
	}

	return CQM_SUCCESS;

bloomfilter_init_err:
	cqm_fake_bloomfilter_uninit(cqm_handle);
	return CQM_FAIL;
}

/**
 * Prototype    : cqm_bloomfilter_init
 * Description  : initialize the bloomfilter of cqm
 * Input        : void *ex_handle
 * Output       : None
 * Return Value : s32
 * 1.Date         : 2016/7/6
 *   Modification : Created function
 */
s32 cqm_bloomfilter_init(void *ex_handle)
{
	struct hinic5_hwdev *handle = (struct hinic5_hwdev *)ex_handle;
	struct tag_cqm_handle *cqm_handle = NULL;

	cqm_handle = (struct tag_cqm_handle *)(handle->cqm_hdl);

	if (cqm_fake_bloomfilter_init(cqm_handle) != CQM_SUCCESS) {
		cqm_err(handle->dev_hdl,
			CQM_FUNCTION_FAIL(cqm_fake_bloomfilter_init));
		return CQM_FAIL;
	}

	if (cqm_func_bloomfilter_init(cqm_handle) != CQM_SUCCESS) {
		cqm_err(handle->dev_hdl,
			CQM_FUNCTION_FAIL(cqm_func_bloomfilter_init));
		goto bloomfilter_init_err;
	}

	return CQM_SUCCESS;

bloomfilter_init_err:
	cqm_fake_bloomfilter_uninit(cqm_handle);
	return CQM_FAIL;
}

/**
 * Prototype    : cqm_bloomfilter_uninit
 * Description  : uninitialize the bloomfilter of cqm
 * Input        : void *ex_handle
 * Output       : None
 * Return Value : void
 * 1.Date         : 2016/7/6
 *   Modification : Created function
 */
void cqm_bloomfilter_uninit(void *ex_handle)
{
	struct hinic5_hwdev *handle = (struct hinic5_hwdev *)ex_handle;
	struct tag_cqm_handle *cqm_handle = NULL;

	cqm_handle = (struct tag_cqm_handle *)(handle->cqm_hdl);

	cqm_fake_bloomfilter_uninit(cqm_handle);
	cqm_func_bloomfilter_uninit(cqm_handle);
}

/**
 * Prototype    : cqm_bloomfilter_cmd
 * Description  : host send bloomfilter api cmd to ucode
 * Input        : void *ex_handle
 *		  u32 op,
 *		  u32 k_flag
 *		  u64 id,
 * Output       : None
 * Return Value : s32
 * 1.Date         : 2016/7/7
 *   Modification : Created function
 */
s32 cqm_bloomfilter_cmd(void *ex_handle, u16 func_id, u32 op, u32 k_flag, u64 id)
{
	struct hinic5_hwdev *handle = (struct hinic5_hwdev *)ex_handle;
	struct tag_cqm_cmd_buf *buf_in = NULL;
	cqm_bloomfilter_cmd_s *cmd = NULL;
	s32 ret;

	buf_in = cqm5_cmd_alloc(ex_handle);
	if (unlikely(buf_in == NULL)) {
		CQM_PTR_CHECK_ERR(CQM_ALLOC_FAIL(buf_in));
		return CQM_FAIL;
	}

	/* Fill the command format and convert it to big-endian. */
	buf_in->size = sizeof(cqm_bloomfilter_cmd_s);
	cmd = (cqm_bloomfilter_cmd_s *)(buf_in->buf);
	(void)memset((void *)cmd, 0, sizeof(cqm_bloomfilter_cmd_s));
	cmd->func_id = func_id;
	cmd->k_en = k_flag;
	cmd->index_h = (u32)(id >> CQM_DW_OFFSET);
	cmd->index_l = (u32)(id & CQM_DW_MASK);

	cqm_swab32((u8 *)cmd, (sizeof(cqm_bloomfilter_cmd_s) >> CQM_DW_SHIFT));

	ret = cqm5_send_cmd_box(ex_handle, CQM_MOD_CQM, (u8)op, buf_in, NULL,
			       NULL, CQM_CMD_TIMEOUT, HINIC5_CHANNEL_DEFAULT);
	if (ret != CQM_SUCCESS) {
		cqm_err(handle->dev_hdl, CQM_FUNCTION_FAIL(cqm5_send_cmd_box));
		cqm_err(handle->dev_hdl, "Bloomfilter: bloomfilter_cmd ret=%d\n",
			ret);
		cqm_err(handle->dev_hdl, "Bloomfilter: op=0x%x, cmd: 0x%x 0x%x 0x%x 0x%x\n",
			op, *((u32 *)(void *)cmd), *(((u32 *)(void *)cmd) + CQM_DW_INDEX1),
			*(((u32 *)(void *)cmd) + CQM_DW_INDEX2),
			*(((u32 *)(void *)cmd) + CQM_DW_INDEX3));
		cqm5_cmd_free(ex_handle, buf_in);
		return CQM_FAIL;
	}

	cqm5_cmd_free(ex_handle, buf_in);

	return CQM_SUCCESS;
}

STATIC struct tag_cqm_handle *cqm_get_func_cqm_handle(struct hinic5_hwdev *ex_handle, u16 func_id)
{
	struct tag_cqm_handle *cqm_handle = NULL;
	u32 child_func_start, child_func_number;

	if (unlikely(ex_handle == NULL)) {
		CQM_PTR_CHECK_ERR(CQM_PTR_NULL(ex_handle));
		return NULL;
	}

	cqm_handle = (struct tag_cqm_handle *)(ex_handle->cqm_hdl);
	if (unlikely(cqm_handle == NULL)) {
		CQM_PTR_CHECK_ERR(CQM_PTR_NULL(cqm_handle));
		return NULL;
	}

	/* function id is PF/VF */
	if (func_id == hinic5_global_func_id(ex_handle))
		return cqm_handle;

	if (!CQM_IS_FAKE_PARENT(cqm_handle)) {
		cqm_err(ex_handle->dev_hdl, CQM_WRONG_VALUE(CQM_FAKE_FUNC_TYPE(cqm_handle)));
		return NULL;
	}

	child_func_start = cqm_get_child_func_start(cqm_handle);
	child_func_number = cqm_get_child_func_number(cqm_handle);
	/* function id is fake vf */
	if (func_id >= child_func_start && (func_id < (child_func_start + child_func_number)))
		return cqm_handle->fake_cqm_handle[func_id - (u16)child_func_start];

	return NULL;
}

/**
 * Prototype    : cqm5_bloomfilter_inc
 * Description  : The reference counting field is added to the ID of the
 *		  bloomfilter.
 * Input        : void *ex_handle
 *		  u64 id--hash value
 * Output       : None
 * Return Value : s32
 * 1.Date         : 2016/7/7
 *   Modification : Created function
 */
s32 cqm5_bloomfilter_inc(void *ex_handle, u16 func_id, u64 id)
{
	struct hinic5_hwdev *handle = (struct hinic5_hwdev *)ex_handle;
	struct tag_cqm_bloomfilter_table *bloomfilter_table = NULL;
	u32 array_tmp[CQM_BF_SECTION_NUMBER] = {0};
	struct tag_cqm_handle *cqm_handle = NULL;
	u32 array_index, array_bit, i;
	u32 k_flag = 0;

	if (!ex_handle)
		return CQM_FAIL;

	cqm_dbg_on(cqm_verbose, handle->dev_hdl,
		"Bloomfilter: func_id: %d, inc id=0x%llx\n", func_id, id);

	cqm_handle = cqm_get_func_cqm_handle(ex_handle, func_id);
	if (unlikely(cqm_handle == NULL)) {
		CQM_PTR_CHECK_ERR(CQM_PTR_NULL(cqm_handle));
		return CQM_FAIL;
	}

	if (cqm_handle->func_capability.bloomfilter_enable == 0) {
		cqm_info(handle->dev_hdl, "Bloomfilter inc: bloomfilter is disable\n");
		return CQM_SUCCESS;
	}

	/* |(array_index=0)32B(array_bit:256bits)|(array_index=1)32B(256bits)|
	 * array_index = 0~bloomfilter_table->table_size/256bit
	 * array_bit = 0~255
	 */
	bloomfilter_table = &cqm_handle->bloomfilter_table;

	/* The array index identifies a 32-byte entry. */
	array_index = (u32)CQM_BF_BITARRAY_INDEX(id, bloomfilter_table->array_mask);
	/* convert the unit of array_index to bit  */
	array_index = array_index << CQM_BF_ENTRY_SIZE_UNIT;
	cqm_dbg_on(cqm_verbose, handle->dev_hdl,
		"Bloomfilter: inc id=0x%llx, array_index=0x%x\n", id, array_index);

	mutex_lock(&bloomfilter_table->lock);
	for (i = 0; i < CQM_BF_SECTION_NUMBER; i++) {
		/* the position of the bit in 64-bit section */
		array_bit = (id >> (CQM_BF_SECTION_BASE + i * CQM_BF_SECTION_SIZE)) & CQM_BF_SECTION_MASK;
		/* array_bit + number of 32-byte array entries + number of
		 * 64-bit sections before the section
		 */
		array_bit = array_bit + array_index + (i * CQM_BF_SECTION_BIT_NUMBER);

		/* array_temp[i] records the index of the bloomfilter.
		 * It is used to roll back the reference counting of the
		 * bitarray.
		 */
		array_tmp[i] = array_bit;

		/* Add one to the corresponding bit in bloomfilter table.
		 * If the value changes from 0 to 1, change the corresponding
		 * bit in k_flag.
		 */
		(bloomfilter_table->table[array_bit])++;
		cqm_dbg_on(cqm_verbose, handle->dev_hdl,
			"Bloomfilter: inc bloomfilter_table->table[%d]=0x%x\n",
			array_bit, bloomfilter_table->table[array_bit]);
		if (bloomfilter_table->table[array_bit] == 1)
			k_flag |= (1U << i);
	}

	/* send cmd to ucode and set corresponding bit. */
	if (k_flag != 0 && cqm_bloomfilter_cmd(ex_handle, func_id, CQM_CMD_T_BLOOMFILTER_SET,
				k_flag, id) != CQM_SUCCESS) {
		cqm_err(handle->dev_hdl,
			CQM_FUNCTION_FAIL(cqm_bloomfilter_cmd_inc));
		for (i = 0; i < CQM_BF_SECTION_NUMBER; i++) {
			array_bit = array_tmp[i];
			(bloomfilter_table->table[array_bit])--;
		}
		mutex_unlock(&bloomfilter_table->lock);
		return CQM_FAIL;
	}

	mutex_unlock(&bloomfilter_table->lock);

	return CQM_SUCCESS;
}
EXPORT_SYMBOL(cqm5_bloomfilter_inc);

/**
 * Prototype    : cqm5_bloomfilter_dec
 * Description  : The reference counting field is decreased to the ID of the
 *		  bloomfilter.
 * Input        : void *ex_handle
 *		  u64 id--hash value
 * Output       : None
 * Return Value : s32
 * 1.Date         : 2016/7/7
 *   Modification : Created function
 */
s32 cqm5_bloomfilter_dec(void *ex_handle, u16 func_id, u64 id)
{
	struct hinic5_hwdev *handle = (struct hinic5_hwdev *)ex_handle;
	struct tag_cqm_bloomfilter_table *bloomfilter_table = NULL;
	u32 array_tmp[CQM_BF_SECTION_NUMBER] = {0};
	u8 decremented[CQM_BF_SECTION_NUMBER] = {0};
	struct tag_cqm_handle *cqm_handle = NULL;
	u32 array_index, array_bit, i;
	u32 k_flag = 0;

	if (!ex_handle)
		return CQM_FAIL;

	cqm_handle = cqm_get_func_cqm_handle(ex_handle, func_id);
	if (unlikely(cqm_handle == NULL)) {
		CQM_PTR_CHECK_ERR(CQM_PTR_NULL(cqm_handle));
		return CQM_FAIL;
	}

	if (cqm_handle->func_capability.bloomfilter_enable == 0) {
		cqm_info(handle->dev_hdl, "Bloomfilter dec: bloomfilter is disable\n");
		return CQM_SUCCESS;
	}

	bloomfilter_table = &cqm_handle->bloomfilter_table;

	/* The array index identifies a 32-byte entry. */
	array_index = (u32)CQM_BF_BITARRAY_INDEX(id, bloomfilter_table->array_mask);
	cqm_dbg_on(cqm_verbose, handle->dev_hdl,
		"Bloomfilter: dec id=0x%llx, array_index=0x%x\n", id, array_index);

	mutex_lock(&bloomfilter_table->lock);
	for (i = 0; i < CQM_BF_SECTION_NUMBER; i++) {
		/* the position of the bit in 64-bit section */
		array_bit = (id >> (CQM_BF_SECTION_BASE + i * CQM_BF_SECTION_SIZE)) &
			CQM_BF_SECTION_MASK;
		/* array_bit + number of 32-byte array entries + number of
		 * 64-bit sections before the section
		 */
		array_bit = array_bit + (array_index << 0x8) + (i * 0x40);

		/* array_temp[i] records the index of the bloomfilter.
		 * It is used to roll back the reference counting of the
		 * bitarray.
		 */
		array_tmp[i] = array_bit;

		/* Deduct one to the corresponding bit in bloomfilter table.
		 * If the value changes from 1 to 0, change the corresponding
		 * bit in k_flag. Do not continue -1 when the reference counting
		 * value of the bit is 0.
		 */
		if (bloomfilter_table->table[array_bit] != 0) {
			bloomfilter_table->table[array_bit]--;
			decremented[i] = 1;
			cqm_dbg_on(cqm_verbose, handle->dev_hdl,
				"Bloomfilter: dec bloomfilter_table->table[%d]=0x%x\n",
				array_bit, bloomfilter_table->table[array_bit]);
			if (bloomfilter_table->table[array_bit] == 0)
				k_flag |= (1U << i);
		}
	}

		/* send cmd to ucode and clear corresponding bit. */
	if (k_flag != 0 && cqm_bloomfilter_cmd(ex_handle, func_id, CQM_CMD_T_BLOOMFILTER_CLEAR,
				k_flag, id) != CQM_SUCCESS) {
		cqm_err(handle->dev_hdl, CQM_FUNCTION_FAIL(cqm_bloomfilter_cmd_dec));
		for (i = 0; i < CQM_BF_SECTION_NUMBER; i++) {
			if (decremented[i]) {
				array_bit = array_tmp[i];
				(bloomfilter_table->table[array_bit])++;
			}
		}
		mutex_unlock(&bloomfilter_table->lock);
		return CQM_FAIL;
	}

	mutex_unlock(&bloomfilter_table->lock);

	return CQM_SUCCESS;
}
EXPORT_SYMBOL(cqm5_bloomfilter_dec);
