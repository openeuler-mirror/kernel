/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hinic5_cqm_cmd.c
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   :
 */

#include <linux/types.h>
#include <linux/sched.h>
#include <linux/module.h>
#include <linux/vmalloc.h>

#include "ossl_knl.h"
#include "hinic5_hw.h"
#include "hinic5_hwdev.h"

#include "hinic5_cqm_bitmap_table.h"
#include "hinic5_cqm_bat_cla.h"
#include "hinic5_cqm_main.h"

/**
 * Prototype    : hinic5_cqm_cmd_alloc
 * Description  : Apply for a cmd buffer. The buffer size is fixed to 2 KB.
 *		  The buffer content is not cleared and needs to be cleared by
 *		  services.
 * Input        : void *ex_handle
 * Output       : None
 * Return Value : struct tag_hinic5_cqm_cmd_buf *
 * 1.Date         : 2015/4/15
 *   Modification : Created function
 */
struct tag_hinic5_cqm_cmd_buf *hinic5_cqm_cmd_alloc(void *ex_handle)
{
	struct hinic5_hwdev *handle = (struct hinic5_hwdev *)ex_handle;

	if (unlikely(ex_handle == NULL)) {
		HINIC5_CQM_PTR_CHECK_ERR(HINIC5_CQM_PTR_NULL(ex_handle));
		return NULL;
	}

	atomic_inc(&handle->hw_stats.hinic5_cqm_stats.hinic5_cqm_cmd_alloc_cnt);

	return (struct tag_hinic5_cqm_cmd_buf *)(void *)hinic5_alloc_cmd_buf(ex_handle);
}
EXPORT_SYMBOL(hinic5_cqm_cmd_alloc);

/**
 * Prototype    : hinic5_cqm_cmd_free
 * Description  : Release for a cmd buffer.
 * Input        : void *ex_handle
 *		  struct tag_hinic5_cqm_cmd_buf *cmd_buf
 * Output       : None
 * Return Value : void
 * 1.Date         : 2015/4/15
 *   Modification : Created function
 */
void hinic5_cqm_cmd_free(void *ex_handle, struct tag_hinic5_cqm_cmd_buf *cmd_buf)
{
	struct hinic5_hwdev *handle = (struct hinic5_hwdev *)ex_handle;

	if (unlikely(ex_handle == NULL)) {
		HINIC5_CQM_PTR_CHECK_ERR(HINIC5_CQM_PTR_NULL(ex_handle));
		return;
	}
	if (unlikely(cmd_buf == NULL)) {
		HINIC5_CQM_PTR_CHECK_ERR(HINIC5_CQM_PTR_NULL(cmd_buf));
		return;
	}
	if (unlikely(cmd_buf->buf == NULL)) {
		HINIC5_CQM_PTR_CHECK_ERR(HINIC5_CQM_PTR_NULL(buf));
		return;
	}

	atomic_inc(&handle->hw_stats.hinic5_cqm_stats.hinic5_cqm_cmd_free_cnt);

	hinic5_free_cmd_buf(ex_handle, (struct hinic5_cmd_buf *)(void *)cmd_buf);
}
EXPORT_SYMBOL(hinic5_cqm_cmd_free);

/**
 * Prototype    : hinic5_cqm_send_cmd_box
 * Description  : Send a cmd message in box mode.
 *		  This interface will mount a completion quantity,
 *		  causing sleep.
 * Input        : void *ex_handle
 *		  u8 mod
 *		  u8 cmd,
 *		  struct tag_hinic5_cqm_cmd_buf *buf_in
 *		  struct tag_hinic5_cqm_cmd_buf *buf_out
 *		  u64 *out_param
 *		  u32 timeout
 * Output       : None
 * Return Value : s32
 * 1.Date         : 2015/4/15
 *   Modification : Created function
 */
s32 hinic5_cqm_send_cmd_box(void *ex_handle, u8 mod, u8 cmd, struct tag_hinic5_cqm_cmd_buf *buf_in,
		     struct tag_hinic5_cqm_cmd_buf *buf_out, u64 *out_param, u32 timeout,
		     u16 channel)
{
	struct hinic5_hwdev *handle = (struct hinic5_hwdev *)ex_handle;

	if (unlikely(ex_handle == NULL)) {
		HINIC5_CQM_PTR_CHECK_ERR(HINIC5_CQM_PTR_NULL(ex_handle));
		return HINIC5_CQM_FAIL;
	}
	if (unlikely(buf_in == NULL)) {
		HINIC5_CQM_PTR_CHECK_ERR(HINIC5_CQM_PTR_NULL(buf_in));
		return HINIC5_CQM_FAIL;
	}
	if (unlikely(buf_in->buf == NULL)) {
		HINIC5_CQM_PTR_CHECK_ERR(HINIC5_CQM_PTR_NULL(buf));
		return HINIC5_CQM_FAIL;
	}

	atomic_inc(&handle->hw_stats.hinic5_cqm_stats.hinic5_cqm_send_cmd_box_cnt);

	return hinic5_cmdq_detail_resp(ex_handle, mod, cmd,
				       (struct hinic5_cmd_buf *)(void *)buf_in,
				       (struct hinic5_cmd_buf *)(void *)buf_out,
				       out_param, timeout, channel);
}
EXPORT_SYMBOL(hinic5_cqm_send_cmd_box);

/**
 * Prototype    : hinic5_cqm_lb_send_cmd_box
 * Description  : Send a cmd message in box mode and open cos_id.
 *		  This interface will mount a completion quantity,
 *		  causing sleep.
 * Input        : void *ex_handle
 *		  u8 mod
 *		  u8 cmd
 *		  u8 cos_id
 *		  struct tag_hinic5_cqm_cmd_buf *buf_in
 *		  struct tag_hinic5_cqm_cmd_buf *buf_out
 *		  u64 *out_param
 *		  u32 timeout
 * Output       : None
 * Return Value : s32
 * 1.Date         : 2020/4/9
 *   Modification : Created function
 */
s32 hinic5_cqm_lb_send_cmd_box(void *ex_handle, u8 mod, u8 cmd, u8 cos_id,
			struct tag_hinic5_cqm_cmd_buf *buf_in, struct tag_hinic5_cqm_cmd_buf *buf_out,
			u64 *out_param, u32 timeout, u16 channel)
{
	struct hinic5_hwdev *handle = (struct hinic5_hwdev *)ex_handle;

	if (unlikely(buf_in == NULL)) {
		HINIC5_CQM_PTR_CHECK_ERR(HINIC5_CQM_PTR_NULL(buf_in));
		return HINIC5_CQM_FAIL;
	}
	if (unlikely(buf_in->buf == NULL)) {
		HINIC5_CQM_PTR_CHECK_ERR(HINIC5_CQM_PTR_NULL(buf_in->buf));
		return HINIC5_CQM_FAIL;
	}
	if (unlikely(ex_handle == NULL)) {
		HINIC5_CQM_PTR_CHECK_ERR(HINIC5_CQM_PTR_NULL(ex_handle));
		return HINIC5_CQM_FAIL;
	}

	atomic_inc(&handle->hw_stats.hinic5_cqm_stats.hinic5_cqm_send_cmd_box_cnt);

	return hinic5_cos_id_detail_resp(ex_handle, mod, cmd, cos_id,
					 (struct hinic5_cmd_buf *)(void *)buf_in,
					 (struct hinic5_cmd_buf *)(void *)buf_out,
					 out_param, timeout, channel);
}
EXPORT_SYMBOL(hinic5_cqm_lb_send_cmd_box);

/**
 * Prototype    : hinic5_cqm_send_cmd_imm
 * Description  : Send a cmd message in imm mode.
 *		  This interface will mount a completion quantity,
 *		  causing sleep.
 * Input        : void *ex_handle
 *		  u8 mod
 *		  u8 cmd
 *		  struct tag_hinic5_cqm_cmd_buf *buf_in
 *		  u64 *out_param
 *		  u32 timeout
 * Output       : None
 * Return Value : s32
 * 1.Date         : 2015/4/15
 *   Modification : Created function
 */
s32 hinic5_cqm_send_cmd_imm(void *ex_handle, u8 mod, u8 cmd, struct tag_hinic5_cqm_cmd_buf *buf_in,
		     u64 *out_param, u32 timeout, u16 channel)
{
	struct hinic5_hwdev *handle = (struct hinic5_hwdev *)ex_handle;

	if (unlikely(buf_in == NULL)) {
		HINIC5_CQM_PTR_CHECK_ERR(HINIC5_CQM_PTR_NULL(buf_in));
		return HINIC5_CQM_FAIL;
	}
	if (unlikely(buf_in->buf == NULL)) {
		HINIC5_CQM_PTR_CHECK_ERR(HINIC5_CQM_PTR_NULL(buf));
		return HINIC5_CQM_FAIL;
	}
	if (unlikely(ex_handle == NULL)) {
		HINIC5_CQM_PTR_CHECK_ERR(HINIC5_CQM_PTR_NULL(ex_handle));
		return HINIC5_CQM_FAIL;
	}

	atomic_inc(&handle->hw_stats.hinic5_cqm_stats.hinic5_cqm_send_cmd_imm_cnt);

	return hinic5_cmdq_direct_resp((void *)ex_handle, mod, cmd,
				       (struct hinic5_cmd_buf *)(void *)buf_in,
				       out_param, timeout, channel);
}
EXPORT_SYMBOL(hinic5_cqm_send_cmd_imm);
