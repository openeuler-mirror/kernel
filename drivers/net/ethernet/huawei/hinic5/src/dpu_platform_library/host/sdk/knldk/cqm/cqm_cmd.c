/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : cqm_cmd.c
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/09/16
 * Description   : CQM command implementation
 */

#include <linux/types.h>
#include <linux/sched.h>
#include <linux/module.h>
#include <linux/vmalloc.h>

#include "ossl_knl.h"
#include "hinic5_hw.h"
#include "hinic5_hwdev.h"

#include "cqm_bitmap_table.h"
#include "cqm_bat_cla.h"
#include "cqm_main.h"

/**
 * Prototype    : cqm5_cmd_alloc
 * Description  : Apply for a cmd buffer. The buffer size is fixed to 2 KB.
 *		  The buffer content is not cleared and needs to be cleared by
 *		  services.
 * Input        : void *ex_handle
 * Output       : None
 * Return Value : struct tag_cqm_cmd_buf *
 * 1.Date         : 2015/4/15
 *   Modification : Created function
 */
struct tag_cqm_cmd_buf *cqm5_cmd_alloc(void *ex_handle)
{
	struct hinic5_hwdev *handle = (struct hinic5_hwdev *)ex_handle;

	if (unlikely(ex_handle == NULL)) {
		CQM_PTR_CHECK_ERR(CQM_PTR_NULL(ex_handle));
		return NULL;
	}

	atomic_inc(&handle->hw_stats.cqm_stats.cqm5_cmd_alloc_cnt);

	return (struct tag_cqm_cmd_buf *)(void *)hinic5_alloc_cmd_buf(ex_handle);
}
EXPORT_SYMBOL(cqm5_cmd_alloc);

/**
 * Prototype    : cqm5_cmd_free
 * Description  : Release for a cmd buffer.
 * Input        : void *ex_handle
 *		  struct tag_cqm_cmd_buf *cmd_buf
 * Output       : None
 * Return Value : void
 * 1.Date         : 2015/4/15
 *   Modification : Created function
 */
void cqm5_cmd_free(void *ex_handle, struct tag_cqm_cmd_buf *cmd_buf)
{
	struct hinic5_hwdev *handle = (struct hinic5_hwdev *)ex_handle;

	if (unlikely(ex_handle == NULL)) {
		CQM_PTR_CHECK_ERR(CQM_PTR_NULL(ex_handle));
		return;
	}
	if (unlikely(cmd_buf == NULL)) {
		CQM_PTR_CHECK_ERR(CQM_PTR_NULL(cmd_buf));
		return;
	}
	if (unlikely(cmd_buf->buf == NULL)) {
		CQM_PTR_CHECK_ERR(CQM_PTR_NULL(buf));
		return;
	}

	atomic_inc(&handle->hw_stats.cqm_stats.cqm5_cmd_free_cnt);

	hinic5_free_cmd_buf(ex_handle, (struct hinic5_cmd_buf *)(void *)cmd_buf);
}
EXPORT_SYMBOL(cqm5_cmd_free);

/**
 * Prototype    : cqm5_send_cmd_box
 * Description  : Send a cmd message in box mode.
 *		  This interface will mount a completion quantity,
 *		  causing sleep.
 * Input        : void *ex_handle
 *		  u8 mod
 *		  u8 cmd,
 *		  struct tag_cqm_cmd_buf *buf_in
 *		  struct tag_cqm_cmd_buf *buf_out
 *		  u64 *out_param
 *		  u32 timeout
 * Output       : None
 * Return Value : s32
 * 1.Date         : 2015/4/15
 *   Modification : Created function
 */
s32 cqm5_send_cmd_box(void *ex_handle, u8 mod, u8 cmd, struct tag_cqm_cmd_buf *buf_in,
		     struct tag_cqm_cmd_buf *buf_out, u64 *out_param, u32 timeout,
		     u16 channel)
{
	struct hinic5_hwdev *handle = (struct hinic5_hwdev *)ex_handle;

	if (unlikely(ex_handle == NULL)) {
		CQM_PTR_CHECK_ERR(CQM_PTR_NULL(ex_handle));
		return CQM_FAIL;
	}
	if (unlikely(buf_in == NULL)) {
		CQM_PTR_CHECK_ERR(CQM_PTR_NULL(buf_in));
		return CQM_FAIL;
	}
	if (unlikely(buf_in->buf == NULL)) {
		CQM_PTR_CHECK_ERR(CQM_PTR_NULL(buf));
		return CQM_FAIL;
	}

	atomic_inc(&handle->hw_stats.cqm_stats.cqm5_send_cmd_box_cnt);

	return hinic5_cmdq_detail_resp(ex_handle, mod, cmd,
				       (struct hinic5_cmd_buf *)(void *)buf_in,
				       (struct hinic5_cmd_buf *)(void *)buf_out,
				       out_param, timeout, channel);
}
EXPORT_SYMBOL(cqm5_send_cmd_box);

/**
 * Prototype    : cqm5_lb_send_cmd_box
 * Description  : Send a cmd message in box mode and open cos_id.
 *		  This interface will mount a completion quantity,
 *		  causing sleep.
 * Input        : void *ex_handle
 *		  u8 mod
 *		  u8 cmd
 *		  u8 cos_id
 *		  struct tag_cqm_cmd_buf *buf_in
 *		  struct tag_cqm_cmd_buf *buf_out
 *		  u64 *out_param
 *		  u32 timeout
 * Output       : None
 * Return Value : s32
 * 1.Date         : 2020/4/9
 *   Modification : Created function
 */
s32 cqm5_lb_send_cmd_box(void *ex_handle, u8 mod, u8 cmd, u8 cos_id,
			struct tag_cqm_cmd_buf *buf_in, struct tag_cqm_cmd_buf *buf_out,
			u64 *out_param, u32 timeout, u16 channel)
{
	struct hinic5_hwdev *handle = (struct hinic5_hwdev *)ex_handle;

	if (unlikely(buf_in == NULL)) {
		CQM_PTR_CHECK_ERR(CQM_PTR_NULL(buf_in));
		return CQM_FAIL;
	}
	if (unlikely(buf_in->buf == NULL)) {
		CQM_PTR_CHECK_ERR(CQM_PTR_NULL(buf_in->buf));
		return CQM_FAIL;
	}
	if (unlikely(ex_handle == NULL)) {
		CQM_PTR_CHECK_ERR(CQM_PTR_NULL(ex_handle));
		return CQM_FAIL;
	}

	atomic_inc(&handle->hw_stats.cqm_stats.cqm5_send_cmd_box_cnt);

	return hinic5_cos_id_detail_resp(ex_handle, mod, cmd, cos_id,
					 (struct hinic5_cmd_buf *)(void *)buf_in,
					 (struct hinic5_cmd_buf *)(void *)buf_out,
					 out_param, timeout, channel);
}
EXPORT_SYMBOL(cqm5_lb_send_cmd_box);

/**
 * Prototype    : cqm5_send_cmd_imm
 * Description  : Send a cmd message in imm mode.
 *		  This interface will mount a completion quantity,
 *		  causing sleep.
 * Input        : void *ex_handle
 *		  u8 mod
 *		  u8 cmd
 *		  struct tag_cqm_cmd_buf *buf_in
 *		  u64 *out_param
 *		  u32 timeout
 * Output       : None
 * Return Value : s32
 * 1.Date         : 2015/4/15
 *   Modification : Created function
 */
s32 cqm5_send_cmd_imm(void *ex_handle, u8 mod, u8 cmd, struct tag_cqm_cmd_buf *buf_in,
		     u64 *out_param, u32 timeout, u16 channel)
{
	struct hinic5_hwdev *handle = (struct hinic5_hwdev *)ex_handle;

	if (unlikely(buf_in == NULL)) {
		CQM_PTR_CHECK_ERR(CQM_PTR_NULL(buf_in));
		return CQM_FAIL;
	}
	if (unlikely(buf_in->buf == NULL)) {
		CQM_PTR_CHECK_ERR(CQM_PTR_NULL(buf));
		return CQM_FAIL;
	}
	if (unlikely(ex_handle == NULL)) {
		CQM_PTR_CHECK_ERR(CQM_PTR_NULL(ex_handle));
		return CQM_FAIL;
	}

	atomic_inc(&handle->hw_stats.cqm_stats.cqm5_send_cmd_imm_cnt);

	return hinic5_cmdq_direct_resp((void *)ex_handle, mod, cmd,
				       (struct hinic5_cmd_buf *)(void *)buf_in,
				       out_param, timeout, channel);
}
EXPORT_SYMBOL(cqm5_send_cmd_imm);
