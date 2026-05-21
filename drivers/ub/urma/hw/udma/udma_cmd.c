// SPDX-License-Identifier: GPL-2.0+
/* Copyright(c) 2025 HiSilicon Technologies CO., Ltd. All rights reserved. */

#define dev_fmt(fmt) "UDMA: " fmt

#include <linux/slab.h>
#include <linux/dmapool.h>
#include <ub/ubase/ubase_comm_dev.h>
#include "udma_safe_mode.h"
#include "udma_eid.h"
#include "udma_cmd.h"
#include "udma_jfc.h"
#include "udma_jfr.h"
#include "udma_jetty.h"
#include "udma_eq.h"

bool debug_switch;

int udma_cmd_init(struct udma_dev *udma_dev)
{
	sema_init(&udma_dev->mb_cmd.poll_sem, 1);
	udma_dev->mb_cmd.pool = dma_pool_create("udma_cmd", udma_dev->dev,
						UDMA_MAILBOX_SIZE,
						UDMA_MAILBOX_SIZE, 0);
	if (!udma_dev->mb_cmd.pool) {
		dev_err(udma_dev->dev, "failed to dma_pool_create.\n");
		return -ENOMEM;
	}

	init_rwsem(&udma_dev->mb_cmd.udma_mb_rwsem);

	return 0;
}

void udma_cmd_cleanup(struct udma_dev *udma_dev)
{
	down_write(&udma_dev->mb_cmd.udma_mb_rwsem);
	dma_pool_destroy(udma_dev->mb_cmd.pool);
	up_write(&udma_dev->mb_cmd.udma_mb_rwsem);
}

static void udma_set_mb_flag_or_fd(uint8_t op, void *buf)
{
	struct udma_jetty_ctx *jfs_ctx;

	if (op == UDMA_CMD_QUERY_JFS_CONTEXT) {
		jfs_ctx = (struct udma_jetty_ctx *)buf;
		jfs_ctx->flush_cqe_done = 1;
		jfs_ctx->state = 1;
		jfs_ctx->flush_ssn_vld = 1;
	}
}

static bool udma_op_ignore_eagain(uint8_t op, void *buf)
{
	struct udma_mbx_op_match matches[] = {
		{ UDMA_CMD_CREATE_JFS_CONTEXT, false },
		{ UDMA_CMD_MODIFY_JFS_CONTEXT, true },
		{ UDMA_CMD_DESTROY_JFS_CONTEXT, true },
		{ UDMA_CMD_QUERY_JFS_CONTEXT, true },
		{ UDMA_CMD_CREATE_JFC_CONTEXT, false },
		{ UDMA_CMD_MODIFY_JFC_CONTEXT, true },
		{ UDMA_CMD_DESTROY_JFC_CONTEXT, true },
		{ UDMA_CMD_QUERY_JFC_CONTEXT, true },
		{ UDMA_CMD_CREATE_JFR_CONTEXT, false },
		{ UDMA_CMD_MODIFY_JFR_CONTEXT, true },
		{ UDMA_CMD_DESTROY_JFR_CONTEXT, true },
		{ UDMA_CMD_QUERY_JFR_CONTEXT, true },
		{ UDMA_CMD_QUERY_TP_CONTEXT, true },
		{ UDMA_CMD_CREATE_JETTY_GROUP_CONTEXT, false },
		{ UDMA_CMD_MODIFY_JETTY_GROUP_CONTEXT, true },
		{ UDMA_CMD_DESTROY_JETTY_GROUP_CONTEXT, true },
		{ UDMA_CMD_QUERY_JETTY_GROUP_CONTEXT, true },
		{ UDMA_CMD_CREATE_RC_CONTEXT, false },
		{ UDMA_CMD_MODIFY_RC_CONTEXT, true },
		{ UDMA_CMD_DESTROY_RC_CONTEXT, true },
		{ UDMA_CMD_QUERY_RC_CONTEXT, true },
	};
	uint32_t i;

	for (i = 0; i < ARRAY_SIZE(matches); i++) {
		if (op == matches[i].op) {
			udma_set_mb_flag_or_fd(op, buf);
			return matches[i].ignore_ret;
		}
	}

	return false;
}

int udma_post_mbox(struct udma_dev *dev, struct ubase_cmd_mailbox *mailbox,
		   struct ubase_mbx_attr *attr)
{
	int ret;

	if (debug_switch)
		dev_info_ratelimited(dev->dev,
				     "Send cmd mailbox, data: %08x %04x%04x.\n",
				     attr->tag, attr->op, attr->mbx_ue_id);

	ret = ubase_adev_mbx_supported(dev->comdev.adev) ?
	      ubase_hw_upgrade_ctx_ex(dev->comdev.adev, attr, mailbox) :
	      udma_post_mbox_over_cmdq(dev, attr, mailbox);

	return (ret == -EAGAIN &&
		udma_op_ignore_eagain(attr->op, mailbox->buf)) ? 0 : ret;
}

int udma_config_ctx_buf_to_hw(struct udma_dev *udma_dev,
			      struct udma_buf *ctx_buf,
			      struct ubase_mbx_attr *attr)
{
	struct ubase_cmd_mailbox mailbox;
	int ret;

	mailbox.dma = ctx_buf->addr;
	ret = udma_post_mbox(udma_dev, &mailbox, attr);
	if (ret)
		dev_err(udma_dev->dev,
			"failed to config ctx_buf to hw, ret = %d.\n", ret);

	return ret;
}

int udma_cmd_query_hw_resource(struct udma_dev *udma_dev, void *out_addr)
{
	struct ubase_cmd_buf out = {};
	struct ubase_cmd_buf in = {};

	udma_fill_buf(&in, UDMA_CMD_QUERY_UE_RES, true, 0, NULL);
	udma_fill_buf(&out, UDMA_CMD_QUERY_UE_RES, true,
		      sizeof(struct udma_cmd_ue_resource), out_addr);

	return ubase_cmd_send_inout(udma_dev->comdev.adev, &in, &out);
}

int udma_query_ucp_res(struct udma_dev *udma_dev, void *out_addr)
{
	struct ubase_cmd_buf out = {};
	struct ubase_cmd_buf in = {};

	udma_fill_buf(&in, UDMA_CMD_QUERY_UCP_RES, true, 0, NULL);
	udma_fill_buf(&out, UDMA_CMD_QUERY_UCP_RES, true,
		      sizeof(struct udma_cmd_ucp_resource), out_addr);

	return ubase_cmd_send_inout(udma_dev->comdev.adev, &in, &out);
}

int post_mailbox_update_ctx(struct udma_dev *udma_dev, void *ctx, uint32_t size,
			    struct ubase_mbx_attr *attr)
{
	struct ubase_cmd_mailbox *mailbox;
	int ret;

	mailbox = udma_alloc_cmd_mailbox(udma_dev);
	if (!mailbox) {
		dev_err(udma_dev->dev,
			"failed to alloc mailbox for opcode 0x%x.\n", attr->op);
		return -ENOMEM;
	}

	if (ctx)
		memcpy(mailbox->buf, ctx, size);

	ret = udma_post_mbox(udma_dev, mailbox, attr);
	if (ret)
		dev_err(udma_dev->dev,
			"failed to post mailbox, opcode = 0x%x, ret = %d.\n", attr->op,
			ret);

	udma_free_cmd_mailbox(udma_dev, mailbox);

	return ret;
}

struct ubase_cmd_mailbox *udma_mailbox_query_ctx(struct udma_dev *udma_dev,
						struct ubase_mbx_attr *attr)
{
	struct ubase_cmd_mailbox *mailbox;
	int ret;

	mailbox = udma_alloc_cmd_mailbox(udma_dev);
	if (!mailbox) {
		dev_err(udma_dev->dev,
			"failed to alloc mailbox query ctx, opcode = %u, id = %u.\n",
			attr->op, attr->tag);
		return NULL;
	}

	ret = udma_post_mbox(udma_dev, mailbox, attr);
	if (ret) {
		dev_err(udma_dev->dev,
			"failed to post mailbox query ctx, opcode = %u, id = %u, ret = %d.\n",
			attr->op, attr->tag, ret);
		udma_free_cmd_mailbox(udma_dev, mailbox);
		return NULL;
	}

	return mailbox;
}

int udma_close_ue_rx(struct udma_dev *dev, bool check_feature_enable, bool check_ta_flush,
		     bool is_reset, uint32_t tp_num)
{
	int ret = 0;

	if (check_ta_flush)
		return ret;

	if (check_feature_enable && !(dev->caps.feature & UDMA_CAP_FEATURE_UE_RX_CLOSE))
		return ret;

	mutex_lock(&dev->disable_ue_rx_mutex);
	if (dev->disable_ue_rx_count == 0 && !is_reset) {
		ret = ubase_deactivate_dev(dev->comdev.adev);
		if (ret) {
			dev_err(dev->dev, "failed to close ue rx, ret = %d.\n", ret);
			goto out;
		}
	}
	if (tp_num)
		dev->disable_ue_rx_count += (int)tp_num;
	else
		dev->disable_ue_rx_count++;
out:
	mutex_unlock(&dev->disable_ue_rx_mutex);

	return ret;
}

static void udma_open_ue_rx_work(struct work_struct *work)
{
	struct udma_flush_work *open_ue_rx_work =
		container_of(work, struct udma_flush_work, work);
	bool check_ta_flush = open_ue_rx_work->check_ta_flush;
	struct udma_dev *udma_dev = open_ue_rx_work->udev;
	uint32_t tp_num = open_ue_rx_work->tp_num;
	uint32_t wait_time = UDMA_MIN_SLEEP_TIME;
	int ret = 0;

	while (true) {
		mutex_lock(&udma_dev->open_rx_mutex);
		if (udma_dev->open_ue_rx_failed) {
			ret = udma_open_ue_rx(udma_dev, true, check_ta_flush, false, tp_num);
			if (!ret) {
				udma_dev->open_ue_rx_failed = false;
				mutex_unlock(&udma_dev->open_rx_mutex);
				break;
			}
			mutex_unlock(&udma_dev->open_rx_mutex);
			msleep(wait_time);
			if (wait_time < UDMA_OPEN_RX_MAX_SLEEP_TIME)
				wait_time *= UDMA_TIME_SLEEP_RATE;
			dev_err_ratelimited(udma_dev->dev, "failed to open ue rx when retry\n");
			continue;
		}
		mutex_unlock(&udma_dev->open_rx_mutex);
		break;
	}

	kfree(open_ue_rx_work);
	open_ue_rx_work = NULL;
}

static void udma_init_open_ue_rx_work(struct udma_dev *udma_dev, uint32_t tp_num,
				      bool check_ta_flush)
{
	struct udma_flush_work *open_ue_rx_work;

	open_ue_rx_work = kzalloc(sizeof(struct udma_flush_work), GFP_KERNEL);
	if (!open_ue_rx_work)
		return;
	open_ue_rx_work->udev = udma_dev;
	open_ue_rx_work->check_ta_flush = check_ta_flush;
	open_ue_rx_work->tp_num = tp_num;

	INIT_WORK(&open_ue_rx_work->work, udma_open_ue_rx_work);
	queue_work(udma_dev->ue_rx_workq, &open_ue_rx_work->work);
}

int udma_open_ue_rx(struct udma_dev *dev, bool check_feature_enable, bool check_ta_flush,
		    bool is_reset, uint32_t tp_num)
{
	int ret = 0;

	if (check_ta_flush)
		return ret;

	if (check_feature_enable && !(dev->caps.feature & UDMA_CAP_FEATURE_UE_RX_CLOSE))
		return ret;

	mutex_lock(&dev->disable_ue_rx_mutex);
	if (!is_reset && ((tp_num && dev->disable_ue_rx_count == tp_num) ||
	   (!tp_num && dev->disable_ue_rx_count == 1))) {
		ret = ubase_activate_dev(dev->comdev.adev);
		if (ret) {
			dev_err(dev->dev, "failed to open ue rx, ret = %d.\n", ret);
			goto out;
		}
	}

	if (tp_num)
		dev->disable_ue_rx_count -= (int)tp_num;
	else
		dev->disable_ue_rx_count--;
out:
	mutex_unlock(&dev->disable_ue_rx_mutex);

	return ret;
}

int udma_open_ue_rx_with_retry(struct udma_dev *dev, bool check_feature_enable, bool check_ta_flush,
			       bool is_reset, uint32_t tp_num)
{
	int ret;

	mutex_lock(&dev->open_rx_mutex);
	ret = udma_open_ue_rx(dev, check_feature_enable, check_ta_flush, is_reset, tp_num);
	if (ret == -ETIMEDOUT) {
		dev->open_ue_rx_failed = true;
		dev->current_handle_tp_num = tp_num;
		mutex_unlock(&dev->open_rx_mutex);
		dev_err(dev->dev, "failed to open ue rx, ret = %d, will retry later.\n", ret);
		udma_init_open_ue_rx_work(dev, tp_num, check_ta_flush);
		return ret;
	}
	mutex_unlock(&dev->open_rx_mutex);

	return ret;
}

void udma_unset_dtu_va_info(struct udma_dev *dev, struct udma_context *ctx)
{
	struct udma_cmd_config_dtu_tbl dtu_info = {};
	struct ubase_cmd_buf in;
	int ret;

	if (!ctx->dtu_en)
		return;

	dtu_info.en = 0;
	dtu_info.win_num = ctx->dtu_win_num;

	udma_fill_buf(&in, UDMA_CMD_CONFIG_DTU_TBL, false,
		      sizeof(dtu_info), (void *)&dtu_info);

	ret = ubase_cmd_send_in(dev->comdev.adev, &in);
	if (ret)
		dev_warn(dev->dev, "failed to delete dtu info, ret = %d.\n", ret);
}

int udma_set_dtu_va_info(struct udma_dev *dev, struct udma_context *ctx)
{
	struct udma_cmd_config_dtu_tbl dtu_info = {};
	struct ubase_cmd_buf in, out;
	uint64_t total_limit;
	int ret;

	if (!ctx->dtu_en)
		return 0;

	total_limit = dev->dtu_info.va_base + dev->dtu_info.pa_size;
	if (dev->dtu_info.va_base > U64_MAX - dev->dtu_info.pa_size) {
		dev_err(dev->dev, "check the sum of 'va base' and 'pa size' failed.\n");
		return -EINVAL;
	}

	dtu_info.en = 1;
	dtu_info.exclusive = 1;
	dtu_info.perm_read = 1;
	dtu_info.perm_write = 1;
	dtu_info.perm_atomic = 1;
	dtu_info.bufferable = 1;
	dtu_info.modified = 1;
	dtu_info.read_allocate = 1;
	dtu_info.write_allocate = 1;
	dtu_info.snoop = 1;
	dtu_info.tid = ctx->tid;
	dtu_info.base_addr_l = dev->dtu_info.va_base & (uint32_t)ADDR_BASE_MASK;
	dtu_info.base_addr_h = (dev->dtu_info.va_base >> ADDR_BASE_H_OFFSET) &
			       (uint32_t)ADDR_BASE_MASK;
	dtu_info.limit_addr_l = total_limit & (uint32_t)ADDR_BASE_MASK;
	dtu_info.limit_addr_h = (total_limit >> ADDR_BASE_H_OFFSET) & (uint32_t)ADDR_BASE_MASK;
	dtu_info.target_addr_l = dev->dtu_info.pa_base & (uint32_t)ADDR_BASE_MASK;
	dtu_info.target_addr_h = (dev->dtu_info.pa_base >> ADDR_BASE_H_OFFSET) &
				 (uint32_t)ADDR_BASE_MASK;

	udma_fill_buf(&in, UDMA_CMD_CONFIG_DTU_TBL, false,
		      sizeof(dtu_info), (void *)&dtu_info);
	udma_fill_buf(&out, UDMA_CMD_CONFIG_DTU_TBL, true,
		      sizeof(dtu_info), (void *)&dtu_info);
	ret = ubase_cmd_send_inout(dev->comdev.adev, &in, &out);
	if (ret) {
		dev_err(dev->dev, "failed to set dtu info, ret = %d.\n", ret);
		return -EFAULT;
	}
	ctx->dtu_win_num = dtu_info.win_num;

	return 0;
}

module_param(debug_switch, bool, 0444);
MODULE_PARM_DESC(debug_switch, "set debug print ON, default: false");
