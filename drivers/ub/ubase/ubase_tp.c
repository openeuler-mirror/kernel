// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved.
 *
 */

#include <ub/ubase/ubase_comm_ctrlq.h>

#include "ubase_ctrlq.h"
#include "ubase_dev.h"
#include "ubase_reset.h"
#include "ubase_tp.h"

#define UBASE_TRANS_TYPE_UM_TP 0x2

static int ubase_notify_tp_flush_done(struct ubase_dev *udev, u32 tpn)
{
	struct ubase_ctrlq_tp_fd_req req = {0};
	struct ubase_ctrlq_msg msg = {0};
	struct ubase_tpg *tpg;
	int ret, tmp_resp;
	u32 i;

	spin_lock(&udev->tp_ctx.tpg_lock);
	tpg = udev->tp_ctx.tpg;
	if (!tpg) {
		spin_unlock(&udev->tp_ctx.tpg_lock);
		ubase_warn(udev,
			   "ubase tpg res does not exist, tpn = %u.\n", tpn);
		return 0;
	}

	for (i = 0; i < udev->caps.unic_caps.tpg.max_cnt; i++) {
		if (tpn >= tpg[i].start_tpn &&
		    tpn < tpg[i].start_tpn + tpg[i].tp_cnt) {
			ubase_dbg(udev,
				 "receive tp flush done AE, tpn:%u, tpgn:%u.\n",
				 tpn, i);
			break;
		}
	}
	spin_unlock(&udev->tp_ctx.tpg_lock);

	msg.service_ver = UBASE_CTRLQ_SER_VER_01;
	msg.service_type = UBASE_CTRLQ_SER_TYPE_TP_ACL;
	msg.opcode = UBASE_CTRLQ_OPC_TP_FLUSH_DONE;
	msg.need_resp = 1;
	msg.in_size = sizeof(req);
	msg.in = &req;
	msg.out_size = sizeof(tmp_resp);
	msg.out = &tmp_resp;
	req.tpn = cpu_to_le32(tpn);

	ret = __ubase_ctrlq_send(udev, &msg, true, NULL);
	if (ret)
		ubase_err(udev, "failed to notify tp flush done, ret = %d.\n",
			  ret);

	spin_lock(&udev->tp_ctx.tpg_lock);
	if (udev->tp_ctx.tpg && i < udev->caps.unic_caps.tpg.max_cnt)
		atomic_inc(&tpg[i].tp_fd_cnt);
	else
		ubase_warn(udev,
			   "ubase tpg res does not exist, tpn = %u.\n", tpn);
	spin_unlock(&udev->tp_ctx.tpg_lock);

	return ret;
}

int ubase_ae_tp_flush_done(struct notifier_block *nb, unsigned long event,
			   void *data)
{
	struct ubase_event_nb *ev_nb = container_of(nb, struct ubase_event_nb, nb);
	struct ubase_dev *udev = (struct ubase_dev *)ev_nb->back;
	struct ubase_aeq_notify_info *info = data;
	u32 tp_num;

	tp_num = info->aeqe->event.queue_event.num;

	return ubase_notify_tp_flush_done(udev, tp_num);
}

int ubase_ae_tp_level_error(struct notifier_block *nb, unsigned long event,
			    void *data)
{
	struct ubase_event_nb *ev_nb = container_of(nb,
						    struct ubase_event_nb, nb);
	struct ubase_aeq_notify_info *info = data;
	struct ubase_dev *udev = ev_nb->back;
	u32 queue_num;

	queue_num = info->aeqe->event.queue_event.num;
	ubase_err(udev,
		  "ubase recv tp level error, event_type = 0x%x, sub_type = 0x%x, queue_num = %u\n",
		  info->event_type, info->sub_type, queue_num);

	__ubase_reset_event(udev, UBASE_UE_RESET);

	return 0;
}

static int ubase_create_tp_tpg(struct ubase_dev *udev, u32 vl)
{
	struct ubase_tp_layer_ctx *tp_ctx = &udev->tp_ctx;
	struct ubase_ctrlq_create_tp_resp resp = {0};
	struct ubase_ctrlq_create_tp_req req = {0};
	struct ubase_ctrlq_msg msg = {0};
	int ret;

	msg.service_ver = UBASE_CTRLQ_SER_VER_01;
	msg.service_type = UBASE_CTRLQ_SER_TYPE_TP_ACL;
	msg.opcode = UBASE_CTRLQ_OPC_CREATE_TP;
	msg.need_resp = 1;
	msg.in_size = sizeof(req);
	msg.in = &req;
	msg.out_size = sizeof(resp);
	msg.out = &resp;

	req.trans_type = UBASE_TRANS_TYPE_UM_TP;
	req.vl = (u8)vl;

	ret = __ubase_ctrlq_send(udev, &msg, true, NULL);
	if (ret && ret != -EEXIST) {
		if (ret == -ETIMEDOUT || ret == -ENODATA)
			set_bit(UBASE_STATE_INIT_AGAIN_B, &udev->state_bits);
		ubase_err(udev, "failed to alloc tp tpg, ret = %d.\n", ret);
		return ret;
	}

	tp_ctx->tpg[vl].mb_tpgn = le32_to_cpu(resp.tpgn);
	tp_ctx->tpg[vl].start_tpn = le32_to_cpu(resp.start_tpn);
	tp_ctx->tpg[vl].tp_cnt = resp.tpn_cnt;

	if (tp_ctx->tpg[vl].mb_tpgn != vl)
		ubase_warn(udev, "unexpected tpgn, vl = %u, tpgn = %u.\n",
			   vl, tp_ctx->tpg[vl].mb_tpgn);

	return 0;
}

static void ubase_wait_tp_flush_done(struct ubase_dev *udev, u32 vl)
{
	struct ubase_tpg *tpg = &udev->tp_ctx.tpg[vl];
	int i;

	for (i = 0; i < UBASE_WAIT_TP_FLUSH_TOTAL_STEPS; i++) {
		msleep(1 << i);

		if (atomic_read(&tpg->tp_fd_cnt) == tpg->tp_cnt)
			return;
	}

	ubase_warn(udev,
		   "wait tp flush done timeout, tpgn = %u, tp_fd_cnt = %u.\n",
		   vl, atomic_read(&tpg->tp_fd_cnt));
}

static void ubase_destroy_tp_tpg(struct ubase_dev *udev, u32 vl)
{
	struct ubase_ctrlq_destroy_tp_req req = {0};
	struct ubase_ctrlq_msg msg = {0};
	int tmp_resp, ret;

	msg.service_ver = UBASE_CTRLQ_SER_VER_01;
	msg.service_type = UBASE_CTRLQ_SER_TYPE_TP_ACL;
	msg.opcode = UBASE_CTRLQ_OPC_DESTROY_TP;
	msg.need_resp = 1;
	msg.in_size = sizeof(req);
	msg.in = &req;
	msg.out_size = sizeof(tmp_resp);
	msg.out = &tmp_resp;

	req.vl = (u8)vl;
	req.trans_type = UBASE_TRANS_TYPE_UM_TP;

	ret = __ubase_ctrlq_send(udev, &msg, true, NULL);
	if (ret) {
		ubase_err(udev,
			  "failed to send destroy tp tpg request, tpgn = %u, ret = %d.\n",
			  vl, ret);
		return;
	}

	ubase_wait_tp_flush_done(udev, vl);
}

static void ubase_destroy_multi_tp_tpg(struct ubase_dev *udev, u32 num)
{
	u32 idx;

	if (ubase_shutting_down(udev) && ubase_is_ctrl_node(udev))
		return;

	for (idx = 0; idx < num; idx++)
		ubase_destroy_tp_tpg(udev, idx);
}

static int ubase_create_multi_tp_tpg(struct ubase_dev *udev)
{
	int ret;
	u32 i;

	for (i = 0; i < udev->caps.unic_caps.tpg.max_cnt; i++) {
		ret = ubase_create_tp_tpg(udev, i);
		if (ret) {
			ubase_err(udev, "failed to create tp tpg, tpgn = %u, ret = %d.\n",
				  i, ret);
			goto err_create_tp_tpg;
		}
	}

	return 0;

err_create_tp_tpg:
	ubase_destroy_multi_tp_tpg(udev, i);

	return ret;
}

int ubase_dev_init_tp_tpg(struct ubase_dev *udev)
{
	struct ubase_adev_caps *unic_caps = &udev->caps.unic_caps;
	struct ubase_tp_layer_ctx *tp_ctx = &udev->tp_ctx;
	int ret;

	if (!ubase_utp_supported(udev) || !ubase_dev_urma_supported(udev))
		return 0;

	spin_lock(&tp_ctx->tpg_lock);
	tp_ctx->tpg = devm_kcalloc(udev->dev, unic_caps->tpg.max_cnt,
				   sizeof(struct ubase_tpg), GFP_ATOMIC);
	if (!tp_ctx->tpg) {
		spin_unlock(&tp_ctx->tpg_lock);
		return -ENOMEM;
	}
	spin_unlock(&tp_ctx->tpg_lock);

	ret = ubase_create_multi_tp_tpg(udev);
	if (ret) {
		spin_lock(&tp_ctx->tpg_lock);
		devm_kfree(udev->dev, tp_ctx->tpg);
		tp_ctx->tpg = NULL;
		spin_unlock(&tp_ctx->tpg_lock);
	}

	return ret;
}

void ubase_dev_uninit_tp_tpg(struct ubase_dev *udev)
{
	struct ubase_adev_caps *unic_caps = &udev->caps.unic_caps;
	struct ubase_tp_layer_ctx *tp_ctx = &udev->tp_ctx;
	u32 num = unic_caps->tpg.max_cnt;

	if (!ubase_utp_supported(udev) || !ubase_dev_urma_supported(udev))
		return;

	if (!tp_ctx->tpg)
		return;

	if (!test_bit(UBASE_STATE_RST_HANDLING_B, &udev->state_bits))
		ubase_destroy_multi_tp_tpg(udev, num);

	spin_lock(&tp_ctx->tpg_lock);
	devm_kfree(udev->dev, tp_ctx->tpg);
	tp_ctx->tpg = NULL;
	spin_unlock(&tp_ctx->tpg_lock);
}
