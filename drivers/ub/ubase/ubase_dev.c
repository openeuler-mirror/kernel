// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved.
 *
 */

#include <linux/delay.h>
#include <linux/etherdevice.h>
#include <linux/kernel.h>
#include <linux/ummu_core.h>

#include <ub/ubus/ubus.h>

#include "debugfs/ubase_debugfs.h"
#include "ubase_arq.h"
#include "ubase_cmd.h"
#include "ubase_ctrlq.h"
#include "ubase_dtumem.h"
#include "ubase_hw.h"
#include "ubase_mailbox.h"
#include "ubase_pmem.h"
#include "ubase_proxy.h"
#include "ubase_rct.h"
#include "ubase_reset.h"
#include "ubase_stats.h"
#include "ubase_usc.h"
#include "ubase_dev.h"

#define UBASE_PERIOD_100MS 100

static int ubase_debug;
module_param_named(debug, ubase_debug, int, 0644);
MODULE_PARM_DESC(debug, "enable ubase debug log, 0:disable, others:enable, default:0");

static DEFINE_IDA(ubase_adev_ida);

bool ubase_dev_urma_supported(struct ubase_dev *udev)
{
	struct ub_entity *ue = container_of(udev->dev, struct ub_entity, dev);

	switch (uent_device(ue)) {
	case UBASE_DEV_ID_K_0_URMA_MUE:
	case UBASE_DEV_ID_K_0_URMA_UE:
	case UBASE_DEV_ID_A_0_URMA_MUE:
	case UBASE_DEV_ID_A_0_URMA_UE:
	case UBASE_DEV_ID_A_0_UBOE_MUE:
	case UBASE_DEV_ID_A_0_UBOE_UE:
	case UBASE_DEV_ID_S_0_URMA_MUE:
	case UBASE_DEV_ID_S_0_URMA_UE:
	case UBASE_DEV_ID_K_V2_URMA_MUE:
	case UBASE_DEV_ID_K_V2_URMA_UE:
	case UBASE_DEV_ID_A_V2_URMA_MUE:
	case UBASE_DEV_ID_A_V2_URMA_UE:
	case UBASE_DEV_ID_A_V2_UBOE_MUE:
	case UBASE_DEV_ID_A_V2_UBOE_UE:
		break;
	default:
		return false;
	}

	return true;
}

bool ubase_dev_unic_supported(struct ubase_dev *udev)
{
	struct ub_entity *ue = container_of(udev->dev, struct ub_entity, dev);

	switch (uent_device(ue)) {
	case UBASE_DEV_ID_K_0_URMA_MUE:
	case UBASE_DEV_ID_A_0_URMA_MUE:
	case UBASE_DEV_ID_A_0_UBOE_MUE:
	case UBASE_DEV_ID_S_0_URMA_MUE:
	case UBASE_DEV_ID_K_V2_URMA_MUE:
	case UBASE_DEV_ID_A_V2_URMA_MUE:
	case UBASE_DEV_ID_A_V2_UBOE_MUE:
		break;
	default:
		return false;
	}

	return !ubase_get_cap_bit(udev, UBASE_SUPPORT_UNIC_DISABLE_B);
}

bool ubase_dev_cdma_supported(struct ubase_dev *udev)
{
	struct ub_entity *ue = container_of(udev->dev, struct ub_entity, dev);

	switch (uent_device(ue)) {
	case UBASE_DEV_ID_K_0_CDMA_MUE:
	case UBASE_DEV_ID_K_0_CDMA_UE:
	case UBASE_DEV_ID_A_0_CDMA_MUE:
	case UBASE_DEV_ID_A_0_CDMA_UE:
	case UBASE_DEV_ID_S_0_CDMA_MUE:
	case UBASE_DEV_ID_K_V2_CDMA_MUE:
	case UBASE_DEV_ID_K_V2_CDMA_UE:
	case UBASE_DEV_ID_A_V2_CDMA_MUE:
	case UBASE_DEV_ID_A_V2_CDMA_UE:
		break;
	default:
		return false;
	}

	return true;
}

bool ubase_dev_pmu_supported(struct ubase_dev *udev)
{
	struct ub_entity *ue = container_of(udev->dev, struct ub_entity, dev);

	switch (uent_device(ue)) {
	case UBASE_DEV_ID_K_0_PMU_MUE:
	case UBASE_DEV_ID_K_0_PMU_UE:
	case UBASE_DEV_ID_A_0_PMU_MUE:
	case UBASE_DEV_ID_A_0_PMU_UE:
	case UBASE_DEV_ID_S_0_PMU_MUE:
	case UBASE_DEV_ID_K_V2_PMU_MUE:
	case UBASE_DEV_ID_K_V2_PMU_UE:
	case UBASE_DEV_ID_A_V2_PMU_MUE:
	case UBASE_DEV_ID_A_V2_PMU_UE:
		break;
	default:
		return false;
	}

	return true;
}

bool ubase_dev_fwctl_supported(struct ubase_dev *udev)
{
	return ubase_dev_pmu_supported(udev);
}

static bool ubase_dev_proxy_supported(struct ubase_dev *udev)
{
	return udev->caps.dev_caps.ue_num > 1 &&
	       ubase_dev_mbx_proxy_supported(udev);
}

static struct ubase_adev_device {
	const char *suffix;
	bool (*is_supported)(struct ubase_dev *dev);
} ubase_adev_devices[UBASE_DRV_MAX] = {
	[UBASE_DRV_UNIC] = {
		.suffix = "unic",
		.is_supported = &ubase_dev_unic_supported
	},
	[UBASE_DRV_UDMA] = {
		.suffix = "udma",
		.is_supported = &ubase_dev_udma_supported
	},
	[UBASE_DRV_CDMA] = {
		.suffix = "cdma",
		.is_supported = &ubase_dev_cdma_supported
	},
	[UBASE_DRV_FWCTL] = {
		.suffix = "fwctl",
		.is_supported = &ubase_dev_fwctl_supported
	},
	[UBASE_DRV_PMU] = {
		.suffix = "pmu",
		.is_supported = &ubase_dev_pmu_supported
	},
	[UBASE_DRV_UVB] = {
		.suffix = "uvb",
		.is_supported = &ubase_dev_uvb_supported
	},
	[UBASE_DRV_UBASEPROXY] = {
		.suffix = "ubaseproxy",
		.is_supported = &ubase_dev_proxy_supported
	},
};

int ubase_adev_idx_alloc(void)
{
	return ida_alloc(&ubase_adev_ida, GFP_KERNEL);
}

void ubase_adev_idx_free(int id)
{
	ida_free(&ubase_adev_ida, id);
}

static void ubase_port_handler(struct ubase_dev *udev, bool link_up)
{
	struct ubase_adev *uadev;
	int i;

	if (!test_bit(UBASE_STATE_INITED_B, &udev->state_bits))
		return;

	mutex_lock(&udev->priv.uadev_lock);
	for (i = 0; i < UBASE_DRV_MAX; i++) {
		uadev = udev->priv.uadev[i];
		if (!uadev)
			continue;

		mutex_lock(&uadev->port_lock);
		if (uadev->port_handler)
			uadev->port_handler(&uadev->adev, link_up);
		mutex_unlock(&uadev->port_lock);
	}
	mutex_unlock(&udev->priv.uadev_lock);
}

void ubase_port_down(struct ubase_dev *udev)
{
	ubase_port_handler(udev, 0);
}

void ubase_port_up(struct ubase_dev *udev)
{
	ubase_port_handler(udev, 1);
}

static void ubase_init_adev_lock(struct ubase_adev *uadev)
{
	mutex_init(&uadev->virt_lock);
	mutex_init(&uadev->port_lock);
	mutex_init(&uadev->reset_lock);
	mutex_init(&uadev->activate_lock);
	mutex_init(&uadev->reinit_lock);
}

static void ubase_destroy_adev_lock(struct ubase_adev *uadev)
{
	mutex_destroy(&uadev->reinit_lock);
	mutex_destroy(&uadev->activate_lock);
	mutex_destroy(&uadev->reset_lock);
	mutex_destroy(&uadev->port_lock);
	mutex_destroy(&uadev->virt_lock);
}

static void ubase_destroy_one_adev(struct ubase_adev *uadev)
{
	ubase_destroy_adev_lock(uadev);
	kfree(uadev);
}

static void ubase_release_one_adev(struct device *dev)
{
	struct ubase_adev *uadev = container_of(dev, struct ubase_adev, adev.dev);

	ubase_destroy_one_adev(uadev);
}

static struct ubase_adev *ubase_create_one_adev(struct ubase_dev *udev, int idx)
{
	struct ubase_adev *uadev;

	uadev = kzalloc(sizeof(struct ubase_adev), GFP_KERNEL);
	if (!uadev) {
		ubase_err(udev, "failed to alloc auxiliary device(%s.%d).\n",
			  ubase_adev_devices[idx].suffix, udev->dev_id);
		return NULL;
	}

	uadev->adev.name = ubase_adev_devices[idx].suffix;
	uadev->adev.id = (u32)udev->dev_id;
	uadev->adev.dev.parent = udev->dev;
	uadev->adev.dev.release = ubase_release_one_adev;
	uadev->idx = idx;
	uadev->udev = udev;

	ATOMIC_INIT_NOTIFIER_HEAD(&uadev->comp_nh);

	ubase_init_adev_lock(uadev);

	return uadev;
}

static int ubase_add_one_adev(struct ubase_dev *udev, int idx)
{
	struct ubase_adev *uadev;
	int ret;

	uadev = ubase_create_one_adev(udev, idx);
	if (!uadev)
		return -ENOMEM;

	ret = auxiliary_device_init(&uadev->adev);
	if (ret) {
		ubase_destroy_one_adev(uadev);
		ubase_err(udev,
			  "failed to init auxiliary device(%s.%d), ret = %d\n",
			  uadev->adev.name, udev->dev_id, ret);
		return ret;
	}

	ret = auxiliary_device_add(&uadev->adev);
	if (ret) {
		ubase_err(udev,
			  "failed to add auxiliary device(%s.%d), ret = %d\n",
			  uadev->adev.name, udev->dev_id, ret);
		goto err_adev_add;
	}

	if (test_bit(UBASE_ADEV_PROBE_FAIL_B, &udev->priv.adev_status[idx])) {
		ubase_err(udev,
			  "auxiliary device(%s.%d) probe failed\n",
			  uadev->adev.name, udev->dev_id);
		set_bit(UBASE_STATE_INIT_AGAIN_B, &udev->state_bits);
		ret = -EAGAIN;
		goto err_probe_fail;
	}

	udev->priv.uadev[idx] = uadev;
	return 0;

err_probe_fail:
	auxiliary_device_delete(&uadev->adev);
err_adev_add:
	auxiliary_device_uninit(&uadev->adev);
	udev->priv.uadev[idx] = NULL;

	return ret;
}

static void ubase_del_one_adev(struct ubase_dev *udev, int idx)
{
	struct ubase_adev *uadev = udev->priv.uadev[idx];

	if (!uadev)
		return;

	auxiliary_device_delete(&uadev->adev);
	auxiliary_device_uninit(&uadev->adev);
	udev->priv.uadev[idx] = NULL;
}

static int ubase_init_aux_devices(struct ubase_dev *udev)
{
	struct ubase_priv *priv = &udev->priv;
	int i, ret;

	for (i = 0; i < ARRAY_SIZE(ubase_adev_devices); i++) {
		if (!ubase_adev_devices[i].is_supported(udev))
			continue;

		ret = ubase_add_one_adev(udev, i);
		if (ret)
			goto error;
	}

	mutex_init(&priv->uadev_lock);

	return 0;
error:
	for (; i > 0; i--)
		ubase_del_one_adev(udev, i - 1);

	return ret;
}

static void ubase_uninit_aux_devices(struct ubase_dev *udev)
{
	struct ubase_priv *priv = &udev->priv;
	int i;

	/* Before uninitializing the auxiliary device, disable the CE IRQ to
	 * avoid concurrency.
	 */
	ubase_disable_ce_irqs(udev);

	for (i = ARRAY_SIZE(ubase_adev_devices) - 1; i >= 0; i--)
		ubase_del_one_adev(udev, i);

	mutex_destroy(&priv->uadev_lock);
}

static void ubase_update_stats_for_all(struct ubase_dev *udev)
{
	int ret;

	if (ubase_dev_unic_supported(udev) &&
	    ubase_dev_eth_mac_supported(udev) &&
	    ubase_dev_mac_stats_supported(udev)) {
		ret = ubase_update_eth_stats_trylock(udev);
		if (ret)
			ubase_err(udev,
				  "failed to update stats for eth, ret = %d.\n",
				  ret);
	}
}

static void ubase_report_rate_limited_log_cnt(struct ubase_dev *udev)
{
	if (udev->log_rs.aeq_event_type_exceed_max_cnt) {
		ubase_warn(udev,
			   "rate limited log: aeq_event_type_exceed_max_cnt = %u.\n",
			   udev->log_rs.aeq_event_type_exceed_max_cnt);
		udev->log_rs.aeq_event_type_exceed_max_cnt = 0;
	}
}

static void ubase_cancel_period_service_task(struct ubase_dev *udev)
{
	if (udev->period_service_task.service_task.work.func)
		cancel_delayed_work_sync(&udev->period_service_task.service_task);
}

static int ubase_enable_period_service_task(struct ubase_dev *udev)
{
	struct ubase_delay_work *period_work = &udev->period_service_task;
	unsigned long delta;

	delta = round_jiffies_relative(msecs_to_jiffies(UBASE_PERIOD_100MS));
	mod_delayed_work(udev->ubase_period_wq,
			 &period_work->service_task,
			 delta);

	return 0;
}

static void ubase_period_service_task(struct work_struct *work)
{
#define UBASE_STATS_TIMER_INTERVAL		(300000 / (UBASE_PERIOD_100MS))
#define UBASE_RL_LOG_TIMER_INTERVAL		(180000 / (UBASE_PERIOD_100MS))

	struct ubase_delay_work *ubase_work =
		container_of(work, struct ubase_delay_work, service_task.work);
	struct ubase_dev *udev = container_of(ubase_work, struct ubase_dev,
					      period_service_task);

	if (test_bit(UBASE_STATE_DISABLED_B, &udev->state_bits)) {
		ubase_enable_period_service_task(udev);
		return;
	}

	if (test_bit(UBASE_STATE_INITED_B, &udev->state_bits) &&
	    !(udev->serv_proc_cnt % UBASE_STATS_TIMER_INTERVAL))
		ubase_update_stats_for_all(udev);

	if (test_bit(UBASE_STATE_INITED_B, &udev->state_bits))
		ubase_ctrlq_clean_service_task(udev);

	if (test_bit(UBASE_STATE_INITED_B, &udev->state_bits) &&
	    !(udev->serv_proc_cnt % UBASE_RL_LOG_TIMER_INTERVAL))
		ubase_report_rate_limited_log_cnt(udev);

	udev->serv_proc_cnt++;
	ubase_enable_period_service_task(udev);
}

static void ubase_arq_service_task(struct work_struct *work)
{
	struct ubase_delay_work *ubase_work =
		container_of(work, struct ubase_delay_work, service_task.work);

	ubase_cmd_arq_handler(ubase_work);
}

static void ubase_reset_service_task(struct work_struct *work)
{
	struct ubase_delay_work *ubase_work =
		container_of(work, struct ubase_delay_work, service_task.work);

	ubase_reset_service(ubase_work);
}

static void ubase_service_task(struct work_struct *work)
{
	struct ubase_delay_work *ubase_work =
		container_of(work, struct ubase_delay_work, service_task.work);

	ubase_crq_service_task(ubase_work);
	ubase_errhandle_service_task(ubase_work);
}

static void ubase_ctrlq_service_task(struct work_struct *work)
{
	struct ubase_delay_work *ubase_work =
		container_of(work, struct ubase_delay_work, service_task.work);

	ubase_ctrlq_crq_service_task(ubase_work);
}

static void ubase_init_delayed_work(struct ubase_dev *udev)
{
	INIT_DELAYED_WORK(&udev->service_task.service_task, ubase_service_task);
	INIT_DELAYED_WORK(&udev->ctrlq_service_task.service_task,
			  ubase_ctrlq_service_task);
	INIT_DELAYED_WORK(&udev->reset_service_task.service_task,
			  ubase_reset_service_task);
	INIT_DELAYED_WORK(&udev->period_service_task.service_task,
			  ubase_period_service_task);
	INIT_DELAYED_WORK(&udev->arq_service_task.service_task,
			  ubase_arq_service_task);
}

static int ubase_wq_init(struct ubase_dev *udev)
{
#define UBASE_ALLOC_WQ(name)	alloc_workqueue("%s", WQ_UNBOUND, 0, name)

	struct ub_entity *ue = to_ub_entity(udev->dev);

	udev->ubase_wq = UBASE_ALLOC_WQ("ubase");
	if (!udev->ubase_wq) {
		ubase_err(udev, "failed to alloc ubase workqueue.\n");
		goto err_alloc_ubase_wq;
	}

	udev->ubase_ctrlq_wq = alloc_ordered_workqueue("ubase_ctrlq_service_%u",
						       0, ue->eid);
	if (!udev->ubase_ctrlq_wq) {
		ubase_err(udev, "failed to alloc ubase ctrlq workqueue.\n");
		goto err_alloc_ubase_ctrlq_wq;
	}

	udev->ubase_async_wq = UBASE_ALLOC_WQ("ubase_async_service");
	if (!udev->ubase_async_wq) {
		ubase_err(udev, "failed to alloc ubase async workqueue.\n");
		goto err_alloc_ubase_async_wq;
	}

	udev->ubase_reset_wq = UBASE_ALLOC_WQ("ubase_reset_service");
	if (!udev->ubase_reset_wq) {
		ubase_err(udev, "failed to alloc ubase reset workqueue.\n");
		goto err_alloc_ubase_reset_wq;
	}

	udev->ubase_period_wq = UBASE_ALLOC_WQ("ubase_period_service");
	if (!udev->ubase_period_wq) {
		ubase_err(udev, "failed to alloc ubase period workqueue.\n");
		goto err_alloc_ubase_period_wq;
	}

	udev->ubase_arq_wq = UBASE_ALLOC_WQ("ubase_arq_service");
	if (!udev->ubase_arq_wq) {
		ubase_err(udev, "failed to alloc ubase arq workqueue.\n");
		goto err_alloc_ubase_arq_wq;
	}

	ubase_init_delayed_work(udev);
	return 0;

err_alloc_ubase_arq_wq:
	destroy_workqueue(udev->ubase_period_wq);
err_alloc_ubase_period_wq:
	destroy_workqueue(udev->ubase_reset_wq);
err_alloc_ubase_reset_wq:
	destroy_workqueue(udev->ubase_async_wq);
err_alloc_ubase_async_wq:
	destroy_workqueue(udev->ubase_ctrlq_wq);
err_alloc_ubase_ctrlq_wq:
	destroy_workqueue(udev->ubase_wq);
err_alloc_ubase_wq:
	return -ENOMEM;
}

static void ubase_wq_uninit(struct ubase_dev *udev)
{
	destroy_workqueue(udev->ubase_arq_wq);
	destroy_workqueue(udev->ubase_period_wq);
	destroy_workqueue(udev->ubase_reset_wq);
	destroy_workqueue(udev->ubase_async_wq);
	destroy_workqueue(udev->ubase_ctrlq_wq);
	destroy_workqueue(udev->ubase_wq);
}

static int ubase_handle_ue2ue_ctrlq_req(struct ubase_dev *udev,
					struct ubase_ue2ue_ctrlq_head *cmd,
					u32 len)
{
	struct ubase_ctrlq_base_block *head = (struct ubase_ctrlq_base_block *)(cmd + 1);
	u16 mbx_ue_id = le16_to_cpu(cmd->head.mbx_ue_id);
	struct ubase_ctrlq_ue_info ue_info;
	struct ubase_ctrlq_msg msg = {0};
	int ret = 0, async;

	if (!ubase_mbx_ue_id_is_valid(mbx_ue_id, udev)) {
		ubase_err(udev, "ubase ue2ue ctrlq req mbx ue id = %u error.\n",
			  mbx_ue_id);
		return -EINVAL;
	}

	if (cmd->in_size > (len - (sizeof(*cmd) + UBASE_CTRLQ_HDR_LEN))) {
		dev_err_ratelimited(udev->dev,
				    "ubase ue2ue cmd len = %u error.\n",
				    cmd->in_size);
		return -EINVAL;
	}

	async = ubase_ctrlq_ue_req_event_callback(udev, cmd);
	if (async)
		return 0;

	msg.service_ver = head->service_ver;
	msg.service_type = head->service_type;
	msg.opcode = head->opcode;
	msg.need_resp = cmd->need_resp;
	msg.is_resp = cmd->is_resp;
	msg.is_async = cmd->is_async;
	msg.resp_seq = cmd->seq;
	msg.in = cmd->in_size ? (u8 *)head + UBASE_CTRLQ_HDR_LEN : NULL;
	msg.in_size = cmd->in_size;
	msg.out = NULL;
	msg.out_size = 0;
	if (ubase_ctrlq_msg_is_sync_req(&msg))
		msg.is_async = 1;

	ue_info.bus_ue_id = le16_to_cpu(cmd->head.bus_ue_id);
	ue_info.seq = cmd->seq;
	ue_info.mbx_ue_id = mbx_ue_id;

	ret = __ubase_ctrlq_send(udev, &msg, false, &ue_info);
	if (ret)
		ubase_err_rl(udev, send_ue_ctrlq_msg_fail,
			     "failed to send ue's ctrlq msg, ser_type = 0x%x, opc = 0x%x, bus_ue_id = %u, seq = %u, ret = %d.\n",
			     head->service_type, head->opcode, ue_info.bus_ue_id, ue_info.seq, ret);

	return ret;
}

static int ubase_handle_ue2ue_ctrlq_event(struct ubase_dev *udev, void *data,
					  u32 len)
{
	struct ubase_ue2ue_ctrlq_head *cmd = data;
	struct ubase_ctrlq_base_block *head;
	u32 ue2ue_data_len, ctrlq_msg_len;

	if (len < (sizeof(*cmd) + UBASE_CTRLQ_HDR_LEN)) {
		dev_err_ratelimited(udev->dev,
				    "invalid ue2ue ctrlq event len(%u).\n", len);
		return -EINVAL;
	}

	if (ubase_dev_ctrlq_supported(udev))
		return ubase_handle_ue2ue_ctrlq_req(udev, cmd, len);

	if (!ubase_ctrlq_check_seq(udev, cmd->seq)) {
		ubase_err(udev, "invalid ue2ue ctrlq seq(%u).\n", cmd->seq);
		return -EINVAL;
	}

	head = (struct ubase_ctrlq_base_block *)(cmd + 1);
	ue2ue_data_len = len - sizeof(*cmd);
	ctrlq_msg_len = head->bb_num * UBASE_CTRLQ_BB_LEN;
	if (ue2ue_data_len < ctrlq_msg_len) {
		ubase_err(udev, "invalid ue2ue data len(%u), ctrlq msg len(%u).\n",
			  ue2ue_data_len, ctrlq_msg_len);
		return -EINVAL;
	}
	ubase_ctrlq_handle_crq_msg(udev, head, cmd->seq,
				   (u8 *)head + UBASE_CTRLQ_HDR_LEN,
				   ctrlq_msg_len - UBASE_CTRLQ_HDR_LEN);

	return 0;
}

struct ubase_ue2ue_event_handler {
	u16 sub_cmd;
	int (*event_handler)(struct ubase_dev *udev, void *data, u32 len);
} ubase_ue2ue_events[] = {
	{
		.sub_cmd = UBASE_UE2UE_CTRLQ_MSG,
		.event_handler = ubase_handle_ue2ue_ctrlq_event,
	},
};

static int ubase_handle_ue2ue_event(void *dev, void *data, u32 len)
{
	struct ubase_ue2ue_common_head *head = data;
	struct ubase_dev *udev = dev;
	int i;

	for (i = 0; i < ARRAY_SIZE(ubase_ue2ue_events); i++) {
		if (ubase_ue2ue_events[i].sub_cmd == head->sub_cmd)
			return ubase_ue2ue_events[i].event_handler(udev, data,
								   len);
	}

	dev_warn_ratelimited(udev->dev,
			     "unknown ubase ue2ue event, sub_cmd = %u.\n",
			     head->sub_cmd);

	return 0;
}

static int ubase_handle_ue_reset_event(void *dev, void *data, u32 len)
{
	struct ubase_dev *udev = dev;

	ubase_info(udev, "recv ue reset req, will reset.\n");
	__ubase_reset_event(udev, UBASE_UE_RESET);

	return 0;
}

static int ubase_handle_activate_resp(void *dev, void *data, u32 len)
{
	struct ubase_activate_resp *resp = data;
	struct ubase_act_info *self, *other;
	struct ubase_dev *udev = dev;
	u16 msn;

	if (len != sizeof(*resp)) {
		ubase_err(udev,
			  "activate dev resp len error, cur = %u, expect = %lu.\n",
			  len, sizeof(*resp));
		return -EINVAL;
	}

	ubase_dbg(udev, "recv activate resp.\n");

	msn = le16_to_cpu(resp->msn);
	self = &udev->act_ctx.self;
	if (self->wait_msn == msn) {
		self->result = -resp->result;
		complete(&self->activate_done);
		return 0;
	}
	other = &udev->act_ctx.other;
	if (other->wait_msn == msn) {
		other->result = -resp->result;
		complete(&other->activate_done);
		return 0;
	}

	ubase_warn_rl(udev, err_msn_in_act_resp,
		      "unknown msn in activate resp, msn = %u, self msn = %u, other msn = %u.\n",
		      msn, self->wait_msn, other->wait_msn);

	return -EIO;
}

static struct ubase_crq_event_nb ubase_crq_events[] = {
	{
		.opcode = UBASE_OPC_UE2UE_UBASE,
		.crq_handler = ubase_handle_ue2ue_event,
	},
	{
		.opcode = UBASE_OPC_NOTIFY_UE_RESET,
		.crq_handler = ubase_handle_ue_reset_event,
	},
	{
		.opcode = UBASE_OPC_ACTIVATE_RESP,
		.crq_handler = ubase_handle_activate_resp,
	},
	{
		.opcode = UBASE_OPC_UE_ISOLATED_NOTIFY,
		.crq_handler = ubase_handle_ue_isolated_notify_event,
	},
	{
		.opcode = UBASE_OPC_SET_CTX_VA_RESP,
		.crq_handler = ubase_handle_ue_ctx_va_resp,
	},
	{
		.opcode = UBASE_OPC_PROXY_TO_UBASE,
		.crq_handler = ubase_handle_mbx_over_cmdq_resp,
	},
};

static void ubase_unregister_cmdq_crq_event(struct ubase_dev *udev)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(ubase_crq_events); i++)
		__ubase_unregister_crq_event(udev, ubase_crq_events[i].opcode);
}

static int ubase_register_cmdq_crq_event(struct ubase_dev *udev)
{
	int ret, i;

	for (i = 0; i < ARRAY_SIZE(ubase_crq_events); i++) {
		ubase_crq_events[i].back = udev;

		ret = __ubase_register_crq_event(udev, &ubase_crq_events[i]);
		if (ret) {
			ubase_err(udev,
				  "failed to register crq event[%d], ret = %d.\n",
				  i, ret);
			goto err_reg_event;
		}
	}

	return 0;

err_reg_event:
	for (i = i - 1; i >= 0; i--)
		__ubase_unregister_crq_event(udev, ubase_crq_events[i].opcode);
	return ret;
}

static int ubase_notify_drv_capbilities(struct ubase_dev *udev)
{
	struct ubase_notify_drv_cap_cmd req = {0};
	struct ubase_cmd_buf in;

	set_bit(UBASE_CAP_SUP_ACTIVATE_B, (unsigned long *)req.cap_bits);
	set_bit(UBASE_PMU_CRQ_SUPPORT_B, (unsigned long *)req.cap_bits);

	__ubase_fill_inout_buf(&in, UBASE_OPC_NOTIFY_DRV_CAPS, false,
			       sizeof(req), &req);

	return __ubase_cmd_send_in(udev, &in);
}

static int ubase_log_rs_init(struct ubase_dev *udev)
{
	UBASE_RATELIMIT_INIT(udev, ctrlq_other_seq_invalid);
	UBASE_RATELIMIT_INIT(udev, ctrlq_wait_resp_timeout);
	UBASE_RATELIMIT_INIT(udev, ctrlq_crq_pi_invalid);
	UBASE_RATELIMIT_INIT(udev, ctrlq_space_insuffice);
	UBASE_RATELIMIT_INIT(udev, ue_send_ctrlq_to_cmdq_fail);
	UBASE_RATELIMIT_INIT(udev, ctrlq_is_disabled);
	UBASE_RATELIMIT_INIT(udev, ctrlq_seq_insuffice);
	UBASE_RATELIMIT_INIT(udev, send_ctrlq_unsup_resp_fail);
	UBASE_RATELIMIT_INIT(udev, send_ue_ctrlq_msg_to_cmdq_fail);
	UBASE_RATELIMIT_INIT(udev, mbx_buff_not_empty);
	UBASE_RATELIMIT_INIT(udev, cmdq_is_disable);
	UBASE_RATELIMIT_INIT(udev, ctrlq_msg_queue_wait_timeout);
	UBASE_RATELIMIT_INIT(udev, mailbox_cmd_timeout);
	UBASE_RATELIMIT_INIT(udev, cmdq_space_insuffice);
	UBASE_RATELIMIT_INIT(udev, post_mailbox_fail);
	UBASE_RATELIMIT_INIT(udev, wait_mbox_fail);
	UBASE_RATELIMIT_INIT(udev, aeq_event_type_exceed_max);
	UBASE_RATELIMIT_INIT(udev, arq_queue_full);
	UBASE_RATELIMIT_INIT(udev, send_ue_ctrlq_msg_fail);
	UBASE_RATELIMIT_INIT(udev, proxy_resp_seq_invalid);
	UBASE_RATELIMIT_INIT(udev, err_msn_in_act_resp);

	return 0;
}

static const struct ubase_init_function ubase_init_func_map[] = {
	{
		"init log rs", UBASE_SUP_ALL, 0,
		ubase_log_rs_init, NULL
	},
	{
		"init work queue", UBASE_SUP_ALL, 0,
		ubase_wq_init, ubase_wq_uninit
	},
	{
		"init cmd queue", UBASE_SUP_ALL, 1,
		ubase_cmd_init, ubase_cmd_uninit
	},
	{
		"notify drv capbilities", UBASE_SUP_ALL, 0,
		ubase_notify_drv_capbilities, NULL
	},
	{
		"query dev res", UBASE_SUP_ALL, 0,
		ubase_query_dev_res, NULL
	},
	{
		"dtu memory", UBASE_SUP_UDMA, 0,
		ubase_dtu_mem_init, ubase_dtu_mem_uninit
	},
	{
		"init mailbox", UBASE_SUP_NO_PMU, 1,
		ubase_mbox_cmd_init, ubase_mbox_cmd_uninit
	},
	{
		"query chip info", UBASE_SUP_ALL, 0,
		ubase_query_chip_info, NULL
	},
	{
		"init die list", UBASE_SUP_ALL, 0,
		ubase_die_list_init, ubase_die_list_uninit
	},
	{
		"query controller_info", UBASE_SUP_NO_PMU, 0,
		ubase_query_controller_info, NULL
	},
	{
		"query hw oor caps", UBASE_SUP_NO_PMU, 0,
		ubase_query_hw_oor_caps, NULL
	},
	{
		"query port bitmap", UBASE_SUP_ALL, 0,
		ubase_query_port_bitmap, NULL
	},
	{
		"init irq table", UBASE_SUP_ALL, 1,
		ubase_irq_table_init, ubase_irq_table_uninit
	},
	{
		"init ctrl queue", UBASE_SUP_NO_PMU, 1,
		ubase_ctrlq_init, ubase_ctrlq_uninit
	},
	{
		"register aeq event", UBASE_SUP_NO_PMU, 0,
		ubase_register_ae_event, ubase_unregister_ae_event
	},
	{
		"register cmdq crq event", UBASE_SUP_NO_PMU, 0,
		ubase_register_cmdq_crq_event, ubase_unregister_cmdq_crq_event
	},
	{
		"register ctrlq crq event", UBASE_SUP_NO_PMU, 0,
		NULL, NULL
	},
	{
		"init qos", UBASE_SUP_NO_PMU, 0,
		ubase_qos_init, ubase_qos_uninit
	},
	{
		"prealloc memory", UBASE_SUP_UDMA, 1,
		ubase_prealloc_mem_init, ubase_prealloc_mem_uninit
	},
	{
		"init ue", UBASE_SUP_NO_PMU, 0,
		ubase_ue_init, ubase_ue_uninit
	},
	{
		"init usc", UBASE_SUP_URMA, 0,
		ubase_usc_init, ubase_usc_uninit
	},
	{
		"init hw", UBASE_SUP_NO_PMU, 1,
		ubase_hw_init, ubase_hw_uninit
	},
	{
		"init rc buf", UBASE_SUP_UDMA, 1,
		ubase_rc_init, ubase_rc_uninit
	},
	{
		"init debugfs", UBASE_SUP_ALL, 0,
		ubase_dbg_init, ubase_dbg_uninit
	},
	{
		"init auxiliary devices", UBASE_SUP_ALL, 0,
		ubase_init_aux_devices, ubase_uninit_aux_devices
	},
	{
		"enable period service task", UBASE_SUP_NO_PMU, 0,
		ubase_enable_period_service_task, ubase_cancel_period_service_task
	},
	{
		"update ue isolated state", UBASE_SUP_URMA, 1,
		ubase_init_ue_isolated_state, NULL
	},
};

static bool ubase_init_func_support(struct ubase_dev *udev, u32 support)
{
	return (((support & UBASE_SUP_UNIC) && ubase_dev_unic_supported(udev)) ||
		((support & UBASE_SUP_UDMA) && ubase_dev_udma_supported(udev)) ||
		((support & UBASE_SUP_CDMA) && ubase_dev_cdma_supported(udev)) ||
		((support & UBASE_SUP_PMU) && ubase_dev_pmu_supported(udev)));
}

int ubase_dev_init(struct ubase_dev *udev)
{
	int i, ret;

	for (i = 0; i < ARRAY_SIZE(ubase_init_func_map); i++) {
		if (!ubase_init_func_support(udev,
			ubase_init_func_map[i].support_devs))
			continue;

		if (ubase_init_func_map[i].init_func) {
			ret = ubase_init_func_map[i].init_func(udev);
			if (ret) {
				ubase_err(udev, "failed to %s, ret = %d.\n",
					  ubase_init_func_map[i].err_msg, ret);
				goto err_init;
			}
		}
	}

	set_bit(UBASE_STATE_INITED_B, &udev->state_bits);

	return 0;

err_init:
	ubase_ubus_fault_log(udev, UBASE_FAULT_EVENT_ID_PROBE, NULL);
	for (i -= 1; i >= 0; i--) {
		if (!ubase_init_func_support(udev,
					     ubase_init_func_map[i].support_devs))
			continue;

		if (ubase_init_func_map[i].uninit_func)
			ubase_init_func_map[i].uninit_func(udev);
	}

	return ret;
}

void ubase_dev_uninit(struct ubase_dev *udev)
{
	int i;

	if (test_bit(UBASE_STATE_CMD_DISABLE, &udev->hw.state)) {
		/* If ELR fails before remove, the cmdq & ctrlq may be disabled.
		 * Since remove relies on cmdq\ctrlq, configuration messages
		 * (e.g., destroy ctx res, close promiscuous, restore QoS..)
		 * cannot be sent to the firmware, resulting in configuration
		 * residue. Therefore, try to reinit these resources as much
		 * as possible.
		 */
		ubase_warn(udev, "cmdq is disabled. try to restore it.\n");
		set_bit(UBASE_STATE_CMD_CRQ_UNAVAIL_B, &udev->state_bits);
		ubase_ctrlq_uninit(udev);
		ubase_irq_table_uninit(udev);
		if (ubase_cmd_init(udev))
			goto start_uninit;
		if (ubase_irq_table_init(udev))
			goto start_uninit;
		clear_bit(UBASE_STATE_CMD_CRQ_UNAVAIL_B, &udev->state_bits);
		ubase_ctrlq_init(udev);
		ubase_register_ae_event(udev);
		ubase_register_cmdq_crq_event(udev);
	}

start_uninit:
	if (udev->service_task.service_task.work.func)
		cancel_delayed_work_sync(&udev->service_task.service_task);
	flush_workqueue(udev->ubase_async_wq);

	for (i = ARRAY_SIZE(ubase_init_func_map) - 1; i >= 0; i--) {
		if (!ubase_init_func_support(udev,
					     ubase_init_func_map[i].support_devs))
			continue;

		if (ubase_init_func_map[i].uninit_func)
			ubase_init_func_map[i].uninit_func(udev);
	}
}

static void __ubase_reset_uninit(struct ubase_dev *udev, int end)
{
	int i;

	for (i = end; i >= 0; i--) {
		if (!ubase_init_func_support(udev,
			ubase_init_func_map[i].support_devs))
			continue;

		if (ubase_init_func_map[i].uninit_func &&
		    ubase_init_func_map[i].need_reset)
			ubase_init_func_map[i].uninit_func(udev);
	}
}

int ubase_dev_reset_init(struct ubase_dev *udev)
{
	int i, ret;

	for (i = 0; i < ARRAY_SIZE(ubase_init_func_map); i++) {
		if (!ubase_init_func_map[i].need_reset)
			continue;

		if (!ubase_init_func_support(udev,
					     ubase_init_func_map[i].support_devs))
			continue;

		if (!ubase_init_func_map[i].init_func)
			continue;

		ret = ubase_init_func_map[i].init_func(udev);
		if (ret) {
			ubase_err(udev, "failed to %s, ret = %d.\n",
				  ubase_init_func_map[i].err_msg, ret);
			goto err_init;
		}
	}

	return 0;

err_init:
	__ubase_reset_uninit(udev, i - 1);

	return ret;
}

void ubase_dev_reset_uninit(struct ubase_dev *udev)
{
	__ubase_reset_uninit(udev, ARRAY_SIZE(ubase_init_func_map) - 1);
}

void ubase_suspend_aux_devices(struct ubase_dev *udev,
			       enum ubase_reset_stage stage)
{
	struct ubase_priv *priv = &udev->priv;
	struct ubase_adev *uadev;
	int i;

	for (i = ARRAY_SIZE(ubase_adev_devices) - 1; i >= 0; i--) {
		uadev = priv->uadev[i];
		if (!uadev)
			continue;

		mutex_lock(&uadev->reset_lock);
		if (uadev->reset_handler)
			uadev->reset_handler(&uadev->adev, stage);
		mutex_unlock(&uadev->reset_lock);
	}
}

int ubase_resume_aux_devices(struct ubase_dev *udev,
			     enum ubase_reset_stage stage)
{
	struct ubase_priv *priv = &udev->priv;
	struct ubase_adev *uadev;
	int i, ret = 0;

	for (i = 0; i < ARRAY_SIZE(ubase_adev_devices); i++) {
		uadev = priv->uadev[i];
		if (!uadev)
			continue;

		mutex_lock(&uadev->reset_lock);
		if (uadev->reset_handler)
			ret = uadev->reset_handler(&uadev->adev, stage);
		mutex_unlock(&uadev->reset_lock);

		ret = stage == UBASE_RESET_STAGE_INIT ? ret : 0;
		if (ret) {
			ubase_err(udev,
				  "auxiliary device(%s.%d) reset init failed, ret = %d.\n",
				  uadev->adev.name, udev->dev_id, ret);
			break;
		}
	}
	return ret;
}

int ubase_reinit_aux_devices(struct ubase_dev *udev)
{
	struct ubase_priv *priv = &udev->priv;
	struct ubase_adev *uadev;
	int i, ret = 0;

	mutex_lock(&priv->uadev_lock);
	for (i = 0; i < ARRAY_SIZE(ubase_adev_devices); i++) {
		uadev = priv->uadev[i];

		if (test_and_clear_bit(UBASE_ADEV_PROBE_FAIL_B, &priv->adev_status[i])) {
			ubase_info(udev, "re-probe auxiliary device[%d].\n", i);
			ubase_del_one_adev(udev, i);
			ret = ubase_add_one_adev(udev, i);
			if (ret)
				break;
		} else if (uadev) {
			mutex_lock(&uadev->reinit_lock);
			if (uadev->reinit_handler) {
				ubase_info(udev, "reinit auxiliary device(%s.%d).\n",
					   uadev->adev.name, udev->dev_id);
				ret = uadev->reinit_handler(&uadev->adev);
			}
			mutex_unlock(&uadev->reinit_lock);
			if (ret) {
				ubase_err(udev,
					  "failed to reinit auxiliary device(%s.%d), ret = %d.\n",
					  uadev->adev.name, udev->dev_id, ret);
				break;
			}
		}
	}
	mutex_unlock(&priv->uadev_lock);

	return ret;
}

/**
 * ubase_get_hw_ver() - obtaining the current hardware version.
 * @adev: auxiliary device
 *
 * This function is used by the auxiliary device driver module to query
 * the hardware version information from ubase.
 *
 * Context: Any context.
 * Return: Hardware code. For details, see the definition in ubase_comm_dev.h.
 */
u32 ubase_get_hw_ver(struct auxiliary_device *adev)
{
	struct ubase_dev *udev;
	struct ub_entity *ue;

	if (!adev)
		return UBASE_HW_VER_UNKNOWN;

	udev = __ubase_get_udev_by_adev(adev);
	ue = container_of(udev->dev, struct ub_entity, dev);

	switch (uent_device(ue)) {
	case UBASE_DEV_ID_K_0_URMA_MUE:
	case UBASE_DEV_ID_K_0_URMA_UE:
	case UBASE_DEV_ID_K_0_CDMA_MUE:
	case UBASE_DEV_ID_K_0_CDMA_UE:
	case UBASE_DEV_ID_K_0_PMU_MUE:
	case UBASE_DEV_ID_K_0_PMU_UE:
		return UBASE_HW_VER_K_0;
	case UBASE_DEV_ID_K_V2_URMA_MUE:
	case UBASE_DEV_ID_K_V2_URMA_UE:
	case UBASE_DEV_ID_K_V2_CDMA_MUE:
	case UBASE_DEV_ID_K_V2_CDMA_UE:
	case UBASE_DEV_ID_K_V2_PMU_MUE:
	case UBASE_DEV_ID_K_V2_PMU_UE:
		return UBASE_HW_VER_K_1;
	case UBASE_DEV_ID_A_0_URMA_MUE:
	case UBASE_DEV_ID_A_0_URMA_UE:
	case UBASE_DEV_ID_A_0_CDMA_MUE:
	case UBASE_DEV_ID_A_0_CDMA_UE:
	case UBASE_DEV_ID_A_0_PMU_MUE:
	case UBASE_DEV_ID_A_0_PMU_UE:
	case UBASE_DEV_ID_A_0_UBOE_MUE:
	case UBASE_DEV_ID_A_0_UBOE_UE:
		return UBASE_HW_VER_A_0;
	case UBASE_DEV_ID_A_V2_URMA_MUE:
	case UBASE_DEV_ID_A_V2_URMA_UE:
	case UBASE_DEV_ID_A_V2_CDMA_MUE:
	case UBASE_DEV_ID_A_V2_CDMA_UE:
	case UBASE_DEV_ID_A_V2_PMU_MUE:
	case UBASE_DEV_ID_A_V2_PMU_UE:
	case UBASE_DEV_ID_A_V2_UBOE_MUE:
	case UBASE_DEV_ID_A_V2_UBOE_UE:
		return UBASE_HW_VER_A_1;
	default:
		return UBASE_HW_VER_UNKNOWN;
	}
}
EXPORT_SYMBOL(ubase_get_hw_ver);

/**
 * ubase_adev_fault_log() - trigger black box to dump register values when faults occur
 * @adev: auxiliary device
 * @event_id: fault event id (high 8 bits: driver module id, low 24 bits: event type)
 * @data: optional string pointer to record additional information (can be NULL)
 *
 * This function is used as trigger function for the black box mechanism. If faults
 * occur during the driver's probe or remove process, this function can be called
 * to dump current values of key registers to the file system for cause analysis.
 *
 * Context: Process context. Takes and releases <mutex>.
 */
void ubase_adev_fault_log(struct auxiliary_device *adev,
			  uint32_t event_id, void *data)
{
	struct ubase_dev *udev;

	if (!adev)
		return;

	udev = __ubase_get_udev_by_adev(adev);

	ubase_ubus_fault_log(udev, event_id, data);
}
EXPORT_SYMBOL(ubase_adev_fault_log);

/**
 * ubase_adev_ubl_supported() - determine whether ub link is supported
 * @adev: auxiliary device
 *
 * This function is used to determine whether ub link is supported.
 *
 * Context: Any context.
 * Return: true or false
 */
bool ubase_adev_ubl_supported(struct auxiliary_device *adev)
{
	if (!adev)
		return false;

	return ubase_dev_ubl_supported(__ubase_get_udev_by_adev(adev));
}
EXPORT_SYMBOL(ubase_adev_ubl_supported);

/**
 * ubase_adev_ctrlq_supported() - determine whether to support ctrlq
 * @adev: auxiliary device
 *
 * This function is used to determine whether to support ctrlq.
 *
 * Context: Any context.
 * Return: true or false
 */
bool ubase_adev_ctrlq_supported(struct auxiliary_device *adev)
{
	if (!adev)
		return false;

	return ubase_dev_ctrlq_supported(__ubase_get_udev_by_adev(adev));
}
EXPORT_SYMBOL(ubase_adev_ctrlq_supported);

/**
 * ubase_adev_eth_mac_supported() - determine whether eth link is supported
 * @adev: auxiliary device
 *
 * This function is used to determine whether eth link is supported.
 *
 * Context: Any context.
 * Return: true or false
 */
bool ubase_adev_eth_mac_supported(struct auxiliary_device *adev)
{
	if (!adev)
		return false;

	return ubase_dev_eth_mac_supported(__ubase_get_udev_by_adev(adev));
}
EXPORT_SYMBOL(ubase_adev_eth_mac_supported);

/**
 * ubase_adev_non_mirror_mem_supported() - determine whether mirror mem is supported
 * @adev: auxiliary device
 *
 * This function is used to determine whether mirror mem is supported.
 *
 * Context: Any context.
 * Return: true or false
 */
bool ubase_adev_non_mirror_mem_supported(struct auxiliary_device *adev)
{
	if (!adev)
		return false;

	return ubase_dev_non_mirror_mem_supported(__ubase_get_udev_by_adev(adev));
}
EXPORT_SYMBOL(ubase_adev_non_mirror_mem_supported);

/**
 * ubase_get_io_base() - get io space base address
 * @adev: auxiliary device
 *
 * The function is used to get io space base address.
 *
 * Context: Any context.
 * Return: NULL if the adev is empty, otherwise the pointer to struct ubase_resource_space
 */
struct ubase_resource_space *ubase_get_io_base(struct auxiliary_device *adev)
{
	if (!adev)
		return NULL;

	return &__ubase_get_udev_by_adev(adev)->hw.io_base;
}
EXPORT_SYMBOL(ubase_get_io_base);

/**
 * ubase_get_mem_base() - get memory space base address
 * @adev: auxiliary device
 *
 * The function is used to get memory space base address.
 *
 * Context: Any context.
 * Return: NULL if the adev is empty, otherwise the pointer to struct ubase_resource_space
 */
struct ubase_resource_space *ubase_get_mem_base(struct auxiliary_device *adev)
{
	if (!adev)
		return NULL;

	return &__ubase_get_udev_by_adev(adev)->hw.mem_base;
}
EXPORT_SYMBOL(ubase_get_mem_base);

/**
 * ubase_get_dev_caps() - get ubase capabilities
 * @adev: auxiliary device
 *
 * The function is used to get ubase capabilities.
 *
 * Context: Any context.
 * Return: NULL if the adev is empty, otherwise the pointer to struct ubase_caps
 */
struct ubase_caps *ubase_get_dev_caps(struct auxiliary_device *adev)
{
	if (!adev)
		return NULL;

	return &__ubase_get_udev_by_adev(adev)->caps.dev_caps;
}
EXPORT_SYMBOL(ubase_get_dev_caps);

/**
 * ubase_get_mdrv_data() - get unic netdev
 * @adev: auxiliary device
 *
 * The function is used to get unic netdev.
 *
 * Context: Any context.
 * Return: NULL if the adev is empty or does not support the unic device,
 * otherwise the pointer to struct ubase_adev_com
 */
const struct ubase_adev_com *ubase_get_mdrv_data(struct auxiliary_device *adev)
{
	struct auxiliary_device *unic_adev;
	struct ubase_priv *priv;
	struct ubase_dev *udev;

	if (!adev)
		return NULL;

	udev = __ubase_get_udev_by_adev(adev);
	if (!ubase_dev_unic_supported(udev))
		return NULL;

	priv = &udev->priv;
	unic_adev = &priv->uadev[UBASE_DRV_UNIC]->adev;

	return dev_get_drvdata(&unic_adev->dev);
}
EXPORT_SYMBOL(ubase_get_mdrv_data);

/**
 * ubase_get_udma_caps() - get udma auxiliary device capabilities
 * @adev: udma auxiliary device pointer
 *
 * The function is used to get udma auxiliary device capabilities.
 *
 * Context: Any context.
 * Return: NULL if the adev is empty, otherwise the pointer to struct ubase_adev_caps
 */
struct ubase_adev_caps *ubase_get_udma_caps(struct auxiliary_device *adev)
{
	struct ubase_dev *udev;

	if (!adev)
		return NULL;

	udev = __ubase_get_udev_by_adev(adev);

	return &udev->caps.udma_caps;
}
EXPORT_SYMBOL(ubase_get_udma_caps);

/**
 * ubase_get_cdma_caps() - get cdma auxiliary device capabilities
 * @adev: cdma auxiliary device pointer
 *
 * The function is used to get cdma auxiliary device capabilities.
 *
 * Context: Any context.
 * Return: NULL if the adev is empty, otherwise the pointer to struct ubase_adev_caps
 */
struct ubase_adev_caps *ubase_get_cdma_caps(struct auxiliary_device *adev)
{
	return ubase_get_udma_caps(adev);
}
EXPORT_SYMBOL(ubase_get_cdma_caps);

/**
 * ubase_get_reset_stage() - get current reset stage
 * @adev: auxiliary device
 *
 * The function is used to get current reset stage.
 *
 * Context: Any context.
 * Return: enum ubase_reset_stage
 */
enum ubase_reset_stage ubase_get_reset_stage(struct auxiliary_device *adev)
{
	struct ubase_dev *udev;

	if (!adev)
		return UBASE_RESET_STAGE_NONE;

	udev = __ubase_get_udev_by_adev(adev);

	return udev->reset_stage;
}
EXPORT_SYMBOL(ubase_get_reset_stage);

/**
 * ubase_virt_register() - register auxiliary device virtualization handling function
 * @adev: auxiliary device
 * @virt_handler: the function pointer to handle virtualization. adev: the same as the
 * parameter 'adev', bus_ue_id: bus ub entity id, is_en: true - enable virtualization,
 * false - disable virtualization.
 *
 * The function is used to register auxiliary device virtualization handling function.
 *
 * Context: Process context. Takes and releases <mutex>.
 */
void ubase_virt_register(struct auxiliary_device *adev,
			 void (*virt_handler)(struct auxiliary_device *adev,
					      u16 bus_ue_id, bool is_en))
{
	struct ubase_adev *uadev;

	if (!adev || !virt_handler)
		return;

	uadev = container_of(adev, struct ubase_adev, adev);

	mutex_lock(&uadev->virt_lock);
	if (!uadev->virt_handler)
		uadev->virt_handler = virt_handler;
	mutex_unlock(&uadev->virt_lock);
}
EXPORT_SYMBOL(ubase_virt_register);

/**
 * ubase_virt_unregister() - unregister auxiliary device virtualization handling function
 * @adev: auxiliary device
 *
 * The function is used to unregister auxiliary device virtualization handling function.
 *
 * Context: Process context. Takes and releases <mutex>.
 */
void ubase_virt_unregister(struct auxiliary_device *adev)
{
	struct ubase_adev *uadev;

	if (!adev)
		return;

	uadev = container_of(adev, struct ubase_adev, adev);

	mutex_lock(&uadev->virt_lock);
	uadev->virt_handler = NULL;
	mutex_unlock(&uadev->virt_lock);
}
EXPORT_SYMBOL(ubase_virt_unregister);

/**
 * ubase_port_register() - register auxiliary device port handling function
 * @adev: auxiliary device
 * @port_handler: the function pointer to port handling. adev: the same as the
 * parameter 'adev', link_up: true - link up, false - link down.
 *
 * The function is used to register auxiliary device port handling function.
 *
 * Context: Process context. Takes and releases <mutex>.
 */
void ubase_port_register(struct auxiliary_device *adev,
			 void (*port_handler)(struct auxiliary_device *adev,
					      bool link_up))
{
	struct ubase_adev *uadev;

	if (!adev || !port_handler)
		return;

	uadev = container_of(adev, struct ubase_adev, adev);

	mutex_lock(&uadev->port_lock);
	if (!uadev->port_handler)
		uadev->port_handler = port_handler;
	mutex_unlock(&uadev->port_lock);
}
EXPORT_SYMBOL(ubase_port_register);

/**
 * ubase_port_unregister() - unregister auxiliary device port handling function
 * @adev: auxiliary device
 *
 * The function is used to unregister auxiliary device port handling function.
 *
 * Context: Process context. Takes and releases <mutex>.
 */
void ubase_port_unregister(struct auxiliary_device *adev)
{
	struct ubase_adev *uadev;

	if (!adev)
		return;

	uadev = container_of(adev, struct ubase_adev, adev);

	mutex_lock(&uadev->port_lock);
	uadev->port_handler = NULL;
	mutex_unlock(&uadev->port_lock);
}
EXPORT_SYMBOL(ubase_port_unregister);

/**
 * ubase_reset_register() - register auxiliary device reset function
 * @adev: auxiliary device
 * @reset_handler: the function pointer to reset. adev: the same as the parameter
 * 'adev', stage: enum ubase_reset_stage.
 *
 * The function is used to register auxiliary device reset function.
 *
 * Context: Process context. Takes and releases <mutex>.
 */
void ubase_reset_register(struct auxiliary_device *adev,
			  int (*reset_handler)(struct auxiliary_device *adev,
					       enum ubase_reset_stage stage))
{
	struct ubase_adev *uadev;

	if (!adev || !reset_handler)
		return;

	uadev = container_of(adev, struct ubase_adev, adev);

	mutex_lock(&uadev->reset_lock);
	if (!uadev->reset_handler)
		uadev->reset_handler = reset_handler;
	mutex_unlock(&uadev->reset_lock);
}
EXPORT_SYMBOL(ubase_reset_register);

/**
 * ubase_reset_unregister() - unregister auxiliary device reset function
 * @adev: auxiliary device
 *
 * The function is used to unregister auxiliary device reset function.
 *
 * Context: Process context. Takes and releases <mutex>.
 */
void ubase_reset_unregister(struct auxiliary_device *adev)
{
	struct ubase_adev *uadev;

	if (!adev)
		return;

	uadev = container_of(adev, struct ubase_adev, adev);

	mutex_lock(&uadev->reset_lock);
	uadev->reset_handler = NULL;
	mutex_unlock(&uadev->reset_lock);
}
EXPORT_SYMBOL(ubase_reset_unregister);

/**
 * ubase_get_unic_caps() - get unic auxiliary device capabilities
 * @adev: unic auxiliary device pointer
 *
 * The function is used to get unic auxiliary device capabilities.
 *
 * Context: Any context.
 * Return: NULL if the adev is empty, otherwise the pointer to struct ubase_adev_caps
 */
struct ubase_adev_caps *ubase_get_unic_caps(struct auxiliary_device *adev)
{
	struct ubase_dev *udev;

	if (!adev)
		return NULL;

	udev = __ubase_get_udev_by_adev(adev);

	return &udev->caps.unic_caps;
}
EXPORT_SYMBOL(ubase_get_unic_caps);

static bool ubase_add_ue_list(struct ubase_dev *udev, u16 bus_ue_id)
{
	struct ubase_ue_node *pos_node, *tmp_node, *new_node;

	new_node = kzalloc(sizeof(*new_node), GFP_KERNEL);
	if (!new_node) {
		ubase_err(udev, "failed to alloc ue node.\n");
		return false;
	}
	new_node->bus_ue_id = bus_ue_id;

	mutex_lock(&udev->ue_list_lock);
	list_for_each_entry_safe(pos_node, tmp_node, &udev->ue_list, list) {
		if (pos_node->bus_ue_id == bus_ue_id) {
			kfree(new_node);
			mutex_unlock(&udev->ue_list_lock);
			return false;
		} else if (bus_ue_id < pos_node->bus_ue_id) {
			list_add(&new_node->list, pos_node->list.prev);
			goto add_ue_end;
		}
	}
	list_add_tail(&new_node->list, &udev->ue_list);

add_ue_end:
	mutex_unlock(&udev->ue_list_lock);
	return true;
}

static bool ubase_del_ue_list(struct ubase_dev *udev, u16 bus_ue_id)
{
	struct ubase_ue_node *pos_node, *tmp_node;

	mutex_lock(&udev->ue_list_lock);
	list_for_each_entry_safe(pos_node, tmp_node, &udev->ue_list, list) {
		if (pos_node->bus_ue_id == bus_ue_id) {
			list_del(&pos_node->list);
			kfree(pos_node);
			mutex_unlock(&udev->ue_list_lock);
			return true;
		}
	}
	mutex_unlock(&udev->ue_list_lock);

	return false;
}

static bool ubase_modify_ue_list(struct ubase_dev *udev, u16 bus_ue_id, bool is_en)
{
	if (is_en)
		return ubase_add_ue_list(udev, bus_ue_id);
	else
		return ubase_del_ue_list(udev, bus_ue_id);
}

void ubase_virt_handler(struct ubase_dev *udev, u16 bus_ue_id, bool is_en)
{
	struct ubase_adev *uadev;
	int i;

	if (!ubase_modify_ue_list(udev, bus_ue_id, is_en))
		return;

	ubase_update_ue_isolated_state(udev);

	mutex_lock(&udev->priv.uadev_lock);
	for (i = 0; i < UBASE_DRV_MAX; i++) {
		uadev = udev->priv.uadev[i];
		if (!uadev)
			continue;

		mutex_lock(&uadev->virt_lock);
		if (uadev->virt_handler)
			uadev->virt_handler(&uadev->adev, bus_ue_id, is_en);
		mutex_unlock(&uadev->virt_lock);
	}
	mutex_unlock(&udev->priv.uadev_lock);
}

bool ubase_dbg_log(void)
{
	return ubase_debug;
}

/**
 * ubase_get_adev_qos() - get auxiliary device qos information
 * @adev: auxiliary device
 *
 * The function is used to get auxiliary device qos information.
 *
 * Context: Any context.
 * Return: NULL if the adev is empty, otherwise the pointer to struct ubase_adev_qos
 */
struct ubase_adev_qos *ubase_get_adev_qos(struct auxiliary_device *adev)
{
	struct ubase_dev *udev;

	if (!adev)
		return NULL;

	udev = __ubase_get_udev_by_adev(adev);
	return &udev->qos.adev_qos;
}
EXPORT_SYMBOL(ubase_get_adev_qos);

/**
 * ubase_adev_mac_stats_supported - determine whether mac statistics querying
 * is supported
 * @adev: auxiliary device
 *
 * The function is used to determine whether the auxiliary device supports
 * querying mac statistics.
 *
 * Context: Any context.
 * Return: true or false
 */
bool ubase_adev_mac_stats_supported(struct auxiliary_device *adev)
{
	if (!adev)
		return false;

	return ubase_dev_mac_stats_supported(__ubase_get_udev_by_adev(adev));
}
EXPORT_SYMBOL(ubase_adev_mac_stats_supported);

/**
 * ubase_adev_ip_over_urma_supported() - determine whether to support IP over
 * urma
 * @adev: auxiliary device
 *
 * This function is used to determine whether to support IP over urma.
 *
 * Context: Any context.
 * Return: true or false
 */
bool ubase_adev_ip_over_urma_supported(struct auxiliary_device *adev)
{
	if (!adev)
		return false;

	return ubase_ip_over_urma_supported(__ubase_get_udev_by_adev(adev));
}
EXPORT_SYMBOL(ubase_adev_ip_over_urma_supported);

/**
 * ubase_adev_ip_over_urma_utp_supported() - determine whether to support utp
 * when IP over urma is supported
 * @adev: auxiliary device
 *
 * This function is used to determine whether to support utp when IP over urma
 * is supported
 *
 * Context: Any context.
 * Return: true or false
 */
bool ubase_adev_ip_over_urma_utp_supported(struct auxiliary_device *adev)
{
	if (!adev)
		return false;

	return ubase_ip_over_urma_utp_supported(__ubase_get_udev_by_adev(adev));
}
EXPORT_SYMBOL(ubase_adev_ip_over_urma_utp_supported);

/**
 * ubase_adev_ucp_supported() - determine whether to support ucp
 * @adev: auxiliary device
 *
 * This function is used to determine whether to support ucp
 * (Unified Cmd Process).
 *
 * Context: Any context.
 * Return: true or false
 */
bool ubase_adev_ucp_supported(struct auxiliary_device *adev)
{
	if (!adev)
		return false;

	return ubase_ucp_supported(__ubase_get_udev_by_adev(adev));
}
EXPORT_SYMBOL(ubase_adev_ucp_supported);

static void ubase_activate_notify(struct ubase_dev *udev,
				  struct auxiliary_device *adev, bool activate)
{
	struct ubase_adev *uadev;
	int i;

	for (i = 0; i < UBASE_DRV_MAX; i++) {
		uadev = udev->priv.uadev[i];
		if (!uadev || &uadev->adev == adev)
			continue;

		mutex_lock(&uadev->activate_lock);
		if (uadev->activate_handler)
			uadev->activate_handler(&uadev->adev, activate);
		mutex_unlock(&uadev->activate_lock);
	}
}

/**
 * ubase_activate_register() - register auxiliary device activate handling function
 * @adev: auxiliary device
 * @activate_handler: the function pointer to activate handling. adev: the same
 * as the parameter 'adev', activate: true - activate, false - deactivate.
 *
 * The function is used to register auxiliary device activate handling function.
 *
 * Context: Process context. Takes and releases <mutex>.
 */
void ubase_activate_register(struct auxiliary_device *adev,
			     void (*activate_handler)(struct auxiliary_device *adev,
						      bool activate))
{
	struct ubase_adev *uadev;

	if (!adev || !activate_handler)
		return;

	uadev = container_of(adev, struct ubase_adev, adev);

	mutex_lock(&uadev->activate_lock);
	if (!uadev->activate_handler)
		uadev->activate_handler = activate_handler;
	mutex_unlock(&uadev->activate_lock);
}
EXPORT_SYMBOL(ubase_activate_register);

/**
 * ubase_activate_unregister() - unregister auxiliary device activate handling function
 * @adev: auxiliary device
 *
 * The function is used to unregister auxiliary device activate handling function.
 *
 * Context: Process context. Takes and releases <mutex>.
 */
void ubase_activate_unregister(struct auxiliary_device *adev)
{
	struct ubase_adev *uadev;

	if (!adev)
		return;

	uadev = container_of(adev, struct ubase_adev, adev);

	mutex_lock(&uadev->activate_lock);
	uadev->activate_handler = NULL;
	mutex_unlock(&uadev->activate_lock);
}
EXPORT_SYMBOL(ubase_activate_unregister);

static bool ubase_fast_shutdown(struct ubase_dev *udev,
				struct ubase_act_info *info)
{
	return ((ubase_shutting_down(udev) || info->shutdown) &&
		 ubase_is_ctrl_node(udev));
}

static int ubase_wait_activate_done(struct ubase_dev *udev, u16 bus_ue_id,
				    struct ubase_act_info *info)
{
#define UBASE_ACTIVE_DEV_TIMEOUT_FAST 1000
#define UBASE_ACTIVE_DEV_TIMEOUT 3000

	/* If cmdq crq is unavailable, we can't recv the resp.
	 * so no need to wait too long
	 */
	bool fast = ubase_fast_shutdown(udev, info) ||
		    test_bit(UBASE_STATE_CMD_CRQ_UNAVAIL_B, &udev->state_bits);
	u32 timeout;

	timeout = fast ? UBASE_ACTIVE_DEV_TIMEOUT_FAST :
			 UBASE_ACTIVE_DEV_TIMEOUT;
	if (!wait_for_completion_timeout(&info->activate_done,
					 msecs_to_jiffies(timeout))) {
		ubase_err(udev,
			  "wait activate dev resp timeout(%u ms), bus_ue_id = %u, msn = %u.\n",
			  timeout, bus_ue_id, info->wait_msn);
		return fast ? 0 : -ETIMEDOUT;
	}

	return info->result;
}

static void ubase_record_msn(struct ubase_dev *udev, u16 bus_ue_id, u16 msn)
{
	struct ub_entity *ue = container_of(udev->dev, struct ub_entity, dev);
	struct ubase_act_info *info;

	info = (ue->entity_idx == bus_ue_id) ? &udev->act_ctx.self :
		&udev->act_ctx.other;

	info->wait_msn = msn;
}

static void ubase_alloc_msn(struct ubase_dev *udev, u16 *msn)
{
	struct ubase_act_ctx *ctx = &udev->act_ctx;

	/* we cannot distinguish whether it is a real 0
	 * or a 0 caused by the peer not assigning a value,
	 * so we skip the number 0.
	 */
	mutex_lock(&ctx->lock);
	++ctx->msn;
	if (!ctx->msn)
		ctx->msn = 1;
	*msn = ctx->msn;
	mutex_unlock(&ctx->lock);
}

static bool ubase_need_retry_activation_req(struct ubase_dev *udev,
					    struct ubase_act_info *info,
					    u16 bus_ue_id, int ret)
{
	struct ub_entity *ue = container_of(udev->dev, struct ub_entity, dev);

	if (ubase_fast_shutdown(udev, info))
		return false;

	if (ue->entity_idx != bus_ue_id)
		return false;

	return ret == -ETIMEDOUT || ret == -ENOSPC || ret == -EBUSY;
}

static int ubase_send_activate_dev_req(struct ubase_dev *udev, bool activate,
				       u16 bus_ue_id)
{
#define UBASE_ACTIVATE_DEV_RETRY_INTERVAL 100
#define UBASE_ACTIVATE_DEV_RETRY_CNT 3

	struct ub_entity *ue = container_of(udev->dev, struct ub_entity, dev);
	struct ubase_activate_req req = {0};
	struct ubase_act_info *info;
	struct ubase_cmd_buf in;
	u16 msn, try_cnt = 0;
	int ret;

	info = (ue->entity_idx == bus_ue_id) ? &udev->act_ctx.self :
	       &udev->act_ctx.other;

	/* During the shutdown process, the activation message does not need to
	 * be sent, and a failure message is directly returned to the ubus.
	 * In this way, the UE state machine can remain in the disabled state,
	 * and subsequent disable messages will not be sent. This speeds up the
	 * shutdown process.
	 */
	if (ubase_fast_shutdown(udev, info) && activate)
		return -EPERM;

	if (test_bit(UBASE_STATE_REMOVING_B, &udev->state_bits) &&
	    test_bit(UBASE_STATE_CMD_DISABLE, &udev->hw.state)) {
		ubase_warn(udev, "cmdq is disabled, can't send %s req.\n",
			   activate ? "activate" : "deactivate");
		return 0;
	}

	req.activate = activate ? 1 : 0;
	req.bus_ue_id = cpu_to_le16(bus_ue_id);
	req.shutdown = ubase_shutting_down(udev);
	ubase_alloc_msn(udev, &msn);
	req.msn = cpu_to_le16(msn);
	ubase_record_msn(udev, bus_ue_id, msn);

	ubase_fill_inout_buf(&in, UBASE_OPC_ACTIVATE_REQ, false, sizeof(req),
			     &req);
	do {
		if (try_cnt) {
			msleep(UBASE_ACTIVATE_DEV_RETRY_INTERVAL);
			ubase_dbg(udev, "cmdq send %s dev req retry = %u.\n",
				  activate ? "activate" : "deactivate", try_cnt);
		}

		ret = __ubase_cmd_send_in(udev, &in);
		if (ret) {
			ubase_err(udev,
				  "failed to send %s dev req, ue id = %u, msn = %u, ret = %d.\n",
				  activate ? "activate" : "deactivate", bus_ue_id, msn, ret);
			continue;
		}

		ret = ubase_wait_activate_done(udev, bus_ue_id, info);
	} while (try_cnt++ < UBASE_ACTIVATE_DEV_RETRY_CNT &&
		 ubase_need_retry_activation_req(udev, info, bus_ue_id, ret));

	return ret;
}

int ubase_activate_handler(struct ubase_dev *udev, u32 bus_ue_id)
{
	return ubase_send_activate_dev_req(udev, true, (u16)bus_ue_id);
}

int ubase_deactivate_handler(struct ubase_dev *udev, u32 bus_ue_id)
{
	return ubase_send_activate_dev_req(udev, false, (u16)bus_ue_id);
}

void ubase_flush_workqueue(struct ubase_dev *udev)
{
	flush_workqueue(udev->ubase_wq);
	flush_workqueue(udev->ubase_ctrlq_wq);
	flush_workqueue(udev->ubase_async_wq);
	flush_workqueue(udev->ubase_period_wq);
	flush_workqueue(udev->ubase_arq_wq);
}

int __ubase_activate_dev(struct ubase_dev *udev)
{
	struct ub_entity *ue = container_of(udev->dev, struct ub_entity, dev);
	int ret;

#ifdef CONFIG_EQUIP
	if (!ubase_dev_rack_server_supported(udev))
		return 0;
#endif

	if (ubase_activate_proxy_supported(udev))
		ret = ub_activate_entity(ue, ue->entity_idx);
	else
		ret = ubase_activate_handler(udev, ue->entity_idx);

	if (ret) {
		if (ret == -ETIMEDOUT)
			ret = -EAGAIN;
		goto activate_dev_err;
	}

	ubase_activate_notify(udev, NULL, true);

activate_dev_err:
	ubase_update_activate_stats(udev, true, ret);

	return ret;
}

/**
 * ubase_activate_dev() - activate device
 * @adev: auxiliary device
 *
 * The auxiliary device actively initializes the activate device process.
 * This function will call the activate handling functions registered by all
 * auxiliary devices under the same ub entity.
 *
 * Context: Process context. Takes and releases <lock>, BH-safe.
 * Return: 0 on success, negative error code otherwise
 */
int ubase_activate_dev(struct auxiliary_device *adev)
{
	struct ubase_dev *udev;
	struct ub_entity *ue;
	int ret = 0;

	if (!adev)
		return 0;

	udev = __ubase_get_udev_by_adev(adev);

	ubase_info(udev, "ubase activate dev, state_bits = 0x%lx.\n",
		   udev->state_bits);

	if (test_bit(UBASE_STATE_RST_HANDLING_B, &udev->state_bits)) {
		ubase_info(udev, "skip activate dev while resetting.\n");
		goto skip_activate_dev;
	}

	ue = container_of(udev->dev, struct ub_entity, dev);
	if (ubase_activate_proxy_supported(udev))
		ret = ub_activate_entity(ue, ue->entity_idx);
	else
		ret = ubase_activate_handler(udev, ue->entity_idx);

	if (ret) {
		if (test_bit(UBASE_STATE_RST_HANDLING_B, &udev->state_bits)) {
			ubase_info(udev, "skip activate dev while resetting.\n");
			ret = 0;
			goto skip_activate_dev;
		}
		ubase_err(udev,
			  "failed to activate ubase dev, ret = %d.\n", ret);
		goto activate_dev_err;
	}

skip_activate_dev:
	ubase_activate_notify(udev, adev, true);

activate_dev_err:
	ubase_update_activate_stats(udev, true, ret);

	return ret;
}
EXPORT_SYMBOL(ubase_activate_dev);

static int ubase_deactivate_wait_reset_done(struct ubase_dev *udev)
{
#define UBASE_MAX_WAIT_RST_CNT	1000
#define UBASE_WAIT_RST_TIME	10

	u16 cnt = 0;

	while (test_bit(UBASE_STATE_RST_WAIT_DEACTIVE_B, &udev->state_bits)) {
		if (!cnt)
			ubase_info(udev,
				   "waitting for reset done in deactivate process.\n");
		msleep(UBASE_WAIT_RST_TIME);
		if (++cnt >= UBASE_MAX_WAIT_RST_CNT) {
			ubase_err(udev, "wait reset done timeout.\n");
			return -EBUSY;
		}
	}

	return 0;
}

void __ubase_deactivate_dev(struct ubase_dev *udev)
{
	struct ub_entity *ue = container_of(udev->dev, struct ub_entity, dev);
	int ret;

	if (ubase_activate_proxy_supported(udev))
		ret = ub_deactivate_entity(ue, ue->entity_idx);
	else
		ret = ubase_deactivate_handler(udev, ue->entity_idx);

	if (ret)
		ubase_warn(udev, "failed to deactivate udev, ret = %d.\n", ret);
}

/**
 * ubase_deactivate_dev() - deactivate device
 * @adev: auxiliary device
 *
 * The auxiliary device actively initializes the deactivate device process.
 * This function will call the activate handling functions registered by all
 * auxiliary devices under the same ub entity.
 *
 * Context: Process context. Takes and releases <lock>, BH-safe.
 * Return: 0 on success, negative error code otherwise
 */
int ubase_deactivate_dev(struct auxiliary_device *adev)
{
	struct ubase_dev *udev;
	struct ub_entity *ue;
	int ret;

	if (!adev)
		return 0;

	udev = __ubase_get_udev_by_adev(adev);

	ubase_info(udev, "ubase deactivate dev, state_bits = 0x%lx.\n",
		   udev->state_bits);

	if (test_bit(UBASE_STATE_RST_HANDLING_B, &udev->state_bits)) {
		ret = ubase_deactivate_wait_reset_done(udev);
		if (ret) {
			ubase_update_activate_stats(udev, false, ret);
			return ret;
		}
		ubase_activate_notify(udev, adev, false);
		goto out;
	}

	ubase_activate_notify(udev, adev, false);

	ue = container_of(udev->dev, struct ub_entity, dev);
	if (ubase_activate_proxy_supported(udev))
		ret = ub_deactivate_entity(ue, ue->entity_idx);
	else
		ret = ubase_deactivate_handler(udev, ue->entity_idx);

	if (ret && test_bit(UBASE_STATE_RST_HANDLING_B, &udev->state_bits))
		ret = ubase_deactivate_wait_reset_done(udev);

	if (ret) {
		ubase_err(udev,
			  "failed to deactivate ubase dev, ret = %d.\n", ret);
		ubase_activate_notify(udev, adev, true);
	}

out:
	ubase_update_activate_stats(udev, false, ret);

	return ret;
}
EXPORT_SYMBOL(ubase_deactivate_dev);

static int ubase_query_bus_eid(struct ubase_dev *udev, struct ubase_bus_eid *eid)
{
	struct ubase_query_ueid_cmd resp = {0};
	struct ubase_cmd_buf in, out;
	int i, ret;

	__ubase_fill_inout_buf(&in, UBASE_OPC_QUERY_BUS_EID, true, 0, NULL);
	__ubase_fill_inout_buf(&out, UBASE_OPC_QUERY_BUS_EID, false,
			       sizeof(resp), &resp);

	ret = __ubase_cmd_send_inout(udev, &in, &out);
	if (ret) {
		ubase_err(udev, "failed to query bus eid, ret = %d.\n", ret);
		return ret;
	}

	for (i = 0; i < UBASE_BUS_EID_LEN; ++i)
		eid->eid[i] = le32_to_cpu(resp.ueid[i]);

	return 0;
}

static int __ubase_get_bus_eid(struct ubase_dev *udev, struct ubase_bus_eid *eid)
{
	return ubase_query_bus_eid(udev, eid);
}

/**
 * ubase_get_bus_eid() - get bus entity id
 * @adev: auxiliary device
 * @eid: save the bus entity id
 *
 * The function is used to get bus entity id.
 *
 * Context: Process context. Takes and releases <lock>, BH-safe.
 * Return: 0 on success, negative error code otherwise
 */
int ubase_get_bus_eid(struct auxiliary_device *adev, struct ubase_bus_eid *eid)
{
	struct ubase_dev *udev;

	if (!adev || !eid)
		return -EINVAL;

	udev = __ubase_get_udev_by_adev(adev);

	return __ubase_get_bus_eid(udev, eid);
}
EXPORT_SYMBOL(ubase_get_bus_eid);

/**
 * ubase_adev_mbx_supported() - determine whether to support mailbox functionality
 * @adev: auxiliary device
 *
 * The function is used to determine whether the auxiliary device supports mailbox
 * functionality.
 *
 * Context: Any context.
 * Return: true or false
 */
bool ubase_adev_mbx_supported(struct auxiliary_device *adev)
{
	if (!adev)
		return false;

	return ubase_dev_mbx_supported(__ubase_get_udev_by_adev(adev));
}
EXPORT_SYMBOL(ubase_adev_mbx_supported);

/**
 * ubase_cmd_ctx_buf_free - Free context buffer of the device
 * @aux_dev: auxiliary device
 * @ctx_buf: context buffer capabilities
 *
 * This function is used to free the context buffer that is
 * allocated by calling function 'ubase_cmd_ctx_buf_alloc'.
 *
 * Context: Any context.
 */
void ubase_cmd_ctx_buf_free(struct auxiliary_device *aux_dev,
			    struct ubase_ctx_buf_cap *ctx_buf)
{
	struct ubase_dev *udev;

	if (!aux_dev || !ctx_buf)
		return;

	udev = __ubase_get_udev_by_adev(aux_dev);
	__ubase_cmd_ctx_buf_free(udev, ctx_buf);
}
EXPORT_SYMBOL(ubase_cmd_ctx_buf_free);

/**
 * ubase_cmd_ctx_buf_alloc - Allocate context buffer of the device
 * @aux_dev: auxiliary device
 * @ctx_buf: context buffer capabilities
 * @attr: mailbox attribute
 *
 * This function is used to allocate context buffer for the device
 * and config context buffer by mailbox to hardware.
 *
 * Context: Process context. Takes and releases <lock>, BH-safe. May sleep
 * Return: 0 on success, negative error code otherwise
 */
int ubase_cmd_ctx_buf_alloc(struct auxiliary_device *aux_dev,
			    struct ubase_ctx_buf_cap *ctx_buf,
			    struct ubase_mbx_attr *attr)
{
	struct ubase_dev *udev;

	if (!aux_dev || !ctx_buf || !attr)
		return -EINVAL;

	udev = __ubase_get_udev_by_adev(aux_dev);
	return __ubase_cmd_ctx_buf_alloc(udev, ctx_buf, attr);
}
EXPORT_SYMBOL(ubase_cmd_ctx_buf_alloc);

/**
 * ubase_set_dev_mac() - Record the MAC address of the device
 * @adev: auxiliary device
 * @dev_addr: MAC address of the device
 * @addr_len: MAC address length
 *
 * This function is used to record the MAC address of the device, and store the
 * MAC address in the ubase_dev structure.
 *
 * Context: Any context.
 * Return: 0 on success, negative error code otherwise
 */
int ubase_set_dev_mac(struct auxiliary_device *adev, const u8 *dev_addr,
		      u8 addr_len)
{
	struct ubase_dev *udev;

	if (!adev || !dev_addr || addr_len < ETH_ALEN)
		return -EINVAL;

	udev = __ubase_get_udev_by_adev(adev);
	ether_addr_copy(udev->dev_mac, dev_addr);

	return 0;
}
EXPORT_SYMBOL(ubase_set_dev_mac);

/**
 * ubase_get_dev_mac() - Obtain the device MAC address and output it.
 * @adev: auxiliary device
 * @dev_addr: Output parameter, save the obtained MAC address array.
 * @addr_len: Length of the array for storing MAC addresses
 *
 * This function is used to get the device MAC address from ubase_dev.
 *
 * Context: Any context.
 * Return: 0 on success, negative error code otherwise
 */
int ubase_get_dev_mac(struct auxiliary_device *adev, u8 *dev_addr, u8 addr_len)
{
	struct ubase_dev *udev;

	if (!adev || !dev_addr || addr_len < ETH_ALEN)
		return -EINVAL;

	udev = __ubase_get_udev_by_adev(adev);
	ether_addr_copy(dev_addr, udev->dev_mac);

	return 0;
}
EXPORT_SYMBOL(ubase_get_dev_mac);

/**
 * ubase_adev_shutting_down() - Determine whether the device is shutting down.
 * @adev: auxiliary device
 *
 * This function is used to determine whether the device is shutting down.
 *
 * Context: Any context.
 * Return: true or false
 */
bool ubase_adev_shutting_down(struct auxiliary_device *adev)
{
	if (!adev)
		return false;

	return ubase_shutting_down(__ubase_get_udev_by_adev(adev));
}
EXPORT_SYMBOL(ubase_adev_shutting_down);

void *ubase_alloc_buf(struct ubase_dev *udev, size_t size,
		      dma_addr_t *iova, struct page **page)
{
	void *va = NULL;

	if (ubase_dev_dtu_supported(udev))
		va = ubase_dtu_alloc(udev, page, size, iova);
	else
		va = dma_alloc_coherent(udev->dev, size, iova, udev->gfp);

	return va;
}

void ubase_free_buf(struct ubase_dev *udev, size_t size,
		    void *va, dma_addr_t iova, struct page *page)
{
	if (ubase_dev_dtu_supported(udev))
		ubase_dtu_free(udev, page, size, iova);
	else
		dma_free_coherent(udev->dev, size, va, iova);
}

/**
 * ubase_reinit_register() - register auxiliary device reinit function
 * @adev: auxiliary device
 * @reinit_handler: the function pointer to reinit handling. adev: the
 * same as the parameter 'adev'.
 *
 * The function is used to register auxiliary device reinit function.
 *
 * Context: Process context. Takes and releases <mutex>.
 */
void ubase_reinit_register(struct auxiliary_device *adev,
			   int (*reinit_handler)(struct auxiliary_device *adev))
{
	struct ubase_adev *uadev;

	if (!adev || !reinit_handler)
		return;

	uadev = container_of(adev, struct ubase_adev, adev);

	mutex_lock(&uadev->reinit_lock);
	uadev->reinit_handler = reinit_handler;
	mutex_unlock(&uadev->reinit_lock);
}
EXPORT_SYMBOL(ubase_reinit_register);

/**
 * ubase_reinit_unregister() - unregister auxiliary device reinit function
 * @adev: auxiliary device
 *
 * The function is used to unregister auxiliary device reinit function.
 *
 * Context: Process context. Takes and releases <mutex>.
 */
void ubase_reinit_unregister(struct auxiliary_device *adev)
{
	struct ubase_adev *uadev;

	if (!adev)
		return;

	uadev = container_of(adev, struct ubase_adev, adev);

	mutex_lock(&uadev->reinit_lock);
	uadev->reinit_handler = NULL;
	mutex_unlock(&uadev->reinit_lock);
}
EXPORT_SYMBOL(ubase_reinit_unregister);

/**
 * ubase_update_dev_status() - Update the ue device status.
 * @adev: auxiliary device
 * @status: ue device status
 *
 * This function is used to update the ue device status.
 *
 * Context: Any context.
 */
void ubase_update_dev_status(struct auxiliary_device *adev, unsigned long status)
{
	struct ubase_dev *udev;

	if (!adev)
		return;

	udev = __ubase_get_udev_by_adev(adev);

	ubase_set_bitmap(&udev->status, status);

	ubase_info(udev, "%s.%d updated dev status, status = 0x%lx.\n",
		   adev->name, udev->dev_id, status);
}
EXPORT_SYMBOL(ubase_update_dev_status);

/**
 * ubase_update_adev_status() - Update the status of auxiliary device.
 * @adev: auxiliary device
 * @status: the status of auxiliary device
 *
 * This function is used to update the status of auxiliary device.
 *
 * Context: Any context.
 */
void ubase_update_adev_status(struct auxiliary_device *adev, unsigned long status)
{
	struct ubase_adev *uadev;
	struct ubase_dev *udev;

	if (!adev)
		return;

	uadev = container_of(adev, struct ubase_adev, adev);
	udev = __ubase_get_udev_by_adev(adev);

	ubase_set_bitmap(&udev->priv.adev_status[uadev->idx], status);
	ubase_info(udev, "%s.%d updated adev status, status = 0x%lx.\n",
		   adev->name, udev->dev_id, status);
}
EXPORT_SYMBOL(ubase_update_adev_status);
