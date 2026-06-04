// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved.
 *
 */

#define dev_fmt(fmt) "unic: (pid %d) " fmt, current->pid

#include <net/rtnetlink.h>
#include <linux/etherdevice.h>
#include <linux/netdevice.h>
#include <ub/ubase/ubase_comm_cmd.h>
#include <ub/ubase/ubase_comm_eq.h>
#include <ub/ubase/ubase_comm_qos.h>
#include <ub/ubase/ubase_comm_ctrlq.h>

#include "unic_cmd.h"
#include "unic_crq.h"
#include "unic_dcbnl.h"
#include "unic_dev.h"
#include "unic_hw.h"
#include "unic_ip.h"
#include "unic_mac.h"
#include "unic_netdev.h"
#include "unic_qos_hw.h"
#include "unic_reset.h"
#include "unic_event.h"

int unic_comp_handler(struct notifier_block *nb, unsigned long jfcn, void *data)
{
	struct auxiliary_device *adev = (struct auxiliary_device *)data;
	struct unic_dev *unic_dev = dev_get_drvdata(&adev->dev);
	struct unic_channels *channels = &unic_dev->channels;
	u32 index;

	if (test_bit(UNIC_STATE_CHANNEL_INVALID, &unic_dev->state))
		return -EBUSY;

	index = jfcn < channels->num ? jfcn : jfcn - channels->num;
	if (index >= channels->num)
		return -EINVAL;

	napi_schedule(&channels->c[index].napi);

	return 0;
}

static void unic_activate_event_process(struct unic_dev *unic_dev)
{
	struct unic_act_info *act_info = &unic_dev->act_info;
	struct net_device *netdev = unic_dev->comdev.netdev;
	int ret;

	if (!test_bit(UNIC_STATE_DEACTIVATE, &unic_dev->state))
		return;

	if (test_bit(UNIC_STATE_DISABLED, &unic_dev->state)) {
		unic_err(unic_dev,
			 "failed to process activate event, device is not ready.\n");
		goto out;
	}

	/* if network interface has already been stopped,
	 * no need to open by activate event
	 */
	if (test_bit(UNIC_STATE_DOWN, &unic_dev->state))
		goto out;

	ret = unic_net_open_no_link_change(netdev);
	if (ret)
		unic_warn(unic_dev, "failed to open net, ret = %d.\n", ret);

	ret = unic_activate_promisc_mode(unic_dev, true);
	if (!ret)
		clear_bit(UNIC_VPORT_STATE_PROMISC_CHANGE, &unic_dev->vport.state);

	if (unic_dev_eth_mac_supported(unic_dev))
		unic_activate_mac_table(unic_dev);

out:
	mutex_lock(&act_info->mutex);
	act_info->deactivate = false;
	mutex_unlock(&act_info->mutex);
	clear_bit(UNIC_STATE_DEACTIVATE, &unic_dev->state);
}

static void unic_deactivate_event_process(struct unic_dev *unic_dev)
{
	struct unic_act_info *act_info = &unic_dev->act_info;
	struct net_device *netdev = unic_dev->comdev.netdev;
	int ret;

	if (test_bit(UNIC_STATE_DEACTIVATE, &unic_dev->state))
		return;

	/* when deactivate event occurs, set flag to true to prevent
	 * periodic tasks changing promisc
	 */
	mutex_lock(&act_info->mutex);
	act_info->deactivate = true;
	mutex_unlock(&act_info->mutex);

	if (test_bit(UNIC_STATE_DISABLED, &unic_dev->state)) {
		unic_err(unic_dev,
			 "failed to process deactivate event, device is not ready.\n");
		goto out;
	}

	if (unic_dev_eth_mac_supported(unic_dev))
		unic_deactivate_mac_table(unic_dev);

	ret = unic_activate_promisc_mode(unic_dev, false);
	if (!ret)
		set_bit(UNIC_VPORT_STATE_PROMISC_CHANGE, &unic_dev->vport.state);

	/* if network interface has already been stopped,
	 * no need to stop again by deactivate event
	 */
	if (test_bit(UNIC_STATE_DOWN, &unic_dev->state))
		goto out;

	unic_net_stop_no_link_change(netdev);

out:
	set_bit(UNIC_STATE_DEACTIVATE, &unic_dev->state);
}

static void unic_activate_handler(struct auxiliary_device *adev, bool activate)
{
	struct unic_dev *unic_dev = dev_get_drvdata(&adev->dev);

	unic_info(unic_dev, "receive %s event callback.\n",
		  activate ? "activate" : "deactivate");

	rtnl_lock();
	if (activate)
		unic_activate_event_process(unic_dev);
	else
		unic_deactivate_event_process(unic_dev);
	rtnl_unlock();
}

static void unic_ub_port_reset(struct unic_dev *unic_dev, bool link_up)
{
	struct net_device *netdev = unic_dev->comdev.netdev;

	if (!netif_running(netdev))
		return;

	if (link_up)
		unic_dev->hw.mac.link_status = UNIC_LINK_STATUS_UP;
	else
		unic_dev->hw.mac.link_status = UNIC_LINK_STATUS_DOWN;
}

static void unic_eth_port_reset(struct net_device *netdev, bool link_up)
{
	rtnl_lock();

	if (!netif_running(netdev))
		goto unlock;

	if (link_up)
		unic_net_open(netdev);
	else
		unic_net_stop(netdev);

unlock:
	rtnl_unlock();
}

static void unic_port_handler(struct auxiliary_device *adev, bool link_up)
{
	struct unic_dev *unic_dev = dev_get_drvdata(&adev->dev);
	struct net_device *netdev = unic_dev->comdev.netdev;

	if (unic_dev_ubl_supported(unic_dev))
		unic_ub_port_reset(unic_dev, link_up);
	else
		unic_eth_port_reset(netdev, link_up);
}

static struct ubase_ctrlq_event_nb unic_ctrlq_events[] = {
	{
		.service_type = UBASE_CTRLQ_SER_TYPE_IP_ACL,
		.opcode = UBASE_CTRLQ_OPC_NOTIFY_IP,
		.crq_handler = unic_handle_notify_ip_event,
	},
};

static void unic_unregister_ctrlq_event(struct auxiliary_device *adev,
					u32 ctrlq_crq_event_num)
{
	u32 i;

	for (i = 0; i < ctrlq_crq_event_num; i++)
		ubase_ctrlq_unregister_crq_event(adev,
						 unic_ctrlq_events[i].service_type,
						 unic_ctrlq_events[i].opcode);
}

static int unic_register_ctrlq_event(struct auxiliary_device *adev)
{
	int ret;
	u32 i;

	for (i = 0; i < ARRAY_SIZE(unic_ctrlq_events); i++) {
		unic_ctrlq_events[i].back = adev;
		ret = ubase_ctrlq_register_crq_event(adev, &unic_ctrlq_events[i]);
		if (ret) {
			dev_err(adev->dev.parent,
				"failed to register ctrlq event[%u], ret = %d.\n",
				i, ret);
			unic_unregister_ctrlq_event(adev, i);
			return ret;
		}
	}

	return 0;
}

static struct ubase_crq_event_nb unic_crq_events[] = {
	{
		.opcode = UBASE_OPC_QUERY_LINK_STATUS,
		.crq_handler = unic_handle_link_status_event,
	},
};

static void unic_unregister_crq_event(struct auxiliary_device *adev,
				      u32 crq_event_num)
{
	u32 i;

	for (i = 0; i < crq_event_num; i++)
		ubase_unregister_crq_event(adev, unic_crq_events[i].opcode);
}

static int unic_register_crq_event(struct auxiliary_device *adev)
{
	int ret;
	u32 i;

	for (i = 0; i < ARRAY_SIZE(unic_crq_events); i++) {
		unic_crq_events[i].back = adev;

		ret = ubase_register_crq_event(adev, &unic_crq_events[i]);
		if (ret) {
			dev_err(adev->dev.parent,
				"failed to register crq event[%u], ret = %d.\n",
				i, ret);
			unic_unregister_crq_event(adev, i);
			return ret;
		}
	}

	return 0;
}

static void unic_unregister_ae_event(struct auxiliary_device *adev,
				     u8 asyn_event_num)
{
	struct unic_dev *unic_dev = dev_get_drvdata(&adev->dev);
	u8 i;

	for (i = 0; i < asyn_event_num; i++)
		ubase_event_unregister(adev, &unic_dev->ae_nbs[i]);
}

static void unic_mask_jfs_ctx_key_words(void *buf)
{
	struct unic_jfs_ctx *jfs = (struct unic_jfs_ctx *)buf;

	jfs->sqe_base_addr_l = 0;
	jfs->sqe_base_addr_h = 0;
	jfs->user_data_l = 0;
	jfs->user_data_h = 0;
}

static void unic_mask_jfr_ctx_key_words(void *buf)

{
	struct unic_jfr_ctx *jfr = (struct unic_jfr_ctx *)buf;

	jfr->rqe_base_addr_l = 0;
	jfr->rqe_base_addr_h = 0;
	jfr->token_value = 0;
	jfr->user_data_l = 0;
	jfr->user_data_h = 0;
	jfr->idx_que_addr_l = 0;
	jfr->idx_que_addr_h = 0;
	jfr->record_db_addr_l = 0;
	jfr->record_db_addr_m = 0;
	jfr->record_db_addr_h = 0;
}

static void unic_mask_jfc_ctx_key_words(void *buf)
{
	struct unic_jfc_ctx *jfc = (struct unic_jfc_ctx *)buf;

	jfc->cqe_base_addr_l = 0;
	jfc->cqe_base_addr_h = 0;
	jfc->record_db_addr_l = 0;
	jfc->record_db_addr_h = 0;
	jfc->remote_token_value = 0;
}

void unic_mask_ctx_key_words(void *buf, enum unic_dbg_ctx_type ctx_type)
{
	switch (ctx_type) {
	case UNIC_DBG_JFS_CTX:
		unic_mask_jfs_ctx_key_words(buf);
		break;
	case UNIC_DBG_JFR_CTX:
		unic_mask_jfr_ctx_key_words(buf);
		break;
	case UNIC_DBG_SQ_JFC_CTX:
	case UNIC_DBG_RQ_JFC_CTX:
		unic_mask_jfc_ctx_key_words(buf);
		break;
	default:
		break;
	}
}

int unic_get_ctx_info(struct unic_dev *unic_dev,
		      enum unic_dbg_ctx_type ctx_type,
		      struct unic_ctx_info *ctx_info)
{
	struct ubase_adev_caps *unic_caps = ubase_get_unic_caps(unic_dev->comdev.adev);

	if (!unic_caps) {
		unic_err(unic_dev, "failed to get unic caps.\n");
		return -ENODATA;
	}

	switch (ctx_type) {
	case UNIC_DBG_JFS_CTX:
		ctx_info->start_idx = unic_caps->jfs.start_idx;
		ctx_info->ctx_size = UBASE_JFS_CTX_SIZE;
		ctx_info->op = UBASE_MB_QUERY_JFS_CONTEXT;
		ctx_info->ctx_name = "jfs";
		break;
	case UNIC_DBG_JFR_CTX:
		ctx_info->start_idx = unic_caps->jfr.start_idx;
		ctx_info->ctx_size = UBASE_JFR_CTX_SIZE;
		ctx_info->op = UBASE_MB_QUERY_JFR_CONTEXT;
		ctx_info->ctx_name = "jfr";
		break;
	case UNIC_DBG_SQ_JFC_CTX:
		ctx_info->start_idx = unic_caps->jfc.start_idx;
		ctx_info->ctx_size = UBASE_JFC_CTX_SIZE;
		ctx_info->op = UBASE_MB_QUERY_JFC_CONTEXT;
		ctx_info->ctx_name = "sq_jfc";
		break;
	case UNIC_DBG_RQ_JFC_CTX:
		ctx_info->start_idx = unic_caps->jfc.start_idx +
				      unic_dev->channels.num;
		ctx_info->ctx_size = UBASE_JFC_CTX_SIZE;
		ctx_info->op = UBASE_MB_QUERY_JFC_CONTEXT;
		ctx_info->ctx_name = "rq_jfc";
		break;
	default:
		unic_err(unic_dev, "failed to get ctx info, ctx_type = %u.\n",
			 ctx_type);
		return -ENODATA;
	}

	return 0;
}

static void unic_context_print(struct unic_dev *udev, void *ctx_addr,
			       u32 ctx_len)
{
#define OFFSET_1 1
#define OFFSET_2 2
#define OFFSET_3 3
#define OFFSET_4 4

	__le32 *p = (__le32 *)ctx_addr;
	u32 i;

	ctx_len = ctx_len / sizeof(u32);
	for (i = 0; (i + OFFSET_3) < ctx_len; i += OFFSET_4, p += OFFSET_4) {
		pr_info("%04zu %08x  %04zu %08x  %04zu %08x  %04zu %08x\n",
			(i + OFFSET_1) * sizeof(u32), le32_to_cpu(*p),
			(i + OFFSET_2) * sizeof(u32), le32_to_cpu(*(p + OFFSET_1)),
			(i + OFFSET_3) * sizeof(u32), le32_to_cpu(*(p + OFFSET_2)),
			(i + OFFSET_4) * sizeof(u32), le32_to_cpu(*(p + OFFSET_3)));
	}

	switch (ctx_len - i) {
	case OFFSET_3:
		pr_info("%04zu %08x  %04zu %08x  %04zu %08x\n",
			(i + OFFSET_1) * sizeof(u32), le32_to_cpu(*p),
			(i + OFFSET_2) * sizeof(u32), le32_to_cpu(*(p + OFFSET_1)),
			(i + OFFSET_3) * sizeof(u32), le32_to_cpu(*(p + OFFSET_2)));
		break;
	case OFFSET_2:
		pr_info("%04zu %08x  %04zu %08x\n",
			(i + OFFSET_1) * sizeof(u32), le32_to_cpu(*p),
			(i + OFFSET_2) * sizeof(u32), le32_to_cpu(*(p + OFFSET_1)));
		break;
	case OFFSET_1:
		pr_info("%04zu %08x\n",
			(i + OFFSET_1) * sizeof(u32), le32_to_cpu(*p));
		break;
	default:
		break;
	}
}

static void unic_context_hw_print(struct unic_dev *udev,
				  enum unic_dbg_ctx_type ctx_type)
{
	struct auxiliary_device *adev = udev->comdev.adev;
	struct unic_ctx_info ctx_info = {0};
	struct ubase_cmd_mailbox *mailbox;
	struct ubase_mbx_attr attr = {0};
	int ret = 0;
	u32 i;

	if (!mutex_trylock(&udev->channels.mutex))
		return;

	if (__unic_resetting(udev) || !udev->channels.c)
		goto unlock;

	mailbox = ubase_alloc_cmd_mailbox(adev);
	if (IS_ERR_OR_NULL(mailbox)) {
		unic_err(udev, "failed to alloc mailbox for dump context.\n");
		goto unlock;
	}

	ret = unic_get_ctx_info(udev, ctx_type, &ctx_info);
	if (ret)
		goto free_mailbox;

	for (i = 0; i < udev->channels.num; i++) {
		ubase_fill_mbx_attr(&attr, i + ctx_info.start_idx, ctx_info.op,
				    0);
		ret = ubase_hw_upgrade_ctx_ex(adev, &attr, mailbox);
		if (ret) {
			unic_err(udev,
				 "failed to query %s ctx mbx, ret = %d.\n",
				 ctx_info.ctx_name, ret);
			goto free_mailbox;
		}
		unic_info(udev, "%s%u\n", ctx_info.ctx_name, i);
		unic_mask_ctx_key_words(mailbox->buf, ctx_type);
		unic_context_print(udev, mailbox->buf, ctx_info.ctx_size);
	}

free_mailbox:
	ubase_free_cmd_mailbox(adev, mailbox);
unlock:
	mutex_unlock(&udev->channels.mutex);
}

static int unic_ae_jetty_level_error(struct notifier_block *nb,
				     unsigned long event, void *data)
{
	struct ubase_event_nb *ev_nb = container_of(nb,
						    struct ubase_event_nb, nb);
	struct auxiliary_device *adev = (struct auxiliary_device *)ev_nb->back;
	struct unic_dev *unic_dev = dev_get_drvdata(&adev->dev);
	struct ubase_aeq_notify_info *info = data;
	u32 queue_num;

	/* Normally, UNIC does not report such abnormal events,
	 * but in order to maintain its scalability,
	 * unic reserves the reset processing of such events.
	 */
	queue_num = info->aeqe->event.queue_event.num;
	unic_err(unic_dev,
		 "recv jetty level error, event_type = 0x%x, sub_type = 0x%x, queue_num = %u.\n",
		 info->event_type, info->sub_type, queue_num);

	unic_context_hw_print(unic_dev, UNIC_DBG_JFS_CTX);
	unic_context_hw_print(unic_dev, UNIC_DBG_JFR_CTX);
	unic_context_hw_print(unic_dev, UNIC_DBG_SQ_JFC_CTX);
	unic_context_hw_print(unic_dev, UNIC_DBG_RQ_JFC_CTX);

	ubase_reset_event(adev, UBASE_UE_RESET);

	return 0;
}

static int unic_register_ae_event(struct auxiliary_device *adev)
{
	struct ubase_event_nb unic_ae_nbs[UNIC_AE_LEVEL_NUM] = {
		{
			.drv_type = UBASE_DRV_UNIC,
			.event_type = UBASE_EVENT_TYPE_JETTY_LEVEL_ERROR,
			.nb = { unic_ae_jetty_level_error },
			.back = adev
		},
	};
	struct unic_dev *unic_dev = dev_get_drvdata(&adev->dev);
	int ret;
	u8 i;

	for (i = 0; i < ARRAY_SIZE(unic_ae_nbs); i++) {
		unic_dev->ae_nbs[i] = unic_ae_nbs[i];
		ret = ubase_event_register(adev, &unic_dev->ae_nbs[i]);
		if (ret) {
			dev_err(adev->dev.parent,
				"failed to register asyn event[%u], ret = %d.\n",
				unic_dev->ae_nbs[i].event_type, ret);
			unic_unregister_ae_event(adev, i);
			return ret;
		}
	}

	return ret;
}

int unic_register_event(struct auxiliary_device *adev)
{
	int ret;

	ret = unic_register_ae_event(adev);
	if (ret)
		return ret;

	ret = unic_register_crq_event(adev);
	if (ret)
		goto unregister_ae;

	ret = unic_register_ctrlq_event(adev);
	if (ret)
		goto unregister_crq;

	ubase_port_register(adev, unic_port_handler);
	ubase_reset_register(adev, unic_reset_handler);
	ubase_activate_register(adev, unic_activate_handler);

	return 0;

unregister_crq:
	unic_unregister_crq_event(adev, ARRAY_SIZE(unic_crq_events));
unregister_ae:
	unic_unregister_ae_event(adev, UNIC_AE_LEVEL_NUM);

	return ret;
}

void unic_unregister_event(struct auxiliary_device *adev)
{
	ubase_activate_unregister(adev);
	ubase_reset_unregister(adev);
	ubase_port_unregister(adev);
	unic_unregister_ctrlq_event(adev, ARRAY_SIZE(unic_ctrlq_events));
	unic_unregister_crq_event(adev, ARRAY_SIZE(unic_crq_events));
	unic_unregister_ae_event(adev, UNIC_AE_LEVEL_NUM);
}
