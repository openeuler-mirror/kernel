// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved.
 *
 */

#include <linux/delay.h>
#include <ub/ubase/ubase_comm_cmd.h>

#include "debugfs/ubase_debugfs.h"
#include "ubase.h"
#include "ubase_cmd.h"
#include "ubase_ctrlq.h"
#include "ubase_hw.h"
#include "ubase_mailbox.h"
#include "ubase_ubus.h"
#include "ubase_reset.h"

static void ubase_reset_task_schedule(struct ubase_dev *udev)
{
#define RESET_TASK_DELAY_TIME msecs_to_jiffies(10)

	if (!test_and_set_bit(UBASE_SERVICE_STATE_RESET_SCHED,
			      &udev->service_task.state)) {
		udev->last_reset_scheduled = jiffies;
		mod_delayed_work(udev->ubase_reset_wq,
				 &udev->reset_service_task.service_task,
				 RESET_TASK_DELAY_TIME);
	}
}

static void ubase_reset_err_handle(struct ubase_dev *udev)
{
	udev->reset_stat.reset_fail_cnt++;
	udev->reset_stat.reset_retry_cnt++;
	if (udev->reset_stat.reset_retry_cnt < UBASE_RST_MAX_RETRY_CNT) {
		ubase_reset_task_schedule(udev);
		ubase_info(udev, "re-schedule reset task(%u).\n",
			   udev->reset_stat.reset_retry_cnt);
		return;
	}

	ubase_err(udev, "failed to reset, too many attempts.\n");
}

void ubase_port_reset(struct ubase_dev *udev)
{
	ubase_port_down(udev);
	ubase_port_up(udev);
	udev->reset_stat.port_reset_cnt++;
}

void ubase_reset_service(struct ubase_delay_work *ubase_work)
{
	struct ubase_dev *udev = container_of(ubase_work, struct ubase_dev,
					      reset_service_task);
	int ret;

	if (!test_and_clear_bit(UBASE_SERVICE_STATE_RESET_SCHED,
				&udev->service_task.state))
		return;

	if (test_bit(UBASE_STATE_RST_HANDLING_B, &udev->state_bits))
		return;

	if (time_is_before_eq_jiffies(udev->last_reset_scheduled +
				      UBASE_RESET_SCHED_TIMEOUT))
		ubase_warn(udev,
			   "reset service task scheduled after %ums on cpu%d!\n",
			   jiffies_to_msecs(jiffies - udev->last_reset_scheduled),
			   smp_processor_id());

	ret = ubase_ubus_reset_entry(udev->dev);
	if (ret)
		ubase_reset_err_handle(udev);
}

void __ubase_reset_event(struct ubase_dev *udev,
			 enum ubase_reset_type reset_type)
{
	udev->reset_type = reset_type;

	switch (reset_type) {
	case UBASE_UE_RESET:
	case UBASE_ELR_RESET:
		ubase_reset_task_schedule(udev);
		break;
	default:
		ubase_err(udev, "unknown reset type = %u, do nothing.\n",
			  reset_type);
		break;
	}
}

/**
 * ubase_reset_event() - reset event processing
 * @adev: auxiliary device
 * @reset_type: reset type
 *
 * The function performs corresponding reset processing based on different 'reset_type'.
 *
 * Context: Any context.
 */
void ubase_reset_event(struct auxiliary_device *adev,
		       enum ubase_reset_type reset_type)
{
	struct ubase_dev *udev;

	if (!adev)
		return;

	udev = __ubase_get_udev_by_adev(adev);

	__ubase_reset_event(udev, reset_type);
}
EXPORT_SYMBOL(ubase_reset_event);

static int ubase_notify_ue_reset(struct ubase_dev *udev, u16 bus_ue_id,
				 u16 single)
{
	struct ubase_notify_ue_reset_cmd req = {0};
	struct ubase_cmd_buf in;
	int ret;

	req.bus_ue_id = bus_ue_id;
	req.single = single;
	__ubase_fill_inout_buf(&in, UBASE_OPC_NOTIFY_UE_RESET, false,
			       sizeof(req), &req);

	ret = __ubase_cmd_send_in(udev, &in);
	if (ret)
		ubase_err(udev, "failed to notify ue%hu reset, ret = %d.\n",
			  bus_ue_id, ret);

	return ret;
}

static void ubase_notify_all_ue_reset(struct ubase_dev *udev)
{
	struct ubase_ue_node *ue_node;

	list_for_each_entry(ue_node, &udev->ue_list, list) {
		if (ue_node->isolated)
			continue;

		ubase_notify_ue_reset(udev, ue_node->bus_ue_id, 0);
	}
}

static void ubase_wait_ue_reset_ready(struct ubase_dev *udev)
{
	struct ubase_ue_reset_ready_cmd resp;
	struct ubase_cmd_buf out, in;
	int try_cnt = 0;
	int ret;

	if (!dev_num_vf(udev->dev))
		return;

	do {
		memset(&resp, 0, sizeof(resp));
		__ubase_fill_inout_buf(&in, UBASE_OPC_QUERY_UE_RST_RDY, true,
				       0, NULL);
		__ubase_fill_inout_buf(&out, UBASE_OPC_QUERY_UE_RST_RDY,
				       false, sizeof(resp), &resp);

		ret = __ubase_cmd_send_inout(udev, &in, &out);
		if (ret) {
			ubase_err(udev, "failed to query ue ready status, ret = %d.\n",
				  ret);
			return;
		}

		msleep(UBASE_RST_WAIT_CMD_TIME);
		try_cnt++;
	} while (resp.ue_unready_num && try_cnt < UBASE_RST_WAIT_CMD_COUNT);

	if (resp.ue_unready_num)
		ubase_warn(udev, "wait ue reset ready timeout! unready num = %u.\n",
			   resp.ue_unready_num);
}

static int ubase_ue_reset_done_check(struct ubase_dev *udev)
{
	u32 reset_done_reg;
	int try_cnt = 0;

	while (try_cnt < UBASE_RST_WAIT_REG_COUNT) {
		reset_done_reg = ubase_read_dev(&udev->hw, UBASE_RST_ING_REG);
		if (!(reset_done_reg & BIT(UBASE_RST_ING_RST_DONE_B)))
			return 0;

		try_cnt++;
		msleep(UBASE_RST_WAIT_REG_TIME);
	}

	ubase_warn(udev, "wait reset done reg time out.\n");
	return -EBUSY;
}

static void ubase_reset_done(struct ubase_dev *udev)
{
	struct ubase_cmd_buf in;
	int ret;

	if (!dev_num_vf(udev->dev))
		return;

	__ubase_fill_inout_buf(&in, UBASE_OPC_RESET_DONE, false, 0, NULL);

	ret = __ubase_cmd_send_in(udev, &in);
	if (ret)
		ubase_err(udev, "failed to send reset done cmd, ret = %d.\n",
			  ret);

	/* Wait for entities to detect that its mue have reset done */
	msleep(UBASE_RST_UE_WAIT_REG_TIME);
}

void ubase_suspend(struct ubase_dev *udev)
{
	if (!test_bit(UBASE_STATE_INITED_B, &udev->state_bits) ||
	    test_and_set_bit(UBASE_STATE_DISABLED_B, &udev->state_bits)) {
		ubase_warn(udev,
			   "failed to suspend ubase, device is not ready or removing.\n");
		return;
	}

	set_bit(UBASE_STATE_RST_HANDLING_B, &udev->state_bits);
	set_bit(UBASE_STATE_RST_WAIT_DEACTIVE_B, &udev->state_bits);

	if (ubase_dev_pmu_supported(udev)) {
		__ubase_cmd_disable(udev);
		udev->reset_stat.elr_reset_cnt++;
		return;
	}

	ubase_notify_all_ue_reset(udev);

	udev->reset_stage = UBASE_RESET_STAGE_DOWN;
	ubase_suspend_aux_devices(udev);
	ubase_wait_ue_reset_ready(udev);
	udev->reset_stage = UBASE_RESET_STAGE_UNINIT;

	udev->reset_stat.elr_reset_cnt++;

	clear_bit(UBASE_STATE_CTX_READY_B, &udev->state_bits);
	ubase_cmd_disable(udev);
	ubase_ctrlq_disable_remote(udev);
	ubase_ctrlq_disable(udev);
	ubase_irq_table_free(udev);
	ubase_flush_workqueue(udev);
}

void ubase_resume(struct ubase_dev *udev)
{
	int ret;

	if (!test_bit(UBASE_STATE_INITED_B, &udev->state_bits) ||
	    !test_bit(UBASE_STATE_RST_HANDLING_B, &udev->state_bits)) {
		ubase_warn(udev,
			   "failed to resume ubase, device is not ready or removing.\n");
		return;
	}

	if (ubase_dev_pmu_supported(udev)) {
		ubase_ubus_reinit(udev->dev);
		__ubase_cmd_enable(udev);
		udev->reset_stat.reset_done_cnt++;
		udev->reset_stat.hw_reset_done_cnt++;
		clear_bit(UBASE_STATE_RST_WAIT_DEACTIVE_B, &udev->state_bits);
		clear_bit(UBASE_STATE_RST_HANDLING_B, &udev->state_bits);
		clear_bit(UBASE_STATE_DISABLED_B, &udev->state_bits);
		return;
	}

	clear_bit(UBASE_STATE_RST_WAIT_DEACTIVE_B, &udev->state_bits);
	udev->reset_stat.hw_reset_done_cnt++;
	ubase_suspend_aux_devices(udev);
	ubase_dev_reset_uninit(udev);
	ubase_ubus_reinit(udev->dev);

	udev->reset_stage = UBASE_RESET_STAGE_NONE;
	ret = ubase_ue_reset_done_check(udev);
	if (ret)
		goto err_resume;

	ret = ubase_dev_reset_init(udev);
	if (ret)
		goto err_resume;

	ubase_resume_aux_devices(udev);
	ubase_reset_done(udev);

	udev->reset_stat.reset_done_cnt++;
	udev->reset_stat.reset_retry_cnt = 0;
	clear_bit(UBASE_STATE_RST_HANDLING_B, &udev->state_bits);
	clear_bit(UBASE_STATE_DISABLED_B, &udev->state_bits);
	return;

err_resume:
	ubase_resume_aux_devices(udev);
	clear_bit(UBASE_STATE_RST_HANDLING_B, &udev->state_bits);
	clear_bit(UBASE_STATE_DISABLED_B, &udev->state_bits);
	ubase_reset_err_handle(udev);
}

void ubase_errhandle_service_task(struct ubase_delay_work *ubase_work)
{
	struct ubase_dev *udev;

	udev = container_of(ubase_work, struct ubase_dev, service_task);
	if (!test_and_clear_bit(UBASE_SERVICE_STATE_ERR_SCHED,
				&ubase_work->state))
		return;

	if (!ubase_dev_err_handle_supported(udev)) {
		ubase_err(udev, "not support err handle processing.\n");
		return;
	}

	if (test_and_clear_bit(UBASE_STATE_PORT_RESETTING_B, &udev->state_bits)) {
		ubase_info(udev, "ras occurred, ubase need to reset port.\n");
		ubase_port_reset(udev);
	}
}

static int ubase_notify_himac_reset(struct ubase_dev *udev)
{
#define HIMAC_RESET_RETRY_DELAY 50
#define HIMAC_RESET_RETRY_CNT 200

	struct ubase_cmd_buf in;
	int try_cnt = 0;
	int ret;

	while (test_bit(UBASE_STATE_RST_HANDLING_B, &udev->state_bits))
		msleep(UBASE_RST_WAIT_TIME);

	do {
		__ubase_fill_inout_buf(&in, UBASE_OPC_HIMAC_RESET, false, 0, NULL);
		ret = __ubase_cmd_send_in(udev, &in);
		if (!ret) {
			udev->reset_stat.himac_reset_cnt++;
			return 0;
		} else if (ret == -EOPNOTSUPP || ret == -EPERM) {
			break;
		}

		msleep(HIMAC_RESET_RETRY_DELAY);
		try_cnt++;
	} while (try_cnt < HIMAC_RESET_RETRY_CNT);

	ubase_err(udev, "failed to send himac reset cmd, ret = %d.\n", ret);
	return ret;
}

/**
 * ubase_himac_reset() - himac reset processing
 * @adev: auxiliary device
 *
 * Himac reset processing function. This function is called when an himac RAS
 * error is generated and needs to be recovered.
 *
 * Context: Process context. Takes and releases <lock>, BH-safe. May sleep.
 * Return: 0 on success, negative error code otherwise
 */
int ubase_himac_reset(struct auxiliary_device *adev)
{
	struct ubase_dev *udev;

	if (!adev)
		return -EINVAL;

	udev = __ubase_get_udev_by_adev(adev);
	if (!ubase_dev_eth_mac_supported(udev) ||
	    !ubase_dev_err_handle_supported(udev))
		return -EOPNOTSUPP;

	ubase_info(udev, "ubase start to reset himac.\n");
	return ubase_notify_himac_reset(udev);
}
EXPORT_SYMBOL(ubase_himac_reset);
