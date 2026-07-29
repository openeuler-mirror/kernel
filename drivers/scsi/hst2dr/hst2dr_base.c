// SPDX-License-Identifier: GPL-2.0
/*
 * This is the  hst2dr base driver providing common API layer interface
 * for access to hst2dr firmware.
 *
 * This code is based on drivers/scsi/hst2dr/hst2dr_base.c

 * Copyright (c) 2021-2026 Sage Micro Corporation
 * (mailto: driver@sage-micro.com.cn)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * NO WARRANTY
 * THE PROGRAM IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED INCLUDING, WITHOUT
 * LIMITATION, ANY WARRANTIES OR CONDITIONS OF TITLE, NON-INFRINGEMENT,
 * MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE. Each Recipient is
 * solely responsible for determining the appropriateness of using and
 * distributing the Program and assumes all risks associated with its
 * exercise of rights under this Agreement, including but not limited to
 * the risks and costs of program errors, damage to or loss of data,
 * programs or equipment, and unavailability or interruption of operations.

 * DISCLAIMER OF LIABILITY
 * NEITHER RECIPIENT NOR ANY CONTRIBUTORS SHALL HAVE ANY LIABILITY FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING WITHOUT LIMITATION LOST PROFITS), HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
 * TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 * USE OR DISTRIBUTION OF THE PROGRAM OR THE EXERCISE OF ANY RIGHTS GRANTED
 * HEREUNDER, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGES

 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/pci.h>
#include <linux/kdev_t.h>
#include <linux/blkdev.h>
#include <linux/delay.h>
#include <linux/interrupt.h>
#include <linux/dma-mapping.h>
#include <linux/io.h>
#include <linux/time.h>
#include <linux/ktime.h>
#include <linux/kthread.h>
#include <linux/aer.h>
#include <linux/cpumask.h>

#include "hst2dr_base.h"
#include "hst2dr_hal.h"
#include "hst2dr_comm.h"
#include "hst2dr_debug.h"

static HST2DR_CALLBACK	hst2dr_callbacks[HST2DR_MAX_CALLBACKS];

#define FAULT_POLLING_INTERVAL 1000 /* in milliseconds */

 /* maximum controller queue depth */
#define MAX_CHAIN_DEPTH		100000
#define MAX_HBA_QUEUE_DEPTH_SAGE  MAX_HW_QUEUE_SIZE

static int max_sgl_entries = -1;
int msix_disable = -1;
module_param(msix_disable, int, 0644);
MODULE_PARM_DESC(msix_disable, "Disable MSIX interrupt");

static int max_msix_vectors = -1;
static int
_base_get_ioa_info(struct HST2DR_ADAPTER *ioa);
static int
_base_reset(struct HST2DR_ADAPTER *ioa, enum reset_type type);

/**
 *  hst2dr_remove_dead_ioa_func - kthread context to remove dead ioa
 * @arg: input argument, used to derive ioa
 *
 * Return 0 if controller is removed from pci subsystem.
 * Return -1 for other case.
 */
static int hst2dr_remove_dead_ioa_func(void *arg)
{
	struct HST2DR_ADAPTER *ioa = (struct HST2DR_ADAPTER *)arg;
	struct pci_dev *pdev;

	if (ioa == NULL)
		return -1;

	pdev = ioa->pdev;
	if (pdev == NULL)
		return -1;
	pci_stop_and_remove_bus_device_locked(pdev);
	return 0;
}

/**
 * _base_fault_reset_work - workq handling ioa fault conditions
 * @work: input argument, used to derive ioa
 * Context: sleep.
 *
 * Return nothing.
 */
static void
_base_fault_reset_work(struct work_struct *work)
{
	struct HST2DR_ADAPTER *ioa =
		container_of(work, struct HST2DR_ADAPTER,
		fault_reset_work.work);
	unsigned long	 flags;
	u32 csts, heartbeat, heartbeat_cnt = 0;
	int rc;
	struct task_struct *p;


	spin_lock_irqsave(&ioa->ioa_reset_in_progress_lock, flags);
	if (ioa->shost_recovery || ioa->pci_error_recovery)
		goto rearm_timer;
	spin_unlock_irqrestore(&ioa->ioa_reset_in_progress_lock, flags);

	csts = hst2dr_base_get_ioastate(ioa, 0);
	if ((csts & SSI2_IOA_STATE_MASK) == SSI2_IOA_STATE_MASK) {
		if (ioa->remove_host == 1)
			return;
		log_error(ioa, "SAS host is non-operational !\n");

		/* It may be possible that EEH recovery can resolve some of
		 * pci bus failure issues rather removing the dead ioa function
		 * by considering controller is in a non-operational state. So
		 * here priority is given to the EEH recovery. If it doesn't
		 * not resolve this issue, hst2dr driver will consider this
		 * controller to non-operational state and remove the dead ioa
		 * function.
		 */
		if (ioa->non_operational_loop++ < 5) {
			spin_lock_irqsave(&ioa->ioa_reset_in_progress_lock,
							 flags);
			goto rearm_timer;
		}

		/*
		 * Call _hst2dr_flush_pending_cmds callback so that we flush all
		 * pending commands back to OS. This call is required to aovid
		 * deadlock at block layer. Dead IOA will fail to do  reset,
		 * and this call is safe since dead ioa will never return any
		 * command back from HW.
		 */
		ioa->schedule_dead_ioa_flush_running_cmds(ioa);
		/*
		 * Set remove_host flag early since kernel thread will
		 * take some time to execute.
		 */
		ioa->remove_host = 1;
		/*Remove the Dead Host */
		p = kthread_run(hst2dr_remove_dead_ioa_func, ioa,
			"%s_dead_ioa_%d", ioa->driver_name, ioa->id);
		if (IS_ERR(p))
			log_error(ioa,
				"%s: Running hst2dr_dead_ioa_%d thread failed !\n",
				__func__, ioa->id);
		else
			log_reset(ioa,
				"%s: Running hst2dr_dead_ioa_%d thread success !\n",
				__func__, ioa->id);
		return; /* don't rearm timer */
	}

	ioa->non_operational_loop = 0;
	heartbeat = hst2dr_read_direct_reg_hal_api(ioa, NVME_REG_WD);
	if (ioa->heartbeat == heartbeat) {
		if (heartbeat_cnt < 5)
			heartbeat_cnt++;
	} else
		heartbeat_cnt = 0;
	if (((csts & SSI2_IOA_STATE_MASK) != SSI2_IOA_STATE_OPERATIONAL) ||
			((csts & SSI2_IOA_STATE_MASK) == SSI2_IOA_STATE_NEED_RESET) ||
			(heartbeat_cnt == 5)) {
		ioa->ioa_reset_in_progress |= 4;
		rc = hst2dr_base_hard_reset_handler(ioa, AER_RESET, 3);
		ioa->ioa_reset_in_progress &= ~4;
		if (ioa->ioa_reset_in_progress == 0) {
			log_warn(ioa, "%s: operating hard reset: %s\n",
				__func__, (rc == 0) ? "success" : "failed");
			csts = hst2dr_base_get_ioastate(ioa, 0);
			if ((csts & SSI2_IOA_STATE_MASK) == SSI2_IOA_STATE_FAULT)
				hst2dr_base_fault_info(ioa, csts &
					SSI2_IOA_DATA_MASK);
			if (rc && (csts & SSI2_IOA_STATE_MASK) !=
					SSI2_IOA_STATE_OPERATIONAL)
				return; /* don't rearm timer */
		}
	}
	ioa->heartbeat = heartbeat;
	spin_lock_irqsave(&ioa->ioa_reset_in_progress_lock, flags);
 rearm_timer:
	if (ioa->fault_reset_work_queue)
		queue_delayed_work(ioa->fault_reset_work_queue,
			&ioa->fault_reset_work,
			msecs_to_jiffies(FAULT_POLLING_INTERVAL));
	spin_unlock_irqrestore(&ioa->ioa_reset_in_progress_lock, flags);
}

/**
 * hst2dr_base_start_watchdog - start the fault_reset_work_queue
 * @ioa: per adapter object
 * Context: sleep.
 *
 * Return nothing.
 */
void
hst2dr_base_start_watchdog(struct HST2DR_ADAPTER *ioa)
{
	unsigned long	 flags;

	if (ioa->fault_reset_work_queue)
		return;

	/* initialize fault polling */
	ioa->heartbeat = hst2dr_read_direct_reg_hal_api(ioa, NVME_REG_WD) - 1;
	INIT_DELAYED_WORK(&ioa->fault_reset_work, _base_fault_reset_work);
	snprintf(ioa->fault_reset_work_queue_name,
		sizeof(ioa->fault_reset_work_queue_name), "poll_%s%d_status",
		ioa->driver_name, ioa->id);
	ioa->fault_reset_work_queue =
		create_singlethread_workqueue(ioa->fault_reset_work_queue_name);
	if (!ioa->fault_reset_work_queue) {
		log_error(ioa,
			"%s:%d create fault_reset_work_queue workqueue failed\n",
			__func__, __LINE__);
		return;
	}
	spin_lock_irqsave(&ioa->ioa_reset_in_progress_lock, flags);
	if (ioa->fault_reset_work_queue)
		queue_delayed_work(ioa->fault_reset_work_queue,
			&ioa->fault_reset_work,
			msecs_to_jiffies(FAULT_POLLING_INTERVAL));
	spin_unlock_irqrestore(&ioa->ioa_reset_in_progress_lock, flags);
}

/**
 * hst2dr_base_stop_watchdog - stop the fault_reset_work_queue
 * @ioa: per adapter object
 * Context: sleep.
 *
 * Return nothing.
 */
void
hst2dr_base_stop_watchdog(struct HST2DR_ADAPTER *ioa)
{
	unsigned long flags;
	struct workqueue_struct *wq;

	spin_lock_irqsave(&ioa->ioa_reset_in_progress_lock, flags);
	wq = ioa->fault_reset_work_queue;
	ioa->fault_reset_work_queue = NULL;
	spin_unlock_irqrestore(&ioa->ioa_reset_in_progress_lock, flags);
	if (wq) {
		if (!cancel_delayed_work_sync(&ioa->fault_reset_work))
			flush_workqueue(wq);
		destroy_workqueue(wq);
	}
}

/**
 * hst2dr_base_fault_info - verbose translation of firmware FAULT code
 * @ioa: per adapter object
 * @fault_code: fault code
 *
 * Return nothing.
 */
void
hst2dr_base_fault_info(struct HST2DR_ADAPTER *ioa, u16 fault_code)
{
	log_error(ioa, "fault_state: 0x%04x\n",
		fault_code);
}


/**
 * _base_sas_ioa_info - verbose translation of the ioa status
 * @ioa: per adapter object
 * @ssi_reply: reply mf payload returned from firmware
 * @request_hdr: request mf
 *
 * Return nothing.
 */
static void
_base_sas_ioa_info(struct HST2DR_ADAPTER *ioa, SSI2_DEFAULT_REPLY *ssi_reply,
	SSI2_REQUEST_HEADER *request_hdr)
{
	u16 ioa_status = le16_to_cpu(ssi_reply->status) &
		SSI2_IOASTATUS_MASK;
	char *desc = NULL;
	u16 frame_sz;
	char *func_str = NULL;

	/* SCSI_IO is handled from _hst2dr_scsi_ioa_info */
	if (request_hdr->opcode == SSI2_FUNCTION_SCSI_IO ||
			request_hdr->opcode == SSI2_FUNCTION_EVENT)
		return;

	if (ioa_status == SSI2_IOASTATUS_CONFIG_INVALID_PAGE)
		return;

	switch (ioa_status) {

/****************************************************************************
 *  Common IOAStatus values for all replies
 ****************************************************************************/

	case SSI2_IOASTATUS_INVALID_FUNCTION:
		desc = "invalid function";
		break;
	case SSI2_IOASTATUS_BUSY:
		desc = "busy";
		break;
	case SSI2_IOASTATUS_INVALID_SGL:
		desc = "invalid sgl";
		break;
	case SSI2_IOASTATUS_INTERNAL_ERROR:
		desc = "internal error";
		break;
	case SSI2_IOASTATUS_INSUFFICIENT_RESOURCES:
		desc = "insufficient resources";
		break;
	case SSI2_IOASTATUS_INSUFFICIENT_POWER:
		desc = "insufficient power";
		break;
	case SSI2_IOASTATUS_INVALID_FIELD:
		desc = "invalid field";
		break;
	case SSI2_IOASTATUS_INVALID_STATE:
		desc = "invalid state";
		break;
	case SSI2_IOASTATUS_OP_STATE_NOT_SUPPORTED:
		desc = "op state not supported";
		break;

/****************************************************************************
 *  Config IOAStatus values
 ****************************************************************************/

	case SSI2_IOASTATUS_CONFIG_INVALID_ACTION:
		desc = "config invalid action";
		break;
	case SSI2_IOASTATUS_CONFIG_INVALID_TYPE:
		desc = "config invalid type";
		break;
	case SSI2_IOASTATUS_CONFIG_INVALID_PAGE:
		desc = "config invalid page";
		break;
	case SSI2_IOASTATUS_CONFIG_INVALID_DATA:
		desc = "config invalid data";
		break;
	case SSI2_IOASTATUS_CONFIG_NO_DEFAULTS:
		desc = "config no defaults";
		break;
	case SSI2_IOASTATUS_CONFIG_CANT_COMMIT:
		desc = "config cant commit";
		break;

/****************************************************************************
 *  SCSI IO Reply
 ****************************************************************************/

	case SSI2_IOASTATUS_SCSI_RECOVERED_ERROR:
	case SSI2_IOASTATUS_SCSI_INVALID_DEVHANDLE:
	case SSI2_IOASTATUS_SCSI_DEVICE_NOT_THERE:
	case SSI2_IOASTATUS_SCSI_DATA_OVERRUN:
	case SSI2_IOASTATUS_SCSI_DATA_UNDERRUN:
	case SSI2_IOASTATUS_SCSI_IO_DATA_ERROR:
	case SSI2_IOASTATUS_SCSI_PROTOCOL_ERROR:
	case SSI2_IOASTATUS_SCSI_TASK_TERMINATED:
	case SSI2_IOASTATUS_SCSI_RESIDUAL_MISMATCH:
	case SSI2_IOASTATUS_SCSI_TASK_MGMT_FAILED:
	case SSI2_IOASTATUS_SCSI_IOA_TERMINATED:
	case SSI2_IOASTATUS_SCSI_EXT_TERMINATED:
		break;

/****************************************************************************
 *  For use by SCSI Initiator and SCSI Target end-to-end data protection
 ****************************************************************************/

	case SSI2_IOASTATUS_EEDP_GUARD_ERROR:
		desc = "eedp guard error";
		break;
	case SSI2_IOASTATUS_EEDP_REF_TAG_ERROR:
		desc = "eedp ref tag error";
		break;
	case SSI2_IOASTATUS_EEDP_APP_TAG_ERROR:
		desc = "eedp app tag error";
		break;

/****************************************************************************
 *  SCSI Target values
 ****************************************************************************/

	case SSI2_IOASTATUS_TARGET_INVALID_IO_INDEX:
		desc = "target invalid io index";
		break;
	case SSI2_IOASTATUS_TARGET_ABORTED:
		desc = "target aborted";
		break;
	case SSI2_IOASTATUS_TARGET_NO_CONN_RETRYABLE:
		desc = "target no conn retryable";
		break;
	case SSI2_IOASTATUS_TARGET_NO_CONNECTION:
		desc = "target no connection";
		break;
	case SSI2_IOASTATUS_TARGET_XFER_COUNT_MISMATCH:
		desc = "target xfer count mismatch";
		break;
	case SSI2_IOASTATUS_TARGET_DATA_OFFSET_ERROR:
		desc = "target data offset error";
		break;
	case SSI2_IOASTATUS_TARGET_TOO_MUCH_WRITE_DATA:
		desc = "target too much write data";
		break;
	case SSI2_IOASTATUS_TARGET_IU_TOO_SHORT:
		desc = "target iu too short";
		break;
	case SSI2_IOASTATUS_TARGET_ACK_NAK_TIMEOUT:
		desc = "target ack nak timeout";
		break;
	case SSI2_IOASTATUS_TARGET_NAK_RECEIVED:
		desc = "target nak received";
		break;

/****************************************************************************
 *  Serial Attached SCSI values
 ****************************************************************************/

	case SSI2_IOASTATUS_SAS_SMP_REQUEST_FAILED:
		desc = "smp request failed";
		break;
	case SSI2_IOASTATUS_SAS_SMP_DATA_OVERRUN:
		desc = "smp data overrun";
		break;

/****************************************************************************
 *  Diagnostic Buffer Post / Diagnostic Release values
 ****************************************************************************/

	default:
		desc = "unknown ioa status";
		break;
	}

	if (!desc)
		return;

	switch (request_hdr->opcode) {
	case SSI2_FUNCTION_CONFIG:
		frame_sz = sizeof(SSI2_INQUIRY_PAGE_REQUEST) + ioa->sge_size;
		func_str = "config_page";
		break;
	case SSI2_FUNCTION_SCSI_TASK_MANAGE:
		frame_sz = sizeof(SSI2_SCSI_TM_REQUEST);
		func_str = "task_manage";
		break;
	case SSI2_FUNCTION_SAS_UNIT:
		frame_sz = sizeof(SSI2_SAS_UNIT_CONTROL_REQUEST);
		func_str = "sas_unit_ctl";
		break;
	case SSI2_FUNCTION_IOA_INIT:
		frame_sz = sizeof(SSI2_IOA_INIT_REQUEST);
		func_str = "ioa_init";
		break;
	case SSI2_FUNCTION_PORT_ENABLE:
		frame_sz = sizeof(SSI2_PORT_ENABLE_REQUEST);
		func_str = "port_enable";
		break;
	case SSI2_FUNCTION_SMP_PASSTHROUGH:
		frame_sz = sizeof(SSI2_SMP_PASSTHROUGH_REQUEST) + ioa->sge_size;
		func_str = "smp_passthru";
		break;
	default:
		frame_sz = 32;
		func_str = "unknown";
		break;
	}

	log_warn(ioa,
		"%s ioa_status value: 0x%04x, req addr: 0x%p, func name: %s)\n",
		desc, ioa_status, request_hdr, func_str);

}

/**
 * _base_display_event_data - verbose translation of firmware asyn events
 * @ioa: per adapter object
 * @ssi_reply: reply mf payload returned from firmware
 *
 * Return nothing.
 */
static void
_base_display_event_data(struct HST2DR_ADAPTER *ioa,
	SSI2_EVENT_NOTIFICATION_REPLY *ssi_reply)
{
	char *desc = NULL;
	u16 event;


	event = le16_to_cpu(ssi_reply->event);

	switch (event) {
	case SSI2_EVENT_SAS_DEVICE_STATUS_CHANGE:
		desc = "Device Status Change";
		break;
	case SSI2_EVENT_SAS_DISCOVERY:
	{
		SSI2_EVENT_DATA_SAS_DISCOVERY *event_data =
			(SSI2_EVENT_DATA_SAS_DISCOVERY *)ssi_reply->event_data;
		log_event(ioa, "Discovery: (%s)",
			(event_data->reason_code ==
			SSI2_EVENT_SAS_DISC_RC_STARTED) ?
			"start" :
			(event_data->reason_code ==
			SSI2_EVENT_SAS_DISC_RC_COMPLETED) ?
			"stop" : "error");
		if (event_data->discovery_status)
			log_event(ioa, " discovery_status(0x%08x)",
				le32_to_cpu(event_data->discovery_status));
		return;
	}
	case SSI2_EVENT_SAS_BROADCAST_PRIMITIVE:
		desc = "SAS Broadcast Primitive";
		break;

	case SSI2_EVENT_SAS_TOPOLOGY_CHANGE_LIST:
		desc = "SAS Topology Change List";
		break;
	case SSI2_EVENT_SAS_ENCL_DEVICE_STATUS_CHANGE:
		desc = "SAS Enclosure Device Status Change";
		break;
	case SSI2_EVENT_IR_CONFIGURATION_CHANGE_LIST:
		desc = "IR_CONFIGURATION_CHANGE_LIST";
		break;
	case SSI2_EVENT_IR_PHYSICAL_DISK:
		desc = "EVENT_IR_PHYSICAL_DISK";
		break;
	case SSI2_EVENT_IR_VOLUME:
		desc = "EVENT_IR_VOLUME";
		break;
	case SSI2_EVENT_IR_OPERATION_STATUS:
		desc = "EVENT_IR_OPERATION_STATUS";
		break;

	}

	if (!desc) {
		log_warn(ioa, "unknown event:%x\n", event);
		return;
	}
	log_event(ioa, "%s\n", desc);
}

/**
 * _base_sas_log_info - verbose translation of firmware log info
 * @ioa: per adapter object
 * @log_info: log info
 *
 * Return nothing.
 */
static void
_base_sas_log_info(struct HST2DR_ADAPTER *ioa, u32 log_info)
{
	union loginfo_type {
		u32	loginfo;
		struct {
			u32	subcode:16;
			u32	code:8;
			u32	originator:4;
			u32	type:4;
		} dw;
	};
	union loginfo_type sas_loginfo;
	char *originator_str = NULL;

	sas_loginfo.loginfo = log_info;
	if (sas_loginfo.dw.type != SSI2_IOALOGINFO_TYPE_SAS)
		return;

	switch (sas_loginfo.dw.originator) {
	case 0:
		originator_str = "IOP";
		break;
	case 1:
		originator_str = "PL";
		break;
	}

	log_warn(ioa,
		"log_info(0x%08x): originator(%s), code(0x%02x), sub_code(0x%04x)\n",
		log_info,
		originator_str, sas_loginfo.dw.code,
		sas_loginfo.dw.subcode);
}

/**
 * _base_display_reply_info -
 * @ioa: per adapter object
 * @cqe: completion queue entity
 *
 * Return nothing.
 */
static void
_base_display_reply_info(struct HST2DR_ADAPTER *ioa,
		hst2dr_nvme_completion *cqe)
{
	SSI2_DEFAULT_REPLY *ssi_reply = NULL;
	u16 ioa_status;
	u32 loginfo = 0;

	ioa_status = le16_to_cpu(cqe->ctrl.status);

	if (cqe->ctrl.description == SSI2_RPY_DESCRIPT_FLAGS_ADDRESS_REPLY) {
		ssi_reply = hst2dr_base_get_reply_virt_addr(ioa, cqe->reply_id);

		if (unlikely(!ssi_reply)) {
			log_error(ioa, "ssi_reply not valid at %s:%d/%s()!\n",
				__FILE__, __LINE__, __func__);
			return;
		} else
			ioa_status &= ~SSI2_IOASTATUS_FLAG_LOG_INFO_AVAILABLE;
	} else
		return;

	if (ioa_status & SSI2_IOASTATUS_MASK) {
		_base_sas_ioa_info(ioa, ssi_reply,
		   hst2dr_base_get_msg_frame(ioa, cqe->host_tag_id));
	}

	if (ioa_status & SSI2_IOASTATUS_FLAG_LOG_INFO_AVAILABLE) {
		loginfo = le32_to_cpu(ssi_reply->log_info);
		_base_sas_log_info(ioa, loginfo);
	}

	if (ioa_status || loginfo)
		ioa_status &= SSI2_IOASTATUS_MASK;
}

/**
 * hst2dr_base_done - base internal command completion routine
 * @ioa: per adapter object
 * @cqe: completion queue entity
 *
 * Return 1 meaning mf should be freed from _base_interrupt
 *	0 means the mf is freed from this function.
 */
u8
hst2dr_base_done(struct HST2DR_ADAPTER *ioa,
		hst2dr_nvme_completion *cqe)
{
	SSI2_DEFAULT_REPLY *ssi_reply = NULL;

	if (cqe->ctrl.description == SSI2_RPY_DESCRIPT_FLAGS_ADDRESS_REPLY)
		ssi_reply = hst2dr_base_get_reply_virt_addr(ioa, cqe->reply_id);
	if (ssi_reply && ssi_reply->opcode == SSI2_FUNCTION_EVENT_ACK)
		return hst2dr_check_for_pending_internal_cmds(ioa,
				cqe->host_tag_id);

	if (ioa->base_cmds.status == HST2DR_CMD_NOT_USED)
		return 1;

	ioa->base_cmds.status |= HST2DR_CMD_COMPLETE;
	if (ssi_reply) {
		if (ssi_reply->msg_len == 0)
			ioa->base_cmds.status |= HST2DR_CMD_NOT_USED;
		else
			ioa->base_cmds.status |= HST2DR_CMD_REPLY_VALID;
		ssi_reply->status = cqe->ctrl.status;
		memcpy(ioa->base_cmds.reply, ssi_reply,
			min_t(u8, ssi_reply->msg_len * 4, 128));
		debug_dump_mem("base_cmds.reply:",
				ioa->base_cmds.reply,
				min_t(u8, ssi_reply->msg_len * 4, 128));
	} else {
		ssi_reply = (SSI2_DEFAULT_REPLY *)ioa->base_cmds.reply;
		ssi_reply->status = cqe->ctrl.status;
	}
	ioa->base_cmds.status &= ~HST2DR_CMD_PENDING;

	complete(&ioa->base_cmds.done);
	return 1;
}

/**
 * _base_async_event - main callback handler for firmware asyn events
 * @ioa: per adapter object
 * @cqe: completion queue entity
 *
 * Return 1 meaning mf should be freed from _base_interrupt
 *	0 means the mf is freed from this function.
 */
static u8
_base_async_event(struct HST2DR_ADAPTER *ioa,
		hst2dr_nvme_completion *cqe)
{
	SSI2_EVENT_NOTIFICATION_REPLY *ssi_reply = NULL;
	SSI2_EVENT_ACK_REQUEST *ack_request;
	u16 host_tag_id;
	struct _event_ack_list *delayed_event_ack;
	hst2dr_command *scmd;

	if (cqe->ctrl.description == SSI2_RPY_DESCRIPT_FLAGS_ADDRESS_REPLY)
		ssi_reply = hst2dr_base_get_reply_virt_addr(ioa, cqe->reply_id);
	if (!ssi_reply) {
		log_event(ioa, "%s:%d reply:%x ssi_reply:%p",
			__func__, __LINE__, cqe->reply_id, ssi_reply);
		return 1;
	}
	if (ssi_reply->opcode != SSI2_FUNCTION_EVENT) {
		log_event(ioa, "%s:%d opcode:%x ",
			__func__, __LINE__, ssi_reply->opcode);
		return 1;
	}
	debug_dump_mem("event", ssi_reply, sizeof(*ssi_reply)
			+ ssi_reply->event_data_len * 4);
	_base_display_event_data(ioa, ssi_reply);

	if (!(ssi_reply->ack_required & SSI2_EVENT_NOTIFICATION_ACK_REQUIRED))
		goto out;
	host_tag_id = hst2dr_base_get_host_tag_id(ioa, ioa->base_cb_idx);
	if (!host_tag_id) {
		delayed_event_ack = kzalloc(sizeof(*delayed_event_ack),
					GFP_ATOMIC);
		if (!delayed_event_ack)
			goto out;
		INIT_LIST_HEAD(&delayed_event_ack->list);
		delayed_event_ack->event = ssi_reply->event;
		delayed_event_ack->event_context = ssi_reply->event_context;
		list_add_tail(&delayed_event_ack->list,
				&ioa->delayed_event_ack_list);
		goto out;
	}
	scmd = hst2dr_base_get_msg_frame(ioa, host_tag_id);
	ack_request = (SSI2_EVENT_ACK_REQUEST *)scmd;
	memset(scmd, 0, sizeof(*scmd));
	ack_request->event = ssi_reply->event;
	ack_request->event_context = ssi_reply->event_context;

	ack_request->opcode = SSI2_FUNCTION_EVENT_ACK;
	ack_request->opflags = cmd_flag_fw_mode_admin;
	ack_request->host_tag_id = host_tag_id;
	ack_request->host_flag = hst2dr_cmd_base;

	ioa->put_host_tag_id_default(ioa, scmd);

 out:

	/* scsih callback handler */
	hst2dr_scsih_event_callback(ioa, cqe);

	return 1;
}

struct scsiio_tracker *
_get_st_from_host_tag_id(struct HST2DR_ADAPTER *ioa, u16 host_tag_id)
{
	struct scsi_cmnd *cmd;


	cmd = _hst2dr_scsi_lookup_get(ioa, host_tag_id);
	if (cmd)
		return scsi_cmd_priv(cmd);

	return NULL;
}

/**
 * _base_get_cb_idx - obtain the callback index
 * @ioa: per adapter object
 * @host_tag_id: request message index
 *
 * Return callback index.
 */
static u8
_base_get_cb_idx(struct HST2DR_ADAPTER *ioa, u16 host_tag_id)
{
	int i;
	u8 cb_idx = INVALID_CB_INDEX;
	struct scsiio_tracker *st;
	u16 ctl_host_tag_id = ioa->scsiio_depth -
		INTERNAL_SCSIIO_CMDS_COUNT + 1;

	if (host_tag_id < ioa->internal_host_tag_id) {
		st = _get_st_from_host_tag_id(ioa, host_tag_id);
		if (likely(st))	{
			if (st->direct_io == MAGIC_NUMBER)
				cb_idx = st->cb_idx;
		} else if (ctl_host_tag_id == host_tag_id)
			cb_idx = ioa->ctl_cb_idx;
	} else if (host_tag_id < HOST_TAG_ID_POLL) {
		i = host_tag_id - ioa->internal_host_tag_id;
		cb_idx = ioa->internal_lookup[i].cb_idx;
	} else
		cb_idx = INVALID_CB_INDEX;
	return cb_idx;
}

/**
 * _base_mask_interrupts - disable interrupts
 * @ioa: per adapter object
 *
 * Disabling ResetIRQ, Reply and NVME Interrupts
 *
 * Return nothing.
 */
static void
_base_mask_interrupts(struct HST2DR_ADAPTER *ioa)
{

	ioa->mask_interrupts = 1;
	hst2dr_write_direct_reg_hal_api(ioa, NVME_REG_INTMS, 0xffffffff);
}

/**
 * _base_unmask_interrupts - enable interrupts
 * @ioa: per adapter object
 *
 * Enabling only Reply Interrupts
 *
 * Return nothing.
 */

static void
_base_unmask_interrupts(struct HST2DR_ADAPTER *ioa)
{

	hst2dr_write_direct_reg_hal_api(ioa, NVME_REG_INTMC, 0xffffffff);
	ioa->mask_interrupts = 0;
	ioa->ioa_reset_in_progress &= ~2;
}

union reply_descriptor {
	u64 word;
	struct {
		u32 low;
		u32 high;
	} u;
};

static inline void push_reply_sense(struct HST2DR_ADAPTER *ioa, u16 reply_id)
{
	unsigned long flags;

	spin_lock_irqsave(&ioa->reply_sense_q_lock, flags);
	ioa->reply_sense_q_ctrl.ctrl.reg.reply_push = 1;
	ioa->reply_sense_q_ctrl.ctrl.reg.sense_push = 0;
	ioa->reply_sense_q_ctrl.ctrl.reg.reply_id = reply_id;
	hst2dr_write_direct_reg_hal_api(ioa, NVME_REG_REPLY_SENSE_Q_CTRL,
		ioa->reply_sense_q_ctrl.ctrl.dw);
	spin_unlock_irqrestore(&ioa->reply_sense_q_lock, flags);
}
static u16 _process_one_queue(struct HST2DR_ADAPTER *ioa, u8 msix_index)
{
	struct nvme_queue *nvmeq;

	hst2dr_nvme_completion *cqe;
	u16 completed_cmds = 0;
	u16 host_tag_id;
	int rc;
	u8 request_descript_type;
	u8 cb_idx;
	u8 push_reply = 1;

	nvmeq = &ioa->hst2dr_var.nvmeq[msix_index];

	cqe = &nvmeq->cqes[nvmeq->cq_head];

	if ((le16_to_cpu(cqe->ctrl.phase) & 1) != nvmeq->cq_phase)
		return 0;

	request_descript_type = cqe->ctrl.description;
	if (unlikely(request_descript_type == SSI2_RPY_DESCRIPT_FLAGS_UNUSED)) {
		log_error(ioa, "descript_type unused\n");
		return 0;
	}
	if (ioa->chip_version == VS_V2M2)
		__builtin_prefetch((const void *)
				&nvmeq->cqes[nvmeq->cq_head], 0, 2);

	do {
		host_tag_id = le16_to_cpu(cqe->host_tag_id);
		if (host_tag_id < HOST_TAG_ID_POLL) {
			//deal with IO/ADMIN reply command
			completed_cmds++;
		cb_idx = _base_get_cb_idx(ioa, host_tag_id);
		if (likely(cb_idx < HST2DR_MAX_CALLBACKS &&
			hst2dr_callbacks[cb_idx])) {
			rc = hst2dr_callbacks[cb_idx](ioa, cqe);
			if (rc)
				hst2dr_base_free_host_tag_id(ioa, host_tag_id);
			ioa->hst2dr_var.nvmeq[cqe->sq_id].sq_head = cqe->sq_head;
		} else {
			log_error(ioa,
				"Invalid callback index %d or callback is NULL, host_tag_id %x\n",
				cb_idx, host_tag_id);
		}
		} else if (host_tag_id == HOST_TAG_ID_EVENT) {
			//Async event is handled
			completed_cmds++;
			ioa->hst2dr_var.nvmeq[cqe->sq_id].sq_head = cqe->sq_head;
			_base_async_event(ioa, cqe);
		} else { //HOST_TAG_ID_POLL:
			push_reply = 0;
		}

		if (likely(push_reply == 1)) {
			if (request_descript_type ==
				SSI2_RPY_DESCRIPT_FLAGS_ADDRESS_REPLY) {
				if ((host_tag_id >= ioa->scsiio_depth)
					&& (host_tag_id < HOST_TAG_ID_POLL))
					_base_display_reply_info(ioa, cqe);
				push_reply_sense(ioa, cqe->reply_id);
			}
		} else
			push_reply = 1;

		if (++nvmeq->cq_head == nvmeq->cq_depth) {
			nvmeq->cq_head = 0;
			nvmeq->cq_phase = !nvmeq->cq_phase;
		}
		if (unlikely(ioa->total_irq == 1)) {
			//When IRQ equals 1, the Admin event should be processed
			//first, and each IO should handle only one event.
			if (ioa->chip_version == VS_V2M2)
				writel(nvmeq->cq_head, CQ_HEADER(msix_index));
			return completed_cmds;
		}
		cqe = &nvmeq->cqes[nvmeq->cq_head];
		if ((le16_to_cpu(cqe->ctrl.phase) & 1) != nvmeq->cq_phase)
			break;

		request_descript_type = cqe->ctrl.description;
		if (unlikely(request_descript_type ==
				SSI2_RPY_DESCRIPT_FLAGS_UNUSED))
			break;
		if (ioa->chip_version == VS_V2M2)
			__builtin_prefetch((const void *)
					&nvmeq->cqes[nvmeq->cq_head], 0, 2);
	} while (1);
	if (ioa->chip_version == VS_V2M2)
		writel(nvmeq->cq_head, CQ_HEADER(msix_index));
	return completed_cmds;
}

static irqreturn_t _base_interrupt(int irq, void *bus_id)
{
	struct adapter_reply_queue *reply_q = bus_id;
	struct HST2DR_ADAPTER *ioa = reply_q->ioa;
	u16 completed_cmds = 0;
	u16 admin_cmds = 0;
	u16 io_cmds = 0;

	if (ioa->mask_interrupts)
		return IRQ_NONE;

	if (!atomic_add_unless(&reply_q->busy, 1, 1))
		return IRQ_NONE;

	if (unlikely(ioa->total_irq == 1)) {
		while (1) {
			admin_cmds = _process_one_queue(ioa, 0);
			io_cmds = _process_one_queue(ioa, 1);
			if (admin_cmds == 0 && io_cmds == 0)
				break;
			completed_cmds += (admin_cmds + io_cmds);
		}
	} else {
		completed_cmds += _process_one_queue(ioa, reply_q->msix_index);
	}
	atomic_dec(&reply_q->busy);
	return completed_cmds ? IRQ_HANDLED : IRQ_NONE;
}

/**
 * _base_is_controller_msix_enabled - is controller support muli-reply queues
 * @ioa: per adapter object
 *
 */
static inline int
_base_is_controller_msix_enabled(struct HST2DR_ADAPTER *ioa)
{
	return ioa->msix_enable;
}

/**
 * hst2dr_base_sync_reply_irqs - flush pending MSIX interrupts
 * @ioa: per adapter object
 * Context: non ISR conext
 *
 * Called when a Task Management request has completed.
 *
 * Return nothing.
 */
void
hst2dr_base_sync_reply_irqs(struct HST2DR_ADAPTER *ioa)
{
	struct adapter_reply_queue *reply_q;

	/* If MSIX capability is turned off
	 * then multi-queues are not enabled
	 */
	if (!_base_is_controller_msix_enabled(ioa))
		return;

	list_for_each_entry(reply_q, &ioa->reply_queue_list, list) {
		if (ioa->shost_recovery || ioa->remove_host ||
				ioa->pci_error_recovery)
			return;
		/* TMs are on msix_index == 0 */
		if (reply_q->msix_index == 0)
			continue;
		synchronize_irq(pci_irq_vector(ioa->pdev, reply_q->msix_index));
	}
}

/**
 * hst2dr_base_release_callback_handler - clear interrupt callback handler
 * @cb_idx: callback index
 *
 * Return nothing.
 */
void
hst2dr_base_release_callback_handler(u8 cb_idx)
{
	hst2dr_callbacks[cb_idx] = NULL;
}

/**
 * hst2dr_base_register_callback_handler - obtain index for the interrupt
 *						callback handler
 * @cb_func: callback function
 *
 * Returns cb_func.
 */
u8
hst2dr_base_register_callback_handler(HST2DR_CALLBACK cb_func)
{
	u8 cb_idx;

	for (cb_idx = HST2DR_MAX_CALLBACKS-1; cb_idx; cb_idx--)
		if (hst2dr_callbacks[cb_idx] == NULL)
			break;

	hst2dr_callbacks[cb_idx] = cb_func;
	return cb_idx;
}

/**
 * hst2dr_base_initialize_callback_handler - initialize the interrupt
 *						callback handler
 *
 * Return nothing.
 */
void
hst2dr_base_initialize_callback_handler(void)
{
	u8 cb_idx;

	for (cb_idx = 0; cb_idx < HST2DR_MAX_CALLBACKS; cb_idx++)
		hst2dr_base_release_callback_handler(cb_idx);
}


/**
 * _base_build_zero_len_sge - build zero length sg entry
 * @ioa: per adapter object
 * @paddr: virtual address for SGE
 *
 * Create a zero length scatter gather entry to insure the IOAs hardware has
 * something to use if the target device goes brain dead and tries
 * to send data even when none is asked for.
 *
 * Return nothing.
 */
static void
_base_build_zero_len_sge(struct HST2DR_ADAPTER *ioa, void *paddr)
{
	u32 flags_length = (u32)((SSI2_SGE_FLAGS_LAST_ELEMENT |
		SSI2_SGE_FLAGS_END_OF_BUFFER | SSI2_SGE_FLAGS_END_OF_LIST |
		SSI2_SGE_FLAGS_SIMPLE_ELEMENT) <<
		SSI2_SGE_FLAGS_SHIFT);
	ioa->base_fill_1_sg(paddr, flags_length, -1);
}

/**
 * _base_fill_1_sg_32 - Place a 32 bit SGE at address pAddr.
 * @paddr: virtual address for SGE
 * @flags_length: SGE flags and data transfer length
 * @dma_addr: Physical address
 *
 * Return nothing.
 */
static void
_base_fill_1_sg_32(void *paddr, u32 flags_length, dma_addr_t dma_addr)
{
	SSI2SGESimple32_t *sgel = paddr;

	flags_length |= (SSI2_SGE_FLAGS_32_BIT_ADDRESSING |
		SSI2_SGE_FLAGS_SYSTEM_ADDRESS) << SSI2_SGE_FLAGS_SHIFT;
	sgel->FlagsLength = cpu_to_le32(flags_length);
	sgel->Address = cpu_to_le32(dma_addr);
}


/**
 * _base_fill_1_sg_64 - Place a 64 bit SGE at address pAddr.
 * @paddr: virtual address for SGE
 * @flags_length: SGE flags and data transfer length
 * @dma_addr: Physical address
 *
 * Return nothing.
 */
static void
_base_fill_1_sg_64(void *paddr, u32 flags_length, dma_addr_t dma_addr)
{
	SSI2SGESimple64_t *sgel = paddr;

	flags_length |= (SSI2_SGE_FLAGS_64_BIT_ADDRESSING |
		SSI2_SGE_FLAGS_SYSTEM_ADDRESS) << SSI2_SGE_FLAGS_SHIFT;
	sgel->FlagsLength = cpu_to_le32(flags_length);
	sgel->Address = cpu_to_le64(dma_addr);
}

/**
 * _base_get_chain_buffer - get chain buffer
 * @ioa: per adapter object
 * @scmd: SCSI commands of the IO request
 *
 * Returns chain tracker from chain_lookup table using key as
 * host_tag_id and host_tag_id's chain_offset.
 */
static struct chain_segment_t *
_base_get_chain_buffer(struct HST2DR_ADAPTER *ioa, struct scsi_cmnd *scmd)
{
	struct chain_segment_t *chain;
	struct scsiio_tracker *st = scsi_cmd_priv(scmd);
	u16 host_tag_id = st->host_tag_id;
	u8 chain_offset =
	   atomic_read(&ioa->chain_lookup[host_tag_id].chain_offset);

	if (chain_offset == ioa->chains_needed_per_io)
		return NULL;

	chain = &ioa->chain_lookup[host_tag_id].chains_per_host_tag_id[chain_offset];
	atomic_inc(&ioa->chain_lookup[host_tag_id].chain_offset);
	return chain;
}


/**
 * _base_build_sg - build generic sg
 * @ioa: per adapter object
 * @psge: virtual address for SGE
 * @data_out_dma: physical address for WRITES
 * @data_out_sz: data xfer size for WRITES
 * @data_in_dma: physical address for READS
 * @data_in_sz: data xfer size for READS
 *
 * Return nothing.
 */
static void
_base_build_sg(struct HST2DR_ADAPTER *ioa, void *psge,
	dma_addr_t data_out_dma, size_t data_out_sz, dma_addr_t data_in_dma,
	size_t data_in_sz)
{
	u32 sgl_flags;

	if (!data_out_sz && !data_in_sz) {
		_base_build_zero_len_sge(ioa, psge);
		return;
	}

	if (data_out_sz && data_in_sz) {
		/* WRITE sgel first */
		sgl_flags = (SSI2_SGE_FLAGS_SIMPLE_ELEMENT |
			SSI2_SGE_FLAGS_END_OF_BUFFER |
			SSI2_SGE_FLAGS_HOST_TO_IOA);
		sgl_flags = sgl_flags << SSI2_SGE_FLAGS_SHIFT;
		ioa->base_fill_1_sg(psge, sgl_flags |
			data_out_sz, data_out_dma);

		/* incr sgel */
		psge += ioa->sge_size;

		/* READ sgel last */
		sgl_flags = (SSI2_SGE_FLAGS_SIMPLE_ELEMENT |
			SSI2_SGE_FLAGS_LAST_ELEMENT |
			SSI2_SGE_FLAGS_END_OF_BUFFER |
			SSI2_SGE_FLAGS_END_OF_LIST);
		sgl_flags = sgl_flags << SSI2_SGE_FLAGS_SHIFT;
		ioa->base_fill_1_sg(psge, sgl_flags |
			data_in_sz, data_in_dma);
	} else if (data_out_sz) /* WRITE */ {
		sgl_flags = (SSI2_SGE_FLAGS_SIMPLE_ELEMENT |
			SSI2_SGE_FLAGS_LAST_ELEMENT |
			SSI2_SGE_FLAGS_END_OF_BUFFER |
			SSI2_SGE_FLAGS_END_OF_LIST |
			SSI2_SGE_FLAGS_HOST_TO_IOA);
		sgl_flags = sgl_flags << SSI2_SGE_FLAGS_SHIFT;
		ioa->base_fill_1_sg(psge, sgl_flags |
			data_out_sz, data_out_dma);
	} else if (data_in_sz) /* READ */ {
		sgl_flags = (SSI2_SGE_FLAGS_SIMPLE_ELEMENT |
			SSI2_SGE_FLAGS_LAST_ELEMENT |
			SSI2_SGE_FLAGS_END_OF_BUFFER |
			SSI2_SGE_FLAGS_END_OF_LIST);
		sgl_flags = sgl_flags << SSI2_SGE_FLAGS_SHIFT;
		ioa->base_fill_1_sg(psge, sgl_flags |
			data_in_sz, data_in_dma);
	}
}

/* IEEE format sgls */

/**
 * _base_fill_1_sg_ieee - add sg for IEEE format
 * @paddr: virtual address for SGE
 * @flags: SGE flags
 * @length: data transfer length
 * @dma_addr: Physical address
 *
 * Return nothing.
 */
static void
_base_fill_1_sg_ieee(void *paddr, u8 flags, u32 length,
	dma_addr_t dma_addr)
{
	SSI2IeeeSgeChain64_t *sgel = paddr;

	sgel->Flags = flags;
	sgel->Length = cpu_to_le32(length);
	sgel->Address = cpu_to_le64(dma_addr);
}

/**
 * _base_build_nodata_sge - build nodata sg entry
 * @ioa: per adapter object
 * @paddr: virtual address for SGE
 *
 * Create a nodata(zero length) scatter gather entry.
 *
 * Return nothing.
 */
static void
_base_build_nodata_sge(struct HST2DR_ADAPTER *ioa, void *paddr)
{
	u8 sgl_flags = (SSI2_IEEE_SGE_FLAGS_SYSTEM_ADDR |
		SSI2_IEEE_SGE_FLAGS_END_OF_LIST);

	_base_fill_1_sg_ieee(paddr, sgl_flags, 0, -1);
}


/**
 * _base_build_sg_scmd_ieee - main sg creation routine for IEEE format
 * @ioa: per adapter object
 * @scmd: scsi command
 * @host_tag_id: request message index
 * Context: none.
 *
 * The main routine that builds scatter gather table from a given
 * scsi request sent via the .queuecommand main handler.
 *
 * Returns 0 success, anything else error
 */
static int
_base_build_sg_scmd_ieee(struct HST2DR_ADAPTER *ioa,
	struct scsi_cmnd *scmd, u16 host_tag_id)
{
	SSI2_SCSI_REQUEST *ssi_request;
	struct scatterlist *sg_scmd;
	void *sg_main;
	int sge_processing;
	struct chain_segment_t *chain_req;
	int index = 0;

	ssi_request = hst2dr_base_get_msg_frame(ioa, host_tag_id);

	sg_scmd = scsi_sglist(scmd);
	sge_processing = scsi_dma_map(scmd);
	if (sge_processing < 0) {
		sdev_printk(KERN_ERR, scmd->device,
			"pci_map_sg failed: request for %d bytes!\n",
			scsi_bufflen(scmd));
		return -ENOMEM;
	}
	sg_main = &ssi_request->sgl;

	scsi_for_each_sg(scmd, sg_scmd, sge_processing, index) {
		if (index ==  sge_processing - 1) { // last sgl
			_base_fill_1_sg_ieee(sg_main,
				SSI2_IEEE_SGE_FLAGS_SYSTEM_ADDR |
				SSI2_IEEE_SGE_FLAGS_END_OF_LIST,
				sg_dma_len(sg_scmd), sg_dma_address(sg_scmd));
			break;

		} else if ((index == 3) || ((index > 3) &&
			(index != sge_processing - 1) &&
			((index - 3) % (ioa->chain_segment_sz /
				MAX_CHAIN_ELEMT_SZ)
			== ioa->max_sges_in_chain_message))) { // add chain sgl
			chain_req = _base_get_chain_buffer(ioa, scmd);
			if (!chain_req)	{
				log_error(ioa,
					"Failed to get chain buffer for sge_processing %d\n",
					sge_processing);
				return -1;
			}
			_base_fill_1_sg_ieee(sg_main,
				SSI2_IEEE_SGE_FLAGS_CHAIN_ELEMENT |
				SSI2_IEEE_SGE_FLAGS_SYSTEM_ADDR,
				sge_processing - index >=
				(ioa->chain_segment_sz / MAX_CHAIN_ELEMT_SZ) ?
				ioa->chain_segment_sz :
				(sge_processing - index) * MAX_CHAIN_ELEMT_SZ,
				chain_req->chain_buffer_dma);
			sg_main = chain_req->chain_buffer;
		}
		_base_fill_1_sg_ieee(sg_main, SSI2_IEEE_SGE_FLAGS_SYSTEM_ADDR,
				sg_dma_len(sg_scmd), sg_dma_address(sg_scmd));
		sg_main += ioa->sge_size_ieee;
	}

	return 0;

}

/**
 * _base_build_sg_ieee - build generic sg for IEEE format
 * @ioa: per adapter object
 * @psge: virtual address for SGE
 * @data_out_dma: physical address for WRITES
 * @data_out_sz: data xfer size for WRITES
 * @data_in_dma: physical address for READS
 * @data_in_sz: data xfer size for READS
 *
 * Return nothing.
 */
static void
_base_build_sg_ieee(struct HST2DR_ADAPTER *ioa, void *psge,
	dma_addr_t data_out_dma, size_t data_out_sz, dma_addr_t data_in_dma,
	size_t data_in_sz)
{
	u8 sgl_flags;

	if (!data_out_sz && !data_in_sz) {
		_base_build_nodata_sge(ioa, psge);
		return;
	}

	if (data_out_sz && data_in_sz) {
		/* WRITE sgel first */
		sgl_flags = SSI2_IEEE_SGE_FLAGS_SYSTEM_ADDR;
		_base_fill_1_sg_ieee(psge, sgl_flags, data_out_sz,
			data_out_dma);

		/* incr sgel */
		psge += ioa->sge_size_ieee;

		/* READ sgel last */
		sgl_flags |= SSI2_IEEE_SGE_FLAGS_END_OF_LIST;
		_base_fill_1_sg_ieee(psge, sgl_flags, data_in_sz,
			data_in_dma);
	} else if (data_out_sz) /* WRITE */ {
		sgl_flags = SSI2_IEEE_SGE_FLAGS_END_OF_LIST |
			SSI2_IEEE_SGE_FLAGS_SYSTEM_ADDR;
		_base_fill_1_sg_ieee(psge, sgl_flags, data_out_sz,
			data_out_dma);
	} else if (data_in_sz) /* READ */ {
		sgl_flags = SSI2_IEEE_SGE_FLAGS_END_OF_LIST |
			SSI2_IEEE_SGE_FLAGS_SYSTEM_ADDR;
		_base_fill_1_sg_ieee(psge, sgl_flags, data_in_sz,
			data_in_dma);
	}
}

#define convert_to_kb(x) ((x) << (PAGE_SHIFT - 10))

/**
 * _base_config_dma_addressing - set dma addressing
 * @ioa: per adapter object
 * @pdev: PCI device struct
 *
 * Returns 0 for success, non-zero for failure.
 */
static int
_base_config_dma_addressing(struct HST2DR_ADAPTER *ioa, struct pci_dev *pdev)
{
	struct sysinfo s;
	u64 consistent_dma_mask, dma_mask;

	consistent_dma_mask = dma_mask = DMA_BIT_MASK(64);

	if (sizeof(dma_addr_t) > 4) {
		const uint64_t required_mask =
			dma_get_required_mask(&pdev->dev);
		if ((required_mask > DMA_BIT_MASK(32)) &&
				!dma_set_mask(&pdev->dev, dma_mask) &&
				!dma_set_coherent_mask(&pdev->dev,
				consistent_dma_mask)) {
			ioa->base_fill_1_sg = &_base_fill_1_sg_64;
			ioa->sge_size = sizeof(SSI2SGESimple64_t);
			ioa->dma_mask = 64;
			goto out;
		}
	}


	if (!dma_set_mask(&pdev->dev, DMA_BIT_MASK(32))
			&& !dma_set_coherent_mask(
			&pdev->dev, DMA_BIT_MASK(32))) {
		ioa->base_fill_1_sg = &_base_fill_1_sg_32;
		ioa->sge_size = sizeof(SSI2SGESimple32_t);
		ioa->dma_mask = 32;
	} else
		return -ENODEV;

 out:
	si_meminfo(&s);
	log_init(ioa,
		"%d BIT PCI BUS DMA ADDRESSING SUPPORTED, total mem (%ld kB)\n",
		ioa->dma_mask, convert_to_kb(s.totalram));

	return 0;
}
/**
 * _base_change_consistent_dma_mask - change dma mask
 * @ioa: per adapter object
 * @pdev: PCI device struct
 *
 * Returns 0 for success, non-zero for failure.
 */

static int
_base_change_consistent_dma_mask(struct HST2DR_ADAPTER *ioa,
		struct pci_dev *pdev)
{
	if (dma_set_coherent_mask(&pdev->dev, DMA_BIT_MASK(64))) {
		if (dma_set_coherent_mask(&pdev->dev, DMA_BIT_MASK(32)))
			return -ENODEV;
	}
	return 0;
}

/**
 * _base_check_enable_msix - checks MSIX enable.
 * @ioa: per adapter object
 *
 * Check to see if MSIX is supported, and set number
 * of available msix vectors
 */
static int
_base_check_enable_msix(struct HST2DR_ADAPTER *ioa)
{
	int base;
	u16 hst2dr_control;

	base = pci_find_capability(ioa->pdev, PCI_CAP_ID_MSIX);
	if (!base) {
		log_error(ioa, "msix not supported!\n");
		return -EINVAL;
	}

	/* get msix vector count */

	pci_read_config_word(ioa->pdev, base + 2, &hst2dr_control);
	ioa->msix_vector_count = (hst2dr_control & 0x3FF) + 1;
	log_init(ioa, "msix is supported, vector_count: %d\n",
		ioa->msix_vector_count);
	return 0;
}


/**
 * _base_free_irq - free irq
 * @ioa: per adapter object
 *
 * Freeing respective reply_queue from the list.
 */
static void
_base_free_irq(struct HST2DR_ADAPTER *ioa)
{
	struct adapter_reply_queue *reply_q, *next;

	if (list_empty(&ioa->reply_queue_list))
		return;

	list_for_each_entry_safe(reply_q, next, &ioa->reply_queue_list, list) {
		list_del_init(&reply_q->list);
		free_irq(pci_irq_vector(ioa->pdev, reply_q->msix_index),
			 reply_q);
		kfree(reply_q);
	}
}

/**
 * _base_request_irq - request irq
 * @ioa: per adapter object
 * @index: msix index into vector table
 *
 * Inserting respective reply_queue into the list.
 */
static int
_base_request_irq(struct HST2DR_ADAPTER *ioa, u8 index)
{
	struct pci_dev *pdev = ioa->pdev;
	struct adapter_reply_queue *reply_q;
	int r;

	reply_q =  kzalloc(sizeof(struct adapter_reply_queue), GFP_KERNEL);
	if (!reply_q) {
		log_error(ioa, "unable to allocate memory %d!\n",
			(int)sizeof(struct adapter_reply_queue));
		return -ENOMEM;
	}
	reply_q->ioa = ioa;
	reply_q->msix_index = index;

	atomic_set(&reply_q->busy, 0);
	if (ioa->msix_enable)
		snprintf(reply_q->name, HST2DR_NAME_LENGTH, "%s%d-msix%d",
			ioa->driver_name, ioa->id, index);
	else
		snprintf(reply_q->name, HST2DR_NAME_LENGTH, "%s%d",
			ioa->driver_name, ioa->id);
	r = request_irq(pci_irq_vector(pdev, index), _base_interrupt,
			IRQF_SHARED, reply_q->name, reply_q);
	if (r) {
		log_error(ioa, "%s: unable to request interrupt %d!\n",
			reply_q->name, pci_irq_vector(pdev, index));
		kfree(reply_q);
		return r;
	}

	INIT_LIST_HEAD(&reply_q->list);
	list_add_tail(&reply_q->list, &ioa->reply_queue_list);

	return 0;
}
/**
 * _base_group_cpus_on_irq - when there are more cpus than available
 *			msix vectors, then group cpus
 *			together on same irq
 * @ioc: per adapter object
 *
 * Return nothing.
 */
static void
_base_group_cpus_on_irq(struct HST2DR_ADAPTER *ioa)
{
	struct adapter_reply_queue *reply_q;
	unsigned int i, cpu, group, nr_cpus, nr_msix, index = 0;

	cpu = cpumask_first(cpu_online_mask);
	nr_msix = ioa->reply_queue_count - 2;
	nr_cpus = num_online_cpus();
	group = nr_cpus / nr_msix;

	list_for_each_entry(reply_q, &ioa->reply_queue_list, list) {

		if (reply_q->msix_index < 1)
			continue;

		if (cpu >= nr_cpus)
			break;

		if (index < nr_cpus % nr_msix)
			group++;

		for (i = 0 ; i < group ; i++) {
			ioa->cpu_msix_table[cpu] = reply_q->msix_index;
			cpu = cpumask_next(cpu, cpu_online_mask);
			log_init(ioa, "__ cpu:%02x msix_index:%02x",
				cpu, ioa->cpu_msix_table[cpu]);
		}
		index++;
	}
}

/**
 * _base_import_managed_irqs_affinity - import msix affinity of managed IRQs
 *	into local cpu mapping table.
 * @ioc - per adapter object
 *
 * Return nothing.
 */
static void
_base_import_managed_irqs_affinity(struct HST2DR_ADAPTER *ioa)
{
	struct adapter_reply_queue *reply_q;
	unsigned int cpu, nr_msix;
	const cpumask_t *mask;
	u64 *p1, *p2;

	nr_msix = ioa->reply_queue_count - 2;
	if (!nr_msix)
		return;

	list_for_each_entry(reply_q, &ioa->reply_queue_list, list) {

		if (reply_q->msix_index < 1) {
			log_init(ioa, "skip affinity msix:%02x\n",
					reply_q->msix_index);
			continue;
		}
		if (reply_q->msix_index == ioa->reply_queue_count - 1) {
			log_init(ioa, "skip affinity msix:%02x\n",
					reply_q->msix_index);
			break;
		}
		mask = pci_irq_get_affinity(ioa->pdev,
			reply_q->msix_index);
		if (!mask) {
			log_init(ioa, "no affinity for msi %x\n",
				reply_q->msix_index);
			goto fall_back;
		}
		p1 = (u64 *)mask;
		p2 = p1++;
		log_init(ioa, "mask msix:%02x: %016llx %016llx",
				reply_q->msix_index, *p1, *p2);
		for_each_cpu_and(cpu, mask, cpu_online_mask) {
			if (cpu >= ioa->cpu_msix_table_sz)
				break;
			ioa->cpu_msix_table[cpu] = reply_q->msix_index;
			log_init(ioa, "io cpu:%02x msix_index:%02x",
					cpu, reply_q->msix_index);
		}
	}
	mask = pci_irq_get_affinity(ioa->pdev, 0);
	for_each_cpu_and(cpu, mask, cpu_online_mask) {
		if (cpu >= ioa->cpu_msix_table_sz)
			break;
		ioa->cpu_msix_table[cpu] = 1;
		log_init(ioa,
			"io cpu:%02x msix_index:%02x", cpu, 1);
	}

	mask = pci_irq_get_affinity(ioa->pdev,
			ioa->reply_queue_count - 1);
	for_each_cpu_and(cpu, mask, cpu_online_mask) {
		if (cpu >= ioa->cpu_msix_table_sz)
			break;
		ioa->cpu_msix_table[cpu] = ioa->reply_queue_count - 2;
		log_init(ioa, "io cpu:%02x msix_index:%02x",
			cpu, ioa->cpu_msix_table[cpu]);
	}

	return;

fall_back:
	_base_group_cpus_on_irq(ioa);
}


/**
 * _base_assign_reply_queues - assigning msix index for each cpu
 * @ioa: per adapter object
 *
 * The enduser would need to set the affinity via /proc/irq/#/smp_affinity
 *
 * It would nice if we could call irq_set_affinity, however it is not
 * an exported symbol
 */
static void
_base_assign_reply_queues(struct HST2DR_ADAPTER *ioa)
{
	unsigned int nr_cpus, nr_msix;

	if (!_base_is_controller_msix_enabled(ioa))
		return;

	memset(ioa->cpu_msix_table, 0, ioa->cpu_msix_table_sz);

	nr_cpus = num_online_cpus();
	nr_msix = ioa->reply_queue_count = min(ioa->reply_queue_count,
					ioa->info.max_msix_vectors);
	if (!nr_msix)
		return;

	_base_import_managed_irqs_affinity(ioa);
}

/**
 * _base_disable_msix - disables msix
 * @ioa: per adapter object
 *
 */
static void
_base_disable_msix(struct HST2DR_ADAPTER *ioa)
{
	pci_free_irq_vectors(ioa->pdev);
	if (!ioa->msix_enable)
		return;
	ioa->msix_enable = 0;
	ioa->hst2dr_var.intr_enabled = 0;
}
/**
 * _base_alloc_irq_vectors - allocate msix vectors
 * @ioc: per adapter object
 *
 */
static int
_base_alloc_irq_vectors(struct HST2DR_ADAPTER *ioa)
{
	int i, irq_flags = PCI_IRQ_MSIX;
	struct irq_affinity desc = { .pre_vectors = ioa->admin_queues };
	struct irq_affinity *descp = &desc;
	/*
	 * Do not allocate msix vectors for poll_queues.
	 * msix_vectors is always within a range of FW supported reply queue.
	 */
	int nr_msix_vectors = ioa->reply_queue_count;

	irq_flags |= PCI_IRQ_AFFINITY | PCI_IRQ_ALL_TYPES;

	ioa->admin_queues = 1;
	log_init(ioa,
		"admin_queues: %d, reply_queue_count: %d, nr_msix_vectors: %d\n",
		ioa->admin_queues, ioa->reply_queue_count, nr_msix_vectors);

	i = pci_alloc_irq_vectors_affinity(ioa->pdev,
		ioa->admin_queues,
		nr_msix_vectors, irq_flags, descp);

	return i;
}
/**
 * _base_enable_msix - enables msix, failback to io_apic
 * @ioa: per adapter object
 *
 */
static int
_base_enable_msix(struct HST2DR_ADAPTER *ioa)
{
	struct msix_entry *entries, *a;
	int r;
	int i, local_max_msix_vectors;
	u8 try_msix = 0;
	int msix_count = 0;

	if (msix_disable == -1)
		try_msix = 1;

	if (!try_msix)
		goto try_legacy;

	if (_base_check_enable_msix(ioa) != 0)
		goto try_legacy;

	ioa->reply_queue_count = min_t(int, ioa->cpu_count,
		ioa->msix_vector_count);
	if (nr_node_ids < 8)
		ioa->numa_count = 9; // least 8 and ctl queue
	else if (nr_node_ids >= 32)
		ioa->numa_count = 32;
	else
		ioa->numa_count = nr_node_ids + 1;
	log_init(ioa, "%s %d, %s %d, %s %d %s %d %s %d\n",
			"MSI-X vectors supported:", ioa->msix_vector_count,
			"no of cores:", ioa->cpu_count,
			"max_msix_vectors:", max_msix_vectors,
			"max_sq:", ioa->info.max_sq,
			"max_cq:", ioa->info.max_cq);
	if (max_msix_vectors == -1)
		local_max_msix_vectors = NUM_OF_IO_Q + 1;
	else
		local_max_msix_vectors = max_msix_vectors;
	ioa->reply_queue_count =
		min_t(int, ioa->reply_queue_count, ioa->info.max_cq + 1);
	if (ioa->reply_queue_count > NUM_OF_IO_Q + 1)
		ioa->reply_queue_count = NUM_OF_IO_Q + 1;
	if (local_max_msix_vectors > 0)
		ioa->reply_queue_count = min_t(int, local_max_msix_vectors,
			ioa->reply_queue_count);
	else if (local_max_msix_vectors == 0)
		goto try_legacy;
	log_init(ioa, "reply_queue_count:%d\n", ioa->reply_queue_count);

	entries = kcalloc(ioa->reply_queue_count, sizeof(struct msix_entry),
			GFP_KERNEL);
	if (!entries) {
		log_error(ioa,
			"No entries, allocate memory failed, goto try_legacy\n");
		goto try_legacy;
	}

	for (i = 0, a = entries; i < ioa->reply_queue_count; i++, a++)
		a->entry = i;

	msix_count = ioa->reply_queue_count;

	r = _base_alloc_irq_vectors(ioa);
	if (r < 0) {
		log_error(ioa,
			"pci_alloc_irq_vectors failed (r=%d) !\n",   r);
		kfree(entries);
		goto try_legacy;
	}
	for (i = 0; i < ioa->reply_queue_count; i++) {
		ioa->total_irq++;
		r = _base_request_irq(ioa, i);
		if (r) {
			log_error(ioa, "request irq fail at %d\n", i);
			_base_free_irq(ioa);
			_base_disable_msix(ioa);
			kfree(entries);
			goto try_legacy;
		}
	}

	kfree(entries);

	ioa->hst2dr_var.intr_enabled = 1;
	ioa->msix_enable = 1;

	return 0;

/* fail, back to io_apic interrupt routing */
 try_legacy:
	ioa->msix_enable = 0;
	ioa->reply_queue_count = 1;

	r = pci_alloc_irq_vectors(ioa->pdev, 1, 1, PCI_IRQ_LEGACY);
	log_init(ioa, "try to execute pci_alloc_irq_vector(legacy)\n");
	if (r < 0) {
		log_error(ioa,
			"pci_alloc_irq_vector(legacy) failed: r=%d\n", r);
		return -EFAULT;
	} else {
		ioa->total_irq = 1;
		r = _base_request_irq(ioa, 0);
		if (r) {
			pci_free_irq_vectors(ioa->pdev);
			return r;
		}
	}
	ioa->hst2dr_var.intr_enabled = 1;

	return 0;
}

/**
 * hst2dr_base_unmap_resources - free controller resources
 * @ioa: per adapter object
 */
static void
hst2dr_base_unmap_resources(struct HST2DR_ADAPTER *ioa)
{
	struct pci_dev *pdev = ioa->pdev;

	_base_free_irq(ioa);
	_base_disable_msix(ioa);


	if (ioa->chip_phys) {
		iounmap(ioa->chip);
		ioa->chip_phys = 0;
	}

	if (pci_is_enabled(pdev)) {
		pci_release_selected_regions(ioa->pdev, ioa->bars);
		pci_disable_device(pdev);
	}
}

/**
 * hst2dr_base_map_resources - map in controller resources (io/irq/memap)
 * @ioa: per adapter object
 *
 * Returns 0 for success, non-zero for failure.
 */
int
hst2dr_base_map_resources(struct HST2DR_ADAPTER *ioa)
{
	struct pci_dev *pdev = ioa->pdev;
	u32 memap_sz;
	u32 pio_sz;
	int i, r = 0;
	u64 pio_chip = 0;
	u64 chip_phys = 0;
	struct adapter_reply_queue *reply_q;

	ioa->bars = pci_select_bars(pdev, IORESOURCE_MEM);
	if (pci_enable_device_mem(pdev)) {
		log_warn(ioa, "pci_enable_device_mem: failed\n");
		ioa->bars = 0;
		return -ENODEV;
	}

	if (pci_request_selected_regions(pdev, ioa->bars,
		ioa->driver_name)) {
		log_warn(ioa, "pci_request_selected_regions: failed\n");
		ioa->bars = 0;
		r = -ENODEV;
		goto out_fail;
	}

	pci_set_master(pdev);


	if (_base_config_dma_addressing(ioa, pdev) != 0) {
		log_warn(ioa, "no suitable DMA mask for %s\n",
			pci_name(pdev));
		r = -ENODEV;
		goto out_fail;
	}

	for (i = 0, memap_sz = 0, pio_sz = 0; (i < DEVICE_COUNT_RESOURCE) &&
			(!memap_sz || !pio_sz); i++) {
		if (pci_resource_flags(pdev, i) & IORESOURCE_IO) {
			if (pio_sz)
				continue;
			pio_chip = (u64)pci_resource_start(pdev, i);
			pio_sz = pci_resource_len(pdev, i);
		} else if (pci_resource_flags(pdev, i) & IORESOURCE_MEM) {
			if (memap_sz)
				continue;
			ioa->chip_phys = pci_resource_start(pdev, i);
			chip_phys = (u64)ioa->chip_phys;
			memap_sz = pci_resource_len(pdev, i);
			ioa->chip = ioremap(ioa->chip_phys, memap_sz);
		}
	}

	if (ioa->chip == NULL) {
		log_error(ioa, "%s %s",
			"unable to map adapter memory!",
			"or resource not found\n");
		r = -EINVAL;
		goto out_fail;
	}

	r = hst2dr_init_nvme_device_and_admin_queue_hal_api(ioa);
	if (r) {
		log_error(ioa, "init nvme queue failed!\n");
		goto out_fail;
	}
	_base_mask_interrupts(ioa);
	r = _base_get_ioa_info(ioa);
	if (r) {
		log_error(ioa, "_base_get_ioa_info failed!\n");
		goto out_fail;
	}

	r = _base_enable_msix(ioa);
	if (r) {
		log_error(ioa, "execute base_enable_msix failed: %d\n", r);
		goto out_fail;
	}

	list_for_each_entry(reply_q, &ioa->reply_queue_list, list)
		log_init(ioa, "%s %s: IRQ %d\n",
			reply_q->name,
			((ioa->msix_enable) ? "PCI-MSI-X enabled" :
			"IO-APIC enabled"),
			pci_irq_vector(ioa->pdev,
			reply_q->msix_index));

	log_init(ioa, "iomem(0x%016llx), mapped(0x%p), size(%d)\n",
		(unsigned long long)chip_phys, ioa->chip, memap_sz);
	log_init(ioa, "ioport(0x%016llx), size(%d)\n",
		(unsigned long long)pio_chip, pio_sz);

	/* Save PCI configuration state for recovery from PCI AER/EEH errors */
	pci_save_state(pdev);
	return 0;

 out_fail:
	hst2dr_base_unmap_resources(ioa);
	return r;
}

/**
 * hst2dr_base_get_msg_frame - obtain request mf pointer
 * @ioa: per adapter object
 * @host_tag_id: request message index(host_tag_id zero is invalid)
 *
 * Returns virt pointer to message frame.
 */
void *
hst2dr_base_get_msg_frame(struct HST2DR_ADAPTER *ioa, u16 host_tag_id)
{
	return (void *)(ioa->request + (host_tag_id * ioa->request_sz));
}

/**
 * hst2dr_base_get_sense_buffer - obtain a sense buffer virt addr
 * @ioa: per adapter object
 * @host_tag_id: request message index
 *
 * Returns virt pointer to sense buffer.
 */
void *
hst2dr_base_get_sense_buffer(struct HST2DR_ADAPTER *ioa, u16 sense_id)
{
	if (sense_id >= ioa->sense_depth)
		return NULL;
	return (void *)(ioa->sense + (sense_id * SCSI_SENSE_BUFFERSIZE));
}

/**
 * hst2dr_base_get_sense_buffer_dma - obtain a sense buffer dma addr
 * @ioa: per adapter object
 * @host_tag_id: request message index
 *
 * Returns phys pointer to the low 32bit address of the sense buffer.
 */
__le32
hst2dr_base_get_sense_buffer_dma(struct HST2DR_ADAPTER *ioa, u16 sense_id)
{
	return cpu_to_le32(ioa->sense_dma + (sense_id *
		SCSI_SENSE_BUFFERSIZE));
}

/**
 * hst2dr_base_get_reply_virt_addr - obtain reply frames virt address
 * @ioa: per adapter object
 * @reply_id: reply index
 *
 * get reply virt address for index reply_id.
 */
void *
hst2dr_base_get_reply_virt_addr(struct HST2DR_ADAPTER *ioa, u16 reply_id)
{
	if ((reply_id == INVALID_REPLY) ||
			(reply_id >= ioa->reply_queue_depth)) {
		if (reply_id != INVALID_REPLY)
			pr_err(HST2DR_FMT
				"error reply id %x\n", ioa->name, reply_id);
		return NULL;
	}
	return ioa->reply + (reply_id * ioa->reply_sz);
}

static inline u8
_base_get_msix_index(struct HST2DR_ADAPTER *ioa)
{
	return ioa->cpu_msix_table[raw_smp_processor_id()];
}

/**
 * hst2dr_base_get_host_tag_id - obtain a free host_tag_id from internal queue
 * @ioa: per adapter object
 * @cb_idx: callback index
 *
 * Returns host_tag_id (zero is invalid)
 */
u16
hst2dr_base_get_host_tag_id(struct HST2DR_ADAPTER *ioa, u8 cb_idx)
{
	unsigned long flags;
	struct request_tracker *request;
	u16 host_tag_id;

	spin_lock_irqsave(&ioa->scsi_lookup_lock, flags);
	if (list_empty(&ioa->internal_free_list)) {
		spin_unlock_irqrestore(&ioa->scsi_lookup_lock, flags);
		log_error(ioa, "%s: host_tag_id not available\n",
			__func__);
		return NO_HOST_TAG_ID;
	}

	request = list_entry(ioa->internal_free_list.next,
		struct request_tracker, tracker_list);

	list_del_init(&request->tracker_list);
	spin_unlock_irqrestore(&ioa->scsi_lookup_lock, flags);

	request->cb_idx = cb_idx;
	host_tag_id = request->host_tag_id;

	return host_tag_id;
}

/**
 * hst2dr_base_get_host_tag_id_scsiio - obtain a free host_tag_id from scsiio
 *					queue
 * @ioa: per adapter object
 * @cb_idx: callback index
 * @scmd: pointer to scsi command object
 *
 * Returns host_tag_id (zero is invalid)
 */
u16
hst2dr_base_get_host_tag_id_scsiio(struct HST2DR_ADAPTER *ioa, u8 cb_idx,
	struct scsi_cmnd *scmd)
{
	struct scsiio_tracker *request = scsi_cmd_priv(scmd);
	unsigned int tag, unique_tag;
	u16 host_tag_id;
	u16 hwq;

	unique_tag = blk_mq_unique_tag(scsi_cmd_to_rq(scmd));
	tag = blk_mq_unique_tag_to_tag(unique_tag);
	hwq = blk_mq_unique_tag_to_hwq(unique_tag);
	host_tag_id = tag + hwq * ioa->host_tag_id_offset[hwq];
	request->cb_idx = cb_idx;
	request->msix_io = _base_get_msix_index(ioa);
	request->host_tag_id = host_tag_id;
	request->direct_io = MAGIC_NUMBER;
	ioa->tag_queue_number[host_tag_id] = hwq;
	INIT_LIST_HEAD(&request->tracker_list);
	return host_tag_id;
}

static void
_base_recovery_check(struct HST2DR_ADAPTER *ioa)
{
	/*
	 * See _wait_for_commands_to_complete() call with regards to this code.
	 */
	if (ioa->shost_recovery && ioa->pending_io_count) {

		ioa->pending_io_count =  scsi_host_busy(ioa->shost);
		if (ioa->pending_io_count == 0)
			wake_up(&ioa->reset_wq);
	}
}

void hst2dr_base_clear_st(struct HST2DR_ADAPTER *ioa,
			   struct scsiio_tracker *st)
{
	st->cb_idx = INVALID_CB_INDEX;
	st->direct_io = 0;
	atomic_set(&ioa->chain_lookup[st->host_tag_id].chain_offset, 0);
	st->host_tag_id = NO_HOST_TAG_ID;
}

/**
 * hst2dr_base_free_host_tag_id - put host_tag_id back on free_list
 * @ioa: per adapter object
 * @host_tag_id: request message index
 *
 * Return nothing.
 */
void
hst2dr_base_free_host_tag_id(struct HST2DR_ADAPTER *ioa, u16 host_tag_id)
{
	unsigned long flags;
	int i;

	if (host_tag_id < ioa->scsiio_depth - INTERNAL_SCSIIO_CMDS_COUNT) {
		struct scsiio_tracker *st;

		st = _get_st_from_host_tag_id(ioa, host_tag_id);
		if (!st || st->host_tag_id == NO_HOST_TAG_ID ||
				st->direct_io != MAGIC_NUMBER) {
			log_error(ioa,
				"failed to free host_tag_id:%d\n", host_tag_id);
			_base_recovery_check(ioa);
			return;
		}
		ioa->tag_queue_number[host_tag_id] = 0xffff;
		hst2dr_base_clear_st(ioa, st);
		_base_recovery_check(ioa);
		return;
	} else if (host_tag_id < ioa->scsiio_depth)
		return;

	if (host_tag_id < HOST_TAG_ID_POLL) {
		/* internal queue */
		spin_lock_irqsave(&ioa->scsi_lookup_lock, flags);
		i = host_tag_id - ioa->internal_host_tag_id;
		ioa->internal_lookup[i].cb_idx = INVALID_CB_INDEX;
		if (list_empty(&ioa->internal_lookup[i].tracker_list))
			list_add(&ioa->internal_lookup[i].tracker_list,
				&ioa->internal_free_list);
		spin_unlock_irqrestore(&ioa->scsi_lookup_lock, flags);
	}
}

/**
 * _base_display_ioa_capabilities - Disply IOA's capabilities.
 * @ioa: per adapter object
 *
 * Return nothing.
 */
static void
_base_display_ioa_capabilities(struct HST2DR_ADAPTER *ioa)
{
	int i = 0;
	char desc[16];

	char info[256] = {0};

	strncpy(desc, ioa->vendor.chip_name, 16);
	pr_info("%s: FWVersion(%02x.%02x.%02x.%02x), chip_revision(0x%02x)\n",
		desc,
		(ioa->info.fw_version.dword & 0xFF000000) >> 24,
		(ioa->info.fw_version.dword & 0x00FF0000) >> 16,
		(ioa->info.fw_version.dword & 0x0000FF00) >> 8,
		ioa->info.fw_version.dword & 0x000000FF,
		ioa->pdev->revision);
	snprintf(info, sizeof(info), HST2DR_FMT "Protocol=(", ioa->name);

	if (ioa->info.protocol_flags & SSI2_IOA_INFO_PROTOCOL_SCSI_INITIATOR) {
		snprintf(&info[strlen(info)],
			sizeof(info) - strlen(info), "Initiator");
		i++;
	}

	if (ioa->info.protocol_flags & SSI2_IOA_INFO_PROTOCOL_SCSI_TARGET) {
		snprintf(&info[strlen(info)],
			sizeof(info) - strlen(info), "%sTarget", i ? "," : "");
		i++;
	}
	pr_info("%s)\n", info);

}

/**
 * hst2dr_base_update_missing_delay - change the missing delay timers
 * @ioa: per adapter object
 * @device_missing_delay: amount of time till device is reported missing
 * @io_missing_delay: interval IO is returned when there is a missing device
 *
 * Return nothing.
 *
 * Passed on the command line, this function will modify the device missing
 * delay, as well as the io missing delay. This should be called at driver
 * load time.
 */
void
hst2dr_base_update_missing_delay(struct HST2DR_ADAPTER *ioa,
	u16 device_missing_delay, u8 io_missing_delay)
{
	u16 dmd, dmd_new, dmd_original;
	u8 io_missing_delay_original;
	u16 sz;
	SSI2_INQUIRY_SAS_UNIT1 *sas_unit1 = NULL;
	SSI2_INQUIRY_PAGE_REPLY ssi_reply;
	u8 num_phys = 0;
	u16 ioa_status;

	hst2dr_cfg_get_number_hba_phys(ioa, &num_phys);
	if (!num_phys)
		return;

	sz = offsetof(SSI2_INQUIRY_SAS_UNIT1, PhyData) + (num_phys *
		sizeof(SSI2_SAS_UNIT1_PHY_DATA));
	sas_unit1 = kzalloc(sz, GFP_KERNEL);
	if (!sas_unit1) {
		log_error(ioa, "allocate %d bytes failed at %s:%d/%s()!\n",
			sz, __FILE__, __LINE__, __func__);
		goto out;
	}
	if ((hst2dr_cfg_get_sas_unit1(ioa, &ssi_reply,
			sas_unit1, sz))) {
		log_error(ioa,
			"hst2dr_cfg_get_sas_unit1 failed at %s:%d/%s()!\n",
			__FILE__, __LINE__, __func__);
		goto out;
	}
	ioa_status = le16_to_cpu(ssi_reply.status) &
		SSI2_IOASTATUS_MASK;
	if (ioa_status != SSI2_IOASTATUS_SUCCESS) {
		log_error(ioa,
			"ssi_reply status %d not equal success at %s:%d/%s()!\n",
			ioa_status, __FILE__, __LINE__, __func__);
		goto out;
	}

	/* device missing delay */
	dmd = sas_unit1->report_dev_missing_delay;
	if (dmd & SSI2_SASIOUNIT1_REPORT_MISSING_UNIT_16)
		dmd = (dmd & SSI2_SASIOUNIT1_REPORT_MISSING_TIMEOUT_MASK) * 16;
	else
		dmd = dmd & SSI2_SASIOUNIT1_REPORT_MISSING_TIMEOUT_MASK;
	dmd_original = dmd;
	if (device_missing_delay > 0x7F) {
		dmd = (device_missing_delay > 0x7F0) ? 0x7F0 :
			device_missing_delay;
		dmd = dmd / 16;
		dmd |= SSI2_SASIOUNIT1_REPORT_MISSING_UNIT_16;
	} else
		dmd = device_missing_delay;
	sas_unit1->report_dev_missing_delay = dmd;

	/* io missing delay */
	io_missing_delay_original = sas_unit1->io_dev_missing_delay;
	sas_unit1->io_dev_missing_delay = io_missing_delay;

	if (!hst2dr_cfg_set_sas_unit1(ioa, &ssi_reply, sas_unit1,
			sz)) {
		if (dmd & SSI2_SASIOUNIT1_REPORT_MISSING_UNIT_16)
			dmd_new = (dmd &
				SSI2_SASIOUNIT1_REPORT_MISSING_TIMEOUT_MASK) *
				16;
		else
			dmd_new =
				dmd &
				SSI2_SASIOUNIT1_REPORT_MISSING_TIMEOUT_MASK;
		log_event(ioa, "device_missing_delay: old(%d), new(%d)\n",
			dmd_original, dmd_new);
		log_event(ioa, "ioa_missing_delay: old(%d), new(%d)\n",
			io_missing_delay_original,
			io_missing_delay);
		ioa->device_missing_delay = dmd_new;
		ioa->io_missing_delay = io_missing_delay;
	}

out:
	kfree(sas_unit1);
}
/**
 * _base_static_config_pages - static start of day config pages
 * @ioa: per adapter object
 *
 * Return nothing.
 */
static void
_base_static_config_pages(struct HST2DR_ADAPTER *ioa)
{
	SSI2_INQUIRY_PAGE_REPLY ssi_reply;

	hst2dr_cfg_get_vendor(ioa, &ssi_reply, &ioa->vendor);
	log_config(ioa, "%s %s, %s %s, %s %s, %s %s, %s %s\n",
		"chip_name:", ioa->vendor.chip_name,
		"chiprivision:", ioa->vendor.chip_revision,
		"board_name:", ioa->vendor.board_name,
		"module_id:", ioa->vendor.module_id,
		"serial_number:", ioa->vendor.serial_number);

	hst2dr_cfg_get_ioa01(ioa, &ssi_reply, &ioa->ioa01);
	_base_display_ioa_capabilities(ioa);

}

/**
 * _base_release_memory_pools - release memory
 * @ioa: per adapter object
 *
 * Free memory allocated from _base_allocate_memory_pools.
 *
 * Return nothing.
 */
static void
_base_release_memory_pools(struct HST2DR_ADAPTER *ioa)
{
	int i = 0, j = 0;
	struct chain_segment_t *cs;

	if (ioa->request) {
		dma_free_coherent(&ioa->pdev->dev, ioa->request_dma_sz,
			ioa->request,  ioa->request_dma);
		log_exit(ioa,
			"request_pool(0x%p): free\n",
			ioa->request);
		ioa->request = NULL;
	}

	if (ioa->sense) {
		dma_pool_free(ioa->sense_dma_pool, ioa->sense, ioa->sense_dma);
		dma_pool_destroy(ioa->sense_dma_pool);
		log_exit(ioa,
			"sense_pool(0x%p): free\n",
			ioa->sense);
		ioa->sense = NULL;
	}

	if (ioa->reply) {
		dma_pool_free(ioa->reply_dma_pool, ioa->reply, ioa->reply_dma);
		dma_pool_destroy(ioa->reply_dma_pool);
		log_exit(ioa,
			"reply_pool(0x%p): free\n",
			ioa->reply);
		ioa->reply = NULL;
	}

	if (ioa->reply_free) {
		dma_pool_free(ioa->reply_free_dma_pool, ioa->reply_free,
			ioa->reply_free_dma);
		dma_pool_destroy(ioa->reply_free_dma_pool);
		log_exit(ioa,
			"reply_free_pool(0x%p): free\n",
			ioa->reply_free);
		ioa->reply_free = NULL;
	}

	if (ioa->config_page) {
		log_exit(ioa,
			"config_page(0x%p): free\n",
			ioa->config_page);
		dma_free_coherent(&ioa->pdev->dev, ioa->config_page_sz,
			ioa->config_page, ioa->config_page_dma);
		ioa->config_page = NULL;
	}

	if (ioa->scsi_lookup) {
		free_pages((ulong)ioa->scsi_lookup, ioa->scsi_lookup_pages);
		ioa->scsi_lookup = NULL;
	}
	if (ioa->tag_queue_number) {
		kfree(ioa->tag_queue_number);
		ioa->tag_queue_number = NULL;
	}
	if (ioa->internal_lookup) {
		kfree(ioa->internal_lookup);
		ioa->internal_lookup = NULL;
	}
	if (ioa->chain_lookup) {
		for (i = 0; i < ioa->scsiio_depth; i++) {
			for (j = 0; j < ioa->chains_needed_per_io; j++) {
				cs = &ioa->chain_lookup[i].chains_per_host_tag_id[j];
				if (cs && cs->chain_buffer)
					dma_pool_free(ioa->chain_dma_pool,
						cs->chain_buffer,
						cs->chain_buffer_dma);
			}
			kfree(ioa->chain_lookup[i].chains_per_host_tag_id);
		}
		dma_pool_destroy(ioa->chain_dma_pool);
		kfree(ioa->chain_lookup);
		ioa->chain_lookup = NULL;
	}
}
/**
 * _base_allocate_memory_request_dma - allocate request cmd dma
 * @ioa: per adapter object
 *
 * Returns 0 success, anything else error
 */
int
_base_allocate_memory_request_dma(struct HST2DR_ADAPTER *ioa)
{
	u32	sz = SQ_SIZE(MAX_HW_QUEUE_SIZE);

	if (ioa->request != NULL)
		return 0;
	ioa->request_dma_sz = sz;
	ioa->request_sz = 128;
	ioa->request = dma_alloc_coherent(&ioa->pdev->dev,
		sz, &ioa->request_dma, GFP_KERNEL);
	if (!ioa->request) {
		log_error(ioa, "%s failed: hba_depth(%d)\n",
			"request pool: dma_alloc_conherent",
			MAX_HW_QUEUE_SIZE);
			return -ENOMEM;
	}
	return 0;
}
/**
 * _base_allocate_memory_pools - allocate start of day memory pools
 * @ioa: per adapter object
 *
 * Returns 0 success, anything else error
 */
static int
_base_allocate_memory_pools(struct HST2DR_ADAPTER *ioa)
{
	struct hst2dr_info *info;
	u16 max_sge_elements;
	u16 chains_needed_per_io;
	u32 sz, total_sz;
	u32 retry_sz;

	unsigned short sg_tablesize;
	u16 sge_size;
	int i, j;

	retry_sz = 0;
	info = &ioa->info;

	/* command line tunables for max sgl entries */
	if (max_sgl_entries != -1)
		sg_tablesize = max_sgl_entries;
	else
		sg_tablesize = HST2DR_SG_DEPTH;

	/* max sgl entries <= HST2DR_KDUMP_MIN_PHYS_SEGMENTS in KDUMP mode */
	if (reset_devices)
		sg_tablesize = min_t(unsigned short, sg_tablesize,
			HST2DR_KDUMP_MIN_PHYS_SEGMENTS);

	if (sg_tablesize < HST2DR_MIN_PHYS_SEGMENTS)
		sg_tablesize = HST2DR_MIN_PHYS_SEGMENTS;
	else if (sg_tablesize > HST2DR_MAX_PHYS_SEGMENTS) {
		sg_tablesize = min_t(unsigned short, sg_tablesize,
				SG_MAX_SEGMENTS);
		log_warn(ioa, "%s (%u) %s(%u)\n",
			"sg_tablesize",
			sg_tablesize,
			"is bigger than kernel defined SG_CHUNK_SIZE",
			HST2DR_MAX_PHYS_SEGMENTS);
	}
	ioa->shost->sg_tablesize = sg_tablesize;

	ioa->internal_depth = ADMIN_QUEUE_SIZE;

	ioa->hba_queue_depth =  MAX_HBA_QUEUE_DEPTH_SAGE;
	/* request frame size */
	ioa->request_sz = info->ioa_request_frame_size * 4;
	/* reply frame size */
	ioa->reply_sz = info->reply_frame_size * 4;
	/* chain blk size */
	if (info->ioa_max_chain_segment_size)
		ioa->chain_segment_sz =
				info->ioa_max_chain_segment_size *
				MAX_CHAIN_ELEMT_SZ;
	else
	/* set to 128 bytes size if IOAMaxChainSegmentSize is zero */
		ioa->chain_segment_sz = DEFAULT_NUM_FWCHAIN_ELEMTS *
					MAX_CHAIN_ELEMT_SZ;

	/* calculate the max scatter element size */
	sge_size = max_t(u16, ioa->sge_size, ioa->sge_size_ieee);

 retry_allocation:
	total_sz = 0;
	/* calculate number of sg elements left over in the 1st frame */
	max_sge_elements = ioa->request_sz - offsetof(SSI2_SCSI_REQUEST, sgl);
	ioa->max_sges_in_main_message = max_sge_elements/sge_size;

	/* now do the same for a chain buffer */
	max_sge_elements = ioa->chain_segment_sz - sge_size;
	ioa->max_sges_in_chain_message = max_sge_elements/sge_size;

	/*
	 *  HST2DR_SG_DEPTH = CONFIG__MAX_SGE
	 */
	chains_needed_per_io = ((ioa->shost->sg_tablesize -
		ioa->max_sges_in_main_message) /
		ioa->max_sges_in_chain_message) + 1;
	if (info->max_chain_depth < 0x80)
		info->max_chain_depth = 0x80;
	if (chains_needed_per_io > info->max_chain_depth) {
		chains_needed_per_io = info->max_chain_depth;
		ioa->shost->sg_tablesize = min_t(u16,
		ioa->max_sges_in_main_message + (ioa->max_sges_in_chain_message
		* chains_needed_per_io), ioa->shost->sg_tablesize);
	}
	ioa->chains_needed_per_io = chains_needed_per_io;
	log_init(ioa,
		"chain_segment_size:%x, max_sges_in_chain_message:%x, max_chain_depth:%x, sg_tablesize:%x\n",
		ioa->chain_segment_sz,
		ioa->max_sges_in_chain_message,
		info->max_chain_depth,
		ioa->shost->sg_tablesize);

	ioa->reply_post_queue_depth =
		info->max_reply_descriptor_post_queue_depth;
	if (ioa->reply_post_queue_depth < 0xc0)
		ioa->reply_post_queue_depth = 0xc0;
	if (ioa->reply_post_queue_depth > MAX_HW_QUEUE_SIZE)
		ioa->reply_post_queue_depth = MAX_HW_QUEUE_SIZE;
	ioa->hba_queue_depth = ioa->reply_post_queue_depth;
	ioa->reply_queue_depth = ioa->hba_queue_depth;
	switch (ioa->chip_version) {
	case VS_V2M2:
		if (ioa->reply_queue_depth > 0x400)
			ioa->reply_queue_depth = 0x400;
		break;
	case VS_V2N1:
		if (ioa->reply_queue_depth > 0x1000)
			ioa->reply_queue_depth = 0x1000;
		break;
	default:
		break;
	}

	log_init(ioa,
		"reply_queue_depth:%d, hba_queue_depth:%d, reply_post_queue_depth:%d\n",
		ioa->reply_queue_depth,
		ioa->hba_queue_depth,
		ioa->reply_post_queue_depth);
	if (ioa->dma_mask == 64) {
		if (_base_change_consistent_dma_mask(ioa, ioa->pdev) != 0) {
			log_warn(ioa, "no suitable consistent DMA mask for %s\n",
				pci_name(ioa->pdev));
			goto out;
		}
	}

	ioa->scsiio_depth = ioa->hba_queue_depth - ioa->internal_depth;
	ioa->sense_depth = min_t(u16, ioa->info.max_sense, ioa->scsiio_depth);
	switch (ioa->chip_version) {
	case VS_V2M2:
		if (ioa->sense_depth > 0x400)
			ioa->sense_depth = 0x400;
		break;
	case VS_V2N1:
		if (ioa->sense_depth > 0x1000)
			ioa->sense_depth = 0x1000;
		break;
	default:
		break;
	}

	/* set the scsi host can_queue depth
	 * with some internal commands that could be outstanding
	 */
	ioa->shost->can_queue = ioa->scsiio_depth - INTERNAL_SCSIIO_CMDS_COUNT;
	log_init(ioa, "can_queue: %d to BLK layer\n", ioa->shost->can_queue);

	/* contiguous pool for request and chains, 16 byte align, one extra "
	 * "frame for host_tag_id = NO_HOST_TAG_ID
	 */
	ioa->chain_depth = ioa->chains_needed_per_io * ioa->scsiio_depth;
	sz = ((ioa->scsiio_depth + 1) * ioa->request_sz);


	/* internal queue */
	sz += (ioa->internal_depth * ioa->request_sz);
	if ((ioa->q_mode == Q_MODE_2) || (ioa->q_mode == Q_MODE_4)) {
		ioa->host_tag_id_poll =
			ioa->scsiio_depth + ADMIN_QUEUE_SIZE - 1;
		ioa->request_dma_sz = sz;
		if (ioa->request == NULL) {
			ioa->request = dma_alloc_coherent(&ioa->pdev->dev,
				sz, &ioa->request_dma, GFP_KERNEL);
			if (!ioa->request) {
				log_error(ioa,
					"%s(%d), %s(%d), frame_sz(%d), total(%d kB)\n",
					"request pool: dma_alloc_coherent failed: hba_depth",
					ioa->hba_queue_depth,
					"chains_per_io",
					ioa->chains_needed_per_io,
					ioa->request_sz,
					sz / 1024);
				if (ioa->scsiio_depth < HST2DR_SAS_QUEUE_DEPTH)
					goto out;
				retry_sz = 64;
				ioa->hba_queue_depth -= retry_sz;
				_base_release_memory_pools(ioa);
				goto retry_allocation;
			}
		}
	} else
		retry_sz = 0;
	if (retry_sz)
		log_error(ioa, "%s(%d), %s(%d), frame_sz(%d), total(%d kb)\n",
			"request pool: dma_alloc_coherent succeed: hba_depth",
			ioa->hba_queue_depth,
			"chains_per_io",
			ioa->chains_needed_per_io,
			ioa->request_sz, sz / 1024);


	/* internal queue */
	if (ioa->q_mode == Q_MODE_3) {
		ioa->internal = ioa->request +
			(IO_QUEUE_SIZE * ioa->request_sz);
		ioa->internal_dma = ioa->request_dma +
			(IO_QUEUE_SIZE * ioa->request_sz);
	} else {
		ioa->internal = ioa->request +
			(ioa->scsiio_depth * ioa->request_sz);
		ioa->internal_dma = ioa->request_dma +
			(ioa->scsiio_depth * ioa->request_sz);
	}

	log_init(ioa,
		"%s 0x%p, %s %d, %s %d, %s %d KB, %s 0x%llx\n",
		"request pool:", ioa->request,
		"depth:", ioa->hba_queue_depth,
		"frame_size:", ioa->request_sz,
		"pool_size:",
		(ioa->hba_queue_depth * ioa->request_sz) / 1024,
		"request pool dma:",
		(unsigned long long)ioa->request_dma);
	total_sz += sz;

	sz = ioa->scsiio_depth * sizeof(struct scsiio_tracker);
	ioa->scsi_lookup_pages = get_order(sz);
	ioa->scsi_lookup = (struct scsiio_tracker *)__get_free_pages(
		GFP_KERNEL, ioa->scsi_lookup_pages);
	if (!ioa->scsi_lookup) {
		log_error(ioa, "scsi_lookup: get_free_pages failed, sz(%d)\n",
			(int)sz);
		goto out;
	}

	log_init(ioa, "scsiio(0x%p): depth(%d)\n",
		ioa->request, ioa->scsiio_depth);
	ioa->chain_depth = min_t(u32, ioa->chain_depth, MAX_CHAIN_DEPTH);

	sz = ioa->scsiio_depth * sizeof(struct chain_lookup);
	ioa->chain_lookup = kzalloc(sz, GFP_KERNEL);
	if (!ioa->chain_lookup) {
		log_error(ioa, "chain_lookup: __get_free_pages failed\n");
		goto out;
	}

	sz = ioa->chains_needed_per_io * sizeof(struct chain_segment_t);
	for (i = 0; i < ioa->scsiio_depth; i++) {
		ioa->chain_lookup[i].chains_per_host_tag_id =
			kzalloc(sz, GFP_KERNEL);
		if (!ioa->chain_lookup[i].chains_per_host_tag_id) {
			log_error(ioa, "chain_lookup: kzalloc failed\n");
			goto out;
		}
	}

	ioa->chain_dma_pool = dma_pool_create("chain pool", &ioa->pdev->dev,
		ioa->chain_segment_sz, 0x1000, 0);
	if (!ioa->chain_dma_pool) {
		log_error(ioa, "chain_dma_pool: dma_pool_create failed\n");
		goto out;
	}
	for (i = 0; i < ioa->scsiio_depth; i++) {
		for (j = 0; j < ioa->chains_needed_per_io; j++) {
			ioa->chain_lookup[i].chains_per_host_tag_id[j].chain_buffer
				= dma_pool_alloc(ioa->chain_dma_pool,
						GFP_KERNEL,
				&ioa->chain_lookup[i].chains_per_host_tag_id[j].chain_buffer_dma);
			if (!ioa->chain_lookup[i].chains_per_host_tag_id[j].chain_buffer) {
				ioa->chain_depth = i;
				goto out;
			}
		}
		total_sz += ioa->chain_segment_sz;
	}

	log_init(ioa,
		"chain pool depth: %d, frame_size: %d, pool_size: %d KB\n",
		ioa->chain_depth, ioa->chain_segment_sz,
		((ioa->chain_depth *  ioa->chain_segment_sz)) / 1024);

	/* initialize internal queue host_tag_id's */
	ioa->internal_lookup = kcalloc(ioa->internal_depth,
		sizeof(struct request_tracker), GFP_KERNEL);
	if (!ioa->internal_lookup) {
		log_error(ioa, "internal_lookup: kcalloc failed\n");
		goto out;
	}
	if (ioa->q_mode == Q_MODE_3) {
		if (ioa->chip_version == VS_V2N1)
			ioa->internal_host_tag_id = IO_QUEUE_SIZE + 3;
		else
			ioa->internal_host_tag_id = IO_QUEUE_SIZE;

	} else
		ioa->internal_host_tag_id = ioa->scsiio_depth;

	log_init(ioa,
		"internal: 0x%p depth: %d, internal_host_tag_id: %d\n",
		ioa->internal,
		ioa->internal_depth, ioa->internal_host_tag_id);

	/* sense buffers, 4 byte align */
	sz = ioa->scsiio_depth * SCSI_SENSE_BUFFERSIZE;
	ioa->sense_dma_pool = dma_pool_create("sense pool",
			&ioa->pdev->dev, sz, 0x1000, 0);
	if (!ioa->sense_dma_pool) {
		log_error(ioa, "sense pool: dma_pool_create failed\n");
		goto out;
	}
	ioa->sense = dma_pool_alloc(ioa->sense_dma_pool, GFP_KERNEL,
		&ioa->sense_dma);
	if (!ioa->sense) {
		log_error(ioa, "sense pool: dma_pool_alloc failed\n");
		goto out;
	}
	log_init(ioa,
		"%s 0x%p, %s %d, %s %d, %s %d KB %s 0x%llx\n",
		"sense pool:", ioa->sense,
		"depth:", ioa->scsiio_depth,
		"element_size:", SCSI_SENSE_BUFFERSIZE,
		"pool_size:", sz / 1024,
		"sense_dma:", (unsigned long long)ioa->sense_dma);
	total_sz += sz;

	ioa->tag_queue_number =
		kcalloc(ioa->scsiio_depth, sizeof(u16), GFP_KERNEL);
	if (!ioa->tag_queue_number) {
		log_error(ioa, "queue tag allocate failed\n");
		goto out;
	}

	/* reply pool, 4 byte align */
	sz = ioa->reply_queue_depth * ioa->reply_sz;
	ioa->reply_dma_pool = dma_pool_create("reply pool",
			&ioa->pdev->dev, sz, 0x1000, 0);
	if (!ioa->reply_dma_pool) {
		log_error(ioa, "reply pool: dma_pool_create failed\n");
		goto out;
	}
	ioa->reply = dma_pool_alloc(ioa->reply_dma_pool, GFP_KERNEL,
		&ioa->reply_dma);
	if (!ioa->reply) {
		log_error(ioa, "reply pool: dma_pool_alloc failed\n");
		goto out;
	}
	ioa->reply_dma_min_address = (u32)(ioa->reply_dma);
	ioa->reply_dma_max_address = (u32)(ioa->reply_dma) + sz;
	log_init(ioa,
		"%s 0x%p, %s %d, %s %d, %s %d KB, %s 0x%llx\n",
		"reply pool:", ioa->reply,
		"depth:", ioa->reply_queue_depth,
		"frame_size:", ioa->reply_sz,
		"pool_size:", sz/1024,
		"reply_dma:", (unsigned long long)ioa->reply_dma);
	total_sz += sz;

	/* reply free queue, 16 byte align */
	sz = ioa->reply_queue_depth * 4;
	ioa->reply_free_dma_pool = dma_pool_create("reply_free pool",
		&ioa->pdev->dev, sz, 0x1000, 0);
	if (!ioa->reply_free_dma_pool) {
		log_error(ioa, "reply_free pool: dma_pool_create failed\n");
		goto out;
	}
	ioa->reply_free = dma_pool_alloc(ioa->reply_free_dma_pool, GFP_KERNEL,
		&ioa->reply_free_dma);
	if (!ioa->reply_free) {
		log_error(ioa, "reply_free pool: dma_pool_alloc failed\n");
		goto out;
	}
	memset(ioa->reply_free, 0, sz);
	log_init(ioa, "%s 0x%p, %s %d, %s %d, %s %d KB, %s 0x%llx\n",
		"reply_free pool:", ioa->reply_free,
		"depth:", ioa->reply_queue_depth,
		"element_size:", 4,
		"pool_size:", sz / 1024,
		"reply_free_dma:", (unsigned long long)ioa->reply_free_dma);
	total_sz += sz;

	ioa->config_page_sz = 512;
	ioa->config_page = dma_alloc_coherent(&ioa->pdev->dev,
		ioa->config_page_sz, &ioa->config_page_dma, GFP_KERNEL);
	if (!ioa->config_page) {
		log_error(ioa, "config page: dma_pool_alloc failed\n");
		goto out;
	}
	log_init(ioa,
		"config page: 0x%p size: %d config_page_dma: 0x%llx\n",
		ioa->config_page, ioa->config_page_sz,
		(unsigned long long)ioa->config_page_dma);
	total_sz += ioa->config_page_sz;
	log_init(ioa, "chain depth:%x chains per io:%x\n",
		ioa->chain_depth, ioa->chains_needed_per_io);
	log_init(ioa, "Allocated physical memory: size(%d kB)\n",
		total_sz / 1024);
	log_init(ioa, "%s (%d), %s (%d)\n",
			"Current Controller Queue Depth",
			ioa->shost->can_queue,
			"Max Controller Queue Depth",
			info->request_credit);
	log_init(ioa, "Scatter Gather Elements per IO(%d)\n",
		ioa->shost->sg_tablesize);
	return 0;

 out:
	return -ENOMEM;
}

/**
 * hst2dr_base_get_ioastate - Get the current state of a hst2dr adapter.
 * @ioa: Pointer to HST2DR_ADAPTER structure
 * @cooked: Request raw or cooked IOA state
 *
 * Returns all IOA csts register bits if cooked==0, else just the
 * csts bits in SSI_IOA_STATE_MASK.
 */
u32
hst2dr_base_get_ioastate(struct HST2DR_ADAPTER *ioa, int cooked)
{
	u32 s, sc;

	s = hst2dr_read_direct_reg_hal_api(ioa, NVME_REG_CSTS);
	s &= 0x0000003f;
	switch (s & 0x3f) {
	case 0x00:
		break;
	case 0x0c:
		s |= SSI2_IOA_STATE_NEED_RESET;
		break;
	case 0x0d:
		s |= SSI2_IOA_STATE_OPERATIONAL;
		break;
	case 0x01:
		s |= SSI2_IOA_STATE_READY;
		break;
	case 0x2:
		s |= SSI2_IOA_STATE_FAULT;
		break;
	case 0x03:
		s |= (SSI2_IOA_STATE_READY + SSI2_IOA_STATE_FAULT);
		break;
	default:
		s |= SSI2_IOA_STATE_MASK;
		log_error(ioa, "non-operational, CSTS:%x\n", s);
		break;
	}

	sc = s & SSI2_IOA_STATE_MASK;
	return cooked ? sc : s;
}

/**
 * _base_send_ioa_reset - send NSSR reset
 * @ioa: per adapter object
 * @reset_type: currently only supports: SSI2_FUNCTION_IOA_MESSAGE_UNIT_RESET
 * @timeout: timeout in second
 *
 * Returns 0 for success, non-zero for failure.
 */
static int
_base_send_ioa_reset(struct HST2DR_ADAPTER *ioa, u8 reset_type, int timeout)
{
	int r = 0;

	if (reset_type != SSI2_FUNCTION_IOA_MESSAGE_UNIT_RESET) {
		log_error(ioa, "%s: unknown reset_type %d\n",
			__func__, reset_type);
		return -EFAULT;
	}

	log_reset(ioa, "sending message unit reset !\n");

	hst2dr_write_direct_reg_hal_api(ioa,	NVME_REG_NSSR, 0x4E564D65);

	log_reset(ioa, "message unit reset: %s\n",
		((r == 0) ? "SUCCESS" : "FAILED"));
	return r;
}

/**
 * hst2dr_base_sas_iounit_control - send sas iounit control to FW
 * @ioa: per adapter object
 * @ssi_reply: the reply payload from FW
 * @ssi_request: the request payload sent to FW
 *
 * The SAS IO Unit Control Request message allows the host to perform low-level
 * operations, such as resets on the PHYs of the IO Unit, also allows the host
 * to obtain the IOA assigned device handles for a device if it has other
 * identifying information about the device, in addition allows the host to
 * remove IOA resources associated with the device.
 *
 * Returns 0 for success, non-zero for failure.
 */
int
hst2dr_base_sas_iounit_control(struct HST2DR_ADAPTER *ioa,
	SSI2_SAS_UNIT_CONTROL_REPLY *ssi_reply,
	SSI2_SAS_UNIT_CONTROL_REQUEST *ssi_request)
{
	u16 host_tag_id;
	u32 ioa_state;
	bool issue_reset = false;
	int rc;
	u16 wait_state_count;
	hst2dr_command *scmd;

	mutex_lock(&ioa->base_cmds.mutex);

	if (ioa->base_cmds.status != HST2DR_CMD_NOT_USED) {
		log_error(ioa, "%s: base_cmd in use\n",
			__func__);
		rc = -EAGAIN;
		goto out;
	}

	wait_state_count = 0;
	ioa_state = hst2dr_base_get_ioastate(ioa, 1);
	while (ioa_state != SSI2_IOA_STATE_OPERATIONAL) {
		if (wait_state_count++ == 10) {
			log_error(ioa,
				"%s: failed due to ioa not operational\n",
				__func__);
			rc = -EFAULT;
			goto out;
		}
		ssleep(1);
		ioa_state = hst2dr_base_get_ioastate(ioa, 1);
		log_reset(ioa, "%s: waiting for operational state(count=%d)\n",
			__func__, wait_state_count);
	}

	host_tag_id = hst2dr_base_get_host_tag_id(ioa, ioa->base_cb_idx);
	if (host_tag_id == NO_HOST_TAG_ID) {
		log_error(ioa, "%s: failed obtaining a host_tag_id\n",
			__func__);
		rc = -EAGAIN;
		goto out;
	}

	rc = 0;
	ioa->base_cmds.status = HST2DR_CMD_PENDING;
	scmd = hst2dr_base_get_msg_frame(ioa, host_tag_id);
	memset(scmd, 0, sizeof(*scmd));
	ioa->base_cmds.host_tag_id = host_tag_id;
	ssi_request->opcode = SSI2_FUNCTION_SAS_UNIT;
	ssi_request->opflags = cmd_flag_fw_mode_admin;
	ssi_request->host_tag_id = host_tag_id;
	ssi_request->host_flag = hst2dr_cmd_base;

	memcpy(scmd, ssi_request, sizeof(SSI2_SAS_UNIT_CONTROL_REQUEST));
	if (ssi_request->operation == SSI2_SAS_OP_PHY_HARD_RESET ||
			ssi_request->operation == SSI2_SAS_OP_PHY_LINK_RESET)
		ioa->ioa_link_reset_in_progress = 1;


	init_completion(&ioa->base_cmds.done);
	ioa->put_host_tag_id_default(ioa, scmd);
	wait_for_completion_timeout(&ioa->base_cmds.done,
		msecs_to_jiffies(10000));
	if ((ssi_request->operation == SSI2_SAS_OP_PHY_HARD_RESET ||
			ssi_request->operation == SSI2_SAS_OP_PHY_LINK_RESET) &&
			ioa->ioa_link_reset_in_progress)
		ioa->ioa_link_reset_in_progress = 0;
	if (!(ioa->base_cmds.status & HST2DR_CMD_COMPLETE)) {
		log_error(ioa, "%s: timeout\n",
			__func__);
		if (!(ioa->base_cmds.status & HST2DR_CMD_RESET))
			issue_reset = true;
		goto issue_host_reset;
	}
	if (ioa->base_cmds.status & HST2DR_CMD_REPLY_VALID)
		memcpy(ssi_reply, ioa->base_cmds.reply,
			sizeof(SSI2_SAS_UNIT_CONTROL_REPLY));
	else
		memset(ssi_reply, 0, sizeof(SSI2_SAS_UNIT_CONTROL_REPLY));
	ioa->base_cmds.status = HST2DR_CMD_NOT_USED;
	goto out;

 issue_host_reset:
	if (issue_reset)
		hst2dr_base_hard_reset_handler(ioa, HARD_RESET, 4);
	ioa->base_cmds.status = HST2DR_CMD_NOT_USED;
	rc = -EFAULT;
 out:
	mutex_unlock(&ioa->base_cmds.mutex);
	return rc;
}


/**
 * _base_get_ioa_info - obtain ioa info reply and save in ioa
 * @ioa: per adapter object
 *
 * Returns 0 for success, non-zero for failure.
 */
static int
_base_get_ioa_info(struct HST2DR_ADAPTER *ioa)
{
	SSI2_IOA_INFO_REPLY ssi_reply;
	struct hst2dr_info *info;

	if (hst2dr_get_ioa_info_comm_api(ioa, &ssi_reply) != 0)
		return 1;

	info = &ioa->info;
	memset(info, 0, sizeof(struct hst2dr_info));
	info->driver_version = le32_to_cpu(ssi_reply.driver_version);
	info->ioa_exceptions = le16_to_cpu(ssi_reply.ioa_exceptions);
	info->max_chain_depth = ssi_reply.max_chain_depth;
	info->owner = ssi_reply.owner;
	info->num_ports = ssi_reply.num_ports;
	info->max_msix_vectors = ssi_reply.max_msix_vectors;
	info->max_sq = ssi_reply.max_sq;
	info->max_cq = ssi_reply.max_cq;
	info->max_sense = ssi_reply.max_sense;
	info->request_credit = le16_to_cpu(ssi_reply.request_credit);
	info->max_reply_descriptor_post_queue_depth =
		le16_to_cpu(ssi_reply.max_reply_descriptor_post_queue_depth);
	if (info->max_reply_descriptor_post_queue_depth > MAX_HW_QUEUE_SIZE)
		info->max_reply_descriptor_post_queue_depth = MAX_HW_QUEUE_SIZE;
	info->PID = le16_to_cpu(ssi_reply.PID);
	info->ioa_capabilities = le32_to_cpu(ssi_reply.ioa_capabilities);
	info->fw_version.dword = le32_to_cpu(ssi_reply.fw_version.dword);
	info->ioa_request_frame_size =
		le16_to_cpu(ssi_reply.ioa_request_frame_size);
	info->ioa_max_chain_segment_size =
		le16_to_cpu(ssi_reply.ioa_max_chain_segment_size);
	info->max_initiators = le16_to_cpu(ssi_reply.max_initiators);
	info->max_targets = le16_to_cpu(ssi_reply.max_targets);
	ioa->shost->max_id = -1;
	info->max_sas_expanders = le16_to_cpu(ssi_reply.max_sas_expanders);
	info->max_enclosures = le16_to_cpu(ssi_reply.max_enclosures);
	info->protocol_flags = le16_to_cpu(ssi_reply.protocol_flags);
	info->high_priority_credit =
		le16_to_cpu(ssi_reply.high_priority_credit);
	info->reply_frame_size = ssi_reply.reply_frame_size;
	info->max_dev_handle = le16_to_cpu(ssi_reply.max_dev_handle);
	info->min_dev_handle = le16_to_cpu(ssi_reply.min_dev_handle);
	info->host_page_size = ssi_reply.host_page_size;

	ioa->smp_flags = ssi_reply.smp_flags;
	log_init(ioa, "Current smp_flags %x\n", ioa->smp_flags);
	ioa->nonio_flags = ssi_reply.nonio_flags & 3;
	log_init(ioa, "Current nonio_flags %x\n", ioa->nonio_flags);
	log_init(ioa, "Current log_type is %08x\n", ioa->log_level);

	log_init(ioa, "%s %x, %s %x, %s %x, %s %x, %s %x, %s %x, %s %x\n",
			"max_chain_depth:",
			info->max_chain_depth,
			"ioa_max_chain_segment_size:",
			info->ioa_max_chain_segment_size,
			"max_msix_vectors:",
			info->max_msix_vectors,
			"max_initiators:",
			info->max_initiators,
			"max_targets:",
			info->max_targets,
			"max_sas_expanders:",
			info->max_sas_expanders,
			"max_enclosures:",
			info->max_enclosures);

	/*
	 * Get the Page Size from IOA info. If it's 0, default to 4k.
	 */
	ioa->page_size = 1 << info->host_page_size;
	if (ioa->page_size == 1) {
		log_init(ioa, "%s 0: %s 4k\n",
			"CurrentHostPageSize is",
			" Setting default host page size to");
		ioa->page_size = 1 << HST2DR_HOST_PAGE_SIZE_4K;
	}
	info->driver_version = cpu_to_le32(DRIVER_VERSION);
	return 0;
}

/**
 * _base_send_ioa_init - send ioa_init to firmware
 * @ioa: per adapter object
 *
 * Returns 0 for success, non-zero for failure.
 */
static int
_base_send_ioa_init(struct HST2DR_ADAPTER *ioa)
{
	SSI2_IOA_INIT_REQUEST *ssi_request;
	SSI2_IOA_INIT_REPLY ssi_reply;
	int  r = 0;
	ktime_t current_time;

	ssi_request = (SSI2_IOA_INIT_REQUEST *)
		(ioa->request + HOST_TAG_ID_POLL * 128);

	memset(ssi_request, 0, sizeof(SSI2_IOA_INIT_REQUEST));
	ssi_request->opcode = SSI2_FUNCTION_IOA_INIT;
	ssi_request->opflags = cmd_flag_fw_mode_admin;
	ssi_request->host_tag_id = HOST_TAG_ID_POLL;
	ssi_request->host_flag = hst2dr_cmd_ioa_init;
	ssi_request->owner = SSI2_WHOINIT_HOST_DRIVER;
	ssi_request->driver_version = cpu_to_le32(DRIVER_VERSION);
	ssi_request->host_page_size = HST2DR_HOST_PAGE_SIZE_4K;

	ssi_request->host_msix_vectors = ioa->reply_queue_count - 1;
	ssi_request->reply_queue_depth =
		cpu_to_le16(ioa->reply_queue_depth);
	ssi_request->sense_queue_depth = cpu_to_le16(ioa->sense_depth);
	ssi_request->sense_buffer_address = cpu_to_le64(ioa->sense_dma);
	ssi_request->reply_queue_address =
		cpu_to_le64((u64)ioa->reply_dma);
	ssi_request->sense_size = SCSI_SENSE_BUFFERSIZE;

	/* This time stamp specifies number of milliseconds
	 * since epoch ~ midnight January 1, 1970.
	 */
	current_time = ktime_get_real();
	ssi_request->time_stamp = cpu_to_le64(ktime_to_ms(current_time));

	if (hst2dr_ioa_init_comm_api(ioa, ssi_request, &ssi_reply) != 0) {
		log_error(ioa,
			"%s: hst2dr_ioa_init_comm_api failed\n", __func__);
		r = -EIO;
	}

	return r;
}

/**
 * hst2dr_port_enable_done - command completion routine for port enable
 * @ioa: per adapter object
 * @cqe: completion queue entity
 *
 * Return 1 meaning mf should be freed from _base_interrupt
 *	0 means the mf is freed from this function.
 */
u8
hst2dr_port_enable_done(struct HST2DR_ADAPTER *ioa,
		hst2dr_nvme_completion *cqe)
{
	SSI2_DEFAULT_REPLY *ssi_reply = NULL;

	if (ioa->port_enable_cmds.status == HST2DR_CMD_NOT_USED)
		return 1;
	if (cqe->ctrl.description == SSI2_RPY_DESCRIPT_FLAGS_ADDRESS_REPLY)
		ssi_reply = hst2dr_base_get_reply_virt_addr(ioa,
				cqe->reply_id);
	if (!ssi_reply) {
		if (cqe->ctrl.status != SSI2_IOASTATUS_SUCCESS) {
			log_event(ioa, "port enable status:%x\n",
				cqe->ctrl.status);
			ioa->port_enable_cmds.status |= HST2DR_CMD_NOT_USED;
			ioa->port_enable_cmds.status &= ~HST2DR_CMD_PENDING;
			ioa->port_enable_cmds.status |= HST2DR_CMD_COMPLETE;
			ssi_reply = (SSI2_DEFAULT_REPLY *)
				ioa->port_enable_cmds.reply;
			ssi_reply->status = cqe->ctrl.status;
			complete(&ioa->port_enable_cmds.done);
			return 1;
		}

	}
	if (ssi_reply)
		if (ssi_reply->opcode != SSI2_FUNCTION_PORT_ENABLE)
			return 1;

	ioa->port_enable_cmds.status &= ~HST2DR_CMD_PENDING;
	ioa->port_enable_cmds.status |= HST2DR_CMD_COMPLETE;
	if (ssi_reply) {
		if (ssi_reply->msg_len == 0) {
			memset(ioa->port_enable_cmds.reply, 0,
					sizeof(SSI2_DEFAULT_REPLY));
			ioa->port_enable_cmds.status |= HST2DR_CMD_NOT_USED;
		} else {
			ioa->port_enable_cmds.status |= HST2DR_CMD_REPLY_VALID;
			ssi_reply->status = cqe->ctrl.status;
			memcpy(ioa->port_enable_cmds.reply,
				ssi_reply, min_t(u8, ssi_reply->msg_len * 4, 128));
			debug_dump_mem("port_enable_done",
				ssi_reply, min_t(u8, ssi_reply->msg_len * 4, 128));
		}
	} else {
		ssi_reply = (SSI2_DEFAULT_REPLY *) ioa->port_enable_cmds.reply;
		ssi_reply->status = cqe->ctrl.status;
	}
	if (cqe->ctrl.status != SSI2_IOASTATUS_SUCCESS)
		ioa->port_enable_failed = 1;

	if (ioa->is_driver_loading) {
		if (cqe->ctrl.status == SSI2_IOASTATUS_SUCCESS) {
			hst2dr_port_enable_complete(ioa);
			return 1;
		} else {
			ioa->start_scan_failed = cqe->ctrl.status;
			ioa->start_scan = 0;
			return 1;
		}
	}
	complete(&ioa->port_enable_cmds.done);
	return 1;
}

/**
 * _base_send_port_enable - send port_enable(discovery stuff) to firmware
 * @ioa: per adapter object
 *
 * Returns 0 for success, non-zero for failure.
 */
static int
_base_send_port_enable(struct HST2DR_ADAPTER *ioa)
{
	SSI2_PORT_ENABLE_REQUEST *ssi_request;
	SSI2_PORT_ENABLE_REPLY *ssi_reply;
	int r = 0;
	u16 host_tag_id;
	u16 ioa_status;
	hst2dr_command *scmd;

	log_comm(ioa, "%s !\n", __func__);

	if (ioa->port_enable_cmds.status & HST2DR_CMD_PENDING) {
		log_error(ioa, "%s: internal command already in use\n",
			__func__);
		return -EAGAIN;
	}

	host_tag_id = hst2dr_base_get_host_tag_id(ioa, ioa->port_enable_cb_idx);
	if (host_tag_id == NO_HOST_TAG_ID) {
		log_error(ioa, "%s: failed obtaining a host_tag_id\n",
			__func__);
		return -EAGAIN;
	}

	ioa->port_enable_cmds.status = HST2DR_CMD_PENDING;
	scmd = hst2dr_base_get_msg_frame(ioa, host_tag_id);
	memset(scmd, 0, sizeof(*scmd));
	ssi_request = (SSI2_PORT_ENABLE_REQUEST *)scmd;
	ioa->port_enable_cmds.host_tag_id = host_tag_id;
	ssi_request->opcode = SSI2_FUNCTION_PORT_ENABLE;
	ssi_request->opflags = cmd_flag_fw_mode_admin;
	ssi_request->host_tag_id = host_tag_id;
	ssi_request->host_flag = hst2dr_cmd_port_enable;

	init_completion(&ioa->port_enable_cmds.done);
	ioa->put_host_tag_id_default(ioa, scmd);
	wait_for_completion_timeout(&ioa->port_enable_cmds.done,
			PORT_ENABLE_WAITING * HZ);
	if (!(ioa->port_enable_cmds.status & HST2DR_CMD_COMPLETE)) {
		log_error(ioa, "%s: SSI2_FUNCTION_PORT_ENABLE timeout\n",
			__func__);
		if (ioa->port_enable_cmds.status & HST2DR_CMD_RESET)
			r = -EFAULT;
		else
			r = -ETIME;
		goto out;
	}

	ssi_reply = ioa->port_enable_cmds.reply;
	ioa_status = le16_to_cpu(ssi_reply->status) & SSI2_IOASTATUS_MASK;
	if (ioa_status != SSI2_IOASTATUS_SUCCESS) {
		log_error(ioa, "%s: failed with (ioa_status=0x%08x)\n",
			__func__, ioa_status);
		r = -EFAULT;
		goto out;
	}

out:
	ioa->port_enable_cmds.status = HST2DR_CMD_NOT_USED;
	log_comm(ioa, "port enable: %s\n", ((r == 0) ?
		"SUCCESS" : "FAILED"));
	return r;
}

/**
 * hst2dr_port_enable - initiate firmware discovery (don't wait for reply)
 * @ioa: per adapter object
 *
 * Returns 0 for success, non-zero for failure.
 */
int
hst2dr_port_enable(struct HST2DR_ADAPTER *ioa)
{
	SSI2_PORT_ENABLE_REQUEST *ssi_request;
	u16 host_tag_id;
	hst2dr_command *scmd;

	log_init(ioa, "%s !\n", __func__);
	if (ioa->port_enable_cmds.status & HST2DR_CMD_PENDING) {
		log_error(ioa, "%s: internal command already in use\n",
			__func__);
		return -EAGAIN;
	}

	host_tag_id = hst2dr_base_get_host_tag_id(ioa, ioa->port_enable_cb_idx);
	if (host_tag_id == NO_HOST_TAG_ID) {
		log_error(ioa, "%s: failed obtaining a host_tag_id\n",
			__func__);
		return -EAGAIN;
	}

	ioa->port_enable_cmds.status = HST2DR_CMD_PENDING;
	scmd = hst2dr_base_get_msg_frame(ioa, host_tag_id);
	memset(scmd, 0, sizeof(*scmd));
	ssi_request = (SSI2_PORT_ENABLE_REQUEST *)scmd;
	ssi_request->opcode = SSI2_FUNCTION_PORT_ENABLE;
	ssi_request->opflags = cmd_flag_fw_mode_admin;
	ssi_request->host_tag_id = host_tag_id;
	ssi_request->host_flag = hst2dr_cmd_port_enable;

	ioa->port_enable_cmds.host_tag_id = host_tag_id;

	ioa->put_host_tag_id_default(ioa, scmd);

	return 0;
}


/**
 * _base_unmask_events - turn on notification for this event
 * @ioa: per adapter object
 * @event: firmware event
 *
 * The mask is stored in ioa->event_masks.
 */
static void
_base_unmask_events(struct HST2DR_ADAPTER *ioa, u16 event)
{
	u32 desired_event;

	if (event >= 128)
		return;

	desired_event = (1 << (event % 32));

	if (event < 32)
		ioa->event_masks[0] &= ~desired_event;
	else if (event < 64)
		ioa->event_masks[1] &= ~desired_event;
	else if (event < 96)
		ioa->event_masks[2] &= ~desired_event;
	else if (event < 128)
		ioa->event_masks[3] &= ~desired_event;
}

/**
 * _base_event_notification - send event notification
 * @ioa: per adapter object
 *
 * Returns 0 for success, non-zero for failure.
 */
static int
_base_event_notification(struct HST2DR_ADAPTER *ioa)
{
	SSI2_EVENT_NOTIFICATION_REQUEST *ssi_request;
	u16 host_tag_id;
	int r = 0;
	int i;
	hst2dr_command *scmd;

	log_event(ioa, "%s %d\n", __func__, __LINE__);
	mutex_lock(&ioa->base_cmds.mutex);

	if (ioa->base_cmds.status != HST2DR_CMD_NOT_USED) {
		log_warn(ioa, "%s: internal command already in use\n",
			__func__);
		mutex_unlock(&ioa->base_cmds.mutex);
		return -EAGAIN;
	}
	host_tag_id = hst2dr_base_get_host_tag_id(ioa, ioa->base_cb_idx);
	if (host_tag_id == NO_HOST_TAG_ID) {
		log_warn(ioa, "%s: failed obtaining a host_tag_id\n",
			__func__);
		ioa->base_cmds.status = HST2DR_CMD_NOT_USED;
		mutex_unlock(&ioa->base_cmds.mutex);
		return -EAGAIN;
	}
	ioa->base_cmds.status = HST2DR_CMD_PENDING;
	scmd = hst2dr_base_get_msg_frame(ioa, host_tag_id);
	memset(scmd, 0, sizeof(*scmd));
	ssi_request = (SSI2_EVENT_NOTIFICATION_REQUEST *)scmd;
	ssi_request->opcode = SSI2_FUNCTION_EVENT;
	ssi_request->opflags = cmd_flag_fw_mode_admin;
	ssi_request->host_tag_id = host_tag_id;
	ssi_request->host_flag = hst2dr_cmd_base;

	ioa->base_cmds.host_tag_id = host_tag_id;

	for (i = 0; i < SSI2_EVENT_NOTIFY_EVENTMASK; i++)
		ssi_request->event_masks[i] =
			cpu_to_le32(ioa->event_masks[i]);

	init_completion(&ioa->base_cmds.done);
	ioa->put_host_tag_id_default(ioa, scmd);
	wait_for_completion_timeout(&ioa->base_cmds.done,
			EVENT_NOTIFICATION_WAITING * HZ);
	if (!(ioa->base_cmds.status & HST2DR_CMD_COMPLETE)) {
		log_error(ioa, "%s: SSI2_FUNCTION_EVENT timeout\n",
			__func__);
		if (ioa->base_cmds.status & HST2DR_CMD_RESET)
			r = -EFAULT;
		else
			r = -ETIME;
	}
	ioa->base_cmds.status = HST2DR_CMD_NOT_USED;
	mutex_unlock(&ioa->base_cmds.mutex);
	return r;
}

/**
 * hst2dr_base_validate_event_type - validating event types
 * @ioa: per adapter object
 * @event: firmware event
 *
 * This will turn on firmware event notification when application
 * ask for that event. We don't mask events that are already enabled.
 */
void
hst2dr_base_validate_event_type(struct HST2DR_ADAPTER *ioa, u32 *event_type)
{
	int i, j;
	u32 event_mask, desired_event;
	u8 send_update_to_fw;

	for (i = 0, send_update_to_fw = 0; i <
			SSI2_EVENT_NOTIFY_EVENTMASK; i++) {
		event_mask = ~event_type[i];
		desired_event = 1;
		for (j = 0; j < 32; j++) {
			if (!(event_mask & desired_event) &&
					(ioa->event_masks[i] &
					desired_event)) {
				ioa->event_masks[i] &= ~desired_event;
				send_update_to_fw = 1;
			}
			desired_event = (desired_event << 1);
		}
	}

	if (!send_update_to_fw)
		return;

	mutex_lock(&ioa->base_cmds.mutex);
	_base_event_notification(ioa);
	mutex_unlock(&ioa->base_cmds.mutex);
}
#define HAND_SHAKE_RETRY_LIMIT			3
#define POOLING_QUERY_STATUS_WAITING	1000	// 1000ms
#define POOLING_QUERY_STATUS_INTERVAL	10	// 10ms
#define POOLING_ACK_WAITING				20000	// 20S
#define POOLING_ACK_INTERVAL			100	// 100ms
/**
 * hst2dr_hankshake - sync to FW ready for hard reset
 * @ioa: per adapter object
 *
 * Returns 0 for success, non-zero for failure.
 */

static int hst2dr_handshake(struct HST2DR_ADAPTER *ioa)
{
	int r;
	int i, retry;

	log_reset(ioa, "reset handshaking...\n");
	retry = 0;
try_reset:
	hst2dr_write_direct_reg_hal_api(ioa, NVME_REG_HR_HS, RESET_QUERY);
	for (i = 0; i < POOLING_QUERY_STATUS_WAITING /
			POOLING_QUERY_STATUS_INTERVAL; i++) {
		msleep(POOLING_QUERY_STATUS_INTERVAL);
		r = hst2dr_read_direct_reg_hal_api(ioa, NVME_REG_HR_HS);
		if (r != RESET_QUERY)
			break;
	}
	if (r == RESET_ACK) {
		for (i = 0; i < POOLING_ACK_WAITING / POOLING_ACK_INTERVAL;
				i++) {
			msleep(POOLING_ACK_INTERVAL);
			r = hst2dr_read_direct_reg_hal_api(ioa, NVME_REG_HR_HS);
			if (r == RESET_READY) {
				log_reset(ioa, "reset hand shake ok\n");
				return SUCCESS;
			}
			if (r == RESET_NCK) {
				r = -EFAULT;
				goto out;
			}
		}
		if (r != RESET_READY) {
			if (retry < HAND_SHAKE_RETRY_LIMIT) {
				retry++;
				goto try_reset;
			} else {
				r = -EFAULT;
				goto out;
			}
		}
	} else if (r == RESET_NCK) {
		r = -EFAULT;
		goto out;
	} else if (r == RESET_QUERY) {
		if (retry < HAND_SHAKE_RETRY_LIMIT) {
			retry++;
			log_reset(ioa, "hand shake retry:%x\n", retry);
			goto try_reset;
		} else {
			r = -EFAULT;
			goto out;
		}
	} else {
		log_reset(ioa, "NVME_REG_HR_HS:%x %s\n",
			r, r == RESET_READY ? "ready" : "fail");
		if (r == RESET_READY)
			return SUCCESS;
		else
			r = -EFAULT;
	}
out:
	return r;
}
/**
 * hst2dr_signaure_sequence_check - signature sequence check
 * @ioa: per adapter object
 *
 * Returns 0 for success, non-zero for failure.
 */

int hst2dr_signature_sequence_check(struct HST2DR_ADAPTER *ioa)
{
	int r, retry = 0;

	log_debug(ioa, "signature sequence start !\n");
	do {
		if (retry++ >= RESET_UNLOCK_RETRY_COUNT) {
			log_debug(ioa, "host reset unlock failed!\n");
			return -EFAULT;
		}
		hst2dr_write_direct_reg_hal_api(ioa,
				NVME_REG_SEQUENCE, SIGNATURE_SEQUENCE0);
		r = hst2dr_read_direct_reg_hal_api(ioa, NVME_REG_CHIP_STATUS);
		log_debug(ioa, "chip status0:%x !\n", r);
		hst2dr_write_direct_reg_hal_api(ioa,
				NVME_REG_SEQUENCE, SIGNATURE_SEQUENCE1);
		r = hst2dr_read_direct_reg_hal_api(ioa, NVME_REG_CHIP_STATUS);
		log_debug(ioa, "chip status1:%x !\n", r);
		hst2dr_write_direct_reg_hal_api(ioa,
				NVME_REG_SEQUENCE, SIGNATURE_SEQUENCE2);
		r = hst2dr_read_direct_reg_hal_api(ioa, NVME_REG_CHIP_STATUS);
		log_debug(ioa, "chip status2:%x !\n", r);
		hst2dr_write_direct_reg_hal_api(ioa,
				NVME_REG_SEQUENCE, SIGNATURE_SEQUENCE3);
		r = hst2dr_read_direct_reg_hal_api(ioa, NVME_REG_CHIP_STATUS);
		log_debug(ioa, "chip status3:%x !\n", r);
		hst2dr_write_direct_reg_hal_api(ioa,
				NVME_REG_SEQUENCE, SIGNATURE_SEQUENCE4);
		r = hst2dr_read_direct_reg_hal_api(ioa, NVME_REG_CHIP_STATUS);
		log_debug(ioa, "chip status4:%x !\n", r);
	} while  ((r & SIGNATURE_SEQUENCE_STATUS_MASK) != CHIP_STATUS_ACTIVE);
	log_debug(ioa, "signature sequence finish !\n");
	return SUCCESS;
}
/**
 * hst2dr_send_chip_reset_sequence - signature sequence check
 * @ioa: per adapter object
 *
 *
 */

void hst2dr_send_chip_reset_sequence(struct HST2DR_ADAPTER *ioa)
{
	log_debug(ioa, "write pci config chip reset");
	pci_write_config_dword(ioa->pdev,
		PCI_REG_CONFIG_CHIP_RESET, CHIP_RESET_SEQUENCE0);
	pci_write_config_dword(ioa->pdev,
		PCI_REG_CONFIG_CHIP_RESET, CHIP_RESET_SEQUENCE1);
	pci_write_config_dword(ioa->pdev,
		PCI_REG_CONFIG_CHIP_RESET, CHIP_RESET_SEQUENCE2);
	pci_write_config_dword(ioa->pdev,
		PCI_REG_CONFIG_CHIP_RESET, CHIP_RESET_SEQUENCE3);
}

/**
 * hst2dr_chip_reset - chip_status IS or CHIP_RESET
 * @ioa: per adapter object
 *
 * Returns 0 for success, non-zero for failure.
 */

static int hst2dr_chip_reset(struct HST2DR_ADAPTER *ioa, enum reset_type type)
{
	int r;
	int i;

	if ((type == AER_RESET) && (ioa->chip_version == VS_V2N1))
		goto aer_reset;
	if (hst2dr_signature_sequence_check(ioa) == SUCCESS)
		hst2dr_write_direct_reg_hal_api(ioa,
			NVME_REG_CHIP_STATUS_IS, 1);
	else
		return -EFAULT;
	udelay(CHIP_RESET_IS_INTERVAL);
	r = hst2dr_read_direct_reg_hal_api(ioa, NVME_REG_CHIP_STATUS);
	log_debug(ioa, "IS chip status:%x\n", r);
	for (i = 0; i < IS_WAITING / CHIP_RESET_QUERY_INTERVAL; i++) {
		r = hst2dr_read_direct_reg_hal_api(ioa, NVME_REG_CHIP_STATUS);
		if ((r & CHIP_STATUS_MASK) == CHIP_STATUS_READY) {
			log_debug(ioa, "IS ready, wait:%d ms", i * 10);
			break;
		} else
			msleep(CHIP_RESET_QUERY_INTERVAL);
	}
	if ((r & CHIP_STATUS_MASK) == CHIP_STATUS_READY)
		return SUCCESS;
	else if (type == AER_RESET_IS)
		return -EFAULT;
	else
		r = 0;
	if ((r & CHIP_STATUS_MASK) != CHIP_STATUS_READY) {
		log_reset(ioa, "CHIP_STATUS_IS failed!\n");
aer_reset:
		if (ioa->nvme_reg_dbs == 0x2000)
			hst2dr_send_chip_reset_sequence(ioa);
		else
			if (hst2dr_signature_sequence_check(ioa) == SUCCESS) {
				hst2dr_write_direct_reg_hal_api(ioa,
						NVME_REG_CHIP_STATUS_CTRL,
						(CHIP_RESET | HW_BALANCE_EN));
				log_debug(ioa, "CHIP_STATUS_CTRL write: 0x%x\n",
						(CHIP_RESET | HW_BALANCE_EN));
			} else
				return -EFAULT;
		msleep(CHIP_RESET_INTERVAL);
		r = hst2dr_read_direct_reg_hal_api(ioa, NVME_REG_CHIP_STATUS);
		log_debug(ioa, "CHIP_RESET chip status:%x\n", r);
		for (i = 0; i < CHIP_RESET_WAITING / CHIP_RESET_QUERY_INTERVAL;
				i++) {
			r = hst2dr_read_direct_reg_hal_api(ioa,
					NVME_REG_CHIP_STATUS);
			if ((r & CHIP_STATUS_MASK) == CHIP_STATUS_READY) {
				log_debug(ioa, "CHIP RESET ready, wait:%d ms",
						i * CHIP_RESET_QUERY_INTERVAL);
				break;
			} else
				msleep(CHIP_RESET_QUERY_INTERVAL);
		}
		if ((r & CHIP_STATUS_MASK) != CHIP_STATUS_READY) {
			log_reset(ioa, "CHIP_RESET failed!\n");
			return -EFAULT;
		}
	}
	return SUCCESS;

}
/**
 * _base_reset - the "hard reset" start of reset
 * @ioa: per adapter object
 *
 * Returns 0 for success, non-zero for failure.
 */

static int
_base_reset(struct HST2DR_ADAPTER *ioa, enum reset_type type)
{
	int r;
	u32 cc;

	if ((ioa->ioa_reset_in_progress & 4) != 4)
		hst2dr_base_stop_watchdog(ioa);
	cc = readl(&ioa->chip->RegsBase + (NVME_REG_CC >> 2));
	cc &= 0xfffffffe; // CC disable
	writel(cc, &ioa->chip->RegsBase + (NVME_REG_CC >> 2));
	if ((type == AER_RESET) || (type == AER_RESET_IS)) {
		if (hst2dr_chip_reset(ioa, type) != SUCCESS)
			goto out;
	} else if (hst2dr_handshake(ioa) != SUCCESS) { // hand shake fail
		if (hst2dr_chip_reset(ioa, type) != SUCCESS)
			goto out;
	}
	log_debug(ioa, "verify pending_io_count:0x%x\n", ioa->pending_io_count);

	_base_free_irq(ioa);
	_base_disable_msix(ioa);
	log_reset(ioa, "Init queue after reset\n");
	if (hst2dr_init_nvme_device_and_admin_queue_hal_api(ioa) != 0) {
		log_error(ioa, "Init queue after reset failed\n");
		goto out;
	}

	r = _base_get_ioa_info(ioa);
	if (r || ioa->info.driver_version == 0) {
		log_error(ioa, "%s %d get ioa info failed\n",
			__func__, __LINE__);
		goto out;
	}
	r = hst2dr_init_nvme_io_queue_hal_api(ioa);
	if (r) {
		log_error(ioa, "%s %d init nvme io queue failed\n",
			__func__, __LINE__);
		goto out;
	}
	log_reset(ioa, "Finished init io queue\n");
	_base_enable_msix(ioa);
	if ((ioa->ioa_reset_in_progress & 4) != 4)
		hst2dr_base_start_watchdog(ioa);
	return 0;

out:
	if ((ioa->ioa_reset_in_progress & 4) != 4)
		hst2dr_base_start_watchdog(ioa);
	return -EFAULT;
}

/**
 * _base_make_ioa_ready - put controller in READY state
 * @ioa: per adapter object
 * @type: HARD_RESET or SOFT_RESET or AER_RESET or AER_RESET_IS
 *
 * Returns 0 for success, non-zero for failure.
 */
static int
_base_make_ioa_ready(struct HST2DR_ADAPTER *ioa, enum reset_type type)
{
	u32 ioa_state;
	int rc;
	int count;

	if (ioa->pci_error_recovery)
		return 0;

	ioa_state = hst2dr_base_get_ioastate(ioa, 0);

	/* if in RESET state, it should move to READY state shortly */
	count = 0;
	if ((ioa_state & SSI2_IOA_STATE_MASK) == SSI2_IOA_STATE_RESET) {
		while ((ioa_state & SSI2_IOA_STATE_MASK) !=
				SSI2_IOA_STATE_READY) {
			if (count++ == 10) {
				log_error(ioa,
					"%s: %s (ioa_state=0x%x)\n",
					__func__,
					"failed going to ready state",
					ioa_state);
				return -EFAULT;
			}
			ssleep(1);
			ioa_state = hst2dr_base_get_ioastate(ioa, 0);
		}
	}

	if (ioa_state & SSI2_IOA_USED)
		goto issue_reset;

	if ((ioa_state & SSI2_IOA_STATE_MASK) == SSI2_IOA_STATE_FAULT) {
		hst2dr_base_fault_info(ioa, ioa_state &
			SSI2_IOA_DATA_MASK);
		goto issue_reset;
	}

	if ((type == HARD_RESET) ||
			(type == AER_RESET) ||
			(type == AER_RESET_IS))
		goto issue_reset;

	if ((ioa_state & SSI2_IOA_STATE_MASK) == SSI2_IOA_STATE_READY) {
		int r;

		if (ioa->pm_state == PM_STATE_RESUME) {
			r = hst2dr_init_nvme_io_queue_hal_api(ioa);
			if (r) {
				log_error(ioa,
					"%s %d init nvme io queue failed\n",
					__func__, __LINE__);
				return r;
			}
		}
		return 0;
	}

	if ((ioa_state & SSI2_IOA_STATE_MASK) == SSI2_IOA_STATE_OPERATIONAL)
		if (!(_base_send_ioa_reset(ioa,
				SSI2_FUNCTION_IOA_MESSAGE_UNIT_RESET, 15))) {
			return 0;
	}

 issue_reset:
	rc = _base_reset(ioa, type);
	return rc;
}

/**
 * _base_make_ioa_operational - put controller in OPERATIONAL state
 * @ioa: per adapter object
 *
 * Returns 0 for success, non-zero for failure.
 */
static int
_base_make_ioa_operational(struct HST2DR_ADAPTER *ioa)
{
	int r, i;
	unsigned long	flags;
	u32 reply_address;
	u16 host_tag_id;
	struct _tr_list *delayed_tr, *delayed_tr_next;
	struct _event_ack_list *delayed_event_ack, *delayed_event_ack_next;

	/* clean the delayed link reset list */
	list_for_each_entry_safe(delayed_tr, delayed_tr_next,
			&ioa->delayed_tr_list, list) {
		list_del_init(&delayed_tr->list);
		kfree(delayed_tr);
	}

	list_for_each_entry_safe(delayed_tr, delayed_tr_next,
		&ioa->delayed_tr_vol_list, list) {
		list_del_init(&delayed_tr->list);
		kfree(delayed_tr);
	}

	list_for_each_entry_safe(delayed_event_ack, delayed_event_ack_next,
		&ioa->delayed_event_ack_list, list) {
		list_del_init(&delayed_event_ack->list);
		kfree(delayed_event_ack);
	}

	/* initialize the scsi lookup free list */
	spin_lock_irqsave(&ioa->scsi_lookup_lock, flags);
	INIT_LIST_HEAD(&ioa->free_list);
	host_tag_id = 0;
	for (i = 0; i < ioa->scsiio_depth; i++, host_tag_id++) {
		INIT_LIST_HEAD(&ioa->scsi_lookup[i].tracker_list);
		ioa->scsi_lookup[i].cb_idx = INVALID_CB_INDEX;
		ioa->scsi_lookup[i].host_tag_id = host_tag_id;
		ioa->scsi_lookup[i].direct_io = 0;
		list_add_tail(&ioa->scsi_lookup[i].tracker_list,
			&ioa->free_list);
	}

	/* internal queue */
	INIT_LIST_HEAD(&ioa->internal_free_list);
	host_tag_id = ioa->internal_host_tag_id;
	for (i = 0; i < ioa->internal_depth - 0x01; i++, host_tag_id++) {
		ioa->internal_lookup[i].cb_idx = INVALID_CB_INDEX;
		ioa->internal_lookup[i].host_tag_id = host_tag_id;
		list_add_tail(&ioa->internal_lookup[i].tracker_list,
			&ioa->internal_free_list);
	}

	/* chain pool */
	INIT_LIST_HEAD(&ioa->free_chain_list);
	for (i = 0; i < ioa->chain_depth; i++)
		list_add_tail(
			&ioa->chain_lookup[i].chains_per_host_tag_id->free_list,
			&ioa->free_chain_list);

	spin_unlock_irqrestore(&ioa->scsi_lookup_lock, flags);

	/* initialize Reply Free Queue */
	for (i = 0, reply_address = (u32)ioa->reply_dma;
			i < ioa->reply_queue_depth ; i++, reply_address +=
			ioa->reply_sz)
		ioa->reply_free[i] = cpu_to_le32(reply_address);

	/* initialize reply queues */
	if (ioa->is_driver_loading)
		_base_assign_reply_queues(ioa);

	r = _base_send_ioa_init(ioa);
	if (r)
		return r;

	_base_unmask_interrupts(ioa);
	r = _base_event_notification(ioa);
	if (r)
		return r;

	_base_static_config_pages(ioa);
	if (ioa->is_driver_loading) {
		ioa->wait_for_discovery_to_complete =
			(ioa->ir_firmware == 1) ? 1 : 0;
		return r; /* scan_start and scan_finished support */
	}
	r = _base_send_port_enable(ioa);
	if (r) {
		log_error(ioa,
			"_base_send_port_enable return failed\n ");
		ioa->start_scan = 0;
		return r;

	}

	return r;
}

/**
 * hst2dr_base_free_resources - free resources controller resources
 * @ioa: per adapter object
 *
 * Return nothing.
 */
void
hst2dr_base_free_resources(struct HST2DR_ADAPTER *ioa)
{
	/* synchronizing freeing resource with pci_access_mutex lock */
	mutex_lock(&ioa->pci_access_mutex);
	if (ioa->chip_phys && ioa->chip) {
		_base_mask_interrupts(ioa);
		ioa->shost_recovery = 1;
		_base_make_ioa_ready(ioa, SOFT_RESET);
		ioa->shost_recovery = 0;
	}

	hst2dr_base_unmap_resources(ioa);
	mutex_unlock(&ioa->pci_access_mutex);
}

/**
 * hst2dr_base_attach - attach controller instance
 * @ioa: per adapter object
 *
 * Returns 0 for success, non-zero for failure.
 */
int
hst2dr_base_attach(struct HST2DR_ADAPTER *ioa)
{
	int r, i;
	U16 blocking_handles_sz;
	int cpu_id, last_cpu_id = 0;

	/* setup cpu_msix_table */
	ioa->cpu_count = num_online_cpus();
	for_each_online_cpu(cpu_id)
		last_cpu_id = cpu_id;
	ioa->cpu_msix_table_sz = last_cpu_id + 1;
	ioa->cpu_msix_table = kzalloc(ioa->cpu_msix_table_sz, GFP_KERNEL);
	ioa->reply_queue_count = 1;
	if (!ioa->cpu_msix_table) {
		r = -ENOMEM;
		goto out_free_resources;
	}
	ioa->dma_mask = 0;
	r = hst2dr_base_map_resources(ioa);
	if (r)
		goto out_free_resources;

	pci_set_drvdata(ioa->pdev, ioa->shost);

	ioa->build_sg_scmd =
		(HST2DR_BUILD_SG_SCMD)&_base_build_sg_scmd_ieee;
	ioa->build_sg = &_base_build_sg_ieee;
	ioa->build_zero_len_sge = &_base_build_nodata_sge;
	ioa->sge_size_ieee = sizeof(SSI2IeeeSgeSimple64_t);

	if (ioa->total_irq == 1)
		ioa->put_host_tag_id_default = &hst2dr_send_legacy_cmd_hal_api;
	else
		ioa->put_host_tag_id_default =
			&hst2dr_send_nvme_vendor_cmd_hal_api;
	ioa->put_host_tag_id_ioctl = &hst2dr_send_ioctl_cmd_hal_api;

	/*
	 * These function pointers for other requests that don't
	 * the require IEEE scatter gather elements.
	 *
	 * For example Configuration Pages and SAS IOUNIT Control don't.
	 */
	ioa->build_sg_ssi = &_base_build_sg;
	ioa->build_zero_len_sge_ssi = &_base_build_zero_len_sge;

	ioa->pinfo = kcalloc(ioa->info.num_ports,
		sizeof(struct hst2dr_port_info), GFP_KERNEL);
	if (!ioa->pinfo) {
		r = -ENOMEM;
		goto out_free_resources;
	}

	// sense only
	r = _base_allocate_memory_pools(ioa);
	if (r)
		goto out_free_resources;

	init_waitqueue_head(&ioa->reset_wq);
	/* allocate memory pd handle bitmask list */
	ioa->pd_handles_sz = (ioa->info.max_dev_handle / 8);
	if (ioa->info.max_dev_handle % 8)
		ioa->pd_handles_sz++;
	ioa->pd_handles = kzalloc(ioa->pd_handles_sz, GFP_KERNEL);
	if (!ioa->pd_handles) {
		r = -ENOMEM;
		goto out_free_resources;
	}
	/* allocate memory pd handle bitmask list */
	blocking_handles_sz = (ioa->info.max_dev_handle / 8);
	if (ioa->info.max_dev_handle % 8)
		blocking_handles_sz++;
	ioa->blocking_handles = kzalloc(blocking_handles_sz, GFP_KERNEL);
	if (!ioa->blocking_handles) {
		r = -ENOMEM;
		goto out_free_resources;
	}

	/* allocate memory for pending OS device add list */
	ioa->pend_os_device_add_sz = (ioa->info.max_dev_handle / 8);
	if (ioa->info.max_dev_handle % 8)
		ioa->pend_os_device_add_sz++;
	ioa->pend_os_device_add =
		kzalloc(ioa->pend_os_device_add_sz, GFP_KERNEL);
	if (!ioa->pend_os_device_add)
		goto out_free_resources;

	ioa->device_remove_in_progress_sz = ioa->pend_os_device_add_sz;
	ioa->device_remove_in_progress =
		kzalloc(ioa->device_remove_in_progress_sz, GFP_KERNEL);
	if (!ioa->device_remove_in_progress)
		goto out_free_resources;

	/* base internal command bits */
	mutex_init(&ioa->base_cmds.mutex);
	ioa->base_cmds.reply = kzalloc(ioa->reply_sz, GFP_KERNEL);
	ioa->base_cmds.status = HST2DR_CMD_NOT_USED;

	/* port_enable command bits */
	ioa->port_enable_cmds.reply = kzalloc(ioa->reply_sz, GFP_KERNEL);
	ioa->port_enable_cmds.status = HST2DR_CMD_NOT_USED;

	/* transport internal command bits */
	ioa->transport_cmds.reply = kzalloc(ioa->reply_sz, GFP_KERNEL);
	ioa->transport_cmds.status = HST2DR_CMD_NOT_USED;
	mutex_init(&ioa->transport_cmds.mutex);

	/* task management internal command bits */
	ioa->tm_cmds.reply = kzalloc(ioa->reply_sz, GFP_KERNEL);
	ioa->tm_cmds.status = HST2DR_CMD_NOT_USED;
	mutex_init(&ioa->tm_cmds.mutex);

	/* config page internal command bits */
	ioa->config_cmds.reply = kzalloc(ioa->reply_sz, GFP_KERNEL);
	ioa->config_cmds.status = HST2DR_CMD_NOT_USED;
	mutex_init(&ioa->config_cmds.mutex);

	/* ctl module internal command bits */
	ioa->ctl_cmds.reply = kzalloc(ioa->reply_sz, GFP_KERNEL);
	ioa->ctl_cmds.sense = kzalloc(SCSI_SENSE_BUFFERSIZE, GFP_KERNEL);
	ioa->ctl_cmds.status = HST2DR_CMD_NOT_USED;
	mutex_init(&ioa->ctl_cmds.mutex);

	if (!ioa->base_cmds.reply || !ioa->port_enable_cmds.reply ||
			!ioa->transport_cmds.reply ||
			!ioa->tm_cmds.reply || !ioa->config_cmds.reply ||
			!ioa->ctl_cmds.reply || !ioa->ctl_cmds.sense) {
		r = -ENOMEM;
		goto out_free_resources;
	}

	for (i = 0; i < SSI2_EVENT_NOTIFY_EVENTMASK; i++)
		ioa->event_masks[i] = -1;

	/* here we enable the events we care about */
	_base_unmask_events(ioa, SSI2_EVENT_SAS_DISCOVERY);
	_base_unmask_events(ioa, SSI2_EVENT_SAS_BROADCAST_PRIMITIVE);
	_base_unmask_events(ioa, SSI2_EVENT_SAS_TOPOLOGY_CHANGE_LIST);
	_base_unmask_events(ioa, SSI2_EVENT_SAS_DEVICE_STATUS_CHANGE);
	_base_unmask_events(ioa, SSI2_EVENT_SAS_ENCL_DEVICE_STATUS_CHANGE);

	r = hst2dr_init_nvme_io_queue_hal_api(ioa);
	if (r)
		goto out_free_resources;
	r = _base_make_ioa_operational(ioa);
	if (r)
		goto out_free_resources;

	ioa->non_operational_loop = 0;
	ioa->got_task_abort_from_ioctl = 0;
	return 0;

out_free_resources:

	ioa->remove_host = 1;
	log_error(ioa, "%s fail, free resources\n", __func__);
	hst2dr_base_free_resources(ioa);
	_base_release_memory_pools(ioa);
	pci_set_drvdata(ioa->pdev, NULL);
	kfree(ioa->cpu_msix_table);
	kfree(ioa->blocking_handles);
	kfree(ioa->device_remove_in_progress);
	kfree(ioa->pend_os_device_add);
	kfree(ioa->tm_cmds.reply);
	kfree(ioa->transport_cmds.reply);
	kfree(ioa->config_cmds.reply);
	kfree(ioa->base_cmds.reply);
	kfree(ioa->port_enable_cmds.reply);
	kfree(ioa->ctl_cmds.reply);
	kfree(ioa->ctl_cmds.sense);
	kfree(ioa->pinfo);
	kfree(ioa->pd_handles);
	ioa->ctl_cmds.reply = NULL;
	ioa->base_cmds.reply = NULL;
	ioa->tm_cmds.reply = NULL;
	ioa->transport_cmds.reply = NULL;
	ioa->config_cmds.reply = NULL;
	ioa->pinfo = NULL;
	return r;
}


/**
 * hst2dr_base_detach - remove controller instance
 * @ioa: per adapter object
 *
 * Return nothing.
 */
void
hst2dr_base_detach(struct HST2DR_ADAPTER *ioa)
{
	hst2dr_base_stop_watchdog(ioa);
	hst2dr_base_free_resources(ioa);
	_base_release_memory_pools(ioa);
	hst2dr_hal_free_resources_hal_api(ioa);

	pci_set_drvdata(ioa->pdev, NULL);
	kfree(ioa->cpu_msix_table);
	kfree(ioa->blocking_handles);
	kfree(ioa->device_remove_in_progress);
	kfree(ioa->pend_os_device_add);
	kfree(ioa->pinfo);
	kfree(ioa->pd_handles);
	kfree(ioa->ctl_cmds.reply);
	kfree(ioa->ctl_cmds.sense);
	kfree(ioa->base_cmds.reply);
	kfree(ioa->port_enable_cmds.reply);
	kfree(ioa->tm_cmds.reply);
	kfree(ioa->transport_cmds.reply);
	kfree(ioa->config_cmds.reply);
}

/**
 * _base_reset_handler - reset callback handler (for base)
 * @ioa: per adapter object
 * @reset_phase: phase
 *
 * The handler for doing any required cleanup or initialization.
 *
 * The reset phase can be HST2DR_IOA_PRE_RESET, HST2DR_IOA_AFTER_RESET,
 * HST2DR_IOA_DONE_RESET
 *
 * Return nothing.
 */
static void
_base_reset_handler(struct HST2DR_ADAPTER *ioa, int reset_phase)
{
	hst2dr_scsih_reset_handler(ioa, reset_phase);
	hst2dr_ctl_reset_handler(ioa, reset_phase);
	switch (reset_phase) {
	case HST2DR_IOA_PRE_RESET:
		break;
	case HST2DR_IOA_AFTER_RESET:
		if (ioa->transport_cmds.status & HST2DR_CMD_PENDING) {
			ioa->transport_cmds.status |= HST2DR_CMD_RESET;
			hst2dr_base_free_host_tag_id(ioa,
					ioa->transport_cmds.host_tag_id);
			complete(&ioa->transport_cmds.done);
		}
		if (ioa->base_cmds.status & HST2DR_CMD_PENDING) {
			ioa->base_cmds.status |= HST2DR_CMD_RESET;
			hst2dr_base_free_host_tag_id(ioa,
					ioa->base_cmds.host_tag_id);
			complete(&ioa->base_cmds.done);
		}
		if (ioa->port_enable_cmds.status & HST2DR_CMD_PENDING) {
			ioa->port_enable_failed = 1;
			ioa->port_enable_cmds.status |= HST2DR_CMD_RESET;
			hst2dr_base_free_host_tag_id(ioa,
					ioa->port_enable_cmds.host_tag_id);
			if (ioa->is_driver_loading) {
				ioa->start_scan_failed =
					SSI2_IOASTATUS_INTERNAL_ERROR;
				ioa->start_scan = 0;
				ioa->port_enable_cmds.status =
					HST2DR_CMD_NOT_USED;
			} else
				complete(&ioa->port_enable_cmds.done);
		}
		if (ioa->config_cmds.status & HST2DR_CMD_PENDING) {
			ioa->config_cmds.status |= HST2DR_CMD_RESET;
			hst2dr_base_free_host_tag_id(ioa,
					ioa->config_cmds.host_tag_id);
			ioa->config_cmds.host_tag_id = USHRT_MAX;
			complete(&ioa->config_cmds.done);
		}
		break;
	case HST2DR_IOA_DONE_RESET:
		break;
	}
}

/**
 * hst2dr_wait_for_commands_to_complete - reset controller wait complete
 * @ioa: Pointer to HST2DR_ADAPTER structure
 *
 * This function waiting(3s) for all pending commands to complete
 * prior to putting controller in reset.
 */
void
hst2dr_wait_for_commands_to_complete(struct HST2DR_ADAPTER *ioa)
{
	u32 ioa_state;
	int i;


	ioa_state = hst2dr_base_get_ioastate(ioa, 0);
	if ((ioa_state & SSI2_IOA_STATE_MASK) != SSI2_IOA_STATE_OPERATIONAL)
		return;

	/* pending command count */
	ioa->pending_io_count = scsi_host_busy(ioa->shost);

	if (!ioa->pending_io_count)
		return;

	/* wait for pending commands to complete */
	for (i = 0; i < IO_COMPLETION_WAITING; i++) {
		msleep(1000);
		ioa->pending_io_count = scsi_host_busy(ioa->shost);
		if (!ioa->pending_io_count)
			return;
	}
}

/**
 * hst2dr_base_hard_reset_handler - reset controller handler
 * @ioa: Pointer to HST2DR_ADAPTER structure
 * @type: HARD_RESET or SOFT_RESET or AER_RESET or AER_RESET_IS
 *
 * Returns 0 for success, non-zero for failure.
 */
int
hst2dr_base_hard_reset_handler(struct HST2DR_ADAPTER *ioa,
	enum reset_type type, u32 res)
{
	int r;
	unsigned long flags;

	if (ioa->pci_error_recovery) {
		log_error(ioa, "%s: pci error recovery reset\n",
			__func__);
		r = 0;
		goto out_unlocked;
	}


	/* wait for an active reset in progress to complete */
	if (!mutex_trylock(&ioa->reset_in_progress_mutex)) {
		log_debug(ioa,
				"reset type:%d is blocked due to another reset in progress\n",
				type);
		if ((ioa->ioa_reset_in_progress & 4) == 4)
			return 0;
		do {
			ssleep(1);
		} while ((ioa->ioa_reset_in_progress & 1) == 1);
		log_debug(ioa, "reset type:%d return recent status:%x",
				type, ioa->recent_reset_status);
		return ioa->recent_reset_status;
	}

	spin_lock_irqsave(&ioa->ioa_reset_in_progress_lock, flags);
	ioa->shost_recovery = 1;
	ioa->ioa_reset_in_progress |= 1;
	ioa->recent_reset_status = -EFAULT;
	spin_unlock_irqrestore(&ioa->ioa_reset_in_progress_lock, flags);
	hst2dr_write_direct_reg_hal_api(ioa, NVME_REG_HR_RES, res);
	log_always(ioa, "reset type:%d res:%d\n", type, res);
	msleep(1000);
	_base_reset_handler(ioa, HST2DR_IOA_PRE_RESET);
	hst2dr_wait_for_commands_to_complete(ioa);
	log_debug(ioa, "pending_io_count:0x%x\n", ioa->pending_io_count);

	_base_mask_interrupts(ioa);
	ioa->ioa_reset_in_progress |= 2;
	msleep(100);
	_base_reset_handler(ioa, HST2DR_IOA_AFTER_RESET);
	r = _base_make_ioa_ready(ioa, type);
	if (r)
		goto out;

	/* If this hard reset is called while port enable is active, then
	 * there is no reason to call make_ioa_operational
	 */
	if (ioa->is_driver_loading && ioa->port_enable_failed) {
		ioa->remove_host = 1;
		r = -EFAULT;
		goto out;
	}

	r = _base_make_ioa_operational(ioa);
	if (!r)
		_base_reset_handler(ioa, HST2DR_IOA_DONE_RESET);

out:
	spin_lock_irqsave(&ioa->ioa_reset_in_progress_lock, flags);
	ioa->shost_recovery = 0;
	spin_unlock_irqrestore(&ioa->ioa_reset_in_progress_lock, flags);
	ioa->ioa_reset_count++;
	ioa->recent_reset_status = r;
	if (!r)
		ioa->ioa_reset_in_progress = 0;

	mutex_unlock(&ioa->reset_in_progress_mutex);

out_unlocked:
	return r;
}
