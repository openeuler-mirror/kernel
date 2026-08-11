// SPDX-License-Identifier: GPL-2.0
/*
 * Management Module Support for hst2dr based controllers
 *
 * This code is based on drivers/scsi/hst2dr/hst2dr_ctl.c

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
#include <linux/version.h>
#include <linux/module.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/pci.h>
#include <linux/delay.h>
#include <linux/compat.h>
#include <linux/poll.h>

#include <linux/io.h>
#include <linux/uaccess.h>

#include "hst2dr_base.h"
#include "hst2dr_ctl.h"
#include "hst2dr_comm.h"
#include "hst2dr_debug.h"
#include "hst2dr_hal.h"

static DECLARE_WAIT_QUEUE_HEAD(ctl_poll_wait);


/**
 * enum block_state - blocking state
 * @NON_BLOCKING: non blocking
 * @BLOCKING: blocking
 *
 * These states are for ioctls that need to wait for a response
 * from firmware, so they probably require sleep.
 */
enum block_state {
	NON_BLOCKING,
	BLOCKING,
};

/**
 * _ctl_sas_device_find_by_handle - sas device search
 * @ioa: per adapter object
 * @handle: sas device handle (assigned by firmware)
 * Context: Calling function should acquire ioa->sas_device_lock
 *
 * This searches for sas_device based on sas_address, then return sas_device
 * object.
 */
static struct _sas_device *
_ctl_sas_device_find_by_handle(struct HST2DR_ADAPTER *ioa, u16 handle)
{
	struct _sas_device *sas_device, *r;

	r = NULL;
	list_for_each_entry(sas_device, &ioa->sas_device_list, list) {
		if (sas_device->handle != handle)
			continue;
		r = sas_device;
		goto out;
	}

 out:
	return r;
}

/**
 * _ctl_display_some_debug - debug routine
 * @ioa: per adapter object
 * @host_tag_id: request message index
 * @calling_function_name: string pass from calling function
 * @ssi_reply: reply message frame
 * Context: none.
 *
 * Function for displaying debug info helpful when debugging issues
 * in this module.
 */
static void
_ctl_display_some_debug(struct HST2DR_ADAPTER *ioa, u16 host_tag_id,
	char *calling_function_name, SSI2_DEFAULT_REPLY *ssi_reply)
{
	SSI2_INQUIRY_PAGE_REQUEST *ssi_request;
	char *desc = NULL;

	ssi_request = hst2dr_base_get_msg_frame(ioa, host_tag_id);
	switch (ssi_request->opcode) {
	case SSI2_FUNCTION_SCSI_IO:
	{
		SSI2_SCSI_REQUEST *scsi_request =
			(SSI2_SCSI_REQUEST *)ssi_request;

		snprintf(ioa->tmp_string, HST2DR_STRING_LENGTH,
			"scsi_io, cmd(0x%02x), cdb_len(%d), cdb_len(%d)",
			scsi_request->cdb.cdb[0],
			le16_to_cpu(scsi_request->cdb_len) & 0xF,
			le16_to_cpu(scsi_request->cdb_len));
		desc = ioa->tmp_string;
		break;
	}
	case SSI2_FUNCTION_SCSI_TASK_MANAGE:
		desc = "task_mgmt";
		break;
	case SSI2_FUNCTION_IOA_INIT:
		desc = "ioa_init";
		break;
	case SSI2_FUNCTION_IOA_INFO:
		desc = "ioa_info";
		break;
	case SSI2_FUNCTION_CONFIG:
	{
		SSI2_INQUIRY_PAGE_REQUEST *cfg_request =
			(SSI2_INQUIRY_PAGE_REQUEST *)ssi_request;

		snprintf(ioa->tmp_string, HST2DR_STRING_LENGTH,
			"config, type(0x%02x), number(%d)",
			cfg_request->header.type,
			cfg_request->header.number);
		desc = ioa->tmp_string;
		break;
	}
	case SSI2_FUNCTION_PORT_ENABLE:
		desc = "port_enable";
		break;
	case SSI2_FUNCTION_EVENT:
		desc = "event_notification";
		break;
	case SSI2_FUNCTION_FW_DOWNLOAD:
		desc = "fw_download";
		break;
	case SSI2_FUNCTION_FW_UPLOAD:
		desc = "fw_upload";
		break;
	case SSI2_FUNCTION_SAS_UNIT:
		desc = "sas_iounit_cntl";
		break;
/*
 *	case SSI2_FUNCTION_SATA_PASSTHROUGH:
 *		desc = "sata_pass";
 *		break;
 */
	case SSI2_FUNCTION_SMP_PASSTHROUGH:
		desc = "smp_passthrough";
		break;
	}

	if (!desc)
		return;

	log_config(ioa, "%s: %s, host_tag_id(%d)\n",
		calling_function_name, desc, host_tag_id);

	if (!ssi_reply)
		return;

	if (ssi_reply->status || ssi_reply->log_info)
		log_config(ioa,
			"\tioastatus(0x%04x), loginfo(0x%08x)\n",
			le16_to_cpu(ssi_reply->status),
			le32_to_cpu(ssi_reply->log_info));

	if (ssi_request->opcode == SSI2_FUNCTION_SCSI_IO) {
		SSI2_SCSI_IO_REPLY *scsi_reply =
			(SSI2_SCSI_IO_REPLY *)ssi_reply;
		struct _sas_device *sas_device = NULL;
		unsigned long flags;

		spin_lock_irqsave(&ioa->sas_device_lock, flags);
		sas_device = _ctl_sas_device_find_by_handle(ioa,
			le16_to_cpu(scsi_reply->dev_handle));
		if (sas_device) {
			log_warn(ioa, "\tsas_address(0x%016llx), phy(%d)\n",
				(unsigned long long)
				sas_device->sas_address, sas_device->phy);
			log_warn(ioa,
				"\tenclosure_logical_id(0x%016llx), slot(%d)\n",
				(unsigned long long)
				sas_device->enclosure_logical_id,
				sas_device->slot);
		}
		spin_unlock_irqrestore(&ioa->sas_device_lock, flags);
		if (scsi_reply->scsi_state || scsi_reply->scsi_status)
			log_config(ioa,
				"\tscsi_state(0x%02x), scsi_status(0x%02x)\n",
				scsi_reply->scsi_state,
				scsi_reply->scsi_status);
	}
}

/**
 * hst2dr_ctl_done - ctl module completion routine
 * @ioa: per adapter object
 * @cqe: completion queue entity
 * Context: none.
 *
 * The callback handler when using ioa->ctl_cb_idx.
 *
 * Return 1 meaning mf should be freed from _base_interrupt
 *	0 means the mf is freed from this function.
 */
u8
hst2dr_ctl_done(struct HST2DR_ADAPTER *ioa, hst2dr_nvme_completion *cqe)
{
	SSI2_DEFAULT_REPLY *ssi_reply = NULL;
	SSI2_SCSI_IO_REPLY *scsiio_reply;
	const void *sense_data;
	u32 sz;

	if (ioa->ctl_cmds.status == HST2DR_CMD_NOT_USED)
		return 1;
	if (ioa->ctl_cmds.host_tag_id != cqe->host_tag_id)
		return 1;
	ioa->ctl_cmds.status |= HST2DR_CMD_COMPLETE;
	if (cqe->ctrl.description == SSI2_RPY_DESCRIPT_FLAGS_ADDRESS_REPLY)
		ssi_reply = hst2dr_base_get_reply_virt_addr(ioa, cqe->reply_id);
	if (ssi_reply) {
		ssi_reply->status = cqe->ctrl.status;
		memcpy(ioa->ctl_cmds.reply, ssi_reply,
			min_t(u8, ssi_reply->msg_len * 4, 128));
		if (ssi_reply->msg_len == 0)
			ioa->ctl_cmds.status |= HST2DR_CMD_NOT_USED;
		else
			ioa->ctl_cmds.status |= HST2DR_CMD_REPLY_VALID;
		/* get sense data */
		if (ssi_reply->opcode == SSI2_FUNCTION_SCSI_IO ||
				ssi_reply->opcode ==
				SSI2_FUNCTION_RAID_SCSI_IO_PASSTHROUGH) {
			scsiio_reply = (SSI2_SCSI_IO_REPLY *)ssi_reply;
			if (scsiio_reply->scsi_state &
					SSI2_SCSI_STATE_AUTOSENSE_VALID) {
				sz = min_t(u32, SCSI_SENSE_BUFFERSIZE,
					le32_to_cpu(scsiio_reply->sense_count));
				sense_data = hst2dr_base_get_sense_buffer(ioa,
					scsiio_reply->sense_id);
				memcpy(ioa->ctl_cmds.sense, sense_data, sz);
				debug_dump_mem("ctl_cmd.sense",
					ioa->ctl_cmds.sense, sz);
			}
		}
	} else if (cqe->ctrl.status == SSI2_IOASTATUS_SUCCESS) {
		ioa->ctl_cmds.status |= HST2DR_CMD_REPLY_VALID;
		memset(ioa->ctl_cmds.reply, 0, ioa->reply_sz);
		ssi_reply = (SSI2_DEFAULT_REPLY *)ioa->ctl_cmds.reply;
		ssi_reply->status = cqe->ctrl.status;
	}

	_ctl_display_some_debug(ioa, cqe->host_tag_id, "ctl_done", ssi_reply);
	ioa->ctl_cmds.status &= ~HST2DR_CMD_PENDING;
	complete(&ioa->ctl_cmds.done);
	return 1;
}

/**
 * _ctl_verify_adapter - validates ioa_number passed from application
 * @ioa: per adapter object
 * @ioapp: The ioa pointer is returned in this.
 * @ssi_version: will be SSI2_VERSION for hst2ctl ioctl device
 *
 * Return (-1) means error, else ioa_number.
 */
static int
_ctl_verify_adapter(int ioa_number, struct HST2DR_ADAPTER **ioapp,
							int ssi_version)
{
	struct HST2DR_ADAPTER *ioa;

	/* global ioa lock to protect controller on list operations */
	spin_lock(&gioa_lock);
	list_for_each_entry(ioa, &hst2dr_ioa_list, list) {
		if (ioa->id != ioa_number)
			continue;

		spin_unlock(&gioa_lock);
		*ioapp = ioa;
		return ioa_number;
	}
	spin_unlock(&gioa_lock);
	*ioapp = NULL;
	return -1;
}

/**
 * hst2dr_ctl_reset_handler - reset callback handler (for ctl)
 * @ioa: per adapter object
 * @reset_phase: phase
 *
 * The handler for doing any required cleanup or initialization.
 *
 * The reset phase can be HST2DR_IOA_PRE_RESET, HST2DR_IOA_AFTER_RESET,
 * HST2DR_IOA_DONE_RESET
 */
void
hst2dr_ctl_reset_handler(struct HST2DR_ADAPTER *ioa, int reset_phase)
{
	switch (reset_phase) {
	case HST2DR_IOA_PRE_RESET:
		break;
	case HST2DR_IOA_AFTER_RESET:
		if (ioa->ctl_cmds.status & HST2DR_CMD_PENDING) {
			ioa->ctl_cmds.status |= HST2DR_CMD_RESET;
			hst2dr_base_free_host_tag_id(ioa, ioa->ctl_cmds.host_tag_id);
			complete(&ioa->ctl_cmds.done);
		}
		break;
	case HST2DR_IOA_DONE_RESET:
		break;

	}
}
/**
 * _ctl_poll -
 * @file -
 * @wait -
 *
 */
static unsigned int
_ctl_poll(struct file *filep, poll_table *wait)
{
	struct HST2DR_ADAPTER *ioa;

	poll_wait(filep, &ctl_poll_wait, wait);

	/* global ioa lock to protect controller on list operations */
	spin_lock(&gioa_lock);
	list_for_each_entry(ioa, &hst2dr_ioa_list, list) {
		if (ioa->aen_event_read_flag) {
			spin_unlock(&gioa_lock);
			return POLLIN | POLLRDNORM;
		}
	}
	spin_unlock(&gioa_lock);
	return 0;
}

u8
hst2dr_ctl_event_callback(struct HST2DR_ADAPTER *ioa, hst2dr_nvme_completion *cqe)
{
	SSI2_EVENT_NOTIFICATION_REPLY *ssi_reply = NULL;

	if (cqe->ctrl.description == SSI2_RPY_DESCRIPT_FLAGS_ADDRESS_REPLY)
		ssi_reply = hst2dr_base_get_reply_virt_addr(ioa, cqe->reply_id);

	return 1;
}

/**
 * _ctl_set_task_mid - assign an active host_tag_id to tm request
 * @ioa: per adapter object
 * @karg - (struct hst2dr_ioctl_command)
 * @tm_request - pointer to mf from user space
 *
 * Returns 0 when an host_tag_id if found, else fail.
 * during failure, the reply frame is filled.
 */
static int
_ctl_set_task_mid(struct HST2DR_ADAPTER *ioa, struct hst2dr_ioctl_command *karg,
	SSI2_SCSI_TM_REQUEST *tm_request)
{
	u8 found = 0;
	u16 i;
	u16 handle;
	struct scsi_cmnd *scmd;
	struct HST2DR_DEVICE *priv_data;
	SSI2_SCSI_TM_REPLY *tm_reply;
	u32 sz;
	u32 lun;
	char *desc = NULL;

	if (tm_request->task_type == SSI2_SCSITASKMGMT_TASKTYPE_ABORT_TASK)
		desc = "abort_task";
	else if (tm_request->task_type == SSI2_SCSITASKMGMT_TASKTYPE_QUERY_TASK)
		desc = "query_task";
	else
		return 0;

	lun = scsilun_to_int((struct scsi_lun *)tm_request->lun);

	handle = le16_to_cpu(tm_request->dev_handle);
	spin_lock(&ioa->scsi_lookup_lock);
	for (i = ioa->scsiio_depth; i && !found; i--) {
		scmd = _hst2dr_scsi_lookup_get(ioa, i);
		if (scmd == NULL || scmd->device == NULL ||
			scmd->device->hostdata == NULL)
			continue;
		if (lun != scmd->device->lun)
			continue;
		priv_data = scmd->device->hostdata;
		if (priv_data->sas_target == NULL)
			continue;
		if (priv_data->sas_target->handle != handle)
			continue;
		tm_request->task_manage_id = cpu_to_le16(ioa->scsi_lookup[i - 1].host_tag_id);
		found = 1;
	}
	spin_unlock(&ioa->scsi_lookup_lock);

	if (!found) {
		tm_reply = ioa->ctl_cmds.reply;
		tm_reply->dev_handle = tm_request->dev_handle;
		tm_reply->opcode = SSI2_FUNCTION_SCSI_TASK_MANAGE;
		tm_reply->task_type = tm_request->task_type;
		tm_reply->msg_len = sizeof(SSI2_SCSI_TM_REPLY) / 4;
		sz = min_t(u32, karg->max_reply_bytes, ioa->reply_sz);
		if (copy_to_user(karg->reply_frame_buf_ptr, ioa->ctl_cmds.reply,
				sz))
			log_error(ioa, "failure at %s:%d/%s()!\n",
				__FILE__, __LINE__, __func__);
		return 1;
	}

	return 0;
}
struct cfg_request {
	u16			sz;
	void			*page;
	dma_addr_t		page_dma;
};

static void *allocate_memory(struct HST2DR_ADAPTER *ioa, ssize_t sz,
	dma_addr_t *dma_addr)
{
	void *ptr = NULL;
	dma_addr_t dma_addr_tmp;

	ptr = dma_alloc_coherent(&ioa->pdev->dev, sz, &dma_addr_tmp, GFP_KERNEL);
	if (!ptr) {
		log_error(ioa, "%s: failed to allocate %zd bytes of memory\n",
			__func__, sz);
	return NULL;
	}

	*dma_addr = dma_addr_tmp;

	return ptr;
}

static void free_memory(struct HST2DR_ADAPTER *ioa, void *ptr,
	dma_addr_t dma_addr, ssize_t sz)
{
	if (ptr)
		dma_free_coherent(&ioa->pdev->dev, sz, ptr, dma_addr);
}

static int check_handle_is_valid(struct HST2DR_ADAPTER *ioa, u16 handle)
{
	if (!handle || (handle > ioa->info.max_dev_handle)) {
		log_error(ioa, "%s: handle is zero\n", __func__);
		return -EINVAL;
	}
	if (test_bit(handle, ioa->device_remove_in_progress)) {
		log_error(ioa, "%s: handle %u is already in use\n",
			__func__, handle);
		return -EINVAL;
	}

	return 0;
}

/**
 * _ctl_do_hst2dr_command - main handler for HST2DR COMMAND opcode
 * @ioa: per adapter object
 * @karg - (struct hst2dr_ioctl_command)
 * @mf - pointer to mf in user space
 */
static long
_ctl_do_hst2dr_command(struct HST2DR_ADAPTER *ioa,
	struct hst2dr_ioctl_command karg, void __user *mf)
{
	SSI2_REQUEST_HEADER  *request;
	SSI2_DEFAULT_REPLY *ssi_reply;
	int wait_counts = 0;
	hst2dr_command *scmd;
	ssize_t data_out_sz;
	ssize_t data_in_sz;
	ssize_t sz;
	U16 host_tag_id;
	struct cfg_request mem;
	long ret = 0;
	U8 opcode;
	void *data_out = NULL;
	dma_addr_t data_out_dma = 0;
	void *data_in = NULL;
	dma_addr_t data_in_dma = 0;
	void *psge = NULL;
	int timeout;
	int issue_reset = 0;
	U8 dont_free_id = 0;
	U8 opflags = 0;
	U8 flag = 0;
	u16 dev_handle;
#define FLAG_USE_OTHER_CMD 0x01
#define FLAG_USE_STANDARD_SG 0x20
#define FLAG_USE_SSI_SG 0x40

	if (ioa->ctl_cmds.status != HST2DR_CMD_NOT_USED) {
		ret = -EBUSY;
		goto out;
	}

	while (hst2dr_base_get_ioastate(ioa, 1) != SSI2_IOA_STATE_OPERATIONAL) {
		// Wait for the IOA to become operational
		if (wait_counts++  == 10) {
			ret = -EFAULT;
			goto out;
		}
		log_ctrl(ioa, "%s: waiting for operational state(count=%d)\n",
			__func__, wait_counts);
		msleep(100);
	}

	if (get_user(opcode, (char __user *)mf)) {
		log_error(ioa, "%s: failed to get opcode from user space\n", __func__);
		ret = -EFAULT;
		goto out;
	}

	switch (opcode) {
	case SSI2_FUNCTION_SCSI_IO:
	case SSI2_FUNCTION_RAID_SCSI_IO_PASSTHROUGH:
		host_tag_id = ioa->scsiio_depth - INTERNAL_SCSIIO_CMDS_COUNT + 1;
		break;
	default:
		host_tag_id = hst2dr_base_get_host_tag_id(ioa, ioa->ctl_cb_idx);
	break;
	}

	if (host_tag_id == NO_HOST_TAG_ID) {
		log_error(ioa, "%s: failed to get host id\n", __func__);
		ret = -EAGAIN;
		goto out;
	}

	if (unlikely(karg.data_sge_offset * 4 > ioa->request_sz - 0x10 ||
		karg.data_sge_offset > (UINT_MAX / 4))) {
		log_error(ioa, "%s: invalid data_sge_offset %u\n",
			__func__, karg.data_sge_offset);
		ret = -EINVAL;
		goto out;
	} else {
		request = hst2dr_base_get_msg_frame(ioa, host_tag_id);
		scmd = (hst2dr_command *)request;
		memset(scmd, 0, sizeof(hst2dr_command));
		if (copy_from_user(scmd, mf, karg.data_sge_offset * 4)) {
			log_error(ioa, "%s: failed to copy request from user space\n",
				__func__);
			ret = -EFAULT;
			goto free_host_tag_id;
		}
	}

	ioa->ctl_cmds.status = HST2DR_CMD_PENDING;
	memset(ioa->ctl_cmds.reply, 0, ioa->reply_sz);
	memset(ioa->ctl_cmds.sense, 0, SCSI_SENSE_BUFFERSIZE);
	ioa->ctl_cmds.host_tag_id = host_tag_id;
	data_out_sz = karg.data_out_size;
	data_in_sz = karg.data_in_size;

	if (data_out_sz) {
		data_out = allocate_memory(ioa, data_out_sz, &data_out_dma);
		if (data_out == NULL) {
			log_error(ioa, "%s: failed to allocate data_out memory\n",
				__func__);
			ret = -ENOMEM;
			goto free_host_tag_id;
		}

		if (copy_from_user(data_out, (void __user *)karg.data_out_buf_ptr,
			data_out_sz)) {
			log_error(ioa, "%s: failed to copy data_out from user space\n",
				__func__);
			ret = -EFAULT;
			goto free_data_out;
		}
	}

	if (data_in_sz) {
		data_in = allocate_memory(ioa, data_in_sz, &data_in_dma);
		if (data_in == NULL) {
			log_error(ioa, "%s: failed to allocate data_in memory\n",
				__func__);
			ret = -ENOMEM;
			goto free_data_out;
		}
	}

	psge = (void *)&scmd->cmd.internal.cmd + (karg.data_sge_offset * 4);

	switch (opcode) {
	case SSI2_FUNCTION_SCSI_IO:
	case SSI2_FUNCTION_RAID_SCSI_IO_PASSTHROUGH:
		{
		hst2dr_vendor_cmd *vc = (hst2dr_vendor_cmd *)scmd;

		dev_handle = le16_to_cpu(scmd->cmd.io.logical_dev_id);

		if (_hst2dr_get_device_is_block(ioa, dev_handle)) {
			log_error(ioa, "%s: device with handle %u is blocked\n",
				__func__, dev_handle);
			goto free_data_out;
		}

		vc->host_tag_id = le16_to_cpu(host_tag_id);
		if (check_handle_is_valid(ioa, dev_handle) != 0) {
			hst2dr_base_free_host_tag_id(ioa, host_tag_id);
			ret = -EINVAL;
			goto free_data_out;
		}
		flag = FLAG_USE_STANDARD_SG;
		goto passthrough;
		break;
		}
	case SSI2_FUNCTION_SCSI_TASK_MANAGE:
		{
		SSI2_SCSI_TM_REQUEST *tm_request = (SSI2_SCSI_TM_REQUEST *)scmd;

		dev_handle = le16_to_cpu(tm_request->dev_handle);

		if (tm_request->task_type == SSI2_SCSITASKMGMT_TASKTYPE_ABORT_TASK
				 || tm_request->task_type ==
				 SSI2_SCSITASKMGMT_TASKTYPE_QUERY_TASK) {
			ioa->got_task_abort_from_ioctl = 1;
			if (_ctl_set_task_mid(ioa, &karg, tm_request)) {
				ioa->got_task_abort_from_ioctl = 0;
				log_error(ioa, "%s: failed to set task mid\n", __func__);
				ret = -EINVAL;
				goto free_data_out;
			}
		}
		if (check_handle_is_valid(ioa, dev_handle) != 0) {
			ret = -EINVAL;
			goto free_data_out;
		}

		hst2dr_set_tm_flag(ioa, le16_to_cpu(tm_request->dev_handle));
		flag = FLAG_USE_SSI_SG;

		opflags = cmd_flag_fw_mode_admin | HI_PRIORITY;
		scmd->cmd.internal.cmd.head.request_flags =
				SSI2_REQ_DESCRIPT_FLAGS_HIGH_PRIORITY;
		break;
		}
	case SSI2_FUNCTION_SMP_PASSTHROUGH:
		{
		SSI2_SMP_PASSTHROUGH_REQUEST *smp_request =
		(SSI2_SMP_PASSTHROUGH_REQUEST *)request;
		U8 *data;

		if (smp_request->passthrough_flags &
			SSI2_SMP_PT_REQ_PT_FLAGS_IMMEDIATE)
			data = (U8 *)&smp_request->sgl;
		else {
			if (unlikely(data_out == NULL)) {
				log_error(ioa, "failure at %s:%d/%s()!\n",
					__FILE__, __LINE__, __func__);
				ret = -EINVAL;
				goto free_data_out;
			}
			data = data_out;
		}

		if (data[1] == 0x91 && (data[10] == 1 || data[10] == 2)) {
			ioa->ioa_link_reset_in_progress = 1;
			ioa->ignore_loginfos = 1;
		}
		flag = FLAG_USE_STANDARD_SG;
		opflags = cmd_flag_hw_mode;

		break;
		}
	case SSI2_FUNCTION_SAS_UNIT:
		{
		SSI2_SAS_UNIT_CONTROL_REQUEST *sasiounit_request =
			(SSI2_SAS_UNIT_CONTROL_REQUEST *)request;

		if (sasiounit_request->operation == SSI2_SAS_OP_PHY_HARD_RESET
				|| sasiounit_request->operation ==
				SSI2_SAS_OP_PHY_LINK_RESET) {
			ioa->ioa_link_reset_in_progress = 1;
			ioa->ignore_loginfos = 1;
		}
		break;
		}
	case SSI2_FUNCTION_CONFIG:
		{
		memset(&mem, 0, sizeof(struct cfg_request));
		mem.sz = data_out_sz ? data_out_sz : data_in_sz;
			log_ctrl(ioa, "%s: data_out_sz = %zd, data_in_sz = %zd\n",
				__func__, data_out_sz, data_in_sz);
		mem.page = allocate_memory(ioa, mem.sz, &mem.page_dma);
		if (mem.page == NULL) {
			log_error(ioa, "%s: failed to allocate config page memory\n",
					 __func__);
			ret = -ENOMEM;
			goto free_data_out;
		}
		if (data_out_sz)
			memcpy(mem.page, data_out, min_t(u16, mem.sz, data_out_sz));

		opflags = cmd_flag_fw_mode_admin;
		flag = FLAG_USE_OTHER_CMD;
		scmd->cmd.internal.cmd.cfg_request.sge.len = mem.sz;
		scmd->cmd.internal.cmd.cfg_request.sge.address =
				cpu_to_le64(mem.page_dma);
		scmd->cmd.internal.cmd.cfg_request.sge.flag =
				SSI2_IEEE_SGE_FLAGS_END_OF_LIST;
		break;
		}
	case SSI2_FUNCTION_FW_DOWNLOAD:
	case SSI2_FUNCTION_FW_UPLOAD:
		flag = FLAG_USE_STANDARD_SG;
		opflags = cmd_flag_fw_mode_admin;
		break;
		// fallthrough
	default:
		flag = FLAG_USE_SSI_SG;
		opflags = cmd_flag_fw_mode_admin;
		break;
	}

	scmd->cmd.internal.cmd.head.opflags = opflags;
	scmd->cmd.internal.cmd.head.host_tag_id = host_tag_id;
	scmd->cmd.internal.cmd.head.host_flag =
		(flag & FLAG_USE_OTHER_CMD) == 0 ? hst2dr_cmd_ctl :
		hst2dr_cmd_config;

passthrough:
	log_ctrl(ioa,
		"%s: %s = 0x%02x, opflags = %d, host_flag = %d, %s = %d\n",
		__func__, "scmd->cmd.internal.cmd.head.opcode",
		scmd->cmd.internal.cmd.head.opcode,
		scmd->cmd.internal.cmd.head.opflags,
		scmd->cmd.internal.cmd.head.host_flag,
		"host_tag_id", scmd->cmd.internal.cmd.head.host_tag_id);

	if (flag & FLAG_USE_STANDARD_SG) {
		log_ctrl(ioa, "%s: using standard SG\n", __func__);
	ioa->build_sg(ioa, psge, data_out_dma, data_out_sz, data_in_dma,
		data_in_sz);
	} else if (flag & FLAG_USE_SSI_SG) {
		log_ctrl(ioa, "%s: using SSI SG\n", __func__);
		ioa->build_sg_ssi(ioa, psge, data_out_dma, data_out_sz,
		data_in_dma, data_in_sz);
	}

	init_completion(&ioa->ctl_cmds.done);


	_ctl_display_some_debug(ioa, host_tag_id, "ctl_request", NULL);
	ioa->put_host_tag_id_ioctl(ioa, scmd);

	timeout = karg.timeout ?
		(karg.timeout > 60 ? 60 : karg.timeout) : HST2DR_IOCTL_DEFAULT_TIMEOUT;

	wait_for_completion_timeout(&ioa->ctl_cmds.done, timeout * HZ);
	log_ctrl(ioa, "ioa->ctl_cmds.status = 0x%02x\n", ioa->ctl_cmds.status);

	dont_free_id = 1;
	if (opcode == SSI2_FUNCTION_SCSI_TASK_MANAGE) {
		SSI2_SCSI_TM_REQUEST *tm_request = (SSI2_SCSI_TM_REQUEST *)request;

		hst2dr_clear_tm_flag(ioa, le16_to_cpu(tm_request->dev_handle));
	} else if ((opcode == SSI2_FUNCTION_SMP_PASSTHROUGH ||
		opcode == SSI2_FUNCTION_SAS_UNIT) && ioa->ioa_link_reset_in_progress) {
		ioa->ioa_link_reset_in_progress = 0;
		ioa->ignore_loginfos = 0;
	} else if (opcode == SSI2_FUNCTION_CONFIG) {
		memcpy(data_in, mem.page, data_in_sz);
		free_memory(ioa, mem.page, mem.page_dma, mem.sz);
	}

	if (!(ioa->ctl_cmds.status & HST2DR_CMD_COMPLETE)) {
		log_error(ioa, "%s: command timed out after %d seconds\n", __func__,
			timeout);
		ret = -ETIMEDOUT;
		if (!(ioa->ctl_cmds.status & HST2DR_CMD_RESET))
			issue_reset = 1;

		goto issue_host_reset;
	}

	ssi_reply = (SSI2_DEFAULT_REPLY *)ioa->ctl_cmds.reply;

	/* copy out xdata to user */
	if (data_in_sz) {
		if (copy_to_user((void __user *)karg.data_in_buf_ptr,
			data_in, data_in_sz)) {
			log_error(ioa, "%s: failed to copy data_in to user space\n",
				__func__);
			ret = -EFAULT;
			goto free_data_out;
		}
	}

	/* copy out reply message frame to user */
	if (karg.max_reply_bytes) {
		sz = min_t(ssize_t, karg.max_reply_bytes, ioa->reply_sz);
		if (copy_to_user((void __user *)karg.reply_frame_buf_ptr,
			ioa->ctl_cmds.reply, sz)) {
			log_error(ioa, "%s: failed to copy reply to user space\n",
				__func__);
			ret = -EFAULT;
			goto free_data_out;
		}
	}

	/* copy out sense to user */
	if (karg.max_sense_bytes && (opcode == SSI2_FUNCTION_SCSI_IO ||
		opcode ==  SSI2_FUNCTION_RAID_SCSI_IO_PASSTHROUGH)) {
		sz = min_t(ssize_t, karg.max_sense_bytes, SCSI_SENSE_BUFFERSIZE);
		if (copy_to_user((void __user *)karg.sense_data_ptr,
			ioa->ctl_cmds.sense, sz)) {
			log_error(ioa, "%s: failed to copy sense data to user space\n",
				__func__);
			ret = -EFAULT;
		goto free_data_out;
		}
	}

issue_host_reset:
	if (issue_reset) {
		ret = -ENODATA;
		if ((opcode == SSI2_FUNCTION_SCSI_IO ||
			opcode == SSI2_FUNCTION_RAID_SCSI_IO_PASSTHROUGH)) {
			hst2dr_vendor_cmd *hvc = (hst2dr_vendor_cmd *)request;
			u16 handle = le16_to_cpu(hvc->logical_dev_id);

			log_ctrl(ioa, "issue target reset: handle = (0x%04x)\n",
				handle);
			hst2dr_issue_task_reset(ioa, handle);
		} else {
			hst2dr_base_hard_reset_handler(ioa, HARD_RESET, 30);
		}
	}
free_data_out:

	/* free memory associated with sg buffers */
	if (data_out)
		free_memory(ioa, data_out, data_out_dma, data_out_sz);

	if (data_in)
		free_memory(ioa, data_in, data_in_dma, data_in_sz);

free_host_tag_id:
	if (!dont_free_id)
		hst2dr_base_free_host_tag_id(ioa, host_tag_id);
out:
	ioa->ctl_cmds.status = HST2DR_CMD_NOT_USED;

	return ret;
}

static long _ctl_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct HST2DR_ADAPTER *ioa = NULL;
	U32 ioa_number;
	long ret;

	if (get_user(ioa_number, (U32 __user *)arg)) {
		ret = -EFAULT;
		goto out;
	}

	if (_ctl_verify_adapter(ioa_number, &ioa, SSI2_VERSION) == -1 || !ioa) {
		ret = -ENODEV;
		goto out;
	}

	log_ctrl(ioa, "ioa_number = %d\n", ioa_number);

	if (atomic_cmpxchg(&ioa->ioctl_in_use, 0, 1) != 0) {
		// The ioctl is in use, return an error
		return -EBUSY;
	}

	switch (cmd) {
	case HST2RESETHBA: {
		struct hst2dr_rsttype *rst =
			(struct hst2dr_rsttype __user *)arg;
		int reset_type;

		if (_IOC_SIZE(cmd) != sizeof(struct hst2dr_rsttype)) {
			ret = -EINVAL;
			break;
		}

		if (get_user(reset_type, &rst->reset_type)) {
			ret = -EFAULT;
			break;
		}

		if (reset_type >= SOFT_RESET) {
			ret = -EINVAL;
			break;
		}
		log_ctrl(ioa, "%s: reset type = %s\n", __func__, "HARD_RESET");
		reset_type = AER_RESET;
		ret = hst2dr_base_hard_reset_handler(ioa, reset_type, 31);
		break;
	}
#ifdef CONFIG_COMPAT
	case HST2COMMAND32:
#endif
	case HST2COMMAND: {
#ifdef CONFIG_COMPAT
		struct hst2dr_ioctl_command32 karg32;
#endif
		struct hst2dr_ioctl_command karg;
		void __user *ptr;

#ifdef CONFIG_COMPAT
		if (cmd == HST2COMMAND32) {
			if (_IOC_SIZE(cmd) != sizeof(struct hst2dr_ioctl_command32)) {
				ret = -EINVAL;
				break;
			}
			if (copy_from_user(&karg32, (void __user *)arg,
				sizeof(karg32))) {
				ret = -EFAULT;
				break;
			}
			karg.hdr.ioa_number = karg32.hdr.ioa_number;
			karg.hdr.max_data_size = karg32.hdr.max_data_size;
			karg.timeout = karg32.timeout;
			karg.max_reply_bytes = karg32.max_reply_bytes;
			karg.data_in_size = karg32.data_in_size;
			karg.data_out_size = karg32.data_out_size;
			karg.max_sense_bytes = karg32.max_sense_bytes;
			karg.data_sge_offset = karg32.data_sge_offset;
			karg.reply_frame_buf_ptr =
				compat_ptr(karg32.reply_frame_buf_ptr);
			karg.data_in_buf_ptr = compat_ptr(karg32.data_in_buf_ptr);
			karg.data_out_buf_ptr = compat_ptr(karg32.data_out_buf_ptr);
			karg.sense_data_ptr = compat_ptr(karg32.sense_data_ptr);
			ptr = (void __user *)
				&((struct hst2dr_ioctl_command32 *)arg)->mf;
		} else
#endif
		{

			if (_IOC_SIZE(cmd) != sizeof(struct hst2dr_ioctl_command)) {
				ret = -EINVAL;
				break;
			}
			if (copy_from_user(&karg, (void __user *)arg, sizeof(karg))) {
				ret = -EFAULT;
				break;
			}
			ptr = (void __user *)
				&((struct hst2dr_ioctl_command *)arg)->mf;
		}
		ret = _ctl_do_hst2dr_command(ioa, karg, ptr);
		break;
		}
	default:
			ret = -ENOTTY;
			break;
	}

out:
	atomic_set(&ioa->ioctl_in_use, 0);
	return ret;
}


/* scsi host attributes */
/**
 * _ctl_version_fw_show - firmware version
 * @cdev - pointer to embedded class device
 * @buf - the buffer returned
 *
 * A sysfs 'read-only' shost attribute.
 */

static ssize_t
version_fw_show(struct device *cdev, struct device_attribute *attr,
	char *buf)
{
	struct Scsi_Host *shost = class_to_shost(cdev);
	struct HST2DR_ADAPTER *ioa = shost_priv(shost);

	return snprintf(buf, PAGE_SIZE, "%02x.%02x.%02x.%02x\n",
		(ioa->info.fw_version.dword & 0xFF000000) >> 24,
		(ioa->info.fw_version.dword & 0x00FF0000) >> 16,
		(ioa->info.fw_version.dword & 0x0000FF00) >> 8,
		ioa->info.fw_version.dword & 0x000000FF);
}
static DEVICE_ATTR_RO(version_fw);

/**
 * _ctl_version_ssi_show - SSI version
 * @cdev - pointer to embedded class device
 * @buf - the buffer returned
 *
 * A sysfs 'read-only' shost attribute.
 */
static ssize_t
version_hst2dr_show(struct device *cdev, struct device_attribute *attr,
	char *buf)
{
	return snprintf(buf, PAGE_SIZE, "%02x.%02x.%02x.%02x\n",
		HST2DR_MAJOR_VERSION, HST2DR_MINOR_VERSION, 0, HST2DR_REVISION_VERSION);
}
static DEVICE_ATTR_RO(version_hst2dr);

/**
 * _ctl_version_product_show - product name
 * @cdev - pointer to embedded class device
 * @buf - the buffer returned
 *
 * A sysfs 'read-only' shost attribute.
 */
static ssize_t
chip_name_show(struct device *cdev, struct device_attribute *attr,
	char *buf)
{
	struct Scsi_Host *shost = class_to_shost(cdev);
	struct HST2DR_ADAPTER *ioa = shost_priv(shost);

	return snprintf(buf, 16, "%s\n", ioa->vendor.chip_name);
}
static DEVICE_ATTR_RO(chip_name);

/**
 * _ctl_board_name_show - board name
 * @cdev - pointer to embedded class device
 * @buf - the buffer returned
 *
 * A sysfs 'read-only' shost attribute.
 */
static ssize_t
board_name_show(struct device *cdev, struct device_attribute *attr,
	char *buf)
{
	struct Scsi_Host *shost = class_to_shost(cdev);
	struct HST2DR_ADAPTER *ioa = shost_priv(shost);

	return snprintf(buf, 16, "%s\n", ioa->vendor.board_name);
}
static DEVICE_ATTR_RO(board_name);

/**
 * _ctl_board_assembly_show - board assembly name
 * @cdev - pointer to embedded class device
 * @buf - the buffer returned
 *
 * A sysfs 'read-only' shost attribute.
 */
static ssize_t
board_assembly_show(struct device *cdev, struct device_attribute *attr,
	char *buf)
{
	struct Scsi_Host *shost = class_to_shost(cdev);
	struct HST2DR_ADAPTER *ioa = shost_priv(shost);

	return snprintf(buf, 16, "%s\n", ioa->vendor.module_id);
}
static DEVICE_ATTR_RO(board_assembly);

/**
 * _ctl_board_tracer_show - board tracer number
 * @cdev - pointer to embedded class device
 * @buf - the buffer returned
 *
 * A sysfs 'read-only' shost attribute.
 */
static ssize_t
board_tracer_show(struct device *cdev, struct device_attribute *attr,
	char *buf)
{
	struct Scsi_Host *shost = class_to_shost(cdev);
	struct HST2DR_ADAPTER *ioa = shost_priv(shost);

	return snprintf(buf, 16, "%s\n", ioa->vendor.serial_number);
}
static DEVICE_ATTR_RO(board_tracer);

/**
 * _ctl_io_delay_show - io missing delay
 * @cdev - pointer to embedded class device
 * @buf - the buffer returned
 *
 * This is for firmware implementation for deboucing device
 * removal events.
 *
 * A sysfs 'read-only' shost attribute.
 */
static ssize_t
io_delay_show(struct device *cdev, struct device_attribute *attr,
	char *buf)
{
	struct Scsi_Host *shost = class_to_shost(cdev);
	struct HST2DR_ADAPTER *ioa = shost_priv(shost);

	return snprintf(buf, PAGE_SIZE, "%02d\n", ioa->io_missing_delay);
}
static DEVICE_ATTR_RO(io_delay);

/**
 * _ctl_device_delay_show - device missing delay
 * @cdev - pointer to embedded class device
 * @buf - the buffer returned
 *
 * This is for firmware implementation for deboucing device
 * removal events.
 *
 * A sysfs 'read-only' shost attribute.
 */
static ssize_t
device_delay_show(struct device *cdev, struct device_attribute *attr,
	char *buf)
{
	struct Scsi_Host *shost = class_to_shost(cdev);
	struct HST2DR_ADAPTER *ioa = shost_priv(shost);

	return snprintf(buf, PAGE_SIZE, "%02d\n", ioa->device_missing_delay);
}
static DEVICE_ATTR_RO(device_delay);

/**
 * _ctl_fw_queue_depth_show - global credits
 * @cdev - pointer to embedded class device
 * @buf - the buffer returned
 *
 * This is firmware queue depth limit
 *
 * A sysfs 'read-only' shost attribute.
 */
static ssize_t
fw_queue_depth_show(struct device *cdev, struct device_attribute *attr,
	char *buf)
{
	struct Scsi_Host *shost = class_to_shost(cdev);
	struct HST2DR_ADAPTER *ioa = shost_priv(shost);

	return snprintf(buf, PAGE_SIZE, "%02d\n", ioa->info.request_credit);
}
static DEVICE_ATTR_RO(fw_queue_depth);

/**
 * _ctl_sas_address_show - sas address
 * @cdev - pointer to embedded class device
 * @buf - the buffer returned
 *
 * This is the controller sas address
 *
 * A sysfs 'read-only' shost attribute.
 */
static ssize_t
host_sas_address_show(struct device *cdev, struct device_attribute *attr,
	char *buf)

{
	struct Scsi_Host *shost = class_to_shost(cdev);
	struct HST2DR_ADAPTER *ioa = shost_priv(shost);

	return snprintf(buf, PAGE_SIZE, "0x%016llx\n",
		(unsigned long long)ioa->sas_hba.sas_address);
}
static DEVICE_ATTR_RO(host_sas_address);


/**
 * _ctl_ioa_reset_count_show - ioa reset count
 * @cdev - pointer to embedded class device
 * @buf - the buffer returned
 *
 * This is firmware queue depth limit
 *
 * A sysfs 'read-only' shost attribute.
 */
static ssize_t
ioa_reset_count_show(struct device *cdev, struct device_attribute *attr,
	char *buf)
{
	struct Scsi_Host *shost = class_to_shost(cdev);
	struct HST2DR_ADAPTER *ioa = shost_priv(shost);

	return snprintf(buf, PAGE_SIZE, "%d\n", ioa->ioa_reset_count);
}
static DEVICE_ATTR_RO(ioa_reset_count);

/**
 * _ctl_ioa_reply_queue_count_show - number of reply queues
 * @cdev - pointer to embedded class device
 * @buf - the buffer returned
 *
 * This is number of reply queues
 *
 * A sysfs 'read-only' shost attribute.
 */
static ssize_t
ioa_reply_queue_count_show(struct device *cdev,
	struct device_attribute *attr, char *buf)
{
	u8 reply_queue_count;
	struct Scsi_Host *shost = class_to_shost(cdev);
	struct HST2DR_ADAPTER *ioa = shost_priv(shost);

	if (ioa->msix_enable)
		reply_queue_count = ioa->reply_queue_count;
	else
		reply_queue_count = 1;

	return snprintf(buf, PAGE_SIZE, "%d\n", reply_queue_count);
}
static DEVICE_ATTR_RO(ioa_reply_queue_count);

static ssize_t
IOA_status_show(struct device *cdev, struct device_attribute *attr,
	char *buf)
{
	struct Scsi_Host *shost = class_to_shost(cdev);
	struct HST2DR_ADAPTER *ioa = shost_priv(shost);

	return snprintf(buf, PAGE_SIZE, "%x\n", hst2dr_base_get_ioastate(ioa, 0));

}
static DEVICE_ATTR_RO(IOA_status);


#ifdef HST2DR_LOG
static ssize_t
hst2dr_log_show(struct device *cdev, struct device_attribute *attr,
	char *buf)
{
	struct Scsi_Host *shost = class_to_shost(cdev);
	struct HST2DR_ADAPTER *ioa = shost_priv(shost);

	return snprintf(buf, PAGE_SIZE, "name:%s log_type:%x\n", ioa->name, ioa->log_level);
}
static ssize_t
hst2dr_log_store(struct device *cdev, struct device_attribute *attr,
	const char *buf, size_t count)
{
	struct Scsi_Host *shost = class_to_shost(cdev);
	struct HST2DR_ADAPTER *ioa = shost_priv(shost);
	int val = 0;

	if (sscanf(buf, "%x", &val) != 1)
		return -EINVAL;
	ioa->log_level = val;
	pr_info(HST2DR_FMT "log_type = %x\n", ioa->name,
		val);
	return strlen(buf);
}
static DEVICE_ATTR_RW(hst2dr_log);
#endif

static struct attribute *hst2dr_host_attrs[] = {
	&dev_attr_version_fw.attr,
	&dev_attr_version_hst2dr.attr,
	&dev_attr_chip_name.attr,
	&dev_attr_board_name.attr,
	&dev_attr_board_assembly.attr,
	&dev_attr_board_tracer.attr,
	&dev_attr_io_delay.attr,
	&dev_attr_device_delay.attr,
	&dev_attr_fw_queue_depth.attr,
	&dev_attr_host_sas_address.attr,
	&dev_attr_ioa_reset_count.attr,
	&dev_attr_ioa_reply_queue_count.attr,
	&dev_attr_IOA_status.attr,
#ifdef HST2DR_LOG
	&dev_attr_hst2dr_log.attr,
#endif
	NULL,
};
static const struct attribute_group hst2dr_host_attr_group = {
	.attrs = hst2dr_host_attrs,
};
const struct attribute_group *hst2dr_host_attr_groups[] = {
	&hst2dr_host_attr_group,
	NULL,
};

/* device attributes */

/**
 * _ctl_device_sas_address_show - sas address
 * @cdev - pointer to embedded class device
 * @buf - the buffer returned
 *
 * This is the sas address for the target
 *
 * A sysfs 'read-only' shost attribute.
 */
static ssize_t
_ctl_device_sas_address_show(struct device *dev, struct device_attribute *attr,
	char *buf)
{
	struct scsi_device *sdev = to_scsi_device(dev);
	struct HST2DR_DEVICE *sas_device_priv_data = sdev->hostdata;

	return snprintf(buf, PAGE_SIZE, "0x%016llx\n",
		(unsigned long long)
		sas_device_priv_data->sas_target->sas_address);
}
static DEVICE_ATTR(sas_address, 0444, _ctl_device_sas_address_show, NULL);

/**
 * _ctl_device_handle_show - device handle
 * @cdev - pointer to embedded class device
 * @buf - the buffer returned
 *
 * This is the firmware assigned device handle
 *
 * A sysfs 'read-only' shost attribute.
 */
static ssize_t
_ctl_device_handle_show(struct device *dev, struct device_attribute *attr,
	char *buf)
{
	struct scsi_device *sdev = to_scsi_device(dev);
	struct HST2DR_DEVICE *sas_device_priv_data = sdev->hostdata;

	return snprintf(buf, PAGE_SIZE, "0x%04x\n",
		sas_device_priv_data->sas_target->handle);
}
static DEVICE_ATTR(sas_device_handle, 0444, _ctl_device_handle_show, NULL);
/**
 * sas_ncq_io_prio_show - send prioritized io commands to device
 * @dev: pointer to embedded device
 * @attr: ?
 * @buf: the buffer returned
 *
 * A sysfs 'read/write' sdev attribute, only works with SATA
 */
static ssize_t
sas_ncq_prio_enable_show(struct device *dev,
				 struct device_attribute *attr, char *buf)
{
	struct scsi_device *sdev = to_scsi_device(dev);
	struct HST2DR_DEVICE *sas_device_priv_data = sdev->hostdata;

	return snprintf(buf, PAGE_SIZE, "%d\n",
			sas_device_priv_data->ncq_prio_enable);
}

static ssize_t
sas_ncq_prio_enable_store(struct device *dev,
				  struct device_attribute *attr,
				  const char *buf, size_t count)
{
	struct scsi_device *sdev = to_scsi_device(dev);
	struct HST2DR_DEVICE *sas_device_priv_data = sdev->hostdata;
	bool ncq_prio_enable = 0;

	if (kstrtobool(buf, &ncq_prio_enable))
		return -EINVAL;

	if (!sas_ata_ncq_prio_supported(sdev))
		return -EINVAL;

	sas_device_priv_data->ncq_prio_enable = ncq_prio_enable;
	return strlen(buf);
}
static DEVICE_ATTR_RW(sas_ncq_prio_enable);

struct attribute *hst2dr_dev_attrs[] = {
	&dev_attr_sas_address.attr,
	&dev_attr_sas_device_handle.attr,
	&dev_attr_sas_ncq_prio_enable.attr,
	NULL,
};
static const struct attribute_group hst2dr_dev_attr_group = {
	.attrs = hst2dr_dev_attrs,
};
const struct attribute_group *hst2dr_dev_attr_groups[] = {
	&hst2dr_dev_attr_group,
	NULL,
};


/* file operations table for hst2ctl device */
static const struct file_operations ctl_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = _ctl_ioctl,
	.poll = _ctl_poll,
#ifdef CONFIG_COMPAT
	.compat_ioctl = _ctl_ioctl,
#endif
};

static struct miscdevice ctl_dev = {
	.minor  = HST2DR_MINOR,
	.name   = HST2DR_DEV_NAME,
	.fops   = &ctl_fops,
};

/**
 * hst2dr_ctl_init - main entry point for ctl.
 *
 */
void
hst2dr_ctl_init(void)
{

	if (misc_register(&ctl_dev) < 0)
		pr_err("%s can't register misc device [minor=%d]\n",
			HST2DR_DRIVER_NAME, HST2DR_MINOR);

	init_waitqueue_head(&ctl_poll_wait);
}

/**
 * hst2dr_ctl_exit - exit point for ctl
 *
 */
void
hst2dr_ctl_exit(void)
{
	struct HST2DR_ADAPTER *ioa;

	list_for_each_entry(ioa, &hst2dr_ioa_list, list) {
		kfree(ioa->event_log);
	}

	misc_deregister(&ctl_dev);
}
