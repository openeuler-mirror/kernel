// SPDX-License-Identifier: GPL-2.0
/*
 * This module provides common API for accessing firmware configuration pages
 *
 * This code is based on drivers/scsi/hst2dr/hst2dr_conf.c

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

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/errno.h>
#include <linux/blkdev.h>
#include <linux/sched.h>
#include <linux/workqueue.h>
#include <linux/delay.h>
#include <linux/pci.h>

#include "hst2dr_base.h"
#include "hst2dr_hal.h"
#include "hst2dr_comm.h"
#include "hst2dr_debug.h"
/* local definitions */

/* Timeout for config page request (in seconds) */
#define HST2DR_CONFIG_PAGE_DEFAULT_TIMEOUT 15

/* Common sgl flags for READING a config page. */
#define HST2DR_CONFIG_COMMON_SGLFLAGS ((SSI2_SGE_FLAGS_SIMPLE_ELEMENT | \
	SSI2_SGE_FLAGS_LAST_ELEMENT | SSI2_SGE_FLAGS_END_OF_BUFFER \
	| SSI2_SGE_FLAGS_END_OF_LIST) << SSI2_SGE_FLAGS_SHIFT)

/* Common sgl flags for WRITING a config page. */
#define HST2DR_CONFIG_COMMON_WRITE_SGLFLAGS ((SSI2_SGE_FLAGS_SIMPLE_ELEMENT | \
	SSI2_SGE_FLAGS_LAST_ELEMENT | SSI2_SGE_FLAGS_END_OF_BUFFER \
	| SSI2_SGE_FLAGS_END_OF_LIST | SSI2_SGE_FLAGS_HOST_TO_IOA) \
	<< SSI2_SGE_FLAGS_SHIFT)

/**
 * struct cfg_request - obtain dma memory via routine
 * @sz: size
 * @page: virt pointer
 * @page_dma: phys pointer
 *
 */
struct cfg_request {
	u16			sz;
	void			*page;
	dma_addr_t		page_dma;
};

/**
 * _cfg_display_some_debug - debug routine
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
_cfg_display_some_debug(struct HST2DR_ADAPTER *ioa, u16 host_tag_id,
	char *calling_function_name, SSI2_INQUIRY_PAGE_REPLY *ssi_reply)
{
	SSI2_INQUIRY_PAGE_REQUEST *ssi_request;
	char *desc = NULL;

	ssi_request = hst2dr_base_get_msg_frame(ioa, host_tag_id);
	switch (ssi_request->header.type) {
	case SSI2_CONFIG_TYPE_IOA:
		desc = "ioa";
		break;
	case SSI2_CONFIG_TYPE_VENDOR:
		desc = "vendor";
		break;
	case SSI2_CONFIG_TYPE_SAS_UNIT:
		desc = "sas_unit";
		break;
	case SSI2_CONFIG_TYPE_EXPANDER:
		desc = "sas_expander";
		break;
	case SSI2_CONFIG_TYPE_SAS_DEV:
		desc = "sas_device";
		break;
	case SSI2_CONFIG_TYPE_PHY:
		desc = "sas_phy";
		break;
	case SSI2_CONFIG_TYPE_ENCLOSURE:
		desc = "enclosure";
		break;
	}

	if (!desc)
		return;

	log_config(ioa,
		"%s: %s(%d), action(%d), form(0x%08x), host_tag_id(%d)\n",
		calling_function_name, desc,
		ssi_request->header.number, ssi_request->header.cmd,
		le32_to_cpu(ssi_request->address), host_tag_id);

	if (!ssi_reply)
		return;

	if (ssi_reply->status || ssi_reply->log_info)
		log_config(ioa, "\tioastatus(0x%04x), loginfo(0x%08x)\n",
			le16_to_cpu(ssi_reply->status),
			le32_to_cpu(ssi_reply->log_info));
}

/**
 * _cfg_alloc_config_dma_memory - obtain physical memory
 * @ioa: per adapter object
 * @mem: struct cfg_request
 *
 * A wrapper for obtaining dma-able memory for config page request.
 *
 * Returns 0 for success, non-zero for failure.
 */
static int
_cfg_alloc_config_dma_memory(struct HST2DR_ADAPTER *ioa,
	struct cfg_request *mem)
{
	int r = 0;

	if (mem->sz > ioa->config_page_sz) {
		mem->page = dma_alloc_coherent(&ioa->pdev->dev, mem->sz,
			&mem->page_dma, GFP_KERNEL);
		if (!mem->page) {
			log_error(ioa,
				"%s: dma_alloc_coherent failed asking for (%d) bytes!\n",
				__func__, mem->sz);
			r = -ENOMEM;
		}
	} else { /* use tmp buffer if less than 512 bytes */
		mem->page = ioa->config_page;
		mem->page_dma = ioa->config_page_dma;
	}
	return r;
}

/**
 * _cfg_free_config_dma_memory - wrapper to free the memory
 * @ioa: per adapter object
 * @mem: struct cfg_request
 *
 * A wrapper to free dma-able memory when using _cfg_alloc_config_dma_memory.
 *
 * Returns 0 for success, non-zero for failure.
 */
static void
_cfg_free_config_dma_memory(struct HST2DR_ADAPTER *ioa,
	struct cfg_request *mem)
{
	if (mem->sz > ioa->config_page_sz)
		dma_free_coherent(&ioa->pdev->dev, mem->sz, mem->page,
			mem->page_dma);
}

/**
 * hst2dr_cfg_done - config page completion routine
 * @ioa: per adapter object
 * @cqe: completion queue entity
 * Context: none.
 *
 * The callback handler when using _cfg_request.
 *
 * Return 1 meaning mf should be freed from _base_interrupt
 *	0 means the mf is freed from this function.
 */
u8
hst2dr_cfg_done(struct HST2DR_ADAPTER *ioa,
	hst2dr_nvme_completion *cqe)
{
	SSI2_INQUIRY_PAGE_REPLY *cfg_reply = NULL;

	if (ioa->config_cmds.status == HST2DR_CMD_NOT_USED)
		return 1;
	if (ioa->config_cmds.host_tag_id != cqe->host_tag_id)
		return 1;
	ioa->config_cmds.status |= HST2DR_CMD_COMPLETE;
	if (cqe->ctrl.status == SSI2_IOASTATUS_SUCCESS) {
		cfg_reply = (SSI2_INQUIRY_PAGE_REPLY *)ioa->config_cmds.reply;
		cfg_reply->status = cqe->ctrl.status;
		cfg_reply->log_info = 0;
		ioa->config_cmds.status |= HST2DR_CMD_REPLY_VALID;
	} else {
		if (cqe->ctrl.description ==
				SSI2_RPY_DESCRIPT_FLAGS_ADDRESS_REPLY)
			cfg_reply = hst2dr_base_get_reply_virt_addr(ioa,
				cqe->reply_id);
		if (cfg_reply) {
			cfg_reply->status = cqe->ctrl.status;
			if (cfg_reply->msg_len == 0)
				ioa->config_cmds.status |= HST2DR_CMD_NOT_USED;
			else
				ioa->config_cmds.status |=
					HST2DR_CMD_REPLY_VALID;
			memcpy(ioa->config_cmds.reply, cfg_reply,
				min_t(u8, cfg_reply->msg_len * 4, 128));
			debug_dump_mem("cfg reply:",
				cfg_reply, min_t(u8, cfg_reply->msg_len * 4, 128));
		} else {
			cfg_reply = (SSI2_INQUIRY_PAGE_REPLY *)
				ioa->config_cmds.reply;
			cfg_reply->status = cqe->ctrl.status;
			cfg_reply->log_info = 0;
			ioa->config_cmds.status |= HST2DR_CMD_REPLY_VALID;

		}
	}
	ioa->config_cmds.status &= ~HST2DR_CMD_PENDING;
	_cfg_display_some_debug(ioa, cqe->host_tag_id,
		"config_done", cfg_reply);
	ioa->config_cmds.host_tag_id = USHRT_MAX;
	complete(&ioa->config_cmds.done);
	return 1;
}

/**
 * _cfg_request - main routine for sending config page requests
 * @ioa: per adapter object
 * @ssi_request: request message frame
 * @ssi_reply: reply mf payload returned from firmware
 * @timeout: timeout in seconds
 * @config_page: contents of the config page
 * @config_page_sz: size of config page
 * Context: sleep
 *
 * A generic API for config page requests to firmware.
 *
 * The ioa->config_cmds.status flag should be HST2DR_CMD_NOT_USED before calling
 * this API.
 *
 * The callback index is set inside `ioa->config_cb_idx.
 *
 * Returns 0 for success, non-zero for failure.
 */
static int
_cfg_request(struct HST2DR_ADAPTER *ioa, SSI2_INQUIRY_PAGE_REQUEST
	*ssi_request, SSI2_INQUIRY_PAGE_REPLY *ssi_reply, int timeout,
	void *config_page, u16 config_page_sz)
{
	u16 host_tag_id;
	u32 ioa_state;
	int r;
	u8 retry_count, issue_host_reset = 0;
	u16 wait_state_count;
	struct cfg_request mem;
	u32 ioa_status = UINT_MAX;
	hst2dr_command *scmd;

	mutex_lock(&ioa->config_cmds.mutex);
	if (ioa->config_cmds.status != HST2DR_CMD_NOT_USED) {
		log_error(ioa, "%s: config_cmd in use\n",
			__func__);
		mutex_unlock(&ioa->config_cmds.mutex);
		return -EAGAIN;
	}

	retry_count = 0;
	memset(&mem, 0, sizeof(struct cfg_request));

	if (config_page) {

		mem.sz = ssi_request->header.len * 4;
		r = _cfg_alloc_config_dma_memory(ioa, &mem);
		if (r != 0)
			goto out;
		ssi_request->sge.len = mem.sz;
		ssi_request->sge.address = cpu_to_le64(mem.page_dma);
		ssi_request->sge.flag = SSI2_IEEE_SGE_FLAGS_END_OF_LIST;

		if (ssi_request->header.cmd ==
			SSI2_CONFIG_CMD_PAGE_WRITE_CURRENT ||
			ssi_request->header.cmd ==
			SSI2_CONFIG_CMD_PAGE_WRITE_NVRAM) {

			memcpy(mem.page, config_page, min_t(u16, mem.sz,
				config_page_sz));
		} else {
			memset(config_page, 0, config_page_sz);
			memset(mem.page, 0, min_t(u16, mem.sz, config_page_sz));
		}
	}

 retry_config:
	if (retry_count) {
		if (retry_count > 2) { /* attempt only 2 retries */
			r = -EFAULT;
			goto free_mem;
		}
		log_config(ioa, "%s: attempting retry (%d)\n",
			__func__, retry_count);
	}
	wait_state_count = 0;
	ioa_state = hst2dr_base_get_ioastate(ioa, 1);
	while (ioa_state != SSI2_IOA_STATE_OPERATIONAL) {
		if (wait_state_count++ == HST2DR_CONFIG_PAGE_DEFAULT_TIMEOUT) {
			log_error(ioa,
				"%s: failed due to ioa not operational\n",
				__func__);
			ioa->config_cmds.status = HST2DR_CMD_NOT_USED;
			r = -EFAULT;
			goto free_mem;
		}
		ssleep(1);
		ioa_state = hst2dr_base_get_ioastate(ioa, 1);
		log_config(ioa,
			"%s: waiting for operational state(count=%d)\n",
			__func__, wait_state_count);
	}
	if (wait_state_count)
		log_config(ioa, "%s: ioa is operational\n",
			__func__);

	host_tag_id = hst2dr_base_get_host_tag_id(ioa, ioa->config_cb_idx);
	if (host_tag_id == NO_HOST_TAG_ID) {
		log_error(ioa, "%s: failed obtaining a host_tag_id\n",
			__func__);
		ioa->config_cmds.status = HST2DR_CMD_NOT_USED;
		r = -EAGAIN;
		goto free_mem;
	}

	r = 0;
	memset(ssi_reply, 0, sizeof(SSI2_INQUIRY_PAGE_REPLY));
	ioa->config_cmds.status = HST2DR_CMD_PENDING;
	scmd = hst2dr_base_get_msg_frame(ioa, host_tag_id);
	ioa->config_cmds.host_tag_id = host_tag_id;
	init_completion(&ioa->config_cmds.done);

	memcpy(&scmd->cmd.internal.cmd, ssi_request,
			sizeof(SSI2_INQUIRY_PAGE_REQUEST));
	scmd->cmd.internal.cmd.head.opcode = SSI2_FUNCTION_CONFIG;
	scmd->cmd.internal.cmd.head.opflags = cmd_flag_fw_mode_admin;
	scmd->cmd.internal.cmd.head.host_tag_id = host_tag_id;
	scmd->cmd.internal.cmd.head.host_flag = hst2dr_cmd_config;

	ioa->put_host_tag_id_default(ioa, scmd);
	wait_for_completion_timeout(&ioa->config_cmds.done, timeout * HZ);
	if (!(ioa->config_cmds.status & HST2DR_CMD_COMPLETE)) {
		log_error(ioa, "%s: opcode: %04x timeout\n",
			__func__, SSI2_FUNCTION_CONFIG);
		retry_count++;
		if (ioa->config_cmds.host_tag_id == host_tag_id)
			hst2dr_base_free_host_tag_id(ioa, host_tag_id);
		if ((ioa->shost_recovery) || (ioa->config_cmds.status &
			HST2DR_CMD_RESET) || ioa->pci_error_recovery)
			goto retry_config;
		issue_host_reset = 1;
		r = -EFAULT;
		goto free_mem;
	}

	if (ioa->config_cmds.status & HST2DR_CMD_REPLY_VALID) {
		memcpy(ssi_reply, ioa->config_cmds.reply,
			sizeof(SSI2_INQUIRY_PAGE_REPLY));

		ioa_status = le16_to_cpu(ssi_reply->status)
			& SSI2_IOASTATUS_MASK;
		if (ioa_status != SSI2_IOASTATUS_SUCCESS)
			r = EFAULT;
	}

	if (retry_count)
		log_config(ioa, "%s: retry (%d) completed!\n",
			__func__, retry_count);

	if ((ioa_status == SSI2_IOASTATUS_SUCCESS) &&
			config_page && ssi_request->header.cmd ==
			SSI2_CONFIG_CMD_PAGE_READ_CURRENT) {

		memcpy(config_page, mem.page, min_t(u16, mem.sz,
			config_page_sz));
		debug_dump_mem("cfg_data:", mem.page,
			min_t(u16, mem.sz, config_page_sz));
	}

 free_mem:
	if (config_page)
		_cfg_free_config_dma_memory(ioa, &mem);
 out:
	ioa->config_cmds.status = HST2DR_CMD_NOT_USED;
	mutex_unlock(&ioa->config_cmds.mutex);

	if (issue_host_reset)
		hst2dr_base_hard_reset_handler(ioa, HARD_RESET, 12);

	return r;
}

/**
 * hst2dr_cfg_get_vendor - obtain vendor page 0
 * @ioa: per adapter object
 * @ssi_reply: reply mf payload returned from firmware
 * @config_page: contents of the config page
 * Context: sleep.
 *
 * Returns 0 for success, non-zero for failure.
 */
int
hst2dr_cfg_get_vendor(struct HST2DR_ADAPTER *ioa,
	SSI2_INQUIRY_PAGE_REPLY *ssi_reply,
	SSI2_INQUIRY_PAGE_VENDOR *config_page)
{
	SSI2_INQUIRY_PAGE_REQUEST ssi_request;
	int r;

	log_config(ioa, "%s\n", __func__);
	memset(&ssi_request, 0, sizeof(SSI2_INQUIRY_PAGE_REQUEST));
	ssi_request.header.type = SSI2_CONFIG_TYPE_VENDOR;
	ssi_request.header.number = 0;
	ssi_request.header.len = sizeof(*config_page) / 4;

	ssi_request.header.cmd = SSI2_CONFIG_CMD_PAGE_READ_CURRENT;
	r = _cfg_request(ioa, &ssi_request, ssi_reply,
		HST2DR_CONFIG_PAGE_DEFAULT_TIMEOUT, config_page,
		sizeof(*config_page));
	return r;
}

/**
 * hst2dr_cfg_get_ioa01 - obtain ioa page 1
 * @ioa: per adapter object
 * @ssi_reply: reply mf payload returned from firmware
 * @config_page: contents of the config page
 * Context: sleep.
 *
 * Returns 0 for success, non-zero for failure.
 */
int
hst2dr_cfg_get_ioa01(struct HST2DR_ADAPTER *ioa,
	SSI2_INQUIRY_PAGE_REPLY *ssi_reply, SSI2_INQUIRY_IOA01 *config_page)
{
	SSI2_INQUIRY_PAGE_REQUEST ssi_request;
	int r;

	log_config(ioa, "%s\n", __func__);
	memset(&ssi_request, 0, sizeof(SSI2_INQUIRY_PAGE_REQUEST));
	ssi_request.header.type = SSI2_CONFIG_TYPE_IOA;
	ssi_request.header.number = 1;
	ssi_request.header.len = sizeof(*config_page) / 4;

	ssi_request.header.cmd = SSI2_CONFIG_CMD_PAGE_READ_CURRENT;
	r = _cfg_request(ioa, &ssi_request, ssi_reply,
		HST2DR_CONFIG_PAGE_DEFAULT_TIMEOUT, config_page,
		sizeof(*config_page));
	return r;
}

/**
 * hst2dr_cfg_get_sas_dev - obtain sas device page 0
 * @ioa: per adapter object
 * @ssi_reply: reply mf payload returned from firmware
 * @config_page: contents of the config page
 * @form: GET_NEXT_HANDLE or HANDLE
 * @handle: device handle
 * Context: sleep.
 *
 * Returns 0 for success, non-zero for failure.
 */
int
hst2dr_cfg_get_sas_dev(struct HST2DR_ADAPTER *ioa,
	SSI2_INQUIRY_PAGE_REPLY *ssi_reply, SSI2_INQUIRY_SAS_DEV *config_page,
	u32 form, u32 handle)
{
	SSI2_INQUIRY_PAGE_REQUEST ssi_request;
	int r;

	log_config(ioa, "%s form:%x handle:%x\n", __func__, form, handle);

	memset(&ssi_request, 0, sizeof(SSI2_INQUIRY_PAGE_REQUEST));
	ssi_request.header.type = SSI2_CONFIG_TYPE_SAS_DEV;
	ssi_request.header.number = 0;
	ssi_request.header.len = sizeof(*config_page) / 4;

	ssi_request.address = cpu_to_le32(form | handle);
	ssi_request.header.cmd = SSI2_CONFIG_CMD_PAGE_READ_CURRENT;
	r = _cfg_request(ioa, &ssi_request, ssi_reply,
		HST2DR_CONFIG_PAGE_DEFAULT_TIMEOUT, config_page,
		sizeof(*config_page));

	return r;
}
/**
 * hst2dr_cfg_get_number_hba_phys - obtain number of phys on the host
 * @ioa: per adapter object
 * @num_phys: pointer returned with the number of phys
 * Context: sleep.
 *
 * Returns 0 for success, non-zero for failure.
 */
int
hst2dr_cfg_get_number_hba_phys(struct HST2DR_ADAPTER *ioa, u8 *num_phys)
{
	SSI2_INQUIRY_PAGE_REQUEST ssi_request;
	int r;
	u16 ioa_status;
	SSI2_INQUIRY_PAGE_REPLY ssi_reply;
	SSI2_INQUIRY_SAS_UNIT0 config_page;
	*num_phys = 0;
	log_config(ioa, "%s %d\n", __func__, __LINE__);

	memset(&ssi_request, 0, sizeof(SSI2_INQUIRY_PAGE_REQUEST));
	ssi_request.header.type = SSI2_CONFIG_TYPE_SAS_UNIT;
	ssi_request.header.number = 0;
	ssi_request.header.len = sizeof(config_page) / 4;

	ssi_request.header.cmd = SSI2_CONFIG_CMD_PAGE_READ_CURRENT;
	r = _cfg_request(ioa, &ssi_request, &ssi_reply,
		HST2DR_CONFIG_PAGE_DEFAULT_TIMEOUT, &config_page,
		sizeof(SSI2_INQUIRY_SAS_UNIT0));
	if (!r) {
		ioa_status = le16_to_cpu(ssi_reply.status) &
			SSI2_IOASTATUS_MASK;
		if (ioa_status == SSI2_IOASTATUS_SUCCESS)
			*num_phys = config_page.num_phys;
	}
	return r;
}

/**
 * hst2dr_cfg_get_sas_unit0 - obtain sas iounit page 0
 * @ioa: per adapter object
 * @ssi_reply: reply mf payload returned from firmware
 * @config_page: contents of the config page
 * @sz: size of buffer passed in config_page
 * Context: sleep.
 *
 * Calling function should call config_get_number_hba_phys prior to
 * this function, so enough memory is allocated for config_page.
 *
 * Returns 0 for success, non-zero for failure.
 */
int
hst2dr_cfg_get_sas_unit0(struct HST2DR_ADAPTER *ioa,
	SSI2_INQUIRY_PAGE_REPLY *ssi_reply, SSI2_INQUIRY_SAS_UNIT0 *config_page,
	u16 sz)
{
	SSI2_INQUIRY_PAGE_REQUEST ssi_request;
	int r;

	log_config(ioa, "%s %d sz:%x\n", __func__, __LINE__, sz);

	memset(&ssi_request, 0, sizeof(SSI2_INQUIRY_PAGE_REQUEST));
	ssi_request.header.type = SSI2_CONFIG_TYPE_SAS_UNIT;
	ssi_request.header.number = 0;
	ssi_request.header.len = sz / 4;

	ssi_request.header.cmd = SSI2_CONFIG_CMD_PAGE_READ_CURRENT;
	r = _cfg_request(ioa, &ssi_request, ssi_reply,
		HST2DR_CONFIG_PAGE_DEFAULT_TIMEOUT, config_page, sz);
	return r;
}

/**
 * hst2dr_cfg_get_sas_unit1 - obtain sas iounit page 1
 * @ioa: per adapter object
 * @ssi_reply: reply mf payload returned from firmware
 * @config_page: contents of the config page
 * @sz: size of buffer passed in config_page
 * Context: sleep.
 *
 * Calling function should call config_get_number_hba_phys prior to
 * this function, so enough memory is allocated for config_page.
 *
 * Returns 0 for success, non-zero for failure.
 */
int
hst2dr_cfg_get_sas_unit1(struct HST2DR_ADAPTER *ioa,
	SSI2_INQUIRY_PAGE_REPLY *ssi_reply, SSI2_INQUIRY_SAS_UNIT1 *config_page,
	u16 sz)
{
	SSI2_INQUIRY_PAGE_REQUEST ssi_request;
	int r;

	log_config(ioa, "%s sz:%x\n", __func__, sz);

	memset(&ssi_request, 0, sizeof(SSI2_INQUIRY_PAGE_REQUEST));
	ssi_request.header.type = SSI2_CONFIG_TYPE_SAS_UNIT;
	ssi_request.header.number = 1;
	ssi_request.header.len = sz / 4;

	ssi_request.header.cmd = SSI2_CONFIG_CMD_PAGE_READ_CURRENT;
	r = _cfg_request(ioa, &ssi_request, ssi_reply,
		HST2DR_CONFIG_PAGE_DEFAULT_TIMEOUT, config_page, sz);
	return r;
}

/**
 * hst2dr_cfg_set_sas_unit1 - send sas iounit page 1
 * @ioa: per adapter object
 * @ssi_reply: reply mf payload returned from firmware
 * @config_page: contents of the config page
 * @sz: size of buffer passed in config_page
 * Context: sleep.
 *
 * Calling function should call config_get_number_hba_phys prior to
 * this function, so enough memory is allocated for config_page.
 *
 * Returns 0 for success, non-zero for failure.
 */
int
hst2dr_cfg_set_sas_unit1(struct HST2DR_ADAPTER *ioa,
	SSI2_INQUIRY_PAGE_REPLY *ssi_reply, SSI2_INQUIRY_SAS_UNIT1 *config_page,
	u16 sz)
{
	SSI2_INQUIRY_PAGE_REQUEST ssi_request;
	int r;

	log_config(ioa, "%s sz:%x\n", __func__, sz);
	memset(&ssi_request, 0, sizeof(SSI2_INQUIRY_PAGE_REQUEST));
	ssi_request.header.type = SSI2_CONFIG_TYPE_SAS_UNIT;
	ssi_request.header.number = 1;
	ssi_request.header.len = sz / 4;

	ssi_request.header.cmd = SSI2_CONFIG_CMD_PAGE_WRITE_CURRENT;
	_cfg_request(ioa, &ssi_request, ssi_reply,
		HST2DR_CONFIG_PAGE_DEFAULT_TIMEOUT, config_page, sz);
	ssi_request.header.cmd = SSI2_CONFIG_CMD_PAGE_WRITE_NVRAM;
	r = _cfg_request(ioa, &ssi_request, ssi_reply,
		HST2DR_CONFIG_PAGE_DEFAULT_TIMEOUT, config_page, sz);
	return r;
}

/**
 * hst2dr_cfg_get_expander - obtain expander page 0
 * @ioa: per adapter object
 * @ssi_reply: reply mf payload returned from firmware
 * @config_page: contents of the config page
 * @form: GET_NEXT_HANDLE or HANDLE
 * @handle: expander handle
 * Context: sleep.
 *
 * Returns 0 for success, non-zero for failure.
 */
int
hst2dr_cfg_get_expander(struct HST2DR_ADAPTER *ioa, SSI2_INQUIRY_PAGE_REPLY
	*ssi_reply, SSI2_INQUIRY_EXPANDER *config_page, u32 form, u32 handle)
{
	SSI2_INQUIRY_PAGE_REQUEST ssi_request;
	int r;

	log_config(ioa, "%s form:%x handle:%x\n", __func__, form, handle);
	memset(&ssi_request, 0, sizeof(SSI2_INQUIRY_PAGE_REQUEST));
	ssi_request.header.type = SSI2_CONFIG_TYPE_EXPANDER;
	ssi_request.header.number = 0;
	ssi_request.header.len = sizeof(*config_page) / 4;

	ssi_request.address = cpu_to_le32(form | handle);
	ssi_request.header.cmd = SSI2_CONFIG_CMD_PAGE_READ_CURRENT;
	r = _cfg_request(ioa, &ssi_request, ssi_reply,
		HST2DR_CONFIG_PAGE_DEFAULT_TIMEOUT, config_page,
		sizeof(*config_page));
	return r;
}

/**
 * hst2dr_cfg_get_expander_phy - obtain expander page 1
 * @ioa: per adapter object
 * @ssi_reply: reply mf payload returned from firmware
 * @config_page: contents of the config page
 * @phy_number: phy number
 * @handle: expander handle
 * Context: sleep.
 *
 * Returns 0 for success, non-zero for failure.
 */
int
hst2dr_cfg_get_expander_phy(struct HST2DR_ADAPTER *ioa, SSI2_INQUIRY_PAGE_REPLY
	*ssi_reply, SSI2_INQUIRY_EXPANDER_PHY *config_page, u32 phy_number,
	u16 handle)
{
	SSI2_INQUIRY_PAGE_REQUEST ssi_request;
	int r;

	log_config(ioa, "%s phy_number:%x handle:%x\n",
		__func__, phy_number, handle);
	memset(&ssi_request, 0, sizeof(SSI2_INQUIRY_PAGE_REQUEST));
	ssi_request.header.type = SSI2_CONFIG_TYPE_EXPANDER;
	ssi_request.header.number = 1;
	if (phy_number & 0x8000)
		ssi_request.header.len =
			sizeof(*config_page) / 4 * (phy_number & 0xff);
	else
		ssi_request.header.len = sizeof(*config_page) / 4;

	ssi_request.address =
		cpu_to_le32(SSI2_SAS_EXPAND_PGAD_FORM_HNDL_PHY_NUM |
		(phy_number << SSI2_SAS_EXPAND_PGAD_PHYNUM_SHIFT) | handle);
	ssi_request.header.cmd = SSI2_CONFIG_CMD_PAGE_READ_CURRENT;
	r = _cfg_request(ioa, &ssi_request, ssi_reply,
		HST2DR_CONFIG_PAGE_DEFAULT_TIMEOUT, config_page,
		ssi_request.header.len * 4);
	return r;
}

/**
 * hst2dr_cfg_get_enclosure - obtain enclosure page 0
 * @ioa: per adapter object
 * @ssi_reply: reply mf payload returned from firmware
 * @config_page: contents of the config page
 * @form: GET_NEXT_HANDLE or HANDLE
 * @handle: expander handle
 * Context: sleep.
 *
 * Returns 0 for success, non-zero for failure.
 */
int
hst2dr_cfg_get_enclosure(struct HST2DR_ADAPTER *ioa, SSI2_INQUIRY_PAGE_REPLY
	*ssi_reply, SSI2_INQUIRY_ENCLOSURE *config_page, u32 form, u32 handle)
{
	SSI2_INQUIRY_PAGE_REQUEST ssi_request;
	int r;

	log_config(ioa, "%s form:%x handle:%x\n", __func__, form, handle);
	memset(&ssi_request, 0, sizeof(SSI2_INQUIRY_PAGE_REQUEST));
	ssi_request.header.type = SSI2_CONFIG_TYPE_ENCLOSURE;
	ssi_request.header.number = 0;
	ssi_request.header.len = sizeof(*config_page) / 4;

	ssi_request.address = cpu_to_le32(form | handle);
	ssi_request.header.cmd = SSI2_CONFIG_CMD_PAGE_READ_CURRENT;
	r = _cfg_request(ioa, &ssi_request, ssi_reply,
		HST2DR_CONFIG_PAGE_DEFAULT_TIMEOUT, config_page,
		sizeof(*config_page));
	return r;
}

/**
 * hst2dr_cfg_get_phy - obtain phy page 0
 * @ioa: per adapter object
 * @ssi_reply: reply mf payload returned from firmware
 * @config_page: contents of the config page
 * @phy_number: phy number
 * Context: sleep.
 *
 * Returns 0 for success, non-zero for failure.
 */
int
hst2dr_cfg_get_phy(struct HST2DR_ADAPTER *ioa, SSI2_INQUIRY_PAGE_REPLY
	*ssi_reply, SSI2_INQUIRY_PHY *config_page, int phy_number)
{
	SSI2_INQUIRY_PAGE_REQUEST ssi_request;
	int r;

	log_config(ioa, "%s, phy_number:%x\n", __func__, phy_number);

	memset(&ssi_request, 0, sizeof(SSI2_INQUIRY_PAGE_REQUEST));
	ssi_request.header.type = SSI2_CONFIG_TYPE_PHY;
	ssi_request.header.number = 0;
	if (phy_number & 0x8000) {
		if (ioa->info.fw_version.dword < 0x22081200)
			return -EFAULT;
		ssi_request.header.len =
			sizeof(*config_page) / 4 * (phy_number & 0xff);
	} else
		ssi_request.header.len = sizeof(*config_page) / 4;

	ssi_request.address =
		cpu_to_le32(SSI2_SAS_PHY_PGAD_FORM_PHY_NUMBER | phy_number);
	ssi_request.header.cmd = SSI2_CONFIG_CMD_PAGE_READ_CURRENT;
	r = _cfg_request(ioa, &ssi_request, ssi_reply,
		HST2DR_CONFIG_PAGE_DEFAULT_TIMEOUT, config_page,
		ssi_request.header.len * 4);
	return r;
}

/**
 * hst2dr_cfg_get_phy02 - obtain phy page 2
 * @ioa: per adapter object
 * @ssi_reply: reply mf payload returned from firmware
 * @config_page: contents of the config page
 * @phy_number: phy number
 * Context: sleep.
 *
 * Returns 0 for success, non-zero for failure.
 */
int
hst2dr_cfg_get_phy_counter(struct HST2DR_ADAPTER *ioa, SSI2_INQUIRY_PAGE_REPLY
	*ssi_reply, SSI2_INQUIRY_PHY_COUNTER *config_page, int phy_number)
{
	SSI2_INQUIRY_PAGE_REQUEST ssi_request;
	int r;

	log_config(ioa, "%s, phy_number:%x\n", __func__, phy_number);
	memset(&ssi_request, 0, sizeof(SSI2_INQUIRY_PAGE_REQUEST));
	ssi_request.header.type = SSI2_CONFIG_TYPE_PHY;
	ssi_request.header.number = 2;
	ssi_request.header.len = sizeof(*config_page) / 4;

	ssi_request.address =
		cpu_to_le32(SSI2_SAS_PHY_PGAD_FORM_PHY_NUMBER | phy_number);
	ssi_request.header.cmd = SSI2_CONFIG_CMD_PAGE_READ_CURRENT;
	r = _cfg_request(ioa, &ssi_request, ssi_reply,
		HST2DR_CONFIG_PAGE_DEFAULT_TIMEOUT, config_page,
		sizeof(*config_page));
	return r;
}
/**
 * hst2dr_cfg_get_raid_vol - obtain raid vol page 0
 * @ioa: per adapter object
 * @ssi_reply: reply mf payload returned from firmware
 * @config_page: contents of the config page
 * Returns 0 for success, non-zero for failure.
 */
int
hst2dr_cfg_get_raid_vol(struct HST2DR_ADAPTER *ioa, SSI2_INQUIRY_PAGE_REPLY
	*ssi_reply, SSI2_INQUIRY_RAID_VOL *config_page, int sz,
	u32 form, u32 handle)
{
	SSI2_INQUIRY_PAGE_REQUEST ssi_request;
	int r;

	log_config(ioa, "%s, form:%x handle:%x\n", __func__, form, handle);
	memset(&ssi_request, 0, sizeof(SSI2_INQUIRY_PAGE_REQUEST));
	ssi_request.header.type = SSI2_CONFIG_TYPE_RAID;
	ssi_request.header.number = 0;
	ssi_request.header.len = sz / 4; // max 256 PD
	ssi_request.address =
		cpu_to_le32(SSI2_RAID_VOLUME_PGAD_FORM_HANDLE | handle);
	ssi_request.header.cmd = SSI2_CONFIG_CMD_PAGE_READ_CURRENT;
	r = _cfg_request(ioa, &ssi_request, ssi_reply,
		HST2DR_CONFIG_PAGE_DEFAULT_TIMEOUT, config_page,
		sz);
	return r;
}
/**
 * hst2dr_cfg_get_raid_info - obtain raid vol page 1
 * @ioa: per adapter object
 * @ssi_reply: reply mf payload returned from firmware
 * @config_page: contents of the config page
 * @phy_number: phy number
 * Returns 0 for success, non-zero for failure.
 */
int
hst2dr_cfg_get_raid_info(struct HST2DR_ADAPTER *ioa, SSI2_INQUIRY_PAGE_REPLY
	*ssi_reply, SSI2_INQUIRY_RAID_INFO *config_page, u32 form, u32 handle)
{
	SSI2_INQUIRY_PAGE_REQUEST ssi_request;
	int r;

	log_config(ioa, "%s, form:%x handle:%x\n", __func__, form, handle);
	memset(&ssi_request, 0, sizeof(SSI2_INQUIRY_PAGE_REQUEST));
	ssi_request.header.type = SSI2_CONFIG_TYPE_RAID;
	ssi_request.header.number = 1;
	ssi_request.header.len = sizeof(*config_page) / 4;
	ssi_request.address = cpu_to_le32(form | handle);
	ssi_request.header.cmd = SSI2_CONFIG_CMD_PAGE_READ_CURRENT;
	r = _cfg_request(ioa, &ssi_request, ssi_reply,
		HST2DR_CONFIG_PAGE_DEFAULT_TIMEOUT, config_page,
		sizeof(*config_page));
	return r;
}
/**
 * hst2dr_cfg_get_raid_pd - obtain raid phys disk page
 * @ioa: per adapter object
 * @ssi_reply: reply mf payload returned from firmware
 * @config_page: contents of the config page
 * @phy_number: phy number
 * Returns 0 for success, non-zero for failure.
 */
int
hst2dr_cfg_get_raid_pd(struct HST2DR_ADAPTER *ioa, SSI2_INQUIRY_PAGE_REPLY
	*ssi_reply, SSI2_INQUIRY_RAID_PD *config_page,
	u32 form, u32 form_specific)
{
	SSI2_INQUIRY_PAGE_REQUEST ssi_request;
	int r;

	log_config(ioa, "%s, form:%x form_specific:%x\n",
		__func__, form, form_specific);
	memset(&ssi_request, 0, sizeof(SSI2_INQUIRY_PAGE_REQUEST));
	ssi_request.header.type = SSI2_CONFIG_TYPE_RAID;
	ssi_request.header.number = 2;
	ssi_request.header.len = sizeof(*config_page) / 4;
	ssi_request.address = cpu_to_le32(form | form_specific);
	ssi_request.header.cmd = SSI2_CONFIG_CMD_PAGE_READ_CURRENT;
	r = _cfg_request(ioa, &ssi_request, ssi_reply,
		HST2DR_CONFIG_PAGE_DEFAULT_TIMEOUT, config_page,
		sizeof(*config_page));
	return r;
}
/**
 * hst2dr_config_get_number_pds - obtain number of phys disk assigned to volume
 * @ioa: per adapter object
 * @handle: volume handle
 * @num_pds: returns pds count
 * Context: sleep.
 *
 * Returns 0 for success, non-zero for failure.
 */
int
hst2dr_config_get_number_pds(struct HST2DR_ADAPTER *ioa, u16 handle,
	u16 *num_pds)
{
	SSI2_INQUIRY_PAGE_REQUEST ssi_request;
	SSI2_INQUIRY_RAID_VOL config_page;
	SSI2_INQUIRY_PAGE_REPLY ssi_reply;
	int r;
	u16 ioa_status;

	log_config(ioa, "%s, handle:%x\n", __func__, handle);
	memset(&ssi_request, 0, sizeof(SSI2_INQUIRY_PAGE_REQUEST));
	*num_pds = 0;
	ssi_request.header.type = SSI2_CONFIG_TYPE_RAID;
	ssi_request.header.number = 0;
	ssi_request.header.len = sizeof(config_page) / 4;
	ssi_request.address =
		cpu_to_le32(SSI2_RAID_VOLUME_PGAD_FORM_HANDLE | handle);
	ssi_request.header.cmd = SSI2_CONFIG_CMD_PAGE_READ_CURRENT;


	r = _cfg_request(ioa, &ssi_request, &ssi_reply,
		HST2DR_CONFIG_PAGE_DEFAULT_TIMEOUT, &config_page,
			sizeof(SSI2_INQUIRY_RAID_VOL));
	if (!r) {
		ioa_status = le16_to_cpu(ssi_reply.status) &
			SSI2_IOASTATUS_MASK;
		if (ioa_status == SSI2_IOASTATUS_SUCCESS)
			*num_pds = config_page.num_phys_disks;
	}

	return r;
}
/**
 * hst2dr_config_get_volume_wwid - returns wwid given the volume handle
 * @ioa: per adapter object
 * @volume_handle: volume handle
 * @wwid: volume wwid
 * @device_info: volume device info
 *
 * Returns 0 for success, non-zero for failure.
 */
int
hst2dr_config_get_volume_wwid(struct HST2DR_ADAPTER *ioa, u16 volume_handle,
	u64 *wwid, U32 *device_info, u16 *qdepth)
{
	SSI2_INQUIRY_PAGE_REPLY ssi_reply;
	SSI2_INQUIRY_RAID_INFO raid_vol_pg1;

	*wwid = 0;
	*device_info = 0;
	log_config(ioa, "%s, volume_handle:%x\n", __func__, volume_handle);
	if (!(hst2dr_cfg_get_raid_info(ioa, &ssi_reply,
		&raid_vol_pg1, SSI2_SAS_ENCLOS_PGAD_FORM_HANDLE,
		volume_handle))) {
		*wwid = le64_to_cpu(raid_vol_pg1.WWID);
		*device_info = le32_to_cpu(raid_vol_pg1.device_info);
		*qdepth = le16_to_cpu(raid_vol_pg1.io_qdepth) * 128;
		return 0;
	} else
		return -1;
}
/**
 * hst2dr_config_get_volume_handle - returns volume handle for give handle
 * raid components
 * @ioa: per adapter object
 * @pd_handle: phys disk handle
 * @volume_handle: volume handle
 * Context: sleep.
 *
 * Returns 0 for success, non-zero for failure.
 */
int
hst2dr_config_get_volume_handle(struct HST2DR_ADAPTER *ioa, u16 pd_handle,
	u16 *volume_handle)
{
	SSI2_INQUIRY_RAID_CONFIG *config_page = NULL;
	SSI2_INQUIRY_PAGE_REQUEST ssi_request;
	SSI2_INQUIRY_PAGE_REPLY ssi_reply;
	int r, i, config_page_sz;
	u16 ioa_status;
	int config_num;
	u16 element_type;
	u16 phys_disk_dev_handle;

	*volume_handle = 0;
	log_config(ioa, "%s, pd_handle:%x\n", __func__, pd_handle);
	memset(&ssi_request, 0, sizeof(ssi_request));
	ssi_request.header.type = SSI2_CONFIG_TYPE_RAID;
	ssi_request.header.number = 3;
	ssi_request.header.len = sizeof(struct _SSI2_INQUIRY_RAID_CONFIG) / 4;
	ssi_request.header.cmd = SSI2_CONFIG_CMD_PAGE_READ_CURRENT;

	config_page_sz = sizeof(struct _SSI2_INQUIRY_RAID_CONFIG);
	config_page = kmalloc(config_page_sz, GFP_KERNEL);
	if (!config_page) {
		r = -1;
		goto out;
	}
	config_num = 0xff;
	while (1) {
		ssi_request.address = cpu_to_le32(config_num +
			SSI2_PHYSDISK_PGAD_FORM_GET_NEXT_PHYSDISKNUM);
		r = _cfg_request(ioa, &ssi_request, &ssi_reply,
			HST2DR_CONFIG_PAGE_DEFAULT_TIMEOUT, config_page,
			config_page_sz);

		if (r)
			goto out;
		r = -1;
		ioa_status = le16_to_cpu(ssi_reply.status) &
				SSI2_IOASTATUS_MASK;
		if (ioa_status != SSI2_IOASTATUS_SUCCESS)
			goto out;
		for (i = 0; i < (config_page->num_elements < 0x10 ?
				config_page->num_elements : 0x10); i++) {
			element_type = le16_to_cpu(
				config_page->config_element[i].element_flags) &
				SSI2_RAID_CONFIG_EFLAGS_MASK_ELEMENT_TYPE;
			if (element_type ==
				SSI2_RAID_CONFIG_EFLAGS_VOL_PHYS_DISK_ELEMENT ||
				element_type ==
				SSI2_RAID_CONFIG_EFLAGS_OCE_ELEMENT) {
				phys_disk_dev_handle = le16_to_cpu
					(config_page->config_element[i].phys_disk_dev_handle);
				if (phys_disk_dev_handle == pd_handle) {
					*volume_handle = le16_to_cpu
						(config_page->config_element[i].vol_dev_handle);
					r = 0;
					goto out;
				}
			} else if (element_type ==
				SSI2_RAID_CONFIG_EFLAGS_HOT_SPARE_ELEMENT) {
				*volume_handle = 0;
				r = 0;
				goto out;
			}
		}
		config_num = config_page->config_num;
	}
 out:

	kfree(config_page);
	return r;
}

/**
 * hst2dr_config_get_volume_handles - returns volume handles
 * raid components
 * @ioa: per adapter object
 * @volume_handles: volume handles bit mask, 0: handle present,
 *					1:handle not exist
 * Context: sleep.
 *
 * Returns 0 for success, non-zero for failure.
 */
int
hst2dr_config_get_raid_handles(struct HST2DR_ADAPTER *ioa,
	U64 *volume_handles)
{
	U64 vol_handles;
	SSI2_INQUIRY_PAGE_REQUEST ssi_request;
	SSI2_INQUIRY_PAGE_REPLY ssi_reply;
	int r, config_page_sz;
	u16 ioa_status;

	*volume_handles = 0xffffffffffffffff;
	log_config(ioa, "%s\n", __func__);
	memset(&ssi_request, 0, sizeof(ssi_request));
	ssi_request.header.type = SSI2_CONFIG_TYPE_RAID;
	ssi_request.header.number = 0x10;
	ssi_request.header.len = sizeof(vol_handles)/4;
	ssi_request.header.cmd = SSI2_CONFIG_CMD_PAGE_READ_CURRENT;

	config_page_sz = sizeof(vol_handles);
	ssi_request.address =
		cpu_to_le32(SSI2_RAID_VOLUME_PGAD_FORM_HANDLE) | 0x0800;
	r = _cfg_request(ioa, &ssi_request, &ssi_reply,
			HST2DR_CONFIG_PAGE_DEFAULT_TIMEOUT, &vol_handles,
			config_page_sz);

	if (r) {
		log_error(ioa, "%s ret=%x\n", __func__, r);
		goto out;
	}
	r = -1;
	ioa_status = le16_to_cpu(ssi_reply.status) & SSI2_IOASTATUS_MASK;
	if (ioa_status != SSI2_IOASTATUS_SUCCESS)
		goto out;
	*volume_handles = vol_handles;
	r = 0;
 out:

	return r;
}

