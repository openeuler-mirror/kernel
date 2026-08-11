// SPDX-License-Identifier: GPL-2.0
/*
 * This is the hst2dr driver providing communication ssi2 interface
 * for access to hst2dr firmware.
 *
 * This code is based on drivers/scsi/hst2dr/hst2dr_comm.c

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


#define HST2DR_COMM_C
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

#include "hst2dr_base.h"
#include "hst2dr_comm.h"
#include "hst2dr_debug.h"


#ifdef HST2DR_LOG


/**
 * _debug_dump_mem - dump data for debugging
 * @hints: dump data guide info
 * @mem: dump data memory address
 * @sz: data size
 *
 */

void _debug_dump_mem(char *hints, void *mem, int sz)
{
	int i;
	unsigned char dump_buffer[256];
	__le32 *mfp = (__le32 *)mem;

	memset(dump_buffer, 0, sizeof(dump_buffer));
	pr_info("%s\n", hints);
	for (i = 0; i < sz / 4; i++) {
		if (i && ((i % 8) == 0)) {
			pr_info("%s\n", dump_buffer);
			dump_buffer[0] = 0;
		}
		snprintf(&dump_buffer[strlen(dump_buffer)],
			sizeof(dump_buffer) - strlen(dump_buffer),
			"%08x ",
			le32_to_cpu(mfp[i]));
	}
	pr_info("%s\n", dump_buffer);
}
#else
void _debug_dump_mem(char *hints, void *mem, int sz)
{
}
#endif
/**
 * hst2dr_send_pool_cmd_hal_api - send vendor pool cmd to hba
 *
 * @ioa: per adapter object
 * @c:vendor cmd
 * Returns 0 for success, non-zero for failure.
 */
int hst2dr_send_pool_cmd_hal_api(struct HST2DR_ADAPTER *ioa, void *c)
{
	struct _hst2dr_vendor_cmd *ssl_cmd = (struct _hst2dr_vendor_cmd *)c;

	struct _hst2dr_command *scmd;

	struct nvme_queue *nvmeq;
	u16 sq_tail, cq_head;
	u16 q_num;
	u16 wait_cnt = WAIT_SYNC_CMD_TIME;
	u16 status;

	scmd = (struct _hst2dr_command *)c;
	debug_dump_mem("ssi:", scmd, 0x40);

	nvmeq = &ioa->hst2dr_var.nvmeq[0];
	q_num = 0;
	if (hst2dr_check_queue_full(ioa, 0)) {
		atomic_inc(&ioa->hst2dr_var.queue_full_cnt[0]);
		return ADMIN_QUEUE_FULL;
	}
	if ((ioa->q_mode == Q_MODE_2) || (ioa->q_mode == Q_MODE_4)) {
		cq_head = nvmeq->cq_head;
		sq_tail = nvmeq->sq_tail;
		memcpy(nvmeq->sq_cmds + (sq_tail << 1), &(*scmd),
			sizeof(*scmd));

		if (++sq_tail == nvmeq->sq_depth)
			sq_tail = 0;

		if (ioa->q_mode == Q_MODE_2)
			writel(sq_tail, SQ_TAIL(0));
		else
			writel(sq_tail,
				&ioa->chip->RegsBase +
				(NVME_REG_ADMIN_SQ >> 2));

		nvmeq->sq_tail = sq_tail;
	} else {
		cq_head = nvmeq->cq_head;
		sq_tail = nvmeq->sq_tail;
		if (++sq_tail == nvmeq->sq_depth)
			sq_tail = 0;
		writel(ssl_cmd->host_tag_id,
			&ioa->chip->RegsBase + (NVME_REG_ADMIN_SQ >> 2));
		nvmeq->sq_tail = sq_tail;
	}
	msleep(50);
	wait_cnt -= 5;
	while (--wait_cnt > 0) {
		if ((ioa->hst2dr_var.intr_enabled) && (!ioa->mask_interrupts))
			if (cq_head != nvmeq->cq_head)
				return 0;
			else
				msleep(10);
		else if ((le16_to_cpu(nvmeq->cqes[nvmeq->cq_head].ctrl.phase) &
				1) == nvmeq->cq_phase) {
			status = nvmeq->cqes[nvmeq->cq_head].ctrl.status;
			if (++nvmeq->cq_head == nvmeq->cq_depth) {
				nvmeq->cq_head = 0;
				nvmeq->cq_phase = !nvmeq->cq_phase;
			}
			writel(nvmeq->cq_head, CQ_HEADER(0));
			if (status == SSI2_IOASTATUS_SUCCESS)
				return 0;
			else {
				log_error(ioa, "%s %d status fail:%x\n",
					__func__, __LINE__, status);
				return -EIO;
			}
		} else {
			if (nvmeq->cq_head == nvmeq->sq_tail)
				return 0;
			msleep(10);
		}
	}
	log_error(ioa, "%s %d send cmd fail\n",
		__func__, __LINE__);
	return -EBUSY;
}

/**
 * hst2dr_get_ioa_info_comm_api - obtain ioa info api
 * @ioa: per adapter object
 * @basic_info: io adapter information
 *
 * Returns 0 for success, non-zero for failure.
 */

int hst2dr_get_ioa_info_comm_api(struct HST2DR_ADAPTER *ioa,
	SSI2_IOA_INFO_REPLY *basic_info)
{
	struct _hst2dr_command *scmd;
	dma_addr_t dma_addr;
	int dma_len = sizeof(SSI2_IOA_INFO_REPLY);
	void *p_dma_data;
	int status;
	int flag = 0;

	p_dma_data = dma_alloc_coherent(&ioa->pdev->dev, dma_len,
					&dma_addr, GFP_KERNEL);
	if (!p_dma_data) {
		log_error(ioa,
			"%s: dma allocate %d bytes fail!\n", __func__, dma_len);
		return -ENOMEM;
	}
	memset(p_dma_data, 0, dma_len);
	if (ioa->request == NULL) {
		flag = 0x55;
		if ((ioa->q_mode == Q_MODE_2) || (ioa->q_mode == Q_MODE_4))
			ioa->request = dma_alloc_coherent(&ioa->pdev->dev, 128,
					&ioa->request_dma, GFP_KERNEL);
	}
	scmd = (struct _hst2dr_command *)(ioa->request +
		HOST_TAG_ID_POLL * 128);
	memset(scmd, 0, sizeof(*scmd));

	scmd->cmd.internal.cmd.ioa_info_request.opcode = SSI2_FUNCTION_IOA_INFO;
	scmd->cmd.internal.cmd.ioa_info_request.opflags =
			cmd_flag_fw_mode_admin;
	scmd->cmd.internal.cmd.ioa_info_request.host_tag_id = HOST_TAG_ID_POLL;
	scmd->cmd.internal.cmd.ioa_info_request.host_flag = hst2dr_cmd_ioa_info;
	scmd->cmd.internal.cmd.ioa_info_request.sgl.len = dma_len;
	scmd->cmd.internal.cmd.ioa_info_request.sgl.address =
			cpu_to_le64(dma_addr);
	scmd->cmd.internal.cmd.ioa_info_request.sgl.flag =
			SSI2_IEEE_SGE_FLAGS_END_OF_LIST;

	status = hst2dr_send_pool_cmd_hal_api(ioa, scmd);
	if (status != 0) {
		log_error(ioa, "ioa info request status:%x\n", status);
		dma_free_coherent(&ioa->pdev->dev, dma_len,
			p_dma_data, dma_addr);
		if (flag == 0x55) {
			if ((ioa->q_mode == Q_MODE_2) ||
					(ioa->q_mode == Q_MODE_4)) {
				dma_free_coherent(&ioa->pdev->dev,
					128, ioa->request,
					ioa->request_dma);
				ioa->request = NULL;
				ioa->request_dma = 0;
			}
		}
		return -EIO;
	}
	debug_dump_mem("ioa info", p_dma_data, dma_len);

	memcpy((u64 *)basic_info, (u64 *)p_dma_data, dma_len);

	dma_free_coherent(&ioa->pdev->dev, dma_len, p_dma_data, dma_addr);
	if (flag == 0x55) {
		if ((ioa->q_mode == Q_MODE_2) ||
				(ioa->q_mode == Q_MODE_4)) {
			dma_free_coherent(&ioa->pdev->dev,
				128, ioa->request, ioa->request_dma);
			ioa->request = NULL;
			ioa->request_dma = 0;
		}
	}
	return 0;
}


/**
 * hst2dr_ioa_init_comm_api - send ioa_init to firmware api
 * @ioa: per adapter object
 * @ssi_request: io adapt init request
 *
 * Returns 0 for success, non-zero for failure.
 */

int hst2dr_ioa_init_comm_api(struct HST2DR_ADAPTER *ioa,
	SSI2_IOA_INIT_REQUEST *ssi_request,
	SSI2_IOA_INIT_REPLY *ioa_init_reply)
{

	struct _hst2dr_command *scmd;
	dma_addr_t dma_addr;
	int dma_len = sizeof(SSI2_IOA_INIT_REPLY);
	void *p_dma_data;
	int status;

	p_dma_data = dma_alloc_coherent(&ioa->pdev->dev, dma_len,
					&dma_addr, GFP_KERNEL);
	if (!p_dma_data) {
		log_error(ioa,
			"%s: dma calloc fail!\n", __func__);
		return -ENOMEM;
	}
	memset(p_dma_data, 0, dma_len);
	scmd = (struct _hst2dr_command *)ssi_request;
	scmd->cmd.internal.cmd.ioa_init_request.sgl.len = dma_len;
	scmd->cmd.internal.cmd.ioa_init_request.sgl.address =
			cpu_to_le64(dma_addr);
	scmd->cmd.internal.cmd.ioa_init_request.sgl.flag =
			SSI2_IEEE_SGE_FLAGS_END_OF_LIST;
	status = hst2dr_send_pool_cmd_hal_api(ioa, scmd);
	memcpy(ioa_init_reply, p_dma_data, dma_len);
	if (status != 0) {
		log_error(ioa, "ioa init status:%x\n", status);
		dma_free_coherent(&ioa->pdev->dev,
			dma_len, p_dma_data, dma_addr);
		if (ioa_init_reply->opcode != SSI2_FUNCTION_IOA_INIT)
			return -EIO;
	} else {
		debug_dump_mem("init", p_dma_data, dma_len);
		dma_free_coherent(&ioa->pdev->dev, dma_len,
			p_dma_data, dma_addr);
	}
	return 0;
}


/**
 * hst2dr_build_scsiio_cmd_api - build scsi io command
 * @ioa: per adapter object
 * @ssi_request: scsi io request
 * @host_tag_id: message index
 *
 * Returns 0 for success, non-zero for failure.
 */

void hst2dr_build_scsiio_cmd_api(struct HST2DR_ADAPTER *ioa,
	SSI2_SCSI_REQUEST *ssi_request, u16 host_tag_id)
{
	switch (ssi_request->cdb.cdb[0]) {
	case READ_6:
	case READ_10:
	case READ_12:
	case READ_16:
	case READ_32:
		ssi_request->host_cmd_flags.io_flag = io_flag_read;
		ssi_request->opflags |= cmd_flag_hw_mode;
		break;
	case WRITE_6:
	case WRITE_10:
	case WRITE_12:
	case WRITE_16:
	case WRITE_32:
		ssi_request->host_cmd_flags.io_flag = io_flag_write;
		ssi_request->opflags |= cmd_flag_hw_mode;
		break;
	case VARIABLE_LENGTH_CMD:
		if (ssi_request->cdb.cdb[9] == WRITE_32)
			ssi_request->host_cmd_flags.io_flag = io_flag_write;
		else if (ssi_request->cdb.cdb[9] == READ_32)
			ssi_request->host_cmd_flags.io_flag = io_flag_read;
		ssi_request->opflags |= cmd_flag_hw_mode;
		break;
	case VENDOR_SPECIFIC_CDB:
		if (ssi_request->cdb.cdb[9] == WRITE_32)
			ssi_request->host_cmd_flags.io_flag = io_flag_write;
		else if (ssi_request->cdb.cdb[9] == READ_32)
			ssi_request->host_cmd_flags.io_flag = io_flag_read;
		ssi_request->opflags |= cmd_flag_fw_mode_io;
		break;

	case ATA_12: //ata passthrough 12
	case ATA_16: //ata passthrough 16
		if (ssi_request->opflags & (2 << 5)) //SATA DEVICE
			ssi_request->opflags |= cmd_flag_fw_mode_io;
		else
			ssi_request->opflags |= cmd_flag_hw_mode;
		break;

	default:
		if (ssi_request->opflags & (2 << 5)) //SATA DEVICE
			ssi_request->opflags |= cmd_flag_fw_mode_io;
		else {
			ssi_request->opflags |= (ioa->nonio_flags & 0xfc);
		}
		break;
	}

	ssi_request->host_tag_id = host_tag_id;
}

/**
 * hst2dr_build_scsiio_cmd_force_fw_mode_api - build scsi io command force fw
 *						mode for fw handle raid
 * @ioa: per adapter object
 * @ssi_request: scsi io request
 * @host_tag_id: message index
 *
 * Returns 0 for success, non-zero for failure.
 */

void hst2dr_build_scsiio_cmd_force_fw_mode_api(struct HST2DR_ADAPTER *ioa,
	SSI2_SCSI_REQUEST *ssi_request, u16 host_tag_id)
{

	switch (ssi_request->cdb.cdb[0]) {
	case READ_6:
	case READ_10:
	case READ_12:
	case READ_16:
	case READ_32:
		ssi_request->host_cmd_flags.io_flag = 2;
		ssi_request->opflags |= cmd_flag_hw_mode;
		break;
	case WRITE_6:
	case WRITE_10:
	case WRITE_16:
	case WRITE_12:
	case WRITE_32:
		ssi_request->host_cmd_flags.io_flag = 1;
		ssi_request->opflags |= cmd_flag_hw_mode;
		break;
	case VARIABLE_LENGTH_CMD:
		if (ssi_request->cdb.cdb[9] == WRITE_32)
			ssi_request->host_cmd_flags.io_flag = 1;
		else if (ssi_request->cdb.cdb[9] == READ_32)
			ssi_request->host_cmd_flags.io_flag = 2;
		ssi_request->opflags |= cmd_flag_hw_mode;
		break;
	case VENDOR_SPECIFIC_CDB:
		if (ssi_request->cdb.cdb[9] == WRITE_32)
			ssi_request->host_cmd_flags.io_flag = 1;
		else if (ssi_request->cdb.cdb[9] == READ_32)
			ssi_request->host_cmd_flags.io_flag = 2;
		ssi_request->opflags |= cmd_flag_fw_mode_io;
		break;
	default:
		if (ssi_request->opflags & (2 << 5)) //SATA DEVICE
			ssi_request->opflags |= cmd_flag_fw_mode_io;
		else {
			ssi_request->opflags |= cmd_flag_fw_mode_io;
		}
		break;
	}

	ssi_request->host_tag_id = host_tag_id;

}

