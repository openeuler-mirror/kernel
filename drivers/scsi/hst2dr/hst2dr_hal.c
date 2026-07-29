// SPDX-License-Identifier: GPL-2.0
/*
 * hst2dr  device driver for Linux.
 *
 * This code is based on drivers/scsi/hst2dr/hst2dr_hal.c

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

#define HST2DR_HAL_C
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

#include "linux/nvme.h"
#include "hst2dr_hal.h"
#include "hst2dr_comm.h"
#include "hst2dr_debug.h"

extern int hst2dr_select_q_mode;
/**
 * hst2dr_nvme_wait_ready - wait for hba ready
 * @ioa: per adapter object
 *
 * Returns 0 for success, non-zero for failure
 */
static int hst2dr_nvme_wait_ready(struct HST2DR_ADAPTER *ioa)
{
	u32 csts;
	u32 cnt = 0, timeout;
	__u64 cap;

	cap = lo_hi_readq(&ioa->chip->RegsBase + NVME_REG_CAP / 4);
	timeout = ((cap >> 24) & 0xff) * 5;
	if (timeout == 0) {
		log_error(ioa, "nvme_wait_ready cap timeout error\n");
		return -EIO;
	}
	log_event(ioa, "CAP:%llx\n", cap);
	while (1) {
		csts = readl(&ioa->chip->RegsBase + (NVME_REG_CSTS >> 2));
		if (csts & NVME_CSTS_RDY) {
			return 0;
		} else {
			cnt++;
			msleep(100);
			if (cnt >= timeout) { // 500ms unit
				log_error(ioa, "CSTS time out\n");
				return -EIO;
			}
		}
	}

}
static int
wait_for_first_cmd_completion(struct HST2DR_ADAPTER *ioa,
	struct nvme_queue *nvmeq, u16 head, u16 tail)
{
	u16 wait_cnt = WAIT_SYNC_CMD_TIME;

	if ((!ioa->hst2dr_var.intr_enabled) || (ioa->mask_interrupts)) {
		while (--wait_cnt != 0)	{
			if  (head != nvmeq->cq_head)
				return 0;
			if ((le16_to_cpu(
					nvmeq->cqes[nvmeq->cq_head].ctrl.phase)
					& 1) == nvmeq->cq_phase) {
				nvmeq->sq_head =
					nvmeq->cqes[nvmeq->cq_head].sq_head;
				if (++nvmeq->cq_head == nvmeq->cq_depth) {
					nvmeq->cq_head = 0;
					nvmeq->cq_phase = !nvmeq->cq_phase;
				}
				writel(nvmeq->cq_head, CQ_HEADER(0));
				return 0;
			} else {
				msleep(10);
			}
		}
		return -EBUSY;
	} else {
		while (--wait_cnt != 0) {
			if (tail == nvmeq->cq_head)
				return 0;
			else
				msleep(10);
		}
		return -EBUSY;
	}
	return 0;
}

/**
 * nvme_set_features - set hba features
 * often use to set number of io cq requested(0 base)  number of io sq
 * requested (0 base)
 * @fid: feature id
 * @dword11: set features parameter
 * @ioa: per adapter object
 *
 * Returns 0 for success, non-zero for failure.
 */
static int nvme_set_features(u32 fid, u32 dword11,
	struct HST2DR_ADAPTER *ioa)
{
	struct nvme_queue *nvmeq = &ioa->hst2dr_var.nvmeq[0];
	struct nvme_command *c;
	u16 tail, head;

	c = (struct nvme_command *)(ioa->request + HOST_TAG_ID_POLL * 128);
	memset(c, 0, sizeof(*c));

	c->features.opcode = nvme_admin_set_features;
	c->features.flags = FLAG_FW_MODE_ADMIN;
	c->features.fid = cpu_to_le32(fid);
	c->features.dword11 = cpu_to_le32(dword11);

	c->features.command_id = HAL_MSG_INDEX;
	if ((ioa->q_mode == Q_MODE_2) || (ioa->q_mode == Q_MODE_4)) {
		tail = nvmeq->sq_tail;
		memcpy(nvmeq->sq_cmds + (tail << 1), c, sizeof(*c));
		head = nvmeq->cq_head;
		if (++tail == nvmeq->sq_depth)
			tail = 0;
		if (ioa->q_mode == Q_MODE_2)
			writel(tail, SQ_TAIL(0));
		else
			writel(tail, &ioa->chip->RegsBase +
					(NVME_REG_ADMIN_SQ >> 2));
		nvmeq->sq_tail = tail;
	} else {
		tail = nvmeq->sq_tail;
		head = nvmeq->cq_head;
		writel(HOST_TAG_ID_POLL, &ioa->chip->RegsBase +
				(NVME_REG_ADMIN_SQ >> 2));
	}

	return wait_for_first_cmd_completion(ioa, nvmeq, head, tail);
}

/**
 * nvme_create_cq - create hba complete queue
 *
 * @qid: queue id
 * @ioa: per adapter object
 *
 * Returns 0 for success, non-zero for failure.
 */
static int nvme_create_cq(u16 qid, struct HST2DR_ADAPTER *ioa)
{
	struct nvme_queue *nvmeq = &ioa->hst2dr_var.nvmeq[qid];
	struct nvme_command *c;
	u16 tail, head;
	u16 vector = 0, node = 0;
	int i;

	for (i = 1; i < ioa->current_Q_num; i++) {
		if (i < qid) {
			vector++;
			if (vector >= ioa->numa_node_vectors[node]) {
				vector = 0;
				node++;
			}
		}
	}

	if ((ioa->info.max_reply_descriptor_post_queue_depth >
				MAX_HW_QUEUE_SIZE) ||
		(IO_QUEUE_SIZE <= 0)) {
		log_error(ioa, "queue depth error\n");
		return -EFAULT;
	}
	if (ioa->reply_queue_count == 1)
		nvmeq->cq_depth = ioa->scsiio_depth;
	else if (qid == ioa->reply_queue_count)
		nvmeq->cq_depth = INTERNAL_SCSIIO_CMDS_COUNT;
	else
		nvmeq->cq_depth = 4096;

	if (qid <= (ioa->reply_queue_count - 1))
		nvmeq->cq_vector = qid;
	else
		nvmeq->cq_vector = (ioa->reply_queue_count - 1);

	if (ioa->hst2dr_nvme_dma[qid].cqes == 0) {
		nvmeq->cqes = dma_alloc_coherent(&ioa->pdev->dev,
					CQ_SIZE(nvmeq->cq_depth),
					&nvmeq->cq_dma_addr, GFP_KERNEL);
		if (!nvmeq->cqes) {
			log_error(ioa, "dma alloc fail\n");
			return -ENOMEM;
		}
		memset((void *)nvmeq->cqes, 0, CQ_SIZE(nvmeq->cq_depth));
		ioa->hst2dr_nvme_dma[qid].cqes =
			(hst2dr_nvme_completion *)nvmeq->cqes;
		ioa->hst2dr_nvme_dma[qid].cq_dma_addr = nvmeq->cq_dma_addr;
	} else {
		nvmeq->cqes = ioa->hst2dr_nvme_dma[qid].cqes;
		nvmeq->cq_dma_addr = ioa->hst2dr_nvme_dma[qid].cq_dma_addr;
		memset((void *)nvmeq->cqes, 0, CQ_SIZE(nvmeq->cq_depth));
	}

	c = (struct nvme_command *)(ioa->request + HOST_TAG_ID_POLL * 128);
	memset(c, 0, sizeof(*c));
	c->create_cq.opcode = nvme_admin_create_cq;
	c->create_cq.flags = FLAG_FW_MODE_ADMIN;
	c->create_cq.prp1 = cpu_to_le64(nvmeq->cq_dma_addr);
	// dw10
	c->create_cq.cqid = cpu_to_le16(qid);
	c->create_cq.qsize = cpu_to_le16(nvmeq->cq_depth - 1);
	// dw11
	c->create_cq.irq_vector = cpu_to_le16(nvmeq->cq_vector);
	c->create_cq.command_id = HAL_MSG_INDEX;
	c->create_cq.rsvd12[0] = (ioa->numa_node_vectors[node] << 16) | node;
	c->create_cq.rsvd12[1] = ioa->current_Q_num;
	log_hal(ioa,
		"vectors in node :0x%02x node:0x%02x total io vectors:0x%02x\n",
		ioa->numa_node_vectors[node], node, ioa->current_Q_num);
	debug_dump_mem("create cq", c, 128);
	nvmeq = &ioa->hst2dr_var.nvmeq[0];
	if ((ioa->q_mode == Q_MODE_2) || (ioa->q_mode == Q_MODE_4)) {
		tail = nvmeq->sq_tail;

		memcpy(nvmeq->sq_cmds + (tail << 1), c, sizeof(*c));
		head = nvmeq->cq_head;
		if (++tail == nvmeq->sq_depth)
			tail = 0;
		if (ioa->q_mode == Q_MODE_2)
			writel(tail,
					&ioa->chip->RegsBase +
					(NVME_REG_DBS >> 2));
		else
			writel(tail,
					&ioa->chip->RegsBase +
					(NVME_REG_ADMIN_SQ >> 2));
		nvmeq->sq_tail = tail;
	} else {
		tail = nvmeq->cq_head;
		head = nvmeq->cq_head;
		writel(HOST_TAG_ID_POLL,
				&ioa->chip->RegsBase +
				(NVME_REG_ADMIN_SQ >> 2));
	}

	return wait_for_first_cmd_completion(ioa, nvmeq, head, tail);
}
/**
 * nvme_create_sq - create hba submission queue
 *
 * @qid: queue id
 * @ioa: per adapter object
 *
 * Returns 0 for success, non-zero for failure.
 */
static int nvme_create_sq(u16 qid, struct HST2DR_ADAPTER *ioa)
{
	struct nvme_queue *nvmeq = &ioa->hst2dr_var.nvmeq[qid];
	struct nvme_command *c;
	u16 tail, head;

	if (ioa->q_mode == Q_MODE_3)
		if (ioa->chip_version == VS_V2N1)
			nvmeq->sq_depth = IO_QUEUE_SIZE;
		else
			nvmeq->sq_depth = ioa->scsiio_depth;
	else if (ioa->reply_queue_count == 1) // LEGACY
		if (ioa->chip_version == VS_V2N1)
			nvmeq->sq_depth = IO_QUEUE_SIZE;
		else
			nvmeq->sq_depth = ioa->scsiio_depth;
	else if (qid == ioa->reply_queue_count - 1)
		nvmeq->sq_depth = INTERNAL_SCSIIO_CMDS_COUNT;
	else {
		if (ioa->reply_queue_count > 2)
			nvmeq->sq_depth =
				(ioa->info.max_reply_descriptor_post_queue_depth
				- INTERNAL_QUEUE_DEPTH) /
				(ioa->reply_queue_count - 2);
		else
			nvmeq->sq_depth =
				(ioa->info.max_reply_descriptor_post_queue_depth
				- INTERNAL_QUEUE_DEPTH);
	}
	if (ioa->hst2dr_nvme_dma[qid].sq_cmds == 0) {
		if ((ioa->q_mode == Q_MODE_2) ||
				(ioa->q_mode == Q_MODE_4)) {
			nvmeq->sq_cmds = dma_alloc_coherent(&ioa->pdev->dev,
						SQ_SIZE(nvmeq->sq_depth),
						&nvmeq->sq_dma_addr,
						GFP_KERNEL);
			if (!nvmeq->sq_cmds) {
				log_error(ioa, "dma alloc fail\n");
				return -ENOMEM;
			}
			ioa->hst2dr_nvme_dma[qid].sq_cmds = nvmeq->sq_cmds;
			ioa->hst2dr_nvme_dma[qid].sq_dma_addr =
				nvmeq->sq_dma_addr;
		} else {
			ioa->hst2dr_nvme_dma[qid].sq_cmds = NULL;
			ioa->hst2dr_nvme_dma[qid].sq_dma_addr =
				ioa->hst2dr_var.nvmeq[0].sq_dma_addr;
		}
	} else {
		nvmeq->sq_cmds = ioa->hst2dr_nvme_dma[qid].sq_cmds;
		nvmeq->sq_dma_addr = ioa->hst2dr_nvme_dma[qid].sq_dma_addr;
	}
	c = (struct nvme_command *)(ioa->request + HOST_TAG_ID_POLL * 128);
	memset(c, 0, sizeof(*c));
	c->create_sq.opcode = nvme_admin_create_sq;
	c->create_sq.flags = FLAG_FW_MODE_ADMIN;
	if (ioa->q_mode == Q_MODE_3)
		c->create_sq.prp1 =
			cpu_to_le64(ioa->hst2dr_var.nvmeq[0].sq_dma_addr);
	else
		c->create_sq.prp1 = cpu_to_le64(nvmeq->sq_dma_addr);
	c->create_sq.sqid = cpu_to_le16(qid);
	c->create_sq.qsize = cpu_to_le16(nvmeq->sq_depth - 1);
	c->create_sq.cqid = cpu_to_le16(qid);
	c->create_sq.command_id = HAL_MSG_INDEX;
	nvmeq = &ioa->hst2dr_var.nvmeq[0];
	if ((ioa->q_mode == Q_MODE_2) || (ioa->q_mode == Q_MODE_4)) {
		tail = nvmeq->sq_tail;
		memcpy(nvmeq->sq_cmds + (tail << 1), c, sizeof(*c));
		head = nvmeq->cq_head;
		if (++tail == nvmeq->sq_depth)
			tail = 0;
		if (ioa->q_mode == Q_MODE_2)
			writel(tail, &ioa->chip->RegsBase +
					(NVME_REG_DBS >> 2));
		else
			writel(tail, &ioa->chip->RegsBase +
					(NVME_REG_ADMIN_SQ >> 2));
		nvmeq->sq_tail = tail;
	} else {
		tail = nvmeq->sq_tail;
		head = nvmeq->cq_head;
		writel(HOST_TAG_ID_POLL,
				&ioa->chip->RegsBase +
				(NVME_REG_ADMIN_SQ >> 2));
	}

	return wait_for_first_cmd_completion(ioa, nvmeq, head, tail);
}
/**
 * hst2dr_nvme_controller_reg_init - init controller, queue var and wait
 * for controller ready
 *
 * @ioa: per adapter object
 *
 * Returns 0 for success, non-zero for failure.
 */
static int hst2dr_nvme_controller_reg_init(struct HST2DR_ADAPTER *ioa,
		int is_chip_reset)
{
	struct nvme_queue *nvmeq = &ioa->hst2dr_var.nvmeq[0];
	int i;
	u32 cc = 0x00460000;
	u32 aqa;
	u32 reset_delay;
	u32 q_mode;
	u32 version;
	u32 csts, csts1;
	u32 r;
	int select_q_mode = hst2dr_select_q_mode;

	version = readl(&ioa->chip->RegsBase + (NVME_REG_VS >> 2));
	ioa->chip_version = version;
	log_hal(ioa, "NVME_REG_VS:%x\n", version);
	switch (version) { // chip generation
	case VS_V2M2:
		ioa->nvme_reg_dbs = 0x1000;
		log_init(ioa, "Detected chip version is V2M2\n");
		break;
	case VS_V2N1:
		ioa->nvme_reg_dbs = 0x2000;
		log_init(ioa, "Detected chip version is V2N1\n");
		break;
	default:
		log_error(ioa, "NVME_REG_VS error, vs:%x\n", version);
		return -EFAULT;
	}

	reset_delay = lo_hi_readq(&ioa->chip->RegsBase +
			(NVME_REG_CAP >> 2));

	cc = readl(&ioa->chip->RegsBase + (NVME_REG_CC >> 2));
	if ((cc & 1) || is_chip_reset) {
		log_init(ioa, "controller reset\n");
		cc &= 0xfffffffe;
		csts = readl(&ioa->chip->RegsBase + (NVME_REG_CSTS >> 2));
		writel(cc, &ioa->chip->RegsBase + (NVME_REG_CC >> 2));
		reset_delay = ((reset_delay >> 24) & 0xff) * 5;
		if (reset_delay == 0)
			reset_delay = HW_RESET_INTERVAL;
		for (i = 0; i < reset_delay; i++) {
			msleep(100);
			csts1 = readl(&ioa->chip->RegsBase +
					(NVME_REG_CSTS >> 2));
			if (csts1 != csts) {
				log_init(ioa, "csts:0x%x\n", csts1);
				break;
			}
		}
		if ((csts == csts1) || (csts1 == 0x0c)) {
			if (ioa->chip_version == VS_V2N1)
				hst2dr_send_chip_reset_sequence(ioa);
			else
				if (hst2dr_signature_sequence_check(ioa) ==
						SUCCESS) {
					hst2dr_write_direct_reg_hal_api(ioa,
						NVME_REG_CHIP_STATUS_CTRL,
						(CHIP_RESET | HW_BALANCE_EN));
					log_debug(ioa,
						"CHIP_STATUS_CTRL write:0x%x\n",
						(CHIP_RESET | HW_BALANCE_EN));
				} else
					return -EFAULT;
			msleep(CHIP_RESET_INTERVAL);
			r = hst2dr_read_direct_reg_hal_api(ioa,
					NVME_REG_CHIP_STATUS);
			log_debug(ioa, "CHIP_RESET chip status:%x\n", r);
			for (i = 0; i < CHIP_RESET_WAITING /
					CHIP_RESET_QUERY_INTERVAL; i++) {
				r = hst2dr_read_direct_reg_hal_api(
						ioa, NVME_REG_CHIP_STATUS);
				if ((r & CHIP_STATUS_MASK) ==
						CHIP_STATUS_READY) {
					log_debug(ioa,
						"CHIP RESET ready, wait:%d ms",
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
	} else {
		for (i = 0; i < CHIP_RESET_WAITING /
				CHIP_RESET_QUERY_INTERVAL; i++) {
			r = hst2dr_read_direct_reg_hal_api(
					ioa, NVME_REG_CHIP_STATUS);
			if ((r & CHIP_STATUS_MASK) ==
					CHIP_STATUS_READY) {
				log_debug(ioa,
					"CHIP RESET ready, wait:%d ms",
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

	if (ioa->chip_version == VS_V2N1) {
		q_mode = readl(&ioa->chip->RegsBase +
			(NVME_REG_Q_MODE_SUPPORTED >> 2));
		log_hal(ioa, "NVME_REG_Q_MODE_SUPPORT:%x\n", q_mode);
		if (select_q_mode == -1) {
			if (q_mode & BIT4) {
				ioa->q_mode = Q_MODE_4;
				if (q_mode & BIT16)
					select_q_mode = BIT4 | BIT16;
				else if (q_mode & BIT17)
					select_q_mode = BIT4 | BIT17;
			} else if (q_mode & BIT3) {
				ioa->q_mode = Q_MODE_3;
				if (q_mode & BIT16)
					select_q_mode = BIT3 | BIT16;
				else if (q_mode & BIT17)
					select_q_mode = BIT3 | BIT17;
			} else if (q_mode & BIT2) {
				ioa->q_mode = Q_MODE_2;
				if (q_mode & BIT16)
					select_q_mode = BIT2 | BIT16;
				else if (q_mode & BIT17)
					select_q_mode = BIT2 | BIT17;
			}
		} else {
			ioa->q_mode = select_q_mode & 0x0f;
			switch (ioa->q_mode) {
			case Q_MODE_2:
				if (q_mode & BIT2)
					if (select_q_mode >> 16)
						select_q_mode =
							BIT2 | BIT17;
					else
						select_q_mode =
							BIT2 | BIT16;
				else
					return -EIO;
				break;
			case Q_MODE_3:
				if (q_mode & BIT3)
					if (select_q_mode >> 16)
						select_q_mode = BIT3 | BIT17;
					else
						select_q_mode =
							BIT3 | BIT16;
				else
					return -EIO;
				break;
			case Q_MODE_4:
				if (q_mode & BIT4)
					if (select_q_mode >> 16)
						select_q_mode =
							BIT4 | BIT17;
					else
						select_q_mode =
							BIT4 | BIT16;
				else
					return -EIO;
				break;
			default:
				return -EIO;
			}

		}
		log_hal(ioa, "NVME_REG_Q_MODE_SET:%x\n", select_q_mode);
		hst2dr_write_direct_reg_hal_api(ioa,
			NVME_REG_Q_MODE_SET,
			select_q_mode);
	} else {
		q_mode = readl(&ioa->chip->RegsBase +
			(NVME_REG_Q_MODE >> 2));
		log_hal(ioa, "NVME_REG_Q_MODE:%x\n", q_mode);
		ioa->q_mode = q_mode & 0xf;

		if ((select_q_mode != ioa->q_mode) &&
				(select_q_mode != -1)) {
			select_q_mode =
				(q_mode & 0xfffffff0) |
					(select_q_mode & 0xf);
			hst2dr_write_direct_reg_hal_api(ioa,
					NVME_REG_Q_MODE,
					select_q_mode);
			ioa->q_mode = select_q_mode & 0xf;
		}

		switch (ioa->q_mode) {
		case Q_MODE_2:
		case Q_MODE_3:
			break;
		default:
			hst2dr_select_q_mode =
				(q_mode & 0xfffffff0) | 3;
			hst2dr_write_direct_reg_hal_api(ioa,
					NVME_REG_Q_MODE,
					select_q_mode);
			ioa->q_mode = 3;
		}

	}
	log_init(ioa, "q_mode:%x\n", ioa->q_mode);
	ioa->info.max_cq = (q_mode >> 4) & 0xfff;
	if (ioa->q_mode == Q_MODE_3) {
		ioa->scsiio_depth = q_mode >> 16;
		ioa->info.max_sq = 2;
	} else
		ioa->info.max_sq = ioa->info.max_cq;

	for (i = 0; i < NUM_OF_IO_Q + 1; i++) {
		ioa->hst2dr_var.nvmeq[i].sq_tail = 0;
		ioa->hst2dr_var.nvmeq[i].cq_head = 0;
		ioa->hst2dr_var.nvmeq[i].sq_head = 0;
		ioa->hst2dr_var.nvmeq[i].cq_phase = 1;
		ioa->hst2dr_var.nvmeq[i].cqe_seen = 0;
	}
	ioa->hst2dr_var.io_tail = 1;
	ioa->hst2dr_var.intr_enabled = 0;
	ioa->hst2dr_var.admin_queue_size  = (u16) (readl(&ioa->chip->RegsBase
		+ NVME_REG_CAP) & 0xffff);

	if (ioa->hst2dr_var.admin_queue_size != INTERNAL_QUEUE_DEPTH) {
		log_error(ioa, "Admin queue size error: %x\n",
			ioa->hst2dr_var.admin_queue_size);
		return -EFAULT;
	}

	if (ioa->q_mode == Q_MODE_3)
		ioa->host_tag_id_poll = IO_QUEUE_SIZE +
			ioa->hst2dr_var.admin_queue_size - 1;
	aqa = (u32)(((ADMIN_QUEUE_SIZE - 1) << 16)
		| (ADMIN_QUEUE_SIZE - 1));

	writel(aqa, &ioa->chip->RegsBase + (NVME_REG_AQA >> 2));
	ioa->hst2dr_var.nvmeq[0].sq_depth = ADMIN_QUEUE_SIZE;
	ioa->hst2dr_var.nvmeq[0].cq_depth = ADMIN_QUEUE_SIZE;

	log_hal(ioa, "set ASQ ACQ, host_tag_id_poll:%x\n", HOST_TAG_ID_POLL);
	// set ASQ AND ACQ
	switch (ioa->q_mode) {
	case Q_MODE_2:
	case Q_MODE_4:
		if (ioa->hst2dr_nvme_dma[0].sq_cmds == 0) {
			nvmeq->sq_cmds = dma_alloc_coherent(&ioa->pdev->dev,
						SQ_SIZE(ADMIN_QUEUE_SIZE),
						&nvmeq->sq_dma_addr,
						GFP_KERNEL);
			if (!nvmeq->sq_cmds)
				goto free_nvmeq;

			ioa->hst2dr_nvme_dma[0].sq_cmds = nvmeq->sq_cmds;
			ioa->hst2dr_nvme_dma[0].sq_dma_addr =
				nvmeq->sq_dma_addr;
		} else {
			nvmeq->sq_cmds = ioa->hst2dr_nvme_dma[0].sq_cmds;
			nvmeq->sq_dma_addr =
				ioa->hst2dr_nvme_dma[0].sq_dma_addr;

		}
		break;
	case Q_MODE_3:
	default:
		if (_base_allocate_memory_request_dma(ioa) != 0)
			return -ENOMEM;
		ioa->hst2dr_nvme_dma[0].sq_cmds = NULL;
		nvmeq->sq_dma_addr = ioa->request_dma;
		ioa->hst2dr_nvme_dma[0].sq_dma_addr = ioa->request_dma;
		break;
	}
	if (ioa->hst2dr_nvme_dma[0].cqes == 0) {
		nvmeq->cqes = dma_alloc_coherent(&ioa->pdev->dev,
						CQ_SIZE(ADMIN_QUEUE_SIZE),
						&nvmeq->cq_dma_addr,
						GFP_KERNEL);
		if (!nvmeq->cqes) {
			dma_free_coherent(&ioa->pdev->dev,
				SQ_SIZE(ADMIN_QUEUE_SIZE),
				nvmeq->sq_cmds, nvmeq->sq_dma_addr);
			goto free_nvmeq;
		}
		memset((void *)nvmeq->cqes, 0, CQ_SIZE(ADMIN_QUEUE_SIZE));
		ioa->hst2dr_nvme_dma[0].cqes =
			(hst2dr_nvme_completion *)nvmeq->cqes;
		ioa->hst2dr_nvme_dma[0].cq_dma_addr = nvmeq->cq_dma_addr;
	} else {
		nvmeq->cqes = ioa->hst2dr_nvme_dma[0].cqes;
		nvmeq->cq_dma_addr = ioa->hst2dr_nvme_dma[0].cq_dma_addr;
		memset((void *)nvmeq->cqes, 0, CQ_SIZE(ADMIN_QUEUE_SIZE));
	}

	log_hal(ioa, "ASQ:%llx ACQ:%llx\n",
			(unsigned long long)nvmeq->sq_dma_addr,
			(unsigned long long)nvmeq->cq_dma_addr);
	lo_hi_writeq(nvmeq->sq_dma_addr,
			&ioa->chip->RegsBase + (NVME_REG_ASQ >> 2));
	lo_hi_writeq(nvmeq->cq_dma_addr,
			&ioa->chip->RegsBase + (NVME_REG_ACQ >> 2));

	// set CC enable
	cc |= 1;
	writel(cc, &ioa->chip->RegsBase + (NVME_REG_CC >> 2));

	// wait for device ready(CSTS.RDY)
	if (hst2dr_nvme_wait_ready(ioa) != 0)
		return -EIO;
	else if (ioa->chip_version == VS_V2N1) {
		q_mode = readl(&ioa->chip->RegsBase + (NVME_REG_Q_MODE >> 2));
		log_hal(ioa, "NVME_REG_Q_MODE:%x\n", q_mode);
		if (ioa->q_mode == Q_MODE_3)
			ioa->scsiio_depth = (q_mode >> 16) + INTERNAL_SCSIIO_CMDS_COUNT;
		if (ioa->q_mode == (q_mode & 0x0f)) {
			if ((select_q_mode & BIT16) &&
					(((q_mode >> 14) & 3) == 0))
				return 0;
			if ((select_q_mode & BIT17) &&
					(((q_mode >> 14) & 3) == 1))
				return 0;
			return -EFAULT;
		} else
			return -EFAULT;
	}
	return 0;
free_nvmeq:
	log_error(ioa,
		"%s %d nvme reg init fail\n",
		__func__, __LINE__);
	return -ENOMEM;

}
/**
 * init_queue_var - clear queue var
 *
 */
static void init_queue_var(struct HST2DR_ADAPTER *ioa)
{
	memset(&ioa->hst2dr_var, 0, sizeof(ioa->hst2dr_var));
}
/**
 * hst2dr_init_nvme_device_and_admin_queue_hal_api - init hba admin queue
 *
 * @ioa: per adapter object
 *
 * Returns 0 for success, non-zero for failure.
 */
int hst2dr_init_nvme_device_and_admin_queue_hal_api(struct HST2DR_ADAPTER *ioa)
{
	int status;

	if (ioa->reset_status == 0) {
		ioa->reset_status = 1;
		memset(&ioa->hst2dr_nvme_dma, 0,
			sizeof(struct hst2dr_hba_nvme_dma) * (NUM_OF_IO_Q + 1));
		init_queue_var(ioa);
	}
	status = hst2dr_nvme_controller_reg_init(ioa, 0);
	if (status == -EFAULT)
		status = hst2dr_nvme_controller_reg_init(ioa, 1);
	return status;
}
/**
 * hst2dr_init_nvme_io_queue_hal_api - init hba io queue
 *
 * @ioa: per adapter object
 *
 * Returns 0 for success, non-zero for failure.
 */
int hst2dr_init_nvme_io_queue_hal_api(struct HST2DR_ADAPTER *ioa)
{
	u32 dw11 = 0, io_queue_cnt = 0;
	u32 io_sq_cnt;
	u8 i, r, node = 0, vector = 0;
	int nr_msix;

	if (ioa->reply_queue_count == 1)
		io_queue_cnt = ioa->reply_queue_count;
	else
		io_queue_cnt = ioa->reply_queue_count - 1;

	// set number of io cq requested and sq requested 1(0 base)
	ioa->current_Q_num = io_queue_cnt;
	dw11 = io_queue_cnt << 16 | io_queue_cnt;
	r = nvme_set_features(NVME_FEAT_NUM_QUEUES, dw11, ioa);
	if (r != 0) {
		log_error(ioa, "set feature fail, status:%d\n", r);
		hst2dr_hal_free_resources_hal_api(ioa);
		return -EFAULT;
	}
	if ((ioa->reply_queue_count > 2) && (ioa->numa_count > 1)) {
		nr_msix = ioa->reply_queue_count - 2;
		for (i = 0; i < ioa->numa_count - 1; i++) {
			ioa->numa_node_vectors[i] =
				nr_msix / (ioa->numa_count - 1);
			if (nr_msix % (ioa->numa_count - 1) > i)
				ioa->numa_node_vectors[i] += 1;
		}
		ioa->numa_node_vectors[ioa->numa_count - 1] = 1;
		debug_dump_mem("numa node vectors", ioa->numa_node_vectors, 32);
		vector = 0;
		node = 0;
		for (i = 1; i <= ioa->reply_queue_count; i++) {
			vector++;
			ioa->vector_node[i] = node;
			if (vector >= ioa->numa_node_vectors[node]) {
				vector = 0;
				node++;
			}
		}
	} else
		ioa->numa_node_vectors[0] = 1;
	debug_dump_mem("vector node", ioa->vector_node, 128);
	for (i = 0; i < io_queue_cnt; i++) {
		r = nvme_create_cq(i + 1, ioa);
		if (r != 0) {
			log_error(ioa, "create cq fail, status:%d\n", r);
			hst2dr_hal_free_resources_hal_api(ioa);
			return -EFAULT;
		}
	}
	if (ioa->info.max_sq > 1)
		if (ioa->info.max_sq > io_queue_cnt)
			io_sq_cnt = io_queue_cnt;
		else
			io_sq_cnt = ioa->info.max_sq;
	else
		io_sq_cnt = 1;
	if (ioa->q_mode == Q_MODE_3)
		io_sq_cnt = 1;
	log_hal(ioa, "create io sq:%d\n", io_sq_cnt);
	for (i = 0; i < io_sq_cnt; i++) {
		r = nvme_create_sq(i + 1, ioa);
		if (r != 0) {
			log_error(ioa, "create sq fail, status:%d\n", r);
			hst2dr_hal_free_resources_hal_api(ioa);
			return -EFAULT;
		}
	}

	return 0;
}
/**
 * hst2dr_stop_nvme_device_and_admin_queue_hal_api - stop hba io queue
 *
 * @ioa: per adapter object
 *
 * Returns 0 for success.
 */
int hst2dr_hal_free_resources_hal_api(struct HST2DR_ADAPTER *ioa)
{
	u32 io_queue_cnt = 0;
	u8 i;
	struct nvme_queue *nvmeq;

	if (ioa->reply_queue_count == 1)
		io_queue_cnt = ioa->reply_queue_count + 1;
	else
		io_queue_cnt = ioa->reply_queue_count;

	for (i = 0; i < io_queue_cnt; i++) {
		nvmeq = &ioa->hst2dr_var.nvmeq[i];
		if (nvmeq == NULL)
			continue;
		if (nvmeq->sq_cmds != 0) {
			if ((ioa->q_mode == Q_MODE_2) ||
					(ioa->q_mode == Q_MODE_4))
				dma_free_coherent(&ioa->pdev->dev,
						i == 0 ?
						SQ_SIZE(ADMIN_QUEUE_SIZE) :
						SQ_SIZE(nvmeq->sq_depth),
						nvmeq->sq_cmds,
						nvmeq->sq_dma_addr);

			nvmeq->sq_cmds = 0;
		}
		if (nvmeq->cqes != 0) {
			dma_free_coherent(&ioa->pdev->dev,
					i == 0 ? CQ_SIZE(ADMIN_QUEUE_SIZE) :
					CQ_SIZE(nvmeq->cq_depth),
					(void *)nvmeq->cqes,
					nvmeq->cq_dma_addr);

			nvmeq->cqes = 0;
		}
	}
	return 0;
}
int hst2dr_check_queue_full(struct HST2DR_ADAPTER *ioa, int q_num)
{
	u16 sq_tail, sq_head;
	struct nvme_queue *nvmeq = &ioa->hst2dr_var.nvmeq[q_num];

	sq_tail = nvmeq->sq_tail;
	sq_head = nvmeq->sq_head;
	if ((sq_head == sq_tail + 1) || ((!sq_head) &&
				(sq_tail == nvmeq->sq_depth - 1))) {
		log_hal(ioa,
				"qfull q:%d tail:%x head:%x\n",
				q_num, sq_tail, sq_head);
		return 1;
	} else
		return 0;
}

int hst2dr_send_ioctl_cmd_hal_api(struct HST2DR_ADAPTER *ioa, void *c)
{
	struct _hst2dr_vendor_cmd *ssl_cmd = (struct _hst2dr_vendor_cmd *)c;
	//struct _hst2dr_command *scmd = (struct _hst2dr_command *)c;
	struct nvme_queue *nvmeq = NULL;
	u8 is_admin;
	u16 sq_tail;
	u16 q_num = 0;

	if (unlikely(c == NULL || (ioa->ioa_reset_in_progress & 2))) {
		log_hal(ioa, "reset in progress %d, or get NULL private data\n",
			ioa->ioa_reset_in_progress);
		return -EFAULT;
	}

	is_admin = ((ssl_cmd->opflags & 3) == FLAG_FW_MODE_ADMIN);

	if (is_admin)
		hst2dr_send_nvme_vendor_cmd_hal_api(ioa, c);
	else {
		if (likely((ioa->q_mode == Q_MODE_2) ||
					(ioa->q_mode == Q_MODE_4))) {
			q_num = ioa->current_Q_num;
			//Fixed the last queue is only for ioctl IO
			nvmeq = &ioa->hst2dr_var.nvmeq[q_num];
			ssl_cmd->sq_id = q_num |
				(ioa->vector_node[q_num] << 11);
			spin_lock(&ioa->nvmeq_lock[q_num]);
			sq_tail = nvmeq->sq_tail;
			memcpy(nvmeq->sq_cmds + (sq_tail << 1),
					&(*ssl_cmd), sizeof(*ssl_cmd));

			if (++sq_tail == nvmeq->sq_depth)
				sq_tail = 0;
			if (ioa->q_mode == Q_MODE_2)
				writel(sq_tail, SQ_TAIL(q_num));
			else
				writel((ssl_cmd->sq_id << 16) | sq_tail,
						&ioa->chip->RegsBase +
						(NVME_REG_IO_SQ >> 2));

		nvmeq->sq_tail = sq_tail;
		spin_unlock(&ioa->nvmeq_lock[q_num]);
		} else {
			ssl_cmd->sq_id = ioa->reply_queue_count;
			writel(ssl_cmd->host_tag_id,
					&ioa->chip->RegsBase +
					(NVME_REG_IO_SQ >> 2));
		}
	}
	return 0;
}
int hst2dr_send_legacy_cmd_hal_api(struct HST2DR_ADAPTER *ioa, void *c)
{
	struct _hst2dr_vendor_cmd *ssl_cmd = (struct _hst2dr_vendor_cmd *)c;
	struct _hst2dr_command *scmd = (struct _hst2dr_command *)c;
	struct nvme_queue *nvmeq = NULL;
	u16 sq_tail;
	u16 q_num = 0;

	u8 is_admin;

	if (unlikely(c == NULL || (ioa->ioa_reset_in_progress & 2))) {
		log_hal(ioa, "reset in progress %d, or get NULL private data\n",
			ioa->ioa_reset_in_progress);
		return -EFAULT;
	}

	is_admin = ((ssl_cmd->opflags & 3) == FLAG_FW_MODE_ADMIN);
	if (scmd->cmd.internal.cmd.head.opcode == SSI2_FUNCTION_SMP_PASSTHROUGH)
		scmd->cmd.internal.cmd.head.opflags = ioa->smp_flags;

	if ((ioa->q_mode == Q_MODE_2) || (ioa->q_mode == Q_MODE_4)) {
		if (is_admin) {
			q_num = 0;
			nvmeq = &ioa->hst2dr_var.nvmeq[q_num];
			if (hst2dr_check_queue_full(ioa, q_num)) {
				atomic_inc(&ioa->hst2dr_var.queue_full_cnt[0]);
				log_error(ioa,
					"Admin queue full,tail:0x%x head:0x%x sq_depth:0x%x\n",
					nvmeq->sq_tail,
					nvmeq->sq_head,
					nvmeq->sq_depth);
				return ADMIN_QUEUE_FULL;
			}
		} else {
			ioa->io_sequence_num[ssl_cmd->host_tag_id]++;
			ioa->io_sequence_num[ssl_cmd->host_tag_id] &= 3;
			ssl_cmd->host_cmd_flags.msg_flag =
				ioa->io_sequence_num[ssl_cmd->host_tag_id];
			q_num = 1;
			nvmeq = &ioa->hst2dr_var.nvmeq[q_num];
			if (hst2dr_check_queue_full(ioa, q_num)) {
				atomic_inc(&ioa->hst2dr_var.queue_full_cnt[1]);
				if (get_jiffies_64() -
						ioa->hst2dr_var.jiffies_ref >
						HZ) {
					ioa->hst2dr_var.jiffies_ref =
						get_jiffies_64();
					log_hal(ioa, "io queue full %d\n",
						atomic_read(&ioa->hst2dr_var.queue_full_cnt[1]));
				}

				return IO_QUEUES_FULL;
			}
		}

		ssl_cmd->sq_id = q_num | (ioa->vector_node[q_num] << 11);
		spin_lock(&ioa->nvmeq_lock[q_num]);
		sq_tail = nvmeq->sq_tail;
		memcpy(nvmeq->sq_cmds + (sq_tail << 1),
				&(*ssl_cmd), sizeof(*ssl_cmd));

		if (++sq_tail == nvmeq->sq_depth)
			sq_tail = 0;

		if (ioa->q_mode == Q_MODE_2)
			writel(sq_tail, SQ_TAIL(q_num));
		else
			writel((ssl_cmd->sq_id << 16) | sq_tail,
					&ioa->chip->RegsBase +
					((is_admin ? NVME_REG_ADMIN_SQ :
					  NVME_REG_IO_SQ) >> 2));

		nvmeq->sq_tail = sq_tail;
		spin_unlock(&ioa->nvmeq_lock[q_num]);

		if (is_admin) {
			debug_dump_mem("ssi:", c, 0x40);
			return 0;
		} else
			debug_dump_mem("scsiio:", c, 0x40);

		return !ioa->hst2dr_var.intr_enabled ? 1 : 0;
	} else {
		u16 reg = (is_admin ? NVME_REG_ADMIN_SQ :
				NVME_REG_IO_SQ);

		if (is_admin)
			q_num = 0;
		else
			q_num =  1;

		ssl_cmd->sq_id = q_num | (ioa->vector_node[q_num] << 11);
		writel(ssl_cmd->host_tag_id,
				&ioa->chip->RegsBase + (reg >> 2));
		if (is_admin) {
			debug_dump_mem("ssi:", c, 0x40);
			return 0;
		} else
			debug_dump_mem("scsiio:", c, 0x40);

		return 0;
	}

	return -EFAULT;
}

/**
 * hst2dr_send_nvme_vendor_cmd_hal_api - send vendor cmd to hba
 *
 * @ioa: per adapter object
 * @c:vendor cmd
 * Returns 0 for success, non-zero for failure.
 */
int hst2dr_send_nvme_vendor_cmd_hal_api(struct HST2DR_ADAPTER *ioa, void *c)
{
	struct _hst2dr_vendor_cmd *ssl_cmd = (struct _hst2dr_vendor_cmd *)c;
	struct _hst2dr_command *scmd = (struct _hst2dr_command *)c;
	struct nvme_queue *nvmeq = NULL;
	u16 sq_tail;
	u16 q_num = 0;

	u8 is_admin;
	unsigned int dispatched;
	int i = 0;

	if (unlikely(c == NULL || (ioa->ioa_reset_in_progress & 2))) {
		log_hal(ioa, "reset in progress %d, or get NULL private data\n",
			ioa->ioa_reset_in_progress);
		return -EFAULT;
	}

	is_admin = ((ssl_cmd->opflags & 3) == FLAG_FW_MODE_ADMIN);
	if (scmd->cmd.internal.cmd.head.opcode == SSI2_FUNCTION_SMP_PASSTHROUGH)
		scmd->cmd.internal.cmd.head.opflags = ioa->smp_flags;

	if (ioa->q_mode == Q_MODE_2 || ioa->q_mode == Q_MODE_4) {
		if (is_admin) {
			q_num = 0;
			nvmeq = &ioa->hst2dr_var.nvmeq[q_num];
			if (hst2dr_check_queue_full(ioa, q_num)) {
				atomic_inc(&ioa->hst2dr_var.queue_full_cnt[0]);
				return ADMIN_QUEUE_FULL;
			}
		} else {
			ioa->io_sequence_num[ssl_cmd->host_tag_id]++;
			ioa->io_sequence_num[ssl_cmd->host_tag_id] &= 3;
			ssl_cmd->host_cmd_flags.msg_flag =
				ioa->io_sequence_num[ssl_cmd->host_tag_id];

			q_num = ioa->cpu_msix_table[raw_smp_processor_id()];
			if (q_num < 1 || q_num > ioa->current_Q_num - 1)
				q_num = 1;
			if (hst2dr_check_queue_full(ioa, q_num)) {
				for (i = 0; i < ioa->current_Q_num - 1; i++) {
					dispatched = (unsigned int)
						atomic_fetch_inc(
							&ioa->fair_dispatched);
					q_num = (ioa->current_Q_num == 1) ? 1 :
						dispatched %
						(ioa->current_Q_num  - 1) + 1;
					if (!hst2dr_check_queue_full(ioa,
								q_num))
						break;
				}
				if (i >= ioa->current_Q_num - 1) {
					atomic_inc(&ioa->hst2dr_var.queue_full_cnt[1]);
					if (get_jiffies_64() -
						ioa->hst2dr_var.jiffies_ref >
						HZ) {
						ioa->hst2dr_var.jiffies_ref =
							get_jiffies_64();
						log_error(ioa,
							"All io queue full %d\n",
							atomic_read(&ioa->hst2dr_var.queue_full_cnt[1]));
					}

					return IO_QUEUES_FULL;
				}
			}
		}

		ssl_cmd->sq_id = q_num | (ioa->vector_node[q_num] << 11);
		nvmeq = &ioa->hst2dr_var.nvmeq[q_num];
		spin_lock(&ioa->nvmeq_lock[q_num]);
		sq_tail = nvmeq->sq_tail;
		memcpy(nvmeq->sq_cmds + (sq_tail << 1),
				&(*ssl_cmd), sizeof(*ssl_cmd));

		if (++sq_tail == nvmeq->sq_depth)
			sq_tail = 0;

		if (ioa->q_mode == Q_MODE_2)
			writel(sq_tail, SQ_TAIL(q_num));
		else
			writel((ssl_cmd->sq_id << 16) | sq_tail,
					&ioa->chip->RegsBase +
					((is_admin ? NVME_REG_ADMIN_SQ :
					 NVME_REG_IO_SQ) >> 2));
		nvmeq->sq_tail = sq_tail;
		spin_unlock(&ioa->nvmeq_lock[q_num]);

		if (is_admin) {
			debug_dump_mem("ssi:", c, 0x40);
			return 0;
		} else
			debug_dump_mem("scsiio:", c, 0x40);

		return !ioa->hst2dr_var.intr_enabled ? 1 : 0;
	} else {
		u16 reg = (is_admin ? NVME_REG_ADMIN_SQ  : NVME_REG_IO_SQ);

		if (is_admin) {
			q_num = 0;
		} else {
			dispatched = (unsigned int)atomic_fetch_inc(
					&ioa->fair_dispatched);
			q_num = (ioa->current_Q_num == 1) ? 1 :
				dispatched % (ioa->current_Q_num - 1) + 1;
		}

		ssl_cmd->sq_id = q_num | (ioa->vector_node[q_num] << 11);
		writel(ssl_cmd->host_tag_id, &ioa->chip->RegsBase + (reg >> 2));

		return 0;
	}

	return -EFAULT;
}
/**
 * hst2dr_read_direct_reg_hal_api - direct read hba register
 *
 * @ioa: per adapter object
 * @reg_offset:register offset
 * Returns register value
 * e.g hst2dr_read_direct_reg_hal_api(ioa, NVME_REG_NSSR);
 */
int hst2dr_read_direct_reg_hal_api(struct HST2DR_ADAPTER *ioa, u32 reg_offset)
{
	/**
	 * @brief direct read access HBA reg
	 * @reg_offset: reg offset, eg  CC:0x14h CSTS:0x1Ch
	 * @return the value of reg read from HBA
	 */
	if (likely(ioa->chip_phys))
		return readl(&ioa->chip->RegsBase + (reg_offset >> 2));
	else
		return -EPERM;
}
/**
 * hst2dr_read_direct_reg_hal_api - direct write hba register
 *
 * @ioa: per adapter object
 * @reg_offset:reg_offset
 * @value:the value set to reg_offset
 * e.g hst2dr_write_direct_reg_hal_api(ioa, NVME_REG_INTMS, 0xffffffff);
 */
void hst2dr_write_direct_reg_hal_api(struct HST2DR_ADAPTER *ioa,
	u32 reg_offset, u32 value)
{
	/**
	 * @brief direct write access HBA reg
	 * @reg_offset: reg offset, eg  CC:0x14h CSTS:0x1Ch
	 * @value:the value write to HBA reg
	 */
	if (likely(ioa->chip_phys))
		writel(value, &ioa->chip->RegsBase + (reg_offset >> 2));
}
