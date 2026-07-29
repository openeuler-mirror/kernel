/* SPDX-License-Identifier: GPL-2.0 */
/*
 * hst2dr  device driver for Linux.
 *
 * This code is based on drivers/scsi/hst2dr/hst2dr_hal.h

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


#include <linux/pci.h>
#include <linux/poll.h>
#include <linux/nvme.h>

#ifndef HST2DR_HAL_H_INCLUDED
#define HST2DR_HAL_H_INCLUDED
#undef Ex
#ifdef HST2DR_HAL_C
#define Ex
#else
#define Ex extern
#endif

#include <linux/io.h>
/**
 * lo_hi_readq - read addr qword register data
 * @addr: address to read
 * Returns read value
 */
static inline __u64 lo_hi_readq(const void __iomem *addr)
{
	const u32 __iomem *p = addr;
	u32 low, high;

	low = readl(p);
	high = readl(p + 1);

	return low + ((u64)high << 32);
}
/**
 * lo_hi_writeq - write val to addr
 * @val: val to write
 * @addr: address to write
 * no Returns
 */
static inline void lo_hi_writeq(__u64 val, void __iomem *addr)
{
	writel(val, addr);
	writel(val >> 32, addr + 4);
}

#define SQ_SIZE(depth)		((depth) * sizeof(hst2dr_vendor_cmd))
#define CQ_SIZE(depth)		((depth) * sizeof(struct nvme_completion))
#define ADMIN_QUEUE_SIZE	(INTERNAL_QUEUE_DEPTH - INTERNAL_SCSIIO_CMDS_COUNT)
#define IO_QUEUE_SIZE		4096
#define MAX_HW_QUEUE_SIZE	(IO_QUEUE_SIZE + INTERNAL_QUEUE_DEPTH)
#define NUM_OF_IO_Q		257 // Max io queue
#define HAL_MSG_INDEX		HOST_TAG_ID_POLL
#define FLAG_FW_MODE_NORMAL	2
#define FLAG_FW_MODE_ADMIN	1
#define FALG_HW_MODE		0
#define SQ_TAIL(n) (&ioa->chip->RegsBase + ((NVME_REG_DBS + 8 * n) >> 2))
#define CQ_HEADER(n) (&ioa->chip->RegsBase + ((NVME_REG_DBS + (2 * n + 1) * 4) >> 2))

#define HW_RESET_INTERVAL	1000

#define HAL_HW_DEBUG() (&ioa->chip->RegsBase + (8))

#define WAIT_SYNC_CMD_TIME	1000 // 10s interval 10ms

#define ADMIN_QUEUE_FULL	0xffff
#define IO_QUEUES_FULL		0xfffe
#define HOST_TAG_ID_POLL	(ioa->host_tag_id_poll)
#define HOST_TAG_ID_EVENT	0xffff
#define NO_HOST_TAG_ID		0xfffe
#define INVALID_REPLY		0xffff

enum HST2DR_RESET_PROGRESS {
	RESET_QUERY		= 0x68617264,
	RESET_ACK		= 0x6961636b,
	RESET_NCK		= 0x696e636b,
	RESET_READY		= 0x69726479,
};
enum {
	BIT0	= 0x00000001,
	BIT1	= 0x00000002,
	BIT2	= 0x00000004,
	BIT3	= 0x00000008,
	BIT4	= 0x00000010,
	BIT16	= 0x00010000,
	BIT17	= 0x00020000,
};
/*
 * An NVM Express queue.  Each device has at least two (one for admin
 * commands and one for I/O commands).
 * @sq_cmds: sq cmds point to vendor cmds from ssl
 * @cqes: cq entry point to vendor completion from hba
 * @sq_dma_addr: sq dma address
 * @cq_dma_addr: cq dma address
 * @q_depth:queue depth
 * @cq_vector:compelet queue vector
 * @sq_tail: tail of submission queue
 * @cq_head: head of compelte queue
 * @qid: id of queue
 * @cq_phase: phase of compelte queue
 */
struct nvme_queue {
	struct device *q_dmadev;
	struct nvme_dev *dev;
	spinlock_t q_lock;
	struct nvme_command *sq_cmds;
	struct nvme_command __iomem *sq_cmds_io;
	hst2dr_nvme_completion *cqes;
	struct blk_mq_tags **tags;
	dma_addr_t sq_dma_addr;
	dma_addr_t cq_dma_addr;
	u32 __iomem *q_db;
	u16 sq_depth;
	u16 cq_depth;
	s16 cq_vector;
	u16 sq_tail;
	u16 cq_head;
	u16 qid;
	u8 cq_phase;
	u8 cqe_seen;
	u16 sq_head;
	u32 *dbbuf_sq_db;
	u32 *dbbuf_cq_db;
	u32 *dbbuf_sq_ei;
	u32 *dbbuf_cq_ei;
};

/*
 * hst2dr hba var related to queue contorl
 * @nvmeq:nvme queue
 * @io_tail:next io to puts ssl cmd,used for round robin arbitration
 * @intr_enabled:interrupt enabled
 * @queue_full_cnt: record queue full counter
 * @jiffies_ref: jiffies the previous print warning
 * @admin_queue_size:Maximum Queue Entries hba Supported
 */

struct hst2dr_hba_var {
	struct nvme_queue nvmeq[NUM_OF_IO_Q + 1];
	u16 io_tail;//used for round robin arbitration
	u8 intr_enabled;
	u8 reserved;
	atomic_t queue_full_cnt[NUM_OF_IO_Q + 1];
	U64 jiffies_ref;
	u16 admin_queue_size;
	u16 cq_size;
};

/*
 * hst2dr_hba_nvme_dma
 * @sq_cmds:submission queue cmds
 * @cqes:complete queue entries
 * @sq_dma_addr:sq dma address
 * @cq_dma_addr:cq dma address
 */
struct hst2dr_hba_nvme_dma {
	struct nvme_command *sq_cmds;
	hst2dr_nvme_completion *cqes;
	dma_addr_t sq_dma_addr;
	dma_addr_t cq_dma_addr;
};

/*
 * hst2dr_sgl_entry_simple64
 * @Address:address of data or sgl segment
 * @Length:length of data or sgl chain length
 * @Flags:0-sgl data block
 *		  40-sgl last segment
 *		  80-sgl segment
 */

typedef struct _hst2dr_sgl_entry_simple64 {
	u64 Address;
	u32 Length;
	u16 Reserved1;
	u8 Reserved2;
	u8 Flags;
} hst2dr_sgl_entry_simple64;
/*
 * hst2dr_sgl_entry_simple64
 * @Address:address of data or sgl segment
 * @Length:length of data or sgl chain length
 * @Flags:0-sgl data block
 *		40-sgl last segment
 *		80-sgl segment
 */
typedef struct _hst2dr_sgl_entry_chain {
	u64 Address;
	u32 Length;
	u16 Reserved1;
	u8 Reserved2;
	u8 Flags;
} hst2dr_sgl_entry_chain;
typedef union _hst2dr_sgl_union {
	hst2dr_sgl_entry_simple64 IeeeSimple;
	hst2dr_sgl_entry_chain IeeeChain;
} hst2dr_sgl_union;
/*
 * hst2dr_vendor_cmd
 * @opcode:operation code
 * @opflag:0-hw mode 1-fw mode admin >1-fw mode normal
 * @host_tag_id: cmd index or tag
 * @sq_id:submission queue id
 * @cid: completion queue id
 * @host_cmd_flags: host command flags
 * @logical_dev_id: logical device id
 * @data_len: data length
 * @lun: LUN
 * @control_flag: control flag
 * @resv0: reserved
 * @control_addition: control additional
 * @cdb: CDB
 * @resv1: reserved
 * @sgl: SG list
 */
#pragma pack(1)
typedef struct _hst2dr_vendor_cmd {
	u8 opcode;/*dw0*/
	u8 opflags;
	u16 host_tag_id;
	u16 sq_id;/*dw1*/
	u16 cid;
	struct {
		unsigned sgl_flag: 2;
		unsigned msg_flag: 2;
		unsigned io_throttle:1;
		unsigned write_same_too_large:1;
		unsigned prod_specific:1;
		unsigned dma_operation_host_pi:1;
		unsigned dma_dir_flag:2;
		unsigned cdb_flag:2;
		unsigned io_flag:2;
		unsigned cmd_host_flag:1;
		unsigned cmd_flag:1;
	} host_cmd_flags; /*dw2*/
	u16 logical_dev_id;
	u32 data_len;/*dw3*/
	u8 lun[8];/*dw4-5*/
	u8 cdb_len;/*dw6*/
	u8 control_flag;
	u8 resv0;
	u8 control_addition;
	SSI2_SCSI_CDB_UNION cdb;/*dw7-14*/
	u16 eedp_flags;
	u16 block_size;
	hst2dr_sgl_union sgl[4];/*dw16-31*/

} hst2dr_vendor_cmd;

#pragma pack()

Ex int hst2dr_init_nvme_device_and_admin_queue_hal_api(struct HST2DR_ADAPTER *ioa);
Ex int hst2dr_init_nvme_io_queue_hal_api(struct HST2DR_ADAPTER *ioa);
Ex int hst2dr_hal_free_resources_hal_api(struct HST2DR_ADAPTER *ioa);
Ex int hst2dr_send_nvme_vendor_cmd_hal_api(struct HST2DR_ADAPTER *ioa, void *c);
Ex int hst2dr_read_direct_reg_hal_api(struct HST2DR_ADAPTER *ioa, u32 reg_offset);
Ex void hst2dr_write_direct_reg_hal_api(struct HST2DR_ADAPTER *ioa,
	u32 reg_offset, u32 value);
Ex int hst2dr_send_ioctl_cmd_hal_api(struct HST2DR_ADAPTER *ioa, void *c);
Ex int hst2dr_send_legacy_cmd_hal_api(struct HST2DR_ADAPTER *ioa, void *c);
Ex int hst2dr_check_queue_full(struct HST2DR_ADAPTER *ioa, int q_num);

#endif
