// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2024 - 2024, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#include <linux/kernel.h>
#include <linux/pci.h>
#include "andes_reg.h"
#include "common/xsc_reg.h"
#include "common/xsc_cmd.h"
#include "common/xsc_hsi.h"
#include "xsc_hal.h"

#define REG_ADDR(bp, offset)	((bp) + (offset))

#define HIF_CPM_IDA_DATA_MEM_STRIDE		0x40

#define CPM_IAE_CMD_READ			0
#define CPM_IAE_CMD_WRITE			1

#define CPM_IAE_ADDR_REG_STRIDE			HIF_CPM_IDA_ADDR_REG_STRIDE

#define CPM_IAE_DATA_MEM_STRIDE			HIF_CPM_IDA_DATA_MEM_STRIDE

#define CPM_IAE_DATA_MEM_MAX_LEN		16

static inline void acquire_ia32_lock(void *hal, void __iomem *bar, int *iae_idx)
{
	struct xsc_hw_abstract_layer *_hal = (struct xsc_hw_abstract_layer *)hal;
	u32 lock_val;
	u32 lock_vld;

	lock_val = readl(REG_ADDR(bar, _hal->regs->cpm_get_lock));
	lock_vld = lock_val >> HIF_CPM_LOCK_GET_REG_LOCK_VLD_SHIFT;
	if (lock_vld)
		*iae_idx = lock_val & HIF_CPM_LOCK_GET_REG_LOCK_IDX_MASK;
	else
		*iae_idx = -1;
}

static inline void release_ia32_lock(void *hal, void __iomem *bar, int lock_idx)
{
	struct xsc_hw_abstract_layer *_hal = hal;

	writel(lock_idx, REG_ADDR(bar, _hal->regs->cpm_put_lock));
}

static inline void ia32_write_data(struct xsc_hw_abstract_layer *hal, void __iomem *bar,
				   u32 *data, int nr, int idx)
{
	int i;
	int offset = hal->regs->cpm_data_mem + idx * CPM_IAE_DATA_MEM_STRIDE;

	for (i = 0; i < nr; i++) {
		writel(*(data++), REG_ADDR(bar, offset));
		offset += sizeof(*data);
	}
}

static inline void ia32_read_data(struct xsc_hw_abstract_layer *hal, void __iomem *bar,
				  u32 *data, int nr, int idx)
{
	int i;
	int offset = hal->regs->cpm_data_mem + idx * CPM_IAE_DATA_MEM_STRIDE;
	u32 *ptr = data;

	for (i = 0; i < nr; i++) {
		*ptr = readl(REG_ADDR(bar, offset));
		offset += sizeof(*data);
		ptr = ptr + 1;
	}
}

static inline void ia32_write_reg_addr(struct xsc_hw_abstract_layer *hal, void __iomem *bar,
				       u32 addr, int idx)
{
	int offset = hal->regs->cpm_addr + idx * CPM_IAE_ADDR_REG_STRIDE;
	u32 reg_addr_val = addr;

	writel(reg_addr_val, REG_ADDR(bar, offset));
}

static inline void initiate_ia32_cmd(struct xsc_hw_abstract_layer *hal, void __iomem *bar,
				     int iae_idx, int length, int r0w1)
{
	struct ia_cmd {
		union {
			struct {
				u32	iae_idx:HIF_CPM_IDA_CMD_REG_IDA_IDX_WIDTH;
				u32	iae_len:HIF_CPM_IDA_CMD_REG_IDA_LEN_WIDTH;
				u32	iae_r0w1:HIF_CPM_IDA_CMD_REG_IDA_R0W1_WIDTH;
			};
			u32 raw;
		};
	} cmd;

	int addr = hal->regs->cpm_cmd;

	cmd.iae_r0w1 = r0w1;
	cmd.iae_len = length - 1;
	cmd.iae_idx = iae_idx;
	writel(cmd.raw, REG_ADDR(bar, addr));
}

static inline void initiate_ia32_write_cmd(struct xsc_hw_abstract_layer *hal, void __iomem *bar,
					   int iae_idx, int length)
{
	initiate_ia32_cmd(hal, bar, iae_idx, length, CPM_IAE_CMD_WRITE);
}

static inline void initiate_ia32_read_cmd(struct xsc_hw_abstract_layer *hal, void __iomem *bar,
					  int iae_idx, int length)
{
	initiate_ia32_cmd(hal, bar, iae_idx, length, CPM_IAE_CMD_READ);
}

static inline void wait_for_ia32_complete(struct xsc_hw_abstract_layer *hal, void __iomem *bar,
					  int iae_idx)
{
	while ((readl(REG_ADDR(bar, hal->regs->cpm_busy)) & (1 << iae_idx)))
		;
}

static void xsc_read32(void *bar, u32 off, void *data, int len)
{
	u32 val = readl(REG_ADDR(bar, off));

	memcpy(data, &val, len);
}

static void xsc_write32(void *bar, u32 off, void *data)
{
	writel(*(u32 *)data, REG_ADDR(bar, off));
}

static void xsc_ia32_write_reg_mr(void *hal, void __iomem *bar, u32 addr,
				  void *data, int nr, int idx)
{
	struct xsc_hw_abstract_layer *_hal = (struct xsc_hw_abstract_layer *)hal;

	ia32_write_data(_hal, bar, data, nr, idx);
	ia32_write_reg_addr(_hal, bar, addr, idx);
	initiate_ia32_write_cmd(_hal, bar, idx, nr);
}

static void xsc_ia32_read(void *hal, void __iomem *bar, u32 addr, void *data, int nr)
{
	struct xsc_hw_abstract_layer *_hal = (struct xsc_hw_abstract_layer *)hal;
	int idx;

	do {
		acquire_ia32_lock(_hal, bar, &idx);
	} while (idx == -1);
	ia32_write_reg_addr(_hal, bar, addr, idx);
	initiate_ia32_read_cmd(_hal, bar, idx, nr);
	wait_for_ia32_complete(_hal, bar, idx);
	ia32_read_data(_hal, bar, data, nr, idx);
	release_ia32_lock(_hal, bar, idx);
}

static void xsc_ia32_write(void *hal, void __iomem *bar, u32 addr, void *data, int nr)
{
	struct xsc_hw_abstract_layer *_hal = (struct xsc_hw_abstract_layer *)hal;
	int idx;

	do {
		acquire_ia32_lock(_hal, bar, &idx);
	} while (idx == -1);
	ia32_write_data(_hal, bar, data, nr, idx);
	ia32_write_reg_addr(_hal, bar, addr, idx);
	initiate_ia32_write_cmd(_hal, bar, idx, nr);
	release_ia32_lock(_hal, bar, idx);
}

static void andes_ring_tx_doorbell(void *hal, void __iomem *bar, u32 sqn, u32 next_pid)
{
	struct xsc_hw_abstract_layer *_hal = (struct xsc_hw_abstract_layer *)hal;
	union xsc_send_doorbell {
		struct{
			u32  next_pid : 16;
			u32 qp_id : 15;
		};
		u32 raw;
	} db;

	db.next_pid = next_pid;
	db.qp_id = sqn;

	/* Make sure that descriptors are written before
	 * updating doorbell record and ringing the doorbell
	 */
	wmb();

	xsc_write32(bar, _hal->regs->tx_db, &db.raw);
}

static void andes_ring_rx_doorbell(void *hal, void __iomem *bar, u32 rqn, u32 next_pid)
{
	struct xsc_hw_abstract_layer *_hal = (struct xsc_hw_abstract_layer *)hal;
	union xsc_recv_doorbell {
		struct{
			u32  next_pid : 13;
			u32 qp_id : 15;
		};
		u32 raw;
	} db;

	db.next_pid = next_pid;
	db.qp_id = rqn;

	/* Make sure that descriptors are written before
	 * updating doorbell record and ringing the doorbell
	 */
	wmb();

	xsc_write32(bar, _hal->regs->rx_db, &db.raw);
}

static void andes_update_cq_db(void *hal, void __iomem *bar, u32 cqn, u32 next_cid, u8 solicited)
{
	struct xsc_hw_abstract_layer *_hal = hal;
	union andes_cq_doorbell {
		struct{
			u32     cq_next_cid:16;
			u32     cq_id:15;
			u32     arm:1;
		};
		u32     val;
	} db;

	db.cq_next_cid = next_cid;
	db.cq_id = cqn;
	db.arm = solicited;

	/* Make sure that the doorbell record in host memory is
	 * written before ringing the doorbell via PCI MMIO.
	 */
	wmb();
	xsc_write32(bar, _hal->regs->complete_db, &db.val);
}

static void andes_set_cq_ci(void *hal, void __iomem *bar, u32 cqn, u32 next_cid)
{
	struct xsc_hw_abstract_layer *_hal = hal;
	union andes_cq_doorbell {
		struct{
			u32     cq_next_cid:16;
			u32     cq_id:15;
			u32     arm:1;
		};
		u32     val;
	} db;

	db.val = 0;
	db.cq_next_cid = next_cid;
	db.cq_id = cqn;
	/* make sure val write to memory done */
	wmb();
	xsc_write32(bar, _hal->regs->complete_reg, &db.val);
}

static void andes_set_eq_ci(void *hal, void __iomem *bar, u32 eqn, u32 next_cid, u8 arm)
{
	struct xsc_hw_abstract_layer *_hal = hal;
	union andes_eq_doorbell {
		struct{
			u32 eq_next_cid : 11;
			u32 eq_id : 11;
			u32 arm : 1;
		};
		u32 val;
	} db;

	db.eq_next_cid = next_cid;
	db.eq_id = eqn;
	db.arm = !!arm;

	/* make sure val write to memory done */
	wmb();
	xsc_write32(bar, _hal->regs->event_db, &db.val);
}

static u8 andes_get_mr_page_mode(u8 page_shift)
{
enum {
	XSC_PAGE_SHIFT_4K	= 12,
	XSC_PAGE_SHIFT_64K	= 16,
	XSC_PAGE_SHIFT_2M	= 21,
	XSC_PAGE_SHIFT_1G	= 30,
};

enum {
	XSC_PAGE_MODE_4K	= 0,
	XSC_PAGE_MODE_64K	= 1,
	XSC_PAGE_MODE_2M	= 2,
	XSC_PAGE_MODE_1G	= 3,
};

	return (page_shift == XSC_PAGE_SHIFT_4K ? XSC_PAGE_MODE_4K :
		(page_shift == XSC_PAGE_SHIFT_64K ? XSC_PAGE_MODE_64K :
		(page_shift == XSC_PAGE_SHIFT_2M ? XSC_PAGE_MODE_2M : XSC_PAGE_MODE_1G)));
}

static inline u32 andes_mkey_to_idx(u32 mkey)
{
	return mkey >> 17;
}

static inline u32 andes_idx_to_mkey(u32 mkey_idx)
{
	return mkey_idx << 17;
}

static void andes_set_mpt_tbl(void *hal, void __iomem *bar, int iae_idx,
			      u32 mtt_base, void *mr_request)
{
	struct xsc_hw_abstract_layer *_hal = hal;
	struct xsc_register_mr_request *req = mr_request;
	union xsc_mpt_entry {
		struct {
			u32 va_l;
			u32 va_h;
			u32 mem_size;
			u32 pdn:24;
			u32 key:8;
			u32 mtt_base:18;
			u32 acc:4;
			u32 page_mode:2;
			u32 mem_map_en:1;
		};
		u32 raw[5];
	} mpt;
	u64 va = be64_to_cpu(req->va_base);
	u32 mkey = be32_to_cpu(req->mkey);
	u32 idx = andes_mkey_to_idx(mkey);
	u32 reg_addr = _hal->regs->mpt_tbl_addr + idx * (_hal->regs->mpt_tbl_width >> 3);

	mpt.va_l = va & 0xffffffff;
	mpt.va_h = va >> 32;
	mpt.mem_size = be64_to_cpu(req->len);
	mpt.pdn = be32_to_cpu(req->pdn);
	mpt.key = mkey & 0xff;
	mpt.mtt_base = mtt_base;
	mpt.acc = req->acc;
	mpt.page_mode = req->page_mode;
	mpt.mem_map_en = req->map_en;

	xsc_ia32_write_reg_mr(_hal, bar, reg_addr, mpt.raw, ARRAY_SIZE(mpt.raw), iae_idx);
}

static void andes_clear_mpt_tbl(void *hal, void __iomem *bar, int iae_idx,
				u32 mtt_base, void *mr_request)
{
	struct xsc_hw_abstract_layer *_hal = hal;
	struct xsc_unregister_mr_mbox_in *req = mr_request;
	union xsc_mpt_entry {
		struct {
			u32 va_l;
			u32 va_h;
			u32 mem_size;
			u32 pdn:24;
			u32 key:8;
			u32 mtt_base:18;
			u32 acc:4;
			u32 page_mode:2;
			u32 mem_map_en:1;
		};
		u32 raw[5];
	} mpt;

	u32 idx = be32_to_cpu(req->mkey);
	u32 reg_addr = _hal->regs->mpt_tbl_addr + idx * (_hal->regs->mpt_tbl_width >> 3);

	memset(&mpt, 0x00,  sizeof(mpt));

	xsc_ia32_write_reg_mr(_hal, bar, reg_addr, mpt.raw, ARRAY_SIZE(mpt.raw), iae_idx);
}

#define PAGE_SHIFT_4K	12
static void andes_set_mtt_tbl(void *hal, void __iomem *bar, int iae_idx,
			      u32 mtt_base, void *mr_request)
{
	struct xsc_hw_abstract_layer *_hal = hal;
	struct xsc_register_mr_request *req = mr_request;
	int i;
	u32 pa_num = be32_to_cpu(req->pa_num);
	u64 pa;
	u32 reg_addr;

	for (i = 0; i < pa_num; i++) {
		pa = req->pas[i];
		pa = be64_to_cpu(pa);
		pa = pa >> PAGE_SHIFT_4K;
		reg_addr = _hal->regs->mtt_inst_base_addr + (mtt_base + i) * sizeof(u64);
		xsc_ia32_write_reg_mr(_hal, bar, reg_addr,
				      (u32 *)&pa, sizeof(pa) / sizeof(u32), iae_idx);
	}
}

static void andes_set_read_done_msix_vector(void *hal, void __iomem *bar, u32 vector)
{
	struct xsc_hw_abstract_layer *_hal = hal;
	u32 val = (1 << 12) | (vector & 0xfff);

	writel(val, REG_ADDR(bar, _hal->regs->tbl2irq_rd_done_msix_reg));
}

#define XSC_DMA_WR_SUCCESS  0x3
static int andes_dma_write_tbl_once(void *hal, void __iomem *bar, u32 data_len, u64 dma_wr_addr,
				    u32 host_id, u32 func_id, u64 success[2], u32 size)
{
	struct xsc_hw_abstract_layer *_hal = hal;
	u32 busy = 0;
	u32 value = 0;
	u32 done = 0;
	u32 reg_addr;

	do {
		busy = readl(REG_ADDR(bar, _hal->regs->tbl_dl_busy_reg));
	} while (busy != 0x0);

	writel(1, REG_ADDR(bar, _hal->regs->err_code_clr_reg));

	value = ((data_len << HIF_TBL_TBL_DL_REQ_REG_TBL_DL_LEN_SHIFT) |
		(host_id << HIF_TBL_TBL_DL_REQ_REG_TBL_DL_HOST_ID_SHIFT) | func_id);

	writel(value, REG_ADDR(bar, _hal->regs->tbl_dl_req_reg));

	value = (dma_wr_addr & HIF_TBL_TBL_DL_ADDR_L_REG_TBL_DL_ADDR_L_MASK);
	writel(value, REG_ADDR(bar, _hal->regs->tbl_dl_addr_l_reg));

	value = ((dma_wr_addr >> 32) & HIF_TBL_TBL_DL_ADDR_H_REG_TBL_DL_ADDR_H_MASK);
	writel(value, REG_ADDR(bar, _hal->regs->tbl_dl_addr_h_reg));

	writel(1, REG_ADDR(bar, _hal->regs->tbl_dl_start_reg));

	do {
		done = readl(REG_ADDR(bar, _hal->regs->dma_dl_done_reg));
	} while ((done & 0x1) != 0x1);
	if (done != XSC_DMA_WR_SUCCESS) {
		reg_addr = _hal->regs->dma_dl_success_reg;
		xsc_ia32_read(_hal, bar, reg_addr, success, (size / sizeof(u32)));
		return -1;
	}

	return 0;
}

static void andes_dma_read_tbl(void *hal, void __iomem *bar,
			       u32 host_id, u32 func_id, u64 data_addr,
			       u32 tbl_id, u32 burst_num, u32 tbl_start_addr)
{
	struct xsc_hw_abstract_layer *_hal = hal;
	u32 busy;
	u32 value;

	writel(1, REG_ADDR(bar, _hal->regs->tbl_msg_rdy_reg));

	do {
		busy = readl(REG_ADDR(bar, _hal->regs->dma_ul_busy_reg));
	} while (busy != 0x0);

	value = ((host_id << HIF_TBL_TBL_UL_REQ_REG_TBL_UL_HOST_ID_SHIFT) | func_id);
	writel(value, REG_ADDR(bar, _hal->regs->tbl_ul_req_reg));

	value = data_addr & HIF_TBL_TBL_UL_ADDR_L_REG_TBL_UL_ADDR_L_MASK;
	writel(value, REG_ADDR(bar, _hal->regs->tbl_ul_addr_l_reg));

	value = (data_addr >> 32) & HIF_TBL_TBL_UL_ADDR_H_REG_TBL_UL_ADDR_H_MASK;
	writel(value, REG_ADDR(bar, _hal->regs->tbl_ul_addr_h_reg));

	writel(1, REG_ADDR(bar, _hal->regs->tbl_ul_start_reg));

	value = tbl_id & CLSF_DMA_DMA_RD_TABLE_ID_REG_DMA_RD_TBL_ID_MASK;
	writel(value, REG_ADDR(bar, _hal->regs->dma_rd_table_id_reg));

	value = (burst_num << CLSF_DMA_DMA_RD_ADDR_REG_DMA_RD_BURST_NUM_SHIFT) | tbl_start_addr;
	writel(value, REG_ADDR(bar, _hal->regs->dma_rd_addr_reg));

	writel(1, REG_ADDR(bar, _hal->regs->indrw_rd_start_reg));
}

static const u32 xsc_msg_opcode[][2][2] = {
	[XSC_MSG_OPCODE_SEND][XSC_REQ][XSC_WITHOUT_IMMDT] = XSC_OPCODE_RDMA_REQ_SEND,
	[XSC_MSG_OPCODE_SEND][XSC_REQ][XSC_WITH_IMMDT] = XSC_OPCODE_RDMA_REQ_SEND_IMMDT,
	[XSC_MSG_OPCODE_SEND][XSC_RSP][XSC_WITHOUT_IMMDT] = XSC_OPCODE_RDMA_RSP_RECV,
	[XSC_MSG_OPCODE_SEND][XSC_RSP][XSC_WITH_IMMDT] = XSC_OPCODE_RDMA_RSP_RECV_IMMDT,
	[XSC_MSG_OPCODE_RDMA_WRITE][XSC_REQ][XSC_WITHOUT_IMMDT] = XSC_OPCODE_RDMA_REQ_WRITE,
	[XSC_MSG_OPCODE_RDMA_WRITE][XSC_REQ][XSC_WITH_IMMDT] = XSC_OPCODE_RDMA_REQ_WRITE_IMMDT,
	[XSC_MSG_OPCODE_RDMA_WRITE][XSC_RSP][XSC_WITHOUT_IMMDT] = XSC_OPCODE_RDMA_CQE_ERROR,
	[XSC_MSG_OPCODE_RDMA_WRITE][XSC_RSP][XSC_WITH_IMMDT] = XSC_OPCODE_RDMA_RSP_WRITE_IMMDT,
	[XSC_MSG_OPCODE_RDMA_READ][XSC_REQ][XSC_WITHOUT_IMMDT] = XSC_OPCODE_RDMA_REQ_READ,
	[XSC_MSG_OPCODE_RDMA_READ][XSC_REQ][XSC_WITH_IMMDT] = XSC_OPCODE_RDMA_CQE_ERROR,
	[XSC_MSG_OPCODE_RDMA_READ][XSC_RSP][XSC_WITHOUT_IMMDT] = XSC_OPCODE_RDMA_CQE_ERROR,
	[XSC_MSG_OPCODE_RDMA_READ][XSC_RSP][XSC_WITH_IMMDT] = XSC_OPCODE_RDMA_CQE_ERROR,
	[XSC_MSG_OPCODE_MAD][XSC_REQ][XSC_WITHOUT_IMMDT] = XSC_OPCODE_RDMA_MAD_REQ_SEND,
	[XSC_MSG_OPCODE_MAD][XSC_RSP][XSC_WITHOUT_IMMDT] = XSC_OPCODE_RDMA_MAD_RSP_RECV,
};

struct andes_cqe {
	union {
		u8		msg_opcode;
		struct {
			u8		error_code:7;
			u8		is_error:1;
		};
	};
	__le32		qp_id:15;
	u8		rsv1:1;
	u8		se:1;
	u8		has_pph:1;
	u8		type:1;
	u8		with_immdt:1;
	u8		csum_err:4;
	__le32		imm_data;
	__le32		msg_len;
	__le32		vni;
	__le64		ts:48;
	__le16		wqe_id;
	__le16		rsv[3];
	__le16		rsv2:15;
	u8		owner:1;
};

static bool andes_is_err_cqe(void *cqe)
{
	struct andes_cqe *_cqe = cqe;

	return _cqe->is_error;
}

static u8 andes_get_cqe_error_code(void *cqe)
{
	struct andes_cqe *_cqe = cqe;

	return _cqe->error_code;
}

static u8 andes_get_cqe_opcode(void *cqe)
{
	struct andes_cqe *_cqe = cqe;
	u8 msg_opcode = _cqe->msg_opcode;

	if (_cqe->is_error)
		return _cqe->type ? XSC_OPCODE_RDMA_RSP_ERROR : XSC_OPCODE_RDMA_REQ_ERROR;
	if (msg_opcode > XSC_MSG_OPCODE_MAD)
		return XSC_OPCODE_RDMA_CQE_ERROR;
	return xsc_msg_opcode[msg_opcode][_cqe->type][_cqe->with_immdt];
}

static u32 andes_get_max_mtt_num(void *hal)
{
	struct xsc_hw_abstract_layer *_hal = hal;

	return _hal->regs->mtt_inst_depth;
}

static u32 andes_get_max_mpt_num(void *hal)
{
	struct xsc_hw_abstract_layer *_hal = hal;

	return _hal->regs->mpt_tbl_depth;
}

struct andes_data_seg {
	u32	in_line:1;
	u32	length:31;
	u32	key;
	u64	addr;
};

static void andes_set_data_seg(void *data_seg, u32 length, u32 key, u64 addr)
{
	struct andes_data_seg *seg = data_seg;

	seg->length = length;
	seg->key = key;
	seg->addr = addr;
}

static bool andes_skb_need_linearize(int ds_num)
{
	return false;
}

static struct xsc_hw_ops andes_arch_ops = {
	.read = xsc_read32,
	.write = xsc_write32,
	.ia_read = xsc_ia32_read,
	.ia_write = xsc_ia32_write,
	.ring_tx_doorbell = andes_ring_tx_doorbell,
	.ring_rx_doorbell = andes_ring_rx_doorbell,
	.update_cq_db = andes_update_cq_db,
	.set_cq_ci = andes_set_cq_ci,
	.set_eq_ci = andes_set_eq_ci,
	.get_mr_page_mode = andes_get_mr_page_mode,
	.mkey_to_idx = andes_mkey_to_idx,
	.idx_to_mkey = andes_idx_to_mkey,
	.set_mpt = andes_set_mpt_tbl,
	.clear_mpt = andes_clear_mpt_tbl,
	.set_mtt = andes_set_mtt_tbl,
	.set_read_done_msix_vector = andes_set_read_done_msix_vector,
	.dma_write_tbl_once = andes_dma_write_tbl_once,
	.dma_read_tbl = andes_dma_read_tbl,
	.is_err_cqe = andes_is_err_cqe,
	.get_cqe_error_code = andes_get_cqe_error_code,
	.get_cqe_opcode = andes_get_cqe_opcode,
	.get_max_mtt_num = andes_get_max_mtt_num,
	.get_max_mpt_num = andes_get_max_mpt_num,
	.set_data_seg = andes_set_data_seg,
	.skb_need_linearize = andes_skb_need_linearize,
};

static struct xsc_hw_reg andes_pf_regs = {
	.cpm_get_lock = HIF_CPM_LOCK_GET_REG_ADDR - 0xa0000000,
	.cpm_put_lock = HIF_CPM_LOCK_PUT_REG_ADDR - 0xa0000000,
	.cpm_lock_avail = HIF_CPM_LOCK_AVAIL_REG_ADDR - 0xa0000000,
	.cpm_data_mem = HIF_CPM_IDA_DATA_MEM_ADDR - 0xa0000000,
	.cpm_cmd = HIF_CPM_IDA_CMD_REG_ADDR - 0xa0000000,
	.cpm_addr = HIF_CPM_IDA_ADDR_REG_ADDR - 0xa0000000,
	.cpm_busy = HIF_CPM_IDA_BUSY_REG_ADDR - 0xa0000000,
	.req_pid_addr = HIF_CMDQM_HOST_REQ_PID_MEM_ADDR - 0xa0000000,
	.req_cid_addr = HIF_CMDQM_HOST_REQ_CID_MEM_ADDR - 0xa0000000,
	.rsp_pid_addr = HIF_CMDQM_HOST_RSP_PID_MEM_ADDR - 0xa0000000,
	.rsp_cid_addr = HIF_CMDQM_HOST_RSP_CID_MEM_ADDR - 0xa0000000,
	.req_buf_h_addr = HIF_CMDQM_HOST_REQ_BUF_BASE_H_ADDR_MEM_ADDR - 0xa0000000,
	.req_buf_l_addr = HIF_CMDQM_HOST_REQ_BUF_BASE_L_ADDR_MEM_ADDR - 0xa0000000,
	.rsp_buf_h_addr = HIF_CMDQM_HOST_RSP_BUF_BASE_H_ADDR_MEM_ADDR - 0xa0000000,
	.rsp_buf_l_addr = HIF_CMDQM_HOST_RSP_BUF_BASE_L_ADDR_MEM_ADDR - 0xa0000000,
	.msix_vec_addr = HIF_CMDQM_VECTOR_ID_MEM_ADDR - 0xa0000000,
	.element_sz_addr = HIF_CMDQM_Q_ELEMENT_SZ_REG_ADDR - 0xa0000000,
	.q_depth_addr = HIF_CMDQM_HOST_Q_DEPTH_REG_ADDR - 0xa0000000,
	.interrupt_stat_addr = HIF_CMDQM_HOST_VF_ERR_STS_MEM_ADDR - 0xa0000000,
	.tbl2irq_rd_done_msix_reg = HIF_IRQ_TBL2IRQ_TBL_RD_DONE_INT_MSIX_REG_ADDR - 0xa0000000,
	.dma_ul_busy_reg = CLSF_DMA_DMA_UL_BUSY_REG_ADDR - 0xa0000000,
	.dma_dl_done_reg = CLSF_DMA_DMA_DL_DONE_REG_ADDR - 0xa0000000,
	.dma_dl_success_reg = CLSF_DMA_DMA_DL_SUCCESS_REG_ADDR - 0xa0000000,
	.err_code_clr_reg = CLSF_DMA_ERR_CODE_CLR_REG_ADDR - 0xa0000000,
	.dma_rd_table_id_reg = CLSF_DMA_DMA_RD_TABLE_ID_REG_ADDR - 0xa0000000,
	.dma_rd_addr_reg = CLSF_DMA_DMA_RD_ADDR_REG_ADDR - 0xa0000000,
	.indrw_rd_start_reg = CLSF_DMA_INDRW_RD_START_REG_ADDR - 0xa0000000,
	.tbl_dl_busy_reg = HIF_TBL_TBL_DL_BUSY_REG_ADDR - 0xa0000000,
	.tbl_dl_req_reg = HIF_TBL_TBL_DL_REQ_REG_ADDR - 0xa0000000,
	.tbl_dl_addr_l_reg = HIF_TBL_TBL_DL_ADDR_L_REG_ADDR - 0xa0000000,
	.tbl_dl_addr_h_reg = HIF_TBL_TBL_DL_ADDR_H_REG_ADDR - 0xa0000000,
	.tbl_dl_start_reg = HIF_TBL_TBL_DL_START_REG_ADDR - 0xa0000000,
	.tbl_ul_req_reg = HIF_TBL_TBL_UL_REQ_REG_ADDR - 0xa0000000,
	.tbl_ul_addr_l_reg = HIF_TBL_TBL_UL_ADDR_L_REG_ADDR - 0xa0000000,
	.tbl_ul_addr_h_reg = HIF_TBL_TBL_UL_ADDR_H_REG_ADDR - 0xa0000000,
	.tbl_ul_start_reg = HIF_TBL_TBL_UL_START_REG_ADDR - 0xa0000000,
	.tbl_msg_rdy_reg = HIF_TBL_MSG_RDY_REG_ADDR - 0xa0000000,
	.mpt_tbl_addr = MMC_MPT_TBL_MEM_ADDR - 0xa0000000,
	.mpt_tbl_depth = MMC_MPT_TBL_MEM_DEPTH,
	.mpt_tbl_width = MMC_MPT_TBL_MEM_WIDTH,
	.mtt_inst_base_addr = MMC_MTT_TBL_MEM_ADDR - 0xa0000000,
	.mtt_inst_stride = 0,
	.mtt_inst_num_log = 0,
	.mtt_inst_depth = MMC_MTT_TBL_MEM_DEPTH,
};

static struct xsc_hw_reg andes_bar_compressed_pf_regs = {
	.tx_db = TX_DB_FUNC_MEM_ADDR,
	.rx_db = RX_DB_FUNC_MEM_ADDR,
	.complete_db = DB_CQ_FUNC_MEM_ADDR,
	.complete_reg = DB_CQ_CID_DIRECT_MEM_ADDR,
	.event_db = DB_EQ_FUNC_MEM_ADDR,
	.cpm_get_lock = CPM_LOCK_GET_REG_ADDR,
	.cpm_put_lock = CPM_LOCK_PUT_REG_ADDR,
	.cpm_lock_avail = CPM_LOCK_AVAIL_REG_ADDR,
	.cpm_data_mem = CPM_IDA_DATA_MEM_ADDR_NEW,
	.cpm_cmd = CPM_IDA_CMD_REG_ADDR,
	.cpm_addr = CPM_IDA_ADDR_REG_ADDR_NEW,
	.cpm_busy = CPM_IDA_BUSY_REG_ADDR,
	.req_pid_addr = CMDQM_HOST_REQ_PID_MEM_ADDR,
	.req_cid_addr = CMDQM_HOST_REQ_CID_MEM_ADDR,
	.rsp_pid_addr = CMDQM_HOST_RSP_PID_MEM_ADDR,
	.rsp_cid_addr = CMDQM_HOST_RSP_CID_MEM_ADDR,
	.req_buf_h_addr = CMDQM_HOST_REQ_BUF_BASE_H_ADDR_MEM_ADDR,
	.req_buf_l_addr = CMDQM_HOST_REQ_BUF_BASE_L_ADDR_MEM_ADDR,
	.rsp_buf_h_addr = CMDQM_HOST_RSP_BUF_BASE_H_ADDR_MEM_ADDR,
	.rsp_buf_l_addr = CMDQM_HOST_RSP_BUF_BASE_L_ADDR_MEM_ADDR,
	.msix_vec_addr = CMDQM_VECTOR_ID_MEM_ADDR,
	.element_sz_addr = CMDQM_Q_ELEMENT_SZ_REG_ADDR,
	.q_depth_addr = CMDQM_HOST_Q_DEPTH_REG_ADDR,
	.interrupt_stat_addr = CMDQM_HOST_VF_ERR_STS_MEM_ADDR,
	.tbl2irq_rd_done_msix_reg = TBL2IRQ_TBL_RD_DONE_INT_MSIX_REG_ADDR,
	.dma_ul_busy_reg = DMA_UL_BUSY_REG_ADDR,
	.dma_dl_done_reg = DMA_DL_DONE_REG_ADDR,
	.dma_dl_success_reg = DMA_DL_SUCCESS_REG_ADDR,
	.err_code_clr_reg = ERR_CODE_CLR_REG_ADDR,
	.dma_rd_table_id_reg = DMA_RD_TABLE_ID_REG_ADDR,
	.dma_rd_addr_reg = DMA_RD_ADDR_REG_ADDR,
	.indrw_rd_start_reg = INDRW_RD_START_REG_ADDR,
	.tbl_dl_busy_reg = TBL_DL_BUSY_REG_ADDR,
	.tbl_dl_req_reg = TBL_DL_REQ_REG_ADDR,
	.tbl_dl_addr_l_reg = TBL_DL_ADDR_L_REG_ADDR,
	.tbl_dl_addr_h_reg = TBL_DL_ADDR_H_REG_ADDR,
	.tbl_dl_start_reg = TBL_DL_START_REG_ADDR,
	.tbl_ul_req_reg = TBL_UL_REQ_REG_ADDR,
	.tbl_ul_addr_l_reg = TBL_UL_ADDR_L_REG_ADDR,
	.tbl_ul_addr_h_reg = TBL_UL_ADDR_H_REG_ADDR,
	.tbl_ul_start_reg = TBL_UL_START_REG_ADDR,
	.tbl_msg_rdy_reg = TBL_MSG_RDY_REG_ADDR,
	.mpt_tbl_addr = MMC_MPT_TBL_MEM_ADDR - 0xa0000000,
	.mpt_tbl_depth = MMC_MPT_TBL_MEM_DEPTH,
	.mpt_tbl_width = MMC_MPT_TBL_MEM_WIDTH,
	.mtt_inst_base_addr = MMC_MTT_TBL_MEM_ADDR - 0xa0000000,
	.mtt_inst_stride = 0,
	.mtt_inst_num_log = 0,
	.mtt_inst_depth = MMC_MTT_TBL_MEM_DEPTH,
};

static struct xsc_hw_reg andes_vf_regs = {
	.tx_db = TX_DB_FUNC_MEM_ADDR,
	.rx_db = RX_DB_FUNC_MEM_ADDR,
	.complete_db = DB_CQ_FUNC_MEM_ADDR,
	.complete_reg = DB_CQ_CID_DIRECT_MEM_ADDR,
	.event_db = DB_EQ_FUNC_MEM_ADDR,
	.cpm_get_lock = CPM_LOCK_GET_REG_ADDR,
	.cpm_put_lock = CPM_LOCK_PUT_REG_ADDR,
	.cpm_lock_avail = CPM_LOCK_AVAIL_REG_ADDR,
	.cpm_data_mem = CPM_IDA_DATA_MEM_ADDR,
	.cpm_cmd = CPM_IDA_CMD_REG_ADDR,
	.cpm_addr = CPM_IDA_ADDR_REG_ADDR,
	.cpm_busy = CPM_IDA_BUSY_REG_ADDR,
	.req_pid_addr = CMDQM_HOST_REQ_PID_MEM_ADDR,
	.req_cid_addr = CMDQM_HOST_REQ_CID_MEM_ADDR,
	.rsp_pid_addr = CMDQM_HOST_RSP_PID_MEM_ADDR,
	.rsp_cid_addr = CMDQM_HOST_RSP_CID_MEM_ADDR,
	.req_buf_h_addr = CMDQM_HOST_REQ_BUF_BASE_H_ADDR_MEM_ADDR,
	.req_buf_l_addr = CMDQM_HOST_REQ_BUF_BASE_L_ADDR_MEM_ADDR,
	.rsp_buf_h_addr = CMDQM_HOST_RSP_BUF_BASE_H_ADDR_MEM_ADDR,
	.rsp_buf_l_addr = CMDQM_HOST_RSP_BUF_BASE_L_ADDR_MEM_ADDR,
	.msix_vec_addr = CMDQM_VECTOR_ID_MEM_ADDR,
	.element_sz_addr = CMDQM_Q_ELEMENT_SZ_REG_ADDR,
	.q_depth_addr = CMDQM_HOST_Q_DEPTH_REG_ADDR,
	.interrupt_stat_addr = CMDQM_HOST_VF_ERR_STS_MEM_ADDR,
	.mpt_tbl_addr = MMC_MPT_TBL_MEM_ADDR - 0xa0000000,
	.mpt_tbl_depth = MMC_MPT_TBL_MEM_DEPTH,
	.mpt_tbl_width = MMC_MPT_TBL_MEM_WIDTH,
	.mtt_inst_base_addr = MMC_MTT_TBL_MEM_ADDR - 0xa0000000,
	.mtt_inst_stride = 0,
	.mtt_inst_num_log = 0,
	.mtt_inst_depth = MMC_MTT_TBL_MEM_DEPTH,
};

struct xsc_hw_abstract_layer andes_pf_hal = {
	.ops = &andes_arch_ops,
	.regs = &andes_pf_regs,
};

struct xsc_hw_abstract_layer compressed_pf_hal = {
	.ops = &andes_arch_ops,
	.regs = &andes_bar_compressed_pf_regs,
};

struct xsc_hw_abstract_layer andes_vf_hal = {
	.ops = &andes_arch_ops,
	.regs = &andes_vf_regs,
};

struct xsc_hw_abstract_layer *get_andes_pf_hal(void)
{
	return &andes_pf_hal;
}

struct xsc_hw_abstract_layer *get_andes_bar_compressed_pf_hal(void)
{
	return &compressed_pf_hal;
}

struct xsc_hw_abstract_layer *get_andes_vf_hal(void)
{
	return &andes_vf_hal;
}

