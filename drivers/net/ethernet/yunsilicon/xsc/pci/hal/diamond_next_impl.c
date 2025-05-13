// SPDX-License-Identifier: GPL-2.0
//
/* Copyright (C) 2024 - 2024, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#include <linux/kernel.h>
#include <linux/pci.h>
#include "diamond_reg.h"
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

static inline void acquire_ia64_lock(void *hal, void __iomem *bar, int *iae_idx)
{
	struct xsc_hw_abstract_layer *_hal = (struct xsc_hw_abstract_layer *)hal;
	u64 lock_val;
	u64 lock_vld;

	lock_val = readq(REG_ADDR(bar, _hal->regs->cpm_get_lock));
	lock_vld = lock_val >> HIF_CPM_LOCK_GET_REG_LOCK_VLD_SHIFT;
	if (lock_vld)
		*iae_idx = lock_val & HIF_CPM_LOCK_GET_REG_LOCK_IDX_MASK;
	else
		*iae_idx = -1;
}

static inline void release_ia64_lock(void *hal, void __iomem *bar, int lock_idx)
{
	struct xsc_hw_abstract_layer *_hal = (struct xsc_hw_abstract_layer *)hal;

	writeq(lock_idx, REG_ADDR(bar, _hal->regs->cpm_put_lock));
}

static inline void ia64_write_data(struct xsc_hw_abstract_layer *hal, void __iomem *bar,
				   u64 *data, int nr, int idx)
{
	int i;
	int offset = hal->regs->cpm_data_mem + idx * CPM_IAE_DATA_MEM_STRIDE;

	for (i = 0; i < nr; i++) {
		writeq(*(data++), REG_ADDR(bar, offset));
		offset += sizeof(*data);
	}
}

static inline void ia64_read_data(struct xsc_hw_abstract_layer *hal, void __iomem *bar,
				  u64 *data, int nr, int idx)
{
	int i;
	int offset = hal->regs->cpm_data_mem + idx * CPM_IAE_DATA_MEM_STRIDE;
	u64 *ptr = data;

	for (i = 0; i < nr; i++) {
		*ptr = readq(REG_ADDR(bar, offset));
		offset += sizeof(*data);
		ptr = ptr + 1;
	}
}

static inline void ia64_write_reg_addr(struct xsc_hw_abstract_layer *hal, void __iomem *bar,
				       u32 addr, int idx)
{
	int offset = hal->regs->cpm_addr + idx * CPM_IAE_ADDR_REG_STRIDE;
	u64 reg_addr_val = addr;

	writeq(reg_addr_val, REG_ADDR(bar, offset));
}

static inline void initiate_ia64_cmd(struct xsc_hw_abstract_layer *hal, void __iomem *bar,
				     int iae_idx, int length, int r0w1)
{
	struct ia_cmd {
		union {
			struct {
				u64	iae_idx:HIF_CPM_IDA_CMD_REG_IDA_IDX_WIDTH;
				u64	iae_len:HIF_CPM_IDA_CMD_REG_IDA_LEN_WIDTH;
				u64	iae_r0w1:HIF_CPM_IDA_CMD_REG_IDA_R0W1_WIDTH;
			};
			u64 raw_data;
		};
	} cmd;

	int addr = hal->regs->cpm_cmd;

	cmd.iae_r0w1 = r0w1;
	cmd.iae_len = length - 1;
	cmd.iae_idx = iae_idx;
	writeq(cmd.raw_data, REG_ADDR(bar, addr));
}

static inline void initiate_ia64_write_cmd(struct xsc_hw_abstract_layer *hal, void __iomem *bar,
					   int iae_idx, int length)
{
	initiate_ia64_cmd(hal, bar, iae_idx, length, CPM_IAE_CMD_WRITE);
}

static inline void initiate_ia64_read_cmd(struct xsc_hw_abstract_layer *hal, void __iomem *bar,
					  int iae_idx, int length)
{
	initiate_ia64_cmd(hal, bar, iae_idx, length, CPM_IAE_CMD_READ);
}

static inline void wait_for_ia64_complete(struct xsc_hw_abstract_layer *hal, void __iomem *bar,
					  int iae_idx)
{
	while ((readq(REG_ADDR(bar, hal->regs->cpm_busy)) & (1 << iae_idx)))
		;
}

static void xsc_read64(void *bar, u32 off, void *data, int len)
{
	u64 val = readq(REG_ADDR(bar, off));

	memcpy(data, &val, len);
}

static void xsc_write64(void *bar, u32 off, void *data)
{
	writeq(*(u64 *)data, REG_ADDR(bar, off));
}

static void xsc_ia64_write_reg_mr(void *hal, void __iomem *bar,
				  u32 addr, void *data, int nr, int idx)
{
	struct xsc_hw_abstract_layer *_hal = hal;

	ia64_write_data(_hal, bar, data, nr, idx);
	ia64_write_reg_addr(_hal, bar, addr, idx);
	initiate_ia64_write_cmd(_hal, bar, idx, nr);
}

static void xsc_ia64_read(void *hal, void __iomem *bar, u32 addr, void *data, int nr)
{
	struct xsc_hw_abstract_layer *_hal = hal;
	int idx;

	do {
		acquire_ia64_lock(_hal, bar, &idx);
	} while (idx == -1);
	ia64_write_reg_addr(_hal, bar, addr, idx);
	initiate_ia64_read_cmd(_hal, bar, idx, nr);
	wait_for_ia64_complete(_hal, bar, idx);
	ia64_read_data(_hal, bar, data, nr, idx);
	release_ia64_lock(_hal, bar, idx);
}

static void xsc_ia64_write(void *hal, void __iomem *bar, u32 addr, void *data, int nr)
{
	struct xsc_hw_abstract_layer *_hal = hal;
	int idx;

	do {
		acquire_ia64_lock(_hal, bar, &idx);
	} while (idx == -1);
	ia64_write_data(_hal, bar, data, nr, idx);
	ia64_write_reg_addr(_hal, bar, addr, idx);
	initiate_ia64_write_cmd(_hal, bar, idx, nr);
	release_ia64_lock(_hal, bar, idx);
}

static void diamond_next_ring_tx_doorbell(void *hal, void __iomem *bar, u32 sqn, u32 next_pid)
{
	struct xsc_hw_abstract_layer *_hal = hal;
	union xsc2_send_doorbell {
		struct{
			u64  next_pid : 17;
			u64 qp_id : 10;
		};
		u64 raw;
	} db;

	db.next_pid = next_pid;
	db.qp_id = sqn;

	/* Make sure that descriptors are written before
	 * updating doorbell record and ringing the doorbell
	 */
	wmb();

	xsc_write64(bar, _hal->regs->tx_db, &db.raw);
}

static void diamond_next_ring_rx_doorbell(void *hal, void __iomem *bar, u32 rqn, u32 next_pid)
{
	struct xsc_hw_abstract_layer *_hal = hal;
	union xsc2_recv_doorbell {
		struct{
			u64  next_pid : 14;
			u64 qp_id : 10;
		};
		u64 raw;
	} db;

	db.next_pid = next_pid;
	db.qp_id = rqn;

	/* Make sure that descriptors are written before
	 * updating doorbell record and ringing the doorbell
	 */
	wmb();

	xsc_write64(bar, _hal->regs->rx_db, &db.raw);
}

union diamond_next_cq_doorbell {
	struct{
		u64	cq_next_cid:23;
		u64	cq_id:10;
		u64	cq_sta:2;
	};
	u64	raw;
};

static void diamond_next_update_cq_db(void *hal, void __iomem *bar,
				      u32 cqn, u32 next_cid, u8 solicited)
{
	struct xsc_hw_abstract_layer *_hal = hal;
	union diamond_next_cq_doorbell db;

	db.cq_next_cid = next_cid;
	db.cq_id = cqn;
	db.cq_sta = solicited ? CQ_STAT_ARM_SOLICITED : CQ_STAT_ARM_NEXT;

	/* Make sure that the doorbell record in host memory is
	 * written before ringing the doorbell via PCI MMIO.
	 */
	wmb();
	xsc_write64(bar, _hal->regs->complete_db, &db.raw);
}

static void diamond_next_set_cq_ci(void *hal, void __iomem *bar, u32 cqn, u32 next_cid)
{
	struct xsc_hw_abstract_layer *_hal = hal;
	union diamond_next_cq_doorbell db;

	db.cq_next_cid = next_cid;
	db.cq_id = cqn;
	db.cq_sta = CQ_STAT_FIRED;
	/* make sure val write to memory done */
	wmb();
	xsc_write64(bar, _hal->regs->complete_db, &db.raw);
}

static void diamond_next_set_eq_ci(void *hal, void __iomem *bar, u32 eqn, u32 next_cid, u8 arm)
{
	struct xsc_hw_abstract_layer *_hal = hal;
	union diamond_next_eq_doorbell {
		struct{
			u64 eq_next_cid : 12;
			u64 eq_id : 8;
			u64 eq_sta : 1;
		};
		u64 raw;
	} db;

	db.eq_next_cid = next_cid;
	db.eq_id = eqn;
	db.eq_sta = !!arm;

	/* make sure val write to memory done */
	wmb();
	xsc_write64(bar, _hal->regs->event_db, &db.raw);
}

static u8 diamond_next_get_mr_page_mode(u8 page_shift)
{
	return page_shift;
}

static inline u32 diamond_next_mkey_to_idx(u32 mkey)
{
	return mkey >> 8;
}

static inline u32 diamond_next_idx_to_mkey(u32 mkey_idx)
{
	return mkey_idx << 8;
}

static void diamond_next_set_mpt_tbl(void *hal, void __iomem *bar, int iae_idx,
				     u32 mtt_base, void *mr_request)
{
	struct xsc_hw_abstract_layer *_hal = hal;
	struct xsc_register_mr_request *req = mr_request;
	union xsc_mpt_entry {
		struct {
			u64 va;
			u64 mem_size:38;
			u64 pdn:24;
			u64 key:8;
			u64 mtt_base:20;
			u64 acc:4;
			u64 page_mode:5;
			u64 is_gpu:1;
			u64 mem_map_dis:1;
		} __packed;
		u64 raw[3];
	} mpt;
	u64 va = be64_to_cpu(req->va_base);
	u32 mkey = be32_to_cpu(req->mkey);
	u32 idx = diamond_next_mkey_to_idx(mkey);
	u32 reg_addr = _hal->regs->mpt_tbl_addr + idx * (_hal->regs->mpt_tbl_width >> 3);

	mpt.va = va;
	mpt.mem_size = be64_to_cpu(req->len);
	mpt.pdn = be32_to_cpu(req->pdn);
	mpt.key = mkey & 0xff;
	mpt.mtt_base = mtt_base;
	mpt.acc = req->acc;
	mpt.page_mode = req->page_mode;
	mpt.is_gpu = req->is_gpu;
	mpt.mem_map_dis = req->map_en;

	xsc_ia64_write_reg_mr(_hal, bar, reg_addr, mpt.raw, ARRAY_SIZE(mpt.raw), iae_idx);
}

static void diamond_next_clear_mpt_tbl(void *hal, void __iomem *bar, int iae_idx,
				       u32 mtt_base, void *mr_request)
{
	struct xsc_hw_abstract_layer *_hal = hal;
	struct xsc_unregister_mr_mbox_in *req = mr_request;
	union xsc_mpt_entry {
		struct {
			u64 va;
			u64 mem_size:38;
			u64 pdn:24;
			u64 key:8;
			u64 mtt_base:20;
			u64 acc:4;
			u64 page_mode:5;
			u64 is_gpu:1;
			u64 mem_map_dis:1;
		};
		u64 raw[3];
	} mpt;
	u32 idx = be32_to_cpu(req->mkey);
	u32 reg_addr = _hal->regs->mpt_tbl_addr + idx * (_hal->regs->mpt_tbl_width >> 3);

	memset(&mpt, 0x00, sizeof(mpt));
	xsc_ia64_write_reg_mr(_hal, bar, reg_addr, mpt.raw, ARRAY_SIZE(mpt.raw), iae_idx);
}

#define PAGE_SHIFT_4K	12
static void diamond_next_set_mtt_tbl(void *hal, void __iomem *bar, int iae_idx,
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
		xsc_write64(bar, reg_addr, &pa);
	}
}

static void diamond_next_set_read_done_msix_vector(void *hal, void __iomem *bar, u32 vector)
{
}

static int diamond_next_dma_write_tbl_once(void *hal, void __iomem *bar,
					   u32 data_len, u64 dma_wr_addr,
					   u32 host_id, u32 func_id, u64 success[2], u32 size)
{
	return -1;
}

static void diamond_next_dma_read_tbl(void *hal, void __iomem *bar, u32 host_id, u32 func_id,
				      u64 data_addr, u32 tbl_id, u32 burst_num, u32 tbl_start_addr)
{
}

static const u32 xsc_msg_opcode[][2][2] = {
	[XSC_MSG_OPCODE_RDMA_WRITE][XSC_REQ][XSC_WITHOUT_IMMDT] = XSC_OPCODE_RDMA_REQ_WRITE,
	[XSC_MSG_OPCODE_RDMA_WRITE][XSC_REQ][XSC_WITH_IMMDT] = XSC_OPCODE_RDMA_REQ_WRITE_IMMDT,
	[XSC_MSG_OPCODE_RDMA_WRITE][XSC_RSP][XSC_WITHOUT_IMMDT] = XSC_OPCODE_RDMA_CQE_ERROR,
	[XSC_MSG_OPCODE_RDMA_WRITE][XSC_RSP][XSC_WITH_IMMDT] = XSC_OPCODE_RDMA_RSP_WRITE_IMMDT,
	[XSC_MSG_OPCODE_RAW][XSC_REQ][XSC_WITHOUT_IMMDT] = XSC_OPCODE_RDMA_MAD_REQ_SEND,
	[XSC_MSG_OPCODE_RAW][XSC_RSP][XSC_WITHOUT_IMMDT] = XSC_OPCODE_RDMA_MAD_RSP_RECV,
};

struct diamond_next_cqe {
	u8		error_code;
	__le32		qp_id:15;
	u8		raw_is_cut:1;
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
	u8		msg_opcode;
	u8		rsv;
	__le16		rsv1[2];
	__le16		rsv2:15;
	u8		owner:1;
};

static bool diamond_next_is_err_cqe(void *cqe)
{
	struct diamond_next_cqe *_cqe = cqe;

	return !!_cqe->error_code;
}

static u8 diamond_next_get_cqe_error_code(void *cqe)
{
	struct diamond_next_cqe *_cqe = cqe;

	return _cqe->error_code;
}

static u8 diamond_next_get_cqe_opcode(void *cqe)
{
	struct diamond_next_cqe *_cqe = cqe;
	u8 msg_opcode = _cqe->msg_opcode;

	if (_cqe->error_code)
		return _cqe->type ? XSC_OPCODE_RDMA_RSP_ERROR : XSC_OPCODE_RDMA_REQ_ERROR;
	if (msg_opcode != XSC_MSG_OPCODE_RAW && msg_opcode != XSC_MSG_OPCODE_RDMA_WRITE)
		return XSC_OPCODE_RDMA_CQE_ERROR;
	return xsc_msg_opcode[msg_opcode][_cqe->type][_cqe->with_immdt];
}

static u32 diamond_next_get_max_mtt_num(void *hal)
{
	struct xsc_hw_abstract_layer *_hal = hal;

	return _hal->regs->mtt_inst_depth << _hal->regs->mtt_inst_num_log;
}

static u32 diamond_next_get_max_mpt_num(void *hal)
{
	struct xsc_hw_abstract_layer *_hal = hal;

	return _hal->regs->mpt_tbl_depth;
}

struct diamond_next_data_seg {
	u32	length;
	u32	key;
	u64	addr;
};

static void diamond_next_set_data_seg(void *data_seg, u32 length, u32 key, u64 addr)
{
	struct diamond_next_data_seg *seg = data_seg;

	seg->length = length;
	seg->key = key;
	seg->addr = addr;
}

static bool diamond_next_skb_need_linearize(int ds_num)
{
	return ds_num > 2;
}

static struct xsc_hw_ops diamond_next_arch_ops = {
	.read = xsc_read64,
	.write = xsc_write64,
	.ia_read = xsc_ia64_read,
	.ia_write = xsc_ia64_write,
	.ring_tx_doorbell = diamond_next_ring_tx_doorbell,
	.ring_rx_doorbell = diamond_next_ring_rx_doorbell,
	.update_cq_db = diamond_next_update_cq_db,
	.set_cq_ci = diamond_next_set_cq_ci,
	.set_eq_ci = diamond_next_set_eq_ci,
	.get_mr_page_mode = diamond_next_get_mr_page_mode,
	.mkey_to_idx = diamond_next_mkey_to_idx,
	.idx_to_mkey = diamond_next_idx_to_mkey,
	.set_mpt = diamond_next_set_mpt_tbl,
	.clear_mpt = diamond_next_clear_mpt_tbl,
	.set_mtt = diamond_next_set_mtt_tbl,
	.set_read_done_msix_vector = diamond_next_set_read_done_msix_vector,
	.dma_write_tbl_once = diamond_next_dma_write_tbl_once,
	.dma_read_tbl = diamond_next_dma_read_tbl,
	.is_err_cqe = diamond_next_is_err_cqe,
	.get_cqe_error_code = diamond_next_get_cqe_error_code,
	.get_cqe_opcode = diamond_next_get_cqe_opcode,
	.get_max_mtt_num = diamond_next_get_max_mtt_num,
	.get_max_mpt_num = diamond_next_get_max_mpt_num,
	.set_data_seg = diamond_next_set_data_seg,
	.skb_need_linearize = diamond_next_skb_need_linearize,
};

static struct xsc_hw_reg diamond_next_pf_regs = {
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
	.mpt_tbl_addr = MMC_MPT_TBL_MEM_ADDR - 0xa0000000,
	.mpt_tbl_depth = MMC_MPT_TBL_MEM_DEPTH,
	.mpt_tbl_width = MMC_MPT_TBL_MEM_WIDTH,
	.mtt_inst_base_addr = MMC_MTT_TBL_MEM_ADDR - 0xa0000000,
	.mtt_inst_stride = 0,
	.mtt_inst_num_log = 0,
	.mtt_inst_depth = MMC_MTT_TBL_MEM_DEPTH,
};

static struct xsc_hw_reg diamond_next_vf_regs = {
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

struct xsc_hw_abstract_layer diamond_next_pf_hal = {
	.ops = &diamond_next_arch_ops,
	.regs = &diamond_next_pf_regs,
};

struct xsc_hw_abstract_layer diamond_next_vf_hal = {
	.ops = &diamond_next_arch_ops,
	.regs = &diamond_next_vf_regs,
};

struct xsc_hw_abstract_layer *get_diamond_next_pf_hal(void)
{
	return &diamond_next_pf_hal;
}

struct xsc_hw_abstract_layer *get_diamond_next_vf_hal(void)
{
	return &diamond_next_vf_hal;
}

