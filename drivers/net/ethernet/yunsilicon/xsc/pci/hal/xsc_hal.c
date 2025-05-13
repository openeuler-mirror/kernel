// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2024 - 2024, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#include "common/xsc_core.h"
#include "xsc_hal.h"

void xsc_init_hal(struct xsc_core_device *xdev, u32 device_id)
{
	struct xsc_hw_abstract_layer *hal;

	switch (device_id) {
	case XSC_MC_PF_DEV_ID:
	case XSC_MF_HOST_PF_DEV_ID:
	case XSC_MF_SOC_PF_DEV_ID:
	case XSC_MS_PF_DEV_ID:
	case XSC_MV_HOST_PF_DEV_ID:
	case XSC_MV_SOC_PF_DEV_ID:
		if (is_pf_bar_compressed(xdev))
			hal = get_andes_bar_compressed_pf_hal();
		else
			hal = get_andes_pf_hal();
		hal->hw_arch = HW_ARCH_ANDES;
		break;
	case XSC_MC_VF_DEV_ID:
	case XSC_MF_HOST_VF_DEV_ID:
	case XSC_MS_VF_DEV_ID:
	case XSC_MV_HOST_VF_DEV_ID:
		hal = get_andes_vf_hal();
		hal->hw_arch = HW_ARCH_ANDES;
		break;
	case XSC_MC_PF_DEV_ID_DIAMOND:
		hal = get_diamond_pf_hal();
		hal->hw_arch = HW_ARCH_DIAMOND;
		break;
	case XSC_MC_PF_DEV_ID_DIAMOND_NEXT:
		hal = get_diamond_next_pf_hal();
		hal->hw_arch = HW_ARCH_DIAMOND_NEXT;
		break;
	default:
		hal = get_andes_pf_hal();
		hal->hw_arch = HW_ARCH_ANDES;
		break;
	}
	xdev->hal = hal;
}

void xsc_set_mtt_info(struct xsc_core_device *xdev)
{
	struct xsc_hw_abstract_layer *hal = xdev->hal;

	hal->regs->mpt_tbl_addr = xdev->caps.mpt_tbl_addr - 0xa0000000;
	hal->regs->mpt_tbl_depth = xdev->caps.mpt_tbl_depth;
	hal->regs->mpt_tbl_width = xdev->caps.mpt_tbl_width;
	hal->regs->mtt_inst_base_addr = xdev->caps.mtt_inst_base_addr - 0xa0000000;
	hal->regs->mtt_inst_stride = xdev->caps.mtt_inst_stride;
	hal->regs->mtt_inst_num_log = xdev->caps.mtt_inst_num_log;
	hal->regs->mtt_inst_depth = xdev->caps.mtt_inst_depth;
}

void xsc_set_pf_db_addr(struct xsc_core_device *xdev,
			u64 tx_db, u64 rx_db, u64 cq_db, u64 cq_reg, u64 eq_db)
{
	struct xsc_hw_abstract_layer *hal = xdev->hal;

	if (is_pf_bar_compressed(xdev))
		return;

	if (xsc_core_is_pf(xdev)) {
		hal->regs->tx_db = tx_db - 0xa0000000;
		hal->regs->rx_db = rx_db - 0xa0000000;
		hal->regs->complete_db = cq_db - 0xa0000000;
		hal->regs->complete_reg = cq_reg - 0xa0000000;
		hal->regs->event_db = eq_db - 0xa0000000;
	}
}

void xsc_get_db_addr(struct xsc_core_device *xdev,
		     u64 *tx_db, u64 *rx_db, u64 *cq_db, u64 *cq_reg, u64 *eq_db)
{
	struct xsc_hw_abstract_layer *hal = xdev->hal;

	if (!xsc_core_is_pf(xdev) || is_pf_bar_compressed(xdev)) {
		if (tx_db)
			*tx_db = hal->regs->tx_db;
		if (rx_db)
			*rx_db = hal->regs->rx_db;
		if (cq_db)
			*cq_db = hal->regs->complete_db;
		if (cq_reg)
			*cq_reg = hal->regs->complete_reg;
		if (eq_db)
			*eq_db = hal->regs->event_db;
	} else {
		if (tx_db)
			*tx_db = hal->regs->tx_db + 0xa0000000;
		if (rx_db)
			*rx_db = hal->regs->rx_db + 0xa0000000;
		if (cq_db)
			*cq_db = hal->regs->complete_db + 0xa0000000;
		if (cq_reg)
			*cq_reg = hal->regs->complete_reg + 0xa0000000;
		if (eq_db)
			*eq_db = hal->regs->event_db + 0xa0000000;
	}
}
EXPORT_SYMBOL_GPL(xsc_get_db_addr);

void xsc_read_reg(struct xsc_core_device *xdev, u32 addr, void *data, int len)
{
	struct xsc_hw_abstract_layer *hal = xdev->hal;

	hal->ops->read(xdev->bar, addr, data, len);
}

void xsc_write_reg(struct xsc_core_device *xdev, u32 addr, void *data)
{
	struct xsc_hw_abstract_layer *hal = xdev->hal;

	hal->ops->write(xdev->bar, addr, data);
}

void xsc_ia_read(struct xsc_core_device *xdev, u32 addr, void *data, int nr)
{
	struct xsc_hw_abstract_layer *hal = xdev->hal;

	hal->ops->ia_read(hal, xdev->bar, addr, data, nr);
}

void xsc_ia_write(struct xsc_core_device *xdev, u32 addr, void *data, int nr)
{
	struct xsc_hw_abstract_layer *hal = xdev->hal;

	hal->ops->ia_write(hal, xdev->bar, addr, data, nr);
}

void xsc_update_tx_db(struct xsc_core_device *xdev, u32 sqn, u32 next_pid)
{
	struct xsc_hw_abstract_layer *hal = xdev->hal;

	hal->ops->ring_tx_doorbell(hal, xdev->bar, sqn, next_pid);
}
EXPORT_SYMBOL_GPL(xsc_update_tx_db);

void xsc_update_rx_db(struct xsc_core_device *xdev, u32 rqn, u32 next_pid)
{
	struct xsc_hw_abstract_layer *hal = xdev->hal;

	hal->ops->ring_rx_doorbell(hal, xdev->bar, rqn, next_pid);
}
EXPORT_SYMBOL_GPL(xsc_update_rx_db);

void xsc_arm_cq(struct xsc_core_device *xdev, u32 cqn, u32 next_cid, u8 solicited)
{
	struct xsc_hw_abstract_layer *hal = xdev->hal;

	hal->ops->update_cq_db(hal, xdev->bar, cqn, next_cid, solicited);
}
EXPORT_SYMBOL_GPL(xsc_arm_cq);

void xsc_update_cq_ci(struct xsc_core_device *xdev, u32 cqn, u32 next_cid)
{
	struct xsc_hw_abstract_layer *hal = xdev->hal;

	hal->ops->set_cq_ci(hal, xdev->bar, cqn, next_cid);
}
EXPORT_SYMBOL_GPL(xsc_update_cq_ci);

void xsc_update_eq_ci(struct xsc_core_device *xdev, u32 eqn, u32 next_cid, u8 arm)
{
	struct xsc_hw_abstract_layer *hal = xdev->hal;

	hal->ops->set_eq_ci(hal, xdev->bar, eqn, next_cid, arm);
}
EXPORT_SYMBOL_GPL(xsc_update_eq_ci);

void xsc_update_cmdq_req_pid(struct xsc_core_device *xdev, u32 req_pid)
{
	struct xsc_hw_abstract_layer *hal = xdev->hal;

	hal->ops->write(xdev->bar, hal->regs->req_pid_addr, &req_pid);
}

void xsc_update_cmdq_req_cid(struct xsc_core_device *xdev, u32 req_cid)
{
	struct xsc_hw_abstract_layer *hal = xdev->hal;

	hal->ops->write(xdev->bar, hal->regs->req_cid_addr, &req_cid);
}

void xsc_update_cmdq_rsp_pid(struct xsc_core_device *xdev, u32 rsp_pid)
{
	struct xsc_hw_abstract_layer *hal = xdev->hal;

	hal->ops->write(xdev->bar, hal->regs->rsp_pid_addr, &rsp_pid);
}

void xsc_update_cmdq_rsp_cid(struct xsc_core_device *xdev, u32 rsp_cid)
{
	struct xsc_hw_abstract_layer *hal = xdev->hal;

	hal->ops->write(xdev->bar, hal->regs->rsp_cid_addr, &rsp_cid);
}

u32 xsc_get_cmdq_req_pid(struct xsc_core_device *xdev)
{
	struct xsc_hw_abstract_layer *hal = xdev->hal;
	u32 val;

	hal->ops->read(xdev->bar, hal->regs->req_pid_addr, &val, sizeof(val));
	return val;
}

u32 xsc_get_cmdq_req_cid(struct xsc_core_device *xdev)
{
	struct xsc_hw_abstract_layer *hal = xdev->hal;
	u32 val;

	hal->ops->read(xdev->bar, hal->regs->req_cid_addr, &val, sizeof(val));
	return val;
}

u32 xsc_get_cmdq_rsp_pid(struct xsc_core_device *xdev)
{
	struct xsc_hw_abstract_layer *hal = xdev->hal;
	u32 val;

	hal->ops->read(xdev->bar, hal->regs->rsp_pid_addr, &val, sizeof(val));
	return val;
}

u32 xsc_get_cmdq_rsp_cid(struct xsc_core_device *xdev)
{
	struct xsc_hw_abstract_layer *hal = xdev->hal;
	u32 val;

	hal->ops->read(xdev->bar, hal->regs->rsp_cid_addr, &val, sizeof(val));
	return val;
}

u32 xsc_get_cmdq_log_stride(struct xsc_core_device *xdev)
{
	struct xsc_hw_abstract_layer *hal = xdev->hal;
	u32 val;

	hal->ops->read(xdev->bar, hal->regs->element_sz_addr, &val, sizeof(val));
	return val;
}

void xsc_set_cmdq_depth(struct xsc_core_device *xdev, u32 depth)
{
	struct xsc_hw_abstract_layer *hal = xdev->hal;

	hal->ops->write(xdev->bar, hal->regs->q_depth_addr, &depth);
}

void xsc_set_cmdq_req_buf_addr(struct xsc_core_device *xdev, u32 haddr, u32 laddr)
{
	struct xsc_hw_abstract_layer *hal = xdev->hal;

	hal->ops->write(xdev->bar, hal->regs->req_buf_h_addr, &haddr);
	hal->ops->write(xdev->bar, hal->regs->req_buf_l_addr, &laddr);
}

void xsc_set_cmdq_rsp_buf_addr(struct xsc_core_device *xdev, u32 haddr, u32 laddr)
{
	struct xsc_hw_abstract_layer *hal = xdev->hal;

	hal->ops->write(xdev->bar, hal->regs->rsp_buf_h_addr, &haddr);
	hal->ops->write(xdev->bar, hal->regs->rsp_buf_l_addr, &laddr);
}

void xsc_set_cmdq_msix_vector(struct xsc_core_device *xdev, u32 vector)
{
	struct xsc_hw_abstract_layer *hal = xdev->hal;

	hal->ops->write(xdev->bar, hal->regs->msix_vec_addr, &vector);
}

void xsc_check_cmdq_status(struct xsc_core_device *xdev)
{
	struct xsc_hw_abstract_layer *hal = xdev->hal;
	u32 status;

	hal->ops->read(xdev->bar, hal->regs->interrupt_stat_addr, &status, sizeof(status));
	if (status) {
		status = 0xf;
		hal->ops->write(xdev->bar, hal->regs->interrupt_stat_addr, &status);
	}
}

int xsc_handle_cmdq_interrupt(struct xsc_core_device *xdev)
{
	struct xsc_hw_abstract_layer *hal = xdev->hal;
	union interrupt_stat {
		struct {
			u32	hw_read_req_err:1;
			u32	hw_write_req_err:1;
			u32	req_pid_err:1;
			u32	rsp_cid_err:1;
		};
		u32	raw;
	} stat;

	int err = 0;
	int retry = 0;

	hal->ops->read(xdev->bar, hal->regs->interrupt_stat_addr, &stat.raw, sizeof(stat.raw));
	while (stat.raw != 0) {
		err++;
		if (stat.hw_read_req_err) {
			retry = 1;
			stat.hw_read_req_err = 0;
			xsc_core_err(xdev, "hw report read req from host failed!\n");
		} else if (stat.hw_write_req_err) {
			retry = 1;
			stat.hw_write_req_err = 0;
			xsc_core_err(xdev, "hw report write req to fw failed!\n");
		} else if (stat.req_pid_err) {
			stat.req_pid_err = 0;
			xsc_core_err(xdev, "hw report unexpected req pid!\n");
		} else if (stat.rsp_cid_err) {
			stat.rsp_cid_err = 0;
			xsc_core_err(xdev, "hw report unexpected rsp cid!\n");
		} else {
			stat.raw = 0;
			xsc_core_err(xdev, "ignore unknown interrupt!\n");
		}
	}

	if (retry) {
		if (xdev->cmd.retry_cnt >= XSC_CMD_MAX_RETRY_CNT) {
			xsc_core_warn(xdev, "err handler have retried for %d times, stop retry\n",
				      xdev->cmd.retry_cnt);
			goto clear_err_int;
		}
		hal->ops->write(xdev->bar, hal->regs->req_pid_addr, &xdev->cmd.cmd_pid);
		xdev->cmd.retry_cnt++;
	}

clear_err_int:
	if (err) {
		stat.raw = 0xf;
		hal->ops->write(xdev->bar, hal->regs->interrupt_stat_addr, &stat.raw);
	}

	return err;
}

u8 xsc_get_mr_page_mode(struct xsc_core_device *xdev, u8 page_shift)
{
	struct xsc_hw_abstract_layer *hal = xdev->hal;

	return hal->ops->get_mr_page_mode(page_shift);
}
EXPORT_SYMBOL_GPL(xsc_get_mr_page_mode);

u32 xsc_mkey_to_idx(struct xsc_core_device *xdev, u32 mkey)
{
	struct xsc_hw_abstract_layer *hal = xdev->hal;

	return hal->ops->mkey_to_idx(mkey);
}

u32 xsc_idx_to_mkey(struct xsc_core_device *xdev, u32 mkey_idx)
{
	struct xsc_hw_abstract_layer *hal = xdev->hal;

	return hal->ops->idx_to_mkey(mkey_idx);
}

void xsc_set_mpt(struct xsc_core_device *xdev, int iae_idx, u32 mtt_base, void *mr_request)
{
	struct xsc_hw_abstract_layer *hal = xdev->hal;

	return hal->ops->set_mpt(hal, xdev->bar, iae_idx, mtt_base, mr_request);
}

void xsc_clear_mpt(struct xsc_core_device *xdev, int iae_idx, u32 mtt_base, void *mr_request)
{
	struct xsc_hw_abstract_layer *hal = xdev->hal;

	return hal->ops->clear_mpt(hal, xdev->bar, iae_idx, mtt_base, mr_request);
}

void xsc_set_mtt(struct xsc_core_device *xdev, int iae_idx, u32 mtt_base, void *mr_request)
{
	struct xsc_hw_abstract_layer *hal = xdev->hal;

	return hal->ops->set_mtt(hal, xdev->bar, iae_idx, mtt_base, mr_request);
}

void xsc_set_read_done_msix_vector(struct xsc_core_device *xdev, u32 vector)
{
	struct xsc_hw_abstract_layer *hal = xdev->hal;

	hal->ops->set_read_done_msix_vector(hal, xdev->bar, vector);
}

int xsc_dma_write_tbl_once(struct xsc_core_device *xdev, u32 data_len, u64 dma_wr_addr,
			   u32 host_id, u32 func_id, u64 success[2], u32 size)
{
	struct xsc_hw_abstract_layer *hal = xdev->hal;

	return hal->ops->dma_write_tbl_once(hal, xdev->bar, data_len, dma_wr_addr,
					    host_id, func_id, success, size);
}

void xsc_dma_read_tbl(struct xsc_core_device *xdev, u32 host_id, u32 func_id, u64 data_addr,
		      u32 tbl_id, u32 burst_num, u32 tbl_start_addr)
{
	struct xsc_hw_abstract_layer *hal = xdev->hal;

	hal->ops->dma_read_tbl(hal, xdev->bar, host_id, func_id, data_addr,
			       tbl_id, burst_num, tbl_start_addr);
}

bool xsc_skb_need_linearize(struct xsc_core_device *xdev, int ds_num)
{
	struct xsc_hw_abstract_layer *hal = xdev->hal;

	return hal->ops->skb_need_linearize(ds_num);
}
EXPORT_SYMBOL_GPL(xsc_skb_need_linearize);

bool xsc_is_err_cqe(struct xsc_core_device *xdev, void *cqe)
{
	struct xsc_hw_abstract_layer *hal = xdev->hal;

	return hal->ops->is_err_cqe(cqe);
}
EXPORT_SYMBOL_GPL(xsc_is_err_cqe);

u8 xsc_get_cqe_error_code(struct xsc_core_device *xdev, void *cqe)
{
	struct xsc_hw_abstract_layer *hal = xdev->hal;

	return hal->ops->get_cqe_error_code(cqe);
}
EXPORT_SYMBOL_GPL(xsc_get_cqe_error_code);

u8 xsc_get_cqe_opcode(struct xsc_core_device *xdev, void *cqe)
{
	struct xsc_hw_abstract_layer *hal = xdev->hal;

	return hal->ops->get_cqe_opcode(cqe);
}
EXPORT_SYMBOL_GPL(xsc_get_cqe_opcode);

u16 xsc_get_eth_channel_num(struct xsc_core_device *xdev)
{
	struct xsc_hw_abstract_layer *hal = xdev->hal;

	return xsc_is_diamond_like_arch(hal->hw_arch) ?
		1 : xdev->dev_res->eq_table.num_comp_vectors;
}
EXPORT_SYMBOL_GPL(xsc_get_eth_channel_num);

u32 xsc_get_max_mtt_num(struct xsc_core_device *xdev)
{
	struct xsc_hw_abstract_layer *hal = xdev->hal;

	return hal->ops->get_max_mtt_num(hal);
}

u32 xsc_get_max_mpt_num(struct xsc_core_device *xdev)
{
	struct xsc_hw_abstract_layer *hal = xdev->hal;

	return hal->ops->get_max_mpt_num(hal);
}

u32 xsc_get_rdma_stat_mask(struct xsc_core_device *xdev)
{
	struct xsc_hw_abstract_layer *hal = xdev->hal;
	u32 mask;

	if (xsc_core_is_pf(xdev))
		mask = xsc_is_diamond_like_arch(hal->hw_arch) ? 0x1FFFFCFF : 0xFFFFFF;
	else
		mask = 0xfff;

	return mask;
}
EXPORT_SYMBOL_GPL(xsc_get_rdma_stat_mask);

u32 xsc_get_eth_stat_mask(struct xsc_core_device *xdev)
{
	struct xsc_hw_abstract_layer *hal = xdev->hal;
	u32 mask;

	if (xsc_core_is_pf(xdev))
		mask = xsc_is_diamond_like_arch(hal->hw_arch) ? 0x30ff : 0x3fff;
	else
		mask = 0xf;

	return mask;
}
EXPORT_SYMBOL_GPL(xsc_get_eth_stat_mask);

void xsc_set_data_seg(struct xsc_core_device *xdev, void *data_seg, u64 addr, u32 key, u32 length)
{
	struct xsc_hw_abstract_layer *hal = xdev->hal;

	hal->ops->set_data_seg(data_seg, length, key, addr);
}
EXPORT_SYMBOL_GPL(xsc_set_data_seg);

u8 xsc_get_mad_msg_opcode(struct xsc_core_device *xdev)
{
	struct xsc_hw_abstract_layer *hal = xdev->hal;

	return xsc_is_diamond_like_arch(hal->hw_arch) ? XSC_MSG_OPCODE_RAW : XSC_MSG_OPCODE_MAD;
}
EXPORT_SYMBOL_GPL(xsc_get_mad_msg_opcode);

u32 xsc_get_max_qp_depth(struct xsc_core_device *xdev)
{
	struct xsc_hw_abstract_layer *hal = xdev->hal;

	return xsc_is_diamond_like_arch(hal->hw_arch) ? xdev->caps.max_wqes : (32 * 1024);
}
EXPORT_SYMBOL_GPL(xsc_get_max_qp_depth);

bool xsc_check_max_qp_depth(struct xsc_core_device *xdev, u32 *wqe_cnt, u32 max_qp_depth)
{
	struct xsc_hw_abstract_layer *hal = xdev->hal;

	if (*wqe_cnt <= max_qp_depth)
		return false;

	if (xsc_is_diamond_like_arch(hal->hw_arch))
		return true;

	*wqe_cnt = max_qp_depth;
	return false;
}
EXPORT_SYMBOL_GPL(xsc_check_max_qp_depth);
