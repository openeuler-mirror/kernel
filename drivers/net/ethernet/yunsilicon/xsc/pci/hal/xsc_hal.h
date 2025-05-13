/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2024 - 2024, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#ifndef XSC_HAL_H
#define XSC_HAL_H

enum hw_arch {
	HW_ARCH_ANDES,
	HW_ARCH_DIAMOND,
	HW_ARCH_DIAMOND_NEXT,
};

struct xsc_hw_abstract_layer;

struct xsc_hw_ops {
	void (*read)(void __iomem *bar, u32 addr, void *data, int len);
	void (*write)(void __iomem *bar, u32 addr, void *data);
	void (*ia_read)(void *hal, void __iomem *bar, u32 addr, void *data, int nr);
	void (*ia_write)(void *hal, void __iomem *bar, u32 addr, void *data, int nr);
	void (*ring_tx_doorbell)(void *hal, void __iomem *bar, u32 sqn, u32 next_pid);
	void (*ring_rx_doorbell)(void *hal, void __iomem *bar, u32 rqn, u32 next_pid);
	void (*update_cq_db)(void *hal, void __iomem *bar, u32 cqn, u32 next_cid, u8 solicited);
	void (*set_cq_ci)(void *hal, void __iomem *bar, u32 cqn, u32 next_cid);
	void (*set_eq_ci)(void *hal, void __iomem *bar, u32 cqn, u32 next_cid, u8 arm);
	u8 (*get_mr_page_mode)(u8 page_shift);
	u32 (*mkey_to_idx)(u32 mkey);
	u32 (*idx_to_mkey)(u32 mkey_idx);
	void (*set_mpt)(void *hal, void __iomem *bar, int iae_idx, u32 mtt_base, void *mr_request);
	void (*clear_mpt)(void *hal, void __iomem *bar, int iae_idx,
			  u32 mtt_base, void *mr_request);
	void (*set_mtt)(void *hal, void __iomem *bar, int iae_idx, u32 mtt_base, void *mr_request);
	void (*set_read_done_msix_vector)(void *hal, void __iomem *bar, u32 vector);
	int (*dma_write_tbl_once)(void *hal, void __iomem *bar, u32 data_len, u64 dma_wr_addr,
				  u32 host_id, u32 func_id, u64 success[2], u32 size);
	void (*dma_read_tbl)(void *hal, void __iomem *bar, u32 host_id, u32 func_id, u64 data_addr,
			     u32 tbl_id, u32 burst_num, u32 tbl_start_addr);
	bool (*is_err_cqe)(void *cqe);
	u8 (*get_cqe_error_code)(void *cqe);
	u8 (*get_cqe_opcode)(void *cqe);
	u32 (*get_max_mtt_num)(void *hal);
	u32 (*get_max_mpt_num)(void *hal);
	void (*set_data_seg)(void *data_seg, u32 length, u32 key, u64 addr);
	bool (*skb_need_linearize)(int ds_num);
};

struct xsc_hw_reg {
	u32 tx_db;
	u32 rx_db;
	u32 complete_db;
	u32 complete_reg;
	u32 event_db;
	u32 cpm_get_lock;
	u32 cpm_put_lock;
	u32 cpm_lock_avail;
	u32 cpm_data_mem;
	u32 cpm_cmd;
	u32 cpm_addr;
	u32 cpm_busy;
	u32 req_pid_addr;
	u32 req_cid_addr;
	u32 rsp_pid_addr;
	u32 rsp_cid_addr;
	u32 req_buf_h_addr;
	u32 req_buf_l_addr;
	u32 rsp_buf_h_addr;
	u32 rsp_buf_l_addr;
	u32 msix_vec_addr;
	u32 element_sz_addr;
	u32 q_depth_addr;
	u32 interrupt_stat_addr;
	u32 tbl2irq_rd_done_msix_reg;
	u32 dma_ul_busy_reg;
	u32 dma_dl_done_reg;
	u32 dma_dl_success_reg;
	u32 err_code_clr_reg;
	u32 dma_rd_table_id_reg;
	u32 dma_rd_addr_reg;
	u32 indrw_rd_start_reg;
	u32 tbl_dl_busy_reg;
	u32 tbl_dl_req_reg;
	u32 tbl_dl_addr_l_reg;
	u32 tbl_dl_addr_h_reg;
	u32 tbl_dl_start_reg;
	u32 tbl_ul_req_reg;
	u32 tbl_ul_addr_l_reg;
	u32 tbl_ul_addr_h_reg;
	u32 tbl_ul_start_reg;
	u32 tbl_msg_rdy_reg;
	u32 mpt_tbl_addr;
	u32 mpt_tbl_depth;
	u32 mpt_tbl_width;
	u32 mtt_inst_base_addr;
	u32 mtt_inst_stride;
	u32 mtt_inst_num_log;
	u32 mtt_inst_depth;
};

struct xsc_hw_abstract_layer {
	u32 hw_arch;
	struct xsc_hw_reg *regs;
	struct xsc_hw_ops *ops;
};

struct xsc_hw_abstract_layer *get_andes_pf_hal(void);
struct xsc_hw_abstract_layer *get_andes_bar_compressed_pf_hal(void);
struct xsc_hw_abstract_layer *get_andes_vf_hal(void);
struct xsc_hw_abstract_layer *get_diamond_pf_hal(void);
struct xsc_hw_abstract_layer *get_diamond_vf_hal(void);
struct xsc_hw_abstract_layer *get_diamond_next_pf_hal(void);
struct xsc_hw_abstract_layer *get_diamond_next_vf_hal(void);

enum {
	CQ_STAT_FIRED,
	CQ_STAT_KEEP,
	CQ_STAT_ARM_NEXT,
	CQ_STAT_ARM_SOLICITED,
};

static inline bool xsc_is_diamond_like_arch(u32 hw_arch)
{
	return hw_arch == HW_ARCH_DIAMOND || hw_arch == HW_ARCH_DIAMOND_NEXT;
}

#endif
