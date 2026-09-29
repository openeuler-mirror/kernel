/* SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB */
/* Copyright (c) 2018 - 2025 Beijing WangXun Technology Co., Ltd. */
#ifndef NSER_H
#define NSER_H

#define RDMA_BIT2(type, a) ((u##type) 1UL << a)
#define RDMA_MASK3(type, mask, shift)	((u##type) mask << shift)
#define MAKEMASK(m, s) ((m) << (s))

#define NSER_WQEALLOC_WQE_DESC_INDEX_S 20
#define NSER_WQEALLOC_WQE_DESC_INDEX GENMASK(31, 20)

#define NSER_CQPTAIL_WQTAIL_S 0
#define NSER_CQPTAIL_WQTAIL GENMASK(10, 0)
#define NSER_CQPTAIL_CQP_OP_ERR_S 31
#define NSER_CQPTAIL_CQP_OP_ERR BIT(31)

#define NSER_CQPERRCODES_CQP_MINOR_CODE_S 0
#define NSER_CQPERRCODES_CQP_MINOR_CODE GENMASK(15, 0)
#define NSER_CQPERRCODES_CQP_MAJOR_CODE_S 16
#define NSER_CQPERRCODES_CQP_MAJOR_CODE GENMASK(31, 16)
#define NSER_GLPCI_LBARCTRL_PE_DB_SIZE_S 4
#define NSER_GLPCI_LBARCTRL_PE_DB_SIZE GENMASK(5, 4)
#define NSER_GLINT_RATE_INTERVAL_S 0
#define NSER_GLINT_RATE_INTERVAL GENMASK(4, 0)
#define NSER_GLINT_RATE_INTRL_ENA_S 6
#define NSER_GLINT_RATE_INTRL_ENA_M BIT(6)
#define NSER_GLINT_RATE_INTRL_ENA BIT(6)



#define NSER_GLINT_DYN_CTL_INTMASK_S 0
#define NSER_GLINT_DYN_CTL_INTMASK BIT(0)
#define NSER_GLINT_DYN_CTL_CLEARPBA_S 1
#define NSER_GLINT_DYN_CTL_CLEARPBA BIT(1)
#define NSER_GLINT_DYN_CTL_ITR_VLD_S 4
#define NSER_GLINT_DYN_CTL_ITR_VLD BIT(4)
#define NSER_GLINT_DYN_CTL_INTERVAL_S 8
#define NSER_GLINT_DYN_CTL_INTERVAL GENMASK(19, 8)

#define NSER_GLINT_CEQCTL_ITR_INDX_S 11
#define NSER_GLINT_CEQCTL_ITR_INDX GENMASK(12, 11)
#define NSER_GLINT_CEQCTL_CAUSE_ENA_S 30
#define NSER_GLINT_CEQCTL_CAUSE_ENA BIT(30)
#define NSER_GLINT_CEQCTL_MSIX_INDX_S 0
#define NSER_GLINT_CEQCTL_MSIX_INDX GENMASK(10, 0)
#define NSER_PFINT_AEQCTL_MSIX_INDX_S 0
#define NSER_PFINT_AEQCTL_MSIX_INDX GENMASK(10, 0)
#define NSER_PFINT_AEQCTL_ITR_INDX_S 11
#define NSER_PFINT_AEQCTL_ITR_INDX GENMASK(12, 11)
#define NSER_PFINT_AEQCTL_CAUSE_ENA_S 30
#define NSER_PFINT_AEQCTL_CAUSE_ENA BIT(30)
#define NSER_PFHMC_PDINV_PMSDIDX_S 0
#define NSER_PFHMC_PDINV_PMSDIDX GENMASK(11, 0)
#define NSER_PFHMC_PDINV_PMSDPARTSEL_S 15
#define NSER_PFHMC_PDINV_PMSDPARTSEL BIT(15)
#define NSER_PFHMC_PDINV_PMPDIDX_S 16
#define NSER_PFHMC_PDINV_PMPDIDX GENMASK(24, 16)
#define NSER_PFHMC_SDDATALOW_PMSDVALID_S 0
#define NSER_PFHMC_SDDATALOW_PMSDVALID BIT(0)
#define NSER_PFHMC_SDDATALOW_PMSDTYPE_S 1
#define NSER_PFHMC_SDDATALOW_PMSDTYPE BIT(1)
#define NSER_PFHMC_SDDATALOW_PMSDBPCOUNT_S 2
#define NSER_PFHMC_SDDATALOW_PMSDBPCOUNT GENMASK(11, 2)
#define NSER_PFHMC_SDDATALOW_PMSDDATALOW_S 12
#define NSER_PFHMC_SDDATALOW_PMSDDATALOW GENMASK(31, 12)
#define NSER_PFHMC_SDCMD_PMSDWR_S 31
#define NSER_PFHMC_SDCMD_PMSDWR BIT(31)
#define NSER_PFHMC_SDCMD_PMSDPARTSEL_S 15
#define NSER_PFHMC_SDCMD_PMSDPARTSEL BIT(15)

#define NSER_PFST_PEC_INIT_DN_INDEX_S 30
#define NSER_PFST_PEC_INIT_DN_INDEX GENMASK(31, 30)

#define NSER_INVALID_CQ_IDX 0xffffffff
#define NSER_MAX_VSI 256

enum nser_dyn_idx_t {
	NSER_IDX_ITR0 = 0,
	NSER_IDX_ITR1 = 1,
	NSER_IDX_ITR2 = 2,
	NSER_IDX_NOITR = 3,
};

enum nser_registers {
	NSER_CCQPLOW,
	NSER_CCQPHIGH,
	NSER_CQPERRCODES,
	NSER_CCQPSTATUS,
	NSER_IPCFG,
	NSER_CQPDB,
	NSER_CQPTAIL,
	NSER_CQARM,
	NSER_CQACK,
	NSER_AEQALLOC,
	NSER_WQEALLOC,
	NSER_GLINT_DYN_CTL,
	NSER_MRTEIDXMASK,
	NSER_CQEDROPCNT,
	NSER_CEQEDROPCNT,
	NSER_AEQEDROPCNT,
	NSER_GLPE_PECSTATUS,
	NSER_DB_ADDR_OFFSET,
	NSER_GLPE_CRITERR,
	NSER_MAX_REGS, /* Must be last entry */
};

enum nser_shifts {
	NSER_CCQPSTATUS_CCQP_DONE_S,
	NSER_CCQPSTATUS_CCQP_ERR_S,
	NSER_CQPSQ_STAG_PDID_S,
	NSER_CQPSQ_CQ_CEQID_S,
	NSER_CQPSQ_CQ_CQID_S,
	NSER_COMMIT_FPM_CQCNT_S,
	NSER_CQPSQ_UPESD_HMCFNID_S,
	NSER_MAX_SHIFTS,
};

enum nser_masks {
	NSER_CCQPSTATUS_CCQP_DONE_M,
	NSER_CCQPSTATUS_CCQP_ERR_M,
	NSER_CQPSQ_STAG_PDID_M,
	NSER_CQPSQ_CQ_CEQID_M,
	NSER_CQPSQ_CQ_CQID_M,
	NSER_COMMIT_FPM_CQCNT_M,
	NSER_CQPSQ_UPESD_HMCFNID_M,
	NSER_MAX_MASKS, /* Must be last entry */
};

#define NSER_MAX_MGS_PER_CTX	8

struct nser_mcast_grp_ctx_entry_info {
	u32 qp_id;
	bool valid_entry;
	u16 dest_port;
	u32 use_cnt;
};

struct nser_mcast_grp_info {
	u8 dest_mac_addr[ETH_ALEN];
	u16 vlan_id;
	u8 hmc_fcn_id;
	bool ipv4_valid:1;
	bool vlan_valid:1;
	u16 mg_id;
	u32 no_of_mgs;
	u32 dest_ip_addr[4];
	u16 qs_handle;
	struct nser_dma_mem dma_mem_mc;
	struct nser_mcast_grp_ctx_entry_info mg_ctx_info[NSER_MAX_MGS_PER_CTX];
};

struct nser_uk_attrs {
	u64 feature_flags;
	u32 max_hw_wq_frags;
	u32 max_hw_read_sges;
	u32 max_hw_inline;
	u32 max_hw_rq_quanta;
	u32 max_hw_wq_quanta;
	u32 min_hw_cq_size;
	u32 max_hw_cq_size;
	u16 max_hw_sq_chunk;
	u16 min_hw_wq_size;
	u8 hw_rev;
};

struct nser_hw_attrs {
	struct nser_uk_attrs uk_attrs;
	u64 max_hw_outbound_msg_size;
	u64 max_hw_inbound_msg_size;
	u64 max_mr_size;
	u32 min_hw_qp_id;
	u32 min_hw_aeq_size;
	u32 max_hw_aeq_size;
	u32 min_hw_ceq_size;
	u32 max_hw_ceq_size;
	u32 max_hw_device_pages;
	//u32 max_hw_vf_fpm_id;
	//u32 first_hw_vf_fpm_id;
	u32 max_hw_ird;
	u32 max_hw_ord;
	u32 max_hw_wqes;
	u32 max_hw_pds;
	u32 max_hw_ena_vf_count;
	u32 max_qp_wr;
	u32 max_pe_ready_count;
	u32 max_done_count;
	u32 max_sleep_count;
	u32 max_cqp_compl_wait_time_ms;
	u16 max_stat_inst;
	u16 max_stat_idx;
	u64 page_size_cap;
};

void nserdma_init_hw(struct nser_sc_dev *dev);
void nser_check_fc_for_qp(struct nser_sc_vsi *vsi, struct nser_sc_qp *sc_qp);
#endif /* NSER_H*/
