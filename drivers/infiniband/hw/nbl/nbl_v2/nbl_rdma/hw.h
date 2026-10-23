/* SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB */
/* Copyright (c) 2021, NEBULARMATRIX */

#ifndef NBL_IB_HW_H
#define NBL_IB_HW_H

#include "regs_v2/nbl_reg_base.h"
#include "regs_v2/nbl_reg_cqpp.h"
#include "regs_v2/nbl_reg_ceaq.h"
#include "regs_v2/nbl_reg_cc.h"
#include "regs_v2/nbl_reg_cqcc.h"
#include "regs_v2/nbl_reg_dipro.h"
#include "regs_v2/nbl_reg_dsch.h"
#include "regs_v2/nbl_reg_eth.h"
#include "regs_v2/nbl_reg_hdma.h"
#include "regs_v2/nbl_reg_pcompleter.h"
#include "regs_v2/nbl_reg_iorqec.h"
#include "regs_v2/nbl_reg_mrtc.h"
#include "regs_v2/nbl_reg_padapt.h"
#include "regs_v2/nbl_reg_pdc.h"
#include "regs_v2/nbl_reg_pblc.h"
#include "regs_v2/nbl_reg_qm.h"
#include "regs_v2/nbl_reg_qpcc.h"
#include "regs_v2/nbl_reg_raqec.h"
#include "regs_v2/nbl_reg_raqp.h"
#include "regs_v2/nbl_reg_rdma_top.h"
#include "regs_v2/nbl_reg_top.h"
#include "regs_v2/nbl_reg_top_ctrl.h"
#include "regs_v2/nbl_reg_ubm.h"
#include "regs_v2/nbl_reg_uipro.h"
#include "regs_v2/nbl_reg_upa.h"
#include "regs_v2/nbl_reg_ustore.h"
#include "regs_v2/nbl_reg_rxp.h"
#include "regs_v2/nbl_reg_shaping.h"
#include "regs_v2/nbl_reg_sqrqec.h"
#include "regs_v2/nbl_reg_srqc.h"
#include "regs_v2/nbl_reg_stat.h"
#include "regs_v2/nbl_reg_store.h"
#include "regs_v2/nbl_reg_txp.h"
#include "regs_v2/nbl_reg_txm.h"
#include "regs_v2/nbl_reg_txmr.h"
#include "regs_v2/nbl_reg_tqp.h"
#include "regs_v2/nbl_reg_unaqc.h"
#include "product.h"

#define NBL_CQPP_READY_DELAY_ONCE 1000 /* 1000ms for 1second */
#define NBL_CQPP_READY_COUNT 10 /* wait for cqpp ready for 10 second */

#define NBL_MSIX_COUNT_MIN 3 /* AEQ use msix 0, CEQ use other msix*/

/* rnic400 set notify */
#define NBL_RDMA_PF0_BAR_ADDR_REG 0xc8008
#define NBL_RDMA_PF1_BAR_ADDR_REG 0xc8028
#define NBL_RDMA_PF2_BAR_ADDR_REG 0xc8030
#define NBL_RDMA_PF3_BAR_ADDR_REG 0xc8038
#define NBL_RDMA_BAR_ADDR_VALUE 0x8ff80000
#define NBL_RDMA_BAR_ADDR_INVALID_VALUE 0x0f000000
#define NBL_RDMA_NORMAL_NOTF_WIDTH 0x40000 /* notify begin to dwqe */

/* ECPU mode:
 * BAR0 is real HW(256MB), notify begin at 0x0100b200 offset from BAR0,
 * and hw addr we got is BAR0 addr.
 * HOST mode:
 * BAR0 is emulate by software(8K), notify begin at 0x00001000(4k) from BAR0,
 * and hw addr we got is 0x00001000(4k) from BAR0 (because rdma use 4k~8k-1).
 */
#define NBL_ECPU_BAR0_HWADDR_OFFSET 0x00000000 /* ECPU offset from BAR0 to hw addr */
#define NBL_ECPU_NOTIFY_OFFSET_v3 0x0ff80000 /* ECPU offset from hw addr to notify for df200 */

#define NBL_HOST_BAR0_HWADDR_OFFSET 0x00080000 /* HOST offset from BAR0 to hw addr */
#define NBL_HOST_SNIC_BAR0_OFFSET 0x00000000
#define NBL_HOST_NOTIFY_OFFSET 0x00000000 /* HOST notify reg offset from hw addr */
#define NBL_HOST_SNIC_RDMA_NOTIFY_OFFSET 0x00002000
#define NBL_HOST_SNIC_RDMA_PF_NOTIFY 0x01F80000
#define NBL_INVALID_OFFSET 0xffffffff
#define NBL_HOST_RNIC_RDMA_NOFITY_OFFSET NBL_ECPU_NOTIFY_OFFSET_v3

#define VF_RDMA_BAR_SIZE (120 * 1024)
#define RDMA_NORMAL_NOTIFY_SIZE SZ_4K
#define VF_RDMA_START_OFFSET SZ_8K

#define NBL_REG_CQP_PI 0x00000000 /* CQP PI reg, 64bit */
#define NBL_REG_SQ_DB 0x00000008 /* SQ doorbell reg, 64bit */
#define NBL_REG_ARM_CQ 0x00000010 /* CQ ARM reg, 64bit */
#define NBL_REG_CEQ0_CI 0x00000018 /* CEQ0 CI, 64bit */
#define NBL_REG_CEQ1_CI 0x00000020 /* CEQ0 CI, 64bit */
#define NBL_REG_AEQ_CI 0x00000028 /* AEQ CI, 64bit */
#define NBL_REG_RQ_DB 0x00000030 /* RQ doorbell reg, 64bit */
#define NBL_REG_SRQ_DB0 0x00000038 /* SRQ doorbell 0 reg, 64bit */
#define NBL_REG_SRQ_DB1 0x00000040 /* SRQ doorbell 1 reg, 64bit */

#define NBL_REG_NOTIFY_OFFSET 0 /* dummy offset */
#define NBL_REG_DWQE_OFFSET 0 /* dummy offset */

#define NBL_REG_ARM_CQ_REG0_FIFO_CNT GENMASK_ULL(10, 0)  /* arm cq fifo cnt */
/* CEAQ REG */
#define NBL_REG_ARM_CQ_REG1_ARM_NEXT_SE BIT_ULL(35) /* arm cq next se */
#define NBL_REG_ARM_CQ_REG1_ARM_CQN GENMASK_ULL(34, 16)  /* arm cqn */
#define NBL_REG_ARM_CQ_REG0_ARM_CQ_CI_PHASE BIT_ULL(15) /* arm cq ci phase */
#define NBL_REG_ARM_CQ_REG0_ARM_CQ_CI GENMASK_ULL(14, 0)  /* arm cq ci */

#define NBL_REG_ARM_CQ_V2_SEQ_NUM GENMASK_ULL(55, 48)
#define NBL_REG_ARM_CQ_V2_REG1_ARM_CQN GENMASK_ULL(42, 19)  /* arm cqn */
#define NBL_REG_ARM_CQ_V2_REG1_SW_SEL_CNT GENMASK_ULL(18, 17)
#define NBL_REG_ARM_CQ_V2_REG1_ARM_NEXT BIT_ULL(16) /* arm cq next */
#define NBL_REG_ARM_CQ_V2_REG0_ARM_CQ_CI_PHASE BIT_ULL(15) /* arm cq ci phase */
#define NBL_REG_ARM_CQ_V2_REG0_ARM_CQ_CI GENMASK_ULL(14, 0)  /* arm cq ci */

/* DF200 uipro dipro */
#define NBL_ETH_MAX_V3 2

/* CEAQ NOTIFY */
#define NBL_CEQ_NOTIFY_CEQN_BIT 18
#define NBL_CEAQ_NOTIFY_CI_PHASH_BIT 17
#define NBL_CEAQ_NOTIFY_CI_MASK 0x1FFFF

#define NBL_SAL(m, s)			((m) << (s))

/* HW msix related */
#define NBL_ECPU_HW_MSIX_ID_OFFSET 1536

/* padpt base */
#define PADAPT_HOST_BASE			(0x0000000000f4c000)
#define PADAPT_ECPU_BASE			(0x00840000)

/* msix_table */
#define MSIX_TABLE_BASE(host_id)		((((host_id) == HOST_ID_TYPE_ECPU) ?\
			PADAPT_ECPU_BASE : PADAPT_HOST_BASE) + \
			NBL_PADAPT_IRQ_KERNEL_CTL_TBL_OFF)

#define IRQ_KERNEL_CTL(host_id, _i) \
	(MSIX_TABLE_BASE((host_id)) + NBL_PADAPT_MSIX_CTRL_MASK_OFF + \
	 (_i) * NBL_PADAPT_MSIX_CTRL_TBL_STRIDE)

#define PADPT_MSIX_INFO_TBL(msix_idx, hw_ver) \
	((hw_ver) == NBL_VER_4 ? \
	NBL_PADAPT_MSIX_INFO_TBL_ADDR_ALT(NBL_REG_PADPT_BASE_V4, (msix_idx)) : \
	NBL_PADAPT_MSIX_INFO_TBL_ADDR_ALT(PADAPT_ECPU_BASE, (msix_idx)))

#define NBL_MSIX_CTRL_TBL(t)	\
	NBL_PADAPT_MSIX_CTRL_TBL_ADDR(NBL_REG_PADPT_BASE_V4, (t))
/* HW msix related END */

/* PADAPT Default Reg Value */
#define NBL_PADPT_CFG_AGE_TIME_DEFAULT 0x806DDD00 /* 16ms 450M */
#define NBL_PADPT_CFG_FC_UP_8BTAG_TH_VAL 0xE0
#define NBL_PADPT_CFG_FC_UP_10BTAG_TH_VAL 0x2E0

#define NBL_DELAY_MIN_TIME_FOR_REGS 100 /* 100us for palladium,3us for s2c */
#define NBL_DELAY_MAX_TIME_FOR_REGS 200 /* 200us for palladium,5us for s2c */

#define NBL_RF_TO_HW_VER(rf) ((rf)->sc_dev.hw_attrs.uk_attrs.hw_rev)
#define NBL_SCDEV_TO_HW_VER(sc_dev) ((sc_dev)->hw_attrs.uk_attrs.hw_rev)

#define NBL_DEBUGFS_DUMP_SQE_COMMAND_QPN_MASK 0xFFFF
#define NBL_DEBUGFS_DUMP_SQE_COMMAND_PI_SHIFT 16
#define NBL_SQWQE_BLOCK_SHIFT 6
#define NBL_RQWQE_BLOCK_SHIFT 6
#define NBL_LEVEL1_PAGE_ADDR_SIZE 8
#define NBL_LEVEL1_PAGE_ADDR_MASK 0xFFFFFFFFFFFFFFFE

struct nbl_ctx_hmc_base_info {
	void *va; /* HMC page base va */
	dma_addr_t pa; /* HMC page base pa */
	u32 ctx_size; /* ctx size OR shadow size */
	u32 shadow_offset; /* shadow offset from page 4K OR 2M */
	u32 shadow_size; /* size of shadow area */
	u32 page_size; /* 4096(4K) or 2097152(2M), from HMC */
};

struct nbl_hw;
struct nbl_dsch_layout;
struct nbl_hw_rdma_ops {
	void (*set_hw_sd_range)(struct nbl_hw *hw, u16 function_id,
				u32 sd_start, u32 sd_cnt, bool valid);
	void (*set_hw_vf_enable)(struct nbl_hw *hw, u16 function_id, u8 enable);
	void (*set_hw_ecpu_notify)(struct nbl_hw *hw, u16 function_id, u64 bar0_addr, u8 enable);
	void (*set_hw_cqp_reg)(struct nbl_hw *hw, u16 function_id, u64 cqp_ba,
			       u32 cqp_len, u8 enable);
	void (*set_hw_vfid_vsi_map)(struct nbl_hw *hw, u16 function_id, u16 vsi_id, bool enable);
	void (*set_hw_dsch_init)(struct nbl_hw *hw, u16 function_id, u16 dport_id,
				 u32 host_id, bool valid,
				 const struct nbl_dsch_layout *layout);
	void (*set_hw_dsch_vf2vsi)(struct nbl_hw *hw, u16 function_id, u16 vsi_id, bool valid);
	void (*update_hw_dsch_dport_id_direct)(struct nbl_hw *hw, u16 function_id,
					       u32 host_id, u16 dport_id, u8 vld);
	void (*set_hw_vsi_port_tbl)(struct nbl_hw *hw, u16 vsi_id, u16 function_id, bool enable);
	void (*set_hw_bdf_tbl)(struct nbl_hw *hw, bool host_en, u16 function_id, u16 bdf_num);
	void (*set_hw_pf_tbl)(struct nbl_hw *hw, u16 function_id, u16 pf_id);
	void (*set_src_addr_info)(struct nbl_hw *hw, const u8 *smac, const u8 *sip,
				  u16 src_addr_index, u8 seq_num);
	int (*get_hw_inst_id)(struct nbl_hw *hw, u8 inst_type, u16 *inst_id);
	int (*put_hw_inst_id)(struct nbl_hw *hw, u8 inst_type, u16 inst_id);
	void (*get_hw_stat_status)(struct nbl_hw *hw, u32 *status);
	void (*get_hw_stat)(struct nbl_hw *hw, u32 op_info, u32 pa_l, u32 pa_h, u16 func_id);
	void (*set_hw_stat)(struct nbl_hw *hw, u32 op_info);
	void (*enable_errcode_hw_stat)(struct nbl_hw *hw, u32 enable);
	void (*get_hw_abnormal_evt)(struct nbl_hw *hw, u32 rdma_top_offset);
	int (*set_hw_cc_reg)(struct nbl_hw *hw, u32 offset, u32 var);
	void (*set_hw_net_tc_tbl)(struct nbl_hw *hw);
	u32 (*get_hw_global_cfg_flag)(struct nbl_hw *hw);
	void (*set_hw_global_cfg)(struct nbl_hw *hw, u8 max_function_id, bool valid);
	void (*set_hw_shaping_dpt)(struct nbl_hw *hw, u16 shaping_id,
				   bool valid, bool is_lag, u8 pf_count);
};

struct nbl_register_layout {
	u32 rdma_top_base;
	u32 cqpp_base;
	u32 hdma_base;
	u32 txp_base;
	u32 rxp_base;
	u32 txmr_base;
	u32 txm_base;
	u32 ceaq_base;
	u32 stat_base;
	u32 dsch_base;
	u32 shaping_base;
	u32 host_pcompleter_base;
	u32 qm_base;
	u32 qpcc_base;
	u32 cqcc_base;
	u32 mrtc_base;
	u32 pblc_base;
	u32 sqrqec_base;
	u32 unaqc_base;
	u32 srqc_base;
	u32 pdc_base;
	u32 iorqec_base;
	u32 raqec_base;
	u32 cc_base;
	u32 tqp_base;
	u32 raqp_base;
	u32 uepro_base;
	u32 dipro_base;
	u32 depro_base;
	u32 ddmux_base;
};

extern const struct nbl_register_layout rdma_base_v2;
extern const struct nbl_register_layout rdma_base_v3;
extern const struct nbl_register_layout rdma_base_v4;
extern const struct nbl_register_layout rdma_base_v5;

struct nbl_hw {
	struct device *device;
	bool jmp_h48zero_addr; /* true: check high 48bit zero and jump */
	u8 __iomem *hw_addr;
	u8 __iomem *bar4_addr;
	u8 __iomem *notify_addr;
	struct nbl_hmc_info hmc;
	struct  nbl_hw_rdma_ops *hw_ops;
	const struct nbl_register_layout *reg_base;
	const u64 *effective_caps;
};

enum nbl_vers {
	NBL_VER_DF50, /* DF50, must be first */
	NBL_VER_1, /* ASIC V1R1 leonis */
	NBL_VER_2, /* ASIC V2R1 draco */
	NBL_VER_3, /* DF200 */
	NBL_VER_4, /* RNIC400 */
	NBL_VER_5, /* Orion */
	NBL_VER_MAX,
};

struct nbl_cache_key {
	u8 offset;
	u8 mask;
};

struct nbl_uk_attrs {
	u64 feature_flags;
	u32 max_hw_wq_sges;
	u32 max_hw_read_sges;
	u32 max_hw_inline;
	u32 max_hw_ud_inline;
	u32 max_hw_rq_quanta;
	u32 max_hw_wq_quanta;
	u32 min_hw_cq_size;
	u32 max_hw_cq_size;
	u16 max_hw_sq_chunk;
	u32 max_hw_srq_wr;
	u8 hw_rev;
	u8 reserved;
	u32 rsv;
};

struct nbl_hw_attrs {
	struct nbl_uk_attrs uk_attrs;
	u64 max_hw_outbound_msg_size;
	u64 max_hw_inbound_msg_size;
	u32 min_hw_aeqe_count;
	u32 max_hw_aeqe_count;
	u32 min_hw_ceqe_count;
	u32 max_hw_ceqe_count;
	u64 max_mr_size;
	u32 max_qp_rd_atom; /*device max send read/atomic ost */
	u32 max_qp_dest_rd_atom; /*device max recv read/atomic ost */
	u32 max_qp_wr;
	u32 max_hw_pds;
	u32 max_hw_ahs;
};

#define NBL_RDMA_MSIX 3
struct get_dpu_global_msix_idx_req {
	u16 function_id;
	u16 rsv;
};

static inline bool nbl_hw_cap_enabled(const struct nbl_hw *hw,
			      enum nbl_product_cap cap)
{
	return hw->effective_caps && (*hw->effective_caps & cap);
}

static inline void wr32(struct nbl_hw *hw, u64 reg, u32 value)
{
	if (nbl_hw_cap_enabled(hw, NBL_PRODUCT_CAP_BAR4_NOTIFY))
		writel((value), ((hw)->bar4_addr + (reg)));
	else
		writel((value), ((hw)->hw_addr + (reg)));
}

#define wr32_for_each(hw, reg, value, size) \
	{ \
		int __n; \
		for (__n = 0; __n < (size); __n += 4) \
			wr32((hw), (reg) + __n, (value)[__n / 4]); \
	}

static inline __maybe_unused u32 rd32(struct nbl_hw *hw, u64 reg)
{
	if (nbl_hw_cap_enabled(hw, NBL_PRODUCT_CAP_BAR4_NOTIFY))
		return readl(hw->bar4_addr + (reg));
	else
		return readl(hw->hw_addr + (reg));
}

static inline __maybe_unused void nbl_hw_read_regs(struct nbl_hw *hw, u64 reg,
						   u8 *data, u32 len)
{
	u32 size = len / 4;
	u32 i = 0;

	if (len % 4)
		return;

	for (i = 0; i < size; i++)
		*(u32 *)(data + i * sizeof(u32)) = rd32(hw, reg + i * sizeof(u32));
}

#define NBL_REG_RDMA_TOP_BASE(hw) ((hw)->reg_base->rdma_top_base)
#define NBL_REG_CQPP_BASE(hw) ((hw)->reg_base->cqpp_base)
#define NBL_REG_HDMA_BASE(hw) ((hw)->reg_base->hdma_base)
#define NBL_REG_TXP_BASE(hw)  ((hw)->reg_base->txp_base)
#define NBL_REG_RXP_BASE(hw)  ((hw)->reg_base->rxp_base)
#define NBL_REG_TXMR_BASE(hw) ((hw)->reg_base->txmr_base)
#define NBL_REG_TXM_BASE(hw)  ((hw)->reg_base->txm_base)
#define NBL_REG_CEAQ_BASE(hw) ((hw)->reg_base->ceaq_base)
#define NBL_REG_STAT_BASE(hw) ((hw)->reg_base->stat_base)
#define NBL_REG_DSCH_BASE(hw) ((hw)->reg_base->dsch_base)
#define NBL_REG_SHAPING_BASE(hw) ((hw)->reg_base->shaping_base)
#define NBL_REG_HOST_PCOMPLETER_BASE(hw) ((hw)->reg_base->host_pcompleter_base)
#define NBL_REG_QM_BASE(hw) ((hw)->reg_base->qm_base)
#define NBL_REG_QPCC_BASE(hw) ((hw)->reg_base->qpcc_base)
#define NBL_REG_CQCC_BASE(hw) ((hw)->reg_base->cqcc_base)
#define NBL_REG_MRTC_BASE(hw) ((hw)->reg_base->mrtc_base)
#define NBL_REG_PBLC_BASE(hw) ((hw)->reg_base->pblc_base)
#define NBL_REG_SQRQEC_BASE(hw) ((hw)->reg_base->sqrqec_base)
#define NBL_REG_UNAQC_BASE(hw) ((hw)->reg_base->unaqc_base)
#define NBL_REG_SRQC_BASE(hw) ((hw)->reg_base->srqc_base)
#define NBL_REG_PDC_BASE(hw) ((hw)->reg_base->pdc_base)
#define NBL_REG_IORQEC_BASE(hw) ((hw)->reg_base->iorqec_base)
#define NBL_REG_RAQEC_BASE(hw) ((hw)->reg_base->raqec_base)
#define NBL_REG_CC_BASE(hw) ((hw)->reg_base->cc_base)
#define NBL_REG_TQP_BASE(hw) ((hw)->reg_base->tqp_base)
#define NBL_REG_RAQP_BASE(hw) ((hw)->reg_base->raqp_base)
#define NBL_REG_UEPRO_BASE(hw) ((hw)->reg_base->uepro_base)
#define NBL_REG_DIPRO_BASE(hw) ((hw)->reg_base->dipro_base)
#define NBL_REG_DEPRO_BASE(hw) ((hw)->reg_base->depro_base)
#define NBL_REG_DDMUX_BASE(hw) ((hw)->reg_base->ddmux_base)


#define RDMA_ECPU_DEVICE_TYPE 4 /* qid tale device type */
union rdma_ecpu_qid_map_tbl_reg {
	struct qid_map_tbl_key {
		u32 max_qid : 16; /* supported max queue_id for virtio dev,rdma no need */
		u32 base_qid : 16; /* rdma function_id */

		u32 rsv1 : 8;
		u32 device_type : 3;
		u32 rsv2 : 5;
		u32 notify_bar_addr_l : 16;
		u32 notify_bar_addr_h : 32;

		u32 rsv3 : 31;
		u32 valid : 1;
	} key;
#define QID_MAP_TBL_KEY_REG_DW_SIZE (sizeof(struct qid_map_tbl_key) / sizeof(u32))
	u32 data[QID_MAP_TBL_KEY_REG_DW_SIZE];
};

union df200_host_rdma_pfid_map_tbl_reg {
	struct rdma_pfid_map_tbl_key {
		u64 rsv1 : 19;
		u64 bar_addr : 29;
		u64 vfid : 6;
		u64 rsv : 10;
	} key;
#define RDMA_PFID_MAP_TBL_KEY_REG_DW_SIZE (sizeof(struct rdma_pfid_map_tbl_key) / sizeof(u32))
	u32 data[RDMA_PFID_MAP_TBL_KEY_REG_DW_SIZE];
	u64 ddata;
};

#define DF200_PCOMP_HOST_BASE (0x000C0000)
#define DF200_HOST_RDMA_PFID_MAP_TABLE(t) (DF200_PCOMP_HOST_BASE + 0x0000a000 + 8 * (t))
#define DF200_HOST_RDMA_TBL_READY  (DF200_PCOMP_HOST_BASE + 0x00008010)
#define DF200_HOST_RDMA_TBL_SEL    (DF200_PCOMP_HOST_BASE + 0x00008014)
#define DF200_HOST_BAR_ADDR_MASK (0xFFFFFFFFFFF80000)
#define DF200_HOST_PFID_MAX_TBL_ENTRY (512)

union df200_rdma_tbl_sel_reg {
	u32 data[1];
	struct {
		u32 rdma_tbl_sel : 1;
		u32 rsv : 31;
	};
};

union df200_rdma_tbl_ready_reg {
	u32 data[1];
	struct {
		u32 rdma_tbl_ready : 1;
		u32 rsv : 31;
	};
};

struct df200_rdma_host_notify {
	u32 pfid_map_tbl_sel;
	int pfid_map_tbl_entries;
	union df200_host_rdma_pfid_map_tbl_reg pfid_map_tbl[DF200_HOST_PFID_MAX_TBL_ENTRY / 2];
};

#define DF200_HOST_PFID_MASTER_TBL_BASE 0
#define DF200_HOST_PFID_SLAVE_TBL_BASE 256

#define NBL_PCOMP_ECPU_BASE 0x00100000
#define NBL_PCOMP_ECPU_QID_MAP_TABLE(vf_id) (NBL_PCOMP_ECPU_BASE + 0x00010000 + 16 * (vf_id))
#define NBL_PCOMP_RDMA_NOTIFY_OFFSET 4

#define DSCH_RDMA_MAX_RETRY_COUNT 6
#define RDMA_MIN_NET_SHAPING_ID_V2	0
#define RDMA_MIN_NET_SHAPING_ID_V3	1983
#define RDMA_MIN_NET_SHAPING_ID_V4	2
#define RDMA_MIN_GRP_SHAPING_ID_V2	0
#define RDMA_MIN_GRP_SHAPING_ID_V3	191
#define RDMA_MIN_GRP_SHAPING_ID_V4	2
struct rdma_grp_node {
	u16 count;
	unsigned long net_id_list[NBL_DSCH_NET_NODE_NUM / BITS_PER_LONG + 1];
};

#define NBL_GET_DSCH_GRPID_BY_VFID(vfid) ((vfid))

struct nbl_hw_rdma_ops *nbl_get_hw_rdma_ops(void);
u64 nbl_read_real_bar_base_addr(struct pci_dev *pdev);
#define NBL_RDMA_INIT_CFG_HPS_REG_ADDR_V3 0x001C083C
#define NBL_INTERRUPT_ECPU2HPS_REG_ADDR_V3 0x001C0050
#define NBL_RDMA_INIT_CFG_HPS_ENABLE 1
#define NBL_INTERRUPT_ECPU2HPS_DISABLE 0
#define NBL_INTERRUPT_ECPU2HPS_ENABLE 1

#define NBL_RDMA_CACHE_EN	0x01d0
#define NBL_RDMA_CACHE_TOTAL 0x01d4
#define NBL_RDMA_CACHE_MISS 0x01d8

#define NBL_HW_RDMA_MOD_NUM 31
#define RDMA_SUBMODULE_BASE_SHIFT 16

#define NBL_TXP_CELL_NUM_CFG_DFT_V4 0

#define NBL_DPA_RDMA_DPORT_VLD BIT(16)
#define NBL_DPA_RDMA_DPORT0 0x0540
#define NBL_DPA_RDMA_DPORT1 0x0544
#define NBL_DPA_RDMA_DPORT2 0x0548

#define NBL_DSTORE_CFG_BG_TH_DFT_V4 0x0E000E00
#define NBL_DSTORE_CFG_BG_TH 0x0110

struct nbl_hw_error_code {
	bool drop;
	bool normal_cqe;   /* send normal cqe */
	bool abnormal_cqe; /* send error cqe */
	bool ae;           /* send ae */
	u16 err_code;
};

#define NBL_RDMA_SYS_CLK_RNIC 400 /* rnic400 defaut rdma freq MHz */
#define NBL_RDMA_MAX_FUNCTION_ID(hw_ver) (((hw_ver) == NBL_VER_2) ? 63 : 1)
#define NBL_REG_TXP_RAQE_CAP 0x81e

/* flush reg */
#define NBL_REG_ARM_CQ_REG1_FLUSH_FLAG BIT_ULL(63)
#define NBL_REG_RQ_DB_REG0_FLUSH_FLAG BIT_ULL(63)
#define NBL_REG_RQ_DB_REG0_FLUSH_PFID GENMASK_ULL(61, 60)
#define CHECK_FLUSH_MAX_COUNT 4

/* cqp max wait time = 5 x 200ms */
#define NBL_CQP_MAX_WAIT_TIME 5
#define NBL_CQP_WAIT_PERIOD 200

void nbl_rdma_set_txm_sq_raq_separate(struct nbl_hw *hw, bool enable);
int df200_host_get_hw_func_id(struct nbl_hw *hw, u16 *inst_id);
void df200_host_put_hw_func_id(struct nbl_hw *hw, u16 inst_id);
#endif /* NBL_IB_HW_H */
