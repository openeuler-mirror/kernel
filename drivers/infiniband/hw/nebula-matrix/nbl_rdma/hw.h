/* SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB */
/* Copyright (c) 2021, NEBULARMATRIX */

#ifndef NBL_IB_HW_H
#define NBL_IB_HW_H

#define NBL_CQPP_READY_DELAY_ONCE 1000 /* 1000ms for 1second */
#define NBL_CQPP_READY_COUNT 10 /* wait for cqpp ready for 10 second */

#define NBL_MSIX_COUNT_MIN 3 /* AEQ use msix 0, CEQ use other msix*/

/* ECPU mode:
 * BAR0 is real HW(256MB), notify begin at 0x0100b200 offset from BAR0,
 * and hw addr we got is BAR0 addr.
 * HOST mode:
 * BAR0 is emulate by software(8K), notify begin at 0x00001000(4k) from BAR0,
 * and hw addr we got is 0x00001000(4k) from BAR0 (because rdma use 4k~8k-1).
 */
#define NBL_ECPU_BAR0_HWADDR_OFFSET 0x00000000 /* ECPU offset from BAR0 to hw addr */
#define NBL_ECPU_NOTIFY_OFFSET 0x03ffe000 /* ECPU offset from hw addr to notify */

#define NBL_HOST_BAR0_HWADDR_OFFSET 0x00002000 /* HOST offset from BAR0 to hw addr */
#define NBL_HOST_SNIC_BAR0_OFFSET 0x00000000
#define NBL_HOST_NOTIFY_OFFSET 0x00000000 /* HOST notify reg offset from hw addr */
#define NBL_HOST_SNIC_RDMA_NOTIFY_OFFSET 0x00002000
#define NBL_HOST_SNIC_AF_RDMA_NOTIFY_OFFSET 0x03FFE000
#define NBL_HOST_SNIC_AF_NOTIFY_OFFSET 0x03FFC000
#define NBL_INVALID_OFFSET 0xffffffff

#define NBL_NOTIFY_AREA_WIDTH 8192 /* 4KB SQ DB and 4KB DWQE area */

#define NBL_REG_CQP_PI 0x00000000 /* CQP PI reg, 64bit */
#define NBL_REG_SQ_DB 0x00000008 /* SQ doorbell reg, 64bit */
#define NBL_REG_ARM_CQ 0x00000010 /* CQ ARM reg, 64bit */
#define NBL_REG_CEQ0_CI 0x00000018 /* CEQ0 CI, 64bit */
#define NBL_REG_CEQ1_CI 0x00000020 /* CEQ0 CI, 64bit */
#define NBL_REG_AEQ_CI 0x00000028 /* AEQ CI, 64bit */
#define NBL_REG_RQ_DB 0x00000030 /* RQ doorbell reg, 64bit */

#define NBL_REG_NOTIFY_OFFSET 0 /* dummy offset */
#define NBL_REG_DWQE_OFFSET 0 /* dummy offset */

/* CQPP REG */
#define NBL_REG_CQPP_INFO_TABLE_RAM_PI_ODD BIT_ULL(5)
#define NBL_REG_CQPP_INFO_TABLE_RAM_PI GENMASK_ULL(4, 0)

#define NBL_REG_ARM_CQ_REG0_FIFO_CNT GENMASK_ULL(10, 0)  /* arm cq fifo cnt */
/* CEAQ REG */
#define NBL_REG_ARM_CQ_REG1_ARM_NEXT_SE BIT_ULL(35) /* arm cq next se */
#define NBL_REG_ARM_CQ_REG1_ARM_CQN GENMASK_ULL(34, 16)  /* arm cqn */
#define NBL_REG_ARM_CQ_REG0_ARM_CQ_CI_PHASE BIT_ULL(15) /* arm cq ci phase */
#define NBL_REG_ARM_CQ_REG0_ARM_CQ_CI GENMASK_ULL(14, 0)  /* arm cq ci */

/* DSCH REG*/
#define NBL_REG_DSCH_BASE_V1 0x00404000
#define NBL_REG_DSCH_CSCH_QLEN_TH (NBL_REG_DSCH_BASE_V1 + 0x124)
#define NBL_REG_DSCH_POLL_WGT (NBL_REG_DSCH_BASE_V1 + 0x128)
#define NBL_REG_DSCH_DB_TO_CSCH_EN (NBL_REG_DSCH_BASE_V1 + 0x144)
#define NBL_REG_DSCH_SQ_PRI_MAP_CFG (NBL_REG_DSCH_BASE_V1 + 0x150)
#define NBL_REG_DSCH_RAQ_PRI_MAP_CFG (NBL_REG_DSCH_BASE_V1 + 0x154)
#define NBL_REG_DSCH_PRI03_MAP_CFG (NBL_REG_DSCH_BASE_V1 + 0x158)
#define NBL_REG_DSCH_PRI47_MAP_CFG (NBL_REG_DSCH_BASE_V1 + 0x15C)
#define NBL_REG_DSCH_IMAP_CFG (NBL_REG_DSCH_BASE_V1 + 0x160)
#define NBL_REG_DSCH_SW_DB_IN_CSCH_TH (NBL_REG_DSCH_BASE_V1 + 0x188)
#define NBL_REG_DSCH_TC_WGT_CFG (NBL_REG_DSCH_BASE_V1 + 0x00088000)
#define NBL_REG_DSCH_SPWRR_CFG (NBL_REG_DSCH_BASE_V1 + 0x8C000)
#define NBL_REG_DSCH_DPT_PFC_MAP_RDMA (NBL_REG_DSCH_BASE_V1 + 0x1F4)
#define NBL_REG_DSCH_TC_WGT_CFG_TBL(vf_id, tc)                                 \
	(NBL_REG_DSCH_TC_WGT_CFG + 8 * (vf_id) + 4 * ((tc) / 4))

/* UPA REG */
#define NBL_REG_UPA_BASE_V1 0x0008C000
#define NBL_REG_UPA_PRI_SEL_CONF(dport_id) (NBL_REG_UPA_BASE_V1 + 0x230 + 4 * (dport_id))
#define NBL_REG_UPA_PRI_CONF_TABLE(dport_id) (NBL_REG_UPA_BASE_V1 + 0x2000 + 32 * (dport_id))

/* DQM REG */
#define NBL_REG_DQM_BASE_V1 0x00714000
#define NBL_REG_DQM_RXMAC_TX_PORT_BP_EN (NBL_REG_DQM_BASE_V1 + 0x660)
#define NBL_REG_DQM_RXMAC_TX_COS_BP_EN (NBL_REG_DQM_BASE_V1 + 0x664)

/* UQM REG */
#define NBL_REG_UQM_BASE_V1 0x00114000
#define NBL_REG_UQM_TX_PORT_BP_EN (NBL_REG_UQM_BASE_V1 + 0x600)
#define NBL_REG_UQM_TX_COS_BP_EN (NBL_REG_UQM_BASE_V1 + 0x604)
#define NBL_REG_UQM_RX_PORT_BP_EN (NBL_REG_UQM_BASE_V1 + 0x610)
#define NBL_REG_UQM_RX_COS_BP_EN (NBL_REG_UQM_BASE_V1 + 0x614)

/* USTORE REG */
#define NBL_REG_USTORE_BASE_V1 0x00104000
#define NBL_REG_USTORE_PORT_FC_TH(dport_id) (NBL_REG_USTORE_BASE_V1 + 0x134 + 4 * (dport_id))
#define NBL_REG_USTORE_COS_FC_TH(dport_id) (NBL_REG_USTORE_BASE_V1 + 0x200 + 32 * (dport_id))
#define NBL_REG_USTORE_PFC_MERGE (NBL_REG_USTORE_BASE_V1 + 0x0508)

/* PP0 REG */
#define NBL_REG_PP0_BASE_V1 0x00B14000
#define NBL_REG_PP0_RDMA_BYPASS (NBL_REG_PP0_BASE_V1 + 0x170)

union rdma_poll_wgt_cfg {
	u32 data[1];
	struct {
		u32 csch : 8;
		u32 sch : 8;
		u32 rnr : 8;
		u32 rto : 8;
	};
};
union rdma_tc_wgt_cfg_tbl {
	u32 data[2];
	struct {
		u32 tc0_wgt : 8;
		u32 tc1_wgt : 8;
		u32 tc2_wgt : 8;
		u32 tc3_wgt : 8;
		u32 tc4_wgt : 8;
		u32 tc5_wgt : 8;
		u32 tc6_wgt : 8;
		u32 tc7_wgt : 8;
	};
};

#define SCH_NET_TC_MAX 3

/* rdma_pri03_map_cfg and rdma_pri47_map_cfg common struct*/
union rdma_pfc_imap_cfg {
	u32 data[2];
	struct {
		u32 pri0_map : 8;
		u32 pri1_map : 8;
		u32 pri2_map : 8;
		u32 pri3_map : 8;
		u32 pri4_map : 8;
		u32 pri5_map : 8;
		u32 pri6_map : 8;
		u32 pri7_map : 8;
	};
};

union pkt_cos_map_table {
	u32 data[1];
	struct {
		u32 pri0 : 3;
		u32 rsv0 : 1;
		u32 pri1 : 3;
		u32 rsv1 : 1;
		u32 pri2 : 3;
		u32 rsv2 : 1;
		u32 pri3 : 3;
		u32 rsv3 : 1;
		u32 pri4 : 3;
		u32 rsv4 : 1;
		u32 pri5 : 3;
		u32 rsv5 : 1;
		u32 pri6 : 3;
		u32 rsv6 : 1;
		u32 pri7 : 3;
		u32 rsv7 : 1;
	};
};
/* rdma_sq_pri_map_cfg
 * rdma_raq_pri_map_cfg
 * rdma_pri_imap_cfg
 * common struct
 */
union rdma_sq_raq_pri_map_cfg {
	u32 data[1];
	struct {
		u32 pri0 : 3;
		u32 pri1 : 3;
		u32 pri2 : 3;
		u32 pri3 : 3;
		u32 pri4 : 3;
		u32 pri5 : 3;
		u32 pri6 : 3;
		u32 pri7 : 3;
		u32 rsv : 8;
	};
};

union dpt_pfc_map_rdma {
	u32 data;
	struct {
		u32 dpt0 : 4;
		u32 dpt1 : 4;
		u32 dpt2 : 4;
		u32 dpt3 : 4;
		u32 rsv : 16;
	};
};

/* upa_pri_sel_conf */
union upa_pri_sel_conf {
	u32 data[1];
	struct {
		u32 in_in_vlan : 1;
		u32 in_out_vlan : 1;
		u32 out_in_vlan : 1;
		u32 out_out_vlan : 1;
		u32 trust_vlan : 1;
		u32 pri_default : 3;
		u32 pri_disen : 1;
		u32 rsv : 23;
	};
};

/* upa_pri_conf_table */
union upa_pri_conf_table {
	u32 data[8];
	struct {
		u32 pri0 : 4;
		u32 pri1 : 4;
		u32 pri2 : 4;
		u32 pri3 : 4;
		u32 pri4 : 4;
		u32 pri5 : 4;
		u32 pri6 : 4;
		u32 pri7 : 4;
	};
};

/* dqm_rxmac_tx_port_bp_en */
union dqm_rxmac_tx_port_bp_en_table {
	u32 data[1];
	struct {
		u32 eth0 : 1;
		u32 eth1 : 1;
		u32 eth2 : 1;
		u32 eth3 : 1;
		u32 rsv : 28;
	};
};

/* dqm_rxmac_tx_cos_bp_en */
union dqm_rxmac_tx_cos_bp_en_table {
	u32 data[1];
	struct {
		u32 eth0 : 8;
		u32 eth1 : 8;
		u32 eth2 : 8;
		u32 eth3 : 8;
	};
};

/* uqm_tx_port_bp_en */
/* uqm_rx_port_bp_en */
union uqm_port_bp_en_table {
	u32 data[1];
	struct {
		u32 l4s_h : 1;
		u32 l4s_l : 1;
		u32 rdma_h : 1;
		u32 rdma_e : 1;
		u32 emp : 1;
		u32 loopback : 1;
		u32 rsv : 28;
	};
};

/* uqm_tx_cos_bp_en */
/* uqm_rx_cos_bp_en */
union uqm_cos_bp_en_table {
	u32 data[2];
	struct {
		u32 l4s_h : 8;
		u32 l4s_l : 8;
		u32 rdma_h : 8;
		u32 rdma_e : 8;
		u32 emp : 8;
		u32 loopback : 8;
		u32 rsv : 16;
	};
};

/* ustore_port_fc_th */
/* ustore_cos_fc_th */
union ustore_fc_th_table {
	u32 data[1];
	struct {
		u32 xoff_th : 12;
		u32 rsv1 : 4;
		u32 xon_th : 12;
		u32 rsv2 : 2;
		u32 fc_set : 1;
		u32 fc_en : 1;
	};
};

/* CEAQ NOTIFY */
#define NBL_CEAQ_NOTIFY_CI_PHASH_BIT 17
#define NBL_CEAQ_NOTIFY_CI_MASK 0x1FFFF

#define NBL_SAL(m, s)			((m) << (s))
/* HW msix related */
#define NBL_ECPU_HW_MSIX_ID_OFFSET 1536

/* padpt base */
#define PADAPT_HOST_BASE			(0x0000000000f4c000)
#define PADAPT_ECPU_BASE			(0x000000000104c000)

/* adpt base */
#define NBL_REG_ADPT_BASE_V1 (0x011c0000)

#define NBL_REG_ADPT_DTRANS_CNT_OUTPUT_BYTE_LOW ((NBL_REG_ADPT_BASE_V1) + 0x328)
#define NBL_REG_ADPT_DTRANS_CNT_OUTPUT_BYTE_HIGH ((NBL_REG_ADPT_BASE_V1) + 0x32c)
#define NBL_REG_ADPT_UTRANS_CNT_INPUT_BYTE_LOW ((NBL_REG_ADPT_BASE_V1) + 0x21c)
#define NBL_REG_ADPT_UTRANS_CNT_INPUT_BYTE_HIGH ((NBL_REG_ADPT_BASE_V1) + 0x220)

/* msix_table */
#define MSIX_TABLE_BASE(host_id)		(((host_id == HOST_ID_TYPE_ECPU) ?\
						PADAPT_ECPU_BASE : PADAPT_HOST_BASE) + 0x00010000)
#define IRQ_KERNEL_CTL_MASK_M			BIT(0)
#define IRQ_KERNEL_CTL(host_id, _i)		(MSIX_TABLE_BASE((host_id)) + 12 + (_i) * 16)
#define ECPU_MSIX_INFO_TBL(msix_idx) (PADAPT_ECPU_BASE + 0x10000 + 8 * (msix_idx))

#define NBL_DELAY_MIN_TIME_FOR_REGS 100 /* 100us for palladium,3us for s2c */
#define NBL_DELAY_MAX_TIME_FOR_REGS 200 /* 200us for palladium,5us for s2c */

union padapt_ecpu_msix_info {
	struct {
		u32 intrl_pnum : 16;
		u32 intrl_rate : 16;
		u32 function_id : 3;
		u32 device_id : 5;
		u32 bus_id : 8;
		u32 valid : 1;
		u32 rsv : 15;
	};
	u32 data[2];
};


struct nbl_ctx_hmc_base_info {
	void *va; /* QPC HMC page base va */
	dma_addr_t pa; /* QPC HMC page base pa */
	u32 ctx_size; /* 512 or other, now 512 */
	u32 shadow_offset; /* where shadow begin from qpc head, now 480 */
	u32 shadow_size; /* size of shadow area, now 32 */
	u32 page_size; /* 4096(4K) or 2097152(2M), from HMC */
};

struct nbl_hw {
	struct device *device;
	u8 __iomem *hw_addr;
	u8 __iomem *notify_addr;
	struct nbl_hmc_info hmc;
};

struct nbl_uk_attrs {
	u64 feature_flags;
	u32 max_hw_wq_sges; /* 1.0 version is 6 */
	u32 max_hw_read_sges; /* 1.0 version is 6 */
	u32 max_hw_inline; /* 1.0 version is 92 */
	u32 max_hw_rq_quanta; /* 1.0 version is 128 */
	u32 max_hw_wq_quanta; /* 1.0 version is 128 */
	u32 min_hw_cq_size;
	u32 max_hw_cq_size;
	u16 max_hw_sq_chunk; /* 1.0 version is 128 */
	u8 hw_rev;
	u8 reserved;
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
	u16 max_hw_sq_chunk;
	u32 max_hw_ird;
	u32 max_hw_ord;
	u32 max_qp_wr;
	u32 max_hw_pds;
	u32 max_hw_ahs;
};

struct nbl_hw_error_code {
	bool msb;
	u8 err_code;
	bool drop;
	bool normal_cqe; /* send normal cqe */
	bool abnormal_cqe; /* send error cqe */
	bool ae; /* send ae */
	bool retry;
	bool rsv[18];
};

#define NBL_RDMA_MSIX 3
struct nbl_ena_rdma_intrl_req {
	u16 msix_global_idx;
	u8 devfn;
	u8 bus;
	u8 valid;
	u8 rsv[3];
};

struct get_dpu_global_msix_idx_req {
	u16 function_id;
	u16 rsv;
};

static inline void wr32(struct nbl_hw *hw, u64 reg, u32 value)
{
	writel((value), ((hw)->hw_addr + (reg)));
}

#define wr32_for_each(hw, reg, value, size) \
	{ \
		int __n; \
		for (__n = 0; __n < (size); __n += 4) \
			wr32((hw), (reg) + __n, (value)[__n / 4]); \
	}

#endif /* NBL_IB_HW_H */
