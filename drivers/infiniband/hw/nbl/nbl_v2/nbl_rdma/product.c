// SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB
/* Copyright (c) 2026, NEBULARMATRIX */

#include <linux/kernel.h>

#include "main.h"
#include "product_internal.h"
#include "counters.h"
#include "nbl_pt_cfg.h"
#include "umr.h"

#define NBL_PRODUCT_FLAGS_MASK	(NBL_PRODUCT_F_RESV_RES | \
				 NBL_PRODUCT_F_CTRL_DEV | \
				 NBL_PRODUCT_F_INIT_SD_DIRECT | \
				 NBL_PRODUCT_F_RX_VLAN_VSI_MAP | \
				 NBL_PRODUCT_F_ABNORMAL_EVENT | \
				 NBL_PRODUCT_F_FW_VER_REG | \
				 NBL_PRODUCT_F_DIRECT_RW_REG | \
				 NBL_PRODUCT_F_CPU_FWD_DEFAULT | \
				 NBL_PRODUCT_F_LAG_MIRROR_CFG)

const struct nbl_feature_ops nbl_common_feature_ops = {};

const struct nbl_feature_ops nbl_rnic400_feature_ops = {
	.umr_resource_init = __nbl_umr_resource_init,
	.umr_resource_cleanup = __nbl_umr_resource_cleanup,
	.pt_debugfs_init = __nbl_pt_debugfs_init,
	.pt_debugfs_cleanup = __nbl_pt_debugfs_cleanup,
};

/* DF200 Host and ECPU share their statistics layout. */
static const struct nbl_stats_layout nbl_stats_df200 = {
	.group_count = NBL_STAT_GROUP_CNT_DF200,
	.entry_count = NBL_TOTAL_ENTRY_CNT_DF200,
	.opcode_count = NBL_OPCODE_CNT_DF200,
	.error_count = NBL_ERRCODE_CNT_DF200,
	.extended_opcode = true,
};

static const struct nbl_product_limits nbl_limits_df200_ecpu = {
	.max_mr_size = NBL_MAX_MR_SIZE,
	.max_total_qps = SZ_256K,
	.max_total_cqs = SZ_512K,
	.max_total_pbls = SZ_256M,
	.max_total_mrs = SZ_16M,
	.max_total_srqs = SZ_64K,
	.max_pds = NBL_MAX_PDS,
	.max_ahs = NBL_MAX_AHS,
	.max_qp_wr = NBL_MAX_QP_WR,
	.max_srq_wr = NBL_MAX_SRQ_WR,
	.max_aeq_entries = NBL_MAX_AEQ_ENTRIES,
	.max_ceq_entries = NBL_MAX_CEQ_ENTRIES,
	.min_aeq_entries = NBL_MIN_AEQ_ENTRIES,
	.min_ceq_entries = NBL_MIN_CEQ_ENTRIES,
	.min_cq_size = NBL_MIN_CQ_SIZE,
	.max_cq_size = NBL_MAX_CQ_SIZE,
	.min_ceqs = NBL_MIN_CEQ_COUNT,
	.max_ceqs = NBL_MAX_CEQ_COUNT,
	.gid_per_function = NBL_GID_FUNC_TABLE_LEN,
	.qpcc_depth = NBL_CACHE_QPCC_DEEP_V3,
	.cqcc_depth = NBL_CACHE_CQCC_DEEP_V3,
	.mrtc_depth = NBL_CACHE_MRTE_DEEP_V3,
	.srqc_depth = NBL_CACHE_SRQC_DEEP,
	.pblc_depth = NBL_CACHE_PBLE_DEEP_V3,
	.sqrqec_depth = NBL_CACHE_SQRQE_DEEP_V2,
	.irqec_depth = NBL_CACHE_IRQE_DEEP,
	.raqec_depth = NBL_CACHE_RAQE_DEEP_V2,
	.unaqec_depth = NBL_CACHE_UNAQ_DEEP,
	.pdc_depth = NBL_CACHE_PD_DEEP_V3,
	.orqec_depth = NBL_CACHE_ORQE_DEEP,
	.max_inline_data = NBL_MAX_INLINE_V2,
	.max_ud_inline_data = NBL_MAX_UD_INLINE_V2,
	.sq_ost_count = NBL_SQ_OST_CNT_V2,
	.max_wqe_quanta = NBL_MAX_WQE_QUANATA_V2,
	.max_sge = NBL_DEFAULT_MAX_SGE_V2,
	.max_read_sge = NBL_DEFAULT_MAX_SGE_V2,
	.rd_atomic_shift = 4,
	.max_rd_atomic = 32,
	.pble_count_align = PBLE_CNT_V2_ALIGN_SIZE,
};

static const struct nbl_product_limits nbl_limits_df200_host = {
	.max_mr_size = NBL_MAX_MR_SIZE,
	.max_total_qps = SZ_256K,
	.max_total_cqs = SZ_512K,
	.max_total_pbls = SZ_256M,
	.max_total_mrs = SZ_16M,
	.max_total_srqs = SZ_64K,
	.max_pds = NBL_MAX_PDS,
	.max_ahs = NBL_MAX_AHS,
	.max_qp_wr = NBL_MAX_QP_WR,
	.max_srq_wr = NBL_MAX_SRQ_WR,
	.max_aeq_entries = NBL_MAX_AEQ_ENTRIES,
	.max_ceq_entries = NBL_MAX_CEQ_ENTRIES,
	.min_aeq_entries = NBL_MIN_AEQ_ENTRIES,
	.min_ceq_entries = NBL_MIN_CEQ_ENTRIES,
	.min_cq_size = NBL_MIN_CQ_SIZE,
	.max_cq_size = NBL_MAX_CQ_SIZE,
	.min_ceqs = NBL_MIN_CEQ_COUNT,
	.max_ceqs = NBL_MAX_CEQ_COUNT,
	.gid_per_function = NBL_GID_FUNC_TABLE_LEN,
	.qpcc_depth = NBL_CACHE_QPCC_DEEP_V3,
	.cqcc_depth = NBL_CACHE_CQCC_DEEP_V3,
	.mrtc_depth = NBL_CACHE_MRTE_DEEP_V3,
	.srqc_depth = NBL_CACHE_SRQC_DEEP,
	.pblc_depth = NBL_CACHE_PBLE_DEEP_V3,
	.sqrqec_depth = NBL_CACHE_SQRQE_DEEP_V2,
	.irqec_depth = NBL_CACHE_IRQE_DEEP,
	.raqec_depth = NBL_CACHE_RAQE_DEEP_V2,
	.unaqec_depth = NBL_CACHE_UNAQ_DEEP,
	.pdc_depth = NBL_CACHE_PD_DEEP_V3,
	.orqec_depth = NBL_CACHE_ORQE_DEEP,
	.max_inline_data = NBL_MAX_INLINE_V2,
	.max_ud_inline_data = NBL_MAX_UD_INLINE_V2,
	.sq_ost_count = NBL_SQ_OST_CNT_V2,
	.max_wqe_quanta = NBL_MAX_WQE_QUANATA_V2,
	.max_sge = NBL_DEFAULT_MAX_SGE_V2,
	.max_read_sge = NBL_DEFAULT_MAX_SGE_V2,
	.rd_atomic_shift = 4,
	.max_rd_atomic = 32,
	.pble_count_align = PBLE_CNT_V2_ALIGN_SIZE,
};

/* Draco PF and VF share their statistics layout. */
static const struct nbl_stats_layout nbl_stats_draco = {
	.group_count = NBL_STAT_GROUP_CNT_ASIC_V2R1,
	.entry_count = NBL_TOTAL_ENTRY_CNT_ASIC_V2R1,
	.opcode_count = NBL_OPCODE_CNT_ASIC_V2R1,
	.error_count = NBL_ERRCODE_CNT_ASIC_V2R1,
	.extended_opcode = false,
};

static const struct nbl_product_limits nbl_limits_draco_pf = {
	.max_mr_size = NBL_MAX_MR_SIZE,
	.max_total_qps = SZ_256K,
	.max_total_cqs = SZ_512K,
	.max_total_pbls = SZ_256M,
	.max_total_mrs = SZ_16M,
	.max_total_srqs = SZ_64K,
	.max_pds = NBL_MAX_PDS,
	.max_ahs = NBL_MAX_AHS,
	.max_qp_wr = NBL_MAX_QP_WR,
	.max_srq_wr = NBL_MAX_SRQ_WR,
	.max_aeq_entries = NBL_MAX_AEQ_ENTRIES,
	.max_ceq_entries = NBL_MAX_CEQ_ENTRIES,
	.min_aeq_entries = NBL_MIN_AEQ_ENTRIES,
	.min_ceq_entries = NBL_MIN_CEQ_ENTRIES,
	.min_cq_size = NBL_MIN_CQ_SIZE,
	.max_cq_size = NBL_MAX_CQ_SIZE,
	.min_ceqs = NBL_MIN_CEQ_COUNT,
	.max_ceqs = NBL_MAX_CEQ_COUNT,
	.gid_per_function = NBL_GID_FUNC_TABLE_LEN,
	.qpcc_depth = NBL_CACHE_QPCC_DEEP_V2,
	.cqcc_depth = NBL_CACHE_CQCC_DEEP_V2,
	.mrtc_depth = NBL_CACHE_MRTE_DEEP_V2,
	.srqc_depth = NBL_CACHE_SRQC_DEEP,
	.pblc_depth = NBL_CACHE_PBLE_DEEP_V2,
	.sqrqec_depth = NBL_CACHE_SQRQE_DEEP_V2,
	.irqec_depth = NBL_CACHE_IRQE_DEEP,
	.raqec_depth = NBL_CACHE_RAQE_DEEP_V2,
	.unaqec_depth = NBL_CACHE_RAQE_DEEP_V2,
	.pdc_depth = NBL_CACHE_PD_DEEP_V2,
	.orqec_depth = NBL_CACHE_ORQE_DEEP,
	.max_inline_data = NBL_MAX_INLINE_V2,
	.max_ud_inline_data = NBL_MAX_UD_INLINE_V2,
	.sq_ost_count = NBL_SQ_OST_CNT,
	.max_wqe_quanta = NBL_MAX_WQE_QUANATA_V2,
	.max_sge = NBL_DEFAULT_MAX_SGE_V2,
	.max_read_sge = NBL_DEFAULT_MAX_SGE_V2,
	.rd_atomic_shift = 2,
	.max_rd_atomic = 32,
	.pble_count_align = PBLE_CNT_V2_ALIGN_SIZE,
};

static const struct nbl_product_limits nbl_limits_draco_vf = {
	.max_mr_size = NBL_MAX_MR_SIZE,
	.max_total_qps = SZ_256K,
	.max_total_cqs = SZ_512K,
	.max_total_pbls = SZ_256M,
	.max_total_mrs = SZ_16M,
	.max_total_srqs = SZ_64K,
	.max_pds = NBL_MAX_PDS,
	.max_ahs = NBL_MAX_AHS,
	.max_qp_wr = NBL_MAX_QP_WR,
	.max_srq_wr = NBL_MAX_SRQ_WR,
	.max_aeq_entries = NBL_MAX_AEQ_ENTRIES,
	.max_ceq_entries = NBL_MAX_CEQ_ENTRIES,
	.min_aeq_entries = NBL_MIN_AEQ_ENTRIES,
	.min_ceq_entries = NBL_MIN_CEQ_ENTRIES,
	.min_cq_size = NBL_MIN_CQ_SIZE,
	.max_cq_size = NBL_MAX_CQ_SIZE,
	.min_ceqs = NBL_MIN_CEQ_COUNT,
	.max_ceqs = NBL_MAX_CEQ_COUNT_VF,
	.gid_per_function = NBL_GID_FUNC_TABLE_LEN,
	.qpcc_depth = NBL_CACHE_QPCC_DEEP_V2,
	.cqcc_depth = NBL_CACHE_CQCC_DEEP_V2,
	.mrtc_depth = NBL_CACHE_MRTE_DEEP_V2,
	.srqc_depth = NBL_CACHE_SRQC_DEEP,
	.pblc_depth = NBL_CACHE_PBLE_DEEP_V2,
	.sqrqec_depth = NBL_CACHE_SQRQE_DEEP_V2,
	.irqec_depth = NBL_CACHE_IRQE_DEEP,
	.raqec_depth = NBL_CACHE_RAQE_DEEP_V2,
	.unaqec_depth = NBL_CACHE_RAQE_DEEP_V2,
	.pdc_depth = NBL_CACHE_PD_DEEP_V2,
	.orqec_depth = NBL_CACHE_ORQE_DEEP,
	.max_inline_data = NBL_MAX_INLINE_V2,
	.max_ud_inline_data = NBL_MAX_UD_INLINE_V2,
	.sq_ost_count = NBL_SQ_OST_CNT,
	.max_wqe_quanta = NBL_MAX_WQE_QUANATA_V2,
	.max_sge = NBL_DEFAULT_MAX_SGE_V2,
	.max_read_sge = NBL_DEFAULT_MAX_SGE_V2,
	.rd_atomic_shift = 2,
	.max_rd_atomic = 32,
	.pble_count_align = PBLE_CNT_V2_ALIGN_SIZE,
};

static const struct nbl_product_limits nbl_limits_orion_pf = {
	.max_mr_size = NBL_MAX_MR_SIZE,
	.max_total_qps = SZ_256K,
	.max_total_cqs = SZ_512K,
	.max_total_pbls = SZ_2G,
	.max_total_mrs = SZ_16M,
	.max_total_srqs = SZ_64K,
	.max_pds = NBL_MAX_PDS,
	.max_ahs = NBL_MAX_AHS,
	.max_qp_wr = NBL_MAX_QP_WR,
	.max_srq_wr = NBL_MAX_SRQ_WR,
	.max_aeq_entries = NBL_MAX_AEQ_ENTRIES,
	.max_ceq_entries = NBL_MAX_CEQ_ENTRIES,
	.min_aeq_entries = NBL_MIN_AEQ_ENTRIES,
	.min_ceq_entries = NBL_MIN_CEQ_ENTRIES,
	.min_cq_size = NBL_MIN_CQ_SIZE,
	.max_cq_size = SZ_2M,
	.min_ceqs = NBL_MIN_CEQ_COUNT,
	.max_ceqs = NBL_MAX_CEQ_COUNT,
	.gid_per_function = NBL_GID_FUNC_TABLE_LEN,
	.qpcc_depth = NBL_CACHE_QPCC_DEEP_V5,
	.cqcc_depth = NBL_CACHE_CQCC_DEEP_V4,
	.mrtc_depth = NBL_CACHE_MRTE_DEEP_V4,
	.srqc_depth = NBL_CACHE_SRQC_DEEP,
	.pblc_depth = NBL_CACHE_PBLE_DEEP_V4,
	.sqrqec_depth = NBL_CACHE_SQRQE_DEEP_V4,
	.irqec_depth = NBL_CACHE_IRQE_DEEP_V4,
	.raqec_depth = NBL_CACHE_RAQE_DEEP_V5,
	.unaqec_depth = NBL_CACHE_RAQE_DEEP_V4,
	.pdc_depth = NBL_CACHE_PD_DEEP,
	.orqec_depth = NBL_CACHE_ORQE_DEEP_V5,
	.max_inline_data = NBL_MAX_INLINE_V2,
	.max_ud_inline_data = NBL_MAX_UD_INLINE_V2,
	.sq_ost_count = NBL_SQ_OST_CNT_V2,
	.max_wqe_quanta = NBL_MAX_WQE_QUANATA_V2,
	.max_sge = NBL_DEFAULT_MAX_SGE_V2,
	.max_read_sge = NBL_DEFAULT_MAX_SGE_V2,
	.rd_atomic_shift = 8,
	.max_rd_atomic = 64,
	.pble_count_align = PBLE_CNT_V2_ALIGN_SIZE,
};

static const struct nbl_product_limits nbl_limits_orion_vf = {
	.max_mr_size = NBL_MAX_MR_SIZE,
	.max_total_qps = SZ_256K,
	.max_total_cqs = SZ_512K,
	.max_total_pbls = SZ_2G,
	.max_total_mrs = SZ_16M,
	.max_total_srqs = SZ_64K,
	.max_pds = NBL_MAX_PDS,
	.max_ahs = NBL_MAX_AHS,
	.max_qp_wr = NBL_MAX_QP_WR,
	.max_srq_wr = NBL_MAX_SRQ_WR,
	.max_aeq_entries = NBL_MAX_AEQ_ENTRIES,
	.max_ceq_entries = NBL_MAX_CEQ_ENTRIES,
	.min_aeq_entries = NBL_MIN_AEQ_ENTRIES,
	.min_ceq_entries = NBL_MIN_CEQ_ENTRIES,
	.min_cq_size = NBL_MIN_CQ_SIZE,
	.max_cq_size = SZ_2M,
	.min_ceqs = NBL_MIN_CEQ_COUNT,
	.max_ceqs = NBL_MAX_CEQ_COUNT_VF,
	.gid_per_function = NBL_GID_FUNC_TABLE_LEN,
	.qpcc_depth = NBL_CACHE_QPCC_DEEP_V5,
	.cqcc_depth = NBL_CACHE_CQCC_DEEP_V4,
	.mrtc_depth = NBL_CACHE_MRTE_DEEP_V4,
	.srqc_depth = NBL_CACHE_SRQC_DEEP,
	.pblc_depth = NBL_CACHE_PBLE_DEEP_V4,
	.sqrqec_depth = NBL_CACHE_SQRQE_DEEP_V4,
	.irqec_depth = NBL_CACHE_IRQE_DEEP_V4,
	.raqec_depth = NBL_CACHE_RAQE_DEEP_V5,
	.unaqec_depth = NBL_CACHE_RAQE_DEEP_V4,
	.pdc_depth = NBL_CACHE_PD_DEEP,
	.orqec_depth = NBL_CACHE_ORQE_DEEP_V5,
	.max_inline_data = NBL_MAX_INLINE_V2,
	.max_ud_inline_data = NBL_MAX_UD_INLINE_V2,
	.sq_ost_count = NBL_SQ_OST_CNT_V2,
	.max_wqe_quanta = NBL_MAX_WQE_QUANATA_V2,
	.max_sge = NBL_DEFAULT_MAX_SGE_V2,
	.max_read_sge = NBL_DEFAULT_MAX_SGE_V2,
	.rd_atomic_shift = 8,
	.max_rd_atomic = 64,
	.pble_count_align = PBLE_CNT_V2_ALIGN_SIZE,
};

static const struct nbl_stats_layout nbl_stats_rnic400 = {
	.group_count = NBL_STAT_GROUP_CNT_RNIC400,
	.entry_count = NBL_TOTAL_ENTRY_CNT_RNIC400,
	.opcode_count = NBL_OPCODE_CNT_RNIC400,
	.error_count = NBL_ERRCODE_CNT_RNIC400,
	.extended_opcode = true,
};

static const struct nbl_product_limits nbl_limits_rnic400_pf = {
	.max_mr_size = NBL_MAX_MR_SIZE,
	.max_total_qps = SZ_256K,
	.max_total_cqs = SZ_512K,
	.max_total_pbls = SZ_256M,
	.max_total_mrs = SZ_16M,
	.max_total_srqs = SZ_64K,
	.max_pds = NBL_MAX_PDS,
	.max_ahs = NBL_MAX_AHS,
	.max_qp_wr = NBL_MAX_QP_WR,
	.max_srq_wr = NBL_MAX_SRQ_WR,
	.max_aeq_entries = NBL_MAX_AEQ_ENTRIES,
	.max_ceq_entries = NBL_MAX_CEQ_ENTRIES,
	.min_aeq_entries = NBL_MIN_AEQ_ENTRIES,
	.min_ceq_entries = NBL_MIN_CEQ_ENTRIES,
	.min_cq_size = NBL_MIN_CQ_SIZE,
	.max_cq_size = NBL_MAX_CQ_SIZE,
	.min_ceqs = NBL_MIN_CEQ_COUNT,
	.max_ceqs = NBL_MAX_CEQ_COUNT_RNIC,
	.gid_per_function = NBL_GID_FUNC_TABLE_LEN_V4,
	.qpcc_depth = NBL_CACHE_QPCC_DEEP_V4,
	.cqcc_depth = NBL_CACHE_CQCC_DEEP_V4,
	.mrtc_depth = NBL_CACHE_MRTE_DEEP_V4,
	.srqc_depth = NBL_CACHE_SRQC_DEEP,
	.pblc_depth = NBL_CACHE_PBLE_DEEP_V4,
	.sqrqec_depth = NBL_CACHE_SQRQE_DEEP_V4,
	.irqec_depth = NBL_CACHE_IRQE_DEEP_V4,
	.raqec_depth = NBL_CACHE_RAQE_DEEP_V4,
	.unaqec_depth = NBL_CACHE_UNAQ_DEEP,
	.pdc_depth = NBL_CACHE_PD_DEEP,
	.orqec_depth = NBL_CACHE_ORQE_DEEP_V4,
	.max_inline_data = NBL_MAX_INLINE_V2,
	.max_ud_inline_data = NBL_MAX_UD_INLINE_V2,
	.sq_ost_count = NBL_SQ_OST_CNT_V2,
	.max_wqe_quanta = NBL_MAX_WQE_QUANATA_V2,
	.max_sge = NBL_DEFAULT_MAX_SGE_V2,
	.max_read_sge = NBL_DEFAULT_MAX_SGE_V2,
	.rd_atomic_shift = 6,
	.max_rd_atomic = 64,
	.pble_count_align = PBLE_CNT_V2_ALIGN_SIZE,
};

/* Keep every supported product in one table for direct, auditable lookup. */
static const struct nbl_product_desc nbl_product_descs[NBL_PRODUCT_ID_MAX] = {
	[NBL_PRODUCT_ID_DF200_ECPU] = {
		.name = "df200-ecpu",
		.id = NBL_PRODUCT_ID_DF200_ECPU,
		.hw_rev = NBL_VER_3,
		.host_id = HOST_ID_TYPE_ECPU,
		.product_type = PRODUCT_TYPE_DPU,
		.function_type = NBL_PRODUCT_FUNCTION_PF,
		.flags = NBL_PRODUCT_F_RESV_RES | NBL_PRODUCT_F_CTRL_DEV |
			 NBL_PRODUCT_F_INIT_SD_DIRECT |
			 NBL_PRODUCT_F_ABNORMAL_EVENT |
			 NBL_PRODUCT_F_FW_VER_REG |
			 NBL_PRODUCT_F_DIRECT_RW_REG |
			 NBL_PRODUCT_F_CPU_FWD_DEFAULT,
		.base_caps = NBL_PRODUCT_CAP_SRQ | NBL_PRODUCT_CAP_ATOMIC |
			     NBL_PRODUCT_CAP_MR_BRANCH |
			     NBL_PRODUCT_CAP_DSCH_DPORT_UPDATE,
		.limits = &nbl_limits_df200_ecpu,
		.regs = &rdma_base_v3,
		.dsch_layout = {
			.net_en_offset = NBL_DSCH_NET_EN_OFF_V3,
			.min_net_shaping_id = RDMA_MIN_NET_SHAPING_ID_V3,
			.min_grp_shaping_id = RDMA_MIN_GRP_SHAPING_ID_V3,
			.direct_init = true,
		},
		.stats = &nbl_stats_df200,
		.debug_layout = {
			.ext_qpc_v4 = false,
		},
		.gid_ops = &nbl_direct_gid_ops,
		.lifecycle_ops = &nbl_df200_ecpu_lifecycle_ops,
		.fun_ops = &nbl_df200_fun_ops,
		.resource_ops = &nbl_df200_resource_ops,
		.irq_ops = &nbl_df200_ecpu_irq_ops,
		.feature_ops = &nbl_common_feature_ops,
		.dump_ops = &nbl_df200_dump_ops,
		.cq_ops = &nbl_common_cq_ops,
		.qpc_ops = &nbl_df200_qpc_ops,
		.qos_ops = &nbl_df200_qos_ops,
		.congestion_ops = &nbl_df200_congestion_ops,
	},
	[NBL_PRODUCT_ID_DF200_HOST] = {
		.name = "df200-host",
		.id = NBL_PRODUCT_ID_DF200_HOST,
		.hw_rev = NBL_VER_3,
		.host_id = HOST_ID_TYPE_HOST,
		.product_type = PRODUCT_TYPE_DPU,
		.function_type = NBL_PRODUCT_FUNCTION_PF,
		.flags = NBL_PRODUCT_F_RESV_RES | NBL_PRODUCT_F_CTRL_DEV |
			 NBL_PRODUCT_F_INIT_SD_DIRECT |
			 NBL_PRODUCT_F_ABNORMAL_EVENT |
			 NBL_PRODUCT_F_DIRECT_RW_REG,
		.base_caps = NBL_PRODUCT_CAP_SRQ | NBL_PRODUCT_CAP_ATOMIC |
			     NBL_PRODUCT_CAP_BAR4_NOTIFY |
			     NBL_PRODUCT_CAP_DSCH_DPORT_UPDATE,
		.limits = &nbl_limits_df200_host,
		.regs = &rdma_base_v3,
		.dsch_layout = {
			.net_en_offset = NBL_DSCH_NET_EN_OFF_V3,
			.min_net_shaping_id = RDMA_MIN_NET_SHAPING_ID_V3,
			.min_grp_shaping_id = RDMA_MIN_GRP_SHAPING_ID_V3,
			.direct_init = true,
		},
		.stats = &nbl_stats_df200,
		.debug_layout = {
			.ext_qpc_v4 = false,
		},
		.gid_ops = &nbl_direct_gid_ops,
		.lifecycle_ops = &nbl_df200_host_lifecycle_ops,
		.fun_ops = &nbl_df200_fun_ops,
		.resource_ops = &nbl_df200_resource_ops,
		.irq_ops = &nbl_host_irq_ops,
		.feature_ops = &nbl_common_feature_ops,
		.dump_ops = &nbl_df200_dump_ops,
		.cq_ops = &nbl_common_cq_ops,
		.qpc_ops = &nbl_df200_qpc_ops,
		.qos_ops = &nbl_df200_qos_ops,
		.congestion_ops = &nbl_df200_congestion_ops,
	},
	[NBL_PRODUCT_ID_DRACO_PF] = {
		.name = "draco-pf",
		.id = NBL_PRODUCT_ID_DRACO_PF,
		.hw_rev = NBL_VER_2,
		.host_id = HOST_ID_TYPE_HOST,
		.product_type = PRODUCT_TYPE_SNIC,
		.function_type = NBL_PRODUCT_FUNCTION_PF,
		.flags = NBL_PRODUCT_F_CTRL_DEV |
			 NBL_PRODUCT_F_RX_VLAN_VSI_MAP |
			 NBL_PRODUCT_F_LAG_MIRROR_CFG,
		.base_caps = NBL_PRODUCT_CAP_SRQ | NBL_PRODUCT_CAP_ATOMIC |
			     NBL_PRODUCT_CAP_SHARED_CQP |
			     NBL_PRODUCT_CAP_PF_NOTIFY |
			     NBL_PRODUCT_CAP_DSCH_DPORT_UPDATE,
		.limits = &nbl_limits_draco_pf,
		.regs = &rdma_base_v2,
		.dsch_layout = {
			.net_en_offset = NBL_DSCH_NET_EN_OFF_V2,
			.min_net_shaping_id = RDMA_MIN_NET_SHAPING_ID_V2,
			.min_grp_shaping_id = RDMA_MIN_GRP_SHAPING_ID_V2,
			.direct_init = false,
		},
		.stats = &nbl_stats_draco,
		.debug_layout = {
			.ext_qpc_v4 = false,
		},
		.gid_ops = &nbl_draco_gid_ops,
		.lifecycle_ops = &nbl_draco_lifecycle_ops,
		.fun_ops = &nbl_common_fun_ops,
		.resource_ops = &nbl_draco_resource_ops,
		.irq_ops = &nbl_host_irq_ops,
		.feature_ops = &nbl_common_feature_ops,
		.dump_ops = &nbl_draco_dump_ops,
		.cq_ops = &nbl_common_cq_ops,
		.qpc_ops = &nbl_draco_qpc_ops,
		.qos_ops = &nbl_draco_qos_ops,
		.congestion_ops = &nbl_draco_congestion_ops,
	},
	[NBL_PRODUCT_ID_DRACO_VF] = {
		.name = "draco-vf",
		.id = NBL_PRODUCT_ID_DRACO_VF,
		.hw_rev = NBL_VER_2,
		.host_id = HOST_ID_TYPE_HOST,
		.product_type = PRODUCT_TYPE_SNIC,
		.function_type = NBL_PRODUCT_FUNCTION_VF,
		.flags = 0,
		.base_caps = NBL_PRODUCT_CAP_SRQ | NBL_PRODUCT_CAP_ATOMIC |
			     NBL_PRODUCT_CAP_DSCH_DPORT_UPDATE,
		.limits = &nbl_limits_draco_vf,
		.regs = &rdma_base_v2,
		.dsch_layout = {
			.net_en_offset = NBL_DSCH_NET_EN_OFF_V2,
			.min_net_shaping_id = RDMA_MIN_NET_SHAPING_ID_V2,
			.min_grp_shaping_id = RDMA_MIN_GRP_SHAPING_ID_V2,
			.direct_init = false,
		},
		.stats = &nbl_stats_draco,
		.debug_layout = {
			.ext_qpc_v4 = false,
		},
		.gid_ops = &nbl_draco_gid_ops,
		.lifecycle_ops = &nbl_draco_lifecycle_ops,
		.fun_ops = &nbl_common_fun_ops,
		.resource_ops = &nbl_draco_resource_ops,
		.irq_ops = &nbl_host_irq_ops,
		.feature_ops = &nbl_common_feature_ops,
		.dump_ops = &nbl_draco_dump_ops,
		.cq_ops = &nbl_common_cq_ops,
		.qpc_ops = &nbl_draco_qpc_ops,
		.qos_ops = &nbl_draco_qos_ops,
		.congestion_ops = &nbl_draco_congestion_ops,
	},
	[NBL_PRODUCT_ID_RNIC400_PF] = {
		.name = "rnic400-pf",
		.id = NBL_PRODUCT_ID_RNIC400_PF,
		.hw_rev = NBL_VER_4,
		.host_id = HOST_ID_TYPE_HOST,
		.product_type = PRODUCT_TYPE_SNIC,
		.function_type = NBL_PRODUCT_FUNCTION_PF,
		.flags = NBL_PRODUCT_F_CTRL_DEV | NBL_PRODUCT_F_INIT_SD_DIRECT |
			 NBL_PRODUCT_F_ABNORMAL_EVENT |
			 NBL_PRODUCT_F_FW_VER_REG |
			 NBL_PRODUCT_F_DIRECT_RW_REG |
			 NBL_PRODUCT_F_CPU_FWD_DEFAULT,
		.base_caps = NBL_PRODUCT_CAP_PT |
			     NBL_PRODUCT_CAP_MPLANE_SPRAY |
			     NBL_PRODUCT_CAP_SRQ | NBL_PRODUCT_CAP_UMR |
			     NBL_PRODUCT_CAP_ATOMIC | NBL_PRODUCT_CAP_DEVX |
			     NBL_PRODUCT_CAP_SRP |
			     NBL_PRODUCT_CAP_SLOW_PATH |
			     NBL_PRODUCT_CAP_CHG_PKT_UDP_PORT |
			     NBL_PRODUCT_CAP_CHG_PSN_OST |
			     NBL_PRODUCT_CAP_QPN_ALLOC_INTERVAL |
			     NBL_PRODUCT_CAP_WRITE_ATOMIC_FENCE,
		.limits = &nbl_limits_rnic400_pf,
		.regs = &rdma_base_v4,
		.dsch_layout = {
			.net_en_offset = NBL_DSCH_NET_EN_OFF_V3,
			.min_net_shaping_id = RDMA_MIN_NET_SHAPING_ID_V4,
			.min_grp_shaping_id = RDMA_MIN_GRP_SHAPING_ID_V4,
			.dport_table_depth = NBL_DSCH_RNIC_TBL_MAX_DEPTH,
			.direct_init = true,
		},
		.stats = &nbl_stats_rnic400,
		.debug_layout = {
			.ext_qpc_v4 = true,
		},
		.gid_ops = &nbl_direct_gid_ops,
		.lifecycle_ops = &nbl_rnic400_lifecycle_ops,
		.fun_ops = &nbl_rnic400_fun_ops,
		.resource_ops = &nbl_rnic400_resource_ops,
		.irq_ops = &nbl_rnic400_irq_ops,
		.feature_ops = &nbl_rnic400_feature_ops,
		.dump_ops = &nbl_rnic400_dump_ops,
		.cq_ops = &nbl_rnic400_cq_ops,
		.qpc_ops = &nbl_rnic400_qpc_ops,
		.qos_ops = &nbl_rnic400_qos_ops,
		.congestion_ops = &nbl_rnic400_congestion_ops,
	},
	[NBL_PRODUCT_ID_ORION_PF] = {
		.name = "orion-pf",
		.id = NBL_PRODUCT_ID_ORION_PF,
		.hw_rev = NBL_VER_5,
		.host_id = HOST_ID_TYPE_HOST,
		.product_type = PRODUCT_TYPE_SNIC,
		.function_type = NBL_PRODUCT_FUNCTION_PF,
		.flags = NBL_PRODUCT_F_CTRL_DEV,
		.base_caps = NBL_PRODUCT_CAP_SRQ | NBL_PRODUCT_CAP_ATOMIC |
			     NBL_PRODUCT_CAP_SHARED_CQP |
			     NBL_PRODUCT_CAP_PF_NOTIFY |
			     NBL_PRODUCT_CAP_DSCH_DPORT_UPDATE,
		.limits = &nbl_limits_orion_pf,
		.regs = &rdma_base_v5,
		.dsch_layout = {
			.net_en_offset = NBL_DSCH_NET_EN_OFF_V2,
			.min_net_shaping_id = RDMA_MIN_NET_SHAPING_ID_V2,
			.min_grp_shaping_id = RDMA_MIN_GRP_SHAPING_ID_V2,
			.direct_init = false,
		},
		.stats = &nbl_stats_draco,
		.debug_layout = {
			.ext_qpc_v4 = false,
		},
		.gid_ops = &nbl_orion_gid_ops,
		.lifecycle_ops = &nbl_orion_lifecycle_ops,
		.fun_ops = &nbl_common_fun_ops,
		.resource_ops = &nbl_orion_resource_ops,
		.irq_ops = &nbl_host_irq_ops,
		.feature_ops = &nbl_common_feature_ops,
		.dump_ops = &nbl_draco_dump_ops,
		.cq_ops = &nbl_common_cq_ops,
		.qpc_ops = &nbl_draco_qpc_ops,
		.qos_ops = &nbl_draco_qos_ops,
		.congestion_ops = &nbl_draco_congestion_ops,
	},
	[NBL_PRODUCT_ID_ORION_VF] = {
		.name = "orion-vf",
		.id = NBL_PRODUCT_ID_ORION_VF,
		.hw_rev = NBL_VER_5,
		.host_id = HOST_ID_TYPE_HOST,
		.product_type = PRODUCT_TYPE_SNIC,
		.function_type = NBL_PRODUCT_FUNCTION_VF,
		.flags = 0,
		.base_caps = NBL_PRODUCT_CAP_SRQ | NBL_PRODUCT_CAP_ATOMIC |
			     NBL_PRODUCT_CAP_DSCH_DPORT_UPDATE,
		.limits = &nbl_limits_orion_vf,
		.regs = &rdma_base_v5,
		.dsch_layout = {
			.net_en_offset = NBL_DSCH_NET_EN_OFF_V2,
			.min_net_shaping_id = RDMA_MIN_NET_SHAPING_ID_V2,
			.min_grp_shaping_id = RDMA_MIN_GRP_SHAPING_ID_V2,
			.direct_init = false,
		},
		.stats = &nbl_stats_draco,
		.debug_layout = {
			.ext_qpc_v4 = false,
		},
		.gid_ops = &nbl_orion_gid_ops,
		.lifecycle_ops = &nbl_orion_lifecycle_ops,
		.fun_ops = &nbl_common_fun_ops,
		.resource_ops = &nbl_orion_resource_ops,
		.irq_ops = &nbl_host_irq_ops,
		.feature_ops = &nbl_common_feature_ops,
		.dump_ops = &nbl_draco_dump_ops,
		.cq_ops = &nbl_common_cq_ops,
		.qpc_ops = &nbl_draco_qpc_ops,
		.qos_ops = &nbl_draco_qos_ops,
		.congestion_ops = &nbl_draco_congestion_ops,
	},
};

struct nbl_product_match {
	u16 device_id_start;
	u16 device_id_end;
	enum nbl_product_id id;
};

static const struct nbl_product_match nbl_product_matches[] = {
	{ DF200_ECPU_PF2_DEVICE_ID, DF200_ECPU_PF3_DEVICE_ID,
	  NBL_PRODUCT_ID_DF200_ECPU },
	{ DF200_HOST_RDMA_DEVICE_ID, DF200_HOST_RDMA_DEVICE_ID,
	  NBL_PRODUCT_ID_DF200_HOST },
	{ ASIC_V2R1_PF_DEVICE_ID, ASIC_V2R1_PF_DEVICE_ID,
	  NBL_PRODUCT_ID_DRACO_PF },
	{ DRACO_RDMA_PF_START_DEVICE_ID, DRACO_RDMA_PF_END_DEVICE_ID,
	  NBL_PRODUCT_ID_DRACO_PF },
	{ ASIC_V2R1_VF_DEVICE_ID, ASIC_V2R1_VF_DEVICE_ID,
	  NBL_PRODUCT_ID_DRACO_VF },
	{ DRACO_RDMA_VF_DEVICE_ID, DRACO_RDMA_VF_DEVICE_ID,
	  NBL_PRODUCT_ID_DRACO_VF },
	{ RNIC400_PF_DEVICE_ID, RNIC400_PF_DEVICE_ID,
	  NBL_PRODUCT_ID_RNIC400_PF },
	{ ORION_RDMA_PF_DEVICE_ID, ORION_RDMA_PF_DEVICE_ID,
	  NBL_PRODUCT_ID_ORION_PF },
	{ ORION_RDMA_VF_DEVICE_ID, ORION_RDMA_VF_DEVICE_ID,
	  NBL_PRODUCT_ID_ORION_VF },
};

const struct nbl_product_desc *nbl_product_lookup(u16 device_id)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(nbl_product_matches); i++) {
		const struct nbl_product_match *match = &nbl_product_matches[i];

		if (device_id >= match->device_id_start &&
		    device_id <= match->device_id_end)
			return &nbl_product_descs[match->id];
	}

	return NULL;
}

static bool nbl_product_limits_valid(const struct nbl_product_limits *limits)
{
	return limits && limits->max_mr_size && limits->max_total_qps &&
	       limits->max_total_cqs && limits->max_total_pbls &&
	       limits->max_total_mrs && limits->max_total_srqs &&
	       !(limits->max_total_cqs % limits->max_total_qps) &&
	       !(limits->max_total_pbls % limits->max_total_qps) &&
	       !(limits->max_total_mrs % limits->max_total_qps) &&
	       !(limits->max_total_qps % limits->max_total_srqs) &&
	       limits->max_pds &&
	       limits->max_ahs && limits->max_qp_wr && limits->max_srq_wr &&
	       limits->max_aeq_entries && limits->max_ceq_entries &&
	       limits->min_aeq_entries && limits->min_ceq_entries &&
	       limits->min_aeq_entries <= limits->max_aeq_entries &&
	       limits->min_ceq_entries <= limits->max_ceq_entries &&
	       limits->min_cq_size && limits->max_cq_size &&
	       limits->min_cq_size <= limits->max_cq_size &&
	       limits->min_ceqs && limits->min_ceqs <= limits->max_ceqs &&
	       limits->gid_per_function && limits->qpcc_depth &&
	       limits->cqcc_depth && limits->mrtc_depth && limits->srqc_depth &&
	       limits->pblc_depth && limits->sqrqec_depth &&
	       limits->irqec_depth && limits->raqec_depth &&
	       limits->unaqec_depth && limits->pdc_depth &&
	       limits->orqec_depth &&
	       limits->max_inline_data && limits->max_ud_inline_data &&
	       limits->sq_ost_count && limits->max_wqe_quanta &&
	       limits->max_sge && limits->max_read_sge &&
	       limits->rd_atomic_shift <= 6 && limits->max_rd_atomic &&
	       is_power_of_2(limits->pble_count_align);
}

static int nbl_product_validation_err(const struct nbl_product_desc *product,
				      const char *reason)
{
	const char *name = "<null>";

	if (product)
		name = product->name && product->name[0] ?
		       product->name : "<unnamed>";

	nbl_pr_err("product %s validation failed: %s\n", name, reason);
	return -EINVAL;
}

int nbl_product_validate(const struct nbl_product_desc *product,
			 const struct nbl_rdma_dev_ops *dev_ops,
			 const struct nbl_cqp_ops *cqp_ops)
{
	u64 vf_invalid_caps = NBL_PRODUCT_CAP_PT |
			      NBL_PRODUCT_CAP_MPLANE_SPRAY |
			      NBL_PRODUCT_CAP_UMR |
			      NBL_PRODUCT_CAP_SHARED_CQP |
			      NBL_PRODUCT_CAP_BAR4_NOTIFY |
			      NBL_PRODUCT_CAP_PF_NOTIFY |
			      NBL_PRODUCT_CAP_MR_BRANCH |
			      NBL_PRODUCT_CAP_DEVX;

	/* A valid descriptor identity is required before it can be used as an
	 * array index or exposed in probe diagnostics.
	 */
	if (!product)
		return nbl_product_validation_err(product,
						  "descriptor is NULL");
	if (!product->name || !product->name[0])
		return nbl_product_validation_err(product,
						  "name is empty");
	if (product->id < 0 || product->id >= NBL_PRODUCT_ID_MAX)
		return nbl_product_validation_err(product,
						  "id is out of range");

	/* The V2 driver only supports the V2-V4 hardware descriptor layouts. */
	if (product->hw_rev < NBL_VER_2 || product->hw_rev >= NBL_VER_MAX)
		return nbl_product_validation_err(product,
						  "hw_rev is unsupported");

	/* Host, product and function identities select protocol and resource
	 * layouts, so values outside their enums cannot be dispatched safely.
	 */
	if (product->host_id < HOST_ID_TYPE_HOST ||
	    product->host_id >= HOST_ID_TYPE_MAX)
		return nbl_product_validation_err(product,
						  "host_id is out of range");
	if (product->product_type < 0 ||
	    product->product_type >= PRODUCT_TYPE_MAX)
		return nbl_product_validation_err(product,
						  "product_type is out of range");
	if (product->function_type < 0 ||
	    product->function_type >= NBL_PRODUCT_FUNCTION_MAX)
		return nbl_product_validation_err(product,
						  "function_type is out of range");

	/* Unknown flags or capabilities have no defined runtime behavior. */
	if (product->flags & ~NBL_PRODUCT_FLAGS_MASK)
		return nbl_product_validation_err(product,
						  "flags contain unknown bits");
	if (product->base_caps & ~NBL_PRODUCT_CAPS_MASK)
		return nbl_product_validation_err(product,
						  "base_caps contain unknown bits");

	/* Limits and register layouts are dereferenced by common data paths. */
	if (!nbl_product_limits_valid(product->limits))
		return nbl_product_validation_err(product,
						  "resource limits are invalid");
	if (!product->regs)
		return nbl_product_validation_err(product,
						  "register layout is missing");
	if (!product->stats || !product->stats->group_count ||
	    !product->stats->entry_count || !product->stats->opcode_count ||
	    !product->stats->error_count ||
	    product->stats->entry_count != product->stats->opcode_count +
					  product->stats->error_count)
		return nbl_product_validation_err(product,
						  "statistics layout is invalid");

	/* Only RNIC400 negotiates mutable capabilities with firmware. */
	if (product->base_caps & NBL_PRODUCT_FW_CAPS_MASK &&
	    product->id != NBL_PRODUCT_ID_RNIC400_PF)
		return nbl_product_validation_err(product,
						  "firmware caps require RNIC400 PF");

	/* The embedded CPU path exists only on a physical DPU function. */
	if (product->host_id == HOST_ID_TYPE_ECPU &&
	    (product->product_type != PRODUCT_TYPE_DPU ||
	     product->function_type != NBL_PRODUCT_FUNCTION_PF))
		return nbl_product_validation_err(product,
						  "ECPU requires a DPU PF");

	/* DPU products do not expose an RDMA virtual-function profile. */
	if (product->product_type == PRODUCT_TYPE_DPU &&
	    product->function_type != NBL_PRODUCT_FUNCTION_PF)
		return nbl_product_validation_err(product,
						  "DPU products must be PFs");

	/* A VF is a host-side SNIC function and cannot own PF-only resources. */
	if (product->function_type == NBL_PRODUCT_FUNCTION_VF &&
	    (product->host_id != HOST_ID_TYPE_HOST ||
	     product->product_type != PRODUCT_TYPE_SNIC ||
	     product->flags || (product->base_caps & vf_invalid_caps)))
		return nbl_product_validation_err(product,
						  "VF has a PF-only identity or capability");

	/* Control-device ownership is restricted to physical functions. */
	if (product->flags & NBL_PRODUCT_F_CTRL_DEV &&
	    product->function_type != NBL_PRODUCT_FUNCTION_PF)
		return nbl_product_validation_err(product,
						  "control device requires a PF");

	/* The extra RX VLAN VSI mappings are a Draco PF workaround. */
	if (product->flags & NBL_PRODUCT_F_RX_VLAN_VSI_MAP &&
	    product->id != NBL_PRODUCT_ID_DRACO_PF)
		return nbl_product_validation_err(product,
						  "RX VLAN VSI map requires Draco PF");

	/* Only products with the RDMA abnormal-event protocol may register it. */
	if (product->flags & NBL_PRODUCT_F_ABNORMAL_EVENT &&
	    product->id != NBL_PRODUCT_ID_DF200_ECPU &&
	    product->id != NBL_PRODUCT_ID_DF200_HOST &&
	    product->id != NBL_PRODUCT_ID_RNIC400_PF)
		return nbl_product_validation_err(product,
						  "abnormal event is unsupported");

	/* Only products exposing the static firmware registers may read them. */
	if (product->flags & NBL_PRODUCT_F_FW_VER_REG &&
	    product->id != NBL_PRODUCT_ID_DF200_ECPU &&
	    product->id != NBL_PRODUCT_ID_RNIC400_PF)
		return nbl_product_validation_err(product,
						  "firmware registers are unsupported");

	/* Direct GRC register access is available only on its native products. */
	if (product->flags & NBL_PRODUCT_F_DIRECT_RW_REG &&
	    product->id != NBL_PRODUCT_ID_DF200_ECPU &&
	    product->id != NBL_PRODUCT_ID_DF200_HOST &&
	    product->id != NBL_PRODUCT_ID_RNIC400_PF)
		return nbl_product_validation_err(product,
						  "direct GRC access is unsupported");

	/* The default CPU forwarding path is native to ECPU and RNIC400. */
	if (product->flags & NBL_PRODUCT_F_CPU_FWD_DEFAULT &&
	    product->id != NBL_PRODUCT_ID_DF200_ECPU &&
	    product->id != NBL_PRODUCT_ID_RNIC400_PF)
		return nbl_product_validation_err(product,
						  "default CPU forwarding is unsupported");

	/* The RDMA mirror setup is part of the Draco PF LAG protocol. */
	if (product->flags & NBL_PRODUCT_F_LAG_MIRROR_CFG &&
	    product->id != NBL_PRODUCT_ID_DRACO_PF)
		return nbl_product_validation_err(product,
						  "LAG mirror config requires Draco PF");

	/* PF notify and shared CQP use the SNIC PF mailbox protocol. */
	if (product->base_caps & (NBL_PRODUCT_CAP_PF_NOTIFY |
				 NBL_PRODUCT_CAP_SHARED_CQP) &&
	    (product->product_type != PRODUCT_TYPE_SNIC ||
	     product->function_type != NBL_PRODUCT_FUNCTION_PF))
		return nbl_product_validation_err(product,
						  "PF mailbox caps require a SNIC PF");

	/* MR branch registration is implemented only by DF200 ECPU. */
	if (product->base_caps & NBL_PRODUCT_CAP_MR_BRANCH &&
	    product->id != NBL_PRODUCT_ID_DF200_ECPU)
		return nbl_product_validation_err(product,
						  "MR branch requires DF200 ECPU");
	if (product->base_caps & NBL_PRODUCT_CAP_DEVX &&
	    product->id != NBL_PRODUCT_ID_RNIC400_PF)
		return nbl_product_validation_err(product,
						  "DevX requires RNIC400 PF");

	/* Optional feature callbacks must match the advertised capability. */
	if (!product->feature_ops ||
	    (!!(product->base_caps & NBL_PRODUCT_CAP_UMR) !=
	     !!product->feature_ops->umr_resource_init) ||
	    (!!(product->base_caps & NBL_PRODUCT_CAP_UMR) !=
	     !!product->feature_ops->umr_resource_cleanup) ||
	    (!!(product->base_caps & NBL_PRODUCT_CAP_PT) !=
	     !!product->feature_ops->pt_debugfs_init) ||
	    (!!(product->base_caps & NBL_PRODUCT_CAP_PT) !=
	     !!product->feature_ops->pt_debugfs_cleanup))
		return nbl_product_validation_err(product,
						  "feature ops do not match capabilities");
	if (!product->dump_ops || !product->dump_ops->set_cfg)
		return nbl_product_validation_err(product,
						  "dump ops are incomplete");

	if (!product->cq_ops ||
	    (!!product->cq_ops->set_cq_moderation !=
	     product->cq_ops->cq_moderation_supported))
		return nbl_product_validation_err(product,
						  "CQ ops are incomplete");

	/* QP create and modify paths require a complete selected QPC format. */
	if (!product->qpc_ops ||
	    !product->qpc_ops->set_rxp_req_pre_hwqpc ||
	    !product->qpc_ops->set_qcn_hwqpc ||
	    !product->qpc_ops->iorqe_size ||
	    !product->qpc_ops->default_raq_wqe_cap)
		return nbl_product_validation_err(product,
						  "QPC ops are incomplete");

	if (!product->qos_ops || !product->qos_ops->update_p2s_cfg ||
	    !product->qos_ops->set_pfc_en || !product->qos_ops->set_pfc_buf ||
	    !product->qos_ops->get_pfc_cfg ||
	    !product->qos_ops->trust_dscp_en ||
	    !product->qos_ops->get_reg_offset ||
	    !product->qos_ops->debugfs_param_supported ||
	    !product->qos_ops->default_cfg)
		return nbl_product_validation_err(product,
						  "QoS ops are incomplete");

	if (!product->congestion_ops ||
	    !product->congestion_ops->debugfs_param_supported ||
	    !product->congestion_ops->default_param_supported)
		return nbl_product_validation_err(product,
						  "congestion ops are incomplete");

	/* Probe, rollback and remove call every lifecycle callback directly. */
	if (!product->lifecycle_ops ||
	    !product->lifecycle_ops->init_global_cfg ||
	    !product->lifecycle_ops->detect_caps ||
	    !product->lifecycle_ops->channel_init ||
	    !product->lifecycle_ops->channel_exit ||
	    !product->lifecycle_ops->get_function_id ||
	    !product->lifecycle_ops->free_function_id ||
	    !product->lifecycle_ops->register_client ||
	    !product->lifecycle_ops->set_notify ||
	    !product->lifecycle_ops->reset_rdma)
		return nbl_product_validation_err(product,
						  "lifecycle ops are incomplete");

	if (!product->fun_ops || !product->fun_ops->set_mtu)
		return nbl_product_validation_err(product,
						  "function ops are incomplete");

	/* IRQ setup and teardown require the common interrupt callbacks. */
	if (!product->irq_ops || !product->irq_ops->get_global_msix_idx ||
	    !product->irq_ops->aeq_qp_event_valid ||
	    !product->irq_ops->nbl_dis_irq ||
	    !product->irq_ops->nbl_en_irq)
		return nbl_product_validation_err(product,
						  "IRQ ops are incomplete");

	/* Object SD setup is mandatory. Global SD setup is optional, but its
	 * init and deinit callbacks must be supplied as a pair.
	 */
	if (!product->resource_ops || !product->resource_ops->obj_sd_init ||
	    (!!product->resource_ops->global_sd_init !=
	     !!product->resource_ops->global_sd_deinit) ||
	    !dev_ops)
		return nbl_product_validation_err(product,
						  "resource or device ops are invalid");

	/* GID add, delete and address-handle paths call all GID callbacks. */
	if (!product->gid_ops || !product->gid_ops->alloc_index ||
	    !product->gid_ops->free_index || !product->gid_ops->get_info ||
	    !product->gid_ops->set_entry || !product->gid_ops->fill_table ||
	    !product->gid_ops->clear_table || !product->gid_ops->update_index)
		return nbl_product_validation_err(product,
						  "GID ops are incomplete");

	/* Direct DSCH callbacks and dport tables are valid only for products
	 * whose scheduler layout is initialized without a mailbox.
	 */
	if (!product->dsch_layout.net_en_offset ||
	    (!!dev_ops->dsch_init != product->dsch_layout.direct_init) ||
	    (dev_ops->update_dsch_dport && !product->dsch_layout.direct_init) ||
	    (product->dsch_layout.dport_table_depth &&
	     !product->dsch_layout.direct_init))
		return nbl_product_validation_err(product,
						  "DSCH layout and ops are inconsistent");

	/* Every function flushes ARMCQ; PF teardown additionally flushes TQP
	 * and RQ doorbells and waits for ARMCQ completion.
	 */
	if (!dev_ops->armcq_db_flush ||
	    (product->function_type == NBL_PRODUCT_FUNCTION_PF &&
	     (!dev_ops->tqp_flush || !dev_ops->rq_db_flush ||
	      !dev_ops->get_armcq_flush_status)))
		return nbl_product_validation_err(product,
						  "required flush ops are missing");

	/* Reserved firmware resources are part of the DPU ownership model. */
	if (product->flags & NBL_PRODUCT_F_RESV_RES &&
	    product->product_type != PRODUCT_TYPE_DPU)
		return nbl_product_validation_err(product,
						  "reserved resources require a DPU");

	/* BAR4 notify is the host-side notification path of a DPU. */
	if (product->base_caps & NBL_PRODUCT_CAP_BAR4_NOTIFY &&
	    (product->product_type != PRODUCT_TYPE_DPU ||
	     product->host_id != HOST_ID_TYPE_HOST))
		return nbl_product_validation_err(product,
						  "BAR4 notify requires a host DPU");

	/* CQ creation, teardown, resize and debug paths share one CQP table. */
	if (!cqp_ops || !cqp_ops->cqp_create_cq || !cqp_ops->cqp_destroy_cq ||
	    !cqp_ops->cqp_cq_ref_add || !cqp_ops->cqp_cq_ref_sub ||
	    !cqp_ops->cqp_cq_resize || !cqp_ops->cqp_dbg_create_cq ||
	    !cqp_ops->cqp_dbg_destroy_cq)
		return nbl_product_validation_err(product,
						  "CQP ops are incomplete");

	return 0;
}

bool nbl_product_cap_enabled(const struct nbl_pci_f *rf,
			     enum nbl_product_cap cap)
{
	return rf->effective_caps & cap;
}

bool nbl_product_flag_enabled(const struct nbl_pci_f *rf,
			      enum nbl_product_flags flag)
{
	return rf->product->flags & flag;
}

enum nbl_rnic_sub_type nbl_product_get_sub_type(const struct nbl_pci_f *rf)
{
	if (!rf->product || rf->product->id != NBL_PRODUCT_ID_RNIC400_PF)
		return RNIC_SUB_TYPE_NONE;

	return rf->product_runtime.sub_type;
}

void nbl_product_set_cap(struct nbl_pci_f *rf,
			 enum nbl_product_cap cap, bool enable)
{
	if (enable)
		rf->effective_caps |= cap & rf->product->base_caps;
	else
		rf->effective_caps &= ~cap;
}

void nbl_product_apply_fw_caps(struct nbl_pci_f *rf, u64 fw_caps)
{
	rf->effective_caps &= ~NBL_PRODUCT_FW_CAPS_MASK;
	rf->effective_caps |= fw_caps & rf->product->base_caps &
			      NBL_PRODUCT_FW_CAPS_MASK;
}
