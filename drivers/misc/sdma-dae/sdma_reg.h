/* SPDX-License-Identifier: GPL-2.0-or-later */

#ifndef __HISI_SDMA_REG_H__
#define __HISI_SDMA_REG_H__

/* HISI_SDMA_CH_REGS Registers' Definitions */
#define HISI_SDMA_CH_CTRL_REG			0x0
#define HISI_SDMA_CH_TEST_REG			0x4
#define HISI_SDMA_IRQ_STATUS			0xC
#define HISI_SDMA_CH_IRQ_CTRL_REG		0x10
#define HISI_SDMA_CH_CQE_STATUS_REG		0x18
#define HISI_SDMA_CH_STATUS_REG			0x1C
#define HISI_SDMA_CH_SQBASER_L_REG		0x40
#define HISI_SDMA_CH_SQBASER_H_REG		0x44
#define HISI_SDMA_CH_SQ_ATTR_REG		0x48
#define HISI_SDMA_CH_SQTDBR_REG			0x4C
#define HISI_SDMA_CH_SQHDBR_REG			0x50
#define HISI_SDMA_CH_CQBASER_L_REG		0x80
#define HISI_SDMA_CH_CQBASER_H_REG		0x84
#define HISI_SDMA_CH_CQ_ATTR_REG		0x88
#define HISI_SDMA_CH_CQTDBR_REG			0x8C
#define HISI_SDMA_CH_CQHDBR_REG			0x90

#define HISI_SDMA_CH_DFX_REG			0x300

#define HISI_SDMA_U32_MSK			GENMASK(31, 0)
/* REG_FILED_MASK IN HISI_SDMA_CH_CTRL_REG */
#define HISI_SDMA_CH_ENABLE_MSK			GENMASK(0, 0)

/* REG_FILED_MASK IN HISI_SDMA_CH_TEST_REG */
#define HISI_SDMA_CH_PAUSE_MSK			GENMASK(0, 0)
#define HISI_SDMA_CH_RESET_MSK			GENMASK(2, 2)

/* HISI_SDMA_CH_FSM_STATUS VAL */
#define HISI_SDMA_CHN_FSM_IDLE_MSK		GENMASK(0, 0)
#define HISI_SDMA_CHN_FSM_PAUSE_MSK		GENMASK(3, 3)
#define HISI_SDMA_CHN_FSM_QUIESCENT_MSK		GENMASK(4, 4)

/* HISI_SDMA_IRQ_STATUS */
#define HISI_SDMA_CHN_IRQ_STATUS_MSK		GENMASK(27, 20)
#define HISI_SDMA_CHN_CQE_STATUS_MSK		GENMASK(5, 1)
#define HISI_SDMA_CHN_CQE_SQEID_MSK		GENMASK(21, 6)

/* HISI_SDMA_CH_DFX_INFO0 */
#define HISI_SDMA_CHN_NORMAL_SQE_CNT_MSK	GENMASK(31, 16)
#define HISI_SDMA_CHN_ERROR_SQE_CNT_MSK		GENMASK(15, 0)

/* HISI_SDMA_SQ_ATTR */
#define HISI_SDMA_CH_SQ_SHARE_ATTR		0x1
#define HISI_SDMA_CH_SQ_CACHE_ATTR		0x7

/* HISI_SDMA_CQ_ATTR */
#define HISI_SDMA_CH_CQ_SHARE_ATTR		0x1
#define HISI_SDMA_CH_CQ_CACHE_ATTR		0x7

/* Define the union U_SDMAM_IRQ_STATUS */
union sdmam_irq_status {
	/* Define the struct bits */
	struct {
		u32    rsv0                             : 16 ; /* [15:0] */
		u32    ch_ioc_status                    : 1  ; /* [16] */
		u32    ch_ioe_status                    : 1  ; /* [17] */
		u32    rsv1                             : 2  ; /* [19:18] */
		u32    ch_err_status                    : 8  ; /* [27:20] */
		u32    rsv2                             : 4  ; /* [31:28] */
		} bits;

		/* Define an unsigned member */
		u32    u32;
};

/* Define the union U_SDMAM_CH_SQ_ATTR */
union sdmam_ch_regs_sdmam_ch_sq_attr {
	/* Define the struct bits */
	struct {
		unsigned int    sq_size         : 16  ; /* [15:0] */
		unsigned int    sq_cacheability : 3  ; /* [18:16] */
		unsigned int    sq_shareability : 2  ; /* [20:19] */
		unsigned int    rsv_12          : 11  ; /* [31:21] */
	} bits;

	/* Define an unsigned member */
	unsigned int    u32;
};

/* Define the union U_SDMAM_CH_CQ_ATTR */
union sdmam_ch_regs_sdmam_ch_cq_attr {
	/* Define the struct bits */
	struct {
		unsigned int    cq_size         : 16  ; /* [15:0] */
		unsigned int    cq_cacheability : 3  ; /* [18:16] */
		unsigned int    cq_shareability : 2  ; /* [20:19] */
		unsigned int    rsv_16          : 11  ; /* [31:21] */
	} bits;

	/* Define an unsigned member */
	unsigned int    u32;
};

#endif

#ifndef __HISI_SDMA_COMMON_REG_OFFSET_H__
#define __HISI_SDMA_COMMON_REG_OFFSET_H__

#define HISI_SDMA_SMMU_BYPASS_PART0		0x3c8
#define HISI_SDMA_SMMU_BYPASS_PART_SIZE		0x4

#define HISI_SDMA_DMA_MPAMID_CFG		0x50c
#define HISI_SDMA_DFX_FEATURE_EN		0x544
#define HISI_SDMA_ERR_STATUSL			0x2010

/* Define the union U_SDMAM_DFX_FEATURE_EN */
union sdmam_dfx_feature_en {
	/* Define the struct bits */
	struct {
		u32    rsv0                             : 4  ; /* [3:0] */
		u32    ch_int_converge_en               : 1  ; /* [4] */
		u32    ch_int_group_converge_en         : 1  ; /* [5] */
		u32    rsv1                             : 26 ; /* [31:6] */
	} bits;

	/* Define an unsigned member */
	u32    u32;
};

/* Define the union U_DMA_MPAMID_CFG */
union sdmam_common_regs_dma_mpamid_cfg {
	/* Define the struct bits */
	struct {
		u32    replace_mpam_ns     : 1  ; /* [0] */
		u32    replace_mpam_pmg    : 2  ; /* [2:1] */
		u32    replace_mpam_partid : 8  ; /* [10:3] */
		u32    replace_qos         : 4  ; /* [14:11] */
		u32    mpam_id_replace_en  : 1  ; /* [15] */
		u32    mpam_id_vf_en       : 1  ; /* [16] */
		u32    rsv_15              : 15  ; /* [31:17] */
	} bits;

	/* Define an unsigned member */
	u32    u32;
};

#endif
