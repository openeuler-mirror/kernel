/* SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB */
/* Copyright (c) 2021, NEBULARMATRIX */

#ifndef NBL_TXP_LAYOUT_H
#define NBL_TXP_LAYOUT_H

#define NBL_TXP_QCN_R_CNP_FIFO_OFF		0x0244
#define NBL_TXP_CC_SENDREQ_DB_CFG_OFF		0x0414
#define NBL_TXP_WQE_CAP_OFF			0x041c
#define NBL_TXP_LAG_CFG_0_OFF			0x0430
#define NBL_TXP_LAG_CFG_1_OFF			0x0434
#define NBL_TXP_LAG_EN_OFF			0x0438
#define NBL_TXP_CELL_NUM_CFG_OFF		0x0440
#define NBL_TXP_PSN_OST_OFF			0x0444
#define NBL_TXP_SRP_PKT_CNT_TH_OFF		0x0470
#define NBL_TXP_QCN_R_CNP_INVL_OFF		0x0490
#define NBL_TXP_CC_NIC_SPRAY_EN_OFF		0x0494
#define NBL_TXP_QCN_CNP_ACCOMPANIED_OFF		0x04ac
#define NBL_TXP_LAG_CFG_0_OFF_V4		0x04c0
#define NBL_TXP_LAG_CFG_1_OFF_V4		0x04e0

#define NBL_TXP_PSN_OST_VALID_MASK		0x80000000U

#define NBL_TXP_REG_ADDR(base, off)		((base) + (off))

union nbl_rdma_lag_en {
	u32 data[1];
	struct {
		u32 lag_en : 1;
		u32 glb_mp_en: 1;
		u32 eth_link_fc : 1;
		u32 eth_pfc : 1;
		u32 qm_link_fc: 1;
		u32 qm_pfc: 1;
		u32 db_mpbp_en : 1;
		u32 wqe_mpbp_en : 1;

		u32 reload_mode : 1;
		u32 w_algha: 2;
		u32 plb_en : 1;
		u32 rsv : 4;
		u32 lag_cfg_bm0: 4;
		u32 lag_cfg_bm1: 4;
		u32 over_cnt_th : 8;
	};
};

/* RNIC400 lag_cfg table, 128bit, 64 entries, 2bit per entry */
#define NBL_LAG_CFG_REG_NUM	8
#define NBL_LAG_CFG_PER_U32	16
#define NBL_LAG_CFG_NUM		(NBL_LAG_CFG_REG_NUM * NBL_LAG_CFG_PER_U32)
#define NBL_LAG_CFG_MASK	0x3U

struct nbl_rdma_lag_cfg_v4 {
	u32 data[NBL_LAG_CFG_REG_NUM]; /* 128bit per table */
};

/* set val (0~3) to entry idx of lag_cfg */
static inline void nbl_lag_cfg_set(struct nbl_rdma_lag_cfg_v4 *cfg, u32 idx,
				   u32 val)
{
	u32 group = idx / NBL_LAG_CFG_PER_U32;
	u32 shift = (idx % NBL_LAG_CFG_PER_U32) * 2;

	cfg->data[group] = (cfg->data[group] & ~(NBL_LAG_CFG_MASK << shift)) |
			   ((val & NBL_LAG_CFG_MASK) << shift);
}

#endif /* NBL_TXP_LAYOUT_H */
