// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#include "zxic_common.h"
#include "dpp_type_api.h"
#include "dpp_reg.h"
// #include "dpp_devmng_api.h"
#include "dpp_stat_car.h"
#include "dpp_stat_api.h"

#if ZXIC_REAL("Global Variable")

static struct dpp_car_soft_reset_data_t g_car_store_data[DPP_DEV_CHANNEL_MAX] = { { { 0 } } };

#define GET_DPP_CAR_SOFT_RESET_INFO(dev_id) (&g_car_store_data[dev_id])

#define DPP_CAR1_REG_OFFSET (0)

#endif

#if ZXIC_REAL("Basic Reg Operation ")
DPP_STATUS dpp_stat_cara_queue_cfg_set(struct dpp_dev_t *dev, u32 flow_id, u32 drop_flag,
				       u32 plcr_en, u32 profile_id)
{
	DPP_STATUS rc = DPP_OK;

	struct dpp_stat_car0_cara_queue_ram0_159_0_t queue_cfg = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), flow_id, 0, DPP_CAR_A_FLOW_ID_MAX);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), drop_flag, 0, 1);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), plcr_en, 0, 1);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), profile_id, 0, DPP_CAR_A_PROFILE_ID_MAX);

	queue_cfg.cara_drop = drop_flag;
	queue_cfg.cara_plcr_en = plcr_en;
	queue_cfg.cara_profile_id = profile_id;

	rc = dpp_reg_write(dev, STAT_CAR0_CARA_QUEUE_RAM0_159_0r, 0, flow_id, &queue_cfg);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_reg_write");

	return rc;
}
DPP_STATUS
dpp_stat_cara_queue_cfg_get(struct dpp_dev_t *dev, u32 flow_id,
			    struct dpp_stat_car_a_queue_cfg_t *p_cara_queue_cfg)
{
	DPP_STATUS rc = DPP_OK;

	struct dpp_stat_car0_cara_queue_ram0_159_0_t queue_cfg = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), flow_id, 0, DPP_CAR_A_FLOW_ID_MAX);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_cara_queue_cfg);

	rc = dpp_reg_read(dev, STAT_CAR0_CARA_QUEUE_RAM0_159_0r, 0, flow_id, &queue_cfg);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_reg_read");

	p_cara_queue_cfg->flow_id = flow_id;
	p_cara_queue_cfg->drop_flag = queue_cfg.cara_drop;
	p_cara_queue_cfg->plcr_en = queue_cfg.cara_plcr_en;
	p_cara_queue_cfg->profile_id = queue_cfg.cara_profile_id;

	p_cara_queue_cfg->tq = ZXIC_COMM_COUNTER64_BUILD(queue_cfg.cara_tq_h, queue_cfg.cara_tq_l);

	p_cara_queue_cfg->ted = queue_cfg.cara_ted;
	p_cara_queue_cfg->tcd = queue_cfg.cara_tcd;
	p_cara_queue_cfg->tei = queue_cfg.cara_tei;
	p_cara_queue_cfg->tci = queue_cfg.cara_tci;

	return rc;
}
DPP_STATUS dpp_stat_cara_pkt_queue_cfg_get(struct dpp_dev_t *dev, u32 flow_id,
					   struct dpp_stat_car_a_pkt_queue_cfg_t *p_cara_queue_cfg)
{
	DPP_STATUS rc = DPP_OK;

	struct dpp_stat_car0_cara_queue_ram0_159_0_pkt_t queue_cfg = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), flow_id, 0, DPP_CAR_A_FLOW_ID_MAX);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_cara_queue_cfg);

	rc = dpp_reg_read(dev, STAT_CAR0_CARA_QUEUE_RAM0_159_0_PKTr, 0, flow_id, &queue_cfg);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_reg_read");

	p_cara_queue_cfg->flow_id = flow_id;
	p_cara_queue_cfg->plcr_en = queue_cfg.cara_plcr_en;
	p_cara_queue_cfg->profile_id = queue_cfg.cara_profile_id;

	p_cara_queue_cfg->tq = ZXIC_COMM_COUNTER64_BUILD(queue_cfg.cara_tq_h, queue_cfg.cara_tq_l);

	p_cara_queue_cfg->dc =
		ZXIC_COMM_COUNTER64_BUILD(queue_cfg.cara_dc_high, queue_cfg.cara_dc_low);
	p_cara_queue_cfg->tc = queue_cfg.cara_tc;

	return rc;
}
DPP_STATUS
dpp_stat_cara_profile_cfg_set(struct dpp_dev_t *dev, u32 profile_id,
			      struct dpp_stat_car_profile_cfg_t *p_cara_profile_cfg)
{
	DPP_STATUS rc = DPP_OK;

	u32 i = 0;

	struct dpp_stat_car0_cara_profile_ram1_255_0_t profile_cfg = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), profile_id, 0, DPP_CAR_A_PROFILE_ID_MAX);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_cara_profile_cfg);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), p_cara_profile_cfg->profile_id, 0,
				  DPP_CAR_A_PROFILE_ID_MAX);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), p_cara_profile_cfg->pkt_sign, 0, 1);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), p_cara_profile_cfg->cf, 0, 1);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), p_cara_profile_cfg->cm, 0, 1);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), p_cara_profile_cfg->cd, CAR_CD_MODE_SRTCM,
				  CAR_CD_MODE_INVALID - 1);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), p_cara_profile_cfg->cir, 0, DPP_CAR_MAX_CIR_VALUE);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), p_cara_profile_cfg->eir, 0, DPP_CAR_MAX_EIR_VALUE);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), p_cara_profile_cfg->cbs, 0, DPP_CAR_MAX_CBS_VALUE);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), p_cara_profile_cfg->ebs, 0, DPP_CAR_MAX_EBS_VALUE);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), p_cara_profile_cfg->random_disc_e, 0, 0xffffffff);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), p_cara_profile_cfg->random_disc_c, 0, 0xffffffff);

	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), p_cara_profile_cfg->e_yellow_pri[0], 0,
				  DPP_CAR_MAX_PRI_VALUE);

	for (i = 1; i < DPP_CAR_PRI_MAX; i++) {
		ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), p_cara_profile_cfg->c_pri[i], 0,
					  DPP_CAR_MAX_PRI_VALUE);
		ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), p_cara_profile_cfg->e_green_pri[i], 0,
					  DPP_CAR_MAX_PRI_VALUE);
		ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), p_cara_profile_cfg->e_yellow_pri[i], 0,
					  DPP_CAR_MAX_PRI_VALUE);
	}
	ZXIC_COMM_TRACE_DEV_INFO(DEV_ID(dev), "==> dpp stat_cara_profile_cfg_set profile_id[%d]:\n",
				 profile_id);
	ZXIC_COMM_TRACE_DEV_INFO(
		DEV_ID(dev),
		"| -------------------------------------------------------------- |\n");
	ZXIC_COMM_TRACE_DEV_INFO(DEV_ID(dev),
				 "| %-5s | %-5s | %-5s | %-10s | %-10s | %-10s | %-10s |\n", "cd",
				 "cf", "cm", "cir", "cbs", "eir", "ebs");
	ZXIC_COMM_TRACE_DEV_INFO(DEV_ID(dev),
				 "| %-5d | %-5d | %-5d | %-10d | %-10d | %-10d | %-10d |\n",
				 p_cara_profile_cfg->cd, p_cara_profile_cfg->cf,
				 p_cara_profile_cfg->cm, p_cara_profile_cfg->cir,
				 p_cara_profile_cfg->cbs, p_cara_profile_cfg->eir,
				 p_cara_profile_cfg->ebs);
	ZXIC_COMM_TRACE_DEV_INFO(
		DEV_ID(dev),
		"| ----- | ----- | ----- | ---------- | ---------- | ---------- | ---------- |\n");

	profile_cfg.cara_e_y_pri7 = p_cara_profile_cfg->e_yellow_pri[7];
	profile_cfg.cara_e_y_pri6 = p_cara_profile_cfg->e_yellow_pri[6];
	profile_cfg.cara_e_y_pri5 = p_cara_profile_cfg->e_yellow_pri[5];
	profile_cfg.cara_e_y_pri4 = p_cara_profile_cfg->e_yellow_pri[4];
	profile_cfg.cara_e_y_pri3 = p_cara_profile_cfg->e_yellow_pri[3];
	profile_cfg.cara_e_y_pri2 = p_cara_profile_cfg->e_yellow_pri[2];
	profile_cfg.cara_e_y_pri1 = p_cara_profile_cfg->e_yellow_pri[1];
	profile_cfg.cara_e_y_pri0 = p_cara_profile_cfg->e_yellow_pri[0];

	profile_cfg.cara_e_g_pri7 = p_cara_profile_cfg->e_green_pri[7];
	profile_cfg.cara_e_g_pri6 = p_cara_profile_cfg->e_green_pri[6];
	profile_cfg.cara_e_g_pri5 = p_cara_profile_cfg->e_green_pri[5];
	profile_cfg.cara_e_g_pri4 = p_cara_profile_cfg->e_green_pri[4];
	profile_cfg.cara_e_g_pri3 = p_cara_profile_cfg->e_green_pri[3];
	profile_cfg.cara_e_g_pri2 = p_cara_profile_cfg->e_green_pri[2];
	profile_cfg.cara_e_g_pri1 = p_cara_profile_cfg->e_green_pri[1];

	profile_cfg.cara_c_pri7 = p_cara_profile_cfg->c_pri[7];
	profile_cfg.cara_c_pri6 = p_cara_profile_cfg->c_pri[6];
	profile_cfg.cara_c_pri5 = p_cara_profile_cfg->c_pri[5];
	profile_cfg.cara_c_pri4 = p_cara_profile_cfg->c_pri[4];
	profile_cfg.cara_c_pri3 = p_cara_profile_cfg->c_pri[3];
	profile_cfg.cara_c_pri2 = p_cara_profile_cfg->c_pri[2];
	profile_cfg.cara_c_pri1 = p_cara_profile_cfg->c_pri[1];

	profile_cfg.cara_cbs = p_cara_profile_cfg->cbs;
	profile_cfg.cara_ebs_pbs = p_cara_profile_cfg->ebs;
	profile_cfg.cara_cir = p_cara_profile_cfg->cir;
	profile_cfg.cara_eir = p_cara_profile_cfg->eir;

	profile_cfg.cara_cd = p_cara_profile_cfg->cd;
	profile_cfg.cara_cf = p_cara_profile_cfg->cf;
	profile_cfg.cara_cm = p_cara_profile_cfg->cm;
	profile_cfg.cara_pkt_sign = p_cara_profile_cfg->pkt_sign;

	profile_cfg.cara_profile_wr = 0;

	rc = dpp_reg_write(dev, STAT_CAR0_CARA_PROFILE_RAM1_255_0r, 0, profile_id, &profile_cfg);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_reg_write");

	return rc;
}
DPP_STATUS
dpp_stat_cara_profile_cfg_get(struct dpp_dev_t *dev, u32 profile_id,
			      struct dpp_stat_car_profile_cfg_t *p_cara_profile_cfg)
{
	DPP_STATUS rc = DPP_OK;

	struct dpp_stat_car0_cara_profile_ram1_255_0_t profile_cfg = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), profile_id, 0, DPP_CAR_A_PROFILE_ID_MAX);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_cara_profile_cfg);

	rc = dpp_reg_read(dev, STAT_CAR0_CARA_PROFILE_RAM1_255_0r, 0, profile_id, &profile_cfg);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_reg_read");

	p_cara_profile_cfg->profile_id = profile_id;
	p_cara_profile_cfg->pkt_sign = profile_cfg.cara_pkt_sign;
	p_cara_profile_cfg->cd = profile_cfg.cara_cd;
	p_cara_profile_cfg->cf = profile_cfg.cara_cf;
	p_cara_profile_cfg->cm = profile_cfg.cara_cm;
	p_cara_profile_cfg->eir = profile_cfg.cara_eir;
	p_cara_profile_cfg->cir = profile_cfg.cara_cir;
	p_cara_profile_cfg->ebs = profile_cfg.cara_ebs_pbs;
	p_cara_profile_cfg->cbs = profile_cfg.cara_cbs;

	p_cara_profile_cfg->c_pri[1] = profile_cfg.cara_c_pri1;
	p_cara_profile_cfg->c_pri[2] = profile_cfg.cara_c_pri2;
	p_cara_profile_cfg->c_pri[3] = profile_cfg.cara_c_pri3;
	p_cara_profile_cfg->c_pri[4] = profile_cfg.cara_c_pri4;
	p_cara_profile_cfg->c_pri[5] = profile_cfg.cara_c_pri5;
	p_cara_profile_cfg->c_pri[6] = profile_cfg.cara_c_pri6;
	p_cara_profile_cfg->c_pri[7] = profile_cfg.cara_c_pri7;

	p_cara_profile_cfg->e_green_pri[1] = profile_cfg.cara_e_g_pri1;
	p_cara_profile_cfg->e_green_pri[2] = profile_cfg.cara_e_g_pri2;
	p_cara_profile_cfg->e_green_pri[3] = profile_cfg.cara_e_g_pri3;
	p_cara_profile_cfg->e_green_pri[4] = profile_cfg.cara_e_g_pri4;
	p_cara_profile_cfg->e_green_pri[5] = profile_cfg.cara_e_g_pri5;
	p_cara_profile_cfg->e_green_pri[6] = profile_cfg.cara_e_g_pri6;
	p_cara_profile_cfg->e_green_pri[7] = profile_cfg.cara_e_g_pri7;

	p_cara_profile_cfg->e_yellow_pri[0] = profile_cfg.cara_e_y_pri0;
	p_cara_profile_cfg->e_yellow_pri[1] = profile_cfg.cara_e_y_pri1;
	p_cara_profile_cfg->e_yellow_pri[2] = profile_cfg.cara_e_y_pri2;
	p_cara_profile_cfg->e_yellow_pri[3] = profile_cfg.cara_e_y_pri3;
	p_cara_profile_cfg->e_yellow_pri[4] = profile_cfg.cara_e_y_pri4;
	p_cara_profile_cfg->e_yellow_pri[5] = profile_cfg.cara_e_y_pri5;
	p_cara_profile_cfg->e_yellow_pri[6] = profile_cfg.cara_e_y_pri6;
	p_cara_profile_cfg->e_yellow_pri[7] = profile_cfg.cara_e_y_pri7;

	return rc;
}
DPP_STATUS
dpp_stat_cara_pkt_profile_cfg_set(struct dpp_dev_t *dev, u32 profile_id,
				  struct dpp_stat_car_pkt_profile_cfg_t *p_cara_profile_cfg)
{
	DPP_STATUS rc = DPP_OK;

	u32 i = 0;

	struct dpp_stat_car0_cara_profile_ram1_255_0_pkt_t profile_cfg = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), profile_id, 0, DPP_CAR_A_PROFILE_ID_MAX);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_cara_profile_cfg);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), p_cara_profile_cfg->pkt_sign, 0, 1);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), p_cara_profile_cfg->cir, 0,
				  DPP_CAR_MAX_PKT_CIR_VALUE);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), p_cara_profile_cfg->cbs, 0,
				  DPP_CAR_MAX_PKT_CBS_VALUE);

	for (i = 0; i < DPP_CAR_PRI_MAX; i++) {
		ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), p_cara_profile_cfg->pri[i], 0,
					  DPP_CAR_MAX_PRI_VALUE);
	}

	profile_cfg.cara_pri7 = p_cara_profile_cfg->pri[7];
	profile_cfg.cara_pri6 = p_cara_profile_cfg->pri[6];
	profile_cfg.cara_pri5 = p_cara_profile_cfg->pri[5];
	profile_cfg.cara_pri4 = p_cara_profile_cfg->pri[4];
	profile_cfg.cara_pri3 = p_cara_profile_cfg->pri[3];
	profile_cfg.cara_pri2 = p_cara_profile_cfg->pri[2];
	profile_cfg.cara_pri1 = p_cara_profile_cfg->pri[1];
	profile_cfg.cara_pri0 = p_cara_profile_cfg->pri[0];

	profile_cfg.cara_pkt_cbs = p_cara_profile_cfg->cbs;
	profile_cfg.cara_pkt_cir = p_cara_profile_cfg->cir;
	profile_cfg.cara_pkt_sign = p_cara_profile_cfg->pkt_sign;

	profile_cfg.cara_profile_wr = 0;

	rc = dpp_reg_write(dev, STAT_CAR0_CARA_PROFILE_RAM1_255_0_PKTr, 0, profile_id,
			   &profile_cfg);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_reg_write");

	return rc;
}
DPP_STATUS
dpp_stat_cara_pkt_profile_cfg_get(struct dpp_dev_t *dev, u32 profile_id,
				  struct dpp_stat_car_pkt_profile_cfg_t *p_cara_profile_cfg)
{
	DPP_STATUS rc = DPP_OK;

	struct dpp_stat_car0_cara_profile_ram1_255_0_pkt_t profile_cfg = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), profile_id, 0, DPP_CAR_A_PROFILE_ID_MAX);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_cara_profile_cfg);

	rc = dpp_reg_read(dev, STAT_CAR0_CARA_PROFILE_RAM1_255_0_PKTr, 0, profile_id, &profile_cfg);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_reg_read");

	p_cara_profile_cfg->profile_id = profile_id;
	p_cara_profile_cfg->pkt_sign = profile_cfg.cara_pkt_sign;
	p_cara_profile_cfg->cir = profile_cfg.cara_pkt_cir;
	p_cara_profile_cfg->cbs = profile_cfg.cara_pkt_cbs;

	p_cara_profile_cfg->pri[0] = profile_cfg.cara_pri0;
	p_cara_profile_cfg->pri[1] = profile_cfg.cara_pri1;
	p_cara_profile_cfg->pri[2] = profile_cfg.cara_pri2;
	p_cara_profile_cfg->pri[3] = profile_cfg.cara_pri3;
	p_cara_profile_cfg->pri[4] = profile_cfg.cara_pri4;
	p_cara_profile_cfg->pri[5] = profile_cfg.cara_pri5;
	p_cara_profile_cfg->pri[6] = profile_cfg.cara_pri6;
	p_cara_profile_cfg->pri[7] = profile_cfg.cara_pri7;

	return rc;
}
DPP_STATUS dpp_stat_cara_queue_qvos_set(struct dpp_dev_t *dev, u32 flow_id, u32 qvos_mode)
{
	DPP_STATUS rc = DPP_OK;
	struct dpp_stat_car0_cara_qovs_ram_ram2_t qvos_cfg = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), flow_id, 0, DPP_CAR_A_FLOW_ID_MAX);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), qvos_mode, CAR_QVOS_MODE_OVERFLOW_0,
				  CAR_QVOS_MODE_OVERFLOW_MAX - 1);

	qvos_cfg.cara_qovs = qvos_mode;

	rc = dpp_reg_write(dev, STAT_CAR0_CARA_QOVS_RAM_RAM2r, 0, flow_id, &qvos_cfg);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_reg_write");

	return rc;
}
DPP_STATUS dpp_stat_cara_queue_qvos_get(struct dpp_dev_t *dev, u32 flow_id, u32 *p_qvos_mode)
{
	DPP_STATUS rc = DPP_OK;
	struct dpp_stat_car0_cara_qovs_ram_ram2_t qvos_cfg = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), flow_id, 0, DPP_CAR_A_FLOW_ID_MAX);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_qvos_mode);

	rc = dpp_reg_read(dev, STAT_CAR0_CARA_QOVS_RAM_RAM2r, 0, flow_id, &qvos_cfg);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_reg_read");

	*p_qvos_mode = qvos_cfg.cara_qovs;

	return rc;
}
DPP_STATUS dpp_stat_cara_queue_map_set(struct dpp_dev_t *dev, u32 flow_id, u32 map_flow_id,
				       u32 map_sp)
{
	DPP_STATUS rc = DPP_OK;
	struct dpp_stat_car0_look_up_table1_t map_cfg = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), flow_id, 0, DPP_CAR_A_FLOW_ID_MAX);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), map_flow_id, 0, DPP_CAR_B_FLOW_ID_MAX);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), map_sp, DPP_CAR_PRI0, DPP_CAR_PRI_MAX - 1);

	map_cfg.cara_flow_id = map_flow_id;
	map_cfg.cara_sp = map_sp;

	rc = dpp_reg_write(dev, STAT_CAR0_LOOK_UP_TABLE1r, 0, flow_id, &map_cfg);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_reg_write");

	return rc;
}
DPP_STATUS dpp_stat_cara_queue_map_get(struct dpp_dev_t *dev, u32 flow_id, u32 *p_map_flow_id,
				       u32 *p_map_sp)
{
	DPP_STATUS rc = DPP_OK;
	struct dpp_stat_car0_look_up_table1_t map_cfg = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), flow_id, 0, DPP_CAR_A_FLOW_ID_MAX);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_map_flow_id);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_map_sp);

	rc = dpp_reg_read(dev, STAT_CAR0_LOOK_UP_TABLE1r, 0, flow_id, &map_cfg);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_reg_read");

	*p_map_flow_id = map_cfg.cara_flow_id;
	*p_map_sp = map_cfg.cara_sp;

	return rc;
}
DPP_STATUS dpp_stat_cara_queue_appoint_mode_set(struct dpp_dev_t *dev, u32 global_en, u32 sp_en,
						u32 appoint_sp, u32 appoint_queue)
{
	DPP_STATUS rc = DPP_OK;
	struct dpp_stat_car0_cara_appoint_qnum_or_sp_t appoint_cfg = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), global_en, 0, 1);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), sp_en, 0, 1);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), appoint_sp, DPP_CAR_PRI0, DPP_CAR_PRI_MAX - 1);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), appoint_queue, 0, DPP_CAR_A_FLOW_ID_MAX);

	appoint_cfg.cara_appoint_qnum_or_not = global_en;
	appoint_cfg.cara_appoint_sp_or_not = sp_en;
	appoint_cfg.cara_plcr_stat_sp = appoint_sp;
	appoint_cfg.cara_plcr_stat_qnum = appoint_queue;

	rc = dpp_reg_write(dev, STAT_CAR0_CARA_APPOINT_QNUM_OR_SPr, 0, 0, &appoint_cfg);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_reg_write");

	return rc;
}
DPP_STATUS dpp_stat_cara_queue_appoint_mode_get(struct dpp_dev_t *dev, u32 *p_global_en,
						u32 *p_sp_en, u32 *p_appoint_sp,
						u32 *p_appoint_queue)
{
	DPP_STATUS rc = DPP_OK;
	struct dpp_stat_car0_cara_appoint_qnum_or_sp_t appoint_cfg = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_global_en);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_sp_en);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_appoint_sp);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_appoint_queue);

	rc = dpp_reg_read(dev, STAT_CAR0_CARA_APPOINT_QNUM_OR_SPr, 0, 0, &appoint_cfg);

	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_reg_read");

	*p_global_en = appoint_cfg.cara_appoint_qnum_or_not;
	*p_sp_en = appoint_cfg.cara_appoint_sp_or_not;
	*p_appoint_sp = appoint_cfg.cara_plcr_stat_sp;
	*p_appoint_queue = appoint_cfg.cara_plcr_stat_qnum;

	return rc;
}
DPP_STATUS dpp_stat_cara_dbg_cnt_mode_set(struct dpp_dev_t *dev, u32 overflow_mode, u32 rd_mode)
{
	DPP_STATUS rc = DPP_OK;
	struct dpp_stat_car0_cara_cfgmt_count_mode_t cnt_mode_cfg = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), overflow_mode, CAR_KEEP_COUNT, CAR_RE_COUNT);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), rd_mode, CAR_READ_NOT_CLEAR, CAR_READ_AND_CLEAR);

	cnt_mode_cfg.cara_cfgmt_count_overflow_mode = overflow_mode;
	cnt_mode_cfg.cara_cfgmt_count_rd_mode = rd_mode;

	rc = dpp_reg_write(dev, STAT_CAR0_CARA_CFGMT_COUNT_MODEr, 0, 0, &cnt_mode_cfg);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_reg_write");

	return rc;
}
DPP_STATUS dpp_stat_cara_dbg_cnt_mode_get(struct dpp_dev_t *dev, u32 *p_overflow_mode,
					  u32 *p_rd_mode)
{
	DPP_STATUS rc = DPP_OK;
	struct dpp_stat_car0_cara_cfgmt_count_mode_t cnt_mode_cfg = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_overflow_mode);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_rd_mode);

	rc = dpp_reg_read(dev, STAT_CAR0_CARA_CFGMT_COUNT_MODEr, 0, 0, &cnt_mode_cfg);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_reg_read");

	*p_overflow_mode = cnt_mode_cfg.cara_cfgmt_count_overflow_mode;
	*p_rd_mode = cnt_mode_cfg.cara_cfgmt_count_rd_mode;

	return rc;
}
DPP_STATUS dpp_stat_carb_queue_cfg_set(struct dpp_dev_t *dev, u32 flow_id, u32 drop_flag,
				       u32 plcr_en, u32 profile_id)
{
	DPP_STATUS rc = DPP_OK;

	struct dpp_stat_car0_carb_queue_ram0_159_0_t queue_cfg = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), flow_id, 0, DPP_CAR_B_FLOW_ID_MAX);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), drop_flag, 0, 1);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), plcr_en, 0, 1);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), profile_id, 0, DPP_CAR_B_PROFILE_ID_MAX);

	queue_cfg.carb_drop = drop_flag;
	queue_cfg.carb_plcr_en = plcr_en;
	queue_cfg.carb_profile_id = profile_id;

	rc = dpp_reg_write(dev, STAT_CAR0_CARB_QUEUE_RAM0_159_0r, 0, flow_id, &queue_cfg);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_reg_write");

	return rc;
}
DPP_STATUS
dpp_stat_carb_queue_cfg_get(struct dpp_dev_t *dev, u32 flow_id,
			    struct dpp_stat_car_b_queue_cfg_t *p_carb_queue_cfg)
{
	DPP_STATUS rc = DPP_OK;

	struct dpp_stat_car0_carb_queue_ram0_159_0_t queue_cfg = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), flow_id, 0, DPP_CAR_B_FLOW_ID_MAX);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_carb_queue_cfg);

	rc = dpp_reg_read(dev, STAT_CAR0_CARB_QUEUE_RAM0_159_0r, 0, flow_id, &queue_cfg);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_reg_read");

	p_carb_queue_cfg->flow_id = flow_id;
	p_carb_queue_cfg->drop_flag = queue_cfg.carb_drop;
	p_carb_queue_cfg->plcr_en = queue_cfg.carb_plcr_en;
	p_carb_queue_cfg->profile_id = queue_cfg.carb_profile_id;

	p_carb_queue_cfg->tq = ZXIC_COMM_COUNTER64_BUILD(queue_cfg.carb_tq_h, queue_cfg.carb_tq_l);

	p_carb_queue_cfg->tce_flag = queue_cfg.carb_ted;
	p_carb_queue_cfg->tce = queue_cfg.carb_tcd;
	p_carb_queue_cfg->te = queue_cfg.carb_tei;
	p_carb_queue_cfg->tc = queue_cfg.carb_tci;

	return rc;
}
DPP_STATUS
dpp_stat_carb_profile_cfg_set(struct dpp_dev_t *dev, u32 profile_id,
			      struct dpp_stat_car_profile_cfg_t *p_carb_profile_cfg)
{
	DPP_STATUS rc = DPP_OK;

	u32 i = 0;

	struct dpp_stat_car0_carb_profile_ram1_255_0_t profile_cfg = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), profile_id, 0, DPP_CAR_B_PROFILE_ID_MAX);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_carb_profile_cfg);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), p_carb_profile_cfg->pkt_sign, 0, 1);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), p_carb_profile_cfg->cf, 0, 1);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), p_carb_profile_cfg->cm, 0, 1);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), p_carb_profile_cfg->random_disc_e, 0, 1);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), p_carb_profile_cfg->random_disc_c, 0, 1);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), p_carb_profile_cfg->cd, CAR_CD_MODE_SRTCM,
				  CAR_CD_MODE_INVALID - 1);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), p_carb_profile_cfg->cir, 0, DPP_CAR_MAX_CIR_VALUE);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), p_carb_profile_cfg->eir, 0, DPP_CAR_MAX_EIR_VALUE);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), p_carb_profile_cfg->cbs, 0, DPP_CAR_MAX_CBS_VALUE);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), p_carb_profile_cfg->ebs, 0, DPP_CAR_MAX_EBS_VALUE);

	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), p_carb_profile_cfg->e_yellow_pri[0], 0,
				  DPP_CAR_MAX_PRI_VALUE);

	for (i = 1; i < DPP_CAR_PRI_MAX; i++) {
		ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), p_carb_profile_cfg->c_pri[i], 0,
					  DPP_CAR_MAX_PRI_VALUE);
		ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), p_carb_profile_cfg->e_green_pri[i], 0,
					  DPP_CAR_MAX_PRI_VALUE);
		ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), p_carb_profile_cfg->e_yellow_pri[i], 0,
					  DPP_CAR_MAX_PRI_VALUE);
	}

	profile_cfg.carb_e_y_pri7 = p_carb_profile_cfg->e_yellow_pri[7];
	profile_cfg.carb_e_y_pri6 = p_carb_profile_cfg->e_yellow_pri[6];
	profile_cfg.carb_e_y_pri5 = p_carb_profile_cfg->e_yellow_pri[5];
	profile_cfg.carb_e_y_pri4 = p_carb_profile_cfg->e_yellow_pri[4];
	profile_cfg.carb_e_y_pri3 = p_carb_profile_cfg->e_yellow_pri[3];
	profile_cfg.carb_e_y_pri2 = p_carb_profile_cfg->e_yellow_pri[2];
	profile_cfg.carb_e_y_pri1 = p_carb_profile_cfg->e_yellow_pri[1];
	profile_cfg.carb_e_y_pri0 = p_carb_profile_cfg->e_yellow_pri[0];

	profile_cfg.carb_e_g_pri7 = p_carb_profile_cfg->e_green_pri[7];
	profile_cfg.carb_e_g_pri6 = p_carb_profile_cfg->e_green_pri[6];
	profile_cfg.carb_e_g_pri5 = p_carb_profile_cfg->e_green_pri[5];
	profile_cfg.carb_e_g_pri4 = p_carb_profile_cfg->e_green_pri[4];
	profile_cfg.carb_e_g_pri3 = p_carb_profile_cfg->e_green_pri[3];
	profile_cfg.carb_e_g_pri2 = p_carb_profile_cfg->e_green_pri[2];
	profile_cfg.carb_e_g_pri1 = p_carb_profile_cfg->e_green_pri[1];

	profile_cfg.carb_c_pri7 = p_carb_profile_cfg->c_pri[7];
	profile_cfg.carb_c_pri6 = p_carb_profile_cfg->c_pri[6];
	profile_cfg.carb_c_pri5 = p_carb_profile_cfg->c_pri[5];
	profile_cfg.carb_c_pri4 = p_carb_profile_cfg->c_pri[4];
	profile_cfg.carb_c_pri3 = p_carb_profile_cfg->c_pri[3];
	profile_cfg.carb_c_pri2 = p_carb_profile_cfg->c_pri[2];
	profile_cfg.carb_c_pri1 = p_carb_profile_cfg->c_pri[1];

	profile_cfg.carb_cbs = p_carb_profile_cfg->cbs;
	profile_cfg.carb_ebs_pbs = p_carb_profile_cfg->ebs;
	profile_cfg.carb_cir = p_carb_profile_cfg->cir;
	profile_cfg.carb_eir = p_carb_profile_cfg->eir;

	profile_cfg.carb_cd = p_carb_profile_cfg->cd;
	profile_cfg.carb_cf = p_carb_profile_cfg->cf;
	profile_cfg.carb_cm = p_carb_profile_cfg->cm;

	profile_cfg.carb_random_discard_en_e = p_carb_profile_cfg->random_disc_e;
	profile_cfg.carb_random_discard_en_c = p_carb_profile_cfg->random_disc_c;

	profile_cfg.carb_pkt_sign = 0;

	profile_cfg.carb_profile_wr = 0;

	rc = dpp_reg_write(dev, STAT_CAR0_CARB_PROFILE_RAM1_255_0r, 0, profile_id, &profile_cfg);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_reg_write");

	return rc;
}
DPP_STATUS
dpp_stat_carb_profile_cfg_get(struct dpp_dev_t *dev, u32 profile_id,
			      struct dpp_stat_car_profile_cfg_t *p_carb_profile_cfg)
{
	DPP_STATUS rc = DPP_OK;

	struct dpp_stat_car0_carb_profile_ram1_255_0_t profile_cfg = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), profile_id, 0, DPP_CAR_B_PROFILE_ID_MAX);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_carb_profile_cfg);

	rc = dpp_reg_read(dev, STAT_CAR0_CARB_PROFILE_RAM1_255_0r, 0, profile_id, &profile_cfg);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_reg_read");

	p_carb_profile_cfg->profile_id = profile_id;
	p_carb_profile_cfg->pkt_sign = profile_cfg.carb_pkt_sign;
	p_carb_profile_cfg->cd = profile_cfg.carb_cd;
	p_carb_profile_cfg->cf = profile_cfg.carb_cf;
	p_carb_profile_cfg->cm = profile_cfg.carb_cm;
	p_carb_profile_cfg->eir = profile_cfg.carb_eir;
	p_carb_profile_cfg->cir = profile_cfg.carb_cir;
	p_carb_profile_cfg->ebs = profile_cfg.carb_ebs_pbs;
	p_carb_profile_cfg->cbs = profile_cfg.carb_cbs;
	p_carb_profile_cfg->random_disc_e = profile_cfg.carb_random_discard_en_e;
	p_carb_profile_cfg->random_disc_c = profile_cfg.carb_random_discard_en_c;

	p_carb_profile_cfg->c_pri[1] = profile_cfg.carb_c_pri1;
	p_carb_profile_cfg->c_pri[2] = profile_cfg.carb_c_pri2;
	p_carb_profile_cfg->c_pri[3] = profile_cfg.carb_c_pri3;
	p_carb_profile_cfg->c_pri[4] = profile_cfg.carb_c_pri4;
	p_carb_profile_cfg->c_pri[5] = profile_cfg.carb_c_pri5;
	p_carb_profile_cfg->c_pri[6] = profile_cfg.carb_c_pri6;
	p_carb_profile_cfg->c_pri[7] = profile_cfg.carb_c_pri7;

	p_carb_profile_cfg->e_green_pri[1] = profile_cfg.carb_e_g_pri1;
	p_carb_profile_cfg->e_green_pri[2] = profile_cfg.carb_e_g_pri2;
	p_carb_profile_cfg->e_green_pri[3] = profile_cfg.carb_e_g_pri3;
	p_carb_profile_cfg->e_green_pri[4] = profile_cfg.carb_e_g_pri4;
	p_carb_profile_cfg->e_green_pri[5] = profile_cfg.carb_e_g_pri5;
	p_carb_profile_cfg->e_green_pri[6] = profile_cfg.carb_e_g_pri6;
	p_carb_profile_cfg->e_green_pri[7] = profile_cfg.carb_e_g_pri7;

	p_carb_profile_cfg->e_yellow_pri[0] = profile_cfg.carb_e_y_pri0;
	p_carb_profile_cfg->e_yellow_pri[1] = profile_cfg.carb_e_y_pri1;
	p_carb_profile_cfg->e_yellow_pri[2] = profile_cfg.carb_e_y_pri2;
	p_carb_profile_cfg->e_yellow_pri[3] = profile_cfg.carb_e_y_pri3;
	p_carb_profile_cfg->e_yellow_pri[4] = profile_cfg.carb_e_y_pri4;
	p_carb_profile_cfg->e_yellow_pri[5] = profile_cfg.carb_e_y_pri5;
	p_carb_profile_cfg->e_yellow_pri[6] = profile_cfg.carb_e_y_pri6;
	p_carb_profile_cfg->e_yellow_pri[7] = profile_cfg.carb_e_y_pri7;

	return rc;
}
DPP_STATUS dpp_stat_carb_queue_qvos_set(struct dpp_dev_t *dev, u32 flow_id, u32 qvos_mode)
{
	DPP_STATUS rc = DPP_OK;
	struct dpp_stat_car0_carb_qovs_ram_ram2_t qvos_cfg = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), flow_id, 0, DPP_CAR_B_FLOW_ID_MAX);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), qvos_mode, CAR_QVOS_MODE_OVERFLOW_0,
				  CAR_QVOS_MODE_OVERFLOW_MAX - 1);

	qvos_cfg.carb_qovs = qvos_mode;

	rc = dpp_reg_write(dev, STAT_CAR0_CARB_QOVS_RAM_RAM2r, 0, flow_id, &qvos_cfg);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_reg_write");

	return rc;
}
DPP_STATUS dpp_stat_carb_queue_qvos_get(struct dpp_dev_t *dev, u32 flow_id, u32 *p_qvos_mode)
{
	DPP_STATUS rc = DPP_OK;
	struct dpp_stat_car0_carb_qovs_ram_ram2_t qvos_cfg = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), flow_id, 0, DPP_CAR_B_FLOW_ID_MAX);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_qvos_mode);

	rc = dpp_reg_read(dev, STAT_CAR0_CARB_QOVS_RAM_RAM2r, 0, flow_id, &qvos_cfg);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_reg_read");

	*p_qvos_mode = qvos_cfg.carb_qovs;

	return rc;
}
DPP_STATUS dpp_stat_carb_queue_map_set(struct dpp_dev_t *dev, u32 flow_id, u32 map_flow_id,
				       u32 map_sp)
{
	DPP_STATUS rc = DPP_OK;
	struct dpp_stat_car0_look_up_table2_t map_cfg = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), flow_id, 0, DPP_CAR_B_FLOW_ID_MAX);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), map_flow_id, 0, DPP_CAR_C_FLOW_ID_MAX);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), map_sp, DPP_CAR_PRI0, DPP_CAR_PRI_MAX - 1);

	map_cfg.carb_flow_id = map_flow_id;
	map_cfg.carb_sp = map_sp;

	rc = dpp_reg_write(dev, STAT_CAR0_LOOK_UP_TABLE2r, 0, flow_id, &map_cfg);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_reg_write");

	return rc;
}
DPP_STATUS dpp_stat_carb_queue_map_get(struct dpp_dev_t *dev, u32 flow_id, u32 *p_map_flow_id,
				       u32 *p_map_sp)
{
	DPP_STATUS rc = DPP_OK;
	struct dpp_stat_car0_look_up_table2_t map_cfg = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), flow_id, 0, DPP_CAR_B_FLOW_ID_MAX);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_map_flow_id);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_map_sp);

	rc = dpp_reg_read(dev, STAT_CAR0_LOOK_UP_TABLE2r, 0, flow_id, &map_cfg);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_reg_read");

	*p_map_flow_id = map_cfg.carb_flow_id;
	*p_map_sp = map_cfg.carb_sp;

	return rc;
}
DPP_STATUS dpp_stat_carb_random_ram_set(struct dpp_dev_t *dev, u32 profile_id,
					struct dpp_car_random_ram_t *p_random_ram_e,
					struct dpp_car_random_ram_t *p_random_ram_c)
{
	DPP_STATUS rc = DPP_OK;

	u64 para0_temp = 0;
	u64 para2_temp = 0;
	u64 para4_temp = 0;
	struct dpp_stat_car0_carb_random_ram_t carb_random_ram_cfg = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_random_ram_e);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), p_random_ram_e->p1, 0, 100);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), p_random_ram_e->p2, 0, 100);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), p_random_ram_e->p3, 0, 100);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_random_ram_c);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), p_random_ram_c->p1, 0, 100);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), p_random_ram_c->p2, 0, 100);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), p_random_ram_c->p3, 0, 100);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), profile_id, 0, DPP_CAR_B_PROFILE_ID_RANDOM_MAX);

	para0_temp = ((u64)((((u64)(p_random_ram_e->t2)) - ((u64)(p_random_ram_e->t1))) *
			    ((u64)(p_random_ram_e->p1)))
		      << DPP_CAR_RANDOM_OFFSET_VAL) /
		     100;
	carb_random_ram_cfg.para0_l_e = (para0_temp & 0xFFFFFFFF);
	carb_random_ram_cfg.para0_h_e = (para0_temp >> 32) & 0xFFFFFFFF;

	carb_random_ram_cfg.para1_e =
		((p_random_ram_e->p2 - p_random_ram_e->p1) << DPP_CAR_RANDOM_OFFSET_VAL) / 100;

	para2_temp = ((u64)((((u64)(p_random_ram_e->t3)) - ((u64)(p_random_ram_e->t2))) *
			    ((u64)(p_random_ram_e->p2)))
		      << DPP_CAR_RANDOM_OFFSET_VAL) /
		     100;
	carb_random_ram_cfg.para2_l_e = (para2_temp & 0xFFFFFFFF);
	carb_random_ram_cfg.para2_h_e = (para2_temp >> 32) & 0xFFFFFFFF;

	carb_random_ram_cfg.para3_e =
		((p_random_ram_e->p3 - p_random_ram_e->p2) << DPP_CAR_RANDOM_OFFSET_VAL) / 100;

	para4_temp = ((u64)((((u64)(p_random_ram_e->tc)) - ((u64)(p_random_ram_e->t3))) *
			    ((u64)(p_random_ram_e->p3)))
		      << DPP_CAR_RANDOM_OFFSET_VAL) /
		     100;
	carb_random_ram_cfg.para4_l_e = (para4_temp & 0xFFFFFFFF);
	carb_random_ram_cfg.para4_h_e = (para4_temp >> 32) & 0xFFFFFFFF;

	carb_random_ram_cfg.para5_e =
		((100 - p_random_ram_e->p3) << DPP_CAR_RANDOM_OFFSET_VAL) / 100;
	carb_random_ram_cfg.para6_e = p_random_ram_e->t1;
	carb_random_ram_cfg.para7_e = p_random_ram_e->t2;
	carb_random_ram_cfg.para8_e = p_random_ram_e->t3;

	para0_temp = ((u64)((((u64)(p_random_ram_c->t2)) - ((u64)(p_random_ram_c->t1))) *
			    ((u64)(p_random_ram_c->p1)))
		      << DPP_CAR_RANDOM_OFFSET_VAL) /
		     100;
	carb_random_ram_cfg.para0_l_c = (para0_temp & 0xFFFFFFFF);
	carb_random_ram_cfg.para0_h_c = (para0_temp >> 32) & 0xFFFFFFFF;

	carb_random_ram_cfg.para1_c =
		((p_random_ram_c->p2 - p_random_ram_c->p1) << DPP_CAR_RANDOM_OFFSET_VAL) / 100;

	para2_temp = ((u64)((((u64)(p_random_ram_c->t3)) - ((u64)(p_random_ram_c->t2))) *
			    ((u64)(p_random_ram_c->p2)))
		      << DPP_CAR_RANDOM_OFFSET_VAL) /
		     100;
	carb_random_ram_cfg.para2_l_c = (para2_temp & 0xFFFFFFFF);
	carb_random_ram_cfg.para2_h_c = (para2_temp >> 32) & 0xFFFFFFFF;

	carb_random_ram_cfg.para3_c =
		((p_random_ram_c->p3 - p_random_ram_c->p2) << DPP_CAR_RANDOM_OFFSET_VAL) / 100;

	para4_temp = ((u64)((((u64)(p_random_ram_c->tc)) - ((u64)(p_random_ram_c->t3))) *
			    ((u64)(p_random_ram_c->p3)))
		      << DPP_CAR_RANDOM_OFFSET_VAL) /
		     100;
	carb_random_ram_cfg.para4_l_c = (para4_temp & 0xFFFFFFFF);
	carb_random_ram_cfg.para4_h_c = (para4_temp >> 32) & 0xFFFFFFFF;

	carb_random_ram_cfg.para5_c =
		((100 - p_random_ram_c->p3) << DPP_CAR_RANDOM_OFFSET_VAL) / 100;
	carb_random_ram_cfg.para6_c = p_random_ram_c->t1;
	carb_random_ram_cfg.para7_c = p_random_ram_c->t2;
	carb_random_ram_cfg.para8_c = p_random_ram_c->t3;

	rc = dpp_reg_write(dev, STAT_CAR0_CARB_RANDOM_RAMr, 0, profile_id, &carb_random_ram_cfg);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_reg_write");

	return rc;
}
DPP_STATUS dpp_stat_carb_random_ram_get(struct dpp_dev_t *dev, u32 profile_id,
					struct dpp_car_random_ram_t *p_random_ram_e,
					struct dpp_car_random_ram_t *p_random_ram_c)
{
	DPP_STATUS rc = DPP_OK;
	struct dpp_stat_car0_carb_random_ram_t carb_random_ram_cfg = { 0 };
	u32 tmp_val = 0;

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_random_ram_e);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_random_ram_c);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), profile_id, 0, DPP_CAR_B_PROFILE_ID_RANDOM_MAX);

	rc = dpp_reg_read(dev, STAT_CAR0_CARB_RANDOM_RAMr, 0, profile_id, &carb_random_ram_cfg);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_reg_read");

	p_random_ram_e->t1 = carb_random_ram_cfg.para6_e;
	p_random_ram_e->t2 = carb_random_ram_cfg.para7_e;
	p_random_ram_e->t3 = carb_random_ram_cfg.para8_e;
	tmp_val = (carb_random_ram_cfg.para5_e * 100) >> DPP_CAR_RANDOM_OFFSET_VAL;
	p_random_ram_e->p3 = 100 - tmp_val;
	tmp_val = (carb_random_ram_cfg.para3_e * 100) >> DPP_CAR_RANDOM_OFFSET_VAL;
	p_random_ram_e->p2 = p_random_ram_e->p3 - tmp_val;
	tmp_val = (carb_random_ram_cfg.para1_e * 100) >> DPP_CAR_RANDOM_OFFSET_VAL;
	p_random_ram_e->p1 = p_random_ram_e->p2 - tmp_val;

	p_random_ram_c->t1 = carb_random_ram_cfg.para6_c;
	p_random_ram_c->t2 = carb_random_ram_cfg.para7_c;
	p_random_ram_c->t3 = carb_random_ram_cfg.para8_c;
	tmp_val = (carb_random_ram_cfg.para5_c * 100) >> DPP_CAR_RANDOM_OFFSET_VAL;
	p_random_ram_c->p3 = 100 - tmp_val;
	tmp_val = (carb_random_ram_cfg.para3_c * 100) >> DPP_CAR_RANDOM_OFFSET_VAL;
	p_random_ram_c->p2 = p_random_ram_c->p3 - tmp_val;
	tmp_val = (carb_random_ram_cfg.para1_c * 100) >> DPP_CAR_RANDOM_OFFSET_VAL;
	p_random_ram_c->p1 = p_random_ram_c->p2 - tmp_val;

	return rc;
}
DPP_STATUS dpp_stat_carc_queue_cfg_set(struct dpp_dev_t *dev, u32 flow_id, u32 drop_flag,
				       u32 plcr_en, u32 profile_id)
{
	DPP_STATUS rc = DPP_OK;

	struct dpp_stat_car0_carc_queue_ram0_159_0_t queue_cfg = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), flow_id, 0, DPP_CAR_C_FLOW_ID_MAX);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), drop_flag, 0, 1);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), plcr_en, 0, 1);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), profile_id, 0, DPP_CAR_C_PROFILE_ID_MAX);

	queue_cfg.carc_drop = drop_flag;
	queue_cfg.carc_plcr_en = plcr_en;
	queue_cfg.carc_profile_id = profile_id;

	rc = dpp_reg_write(dev, STAT_CAR0_CARC_QUEUE_RAM0_159_0r, 0, flow_id, &queue_cfg);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_reg_write");

	return rc;
}
DPP_STATUS
dpp_stat_carc_queue_cfg_get(struct dpp_dev_t *dev, u32 flow_id,
			    struct dpp_stat_car_c_queue_cfg_t *p_carc_queue_cfg)
{
	DPP_STATUS rc = DPP_OK;

	struct dpp_stat_car0_carc_queue_ram0_159_0_t queue_cfg = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), flow_id, 0, DPP_CAR_C_FLOW_ID_MAX);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_carc_queue_cfg);

	rc = dpp_reg_read(dev, STAT_CAR0_CARC_QUEUE_RAM0_159_0r, 0, flow_id, &queue_cfg);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_reg_read");

	p_carc_queue_cfg->flow_id = flow_id;
	p_carc_queue_cfg->drop_flag = queue_cfg.carc_drop;
	p_carc_queue_cfg->plcr_en = queue_cfg.carc_plcr_en;
	p_carc_queue_cfg->profile_id = queue_cfg.carc_profile_id;

	p_carc_queue_cfg->tq = ZXIC_COMM_COUNTER64_BUILD(queue_cfg.carc_tq_h, queue_cfg.carc_tq_l);

	p_carc_queue_cfg->tce_flag = queue_cfg.carc_ted;
	p_carc_queue_cfg->tce = queue_cfg.carc_tcd;
	p_carc_queue_cfg->te = queue_cfg.carc_tei;
	p_carc_queue_cfg->tc = queue_cfg.carc_tci;

	return rc;
}
DPP_STATUS
dpp_stat_carc_profile_cfg_set(struct dpp_dev_t *dev, u32 profile_id,
			      struct dpp_stat_car_profile_cfg_t *p_carc_profile_cfg)
{
	DPP_STATUS rc = DPP_OK;

	u32 i = 0;

	struct dpp_stat_car0_carc_profile_ram1_255_0_t profile_cfg = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), profile_id, 0, DPP_CAR_C_PROFILE_ID_MAX);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_carc_profile_cfg);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), p_carc_profile_cfg->pkt_sign, 0, 1);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), p_carc_profile_cfg->cf, 0, 1);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), p_carc_profile_cfg->cm, 0, 1);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), p_carc_profile_cfg->random_disc_e, 0, 1);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), p_carc_profile_cfg->random_disc_c, 0, 1);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), p_carc_profile_cfg->cd, CAR_CD_MODE_SRTCM,
				  CAR_CD_MODE_INVALID - 1);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), p_carc_profile_cfg->cir, 0, DPP_CAR_MAX_CIR_VALUE);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), p_carc_profile_cfg->eir, 0, DPP_CAR_MAX_EIR_VALUE);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), p_carc_profile_cfg->cbs, 0, DPP_CAR_MAX_CBS_VALUE);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), p_carc_profile_cfg->ebs, 0, DPP_CAR_MAX_EBS_VALUE);

	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), p_carc_profile_cfg->e_yellow_pri[0], 0,
				  DPP_CAR_MAX_PRI_VALUE);

	for (i = 1; i < DPP_CAR_PRI_MAX; i++) {
		ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), p_carc_profile_cfg->c_pri[i], 0,
					  DPP_CAR_MAX_PRI_VALUE);
		ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), p_carc_profile_cfg->e_green_pri[i], 0,
					  DPP_CAR_MAX_PRI_VALUE);
		ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), p_carc_profile_cfg->e_yellow_pri[i], 0,
					  DPP_CAR_MAX_PRI_VALUE);
	}

	profile_cfg.carc_e_y_pri7 = p_carc_profile_cfg->e_yellow_pri[7];
	profile_cfg.carc_e_y_pri6 = p_carc_profile_cfg->e_yellow_pri[6];
	profile_cfg.carc_e_y_pri5 = p_carc_profile_cfg->e_yellow_pri[5];
	profile_cfg.carc_e_y_pri4 = p_carc_profile_cfg->e_yellow_pri[4];
	profile_cfg.carc_e_y_pri3 = p_carc_profile_cfg->e_yellow_pri[3];
	profile_cfg.carc_e_y_pri2 = p_carc_profile_cfg->e_yellow_pri[2];
	profile_cfg.carc_e_y_pri1 = p_carc_profile_cfg->e_yellow_pri[1];
	profile_cfg.carc_e_y_pri0 = p_carc_profile_cfg->e_yellow_pri[0];

	profile_cfg.carc_e_g_pri7 = p_carc_profile_cfg->e_green_pri[7];
	profile_cfg.carc_e_g_pri6 = p_carc_profile_cfg->e_green_pri[6];
	profile_cfg.carc_e_g_pri5 = p_carc_profile_cfg->e_green_pri[5];
	profile_cfg.carc_e_g_pri4 = p_carc_profile_cfg->e_green_pri[4];
	profile_cfg.carc_e_g_pri3 = p_carc_profile_cfg->e_green_pri[3];
	profile_cfg.carc_e_g_pri2 = p_carc_profile_cfg->e_green_pri[2];
	profile_cfg.carc_e_g_pri1 = p_carc_profile_cfg->e_green_pri[1];

	profile_cfg.carc_c_pri7 = p_carc_profile_cfg->c_pri[7];
	profile_cfg.carc_c_pri6 = p_carc_profile_cfg->c_pri[6];
	profile_cfg.carc_c_pri5 = p_carc_profile_cfg->c_pri[5];
	profile_cfg.carc_c_pri4 = p_carc_profile_cfg->c_pri[4];
	profile_cfg.carc_c_pri3 = p_carc_profile_cfg->c_pri[3];
	profile_cfg.carc_c_pri2 = p_carc_profile_cfg->c_pri[2];
	profile_cfg.carc_c_pri1 = p_carc_profile_cfg->c_pri[1];

	profile_cfg.carc_cbs = p_carc_profile_cfg->cbs;
	profile_cfg.carc_ebs_pbs = p_carc_profile_cfg->ebs;
	profile_cfg.carc_cir = p_carc_profile_cfg->cir;
	profile_cfg.carc_eir = p_carc_profile_cfg->eir;

	profile_cfg.carc_cd = p_carc_profile_cfg->cd;
	profile_cfg.carc_cf = p_carc_profile_cfg->cf;
	profile_cfg.carc_cm = p_carc_profile_cfg->cm;
	profile_cfg.carc_random_discard_en_e = p_carc_profile_cfg->random_disc_e;
	profile_cfg.carc_random_discard_en_c = p_carc_profile_cfg->random_disc_c;

	profile_cfg.carc_pkt_sign = 0;

	profile_cfg.carc_profile_wr = 0;

	rc = dpp_reg_write(dev, STAT_CAR0_CARC_PROFILE_RAM1_255_0r, 0, profile_id, &profile_cfg);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_reg_write");

	return rc;
}
DPP_STATUS
dpp_stat_carc_profile_cfg_get(struct dpp_dev_t *dev, u32 profile_id,
			      struct dpp_stat_car_profile_cfg_t *p_carc_profile_cfg)
{
	DPP_STATUS rc = DPP_OK;
	struct dpp_stat_car0_carc_profile_ram1_255_0_t profile_cfg = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), profile_id, 0, DPP_CAR_C_PROFILE_ID_MAX);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_carc_profile_cfg);

	rc = dpp_reg_read(dev, STAT_CAR0_CARC_PROFILE_RAM1_255_0r, 0, profile_id, &profile_cfg);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_reg_read");

	p_carc_profile_cfg->profile_id = profile_id;
	p_carc_profile_cfg->pkt_sign = profile_cfg.carc_pkt_sign;
	p_carc_profile_cfg->cd = profile_cfg.carc_cd;
	p_carc_profile_cfg->cf = profile_cfg.carc_cf;
	p_carc_profile_cfg->cm = profile_cfg.carc_cm;

	p_carc_profile_cfg->eir = profile_cfg.carc_eir;
	p_carc_profile_cfg->cir = profile_cfg.carc_cir;
	p_carc_profile_cfg->ebs = profile_cfg.carc_ebs_pbs;
	p_carc_profile_cfg->cbs = profile_cfg.carc_cbs;

	p_carc_profile_cfg->random_disc_e = profile_cfg.carc_random_discard_en_e;
	p_carc_profile_cfg->random_disc_c = profile_cfg.carc_random_discard_en_c;

	p_carc_profile_cfg->c_pri[1] = profile_cfg.carc_c_pri1;
	p_carc_profile_cfg->c_pri[2] = profile_cfg.carc_c_pri2;
	p_carc_profile_cfg->c_pri[3] = profile_cfg.carc_c_pri3;
	p_carc_profile_cfg->c_pri[4] = profile_cfg.carc_c_pri4;
	p_carc_profile_cfg->c_pri[5] = profile_cfg.carc_c_pri5;
	p_carc_profile_cfg->c_pri[6] = profile_cfg.carc_c_pri6;
	p_carc_profile_cfg->c_pri[7] = profile_cfg.carc_c_pri7;

	p_carc_profile_cfg->e_green_pri[1] = profile_cfg.carc_e_g_pri1;
	p_carc_profile_cfg->e_green_pri[2] = profile_cfg.carc_e_g_pri2;
	p_carc_profile_cfg->e_green_pri[3] = profile_cfg.carc_e_g_pri3;
	p_carc_profile_cfg->e_green_pri[4] = profile_cfg.carc_e_g_pri4;
	p_carc_profile_cfg->e_green_pri[5] = profile_cfg.carc_e_g_pri5;
	p_carc_profile_cfg->e_green_pri[6] = profile_cfg.carc_e_g_pri6;
	p_carc_profile_cfg->e_green_pri[7] = profile_cfg.carc_e_g_pri7;

	p_carc_profile_cfg->e_yellow_pri[0] = profile_cfg.carc_e_y_pri0;
	p_carc_profile_cfg->e_yellow_pri[1] = profile_cfg.carc_e_y_pri1;
	p_carc_profile_cfg->e_yellow_pri[2] = profile_cfg.carc_e_y_pri2;
	p_carc_profile_cfg->e_yellow_pri[3] = profile_cfg.carc_e_y_pri3;
	p_carc_profile_cfg->e_yellow_pri[4] = profile_cfg.carc_e_y_pri4;
	p_carc_profile_cfg->e_yellow_pri[5] = profile_cfg.carc_e_y_pri5;
	p_carc_profile_cfg->e_yellow_pri[6] = profile_cfg.carc_e_y_pri6;
	p_carc_profile_cfg->e_yellow_pri[7] = profile_cfg.carc_e_y_pri7;

	return rc;
}
DPP_STATUS dpp_stat_carc_queue_qvos_set(struct dpp_dev_t *dev, u32 flow_id, u32 qvos_mode)
{
	DPP_STATUS rc = DPP_OK;
	struct dpp_stat_car0_carc_qovs_ram_ram2_t qvos_cfg = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), flow_id, 0, DPP_CAR_C_FLOW_ID_MAX);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), qvos_mode, CAR_QVOS_MODE_OVERFLOW_0,
				  CAR_QVOS_MODE_OVERFLOW_MAX - 1);

	qvos_cfg.carc_qovs = qvos_mode;

	rc = dpp_reg_write(dev, STAT_CAR0_CARC_QOVS_RAM_RAM2r, 0, flow_id, &qvos_cfg);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_reg_write");

	return rc;
}
DPP_STATUS dpp_stat_carc_queue_qvos_get(struct dpp_dev_t *dev, u32 flow_id, u32 *p_qvos_mode)
{
	DPP_STATUS rc = DPP_OK;
	struct dpp_stat_car0_carc_qovs_ram_ram2_t qvos_cfg = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), flow_id, 0, DPP_CAR_C_FLOW_ID_MAX);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_qvos_mode);

	rc = dpp_reg_read(dev, STAT_CAR0_CARC_QOVS_RAM_RAM2r, 0, flow_id, &qvos_cfg);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_reg_read");

	*p_qvos_mode = qvos_cfg.carc_qovs;

	return rc;
}
DPP_STATUS dpp_stat_carc_random_ram_set(struct dpp_dev_t *dev, u32 profile_id,
					struct dpp_car_random_ram_t *p_random_ram_e,
					struct dpp_car_random_ram_t *p_random_ram_c)
{
	DPP_STATUS rc = DPP_OK;

	u64 para0_temp = 0;
	u64 para2_temp = 0;
	u64 para4_temp = 0;
	struct dpp_stat_car0_carc_random_ram_t carc_random_ram_cfg = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_random_ram_e);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), p_random_ram_e->p1, 0, 100);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), p_random_ram_e->p2, 0, 100);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), p_random_ram_e->p3, 0, 100);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_random_ram_c);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), p_random_ram_c->p1, 0, 100);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), p_random_ram_c->p2, 0, 100);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), p_random_ram_c->p3, 0, 100);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), profile_id, 0, DPP_CAR_C_PROFILE_ID_RANDOM_MAX);

	para0_temp = ((u64)((((u64)(p_random_ram_e->t2)) - ((u64)(p_random_ram_e->t1))) *
			    ((u64)(p_random_ram_e->p1)))
		      << DPP_CAR_RANDOM_OFFSET_VAL) /
		     100;
	carc_random_ram_cfg.para0_l_e = (para0_temp & 0xFFFFFFFF);
	carc_random_ram_cfg.para0_h_e = (para0_temp >> 32) & 0xFFFFFFFF;

	carc_random_ram_cfg.para1_e =
		((p_random_ram_e->p2 - p_random_ram_e->p1) << DPP_CAR_RANDOM_OFFSET_VAL) / 100;

	para2_temp = ((u64)((((u64)(p_random_ram_e->t3)) - ((u64)(p_random_ram_e->t2))) *
			    ((u64)(p_random_ram_e->p2)))
		      << DPP_CAR_RANDOM_OFFSET_VAL) /
		     100;
	carc_random_ram_cfg.para2_l_e = (para2_temp & 0xFFFFFFFF);
	carc_random_ram_cfg.para2_h_e = (para2_temp >> 32) & 0xFFFFFFFF;

	carc_random_ram_cfg.para3_e =
		((p_random_ram_e->p3 - p_random_ram_e->p2) << DPP_CAR_RANDOM_OFFSET_VAL) / 100;

	para4_temp = ((u64)((((u64)(p_random_ram_e->tc)) - ((u64)(p_random_ram_e->t3))) *
			    ((u64)(p_random_ram_e->p3)))
		      << DPP_CAR_RANDOM_OFFSET_VAL) /
		     100;
	carc_random_ram_cfg.para4_l_e = (para4_temp & 0xFFFFFFFF);
	carc_random_ram_cfg.para4_h_e = (para4_temp >> 32) & 0xFFFFFFFF;

	carc_random_ram_cfg.para5_e =
		((100 - p_random_ram_e->p3) << DPP_CAR_RANDOM_OFFSET_VAL) / 100;
	carc_random_ram_cfg.para6_e = p_random_ram_e->t1;
	carc_random_ram_cfg.para7_e = p_random_ram_e->t2;
	carc_random_ram_cfg.para8_e = p_random_ram_e->t3;

	para0_temp = ((u64)((((u64)(p_random_ram_c->t2)) - ((u64)(p_random_ram_c->t1))) *
			    ((u64)(p_random_ram_c->p1)))
		      << DPP_CAR_RANDOM_OFFSET_VAL) /
		     100;
	carc_random_ram_cfg.para0_l_c = (para0_temp & 0xFFFFFFFF);
	carc_random_ram_cfg.para0_h_c = (para0_temp >> 32) & 0xFFFFFFFF;

	carc_random_ram_cfg.para1_c =
		((p_random_ram_c->p2 - p_random_ram_c->p1) << DPP_CAR_RANDOM_OFFSET_VAL) / 100;

	para2_temp = ((u64)((((u64)(p_random_ram_c->t3)) - ((u64)(p_random_ram_c->t2))) *
			    ((u64)(p_random_ram_c->p2)))
		      << DPP_CAR_RANDOM_OFFSET_VAL) /
		     100;
	carc_random_ram_cfg.para2_l_c = (para2_temp & 0xFFFFFFFF);
	carc_random_ram_cfg.para2_h_c = (para2_temp >> 32) & 0xFFFFFFFF;

	carc_random_ram_cfg.para3_c =
		((p_random_ram_c->p3 - p_random_ram_c->p2) << DPP_CAR_RANDOM_OFFSET_VAL) / 100;

	para4_temp = ((u64)((((u64)(p_random_ram_c->tc)) - ((u64)(p_random_ram_c->t3))) *
			    ((u64)(p_random_ram_c->p3)))
		      << DPP_CAR_RANDOM_OFFSET_VAL) /
		     100;
	carc_random_ram_cfg.para4_l_c = (para4_temp & 0xFFFFFFFF);
	carc_random_ram_cfg.para4_h_c = (para4_temp >> 32) & 0xFFFFFFFF;

	carc_random_ram_cfg.para5_c =
		((100 - p_random_ram_c->p3) << DPP_CAR_RANDOM_OFFSET_VAL) / 100;
	carc_random_ram_cfg.para6_c = p_random_ram_c->t1;
	carc_random_ram_cfg.para7_c = p_random_ram_c->t2;
	carc_random_ram_cfg.para8_c = p_random_ram_c->t3;

	rc = dpp_reg_write(dev, STAT_CAR0_CARC_RANDOM_RAMr, 0, profile_id, &carc_random_ram_cfg);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_reg_write");

	return rc;
}
DPP_STATUS dpp_stat_carc_random_ram_get(struct dpp_dev_t *dev, u32 profile_id,
					struct dpp_car_random_ram_t *p_random_ram_e,
					struct dpp_car_random_ram_t *p_random_ram_c)
{
	DPP_STATUS rc = DPP_OK;
	struct dpp_stat_car0_carb_random_ram_t carc_random_ram_cfg = { 0 };
	u32 tmp_val = 0;

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_random_ram_e);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_random_ram_c);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), profile_id, 0, DPP_CAR_C_PROFILE_ID_RANDOM_MAX);

	rc = dpp_reg_read(dev, STAT_CAR0_CARC_RANDOM_RAMr, 0, profile_id, &carc_random_ram_cfg);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_reg_read");

	p_random_ram_e->t1 = carc_random_ram_cfg.para6_e;
	p_random_ram_e->t2 = carc_random_ram_cfg.para7_e;
	p_random_ram_e->t3 = carc_random_ram_cfg.para8_e;
	tmp_val = (carc_random_ram_cfg.para5_e * 100) >> DPP_CAR_RANDOM_OFFSET_VAL;
	p_random_ram_e->p3 = 100 - tmp_val;
	tmp_val = (carc_random_ram_cfg.para3_e * 100) >> DPP_CAR_RANDOM_OFFSET_VAL;
	p_random_ram_e->p2 = p_random_ram_e->p3 - tmp_val;
	tmp_val = (carc_random_ram_cfg.para1_e * 100) >> DPP_CAR_RANDOM_OFFSET_VAL;
	p_random_ram_e->p1 = p_random_ram_e->p2 - tmp_val;

	p_random_ram_c->t1 = carc_random_ram_cfg.para6_c;
	p_random_ram_c->t2 = carc_random_ram_cfg.para7_c;
	p_random_ram_c->t3 = carc_random_ram_cfg.para8_c;
	tmp_val = (carc_random_ram_cfg.para5_c * 100) >> DPP_CAR_RANDOM_OFFSET_VAL;
	p_random_ram_c->p3 = 100 - tmp_val;
	tmp_val = (carc_random_ram_cfg.para3_c * 100) >> DPP_CAR_RANDOM_OFFSET_VAL;
	p_random_ram_c->p2 = p_random_ram_c->p3 - tmp_val;
	tmp_val = (carc_random_ram_cfg.para1_c * 100) >> DPP_CAR_RANDOM_OFFSET_VAL;
	p_random_ram_c->p1 = p_random_ram_c->p2 - tmp_val;

	return rc;
}
DPP_STATUS dpp_stat_car_en_mode_set(struct dpp_dev_t *dev, u32 mode)
{
	DPP_STATUS rc = DPP_OK;
	struct dpp_stat_car0_car_hierarchy_mode_t car_en_mode_cfg = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), mode, DPP_CAR_EN_MODE_BOTH_EN,
				  DPP_CAR_EN_MODE_INVALID - 1);

	car_en_mode_cfg.car_hierarchy_mode = mode;

	rc = dpp_reg_write(dev, STAT_CAR0_CAR_HIERARCHY_MODEr, 0, 0, &car_en_mode_cfg);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_reg_write");

	return rc;
}
DPP_STATUS dpp_stat_car_en_mode_get(struct dpp_dev_t *dev, u32 *p_mode)
{
	DPP_STATUS rc = DPP_OK;
	struct dpp_stat_car0_car_hierarchy_mode_t car_en_mode_cfg = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_mode);

	rc = dpp_reg_read(dev, STAT_CAR0_CAR_HIERARCHY_MODEr, 0, 0, &car_en_mode_cfg);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_reg_read");

	*p_mode = car_en_mode_cfg.car_hierarchy_mode;

	return rc;
}
DPP_STATUS dpp_stat_car_pkt_size_offset_set(struct dpp_dev_t *dev, u32 pkt_size_off)
{
	DPP_STATUS rc = DPP_OK;
	struct dpp_stat_car0_pkt_size_offset_t car_pkt_size_offset = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), pkt_size_off, 0, 0xffffffff);

	car_pkt_size_offset.pkt_size_offset = pkt_size_off;

	rc = dpp_reg_write(dev, STAT_CAR0_PKT_SIZE_OFFSETr, 0, 0, &car_pkt_size_offset);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_reg_write");

	return rc;
}
DPP_STATUS dpp_stat_car_pkt_size_offset_get(struct dpp_dev_t *dev, u32 *p_pkt_size_off)
{
	DPP_STATUS rc = DPP_OK;
	struct dpp_stat_car0_pkt_size_offset_t car_pkt_size_offset = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_pkt_size_off);

	rc = dpp_reg_read(dev, STAT_CAR0_PKT_SIZE_OFFSETr, 0, 0, &car_pkt_size_offset);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_reg_read");

	*p_pkt_size_off = car_pkt_size_offset.pkt_size_offset;

	return rc;
}
DPP_STATUS dpp_stat_cara_max_pkt_size_set(struct dpp_dev_t *dev, u32 max_pkt_size)
{
	DPP_STATUS rc = DPP_OK;
	struct dpp_stat_car0_max_pkt_size_a_t car_max_pkt_size = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), max_pkt_size, 0, 0x3fff);

	car_max_pkt_size.max_pkt_size_a = max_pkt_size;

	rc = dpp_reg_write(dev, STAT_CAR0_MAX_PKT_SIZE_Ar, 0, 0, &car_max_pkt_size);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_reg_write");

	return rc;
}
DPP_STATUS dpp_stat_cara_max_pkt_size_get(struct dpp_dev_t *dev, u32 *p_max_pkt_size)
{
	DPP_STATUS rc = DPP_OK;
	struct dpp_stat_car0_max_pkt_size_a_t car_max_pkt_size = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_max_pkt_size);

	rc = dpp_reg_read(dev, STAT_CAR0_MAX_PKT_SIZE_Ar, 0, 0, &car_max_pkt_size);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_reg_read");

	*p_max_pkt_size = car_max_pkt_size.max_pkt_size_a;

	return rc;
}
DPP_STATUS dpp_stat_carb_max_pkt_size_set(struct dpp_dev_t *dev, u32 max_pkt_size)
{
	DPP_STATUS rc = DPP_OK;
	struct dpp_stat_car0_max_pkt_size_b_t car_max_pkt_size = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), max_pkt_size, 0, 0x3fff);

	car_max_pkt_size.max_pkt_size_b = max_pkt_size;

	rc = dpp_reg_write(dev, STAT_CAR0_MAX_PKT_SIZE_Br, 0, 0, &car_max_pkt_size);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_reg_write");

	return rc;
}
DPP_STATUS dpp_stat_carb_max_pkt_size_get(struct dpp_dev_t *dev, u32 *p_max_pkt_size)
{
	DPP_STATUS rc = DPP_OK;
	struct dpp_stat_car0_max_pkt_size_b_t car_max_pkt_size = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_max_pkt_size);

	rc = dpp_reg_read(dev, STAT_CAR0_MAX_PKT_SIZE_Br, 0, 0, &car_max_pkt_size);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_reg_read");

	*p_max_pkt_size = car_max_pkt_size.max_pkt_size_b;

	return rc;
}
DPP_STATUS dpp_stat_carc_max_pkt_size_set(struct dpp_dev_t *dev, u32 max_pkt_size)
{
	DPP_STATUS rc = DPP_OK;
	struct dpp_stat_car0_max_pkt_size_c_t car_max_pkt_size = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), max_pkt_size, 0, 0x3fff);

	car_max_pkt_size.max_pkt_size_c = max_pkt_size;

	rc = dpp_reg_write(dev, STAT_CAR0_MAX_PKT_SIZE_Cr, 0, 0, &car_max_pkt_size);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_reg_write");

	return rc;
}
DPP_STATUS dpp_stat_carc_max_pkt_size_get(struct dpp_dev_t *dev, u32 *p_max_pkt_size)
{
	DPP_STATUS rc = DPP_OK;
	struct dpp_stat_car0_max_pkt_size_c_t car_max_pkt_size = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_max_pkt_size);

	rc = dpp_reg_read(dev, STAT_CAR0_MAX_PKT_SIZE_Cr, 0, 0, &car_max_pkt_size);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_reg_read");

	*p_max_pkt_size = car_max_pkt_size.max_pkt_size_c;

	return rc;
}

#endif

#if ZXIC_REAL("Advanced Function")

DPP_STATUS dpp_stat_car_queue_cfg_set(struct dpp_dev_t *dev, u32 car_type, u32 flow_id,
				      u32 drop_flag, u32 plcr_en, u32 profile_id)
{
	DPP_STATUS rc = DPP_OK;

	u32 flow_num = 0;

	struct dpp_car_soft_reset_data_t *p_restore_data = NULL;

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), car_type, STAT_CAR_A_TYPE, STAT_CAR_MAX_TYPE - 1);

	if (car_type == STAT_CAR_A_TYPE) {
		ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), flow_id, 0, DPP_CAR_A_FLOW_ID_MAX);
		ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), profile_id, 0, DPP_CAR_A_PROFILE_ID_MAX);
	} else if (car_type == STAT_CAR_B_TYPE) {
		ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), flow_id, 0, DPP_CAR_B_FLOW_ID_MAX);
		ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), profile_id, 0, DPP_CAR_B_PROFILE_ID_MAX);
	} else {
		ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), flow_id, 0, DPP_CAR_C_FLOW_ID_MAX);
		ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), profile_id, 0, DPP_CAR_C_PROFILE_ID_MAX);
	}

	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), drop_flag, 0, 1);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), plcr_en, 0, 1);

	p_restore_data = GET_DPP_CAR_SOFT_RESET_INFO(DEV_ID(dev));

	switch (car_type) {
	case STAT_CAR_A_TYPE: {
		rc = dpp_stat_cara_queue_cfg_set(dev, flow_id, drop_flag, plcr_en, profile_id);
		ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_stat_cara_queue_cfg_set");

		flow_num = p_restore_data->cara_flow_num;
		if (flow_num < DPP_CAR_A_FLOW_ID_NUM) {
			p_restore_data->cara_item[flow_num].flow_id = flow_id;
			p_restore_data->cara_item[flow_num].profile_id = profile_id;
			ZXIC_COMM_CHECK_DEV_INDEX_ADD_OVERFLOW(DEV_ID(dev),
							       p_restore_data->cara_flow_num, 1);
			p_restore_data->cara_flow_num++;
		}

	} break;

	case STAT_CAR_B_TYPE: {
		rc = dpp_stat_carb_queue_cfg_set(dev, flow_id, drop_flag, plcr_en, profile_id);
		ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_stat_carb_queue_cfg_set");

		flow_num = p_restore_data->carb_flow_num;
		if (flow_num < DPP_CAR_B_FLOW_ID_NUM) {
			p_restore_data->carb_item[flow_num].flow_id = flow_id;
			p_restore_data->carb_item[flow_num].profile_id = profile_id;
			ZXIC_COMM_CHECK_DEV_INDEX_ADD_OVERFLOW(DEV_ID(dev),
							       p_restore_data->carb_flow_num, 1);
			p_restore_data->carb_flow_num++;
		}

	} break;

	case STAT_CAR_C_TYPE: {
		rc = dpp_stat_carc_queue_cfg_set(dev, flow_id, drop_flag, plcr_en, profile_id);
		ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_stat_carc_queue_cfg_set");

		flow_num = p_restore_data->carc_flow_num;
		if (flow_num < DPP_CAR_C_FLOW_ID_NUM) {
			p_restore_data->carc_item[flow_num].flow_id = flow_id;
			p_restore_data->carc_item[flow_num].profile_id = profile_id;
			ZXIC_COMM_CHECK_DEV_INDEX_ADD_OVERFLOW_NO_ASSERT(
				DEV_ID(dev), p_restore_data->carc_flow_num, 1);
			p_restore_data->carc_flow_num++;
		}

	} break;
	}

	return rc;
}
DPP_STATUS dpp_stat_car_queue_get(struct dpp_dev_t *dev, u32 car_type, u32 pkt_sign, u32 flow_id,
				  void *p_data)
{
	DPP_STATUS rc = DPP_OK;

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), car_type, STAT_CAR_A_TYPE, STAT_CAR_MAX_TYPE - 1);

	if (car_type == STAT_CAR_A_TYPE) {
		ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), pkt_sign, 0, 1);
		ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), flow_id, 0, DPP_CAR_A_FLOW_ID_MAX);
	} else if (car_type == STAT_CAR_B_TYPE) {
		ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), flow_id, 0, DPP_CAR_B_FLOW_ID_MAX);
	} else {
		ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), flow_id, 0, DPP_CAR_C_FLOW_ID_MAX);
	}

	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_data);

	switch (car_type) {
	case STAT_CAR_A_TYPE: {
		if (pkt_sign == 0) {
			rc = dpp_stat_cara_queue_cfg_get(
				dev, flow_id, (struct dpp_stat_car_a_queue_cfg_t *)p_data);
			ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_stat_cara_queue_cfg_get");
		} else {
			rc = dpp_stat_cara_pkt_queue_cfg_get(
				dev, flow_id, (struct dpp_stat_car_a_pkt_queue_cfg_t *)p_data);
			ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_stat_cara_pkt_queue_cfg_get");
		}

	} break;

	case STAT_CAR_B_TYPE: {
		rc = dpp_stat_carb_queue_cfg_get(dev, flow_id,
						 (struct dpp_stat_car_b_queue_cfg_t *)p_data);
		ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_stat_carb_queue_cfg_get");
	} break;

	case STAT_CAR_C_TYPE: {
		rc = dpp_stat_carc_queue_cfg_get(dev, flow_id,
						 (struct dpp_stat_car_c_queue_cfg_t *)p_data);
		ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_stat_carc_queue_cfg_get");
	} break;
	}

	return rc;
}
DPP_STATUS dpp_stat_car_queue_cfg_get(struct dpp_dev_t *dev, u32 car_type, u32 flow_id,
				      u32 *p_drop_flag, u32 *p_plcr_en, u32 *p_profile_id)
{
	DPP_STATUS rc = DPP_OK;
	struct dpp_stat_car_a_queue_cfg_t car_a_queue_cfg = { 0 };
	struct dpp_stat_car_b_queue_cfg_t car_b_queue_cfg = { 0 };
	struct dpp_stat_car_c_queue_cfg_t car_c_queue_cfg = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), car_type, STAT_CAR_A_TYPE, STAT_CAR_MAX_TYPE - 1);

	if (car_type == STAT_CAR_A_TYPE)
		ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), flow_id, 0, DPP_CAR_A_FLOW_ID_MAX);
	else if (car_type == STAT_CAR_B_TYPE)
		ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), flow_id, 0, DPP_CAR_B_FLOW_ID_MAX);
	else
		ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), flow_id, 0, DPP_CAR_C_FLOW_ID_MAX);

	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_drop_flag);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_plcr_en);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_profile_id);

	switch (car_type) {
	case STAT_CAR_A_TYPE: {
		rc = dpp_stat_cara_queue_cfg_get(dev, flow_id, &car_a_queue_cfg);
		ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_stat_cara_queue_cfg_get");

		*p_profile_id = car_a_queue_cfg.profile_id;
		*p_plcr_en = car_a_queue_cfg.plcr_en;
		*p_drop_flag = car_a_queue_cfg.drop_flag;
	} break;

	case STAT_CAR_B_TYPE: {
		rc = dpp_stat_carb_queue_cfg_get(dev, flow_id, &car_b_queue_cfg);
		ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_stat_carb_queue_cfg_get");

		*p_profile_id = car_b_queue_cfg.profile_id;
		*p_plcr_en = car_b_queue_cfg.plcr_en;
		*p_drop_flag = car_b_queue_cfg.drop_flag;
	} break;

	case STAT_CAR_C_TYPE: {
		rc = dpp_stat_carc_queue_cfg_get(dev, flow_id, &car_c_queue_cfg);
		ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_stat_carc_queue_cfg_get");

		*p_profile_id = car_c_queue_cfg.profile_id;
		*p_plcr_en = car_c_queue_cfg.plcr_en;
		*p_drop_flag = car_c_queue_cfg.drop_flag;
	} break;
	}

	return rc;
}
DPP_STATUS dpp_stat_car_profile_cfg_set(struct dpp_dev_t *dev, u32 car_type, u32 pkt_sign,
					u32 profile_id, void *p_car_profile_cfg)
{
	DPP_STATUS rc = DPP_OK;

	struct dpp_car_soft_reset_data_t *p_restore_data = NULL;
	struct dpp_stat_car_profile_cfg_t *p_stat_car_profile_cfg = NULL;
	struct dpp_stat_car_pkt_profile_cfg_t *p_stat_pkt_car_profile_cfg = NULL;

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), car_type, STAT_CAR_A_TYPE, STAT_CAR_MAX_TYPE - 1);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), pkt_sign, 0, 1);

	if (car_type == STAT_CAR_A_TYPE)
		ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), profile_id, 0, DPP_CAR_A_PROFILE_ID_MAX);
	else if (car_type == STAT_CAR_B_TYPE)
		ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), profile_id, 0, DPP_CAR_B_PROFILE_ID_MAX);
	else
		ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), profile_id, 0, DPP_CAR_C_PROFILE_ID_MAX);

	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_car_profile_cfg);

	p_restore_data = GET_DPP_CAR_SOFT_RESET_INFO(DEV_ID(dev));

	if ((car_type == STAT_CAR_A_TYPE) && (pkt_sign == 1)) {
		p_stat_pkt_car_profile_cfg =
			(struct dpp_stat_car_pkt_profile_cfg_t *)p_car_profile_cfg;

		rc = dpp_stat_cara_pkt_profile_cfg_set(dev, profile_id, p_stat_pkt_car_profile_cfg);
		ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_stat_cara_pkt_profile_cfg_set");

		p_restore_data->car_pkt_sign[profile_id] = ZXIC_TRUE;

		ZXIC_COMM_CHECK_DEV_INDEX_ADD_OVERFLOW_NO_ASSERT(DEV_ID(dev),
								 p_restore_data->car0_pkt_num, 1);
		p_restore_data->car0_pkt_num++;
	} else {
		p_stat_car_profile_cfg = (struct dpp_stat_car_profile_cfg_t *)p_car_profile_cfg;
		ZXIC_COMM_TRACE_DEV_INFO(DEV_ID(dev), "==> dpp stat_car_profile_cfg_set :\n");
		ZXIC_COMM_TRACE_DEV_INFO(DEV_ID(dev), "| %-10s | %-10s | %-10s | %-10s |\n",
					 "profile_id", "car_id", "car_type", "pkt_sign");
		ZXIC_COMM_TRACE_DEV_INFO(DEV_ID(dev), "| %-10d | %-10d | %-10d | 0x%-8x |\n",
					 profile_id, 0, car_type, pkt_sign);
		ZXIC_COMM_TRACE_DEV_INFO(DEV_ID(dev),
					 "| ------------------------------------------------- |\n");
		ZXIC_COMM_TRACE_DEV_INFO(DEV_ID(dev),
					 "| %-5s | %-5s | %-5s | %-10s | %-10s | %-10s | %-10s |\n",
					 "cd", "cf", "cm", "cir", "cbs", "eir", "ebs");
		ZXIC_COMM_TRACE_DEV_INFO(DEV_ID(dev),
					 "| %-5d | %-5d | %-5d | %-10d | %-10d | %-10d | %-10d |\n",
					 p_stat_car_profile_cfg->cd, p_stat_car_profile_cfg->cf,
					 p_stat_car_profile_cfg->cm, p_stat_car_profile_cfg->cir,
					 p_stat_car_profile_cfg->cbs, p_stat_car_profile_cfg->eir,
					 p_stat_car_profile_cfg->ebs);

		if (car_type == STAT_CAR_A_TYPE) {
			rc = dpp_stat_cara_profile_cfg_set(dev, profile_id, p_stat_car_profile_cfg);
			ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_stat_cara_profile_cfg_set");

			if (p_restore_data->car_pkt_sign[profile_id] == ZXIC_TRUE) {
				p_restore_data->car0_pkt_num--;
				p_restore_data->car_pkt_sign[profile_id] = ZXIC_FALSE;
			}
		} else if (car_type == STAT_CAR_B_TYPE) {
			rc = dpp_stat_carb_profile_cfg_set(dev, profile_id, p_stat_car_profile_cfg);
			ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_stat_carb_profile_cfg_set");
		} else {
			rc = dpp_stat_carc_profile_cfg_set(dev, profile_id, p_stat_car_profile_cfg);
			ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_stat_carc_profile_cfg_set");
		}
	}

	return rc;
}
DPP_STATUS dpp_stat_car_profile_cfg_get(struct dpp_dev_t *dev, u32 car_type, u32 pkt_sign,
					u32 profile_id, void *p_car_profile_cfg)
{
	DPP_STATUS rc = DPP_OK;
	struct dpp_stat_car_profile_cfg_t *p_stat_car_profile_cfg = NULL;
	struct dpp_stat_car_pkt_profile_cfg_t *p_stat_pkt_car_profile_cfg = NULL;

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), car_type, STAT_CAR_A_TYPE, STAT_CAR_MAX_TYPE - 1);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), pkt_sign, 0, 1);

	if (car_type == STAT_CAR_A_TYPE)
		ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), profile_id, 0, DPP_CAR_A_PROFILE_ID_MAX);
	else if (car_type == STAT_CAR_B_TYPE)
		ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), profile_id, 0, DPP_CAR_B_PROFILE_ID_MAX);
	else
		ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), profile_id, 0, DPP_CAR_C_PROFILE_ID_MAX);

	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_car_profile_cfg);

	if ((car_type == STAT_CAR_A_TYPE) && (pkt_sign == 1)) {
		p_stat_pkt_car_profile_cfg =
			(struct dpp_stat_car_pkt_profile_cfg_t *)p_car_profile_cfg;
		rc = dpp_stat_cara_pkt_profile_cfg_get(dev, profile_id, p_stat_pkt_car_profile_cfg);
		ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_stat_cara_pkt_profile_cfg_get");
	} else {
		p_stat_car_profile_cfg = (struct dpp_stat_car_profile_cfg_t *)p_car_profile_cfg;

		if (car_type == STAT_CAR_A_TYPE) {
			rc = dpp_stat_cara_profile_cfg_get(dev, profile_id, p_stat_car_profile_cfg);
			ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_stat_cara_profile_cfg_get");
		} else if (car_type == STAT_CAR_B_TYPE) {
			rc = dpp_stat_carb_profile_cfg_get(dev, profile_id, p_stat_car_profile_cfg);
			ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_stat_carb_profile_cfg_get");
		} else {
			rc = dpp_stat_carc_profile_cfg_get(dev, profile_id, p_stat_car_profile_cfg);
			ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_stat_carc_profile_cfg_get");
		}
	}

	return rc;
}
DPP_STATUS dpp_stat_car_queue_map_set(struct dpp_dev_t *dev, u32 car_type, u32 flow_id,
				      u32 map_flow_id, u32 map_sp)
{
	DPP_STATUS rc = DPP_OK;

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), car_type, STAT_CAR_A_TYPE, STAT_CAR_B_TYPE);

	if (car_type == STAT_CAR_A_TYPE) {
		ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), flow_id, 0, DPP_CAR_A_FLOW_ID_MAX);
		ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), map_flow_id, 0, DPP_CAR_B_FLOW_ID_MAX);
		ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), map_sp, DPP_CAR_PRI0, DPP_CAR_PRI_MAX - 1);
		rc = dpp_stat_cara_queue_map_set(dev, flow_id, map_flow_id, map_sp);
		ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_stat_cara_queue_map_set");
	} else {
		ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), flow_id, 0, DPP_CAR_B_FLOW_ID_MAX);
		ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), map_flow_id, 0, DPP_CAR_C_FLOW_ID_MAX);
		ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), map_sp, DPP_CAR_PRI0, DPP_CAR_PRI_MAX - 1);
		rc = dpp_stat_carb_queue_map_set(dev, flow_id, map_flow_id, map_sp);
		ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_stat_carb_queue_map_set");
	}

	return rc;
}
DPP_STATUS dpp_stat_car_queue_map_get(struct dpp_dev_t *dev, u32 car_type, u32 flow_id,
				      u32 *p_map_flow_id, u32 *p_map_sp)
{
	DPP_STATUS rc = DPP_OK;

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), car_type, STAT_CAR_A_TYPE, STAT_CAR_B_TYPE);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_map_flow_id);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_map_sp);

	if (car_type == STAT_CAR_A_TYPE) {
		ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), flow_id, 0, DPP_CAR_A_FLOW_ID_MAX);
		rc = dpp_stat_cara_queue_map_get(dev, flow_id, p_map_flow_id, p_map_sp);
		ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_stat_cara_queue_map_get");
	} else {
		ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), flow_id, 0, DPP_CAR_B_FLOW_ID_MAX);
		rc = dpp_stat_carb_queue_map_get(dev, flow_id, p_map_flow_id, p_map_sp);
		ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_stat_carb_queue_map_get");
	}

	return rc;
}
DPP_STATUS dpp_stat_car_random_ram_set(struct dpp_dev_t *dev, u32 car_type, u32 profile_id,
				       struct dpp_car_random_ram_t *p_random_ram_e,
				       struct dpp_car_random_ram_t *p_random_ram_c)
{
	DPP_STATUS rc = DPP_OK;

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), car_type, STAT_CAR_B_TYPE, STAT_CAR_C_TYPE);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_random_ram_e);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_random_ram_c);

	if (car_type == STAT_CAR_B_TYPE) {
		ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), profile_id, 0,
					  DPP_CAR_B_PROFILE_ID_RANDOM_MAX);
		rc = dpp_stat_carb_random_ram_set(dev, profile_id, p_random_ram_e, p_random_ram_c);
		ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_stat_carb_random_ram_set");
	} else {
		ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), profile_id, 0,
					  DPP_CAR_C_PROFILE_ID_RANDOM_MAX);
		rc = dpp_stat_carc_random_ram_set(dev, profile_id, p_random_ram_e, p_random_ram_c);
		ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_stat_carc_random_ram_set");
	}

	return rc;
}
DPP_STATUS dpp_stat_car_random_ram_get(struct dpp_dev_t *dev, u32 car_type, u32 profile_id,
				       struct dpp_car_random_ram_t *p_random_ram_e,
				       struct dpp_car_random_ram_t *p_random_ram_c)
{
	DPP_STATUS rc = DPP_OK;

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), car_type, STAT_CAR_B_TYPE, STAT_CAR_C_TYPE);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_random_ram_e);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_random_ram_c);

	if (car_type == STAT_CAR_B_TYPE) {
		ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), profile_id, 0,
					  DPP_CAR_B_PROFILE_ID_RANDOM_MAX);
		rc = dpp_stat_carb_random_ram_get(dev, profile_id, p_random_ram_e, p_random_ram_c);
		ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_stat_carb_random_ram_get");
	} else {
		ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), profile_id, 0,
					  DPP_CAR_C_PROFILE_ID_RANDOM_MAX);
		rc = dpp_stat_carc_random_ram_get(dev, profile_id, p_random_ram_e, p_random_ram_c);
		ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_stat_carc_random_ram_get");
	}

	return rc;
}
DPP_STATUS dpp_stat_car_max_pkt_size_get(struct dpp_dev_t *dev, u32 car_type, u32 *p_max_pkt_len)
{
	DPP_STATUS rc = DPP_OK;
	u32 pkt_len = 0;

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), car_type, STAT_CAR_A_TYPE, STAT_CAR_MAX_TYPE - 1);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_max_pkt_len);

	switch (car_type) {
	case STAT_CAR_A_TYPE: {
		rc = dpp_stat_cara_max_pkt_size_get(dev, &pkt_len);
		ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_stat_cara_max_pkt_size_get");
	} break;

	case STAT_CAR_B_TYPE: {
		rc = dpp_stat_carb_max_pkt_size_get(dev, &pkt_len);
		ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_stat_carb_max_pkt_size_get");
	} break;

	case STAT_CAR_C_TYPE: {
		rc = dpp_stat_carc_max_pkt_size_get(dev, &pkt_len);
		ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_stat_carc_max_pkt_size_get");
	} break;
	}

	*p_max_pkt_len = pkt_len;

	return rc;
}
DPP_STATUS dpp_stat_car_max_pkt_size_set(struct dpp_dev_t *dev, u32 car_type, u32 max_pkt_size)
{
	DPP_STATUS rc = DPP_OK;

	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), car_type, STAT_CAR_A_TYPE, STAT_CAR_MAX_TYPE - 1);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), max_pkt_size, 0, 0x3fff);

	switch (car_type) {
	case STAT_CAR_A_TYPE: {
		rc = dpp_stat_cara_max_pkt_size_set(dev, max_pkt_size);
		ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_stat_cara_max_pkt_size_set");
	} break;

	case STAT_CAR_B_TYPE: {
		rc = dpp_stat_carb_max_pkt_size_set(dev, max_pkt_size);
		ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_stat_carb_max_pkt_size_set");
	} break;

	case STAT_CAR_C_TYPE: {
		rc = dpp_stat_carc_max_pkt_size_set(dev, max_pkt_size);
		ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_stat_carc_max_pkt_size_set");
	} break;
	}

	return rc;
}
DPP_STATUS dpp_stat_car_glb_size_get(struct dpp_dev_t *dev, u32 *p_size)
{
	DPP_STATUS rc = DPP_OK;

	u32 queue_num = 0;
	u32 profile_num = 0;
	u32 pkt_profile_num = 0;

	struct dpp_car_soft_reset_data_t *p_g_restore_data = NULL;

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_size);

	p_g_restore_data = GET_DPP_CAR_SOFT_RESET_INFO(DEV_ID(dev));

	if (p_g_restore_data->is_init == 0) {
		ZXIC_COMM_PRINT("Not init!!!\n");
		*p_size = sizeof(u32);
	} else {
		/* CAR A */
		ZXIC_COMM_CHECK_DEV_INDEX_ADD_OVERFLOW_NO_ASSERT(DEV_ID(dev), queue_num,
								 p_g_restore_data->cara_flow_num);
		queue_num += p_g_restore_data->cara_flow_num;

		/* CAR B */
		ZXIC_COMM_CHECK_DEV_INDEX_ADD_OVERFLOW_NO_ASSERT(DEV_ID(dev), queue_num,
								 p_g_restore_data->carb_flow_num);
		queue_num += p_g_restore_data->carb_flow_num;

		/* CAR C */
		ZXIC_COMM_CHECK_DEV_INDEX_ADD_OVERFLOW_NO_ASSERT(DEV_ID(dev), queue_num,
								 p_g_restore_data->carc_flow_num);
		queue_num += p_g_restore_data->carc_flow_num;

		pkt_profile_num = p_g_restore_data->car0_pkt_num;
		ZXIC_COMM_CHECK_DEV_INDEX_SUB_OVERFLOW_NO_ASSERT(DEV_ID(dev),
								 (DPP_CAR_A_PROFILE_ID_MAX +
								  DPP_CAR_B_PROFILE_ID_MAX +
								  DPP_CAR_C_PROFILE_ID_MAX + 3),
								 pkt_profile_num);
		profile_num = DPP_CAR_A_PROFILE_ID_MAX + DPP_CAR_B_PROFILE_ID_MAX +
			      DPP_CAR_C_PROFILE_ID_MAX + 3 - pkt_profile_num;

		ZXIC_COMM_CHECK_DEV_INDEX_MUL_OVERFLOW_NO_ASSERT(
			DEV_ID(dev), queue_num,
			((u32)ZXIC_SIZEOF(struct dpp_car_soft_reset_queue_t)));
		ZXIC_COMM_CHECK_DEV_INDEX_MUL_OVERFLOW_NO_ASSERT(
			DEV_ID(dev), pkt_profile_num,
			((u32)ZXIC_SIZEOF(struct dpp_stat_car_pkt_profile_cfg_t)));
		ZXIC_COMM_CHECK_DEV_INDEX_MUL_OVERFLOW_NO_ASSERT(
			DEV_ID(dev), profile_num,
			((u32)ZXIC_SIZEOF(struct dpp_stat_car_profile_cfg_t)));
		*p_size = ((u32)ZXIC_SIZEOF(u32)) * 5 +
			  queue_num * ((u32)ZXIC_SIZEOF(struct dpp_car_soft_reset_queue_t)) +
			  pkt_profile_num *
				  ((u32)ZXIC_SIZEOF(struct dpp_stat_car_pkt_profile_cfg_t)) +
			  profile_num * ((u32)ZXIC_SIZEOF(struct dpp_stat_car_profile_cfg_t));
		ZXIC_COMM_PRINT("glb_size = %d!!!\n", *p_size);
	}

	return rc;
}

#endif
