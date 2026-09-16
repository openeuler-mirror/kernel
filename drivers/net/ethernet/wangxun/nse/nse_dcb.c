// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2018 - 2021 Beijing WangXun Technology Co., Ltd. */

#include "nse_common.h"
#include "nse_sched.h"
#include "nse_dcb.h"
#include "nse_dcb_lib.h"

/**
 * nse_get_dcb_cfg
 * @pi: port information structure
 *
 * Get DCB configuration from the Firmware
 */
enum nse_status nse_get_dcb_cfg(struct nse_port_info *pi)
{
	enum nse_status ret;
	struct nse_aqc_qos_db_cfg *db_cfg = NULL;

	if (!pi)
		return NSE_ERR_PARAM;

	db_cfg = kzalloc(sizeof(*db_cfg), GFP_KERNEL);
	if (!db_cfg)
		return NSE_ERR_NO_MEMORY;

	ret = nse_aq_qos_db_get_cfg(pi->hw, db_cfg);

	if (!ret) {
		nse_save_dcbx_cfg_from_aqc(pi->hw, &pi->qos_cfg.local_dcbx_cfg, db_cfg, true);
		nse_save_dcbx_cfg_from_aqc(pi->hw, &pi->qos_cfg.remote_dcbx_cfg, db_cfg, false);
	}

	kfree(db_cfg);

	return ret;
}

static void dump_dbcfg_amber(struct nse_hw *hw, struct nse_aqc_qos_db_cfg_amber *dbcfg)
{
	struct device *dev = nse_hw_to_dev(hw);
	int i, j;

		dev_info(dev, "\t eth_grp_id=%d\n",
							dbcfg->eth_grp_id);
		dev_info(dev, "\t dcbx_cfg_flags=0x%X\n",
							le32_to_cpu(dbcfg->dcbx_cfg_flags));
		dev_info(dev, "\t sch_tree_flags=0x%X\n",
							le32_to_cpu(dbcfg->sch_tree_flags));

		dev_info(dev, "\t ====== RPB:\n");
		dev_info(dev, "\t\t rpb_pb_ctl_vld=%d\n", le32_to_cpu(dbcfg->rpb_pb_ctl_vld));
		dev_info(dev, "\t\t rpb_pb_ctl_value=0x%X\n", le32_to_cpu(dbcfg->rpb_pb_ctl_value));
		dev_info(dev, "\t\t rpb_pb_sz_vld=%d\n", le32_to_cpu(dbcfg->rpb_pb_sz_vld));
		for (i = 0; i < 8; i++)
			dev_info(dev, "\t\t rpb_pb_sz_value[%d]=0x%X\n",
						i, le32_to_cpu(dbcfg->rpb_pb_sz_value[i]));
		dev_info(dev, "\t\t rpb_share_sz_vld=%d\n", le32_to_cpu(dbcfg->rpb_share_sz_vld));
		dev_info(dev, "\t\t rpb_share_sz_value=0x%X\n",
			 le32_to_cpu(dbcfg->rpb_share_sz_value));
		dev_info(dev, "\t\t rpb_pbrarb_ctl_vld=%d\n",
			 le32_to_cpu(dbcfg->rpb_pbrarb_ctl_vld));
		dev_info(dev, "\t\t rpb_pbrarb_ctl_value=0x%X\n",
			 le32_to_cpu(dbcfg->rpb_pbrarb_ctl_value));
		dev_info(dev, "\t\t rpb_pbrarb_credit_vld=%d\n",
			 le32_to_cpu(dbcfg->rpb_pbrarb_credit_vld));
		for (i = 0; i < 8; i++)
			dev_info(dev, "\t\t rpb_pbrarb_credit_value[%d]=0x%X\n",
						i, le32_to_cpu(dbcfg->rpb_pbrarb_credit_value[i]));
		dev_info(dev, "\t\t rpb_ovfl_time_vld=%d\n", le32_to_cpu(dbcfg->rpb_ovfl_time_vld));
		dev_info(dev, "\t\t rpb_ovfl_time_value=0x%X\n",
			 le32_to_cpu(dbcfg->rpb_ovfl_time_value));
		dev_info(dev, "\t\t rpb_dhw_vld=%d\n", le32_to_cpu(dbcfg->rpb_dhw_vld));
		for (i = 0; i < 8; i++)
			dev_info(dev, "\t\t rpb_dhw_value[%d]=0x%X\n",
						i, le32_to_cpu(dbcfg->rpb_dhw_value[i]));
		dev_info(dev, "\t\t rpb_dlw_vld=%d\n", le32_to_cpu(dbcfg->rpb_dlw_vld));
		for (i = 0; i < 8; i++)
			dev_info(dev, "\t\t rpb_dlw_value[%d]=0x%X\n",
						i, le32_to_cpu(dbcfg->rpb_dlw_value[i]));
		dev_info(dev, "\t\t rpb_sht_vld=%d\n", le32_to_cpu(dbcfg->rpb_sht_vld));
		for (i = 0; i < 8; i++)
			dev_info(dev, "\t\t rpb_sht_value[%d]=0x%X\n",
						i, le32_to_cpu(dbcfg->rpb_sht_value[i]));
		dev_info(dev, "\t\t rpb_slt_vld=%d\n", le32_to_cpu(dbcfg->rpb_slt_vld));
		for (i = 0; i < 8; i++)
			dev_info(dev, "\t\t rpb_slt_value[%d]=0x%X\n",
						i, le32_to_cpu(dbcfg->rpb_slt_value[i]));
		dev_info(dev, "\t\t rpb_shw_vld=%d\n", le32_to_cpu(dbcfg->rpb_shw_vld));
		dev_info(dev, "\t\t rpb_shw_value=0x%X\n", le32_to_cpu(dbcfg->rpb_shw_value));
		dev_info(dev, "\t\t rpb_slw_vld=%d\n", le32_to_cpu(dbcfg->rpb_slw_vld));
		dev_info(dev, "\t\t rpb_slw_value=0x%X\n", le32_to_cpu(dbcfg->rpb_slw_value));
		dev_info(dev, "\t\t rpb_ghw_vld=%d\n", le32_to_cpu(dbcfg->rpb_ghw_vld));
		dev_info(dev, "\t\t rpb_ghw_value=0x%X\n", le32_to_cpu(dbcfg->rpb_ghw_value));
		dev_info(dev, "\t\t rpb_glw_vld=%d\n", le32_to_cpu(dbcfg->rpb_glw_vld));
		dev_info(dev, "\t\t rpb_glw_value=0x%X\n", le32_to_cpu(dbcfg->rpb_glw_value));
		dev_info(dev, "\t\t rpb_up2tc_vld=%d\n", le32_to_cpu(dbcfg->rpb_up2tc_vld));
		dev_info(dev, "\t\t rpb_up2tc_value=0x%X\n", le32_to_cpu(dbcfg->rpb_up2tc_value));
		dev_info(dev, "\t\t rpb_tc2pfc_vld=%d\n", le32_to_cpu(dbcfg->rpb_tc2pfc_vld));
		dev_info(dev, "\t\t rpb_tc2pfc_value=0x%X\n", le32_to_cpu(dbcfg->rpb_tc2pfc_value));
		dev_info(dev, "\t\t rpb_lltc_vld=%d\n", le32_to_cpu(dbcfg->rpb_lltc_vld));
		dev_info(dev, "\t\t rpb_lltc_value=0x%X\n", le32_to_cpu(dbcfg->rpb_lltc_value));

		dev_info(dev, "\t ====== RDB:\n");
		dev_info(dev, "\t\t rdb_pb_ctl_vld=%d\n", le32_to_cpu(dbcfg->rdb_pb_ctl_vld));
		dev_info(dev, "\t\t rdb_pb_ctl_value=0x%X\n", le32_to_cpu(dbcfg->rdb_pb_ctl_value));
		dev_info(dev, "\t\t rdb_pbwarb_ctl_vld=%d\n",
			 le32_to_cpu(dbcfg->rdb_pbwarb_ctl_vld));
		dev_info(dev, "\t\t rdb_pbwarb_ctl_value=0x%X\n",
			 le32_to_cpu(dbcfg->rdb_pbwarb_ctl_value));
		dev_info(dev, "\t\t rdb_pbwarb_credit_vld=%d\n",
			 le32_to_cpu(dbcfg->rdb_pbwarb_credit_vld));
		dev_info(dev, "\t\t rdb_pbwarb_credit_value[0]=0x%X\n",
			 le32_to_cpu(dbcfg->rdb_pbwarb_credit_value[0]));
		dev_info(dev, "\t\t rdb_pbwarb_credit_value[1]=0x%X\n",
			 le32_to_cpu(dbcfg->rdb_pbwarb_credit_value[1]));
		dev_info(dev, "\t\t rdb_pbrarb_ctl_vld=%d\n",
			 le32_to_cpu(dbcfg->rdb_pbrarb_ctl_vld));
		dev_info(dev, "\t\t rdb_pbrarb_ctl_value=0x%X\n",
			 le32_to_cpu(dbcfg->rdb_pbrarb_ctl_value));
		dev_info(dev, "\t\t rdb_pbrarb_credit_vld=%d\n",
			 le32_to_cpu(dbcfg->rdb_pbrarb_credit_vld));
		for (i = 0; i < 7; i++)
			dev_info(dev, "\t\t rdb_pbrarb_credit_value[%d]=0x%X\n",
				 i, le32_to_cpu(dbcfg->rdb_pbrarb_credit_value[i]));

		dev_info(dev, "\t ====== TDB:\n");
		dev_info(dev, "\t\t tdb_pb_ctl_vld=%d\n", le32_to_cpu(dbcfg->tdb_pb_ctl_vld));
		dev_info(dev, "\t\t tdb_pb_ctl_value=0x%X\n", le32_to_cpu(dbcfg->tdb_pb_ctl_value));
		dev_info(dev, "\t\t tdb_pb_sz_vld=%d\n", le32_to_cpu(dbcfg->tdb_pb_sz_vld));
		dev_info(dev, "\t\t tdb_pb_sz_egrps_bitmap=0x%X\n",
			 le32_to_cpu(dbcfg->tdb_pb_sz_egrps_bitmap));
		for (i = 0; i < 4; i++) {
			for (j = 0; j < 8; j++) {
				dev_info(dev, "\t\t tdb_pb_sz_egrps_values[%d][%d]=0x%X\n",
					 i, j, le32_to_cpu(dbcfg->tdb_pb_sz_egrps_values[i][j]));
			}
		}
		dev_info(dev, "\t\t tdb_share_sz_vld=%d\n", le32_to_cpu(dbcfg->tdb_share_sz_vld));
		dev_info(dev, "\t\t tdb_share_sz_value=0x%X\n",
			 le32_to_cpu(dbcfg->tdb_share_sz_value));
		dev_info(dev, "\t\t tdb_sht_vld=%d\n", le32_to_cpu(dbcfg->tdb_sht_vld));
		dev_info(dev, "\t\t tdb_sht_egrps_bitmap=0x%X\n",
			 le32_to_cpu(dbcfg->tdb_sht_egrps_bitmap));
		for (i = 0; i < 4; i++) {
			for (j = 0; j < 8; j++) {
				dev_info(dev, "\t\t tdb_sht_egrps_values[%d][%d]=0x%X\n",
					 i, j, le32_to_cpu(dbcfg->tdb_sht_egrps_values[i][j]));
			}
		}
		dev_info(dev, "\t\t tdb_pbwarb_credit_vld=%d\n",
			 le32_to_cpu(dbcfg->tdb_pbwarb_credit_vld));
		dev_info(dev, "\t\t tdb_pbwarb_credit_value[0]=0x%X\n",
			 le32_to_cpu(dbcfg->tdb_pbwarb_credit_value[0]));
		dev_info(dev, "\t\t tdb_pbwarb_credit_value[1]=0x%X\n",
			 le32_to_cpu(dbcfg->tdb_pbwarb_credit_value[1]));
		dev_info(dev, "\t\t tdb_pbrarb_ctl_vld=%d\n",
			 le32_to_cpu(dbcfg->tdb_pbrarb_ctl_vld));
		dev_info(dev, "\t\t tdb_pbrarb_ctl_value=0x%X\n",
			 le32_to_cpu(dbcfg->tdb_pbrarb_ctl_value));
		dev_info(dev, "\t\t tdb_pbrarb_credit_vld=%d\n",
			 le32_to_cpu(dbcfg->tdb_pbrarb_credit_vld));
		for (i = 0; i < 4; i++)
			dev_info(dev, "\t\t tdb_pbrarb_credit_value[%d]=0x%X\n",
				 i, le32_to_cpu(dbcfg->tdb_pbrarb_credit_value[i]));
		dev_info(dev, "\t\t tdb_tcpbrarb_credit_vld=%d\n",
			 le32_to_cpu(dbcfg->tdb_tcpbrarb_credit_vld));
		dev_info(dev, "\t\t tdb_tcpbrarb_credit_egrps_bitmap=0x%X\n",
			 le32_to_cpu(dbcfg->tdb_tcpbrarb_credit_egrps_bitmap));
		for (i = 0; i < 4; i++) {
			for (j = 0; j < 8; j++) {
				dev_info(dev, "\t\t tdb_tcpbrarb_credit_egrps_values[%d][%d]=0x%X\n",
					i, j,
					le32_to_cpu(dbcfg->tdb_tcpbrarb_credit_egrps_values[i][j]));
			}
		}

		dev_info(dev, "\t ====== TRT:\n");
		dev_info(dev, "\t\t trt_ctl_vld=%d\n", le32_to_cpu(dbcfg->trt_ctl_vld));
		dev_info(dev, "\t\t trt_ctl_value=0x%X\n", le32_to_cpu(dbcfg->trt_ctl_value));
		dev_info(dev, "\t\t trt_pb_sz_lan_dedicate_vld=%d\n",
			 le32_to_cpu(dbcfg->trt_pb_sz_lan_dedicate_vld));
		dev_info(dev, "\t\t trt_pb_sz_lan_dedicate_bitmap=0x%X\n",
			 le32_to_cpu(dbcfg->trt_pb_sz_lan_dedicate_bitmap));
		for (i = 0; i < 2; i++) {
			for (j = 0; j < 8; j++) {
				dev_info(dev, "\t\t trt_pb_sz_lan_dedicate_values[%d][%d]=0x%X\n",
					i, j,
					le32_to_cpu(dbcfg->trt_pb_sz_lan_dedicate_values[i][j]));
			}
		}
		dev_info(dev, "\t\t trt_pb_sz_tmp_buf_vld=%d\n",
			 le32_to_cpu(dbcfg->trt_pb_sz_tmp_buf_vld));
		dev_info(dev, "\t\t trt_pb_sz_tmp_buf_value=0x%X\n",
			 le32_to_cpu(dbcfg->trt_pb_sz_tmp_buf_value));
		dev_info(dev, "\t\t trt_share_sz_vld=%d\n", le32_to_cpu(dbcfg->trt_share_sz_vld));
		dev_info(dev, "\t\t trt_share_sz_value=0x%X\n",
			 le32_to_cpu(dbcfg->trt_share_sz_value));
		dev_info(dev, "\t\t trt_sht_lan_dedicate_vld=%d\n",
			 le32_to_cpu(dbcfg->trt_sht_lan_dedicate_vld));
		dev_info(dev, "\t\t trt_sht_lan_dedicate_bitmap=0x%X\n",
			 le32_to_cpu(dbcfg->trt_sht_lan_dedicate_bitmap));
		for (i = 0; i < 2; i++) {
			for (j = 0; j < 8; j++) {
				dev_info(dev, "\t\t trt_sht_lan_dedicate_values[%d][%d]=0x%X\n",
					i, j,
					le32_to_cpu(dbcfg->trt_sht_lan_dedicate_values[i][j]));
			}
		}
		dev_info(dev, "\t\t trt_sht_tmp_buf_vld=%d\n",
			 le32_to_cpu(dbcfg->trt_sht_tmp_buf_vld));
		dev_info(dev, "\t\t trt_sht_tmp_buf_value=0x%X\n",
			 le32_to_cpu(dbcfg->trt_sht_tmp_buf_value));
		dev_info(dev, "\t\t trt_pbrarb_ctl_vld=%d\n",
			 le32_to_cpu(dbcfg->trt_pbrarb_ctl_vld));
		dev_info(dev, "\t\t trt_pbrarb_ctl_value=0x%X\n",
			 le32_to_cpu(dbcfg->trt_pbrarb_ctl_value));
		dev_info(dev, "\t\t trt_pbrarb_credit_vld=%d\n",
			 le32_to_cpu(dbcfg->trt_pbrarb_credit_vld));
		dev_info(dev, "\t\t trt_pbrarb_credit_lan_bitmap=0x%X\n",
			 le32_to_cpu(dbcfg->trt_pbrarb_credit_lan_bitmap));
		for (i = 0; i < 2; i++) {
			for (j = 0; j < 8; j++) {
				dev_info(dev, "\t\t trt_pbrarb_credit_lan_values[%d][%d]=0x%X\n",
					i, j,
					le32_to_cpu(dbcfg->trt_pbrarb_credit_lan_values[i][j]));
			}
		}
		dev_info(dev, "\t\t trt_mng_tc_vld=%d\n", le32_to_cpu(dbcfg->trt_mng_tc_vld));
		dev_info(dev, "\t\t trt_mng_tc_value=0x%X\n", le32_to_cpu(dbcfg->trt_mng_tc_value));
		dev_info(dev, "\t\t trt_up2tc_lan0_vld=%d\n",
			 le32_to_cpu(dbcfg->trt_up2tc_lan0_vld));
		dev_info(dev, "\t\t trt_up2tc_lan0_value=0x%X\n",
			 le32_to_cpu(dbcfg->trt_up2tc_lan0_value));
		dev_info(dev, "\t\t trt_up2tc_lan1_vld=%d\n",
			 le32_to_cpu(dbcfg->trt_up2tc_lan1_vld));
		dev_info(dev, "\t\t trt_up2tc_lan1_value=0x%X\n",
			 le32_to_cpu(dbcfg->trt_up2tc_lan1_value));
		dev_info(dev, "\t\t trt_sch_cfg_lan0_vld=%d\n",
			 le32_to_cpu(dbcfg->trt_sch_cfg_lan0_vld));
		dev_info(dev, "\t\t trt_sch_cfg_lan0_value=0x%X\n",
			 le32_to_cpu(dbcfg->trt_sch_cfg_lan0_value));
		dev_info(dev, "\t\t trt_sch_cfg_lan1_vld=%d\n",
			 le32_to_cpu(dbcfg->trt_sch_cfg_lan1_vld));
		dev_info(dev, "\t\t trt_sch_cfg_lan1_value=0x%X\n",
			 le32_to_cpu(dbcfg->trt_sch_cfg_lan1_value));
		dev_info(dev, "\t\t trt_exoff_thres_vld=%d\n",
			 le32_to_cpu(dbcfg->trt_exoff_thres_vld));
		dev_info(dev, "\t\t trt_exoff_thres_value=0x%X\n",
			 le32_to_cpu(dbcfg->trt_exoff_thres_value));
		dev_info(dev, "\t\t trt_1us_tick_cnt_vld=%d\n",
			 le32_to_cpu(dbcfg->trt_1us_tick_cnt_vld));
		dev_info(dev, "\t\t trt_1us_tick_cnt_value=0x%X\n",
			 le32_to_cpu(dbcfg->trt_1us_tick_cnt_value));
		dev_info(dev, "\t\t trt_lksts_fltr_vld=%d\n",
			 le32_to_cpu(dbcfg->trt_lksts_fltr_vld));
		dev_info(dev, "\t\t trt_lksts_fltr_value=0x%X\n",
			 le32_to_cpu(dbcfg->trt_lksts_fltr_value));

		dev_info(dev, "\t ====== LMAC:\n");
		dev_info(dev, "\t\t lmac_rx_flow_ctl_vld=%d\n",
			 le32_to_cpu(dbcfg->lmac_rx_flow_ctl_vld));
		dev_info(dev, "\t\t lmac_rx_flow_ctl_value=0x%X\n",
			 le32_to_cpu(dbcfg->lmac_rx_flow_ctl_value));
		dev_info(dev, "\t\t lmac_tx_flow_ctl_vld=%d\n",
			 le32_to_cpu(dbcfg->lmac_tx_flow_ctl_vld));
		for (i = 0; i < 8; i++)
			dev_info(dev, "\t\t lmac_tx_flow_ctl_value[%d]=0x%X\n",
				 i, le32_to_cpu(dbcfg->lmac_tx_flow_ctl_value[i]));
		dev_info(dev, "\t\t lmac_rxq_prio_mapping_ctrl_vld=%d\n",
			 le32_to_cpu(dbcfg->lmac_rxq_prio_mapping_ctrl_vld));
		for (i = 0; i < 2; i++)
			dev_info(dev, "\t\t lmac_rxq_prio_mapping_ctrl_value[%d]=0x%X\n",
				 i, le32_to_cpu(dbcfg->lmac_rxq_prio_mapping_ctrl_value[i]));
}

static void dump_dbcfg_ms(struct nse_hw *hw, struct nse_aqc_qos_db_cfg_ms *dbcfg)
{
	struct device *dev = nse_hw_to_dev(hw);
	int i;

		dev_info(dev, "\t dcbx_cfg_flags=0x%X\n",
							le32_to_cpu(dbcfg->dcbx_cfg_flags));

		dev_info(dev, "\t ====== RPB:\n");

		dev_info(dev, "\t\t rpb_pb_ctl_vld=%d\n", le32_to_cpu(dbcfg->rpb_pb_ctl_vld));
		dev_info(dev, "\t\t rpb_pb_ctl_value=0x%X\n", le32_to_cpu(dbcfg->rpb_pb_ctl_value));

		dev_info(dev, "\t\t rpb_tc_dedicate_sz_vld=%d\n",
			 le32_to_cpu(dbcfg->rpb_tc_dedicate_sz_vld));
		for (i = 0; i < 8; i++)
			dev_info(dev, "\t\t rpb_tc_dedicate_sz_value[%d]=0x%X\n",
						i, le32_to_cpu(dbcfg->rpb_tc_dedicate_sz_value[i]));

		dev_info(dev, "\t\t rpb_tc_share_sz_vld=%d\n",
			 le32_to_cpu(dbcfg->rpb_tc_share_sz_vld));
		for (i = 0; i < 8; i++)
			dev_info(dev, "\t\t rpb_tc_share_sz_value[%d]=0x%X\n",
						i, le32_to_cpu(dbcfg->rpb_tc_share_sz_value[i]));

		dev_info(dev, "\t\t rpb_tc_dhw_vld=%d\n", le32_to_cpu(dbcfg->rpb_tc_dhw_vld));
		for (i = 0; i < 8; i++)
			dev_info(dev, "\t\t rpb_tc_dhw_value[%d]=0x%X\n",
						i, le32_to_cpu(dbcfg->rpb_tc_dhw_value[i]));

		dev_info(dev, "\t\t rpb_tc_dlw_vld=%d\n", le32_to_cpu(dbcfg->rpb_tc_dlw_vld));
		for (i = 0; i < 8; i++)
			dev_info(dev, "\t\t rpb_tc_dlw_value[%d]=0x%X\n",
						i, le32_to_cpu(dbcfg->rpb_tc_dlw_value[i]));

		dev_info(dev, "\t\t rpb_tc_slw_vld=%d\n", le32_to_cpu(dbcfg->rpb_tc_slw_vld));
		for (i = 0; i < 8; i++)
			dev_info(dev, "\t\t rpb_tc_slw_value[%d]=0x%X\n",
						i, le32_to_cpu(dbcfg->rpb_tc_slw_value[i]));

		dev_info(dev, "\t\t rpb_tc2pfc_vld=%d\n", le32_to_cpu(dbcfg->rpb_tc2pfc_vld));
		dev_info(dev, "\t\t rpb_tc2pfc_value=0x%X\n", le32_to_cpu(dbcfg->rpb_tc2pfc_value));

		dev_info(dev, "\t\t rpb_lltc_vld=%d\n", le32_to_cpu(dbcfg->rpb_lltc_vld));
		dev_info(dev, "\t\t rpb_lltc_value=0x%X\n", le32_to_cpu(dbcfg->rpb_lltc_value));

		dev_info(dev, "\t\t rpb_arb_credit_vld=%d\n",
			 le32_to_cpu(dbcfg->rpb_arb_credit_vld));
		for (i = 0; i < 8; i++)
			dev_info(dev, "\t\t rpb_arb_credit_value[%d]=0x%X\n",
						i, le32_to_cpu(dbcfg->rpb_arb_credit_value[i]));

		dev_info(dev, "\t\t rpb_ovfl_en_vld=%d\n", le32_to_cpu(dbcfg->rpb_ovfl_en_vld));
		dev_info(dev, "\t\t rpb_ovfl_en_value=0x%X\n",
			 le32_to_cpu(dbcfg->rpb_ovfl_en_value));

		dev_info(dev, "\t\t rpb_ovfl_time_vld=%d\n", le32_to_cpu(dbcfg->rpb_ovfl_time_vld));
		dev_info(dev, "\t\t rpb_ovfl_time_value=0x%X\n",
			 le32_to_cpu(dbcfg->rpb_ovfl_time_value));

		dev_info(dev, "\t\t rpb_port_ctl_vld=%d\n", le32_to_cpu(dbcfg->rpb_port_ctl_vld));
		dev_info(dev, "\t\t rpb_port_ctl_value=0x%X\n",
			 le32_to_cpu(dbcfg->rpb_port_ctl_value));

		dev_info(dev, "\t\t rpb_port_share_sz_vld=%d\n",
			 le32_to_cpu(dbcfg->rpb_port_share_sz_vld));
		dev_info(dev, "\t\t rpb_port_share_sz_value=0x%X\n",
			 le32_to_cpu(dbcfg->rpb_port_share_sz_value));

		dev_info(dev, "\t\t rpb_port_ghw_vld=%d\n", le32_to_cpu(dbcfg->rpb_port_ghw_vld));
		dev_info(dev, "\t\t rpb_port_ghw_value=0x%X\n",
			 le32_to_cpu(dbcfg->rpb_port_ghw_value));

		dev_info(dev, "\t\t rpb_port_glw_vld=%d\n", le32_to_cpu(dbcfg->rpb_port_glw_vld));
		dev_info(dev, "\t\t rpb_port_glw_value=0x%X\n",
			 le32_to_cpu(dbcfg->rpb_port_glw_value));

		dev_info(dev, "\t\t rpb_port_shw_vld=%d\n", le32_to_cpu(dbcfg->rpb_port_shw_vld));
		dev_info(dev, "\t\t rpb_port_shw_value=0x%X\n",
			 le32_to_cpu(dbcfg->rpb_port_shw_value));

		dev_info(dev, "\t\t rpb_port_slw_vld=%d\n", le32_to_cpu(dbcfg->rpb_port_slw_vld));
		dev_info(dev, "\t\t rpb_port_slw_value=0x%X\n",
			 le32_to_cpu(dbcfg->rpb_port_slw_value));

		dev_info(dev, "\t\t rpb_port_up2tc_vld=%d\n",
			 le32_to_cpu(dbcfg->rpb_port_up2tc_vld));
		dev_info(dev, "\t\t rpb_port_up2tc_value=0x%X\n",
			 le32_to_cpu(dbcfg->rpb_port_up2tc_value));

		dev_info(dev, "\t\t rpb_port_vlan2up_ctrl_vld=%d\n",
			 le32_to_cpu(dbcfg->rpb_port_vlan2up_ctrl_vld));
		dev_info(dev, "\t\t rpb_port_vlan2up_ctrl_value=0x%X\n",
			 le32_to_cpu(dbcfg->rpb_port_vlan2up_ctrl_value));

		dev_info(dev, "\t ====== RDB:\n");

		dev_info(dev, "\t\t rdb_pb_ctl_vld=%d\n", le32_to_cpu(dbcfg->rdb_pb_ctl_vld));
		dev_info(dev, "\t\t rdb_pb_ctl_value=0x%X\n", le32_to_cpu(dbcfg->rdb_pb_ctl_value));

		dev_info(dev, "\t\t rdb_pbrarb_ctl_vld=%d\n",
			 le32_to_cpu(dbcfg->rdb_pbrarb_ctl_vld));
		dev_info(dev, "\t\t rdb_pbrarb_ctl_value=0x%X\n",
			 le32_to_cpu(dbcfg->rdb_pbrarb_ctl_value));

		dev_info(dev, "\t\t rdb_pbrarb_credit_vld=%d\n",
			 le32_to_cpu(dbcfg->rdb_pbrarb_credit_vld));
		for (i = 0; i < 7; i++)
			dev_info(dev, "\t\t rdb_pbrarb_credit_value[%d]=0x%X\n",
				 i, le32_to_cpu(dbcfg->rdb_pbrarb_credit_value[i]));

		dev_info(dev, "\t\t rdb_stall_time_vld=%d\n",
			 le32_to_cpu(dbcfg->rdb_stall_time_vld));
		dev_info(dev, "\t\t rdb_stall_time_value=0x%X\n",
			 le32_to_cpu(dbcfg->rdb_stall_time_value));

		dev_info(dev, "\t ====== TDB:\n");

		dev_info(dev, "\t\t tdb_pb_ctl_vld=%d\n", le32_to_cpu(dbcfg->tdb_pb_ctl_vld));
		dev_info(dev, "\t\t tdb_pb_ctl_value=0x%X\n", le32_to_cpu(dbcfg->tdb_pb_ctl_value));

		dev_info(dev, "\t\t tdb_pb_sz_vld=%d\n", le32_to_cpu(dbcfg->tdb_pb_sz_vld));
		for (i = 0; i < 8; i++) {
			dev_info(dev, "\t\t tdb_pb_sz_value[%d]=0x%X\n",
							i, le32_to_cpu(dbcfg->tdb_pb_sz_value[i]));
		}

		dev_info(dev, "\t\t tdb_share_sz_vld=%d\n", le32_to_cpu(dbcfg->tdb_share_sz_vld));
		dev_info(dev, "\t\t tdb_share_sz_value=0x%X\n",
			 le32_to_cpu(dbcfg->tdb_share_sz_value));

		dev_info(dev, "\t\t tdb_sht_vld=%d\n", le32_to_cpu(dbcfg->tdb_sht_vld));
		for (i = 0; i < 8; i++) {
			dev_info(dev, "\t\t tdb_sht_value[%d]=0x%X\n",
							i, le32_to_cpu(dbcfg->tdb_sht_value[i]));
		}

		dev_info(dev, "\t\t tdb_pbwarb_credit_vld=%d\n",
			 le32_to_cpu(dbcfg->tdb_pbwarb_credit_vld));
		dev_info(dev, "\t\t tdb_pbwarb_credit_value[0]=0x%X\n",
			 le32_to_cpu(dbcfg->tdb_pbwarb_credit_value[0]));
		dev_info(dev, "\t\t tdb_pbwarb_credit_value[1]=0x%X\n",
			 le32_to_cpu(dbcfg->tdb_pbwarb_credit_value[1]));

		dev_info(dev, "\t\t tdb_pbrarb_ctl_vld=%d\n",
			 le32_to_cpu(dbcfg->tdb_pbrarb_ctl_vld));
		dev_info(dev, "\t\t tdb_pbrarb_ctl_value=0x%X\n",
			 le32_to_cpu(dbcfg->tdb_pbrarb_ctl_value));

		dev_info(dev, "\t\t tdb_tcpbrarb_credit_vld=%d\n",
			 le32_to_cpu(dbcfg->tdb_tcpbrarb_credit_vld));
		for (i = 0; i < 8; i++) {
			dev_info(dev, "\t\t tdb_tcpbrarb_credit_value[%d]=0x%X\n",
				 i, le32_to_cpu(dbcfg->tdb_tcpbrarb_credit_value[i]));
		}

		dev_info(dev, "\t ====== LMAC:\n");

		dev_info(dev, "\t\t lmac_tx_pause_en_vld=%d\n",
			 le32_to_cpu(dbcfg->lmac_tx_pause_en_vld));
		dev_info(dev, "\t\t lmac_tx_pause_en_value=0x%X\n",
			 le32_to_cpu(dbcfg->lmac_tx_pause_en_value));

		dev_info(dev, "\t\t lmac_retransmit_xoff_holdoff_en_vld=%d\n",
			 le32_to_cpu(dbcfg->lmac_retransmit_xoff_holdoff_en_vld));
		dev_info(dev, "\t\t lmac_retransmit_xoff_holdoff_en_value=0x%X\n",
			 le32_to_cpu(dbcfg->lmac_retransmit_xoff_holdoff_en_value));

		dev_info(dev, "\t\t lmac_retransmit_xoff_holdoff_quanta_vld=%d\n",
			 le32_to_cpu(dbcfg->lmac_retransmit_xoff_holdoff_quanta_vld));
		dev_info(dev, "\t\t lmac_retransmit_xoff_holdoff_quanta_value=0x%X\n",
			 le32_to_cpu(dbcfg->lmac_retransmit_xoff_holdoff_quanta_value));

		dev_info(dev, "\t\t lmac_tx_pause_quanta_vld=%d\n",
			 le32_to_cpu(dbcfg->lmac_tx_pause_quanta_vld));
		dev_info(dev, "\t\t lmac_tx_pause_quanta_value=0x%X\n",
			 le32_to_cpu(dbcfg->lmac_tx_pause_quanta_value));

		dev_info(dev, "\t\t lmac_tx_xof_en_tx_pause_qnumber_vld=%d\n",
			 le32_to_cpu(dbcfg->lmac_tx_xof_en_tx_pause_qnumber_vld));
		dev_info(dev, "\t\t lmac_tx_xof_en_tx_pause_qnumber_value=0x%X\n",
			 le32_to_cpu(dbcfg->lmac_tx_xof_en_tx_pause_qnumber_value));

		dev_info(dev, "\t\t lmac_cfg_retransmit_holdoff_en_vld=%d\n",
			 le32_to_cpu(dbcfg->lmac_cfg_retransmit_holdoff_en_vld));
		dev_info(dev, "\t\t lmac_cfg_retransmit_holdoff_en_value=0x%X\n",
			 le32_to_cpu(dbcfg->lmac_cfg_retransmit_holdoff_en_value));

		dev_info(dev, "\t\t lmac_cfg_retransmit_holdoff_quanta_vld=%d\n",
			 le32_to_cpu(dbcfg->lmac_cfg_retransmit_holdoff_quanta_vld));
		dev_info(dev, "\t\t lmac_cfg_retransmit_holdoff_quanta_value=0x%X\n",
			 le32_to_cpu(dbcfg->lmac_cfg_retransmit_holdoff_quanta_value));

		dev_info(dev, "\t\t lmac_txsfc_ehip_cfg_vld=%d\n",
			 le32_to_cpu(dbcfg->lmac_txsfc_ehip_cfg_vld));
		dev_info(dev, "\t\t lmac_txsfc_ehip_cfg_value=0x%X\n",
			 le32_to_cpu(dbcfg->lmac_txsfc_ehip_cfg_value));

		dev_info(dev, "\t\t lmac_rx_pause_enable_vld=%d\n",
			 le32_to_cpu(dbcfg->lmac_rx_pause_enable_vld));
		dev_info(dev, "\t\t lmac_rx_pause_enable_value=0x%X\n",
			 le32_to_cpu(dbcfg->lmac_rx_pause_enable_value));

		dev_info(dev, "\t\t lmac_rx_pause_fwd_vld=%d\n",
			 le32_to_cpu(dbcfg->lmac_rx_pause_fwd_vld));
		dev_info(dev, "\t\t lmac_rx_pause_fwd_value=0x%X\n",
			 le32_to_cpu(dbcfg->lmac_rx_pause_fwd_value));

		dev_info(dev, "\t\t lmac_rxsfc_ehip_cfg_vld=%d\n",
			 le32_to_cpu(dbcfg->lmac_rxsfc_ehip_cfg_vld));
		dev_info(dev, "\t\t lmac_rxsfc_ehip_cfg_value=0x%X\n",
			 le32_to_cpu(dbcfg->lmac_rxsfc_ehip_cfg_value));

		dev_info(dev, "\t\t lmac_pfc_pause_quanta_vld=%d\n",
			 le32_to_cpu(dbcfg->lmac_pfc_pause_quanta_vld));
		for (i = 0; i < 8; i++) {
			dev_info(dev, "\t\t lmac_pfc_pause_quanta_value[%d]=0x%X\n",
				 i, le32_to_cpu(dbcfg->lmac_pfc_pause_quanta_value[i]));
		}

		dev_info(dev, "\t\t lmac_pfc_holdoff_quanta_vld=%d\n",
			 le32_to_cpu(dbcfg->lmac_pfc_holdoff_quanta_vld));
		for (i = 0; i < 8; i++) {
			dev_info(dev, "\t\t lmac_pfc_holdoff_quanta_value[%d]=0x%X\n",
				 i, le32_to_cpu(dbcfg->lmac_pfc_holdoff_quanta_value[i]));
		}
}

void
nse_dump_dcbcfg_and_dbcfg(struct nse_hw *hw,
						struct nse_dcbx_cfg *dcbcfg,
						struct nse_aqc_qos_db_cfg *dbcfg)
{
	struct device *dev = nse_hw_to_dev(hw);

	if (dcbcfg) {
		dev_info(dev, "=== dcbcfg:\n");

		dev_info(dev, "\t etscfg:\n");
		dev_info(dev, "\t\t willing=%d\n", dcbcfg->etscfg.willing);
		dev_info(dev, "\t\t cbs=%d\n", dcbcfg->etscfg.cbs);
		dev_info(dev, "\t\t maxtcs=%d\n", dcbcfg->etscfg.maxtcs);
		dev_info(dev, "\t\t prio_table[8]=%d %d %d %d %d %d %d %d\n",
						dcbcfg->etscfg.prio_table[0],
						dcbcfg->etscfg.prio_table[1],
						dcbcfg->etscfg.prio_table[2],
						dcbcfg->etscfg.prio_table[3],
						dcbcfg->etscfg.prio_table[4],
						dcbcfg->etscfg.prio_table[5],
						dcbcfg->etscfg.prio_table[6],
						dcbcfg->etscfg.prio_table[7]);
		dev_info(dev, "\t\t tcbwtable[8]=%d %d %d %d %d %d %d %d\n",
						dcbcfg->etscfg.tcbwtable[0],
						dcbcfg->etscfg.tcbwtable[1],
						dcbcfg->etscfg.tcbwtable[2],
						dcbcfg->etscfg.tcbwtable[3],
						dcbcfg->etscfg.tcbwtable[4],
						dcbcfg->etscfg.tcbwtable[5],
						dcbcfg->etscfg.tcbwtable[6],
						dcbcfg->etscfg.tcbwtable[7]);
		dev_info(dev, "\t\t tsatable[8]=%d %d %d %d %d %d %d %d\n",
						dcbcfg->etscfg.tsatable[0],
						dcbcfg->etscfg.tsatable[1],
						dcbcfg->etscfg.tsatable[2],
						dcbcfg->etscfg.tsatable[3],
						dcbcfg->etscfg.tsatable[4],
						dcbcfg->etscfg.tsatable[5],
						dcbcfg->etscfg.tsatable[6],
						dcbcfg->etscfg.tsatable[7]);

		dev_info(dev, "\t pfc:\n");
		dev_info(dev, "\t\t willing=%d\n", dcbcfg->pfc.willing);
		dev_info(dev, "\t\t mbc=%d\n", dcbcfg->pfc.mbc);
		dev_info(dev, "\t\t pfccap=0x%X\n", dcbcfg->pfc.pfccap);
		dev_info(dev, "\t\t pfcena=0x%X\n", dcbcfg->pfc.pfcena);
	}

	if (dbcfg) {
		dev_info(dev, "=== dbcfg:\n");

		nse_aqc_dump_generic_common_hdr(hw, &dbcfg->hdr);

		if (hw->mac_type == NSE_MAC_TYPE_AMBER)
			dump_dbcfg_amber(hw, &dbcfg->amber);
		else if (hw->mac_type == NSE_MAC_TYPE_MOONSTONE)
			dump_dbcfg_ms(hw, &dbcfg->ms);
	}
}

static void
dcbcfg_to_dbcfg_amber(struct nse_hw *hw,
						struct nse_aqc_qos_db_cfg_amber *dbcfg,
						struct nse_dcbx_cfg *dcbcfg,
						bool set_all_or_this_lan)
{
	struct nse_port_info *pi = hw->port_info;
	struct nse_fc_info *fc_info = &pi->lmac_phy_info.fc_info;
	int i = 0, j = 0;
	u8 ena_tc_num = nse_dcb_get_num_tc(dcbcfg);
	u32 val = 0, val_2 = 0;
	unsigned int egrps_cnt;

	dbcfg->eth_grp_id = hw->port_info->curr_eth_grp_id;

	dbcfg->dcbx_cfg_flags = cpu_to_le32(QOS_DCBX_CFG_FLAG_LOCAL);

	memcpy(&dbcfg->local_dcbx_cfg, dcbcfg, sizeof(dbcfg->local_dcbx_cfg));

	/****************************************
	 *
	 * RPB setting translate
	 *
	 ****************************************/

	/* enable RPB */
	dbcfg->rpb_pb_ctl_vld = cpu_to_le32(1);
	dbcfg->rpb_pb_ctl_value = cpu_to_le32(RPB_PB_CTL_EN_M);

	if (nse_qos_db_use_share) {
		/* use shared instead of dedicated
		 */

		/* set all dedicated buffer to be 0 */
		dbcfg->rpb_pb_sz_vld = cpu_to_le32(1);
		for (i = 0; i < 8; i++)
			dbcfg->rpb_pb_sz_value[i] = 0;

		/* all use shared buffer */
		dbcfg->rpb_share_sz_vld = cpu_to_le32(1);

		val = (hw->is_only_lan_in_chan) ? hw->hw_conf.rpb_pb_total_size_per_lan_channel :
			hw->hw_conf.rpb_pb_total_size_per_lan;
		val <<= RPB_PB_SZ_SIZE_S;
		dbcfg->rpb_share_sz_value = cpu_to_le32(val);

	} else {
		/* equally divide per-TC dedicate buffer
		 */

		dbcfg->rpb_pb_sz_vld = cpu_to_le32(1);

		val = (hw->is_only_lan_in_chan) ? hw->hw_conf.rpb_pb_total_size_per_lan_channel :
			hw->hw_conf.rpb_pb_total_size_per_lan;
		val = val / ena_tc_num;

		val <<= RPB_PB_SZ_SIZE_S;
		for (i = 0; i < ena_tc_num; i++)
			dbcfg->rpb_pb_sz_value[i] = cpu_to_le32(val);

		/* the rest disabled TC are already memset(0) in nse_dcbcfg_to_dbcfg() */

		/* do not use share buffer */
		dbcfg->rpb_share_sz_vld = cpu_to_le32(1);
		dbcfg->rpb_share_sz_value = cpu_to_le32(0);
	}

	/* use WRR, do not use WSP */
	dbcfg->rpb_pbrarb_ctl_vld = cpu_to_le32(1);
	dbcfg->rpb_pbrarb_ctl_value = cpu_to_le32((RPB_PBRARB_CTL_RPPAC_WRR <<
						  RPB_PBRARB_CTL_RPPAC_S));

	dbcfg->rpb_pbrarb_credit_vld = cpu_to_le32(1);

	val = RPB_PBRARB_CREDIT_VAL_SP_MAX;
	for (i = (ena_tc_num - 1); i >= 0; i--) {
		/* TC value higher, its priority order are higher */
		if (dcbcfg->etscfg.tsatable[i] == IEEE_8021QAZ_TSA_STRICT) {
			dbcfg->rpb_pbrarb_credit_value[i] =
				cpu_to_le32((val & RPB_PBRARB_CREDIT_VAL_M));
			if (val > RPB_PBRARB_CREDIT_VAL_SP_MIN)
				val >>= 1;
		} else if (dcbcfg->etscfg.tsatable[i] == IEEE_8021QAZ_TSA_ETS) {
			val_2 =
			(RPB_PBRARB_CREDIT_VAL_ETS_TOTAL * dcbcfg->etscfg.tcbwtable[i]) / 100;
			dbcfg->rpb_pbrarb_credit_value[i] =
				cpu_to_le32((val_2 & RPB_PBRARB_CREDIT_VAL_M));
		}
	}

	/* don't use this feature */
	dbcfg->rpb_ovfl_time_vld = cpu_to_le32(0);

	if (nse_qos_db_use_share) {
		dbcfg->rpb_dhw_vld = cpu_to_le32(1);
		dbcfg->rpb_dlw_vld = cpu_to_le32(1);

		/* no dedicated buffer, then no its dedicated watermark */
		for (i = 0; i < 8; i++) {
			dbcfg->rpb_dhw_value[i] = 0;
			dbcfg->rpb_dlw_value[i] = 0;
		}

		/*  for each TC, for using shared buffer: high watermark: 3/4 (trigger XOFF), low
		 * watermark: 1/4 (trigger XON)
		 */
		/* for all shared buffer total, also use this watermark setting .*/

		dbcfg->rpb_sht_vld = cpu_to_le32(1);
		dbcfg->rpb_slt_vld = cpu_to_le32(1);

		/* bits 19:10 is in unit of KB, the whole register is in unit of bytes */
		val = le32_to_cpu(dbcfg->rpb_share_sz_value);

		val_2 = val / 4;	/* low watermark: 1/4 (trigger XON) */
		val = val_2 * 3;	/* high watermark: 3/4 (trigger XOFF) */

		val &= RPB_WM_THRES_VAL_M;		/* mask 3:0, align to 16-bytes */
		val_2 &= RPB_WM_THRES_VAL_M;

#if defined(NSE_DEBUG_EXT)
		if (nse_qos_db_test_fc_tx) {
			val = NSE_QOS_DB_RPB_SMALL_HTHRES;
			val_2 = NSE_QOS_DB_RPB_SMALL_LTHRES;
		}
#endif

		for (i = 0; i < 8; i++) {
			dbcfg->rpb_sht_value[i] = cpu_to_le32(val);
			dbcfg->rpb_slt_value[i] = cpu_to_le32(val_2);
		}

		dbcfg->rpb_shw_vld = cpu_to_le32(1);
		dbcfg->rpb_slw_vld = cpu_to_le32(1);

		dbcfg->rpb_shw_value = cpu_to_le32(val);
		dbcfg->rpb_slw_value = cpu_to_le32(val_2);

#if defined(NSE_DEBUG_EXT)
		if (nse_qos_db_test_fc_tx) {
			//NSE_QOS_DB_RPB_SMALL_HTHRES x 4
			dbcfg->rpb_shw_value = cpu_to_le32(val * 4);
			//NSE_QOS_DB_RPB_SMALL_LTHRES x 4
			dbcfg->rpb_slw_value = cpu_to_le32(val_2 * 4);
		}
#endif

	} else {
		/*  dedicated buffer: high watermark: 3/4 (trigger XOFF), low watermark: 1/4
		 * (trigger XON)
		 */
		dbcfg->rpb_dhw_vld = cpu_to_le32(1);
		dbcfg->rpb_dlw_vld = cpu_to_le32(1);

		for (i = 0; i < ena_tc_num; i++) {
			/* bits 19:10 is in unit of KB, the whole register is in unit of bytes */
			val = le32_to_cpu(dbcfg->rpb_pb_sz_value[i]);

			val_2 = val / 4;	/* low watermark: 1/4 (trigger XON) */
			val = val_2 * 3;	/* high watermark: 3/4 (trigger XOFF) */

			val &= RPB_WM_THRES_VAL_M;		/* mask 3:0, align 16-bytes */
			val_2 &= RPB_WM_THRES_VAL_M;

			dbcfg->rpb_dhw_value[i] = cpu_to_le32(val);
			dbcfg->rpb_dlw_value[i] = cpu_to_le32(val_2);
		}

		/* share buffer: don't use, set its high/low watermark to 0
		 *
		 * their values are already memset(0) in nse_dcbcfg_to_dbcfg()
		 */
		dbcfg->rpb_sht_vld = cpu_to_le32(1);
		dbcfg->rpb_slt_vld = cpu_to_le32(1);
		dbcfg->rpb_shw_vld = cpu_to_le32(1);
		dbcfg->rpb_slw_vld = cpu_to_le32(1);
	}

	/* global high/low watermark: also 3/4, 1/4
	 */
	dbcfg->rpb_ghw_vld = cpu_to_le32(1);
	dbcfg->rpb_glw_vld = cpu_to_le32(1);

	val = (hw->is_only_lan_in_chan) ? hw->hw_conf.rpb_pb_total_size_per_lan_channel :
		hw->hw_conf.rpb_pb_total_size_per_lan;
	val <<= 10;		/* convert to bytes */

	val = (val) / 4;	/* 1/4 */
	dbcfg->rpb_glw_value = cpu_to_le32((val & RPB_WM_THRES_VAL_M));	/* align to 16B */

	val = (val) * 3;	/* 3/4 */
	dbcfg->rpb_ghw_value = cpu_to_le32((val & RPB_WM_THRES_VAL_M));	/* align to 16B */

#if defined(NSE_DEBUG_EXT)
	if (nse_qos_db_test_fc_tx) {
		dbcfg->rpb_ghw_value = cpu_to_le32(NSE_QOS_DB_RPB_SMALL_HTHRES * 4);
		dbcfg->rpb_glw_value = cpu_to_le32(NSE_QOS_DB_RPB_SMALL_LTHRES * 4);
	}
#endif

	/* up2tc mapping */
	dbcfg->rpb_up2tc_vld = cpu_to_le32(1);

	val = 0;
	for (i = 0; i < IEEE_8021Q_MAX_PRIORITIES; i++) {
		/* this is in case prio_table[i] maps to non-contingous TC
		 *
		 * see internal limitation in nse_dcb_get_num_tc().
		 *
		 * then we map those UP to TC-0.
		 *
		 * I should have done the similar handling in upper code trace,
		 * but also do it here, for another insurance.
		 */
		if (dcbcfg->etscfg.prio_table[i] < ena_tc_num)
			val |= ((u32)dcbcfg->etscfg.prio_table[i] << (i * RPB_UP2TC_PER_TC_SHIFT));
	}
	dbcfg->rpb_up2tc_value = cpu_to_le32(val);

	/* tc2pfc */
	dbcfg->rpb_tc2pfc_vld = cpu_to_le32(1);

	val = 0;
	for (i = 0; i < IEEE_8021Q_MAX_PRIORITIES; i++) {
		/* this UP enable PFC */
		if ((dcbcfg->pfc.pfcena & BIT(i)) &&
			dcbcfg->etscfg.prio_table[i] < ena_tc_num) {	/* this UP's TC is valid */
			val |= BIT((dcbcfg->etscfg.prio_table[i]));
		}
	}

	/* if above PFC not set, then fallback to LFC:
	 *		need to set bit(0) for TC-0
	 *
	 * if LFC is also not enabled, then the register would be 0.
	 */
	if (fc_info->req_mode == NSE_FC_LFC_TX_PAUSE ||
		fc_info->req_mode == NSE_FC_LFC_FULL)
		val |= BIT(0);

	dbcfg->rpb_tc2pfc_value = cpu_to_le32(val);

	if (!set_all_or_this_lan)
		goto translate_trt;

	/****************************************
	 *
	 * RDB setting translate
	 *
	 ****************************************/

	dbcfg->rdb_pb_ctl_vld = cpu_to_le32(1);
	dbcfg->rdb_pb_ctl_value = cpu_to_le32(RDB_PB_CTL_EN_M);

	dbcfg->rdb_pbwarb_ctl_vld = cpu_to_le32(1);
	dbcfg->rdb_pbwarb_ctl_value = cpu_to_le32((RDB_PBWARB_CTL_RPPAC_WRR <<
						  RDB_PBWARB_CTL_RPPAC_S));

	dbcfg->rdb_pbwarb_credit_vld = cpu_to_le32(1);
	val = (RDB_PBWARB_CREDIT_VAL_DFLT << RDB_PBWARB_CREDIT_VAL_S);
	dbcfg->rdb_pbwarb_credit_value[0] = cpu_to_le32(val);
	dbcfg->rdb_pbwarb_credit_value[1] = cpu_to_le32(val);

	dbcfg->rdb_pbrarb_ctl_vld = cpu_to_le32(1);
	/* explicitly set the reset-init value */
	val = ((RDB_PBRARB_CTL_RPPAC_WRR << RDB_PBRARB_CTL_RPPAC_S) |
			(RDB_PBRARB_CTL_WSP_PRI_PACKET << RDB_PBRARB_CTL_WSP_PRI_S));
	dbcfg->rdb_pbrarb_ctl_value = cpu_to_le32(val);

	dbcfg->rdb_pbrarb_credit_vld = cpu_to_le32(1);
	val = (RDB_PBRARB_CREDIT_VAL_DFLT << RDB_PBRARB_CREDIT_VAL_S);
	for (i = 0; i < 7; i++)
		dbcfg->rdb_pbrarb_credit_value[i] = cpu_to_le32(val);

	/****************************************
	 *
	 * TDB setting translate
	 *
	 ****************************************/

	dbcfg->tdb_pb_ctl_vld = cpu_to_le32(1);
	dbcfg->tdb_pb_ctl_value = cpu_to_le32(TDB_PB_CTL_EN_M);

	if (nse_qos_db_use_share) {
		/* use shared instead of dedicated.
		 */

		dbcfg->tdb_pb_sz_vld = cpu_to_le32(1);
		dbcfg->tdb_pb_sz_egrps_bitmap = cpu_to_le32(0xF);	/* all 4 egrps */

		for (i = 0; i < 4; i++) {
			for (j = 0; j < 8; j++)
				dbcfg->tdb_pb_sz_egrps_values[i][j] = 0;
		}

		val = hw->hw_conf.tdb_pb_sz_total;

		dbcfg->tdb_share_sz_vld = cpu_to_le32(1);
		dbcfg->tdb_share_sz_value = cpu_to_le32((val << TDB_PB_SZ_SIZE_S));

		dbcfg->tdb_sht_vld = cpu_to_le32(1);
		dbcfg->tdb_sht_egrps_bitmap = cpu_to_le32(0xF);		/* all 4 egrps */

		/* high WM: 3/4, unit: byte, */
		val = (val * 1024 * 3) / 4;
		for (i = 0; i < 4; i++) {
			for (j = 0; j < 8; j++) {
				dbcfg->tdb_sht_egrps_values[i][j] =
					cpu_to_le32((val & TDB_SHT_SIZE_M));
			}
		}
	} else {
		dbcfg->tdb_pb_sz_vld = cpu_to_le32(1);
		dbcfg->tdb_pb_sz_egrps_bitmap = cpu_to_le32(0xF);	/* all 4 egrps */

		if (hw->hw_conf.hw_platform == NSE_HW_PLATFORM_FPGA)
			egrps_cnt = 2;
		else
			egrps_cnt = 4;

		val = (hw->hw_conf.tdb_pb_sz_total / egrps_cnt / hw->hw_conf.max_tc_allowed);

		for (i = 0; i < egrps_cnt; i++) {
			for (j = 0; j < hw->hw_conf.max_tc_allowed; j++) {
				dbcfg->tdb_pb_sz_egrps_values[i][j] =
					cpu_to_le32((val << TDB_PB_SZ_SIZE_S));
			}
		}

		dbcfg->tdb_share_sz_vld = cpu_to_le32(1);
		dbcfg->tdb_share_sz_value = 0;		/* don't use share_sz */

		dbcfg->tdb_sht_vld = cpu_to_le32(1);
		dbcfg->tdb_sht_egrps_bitmap = cpu_to_le32(0xF);		/* all 4 egrps */
		/* leave tdb_sht[32] to all 0, since we set tdb_share_sz = 0 */
	}

	dbcfg->tdb_pbwarb_credit_vld = cpu_to_le32(1);
	val = (TDB_PBWARB_CREDIT_VAL_DFLT << TDB_PBWARB_CREDIT_VAL_S);
	dbcfg->tdb_pbwarb_credit_value[0] = cpu_to_le32(val);
	dbcfg->tdb_pbwarb_credit_value[1] = cpu_to_le32(val);

	dbcfg->tdb_pbrarb_ctl_vld = cpu_to_le32(1);
	dbcfg->tdb_pbrarb_ctl_value = 0;	/* wsp_pri=0 (packet), all rppac = WRR */

	dbcfg->tdb_pbrarb_credit_vld = cpu_to_le32(1);
	val = (TDB_PBRARB_CREDIT_VAL_DFLT << TDB_PBRARB_CREDIT_VAL_S);
	dbcfg->tdb_pbrarb_credit_value[0] = cpu_to_le32(val);
	dbcfg->tdb_pbrarb_credit_value[1] = cpu_to_le32(val);
	dbcfg->tdb_pbrarb_credit_value[2] = cpu_to_le32(val);
	dbcfg->tdb_pbrarb_credit_value[3] = cpu_to_le32(val);

	dbcfg->tdb_tcpbrarb_credit_vld = cpu_to_le32(1);
	dbcfg->tdb_tcpbrarb_credit_egrps_bitmap = cpu_to_le32(0xF);		/* all 4 egrps */
	for (i = 0; i < 4; i++) {
		for (j = 0; j < 8; j++) {
			dbcfg->tdb_tcpbrarb_credit_egrps_values[i][j] =
				cpu_to_le32((TDB_TCPBRARB_CREDIT_VAL_DFLT <<
					    TDB_TCPBRARB_CREDIT_VAL_S));
		}
	}

translate_trt:

	/****************************************
	 *
	 * TRT setting translate
	 *
	 ***************************************/

	dbcfg->trt_ctl_vld = cpu_to_le32(1);
	val = TRT_CTL_MNG_DRP_EN_M |
			TRT_CTL_LPBK_DRP_EN_M |
			TRT_CTL_PB_EN_M;

	dbcfg->trt_ctl_value = cpu_to_le32(val);

	if (nse_qos_db_use_share) {
		/* use share, no dedicated.
		 */

		dbcfg->trt_pb_sz_lan_dedicate_vld = cpu_to_le32(1);
		dbcfg->trt_pb_sz_lan_dedicate_bitmap = cpu_to_le32(0x3);

		for (i = 0; i < 2; i++) {
			for (j = 0; j < 8; j++)
				dbcfg->trt_pb_sz_lan_dedicate_values[i][j] = 0;
		}

		dbcfg->trt_pb_sz_tmp_buf_vld = cpu_to_le32(1);
		dbcfg->trt_pb_sz_tmp_buf_value = 0;

		dbcfg->trt_share_sz_vld = cpu_to_le32(1);
		val = hw->hw_conf.trt_pb_sz_total;
		dbcfg->trt_share_sz_value = cpu_to_le32((val << TRT_PB_SZ_SIZE_S));

		/* all threshold are 3/4 */
		dbcfg->trt_sht_lan_dedicate_vld = cpu_to_le32(1);
		dbcfg->trt_sht_lan_dedicate_bitmap = cpu_to_le32(0x3);

		val = hw->hw_conf.trt_pb_sz_total;
		val = (val * 1024 * 3) / 4;
		val &= TRT_SHT_VAL_M;					/* align to 32-bytes unit */

		for (i = 0; i < 2; i++) {
			for (j = 0; j < 8; j++)
				dbcfg->trt_sht_lan_dedicate_values[i][j] = cpu_to_le32(val);
		}

		dbcfg->trt_sht_tmp_buf_vld = cpu_to_le32(1);
		dbcfg->trt_sht_tmp_buf_value = cpu_to_le32(val);
	} else {
		/* use dedicated, no share.
		 */

		dbcfg->trt_pb_sz_lan_dedicate_vld = cpu_to_le32(1);

		i = hw->lan_id & 0x1;	/* local lan_id in this channel */
		dbcfg->trt_pb_sz_lan_dedicate_bitmap = cpu_to_le32((1 << i));

		if (hw->is_only_lan_in_chan)
			val = hw->hw_conf.trt_pb_sz_per_lan_dedicated_dflt * 2;	/* KB */
		else
			val = hw->hw_conf.trt_pb_sz_per_lan_dedicated_dflt;		/* KB */

		val /= ena_tc_num;

		/* note here, i is used for lan_id, so use j as TC index */
		for (j = 0; j < ena_tc_num; j++) {
			dbcfg->trt_pb_sz_lan_dedicate_values[i][j] = cpu_to_le32((val <<
										 TRT_PB_SZ_SIZE_S));
		}
		/* rest disabled TC are already memset(0) in nse_dcbcfg_to_dbcfg() */

		dbcfg->trt_pb_sz_tmp_buf_vld = cpu_to_le32(1);
		val = hw->hw_conf.trt_pb_sz_tmp_buf_size_dflt;
		dbcfg->trt_pb_sz_tmp_buf_value = cpu_to_le32((val << TRT_PB_SZ_SIZE_S));

		/*  do not use trt_share_sz, and related trt_sht, keep their value as reset-default
		 * 0
		 */
		dbcfg->trt_share_sz_vld = cpu_to_le32(0);
		dbcfg->trt_sht_lan_dedicate_vld = cpu_to_le32(0);
		dbcfg->trt_sht_tmp_buf_vld = cpu_to_le32(0);
	}

	dbcfg->trt_pbrarb_ctl_vld = cpu_to_le32(1);
	val = (TRT_PBRARB_CTL_TPPAC_WRR << TRT_PBRARB_CTL_TPPAC0_S) |
			(TRT_PBRARB_CTL_TPPAC_WRR << TRT_PBRARB_CTL_TPPAC1_S);
	dbcfg->trt_pbrarb_ctl_value = cpu_to_le32(val);

	dbcfg->trt_pbrarb_credit_vld = cpu_to_le32(1);
	i = (hw->lan_id & 0x1);
	dbcfg->trt_pbrarb_credit_lan_bitmap = cpu_to_le32((1 << i));

	val = TRT_PBRARB_CREDIT_VAL_SP_MAX;
	/* note here, i is used for lan_id, so use j as TC index */
	for (j = (ena_tc_num - 1); j >= 0; j--) {
		/* TC value higher, its priority order are higher */
		if (dcbcfg->etscfg.tsatable[j] == IEEE_8021QAZ_TSA_STRICT) {
			dbcfg->trt_pbrarb_credit_lan_values[i][j] =
				cpu_to_le32((val & TRT_PBRARB_CREDIT_VAL_M));
			if (val > TRT_PBRARB_CREDIT_VAL_SP_MIN)
				val >>= 1;
		} else if (dcbcfg->etscfg.tsatable[j] == IEEE_8021QAZ_TSA_ETS) {
			val_2 =
			(TRT_PBRARB_CREDIT_VAL_ETS_TOTAL * dcbcfg->etscfg.tcbwtable[j]) / 100;
			dbcfg->trt_pbrarb_credit_lan_values[i][j] =
				cpu_to_le32((val_2 & TRT_PBRARB_CREDIT_VAL_M));
		}
	}

	val = 0;
	for (i = 0; i < IEEE_8021Q_MAX_PRIORITIES; i++) {
		/* this is in case prio_table[i] maps to non-contingous TC
		 *
		 * see internal limitation in nse_dcb_get_num_tc().
		 *
		 * then we map those UP to TC-0.
		 *
		 * I should have done the similar handling in upper code trace,
		 * but also do it here, for another insurance.
		 */
		if (dcbcfg->etscfg.prio_table[i] < ena_tc_num)
			val |= ((u32)dcbcfg->etscfg.prio_table[i] << (i * TRT_UP2TC_PER_TC_SHIFT));

		if (dcbcfg->pfc.pfcena & BIT(i))	/* at least 1 UP/TC enables PFC */
			val |= TRT_UP2TC_PFCE_M;
	}

	if (hw->lan_id & 0x1) {
		dbcfg->trt_up2tc_lan1_vld = cpu_to_le32(1);
		dbcfg->trt_up2tc_lan1_value = cpu_to_le32(val);
	} else {
		dbcfg->trt_up2tc_lan0_vld = cpu_to_le32(1);
		dbcfg->trt_up2tc_lan0_value = cpu_to_le32(val);
	}

	dbcfg->trt_sch_cfg_lan0_vld = 0;
	dbcfg->trt_sch_cfg_lan1_vld = 0;
	dbcfg->trt_exoff_thres_vld = 0;
	dbcfg->trt_1us_tick_cnt_vld = 0;
	dbcfg->trt_lksts_fltr_vld = 0;

	/****************************************
	 *
	 * LMAC setting translate
	 *
	 ***************************************/

	dbcfg->lmac_rx_flow_ctl_vld = cpu_to_le32(1);

	val = LMAC_TYPE_1_RX_FLOW_CTL_UP_M;

	for (i = 0; i < IEEE_8021Q_MAX_PRIORITIES; i++) {
		if (dcbcfg->pfc.pfcena & BIT(i)) {	/* at least 1 UP/TC enables PFC */
			val |= (LMAC_TYPE_1_RX_FLOW_CTL_PFCE_M | LMAC_TYPE_1_RX_FLOW_CTL_RFE_M);
			break;
		}
	}

	/* if above PFC not set, then fallback to LFC  --- RFE = 1, PFCE=0
	 *
	 * if LFC also not set, then RFE bit not set.
	 */
	if (fc_info->req_mode == NSE_FC_LFC_RX_PAUSE ||
		fc_info->req_mode == NSE_FC_LFC_FULL)
		val |= LMAC_TYPE_1_RX_FLOW_CTL_RFE_M;

	dbcfg->lmac_rx_flow_ctl_value = cpu_to_le32(val);

	dbcfg->lmac_tx_flow_ctl_vld = cpu_to_le32(1);

	val = ((0x7FFF << LMAC_TYPE_1_TX_FLOW_CTL_PT_S) |
			(0x4 << LMAC_TYPE_1_TX_FLOW_CTL_PLT_S));

	for (i = 0; i < IEEE_8021Q_MAX_PRIORITIES; i++) {
		if (dcbcfg->pfc.pfcena & BIT(i))
			dbcfg->lmac_tx_flow_ctl_value[i] =
				cpu_to_le32((val | LMAC_TYPE_1_TX_FLOW_CTL_TFE_M));
	}

	/*  if above PFC not set, then fallback to LFC --- tx_flow_ctl[0] TFE=1 ( PFCE=0 in
	 * rx_flow_ctl indicate LFC not PFC)
	 *
	 * if LFC also not set, then TFE bit not set.
	 */
	if (fc_info->req_mode == NSE_FC_LFC_TX_PAUSE ||
		fc_info->req_mode == NSE_FC_LFC_FULL)
		dbcfg->lmac_tx_flow_ctl_value[0] = cpu_to_le32((val |
							       LMAC_TYPE_1_TX_FLOW_CTL_TFE_M));

	dbcfg->lmac_rxq_prio_mapping_ctrl_vld = cpu_to_le32(1);

	dbcfg->lmac_rxq_prio_mapping_ctrl_value[0] = cpu_to_le32(0x08040201);	/* 0x08040201 */
	dbcfg->lmac_rxq_prio_mapping_ctrl_value[1] = cpu_to_le32(0x80402010);	/* 0x80402010 */
}

static void
dcbcfg_to_dbcfg_ms(struct nse_hw *hw,
						struct nse_aqc_qos_db_cfg_ms *dbcfg,
						struct nse_dcbx_cfg *dcbcfg)
{
	struct nse_port_info *pi = hw->port_info;
	struct nse_fc_info *fc_info = &pi->lmac_phy_info.fc_info;
	int i = 0;
	u8 ena_tc_num = nse_dcb_get_num_tc(dcbcfg);
	u32 val = 0, val_2 = 0;

	/* request update FW local_dcbx_cfg
	 */
	dbcfg->dcbx_cfg_flags = cpu_to_le32(QOS_DCBX_CFG_FLAG_LOCAL);

	memcpy(&dbcfg->local_dcbx_cfg, dcbcfg, sizeof(dbcfg->local_dcbx_cfg));

	/****************************************
	 *
	 * RPB setting translate
	 *
	 ****************************************/

	dbcfg->rpb_pb_ctl_vld = cpu_to_le32(1);

	val = (MS_RPB_PB_CTL_WARB_MODE_WRR << MS_RPB_PB_CTL_WARB_MODE_S) |
			MS_RPB_PB_CTL_TC_TX_EN_M |
			MS_RPB_PB_CTL_TC_RX_EN_M;

	dbcfg->rpb_pb_ctl_value = cpu_to_le32(val);

	dbcfg->rpb_tc_dedicate_sz_vld = cpu_to_le32(1);

	val = (hw->hw_conf.rpb_pb_total_size_per_lan_channel << 1) / ena_tc_num;

	val <<= MS_RPB_SZ_WM_VAL_S;

	for (i = 0; i < ena_tc_num; i++)
		dbcfg->rpb_tc_dedicate_sz_value[i] = cpu_to_le32(val);

	/* do not use share buffer - values unset */
	dbcfg->rpb_tc_share_sz_vld = cpu_to_le32(1);

	dbcfg->rpb_tc_dhw_vld = cpu_to_le32(1);
	dbcfg->rpb_tc_dlw_vld = cpu_to_le32(1);

	for (i = 0; i < ena_tc_num; i++) {
		val = le32_to_cpu(dbcfg->rpb_tc_dedicate_sz_value[i]);

		val_2 = val / 4;	/* low watermark: 1/4 (trigger XON) */
		val = val_2 * 3;	/* high watermark: 3/4 (trigger XOFF) */

		val &= MS_RPB_SZ_WM_VAL_M;
		val_2 &= MS_RPB_SZ_WM_VAL_M;

		dbcfg->rpb_tc_dhw_value[i] = cpu_to_le32(val);
		dbcfg->rpb_tc_dlw_value[i] = cpu_to_le32(val_2);
	}

	dbcfg->rpb_tc_slw_vld = cpu_to_le32(1);		/* do not use share buffer - values unset */

	/* tc2pfc */
	dbcfg->rpb_tc2pfc_vld = cpu_to_le32(1);

	val = 0;
	for (i = 0; i < IEEE_8021Q_MAX_PRIORITIES; i++) {
		/* this UP enable PFC */
		if ((dcbcfg->pfc.pfcena & BIT(i)) &&
			dcbcfg->etscfg.prio_table[i] < ena_tc_num) {	/* this UP's TC is valid */
			val |= BIT((dcbcfg->etscfg.prio_table[i]));
		}
	}

	if (fc_info->req_mode == NSE_FC_LFC_TX_PAUSE ||
		fc_info->req_mode == NSE_FC_LFC_FULL)
		val |= BIT(0);

	dbcfg->rpb_tc2pfc_value = cpu_to_le32(val);

	/* no use LLTC for TSA=SP, but give them more credit */
	dbcfg->rpb_lltc_vld = cpu_to_le32(1);

	dbcfg->rpb_arb_credit_vld = cpu_to_le32(1);

	val = MS_RPB_PBRARB_CREDIT_VAL_SP_MAX;

	for (i = (ena_tc_num - 1); i >= 0; i--) {
		/* TC value higher, its priority order are higher */
		if (dcbcfg->etscfg.tsatable[i] == IEEE_8021QAZ_TSA_STRICT) {
			dbcfg->rpb_arb_credit_value[i] =
				cpu_to_le32((val & MS_RPB_PBRARB_CREDIT_VAL_M));
			if (val > MS_RPB_PBRARB_CREDIT_VAL_SP_MIN)
				val >>= 1;

		} else if (dcbcfg->etscfg.tsatable[i] == IEEE_8021QAZ_TSA_ETS) {
			val_2 =
			(MS_RPB_PBRARB_CREDIT_VAL_ETS_TOTAL * dcbcfg->etscfg.tcbwtable[i]) / 100;
			dbcfg->rpb_arb_credit_value[i] =
				cpu_to_le32((val_2 & MS_RPB_PBRARB_CREDIT_VAL_M));
		}
	}

	/* don't use this feature */
	dbcfg->rpb_ovfl_en_vld = cpu_to_le32(1);

	dbcfg->rpb_ovfl_time_vld = cpu_to_le32(1);

	dbcfg->rpb_port_ctl_vld = cpu_to_le32(1);

	/* moonstone have only 1 ports, so the port size use all RPB size */
	/* KB unit covert to 512B unit */
	val = (hw->hw_conf.rpb_pb_total_size_per_lan_channel << 1);

	val <<= MS_RPB_SZ_WM_VAL_S;

	dbcfg->rpb_port_ctl_value = cpu_to_le32(val);

	/* do not use share buffer - values unset */
	dbcfg->rpb_port_share_sz_vld = cpu_to_le32(1);

	dbcfg->rpb_port_ghw_vld = cpu_to_le32(1);
	dbcfg->rpb_port_glw_vld = cpu_to_le32(1);

	val_2 = val / 4;	/* low watermark: 1/4 (trigger XON) */
	val = val_2 * 3;	/* high watermark: 3/4 (trigger XOFF) */

	val &= MS_RPB_SZ_WM_VAL_M;
	val_2 &= MS_RPB_SZ_WM_VAL_M;

	dbcfg->rpb_port_ghw_value = cpu_to_le32(val);
	dbcfg->rpb_port_glw_value = cpu_to_le32(val_2);

	/* do not use share buffer - values unset */
	dbcfg->rpb_port_shw_vld = cpu_to_le32(1);
	/* do not use share buffer - values unset */
	dbcfg->rpb_port_slw_vld = cpu_to_le32(1);

	/* up2tc mapping */
	dbcfg->rpb_port_up2tc_vld = cpu_to_le32(1);

	val = 0;
	for (i = 0; i < IEEE_8021Q_MAX_PRIORITIES; i++) {
		/* this is in case prio_table[i] maps to non-contingous TC
		 *
		 * see internal limitation in nse_dcb_get_num_tc().
		 *
		 * then we map those UP to TC-0.
		 *
		 * I should have done the similar handling in upper code trace,
		 * but also do it here, for another insurance.
		 */
		if (dcbcfg->etscfg.prio_table[i] < ena_tc_num)
			val |= ((u32)dcbcfg->etscfg.prio_table[i] <<
				(i * MS_RPB_PORT_UP2TC_PER_TC_SHIFT));
	}
	dbcfg->rpb_port_up2tc_value = cpu_to_le32(val);

	dbcfg->rpb_port_vlan2up_ctrl_vld = cpu_to_le32(1);	/* default_up = 0 */

	/****************************************
	 *
	 * RDB setting translate
	 *
	 ****************************************/

	dbcfg->rdb_pb_ctl_vld = cpu_to_le32(1);

	/* should not set MS_RDB_PB_PSR_BP_M which is invalid and cause problem */
	val = MS_RDB_PB_CTL_EN_M;

	dbcfg->rdb_pb_ctl_value = cpu_to_le32(val);

	dbcfg->rdb_pbrarb_ctl_vld = cpu_to_le32(1);
	/* explicitly set the reset-init value */
	val = ((MS_RDB_PBRARB_CTL_WSP_PRI_PACKET << MS_RDB_PBRARB_CTL_WSP_PRI_S) |
			(MS_RDB_PBRARB_CTL_RPPAC_WRR << MS_RDB_PBRARB_CTL_RPPAC_S));
	dbcfg->rdb_pbrarb_ctl_value = cpu_to_le32(val);

	dbcfg->rdb_pbrarb_credit_vld = cpu_to_le32(1);
	val = (MS_RDB_PBRARB_CREDIT_VAL_DFLT << MS_RDB_PBRARB_CREDIT_VAL_S);
	for (i = 0; i < 7; i++)
		dbcfg->rdb_pbrarb_credit_value[i] = cpu_to_le32(val);

	dbcfg->rdb_stall_time_vld = cpu_to_le32(1);	/* value is unset 0, not use this feature */

	/****************************************
	 *
	 * TDB setting translate
	 *
	 ****************************************/

	dbcfg->tdb_pb_ctl_vld = cpu_to_le32(1);
	dbcfg->tdb_pb_ctl_value = cpu_to_le32(MS_TDB_PB_CTL_EN_M);

	if (!nse_qos_db_use_share) {
		dbcfg->tdb_pb_sz_vld = cpu_to_le32(1);

		val = (hw->hw_conf.tdb_pb_sz_total / hw->hw_conf.max_tc_allowed);

		for (i = 0; i < hw->hw_conf.max_tc_allowed; i++)
			dbcfg->tdb_pb_sz_value[i] = cpu_to_le32((val << MS_TDB_PB_SZ_SIZE_S));

		/* value is unset 0, not use share */
		dbcfg->tdb_share_sz_vld = cpu_to_le32(1);

		/* value is unset 0, not use share */
		dbcfg->tdb_sht_vld = cpu_to_le32(1);

	} else {
		/* value is unset 0, gonna use share */
		dbcfg->tdb_pb_sz_vld = cpu_to_le32(1);

		dbcfg->tdb_share_sz_vld = cpu_to_le32(1);
		dbcfg->tdb_share_sz_value = cpu_to_le32((hw->hw_conf.tdb_pb_sz_total <<
							MS_TDB_PB_SZ_SIZE_S));

		dbcfg->tdb_sht_vld = cpu_to_le32(1);

		/* let each TC can use up to the whole TDB pb_size */
		val = hw->hw_conf.tdb_pb_sz_total;

		for (i = 0; i < hw->hw_conf.max_tc_allowed; i++) {
			/* for simplicity, not using MS_TDB_SHT_SIZE_S */
			dbcfg->tdb_sht_value[i] = cpu_to_le32((val << MS_TDB_PB_SZ_SIZE_S));
		}
	}

	dbcfg->tdb_pbwarb_credit_vld = cpu_to_le32(1);
	val = (MS_TDB_PBWARB_CREDIT_VAL_DFLT << MS_TDB_PBWARB_CREDIT_VAL_S);
	dbcfg->tdb_pbwarb_credit_value[0] = cpu_to_le32(val);
	dbcfg->tdb_pbwarb_credit_value[1] = cpu_to_le32(val);

	dbcfg->tdb_pbrarb_ctl_vld = cpu_to_le32(1);
	val = (MS_TDB_PBRARB_CTL_POH_STORE_CNT_DFLT << MS_TDB_PBRARB_CTL_POH_STORE_CNT_S);
	dbcfg->tdb_pbrarb_ctl_value = cpu_to_le32(val);	/* rppac0 = WRR */

	dbcfg->tdb_tcpbrarb_credit_vld = cpu_to_le32(1);

	for (i = 0; i < 8; i++) {
		dbcfg->tdb_tcpbrarb_credit_value[i] =
				cpu_to_le32((MS_TDB_TCPBRARB_CREDIT_VAL_DFLT <<
					    MS_TDB_TCPBRARB_CREDIT_VAL_S));
	}

	/****************************************
	 *
	 * LMAC setting translate
	 *
	 ***************************************/

	val = 0;
	for (i = 0; i < IEEE_8021Q_MAX_PRIORITIES; i++) {
		if (dcbcfg->pfc.pfcena & BIT(i))
			val = 1;	/* should use PFC */
	}

	dbcfg->lmac_tx_pause_en_vld = cpu_to_le32(1);

	if (val)
		dbcfg->lmac_tx_pause_en_value = cpu_to_le32(0xFF);	/* bits 7:0*/
	else
		dbcfg->lmac_tx_pause_en_value = cpu_to_le32(0x100);	/* bit 8 */

	dbcfg->lmac_retransmit_xoff_holdoff_en_vld = cpu_to_le32(1);
	/* default, no bother set it again */
	dbcfg->lmac_retransmit_xoff_holdoff_en_value = cpu_to_le32(0x1FF);

	dbcfg->lmac_retransmit_xoff_holdoff_quanta_vld = cpu_to_le32(1);
	/* default, no bother set it again */
	dbcfg->lmac_retransmit_xoff_holdoff_quanta_value = cpu_to_le32(0xFFFF);

	dbcfg->lmac_tx_pause_quanta_vld = cpu_to_le32(1);
	/* default, no bother set it again */
	dbcfg->lmac_tx_pause_quanta_value = cpu_to_le32(0xFFFF);

	dbcfg->lmac_tx_xof_en_tx_pause_qnumber_vld = 0;	/* don't know what it is */

	/* badly named, should be "Uniform Holdoff" */
	dbcfg->lmac_cfg_retransmit_holdoff_en_vld = cpu_to_le32(0);
	//dbcfg->lmac_cfg_retransmit_holdoff_en_value = cpu_to_le32(0);

	/* badly named, should be "Uniform Holdoff" */
	dbcfg->lmac_cfg_retransmit_holdoff_quanta_vld = cpu_to_le32(1);
	dbcfg->lmac_cfg_retransmit_holdoff_quanta_value =  cpu_to_le32(0xFFFF);

	dbcfg->lmac_txsfc_ehip_cfg_vld = 1;

	if (val)	/* TX PFC */
		dbcfg->lmac_txsfc_ehip_cfg_value = cpu_to_le32(LMAC_TYPE_2_TXSFC_CHIP_CFG_EN_PFC_M);
	/* TX LFC */
	else if (fc_info->req_mode == NSE_FC_LFC_TX_PAUSE || fc_info->req_mode == NSE_FC_LFC_FULL)
		dbcfg->lmac_txsfc_ehip_cfg_value = cpu_to_le32(LMAC_TYPE_2_TXSFC_CHIP_CFG_EN_SFC_M);

	dbcfg->lmac_rx_pause_enable_vld = cpu_to_le32(1);
	dbcfg->lmac_rx_pause_enable_value = cpu_to_le32(0xFF);

	dbcfg->lmac_rx_pause_fwd_vld = 0;

	dbcfg->lmac_rxsfc_ehip_cfg_vld = cpu_to_le32(1);

	if (val)	/* RX PFC */
		dbcfg->lmac_rxsfc_ehip_cfg_value = cpu_to_le32(LMAC_TYPE_2_RXSFC_CHIP_CFG_EN_PFC_M);
	/* RX LFC */
	else if (fc_info->req_mode == NSE_FC_LFC_RX_PAUSE || fc_info->req_mode == NSE_FC_LFC_FULL)
		dbcfg->lmac_rxsfc_ehip_cfg_value = cpu_to_le32(LMAC_TYPE_2_RXSFC_CHIP_CFG_EN_SFC_M);

	dbcfg->lmac_pfc_pause_quanta_vld = cpu_to_le32(1);
	for (i = 0; i < 8; i++)
		/* default is 0xFFFF, no bother set it again */
		dbcfg->lmac_pfc_pause_quanta_value[i] = cpu_to_le32(0xFFFF);

	dbcfg->lmac_pfc_holdoff_quanta_vld = cpu_to_le32(1);
	for (i = 0; i < 8; i++)
		/* default is 0xFFFF, no bother set it again */
		dbcfg->lmac_pfc_holdoff_quanta_value[i] = cpu_to_le32(0xFFFF);
}

static void
nse_dcbcfg_to_dbcfg(struct nse_hw *hw,
						struct nse_aqc_qos_db_cfg *dbcfg,
						struct nse_dcbx_cfg *dcbcfg,
						bool set_all_or_this_lan)
{
	memset(dbcfg, 0, sizeof(*dbcfg));

	nse_aqc_fill_generic_common_hdr_dft(hw, &dbcfg->hdr, NSE_VSI_INVAL_ID);

	if (hw->mac_type == NSE_MAC_TYPE_AMBER)
		dcbcfg_to_dbcfg_amber(hw, &dbcfg->amber, dcbcfg, set_all_or_this_lan);
	else if (hw->mac_type == NSE_MAC_TYPE_MOONSTONE)
		dcbcfg_to_dbcfg_ms(hw, &dbcfg->ms, dcbcfg);

	/* request update sch-tree
	 */
}

enum nse_status nse_set_dcb_cfg(struct nse_port_info *pi, bool set_all_or_this_lan)
{
	struct nse_aqc_qos_db_cfg *dbcfg = NULL;
	struct nse_dcbx_cfg *dcbcfg;
	struct nse_hw *hw = pi->hw;
	enum nse_status ret;

	/* update the HW's local_dcbx_cfg */
	dcbcfg = &pi->qos_cfg.local_dcbx_cfg;

	/* allocate the aq-cmd buff */
	dbcfg = devm_kzalloc(nse_hw_to_dev(hw), sizeof(*dbcfg), GFP_KERNEL);
	if (!dbcfg)
		return NSE_ERR_NO_MEMORY;

	ret = nse_qos_db_flush_disable_this_lan(hw);
	if (ret) {
		dev_err(nse_hw_to_dev(hw), "[%s, %d] FAIL: qos_db_flush_disable_this_lan(): ret=%d(%s)\n",
									__func__, __LINE__,
									ret, nse_stat_str(ret));
		goto out;
	}

	/* would enable those DB module internally */
	nse_dcbcfg_to_dbcfg(hw, dbcfg, dcbcfg, set_all_or_this_lan);

	ret = nse_aq_qos_db_set_cfg(hw, dbcfg);
	if (ret) {
		dev_err(nse_hw_to_dev(hw), "[%s, %d] FAIL: aq_qos_db_set_cfg(): ret=%d(%s)\n",
									__func__, __LINE__,
									ret, nse_stat_str(ret));
		goto out;
	}

	memcpy(&pi->qos_cfg.fc_chk_saved_db_cfg, dbcfg, sizeof(*dbcfg));

out:
	devm_kfree(nse_hw_to_dev(hw), dbcfg);

	return ret;
}

static void
nse_dcbcfg_to_dbcfg_registers_lw_amber(struct nse_hw *hw,
						struct nse_aqc_qos_db_cfg_amber *dbcfg,
						struct nse_dcbx_cfg *dcbcfg,
						u32 cfg_chg_type)
{
	struct nse_port_info *pi = hw->port_info;
	struct nse_fc_info *fc_info = &pi->lmac_phy_info.fc_info;
	int i = 0;
	u8 ena_tc_num = nse_dcb_get_num_tc(dcbcfg);
	u32 val = 0;

	dbcfg->eth_grp_id = hw->port_info->curr_eth_grp_id;

	/* request update FW local_dcbx_cfg
	 */
	dbcfg->dcbx_cfg_flags = cpu_to_le32(QOS_DCBX_CFG_FLAG_LOCAL);

	memcpy(&dbcfg->local_dcbx_cfg, dcbcfg, sizeof(dbcfg->local_dcbx_cfg));

	if (cfg_chg_type & NSE_DCB_CFG_CHG_TYPE_UP2TC) {
		/* RPB - up2tc */
		dbcfg->rpb_up2tc_vld = cpu_to_le32(1);

		val = 0;
		for (i = 0; i < IEEE_8021Q_MAX_PRIORITIES; i++) {
			if (dcbcfg->etscfg.prio_table[i] < ena_tc_num)
				val |= ((u32)dcbcfg->etscfg.prio_table[i] <<
					(i * RPB_UP2TC_PER_TC_SHIFT));
		}
		dbcfg->rpb_up2tc_value = cpu_to_le32(val);

		/* TRT - up2tc */
		val = 0;
		for (i = 0; i < IEEE_8021Q_MAX_PRIORITIES; i++) {
			if (dcbcfg->etscfg.prio_table[i] < ena_tc_num)
				val |= ((u32)dcbcfg->etscfg.prio_table[i] <<
					(i * TRT_UP2TC_PER_TC_SHIFT));
		}

		if (hw->lan_id & 0x1) {
			dbcfg->trt_up2tc_lan1_vld = cpu_to_le32(1);
			dbcfg->trt_up2tc_lan1_value = cpu_to_le32(val);
		} else {
			dbcfg->trt_up2tc_lan0_vld = cpu_to_le32(1);
			dbcfg->trt_up2tc_lan0_value = cpu_to_le32(val);
		}
	}

	if (cfg_chg_type & NSE_DCB_CFG_CHG_TYPE_PFC) {
		/* RPB - tc2pfc */
		dbcfg->rpb_tc2pfc_vld = cpu_to_le32(1);

		val = 0;
		for (i = 0; i < IEEE_8021Q_MAX_PRIORITIES; i++) {
			/* this UP enable PFC */
			if ((dcbcfg->pfc.pfcena & BIT(i)) &&
				/* this UP's TC is valid */
				dcbcfg->etscfg.prio_table[i] < ena_tc_num) {
				val |= BIT((dcbcfg->etscfg.prio_table[i]));
			}
		}

		/* if above PFC not set, then fallback to LFC:
		 *		need to set bit(0) for TC-0
		 *
		 * if LFC is also not enabled, then the register would be 0.
		 */
		if (fc_info->req_mode == NSE_FC_LFC_TX_PAUSE ||
			fc_info->req_mode == NSE_FC_LFC_FULL)
			val |= BIT(0);

		dbcfg->rpb_tc2pfc_value = cpu_to_le32(val);

		/* LMAC */
		dbcfg->lmac_rx_flow_ctl_vld = cpu_to_le32(1);

		val = LMAC_TYPE_1_RX_FLOW_CTL_UP_M;

		for (i = 0; i < IEEE_8021Q_MAX_PRIORITIES; i++) {
			if (dcbcfg->pfc.pfcena & BIT(i)) {	/* at least 1 UP/TC enables PFC */
				val |= (LMAC_TYPE_1_RX_FLOW_CTL_PFCE_M |
					LMAC_TYPE_1_RX_FLOW_CTL_RFE_M);
				break;
			}
		}

		/* if above PFC not set, then fallback to LFC  --- RFE = 1, PFCE=0
		 *
		 * if LFC also not set, then RFE bit not set.
		 */
		if (fc_info->req_mode == NSE_FC_LFC_RX_PAUSE ||
			fc_info->req_mode == NSE_FC_LFC_FULL)
			val |= LMAC_TYPE_1_RX_FLOW_CTL_RFE_M;

		dbcfg->lmac_rx_flow_ctl_value = cpu_to_le32(val);

		dbcfg->lmac_tx_flow_ctl_vld = cpu_to_le32(1);

		val = ((0x7FFF << LMAC_TYPE_1_TX_FLOW_CTL_PT_S) |
				(0x4 << LMAC_TYPE_1_TX_FLOW_CTL_PLT_S));

		for (i = 0; i < IEEE_8021Q_MAX_PRIORITIES; i++) {
			if (dcbcfg->pfc.pfcena & BIT(i))
				dbcfg->lmac_tx_flow_ctl_value[i] =
					cpu_to_le32((val | LMAC_TYPE_1_TX_FLOW_CTL_TFE_M));
		}

		/*  if above PFC not set, then fallback to LFC --- tx_flow_ctl[0] TFE=1 ( PFCE=0 in
		 * rx_flow_ctl indicate LFC not PFC)
		 *
		 * if LFC also not set, then TFE bit not set.
		 */
		if (fc_info->req_mode == NSE_FC_LFC_TX_PAUSE ||
			fc_info->req_mode == NSE_FC_LFC_FULL)
			dbcfg->lmac_tx_flow_ctl_value[0] =
				cpu_to_le32((val | LMAC_TYPE_1_TX_FLOW_CTL_TFE_M));

		dbcfg->lmac_rxq_prio_mapping_ctrl_vld = cpu_to_le32(1);

		/* 0x08040201 */
		dbcfg->lmac_rxq_prio_mapping_ctrl_value[0] = cpu_to_le32(0x08040201);
		/* 0x80402010 */
		dbcfg->lmac_rxq_prio_mapping_ctrl_value[1] = cpu_to_le32(0x80402010);
	}
}

static void
nse_dcbcfg_to_dbcfg_registers_lw_ms(struct nse_hw *hw,
						struct nse_aqc_qos_db_cfg_ms *dbcfg,
						struct nse_dcbx_cfg *dcbcfg,
						u32 cfg_chg_type)
{
	struct nse_port_info *pi = hw->port_info;
	struct nse_fc_info *fc_info = &pi->lmac_phy_info.fc_info;
	int i = 0;
	u8 ena_tc_num = nse_dcb_get_num_tc(dcbcfg);
	u32 val = 0;

	/* request update FW local_dcbx_cfg
	 */
	dbcfg->dcbx_cfg_flags = cpu_to_le32(QOS_DCBX_CFG_FLAG_LOCAL);

	memcpy(&dbcfg->local_dcbx_cfg, dcbcfg, sizeof(dbcfg->local_dcbx_cfg));

	if (cfg_chg_type & NSE_DCB_CFG_CHG_TYPE_UP2TC) {
		/* RPB - up2tc */
		dbcfg->rpb_port_up2tc_vld = cpu_to_le32(1);

		val = 0;
		for (i = 0; i < IEEE_8021Q_MAX_PRIORITIES; i++) {
			if (dcbcfg->etscfg.prio_table[i] < ena_tc_num)
				val |= ((u32)dcbcfg->etscfg.prio_table[i] <<
					(i * MS_RPB_PORT_UP2TC_PER_TC_SHIFT));
		}
		dbcfg->rpb_port_up2tc_value = cpu_to_le32(val);
	}

	if (cfg_chg_type & NSE_DCB_CFG_CHG_TYPE_PFC) {
		/* RPB - tc2pfc */
		dbcfg->rpb_tc2pfc_vld = cpu_to_le32(1);

		val = 0;
		for (i = 0; i < IEEE_8021Q_MAX_PRIORITIES; i++) {
			/* this UP enable PFC */
			if ((dcbcfg->pfc.pfcena & BIT(i)) &&
				/* this UP's TC is valid */
				dcbcfg->etscfg.prio_table[i] < ena_tc_num) {
				val |= BIT((dcbcfg->etscfg.prio_table[i]));
			}
		}

		/* if above PFC not set, then fallback to LFC:
		 *		need to set bit(0) for TC-0
		 *
		 * if LFC is also not enabled, then the register would be 0.
		 */
		if (fc_info->req_mode == NSE_FC_LFC_TX_PAUSE ||
			fc_info->req_mode == NSE_FC_LFC_FULL)
			val |= BIT(0);

		dbcfg->rpb_tc2pfc_value = cpu_to_le32(val);

		/****************************************
		 *
		 * LMAC setting, same as in dcbcfg_to_dbcfg_ms()
		 *
		 ***************************************/

		val = 0;
		for (i = 0; i < IEEE_8021Q_MAX_PRIORITIES; i++) {
			if (dcbcfg->pfc.pfcena & BIT(i))
				val = 1;	/* should use PFC */
		}

		dbcfg->lmac_tx_pause_en_vld = cpu_to_le32(1);

		if (val)
			dbcfg->lmac_tx_pause_en_value = cpu_to_le32(0xFF);	/* bits 7:0*/
		else
			dbcfg->lmac_tx_pause_en_value = cpu_to_le32(0x100);	/* bit 8 */

		dbcfg->lmac_retransmit_xoff_holdoff_en_vld = cpu_to_le32(1);
		/* default, no bother set it again */
		dbcfg->lmac_retransmit_xoff_holdoff_en_value = cpu_to_le32(0x1FF);

		dbcfg->lmac_retransmit_xoff_holdoff_quanta_vld = cpu_to_le32(1);
		/* default, no bother set it again */
		dbcfg->lmac_retransmit_xoff_holdoff_quanta_value = cpu_to_le32(0xFFFF);

		dbcfg->lmac_tx_pause_quanta_vld = cpu_to_le32(1);
		/* default, no bother set it again */
		dbcfg->lmac_tx_pause_quanta_value = cpu_to_le32(0xFFFF);

		dbcfg->lmac_tx_xof_en_tx_pause_qnumber_vld = 0;	/* don't know what it is */

		/* badly named, should be "Uniform Holdoff" */
		dbcfg->lmac_cfg_retransmit_holdoff_en_vld = cpu_to_le32(0);
		//dbcfg->lmac_cfg_retransmit_holdoff_en_value = cpu_to_le32(0);

		/* badly named, should be "Uniform Holdoff" */
		dbcfg->lmac_cfg_retransmit_holdoff_quanta_vld = cpu_to_le32(1);
		dbcfg->lmac_cfg_retransmit_holdoff_quanta_value =  cpu_to_le32(0xFFFF);

		dbcfg->lmac_txsfc_ehip_cfg_vld = 1;

		if (val)	/* TX PFC */
			dbcfg->lmac_txsfc_ehip_cfg_value =
				cpu_to_le32(LMAC_TYPE_2_TXSFC_CHIP_CFG_EN_PFC_M);
		else if (fc_info->req_mode == NSE_FC_LFC_TX_PAUSE ||
			fc_info->req_mode == NSE_FC_LFC_FULL)	/* TX LFC */
			dbcfg->lmac_txsfc_ehip_cfg_value =
				cpu_to_le32(LMAC_TYPE_2_TXSFC_CHIP_CFG_EN_SFC_M);

		dbcfg->lmac_rx_pause_enable_vld = cpu_to_le32(1);
		dbcfg->lmac_rx_pause_enable_value = cpu_to_le32(0xFF);

		dbcfg->lmac_rx_pause_fwd_vld = 0;

		dbcfg->lmac_rxsfc_ehip_cfg_vld = cpu_to_le32(1);

		if (val)	/* RX PFC */
			dbcfg->lmac_rxsfc_ehip_cfg_value =
				cpu_to_le32(LMAC_TYPE_2_RXSFC_CHIP_CFG_EN_PFC_M);
		else if (fc_info->req_mode == NSE_FC_LFC_RX_PAUSE ||
			fc_info->req_mode == NSE_FC_LFC_FULL)	/* RX LFC */
			dbcfg->lmac_rxsfc_ehip_cfg_value =
				cpu_to_le32(LMAC_TYPE_2_RXSFC_CHIP_CFG_EN_SFC_M);

		dbcfg->lmac_pfc_pause_quanta_vld = cpu_to_le32(1);
		for (i = 0; i < 8; i++)
			/* default is 0xFFFF, no bother set it again */
			dbcfg->lmac_pfc_pause_quanta_value[i] = cpu_to_le32(0xFFFF);

		dbcfg->lmac_pfc_holdoff_quanta_vld = cpu_to_le32(1);
		for (i = 0; i < 8; i++)
			/* default is 0xFFFF, no bother set it again */
			dbcfg->lmac_pfc_holdoff_quanta_value[i] = cpu_to_le32(0xFFFF);
	}
}

static void
nse_dcbcfg_to_dbcfg_lw(struct nse_hw *hw,
						struct nse_aqc_qos_db_cfg *dbcfg,
						struct nse_dcbx_cfg *dcbcfg,
						u32 cfg_chg_type)
{
	memset(dbcfg, 0, sizeof(*dbcfg));

	nse_aqc_fill_generic_common_hdr_dft(hw, &dbcfg->hdr, NSE_VSI_INVAL_ID);

	if (hw->mac_type == NSE_MAC_TYPE_AMBER)
		nse_dcbcfg_to_dbcfg_registers_lw_amber(hw, &dbcfg->amber, dcbcfg, cfg_chg_type);
	else if (hw->mac_type == NSE_MAC_TYPE_MOONSTONE)
		nse_dcbcfg_to_dbcfg_registers_lw_ms(hw, &dbcfg->ms, dcbcfg, cfg_chg_type);
}

enum nse_status nse_set_dcb_cfg_lw(struct nse_port_info *pi, u32 cfg_chg_type)
{
	struct nse_aqc_qos_db_cfg *dbcfg = NULL;
	struct nse_dcbx_cfg *dcbcfg;
	struct nse_hw *hw;
	enum nse_status ret;

	if (!pi)
		return NSE_ERR_PARAM;

	hw = pi->hw;

	/* update the HW's local_dcbx_cfg */
	dcbcfg = &pi->qos_cfg.local_dcbx_cfg;

	/* allocate the aq-cmd buff */
	dbcfg = devm_kzalloc(nse_hw_to_dev(hw), sizeof(*dbcfg), GFP_KERNEL);
	if (!dbcfg)
		return NSE_ERR_NO_MEMORY;

	/* would enable those DB module internally */
	nse_dcbcfg_to_dbcfg_lw(hw, dbcfg, dcbcfg, cfg_chg_type);

	ret = nse_aq_qos_db_set_cfg(hw, dbcfg);
	if (ret) {
		dev_err(nse_hw_to_dev(hw), "[%s, %d] FAIL: aq_qos_db_set_cfg(): ret=%d (%s)\n",
									__func__, __LINE__,
									ret, nse_stat_str(ret));
		goto out;
	}

	if (cfg_chg_type & NSE_DCB_CFG_CHG_TYPE_PFC)
		memcpy(&pi->qos_cfg.fc_chk_saved_db_cfg, dbcfg, sizeof(*dbcfg));

out:
	devm_kfree(nse_hw_to_dev(hw), dbcfg);

	return ret;
}

void
nse_dump_up_enforcement(struct nse_hw *hw,
						struct nse_aqc_qos_db_conf_up_enforcement *upe)
{
	struct device *dev = nse_hw_to_dev(hw);
	u32 i, j;

	dev_info(dev, "=== up_enforcement:\n");

	dev_info(dev, "\t up_ctl: 0x%X\n", le32_to_cpu(upe->up_ctl_value));

	dev_info(dev, "\t tctupr_bitmap: 0x%X\n", le32_to_cpu(upe->tctupr_bitmap));

	for (i = 0; i < 4; i++) {
		for (j = 0; j < 8; j++) {
			dev_info(dev, "\t tctupr[%d][%d]: 0x%X\n", i, j,
				 le32_to_cpu(upe->tctupr_values[i][j]));
		}
	}
}

void
nse_dcbcfg_to_up_enforcement_registers(struct nse_hw *hw,
						struct nse_dcbx_cfg *dcbcfg,
						struct nse_aqc_qos_db_conf_up_enforcement *upe)
{
	struct nse_dcb_ets_cfg *etscfg = &dcbcfg->etscfg;
	u32 ena_tc_num = nse_dcb_get_num_tc(dcbcfg);
	u32 eth_group_id = hw->lan_id;		/* by default, lan_id is eth_grp_id */
	u32 val = 0;
	u32 tc, up, dflt_up_of_this_tc;
	bool dflt_up_of_this_tc_found;

	memset(upe, 0, sizeof(*upe));

	/* always enable UP enforcement */
	upe->up_ctl_vld = cpu_to_le32(1);
	upe->up_ctl_value = cpu_to_le32(UP_CTL_ENFORCE_EN_M);

	upe->tctupr_vld = cpu_to_le32(1);
	upe->tctupr_bitmap = cpu_to_le32(BIT(eth_group_id));
	for (tc = 0; tc < ena_tc_num; tc++) {
		val = 0;
		dflt_up_of_this_tc = 0;
		dflt_up_of_this_tc_found = false;

		for (up = 0; up < IEEE_8021Q_MAX_PRIORITIES; up++) {
			if (etscfg->prio_table[up] == tc) {	/* this UP mapped to this TC */
				/* use right this UP, don't overwrite */
				val |= ((up) << (up * TCTUPR_PER_UP_SHIFT));

				/* use first UP of this TC to be default UP of this TC */
				if (!dflt_up_of_this_tc_found) {
					dflt_up_of_this_tc = up;
					dflt_up_of_this_tc_found = true;
				}
			}
		}

		/* set some overwrite fields */
		for (up = 0; up < IEEE_8021Q_MAX_PRIORITIES; up++) {
			if (!(val & (0x7 << (up * TCTUPR_PER_UP_SHIFT))))
				val |= (dflt_up_of_this_tc << (up * TCTUPR_PER_UP_SHIFT));
		}

		upe->tctupr_values[eth_group_id][tc] = cpu_to_le32(val);
	}
}

enum nse_status
nse_set_dcb_up_enforcement(struct nse_hw *hw, struct nse_dcbx_cfg *dcbcfg)
{
	struct nse_aqc_qos_db_conf_up_enforcement *upe = NULL;
	enum nse_status status = 0;

	if (!nse_is_hw_static_fea_set(hw, NSE_HW_STATIC_FEA_TDM_SUPPORT_UP_ENFORCE))
		return NSE_SUCCESS;

	upe = kzalloc(sizeof(*upe), GFP_ATOMIC);
	if (!upe) {
		status = NSE_ERR_NO_MEMORY;
		goto out;
	}

	nse_dcbcfg_to_up_enforcement_registers(hw, dcbcfg, upe);

	if (hw->debug_mask & NSE_DBG_DCB)
		nse_dump_up_enforcement(hw, upe);

	status = nse_aq_qos_db_write_up_enforcement(hw, upe);

out:
	kfree(upe);

	nse_debug(hw, NSE_DBG_DCB, "[%s] status = %d\n", __func__, status);

	return status;
}

/* only for debug */
enum nse_status
nse_set_dcb_up_enforcement_force_off(struct nse_hw *hw)
{
	struct nse_aqc_qos_db_conf_up_enforcement *upe = NULL;
	enum nse_status status = 0;

	if (!nse_is_hw_static_fea_set(hw, NSE_HW_STATIC_FEA_TDM_SUPPORT_UP_ENFORCE))
		return NSE_SUCCESS;

	upe = kzalloc(sizeof(*upe), GFP_ATOMIC);
	if (!upe) {
		status = NSE_ERR_NO_MEMORY;
		goto out;
	}

	memset(upe, 0, sizeof(*upe));

	/* turn off UP enforcement */
	upe->up_ctl_vld = cpu_to_le32(1);
	upe->up_ctl_value = cpu_to_le32(0);

	if (hw->debug_mask & NSE_DBG_DCB)
		nse_dump_up_enforcement(hw, upe);

	status = nse_aq_qos_db_write_up_enforcement(hw, upe);

out:
	kfree(upe);

	nse_debug(hw, NSE_DBG_DCB, "[%s] status = %d\n", __func__, status);

	return status;
}
