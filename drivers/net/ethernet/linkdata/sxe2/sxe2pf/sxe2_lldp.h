/* SPDX-License-Identifier: GPL-2.0 */
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2_lldp.h
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#ifndef __SXE2_LLDP_H__
#define __SXE2_LLDP_H__

#include "sxe2_cmd.h"
#include "sxe2_log.h"

static inline void sxe2_lldp_fw_stats(struct sxe2_adapter *adapter)
{
	s32 ret;
	struct sxe2_cmd_params cmd = { 0 };
	struct sxe2_fwc_lldp_stats lldp_stats = { 0 };

	sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_LLDP_FW_STATS, NULL, 0,
				  &lldp_stats, sizeof(lldp_stats));

	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret) {
		LOG_DEV_ERR("lldp fw state cmd fail, ret=%d\n", ret);
		return;
	}
	LOG_DEV_INFO("\t lldp fw stats\n");
	LOG_DEV_INFO("\t\t lldp_enable=%d\n", lldp_stats.lldp_enable);
	LOG_DEV_INFO("\t\t admin_status=%d\n", lldp_stats.admin_status);
	LOG_DEV_INFO("\t\t rx_state=%d\n", lldp_stats.rx_state);
	LOG_DEV_INFO("\t\t tx_state=%d\n", lldp_stats.tx_state);

	LOG_DEV_INFO("\t\t tx_failed=%d\n", lldp_stats.tx_failed);
	LOG_DEV_INFO("\t\t tx_frames_out_total=%d\n", lldp_stats.tx_frames_out_total);
	LOG_DEV_INFO("\t\t tx_lldpdu_length_errors=%d\n", lldp_stats.tx_lldpdu_length_errors);
	LOG_DEV_INFO("\t\t rx_ageouts_total=%d\n", lldp_stats.rx_ageouts_total);
	LOG_DEV_INFO("\t\t rx_frames_discarded_total=%d\n", lldp_stats.rx_frames_discarded_total);
	LOG_DEV_INFO("\t\t rx_frames_in_errors_total=%d\n", lldp_stats.rx_frames_in_errors_total);
	LOG_DEV_INFO("\t\t rx_frames_in_total=%d\n", lldp_stats.rx_frames_in_total);
	LOG_DEV_INFO("\t\t rx_tlvs_discarded_total=%d\n", lldp_stats.rx_tlvs_discarded_total);
	LOG_DEV_INFO("\t\t rx_tlvs_unrecognized_total=%d\n", lldp_stats.rx_tlvs_unrecognized_total);
}

static inline void sxe2_lldp_remote_mibs_dump(struct sxe2_adapter *adapter)
{
	s32 ret, i, j;
	struct sxe2_cmd_params cmd = { 0 };
	struct sxe2_fwc_lldp_mibs_info info = { 0 };
	struct sxe2_fwc_lldp_mibs_dump_req dump_req;
	struct sxe2_fwc_lldp_mibs_dump_resp *dump_resp;

	dump_resp = kzalloc(sizeof(*dump_resp), GFP_KERNEL);
	if (!dump_resp) {
		LOG_DEV_ERR("low memory\n");
		return;
	}

	sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_LLDP_REMOTE_MIBS_INFO, NULL, 0,
				  &info, sizeof(info));

	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret) {
		LOG_DEV_ERR("lldp remote mibs dump cmd fail, ret=%d\n", ret);
		goto l_end;
	}
	LOG_DEV_INFO("\t lldp remote mibs dump_resp\n");
	LOG_DEV_INFO("\t\t lldp remote mibs count %d\n", info.count);

	for (i = 0; i < info.count; i++) {
		dump_req.index = (u8)i;
		sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_LLDP_REMOTE_MIBS_DUMP,
					  &dump_req, sizeof(dump_req),
		dump_resp, sizeof(*dump_resp));

		ret = sxe2_cmd_fw_exec(adapter, &cmd);
		if (ret) {
			LOG_DEV_ERR("lldp remote mibs dump, ret=%d\n", ret);
			goto l_end;
		}
		LOG_DEV_INFO("\t\t lldp remote mib[%d]\n", i);
		print_hex_dump(KERN_INFO, "\t\t content: ", DUMP_PREFIX_OFFSET, 16, 1,
			       dump_resp->buffer, dump_resp->size, true);
		memset(dump_resp->buffer, 0, dump_resp->size);
		LOG_DEV_INFO("\t\t ets cfg parse:\n");
		LOG_DEV_INFO("\t\t ets cfg willing %d\n", dump_resp->ets_cfg.willing);
		LOG_DEV_INFO("\t\t ets cfg cbs %d\n", dump_resp->ets_cfg.cbs);
		LOG_DEV_INFO("\t\t ets cfg maxtcs %d\n", dump_resp->ets_cfg.maxtcs);
		LOG_DEV_INFO("\t\t ets cfg prioTable 0:%d,1:%d,2:%d,3:%d,4:%d,5:%d,6:%d,7:%d\n",
			     dump_resp->ets_cfg.prioTable[0], dump_resp->ets_cfg.prioTable[1],
			     dump_resp->ets_cfg.prioTable[2], dump_resp->ets_cfg.prioTable[3],
			     dump_resp->ets_cfg.prioTable[4], dump_resp->ets_cfg.prioTable[5],
			     dump_resp->ets_cfg.prioTable[6], dump_resp->ets_cfg.prioTable[7]);
		LOG_DEV_INFO("\t\t ets cfg tcbwtable 0:%d,1:%d,2:%d,3:%d,4:%d,5:%d,6:%d,7:%d\n",
			     dump_resp->ets_cfg.tcbwtable[0], dump_resp->ets_cfg.tcbwtable[1],
			     dump_resp->ets_cfg.tcbwtable[2], dump_resp->ets_cfg.tcbwtable[3],
			     dump_resp->ets_cfg.tcbwtable[4], dump_resp->ets_cfg.tcbwtable[5],
			     dump_resp->ets_cfg.tcbwtable[6], dump_resp->ets_cfg.tcbwtable[7]);
		LOG_DEV_INFO("\t\t ets cfg tsatable 0:%d,1:%d,2:%d,3:%d,4:%d,5:%d,6:%d,7:%d\n",
			     dump_resp->ets_cfg.tsatable[0], dump_resp->ets_cfg.tsatable[1],
			     dump_resp->ets_cfg.tsatable[2], dump_resp->ets_cfg.tsatable[3],
			     dump_resp->ets_cfg.tsatable[4], dump_resp->ets_cfg.tsatable[5],
			     dump_resp->ets_cfg.tsatable[6], dump_resp->ets_cfg.tsatable[7]);
		LOG_DEV_INFO("\t\t ets rec parse:\n");
		LOG_DEV_INFO("\t\t ets rec prioTable 0:%d,1:%d,2:%d,3:%d,4:%d,5:%d,6:%d,7:%d\n",
			     dump_resp->ets_rec.prioTable[0], dump_resp->ets_rec.prioTable[1],
			     dump_resp->ets_rec.prioTable[2], dump_resp->ets_rec.prioTable[3],
			     dump_resp->ets_rec.prioTable[4], dump_resp->ets_rec.prioTable[5],
			     dump_resp->ets_rec.prioTable[6], dump_resp->ets_rec.prioTable[7]);
		LOG_DEV_INFO("\t\t ets rec tcbwtable 0:%d,1:%d,2:%d,3:%d,4:%d,5:%d,6:%d,7:%d\n",
			     dump_resp->ets_rec.tcbwtable[0], dump_resp->ets_rec.tcbwtable[1],
			     dump_resp->ets_rec.tcbwtable[2], dump_resp->ets_rec.tcbwtable[3],
			     dump_resp->ets_rec.tcbwtable[4], dump_resp->ets_rec.tcbwtable[5],
			     dump_resp->ets_rec.tcbwtable[6], dump_resp->ets_rec.tcbwtable[7]);
		LOG_DEV_INFO("\t\t ets rec tsatable 0:%d,1:%d,2:%d,3:%d,4:%d,5:%d,6:%d,7:%d\n",
			     dump_resp->ets_rec.tsatable[0], dump_resp->ets_rec.tsatable[1],
			     dump_resp->ets_rec.tsatable[2], dump_resp->ets_rec.tsatable[3],
			     dump_resp->ets_rec.tsatable[4], dump_resp->ets_rec.tsatable[5],
			     dump_resp->ets_rec.tsatable[6], dump_resp->ets_rec.tsatable[7]);
		LOG_DEV_INFO("\t\t pfc cfg parse:\n");
		LOG_DEV_INFO("\t\t pfc cfg willing %d\n", dump_resp->pfc_cfg.willing);
		LOG_DEV_INFO("\t\t pfc cfg mbc %d\n", dump_resp->pfc_cfg.mbc);
		LOG_DEV_INFO("\t\t pfc cfg pfccap 0x%02x\n", dump_resp->pfc_cfg.pfccap);
		LOG_DEV_INFO("\t\t pfc cfg pfcena 0x%02x\n", dump_resp->pfc_cfg.pfcena);

		LOG_DEV_INFO("\t\t app cfg parse:\n");
		LOG_DEV_INFO("\t\t app cfg numapps %d\n", dump_resp->num_apps);
		for (j = 0; j < dump_resp->num_apps; j++) {
			LOG_DEV_INFO("\t\t app cfg app[%d] %d,%d,%d\n", j,
				     dump_resp->app_cfg[j].priority, dump_resp->app_cfg[j].selector,
				     dump_resp->app_cfg[j].protId);
		}
	}
l_end:
	kfree(dump_resp);
}

#ifdef SXE2_CFG_DEBUG
static inline void sxe2_lldp_dcbx_agent_on(struct sxe2_adapter *adapter)
{
	s32 ret;
	struct sxe2_cmd_params cmd = { 0 };
	struct sxe2_fwc_fw_agent req = { 0 };

	sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_LLDP_DCBX_FW_AGENT_SET, &req, sizeof(req),
				  NULL, 0);

	req.enable = 1;
	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret)
		LOG_DEV_ERR("lldp fw state cmd fail, ret=%d\n", ret);
}

static inline void sxe2_lldp_dcbx_agent_off(struct sxe2_adapter *adapter)
{
	s32 ret;
	struct sxe2_cmd_params cmd = { 0 };
	struct sxe2_fwc_fw_agent req = { 0 };

	sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_LLDP_DCBX_FW_AGENT_SET, &req, sizeof(req),
				  NULL, 0);

	req.enable = 0;
	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret)
		LOG_DEV_ERR("lldp fw state cmd fail, ret=%d\n", ret);
}

static inline void sxe2_lldp_dcbx_agent_is_on(struct sxe2_adapter *adapter)
{
	s32 ret;
	struct sxe2_cmd_params cmd = { 0 };
	struct sxe2_fwc_fw_agent resp = { 0 };

	sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_LLDP_DCBX_FW_AGENT_GET, NULL, 0,
				  &resp, sizeof(resp));

	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret)
		LOG_DEV_ERR("lldp fw state cmd fail, ret=%d\n", ret);

	LOG_DEV_INFO("\t lldp fw stats\n");
	LOG_DEV_INFO("\t\t lldp dcbx agent is %s\n", resp.enable ? "on" : "off");
}
#endif

#endif
