/* SPDX-License-Identifier: GPL-2.0 */
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2_dcb.h
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */
#ifndef __SXE2_DCB_H__
#define __SXE2_DCB_H__

#include <linux/netdevice.h>
#include <linux/types.h>
#include "sxe2_cmd.h"
#include "sxe2_drv_aux.h"

#define SXE2_DFLT_TC_NUM	1
#define SXE2_DFLT_TC_BITMAP	BIT(0)
#define SXE2_BYTES_PER_DSCP_VAL 8

#define SXE2_TC_MAX_BW		100
#define SXE2_DCB_HW_CHG_RST	0
#define SXE2_DCB_NO_HW_CHG	1
#define SXE2_DCB_HW_CHG	2

#define SXE2_IEEE_TSA_STRICT	0
#define SXE2_IEEE_TSA_ETS	2

#define SXE2_DCBX_MODE_CEE	0x1
#define SXE2_DCBX_MODE_IEEE	0x2
#define SXE2_DSCP_NUM_VAL	64
#define SXE2_DCBX_APPS_NON_WILLING	0x1

enum sxe2_dcb_state {
	SXE2_DCB_STATE_UNINIT = 0,
	SXE2_DCB_STATE_READY,
	SXE2_DCB_STATE_RESET,
	SXE2_DCB_STATE_MAX,
};

struct sxe2_dcb_ets_cfg {
	u8 willing;
	u8 cbs;
	u8 maxtcs;
	u8 prio_tbl[IEEE_8021Q_MAX_PRIORITIES];
	u8 tcbw_tbl[IEEE_8021QAZ_MAX_TCS];
	u8 tsa_tbl[IEEE_8021QAZ_MAX_TCS];
};

struct sxe2_dcb_pfc_cfg {
	u8 willing;
	u8 mbc;
	u8 cap;
	u8 enable;
};

struct sxe2_lfc_context {
	u8 tx_en;
	u8 rx_en;
	u8 recv[2];
};

struct sxe2_dcb_app_prio_tbl {
	u16 prot_id;

	u8 prio;

	u8 selector;
};

struct sxe2_dcbx_cfg {
	u8 dcbx_mode;

	struct sxe2_dcb_ets_cfg ets;
	struct sxe2_dcb_ets_cfg etsrec;
	struct sxe2_dcb_pfc_cfg pfc;

	u8 qos_mode;

	u32 numapps;
	u8 app_mode;
	DECLARE_BITMAP(dscp_mapped, SXE2_DSCP_NUM_VAL);
	u8 dscp_map[SXE2_DSCP_NUM_VAL];
	struct sxe2_dcb_app_prio_tbl app[SXE2_DCBX_MAX_APPS];
	u64 usr_bw_value[IEEE_8021QAZ_MAX_TCS];
	u32 hw_bw_value[IEEE_8021QAZ_MAX_TCS];
};

struct sxe2_dcb_context {
	struct sxe2_dcbx_cfg local_dcbx_cfg;
	struct sxe2_dcbx_cfg desired_dcbx_cfg;
	struct sxe2_dcbx_cfg remote_dcbx_cfg;
	enum sxe2_dcb_state state;
	u8 dcbx_cap;

	/* in order to protect the data */
	struct mutex tc_mutex;
};

void sxe2_dcb_set_state(struct sxe2_adapter *adapter,
			enum sxe2_dcb_state state, bool need_lock);

u8 sxe2_dcb_tc_bitmap_get(struct sxe2_dcbx_cfg *dcbcfg);

u8 sxe2_dcb_tc_cnt_get(struct sxe2_dcbx_cfg *dcbcfg);

s32 sxe2_dcb_bw_chk(struct sxe2_adapter *adapter,
		    struct sxe2_dcbx_cfg *dcbcfg);

void sxe2_dcb_sw_safe_mode_cfg(struct sxe2_adapter *adapter);

s32 sxe2_dcb_sw_dflt_cfg(struct sxe2_adapter *adapter,
			 bool ets_willing, bool locked);

s32 sxe2_dcb_cfg(struct sxe2_adapter *adapter,
		 struct sxe2_dcbx_cfg *new_cfg, bool locked);

s32 sxe2_qos_mode_set(struct sxe2_adapter *adapter, enum sxe2QosMode mode);

s32 sxe2_dcbx_fw_agent_status_set(struct sxe2_adapter *adapter, bool isenable);

void sxe2_dcb_stats_update(struct sxe2_adapter *adapter);

s32 sxe2_dcb_rebuild(struct sxe2_adapter *adapter);

s32 sxe2_dcb_maxrate_rebuild(struct sxe2_adapter *adapter);

s32 sxe2_dcbx_agent_enable(struct sxe2_adapter *adapter);

s32 sxe2_dcbx_agent_disable(struct sxe2_adapter *adapter);

s32 sxe2_dcb_init(struct sxe2_adapter *adapter, bool locked);

void sxe2_dcb_deinit(struct sxe2_adapter *adapter, bool locked);

s32 sxe2_dcb_lldp_mib_cfg(struct sxe2_adapter *adapter,
			  struct sxe2_fwc_local_mib_set *mib);

void sxe2_dcbx_agent_event_deinit(struct sxe2_adapter *adapter);

s32 sxe2_lldp_agent_event_init(struct sxe2_adapter *adapter);

void sxe2_lldp_agent_event_deinit(struct sxe2_adapter *adapter);

s32 sxe2_lldp_fw_agent_status_get(struct sxe2_adapter *adapter,
				  bool *isenable, u8 *direction);

s32 sxe2_dcbx_fw_agent_status_get(struct sxe2_adapter *adapter, bool *is_enable);

void sxe2_lldp_sw_rule_change(struct sxe2_adapter *adapter, u8 stats);

s32 sxe2_dcb_process_lldp_set_mib_change(struct sxe2_adapter *adapter,
					 void *buf, u32 buf_len);

s32 sxe2_lldp_fw_agent_change(struct sxe2_adapter *adapter,
			      void *buf, u32 buf_len);

s32 sxe2_dcbx_agent_event_init(struct sxe2_adapter *adapter);

void sxe2_setup_dcb_qos_info(struct sxe2_adapter *adapter,
			     struct aux_qos_params *qos_info);

void sxe2_vsi_netdev_tc_cfg(struct sxe2_vsi *vsi, u8 tc_bitmap);

s32 sxe2_fc_get(struct sxe2_adapter *adapter, u16 vsi_id, u8 *fc);

void sxe2_set_fc_flag(struct sxe2_vsi *vsi, bool on);

#endif
