// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2_linkchg.c
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#include "sxe2.h"
#include "sxe2_hw.h"
#include "sxe2_vsi.h"
#include "sxe2_log.h"
#include "sxe2_linkchg.h"
#include "sxe2_event.h"
#include "sxe2_common.h"
#include "sxe2_ethtool.h"
#include "sxe2_monitor.h"

#define CGMAC_LINKCHG_INFO(i) (0x002B4000 + (i) * 0x4000)
s32 sxe2_white_list_mib(struct sxe2_adapter *adapter, void *buf, u32 buf_len)
{
	enum sxe2_drv_event_code *whilt_ptr = (enum sxe2_drv_event_code *)buf;
	enum sxe2_drv_event_code whilt_list = *whilt_ptr;

	if (whilt_list == SXE2_EVENT_CODE_SFP_WHITE_LIST) {
		LOG_DEV_WARN("an unsupport optical module type was detected\n");
		LOG_DEV_WARN("refer to the sxe2 ethernet adapters and devices usr guide \t"
			     "for a list of supported modules\n");
	}

	return 0;
}

s32 sxe2_tx_fault_mib(struct sxe2_adapter *adapter, void *buf, u32 buf_len)
{
	enum sxe2_drv_event_code *tx_fault_ptr = (enum sxe2_drv_event_code *)buf;
	enum sxe2_drv_event_code tx_fault = *tx_fault_ptr;

	if (tx_fault == SXE2_EVENT_CODE_SFP_TX_FAULT)
		LOG_INFO_BDF("Optical Mod is happened tx fault!!");

	return 0;
}

s32 sxe2_tx_fault_event_count_mib(struct sxe2_adapter *adapter, void *buf,
				  u32 buf_len)
{
	struct sxe2_tx_fault_count_mib *tx_fault_count = (struct sxe2_tx_fault_count_mib *)buf;

	LOG_DEV_INFO("Optical Mod is happened tx faultcount: %llu",
		     tx_fault_count->tx_fault_count);

	return 0;
}

void sxe2_link_get_info_config(struct sxe2_adapter *adapter, u8 *link_state,
			       u32 *link_speed)
{
	*link_state = sxe2_get_pf_link_status(adapter);
	if (*link_state == SXE2_LINK_DOWN)
		*link_speed = SXE2_LINK_SPEED_UNKNOWN;
	else
		*link_speed = sxe2_get_link_speed(adapter);
}
