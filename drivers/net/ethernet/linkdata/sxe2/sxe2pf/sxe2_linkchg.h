/* SPDX-License-Identifier: GPL-2.0 */
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2_linkchg.h
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */
#ifndef __SXE2_LINKCHG_H__
#define __SXE2_LINKCHG_H__
#include <linux/netdevice.h>
#include <linux/types.h>
#include "sxe2_cmd.h"
#include "sxe2_drv_aux.h"

s32 sxe2_white_list_mib(struct sxe2_adapter *adapter, void *buf, u32 buf_len);

s32 sxe2_tx_fault_mib(struct sxe2_adapter *adapter, void *buf, u32 buf_len);

s32 sxe2_tx_fault_event_count_mib(struct sxe2_adapter *adapter, void *buf, u32 buf_len);

void sxe2_link_get_info_config(struct sxe2_adapter *adapter, u8 *link_state, u32 *link_speed);

#endif
