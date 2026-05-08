/* SPDX-License-Identifier: GPL-2.0 */
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2_event.h
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#ifndef __SXE2_EVENT_H__
#define __SXE2_EVENT_H__

enum sxe2_cmd_event_status {
	SXE2_CMD_EVENT_STATUS_INIT = 0,
	SXE2_CMD_EVENT_STATUS_SUB,
	SXE2_CMD_EVENT_STATUS_UNSUB,
};

s32 sxe2_event_handle(struct sxe2_adapter *adapter, u16 event_code, void *buf, u32 buf_len);

s32 sxe2_fwc_event_subscribe(struct sxe2_adapter *adapter, struct sxe2_fwc_event *subscribe);

s32 sxe2_fwc_event_unsubscribe(struct sxe2_adapter *adapter, struct sxe2_fwc_event *unsubscribe);

s32 sxe2_set_event_status(struct sxe2_adapter *adapter,
			  u16 event_code,
			  enum sxe2_cmd_event_status status);

#endif
