// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2_event.c
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#include "sxe2.h"
#include "sxe2_log.h"
#include "sxe2_dcb.h"
#include "sxe2_cmd.h"
#include "sxe2_event.h"
#include "sxe2_log_export.h"
#include "sxe2_cmd_channel.h"
#include "sxe2_linkchg.h"
#include "sxe2_event.h"

#define SXE2_FW_LOG_PATH "/var/log/sxe2_fw_log/"

struct sxe2_event_handle {
	u16 event_code;
	s32 (*handler)(struct sxe2_adapter *adapter, void *buf, u32 buf_len);
	enum sxe2_cmd_event_status event_status;
};

STATIC struct sxe2_event_handle event_table[] = {
		{SXE2_EVENT_CODE_AUTO_LOG, sxe2_event_log_export,
		 SXE2_CMD_EVENT_STATUS_INIT},
		{SXE2_EVENT_CODE_MIB_NOTIFY, sxe2_dcb_process_lldp_set_mib_change,
		 SXE2_CMD_EVENT_STATUS_INIT},
		{SXE2_EVENT_CODE_SFP_WHITE_LIST, sxe2_white_list_mib,
		 SXE2_CMD_EVENT_STATUS_INIT},
		{SXE2_EVENT_CODE_SFP_TX_FAULT, sxe2_tx_fault_mib,
		 SXE2_CMD_EVENT_STATUS_INIT},
		{SXE2_EVENT_CODE_QSFP_TX_FAULT_COUNT, sxe2_tx_fault_event_count_mib,
		 SXE2_CMD_EVENT_STATUS_INIT},
		{SXE2_EVENT_CODE_LLDP_AGENT_NOTIFY, sxe2_lldp_fw_agent_change,
		 SXE2_CMD_EVENT_STATUS_INIT},
		{
				SXE2_EVENT_CODE_INVAL,
		}
};

s32 sxe2_event_handle(struct sxe2_adapter *adapter, u16 event_code, void *buf,
		      u32 buf_len)
{
	s32 ret = 0;
	const struct sxe2_event_handle *event_handler = NULL;
	struct mutex *event_lock = sxe2_cmd_channel_get_event_lock(adapter);

	mutex_lock(event_lock);
	for (event_handler = &event_table[0]; event_handler->event_code;
	     event_handler++) {
		if (event_handler->event_code == event_code)
			break;
	}

	if (!event_handler->handler ||
	    event_handler->event_code == SXE2_EVENT_CODE_INVAL ||
	    event_handler->event_status != SXE2_CMD_EVENT_STATUS_SUB) {
		ret = -EINVAL;
		LOG_ERROR_BDF("event %d buf_len %d, ret=%d\n", event_code, buf_len,
			      ret);
		goto l_unlock;
	}

	ret = event_handler->handler(adapter, buf, buf_len);
l_unlock:
	mutex_unlock(event_lock);
	return ret;
}

s32 sxe2_fwc_event_subscribe(struct sxe2_adapter *adapter,
			     struct sxe2_fwc_event *subscribe)
{
	s32 ret = 0;
	struct sxe2_cmd_params cmd = {};

	sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_EVENT_SUBSCRIBE, subscribe,
				  sizeof(*subscribe), NULL, 0);

	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret) {
		LOG_ERROR_BDF("%d event %d subscribe failed, ret=%d\n",
			      subscribe->count, le16_to_cpu(subscribe->code[0]),
			      ret);
		ret = -EIO;
	}

	return ret;
}

s32 sxe2_fwc_event_unsubscribe(struct sxe2_adapter *adapter,
			       struct sxe2_fwc_event *unsubscribe)
{
	s32 ret;
	struct sxe2_cmd_params cmd = {};

	sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_EVENT_UNSUBSCRIBE, unsubscribe,
				  sizeof(*unsubscribe), NULL, 0);

	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret) {
		LOG_ERROR_BDF("%d event %d unsubscribe failed, ret=%d\n",
			      unsubscribe->count, le16_to_cpu(unsubscribe->code[0]),
			      ret);
		ret = -EIO;
	}

	return ret;
}

s32 sxe2_set_event_status(struct sxe2_adapter *adapter, u16 event_code,
			  enum sxe2_cmd_event_status status)
{
	struct sxe2_event_handle *event_handler = NULL;
	struct mutex *event_lock = sxe2_cmd_channel_get_event_lock(adapter);
	s32 ret = 0;

	mutex_lock(event_lock);
	for (event_handler = &event_table[0]; event_handler->event_code;
	     event_handler++) {
		if (event_handler->event_code == event_code)
			break;
	}

	if (event_handler->event_code == SXE2_EVENT_CODE_INVAL) {
		ret = -EINVAL;
		LOG_ERROR_BDF("event %d status %d, ret=%d\n", event_code, status,
			      ret);
		goto l_unlock;
	}

	event_handler->event_status = status;

l_unlock:
	mutex_unlock(event_lock);
	return ret;
}
