/* SPDX-License-Identifier: GPL-2.0 */
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2_mbx_channel.h
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#ifndef __SXE2_MBX_CHANNEL_H__
#define __SXE2_MBX_CHANNEL_H__

s32 sxe2_mbx_msg_send(struct sxe2_adapter *adapter,
		      struct sxe2_cmd_params *cmd_params);

s32 sxe2_mbx_msg_reply(struct sxe2_adapter *adapter,
		       struct sxe2_cmd_params *cmd_params);
#endif
