/* SPDX-License-Identifier: GPL-2.0 */
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2_mbx_msg.h
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#ifndef __SXE2_MBX_MSG_H__
#define __SXE2_MBX_MSG_H__

#include "sxe2.h"
#include "sxe2_cmd_channel.h"
#include "sxe2_fnav.h"

enum {
	SXE2_MBX_MSG_SRC_TYPE_PF = 0,
	SXE2_MBX_MSG_SRC_TYPE_VF,
	SXE2_MBX_MSG_SRC_TYPE_VSI,
};

#define SXE2_MBX_DESC_SRC_TYPE_SHIFT 10
#define SXE2_MBX_DESC_SRC_TYPE_MASK 0x3

struct sxe2_mbx_msg_info {
	u32 opcode;
	u16 msg_len;
	u8 *buf;
};

struct sxe2_mbx_msg_table {
	u32 opcode;
	s32 (*func)(struct sxe2_vf_node *vf,
		    struct sxe2_mbx_msg_info *msg_info);
};

void sxe2_cmd_vf_msg_handler(struct sxe2_adapter *adapter,
			     struct sxe2_recv_msg *msg);

struct sxe2_mbx_msg_table *sxe2_mbx_msg_table_get(void);

void sxe2_notify_vf_link_state(struct sxe2_vf_node *vf);

void sxe2_mbx_msg_params_fill(struct sxe2_cmd_params *cmd, u32 opc,
			      void *req_data, u32 req_len, u16 vf_idx,
			      bool no_resp);
struct sxe2_mbx_msg_table *sxe2_esw_mbx_msg_table_get(void);

void sxe2_mbx_msg_table_set(struct sxe2_vf_node *vf);

s32 sxe2_aux_reply_rdma_msg_to_vf(struct sxe2_adapter *adapter, u16 vf_id,
				  u8 *msg, u16 len, u64 session_id);

#endif
