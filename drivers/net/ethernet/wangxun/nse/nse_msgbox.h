/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2018 - 2021 Beijing WangXun Technology Co., Ltd. */

#ifndef _NSE_MSGBOX_H
#define _NSE_MSGBOX_H

#include <linux/types.h>
#include <linux/mutex.h>

#include "nse_adminq_cmd.h"

#define NSE_MSGBOX_MSG_FRAG_FLAG_S		30
#define NSE_MSGBOX_MSG_FRAG_FLAG_M		BIT(30)

	#define NSE_MSGBOX_MSG_FRAG_FLAG_MORE		0
	#define NSE_MSGBOX_MSG_FRAG_FLAG_LAST		1

#define MSG_MSGBOX_MSG_TYPE_S			29
#define MSG_MSGBOX_MSG_TYPE_M			BIT(29)

	#define MSG_MSGBOX_MSG_TYPE_RESPONSE	0
	#define MSG_MSGBOX_MSG_TYPE_EVENT		1

#define NSE_MSGBOX_MSG_FRAG_SEQ_S		16
#define NSE_MSGBOX_MSG_FRAG_SEQ_M		NSE_M(0xFF, 16)

#define NSE_MSGBOX_MSG_MAX_LEN			4096
#define NSE_MSGBOX_MSG_FRAG_LEN			16
#define NSE_MSGBOX_MSG_FRAG_MAX_CNT		256

struct nse_msgbox_rx_msg_buf {
	char *msg_buf;	/* NSE_MSGBOX_MSG_MAX_LEN, reassemly in here */

	/* actual content of rx_msg_buf, the len is decided when FLAG_LAST is received */
	unsigned int rx_msg_len;

	DECLARE_BITMAP(rx_frag_bitmap, NSE_MSGBOX_MSG_FRAG_MAX_CNT);
};

struct nse_msgbox_cb {
	/* indexed by vsi_rel_id inside PF */
	struct nse_msgbox_rx_msg_buf v2p_rx_msg_buf[NSE_MAX_VSI];

	struct mutex v2p_mutex[NSE_MAX_VSI];
	struct mutex p2v_mutex[NSE_MAX_VSI];

	struct {
		unsigned long v2p_rx_bad_dup_frag;
		unsigned long v2p_rx_bad_miss_frag;

		unsigned long p2v_tx_send_wait_cnt;
		unsigned long p2v_tx_send_timeout_cnt;
	} stats;
};

#endif

