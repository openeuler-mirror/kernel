/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (c) 2018 - 2021 Beijing WangXun Technology Co., Ltd. */

#ifndef _NSEVF_MSGBOX_H
#define _NSEVF_MSGBOX_H

#include <linux/types.h>
#include <linux/mutex.h>

#define NSE_MSGBOX_MSG_FRAG_FLAG_S 30
#define NSE_MSGBOX_MSG_FRAG_FLAG_M BIT(30)

#define NSE_MSGBOX_MSG_FRAG_FLAG_MORE 0
#define NSE_MSGBOX_MSG_FRAG_FLAG_LAST 1

#define MSG_MSGBOX_MSG_TYPE_S 29
#define MSG_MSGBOX_MSG_TYPE_M BIT(29)

#define MSG_MSGBOX_MSG_TYPE_RESPONSE 0
#define MSG_MSGBOX_MSG_TYPE_EVENT 1

#define NSE_MSGBOX_MSG_FRAG_SEQ_S 16
#define NSE_MSGBOX_MSG_FRAG_SEQ_M NSE_M(0xFF, 16)

#define NSE_MSGBOX_MSG_MAX_LEN 4096
#define NSE_MSGBOX_MSG_FRAG_LEN 16
#define NSE_MSGBOX_MSG_FRAG_MAX_CNT 256

struct nsevf_msgbox_rx_msg_buf {
	char *msg_buf; /* NSE_MSGBOX_MSG_MAX_LEN, reassemly in here */

	unsigned int
		rx_msg_len; /* Valid length, finalized when FLAG_LAST arrives. */

	unsigned int msg_type; /* TYPE_RESPONSE or TYPE_EVENT */

	DECLARE_BITMAP(rx_frag_bitmap, NSE_MSGBOX_MSG_FRAG_MAX_CNT);
};

struct nsevf_msgbox_cb {
	struct nsevf_msgbox_rx_msg_buf p2v_rx_msg_buf;

	struct mutex v2p_mutex; /* serializes VF-to-PF messages */
	struct mutex p2v_mutex; /* serializes PF-to-VF messages */

	struct {
		unsigned long p2v_rx_bad_dup_frag;
		unsigned long p2v_rx_bad_miss_frag;

		unsigned long v2p_tx_send_wait_cnt;
		unsigned long v2p_tx_send_timeout_cnt;
	} stats;
};

enum nsevf_status nsevf_msgbox_p2v_clean_rx(struct nsevf_hw *hw,
					    struct nsevf_arq_event_info *e,
					    u16 *pending);
int nsevf_msgbox_p2v_poll_virtchnl_msg(struct nsevf_hw *hw,
				       struct nsevf_arq_event_info *event,
				       enum virtchnl_ops op_to_poll);
enum nsevf_status nsevf_msgbox_init_mailboxq(struct nsevf_hw *hw);

#endif
