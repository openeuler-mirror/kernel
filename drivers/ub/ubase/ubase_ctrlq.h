/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved.
 *
 */

#ifndef __UBASE_CTRLQ_H__
#define __UBASE_CTRLQ_H__

#include <ub/ubase/ubase_comm_ctrlq.h>

#include "ubase_cmd.h"
#include "ubase_dev.h"

#define UBASE_CTRLQ_TX_TIMEOUT		30000
#define UBASE_CTRLQ_BB_LEN		32U
#define UBASE_CTRLQ_HDR_LEN		12
#define UBASE_CTRLQ_DATA_LEN		(UBASE_CTRLQ_BB_LEN - UBASE_CTRLQ_HDR_LEN)
#define UBASE_CTRLQ_MAX_BB		32
#define UBASE_CTRLQ_SCHED_TIMEOUT	(HZ / 2)
#define UBASE_CTRLQ_SEQ_MASK		BIT(15)
#define UBASE_CTRLQ_CHAN_DISABLE_OPC	0x1
#define UBASE_CTRL_PLANE_INIT_RES	BIT(0)
#define UBASE_CTRLQ_RETRY_TIMES		3
#define UBASE_CTRLQ_TX_TIMES		(UBASE_CTRLQ_RETRY_TIMES + 1)
#define UBASE_CTRLQ_ADDITIONAL_TIME	500

#define UBASE_CTRLQ_DEAD_TIME(tx_timeout) \
	((tx_timeout) * UBASE_CTRLQ_TX_TIMES + UBASE_CTRLQ_ADDITIONAL_TIME)

#define UBASE_CTRLQ_UE_MSG_HDR_LEN \
	(sizeof(struct ubase_ue2ue_ctrlq_head) + UBASE_CTRLQ_HDR_LEN)

enum ubase_ctrlq_state {
	UBASE_CTRLQ_STATE_ENABLE,
};

struct ubase_ctrlq_ue_info {
	u8	mbx_ue_id;
	u16	seq;
	u16	bus_ue_id;
};

struct ubase_ctrlq_create_tp_req {
	u8	trans_type : 4;
	u8	rsv0 : 4;
	u8	vl;
	u8	rsv1[2];
};

struct ubase_ctrlq_create_tp_resp {
	__le32	tpgn : 24;
	__le32	rsv : 8;
	__le32	tpn_cnt : 8;
	__le32	start_tpn : 24;
};

struct ubase_ctrlq_destroy_tp_req {
	u8	trans_type : 4;
	u8	rsv0 : 4;
	u8	vl;
	u8	rsv1[2];
};

struct ubase_ctrlq_tp_fd_req {
	__le32	tpn : 24;
	__le32	rsv : 8;
};

struct ubase_ctrlq_query_vl_resp {
	__le16 vl_bitmap;
	u8 rsv[18];
};

struct ubase_ctrlq_query_vl_req {
	u8 rsv[20];
};

struct ubase_ctrlq_query_sl_resp {
	__le16 unic_sl_bitmap;
	__le16 rc_max_cnt;
	__le16 udma_tp_sl_bitmap;
	__le16 udma_ctp_sl_bitmap;
	u8 rsv1[12];
};

struct ubase_ctrlq_query_sl_req {
	u8 rsv[20];
};

struct ubase_ctrlq_chan_ctrl_req {
	u8 opc;
	u8 rsv[3];
};

struct ubase_ctrlq_reset_ctrl_req {
	u8 flag;
	u8 rsv[3];
};

static inline bool ubase_ctrlq_msg_is_sync_req(struct ubase_ctrlq_msg *msg)
{
	return !msg->is_resp && !msg->is_async && msg->need_resp;
}

static inline bool ubase_ctrlq_msg_is_async_req(struct ubase_ctrlq_msg *msg)
{
	return !msg->is_resp && msg->is_async && msg->need_resp;
}

static inline bool ubase_ctrlq_msg_is_notify_req(struct ubase_ctrlq_msg *msg)
{
	return !msg->is_resp && !msg->is_async && !msg->need_resp;
}

static inline bool ubase_ctrlq_msg_is_resp(struct ubase_ctrlq_msg *msg)
{
	return msg->is_resp && !msg->is_async && !msg->need_resp;
}

int ubase_ctrlq_init(struct ubase_dev *udev);
void ubase_ctrlq_uninit(struct ubase_dev *udev);
void ubase_ctrlq_disable(struct ubase_dev *udev);

int __ubase_ctrlq_send(struct ubase_dev *udev, struct ubase_ctrlq_msg *msg,
		       bool need_retry, struct ubase_ctrlq_ue_info *ue_info);

bool ubase_ctrlq_check_seq(struct ubase_dev *udev, u16 seq);
void ubase_ctrlq_crq_service_task(struct ubase_delay_work *ubase_work);
void ubase_ctrlq_handle_crq_msg(struct ubase_dev *udev,
				struct ubase_ctrlq_base_block *head,
				u16 seq, void *msg, u16 data_len);
void ubase_ctrlq_clean_service_task(struct ubase_dev *udev);
void ubase_ctrlq_disable_remote(struct ubase_dev *udev);
int ubase_ctrlq_ue_req_event_callback(struct ubase_dev *udev,
				      struct ubase_ue2ue_ctrlq_head *cmd);

#endif /* __UBASE_CTRLQ_H__ */
