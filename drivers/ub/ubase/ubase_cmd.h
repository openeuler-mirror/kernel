/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved.
 *
 */

#ifndef __UBASE_CMD_H__
#define __UBASE_CMD_H__

#include <ub/ubase/ubase_comm_cmd.h>

#include "ubase_dev.h"

#define UBASE_CMDQ_DESC_NUM_S		3
#define UBASE_CMDQ_DESC_NUM		1024
#define UBASE_CMDQ_TX_TIMEOUT		300000
#define UBASE_CMDQ_MBX_TX_TIMEOUT	3000
#define UBASE_CMDQ_CLEAR_WAIT_TIME	200
#define UBASE_CMDQ_WAIT_TIME		10

#define UBASE_CMD_FLAG_IN		BIT(0)
#define UBASE_CMD_FLAG_OUT		BIT(1)
#define UBASE_CMD_FLAG_NEXT		BIT(2)
#define UBASE_CMD_FLAG_WR		BIT(3)
#define UBASE_CMD_FLAG_NO_INTR		BIT(4)
#define UBASE_CMD_FLAG_ERR_INTR		BIT(5)
#define UBASE_CMD_FLAG_GET_BD_NUM	BIT(6)

#define UBASE_UE2UE_MSG_WAIT_TIME	3000

#define UBASE_CRQ_SCHED_TIMEOUT		(HZ / 2)

#define UBASE_CMD_HEADER_LENGTH		8
#define UBASE_CMD_DATA_LENGTH		(UBASE_DESC_DATA_LEN * sizeof(__le32))
#define UBASE_CMD_MAX_DESC_SIZE \
	(UBASE_CMDQ_DESC_NUM * sizeof(struct ubase_cmdq_desc))

#define UBASE_MOVE_CRQ_RING_PTR(crq) \
	((crq)->ci = ((crq)->ci + 1) % (crq)->desc_num)

union ubase_mbox {
	struct {
		/* MB 0 */
		__le32 in_param_l;
		/* MB 1 */
		__le32 in_param_h;
		/* MB 2 */
		__le32 cmd : 8;
		__le32 tag : 24;
		/* MB 3 */
		__le32 seq_num : 16;
		__le32 event_en : 1;
		__le32 mbx_ue_id : 8;
		__le32 rsv : 7;
		/* MB 4 */
		__le32 status : 1;
		__le32 hw_run : 1;
		__le32 rsv1 : 30;
	};

	struct {
		__le32 query_status : 1;
		__le32 query_hw_run : 1;
		__le32 query_rsv : 30;
	};
};

#define UBASE_DESC_DATA_LEN	6
struct ubase_cmdq_desc {
	__le16 opcode;
	u8 flag;
	u8 bd_num;
	__le16 ret;
	__le16 rsv;
	__le32 data[UBASE_DESC_DATA_LEN];
};

enum ubase_cmd_state {
	UBASE_STATE_CMD_DISABLE
};

struct ubase_query_version_cmd {
	__le32	fw_version;
	u8	rsv[20];
};

enum ubase_drv_cap_bit {
	UBASE_CAP_SUP_ACTIVATE_B = 0,
	UBASE_PMU_CRQ_SUPPORT_B  = 1,
};

struct ubase_notify_drv_cap_cmd {
	u8	cap_bits[24]; /* see ubase_drv_cap_bit */
};

#define UBASE_UBCL_CFG_DATA_ALIGN	4
#define UBASE_UBCL_CFG_DATA_NUM		60
struct ubase_ubcl_config_cmd {
	__le16	is_query_size;
	__le16	offset;
	__le16	size;
	__le16	rsv;
	__le32	data[UBASE_UBCL_CFG_DATA_NUM];
};

enum ubase_ue2ue_sub_cmd {
	UBASE_UE2UE_CTRLQ_MSG = 3,
};

struct ubase_ue2ue_common_head {
	__le16 bus_ue_id;
	__le16 mbx_ue_id;
	u16 sub_cmd;
	u16 status;
};

struct ubase_ue2ue_ctrlq_head {
	struct ubase_ue2ue_common_head head;
	u16 seq;
	u16 in_size;
	u16 out_size;
	u8 need_resp : 1;
	u8 is_resp : 1;
	u8 is_async : 1;
	u8 rsv : 5;
};

struct ubase_start_perf_stats_cmd {
	__le32	period;
	__le32	logic_port_bitmap[2];
	u8	rsv[12];
};

struct ubase_stop_perf_stats_cmd {
	__le32	period; /* ms */
	__le16	port_id;
	u8	rsv[2];

	__le32	tx_port_bw; /* kbps */
	__le32	rx_port_bw;
	__le32	tx_vl_bw[UBASE_STATS_MAX_VL_NUM];
	__le32	rx_vl_bw[UBASE_STATS_MAX_VL_NUM];

	__le32	tx_max_port_bw;
	__le32	rx_max_port_bw;
};

struct ubase_cfg_ets_vl_sch_cmd {
	__le16 vl_bitmap;
	u8 rsvd[2];
	u8 vl_bw[UBASE_MAX_VL_NUM];
	__le32 port_bitmap;
};

struct ubase_query_dl_pkt_stats_cmd {
	__le16	logic_port_id;
	u8	rsvd[2];
	__le32	tx_flit_num_l;
	__le32	tx_flit_num_h;
	__le32	rx_flit_num_l;
	__le32	rx_flit_num_h;
	u8	rsvd1[4];
};

struct ubase_cfg_tm_vl_sch_cmd {
	u8 rsvd0[2];
	__le16 vl_bitmap;
	__le16 vl_tsa;
	u8 rsvd1[2];
	u8 vl_bw[UBASE_MAX_VL_NUM];
};

struct ubase_ets_shaping_info {
	u8 ir_b;
	u8 ir_u;
	u8 ir_s;
	u8 bs_b;
	u8 bs_s;
	u8 rsvd[3];
	__le32 rate;
};

struct ubase_query_ets_tcg_cmd {
	u8 tcg_weight[UBASE_MAX_TCG_NUM];
	__le16 tcg_tc_map[UBASE_MAX_TCG_NUM];
	struct ubase_ets_shaping_info tcg_info[UBASE_MAX_TCG_NUM];
};

struct ubase_query_ets_port_cmd {
	struct ubase_ets_shaping_info port_info;
};

struct ubase_fst_revert_tbl {
	__le16 fst_idx;
	u8 queue_ue_num;
	u8 queue_que_num;
	__le16 queue_vl_num;
	u8 resv[2];
};

struct ubase_rqmt_tbl {
	__le16 fst_idx;
	__le16 start_queue_idx;
	__le16 queue_quantity_shift;
	u8 resv[2];
};

struct ubase_query_fst_fvt_rqmt_cmd {
	__le16 bus_ue_id;
	u8 rsv[2];
	__le16 sl_queue_vl_num;
	__le16 sl_queue_start_qid;
	__le16 fvt_vl_size;
	__le16 fvt_rqmt_offset;
	struct ubase_fst_revert_tbl fstr_info[UBASE_MAX_VL_NUM];
	struct ubase_rqmt_tbl rqmt_info[UBASE_MAX_VL_NUM];
};

struct ubase_query_tm_queue_cmd {
	__le16 bus_ue_id;
	u8 queue_num;
	u8 resv0;
	u8 queue_vl[UBASE_MAX_VL_NUM];
	u8 queue_id[UBASE_MAX_VL_NUM];
	u8 qset_id[UBASE_MAX_VL_NUM];
	__le16 link_vld_bitmap;
	u8 resv1[2];
};

struct ubase_query_tm_qset_cmd {
	__le16 bus_ue_id;
	u8 qset_num;
	u8 rate_limit_bypass;
	u8 ir_b[UBASE_MAX_VL_NUM];
	u8 ir_u[UBASE_MAX_VL_NUM];
	u8 ir_s[UBASE_MAX_VL_NUM];
	u8 bs_b[UBASE_MAX_VL_NUM];
	u8 bs_s[UBASE_MAX_VL_NUM];
	__le32 rate[UBASE_MAX_VL_NUM];
	u8 qset_id[UBASE_MAX_VL_NUM];
	u8 pri_id[UBASE_MAX_VL_NUM];
	__le16 qset_pri_link_vld;
	__le16 qset_sch_mode;
	u8 qset_weight[UBASE_MAX_VL_NUM];
	u8 resv1[16];
};

struct ubase_query_tm_pri_cmd {
	__le16 bus_ue_id;
	u8 pri_id;
	u8 pg_id;
	u8 pri_sch_mode;
	u8 pri_weight;
	u8 c_ir_b;
	u8 c_ir_u;
	u8 c_ir_s;
	u8 c_bs_b;
	u8 c_bs_s;
	u8 p_ir_b;
	u8 p_ir_u;
	u8 p_ir_s;
	u8 p_bs_b;
	u8 p_bs_s;
	__le32 c_rate;
	__le32 p_rate;

	u8 c_rate_limit_bypass;
	u8 p_rate_limit_bypass;
	u8 resv1[30];
};

struct ubase_query_tm_pg_cmd {
	__le16 bus_ue_id;
	u8 pg_id;
	u8 pg_sch_mode;
	u8 pg_weight;
	u8 c_ir_b;
	u8 c_ir_u;
	u8 c_ir_s;
	u8 c_bs_b;
	u8 c_bs_s;
	u8 p_ir_b;
	u8 p_ir_u;
	u8 p_ir_s;
	u8 p_bs_b;
	u8 p_bs_s;
	u8 resv0;
	__le32 c_rate;
	__le32 p_rate;

	u8 c_rate_limit_bypass;
	u8 p_rate_limit_bypass;
	u8 resv1[30];
};

struct ubase_query_tm_port_cmd {
	u8 ir_b;
	u8 ir_u;
	u8 ir_s;
	u8 bs_b;
	u8 bs_s;
	u8 rate_limit_bypass;
	u8 resv0[2];
	__le32 rate;
	u8 resv1[12];
};

struct ubase_config_vl_speed_cmd {
	u8 resv0[2];
	__le16 vl_bitmap;
	__le32 max_speed[UBASE_MAX_VL_NUM];
	u8 resv1[20];
};

struct ubase_activate_req {
	__le16	bus_ue_id;
	__le16	msn;
	u8	activate;
	u8	shutdown;
	u8	resv[18];
};

struct ubase_activate_resp {
	__le16	bus_ue_id;
	__le16	msn;
	u8	result;
	u8	resv[19];
};

struct ubase_query_ueid_cmd {
	__le32 ueid[UBASE_BUS_EID_LEN];
	u32 rsv[2];
};

static inline void __ubase_fill_inout_buf(struct ubase_cmd_buf *buf, u16 opcode,
					  bool is_read, u32 data_size, void *data)
{
	buf->opcode = opcode;
	buf->is_read = is_read;
	buf->data_size = data_size;
	buf->data = data;
}

int ubase_cmd_init(struct ubase_dev *udev);
void ubase_cmd_uninit(struct ubase_dev *udev);

static inline void __ubase_cmd_enable(struct ubase_dev *udev)
{
	clear_bit(UBASE_STATE_CMD_DISABLE, &udev->hw.state);
}

static inline void __ubase_cmd_disable(struct ubase_dev *udev)
{
	set_bit(UBASE_STATE_CMD_DISABLE, &udev->hw.state);
}

void ubase_cmd_disable(struct ubase_dev *udev);

void ubase_cmd_setup_basic_desc(struct ubase_cmdq_desc *desc,
				enum ubase_opcode_type opcode, bool is_read,
				u8 num);
int ubase_send_cmd(struct ubase_dev *udev,
		   struct ubase_cmdq_desc *desc, int num);

int ubase_post_mailbox_by_event(struct ubase_dev *udev,
				struct ubase_cmd_buf *in,
				struct ubase_cmd_buf *out,
				struct ubase_cmd_mailbox *mailbox);
int __ubase_cmd_send_in(struct ubase_dev *udev, struct ubase_cmd_buf *in);
int __ubase_cmd_send_inout(struct ubase_dev *udev, struct ubase_cmd_buf *in,
			   struct ubase_cmd_buf *out);

int __ubase_register_crq_event(struct ubase_dev *udev,
			       struct ubase_crq_event_nb *nb);
void __ubase_unregister_crq_event(struct ubase_dev *udev, u16 opcode);

void ubase_crq_service_task(struct ubase_delay_work *ubase_work);

void ubase_mask_key_words(struct ubase_cmdq_desc *desc, u16 opc, int idx);

#endif /* __UBASE_CMD_H__ */
