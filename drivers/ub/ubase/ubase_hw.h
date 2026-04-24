/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved.
 *
 */

#ifndef __UBASE_HW_H__
#define __UBASE_HW_H__

#include <ub/ubase/ubase_comm_mbx.h>

#include "ubase_dev.h"
#include "ubase_cmd.h"

#define UBASE_CTX_REMOVE_ALL		(-2)

#define UBASE_DEF_CEQ_VECTOR_NUM	1
#define UBASE_DEF_AEQ_VECTOR_NUM	1
#define UBASE_DEF_MISC_VERCTOR_NUM	1
#define UBASE_DEF_PUBLIC_JETTY_CNT	1024
#define UBASE_DEF_EQE_SIZE		64
#define UBASE_DEF_AEQ_DEPTH		512
#define UBASE_DEF_CEQ_DEPTH		4096

struct ubase_caps_item {
	void		*p;
	u32		default_val;
	u8		size;
	const char	*name;
};

struct ubase_res_cmd_resp {
	__le32	cap_bits[UBASE_CAP_LEN];
	__le32	rsvd0[3];

	u8	node_type;
	u8	rsvd1;
	__le16	ceq_vector_num;
	__le16	aeq_vector_num;
	__le16	misc_vector_num;
	__le16	aeqe_size;
	__le16	ceqe_size;
	__le16	udma_cqe_size;
	__le16	nic_cqe_size;
	__le32	aeqe_depth;
	__le32	ceqe_depth;
	__le32	udma_jfs_max_cnt;
	u8	rsvd2[4];

	__le32	udma_jfs_depth;
	__le32	udma_jfr_max_cnt;
	u8	rsvd3[4];
	__le32	udma_jfr_depth;
	u8	rsvd4[12];
	__le32	udma_jfc_max_cnt;

	u8	rsvd5[4];
	__le32	udma_jfc_depth;
	u8	rsvd6[24];

	__le32	nic_jfs_max_cnt;
	u8	rsvd7[4];
	__le32	nic_jfs_depth;
	__le32	nic_jfr_max_cnt;
	u8	rsvd8[4];
	__le32	nic_jfr_depth;
	__le32	rsvd9[2];

	__le32	rsvd10;
	__le32	nic_jfc_max_cnt;
	u8	rsvd11[4];
	__le32	nic_jfc_depth;
	u8	rsvd12[16];

	u8	rsvd13[8];
	__le32	total_ue_num;
	u8	rsvd14[16];
	__le16	rsvd_jetty_cnt;
	__le16	mac_stats_num;

	__le32	ta_extdb_buf_size;
	__le32	ta_timer_buf_size;
	__le32	public_jetty_cnt;
	u8	rsvd15[10];
	u8	udma_tp_resp_vl_offset;
	u8	ue_num;
	u8	rsvd16[8];

	u8	rsvd17[8];
	__le32	udma_rc_depth;
	u8	rsvd18[4];
	__le32	jtg_max_cnt;
	__le32	rc_max_cnt_per_vl;
	u8	rsvd19[8];

	u8	rsvd20[32];
};

struct ubase_query_oor_resp {
	u8	oor_en;
	u8	reorder_cq_buffer_en;
	u8	reorder_cap;
	u8	reorder_cq_shift;
	__le32	on_flight_size;
	u8	dynamic_ack_timeout;
	u8	rsvd0[15];
};

struct ubase_query_port_bitmap_resp {
	__le32 logic_port_bitmap;
	__le32 chip_id;
	__le32 die_id;
	__le32 resv[3];
};

struct ubase_query_controller_info_resp {
	__le32	rsvd0[2];
	u8	packet_pattern_mode : 1;
	u8	ack_queue_num : 4;
	u8	rsvd1 : 3;
	u8	rsvd2[15];
};

struct ubase_cfg_dma_buf_req {
	__le32 addr_l;
	__le32 addr_h;
	__le32 tp_num; /* only used when cfg TP extdb buf */
	__le32 resv[3];
};

struct ubase_query_sl_vl_cmd {
	u8	sl_num;
	u8	sl_vl[23];
};

struct ubase_query_chip_die_cmd {
	__le16	nl_port_id;
	__le16	chip_id;
	__le16	die_id;
	__le16	io_port_id;
	__le16	ue_id;
	__le16	ub_port_logic_id;
	__le16	nl_id;
	__le16	io_port_logic_id;
};

struct ubase_ctx_buf_map {
	struct ubase_ctx_buf_cap *ctx;
	u16 mb_cmd;
};

struct ubase_query_ctp_vl_offset_cmd {
	u8	ctp_vl_offset;
	u8	rsv[23];
};

int ubase_hw_init(struct ubase_dev *udev);
void ubase_hw_uninit(struct ubase_dev *udev);
int ubase_query_sl_vl_map(struct ubase_dev *udev, u8 *sl_vl);
int ubase_qos_init(struct ubase_dev *udev);
void ubase_qos_uninit(struct ubase_dev *udev);
int ubase_query_ets_tc(struct ubase_dev *udev, u32 port_bitmap,
		       u16 vl_bitmap, struct ubase_cfg_ets_vl_sch_cmd *resp);
int ubase_query_ets_tcg(struct ubase_dev *udev,
			struct ubase_query_ets_tcg_cmd *resp);
int ubase_query_ets_port(struct ubase_dev *udev,
			 struct ubase_query_ets_port_cmd *resp);
int ubase_query_dev_res(struct ubase_dev *udev);
int ubase_query_chip_info(struct ubase_dev *udev);
int ubase_query_controller_info(struct ubase_dev *udev);
int ubase_query_hw_oor_caps(struct ubase_dev *udev);
int ubase_query_tm_queue(struct ubase_dev *udev, u16 bus_ue_id,
			 struct ubase_query_tm_queue_cmd *resp);
int ubase_query_tm_qset(struct ubase_dev *udev, u16 bus_ue_id,
			struct ubase_query_tm_qset_cmd *resp);
int ubase_query_tm_pri(struct ubase_dev *udev, u16 bus_ue_id,
		       struct ubase_query_tm_pri_cmd *resp);
int ubase_query_tm_pg(struct ubase_dev *udev, u16 bus_ue_id,
		      struct ubase_query_tm_pg_cmd *resp);
int ubase_query_tm_port(struct ubase_dev *udev,
			struct ubase_query_tm_port_cmd *resp);
int ubase_ue_init(struct ubase_dev *udev);
void ubase_ue_uninit(struct ubase_dev *udev);
int ubase_query_fst_fvt_rqmt(struct ubase_dev *udev,
			     struct ubase_query_fst_fvt_rqmt_cmd *resp,
			     u16 bus_ue_id);
int ubase_query_port_bitmap(struct ubase_dev *udev);
int __ubase_cmd_ctx_buf_alloc(struct ubase_dev *udev,
			      struct ubase_ctx_buf_cap *ctx_buf,
			      struct ubase_mbx_attr *attr);
void __ubase_cmd_ctx_buf_free(struct ubase_dev *udev,
			      struct ubase_ctx_buf_cap *ctx_buf);
int __ubase_perf_stats(struct ubase_dev *udev, u64 port_bitmap, u32 period,
		       struct ubase_perf_stats_result *data, u32 data_size);
int ubase_config_ctx_buf_to_hw(struct ubase_dev *udev,
			       struct ubase_ctx_buf_cap *ctx_buf,
			       struct ubase_mbx_attr *attr);

#endif /* __UBASE_HW_H__ */
