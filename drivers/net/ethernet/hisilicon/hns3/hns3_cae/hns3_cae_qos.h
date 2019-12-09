/* SPDX-License-Identifier: GPL-2.0+ */
/* Copyright (c) 2016-2019 Hisilicon Limited. */

#ifndef __HNS3_CAE_QOS_H__
#define __HNS3_CAE_QOS_H__

#include "hns3_cae_tm.h"

struct hns3_rx_priv_buff_wl_param {
	u32 tc_no;
	u32 high_wl;
	u32 low_wl;
	u8 is_read;
};

struct hns3_tx_buff_param {
	u16 buff_size[MAX_TC_NUM];
	u8 is_read;
};

struct hns3_rx_buff_param {
	u16 buff_size[MAX_TC_NUM];
	u16 share_buff;
	u8 is_read;
};

struct hns3_rx_priv_wl {
	u16 high;
	u16 low;
};

struct hns3_total_priv_wl_param {
	struct hns3_rx_priv_wl priv_wl[MAX_TC_NUM];
};

enum opt_type {
	IS_READ = 1,
	IS_WRITE,
};

#define HNS3_QOS_QCN_MASK		0xF0000
#define HNS3_QCN_SHAP_BYPASS_MASK	0xCFFFF
#define HNS3_QOS_QCN_BYPASS_MASK	0x20000
#define HNS3_QCN_SHAP_BYPASS_OFF	17

int hns3_cae_rx_priv_buff_wl_cfg(struct hns3_nic_priv *net_priv,
				 void *buf_in, u32 in_size,
				 void *buf_out, u32 out_size);
int hns3_cae_common_thrd_cfg(struct hns3_nic_priv *net_priv,
			     void *buf_in, u32 in_size,
			     void *buf_out, u32 out_size);
int hns3_cae_common_wl_cfg(struct hns3_nic_priv *net_priv,
			   void *buf_in, u32 in_size,
			   void *buf_out, u32 out_size);
int hns3_cae_tx_buff_cfg(struct hns3_nic_priv *net_priv,
			 void *buf_in, u32 in_size,
			 void *buf_out, u32 out_size);
int hns3_cae_rx_buff_cfg(struct hns3_nic_priv *net_priv,
			 void *buf_in, u32 in_size,
			 void *buf_out, u32 out_size);
int hns3_cae_show_rx_priv_wl(struct hns3_nic_priv *net_priv,
			     void *buf_in, u32 in_size,
			     void *buf_out, u32 out_size);
int hns3_cae_show_comm_thres(struct hns3_nic_priv *net_priv,
			     void *buf_in, u32 in_size,
			     void *buf_out, u32 out_size);
int hns3_cae_qcn_cfg(struct hns3_nic_priv *net_priv,
		     void *buf_in, u32 in_size, void *buf_out, u32 out_size);

#endif
