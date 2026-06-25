/* SPDX-License-Identifier: GPL-2.0+ */
/* Copyright(c) 2025 HiSilicon Technologies CO., Ltd. All rights reserved. */

#ifndef __UDMA_CTRLQ_TP_H__
#define __UDMA_CTRLQ_TP_H__

#include <linux/wait.h>
#include "udma_common.h"

#define UDMA_EID_SIZE		16
#define UDMA_CNA_SIZE		16
#define UDMA_PID_MASK		0xFFFFFF
#define UDMA_DEFAULT_PID	1
#define UDMA_UE_NUM		64
#define UDMA_MAX_UE_IDX		256
#define UDMA_MAX_TPID_NUM	32
#define UDMA_IP_SIZE		16
#define UDMA_CTRLQ_SER_TYPE_UBMEM 5
#define UDMA_CTRLQ_EID_TYPE_128 1
#define UDMA_CTRLQ_UBMEM_INFO_NUM (205)
#define UDMA_CTRLQ_HOST_UBMEM_INFO_NUM (8)
#define UDMA_TPN_CNT_MASK 0x1F
#define UDMA_GLOBAL_TP_HANDLE	UINT32_MAX
#define UDMA_UDP_RANGE_MAX	8
#define UDMA_UDP_ATTR_MASK	0x1F
#define UDMA_UDP_ATTR_SHIFT	12
#define UDMA_UDP_ATTR_NUM	5
#define UDMA_UDP_GLOBAL_MASK	0x1
#define UDMA_UDP_GLOBAL_SHIFT	16

enum udma_ctrlq_cmd_code_type {
	UDMA_CMD_CTRLQ_REMOVE_SINGLE_TP = 0x13,
	UDMA_CMD_CTRLQ_TP_FLUSH_DONE,
	UDMA_CMD_CTRLQ_CHECK_TP_ACTIVE,
	UDMA_CMD_CTRLQ_TP_PORT_CHANGE = 0x16,
	UDMA_CMD_CTRLQ_GET_EID_BY_IP = 0x17,
	UDMA_CMD_CTRLQ_GET_IP_BY_EID,
	UDMA_CMD_CTRLQ_GET_TP_LIST = 0x21,
	UDMA_CMD_CTRLQ_ACTIVE_TP,
	UDMA_CMD_CTRLQ_DEACTIVE_TP,
	UDMA_CMD_CTRLQ_SET_TP_ATTR,
	UDMA_CMD_CTRLQ_GET_TP_ATTR,
	UDMA_CMD_CTRLQ_GET_TP_INFO,
	UDMA_CMD_CTRLQ_GET_TPID_NUM,
	UDMA_CMD_CTRLQ_TPID_DESTROY_DONE,
	UDMA_CMD_CTRLQ_MAX
};

enum udma_ctrlq_ubmem_opcode {
	UDMA_CTRLQ_QUERY_UBMEM_INFO = 0x1,
	UDMA_CTRLQ_QUERY_HOST_UBMEM_INFO,
};

enum udma_link_mode {
	UDMA_LINK_MODE_UB,
	UDMA_LINK_MODE_UBOE,
};

enum udma_ctrlq_trans_type {
	UDMA_CTRLQ_TRANS_TYPE_TP_RM = 0,
	UDMA_CTRLQ_TRANS_TYPE_CTP,
	UDMA_CTRLQ_TRANS_TYPE_TP_UM,
	UDMA_CTRLQ_TRANS_TYPE_TP_RC = 4,
	UDMA_CTRLQ_TRANS_TYPE_UBOE_RM,
	UDMA_CTRLQ_TRANS_TYPE_UBOE_RC,
	UDMA_CTRLQ_TRANS_TYPE_UBOE_UM,
	UDMA_CTRLQ_TRANS_TYPE_STATIC_TP,
	UDMA_CTRLQ_TRANS_TYPE_STATIC_CTP,
	UDMA_CTRLQ_TRANS_TYPE_MAX
};

enum udma_ctrlq_tpid_status {
	UDMA_CTRLQ_TPID_IN_USE = 0,
	UDMA_CTRLQ_TPID_EXITED,
	UDMA_CTRLQ_TPID_IDLE,
};

struct udma_ctrlq_tpid {
	uint32_t tpid : 24;
	uint32_t tpn_cnt : 8;
	uint32_t tpn_start : 24;
	uint32_t rsv0 : 4;
	uint32_t migr : 1;
	uint32_t rsv1 : 3;
};

struct udma_ctrlq_tpid_list_rsp {
	uint32_t tp_list_cnt : 16;
	uint32_t rsv : 16;
	struct udma_ctrlq_tpid tpid_list[UDMA_MAX_TPID_NUM];
};

struct udma_ctrlq_active_tp_req_data {
	uint32_t local_tp_id : 24;
	uint32_t local_tpn_cnt : 8;
	uint32_t local_tpn_start : 24;
	uint32_t rsv : 8;
	uint32_t remote_tp_id : 24;
	uint32_t remote_tpn_cnt : 8;
	uint32_t remote_tpn_start : 24;
	uint32_t rsv1 : 8;
	uint32_t local_psn;
	uint32_t remote_psn;
};

struct udma_ctrlq_active_tp_resp_data {
	uint32_t local_tp_id : 24;
	uint32_t local_tpn_cnt : 8;
	uint32_t local_tpn_start : 24;
	uint32_t rsv : 8;
};

struct udma_ctrlq_deactive_tp_req_data {
	uint32_t tp_id : 24;
	uint32_t tpn_cnt : 8;
	uint32_t start_tpn : 24;
	uint32_t rsv : 8;
	uint32_t pid_flag : 24;
	uint32_t rsv1 : 8;
};

struct udma_ctrlq_tp_flush_done_req_data {
	uint32_t tpn : 24;
	uint32_t rsv : 8;
};

struct udma_ctrlq_remove_single_tp_req_data {
	uint32_t tpn : 24;
	uint32_t tp_status : 8;
};

struct udma_ctrlq_tpn_data {
	uint32_t tpg_flag : 8;
	uint32_t rsv : 24;
	uint32_t tpgn : 24;
	uint32_t rsv1 : 8;
	uint32_t tpn_cnt : 8;
	uint32_t start_tpn : 24;
};

struct udma_ctrlq_check_tp_active_req_data {
	uint32_t tp_id : 24;
	uint32_t rsv : 8;
	uint32_t pid_flag : 24;
	uint32_t rsv1 : 8;
};

struct udma_ctrlq_check_tp_active_req_info {
	uint32_t num : 8;
	uint32_t rsv : 24;
	struct udma_ctrlq_check_tp_active_req_data data[0];
};

struct udma_ctrlq_tpid_destroy_done_out_data {
	uint32_t tp_id : 24;
	uint32_t rsv : 8;
};

struct udma_ctrlq_tpid_destroy_done_rsp_data {
	uint32_t tp_id : 24;
	uint32_t rsv : 8;
};

struct udma_ctrlq_check_tp_active_rsp_data {
	uint32_t tp_id : 24;
	uint32_t result : 8;
};

struct udma_ctrlq_check_tp_active_rsp_info {
	uint32_t num : 8;
	uint32_t rsv : 24;
	struct udma_ctrlq_check_tp_active_rsp_data data[0];
};

struct udma_ctrlq_tp_port_change_req_data {
	uint32_t tpn : 24;
	uint32_t rsv : 8;
};

struct udma_ctrlq_get_tp_list_req_data {
	uint8_t seid[UDMA_EID_SIZE];
	uint8_t deid[UDMA_EID_SIZE];
	uint32_t trans_type : 4;
	uint32_t rsv : 28;
	uint32_t rsv1 : 8;
	uint32_t group_id : 16;
	uint32_t max_tp_cnt : 8;
};

enum udma_cmd_ue_opcode {
	UDMA_CMD_UBCORE_COMMAND = 0x1,
	UDMA_CMD_NOTIFY_MUE_SAVE_TP = 0x2,
	UDMA_CMD_NOTIFY_UE_FLUSH_DONE = 0x3,
	UDMA_CMD_NOTIFY_MUE_DELETE_GUID = 0x4,
};

struct udma_ue_tp_info {
	uint32_t tp_cnt : 8;
	uint32_t start_tpn : 24;
};

struct udma_ctrlq_tp_info_req_data {
	uint32_t tp_id : 24;
	uint32_t rsv : 8;
};

struct udma_ctrlq_tp_info_resp_data {
	uint32_t tp_id : 24;
	uint32_t rsv : 8;
	uint32_t rep_start_tpn : 24;
	uint32_t req_tpn_cnt : 8;
	uint32_t resp_start_tpn : 24;
	uint32_t resp_tpn_cnt : 8;
	uint32_t normal_tp_cnt : 8;
	uint32_t error_tp_cnt : 8;
	uint32_t deactive_tp_cnt : 8;
	uint32_t rsv1 : 8;
};

struct udma_ue_idx_table {
	uint32_t num;
	uint8_t ue_idx[UDMA_UE_NUM];
};

struct udma_ctrlq_ubmem_out_query {
	uint32_t data[UDMA_CTRLQ_UBMEM_INFO_NUM];
};

struct udma_ctrlq_host_ubmem_out_query {
	uint32_t data[UDMA_CTRLQ_HOST_UBMEM_INFO_NUM];
};

struct udma_ctrlq_tp_attr {
	uint32_t tp_attr_bitmap;
	struct ubcore_tp_attr_value tp_attr_value;
};

struct udma_ctrlq_get_tp_attr_req {
	struct udma_ctrlq_tpid tpid;
};

struct udma_cmdq_info {
	struct xarray seq_tbl;
	uint32_t seq_num;
	struct mutex seq_lock;
};

struct udma_cmdq_wait_info {
	struct completion ret_completion;
	uint32_t seq_num;
	int ret;
};

struct udma_ctrlq_set_tp_attr_req {
	uint32_t tpid : 24;
	uint32_t tpn_cnt : 8;
	uint32_t tpn_start : 24;
	uint32_t tp_attr_cnt : 8;
	struct udma_ctrlq_tp_attr tp_attr;
};

struct udma_ctrlq_get_tp_attr_resp {
	uint32_t tpid : 24;
	uint32_t tp_attr_cnt : 8;
	struct udma_ctrlq_tp_attr tp_attr;
};

struct udma_dev_resource_ratio {
	struct ubase_bus_eid eid;
	uint32_t index;
};

struct udma_ctrlq_get_eid_by_ip_req {
	uint32_t addr_type : 8;
	uint32_t rsv : 24;
	uint8_t ip[UDMA_IP_SIZE];
};

struct udma_ctrlq_get_ip_by_eid_req {
	uint32_t eid_type : 8;
	uint32_t rsv : 24;
	uint8_t eid[UDMA_EID_SIZE];
};

struct udma_ctrlq_get_eid_by_ip_resp {
	uint8_t eid[UDMA_EID_SIZE];
};

struct udma_ctrlq_get_ip_by_eid_resp {
	uint32_t addr_type : 8;
	uint32_t rsv : 24;
	uint8_t ip[UDMA_IP_SIZE];
};

struct udma_ctrlq_query_host_ubmem_req {
	struct ubase_bus_eid eid;
};

struct udma_ae_work {
	struct udma_dev	*udev;
	uint32_t tpn;
	struct work_struct work;
};

int udma_query_pair_dev_count(struct ubcore_device *dev, struct ubcore_ucontext *uctx,
			      struct ubcore_user_ctl_in *in, struct ubcore_user_ctl_out *out);

int udma_get_dev_resource_ratio(struct ubcore_device *dev, struct ubcore_ucontext *uctx,
				struct ubcore_user_ctl_in *in, struct ubcore_user_ctl_out *out);

int udma_register_npu_cb(struct ubcore_device *dev, struct ubcore_ucontext *uctx,
			 struct ubcore_user_ctl_in *in, struct ubcore_user_ctl_out *out);

int udma_unregister_npu_cb(struct ubcore_device *dev, struct ubcore_ucontext *uctx,
			   struct ubcore_user_ctl_in *in, struct ubcore_user_ctl_out *out);
int udma_ctrlq_tp_flush_done(struct udma_dev *udev, uint32_t tpn);
int udma_ctrlq_remove_single_tp(struct udma_dev *udev, uint32_t tpn, int status);
int udma_get_tp_list(struct ubcore_device *dev, struct ubcore_get_tp_cfg *tpid_cfg,
		     uint32_t *tp_cnt, struct ubcore_tp_info *tp_list,
		     struct ubcore_udata *udata);

void udma_ctrlq_destroy_tpid_list(struct xarray *ctrlq_tpid_table);
int udma_ctrlq_tpn_flush_done(struct udma_dev *dev, struct xarray *ctrlq_tpid_table,
			      uint32_t tp_id, bool is_udata);
int udma_ctrlq_set_active_tp_ex(struct udma_dev *dev,
				struct ubcore_active_tp_cfg *active_cfg);
int udma_k_ctrlq_deactive_tp(struct udma_dev *udev, union ubcore_tp_handle tp_handle,
			     struct ubcore_udata *udata);

int udma_ctrlq_query_ubmem_info(struct ubcore_device *dev, struct ubcore_ucontext *uctx,
				struct ubcore_user_ctl_in *in, struct ubcore_user_ctl_out *out);

int udma_ctrlq_query_host_ubmem_info(struct ubcore_device *dev, struct ubcore_ucontext *uctx,
				     struct ubcore_user_ctl_in *in,
				     struct ubcore_user_ctl_out *out);

int udma_set_tp_attr(struct ubcore_device *dev, const uint64_t tp_handle,
		     const uint8_t tp_attr_cnt, const uint32_t tp_attr_bitmap,
		     const struct ubcore_tp_attr_value *tp_attr, struct ubcore_udata *udata);
int udma_get_tp_attr(struct ubcore_device *dev, const uint64_t tp_handle,
		     uint8_t *tp_attr_cnt, uint32_t *tp_attr_bitmap,
		     struct ubcore_tp_attr_value *tp_attr, struct ubcore_udata *udata);
int udma_send_msg_to_ue(struct udma_dev *udma_dev, struct udma_entity_buf *add_buf,
			uint8_t dst_ue_idx, uint16_t opcode);
void udma_notify_mue_delete_guid(struct udma_dev *dev);
int udma_recv_resp_from_mue(struct udma_dev *udev, struct udma_entity_msg *resp, uint32_t len);
int udma_send_resp_to_ue(struct udma_dev *udev,
			 struct udma_entity_msg *req, int ret_val, uint16_t opcode);
int udma_active_tp(struct ubcore_device *dev, struct ubcore_active_tp_cfg *active_cfg);
int udma_deactive_tp(struct ubcore_device *dev, union ubcore_tp_handle tp_handle,
		     struct ubcore_udata *udata);
int udma_ctrlq_notify_tp_port_change(struct udma_dev *udev, uint32_t tpn);
int udma_get_smac(struct ubcore_device *dev, uint8_t *mac);
int udma_get_eid_by_ip(struct ubcore_device *dev, const struct ubcore_net_addr *net_addr,
		       union ubcore_eid *eid);
int udma_get_ip_by_eid(struct ubcore_device *dev, const union ubcore_eid *eid,
		       struct ubcore_net_addr *net_addr);
void udma_tp_ae_work(struct work_struct *work);
void udma_dispatch_tpid_destroy_done(struct udma_dev *dev,
				     struct udma_ctrlq_tpid_destroy_done_out_data *tpid_entry);

#endif /* __UDMA_CTRLQ_TP_H__ */
