/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 *
 * Description: ubagg ioctl head file
 * Author: Dongxu Li
 * Create: 2025-1-26
 * Note:
 * History: 2025-1-26: Create file
 */
#ifndef UBAGG_IOCTL_H
#define UBAGG_IOCTL_H

#include <ub/urma/ubcore_types.h>
#include "ubagg_topo_info.h"
#include "ubagg_types.h"

enum ubagg_cmd {
	UBAGG_CMD_ADD_DEV = 1,
	UBAGG_CMD_RMV_DEV,
	UBAGG_CMD_SET_TOPO_INFO,
	UBAGG_CMD_CREATE_DEV,
	UBAGG_CMD_DELETE_DEV,
	UBAGG_CMD_GET_DEV_NAME,
};

struct ubagg_cmd_hdr {
	uint32_t command;
	uint32_t args_len;
	uint64_t args_addr;
};

#define UBAGG_CMD_MAGIC 'B'
#define UBAGG_CMD _IOWR(UBAGG_CMD_MAGIC, 1, struct ubagg_cmd_hdr)

#define UBAGG_EID_SIZE (16)

/** A copy of urma_device_cap.
 * This module needs user pass `urma_device_cap` in ioctl,
 * but it can't include `urma_types.h` in kmod.
 * So we copy this structure.
 */
union ubagg_order_type_cap {
	struct {
		uint32_t ot : 1;
		uint32_t oi : 1;
		uint32_t ol : 1;
		uint32_t no : 1;
		uint32_t reserved : 28;
	} bs;
	uint32_t value;
};
union ubagg_tp_type_cap {
	struct {
		uint32_t rtp : 1;
		uint32_t ctp : 1;
		uint32_t utp : 1;
		uint32_t reserved : 29;
	} bs;
	uint32_t value;
};

union ubagg_tp_feature {
	struct {
		uint32_t rm_multi_path : 1;
		uint32_t rc_multi_path : 1;
		uint32_t reserved : 30;
	} bs;
	uint32_t value;
};

struct ubagg_sl_info {
	uint32_t SL;
	union ubagg_tp_type_cap tp_type;
};

struct ubagg_device_cap {
	union ubcore_device_feat feature;
	uint32_t max_jfc;
	uint32_t max_jfs;
	uint32_t max_jfr;
	uint32_t max_jetty;
	uint32_t max_jetty_grp;
	uint32_t max_jetty_in_jetty_grp;
	uint32_t max_jfc_depth;
	uint32_t max_jfs_depth;
	uint32_t max_jfr_depth;
	uint32_t max_jfs_inline_size;
	uint32_t max_jfs_sge;
	uint32_t max_jfs_rsge;
	uint32_t max_jfr_sge;
	uint64_t max_msg_size;
	uint32_t max_read_size;
	uint32_t max_write_size;
	uint32_t max_cas_size;
	uint32_t max_swap_size;
	uint32_t max_fetch_and_add_size;
	uint32_t max_fetch_and_sub_size;
	uint32_t max_fetch_and_and_size;
	uint32_t max_fetch_and_or_size;
	uint32_t max_fetch_and_xor_size;
	union ubcore_atomic_feat atomic_feat;
	uint16_t trans_mode; /* one or more from ubcore_transport_mode_t */
	uint16_t sub_trans_mode_cap; /* one or more from ubcore_sub_trans_mode_cap */
	uint16_t congestion_ctrl_alg; /* one or more mode from ubcore_congestion_ctrl_alg_t */
	uint32_t ceq_cnt; /* completion vector count */
	uint32_t max_tp_in_tpg;
	uint32_t max_eid_cnt;
	uint64_t page_size_cap;
	uint32_t max_oor_cnt; /* max OOR window size by packet */
	uint32_t mn;
	uint32_t max_netaddr_cnt;
	union ubagg_order_type_cap rm_order_cap;
	union ubagg_order_type_cap rc_order_cap;
	union ubagg_tp_type_cap rm_tp_cap;
	union ubagg_tp_type_cap rc_tp_cap;
	union ubagg_tp_type_cap um_tp_cap;
	union ubagg_tp_feature tp_feature;
	struct ubagg_sl_info priority_info[UBCORE_MAX_PRIORITY_CNT];
};
/** A structure mimicking `urma_device_attr`.
 * The field `dev_cap` is the same of that in `urma_device_attr`.
 */
struct ubagg_config_dev_attr {
	struct ubagg_device_cap dev_cap;
};

struct ubagg_add_dev {
	struct {
		int slave_dev_num;
		char master_dev_name[UBAGG_MAX_DEV_NAME_LEN];
		char slave_dev_name[UBAGG_MAX_DEV_NUM][UBAGG_MAX_DEV_NAME_LEN];
		union ubcore_eid eid;
		struct ubagg_config_dev_attr dev_attr;
	} in;
};

struct ubagg_rmv_dev {
	struct {
		char master_dev_name[UBAGG_MAX_DEV_NAME_LEN];
	} in;
};

struct ubagg_set_topo_info {
	struct {
		void *topo;
		uint32_t topo_num;
	} in;
};

struct ubagg_create_dev_arg {
	struct {
		union ubcore_eid agg_eid;
		char dev_name[UBAGG_MAX_DEV_NAME_LEN];
	} in;
};

struct ubagg_delete_dev_arg {
	struct {
		union ubcore_eid agg_eid;
	} in;
};

struct ubagg_get_dev_name_arg {
	struct {
		union ubcore_eid eid;
	} in;
	struct {
		char dev_name[UBAGG_MAX_DEV_NAME_LEN];
	} out;
};

enum ubagg_userctl_opcode {
	GET_SLAVE_DEVICE = 1,
	GET_TOPO_INFO = 2,
	GET_JFR_ID = 3,
	GET_JETTY_ID = 4,
	GET_SEG_INFO = 5,
	GET_JETTY_INFO = 6,
};

struct ubagg_slave_device {
	int slave_dev_num;
	char slave_dev_name[UBAGG_MAX_DEV_NUM][UBAGG_MAX_DEV_NAME_LEN];
	struct ubagg_physical_device physical_devices[IODIE_NUM];
};

struct ubagg_topo_info_out {
	struct ubagg_topo_node topo_info[MAX_NODE_NUM];
	uint32_t node_num;
};

void ubagg_delete_topo_map(void);

struct ubagg_primary_port_eid {
	union ubcore_eid primary_eid;
	union ubcore_eid port_eid[MAX_PORT_NUM];
};

struct ubagg_add_dev_by_uvs {
	char master_dev_name[UBAGG_MAX_DEV_NAME_LEN];
	union ubcore_eid agg_eid;
	struct ubagg_primary_port_eid slave_eid[IODIE_NUM];
};

long ubagg_ioctl(struct file *filp, unsigned int cmd, unsigned long arg);

void ubagg_clear_dev_list(void);
#endif // UBAGG_IOCTL_H
