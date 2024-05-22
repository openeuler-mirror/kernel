/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
 * for more details.
 *
 * Description: ubcore vtp header
 * Author: Yan Fangfang
 * Create: 2023-07-14
 * Note:
 * History: 2023-07-14: Create file
 */

#ifndef UBCORE_VTP_H
#define UBCORE_VTP_H

#include <urma/ubcore_types.h>
#include "ubcore_netlink.h"
#include "ubcore_msg.h"
#include "ubcore_netlink.h"
#include "ubcore_tp.h"

#define UBCORE_VTP_TARGET 1
#define UBCORE_VTP_INITIATOR 0
#define UBCORE_VTP_DUPLEX 2

struct ubcore_vtp_param {
	enum ubcore_transport_mode trans_mode;
	uint32_t sub_trans_mode;
	uint32_t rc_share_tp;
	/* vtpn key start */
	union ubcore_eid local_eid;
	union ubcore_eid peer_eid;
	uint32_t local_jetty;
	uint32_t peer_jetty;
	/* vtpn key end */
	uint32_t eid_index;
	/* for alpha */
	struct ubcore_ta ta;
};

struct ubcore_create_vtp_req {
	uint32_t vtpn;
	enum ubcore_transport_mode trans_mode;
	uint32_t sub_trans_mode;
	uint32_t rc_share_tp;
	union ubcore_eid local_eid;
	union ubcore_eid peer_eid;
	uint32_t eid_index;
	uint32_t local_jetty;
	uint32_t peer_jetty;
	char dev_name[UBCORE_MAX_DEV_NAME];
	bool virtualization;
	char tpfdev_name[UBCORE_MAX_DEV_NAME];
	/* for alpha */
	struct ubcore_ta_data ta_data;
	uint32_t udrv_in_len;
	uint32_t ext_len;
	uint8_t udrv_ext[0]; /* struct ubcore_udrv_priv->in_len + struct ubcore_tp_ext->len*/
};

struct ubcore_create_vtp_resp {
	int ret;
	uint32_t vtpn;
};

struct ubcore_destroy_vtp_resp {
	int ret;
};

/* map vtpn to tpg, tp, utp or ctp */
struct ubcore_cmd_vtp_cfg {
	uint16_t fe_idx;
	uint32_t vtpn;
	uint32_t local_jetty;
	union ubcore_eid local_eid;
	union ubcore_eid peer_eid;
	uint32_t peer_jetty;
	union ubcore_vtp_cfg_flag flag;
	enum ubcore_transport_mode trans_mode;
	union {
		uint32_t tpgn;
		uint32_t tpn;
		uint32_t utpn;
		uint32_t ctpn;
		uint32_t value;
	};
};

struct ubcore_migrate_vtp_req {
	struct ubcore_cmd_vtp_cfg vtp_cfg;
	char dev_name[UBCORE_MAX_DEV_NAME];
	enum ubcore_event_type event_type;
};

struct ubcore_vtpn *ubcore_connect_vtp(struct ubcore_device *dev,
	struct ubcore_vtp_param *param);
int ubcore_disconnect_vtp(struct ubcore_vtpn *vtpn, struct ubcore_vtp_param *param);
/* map vtp to tpg, utp .... */
struct ubcore_vtp *ubcore_create_and_map_vtp(struct ubcore_device *dev, struct ubcore_vtp_cfg *cfg);
struct ubcore_vtp *ubcore_check_and_map_vtp(struct ubcore_device *dev, struct ubcore_vtp_cfg *cfg,
	uint32_t role);
struct ubcore_vtp *ubcore_check_and_map_target_vtp(struct ubcore_device *dev,
	struct ubcore_vtp_cfg *cfg, uint32_t role);
int ubcore_unmap_vtp(struct ubcore_vtp *vtp);
int ubcore_check_and_unmap_vtp(struct ubcore_vtp *vtp, uint32_t role);
/* find mapped vtp */
struct ubcore_vtp *ubcore_find_vtp(struct ubcore_device *dev, enum ubcore_transport_mode mode,
	union ubcore_eid *local_eid, union ubcore_eid *peer_eid);
struct ubcore_vtp *ubcore_find_get_vtp(struct ubcore_device *dev,
	enum ubcore_transport_mode mode, union ubcore_eid *local_eid, union ubcore_eid *peer_eid);

void ubcore_set_vtp_param(struct ubcore_device *dev, struct ubcore_jetty *jetty,
	struct ubcore_tjetty_cfg *cfg, struct ubcore_vtp_param *vtp_param);
/* config function migrate state */
int ubcore_config_function_migrate_state(struct ubcore_device *dev, uint16_t fe_idx,
	uint32_t cnt, struct ubcore_ueid_cfg *cfg, enum ubcore_mig_state state);
int ubcore_modify_vtp(struct ubcore_device *dev, struct ubcore_vtp_param *vtp_param,
	struct ubcore_vtp_attr *vattr, union ubcore_vtp_attr_mask *vattr_mask);

uint32_t ubcore_get_all_vtp_cnt(struct ubcore_hash_table *ht);
/* returned list should be freed by caller */
struct ubcore_vtp **ubcore_get_all_vtp(struct ubcore_hash_table *ht,
	uint32_t *dev_vtp_cnt);

void ubcore_vtp_get(void *obj);
void ubcore_vtpn_get(void *obj);
void ubcore_vtp_kref_put(struct ubcore_vtp *vtp);
#endif
