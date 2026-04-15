/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2025. All rights reserved.
 *
 * Description: ubcore vtp header
 * Author: Yan Fangfang
 * Create: 2023-07-14
 * Note:
 * History: 2023-07-14: Create file
 */

#ifndef UBCORE_VTP_H
#define UBCORE_VTP_H

#include <ub/urma/ubcore_types.h>
#include "ubcore_netlink.h"
#include "ubcore_msg.h"
#include "ubcore_netlink.h"
#include "ubcore_tp.h"

#define UBCORE_VTP_TARGET 1
#define UBCORE_VTP_INITIATOR 0
#define UBCORE_VTP_DUPLEX 2
#define UBCORE_VTP_NO_LOCATION 3
#define UBCORE_MAX_UDRV_EXT_LEN 128

struct ubcore_vtp_param {
	enum ubcore_transport_mode trans_mode;
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
	union ubcore_eid local_eid;
	union ubcore_eid peer_eid;
	uint32_t eid_index;
	uint32_t local_jetty;
	uint32_t peer_jetty;
	char dev_name[UBCORE_MAX_DEV_NAME];
	bool virtualization;
	char muedev_name[UBCORE_MAX_DEV_NAME];

	/* for alpha */
	struct ubcore_ta_data ta_data;
	uint32_t udrv_in_len;
	uint32_t ext_len; // deprecated keep zero
	/* struct ubcore_udrv_priv->in_len + struct ubcore_tp_ext->len */
	uint8_t udrv_ext[UBCORE_MAX_UDRV_EXT_LEN];

	/* For compatibility, do not change msg structure */
};

struct ubcore_create_vtp_resp {
	int ret;
	uint32_t vtpn;
};

struct ubcore_destroy_vtp_resp {
	int ret;
};

struct ubcore_vtp_status_notify {
	char mue_name[UBCORE_MAX_DEV_NAME];
	uint32_t vtpn;
	enum ubcore_transport_mode trans_mode;
	enum ubcore_vtp_state status;
	union ubcore_eid local_eid;
	union ubcore_eid peer_eid;
	uint32_t local_jetty_id;  // only for RC
	uint32_t peer_jetty_id;   // only for RC
};

/* map vtpn to tpg, tp, utp or ctp */
struct ubcore_cmd_vtp_cfg {
	uint16_t ue_idx;
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

struct ubcore_wait_vtpn_resp_work {
	struct delayed_work delay_work;
	struct ubcore_device *dev;
	struct ubcore_msg_session *s;
	struct ubcore_vtp_param param;
	int timeout;
	struct ubcore_vtpn *vtpn;
	uint32_t msg_id;
};

struct ubcore_vtpn_cb_para {
	enum ubcore_tjetty_type type;
	struct ubcore_tjetty *tjetty;
	struct ubcore_jetty *jetty;
	struct ubcore_import_cb *import_cb;
	struct ubcore_bind_cb *bind_cb;
	struct ubcore_unimport_cb *unimport_cb;
	struct ubcore_unbind_cb *unbind_cb;
};

struct ubcore_vtpn_wait_cb_node {
	struct list_head node;
	struct ubcore_vtpn_cb_para para;
	struct ubcore_wait_vtpn_resp_work *wait_work;
};

struct ubcore_vtpn *ubcore_find_get_vtpn_ctrlplane(struct ubcore_device *dev,
	struct ubcore_active_tp_cfg *active_tp_cfg);
void ubcore_vtpn_kref_put(struct ubcore_vtpn *vtpn);
void ubcore_add_async_wait_list(struct ubcore_vtpn *vtpn,
	struct ubcore_vtpn_cb_para *para, struct ubcore_wait_vtpn_resp_work *wait_work);
void ubcore_del_async_wait_list(struct ubcore_vtpn *vtpn);
struct ubcore_vtpn *ubcore_connect_vtp(struct ubcore_device *dev,
	struct ubcore_vtp_param *param);
struct ubcore_vtpn *ubcore_connect_vtp_ctrlplane(struct ubcore_device *dev,
	struct ubcore_vtp_param *param, struct ubcore_active_tp_cfg *active_tp_cfg,
	struct ubcore_udata *udata);
struct ubcore_vtpn *
	ubcore_connect_rc_vtp_ctrlplane(struct ubcore_device *dev,
	struct ubcore_vtp_param *param,
	struct ubcore_active_tp_cfg *active_tp_cfg,
	struct ubcore_udata *udata);
struct ubcore_vtpn *ubcore_connect_vtp_async(struct ubcore_device *dev,
	struct ubcore_vtp_param *param, int timeout, struct ubcore_vtpn_cb_para *para);
int ubcore_disconnect_vtp(struct ubcore_vtpn *vtpn);
int ubcore_disconnect_vtp_async(struct ubcore_vtpn *vtpn, int timeout,
	struct ubcore_vtpn_cb_para *para);
int ubcore_queue_destroy_vtp_task(struct ubcore_device *dev, struct ubcore_vtpn *vtpn,
	uint32_t retry_times);
void ubcore_flush_dev_vtp_work(struct ubcore_device *dev);
void ubcore_wait_connect_vtp_resp_intime(struct ubcore_msg_session *s,
	struct ubcore_device *dev, struct ubcore_resp *resp);
void ubcore_wait_disconnect_vtp_resp_intime(struct ubcore_msg_session *s,
	struct ubcore_device *dev, struct ubcore_resp *resp);
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

int ubcore_modify_vtp(struct ubcore_device *dev, struct ubcore_vtp_param *vtp_param,
	struct ubcore_vtp_attr *vattr, union ubcore_vtp_attr_mask *vattr_mask);

uint32_t ubcore_get_all_vtp_cnt(struct ubcore_hash_table *ht, struct ubcore_device *dev,
	uint32_t target_uvs_id);
/* returned list should be freed by caller */
struct ubcore_vtp **ubcore_get_all_vtp(struct ubcore_hash_table *ht, struct ubcore_device *dev,
	uint32_t target_uvs_id, uint32_t *dev_vtp_cnt);

int ubcore_process_vtp_status_nofity(struct ubcore_device *dev,
	struct ubcore_vtp_status_notify *msg);

void ubcore_vtp_get(void *obj);
void ubcore_vtpn_get(void *obj);
void ubcore_vtp_kref_put(struct ubcore_vtp *vtp);
#endif
