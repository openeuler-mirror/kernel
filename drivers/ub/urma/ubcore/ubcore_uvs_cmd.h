/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2025. All rights reserved.
 *
 * Description: ubcore uvs cmd header file
 * Author: Ji Lei
 * Create: 2023-07-03
 * Note:
 * History: 2023-07-03: Create file
 */

#ifndef UBCORE_UVS_CMD_H
#define UBCORE_UVS_CMD_H

#include <linux/types.h>
#include <linux/uaccess.h>
#include <ub/urma/ubcore_types.h>
#include <ub/urma/ubcore_uapi.h>
#include "ubcore_cmd.h"
#include "ubcore_log.h"
#include "ubcore_priv.h"
#include "ubcore_topo_info.h"

#define UBCORE_UVS_CMD_MAGIC 'V'
#define UBCORE_UVS_CMD _IOWR(UBCORE_UVS_CMD_MAGIC, 1, struct ubcore_cmd_hdr)
#define UBCORE_CMD_CHANNEL_INIT_SIZE 32
#define UBCORE_MAX_VTP_CFG_CNT 32
#define UBCORE_MAX_EID_CONFIG_CNT 32
#define UBCORE_MAX_DSCP_VL_NUM 64
#define UBCORE_CMD_MAX_MUE_NUM 128
#define UBCORE_HOST_EID_BATCH_EID_MAX 32

/* only for uvs control ubcore device ioctl */
enum ubcore_uvs_mue_cmd {
	UBCORE_CMD_CHANNEL_INIT = 1,
	UBCORE_CMD_SET_MUE_CFG,
	UBCORE_CMD_CREATE_TPG, /* initiator */
	UBCORE_CMD_CREATE_VTP, /* initiator */
	UBCORE_CMD_MODIFY_TPG,
	UBCORE_CMD_MODIFY_TPG_MAP_VTP,
	UBCORE_CMD_MODIFY_TPG_TP_CNT,
	UBCORE_CMD_CREATE_TARGET_TPG, /* target */
	UBCORE_CMD_MODIFY_TARGET_TPG,
	UBCORE_CMD_DESTROY_VTP, /* initiator or target */
	UBCORE_CMD_DESTROY_TPG, /* initiator or target */
	UBCORE_CMD_ADD_SIP,
	UBCORE_CMD_DEL_SIP,
	UBCORE_CMD_MAP_VTP,
	UBCORE_CMD_CREATE_UTP,
	UBCORE_CMD_ONLY_CREATE_UTP,
	UBCORE_CMD_DESTROY_UTP,
	UBCORE_CMD_GET_DEV_FEATURE,
	UBCORE_CMD_RESTORE_TP_ERROR_RSP,
	UBCORE_CMD_RESTORE_TARGET_TP_ERROR_REQ,
	UBCORE_CMD_RESTORE_TARGET_TP_ERROR_ACK,
	UBCORE_CMD_RESTORE_TP_SUSPEND,
	UBCORE_CMD_CHANGE_TP_TO_ERROR,
	UBCORE_NOUSE_1,
	UBCORE_NOUSE_2,
	UBCORE_CMD_CONFIG_FUNCTION_MIGRATE_STATE,
	UBCORE_CMD_SET_VPORT_CFG,
	UBCORE_CMD_MODIFY_VTP,
	UBCORE_CMD_GET_DEV_INFO,
	UBCORE_CMD_CHANGE_TPG_TO_ERROR,
	UBCORE_CMD_ALLOC_EID,
	UBCORE_CMD_DEALLOC_EID,
	UBCORE_CMD_QUERY_UE_IDX,
	UBCORE_CMD_CONFIG_DSCP_VL,
	UBCORE_CMD_MAP_TARGET_VTP,
	UBCORE_CMD_LIST_MIGRATE_ENTRY,
	UBCORE_CMD_QUERY_DSCP_VL,
	UBCORE_CMD_DFX_QUERY_STATS,
	UBCORE_CMD_DFX_QUERY_RES,
	UBCORE_CMD_DISCOVER_DMAC,
	UBCORE_CMD_CLEAR_VICE_TPG,
	UBCORE_CMD_USER_CTL,
	UBCORE_CMD_MUE_LAST
};

enum ubcore_uvs_global_cmd {
	UBCORE_CMD_REGISTER_UVS = 1,
	UBCORE_CMD_UNREGISTER_UVS,
	UBCORE_CMD_GET_VTP_TABLE_CNT,
	UBCORE_CMD_RESTORE_TABLE,
	UBCORE_CMD_GET_TPG_TABLE_CNT,
	UBCORE_CMD_RESTORE_TPG_TABLE,
	UBCORE_CMD_GET_UE_TABLE_CNT,
	UBCORE_CMD_RESTORE_UE_TABLE,
	UBCORE_CMD_GLOBAL_SET_UPI,
	UBCORE_CMD_GLOBAL_SHOW_UPI,
	UBCORE_CMD_LIST_MUE,
	UBCORE_CMD_SET_TOPO,
	UBCORE_CMD_GET_TOPO_RESERVE,
	UBCORE_CMD_GET_PATH_SET,
	UBCORE_CMD_INSERT_MAIN_UE_EID,
	UBCORE_CMD_DELETE_MAIN_UE_EID,
	UBCORE_CMD_LOOKUP_MAIN_UE_EID,
	UBCORE_CMD_FLUSH_MAIN_UE_EID,
	UBCORE_CMD_INSERT_MAIN_UE_EID_BATCH,
	UBCORE_CMD_INSERT_HOST_EID_BATCH,
	UBCORE_CMD_GLOBAL_LAST
};

struct ubcore_cmd_set_topo {
	struct {
		void *topo_info;
		uint32_t topo_num;
	} in;
};

struct ubcore_cmd_get_path_set {
	struct {
		union ubcore_eid src_bonding_eid;
		union ubcore_eid dst_bonding_eid;
		enum ubcore_tp_type tp_type;
		bool iodie_level;
	} in;
	struct {
		struct ubcore_path_set path_set;
	} out;
};

struct ubcore_cmd_main_ue_eid_entry {
	struct {
		union ubcore_eid eid;
		union ubcore_eid main_ue_eid;
	} in;
};

struct ubcore_cmd_main_ue_eid_delete {
	struct {
		union ubcore_eid eid;
	} in;
};

struct ubcore_cmd_main_ue_eid_lookup {
	struct {
		union ubcore_eid eid;
	} in;
	struct {
		union ubcore_eid main_ue_eid;
	} out;
};

struct ubcore_cmd_main_ue_eid_flush {
	struct {
		int status;
	} out;
};

struct ubcore_cmd_main_ue_eid_batch {
	struct {
		union ubcore_eid main_ue_eid;
		uint32_t eid_num;
		union ubcore_eid eids[UBCORE_MAIN_UE_EID_BATCH_EID_MAX];
	} in;
};

struct ubcore_cmd_host_eid_batch {
	struct {
		union ubcore_eid host_eid;
		uint32_t eid_num;
		union ubcore_eid eids[UBCORE_HOST_EID_BATCH_EID_MAX];
	} in;
};

int ubcore_uvs_mue_cmd_parse(struct ubcore_mue_file *file,
			     struct ubcore_cmd_hdr *hdr);

int ubcore_uvs_global_cmd_parse(struct ubcore_global_file *file,
				struct ubcore_cmd_hdr *hdr);

#endif
