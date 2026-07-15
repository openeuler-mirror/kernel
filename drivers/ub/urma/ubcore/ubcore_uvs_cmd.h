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

#define UBCORE_UVS_CMD_MAGIC 'V'
#define UBCORE_UVS_CMD _IOWR(UBCORE_UVS_CMD_MAGIC, 1, struct ubcore_cmd_hdr)
#define UBCORE_CMD_CHANNEL_INIT_SIZE 32
#define UBCORE_MAX_VTP_CFG_CNT 32
#define UBCORE_MAX_EID_CONFIG_CNT 32
#define UBCORE_MAX_DSCP_VL_NUM 64
#define UBCORE_CMD_MAX_MUE_NUM 128
#define UBCORE_HOST_EID_BATCH_EID_MAX 32

enum ubcore_uvs_global_cmd {
	UBCORE_CMD_SET_TOPO = 1,
	UBCORE_CMD_GET_ROUTE_LIST = 2,
	UBCORE_CMD_GET_TOPO = 3,
	UBCORE_CMD_GET_PATH_SET = 4,
	UBCORE_CMD_INSERT_MAIN_UE_EID = 5,
	UBCORE_CMD_DELETE_MAIN_UE_EID = 6,
	UBCORE_CMD_LOOKUP_MAIN_UE_EID = 7,
	UBCORE_CMD_FLUSH_MAIN_UE_EID = 8,
	UBCORE_CMD_INSERT_MAIN_UE_EID_BATCH = 9,
	UBCORE_CMD_INSERT_HOST_EID_BATCH = 10,
	UBCORE_CMD_GLOBAL_LAST
};

struct ubcore_cmd_set_topo {
	struct {
		void *topo_info;
		uint32_t topo_num;
	} in;
};

struct ubcore_cmd_get_topo {
	struct {
		void *topo_map;
	} out;
};

struct ubcore_cmd_get_route_list {
	struct ubcore_route in;
	struct ubcore_route_list out;
};

struct ubcore_cmd_get_path_set {
	struct {
		union ubcore_eid src_bonding_eid;
		union ubcore_eid dst_bonding_eid;
		enum ubcore_tp_type tp_type;
		bool iodie_level;
	} in;
	struct ubcore_path_set out;
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
