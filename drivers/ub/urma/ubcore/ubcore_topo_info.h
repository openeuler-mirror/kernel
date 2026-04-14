/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 *
 * Description: ubcore topo info head file
 * Author: Liu Jiajun
 * Create: 2025-07-03
 * Note:
 * History: 2025-07-03 Create file
 */

#ifndef UBCORE_TOPO_INFO_H
#define UBCORE_TOPO_INFO_H

#include <ub/urma/ubcore_types.h>

#define EID_LEN (16)
#define MAX_NODE_NUM (64)
#define ENTITY_AGG_DEV_NUM (3) // bonding device number per entity
#define PORT_NUM (9)
#define CHIP_NUM (2)
#define IODIE_NUM_PER_CHIP (1)
#define DEV_NUM (256)
#define IODIE_NUM (IODIE_NUM_PER_CHIP * CHIP_NUM)
#define MAX_PATH_NUM (16)

struct ubcore_topo_ue {
	uint32_t chip_id;
	uint32_t die_id;
	uint32_t entity_id;
	char primary_eid[EID_LEN];
	char port_eid[PORT_NUM][EID_LEN];
};

struct ubcore_topo_agg_dev {
	char agg_eid[EID_LEN];
	struct ubcore_topo_ue ues[IODIE_NUM];
};

struct ubcore_topo_physical_dev {
	char dev_name[UBCORE_MAX_DEV_NAME];
	uint32_t chip_id;
	uint32_t primary_eid_idx;
	uint32_t port_eid_idx[PORT_NUM];
};

struct ubcore_topo_bonding_dev {
	char dev_name[UBCORE_MAX_DEV_NAME];
	uint32_t bonding_eid_idx;
	struct ubcore_topo_physical_dev physical_devs[IODIE_NUM];
};

struct ubcore_topo_link {
	uint32_t peer_node; // node id
	uint32_t peer_iodie; // iodie idx
	uint32_t peer_port; // port idx, UINT32_MAX indicates no connection
};

struct ubcore_topo_node {
	uint32_t type;  // 0:1D-fullmesh, 1: Clos topology with parallel planes
	uint32_t super_node_id;
	uint32_t node_id;
	uint32_t is_current;
	struct ubcore_topo_link links[IODIE_NUM][PORT_NUM]; /*Links[i] represents
		the destination information connected to the current node's port[i].
		It is not filled in Clos topology and relies on preset information.*/
	struct ubcore_topo_agg_dev agg_devs[DEV_NUM];
};


enum ubcore_topo_type_t {
	UBCORE_TOPO_TYPE_FULLMESH_1D,
	UBCORE_TOPO_TYPE_CLOS
};

struct ubcore_node_id {
	uint32_t super_node_id;
	uint32_t node_id;
};

union ubcore_port_id {
	struct {
		uint8_t chip_id;
		uint8_t die_id;
		uint8_t port_idx;
		uint8_t reserved;
	};
	uint64_t value;
};

struct ubcore_path {
	union ubcore_port_id src_port;
	union ubcore_port_id dst_port;
	union ubcore_eid src_eid;
	union ubcore_eid dst_eid;
};

struct ubcore_path_set {
	enum ubcore_topo_type_t topo_type;
	struct ubcore_node_id src_node;
	struct ubcore_node_id dst_node;
	uint32_t chip_count;
	uint32_t die_count;
	uint32_t path_count;
	struct ubcore_path paths[MAX_PATH_NUM];
};

struct ubcore_topo_map {
	struct ubcore_topo_node topo_infos[MAX_NODE_NUM];
	uint32_t node_num;
};

struct ubcore_topo_map *
ubcore_create_global_topo_map(struct ubcore_topo_node *topo_infos,
			      uint32_t node_num);
void ubcore_delete_global_topo_map(void);
struct ubcore_topo_map *ubcore_get_global_topo_map(void);
struct ubcore_topo_map *
ubcore_create_topo_map_from_user(struct ubcore_topo_node *user_topo_infos,
				 uint32_t node_num);
void ubcore_delete_topo_map(struct ubcore_topo_map *topo_map);
bool is_agg_dev_valid(struct ubcore_topo_agg_dev *agg_dev);
bool is_eid_valid(const char *eid);
struct ubcore_topo_node *
ubcore_get_cur_topo_info(struct ubcore_topo_map *topo_map);
int ubcore_update_topo_map(struct ubcore_topo_map *new_topo_map,
			   struct ubcore_topo_map *old_topo_map);
void ubcore_show_topo_map(struct ubcore_topo_map *topo_map);
int ubcore_get_primary_eid(union ubcore_eid *eid, union ubcore_eid *primary_eid,
	uint32_t *entity_id, uint32_t *chip_id, uint32_t *nd_id);
int ubcore_get_main_primary_eid(union ubcore_eid *eid,
	union ubcore_eid *main_primary_eid);

int ubcore_get_primary_eid_by_agg_eid(union ubcore_eid *agg_eid,
	union ubcore_eid *primary_eid);

int ubcore_get_topo_bonding_dev_by_agg_eid(union ubcore_eid *agg_eid,
	struct ubcore_topo_bonding_dev *out);

int ubcore_get_path_set(union ubcore_eid *src_bonding_eid,
	union ubcore_eid *dst_bonding_eid, enum ubcore_tp_type tp_type,
	bool multi_path, struct ubcore_path_set *path_set);

#endif // UBCORE_TOPO_INFO_H
