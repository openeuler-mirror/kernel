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
#define MAX_NODE_NUM (1024)
#define ENTITY_AGG_DEV_NUM (3) // bonding device number per entity
#define PORT_NUM (9)
#define CHIP_NUM (2)
#define IODIE_NUM_PER_CHIP (1)
#define DEV_NUM (256)
#define IODIE_NUM (IODIE_NUM_PER_CHIP * CHIP_NUM)

struct ubcore_topo_ue {
	uint32_t chip_id;
	uint32_t die_id;
	uint32_t entity_id;
	char primary_eid[EID_LEN];
	char port_eid[PORT_NUM][EID_LEN];
	char cna[PORT_NUM][EID_LEN];
};

struct ubcore_topo_agg_dev {
	char agg_eid[EID_LEN];
	struct ubcore_topo_ue ues[IODIE_NUM];
};

struct ubcore_topo_link {
	uint32_t peer_node; // node id
	uint32_t peer_iodie; // iodie idx
	uint32_t peer_port; // port idx, UINT32_MAX indicates no connection
};

struct ubcore_topo_node {
	uint32_t type; // 0:1D-fullmesh, 1: Clos topology with parallel planes
	uint32_t super_node_id;
	uint32_t node_id;
	uint32_t is_current;
	/*
	 * links[local_idx][remote_idx] represents connectivity
	 * between this node's port local_idx and node i's port remote_idx.
	 */
	bool links[IODIE_NUM * PORT_NUM][IODIE_NUM * PORT_NUM];
	struct ubcore_topo_agg_dev agg_devs[DEV_NUM];
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
bool is_eid_valid(const char *eid);
int ubcore_update_topo_map(struct ubcore_topo_map *new_topo_map,
			   struct ubcore_topo_map *old_topo_map);
void ubcore_show_topo_map(struct ubcore_topo_map *topo_map);

#endif // UBCORE_TOPO_INFO_H
