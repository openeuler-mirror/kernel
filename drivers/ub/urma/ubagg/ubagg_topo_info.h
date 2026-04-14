/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 *
 * Description: ubagg topo info head file
 * Author: Ma Chuan
 * Create: 2025-06-07
 * Note:
 * History: 2025-06-07 Create file
 */
#ifndef ubagg_topo_info_H
#define ubagg_topo_info_H

#include <linux/types.h>
#include <ub/urma/ubcore_types.h>

#define EID_LEN (16)
#define MAX_NODE_NUM (64)
#define MAX_PORT_NUM (9)
#define IODIE_NUM_PER_CHIP (1)
#define PORT_NUM (9)
#define CHIP_NUM (2)
#define DEV_NUM (256)
#define IODIE_NUM (IODIE_NUM_PER_CHIP * CHIP_NUM)
#define UBAGG_DEV_MAX_NUM (20)

struct ubagg_topo_ue {
	uint32_t chip_id;
	uint32_t die_id;
	uint32_t entity_id;
	char primary_eid[EID_LEN];
	char port_eid[PORT_NUM][EID_LEN];
};

struct ubagg_topo_agg_dev {
	char agg_eid[EID_LEN];
	struct ubagg_topo_ue ues[IODIE_NUM];
};

struct ubagg_topo_link {
	uint32_t peer_node; // node id
	uint32_t peer_iodie; // iodie idx
	uint32_t peer_port; // port idx, UINT32_MAX indicates no connection
};

struct ubagg_topo_node {
	uint32_t type;
	uint32_t super_node_id;
	uint32_t node_id;
	uint32_t is_current;
	struct ubagg_topo_link links[IODIE_NUM][PORT_NUM];
	struct ubagg_topo_agg_dev agg_devs[DEV_NUM];
};

struct ubagg_topo_map {
	struct ubagg_topo_node topo_infos[MAX_NODE_NUM];
	uint32_t node_num;
};

enum ubagg_topo_type {
	UBAGG_TOPO_TYPE_FULLMESH,
	UBAGG_TOPO_TYPE_CLOS
};

struct ubagg_topo_map *
create_global_ubagg_topo_map(struct ubagg_topo_node *topo_infos,
			     uint32_t node_num);

void delete_global_ubagg_topo_map(void);

struct ubagg_topo_map *get_global_ubagg_map(void);
int find_linked_port(
	union ubcore_eid *dst_eid,
	bool connected[UBAGG_DEV_MAX_NUM][UBAGG_DEV_MAX_NUM]);

struct ubagg_topo_map *
create_ubagg_topo_map_from_user(struct ubagg_topo_node *topo_infos,
				uint32_t node_num);

void delete_ubagg_topo_map(struct ubagg_topo_map *topo_map);

struct ubagg_topo_node *find_cur_topo_node(struct ubagg_topo_map *topo_map);
struct ubagg_topo_agg_dev *
find_cur_topo_agg_dev(struct ubagg_topo_map *topo_map,
		      union ubcore_eid *bonding_eid);

#endif // ubcore_topo_node_H
