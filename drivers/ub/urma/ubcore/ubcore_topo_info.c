// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 *
 * Description: ubcore topo info file
 * Author: Liu Jiajun
 * Create: 2025-07-03
 * Note:
 * History: 2025-07-03 Create file
 */

#include <linux/uaccess.h>
#include <linux/vmalloc.h>
#include <ub/urma/ubcore_types.h>
#include <ub/urma/ubcore_uapi.h>
#include "ubcore_log.h"
#include "ubcore_topo_info.h"
#include "ubcore_priv.h"

#define INVALID_PORT (255)
static struct ubcore_topo_map *g_ubcore_topo_map;

struct ubcore_topo_map *
ubcore_create_global_topo_map(struct ubcore_topo_node *topo_infos,
				  uint32_t node_num)
{
	g_ubcore_topo_map =
		ubcore_create_topo_map_from_user(topo_infos, node_num);
	return g_ubcore_topo_map;
}

void ubcore_delete_global_topo_map(void)
{
	if (!g_ubcore_topo_map)
		return;
	ubcore_delete_topo_map(g_ubcore_topo_map);
	g_ubcore_topo_map = NULL;
}

struct ubcore_topo_map *ubcore_get_global_topo_map(void)
{
	return g_ubcore_topo_map;
}

struct ubcore_topo_map *
ubcore_create_topo_map_from_user(struct ubcore_topo_node *user_topo_infos,
				 uint32_t node_num)
{
	struct ubcore_topo_map *topo_map = NULL;
	int ret = 0;

	if (!user_topo_infos || node_num <= 0 ||
		node_num > MAX_NODE_NUM) {
		ubcore_log_err("Invalid param\n");
		return NULL;
	}
	topo_map = vzalloc(sizeof(struct ubcore_topo_map));
	if (!topo_map)
		return NULL;
	ret = copy_from_user(topo_map->topo_infos,
				 (void __user *)user_topo_infos,
				 sizeof(struct ubcore_topo_node) * node_num);
	if (ret != 0) {
		ubcore_log_err("Failed to copy topo infos\n");
		vfree(topo_map);
		return NULL;
	}
	topo_map->node_num = node_num;
	return topo_map;
}

void ubcore_delete_topo_map(struct ubcore_topo_map *topo_map)
{
	if (!topo_map)
		return;
	vfree(topo_map);
}

bool is_agg_dev_valid(struct ubcore_topo_agg_dev *agg_dev)
{
	struct ubcore_topo_agg_dev empty_dev = {0};

	return (memcmp(agg_dev, &empty_dev,
		sizeof(struct ubcore_topo_agg_dev)) == 0) ? false : true;
}

bool is_eid_valid(const char *eid)
{
	int i;

	for (i = 0; i < EID_LEN; i++) {
		if (eid[i] != 0)
			return true;
	}
	return false;
}

static int find_cur_node_index(struct ubcore_topo_map *topo_map,
				   uint32_t *node_index)
{
	int i;

	for (i = 0; i < topo_map->node_num; i++) {
		if (topo_map->topo_infos[i].is_current) {
			*node_index = i;
			break;
		}
	}
	if (i == topo_map->node_num) {
		ubcore_log_err("can't find cur node\n");
		return -EINVAL;
	}
	return 0;
}

static bool is_eid_match(const char *eid1, const char *eid2)
{
	return memcmp(eid1, eid2, EID_LEN) == 0;
}

struct ubcore_topo_node *
ubcore_get_cur_topo_info(struct ubcore_topo_map *topo_map)
{
	uint32_t cur_node_index = 0;

	if (find_cur_node_index(topo_map, &cur_node_index) != 0) {
		ubcore_log_err("find cur node index failed\n");
		return NULL;
	}
	return &(topo_map->topo_infos[cur_node_index]);
}

static int update_dev_info(struct ubcore_topo_node *new_topo_info,
				struct ubcore_topo_node *old_topo_info)
{
	int dev_id;
	bool new_valid, old_valid;

	for (dev_id = 0; dev_id < DEV_NUM; dev_id++) {
		new_valid = is_agg_dev_valid(&new_topo_info->agg_devs[dev_id]);
		old_valid = is_agg_dev_valid(&old_topo_info->agg_devs[dev_id]);
		if (old_valid && new_valid) {
			/* if both dev are valid, return error */
			if (memcmp(&old_topo_info->agg_devs[dev_id],
				&new_topo_info->agg_devs[dev_id],
				sizeof(struct ubcore_topo_agg_dev)) != 0) {
				ubcore_log_err("dev %d is not the same\n", dev_id);
				return -1;
			}
		}
		if (!old_valid && new_valid) {
			/* if old dev is not valid, update it */
			(void)memcpy(&old_topo_info->agg_devs[dev_id],
				&new_topo_info->agg_devs[dev_id],
				sizeof(struct ubcore_topo_agg_dev));
		}
	}

	return 0;
}

static int update_link_info(struct ubcore_topo_node *new_topo_info,
				struct ubcore_topo_node *old_topo_info)
{
	int local_idx, remote_idx;

	for (local_idx = 0; local_idx < IODIE_NUM * PORT_NUM; local_idx++) {
		for (remote_idx = 0; remote_idx < IODIE_NUM * PORT_NUM; remote_idx++) {
			// if new link is not connected, skip it
			if (!new_topo_info->links[local_idx][remote_idx])
				continue;
			// if old link is not connected, update it
			if (!old_topo_info->links[local_idx][remote_idx])
				old_topo_info->links[local_idx][remote_idx] = true;
		}
	}
	return 0;
}

int ubcore_update_topo_map(struct ubcore_topo_map *new_topo_map,
			   struct ubcore_topo_map *old_topo_map)
{
	struct ubcore_topo_node *new_node, *old_node;
	uint32_t i, j;

	if (!new_topo_map || !old_topo_map) {
		ubcore_log_err("Invalid topo map\n");
		return -EINVAL;
	}

	for (i = 0; i < new_topo_map->node_num; i++) {
		new_node = &new_topo_map->topo_infos[i];
		for (j = 0; j < old_topo_map->node_num; j++) {
			old_node = &old_topo_map->topo_infos[j];
			if (new_node->node_id == old_node->node_id) {
				if (update_link_info(new_node, old_node)) {
					ubcore_log_err("update link info failed\n");
					return -EINVAL;
				}
				if (update_dev_info(new_node, old_node)) {
					ubcore_log_err("update dev info failed\n");
					return -EINVAL;
				}
			}
		}
	}

	return 0;
}

void ubcore_show_topo_map(struct ubcore_topo_map *topo_map)
{
	int node_idx, dev_idx, die_idx, port_idx, local_idx, remote_idx;
	struct ubcore_topo_node *node;

	if (!topo_map) {
		ubcore_log_err("topo_map is NULL\n");
		return;
	}

	ubcore_log_info(
		"========================== topo map start =============================\n");
	for (node_idx = 0; node_idx < topo_map->node_num; node_idx++) {
		node = &topo_map->topo_infos[node_idx];

		ubcore_log_info(
			"===================== node %u start(is_current:%d) =======================\n",
			node->node_id, node->is_current);

		/* print link table for this node */
		for (local_idx = 0; local_idx < IODIE_NUM * PORT_NUM; local_idx++) {
			for (remote_idx = 0; remote_idx < IODIE_NUM * PORT_NUM; remote_idx++) {
				if (!node->links[local_idx][remote_idx])
					continue;
				ubcore_log_info(
					"link: local iodie%d port%d <-> remote iodie%d port%d connected\n",
					local_idx / PORT_NUM, local_idx % PORT_NUM,
					remote_idx / PORT_NUM, remote_idx % PORT_NUM);
			}
		}

		/* print device list (only devices with valid agg_eid) */
		for (dev_idx = 0; dev_idx < DEV_NUM; dev_idx++) {
			if (!is_eid_valid(node->agg_devs[dev_idx].agg_eid))
				continue;

			ubcore_log_info("---- dev %d agg_eid: " EID_FMT "\n", dev_idx,
				EID_RAW_ARGS(node->agg_devs[dev_idx].agg_eid));

			for (die_idx = 0; die_idx < IODIE_NUM; die_idx++) {
				ubcore_log_info("------ chip_id[%d]: %u\n", die_idx,
					node->agg_devs[dev_idx].ues[die_idx].chip_id);

				ubcore_log_info("------ entity_id[%d]: %u\n", die_idx,
					node->agg_devs[dev_idx].ues[die_idx].entity_id);

				ubcore_log_info("------ primary_eid[%d]: " EID_FMT "\n", die_idx,
					EID_RAW_ARGS(
						node->agg_devs[dev_idx].ues[die_idx].primary_eid));

				for (port_idx = 0; port_idx < PORT_NUM; port_idx++) {
					ubcore_log_info("-------- port_eid[%d][%d]: " EID_FMT "\n",
					die_idx, port_idx,
					EID_RAW_ARGS(
					node->agg_devs[dev_idx].ues[die_idx].port_eid[port_idx]
					));
				}
			}
		}

		ubcore_log_info(
			"===================== node %d end =======================\n",
			node_idx);
	}
	ubcore_log_info(
		"========================== topo map end =============================\n");
}

static int find_primary_eid_in_ues(struct ubcore_topo_agg_dev *agg_dev,
								const char *eid_raw,
								union ubcore_eid *primary_eid,
								uint32_t *entity_id,
								uint32_t *chip_id)
{
	int iodie_id, port_id;

	for (iodie_id = 0; iodie_id < IODIE_NUM; iodie_id++) {
		if (is_eid_match(agg_dev->ues[iodie_id].primary_eid,
			eid_raw)) {
			(void)memcpy(
				primary_eid,
				agg_dev->ues[iodie_id].primary_eid,
				EID_LEN);
			*entity_id = agg_dev->ues[iodie_id].entity_id;
			*chip_id = agg_dev->ues[iodie_id].chip_id;
			ubcore_log_info(
				"find primary eid: "EID_FMT", entity_id: %u, chip_id: %u.\n",
				EID_ARGS(*primary_eid), *entity_id, *chip_id);
			return 0;
		}

		for (port_id = 0; port_id < PORT_NUM; port_id++) {
			if (is_eid_match(
				agg_dev->ues[iodie_id].port_eid[port_id],
				eid_raw)) {
				(void)memcpy(
					primary_eid,
					agg_dev->ues[iodie_id].primary_eid,
					EID_LEN);
				*entity_id = agg_dev->ues[iodie_id].entity_id;
				*chip_id = agg_dev->ues[iodie_id].chip_id;
				ubcore_log_info(
					"find primary eid by port eid, port_eid: "EID_FMT
					", ", EID_ARGS(*(union ubcore_eid *)eid_raw));
				ubcore_log_info(
					"primary eid: "EID_FMT", entity_id: %u, chip_id: %u.\n",
					EID_ARGS(*primary_eid), *entity_id, *chip_id);
				return 0;
			}
		}
	}

	return -EINVAL;
}

int ubcore_get_primary_eid(union ubcore_eid *eid, union ubcore_eid *primary_eid,
	uint32_t *entity_id, uint32_t *chip_id, uint32_t *nd_id)
{
	int node_id, dev_id;
	struct ubcore_topo_node *cur_node_info;

	if (!g_ubcore_topo_map) {
		ubcore_log_info("ubcore topo map doesn't exist, eid is primary_eid.\n");
		(void)memcpy(primary_eid, eid, EID_LEN);
		return 0;
	}

	for (node_id = 0; node_id < g_ubcore_topo_map->node_num; node_id++) {
		cur_node_info = g_ubcore_topo_map->topo_infos + node_id;
		for (dev_id = 0; dev_id < DEV_NUM; dev_id++) {
			if (is_eid_match(cur_node_info->agg_devs[dev_id].agg_eid,
							(char *)eid->raw)) {
				ubcore_log_err("input eid is bonding eid!\n");
				return -EINVAL;
			}

			if (find_primary_eid_in_ues(
				&cur_node_info->agg_devs[dev_id],
				(char *)eid->raw,
				primary_eid, entity_id, chip_id) == 0) {
				*nd_id = (uint32_t)node_id;
				return 0;
			}
		}
	}

	ubcore_log_err("can't find primary eid\n");
	return -EINVAL;
}

static struct ubcore_topo_node *
	ubcore_get_topo_info_by_agg_eid(union ubcore_eid *agg_eid, int *device_id)
{
	struct ubcore_topo_map *topo_map;
	int node_id, dev_id;

	topo_map = g_ubcore_topo_map;
	if (!topo_map) {
		ubcore_log_err(
			"Failed to get topo info, ubcore topo map doesn't exist.\n");
		return NULL;
	}

	for (node_id = 0; node_id < topo_map->node_num; node_id++) {
		for (dev_id = 0; dev_id < DEV_NUM; dev_id++) {
			if (memcmp(agg_eid, topo_map->topo_infos[node_id].agg_devs[dev_id].agg_eid,
					sizeof(*agg_eid)) == 0) {
				*device_id = dev_id;
				return &topo_map->topo_infos[node_id];
			}
		}
	}

	ubcore_log_err(
		"Failed to get topo info, agg_eid: "EID_FMT".\n",
		EID_ARGS(*agg_eid));
	return NULL;
}

static struct ubcore_topo_agg_dev *
get_topo_agg_dev(union ubcore_eid *agg_eid)
{
	int node_id, dev_id;
	struct ubcore_topo_map *topo_map = g_ubcore_topo_map;

	if (!topo_map) {
		ubcore_log_err(
			"Failed to get agg_dev, ubcore topo map doesn't exist.\n");
		return NULL;
	}
	for (node_id = 0; node_id < topo_map->node_num; node_id++) {
		for (dev_id = 0; dev_id < DEV_NUM; dev_id++) {
			if (memcmp(topo_map->topo_infos[node_id].agg_devs[dev_id].agg_eid,
				agg_eid, sizeof(union ubcore_eid)) == 0) {
				return &topo_map->topo_infos[node_id].agg_devs[dev_id];
			}
		}
	}
	ubcore_log_err("Failed to get ubcore agg_dev, agg_eid: " EID_FMT".\n", EID_ARGS(*agg_eid));
	return NULL;
}

static void append_route_list(struct ubcore_route_list *route_list,
	char *src_eid_buf, char *dst_eid_buf, uint32_t chip_id)
{
	int num = route_list->route_num;
	(void)memcpy(&route_list->buf[num].src, src_eid_buf, sizeof(union ubcore_eid));
	(void)memcpy(&route_list->buf[num].dst, dst_eid_buf, sizeof(union ubcore_eid));
	route_list->buf[num].chip_id = chip_id;
	route_list->buf[num].flag.bs.rtp = 1;
	route_list->buf[num].flag.bs.ctp = 1;
	route_list->buf[num].flag.bs.utp = 1;
	route_list->buf[num].hops = 0;
	route_list->route_num++;
}

static void append_route_list_ctp(struct ubcore_route_list *route_list,
	char *src_eid_buf, char *dst_eid_buf, uint32_t chip_id)
{
	int num = route_list->route_num;
	(void)memcpy(&route_list->buf[num].src, src_eid_buf, sizeof(union ubcore_eid));
	(void)memcpy(&route_list->buf[num].dst, dst_eid_buf, sizeof(union ubcore_eid));
	route_list->buf[num].chip_id = chip_id;
	route_list->buf[num].flag.bs.ctp = 1;
	route_list->buf[num].hops = 0;
	route_list->route_num++;
}

static int get_route_port_eid_same_node(
	struct ubcore_topo_agg_dev *src_agg_dev, struct ubcore_topo_agg_dev *dst_agg_dev,
	struct ubcore_route_list *route_list)
{
	int iodie_id, port_id, num;

	for (iodie_id = 0; iodie_id < IODIE_NUM; iodie_id++) {
		num = route_list->route_num;
		if (num >= UBCORE_MAX_ROUTE_NUM) {
			ubcore_log_warn("Invalid route num, num = %d.\n", num);
			return 0;
		}
		for (port_id = 0; port_id < PORT_NUM; port_id++) {
			if (is_eid_valid(src_agg_dev->ues[iodie_id].port_eid[port_id]) &&
				is_eid_valid(dst_agg_dev->ues[iodie_id].port_eid[port_id])) {
				break;
			}
		}
		if (port_id >= PORT_NUM) {
			ubcore_log_err("No valid port_eid found, num = %d.\n", num);
			return -EINVAL;
		}
		append_route_list(route_list, src_agg_dev->ues[iodie_id].port_eid[port_id],
			dst_agg_dev->ues[iodie_id].port_eid[port_id],
			src_agg_dev->ues[iodie_id].chip_id);
	}
	return 0;
}

static int ubcore_get_route_port_eid(union ubcore_eid *src_v_eid,
	union ubcore_eid *dst_v_eid, struct ubcore_route_list *route_list)
{
	int src_dev_id, dst_dev_id, local_idx, remote_idx;
	struct ubcore_topo_agg_dev *src_agg_dev = NULL;
	struct ubcore_topo_agg_dev *dst_agg_dev = NULL;
	struct ubcore_topo_node *src_topo_info = NULL;
	struct ubcore_topo_node *dst_topo_info = NULL;
	uint32_t num = route_list->route_num;
	int ret = 0;

	src_topo_info = ubcore_get_topo_info_by_agg_eid(src_v_eid, &src_dev_id);
	if (IS_ERR_OR_NULL(src_topo_info)) {
		ubcore_log_err("Failed to get src_topo_info.\n");
		return -EINVAL;
	}
	dst_topo_info = ubcore_get_topo_info_by_agg_eid(dst_v_eid, &dst_dev_id);
	if (IS_ERR_OR_NULL(dst_topo_info)) {
		ubcore_log_err("Failed to get dst_topo_info.\n");
		return -EINVAL;
	}
	src_agg_dev = &src_topo_info->agg_devs[src_dev_id];
	dst_agg_dev = &dst_topo_info->agg_devs[dst_dev_id];
	// handle the possibility where src and dst share the same node.
	if (src_topo_info->node_id == dst_topo_info->node_id)
		return get_route_port_eid_same_node(src_agg_dev, dst_agg_dev, route_list);

	for (local_idx = 0; local_idx < IODIE_NUM * PORT_NUM; local_idx++) {
		uint32_t local_iodie = local_idx / PORT_NUM;
		uint32_t local_port = local_idx % PORT_NUM;

		if (route_list->route_num >= UBCORE_MAX_ROUTE_NUM) {
			route_list->route_num = UBCORE_MAX_ROUTE_NUM;
			ubcore_log_warn("Invalid route num, num = %d.\n",
				route_list->route_num);
			return 0;
		}
		if (!is_eid_valid(src_agg_dev->ues[local_iodie].port_eid[local_port])) {
				continue;
		}

		for (remote_idx = 0; remote_idx < IODIE_NUM * PORT_NUM; remote_idx++) {
			if (!dst_topo_info->links[local_idx][remote_idx])
				continue;

			uint32_t remote_iodie = remote_idx / PORT_NUM;
			uint32_t remote_port = remote_idx % PORT_NUM;

			append_route_list(route_list,
				src_agg_dev->ues[local_iodie].port_eid[local_port],
				dst_agg_dev->ues[remote_iodie].port_eid[remote_port],
				src_agg_dev->ues[local_iodie].chip_id);
		}
	}

	if (route_list->route_num == num) {
		ubcore_log_err(
			"Failed to get topo port eid, route_num: %u.\n", route_list->route_num);
		return -EINVAL;
	}

	return ret;
}

static int ubcore_get_route_primary_eid(union ubcore_eid *src_v_eid,
	union ubcore_eid *dst_v_eid, struct ubcore_route_list *route_list)
{
	int iodie_id;
	struct ubcore_topo_agg_dev *src_agg_dev = NULL;
	struct ubcore_topo_agg_dev *dst_agg_dev = NULL;

	src_agg_dev = get_topo_agg_dev(src_v_eid);
	if (IS_ERR_OR_NULL(src_agg_dev)) {
		ubcore_log_err("Failed to get src_agg_dev.\n");
		return -EINVAL;
	}
	dst_agg_dev = get_topo_agg_dev(dst_v_eid);
	if (IS_ERR_OR_NULL(dst_agg_dev)) {
		ubcore_log_err("Failed to get dst_agg_dev.\n");
		return -EINVAL;
	}

	for (iodie_id = 0; iodie_id < IODIE_NUM; iodie_id++) {
		append_route_list_ctp(route_list, src_agg_dev->ues[iodie_id].primary_eid,
			dst_agg_dev->ues[iodie_id].primary_eid,
			src_agg_dev->ues[iodie_id].chip_id);
	}
	return 0;
}

int ubcore_get_route_loopback_primary_eid(union ubcore_eid *local_eid,
	struct ubcore_route_list *route_list)
{
	int dev_id, iodie_id, num;
	struct ubcore_topo_agg_dev *agg_dev = NULL;
	struct ubcore_topo_node *topo_info = NULL;

	topo_info = ubcore_get_topo_info_by_agg_eid(local_eid, &dev_id);
	if (IS_ERR_OR_NULL(topo_info)) {
		ubcore_log_err("Failed to get topo_info, local_eid=" EID_FMT ".\n",
			EID_ARGS(*local_eid));
		return -EINVAL;
	}
	agg_dev = &topo_info->agg_devs[dev_id];

	for (iodie_id = 0; iodie_id < IODIE_NUM; iodie_id++) {
		num = route_list->route_num;
		if (num >= UBCORE_MAX_ROUTE_NUM) {
			ubcore_log_warn("Invalid route num, num = %d.\n", num);
			return 0;
		}
		append_route_list_ctp(route_list, agg_dev->ues[iodie_id].primary_eid,
			agg_dev->ues[iodie_id].primary_eid, (uint32_t)(iodie_id + 1));
	}

	return 0;
}

int ubcore_get_route_list(struct ubcore_route *route,
	struct ubcore_route_list *route_list)
{
	int ret = 0;

	// check valid pointer to v_eid
	if (IS_ERR_OR_NULL(route) || IS_ERR_OR_NULL(route_list)) {
		ubcore_log_err("Invalid parameter.\n");
		return -EINVAL;
	}
	union ubcore_eid *src_v_eid = &route->src;
	union ubcore_eid *dst_v_eid = &route->dst;

	if (!g_ubcore_topo_map) {
		ubcore_log_err(
			"Failed to get p_eid, ubcore topo map doesn't exist.\n");
		return -EINVAL;
	}

	(void)memset(route_list, 0, sizeof(struct ubcore_route_list));

	ret = ubcore_get_route_primary_eid(src_v_eid, dst_v_eid, route_list);
	if (ret != 0) {
		ubcore_log_err("Failed to get primary eid, ret: %d.\n", ret);
		return ret;
	}

	ret = ubcore_get_route_port_eid(src_v_eid, dst_v_eid, route_list);
	if (ret != 0) {
		ubcore_log_err("Failed to get port eid, ret: %d.\n", ret);
		return ret;
	}

	ubcore_log_info("Finish to query primary port eid, route_num: %u.\n",
		route_list->route_num);
	return 0;
}
EXPORT_SYMBOL(ubcore_get_route_list);

static int ubcore_get_path_set_primary(struct ubcore_topo_node *dst_topo_info,
	struct ubcore_topo_agg_dev *src_agg_dev, struct ubcore_topo_agg_dev *dst_agg_dev,
	struct ubcore_path_set *path_set)
{
	uint32_t path_idx = 0;
	struct ubcore_path *path;

	for (uint32_t local_iodie = 0; local_iodie < IODIE_NUM; local_iodie++) {
		for (uint32_t remote_iodie = 0; remote_iodie < IODIE_NUM; remote_iodie++) {
			bool has_port_link = false;

			if (path_idx >= UBCORE_MAX_ROUTE_NUM) {
				ubcore_log_warn("Path set is full, path_count: %u.\n", path_idx);
				path_set->path_count = path_idx;
				return 0;
			}

			for (uint32_t local_port = 0;
				local_port < PORT_NUM && !has_port_link; local_port++) {
				uint32_t local_idx = local_iodie * PORT_NUM + local_port;
				for (uint32_t remote_port = 0;
					remote_port < PORT_NUM && !has_port_link; remote_port++) {
					uint32_t remote_idx = remote_iodie * PORT_NUM + remote_port;
					if (dst_topo_info->links[local_idx][remote_idx]) {
						has_port_link = true;
					}
				}
			}

			if (!has_port_link)
				continue;

			if (!is_eid_valid(src_agg_dev->ues[local_iodie].primary_eid) ||
				!is_eid_valid(dst_agg_dev->ues[remote_iodie].primary_eid)) {
				continue;
			}

			path = &path_set->paths[path_idx];
			path->src_port.chip_id = src_agg_dev->ues[local_iodie].chip_id;
			path->src_port.die_id = src_agg_dev->ues[local_iodie].die_id;
			path->src_port.port_idx = INVALID_PORT;
			path->src_port.reserved = 0;

			path->dst_port.chip_id = dst_agg_dev->ues[remote_iodie].chip_id;
			path->dst_port.die_id = dst_agg_dev->ues[remote_iodie].die_id;
			path->dst_port.port_idx = INVALID_PORT;
			path->dst_port.reserved = 0;

			(void)memcpy(&path->src_eid,
						src_agg_dev->ues[local_iodie].primary_eid,
						sizeof(union ubcore_eid));
			(void)memcpy(&path->dst_eid,
						dst_agg_dev->ues[remote_iodie].primary_eid,
						sizeof(union ubcore_eid));
			ubcore_log_info("src chip_idx is %u, die_idx is %u, port_idx is %u.\n.",
				path->src_port.chip_id, path->src_port.die_id,
				path->src_port.port_idx);
			ubcore_log_info("dst chip_idx is %u, die_idx is %u, port_idx is %u.\n.",
				path->dst_port.chip_id, path->dst_port.die_id,
				path->dst_port.port_idx);
			path_idx++;
		}
	}

	path_set->path_count = path_idx;

	if (path_idx == 0) {
		ubcore_log_err("Failed to get any valid primary path.\n");
		return -EINVAL;
	}

	return 0;
}

static int ubcore_get_path_set_port(struct ubcore_topo_node *src_topo_info,
	struct ubcore_topo_node *dst_topo_info, struct ubcore_topo_agg_dev *src_agg_dev,
	struct ubcore_topo_agg_dev *dst_agg_dev, struct ubcore_path_set *path_set)
{
	uint32_t path_idx = 0;
	struct ubcore_path *path;

	for (uint32_t local_idx = 0; local_idx < IODIE_NUM * PORT_NUM; local_idx++) {
		uint32_t local_iodie = local_idx / PORT_NUM;
		uint32_t local_port = local_idx % PORT_NUM;

		if (path_idx >= UBCORE_MAX_ROUTE_NUM) {
			ubcore_log_warn("Path set is full, path_count: %u.\n", path_idx);
			path_set->path_count = path_idx;
			return 0;
		}

		if (!is_eid_valid(src_agg_dev->ues[local_iodie].port_eid[local_port]))
			continue;

		for (uint32_t remote_idx = 0; remote_idx < IODIE_NUM * PORT_NUM; remote_idx++) {
			if (!dst_topo_info->links[local_idx][remote_idx])
				continue;

			if (path_idx >= UBCORE_MAX_ROUTE_NUM) {
				ubcore_log_warn("Path set is full, path_count: %u.\n", path_idx);
				path_set->path_count = path_idx;
				return 0;
			}

			uint32_t remote_iodie = remote_idx / PORT_NUM;
			uint32_t remote_port = remote_idx % PORT_NUM;

			path = &path_set->paths[path_idx];
			path->src_port.chip_id = src_agg_dev->ues[local_iodie].chip_id;
			path->src_port.die_id = src_agg_dev->ues[local_iodie].die_id;
			path->src_port.port_idx = local_port;
			path->src_port.reserved = 0;

			path->dst_port.chip_id = dst_agg_dev->ues[remote_iodie].chip_id;
			path->dst_port.die_id = dst_agg_dev->ues[remote_iodie].die_id;
			path->dst_port.port_idx = remote_port;
			path->dst_port.reserved = 0;

			(void)memcpy(&path->src_eid,
				src_agg_dev->ues[local_iodie].port_eid[local_port],
				sizeof(union ubcore_eid));
			(void)memcpy(&path->dst_eid,
				dst_agg_dev->ues[remote_iodie].port_eid[remote_port],
				sizeof(union ubcore_eid));
			ubcore_log_info("src chip_idx is %u, die_idx is %u, port_idx is %u.\n.",
				path->src_port.chip_id, path->src_port.die_id,
				path->src_port.port_idx);
			ubcore_log_info("dst chip_idx is %u, die_idx is %u, port_idx is %u.\n.",
				path->dst_port.chip_id, path->dst_port.die_id,
				path->dst_port.port_idx);
			path_idx++;
		}
	}

	path_set->path_count = path_idx;

	if (path_idx == 0) {
		ubcore_log_err("Failed to get any valid port path.\n");
		return -EINVAL;
	}

	return 0;
}

int ubcore_get_path_set(union ubcore_eid *src_bonding_eid,
	union ubcore_eid *dst_bonding_eid, enum ubcore_tp_type tp_type,
	bool iodie_level, struct ubcore_path_set *path_set)
{
	int ret = 0;
	struct ubcore_topo_agg_dev *src_agg_dev = NULL;
	struct ubcore_topo_agg_dev *dst_agg_dev = NULL;
	struct ubcore_topo_node *src_topo_info = NULL;
	struct ubcore_topo_node *dst_topo_info = NULL;
	int src_dev_id, dst_dev_id;

	if (IS_ERR_OR_NULL(src_bonding_eid) || IS_ERR_OR_NULL(dst_bonding_eid) ||
		IS_ERR_OR_NULL(path_set)) {
		ubcore_log_err("Invalid parameter.\n");
		return -EINVAL;
	}

	if (!g_ubcore_topo_map) {
		ubcore_log_err("Failed to get path set, ubcore topo map doesn't exist.\n");
		return -EINVAL;
	}

	(void)memset(path_set, 0, sizeof(struct ubcore_path_set));

	src_topo_info = ubcore_get_topo_info_by_agg_eid(src_bonding_eid, &src_dev_id);
	if (IS_ERR_OR_NULL(src_topo_info)) {
		ubcore_log_err("Failed to get src_topo_info.\n");
		return -EINVAL;
	}
	dst_topo_info = ubcore_get_topo_info_by_agg_eid(dst_bonding_eid, &dst_dev_id);
	if (IS_ERR_OR_NULL(dst_topo_info)) {
		ubcore_log_err("Failed to get dst_topo_info.\n");
		return -EINVAL;
	}
	if (src_topo_info->type != dst_topo_info->type) {
		ubcore_log_err("src topo_type is not equal with dst topo_type.\n");
		return -EINVAL;
	}
	path_set->topo_type = src_topo_info->type;
	path_set->chip_count = IODIE_NUM;
	path_set->die_count = IODIE_NUM_PER_CHIP;
	path_set->src_node.node_id = src_topo_info->node_id;
	path_set->src_node.super_node_id = src_topo_info->super_node_id;
	path_set->dst_node.node_id = dst_topo_info->node_id;
	path_set->dst_node.super_node_id = dst_topo_info->super_node_id;

	src_agg_dev = &src_topo_info->agg_devs[src_dev_id];
	dst_agg_dev = &dst_topo_info->agg_devs[dst_dev_id];

	/* iodie_level == true && tp_type == RTP: paths array all empty */
	if (iodie_level && tp_type == UBCORE_RTP) {
		path_set->path_count = 0;
		ubcore_log_info("iodie_level RTP mode, path_count set to 0.\n");
		return 0;
	}

	/* iodie_level == true && tp_type == CTP: all paths use primary logic */
	if (iodie_level && tp_type == UBCORE_CTP) {
		ret = ubcore_get_path_set_primary(dst_topo_info, src_agg_dev, dst_agg_dev, path_set);
		if (ret != 0)
			ubcore_log_err("Failed to get primary path set, ret: %d.\n", ret);
		return ret;
	}

	/* iodie_level == false && (tp_type == CTP || tp_type == RTP): original port logic */
	ret = ubcore_get_path_set_port(src_topo_info, dst_topo_info, src_agg_dev,
			dst_agg_dev, path_set);
	if (ret != 0) {
		ubcore_log_err("Failed to get port path set, ret: %d.\n", ret);
		return ret;
	}

	ubcore_log_info("Finish to get path set, path_count: %u.\n", path_set->path_count);

	return 0;
}
EXPORT_SYMBOL(ubcore_get_path_set);

int ubcore_get_topo_eid(uint32_t tp_type, union ubcore_eid *src_v_eid,
	union ubcore_eid *dst_v_eid, union ubcore_eid *src_p_eid, union ubcore_eid *dst_p_eid)
{
	if (src_v_eid != NULL && dst_v_eid != NULL && src_p_eid != NULL && dst_p_eid != NULL) {
		ubcore_log_info("Query topo eid, tp_type: %u.\n", tp_type);
		return 0;
	}
	return -1;
}
EXPORT_SYMBOL(ubcore_get_topo_eid);
