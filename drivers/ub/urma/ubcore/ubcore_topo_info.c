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
#include <ub/urma/ubcore_types.h>
#include <ub/urma/ubcore_uapi.h>
#include "ubcore_log.h"
#include "ubcore_topo_info.h"
#include "ubcore_priv.h"

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
	topo_map = kzalloc(sizeof(struct ubcore_topo_map), GFP_KERNEL);
	if (!topo_map)
		return NULL;
	ret = copy_from_user(topo_map->topo_infos,
				 (void __user *)user_topo_infos,
				 sizeof(struct ubcore_topo_node) * node_num);
	if (ret != 0) {
		ubcore_log_err("Failed to copy topo infos\n");
		kfree(topo_map);
		return NULL;
	}
	topo_map->node_num = node_num;
	return topo_map;
}

void ubcore_delete_topo_map(struct ubcore_topo_map *topo_map)
{
	if (!topo_map)
		return;
	kfree(topo_map);
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
	int iodie_id, port_id, new_remote_port_id, old_remote_port_id;

	for (iodie_id = 0; iodie_id < IODIE_NUM; iodie_id++) {
		for (port_id = 0; port_id < PORT_NUM; ++port_id) {
			new_remote_port_id = new_topo_info->links[iodie_id][port_id].peer_port;
			old_remote_port_id = old_topo_info->links[iodie_id][port_id].peer_port;
			if (new_remote_port_id == UINT32_MAX) {
				// if new link is not connected, skip it
				continue;
			} else if (old_remote_port_id == UINT32_MAX) {
				// if old link is not connected, update it
				(void)memcpy(&old_topo_info->links[iodie_id][port_id],
					&new_topo_info->links[iodie_id][port_id],
					sizeof(struct ubcore_topo_link));
			} else {
				/* if old link is connected and new link is connected,
				   check if they are the same */
				if (memcmp(&old_topo_info->links[iodie_id][port_id],
						&new_topo_info->links[iodie_id][port_id],
						sizeof(struct ubcore_topo_link)) != 0) {
					ubcore_log_err("link is not the same, ");
					ubcore_log_err(
						"new: peer_node[%u]/peer_iodie[%u]/peer_port[%u], ",
						new_topo_info->links[iodie_id][port_id].peer_node,
						new_topo_info->links[iodie_id][port_id].peer_iodie,
						new_topo_info->links[iodie_id][port_id].peer_port);
					ubcore_log_err(
						"old: peer_node[%u]/peer_iodie[%u]/peer_port[%u]\n",
						old_topo_info->links[iodie_id][port_id].peer_node,
						old_topo_info->links[iodie_id][port_id].peer_iodie,
						old_topo_info->links[iodie_id][port_id].peer_port);
					return -1;
				}
			}
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
			if (new_node->id == old_node->id) {
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
	int node_idx, dev_idx, die_idx, port_idx;
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
			node->id, node->is_current);

		/* print link table for this node */
		for (die_idx = 0; die_idx < IODIE_NUM; die_idx++) {
			for (port_idx = 0; port_idx < PORT_NUM; port_idx++) {
				ubcore_log_info(
					"link[iodie_idx:%d][port_idx:%d] -> ",
					die_idx,
					port_idx);
				ubcore_log_info(
					"peer_node: %u, peer_iodie: %u,peer_port: %u\n",
					node->links[die_idx][port_idx].peer_node,
					node->links[die_idx][port_idx].peer_iodie,
					node->links[die_idx][port_idx].peer_port);
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

		for (port_id = 0; port_id < MAX_PORT_NUM; port_id++) {
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

static int ubcore_get_primary_eid_array(uint32_t entity_id,
	uint32_t chip_id, uint32_t nd_id, union ubcore_eid *eid_array)
{
	struct ubcore_topo_node *cur_node_info;
	int node_id, dev_id, iodie_id;
	struct ubcore_topo_ue *ue;
	int eid_num = 0;

	if (!g_ubcore_topo_map) {
		ubcore_log_warn("ubcore topo map doesn't exist.\n");
		return -1;
	}

	for (node_id = 0; node_id < g_ubcore_topo_map->node_num; node_id++) {
		if (node_id != nd_id)
			continue;
		cur_node_info = g_ubcore_topo_map->topo_infos + node_id;
		for (dev_id = 0; dev_id < DEV_NUM; dev_id++) {
			for (iodie_id = 0; iodie_id < IODIE_NUM; iodie_id++) {
				ue = &(cur_node_info->agg_devs[dev_id].ues[iodie_id]);
				if (ue->entity_id == entity_id &&
					ue->chip_id == chip_id &&
					eid_num < ENTITY_AGG_DEV_NUM) {
					(void)memcpy(&eid_array[eid_num],
						ue->primary_eid,
						sizeof(union ubcore_eid));
					ubcore_log_info(
						"Eid "EID_FMT", num %d, entity %u, chip %u.\n",
						EID_ARGS(eid_array[eid_num]), eid_num,
						entity_id, chip_id);
					eid_num++;
				}
				if (eid_num >= ENTITY_AGG_DEV_NUM) {
					ubcore_log_info("Finish to find primary eid array.\n");
					return 0;
				}
			}
		}
	}

	if (eid_num == 0) {
		ubcore_log_err("Failed to find primary eid array.\n");
		return -EINVAL;
	}

	return 0;
}

static void ubcore_get_min_eid(union ubcore_eid *eid_arr,
	union ubcore_eid *main_primary_eid)
{
	union ubcore_eid empty = {0};
	int index;

	(void)memcpy(main_primary_eid, &eid_arr[0], sizeof(union ubcore_eid));
	for (index = 1; index < ENTITY_AGG_DEV_NUM; index++) {
		if (memcmp(&eid_arr[index], &empty, sizeof(union ubcore_eid)) == 0)
			continue;
		if (memcmp(main_primary_eid, &eid_arr[index], sizeof(union ubcore_eid)) > 0)
			(void)memcpy(main_primary_eid, &eid_arr[index],
				sizeof(union ubcore_eid));
	}
}

int ubcore_get_main_primary_eid(union ubcore_eid *eid,
	union ubcore_eid *main_primary_eid)
{
	union ubcore_eid eid_arr[ENTITY_AGG_DEV_NUM] = {0};
	uint32_t entity_id, chip_id, node_id;
	union ubcore_eid primary_eid = {0};
	int ret;

	ret = ubcore_get_primary_eid(eid, &primary_eid, &entity_id,
		&chip_id, &node_id);
	if (ret != 0) {
		ubcore_log_err("Failed to get primary eid, ret: %d.\n", ret);
		return ret;
	}

	ret = ubcore_get_primary_eid_array(entity_id, chip_id, node_id,
		eid_arr);
	if (ret != 0) {
		ubcore_log_err("Failed to get primary eid array, ret: %d.\n", ret);
		return ret;
	}

	ubcore_get_min_eid(eid_arr, main_primary_eid);

	ubcore_log_info("Finish to get main primary eid "EID_FMT".\n",
		EID_ARGS(*main_primary_eid));
	return 0;
}

static struct ubcore_topo_node *
	ubcore_get_topo_info_by_agg_eid(union ubcore_eid *agg_eid, int *device_id)
{
	struct ubcore_topo_map *topo_map;
	int node_id, dev_id;

	topo_map = g_ubcore_topo_map;
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

static int ubcore_query_eid_idx(struct ubcore_device *dev, union ubcore_eid *eid, uint32_t *eid_idx)
{
	struct ubcore_eid_entry *eid_entity;

	for (int32_t i = 0; i < dev->eid_table.eid_cnt; i++) {
		eid_entity = &dev->eid_table.eid_entries[i];
		if (memcmp(eid, &eid_entity->eid, sizeof(*eid)) == 0) {
			*eid_idx = eid_entity->eid_index;
			return 0;
		}
	}
	return -ENOENT;
}

int ubcore_get_topo_bonding_dev_by_agg_eid(union ubcore_eid *agg_eid,
	struct ubcore_topo_bonding_dev *out)
{
	struct ubcore_device *dev;
	struct ubcore_topo_node *node;
	struct ubcore_topo_agg_dev *agg_dev;
	int dev_id;
	int ret;
	int i, j;

	if (agg_eid == NULL || out == NULL)
		return -EINVAL;

	memset(out, 0, sizeof(*out));
	dev = ubcore_find_device(agg_eid, UBCORE_TRANSPORT_UB);
	if (IS_ERR_OR_NULL(dev))
		return -ENOENT;
	(void)memcpy(out->dev_name, dev->dev_name, UBCORE_MAX_DEV_NAME);
	ret = ubcore_query_eid_idx(dev, agg_eid, &out->bonding_eid_idx);
	ubcore_put_device(dev);
	if (ret != 0) {
		ubcore_log_err("Failed to query eid information, eid: "EID_FMT"\n",
			EID_ARGS(*agg_eid));
		return ret;
	}

	node = ubcore_get_topo_info_by_agg_eid(agg_eid, &dev_id);
	if (node == NULL)
		return -ENOENT;

	agg_dev = &node->agg_devs[dev_id];
	if (!is_agg_dev_valid(agg_dev))
		return -EINVAL;

	for (i = 0; i < IODIE_NUM; i++) {
		if (!is_eid_valid(agg_dev->ues[i].primary_eid)) {
			out->physical_devs[i].primary_eid_idx = UINT32_MAX;
			continue;
		}
		out->physical_devs[i].chip_id = agg_dev->ues[i].chip_id;
		dev = ubcore_find_device((union ubcore_eid *) &agg_dev->ues[i].primary_eid,
			UBCORE_TRANSPORT_UB);
		if (IS_ERR_OR_NULL(dev)) {
			ubcore_log_err("Failed to query primary dev, eid: "EID_FMT"\n",
				EID_RAW_ARGS(agg_dev->ues[i].primary_eid));
			return -ENOENT;
		}
		(void)memcpy(out->physical_devs[i].dev_name, dev->dev_name, UBCORE_MAX_DEV_NAME);
		ret = ubcore_query_eid_idx(dev, (union ubcore_eid *)&agg_dev->ues[i].primary_eid,
			&out->physical_devs[i].primary_eid_idx);
		if (ret != 0) {
			ubcore_log_err("Failed to query primary eid information, eid: "
				EID_FMT"\n", EID_ARGS(*agg_eid));
			ubcore_put_device(dev);
			return ret;
		}
		for (j = 0; j < PORT_NUM; j++) {
			if (!is_eid_valid((const char *)agg_dev->ues[i].port_eid[j])) {
				out->physical_devs[i].port_eid_idx[j] = UINT32_MAX;
				continue;
			}
			ret = ubcore_query_eid_idx(dev,
				(union ubcore_eid *) &agg_dev->ues[i].port_eid[j],
				&out->physical_devs[i].port_eid_idx[j]);
			if (ret != 0) {
				ubcore_log_err("Failed to query port eid information, eid: "
					EID_FMT"\n", EID_ARGS(*agg_eid));
				ubcore_put_device(dev);
				return ret;
			}
		}
		ubcore_put_device(dev);
	}
	return 0;
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
		for (port_id = 0; port_id < MAX_PORT_NUM; port_id++) {
			if (is_eid_valid(src_agg_dev->ues[iodie_id].port_eid[port_id]) &&
				is_eid_valid(dst_agg_dev->ues[iodie_id].port_eid[port_id])) {
				break;
			}
		}
		if (port_id >= MAX_PORT_NUM) {
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
	int src_dev_id, dst_dev_id, iodie_id, port_id, peer_port_id;
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
	if (src_topo_info->id == dst_topo_info->id) {
		return get_route_port_eid_same_node(src_agg_dev, dst_agg_dev, route_list);
	}

	for (iodie_id = 0; iodie_id < IODIE_NUM; iodie_id++) {
		for (port_id = 0; port_id < MAX_PORT_NUM; port_id++) {
			if (route_list->route_num >= UBCORE_MAX_ROUTE_NUM) {
				route_list->route_num = UBCORE_MAX_ROUTE_NUM;
				ubcore_log_warn("Invalid route num, num = %d.\n",
					route_list->route_num);
				return 0;
			}
			if (!is_eid_valid(src_agg_dev->ues[iodie_id].port_eid[port_id]) ||
				src_topo_info->links[iodie_id][port_id].peer_port == UINT32_MAX ||
				src_topo_info->links[iodie_id][port_id].peer_node != dst_topo_info->id) {
				continue;
			}
			// use link to get peer info
			peer_port_id = src_topo_info->links[iodie_id][port_id].peer_port;
			append_route_list(route_list, src_agg_dev->ues[iodie_id].port_eid[port_id],
				dst_agg_dev->ues[iodie_id].port_eid[peer_port_id],
				src_agg_dev->ues[iodie_id].chip_id);
		}
	}

	if (route_list->route_num == num) {
		ubcore_log_err(
			"Failed to get topo port eid, route_num: %u.\n", route_list->route_num);
		return -EINVAL;
	}

	return ret;
}

int ubcore_get_primary_eid_by_agg_eid(union ubcore_eid *agg_eid,
	union ubcore_eid *primary_eid)
{
	struct ubcore_topo_map *topo_map;
	int node_id, dev_id;

	topo_map = ubcore_get_global_topo_map();
	if (!topo_map) {
		ubcore_log_err("Failed get global topo map");
		return -EINVAL;
	}

	for (node_id = 0; node_id < topo_map->node_num; node_id++) {
		for (dev_id = 0; dev_id < DEV_NUM; dev_id++) {
			if (memcmp(agg_eid, topo_map->topo_infos[node_id].agg_devs[dev_id].agg_eid,
					sizeof(*agg_eid)) == 0) {
				*primary_eid = *((union ubcore_eid *)
				topo_map->topo_infos[node_id].agg_devs[dev_id].ues[0].primary_eid);
				return 0;
			}
		}
	}
	return -EINVAL;
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
