// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 *
 * Description: ubagg topo info file
 * Author: Ma Chuan
 * Create: 2025-06-07
 * Note:
 * History: 2025-06-07 Create file
 */
#include <linux/slab.h>
#include <linux/sort.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>
#include "ubagg_log.h"
#include "ubagg_topo_info.h"

/*
 * Topology updates and lookups run in separate phases. The caller guarantees
 * that create, update, and delete operations do not overlap topology readers,
 * so the global topology map and its EID index need no internal locking.
 */
static struct ubagg_topo_map *g_topo_map;

struct ubagg_topo_eid_index_entry {
	union ubcore_eid eid;
	uint32_t node_idx;
	uint32_t dev_idx;
};

static struct ubagg_topo_eid_index_entry *g_topo_eid_index;
static size_t g_topo_eid_index_cnt;

static void ubagg_invalidate_topo_eid_index(void)
{
	struct ubagg_topo_eid_index_entry *old_index;

	old_index = g_topo_eid_index;
	g_topo_eid_index = NULL;
	g_topo_eid_index_cnt = 0;

	kvfree(old_index);
}

struct ubagg_topo_map *
create_global_ubagg_topo_map(struct ubagg_topo_node *topo_infos,
			     uint32_t node_num)
{
	g_topo_map = create_ubagg_topo_map_from_user(topo_infos, node_num);
	return g_topo_map;
}

void delete_global_ubagg_topo_map(void)
{
	if (g_topo_map == NULL)
		return;
	ubagg_invalidate_topo_eid_index();
	delete_ubagg_topo_map(g_topo_map);
	g_topo_map = NULL;
}

struct ubagg_topo_map *get_global_ubagg_map(void)
{
	return g_topo_map;
}

struct ubagg_topo_node *get_current_topo_node(void)
{
	if (g_topo_map == NULL)
		return NULL;

	for (uint32_t i = 0; i < g_topo_map->node_num; i++)
		if (g_topo_map->topo_infos[i].is_current)
			return &g_topo_map->topo_infos[i];
	return NULL;
}

static int ubagg_topo_eid_index_cmp(const void *lhs, const void *rhs)
{
	const struct ubagg_topo_eid_index_entry *left = lhs;
	const struct ubagg_topo_eid_index_entry *right = rhs;
	int ret;

	ret = memcmp(left->eid.raw, right->eid.raw, EID_LEN);
	if (ret != 0)
		return ret;
	if (left->node_idx != right->node_idx)
		return left->node_idx < right->node_idx ? -1 : 1;
	if (left->dev_idx != right->dev_idx)
		return left->dev_idx < right->dev_idx ? -1 : 1;
	return 0;
}

static void ubagg_fill_topo_eid_index_entry(
	struct ubagg_topo_eid_index_entry *entry, const char *eid,
	uint32_t node_idx, uint32_t dev_idx)
{
	(void)memcpy(entry->eid.raw, eid, EID_LEN);
	entry->node_idx = node_idx;
	entry->dev_idx = dev_idx;
}

int ubagg_rebuild_topo_eid_index(struct ubagg_topo_map *topo_map)
{
	struct ubagg_topo_eid_index_entry *new_index;
	struct ubagg_topo_eid_index_entry *old_index;
	size_t entry_idx = 0;
	size_t entry_cnt = 0;
	uint32_t node_idx;
	uint32_t dev_idx;
	uint32_t ue_idx;
	uint32_t port_idx;

	if (topo_map == NULL)
		return -EINVAL;

	for (node_idx = 0; node_idx < topo_map->node_num; node_idx++) {
		for (dev_idx = 0; dev_idx < DEV_NUM; dev_idx++) {
			struct ubagg_topo_agg_dev *agg_dev =
				&topo_map->topo_infos[node_idx].agg_devs[dev_idx];

			if (memchr_inv(agg_dev->agg_eid, 0, EID_LEN) == NULL)
				continue;
			entry_cnt++;
			for (ue_idx = 0; ue_idx < IODIE_NUM; ue_idx++) {
				if (memchr_inv(agg_dev->ues[ue_idx].primary_eid,
					       0, EID_LEN) != NULL)
					entry_cnt++;
				for (port_idx = 0; port_idx < PORT_NUM;
				     port_idx++) {
					if (memchr_inv(agg_dev->ues[ue_idx]
							       .port_eid[port_idx],
						       0, EID_LEN) != NULL)
						entry_cnt++;
				}
			}
		}
	}

	new_index = kvmalloc_array(entry_cnt, sizeof(*new_index), GFP_KERNEL);
	if (entry_cnt != 0 && new_index == NULL) {
		ubagg_invalidate_topo_eid_index();
		return -ENOMEM;
	}

	for (node_idx = 0; node_idx < topo_map->node_num; node_idx++) {
		for (dev_idx = 0; dev_idx < DEV_NUM; dev_idx++) {
			struct ubagg_topo_agg_dev *agg_dev =
				&topo_map->topo_infos[node_idx].agg_devs[dev_idx];

			if (memchr_inv(agg_dev->agg_eid, 0, EID_LEN) == NULL)
				continue;
			ubagg_fill_topo_eid_index_entry(&new_index[entry_idx++],
				agg_dev->agg_eid, node_idx, dev_idx);

			for (ue_idx = 0; ue_idx < IODIE_NUM; ue_idx++) {
				if (memchr_inv(agg_dev->ues[ue_idx].primary_eid,
					       0, EID_LEN) != NULL)
					ubagg_fill_topo_eid_index_entry(
						&new_index[entry_idx++],
						agg_dev->ues[ue_idx].primary_eid,
						node_idx, dev_idx);

				for (port_idx = 0; port_idx < PORT_NUM;
				     port_idx++) {
					char *port_eid = agg_dev->ues[ue_idx]
							 .port_eid[port_idx];

					if (memchr_inv(port_eid, 0, EID_LEN) == NULL)
						continue;
					ubagg_fill_topo_eid_index_entry(
						&new_index[entry_idx++], port_eid,
						node_idx, dev_idx);
				}
			}
		}
	}

	sort(new_index, entry_cnt, sizeof(*new_index),
	     ubagg_topo_eid_index_cmp, NULL);

	old_index = g_topo_eid_index;
	g_topo_eid_index = new_index;
	g_topo_eid_index_cnt = entry_cnt;

	kvfree(old_index);
	return 0;
}

static int ubagg_lookup_topo_eid_index(const union ubcore_eid *eid,
	uint32_t *node_idx, uint32_t *dev_idx)
{
	size_t left = 0;
	size_t right;
	int ret = -ENOENT;

	right = g_topo_eid_index_cnt;
	while (left < right) {
		size_t mid = left + (right - left) / 2;
		int cmp = memcmp(g_topo_eid_index[mid].eid.raw, eid->raw,
				 EID_LEN);

		if (cmp < 0)
			left = mid + 1;
		else
			right = mid;
	}

	if (left < g_topo_eid_index_cnt &&
	    memcmp(g_topo_eid_index[left].eid.raw, eid->raw, EID_LEN) == 0) {
		*node_idx = g_topo_eid_index[left].node_idx;
		*dev_idx = g_topo_eid_index[left].dev_idx;
		ret = 0;
	}

	return ret;
}

static int ubagg_find_topo_by_eid(const union ubcore_eid *eid,
	struct ubagg_topo_node **matched_node,
	struct ubagg_topo_agg_dev **matched_dev, uint32_t *matched_dev_idx)
{
	uint32_t node_idx;
	uint32_t dev_idx;
	int ret;

	if (eid == NULL || memchr_inv(eid->raw, 0, EID_LEN) == NULL)
		return -EINVAL;
	if (g_topo_map == NULL)
		return -ENXIO;

	ret = ubagg_lookup_topo_eid_index(eid, &node_idx, &dev_idx);
	if (ret != 0)
		return ret;
	if (node_idx >= g_topo_map->node_num || dev_idx >= DEV_NUM)
		return -EIO;

	if (matched_node != NULL)
		*matched_node = &g_topo_map->topo_infos[node_idx];
	if (matched_dev != NULL)
		*matched_dev =
			&g_topo_map->topo_infos[node_idx].agg_devs[dev_idx];
	if (matched_dev_idx != NULL)
		*matched_dev_idx = dev_idx;
	return 0;
}

static struct ubagg_topo_node *get_topo_node(union ubcore_eid *eid)
{
	struct ubagg_topo_node *node = NULL;

	if (ubagg_find_topo_by_eid(eid, &node, NULL, NULL) != 0)
		return NULL;
	return node;
}

int find_linked_port(union ubcore_eid *dst_eid,
		     bool connected[UBAGG_DEV_MAX_NUM][UBAGG_DEV_MAX_NUM])
{
	struct ubagg_topo_node *src_node = get_current_topo_node();
	struct ubagg_topo_node *dst_node = get_topo_node(dst_eid);

	if (src_node == NULL) {
		ubagg_log_err("Failed to get current topo node\n");
		return -EINVAL;
	}
	if (dst_node == NULL) {
		ubagg_log_err("Failed to get target topo node\n");
		return -EINVAL;
	}

	for (uint32_t local_idx = 0; local_idx < IODIE_NUM * PORT_NUM; local_idx++) {
		uint32_t local_indice = IODIE_NUM + local_idx;
		if (local_indice >= UBAGG_DEV_MAX_NUM) {
			ubagg_log_err("local_indice %u is out of range\n", local_indice);
			continue;
		}
		for (uint32_t remote_idx = 0; remote_idx < IODIE_NUM * PORT_NUM; remote_idx++) {
			uint32_t remote_indice = IODIE_NUM + remote_idx;
			if (remote_indice >= UBAGG_DEV_MAX_NUM) {
				ubagg_log_err("remote_indice %u is out of range\n", remote_indice);
				continue;
			}
			connected[local_indice][remote_indice] =
				dst_node->links[local_idx][remote_idx];
		}
	}

	/*
	 * Derive iodie-level connectivity (first IODIE_NUM x IODIE_NUM block)
	 * from port-level links: iodie i <-> iodie j is connected if any of
	 * their ports has a valid link.
	 */
	for (uint32_t local_iodie = 0; local_iodie < IODIE_NUM; local_iodie++) {
		for (uint32_t remote_iodie = 0; remote_iodie < IODIE_NUM; remote_iodie++) {
			bool has_port_link = false;
			for (uint32_t local_port = 0;
				local_port < PORT_NUM && !has_port_link; local_port++) {
				uint32_t local_indice =
					IODIE_NUM + local_iodie * PORT_NUM + local_port;
				if (local_indice >= UBAGG_DEV_MAX_NUM) {
					ubagg_log_err("local_indice %u is out of range\n",
						local_indice);
					continue;
				}
				for (uint32_t remote_port = 0; remote_port < PORT_NUM; remote_port++) {
					uint32_t remote_indice =
						IODIE_NUM + remote_iodie * PORT_NUM + remote_port;
					if (remote_indice >= UBAGG_DEV_MAX_NUM) {
						ubagg_log_err("remote_indice %u is out of range\n",
							remote_indice);
						continue;
					}
					if (connected[local_indice][remote_indice]) {
						has_port_link = true;
						break;
					}
				}
			}
			if (has_port_link)
				connected[local_iodie][remote_iodie] = true;
		}
	}

	return 0;
}

struct ubagg_topo_map *
create_ubagg_topo_map_from_user(struct ubagg_topo_node *user_topo_infos,
				uint32_t node_num)
{
	struct ubagg_topo_map *topo_map = NULL;
	int ret = 0;

	if (user_topo_infos == NULL || node_num <= 0 ||
	    node_num > MAX_NODE_NUM) {
		ubagg_log_err("Invalid param\n");
		return NULL;
	}
	topo_map = vzalloc(sizeof(struct ubagg_topo_map));
	if (topo_map == NULL)
		return NULL;
	ret = copy_from_user(topo_map->topo_infos,
			     (void __user *)user_topo_infos,
			     sizeof(struct ubagg_topo_node) * node_num);
	if (ret != 0) {
		ubagg_log_err("Failed to copy topo info.ret is %d.\n", ret);
		vfree(topo_map);
		return NULL;
	}
	topo_map->node_num = node_num;
	return topo_map;
}

void delete_ubagg_topo_map(struct ubagg_topo_map *topo_map)
{
	if (topo_map == NULL)
		return;
	vfree(topo_map);
}

struct ubagg_topo_node *find_cur_topo_node(struct ubagg_topo_map *topo_map)
{
	for (int i = 0; i < topo_map->node_num; i++)
		if (topo_map->topo_infos[i].is_current)
			return &(topo_map->topo_infos[i]);
	ubagg_log_err("can not find cur node index\n");
	return NULL;
}

struct ubagg_topo_agg_dev *
find_cur_topo_agg_dev(struct ubagg_topo_map *topo_map,
		      const union ubcore_eid *bonding_eid)
{
	struct ubagg_topo_node *cur_node = NULL;

	cur_node = find_cur_topo_node(topo_map);
	if (cur_node == NULL) {
		ubagg_log_err("find cur node index failed\n");
		return NULL;
	}
	for (int i = 0; i < DEV_NUM; i++) {
		char *bonding_eid_i = cur_node->agg_devs[i].agg_eid;

		if (memcmp(bonding_eid_i, bonding_eid->raw, EID_LEN) == 0)
			return &(cur_node->agg_devs[i]);
	}
	return NULL;
}

int ubagg_get_primary_eid_by_agg_eid(union ubcore_eid *agg_eid,
	union ubcore_eid *primary_eid, uint32_t ue_id)
{
	struct ubagg_topo_map *topo_map;
	int node_id, dev_id;

	if (ue_id >= IODIE_NUM) {
		ubagg_log_err("Invalid ue_id: %u.\n", ue_id);
		return -EINVAL;
	}

	topo_map = get_global_ubagg_map();
	if (!topo_map) {
		ubagg_log_err("Failed get global topo map");
		return -EINVAL;
	}

	for (node_id = 0; node_id < topo_map->node_num; node_id++) {
		for (dev_id = 0; dev_id < DEV_NUM; dev_id++) {
			struct ubagg_topo_agg_dev *agg_dev =
				&topo_map->topo_infos[node_id].agg_devs[dev_id];

			if (memcmp(agg_eid, agg_dev->agg_eid, sizeof(*agg_eid)) == 0) {
				*primary_eid = *((union ubcore_eid *)
				agg_dev->ues[ue_id].primary_eid);
				return 0;
			}
		}
	}
	return -EINVAL;
}

int ubagg_get_topo_by_eid(const union ubcore_eid *eid,
	struct ubagg_topo_by_eid_out *out)
{
	struct ubagg_topo_agg_dev *agg_dev = NULL;
	struct ubagg_topo_node *node = NULL;
	uint32_t dev_idx;
	int ret;

	if (out == NULL)
		return -EINVAL;

	ret = ubagg_find_topo_by_eid(eid, &node, &agg_dev, &dev_idx);
	if (ret != 0)
		return ret;

	(void)memset(out, 0, sizeof(*out));
	out->type = node->type;
	out->super_node_id = node->super_node_id;
	out->node_id = node->node_id;
	out->is_current = node->is_current;
	out->dev_idx = dev_idx;
	(void)memcpy(out->links, node->links, sizeof(out->links));
	(void)memcpy(&out->agg_dev, agg_dev, sizeof(out->agg_dev));
	return 0;
}
