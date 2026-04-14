// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2025. All rights reserved.
 *
 * Description: ubcore uvs cmd implement
 * Author: Ji Lei
 * Create: 2023-07-03
 * Note:
 * History: 2023-07-03: create file
 */

#include <net/net_namespace.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <ub/urma/ubcore_api.h>
#include <ub/urma/ubcore_uapi.h>
#include "ubcore_device.h"
#include "ubcore_priv.h"
#include "ubcore_cmd_tlv.h"
#include "ubcore_topo_info.h"
#include "net/ubcore_cm.h"
#include "ubmgr/ubmgr_topo.h"
#include "ubcore_uvs_cmd.h"

int ubcore_get_path_set(union ubcore_eid *src_bonding_eid,
	union ubcore_eid *dst_bonding_eid, enum ubcore_tp_type tp_type,
	bool multi_path, struct ubcore_path_set *path_set);

static int ubcore_eidtbl_add_entry(struct ubcore_device *dev,
				   union ubcore_eid *eid, uint32_t *eid_idx,
				   struct net *net)
{
	uint32_t i;

	if (dev->eid_table.eid_entries == NULL)
		return -EINVAL;

	for (i = 0; i < dev->attr.dev_cap.max_eid_cnt; i++) {
		if (memcmp(dev->eid_table.eid_entries[i].eid.raw, eid->raw,
			   UBCORE_EID_SIZE) == 0) {
			ubcore_log_warn("eid already exists\n");
			return 0;
		}
	}
	for (i = 0; i < dev->attr.dev_cap.max_eid_cnt; i++) {
		if (dev->eid_table.eid_entries[i].valid == false) {
			dev->eid_table.eid_entries[i].eid = *eid;
			dev->eid_table.eid_entries[i].valid = true;
			dev->eid_table.eid_entries[i].eid_index = i;
			dev->eid_table.eid_entries[i].net =
				(net == NULL) ? &init_net : net;
			*eid_idx = i;
			ubcore_log_info(
				"dev:%s, add eid: %pI6c, idx: %u, net:0x%p\n",
				dev->dev_name, eid, i, net);
			break;
		}
	}
	if (i == dev->attr.dev_cap.max_eid_cnt) {
		ubcore_log_err("eid table is full\n");
		return -1;
	}
	return 0;
}

static int ubcore_eidtbl_del_entry(struct ubcore_device *dev,
				   union ubcore_eid *eid, uint32_t *eid_idx)
{
	uint32_t i;

	if (dev->eid_table.eid_entries == NULL)
		return -EINVAL;

	for (i = 0; i < dev->attr.dev_cap.max_eid_cnt; i++) {
		if (memcmp(dev->eid_table.eid_entries[i].eid.raw, eid->raw,
			   UBCORE_EID_SIZE) == 0) {
			(void)memset(&dev->eid_table.eid_entries[i], 0,
				     sizeof(struct ubcore_eid_entry));
			*eid_idx = i;
			ubcore_log_info("dev:%s, del eid: %pI6c, idx: %u\n",
					dev->dev_name, eid, i);
			break;
		}
	}
	if (i == dev->attr.dev_cap.max_eid_cnt) {
		ubcore_log_err("eid table is empty");
		return -1;
	}
	return 0;
}

static inline void ubcore_dispatch_eid_change(struct ubcore_device *dev,
					      uint32_t eid_idx)
{
	struct ubcore_event event;

	event.ub_dev = dev;
	event.event_type = UBCORE_EVENT_EID_CHANGE;
	event.element.eid_idx = eid_idx;

	ubcore_dispatch_async_event(&event);
}

static int ubcore_eidtbl_update_entry(struct ubcore_device *dev,
				      union ubcore_eid *eid, uint32_t eid_idx,
				      bool is_add, struct net *net)
{
	if (dev->eid_table.eid_entries == NULL)
		return -EINVAL;

	if (eid_idx >= dev->attr.dev_cap.max_eid_cnt) {
		ubcore_log_err("eid table is full\n");
		return -1;
	}
	if (is_add)
		dev->eid_table.eid_entries[eid_idx].eid = *eid;
	else
		(void)memset(&dev->eid_table.eid_entries[eid_idx].eid, 0,
			     sizeof(union ubcore_eid));
	/* dispatch eid change for both eid add and remove */
	ubcore_dispatch_eid_change(dev, eid_idx);

	dev->eid_table.eid_entries[eid_idx].valid = is_add;
	dev->eid_table.eid_entries[eid_idx].eid_index = eid_idx;
	dev->eid_table.eid_entries[eid_idx].net = net;
	ubcore_log_info("%s eid: %pI6c, idx: %u\n",
			is_add == true ? "add" : "del", eid, eid_idx);
	return 0;
}

int ubcore_update_eidtbl_by_eid(struct ubcore_device *dev,
				union ubcore_eid *eid, uint32_t *eid_idx,
				bool is_alloc_eid, struct net *net)
{
	int ret;

	spin_lock(&dev->eid_table.lock);
	if (is_alloc_eid)
		ret = ubcore_eidtbl_add_entry(dev, eid, eid_idx, net);
	else
		ret = ubcore_eidtbl_del_entry(dev, eid, eid_idx);

	spin_unlock(&dev->eid_table.lock);
	return ret;
}

int ubcore_update_eidtbl_by_idx(struct ubcore_device *dev,
				union ubcore_eid *eid, uint32_t eid_idx,
				bool is_alloc_eid, struct net *net)
{
	int ret;

	spin_lock(&dev->eid_table.lock);
	ret = ubcore_eidtbl_update_entry(dev, eid, eid_idx, is_alloc_eid, net);
	spin_unlock(&dev->eid_table.lock);
	return ret;
}

static int ubcore_get_eid_index(struct ubcore_device *dev,
				union ubcore_eid *eid, uint32_t *eid_index)
{
	uint32_t idx, ret = 0;

	spin_lock(&dev->eid_table.lock);
	for (idx = 0; idx < dev->eid_table.eid_cnt; idx++) {
		if (memcmp(&dev->eid_table.eid_entries[idx].eid, eid,
			   sizeof(union ubcore_eid)) == 0) {
			*eid_index = idx;
			break;
		}
	}
	if (idx == dev->eid_table.eid_cnt)
		ret = -1;
	spin_unlock(&dev->eid_table.lock);
	return ret;
}

static int ubcore_create_jetty_rsrc(struct ubcore_topo_map *topo_map)
{
	struct ubcore_device *dev;
	struct ubcore_eid_info eid_info = { 0 };
	struct ubcore_topo_node *cur_node_info;
	bool has_any_primary_eid = false;
	int dev_idx, die_idx;
	int ret;

	cur_node_info = ubcore_get_cur_topo_info(topo_map);
	if (cur_node_info == NULL) {
		ubcore_log_err("Failed to get current node info\n");
		return -EINVAL;
	}

	for (dev_idx = 0; dev_idx < DEV_NUM; dev_idx++) {
		for (die_idx = 0; die_idx < IODIE_NUM; die_idx++) {
			if (!is_eid_valid(
				cur_node_info->agg_devs[dev_idx].ues[die_idx].primary_eid))
				continue;

			has_any_primary_eid = true;
			(void)memcpy(&eid_info.eid,
					cur_node_info->agg_devs[dev_idx].ues[die_idx].primary_eid,
					sizeof(union ubcore_eid));

			dev = ubcore_get_device_by_eid(&eid_info.eid,
								   UBCORE_TRANSPORT_UB);
			if (dev == NULL) {
				ubcore_log_err(
				"primary dev not exist, node %d dev %d die %d, eid: " EID_FMT
				"\n",
				cur_node_info->node_id, dev_idx, die_idx,
				EID_RAW_ARGS(
				cur_node_info->agg_devs[dev_idx].ues[die_idx].primary_eid
				));
				return -1;
			}

			ret = ubcore_get_eid_index(dev, &eid_info.eid,
						&eid_info.eid_index);
			if (ret != 0) {
				ubcore_log_err("Failed to get eid index\n");
				return ret;
			}

			ret = ubcore_call_cm_eid_ops(dev, &eid_info,
						UBCORE_MGMT_EVENT_EID_ADD);
			if (ret != 0) {
				ubcore_log_err("Failed to call cm eid ops\n");
				return ret;
			}

			ubcore_log_info(
				"Created jetty rsrc: node %d dev %d primary die %d, eid: " EID_FMT
				", idx: %d\n",
				cur_node_info->node_id, dev_idx, die_idx,
				EID_RAW_ARGS(
				cur_node_info->agg_devs[dev_idx].ues[die_idx].primary_eid),
				eid_info.eid_index);
		}
	}

	return has_any_primary_eid ? 0 : -1;
}

static int ubcore_cmd_set_topo(struct ubcore_global_file *file,
			       struct ubcore_cmd_hdr *hdr)
{
	struct ubcore_cmd_set_topo arg;
	struct ubcore_topo_map *new_topo_map;
	struct ubcore_topo_map *topo_map;
	int ret = 0;

	ret = ubcore_global_tlv_parse(hdr, (void *)&arg);
	if (ret != 0)
		return ret;

	if (arg.in.topo_info == NULL || arg.in.topo_num == 0 ||
	    arg.in.topo_num > MAX_NODE_NUM) {
		ubcore_log_err("Invalid set_topo_info param\n");
		return -EINVAL;
	}
	topo_map = ubcore_get_global_topo_map();
	if (topo_map == NULL) {
		topo_map = ubcore_create_global_topo_map(arg.in.topo_info,
							 arg.in.topo_num);
		if (topo_map == NULL) {
			ubcore_log_err("Failed to create topo map\n");
			return -ENOMEM;
		}
	} else {
		new_topo_map = ubcore_create_topo_map_from_user(
			arg.in.topo_info, arg.in.topo_num);
		if (ubcore_update_topo_map(new_topo_map, topo_map) != 0) {
			ubcore_delete_topo_map(new_topo_map);
			ubcore_log_err("Failed to update topo info\n");
			return -1;
		}
		ubcore_delete_topo_map(new_topo_map);
	}
	ubcore_show_topo_map(topo_map);

	ret = ubcore_create_jetty_rsrc(topo_map);
	if (ret != 0) {
		ubcore_log_err("Failed to create jetty rsrc\n");
		ubcore_delete_global_topo_map();
		return ret;
	}

	ubmgr_notify_set_topo();
	return 0;
}

static int ubcore_cmd_get_topo(struct ubcore_global_file *file,
			       struct ubcore_cmd_hdr *hdr)
{
	struct ubcore_cmd_get_topo arg = {0};
	struct ubcore_topo_map *topo_map;
	int ret = 0;

	ret = ubcore_global_tlv_parse(hdr, (void *)&arg);
	if (ret != 0) {
		ubcore_log_err("Failed to parse get_topo_info params\n");
		return ret;
	}

	if (arg.out.topo_map == NULL) {
		ubcore_log_err("Invalid get_topo_info param\n");
		return -EINVAL;
	}

	topo_map = ubcore_get_global_topo_map();
	if (topo_map == NULL) {
		ubcore_log_err("Failed to get global topo map\n");
		return -ENOMEM;
	}
	ret = copy_to_user((void __user *)arg.out.topo_map, topo_map,
					sizeof(struct ubcore_topo_map)
	);
	if (ret != 0) {
		ubcore_log_err("copy_to_user fail.");
		return ret;
	}

	return 0;
}

static int ubcore_cmd_get_route_list(struct ubcore_global_file *file,
	struct ubcore_cmd_hdr *hdr)
{
	struct ubcore_cmd_get_route_list arg;

	int ret = 0;

	ret = ubcore_global_tlv_parse(hdr, (void *)&arg);
	if (ret != 0) {
		ubcore_log_err("Failed to parse ubcore cmd tlv.\n");
		return ret;
	}
	ret = ubcore_get_route_list(&arg.in, &arg.out);
	if (ret != 0) {
		ubcore_log_err("Failed to get_route_list, ret: %d.\n", ret);
		return ret;
	}
	if (ubcore_global_tlv_append(hdr, (void *)&arg) != 0)
		ret = -EPERM;

	return ret;
}

static int ubcore_cmd_get_path_set(struct ubcore_global_file *file,
	struct ubcore_cmd_hdr *hdr)
{
	struct ubcore_cmd_get_path_set arg;

	int ret = 0;

	ret = ubcore_global_tlv_parse(hdr, (void *)&arg);
	if (ret != 0) {
		ubcore_log_err("Failed to parse ubcore cmd tlv.\n");
		return ret;
	}
	ret = ubcore_get_path_set(&arg.in.src_bonding_eid, &arg.in.dst_bonding_eid,
		arg.in.tp_type, arg.in.multi_path, &arg.out);
	if (ret != 0) {
		ubcore_log_err("Failed to get_path_set, ret: %d.\n", ret);
		return ret;
	}
	if (ubcore_global_tlv_append(hdr, (void *)&arg) != 0)
		ret = -EPERM;

	return ret;
}

typedef int (*ubcore_uvs_global_cmd_handler)(struct ubcore_global_file *file,
					     struct ubcore_cmd_hdr *hdr);
struct ubcore_uvs_global_cmd_func {
	ubcore_uvs_global_cmd_handler func;
	bool need_cap_verify;
};

static struct ubcore_uvs_global_cmd_func g_ubcore_uvs_global_cmd_funcs[] = {
	[0] = { NULL, false },
	[UBCORE_CMD_SET_TOPO] = { ubcore_cmd_set_topo, true },
	[UBCORE_CMD_GET_ROUTE_LIST] = { ubcore_cmd_get_route_list, false },
	[UBCORE_CMD_GET_TOPO] = { ubcore_cmd_get_topo, false },
	[UBCORE_CMD_GET_PATH_SET] = { ubcore_cmd_get_path_set, false },
};

int ubcore_uvs_global_cmd_parse(struct ubcore_global_file *file,
	struct ubcore_cmd_hdr *hdr)
{
	if (hdr->command < UBCORE_CMD_SET_TOPO ||
	    hdr->command >= UBCORE_CMD_GLOBAL_LAST ||
	    g_ubcore_uvs_global_cmd_funcs[hdr->command].func == NULL) {
		ubcore_log_err("bad ubcore global command: %d.\n",
			       (int)hdr->command);
		return -EINVAL;
	}

	if (g_ubcore_uvs_global_cmd_funcs[hdr->command].need_cap_verify &&
	    !capable(CAP_NET_ADMIN)) {
		ubcore_log_err(
			"failed cap verify, ubcore global command: %d.\n",
			(int)hdr->command);
		return -EPERM;
	}
	return g_ubcore_uvs_global_cmd_funcs[hdr->command].func(file, hdr);
}
