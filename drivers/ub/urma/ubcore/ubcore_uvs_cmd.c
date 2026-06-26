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
#include "ubcore_main_ue_eid.h"
#include "ubcore_host_info.h"
#include "ubcore_topo_info.h"
#include "net/ubcore_cm.h"
#include "ubcore_uvs_cmd.h"

int ubcore_get_path_set(union ubcore_eid *src_bonding_eid,
	union ubcore_eid *dst_bonding_eid, enum ubcore_tp_type tp_type,
	bool iodie_level, struct ubcore_path_set *path_set);

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

	return 0;
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
		arg.in.tp_type, arg.in.iodie_level, &arg.out.path_set);
	if (ret != 0) {
		ubcore_log_err("Failed to get_path_set, ret: %d.\n", ret);
		return ret;
	}
	if (ubcore_global_tlv_append(hdr, (void *)&arg) != 0)
		ret = -EPERM;

	return ret;
}

static int ubcore_insert_host_eid_batch(
	const union ubcore_eid *host_eid, uint32_t eid_num,
	const union ubcore_eid *eids, const union ubcore_net_addr_union *cnas)
{
	struct ubcore_host_info host_info = {0};
	uint32_t i;
	int ret;

	if (host_eid == NULL || eids == NULL || cnas == NULL ||
	    eid_num == 0 || eid_num > UBCORE_HOST_EID_BATCH_EID_MAX) {
		ubcore_log_err("invalid host eid batch.\n");
		return -EINVAL;
	}

	host_info.eid = *host_eid;
	for (i = 0; i < eid_num; i++) {
		host_info.cna = cnas[i];
		ubcore_log_debug("insert host_eid=" EID_FMT " cna=" EID_FMT "\n",
				 EID_ARGS(*host_eid), EID_RAW_ARGS(cnas[i].raw));
		ret = ubcore_insert_host_info(&eids[i], &host_info);
		if (ret != 0) {
			ubcore_log_err("insert host eid batch failed, idx: %u, ret: %d\n",
				       i, ret);
			return ret;
		}
	}

	return 0;
}

static int ubcore_insert_main_ue_eid_batch(
	const union ubcore_eid *main_ue_eid, uint32_t eid_num,
	const union ubcore_eid *eids)
{
	uint32_t i;
	int ret;

	if (main_ue_eid == NULL || eids == NULL || eid_num == 0 ||
	    eid_num > UBCORE_MAIN_UE_EID_BATCH_EID_MAX) {
		ubcore_log_err("invalid main ue eid batch.\n");
		return -EINVAL;
	}

	for (i = 0; i < eid_num; i++) {
		ret = ubcore_insert_main_ue_eid(&eids[i], main_ue_eid);
		if (ret != 0) {
			ubcore_log_err("insert main ue eid batch failed, idx: %u, ret: %d\n",
				       i, ret);
			return ret;
		}
	}

	return 0;
}

static int ubcore_cmd_insert_main_ue_eid(struct ubcore_global_file *file,
	struct ubcore_cmd_hdr *hdr)
{
	struct ubcore_cmd_main_ue_eid_entry arg;
	int ret;

	ret = ubcore_global_tlv_parse(hdr, (void *)&arg);
	if (ret != 0)
		return ret;

	return ubcore_insert_main_ue_eid(&arg.in.eid,
		&arg.in.main_ue_eid);
}

static int ubcore_cmd_delete_main_ue_eid(struct ubcore_global_file *file,
	struct ubcore_cmd_hdr *hdr)
{
	struct ubcore_cmd_main_ue_eid_delete arg;
	int ret;

	ret = ubcore_global_tlv_parse(hdr, (void *)&arg);
	if (ret != 0)
		return ret;

	ret = ubcore_delete_main_ue_eid(&arg.in.eid);
	if (ret != 0)
		ubcore_log_err("delete main ue eid failed, ret: %d\n", ret);

	return ret;
}

static int ubcore_cmd_lookup_main_ue_eid(struct ubcore_global_file *file,
	struct ubcore_cmd_hdr *hdr)
{
	struct ubcore_cmd_main_ue_eid_lookup arg;
	int ret;

	ret = ubcore_global_tlv_parse(hdr, (void *)&arg);
	if (ret != 0)
		return ret;

	ret = ubcore_lookup_main_ue_eid(&arg.in.eid,
		&arg.out.main_ue_eid);
	if (ret != 0) {
		ubcore_log_err("lookup main ue eid failed, ret: %d\n", ret);
		return ret;
	}

	if (ubcore_global_tlv_append(hdr, (void *)&arg) != 0)
		return -EPERM;

	return 0;
}

static int ubcore_cmd_flush_main_ue_eid(struct ubcore_global_file *file,
	struct ubcore_cmd_hdr *hdr)
{
	struct ubcore_cmd_main_ue_eid_flush arg = {
		.out.status = -1,
	};

	ubcore_flush_main_ue_eid();
	arg.out.status = 0;
	return ubcore_global_tlv_append(hdr, &arg);
}

static int ubcore_cmd_insert_main_ue_eid_batch(
	struct ubcore_global_file *file, struct ubcore_cmd_hdr *hdr)
{
	struct ubcore_cmd_main_ue_eid_batch *arg;
	int ret;

	arg = kzalloc(sizeof(*arg), GFP_KERNEL);
	if (arg == NULL)
		return -ENOMEM;

	ret = ubcore_global_tlv_parse(hdr, (void *)arg);
	if (ret == 0)
		ret = ubcore_insert_main_ue_eid_batch(&arg->in.main_ue_eid,
			arg->in.eid_num, arg->in.eids);

	kfree(arg);
	return ret;
}

static int ubcore_cmd_insert_host_eid_batch(
	struct ubcore_global_file *file, struct ubcore_cmd_hdr *hdr)
{
	struct ubcore_cmd_host_eid_batch *arg;
	int ret;

	arg = kzalloc(sizeof(*arg), GFP_KERNEL);
	if (arg == NULL)
		return -ENOMEM;

	ret = ubcore_global_tlv_parse(hdr, (void *)arg);
	if (ret == 0)
		ret = ubcore_insert_host_eid_batch(&arg->in.host_eid,
						   arg->in.eid_num,
						   arg->in.eids,
						   arg->in.cnas);

	kfree(arg);
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
	[UBCORE_CMD_GET_PATH_SET] = { ubcore_cmd_get_path_set, false },
	[UBCORE_CMD_INSERT_MAIN_UE_EID] = {
		ubcore_cmd_insert_main_ue_eid, true },
	[UBCORE_CMD_DELETE_MAIN_UE_EID] = {
		ubcore_cmd_delete_main_ue_eid, true },
	[UBCORE_CMD_LOOKUP_MAIN_UE_EID] = {
		ubcore_cmd_lookup_main_ue_eid, false },
	[UBCORE_CMD_FLUSH_MAIN_UE_EID] = {
		ubcore_cmd_flush_main_ue_eid, true },
	[UBCORE_CMD_INSERT_MAIN_UE_EID_BATCH] = {
		ubcore_cmd_insert_main_ue_eid_batch, true },
	[UBCORE_CMD_INSERT_HOST_EID_BATCH] = {
		ubcore_cmd_insert_host_eid_batch, true },
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
