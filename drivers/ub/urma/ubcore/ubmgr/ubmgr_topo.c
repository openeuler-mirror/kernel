// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 *
 * Description: ubmgr topo implementation file
 * Author: Wang Hang
 * Create: 2026-02-03
 * Note:
 * History: 2026-02-03 Create file
 */

#include <ub/urma/ubcore_types.h>
#include "ubcore_device.h"
#include "ubcore_log.h"
#include "ubcore_topo_info.h"

#include "ubmgr_topo.h"

static struct ubcore_topo_node *
get_current_node_info(struct ubcore_topo_map *topo_map)
{
	for (uint32_t i = 0; i < topo_map->node_num; i++) {
		struct ubcore_topo_node *node_info;

		node_info = &topo_map->topo_infos[i];
		if (node_info->is_current)
			return node_info;
	}
	return NULL;
}

static int ubmgr_get_first_eid(struct ubcore_device *dev, union ubcore_eid *eid)
{
	spin_lock(&dev->eid_table.lock);
	for (uint32_t i = 0; i < dev->attr.dev_cap.max_eid_cnt; i++) {
		if (dev->eid_table.eid_entries[i].valid == true) {
			*eid = dev->eid_table.eid_entries[i].eid;
			spin_unlock(&dev->eid_table.lock);
			return 0;
		}
	}
	spin_unlock(&dev->eid_table.lock);
	return -1;
}

int ubmgr_get_first_primary_eid(struct ubcore_device *dev,
				struct ubcore_eid_info *primary_eid_info)
{
	int ret;
	union ubcore_eid first_eid;
	union ubcore_eid primary_eid;

	ret = ubmgr_get_first_eid(dev, &first_eid);
	if (ret != 0)
		return -EINVAL;

	ret = ubcore_get_main_primary_eid(&first_eid, &primary_eid);
	if (ret != 0)
		return -EINVAL;

	spin_lock(&dev->eid_table.lock);
	for (int i = 0; i < dev->attr.dev_cap.max_eid_cnt; i++) {
		struct ubcore_eid_entry *eid_entry;

		eid_entry = &dev->eid_table.eid_entries[i];
		if (eid_entry->valid && memcmp(primary_eid.raw, &eid_entry->eid,
					       UBCORE_EID_SIZE) == 0) {
			primary_eid_info->eid = eid_entry->eid;
			primary_eid_info->eid_index = eid_entry->eid_index;

			spin_unlock(&dev->eid_table.lock);
			return 0;
		}
	}
	spin_unlock(&dev->eid_table.lock);
	return -EINVAL;
}

static LIST_HEAD(g_ubmgr_event_notifier_list);
static DEFINE_SPINLOCK(g_ubmgr_notifier_list);

void ubmgr_register_event_notifier(struct ubmgr_event_notifier *notifier)
{
	unsigned long flags;

	spin_lock_irqsave(&g_ubmgr_notifier_list, flags);
	list_add(&notifier->node, &g_ubmgr_event_notifier_list);
	spin_unlock_irqrestore(&g_ubmgr_notifier_list, flags);
}

void ubmgr_unregister_event_notifier(struct ubmgr_event_notifier *notifier)
{
	unsigned long flags;

	spin_lock_irqsave(&g_ubmgr_notifier_list, flags);
	list_del(&notifier->node);
	spin_unlock_irqrestore(&g_ubmgr_notifier_list, flags);
}

static void ubmgr_notify_event(enum ubmgr_event_type event_type,
			       void *event_data)
{
	struct ubmgr_event_notifier *iter;
	unsigned long flags;
	ubmgr_event_cb_t local_cb;

	spin_lock_irqsave(&g_ubmgr_notifier_list, flags);
	list_for_each_entry(iter, &g_ubmgr_event_notifier_list, node) {
		local_cb = iter->cb;
	}
	spin_unlock_irqrestore(&g_ubmgr_notifier_list, flags);

	local_cb(event_type, event_data, NULL);
}

void ubmgr_notify_mgmt_event(struct ubcore_mgmt_event *event)
{
	if (event->event_type != UBCORE_MGMT_EVENT_EID_ADD)
		return;

	struct ubcore_eid_info primary_eid;
	int ret;

	ret = ubmgr_get_first_primary_eid(event->ub_dev, &primary_eid);
	if (ret != 0)
		return;

	struct ubcore_eid_info *new_eid;

	new_eid = event->element.eid_info;
	if (memcmp(&primary_eid.eid, &new_eid->eid, UBCORE_EID_SIZE) != 0)
		return;

	ubmgr_notify_event(UBMGR_EVENT_PRIMARY_EID_CHANGE, event->ub_dev);
}

void ubmgr_notify_set_topo(void)
{
	struct ubcore_topo_map *topo_map;

	topo_map = ubcore_get_global_topo_map();
	if (topo_map == NULL)
		return;

	struct ubcore_topo_node *current_node;

	current_node = get_current_node_info(topo_map);
	if (current_node == NULL)
		return;

	for (int i = 0; i < DEV_NUM; i++) {
		for (int j = 0; j < IODIE_NUM; j++) {
			struct ubcore_topo_ue *ue_info;

			ue_info = &current_node->agg_devs[i].ues[j];
			if (!is_eid_valid(ue_info->primary_eid))
				continue;

			union ubcore_eid eid = { 0 };

			memcpy(&eid, ue_info->primary_eid, EID_LEN);

			struct ubcore_device *dev;

			dev = ubcore_find_device(&eid, UBCORE_TRANSPORT_UB);
			if (IS_ERR_OR_NULL(dev))
				continue;
			ubmgr_notify_event(UBMGR_EVENT_PRIMARY_EID_CHANGE, dev);
			ubcore_put_device(dev);
		}
	}
}
