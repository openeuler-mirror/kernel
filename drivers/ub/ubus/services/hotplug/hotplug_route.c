// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) HiSilicon Technologies Co., Ltd. 2025. All rights reserved.
 */

#include <linux/kfifo.h>

#include "../../ubus.h"
#include "../../ubus_entity.h"
#include "../../ubus_driver.h"
#include "../../port.h"
#include "../../route.h"
#include "hotplug.h"

int ubhp_update_route_link_up(struct ub_slot *slot)
{
	struct ub_entity *uent = slot->uent, *r_uent = slot->r_uent;
	struct ub_port *port, *r_port;
	int ret;

	for_each_slot_port(port, slot) {
		if (!port->r_uent)
			continue;

		r_port = port->r_uent->ports + port->r_index;
		ret = ub_route_mod_neighbor(port, r_port);
		if (ret)
			return ret;

		ret = ub_route_mod_neighbor(r_port, port);
		if (ret)
			return ret;
	}

	/* for uent that can't forward, there's no need to update other uent */
	if (ub_entity_support_forward(uent))
		ub_route_mod_bfs(uent);

	if (ub_entity_support_forward(r_uent))
		ub_route_mod_bfs(r_uent);

	ub_route_sync_all();
	return 0;
}

void ubhp_update_route_link_down(struct ub_slot *slot)
{
	struct ub_entity *uent = slot->uent;
	struct ub_port *port;

	for_each_slot_port(port, slot)
		ub_route_clear_port(port);

	/* for uent that can't forward, there's no need to update other uent */
	if (ub_entity_support_forward(uent))
		ub_route_del_bfs(uent);

	ub_route_sync_all();
}

/**
 * ubhp_mark_detached_entities() - mark devices as detached and put them into dev_list
 * @root: a device that needs to be removed
 * @dev_list: a list to store the detached devices
 *
 * this func use bfs to mark devices and put them into dev_list, all devices
 * that connected with root will be marked as detached
 */
void ubhp_mark_detached_entities(struct ub_entity *root, struct list_head *dev_list)
{
#define UBHP_KFIFO_DEPTH SZ_16
	DECLARE_KFIFO(kfifo, struct ub_entity *, UBHP_KFIFO_DEPTH);
	struct ub_port *port;
	struct ub_entity *uent, *r_uent;

	INIT_KFIFO(kfifo);
	ub_entity_assign_priv_flag(root, UB_ENTITY_DETACHED, true);
	kfifo_put(&kfifo, root);

	down_write(&ub_bus_sem);
	while (kfifo_get(&kfifo, &uent)) {
		for_each_uent_port(port, uent) {
			if (!port->r_uent)
				continue;

			r_uent = port->r_uent;
			if (ub_entity_test_and_set_priv_flag(r_uent, UB_ENTITY_DETACHED))
				continue;

			if (!kfifo_put(&kfifo, r_uent))
				ub_err(r_uent, "hp detached entity kfifo put failed!\n");
		}

		list_del(&uent->node);
		list_add_tail(&uent->node, dev_list);
	}
	up_write(&ub_bus_sem);
}

/**
 * ubhp_stop_entities() - stop devices in dev_list
 * @dev_list: a list to store devices
 */
void ubhp_stop_entities(struct list_head *dev_list)
{
	struct ub_entity *uent;

	list_for_each_entry_reverse(uent, dev_list, node)
		ub_stop_ent(uent);
}

/**
 * ubhp_remove_entities() - remove devices in dev_list
 * @dev_list: a list to store devices
 */
void ubhp_remove_entities(struct list_head *dev_list)
{
	struct ub_entity *uent, *tmp;

	list_for_each_entry_safe_reverse(uent, tmp, dev_list, node)
		ub_remove_ent(uent);
}
