// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) HiSilicon Technologies Co., Ltd. 2025. All rights reserved.
 */

#define pr_fmt(fmt)	"ubus route: " fmt

#include <linux/kfifo.h>

#include "ubus.h"
#include "msg.h"
#include "enum.h"
#include "port.h"
#include "ubus_driver.h"
#include "route.h"

#define UB_ROUTE_TABLE_ENTRY_START (UB_ROUTE_TABLE_SLICE_START + (0x10 << 2))
#define EBW(port_nums) ((((port_nums) - 1) >> 5) + 1) /* Entry Bit Width */
#define UB_ROUTE_TABLE_ENTRY_BITS SZ_128
#define UB_ROUTE_KFIFO_DEPTH SZ_16

/* node to update routing table */
struct cna_node {
	u32 cna;
	u16 distance; /* distance of path */
	u16 count; /* number of ports that have route to this cna */
	bool need_update; /* need to write to routing table */

	struct kref ref;
	struct list_head node;
};

static struct cna_node *ub_create_cna_node(u32 cna, short distance)
{
	struct cna_node *new_cna;

	new_cna = kzalloc(sizeof(*new_cna), GFP_KERNEL);
	if (!new_cna)
		return NULL;

	new_cna->cna = cna;
	new_cna->need_update = true;
	new_cna->distance = distance;
	new_cna->count = 1;
	kref_init(&new_cna->ref);
	INIT_LIST_HEAD(&new_cna->node);

	return new_cna;
}

static void ub_cna_node_release(struct kref *kref)
{
	struct cna_node *cna = container_of(kref, struct cna_node, ref);

	kfree(cna);
}

static struct cna_node *ub_cna_node_get(struct cna_node *cna)
{
	kref_get(&cna->ref);
	return cna;
}

static void ub_cna_node_put(struct cna_node *cna)
{
	kref_put(&cna->ref, ub_cna_node_release);
}

static int ub_add_cna_node(u32 cna, short distance, struct list_head *cna_list)
{
	struct list_head *prev_head = cna_list;
	struct cna_node *new_cna, *prev_cna;

	/**
	 * keep the cna list in ascending order to get the smallest cna quickly
	 * traverse from tail to end, insert new node when prev is smaller
	 */
	list_for_each_entry_reverse(prev_cna, cna_list, node) {
		if (prev_cna->cna > cna)
			continue;

		if (prev_cna->cna == cna) {
			prev_cna->count++;
			return 0;
		}

		prev_head = &prev_cna->node;
		break;
	}

	new_cna = ub_create_cna_node(cna, distance);
	if (!new_cna)
		return -ENOMEM;

	list_add(&new_cna->node, prev_head);
	return 0;
}

static struct cna_node *ub_find_cna_node(u32 cna, struct list_head *cna_list)
{
	struct cna_node *cna_node;

	list_for_each_entry(cna_node, cna_list, node) {
		if (cna_node->cna < cna)
			continue;

		if (cna_node->cna > cna)
			break;

		return ub_cna_node_get(cna_node);
	}

	return NULL;
}

static void ub_clear_cna_list(struct list_head *cna_list)
{
	struct cna_node *cna, *tmp;

	list_for_each_entry_safe(cna, tmp, cna_list, node) {
		list_del(&cna->node);
		ub_cna_node_put(cna);
	}
}

/* the cna_list had better be empty since it'll be clear when err comes */
static int ub_entity_copy_cna_list(struct ub_entity *uent, struct list_head *cna_list,
				bool update_only)
{
	struct cna_node *cna, *new_cna;

	list_for_each_entry(cna, &uent->cna_list, node) {
		if (update_only && !cna->need_update)
			continue;

		new_cna = ub_create_cna_node(cna->cna, cna->distance);
		if (!new_cna) {
			ub_clear_cna_list(cna_list);
			return -ENOMEM;
		}
		list_add_tail(&new_cna->node, cna_list);
	}

	return 0;
}

void ub_route_clear(struct ub_entity *uent)
{
	struct ub_port *port;

	if (!uent)
		return;

	for_each_uent_port(port, uent)
		bitmap_clear(port->cna_maps, 0, UB_ROUTE_TABLE_ENTRY_BITS);

	ub_clear_cna_list(&uent->cna_list);
}

int ub_route_add_entry(struct ub_port *port, u32 cna, short distance)
{
	if (!port)
		return -EINVAL;

	if (test_bit(cna, port->cna_maps))
		return -EEXIST;

	set_bit(cna, port->cna_maps);
	return ub_add_cna_node(cna, distance, &port->uent->cna_list);
}

static void ub_route_del_entry(struct ub_port *port, u32 cna)
{
	struct cna_node *node;

	clear_bit(cna, port->cna_maps);
	node = ub_find_cna_node(cna, &port->uent->cna_list);
	if (!node) {
		ub_err(port->uent, "can not find cna %#x from uent cna list\n",
		       cna);
		return;
	}

	node->need_update = true;
	node->count--;
	ub_cna_node_put(node);
}

static bool ub_route_del_entries(struct ub_port *port,
				 struct list_head *cna_list)
{
	struct ub_entity *uent = port->uent;
	bool route_updated = false;
	struct cna_node *cna;

	list_for_each_entry(cna, cna_list, node) {
		if (!test_bit(cna->cna, port->cna_maps))
			continue;

		ub_route_del_entry(port, cna->cna);
		route_updated = true;
	}

	if (route_updated)
		ub_entity_assign_priv_flag(uent, UB_ENTITY_ROUTE_UPDATED, true);

	return route_updated;
}

static bool ub_entity_has_cna(u32 cna, struct ub_entity *uent)
{
	struct ub_port *port;

	if (uent->cna == cna)
		return true;

	for_each_uent_port(port, uent)
		if (port->cna == cna)
			return true;

	return false;
}

/* try update routing table from cna_list, return true if updated */
static bool ub_route_mod_entries(struct ub_port *port,
				 struct list_head *cna_list, short off)
{
	struct ub_entity *uent = port->uent;
	struct cna_node *cna, *uent_cna;
	bool route_updated = false;
	short new_distance;
	int ret;

	list_for_each_entry(cna, cna_list, node) {
		if (test_bit(cna->cna, port->cna_maps))
			continue;

		if (ub_entity_has_cna(cna->cna, uent))
			continue;

		new_distance = cna->distance + off;

		uent_cna = ub_find_cna_node(cna->cna, &uent->cna_list);
		if (!uent_cna) {
			ret = ub_route_add_entry(port, cna->cna, new_distance);
			if (!ret)
				goto set_flag;

			ub_err(uent, "add route entry for %#x failed with %d\n",
			       cna->cna, ret);
			return false;
		}

		if (uent_cna->distance < new_distance) {
			ub_cna_node_put(uent_cna);
			continue;
		}

		/* in bfs we will never encounter a shorter path */
		set_bit(cna->cna, port->cna_maps);
		uent_cna->need_update = true;
		uent_cna->count++;
		ub_cna_node_put(uent_cna);
set_flag:
		route_updated = true;
	}

	if (route_updated)
		ub_entity_assign_priv_flag(uent, UB_ENTITY_ROUTE_UPDATED, true);

	return route_updated;
}

bool ub_entity_support_forward(struct ub_entity *uent)
{
	if (!uent)
		return false;

	if (is_ibus_controller(uent))
		return true;

	if (is_switch(uent))
		return true;

	return false;
}

static bool ub_check_path(struct ub_port *from, struct ub_port *to)
{
	if (to == from)
		return false;

	if (!to->r_uent)
		return false;

	if (to->r_uent->port_nums <= 1)
		return false;

	return true;
}

/**
 * consider a given topo like
 * +-------------+         +---------+
 * | controller0 |p0:---:p1| device0 |
 * +-------------+         +---------+
 * when ub_route_mod_neighbor is called for p0, p1, device0's routing table
 * will be updated with p0'cna and controller0's cna. If controller0 supports
 * forward, device0 will also know all route in controller0's routing table
 */
int ub_route_mod_neighbor(struct ub_port *port, struct ub_port *r_port)
{
	struct list_head cna_list;
	int ret;

	if (!port || !r_port)
		return -EINVAL;

	INIT_LIST_HEAD(&cna_list);

	/* if uent can not forward, only need to update uent & port's cna */
	if (ub_entity_support_forward(port->uent)) {
		ret = ub_entity_copy_cna_list(port->uent, &cna_list, false);
		if (ret)
			return ret;
	}

	ret = ub_add_cna_node(port->uent->cna, 0, &cna_list);
	if (ret)
		goto clear_cna;

	ret = ub_add_cna_node(port->cna, 0, &cna_list);
	if (ret)
		goto clear_cna;

	ub_route_mod_entries(r_port, &cna_list, 1);

clear_cna:
	ub_clear_cna_list(&cna_list);
	return ret;
}

/**
 * consider a given topo like
 * +-------------+         +---------+
 * | controller0 |p0:---:p1| device0 |
 * +-------------+         +---------+
 * when device0 is being removed, ub_route_clear_port is called for p0
 * 1. all route that pass though this p0 will be del from controller0's cna_list
 * 2. p0's cna_maps will be clear
 */
void ub_route_clear_port(struct ub_port *port)
{
	struct list_head *cna_list;
	struct cna_node *cna_node;
	bool route_update = false;
	struct ub_entity *uent;
	u32 cna; /* use u32 to avoid wraparound */

	if (!port)
		return;

	uent = port->uent;
	cna_list = &uent->cna_list;
	cna_node = list_first_entry(cna_list, struct cna_node, node);
	cna = find_next_bit(port->cna_maps, UB_MAX_CNA_NUM, 0);

	while (cna < UB_MAX_CNA_NUM) {
		if (list_entry_is_head(cna_node, cna_list, node))
			goto clear_bit;

		while (cna_node->cna < cna) {
			cna_node = list_next_entry(cna_node, node);
			if (list_entry_is_head(cna_node, cna_list, node)) {
				ub_warn(uent, "can't find cna %u in list\n", cna);
				goto clear_bit;
			}
		}

		if (cna_node->cna == cna) {
			route_update = true;
			cna_node->count--;
			cna_node->need_update = true;
		}
clear_bit:
		clear_bit(cna, port->cna_maps);
		cna = find_next_bit(port->cna_maps, UB_MAX_CNA_NUM, cna + 1);
	}

	if (route_update)
		ub_entity_assign_priv_flag(uent, UB_ENTITY_ROUTE_UPDATED, true);
}

struct bfs_node {
	struct ub_port *from;
	short off;
};

/**
 * consider a given topo like
 * +-------------+         +---------+                 +--------+
 * | controller0 |p0:---:p0| switch0 |p1:---slot0---:p0| device0|
 * +-------------+         +---------+                 +--------+
 * after device0 is plugged in, switch0 updates route with p0 and device0's cna,
 * ub_route_mod_bfs tries to use the updated route in switch0's routing
 * table to update controller0 through p0. If success, then pass through
 * controller0's other ports to update neighbor
 */
void ub_route_mod_bfs(struct ub_entity *uent)
{
	DECLARE_KFIFO(kfifo, struct bfs_node, UB_ROUTE_KFIFO_DEPTH);
	struct bfs_node curr, next;
	struct list_head cna_list;
	struct ub_port *from, *to;

	if (!uent)
		return;

	INIT_KFIFO(kfifo);
	INIT_LIST_HEAD(&cna_list);

	if (ub_entity_copy_cna_list(uent, &cna_list, true))
		goto clear_cna;

	for_each_uent_port(to, uent) {
		if (to->r_uent && to->r_uent->port_nums > 1) {
			next.from = to->r_uent->ports + to->r_index;
			next.off = 1;
			kfifo_put(&kfifo, next);
		}
	}

	while (kfifo_get(&kfifo, &curr)) {
		from = curr.from;
		if (!ub_route_mod_entries(from, &cna_list, curr.off))
			continue;

		if (!ub_entity_support_forward(from->uent))
			continue;

		for_each_uent_port(to, from->uent) {
			if (!ub_check_path(from, to))
				continue;

			next.from = to->r_uent->ports + to->r_index;
			next.off = curr.off + 1;
			if (!kfifo_put(&kfifo, next))
				ub_err(next.from->uent,
				       "%s kfifo put failed!\n", __func__);
		}
	}

clear_cna:
	ub_clear_cna_list(&cna_list);
}

/* same as ub_route_mod_bfs, but used to del route instead of update route */
void ub_route_del_bfs(struct ub_entity *uent)
{
	DECLARE_KFIFO(kfifo, struct ub_port *, UB_ROUTE_KFIFO_DEPTH);
	struct ub_port *from, *to;
	struct list_head cna_list;

	if (!uent)
		return;

	INIT_KFIFO(kfifo);
	INIT_LIST_HEAD(&cna_list);

	if (ub_entity_copy_cna_list(uent, &cna_list, true))
		goto clear_cna;

	for_each_uent_port(to, uent)
		if (to->r_uent && to->r_uent->port_nums > 1)
			kfifo_put(&kfifo, to->r_uent->ports + to->r_index);

	while (kfifo_get(&kfifo, &from)) {
		if (!ub_route_del_entries(from, &cna_list))
			continue;

		if (!ub_entity_support_forward(from->uent))
			continue;

		for_each_uent_port(to, from->uent) {
			if (!ub_check_path(from, to))
				continue;

			if (!kfifo_put(&kfifo, to->r_uent->ports + to->r_index))
				ub_err(to->r_uent,
				       "%s kfifo put failed!\n", __func__);
		}
	}

clear_cna:
	ub_clear_cna_list(&cna_list);
}

static void ub_set_route_table_entry(struct ub_entity *uent, u32 dst_cna,
				     u32 *route_table_entry)
{
	u32 offset, i;

	/* Routing Table Block is not required for single-port devices. */
	if (uent->port_nums == 1)
		return;

	/* In a cluster scenario, do not configure the UBC routing table. */
	if (is_ibus_controller(uent) && uent->ubc->cluster)
		return;

	pr_info("cna %#x uent set dstcna %#x route\n", uent->cna, dst_cna);

	for (i = 0; i < EBW(uent->port_nums); i++) {
		offset = ((dst_cna + 1) * EBW(uent->port_nums) + i) << SZ_2;
		ub_cfg_write_dword(uent, UB_ROUTE_TABLE_ENTRY_START + offset,
				   route_table_entry[i]);
	}
}

/**
 * after updating routing table in software, this function must be called
 * to sync the software routing table to config space
 */
void ub_route_sync_dev(struct ub_entity *uent)
{
	DECLARE_BITMAP(route_table_entry, UB_ROUTE_TABLE_ENTRY_BITS);
	struct cna_node *cna_node, *tmp;
	struct ub_port *port;
	u32 cna;

	if (!uent || !ub_entity_test_priv_flag(uent, UB_ENTITY_ROUTE_UPDATED))
		return;

	list_for_each_entry_safe(cna_node, tmp, &uent->cna_list, node) {
		if (!cna_node->need_update)
			continue;

		cna = cna_node->cna;
		bitmap_zero(route_table_entry, UB_ROUTE_TABLE_ENTRY_BITS);

		if (cna_node->count == 0) {
			list_del(&cna_node->node);
			kfree(cna_node);
			goto set_entry;
		}

		for_each_uent_port(port, uent)
			if (test_bit(cna, port->cna_maps))
				set_bit(port->index, route_table_entry);

		cna_node->need_update = false;
set_entry:
		ub_set_route_table_entry(uent, cna, (u32 *)route_table_entry);
	}

	ub_entity_assign_priv_flag(uent, UB_ENTITY_ROUTE_UPDATED, false);
}

/**
 * this function sync all updated routing table entry to config space
 * for devices that aren't in ubc dev list, this function will not update them
 */
void ub_route_sync_all(void)
{
	struct ub_bus_controller *ubc;
	struct ub_entity *uent;

	down_read(&ub_bus_sem);
	list_for_each_entry(ubc, &ubc_list, node)
		list_for_each_entry(uent, &ubc->devs, node)
			ub_route_sync_dev(uent);
	up_read(&ub_bus_sem);
}

int ub_route_entities(struct list_head *dev_list)
{
	if (!dev_list)
		return -EINVAL;

	return ub_enum_bfs_route_cal(dev_list);
}

void ub_route_table_clear_for_port(struct ub_port *port, struct ub_port *r_port)
{
	ub_route_clear_port(r_port);

	ub_route_clear_port(port);

	if (ub_entity_support_forward(r_port->uent))
		ub_route_del_bfs(r_port->uent);

	if (ub_entity_support_forward(port->uent))
		ub_route_del_bfs(port->uent);

	ub_route_sync_all();
}

int ub_route_table_set_for_port(struct ub_port *port,
				struct ub_port *r_port)
{
	int ret;

	ret = ub_route_mod_neighbor(port, r_port);
	if (ret)
		return ret;

	ret = ub_route_mod_neighbor(r_port, port);
	if (ret)
		return ret;

	if (ub_entity_support_forward(port->uent))
		ub_route_mod_bfs(port->uent);

	if (ub_entity_support_forward(r_port->uent))
		ub_route_mod_bfs(r_port->uent);

	ub_route_sync_all();

	return 0;
}
