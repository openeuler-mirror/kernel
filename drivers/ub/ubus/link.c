// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) HiSilicon Technologies Co., Ltd. 2025. All rights reserved.
 */

#define pr_fmt(fmt)	"ubus link: " fmt

#include <linux/kfifo.h>

#include "ubus.h"
#include "msg.h"
#include "enum.h"
#include "port.h"
#include "route.h"
#include "ubus_entity.h"
#include "ubus_driver.h"
#include "services/hotplug/hotplug.h"
#include "link.h"

static struct ub_entity *ublc_get_port_r_uent(struct ub_port *port)
{
	struct ub_entity *r_uent = NULL;
	void *buf;

#define UB_TOPO_BUF_SZ SZ_4K
	buf = kzalloc(UB_TOPO_BUF_SZ, GFP_KERNEL);
	if (!buf)
		return NULL;

	r_uent = ub_enum_get_port_r_uent(port, buf);
	if (!r_uent) {
		port->r_index = 0;
		guid_copy(&port->r_guid, &guid_null);
	}

	kfree(buf);
	return r_uent;
}

static void ublc_stop_devices(struct list_head *dev_list)
{
	struct ub_entity *uent;

	list_for_each_entry_reverse(uent, dev_list, node)
		ub_stop_ent(uent);
}

static void ublc_remove_devices(struct list_head *dev_list)
{
	struct ub_entity *uent, *tmp;

	list_for_each_entry_safe_reverse(uent, tmp, dev_list, node)
		ub_remove_ent(uent);
}

static void ublc_update_route_link_down(struct ub_port *port)
{
	struct ub_entity *uent = port->uent;

	ub_route_clear_port(port);

	if (ub_entity_support_forward(uent))
		ub_route_del_bfs(uent);

	ub_route_sync_all();
}

/**
 * ublc_enum_at_port() - enum at port to find new devices
 * @port: the port that has new device plugged in or all port down remove
 * @dev_list: a list to store the new found devices
 *
 * this func use bfs to enum devices and put them into dev_list,
 * which means the previous device in dev_list is enumerated previous
 */
static int ublc_enum_at_port(struct ub_port *port, struct list_head *dev_list)
{
	void *buf;
	int ret;

#define UB_TOPO_BUF_SZ SZ_4K
	buf = kzalloc(UB_TOPO_BUF_SZ, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	ret = ub_enum_topo_scan_ports(port->uent, port->index, 1, dev_list, buf);
	if (ret) {
		port->r_index = 0;
		guid_copy(&port->r_guid, &guid_null);
	}

	kfree(buf);
	return ret;
}

static int ublc_update_route_link_up(struct ub_port *port)
{
	struct ub_entity *uent = port->uent, *r_uent = port->r_uent;
	struct ub_port *r_port;
	int ret;

	r_port = port->r_uent->ports + port->r_index;
	ret = ub_route_mod_neighbor(port, r_port);
	if (ret)
		return ret;

	ret = ub_route_mod_neighbor(r_port, port);
	if (ret)
		return ret;

	/* for uent that can't forward, there's no need to update other uent */
	if (ub_entity_support_forward(uent))
		ub_route_mod_bfs(uent);

	if (ub_entity_support_forward(r_uent))
		ub_route_mod_bfs(r_uent);

	ub_route_sync_all();
	return 0;
}

/**
 * a simple example for a new device link up, which is hotplug or reset
 * for a given topo like
 * +-------------+        +---------+               +---------+        +---------+
 * | controller0 |p0:--:p0| switch0 |p1:--slot0--:p0| switch1 |p1:--:p0| device0 |
 * +-------------+        +---------+               +---------+        +---------+
 * when port0 is calling handle link up
 * 1. enum at port0 to create switch1 and device0, put them in dev_list
 * 2. route dev_list to set up route between these two devices
 * 3. handle route link up at port0, add route of left(controller0 & switch0)
 *	into right(switch1 & device0) and route of right into left
 * 4. start switch1 and device0
 */
static int ublc_handle_new_device_link_up(struct ub_port *port)
{
	struct list_head dev_list;
	int ret;

	INIT_LIST_HEAD(&dev_list);

	ret = ublc_enum_at_port(port, &dev_list);
	if (ret) {
		ub_err(port->uent, "link up enum at port%u failed, ret=%d\n",
		       port->index, ret);
		return ret;
	}

	if (list_empty(&dev_list)) {
		ub_warn(port->uent, "link up without remote dev\n");
		if (port->link_state == LINK_STATE_RESETING)
			port->link_state = LINK_STATE_DONE;
		return -ENXIO;
	}

	ret = ub_route_entities(&dev_list);
	if (ret) {
		ub_err(port->uent, "link up cal route failed, ret=%d\n", ret);
		goto err_route;
	}

	if (port->slot)
		port->slot->r_uent = port->r_uent;

	ret = ublc_update_route_link_up(port);
	if (ret) {
		ub_err(port->uent, "link up update route failed, ret=%d\n", ret);
		goto err_link_up;
	}

	ret = ub_enum_entities_active(&dev_list);
	if (ret) {
		ub_err(port->uent, "link up start devices failed, ret=%d\n", ret);
		goto err_link_up;
	}

	if (port->link_state == LINK_STATE_RESETING)
		port->link_state = LINK_STATE_DONE;

	return 0;

err_link_up:
	ublc_update_route_link_down(port);
	port->r_uent = NULL;
	if (port->slot)
		port->slot->r_uent = NULL;
err_route:
	ub_enum_clear_ent_list(&dev_list);
	return ret;
}

/**
 * ublc_mark_detached_devices() - mark devices as detached and put them into dev_list
 * @root: a device that needs to be removed
 * @dev_list: a list to store the detached devices
 *
 * this func use bfs to mark devices and put them into dev_list, all devices
 * that connected with root will be marked as detached
 */
static void ublc_mark_detached_devices(struct ub_entity *root,
				       struct list_head *dev_list)
{
#define UB_LC_KFIFO_DEPTH SZ_16
	DECLARE_KFIFO(kfifo, struct ub_entity *, UB_LC_KFIFO_DEPTH);
	struct ub_entity *uent, *r_uent;
	struct ub_port *port;

	INIT_KFIFO(kfifo);
	ub_entity_assign_priv_flag(root, UB_ENTITY_DETACHED, true);
	kfifo_put(&kfifo, root);

	down_write(&ub_bus_sem);
	while (kfifo_get(&kfifo, &uent)) {
		for_each_uent_port(port, uent) {
			if (!port->r_uent)
				continue;

			r_uent = port->r_uent;
			if (ub_entity_test_priv_flag(r_uent, UB_ENTITY_DETACHED))
				continue;

			ub_entity_assign_priv_flag(r_uent, UB_ENTITY_DETACHED, true);
			if (!kfifo_put(&kfifo, r_uent))
				ub_err(r_uent, "%s kfifo put failed!\n", __func__);
		}

		list_del(&uent->node);
		list_add_tail(&uent->node, dev_list);
	}
	up_write(&ub_bus_sem);
}

/**
 * a simple example for link down
 * for a given topo like
 * +-------------+        +---------+               +---------+        +---------+
 * | controller0 |p0:--:p0| switch0 |p1:--slot0--:p0| switch1 |p1:--:p0| device0 |
 * +-------------+        +---------+               +---------+        +---------+
 * when slot0's final port is calling handle link down
 * 1. disconnect p1 and p0 so that p1 and p0 is not connected in software
 * 2. put switch1 and device0 into dev_list, mark them as detached
 * 3. stop switch1 and device0
 * 4. remove switch1 and device0
 * 5. handle route link down at p1, del route of right(switch1 & device0)
 *	from left(controller0 & switch0)
 */
static void ublc_handle_all_link_down(struct ub_port *port, struct ub_entity *r_uent)
{
	struct list_head dev_list;

	INIT_LIST_HEAD(&dev_list);
	ub_port_disconnect(port);

	if (port->slot)
		port->slot->r_uent = NULL;

	ublc_mark_detached_devices(r_uent, &dev_list);
	ublc_stop_devices(&dev_list);
	ublc_remove_devices(&dev_list);
	ublc_update_route_link_down(port);
}

static bool ublc_device_is_down(struct ub_port *port)
{
	struct ub_entity *r_uent = port->r_uent;
	struct ub_entity *uent = port->uent;
	struct ub_port *tmp;

	for_each_uent_port(tmp, uent)
		if (tmp->index != port->index && tmp->r_uent == r_uent)
			return false;

	return true;
}

static void port_link_state_change(struct ub_port *port, struct ub_port *r_port)
{
	if (port->link_state == LINK_STATE_RESETING)
		port->link_state = LINK_STATE_DONE;

	if (r_port->link_state == LINK_STATE_RESETING)
		r_port->link_state = LINK_STATE_DONE;
}

void ublc_link_up_handle(struct ub_port *port)
{
	struct ub_entity *uent = port->uent;
	struct ub_entity *r_uent;
	struct ub_port *r_port;
	int ret;

	if (port->r_uent) {
		ub_warn(uent, "port%u is already up\n", port->index);
		goto link_up_notify;
	}

	device_lock(&uent->dev);

	r_uent = ublc_get_port_r_uent(port);
	if (!r_uent) {
		ret = ublc_handle_new_device_link_up(port);
		if (ret) {
			ubhp_handle_power(port->slot, false);
		} else {
			ub_info(uent, "port%u link up and create device\n",
				port->index);
			ubhp_handle_power(port->slot, true);
		}
		goto out;
	}

	if (!ub_check_and_connect(port, r_uent))
		goto out;

	r_port = port->r_uent->ports + port->r_index;
	ret = ub_route_table_set_for_port(port, r_port);
	if (ret) {
		ub_err(uent, "port%u up set route table failed! ret=%d\n",
		       port->index, ret);
		goto out;
	}

	port_link_state_change(port, r_port);
	ub_info(uent, "port%u link up\n", port->index);
out:
	device_unlock(&uent->dev);
link_up_notify:
	ub_notify_share_port(port, UB_PORT_EVENT_LINK_UP);
}

static void check_entity_disconnected(struct ub_port *port)
{
	struct ub_entity *ent_near = port->uent, *ent_far = port->r_uent, *tmp;
	bool is_connected = false;
	struct ub_port *port_iter;
	u8 val;

	if (port->type == VIRTUAL)
		return;

	/* Ensure topo_rank of ent_near is less than topo_rank of ent_far */
	if (ent_near->topo_rank > ent_far->topo_rank) {
		tmp = ent_near;
		ent_near = ent_far;
		ent_far = tmp;
	}

	if (ub_entity_test_priv_flag(ent_far, UB_ENTITY_DISCONNECTED))
		return;

	/* Traverse all ports of ent_near and check if they are connected to ent_far */
	for_each_uent_port(port_iter, ent_near) {
		if (port_iter->r_uent != ent_far)
			continue;
		if (ub_port_read_byte(port_iter,
		    UB_PORT_PHYSICAL_PORT_LINK_STATUS, &val)) {
			ub_err(ent_near, "get port[%u] link status failed\n",
			       port_iter->index);
			return;
		}
		if (val) {
			is_connected = true;
			break;
		}
	}

	/* If no connection is detected, mark ent_far as disconnected */
	if (!is_connected) {
		ub_info(ent_far, "ub entity is down\n");
		ub_entity_assign_priv_flag(ent_far, UB_ENTITY_DISCONNECTED, true);
	}
}

void ublc_link_down_handle(struct ub_port *port)
{
	struct ub_entity *uent = port->uent;
	struct ub_port *r_port;

	if (!port->r_uent) {
		ub_warn(uent, "port%u is already down\n", port->index);
		goto link_down_notify;
	}

	check_entity_disconnected(port);

	device_lock(&uent->dev);

	if (ublc_device_is_down(port)) {
		ub_entity_assign_priv_flag(port->r_uent, UB_ENTITY_DISCONNECTED, true);
		ub_info(uent, "port%u link down\n", port->index);
		ublc_handle_all_link_down(port, port->r_uent);
		ub_info(uent, "all port link down and remove device\n");
		device_unlock(&uent->dev);

		goto link_down_notify;
	}

	r_port = port->r_uent->ports + port->r_index;

	ub_route_table_clear_for_port(port, r_port);
	ub_port_disconnect(port);

	device_unlock(&uent->dev);

	ub_info(uent, "port%u link down\n", port->index);
link_down_notify:
	ub_notify_share_port(port, UB_PORT_EVENT_LINK_DOWN);
}

static void ub_link_handle_event(struct ub_port *port, enum ub_link_event event)
{
	if (event == UB_LINK_UP)
		ublc_link_up_handle(port);
	else
		ublc_link_down_handle(port);
}

static struct ub_port *ub_link_get_port_from_msg(void *pkt)
{
	struct msg_pkt_header *header = (struct msg_pkt_header *)pkt;
	struct link_msg_payload *payload;
	struct ub_port *port = NULL;
	struct ub_entity *uent;
	u32 seid;

	seid = eid_gen(header->seid_h, header->seid_l);
	uent = ub_get_ent_by_eid(seid);
	if (!uent) {
		pr_warn("get no device by eid %u\n", seid);
		return NULL;
	}

	payload = (struct link_msg_payload *)header->payload;
	if (payload->port_idx >= uent->port_nums) {
		pr_err("link port idx %u exceeds uent port num %u\n",
		       payload->port_idx, uent->port_nums);
		goto out;
	}

	port = uent->ports + payload->port_idx;

out:
	ub_entity_put(uent);
	return port;
}

static void ub_link_event_handler(struct ub_bus_controller *ubc, void *pkt, u16 len)
{
	struct msg_pkt_header *header = (struct msg_pkt_header *)pkt;
	struct ub_port *port;

	if (len < UB_LINK_MSG_SIZE) {
		dev_err(&ubc->dev, "lc msg len[%#x] invalid\n", len);
		return;
	}

	port = ub_link_get_port_from_msg(pkt);
	if (!port)
		return;

	ub_link_handle_event(port,
			     (enum ub_link_event)header->msgetah.sub_msg_code);
}

/**
 * for an incoming msg, the following procedure is performed:
 * 1. parse relating link event from msg
 * 2. parse slot/port that has this event
 * 3. if hotplug event is button pressed, queue a button work; if hotplug event
 *	is card presence, queue a present work with 0s delay, if the work
 *	already exists, modify it's delay time to 0s
 */

static rx_msg_handler_t link_msg_handler[UB_SUB_MSG_CODE_NUM] = {
	ub_link_event_handler,
	ub_link_event_handler,
	ubhp_event_handler,
	ubhp_event_handler,
};

void ub_link_msg_handler(struct ub_bus_controller *ubc, void *pkt, u16 len)
{
	struct msg_pkt_header *header = (struct msg_pkt_header *)pkt;
	u8 sub_msg_code = header->msgetah.sub_msg_code;
	rx_msg_handler_t handler;

	handler = link_msg_handler[sub_msg_code];
	if (handler)
		handler(ubc, pkt, len);
	else
		dev_err(&ubc->dev, "link sub msg code[%#x] not support\n",
			sub_msg_code);
}
