// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) HiSilicon Technologies Co., Ltd. 2025. All rights reserved.
 */

#include "../../ubus.h"
#include "../../msg.h"
#include "../../enum.h"
#include "../../route.h"
#include "../../port.h"
#include "../../task.h"
#include "../service.h"
#include "hotplug.h"

#define to_ub_slot(s) container_of(s, struct ub_slot, kobj)

static void ubhp_destroy_slot(struct ub_slot *slot)
{
	mutex_destroy(&slot->state_lock);
	kfree(slot);
}

static void ubhp_slot_release(struct kobject *kobj)
{
	struct ub_slot *slot = to_ub_slot(kobj);

	ubhp_destroy_slot(slot);
}

enum slot_state {
	SLOT_ON, /* slot on, device running */
	SLOT_POWERON, /* from slot off to slot on */
	SLOT_POWEROFF, /* from slot on to slot off */
	SLOT_OFF, /* slot off, device not present */
};

struct ub_slot_attribute {
	struct attribute attr;
	ssize_t (*show)(struct ub_slot *slot, char *buf);
	ssize_t (*store)(struct ub_slot *slot, const char *buf, size_t count);
};

#define to_ub_slot_attr(s) container_of(s, struct ub_slot_attribute, attr)

static void ubhp_enable_slot(struct ub_slot *slot)
{
	bool queued = false;

	ubhp_get_slot(slot);
	mutex_lock(&slot->state_lock);

	if (slot->state == SLOT_OFF)
		queued = queue_work(get_rx_msg_wq(UB_MSG_CODE_LINK),
				    &slot->button_work);
	else
		ub_info(slot->uent, "ignore slot poweron\n");

	mutex_unlock(&slot->state_lock);
	if (!queued)
		ubhp_put_slot(slot);
}

static void ubhp_disable_slot(struct ub_slot *slot)
{
	bool queued = false;

	ubhp_get_slot(slot);
	mutex_lock(&slot->state_lock);

	if (slot->state == SLOT_ON)
		queued = queue_work(get_rx_msg_wq(UB_MSG_CODE_LINK),
				    &slot->button_work);
	else
		ub_info(slot->uent, "ignore slot poweroff\n");

	mutex_unlock(&slot->state_lock);
	if (!queued)
		ubhp_put_slot(slot);
}

static ssize_t power_show(struct ub_slot *slot, char *buf)
{
	ssize_t ret;

	mutex_lock(&slot->state_lock);
	switch (slot->state) {
	case SLOT_ON:
		ret = sysfs_emit(buf, "slot is %s\n", "on");
		break;
	case SLOT_POWERON:
		ret = sysfs_emit(buf, "slot is %s\n", "poweron");
		break;
	case SLOT_POWEROFF:
		ret = sysfs_emit(buf, "slot is %s\n", "poweroff");
		break;
	case SLOT_OFF:
		ret = sysfs_emit(buf, "slot is %s\n", "off");
		break;
	default:
		ret = sysfs_emit(buf, "unknown state %u\n", slot->state);
		break;
	}
	mutex_unlock(&slot->state_lock);

	return ret;
}

static ssize_t power_store(struct ub_slot *slot, const char *buf, size_t count)
{
	unsigned long power;
	int ret;

	ret = kstrtoul(buf, 0, &power);
	if (ret) {
		ub_err(slot->uent, "Invalid val for power\n");
		return ret;
	}

	switch (power) {
	case 0:
		ubhp_disable_slot(slot);
		break;
	case 1:
		ubhp_enable_slot(slot);
		break;
	default:
		ub_err(slot->uent, "Invalid val %lu for power\n", power);
		return -EINVAL;
	}

	return count;
}
static struct ub_slot_attribute ub_slot_attr_power = __ATTR_RW(power);

static struct attribute *ub_slot_default_attrs[] = {
	&ub_slot_attr_power.attr,
	NULL
};
ATTRIBUTE_GROUPS(ub_slot_default);

static ssize_t ub_slot_attr_show(struct kobject *kobj, struct attribute *attr,
				 char *buf)
{
	struct ub_slot_attribute *attribute = to_ub_slot_attr(attr);
	struct ub_slot *slot = to_ub_slot(kobj);

	if (!attribute->show)
		return -EIO;

	return attribute->show(slot, buf);
}

static ssize_t ub_slot_attr_store(struct kobject *kobj, struct attribute *attr,
				  const char *buf, size_t count)
{
	struct ub_slot_attribute *attribute = to_ub_slot_attr(attr);
	struct ub_slot *slot = to_ub_slot(kobj);

	if (!attribute->store)
		return -EIO;

	return attribute->store(slot, buf, count);
}

static const struct sysfs_ops ub_slot_sysfs_ops = {
	.show = ub_slot_attr_show,
	.store = ub_slot_attr_store,
};

static const struct kobj_type ub_slot_ktype = {
	.release = ubhp_slot_release,
	.sysfs_ops = &ub_slot_sysfs_ops,
	.default_groups = ub_slot_default_groups,
};

static void ubhp_button_handler(struct work_struct *work);
static void ubhp_present_handler(struct work_struct *work);
static void ubhp_power_handler(struct work_struct *work);
static struct ub_slot *ubhp_create_slot(void)
{
	struct ub_slot *slot;

	slot = kzalloc(sizeof(*slot), GFP_KERNEL);
	if (!slot)
		return NULL;

	slot->ports = NULL;
	INIT_LIST_HEAD(&slot->node);
	INIT_WORK(&slot->button_work, ubhp_button_handler);
	INIT_DELAYED_WORK(&slot->present_work, ubhp_present_handler);
	INIT_DELAYED_WORK(&slot->power_work, ubhp_power_handler);
	mutex_init(&slot->state_lock);

	return slot;
}

static int ubhp_slot_port_check(struct ub_entity *uent, int idx, u32 val)
{
	struct ub_port *ports, *tmp;
	u16 port_start, port_end;
	u16 port_num;

	port_start = (u16)(val & UB_SLOT_START_PORT);
	port_end = (u16)(val >> SZ_16);

	if (port_start > port_end || port_end >= uent->port_nums) {
		ub_err(uent, "slot%d port range err, start=%u, end=%u, total=%u\n",
		       idx, port_start, port_end, uent->port_nums);
		return -EINVAL;
	}

	port_num = port_end - port_start + 1;
	ports = uent->ports + port_start;
	for (tmp = ports; (tmp - ports) < port_num; tmp++) {
		if (tmp->type == VIRTUAL) {
			ub_err(uent, "slot%d port%u type is virtual\n",
			       idx, tmp->index);
			return -EINVAL;
		}

		if (tmp->slot) {
			ub_err(uent, "slot%d port%u already in slot%u\n",
			       idx, tmp->index, tmp->slot->slot_id);
			return -EINVAL;
		}
	}

	return 0;
}

static int ubhp_setup_slot(struct ub_slot *slot, struct ub_entity *uent, int idx)
{
	u16 port_start, port_end;
	u32 val, cap;
	int ret;

	slot->uent = uent;
	slot->slot_id = idx;

	ret = ub_slot_read_dword(slot, UB_SLOT_PORT, &val);
	if (ret)
		return ret;

	ret = ubhp_slot_port_check(uent, idx, val);
	if (ret)
		return ret;

	ret = ub_slot_read_dword(slot, UB_SLOT_CAP, &cap);
	if (ret)
		return ret;

	port_start = (u16)(val & UB_SLOT_START_PORT);
	port_end = (u16)(val >> SZ_16);

	slot->port_start = port_start;
	slot->port_num = port_end - port_start + 1;
	slot->ports = uent->ports + port_start;
	slot->slot_cap = cap;

	ub_info(uent, "slot%u port[%u:%u] cap[%#x] setup\n",
		slot->slot_id, slot->port_start, port_end, slot->slot_cap);

	return 0;
}

static void ubhp_del_slot(struct ub_slot *slot)
{
	struct ub_port *port;

	cancel_work_sync(&slot->button_work);
	cancel_delayed_work_sync(&slot->power_work);
	cancel_delayed_work_sync(&slot->present_work);

	list_del(&slot->node);

	for_each_slot_port(port, slot)
		port->slot = NULL;

	kobject_del(&slot->kobj);
}

static int ubhp_add_slot(struct ub_slot *slot)
{
	struct ub_entity *uent = slot->uent;
	struct ub_port *port;
	int ret;

	ret = kobject_init_and_add(&slot->kobj, &ub_slot_ktype, &uent->dev.kobj,
				   "slot%d", slot->slot_id);
	if (ret)
		return ret;

	if (slot->ports->r_uent) {
		slot->state = SLOT_ON;
		slot->r_uent = slot->ports->r_uent;
	} else {
		slot->state = SLOT_OFF;
	}

	for_each_slot_port(port, slot)
		port->slot = slot;

	list_add(&slot->node, &uent->slot_list);

	return ret;
}

static int ubhp_probe(struct ub_service_device *sdev)
{
	struct ub_entity *uent = sdev->uent;
	struct ub_slot *slot, *tmp;
	u16 slot_num;
	int i, ret;

	if (sdev->service != UB_SERVICE_HP)
		return -ENODEV;

	ret = ub_cfg_read_word(uent, UB_SLOT_START + UB_SLOT_NUM, &slot_num);
	if (ret)
		return ret;

	if (!slot_num) {
		ub_err(uent, "hotplug probe without slot, ignoring\n");
		return -ENODEV;
	}

	for (i = 0; i < slot_num; i++) {
		slot = ubhp_create_slot();
		if (!slot) {
			ret = -ENOMEM;
			goto free_slots;
		}

		ret = ubhp_setup_slot(slot, uent, i);
		if (ret) {
			ubhp_destroy_slot(slot);
			goto free_slots;
		}

		ret = ubhp_add_slot(slot);
		if (ret) {
			ubhp_put_slot(slot);
			goto free_slots;
		}
	}

	ubhp_start_slots(uent);

	return 0;
free_slots:
	list_for_each_entry_safe_reverse(slot, tmp, &uent->slot_list, node) {
		ubhp_del_slot(slot);
		ubhp_put_slot(slot);
	}

	return ret;
}

static void ubhp_remove(struct ub_service_device *sdev)
{
	struct ub_entity *uent = sdev->uent;
	struct ub_slot *slot, *tmp;

	ubhp_stop_slots(uent);

	list_for_each_entry_safe(slot, tmp, &uent->slot_list, node) {
		ubhp_del_slot(slot);
		ubhp_put_slot(slot);
	}
}

static struct ub_service_driver ubhp_service_driver = {
	.name = "ub-hotplug",

	.probe = ubhp_probe,
	.remove = ubhp_remove,

	.service = UB_SERVICE_HP,
};

void ubhp_service_init(void)
{
	ub_service_driver_register(&ubhp_service_driver);
}

void ubhp_service_uninit(void)
{
	ub_service_driver_unregister(&ubhp_service_driver);
}

static void ubhp_disconnect_slot(struct ub_slot *slot)
{
	struct ub_port *port;

	for_each_slot_port(port, slot)
		ub_port_disconnect(port);

	slot->r_uent = NULL;
}

static void ubhp_clear_port(struct ub_slot *slot)
{
	struct ub_port *port;

	for_each_slot_port(port, slot) {
		port->r_index = 0;
		guid_copy(&port->r_guid, &guid_null);
	}
}

/**
 * ubhp_enum_at_slot() - enum at slot to find new devices
 * @slot: the slot that has new device plugged in
 * @dev_list: a list to store the new found devices
 *
 * this func use bfs to enum devices and put them into dev_list,
 * which means the previous device in dev_list is enumerated previous
 */
static int ubhp_enum_at_slot(struct ub_slot *slot, struct list_head *dev_list)
{
	void *buf;
	int ret;

#define UB_TOPO_BUF_SZ SZ_4K
	buf = kzalloc(UB_TOPO_BUF_SZ, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	ret = ub_enum_topo_scan_ports(slot->uent, slot->port_start, slot->port_num,
				      dev_list, buf);
	if (ret)
		ubhp_clear_port(slot);

	kfree(buf);
	return ret;
}

/**
 * a simple example for link up
 * for a given topo like
 * +-------------+         +---------+                 +---------+         +--------+
 * | controller0 |p0:---:p0| switch0 |p1:---slot0---:p0| switch1 |p1:---:p0| device0|
 * +-------------+         +---------+                 +---------+         +--------+
 * when slot0 is calling handle link up
 * 1. enum at slot0 to create switch1 and device0, put them in dev_list
 * 2. route dev_list to set up route between these two devices
 * 3. handle route link up at slot0, add route of left(controller0 & switch0)
 *	into right(switch1 & device0) and route of right into left
 * 4. start switch1 and device0
 */
static int ubhp_handle_link_up(struct ub_slot *slot)
{
	struct list_head dev_list;
	int ret;

	INIT_LIST_HEAD(&dev_list);

	ret = ubhp_enum_at_slot(slot, &dev_list);
	if (ret) {
		ub_err(slot->uent, "enum at slot%u failed, ret=%d\n", slot->slot_id, ret);
		return ret;
	}

	if (list_empty(&dev_list)) {
		ub_warn(slot->uent, "link up without remote dev\n");
		return -ENXIO;
	}

	ret = ub_route_entities(&dev_list);
	if (ret) {
		ub_err(slot->uent, "hotplug cal route failed, ret=%d\n", ret);
		goto err_route;
	}

	slot->r_uent = slot->ports->r_uent;
	ret = ubhp_update_route_link_up(slot);
	if (ret) {
		ub_err(slot->uent, "hotplug update route failed, ret=%d\n", ret);
		goto err_link_up;
	}

	ret = ub_enum_entities_active(&dev_list, TASK_SRC_SELF);
	if (ret) {
		ub_err(slot->uent, "hotplug start devices failed, ret=%d\n", ret);
		goto err_link_up;
	}

	return 0;
err_link_up:
	ubhp_update_route_link_down(slot);
	slot->r_uent = NULL;
err_route:
	ub_enum_clear_ent_list(&dev_list);
	return ret;
}

/**
 * a simple example for link down
 * for a given topo like
 * +-------------+         +---------+                 +---------+         +--------+
 * | controller0 |p0:---:p0| switch0 |p1:---slot0---:p0| switch1 |p1:---:p0| device0|
 * +-------------+         +---------+                 +---------+         +--------+
 * when slot0 is calling handle link down
 * 1. disconnect slot0 so that p1 and p0 is not connected in software
 * 2. put switch1 and device0 into dev_list, mark them as detached
 * 3. stop switch1 and device0
 * 4. remove switch1 and device0
 * 5. handle route link down at slot0, del route of right(switch1 & device0)
 *	from left(controller0 & switch0)
 */
static void ubhp_handle_link_down(struct ub_slot *slot)
{
	struct list_head dev_list;
	struct ub_entity *r_uent;

	INIT_LIST_HEAD(&dev_list);

	r_uent = slot->r_uent;
	if (!r_uent) {
		ub_warn(slot->uent, "link down without remote dev\n");
		return;
	}

	ubhp_disconnect_slot(slot);
	ubhp_mark_detached_entities(r_uent, &dev_list);
	ubhp_stop_entities(&dev_list);
	ubhp_remove_entities(&dev_list);
	ubhp_update_route_link_down(slot);
}

static void ubhp_handle_button_press(struct ub_slot *slot)
{
#define POWER_ON_WAIT 5
	bool queued = false;

	ubhp_get_slot(slot);
	mutex_lock(&slot->state_lock);

	if (slot->state == SLOT_ON) {
		slot->state = SLOT_POWEROFF;
		ub_info(slot->uent, "slot%u poweroff\n", slot->slot_id);
		ubhp_set_indicators(slot, INDICATOR_BLINKING, INDICATOR_NOOP);
		/* for power off, issued the present work immediately */
		queued = queue_delayed_work(get_rx_msg_wq(UB_MSG_CODE_LINK),
					    &slot->present_work, 0);
	} else if (slot->state == SLOT_OFF) {
		slot->state = SLOT_POWERON;
		ub_info(slot->uent, "slot%u poweron\n", slot->slot_id);
		ubhp_set_indicators(slot, INDICATOR_BLINKING, INDICATOR_NOOP);
		/* for power on, left 5s for possible card insertion */
		queued = queue_delayed_work(get_rx_msg_wq(UB_MSG_CODE_LINK),
					    &slot->present_work,
					    POWER_ON_WAIT * HZ);
	}

	mutex_unlock(&slot->state_lock);
	if (!queued)
		ubhp_put_slot(slot);
}

static void ubhp_button_handler(struct work_struct *work)
{
	struct ub_slot *slot = container_of(work, struct ub_slot, button_work);

	ubhp_handle_button_press(slot);
	ubhp_put_slot(slot);
}

void ubhp_handle_power(struct ub_slot *slot, bool power_on)
{
	if (!slot || !PWR(slot))
		return;

	mutex_lock(&slot->state_lock);

	if (slot->state != SLOT_POWERON)
		goto out;

	if (power_on) {
		ubhp_set_indicators(slot, INDICATOR_ON, INDICATOR_NOOP);
		slot->state = SLOT_ON;
		ub_info(slot->uent, "slot%u on\n", slot->slot_id);
		ub_info(slot->uent,
			"slot%u handle hotplug success\n", slot->slot_id);
		if (cancel_work(&slot->button_work))
			ubhp_put_slot(slot);
	} else {
		ubhp_set_slot_power(slot, POWER_OFF);
		slot->state = SLOT_OFF;
		ubhp_set_indicators(slot, INDICATOR_OFF, INDICATOR_NOOP);
		ub_info(slot->uent, "slot%u off\n", slot->slot_id);
		ub_info(slot->uent,
			"slot%u handle hotplug unsuccess\n", slot->slot_id);
	}

out:
	mutex_unlock(&slot->state_lock);
}

static void ubhp_power_handler(struct work_struct *work)
{
	struct delayed_work *power_work;
	struct ub_slot *slot;

	power_work = to_delayed_work(work);
	slot = container_of(power_work, struct ub_slot, power_work);

	ubhp_handle_power(slot, false);
	ubhp_put_slot(slot);
}

static void ubhp_handle_present(struct ub_slot *slot)
{
#define HP_LINK_WAIT_DELAY 10
	mutex_lock(&slot->state_lock);

	if (slot->state == SLOT_POWEROFF || slot->state == SLOT_ON) {
		ubhp_handle_link_down(slot);
		ubhp_set_slot_power(slot, POWER_OFF);
		ubhp_set_indicators(slot, INDICATOR_OFF, INDICATOR_NOOP);
		slot->state = SLOT_OFF;
		ub_info(slot->uent, "slot%u off\n", slot->slot_id);
		goto out;
	}

	if (!ubhp_card_present(slot))
		goto clear_state;

	ubhp_set_slot_power(slot, POWER_ON);

	/* If support power ctrl, wait link up process */
	if (PWR(slot)) {
		mutex_unlock(&slot->state_lock);
		ubhp_get_slot(slot);
		queue_delayed_work(get_rx_msg_wq(UB_MSG_CODE_LINK),
				   &slot->power_work, HP_LINK_WAIT_DELAY * HZ);
		return;
	}

	if (!slot->r_uent && ubhp_handle_link_up(slot))
		goto poweroff;

	ubhp_set_indicators(slot, INDICATOR_ON, INDICATOR_NOOP);
	slot->state = SLOT_ON;
	ub_info(slot->uent, "slot%u on\n", slot->slot_id);

out:
	/**
	 * why cancel button work here:
	 * 1. for a slot with many ports, it's possible that every port will send
	 *	msg when hotplug event occurred, it's possible some of this msgs
	 *	is handled after present work is triggered, if these msgs are
	 *	handled as usually, may come into error like slot power off
	 *	immediately after power on, so button work is banned during
	 *	handling present work
	 * 2. when the user pressed button repeatedly, some msgs come when
	 *	handling present work, it's reasonable to ignore them
	 *
	 * by holding the state_lock both during button work and present work,
	 *	it's guaranteed that button work and present work can't be handled
	 *	at the same time. So cancel button work before present work ends
	 *	makes sure that button work issued during present work is ignored
	 */
	if (cancel_work(&slot->button_work))
		ubhp_put_slot(slot);
	mutex_unlock(&slot->state_lock);

	ub_info(slot->uent, "slot%u handle hotplug succeeded\n", slot->slot_id);
	return;
poweroff:
	ubhp_set_slot_power(slot, POWER_OFF);
clear_state:
	slot->state = SLOT_OFF;
	ubhp_set_indicators(slot, INDICATOR_OFF, INDICATOR_NOOP);
	ub_info(slot->uent, "slot%u off\n", slot->slot_id);
	mutex_unlock(&slot->state_lock);
	ub_warn(slot->uent, "slot%u handle hotplug failed\n", slot->slot_id);
}

static void ubhp_present_handler(struct work_struct *work)
{
	struct delayed_work *present_work;
	struct ub_slot *slot;

	present_work = to_delayed_work(work);
	slot = container_of(present_work, struct ub_slot, present_work);

	ubhp_handle_present(slot);
	ubhp_put_slot(slot);
}
