// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) HiSilicon Technologies Co., Ltd. 2025. All rights reserved.
 */

#define pr_fmt(fmt)	"ubus port: " fmt

#include <linux/string_choices.h>

#include "ubus.h"
#include "reset.h"
#include "link.h"
#include "port.h"

struct ub_port_attribute {
	struct attribute attr;
	ssize_t (*show)(struct ub_port *port, char *buf);
	ssize_t (*store)(struct ub_port *port, const char *buf, size_t count);
};

#define to_ub_port(o) container_of(o, struct ub_port, kobj)
#define to_ub_port_attr(a) container_of(a, struct ub_port_attribute, attr)

#define UB_PORT_ATTR_RO(field) \
	static struct ub_port_attribute ub_port_attr_##field = __ATTR_RO(field)

#define UB_PORT_ATTR_RW(field) \
	static struct ub_port_attribute ub_port_attr_##field = __ATTR_RW(field)

#define UB_PORT_ATTR_WO(field) \
	static struct ub_port_attribute ub_port_attr_##field = __ATTR_WO(field)

int ub_port_read_byte(struct ub_port *port, u32 pos, u8 *val)
{
	u64 base = UB_PORT_SLICE_START + port->index * UB_PORT_SLICE_SIZE;

	return ub_cfg_read_byte(port->uent, base + pos, val);
}

int ub_port_read_word(struct ub_port *port, u32 pos, u16 *val)
{
	u64 base = UB_PORT_SLICE_START + port->index * UB_PORT_SLICE_SIZE;

	return ub_cfg_read_word(port->uent, base + pos, val);
}

int ub_port_read_dword(struct ub_port *port, u32 pos, u32 *val)
{
	u64 base = UB_PORT_SLICE_START + port->index * UB_PORT_SLICE_SIZE;

	return ub_cfg_read_dword(port->uent, base + pos, val);
}

int ub_port_write_byte(struct ub_port *port, u32 pos, u8 val)
{
	u64 base = UB_PORT_SLICE_START + port->index * UB_PORT_SLICE_SIZE;

	return ub_cfg_write_byte(port->uent, base + pos, val);
}

int ub_port_write_word(struct ub_port *port, u32 pos, u16 val)
{
	u64 base = UB_PORT_SLICE_START + port->index * UB_PORT_SLICE_SIZE;

	return ub_cfg_write_word(port->uent, base + pos, val);
}

int ub_port_write_dword(struct ub_port *port, u32 pos, u32 val)
{
	u64 base = UB_PORT_SLICE_START + port->index * UB_PORT_SLICE_SIZE;

	return ub_cfg_write_dword(port->uent, base + pos, val);
}

static ssize_t cna_show(struct ub_port *port, char *buf)
{
	return sysfs_emit(buf, "%#06x\n", port->cna);
}
UB_PORT_ATTR_RO(cna);

static ssize_t boundary_show(struct ub_port *port, char *buf)
{
	return sysfs_emit(buf, "%#01x\n", port->domain_boundary);
}
UB_PORT_ATTR_RO(boundary);

static ssize_t linkup_show(struct ub_port *port, char *buf)
{
	u8 val;

	if (port->type == VIRTUAL)
		return sysfs_emit(buf, "Virtual port does not have real link status\n");

	if (ub_port_read_byte(port, UB_PORT_PHYSICAL_PORT_LINK_STATUS, &val)) {
		ub_err(port->uent, "get port link cap fail\n");
		return -EIO;
	}

	return sysfs_emit(buf, "%u\n", val & UB_PORT_LINK_STATE);
}
UB_PORT_ATTR_RO(linkup);

static ssize_t neighbor_port_idx_show(struct ub_port *port, char *buf)
{
	if (!port->r_uent)
		return sysfs_emit(buf, "No Neighbor\n");
	return sysfs_emit(buf, "%u\n", port->r_index);
}
UB_PORT_ATTR_RO(neighbor_port_idx);

static ssize_t neighbor_guid_show(struct ub_port *port, char *buf)
{
	struct ub_guid *guid;
	int count;

	if (!port->r_uent && guid_is_null(&port->r_guid))
		return sysfs_emit(buf, "No Neighbor\n");

	guid = port->r_uent ? &port->r_uent->guid :
				    (struct ub_guid *)&port->r_guid;

	count = ub_show_guid(guid, buf);

	return count + sysfs_emit_at(buf, count, "\n");
}
UB_PORT_ATTR_RO(neighbor_guid);

static ssize_t neighbor_show(struct ub_port *port, char *buf)
{
	if (!port->r_uent)
		return sysfs_emit(buf, "No Neighbor\n");

	return sysfs_emit(buf, "%05x\n", port->r_uent->uent_num);
}
UB_PORT_ATTR_RO(neighbor);

static ssize_t asy_link_width_show(struct ub_port *port, char *buf)
{
	u8 val;

	if (ub_port_read_byte(port, PORT_CAP15_QDLWS_CAP, &val)) {
		ub_err(port->uent, "get port cap15 cap fail\n");
		return -EIO;
	}

	if (val & ASY_LINK_WIDTH_MASK)
		return sysfs_emit(buf, "Support\n");
	else
		return sysfs_emit(buf, "Not Support\n");
}
UB_PORT_ATTR_RO(asy_link_width);

static ssize_t port_reset_store(struct ub_port *port, const char *buf,
				size_t count)
{
	unsigned long val;
	int ret;

	ret = kstrtoul(buf, 0, &val);
	if (ret || (val != 1)) {
		ub_err(port->uent, "Invalid val for port reset\n");
		return -EINVAL;
	}

	if (port->uent->ubc->cluster) {
		ub_err(port->uent, "Port reset is not supported by sysfs in cluster mode\n");
		return -EINVAL;
	}

	ret = ub_port_reset_function(port);
	if (ret < 0)
		return ret;

	return count;
}
UB_PORT_ATTR_WO(port_reset);

static ssize_t glb_qdlws_show(struct ub_port *port, char *buf)
{
	u8 val;

	if (ub_port_read_byte(port, PORT_CAP15_QDLWS_CTRL, &val)) {
		ub_err(port->uent, "get global qdlws fail\n");
		return -EIO;
	}

	return sysfs_emit(buf, "%s\n", str_enable_disable(val & GLB_QDLWS_MASK));
}

static ssize_t glb_qdlws_store(struct ub_port *port, const char *buf,
			       size_t count)
{
	unsigned long val;
	int ret;
	u8 cur;

	ret = kstrtoul(buf, 0, &val);
	if (ret || (val != 0 && val != 1)) {
		ub_err(port->uent, "Invalid val for global qdlws\n");
		return -EINVAL;
	}

	if (ub_port_read_byte(port, PORT_CAP15_QDLWS_CTRL, &cur)) {
		ub_err(port->uent, "get global qdlws fail\n");
		return -EIO;
	}

	if (val)
		cur = cur | GLB_QDLWS_ENABLE_MASK;
	else
		cur = cur & GLB_QDLWS_DISABLE_MASK;

	if (ub_port_write_byte(port, PORT_CAP15_QDLWS_CTRL, cur)) {
		ub_err(port->uent, "set global qdlws fail\n");
		return -EIO;
	}

	return count;
}
UB_PORT_ATTR_RW(glb_qdlws);

static ssize_t tx_qdlws_show(struct ub_port *port, char *buf)
{
	u8 val;

	if (ub_port_read_byte(port, PORT_CAP15_QDLWS_CTRL, &val)) {
		ub_err(port->uent, "get TX qdlws fail\n");
		return -EIO;
	}

	return sysfs_emit(buf, "%s\n", str_enable_disable(val & TX_QDLWS_MASK));
}

static ssize_t tx_qdlws_store(struct ub_port *port, const char *buf,
			      size_t count)
{
	unsigned long val;
	int ret;
	u8 cur;

	ret = kstrtoul(buf, 0, &val);
	if (ret || (val != 0 && val != 1)) {
		ub_err(port->uent, "Invalid val for TX qdlws\n");
		return -EINVAL;
	}

	if (ub_port_read_byte(port, PORT_CAP15_QDLWS_CTRL, &cur)) {
		ub_err(port->uent, "get value for TX qdlws fail\n");
		return -EIO;
	}

	if (val)
		cur = cur | TX_QDLWS_ENABLE_MASK;
	else
		cur = cur & TX_QDLWS_DISABLE_MASK;

	if (ub_port_write_byte(port, PORT_CAP15_QDLWS_CTRL, cur)) {
		ub_err(port->uent, "set TX qdlws fail\n");
		return -EIO;
	}

	return count;
}
UB_PORT_ATTR_RW(tx_qdlws);

static ssize_t rx_qdlws_show(struct ub_port *port, char *buf)
{
	u8 val;

	if (ub_port_read_byte(port, PORT_CAP15_QDLWS_CTRL, &val)) {
		ub_err(port->uent, "get RX qdlws fail\n");
		return -EIO;
	}

	return sysfs_emit(buf, "%s\n", str_enable_disable(val & RX_QDLWS_MASK));
}

static ssize_t rx_qdlws_store(struct ub_port *port, const char *buf,
			      size_t count)
{
	unsigned long val;
	int ret;
	u8 cur;

	ret = kstrtoul(buf, 0, &val);
	if (ret || (val != 0 && val != 1)) {
		ub_err(port->uent, "Invalid val for RX qdlws\n");
		return -EINVAL;
	}

	if (ub_port_read_byte(port, PORT_CAP15_QDLWS_CTRL, &cur)) {
		ub_err(port->uent, "get value for RX qdlws fail\n");
		return -EIO;
	}

	if (val)
		cur = cur | RX_QDLWS_ENABLE_MASK;
	else
		cur = cur & RX_QDLWS_DISABLE_MASK;

	if (ub_port_write_byte(port, PORT_CAP15_QDLWS_CTRL, cur)) {
		ub_err(port->uent, "set RX qdlws fail\n");
		return -EIO;
	}

	return count;
}
UB_PORT_ATTR_RW(rx_qdlws);

static const char * const status[] = { "IDLE", "NAK", "In progress", "Timeout",
				"Successful Done" };

static ssize_t qdlws_exec_state_show(struct ub_port *port, char *buf)
{
	u8 val;

	if (ub_port_read_byte(port, PORT_CAP15_QDLWS_STATE, &val)) {
		ub_err(port->uent, "get qdlws exec state fail\n");
		return -EIO;
	}

	val = val & QDLWS_EXEC_STATUS_MASK;
	if (val > QDLWS_EXEC_STATUS_MAX) {
		ub_err(port->uent, "get error state, value[%u]\n", val);
		return sysfs_emit(buf, "Not support state\n");
	}

	return sysfs_emit(buf, "%s\n", status[val]);
}
UB_PORT_ATTR_RO(qdlws_exec_state);

static ssize_t mgmt_state_show(struct ub_port *port, char *buf)
{
	return sysfs_emit(buf, "%d\n", atomic_read(&port->port_mgmt_state));
}
UB_PORT_ATTR_RO(mgmt_state);

static struct attribute *ub_port_default_attrs[] = {
	&ub_port_attr_cna.attr,
	&ub_port_attr_boundary.attr,
	&ub_port_attr_linkup.attr,
	/* neighbor info */
	&ub_port_attr_neighbor_port_idx.attr,
	&ub_port_attr_neighbor_guid.attr,
	&ub_port_attr_neighbor.attr,
	&ub_port_attr_port_reset.attr,
	&ub_port_attr_mgmt_state.attr,
	NULL
};

static const struct attribute_group ub_port_default_group = {
	.attrs = ub_port_default_attrs,
};

static struct attribute *ub_port_qdlws_attrs[] = {
	&ub_port_attr_asy_link_width.attr,
	&ub_port_attr_glb_qdlws.attr,
	&ub_port_attr_tx_qdlws.attr,
	&ub_port_attr_rx_qdlws.attr,
	&ub_port_attr_qdlws_exec_state.attr,
	NULL
};

static umode_t ub_port_qdlws_is_visible(struct kobject *kobj,
					struct attribute *a, int n)
{
	struct ub_port *port = to_ub_port(kobj);
	struct ub_entity *uent = port->uent;

	if (port->type == VIRTUAL)
		return 0;

	if (is_ibus_controller(uent) && uent->ubc->cluster)
		return 0;

	if (test_bit(UB_PORT_CAP15_QDLWS, port->cap_map))
		return a->mode;

	return 0;
}

static const struct attribute_group ub_port_qdlws_group = {
	.is_visible = ub_port_qdlws_is_visible,
	.attrs = ub_port_qdlws_attrs,
};

static const struct attribute_group *ub_port_groups[] = {
	&ub_port_default_group,
	&ub_port_qdlws_group,
	NULL
};

static ssize_t ub_port_attr_show(struct kobject *kobj, struct attribute *attr,
				 char *buf)
{
	struct ub_port_attribute *attribute = to_ub_port_attr(attr);
	struct ub_port *port = to_ub_port(kobj);

	if (!attribute->show)
		return -EIO;

	return attribute->show(port, buf);
}

static ssize_t ub_port_attr_store(struct kobject *kobj, struct attribute *attr,
				  const char *buf, size_t count)
{
	struct ub_port_attribute *attribute = to_ub_port_attr(attr);
	struct ub_port *port = to_ub_port(kobj);

	if (!attribute->store)
		return -EIO;

	return attribute->store(port, buf, count);
}

static const struct sysfs_ops ub_port_sysfs_ops = {
	.show = ub_port_attr_show,
	.store = ub_port_attr_store,
};

static const struct kobj_type ub_port_ktype = {
	.sysfs_ops = &ub_port_sysfs_ops,
	.default_groups = ub_port_groups,
};

void ub_port_disconnect(struct ub_port *port)
{
	struct ub_port *r_port;

	if (!port || !port->r_uent)
		return;

	r_port = port->r_uent->ports + port->r_index;
	r_port->r_uent = NULL;
	r_port->r_guid = guid_null;

	port->r_uent = NULL;
	port->r_guid = guid_null;
}

/* connect two ports, caller should make sure that the ports match */
void ub_port_connect(struct ub_port *port, struct ub_port *r_port)
{
	if (!port || !r_port)
		return;

	port->r_index = r_port->index;
	port->r_uent = r_port->uent;
	r_port->r_index = port->index;
	r_port->r_uent = port->uent;
}

bool ub_check_and_connect(struct ub_port *port, struct ub_entity *r_uent)
{
	struct ub_port *r_port;

	if (!port || !r_uent)
		return false;

	if (port->r_index >= r_uent->port_nums) {
		pr_err("port%u should connect to port%u, but remote device has only %u ports\n",
		       port->index, port->r_index, r_uent->port_nums);
		return false;
	}

	r_port = r_uent->ports + port->r_index;

	if (r_port->r_uent) {
		pr_err("port%u should connect to port%u, which is already connected\n",
		       port->index, port->r_index);
		return false;
	}

	ub_port_connect(port, r_port);

	return true;
}

static int ub_port_config(struct ub_port *port)
{
	u32 map[UB_PORT_CAP_NUM / SZ_32];
	int ret, i;

	/* virtual port doesn't have bitmap */
	if (port->type == VIRTUAL)
		return 0;

	for (i = 0; i < UB_PORT_CAP_NUM / SZ_32; i++) {
		ret = ub_port_read_dword(
			port, UB_CFG0_PORT_BITMAP + i * sizeof(u32), &map[i]);
		if (ret) {
			ub_err(port->uent,
			       "failed to read port%u bitmap %d with %d\n",
			       port->index, i, ret);
			return ret;
		}
	}

	memcpy((void *)port->cap_map, (void *)map, sizeof(map));
	return 0;
}

int ub_ports_add(struct ub_entity *uent)
{
	struct ub_port *port;
	int ret;

	if (!uent)
		return -EINVAL;

	for_each_uent_port(port, uent) {
		ret = ub_port_config(port);
		if (ret) {
			ub_err(uent,
			       "config port%u failed, stop adding ports\n",
			       port->index);
			return ret;
		}

		ret = kobject_add(&port->kobj, &uent->dev.kobj, "port%u",
				  port->index);
		if (ret) {
			ub_warn(uent, "cannot add port%u, stop adding ports\n",
				port->index);
			return ret;
		}
	}

	return 0;
}

void ub_ports_del(struct ub_entity *uent)
{
	struct ub_port *port;

	if (!uent)
		return;

	for_each_uent_port(port, uent)
		kobject_put(&port->kobj);
}

static int ub_port_init(struct ub_entity *uent, struct ub_port *port)
{
	port->uent = uent;
	port->type = PHYSICAL;
	port->cna = 0;
	port->r_uent = NULL;
	port->link_state = LINK_STATE_NORMAL;
	port->r_index = 0;
	port->r_guid = guid_null;
	bitmap_zero(port->cna_maps, UB_MAX_CNA_NUM);
	bitmap_zero(port->cap_map, UB_PORT_CAP_NUM);
	kobject_init(&port->kobj, &ub_port_ktype);
	port->port_lock = kzalloc(sizeof(struct mutex), GFP_KERNEL);
	if (!port->port_lock)
		return -ENOMEM;
	mutex_init(port->port_lock);

	return 0;
}

int ub_ports_setup(struct ub_entity *uent)
{
	struct ub_port *port;

	if (!uent || !uent->port_nums)
		return -EINVAL;

	if (uent->ports)
		return 0;

	uent->ports = kvcalloc(uent->port_nums, sizeof(*port), GFP_KERNEL);
	if (!uent->ports)
		return -ENOMEM;

	for_each_uent_port(port, uent) {
		port->index = port - uent->ports;
		if (ub_port_init(uent, port))
			goto err_free;
	}

	return 0;

err_free:
	for_each_uent_port(port, uent)
		kfree(port->port_lock);
	kvfree(uent->ports);
	uent->ports = NULL;
	return -ENOMEM;
}

void ub_ports_unset(struct ub_entity *uent)
{
	struct ub_port *port;

	if (!uent)
		return;

	for_each_uent_port(port, uent)
		kfree(port->port_lock);

	kvfree(uent->ports);
	uent->ports = NULL;
	pr_debug("port release\n");
}

static LIST_HEAD(ub_share_port_notify_list);
static DECLARE_RWSEM(ub_share_port_notify_list_rwsem);

struct ub_share_port_notify_node {
	struct ub_entity *parent;
	struct ub_entity *entity;
	u16 port_id;
	struct ub_share_port_ops *ops;
	struct list_head node;
};

int ub_register_share_port(struct ub_entity *entity, u16 port_id,
			   struct ub_share_port_ops *ops)
{
	struct ub_share_port_notify_node *notify_node;
	struct ub_entity *parent;
	struct ub_port *port;

	if (unlikely(!entity || !ops))
		return -EINVAL;

	if (!is_idev(entity) && !is_ibus_controller(entity)) {
		ub_err(entity,
		       "does not support device with type %u register share port\n",
		       uent_type(entity));
		return -EINVAL;
	}

	/* get primary entity first */
	parent = entity;
	if (is_idev(parent)) {
		while (!is_primary(parent))
			parent = parent->pue;

		/* check parent is controller */
		parent = to_ub_entity(parent->dev.parent);
		if (!is_ibus_controller(parent)) {
			ub_err(entity, "does not support register share port at non-controller device with type %u\n",
			       uent_type(parent));
			return -EINVAL;
		}
	}

	if (port_id >= parent->port_nums) {
		ub_err(parent, "port id %u exceeds port num %u\n", port_id,
		       parent->port_nums);
		return -EINVAL;
	}

	port = parent->ports + port_id;
	if (is_idev(entity) && !port->shareable) {
		ub_err(parent, "port%u isn't shareable\n", port_id);
		return -EINVAL;
	}

	notify_node = kzalloc(sizeof(*notify_node), GFP_KERNEL);
	if (!notify_node)
		return -ENOMEM;

	notify_node->parent = parent;
	notify_node->entity = entity;
	notify_node->port_id = port_id;
	notify_node->ops = ops;
	INIT_LIST_HEAD(&notify_node->node);

	down_write(&ub_share_port_notify_list_rwsem);
	list_add_tail(&notify_node->node, &ub_share_port_notify_list);
	up_write(&ub_share_port_notify_list_rwsem);

	ub_info(entity, "register share port at %u success\n", port_id);
	return 0;
}
EXPORT_SYMBOL_GPL(ub_register_share_port);

void ub_unregister_share_port(struct ub_entity *entity, u16 port_id,
			      struct ub_share_port_ops *ops)
{
	struct ub_share_port_notify_node *notify_node;

	if (unlikely(!entity))
		return;

	down_write(&ub_share_port_notify_list_rwsem);

	list_for_each_entry(notify_node, &ub_share_port_notify_list, node) {
		if (notify_node->entity != entity ||
		    notify_node->port_id != port_id || notify_node->ops != ops)
			continue;

		list_del(&notify_node->node);
		kfree(notify_node);
		ub_info(entity, "unregister share port at %u success\n", port_id);
		goto unlock;
	}

	ub_err(entity, "share port %u isn't registered, unregister failed\n",
	       port_id);
unlock:
	up_write(&ub_share_port_notify_list_rwsem);
}
EXPORT_SYMBOL_GPL(ub_unregister_share_port);

void ub_notify_share_port(struct ub_port *port,
			  enum ub_port_event type)
{
	struct ub_share_port_notify_node *notify_node;
	struct ub_share_port_ops *ops;
	struct ub_entity *uent;

	if (!port || type > UB_PORT_EVENT_RESET_FAILED)
		return;

	uent = port->uent;
	down_read(&ub_share_port_notify_list_rwsem);
	list_for_each_entry(notify_node, &ub_share_port_notify_list, node) {
		if (notify_node->parent != uent ||
		    notify_node->port_id != port->index)
			continue;

		ops = notify_node->ops;
		if (ops->event_notify)
			ops->event_notify(notify_node->entity,
					  notify_node->port_id, type);
	}
	up_read(&ub_share_port_notify_list_rwsem);
}
EXPORT_SYMBOL_GPL(ub_notify_share_port);

bool ub_port_check_link_up(struct ub_port *port)
{
	u8 val;

	if (!port)
		return false;

	if (ub_port_read_byte(port, UB_PORT_PHYSICAL_PORT_LINK_STATUS, &val))
		return false;

	return !!(val & UB_PORT_LINK_STATE);
}
