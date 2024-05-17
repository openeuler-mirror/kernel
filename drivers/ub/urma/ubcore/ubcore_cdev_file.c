// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
 * for more details.
 *
 * Description: ubcore cdev file
 * Author: Qian Guoxin
 * Create: 2024-02-05
 * Note:
 * History: 2024-02-05: Create file
 */

#include <linux/fs.h>
#include <linux/inet.h>
#include <linux/version.h>

#include "urma/ubcore_types.h"
#include "urma/ubcore_uapi.h"

#include "ubcore_log.h"
#include "ubcore_cdev_file.h"

#define UBCORE_MAX_VALUE_LEN 24

/* callback information */
typedef ssize_t (*ubcore_show_attr_cb)(struct ubcore_device *dev,
	char *buf);
typedef ssize_t (*ubcore_store_attr_cb)(struct ubcore_device *dev,
	const char *buf, size_t len);
typedef ssize_t (*ubcore_show_port_attr_cb)(struct ubcore_device *dev,
	char *buf, uint8_t port_id);

static inline struct ubcore_device *get_ubcore_device(struct ubcore_logic_device *ldev)
{
	return ldev == NULL ? NULL : ldev->ub_dev;
}

static ssize_t ubcore_show_dev_attr(struct device *dev, struct device_attribute *attr,
	char *buf, ubcore_show_attr_cb show_cb)
{
	struct ubcore_logic_device *ldev = dev_get_drvdata(dev);
	struct ubcore_device *ub_dev = get_ubcore_device(ldev);

	if (!ldev || !ub_dev || !buf) {
		ubcore_log_err("Invalid argument.\n");
		return -EINVAL;
	}

	return show_cb(ub_dev, buf);
}

static ssize_t ubcore_store_dev_attr(struct device *dev, struct device_attribute *attr,
				     const char *buf, size_t len, ubcore_store_attr_cb store_cb)
{
	struct ubcore_logic_device *ldev = dev_get_drvdata(dev);
	struct ubcore_device *ub_dev = get_ubcore_device(ldev);

	if (!ldev || !ub_dev || !buf) {
		ubcore_log_err("Invalid argument.\n");
		return -EINVAL;
	}

	return store_cb(ub_dev, buf, len);
}

/* interface for exporting device attributes */
static ssize_t ubdev_show_cb(struct ubcore_device *dev, char *buf)
{
	return snprintf(buf, UBCORE_MAX_DEV_NAME, "%s\n", dev->dev_name);
}

static ssize_t ubdev_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	return ubcore_show_dev_attr(dev, attr, buf, ubdev_show_cb);
}

static DEVICE_ATTR_RO(ubdev);

static ssize_t guid_show_cb(struct ubcore_device *dev, char *buf)
{
	return snprintf(buf, (UBCORE_EID_STR_LEN + 1) + 1, EID_FMT"\n",
		EID_ARGS(dev->attr.guid));      // The format of  GUID is the same as EID.
}

static ssize_t guid_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	return ubcore_show_dev_attr(dev, attr, buf, guid_show_cb);
}

static DEVICE_ATTR_RO(guid);

static ssize_t max_upi_cnt_show_cb(struct ubcore_device *dev, char *buf)
{
	return snprintf(buf, UBCORE_MAX_VALUE_LEN, "%u\n", dev->attr.dev_cap.max_upi_cnt);
}

static ssize_t max_upi_cnt_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	return ubcore_show_dev_attr(dev, attr, buf, max_upi_cnt_show_cb);
}

static DEVICE_ATTR_RO(max_upi_cnt);


static ssize_t feature_show_cb(struct ubcore_device *dev, char *buf)
{
	return snprintf(buf, UBCORE_MAX_VALUE_LEN, "0x%x\n", dev->attr.dev_cap.feature.value);
}

static ssize_t feature_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	return ubcore_show_dev_attr(dev, attr, buf, feature_show_cb);
}

static DEVICE_ATTR_RO(feature);

static ssize_t max_jfc_show_cb(struct ubcore_device *dev, char *buf)
{
	return snprintf(buf, UBCORE_MAX_VALUE_LEN, "%u\n", dev->attr.dev_cap.max_jfc);
}

static ssize_t max_jfc_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	return ubcore_show_dev_attr(dev, attr, buf, max_jfc_show_cb);
}

static DEVICE_ATTR_RO(max_jfc);

static ssize_t max_jfs_show_cb(struct ubcore_device *dev, char *buf)
{
	return snprintf(buf, UBCORE_MAX_VALUE_LEN, "%u\n", dev->attr.dev_cap.max_jfs);
}

static ssize_t max_jfs_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	return ubcore_show_dev_attr(dev, attr, buf, max_jfs_show_cb);
}

static DEVICE_ATTR_RO(max_jfs);

static ssize_t max_jfr_show_cb(struct ubcore_device *dev, char *buf)
{
	return snprintf(buf, UBCORE_MAX_VALUE_LEN, "%u\n", dev->attr.dev_cap.max_jfr);
}

static ssize_t max_jfr_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	return ubcore_show_dev_attr(dev, attr, buf, max_jfr_show_cb);
}

static DEVICE_ATTR_RO(max_jfr);

static ssize_t max_jetty_show_cb(struct ubcore_device *dev, char *buf)
{
	return snprintf(buf, UBCORE_MAX_VALUE_LEN, "%u\n", dev->attr.dev_cap.max_jetty);
}

static ssize_t max_jetty_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	return ubcore_show_dev_attr(dev, attr, buf, max_jetty_show_cb);
}

static DEVICE_ATTR_RO(max_jetty);

static ssize_t show_max_jetty_grp_cb(struct ubcore_device *dev, char *buf)
{
	return snprintf(buf, UBCORE_MAX_VALUE_LEN, "%u\n", dev->attr.dev_cap.max_jetty_grp);
}
static ssize_t max_jetty_grp_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	return ubcore_show_dev_attr(dev, attr, buf, show_max_jetty_grp_cb);
}
static DEVICE_ATTR_RO(max_jetty_grp);

static ssize_t show_max_jetty_in_jetty_grp_cb(struct ubcore_device *dev, char *buf)
{
	return snprintf(
		buf, UBCORE_MAX_VALUE_LEN, "%u\n", dev->attr.dev_cap.max_jetty_in_jetty_grp);
}
static ssize_t max_jetty_in_jetty_grp_show(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	return ubcore_show_dev_attr(dev, attr, buf, show_max_jetty_in_jetty_grp_cb);
}
static DEVICE_ATTR_RO(max_jetty_in_jetty_grp);

static ssize_t max_jfc_depth_show_cb(struct ubcore_device *dev, char *buf)
{
	return snprintf(buf, UBCORE_MAX_VALUE_LEN, "%u\n", dev->attr.dev_cap.max_jfc_depth);
}

static ssize_t max_jfc_depth_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	return ubcore_show_dev_attr(dev, attr, buf, max_jfc_depth_show_cb);
}

static DEVICE_ATTR_RO(max_jfc_depth);

static ssize_t max_jfs_depth_show_cb(struct ubcore_device *dev, char *buf)
{
	return snprintf(buf, UBCORE_MAX_VALUE_LEN, "%u\n", dev->attr.dev_cap.max_jfs_depth);
}

static ssize_t max_jfs_depth_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	return ubcore_show_dev_attr(dev, attr, buf, max_jfs_depth_show_cb);
}

static DEVICE_ATTR_RO(max_jfs_depth);

static ssize_t max_jfr_depth_show_cb(struct ubcore_device *dev, char *buf)
{
	return snprintf(buf, UBCORE_MAX_VALUE_LEN, "%u\n", dev->attr.dev_cap.max_jfr_depth);
}

static ssize_t max_jfr_depth_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	return ubcore_show_dev_attr(dev, attr, buf, max_jfr_depth_show_cb);
}

static DEVICE_ATTR_RO(max_jfr_depth);

static ssize_t show_max_jfs_inline_size_cb(struct ubcore_device *dev, char *buf)
{
	return snprintf(buf, UBCORE_MAX_VALUE_LEN, "%u\n", dev->attr.dev_cap.max_jfs_inline_size);
}

static ssize_t max_jfs_inline_size_show(struct device *dev, struct device_attribute *attr,
					char *buf)
{
	return ubcore_show_dev_attr(dev, attr, buf, show_max_jfs_inline_size_cb);
}

static DEVICE_ATTR_RO(max_jfs_inline_size);

static ssize_t max_jfs_sge_show_cb(struct ubcore_device *dev, char *buf)
{
	return snprintf(buf, UBCORE_MAX_VALUE_LEN, "%u\n", dev->attr.dev_cap.max_jfs_sge);
}

static ssize_t max_jfs_sge_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	return ubcore_show_dev_attr(dev, attr, buf, max_jfs_sge_show_cb);
}

static DEVICE_ATTR_RO(max_jfs_sge);

static ssize_t max_jfs_rsge_show_cb(struct ubcore_device *dev, char *buf)
{
	return snprintf(buf, UBCORE_MAX_VALUE_LEN, "%u\n", dev->attr.dev_cap.max_jfs_rsge);
}

static ssize_t max_jfs_rsge_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	return ubcore_show_dev_attr(dev, attr, buf, max_jfs_rsge_show_cb);
}

static DEVICE_ATTR_RO(max_jfs_rsge);

static ssize_t max_jfr_sge_show_cb(struct ubcore_device *dev, char *buf)
{
	return snprintf(buf, UBCORE_MAX_VALUE_LEN, "%u\n", dev->attr.dev_cap.max_jfr_sge);
}

static ssize_t max_jfr_sge_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	return ubcore_show_dev_attr(dev, attr, buf, max_jfr_sge_show_cb);
}

static DEVICE_ATTR_RO(max_jfr_sge);

static ssize_t max_msg_size_show_cb(struct ubcore_device *dev, char *buf)
{
	return snprintf(buf, UBCORE_MAX_VALUE_LEN, "%llu\n", dev->attr.dev_cap.max_msg_size);
}

static ssize_t max_msg_size_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	return ubcore_show_dev_attr(dev, attr, buf, max_msg_size_show_cb);
}

static DEVICE_ATTR_RO(max_msg_size);

static ssize_t show_max_atomic_size_cb(struct ubcore_device *dev, char *buf)
{
	return snprintf(buf, UBCORE_MAX_VALUE_LEN, "%u\n", dev->attr.dev_cap.max_atomic_size);
}
static ssize_t max_atomic_size_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	return ubcore_show_dev_attr(dev, attr, buf, show_max_atomic_size_cb);
}
static DEVICE_ATTR_RO(max_atomic_size);

static ssize_t show_atomic_feat_cb(struct ubcore_device *dev, char *buf)
{
	return snprintf(buf, UBCORE_MAX_VALUE_LEN, "%u\n", dev->attr.dev_cap.atomic_feat.value);
}
static ssize_t atomic_feat_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	return ubcore_show_dev_attr(dev, attr, buf, show_atomic_feat_cb);
}
static DEVICE_ATTR_RO(atomic_feat);

static ssize_t max_rc_outstd_cnt_show_cb(struct ubcore_device *dev, char *buf)
{
	return snprintf(buf, UBCORE_MAX_VALUE_LEN, "%llu\n", dev->attr.dev_cap.max_rc_outstd_cnt);
}

static ssize_t max_rc_outstd_cnt_show(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	return ubcore_show_dev_attr(dev, attr, buf, max_rc_outstd_cnt_show_cb);
}

static DEVICE_ATTR_RO(max_rc_outstd_cnt);

static ssize_t trans_mode_show_cb(struct ubcore_device *dev, char *buf)
{
	return snprintf(buf, UBCORE_MAX_VALUE_LEN, "%u\n", dev->attr.dev_cap.trans_mode);
}

static ssize_t trans_mode_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	return ubcore_show_dev_attr(dev, attr, buf, trans_mode_show_cb);
}

static DEVICE_ATTR_RO(trans_mode);

static ssize_t congestion_ctrl_alg_show_cb(struct ubcore_device *dev, char *buf)
{
	return snprintf(buf, UBCORE_MAX_VALUE_LEN, "%u\n", dev->attr.dev_cap.congestion_ctrl_alg);
}

static ssize_t congestion_ctrl_alg_show(struct device *dev, struct device_attribute *attr,
					char *buf)
{
	return ubcore_show_dev_attr(dev, attr, buf, congestion_ctrl_alg_show_cb);
}

static ssize_t congestion_ctrl_alg_store_cb(struct ubcore_device *dev, const char *buf,
					    size_t len)
{
	uint16_t value;
	int ret;

	ret = kstrtou16(buf, 0, &value);
	if (ret != 0)
		return -EINVAL;

	dev->attr.dev_cap.congestion_ctrl_alg = value;
	return (ssize_t)len;
}

static ssize_t congestion_ctrl_alg_store(struct device *dev, struct device_attribute *attr,
					 const char *buf, size_t len)
{
	return ubcore_store_dev_attr(dev, attr, buf, len, congestion_ctrl_alg_store_cb);
}

static DEVICE_ATTR_RW(congestion_ctrl_alg); // 0644

static ssize_t ceq_cnt_show_cb(struct ubcore_device *dev, char *buf)
{
	return snprintf(buf, UBCORE_MAX_VALUE_LEN, "%u\n", dev->attr.dev_cap.ceq_cnt);
}

static ssize_t ceq_cnt_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	return ubcore_show_dev_attr(dev, attr, buf, ceq_cnt_show_cb);
}

static DEVICE_ATTR_RO(ceq_cnt);

static ssize_t utp_cnt_show_cb(struct ubcore_device *dev, char *buf)
{
	return snprintf(buf, UBCORE_MAX_VALUE_LEN, "%u\n",
		dev->attr.dev_cap.max_utp_cnt);
}

static ssize_t utp_cnt_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	return ubcore_show_dev_attr(dev, attr, buf, utp_cnt_show_cb);
}

static DEVICE_ATTR_RO(utp_cnt);

static ssize_t max_tp_in_tpg_show_cb(struct ubcore_device *dev, char *buf)
{
	return snprintf(buf, UBCORE_MAX_VALUE_LEN, "%u\n", dev->attr.dev_cap.max_tp_in_tpg);
}

static ssize_t max_tp_in_tpg_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	return ubcore_show_dev_attr(dev, attr, buf, max_tp_in_tpg_show_cb);
}

static DEVICE_ATTR_RO(max_tp_in_tpg);

static ssize_t port_count_show_cb(struct ubcore_device *dev, char *buf)
{
	return snprintf(buf, UBCORE_MAX_VALUE_LEN, "%u\n", dev->attr.port_cnt);
}

static ssize_t port_count_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	return ubcore_show_dev_attr(dev, attr, buf, port_count_show_cb);
}

static DEVICE_ATTR_RO(port_count);

static ssize_t virtualization_show_cb(struct ubcore_device *dev, char *buf)
{
	return snprintf(
		buf, UBCORE_MAX_VALUE_LEN, "%s\n", dev->attr.virtualization ? "true" : "false");
}
static ssize_t virtualization_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	return ubcore_show_dev_attr(dev, attr, buf, virtualization_show_cb);
}
static DEVICE_ATTR_RO(virtualization);

static ssize_t show_fe_cnt_cb(struct ubcore_device *dev, char *buf)
{
	return snprintf(buf, UBCORE_MAX_VALUE_LEN, "%u\n", dev->attr.dev_cap.max_fe_cnt);
}
static ssize_t fe_cnt_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	return ubcore_show_dev_attr(dev, attr, buf, show_fe_cnt_cb);
}
static DEVICE_ATTR_RO(fe_cnt);

static ssize_t show_dynamic_eid_cb(struct ubcore_device *dev, char *buf)
{
	return snprintf(buf, UBCORE_MAX_VALUE_LEN, "%d\n", dev->dynamic_eid);
}
static ssize_t dynamic_eid_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	return ubcore_show_dev_attr(dev, attr, buf, show_dynamic_eid_cb);
}
static DEVICE_ATTR_RO(dynamic_eid);

static ssize_t max_eid_cnt_show_cb(struct ubcore_device *dev, char *buf)
{
	return snprintf(buf, UBCORE_MAX_VALUE_LEN, "%u\n", dev->attr.dev_cap.max_eid_cnt);
}

static ssize_t max_eid_cnt_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	return ubcore_show_dev_attr(dev, attr, buf, max_eid_cnt_show_cb);
}

static DEVICE_ATTR_RO(max_eid_cnt);

static ssize_t transport_type_show_cb(struct ubcore_device *dev, char *buf)
{
	return snprintf(buf, UBCORE_MAX_VALUE_LEN, "%d\n", (int)dev->transport_type);
}

static ssize_t transport_type_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	return ubcore_show_dev_attr(dev, attr, buf, transport_type_show_cb);
}

static DEVICE_ATTR_RO(transport_type);

static ssize_t driver_name_show_cb(struct ubcore_device *dev, char *buf)
{
	if (dev->ops == NULL)
		return -EINVAL;

	return snprintf(buf, UBCORE_MAX_DRIVER_NAME, "%s\n", dev->ops->driver_name);
}

static ssize_t driver_name_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	return ubcore_show_dev_attr(dev, attr, buf, driver_name_show_cb);
}

static DEVICE_ATTR_RO(driver_name);

/* One eid line has upto 51 bytes with the format:
 * "4294967295 0000:0000:0000:0000:0000:ffff:7f00:0001\n"
 * sysfs buf size is PAGESIZE, upto 80 eid lines are supported in the sysfs
 */
#define UBCORE_MAX_EID_LINE 51

static ssize_t eid_show_cb(struct ubcore_device *dev, char *buf, struct net *net)
{
	struct ubcore_eid_entry *e;
	ssize_t len = 0;
	uint32_t i;

	if (dev->eid_table.eid_entries == NULL)
		return -EINVAL;

	spin_lock(&dev->eid_table.lock);
	for (i = 0; i < dev->eid_table.eid_cnt; i++) {
		e = &dev->eid_table.eid_entries[i];
		if (!e->valid || !net_eq(e->net, net))
			continue;
		len += snprintf(buf + len, UBCORE_MAX_EID_LINE,
			"%u "EID_FMT"\n", i, EID_ARGS(e->eid));
		if (len >= (ssize_t)(PAGE_SIZE - UBCORE_MAX_EID_LINE))
			break;
	}
	spin_unlock(&dev->eid_table.lock);
	return len;
}

static ssize_t eid_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct ubcore_logic_device *ldev = dev_get_drvdata(dev);
	struct ubcore_device *ub_dev = get_ubcore_device(ldev);

	if (!ldev || !ub_dev || !buf) {
		ubcore_log_err("Invalid argument.\n");
		return -EINVAL;
	}

	return eid_show_cb(ub_dev, buf, read_pnet(&ldev->net));
}
static DEVICE_ATTR_RO(eid);


static struct attribute *ubcore_dev_attrs[] = {
	&dev_attr_ubdev.attr,
	&dev_attr_guid.attr,
	&dev_attr_max_upi_cnt.attr,
	&dev_attr_feature.attr,
	&dev_attr_max_jfc.attr,
	&dev_attr_max_jfs.attr,
	&dev_attr_max_jfr.attr,
	&dev_attr_max_jetty.attr,
	&dev_attr_max_jetty_grp.attr,
	&dev_attr_max_jetty_in_jetty_grp.attr,
	&dev_attr_max_jfc_depth.attr,
	&dev_attr_max_jfs_depth.attr,
	&dev_attr_max_jfr_depth.attr,
	&dev_attr_max_jfs_inline_size.attr,
	&dev_attr_max_jfs_sge.attr,
	&dev_attr_max_jfs_rsge.attr,
	&dev_attr_max_jfr_sge.attr,
	&dev_attr_max_msg_size.attr,
	&dev_attr_max_atomic_size.attr,
	&dev_attr_atomic_feat.attr,
	&dev_attr_max_rc_outstd_cnt.attr,
	&dev_attr_trans_mode.attr,
	&dev_attr_congestion_ctrl_alg.attr,
	&dev_attr_ceq_cnt.attr,
	&dev_attr_utp_cnt.attr,
	&dev_attr_max_tp_in_tpg.attr,
	&dev_attr_port_count.attr,
	&dev_attr_fe_cnt.attr,
	&dev_attr_max_eid_cnt.attr,
	&dev_attr_dynamic_eid.attr,
	&dev_attr_virtualization.attr,
	&dev_attr_transport_type.attr,
	&dev_attr_driver_name.attr,
	&dev_attr_eid.attr,
	NULL,
};

static const struct attribute_group ubcore_dev_attr_group = {
	.attrs = ubcore_dev_attrs,
};

static ssize_t ubcore_show_port_attr(
	struct ubcore_port_kobj *p, struct ubcore_port_attribute *attr,
	char *buf, ubcore_show_port_attr_cb show_cb)
{
	struct ubcore_device *dev = p->dev;

	if (!dev || !buf) {
		ubcore_log_err("Invalid argument.\n");
		return -EINVAL;
	}

	return show_cb(dev, buf, p->port_id);
}

static ssize_t max_mtu_show_cb(struct ubcore_device *dev, char *buf, uint8_t port_id)
{
	return snprintf(
		buf, UBCORE_MAX_VALUE_LEN, "%d\n", (int)dev->attr.port_attr[port_id].max_mtu);
}

static ssize_t max_mtu_show(struct ubcore_port_kobj *p,
	struct ubcore_port_attribute *attr, char *buf)
{
	return ubcore_show_port_attr(p, attr, buf, max_mtu_show_cb);
}

static PORT_ATTR_RO(max_mtu);

static ssize_t state_show_cb(struct ubcore_device *dev, char *buf, uint8_t port_id)
{
	struct ubcore_device_status status;

	if (ubcore_query_device_status(dev, &status) != 0) {
		ubcore_log_err("query device status for state failed.\n");
		return -EPERM;
	}

	return snprintf(
		buf, UBCORE_MAX_VALUE_LEN, "%u\n", (uint32_t)status.port_status[port_id].state);
}

static ssize_t state_show(
	struct ubcore_port_kobj *p, struct ubcore_port_attribute *attr, char *buf)
{
	return ubcore_show_port_attr(p, attr, buf, state_show_cb);
}

static PORT_ATTR_RO(state);

static ssize_t active_speed_show_cb(struct ubcore_device *dev, char *buf,
				    uint8_t port_id)
{
	struct ubcore_device_status status;

	if (ubcore_query_device_status(dev, &status) != 0) {
		ubcore_log_err("query device status for active speed failed.\n");
		return -EPERM;
	}

	return snprintf(
		buf, UBCORE_MAX_VALUE_LEN, "%u\n", status.port_status[port_id].active_speed);
}

static ssize_t active_speed_show(struct ubcore_port_kobj *p, struct ubcore_port_attribute *attr,
				 char *buf)
{
	return ubcore_show_port_attr(p, attr, buf, active_speed_show_cb);
}

static PORT_ATTR_RO(active_speed);

static ssize_t active_width_show_cb(struct ubcore_device *dev, char *buf,
				    uint8_t port_id)
{
	struct ubcore_device_status status;

	if (ubcore_query_device_status(dev, &status) != 0) {
		ubcore_log_err("query device status for active width failed.\n");
		return -EPERM;
	}

	return snprintf(
		buf, UBCORE_MAX_VALUE_LEN, "%u\n", status.port_status[port_id].active_width);
}

static ssize_t active_width_show(struct ubcore_port_kobj *p, struct ubcore_port_attribute *attr,
				 char *buf)
{
	return ubcore_show_port_attr(p, attr, buf, active_width_show_cb);
}

static PORT_ATTR_RO(active_width);

static ssize_t active_mtu_show_cb(struct ubcore_device *dev, char *buf, uint8_t port_id)
{
	struct ubcore_device_status status;

	if (ubcore_query_device_status(dev, &status) != 0) {
		ubcore_log_err("query device status for active mtu failed.\n");
		return -EPERM;
	}

	return snprintf(buf, UBCORE_MAX_VALUE_LEN, "%u\n",
		(uint32_t)status.port_status[port_id].active_mtu);
}

static ssize_t active_mtu_show(struct ubcore_port_kobj *p, struct ubcore_port_attribute *attr,
	char *buf)
{
	return ubcore_show_port_attr(p, attr, buf, active_mtu_show_cb);
}

static PORT_ATTR_RO(active_mtu);

static struct attribute *ubcore_port_attrs[] = {
	&port_attr_max_mtu.attr,      &port_attr_state.attr,	  &port_attr_active_speed.attr,
	&port_attr_active_width.attr, &port_attr_active_mtu.attr, NULL,
};

static ssize_t ubcore_port_attr_show(struct kobject *kobj, struct attribute *attr, char *buf)
{
	struct ubcore_port_attribute *port_attr =
		container_of(attr, struct ubcore_port_attribute, attr);
	struct ubcore_port_kobj *p = container_of(kobj, struct ubcore_port_kobj, kobj);

	if (!port_attr->show)
		return -EIO;

	return port_attr->show(p, port_attr, buf);
}

static ssize_t ubcore_port_attr_store(struct kobject *kobj, struct attribute *attr,
	const char *buf, size_t count)
{
	struct ubcore_port_attribute *port_attr =
		container_of(attr, struct ubcore_port_attribute, attr);
	struct ubcore_port_kobj *p = container_of(kobj, struct ubcore_port_kobj, kobj);

	if (!port_attr->store)
		return -EIO;

	return port_attr->store(p, port_attr, buf, count);
}

static const struct sysfs_ops ubcore_port_sysfs_ops = { .show = ubcore_port_attr_show,
							.store = ubcore_port_attr_store };

static void ubcore_port_release(struct kobject *kobj)
{
}

// ATTRIBUTE_GROUPS defined in 3.11, but must be consistent with kobj_type->default_groups
ATTRIBUTE_GROUPS(ubcore_port);

static struct kobj_type ubcore_port_type = { .release = ubcore_port_release,
					     .sysfs_ops = &ubcore_port_sysfs_ops,
					     .default_groups = ubcore_port_groups
};

int ubcore_create_port_attr_files(struct ubcore_logic_device *ldev,
	struct ubcore_device *dev, uint8_t port_id)
{
	struct ubcore_port_kobj *p;

	p = &ldev->port[port_id];
	p->dev = dev;
	p->port_id = port_id;

	return kobject_init_and_add(&p->kobj, &ubcore_port_type, &ldev->dev->kobj,
		"port%hhu", port_id);
}


int ubcore_create_dev_attr_files(struct ubcore_logic_device *ldev)
{
	int ret;

	ret = sysfs_create_group(&ldev->dev->kobj, &ubcore_dev_attr_group);
	if (ret != 0) {
		ubcore_log_err("sysfs create group failed, ret:%d.\n", ret);
		return -1;
	}

	return 0;
}

void ubcore_remove_port_attr_files(struct ubcore_logic_device *ldev, uint8_t port_id)
{
	kobject_put(&ldev->port[port_id].kobj);
}

void ubcore_remove_dev_attr_files(struct ubcore_logic_device *ldev)
{
	sysfs_remove_group(&ldev->dev->kobj, &ubcore_dev_attr_group);
}

int ubcore_fill_logic_device_attr(struct ubcore_logic_device *ldev,
	struct ubcore_device *dev)
{
	uint8_t p1, p2; /* port */

	if (ubcore_create_dev_attr_files(ldev) != 0) {
		ubcore_log_err("failed to fill attributes, device:%s.\n", dev->dev_name);
		return -EPERM;
	}

	/* create /sys/class/ubcore/<dev->dev_name>/port* */
	for (p1 = 0; p1 < dev->attr.port_cnt; p1++) {
		if (ubcore_create_port_attr_files(ldev, dev, p1) != 0)
			goto err_port_attr;
	}

	return 0;

err_port_attr:
	for (p2 = 0; p2 < p1; p2++)
		ubcore_remove_port_attr_files(ldev, p2);

	ubcore_remove_dev_attr_files(ldev);
	return -EPERM;
}

void ubcore_unfill_logic_device_attr(struct ubcore_logic_device *ldev,
	struct ubcore_device *dev)
{
	uint8_t p;

	for (p = 0; p < dev->attr.port_cnt; p++)
		ubcore_remove_port_attr_files(ldev, p);

	ubcore_remove_dev_attr_files(ldev);
}
