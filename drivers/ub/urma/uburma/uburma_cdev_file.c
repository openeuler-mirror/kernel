// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
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
 * Description: uburma cdev file
 * Author: Qian Guoxin
 * Create: 2022-08-16
 * Note:
 * History: 2022-08-16: Create file
 */

#include <linux/fs.h>
#include <linux/inet.h>
#include <linux/version.h>

#include <urma/ubcore_types.h>
#include <urma/ubcore_uapi.h>

#include "uburma_log.h"
#include "uburma_types.h"
#include "uburma_cdev_file.h"

#define UBURMA_MAX_DEV_NAME 64
#define UBURMA_MAX_VALUE_LEN 24

/* callback information */
typedef ssize_t (*uburma_show_attr_cb)(struct ubcore_device *ubc_dev,
	char *buf);
typedef ssize_t (*uburma_store_attr_cb)(struct ubcore_device *ubc_dev,
	const char *buf, size_t len);
typedef ssize_t (*uburma_show_port_attr_cb)(struct ubcore_device *ubc_dev,
	char *buf, uint8_t port_num);
typedef ssize_t (*uburma_show_fe_attr_cb)(struct ubcore_device *ubc_dev,
	char *buf, uint16_t fe_num);
typedef ssize_t (*uburma_store_fe_attr_cb)(struct ubcore_device *ubc_dev,
	const char *buf, size_t len, uint16_t fe_num);
typedef ssize_t (*uburma_show_eid_attr_cb)(struct ubcore_device *ubc_dev,
	char *buf, uint16_t idx, struct net *net);

static inline struct uburma_device *get_uburma_device(struct uburma_logic_device *ldev)
{
	return ldev == NULL ? NULL : ldev->ubu_dev;
}

static ssize_t uburma_show_dev_attr(struct device *dev, struct device_attribute *attr,
	char *buf, uburma_show_attr_cb show_cb)
{
	struct uburma_logic_device *ldev = dev_get_drvdata(dev);
	struct uburma_device *ubu_dev = get_uburma_device(ldev);
	struct ubcore_device *ubc_dev;
	ssize_t ret = -ENODEV;
	int srcu_idx;

	if (!ldev || !ubu_dev || !buf) {
		uburma_log_err("Invalid argument.\n");
		return -EINVAL;
	}

	srcu_idx = srcu_read_lock(&ubu_dev->ubc_dev_srcu);
	ubc_dev = srcu_dereference(ubu_dev->ubc_dev, &ubu_dev->ubc_dev_srcu);
	if (ubc_dev)
		ret = show_cb(ubc_dev, buf);

	srcu_read_unlock(&ubu_dev->ubc_dev_srcu, srcu_idx);
	return ret;
}

static ssize_t uburma_store_dev_attr(struct device *dev, struct device_attribute *attr,
				     const char *buf, size_t len, uburma_store_attr_cb store_cb)
{
	struct uburma_logic_device *ldev = dev_get_drvdata(dev);
	struct uburma_device *ubu_dev = get_uburma_device(ldev);
	struct ubcore_device *ubc_dev;
	ssize_t ret = -ENODEV;
	int srcu_idx;

	if (!ldev || !ubu_dev || !buf) {
		uburma_log_err("Invalid argument.\n");
		return -EINVAL;
	}

	srcu_idx = srcu_read_lock(&ubu_dev->ubc_dev_srcu);
	ubc_dev = srcu_dereference(ubu_dev->ubc_dev, &ubu_dev->ubc_dev_srcu);
	if (ubc_dev)
		ret = store_cb(ubc_dev, buf, len);

	srcu_read_unlock(&ubu_dev->ubc_dev_srcu, srcu_idx);
	return ret;
}

/* interface for exporting device attributes */
static ssize_t ubdev_show_cb(struct ubcore_device *ubc_dev, char *buf)
{
	return snprintf(buf, UBCORE_MAX_DEV_NAME, "%s\n", ubc_dev->dev_name);
}

static ssize_t ubdev_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	return uburma_show_dev_attr(dev, attr, buf, ubdev_show_cb);
}

static DEVICE_ATTR_RO(ubdev);

static ssize_t guid_show_cb(struct ubcore_device *ubc_dev, char *buf)
{
	return snprintf(buf, UBURMA_MAX_VALUE_LEN, "%llu\n", ubc_dev->attr.guid);
}

static ssize_t guid_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	return uburma_show_dev_attr(dev, attr, buf, guid_show_cb);
}

static DEVICE_ATTR_RO(guid);

static ssize_t max_upi_cnt_show_cb(struct ubcore_device *ubc_dev, char *buf)
{
	return snprintf(buf, UBURMA_MAX_VALUE_LEN, "%u\n", ubc_dev->attr.max_upi_cnt);
}

static ssize_t max_upi_cnt_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	return uburma_show_dev_attr(dev, attr, buf, max_upi_cnt_show_cb);
}

static DEVICE_ATTR_RO(max_upi_cnt);

static ssize_t uburma_query_upi(struct ubcore_device *ubc_dev, char *buf, uint16_t fe_idx)
{
	struct ubcore_res_key key = { 0 };
	struct ubcore_res_val val = { 0 };
	uint32_t upi;
	uint32_t i;
	ssize_t ret;

	key.type = UBCORE_RES_KEY_UPI;
	key.key = (uint32_t)fe_idx;

	val.len = (uint32_t)sizeof(uint32_t) * UBCORE_MAX_UPI_CNT;
	val.addr = (uint64_t)kcalloc(1, val.len, GFP_KERNEL);
	if (val.addr == 0) {
		uburma_log_err("kcalloc fe%hu failed.\n", fe_idx);
		return -ENOMEM;
	}

	if (ubcore_query_resource(ubc_dev, &key, &val) != 0) {
		uburma_log_err("query fe%hu resource failed.\n", fe_idx);
		kfree((void *)val.addr);
		return -EPERM;
	}

#define UBURMA_UPI_STR_LEN (9) /* 2^20 <= 8bit, add 1 bit space */
	for (i = 0; i < (val.len / sizeof(upi)); i++) {
		upi = *((uint32_t *)val.addr + i);
		ret = snprintf(buf + (UBURMA_UPI_STR_LEN * i), UBURMA_UPI_STR_LEN + 1, "%8u ", upi);
		if (ret <= 0) {
			uburma_log_err("snprintf for fe%hu upi failed %ld.\n", fe_idx, ret);
			kfree((void *)val.addr);
			return ret;
		}
	}

	buf[(UBURMA_UPI_STR_LEN * i) - 1] = '\n';

	kfree((void *)val.addr);
	return (ssize_t)(UBURMA_UPI_STR_LEN * i);
}

static int uburma_parse_upi_str(const char *buf, size_t len, uint16_t *idx, uint32_t *upi)
{
	int ret;

	ret = sscanf(buf, "%hu=%u", idx, upi);
	if (ret <= 1)  // ret must be equal to 2
		return -1;

	return 0;
}

static ssize_t uburma_set_upi(struct ubcore_device *ubc_dev, const char *buf,
	size_t len, uint16_t fe_idx)
{
	ssize_t ret = -ENODEV;
	uint16_t idx;
	uint32_t upi;

	ret = uburma_parse_upi_str(buf, len, &idx, &upi);
	if (ret != 0) {
		uburma_log_err("parse fe%hu upi str:%s failed %ld.\n", fe_idx, buf, ret);
		return -EINVAL;
	}

	if (ubcore_set_upi(ubc_dev, fe_idx, idx, upi) != 0) {
		uburma_log_err("set fe%hu idx:%hu upi:%u failed.\n", fe_idx, idx, upi);
		return -EPERM;
	}
	return (ssize_t)len; // len is required for success return.
}

static ssize_t upi_show_cb(struct ubcore_device *ubc_dev, char *buf)
{
	return uburma_query_upi(ubc_dev, buf, UBCORE_OWN_FE_IDX);
}

static ssize_t upi_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	return uburma_show_dev_attr(dev, attr, buf, upi_show_cb);
}

static ssize_t upi_store_cb(struct ubcore_device *ubc_dev, const char *buf, size_t len)
{
	return uburma_set_upi(ubc_dev, buf, len, UBCORE_OWN_FE_IDX);
}

static ssize_t upi_store(struct device *dev, struct device_attribute *attr,
	const char *buf, size_t len)
{
	return uburma_store_dev_attr(dev, attr, buf, len, upi_store_cb);
}

static DEVICE_ATTR_RW(upi);

static ssize_t feature_show_cb(struct ubcore_device *ubc_dev, char *buf)
{
	return snprintf(buf, UBURMA_MAX_VALUE_LEN, "0x%x\n", ubc_dev->attr.dev_cap.feature.value);
}

static ssize_t feature_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	return uburma_show_dev_attr(dev, attr, buf, feature_show_cb);
}

static DEVICE_ATTR_RO(feature);

static ssize_t max_jfc_show_cb(struct ubcore_device *ubc_dev, char *buf)
{
	return snprintf(buf, UBURMA_MAX_VALUE_LEN, "%u\n", ubc_dev->attr.dev_cap.max_jfc);
}

static ssize_t max_jfc_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	return uburma_show_dev_attr(dev, attr, buf, max_jfc_show_cb);
}

static DEVICE_ATTR_RO(max_jfc);

static ssize_t max_jfs_show_cb(struct ubcore_device *ubc_dev, char *buf)
{
	return snprintf(buf, UBURMA_MAX_VALUE_LEN, "%u\n", ubc_dev->attr.dev_cap.max_jfs);
}

static ssize_t max_jfs_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	return uburma_show_dev_attr(dev, attr, buf, max_jfs_show_cb);
}

static DEVICE_ATTR_RO(max_jfs);

static ssize_t max_jfr_show_cb(struct ubcore_device *ubc_dev, char *buf)
{
	return snprintf(buf, UBURMA_MAX_VALUE_LEN, "%u\n", ubc_dev->attr.dev_cap.max_jfr);
}

static ssize_t max_jfr_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	return uburma_show_dev_attr(dev, attr, buf, max_jfr_show_cb);
}

static DEVICE_ATTR_RO(max_jfr);

static ssize_t max_jetty_show_cb(struct ubcore_device *ubc_dev, char *buf)
{
	return snprintf(buf, UBURMA_MAX_VALUE_LEN, "%u\n", ubc_dev->attr.dev_cap.max_jetty);
}

static ssize_t max_jetty_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	return uburma_show_dev_attr(dev, attr, buf, max_jetty_show_cb);
}

static DEVICE_ATTR_RO(max_jetty);

static ssize_t show_max_jetty_grp_cb(struct ubcore_device *ubc_dev, char *buf)
{
	return snprintf(buf, UBURMA_MAX_VALUE_LEN, "%u\n", ubc_dev->attr.dev_cap.max_jetty_grp);
}
static ssize_t max_jetty_grp_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	return uburma_show_dev_attr(dev, attr, buf, show_max_jetty_grp_cb);
}
static DEVICE_ATTR_RO(max_jetty_grp);

static ssize_t show_max_jetty_in_jetty_grp_cb(struct ubcore_device *ubc_dev, char *buf)
{
	return snprintf(buf, UBURMA_MAX_VALUE_LEN, "%u\n",
		ubc_dev->attr.dev_cap.max_jetty_in_jetty_grp);
}
static ssize_t max_jetty_in_jetty_grp_show(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	return uburma_show_dev_attr(dev, attr, buf, show_max_jetty_in_jetty_grp_cb);
}
static DEVICE_ATTR_RO(max_jetty_in_jetty_grp);

static ssize_t max_jfc_depth_show_cb(struct ubcore_device *ubc_dev, char *buf)
{
	return snprintf(buf, UBURMA_MAX_VALUE_LEN, "%u\n", ubc_dev->attr.dev_cap.max_jfc_depth);
}

static ssize_t max_jfc_depth_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	return uburma_show_dev_attr(dev, attr, buf, max_jfc_depth_show_cb);
}

static DEVICE_ATTR_RO(max_jfc_depth);

static ssize_t max_jfs_depth_show_cb(struct ubcore_device *ubc_dev, char *buf)
{
	return snprintf(buf, UBURMA_MAX_VALUE_LEN, "%u\n", ubc_dev->attr.dev_cap.max_jfs_depth);
}

static ssize_t max_jfs_depth_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	return uburma_show_dev_attr(dev, attr, buf, max_jfs_depth_show_cb);
}

static DEVICE_ATTR_RO(max_jfs_depth);

static ssize_t max_jfr_depth_show_cb(struct ubcore_device *ubc_dev, char *buf)
{
	return snprintf(buf, UBURMA_MAX_VALUE_LEN, "%u\n", ubc_dev->attr.dev_cap.max_jfr_depth);
}

static ssize_t max_jfr_depth_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	return uburma_show_dev_attr(dev, attr, buf, max_jfr_depth_show_cb);
}

static DEVICE_ATTR_RO(max_jfr_depth);

static ssize_t show_max_jfs_inline_size_cb(struct ubcore_device *ubc_dev, char *buf)
{
	return snprintf(buf, UBURMA_MAX_VALUE_LEN, "%u\n",
		ubc_dev->attr.dev_cap.max_jfs_inline_size);
}

static ssize_t max_jfs_inline_size_show(struct device *dev, struct device_attribute *attr,
					char *buf)
{
	return uburma_show_dev_attr(dev, attr, buf, show_max_jfs_inline_size_cb);
}

static DEVICE_ATTR_RO(max_jfs_inline_size);

static ssize_t max_jfs_sge_show_cb(struct ubcore_device *ubc_dev, char *buf)
{
	return snprintf(buf, UBURMA_MAX_VALUE_LEN, "%u\n", ubc_dev->attr.dev_cap.max_jfs_sge);
}

static ssize_t max_jfs_sge_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	return uburma_show_dev_attr(dev, attr, buf, max_jfs_sge_show_cb);
}

static DEVICE_ATTR_RO(max_jfs_sge);

static ssize_t max_jfs_rsge_show_cb(struct ubcore_device *ubc_dev, char *buf)
{
	return snprintf(buf, UBURMA_MAX_VALUE_LEN, "%u\n", ubc_dev->attr.dev_cap.max_jfs_rsge);
}

static ssize_t max_jfs_rsge_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	return uburma_show_dev_attr(dev, attr, buf, max_jfs_rsge_show_cb);
}

static DEVICE_ATTR_RO(max_jfs_rsge);

static ssize_t max_jfr_sge_show_cb(struct ubcore_device *ubc_dev, char *buf)
{
	return snprintf(buf, UBURMA_MAX_VALUE_LEN, "%u\n", ubc_dev->attr.dev_cap.max_jfr_sge);
}

static ssize_t max_jfr_sge_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	return uburma_show_dev_attr(dev, attr, buf, max_jfr_sge_show_cb);
}

static DEVICE_ATTR_RO(max_jfr_sge);

static ssize_t max_msg_size_show_cb(struct ubcore_device *ubc_dev, char *buf)
{
	return snprintf(buf, UBURMA_MAX_VALUE_LEN, "%llu\n", ubc_dev->attr.dev_cap.max_msg_size);
}

static ssize_t max_msg_size_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	return uburma_show_dev_attr(dev, attr, buf, max_msg_size_show_cb);
}

static DEVICE_ATTR_RO(max_msg_size);

static ssize_t show_max_atomic_size_cb(struct ubcore_device *ubc_dev, char *buf)
{
	return snprintf(buf, UBURMA_MAX_VALUE_LEN, "%u\n", ubc_dev->attr.dev_cap.max_atomic_size);
}
static ssize_t max_atomic_size_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	return uburma_show_dev_attr(dev, attr, buf, show_max_atomic_size_cb);
}
static DEVICE_ATTR_RO(max_atomic_size);

static ssize_t show_atomic_feat_cb(struct ubcore_device *ubc_dev, char *buf)
{
	return snprintf(buf, UBURMA_MAX_VALUE_LEN, "%u\n", ubc_dev->attr.dev_cap.atomic_feat.value);
}
static ssize_t atomic_feat_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	return uburma_show_dev_attr(dev, attr, buf, show_atomic_feat_cb);
}
static DEVICE_ATTR_RO(atomic_feat);

static ssize_t max_rc_outstd_cnt_show_cb(struct ubcore_device *ubc_dev, char *buf)
{
	return snprintf(buf, UBURMA_MAX_VALUE_LEN,
		"%llu\n", ubc_dev->attr.dev_cap.max_rc_outstd_cnt);
}

static ssize_t max_rc_outstd_cnt_show(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	return uburma_show_dev_attr(dev, attr, buf, max_rc_outstd_cnt_show_cb);
}

static DEVICE_ATTR_RO(max_rc_outstd_cnt);

static ssize_t trans_mode_show_cb(struct ubcore_device *ubc_dev, char *buf)
{
	return snprintf(buf, UBURMA_MAX_VALUE_LEN, "%u\n", ubc_dev->attr.dev_cap.trans_mode);
}

static ssize_t trans_mode_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	return uburma_show_dev_attr(dev, attr, buf, trans_mode_show_cb);
}

static DEVICE_ATTR_RO(trans_mode);

static ssize_t congestion_ctrl_alg_show_cb(struct ubcore_device *ubc_dev, char *buf)
{
	return snprintf(buf, UBURMA_MAX_VALUE_LEN,
		"%u\n", ubc_dev->attr.dev_cap.congestion_ctrl_alg);
}

static ssize_t congestion_ctrl_alg_show(struct device *dev, struct device_attribute *attr,
					char *buf)
{
	return uburma_show_dev_attr(dev, attr, buf, congestion_ctrl_alg_show_cb);
}

static ssize_t congestion_ctrl_alg_store_cb(struct ubcore_device *ubc_dev, const char *buf,
					    size_t len)
{
	uint16_t value;
	int ret;

	ret = kstrtou16(buf, 0, &value);
	if (ret != 0)
		return -EINVAL;

	ubc_dev->attr.dev_cap.congestion_ctrl_alg = value;
	return (ssize_t)len;
}

static ssize_t congestion_ctrl_alg_store(struct device *dev, struct device_attribute *attr,
					 const char *buf, size_t len)
{
	return uburma_store_dev_attr(dev, attr, buf, len, congestion_ctrl_alg_store_cb);
}

static DEVICE_ATTR_RW(congestion_ctrl_alg); // 0644

static ssize_t ceq_cnt_show_cb(struct ubcore_device *ubc_dev, char *buf)
{
	return snprintf(buf, UBURMA_MAX_VALUE_LEN, "%u\n", ubc_dev->attr.dev_cap.ceq_cnt);
}

static ssize_t ceq_cnt_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	return uburma_show_dev_attr(dev, attr, buf, ceq_cnt_show_cb);
}

static DEVICE_ATTR_RO(ceq_cnt);

static ssize_t utp_cnt_show_cb(struct ubcore_device *ubc_dev, char *buf)
{
	return snprintf(buf, UBURMA_MAX_VALUE_LEN, "%u\n", ubc_dev->attr.dev_cap.utp_cnt);
}

static ssize_t utp_cnt_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	return uburma_show_dev_attr(dev, attr, buf, utp_cnt_show_cb);
}

static DEVICE_ATTR_RO(utp_cnt);

static ssize_t port_count_show_cb(struct ubcore_device *ubc_dev, char *buf)
{
	return snprintf(buf, UBURMA_MAX_VALUE_LEN, "%u\n", ubc_dev->attr.port_cnt);
}

static ssize_t port_count_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	return uburma_show_dev_attr(dev, attr, buf, port_count_show_cb);
}

static DEVICE_ATTR_RO(port_count);

static ssize_t virtualization_show_cb(struct ubcore_device *ubc_dev, char *buf)
{
	return snprintf(buf, UBURMA_MAX_VALUE_LEN,
		"%s\n", ubc_dev->attr.virtualization ? "true" : "false");
}
static ssize_t virtualization_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	return uburma_show_dev_attr(dev, attr, buf, virtualization_show_cb);
}
static DEVICE_ATTR_RO(virtualization);

static ssize_t show_fe_cnt_cb(struct ubcore_device *ubc_dev, char *buf)
{
	return snprintf(buf, UBURMA_MAX_VALUE_LEN - 1, "%u\n", ubc_dev->attr.fe_cnt);
}
static ssize_t fe_cnt_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	return uburma_show_dev_attr(dev, attr, buf, show_fe_cnt_cb);
}
static DEVICE_ATTR_RO(fe_cnt);

static ssize_t show_dynamic_eid_cb(struct ubcore_device *ubc_dev, char *buf)
{
	return snprintf(buf, UBURMA_MAX_VALUE_LEN, "%d\n", ubc_dev->dynamic_eid);
}
static ssize_t dynamic_eid_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	return uburma_show_dev_attr(dev, attr, buf, show_dynamic_eid_cb);
}
static DEVICE_ATTR_RO(dynamic_eid);

static ssize_t max_eid_cnt_show_cb(struct ubcore_device *ubc_dev, char *buf)
{
	return snprintf(buf, UBURMA_MAX_VALUE_LEN, "%u\n", ubc_dev->attr.max_eid_cnt);
}

static ssize_t max_eid_cnt_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	return uburma_show_dev_attr(dev, attr, buf, max_eid_cnt_show_cb);
}

static DEVICE_ATTR_RO(max_eid_cnt);

static ssize_t transport_type_show_cb(struct ubcore_device *ubc_dev, char *buf)
{
	return snprintf(buf, UBURMA_MAX_VALUE_LEN, "%d\n", (int)ubc_dev->transport_type);
}

static ssize_t transport_type_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	return uburma_show_dev_attr(dev, attr, buf, transport_type_show_cb);
}

static DEVICE_ATTR_RO(transport_type);

static ssize_t driver_name_show_cb(struct ubcore_device *ubc_dev, char *buf)
{
	if (ubc_dev->ops == NULL)
		return -EINVAL;

	return snprintf(buf, UBCORE_MAX_DRIVER_NAME, "%s\n", ubc_dev->ops->driver_name);
}

static ssize_t driver_name_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	return uburma_show_dev_attr(dev, attr, buf, driver_name_show_cb);
}

static DEVICE_ATTR_RO(driver_name);

static struct attribute *uburma_dev_attrs[] = {
	&dev_attr_ubdev.attr,
	&dev_attr_guid.attr,
	&dev_attr_max_upi_cnt.attr,
	&dev_attr_upi.attr,
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
	&dev_attr_port_count.attr,
	&dev_attr_fe_cnt.attr,
	&dev_attr_max_eid_cnt.attr,
	&dev_attr_dynamic_eid.attr,
	&dev_attr_virtualization.attr,
	&dev_attr_transport_type.attr,
	&dev_attr_driver_name.attr,
	NULL,
};

static const struct attribute_group uburma_dev_attr_group = {
	.attrs = uburma_dev_attrs,
};

static ssize_t uburma_show_port_attr(struct uburma_port *p, struct uburma_port_attribute *attr,
				     char *buf, uburma_show_port_attr_cb show_cb)
{
	struct uburma_device *ubu_dev = p->ubu_dev;
	struct ubcore_device *ubc_dev;
	ssize_t ret = -ENODEV;
	int srcu_idx;

	if (!ubu_dev || !buf) {
		uburma_log_err("Invalid argument.\n");
		return -EINVAL;
	}

	srcu_idx = srcu_read_lock(&ubu_dev->ubc_dev_srcu);
	ubc_dev = srcu_dereference(ubu_dev->ubc_dev, &ubu_dev->ubc_dev_srcu);
	if (ubc_dev == NULL) {
		srcu_read_unlock(&ubu_dev->ubc_dev_srcu, srcu_idx);
		return -ENODEV;
	}

	ret = show_cb(ubc_dev, buf, p->port_num);
	srcu_read_unlock(&ubu_dev->ubc_dev_srcu, srcu_idx);
	return ret;
}

static ssize_t max_mtu_show_cb(struct ubcore_device *ubc_dev, char *buf, uint8_t port_num)
{
	return snprintf(buf, UBURMA_MAX_VALUE_LEN,
		"%d\n", (int)ubc_dev->attr.port_attr[port_num].max_mtu);
}

static ssize_t max_mtu_show(struct uburma_port *p, struct uburma_port_attribute *attr, char *buf)
{
	return uburma_show_port_attr(p, attr, buf, max_mtu_show_cb);
}

static PORT_ATTR_RO(max_mtu);

static ssize_t state_show_cb(struct ubcore_device *ubc_dev, char *buf, uint8_t port_num)
{
	struct ubcore_device_status status;

	if (ubcore_query_device_status(ubc_dev, &status) != 0) {
		uburma_log_err("query device status for state failed.\n");
		return -EPERM;
	}

	return snprintf(buf, UBURMA_MAX_VALUE_LEN,
		"%u\n", (uint32_t)status.port_status[port_num].state);
}

static ssize_t state_show(struct uburma_port *p, struct uburma_port_attribute *attr, char *buf)
{
	return uburma_show_port_attr(p, attr, buf, state_show_cb);
}

static PORT_ATTR_RO(state);

static ssize_t active_speed_show_cb(struct ubcore_device *ubc_dev, char *buf,
				    uint8_t port_num)
{
	struct ubcore_device_status status;

	if (ubcore_query_device_status(ubc_dev, &status) != 0) {
		uburma_log_err("query device status for active speed failed.\n");
		return -EPERM;
	}

	return snprintf(buf, UBURMA_MAX_VALUE_LEN,
		"%u\n", status.port_status[port_num].active_speed);
}

static ssize_t active_speed_show(struct uburma_port *p, struct uburma_port_attribute *attr,
				 char *buf)
{
	return uburma_show_port_attr(p, attr, buf, active_speed_show_cb);
}

static PORT_ATTR_RO(active_speed);

static ssize_t active_width_show_cb(struct ubcore_device *ubc_dev, char *buf,
				    uint8_t port_num)
{
	struct ubcore_device_status status;

	if (ubcore_query_device_status(ubc_dev, &status) != 0) {
		uburma_log_err("query device status for active width failed.\n");
		return -EPERM;
	}

	return snprintf(buf, UBURMA_MAX_VALUE_LEN,
		"%u\n", status.port_status[port_num].active_width);
}

static ssize_t active_width_show(struct uburma_port *p, struct uburma_port_attribute *attr,
				 char *buf)
{
	return uburma_show_port_attr(p, attr, buf, active_width_show_cb);
}

static PORT_ATTR_RO(active_width);

static ssize_t active_mtu_show_cb(struct ubcore_device *ubc_dev, char *buf, uint8_t port_num)
{
	struct ubcore_device_status status;

	if (ubcore_query_device_status(ubc_dev, &status) != 0) {
		uburma_log_err("query device status for active mtu failed.\n");
		return -EPERM;
	}

	return snprintf(buf, UBURMA_MAX_VALUE_LEN,
		"%u\n", (uint32_t)status.port_status[port_num].active_mtu);
}

static ssize_t active_mtu_show(struct uburma_port *p, struct uburma_port_attribute *attr,
	char *buf)
{
	return uburma_show_port_attr(p, attr, buf, active_mtu_show_cb);
}

static PORT_ATTR_RO(active_mtu);

static struct attribute *uburma_port_attrs[] = {
	&port_attr_max_mtu.attr,      &port_attr_state.attr,	  &port_attr_active_speed.attr,
	&port_attr_active_width.attr, &port_attr_active_mtu.attr, NULL,
};

static ssize_t uburma_port_attr_show(struct kobject *kobj, struct attribute *attr, char *buf)
{
	struct uburma_port_attribute *port_attr =
		container_of(attr, struct uburma_port_attribute, attr);
	struct uburma_port *p = container_of(kobj, struct uburma_port, kobj);

	if (!port_attr->show)
		return -EIO;

	return port_attr->show(p, port_attr, buf);
}

static ssize_t uburma_port_attr_store(struct kobject *kobj, struct attribute *attr,
	const char *buf, size_t count)
{
	struct uburma_port_attribute *port_attr =
		container_of(attr, struct uburma_port_attribute, attr);
	struct uburma_port *p = container_of(kobj, struct uburma_port, kobj);

	if (!port_attr->store)
		return -EIO;

	return port_attr->store(p, port_attr, buf, count);
}

static const struct sysfs_ops uburma_port_sysfs_ops = { .show = uburma_port_attr_show,
							.store = uburma_port_attr_store };

static void uburma_port_release(struct kobject *kobj)
{
}

// ATTRIBUTE_GROUPS defined in 3.11, but must be consistent with kobj_type->default_groups
ATTRIBUTE_GROUPS(uburma_port);

static struct kobj_type uburma_port_type = { .release = uburma_port_release,
					     .sysfs_ops = &uburma_port_sysfs_ops,
					     .default_groups = uburma_port_groups
};

static ssize_t uburma_show_fe_attr(struct uburma_fe *fe, struct uburma_fe_attribute *attr,
	char *buf, uburma_show_fe_attr_cb show_cb)
{
	struct uburma_device *ubu_dev = fe->ubu_dev;
	struct ubcore_device *ubc_dev;
	int srcu_idx;
	ssize_t ret;

	if (!ubu_dev) {
		uburma_log_err("Invalid argument in show_fe_attr.\n");
		return -EINVAL;
	}

	srcu_idx = srcu_read_lock(&ubu_dev->ubc_dev_srcu);
	ubc_dev = srcu_dereference(ubu_dev->ubc_dev, &ubu_dev->ubc_dev_srcu);
	if (ubc_dev == NULL) {
		srcu_read_unlock(&ubu_dev->ubc_dev_srcu, srcu_idx);
		return -ENODEV;
	}

	ret = show_cb(ubc_dev, buf, fe->fe_idx);
	srcu_read_unlock(&ubu_dev->ubc_dev_srcu, srcu_idx);
	return ret;
}

static ssize_t uburma_store_fe_attr(struct uburma_fe *fe, struct uburma_fe_attribute *attr,
	const char *buf, size_t len, uburma_store_fe_attr_cb store_cb)
{
	struct uburma_device *ubu_dev = fe->ubu_dev;
	struct ubcore_device *ubc_dev;
	int srcu_idx;
	ssize_t ret;

	if (!ubu_dev) {
		uburma_log_err("Invalid argument in store_fe_attr.\n");
		return -EINVAL;
	}

	srcu_idx = srcu_read_lock(&ubu_dev->ubc_dev_srcu);
	ubc_dev = srcu_dereference(ubu_dev->ubc_dev, &ubu_dev->ubc_dev_srcu);
	if (ubc_dev == NULL) {
		srcu_read_unlock(&ubu_dev->ubc_dev_srcu, srcu_idx);
		return -ENODEV;
	}

	ret = store_cb(ubc_dev, buf, len, fe->fe_idx);
	srcu_read_unlock(&ubu_dev->ubc_dev_srcu, srcu_idx);
	return ret;
}

static ssize_t fe_upi_show_cb(struct ubcore_device *ubc_dev, char *buf, uint16_t fe_idx)
{
	return uburma_query_upi(ubc_dev, buf, fe_idx);
}

static ssize_t fe_upi_show(struct uburma_fe *fe, struct uburma_fe_attribute *attr, char *buf)
{
	return uburma_show_fe_attr(fe, attr, buf, fe_upi_show_cb);
}

static ssize_t fe_upi_store_cb(struct ubcore_device *ubc_dev, const char *buf,
	size_t len, uint16_t fe_idx)
{
	if (ubc_dev == NULL || buf == NULL)
		return -EINVAL;

	return uburma_set_upi(ubc_dev, buf, len, fe_idx);
}

static ssize_t fe_upi_store(struct uburma_fe *fe, struct uburma_fe_attribute *attr,
	const char *buf, size_t len)
{
	return uburma_store_fe_attr(fe, attr, buf, len, fe_upi_store_cb);
}

static FE_ATTR(upi, 0644, fe_upi_show, fe_upi_store);

static struct attribute *uburma_fe_attrs[] = {
	&fe_attr_upi.attr,
	NULL,
};

static ssize_t uburma_fe_attr_show(struct kobject *kobj, struct attribute *attr, char *buf)
{
	struct uburma_fe_attribute *fe_attr = container_of(attr, struct uburma_fe_attribute, attr);
	struct uburma_fe *fe = container_of(kobj, struct uburma_fe, kobj);

	if (!fe_attr->show)
		return -EIO;

	return fe_attr->show(fe, fe_attr, buf);
}

static ssize_t uburma_fe_attr_store(struct kobject *kobj, struct attribute *attr,
	const char *buf, size_t count)
{
	struct uburma_fe_attribute *fe_attr = container_of(attr, struct uburma_fe_attribute, attr);
	struct uburma_fe *fe = container_of(kobj, struct uburma_fe, kobj);

	if (!fe_attr->store)
		return -EIO;
	return fe_attr->store(fe, fe_attr, buf, count);
}

static const struct sysfs_ops uburma_fe_sysfs_ops = {
	.show	= uburma_fe_attr_show,
	.store	= uburma_fe_attr_store
};

static void uburma_fe_release(struct kobject *kobj)
{
}

// ATTRIBUTE_GROUPS defined in 3.11, but must be consistent with kobj_type->default_groups
ATTRIBUTE_GROUPS(uburma_fe);

static struct kobj_type uburma_fe_type = {
	.release       = uburma_fe_release,
	.sysfs_ops     = &uburma_fe_sysfs_ops,
	.default_groups = uburma_fe_groups
};

static ssize_t uburma_show_eid_attr(struct uburma_eid *eid, struct uburma_eid_attribute *attr,
	char *buf, uburma_show_eid_attr_cb show_cb)
{
	struct uburma_logic_device *ldev = eid->ldev;
	struct uburma_device *ubu_dev = get_uburma_device(ldev);
	struct ubcore_device *ubc_dev;
	int srcu_idx;
	ssize_t ret;

	if (!ldev || !ubu_dev) {
		uburma_log_err("Invalid argument in show_fe_attr.\n");
		return -EINVAL;
	}

	srcu_idx = srcu_read_lock(&ubu_dev->ubc_dev_srcu);
	ubc_dev = srcu_dereference(ubu_dev->ubc_dev, &ubu_dev->ubc_dev_srcu);
	if (ubc_dev == NULL) {
		srcu_read_unlock(&ubu_dev->ubc_dev_srcu, srcu_idx);
		return -ENODEV;
	}

	ret = show_cb(ubc_dev, buf, eid->eid_idx, read_pnet(&ldev->net));
	srcu_read_unlock(&ubu_dev->ubc_dev_srcu, srcu_idx);
	return ret;
}

static ssize_t show_eid_cb(struct ubcore_device *ubc_dev, char *buf, uint16_t idx, struct net *net)
{
	union ubcore_eid eid;

	if (ubc_dev->eid_table.eid_entries[idx].net == net) {
		return snprintf(buf, (UBCORE_EID_STR_LEN + 1) + 1, EID_FMT"\n",
			EID_ARGS(ubc_dev->eid_table.eid_entries[idx].eid));
	} else {
		memset(&eid, 0, sizeof(union ubcore_eid));
		return snprintf(buf, (UBCORE_EID_STR_LEN + 1) + 1, EID_FMT"\n",
			EID_ARGS(eid));
	}
}

static ssize_t eid_show(struct uburma_eid *eid, struct uburma_eid_attribute *attr, char *buf)
{
	return uburma_show_eid_attr(eid, attr, buf, show_eid_cb);
}

static EID_ATTR_RO(eid);

static struct attribute *uburma_eid_attrs[] = {
	&eid_attr_eid.attr,
	NULL,
};

static ssize_t uburma_eid_attr_show(struct kobject *kobj, struct attribute *attr, char *buf)
{
	struct uburma_eid_attribute *eid_attr =
		container_of(attr, struct uburma_eid_attribute, attr);
	struct uburma_eid *eid = container_of(kobj, struct uburma_eid, kobj);

	if (!eid_attr->show)
		return -EIO;

	return eid_attr->show(eid, eid_attr, buf);
}

static ssize_t uburma_eid_attr_store(struct kobject *kobj, struct attribute *attr,
	const char *buf, size_t count)
{
	struct uburma_eid_attribute *eid_attr =
		container_of(attr, struct uburma_eid_attribute, attr);
	struct uburma_eid *eid = container_of(kobj, struct uburma_eid, kobj);

	if (!eid_attr->store)
		return -EIO;
	return eid_attr->store(eid, eid_attr, buf, count);
}

static const struct sysfs_ops uburma_eid_sysfs_ops = {
	.show	= uburma_eid_attr_show,
	.store	= uburma_eid_attr_store
};

static void uburma_eid_release(struct kobject *kobj)
{
}

// ATTRIBUTE_GROUPS defined in 3.11, but must be consistent with kobj_type->default_groups
ATTRIBUTE_GROUPS(uburma_eid);

static struct kobj_type uburma_eid_type = {
	.release       = uburma_eid_release,
	.sysfs_ops     = &uburma_eid_sysfs_ops,
	.default_groups = uburma_eid_groups
};

int uburma_create_port_attr_files(struct uburma_logic_device *ldev,
	struct uburma_device *ubu_dev, uint8_t port_num)
{
	struct uburma_port *p;

	p = &ldev->port[port_num];
	p->ubu_dev = ubu_dev;
	p->port_num = port_num;

	return kobject_init_and_add(&p->kobj, &uburma_port_type, &ldev->dev->kobj,
		"port%hhu", port_num);
}

int uburma_create_fe_attr_files(struct uburma_logic_device *ldev,
	struct uburma_device *ubu_dev, uint16_t fe_num)
{
	struct uburma_fe *fe;

	fe = &ldev->fe[fe_num];
	fe->ubu_dev = ubu_dev;
	fe->fe_idx = fe_num;

	return kobject_init_and_add(&fe->kobj, &uburma_fe_type, &ldev->dev->kobj,
		"fe%hu", fe_num);
}

int uburma_create_eid_attr_files(struct uburma_logic_device *ldev, uint32_t eid_num)
{
	struct uburma_eid *eid;

	eid = &ldev->eid[eid_num];
	eid->ldev = ldev;
	eid->eid_idx = eid_num;

	return kobject_init_and_add(&eid->kobj, &uburma_eid_type, &ldev->dev->kobj,
		"eid%u", eid_num);
}

int uburma_create_dev_attr_files(struct uburma_logic_device *ldev)
{
	int ret;

	ret = sysfs_create_group(&ldev->dev->kobj, &uburma_dev_attr_group);
	if (ret != 0) {
		uburma_log_err("sysfs create group failed, ret:%d.\n", ret);
		return -1;
	}

	return 0;
}

void uburma_remove_port_attr_files(struct uburma_logic_device *ldev, uint8_t port_num)
{
	kobject_put(&ldev->port[port_num].kobj);
}

void uburma_remove_fe_attr_files(struct uburma_logic_device *ldev, uint16_t fe_num)
{
	kobject_put(&ldev->fe[fe_num].kobj);
}

void uburma_remove_eid_attr_files(struct uburma_logic_device *ldev, uint32_t eid_num)
{
	kobject_put(&ldev->eid[eid_num].kobj);
}

void uburma_remove_dev_attr_files(struct uburma_logic_device *ldev)
{
	sysfs_remove_group(&ldev->dev->kobj, &uburma_dev_attr_group);
}
