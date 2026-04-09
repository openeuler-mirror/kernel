// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2025. All rights reserved.
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
#include <ub/urma/ubcore_types.h>
#include <ub/urma/ubcore_uapi.h>
#include "ubcore_log.h"
#include "ubcore_device.h"
#include "ubcore_cdev_file.h"

#define UBCORE_MAX_VALUE_LEN 24
#define UBCORE_READ_ONLY_MODE 0444
#define UBCORE_RESERVED_JETTY_PARAM_NUM 2

/* callback information */
typedef ssize_t (*ubcore_show_attr_cb)(struct ubcore_device *dev, char *buf);
typedef ssize_t (*ubcore_store_attr_cb)(struct ubcore_device *dev,
					const char *buf, size_t len);
typedef ssize_t (*ubcore_show_port_attr_cb)(struct ubcore_device *dev,
					    char *buf, uint8_t port_id);
typedef ssize_t (*ubcore_show_priority_attr_cb)(struct ubcore_device *dev,
	char *buf, uint8_t priority_id);

static inline struct ubcore_device *
get_ubcore_device(struct ubcore_logic_device *ldev)
{
	return ldev == NULL ? NULL : ldev->ub_dev;
}

static ssize_t ubcore_show_dev_attr(struct device *dev,
				    struct device_attribute *attr, char *buf,
				    ubcore_show_attr_cb show_cb)
{
	struct ubcore_logic_device *ldev = dev_get_drvdata(dev);
	struct ubcore_device *ub_dev = get_ubcore_device(ldev);

	if (!ldev || !ub_dev || !buf) {
		ubcore_log_err("Invalid argument.\n");
		return -EINVAL;
	}

	return show_cb(ub_dev, buf);
}

static ssize_t ubcore_store_dev_attr(struct device *dev,
				     struct device_attribute *attr,
				     const char *buf, size_t len,
				     ubcore_store_attr_cb store_cb)
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

static ssize_t ubdev_show(struct device *dev, struct device_attribute *attr,
			  char *buf)
{
	return ubcore_show_dev_attr(dev, attr, buf, ubdev_show_cb);
}

static DEVICE_ATTR_RO(ubdev);

static ssize_t guid_show_cb(struct ubcore_device *dev, char *buf)
{
	return snprintf(
		buf, (UBCORE_EID_STR_LEN + 1) + 1, EID_FMT "\n",
		EID_ARGS(
			dev->attr.guid)); // The format of  GUID is the same as EID.
}

static ssize_t guid_show(struct device *dev, struct device_attribute *attr,
			 char *buf)
{
	return ubcore_show_dev_attr(dev, attr, buf, guid_show_cb);
}

static DEVICE_ATTR_RO(guid);

static ssize_t max_upi_cnt_show_cb(struct ubcore_device *dev, char *buf)
{
	return snprintf(buf, UBCORE_MAX_VALUE_LEN, "%u\n",
			dev->attr.dev_cap.max_upi_cnt);
}

static ssize_t max_upi_cnt_show(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	return ubcore_show_dev_attr(dev, attr, buf, max_upi_cnt_show_cb);
}

static DEVICE_ATTR_RO(max_upi_cnt);

static ssize_t feature_show_cb(struct ubcore_device *dev, char *buf)
{
	return snprintf(buf, UBCORE_MAX_VALUE_LEN, "0x%x\n",
			dev->attr.dev_cap.feature.value);
}

static ssize_t feature_show(struct device *dev, struct device_attribute *attr,
			    char *buf)
{
	return ubcore_show_dev_attr(dev, attr, buf, feature_show_cb);
}

static DEVICE_ATTR_RO(feature);

static ssize_t max_jfc_show_cb(struct ubcore_device *dev, char *buf)
{
	return snprintf(buf, UBCORE_MAX_VALUE_LEN, "%u\n",
			dev->attr.dev_cap.max_jfc);
}

static ssize_t max_jfc_show(struct device *dev, struct device_attribute *attr,
			    char *buf)
{
	return ubcore_show_dev_attr(dev, attr, buf, max_jfc_show_cb);
}

static DEVICE_ATTR_RO(max_jfc);

static ssize_t max_jfs_show_cb(struct ubcore_device *dev, char *buf)
{
	return snprintf(buf, UBCORE_MAX_VALUE_LEN, "%u\n",
			dev->attr.dev_cap.max_jfs);
}

static ssize_t max_jfs_show(struct device *dev, struct device_attribute *attr,
			    char *buf)
{
	return ubcore_show_dev_attr(dev, attr, buf, max_jfs_show_cb);
}

static DEVICE_ATTR_RO(max_jfs);

static ssize_t max_jfr_show_cb(struct ubcore_device *dev, char *buf)
{
	return snprintf(buf, UBCORE_MAX_VALUE_LEN, "%u\n",
			dev->attr.dev_cap.max_jfr);
}

static ssize_t max_jfr_show(struct device *dev, struct device_attribute *attr,
			    char *buf)
{
	return ubcore_show_dev_attr(dev, attr, buf, max_jfr_show_cb);
}

static DEVICE_ATTR_RO(max_jfr);

static ssize_t max_jetty_show_cb(struct ubcore_device *dev, char *buf)
{
	return snprintf(buf, UBCORE_MAX_VALUE_LEN, "%u\n",
			dev->attr.dev_cap.max_jetty);
}

static ssize_t max_jetty_show(struct device *dev, struct device_attribute *attr,
			      char *buf)
{
	return ubcore_show_dev_attr(dev, attr, buf, max_jetty_show_cb);
}

static DEVICE_ATTR_RO(max_jetty);

static ssize_t show_max_jetty_grp_cb(struct ubcore_device *dev, char *buf)
{
	return snprintf(buf, UBCORE_MAX_VALUE_LEN, "%u\n",
			dev->attr.dev_cap.max_jetty_grp);
}
static ssize_t max_jetty_grp_show(struct device *dev,
				  struct device_attribute *attr, char *buf)
{
	return ubcore_show_dev_attr(dev, attr, buf, show_max_jetty_grp_cb);
}
static DEVICE_ATTR_RO(max_jetty_grp);

static ssize_t show_max_jetty_in_jetty_grp_cb(struct ubcore_device *dev,
					      char *buf)
{
	return snprintf(buf, UBCORE_MAX_VALUE_LEN, "%u\n",
			dev->attr.dev_cap.max_jetty_in_jetty_grp);
}
static ssize_t max_jetty_in_jetty_grp_show(struct device *dev,
					   struct device_attribute *attr,
					   char *buf)
{
	return ubcore_show_dev_attr(dev, attr, buf,
				    show_max_jetty_in_jetty_grp_cb);
}
static DEVICE_ATTR_RO(max_jetty_in_jetty_grp);

static ssize_t max_jfc_depth_show_cb(struct ubcore_device *dev, char *buf)
{
	return snprintf(buf, UBCORE_MAX_VALUE_LEN, "%u\n",
			dev->attr.dev_cap.max_jfc_depth);
}

static ssize_t max_jfc_depth_show(struct device *dev,
				  struct device_attribute *attr, char *buf)
{
	return ubcore_show_dev_attr(dev, attr, buf, max_jfc_depth_show_cb);
}

static DEVICE_ATTR_RO(max_jfc_depth);

static ssize_t max_jfs_depth_show_cb(struct ubcore_device *dev, char *buf)
{
	return snprintf(buf, UBCORE_MAX_VALUE_LEN, "%u\n",
			dev->attr.dev_cap.max_jfs_depth);
}

static ssize_t max_jfs_depth_show(struct device *dev,
				  struct device_attribute *attr, char *buf)
{
	return ubcore_show_dev_attr(dev, attr, buf, max_jfs_depth_show_cb);
}

static DEVICE_ATTR_RO(max_jfs_depth);

static ssize_t max_jfr_depth_show_cb(struct ubcore_device *dev, char *buf)
{
	return snprintf(buf, UBCORE_MAX_VALUE_LEN, "%u\n",
			dev->attr.dev_cap.max_jfr_depth);
}

static ssize_t max_jfr_depth_show(struct device *dev,
				  struct device_attribute *attr, char *buf)
{
	return ubcore_show_dev_attr(dev, attr, buf, max_jfr_depth_show_cb);
}

static DEVICE_ATTR_RO(max_jfr_depth);

static ssize_t show_max_jfs_inline_size_cb(struct ubcore_device *dev, char *buf)
{
	return snprintf(buf, UBCORE_MAX_VALUE_LEN, "%u\n",
			dev->attr.dev_cap.max_jfs_inline_size);
}

static ssize_t max_jfs_inline_size_show(struct device *dev,
					struct device_attribute *attr,
					char *buf)
{
	return ubcore_show_dev_attr(dev, attr, buf,
				    show_max_jfs_inline_size_cb);
}

static DEVICE_ATTR_RO(max_jfs_inline_size);

static ssize_t max_jfs_sge_show_cb(struct ubcore_device *dev, char *buf)
{
	return snprintf(buf, UBCORE_MAX_VALUE_LEN, "%u\n",
			dev->attr.dev_cap.max_jfs_sge);
}

static ssize_t max_jfs_sge_show(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	return ubcore_show_dev_attr(dev, attr, buf, max_jfs_sge_show_cb);
}

static DEVICE_ATTR_RO(max_jfs_sge);

static ssize_t max_jfs_rsge_show_cb(struct ubcore_device *dev, char *buf)
{
	return snprintf(buf, UBCORE_MAX_VALUE_LEN, "%u\n",
			dev->attr.dev_cap.max_jfs_rsge);
}

static ssize_t max_jfs_rsge_show(struct device *dev,
				 struct device_attribute *attr, char *buf)
{
	return ubcore_show_dev_attr(dev, attr, buf, max_jfs_rsge_show_cb);
}

static DEVICE_ATTR_RO(max_jfs_rsge);

static ssize_t max_jfr_sge_show_cb(struct ubcore_device *dev, char *buf)
{
	return snprintf(buf, UBCORE_MAX_VALUE_LEN, "%u\n",
			dev->attr.dev_cap.max_jfr_sge);
}

static ssize_t max_jfr_sge_show(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	return ubcore_show_dev_attr(dev, attr, buf, max_jfr_sge_show_cb);
}

static DEVICE_ATTR_RO(max_jfr_sge);

static ssize_t max_msg_size_show_cb(struct ubcore_device *dev, char *buf)
{
	return snprintf(buf, UBCORE_MAX_VALUE_LEN, "%llu\n",
			dev->attr.dev_cap.max_msg_size);
}

static ssize_t max_msg_size_show(struct device *dev,
				 struct device_attribute *attr, char *buf)
{
	return ubcore_show_dev_attr(dev, attr, buf, max_msg_size_show_cb);
}

static DEVICE_ATTR_RO(max_msg_size);

static ssize_t show_max_read_size_cb(struct ubcore_device *dev, char *buf)
{
	return snprintf(buf, UBCORE_MAX_VALUE_LEN, "%u\n",
			dev->attr.dev_cap.max_read_size);
}
static ssize_t max_read_size_show(struct device *dev,
				  struct device_attribute *attr, char *buf)
{
	return ubcore_show_dev_attr(dev, attr, buf, show_max_read_size_cb);
}
static DEVICE_ATTR_RO(max_read_size);

static ssize_t show_max_write_size_cb(struct ubcore_device *dev, char *buf)
{
	return snprintf(buf, UBCORE_MAX_VALUE_LEN, "%u\n",
			dev->attr.dev_cap.max_write_size);
}
static ssize_t max_write_size_show(struct device *dev,
				   struct device_attribute *attr, char *buf)
{
	return ubcore_show_dev_attr(dev, attr, buf, show_max_write_size_cb);
}
static DEVICE_ATTR_RO(max_write_size);

static ssize_t show_max_cas_size_cb(struct ubcore_device *dev, char *buf)
{
	return snprintf(buf, UBCORE_MAX_VALUE_LEN, "%u\n",
			dev->attr.dev_cap.max_cas_size);
}
static ssize_t max_cas_size_show(struct device *dev,
				 struct device_attribute *attr, char *buf)
{
	return ubcore_show_dev_attr(dev, attr, buf, show_max_cas_size_cb);
}
static DEVICE_ATTR_RO(max_cas_size);

static ssize_t show_max_swap_size_cb(struct ubcore_device *dev, char *buf)
{
	return snprintf(buf, UBCORE_MAX_VALUE_LEN, "%u\n",
			dev->attr.dev_cap.max_swap_size);
}
static ssize_t max_swap_size_show(struct device *dev,
				  struct device_attribute *attr, char *buf)
{
	return ubcore_show_dev_attr(dev, attr, buf, show_max_swap_size_cb);
}
static DEVICE_ATTR_RO(max_swap_size);

static ssize_t show_max_fetch_and_add_size_cb(struct ubcore_device *dev,
					      char *buf)
{
	return snprintf(buf, UBCORE_MAX_VALUE_LEN, "%u\n",
			dev->attr.dev_cap.max_fetch_and_add_size);
}
static ssize_t max_fetch_and_add_size_show(struct device *dev,
					   struct device_attribute *attr,
					   char *buf)
{
	return ubcore_show_dev_attr(dev, attr, buf,
				    show_max_fetch_and_add_size_cb);
}
static DEVICE_ATTR_RO(max_fetch_and_add_size);

static ssize_t show_max_fetch_and_sub_size_cb(struct ubcore_device *dev,
					      char *buf)
{
	return snprintf(buf, UBCORE_MAX_VALUE_LEN, "%u\n",
			dev->attr.dev_cap.max_fetch_and_sub_size);
}
static ssize_t max_fetch_and_sub_size_show(struct device *dev,
					   struct device_attribute *attr,
					   char *buf)
{
	return ubcore_show_dev_attr(dev, attr, buf,
				    show_max_fetch_and_sub_size_cb);
}
static DEVICE_ATTR_RO(max_fetch_and_sub_size);

static ssize_t show_max_fetch_and_and_size_cb(struct ubcore_device *dev,
					      char *buf)
{
	return snprintf(buf, UBCORE_MAX_VALUE_LEN, "%u\n",
			dev->attr.dev_cap.max_fetch_and_and_size);
}
static ssize_t max_fetch_and_and_size_show(struct device *dev,
					   struct device_attribute *attr,
					   char *buf)
{
	return ubcore_show_dev_attr(dev, attr, buf,
				    show_max_fetch_and_and_size_cb);
}
static DEVICE_ATTR_RO(max_fetch_and_and_size);

static ssize_t show_max_fetch_and_or_size_cb(struct ubcore_device *dev,
					     char *buf)
{
	return snprintf(buf, UBCORE_MAX_VALUE_LEN, "%u\n",
			dev->attr.dev_cap.max_fetch_and_or_size);
}
static ssize_t max_fetch_and_or_size_show(struct device *dev,
					  struct device_attribute *attr,
					  char *buf)
{
	return ubcore_show_dev_attr(dev, attr, buf,
				    show_max_fetch_and_or_size_cb);
}
static DEVICE_ATTR_RO(max_fetch_and_or_size);

static ssize_t show_max_fetch_and_xor_size_cb(struct ubcore_device *dev,
					      char *buf)
{
	return snprintf(buf, UBCORE_MAX_VALUE_LEN, "%u\n",
			dev->attr.dev_cap.max_fetch_and_xor_size);
}
static ssize_t max_fetch_and_xor_size_show(struct device *dev,
					   struct device_attribute *attr,
					   char *buf)
{
	return ubcore_show_dev_attr(dev, attr, buf,
				    show_max_fetch_and_xor_size_cb);
}
static DEVICE_ATTR_RO(max_fetch_and_xor_size);

static ssize_t show_atomic_feat_cb(struct ubcore_device *dev, char *buf)
{
	return snprintf(buf, UBCORE_MAX_VALUE_LEN, "%u\n",
			dev->attr.dev_cap.atomic_feat.value);
}
static ssize_t atomic_feat_show(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	return ubcore_show_dev_attr(dev, attr, buf, show_atomic_feat_cb);
}
static DEVICE_ATTR_RO(atomic_feat);

static ssize_t max_rc_outstd_cnt_show_cb(struct ubcore_device *dev, char *buf)
{
	return snprintf(buf, UBCORE_MAX_VALUE_LEN, "%llu\n",
			dev->attr.dev_cap.max_rc_outstd_cnt);
}

static ssize_t max_rc_outstd_cnt_show(struct device *dev,
				      struct device_attribute *attr, char *buf)
{
	return ubcore_show_dev_attr(dev, attr, buf, max_rc_outstd_cnt_show_cb);
}

static DEVICE_ATTR_RO(max_rc_outstd_cnt);

static ssize_t trans_mode_show_cb(struct ubcore_device *dev, char *buf)
{
	return snprintf(buf, UBCORE_MAX_VALUE_LEN, "%u\n",
			dev->attr.dev_cap.trans_mode);
}

static ssize_t trans_mode_show(struct device *dev,
			       struct device_attribute *attr, char *buf)
{
	return ubcore_show_dev_attr(dev, attr, buf, trans_mode_show_cb);
}

static DEVICE_ATTR_RO(trans_mode);

static ssize_t congestion_ctrl_alg_show_cb(struct ubcore_device *dev, char *buf)
{
	return snprintf(buf, UBCORE_MAX_VALUE_LEN, "%u\n",
			dev->attr.dev_cap.congestion_ctrl_alg);
}

static ssize_t congestion_ctrl_alg_show(struct device *dev,
					struct device_attribute *attr,
					char *buf)
{
	return ubcore_show_dev_attr(dev, attr, buf,
				    congestion_ctrl_alg_show_cb);
}

static ssize_t congestion_ctrl_alg_store_cb(struct ubcore_device *dev,
					    const char *buf, size_t len)
{
	uint16_t value;
	int ret;

	ret = kstrtou16(buf, 0, &value);
	if (ret != 0)
		return -EINVAL;

	dev->attr.dev_cap.congestion_ctrl_alg = value;
	return (ssize_t)len;
}

static ssize_t congestion_ctrl_alg_store(struct device *dev,
					 struct device_attribute *attr,
					 const char *buf, size_t len)
{
	return ubcore_store_dev_attr(dev, attr, buf, len,
				     congestion_ctrl_alg_store_cb);
}

static DEVICE_ATTR_RW(congestion_ctrl_alg); // 0644

static ssize_t ceq_cnt_show_cb(struct ubcore_device *dev, char *buf)
{
	return snprintf(buf, UBCORE_MAX_VALUE_LEN, "%u\n",
			dev->attr.dev_cap.ceq_cnt);
}

static ssize_t ceq_cnt_show(struct device *dev, struct device_attribute *attr,
			    char *buf)
{
	return ubcore_show_dev_attr(dev, attr, buf, ceq_cnt_show_cb);
}

static DEVICE_ATTR_RO(ceq_cnt);

static ssize_t utp_cnt_show_cb(struct ubcore_device *dev, char *buf)
{
	return snprintf(buf, UBCORE_MAX_VALUE_LEN, "%u\n",
			dev->attr.dev_cap.max_utp_cnt);
}

static ssize_t utp_cnt_show(struct device *dev, struct device_attribute *attr,
			    char *buf)
{
	return ubcore_show_dev_attr(dev, attr, buf, utp_cnt_show_cb);
}

static DEVICE_ATTR_RO(utp_cnt);

static ssize_t max_tp_in_tpg_show_cb(struct ubcore_device *dev, char *buf)
{
	return snprintf(buf, UBCORE_MAX_VALUE_LEN, "%u\n",
			dev->attr.dev_cap.max_tp_in_tpg);
}

static ssize_t max_tp_in_tpg_show(struct device *dev,
				  struct device_attribute *attr, char *buf)
{
	return ubcore_show_dev_attr(dev, attr, buf, max_tp_in_tpg_show_cb);
}

static DEVICE_ATTR_RO(max_tp_in_tpg);

static ssize_t max_oor_cnt_show_cb(struct ubcore_device *dev, char *buf)
{
	return snprintf(buf, UBCORE_MAX_VALUE_LEN, "%u\n",
			dev->attr.dev_cap.max_oor_cnt);
}

static ssize_t max_oor_cnt_show(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	return ubcore_show_dev_attr(dev, attr, buf, max_oor_cnt_show_cb);
}

static DEVICE_ATTR_RO(max_oor_cnt);

static ssize_t mn_show_cb(struct ubcore_device *dev, char *buf)
{
	return snprintf(buf, UBCORE_MAX_VALUE_LEN, "%u\n",
			dev->attr.dev_cap.mn);
}

static ssize_t mn_show(struct device *dev, struct device_attribute *attr,
		       char *buf)
{
	return ubcore_show_dev_attr(dev, attr, buf, mn_show_cb);
}

static DEVICE_ATTR_RO(mn);

static ssize_t max_netaddr_cnt_show_cb(struct ubcore_device *dev, char *buf)
{
	return snprintf(buf, UBCORE_MAX_VALUE_LEN, "%u\n",
			dev->attr.dev_cap.max_netaddr_cnt);
}

static ssize_t max_netaddr_cnt_show(struct device *dev,
				    struct device_attribute *attr, char *buf)
{
	return ubcore_show_dev_attr(dev, attr, buf, max_netaddr_cnt_show_cb);
}

static DEVICE_ATTR_RO(max_netaddr_cnt);

static ssize_t port_count_show_cb(struct ubcore_device *dev, char *buf)
{
	return snprintf(buf, UBCORE_MAX_VALUE_LEN, "%u\n", dev->attr.port_cnt);
}

static ssize_t port_count_show(struct device *dev,
			       struct device_attribute *attr, char *buf)
{
	return ubcore_show_dev_attr(dev, attr, buf, port_count_show_cb);
}

static DEVICE_ATTR_RO(port_count);

static ssize_t virtualization_show_cb(struct ubcore_device *dev, char *buf)
{
	return snprintf(buf, UBCORE_MAX_VALUE_LEN, "%s\n",
			dev->attr.virtualization ? "true" : "false");
}
static ssize_t virtualization_show(struct device *dev,
				   struct device_attribute *attr, char *buf)
{
	return ubcore_show_dev_attr(dev, attr, buf, virtualization_show_cb);
}
static DEVICE_ATTR_RO(virtualization);

static ssize_t tp_maintainer_show_cb(struct ubcore_device *dev, char *buf)
{
	return snprintf(buf, UBCORE_MAX_VALUE_LEN, "%s\n",
			dev->attr.tp_maintainer ? "true" : "false");
}
static ssize_t tp_maintainer_show(struct device *dev,
				  struct device_attribute *attr, char *buf)
{
	return ubcore_show_dev_attr(dev, attr, buf, tp_maintainer_show_cb);
}
static DEVICE_ATTR_RO(tp_maintainer);

static ssize_t show_ue_cnt_cb(struct ubcore_device *dev, char *buf)
{
	return snprintf(buf, UBCORE_MAX_VALUE_LEN, "%u\n",
			dev->attr.dev_cap.max_ue_cnt);
}
static ssize_t ue_cnt_show(struct device *dev, struct device_attribute *attr,
			   char *buf)
{
	return ubcore_show_dev_attr(dev, attr, buf, show_ue_cnt_cb);
}
static DEVICE_ATTR_RO(ue_cnt);

static ssize_t show_page_size_cap_cb(struct ubcore_device *dev, char *buf)
{
	return snprintf(buf, UBCORE_MAX_VALUE_LEN, "0x%llx\n",
			dev->attr.dev_cap.page_size_cap);
}

static ssize_t page_size_cap_show(struct device *dev,
				  struct device_attribute *attr, char *buf)
{
	return ubcore_show_dev_attr(dev, attr, buf, show_page_size_cap_cb);
}
static DEVICE_ATTR_RO(page_size_cap);

static ssize_t show_dynamic_eid_cb(struct ubcore_device *dev, char *buf)
{
	return snprintf(buf, UBCORE_MAX_VALUE_LEN, "%d\n", dev->dynamic_eid);
}
static ssize_t dynamic_eid_show(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	return ubcore_show_dev_attr(dev, attr, buf, show_dynamic_eid_cb);
}
static DEVICE_ATTR_RO(dynamic_eid);

static ssize_t max_eid_cnt_show_cb(struct ubcore_device *dev, char *buf)
{
	return snprintf(buf, UBCORE_MAX_VALUE_LEN, "%u\n",
			dev->attr.dev_cap.max_eid_cnt);
}

static ssize_t max_eid_cnt_show(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	return ubcore_show_dev_attr(dev, attr, buf, max_eid_cnt_show_cb);
}

static DEVICE_ATTR_RO(max_eid_cnt);

static ssize_t transport_type_show_cb(struct ubcore_device *dev, char *buf)
{
	return snprintf(buf, UBCORE_MAX_VALUE_LEN, "%d\n",
			(int)dev->transport_type);
}

static ssize_t transport_type_show(struct device *dev,
				   struct device_attribute *attr, char *buf)
{
	return ubcore_show_dev_attr(dev, attr, buf, transport_type_show_cb);
}

static DEVICE_ATTR_RO(transport_type);

static ssize_t driver_name_show_cb(struct ubcore_device *dev, char *buf)
{
	if (!dev->ops)
		return -EINVAL;

	return snprintf(buf, UBCORE_MAX_DRIVER_NAME, "%s\n",
			dev->ops->driver_name);
}

static ssize_t driver_name_show(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	return ubcore_show_dev_attr(dev, attr, buf, driver_name_show_cb);
}

static DEVICE_ATTR_RO(driver_name);

static ssize_t reserved_jetty_id_show_cb(struct ubcore_device *dev, char *buf)
{
	int ret = 0;

	ret = ubcore_query_device_attr(dev, &dev->attr);
	if (ret != 0) {
		ubcore_log_err("failed query device attr.\n");
		return ret;
	}
	return snprintf(buf, UBCORE_MAX_VALUE_LEN, "%u-%u\n",
			dev->attr.reserved_jetty_id_min,
			dev->attr.reserved_jetty_id_max);
}

static ssize_t reserved_jetty_id_show(struct device *dev,
				      struct device_attribute *attr, char *buf)
{
	return ubcore_show_dev_attr(dev, attr, buf, reserved_jetty_id_show_cb);
}

static ssize_t reserved_jetty_id_store_cb(struct ubcore_device *dev,
					  const char *buf, size_t len)
{
	uint32_t min_jetty_id = 0;
	uint32_t max_jetty_id = 0;
	int ret;

	ret = sscanf(buf, "%u-%u", &min_jetty_id, &max_jetty_id);
	if (ret != UBCORE_RESERVED_JETTY_PARAM_NUM)
		return -EINVAL;

	if (max_jetty_id < min_jetty_id) {
		ubcore_log_err(
			"Invalid param min jetty id:%u, max jetty id:%u\n",
			min_jetty_id, max_jetty_id);
		return -EINVAL;
	}

	ret = ubcore_config_rsvd_jetty(dev, min_jetty_id, max_jetty_id);
	if (ret != 0) {
		ubcore_log_err("dev:%s, cfg min jetty id:%u, max jetty id:%u\n",
			       dev->dev_name, min_jetty_id, max_jetty_id);
		return -EINVAL;
	}

	return (ssize_t)len;
}

static ssize_t reserved_jetty_id_store(struct device *dev,
				       struct device_attribute *attr,
				       const char *buf, size_t len)
{
	return ubcore_store_dev_attr(dev, attr, buf, len,
				     reserved_jetty_id_store_cb);
}

static DEVICE_ATTR_RW(reserved_jetty_id); // 0644

static ssize_t net_dev_show_cb(struct ubcore_device *dev, char *buf)
{
	struct net_device *net_dev;
	int ret = 0;

	if (!dev->netdev)
		return 0;

	rcu_read_lock();
	net_dev = rcu_dereference(dev->netdev);
	if (net_dev)
		ret = snprintf(buf, IFNAMSIZ, "%s\n", net_dev->name);
	rcu_read_unlock();

	return ret;
}

static ssize_t net_dev_show(struct device *dev, struct device_attribute *attr,
			    char *buf)
{
	return ubcore_show_dev_attr(dev, attr, buf, net_dev_show_cb);
}

static DEVICE_ATTR_RO(net_dev);

/* One eid line has up to 51 bytes with the format:
 * "4294967295 0000:0000:0000:0000:0000:ffff:7f00:0001\n"
 * sysfs buf size is PAGESIZE, up to 80 eid lines are supported in the sysfs
 */
#define UBCORE_MAX_EID_LINE 51

static ssize_t eid_show_cb(struct ubcore_device *dev, char *buf,
			   struct net *net, uint32_t eid_idx)
{
	union ubcore_eid invalid_eid = { 0 };
	struct ubcore_eid_entry *e;
	ssize_t len = 0;

	spin_lock(&dev->eid_table.lock);
	if (!dev->eid_table.eid_entries ||
	    eid_idx >= dev->eid_table.eid_cnt) {
		spin_unlock(&dev->eid_table.lock);
		return -EINVAL;
	}

	e = &dev->eid_table.eid_entries[eid_idx];
	if (!e->valid || !net_eq(e->net, net))
		len = snprintf(buf, UBCORE_MAX_EID_LINE, "" EID_FMT "\n",
			       EID_ARGS(invalid_eid));
	else
		len = snprintf(buf, UBCORE_MAX_EID_LINE, "" EID_FMT "\n",
			       EID_ARGS(e->eid));

	spin_unlock(&dev->eid_table.lock);
	return len;
}

static ssize_t eid_show(struct device *dev, struct device_attribute *attr,
			char *buf)
{
	struct ubcore_eid_attr *eid_attr =
		container_of(attr, struct ubcore_eid_attr, attr);
	struct ubcore_logic_device *ldev = dev_get_drvdata(dev);
	struct ubcore_device *ub_dev = get_ubcore_device(ldev);

	if (!ldev || !ub_dev || !buf) {
		ubcore_log_err("Invalid argument.\n");
		return -EINVAL;
	}

	return eid_show_cb(ub_dev, buf, read_pnet(&ldev->net),
			   eid_attr->eid_idx);
}

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
	&dev_attr_max_read_size.attr,
	&dev_attr_max_write_size.attr,
	&dev_attr_max_cas_size.attr,
	&dev_attr_max_swap_size.attr,
	&dev_attr_max_fetch_and_add_size.attr,
	&dev_attr_max_fetch_and_sub_size.attr,
	&dev_attr_max_fetch_and_and_size.attr,
	&dev_attr_max_fetch_and_or_size.attr,
	&dev_attr_max_fetch_and_xor_size.attr,
	&dev_attr_atomic_feat.attr,
	&dev_attr_max_rc_outstd_cnt.attr,
	&dev_attr_trans_mode.attr,
	&dev_attr_congestion_ctrl_alg.attr,
	&dev_attr_ceq_cnt.attr,
	&dev_attr_utp_cnt.attr,
	&dev_attr_max_tp_in_tpg.attr,
	&dev_attr_max_oor_cnt.attr,
	&dev_attr_mn.attr,
	&dev_attr_max_netaddr_cnt.attr,
	&dev_attr_port_count.attr,
	&dev_attr_ue_cnt.attr,
	&dev_attr_page_size_cap.attr,
	&dev_attr_max_eid_cnt.attr,
	&dev_attr_dynamic_eid.attr,
	&dev_attr_virtualization.attr,
	&dev_attr_tp_maintainer.attr,
	&dev_attr_transport_type.attr,
	&dev_attr_driver_name.attr,
	&dev_attr_reserved_jetty_id.attr,
	&dev_attr_net_dev.attr,
	NULL,
};

static const struct attribute_group ubcore_dev_attr_group = {
	.attrs = ubcore_dev_attrs,
};

static ssize_t ubcore_show_port_attr(struct ubcore_port_kobj *p,
				     struct ubcore_port_attribute *attr,
				     char *buf,
				     ubcore_show_port_attr_cb show_cb)
{
	struct ubcore_device *dev = p->dev;

	if (!dev || !buf) {
		ubcore_log_err("Invalid argument.\n");
		return -EINVAL;
	}

	return show_cb(dev, buf, p->port_id);
}

static ssize_t max_mtu_show_cb(struct ubcore_device *dev, char *buf,
			       uint8_t port_id)
{
	return snprintf(buf, UBCORE_MAX_VALUE_LEN, "%d\n",
			(int)dev->attr.port_attr[port_id].max_mtu);
}

static ssize_t max_mtu_show(struct ubcore_port_kobj *p,
			    struct ubcore_port_attribute *attr, char *buf)
{
	return ubcore_show_port_attr(p, attr, buf, max_mtu_show_cb);
}

static PORT_ATTR_RO(max_mtu);

static ssize_t state_show_cb(struct ubcore_device *dev, char *buf,
			     uint8_t port_id)
{
	struct ubcore_device_status status;

	if (ubcore_query_device_status(dev, &status) != 0) {
		ubcore_log_err("query device status for state failed.\n");
		return -EPERM;
	}

	return snprintf(buf, UBCORE_MAX_VALUE_LEN, "%u\n",
			(uint32_t)status.port_status[port_id].state);
}

static ssize_t state_show(struct ubcore_port_kobj *p,
			  struct ubcore_port_attribute *attr, char *buf)
{
	return ubcore_show_port_attr(p, attr, buf, state_show_cb);
}

static PORT_ATTR_RO(state);

static ssize_t active_speed_show_cb(struct ubcore_device *dev, char *buf,
				    uint8_t port_id)
{
	struct ubcore_device_status status;

	if (ubcore_query_device_status(dev, &status) != 0) {
		ubcore_log_err(
			"query device status for active speed failed.\n");
		return -EPERM;
	}

	return snprintf(buf, UBCORE_MAX_VALUE_LEN, "%u\n",
			status.port_status[port_id].active_speed);
}

static ssize_t active_speed_show(struct ubcore_port_kobj *p,
				 struct ubcore_port_attribute *attr, char *buf)
{
	return ubcore_show_port_attr(p, attr, buf, active_speed_show_cb);
}

static PORT_ATTR_RO(active_speed);

static ssize_t active_width_show_cb(struct ubcore_device *dev, char *buf,
				    uint8_t port_id)
{
	struct ubcore_device_status status;

	if (ubcore_query_device_status(dev, &status) != 0) {
		ubcore_log_err(
			"query device status for active width failed.\n");
		return -EPERM;
	}

	return snprintf(buf, UBCORE_MAX_VALUE_LEN, "%u\n",
			status.port_status[port_id].active_width);
}

static ssize_t active_width_show(struct ubcore_port_kobj *p,
				 struct ubcore_port_attribute *attr, char *buf)
{
	return ubcore_show_port_attr(p, attr, buf, active_width_show_cb);
}

static PORT_ATTR_RO(active_width);

static ssize_t active_mtu_show_cb(struct ubcore_device *dev, char *buf,
				  uint8_t port_id)
{
	struct ubcore_device_status status;

	if (ubcore_query_device_status(dev, &status) != 0) {
		ubcore_log_err("query device status for active mtu failed.\n");
		return -EPERM;
	}

	return snprintf(buf, UBCORE_MAX_VALUE_LEN, "%u\n",
			(uint32_t)status.port_status[port_id].active_mtu);
}

static ssize_t active_mtu_show(struct ubcore_port_kobj *p,
			       struct ubcore_port_attribute *attr, char *buf)
{
	return ubcore_show_port_attr(p, attr, buf, active_mtu_show_cb);
}

static PORT_ATTR_RO(active_mtu);

static struct attribute *ubcore_port_attrs[] = {
	&port_attr_max_mtu.attr,      &port_attr_state.attr,
	&port_attr_active_speed.attr, &port_attr_active_width.attr,
	&port_attr_active_mtu.attr,   NULL,
};

static ssize_t ubcore_port_attr_show(struct kobject *kobj,
				     struct attribute *attr, char *buf)
{
	struct ubcore_port_attribute *port_attr =
		container_of(attr, struct ubcore_port_attribute, attr);
	struct ubcore_port_kobj *p =
		container_of(kobj, struct ubcore_port_kobj, kobj);

	if (!port_attr->show)
		return -EIO;

	return port_attr->show(p, port_attr, buf);
}

static ssize_t ubcore_port_attr_store(struct kobject *kobj,
				      struct attribute *attr, const char *buf,
				      size_t count)
{
	struct ubcore_port_attribute *port_attr =
		container_of(attr, struct ubcore_port_attribute, attr);
	struct ubcore_port_kobj *p =
		container_of(kobj, struct ubcore_port_kobj, kobj);

	if (!port_attr->store)
		return -EIO;

	return port_attr->store(p, port_attr, buf, count);
}

static const struct sysfs_ops ubcore_port_sysfs_ops = {
	.show = ubcore_port_attr_show,
	.store = ubcore_port_attr_store
};

static void ubcore_port_release(struct kobject *kobj)
{
}

// ATTRIBUTE_GROUPS defined in 3.11, but must be consistent with kobj_type->default_groups
ATTRIBUTE_GROUPS(ubcore_port);

static const struct kobj_type ubcore_port_type = {
	.release = ubcore_port_release,
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

	return kobject_init_and_add(&p->kobj, &ubcore_port_type,
				    &ldev->dev->kobj, "port%hhu", port_id);
}

static struct attribute_group *
ubcore_alloc_eids_group(struct ubcore_logic_device *ldev)
{
	struct ubcore_eid_attr *eid_attr_list = NULL;
	struct attribute_group *attr_grp = NULL;
	struct attribute **attr_list = NULL;
	uint32_t eid_cnt = 0;
	uint32_t i;

	eid_cnt = ldev->ub_dev->eid_table.eid_cnt;
	if (eid_cnt == 0 || eid_cnt > UBCORE_MAX_EID_CNT)
		return NULL;

	attr_grp = kcalloc(1, sizeof(*attr_grp), GFP_KERNEL);
	if (!attr_grp)
		return NULL;

	attr_list = kcalloc(eid_cnt + 1, sizeof(*attr_list), GFP_KERNEL);
	if (!attr_list)
		goto free_grp;

	eid_attr_list =
		kcalloc(eid_cnt, sizeof(struct ubcore_eid_attr), GFP_KERNEL);
	if (!eid_attr_list)
		goto free_attr_list;

	// create /sys/class/dev_name/eids/eid_x
	for (i = 0; i < eid_cnt; i++) {
		struct ubcore_eid_attr *eid_attr = &eid_attr_list[i];

		if (snprintf(eid_attr->name, UBCORE_EID_GROUP_NAME_LEN - 1,
			     "eid%d", i) < 0)
			goto free_eid_attr;

		sysfs_attr_init(&eid_attr->attr.attr);
		eid_attr->attr.attr.name = eid_attr->name;
		eid_attr->attr.attr.mode = UBCORE_READ_ONLY_MODE;
		eid_attr->attr.show = eid_show;
		eid_attr->eid_idx = i;
		attr_list[i] = &eid_attr->attr.attr;
	}

	attr_grp->name = "eids";
	attr_grp->attrs = attr_list;
	return attr_grp;

free_eid_attr:
	kfree(eid_attr_list);
free_attr_list:
	kfree(attr_list);
free_grp:
	kfree(attr_grp);
	return NULL;
}

static void ubcore_free_eids_group(struct ubcore_logic_device *ldev)
{
	const struct attribute_group *eid_grp;
	struct ubcore_eid_attr *eid_attr_list;
	struct device_attribute *dev_attr;

	eid_grp = ldev->dev_group[UBCORE_ATTR_GROUP_EIDS];
	if (eid_grp) {
		if (eid_grp->attrs && eid_grp->attrs[0]) {
			dev_attr = container_of(eid_grp->attrs[0],
						struct device_attribute, attr);
			eid_attr_list = container_of(
				dev_attr, struct ubcore_eid_attr, attr);
			kfree(eid_attr_list);
		}

		kfree(eid_grp->attrs);
		kfree(eid_grp);

		ldev->dev_group[UBCORE_ATTR_GROUP_EIDS] = NULL;
	}
}

int ubcore_create_dev_attr_files(struct ubcore_logic_device *ldev)
{
	int ret;
	const struct attribute_group *eid_grp;

	eid_grp = ubcore_alloc_eids_group(ldev);
	ldev->dev_group[UBCORE_ATTR_GROUP_DEV_DEFAULT] = &ubcore_dev_attr_group;
	ldev->dev_group[UBCORE_ATTR_GROUP_EIDS] = eid_grp;
	ldev->dev_group[UBCORE_ATTR_GROUP_NULL] = NULL;

	ret = sysfs_create_groups(&ldev->dev->kobj, ldev->dev_group);
	if (ret != 0) {
		ubcore_log_err("sysfs create group failed, ret:%d.\n", ret);
		ubcore_free_eids_group(ldev);
		return -EINVAL;
	}

	return 0;
}

void ubcore_remove_port_attr_files(struct ubcore_logic_device *ldev,
				   uint8_t port_id)
{
	kobject_put(&ldev->port[port_id].kobj);
}

void ubcore_remove_dev_attr_files(struct ubcore_logic_device *ldev)
{
	sysfs_remove_groups(&ldev->dev->kobj, ldev->dev_group);
	ubcore_free_eids_group(ldev);
}

static ssize_t ubcore_show_priority_attr(struct ubcore_priority_kobj *p,
					 struct ubcore_priority_attribute *attr,
					 char *buf, ubcore_show_priority_attr_cb show_cb)
{
	struct ubcore_device *dev = p->dev;

	if (!dev || !buf) {
		ubcore_log_err("Invalid argument.\n");
		return -EINVAL;
	}

	return show_cb(dev, buf, p->priority_id);
}

static ssize_t sl_show_cb(struct ubcore_device *dev, char *buf, uint8_t priority_id)
{
	int ret = 0;

	ret = ubcore_query_device_attr(dev, &dev->attr);
	if (ret != 0) {
		ubcore_log_err("failed query device attr.\n");
		return ret;
	}
	return snprintf(buf, UBCORE_MAX_VALUE_LEN, "%u\n",
		dev->attr.dev_cap.priority_info[priority_id].SL);
}

static ssize_t sl_show(struct ubcore_priority_kobj *p, struct ubcore_priority_attribute *attr,
					char *buf)
{
	return ubcore_show_priority_attr(p, attr, buf, sl_show_cb);
}

static PRIORITY_ATTR_RO(sl);

static ssize_t tp_type_show_cb(struct ubcore_device *dev, char *buf, uint8_t priority_id)
{
	int ret = 0;

	ret = ubcore_query_device_attr(dev, &dev->attr);
	if (ret != 0) {
		ubcore_log_err("failed query device attr.\n");
		return ret;
	}
	return snprintf(buf, UBCORE_MAX_VALUE_LEN, "%u\n",
		dev->attr.dev_cap.priority_info[priority_id].tp_type.value);
}

static ssize_t tp_type_show(struct ubcore_priority_kobj *p, struct ubcore_priority_attribute *attr,
					char *buf)
{
	return ubcore_show_priority_attr(p, attr, buf, tp_type_show_cb);
}

static PRIORITY_ATTR_RO(tp_type);

static struct attribute *ubcore_priority_attrs[] = {
	&priority_attr_sl.attr,      &priority_attr_tp_type.attr, NULL,
};

static ssize_t ubcore_priority_attr_show(struct kobject *kobj, struct attribute *attr, char *buf)
{
	struct ubcore_priority_attribute *port_attr =
		container_of(attr, struct ubcore_priority_attribute, attr);
	struct ubcore_priority_kobj *p = container_of(kobj, struct ubcore_priority_kobj, kobj);

	if (!port_attr->show)
		return -EIO;

	return port_attr->show(p, port_attr, buf);
}

static ssize_t ubcore_priority_attr_store(struct kobject *kobj, struct attribute *attr,
	const char *buf, size_t count)
{
	struct ubcore_priority_attribute *port_attr =
		container_of(attr, struct ubcore_priority_attribute, attr);
	struct ubcore_priority_kobj *p = container_of(kobj, struct ubcore_priority_kobj, kobj);

	if (!port_attr->store)
		return -EIO;

	return port_attr->store(p, port_attr, buf, count);
}

static const struct sysfs_ops ubcore_priority_sysfs_ops = { .show = ubcore_priority_attr_show,
							.store = ubcore_priority_attr_store };

static void ubcore_priority_release(struct kobject *kobj)
{
}

// ATTRIBUTE_GROUPS defined in 3.11, but must be consistent with kobj_type->default_groups

ATTRIBUTE_GROUPS(ubcore_priority);

static const struct kobj_type ubcore_priority_type = { .release = ubcore_priority_release,
	.sysfs_ops = &ubcore_priority_sysfs_ops,
	.default_groups = ubcore_priority_groups
};

static const struct kobj_type ubcore_priority_grp_type = { .release = ubcore_priority_release,
						 .sysfs_ops = &ubcore_priority_sysfs_ops};

int ubcore_create_priority_attr_files(struct ubcore_logic_device *ldev,
	struct ubcore_device *dev, uint8_t priority_id)
{
	struct ubcore_priority_kobj *p;

	p = &ldev->prioritys.priority[priority_id];
	p->dev = dev;
	p->priority_id = priority_id;

	return kobject_init_and_add(&p->kobj, &ubcore_priority_type, &ldev->prioritys.kobj,
		"priority%hhu", priority_id);
}

void ubcore_remove_priority_attr_files(struct ubcore_logic_device *ldev, uint8_t priority_id)
{
	kobject_put(&ldev->prioritys.priority[priority_id].kobj);
}

int ubcore_create_priority_grp_attr_files(struct ubcore_logic_device *ldev,
	struct ubcore_device *dev)
{
	struct ubcore_prioritys_kobj *p;
	int ret;
	uint8_t p1, p2;

	p = &ldev->prioritys;
	p->dev = dev;

	ret = kobject_init_and_add(&p->kobj, &ubcore_priority_grp_type, &ldev->dev->kobj,
		"priority");
	if (ret != 0)
		return ret;

	for (p1 = 0; p1 < UBCORE_MAX_PRIORITY_CNT; p1++) {
		ret = ubcore_create_priority_attr_files(ldev, dev, p1);
		if (ret != 0)
			goto err_attr;
	}
	return 0;
err_attr:
	for (p2 = 0; p2 < p1; p2++)
		ubcore_remove_priority_attr_files(ldev, p2);
	kobject_put(&ldev->prioritys.kobj);
	return ret;
}

int ubcore_fill_logic_device_attr(struct ubcore_logic_device *ldev,
				  struct ubcore_device *dev)
{
	uint8_t p1, p2; /* port */

	if (ubcore_create_dev_attr_files(ldev) != 0) {
		ubcore_log_err("failed to fill attributes, device:%s.\n",
			       dev->dev_name);
		return -EPERM;
	}

	/* create /sys/class/ubcore/<dev->dev_name>/port* */
	for (p1 = 0; p1 < dev->attr.port_cnt; p1++) {
		if (ubcore_create_port_attr_files(ldev, dev, p1) != 0)
			goto err_port_attr;
	}

	if (ubcore_create_priority_grp_attr_files(ldev, dev) != 0)
		return -EPERM;

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
