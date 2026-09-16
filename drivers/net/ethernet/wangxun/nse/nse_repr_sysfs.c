// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2018 - 2021 Beijing WangXun Technology Co., Ltd. */

#include "nse.h"
#include "nse_repr_sysfs.h"
#include "nse_repr_meter.h"

static ssize_t repr_attr_show(struct kobject *kobj,
			     struct attribute *attr, char *buf)
{
	struct kobj_attribute *kattr;
	ssize_t ret = -EIO;

	kattr = container_of(attr, struct kobj_attribute, attr);
	if (kattr->show)
		ret = kattr->show(kobj, kattr, buf);
	return ret;
}

static ssize_t repr_attr_store(struct kobject *kobj,
			      struct attribute *attr,
			      const char *buf, size_t count)
{
	struct kobj_attribute *kattr;
	ssize_t ret = -EIO;

	kattr = container_of(attr, struct kobj_attribute, attr);
	if (kattr->store)
		ret = kattr->store(kobj, kattr, buf, count);
	return ret;
}

static ssize_t miss_rl_cfg_store(struct kobject *kobj,
				 struct kobj_attribute *attr,
				 const char *buf,
				 size_t count)
{
	struct nse_rep_sysfs *tmp =
		container_of(kobj, struct nse_rep_sysfs, kobj);
	struct nse_pf *pf = tmp->pf;
	struct device *dev = nse_pf_to_dev(pf);
	u64 rate, burst;
	int err = 0;

	err = sscanf(buf, "%llu %llu", &rate, &burst);
	if (err != 2) {
		dev_err(dev,
			"[%s, %d] rate burst should be configurated meanwhile.\n",
			__func__, __LINE__);
		return -EINVAL;
	}

	if (rate < 0 || burst < 0) {
		dev_err(dev,
			"[%s, %d] rate burst should be both bigger than 0\n",
			__func__, __LINE__);
		return -EINVAL;
	}

	dev_info(dev,
		"[%s, %d] Received a miss rate limit store: rate=%llu, burst=%llu, is_uplink = %d, vf_id = %d\n",
		__func__, __LINE__, rate, burst, tmp->is_uplink, tmp->vf_id);

	err = nse_rep_set_miss_meter(tmp->pf, tmp->is_uplink, tmp->repr,
				      rate, burst);
	if (err) {
		dev_err(dev,
			"[%s, %d] Failed to set repr miss meter.\n",
			__func__, __LINE__);
		return err;
	}

	return count;
}

static ssize_t miss_rl_cfg_show(struct kobject *kobj,
				struct kobj_attribute *attr,
				char *buf)
{
	struct nse_rep_sysfs *tmp =
		container_of(kobj, struct nse_rep_sysfs, kobj);
	struct nse_pf *pf = tmp->pf;
	struct device *dev = nse_pf_to_dev(pf);
	u64 rate, burst;
	int err;

	dev_info(dev,
		"[%s, %d] Received a miss rate limit show: is_uplink = %d, vf_id = %d\n",
		__func__, __LINE__, tmp->is_uplink, tmp->vf_id);

	err = nse_rep_get_miss_meter_data(tmp->pf, tmp->is_uplink, tmp->repr,
					   NSE_RATE_LIMIT_DATA_RATE, &rate);
	if (err) {
		dev_err(dev,
			"[%s, %d] Failed to get repr miss meter's rate.\n",
			__func__, __LINE__);
		return err;
	}
	err = nse_rep_get_miss_meter_data(tmp->pf, tmp->is_uplink, tmp->repr,
				   NSE_RATE_LIMIT_DATA_BURST, &burst);
	if (err) {
		dev_err(dev,
			"[%s, %d] Failed to get repr miss meter's burst.\n",
			__func__, __LINE__);
		return err;
	}

	return sprintf(buf,
		       "rate: %llu[packes/s] burst: %llu[packets]\n",
		       rate, burst);
}

static ssize_t miss_rl_dropped_show_common(struct kobject *kobj,
					   int drop_type,
					   char *buf)
{
	struct nse_rep_sysfs *tmp =
		container_of(kobj, struct nse_rep_sysfs, kobj);
	struct nse_pf *pf = tmp->pf;
	struct device *dev = nse_pf_to_dev(pf);
	u64 data;
	int err;

	err = nse_rep_get_miss_meter_data(tmp->pf, tmp->is_uplink, tmp->repr,
					   drop_type, &data);
	if (err) {
		if (drop_type == NSE_RATE_LIMIT_DATA_PACKETS_DROPPED)
			dev_err(dev,
				"[%s, %d] Failed to get repr miss meter's dropped packets.\n",
				__func__, __LINE__);

		else if (drop_type == NSE_RATE_LIMIT_DATA_BYTES_DROPPED)
			dev_err(dev,
				"[%s, %d] Failed to get repr miss meter's dropped bytes.\n",
				__func__, __LINE__);

		return err;
	}

	return sprintf(buf, "%llu\n", data);
}

static ssize_t miss_rl_dropped_packets_show(struct kobject *kobj,
					    struct kobj_attribute *attr,
					    char *buf)
{
	return miss_rl_dropped_show_common(kobj, NSE_RATE_LIMIT_DATA_PACKETS_DROPPED, buf);
}

static ssize_t miss_rl_dropped_bytes_show(struct kobject *kobj,
					  struct kobj_attribute *attr,
					  char *buf)
{
	return miss_rl_dropped_show_common(kobj, NSE_RATE_LIMIT_DATA_BYTES_DROPPED, buf);
}

static struct kobj_attribute attr_miss_rl_cfg = {
	.attr = {.name = "miss_rl_cfg",
		 .mode = 0644 },
	.show = miss_rl_cfg_show,
	.store = miss_rl_cfg_store,
};

static struct kobj_attribute attr_miss_rl_dropped_packets = {
	.attr = {.name = "miss_rl_dropped_packets",
		 .mode = 0444 },
	.show = miss_rl_dropped_packets_show,
};

static struct kobj_attribute attr_miss_rl_dropped_bytes = {
	.attr = {.name = "miss_rl_dropped_bytes",
		 .mode = 0444 },
	.show = miss_rl_dropped_bytes_show,
};

static struct attribute *repr_attrs[] = {
	&attr_miss_rl_cfg.attr,
	&attr_miss_rl_dropped_packets.attr,
	&attr_miss_rl_dropped_bytes.attr,
	NULL,
};

static const struct sysfs_ops repr_sysfs_ops = {
	.show   = repr_attr_show,
	.store  = repr_attr_store
};

ATTRIBUTE_GROUPS(repr);

static const struct kobj_type repr_type = {
	.sysfs_ops     = &repr_sysfs_ops,
	.default_groups = repr_groups,
};

/**
 * nse_create_rep_sysfs - make directory of vf repr config when switchdev enable
 * @repr: pointer to vf representor structure
 */
void nse_create_rep_sysfs(struct nse_repr *repr)
{
	struct nse_rep_sysfs *tmp;
	int err;

	tmp = &repr->rep_sysfs;
	memset(tmp, 0, sizeof(*tmp));
	err = kobject_init_and_add(&tmp->kobj, &repr_type,
				   &repr->netdev->dev.kobj, "rep_config");

	if (err) {
		dev_err(&repr->netdev->dev,
			"[%s, %d] Failed to create repr sysfs\n",
			__func__, __LINE__);
		return;
	}

	kobject_uevent(&tmp->kobj, KOBJ_ADD);

	tmp->pf = repr->src_vsi->back;
	tmp->vf_id = repr->vf->vf_id;
	tmp->repr = repr;
	tmp->is_uplink = false;
}

/**
 * nse_cleanup_rep_sysfs - cleanup directory of vf repr config when switchdev disable
 * @repr: pointer to vf representor structure
 */
void nse_cleanup_rep_sysfs(struct nse_repr *repr)
{
	struct nse_rep_sysfs *tmp;

	tmp = &repr->rep_sysfs;

	if (!tmp->pf || tmp->is_uplink)
		return;

	kobject_put(&tmp->kobj);
}

/**
 * nse_create_rep_sysfs - make directory of uplink repr config when switchdev enable
 * @pf: pointer to the PF structure
 */
void nse_create_uplink_sysfs(struct nse_pf *pf)
{
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_rep_sysfs *tmp;
	struct nse_vsi *uplink_vsi;
	int err;

	uplink_vsi = pf->switchdev.uplink_vsi;
	if (!uplink_vsi) {
		dev_err(dev,
			"[%s, %d] Failed to get uplink vsi\n",
			__func__, __LINE__);
		return;
	}

	tmp = &pf->switchdev.uplink_sysfs;
	memset(tmp, 0, sizeof(*tmp));
	err = kobject_init_and_add(&tmp->kobj, &repr_type,
						&uplink_vsi->netdev->dev.kobj, "rep_config");
	if (err) {
		dev_err(dev,
			"[%s, %d] Failed to create uplink sysfs\n",
			__func__, __LINE__);
		return;
	}

	kobject_uevent(&tmp->kobj, KOBJ_ADD);
	tmp->pf = pf;
	tmp->vf_id = 0xff;
	tmp->repr = NULL;
	tmp->is_uplink = true;
}

/**
 * nse_cleanup_uplink_sysfs - cleanup directory of uplink repr config when switchdev disable
 * @pf: pointer to the PF structure
 */
void nse_cleanup_uplink_sysfs(struct nse_pf *pf)
{
	struct nse_rep_sysfs *tmp;

	tmp = &pf->switchdev.uplink_sysfs;

	if (!tmp->pf || !tmp->is_uplink)
		return;

	kobject_put(&tmp->kobj);
}

