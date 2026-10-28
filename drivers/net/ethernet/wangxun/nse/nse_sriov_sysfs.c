// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2018 - 2021 Beijing WangXun Technology Co., Ltd. */

#include "nse.h"
#include "nse_sriov_sysfs.h"
#include "nse_vf_meter.h"

struct vf_attributes {
	struct attribute attr;
	ssize_t (*show)(struct nse_vf_sysfs *vf_sysfs, struct vf_attributes *attr,
			 char *buf);
	ssize_t (*store)(struct nse_vf_sysfs *vf_sysfs, struct vf_attributes *attr,
			 const char *buf, size_t count);
};
static ssize_t vf_meter_attr_show(struct kobject *kobj,
			    struct attribute *attr, char *buf)
{
	struct vf_attributes *ga =
		container_of(attr, struct vf_attributes, attr);
	struct nse_vf_sysfs *g = container_of(kobj, struct nse_vf_sysfs, kobj);

	if (!ga->show)
		return -EIO;

	return ga->show(g, ga, buf);
}

static ssize_t vf_meter_attr_store(struct kobject *kobj,
			     struct attribute *attr,
			     const char *buf, size_t size)
{
	struct vf_attributes *ga =
		container_of(attr, struct vf_attributes, attr);
	struct nse_vf_sysfs *g = container_of(kobj, struct nse_vf_sysfs, kobj);

	if (!ga->store)
		return -EIO;

	return ga->store(g, ga, buf, size);
}

static ssize_t vf_meter_common_show(struct nse_vf_sysfs *g,
				    struct vf_attributes *oa, char *buf,
				    int data_type)
{
	struct nse_pf *pf = g->pf;
	struct device *dev = nse_pf_to_dev(pf);
	u64 data = 0;
	int err = 0;

	dev_info(dev,
		"[%s, %d] Received a vf meter show cmd msg\n",
		__func__, __LINE__);

	err = nse_get_vf_meter_data(pf, g->vf_id, data_type,
					     g->meter_type.rx_tx,
					     g->meter_type.xps, &data);
	if (err)
		return err;

	return sprintf(buf, "%lld\n", data);
}

static ssize_t vf_meter_common_store(struct nse_vf_sysfs *g,
				     struct vf_attributes *oa,
				     const char *buf, size_t count,
				     int data_type)
{
	struct nse_pf *pf = g->pf;
	struct device *dev = nse_pf_to_dev(pf);
	s64 data;
	int err;

	dev_info(dev,
		"[%s, %d] Received a vf meter store cmd msg\n",
		__func__, __LINE__);

	err = kstrtos64(buf, 10, &data);
	if (err)
		return err;

	if (data < 0)
		return -EINVAL;

	err = nse_set_vf_meter_data(pf, g->vf_id, data_type,
					     g->meter_type.rx_tx,
					     g->meter_type.xps, data);

	return err ? err : count;
}

static ssize_t rate_show(struct nse_vf_sysfs *g, struct vf_attributes *oa,
			 char *buf)
{
	return vf_meter_common_show(g, oa, buf, NSE_RATE_LIMIT_DATA_RATE);
}

static ssize_t rate_store(struct nse_vf_sysfs *g, struct vf_attributes *oa,
			  const char *buf, size_t count)
{
	return vf_meter_common_store(g, oa, buf, count, NSE_RATE_LIMIT_DATA_RATE);
}

static ssize_t burst_show(struct nse_vf_sysfs *g, struct vf_attributes *oa,
			  char *buf)
{
	return vf_meter_common_show(g, oa, buf, NSE_RATE_LIMIT_DATA_BURST);
}

static ssize_t burst_store(struct nse_vf_sysfs *g, struct vf_attributes *oa,
			   const char *buf, size_t count)
{
	return vf_meter_common_store(g, oa, buf, count, NSE_RATE_LIMIT_DATA_BURST);
}

static ssize_t bytes_dropped_show(struct nse_vf_sysfs *g, struct vf_attributes *oa,
				  char *buf)
{
	return vf_meter_common_show(g, oa, buf, NSE_RATE_LIMIT_DATA_BYTES_DROPPED);
}

static ssize_t bytes_dropped_store(struct nse_vf_sysfs *g, struct vf_attributes *oa,
				   const char *buf, size_t count)
{
	return -EOPNOTSUPP;
}

static ssize_t packets_dropped_show(struct nse_vf_sysfs *g, struct vf_attributes *oa,
				    char *buf)
{
	return vf_meter_common_show(g, oa, buf, NSE_RATE_LIMIT_DATA_PACKETS_DROPPED);
}

static ssize_t packets_dropped_store(struct nse_vf_sysfs *g, struct vf_attributes *oa,
				     const char *buf, size_t count)
{
	return -EOPNOTSUPP;
}

#define VF_ATTR(_name) struct vf_attributes vf_attr_##_name = \
	__ATTR(_name, 0644, _name##_show, _name##_store)

VF_ATTR(rate);
VF_ATTR(burst);
VF_ATTR(bytes_dropped);
VF_ATTR(packets_dropped);

static struct attribute *vf_meters_eth_attrs[] = {
	&vf_attr_rate.attr,
	&vf_attr_burst.attr,
	&vf_attr_bytes_dropped.attr,
	&vf_attr_packets_dropped.attr,
	NULL
};

ATTRIBUTE_GROUPS(vf_meters_eth);

static const struct sysfs_ops vf_meter_sysfs_ops = {
	.show = vf_meter_attr_show,
	.store = vf_meter_attr_store,
};

static const struct kobj_type vf_meters_type_eth = {
	.sysfs_ops     = &vf_meter_sysfs_ops,
	.default_groups = vf_meters_eth_groups,
};

/*start to config per vf*/
static ssize_t vf_attr_show(struct kobject *kobj,
			    struct attribute *attr, char *buf)
{
	struct vf_attributes *ga =
		container_of(attr, struct vf_attributes, attr);
	struct nse_vf_sysfs *g = container_of(kobj, struct nse_vf_sysfs, kobj);

	if (!ga->show)
		return -EIO;

	return ga->show(g, ga, buf);
}

static ssize_t vf_attr_store(struct kobject *kobj,
			     struct attribute *attr,
			     const char *buf, size_t size)
{
	struct vf_attributes *ga =
		container_of(attr, struct vf_attributes, attr);
	struct nse_vf_sysfs *g = container_of(kobj, struct nse_vf_sysfs, kobj);

	if (!ga->store)
		return -EIO;

	return ga->store(g, ga, buf, size);
}

static struct attribute *vf_eth_attrs[] = {
	NULL
};

ATTRIBUTE_GROUPS(vf_eth);

static const struct sysfs_ops vf_sysfs_ops = {
	.show = vf_attr_show,
	.store = vf_attr_store,
};

static const struct kobj_type vf_type_eth = {
	.sysfs_ops     = &vf_sysfs_ops,
	.default_groups = vf_eth_groups
};

/**
 * nse_destroy_vfs_sysfs_meters_by_num - cleanup directory of vf meter sysfs
 * @pf: pointer to the PF structure
 * @num_vfs: number of vfs
 *
 */
void nse_destroy_vfs_sysfs_meters_by_num(struct nse_pf *pf,
	int num_vfs)
{
	struct nse_vfs *vfs = &pf->vfs;
	struct nse_vf_sysfs *tmp;
	struct nse_vf_sysfs_meters *meters;
	int i, j;

	for (i = 0; i < num_vfs; i++) {
		tmp = &vfs->sysfs_vfs[i];
		meters = tmp->meters;

		if (!meters)
			break;

		for (j = 0; j < 4; j++)
			kobject_put(&meters->meters[j].kobj);

		kobject_put(meters->rx_kobj);
		kobject_put(meters->tx_kobj);
		kobject_put(meters->kobj);

		kfree(meters);
	}
}

/**
 * nse_init_vfs_sysfs_init_meter
 * @vf: vf kobj level of sysfs
 * @meters: meters kobj level of sysfs
 * @meter: meter kobj level of sysfs
 */
static int nse_init_vfs_sysfs_init_meter(struct nse_vf_sysfs *vf_sysfs,
					  struct nse_vf_sysfs_meters *meters,
					  struct nse_vf_sysfs *meter,
					  int rx_tx, int xps)
{
	struct kobject *parent;
	int err;

	if (rx_tx == NSE_VF_RATE_LIMIT_TX)
		parent = meters->tx_kobj;
	else
		parent = meters->rx_kobj;

	err = kobject_init_and_add(&meter->kobj, &vf_meters_type_eth, parent,
				   (xps == NSE_VF_RATE_LIMIT_PPS) ? "pps" : "bps");
	if (err)
		return err;

	meter->pf = vf_sysfs->pf;
	meter->vf_id = vf_sysfs->vf_id;
	meter->meter_type.rx_tx = rx_tx;
	meter->meter_type.xps = xps;

	kobject_uevent(&meter->kobj, KOBJ_ADD);

	return 0;
}

/**
 * nse_create_vfs_sysfs_meters - make directory of vf meter config when sriov enable
 * @pf: pointer to the PF structure
 * @num_vfs: number of vfs
 */
static int
nse_create_vfs_sysfs_meters(struct nse_pf *pf, u16 num_vfs)
{
	struct nse_vfs *vfs = &pf->vfs;
	struct nse_vf_sysfs *vf_sysfs;
	struct nse_vf_sysfs_meters *meters;
	struct device *dev = nse_pf_to_dev(pf);
	int err, i;

	for (i = 0; i < num_vfs; i++) {
		vf_sysfs = &vfs->sysfs_vfs[i];
		meters = kzalloc(sizeof(*meters), GFP_KERNEL);
		if (!meters) {
			err = -ENOMEM;
			goto err_meters_malloc;
		}

		meters->kobj = kobject_create_and_add("meters", &vf_sysfs->kobj);
		if (!meters->kobj) {
			dev_err(dev,
				"[%s, %d] Failed to create meters sysfs, vf_id = %d\n",
				__func__, __LINE__, i);

			err = -EINVAL;
			goto err_meters_kobj;
		}

		meters->rx_kobj = kobject_create_and_add("rx", meters->kobj);
		if (!meters->rx_kobj) {
			dev_err(dev,
				"[%s, %d] Failed to create meter rx sysfs, vf_id = %d\n",
				__func__, __LINE__, i);

			err = -EINVAL;
			goto err_rx_kobj;
		}

		meters->tx_kobj = kobject_create_and_add("tx", meters->kobj);
		if (!meters->tx_kobj) {
			dev_err(dev,
				"[%s, %d] Failed to create meter tx sysfs, vf_id = %d\n",
				__func__, __LINE__, i);

			err = -EINVAL;
			goto err_tx_kobj;
		}

		err = nse_init_vfs_sysfs_init_meter(vf_sysfs, meters,
						     &meters->meters[0],
						     NSE_VF_RATE_LIMIT_RX,
						     NSE_VF_RATE_LIMIT_BPS);
		if (err) {
			dev_err(dev,
				"[%s, %d] Failed to create meter[0] sysfs, vf_id = %d\n",
				__func__, __LINE__, i);
			goto err_put_meter_0;
		}

		err = nse_init_vfs_sysfs_init_meter(vf_sysfs, meters,
						     &meters->meters[1],
						     NSE_VF_RATE_LIMIT_RX,
						     NSE_VF_RATE_LIMIT_PPS);
		if (err) {
			dev_err(dev,
				"[%s, %d] Failed to create meter[1] sysfs, vf_id = %d\n",
				__func__, __LINE__, i);
			goto err_put_meter_1;
		}

		err = nse_init_vfs_sysfs_init_meter(vf_sysfs, meters,
						     &meters->meters[2],
						     NSE_VF_RATE_LIMIT_TX,
						     NSE_VF_RATE_LIMIT_BPS);
		if (err) {
			dev_err(dev,
				"[%s, %d] Failed to create meter[2] sysfs, vf_id = %d\n",
				__func__, __LINE__, i);
			goto err_put_meter_2;
		}

		err = nse_init_vfs_sysfs_init_meter(vf_sysfs, meters,
						     &meters->meters[3],
						     NSE_VF_RATE_LIMIT_TX,
						     NSE_VF_RATE_LIMIT_PPS);
		if (err) {
			dev_err(dev,
				"[%s, %d] Failed to create meter[3] sysfs, vf_id = %d\n",
				__func__, __LINE__, i);
			goto err_put_meter_3;
		}

		vf_sysfs->meters = meters;
	}

	return 0;

err_put_meter_3:
	kobject_put(&meters->meters[2].kobj);
err_put_meter_2:
	kobject_put(&meters->meters[1].kobj);
err_put_meter_1:
	kobject_put(&meters->meters[0].kobj);
err_put_meter_0:
	kobject_put(meters->tx_kobj);
err_tx_kobj:
	kobject_put(meters->rx_kobj);
err_rx_kobj:
	kobject_put(meters->kobj);
err_meters_kobj:
	kfree(meters);
err_meters_malloc:

	/* destroy created vf meter sysfs*/
	nse_destroy_vfs_sysfs_meters_by_num(pf, i);

	return err;
}

/**
 * nse_create_vfs_sysfs - make directory of vf config when sriov enable
 * @pf: pointer to the PF structure
 * @num_vfs: number of vfs
 */
int nse_create_vfs_sysfs(struct nse_pf *pf, u16 num_vfs)
{
	struct nse_vfs *vfs = &pf->vfs;
	struct nse_vf_sysfs *tmp;
	struct device *dev = nse_pf_to_dev(pf);
	int err;
	u16 vf_id;

	vfs->sysfs_vfs = kcalloc(num_vfs, sizeof(*vfs->sysfs_vfs), GFP_KERNEL);
	if (!vfs->sysfs_vfs)
		return -ENOMEM;

	for (vf_id = 0; vf_id < num_vfs; vf_id++) {
		tmp = &vfs->sysfs_vfs[vf_id];
		tmp->pf = pf;
		tmp->vf_id = vf_id;
		err = kobject_init_and_add(&tmp->kobj, &vf_type_eth, vfs->config,
					   "%d", vf_id);
		if (err) {
			dev_err(dev,
				"[%s, %d] Failed to create vf %d sysfs\n",
				__func__, __LINE__, vf_id);
			err = -ENOMEM;
			goto err_vf;
		}
		kobject_uevent(&tmp->kobj, KOBJ_ADD);
	}

	err = nse_create_vfs_sysfs_meters(pf, num_vfs);
	if (err) {
		dev_err(dev,
			"[%s, %d] Failed to create vf meter sysfs\n",
			__func__, __LINE__);
		--vf_id;
		goto err_vf;
	}

	return 0;

err_vf:
	for (; vf_id >= 0; vf_id--) {
		tmp = &vfs->sysfs_vfs[vf_id];
		kobject_put(&tmp->kobj);
	}

	kfree(vfs->sysfs_vfs);
	vfs->sysfs_vfs = NULL;
	return err;
}

/**
 * nse_destroy_vfs_sysfs_meters - cleanup directory of vf meter sysfs
 * @pf: pointer to the PF structure
 *
 */
void nse_destroy_vfs_sysfs_meters(struct nse_pf *pf)
{
	struct nse_vfs *vfs = &pf->vfs;
	struct nse_vf *vf;
	struct nse_vf_sysfs *tmp;
	unsigned int bkt;
	struct nse_vf_sysfs_meters *meters;
	int j;

	nse_for_each_vf(pf, bkt, vf) {
		tmp = &vfs->sysfs_vfs[vf->vf_id];
		meters = tmp->meters;

		if (!meters)
			break;

		for (j = 0; j < 4; j++)
			kobject_put(&meters->meters[j].kobj);

		kobject_put(meters->rx_kobj);
		kobject_put(meters->tx_kobj);
		kobject_put(meters->kobj);

		kfree(meters);
	}
}

/**
 * nse_destroy_vfs_sysfs - cleanup directory of vf config when sriov disable
 * @pf: pointer to the PF structure
 *
 */
void nse_destroy_vfs_sysfs(struct nse_pf *pf)
{
	struct nse_vfs *vfs = &pf->vfs;
	struct nse_vf *vf;
	unsigned int bkt;
	struct nse_vf_sysfs *tmp;

	nse_destroy_vfs_sysfs_meters(pf);

	nse_for_each_vf(pf, bkt, vf) {
		tmp = &vfs->sysfs_vfs[vf->vf_id];
		kobject_put(&tmp->kobj);
	}

	kfree(vfs->sysfs_vfs);
	vfs->sysfs_vfs = NULL;
}

/**
 * nse_sriov_sysfs_init - make a directory for sriov config at probe stage
 * @pf: pointer to the PF structure
 *
 * Returns 0 on success and negative on failure
 */
int nse_sriov_sysfs_init(struct nse_pf *pf)
{
	struct nse_vfs *vfs = &pf->vfs;
	struct device *dev = nse_pf_to_dev(pf);

	vfs->config = kobject_create_and_add("sriov", &dev->kobj);
	if (!vfs->config) {
		dev_err(dev,
			"[%s, %d] Failed to create sriov sysfs\n",
			__func__, __LINE__);
		return -ENOMEM;
	}

	return 0;
}

/**
 * nse_sriov_sysfs_cleanup - cleanup directory for sriov config at remove stage
 * @pf: pointer to the PF structure
 *
 */
void nse_sriov_sysfs_cleanup(struct nse_pf *pf)
{
	struct nse_vfs *vfs = &pf->vfs;

	kobject_put(vfs->config);
	vfs->config = NULL;
}

