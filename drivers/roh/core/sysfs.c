// SPDX-License-Identifier: GPL-2.0+
// Copyright (c) 2020-2022 Hisilicon Limited.

#include <linux/sysfs.h>
#include <linux/stat.h>
#include <net/sock.h>

#include "core.h"
#include "core_priv.h"

#define ROH_MIB_STATS_TYPE_NUM 2

static ssize_t node_eid_show(struct device *device,
			     struct device_attribute *attr, char *buf)
{
	struct roh_device *dev = container_of(device, struct roh_device, dev);
	struct roh_eid_attr eid;

	roh_device_get_eid(dev, &eid);

	return sprintf(buf, "base:%u num:%u\n", eid.base, eid.num);
}

static ssize_t node_guid_show(struct device *device,
			      struct device_attribute *attr, char *buf)
{
	struct roh_device *dev = container_of(device, struct roh_device, dev);
	struct roh_guid_attr guid;
	u32 *val = (u32 *)guid.data;

	roh_device_query_guid(dev, &guid);

	return sprintf(buf, "%08x:%08x:%08x:%08x\n", val[0], val[1], val[2], val[3]);
}

static ssize_t node_link_status_show(struct device *device,
				     struct device_attribute *attr, char *buf)
{
	struct roh_device *dev = container_of(device, struct roh_device, dev);

	return sprintf(buf, "%s\n",
		       (roh_device_query_link_status(dev) == ROH_LINK_UP) ?
		       "UP" : "DOWN");
}

static DEVICE_ATTR_RO(node_eid);
static DEVICE_ATTR_RO(node_guid);
static DEVICE_ATTR_RO(node_link_status);

static struct device_attribute *roh_class_attr[] = {
	&dev_attr_node_eid,
	&dev_attr_node_guid,
	&dev_attr_node_link_status,
};

struct roh_hw_stats_attribute {
	struct attribute attr;
	ssize_t (*show)(struct kobject *kobj,
			struct attribute *attr, char *buf);
	ssize_t (*store)(struct kobject *kobj,
			 struct attribute *attr,
			 const char *buf,
			 size_t count);
};

static void remove_device_sysfs(struct roh_device *device)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(roh_class_attr); i++)
		device_remove_file(&device->dev, roh_class_attr[i]);
}

static const char * const roh_hw_stats_name[ROH_MIB_STATS_TYPE_NUM] = {
	"mib_public",
	"mib_private",
};

static ssize_t print_hw_stat(struct roh_device *dev,
			     struct roh_mib_stats *stats, char *buf)
{
	int offset = 0;
	int i;

	for (i = 0; i < stats->num_counters; i++)
		offset += sprintf(buf + offset, "%s: %llu\n",
				  stats->names[i], stats->value[i]);
	return offset;
}

static ssize_t node_public_mib_stats_show(struct kobject *kobj,
					  struct attribute *attr, char *buf)
{
	struct roh_hw_stats_attribute *hsa;
	struct roh_mib_stats *public_stats;
	struct roh_device *dev;
	int ret;

	hsa = container_of(attr, struct roh_hw_stats_attribute, attr);
	dev = container_of(kobj, struct roh_device, dev.kobj);
	public_stats = dev->hw_public_stats;
	mutex_lock(&public_stats->lock);
	ret = dev->ops.get_hw_stats(dev, public_stats, ROH_MIB_PUBLIC);
	if (ret)
		goto unlock;

	ret = print_hw_stat(dev, public_stats, buf);

unlock:
	mutex_unlock(&public_stats->lock);
	return ret;
}

static ssize_t node_private_mib_stats_show(struct kobject *kobj,
					   struct attribute *attr, char *buf)
{
	struct roh_mib_stats *private_stats;
	struct roh_hw_stats_attribute *hsa;
	struct roh_device *dev;
	int ret;

	hsa = container_of(attr, struct roh_hw_stats_attribute, attr);
	dev = container_of(kobj, struct roh_device, dev.kobj);
	private_stats = dev->hw_private_stats;
	mutex_lock(&private_stats->lock);
	ret = dev->ops.get_hw_stats(dev, private_stats, ROH_MIB_PRIVATE);
	if (ret)
		goto unlock;

	ret = print_hw_stat(dev, private_stats, buf);

unlock:
	mutex_unlock(&private_stats->lock);
	return ret;
}

static ssize_t (*show_roh_mib_hw_stats[ROH_MIB_STATS_TYPE_NUM])
	(struct kobject *, struct attribute *, char *) = {
	node_public_mib_stats_show,
	node_private_mib_stats_show
};

static void free_hsag(struct kobject *kobj, struct attribute_group *attr_group)
{
	struct attribute **attr;

	sysfs_remove_group(kobj, attr_group);

	for (attr = attr_group->attrs; *attr; attr++)
		kfree(*attr);
	kfree(attr_group);
}

static struct attribute *alloc_hsa(const char *name,
				   ssize_t (*show_roh_mib_hw_stats)
				   (struct kobject *, struct attribute *, char *))
{
	struct roh_hw_stats_attribute *hsa;

	hsa = kmalloc(sizeof(*hsa), GFP_KERNEL);
	if (!hsa)
		return NULL;

	hsa->attr.name = (char *)name;
	hsa->attr.mode = 0444;
	hsa->show = show_roh_mib_hw_stats;
	hsa->store = NULL;
	return &hsa->attr;
}

static void setup_mib_stats(struct roh_device *device)
{
	struct roh_mib_stats *privite_stats, *public_stats;
	struct attribute_group *hsag;
	struct kobject *kobj;
	int i, j;
	int ret;

	public_stats = device->ops.alloc_hw_stats(device, ROH_MIB_PUBLIC);
	if (!public_stats)
		return;

	privite_stats = device->ops.alloc_hw_stats(device, ROH_MIB_PRIVATE);
	if (!privite_stats) {
		kfree(public_stats);
		return;
	}

	hsag = kzalloc(sizeof(*hsag) +
		       sizeof(void *) * (ARRAY_SIZE(roh_hw_stats_name)),
		       GFP_KERNEL);
	if (!hsag)
		goto err_free_stats;

	ret = device->ops.get_hw_stats(device, public_stats, ROH_MIB_PUBLIC);
	if (ret)
		goto err_free_hsag;

	ret = device->ops.get_hw_stats(device, privite_stats, ROH_MIB_PRIVATE);
	if (ret)
		goto err_free_hsag;

	hsag->name = "node_mib_stats";
	hsag->attrs = (void *)hsag + sizeof(*hsag);

	for (i = 0; i < ARRAY_SIZE(roh_hw_stats_name); i++) {
		hsag->attrs[i] = alloc_hsa(roh_hw_stats_name[i],
					   show_roh_mib_hw_stats[i]);
		if (!hsag->attrs[i])
			goto err;
		sysfs_attr_init(hsag->attrs[i]);
	}

	mutex_init(&privite_stats->lock);
	mutex_init(&public_stats->lock);

	kobj = &device->dev.kobj;
	ret = sysfs_create_group(kobj, hsag);
	if (ret)
		goto err;
	device->hw_stats_ag = hsag;
	device->hw_public_stats = public_stats;
	device->hw_private_stats = privite_stats;

	return;

err:
	for (j = i - 1; j >= 0; j--)
		kfree(hsag->attrs[j]);
err_free_hsag:
	kfree(hsag);
err_free_stats:
	kfree(public_stats);
	kfree(privite_stats);
}

int roh_device_register_sysfs(struct roh_device *device)
{
	int ret;
	int i;

	for (i = 0; i < ARRAY_SIZE(roh_class_attr); i++) {
		ret = device_create_file(&device->dev, roh_class_attr[i]);
		if (ret) {
			pr_err("failed to create node %s, ret = %d.\n",
			       roh_class_attr[i]->attr.name, ret);
			goto err;
		}
	}

	if (device->ops.alloc_hw_stats)
		setup_mib_stats(device);

	return 0;

err:
	remove_device_sysfs(device);
	return ret;
}

void roh_device_unregister_sysfs(struct roh_device *device)
{
	if (device->hw_stats_ag)
		free_hsag(&device->dev.kobj, device->hw_stats_ag);

	kfree(device->hw_private_stats);
	kfree(device->hw_public_stats);

	remove_device_sysfs(device);
}
