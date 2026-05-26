// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) HiSilicon Technologies Co., Ltd. 2025. All rights reserved.
 */

#define pr_fmt(fmt) "ubus instance: " fmt

#include <ub/ubfi/ubfi.h>
#include <uapi/ub/ubus/ubus.h>

#include "ubus.h"
#include "eid.h"
#include "resource.h"
#include "eu.h"
#include "ubus_driver.h"
#include "instance.h"

#define DYNAMIC_DEFAULT_UBC 0

static LIST_HEAD(ubi_list);
static DEFINE_MUTEX(ubi_list_mutex);
static DEFINE_MUTEX(dynamic_mutex);
static u32 instance_count;
static u32 instance_start;

typedef bool (*instance_match)(struct ub_bus_instance *bi, void *arg);

static ssize_t instance_store(const struct bus_type *bus, const char *buf,
			      size_t count)
{
	unsigned long val;
	ssize_t ret;

	ret = kstrtoul(buf, 0, &val);
	if (ret < 0)
		return ret;

	mutex_lock(&ubi_list_mutex);
	if (val >= instance_count) {
		pr_err("store instance %#lx over %#x\n", val, instance_count);
		mutex_unlock(&ubi_list_mutex);
		return -EINVAL;
	}

	instance_start = val;
	mutex_unlock(&ubi_list_mutex);
	return count;
}

static ssize_t instance_show(const struct bus_type *bus, char *buf)
{
	struct ub_bus_instance_info *info;
	struct ub_bus_instance *bi;
	u32 show, left, end, i = 0;
	struct ub_guid *guid;
	ssize_t len;

#define MAX_DUMP 50
	mutex_lock(&ubi_list_mutex);
	left = instance_count - instance_start;
	show = left > MAX_DUMP ? MAX_DUMP : left;
	end = instance_start + show;
	len = sysfs_emit(buf, "count %#x, from %#x, show %#x\n", instance_count,
			 instance_start, show);

	list_for_each_entry(bi, &ubi_list, node) {
		if (i < instance_start) {
			i++;
			continue;
		}

		if (i == end)
			break;

		info = &bi->info;
		guid = &info->guid;
		len += sysfs_emit_at(buf, len, "guid:");
		len += ub_show_guid(guid, buf + len);
		len += sysfs_emit_at(buf, len, " type:%01x eid:%05x upi:%04x\n",
				     info->type, info->eid, info->upi);
		i++;
	}

	instance_start = 0;
	mutex_unlock(&ubi_list_mutex);
	return len;
}
BUS_ATTR_RW(instance);

static void ub_unregister_bus_instance(struct ub_bus_instance *bi);
static void ub_bus_instance_destroy(struct ub_bus_instance *bi)
{
	guid_t *tar = (guid_t *)&guid_null;

	if (is_dynamic(bi))
		tar = &bi->info.guid.id;

	ummu_core_del_eid(tar, bi->info.eid, EID_NONE);
	ub_unregister_bus_instance(bi);
}

static void ub_release_bus_instance(struct kref *kref)
{
	struct ub_bus_instance *bi =
		container_of(kref, struct ub_bus_instance, kref);

	if (bi->registered)
		ub_bus_instance_destroy(bi);

	kfree(bi);
}

static struct ub_bus_instance *ub_bus_instance_get(struct ub_bus_instance *bi)
{
	if (bi)
		kref_get(&bi->kref);

	return bi;
}

static void ub_bus_instance_put(struct ub_bus_instance *bi)
{
	if (bi)
		kref_put(&bi->kref, ub_release_bus_instance);
}

static bool eid_match(struct ub_bus_instance *bi, void *arg)
{
	if (bi == NULL || arg == NULL)
		return false;

	u32 *eid = (u32 *)arg;

	return bi->info.eid == *eid;
}

static struct ub_bus_instance *ub_alloc_bus_instance(void)
{
	struct ub_bus_instance *bi;

	bi = kzalloc(sizeof(*bi), GFP_KERNEL);
	if (!bi)
		return NULL;

	INIT_LIST_HEAD(&bi->node);
	kref_init(&bi->kref);
	INIT_LIST_HEAD(&bi->uents);
	mutex_init(&bi->lock);

	return bi;
}

static bool guid_match(struct ub_bus_instance *bi, void *arg)
{
	guid_t *guid = (guid_t *)arg;

	return guid_equal(&bi->info.guid.id, guid);
}

static struct ub_bus_instance *ub_find_bus_instance(instance_match match,
						    void *arg)
{
	struct ub_bus_instance *bi;

	mutex_lock(&ubi_list_mutex);
	list_for_each_entry(bi, &ubi_list, node)
		if (match(bi, arg))
			goto out;

	bi = NULL;
out:
	ub_bus_instance_get(bi);
	mutex_unlock(&ubi_list_mutex);

	return bi;
}

bool ub_bus_instance_exist(u32 eid)
{
	struct ub_bus_instance *bi;

	bi = ub_find_bus_instance(eid_match, &eid);
	if (!bi)
		return false;

	ub_bus_instance_put(bi);
	return true;
}
EXPORT_SYMBOL_GPL(ub_bus_instance_exist);

static int bi_duplicate_check(struct ub_bus_instance_info *n)
{
	struct ub_bus_instance_info *old;
	struct ub_bus_instance *bi;
	int ret;

	bi = ub_find_bus_instance(guid_match, &n->guid.id);
	if (!bi)
		return 0;

	old = &bi->info;

	if (n->type != old->type) {
		pr_err("bus instance guid exist with different type\n");
		ub_bus_instance_put(bi);
		return -EINVAL;
	}

	if (n->eid) {
		if (n->upi)
			ret = (n->eid == old->eid && n->upi == old->upi) ?
				      -EEXIST :
				      -EINVAL;
		else
			ret = (n->eid == old->eid) ? -EEXIST : -EINVAL;
	} else {
		if (n->upi)
			ret = (n->upi == old->upi) ? -EEXIST : -EINVAL;
		else
			ret = -EEXIST;
	}

	if (ret == -EEXIST)
		pr_warn("bus instance guid exist\n");
	else
		pr_err("bus instance guid exist, but eid/upi invalid\n");

	ub_bus_instance_put(bi);

	return ret;
}

static int bi_valid_check(struct ub_bus_instance *bi)
{
	struct ub_bus_instance_info *info = &bi->info;

	if (info->guid.bits.type != UB_TYPE_BUS_INSTANCE ||
	    guid_is_null((const guid_t *)&info->guid)) {
		pr_err("guid type is not bus instance or guid_null\n");
		return -EINVAL;
	}

	if (is_cluster(bi) && (info->eid == 0 || info->upi == 0 ||
			       info->eid <= ubc_eid_end)) {
		pr_err("cluster bi eid or upi invalid, eid=%#x, upi=%#x\n",
		       info->eid, info->upi);
		return -EINVAL;
	}

	if (is_server(bi) && info->eid && info->eid <= ubc_eid_end) {
		pr_err("server bi eid within the local scope, eid=%#x\n",
		       info->eid);
		return -EINVAL;
	}

	return 0;
}

static int ub_cfg_bus_instance_eid(struct ub_bus_instance *bi, bool alloc)
{
	struct ub_bus_instance_info *info = &bi->info;
	struct ub_guid guid = info->guid;
	u32 eid;
	int ret;

	if (is_cluster(bi))
		return 0;

	if (alloc) {
		if (info->eid)
			return 0;

		ret = ub_eid_request(&guid.id, &eid);
		if (ret) {
			pr_err("bus instance eid cfg failed, ret=%d\n", ret);
			return ret;
		}

		info->eid = eid;
	} else {
		if (info->eid > ubc_eid_end)
			return 0;

		ub_eid_release(info->eid);
		info->eid = 0;
	}

	return 0;
}

static void ub_cfg_bus_instance_upi(struct ub_bus_instance *bi)
{
	struct ub_bus_instance_info *info = &bi->info;

	if (is_cluster(bi) || info->upi)
		return;

	info->upi = UB_CP_UPI;
}

static int ub_register_bus_instance(struct ub_bus_instance *bi)
{
	struct ub_bus_instance_info *info = &bi->info;
	struct ub_bus_controller *ubc;
	int ret, i = 0, count = 0;

	ret = bi_duplicate_check(info);
	if (ret)
		return ret;

	ret = bi_valid_check(bi);
	if (ret)
		return ret;

	ret = ub_cfg_bus_instance_eid(bi, true);
	if (ret)
		return ret;

	ub_cfg_bus_instance_upi(bi);

	if (is_static_server(bi)) {
		ret = ub_cfg_eu_table(bi->major, true, bi->info.eid,
				      bi->info.upi);
		if (ret)
			goto out;
	} else {
		list_for_each_entry(ubc, &ubc_list, node) {
			ret = ub_cfg_eu_table(ubc, true, bi->info.eid,
					      bi->info.upi);
			if (ret)
				goto cfg_fail;
			count++;
		}
	}

	mutex_lock(&ubi_list_mutex);
	bi->registered = true;
	list_add_tail(&bi->node, &ubi_list);
	instance_count++;
	mutex_unlock(&ubi_list_mutex);
	return 0;
cfg_fail:
	list_for_each_entry(ubc, &ubc_list, node) {
		if (i == count)
			break;

		(void)ub_cfg_eu_table(ubc, false, bi->info.eid, bi->info.upi);
		i++;
	}
out:
	/* upi no need unconfigure */
	(void)ub_cfg_bus_instance_eid(bi, false);
	return ret;
}

static void ub_unregister_bus_instance(struct ub_bus_instance *bi)
{
	struct ub_bus_controller *ubc;

	mutex_lock(&ubi_list_mutex);
	if (!bi->registered) {
		mutex_unlock(&ubi_list_mutex);
		return;
	}

	instance_count--;
	list_del(&bi->node);
	bi->registered = false;
	mutex_unlock(&ubi_list_mutex);

	if (is_static_server(bi)) {
		(void)ub_cfg_eu_table(bi->major, false, bi->info.eid,
				      bi->info.upi);
	} else {
		list_for_each_entry(ubc, &ubc_list, node)
			(void)ub_cfg_eu_table(ubc, false, bi->info.eid,
					      bi->info.upi);
	}

	/* upi no need unconfigure */
	(void)ub_cfg_bus_instance_eid(bi, false);
}

int ub_static_bus_instance_init(struct ub_bus_controller *ubc)
{
	struct ub_bus_instance *bi;
	struct ub_bus_controller *tmp;
	int ret;

	if (ubc->ctl_no != 0) {
		tmp = ub_find_bus_controller(0);
		if (!tmp || !tmp->bi)
			return -EINVAL;

		ubc->bi = ub_bus_instance_get(tmp->bi);

		return ub_cfg_eu_table(ubc, true, ubc->bi->info.eid,
				      ubc->bi->info.upi);
	}

	bi = ub_alloc_bus_instance();
	if (!bi)
		return -ENOMEM;

	bi->info.type = UBUS_INSTANCE_STATIC_SERVER;
	guid_copy(&bi->info.guid.id, &ubc->uent->guid.id);
	bi->info.guid.bits.type = UB_TYPE_BUS_INSTANCE;
	bi->major = ubc;

	ret = ub_register_bus_instance(bi);
	if (ret) {
		dev_err(&ubc->dev, "static server register bi failed ret=%d\n",
			ret);
		goto put;
	}

	ret = ummu_core_add_eid((guid_t *)&guid_null, bi->info.eid,
				EID_NONE);
	if (ret) {
		dev_err(&ubc->dev, "static server ummu core add eid, ret=%d\n",
			ret);
		goto unregister;
	}

	ubc->bi = ub_bus_instance_get(bi);

	ub_bus_instance_put(bi); /* put the init one */

	return 0;
unregister:
	ub_unregister_bus_instance(bi);
put:
	ub_bus_instance_put(bi);
	return ret;
}

void ub_static_bus_instance_uninit(struct ub_bus_controller *ubc)
{
	if (ubc->ctl_no != 0)
		(void)ub_cfg_eu_table(ubc, false, ubc->bi->info.eid,
				      ubc->bi->info.upi);

	ub_bus_instance_put(ubc->bi);
	ubc->bi = NULL;
}

static struct ub_bus_instance *
ub_dynamic_bus_instance_create(struct ub_bus_instance_info *info, enum eid_type type)
{
	struct ub_bus_instance *bi;
	struct ub_bus_controller *ubc;
	int ret;

	ubc = ub_find_bus_controller(DYNAMIC_DEFAULT_UBC);
	if (!ubc) {
		pr_err("ubc 0 not exist\n");
		return (struct ub_bus_instance *)ERR_PTR(-ENODEV);
	}

	bi = ub_alloc_bus_instance();
	if (!bi)
		return (struct ub_bus_instance *)ERR_PTR(-ENOMEM);

	if (ubc->cluster)
		info->type = UBUS_INSTANCE_DYNAMIC_CLUSTER;
	else
		info->type = UBUS_INSTANCE_DYNAMIC_SERVER;

	bi->info = *info;
	bi->major = ubc;

	ret = ub_register_bus_instance(bi);
	if (ret)
		goto put;

	ret = ummu_core_add_eid(&bi->info.guid.id, bi->info.eid, type);
	if (ret) {
		pr_err("bus instance add eid, ret=%d\n", ret);
		goto unregister;
	}

	return bi;

unregister:
	ub_unregister_bus_instance(bi);
put:
	ub_bus_instance_put(bi);
	return (struct ub_bus_instance *)ERR_PTR(ret);
}

static void bi_info_init(struct ub_bus_instance_info *info,
			 const struct ubus_cmd_bi_create *create)
{
	info->type = create->type;
	info->upi = create->upi;
	info->eid = create->eid;
	guid_copy(&info->guid.id, (const guid_t *)create->guid);
}

int ub_ioctl_bus_instance_create(void __user *uptr)
{
	size_t size = sizeof(struct ubus_cmd_bi_create);
	struct ubus_cmd_bi_create create = {};
	struct ub_bus_instance_info info = {};
	struct ub_bus_instance *bi;

	if (copy_from_user(&create, uptr + UBUS_IOCTL_HEADER_SIZE, size))
		return -EFAULT;

	bi_info_init(&info, &create);

	mutex_lock(&dynamic_mutex);
	bi = ub_dynamic_bus_instance_create(&info, EID_NONE);
	if (IS_ERR(bi)) {
		pr_err("bus instance create failed, ret=%ld\n", PTR_ERR(bi));
		mutex_unlock(&dynamic_mutex);
		return PTR_ERR(bi);
	}

	create.eid = bi->info.eid;
	create.upi = bi->info.upi;

	if (copy_to_user(uptr + UBUS_IOCTL_HEADER_SIZE, &create, size)) {
		ub_bus_instance_put(bi);
		pr_err("bus instance copy to user failed\n");
		mutex_unlock(&dynamic_mutex);
		return -EFAULT;
	}

	mutex_unlock(&dynamic_mutex);
	return 0;
}

int ub_ioctl_bus_instance_destroy(void __user *uptr)
{
	size_t size = sizeof(struct ubus_cmd_bi_destroy);
	struct ubus_cmd_bi_destroy destroy = {};
	struct ub_bus_instance *bi;
	char b_str[SZ_64];

	if (copy_from_user(&destroy, uptr + UBUS_IOCTL_HEADER_SIZE, size))
		return -EFAULT;

	(void)snprintf(b_str, SZ_64, "%#llx %llx",
		       *((u64 *)&destroy.guid[SZ_8]),
		       *((u64 *)&destroy.guid[0]));

	mutex_lock(&dynamic_mutex);
	bi = ub_find_bus_instance(guid_match, destroy.guid);
	if (!bi) {
		pr_err("bus instance destroy invalid, guid=%s\n", b_str);
		mutex_unlock(&dynamic_mutex);
		return -ENODEV;
	}

	if (!is_dynamic(bi)) {
		pr_err("instance %s is not dynamic\n", b_str);
		ub_bus_instance_put(bi);
		mutex_unlock(&dynamic_mutex);
		return -EINVAL;
	}

	if (kref_read(&bi->kref) != 2) { /* 2 is original + find */
		pr_err("instance %s is still in use\n", b_str);
		ub_bus_instance_put(bi);
		mutex_unlock(&dynamic_mutex);
		return -EBUSY;
	}

	ub_bus_instance_put(bi); /* put find */
	ub_bus_instance_put(bi); /* real put */

	mutex_unlock(&dynamic_mutex);
	return 0;
}

int ub_msg_bus_instance_create(struct ub_bus_controller *ubc, u32 *guid, u32 eid,
			       u16 upi, enum eid_type type)
{
	struct ub_bus_instance_info info = {};
	struct ub_bus_instance *bi;
	int ret = 0;

	info.upi = upi;
	info.eid = eid;
	guid_copy(&info.guid.id, (const guid_t *)guid);

	mutex_lock(&dynamic_mutex);
	bi = ub_dynamic_bus_instance_create(&info, type);
	if (IS_ERR(bi)) {
		ret = PTR_ERR(bi);
		dev_err(&ubc->dev, "msg bus instance create failed, ret=%d\n",
			ret);
	}

	mutex_unlock(&dynamic_mutex);
	return ret;
}
EXPORT_SYMBOL_GPL(ub_msg_bus_instance_create);

int ub_msg_bus_instance_destroy(struct ub_bus_controller *ubc, u32 *guid)
{
	struct ub_bus_instance *bi;
	char b_str[SZ_64];

	(void)snprintf(b_str, SZ_64, "%#llx %llx", *((u64 *)&guid[SZ_2]),
		       *((u64 *)&guid[0]));

	mutex_lock(&dynamic_mutex);
	bi = ub_find_bus_instance(guid_match, guid);
	if (!bi) {
		dev_err(&ubc->dev,
			"msg bus instance destroy invalid, guid=%s\n", b_str);
		mutex_unlock(&dynamic_mutex);
		return -ENODEV;
	}

	if (!is_dynamic_cluster(bi)) {
		dev_err(&ubc->dev, "msg destroy instance %s type invalid\n",
			b_str);
		ub_bus_instance_put(bi);
		mutex_unlock(&dynamic_mutex);
		return -EINVAL;
	}

	if (kref_read(&bi->kref) != 2) { /* 2 is original + find */
		dev_err(&ubc->dev, "msg instance %s still in use\n", b_str);
		ub_bus_instance_put(bi);
		mutex_unlock(&dynamic_mutex);
		return -EBUSY;
	}

	ub_bus_instance_put(bi); /* put find */
	ub_bus_instance_put(bi); /* real put */

	mutex_unlock(&dynamic_mutex);
	return 0;
}

void ub_dynamic_bus_instance_drain(void)
{
	struct ub_bus_instance *bi, *tmp;

	mutex_lock(&dynamic_mutex);

	list_for_each_entry_safe(bi, tmp, &ubi_list, node)
		if (is_dynamic(bi))
			ub_bus_instance_put(bi);

	mutex_unlock(&dynamic_mutex);
}

static int
ub_static_cluster_instance_create(struct ub_bus_controller *ubc, u32 *guid,
				  u32 eid, u16 upi)
{
	struct ub_bus_instance *bi;
	int ret;

	bi = ub_alloc_bus_instance();
	if (!bi)
		return -ENOMEM;

	bi->info.type = UBUS_INSTANCE_STATIC_CLUSTER;
	guid_copy(&bi->info.guid.id, (guid_t *)guid);
	bi->info.eid = eid;
	bi->info.upi = upi;
	bi->major = ubc;

	ret = ub_register_bus_instance(bi);
	if (ret)
		goto put;

	ret = ummu_core_add_eid((guid_t *)&guid_null, bi->info.eid,
				EID_NONE);
	if (ret) {
		dev_err(&ubc->dev, "bus instance add eid failed, ret=%d\n", ret);
		goto unregister;
	}

	ubc->cluster_bi = bi;
	return 0;

unregister:
	ub_unregister_bus_instance(bi);
put:
	ub_bus_instance_put(bi);
	return ret;
}

int ub_notify_bus_instance_handle(struct ub_bus_controller *ubc, bool flag,
				  u32 *guid, u32 eid, u16 upi)
{
	struct ub_bus_instance *bi;
	struct ub_guid *tmp;
	int ret;

	if (!flag) {
		bi = ub_find_bus_instance(guid_match, guid);
		if (!bi) {
			dev_err(&ubc->dev, "notify can't find bus instance\n");
			return -ENODEV;
		}

		if (!is_static_cluster(bi) || bi->info.eid != eid ||
		    bi->info.upi != upi) {
			dev_err(&ubc->dev, "notify bus instance is invalid\n");
			ub_bus_instance_put(bi);
			return -EINVAL;
		}

		/* May receive the same UBC Notify message */
		if (ubc->cluster_bi)
			ub_bus_instance_put(bi);
		else
			ubc->cluster_bi = bi;

		return 0;
	}

	tmp = (struct ub_guid *)guid;
	if (tmp->bits.type != UB_TYPE_BUS_INSTANCE) {
		dev_err(&ubc->dev, "notify msg guid type is invalid\n");
		return -EINVAL;
	}

	/* BI may have already been created in other UBC Notify messages */
	ret = ub_static_cluster_instance_create(ubc, guid, eid, upi);
	if (ret && ret != -EEXIST) {
		dev_err(&ubc->dev, "create static cluster instance failed\n");
		return ret;
	}

	if (!ubc->cluster_bi)
		ubc->cluster_bi = ub_find_bus_instance(guid_match, guid);

	return 0;
}

void ub_static_cluster_instance_drain(void)
{
	struct ub_bus_controller *ubc;

	list_for_each_entry(ubc, &ubc_list, node) {
		ub_bus_instance_put(ubc->cluster_bi);
		ubc->cluster_bi = NULL;
	}
}

/* Only for dynamic use */
static int get_bus_instance_and_uent(u8 *b_guid, u8 *d_guid,
				     struct ub_bus_instance **p_bi,
				     struct ub_entity **p_uent)
{
	char b_str[SZ_64], d_str[SZ_64];
	struct ub_bus_instance *bi;
	struct ub_entity *uent;
	int ret = -ENODEV;

	(void)snprintf(b_str, SZ_64, "%#llx %llx", *((u64 *)&b_guid[SZ_8]),
		       *((u64 *)&b_guid[0]));
	(void)snprintf(d_str, SZ_64, "%#llx %llx", *((u64 *)&d_guid[SZ_8]),
		       *((u64 *)&d_guid[0]));

	bi = ub_find_bus_instance(guid_match, b_guid);
	if (!bi)
		goto err;

	if (!is_dynamic(bi)) {
		ret = -EINVAL;
		goto put;
	}

	uent = ub_get_ent_by_guid((struct ub_guid *)d_guid);
	if (!uent)
		goto put;

	if (is_p_device(uent)) {
		pr_err("fad dev not support bind again\n");
		ub_entity_put(uent);
		goto put;
	}

	*p_bi = bi;
	*p_uent = uent;
	return 0;
put:
	ub_bus_instance_put(bi);
err:
	pr_err("get bi and uent failed, bi_guid=%s, dev_guid=%s\n", b_str, d_str);
	return ret;
}

static int ub_bind_bus_instance(struct ub_entity *uent, struct ub_bus_instance *bi)
{
	if (!uent || uent->bi || !bi || !bi->registered)
		return -EINVAL;

	uent->bi = ub_bus_instance_get(bi);

	mutex_lock(&bi->lock);
	list_add_tail(&uent->instance_node, &bi->uents);
	mutex_unlock(&bi->lock);

	ub_entity_decoder_map_mmio(uent);
	return 0;
}

static void ub_unbind_bus_instance(struct ub_entity *uent)
{
	if (!uent || !uent->bi)
		return;

	mutex_lock(&uent->bi->lock);
	list_del(&uent->instance_node);
	mutex_unlock(&uent->bi->lock);

	ub_bus_instance_put(uent->bi);
	uent->bi = NULL;
	ub_entity_decoder_unmap_mmio(uent);
}

int ub_ioctl_bus_instance_bind(void __user *uptr)
{
	size_t size = sizeof(struct ubus_cmd_bi_bind);
	struct ubus_cmd_bi_bind bind = {};
	struct ub_bus_instance *bi, *old;
	struct ub_entity *uent;
	char b_str[SZ_64];
	int ret;

	if (copy_from_user(&bind, uptr + UBUS_IOCTL_HEADER_SIZE, size))
		return -EFAULT;

	mutex_lock(&dynamic_mutex);
	ret = get_bus_instance_and_uent(bind.instance_guid, bind.dev_guid, &bi,
					&uent);
	if (ret) {
		mutex_unlock(&dynamic_mutex);
		return ret;
	}

	(void)snprintf(b_str, SZ_64, "%#llx %llx",
		       *((u64 *)&bind.instance_guid[SZ_8]),
		       *((u64 *)&bind.instance_guid[0]));

	mutex_lock(&uent->instance_lock);
	old = uent->bi;
	if (!old) {
		ub_err(uent, "dev has no static instance\n");
		ret = -EINVAL;
		goto out;
	}

	if (is_static(old)) {
		ub_unbind_bus_instance(uent);
		ret = ub_bind_bus_instance(uent, bi);
		if (ret) {
			ub_err(uent, "bind instance failed, guid=%s\n", b_str);
			(void)ub_bind_bus_instance(uent, uent->ubc->bi);
		}
	} else {
		/* If bind the same again, do nothing */
		if (old != bi) {
			ub_err(uent, "dev already bind instance\n");
			ret = -EBUSY;
		}
	}

out:
	ub_entity_put(uent);
	ub_bus_instance_put(bi);
	mutex_unlock(&uent->instance_lock);
	mutex_unlock(&dynamic_mutex);
	return ret;
}

int ub_ioctl_bus_instance_unbind(void __user *uptr)
{
	size_t size = sizeof(struct ubus_cmd_bi_unbind);
	struct ubus_cmd_bi_unbind unbind = {};
	struct ub_bus_instance *bi;
	struct ub_entity *uent;
	char b_str[SZ_64];
	int ret;

	if (copy_from_user(&unbind, uptr + UBUS_IOCTL_HEADER_SIZE, size))
		return -EFAULT;

	mutex_lock(&dynamic_mutex);
	ret = get_bus_instance_and_uent(unbind.instance_guid, unbind.dev_guid,
					&bi, &uent);
	if (ret) {
		mutex_unlock(&dynamic_mutex);
		return ret;
	}

	(void)snprintf(b_str, SZ_64, "%#llx %llx",
		       *((u64 *)&unbind.instance_guid[SZ_8]),
		       *((u64 *)&unbind.instance_guid[0]));

	mutex_lock(&uent->instance_lock);
	if (uent->bi != bi) {
		ub_err(uent, "dev not bind bus instance, guid=%s\n", b_str);
		ret = -EINVAL;
		goto out;
	}

	ub_unbind_bus_instance(uent);
	ret = ub_bind_bus_instance(uent, uent->ubc->bi);
	if (ret) {
		ub_err(uent, "unbind instance failed, guid=%s\n", b_str);
		(void)ub_bind_bus_instance(uent, bi);
	}

out:
	ub_entity_put(uent);
	ub_bus_instance_put(bi);
	mutex_unlock(&uent->instance_lock);
	mutex_unlock(&dynamic_mutex);
	return ret;
}

int ub_default_bus_instance_init(struct ub_entity *uent)
{
	struct ub_bus_instance *bi;
	bool use_cluster;
	int ret;

	if (is_switch(uent))
		return 0;

	use_cluster = is_p_device(uent) || is_p_idevice(uent) ||
		      (is_ibus_controller(uent) && uent->ubc->cluster);
	if (use_cluster) {
		mutex_lock(&dynamic_mutex);
		bi = ub_find_bus_instance(eid_match, &uent->user_eid);
	} else {
		bi = uent->ubc->bi;
	}

	if (!bi) {
		if (use_cluster)
			mutex_unlock(&dynamic_mutex);
		ub_err(uent, "get default bi NULL\n");
		return -EINVAL;
	}

	mutex_lock(&uent->instance_lock);
	ret = ub_bind_bus_instance(uent, bi);
	mutex_unlock(&uent->instance_lock);

	if (use_cluster) {
		ub_bus_instance_put(bi);
		mutex_unlock(&dynamic_mutex);
	}

	return ret;
}

void ub_default_bus_instance_uninit(struct ub_entity *uent)
{
	if (is_switch(uent))
		return;

	mutex_lock(&uent->instance_lock);
	ub_unbind_bus_instance(uent);
	mutex_unlock(&uent->instance_lock);
}
