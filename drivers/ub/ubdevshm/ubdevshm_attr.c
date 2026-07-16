// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved.
 * Description：ubdevshm attr function
 */
#define pr_fmt(fmt) "UBDEVSHM: " fmt

#include <linux/list.h>
#include <linux/kobject.h>
#include <linux/sysfs.h>
#include <ub/ubdevshm/ubdevshm.h>
#include "ubdevshm_main.h"

static struct kobject *ubdevshm_kobj;
static int container_attr_index;
static int provider_attr_index;
static struct kobj_attribute ubdevshm_provider_list_attr;
static struct kobj_attribute ubdevshm_provider_info_attr;
static struct kobj_attribute ubdevshm_container_list_attr;
static struct kobj_attribute ubdevshm_container_info_attr;

static ssize_t provider_list_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	struct mem_provider *pos = NULL;
	int count = 0;

	count += sysfs_emit_at(buf, count, "provider list:\n");
	down_read(&ubdevshm_rw_semlock);
	list_for_each_entry(pos, &provider_list, node)
		count += sysfs_emit_at(buf, count, "index:%d name:%s version:%u\n",
				       pos->handle_id, pos->ops->name, pos->ops->version);

	up_read(&ubdevshm_rw_semlock);

	return count;
}

static ssize_t provider_info_store(struct kobject *kobj, struct kobj_attribute *attr,
				   const char *buf, size_t count)
{
	int provider_id, ret;

	ret = kstrtoint(buf, 0, &provider_id);
	if (ret)
		return ret;

	provider_attr_index = provider_id;
	return count;
}

static ssize_t provider_info_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	struct shm_area *area_pos = NULL, *area_n = NULL;
	struct access_ctx_inner *ctx_pos = NULL;
	struct mem_provider *provider = NULL;
	struct shm_container *pos = NULL;
	int count = 0;

	down_read(&ubdevshm_rw_semlock);
	provider = idr_find(&mem_provider_idr, provider_attr_index);
	if (!provider) {
		count = sysfs_emit_at(buf, count, "provider index:%d not existed.\n",
				      provider_attr_index);
		up_read(&ubdevshm_rw_semlock);
		return count;
	}

	count = sysfs_emit_at(buf, count, "provider:%s info:\n", provider->ops->name);
	list_for_each_entry(pos, &container_list, node) {
		mutex_lock(&pos->lock);
		rbtree_postorder_for_each_entry_safe(area_pos, area_n, &pos->shm_area_root, node) {
			list_for_each_entry(ctx_pos, &area_pos->ctx_list, node) {
				if (ctx_pos->provider == provider) {
					count += sysfs_emit_at(buf, count,
							       " register size:0x%llx owner:%s\n",
							       area_pos->size, pos->owner.name);
					break;
				}
			}

		}
		mutex_unlock(&pos->lock);
	}
	up_read(&ubdevshm_rw_semlock);

	return count;
}

static ssize_t container_list_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	struct shm_container *pos = NULL;
	int count = 0;

	count += sysfs_emit_at(buf, count, "container list:\n");
	down_read(&ubdevshm_rw_semlock);
	list_for_each_entry(pos, &container_list, node)
		count += sysfs_emit_at(buf, count, "index:%d name:%s\n", pos->id, pos->owner.name);

	up_read(&ubdevshm_rw_semlock);

	return count;
}

static ssize_t container_info_store(struct kobject *kobj, struct kobj_attribute *attr,
				    const char *buf, size_t count)
{
	int cntr_id, ret;

	ret = kstrtoint(buf, 0, &cntr_id);
	if (ret)
		return ret;

	container_attr_index = cntr_id;
	return count;
}

static ssize_t container_info_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	struct shm_area *area_pos = NULL, *area_n = NULL;
	struct access_ctx_inner *ctx_pos = NULL;
	struct shm_container *cntr = NULL;
	int count = 0;

	down_read(&ubdevshm_rw_semlock);
	cntr = idr_find(&shm_container_idr, container_attr_index);
	if (!cntr) {
		count = sysfs_emit_at(buf, count, "container index:%d not existed.\n",
				      container_attr_index);
		up_read(&ubdevshm_rw_semlock);
		return count;
	}

	count = sysfs_emit_at(buf, count, "container:%s info:\n", cntr->owner.name);

	mutex_lock(&cntr->lock);
	rbtree_postorder_for_each_entry_safe(area_pos, area_n, &cntr->shm_area_root, node) {
		count += sysfs_emit_at(buf, count, " register size:0x%llx\n", area_pos->size);
		list_for_each_entry(ctx_pos, &area_pos->ctx_list, node)
			count += sysfs_emit_at(buf, count, " grant to user:%s\n",
					       ctx_pos->user.name);
	}
	mutex_unlock(&cntr->lock);
	up_read(&ubdevshm_rw_semlock);

	return count;
}

static int init_provider_list(struct kobject *kobj, struct kobj_attribute *attrs)
{
	sysfs_attr_init(&attrs->attr);
	attrs->attr.name = "provider_list";
	attrs->attr.mode = 0440;
	attrs->show = provider_list_show;

	return sysfs_create_file(kobj, &ubdevshm_provider_list_attr.attr);
}

static int init_provider_info(struct kobject *kobj, struct kobj_attribute *attrs)
{
	sysfs_attr_init(&attrs->attr);
	attrs->attr.name = "provider_info";
	attrs->attr.mode = 0660;
	attrs->show = provider_info_show;
	attrs->store = provider_info_store;

	return sysfs_create_file(kobj, &attrs->attr);
}

static int init_container_list(struct kobject *kobj, struct kobj_attribute *attrs)
{
	sysfs_attr_init(&attrs->attr);
	attrs->attr.name = "container_list";
	attrs->attr.mode = 0440;
	attrs->show = container_list_show;

	return sysfs_create_file(kobj, &attrs->attr);
}

static int init_container_info(struct kobject *kobj, struct kobj_attribute *attrs)
{
	sysfs_attr_init(&attrs->attr);
	attrs->attr.name = "container_info";
	attrs->attr.mode = 0660;
	attrs->show = container_info_show;
	attrs->store = container_info_store;

	return sysfs_create_file(kobj, &attrs->attr);
}

int ubdevshm_attr_file_init(void)
{
	int ret;

	ubdevshm_kobj = kobject_create_and_add("ubdevshm", kernel_kobj);
	if (!ubdevshm_kobj) {
		pr_err("Failed to create kobject\n");
		return -ENOMEM;
	}

	ret = init_provider_list(ubdevshm_kobj, &ubdevshm_provider_list_attr);
	if (ret) {
		pr_err("Failed to create provider list file\n");
		goto err_provider_list_en;
	}

	ret = init_provider_info(ubdevshm_kobj, &ubdevshm_provider_info_attr);
	if (ret) {
		pr_err("Failed to create provider info file\n");
		goto err_provider_info_en;
	}

	ret = init_container_list(ubdevshm_kobj, &ubdevshm_container_list_attr);
	if (ret) {
		pr_err("Failed to create container list file\n");
		goto err_container_list_en;
	}

	ret = init_container_info(ubdevshm_kobj, &ubdevshm_container_info_attr);
	if (ret) {
		pr_err("Failed to create container info file\n");
		goto err_container_info_en;
	}
	return 0;

err_container_info_en:
	sysfs_remove_file(ubdevshm_kobj, &ubdevshm_container_list_attr.attr);
err_container_list_en:
	sysfs_remove_file(ubdevshm_kobj, &ubdevshm_provider_info_attr.attr);
err_provider_info_en:
	sysfs_remove_file(ubdevshm_kobj, &ubdevshm_provider_list_attr.attr);
err_provider_list_en:
	kobject_put(ubdevshm_kobj);
	return ret;
}

void ubdevshm_attr_file_uninit(void)
{
	sysfs_remove_file(ubdevshm_kobj, &ubdevshm_container_info_attr.attr);
	sysfs_remove_file(ubdevshm_kobj, &ubdevshm_container_list_attr.attr);
	sysfs_remove_file(ubdevshm_kobj, &ubdevshm_provider_info_attr.attr);
	sysfs_remove_file(ubdevshm_kobj, &ubdevshm_provider_list_attr.attr);
	kobject_put(ubdevshm_kobj);
}
