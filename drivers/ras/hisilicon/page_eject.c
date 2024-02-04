// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) Huawei Technologies Co., Ltd. 2023. All rights reserved.
 */

#define pr_fmt(fmt) "page eject: " fmt

#include <linux/mm.h>
#include <linux/module.h>
#include <linux/slab.h>

static struct list_head eject_page_list = LIST_HEAD_INIT(eject_page_list);
static DEFINE_MUTEX(eject_page_mutex);
static struct kobject *eject_page_kobj;

struct ejected_pfn {
	struct list_head list;
	unsigned long pfn;
};

static struct ejected_pfn *page_eject_remove_pfn_locked(unsigned long pfn)
{
	struct ejected_pfn *item, *next, *ret = NULL;

	mutex_lock(&eject_page_mutex);
	list_for_each_entry_safe(item, next, &eject_page_list, list) {
		if (pfn == item->pfn) {
			list_del(&item->list);
			ret = item;
			break;
		}
	}
	mutex_unlock(&eject_page_mutex);

	return ret;
}

static void page_eject_add_pfn_locked(struct ejected_pfn *item)
{
	mutex_lock(&eject_page_mutex);
	list_add_tail(&item->list, &eject_page_list);
	mutex_unlock(&eject_page_mutex);
}

static void page_eject_clear_list_locked(void)
{
	struct ejected_pfn *item, *next;

	mutex_lock(&eject_page_mutex);
	list_for_each_entry_safe(item, next, &eject_page_list, list) {
		list_del(&item->list);
		kfree(item);
	}
	mutex_unlock(&eject_page_mutex);
}

static int page_eject_offline_page(unsigned long pfn)
{
	struct ejected_pfn *item;
	struct page *page;
	int ret;

	page = pfn_to_online_page(pfn);
	if (!page)
		return -EINVAL;

	if (PageHWPoison(page)) {
		pr_err("page fail to be offlined, page is already offlined, pfn: %#lx\n", pfn);
		return -EINVAL;
	}

	item = kzalloc(sizeof(struct ejected_pfn), GFP_KERNEL);
	if (!item)
		return -ENOMEM;

	/*
	 * if soft_offline_page return 0 because PageHWPoison, this pfn
	 * will add to list and this add will be removed during online
	 * since it is poisoned.
	 */
	ret = soft_offline_page(pfn, 0);
	if (ret) {
		pr_err("page fail to be offlined, soft_offline_page failed(%d), pfn=%#lx\n",
		       ret, pfn);
		kfree(item);
		return ret;
	}

	item->pfn = pfn;

	page_eject_add_pfn_locked(item);

	return 0;
}

static int page_eject_online_page(unsigned long pfn)
{
	struct ejected_pfn *item;
	struct page *page;
	int ret;

	page = pfn_to_online_page(pfn);
	if (!page)
		return -EINVAL;

	item = page_eject_remove_pfn_locked(pfn);
	if (!item) {
		pr_err("page failed to be onlined, pfn: %#lx\n", pfn);
		return -EINVAL;
	}

	ret = soft_online_page(pfn);
	if (!ret) {
		kfree(item);
		return ret;
	}

	/* re-add pfn to list if unpoison failed */
	page_eject_add_pfn_locked(item);
	pr_err("page failed to be onlined, online error(%d), pfn: %#lx\n",
		ret, pfn);
	return ret;
}

static int page_eject_remove_page(unsigned long pfn)
{
	struct ejected_pfn *item;

	item = page_eject_remove_pfn_locked(pfn);
	if (!item) {
		pr_info("page fail to be removed, pfn: %#lx\n", pfn);
		return -EINVAL;
	}

	kfree(item);

	return 0;
}

static ssize_t offline_store(struct kobject *kobj, struct kobj_attribute *attr,
			     const char *buf, size_t count)
{
	u64 paddr;
	int res;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	if (kstrtoull(buf, 16, &paddr))
		return -EINVAL;

	res = page_eject_offline_page(paddr >> PAGE_SHIFT);
	if (res)
		return res;

	return count;
}

static ssize_t online_store(struct kobject *kobj, struct kobj_attribute *attr,
			    const char *buf, size_t count)
{
	u64 paddr;
	int res;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	if (kstrtoull(buf, 16, &paddr))
		return -EINVAL;

	res = page_eject_online_page(paddr >> PAGE_SHIFT);
	if (res)
		return res;

	return count;
}

static ssize_t remove_store(struct kobject *kobj, struct kobj_attribute *attr,
			    const char *buf, size_t count)
{
	u64 paddr;
	int res;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	if (kstrtoull(buf, 16, &paddr))
		return -EINVAL;

	res = page_eject_remove_page(paddr >> PAGE_SHIFT);
	if (res)
		return res;

	return count;
}

static struct kobj_attribute online_attr =
	__ATTR(online_page, 0200, NULL, online_store);
static struct kobj_attribute offline_attr =
	__ATTR(offline_page, 0200, NULL, offline_store);
static struct kobj_attribute remove_attr =
	__ATTR(remove_page, 0200, NULL, remove_store);

static struct attribute *eject_page_attrs[] = {
	&offline_attr.attr,
	&online_attr.attr,
	&remove_attr.attr,
	NULL,
};

static struct attribute_group eject_page_attr_group = {
	.attrs = eject_page_attrs,
};

static int __init page_eject_init(void)
{
	int ret = -ENOMEM;

	eject_page_kobj = kobject_create_and_add("page_eject", kernel_kobj);
	if (!eject_page_kobj)
		return ret;

	ret = sysfs_create_group(eject_page_kobj, &eject_page_attr_group);
	if (ret) {
		kobject_put(eject_page_kobj);
		return ret;
	}

	mutex_init(&eject_page_mutex);

	pr_info("init page eject succeed\n");
	return ret;
}

static void __exit page_eject_exit(void)
{
	page_eject_clear_list_locked();

	kobject_put(eject_page_kobj);

	pr_info("exit page eject succeed\n");
}

module_init(page_eject_init);
module_exit(page_eject_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Ma Wupeng <mawupeng1@huawei.com>");
MODULE_DESCRIPTION("page eject");
