// SPDX-License-Identifier: GPL-2.0+
// Copyright (c) 2016-2017 Hisilicon Limited.

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/fs.h>
#include <linux/errno.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/init.h>
#include <linux/cdev.h>
#include <linux/string.h>
#include <linux/timer.h>
#include <linux/slab.h>
#include <linux/device.h>
#include <linux/dma-mapping.h>
#include <linux/kobject.h>
#include <linux/io.h>
#include <linux/uaccess.h>
#include <linux/atomic.h>

#include "rdfx_main.h"
#include "rdfx_common.h"

struct class *drv_class;
struct device *drv_device;
static int major;

struct rdfx_top_info rdfx_top_info_list[MAX_IB_DEV];

const struct file_operations chr_ops = {
	.owner = THIS_MODULE,
};

static const struct rdfx_dev_id rdfx_dev_tbl[] = {
	{.name = "hisi_",	.ops = NULL},
	{.name = "hns",	.ops = &rdfx_ops_hw_v2},
};

/*
 * if can not find optstring, return -EINVAL;
 * if find optstring, return 0
 *         if there's input value, parg will be set with input
 *         if there's no input value, parg will be set to '\0'
 */
int parg_getopt(char *input, char *optstring, char *parg)
{
	char *_input;
	char *p;
	int cnt = 0;
	char _optstring[3];

	if (input == NULL || optstring == NULL)
		return -EINVAL;
	_input = kmalloc(strlen(input) + 1, GFP_KERNEL);
	if (ZERO_OR_NULL_PTR(_input))
		return -ENOMEM;
	strcpy(_input, input);
	_optstring[0] = '-';
	_optstring[1] = optstring[0];
	_optstring[2] = '\0';
	p = strstr(_input, _optstring);
	if (!p) {
		kfree(_input);
		return -EINVAL;
	}
	if (optstring[1] == '\0' || parg == NULL) {
		kfree(_input);
		return 0;
	}
	p += 2;
	while (*p == ' ')
		p++;
	while (*p != ' ' && *p != '\0') {
		p++;
		cnt++;
	}
	if (cnt >= DEF_OPT_STR_LEN) {
		kfree(_input);
		return -EINVAL;
	}
	*p = '\0';
	p -= cnt;
	strcpy(parg, p);
	kfree(_input);

	return 0;
}

static char *strtok_r(char *s, const char *delim, char **save_ptr)
{
	char *token;

	if (s == NULL)
		s = *save_ptr;

	/* Scan to move after delimiters */
	s += strspn(s, delim);
	if (*s == (char)0)
		return NULL;

	/* Find the end of the token.  */
	token = s;
	s = strpbrk(token, delim);
	if (s == NULL)/* This token finishes the string.  */
		*save_ptr = strchr(token, 0);
	else {/* Terminate the token and make *SAVE_PTR point past it.  */
		*s = 0;
		*save_ptr = s + 1;
	}

	return token;
}

char *strtok(char *s, const char *delim)
{
	static char *last;

	return strtok_r(s, delim, &last);
}

int str_to_ll(char *p_buf, unsigned long long *pll_val, unsigned int *num)
{
	unsigned long long lng = 0;
	long long convert_val;
	char *p = NULL;
	char delim[] = ",";
	unsigned int idx = 0;
	unsigned int i = 0;
	unsigned long long *arr = NULL;
	int ret = 0;

	arr = kzalloc(sizeof(unsigned long long) *
				SYSFS_MAX_PARA, GFP_KERNEL);
	if (ZERO_OR_NULL_PTR(arr))
		return -ENOMEM;

	p = strtok(p_buf, delim);
	while (p) {
		if (kstrtoll(p, 0, &convert_val)) {
			pr_info("convert str failed\n");
			ret = -EINVAL;
			goto out;
		}
		lng = (unsigned long long)convert_val;
		arr[idx] = lng;
		pr_info("arr[%u] = 0x%llx\n", idx, arr[idx]);
		idx++;
		if (idx >= SYSFS_MAX_PARA) {
			pr_err("sub string num should not bigger than 16\n");
			ret = -EINVAL;
			goto out;
		}
		p = strtok(NULL, delim);
	}

	*num = idx;
	for (i = 0; i < idx; i++)
		*(pll_val + i) = arr[i];

out:
	kfree(arr);

	return ret;
}

int str_match(char *s, const char *delim)
{
	int num = strspn(s, delim);

	if (num != 0)
		return 1;
	else
		return 0;
}

int check_input(char *buf, unsigned long long *a_val, unsigned int max,
		unsigned int min, unsigned int *param_num)
{
	int ret;

	ret = str_to_ll(buf, a_val, param_num);
	if (ret) {
		pr_info("parse input string err.\r\n");
		return ret;
	}

	if ((*param_num > max) || (*param_num < min)) {
		pr_info("para num(0x%x) is invalid.\n", *param_num);
		return -EINVAL;
	}

	return 0;
}

struct rdfx_info *rdfx_find_rdfx_info(char *dev_name)
{
	int i;

	if (!strlen(dev_name))
		return NULL;

	for (i = 0; i < MAX_IB_DEV; i++) {
		if (!rdfx_top_info_list[i].dev)
			continue;
		if (!memcmp(dev_name,
			(rdfx_top_info_list[i].rdfx)->dev.dev_name,
			strlen((rdfx_top_info_list[i].rdfx)->dev.dev_name))) {
			pr_info("get rdfx info, name:%s, num: %d",
				dev_name, i);
			return rdfx_top_info_list[i].rdfx;
		}
	}

	return NULL;
}

void *rdfx_buf_offset(struct dfx_buf *buf, int offset)
{
	u32 bits_per_long_val = BITS_PER_LONG;
	u32 page_size = 1 << buf->page_shift;

	if ((bits_per_long_val == 64 && buf->page_shift == PAGE_SHIFT) ||
	    buf->nbufs == 1)
		return buf->direct.buf ?
		       (void *)((char *)(buf->direct.buf) + offset) : NULL;
	else
		return (buf->page_list &&
		       buf->page_list[offset >> buf->page_shift].buf) ?
		       (void *)((char *)
		       (buf->page_list[offset >> buf->page_shift].buf) +
		       (offset & (page_size - 1))) : NULL;
}

static int rdfx_info_init(struct ib_device *ib_dev, int i)
{
	int j;

	for (j = 0; j < sizeof(rdfx_dev_tbl)/sizeof(struct rdfx_dev_id); j++) {
		if (!memcmp(rdfx_dev_tbl[j].name, ib_dev->name,
		    strlen(rdfx_dev_tbl[j].name)) && rdfx_dev_tbl[j].ops) {
			rdfx_top_info_list[i].rdfx =
				rdfx_dev_tbl[j].ops->get_dfx(ib_dev);
			(rdfx_top_info_list[i].rdfx)->ops = rdfx_dev_tbl[j].ops;
			(rdfx_top_info_list[i].rdfx)->drv_dev = drv_device;

			memset(&((rdfx_top_info_list[i].rdfx)->kobj), 0,
				sizeof(struct kobject));
			strlcpy((rdfx_top_info_list[i].rdfx)->dev.dev_name,
				ib_dev->name, IB_DEVICE_NAME_MAX);
			pr_info("init dev %s success\n", ib_dev->name);
			break;
		}
	}

	if (!rdfx_top_info_list[i].rdfx) {
		pr_err("dev(%s) not support\n",	ib_dev->name);
		return -EINVAL;
	}
	return 0;
}

static void rdfx_add_device(struct ib_device *ib_dev)
{
	int i = 0;
	int ret = 0;
	struct rdfx_ops *ops = NULL;

	for (i = 0; i < MAX_IB_DEV; i++)
		if (!rdfx_top_info_list[i].dev)
			break;
	if (i == MAX_IB_DEV) {
		pr_err("rdfx add device failed, rdfx top info list is full\n.");
		return;
	}

	rdfx_top_info_list[i].dev = ib_dev;
	pr_info("rdfx add ib device(%pK), idx - %d, name - %s\n",
		ib_dev, i, ib_dev->name);
	ret = rdfx_info_init(ib_dev, i);
	if (ret) {
		pr_err("rdfx info init failed\n");
		rdfx_top_info_list[i].dev = NULL;
		return;
	}

	ops = (rdfx_top_info_list[i].rdfx)->ops;
	ret = ops->add_sysfs(rdfx_top_info_list[i].rdfx);
	if (ret) {
		rdfx_top_info_list[i].rdfx = NULL;
		rdfx_top_info_list[i].dev = NULL;
		pr_err("rdfx add hw sysfs failed\n");
	}
}

static void rdfx_remove_device(struct ib_device *ib_dev, void *client_data)
{
	int i = 0;
	struct rdfx_ops *ops = NULL;

	for (i = 0; i < MAX_IB_DEV; i++) {
		if (rdfx_top_info_list[i].dev &&
		    (rdfx_top_info_list[i].dev == ib_dev)) {
			pr_info("rdfx rm ib device(%pK), idx - %d, name - %s\n",
				ib_dev, i, ib_dev->name);
			ops = (rdfx_top_info_list[i].rdfx)->ops;
			ops->del_sysfs(rdfx_top_info_list[i].rdfx);
			memset(&rdfx_top_info_list[i], 0,
			       sizeof(struct rdfx_top_info));
		}
	}
}

struct ib_client rdfx_client = {
	.name   = "rdfx_client",
	.add	= rdfx_add_device,
	.remove = rdfx_remove_device,
};

static int __init rdfx_init(void)
{
	int ret = 0;

	major = register_chrdev(0, DFX_DEVICE_NAME, &chr_ops);
	if (major < 0) {
		pr_err("Sorry, register the character device failed\n ");
		return major;
	}

	/*default content:/sys/class */
	drv_class = class_create(THIS_MODULE, DFX_DEVICE_NAME);
	if (IS_ERR(drv_class)) {
		pr_err("rdfx register client failed\n");
		goto class_create_failed;
	}
	drv_device = device_create(drv_class, NULL, MKDEV(major, 0),
				   NULL, DFX_DEVICE_NAME);
	if (IS_ERR(drv_device)) {
		pr_err("rdfx register device failed\n");
		goto device_regist_failed;
	}

	memset(rdfx_top_info_list, 0, sizeof(rdfx_top_info_list));

	ret = ib_register_client(&rdfx_client);
	if (ret) {
		pr_err("rdfx register client failed, ret = %d\n", ret);
		goto register_client_failed;
	}

	/*init and add kobjects*/
	ret = rdfx_add_common_sysfs(drv_device);
	if (ret) {
		pr_err("rdfx add common sysfs failed, ret = %d\n", ret);
		goto add_common_sysfs_failed;
	}

	return 0;

add_common_sysfs_failed:
	ib_unregister_client(&rdfx_client);
register_client_failed:
	device_unregister(drv_device);
device_regist_failed:
	class_destroy(drv_class);
class_create_failed:
	unregister_chrdev(major, DFX_DEVICE_NAME);

	return ret;
}

void __exit rdfx_exit(void)
{
	pr_info("rmmod rdfx module\n");

	rdfx_del_common_sysfs();
	ib_unregister_client(&rdfx_client);

	device_destroy(drv_class, MKDEV(major, 0));
	class_destroy(drv_class);
	unregister_chrdev(major, DFX_DEVICE_NAME);
}

module_init(rdfx_init);
module_exit(rdfx_exit);

MODULE_AUTHOR("Huawei Tech. Co., Ltd.");
MODULE_DESCRIPTION("Hisilicon Hip08 Family RoCE DFx Driver");
MODULE_LICENSE("Dual BSD/GPL");

