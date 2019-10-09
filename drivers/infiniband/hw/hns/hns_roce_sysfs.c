// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) 2016-2017 Hisilicon Limited.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <linux/acpi.h>
#include <linux/etherdevice.h>
#include <linux/interrupt.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <net/addrconf.h>
#include <rdma/ib_addr.h>
#include <rdma/ib_cache.h>
#include <rdma/ib_umem.h>

#include "hnae3.h"
#include "hns_roce_common.h"
#include "hns_roce_device.h"
#include "hns_roce_cmd.h"
#include "hns_roce_hem.h"
#include "hns_roce_hw_v2.h"



static ssize_t cqc_store(struct device *dev,
			 struct device_attribute *attr,
			 const char *buf, size_t count)
{
	struct hns_roce_dev *hr_dev =
		container_of(dev, struct hns_roce_dev, ib_dev.dev);
	int ret;

	ret = kstrtou32(buf, 10, &hr_dev->hr_stat.cqn);
	if (ret) {
		dev_err(dev, "Input params format unmatch\n");
		return -EINVAL;
	}

	return strnlen(buf, count);
}

static ssize_t cqc_show(struct device *dev,
			struct device_attribute *attr,
			char *buf)
{
	struct hns_roce_dev *hr_dev =
		container_of(dev, struct hns_roce_dev, ib_dev.dev);
	int ret;
	int count = 0;

	ret = hr_dev->dfx->query_cqc_stat(hr_dev, buf, &count);
	if (ret) {
		dev_err(dev, "CQC query failed(%d).", ret);
		return -EBUSY;
	}

	return count;
}

static ssize_t cmd_show(struct device *dev,
			 struct device_attribute *attr, char *buf)
{
	struct hns_roce_dev *hr_dev =
		container_of(dev, struct hns_roce_dev, ib_dev.dev);
	int ret;
	int count = 0;

	ret = hr_dev->dfx->query_cmd_stat(hr_dev, buf, &count);
	if (ret) {
		dev_err(dev, "Cmd query failed(%d).", ret);
		return -EBUSY;
	}

	return count;
}

static ssize_t pkt_show(struct device *dev,
			 struct device_attribute *attr, char *buf)
{
	struct hns_roce_dev *hr_dev =
		container_of(dev, struct hns_roce_dev, ib_dev.dev);
	int ret;
	int count = 0;

	ret = hr_dev->dfx->query_pkt_stat(hr_dev, buf, &count);
	if (ret) {
		dev_err(dev, "Pkt query failed(%d).", ret);
		return -EBUSY;
	}

	return count;
}

static ssize_t ceqc_store(struct device *dev,
			 struct device_attribute *attr,
			 const char *buf, size_t count)
{
	struct hns_roce_dev *hr_dev =
		container_of(dev, struct hns_roce_dev, ib_dev.dev);
	int ret;

	ret = kstrtou32(buf, 10, &hr_dev->hr_stat.ceqn);
	if (ret) {
		dev_err(dev, "Input params format unmatch\n");
		return -EINVAL;
	}

	return strnlen(buf, count);
}

static ssize_t ceqc_show(struct device *dev,
			 struct device_attribute *attr, char *buf)
{
	struct hns_roce_dev *hr_dev =
		container_of(dev, struct hns_roce_dev, ib_dev.dev);
	int ret;
	int count = 0;

	ret = hr_dev->dfx->query_ceqc_stat(hr_dev, buf, &count);
	if (ret) {
		dev_err(dev, "CEQC query failed");
		return -EBUSY;
	}

	return count;
}

static ssize_t aeqc_store(struct device *dev, struct device_attribute *attr,
			 const char *buf, size_t count)
{
	struct hns_roce_dev *hr_dev =
		container_of(dev, struct hns_roce_dev, ib_dev.dev);
	int ret;

	ret = kstrtou32(buf, 10, &hr_dev->hr_stat.aeqn);
	if (ret) {
		dev_err(dev, "Input params format unmatch\n");
		return -EINVAL;
	}

	return strnlen(buf, count);
}

static ssize_t aeqc_show(struct device *dev, struct device_attribute *attr,
			 char *buf)

{
	struct hns_roce_dev *hr_dev =
		container_of(dev, struct hns_roce_dev, ib_dev.dev);
	int ret;
	int count = 0;

	ret = hr_dev->dfx->query_aeqc_stat(hr_dev, buf, &count);
	if (ret) {
		dev_err(dev, "aeqc query failed");
		return -EBUSY;
	}

	return count;
}

static ssize_t qpc_store(struct device *dev, struct device_attribute *attr,
			 const char *buf, size_t count)
{
	struct hns_roce_dev *hr_dev =
		container_of(dev, struct hns_roce_dev, ib_dev.dev);
	int ret;

	ret = kstrtou32(buf, 10, &hr_dev->hr_stat.qpn);
	if (ret) {
		dev_err(dev, "Input params format unmatch\n");
		return -EINVAL;
	}

	return strnlen(buf, count);
}

static ssize_t qpc_show(struct device *dev, struct device_attribute *attr,
			char *buf)
{
	struct hns_roce_dev *hr_dev =
		container_of(dev, struct hns_roce_dev, ib_dev.dev);
	int ret;
	int count = 0;

	ret = hr_dev->dfx->query_qpc_stat(hr_dev,
				    buf, &count);
	if (ret) {
		dev_err(dev, "QPC query failed");
		return -EBUSY;
	}

	return count;
}

static ssize_t srqc_store(struct device *dev, struct device_attribute *attr,
			 const char *buf, size_t count)
{
	struct hns_roce_dev *hr_dev =
		container_of(dev, struct hns_roce_dev, ib_dev.dev);
	int ret;

	ret = kstrtou32(buf, 10, &hr_dev->hr_stat.srqn);
	if (ret) {
		dev_err(dev, "Input params format unmatch\n");
		return -EINVAL;
	}

	return strnlen(buf, count);
}

static ssize_t srqc_show(struct device *dev, struct device_attribute *attr,
			 char *buf)
{
	struct hns_roce_dev *hr_dev =
		container_of(dev, struct hns_roce_dev, ib_dev.dev);
	int ret;
	int count = 0;

	ret = hr_dev->dfx->query_srqc_stat(hr_dev, buf, &count);
	if (ret) {
		dev_err(dev, "SRQC query failed");
		return -EBUSY;
	}

	return count;
}

static ssize_t mpt_store(struct device *dev, struct device_attribute *attr,
			 const char *buf, size_t count)
{
	struct hns_roce_dev *hr_dev =
		container_of(dev, struct hns_roce_dev, ib_dev.dev);
	int ret;

	ret = kstrtou32(buf, 10, &hr_dev->hr_stat.key);
	if (ret) {
		dev_err(dev, "Input params format unmatch\n");
		return -EINVAL;
	}

	return strnlen(buf, count);
}

static ssize_t mpt_show(struct device *dev, struct device_attribute *attr,
			char *buf)
{
	struct hns_roce_dev *hr_dev =
		container_of(dev, struct hns_roce_dev, ib_dev.dev);
	int ret;
	int count = 0;

	ret = hr_dev->dfx->query_mpt_stat(hr_dev, buf, &count);
	if (ret) {
		dev_err(dev, "mpt query failed");
		return -EBUSY;
	}

	return count;
}

static ssize_t coalesce_maxcnt_show(struct device *dev,
				    struct device_attribute *attr, char *buf)
{
	struct hns_roce_dev *hr_dev = container_of(dev, struct hns_roce_dev,
						   ib_dev.dev);
	struct hns_roce_eq *eq = hr_dev->eq_table.eq;

	return scnprintf(buf, PAGE_SIZE, "%d\n", eq->eq_max_cnt);
}

static ssize_t coalesce_maxcnt_store(struct device *dev,
				     struct device_attribute *attr,
				     const char *buf, size_t count)
{
	struct hns_roce_dev *hr_dev = container_of(dev, struct hns_roce_dev,
						   ib_dev.dev);
	struct hns_roce_eq *eq;
	u32 int_maxcnt;
	int ceq_num;
	int i;
	int ret;

	ceq_num = hr_dev->caps.num_comp_vectors;

	ret = kstrtou32(buf, 10, &int_maxcnt);
	if (ret) {
		dev_err(dev,
			"Input params of irq coalesce maxcnt format unmatch\n");
		return -EINVAL;
	}

	if (int_maxcnt > HNS_ROCE_CEQ_MAX_BURST_NUM) {
		dev_err(dev, "int_maxcnt(%d) must be less than 2^16!\n",
			int_maxcnt);
		return -EINVAL;
	}

	for (i = 0; i < ceq_num; i++) {
		eq = &hr_dev->eq_table.eq[i];
		eq->eq_max_cnt = int_maxcnt;
		ret = hr_dev->dfx->modify_eq(hr_dev, eq, eq->eq_max_cnt, 0,
					    HNS_ROCE_EQ_MAXCNT_MASK);
		if (ret) {
			dev_err(dev, "EQC(%d) modify failed(%d).\n", eq->eqn,
				ret);
			return -EBUSY;
		}
	}

	return count;
}

static ssize_t coalesce_period_show(struct device *dev,
				    struct device_attribute *attr, char *buf)
{
	struct hns_roce_dev *hr_dev = container_of(dev, struct hns_roce_dev,
						   ib_dev.dev);
	struct hns_roce_eq *eq = hr_dev->eq_table.eq;

	return scnprintf(buf, PAGE_SIZE, "%d\n", eq->eq_period);
}

static ssize_t coalesce_period_store(struct device *dev,
				     struct device_attribute *attr,
				     const char *buf, size_t count)
{
	struct hns_roce_dev *hr_dev = container_of(dev, struct hns_roce_dev,
						   ib_dev.dev);
	struct hns_roce_eq *eq;
	u32 int_period;
	int ceq_num;
	int i;
	int ret;

	ceq_num = hr_dev->caps.num_comp_vectors;

	ret = kstrtou32(buf, 10, &int_period);
	if (ret) {
		dev_err(dev,
			"Input params of irq coalesce period format unmatch\n");
		return -EINVAL;
	}

	if (int_period > HNS_ROCE_CEQ_MAX_INTERVAL) {
		dev_err(dev, "int_period(%d) must be less than 2^16!\n",
			int_period);
		return -EINVAL;
	}

	for (i = 0; i < ceq_num; i++) {
		eq = &hr_dev->eq_table.eq[i];
		eq->eq_period = int_period;
		ret = hr_dev->dfx->modify_eq(hr_dev, eq, 0, eq->eq_period,
					    HNS_ROCE_EQ_PERIOD_MASK);
		if (ret) {
			dev_err(dev, "EQC(%d) modify failed(%d).\n", eq->eqn,
				ret);
			return -EBUSY;
		}
	}

	return count;
}

static DEVICE_ATTR_RW(aeqc);
static DEVICE_ATTR_RW(qpc);
static DEVICE_ATTR_RW(srqc);
static DEVICE_ATTR_RW(mpt);
static DEVICE_ATTR_RW(ceqc);
static DEVICE_ATTR_RO(pkt);
static DEVICE_ATTR_RO(cmd);
static DEVICE_ATTR_RW(cqc);
static DEVICE_ATTR_RW(coalesce_maxcnt);
static DEVICE_ATTR_RW(coalesce_period);

static struct device_attribute *hns_roce_hw_attrs_list[] = {
	&dev_attr_cmd,
	&dev_attr_cqc,
	&dev_attr_aeqc,
	&dev_attr_qpc,
	&dev_attr_mpt,
	&dev_attr_pkt,
	&dev_attr_ceqc,
	&dev_attr_srqc,
	&dev_attr_coalesce_maxcnt,
	&dev_attr_coalesce_period,
};

int hns_roce_register_sysfs(struct hns_roce_dev *hr_dev)
{
	int ret;
	int  i;

	for (i = 0; i < ARRAY_SIZE(hns_roce_hw_attrs_list); i++) {
		ret = device_create_file(&hr_dev->ib_dev.dev,
				hns_roce_hw_attrs_list[i]);
		if (ret) {
			dev_err(hr_dev->dev, "register_sysfs failed!\n");
			return ret;
		}
	}

	return 0;
}

void hns_roce_unregister_sysfs(struct hns_roce_dev *hr_dev)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(hns_roce_hw_attrs_list); i++)
		device_remove_file(&hr_dev->ib_dev.dev,
				hns_roce_hw_attrs_list[i]);
}
