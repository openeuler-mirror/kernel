// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/*
 * Copyright (c) 2023 Hisilicon Limited.
 */

#include <rdma/ib_sysfs.h>

#include "hnae3.h"
#include "hns_roce_device.h"
#include "hns_roce_hw_v2.h"

static void scc_param_config_work(struct work_struct *work)
{
	struct hns_roce_scc_param *scc_param = container_of(work,
			struct hns_roce_scc_param, scc_cfg_dwork.work);
	struct hns_roce_dev *hr_dev = scc_param->hr_dev;

	hr_dev->hw->config_scc_param(hr_dev, scc_param->algo_type);
}

static void get_default_scc_param(struct hns_roce_dev *hr_dev)
{
	int ret;
	int i;

	for (i = 0; i < HNS_ROCE_SCC_ALGO_TOTAL; i++) {
		hr_dev->scc_param[i].timestamp = jiffies;
		ret = hr_dev->hw->query_scc_param(hr_dev, i);
		if (ret && ret != -EOPNOTSUPP)
			ibdev_warn_ratelimited(&hr_dev->ib_dev,
				"failed to get default parameters of scc algo %d, ret = %d.\n",
				i, ret);
	}
}

int hns_roce_alloc_scc_param(struct hns_roce_dev *hr_dev)
{
	struct hns_roce_scc_param *scc_param;
	int i;

	scc_param = kvcalloc(HNS_ROCE_SCC_ALGO_TOTAL, sizeof(*scc_param),
			     GFP_KERNEL);
	if (!scc_param)
		return -ENOMEM;

	for (i = 0; i < HNS_ROCE_SCC_ALGO_TOTAL; i++) {
		scc_param[i].algo_type = i;
		scc_param[i].hr_dev = hr_dev;
		INIT_DELAYED_WORK(&scc_param[i].scc_cfg_dwork,
				  scc_param_config_work);
	}

	hr_dev->scc_param = scc_param;

	get_default_scc_param(hr_dev);

	return 0;
}
void hns_roce_dealloc_scc_param(struct hns_roce_dev *hr_dev)
{
	int i;

	if (!hr_dev->scc_param)
		return;

	for (i = 0; i < HNS_ROCE_SCC_ALGO_TOTAL; i++)
		cancel_delayed_work_sync(&hr_dev->scc_param[i].scc_cfg_dwork);

	kvfree(hr_dev->scc_param);
	hr_dev->scc_param = NULL;
}

struct hns_port_cc_attr {
	struct ib_port_attribute port_attr;
	enum hns_roce_scc_algo algo_type;
	u32 offset;
	u32 size;
	u32 max;
	u32 min;
};

static int scc_attr_check(struct hns_roce_dev *hr_dev,
			  struct hns_port_cc_attr *scc_attr, u32 port_num)
{
	if (port_num > hr_dev->caps.num_ports)
		return -ENODEV;

	if (WARN_ON(scc_attr->size > sizeof(u32)))
		return -EINVAL;

	if (WARN_ON(scc_attr->algo_type >= HNS_ROCE_SCC_ALGO_TOTAL))
		return -EINVAL;

	return 0;
}

static ssize_t scc_attr_show(struct ib_device *ibdev, u32 port_num,
			     struct ib_port_attribute *attr, char *buf)
{
	struct hns_port_cc_attr *scc_attr =
		container_of(attr, struct hns_port_cc_attr, port_attr);
	struct hns_roce_dev *hr_dev = to_hr_dev(ibdev);
	struct hns_roce_scc_param *scc_param;
	__le32 val = 0;
	int ret;

	ret = scc_attr_check(hr_dev, scc_attr, port_num);
	if (ret)
		return ret;

	scc_param = &hr_dev->scc_param[scc_attr->algo_type];

	memcpy(&val, (void *)scc_param + scc_attr->offset, scc_attr->size);

	return sysfs_emit(buf, "%u\n", le32_to_cpu(val));
}

static ssize_t scc_attr_store(struct ib_device *ibdev, u32 port_num,
			      struct ib_port_attribute *attr, const char *buf,
			      size_t count)
{
	struct hns_port_cc_attr *scc_attr =
		container_of(attr, struct hns_port_cc_attr, port_attr);
	struct hns_roce_dev *hr_dev = to_hr_dev(ibdev);
	struct hns_roce_scc_param *scc_param;
	unsigned long lifespan_jiffies;
	unsigned long exp_time;
	__le32 attr_val;
	u32 val;
	int ret;

	ret = scc_attr_check(hr_dev, scc_attr, port_num);
	if (ret)
		return ret;

	if (kstrtou32(buf, 0, &val))
		return -EINVAL;

	if (val > scc_attr->max || val < scc_attr->min)
		return -EINVAL;

	attr_val = cpu_to_le32(val);
	scc_param = &hr_dev->scc_param[scc_attr->algo_type];
	memcpy((void *)scc_param + scc_attr->offset, &attr_val,
	       scc_attr->size);

	/* lifespan is only used for driver */
	if (scc_attr->offset >= offsetof(typeof(*scc_param), lifespan))
		return count;

	lifespan_jiffies = msecs_to_jiffies(scc_param->lifespan);
	exp_time = scc_param->timestamp + lifespan_jiffies;

	if (time_is_before_eq_jiffies(exp_time)) {
		scc_param->timestamp = jiffies;
		queue_delayed_work(hr_dev->irq_workq, &scc_param->scc_cfg_dwork,
				   lifespan_jiffies);
	}

	return count;
}

static umode_t scc_attr_is_visible(struct kobject *kobj,
				   struct attribute *attr, int i)
{
	struct ib_port_attribute *port_attr =
		container_of(attr, struct ib_port_attribute, attr);
	struct hns_port_cc_attr *scc_attr =
		container_of(port_attr, struct hns_port_cc_attr, port_attr);
	u32 port_num;
	struct ib_device *ibdev = ib_port_sysfs_get_ibdev_kobj(kobj, &port_num);
	struct hns_roce_dev *hr_dev = to_hr_dev(ibdev);

	if (!hr_dev->scc_param)
		return 0;

	if (hr_dev->is_vf ||
	    !(hr_dev->caps.flags & HNS_ROCE_CAP_FLAG_QP_FLOW_CTRL))
		return 0;

	if (!(hr_dev->caps.cong_cap & (1 << scc_attr->algo_type)))
		return 0;

	return 0644;
}

#define __HNS_SCC_ATTR(_name, _type, _offset, _size, _min, _max) {		\
	.port_attr = __ATTR(_name, 0644, scc_attr_show,  scc_attr_store),	\
	.algo_type = _type,							\
	.offset = _offset,							\
	.size = _size,								\
	.min = _min,								\
	.max = _max,								\
}

#define HNS_PORT_DCQCN_CC_ATTR_RW(_name, NAME)				\
	struct hns_port_cc_attr hns_roce_port_attr_dcqcn_##_name =	\
	__HNS_SCC_ATTR(_name, HNS_ROCE_SCC_ALGO_DCQCN,			\
			HNS_ROCE_DCQCN_##NAME##_OFS,			\
			HNS_ROCE_DCQCN_##NAME##_SZ,			\
			0, HNS_ROCE_DCQCN_##NAME##_MAX)

HNS_PORT_DCQCN_CC_ATTR_RW(ai, AI);
HNS_PORT_DCQCN_CC_ATTR_RW(f, F);
HNS_PORT_DCQCN_CC_ATTR_RW(tkp, TKP);
HNS_PORT_DCQCN_CC_ATTR_RW(tmp, TMP);
HNS_PORT_DCQCN_CC_ATTR_RW(alp, ALP);
HNS_PORT_DCQCN_CC_ATTR_RW(max_speed, MAX_SPEED);
HNS_PORT_DCQCN_CC_ATTR_RW(g, G);
HNS_PORT_DCQCN_CC_ATTR_RW(al, AL);
HNS_PORT_DCQCN_CC_ATTR_RW(cnp_time, CNP_TIME);
HNS_PORT_DCQCN_CC_ATTR_RW(ashift, ASHIFT);
HNS_PORT_DCQCN_CC_ATTR_RW(lifespan, LIFESPAN);

static struct attribute *dcqcn_param_attrs[] = {
	&hns_roce_port_attr_dcqcn_ai.port_attr.attr,
	&hns_roce_port_attr_dcqcn_f.port_attr.attr,
	&hns_roce_port_attr_dcqcn_tkp.port_attr.attr,
	&hns_roce_port_attr_dcqcn_tmp.port_attr.attr,
	&hns_roce_port_attr_dcqcn_alp.port_attr.attr,
	&hns_roce_port_attr_dcqcn_max_speed.port_attr.attr,
	&hns_roce_port_attr_dcqcn_g.port_attr.attr,
	&hns_roce_port_attr_dcqcn_al.port_attr.attr,
	&hns_roce_port_attr_dcqcn_cnp_time.port_attr.attr,
	&hns_roce_port_attr_dcqcn_ashift.port_attr.attr,
	&hns_roce_port_attr_dcqcn_lifespan.port_attr.attr,
	NULL,
};

static const struct attribute_group dcqcn_cc_param_group = {
	.name = "dcqcn_cc_param",
	.attrs = dcqcn_param_attrs,
	.is_visible = scc_attr_is_visible,
};

#define HNS_PORT_LDCP_CC_ATTR_RW(_name, NAME)				\
	struct hns_port_cc_attr hns_roce_port_attr_ldcp_##_name =	\
	__HNS_SCC_ATTR(_name, HNS_ROCE_SCC_ALGO_LDCP,			\
			HNS_ROCE_LDCP_##NAME##_OFS,			\
			HNS_ROCE_LDCP_##NAME##_SZ,			\
			0, HNS_ROCE_LDCP_##NAME##_MAX)

HNS_PORT_LDCP_CC_ATTR_RW(cwd0, CWD0);
HNS_PORT_LDCP_CC_ATTR_RW(alpha, ALPHA);
HNS_PORT_LDCP_CC_ATTR_RW(gamma, GAMMA);
HNS_PORT_LDCP_CC_ATTR_RW(beta, BETA);
HNS_PORT_LDCP_CC_ATTR_RW(eta, ETA);
HNS_PORT_LDCP_CC_ATTR_RW(lifespan, LIFESPAN);

static struct attribute *ldcp_param_attrs[] = {
	&hns_roce_port_attr_ldcp_cwd0.port_attr.attr,
	&hns_roce_port_attr_ldcp_alpha.port_attr.attr,
	&hns_roce_port_attr_ldcp_gamma.port_attr.attr,
	&hns_roce_port_attr_ldcp_beta.port_attr.attr,
	&hns_roce_port_attr_ldcp_eta.port_attr.attr,
	&hns_roce_port_attr_ldcp_lifespan.port_attr.attr,
	NULL,
};

static const struct attribute_group ldcp_cc_param_group = {
	.name = "ldcp_cc_param",
	.attrs = ldcp_param_attrs,
	.is_visible = scc_attr_is_visible,
};

#define HNS_PORT_HC3_CC_ATTR_RW(_name, NAME)				\
	struct hns_port_cc_attr hns_roce_port_attr_hc3_##_name =	\
	__HNS_SCC_ATTR(_name, HNS_ROCE_SCC_ALGO_HC3,			\
			HNS_ROCE_HC3_##NAME##_OFS,			\
			HNS_ROCE_HC3_##NAME##_SZ,			\
			0, HNS_ROCE_HC3_##NAME##_MAX)

HNS_PORT_HC3_CC_ATTR_RW(initial_window, INITIAL_WINDOW);
HNS_PORT_HC3_CC_ATTR_RW(bandwidth, BANDWIDTH);
HNS_PORT_HC3_CC_ATTR_RW(qlen_shift, QLEN_SHIFT);
HNS_PORT_HC3_CC_ATTR_RW(port_usage_shift, PORT_USAGE_SHIFT);
HNS_PORT_HC3_CC_ATTR_RW(over_period, OVER_PERIOD);
HNS_PORT_HC3_CC_ATTR_RW(max_stage, MAX_STAGE);
HNS_PORT_HC3_CC_ATTR_RW(gamma_shift, GAMMA_SHIFT);
HNS_PORT_HC3_CC_ATTR_RW(lifespan, LIFESPAN);

static struct attribute *hc3_param_attrs[] = {
	&hns_roce_port_attr_hc3_initial_window.port_attr.attr,
	&hns_roce_port_attr_hc3_bandwidth.port_attr.attr,
	&hns_roce_port_attr_hc3_qlen_shift.port_attr.attr,
	&hns_roce_port_attr_hc3_port_usage_shift.port_attr.attr,
	&hns_roce_port_attr_hc3_over_period.port_attr.attr,
	&hns_roce_port_attr_hc3_max_stage.port_attr.attr,
	&hns_roce_port_attr_hc3_gamma_shift.port_attr.attr,
	&hns_roce_port_attr_hc3_lifespan.port_attr.attr,
	NULL,
};

static const struct attribute_group hc3_cc_param_group = {
	.name = "hc3_cc_param",
	.attrs = hc3_param_attrs,
	.is_visible = scc_attr_is_visible,
};

#define HNS_PORT_DIP_CC_ATTR_RW(_name, NAME)				\
	struct hns_port_cc_attr hns_roce_port_attr_dip_##_name =	\
	__HNS_SCC_ATTR(_name, HNS_ROCE_SCC_ALGO_DIP,			\
			HNS_ROCE_DIP_##NAME##_OFS,			\
			HNS_ROCE_DIP_##NAME##_SZ,			\
			0, HNS_ROCE_DIP_##NAME##_MAX)

HNS_PORT_DIP_CC_ATTR_RW(ai, AI);
HNS_PORT_DIP_CC_ATTR_RW(f, F);
HNS_PORT_DIP_CC_ATTR_RW(tkp, TKP);
HNS_PORT_DIP_CC_ATTR_RW(tmp, TMP);
HNS_PORT_DIP_CC_ATTR_RW(alp, ALP);
HNS_PORT_DIP_CC_ATTR_RW(max_speed, MAX_SPEED);
HNS_PORT_DIP_CC_ATTR_RW(g, G);
HNS_PORT_DIP_CC_ATTR_RW(al, AL);
HNS_PORT_DIP_CC_ATTR_RW(cnp_time, CNP_TIME);
HNS_PORT_DIP_CC_ATTR_RW(ashift, ASHIFT);
HNS_PORT_DIP_CC_ATTR_RW(lifespan, LIFESPAN);

static struct attribute *dip_param_attrs[] = {
	&hns_roce_port_attr_dip_ai.port_attr.attr,
	&hns_roce_port_attr_dip_f.port_attr.attr,
	&hns_roce_port_attr_dip_tkp.port_attr.attr,
	&hns_roce_port_attr_dip_tmp.port_attr.attr,
	&hns_roce_port_attr_dip_alp.port_attr.attr,
	&hns_roce_port_attr_dip_max_speed.port_attr.attr,
	&hns_roce_port_attr_dip_g.port_attr.attr,
	&hns_roce_port_attr_dip_al.port_attr.attr,
	&hns_roce_port_attr_dip_cnp_time.port_attr.attr,
	&hns_roce_port_attr_dip_ashift.port_attr.attr,
	&hns_roce_port_attr_dip_lifespan.port_attr.attr,
	NULL,
};

static const struct attribute_group dip_cc_param_group = {
	.name = "dip_cc_param",
	.attrs = dip_param_attrs,
	.is_visible = scc_attr_is_visible,
};

const struct attribute_group *hns_attr_port_groups[] = {
	&dcqcn_cc_param_group,
	&ldcp_cc_param_group,
	&hc3_cc_param_group,
	&dip_cc_param_group,
	NULL,
};
