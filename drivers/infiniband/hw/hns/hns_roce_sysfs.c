// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/*
 * Copyright (c) 2023 Hisilicon Limited.
 */

#include "hnae3.h"
#include "hns_roce_device.h"
#include "hns_roce_hw_v2.h"

struct hns_port_attribute {
	struct attribute attr;
	ssize_t (*show)(struct hns_roce_port *pdata,
			struct hns_port_attribute *attr, char *buf);
	ssize_t (*store)(struct hns_roce_port *pdata,
			 struct hns_port_attribute *attr, const char *buf,
			 size_t count);
};

static void scc_param_config_work(struct work_struct *work)
{
	struct hns_roce_scc_param *scc_param = container_of(work,
			struct hns_roce_scc_param, scc_cfg_dwork.work);
	struct hns_roce_dev *hr_dev = scc_param->hr_dev;

	hr_dev->hw->config_scc_param(hr_dev, scc_param->port_num,
				     scc_param->algo_type);
}

static void get_default_cnp_pri_param(struct hns_roce_dev *hr_dev,
				  struct hns_roce_port *pdata)
{
	if (hr_dev->is_vf || hr_dev->pci_dev->revision <= PCI_REVISION_ID_HIP09)
		return;

	if (hr_dev->mac_type != HNAE3_MAC_ROH ||
	    hr_dev->func_id != MAIN_PF_FUNC_ID)
		return;

	if (!(hr_dev->caps.flags & HNS_ROCE_CAP_FLAG_QP_FLOW_CTRL) ||
	    !(hr_dev->caps.fw_cap & FW_CAP_FLAG_CNP_PRI))
		return;

	hr_dev->hw->query_cnp_pri_param(hr_dev, pdata->port_num);
}

static int alloc_cnp_pri_param(struct hns_roce_dev *hr_dev,
			       struct hns_roce_port *pdata)
{
	struct hns_roce_cnp_pri_param *cnp_pri_param;

	cnp_pri_param = kvzalloc(sizeof(*cnp_pri_param), GFP_KERNEL);
	if (!cnp_pri_param)
		return -ENOMEM;

	cnp_pri_param->hr_dev = hr_dev;
	cnp_pri_param->port_num = pdata->port_num;
	pdata->cnp_pri_param = cnp_pri_param;

	get_default_cnp_pri_param(hr_dev, pdata);

	return 0;
}

static void get_default_scc_param(struct hns_roce_dev *hr_dev,
				  struct hns_roce_port *pdata)
{
	int ret;
	int i;

	for (i = 0; i < HNS_ROCE_SCC_ALGO_TOTAL; i++) {
		pdata->scc_param[i].timestamp = jiffies;
		ret = hr_dev->hw->query_scc_param(hr_dev, pdata->port_num, i);
		if (ret && ret != -EOPNOTSUPP)
			ibdev_warn_ratelimited(&hr_dev->ib_dev,
				"failed to get default parameters of scc algo %d, ret = %d.\n",
				i, ret);
	}
}

static int alloc_scc_param(struct hns_roce_dev *hr_dev,
			   struct hns_roce_port *pdata)
{
	struct hns_roce_scc_param *scc_param;
	int i;

	scc_param = kcalloc(HNS_ROCE_SCC_ALGO_TOTAL, sizeof(*scc_param),
			    GFP_KERNEL);
	if (!scc_param)
		return -ENOMEM;

	for (i = 0; i < HNS_ROCE_SCC_ALGO_TOTAL; i++) {
		scc_param[i].algo_type = i;
		scc_param[i].hr_dev = hr_dev;
		scc_param[i].port_num = pdata->port_num;
		mutex_init(&scc_param[i].scc_mutex);
		INIT_DELAYED_WORK(&scc_param[i].scc_cfg_dwork,
				  scc_param_config_work);
	}

	pdata->scc_param = scc_param;

	get_default_scc_param(hr_dev, pdata);

	return 0;
}

struct hns_port_cc_attr {
	struct hns_port_attribute port_attr;
	enum hns_roce_scc_algo algo_type;
	u32 offset;
	u32 size;
	u32 max;
	u32 min;
};

struct hns_port_cnp_pri_attr {
	struct hns_port_attribute port_attr;
	u32 bit_offset;
	u32 bit_size;
	u32 bit_mask;
	u32 max;
};

static int scc_attr_check(struct hns_port_cc_attr *scc_attr)
{
	if (WARN_ON(scc_attr->size > sizeof(u32)))
		return -EINVAL;

	if (WARN_ON(scc_attr->algo_type >= HNS_ROCE_SCC_ALGO_TOTAL))
		return -EINVAL;
	return 0;
}

static ssize_t cnp_pri_attr_show(struct hns_roce_port *pdata,
				 struct hns_port_attribute *attr, char *buf)
{
	struct hns_port_cnp_pri_attr *cnp_pri_attr =
		container_of(attr, struct hns_port_cnp_pri_attr, port_attr);
	struct hns_roce_cnp_pri_param *cnp_pri_param;
	u32 param;
	u32 val;

	cnp_pri_param = pdata->cnp_pri_param;
	param = le32_to_cpu(cnp_pri_param->param);
	val = (param & cnp_pri_attr->bit_mask) >> cnp_pri_attr->bit_offset;

	return sysfs_emit(buf, "%u\n", val);
}

static ssize_t cnp_pri_attr_store(struct hns_roce_port *pdata,
				  struct hns_port_attribute *attr,
				  const char *buf, size_t count)
{
	struct hns_port_cnp_pri_attr *cnp_pri_attr =
		container_of(attr, struct hns_port_cnp_pri_attr, port_attr);
	struct hns_roce_cnp_pri_param *cnp_pri_param;
	struct hns_roce_dev *hr_dev;
	__le32 param_bak;
	u32 param;
	u32 val;
	int ret;

	ret = kstrtou32(buf, 0, &val);
	if (ret)
		return ret;

	if (val > cnp_pri_attr->max)
		return -EINVAL;

	cnp_pri_param = pdata->cnp_pri_param;
	param = le32_to_cpu(cnp_pri_param->param);
	if (cnp_pri_attr->bit_offset != HNS_ROCE_CNP_PRI_ENABLE_BIT_OFS &&
	    !(param & HNS_ROCE_CNP_PRI_ENABLE_BIT_MASK))
		return -EPERM;

	param = param & (~cnp_pri_attr->bit_mask);
	val = (val << cnp_pri_attr->bit_offset) | param;
	param_bak = cnp_pri_param->param;
	cnp_pri_param->param = cpu_to_le32(val);
	hr_dev = cnp_pri_param->hr_dev;

	ret = hr_dev->hw->config_cnp_pri_param(hr_dev, cnp_pri_param->port_num);
	if (ret) {
		cnp_pri_param->param = param_bak;
		return ret;
	}

	return count;
}

static ssize_t scc_attr_show(struct hns_roce_port *pdata,
			     struct hns_port_attribute *attr, char *buf)
{
	struct hns_port_cc_attr *scc_attr =
		container_of(attr, struct hns_port_cc_attr, port_attr);
	struct hns_roce_scc_param *scc_param;
	__le32 val = 0;
	int ret;

	ret = scc_attr_check(scc_attr);
	if (ret)
		return ret;

	scc_param = &pdata->scc_param[scc_attr->algo_type];

	mutex_lock(&scc_param->scc_mutex);
	if (scc_attr->offset == offsetof(typeof(*scc_param), lifespan))
		val = scc_param->lifespan;
	else
		memcpy(&val, (void *)scc_param->latest_param + scc_attr->offset,
		       scc_attr->size);
	mutex_unlock(&scc_param->scc_mutex);

	return sysfs_emit(buf, "%u\n", le32_to_cpu(val));
}

static ssize_t scc_attr_store(struct hns_roce_port *pdata,
			      struct hns_port_attribute *attr,
			      const char *buf, size_t count)
{
	struct hns_port_cc_attr *scc_attr =
		container_of(attr, struct hns_port_cc_attr, port_attr);
	struct hns_roce_scc_param *scc_param;
	unsigned long lifespan_jiffies;
	unsigned long exp_time;
	__le32 attr_val;
	u32 val;
	int ret;

	ret = scc_attr_check(scc_attr);
	if (ret)
		return ret;

	if (kstrtou32(buf, 0, &val))
		return -EINVAL;

	if (val > scc_attr->max || val < scc_attr->min)
		return -EINVAL;

	attr_val = cpu_to_le32(val);
	scc_param = &pdata->scc_param[scc_attr->algo_type];
	mutex_lock(&scc_param->scc_mutex);
	memcpy((void *)scc_param + scc_attr->offset, &attr_val,
	       scc_attr->size);
	mutex_unlock(&scc_param->scc_mutex);

	/* lifespan is only used for driver */
	if (scc_attr->offset >= offsetof(typeof(*scc_param), lifespan))
		return count;

	lifespan_jiffies = msecs_to_jiffies(le32_to_cpu(scc_param->lifespan));
	exp_time = scc_param->timestamp + lifespan_jiffies;

	if (time_is_before_eq_jiffies(exp_time)) {
		scc_param->timestamp = jiffies;
		queue_delayed_work(pdata->hr_dev->irq_workq,
				   &scc_param->scc_cfg_dwork, lifespan_jiffies);
	}

	return count;
}

static umode_t cnp_pri_param_is_visible(struct kobject *kobj,
				     struct attribute *attr, int i)
{
	struct hns_roce_port *pdata =
		container_of(kobj, struct hns_roce_port, kobj);
	struct hns_roce_dev *hr_dev = pdata->hr_dev;

	if (hr_dev->is_vf || hr_dev->pci_dev->revision <= PCI_REVISION_ID_HIP09)
		return 0;

	if (hr_dev->mac_type != HNAE3_MAC_ROH ||
	    hr_dev->func_id != MAIN_PF_FUNC_ID)
		return 0;

	if (!(hr_dev->caps.flags & HNS_ROCE_CAP_FLAG_QP_FLOW_CTRL) ||
	    !(hr_dev->caps.fw_cap & FW_CAP_FLAG_CNP_PRI))
		return 0;

	return 0644;
}

static umode_t scc_attr_is_visible(struct kobject *kobj,
				   struct attribute *attr, int i)
{
	struct hns_port_attribute *port_attr =
		container_of(attr, struct hns_port_attribute, attr);
	struct hns_port_cc_attr *scc_attr =
		container_of(port_attr, struct hns_port_cc_attr, port_attr);
	struct hns_roce_port *pdata =
		container_of(kobj, struct hns_roce_port, kobj);
	struct hns_roce_dev *hr_dev = pdata->hr_dev;

	if (hr_dev->is_vf ||
	    !(hr_dev->caps.flags & HNS_ROCE_CAP_FLAG_QP_FLOW_CTRL))
		return 0;

	if (!(hr_dev->caps.congest_type & (1 << scc_attr->algo_type)))
		return 0;

	return 0644;
}

#define __HNS_CNP_PRI_ATTR(_name, _offset, _size, _mask, _max) {		\
	.port_attr = __ATTR(_name, 0644, cnp_pri_attr_show,  cnp_pri_attr_store),	\
	.bit_offset = _offset,							\
	.bit_size = _size,								\
	.bit_mask = _mask,								\
	.max = _max,								\
}

#define HNS_PORT_CNP_PRI_ATTR_RW(_name, NAME)						\
	static struct hns_port_cnp_pri_attr hns_roce_port_attr_cnp_pri_##_name =	\
	__HNS_CNP_PRI_ATTR(_name,		\
			HNS_ROCE_CNP_PRI_##NAME##_BIT_OFS,				\
			HNS_ROCE_CNP_PRI_##NAME##_BIT_SZ,				\
			HNS_ROCE_CNP_PRI_##NAME##_BIT_MASK,				\
			HNS_ROCE_CNP_PRI_##NAME##_MAX)

HNS_PORT_CNP_PRI_ATTR_RW(enable, ENABLE);
HNS_PORT_CNP_PRI_ATTR_RW(dscp, DSCP);

static struct attribute *cnp_pri_param_attrs[] = {
	&hns_roce_port_attr_cnp_pri_enable.port_attr.attr,
	&hns_roce_port_attr_cnp_pri_dscp.port_attr.attr,
	NULL,
};

static const struct attribute_group cnp_pri_param_group = {
	.name = "cnp_pri_param",
	.attrs = cnp_pri_param_attrs,
	.is_visible = cnp_pri_param_is_visible,
};

#define __HNS_SCC_ATTR(_name, _type, _offset, _size, _min, _max) {		\
	.port_attr = __ATTR(_name, 0644, scc_attr_show,  scc_attr_store),	\
	.algo_type = _type,							\
	.offset = _offset,							\
	.size = _size,								\
	.min = _min,								\
	.max = _max,								\
}

#define HNS_PORT_DCQCN_CC_ATTR_RW(_name, NAME)					\
	static struct hns_port_cc_attr hns_roce_port_attr_dcqcn_##_name =	\
	__HNS_SCC_ATTR(_name, HNS_ROCE_SCC_ALGO_DCQCN,				\
			HNS_ROCE_DCQCN_##NAME##_OFS,				\
			HNS_ROCE_DCQCN_##NAME##_SZ,				\
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

#define HNS_PORT_LDCP_CC_ATTR_RW(_name, NAME)					\
	static struct hns_port_cc_attr hns_roce_port_attr_ldcp_##_name =	\
	__HNS_SCC_ATTR(_name, HNS_ROCE_SCC_ALGO_LDCP,				\
			HNS_ROCE_LDCP_##NAME##_OFS,				\
			HNS_ROCE_LDCP_##NAME##_SZ,				\
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
	static struct hns_port_cc_attr hns_roce_port_attr_hc3_##_name =	\
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
	static struct hns_port_cc_attr hns_roce_port_attr_dip_##_name =	\
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

static const struct attribute_group *hns_attr_port_groups[] = {
	&dcqcn_cc_param_group,
	&ldcp_cc_param_group,
	&hc3_cc_param_group,
	&dip_cc_param_group,
	&cnp_pri_param_group,
	NULL,
};

static ssize_t hns_roce_port_attr_show(struct kobject *kobj,
				       struct attribute *attr, char *buf)
{
	struct hns_port_attribute *port_attr =
		container_of(attr, struct hns_port_attribute, attr);
	struct hns_roce_port *p =
		container_of(kobj, struct hns_roce_port, kobj);

	if (!port_attr->show)
		return -EIO;

	return port_attr->show(p, port_attr, buf);
}

static ssize_t hns_roce_port_attr_store(struct kobject *kobj,
					struct attribute *attr,
					const char *buf, size_t count)
{
	struct hns_port_attribute *port_attr =
		container_of(attr, struct hns_port_attribute, attr);
	struct hns_roce_port *p =
		container_of(kobj, struct hns_roce_port, kobj);

	if (!port_attr->store)
		return -EIO;

	return port_attr->store(p, port_attr, buf, count);
}

static void hns_roce_port_release(struct kobject *kobj)
{
	struct hns_roce_port *pdata =
		container_of(kobj, struct hns_roce_port, kobj);

	kfree(pdata->scc_param);
	kvfree(pdata->cnp_pri_param);
}

static const struct sysfs_ops hns_roce_port_ops = {
	.show = hns_roce_port_attr_show,
	.store = hns_roce_port_attr_store,
};

static struct kobj_type hns_roce_port_ktype = {
	.release = hns_roce_port_release,
	.sysfs_ops = &hns_roce_port_ops,
};

int hns_roce_create_port_files(struct ib_device *ibdev, u8 port_num,
			       struct kobject *kobj)
{
	struct hns_roce_dev *hr_dev = to_hr_dev(ibdev);
	struct hns_roce_port *pdata;
	int ret;

	if (!port_num || port_num > hr_dev->caps.num_ports) {
		ibdev_err(ibdev, "fail to create port sysfs for invalid port %u.\n",
			  port_num);
		return -ENODEV;
	}

	pdata = &hr_dev->port_data[port_num - 1];
	pdata->hr_dev = hr_dev;
	pdata->port_num = port_num;
	ret = kobject_init_and_add(&pdata->kobj, &hns_roce_port_ktype,
				   kobj, "cc_param");
	if (ret) {
		ibdev_err(ibdev, "fail to create port(%u) sysfs, ret = %d.\n",
			  port_num, ret);
		goto fail_kobj;
	}
	kobject_uevent(&pdata->kobj, KOBJ_ADD);

	ret = alloc_scc_param(hr_dev, pdata);
	if (ret) {
		dev_err(hr_dev->dev, "alloc scc param failed, ret = %d!\n",
			ret);
		goto fail_kobj;
	}

	ret = alloc_cnp_pri_param(hr_dev, pdata);
	if (ret) {
		dev_err(hr_dev->dev, "alloc cnp pri param failed, ret = %d!\n",
			ret);
		goto fail_kobj;
	}

	ret = sysfs_create_groups(&pdata->kobj, hns_attr_port_groups);
	if (ret) {
		ibdev_err(ibdev,
			  "fail to create port(%u) cc param sysfs, ret = %d.\n",
			  port_num, ret);
		goto fail_kobj;
	}

	return ret;

fail_kobj:
	kobject_put(&pdata->kobj);

	return ret;
}

static void hns_roce_unregister_port_sysfs(struct hns_roce_dev *hr_dev,
					   u8 port_num)
{
	struct hns_roce_scc_param *scc_param;
	struct hns_roce_port *pdata;
	int i;

	pdata = &hr_dev->port_data[port_num];
	sysfs_remove_groups(&pdata->kobj, hns_attr_port_groups);
	scc_param = pdata->scc_param;
	for (i = 0; i < HNS_ROCE_SCC_ALGO_TOTAL; i++) {
		cancel_delayed_work_sync(&scc_param[i].scc_cfg_dwork);
		mutex_destroy(&scc_param[i].scc_mutex);
	}
	kobject_put(&pdata->kobj);
}

void hns_roce_unregister_sysfs(struct hns_roce_dev *hr_dev)
{
	int i;

	for (i = 0; i < hr_dev->caps.num_ports; i++)
		hns_roce_unregister_port_sysfs(hr_dev, i);
}
