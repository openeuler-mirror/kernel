// SPDX-License-Identifier: GPL-2.0
/* Huawei UDMA Linux driver
 * Copyright (c) 2023-2023 Hisilicon Limited.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
 * for more details.
 *
 */

#include <linux/slab.h>
#include "hns3_udma_cmd.h"
#include "hns3_udma_sysfs.h"

static enum udma_opcode_type scc_opcode[] = {
	UDMA_OPC_CFG_DCQCN_PARAM,
	UDMA_OPC_CFG_LDCP_PARAM,
	UDMA_OPC_CFG_HC3_PARAM,
	UDMA_OPC_CFG_DIP_PARAM,
};

static int udma_config_scc_param(struct udma_dev *udma_dev,
				 uint8_t port_num, enum udma_cong_type algo)
{
	struct udma_scc_param *scc_param;
	struct udma_cmq_desc desc;
	struct udma_port *pdata;
	int ret;

	if (port_num >= udma_dev->caps.num_ports) {
		dev_err_ratelimited(udma_dev->dev,
				    "invalid port num %u.\n", port_num);
		return -ENODEV;
	}

	if (algo >= UDMA_CONG_TYPE_TOTAL) {
		dev_err_ratelimited(udma_dev->dev, "invalid SCC algo.\n");
		return -EINVAL;
	}

	udma_cmq_setup_basic_desc(&desc, scc_opcode[algo], false);
	pdata = &udma_dev->port_data[port_num];
	scc_param = &pdata->scc_param[algo];
	if (!scc_param) {
		dev_err_ratelimited(udma_dev->dev, "scc_param has been freed.\n");
		return -ENODEV;
	}

	memcpy(&desc.data, scc_param, sizeof(scc_param->param));

	ret = udma_cmq_send(udma_dev, &desc, 1);
	if (ret)
		dev_err_ratelimited(udma_dev->dev,
				    "failed to configure scc param, opcode: 0x%x, ret = %d.\n",
				    le16_to_cpu(desc.opcode), ret);

	return ret;
}

static int udma_query_scc_param(struct udma_dev *udma_dev,
				uint8_t port_num, enum udma_cong_type algo)
{
	struct udma_scc_param *scc_param;
	struct udma_cmq_desc desc;
	struct udma_port *pdata;
	int ret;

	if (port_num >= udma_dev->caps.num_ports) {
		dev_err_ratelimited(udma_dev->dev,
				    "invalid port num %u.\n", port_num);
		return -ENODEV;
	}

	if (algo >= UDMA_CONG_TYPE_TOTAL) {
		dev_err_ratelimited(udma_dev->dev, "invalid SCC algo.\n");
		return -EINVAL;
	}

	udma_cmq_setup_basic_desc(&desc, scc_opcode[algo], true);
	ret = udma_cmq_send(udma_dev, &desc, 1);
	if (ret) {
		dev_err_ratelimited(udma_dev->dev,
				    "failed to query scc param, opcode: 0x%x, ret = %d.\n",
				    le16_to_cpu(desc.opcode), ret);
		return ret;
	}

	pdata = &udma_dev->port_data[port_num];
	scc_param = &pdata->scc_param[algo];
	memcpy(scc_param, &desc.data, sizeof(scc_param->param));

	return 0;
}

static void scc_param_config_work(struct work_struct *work)
{
	struct udma_scc_param *scc_param = container_of(work,
							struct udma_scc_param,
							scc_cfg_dwork.work);
	struct udma_dev *udma_dev = scc_param->udma_dev;

	udma_config_scc_param(udma_dev, scc_param->port_num,
			      scc_param->algo_type);
}

static int alloc_scc_param(struct udma_dev *udma_dev,
			   struct udma_port *pdata)
{
	struct udma_scc_param *scc_param;
	int i;

	scc_param = kcalloc(UDMA_CONG_TYPE_TOTAL, sizeof(*scc_param),
			    GFP_KERNEL);
	if (!scc_param)
		return -ENOMEM;

	for (i = 0; i < UDMA_CONG_TYPE_TOTAL; i++) {
		scc_param[i].algo_type = (enum udma_cong_type)i;
		scc_param[i].timestamp = jiffies;
		scc_param[i].udma_dev = udma_dev;
		scc_param[i].port_num = pdata->port_num;
		scc_param[i].configured = false;
		INIT_DELAYED_WORK(&scc_param[i].scc_cfg_dwork,
				  scc_param_config_work);
	}

	pdata->scc_param = scc_param;

	return 0;
}

static int scc_attr_check(struct udma_port_cc_attr *scc_attr)
{
	if (WARN_ON(scc_attr->size > sizeof(uint32_t)))
		return -EINVAL;

	if (WARN_ON(scc_attr->algo_type >= UDMA_CONG_TYPE_TOTAL))
		return -EINVAL;

	return 0;
}

static ssize_t scc_attr_show(struct udma_port *pdata,
			     struct udma_port_attribute *attr, char *buf)
{
	struct udma_port_cc_attr *scc_attr;
	struct udma_scc_param *scc_param;
	unsigned long exp_time;
	uint32_t val = 0;
	int ret;

	scc_attr = container_of(attr, struct udma_port_cc_attr, port_attr);
	ret = scc_attr_check(scc_attr);
	if (ret)
		return ret;

	scc_param = &pdata->scc_param[scc_attr->algo_type];

	/* Only HW param need be queried */
	if (scc_attr->offset < offsetof(typeof(*scc_param), lifespan)) {
		exp_time = scc_param->timestamp +
			   msecs_to_jiffies(scc_param->lifespan);
		if (time_is_before_eq_jiffies(exp_time)) {
			scc_param->timestamp = jiffies;
			udma_query_scc_param(pdata->udma_dev,
					     pdata->port_num,
					     scc_attr->algo_type);
		}
	}

	memcpy(&val, (void *)scc_param + scc_attr->offset, scc_attr->size);

	return sysfs_emit(buf, "%u\n", le32_to_cpu(val));
}

static ssize_t scc_attr_store(struct udma_port *pdata,
			      struct udma_port_attribute *attr,
			      const char *buf, size_t count)
{
	struct udma_port_cc_attr *scc_attr;
	struct udma_scc_param *scc_param;
	uint64_t lifespan_jiffies;
	unsigned long exp_time;
	uint32_t attr_val;
	uint32_t val;
	int ret;

	scc_attr = container_of(attr, struct udma_port_cc_attr, port_attr);
	ret = scc_attr_check(scc_attr);
	if (ret)
		return ret;

	if (kstrtou32(buf, 0, &val))
		return -EINVAL;

	if (val > scc_attr->max || val < scc_attr->min)
		return -EINVAL;

	attr_val = cpu_to_le32(val);
	scc_param = &pdata->scc_param[scc_attr->algo_type];

	/* get current params of this scc algo before configure it first time */
	if (scc_param->configured == false)
		udma_query_scc_param(pdata->udma_dev, scc_param->port_num,
				     scc_param->algo_type);

	memcpy((void *)scc_param + scc_attr->offset, &attr_val, scc_attr->size);

	/* lifespan is only used for driver */
	if (scc_attr->offset >= offsetof(typeof(*scc_param), lifespan))
		return count;

	lifespan_jiffies = msecs_to_jiffies(scc_param->lifespan);
	exp_time = scc_param->timestamp + lifespan_jiffies;

	if (time_is_before_eq_jiffies(exp_time)) {
		scc_param->timestamp = jiffies;
		queue_delayed_work(pdata->udma_dev->irq_workq,
				   &scc_param->scc_cfg_dwork, lifespan_jiffies);
		scc_param->configured = true;
	}

	return count;
}

static umode_t scc_attr_is_visible(struct kobject *kobj,
				   struct attribute *attr, int i)
{
	struct udma_port_attribute *port_attr;
	struct udma_port_cc_attr *scc_attr;
	struct udma_dev *udma_dev;
	struct udma_port *pdata;

	port_attr = container_of(attr, struct udma_port_attribute, attr);
	scc_attr = container_of(port_attr, struct udma_port_cc_attr, port_attr);
	pdata = container_of(kobj, struct udma_port, kobj);
	udma_dev = pdata->udma_dev;

	if (!(udma_dev->caps.flags & UDMA_CAP_FLAG_QP_FLOW_CTRL))
		return 0;

	if (!(udma_dev->caps.cong_type & (1 << scc_attr->algo_type)))
		return 0;

	return ATTR_RW_RONLY_RONLY;
}

#define __UDMA_SCC_ATTR(_name, _type, _offset, _size, _min, _max) {		\
	.port_attr = __ATTR(_name, 0644, scc_attr_show,  scc_attr_store),	\
	.algo_type = (_type),							\
	.offset = (_offset),							\
	.size = (_size),							\
	.min = (_min),								\
	.max = (_max),								\
}

#define UDMA_DCQCN_CC_ATTR_RW(_name, NAME)			\
	struct udma_port_cc_attr udma_port_attr_dcqcn_##_name =	\
	__UDMA_SCC_ATTR(_name, UDMA_CONG_TYPE_DCQCN,		\
			UDMA_DCQCN_##NAME##_OFS,		\
			UDMA_DCQCN_##NAME##_SZ,			\
			0, UDMA_DCQCN_##NAME##_MAX)

UDMA_DCQCN_CC_ATTR_RW(ai, AI);
UDMA_DCQCN_CC_ATTR_RW(f, F);
UDMA_DCQCN_CC_ATTR_RW(tkp, TKP);
UDMA_DCQCN_CC_ATTR_RW(tmp, TMP);
UDMA_DCQCN_CC_ATTR_RW(alp, ALP);
UDMA_DCQCN_CC_ATTR_RW(max_speed, MAX_SPEED);
UDMA_DCQCN_CC_ATTR_RW(g, G);
UDMA_DCQCN_CC_ATTR_RW(al, AL);
UDMA_DCQCN_CC_ATTR_RW(cnp_time, CNP_TIME);
UDMA_DCQCN_CC_ATTR_RW(ashift, ASHIFT);
UDMA_DCQCN_CC_ATTR_RW(lifespan, LIFESPAN);

static struct attribute *dcqcn_param_attrs[] = {
	&udma_port_attr_dcqcn_ai.port_attr.attr,
	&udma_port_attr_dcqcn_f.port_attr.attr,
	&udma_port_attr_dcqcn_tkp.port_attr.attr,
	&udma_port_attr_dcqcn_tmp.port_attr.attr,
	&udma_port_attr_dcqcn_alp.port_attr.attr,
	&udma_port_attr_dcqcn_max_speed.port_attr.attr,
	&udma_port_attr_dcqcn_g.port_attr.attr,
	&udma_port_attr_dcqcn_al.port_attr.attr,
	&udma_port_attr_dcqcn_cnp_time.port_attr.attr,
	&udma_port_attr_dcqcn_ashift.port_attr.attr,
	&udma_port_attr_dcqcn_lifespan.port_attr.attr,
	NULL,
};

static const struct attribute_group dcqcn_cc_param_group = {
	.name = "dcqcn_cc_param",
	.attrs = dcqcn_param_attrs,
	.is_visible = scc_attr_is_visible,
};

#define UDMA_LDCP_CC_ATTR_RW(_name, NAME)			\
	struct udma_port_cc_attr udma_port_attr_ldcp_##_name =	\
	__UDMA_SCC_ATTR(_name, UDMA_CONG_TYPE_LDCP,		\
			UDMA_LDCP_##NAME##_OFS,			\
			UDMA_LDCP_##NAME##_SZ,			\
			0, UDMA_LDCP_##NAME##_MAX)

UDMA_LDCP_CC_ATTR_RW(cwd0, CWD0);
UDMA_LDCP_CC_ATTR_RW(alpha, ALPHA);
UDMA_LDCP_CC_ATTR_RW(gamma, GAMMA);
UDMA_LDCP_CC_ATTR_RW(beta, BETA);
UDMA_LDCP_CC_ATTR_RW(eta, ETA);
UDMA_LDCP_CC_ATTR_RW(lifespan, LIFESPAN);

static struct attribute *ldcp_param_attrs[] = {
	&udma_port_attr_ldcp_cwd0.port_attr.attr,
	&udma_port_attr_ldcp_alpha.port_attr.attr,
	&udma_port_attr_ldcp_gamma.port_attr.attr,
	&udma_port_attr_ldcp_beta.port_attr.attr,
	&udma_port_attr_ldcp_eta.port_attr.attr,
	&udma_port_attr_ldcp_lifespan.port_attr.attr,
	NULL,
};

static const struct attribute_group ldcp_cc_param_group = {
	.name = "ldcp_cc_param",
	.attrs = ldcp_param_attrs,
	.is_visible = scc_attr_is_visible,
};

#define UDMA_HC3_CC_ATTR_RW(_name, NAME)			\
	struct udma_port_cc_attr udma_port_attr_hc3_##_name =	\
	__UDMA_SCC_ATTR(_name, UDMA_CONG_TYPE_HC3,		\
			UDMA_HC3_##NAME##_OFS,			\
			UDMA_HC3_##NAME##_SZ,			\
			0, UDMA_HC3_##NAME##_MAX)

UDMA_HC3_CC_ATTR_RW(initial_window, INITIAL_WINDOW);
UDMA_HC3_CC_ATTR_RW(bandwidth, BANDWIDTH);
UDMA_HC3_CC_ATTR_RW(qlen_shift, QLEN_SHIFT);
UDMA_HC3_CC_ATTR_RW(port_usage_shift, PORT_USAGE_SHIFT);
UDMA_HC3_CC_ATTR_RW(over_period, OVER_PERIOD);
UDMA_HC3_CC_ATTR_RW(max_stage, MAX_STAGE);
UDMA_HC3_CC_ATTR_RW(gamma_shift, GAMMA_SHIFT);
UDMA_HC3_CC_ATTR_RW(lifespan, LIFESPAN);

static struct attribute *hc3_param_attrs[] = {
	&udma_port_attr_hc3_initial_window.port_attr.attr,
	&udma_port_attr_hc3_bandwidth.port_attr.attr,
	&udma_port_attr_hc3_qlen_shift.port_attr.attr,
	&udma_port_attr_hc3_port_usage_shift.port_attr.attr,
	&udma_port_attr_hc3_over_period.port_attr.attr,
	&udma_port_attr_hc3_max_stage.port_attr.attr,
	&udma_port_attr_hc3_gamma_shift.port_attr.attr,
	&udma_port_attr_hc3_lifespan.port_attr.attr,
	NULL,
};

static const struct attribute_group hc3_cc_param_group = {
	.name = "hc3_cc_param",
	.attrs = hc3_param_attrs,
	.is_visible = scc_attr_is_visible,
};

#define UDMA_DIP_CC_ATTR_RW(_name, NAME)			\
	struct udma_port_cc_attr udma_port_attr_dip_##_name =	\
	__UDMA_SCC_ATTR(_name, UDMA_CONG_TYPE_DIP,		\
			UDMA_DIP_##NAME##_OFS,			\
			UDMA_DIP_##NAME##_SZ,			\
			0, UDMA_DIP_##NAME##_MAX)

UDMA_DIP_CC_ATTR_RW(ai, AI);
UDMA_DIP_CC_ATTR_RW(f, F);
UDMA_DIP_CC_ATTR_RW(tkp, TKP);
UDMA_DIP_CC_ATTR_RW(tmp, TMP);
UDMA_DIP_CC_ATTR_RW(alp, ALP);
UDMA_DIP_CC_ATTR_RW(max_speed, MAX_SPEED);
UDMA_DIP_CC_ATTR_RW(g, G);
UDMA_DIP_CC_ATTR_RW(al, AL);
UDMA_DIP_CC_ATTR_RW(cnp_time, CNP_TIME);
UDMA_DIP_CC_ATTR_RW(ashift, ASHIFT);
UDMA_DIP_CC_ATTR_RW(lifespan, LIFESPAN);

static struct attribute *dip_param_attrs[] = {
	&udma_port_attr_dip_ai.port_attr.attr,
	&udma_port_attr_dip_f.port_attr.attr,
	&udma_port_attr_dip_tkp.port_attr.attr,
	&udma_port_attr_dip_tmp.port_attr.attr,
	&udma_port_attr_dip_alp.port_attr.attr,
	&udma_port_attr_dip_max_speed.port_attr.attr,
	&udma_port_attr_dip_g.port_attr.attr,
	&udma_port_attr_dip_al.port_attr.attr,
	&udma_port_attr_dip_cnp_time.port_attr.attr,
	&udma_port_attr_dip_ashift.port_attr.attr,
	&udma_port_attr_dip_lifespan.port_attr.attr,
	NULL,
};

static const struct attribute_group dip_cc_param_group = {
	.name = "dip_cc_param",
	.attrs = dip_param_attrs,
	.is_visible = scc_attr_is_visible,
};

const struct attribute_group *udma_attr_port_groups[] = {
	&dcqcn_cc_param_group,
	&ldcp_cc_param_group,
	&hc3_cc_param_group,
	&dip_cc_param_group,
	NULL,
};

static ssize_t udma_port_attr_show(struct kobject *kobj,
				   struct attribute *attr, char *buf)
{
	struct udma_port_attribute *port_attr;
	struct udma_port *port;

	port_attr = container_of(attr, struct udma_port_attribute, attr);
	port = container_of(kobj, struct udma_port, kobj);
	if (!port_attr->show)
		return -EIO;

	return port_attr->show(port, port_attr, buf);
}

static ssize_t udma_port_attr_store(struct kobject *kobj,
				    struct attribute *attr,
				    const char *buf, size_t count)
{
	struct udma_port_attribute *port_attr;
	struct udma_port *p;

	port_attr = container_of(attr, struct udma_port_attribute, attr);
	p = container_of(kobj, struct udma_port, kobj);
	if (!port_attr->store)
		return -EIO;

	return port_attr->store(p, port_attr, buf, count);
}

static void udma_port_release(struct kobject *kobj)
{
	struct udma_port *pdata;
	int i;

	pdata = container_of(kobj, struct udma_port, kobj);

	for (i = 0; i < UDMA_CONG_TYPE_TOTAL; i++)
		cancel_delayed_work_sync(&pdata->scc_param[i].scc_cfg_dwork);

	kfree(pdata->scc_param);
	pdata->scc_param = NULL;
}

static const struct sysfs_ops udma_port_ops = {
	.show = udma_port_attr_show,
	.store = udma_port_attr_store,
};

static struct kobj_type udma_port_ktype = {
	.release = udma_port_release,
	.sysfs_ops = &udma_port_ops,
};

static int udma_register_port_sysfs(struct udma_dev *udma_dev, uint8_t port_num,
				    struct kobject *kobj)
{
	struct udma_port *pdata;
	int ret;

	if (port_num >= udma_dev->caps.num_ports) {
		dev_err(udma_dev->dev, "fail to create port sysfs for invalid port %u.\n",
			port_num);
		return -ENODEV;
	}

	pdata = &udma_dev->port_data[port_num];
	pdata->udma_dev = udma_dev;
	pdata->port_num = port_num;
	ret = kobject_init_and_add(&pdata->kobj, &udma_port_ktype,
				   kobj, "cc_param");
	if (ret) {
		dev_err(udma_dev->dev, "fail to create port(%u) sysfs, ret = %d.\n",
			port_num, ret);
		goto fail_kobj;
	}
	kobject_uevent(&pdata->kobj, KOBJ_ADD);

	ret = sysfs_create_groups(&pdata->kobj, udma_attr_port_groups);
	if (ret) {
		dev_err(udma_dev->dev,
			"fail to create port(%u) cc param sysfs, ret = %d.\n",
			port_num, ret);
		goto fail_kobj;
	}

	ret = alloc_scc_param(udma_dev, pdata);
	if (ret) {
		dev_err(udma_dev->dev, "alloc scc param failed, ret = %d!\n",
			ret);
		goto fail_group;
	}

	return ret;

fail_group:
	sysfs_remove_groups(&pdata->kobj, udma_attr_port_groups);
fail_kobj:
	kobject_put(&pdata->kobj);
	return ret;
}

static void udma_unregister_port_sysfs(struct udma_dev *udma_dev, uint8_t port_num)
{
	struct udma_port *pdata;

	pdata = &udma_dev->port_data[port_num];
	sysfs_remove_groups(&pdata->kobj, udma_attr_port_groups);
	kobject_put(&pdata->kobj);
}

int udma_register_cc_sysfs(struct udma_dev *udma_dev)
{
	uint8_t i;
	uint8_t j;

	for (i = 0; i < udma_dev->caps.num_ports; i++) {
		if (udma_register_port_sysfs(udma_dev, i, &udma_dev->dev->kobj) != 0)
			goto err_port_attr;
	}

	return 0;

err_port_attr:
	for (j = 0; j < i; j++)
		udma_unregister_port_sysfs(udma_dev, j);

	return -EPERM;
}

void udma_unregister_cc_sysfs(struct udma_dev *udma_dev)
{
	int i;

	for (i = 0; i < udma_dev->caps.num_ports; i++)
		udma_unregister_port_sysfs(udma_dev, i);
}
