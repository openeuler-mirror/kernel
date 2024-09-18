// SPDX-License-Identifier: GPL-2.0
/* Huawei HNS3_UDMA Linux driver
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

static enum hns3_udma_opcode_type scc_opcode[] = {
	HNS3_UDMA_OPC_CFG_DCQCN_PARAM,
	HNS3_UDMA_OPC_CFG_LDCP_PARAM,
	HNS3_UDMA_OPC_CFG_HC3_PARAM,
	HNS3_UDMA_OPC_CFG_DIP_PARAM,
};

static int hns3_udma_config_scc_param(struct hns3_udma_dev *udma_dev,
				      uint8_t port_num, enum hns3_udma_cong_type algo)
{
	struct hns3_udma_scc_param *scc_param;
	struct hns3_udma_cmq_desc desc = {};
	struct hns3_udma_port *pdata;
	int ret;

	hns3_udma_cmq_setup_basic_desc(&desc, scc_opcode[algo], false);
	pdata = &udma_dev->port_data[port_num];
	scc_param = &pdata->scc_param[algo];
	if (!scc_param) {
		dev_err_ratelimited(udma_dev->dev, "scc_param has been freed.\n");
		return -ENODEV;
	}

	mutex_lock(&scc_param->scc_mutex);
	(void)memcpy(&desc.data, scc_param->param, sizeof(scc_param->param));

	ret = hns3_udma_cmq_send(udma_dev, &desc, 1);
	if (ret) {
		dev_err_ratelimited(udma_dev->dev,
				    "failed to configure scc param, opcode: 0x%x, ret = %d.\n",
				    le16_to_cpu(desc.opcode), ret);
		mutex_unlock(&scc_param->scc_mutex);
		return ret;
	}

	(void)memcpy(scc_param->latest_param, &desc.data,
	       sizeof(scc_param->latest_param));
	mutex_unlock(&scc_param->scc_mutex);

	return ret;
}

static int hns3_udma_query_scc_param(struct hns3_udma_dev *udma_dev,
				     uint8_t port_num, enum hns3_udma_cong_type algo)
{
	struct hns3_udma_scc_param *scc_param;
	struct hns3_udma_cmq_desc desc = {};
	struct hns3_udma_port *pdata;
	int ret;

	hns3_udma_cmq_setup_basic_desc(&desc, scc_opcode[algo], true);
	ret = hns3_udma_cmq_send(udma_dev, &desc, 1);
	if (ret) {
		dev_err_ratelimited(udma_dev->dev,
				    "failed to query scc param, opcode: 0x%x, ret = %d.\n",
				    le16_to_cpu(desc.opcode), ret);
		return ret;
	}

	pdata = &udma_dev->port_data[port_num];
	scc_param = &pdata->scc_param[algo];
	mutex_lock(&scc_param->scc_mutex);
	(void)memcpy(scc_param->param, &desc.data, sizeof(scc_param->param));
	(void)memcpy(scc_param->latest_param, &desc.data,
	       sizeof(scc_param->latest_param));
	mutex_unlock(&scc_param->scc_mutex);

	return 0;
}

static void scc_param_config_work(struct work_struct *work)
{
	struct hns3_udma_scc_param *scc_param =
		container_of(work, struct hns3_udma_scc_param, scc_cfg_dwork.work);
	struct hns3_udma_dev *udma_dev = scc_param->udma_dev;

	hns3_udma_config_scc_param(udma_dev, scc_param->port_num,
				   scc_param->algo_type);
}

static int alloc_scc_param(struct hns3_udma_dev *udma_dev,
			   struct hns3_udma_port *pdata)
{
	struct hns3_udma_scc_param *scc_param;
	int i;

	scc_param = kcalloc(HNS3_UDMA_CONG_TYPE_TOTAL, sizeof(*scc_param),
			    GFP_KERNEL);
	if (!scc_param)
		return -ENOMEM;

	for (i = 0; i < HNS3_UDMA_CONG_TYPE_TOTAL; i++) {
		scc_param[i].algo_type = (enum hns3_udma_cong_type)i;
		scc_param[i].timestamp = jiffies;
		scc_param[i].udma_dev = udma_dev;
		scc_param[i].port_num = pdata->port_num;
		scc_param[i].configured = false;
		mutex_init(&scc_param[i].scc_mutex);
		INIT_DELAYED_WORK(&scc_param[i].scc_cfg_dwork,
				  scc_param_config_work);
	}

	pdata->scc_param = scc_param;

	return 0;
}

static int scc_attr_check(struct hns3_udma_port_cc_attr *scc_attr)
{
	if (WARN_ON(scc_attr->size > sizeof(uint32_t)))
		return -EINVAL;

	if (WARN_ON(scc_attr->algo_type >= HNS3_UDMA_CONG_TYPE_TOTAL))
		return -EINVAL;

	return 0;
}

static ssize_t scc_attr_show(struct hns3_udma_port *pdata,
			     struct hns3_udma_port_attribute *attr, char *buf)
{
	struct hns3_udma_port_cc_attr *scc_attr;
	struct hns3_udma_scc_param *scc_param;
	unsigned long exp_time;
	uint32_t val = 0;
	int ret;

	scc_attr = container_of(attr, struct hns3_udma_port_cc_attr, port_attr);
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
			ret = hns3_udma_query_scc_param(pdata->udma_dev,
							pdata->port_num,
							scc_attr->algo_type);
			if (ret)
				return ret;
		}
	}

	mutex_lock(&scc_param->scc_mutex);
	if (scc_attr->offset == offsetof(typeof(*scc_param), lifespan))
		val = scc_param->lifespan;
	else
		(void)memcpy(&val, (void *)scc_param->latest_param + scc_attr->offset,
		       scc_attr->size);
	mutex_unlock(&scc_param->scc_mutex);

	return sysfs_emit(buf, "%u\n", le32_to_cpu(val));
}

static ssize_t scc_attr_store(struct hns3_udma_port *pdata,
			      struct hns3_udma_port_attribute *attr,
			      const char *buf, size_t count)
{
	struct hns3_udma_port_cc_attr *scc_attr;
	struct hns3_udma_scc_param *scc_param;
	uint64_t lifespan_jiffies;
	unsigned long exp_time;
	uint32_t attr_val;
	uint32_t val;
	int ret;

	scc_attr = container_of(attr, struct hns3_udma_port_cc_attr, port_attr);
	ret = scc_attr_check(scc_attr);
	if (ret)
		return ret;

	if (kstrtou32(buf, 0, &val))
		return -EINVAL;

	if (val > scc_attr->max || val < scc_attr->min) {
		dev_err(pdata->udma_dev->dev, "val = %u, max = %u, min = %u", val,
			scc_attr->max, scc_attr->min);
		return -EINVAL;
	}

	attr_val = cpu_to_le32(val);
	scc_param = &pdata->scc_param[scc_attr->algo_type];

	/* get current params of this scc algo before configure it first time */
	if (scc_param->configured == false) {
		ret = hns3_udma_query_scc_param(pdata->udma_dev, scc_param->port_num,
						scc_param->algo_type);
		if (ret)
			return ret;
	}

	mutex_lock(&scc_param->scc_mutex);
	(void)memcpy((void *)scc_param->param + scc_attr->offset, &attr_val, scc_attr->size);
	mutex_unlock(&scc_param->scc_mutex);

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
	struct hns3_udma_port_attribute *port_attr;
	struct hns3_udma_port_cc_attr *scc_attr;
	struct hns3_udma_dev *udma_dev;
	struct hns3_udma_port *pdata;

	port_attr = container_of(attr, struct hns3_udma_port_attribute, attr);
	scc_attr = container_of(port_attr, struct hns3_udma_port_cc_attr, port_attr);
	pdata = container_of(kobj, struct hns3_udma_port, kobj);
	udma_dev = pdata->udma_dev;

	if (!(udma_dev->caps.flags & HNS3_UDMA_CAP_FLAG_QP_FLOW_CTRL))
		return 0;

	if (!(udma_dev->caps.cong_type & (1 << scc_attr->algo_type)))
		return 0;

	return ATTR_RW_RONLY_RONLY;
}

static void cnp_param_config_work(struct work_struct *work)
{
	struct hns3_udma_cnp_param *cnp_param =
		container_of(work, struct hns3_udma_cnp_param, cnp_cfg_dwork.work);
	struct hns3_udma_dev *udma_dev = cnp_param->udma_dev;
	struct hns3_udma_cmdq_cnp_cfg *cnp_cfg;
	struct hns3_udma_cmq_desc desc = {};
	int ret;

	cnp_cfg = (struct hns3_udma_cmdq_cnp_cfg *)desc.data;
	hns3_udma_cmq_setup_basic_desc(&desc, HNS3_UDMA_OPC_CFG_CNP, false);
	cnp_cfg->cnp_attr_sel = cpu_to_le32(cnp_param->tmp_attr_sel);
	cnp_cfg->cnp_dscp = cpu_to_le32(cnp_param->tmp_dscp);
	ret = hns3_udma_cmq_send(udma_dev, &desc, 1);
	if (ret) {
		dev_err(udma_dev->dev, "failed to set cnp param, ret = %d", ret);
	} else {
		cnp_param->attr_sel = cnp_param->tmp_attr_sel;
		cnp_param->dscp = cnp_param->tmp_dscp;
	}
}

static void hns3_udma_init_cnp_param(struct hns3_udma_port *port_data)
{
	struct hns3_udma_dev *udma_dev = port_data->udma_dev;
	struct hns3_udma_cmdq_cnp_cfg *cnp_cfg;
	struct hns3_udma_cmq_desc desc = {};
	int ret;

	port_data->cnp_param.udma_dev = udma_dev;
	port_data->cnp_param.timestamp = jiffies;
	INIT_DELAYED_WORK(&port_data->cnp_param.cnp_cfg_dwork, cnp_param_config_work);
	port_data->cnp_param.cnp_param_inited = true;

	hns3_udma_cmq_setup_basic_desc(&desc, HNS3_UDMA_OPC_CFG_CNP, true);
	ret = hns3_udma_cmq_send(udma_dev, &desc, 1);
	if (ret) {
		dev_warn(udma_dev->dev, "failed to query cnp param, ret = %d.\n", ret);
		return;
	}

	cnp_cfg = (struct hns3_udma_cmdq_cnp_cfg *)desc.data;
	port_data->cnp_param.attr_sel = cnp_cfg->cnp_attr_sel;
	port_data->cnp_param.tmp_attr_sel = cnp_cfg->cnp_attr_sel;
	port_data->cnp_param.dscp = cnp_cfg->cnp_dscp;
	port_data->cnp_param.tmp_dscp = cnp_cfg->cnp_dscp;
}

static ssize_t cnp_attr_show(struct hns3_udma_port *pdata,
			     struct hns3_udma_port_attribute *attr, char *buf)
{
	struct hns3_udma_cnp_attr *cnp_attr = to_hns3_udma_cnp_attr(attr);
	uint32_t val;

	val = cnp_attr->type == CNP_PARAM_ATTR_SEL ? pdata->cnp_param.attr_sel :
				pdata->cnp_param.dscp;

	return sysfs_emit(buf, "%u\n", le32_to_cpu(val));
}

static ssize_t cnp_attr_store(struct hns3_udma_port *pdata,
			      struct hns3_udma_port_attribute *attr,
			      const char *buf, size_t count)
{
#define CNP_LIFESPAN 100
	struct hns3_udma_cnp_attr *cnp_attr = to_hns3_udma_cnp_attr(attr);
	struct net_device *net_dev;
	unsigned long exp_time;
	uint32_t val;

	net_dev = pdata->udma_dev->uboe.netdevs[pdata->port_num];
	if (!net_dev || (netif_running(net_dev) && netif_carrier_ok(net_dev)))
		return -EPERM;

	if (kstrtou32(buf, 0, &val))
		return -EINVAL;

	if (cnp_attr->type == CNP_PARAM_ATTR_SEL) {
		if (val > HNS3_UDMA_CNP_ATTR_SEL_MAX)
			return -EINVAL;
		pdata->cnp_param.tmp_attr_sel = val;
	} else {
		if (pdata->cnp_param.attr_sel == 0)
			return -EPERM;
		if (val > HNS3_UDMA_CNP_DSCP_MAX)
			return -EINVAL;
		pdata->cnp_param.tmp_dscp = val;
	}

	exp_time = pdata->cnp_param.timestamp + msecs_to_jiffies(CNP_LIFESPAN);
	if (time_is_before_eq_jiffies(exp_time)) {
		pdata->cnp_param.timestamp = jiffies;
		queue_delayed_work(pdata->udma_dev->irq_workq,
				   &pdata->cnp_param.cnp_cfg_dwork, CNP_LIFESPAN);
	}

	return count;
}

#define __HNS3_UDMA_SCC_ATTR(_name, _type, _offset, _size, _min, _max) {	\
	.port_attr = __ATTR(_name, 0644, scc_attr_show,  scc_attr_store),	\
	.algo_type = (_type),							\
	.offset = (_offset),							\
	.size = (_size),							\
	.min = (_min),								\
	.max = (_max),								\
}

#define HNS3_UDMA_DCQCN_CC_ATTR_RW(_name, NAME)					\
	struct hns3_udma_port_cc_attr hns3_udma_port_attr_dcqcn_##_name =	\
	__HNS3_UDMA_SCC_ATTR(_name, HNS3_UDMA_CONG_TYPE_DCQCN,			\
			     HNS3_UDMA_DCQCN_##NAME##_OFS,			\
			     HNS3_UDMA_DCQCN_##NAME##_SZ,			\
			     0, HNS3_UDMA_DCQCN_##NAME##_MAX)

HNS3_UDMA_DCQCN_CC_ATTR_RW(ai, AI);
HNS3_UDMA_DCQCN_CC_ATTR_RW(f, F);
HNS3_UDMA_DCQCN_CC_ATTR_RW(tkp, TKP);
HNS3_UDMA_DCQCN_CC_ATTR_RW(tmp, TMP);
HNS3_UDMA_DCQCN_CC_ATTR_RW(alp, ALP);
HNS3_UDMA_DCQCN_CC_ATTR_RW(max_speed, MAX_SPEED);
HNS3_UDMA_DCQCN_CC_ATTR_RW(g, G);
HNS3_UDMA_DCQCN_CC_ATTR_RW(al, AL);
HNS3_UDMA_DCQCN_CC_ATTR_RW(cnp_time, CNP_TIME);
HNS3_UDMA_DCQCN_CC_ATTR_RW(ashift, ASHIFT);
HNS3_UDMA_DCQCN_CC_ATTR_RW(lifespan, LIFESPAN);

static struct attribute *dcqcn_param_attrs[] = {
	&hns3_udma_port_attr_dcqcn_ai.port_attr.attr,
	&hns3_udma_port_attr_dcqcn_f.port_attr.attr,
	&hns3_udma_port_attr_dcqcn_tkp.port_attr.attr,
	&hns3_udma_port_attr_dcqcn_tmp.port_attr.attr,
	&hns3_udma_port_attr_dcqcn_alp.port_attr.attr,
	&hns3_udma_port_attr_dcqcn_max_speed.port_attr.attr,
	&hns3_udma_port_attr_dcqcn_g.port_attr.attr,
	&hns3_udma_port_attr_dcqcn_al.port_attr.attr,
	&hns3_udma_port_attr_dcqcn_cnp_time.port_attr.attr,
	&hns3_udma_port_attr_dcqcn_ashift.port_attr.attr,
	&hns3_udma_port_attr_dcqcn_lifespan.port_attr.attr,
	NULL,
};

static const struct attribute_group dcqcn_cc_param_group = {
	.name = "dcqcn_cc_param",
	.attrs = dcqcn_param_attrs,
	.is_visible = scc_attr_is_visible,
};

struct hns3_udma_cnp_attr hns3_udma_attr_cnp_attr_sel = {
	.port_attr = __ATTR(dscp_enable, 0644, cnp_attr_show, cnp_attr_store),
	.type = CNP_PARAM_ATTR_SEL
};

struct hns3_udma_cnp_attr hns3_udma_attr_cnp_dscp = {
	.port_attr = __ATTR(dscp, 0644, cnp_attr_show, cnp_attr_store),
	.type = CNP_PARAM_DSCP
};

static struct attribute *cnp_param_attrs[] = {
	&hns3_udma_attr_cnp_attr_sel.port_attr.attr,
	&hns3_udma_attr_cnp_dscp.port_attr.attr,
	NULL,
};

static const struct attribute_group cnp_param_group = {
	.name = "cnp_param",
	.attrs = cnp_param_attrs,
};

#define HNS3_UDMA_LDCP_CC_ATTR_RW(_name, NAME)					\
	struct hns3_udma_port_cc_attr hns3_udma_port_attr_ldcp_##_name =	\
	__HNS3_UDMA_SCC_ATTR(_name, HNS3_UDMA_CONG_TYPE_LDCP,			\
			     HNS3_UDMA_LDCP_##NAME##_OFS,			\
			     HNS3_UDMA_LDCP_##NAME##_SZ,			\
			     0, HNS3_UDMA_LDCP_##NAME##_MAX)

HNS3_UDMA_LDCP_CC_ATTR_RW(cwd0, CWD0);
HNS3_UDMA_LDCP_CC_ATTR_RW(alpha, ALPHA);
HNS3_UDMA_LDCP_CC_ATTR_RW(gamma, GAMMA);
HNS3_UDMA_LDCP_CC_ATTR_RW(beta, BETA);
HNS3_UDMA_LDCP_CC_ATTR_RW(eta, ETA);
HNS3_UDMA_LDCP_CC_ATTR_RW(lifespan, LIFESPAN);

static struct attribute *ldcp_param_attrs[] = {
	&hns3_udma_port_attr_ldcp_cwd0.port_attr.attr,
	&hns3_udma_port_attr_ldcp_alpha.port_attr.attr,
	&hns3_udma_port_attr_ldcp_gamma.port_attr.attr,
	&hns3_udma_port_attr_ldcp_beta.port_attr.attr,
	&hns3_udma_port_attr_ldcp_eta.port_attr.attr,
	&hns3_udma_port_attr_ldcp_lifespan.port_attr.attr,
	NULL,
};

static const struct attribute_group ldcp_cc_param_group = {
	.name = "ldcp_cc_param",
	.attrs = ldcp_param_attrs,
	.is_visible = scc_attr_is_visible,
};

#define HNS3_UDMA_HC3_CC_ATTR_RW(_name, NAME)					\
	struct hns3_udma_port_cc_attr hns3_udma_port_attr_hc3_##_name =		\
	__HNS3_UDMA_SCC_ATTR(_name, HNS3_UDMA_CONG_TYPE_HC3,			\
			     HNS3_UDMA_HC3_##NAME##_OFS,			\
			     HNS3_UDMA_HC3_##NAME##_SZ,				\
			     0, HNS3_UDMA_HC3_##NAME##_MAX)

HNS3_UDMA_HC3_CC_ATTR_RW(initial_window, INITIAL_WINDOW);
HNS3_UDMA_HC3_CC_ATTR_RW(bandwidth, BANDWIDTH);
HNS3_UDMA_HC3_CC_ATTR_RW(qlen_shift, QLEN_SHIFT);
HNS3_UDMA_HC3_CC_ATTR_RW(port_usage_shift, PORT_USAGE_SHIFT);
HNS3_UDMA_HC3_CC_ATTR_RW(over_period, OVER_PERIOD);
HNS3_UDMA_HC3_CC_ATTR_RW(max_stage, MAX_STAGE);
HNS3_UDMA_HC3_CC_ATTR_RW(gamma_shift, GAMMA_SHIFT);
HNS3_UDMA_HC3_CC_ATTR_RW(lifespan, LIFESPAN);

static struct attribute *hc3_param_attrs[] = {
	&hns3_udma_port_attr_hc3_initial_window.port_attr.attr,
	&hns3_udma_port_attr_hc3_bandwidth.port_attr.attr,
	&hns3_udma_port_attr_hc3_qlen_shift.port_attr.attr,
	&hns3_udma_port_attr_hc3_port_usage_shift.port_attr.attr,
	&hns3_udma_port_attr_hc3_over_period.port_attr.attr,
	&hns3_udma_port_attr_hc3_max_stage.port_attr.attr,
	&hns3_udma_port_attr_hc3_gamma_shift.port_attr.attr,
	&hns3_udma_port_attr_hc3_lifespan.port_attr.attr,
	NULL,
};

static const struct attribute_group hc3_cc_param_group = {
	.name = "hc3_cc_param",
	.attrs = hc3_param_attrs,
	.is_visible = scc_attr_is_visible,
};

#define HNS3_UDMA_DIP_CC_ATTR_RW(_name, NAME)					\
	struct hns3_udma_port_cc_attr hns3_udma_port_attr_dip_##_name =		\
	__HNS3_UDMA_SCC_ATTR(_name, HNS3_UDMA_CONG_TYPE_DIP,			\
			     HNS3_UDMA_DIP_##NAME##_OFS,			\
			     HNS3_UDMA_DIP_##NAME##_SZ,				\
			     0, HNS3_UDMA_DIP_##NAME##_MAX)

HNS3_UDMA_DIP_CC_ATTR_RW(ai, AI);
HNS3_UDMA_DIP_CC_ATTR_RW(f, F);
HNS3_UDMA_DIP_CC_ATTR_RW(tkp, TKP);
HNS3_UDMA_DIP_CC_ATTR_RW(tmp, TMP);
HNS3_UDMA_DIP_CC_ATTR_RW(alp, ALP);
HNS3_UDMA_DIP_CC_ATTR_RW(max_speed, MAX_SPEED);
HNS3_UDMA_DIP_CC_ATTR_RW(g, G);
HNS3_UDMA_DIP_CC_ATTR_RW(al, AL);
HNS3_UDMA_DIP_CC_ATTR_RW(cnp_time, CNP_TIME);
HNS3_UDMA_DIP_CC_ATTR_RW(ashift, ASHIFT);
HNS3_UDMA_DIP_CC_ATTR_RW(lifespan, LIFESPAN);

static struct attribute *dip_param_attrs[] = {
	&hns3_udma_port_attr_dip_ai.port_attr.attr,
	&hns3_udma_port_attr_dip_f.port_attr.attr,
	&hns3_udma_port_attr_dip_tkp.port_attr.attr,
	&hns3_udma_port_attr_dip_tmp.port_attr.attr,
	&hns3_udma_port_attr_dip_alp.port_attr.attr,
	&hns3_udma_port_attr_dip_max_speed.port_attr.attr,
	&hns3_udma_port_attr_dip_g.port_attr.attr,
	&hns3_udma_port_attr_dip_al.port_attr.attr,
	&hns3_udma_port_attr_dip_cnp_time.port_attr.attr,
	&hns3_udma_port_attr_dip_ashift.port_attr.attr,
	&hns3_udma_port_attr_dip_lifespan.port_attr.attr,
	NULL,
};

static const struct attribute_group dip_cc_param_group = {
	.name = "dip_cc_param",
	.attrs = dip_param_attrs,
	.is_visible = scc_attr_is_visible,
};

const struct attribute_group *hns3_udma_attr_port_groups[] = {
	&dcqcn_cc_param_group,
	&ldcp_cc_param_group,
	&hc3_cc_param_group,
	&dip_cc_param_group,
	NULL,
};

static ssize_t hns3_udma_port_attr_show(struct kobject *kobj,
				   struct attribute *attr, char *buf)
{
	struct hns3_udma_port_attribute *port_attr;
	struct hns3_udma_port *port;

	port_attr = container_of(attr, struct hns3_udma_port_attribute, attr);
	port = container_of(kobj, struct hns3_udma_port, kobj);
	if (!port_attr->show)
		return -EIO;

	return port_attr->show(port, port_attr, buf);
}

static ssize_t hns3_udma_port_attr_store(struct kobject *kobj,
					 struct attribute *attr,
					 const char *buf, size_t count)
{
	struct hns3_udma_port_attribute *port_attr;
	struct hns3_udma_port *p;

	port_attr = container_of(attr, struct hns3_udma_port_attribute, attr);
	p = container_of(kobj, struct hns3_udma_port, kobj);
	if (!port_attr->store)
		return -EIO;

	return port_attr->store(p, port_attr, buf, count);
}

static void hns3_udma_port_release(struct kobject *kobj)
{
	struct hns3_udma_port *pdata;
	int i;

	pdata = container_of(kobj, struct hns3_udma_port, kobj);

	if (pdata->scc_param) {
		for (i = 0; i < HNS3_UDMA_CONG_TYPE_TOTAL; i++)
			cancel_delayed_work_sync(&pdata->scc_param[i].scc_cfg_dwork);

		kfree(pdata->scc_param);
		pdata->scc_param = NULL;
	}

	if (pdata->udma_dev->caps.cnp_en && pdata->cnp_param.cnp_param_inited)
		cancel_delayed_work_sync(&pdata->cnp_param.cnp_cfg_dwork);
}

static const struct sysfs_ops hns3_udma_port_ops = {
	.show = hns3_udma_port_attr_show,
	.store = hns3_udma_port_attr_store,
};

static struct kobj_type hns3_udma_port_ktype = {
	.release = hns3_udma_port_release,
	.sysfs_ops = &hns3_udma_port_ops,
};

static int hns3_udma_register_port_sysfs(struct hns3_udma_dev *udma_dev, uint8_t port_num,
					 struct kobject *kobj)
{
	struct hns3_udma_port *pdata;
	int ret;

	pdata = &udma_dev->port_data[port_num];
	pdata->udma_dev = udma_dev;
	pdata->port_num = port_num;
	ret = kobject_init_and_add(&pdata->kobj, &hns3_udma_port_ktype,
				   kobj, "cc_param");
	if (ret) {
		dev_err(udma_dev->dev, "fail to create port(%u) sysfs, ret = %d.\n",
			port_num, ret);
		goto fail_kobj;
	}
	kobject_uevent(&pdata->kobj, KOBJ_ADD);

	ret = alloc_scc_param(udma_dev, pdata);
	if (ret) {
		dev_err(udma_dev->dev, "alloc scc param failed, ret = %d!\n",
			ret);
		goto fail_kobj;
	}

	if (udma_dev->caps.cnp_en) {
		hns3_udma_init_cnp_param(pdata);
		ret = sysfs_create_group(&pdata->kobj, &cnp_param_group);
		if (ret) {
			dev_err(udma_dev->dev,
				"fail to create port(%u) cnp param sysfs, ret = %d.\n",
				port_num, ret);
			goto fail_create_cnp;
		}
	}

	ret = sysfs_create_groups(&pdata->kobj, hns3_udma_attr_port_groups);
	if (ret) {
		dev_err(udma_dev->dev,
			"fail to create port(%u) cc param sysfs, ret = %d.\n",
			port_num, ret);
		goto fail_create_scc;
	}

	return ret;

fail_create_scc:
	if (udma_dev->caps.cnp_en)
		sysfs_remove_group(&pdata->kobj, &cnp_param_group);
fail_create_cnp:
fail_kobj:
	kobject_put(&pdata->kobj);
	return ret;
}

static void hns3_udma_unregister_port_sysfs(struct hns3_udma_dev *udma_dev, uint8_t port_num)
{
	struct hns3_udma_port *pdata;

	pdata = &udma_dev->port_data[port_num];
	sysfs_remove_groups(&pdata->kobj, hns3_udma_attr_port_groups);
	if (udma_dev->caps.cnp_en)
		sysfs_remove_group(&pdata->kobj, &cnp_param_group);
	kobject_put(&pdata->kobj);
}

int hns3_udma_register_cc_sysfs(struct hns3_udma_dev *udma_dev)
{
	int i;
	int j;

	for (i = 0; i < udma_dev->caps.num_ports; i++) {
		if (hns3_udma_register_port_sysfs(udma_dev, i, &udma_dev->dev->kobj) != 0)
			goto err_port_attr;
	}

	return 0;

err_port_attr:
	for (j = 0; j < i; j++)
		hns3_udma_unregister_port_sysfs(udma_dev, j);

	return -EPERM;
}

void hns3_udma_unregister_cc_sysfs(struct hns3_udma_dev *udma_dev)
{
	int i;

	for (i = 0; i < udma_dev->caps.num_ports; i++)
		hns3_udma_unregister_port_sysfs(udma_dev, i);
}

static ssize_t hns3_udma_num_qp_store(struct kobject *kobj,
				      struct hns3_udma_num_qp *attr,
				      const char *buf, size_t count)
{
	struct hns3_udma_cmq_desc desc = {};
	struct hns3_udma_num_qp_cmd *cmd;
	struct hns3_udma_dev *udma_dev;
	int ret;

	udma_dev = container_of(attr, struct hns3_udma_dev, num_qp);
	hns3_udma_cmq_setup_basic_desc(&desc, HNS3_UDMA_NUM_QP_CFG, false);
	cmd = (struct hns3_udma_num_qp_cmd *)desc.data;
	if (kstrtou32(buf, 0, &cmd->num))
		goto error_value;

	if (((cmd->num & (cmd->num - 1)) != 0) ||
	    ((cmd->num < HNS3_UDMA_NUM_QP_MIN) && (cmd->num != 0)) ||
	    (cmd->num > HNS3_UDMA_NUM_QP_MAX))
		goto error_value;

	if (cmd->num == HNS3_UDMA_NUM_QP_MIN)
		dev_warn(udma_dev->dev,
			 "VF traffic maybe cann't work correctly when VF QP is %u.\n",
			 cmd->num);

	cmd->num = cpu_to_le32(cmd->num);
	ret = hns3_udma_cmq_send(udma_dev, &desc, 1);
	if (ret)
		goto error_cmdq;

	return count;

error_value:
	dev_err(udma_dev->dev,
		"invalid num(%u).\n it must be powers of 2 and between [8, 512K],0 is default.\n",
		cmd->num);

	return -EINVAL;

error_cmdq:
	dev_err(udma_dev->dev, "fail to set num_qp(num:%u), ret = %d.\n", cmd->num, ret);

	return -EIO;
}

static ssize_t hns3_udma_num_qp_show(struct kobject *kobj, struct hns3_udma_num_qp *attr, char *buf)
{
	struct hns3_udma_cmq_desc desc = {};
	struct hns3_udma_num_qp_cmd *cmd;
	struct hns3_udma_dev *udma_dev;
	int ret;

	udma_dev = container_of(attr, struct hns3_udma_dev, num_qp);
	hns3_udma_cmq_setup_basic_desc(&desc, HNS3_UDMA_NUM_QP_CFG, true);
	ret = hns3_udma_cmq_send(udma_dev, &desc, 1);
	if (ret)
		goto error_cmdq;

	cmd = (struct hns3_udma_num_qp_cmd *)desc.data;

	return sysfs_emit(buf, "%u\n", le32_to_cpu(cmd->num));

error_cmdq:
	dev_err(udma_dev->dev, "fail to get num_qp, ret = %d.\n", ret);

	return -EIO;
}

int hns3_udma_register_num_qp_sysfs(struct hns3_udma_dev *udma_dev)
{
	int ret;

	if (!udma_dev->caps.num_qp_en) {
		dev_info(udma_dev->dev, "current imp version cann't support qp config.\n");
		return 0;
	}

	udma_dev->num_qp.attr.name = __stringify(num_qp);
	udma_dev->num_qp.attr.mode = ATTR_RW_RONLY_RONLY;
	udma_dev->num_qp.show = hns3_udma_num_qp_show;
	udma_dev->num_qp.store = hns3_udma_num_qp_store;
	ret = sysfs_create_file(&udma_dev->dev->kobj, &udma_dev->num_qp.attr);
	if (ret) {
		dev_err(udma_dev->dev, "fail to create num_qp sysfs, ret = %d.\n", ret);
		return -EINVAL;
	}

	return ret;
}

void hns3_udma_unregister_num_qp_sysfs(struct hns3_udma_dev *udma_dev)
{
	if (!udma_dev->caps.num_qp_en)
		return;

	sysfs_remove_file(&udma_dev->dev->kobj, &udma_dev->num_qp.attr);
}
