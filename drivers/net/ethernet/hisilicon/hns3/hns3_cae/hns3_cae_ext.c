// SPDX-License-Identifier: GPL-2.0+
// Copyright (c) 2016-2017 Hisilicon Limited.

#if (defined CONFIG_EXT_TEST) && (defined CONFIG_IT_VALIDATION)
#include "hns3_cae_ext.h"
#include "hns3_ext.h"

static int hns3_disable_netclk(const struct hns3_nic_priv *net_priv)
{
	struct net_device *netdev = net_priv->netdev;

	return nic_disable_clock(netdev);
}

static int hns3_get_cpu_affinity(const struct hns3_nic_priv *priv)
{
	struct hns3_enet_tqp_vector *tqp_vector = NULL;
	struct hnae3_handle *h = NULL;
	int i;

	if (!priv) {
		pr_err("invalid input param when get cpu affinity\n");
		return -EINVAL;
	}

	h = priv->ae_handle;
	if (nic_netdev_match_check(priv->netdev))
		return -ENODEV;

	pr_info("%s : %d irq total.\n", h->pdev->driver->name,
		priv->vector_num);
	for (i = 0; i < priv->vector_num; i++) {
		tqp_vector = &priv->tqp_vector[i];
		if (tqp_vector->irq_init_flag != HNS3_VECTOR_INITED)
			continue;

		pr_err("irq %d ==> cpu affinity: %*pb\n",
		       tqp_vector->vector_irq,
		       cpumask_pr_args(&tqp_vector->affinity_mask));
	}

	return 0;
}

static int hns3_affi(const struct hns3_nic_priv *net_priv, void *in)
{
	struct hns3_cpumask_param *cpumask_param = NULL;
	cpumask_var_t cpumask_new;
	int ret;

	cpumask_param = (struct hns3_cpumask_param *)in;

	if (cpumask_param->affi_exec_flag != HNS3_AFFI_GET_BIT) {
		if (!alloc_cpumask_var(&cpumask_new, GFP_KERNEL))
			return -ENOMEM;

		ret = cpumask_parse(cpumask_param->mask, cpumask_new);
		if (ret) {
			pr_err("parse cpu affinity from user fail, ret = %d\n",
			       ret);
			return ret;
		}

		ret = nic_set_cpu_affinity(net_priv->netdev, cpumask_new);
		if (ret) {
			pr_err("set cpu affinity fail, ret = %d\n", ret);
			return ret;
		}
	} else {
		ret = hns3_get_cpu_affinity(net_priv);
		if (ret) {
			pr_err("get cpu affinity fail, ret = %d\n", ret);
			return ret;
		}
	}

	return ret;
}

static int hns3_get_chipid(const struct hns3_nic_priv *net_priv, void *out)
{
	u32 chip_id;
	int ret;

	ret = nic_get_chipid(net_priv->netdev, &chip_id);
	if (!ret)
		*(u32 *)out = chip_id;

	return ret;
}

static int hns3_match_check(const struct hns3_nic_priv *net_priv)
{
	struct net_device *netdev = net_priv->netdev;

	return nic_netdev_match_check(netdev);
}

static int hns3_set_led(const struct hns3_nic_priv *net_priv, void *in)
{
	struct hns3_led_state_para *para = (struct hns3_led_state_para *)in;
	struct net_device *netdev = net_priv->netdev;

	return nic_set_led(netdev, para->type, para->status);
}

static int hns3_get_sfp_info(const struct hns3_nic_priv *net_priv, void *in,
			     void *out)
{
	struct hns3_priv_sfp_info_para *para_in =
	    (struct hns3_priv_sfp_info_para *)in;
	struct hns3_priv_sfp_info_para *para_out =
	    (struct hns3_priv_sfp_info_para *)out;
	struct net_device *netdev = net_priv->netdev;
	int ret;

	ret = nic_get_sfpinfo(netdev, para_out->buff, para_in->size,
			      &para_out->outlen);

	return ret;
}

static int hns3_get_sfp_present(const struct hns3_nic_priv *net_priv,
				void *out)
{
	struct net_device *netdev = net_priv->netdev;
	u32 present;
	int ret;

	ret = nic_get_sfp_present(netdev, &present);
	if (!ret)
		*(u32 *)out = present;

	return ret;
}

static int hns3_set_sfp_state(const struct hns3_nic_priv *net_priv, void *in)
{
	struct net_device *netdev = net_priv->netdev;
	bool en = *(bool *)in;

	return nic_set_sfp_state(netdev, en);
}

static int hns3_clean_stats64(const struct hns3_nic_priv *net_priv)
{
	struct net_device *netdev = net_priv->netdev;

	return nic_clean_stats64(netdev, NULL);
}

static int hns3_get_chip_num(const struct hns3_nic_priv *net_priv, void *out)
{
	u32 chip_num;
	int ret;

	ret = nic_get_chip_num(net_priv->netdev, &chip_num);
	if (!ret)
		*(u32 *)out = chip_num;

	return ret;
}

static int hns3_get_port_num(const struct hns3_nic_priv *net_priv, void *out)
{
	u32 port_num;
	int ret;

	ret = nic_get_port_num_per_chip(net_priv->netdev, &port_num);
	if (!ret)
		*(u32 *)out = port_num;

	return ret;
}

static int hns3_disable_net_lane(const struct hns3_nic_priv *net_priv)
{
	struct net_device *netdev = net_priv->netdev;

	return nic_disable_net_lane(netdev);
}

static int hns3_get_lane_status(const struct hns3_nic_priv *net_priv,
				void *out)
{
	u32 lane_status;
	int ret;

	ret = nic_get_net_lane_status(net_priv->netdev, &lane_status);
	if (!ret)
		*(u32 *)out = lane_status;

	return ret;
}

static int hns3_set_mac_state(const struct hns3_nic_priv *net_priv, void *in)
{
	struct net_device *netdev = net_priv->netdev;
	int enable = *(int *)in;

	return nic_set_mac_state(netdev, enable);
}

static int hns3_set_pfc_storm_para(const struct hns3_nic_priv *net_priv,
				   void *in)
{
	struct hns3_pfc_storm_para *para = (struct hns3_pfc_storm_para *)in;
	struct net_device *netdev = net_priv->netdev;

	return nic_set_pfc_storm_para(netdev, para->dir, para->enable,
				      para->period_ms, para->times,
				      para->recovery_period_ms);
}

static int hns3_get_pfc_storm_para(const struct hns3_nic_priv *net_priv,
				   void *in, void *out)
{
	struct hns3_pfc_storm_para *para_in = (struct hns3_pfc_storm_para *)in;
	struct net_device *netdev = net_priv->netdev;
	struct hns3_pfc_storm_para *para_out =
					      (struct hns3_pfc_storm_para *)out;
	u32 recovery_period_ms;
	u32 period_ms;
	u32 enable;
	u32 times;
	u32 dir;
	int ret;

	dir = para_in->dir;
	ret = nic_get_pfc_storm_para(netdev, dir, &enable, &period_ms,
				     &times, &recovery_period_ms);
	if (!ret) {
		para_out->dir = dir;
		para_out->enable = enable;
		para_out->period_ms = period_ms;
		para_out->times = times;
		para_out->recovery_period_ms = recovery_period_ms;
	}

	return ret;
}

static int hns3_get_phy_reg(const struct hns3_nic_priv *net_priv,
			    void *in, void *out,
			    enum phy_type phy_type)
{
	struct hns3_phy_para *para_out = (struct hns3_phy_para *)out;
	struct hns3_phy_para *para_in = (struct hns3_phy_para *)in;
	u32 page_select_addr = para_in->page_select_addr;
	struct net_device *netdev = net_priv->netdev;
	u32 reg_addr = para_in->reg_addr;
	u16 page = para_in->page;
	u16 data;
	int ret;

	if (phy_type == PHY_TYPE_8211)
		ret = nic_get_8211_phy_reg(netdev, page_select_addr, page,
					   reg_addr, &data);
	else
		ret = nic_get_phy_reg(netdev, page_select_addr, page, reg_addr,
				      &data);
	if (!ret) {
		para_out->page = page;
		para_out->reg_addr = reg_addr;
		para_out->data = data;
	}

	return ret;
}

static int hns3_set_phy_reg(const struct hns3_nic_priv *net_priv, void *in,
			    enum phy_type phy_type)
{
	struct hns3_phy_para *para = (struct hns3_phy_para *)in;
	struct net_device *netdev = net_priv->netdev;

	if (phy_type == PHY_TYPE_8211)
		return nic_set_8211_phy_reg(netdev, para->page_select_addr,
					    para->page, para->reg_addr,
					    para->data);
	else
		return nic_set_phy_reg(netdev, para->page_select_addr,
				       para->page, para->reg_addr,
				       para->data);
}

static int hns3_get_macid(const struct hns3_nic_priv *net_priv, void *out)
{
	u32 mac_id;
	int ret;

	ret = nic_get_mac_id(net_priv->netdev, &mac_id);
	if (!ret)
		*(u32 *)out = mac_id;

	return ret;
}

static int hns3_get_hilink_ref_los(const struct hns3_nic_priv *net_priv,
				   void *out)
{
	u32 status;
	int ret;

	ret = nic_get_hilink_ref_los(net_priv->netdev, &status);
	if (!ret)
		*(u32 *)out = status;

	return ret;
}

static int hns3_get_port_type(const struct hns3_nic_priv *net_priv, void *out)
{
	u32 wire_type;
	int ret;

	ret = nic_get_port_wire_type(net_priv->netdev, &wire_type);
	if (!ret)
		*(u32 *)out = wire_type;

	return ret;
}

int hns3_ext_interface_test(const struct hns3_nic_priv *net_priv,
			    void *buf_in, u32 in_size,
			    void *buf_out, u32 out_size)
{
	struct cmd_ext_driver_param *ext_param_out =
					 (struct cmd_ext_driver_param *)buf_out;
	struct cmd_ext_driver_param *ext_param_in =
					  (struct cmd_ext_driver_param *)buf_in;
	bool check = !buf_in || in_size < sizeof(struct cmd_ext_driver_param) ||
		     !buf_out || out_size < sizeof(struct cmd_ext_driver_param);
	void *out = NULL;
	void *in = NULL;
	int ret;

	if (check) {
		pr_err("input parameter error in %s function\n", __func__);
		return -EFAULT;
	}

	in = ext_param_in->buf;
	out = ext_param_out->buf;

	switch (ext_param_in->op_code) {
	case EXT_AFFI_MASK:
		ret = hns3_affi(net_priv, in);
		break;
	case EXT_DISABLE_NET_CLK:
		ret = hns3_disable_netclk(net_priv);
		break;
	case EXT_GET_CHIP_ID:
		ret = hns3_get_chipid(net_priv, out);
		break;
	case EXT_NET_MATCH_CHECK:
		ret = hns3_match_check(net_priv);
		break;
	case EXT_SET_LED:
		ret = hns3_set_led(net_priv, in);
		break;
	case EXT_GET_SFP_INFO:
		ret = hns3_get_sfp_info(net_priv, in, out);
		break;
	case EXT_GET_SFP_PRESENT:
		ret = hns3_get_sfp_present(net_priv, out);
		break;
	case EXT_SET_SFP_STATE:
		ret = hns3_set_sfp_state(net_priv, in);
		break;
	case EXT_CLEAN_STATS64:
		ret = hns3_clean_stats64(net_priv);
		break;
	case EXT_GET_CHIP_NUM:
		ret = hns3_get_chip_num(net_priv, out);
		break;
	case EXT_GET_PORT_NUM:
		ret = hns3_get_port_num(net_priv, out);
		break;
	case EXT_DISABLE_NET_LANE:
		ret = hns3_disable_net_lane(net_priv);
		break;
	case EXT_GET_LANE_STATUS:
		ret = hns3_get_lane_status(net_priv, out);
		break;
	case EXT_SET_MAC_STATE:
		ret = hns3_set_mac_state(net_priv, in);
		break;
	case EXT_SET_PFC_STORM_PARA:
		ret = hns3_set_pfc_storm_para(net_priv, in);
		break;
	case EXT_GET_PFC_STORM_PARA:
		ret = hns3_get_pfc_storm_para(net_priv, in, out);
		break;
	case EXT_GET_PHY_REG:
		ret = hns3_get_phy_reg(net_priv, in, out, PHY_TYPE_1512);
		break;
	case EXT_SET_PHY_REG:
		ret = hns3_set_phy_reg(net_priv, in, PHY_TYPE_1512);
		break;
	case EXT_GET_MAC_ID:
		ret = hns3_get_macid(net_priv, out);
		break;
	case EXT_GET_HILINK_REF_LOS:
		ret = hns3_get_hilink_ref_los(net_priv, out);
		break;
	case EXT_GET_8211_PHY_REG:
		ret = hns3_get_phy_reg(net_priv, in, out, PHY_TYPE_8211);
		break;
	case EXT_SET_8211_PHY_REG:
		ret = hns3_set_phy_reg(net_priv, in, PHY_TYPE_8211);
		break;
	case EXT_GET_PORT_TYPE:
		ret = hns3_get_port_type(net_priv, out);
		break;
	default:
		ret = -EFAULT;
	}

	return ret;
}
#endif
