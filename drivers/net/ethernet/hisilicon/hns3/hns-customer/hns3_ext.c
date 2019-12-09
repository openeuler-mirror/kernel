// SPDX-License-Identifier: GPL-2.0+
// Copyright (c) 2016-2017 Hisilicon Limited.

#ifdef CONFIG_HNS3_TEST
#include <linux/dma-mapping.h>
#include <linux/etherdevice.h>
#include <linux/interrupt.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/skbuff.h>
#include <linux/sctp.h>
#include <linux/vermagic.h>
#include <net/gre.h>
#include <net/pkt_cls.h>
#include <net/vxlan.h>
#include "hns3_ext.h"

extern const char hns3_driver_name[];

int nic_netdev_match_check(struct net_device *netdev)
{
	struct ethtool_drvinfo drv_info;

	if (!netdev)
		return -EINVAL;

	if (netdev->ethtool_ops && netdev->ethtool_ops->get_drvinfo)
		netdev->ethtool_ops->get_drvinfo(netdev, &drv_info);

	if (!strncmp(drv_info.driver, hns3_driver_name,
		     strlen(hns3_driver_name)))
		return 0;

	return -EINVAL;
}
EXPORT_SYMBOL(nic_netdev_match_check);

void nic_chip_recover_handler(struct net_device *netdev,
			      enum hnae3_event_type_custom event_t)
{
	struct hnae3_handle *h;

	if (nic_netdev_match_check(netdev))
		return;

	dev_info(&netdev->dev, "reset type is %d!!\n", event_t);

	if (event_t == HNAE3_PPU_POISON_CUSTOM)
		event_t = HNAE3_FUNC_RESET_CUSTOM;

	if (event_t != HNAE3_FUNC_RESET_CUSTOM &&
	    event_t != HNAE3_GLOBAL_RESET_CUSTOM &&
	    event_t != HNAE3_IMP_RESET_CUSTOM) {
		dev_err(&netdev->dev, "reset type err!!\n");
		return;
	}

	h = hns3_get_handle(netdev);
	if (h->ae_algo->ops->priv_ops)
		h->ae_algo->ops->priv_ops(h, HNS3_EXT_OPC_RESET, &event_t, 0);
}
EXPORT_SYMBOL(nic_chip_recover_handler);

int nic_clean_stats64(struct net_device *ndev, struct rtnl_link_stats64 *stats)
{
	struct hns3_nic_priv *priv;
	struct hnae3_handle *h;
	struct hnae3_knic_private_info *kinfo;
	struct hns3_enet_ring *ring;
	int i;

	if (nic_netdev_match_check(ndev))
		return -ENODEV;

	priv = netdev_priv(ndev);
	h = hns3_get_handle(ndev);
	kinfo = &h->kinfo;

	if (h->ae_algo->ops->priv_ops)
		h->ae_algo->ops->priv_ops(h, HNS3_EXT_OPC_CLEAN_STATS64, stats,
					  0);

	for (i = 0; i < kinfo->num_tqps; i++) {
		ring = &priv->ring[i];
		memset(&ring->stats, 0, sizeof(struct ring_stats));
		ring = &priv->ring[i + kinfo->num_tqps];
		memset(&ring->stats, 0, sizeof(struct ring_stats));
	}

	memset(&ndev->stats, 0, sizeof(struct net_device_stats));
	return 0;
}
EXPORT_SYMBOL(nic_clean_stats64);

int nic_get_chipid(struct net_device *ndev, u32 *chip_id)
{
	struct hnae3_handle *h;

	if (nic_netdev_match_check(ndev))
		return -ENODEV;

	if (!chip_id)
		return -EINVAL;

	h = hns3_get_handle(ndev);

	if (h->ae_algo->ops->priv_ops)
		return h->ae_algo->ops->priv_ops(h, HNS3_EXT_OPC_GET_CHIPID,
						 chip_id, 0);
	else
		return -EOPNOTSUPP;
}
EXPORT_SYMBOL(nic_get_chipid);

int nic_get_mac_id(struct net_device *ndev, u32 *mac_id)
{
	struct hnae3_handle *h;

	if (nic_netdev_match_check(ndev))
		return -ENODEV;

	if (!mac_id)
		return -EINVAL;

	h = hns3_get_handle(ndev);

	if (h->ae_algo->ops->priv_ops)
		return h->ae_algo->ops->priv_ops(h, HNS3_EXT_OPC_GET_MAC_ID,
						 mac_id, 0);
	else
		return -EOPNOTSUPP;
}
EXPORT_SYMBOL(nic_get_mac_id);

int nic_get_sfpinfo(struct net_device *ndev, u8 *buff, u16 size, u16 *outlen)
{
	struct hns3_sfp_info_para para;
	struct hnae3_handle *h;

	if (nic_netdev_match_check(ndev))
		return -ENODEV;

	if (!buff || !outlen)
		return -EINVAL;

	para.buff = buff;
	para.outlen = outlen;
	para.offset = 0;
	para.size = size;
	h = hns3_get_handle(ndev);

	if (h->ae_algo->ops->priv_ops) {
		return h->ae_algo->ops->priv_ops(h, HNS3_EXT_OPC_GET_SFPINFO,
						 &para, 0);
	} else {
		return -EOPNOTSUPP;
	}
}
EXPORT_SYMBOL(nic_get_sfpinfo);

int nic_get_sfp_present(struct net_device *ndev, int *present)
{
	struct hnae3_handle *h;

	if (nic_netdev_match_check(ndev))
		return -ENODEV;

	if (!present)
		return -EINVAL;

	h = hns3_get_handle(ndev);

	if (h->ae_algo->ops->priv_ops)
		return h->ae_algo->ops->priv_ops(h, HNS3_EXT_OPC_GET_PRESENT,
						 present, 0);
	else
		return -EOPNOTSUPP;
}
EXPORT_SYMBOL(nic_get_sfp_present);

int nic_set_sfp_state(struct net_device *ndev, bool en)
{
	struct hnae3_handle *h;

	if (nic_netdev_match_check(ndev))
		return -ENODEV;

	h = hns3_get_handle(ndev);
	if (h->ae_algo->ops->priv_ops)
		return h->ae_algo->ops->priv_ops(h, HNS3_EXT_OPC_SET_SFP_STATE,
						 &en, 0);
	else
		return -EOPNOTSUPP;
}
EXPORT_SYMBOL(nic_set_sfp_state);

int nic_get_chip_num(struct net_device *ndev, u32 *chip_num)
{
	struct hnae3_handle *h;

	if (nic_netdev_match_check(ndev))
		return -ENODEV;

	if (!chip_num)
		return -EINVAL;

	h = hns3_get_handle(ndev);
	if (h->ae_algo->ops->priv_ops)
		return h->ae_algo->ops->priv_ops(h, HNS3_EXT_OPC_GET_CHIP_NUM,
						 chip_num, 0);
	else
		return -EOPNOTSUPP;
}
EXPORT_SYMBOL(nic_get_chip_num);

int nic_get_port_num_per_chip(struct net_device *ndev, u32 *port_num)
{
	struct hnae3_handle *h;

	if (nic_netdev_match_check(ndev))
		return -ENODEV;

	if (!port_num)
		return -EINVAL;

	h = hns3_get_handle(ndev);
	if (h->ae_algo->ops->priv_ops)
		return h->ae_algo->ops->priv_ops(h, HNS3_EXT_OPC_GET_PORT_NUM,
						 port_num, 0);
	else
		return -EOPNOTSUPP;
}
EXPORT_SYMBOL(nic_get_port_num_per_chip);

int nic_set_led(struct net_device *ndev, int type, int status)
{
	struct hns3_led_state_para para;
	struct hnae3_handle *h;

	if (nic_netdev_match_check(ndev))
		return -ENODEV;

	para.status = status;
	para.type = type;
	h = hns3_get_handle(ndev);
	if (h->ae_algo->ops->priv_ops)
		return h->ae_algo->ops->priv_ops(h, HNS3_EXT_OPC_SET_LED, &para,
						 0);
	else
		return -EOPNOTSUPP;
}
EXPORT_SYMBOL(nic_set_led);

int nic_get_led_signal(struct net_device *ndev, struct hns3_lamp_signal *signal)
{
	struct hnae3_handle *h;

	if (nic_netdev_match_check(ndev))
		return -ENODEV;

	if (!signal)
		return -EINVAL;

	h = hns3_get_handle(ndev);
	if (h->ae_algo->ops->priv_ops)
		return h->ae_algo->ops->priv_ops(h, HNS3_EXT_OPC_GET_LED_SIGNAL,
						 signal, 0);
	else
		return -EOPNOTSUPP;
}
EXPORT_SYMBOL(nic_get_led_signal);

int nic_disable_net_lane(struct net_device *ndev)
{
	struct hnae3_handle *h;

	if (nic_netdev_match_check(ndev))
		return -ENODEV;

	h = hns3_get_handle(ndev);
	if (h->ae_algo->ops->priv_ops)
		return h->ae_algo->ops->priv_ops(h, HNS3_EXT_OPC_DISABLE_LANE,
						 NULL, 0);
	else
		return -EOPNOTSUPP;
}
EXPORT_SYMBOL(nic_disable_net_lane);

int nic_get_net_lane_status(struct net_device *ndev, u32 *status)
{
	struct hnae3_handle *h;

	if (nic_netdev_match_check(ndev))
		return -ENODEV;

	if (!status)
		return -EINVAL;

	h = hns3_get_handle(ndev);
	if (h->ae_algo->ops->priv_ops)
		return h->ae_algo->ops->priv_ops(h,
						 HNS3_EXT_OPC_GET_LANE_STATUS,
						 status, 0);
	else
		return -EOPNOTSUPP;
}
EXPORT_SYMBOL(nic_get_net_lane_status);

int nic_set_mac_state(struct net_device *ndev, int enable)
{
	struct hnae3_handle *h;
	bool en;

	if (nic_netdev_match_check(ndev))
		return -ENODEV;

	h = hns3_get_handle(ndev);
	en = !!enable;
	if (h->ae_algo->ops->priv_ops)
		return h->ae_algo->ops->priv_ops(h, HNS3_EXT_OPC_SET_MAC_STATE,
						 &en, 0);
	else
		return -EOPNOTSUPP;
}
EXPORT_SYMBOL(nic_set_mac_state);

int nic_set_cpu_affinity(struct net_device *netdev, cpumask_t *affinity_mask)
{
	struct hns3_enet_tqp_vector *tqp_vector;
	struct hns3_nic_priv *priv;
	int ret;
	u16 i;

	if (!netdev || !affinity_mask) {
		pr_err("Invalid input param when set ethernet cpu affinity\n");
		return -EINVAL;
	}

	if (nic_netdev_match_check(netdev))
		return -ENODEV;

	priv = netdev_priv(netdev);
	if (test_bit(HNS3_NIC_STATE_DOWN, &priv->state)) {
		dev_err(&netdev->dev,
			"ethernet is down, not support cpu affinity set\n");
		return -EOPNOTSUPP;
	}

	for (i = 0; i < priv->vector_num; i++) {
		tqp_vector = &priv->tqp_vector[i];
		if (tqp_vector->irq_init_flag != HNS3_VECTOR_INITED)
			continue;

		tqp_vector->affinity_mask = *affinity_mask;

		ret = irq_set_affinity_hint(tqp_vector->vector_irq, NULL);
		if (ret) {
			dev_err(&netdev->dev,
				"reset affinity hint fail, ret = %d\n", ret);
			return ret;
		}

		ret = irq_set_affinity_hint(tqp_vector->vector_irq,
					    &tqp_vector->affinity_mask);
		if (ret) {
			dev_err(&netdev->dev,
				"set affinity hint fail, ret = %d\n", ret);
			return ret;
		}
	}

	dev_info(&netdev->dev, "set nic cpu affinity %*pb succeed\n",
		 cpumask_pr_args(affinity_mask));

	return 0;
}
EXPORT_SYMBOL(nic_set_cpu_affinity);

int nic_disable_clock(struct net_device *ndev)
{
	struct hnae3_handle *h;
	u32 en;
	if (nic_netdev_match_check(ndev))
		return -ENODEV;

	en = 0;
	h = hns3_get_handle(ndev);
	if (h->ae_algo->ops->priv_ops)
		return h->ae_algo->ops->priv_ops(h, HNS3_EXT_OPC_CONFIG_CLOCK,
						 &en, 0);
	else
		return -EOPNOTSUPP;
}
EXPORT_SYMBOL(nic_disable_clock);

int nic_set_pfc_storm_para(struct net_device *ndev, int dir, int enable,
			   int period_ms, int times, int recovery_period_ms)
{
	struct hns3_pfc_storm_para para;
	struct hnae3_handle *h;

	if (nic_netdev_match_check(ndev))
		return -ENODEV;

	para.dir = dir;
	para.enable = enable;
	para.period_ms = period_ms;
	para.times = times;
	para.recovery_period_ms = recovery_period_ms;
	h = hns3_get_handle(ndev);
	if (h->ae_algo->ops->priv_ops)
		return h->ae_algo->ops->priv_ops(h,
						HNS3_EXT_OPC_SET_PFC_STORM_PARA,
						&para, 0);
	else
		return -EOPNOTSUPP;
}
EXPORT_SYMBOL(nic_set_pfc_storm_para);

int nic_get_pfc_storm_para(struct net_device *ndev, int dir, int *enable,
			   int *period_ms, int *times, int *recovery_period_ms)
{
	struct hns3_pfc_storm_para para;
	struct hnae3_handle *h;
	int ret;

	if (nic_netdev_match_check(ndev))
		return -ENODEV;

	if (!enable || !period_ms || !times || !recovery_period_ms) {
		pr_err("get pfc storm para failed because invalid input param.\n");
		return -EINVAL;
	}

	h = hns3_get_handle(ndev);
	if (h->ae_algo->ops->priv_ops) {
		para.dir = dir;
		ret = h->ae_algo->ops->priv_ops(h,
						HNS3_EXT_OPC_GET_PFC_STORM_PARA,
						&para, 0);
		if (!ret) {
			*enable = para.enable;
			*period_ms = para.period_ms;
			*times = para.times;
			*recovery_period_ms = para.recovery_period_ms;
			return 0;
		} else {
			return ret;
		}
	} else {
		return -EOPNOTSUPP;
	}
}
EXPORT_SYMBOL(nic_get_pfc_storm_para);

int nic_get_phy_reg(struct net_device *ndev, u32 page_select_addr,
		    u16 page, u32 reg_addr, u16 *data)
{
	struct hns3_phy_para para;
	struct hnae3_handle *h;
	int ret;

	if (nic_netdev_match_check(ndev))
		return -ENODEV;

	para.page_select_addr = page_select_addr;
	para.page = page;
	para.reg_addr = reg_addr;
	h = hns3_get_handle(ndev);
	if (h->ae_algo->ops->priv_ops) {
		ret = h->ae_algo->ops->priv_ops(h, HNS3_EXT_OPC_GET_PHY_REG,
						&para, 0);
		if (!ret) {
			*data = para.data;
			return 0;
		} else {
			return ret;
		}
	} else {
		return -EOPNOTSUPP;
	}
}
EXPORT_SYMBOL(nic_get_phy_reg);

int nic_set_phy_reg(struct net_device *ndev, u32 page_select_addr,
		    u16 page, u32 reg_addr, u16 data)
{
	struct hns3_phy_para para;
	struct hnae3_handle *h;

	if (nic_netdev_match_check(ndev))
		return -ENODEV;

	para.page_select_addr = page_select_addr;
	para.page = page;
	para.reg_addr = reg_addr;
	para.data = data;
	h = hns3_get_handle(ndev);
	if (h->ae_algo->ops->priv_ops)
		return h->ae_algo->ops->priv_ops(h, HNS3_EXT_OPC_SET_PHY_REG,
						 &para, 0);

	else
		return -EOPNOTSUPP;
}
EXPORT_SYMBOL(nic_set_phy_reg);

int nic_get_hilink_ref_los(struct net_device *ndev, u32 *status)
{
	struct hnae3_handle *h;

	if (nic_netdev_match_check(ndev))
		return -ENODEV;

	if (!status)
		return -EINVAL;

	h = hns3_get_handle(ndev);
	if (h->ae_algo->ops->priv_ops)
		return h->ae_algo->ops->priv_ops(h,
						HNS3_EXT_OPC_GET_HILINK_REF_LOS,
						status, 0);
	else
		return -EOPNOTSUPP;
}
EXPORT_SYMBOL(nic_get_hilink_ref_los);

int nic_get_8211_phy_reg(struct net_device *ndev, u32 page_select_addr,
			 u16 page, u32 reg_addr, u16 *data)
{
	struct hns3_phy_para phy_para;
	struct hnae3_handle *h;
	int ret;

	if (nic_netdev_match_check(ndev))
		return -ENODEV;

	phy_para.page_select_addr = page_select_addr;
	phy_para.page = page;
	phy_para.reg_addr = reg_addr;
	h = hns3_get_handle(ndev);
	if (h->ae_algo->ops->priv_ops) {
		ret = h->ae_algo->ops->priv_ops(h,
						HNS3_EXT_OPC_GET_8211_PHY_REG,
						&phy_para, 0);
		if (!ret) {
			*data = phy_para.data;
			return 0;
		} else {
			return ret;
		}
	} else {
		return -EOPNOTSUPP;
	}
}
EXPORT_SYMBOL(nic_get_8211_phy_reg);

int nic_set_8211_phy_reg(struct net_device *ndev, u32 page_select_addr,
			 u16 page, u32 reg_addr, u16 data)
{
	struct hns3_phy_para phy_para;
	struct hnae3_handle *h;

	if (nic_netdev_match_check(ndev))
		return -ENODEV;

	phy_para.page_select_addr = page_select_addr;
	phy_para.page = page;
	phy_para.reg_addr = reg_addr;
	phy_para.data = data;
	h = hns3_get_handle(ndev);
	if (h->ae_algo->ops->priv_ops)
		return h->ae_algo->ops->priv_ops(h,
						 HNS3_EXT_OPC_SET_8211_PHY_REG,
						 &phy_para, 0);
	else
		return -EOPNOTSUPP;
}
EXPORT_SYMBOL(nic_set_8211_phy_reg);
#endif
