// SPDX-License-Identifier: GPL-2.0+
// Copyright (c) 2016-2017 Hisilicon Limited.

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
			      enum hnae3_reset_type_custom event_t)
{
	struct hnae3_ae_dev *ae_dev;
	struct hns3_nic_priv *priv;
	struct hnae3_handle *h;

	if (nic_netdev_match_check(netdev))
		return;

	priv = netdev_priv(netdev);
	h = priv->ae_handle;
	ae_dev = pci_get_drvdata(h->pdev);

	if (ae_dev->ops->reset_event)
		ae_dev->ops->reset_event(h->pdev, NULL);
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
	hclge_clean_stats64(h);

	for (i = 0; i < kinfo->num_tqps; i++) {
		ring = priv->ring_data[i].ring;
		memset(&ring->stats, 0, sizeof(struct ring_stats));
		ring = priv->ring_data[i + kinfo->num_tqps].ring;
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
	return hclge_get_chipid(h, chip_id);
}
EXPORT_SYMBOL(nic_get_chipid);

int nic_get_sfpinfo(struct net_device *ndev, u8 *buff, u16 size, u16 *outlen)
{
	struct hnae3_handle *h;

	if (nic_netdev_match_check(ndev))
		return -ENODEV;

	if (!buff || !outlen)
		return -EINVAL;

	h = hns3_get_handle(ndev);
	return hclge_get_sfpinfo(h, buff, 0, size, outlen);
}
EXPORT_SYMBOL(nic_get_sfpinfo);

int nic_get_sfp_present(struct net_device *ndev, u32 *present)
{
	struct hnae3_handle *h;

	if (nic_netdev_match_check(ndev))
		return -ENODEV;

	if (!present)
		return -EINVAL;

	h = hns3_get_handle(ndev);
	return hclge_get_sfp_present(h, present);
}
EXPORT_SYMBOL(nic_get_sfp_present);

int nic_set_sfp_state(struct net_device *ndev, bool en)
{
	struct hnae3_handle *h;

	if (nic_netdev_match_check(ndev))
		return -ENODEV;

	h = hns3_get_handle(ndev);
	return hclge_set_sfp_state(h, en);
}
EXPORT_SYMBOL(nic_set_sfp_state);

int nic_get_sfp_speed(struct net_device *ndev, u32 *speed)
{
	struct hnae3_handle *h;

	if (nic_netdev_match_check(ndev))
		return -ENODEV;

	if (!speed)
		return -EINVAL;

	h = hns3_get_handle(ndev);
	return hclge_ext_get_sfp_speed(h, speed);
}
EXPORT_SYMBOL(nic_get_sfp_speed);

int nic_get_chip_num(struct net_device *ndev, u32 *chip_num)
{
	struct hnae3_handle *h;

	if (nic_netdev_match_check(ndev))
		return -ENODEV;

	if (!chip_num)
		return -EINVAL;

	h = hns3_get_handle(ndev);
	return hclge_get_chip_num(h, chip_num);
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
	return hclge_get_port_num(h, port_num);
}
EXPORT_SYMBOL(nic_get_port_num_per_chip);

int nic_set_led(struct net_device *ndev, int type, int status)
{
	struct hnae3_handle *h;

	if (nic_netdev_match_check(ndev))
		return -ENODEV;

	h = hns3_get_handle(ndev);
	return hclge_set_led(h, type, status);
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
	return hclge_get_led_signal(h, signal);
}
EXPORT_SYMBOL(nic_get_led_signal);

int nic_disable_net_lane(struct net_device *ndev)
{
	struct hnae3_handle *h;

	if (nic_netdev_match_check(ndev))
		return -ENODEV;

	h = hns3_get_handle(ndev);
	return hclge_disable_net_lane(h);
}
EXPORT_SYMBOL(nic_disable_net_lane);

int nic_get_net_lane_status(struct net_device *ndev,  u32 *status)
{
	struct hnae3_handle *h;

	if (nic_netdev_match_check(ndev))
		return -ENODEV;

	if (!status)
		return -EINVAL;

	h = hns3_get_handle(ndev);
	return hclge_get_net_lane_status(h, status);
}
EXPORT_SYMBOL(nic_get_net_lane_status);

int nic_set_mac_state(struct net_device *ndev,  int enable)
{
	struct hnae3_handle *h;
	bool en;

	if (nic_netdev_match_check(ndev))
		return -ENODEV;

	h = hns3_get_handle(ndev);
	en = !!enable;
	return hclge_set_mac_state(h, en);
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
		dev_err(&netdev->dev, "ethernet is down, not support cpu affinity set\n");
		return -EOPNOTSUPP;
	}

	for (i = 0; i < priv->vector_num; i++) {
		tqp_vector = &priv->tqp_vector[i];
		if (tqp_vector->irq_init_flag != HNS3_VECTOR_INITED)
			continue;

		tqp_vector->affinity_mask = *affinity_mask;

		ret = irq_set_affinity_hint(tqp_vector->vector_irq, NULL);
		if (ret) {
			dev_err(&netdev->dev, "reset affinity hint fail, ret = %d\n",
				ret);
			return ret;
		}

		ret = irq_set_affinity_hint(tqp_vector->vector_irq,
					    &tqp_vector->affinity_mask);
		if (ret) {
			dev_err(&netdev->dev, "set affinity hint fail, ret = %d\n",
				ret);
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

	if (nic_netdev_match_check(ndev))
		return -ENODEV;

	h = hns3_get_handle(ndev);
	return hclge_config_nic_clock(h, 0);
}
EXPORT_SYMBOL(nic_disable_clock);

