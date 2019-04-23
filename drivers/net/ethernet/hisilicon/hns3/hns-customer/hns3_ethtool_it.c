// SPDX-License-Identifier: GPL-2.0+
// Copyright (c) 2016-2017 Hisilicon Limited.

#include <linux/etherdevice.h>
#include <linux/string.h>
#include <linux/phy.h>
#include "../hns3_enet.h"

static int hns3_check_ksettings_para(struct net_device *netdev,
				     const struct ethtool_link_ksettings *cmd)
{
	struct hns3_nic_priv *priv = netdev_priv(netdev);
	struct hnae3_handle *h = priv->ae_handle;

	u8 media_type = HNAE3_MEDIA_TYPE_UNKNOWN;
	u8 module_type = HNAE3_MODULE_TYPE_UNKNOWN;
	u8 autoneg = 0;
	u32 speed = 0;
	u8 duplex = 0;
	u32 check_flag;

	/* Verify the settings we care about. */
	if (cmd->base.autoneg != AUTONEG_ENABLE &&
	    cmd->base.autoneg != AUTONEG_DISABLE)
		return -EINVAL;

	if (h->ae_algo->ops->get_media_type)
		h->ae_algo->ops->get_media_type(h, &media_type, &module_type);

	if (h->ae_algo->ops->get_ksettings_an_result)
		h->ae_algo->ops->get_ksettings_an_result(h, &autoneg, &speed,
							 &duplex);

	if (cmd->base.autoneg == autoneg &&
	    cmd->base.speed == speed &&
	    cmd->base.duplex == duplex)
		return 0;

	if (media_type == HNAE3_MEDIA_TYPE_COPPER) {
		check_flag = (cmd->base.speed != SPEED_10 &&
			      cmd->base.speed != SPEED_100 &&
			      cmd->base.speed != SPEED_1000);
		if (check_flag)
			return -EINVAL;
	} else {
		check_flag = (cmd->base.speed != SPEED_1000 &&
			      cmd->base.speed != SPEED_10000 &&
			      cmd->base.speed != SPEED_25000 &&
			      cmd->base.speed != SPEED_40000 &&
			      cmd->base.speed != SPEED_50000 &&
			      cmd->base.speed != SPEED_100000);
		if (check_flag)
			return -EINVAL;
	}

	check_flag = (cmd->base.duplex != DUPLEX_HALF &&
		      cmd->base.duplex != DUPLEX_FULL);

	if (check_flag)
		return -EINVAL;

	return 0;
}

int hns3_set_link_ksettings_it(struct net_device *netdev,
			       const struct ethtool_link_ksettings *cmd)
{
	struct hns3_nic_priv *priv = netdev_priv(netdev);
	struct hnae3_handle *h = priv->ae_handle;
	int ret = 0;

	if (!h->ae_algo || !h->ae_algo->ops)
		return -ESRCH;

	ret = hns3_check_ksettings_para(netdev, cmd);
	if (ret)
		return ret;

	netdev_info(netdev, "set link setting autoneg = %d, speed = %d, duplex = %d\n",
		    cmd->base.autoneg, cmd->base.speed, cmd->base.duplex);

	if (netdev->phydev)
		return phy_ethtool_ksettings_set(netdev->phydev, cmd);

	if (h->ae_algo->ops->set_autoneg)
		h->ae_algo->ops->set_autoneg(h, cmd->base.autoneg);

	if (h->ae_algo->ops->cfg_mac_speed_dup_h)
		h->ae_algo->ops->cfg_mac_speed_dup_h(h,
			cmd->base.speed, cmd->base.duplex);

	return 0;
}
EXPORT_SYMBOL(hns3_set_link_ksettings_it);
