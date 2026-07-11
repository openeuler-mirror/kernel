// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#include <linux/dinghai/driver.h>
#include <linux/compiler_types.h>
#include <linux/netdevice.h>
#include <linux/ethtool.h>
#include <linux/types.h>
#include <linux/bitmap.h>
#include "../slib.h"
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/vmalloc.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/file.h>
#include <linux/path.h>
#include <linux/dcache.h>
#include <linux/namei.h>
#include <linux/mount.h>
#include <linux/mnt_idmapping.h>

#include "../en_aux/queue.h"
#include "../en_aux.h"
#include "../en_aux/en_aux_cmd.h"
#include "../en_np/table/include/dpp_tbl_api.h"
#include "ethtool.h"
#include "linux/dinghai/dh_cmd.h"
#include "../msg_common.h"
#include "../bonding/rdma_ops.h"
#include "../bonding/zxdh_lag.h"
#include "../en_aux/dcbnl/en_dcbnl_api.h"
#include "../en_aux/priv_queue.h"
#include "../en_aux/queue.h"
#include "../en_pf/msg_func.h"

MODULE_LICENSE("Dual BSD/GPL");

#define DRV_NAME "dinghai10e"
#define ETHTOOL_LINK_MODE_MASK_MAX_KERNEL_NBITS 32
#define MAX_DRV_NAME_LEN 32
#define MAX_DRV_VERSION_LEN 32
#define PCI_BUS(PCI_BDF) ((PCI_BDF >> 8) & 0xff)

#define ZXDH_EN_LINK_MODE_ADD(ks, name, sup)                                           \
	do {                                                                           \
		if (sup) {                                                             \
			ethtool_link_ksettings_add_link_mode((ks), supported, name);   \
		} else {                                                               \
			ethtool_link_ksettings_add_link_mode((ks), advertising, name); \
		}                                                                      \
	} while (0)

#define ZXDH_EN_SPEED_MODE_TO_ETHTOOL(en_dev, bit, sup)                       \
	((sup) ? (((en_dev)->supported_speed_modes) & BIT(bit)) == BIT(bit) : \
		       (((en_dev)->advertising_speed_modes) & BIT(bit)) == BIT(bit))

#define GET_FEC_LINK_FLAG (0)
#define GET_FEC_CFG_FLAG (1)
#define GET_FEC_CAP_FLAG (2)

bool enable_1588_debug;

static const u32 fec_2_ethtool_fecparam[] = {
	[SPM_FEC_NONE] = ETHTOOL_FEC_OFF,
	[SPM_FEC_BASER] = ETHTOOL_FEC_BASER,
	[SPM_FEC_RS528] = ETHTOOL_FEC_RS,
	[SPM_FEC_RS544] = ETHTOOL_FEC_RS,
};

static u32 zxdh_en_fec_to_ethtool_fecparam(u32 fec_mode, u32 flag)
{
	s32 i;
	u32 fecparam_cap = 0;

	if (!fec_mode) {
		if (flag == GET_FEC_LINK_FLAG)
			return ETHTOOL_FEC_NONE;
		else if (flag == GET_FEC_CFG_FLAG)
			return ETHTOOL_FEC_AUTO;
	}

	for (i = 0; i < ARRAY_SIZE(fec_2_ethtool_fecparam); i++) {
		if (fec_mode & BIT(i))
			fecparam_cap |= fec_2_ethtool_fecparam[i];
	}

	if (flag == GET_FEC_CAP_FLAG)
		fecparam_cap |= ETHTOOL_FEC_AUTO;

	return fecparam_cap;
}

static void zxdh_en_fec_to_link_ksettings(u32 fec_mode, struct ethtool_link_ksettings *ks, bool sup)
{
	if (fec_mode & BIT(SPM_FEC_NONE))
		ZXDH_EN_LINK_MODE_ADD(ks, FEC_NONE, sup);
	if (fec_mode & BIT(SPM_FEC_BASER))
		ZXDH_EN_LINK_MODE_ADD(ks, FEC_BASER, sup);
	if (fec_mode & BIT(SPM_FEC_RS528) || fec_mode & BIT(SPM_FEC_RS544))
		ZXDH_EN_LINK_MODE_ADD(ks, FEC_RS, sup);
}

static void zxdh_en_fec_link_ksettings_get(struct zxdh_en_device *en_dev,
					   struct ethtool_link_ksettings *ks)
{
	s32 ret;
	u32 fec_cap;
	u32 fec_active;

	ret = zxdh_en_fec_mode_get(en_dev, &fec_cap, NULL, &fec_active);
	if (ret) {
		LOG_ERR("zxdh_en_fec_mode_get failed!\n");
		return;
	}
	//LOG_INFO("fec_cap=0x%x, fec_active=0x%x\n", fec_cap, fec_active);

	zxdh_en_fec_to_link_ksettings(fec_cap, ks, true);
	zxdh_en_fec_to_link_ksettings(fec_active, ks, false);
}

static void zxdh_en_pause_link_ksettings_get(struct zxdh_en_device *en_dev,
					     struct ethtool_link_ksettings *ks)
{
	s32 err;
	u32 fc_mode;

	err = zxdh_en_fc_mode_get(en_dev, &fc_mode);
	if (err != 0) {
		LOG_ERR("zxdh_en_fc_mode_get failed!\n");
		return;
	}

	ZXDH_EN_LINK_MODE_ADD(ks, Pause, true);

	if (fc_mode == BIT(SPM_FC_PAUSE_FULL))
		ZXDH_EN_LINK_MODE_ADD(ks, Pause, false);
	else if (fc_mode == BIT(SPM_FC_PAUSE_RX) || fc_mode == BIT(SPM_FC_PAUSE_TX))
		ZXDH_EN_LINK_MODE_ADD(ks, Asym_Pause, false);
}

static void zxdh_en_phytype_to_ethtool(struct zxdh_en_device *en_dev,
				       struct ethtool_link_ksettings *ks, bool sup)
{
	//0x20000020020
	if (ZXDH_EN_SPEED_MODE_TO_ETHTOOL(en_dev, SPM_SPEED_1X_1G, sup)) {
		ZXDH_EN_LINK_MODE_ADD(ks, 1000baseT_Full, sup);
		ZXDH_EN_LINK_MODE_ADD(ks, 1000baseKX_Full, sup);
		ZXDH_EN_LINK_MODE_ADD(ks, 1000baseX_Full, sup);
	}

	//0x5C0000081000
	if (ZXDH_EN_SPEED_MODE_TO_ETHTOOL(en_dev, SPM_SPEED_1X_10G, sup)) {
		ZXDH_EN_LINK_MODE_ADD(ks, 10000baseT_Full, sup);
		ZXDH_EN_LINK_MODE_ADD(ks, 10000baseKR_Full, sup);
		ZXDH_EN_LINK_MODE_ADD(ks, 10000baseCR_Full, sup);
		ZXDH_EN_LINK_MODE_ADD(ks, 10000baseSR_Full, sup);
		ZXDH_EN_LINK_MODE_ADD(ks, 10000baseLR_Full, sup);
		ZXDH_EN_LINK_MODE_ADD(ks, 10000baseER_Full, sup);
	}

	//0x380000000
	if (ZXDH_EN_SPEED_MODE_TO_ETHTOOL(en_dev, SPM_SPEED_1X_25G, sup)) {
		ZXDH_EN_LINK_MODE_ADD(ks, 25000baseCR_Full, sup);
		ZXDH_EN_LINK_MODE_ADD(ks, 25000baseKR_Full, sup);
		ZXDH_EN_LINK_MODE_ADD(ks, 25000baseSR_Full, sup);
	}

	//0x10C00000000
	if (ZXDH_EN_SPEED_MODE_TO_ETHTOOL(en_dev, SPM_SPEED_1X_50G, sup)) {
		ZXDH_EN_LINK_MODE_ADD(ks, 50000baseCR2_Full, sup);
		ZXDH_EN_LINK_MODE_ADD(ks, 50000baseKR2_Full, sup);
		ZXDH_EN_LINK_MODE_ADD(ks, 50000baseSR2_Full, sup);
	}

	//0x7800000
	if (ZXDH_EN_SPEED_MODE_TO_ETHTOOL(en_dev, SPM_SPEED_4X_40G, sup)) {
		ZXDH_EN_LINK_MODE_ADD(ks, 40000baseKR4_Full, sup);
		ZXDH_EN_LINK_MODE_ADD(ks, 40000baseCR4_Full, sup);
		ZXDH_EN_LINK_MODE_ADD(ks, 40000baseSR4_Full, sup);
		ZXDH_EN_LINK_MODE_ADD(ks, 40000baseLR4_Full, sup);
	}

	//0xF000000000
	if (ZXDH_EN_SPEED_MODE_TO_ETHTOOL(en_dev, SPM_SPEED_4X_100G, sup)) {
		ZXDH_EN_LINK_MODE_ADD(ks, 100000baseKR4_Full, sup);
		ZXDH_EN_LINK_MODE_ADD(ks, 100000baseSR4_Full, sup);
		ZXDH_EN_LINK_MODE_ADD(ks, 100000baseCR4_Full, sup);
		ZXDH_EN_LINK_MODE_ADD(ks, 100000baseLR4_ER4_Full, sup);
	}

	//0x1E00000000000000
	if (ZXDH_EN_SPEED_MODE_TO_ETHTOOL(en_dev, SPM_SPEED_2X_100G, sup)) {
		ZXDH_EN_LINK_MODE_ADD(ks, 100000baseKR2_Full, sup);
		ZXDH_EN_LINK_MODE_ADD(ks, 100000baseSR2_Full, sup);
		ZXDH_EN_LINK_MODE_ADD(ks, 100000baseCR2_Full, sup);
		ZXDH_EN_LINK_MODE_ADD(ks, 100000baseLR2_ER2_FR2_Full, sup);
		ZXDH_EN_LINK_MODE_ADD(ks, 100000baseCR2_Full, sup);
	}

	//0x5C000000000000000
	if (ZXDH_EN_SPEED_MODE_TO_ETHTOOL(en_dev, SPM_SPEED_4X_200G, sup)) {
		ZXDH_EN_LINK_MODE_ADD(ks, 200000baseKR4_Full, sup);
		ZXDH_EN_LINK_MODE_ADD(ks, 200000baseSR4_Full, sup);
		ZXDH_EN_LINK_MODE_ADD(ks, 200000baseCR4_Full, sup);
		ZXDH_EN_LINK_MODE_ADD(ks, 200000baseLR4_ER4_FR4_Full, sup);
	}
}

static void zxdh_en_ethtool_to_phytype(struct ethtool_link_ksettings *ks, u32 *speed_modes)
{
	if (ethtool_link_ksettings_test_link_mode(ks, advertising, 1000baseT_Full))
		*speed_modes |= BIT(SPM_SPEED_1X_1G);

	if (ethtool_link_ksettings_test_link_mode(ks, advertising, 10000baseT_Full))
		*speed_modes |= BIT(SPM_SPEED_1X_10G);

	if (ethtool_link_ksettings_test_link_mode(ks, advertising, 25000baseCR_Full))
		*speed_modes |= BIT(SPM_SPEED_1X_25G);

	if (ethtool_link_ksettings_test_link_mode(ks, advertising, 50000baseCR2_Full))
		*speed_modes |= BIT(SPM_SPEED_1X_50G);

	if (ethtool_link_ksettings_test_link_mode(ks, advertising, 40000baseKR4_Full))
		*speed_modes |= BIT(SPM_SPEED_4X_40G);

	if (ethtool_link_ksettings_test_link_mode(ks, advertising, 100000baseKR4_Full))
		*speed_modes |= BIT(SPM_SPEED_4X_100G);

	if (ethtool_link_ksettings_test_link_mode(ks, advertising, 100000baseKR2_Full))
		*speed_modes |= BIT(SPM_SPEED_2X_100G);

	if (ethtool_link_ksettings_test_link_mode(ks, advertising, 200000baseKR4_Full))
		*speed_modes |= BIT(SPM_SPEED_4X_200G);
}

static s32 zxdh_en_speed_to_speed_modes(u32 speed, u32 *speed_modes, u32 sup_modes)
{
	switch (speed) {
	case SPEED_1000: {
		*speed_modes |= BIT(SPM_SPEED_1X_1G);
		break;
	}
	case SPEED_10000: {
		*speed_modes |= BIT(SPM_SPEED_1X_10G);
		break;
	}
	case SPEED_25000: {
		*speed_modes |= BIT(SPM_SPEED_1X_25G);
		break;
	}
	case SPEED_40000: {
		*speed_modes |= BIT(SPM_SPEED_4X_40G);
		break;
	}
	case SPEED_50000: {
		*speed_modes |= BIT(SPM_SPEED_1X_50G);
		break;
	}
	case SPEED_100000: {
		*speed_modes |= BIT(SPM_SPEED_2X_100G);
		*speed_modes |= BIT(SPM_SPEED_4X_100G);
		break;
	}
	case SPEED_200000: {
		*speed_modes |= BIT(SPM_SPEED_4X_200G);
		break;
	}
	default: {
		return -EINVAL;
	}
	}

	*speed_modes &= sup_modes;
	if (*speed_modes == 0)
		return -EINVAL;

	return 0;
}

static s32 zxdh_en_get_link_ksettings(struct net_device *netdev, struct ethtool_link_ksettings *ks)
{
	struct zxdh_en_priv *en_priv = netdev_priv(netdev);
	struct zxdh_en_device *en_dev = &en_priv->edev;

	ethtool_link_ksettings_zero_link_mode(ks, supported);
	ethtool_link_ksettings_zero_link_mode(ks, advertising);

	ks->base.port = PORT_FIBRE;
	ks->base.autoneg = en_dev->autoneg_enable;
	ethtool_link_ksettings_add_link_mode(ks, supported, FIBRE);
	ethtool_link_ksettings_add_link_mode(ks, supported, Autoneg);

	if (en_dev->autoneg_enable == AUTONEG_ENABLE)
		ethtool_link_ksettings_add_link_mode(ks, advertising, Autoneg);

	ks->base.speed = en_dev->speed;
	if ((!netif_running(netdev)) || (!netif_carrier_ok(netdev)))
		ks->base.speed = SPEED_UNKNOWN;
	ks->base.duplex = ks->base.speed == SPEED_UNKNOWN ? DUPLEX_UNKNOWN : DUPLEX_FULL;

	zxdh_en_phytype_to_ethtool(en_dev, ks, true);
	zxdh_en_phytype_to_ethtool(en_dev, ks, false);

	if (en_dev->ops->get_coredev_type(en_dev->parent) == DH_COREDEV_PF &&
	    zxdh_en_is_panel_port(en_dev)) {
		zxdh_en_fec_link_ksettings_get(en_dev, ks);
		zxdh_en_pause_link_ksettings_get(en_dev, ks);
	}

	return 0;
}

static s32 zxdh_en_set_link_ksettings(struct net_device *netdev,
				      const struct ethtool_link_ksettings *ks)
{
	struct zxdh_en_priv *en_priv = netdev_priv(netdev);
	struct zxdh_en_device *en_dev = &en_priv->edev;
	struct ethtool_link_ksettings safe_ks;
	u32 advertising_link_modes = 0;
	u32 off_speed_modes = 0;
	u32 on_speed_modes = 0;
	s32 err = 0;

	if (en_dev->device_state == ZXDH_DEVICE_STATE_INTERNAL_ERROR)
		return -ENXIO;
	if ((en_dev->ops->get_coredev_type(en_dev->parent) == DH_COREDEV_VF) ||
	    (!zxdh_en_is_panel_port(en_dev))) {
		return -EOPNOTSUPP;
	}

	if (ks->base.duplex == DUPLEX_HALF)
		return -ENAVAIL;

	memset(&safe_ks, 0, sizeof(safe_ks));
	ethtool_link_ksettings_zero_link_mode(&safe_ks, supported);
	ethtool_link_ksettings_zero_link_mode(&safe_ks, advertising);

	if (ks->base.autoneg == AUTONEG_DISABLE) {
		err = zxdh_en_speed_to_speed_modes(ks->base.speed, &off_speed_modes,
						   en_dev->supported_speed_modes);
		LOG_DEBUG("set speed: %d, off_speed_modes: 0x%x\n", ks->base.speed,
			  off_speed_modes);
		if (err != 0) {
			LOG_ERR("zxdh_en_speed_to_speed_mode failed: %d\n", err);
			return -EOPNOTSUPP;
		}

		advertising_link_modes = off_speed_modes;
	} else {
		zxdh_en_phytype_to_ethtool(en_dev, &safe_ks, true);
		if (!bitmap_intersects(ks->link_modes.advertising, safe_ks.link_modes.supported,
				       __ETHTOOL_LINK_MODE_MASK_NBITS)) {
			LOG_ERR("link_mode not supported\n");
			return -EOPNOTSUPP;
		}

		bitmap_and(safe_ks.link_modes.advertising, ks->link_modes.advertising,
			   safe_ks.link_modes.supported, __ETHTOOL_LINK_MODE_MASK_NBITS);
		zxdh_en_ethtool_to_phytype(&safe_ks, &on_speed_modes);
		LOG_DEBUG("on_speed_modes: 0x%x\n", on_speed_modes);
		advertising_link_modes = on_speed_modes;
	}

	if ((advertising_link_modes == en_dev->advertising_speed_modes) &&
	    (ks->base.autoneg == en_dev->autoneg_enable)) {
		LOG_DEBUG("nothing changed\n");
		return 0;
	}

	safe_ks.base.speed = en_dev->speed;
	en_dev->speed = SPEED_UNKNOWN;
	LOG_INFO("autoneg %d, link_modes: 0x%x\n", ks->base.autoneg, advertising_link_modes);
	err = zxdh_en_autoneg_set(en_dev, ks->base.autoneg, advertising_link_modes);
	if (err != 0) {
		en_dev->speed = safe_ks.base.speed;
		LOG_ERR("zxdh_en_autoneg_set failed: %d\n", err);
		return err;
	}
	en_dev->autoneg_enable = ks->base.autoneg;
	en_dev->advertising_speed_modes = advertising_link_modes;
	en_dev->link_up = false;
	netif_carrier_off(netdev);
	en_dev->ops->set_pf_link_up(en_dev->parent, FALSE);
	queue_work(en_priv->events->wq, &en_priv->edev.vf_link_info_update_work);
	queue_work(en_priv->events->wq, &en_priv->edev.link_info_irq_update_np_work);

	return err;
}

static u32 zxdh_en_get_link(struct net_device *netdev)
{
	return netif_carrier_ok(netdev) ? 1 : 0;
}

static int zxdh_en_get_eeprom_len(struct net_device *netdev)
{
	return 0;
}

static int zxdh_en_get_eeprom(struct net_device *netdev, struct ethtool_eeprom *eeprom, u8 *bytes)
{
	return 0;
}

static int zxdh_en_set_eeprom(struct net_device *netdev, struct ethtool_eeprom *eeprom, u8 *bytes)
{
	return 0;
}

static void zxdh_en_get_ringparam(struct net_device *netdev, struct ethtool_ringparam *param,
				  struct kernel_ethtool_ringparam *kernel_ring,
				  struct netlink_ext_ack *ack)
{
	struct zxdh_en_priv *en_priv = netdev_priv(netdev);
	struct zxdh_en_device *en_dev = &en_priv->edev;

	param->rx_max_pending = ZXDH_PF_MAX_DESC_NUM(en_dev);
	param->tx_max_pending = ZXDH_PF_MAX_DESC_NUM(en_dev);
	param->rx_pending = en_dev->eth_config.rx_queue_size;
	param->tx_pending = en_dev->eth_config.tx_queue_size;
}

static s32 zxdh_phy_vq_reset(struct zxdh_en_device *en_dev)
{
	union zxdh_msg *msg = NULL;
	s32 err = 0;
	s32 i = 0;
	struct zxdh_bar_extra_para para = { 0 };

	para.is_sync = true;
	para.retrycnt = BAR_MSG_RETRY_CNT_MAX;

	msg = kzalloc(sizeof(union zxdh_msg), GFP_KERNEL);
	if (!msg) {
		LOG_ERR("kzalloc(%lu, GFP_KERNEL) failed !", sizeof(union zxdh_msg));
		return -ENOMEM;
	}

	msg->vqm_msg.opcode = MSIX_MODE_SET;
	msg->vqm_msg.cmd = OVS_VQM_CTRL_RESET_QIDS;
	msg->vqm_msg.qid_reset_msg.version = ZXDH_VNET_ZTE;
	msg->vqm_msg.qid_reset_msg.qnum = en_dev->max_queue_pairs * 2;
	for (i = 0; i < en_dev->max_queue_pairs * 2; ++i)
		msg->vqm_msg.qid_reset_msg.qid[i] = en_dev->phy_index[i];
	err = en_dev->ops->msg_send_cmd(en_dev->parent, MODULE_CFG_VQM, msg, msg, &para);
	if (err != 0)
		LOG_ERR("send cfg msix mode msg to riscv failed\n");
	kfree(msg);
	return err;
}

static int zxdh_en_set_ringparam(struct net_device *netdev, struct ethtool_ringparam *param,
				 struct kernel_ethtool_ringparam *kernel_ring,
				 struct netlink_ext_ack *ack)
{
	struct zxdh_en_priv *en_priv = netdev_priv(netdev);
	struct zxdh_en_device *en_dev = &en_priv->edev;
	s32 carrier_ok;
	s32 err = 0;
	s32 i = 0;
	bool is_up = netif_running(netdev);

	if (en_dev->device_state == ZXDH_DEVICE_STATE_INTERNAL_ERROR)
		return -ENXIO;
	if (!en_dev->ops->is_fw_feature_support(en_dev->parent, FW_FEATURE_QUEUE_RESET)) {
		LOG_ERR("fw feature not supported\n");
		return -EINVAL;
	}

	if (en_dev->ops->is_bond(en_dev->parent))
		return -EINVAL;

	if (param->rx_jumbo_pending) {
		LOG_ERR("rx_jumbo_pending not supported\n");
		return -EINVAL;
	}
	if (param->rx_mini_pending) {
		LOG_ERR("rx_mini_pending not supported\n");
		return -EINVAL;
	}

	if ((param->rx_pending < ZXDH_PF_MIN_DESC_NUM) ||
	    (param->rx_pending > ZXDH_PF_MAX_DESC_NUM(en_dev))) {
		LOG_ERR("rx_pending (%d) out of range\n", param->rx_pending);
		return -EINVAL;
	}

	if ((param->tx_pending < ZXDH_PF_MIN_DESC_NUM) ||
	    (param->tx_pending > ZXDH_PF_MAX_DESC_NUM(en_dev))) {
		LOG_ERR("tx_pending (%d) out of range\n", param->tx_pending);
		return -EINVAL;
	}

	if (param->rx_pending == en_dev->eth_config.rx_queue_size &&
	    param->tx_pending == en_dev->eth_config.tx_queue_size) {
		LOG_DEBUG("no need to set ring param\n");
		return 0;
	}

	carrier_ok = netif_carrier_ok(netdev);
	netif_carrier_off(netdev);
	if (is_up)
		zxdh_port_enable(en_dev, false);

	if (carrier_ok) {
		msleep(80);
		if (!is_flow_stopped(en_dev)) {
			LOG_ERR("rx flow stopped failed\n");
			err = -EINVAL;
			goto out;
		}
	}

#ifdef ZXDH_MSGQ
	if (NEED_MSGQ(en_dev))
		msgq_privq_uninit((struct msgq_dev *)en_dev->msgq_dev);
#endif
	if (is_up) {
		mutex_lock(&en_priv->lock);
		cancel_delayed_work_sync(&en_dev->refill);
		for (i = 0; i < en_dev->max_vq_pairs; i++) {
			napi_disable(&en_dev->rq[i].napi);
			virtnet_napi_tx_disable(&en_dev->sq[i].napi);
		}
		netif_tx_stop_all_queues(netdev);
		netif_tx_disable(netdev);
	}

	en_dev->eth_config.rx_queue_size = roundup_pow_of_two(param->rx_pending);
	en_dev->eth_config.tx_queue_size = roundup_pow_of_two(param->tx_pending);
	LOG_DEBUG("rx_size: %d, tx_size: %d\n", en_dev->eth_config.rx_queue_size,
		  en_dev->eth_config.tx_queue_size);
	mutex_lock(&en_dev->parent->lock);
	zxdh_free_unused_bufs(netdev);
	usleep_range(70, 100);
	zxdh_vvq_reset(en_dev);
	mutex_unlock(&en_dev->parent->lock);

	err = zxdh_phy_vq_reset(en_dev);
	if (err != 0) {
		LOG_ERR("zxdh_phy_vq_reset failed\n");
		err = -EINVAL;
	}

	if (is_up) {
		for (i = 0; i < en_dev->max_vq_pairs; i++) {
			if (i < en_dev->curr_queue_pairs) {
				if (!try_fill_recv(&en_dev->rq[i], GFP_KERNEL))
					schedule_delayed_work(&en_dev->refill, 0);
			}
			virtnet_napi_enable(en_dev->rq[i].vq, &en_dev->rq[i].napi);
			virtnet_napi_tx_enable(netdev, en_dev->sq[i].vq, &en_dev->sq[i].napi);
		}
		mutex_unlock(&en_priv->lock);
	}

out:

#ifdef ZXDH_MSGQ
	if (NEED_MSGQ(en_dev))
		msgq_privq_init((struct msgq_dev *)en_dev->msgq_dev, netdev);
#endif
	if (is_up) {
		zxdh_port_enable(en_dev, true);
		netif_tx_wake_all_queues(netdev);
	}
	if (carrier_ok)
		netif_carrier_on(netdev);

	return err;
}

static void zxdh_en_get_pauseparam(struct net_device *netdev, struct ethtool_pauseparam *pause)
{
	s32 err;
	u32 fc_mode;
	struct zxdh_en_device *en_dev = netdev_priv(netdev);

	if (en_dev->device_state == ZXDH_DEVICE_STATE_INTERNAL_ERROR)
		return;

	if (en_dev->ops->get_coredev_type(en_dev->parent) == DH_COREDEV_VF)
		return;

	err = zxdh_en_fc_mode_get(en_dev, &fc_mode);
	if (err != 0) {
		LOG_ERR("zxdh_en_fc_mode_get failed!\n");
		return;
	}

	pause->autoneg = 0;

	switch (fc_mode) {
	case BIT(SPM_FC_PAUSE_FULL): {
		pause->rx_pause = 1;
		pause->tx_pause = 1;
		break;
	}
	case BIT(SPM_FC_PAUSE_RX): {
		pause->rx_pause = 1;
		pause->tx_pause = 0;
		break;
	}
	case BIT(SPM_FC_PAUSE_TX): {
		pause->rx_pause = 0;
		pause->tx_pause = 1;
		break;
	}
	default: {
		pause->rx_pause = 0;
		pause->tx_pause = 0;
		break;
	}
	}
}

static s32 zxdh_en_set_pauseparam(struct net_device *netdev, struct ethtool_pauseparam *pause)
{
	s32 err;
	u32 fc_mode_cur;
	u32 fc_mode_cfg;
	struct zxdh_en_device *en_dev = netdev_priv(netdev);

	if (en_dev->device_state == ZXDH_DEVICE_STATE_INTERNAL_ERROR)
		return -ENXIO;
	if ((en_dev->ops->get_coredev_type(en_dev->parent) == DH_COREDEV_VF) ||
	    !(zxdh_en_is_panel_port(en_dev))) {
		return -EOPNOTSUPP;
	}

	if (pause->autoneg) {
		LOG_ERR("not support pause autoneg!\n");
		return -EOPNOTSUPP;
	}

	err = zxdh_en_fc_mode_get(en_dev, &fc_mode_cur);
	if (err != 0) {
		LOG_ERR("zxdh_en_fc_mode_get failed!\n");
		return err;
	}

	if ((pause->rx_pause || pause->tx_pause) && (fc_mode_cur == BIT(SPM_FC_PFC_FULL)))
		LOG_ERR("warning, ethtool cfg pause on, this will lead to pfc off!\n");

	if (pause->rx_pause && pause->tx_pause) {
		fc_mode_cfg = BIT(SPM_FC_PAUSE_FULL);
	} else if (pause->rx_pause) {
		fc_mode_cfg = BIT(SPM_FC_PAUSE_RX);
	} else if (pause->tx_pause) {
		fc_mode_cfg = BIT(SPM_FC_PAUSE_TX);
	} else {
		if (fc_mode_cur == BIT(SPM_FC_PFC_FULL))
			fc_mode_cfg = BIT(SPM_FC_PFC_FULL);
		else
			fc_mode_cfg = BIT(SPM_FC_NONE);
	}

	if (fc_mode_cfg != fc_mode_cur) {
		err = zxdh_en_fc_mode_set(en_dev, fc_mode_cfg);
		if (err != 0) {
			LOG_ERR("zxdh_en_fc_mode_set failed!\n");
			return err;
		}
	}

	return 0;
}

static s32 zxdh_en_get_fecparam(struct net_device *netdev, struct ethtool_fecparam *fecparam)
{
	s32 err;
	u32 fec_cfg;
	u32 fec_active;
	struct zxdh_en_device *en_dev = netdev_priv(netdev);

	if (en_dev->device_state == ZXDH_DEVICE_STATE_INTERNAL_ERROR)
		return -ENXIO;
	if ((en_dev->ops->get_coredev_type(en_dev->parent) == DH_COREDEV_VF) ||
	    (!zxdh_en_is_panel_port(en_dev))) {
		return -EOPNOTSUPP;
	}

	err = zxdh_en_fec_mode_get(en_dev, NULL, &fec_cfg, &fec_active);
	if (err != 0) {
		LOG_ERR("zxdh_en_fec_mode_get failed!\n");
		return err;
	}

	fecparam->fec = zxdh_en_fec_to_ethtool_fecparam(fec_cfg, GET_FEC_CFG_FLAG);
	fecparam->active_fec = zxdh_en_fec_to_ethtool_fecparam(fec_active, GET_FEC_LINK_FLAG);

	//LOG_INFO("fec_cfg=0x%x, fecparam->fec=0x%x, fec_active=0x%x, fecparam->active_fec=0x%x\n",
	//          fec_cfg, fecparam->fec, fec_active, fecparam->active_fec);

	return 0;
}

static s32 zxdh_en_set_fecparam(struct net_device *netdev, struct ethtool_fecparam *fecparam)
{
	s32 i;
	s32 err;
	u32 fec_cap;
	u32 fec_cfg = 0;
	u32 fecparam_cap;
	struct zxdh_en_device *en_dev = netdev_priv(netdev);

	if (en_dev->device_state == ZXDH_DEVICE_STATE_INTERNAL_ERROR)
		return -ENXIO;
	if ((en_dev->ops->get_coredev_type(en_dev->parent) == DH_COREDEV_VF) ||
	    (!zxdh_en_is_panel_port(en_dev))) {
		return -EOPNOTSUPP;
	}

	err = zxdh_en_fec_mode_get(en_dev, &fec_cap, NULL, NULL);
	if (err != 0) {
		LOG_ERR("zxdh_en_fec_mode_get failed!\n");
		return err;
	}
	fecparam_cap = zxdh_en_fec_to_ethtool_fecparam(fec_cap, GET_FEC_CAP_FLAG);

	if ((fecparam->fec | fecparam_cap) != fecparam_cap) {
		LOG_ERR("fecparam->fec 0x%x unsupport !\n", fecparam->fec);
		return -EOPNOTSUPP;
	}

	for (i = 0; i < ARRAY_SIZE(fec_2_ethtool_fecparam); i++) {
		if (fecparam->fec == fec_2_ethtool_fecparam[i])
			fec_cfg |= BIT(i);
	}

	if (!fec_cfg && (fecparam->fec != ETHTOOL_FEC_AUTO)) {
		LOG_ERR("fecparam->fec 0x%x unsupport !\n", fecparam->fec);
		return -EOPNOTSUPP;
	}

	//LOG_INFO("fecparam_cap=0x%x, fec_cap=0x%x, fecparam->fec=0x%x, fec_cfg=0x%x\n",
	//          fecparam_cap, fec_cap, fecparam->fec, fec_cfg);

	err = zxdh_en_fec_mode_set(en_dev, fec_cfg);
	if (err != 0) {
		LOG_ERR("zxdh_en_fec_mode_set failed!\n");
		return err;
	}

	return 0;
}

static s32 zxdh_en_get_module_info(struct net_device *netdev, struct ethtool_modinfo *modinfo)
{
	u32 read_bytes;
	u8 data[2] = { 0 };
	struct zxdh_en_module_eeprom_param query = { 0 };
	struct zxdh_en_device *en_dev = netdev_priv(netdev);

	if (en_dev->device_state == ZXDH_DEVICE_STATE_INTERNAL_ERROR)
		return -ENXIO;
	if ((en_dev->ops->get_coredev_type(en_dev->parent) == DH_COREDEV_VF) ||
	    (!zxdh_en_is_panel_port(en_dev))) {
		return -EOPNOTSUPP;
	}

	query.i2c_addr = SFF_I2C_ADDRESS_LOW;
	query.page = 0;
	query.offset = 0;
	query.length = 2;
	read_bytes = zxdh_en_module_eeprom_read(en_dev, &query, data);
	if (read_bytes != query.length)
		return -EIO;

	switch (data[0]) {
	case ZXDH_MODULE_ID_SFP:
		modinfo->type = ETH_MODULE_SFF_8472;
		modinfo->eeprom_len = ETH_MODULE_SFF_8472_LEN;
		break;
	case ZXDH_MODULE_ID_QSFP:
		modinfo->type = ETH_MODULE_SFF_8436;
		modinfo->eeprom_len = ETH_MODULE_SFF_8436_MAX_LEN;
		break;
	case ZXDH_MODULE_ID_QSFP_PLUS:
	case ZXDH_MODULE_ID_QSFP28:
		if (data[1] < 3) {
			modinfo->type = ETH_MODULE_SFF_8436;
			modinfo->eeprom_len = ETH_MODULE_SFF_8436_MAX_LEN;
		} else {
			modinfo->type = ETH_MODULE_SFF_8636;
			modinfo->eeprom_len = ETH_MODULE_SFF_8636_MAX_LEN;
		}
		break;

	case ZXDH_MODULE_ID_QSFP_DD:
	case ZXDH_MODULE_ID_OSFP:
	case ZXDH_MODULE_ID_DSFP:
	case ZXDH_MODULE_ID_QSFP_PLUS_WITH_CMIS:
	case ZXDH_MODULE_ID_SFP_DD_WITH_CMIS:
	case ZXDH_MODULE_ID_SFP_PLUS_WITH_CMIS:
		modinfo->type = ETH_MODULE_SFF_8636;
		modinfo->eeprom_len = ETH_MODULE_SFF_8636_MAX_LEN;
		break;
	default:
		LOG_ERR("can not recognize module identifier 0x%x!\n", data[0]);
		return -EINVAL;
	}

	return 0;
}

static s32 zxdh_en_get_module_eeprom(struct net_device *netdev, struct ethtool_eeprom *ee, u8 *data)
{
	struct zxdh_en_module_eeprom_param query = { 0 };
	struct zxdh_en_device *en_dev = netdev_priv(netdev);
	u32 offset = ee->offset;
	u32 length = ee->len;
	u8 identifier;
	u32 offset_boundary = 0;
	u32 total_read_bytes = 0;
	u32 read_bytes = 0;

	if (en_dev->device_state == ZXDH_DEVICE_STATE_INTERNAL_ERROR)
		return -ENXIO;

	if ((en_dev->ops->get_coredev_type(en_dev->parent) == DH_COREDEV_VF) ||
	    (!zxdh_en_is_panel_port(en_dev))) {
		return -EOPNOTSUPP;
	}

	//LOG_INFO("offset %u, len %u\n", ee->offset, ee->len);

	if (!ee->len)
		return -EINVAL;

	memset(data, 0, ee->len);

	query.i2c_addr = SFF_I2C_ADDRESS_LOW;
	query.bank = 0;
	query.page = 0;
	query.offset = 0;
	query.length = 1;
	read_bytes = zxdh_en_module_eeprom_read(en_dev, &query, &identifier);
	if (read_bytes != query.length)
		return -EIO;

	while (total_read_bytes < ee->len) {
		if (identifier == ZXDH_MODULE_ID_SFP) {
			if (offset < 256) {
				query.i2c_addr = SFF_I2C_ADDRESS_LOW;
				query.page = 0;
				query.offset = offset;
			} else {
				query.i2c_addr = SFF_I2C_ADDRESS_HIGH;
				query.page = 0;
				query.offset = offset - 256;
			}
			offset_boundary = (query.offset < 128) ? 128 : 256;
			query.length = ((query.offset + length) > offset_boundary) ?
						     (offset_boundary - query.offset) :
						     length;
		} else if (identifier == ZXDH_MODULE_ID_QSFP ||
			   identifier == ZXDH_MODULE_ID_QSFP_PLUS ||
			   identifier == ZXDH_MODULE_ID_QSFP28 ||
			   identifier == ZXDH_MODULE_ID_QSFP_DD ||
			   identifier == ZXDH_MODULE_ID_OSFP || identifier == ZXDH_MODULE_ID_DSFP ||
			   identifier == ZXDH_MODULE_ID_QSFP_PLUS_WITH_CMIS ||
			   identifier == ZXDH_MODULE_ID_SFP_DD_WITH_CMIS ||
			   identifier == ZXDH_MODULE_ID_SFP_PLUS_WITH_CMIS) {
			query.i2c_addr = SFF_I2C_ADDRESS_LOW;
			if (offset < 256) {
				query.page = 0;
				query.offset = offset;
			} else {
				query.page = (offset - 256) / 128 + 1;
				query.offset = offset - 128 * query.page;
			}
			offset_boundary = (query.offset < 128) ? 128 : 256;
			query.length = ((query.offset + length) > offset_boundary) ?
						     (offset_boundary - query.offset) :
						     length;
		} else {
			LOG_ERR("can not recognize module identifier 0x%x!\n", identifier);
			return -EINVAL;
		}

		read_bytes = zxdh_en_module_eeprom_read(en_dev, &query, data + total_read_bytes);
		if (read_bytes != query.length)
			return -EIO;

		total_read_bytes += read_bytes;
		offset += read_bytes;
		length -= read_bytes;
	}

	return 0;
}

static s32 zxdh_en_get_module_eeprom_by_page(struct net_device *netdev,
					     const struct ethtool_module_eeprom *page_data,
					     struct netlink_ext_ack *extack)
{
	struct zxdh_en_module_eeprom_param query = { 0 };
	struct zxdh_en_device *en_dev = netdev_priv(netdev);
	u32 read_bytes = 0;

	if (en_dev->device_state == ZXDH_DEVICE_STATE_INTERNAL_ERROR)
		return -ENXIO;

	if ((en_dev->ops->get_coredev_type(en_dev->parent) == DH_COREDEV_VF) ||
	    (!zxdh_en_is_panel_port(en_dev))) {
		return -EOPNOTSUPP;
	}

	if (!page_data->length)
		return -EINVAL;

	zte_memset_s(page_data->data, 0, page_data->length);

	query.i2c_addr = page_data->i2c_address;
	query.bank = page_data->bank;
	query.page = page_data->page;
	query.offset = page_data->offset;
	query.length = page_data->length;
	read_bytes = zxdh_en_module_eeprom_read(en_dev, &query, page_data->data);
	if (read_bytes != query.length)
		return -EIO;

	return read_bytes;
}

static s32 zxdh_test_health_info(struct zxdh_en_priv *en_priv)
{
	struct zxdh_en_device *en_dev = &en_priv->edev;
	struct dh_core_dev *dh_dev = en_dev->parent;
	struct zxdh_pf_device *pf_dev = dh_core_priv(dh_dev->parent);
	struct zxdh_core_health *health = &pf_dev->health;

	return health->fatal ? 1 : 0;
}

static s32 zxdh_test_link_speed(struct zxdh_en_priv *en_priv)
{
	struct zxdh_en_device *en_dev = &en_priv->edev;

	if (!test_bit(ZXDH_DEVICE_STATE_OPENED, &en_dev->state))
		return 1;

	if (en_dev->speed == SPEED_UNKNOWN) {
		LOG_ERR("get link speed error\n");
		return 1;
	}
	return 0;
}

static s32 zxdh_test_link_state(struct zxdh_en_priv *en_priv)
{
	struct zxdh_en_device *en_dev = &en_priv->edev;

	if (!test_bit(ZXDH_DEVICE_STATE_OPENED, &en_dev->state))
		return 1;

	if ((!en_dev->link_up) && (!netif_carrier_ok(en_dev->netdev))) {
		LOG_ERR("curr state is link down\n");
		return 1;
	}

	return 0;
}

#ifdef CONFIG_INET
static s32 zxdh_test_loopback_validate(struct sk_buff *skb, struct net_device *ndev,
				       struct packet_type *pt, struct net_device *orig_ndev)
{
	struct zxdh_lbt_priv *lbtp = pt->af_packet_priv;
	struct zxdh_ehdr *zxdhh = NULL;
	struct ethhdr *ethh = NULL;
	struct udphdr *udph = NULL;
	struct iphdr *iph = NULL;

	ethh = (struct ethhdr *)skb_mac_header(skb);
	if (!ether_addr_equal(ethh->h_dest, orig_ndev->dev_addr))
		goto out;

	iph = ip_hdr(skb);
	if (iph->protocol != IPPROTO_UDP)
		goto out;

	/* Don't assume skb_transport_header() was set */
	udph = (struct udphdr *)((u8 *)iph + 4 * iph->ihl);
	if (udph->dest != htons(9))
		goto out;

	zxdhh = (struct zxdh_ehdr *)((int8_t *)udph + sizeof(*udph));
	if (zxdhh->magic != cpu_to_be64(ZXDH_TEST_MAGIC))
		goto out; /* so close ! */
	lbtp->loopback_ok = true;
	complete(&lbtp->comp);
out:
	kfree_skb(skb);
	return 0;
}

s32 zxdh_test_loopback_setup(struct zxdh_en_priv *en_priv, struct zxdh_lbt_priv *lbtp)
{
	struct zxdh_en_device *en_dev = &en_priv->edev;

	en_dev->local_lb_enable = true;
	lbtp->loopback_ok = false;
	init_completion(&lbtp->comp);

	lbtp->pt.type = htons(ETH_P_IP);
	lbtp->pt.func = zxdh_test_loopback_validate;
	lbtp->pt.dev = en_dev->netdev;
	lbtp->pt.af_packet_priv = lbtp;
	dev_add_pack(&lbtp->pt);
	return 0;
}

static void zxdh_test_loopback_cleanup(struct zxdh_en_priv *en_priv, struct zxdh_lbt_priv *lbtp)
{
	struct zxdh_en_device *en_dev = &en_priv->edev;

	en_dev->local_lb_enable = false;
	dev_remove_pack(&lbtp->pt);
}

static struct sk_buff *zxdh_test_get_udp_skb(struct zxdh_en_priv *en_priv)
{
	struct zxdh_en_device *en_dev = &en_priv->edev;
	struct sk_buff *skb = NULL;
	struct zxdh_ehdr *zxdhh = NULL;
	struct ethhdr *ethh = NULL;
	struct udphdr *udph = NULL;
	struct iphdr *iph = NULL;
	s32 iplen = 0;
	struct zxdh_bar_extra_para para = { 0 };

	para.is_sync = true;
	para.retrycnt = BAR_MSG_RETRY_CNT_MAX;

	skb = netdev_alloc_skb(en_dev->netdev, ZXDH_TEST_PKT_SIZE);
	if (!skb) {
		LOG_ERR("Failed to alloc loopback skb\n");
		return NULL;
	}

	/* Reserve for ethernet and IP header  */
	ethh = skb_push(skb, ETH_HLEN);
	skb_reset_mac_header(skb);

	skb_set_network_header(skb, skb->len);
	iph = skb_put(skb, sizeof(struct iphdr));

	skb_set_transport_header(skb, skb->len);
	udph = skb_put(skb, sizeof(struct udphdr));

	/* Fill ETH header */
	ether_addr_copy(ethh->h_dest, en_dev->netdev->dev_addr);
	eth_zero_addr(ethh->h_source);
	ethh->h_proto = htons(ETH_P_IP); /* ipv4 */

	/* Fill UDP header */
	udph->source = htons(9);
	udph->dest = htons(9);
	udph->len = htons(sizeof(struct zxdh_ehdr) + sizeof(struct udphdr));
	udph->check = 0;

	/* Fill IP header */
	iph->ihl = 5;
	iph->ttl = 32;
	iph->version = 4;
	iph->protocol = IPPROTO_UDP;
	iplen = sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct zxdh_ehdr);
	iph->tot_len = htons(iplen);
	iph->frag_off = 0;
	iph->saddr = 0;
	iph->daddr = 0;
	iph->tos = 0;
	iph->id = 0;
	ip_send_check(iph);

	/* Fill test header and data */
	zxdhh = skb_put(skb, sizeof(*zxdhh));
	zxdhh->magic = cpu_to_be64(ZXDH_TEST_MAGIC);

	skb->csum = 0;
	skb->ip_summed = CHECKSUM_PARTIAL;
	udp4_hwcsum(skb, iph->saddr, iph->daddr);

	skb->protocol = htons(ETH_P_IP);
	skb->pkt_type = PACKET_HOST;
	skb->dev = en_dev->netdev;

	return skb;
}

static s32 zxdh_test_loopback(struct zxdh_en_priv *en_priv)
{
	struct zxdh_en_device *en_dev = &en_priv->edev;
	struct zxdh_lbt_priv *lbtp = NULL;
	struct sk_buff *skb = NULL;
	s32 err = 0;

	if (!test_bit(ZXDH_DEVICE_STATE_OPENED, &en_dev->state)) {
		LOG_ERR("Can't perform loopback test while device is down\n");
		return -ENODEV;
	}

	lbtp = kzalloc(sizeof(*lbtp), GFP_KERNEL);
	if (!lbtp)
		return -ENOMEM;
	lbtp->loopback_ok = false;

	err = zxdh_test_loopback_setup(en_priv, lbtp);
	if (err != 0)
		goto out;

	skb = zxdh_test_get_udp_skb(en_priv);
	if (!skb) {
		err = -ENOMEM;
		goto cleanup;
	}

	skb_set_queue_mapping(skb, 0);
	err = dev_queue_xmit(skb);
	if (err) {
		LOG_ERR("Failed to xmit loopback packet err(%d)\n", err);
		goto cleanup;
	}

	wait_for_completion_timeout(&lbtp->comp, ZXDH_LB_VERIFY_TIMEOUT);
	err = !lbtp->loopback_ok;

cleanup:
	zxdh_test_loopback_cleanup(en_priv, lbtp);
out:
	kfree(lbtp);
	return err;
}
#endif /* CONFIG_INET */

static s32 (*zxdh_st_func[ZXDH_ST_NUM])(struct zxdh_en_priv *) = {
	zxdh_test_link_state,
	zxdh_test_link_speed,
	zxdh_test_health_info,
#ifdef CONFIG_INET
	zxdh_test_loopback,
#endif
};

s32 zxdh_en_self_test_num(void)
{
	return ARRAY_SIZE(zxdh_self_tests);
}

static void zxdh_en_diag_test(struct net_device *netdev, struct ethtool_test *etest, u64 *buf)
{
	struct zxdh_en_priv *en_priv = netdev_priv(netdev);
	s32 i = 0;

	if (en_priv->edev.device_state == ZXDH_DEVICE_STATE_INTERNAL_ERROR)
		return;

	memset(buf, 0, sizeof(u64) * ZXDH_ST_NUM);

	mutex_lock(&en_priv->lock);

	LOG_INFO("Self test begin...\n");

	for (i = 0; i < ZXDH_ST_NUM; i++) {
		LOG_INFO("[%d] %s start..\n", i, zxdh_self_tests[i]);
		buf[i] = zxdh_st_func[i](en_priv);
		LOG_INFO("[%d] %s end: result(%lld)\n", i, zxdh_self_tests[i], buf[i]);
	}

	mutex_unlock(&en_priv->lock);

	for (i = 0; i < ZXDH_ST_NUM; i++) {
		if (buf[i]) {
			etest->flags |= ETH_TEST_FL_FAILED;
			break;
		}
	}

	LOG_INFO("Self test out: status flags(0x%x)\n", etest->flags);
}

static s32 zxdh_hardware_bond_enable_proc(struct net_device *netdev, bool enable)
{
	struct zxdh_en_priv *en_priv = netdev_priv(netdev);
	struct zxdh_en_device *en_dev = &en_priv->edev;
	struct event_node *node, *tmp;

	if ((en_dev->ops->is_bond(en_dev->parent)) ||
	    (en_dev->ops->is_special_bond(en_dev->parent)) || (!zxdh_en_is_panel_port(en_dev)) ||
	    (en_dev->ops->get_coredev_type(en_dev->parent) == DH_COREDEV_VF))
		return 0;

	if (netif_is_lag_port(netdev)) {
		LOG_INFO("refuse to configure hardware_bond when netdev %s is bond slave\n",
			 netdev->name);
		return -EINVAL;
	}

	spin_lock(&(en_dev->hardware_bond->ctx.lock));
	list_for_each_entry_safe(node, tmp, &(en_dev->hardware_bond->ctx.event_list), list) {
		list_del(&node->list);
		LOG_INFO(
			"%s node %d addr %p del from list, event %ld linking %d link_up %d tx_enabled %d\n",
			netdev->name, node->idx, (void *)node, node->event, node->linking,
			node->link_up, node->tx_enabled);
		kfree(node);
	}
	spin_unlock(&(en_dev->hardware_bond->ctx.lock));

	en_dev->is_hwbond = enable;
	en_dev->ops->is_hwbond(en_dev->parent, en_dev->is_hwbond, TRUE);
	en_dev->ops->optim_hardware_bond_time(en_dev->parent, en_dev->is_hwbond);
	if (!en_dev->is_hwbond && en_dev->is_primary_port)
		zxdh_set_rdma_hwbond_speed(netdev, en_dev->speed);

	return en_dev->ops->update_hb_file_val(en_dev->parent, en_dev->spec_sbdf, "solid",
					       en_dev->is_hwbond);
}

static s32 zxdh_hardware_bond_primary_enable_proc(struct net_device *netdev, bool enable)
{
	struct zxdh_en_priv *en_priv = netdev_priv(netdev);
	struct zxdh_en_device *en_dev = &en_priv->edev;

	if (en_dev->ops->is_bond(en_dev->parent) ||
	    (en_dev->ops->is_special_bond(en_dev->parent)) ||
	    (en_dev->ops->get_coredev_type(en_dev->parent) == DH_COREDEV_VF) ||
	    (!zxdh_en_is_panel_port(en_dev)))
		return 0;

	if (netif_is_lag_port(netdev)) {
		LOG_INFO("refuse to configure hardware_bond_primary when netdev %s is bond slave\n",
			 netdev->name);
		return -EINVAL;
	}

	en_dev->is_primary_port = enable;
	en_dev->ops->is_primary_port(en_dev->parent, en_dev->is_primary_port, TRUE);
	en_dev->hardware_bond->primary = en_dev->is_primary_port;
	// ZXDH_PFLAG_HARDWARE_BOND_PRIMARY
	if (en_dev->ops->is_rdma_enable(en_dev->parent)) {
		if (en_dev->is_primary_port && !en_dev->is_rdma_aux_plug) {
			LOG_INFO("plug rdma auxiliary device\n");
			queue_work(en_priv->events->wq, &en_dev->plug_adev_work);
		} else if (!en_dev->is_primary_port && en_dev->is_rdma_aux_plug) {
			LOG_INFO("unplug rdma auxiliary device\n");
			queue_work(en_priv->events->wq, &en_dev->unplug_adev_work);
		}
	}

	return en_dev->ops->update_hb_file_val(en_dev->parent, en_dev->spec_sbdf, "primary",
					       en_dev->is_primary_port);
}

static s32 zxdh_lldp_enable_proc(struct net_device *netdev, bool enable)
{
	s32 ret = 0;
	struct zxdh_en_priv *en_priv = netdev_priv(netdev);

	ret = zxdh_lldp_enable_set(&en_priv->edev, enable);
	if (ret != 0) {
		LOG_ERR("%s lldp failed!\n", enable ? "enable" : "disable");
		return ret;
	}

	return ret;
}

static s32 zxdh_dual_tor_switch_proc(struct net_device *netdev, bool enable)
{
	s32 ret = 0;
	struct zxdh_en_priv *en_priv = netdev_priv(netdev);

	ret = zxdh_dual_tor_switch(&en_priv->edev, enable);
	if (ret != 0) {
		LOG_ERR("%s zxdh_dual_tor_switch failed!\n", enable ? "enable" : "disable");
		return ret;
	}

	return ret;
}

static s32 zxdh_sshd_enable_proc(struct net_device *netdev, bool enable)
{
	s32 ret = 0;
	struct zxdh_en_priv *en_priv = netdev_priv(netdev);

	ret = zxdh_sshd_enable_set(&en_priv->edev, enable);
	if (ret != 0) {
		LOG_ERR("%s riscv sshd failed!\n", enable ? "enable" : "disable");
		return ret;
	}

	ZXDH_SET_PFLAG(en_priv->edev.pflags, ZXDH_PFLAG_IP, enable);

	return ret;
}

static s32 zxdh_1588_debug_enable_proc(struct net_device *netdev, bool enable)
{
	enable_1588_debug = enable;
	return 0;
}

static s32 zxdh_1588_enable_proc(struct net_device *netdev, bool enable)
{
	union zxdh_msg *msg = NULL;
	struct zxdh_en_priv *en_priv = netdev_priv(netdev);
	struct zxdh_en_device *en_dev = &en_priv->edev;
	s32 ret = 0;
	struct zxdh_bar_extra_para para = { 0 };
	struct dpp_pf_info_t dpp_pf_info = {
		.slot = en_dev->slot_id,
		.vport = en_dev->vport,
	};

	para.is_sync = true;
	para.retrycnt = BAR_MSG_RETRY_CNT_MAX;
	if (en_dev->ops->get_coredev_type(en_dev->parent) != DH_COREDEV_PF) {
		msg = kzalloc(sizeof(union zxdh_msg), GFP_KERNEL);
		if (!msg) {
			LOG_ERR("kzalloc(%lu, GFP_KERNEL) failed !", sizeof(union zxdh_msg));
			return -ENOMEM;
		}

		msg->payload.vf_1588_enable.proc_cmd = ZXDH_VF_1588_ENABLE_SET;
		msg->payload.hdr.op_code = ZXDH_VF_1588_ENABLE;
		msg->payload.hdr.vport = en_dev->vport;
		msg->payload.hdr.pcie_id = en_dev->pcie_id;
		msg->payload.vf_1588_enable.enable_1588_vf = (u32)enable;
		ret = en_dev->ops->msg_send_cmd(en_dev->parent, MODULE_VF_BAR_MSG_TO_PF, msg, msg,
						&para);
		if (ret != 0) {
			LOG_ERR("zxdh_send_command_to_pf failed: %d\n", ret);
			kfree(msg);
			return ret;
		}

		kfree(msg);
		en_dev->enable_1588 = enable;
		return ret;
	}

	ret = dpp_vport_attr_set(&dpp_pf_info, SRIOV_VPORT_1588_EN, (u32)enable);
	if (ret != 0) {
		LOG_ERR("dpp_vport_attr_set SRIOV_VPORT_1588_EN failed, ret:%d\n", ret);
		return ret;
	}

	en_dev->enable_1588 = enable;
	return ret;
}

static s32 zxdh_link_down_on_close_proc(struct net_device *netdev, bool enable)
{
	struct zxdh_en_priv *en_priv = netdev_priv(netdev);
	s32 ret = 0;

	en_priv->edev.link_down_on_close = enable;

	return ret;
}

static s32 zxdh_ets_info_update(struct zxdh_en_priv *en_priv, u32 mode, u32 *cur_mode,
				u32 *tc_td_th)
{
	struct zxdh_en_device *en_dev = &en_priv->edev;
	s32 ret = 0;
	u32 ets_tc_td_th[ZXDH_DCBNL_MAX_TRAFFIC_CLASS] = { 0 };
	struct dpp_pf_info_t pf_info = { 0 };

	pf_info.slot = en_dev->slot_id;
	pf_info.vport = en_dev->vport;

	ret = zxdh_dcbnl_get_flow_td_th(en_priv, ets_tc_td_th);
	if (ret) {
		LOG_ERR("get td_th fail\n");
		return ret;
	}

	*cur_mode = en_dev->ets_info.cur_ets;
	if (!en_dev->ets_info.switch_flag) {
		memcpy(en_dev->ets_info.tc_td_th, ets_tc_td_th,
		       sizeof(u32) * ZXDH_DCBNL_MAX_TRAFFIC_CLASS);
	} else if (en_dev->ets_info.cur_ets) {
		memcpy(en_dev->ets_info.tc_td_th, ets_tc_td_th,
		       sizeof(u32) * ZXDH_DCBNL_MAX_TRAFFIC_CLASS);
		LOG_INFO("Updated PF ets_info: slot=%d, vport=0x%x, ets_mode=%u\n", pf_info.slot,
			 pf_info.vport, mode);
	}
	en_dev->ets_info.cur_ets = mode;
	en_dev->ets_info.switch_flag = 1;

	memcpy(tc_td_th, en_dev->ets_info.tc_td_th, sizeof(u32) * ZXDH_DCBNL_MAX_TRAFFIC_CLASS);

	return ret;
}

static s32 zxdh_ets_switch_proc(struct net_device *netdev, bool enable)
{
	s32 ret = 0;
	u32 mode = enable == true ? 1 : 0;
	u32 old_mode = 0;
	u32 tc_td_th[ZXDH_DCBNL_MAX_TRAFFIC_CLASS] = { 0 };
	struct zxdh_en_priv *en_priv = netdev_priv(netdev);

	ret = zxdh_dcbnl_enable_debug(en_priv);
	if (ret) {
		LOG_ERR("clean flow fail %s\n", netdev->name);
		return ret;
	}

	ret = zxdh_ets_info_update(en_priv, mode, &old_mode, tc_td_th);
	if (ret) {
		LOG_ERR("ets_info_update fail %s\n", netdev->name);
		return ret;
	}

	if ((old_mode ^ mode) && mode) {
		ret = zxdh_dcbnl_set_flow_td_th(en_priv, tc_td_th);
		LOG_INFO(
			"set_flow_td_th -> tc_td_th[0]:%d tc_td_th[1]:%d tc_td_th[2]:%d tc_td_th[3]:%d tc_td_th[4]:%d tc_td_th[5]:%d tc_td_th[6]:%d tc_td_th[7]:%d\n",
			tc_td_th[0], tc_td_th[1], tc_td_th[2], tc_td_th[3], tc_td_th[4],
			tc_td_th[5], tc_td_th[6], tc_td_th[7]);
		if (ret) {
			LOG_ERR("set td_th fail %s\n", netdev->name);
			return ret;
		}

		ret = zxdh_dcbnl_set_tm_gate(en_priv, mode);
		if (ret) {
			LOG_ERR("ets switch fail %s %u\n", netdev->name, mode);
			return ret;
		}
	}

	if ((old_mode ^ mode) && !mode) {
		ret = zxdh_dcbnl_set_tm_gate(en_priv, mode);
		if (ret) {
			LOG_ERR("ets switch fail %s %u\n", netdev->name, mode);
			return ret;
		}

		ret = zxdh_dcbnl_clear_flow_td_th(en_priv);
		if (ret) {
			LOG_ERR("clear td_th fail %s\n", netdev->name);
			return ret;
		}
	}

	ret = zxdh_dcbnl_disable_debug(en_priv);
	if (ret) {
		LOG_ERR("disable debug %s\n", netdev->name);
		return ret;
	}

	LOG_INFO("ets switch success %s %u\n", netdev->name, mode);
	return ret;
}

static s32 zxdh_pcie_rp_cpl_timeout(struct net_device *netdev, bool mask)
{
	struct zxdh_en_priv *en_priv = netdev_priv(netdev);
	struct zxdh_en_device *en_dev = &en_priv->edev;

	return en_dev->ops->set_cpl_timeout_mask(en_dev->parent, mask);
}

static s32 zxdh_pcie_rp_hp_irq_ctl(struct net_device *netdev, bool status)
{
	struct zxdh_en_priv *en_priv = netdev_priv(netdev);
	struct zxdh_en_device *en_dev = &en_priv->edev;

	return en_dev->ops->set_hp_irq_ctrl_status(en_dev->parent, status);
}

typedef s32 (*zxdh_pflag_handler)(struct net_device *netdev, bool enable);

struct flag_desc {
	u8 name[ETH_GSTRING_LEN];
	u32 bitno;
	zxdh_pflag_handler handler;
};

#define ZXDH_PRIV_DESC(_name, _bitno, _handler)                      \
	{                                                            \
		.name = _name, .bitno = _bitno, .handler = _handler, \
	}

static const struct flag_desc zxdh_gstrings_priv_flags[] = {
	ZXDH_PRIV_DESC("enable_lldp", ZXDH_PFLAG_ENABLE_LLDP, zxdh_lldp_enable_proc),
	ZXDH_PRIV_DESC("enable_sshd", ZXDH_PFLAG_ENABLE_SSHD, zxdh_sshd_enable_proc),
	ZXDH_PRIV_DESC("debug_ip", ZXDH_PFLAG_IP, NULL),
	ZXDH_PRIV_DESC("1588_debug", ZXDH_PFLAG_1588_DEBUG, zxdh_1588_debug_enable_proc),
	ZXDH_PRIV_DESC("hardware-bond", ZXDH_PFLAG_HARDWARE_BOND, zxdh_hardware_bond_enable_proc),
	ZXDH_PRIV_DESC("hardware-bond-primary", ZXDH_PFLAG_HARDWARE_BOND_PRIMARY,
		       zxdh_hardware_bond_primary_enable_proc),
	ZXDH_PRIV_DESC("link-down-on-close", ZXDH_PFLAG_LINK_DOWN_ON_CLOSE,
		       zxdh_link_down_on_close_proc),
	ZXDH_PRIV_DESC("ets-switch", ZXDH_PFLAG_ETS_SWITCH, zxdh_ets_switch_proc),
	ZXDH_PRIV_DESC("pcie_aer_cpl_timeout", ZXDH_PFLAG_PCIE_AER_CPL_TIMEOUT,
		       zxdh_pcie_rp_cpl_timeout),
	ZXDH_PRIV_DESC("pcie_rp_hp_irq_ctl", ZXDH_PFLAG_PCIE_HP_IRQ_CTRL, zxdh_pcie_rp_hp_irq_ctl),
	ZXDH_PRIV_DESC("dual_tor", ZXDH_PFLAG_DUAL_TOR_CTRL, zxdh_dual_tor_switch_proc),
	ZXDH_PRIV_DESC("1588_enable", ZXDH_PFLAG_1588_ENABLE, zxdh_1588_enable_proc),
};

#define ZXDH_PRIV_FALG_ARRAY_SIZE ARRAY_SIZE(zxdh_gstrings_priv_flags)

static void zxdh_en_get_strings(struct net_device *netdev, u32 stringset, u8 *data)
{
	struct zxdh_en_priv *en_priv = netdev_priv(netdev);
	struct zxdh_en_device *en_dev = &en_priv->edev;
	struct dh_core_dev *dh_dev = en_dev->parent;
	struct zxdh_pf_device *pf_dev = dh_core_priv(dh_dev->parent);
	u16 i = 0;
	int8_t ip[20] = { 0 };
	s32 ret = 0;

	switch (stringset) {
	case ETH_SS_STATS: {
		snprintf(data, ETH_GSTRING_LEN,
			 "rx_packets"); //get stat from netdev->stats
		ZXDH_ADD_STRING(data, "tx_packets");
		ZXDH_ADD_STRING(data, "rx_bytes");
		ZXDH_ADD_STRING(data, "tx_bytes");
		ZXDH_ADD_STRING(data, "tx_queue_wake");
		ZXDH_ADD_STRING(data, "tx_queue_stopped");
		ZXDH_ADD_STRING(data, "tx_queue_dropped");
		ZXDH_ADD_STRING(data,
				"rx_removed_vlan_packets"); //get stat from xmit-func
		ZXDH_ADD_STRING(data, "tx_added_vlan_packets");
		ZXDH_ADD_STRING(data, "rx_csum_offload_good");
		ZXDH_ADD_STRING(data, "rx_csum_offload_error");

		ZXDH_ADD_STRING(data, "rx_vport_packets"); //get stat from vqm
		ZXDH_ADD_STRING(data, "tx_vport_packets");
		ZXDH_ADD_STRING(data, "rx_vport_bytes");
		ZXDH_ADD_STRING(data, "tx_vport_bytes");
		ZXDH_ADD_STRING(data, "rx_vport_dropped");
		ZXDH_ADD_STRING(data,
				"rx_vport_unicast_packets"); //get stat from np
		ZXDH_ADD_STRING(data, "tx_vport_unicast_packets");
		ZXDH_ADD_STRING(data, "rx_vport_unicast_bytes");
		ZXDH_ADD_STRING(data, "tx_vport_unicast_bytes");
		ZXDH_ADD_STRING(data, "rx_vport_multicast_packets");
		ZXDH_ADD_STRING(data, "tx_vport_multicast_packets");
		ZXDH_ADD_STRING(data, "rx_vport_multicast_bytes");
		ZXDH_ADD_STRING(data, "tx_vport_multicast_bytes");
		ZXDH_ADD_STRING(data, "rx_vport_broadcast_packets");
		ZXDH_ADD_STRING(data, "tx_vport_broadcast_packets");
		ZXDH_ADD_STRING(data, "rx_vport_broadcast_bytes");
		ZXDH_ADD_STRING(data, "tx_vport_broadcast_bytes");
		ZXDH_ADD_STRING(data, "rx_vport_mtu_drop_packets");
		ZXDH_ADD_STRING(data, "tx_vport_mtu_drop_packets");
		ZXDH_ADD_STRING(data, "rx_vport_mtu_drop_bytes");
		ZXDH_ADD_STRING(data, "tx_vport_mtu_drop_bytes");
		ZXDH_ADD_STRING(data, "rx_vport_plcr_drop_packets");
		ZXDH_ADD_STRING(data, "tx_vport_plcr_drop_packets");
		ZXDH_ADD_STRING(data, "rx_vport_plcr_drop_bytes");
		ZXDH_ADD_STRING(data, "tx_vport_plcr_drop_bytes");
		ZXDH_ADD_STRING(data, "tx_vport_ssvpc_packets");
		ZXDH_ADD_STRING(data, "rx_vport_idma_drop_packets");
		ZXDH_ADD_STRING(data, "rx_lro_packets");
		ZXDH_ADD_STRING(data, "rx_udp_csum_fail_packets");
		ZXDH_ADD_STRING(data, "tx_udp_csum_fail_packets");
		ZXDH_ADD_STRING(data, "rx_tcp_csum_fail_packets");
		ZXDH_ADD_STRING(data, "tx_tcp_csum_fail_packets");
		ZXDH_ADD_STRING(data, "rx_ipv4_csum_fail_packets");
		ZXDH_ADD_STRING(data, "tx_ipv4_csum_fail_packets");

		ZXDH_ADD_STRING(data, "rx_packets_phy"); //get stat from mac
		ZXDH_ADD_STRING(data, "tx_packets_phy");
		ZXDH_ADD_STRING(data, "rx_bytes_phy");
		ZXDH_ADD_STRING(data, "tx_bytes_phy");
		ZXDH_ADD_STRING(data, "rx_error_phy");
		ZXDH_ADD_STRING(data, "tx_error_phy");
		ZXDH_ADD_STRING(data, "rx_drop_phy");
		ZXDH_ADD_STRING(data, "tx_drop_phy");
		ZXDH_ADD_STRING(data, "rx_good_bytes_phy");
		ZXDH_ADD_STRING(data, "tx_good_bytes_phy");
		ZXDH_ADD_STRING(data, "rx_unicast_phy");
		ZXDH_ADD_STRING(data, "tx_unicast_phy");
		ZXDH_ADD_STRING(data, "rx_multicast_phy");
		ZXDH_ADD_STRING(data, "tx_multicast_phy");
		ZXDH_ADD_STRING(data, "rx_broadcast_phy");
		ZXDH_ADD_STRING(data, "tx_broadcast_phy");
		ZXDH_ADD_STRING(data, "rx_under64_drop");
		ZXDH_ADD_STRING(data, "rx_undersize_phy");
		ZXDH_ADD_STRING(data, "rx_size_64_phy");
		ZXDH_ADD_STRING(data, "rx_size_65_127");
		ZXDH_ADD_STRING(data, "rx_size_128_255");
		ZXDH_ADD_STRING(data, "rx_size_256_511");
		ZXDH_ADD_STRING(data, "rx_size_512_1023");
		ZXDH_ADD_STRING(data, "rx_size_1024_1518");
		ZXDH_ADD_STRING(data, "rx_size_1519_mru");
		ZXDH_ADD_STRING(data, "rx_oversize_phy");
		ZXDH_ADD_STRING(data, "tx_undersize_phy");
		ZXDH_ADD_STRING(data, "tx_size_64_phy");
		ZXDH_ADD_STRING(data, "tx_size_65_127");
		ZXDH_ADD_STRING(data, "tx_size_128_255");
		ZXDH_ADD_STRING(data, "tx_size_256_511");
		ZXDH_ADD_STRING(data, "tx_size_512_1023");
		ZXDH_ADD_STRING(data, "tx_size_1024_1518");
		ZXDH_ADD_STRING(data, "tx_size_1519_mtu");
		ZXDH_ADD_STRING(data, "tx_oversize_phy");
		ZXDH_ADD_STRING(data, "rx_pause_phy");
		ZXDH_ADD_STRING(data, "tx_pause_phy");
		ZXDH_ADD_STRING(data, "rx_crc_errors");
		ZXDH_ADD_STRING(data, "tx_crc_errors");
		ZXDH_ADD_STRING(data, "rx_mac_control_phy");
		ZXDH_ADD_STRING(data, "tx_mac_control_phy");
		ZXDH_ADD_STRING(data, "rx_fragment_phy");
		ZXDH_ADD_STRING(data, "tx_fragment_phy");
		ZXDH_ADD_STRING(data, "rx_jabber_phy");
		ZXDH_ADD_STRING(data, "tx_jabber_phy");
		ZXDH_ADD_STRING(data, "rx_vlan_phy");
		ZXDH_ADD_STRING(data, "tx_vlan_phy");
		ZXDH_ADD_STRING(data, "rx_eee_phy");
		ZXDH_ADD_STRING(data, "tx_eee_phy");
		ZXDH_ADD_STRING(data, "rx_arn_phy");
		ZXDH_ADD_STRING(data, "tx_psn_phy");
		ZXDH_ADD_STRING(data, "rx_psn_phy");
		ZXDH_ADD_STRING(data, "tx_psn_ack_phy");
		ZXDH_ADD_STRING(data, "rx_psn_ack_phy");

		for (i = 0; i < en_dev->curr_queue_pairs; i++) {
			ZXDH_ADD_QUEUE_STRING(data, "rx_pkts", i);
			ZXDH_ADD_QUEUE_STRING(data, "tx_pkts", i);
			ZXDH_ADD_QUEUE_STRING(data, "rx_bytes", i);
			ZXDH_ADD_QUEUE_STRING(data, "tx_bytes", i);
			ZXDH_ADD_QUEUE_STRING(data, "tx_stopped", i);
			ZXDH_ADD_QUEUE_STRING(data, "tx_wake", i);
			ZXDH_ADD_QUEUE_STRING(data, "tx_dropped", i);
		}
		break;
	}
	case ETH_SS_PRIV_FLAGS: {
		u8 *p = data;

		for (i = 0; i < ZXDH_NUM_PFLAGS; i++)
			ethtool_puts(&p, zxdh_gstrings_priv_flags[i].name);

		if ((pf_dev->board_type == DH_STDA) || (pf_dev->board_type == DH_STDB) ||
		    (pf_dev->board_type == DH_STDC) || (pf_dev->board_type == DH_STD_E312S)) {
			LOG_INFO("zios not supported telnet\n");
			break;
		}

		ret = zxdh_debug_ip_get(en_dev, ip);
		if (ret != 0) {
			LOG_ERR("ip get failed");
			break;
		}
		ethtool_puts(&p, ip);
		break;
	}
	case ETH_SS_TEST:
		for (i = 0; i < zxdh_en_self_test_num(); i++)
			strscpy(data + i * ETH_GSTRING_LEN, zxdh_self_tests[i], ETH_GSTRING_LEN);
		break;
	default: {
		LOG_ERR("invalid para\n");
		break;
	}
	}
}

s32 zxdh_pflags_update(struct net_device *netdev, u8 flag, bool enable)
{
	if (!zxdh_gstrings_priv_flags[flag].handler)
		return 0;
	return zxdh_gstrings_priv_flags[flag].handler(netdev, enable);
}

static s32 zxdh_handle_pflag(struct net_device *netdev, u32 wanted_flags, enum zxdh_priv_flag flag)
{
	struct zxdh_en_priv *en_priv = netdev_priv(netdev);
	bool enable = !!(wanted_flags & BIT(flag));
	u32 changes = wanted_flags ^ en_priv->edev.pflags;
	s32 err = 0;

	if (!(changes & BIT(flag)))
		return 0;

	err = zxdh_pflags_update(netdev, flag, enable);
	if (err != 0) {
		LOG_ERR("%s private flag '%s' failed err %d\n", enable ? "Enable" : "Disable",
			zxdh_gstrings_priv_flags[flag].name, err);
		return err;
	}

	if (flag != ZXDH_PFLAG_IP)
		ZXDH_SET_PFLAG(en_priv->edev.pflags, flag, enable);

	return 0;
}

static s32 zxdh_en_set_priv_flags(struct net_device *netdev, u32 pflags)
{
	struct zxdh_en_priv *en_priv = netdev_priv(netdev);
	struct zxdh_en_device *en_dev = &en_priv->edev;
	enum zxdh_priv_flag pflag = 0;
	s32 err = 0;
	u32 changes = pflags ^ en_priv->edev.pflags;
	bool hardware_bond_change = changes & BIT(ZXDH_PFLAG_HARDWARE_BOND);
	bool hardware_bond_prima_change = changes & BIT(ZXDH_PFLAG_HARDWARE_BOND_PRIMARY);

	LOG_INFO("hardware_bond_change %d, hardware_bond_prima_change %d\n", hardware_bond_change,
		 hardware_bond_prima_change);
	if (!(hardware_bond_change || hardware_bond_prima_change)) {
		if (en_dev->device_state == ZXDH_DEVICE_STATE_INTERNAL_ERROR)
			return -ENXIO;
	}
	for (pflag = 0; pflag < ZXDH_NUM_PFLAGS; pflag++) {
		err = zxdh_handle_pflag(netdev, pflags, pflag);
		if (err != 0)
			break;
	}

	return err;
}

static void flag_enable_1588_get(struct zxdh_en_device *en_dev)
{
	s32 ret = 0;
	union zxdh_msg *msg = NULL;
	struct zxdh_sriov_vport_t port_attr_entry = { 0 };
	struct zxdh_bar_extra_para para = { 0 };
	struct dpp_pf_info_t dpp_pf_info = {
		.slot = en_dev->slot_id,
		.vport = en_dev->vport,
	};

	para.is_sync = true;
	para.retrycnt = BAR_MSG_RETRY_CNT_MAX;

	if (en_dev->ops->get_coredev_type(en_dev->parent) != DH_COREDEV_PF) {
		msg = kzalloc(sizeof(union zxdh_msg), GFP_KERNEL);
		if (!msg) {
			LOG_ERR("kzalloc(%lu, GFP_KERNEL) failed !", sizeof(union zxdh_msg));
			return;
		}

		msg->payload.vf_1588_enable.proc_cmd = ZXDH_VF_1588_ENABLE_GET;
		msg->payload.hdr.op_code = ZXDH_VF_1588_ENABLE;
		msg->payload.hdr.vport = en_dev->vport;
		msg->payload.hdr.pcie_id = en_dev->pcie_id;
		ret = en_dev->ops->msg_send_cmd(en_dev->parent, MODULE_VF_BAR_MSG_TO_PF, msg, msg,
						&para);
		if (ret != 0) {
			LOG_ERR("zxdh_send_command_to_pf failed: %d\n", ret);
			kfree(msg);
			return;
		}

		en_dev->enable_1588 = msg->reps.vf_1588_enable_rsp.enable_1588_vf_rsp;
		kfree(msg);
	} else {
		ret = dpp_vport_attr_get(&dpp_pf_info, &port_attr_entry);
		if (ret != 0) {
			LOG_ERR("dpp_vport_attr_get SRIOV_VPORT_1588_EN failed, ret:%d\n", ret);
			return;
		}

		en_dev->enable_1588 = port_attr_entry.flag_1588_enable;
	}

	if (en_dev->enable_1588 == 0)
		en_dev->pflags &= ~BIT(ZXDH_PFLAG_1588_ENABLE);
	else
		en_dev->pflags |= BIT(ZXDH_PFLAG_1588_ENABLE);
}
static u32 zxdh_en_get_priv_flags(struct net_device *netdev)
{
	struct zxdh_en_priv *en_priv = netdev_priv(netdev);
	struct zxdh_en_device *en_dev = &en_priv->edev;
	u32 flag_lldp = 0;
	u32 lldp_mask = 0;
	u32 cpl_timeout_mask = 0;
	u32 hp_irq_ctrl_status = 0;
	s32 ret = 0;

	ret = zxdh_lldp_enable_get(&en_priv->edev, &flag_lldp);
	if ((ret != 0) && (flag_lldp != 0) && (flag_lldp != 1))
		LOG_ERR("zxdh_lldp_enable_get err, ret(%d), flag_lldp(%u).\n", ret, flag_lldp);

	flag_lldp = flag_lldp << ZXDH_PFLAG_ENABLE_LLDP;

	lldp_mask = 0xFFFFFFFF ^ BIT(ZXDH_PFLAG_ENABLE_LLDP);
	en_priv->edev.pflags = (en_priv->edev.pflags & lldp_mask) | flag_lldp;

	if (en_dev->is_hwbond)
		en_priv->edev.pflags |= (1 << ZXDH_PFLAG_HARDWARE_BOND);
	else
		en_priv->edev.pflags &= ~(1 << ZXDH_PFLAG_HARDWARE_BOND);

	if (en_dev->is_primary_port)
		en_priv->edev.pflags |= (1 << ZXDH_PFLAG_HARDWARE_BOND_PRIMARY);
	else
		en_priv->edev.pflags &= ~(1 << ZXDH_PFLAG_HARDWARE_BOND_PRIMARY);

	cpl_timeout_mask = en_dev->ops->get_cpl_timeout_if_mask(en_dev->parent);
	LOG_DEBUG("cpl_timeout_mask: %d\n", cpl_timeout_mask);
	if (cpl_timeout_mask == 1)
		en_dev->pflags |= BIT(ZXDH_PFLAG_PCIE_AER_CPL_TIMEOUT);
	else
		en_dev->pflags &= ~BIT(ZXDH_PFLAG_PCIE_AER_CPL_TIMEOUT);

	hp_irq_ctrl_status = en_dev->ops->get_hp_irq_ctrl_status(en_dev->parent);
	LOG_DEBUG("hp_irq_ctrl_status: %d\n", hp_irq_ctrl_status);
	if (hp_irq_ctrl_status == 1)
		en_dev->pflags |= BIT(ZXDH_PFLAG_PCIE_HP_IRQ_CTRL);
	else
		en_dev->pflags &= ~BIT(ZXDH_PFLAG_PCIE_HP_IRQ_CTRL);

	ret = zxdh_dual_tor_label_get(en_dev);
	if (ret == 1)
		en_dev->pflags |= BIT(ZXDH_PFLAG_DUAL_TOR_CTRL);
	else if (!ret)
		en_dev->pflags &= ~BIT(ZXDH_PFLAG_DUAL_TOR_CTRL);

	flag_enable_1588_get(en_dev);

	return en_priv->edev.pflags;
}

static int zxdh_en_get_regs_len(struct net_device *netdev)
{
#define ZXDH_REGS_LEN (128 * 1024)
	return ZXDH_REGS_LEN * sizeof(u32);
}

static void zxdh_en_get_regs(struct net_device *netdev, struct ethtool_regs *regs, void *p)
{
}

static void zxdh_en_get_wol(struct net_device *netdev, struct ethtool_wolinfo *wol)
{
	struct zxdh_en_priv *en_priv = netdev_priv(netdev);
	struct zxdh_en_device *en_dev = &en_priv->edev;

	wol->supported = en_dev->wol_support;
	if (wol->supported == 0)
		return;
	wol->wolopts = en_dev->wolopts;
}

static int zxdh_en_set_wol(struct net_device *netdev, struct ethtool_wolinfo *wol)
{
	struct zxdh_en_priv *en_priv = netdev_priv(netdev);
	struct zxdh_en_device *en_dev = &en_priv->edev;
	struct dpp_pf_info_t pf_info = { 0 };

	pf_info.slot = en_dev->slot_id;
	pf_info.vport = en_dev->vport;

	if (en_dev->device_state == ZXDH_DEVICE_STATE_INTERNAL_ERROR)
		return -ENXIO;
	if ((en_dev->ops->get_coredev_type(en_dev->parent) != DH_COREDEV_PF) ||
	    !zxdh_en_is_panel_port(en_dev)) {
		return -EOPNOTSUPP;
	}

	LOG_INFO("wol mode=0x%x, en_dev->phy_port=0x%x\n", wol->wolopts, en_dev->phy_port);
	if (en_dev->ops->get_coredev_type(en_dev->parent) != DH_COREDEV_PF)
		return -EOPNOTSUPP;

	if (wol->wolopts & WAKE_MAGIC) {
		en_dev->wolopts = WAKE_MAGIC;
		dpp_uplink_phy_attr_set(&pf_info, en_dev->phy_port,
					UPLINK_PHY_PORT_MAGIC_PACKET_ENABLE, 1);
	} else if (wol->wolopts == 0) {
		en_dev->wolopts = 0;
		dpp_uplink_phy_attr_set(&pf_info, en_dev->phy_port,
					UPLINK_PHY_PORT_MAGIC_PACKET_ENABLE, 0);
	} else {
		return -EOPNOTSUPP;
	}

	return 0;
}

static u32 zxdh_en_get_msglevel(struct net_device *netdev)
{
	struct zxdh_en_priv *en_priv = netdev_priv(netdev);
	struct zxdh_en_device *en_dev = &en_priv->edev;

	return en_dev->msglevel;
}

static void zxdh_en_set_msglevel(struct net_device *netdev, u32 data)
{
	struct zxdh_en_priv *en_priv = netdev_priv(netdev);
	struct zxdh_en_device *en_dev = &en_priv->edev;

	en_dev->msglevel = data;
}

static int zxdh_en_nway_reset(struct net_device *netdev)
{
	return 0;
}

#ifdef HAVE_ETHTOOL_SET_PHYS_ID
static int zxdh_en_set_phys_id(struct net_device *netdev, enum ethtool_phys_id_state state)
{
	struct zxdh_en_priv *en_priv = netdev_priv(netdev);
	struct zxdh_en_device *en_dev = &en_priv->edev;
	int ret = 0;
	union zxdh_msg *msg = NULL;
	struct zxdh_bar_extra_para para = { 0 };

	para.is_sync = true;
	para.retrycnt = BAR_MSG_RETRY_CNT_MAX;

	if (en_dev->device_state == ZXDH_DEVICE_STATE_INTERNAL_ERROR)
		return -ENXIO;
	if (en_dev->phy_port == INVALID_PHY_PORT) {
		LOG_ERR("phyport is invalid!");
		return -EOPNOTSUPP;
	}

	msg = kzalloc(sizeof(union zxdh_msg), GFP_KERNEL);
	if (unlikely(!msg)) {
		LOG_ERR("failed to kzalloc\n");
		return -ENOMEM;
	}

	switch (state) {
	case ETHTOOL_ID_ACTIVE: {
		msg->payload.mac_set_msg.blink_enable = 1;
		break;
	}
	case ETHTOOL_ID_INACTIVE: {
		msg->payload.mac_set_msg.blink_enable = 0;
		break;
	}
	default: {
		kfree(msg);
		return -EOPNOTSUPP;
	}
	}
	msg->payload.hdr_to_agt.op_code = AGENT_MAC_LED_BLINK;
	msg->payload.hdr_to_agt.phyport = en_dev->phy_port;
	LOG_DEBUG("send phyport %d, blink_enable=%d\n", en_dev->phy_port,
		  msg->payload.mac_set_msg.blink_enable);
	ret = en_dev->ops->msg_send_cmd(en_dev->parent, MODULE_MAC, msg, msg, &para);
	if (ret != 0)
		LOG_ERR("zxdh_send_command_to_riscv_mac failed, err: %d\n", ret);

	kfree(msg);
	return ret;
}
#else
static int zxdh_en_phys_id(struct net_device *netdev, u32 data)
{
	return 0;
}
#endif /* HAVE_ETHTOOL_SET_PHYS_ID */

#ifdef HAVE_ETHTOOL_GET_SSET_COUNT
static s32 zxdh_en_get_sset_count(struct net_device *netdev, int sset)
{
	struct zxdh_en_priv *en_priv = netdev_priv(netdev);
	struct zxdh_en_device *en_dev = &en_priv->edev;

	switch (sset) {
	case ETH_SS_STATS: {
		return ZXDH_NET_PF_STATS_NUM(en_dev);
	}
	case ETH_SS_PRIV_FLAGS: {
		return ZXDH_NUM_PFLAGS;
	}
	case ETH_SS_TEST: {
		return zxdh_en_self_test_num();
	}
	default: {
		return -EOPNOTSUPP;
	}
	}

	return 0;
}
#endif

static void zxdh_en_get_drvinfo(struct net_device *netdev, struct ethtool_drvinfo *drvinfo)
{
	struct zxdh_en_priv *en_priv = netdev_priv(netdev);
	struct zxdh_en_device *en_dev = &en_priv->edev;
	s32 ret = 0;
	u8 drv_name_len = 0;
	u8 drv_version[MAX_DRV_VERSION_LEN] = { 0 };
	u8 drv_version_len = 0;
	u16 vport = 0;

	ret = en_dev->ops->get_pf_drv_msg(en_dev->parent, drv_version, &drv_version_len);
	if (drv_version_len > MAX_DRV_NAME_LEN) {
		LOG_ERR("drv_version_len(%hhu) greater than %u", drv_version_len, MAX_DRV_NAME_LEN);
		drv_version_len = MAX_DRV_NAME_LEN;
	}

	vport = en_dev->vport;
	drv_name_len = strlen(DRV_NAME);

	if (drv_name_len > MAX_DRV_NAME_LEN) {
		LOG_ERR("drv_name_len(%hhu) greater than %u", drv_name_len, MAX_DRV_NAME_LEN);
		drv_name_len = MAX_DRV_NAME_LEN;
	}

	memcpy(drvinfo->driver, DRV_NAME, drv_name_len);
	memcpy(drvinfo->version, drv_version, drv_version_len);

	strscpy(drvinfo->bus_info, dev_name(en_dev->parent->parent->device),
		sizeof(drvinfo->bus_info));

	drvinfo->n_priv_flags = ZXDH_NUM_PFLAGS;
	drvinfo->n_stats = ZXDH_NET_PF_STATS_NUM(en_dev);
	drvinfo->eedump_len = zxdh_en_get_eeprom_len(netdev);
	drvinfo->regdump_len = zxdh_en_get_regs_len(netdev);
	drvinfo->testinfo_len = zxdh_en_self_test_num();

	memcpy(drvinfo->fw_version, en_dev->fw_version, en_dev->fw_version_len);
}

s32 zxdh_stats_update(struct zxdh_en_device *en_dev)
{
	u16 i = 0;
	s32 ret = 0;

	ret = zxdh_vport_stats_get(en_dev);
	if (ret != 0) {
		LOG_ERR("zxdh_vport_stats_get failed, ret: %d\n", ret);
		return -1;
	}

	ret = zxdh_mac_stats_get(en_dev);
	if (ret != 0) {
		LOG_ERR("zxdh_mac_stats_get failed, ret: %d\n", ret);
		return -1;
	}

	ret = zxdh_en_udp_pkt_stats_get(en_dev);
	if (ret != 0) {
		LOG_ERR("zxdh_en_udp_pkt_stats_get failed, ret: %d\n", ret);
		return -1;
	}

	en_dev->hw_stats.netdev_stats.rx_packets = 0;
	en_dev->hw_stats.netdev_stats.tx_packets = 0;
	en_dev->hw_stats.netdev_stats.rx_bytes = 0;
	en_dev->hw_stats.netdev_stats.tx_bytes = 0;
	en_dev->hw_stats.netdev_stats.tx_queue_wake = 0;
	en_dev->hw_stats.netdev_stats.tx_queue_stopped = 0;
	en_dev->hw_stats.netdev_stats.tx_queue_dropped = 0;
	en_dev->hw_stats.netdev_stats.rx_csum_offload_good = 0;
	en_dev->hw_stats.netdev_stats.rx_removed_vlan_packets = 0;
	for (i = 0; i < en_dev->curr_queue_pairs; i++) {
		/* queue software statistics */
		en_dev->hw_stats.q_stats[i].q_rx_pkts = en_dev->rq[i].stats.packets;
		en_dev->hw_stats.q_stats[i].q_tx_pkts = en_dev->sq[i].stats.packets;
		en_dev->hw_stats.q_stats[i].q_rx_bytes = en_dev->rq[i].stats.bytes;
		en_dev->hw_stats.q_stats[i].q_tx_bytes = en_dev->sq[i].stats.bytes;

		en_dev->hw_stats.netdev_stats.rx_packets += en_dev->rq[i].stats.packets;
		en_dev->hw_stats.netdev_stats.tx_packets += en_dev->sq[i].stats.packets;
		en_dev->hw_stats.netdev_stats.rx_bytes += en_dev->rq[i].stats.bytes;
		en_dev->hw_stats.netdev_stats.tx_bytes += en_dev->sq[i].stats.bytes;
		en_dev->hw_stats.netdev_stats.rx_csum_offload_good +=
			en_dev->rq[i].stats.rx_csum_offload_good;
		en_dev->hw_stats.netdev_stats.rx_removed_vlan_packets +=
			en_dev->rq[i].stats.rx_removed_vlan_packets;
		en_dev->hw_stats.netdev_stats.tx_queue_wake +=
			en_dev->hw_stats.q_stats[i].q_tx_wake;
		en_dev->hw_stats.netdev_stats.tx_queue_stopped +=
			en_dev->hw_stats.q_stats[i].q_tx_stopped;
		en_dev->hw_stats.netdev_stats.tx_queue_dropped +=
			en_dev->hw_stats.q_stats[i].q_tx_dropped;
	}

	return ret;
}

static void zxdh_en_get_ethtool_stats(struct net_device *netdev, struct ethtool_stats *stats,
				      u64 *data)
{
	struct zxdh_en_priv *en_priv = netdev_priv(netdev);
	struct zxdh_en_device *en_dev = &en_priv->edev;
	u32 offset = ZXDH_NETDEV_STATS_NUM + ZXDH_MAC_STATS_NUM + ZXDH_VPORT_STATS_NUM +
		     ZXDH_UDP_STATS_NUM;

	if (en_dev->device_state == ZXDH_DEVICE_STATE_INTERNAL_ERROR)
		return;

	zxdh_stats_update(en_dev);
	memcpy(data, &en_dev->hw_stats, ZXDH_NET_PF_STATS_NUM(en_dev) * sizeof(u64));
	memcpy(data + offset, en_dev->hw_stats.q_stats,
	       (en_dev->curr_queue_pairs * ZXDH_QUEUE_STATS_NUM) * sizeof(u64));
}

static int zxdh_en_get_ts_info(struct net_device *netdev, struct ethtool_ts_info *info)
{
	struct zxdh_en_priv *en_priv = NULL;
	struct zxdh_en_device *en_dev = NULL;
	s32 ret = 0;
	u32 ptp_clock_index;

	CHECK_EQUAL_ERR(netdev, NULL, -EADDRNOTAVAIL, "netdev is null!\n");

	en_priv = netdev_priv(netdev);
	CHECK_EQUAL_ERR(en_priv, NULL, -EADDRNOTAVAIL, "netdev priv is null!\n");
	en_dev = &en_priv->edev;
	if (en_dev->device_state == ZXDH_DEVICE_STATE_INTERNAL_ERROR)
		return -ENXIO;

	if (en_dev->ops->get_coredev_type(en_dev->parent) != DH_COREDEV_PF)
		return 0;
	ret = zxdh_get_ptp_clock_index(en_dev, &ptp_clock_index);
	if (ret != 0)
		return 0;

	info->so_timestamping = SOF_TIMESTAMPING_TX_HARDWARE | SOF_TIMESTAMPING_RX_HARDWARE |
				SOF_TIMESTAMPING_RAW_HARDWARE;

	info->phc_index = ptp_clock_index;

	info->tx_types = (1 << HWTSTAMP_TX_OFF) | (1 << HWTSTAMP_TX_ON);

	info->rx_filters = (1 << HWTSTAMP_FILTER_NONE) | (1 << HWTSTAMP_FILTER_ALL);
	return 0;
}

#ifdef CONFIG_PM_RUNTIME
static int zxdh_en_ethtool_begin(struct net_device *netdev)
{
	return 0;
}

static void zxdh_en_ethtool_complete(struct net_device *netdev)
{
}
#endif

#ifndef HAVE_NDO_SET_FEATURES
static int zxdh_en_get_rx_csum(struct net_device *netdev)
{
	return 0;
}

static int zxdh_en_set_rx_csum(struct net_device *netdev, u32 data)
{
	return 0;
}

static int zxdh_en_set_tx_csum(struct net_device *netdev, u32 data)
{
	return 0;
}

#ifdef NETIF_F_TSO
static int zxdh_en_set_tso(struct net_device *netdev, u32 data)
{
	return 0;
}
#endif /* NETIF_F_TSO */

#ifdef ETHTOOL_GFLAGS
static int zxdh_en_set_flags(struct net_device *netdev, u32 data)
{
	return 0;
}
#endif /* ETHTOOL_GFLAGS */
#endif /* HAVE_NDO_SET_FEATURES */

static int zxdh_en_get_eee(struct net_device *netdev, struct ethtool_eee *edata)
{
	return 0;
}

static int zxdh_en_set_eee(struct net_device *netdev, struct ethtool_eee *edata)
{
	return 0;
}
#ifdef ETHTOOL_GRXFHINDIR
#ifdef HAVE_ETHTOOL_GRXFHINDIR_SIZE
static u32 zxdh_en_get_rxfh_indir_size(struct net_device *netdev)
{
	return ZXDH_INDIR_RQT_SIZE;
}

static u32 zxdh_en_get_rxfh_key_size(struct net_device *netdev)
{
	return ZXDH_NET_HASH_KEY_SIZE;
}

int zxdh_en_hash_key_get(struct zxdh_en_device *en_dev, u8 *key)
{
	union zxdh_msg *msg = NULL;
	s32 ret = 0;
	struct dpp_pf_info_t pf_info = { 0 };
	struct zxdh_bar_extra_para para = { 0 };

	para.is_sync = true;
	para.retrycnt = BAR_MSG_RETRY_CNT_MAX;

	msg = kzalloc(sizeof(union zxdh_msg), GFP_KERNEL);
	if (!msg) {
		LOG_ERR("malloc(%lu) failed !", sizeof(union zxdh_msg));
		return -ENOMEM;
	}

	if (en_dev->ops->get_coredev_type(en_dev->parent) == DH_COREDEV_PF) {
		pf_info.slot = en_dev->slot_id;
		pf_info.vport = en_dev->vport;
		ret = dpp_thash_key_get(&pf_info, key, ZXDH_NET_HASH_KEY_SIZE);
	} else {
		msg->payload.hdr.op_code = ZXDH_THASH_KEY_GET;
		msg->payload.hdr.vport = en_dev->vport;
		msg->payload.hdr.pcie_id = en_dev->pcie_id;
		ret = en_dev->ops->msg_send_cmd(en_dev->parent, MODULE_VF_BAR_MSG_TO_PF, msg, msg,
						&para);
		if (!ret)
			zte_memcpy_s(key, msg->reps.thash_key_set_msg.key_map,
				     ZXDH_NET_HASH_KEY_SIZE);
	}

	if (ret != 0)
		LOG_ERR("get hash key failed !\n");

	kfree(msg);
	return ret;
}

#if (defined(ETHTOOL_GRSSH) && !defined(HAVE_ETHTOOL_GSRSSH))
#ifdef HAVE_RXFH_HASHFUNC
static int zxdh_en_get_rxfh(struct net_device *netdev, u32 *indir, u8 *key, u8 *hfunc)
#else
static int zxdh_en_get_rxfh(struct net_device *netdev, u32 *indir, u8 *key)
#endif /* HAVE_RXFH_HASHFUNC */
#else
static int zxdh_en_get_rxfh_indir(struct net_device *netdev, u32 *indir)
#endif /* HAVE_ETHTOOL_GSRSSH */
{
	struct zxdh_en_priv *en_priv = netdev_priv(netdev);
	struct zxdh_en_device *en_dev = &en_priv->edev;
	s32 ret = 0;
	u8 func = 0;

	LOG_DEBUG("zxdh_en_get_rxfh start\n");
	if (en_dev->device_state == ZXDH_DEVICE_STATE_INTERNAL_ERROR)
		return -ENXIO;

	if (indir)
		memcpy(indir, en_dev->indir_rqt, sizeof(u32) * ZXDH_INDIR_RQT_SIZE);

	if (key) {
		LOG_DEBUG("get key is called\n");
		ret = zxdh_en_hash_key_get(en_dev, key);
		if (ret)
			return -EOPNOTSUPP;
	}

	if (hfunc) {
		func = en_dev->eth_config.hash_func;
		switch (func) {
		case ZXDH_FUNC_TOP: {
			*hfunc = ETH_RSS_HASH_TOP;
			break;
		}
		case ZXDH_FUNC_XOR: {
			*hfunc = ETH_RSS_HASH_XOR;
			break;
		}
		case ZXDH_FUNC_CRC32: {
			*hfunc = ETH_RSS_HASH_CRC32;
			break;
		}
		default: {
			return -EOPNOTSUPP;
		}
		}
	}

	return 0;
}
#else
static int zxdh_en_get_rxfh_indir(struct net_device *netdev, struct ethtool_rxfh_indir *indir)
{
	return 0;
}
#endif /* HAVE_ETHTOOL_GRXFHINDIR_SIZE */
#endif /* ETHTOOL_GRXFHINDIR */

s32 zxdh_indir_to_queue_map(struct zxdh_en_device *en_dev, const u32 *indir)
{
	u32 *queue_map = NULL;
	s32 err = 0;
	u16 i = 0;
	u16 j = 0;

	queue_map = kcalloc(ZXDH_INDIR_RQT_SIZE, sizeof(u32), GFP_KERNEL);
	if (!queue_map) {
		LOG_ERR("queue_map is NULL\n");
		return -ENOMEM;
	}
	for (i = 0; i < ZXDH_INDIR_RQT_SIZE; i++) {
		j = indir[i];
		queue_map[i] = en_dev->phy_index[2 * j];
	}

	memcpy(en_dev->eth_config.queue_map, queue_map, ZXDH_INDIR_RQT_SIZE * sizeof(u32));

	kfree(queue_map);
	return err;
}

int zxdh_en_hash_func_set(struct zxdh_en_device *en_dev, u8 func)
{
	union zxdh_msg *msg = NULL;
	s32 ret = 0;
	struct dpp_pf_info_t pf_info = { 0 };
	struct zxdh_bar_extra_para para = { 0 };

	para.is_sync = true;
	para.retrycnt = BAR_MSG_RETRY_CNT_MAX;

	msg = kzalloc(sizeof(union zxdh_msg), GFP_KERNEL);
	if (!msg) {
		LOG_ERR("malloc(%lu) failed !", sizeof(union zxdh_msg));
		return -ENOMEM;
	}

	if (en_dev->ops->get_coredev_type(en_dev->parent) == DH_COREDEV_PF) {
		pf_info.slot = en_dev->slot_id;
		pf_info.vport = en_dev->vport;
		ret = dpp_vport_hash_funcs_set(&pf_info, func);
	} else {
		msg->payload.hdr.op_code = ZXDH_HASH_FUNC_SET;
		msg->payload.hdr.vport = en_dev->vport;
		msg->payload.hdr.pcie_id = en_dev->pcie_id;
		msg->payload.hfunc_set_msg.func = func;
		ret = en_dev->ops->msg_send_cmd(en_dev->parent, MODULE_VF_BAR_MSG_TO_PF, msg, msg,
						&para);
	}

	if (!ret)
		en_dev->eth_config.hash_func = func;

	kfree(msg);
	return ret;
}

static int zxdh_en_hash_key_set(struct zxdh_en_device *en_dev, u8 *key)
{
	union zxdh_msg *msg = NULL;
	s32 ret = 0;
	struct dpp_pf_info_t pf_info = { 0 };
	struct zxdh_bar_extra_para para = { 0 };

	para.is_sync = true;
	para.retrycnt = BAR_MSG_RETRY_CNT_MAX;

	msg = kzalloc(sizeof(union zxdh_msg), GFP_KERNEL);
	if (!msg) {
		LOG_ERR("malloc(%lu) failed !", sizeof(union zxdh_msg));
		return -ENOMEM;
	}

	if (en_dev->ops->get_coredev_type(en_dev->parent) == DH_COREDEV_PF) {
		pf_info.slot = en_dev->slot_id;
		pf_info.vport = en_dev->vport;
		ret = dpp_thash_key_set(&pf_info, key, ZXDH_NET_HASH_KEY_SIZE);
	} else {
		msg->payload.hdr.op_code = ZXDH_THASH_KEY_SET;
		msg->payload.hdr.vport = en_dev->vport;
		msg->payload.hdr.pcie_id = en_dev->pcie_id;
		zte_memcpy_s(msg->payload.thash_key_set_msg.key_map, key, ZXDH_NET_HASH_KEY_SIZE);
		ret = en_dev->ops->msg_send_cmd(en_dev->parent, MODULE_VF_BAR_MSG_TO_PF, msg, msg,
						&para);
	}

	kfree(msg);
	return ret;
}

s32 zxdh_en_hash_key_recover(struct zxdh_en_device *en_dev)
{
	u8 key[ZXDH_NET_HASH_KEY_SIZE] = { 0 };
	s32 err = 0;

	err = zxdh_en_hash_key_get(en_dev, key);
	ZXDH_CHECK_RET_RETURN(err, "zxdh_en_hash_key_get failed: %d\n", err);

	err = zxdh_en_hash_key_set(en_dev, key);
	ZXDH_CHECK_RET_RETURN(err, "zxdh_en_hash_key_set failed: %d\n", err);

	return err;
}

#ifdef HAVE_ETHTOOL_GRXFHINDIR_SIZE
#if (defined(ETHTOOL_GRSSH) && !defined(HAVE_ETHTOOL_GSRSSH))
#ifdef HAVE_RXFH_HASHFUNC
static int zxdh_en_set_rxfh(struct net_device *netdev, const u32 *indir, const u8 *key,
			    const u8 hfunc)
#else
static int zxdh_en_set_rxfh(struct net_device *netdev, const u32 *indir, const u8 *key)
#endif /* HAVE_RXFH_HASHFUNC */
#else
static int zxdh_en_set_rxfh_indir(struct net_device *netdev, const u32 *indir)
#endif /* HAVE_ETHTOOL_GSRSSH */
{
	struct zxdh_en_priv *en_priv = netdev_priv(netdev);
	struct zxdh_en_device *en_dev = &en_priv->edev;
	s32 ret = 0;
	u8 func = 0;

	LOG_DEBUG("zxdh_en_set_rxfh_indir start\n");
	if (en_dev->device_state == ZXDH_DEVICE_STATE_INTERNAL_ERROR)
		return -ENXIO;

	switch (hfunc) {
	case ETH_RSS_HASH_NO_CHANGE: {
		break;
	}
	case ETH_RSS_HASH_TOP: {
		func = ZXDH_FUNC_TOP;
		break;
	}
	case ETH_RSS_HASH_XOR: {
		func = ZXDH_FUNC_XOR;
		break;
	}
	case ETH_RSS_HASH_CRC32: {
		func = ZXDH_FUNC_CRC32;
		break;
	}
	default: {
		return -EOPNOTSUPP;
	}
	}

	if ((hfunc != ETH_RSS_HASH_NO_CHANGE) && (func != en_dev->eth_config.hash_func)) {
		LOG_DEBUG("func: %u\n", func);
		ret = zxdh_en_hash_func_set(en_dev, func);
		if (ret != 0) {
			LOG_ERR("hunc set failed: %d", ret);
			return -EOPNOTSUPP;
		}
	}

	if (indir) {
		LOG_DEBUG("set indir is called\n");
		ret = zxdh_indir_to_queue_map(en_dev, indir);
		if (ret != 0) {
			LOG_ERR("indir set failed: %d", ret);
			return -EOPNOTSUPP;
		}

		memcpy(en_dev->indir_rqt, indir, ZXDH_INDIR_RQT_SIZE * sizeof(u32));
		ret = zxdh_rxfh_set(en_dev, en_dev->eth_config.queue_map);
		if (ret != 0) {
			LOG_ERR("zxdh_rxfh_set failed: %d\n", ret);
			return -EOPNOTSUPP;
		}
	}

	if (key) {
		LOG_DEBUG("set thash key is called\n");
		ret = zxdh_en_hash_key_set(en_dev, (u8 *)key);
	}

	return ret;
}
#else
static int zxdh_en_set_rxfh_indir(struct net_device *netdev, struct ethtool_cmd *ecmd)
{
	return 0;
}
#endif
#ifdef ETHTOOL_GCHANNELS
static void zxdh_en_get_channels(struct net_device *netdev, struct ethtool_channels *ch)
{
	struct zxdh_en_priv *en_priv = netdev_priv(netdev);
	struct zxdh_en_device *en_dev = &en_priv->edev;
	union zxdh_msg *msg = NULL;
	s32 err = 0;
	struct dpp_pf_info_t pf_info = { 0 };
	struct zxdh_bar_extra_para para = { 0 };

	para.is_sync = true;
	para.retrycnt = BAR_MSG_RETRY_CNT_MAX;

	ch->max_combined = en_dev->max_vq_pairs;
	ch->combined_count = en_dev->curr_queue_pairs;

	if (en_dev->device_state == ZXDH_DEVICE_STATE_INTERNAL_ERROR)
		return;

	if (en_dev->ops->is_bond(en_dev->parent))
		return;

	msg = kzalloc(sizeof(union zxdh_msg), GFP_KERNEL);
	if (!msg) {
		LOG_ERR("kzalloc(%lu, GFP_KERNEL) failed !", sizeof(union zxdh_msg));
		return;
	}
	if (en_dev->ops->get_coredev_type(en_dev->parent) == DH_COREDEV_PF) {
		pf_info.slot = en_dev->slot_id;
		pf_info.vport = en_dev->vport;
		err = dpp_rxfh_get(&pf_info, msg->payload.rxfh_set_msg.queue_map,
				   ZXDH_INDIR_RQT_SIZE);
		if (err != 0) {
			LOG_ERR("dpp_rxfh_get failed: %d\n", err);
			goto free_msg;
		}

		LOG_DEBUG("*******pf_queue_map*******\n");
		zxdh_u32_array_print(msg->payload.rxfh_set_msg.queue_map, ZXDH_INDIR_RQT_SIZE);
	} else {
		msg->payload.hdr.op_code = ZXDH_RXFH_GET;
		msg->payload.hdr.vport = en_dev->vport;
		msg->payload.hdr.pcie_id = en_dev->pcie_id;
		err = en_dev->ops->msg_send_cmd(en_dev->parent, MODULE_VF_BAR_MSG_TO_PF, msg, msg,
						&para);
		if (err != 0) {
			LOG_ERR("dpp_rxfh_get failed: %d\n", err);
			goto free_msg;
		}

		LOG_DEBUG("*******vf_queue_map*******\n");
		zxdh_u32_array_print(msg->reps.rxfh_get_msg.queue_map, ZXDH_INDIR_RQT_SIZE);
	}
free_msg:
	kfree(msg);
}
#endif /* ETHTOOL_GCHANNELS */

s32 zxdh_num_channels_changed(struct zxdh_en_device *en_dev, u16 num_changed)
{
	u32 *indir = NULL;
	s32 err = 0;
	u16 i = 0;

	if (num_changed == 0) {
		LOG_ERR("num_changed cannot be zero\n");
		return -1;
	}

	indir = kzalloc(sizeof(u32) * ZXDH_INDIR_RQT_SIZE, GFP_KERNEL);
	if (unlikely(!indir)) {
		LOG_ERR("failed to kzalloc\n");
		return -ENOMEM;
	}

	if (!netif_is_rxfh_configured(en_dev->netdev)) {
		LOG_DEBUG("indir_is_default\n");
		for (i = 0; i < ZXDH_INDIR_RQT_SIZE; ++i)
			indir[i] = i % num_changed;

		err = zxdh_indir_to_queue_map(en_dev, indir);
		if (err != 0) {
			LOG_ERR("zxdh_indir_to_queue_map failed: %d\n", err);
			kfree(indir);
			return err;
		}

		zte_memcpy_s(en_dev->indir_rqt, indir, ZXDH_INDIR_RQT_SIZE * sizeof(u32));
		err = zxdh_rxfh_set(en_dev, en_dev->eth_config.queue_map);
		if (err != 0) {
			LOG_ERR("zxdh_rxfh_set failed: %d\n", err);
			kfree(indir);
			return -EOPNOTSUPP;
		}
	}

	en_dev->old_queue_pairs = en_dev->curr_queue_pairs;
	en_dev->curr_queue_pairs = num_changed;
	LOG_INFO("old_queue_pairs: %d, curr_queue_pairs: %d\n", en_dev->old_queue_pairs,
		 en_dev->curr_queue_pairs);
	kfree(indir);

	return set_feature_rxhash(en_dev, en_dev->curr_queue_pairs != 1 ? true : false);
}

#ifdef ETHTOOL_SCHANNELS
static int zxdh_en_set_channels(struct net_device *netdev, struct ethtool_channels *ch)
{
	struct zxdh_en_priv *en_priv = netdev_priv(netdev);
	struct zxdh_en_device *en_dev = &en_priv->edev;
	s32 ret = 0;

	LOG_DEBUG("zxdh en_set_channels start\n");
	if (en_dev->device_state == ZXDH_DEVICE_STATE_INTERNAL_ERROR)
		return -ENXIO;

	if (ch->rx_count || ch->tx_count || ch->other_count) {
		LOG_ERR("not supported\n");
		return -EINVAL;
	}

	if ((ch->combined_count > en_dev->max_vq_pairs) || (ch->combined_count == 0)) {
		LOG_ERR("invalid para\n");
		return -EINVAL;
	}

	if (en_dev->xdp_enabled) {
		LOG_ERR("XDP is enabled, not support set channels\n");
		return -EOPNOTSUPP;
	}

	if (ch->combined_count == en_dev->curr_queue_pairs)
		return 0;

	ret = zxdh_num_channels_changed(en_dev, ch->combined_count);
	if (ret != 0) {
		LOG_ERR("zxdh_num_channels_changed failed: %d\n", ret);
		return -1;
	}

	en_dev->eth_config.curr_combined = en_dev->curr_queue_pairs;
	zxdh_set_default_xps_cpumasks(en_dev);
	netif_set_real_num_tx_queues(netdev, en_dev->curr_queue_pairs);
	netif_set_real_num_rx_queues(netdev, en_dev->curr_queue_pairs);

	zxdh_flow_map_update_sysfs(netdev);

	return 0;
}
#endif

static s32 zxdh_get_rss_hash(struct ethtool_rxnfc *cmd, struct zxdh_en_device *en_dev)
{
	union zxdh_msg *msg = NULL;
	u32 hash_mode = 0;
	s32 ret = 0;
	struct dpp_pf_info_t pf_info = { 0 };

	struct zxdh_bar_extra_para para = { 0 };

	para.is_sync = true;
	para.retrycnt = BAR_MSG_RETRY_CNT_MAX;

	if (en_dev->device_state == ZXDH_DEVICE_STATE_INTERNAL_ERROR)
		return -ENXIO;
	pf_info.slot = en_dev->slot_id;
	pf_info.vport = en_dev->vport;

	msg = kzalloc(sizeof(union zxdh_msg), GFP_KERNEL);
	if (!msg) {
		LOG_ERR("failed to kzalloc\n");
		return -ENOMEM;
	}

	if (en_dev->ops->get_coredev_type(en_dev->parent) == DH_COREDEV_PF) {
		ret = dpp_vport_rx_flow_hash_get(&pf_info, &hash_mode);
	} else {
		msg->payload.hdr.op_code = ZXDH_RX_FLOW_HASH_GET;
		msg->payload.hdr.vport = en_dev->vport;
		msg->payload.hdr.pcie_id = en_dev->pcie_id;
		ret = en_dev->ops->msg_send_cmd(en_dev->parent, MODULE_VF_BAR_MSG_TO_PF, msg, msg,
						&para);
		hash_mode = msg->reps.rx_flow_hash_set_msg.hash_mode;
	}
	if (ret != 0) {
		kfree(msg);
		return ret;
	}

	LOG_INFO("hash_mode: %u\n", hash_mode);
	switch (hash_mode) {
	case ZXDH_NET_RX_FLOW_HASH_MV: {
		cmd->data = RXH_L2DA + RXH_VLAN;
		break;
	}
	case ZXDH_NET_RX_FLOW_HASH_SDT: {
		cmd->data = RXH_L3_PROTO + RXH_IP_SRC + RXH_IP_DST;
		break;
	}
	case ZXDH_NET_RX_FLOW_HASH_SDFNT: {
		cmd->data = RXH_L3_PROTO + RXH_IP_SRC + RXH_IP_DST + RXH_L4_B_0_1 + RXH_L4_B_2_3;
		break;
	}
	default: {
		LOG_ERR("invalid hash_mode\n");
		kfree(msg);
		return -1;
	}
	}
	kfree(msg);
	return 0;
}

static s32 zxdh_ethtool_get_flow(struct zxdh_en_device *en_dev, struct ethtool_rxnfc *info,
				 s32 location)
{
	struct zxdh_fd_cfg_t p_fd_cfg = { 0 };
	struct dpp_pf_info_t pf_info = { 0 };
	s32 err = 0;

	pf_info.slot = en_dev->slot_id;
	pf_info.vport = en_dev->vport;

	if (location < 0 || location >= ETHTOOL_FD_MAX_NUM)
		return -EINVAL;

	if (!en_dev->fs.ethtool_fs[location].is_used)
		return -ENOENT;

	zte_memcpy_s(&info->fs, &en_dev->fs.ethtool_fs[location].rfs,
		     sizeof(struct ethtool_rx_flow_spec));

	if (en_dev->ops->get_coredev_type(en_dev->parent) == DH_COREDEV_PF) {
		err = dpp_tbl_fd_cfg_get(&pf_info, ZXDH_SDT_FD_CFG_TABLE,
					 en_dev->fs.ethtool_fs[location].index, &p_fd_cfg);
		if (err != 0) {
			LOG_ERR("pf can't find fd_cfg %d\n", location);
			return -ENOENT;
		}
	} else {
		err = zxdh_vf_get_fd(en_dev, en_dev->fs.ethtool_fs[location].index);
		if (err != 0) {
			LOG_ERR("vf can't find fd_cfg %d\n", location);
			return -ENOENT;
		}
	}
	return 0;
}

/* @rule_cnt: Number of rules to be affected
 * @rule_locs: Array of used rule locations
 */
static s32 zxdh_ethtool_get_all_flows(struct zxdh_en_device *en_dev, struct ethtool_rxnfc *info,
				      u32 *rule_locs)
{
	s32 location = 0;
	s32 idx = 0;
	s32 err = 0;

	info->data = ETHTOOL_FD_MAX_NUM;

	LOG_INFO("zxdh ethtool_get_all_flows rule_cnt:%d\n", info->rule_cnt);

	while ((!err || err == -ENOENT) && idx < info->rule_cnt) {
		err = zxdh_ethtool_get_flow(en_dev, info, location);
		if (!err)
			rule_locs[idx++] = location;
		location++;
	}
	if (info->rule_cnt > idx)
		LOG_INFO("zxdh ethtool_get_all_flows idx:%d less than %d\n", idx, info->rule_cnt);

	return err;
}

static int zxdh_en_get_rxnfc(struct net_device *netdev, struct ethtool_rxnfc *info,
#ifdef HAVE_ETHTOOL_GET_RXNFC_VOID_RULE_LOCS
			     void *rule_locs)
#else
			     u32 *rule_locs)
#endif
{
	struct zxdh_en_priv *en_priv = netdev_priv(netdev);
	struct zxdh_en_device *en_dev = &en_priv->edev;
	s32 err = 0;

	LOG_INFO("zxdh_en_get_rxnfc start\n");
	switch (info->cmd) {
	case ETHTOOL_GRXRINGS:
		info->data = en_dev->curr_queue_pairs;
		break;
	case ETHTOOL_GRXFH:
		err = zxdh_get_rss_hash(info, en_dev);
		break;
	case ETHTOOL_GRXCLSRLCNT:
		info->rule_cnt = en_dev->fs.tot_num_rules;
		break;
	case ETHTOOL_GRXCLSRULE:
		err = zxdh_ethtool_get_flow(en_dev, info, info->fs.location);
		break;
	case ETHTOOL_GRXCLSRLALL:
		err = zxdh_ethtool_get_all_flows(en_dev, info, rule_locs);
		break;
	default:
		err = -EOPNOTSUPP;
		break;
	}

	return err;
}

static s32 validate_ethter(struct ethtool_rx_flow_spec *fs)
{
	struct ethhdr *eth_mask = &fs->m_u.ether_spec;
	s32 ntuples = 0;

	if (!is_zero_ether_addr(eth_mask->h_dest))
		ntuples++;
	if (!is_zero_ether_addr(eth_mask->h_source))
		ntuples++;
	if (eth_mask->h_proto)
		ntuples++;

	LOG_INFO("current ethet_addr num is %d\n", ntuples);
	return ntuples;
}

static s32 validate_tcpudp4(struct ethtool_rx_flow_spec *fs)
{
	struct ethtool_tcpip4_spec *l4_mask = &fs->m_u.tcp_ip4_spec;
	int ntuples = 0;

	if (l4_mask->tos)
		return -EINVAL;
	if (l4_mask->ip4src)
		ntuples++;
	if (l4_mask->ip4dst)
		ntuples++;
	if (l4_mask->psrc)
		ntuples++;
	if (l4_mask->pdst)
		ntuples++;

	/* tcp4/udp4 flow: proto and ethtype is masked */
	ntuples += 2;

	LOG_INFO("current TCP/UDP4 num is %d\n", ntuples);
	return ntuples;
}

static s32 validate_ip4(struct ethtool_rx_flow_spec *fs)
{
	struct ethtool_usrip4_spec *l3_mask = &fs->m_u.usr_ip4_spec;
	s32 ntuples = 0;

	if (l3_mask->l4_4_bytes || l3_mask->tos || fs->h_u.usr_ip4_spec.ip_ver != ETH_RX_NFC_IP4)
		return -EINVAL;
	if (l3_mask->ip4src)
		ntuples++;
	if (l3_mask->ip4dst)
		ntuples++;
	if (l3_mask->proto)
		ntuples++;

	/* ip4 flow: ethtype is masked */
	ntuples++;
	LOG_INFO("current Ipv4 num is %d\n", ntuples);
	return ntuples;
}

static s32 validate_ip6(struct ethtool_rx_flow_spec *fs)
{
	struct ethtool_usrip6_spec *l3_mask = &fs->m_u.usr_ip6_spec;
	s32 ntuples = 0;

	if (l3_mask->l4_4_bytes || l3_mask->tclass)
		return -EINVAL;
	if (!ipv6_addr_any((struct in6_addr *)l3_mask->ip6src))
		ntuples++;
	if (!ipv6_addr_any((struct in6_addr *)l3_mask->ip6dst))
		ntuples++;
	if (l3_mask->l4_proto)
		ntuples++;

	/* ip6 flow: ethtype is masked */
	ntuples++;
	LOG_INFO("current IPv6 flow-type num is %d\n", ntuples);
	return ntuples;
}

static s32 validate_tcpudp6(struct ethtool_rx_flow_spec *fs)
{
	struct ethtool_tcpip6_spec *l4_mask = &fs->m_u.tcp_ip6_spec;
	s32 ntuples = 0;

	if (l4_mask->tclass)
		return -EINVAL;
	if (!ipv6_addr_any((struct in6_addr *)l4_mask->ip6src))
		ntuples++;
	if (!ipv6_addr_any((struct in6_addr *)l4_mask->ip6dst))
		ntuples++;
	if (l4_mask->psrc)
		ntuples++;
	if (l4_mask->pdst)
		ntuples++;

	/* tcp6/udp6 flow: proto and ethtype is masked */
	ntuples += 2;
	LOG_INFO("current TCP/UDP6 flow-type num is %d\n", ntuples);
	return ntuples;
}

static s32 validate_vlan(struct ethtool_rx_flow_spec *fs)
{
	int ntuples = 0;

	if (fs->m_ext.vlan_etype && ntohs(fs->h_ext.vlan_etype) != ETH_TYPE_VLAN)
		return -EINVAL;

	if (fs->m_ext.vlan_tci) {
		if (ntohs(fs->h_ext.vlan_tci) >= VLAN_N_VID)
			return -EINVAL;
		ntuples++;
	}
	LOG_INFO("current extra vlan flow num is %d\n", ntuples);
	return ntuples;
}

void print_ethtool_rx_flow_spec(const struct ethtool_rx_flow_spec *fs)
{
	LOG_DEBUG("struct ethtool_rx_flow_spec:\n");
	LOG_DEBUG("  flow_type: 0x%08x\n", fs->flow_type);

	switch (fs->flow_type & ~(FLOW_EXT | FLOW_MAC_EXT)) {
	case TCP_V4_FLOW:
		LOG_DEBUG("TCP_V4_FLOW\n");
		break;
	case UDP_V4_FLOW:
		LOG_DEBUG("UDP_V4_FLOW\n");
		break;
	case TCP_V6_FLOW:
		LOG_DEBUG("TCP_V6_FLOW\n");
		break;
	case UDP_V6_FLOW:
		LOG_DEBUG("UDP_V6_FLOW\n");
		break;
	case IP_USER_FLOW:
		LOG_DEBUG("IP_USER_FLOW\n");
		break;
	case IPV6_USER_FLOW:
		LOG_DEBUG("IPV6_USER_FLOW\n");
		break;
	case ETHER_FLOW:
		LOG_DEBUG("ETHER_FLOW\n");
		break;
	default:
		LOG_DEBUG("UNKNOWN\n");
		break;
	}
	if (fs->flow_type & FLOW_EXT)
		LOG_DEBUG(" | FLOW_EXT\n");
	if (fs->flow_type & FLOW_MAC_EXT)
		LOG_DEBUG(" | FLOW_MAC_EXT\n");

	if ((fs->flow_type & ~(FLOW_EXT | FLOW_MAC_EXT)) == TCP_V4_FLOW ||
	    (fs->flow_type & ~(FLOW_EXT | FLOW_MAC_EXT)) == UDP_V4_FLOW ||
	    (fs->flow_type & ~(FLOW_EXT | FLOW_MAC_EXT)) == IP_USER_FLOW) {
		LOG_DEBUG("  h_u.tcp_ip4_spec:\n");
		LOG_DEBUG("    ip4src: %pI4\n", &fs->h_u.tcp_ip4_spec.ip4src);
		LOG_DEBUG("    ip4dst: %pI4\n", &fs->h_u.tcp_ip4_spec.ip4dst);
		LOG_DEBUG("    psrc: %u\n", ntohs(fs->h_u.tcp_ip4_spec.psrc));
		LOG_DEBUG("    pdst: %u\n", ntohs(fs->h_u.tcp_ip4_spec.pdst));
		LOG_DEBUG("    tos: 0x%02x\n", fs->h_u.tcp_ip4_spec.tos);

		LOG_DEBUG("  m_u.tcp_ip4_spec:\n");
		LOG_DEBUG("    ip4src: 0x%08x\n", ntohl(fs->m_u.tcp_ip4_spec.ip4src));
		LOG_DEBUG("    ip4dst: 0x%08x\n", ntohl(fs->m_u.tcp_ip4_spec.ip4dst));
		LOG_DEBUG("    psrc: 0x%04x\n", ntohs(fs->m_u.tcp_ip4_spec.psrc));
		LOG_DEBUG("    pdst: 0x%04x\n", ntohs(fs->m_u.tcp_ip4_spec.pdst));
		LOG_DEBUG("    tos: 0x%02x\n", fs->m_u.tcp_ip4_spec.tos);
	} else if ((fs->flow_type & ~(FLOW_EXT | FLOW_MAC_EXT)) == ETHER_FLOW) {
		LOG_DEBUG("  h_u.ether_spec:\n");
		LOG_DEBUG("    h_dest: %02x:%02x:%02x:%02x:%02x:%02x\n",
			  fs->h_u.ether_spec.h_dest[0], fs->h_u.ether_spec.h_dest[1],
			  fs->h_u.ether_spec.h_dest[2], fs->h_u.ether_spec.h_dest[3],
			  fs->h_u.ether_spec.h_dest[4], fs->h_u.ether_spec.h_dest[5]);
		LOG_DEBUG("    h_source: %02x:%02x:%02x:%02x:%02x:%02x\n",
			  fs->h_u.ether_spec.h_source[0], fs->h_u.ether_spec.h_source[1],
			  fs->h_u.ether_spec.h_source[2], fs->h_u.ether_spec.h_source[3],
			  fs->h_u.ether_spec.h_source[4], fs->h_u.ether_spec.h_source[5]);
		LOG_DEBUG("    h_proto: 0x%04x\n", ntohs(fs->h_u.ether_spec.h_proto));

		LOG_DEBUG("  m_u.ether_spec:\n");
		LOG_DEBUG("    h_dest: %02x:%02x:%02x:%02x:%02x:%02x\n",
			  fs->m_u.ether_spec.h_dest[0], fs->m_u.ether_spec.h_dest[1],
			  fs->m_u.ether_spec.h_dest[2], fs->m_u.ether_spec.h_dest[3],
			  fs->m_u.ether_spec.h_dest[4], fs->m_u.ether_spec.h_dest[5]);
		LOG_DEBUG("    h_source: %02x:%02x:%02x:%02x:%02x:%02x\n",
			  fs->m_u.ether_spec.h_source[0], fs->m_u.ether_spec.h_source[1],
			  fs->m_u.ether_spec.h_source[2], fs->m_u.ether_spec.h_source[3],
			  fs->m_u.ether_spec.h_source[4], fs->m_u.ether_spec.h_source[5]);
		LOG_DEBUG("    h_proto: 0x%04x\n", ntohs(fs->m_u.ether_spec.h_proto));
	} else {
		LOG_DEBUG("  h_u/m_u: <Unsupported flow type>\n");
	}

	LOG_DEBUG("  h_ext:\n");
	if (fs->flow_type & FLOW_MAC_EXT) {
		LOG_DEBUG("    h_dest: %02x:%02x:%02x:%02x:%02x:%02x\n", fs->h_ext.h_dest[0],
			  fs->h_ext.h_dest[1], fs->h_ext.h_dest[2], fs->h_ext.h_dest[3],
			  fs->h_ext.h_dest[4], fs->h_ext.h_dest[5]);
	} else {
		LOG_DEBUG("    h_dest: <Disabled, no FLOW_MAC_EXT>\n");
	}
	if (fs->flow_type & FLOW_EXT) {
		LOG_DEBUG("    vlan_etype: 0x%04x\n", ntohs(fs->h_ext.vlan_etype));
		LOG_DEBUG("    vlan_tci: 0x%04x (VLAN ID: %u, Priority: %u)\n",
			  ntohs(fs->h_ext.vlan_tci), ntohs(fs->h_ext.vlan_tci) & 0x0FFF,
			  (ntohs(fs->h_ext.vlan_tci) >> 13) & 0x7);
		LOG_DEBUG("    data: 0x%08x 0x%08x\n", ntohl(fs->h_ext.data[0]),
			  ntohl(fs->h_ext.data[1]));
	} else {
		LOG_DEBUG("    vlan_etype, vlan_tci, data: <Disabled, no FLOW_EXT>\n");
	}

	LOG_DEBUG("  m_ext:\n");
	if (fs->flow_type & FLOW_MAC_EXT) {
		LOG_DEBUG("h_dest: %02x:%02x:%02x:%02x:%02x:%02x\n", fs->m_ext.h_dest[0],
			  fs->m_ext.h_dest[1], fs->m_ext.h_dest[2], fs->m_ext.h_dest[3],
			  fs->m_ext.h_dest[4], fs->m_ext.h_dest[5]);
	} else {
		LOG_DEBUG("    h_dest: <Disabled, no FLOW_MAC_EXT>\n");
	}

	if (fs->flow_type & FLOW_EXT) {
		LOG_DEBUG("    vlan_etype: 0x%04x\n", ntohs(fs->m_ext.vlan_etype));
		LOG_DEBUG("    vlan_tci: 0x%04x\n", ntohs(fs->m_ext.vlan_tci));
		LOG_DEBUG("    data: 0x%08x 0x%08x\n", ntohl(fs->m_ext.data[0]),
			  ntohl(fs->m_ext.data[1]));
	} else {
		LOG_DEBUG("    vlan_etype, vlan_tci, data: <Disabled, no FLOW_EXT>\n");
	}

	LOG_DEBUG("  ring_cookie: 0x%llx\n", (unsigned long long)fs->ring_cookie);
	if (fs->ring_cookie == RX_CLS_FLOW_DISC) {
		LOG_DEBUG("DISCARD\n");
	} else {
		u8 vf = ethtool_get_flow_spec_ring_vf(fs->ring_cookie);
		u32 queue = ethtool_get_flow_spec_ring(fs->ring_cookie);

		if (vf) {
			LOG_DEBUG("print ethtool_rx_flow_spec\n");
			LOG_DEBUG("Action: Direct to VF %u queue %u\n", vf - 1, queue);
		} else {
			LOG_DEBUG("print ethtool_rx_flow_spec\n");
			LOG_DEBUG("Action: Direct to queue %u\n", queue);
		}
	}

	LOG_DEBUG("  location: %u\n", fs->location);
}

static s32 validate_ring_cookie(struct ethtool_rx_flow_spec *fs, struct zxdh_en_device *en_dev)
{
	u64 ring_cookie = fs->ring_cookie;
	u8 vf_id = 0;
	u32 queue_id = 0;

	if (ring_cookie == RX_CLS_FLOW_DISC) {
		LOG_INFO("fs->ring_cookie is 0x%llx, action is DISCARD\n", fs->ring_cookie);
		return 0;
	}
	LOG_INFO("fs->ring_cookie is 0x%llx", fs->ring_cookie);
	vf_id = ethtool_get_flow_spec_ring_vf(fs->ring_cookie);
	queue_id = ethtool_get_flow_spec_ring(fs->ring_cookie);
	if (vf_id > 0) {
		vf_id--;
		LOG_INFO("vf_id is %u\n", vf_id);
	}
	if (queue_id == QUEUE_RSS) {
		LOG_INFO("queue_id is 0xffff, use rss to distribute packets\n");
	} else if (queue_id >= en_dev->curr_queue_pairs && queue_id != QUEUE_RSS) {
		LOG_ERR("queue_id is out of range %d\n", en_dev->curr_queue_pairs - 1);
		return -EINVAL;
	}

	if (queue_id != QUEUE_RSS && queue_id < en_dev->curr_queue_pairs)
		LOG_INFO("queue_id is %u\n", queue_id);

	return 0;
}

static s32 validate_flow(struct zxdh_en_device *en_dev, struct ethtool_rx_flow_spec *fs)
{
	s32 num_tuples = 0;
	s32 ret = 0;

	print_ethtool_rx_flow_spec(fs);

	if (fs->location >= ETHTOOL_FD_MAX_NUM)
		return -EINVAL;

	if (validate_ring_cookie(fs, en_dev))
		return -EINVAL;

	switch (fs->flow_type & ~(FLOW_EXT | FLOW_MAC_EXT)) {
	case ETHER_FLOW:
		num_tuples += validate_ethter(fs);
		break;
	case TCP_V4_FLOW:
	case UDP_V4_FLOW:
		ret = validate_tcpudp4(fs);
		if (ret < 0)
			return ret;
		num_tuples += ret;
		break;
	case IP_USER_FLOW:
		ret = validate_ip4(fs);
		if (ret < 0)
			return ret;
		num_tuples += ret;
		break;
	case TCP_V6_FLOW:
	case UDP_V6_FLOW:
		ret = validate_tcpudp6(fs);
		if (ret < 0)
			return ret;
		num_tuples += ret;
		break;
	case IPV6_USER_FLOW:
		ret = validate_ip6(fs);
		if (ret < 0)
			return ret;
		num_tuples += ret;
		break;
	default:
		return -EOPNOTSUPP;
	}

	if ((fs->flow_type & FLOW_EXT)) {
		ret = validate_vlan(fs);
		if (ret < 0)
			return ret;
		num_tuples += ret;
	}

	if ((fs->flow_type & FLOW_MAC_EXT) && (!is_zero_ether_addr(fs->m_ext.h_dest)))
		num_tuples++;

	/* For coverity */
	if (num_tuples > 0)
		num_tuples = MAX_NUM_TUPLES;
	else
		num_tuples = 0;

	return num_tuples;
}

s32 zxdh_flow_table_pf_action_add(struct zxdh_en_device *en_dev, struct ethtool_rx_flow_spec *fs,
				  struct zxdh_fd_cfg_t *p_fd_cfg)
{
	u8 vf_id = 0;
	u32 queue_id = 0;
	struct zxdh_vf_item *vf_item = NULL;
	struct dpp_pf_info_t pf_info = { 0 };
	u32 base_qid = 0;
	s32 ret = 0;

	if (fs->ring_cookie == RX_CLS_FLOW_DISC) {
		p_fd_cfg->as_rlt.action_index |= ACTION_TYPE_DROP;
		return 0;
	}

	vf_id = ethtool_get_flow_spec_ring_vf(fs->ring_cookie);
	queue_id = ethtool_get_flow_spec_ring(fs->ring_cookie);

	if (vf_id > 0) {
		vf_id--;
		vf_item = en_dev->ops->get_vf_item(en_dev->parent, vf_id);
		if (IS_ERR_OR_NULL(vf_item)) {
			LOG_ERR("vif_item %d get failed", vf_id);
			return -EINVAL;
		}
		p_fd_cfg->as_rlt.action_index2 |= ACTION_TYPE_SPEC_PORT;
		p_fd_cfg->as_rlt.spec_port_vfid = vf_id;
		if (queue_id == QUEUE_RSS) {
			p_fd_cfg->as_rlt.action_index |= ACTION_TYPE_RSS;
			return 0;
		}

		pf_info.slot = en_dev->slot_id;
		pf_info.vport = vf_item->vport;

		ret = dpp_vport_base_qid_get(&pf_info, &base_qid);
		if (ret) {
			LOG_ERR("zxdh_cfg_fd_add: get vf %u base qid failed", vf_id);
			return ret;
		}
		LOG_INFO("zxdh_cfg_fd_add, vf %u, phy base qid is %u", vf_id, base_qid);
	} else {
		if (queue_id == QUEUE_RSS) {
			p_fd_cfg->as_rlt.action_index |= ACTION_TYPE_RSS;
			return 0;
		}
		base_qid = en_dev->phy_index[0];
	}
	p_fd_cfg->as_rlt.action_index |= ACTION_TYPE_QUEUE;
	p_fd_cfg->as_rlt.v_qid = queue_id * 2 + base_qid;
	LOG_INFO("zxdh_cfg_fd_add, phy queue id is %u", p_fd_cfg->as_rlt.v_qid);
	return 0;
}

static s32 zxdh_cfg_np_fd(struct zxdh_en_device *en_dev, struct ethtool_rx_flow_spec *fs,
			  u32 *index)
{
	struct dpp_pf_info_t pf_info = { 0 };
	struct zxdh_fd_cfg_t p_fd_cfg = { 0 };
	u32 handle = 0;
	u32 err = 0;

	pf_info.slot = en_dev->slot_id;
	pf_info.vport = en_dev->vport;

	LOG_INFO("zxdh cfg_np_fd start\n");

	if (en_dev->ops->get_coredev_type(en_dev->parent) == DH_COREDEV_VF) {
		err = zxdh_vf_add_fd(en_dev, fs, index);
		if (err) {
			LOG_ERR("zxdh_vf_add_fd failed\n");
			return -1;
		}
		return 0;
	}

	zxdh_flow_table_add(fs, &p_fd_cfg, &pf_info);
	err = zxdh_flow_table_pf_action_add(en_dev, fs, &p_fd_cfg);
	if (err) {
		LOG_ERR("zxdh_cfg_fd_add_action failed");
		return -EINVAL;
	}

	if (!en_dev->fs.ethtool_fs[fs->location].is_used) {
		err = dpp_fd_acl_index_request(&pf_info, &handle);
		if (err) {
			LOG_ERR("failed to request index!\n");
			return -ENOSPC;
		}
	} else {
		handle = en_dev->fs.ethtool_fs[fs->location].index;
	}

	*index = handle;
	LOG_INFO("fd index is %d\n", *index);

	LOG_INFO("dpp_tbl_fd_cfg_add start\n");

	err = dpp_tbl_fd_cfg_add(&pf_info, ZXDH_SDT_FD_CFG_TABLE, handle, &p_fd_cfg);
	if (err != 0) {
		LOG_ERR("failed to add fd in np!\n");
		return -1;
	}

	LOG_INFO("dpp_tbl_fd_cfg_add end\n");
	return 0;
}

static void set_flow_table(struct zxdh_en_device *en_dev, struct ethtool_rx_flow_spec *fs,
			   u32 index)
{
	zte_memcpy_s(&en_dev->fs.ethtool_fs[fs->location].rfs, fs,
		     sizeof(struct ethtool_rx_flow_spec));
	if (!en_dev->fs.ethtool_fs[fs->location].is_used) { /* add */
		en_dev->fs.ethtool_fs[fs->location].loc = fs->location;
		en_dev->fs.ethtool_fs[fs->location].index = index;
		en_dev->fs.ethtool_fs[fs->location].is_used = true;
		en_dev->fs.tot_num_rules++;
	}

	LOG_INFO("set flow table: location is %u, index is %u\n", fs->location, index);
}

static s32 zxdh_ethtool_flow_replace(struct zxdh_en_device *en_dev, struct ethtool_rx_flow_spec *fs)
{
	s32 num_tuples = 0;
	s32 err = 0;
	u32 index = 0;

	LOG_INFO("zxdh ethtool_flow_replace start!\n");

	num_tuples = validate_flow(en_dev, fs);
	if (num_tuples <= 0) {
		LOG_ERR("flow is not valid %d\n", num_tuples);
		return -EINVAL;
	}

	err = zxdh_cfg_np_fd(en_dev, fs, &index);
	if (err != 0) {
		LOG_ERR("zxdh_cfg_np_fd failed!\n");
		return -EINVAL;
	}

	set_flow_table(en_dev, fs, index);
	return 0;
}

static s32 zxdh_ethtool_flow_remove(struct zxdh_en_device *en_dev, s32 location)
{
	u32 err = 0;
	struct dpp_pf_info_t pf_info = { 0 };

	LOG_INFO("zxdh ethtool_flow_remove start!\n");

	pf_info.slot = en_dev->slot_id;
	pf_info.vport = en_dev->vport;

	if (location < 0 || location >= ETHTOOL_FD_MAX_NUM)
		return -EINVAL;

	if (!en_dev->fs.ethtool_fs[location].is_used) {
		LOG_ERR("location %d is not used!!!\n", location);
		return -EINVAL;
	}

	if (en_dev->ops->get_coredev_type(en_dev->parent) == DH_COREDEV_VF) {
		err = zxdh_vf_del_fd(en_dev, en_dev->fs.ethtool_fs[location].index);
		if (err != 0) {
			LOG_ERR("zxdh_vf_del_fd failed!\n");
			return -EINVAL;
		}
		goto free_flow_table;
	}

	err = dpp_tbl_fd_cfg_del(&pf_info, ZXDH_SDT_FD_CFG_TABLE,
				 en_dev->fs.ethtool_fs[location].index);
	if (err != 0) {
		LOG_ERR("dpp_tbl_fd_cfg_del failed!\n");
		return -EINVAL;
	}

	err = dpp_fd_acl_index_release(&pf_info, en_dev->fs.ethtool_fs[location].index);
	if (err) {
		LOG_ERR("failed to release index!!!\n");
		return -EINVAL;
	}

free_flow_table:

	zte_memset_s(&en_dev->fs.ethtool_fs[location], 0, sizeof(struct zxdh_ethtool_table));
	en_dev->fs.tot_num_rules--;
	return 0;
}

s32 zxdh_ethtool_rss_set(struct zxdh_en_device *en_dev, struct ethtool_rxnfc *cmd)
{
	union zxdh_msg *msg = NULL;
	u32 hash_mode = 0;
	s32 ret = 0;

	struct dpp_pf_info_t pf_info = { 0 };
	struct zxdh_bar_extra_para para = { 0 };

	pf_info.slot = en_dev->slot_id;
	pf_info.vport = en_dev->vport;

	para.is_sync = true;
	para.retrycnt = BAR_MSG_RETRY_CNT_MAX;

	msg = kzalloc(sizeof(union zxdh_msg), GFP_KERNEL);
	if (!msg) {
		LOG_ERR("kzalloc(%lu, GFP_KERNEL) failed !", sizeof(union zxdh_msg));
		return -ENOMEM;
	}

	switch (cmd->data) {
	/* input parameter mv */
	case (RXH_L2DA + RXH_VLAN): {
		hash_mode = ZXDH_NET_RX_FLOW_HASH_MV;
		break;
	}
	/* input parameter sdt */
	case (RXH_L3_PROTO + RXH_IP_SRC + RXH_IP_DST): {
		hash_mode = ZXDH_NET_RX_FLOW_HASH_SDT;
		break;
	}
	/* input parameter sdfnt  */
	case (RXH_L3_PROTO + RXH_IP_SRC + RXH_IP_DST + RXH_L4_B_0_1 + RXH_L4_B_2_3): {
		hash_mode = ZXDH_NET_RX_FLOW_HASH_SDFNT;
		break;
	}
	default: {
		LOG_ERR("invalid para, support mv, sdt, sdfnt\n");
		ret = -EOPNOTSUPP;
		goto free_msg;
	}
	}
	LOG_INFO("hash_mode: %u\n", hash_mode);

	if (en_dev->ops->get_coredev_type(en_dev->parent) == DH_COREDEV_PF) {
		ret = dpp_vport_rx_flow_hash_set(&pf_info, hash_mode);
	} else {
		msg->payload.hdr.op_code = ZXDH_RX_FLOW_HASH_SET;
		msg->payload.hdr.vport = en_dev->vport;
		msg->payload.hdr.pcie_id = en_dev->pcie_id;
		msg->payload.rx_flow_hash_set_msg.hash_mode = hash_mode;
		ret = en_dev->ops->msg_send_cmd(en_dev->parent, MODULE_VF_BAR_MSG_TO_PF, msg, msg,
						&para);
	}
	if (!ret)
		en_dev->eth_config.hash_mode = hash_mode;
free_msg:
	kfree(msg);
	return ret;
}

static int zxdh_en_set_rxnfc(struct net_device *netdev, struct ethtool_rxnfc *cmd)
{
	struct zxdh_en_priv *en_priv = netdev_priv(netdev);
	struct zxdh_en_device *en_dev = &en_priv->edev;
	s32 ret = 0;

	if (en_dev->device_state == ZXDH_DEVICE_STATE_INTERNAL_ERROR)
		return -ENXIO;

	LOG_INFO("zxdh en_set_rxnfc start\n");

	switch (cmd->cmd) {
	case ETHTOOL_SRXCLSRLINS:
		ret = zxdh_ethtool_flow_replace(en_dev, &cmd->fs);
		break;
	case ETHTOOL_SRXCLSRLDEL:
		ret = zxdh_ethtool_flow_remove(en_dev, cmd->fs.location);
		break;
	case ETHTOOL_SRXFH:
		ret = zxdh_ethtool_rss_set(en_dev, cmd);
		break;
	default:
		ret = -EOPNOTSUPP;
		break;
	}

	return ret;
}

static s32 zxdh_en_get_coalesce(struct net_device *netdev, struct ethtool_coalesce *coal,
				struct kernel_ethtool_coalesce *kec, struct netlink_ext_ack *ack)
{
	struct zxdh_en_priv *en_priv = netdev_priv(netdev);
	struct zxdh_en_device *en_dev = &en_priv->edev;
	u16 rx_msix_mode = 0;
	u16 tx_msix_mode = 0;
	u32 rx_coalesce_usecs = 0;
	u32 tx_coalesce_usecs = 0;
	s32 err = 0;

	if (en_dev->device_state == ZXDH_DEVICE_STATE_INTERNAL_ERROR)
		return -ENXIO;
	LOG_DEBUG("zxdh en_get_coalesce start\n");
	err = zxdh_get_misx_mode(en_dev, &rx_msix_mode, &tx_msix_mode);
	if (err != 0) {
		LOG_ERR("zxdh_get_misx_mode failed\n");
		return -1;
	}

	LOG_DEBUG("get rx_msix_mode is %d\n", rx_msix_mode);
	LOG_DEBUG("get tx_msix_mode is %d\n", tx_msix_mode);

	if (rx_msix_mode == PROTOCOL_MODE)
		coal->use_adaptive_rx_coalesce = 1;
	else if (rx_msix_mode == AGGREGATION_MODE)
		coal->use_adaptive_rx_coalesce = 0;
	else
		LOG_ERR("invalid rx_msix_mode:%d\n", rx_msix_mode);

	if (tx_msix_mode == PROTOCOL_MODE)
		coal->use_adaptive_tx_coalesce = 1;
	else if (tx_msix_mode == AGGREGATION_MODE)
		coal->use_adaptive_tx_coalesce = 0;
	else
		LOG_ERR("invalid tx_msix_mode:%d\n", tx_msix_mode);

	err = zxdh_get_coalesce_usecs(en_dev, &rx_coalesce_usecs, &tx_coalesce_usecs);
	if (err != 0) {
		LOG_ERR("zxdh_get_coalesce_usecs failed\n");
		return -1;
	}
	LOG_DEBUG("get rx_coalesce_usecs is:%d\n", rx_coalesce_usecs);
	LOG_DEBUG("get tx_coalesce_usecs is:%d\n", tx_coalesce_usecs);

	coal->rx_coalesce_usecs = rx_coalesce_usecs;
	coal->tx_coalesce_usecs = tx_coalesce_usecs;

	LOG_DEBUG("zxdh en_get_coalesce end\n");
	return 0;
}

static s32 zxdh_en_set_coalesce(struct net_device *netdev, struct ethtool_coalesce *coal,
				struct kernel_ethtool_coalesce *kec, struct netlink_ext_ack *ack)
{
	struct zxdh_en_priv *en_priv = netdev_priv(netdev);
	struct zxdh_en_device *en_dev = &en_priv->edev;
	u16 rx_msix_mode = 0;
	u16 tx_msix_mode = 0;
	s32 err = 0;

	if (en_dev->device_state == ZXDH_DEVICE_STATE_INTERNAL_ERROR)
		return -ENXIO;
	LOG_DEBUG("zxdh en_set_coalesce start\n");
	if (coal->tx_coalesce_usecs > ZXDH_MAX_COAL_TIME ||
	    coal->rx_coalesce_usecs > ZXDH_MAX_COAL_TIME) {
		LOG_ERR("maximum coalesce time supported is %u usecs\n", ZXDH_MAX_COAL_TIME);
		return -ERANGE;
	}

	mutex_lock(&en_priv->lock);
	rx_msix_mode = (coal->use_adaptive_rx_coalesce == 1) ? PROTOCOL_MODE : AGGREGATION_MODE;
	tx_msix_mode = (coal->use_adaptive_tx_coalesce == 1) ? PROTOCOL_MODE : AGGREGATION_MODE;

	LOG_DEBUG("cfg rx_msix_mode is %d\n", rx_msix_mode);
	LOG_DEBUG("cfg tx_msix_mode is %d\n", tx_msix_mode);
	LOG_DEBUG("cfg rx_coalesce_usecs is %d\n", coal->rx_coalesce_usecs);
	LOG_DEBUG("cfg tx_coalesce_usecs is %d\n", coal->tx_coalesce_usecs);

	err = zxdh_cfg_misx_mode(en_dev, rx_msix_mode, tx_msix_mode);
	if (err != 0) {
		LOG_ERR("zxdh_cfg_misx_mode failed\n");
		goto out;
	}

	err = zxdh_cfg_coalesce_usecs(en_dev, coal->rx_coalesce_usecs, coal->tx_coalesce_usecs);
	if (err != 0) {
		LOG_ERR("zxdh_cfg_coalesce_usecs failed\n");
		goto out;
	}

out:
	mutex_unlock(&en_priv->lock);
	return err;
}

static const struct ethtool_ops zxdh_en_ethtool_ops = {
#ifdef HAVE_ETHTOOL_COALESCE_PARAMS_SUPPORT
	.supported_coalesce_params = ETHTOOL_COALESCE_USECS | ETHTOOL_COALESCE_RX_USECS |
				     ETHTOOL_COALESCE_TX_USECS | ETHTOOL_COALESCE_USE_ADAPTIVE_RX |
				     ETHTOOL_COALESCE_USE_ADAPTIVE_TX,
#endif
	.get_coalesce = zxdh_en_get_coalesce,
	.set_coalesce = zxdh_en_set_coalesce,
	.get_drvinfo = zxdh_en_get_drvinfo,
	.get_link_ksettings = zxdh_en_get_link_ksettings,
	.set_link_ksettings = zxdh_en_set_link_ksettings,
	.get_regs_len = zxdh_en_get_regs_len,
	.get_regs = zxdh_en_get_regs,
	.get_wol = zxdh_en_get_wol,
	.set_wol = zxdh_en_set_wol,
	.get_msglevel = zxdh_en_get_msglevel,
	.set_msglevel = zxdh_en_set_msglevel,
	.nway_reset = zxdh_en_nway_reset,
	.get_link = zxdh_en_get_link,
	.get_eeprom_len = zxdh_en_get_eeprom_len,
	.get_eeprom = zxdh_en_get_eeprom,
	.set_eeprom = zxdh_en_set_eeprom,
	.get_ringparam = zxdh_en_get_ringparam,
	.set_ringparam = zxdh_en_set_ringparam,
	.get_pauseparam = zxdh_en_get_pauseparam,
	.set_pauseparam = zxdh_en_set_pauseparam,
	.get_fecparam = zxdh_en_get_fecparam,
	.set_fecparam = zxdh_en_set_fecparam,
	.get_module_info = zxdh_en_get_module_info,
	.get_module_eeprom = zxdh_en_get_module_eeprom,
	.get_module_eeprom_by_page = zxdh_en_get_module_eeprom_by_page,
	.self_test = zxdh_en_diag_test,
	.get_strings = zxdh_en_get_strings,
	.get_priv_flags = zxdh_en_get_priv_flags,
	.set_priv_flags = zxdh_en_set_priv_flags,
#ifndef HAVE_RHEL6_ETHTOOL_OPS_EXT_STRUCT
#ifdef HAVE_ETHTOOL_SET_PHYS_ID
	.set_phys_id = zxdh_en_set_phys_id,
#else
	.phys_id = zxdh_en_phys_id,
#endif /* HAVE_ETHTOOL_SET_PHYS_ID */
#endif /* HAVE_RHEL6_ETHTOOL_OPS_EXT_STRUCT */

#ifdef HAVE_ETHTOOL_GET_SSET_COUNT
	.get_sset_count = zxdh_en_get_sset_count,
#endif
	.get_ethtool_stats = zxdh_en_get_ethtool_stats,

#ifndef HAVE_RHEL6_ETHTOOL_OPS_EXT_STRUCT
#ifdef HAVE_ETHTOOL_GET_TS_INFO
	.get_ts_info = zxdh_en_get_ts_info,
#endif /* HAVE_ETHTOOL_GET_TS_INFO */
#endif /* HAVE_RHEL6_ETHTOOL_OPS_EXT_STRUCT */
#ifdef CONFIG_PM_RUNTIME
	.begin = zxdh_en_ethtool_begin,
	.complete = zxdh_en_ethtool_complete,
#endif /* CONFIG_PM_RUNTIME */
#ifndef HAVE_NDO_SET_FEATURES
	.get_rx_csum = zxdh_en_get_rx_csum,
	.set_rx_csum = zxdh_en_set_rx_csum,
	.set_tx_csum = zxdh_en_set_tx_csum,
#ifdef NETIF_F_TSO
	.set_tso = zxdh_en_set_tso,
#endif
#ifdef ETHTOOL_GFLAGS
	.set_flags = zxdh_en_set_flags,
#endif /* ETHTOOL_GFLAGS */
#endif /* HAVE_NDO_SET_FEATURES */

#ifndef HAVE_RHEL6_ETHTOOL_OPS_EXT_STRUCT
#ifdef ETHTOOL_GEEE
	.get_eee = zxdh_en_get_eee,
#endif
#ifdef ETHTOOL_SEEE
	.set_eee = zxdh_en_set_eee,
#endif
#ifdef ETHTOOL_GRXFHINDIR
#ifdef HAVE_ETHTOOL_GRXFHINDIR_SIZE
	.get_rxfh_indir_size = zxdh_en_get_rxfh_indir_size,
	.get_rxfh_key_size = zxdh_en_get_rxfh_key_size,
#endif /* HAVE_ETHTOOL_GRSFHINDIR_SIZE */
#if (defined(ETHTOOL_GRSSH) && !defined(HAVE_ETHTOOL_GSRSSH))
	.get_rxfh = zxdh_en_get_rxfh,
#else
	.get_rxfh_indir = zxdh_en_get_rxfh_indir,
#endif /* HAVE_ETHTOOL_GSRSSH */
#endif /* ETHTOOL_GRXFHINDIR */
#ifdef ETHTOOL_SRXFHINDIR
#if (defined(ETHTOOL_GRSSH) && !defined(HAVE_ETHTOOL_GSRSSH))
	.set_rxfh = zxdh_en_set_rxfh,
#else
	.set_rxfh_indir = zxdh_en_set_rxfh_indir,
#endif /* HAVE_ETHTOOL_GSRSSH */
#endif /* ETHTOOL_SRXFHINDIR */
#ifdef ETHTOOL_GCHANNELS
	.get_channels = zxdh_en_get_channels,
#endif /* ETHTOOL_GCHANNELS */
#ifdef ETHTOOL_SCHANNELS
	.set_channels = zxdh_en_set_channels,
#endif /* ETHTOOL_SCHANNELS */
#endif /* HAVE_RHEL6_ETHTOOL_OPS_EXT_STRUCT */
#ifdef ETHTOOL_GRXFH
	.get_rxnfc = zxdh_en_get_rxnfc,
	.set_rxnfc = zxdh_en_set_rxnfc,
#endif
};

#ifdef HAVE_RHEL6_ETHTOOL_OPS_EXT_STRUCT
static const struct ethtool_ops_ext zxdh_en_ethtool_ops_ext = {
	.size = sizeof(struct ethtool_ops_ext),
	.get_ts_info = zxdh_en_get_ts_info,
	.set_phys_id = zxdh_en_set_phys_id,
	.get_eee = zxdh_en_get_eee,
	.set_eee = zxdh_en_set_eee,
#ifdef HAVE_ETHTOOL_GRXFHINDIR_SIZE
	.get_rxfh_indir_size = zxdh_en_get_rxfh_indir_size,
#endif /* HAVE_ETHTOOL_GRSFHINDIR_SIZE */
	.get_rxfh_indir = zxdh_en_get_rxfh_indir,
	.set_rxfh_indir = zxdh_en_set_rxfh_indir,
	.get_channels = zxdh_en_get_channels,
	.set_channels = zxdh_en_set_channels,
};

void zxdh_en_set_ethtool_ops_ext(struct net_device *netdev)
{
	netdev->ethtool_ops = &zxdh_en_ethtool_ops;
	set_ethtool_ops_ext(netdev, &zxdh_en_ethtool_ops_ext);
}
#else
void zxdh_en_set_ethtool_ops(struct net_device *netdev)
{
	netdev->ethtool_ops = &zxdh_en_ethtool_ops;
}
#endif /* HAVE_RHEL6_ETHTOOL_OPS_EXT_STRUCT */
