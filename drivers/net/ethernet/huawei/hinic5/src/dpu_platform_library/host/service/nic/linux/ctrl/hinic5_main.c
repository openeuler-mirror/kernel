/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hinic5_main.c
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   :
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": [NIC]" fmt
#include <linux/kernel.h>
#include <linux/device.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/interrupt.h>
#include <linux/etherdevice.h>
#include <linux/netdevice.h>
#include <linux/if_vlan.h>
#include <linux/ethtool.h>
#include <linux/dcbnl.h>
#include <linux/tcp.h>
#include <linux/ip.h>
#include <linux/debugfs.h>
#include <linux/notifier.h>
#include <linux/skbuff.h>

#include "ossl_knl.h"
#include "drv_nic_api.h"
#include "hinic5_bond.h"
#include "hinic5_hw.h"
#include "hinic5_crm.h"
#include "hinic5_mt.h"
#include "hinic5_hinic5_vram.h"
#include "hinic5_nic_cfg.h"
#include "hinic5_srv_nic.h"
#include "hinic5_nic_io.h"
#include "hinic5_nic_dev.h"
#include "hinic5_tx.h"
#include "hinic5_rx.h"
#include "hinic5_tc.h"
#include "hinic5_lld.h"
#include "hinic5_rss.h"
#include "hinic5_dcb.h"
#include "hinic5_ptp.h"
#include "hinic5_nic_event.h"
#include "hinic5_hinic5_vram_api.h"
#include "hinic5_macsec_api.h"
#include "hinic5_main.h"

#if defined(HAVE_NDO_UDP_TUNNEL_ADD) || defined(HAVE_UDP_TUNNEL_NIC_INFO)
#include <net/udp_tunnel.h>
#endif /* HAVE_NDO_UDP_TUNNEL_ADD || HAVE_UDP_TUNNEL_NIC_INFO */

#define CFM_BOND_FULL

#define DEFAULT_POLL_WEIGHT	64
static unsigned int poll_weight = DEFAULT_POLL_WEIGHT;
module_param(poll_weight, uint, 0444);
MODULE_PARM_DESC(poll_weight, "Number packets for NAPI budget (default=64)");

#define HINIC5_DEAULT_TXRX_MSIX_PENDING_LIMIT		2
#define HINIC5_MAX_TXRX_MSIX_PENDING_LIMIT 255

#define HINIC5_DEAULT_TXRX_MSIX_COALESC_TIMER_CFG	25
#define HINIC5_MAX_TXRX_MSIX_COALESC_TIMER_CFG 255

static unsigned char qp_pending_limit = HINIC5_DEAULT_TXRX_MSIX_PENDING_LIMIT;
module_param(qp_pending_limit, byte, 0444);
MODULE_PARM_DESC(qp_pending_limit, "QP MSI-X Interrupt coalescing parameter pending_limit, 0-255 (default=2, unit=8)");

static unsigned char qp_coalesc_timer_cfg =
		HINIC5_DEAULT_TXRX_MSIX_COALESC_TIMER_CFG;
module_param(qp_coalesc_timer_cfg, byte, 0444);
MODULE_PARM_DESC(qp_coalesc_timer_cfg, "QP MSI-X Interrupt coalescing parameter coalesc_timer_cfg, 0-255 (default=25, unit=5us)");

#define DEFAULT_RX_BUFF_LEN	2
u16 hinic5_rx_buff = DEFAULT_RX_BUFF_LEN;
module_param(hinic5_rx_buff, ushort, 0444);
MODULE_PARM_DESC(hinic5_rx_buff, "Set hinic5_rx_buff size, 2,4,8 (unit: KB, default=2KB)");

static unsigned int lro_replenish_thld = 256;
module_param(lro_replenish_thld, uint, 0444);
MODULE_PARM_DESC(lro_replenish_thld, "Number wqe for lro replenish buffer, 0-16384 (unit: wqebb, default=256)");

static unsigned char set_link_status_follow = HINIC5_LINK_FOLLOW_STATUS_MAX;
module_param(set_link_status_follow, byte, 0444);
MODULE_PARM_DESC(set_link_status_follow, "Set link status follow port status, 0: DEFAULT, 1: PORT, 2: SEPARATE, 3: UNSET (default=3)");

static bool page_pool_enabled = true;
module_param(page_pool_enabled, bool, 0444);
MODULE_PARM_DESC(page_pool_enabled, "Set page_pool feature state, 0: DISABLE, 1: ENABLE (default=1)");

static bool macsec_enabled;
module_param(macsec_enabled, bool, 0444);
MODULE_PARM_DESC(macsec_enabled, "Set macsec module state, 0: DISABLE, 1: ENABLE (default=0)");

#define HINIC5_MAX_POLL_WEIGHT		16384

#define HINIC5_MAX_LRO_REPLENISH_THLD	16384
#define HINIC5_DEFAULT_LRO_REPLENISH_THLD	255

#define HINIC5_MAX_RX_BUFF		8
#define HINIC5_MIN_RX_BUFF		2

static inline void hinic5_main_param_validate(void)
{
	if (poll_weight == 0 || poll_weight > HINIC5_MAX_POLL_WEIGHT) {
		poll_weight = DEFAULT_POLL_WEIGHT;
		pr_warn("[NIC] poll_weight is out of range(0-%u), reset to default %u\n",
			HINIC5_MAX_POLL_WEIGHT, DEFAULT_POLL_WEIGHT);
	}

	if (qp_pending_limit > HINIC5_MAX_TXRX_MSIX_PENDING_LIMIT) {
		qp_pending_limit = HINIC5_DEAULT_TXRX_MSIX_PENDING_LIMIT;
		pr_warn("[NIC] qp_pending_limit is out of range(0-255), reset to default %u\n",
			HINIC5_DEAULT_TXRX_MSIX_PENDING_LIMIT);
	}

	if (qp_coalesc_timer_cfg > HINIC5_MAX_TXRX_MSIX_COALESC_TIMER_CFG) {
		qp_coalesc_timer_cfg = HINIC5_DEAULT_TXRX_MSIX_COALESC_TIMER_CFG;
		pr_warn("[NIC] qp_coalesc_timer_cfg is out of range(0-255), reset to default %u\n",
			HINIC5_DEAULT_TXRX_MSIX_COALESC_TIMER_CFG);
	}

	if (hinic5_rx_buff != RX_BUFF_VALID_2KB && hinic5_rx_buff != RX_BUFF_VALID_4KB &&
	    hinic5_rx_buff != RX_BUFF_VALID_8KB) {
		hinic5_rx_buff = DEFAULT_RX_BUFF_LEN;
		pr_warn("[NIC] hinic5_rx_buff is invalid(%u), only 2/4/8KB supported, reset to default %uKB\n",
			hinic5_rx_buff, DEFAULT_RX_BUFF_LEN);
	}

	if (lro_replenish_thld > HINIC5_MAX_LRO_REPLENISH_THLD) {
		lro_replenish_thld = HINIC5_DEFAULT_LRO_REPLENISH_THLD;
		pr_warn("[NIC] lro_replenish_thld is out of range(0-%u), reset to default %u\n",
			HINIC5_MAX_LRO_REPLENISH_THLD, HINIC5_DEFAULT_LRO_REPLENISH_THLD);
	}

	if (set_link_status_follow > HINIC5_LINK_FOLLOW_STATUS_MAX) {
		set_link_status_follow = HINIC5_LINK_FOLLOW_STATUS_MAX;
		pr_warn("[NIC] set_link_status_follow is out of range(0-3), reset to default %u\n",
			HINIC5_LINK_FOLLOW_STATUS_MAX);
	}
}

#ifdef HAVE_MULTI_VLAN_OFFLOAD_EN
static int hinic5_netdev_event(struct notifier_block *notifier, unsigned long event, void *ptr);

#define HINIC5_ASIC_WAIT_FLUSH_QP_RESOURCE_TIMEOUT		100
#define HINIC5_FPGA_WAIT_FLUSH_QP_RESOURCE_TIMEOUT		2000
#define HINIC5_EMU_WAIT_FLUSH_QP_RESOURCE_TIMEOUT		2000
#define HINIC5_EDA_WAIT_FLUSH_QP_RESOURCE_TIMEOUT		2000

#define HINIC5_GET_TIMEOUT(board, type) HINIC5_##board##_##type##_TIMEOUT

/* used for netdev notifier register/unregister */
static DEFINE_MUTEX(hinic5_netdev_notifiers_mutex);
static int hinic5_netdev_notifiers_ref_cnt;
static struct notifier_block hinic5_netdev_notifier = {
	.notifier_call = hinic5_netdev_event,
};

#ifdef HAVE_UDP_TUNNEL_NIC_INFO
static const struct udp_tunnel_nic_info hinic5_udp_tunnels = {
	.set_port	= hinic5_udp_tunnel_set_port,
	.unset_port	= hinic5_udp_tunnel_unset_port,
	.flags		= UDP_TUNNEL_NIC_INFO_MAY_SLEEP,
	.tables		= {
		{ .n_entries = 1, .tunnel_types = UDP_TUNNEL_TYPE_VXLAN, },
	},
};
#endif /* HAVE_UDP_TUNNEL_NIC_INFO */

static void hinic5_register_notifier(struct hinic5_nic_dev *nic_dev)
{
	int err;

	mutex_lock(&hinic5_netdev_notifiers_mutex);
	hinic5_netdev_notifiers_ref_cnt++;
	if (hinic5_netdev_notifiers_ref_cnt == 1) {
		err = register_netdevice_notifier(&hinic5_netdev_notifier);
		if (err != 0) {
			nic_info(nic_dev->lld_dev->dev, "Register netdevice notifier failed, err: %d\n",
				 err);
			hinic5_netdev_notifiers_ref_cnt--;
		}
	}
	mutex_unlock(&hinic5_netdev_notifiers_mutex);
}

static void hinic5_unregister_notifier(struct hinic5_nic_dev *nic_dev)
{
	mutex_lock(&hinic5_netdev_notifiers_mutex);
	if (hinic5_netdev_notifiers_ref_cnt == 1)
		unregister_netdevice_notifier(&hinic5_netdev_notifier);

	if (hinic5_netdev_notifiers_ref_cnt != 0)
		hinic5_netdev_notifiers_ref_cnt--;
	mutex_unlock(&hinic5_netdev_notifiers_mutex);
}

#define HINIC5_MAX_VLAN_DEPTH_OFFLOAD_SUPPORT	1
#define HINIC5_VLAN_CLEAR_OFFLOAD	(NETIF_F_IP_CSUM | NETIF_F_IPV6_CSUM | \
					 NETIF_F_SCTP_CRC | NETIF_F_RXCSUM | \
					 NETIF_F_ALL_TSO)

static int hinic5_netdev_event(struct notifier_block *notifier, unsigned long event, void *ptr)
{
	struct net_device *ndev = netdev_notifier_info_to_dev(ptr);
	struct net_device *real_dev = NULL;
	struct net_device *ret = NULL;
	u16 vlan_depth;

	if (!virt_addr_valid((const void *)ndev))
		return NOTIFY_DONE;

	if (!is_vlan_dev(ndev))
		return NOTIFY_DONE;

	dev_hold(ndev);

	switch (event) {
	case NETDEV_REGISTER:
		real_dev = vlan_dev_real_dev(ndev);
		if (!hinic5_is_netdev_ops_match(real_dev))
			goto out;

		vlan_depth = 1;
		ret = vlan_dev_priv(ndev)->real_dev;
		while (is_vlan_dev(ret)) {
			ret = vlan_dev_priv(ret)->real_dev;
			vlan_depth++;
		}

		if (vlan_depth == HINIC5_MAX_VLAN_DEPTH_OFFLOAD_SUPPORT) {
			ndev->vlan_features &= (~HINIC5_VLAN_CLEAR_OFFLOAD);
		} else if (vlan_depth > HINIC5_MAX_VLAN_DEPTH_OFFLOAD_SUPPORT) {
#ifdef HAVE_NDO_SET_FEATURES
#ifdef HAVE_NDO_SET_U32_FEATURES
			set_netdev_hw_features(ndev,
					       get_netdev_hw_features(ndev) &
					       (~HINIC5_VLAN_CLEAR_OFFLOAD));
#else
			ndev->hw_features &= (~HINIC5_VLAN_CLEAR_OFFLOAD);
#endif
#endif
			ndev->features &= (~HINIC5_VLAN_CLEAR_OFFLOAD);
		}

		break;

	default:
		break;
	};

out:
	dev_put(ndev);

	return NOTIFY_DONE;
}
#endif

void hinic5_link_status_change(struct hinic5_nic_dev *nic_dev, bool status)
{
	struct net_device *netdev = nic_dev->netdev;

	if (!HINIC5_CHANNEL_RES_VALID(nic_dev) ||
	    test_bit(HINIC5_LP_TEST, &nic_dev->flags) ||
	    test_bit(HINIC5_FORCE_LINK_UP, &nic_dev->flags))
		return;

	if (status) {
		if (netif_carrier_ok(netdev))
			return;

		nic_dev->link_status = status;
		netif_carrier_on(netdev);
		nicif_info(nic_dev, link, netdev, "Link is up\n");
	} else {
		if (!netif_carrier_ok(netdev))
			return;

		nic_dev->link_status = status;
		netif_carrier_off(netdev);
		nicif_info(nic_dev, link, netdev, "Link is down\n");
	}
}

static void netdev_vlan_feature_init(struct hinic5_nic_dev *nic_dev, netdev_features_t *vlan_fts)
{
	if (HINIC5_SUPPORT_VLAN_OFFLOAD(nic_dev->hwdev) != 0) {
#if defined(NETIF_F_HW_VLAN_CTAG_TX)
		*vlan_fts |= NETIF_F_HW_VLAN_CTAG_TX;
#elif defined(NETIF_F_HW_VLAN_TX)
		*vlan_fts |= NETIF_F_HW_VLAN_TX;
#endif

#if defined(NETIF_F_HW_VLAN_CTAG_RX)
		*vlan_fts |= NETIF_F_HW_VLAN_CTAG_RX;
#elif defined(NETIF_F_HW_VLAN_RX)
		*vlan_fts |= NETIF_F_HW_VLAN_RX;
#endif
	}

	if (HINIC5_SUPPORT_RXVLAN_FILTER(nic_dev->hwdev) != 0) {
#if defined(NETIF_F_HW_VLAN_CTAG_FILTER)
		*vlan_fts |= NETIF_F_HW_VLAN_CTAG_FILTER;
#elif defined(NETIF_F_HW_VLAN_FILTER)
		*vlan_fts |= NETIF_F_HW_VLAN_FILTER;
#endif
	}
}

static void netdev_hw_feature_init(struct net_device *netdev,
				   struct hinic5_nic_dev *nic_dev, netdev_features_t *hw_features)
{
	/* LRO is disable in default, only set hw features */
	if (HINIC5_SUPPORT_LRO(nic_dev->hwdev) != 0)
		*hw_features |= NETIF_F_LRO;

#if (KERNEL_VERSION(4, 11, 0) > LINUX_VERSION_CODE)
	if (HINIC5_SUPPORT_UFO(nic_dev->hwdev) != 0) {
		/* UFO is disable in default */
		*hw_features |= NETIF_F_UFO;
		netdev->vlan_features |= NETIF_F_UFO;
	}
#endif
}

static void netdev_tso_feature_init(struct hinic5_nic_dev *nic_dev, netdev_features_t *tso_fts)
{
#ifdef HAVE_ENCAPSULATION_TSO
	if (HINIC5_SUPPORT_VXLAN_OFFLOAD(nic_dev->hwdev) ||
	    HINIC5_SUPPORT_GENEVE_OFFLOAD(nic_dev->hwdev))
		*tso_fts |= NETIF_F_GSO_UDP_TUNNEL | NETIF_F_GSO_UDP_TUNNEL_CSUM;

	if (HINIC5_SUPPORT_IPXIP_OFFLOAD(nic_dev->hwdev))
		*tso_fts |= NETIF_F_GSO_IPXIP4 | NETIF_F_GSO_IPXIP6;
#endif /* HAVE_ENCAPSULATION_TSO */
}

static void netdev_feature_init(struct net_device *netdev)
{
	struct hinic5_nic_dev *nic_dev = netdev_priv(netdev);
	netdev_features_t cso_fts = 0;
	netdev_features_t vlan_fts = 0;
	netdev_features_t tso_fts = 0;
	netdev_features_t hw_features = 0;
	netdev_features_t dft_fts = NETIF_F_SG | NETIF_F_HIGHDMA;

	if (HINIC5_SUPPORT_CSUM(nic_dev->hwdev) != 0)
		cso_fts |= NETIF_F_IP_CSUM | NETIF_F_IPV6_CSUM | NETIF_F_RXCSUM;
	if (HINIC5_SUPPORT_SCTP_CRC(nic_dev->hwdev) != 0)
		cso_fts |= NETIF_F_SCTP_CRC;

	if (HINIC5_SUPPORT_TSO(nic_dev->hwdev) != 0)
		tso_fts |= NETIF_F_TSO | NETIF_F_TSO6;

	netdev_vlan_feature_init(nic_dev, &vlan_fts);

	netdev_tso_feature_init(nic_dev, &tso_fts);

	if (HINIC5_SUPPORT_FEATURE(nic_dev->hwdev, TC_FLOWER_OFFLOAD)) {
		netdev->features |= NETIF_F_HW_TC;
		hw_features |= NETIF_F_HW_TC;
	}
	netdev_hw_feature_init(netdev, nic_dev, &hw_features);

	netdev->features |= dft_fts | cso_fts | tso_fts | vlan_fts;
	netdev->vlan_features |= dft_fts | cso_fts | tso_fts;

#ifdef HAVE_NDO_SET_U32_FEATURES
	hw_features |= get_netdev_hw_features(netdev);
#else
	hw_features |= netdev->hw_features;
#endif

	hw_features |= netdev->features;

#ifdef HAVE_NDO_SET_U32_FEATURES
	set_netdev_hw_features(netdev, hw_features);
#else
	netdev->hw_features = hw_features;
#endif

#ifdef IFF_UNICAST_FLT
	netdev->priv_flags |= IFF_UNICAST_FLT;
#endif

#ifdef HAVE_ENCAPSULATION_CSUM
	netdev->hw_enc_features |= dft_fts;
	if (HINIC5_SUPPORT_VXLAN_OFFLOAD(nic_dev->hwdev) ||
	    HINIC5_SUPPORT_GENEVE_OFFLOAD(nic_dev->hwdev)) {
		netdev->hw_enc_features |= cso_fts & (~NETIF_F_SCTP_CRC);
#ifdef HAVE_ENCAPSULATION_TSO
		netdev->hw_enc_features |= tso_fts | NETIF_F_TSO_ECN;
#endif /* HAVE_ENCAPSULATION_TSO */
	}

	/* When the chip does not support parsing IPinIP tunnel packets,
	 * disable the checksum offloading for inner SCTP.
	 */
	if (HINIC5_SUPPORT_IPXIP_OFFLOAD(nic_dev->hwdev))
		netdev->hw_enc_features |= NETIF_F_SCTP_CRC;
#endif /* HAVE_ENCAPSULATION_CSUM */
#ifdef HAVE_NETDEV_XDP_ACT_NDO_XMIT
	netdev->xdp_features = NETDEV_XDP_ACT_NDO_XMIT;
#endif /* HAVE_NETDEV_XDP_ACT_NDO_XMIT */
}

static void init_intr_coal_param(struct hinic5_nic_dev *nic_dev)
{
	struct hinic5_qp_coalesce_info *info = NULL;
	u16 i;

	for (i = 0; i < nic_dev->max_qps; i++) {
		info = &nic_dev->intr_coalesce[i];

		info->tx_pending_limt = qp_pending_limit;
		info->tx_coalesce_timer_cfg = qp_coalesc_timer_cfg;
		info->rx_pending_limt = qp_pending_limit;
		info->rx_coalesce_timer_cfg = qp_coalesc_timer_cfg;

		info->pkt_rate_high = HINIC5_RX_RATE_HIGH;
		info->rx_usecs_high = HINIC5_RX_COAL_TIME_HIGH;
		info->rx_pending_limt_high = HINIC5_RX_PENDING_LIMIT_HIGH;

		info->pkt_rate_low = HINIC5_RX_RATE_LOW;
		info->rx_usecs_low = HINIC5_RX_COAL_TIME_LOW;
		info->rx_pending_limt_low = HINIC5_RX_PENDING_LIMIT_LOW;
	}
}

static int hinic5_init_intr_coalesce(struct hinic5_nic_dev *nic_dev)
{
	u64 size;

	if (qp_pending_limit != HINIC5_DEAULT_TXRX_MSIX_PENDING_LIMIT ||
	    qp_coalesc_timer_cfg != HINIC5_DEAULT_TXRX_MSIX_COALESC_TIMER_CFG)
		nic_dev->intr_coal_set_flag = 1;
	else
		nic_dev->intr_coal_set_flag = 0;

	size = sizeof(*nic_dev->intr_coalesce) * nic_dev->max_qps;
	if (size == 0) {
		nic_err(nic_dev->lld_dev->dev, "Cannot allocate zero size intr coalesce\n");
		return -EINVAL;
	}
	nic_dev->intr_coalesce = kzalloc(size, GFP_KERNEL);
	if (!nic_dev->intr_coalesce)
		return -ENOMEM;

	init_intr_coal_param(nic_dev);

	if (test_bit(HINIC5_INTR_ADAPT, &nic_dev->flags) != 0)
		nic_dev->adaptive_rx_coal = 1;
	else
		nic_dev->adaptive_rx_coal = 0;

	return 0;
}

static void hinic5_free_intr_coalesce(struct hinic5_nic_dev *nic_dev)
{
	kfree(nic_dev->intr_coalesce);
	nic_dev->intr_coalesce = NULL;
}

static int hinic5_alloc_txrxqs(struct hinic5_nic_dev *nic_dev)
{
	struct net_device *netdev = nic_dev->netdev;
	int err;

	err = hinic5_alloc_txqs(netdev);
	if (err != 0) {
		nic_err(nic_dev->lld_dev->dev, "Failed to alloc txqs\n");
		return err;
	}

	err = hinic5_alloc_rxqs(netdev);
	if (err != 0) {
		nic_err(nic_dev->lld_dev->dev, "Failed to alloc rxqs\n");
		goto alloc_rxqs_err;
	}

	err = hinic5_init_intr_coalesce(nic_dev);
	if (err != 0) {
		nic_err(nic_dev->lld_dev->dev, "Failed to init_intr_coalesce\n");
		goto init_intr_err;
	}

	return 0;

init_intr_err:
	hinic5_free_rxqs(netdev);

alloc_rxqs_err:
	hinic5_free_txqs(netdev);

	return err;
}

static void hinic5_free_txrxqs(struct hinic5_nic_dev *nic_dev)
{
	hinic5_free_intr_coalesce(nic_dev);
	hinic5_free_rxqs(nic_dev->netdev);
	hinic5_free_txqs(nic_dev->netdev);
}

static void hinic5_sw_deinit(struct hinic5_nic_dev *nic_dev)
{
	hinic5_free_txrxqs(nic_dev);

	hinic5_clean_mac_list_filter(nic_dev);

	hinic5_del_mac(nic_dev->hwdev, nic_dev->netdev->dev_addr, 0,
		       hinic5_global_func_id(nic_dev->hwdev),
		       HINIC5_CHANNEL_NIC);

	hinic5_clear_rss_config(nic_dev);

	if (test_bit(HINIC5_DCB_ENABLE, &nic_dev->flags))
		hinic5_sync_dcb_state(nic_dev->hwdev, 1, 0);
}

static inline int invalid_mac_address(struct hinic5_nic_dev *nic_dev)
{
	if (!is_valid_ether_addr(nic_dev->netdev->dev_addr)) {
		if (!HINIC5_FUNC_IS_VF(nic_dev->hwdev))
			return -EIO;
		nic_info(nic_dev->lld_dev->dev, "Invalid MAC address %pM, using random\n",
			 nic_dev->netdev->dev_addr);
		eth_hw_addr_random(nic_dev->netdev);
	}
	return 0;
}

static void hinic5_sw_mtu_range_init(struct net_device *netdev)
{
	/* MTU range: 256 - 9600 */
#ifdef HAVE_NETDEVICE_MIN_MAX_MTU
	netdev->min_mtu = HINIC5_MIN_MTU_SIZE;
	netdev->max_mtu = HINIC5_MAX_JUMBO_FRAME_SIZE;
#endif

#ifdef HAVE_NETDEVICE_EXTENDED_MIN_MAX_MTU
	netdev->extended->min_mtu = HINIC5_MIN_MTU_SIZE;
	netdev->extended->max_mtu = HINIC5_MAX_JUMBO_FRAME_SIZE;
#endif
}

static void hinic5_tx_rx_ops_init(struct hinic5_nic_dev *nic_dev)
{
	nic_dev->tx_wqe_compact_task = HINIC5_SUPPORT_TX_WQE_COMPACT_TASK(nic_dev->hwdev);

	if (HINIC5_SUPPORT_TX_WQE_COMPACT_TASK(nic_dev->hwdev))
		nic_dev->tx_rx_ops.tx_set_wqe_offload = hinic5_tx_set_compact_task_offload;
	else
		nic_dev->tx_rx_ops.tx_set_wqe_offload = hinic5_tx_set_normal_task_offload;

	if (hinic5_get_rq_wqe_type(nic_dev->hwdev) == HINIC5_COMPACT_RQ_WQE) {
		/* 1825/1872 integrated CQE */
		nic_dev->tx_rx_ops.rx_get_cqe_info = hinic5_rx_get_compact_cqe_info;
		nic_dev->cqe_mode = HINIC5_RQ_CQE_INTEGRATE;
		nic_dev->tx_rx_ops.rx_cqe_done = hinic5_rx_integrated_cqe_done;
	} else if (HINIC5_SUPPORT_RX_HW_COMPACT_CQE(nic_dev->hwdev)) {
		/* 1872 separate CQE */
		nic_dev->tx_rx_ops.rx_get_cqe_info = hinic5_rx_get_compact_cqe_info;
		nic_dev->cqe_mode = HINIC5_RQ_CQE_SEPARATE;
		nic_dev->tx_rx_ops.rx_cqe_done = hinic5_rx_separate_cqe_done;
	} else {
		/* 1823/1825 separate CQE */
		nic_dev->tx_rx_ops.rx_get_cqe_info = hinic5_rx_get_cqe_info;
		nic_dev->cqe_mode = HINIC5_RQ_CQE_SEPARATE;
		nic_dev->tx_rx_ops.rx_cqe_done = hinic5_rx_separate_cqe_done;
	}
}

static void hinic5_set_hw_default_cos(struct hinic5_nic_dev *nic_dev)
{
	u8 hw_default_cos;

	hw_default_cos = hinic5_func_dev_default_cos(nic_dev->hwdev);
	nic_dev->hw_default_cos_valid = HW_DEFAULT_COS_IS_VALID(hw_default_cos);
	nic_dev->hw_default_cos = hw_default_cos & HW_DEFAULT_COS_VALID_BIT;
}

static int hinic5_sw_init(struct hinic5_nic_dev *nic_dev)
{
	struct net_device *netdev = nic_dev->netdev;
	u64 nic_features;
	u8 mac_temp[ETH_ALEN];
	int err = 0;

	nic_features = hinic5_get_feature_cap(nic_dev->hwdev);
	/* You can update the features supported by the driver according to the
	 * scenario here
	 */
	hinic5_update_nic_feature(nic_dev->hwdev, nic_features & NIC_DRV_DEFAULT_FEATURE);

	sema_init(&nic_dev->port_state_sem, 1);

	nic_dev->cos_mask_mode = hinic5_func_cos_mask_mode(nic_dev->hwdev);

	hinic5_set_hw_default_cos(nic_dev);

	err = hinic5_dcb_init(nic_dev);
	if (err != 0) {
		nic_err(nic_dev->lld_dev->dev, "Failed to init dcb\n");
		return -EFAULT;
	}

	nic_dev->q_params.sq_depth = HINIC5_SQ_DEPTH;
	nic_dev->q_params.rq_depth = HINIC5_RQ_DEPTH;

	hinic5_try_to_enable_rss(nic_dev);

	err = hinic5_get_default_mac(nic_dev->hwdev, mac_temp);
	if (err != 0) {
		nic_err(nic_dev->lld_dev->dev, "Failed to get MAC address\n");
		goto err_mac;
	}

	hinic5_eth_hw_addr_set(nic_dev->netdev, mac_temp);

	err = invalid_mac_address(nic_dev);
	if (err != 0) {
		nic_err(nic_dev->lld_dev->dev, "Invalid MAC address %pM\n", netdev->dev_addr);
		goto err_mac;
	}

	err = hinic5_set_mac(nic_dev->hwdev, netdev->dev_addr, 0,
			     hinic5_global_func_id(nic_dev->hwdev), HINIC5_CHANNEL_NIC);
	/* When this is VF driver, we must consider that PF has already set VF
	 * MAC, and we can't consider this condition is error status during
	 * driver probe procedure.
	 */
	if (err != 0 && err != HINIC5_PF_SET_VF_ALREADY) {
		nic_err(nic_dev->lld_dev->dev, "Failed to set default MAC\n");
		goto err_mac;
	}

	hinic5_sw_mtu_range_init(netdev);

	err = hinic5_alloc_txrxqs(nic_dev);
	if (err != 0) {
		nic_err(nic_dev->lld_dev->dev, "Failed to alloc qps\n");
		goto alloc_qps_err;
	}

	hinic5_tx_rx_ops_init(nic_dev);

	return 0;

alloc_qps_err:
	hinic5_del_mac(nic_dev->hwdev, netdev->dev_addr, 0,
		       hinic5_global_func_id(nic_dev->hwdev),
		HINIC5_CHANNEL_NIC);

err_mac:
	hinic5_clear_rss_config(nic_dev);

	return err;
}

static void hinic5_assign_netdev_ops(struct hinic5_nic_dev *adapter)
{
	hinic5_set_netdev_ops(adapter);
	if (!HINIC5_FUNC_IS_VF(adapter->hwdev))
		hinic5_set_ethtool_ops(adapter->netdev);
	else
		hinic5vf_set_ethtool_ops(adapter->netdev);

	adapter->netdev->watchdog_timeo = WATCHDOG_TIMEOUT * HZ;
}

static int hinic5_validate_parameters(struct hinic5_lld_dev *lld_dev)
{
	/* If weight exceeds the queue depth, the queue resources will be
	 * exhausted, and increasing it has no effect.
	 */

	hinic5_main_param_validate();
	hinic5_nic_io_param_validate();

	return 0;
}

static void decide_intr_cfg(struct hinic5_nic_dev *nic_dev)
{
	set_bit(HINIC5_INTR_ADAPT, &nic_dev->flags);
}

static void adaptive_configuration_init(struct hinic5_nic_dev *nic_dev)
{
	decide_intr_cfg(nic_dev);
}

static int set_interrupt_moder(struct hinic5_nic_dev *nic_dev, u16 q_id,
			       u8 coalesc_timer_cfg, u8 pending_limt)
{
	struct hinic5_qp_coalesce_info coalesce_info;
	int err;

	if (coalesc_timer_cfg == nic_dev->rxqs[q_id].last_coalesc_timer_cfg &&
	    pending_limt == nic_dev->rxqs[q_id].last_pending_limt)
		return 0;

	/* netdev not running or qp not in using,
	 * don't need to set coalesce to hw
	 */
	if (!HINIC5_CHANNEL_RES_VALID(nic_dev) ||
	    q_id >= nic_dev->q_params.num_qps)
		return 0;

	memset(&coalesce_info, 0, sizeof(coalesce_info));
	coalesce_info.rx_coalesce_timer_cfg = coalesc_timer_cfg;
	coalesce_info.rx_pending_limt = pending_limt;
	coalesce_info.tx_coalesce_timer_cfg = coalesc_timer_cfg;
	coalesce_info.tx_pending_limt = pending_limt;

	err = hinic5_set_sq_rq_coalesce_cfg(nic_dev->hwdev, q_id, HINIC5_SQ_RQ_COALESCE,
					    &coalesce_info);
	if (err != 0) {
		nicif_err(nic_dev, drv, nic_dev->netdev,
			  "Failed to modify moderation for Queue: %u\n", q_id);
	} else {
		nic_dev->rxqs[q_id].last_coalesc_timer_cfg = coalesc_timer_cfg;
		nic_dev->rxqs[q_id].last_pending_limt = pending_limt;
	}

	return err;
}

static void calc_coal_para(struct hinic5_nic_dev *nic_dev,
			   struct hinic5_qp_coalesce_info *q_coal, u64 rx_rate,
			   u8 *coalesc_timer_cfg, u8 *pending_limt)
{
	if (rx_rate < q_coal->pkt_rate_low) {
		*coalesc_timer_cfg = q_coal->rx_usecs_low;
		*pending_limt = q_coal->rx_pending_limt_low;
	} else if (rx_rate > q_coal->pkt_rate_high) {
		*coalesc_timer_cfg = q_coal->rx_usecs_high;
		*pending_limt = q_coal->rx_pending_limt_high;
	} else {
		*coalesc_timer_cfg =
			(u8)((rx_rate - q_coal->pkt_rate_low) *
			     (q_coal->rx_usecs_high - q_coal->rx_usecs_low) /
			     (q_coal->pkt_rate_high - q_coal->pkt_rate_low) +
			     q_coal->rx_usecs_low);

		*pending_limt =
			(u8)((rx_rate - q_coal->pkt_rate_low) *
			     (q_coal->rx_pending_limt_high - q_coal->rx_pending_limt_low) /
			     (q_coal->pkt_rate_high - q_coal->pkt_rate_low) +
			     q_coal->rx_pending_limt_low);
	}
}

static void update_queue_coal(struct hinic5_nic_dev *nic_dev, u16 qid,
			      u64 rx_rate, u64 avg_pkt_size, u64 tx_rate)
{
	struct hinic5_qp_coalesce_info *q_coal = NULL;
	u8 coalesc_timer_cfg, pending_limt;

	q_coal = &nic_dev->intr_coalesce[qid];

	if (rx_rate > HINIC5_RX_RATE_THRESH && avg_pkt_size > HINIC5_AVG_PKT_SMALL) {
		calc_coal_para(nic_dev, q_coal, rx_rate, &coalesc_timer_cfg, &pending_limt);
	} else {
		coalesc_timer_cfg = HINIC5_LOWEST_LATENCY;
		pending_limt = q_coal->rx_pending_limt_low;
	}

	set_interrupt_moder(nic_dev, qid, coalesc_timer_cfg, pending_limt);
}

void hinic5_auto_moderation_work(struct work_struct *work)
{
	struct delayed_work *delay = to_delayed_work(work);
	struct hinic5_nic_dev *nic_dev = container_of(delay,
						      struct hinic5_nic_dev,
						      moderation_task);
	unsigned long period = (unsigned long)(jiffies -
		nic_dev->last_moder_jiffies);
	u64 rx_packets, rx_bytes, rx_pkt_diff, rx_rate, avg_pkt_size;
	u64 tx_packets, tx_bytes, tx_pkt_diff, tx_rate;
	u16 qid;

	if (test_bit(HINIC5_INTF_UP, &nic_dev->flags) == 0)
		return;

	queue_delayed_work(nic_dev->workq, &nic_dev->moderation_task,
			   HINIC5_MODERATONE_DELAY);

	if (nic_dev->adaptive_rx_coal == 0 || period == 0)
		return;

	for (qid = 0; qid < nic_dev->q_params.num_qps; qid++) {
		rx_packets = nic_dev->rxqs[qid].rxq_stats.packets;
		rx_bytes = nic_dev->rxqs[qid].rxq_stats.bytes;
		tx_packets = nic_dev->txqs[qid].txq_stats.packets;
		tx_bytes = nic_dev->txqs[qid].txq_stats.bytes;

		rx_pkt_diff =
			rx_packets - nic_dev->rxqs[qid].last_moder_packets;
		avg_pkt_size = (rx_pkt_diff != 0) ?
			((unsigned long)(rx_bytes -
			 nic_dev->rxqs[qid].last_moder_bytes)) /
			 rx_pkt_diff : 0;

		rx_rate = rx_pkt_diff * HZ / period;
		tx_pkt_diff =
			tx_packets - nic_dev->txqs[qid].last_moder_packets;
		tx_rate = tx_pkt_diff * HZ / period;

		update_queue_coal(nic_dev, qid, rx_rate, avg_pkt_size,
				  tx_rate);

		nic_dev->rxqs[qid].last_moder_packets = rx_packets;
		nic_dev->rxqs[qid].last_moder_bytes = rx_bytes;
		nic_dev->txqs[qid].last_moder_packets = tx_packets;
		nic_dev->txqs[qid].last_moder_bytes = tx_bytes;
	}

	nic_dev->last_moder_jiffies = jiffies;
}

static void hinic5_periodic_work_handler(struct work_struct *work)
{
	struct delayed_work *delay = to_delayed_work(work);
	struct hinic5_nic_dev *nic_dev = container_of(delay, struct hinic5_nic_dev, periodic_work);

	if (test_and_clear_bit(EVENT_WORK_TX_TIMEOUT, &nic_dev->event_flag) != 0)
		hinic5_fault_event_report(nic_dev->hwdev, HINIC5_FAULT_SRC_TX_TIMEOUT,
					  FAULT_LEVEL_SERIOUS_FLR);

	queue_delayed_work(nic_dev->workq, &nic_dev->periodic_work, HZ);
}

void hinic5_arp_dual_work(struct work_struct *work)
{
	int ret;
	struct hinic5_nic_dev *nic_dev =
			container_of(work, struct hinic5_nic_dev, arp_dual_work);
	struct sk_buff *skb = NULL;
	struct hinic5_arp_pkt_info info = {0};
	struct hinic5_txq *txq = NULL;
	u16 q_id;
	u32 pkt_len;

	while ((skb = skb_dequeue(&nic_dev->arp_queue)) != NULL) {
		q_id = skb_get_queue_mapping(skb);
		pkt_len = skb->len;
		info.pkt_length = (u16)skb->len;
		info.origin_queue_id = q_id;
		info.func_id = hinic5_global_func_id(nic_dev->hwdev);

		if (pkt_len > HINIC5_ARP_PKT_MAX_LEN) {
			kfree_skb(skb);
			txq = &nic_dev->txqs[q_id];
			u64_stats_update_begin(&txq->txq_stats.syncp);
			txq->txq_stats.dropped++;
			u64_stats_update_end(&txq->txq_stats.syncp);
			continue;
		}
		ret = skb_copy_bits(skb, 0, info.pkt_buf, (int)pkt_len);
		if (ret < 0) {
			kfree_skb(skb);
			nic_err(nic_dev->lld_dev->dev, "Copy skb failed, ret:%d.\n", ret);
			continue;
		}
		kfree_skb(skb);

		ret = hinic5_send_arp_to_mpu(nic_dev->hwdev, &info);
		if (ret < 0)
			nic_err(nic_dev->lld_dev->dev, "Send ARP to mpu failed, ret:%d.\n", ret);
	}
}

void hinic5_update_stats_work(struct work_struct *work)
{
	int ret = 0;
	struct hinic5_nic_dev *nic_dev =
			container_of(work, struct hinic5_nic_dev, update_stats_work);

	ret = hinic5_get_vport_stats(nic_dev->hwdev, hinic5_global_func_id(nic_dev->hwdev),
				     &nic_dev->vport_stats);
	if (ret != 0)
		nic_err(nic_dev->lld_dev->dev, "Failed to get function stats from fw, ret:%d.\n", ret);
	return;
}

static int init_nic_dev_hinic5_vram(struct hinic5_nic_dev *nic_dev)
{
	int is_in_kexec = hinic5_vram_get_kexec_flag();
	int is_use_hinic5_vram = get_use_hinic5_vram_flag();
	u16 func_id;
	int ret;

	if (is_use_hinic5_vram != 0) {
		func_id = hinic5_global_func_id(nic_dev->hwdev);
		ret = snprintf(nic_dev->nic_hinic5_vram_name, HINIC5_VRAM_NAME_MAX_LEN,
			       "%s%hu", HINIC5_VRAM_NIC_HINIC5_VRAM, func_id);
		if (ret < 0) {
			nic_err(nic_dev->lld_dev->dev,
				"NIC hinic5_vram name snprintf_s failed, ret:%d.\n", ret);
			return -EINVAL;
		}

		nic_dev->nic_hinic5_vram =
			(struct hinic5_hinic5_vram *)
			hinic5_hinic5_vram_kalloc(nic_dev->nic_hinic5_vram_name,
						  sizeof(struct hinic5_hinic5_vram));
		if (!nic_dev->nic_hinic5_vram) {
			nic_err(nic_dev->lld_dev->dev, "Failed to allocate nic hinic5_vram\n");
			return -ENOMEM;
		}

		if (is_in_kexec == 0)
			nic_dev->nic_hinic5_vram->hinic5_vram_mtu = nic_dev->netdev->mtu;
		else
			nic_dev->netdev->mtu = nic_dev->nic_hinic5_vram->hinic5_vram_mtu;
	} else {
		nic_dev->nic_hinic5_vram = kzalloc(sizeof(struct hinic5_hinic5_vram), GFP_KERNEL);
		if (!nic_dev->nic_hinic5_vram)
			return -ENOMEM;
		nic_dev->nic_hinic5_vram->hinic5_vram_mtu = nic_dev->netdev->mtu;
	}

	return 0;
}

static void free_nic_dev_hinic5_vram(struct hinic5_nic_dev *nic_dev)
{
	int is_use_hinic5_vram = get_use_hinic5_vram_flag();

	if (is_use_hinic5_vram != 0)
		hinic5_hinic5_vram_kfree((void *)nic_dev->nic_hinic5_vram,
					 nic_dev->nic_hinic5_vram_name,
					 sizeof(struct hinic5_hinic5_vram));
	else
		kfree(nic_dev->nic_hinic5_vram);
	nic_dev->nic_hinic5_vram = NULL;
}

static void free_nic_dev(struct hinic5_nic_dev *nic_dev)
{
	destroy_workqueue(nic_dev->workq);
	kfree(nic_dev->vlan_bitmap);
	nic_dev->vlan_bitmap = NULL;
	free_nic_dev_hinic5_vram(nic_dev);
}

static void nic_dev_init(struct hinic5_nic_dev *nic_dev, struct net_device *netdev,
			 struct hinic5_lld_dev *lld_dev)
{
	u8 rx_buff_per_page = RX_BUFF_NUM_PER_PAGE;
	u32 page_num;

#ifdef HAVE_PAGE_POOL_SUPPORT
	/* If page pool is enabled, page reuse not supported */
	rx_buff_per_page = page_pool_enabled ? 1 : RX_BUFF_NUM_PER_PAGE;
#endif

	nic_dev->netdev = netdev;
	SET_NETDEV_DEV(netdev, lld_dev->dev);
	nic_dev->lld_dev = lld_dev;
	nic_dev->hwdev = lld_dev->hwdev;
	nic_dev->poll_weight = (int)poll_weight;
	nic_dev->msg_enable = DEFAULT_MSG_ENABLE;
	nic_dev->lro_replenish_thld = lro_replenish_thld;
	nic_dev->rx_buff_len = (u16)(hinic5_rx_buff * CONVERT_UNIT);
	nic_dev->dma_rx_buff_size = rx_buff_per_page * nic_dev->rx_buff_len;
	page_num = nic_dev->dma_rx_buff_size / PAGE_SIZE;
	nic_dev->page_order = (page_num > 0) ? ilog2(page_num) : 0;
	nic_dev->page_pool_enabled = page_pool_enabled;
	nic_dev->support_htn = hinic5_support_htn(nic_dev->hwdev);
}

static void init_list_head(struct hinic5_nic_dev *nic_dev)
{
	INIT_LIST_HEAD(&nic_dev->uc_filter_list);
	INIT_LIST_HEAD(&nic_dev->mc_filter_list);
	INIT_LIST_HEAD(&nic_dev->rx_flow_rule.rules);
	INIT_LIST_HEAD(&nic_dev->tcam.tcam_list);
	INIT_LIST_HEAD(&nic_dev->tcam.tcam_dynamic_info.tcam_dynamic_list);
}

static int setup_nic_dev(struct net_device *netdev,
			 struct hinic5_lld_dev *lld_dev)
{
	struct hinic5_nic_dev *nic_dev = (struct hinic5_nic_dev *)netdev_priv(netdev);
	int ret;

	nic_dev_init(nic_dev, netdev, lld_dev);

	ret = init_nic_dev_hinic5_vram(nic_dev);
	if (ret != 0)
		return ret;

	mutex_init(&nic_dev->nic_mutex);

	nic_dev->vlan_bitmap = kzalloc(VLAN_BITMAP_SIZE(nic_dev), GFP_KERNEL);
	if (nic_dev->vlan_bitmap == 0) {
		nic_err(lld_dev->dev, "Failed to allocate vlan bitmap\n");
		ret = -ENOMEM;
		goto vlan_bitmap_error;
	}

	nic_dev->workq = create_singlethread_workqueue(HINIC5_NIC_DEV_WQ_NAME);
	if (!nic_dev->workq) {
		nic_err(lld_dev->dev, "Failed to initialize nic workqueue\n");
		ret = -ENOMEM;
		goto create_workq_error;
	}

	INIT_DELAYED_WORK(&nic_dev->periodic_work, hinic5_periodic_work_handler);
	INIT_DELAYED_WORK(&nic_dev->rxq_check_work, hinic5_rxq_check_work_handler);
	init_list_head(nic_dev);
	skb_queue_head_init(&nic_dev->arp_queue);
	INIT_WORK(&nic_dev->rx_mode_work, hinic5_set_rx_mode_work);
	INIT_WORK(&nic_dev->arp_dual_work, hinic5_arp_dual_work);
	INIT_WORK(&nic_dev->update_stats_work, hinic5_update_stats_work);

	return 0;

create_workq_error:
	kfree(nic_dev->vlan_bitmap);
	nic_dev->vlan_bitmap = NULL;
vlan_bitmap_error:
	free_nic_dev_hinic5_vram(nic_dev);
	return ret;
}

static int hinic5_set_default_hw_feature(struct hinic5_nic_dev *nic_dev)
{
	int err;

	if (!HINIC5_FUNC_IS_VF(nic_dev->hwdev)) {
		hinic5_dcb_reset_hw_config(nic_dev);

		if (set_link_status_follow < HINIC5_LINK_FOLLOW_STATUS_MAX) {
			err = hinic5_set_link_status_follow(nic_dev->hwdev,
							    set_link_status_follow);
			if (err == HINIC5_MGMT_CMD_UNSUPPORTED)
				nic_warn(nic_dev->lld_dev->dev,
					 "Current version of firmware doesn't support to set link status follow port status\n");
		}
	}

	err = hinic5_set_nic_feature_to_hw(nic_dev->hwdev);
	if (err != 0) {
		nic_err(nic_dev->lld_dev->dev, "Failed to set nic features\n");
		return err;
	}

	/* enable all hw features in netdev->features */
	err = hinic5_set_hw_features(nic_dev);
	if (err != 0) {
		hinic5_update_nic_feature(nic_dev->hwdev, 0);
		hinic5_set_nic_feature_to_hw(nic_dev->hwdev);
		return err;
	}

	if (HINIC5_SUPPORT_RXQ_RECOVERY(nic_dev->hwdev) != 0)
		set_bit(HINIC5_RXQ_RECOVERY, &nic_dev->flags);

	return 0;
}

static int nic_init_for_hotreplace(struct hinic5_lld_dev *lld_dev, struct hinic5_nic_dev *nic_dev)
{
	int is_use_hinic5_vram = get_use_hinic5_vram_flag();
	int is_in_kexec = hinic5_vram_get_kexec_flag();
	int err;

	/* register netdev flush ops, required only in sdinanoos hotreplace */
	if (is_use_hinic5_vram != 0) {
		err = hiudk5_register_flush_fn(lld_dev, hinic5_flush_nic_dev);
		if (err != 0) {
			nic_err(lld_dev->dev, "Failed to register netdev flush ops, err:%d.\n",
				err);
			return err;
		}
	}

	if (is_in_kexec != 0 &&
	    test_bit(HINIC5_DCB_ENABLE, &nic_dev->nic_hinic5_vram->flags) != 0) {
		err = hinic5_configure_dcb_hw(nic_dev, 1);
		if (err != 0) {
			nic_err(lld_dev->dev, "Failed to enable dcb during sdinanoos-hotreplace\n");
			hiudk5_unregister_flush_fn(lld_dev);
			return err;
		}
		nic_info(lld_dev->dev, "Enable dcb success during sdinanoos-hotreplace\n");
	}

	return 0;
}

#define hinic5_set_dpath_timeout(nic_dev, hw_type) { \
	(nic_dev)->timeout.wait_flush_qp_res_timeout = \
					HINIC5_GET_TIMEOUT(hw_type, WAIT_FLUSH_QP_RESOURCE); \
}

static void hinic5_init_dpath_timeout(struct hinic5_nic_dev *nic_dev)
{
	u8 hw_type;

	hw_type = hinic5_get_hw_type(nic_dev->hwdev);
	if (hw_type == HINIC5_HW_TYPE_FPGA) {
		hinic5_set_dpath_timeout(nic_dev, FPGA);
	} else if (hw_type == HINIC5_HW_TYPE_ASIC) {
		hinic5_set_dpath_timeout(nic_dev, ASIC);
	} else if (hw_type == HINIC5_HW_TYPE_EMU) {
		hinic5_set_dpath_timeout(nic_dev, EMU);
	} else if (hw_type == HINIC5_HW_TYPE_EDA) {
		hinic5_set_dpath_timeout(nic_dev, EDA);
	} else {
		hinic5_set_dpath_timeout(nic_dev, FPGA);
	}
}

__weak int hinic5_probe_extend_hook(struct net_device *netdev)
{
	return 0;
}

__weak void hinic5_remove_extend_hook(struct net_device *netdev)
{
}

static int nic_probe(struct hinic5_lld_dev *lld_dev, void **uld_dev,
		     char *uld_dev_name)
{
	struct hinic5_nic_dev *nic_dev = NULL;
	struct net_device *netdev = NULL;
	u16 glb_func_id;
	int err;

	if (!hinic5_support_nic(lld_dev->hwdev, NULL)) {
		nic_info(lld_dev->dev, "Hw don't support nic\n");
		return 0;
	}

	nic_info(lld_dev->dev, "NIC service probe begin\n");

	err = hinic5_validate_parameters(lld_dev);
	if (err != 0)
		goto err_out;

	glb_func_id = hinic5_global_func_id(lld_dev->hwdev);
	err = hinic5_func_reset(lld_dev->hwdev, glb_func_id, HINIC5_NIC_RES, HINIC5_CHANNEL_NIC);
	if (err != 0) {
		nic_err(lld_dev->dev, "Failed to reset function\n");
		goto err_out;
	}

	netdev = alloc_etherdev_mq(sizeof(*nic_dev), hinic5_func_max_nic_qnum(lld_dev->hwdev));
	if (!netdev) {
		nic_err(lld_dev->dev, "Failed to allocate ETH device\n");
		err = -ENOMEM;
		goto err_out;
	}

	nic_dev = (struct hinic5_nic_dev *)netdev_priv(netdev);
	err = setup_nic_dev(netdev, lld_dev);
	if (err != 0)
		goto setup_dev_err;

	adaptive_configuration_init(nic_dev);

	hinic5_init_dpath_timeout(nic_dev);

	/* get nic cap from hw */
	hinic5_support_nic(lld_dev->hwdev, &nic_dev->nic_cap);

	err = hinic5_init_nic_hwdev(nic_dev->hwdev, lld_dev->dev, nic_dev->rx_buff_len);
	if (err != 0) {
		nic_err(lld_dev->dev, "Failed to init nic hwdev\n");
		goto init_nic_hwdev_err;
	}

	err = hinic5_sw_init(nic_dev);
	if (err != 0)
		goto sw_init_err;
	hinic5_assign_netdev_ops(nic_dev);
	netdev_feature_init(netdev);
#ifdef HAVE_UDP_TUNNEL_NIC_INFO
	netdev->udp_tunnel_nic_info = &hinic5_udp_tunnels;
#endif /* HAVE_UDP_TUNNEL_NIC_INFO */
	err = hinic5_set_default_hw_feature(nic_dev);
	if (err != 0)
		goto set_features_err;

	err = hinic5_probe_extend_hook(netdev);
	if (err != 0)
		goto probe_hook_err;

	if (register_netdev(netdev) != 0) {
		nic_err(lld_dev->dev, "Failed to register netdev\n");
		err = -ENOMEM;
		goto netdev_err;
	}

#ifdef HAVE_MULTI_VLAN_OFFLOAD_EN
	hinic5_register_notifier(nic_dev);
#endif

	queue_delayed_work(nic_dev->workq, &nic_dev->periodic_work, HZ);
	netif_carrier_off(netdev);

	hinic5_ptp_init(nic_dev);

#if (KERNEL_VERSION(5, 1, 1) <= LINUX_VERSION_CODE)
	if (HINIC5_SUPPORT_FEATURE(nic_dev->hwdev, TC_FLOWER_OFFLOAD)) {
		err = hinic5_init_tc(nic_dev);
		if (err != 0)
			goto hinic5_init_tc_err;
	}
#endif

	if (macsec_enabled && HINIC5_SUPPORT_FEATURE(nic_dev->hwdev, MACSEC_OFFLOAD)) {
		err = macsec_init_offload(nic_dev);
		if (err != 0)
			goto hinic5_init_macsec_err;
	}

	err = nic_init_for_hotreplace(lld_dev, nic_dev);
	if (err != 0)
		goto init_hotreplace_err;

	*uld_dev = nic_dev;

	nicif_info(nic_dev, probe, netdev, "Register netdev succeed\n");
	nic_info(lld_dev->dev, "NIC service probed\n");

	return 0;

init_hotreplace_err:
	if (macsec_enabled && HINIC5_SUPPORT_FEATURE(nic_dev->hwdev, MACSEC_OFFLOAD))
		macsec_cleanup_offload(nic_dev);

hinic5_init_macsec_err:
#if (KERNEL_VERSION(5, 1, 1) <= LINUX_VERSION_CODE)
	if (HINIC5_SUPPORT_FEATURE(nic_dev->hwdev, TC_FLOWER_OFFLOAD))
		hinic5_deinit_tc(nic_dev);
hinic5_init_tc_err:
#endif
	hinic5_ptp_deinit(nic_dev);

	unregister_netdev(netdev);
netdev_err:
	hinic5_remove_extend_hook(netdev);
probe_hook_err:
#ifdef HAVE_MULTI_VLAN_OFFLOAD_EN
	hinic5_unregister_notifier(nic_dev);
#endif
	hinic5_update_nic_feature(nic_dev->hwdev, 0);
	hinic5_set_nic_feature_to_hw(nic_dev->hwdev);

set_features_err:
	hinic5_sw_deinit(nic_dev);

sw_init_err:
	hinic5_free_nic_hwdev(nic_dev->hwdev);

init_nic_hwdev_err:
	free_nic_dev(nic_dev);
setup_dev_err:
	free_netdev(netdev);

err_out:
	nic_err(lld_dev->dev, "NIC service probe failed\n");

	return err;
}

static void nic_remove(struct hinic5_lld_dev *lld_dev, void *adapter)
{
	struct hinic5_nic_dev *nic_dev = adapter;
	struct net_device *netdev = NULL;
	int is_use_hinic5_vram = get_use_hinic5_vram_flag();

	if (!nic_dev || !hinic5_support_nic(lld_dev->hwdev, NULL))
		return;

	nic_info(lld_dev->dev, "NIC service remove begin\n");

	hinic5_ptp_deinit(nic_dev);

	netdev = nic_dev->netdev;

	if (macsec_enabled && HINIC5_SUPPORT_FEATURE(nic_dev->hwdev, MACSEC_OFFLOAD))
		macsec_cleanup_offload(nic_dev);

#if (KERNEL_VERSION(5, 1, 1) <= LINUX_VERSION_CODE)
	if (HINIC5_SUPPORT_FEATURE(nic_dev->hwdev, TC_FLOWER_OFFLOAD))
		hinic5_deinit_tc(nic_dev);
#endif

#ifdef HAVE_XDP_SUPPORT
	nic_dev->remove_flag = true;
#endif
	/* Unregister the network device using kernel function,
	 * and release queues, xdp programs and other related resources
	 */
	unregister_netdev(netdev);

#ifdef HAVE_XDP_SUPPORT
	nic_dev->remove_flag = false;
#endif

	hinic5_remove_extend_hook(netdev);

#ifdef HAVE_MULTI_VLAN_OFFLOAD_EN
	hinic5_unregister_notifier(nic_dev);
#endif

	cancel_delayed_work_sync(&nic_dev->periodic_work);
	cancel_delayed_work_sync(&nic_dev->rxq_check_work);
	cancel_work_sync(&nic_dev->rx_mode_work);
	cancel_work_sync(&nic_dev->arp_dual_work);
	cancel_work_sync(&nic_dev->update_stats_work);
	skb_queue_purge(&nic_dev->arp_queue);
	destroy_workqueue(nic_dev->workq);

	hinic5_flush_rx_flow_rule(nic_dev);

	hinic5_update_nic_feature(nic_dev->hwdev, 0);
	hinic5_set_nic_feature_to_hw(nic_dev->hwdev);

	hinic5_sw_deinit(nic_dev);

	hinic5_free_nic_hwdev(nic_dev->hwdev);

	kfree(nic_dev->vlan_bitmap);
	nic_dev->vlan_bitmap = NULL;

	if (is_use_hinic5_vram != 0)
		hinic5_hinic5_vram_kfree((void *)nic_dev->nic_hinic5_vram,
					 nic_dev->nic_hinic5_vram_name,
					 sizeof(struct hinic5_hinic5_vram));
	else
		kfree(nic_dev->nic_hinic5_vram);

	free_netdev(netdev);

	if (is_use_hinic5_vram != 0)
		hiudk5_unregister_flush_fn(lld_dev);

	nic_info(lld_dev->dev, "NIC service removed\n");
}

static void sriov_state_change(struct hinic5_nic_dev *nic_dev,
			       const struct hinic5_sriov_state_info *info)
{
	/* todo: ubus scenario support to disable a single VF,
	 * nic_dev records the actual active VF count, PCIe and ubus logic should be unified
	 */
	if (info->enable == 0)
		hinic5_clear_vfs_info(nic_dev->hwdev, info->vf_id, info->vf_id);
}

static void hinic5_port_module_event_handler(struct hinic5_nic_dev *nic_dev,
					     struct hinic5_event_info *event)
{
	const char *g_hinic5_module_link_err[LINK_ERR_NUM] = { "Unrecognized module" };
	struct hinic5_port_module_event *module_event = (void *)event->event_data;
	enum port_module_event_type type = module_event->type;
	enum link_err_type err_type = module_event->err_type;

	switch (type) {
	case HINIC5_PORT_MODULE_CABLE_PLUGGED:
	case HINIC5_PORT_MODULE_CABLE_UNPLUGGED:
		nicif_info(nic_dev, link, nic_dev->netdev,
			   "Port module event: Cable %s\n",
			   type == HINIC5_PORT_MODULE_CABLE_PLUGGED ?
			   "plugged" : "unplugged");
		break;
	case HINIC5_PORT_MODULE_LINK_ERR:
		if (err_type >= LINK_ERR_NUM) {
			nicif_info(nic_dev, link, nic_dev->netdev,
				   "Link failed, Unknown error type: 0x%x\n",
				   err_type);
		} else {
			nicif_info(nic_dev, link, nic_dev->netdev,
				   "Link failed, error type: 0x%x: %s\n",
				   err_type,
				   g_hinic5_module_link_err[err_type]);
		}
		break;
	default:
		nicif_err(nic_dev, link, nic_dev->netdev,
			  "Unknown port module type %d\n", type);
		break;
	}
}

static void nic_event(struct hinic5_lld_dev *lld_dev, void *adapter,
		      struct hinic5_event_info *event)
{
	struct hinic5_nic_dev *nic_dev = adapter;
	struct hinic5_fault_event *fault = NULL;

	if (!nic_dev || !event || !hinic5_support_nic(lld_dev->hwdev, NULL))
		return;

	switch (HINIC5_SRV_EVENT_TYPE(event->service, event->type)) {
	case HINIC5_SRV_EVENT_TYPE(EVENT_SRV_NIC, EVENT_NIC_LINK_DOWN):
		hinic5_link_status_change(nic_dev, false);
		break;
	case HINIC5_SRV_EVENT_TYPE(EVENT_SRV_NIC, EVENT_NIC_LINK_UP):
		hinic5_link_status_change(nic_dev, true);
		break;
	case HINIC5_SRV_EVENT_TYPE(EVENT_SRV_NIC, EVENT_NIC_PORT_MODULE_EVENT):
		hinic5_port_module_event_handler(nic_dev, event);
		break;
	case HINIC5_SRV_EVENT_TYPE(EVENT_SRV_COMM, EVENT_COMM_SRIOV_STATE_CHANGE):
		sriov_state_change(nic_dev, (void *)event->event_data);
		break;
	case HINIC5_SRV_EVENT_TYPE(EVENT_SRV_COMM, EVENT_COMM_FAULT):
		fault = (void *)event->event_data;
		if (fault->fault_level == FAULT_LEVEL_SERIOUS_FLR &&
		    fault->event.chip.func_id == hinic5_global_func_id(lld_dev->hwdev))
			hinic5_link_status_change(nic_dev, false);
		break;
	case HINIC5_SRV_EVENT_TYPE(EVENT_SRV_COMM, EVENT_COMM_PCIE_LINK_DOWN):
	case HINIC5_SRV_EVENT_TYPE(EVENT_SRV_COMM, EVENT_COMM_HEART_LOST):
	case HINIC5_SRV_EVENT_TYPE(EVENT_SRV_COMM, EVENT_COMM_MGMT_WATCHDOG):
		hinic5_link_status_change(nic_dev, false);
		break;
	default:
		break;
	}
}

struct net_device *hinic5_get_netdev_by_lld(struct hinic5_lld_dev *lld_dev)
{
	struct hinic5_nic_dev *nic_dev = NULL;

	if (!lld_dev || !hinic5_support_nic(lld_dev->hwdev, NULL))
		return NULL;

	nic_dev = hinic5_get_uld_dev_unsafe(lld_dev, SERVICE_T_NIC);
	if (!nic_dev) {
		nic_err(lld_dev->dev,
			"There's no net device attached on the pci device");
		return NULL;
	}

	return nic_dev->netdev;
}
EXPORT_SYMBOL(hinic5_get_netdev_by_lld);

struct hinic5_lld_dev *hinic5_get_lld_dev_by_netdev(struct net_device *netdev)
{
	struct hinic5_nic_dev *nic_dev = NULL;

	if (!netdev || !hinic5_is_netdev_ops_match(netdev))
		return NULL;

	nic_dev = netdev_priv(netdev);
	if (!nic_dev)
		return NULL;

	return nic_dev->lld_dev;
}
EXPORT_SYMBOL(hinic5_get_lld_dev_by_netdev);

int hinic5_get_phy_port_id_by_netdev(struct net_device *netdev, uint8_t *phy_port_id)
{
	struct hinic5_lld_dev *lld_dev = NULL;

	if (!netdev || !phy_port_id)
		return -EINVAL;

	lld_dev = hinic5_get_lld_dev_by_netdev(netdev);
	if (!lld_dev)
		return -ENXIO;

	*phy_port_id = hinic5_physical_port_id(lld_dev->hwdev);

	return 0;
}

void *hinic5_netdev_priv_get(const struct net_device *dev)
{
	struct hinic5_nic_dev *nic_dev = NULL;

	if (!dev)
		return NULL;

	nic_dev = netdev_priv(dev);

	return nic_dev->extend;
}

int hinic5_netdev_priv_set(const struct net_device *dev, void *priv)
{
	struct hinic5_nic_dev *nic_dev = NULL;

	if (!dev || !priv)
		return -EINVAL;

	nic_dev = netdev_priv(dev);
	nic_dev->extend = priv;

	return 0;
}

struct hinic5_uld_info hinic5_g_nic_uld_info = {
	.probe = nic_probe,
	.remove = nic_remove,
	.suspend = NULL,
	.resume = NULL,
	.event = nic_event,
	.ioctl = hinic5_nic_ioctl,
};

struct hinic5_uld_info *hinic5_get_nic_uld_info(void)
{
	return &hinic5_g_nic_uld_info;
}

#define HINIC5_NIC_DRV_DESC "Intelligent Network Interface Card Driver"

static __init int hinic5_nic_lld_init(void)
{
	int err;

	pr_info("%s - version %s\n", HINIC5_NIC_DRV_DESC,
		HINIC5_NIC_DRV_VERSION);

	err = hinic5_lld_init();
	if (err) {
		pr_err("SDK failed.\n");
		return err;
	}

	err = hinic5_module_pre_init();
	if (err != 0) {
		pr_err("hinic5_module_pre_init failed\n");
		goto hinic5_module_pre_init_fail;
	}

	err = hinic5_register_uld(SERVICE_T_NIC, &hinic5_g_nic_uld_info);
	if (err != 0) {
		pr_err("Register hinic5 uld failed\n");
		goto hinic5_register_uld_fail;
	}

	err = hinic5_bond_init();
	if (err != 0) {
		pr_err("Init bond failed\n");
		goto hinic5_bond_init_fail;
	}

	err = hinic5_module_post_init();
	if (err != 0) {
		pr_err("hinic5_module_post_init failed\n");
		goto hinic5_module_post_init_fail;
	}

	return 0;

hinic5_module_post_init_fail:
	hinic5_bond_deinit();
hinic5_bond_init_fail:
	hinic5_unregister_uld(SERVICE_T_NIC);
hinic5_register_uld_fail:
	hinic5_module_post_exit();
hinic5_module_pre_init_fail:
	hinic5_lld_exit();

	return err;
}

static __exit void hinic5_nic_lld_exit(void)
{
	hinic5_module_pre_exit();
	hinic5_bond_deinit();
	hinic5_unregister_uld(SERVICE_T_NIC);
	hinic5_module_post_exit();
	hinic5_lld_exit();
}

#ifndef _LLT_TEST_
module_init(hinic5_nic_lld_init);
module_exit(hinic5_nic_lld_exit);
#endif

MODULE_AUTHOR("Huawei Technologies CO., Ltd");
MODULE_DESCRIPTION(HINIC5_NIC_DRV_DESC);
MODULE_VERSION(HINIC5_NIC_DRV_VERSION);
MODULE_LICENSE("GPL");
