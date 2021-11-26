// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2021 Ramaxel Memory Technology, Ltd */

#define pr_fmt(fmt) KBUILD_MODNAME ": [NIC]" fmt
#include <linux/kernel.h>
#include <linux/pci.h>
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

#include "sphw_common.h"
#include "sphw_hw.h"
#include "sphw_crm.h"
#include "sphw_mt.h"
#include "spnic_nic_cfg.h"
#include "spnic_nic_io.h"
#include "spnic_nic_dev.h"
#include "spnic_tx.h"
#include "spnic_rx.h"
#include "spnic_lld.h"
#include "spnic_rss.h"
#include "spnic_dcb.h"

#define DEFAULT_POLL_WEIGHT	64
static unsigned int poll_weight = DEFAULT_POLL_WEIGHT;
module_param(poll_weight, uint, 0444);
MODULE_PARM_DESC(poll_weight, "Number packets for NAPI budget (default=64)");

#define SPNIC_DEAULT_TXRX_MSIX_PENDING_LIMIT		0
#define SPNIC_DEAULT_TXRX_MSIX_COALESC_TIMER_CFG	0
#define SPNIC_DEAULT_TXRX_MSIX_RESEND_TIMER_CFG	7

static unsigned char qp_pending_limit = SPNIC_DEAULT_TXRX_MSIX_PENDING_LIMIT;
module_param(qp_pending_limit, byte, 0444);
MODULE_PARM_DESC(qp_pending_limit, "QP MSI-X Interrupt coalescing parameter pending_limit (default=2)");

static unsigned char qp_coalesc_timer_cfg =
		SPNIC_DEAULT_TXRX_MSIX_COALESC_TIMER_CFG;
module_param(qp_coalesc_timer_cfg, byte, 0444);
MODULE_PARM_DESC(qp_coalesc_timer_cfg, "QP MSI-X Interrupt coalescing parameter coalesc_timer_cfg (default=32)");

#define DEFAULT_RX_BUFF_LEN	2
u16 rx_buff = DEFAULT_RX_BUFF_LEN;
module_param(rx_buff, ushort, 0444);
MODULE_PARM_DESC(rx_buff, "Set rx_buff size, buffer len must be 2^n. 2 - 16, default is 2KB");

static unsigned int lro_replenish_thld = 256;
module_param(lro_replenish_thld, uint, 0444);
MODULE_PARM_DESC(lro_replenish_thld, "Number wqe for lro replenish buffer (default=256)");

#define SPNIC_NIC_DEV_WQ_NAME		"spnic_nic_dev_wq"

#define DEFAULT_MSG_ENABLE		(NETIF_MSG_DRV | NETIF_MSG_LINK)

#define QID_MASKED(q_id, nic_dev)	((q_id) & ((nic_dev)->num_qps - 1))
#define WATCHDOG_TIMEOUT	5

#define SPNIC_SQ_DEPTH			1024
#define SPNIC_RQ_DEPTH			1024

enum spnic_rx_buff_len {
	RX_BUFF_VALID_2KB		= 2,
	RX_BUFF_VALID_4KB		= 4,
	RX_BUFF_VALID_8KB		= 8,
	RX_BUFF_VALID_16KB		= 16,
};

#define CONVERT_UNIT			1024

static int spnic_netdev_event(struct notifier_block *notifier, unsigned long event, void *ptr);

/* used for netdev notifier register/unregister */
DEFINE_MUTEX(spnic_netdev_notifiers_mutex);
static int spnic_netdev_notifiers_ref_cnt;
static struct notifier_block spnic_netdev_notifier = {
	.notifier_call = spnic_netdev_event,
};

static void spnic_register_notifier(struct spnic_nic_dev *nic_dev)
{
	int err;

	mutex_lock(&spnic_netdev_notifiers_mutex);
	spnic_netdev_notifiers_ref_cnt++;
	if (spnic_netdev_notifiers_ref_cnt == 1) {
		err = register_netdevice_notifier(&spnic_netdev_notifier);
		if (err) {
			nic_info(&nic_dev->pdev->dev, "Register netdevice notifier failed, err: %d\n",
				 err);
			spnic_netdev_notifiers_ref_cnt--;
		}
	}
	mutex_unlock(&spnic_netdev_notifiers_mutex);
}

static void spnic_unregister_notifier(struct spnic_nic_dev *nic_dev)
{
	mutex_lock(&spnic_netdev_notifiers_mutex);
	if (spnic_netdev_notifiers_ref_cnt == 1)
		unregister_netdevice_notifier(&spnic_netdev_notifier);

	if (spnic_netdev_notifiers_ref_cnt)
		spnic_netdev_notifiers_ref_cnt--;
	mutex_unlock(&spnic_netdev_notifiers_mutex);
}

#define SPNIC_MAX_VLAN_DEPTH_OFFLOAD_SUPPORT	1
#define SPNIC_VLAN_CLEAR_OFFLOAD	(NETIF_F_IP_CSUM | NETIF_F_IPV6_CSUM | \
					 NETIF_F_SCTP_CRC | NETIF_F_RXCSUM | \
					 NETIF_F_ALL_TSO)

int spnic_netdev_event(struct notifier_block *notifier, unsigned long event, void *ptr)
{
	struct net_device *ndev = netdev_notifier_info_to_dev(ptr);
	struct net_device *real_dev = NULL;
	struct net_device *ret = NULL;
	struct spnic_nic_dev *nic_dev = NULL;
	u16 vlan_depth;

	if (!is_vlan_dev(ndev))
		return NOTIFY_DONE;

	dev_hold(ndev);

	switch (event) {
	case NETDEV_REGISTER:
		real_dev = vlan_dev_real_dev(ndev);
		nic_dev = spnic_get_uld_dev_by_ifname(real_dev->name, SERVICE_T_NIC);
		if (!nic_dev)
			goto out;

		vlan_depth = 1;
		ret = vlan_dev_priv(ndev)->real_dev;
		while (is_vlan_dev(ret)) {
			ret = vlan_dev_priv(ret)->real_dev;
			vlan_depth++;
		}

		if (vlan_depth == SPNIC_MAX_VLAN_DEPTH_OFFLOAD_SUPPORT) {
			ndev->vlan_features &= (~SPNIC_VLAN_CLEAR_OFFLOAD);
		} else if (vlan_depth > SPNIC_MAX_VLAN_DEPTH_OFFLOAD_SUPPORT) {
			ndev->hw_features &= (~SPNIC_VLAN_CLEAR_OFFLOAD);
			ndev->features &= (~SPNIC_VLAN_CLEAR_OFFLOAD);
		}

		break;

	default:
		break;
	};

out:
	dev_put(ndev);

	return NOTIFY_DONE;
}

void spnic_link_status_change(struct spnic_nic_dev *nic_dev, bool status)
{
	struct net_device *netdev = nic_dev->netdev;

	if (!SPHW_CHANNEL_RES_VALID(nic_dev) || test_bit(SPNIC_LP_TEST, &nic_dev->flags))
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

static void netdev_feature_init(struct net_device *netdev)
{
	struct spnic_nic_dev *nic_dev = netdev_priv(netdev);
	netdev_features_t dft_fts = 0;
	netdev_features_t cso_fts = 0;
	netdev_features_t vlan_fts = 0;
	netdev_features_t tso_fts = 0;
	netdev_features_t hw_features = 0;

	dft_fts |= NETIF_F_SG | NETIF_F_HIGHDMA;

	if (SPNIC_SUPPORT_CSUM(nic_dev->hwdev))
		cso_fts |= NETIF_F_IP_CSUM | NETIF_F_IPV6_CSUM | NETIF_F_RXCSUM;
	if (SPNIC_SUPPORT_SCTP_CRC(nic_dev->hwdev))
		cso_fts |= NETIF_F_SCTP_CRC;

	if (SPNIC_SUPPORT_TSO(nic_dev->hwdev))
		tso_fts |= NETIF_F_TSO | NETIF_F_TSO6;

	if (SPNIC_SUPPORT_VLAN_OFFLOAD(nic_dev->hwdev)) {
		vlan_fts |= NETIF_F_HW_VLAN_CTAG_TX;
		vlan_fts |= NETIF_F_HW_VLAN_CTAG_RX;
	}

	if (SPNIC_SUPPORT_RXVLAN_FILTER(nic_dev->hwdev))
		vlan_fts |= NETIF_F_HW_VLAN_CTAG_FILTER;

	if (SPNIC_SUPPORT_VXLAN_OFFLOAD(nic_dev->hwdev))
		tso_fts |= NETIF_F_GSO_UDP_TUNNEL | NETIF_F_GSO_UDP_TUNNEL_CSUM;

	/* LRO is disable in default, only set hw features */
	if (SPNIC_SUPPORT_LRO(nic_dev->hwdev))
		hw_features |= NETIF_F_LRO;

	netdev->features |= dft_fts | cso_fts | tso_fts | vlan_fts;
	netdev->vlan_features |= dft_fts | cso_fts | tso_fts;

	hw_features |= netdev->hw_features;

	hw_features |= netdev->features;

	netdev->hw_features = hw_features;

	netdev->priv_flags |= IFF_UNICAST_FLT;

	netdev->hw_enc_features |= dft_fts;
	if (SPNIC_SUPPORT_VXLAN_OFFLOAD(nic_dev->hwdev)) {
		netdev->hw_enc_features |= cso_fts;
		netdev->hw_enc_features |= tso_fts | NETIF_F_TSO_ECN;
	}
}

static void init_intr_coal_param(struct spnic_nic_dev *nic_dev)
{
	struct spnic_intr_coal_info *info = NULL;
	u16 i;

	for (i = 0; i < nic_dev->max_qps; i++) {
		info = &nic_dev->intr_coalesce[i];

		info->pending_limt = qp_pending_limit;
		info->coalesce_timer_cfg = qp_coalesc_timer_cfg;

		info->resend_timer_cfg = SPNIC_DEAULT_TXRX_MSIX_RESEND_TIMER_CFG;

		info->pkt_rate_high = SPNIC_RX_RATE_HIGH;
		info->rx_usecs_high = SPNIC_RX_COAL_TIME_HIGH;
		info->rx_pending_limt_high = SPNIC_RX_PENDING_LIMIT_HIGH;
		info->pkt_rate_low = SPNIC_RX_RATE_LOW;
		info->rx_usecs_low = SPNIC_RX_COAL_TIME_LOW;
		info->rx_pending_limt_low = SPNIC_RX_PENDING_LIMIT_LOW;
	}
}

static int spnic_init_intr_coalesce(struct spnic_nic_dev *nic_dev)
{
	u64 size;

	if (qp_pending_limit != SPNIC_DEAULT_TXRX_MSIX_PENDING_LIMIT ||
	    qp_coalesc_timer_cfg != SPNIC_DEAULT_TXRX_MSIX_COALESC_TIMER_CFG)
		nic_dev->intr_coal_set_flag = 1;
	else
		nic_dev->intr_coal_set_flag = 0;

	size = sizeof(*nic_dev->intr_coalesce) * nic_dev->max_qps;
	if (!size) {
		nic_err(&nic_dev->pdev->dev, "Cannot allocate zero size intr coalesce\n");
		return -EINVAL;
	}
	nic_dev->intr_coalesce = kzalloc(size, GFP_KERNEL);
	if (!nic_dev->intr_coalesce) {
		nic_err(&nic_dev->pdev->dev, "Failed to alloc intr coalesce\n");
		return -ENOMEM;
	}

	init_intr_coal_param(nic_dev);

	if (test_bit(SPNIC_INTR_ADAPT, &nic_dev->flags))
		nic_dev->adaptive_rx_coal = 1;
	else
		nic_dev->adaptive_rx_coal = 0;

	return 0;
}

static void spnic_free_intr_coalesce(struct spnic_nic_dev *nic_dev)
{
	kfree(nic_dev->intr_coalesce);
}

static int spnic_alloc_txrxqs(struct spnic_nic_dev *nic_dev)
{
	struct net_device *netdev = nic_dev->netdev;
	int err;

	err = spnic_alloc_txqs(netdev);
	if (err) {
		nic_err(&nic_dev->pdev->dev, "Failed to alloc txqs\n");
		return err;
	}

	err = spnic_alloc_rxqs(netdev);
	if (err) {
		nic_err(&nic_dev->pdev->dev, "Failed to alloc rxqs\n");
		goto alloc_rxqs_err;
	}

	err = spnic_init_intr_coalesce(nic_dev);
	if (err) {
		nic_err(&nic_dev->pdev->dev, "Failed to init_intr_coalesce\n");
		goto init_intr_err;
	}

	return 0;

init_intr_err:
	spnic_free_rxqs(netdev);

alloc_rxqs_err:
	spnic_free_txqs(netdev);

	return err;
}

static void spnic_free_txrxqs(struct spnic_nic_dev *nic_dev)
{
	spnic_free_intr_coalesce(nic_dev);
	spnic_free_rxqs(nic_dev->netdev);
	spnic_free_txqs(nic_dev->netdev);
}

static void spnic_sw_deinit(struct spnic_nic_dev *nic_dev)
{
	spnic_free_txrxqs(nic_dev);

	spnic_clean_mac_list_filter(nic_dev);

	spnic_del_mac(nic_dev->hwdev, nic_dev->netdev->dev_addr, 0,
		      sphw_global_func_id(nic_dev->hwdev), SPHW_CHANNEL_NIC);

	if (test_bit(SPNIC_RSS_ENABLE, &nic_dev->flags))
		spnic_rss_template_free(nic_dev->hwdev);

	spnic_clear_rss_config(nic_dev);
}

static int spnic_sw_init(struct spnic_nic_dev *nic_dev)
{
	struct net_device *netdev = nic_dev->netdev;

	int err = 0;

	sema_init(&nic_dev->port_state_sem, 1);

	err = spnic_dcb_init(nic_dev);
	if (err) {
		nic_err(&nic_dev->pdev->dev, "Failed to init dcb\n");
		return -EFAULT;
	}

	nic_dev->q_params.sq_depth = SPNIC_SQ_DEPTH;
	nic_dev->q_params.rq_depth = SPNIC_RQ_DEPTH;

	spnic_try_to_enable_rss(nic_dev);

	err = spnic_get_default_mac(nic_dev->hwdev, netdev->dev_addr);
	if (err) {
		nic_err(&nic_dev->pdev->dev, "Failed to get MAC address\n");
		goto get_mac_err;
	}

	if (!is_valid_ether_addr(netdev->dev_addr)) {
		if (!SPNIC_FUNC_IS_VF(nic_dev->hwdev)) {
			nic_err(&nic_dev->pdev->dev, "Invalid MAC address %pM\n", netdev->dev_addr);
			err = -EIO;
			goto err_mac;
		}

		nic_info(&nic_dev->pdev->dev, "Invalid MAC address %pM, using random\n",
			 netdev->dev_addr);
		eth_hw_addr_random(netdev);
	}

	err = spnic_set_mac(nic_dev->hwdev, netdev->dev_addr, 0,
			    sphw_global_func_id(nic_dev->hwdev), SPHW_CHANNEL_NIC);
	/* When this is VF driver, we must consider that PF has already set VF
	 * MAC, and we can't consider this condition is error status during
	 * driver probe procedure.
	 */
	if (err && err != SPNIC_PF_SET_VF_ALREADY) {
		nic_err(&nic_dev->pdev->dev, "Failed to set default MAC\n");
		goto set_mac_err;
	}

	/* MTU range: 384 - 9600 */
	netdev->min_mtu = SPNIC_MIN_MTU_SIZE;
	netdev->max_mtu = SPNIC_MAX_JUMBO_FRAME_SIZE;

	err = spnic_alloc_txrxqs(nic_dev);
	if (err) {
		nic_err(&nic_dev->pdev->dev, "Failed to alloc qps\n");
		goto alloc_qps_err;
	}

	return 0;

alloc_qps_err:
	spnic_del_mac(nic_dev->hwdev, netdev->dev_addr, 0, sphw_global_func_id(nic_dev->hwdev),
		      SPHW_CHANNEL_NIC);

set_mac_err:
err_mac:
get_mac_err:

	if (test_bit(SPNIC_RSS_ENABLE, &nic_dev->flags))
		spnic_rss_template_free(nic_dev->hwdev);
	spnic_clear_rss_config(nic_dev);

	return err;
}

static void spnic_assign_netdev_ops(struct spnic_nic_dev *adapter)
{
	spnic_set_netdev_ops(adapter);
	if (!SPNIC_FUNC_IS_VF(adapter->hwdev))
		spnic_set_ethtool_ops(adapter->netdev);
	else
		spnicvf_set_ethtool_ops(adapter->netdev);

	adapter->netdev->watchdog_timeo = WATCHDOG_TIMEOUT * HZ;
}

static int spnic_validate_parameters(struct spnic_lld_dev *lld_dev)
{
	struct pci_dev *pdev = lld_dev->pdev;

	/* If weight exceeds the queue depth, the queue resources will be
	 * exhausted, and increasing it has no effect.
	 */
	if (!poll_weight || poll_weight > SPNIC_MAX_RX_QUEUE_DEPTH) {
		nic_warn(&pdev->dev, "Module Parameter poll_weight is out of range: [1, %d], resetting to %d\n",
			 SPNIC_MAX_RX_QUEUE_DEPTH, DEFAULT_POLL_WEIGHT);
		poll_weight = DEFAULT_POLL_WEIGHT;
	}

	/* check rx_buff value, default rx_buff is 2KB.
	 * Valid rx_buff include 2KB/4KB/8KB/16KB.
	 */
	if (rx_buff != RX_BUFF_VALID_2KB && rx_buff != RX_BUFF_VALID_4KB &&
	    rx_buff != RX_BUFF_VALID_8KB && rx_buff != RX_BUFF_VALID_16KB) {
		nic_warn(&pdev->dev, "Module Parameter rx_buff value %u is out of range, must be 2^n. Valid range is 2 - 16, resetting to %dKB",
			 rx_buff, DEFAULT_RX_BUFF_LEN);
		rx_buff = DEFAULT_RX_BUFF_LEN;
	}

	return 0;
}

static void adaptive_configuration_init(struct spnic_nic_dev *nic_dev)
{
	/* TODO： */
}

static int set_interrupt_moder(struct spnic_nic_dev *nic_dev, u16 q_id,
			       u8 coalesc_timer_cfg, u8 pending_limt)
{
	struct interrupt_info info;
	int err;

	memset(&info, 0, sizeof(info));

	if (coalesc_timer_cfg == nic_dev->rxqs[q_id].last_coalesc_timer_cfg &&
	    pending_limt == nic_dev->rxqs[q_id].last_pending_limt)
		return 0;

	/* netdev not running or qp not in using,
	 * don't need to set coalesce to hw
	 */
	if (!SPHW_CHANNEL_RES_VALID(nic_dev) || q_id >= nic_dev->q_params.num_qps)
		return 0;

	info.lli_set = 0;
	info.interrupt_coalesc_set = 1;
	info.coalesc_timer_cfg = coalesc_timer_cfg;
	info.pending_limt = pending_limt;
	info.msix_index = nic_dev->q_params.irq_cfg[q_id].msix_entry_idx;
	info.resend_timer_cfg = nic_dev->intr_coalesce[q_id].resend_timer_cfg;

	err = sphw_set_interrupt_cfg(nic_dev->hwdev, info, SPHW_CHANNEL_NIC);
	if (err) {
		nicif_err(nic_dev, drv, nic_dev->netdev,
			  "Failed to modify moderation for Queue: %u\n", q_id);
	} else {
		nic_dev->rxqs[q_id].last_coalesc_timer_cfg = coalesc_timer_cfg;
		nic_dev->rxqs[q_id].last_pending_limt = pending_limt;
	}

	return err;
}

static void calc_coal_para(struct spnic_nic_dev *nic_dev, struct spnic_intr_coal_info *q_coal,
			   u64 rx_rate, u8 *coalesc_timer_cfg, u8 *pending_limt)
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
			     (q_coal->pkt_rate_high - q_coal->pkt_rate_low) + q_coal->rx_usecs_low);

		*pending_limt = q_coal->rx_pending_limt_low;
	}
}

static void update_queue_coal(struct spnic_nic_dev *nic_dev, u16 qid,
			      u64 rx_rate, u64 avg_pkt_size, u64 tx_rate)
{
	struct spnic_intr_coal_info *q_coal = NULL;
	u8 coalesc_timer_cfg, pending_limt;

	q_coal = &nic_dev->intr_coalesce[qid];

	if (rx_rate > SPNIC_RX_RATE_THRESH &&
	    avg_pkt_size > SPNIC_AVG_PKT_SMALL) {
		calc_coal_para(nic_dev, q_coal, rx_rate, &coalesc_timer_cfg, &pending_limt);
	} else {
		coalesc_timer_cfg = SPNIC_LOWEST_LATENCY;
		pending_limt = q_coal->rx_pending_limt_low;
	}

	set_interrupt_moder(nic_dev, qid, coalesc_timer_cfg, pending_limt);
}

void spnic_auto_moderation_work(struct work_struct *work)
{
	struct delayed_work *delay = to_delayed_work(work);
	struct spnic_nic_dev *nic_dev = container_of(delay, struct spnic_nic_dev, moderation_task);
	unsigned long period = (unsigned long)(jiffies - nic_dev->last_moder_jiffies);
	u64 rx_packets, rx_bytes, rx_pkt_diff, rx_rate, avg_pkt_size;
	u64 tx_packets, tx_bytes, tx_pkt_diff, tx_rate;
	u16 qid;

	if (!test_bit(SPNIC_INTF_UP, &nic_dev->flags))
		return;

	queue_delayed_work(nic_dev->workq, &nic_dev->moderation_task, SPNIC_MODERATONE_DELAY);

	if (!nic_dev->adaptive_rx_coal || !period)
		return;

	for (qid = 0; qid < nic_dev->q_params.num_qps; qid++) {
		rx_packets = nic_dev->rxqs[qid].rxq_stats.packets;
		rx_bytes = nic_dev->rxqs[qid].rxq_stats.bytes;
		tx_packets = nic_dev->txqs[qid].txq_stats.packets;
		tx_bytes = nic_dev->txqs[qid].txq_stats.bytes;

		rx_pkt_diff = rx_packets - nic_dev->rxqs[qid].last_moder_packets;
		avg_pkt_size = rx_pkt_diff ?
			((unsigned long)(rx_bytes - nic_dev->rxqs[qid].last_moder_bytes)) /
			rx_pkt_diff : 0;

		rx_rate = rx_pkt_diff * HZ / period;
		tx_pkt_diff = tx_packets - nic_dev->txqs[qid].last_moder_packets;
		tx_rate = tx_pkt_diff * HZ / period;

		update_queue_coal(nic_dev, qid, rx_rate, avg_pkt_size, tx_rate);

		nic_dev->rxqs[qid].last_moder_packets = rx_packets;
		nic_dev->rxqs[qid].last_moder_bytes = rx_bytes;
		nic_dev->txqs[qid].last_moder_packets = tx_packets;
		nic_dev->txqs[qid].last_moder_bytes = tx_bytes;
	}

	nic_dev->last_moder_jiffies = jiffies;
}

void spnic_periodic_work_handler(struct work_struct *work)
{
	struct delayed_work *delay = to_delayed_work(work);
	struct spnic_nic_dev *nic_dev = container_of(delay, struct spnic_nic_dev, periodic_work);

	if (test_and_clear_bit(EVENT_WORK_TX_TIMEOUT, &nic_dev->event_flag))
		sphw_fault_event_report(nic_dev->hwdev, SPHW_FAULT_SRC_TX_TIMEOUT,
					FAULT_LEVEL_SERIOUS_FLR);

	queue_delayed_work(nic_dev->workq, &nic_dev->periodic_work, HZ);
}

static void free_nic_dev(struct spnic_nic_dev *nic_dev)
{
	destroy_workqueue(nic_dev->workq);
	kfree(nic_dev->vlan_bitmap);
}

static int setup_nic_dev(struct net_device *netdev, struct spnic_lld_dev *lld_dev)
{
	struct pci_dev *pdev = lld_dev->pdev;
	struct spnic_nic_dev *nic_dev;
	u32 page_num;

	nic_dev = (struct spnic_nic_dev *)netdev_priv(netdev);
	nic_dev->netdev = netdev;
	SET_NETDEV_DEV(netdev, &pdev->dev);
	nic_dev->hwdev = lld_dev->hwdev;
	nic_dev->pdev = pdev;
	nic_dev->poll_weight = (int)poll_weight;
	nic_dev->msg_enable = DEFAULT_MSG_ENABLE;
	nic_dev->lro_replenish_thld = lro_replenish_thld;
	nic_dev->rx_buff_len = (u16)(rx_buff * CONVERT_UNIT);
	nic_dev->dma_rx_buff_size = RX_BUFF_NUM_PER_PAGE * nic_dev->rx_buff_len;
	page_num = nic_dev->dma_rx_buff_size / PAGE_SIZE;
	nic_dev->page_order = page_num > 0 ? ilog2(page_num) : 0;

	mutex_init(&nic_dev->nic_mutex);

	nic_dev->vlan_bitmap = kzalloc(VLAN_BITMAP_SIZE(nic_dev), GFP_KERNEL);
	if (!nic_dev->vlan_bitmap) {
		nic_err(&pdev->dev, "Failed to allocate vlan bitmap\n");
		return -ENOMEM;
	}

	nic_dev->workq = create_singlethread_workqueue(SPNIC_NIC_DEV_WQ_NAME);
	if (!nic_dev->workq) {
		nic_err(&pdev->dev, "Failed to initialize nic workqueue\n");
		kfree(nic_dev->vlan_bitmap);
		return -ENOMEM;
	}

	INIT_DELAYED_WORK(&nic_dev->periodic_work, spnic_periodic_work_handler);

	INIT_LIST_HEAD(&nic_dev->uc_filter_list);
	INIT_LIST_HEAD(&nic_dev->mc_filter_list);
	INIT_WORK(&nic_dev->rx_mode_work, spnic_set_rx_mode_work);

	INIT_LIST_HEAD(&nic_dev->rx_flow_rule.rules);
	INIT_LIST_HEAD(&nic_dev->tcam.tcam_list);
	INIT_LIST_HEAD(&nic_dev->tcam.tcam_dynamic_info.tcam_dynamic_list);

	return 0;
}

static int spnic_set_default_hw_feature(struct spnic_nic_dev *nic_dev)
{
	u64 nic_features;
	int err;

	if (!SPNIC_FUNC_IS_VF(nic_dev->hwdev)) {
		err = spnic_dcb_reset_hw_config(nic_dev);
		if (err) {
			nic_err(&nic_dev->pdev->dev, "Failed to reset hw dcb configuration\n");
			return err;
		}
	}

	nic_features = spnic_get_feature_cap(nic_dev->hwdev);
	err = spnic_set_nic_feature(nic_dev->hwdev, &nic_features, 1);
	if (err) {
		nic_err(&nic_dev->pdev->dev, "Failed to set nic features\n");
		return err;
	}

	/* enable all hw features in netdev->features */
	return spnic_set_hw_features(nic_dev);
}

static int nic_probe(struct spnic_lld_dev *lld_dev, void **uld_dev, char *uld_dev_name)
{
	struct pci_dev *pdev = lld_dev->pdev;
	struct spnic_nic_dev *nic_dev = NULL;
	struct net_device *netdev = NULL;
	u16 max_qps, glb_func_id;
	int err;

	/* *uld_dev should always no be NULL */
	*uld_dev = lld_dev;

	if (!sphw_support_nic(lld_dev->hwdev, NULL)) {
		nic_info(&pdev->dev, "Hw don't support nic\n");
		return 0;
	}

	nic_info(&pdev->dev, "NIC service probe begin\n");

	err = spnic_validate_parameters(lld_dev);
	if (err) {
		err = -EINVAL;
		goto err_out;
	}

	glb_func_id = sphw_global_func_id(lld_dev->hwdev);
	err = sphw_func_reset(lld_dev->hwdev, glb_func_id, SPHW_NIC_RES, SPHW_CHANNEL_NIC);
	if (err) {
		nic_err(&pdev->dev, "Failed to reset function\n");
		goto err_out;
	}

	max_qps = sphw_func_max_nic_qnum(lld_dev->hwdev);
	netdev = alloc_etherdev_mq(sizeof(*nic_dev), max_qps);
	if (!netdev) {
		nic_err(&pdev->dev, "Failed to allocate ETH device\n");
		err = -ENOMEM;
		goto err_out;
	}

	nic_dev = (struct spnic_nic_dev *)netdev_priv(netdev);
	err = setup_nic_dev(netdev, lld_dev);
	if (err)
		goto setup_dev_err;

	adaptive_configuration_init(nic_dev);

	/* get nic cap from hw */
	sphw_support_nic(lld_dev->hwdev, &nic_dev->nic_cap);

	err = spnic_init_nic_hwdev(nic_dev->hwdev, pdev, &pdev->dev, nic_dev->rx_buff_len);
	if (err) {
		nic_err(&pdev->dev, "Failed to init nic hwdev\n");
		goto init_nic_hwdev_err;
	}

	spnic_assign_netdev_ops(nic_dev);
	netdev_feature_init(netdev);

	err = spnic_sw_init(nic_dev);
	if (err)
		goto sw_init_err;

	err = spnic_set_default_hw_feature(nic_dev);
	if (err)
		goto set_features_err;

	spnic_register_notifier(nic_dev);

	err = register_netdev(netdev);
	if (err) {
		nic_err(&pdev->dev, "Failed to register netdev\n");
		err = -ENOMEM;
		goto netdev_err;
	}

	queue_delayed_work(nic_dev->workq, &nic_dev->periodic_work, HZ);
	netif_carrier_off(netdev);

	*uld_dev = nic_dev;
	nicif_info(nic_dev, probe, netdev, "Register netdev succeed\n");
	nic_info(&pdev->dev, "NIC service probed\n");

	return 0;

netdev_err:
	spnic_unregister_notifier(nic_dev);

set_features_err:
	spnic_sw_deinit(nic_dev);

sw_init_err:
	spnic_free_nic_hwdev(nic_dev->hwdev);

init_nic_hwdev_err:
	free_nic_dev(nic_dev);
setup_dev_err:
	free_netdev(netdev);

err_out:
	nic_err(&pdev->dev, "NIC service probe failed\n");

	return err;
}

static void nic_remove(struct spnic_lld_dev *lld_dev, void *adapter)
{
	struct spnic_nic_dev *nic_dev = adapter;
	struct net_device *netdev = NULL;

	if (!nic_dev || !sphw_support_nic(lld_dev->hwdev, NULL))
		return;

	nic_info(&lld_dev->pdev->dev, "NIC service remove begin\n");

	netdev = nic_dev->netdev;

	unregister_netdev(netdev);
	spnic_unregister_notifier(nic_dev);

	cancel_delayed_work_sync(&nic_dev->periodic_work);
	cancel_work_sync(&nic_dev->rx_mode_work);
	destroy_workqueue(nic_dev->workq);

	spnic_sw_deinit(nic_dev);

	spnic_flush_rx_flow_rule(nic_dev);
	spnic_free_nic_hwdev(nic_dev->hwdev);

	kfree(nic_dev->vlan_bitmap);

	free_netdev(netdev);

	nic_info(&lld_dev->pdev->dev, "NIC service removed\n");
}

static void sriov_state_change(struct spnic_nic_dev *nic_dev,
			       const struct sphw_sriov_state_info *info)
{
	if (!info->enable)
		spnic_clear_vfs_info(nic_dev->hwdev);
}

const char *g_spnic_module_link_err[LINK_ERR_NUM] = {
	"Unrecognized module",
};

void sphw_port_module_event_handler(struct spnic_nic_dev *nic_dev, struct sphw_event_info *event)
{
	enum port_module_event_type type = event->module_event.type;
	enum link_err_type err_type = event->module_event.err_type;

	switch (type) {
	case SPHW_PORT_MODULE_CABLE_PLUGGED:
	case SPHW_PORT_MODULE_CABLE_UNPLUGGED:
		nicif_info(nic_dev, link, nic_dev->netdev,
			   "Port module event: Cable %s\n",
			   type == SPHW_PORT_MODULE_CABLE_PLUGGED ?
			   "plugged" : "unplugged");
		break;
	case SPHW_PORT_MODULE_LINK_ERR:
		if (err_type >= LINK_ERR_NUM) {
			nicif_info(nic_dev, link, nic_dev->netdev,
				   "Link failed, Unknown error type: 0x%x\n", err_type);
		} else {
			nicif_info(nic_dev, link, nic_dev->netdev, "Link failed, error type: 0x%x: %s\n",
				   err_type, g_spnic_module_link_err[err_type]);
		}
		break;
	default:
		nicif_err(nic_dev, link, nic_dev->netdev, "Unknown port module type %d\n", type);
		break;
	}
}

void nic_event(struct spnic_lld_dev *lld_dev, void *adapter, struct sphw_event_info *event)
{
	struct spnic_nic_dev *nic_dev = adapter;
	enum sphw_event_type type;

	if (!nic_dev || !event || !sphw_support_nic(lld_dev->hwdev, NULL))
		return;

	type = event->type;

	switch (type) {
	case SPHW_EVENT_LINK_DOWN:
		spnic_link_status_change(nic_dev, false);
		break;
	case SPHW_EVENT_LINK_UP:
		spnic_link_status_change(nic_dev, true);
		break;
	case SPHW_EVENT_SRIOV_STATE_CHANGE:
		sriov_state_change(nic_dev, &event->sriov_state);
		break;
	case SPHW_EVENT_PORT_MODULE_EVENT:
		sphw_port_module_event_handler(nic_dev, event);
		break;
	case SPHW_EVENT_FAULT:
		if (event->info.fault_level == FAULT_LEVEL_SERIOUS_FLR &&
		    event->info.event.chip.func_id == sphw_global_func_id(lld_dev->hwdev))
			spnic_link_status_change(nic_dev, false);
		break;
	case SPHW_EVENT_PCIE_LINK_DOWN:
	case SPHW_EVENT_HEART_LOST:
		spnic_link_status_change(nic_dev, false);
		break;
	default:
		break;
	}
}

struct net_device *spnic_get_netdev_by_lld(struct spnic_lld_dev *lld_dev)
{
	struct spnic_nic_dev *nic_dev = NULL;

	if (!lld_dev || !sphw_support_nic(lld_dev->hwdev, NULL))
		return NULL;

	nic_dev = spnic_get_uld_dev_by_pdev(lld_dev->pdev, SERVICE_T_NIC);
	if (!nic_dev) {
		sdk_err(&lld_dev->pdev->dev,
			"There's no net device attached on the pci device");
		return NULL;
	}

	return nic_dev->netdev;
}

void *spnic_get_hwdev_by_netdev(struct net_device *netdev)
{
	struct spnic_nic_dev *nic_dev = netdev_priv(netdev);

	if (!nic_dev || !netdev)
		return NULL;

	return nic_dev->hwdev;
}

struct spnic_uld_info nic_uld_info = {
	.probe = nic_probe,
	.remove = nic_remove,
	.suspend = NULL,
	.resume = NULL,
	.event = nic_event,
	.ioctl = nic_ioctl,
};
