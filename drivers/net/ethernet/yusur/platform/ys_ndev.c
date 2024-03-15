// SPDX-License-Identifier: GPL-2.0

#include <linux/etherdevice.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/pci.h>

#include "ys_auxiliary.h"
#include "ys_ndev.h"
#include "ys_pdev.h"

#include "../net/ys_ethtool_ops.h"
#include "../net/ys_ndev_ops.h"

#include "ys_debug.h"
#include "ys_irq.h"

void ys_ndev_destroy(struct net_device *ndev)
{
	struct ys_ndev_priv *ndev_priv;
	struct ys_pdev_priv *pdev_priv;

	if (IS_ERR_OR_NULL(ndev))
		return;

	ndev_priv = netdev_priv(ndev);
	pdev_priv = pci_get_drvdata(ndev_priv->pdev);
	/* netif_carrier_off(ndev); */
	ys_ethtool_hw_uninit(ndev);

	if (ndev->reg_state == NETREG_REGISTERED) {
		ys_net_info("unregister net dev %s\n", ndev->name);
		unregister_netdev(ndev);
	}

	cancel_delayed_work(&ndev_priv->update_stats_work);
	if (!IS_ERR_OR_NULL(pdev_priv->ops->hw_adp_uninit))
		pdev_priv->ops->hw_adp_uninit(ndev);
	ys_ndev_hw_uninit(ndev);

	ndev->num_tx_queues = 0;
	ndev->num_rx_queues = 0;
	netif_set_real_num_tx_queues(ndev, 0);
	netif_set_real_num_rx_queues(ndev, 0);
}

static void ys_update_stats_work(struct work_struct *work)
{
	struct ys_ndev_priv *ndev_priv =
		container_of(work, struct ys_ndev_priv, update_stats_work.work);

	if (ndev_priv->ys_eth_hw->et_update_stats)
		ndev_priv->ys_eth_hw->et_update_stats(ndev_priv->ndev);
	schedule_delayed_work(&ndev_priv->update_stats_work,
			      msecs_to_jiffies(STATS_SCHEDULE_DELAY));
}

/* NIC statistics information init
 */
static void ys_ethtool_stats_init(struct ys_ndev_priv *ndev_priv)
{
	u32 i = 0;

	ndev_priv->eth_string.stats_len = LAN_STATS_INFO_LEN;
	ndev_priv->eth_string.ys_eth_stats =
		(struct ys_stats *)ndev_priv->eth_string.lan_stats;
	INIT_DELAYED_WORK(&ndev_priv->update_stats_work, ys_update_stats_work);
	for (i = 0; i < ndev_priv->eth_string.stats_len; i++)
		ndev_priv->eth_string.lan_stats[i] = 0;
	schedule_delayed_work(&ndev_priv->update_stats_work,
			      msecs_to_jiffies(STATS_SCHEDULE_DELAY));
}

static void __maybe_unused ys_link_timer_callback(struct timer_list *link_timer)
{
	struct ys_ndev_priv *ndev_priv =
		container_of(link_timer, struct ys_ndev_priv, link_timer);

	if (ndev_priv->ys_eth_hw->et_check_link)
		ndev_priv->ys_eth_hw->et_check_link(ndev_priv->ndev);

	mod_timer(&ndev_priv->link_timer, jiffies + HZ);
}

struct net_device *ys_ndev_create(struct ys_pdev_priv *pdev_priv,
				  int port_id, int queue)
{
	struct ys_ndev_priv *ndev_priv = NULL;
	struct net_device *ndev;
	struct device *dev;
	int ret = 0;

	dev = pdev_priv->dev;

	ys_dev_info("port id %d\n", port_id);
	if (queue == 0) {
		ys_dev_err("etherdev alloc max queue can't be 0");
		return NULL;
	}

	ndev = alloc_etherdev_mq(sizeof(*ndev_priv), queue);
	if (IS_ERR_OR_NULL(ndev)) {
		ys_dev_err("Failed to allocate memory");
		goto fail;
	}

	SET_NETDEV_DEV(ndev, dev);

	ndev->dev_port = port_id;

	ndev_priv = netdev_priv(ndev);
	memset(ndev_priv, 0, sizeof(*ndev_priv));

	spin_lock_init(&ndev_priv->stats_lock);
	mutex_init(&ndev_priv->state_lock);

	ndev_priv->ndev = ndev;
	ndev_priv->pdev = pdev_priv->pdev;

	ret = ys_ethtool_hw_init(ndev);
	if (ret) {
		ys_dev_err("ethtool hw init failed on port %d", port_id);
		goto fail;
	}

	ret = ys_ndev_hw_init(ndev);
	if (ret) {
		ys_dev_err("netdevice hw init failed on port %d", port_id);
		goto fail;
	}

	if (!IS_ERR_OR_NULL(pdev_priv->ops->hw_adp_init)) {
		ret = pdev_priv->ops->hw_adp_init(ndev);
		if (ret) {
			ys_dev_err("netdev init failed on port %d", port_id);
			goto fail;
		}
	} else {
		ys_dev_err("netdev init failed on port %d", port_id);
		goto fail;
	}

	/* for hw mac set check */
	if (!IS_ERR_OR_NULL(pdev_priv->ops->hw_adp_set_mac))
		pdev_priv->ops->hw_adp_set_mac(ndev);

	/* if hw set failed, no hw set func, or invalid MAC address */
	if (!is_valid_ether_addr(ndev->dev_addr)) {
		ys_dev_info("using random MAC");
		ndev->addr_len = ETH_ALEN;
		eth_hw_addr_random(ndev);
	}

	if (!IS_ERR_OR_NULL(ndev_priv->ys_ndev_hw->ys_init_hw_features))
		ndev_priv->ys_ndev_hw->ys_init_hw_features(ndev);

	ndev->netdev_ops = &ys_ndev_ops;
	ndev->ethtool_ops = &ys_ethtool_ops;
	ys_ethtool_stats_init(ndev_priv);
	netif_carrier_off(ndev);
	ret = register_netdev(ndev);
	if (ret) {
		ys_dev_err("register_netdev fail");
		goto fail;
	}
	ys_net_info("register_netdev success %s", ndev->name);
	return ndev;

fail:
	ys_ndev_destroy(ndev);
	free_netdev(ndev);
	return NULL;
}

static int ys_register_init_irqs(struct ys_pdev_priv *pdev_priv)
{
	struct ys_irq_table *irq_table = &pdev_priv->irq_table;
	struct ys_irq_sub sub;
	int init_count = 0;
	int ret;
	int i;

	if (!IS_ERR_OR_NULL(pdev_priv->ops->hw_adp_irq_pre_init))
		pdev_priv->ops->hw_adp_irq_pre_init(pdev_priv->pdev);

	for (i = 0; i < irq_table->max; i++) {
		memset(&sub, 0, sizeof(sub));
		ret = pdev_priv->ops->hw_adp_get_init_irq_sub(pdev_priv->pdev,
							      i, &sub);
		if (ret < 0) {
			ys_dev_err("Get hw No%d initial irq info error!", i);
			return ret;
		} else if (ret == 0) {
			init_count++;
		} else {
			break;
		}

		ret = YS_REGISTER_IRQ(&irq_table->nh, YS_IRQ_NB_REGISTER_FIXED,
				      i, pdev_priv->pdev, sub);
		if (ret < 0) {
			ys_dev_err("Setup irq %d error: %d", i, ret);
			return ret;
		}
	}

	ys_debug("init irq count %d", init_count);

	return 0;
}

int ys_ndev_init(struct ys_pdev_priv *pdev_priv)
{
	int ret;
	int i;

	for (i = 0; i < pdev_priv->nic_type->ndev_sum; i++)
		ys_aux_add_adev(pdev_priv->pdev, (int)i, AUX_NAME_ETH);

	ret = ys_register_init_irqs(pdev_priv);
	if (ret)
		return ret;

	return 0;
}

void ys_ndev_uninit(struct ys_pdev_priv *pdev_priv)
{
	struct ys_irq_table *irq_table = &pdev_priv->irq_table;
	int i;

	for (i = 0; i < irq_table->max; i++)
		YS_UNREGISTER_IRQ(&irq_table->nh, i, pdev_priv->pdev);

	for (i = 0; i < pdev_priv->nic_type->ndev_sum; i++)
		ys_aux_del_match_adev(pdev_priv->pdev, (int)i, AUX_NAME_ETH);
}
