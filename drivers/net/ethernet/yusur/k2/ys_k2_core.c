// SPDX-License-Identifier: GPL-2.0
#include <linux/etherdevice.h>
#include <linux/list.h>
#include <linux/netdevice.h>
#include "ys_k2_core.h"

static void ysk2_destroy_rings(struct ysk2_port *k2port)
{
	int i;

	if (!k2port->qps)
		return;

	/* free rings */
	for (i = 0; i < k2port->ndev->num_tx_queues; i++) {
		if (k2port->qps[i].event_ring)
			ysk2_destroy_eq_ring(&k2port->qps[i].event_ring);
		if (k2port->qps[i].tx_ring)
			ysk2_destroy_tx_ring(&k2port->qps[i].tx_ring);
		if (k2port->qps[i].tx_cpl_ring)
			ysk2_destroy_cq_ring(&k2port->qps[i].tx_cpl_ring);
		if (k2port->qps[i].rx_ring)
			ysk2_destroy_tx_ring(&k2port->qps[i].rx_ring);
		if (k2port->qps[i].rx_cpl_ring)
			ysk2_destroy_cq_ring(&k2port->qps[i].rx_cpl_ring);
	}
	kfree(k2port->qps);
	k2port->qps = NULL;
}

static int ysk2_create_rings(struct ysk2_port *k2port)
{
	int ret, i;

	k2port->qps = kcalloc(k2port->ndev->num_tx_queues,
			      sizeof(struct ysk2_qp), GFP_KERNEL);
	if (!k2port->qps)
		return -ENOMEM;

	for (i = 0; i < k2port->ndev->real_num_tx_queues; i++) {
		ret = ysk2_create_eq_ring(k2port, i, YSK2_EQ_ENTR_NUM);
		if (ret)
			goto fail;
		ret = ysk2_create_tx_ring(k2port, i, YSK2_TXQ_ENTR_NUM,
					  YSK2_DEFAULT_FRAGS);
		if (ret)
			goto fail;
		ret = ysk2_create_txcq_ring(k2port, i, YSK2_TXCPL_ENTR_NUM);
		if (ret)
			goto fail;
		ret = ysk2_create_rx_ring(k2port, i, YSK2_RXQ_ENTR_NUM);
		if (ret)
			goto fail;
		ret = ysk2_create_rxcq_ring(k2port, i, YSK2_RXCPL_ENTR_NUM);
		if (ret)
			goto fail;

		/* register cq process handler, top half irq */
		k2port->qps[i].tx_cpl_ring->handler = ysk2_cq_irq_handler;
		k2port->qps[i].rx_cpl_ring->handler = ysk2_cq_irq_handler;
	}

	return 0;

fail:
	ysk2_destroy_rings(k2port);

	return ret;
}

static int ysk2_ndev_start(struct net_device *ndev)
{
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);
	struct ysk2_port *k2port = ndev_priv->adp_priv;
	u32 pkt_maxlen, num_pages;
	int i;

	for (i = 0; i < ndev->real_num_tx_queues; i++) {
		/* set up Event queue */
		ysk2_activate_ring(&k2port->qps[i].event_ring->ring, false);
		/* enable event queue interrupt */
		ysk2_arm_ring_irq(&k2port->qps[i].event_ring->ring);

		/* set up RXCQ */
		ysk2_activate_ring(&k2port->qps[i].rx_cpl_ring->ring, false);
		/* register rxcq napi handler, bottom half irq */
		netif_napi_add(ndev, &k2port->qps[i].rx_cpl_ring->napi,
			       ysk2_napi_poll_cq, NAPI_POLL_WEIGHT);
		napi_enable(&k2port->qps[i].rx_cpl_ring->napi);
		/* enable rx complete queue interrupt */
		ysk2_arm_ring_irq(&k2port->qps[i].rx_cpl_ring->ring);

		/* set up RX queue */
		pkt_maxlen = ndev->features & NETIF_F_LRO ? YSK2_MAX_MTU :
							    ndev->mtu;
		/* pkt_maxlen also include eth header and vlan field */
		pkt_maxlen += ETH_HLEN + ETH_TLEN;
		num_pages = (pkt_maxlen + PAGE_SIZE - 1) >> PAGE_SHIFT;
		num_pages = roundup_pow_of_two(num_pages);
		k2port->qps[i].rx_ring->page_order = ilog2(num_pages);
		/* fill rx desc to receive */
		ysk2_init_rx_buf(k2port->qps[i].rx_ring);
		ysk2_activate_ring(&k2port->qps[i].rx_ring->ring, false);

		/* set up TXCQ */
		ysk2_activate_ring(&k2port->qps[i].tx_cpl_ring->ring, false);
		/* register txcq napi handler, bottom half irq */
		netif_napi_add(ndev, &k2port->qps[i].tx_cpl_ring->napi,
			       ysk2_napi_poll_cq, NAPI_POLL_WEIGHT);
		napi_enable(&k2port->qps[i].tx_cpl_ring->napi);
		/* enable tx complete queue interrupt */
		ysk2_arm_ring_irq(&k2port->qps[i].tx_cpl_ring->ring);

		/* set up TX queue */
		k2port->qps[i].tx_ring->tx_queue = netdev_get_tx_queue(ndev, i);
		ysk2_activate_ring(&k2port->qps[i].tx_ring->ring, true);

		/* enable this channel schedule */
		ys_wr32(k2port->k2nic->hw_addr,
			YSK2_CHN_CONTROL(ndev_priv->qbase + i),
			YSK2_CHN_ENABLE);
	}

	return 0;
}

static void ysk2_ndev_stop(struct net_device *ndev)
{
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);
	struct ysk2_port *k2port = ndev_priv->adp_priv;
	int i;

	if (!k2port)
		return;

	for (i = 0; i < ndev->real_num_tx_queues; i++) {
		/* disable this channel schedule */
		ys_wr32(k2port->k2nic->hw_addr,
			YSK2_CHN_CONTROL(ndev_priv->qbase + i), 0);
		/* deactivate EQ */
		ysk2_unarm_ring_irq(&k2port->qps[i].event_ring->ring);
		/* deactivate TX */
		ysk2_deactivate_ring(&k2port->qps[i].tx_ring->ring);
		ysk2_unarm_ring_irq(&k2port->qps[i].tx_cpl_ring->ring);
		ysk2_deactivate_ring(&k2port->qps[i].tx_cpl_ring->ring);
		napi_disable(&k2port->qps[i].tx_cpl_ring->napi);
		netif_napi_del(&k2port->qps[i].tx_cpl_ring->napi);
		/* deactivate RX */
		ysk2_deactivate_ring(&k2port->qps[i].rx_ring->ring);
		ysk2_unarm_ring_irq(&k2port->qps[i].rx_cpl_ring->ring);
		ysk2_deactivate_ring(&k2port->qps[i].rx_cpl_ring->ring);
		napi_disable(&k2port->qps[i].rx_cpl_ring->napi);
		netif_napi_del(&k2port->qps[i].rx_cpl_ring->napi);
	}

	/* NOTE: sleep is necessary to wait hardware rx pipeline flush */
	msleep(20);

	/* free descriptors in RXTX queues */
	for (i = 0; i < ndev->real_num_tx_queues; i++) {
		ysk2_free_tx_buf(k2port->qps[i].tx_ring);
		ysk2_free_rx_buf(k2port->qps[i].rx_ring);
	}
}

static void ysk2_ndev_update_stat(struct net_device *ndev)
{
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);
	struct ysk2_port *k2port = ndev_priv->adp_priv;
	u64 packets, bytes;
	int i;

	packets = 0;
	bytes = 0;
	for (i = 0; i < ndev->real_num_tx_queues; i++) {
		const struct ysk2_desc_ring *ring = k2port->qps[i].rx_ring;

		packets += READ_ONCE(ring->packets);
		bytes += READ_ONCE(ring->bytes);
	}
	ndev_priv->netdev_stats.rx_packets = packets;
	ndev_priv->netdev_stats.rx_bytes = bytes;

	packets = 0;
	bytes = 0;
	for (i = 0; i < ndev->real_num_tx_queues; i++) {
		const struct ysk2_desc_ring *ring = k2port->qps[i].tx_ring;

		packets += READ_ONCE(ring->packets);
		bytes += READ_ONCE(ring->bytes);
	}

	ndev_priv->netdev_stats.tx_packets = packets;
	ndev_priv->netdev_stats.tx_bytes = bytes;
}

static irqreturn_t ysk2_irq_handler(int irqn, void *data)
{
	struct ys_ndev_priv *ndev_priv;
	struct ys_irq *irq = data;
	struct ysk2_port *k2port;
	struct net_device *ndev;

	ndev = ys_aux_match_ndev(irq->pdev, AUX_TYPE_ETH, 0);
	ndev_priv = netdev_priv(ndev);
	k2port = ndev_priv->adp_priv;

	/* If kernel enable CONFIG_DEBUG_SHIRQ config, free_irq will call
	 * irq_handler again.
	 * We free the event ring resources before free_irq and set the porinter
	 * of event_ring to zero. Therefore, it is nesserry to assert the null
	 * pointer and then do irq procress func.
	 */
	if (unlikely(!k2port->qps || !k2port->qps[irq->index].event_ring))
		return IRQ_HANDLED;

	ysk2_process_eq(k2port->qps[irq->index].event_ring);

	return IRQ_HANDLED;
}

static int ysk2_get_init_irq_sub(struct pci_dev *pdev, int index, void *irq_sub)
{
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(pdev);
	struct ys_irq_sub *sub = (struct ys_irq_sub *)irq_sub;

	if (IS_ERR_OR_NULL(sub))
		return -EINVAL;

	if (index < 0 || index >= pdev_priv->irq_table.max)
		return -EINVAL;

	if (index >= YSK2_DEFAULT_Q_CNT)
		return 1;

	memset(sub, 0, sizeof(*sub));
	sub->irq_type = YS_IRQ_TYPE_QUEUE;
	sub->handler = ysk2_irq_handler;
	sub->bh_type = YS_IRQ_BH_NONE;

	return 0;
}

static int ysk2_ndev_init(struct net_device *ndev)
{
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(ndev_priv->pdev);
	struct ysk2_port *k2port;
	int ret;

	k2port = kzalloc(sizeof(*k2port), GFP_KERNEL);
	if (!k2port)
		return -ENOMEM;

	k2port->ndev = ndev;
	k2port->pdev = ndev_priv->pdev;
	k2port->k2nic = pdev_priv->padp_priv;
	/* qbase for pf/vf ndev is zero */
	k2port->qbase = 0;
	k2port->dev = &k2port->pdev->dev;
	ndev_priv->qbase = k2port->k2nic->hw_qbase + k2port->qbase;
	ndev_priv->adp_priv = k2port;

	/* ethtool -k offload default value */
	ndev->features |= NETIF_F_HIGHDMA;
	ndev->features |= NETIF_F_SG;
	ndev->features |= NETIF_F_GSO;
	ndev->features |= NETIF_F_GRO;

	/* ethtool -k offload option */
	ndev->hw_features |= NETIF_F_SG;
	ndev->hw_features |= NETIF_F_GSO;
	ndev->hw_features |= NETIF_F_GRO;
	ndev->min_mtu = ETH_MIN_MTU;
	ndev->max_mtu = YSK2_MAX_MTU;
	ndev->gso_max_size = YSK2_MAX_MTU;

	/* default queue should be set by platform */
	netif_set_real_num_tx_queues(ndev, YSK2_DEFAULT_Q_CNT);
	netif_set_real_num_rx_queues(ndev, YSK2_DEFAULT_Q_CNT);

	ys_dev_info("queue pairs base: %u qnum: %u real_qnum: %u\n",
		    ndev_priv->qbase, ndev->num_tx_queues,
			ndev->real_num_tx_queues);

	/* create queue pair rings */
	ret = ysk2_create_rings(k2port);
	if (ret) {
		ys_dev_info("create rings failed. ret:%d", ret);
		kfree(k2port);
		return ret;
	}

	return 0;
}

static void ysk2_ndev_uninit(struct net_device *ndev)
{
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);
	struct ysk2_port *k2port = ndev_priv->adp_priv;

	/* destroy ring buffers */
	ysk2_destroy_rings(k2port);
	kfree(k2port);
}

static struct hw_adapter_ops ysk2_ops = {
	.hw_adp_init = ysk2_ndev_init,
	.hw_adp_uninit = ysk2_ndev_uninit,
	.hw_adp_start = ysk2_ndev_start,
	.hw_adp_stop = ysk2_ndev_stop,
	.hw_adp_update_stat = ysk2_ndev_update_stat,
	.hw_adp_send = ysk2_start_xmit,
	.hw_adp_get_init_irq_sub = ysk2_get_init_irq_sub,
};

int ysk2_pdev_init(struct ys_pdev_priv *pdev_priv)
{
	struct ysk2_nic *k2nic;
	void __iomem *addr;
	u32 val;

	k2nic = kzalloc(sizeof(*k2nic), GFP_KERNEL);
	if (!k2nic)
		return -ENOMEM;

	/* get mmio base */
	k2nic->hw_addr =
		(void *)pdev_priv->bar_addr[pdev_priv->nic_type->bar_base];

	/* get pf id */
	val = ys_rd32(k2nic->hw_addr, YSK2_FUNC_ID);
	pdev_priv->pf_id = FIELD_GET(YSK2_FID_PF, val);

	/* get qbase and netdev_qnum */
	if (pdev_priv->nic_type->is_vf) {
		/* only developer debug or dpdk driver */
		/* may unset this register */
		if (unlikely(!ys_rd32(k2nic->hw_addr, YSK2_FUNC_QREADY))) {
			ys_dev_err("vf is not ready!");
			kfree(k2nic);
			return -EINVAL;
		}
		k2nic->hw_qbase = ys_rd32(k2nic->hw_addr, YSK2_FUNC_QSTART);
		pdev_priv->netdev_qnum =
			ys_rd32(k2nic->hw_addr, YSK2_FUNC_QSTOP) -
				k2nic->hw_qbase + 1;
	} else {
		/* each pf own 512 queues */
		k2nic->hw_qbase = pdev_priv->pf_id * 0x200;
		/* get vf hw func base id */
		k2nic->vfbase = ys_rd32(k2nic->hw_addr,
					YSK2_CFG_VF_START(pdev_priv->pf_id));
		pdev_priv->total_qnum = 0x200;
		pdev_priv->netdev_qnum = YSK2_MAX_RINGS;

		/* PF should enable queue assignment */
		ys_wr32(k2nic->hw_addr, YSK2_CFG_QSTART(pdev_priv->pf_id),
			k2nic->hw_qbase);
		ys_wr32(k2nic->hw_addr, YSK2_CFG_QSTOP(pdev_priv->pf_id),
			k2nic->hw_qbase + pdev_priv->total_qnum - 1);
		ys_wr32(k2nic->hw_addr, YSK2_CFG_QREADY(pdev_priv->pf_id), 1);
		ys_wr32(k2nic->hw_addr, YSK2_CFG_IRQ_BASE(0),
			pdev_priv->total_qnum);

		/* enable tx, uninit can't disable tx for multi pf! */
		ys_wr32(k2nic->hw_addr, YSK2_CFG_TX_SCH_ENABLE, 1);
	}

	pdev_priv->padp_priv = k2nic;
	pdev_priv->ops = &ysk2_ops;

	addr = pdev_priv->bar_addr[pdev_priv->nic_type->bar_base];
	ys_wr32(addr, MAC_CHMODE0_L(pdev_priv->pf_id), CHMODE0_CFG0_L);
	ys_wr32(addr, MAC_CHMODE0_H(pdev_priv->pf_id), CHMODE0_CFG0_H);

	ys_wr32(addr, MAC_PCSTXOVERRIDE1_L(pdev_priv->pf_id),
		PCSTXOVERRIDE1_CFG_L);
	ys_wr32(addr, MAC_PCSTXOVERRIDE1_H(pdev_priv->pf_id),
		PCSTXOVERRIDE1_CFG_H);

	ys_wr32(addr, MAC_MACCFG0_L(pdev_priv->pf_id), MACCFG0_CFG_L);
	ys_wr32(addr, MAC_MACCFG0_H(pdev_priv->pf_id), MACCFG0_CFG_H);

	ys_wr32(addr, MAC_TXFIFOCFG_0_L(pdev_priv->pf_id), TXFIFOCFG_0_CFG_L);
	ys_wr32(addr, MAC_TXFIFOCFG_0_H(pdev_priv->pf_id), TXFIFOCFG_0_CFG_H);

	ys_wr32(addr, MAC_CHCONFIG3_0_L(pdev_priv->pf_id), CHCONFIG3_0_CFG_L);
	ys_wr32(addr, MAC_CHCONFIG3_0_H(pdev_priv->pf_id), CHCONFIG3_0_CFG_H);

	ys_wr32(addr, MAC_CHCONFIG4_0_L(pdev_priv->pf_id), CHCONFIG4_0_CFG_L);
	ys_wr32(addr, MAC_CHCONFIG4_0_H(pdev_priv->pf_id), CHCONFIG4_0_CFG_H);

	ys_wr32(addr, MAC_CHCONFIG8_0_L(pdev_priv->pf_id), CHCONFIG8_0_CFG_L);
	ys_wr32(addr, MAC_CHCONFIG8_0_H(pdev_priv->pf_id), CHCONFIG8_0_CFG_H);

	ys_wr32(addr, MAC_CHCONFIG31_0_L(pdev_priv->pf_id), CHCONFIG31_0_CFG_L);
	ys_wr32(addr, MAC_CHCONFIG31_0_H(pdev_priv->pf_id), CHCONFIG31_0_CFG_H);

	ys_wr32(addr, MAC_PCSRXOVERRIDE0_0_L(pdev_priv->pf_id),
		PCSRXOVERRIDE0_0_CFG_L);
	ys_wr32(addr, MAC_PCSRXOVERRIDE0_0_H(pdev_priv->pf_id),
		PCSRXOVERRIDE0_0_CFG_H);

	ys_wr32(addr, MAC_CHMODE0_L(pdev_priv->pf_id), CHMODE0_CFG1_L);
	ys_wr32(addr, MAC_CHMODE0_H(pdev_priv->pf_id), CHMODE0_CFG1_H);

	ys_rd32(addr, MAC_CHSTS_0_L(pdev_priv->pf_id));
	ys_wr32(addr, MAC_BIGENDIAN_CONVERTE(pdev_priv->pf_id), 1);

	return 0;
}

void ysk2_pdev_uninit(struct ys_pdev_priv *pdev_priv)
{
	struct ysk2_nic *k2nic = pdev_priv->padp_priv;

	if (!pdev_priv->nic_type->is_vf)
		ys_wr32(k2nic->hw_addr, YSK2_CFG_QREADY(pdev_priv->pf_id), 0);
	pdev_priv->ops = NULL;
	kfree(k2nic);
}
