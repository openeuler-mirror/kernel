// SPDX-License-Identifier: GPL-2.0+
/* Copyright (c) 2022 - 2024 Motorcomm Electronic Technology Co.,Ltd.
 *
 * Below is a simplified block diagram of YT6801 chip and its relevant
 * interfaces.
 *                      ||
 *  ********************++**********************
 *  *            | PCIE Endpoint |             *
 *  *            +---------------+             *
 *  *                | GMAC |                  *
 *  *                +--++--+                  *
 *  *                  |**|                    *
 *  *         GMII --> |**| <-- MDIO           *
 *  *                 +-++--+                  *
 *  *            | Integrated PHY |  YT8531S   *
 *  *                 +-++-+                   *
 *  ********************||******************* **
 */

#include <linux/if_vlan.h>
#include <linux/module.h>
#include <linux/phy.h>
#include <linux/tcp.h>

#include "yt6801_type.h"
#include "yt6801_desc.h"

const struct net_device_ops *fxgmac_get_netdev_ops(void);
static void fxgmac_napi_enable(struct fxgmac_pdata *priv);
const struct ethtool_ops *fxgmac_get_ethtool_ops(void);

static const struct ethtool_ops fxgmac_ethtool_ops = {
	.get_link		= ethtool_op_get_link,
	.get_link_ksettings	= phy_ethtool_get_link_ksettings,
	.set_link_ksettings	= phy_ethtool_set_link_ksettings
};

const struct ethtool_ops *fxgmac_get_ethtool_ops(void)
{
	return &fxgmac_ethtool_ops;
}

#define PHY_WR_CONFIG(reg_offset)	(0x8000205 + ((reg_offset) * 0x10000))
static int fxgmac_phy_write_reg(struct fxgmac_pdata *priv, u32 reg_id, u32 data)
{
	u32 val;
	int ret;

	fxgmac_io_wr(priv, MAC_MDIO_DATA, data);
	fxgmac_io_wr(priv, MAC_MDIO_ADDR, PHY_WR_CONFIG(reg_id));
	ret = read_poll_timeout_atomic(fxgmac_io_rd, val,
				       !field_get(MAC_MDIO_ADDR_BUSY, val),
				       10, 250, false, priv, MAC_MDIO_ADDR);
	if (ret == -ETIMEDOUT)
		dev_err(priv->dev, "%s, id:%x ctrl:0x%08x, data:0x%08x\n",
			__func__, reg_id, PHY_WR_CONFIG(reg_id), data);

	return ret;
}

#define PHY_RD_CONFIG(reg_offset)	(0x800020d + ((reg_offset) * 0x10000))
static int fxgmac_phy_read_reg(struct fxgmac_pdata *priv, u32 reg_id)
{
	u32 val;
	int ret;

	fxgmac_io_wr(priv, MAC_MDIO_ADDR, PHY_RD_CONFIG(reg_id));
	ret = read_poll_timeout_atomic(fxgmac_io_rd, val,
				       !field_get(MAC_MDIO_ADDR_BUSY, val),
				       10, 250, false, priv, MAC_MDIO_ADDR);
	if (ret == -ETIMEDOUT) {
		dev_err(priv->dev, "%s, id:%x, ctrl:0x%08x, val:0x%08x.\n",
			__func__, reg_id, PHY_RD_CONFIG(reg_id), val);
		return ret;
	}

	return fxgmac_io_rd(priv, MAC_MDIO_DATA); /* Read data */
}

static int fxgmac_mdio_write_reg(struct mii_bus *mii_bus, int phyaddr,
				 int phyreg, u16 val)
{
	if (phyaddr > 0)
		return -ENODEV;

	return fxgmac_phy_write_reg(mii_bus->priv, phyreg, val);
}

static int fxgmac_mdio_read_reg(struct mii_bus *mii_bus, int phyaddr,
				int phyreg)
{
	if (phyaddr > 0)
		return -ENODEV;

	return fxgmac_phy_read_reg(mii_bus->priv, phyreg);
}

static int fxgmac_mdio_register(struct fxgmac_pdata *priv)
{
	struct pci_dev *pdev = to_pci_dev(priv->dev);
	struct phy_device *phydev;
	struct mii_bus *new_bus;
	int ret;

	new_bus = devm_mdiobus_alloc(&pdev->dev);
	if (!new_bus)
		return -ENOMEM;

	new_bus->name = "yt6801";
	new_bus->priv = priv;
	new_bus->parent = &pdev->dev;
	new_bus->read = fxgmac_mdio_read_reg;
	new_bus->write = fxgmac_mdio_write_reg;
	snprintf(new_bus->id, MII_BUS_ID_SIZE, "yt6801-%x-%x",
		 pci_domain_nr(pdev->bus), pci_dev_id(pdev));

	ret = devm_mdiobus_register(&pdev->dev, new_bus);
	if (ret < 0)
		return ret;

	phydev = mdiobus_get_phy(new_bus, 0);
	if (!phydev)
		return -ENODEV;

	priv->phydev = phydev;
	return 0;
}

static void fxgmac_tx_start_xmit(struct fxgmac_channel *channel,
				 struct fxgmac_ring *ring)
{
	struct fxgmac_desc_data *desc_data;

	wmb();  /* Make sure everything is written before the register write */

	/* Issue a poll command to Tx DMA by writing address
	 * of next immediate free descriptor
	 */
	desc_data = FXGMAC_GET_DESC_DATA(ring, ring->cur);
	fxgmac_dma_io_wr(channel, DMA_CH_TDTR_LO,
			 lower_32_bits(desc_data->dma_desc_addr));

	ring->tx.xmit_more = 0;
}

static unsigned int fxgmac_desc_tx_avail(struct fxgmac_ring *ring)
{
	if (ring->dirty > ring->cur)
		return ring->dirty - ring->cur;
	else
		return ring->dma_desc_count - ring->cur + ring->dirty;
}

static netdev_tx_t fxgmac_maybe_stop_tx_queue(struct fxgmac_channel *channel,
					      struct fxgmac_ring *ring,
					      unsigned int count)
{
	struct fxgmac_pdata *priv = channel->priv;

	if (count > fxgmac_desc_tx_avail(ring)) {
		netdev_err(priv->ndev, "Tx queue stopped, not enough descriptors available\n");
		netif_stop_subqueue(priv->ndev, channel->queue_index);
		ring->tx.queue_stopped = 1;

		/* If we haven't notified the hardware because of xmit_more
		 * support, tell it now
		 */
		if (ring->tx.xmit_more)
			fxgmac_tx_start_xmit(channel, ring);

		return NETDEV_TX_BUSY;
	}

	return NETDEV_TX_OK;
}

static void fxgmac_enable_msix_one_irq(struct fxgmac_pdata *priv, u32 int_id)
{
	fxgmac_io_wr(priv, MSIX_TBL_MASK + int_id * 16, 0);
}

static void fxgmac_disable_msix_one_irq(struct fxgmac_pdata *priv, u32 intid)
{
	fxgmac_io_wr(priv, MSIX_TBL_MASK + intid * 16, 1);
}

static void fxgmac_disable_mgm_irq(struct fxgmac_pdata *priv)
{
	fxgmac_io_wr_bits(priv, MGMT_INT_CTRL0, MGMT_INT_CTRL0_INT_MASK,
			  MGMT_INT_CTRL0_INT_MASK_MASK);
}

static irqreturn_t fxgmac_isr(int irq, void *data)
{
	struct fxgmac_pdata *priv = data;
	u32 val;

	val = fxgmac_io_rd(priv, MGMT_INT_CTRL0);
	if (!(val & MGMT_INT_CTRL0_INT_STATUS_RXTX))
		return IRQ_NONE;

	/* Restart the device on a Fatal Bus Error */
	for (u32 i = 0; i < priv->channel_count; i++) {
		val = fxgmac_dma_io_rd(priv->channel_head + i, DMA_CH_SR);
		if (field_get(DMA_CH_SR_FBE, val))
			schedule_work(&priv->restart_work);
		 /* Clear all the interrupts which are set */
		fxgmac_dma_io_wr(priv->channel_head + i, DMA_CH_SR, val);
	}

	fxgmac_disable_mgm_irq(priv);
	napi_schedule_irqoff(&priv->napi); /* Turn on polling */
	return IRQ_HANDLED;
}

static irqreturn_t fxgmac_dma_isr(int irq, void *data)
{
	struct fxgmac_channel *channel = data;

	if (irq == channel->dma_irq_tx) {
		fxgmac_disable_msix_one_irq(channel->priv, MSI_ID_TXQ0);
		/* Clear Tx signal */
		fxgmac_dma_io_wr(channel, DMA_CH_SR, DMA_CH_SR_TI);
		napi_schedule_irqoff(&channel->napi_tx);
		return IRQ_HANDLED;
	}

	fxgmac_disable_msix_one_irq(channel->priv, channel->queue_index);
	/* Clear Rx signal */
	fxgmac_dma_io_wr(channel, DMA_CH_SR, DMA_CH_SR_RI);
	napi_schedule_irqoff(&channel->napi_rx);
	return IRQ_HANDLED;
}

static void napi_disable_del(struct fxgmac_pdata *priv, struct napi_struct *n,
			     u32 flag)
{
	napi_disable(n);
	netif_napi_del(n);
	priv->int_flag &= ~flag;
}

static void fxgmac_napi_disable(struct fxgmac_pdata *priv)
{
	struct fxgmac_channel *channel = priv->channel_head;
	u32 rx_napi[] = {INT_FLAG_RX0_NAPI, INT_FLAG_RX1_NAPI,
			INT_FLAG_RX2_NAPI, INT_FLAG_RX3_NAPI};

	if (!priv->per_channel_irq) {
		if (!field_get(INT_FLAG_LEGACY_NAPI, priv->int_flag))
			return;

		napi_disable_del(priv, &priv->napi,
				 INT_FLAG_LEGACY_NAPI);
		return;
	}

	if (field_get(INT_FLAG_TX_NAPI, priv->int_flag))
		napi_disable_del(priv, &channel->napi_tx, INT_FLAG_TX_NAPI);

	for (u32 i = 0; i < priv->channel_count; i++, channel++)
		if (priv->int_flag & rx_napi[i])
			napi_disable_del(priv, &channel->napi_rx, rx_napi[i]);
}

static void fxgmac_free_irqs(struct fxgmac_pdata *priv)
{
	u32 rx_irq[] = {INT_FLAG_RX0_IRQ, INT_FLAG_RX1_IRQ,
			INT_FLAG_RX2_IRQ, INT_FLAG_RX3_IRQ};
	struct fxgmac_channel *channel = priv->channel_head;

	if (!field_get(INT_FLAG_MSIX, priv->int_flag) &&
	    field_get(INT_FLAG_LEGACY_IRQ, priv->int_flag)) {
		devm_free_irq(priv->dev, priv->dev_irq, priv);
		priv->int_flag &= ~INT_FLAG_LEGACY_IRQ;
	}

	if (!priv->per_channel_irq)
		return;

	if (field_get(INT_FLAG_TX_IRQ, priv->int_flag)) {
		priv->int_flag &= ~INT_FLAG_TX_IRQ;
		devm_free_irq(priv->dev, channel->dma_irq_tx, channel);
	}

	for (u32 i = 0; i < priv->channel_count; i++, channel++)
		if (priv->int_flag & rx_irq[i]) {
			priv->int_flag &= ~rx_irq[i];
			devm_free_irq(priv->dev, channel->dma_irq_rx, channel);
		}
}

static int fxgmac_request_irqs(struct fxgmac_pdata *priv)
{
	u32 rx_irq[] = {INT_FLAG_RX0_IRQ, INT_FLAG_RX1_IRQ,
			INT_FLAG_RX2_IRQ, INT_FLAG_RX3_IRQ};
	u32 i = 0, msi = field_get(INT_FLAG_MSI, priv->int_flag);
	struct fxgmac_channel *channel = priv->channel_head;
	struct net_device *ndev = priv->ndev;
	int ret;

	if (!field_get(INT_FLAG_MSIX, priv->int_flag) &&
	    !field_get(INT_FLAG_LEGACY_IRQ, priv->int_flag)) {
		priv->int_flag |= INT_FLAG_LEGACY_IRQ;
		ret = devm_request_irq(priv->dev, priv->dev_irq, fxgmac_isr,
				       msi ? 0 : IRQF_SHARED, ndev->name,
				       priv);
		if (ret) {
			dev_err(priv->dev, "Requesting irq:%d, failed:%d\n",
				priv->dev_irq, ret);
			return ret;
		}
	}

	if (!priv->per_channel_irq)
		return 0;

	if (!field_get(INT_FLAG_TX_IRQ, priv->int_flag)) {
		snprintf(channel->dma_irq_tx_name,
			 sizeof(channel->dma_irq_tx_name) - 1,
			 "%s-ch%d-Tx-%u", netdev_name(ndev), 0,
			 channel->queue_index);
		priv->int_flag |= INT_FLAG_TX_IRQ;
		ret = devm_request_irq(priv->dev, channel->dma_irq_tx,
				       fxgmac_dma_isr, 0,
				       channel->dma_irq_tx_name, channel);
		if (ret) {
			dev_err(priv->dev, "dev:%p, channel:%p\n",
				priv->dev, channel);

			dev_err(priv->dev, "Requesting tx irq:%d, failed:%d\n",
				channel->dma_irq_tx, ret);
			goto err_irq;
		}
	}

	for (i = 0; i < priv->channel_count; i++, channel++) {
		snprintf(channel->dma_irq_rx_name,
			 sizeof(channel->dma_irq_rx_name) - 1, "%s-ch%d-Rx-%u",
			 netdev_name(ndev), i, channel->queue_index);

		if ((priv->int_flag & rx_irq[i]) != rx_irq[i]) {
			priv->int_flag |= rx_irq[i];
			ret = devm_request_irq(priv->dev, channel->dma_irq_rx,
					       fxgmac_dma_isr, 0,
					       channel->dma_irq_rx_name,
					       channel);
			if (ret) {
				dev_err(priv->dev, "Requesting rx irq:%d, failed:%d\n",
					channel->dma_irq_rx, ret);
				goto err_irq;
			}
		}
	}

	return 0;

err_irq:
	fxgmac_free_irqs(priv);
	return ret;
}

static void fxgmac_free_tx_data(struct fxgmac_pdata *priv)
{
	struct fxgmac_channel *channel = priv->channel_head;
	struct fxgmac_ring *ring;

	for (u32 i = 0; i < priv->channel_count; i++, channel++) {
		ring = channel->tx_ring;
		if (!ring)
			break;

		for (u32 j = 0; j < ring->dma_desc_count; j++)
			fxgmac_desc_data_unmap(priv,
					       FXGMAC_GET_DESC_DATA(ring, j));
	}
}

static void fxgmac_free_rx_data(struct fxgmac_pdata *priv)
{
	struct fxgmac_channel *channel = priv->channel_head;
	struct fxgmac_ring *ring;

	for (u32 i = 0; i < priv->channel_count; i++, channel++) {
		ring = channel->rx_ring;
		if (!ring)
			break;

		for (u32 j = 0; j < ring->dma_desc_count; j++)
			fxgmac_desc_data_unmap(priv,
					       FXGMAC_GET_DESC_DATA(ring, j));
	}
}

static void fxgmac_enable_tx(struct fxgmac_pdata *priv)
{
	struct fxgmac_channel *channel = priv->channel_head;

	/* Enable Tx DMA channel */
	fxgmac_dma_wr_bits(channel, DMA_CH_TCR, DMA_CH_TCR_ST, 1);

	/* Enable Tx queue */
	fxgmac_mtl_wr_bits(priv, 0, MTL_Q_TQOMR, MTL_Q_TQOMR_TXQEN,
			   MTL_Q_ENABLED);
	/* Enable MAC Tx */
	fxgmac_io_wr_bits(priv, MAC_CR, MAC_CR_TE, 1);
}

static void fxgmac_prepare_tx_stop(struct fxgmac_pdata *priv,
				   struct fxgmac_channel *channel)
{
	unsigned long tx_timeout;
	unsigned int tx_status;

	/* The Tx engine cannot be stopped if it is actively processing
	 * descriptors. Wait for the Tx engine to enter the stopped or
	 * suspended state.
	 */
	tx_timeout = jiffies + (FXGMAC_DMA_STOP_TIMEOUT * HZ);

	while (time_before(jiffies, tx_timeout)) {
		tx_status = fxgmac_io_rd(priv, DMA_DSR0);
		tx_status = field_get(DMA_DSR0_TPS, tx_status);
		if (tx_status == DMA_TPS_STOPPED ||
		    tx_status == DMA_TPS_SUSPENDED)
			break;

		fsleep(500);
	}

	if (!time_before(jiffies, tx_timeout))
		dev_err(priv->dev, "timed out waiting for Tx DMA channel  stop\n");
}

static void fxgmac_disable_tx(struct fxgmac_pdata *priv)
{
	struct fxgmac_channel *channel = priv->channel_head;

	/* Prepare for Tx DMA channel stop */
	fxgmac_prepare_tx_stop(priv, channel);

	fxgmac_io_wr_bits(priv, MAC_CR, MAC_CR_TE, 0); /* Disable MAC Tx */

	/* Disable Tx queue */
	fxgmac_mtl_wr_bits(priv, 0, MTL_Q_TQOMR, MTL_Q_TQOMR_TXQEN,
			   MTL_Q_DISABLED);

	/* Disable Tx DMA channel */
	fxgmac_dma_wr_bits(channel, DMA_CH_TCR, DMA_CH_TCR_ST, 0);
}

static void fxgmac_enable_rx(struct fxgmac_pdata *priv)
{
	struct fxgmac_channel *channel = priv->channel_head;
	u32 val = 0, i;

	/* Enable each Rx DMA channel */
	for (i = 0; i < priv->channel_count; i++, channel++)
		fxgmac_dma_wr_bits(channel, DMA_CH_RCR, DMA_CH_RCR_SR, 1);

	/* Enable each Rx queue */
	for (i = 0; i < priv->rx_q_count; i++)
		val |= (0x02 << (i << 1));

	fxgmac_io_wr(priv, MAC_RQC0R, val);

	/* Enable MAC Rx */
	fxgmac_io_wr_bits(priv, MAC_CR, MAC_CR_CST, 1);
	fxgmac_io_wr_bits(priv, MAC_CR,  MAC_CR_ACS, 1);
	fxgmac_io_wr_bits(priv, MAC_CR,  MAC_CR_RE, 1);
}

static void fxgmac_prepare_rx_stop(struct fxgmac_pdata *priv,
				   unsigned int queue)
{
	unsigned int rx_status, rx_q, rx_q_sts;
	unsigned long rx_timeout;

	/* The Rx engine cannot be stopped if it is actively processing
	 * packets. Wait for the Rx queue to empty the Rx fifo.
	 */
	rx_timeout = jiffies + (FXGMAC_DMA_STOP_TIMEOUT * HZ);

	while (time_before(jiffies, rx_timeout)) {
		rx_status = fxgmac_mtl_io_rd(priv, queue, MTL_Q_RQDR);
		rx_q = field_get(MTL_Q_RQDR_PRXQ, rx_status);
		rx_q_sts = field_get(MTL_Q_RQDR_RXQSTS, rx_status);
		if (rx_q == 0 && rx_q_sts == 0)
			break;

		fsleep(500);
	}

	if (!time_before(jiffies, rx_timeout))
		dev_err(priv->dev, "timed out waiting for Rx queue %u to empty\n",
			queue);
}

static void fxgmac_disable_rx(struct fxgmac_pdata *priv)
{
	struct fxgmac_channel *channel = priv->channel_head;
	u32 i;

	/* Disable MAC Rx */
	fxgmac_io_wr_bits(priv, MAC_CR,  MAC_CR_CST, 0);
	fxgmac_io_wr_bits(priv, MAC_CR,  MAC_CR_ACS, 0);
	fxgmac_io_wr_bits(priv, MAC_CR,  MAC_CR_RE, 0);

	/* Prepare for Rx DMA channel stop */
	for (i = 0; i < priv->rx_q_count; i++)
		fxgmac_prepare_rx_stop(priv, i);

	fxgmac_io_wr(priv, MAC_RQC0R, 0); /* Disable each Rx queue */

	/* Disable each Rx DMA channel */
	for (i = 0; i < priv->channel_count; i++, channel++)
		fxgmac_dma_wr_bits(channel, DMA_CH_RCR, DMA_CH_RCR_SR, 0);
}

static void fxgmac_default_speed_duplex_config(struct fxgmac_pdata *priv)
{
	priv->mac_duplex = DUPLEX_FULL;
	priv->mac_speed = SPEED_1000;
}

static void fxgmac_config_mac_speed(struct fxgmac_pdata *priv)
{
	if (priv->mac_duplex == DUPLEX_UNKNOWN &&
	    priv->mac_speed == SPEED_UNKNOWN)
		fxgmac_default_speed_duplex_config(priv);

	fxgmac_io_wr_bits(priv, MAC_CR,  MAC_CR_DM, priv->mac_duplex);

	switch (priv->mac_speed) {
	case SPEED_1000:
		fxgmac_io_wr_bits(priv, MAC_CR,  MAC_CR_PS, 0);
		fxgmac_io_wr_bits(priv, MAC_CR,  MAC_CR_FES, 0);
		break;
	case SPEED_100:
		fxgmac_io_wr_bits(priv, MAC_CR,  MAC_CR_PS, 1);
		fxgmac_io_wr_bits(priv, MAC_CR,  MAC_CR_FES, 1);
		break;
	case SPEED_10:
		fxgmac_io_wr_bits(priv, MAC_CR,  MAC_CR_PS, 1);
		fxgmac_io_wr_bits(priv, MAC_CR,  MAC_CR_FES, 0);
		break;
	default:
		WARN_ON(1);
		break;
	}
}

static void fxgmac_phylink_handler(struct net_device *ndev)
{
	struct fxgmac_pdata *priv = netdev_priv(ndev);

	priv->mac_speed = priv->phydev->speed;
	priv->mac_duplex = priv->phydev->duplex;

	if (priv->phydev->link) {
		fxgmac_config_mac_speed(priv);
		fxgmac_enable_rx(priv);
		fxgmac_enable_tx(priv);
		if (netif_running(priv->ndev))
			netif_tx_wake_all_queues(priv->ndev);
	} else {
		netif_tx_stop_all_queues(priv->ndev);
		fxgmac_disable_rx(priv);
		fxgmac_disable_tx(priv);
	}

	phy_print_status(priv->phydev);
}

static int fxgmac_phy_connect(struct fxgmac_pdata *priv)
{
	struct phy_device *phydev = priv->phydev;
	int ret;

	priv->phydev->irq = PHY_POLL;
	ret = phy_connect_direct(priv->ndev, phydev, fxgmac_phylink_handler,
				 PHY_INTERFACE_MODE_INTERNAL);
	if (ret)
		return ret;

	phy_support_asym_pause(phydev);
	priv->phydev->mac_managed_pm = 1;
	phy_attached_info(phydev);

	return 0;
}

static void fxgmac_enable_msix_irqs(struct fxgmac_pdata *priv)
{
	for (u32 intid = 0; intid < MSIX_TBL_MAX_NUM; intid++)
		fxgmac_enable_msix_one_irq(priv, intid);
}

static void __fxgmac_set_mac_address(struct fxgmac_pdata *priv, u8 *addr)
{
	u32 mac_hi, mac_lo;

	mac_lo = (u32)addr[0] | ((u32)addr[1] << 8) | ((u32)addr[2] << 16) |
		 ((u32)addr[3] << 24);

	mac_hi = (u32)addr[4] | ((u32)addr[5] << 8);

	fxgmac_io_wr(priv, MAC_MACA0LR, mac_lo);
	fxgmac_io_wr(priv, MAC_MACA0HR, mac_hi);
}

static void fxgmac_config_mac_address(struct fxgmac_pdata *priv)
{
	__fxgmac_set_mac_address(priv, priv->mac_addr);
	fxgmac_io_wr_bits(priv, MAC_PFR, MAC_PFR_HPF, 1);
	fxgmac_io_wr_bits(priv, MAC_PFR, MAC_PFR_HUC, 1);
	fxgmac_io_wr_bits(priv, MAC_PFR, MAC_PFR_HMC, 1);
}

static void fxgmac_config_crc_check_en(struct fxgmac_pdata *priv)
{
	fxgmac_io_wr_bits(priv, MAC_ECR, MAC_ECR_DCRCC, 1);
}

static void fxgmac_config_checksum_offload(struct fxgmac_pdata *priv)
{
	if (priv->ndev->features & NETIF_F_RXCSUM)
		fxgmac_io_wr_bits(priv, MAC_CR, MAC_CR_IPC, 1);
	else
		fxgmac_io_wr_bits(priv, MAC_CR, MAC_CR_IPC, 0);
}

static void fxgmac_set_promiscuous_mode(struct fxgmac_pdata *priv,
					unsigned int enable)
{
	fxgmac_io_wr_bits(priv, MAC_PFR, MAC_PFR_PR, enable);
}

static void fxgmac_enable_rx_broadcast(struct fxgmac_pdata *priv,
				       unsigned int enable)
{
	fxgmac_io_wr_bits(priv, MAC_PFR, MAC_PFR_DBF, enable);
}

static void fxgmac_set_all_multicast_mode(struct fxgmac_pdata *priv,
					  unsigned int enable)
{
	fxgmac_io_wr_bits(priv, MAC_PFR, MAC_PFR_PM, enable);
}

static void fxgmac_config_rx_mode(struct fxgmac_pdata *priv)
{
	u32 pr_mode, am_mode, bd_mode;

	pr_mode = ((priv->ndev->flags & IFF_PROMISC) != 0);
	am_mode = ((priv->ndev->flags & IFF_ALLMULTI) != 0);
	bd_mode = ((priv->ndev->flags & IFF_BROADCAST) != 0);

	fxgmac_enable_rx_broadcast(priv, bd_mode);
	fxgmac_set_promiscuous_mode(priv, pr_mode);
	fxgmac_set_all_multicast_mode(priv, am_mode);
}

static void fxgmac_config_tx_flow_control(struct fxgmac_pdata *priv)
{
	/* Set MTL flow control */
	for (u32 i = 0; i < priv->rx_q_count; i++)
		fxgmac_mtl_wr_bits(priv, i, MTL_Q_RQOMR, MTL_Q_RQOMR_EHFC,
				   priv->tx_pause);

	/* Set MAC flow control */
	fxgmac_io_wr_bits(priv, MAC_Q0TFCR, MAC_Q0TFCR_TFE, priv->tx_pause);

	if (priv->tx_pause == 1) /* Set pause time */
		fxgmac_io_wr_bits(priv, MAC_Q0TFCR, MAC_Q0TFCR_PT, 0xffff);
}

static void fxgmac_config_rx_flow_control(struct fxgmac_pdata *priv)
{
	fxgmac_io_wr_bits(priv, MAC_RFCR, MAC_RFCR_RFE, priv->rx_pause);
}

static void fxgmac_config_rx_coalesce(struct fxgmac_pdata *priv)
{
	struct fxgmac_channel *channel = priv->channel_head;

	for (u32 i = 0; i < priv->channel_count; i++, channel++) {
		if (!channel->rx_ring)
			break;
		fxgmac_dma_wr_bits(channel, DMA_CH_RIWT, DMA_CH_RIWT_RWT,
				   priv->rx_riwt);
	}
}

static void fxgmac_config_rx_fep_disable(struct fxgmac_pdata *priv)
{
	/* Enable the rx queue forward packet with error status
	 * (crc error,gmii_er, watch dog timeout.or overflow)
	 */
	for (u32 i = 0; i < priv->rx_q_count; i++)
		fxgmac_mtl_wr_bits(priv, i, MTL_Q_RQOMR, MTL_Q_RQOMR_FEP, 1);
}

static void fxgmac_config_rx_fup_enable(struct fxgmac_pdata *priv)
{
	for (u32 i = 0; i < priv->rx_q_count; i++)
		fxgmac_mtl_wr_bits(priv, i, MTL_Q_RQOMR, MTL_Q_RQOMR_FUP, 1);
}

static void fxgmac_config_rx_buffer_size(struct fxgmac_pdata *priv)
{
	struct fxgmac_channel *channel = priv->channel_head;

	for (u32 i = 0; i < priv->channel_count; i++, channel++)
		fxgmac_dma_wr_bits(channel, DMA_CH_RCR, DMA_CH_RCR_RBSZ,
				   priv->rx_buf_size);
}

static void fxgmac_config_tso_mode(struct fxgmac_pdata *priv)
{
	fxgmac_dma_wr_bits(priv->channel_head, DMA_CH_TCR, DMA_CH_TCR_TSE,
			   priv->hw_feat.tso);
}

static void fxgmac_config_sph_mode(struct fxgmac_pdata *priv)
{
	struct fxgmac_channel *channel = priv->channel_head;

	for (u32 i = 0; i < priv->channel_count; i++, channel++)
		fxgmac_dma_wr_bits(channel, DMA_CH_CR, DMA_CH_CR_SPH, 0);

	fxgmac_io_wr_bits(priv, MAC_ECR, MAC_ECR_HDSMS, MAC_ECR_HDSMS_512B);
}

static void fxgmac_config_rx_threshold(struct fxgmac_pdata *priv,
				       unsigned int set_val)
{
	for (u32 i = 0; i < priv->rx_q_count; i++)
		fxgmac_mtl_wr_bits(priv, i, MTL_Q_RQOMR, MTL_Q_RQOMR_RTC,
				   set_val);
}

static void fxgmac_config_mtl_mode(struct fxgmac_pdata *priv)
{
	/* Set Tx to weighted round robin scheduling algorithm */
	fxgmac_io_wr_bits(priv, MTL_OMR, MTL_OMR_ETSALG, MTL_ETSALG_WRR);

	/* Set Tx traffic classes to use WRR algorithm with equal weights */
	fxgmac_mtl_wr_bits(priv, 0, MTL_TC_QWR, MTL_TC_QWR_QW, 1);

	/* Set Rx to strict priority algorithm */
	fxgmac_io_wr_bits(priv, MTL_OMR, MTL_OMR_RAA, MTL_RAA_SP);
}

static void fxgmac_config_queue_mapping(struct fxgmac_pdata *priv)
{
	unsigned int ppq, ppq_extra, prio_queues;
	unsigned int __maybe_unused prio;
	unsigned int reg, val, mask;

	/* Map the 8 VLAN priority values to available MTL Rx queues */
	prio_queues =
		min_t(unsigned int, IEEE_8021QAZ_MAX_TCS, priv->rx_q_count);
	ppq = IEEE_8021QAZ_MAX_TCS / prio_queues;
	ppq_extra = IEEE_8021QAZ_MAX_TCS % prio_queues;

	reg = MAC_RQC2R;
	for (u32 i = 0, prio = 0; i < prio_queues;) {
		val = 0;
		mask = 0;
		for (u32 j = 0; j < ppq; j++) {
			mask |= (1 << prio);
			prio++;
		}

		if (i < ppq_extra) {
			mask |= (1 << prio);
			prio++;
		}

		val |= (mask << ((i++ % MAC_RQC2_Q_PER_REG) << 3));

		if ((i % MAC_RQC2_Q_PER_REG) && i != prio_queues)
			continue;

		fxgmac_io_wr(priv, reg, val);
		reg += MAC_RQC2_INC;
	}

	/* Configure one to one, MTL Rx queue to DMA Rx channel mapping
	 * ie Q0 <--> CH0, Q1 <--> CH1 ... Q7 <--> CH7
	 */
	val = fxgmac_io_rd(priv, MTL_RQDCM0R);
	val |= (MTL_RQDCM0R_Q0MDMACH | MTL_RQDCM0R_Q1MDMACH |
		MTL_RQDCM0R_Q2MDMACH | MTL_RQDCM0R_Q3MDMACH);
	fxgmac_io_wr(priv, MTL_RQDCM0R, val);

	val = fxgmac_io_rd(priv, MTL_RQDCM0R + MTL_RQDCM_INC);
	val |= (MTL_RQDCM1R_Q4MDMACH | MTL_RQDCM1R_Q5MDMACH |
		MTL_RQDCM1R_Q6MDMACH | MTL_RQDCM1R_Q7MDMACH);
	fxgmac_io_wr(priv, MTL_RQDCM0R + MTL_RQDCM_INC, val);
}

static unsigned int fxgmac_calculate_per_queue_fifo(unsigned int fifo_size,
						    unsigned int queue_count)
{
	u32 q_fifo_size, p_fifo;

	/* Calculate the configured fifo size */
	q_fifo_size = 1 << (fifo_size + 7);

#define FXGMAC_MAX_FIFO 81920
	/* The configured value may not be the actual amount of fifo RAM */
	q_fifo_size = min_t(unsigned int, FXGMAC_MAX_FIFO, q_fifo_size);
	q_fifo_size = q_fifo_size / queue_count;

	/* Each increment in the queue fifo size represents 256 bytes of
	 * fifo, with 0 representing 256 bytes. Distribute the fifo equally
	 * between the queues.
	 */
	p_fifo = q_fifo_size / 256;
	if (p_fifo)
		p_fifo--;

	return p_fifo;
}

static void fxgmac_config_tx_fifo_size(struct fxgmac_pdata *priv)
{
	u32 fifo_size;

	fifo_size = fxgmac_calculate_per_queue_fifo(priv->hw_feat.tx_fifo_size,
						    FXGMAC_TX_1_Q);
	fxgmac_mtl_wr_bits(priv, 0, MTL_Q_TQOMR, MTL_Q_TQOMR_TQS, fifo_size);
}

static void fxgmac_config_rx_fifo_size(struct fxgmac_pdata *priv)
{
	u32 fifo_size;

	fifo_size = fxgmac_calculate_per_queue_fifo(priv->hw_feat.rx_fifo_size,
						    priv->rx_q_count);

	for (u32 i = 0; i < priv->rx_q_count; i++)
		fxgmac_mtl_wr_bits(priv, i, MTL_Q_RQOMR, MTL_Q_RQOMR_RQS,
				   fifo_size);
}

static void fxgmac_config_flow_control_threshold(struct fxgmac_pdata *priv)
{
	for (u32 i = 0; i < priv->rx_q_count; i++) {
		/* Activate flow control when less than 4k left in fifo */
		fxgmac_mtl_wr_bits(priv, i, MTL_Q_RQOMR, MTL_Q_RQOMR_RFA, 6);
		/* De-activate flow control when more than 6k left in fifo */
		fxgmac_mtl_wr_bits(priv, i, MTL_Q_RQOMR, MTL_Q_RQOMR_RFD, 10);
	}
}

static void fxgmac_config_tx_threshold(struct fxgmac_pdata *priv,
				       unsigned int set_val)
{
	fxgmac_mtl_wr_bits(priv, 0, MTL_Q_TQOMR, MTL_Q_TQOMR_TTC, set_val);
}

static void fxgmac_config_rsf_mode(struct fxgmac_pdata *priv,
				   unsigned int set_val)
{
	for (u32 i = 0; i < priv->rx_q_count; i++)
		fxgmac_mtl_wr_bits(priv, i, MTL_Q_RQOMR, MTL_Q_RQOMR_RSF,
				   set_val);
}

static void fxgmac_config_tsf_mode(struct fxgmac_pdata *priv,
				   unsigned int set_val)
{
	fxgmac_mtl_wr_bits(priv, 0, MTL_Q_TQOMR, MTL_Q_TQOMR_TSF, set_val);
}

static void fxgmac_config_osp_mode(struct fxgmac_pdata *priv)
{
	fxgmac_dma_wr_bits(priv->channel_head, DMA_CH_TCR, DMA_CH_TCR_OSP,
			   priv->tx_osp_mode);
}

static void fxgmac_config_pblx8(struct fxgmac_pdata *priv)
{
	struct fxgmac_channel *channel = priv->channel_head;

	for (u32 i = 0; i < priv->channel_count; i++, channel++)
		fxgmac_dma_wr_bits(channel, DMA_CH_CR, DMA_CH_CR_PBLX8,
				   priv->pblx8);
}

static void fxgmac_config_tx_pbl_val(struct fxgmac_pdata *priv)
{
	fxgmac_dma_wr_bits(priv->channel_head, DMA_CH_TCR, DMA_CH_TCR_PBL,
			   priv->tx_pbl);
}

static void fxgmac_config_rx_pbl_val(struct fxgmac_pdata *priv)
{
	struct fxgmac_channel *channel = priv->channel_head;

	for (u32 i = 0; i < priv->channel_count; i++, channel++)
		fxgmac_dma_wr_bits(channel, DMA_CH_RCR, DMA_CH_RCR_PBL,
				   priv->rx_pbl);
}

static void fxgmac_config_mmc(struct fxgmac_pdata *priv)
{
	/* Set counters to reset on read, Reset the counters */
	fxgmac_io_wr_bits(priv, MMC_CR, MMC_CR_ROR, 1);
	fxgmac_io_wr_bits(priv, MMC_CR, MMC_CR_CR, 1);

	fxgmac_io_wr(priv, MMC_IPC_RXINT_MASK, 0xffffffff);
}

static void fxgmac_enable_dma_interrupts(struct fxgmac_pdata *priv)
{
	struct fxgmac_channel *channel = priv->channel_head;
	u32 ch_sr;

	for (u32 i = 0; i < priv->channel_count; i++, channel++) {
		/* Clear all the interrupts which are set */
		ch_sr = fxgmac_dma_io_rd(channel, DMA_CH_SR);
		fxgmac_dma_io_wr(channel, DMA_CH_SR, ch_sr);

		ch_sr = 0;
		/* Enable Normal Interrupt Summary Enable and Fatal Bus Error
		 * Enable interrupts.
		 */
		ch_sr |= (DMA_CH_IER_NIE | DMA_CH_IER_FBEE);

		/* only one tx, enable Transmit Interrupt Enable interrupts */
		if (i == 0 && channel->tx_ring)
			ch_sr |= DMA_CH_IER_TIE;

		/* Enable Receive Buffer Unavailable Enable and Receive
		 * Interrupt Enable interrupts.
		 */
		if (channel->rx_ring)
			ch_sr |= (DMA_CH_IER_RBUE | DMA_CH_IER_RIE);

		fxgmac_dma_io_wr(channel, DMA_CH_IER, ch_sr);
	}
}

static void fxgmac_enable_mtl_interrupts(struct fxgmac_pdata *priv)
{
	unsigned int mtl_q_isr;

	for (u32 i = 0; i < priv->hw_feat.rx_q_cnt; i++) {
		/* Clear all the interrupts which are set */
		mtl_q_isr = fxgmac_mtl_io_rd(priv, i, MTL_Q_IR);
		fxgmac_mtl_io_wr(priv, i, MTL_Q_IR, mtl_q_isr);

		/* No MTL interrupts to be enabled */
		fxgmac_mtl_io_wr(priv, i, MTL_Q_IR, 0);
	}
}

static void fxgmac_enable_mac_interrupts(struct fxgmac_pdata *priv)
{
	/* Disable Timestamp interrupt */
	fxgmac_io_wr_bits(priv, MAC_IER, MAC_IER_TSIE, 0);

	fxgmac_io_wr_bits(priv, MMC_RIER, MMC_RIER_ALL_INTERRUPTS, 0);
	fxgmac_io_wr_bits(priv, MMC_TIER, MMC_TIER_ALL_INTERRUPTS, 0);
}

static int fxgmac_flush_tx_queues(struct fxgmac_pdata *priv)
{
	u32 val, count = 2000;

	fxgmac_mtl_wr_bits(priv, 0, MTL_Q_TQOMR, MTL_Q_TQOMR_FTQ, 1);
	do {
		fsleep(20);
		val = fxgmac_mtl_io_rd(priv, 0, MTL_Q_TQOMR);
		val = field_get(MTL_Q_TQOMR_FTQ, val);

	} while (--count && val);

	if (val)
		return -EBUSY;

	return 0;
}

static void fxgmac_config_dma_bus(struct fxgmac_pdata *priv)
{
	u32 val = fxgmac_io_rd(priv, DMA_SBMR);

	val &= ~(DMA_SBMR_EAME | DMA_SBMR_RD_OSR_LMT |
		 DMA_SBMR_WR_OSR_LMT | DMA_SBMR_FB);

	/* Set enhanced addressing mode */
	val |= DMA_SBMR_EAME;

	/* Out standing read/write requests */
	val |= field_prep(DMA_SBMR_RD_OSR_LMT, 0x7);
	val |= field_prep(DMA_SBMR_WR_OSR_LMT, 0x7);

	/* Set the System Bus mode */
	val |= (DMA_SBMR_BLEN_4 | DMA_SBMR_BLEN_8 |
		DMA_SBMR_BLEN_16 | DMA_SBMR_BLEN_32);

	fxgmac_io_wr(priv, DMA_SBMR, val);
}

static void fxgmac_desc_rx_channel_init(struct fxgmac_channel *channel)
{
	struct fxgmac_ring *ring = channel->rx_ring;
	unsigned int start_index = ring->cur;
	struct fxgmac_desc_data *desc_data;

	/* Initialize all descriptors */
	for (u32 i = 0; i < ring->dma_desc_count; i++) {
		desc_data = FXGMAC_GET_DESC_DATA(ring, i);
		fxgmac_desc_rx_reset(desc_data); /* Initialize Rx descriptor */
	}

	/* Update the total number of Rx descriptors */
	fxgmac_dma_io_wr(channel, DMA_CH_RDRLR, ring->dma_desc_count - 1);

	/* Update the starting address of descriptor ring */
	desc_data = FXGMAC_GET_DESC_DATA(ring, start_index);

	fxgmac_dma_io_wr(channel, DMA_CH_RDLR_HI,
			 upper_32_bits(desc_data->dma_desc_addr));
	fxgmac_dma_io_wr(channel, DMA_CH_RDLR_LO,
			 lower_32_bits(desc_data->dma_desc_addr));

	/* Update the Rx Descriptor Tail Pointer */
	desc_data = FXGMAC_GET_DESC_DATA(ring, start_index +
					 ring->dma_desc_count - 1);
	fxgmac_dma_io_wr(channel, DMA_CH_RDTR_LO,
			 lower_32_bits(desc_data->dma_desc_addr));
}

static void fxgmac_desc_rx_init(struct fxgmac_pdata *priv)
{
	struct fxgmac_channel *channel = priv->channel_head;
	struct fxgmac_desc_data *desc_data;
	struct fxgmac_dma_desc *dma_desc;
	dma_addr_t dma_desc_addr;
	struct fxgmac_ring *ring;

	for (u32 i = 0; i < priv->channel_count; i++, channel++) {
		ring = channel->rx_ring;
		dma_desc = ring->dma_desc_head;
		dma_desc_addr = ring->dma_desc_head_addr;

		for (u32 j = 0; j < ring->dma_desc_count; j++) {
			desc_data = FXGMAC_GET_DESC_DATA(ring, j);
			desc_data->dma_desc = dma_desc;
			desc_data->dma_desc_addr = dma_desc_addr;
			if (fxgmac_rx_buffe_map(priv, ring, desc_data))
				break;

			dma_desc++;
			dma_desc_addr += sizeof(struct fxgmac_dma_desc);
		}

		ring->cur = 0;
		ring->dirty = 0;

		fxgmac_desc_rx_channel_init(channel);
	}
}

static void fxgmac_desc_tx_channel_init(struct fxgmac_channel *channel)
{
	struct fxgmac_ring *ring = channel->tx_ring;
	struct fxgmac_desc_data *desc_data;
	int start_index = ring->cur;

	/* Initialize all descriptors */
	for (u32 i = 0; i < ring->dma_desc_count; i++) {
		desc_data = FXGMAC_GET_DESC_DATA(ring, i);
		fxgmac_desc_tx_reset(desc_data); /* Initialize Tx descriptor */
	}

	/* Update the total number of Tx descriptors */
	fxgmac_dma_io_wr(channel, DMA_CH_TDRLR,
			 channel->priv->tx_desc_count - 1);

	/* Update the starting address of descriptor ring */
	desc_data = FXGMAC_GET_DESC_DATA(ring, start_index);

	fxgmac_dma_io_wr(channel, DMA_CH_TDLR_HI,
			 upper_32_bits(desc_data->dma_desc_addr));
	fxgmac_dma_io_wr(channel, DMA_CH_TDLR_LO,
			 lower_32_bits(desc_data->dma_desc_addr));
}

static void fxgmac_desc_tx_init(struct fxgmac_pdata *priv)
{
	struct fxgmac_channel *channel = priv->channel_head;
	struct fxgmac_ring *ring = channel->tx_ring;
	struct fxgmac_desc_data *desc_data;
	struct fxgmac_dma_desc *dma_desc;
	dma_addr_t dma_desc_addr;

	dma_desc = ring->dma_desc_head;
	dma_desc_addr = ring->dma_desc_head_addr;

	for (u32 j = 0; j < ring->dma_desc_count; j++) {
		desc_data = FXGMAC_GET_DESC_DATA(ring, j);
		desc_data->dma_desc = dma_desc;
		desc_data->dma_desc_addr = dma_desc_addr;

		dma_desc++;
		dma_desc_addr += sizeof(struct fxgmac_dma_desc);
	}

	ring->cur = 0;
	ring->dirty = 0;
	memset(&ring->tx, 0, sizeof(ring->tx));
	fxgmac_desc_tx_channel_init(priv->channel_head);
}

static int fxgmac_hw_init(struct fxgmac_pdata *priv)
{
	int ret;

	ret = fxgmac_flush_tx_queues(priv); /* Flush Tx queues */
	if (ret < 0) {
		dev_err(priv->dev, "%s, flush tx queue failed:%d\n",
			__func__, ret);
		return ret;
	}

	/* Initialize DMA related features */
	fxgmac_config_dma_bus(priv);
	fxgmac_config_osp_mode(priv);
	fxgmac_config_pblx8(priv);
	fxgmac_config_tx_pbl_val(priv);
	fxgmac_config_rx_pbl_val(priv);
	fxgmac_config_rx_coalesce(priv);
	fxgmac_config_rx_buffer_size(priv);
	fxgmac_config_tso_mode(priv);
	fxgmac_config_sph_mode(priv);
	fxgmac_desc_tx_init(priv);
	fxgmac_desc_rx_init(priv);
	fxgmac_enable_dma_interrupts(priv);

	/* Initialize MTL related features */
	fxgmac_config_mtl_mode(priv);
	fxgmac_config_queue_mapping(priv);
	fxgmac_config_tsf_mode(priv, priv->tx_sf_mode);
	fxgmac_config_rsf_mode(priv, priv->rx_sf_mode);
	fxgmac_config_tx_threshold(priv, priv->tx_threshold);
	fxgmac_config_rx_threshold(priv, priv->rx_threshold);
	fxgmac_config_tx_fifo_size(priv);
	fxgmac_config_rx_fifo_size(priv);
	fxgmac_config_flow_control_threshold(priv);
	fxgmac_config_rx_fep_disable(priv);
	fxgmac_config_rx_fup_enable(priv);
	fxgmac_enable_mtl_interrupts(priv);

	/* Initialize MAC related features */
	fxgmac_config_mac_address(priv);
	fxgmac_config_crc_check_en(priv);
	fxgmac_config_rx_mode(priv);
	fxgmac_config_tx_flow_control(priv);
	fxgmac_config_rx_flow_control(priv);
	fxgmac_config_mac_speed(priv);
	fxgmac_config_checksum_offload(priv);
	fxgmac_config_mmc(priv);
	fxgmac_enable_mac_interrupts(priv);

	return 0;
}

static void fxgmac_dismiss_all_int(struct fxgmac_pdata *priv)
{
	struct fxgmac_channel *channel = priv->channel_head;
	u32 i;

	/* Clear all the interrupts which are set */
	for (i = 0; i < priv->channel_count; i++, channel++)
		fxgmac_dma_io_wr(channel, DMA_CH_SR,
				 fxgmac_dma_io_rd(channel, DMA_CH_SR));

	for (i = 0; i < priv->hw_feat.rx_q_cnt; i++)
		fxgmac_mtl_io_wr(priv, i, MTL_Q_IR,
				 fxgmac_mtl_io_rd(priv, i, MTL_Q_IR));

	fxgmac_io_rd(priv, MAC_ISR);      /* Clear all MAC interrupts */
	fxgmac_io_rd(priv, MAC_TX_RX_STA);/* Clear tx/rx error interrupts */
	fxgmac_io_rd(priv, MAC_PMT_STA);
	fxgmac_io_rd(priv, MAC_LPI_STA);

	fxgmac_io_wr(priv, MAC_DBG_STA, fxgmac_io_rd(priv, MAC_DBG_STA));
}

static void fxgmac_set_interrupt_moderation(struct fxgmac_pdata *priv)
{
	fxgmac_io_wr_bits(priv, INT_MOD, INT_MOD_TX, priv->tx_usecs);
	fxgmac_io_wr_bits(priv, INT_MOD, INT_MOD_RX, priv->rx_usecs);
}

static void fxgmac_enable_mgm_irq(struct fxgmac_pdata *priv)
{
	fxgmac_io_wr_bits(priv, MGMT_INT_CTRL0, MGMT_INT_CTRL0_INT_STATUS, 0);
	fxgmac_io_wr_bits(priv, MGMT_INT_CTRL0, MGMT_INT_CTRL0_INT_MASK,
			  MGMT_INT_CTRL0_INT_MASK_MISC);
}

/**
 * fxgmac_set_oob_wol - disable or enable oob wol crtl function
 * @priv: driver private struct
 * @en: 1 or 0
 *
 * Description:  After enable OOB_WOL from efuse, mac will loopcheck phy status,
 *   and lead to panic sometimes. So we should disable it from powerup,
 *   enable it from power down.
 */
static void fxgmac_set_oob_wol(struct fxgmac_pdata *priv, unsigned int en)
{
	/* en = 1 is disable */
	fxgmac_io_wr_bits(priv, OOB_WOL_CTRL, OOB_WOL_CTRL_DIS, !en);
}

static void fxgmac_config_powerup(struct fxgmac_pdata *priv)
{
	fxgmac_set_oob_wol(priv, 0);
	/* GAMC power up */
	fxgmac_io_wr_bits(priv, MAC_PMT_STA, MAC_PMT_STA_PWRDWN, 0);
}

static void fxgmac_pre_powerdown(struct fxgmac_pdata *priv)
{
	fxgmac_set_oob_wol(priv, 1);
	fsleep(2000);
}

static void fxgmac_restore_nonstick_reg(struct fxgmac_pdata *priv)
{
	for (u32 i = GLOBAL_CTRL0; i < MSI_PBA; i += 4)
		fxgmac_io_wr(priv, i,
			     priv->reg_nonstick[(i - GLOBAL_CTRL0) >> 2]);
}

static void fxgmac_phy_release(struct fxgmac_pdata *priv)
{
	fxgmac_io_wr_bits(priv, EPHY_CTRL, EPHY_CTRL_RESET, 1);
	fsleep(100);
}

static void fxgmac_hw_exit(struct fxgmac_pdata *priv)
{
	/* Reset CHIP, it will reset trigger circuit and reload efuse patch */
	fxgmac_io_wr_bits(priv, SYS_RESET, SYS_RESET_RESET, 1);
	fsleep(9000);

	fxgmac_phy_release(priv);

	/* Reset will clear nonstick registers. */
	fxgmac_restore_nonstick_reg(priv);
}

static void fxgmac_pcie_init(struct fxgmac_pdata *priv)
{
	/* snoopy + non-snoopy */
	fxgmac_io_wr_bits(priv, LTR_IDLE_ENTER, LTR_IDLE_ENTER_REQUIRE, 1);
	fxgmac_io_wr_bits(priv, LTR_IDLE_ENTER, LTR_IDLE_ENTER_SCALE,
			  LTR_IDLE_ENTER_SCALE_1024_NS);
	fxgmac_io_wr_bits(priv, LTR_IDLE_ENTER, LTR_IDLE_ENTER_ENTER,
			  LTR_IDLE_ENTER_900_US);

	/* snoopy + non-snoopy */
	fxgmac_io_wr_bits(priv, LTR_IDLE_EXIT, LTR_IDLE_EXIT_REQUIRE, 1);
	fxgmac_io_wr_bits(priv, LTR_IDLE_EXIT, LTR_IDLE_EXIT_SCALE, 2);
	fxgmac_io_wr_bits(priv, LTR_IDLE_EXIT, LTR_IDLE_EXIT_EXIT,
			  LTR_IDLE_EXIT_171_US);

	fxgmac_io_wr_bits(priv, PCIE_SERDES_PLL, PCIE_SERDES_PLL_AUTOOFF, 1);
}

static void fxgmac_phy_reset(struct fxgmac_pdata *priv)
{
	fxgmac_io_wr_bits(priv, EPHY_CTRL, EPHY_CTRL_RESET, 0);
	fsleep(1500);
}

static int fxgmac_start(struct fxgmac_pdata *priv)
{
	int ret;

	if (priv->dev_state != FXGMAC_DEV_OPEN &&
	    priv->dev_state != FXGMAC_DEV_STOP &&
	    priv->dev_state != FXGMAC_DEV_RESUME) {
		return 0;
	}

	if (priv->dev_state != FXGMAC_DEV_STOP) {
		fxgmac_phy_reset(priv);
		fxgmac_phy_release(priv);
	}

	if (priv->dev_state == FXGMAC_DEV_OPEN) {
		ret = fxgmac_phy_connect(priv);
		if (ret < 0)
			return ret;
	}

	fxgmac_pcie_init(priv);
	if (test_bit(FXGMAC_POWER_STATE_DOWN, &priv->power_state)) {
		dev_err(priv->dev, "fxgmac powerstate is %lu when config power up.\n",
			priv->power_state);
	}

	fxgmac_config_powerup(priv);
	fxgmac_dismiss_all_int(priv);
	ret = fxgmac_hw_init(priv);
	if (ret < 0) {
		dev_err(priv->dev, "fxgmac hw init failed.\n");
		return ret;
	}

	fxgmac_napi_enable(priv);
	ret = fxgmac_request_irqs(priv);
	if (ret < 0)
		return ret;

	/* Config interrupt to level signal */
	fxgmac_io_wr_bits(priv, DMA_MR, DMA_MR_INTM, 2);
	fxgmac_io_wr_bits(priv, DMA_MR, DMA_MR_QUREAD, 1);

	fxgmac_enable_mgm_irq(priv);
	fxgmac_set_interrupt_moderation(priv);

	if (priv->per_channel_irq)
		fxgmac_enable_msix_irqs(priv);

	fxgmac_enable_dma_interrupts(priv);
	priv->dev_state = FXGMAC_DEV_START;
	phy_start(priv->phydev);

	return 0;
}

static void fxgmac_disable_msix_irqs(struct fxgmac_pdata *priv)
{
	for (u32 intid = 0; intid < MSIX_TBL_MAX_NUM; intid++)
		fxgmac_disable_msix_one_irq(priv, intid);
}

static void fxgmac_stop(struct fxgmac_pdata *priv)
{
	struct net_device *ndev = priv->ndev;
	struct netdev_queue *txq;

	if (priv->dev_state != FXGMAC_DEV_START)
		return;

	priv->dev_state = FXGMAC_DEV_STOP;

	if (priv->per_channel_irq)
		fxgmac_disable_msix_irqs(priv);
	else
		fxgmac_disable_mgm_irq(priv);

	netif_carrier_off(ndev);
	netif_tx_stop_all_queues(ndev);
	fxgmac_disable_tx(priv);
	fxgmac_disable_rx(priv);
	fxgmac_free_irqs(priv);
	fxgmac_napi_disable(priv);
	phy_stop(priv->phydev);

	txq = netdev_get_tx_queue(ndev, priv->channel_head->queue_index);
	netdev_tx_reset_queue(txq);
}

static void fxgmac_restart(struct fxgmac_pdata *priv)
{
	int ret;

	/* If not running, "restart" will happen on open */
	if (!netif_running(priv->ndev) && priv->dev_state != FXGMAC_DEV_START)
		return;

	fxgmac_stop(priv);
	fxgmac_free_tx_data(priv);
	fxgmac_free_rx_data(priv);
	ret = fxgmac_start(priv);
	if (ret < 0)
		dev_err(priv->dev, "fxgmac start failed:%d.\n", ret);
}

static void fxgmac_restart_work(struct work_struct *work)
{
	rtnl_lock();
	fxgmac_restart(container_of(work, struct fxgmac_pdata, restart_work));
	rtnl_unlock();
}

static int fxgmac_net_powerup(struct fxgmac_pdata *priv)
{
	int ret;

	priv->power_state = 0;/* clear all bits as normal now */
	ret = fxgmac_start(priv);
	if (ret < 0) {
		dev_err(priv->dev, "fxgmac start failed:%d.\n", ret);
		return ret;
	}

	return 0;
}

static void fxgmac_config_powerdown(struct fxgmac_pdata *priv)
{
	fxgmac_io_wr_bits(priv, MAC_CR, MAC_CR_RE, 1); /* Enable MAC Rx */
	fxgmac_io_wr_bits(priv, MAC_CR, MAC_CR_TE, 1); /* Enable MAC TX */

	/* Set GAMC power down */
	fxgmac_io_wr_bits(priv, MAC_PMT_STA, MAC_PMT_STA_PWRDWN, 1);
}

static int fxgmac_net_powerdown(struct fxgmac_pdata *priv)
{
	struct net_device *ndev = priv->ndev;

	/* Signal that we are down to the interrupt handler */
	if (__test_and_set_bit(FXGMAC_POWER_STATE_DOWN, &priv->power_state))
		return 0; /* do nothing if already down */

	__clear_bit(FXGMAC_POWER_STATE_UP, &priv->power_state);
	netif_tx_stop_all_queues(ndev); /* Shut off incoming Tx traffic */

	/* Call carrier off first to avoid false dev_watchdog timeouts */
	netif_carrier_off(ndev);
	netif_tx_disable(ndev);
	fxgmac_disable_rx(priv);

	/* Synchronize_rcu() needed for pending XDP buffers to drain */
	synchronize_rcu();

	fxgmac_stop(priv);
	fxgmac_pre_powerdown(priv);

	if (!test_bit(FXGMAC_POWER_STATE_DOWN, &priv->power_state))
		dev_err(priv->dev, "fxgmac powerstate is %lu when config powe down.\n",
			priv->power_state);

	/* Set mac to lowpower mode */
	fxgmac_config_powerdown(priv);
	fxgmac_free_tx_data(priv);
	fxgmac_free_rx_data(priv);

	return 0;
}

static int fxgmac_calc_rx_buf_size(struct fxgmac_pdata *priv, unsigned int mtu)
{
	u32 rx_buf_size, max_mtu = FXGMAC_JUMBO_PACKET_MTU - ETH_HLEN;

	if (mtu > max_mtu) {
		dev_err(priv->dev, "MTU exceeds maximum supported value\n");
		return -EINVAL;
	}

	rx_buf_size = mtu + ETH_HLEN + ETH_FCS_LEN + VLAN_HLEN;
	rx_buf_size =
		clamp_val(rx_buf_size, FXGMAC_RX_MIN_BUF_SIZE, PAGE_SIZE * 4);

	rx_buf_size = (rx_buf_size + FXGMAC_RX_BUF_ALIGN - 1) &
		      ~(FXGMAC_RX_BUF_ALIGN - 1);

	return rx_buf_size;
}

static int fxgmac_open(struct net_device *ndev)
{
	struct fxgmac_pdata *priv = netdev_priv(ndev);
	int ret;

	priv->dev_state = FXGMAC_DEV_OPEN;

	/* Calculate the Rx buffer size before allocating rings */
	ret = fxgmac_calc_rx_buf_size(priv, ndev->mtu);
	if (ret < 0)
		goto unlock;

	priv->rx_buf_size = ret;
	ret = fxgmac_channels_rings_alloc(priv);
	if (ret < 0)
		goto unlock;

	INIT_WORK(&priv->restart_work, fxgmac_restart_work);
	ret = fxgmac_start(priv);
	if (ret < 0)
		goto err_channels_and_rings;

	return 0;

err_channels_and_rings:
	fxgmac_channels_rings_free(priv);
	dev_err(priv->dev, "%s, channel alloc failed\n", __func__);
unlock:
	rtnl_unlock();
	return ret;
}

static int fxgmac_close(struct net_device *ndev)
{
	struct fxgmac_pdata *priv = netdev_priv(ndev);

	fxgmac_stop(priv); /* Stop the device */
	priv->dev_state = FXGMAC_DEV_CLOSE;
	fxgmac_channels_rings_free(priv); /* Free the channels and rings */
	fxgmac_phy_reset(priv);
	phy_disconnect(priv->phydev);

	return 0;
}

static void fxgmac_dump_state(struct fxgmac_pdata *priv)
{
	struct fxgmac_channel *channel = priv->channel_head;
	struct fxgmac_ring *ring = &channel->tx_ring[0];
	struct device *pdev = priv->dev;

	dev_err(pdev, "Tx descriptor info:\n");
	dev_err(pdev, " cur = 0x%x\n", ring->cur);
	dev_err(pdev, " dirty = 0x%x\n", ring->dirty);
	dev_err(pdev, " dma_desc_head = %pad\n", &ring->dma_desc_head);
	dev_err(pdev, " desc_data_head = %pad\n", &ring->desc_data_head);

	for (u32 i = 0; i < priv->channel_count; i++, channel++) {
		ring = &channel->rx_ring[0];
		dev_err(pdev, "Rx[%d] descriptor info:\n", i);
		dev_err(pdev, " cur = 0x%x\n", ring->cur);
		dev_err(pdev, " dirty = 0x%x\n", ring->dirty);
		dev_err(pdev, " dma_desc_head = %pad\n", &ring->dma_desc_head);
		dev_err(pdev, " desc_data_head = %pad\n",
			&ring->desc_data_head);
	}

	dev_err(pdev, "Device Registers:\n");
	dev_err(pdev, "MAC_ISR = %08x\n", fxgmac_io_rd(priv, MAC_ISR));
	dev_err(pdev, "MAC_IER = %08x\n", fxgmac_io_rd(priv, MAC_IER));
	dev_err(pdev, "MMC_RISR = %08x\n", fxgmac_io_rd(priv, MMC_RISR));
	dev_err(pdev, "MMC_RIER = %08x\n", fxgmac_io_rd(priv, MMC_RIER));
	dev_err(pdev, "MMC_TISR = %08x\n", fxgmac_io_rd(priv, MMC_TISR));
	dev_err(pdev, "MMC_TIER = %08x\n", fxgmac_io_rd(priv, MMC_TIER));

	dev_err(pdev, "EPHY_CTRL = %04x\n", fxgmac_io_rd(priv, EPHY_CTRL));
	dev_err(pdev,  "MGMT_INT_CTRL0 = %04x\n",
		fxgmac_io_rd(priv, MGMT_INT_CTRL0));
	dev_err(pdev, "MSIX_TBL_MASK = %04x\n",
		fxgmac_io_rd(priv, MSIX_TBL_MASK));

	dev_err(pdev, "Dump nonstick regs:\n");
	for (u32 i = GLOBAL_CTRL0; i < MSI_PBA; i += 4)
		dev_err(pdev, "[%d] = %04x\n", i / 4, fxgmac_io_rd(priv, i));
}

static void fxgmac_tx_timeout(struct net_device *ndev, unsigned int unused)
{
	struct fxgmac_pdata *priv = netdev_priv(ndev);

	fxgmac_dump_state(priv);
	schedule_work(&priv->restart_work);
}

#define EFUSE_FISRT_UPDATE_ADDR				255
#define EFUSE_SECOND_UPDATE_ADDR			209
#define EFUSE_MAX_ENTRY					39
#define EFUSE_PATCH_ADDR_START				0
#define EFUSE_PATCH_DATA_START				2
#define EFUSE_PATCH_SIZE				6
#define EFUSE_REGION_A_B_LENGTH				18

static bool fxgmac_efuse_read_data(struct fxgmac_pdata *priv, u32 offset,
				   u8 *value)
{
	u32 val = 0, wait = 1000;
	bool ret = false;

	val |= field_prep(EFUSE_OP_ADDR, offset);
	val |= EFUSE_OP_START;
	val |= field_prep(EFUSE_OP_MODE, EFUSE_OP_MODE_ROW_READ);
	fxgmac_io_wr(priv, EFUSE_OP_CTRL_0, val);

	while (wait--) {
		fsleep(20);
		val = fxgmac_io_rd(priv, EFUSE_OP_CTRL_1);
		if (field_get(EFUSE_OP_DONE, val)) {
			ret = true;
			break;
		}
	}

	if (!ret) {
		dev_err(priv->dev, "Reading efuse Byte:%d failed\n", offset);
		return ret;
	}

	if (value)
		*value = field_get(EFUSE_OP_RD_DATA, val) & 0xff;

	return ret;
}

static bool fxgmac_efuse_read_index_patch(struct fxgmac_pdata *priv, u8 index,
					  u32 *offset, u32 *value)
{
	u8 tmp[EFUSE_PATCH_SIZE - EFUSE_PATCH_DATA_START];
	u32 addr, i;
	bool ret;

	if (index >= EFUSE_MAX_ENTRY) {
		dev_err(priv->dev, "Reading efuse out of range, index %d\n",
			index);
		return false;
	}

	for (i = EFUSE_PATCH_ADDR_START; i < EFUSE_PATCH_DATA_START; i++) {
		addr = EFUSE_REGION_A_B_LENGTH + index * EFUSE_PATCH_SIZE + i;
		ret = fxgmac_efuse_read_data(priv, addr,
					     tmp + i - EFUSE_PATCH_ADDR_START);
		if (!ret) {
			dev_err(priv->dev, "Reading efuse Byte:%d failed\n",
				addr);
			return ret;
		}
	}
	/* tmp[0] is low 8bit date, tmp[1] is high 8bit date */
	if (offset)
		*offset = tmp[0] | (tmp[1] << 8);

	for (i = EFUSE_PATCH_DATA_START; i < EFUSE_PATCH_SIZE; i++) {
		addr = EFUSE_REGION_A_B_LENGTH + index * EFUSE_PATCH_SIZE + i;
		ret = fxgmac_efuse_read_data(priv, addr,
					     tmp + i - EFUSE_PATCH_DATA_START);
		if (!ret) {
			dev_err(priv->dev, "Reading efuse Byte:%d failed\n",
				addr);
			return ret;
		}
	}
	/* tmp[0] is low 8bit date, tmp[1] is low 8bit date
	 * ...  tmp[3] is highest 8bit date
	 */
	if (value)
		*value = tmp[0] | (tmp[1] << 8) | (tmp[2] << 16) |
			 (tmp[3] << 24);

	return ret;
}

static bool fxgmac_efuse_read_mac_subsys(struct fxgmac_pdata *priv,
					 u8 *mac_addr, u32 *subsys, u32 *revid)
{
	u32 machr = 0, maclr = 0, offset = 0, val = 0;

	for (u8 index = 0; index < EFUSE_MAX_ENTRY; index++) {
		if (!fxgmac_efuse_read_index_patch(priv, index, &offset, &val))
			return false;

		if (offset == 0x00)
			break; /* Reach the blank. */
		if (offset == MACA0LR_FROM_EFUSE)
			maclr = val;
		if (offset == MACA0HR_FROM_EFUSE)
			machr = val;
		if (offset == PCI_REVISION_ID && revid)
			*revid = val;
		if (offset == PCI_SUBSYSTEM_VENDOR_ID && subsys)
			*subsys = val;
	}

	if (mac_addr) {
		mac_addr[5] = (u8)(maclr & 0xFF);
		mac_addr[4] = (u8)((maclr >> 8) & 0xFF);
		mac_addr[3] = (u8)((maclr >> 16) & 0xFF);
		mac_addr[2] = (u8)((maclr >> 24) & 0xFF);
		mac_addr[1] = (u8)(machr & 0xFF);
		mac_addr[0] = (u8)((machr >> 8) & 0xFF);
	}

	return true;
}

static int fxgmac_read_mac_addr(struct fxgmac_pdata *priv)
{
	u8 default_addr[ETH_ALEN] = { 0, 0x55, 0x7b, 0xb5, 0x7d, 0xf7 };
	struct net_device *ndev = priv->ndev;
	int ret;

	/* If efuse have mac addr, use it. if not, use static mac address. */
	ret = fxgmac_efuse_read_mac_subsys(priv, priv->mac_addr, NULL, NULL);
	if (!ret)
		return -1;

	if (is_zero_ether_addr(priv->mac_addr))
		/* Use a static mac address for test */
		memcpy(priv->mac_addr, default_addr, ndev->addr_len);

	return 0;
}

static void fxgmac_default_config(struct fxgmac_pdata *priv)
{
	priv->sysclk_rate = 125000000; /* System clock is 125 MHz */
	priv->tx_threshold = MTL_Q_TQOMR_TTC_THRESHOLD_128;
	priv->rx_threshold = MTL_Q_RQOMR_RTC_THRESHOLD_128;
	priv->tx_osp_mode =  1;	/* Enable DMA OSP */
	priv->tx_sf_mode = 1;	/* Enable MTL TSF */
	priv->rx_sf_mode = 1;	/* Enable MTL RSF */
	priv->pblx8 = 1;	/* Enable DMA PBL X8 */
	priv->tx_pause = 1;	/* Enable tx pause */
	priv->rx_pause = 1;	/* Enable rx pause */
	priv->tx_pbl = DMA_CH_PBL_16;
	priv->rx_pbl = DMA_CH_PBL_4;

	fxgmac_default_speed_duplex_config(priv);
}

static void fxgmac_get_all_hw_features(struct fxgmac_pdata *priv)
{
	struct fxgmac_hw_features *hw_feat = &priv->hw_feat;
	unsigned int mac_hfr0, mac_hfr1, mac_hfr2, mac_hfr3;

	mac_hfr0 = fxgmac_io_rd(priv, MAC_HWF0R);
	mac_hfr1 = fxgmac_io_rd(priv, MAC_HWF1R);
	mac_hfr2 = fxgmac_io_rd(priv, MAC_HWF2R);
	mac_hfr3 = fxgmac_io_rd(priv, MAC_HWF3R);
	memset(hw_feat, 0, sizeof(*hw_feat));
	hw_feat->version = fxgmac_io_rd(priv, MAC_VR);

	/* Hardware feature register 0 */
	hw_feat->phyifsel = field_get(MAC_HWF0R_ACTPHYIFSEL, mac_hfr0);
	hw_feat->vlhash = field_get(MAC_HWF0R_VLHASH, mac_hfr0);
	hw_feat->sma = field_get(MAC_HWF0R_SMASEL, mac_hfr0);
	hw_feat->rwk = field_get(MAC_HWF0R_RWKSEL, mac_hfr0);
	hw_feat->mgk = field_get(MAC_HWF0R_MGKSEL, mac_hfr0);
	hw_feat->mmc = field_get(MAC_HWF0R_MMCSEL, mac_hfr0);
	hw_feat->aoe = field_get(MAC_HWF0R_ARPOFFSEL, mac_hfr0);
	hw_feat->ts = field_get(MAC_HWF0R_TSSEL, mac_hfr0);
	hw_feat->eee = field_get(MAC_HWF0R_EEESEL, mac_hfr0);
	hw_feat->tx_coe = field_get(MAC_HWF0R_TXCOESEL, mac_hfr0);
	hw_feat->rx_coe = field_get(MAC_HWF0R_RXCOESEL, mac_hfr0);
	hw_feat->addn_mac = field_get(MAC_HWF0R_ADDMACADRSEL, mac_hfr0);
	hw_feat->ts_src = field_get(MAC_HWF0R_TSSTSSEL, mac_hfr0);
	hw_feat->sa_vlan_ins = field_get(MAC_HWF0R_SAVLANINS, mac_hfr0);

	/* Hardware feature register 1 */
	hw_feat->rx_fifo_size = field_get(MAC_HWF1R_RXFIFOSIZE, mac_hfr1);
	hw_feat->tx_fifo_size = field_get(MAC_HWF1R_TXFIFOSIZE, mac_hfr1);
	hw_feat->adv_ts_hi = field_get(MAC_HWF1R_ADVTHWORD, mac_hfr1);
	hw_feat->dma_width = field_get(MAC_HWF1R_ADDR64, mac_hfr1);
	hw_feat->dcb = field_get(MAC_HWF1R_DCBEN, mac_hfr1);
	hw_feat->sph = field_get(MAC_HWF1R_SPHEN, mac_hfr1);
	hw_feat->tso = field_get(MAC_HWF1R_TSOEN, mac_hfr1);
	hw_feat->dma_debug = field_get(MAC_HWF1R_DBGMEMA, mac_hfr1);
	hw_feat->avsel = field_get(MAC_HWF1R_AVSEL, mac_hfr1);
	hw_feat->ravsel = field_get(MAC_HWF1R_RAVSEL, mac_hfr1);
	hw_feat->hash_table_size = field_get(MAC_HWF1R_HASHTBLSZ, mac_hfr1);
	hw_feat->l3l4_filter_num = field_get(MAC_HWF1R_L3L4FNUM, mac_hfr1);
	hw_feat->tx_q_cnt = field_get(MAC_HWF2R_TXQCNT, mac_hfr1);
	hw_feat->rx_ch_cnt = field_get(MAC_HWF2R_RXCHCNT, mac_hfr1);
	hw_feat->tx_ch_cnt = field_get(MAC_HWF2R_TXCHCNT, mac_hfr1);
	hw_feat->pps_out_num = field_get(MAC_HWF2R_PPSOUTNUM, mac_hfr1);
	hw_feat->aux_snap_num = field_get(MAC_HWF2R_AUXSNAPNUM, mac_hfr1);

	/* Translate the Hash Table size into actual number */
	switch (hw_feat->hash_table_size) {
	case 0:
		break;
	case 1:
		hw_feat->hash_table_size = 64;
		break;
	case 2:
		hw_feat->hash_table_size = 128;
		break;
	case 3:
		hw_feat->hash_table_size = 256;
		break;
	}

	/* Translate the address width setting into actual number */
	switch (hw_feat->dma_width) {
	case 0:
		hw_feat->dma_width = 32;
		break;
	case 1:
		hw_feat->dma_width = 40;
		break;
	case 2:
		hw_feat->dma_width = 48;
		break;
	default:
		hw_feat->dma_width = 32;
	}

	/* The Queue, Channel are zero based so increment them
	 * to get the actual number
	 */
	hw_feat->tx_q_cnt++;
	hw_feat->rx_ch_cnt++;
	hw_feat->tx_ch_cnt++;

	/* HW implement 1 rx fifo, 4 dma channel.  but from software
	 * we see 4 logical queues. hardcode to 4 queues.
	 */
	hw_feat->rx_q_cnt = 4;
	hw_feat->hwfr3 = mac_hfr3;
}

static unsigned int fxgmac_usec_to_riwt(struct fxgmac_pdata *priv,
					unsigned int usec)
{
	/* Convert the input usec value to the watchdog timer value. Each
	 * watchdog timer value is equivalent to 256 clock cycles.
	 * Calculate the required value as:
	 *  ( usec * ( system_clock_mhz / 10^6) / 256
	 */
	return (usec * (priv->sysclk_rate / 1000000)) / 256;
}

static void fxgmac_save_nonstick_reg(struct fxgmac_pdata *priv)
{
	for (u32 i = GLOBAL_CTRL0; i < MSI_PBA; i += 4) {
		priv->reg_nonstick[(i - GLOBAL_CTRL0) >> 2] =
			fxgmac_io_rd(priv, i);
	}
}

static int fxgmac_init(struct fxgmac_pdata *priv, bool save_private_reg)
{
	struct net_device *ndev = priv->ndev;
	int ret;

	fxgmac_default_config(priv);	/* Set default configuration data */
	ndev->irq = priv->dev_irq;
	ndev->base_addr = (unsigned long)priv->hw_addr;

	ret = fxgmac_read_mac_addr(priv);
	if (ret) {
		dev_err(priv->dev, "Read mac addr failed:%d\n", ret);
		return ret;
	}
	eth_hw_addr_set(ndev, priv->mac_addr);

	if (save_private_reg)
		fxgmac_save_nonstick_reg(priv);

	fxgmac_hw_exit(priv);	/* Reset here to get hw features correctly */
	fxgmac_get_all_hw_features(priv);

	/* Set the DMA mask */
	ret = dma_set_mask_and_coherent(priv->dev,
					DMA_BIT_MASK(priv->hw_feat.dma_width));
	if (ret) {
		ret = dma_set_mask_and_coherent(priv->dev, DMA_BIT_MASK(32));
		if (ret) {
			dev_err(priv->dev, "No usable DMA configuration, aborting\n");
			return ret;
		}
	}

	if (field_get(INT_FLAG_LEGACY, priv->int_flag)) {
		/* We should disable msi and msix here when we use legacy
		 * interrupt,for two reasons:
		 * 1. Exit will restore msi and msix config regisiter,
		 * that may enable them.
		 * 2. When the driver that uses the msix interrupt by default
		 * is compiled into the OS, uninstall the driver through rmmod,
		 * and then install the driver that uses the legacy interrupt,
		 * at which time the msix enable will be turned on again by
		 * default after waking up from S4 on some
		 * platform. such as UOS platform.
		 */
		pci_disable_msi(to_pci_dev(priv->dev));
		pci_disable_msix(to_pci_dev(priv->dev));
	}

	BUILD_BUG_ON_NOT_POWER_OF_2(FXGMAC_TX_DESC_CNT);
	priv->tx_desc_count = FXGMAC_TX_DESC_CNT;
	BUILD_BUG_ON_NOT_POWER_OF_2(FXGMAC_RX_DESC_CNT);
	priv->rx_desc_count = FXGMAC_RX_DESC_CNT;

	ret = netif_set_real_num_tx_queues(ndev, FXGMAC_TX_1_Q);
	if (ret) {
		dev_err(priv->dev, "Setting real tx queue count failed\n");
		return ret;
	}

	priv->rx_ring_count = min_t(unsigned int,
				    netif_get_num_default_rss_queues(),
				    priv->hw_feat.rx_ch_cnt);
	priv->rx_ring_count = min_t(unsigned int, priv->rx_ring_count,
				    priv->hw_feat.rx_q_cnt);
	priv->rx_q_count = priv->rx_ring_count;
	ret = netif_set_real_num_rx_queues(ndev, priv->rx_q_count);
	if (ret) {
		dev_err(priv->dev, "Setting real rx queue count failed\n");
		return ret;
	}

	priv->channel_count =
		max_t(unsigned int, FXGMAC_TX_1_RING, priv->rx_ring_count);

	ndev->min_mtu = ETH_MIN_MTU;
	ndev->max_mtu =
		FXGMAC_JUMBO_PACKET_MTU + (ETH_HLEN + VLAN_HLEN + ETH_FCS_LEN);

	ndev->netdev_ops = fxgmac_get_netdev_ops();/* Set device operations */
	ndev->ethtool_ops = fxgmac_get_ethtool_ops();/* Set device operations */

	/* Set device features */
	if (priv->hw_feat.tso) {
		ndev->hw_features = NETIF_F_TSO;
		ndev->hw_features |= NETIF_F_TSO6;
		ndev->hw_features |= NETIF_F_SG;
		ndev->hw_features |= NETIF_F_IP_CSUM;
		ndev->hw_features |= NETIF_F_IPV6_CSUM;
	} else if (priv->hw_feat.tx_coe) {
		ndev->hw_features = NETIF_F_IP_CSUM;
		ndev->hw_features |= NETIF_F_IPV6_CSUM;
	}

	if (priv->hw_feat.rx_coe) {
		ndev->hw_features |= NETIF_F_RXCSUM;
		ndev->hw_features |= NETIF_F_GRO;
	}

	ndev->hw_features |= NETIF_F_RXHASH;
	ndev->vlan_features |= ndev->hw_features;
	ndev->hw_features |= NETIF_F_HW_VLAN_CTAG_RX;

	if (priv->hw_feat.sa_vlan_ins)
		ndev->hw_features |= NETIF_F_HW_VLAN_CTAG_TX;

	ndev->features |= ndev->hw_features;

	ndev->priv_flags |= IFF_UNICAST_FLT;
	ndev->watchdog_timeo = msecs_to_jiffies(5000);

#define NIC_MAX_TCP_OFFLOAD_SIZE 7300
	netif_set_tso_max_size(ndev, NIC_MAX_TCP_OFFLOAD_SIZE);

/* Default coalescing parameters */
#define FXGMAC_INIT_DMA_TX_USECS INT_MOD_200_US
#define FXGMAC_INIT_DMA_TX_FRAMES 25
#define FXGMAC_INIT_DMA_RX_USECS INT_MOD_200_US
#define FXGMAC_INIT_DMA_RX_FRAMES 25

	/* Tx coalesce parameters initialization */
	priv->tx_usecs = FXGMAC_INIT_DMA_TX_USECS;
	priv->tx_frames = FXGMAC_INIT_DMA_TX_FRAMES;

	/* Rx coalesce parameters initialization */
	priv->rx_riwt = fxgmac_usec_to_riwt(priv, FXGMAC_INIT_DMA_RX_USECS);
	priv->rx_usecs = FXGMAC_INIT_DMA_RX_USECS;
	priv->rx_frames = FXGMAC_INIT_DMA_RX_FRAMES;

	return 0;
}

static void fxgmac_init_interrupt_scheme(struct fxgmac_pdata *priv)
{
	struct pci_dev *pdev = to_pci_dev(priv->dev);
	int req_vectors = FXGMAC_MAX_DMA_CHANNELS;

	/* Since we have FXGMAC_MAX_DMA_CHANNELS channels, we must ensure the
	 * number of cpu core is ok. otherwise, just roll back to legacy.
	 */
	if (num_online_cpus() < FXGMAC_MAX_DMA_CHANNELS - 1)
		goto enable_msi_interrupt;

	priv->msix_entries =
		kcalloc(req_vectors, sizeof(struct msix_entry), GFP_KERNEL);
	if (!priv->msix_entries)
		goto enable_msi_interrupt;

	for (u32 i = 0; i < req_vectors; i++)
		priv->msix_entries[i].entry = i;

	if (pci_enable_msix_exact(pdev, priv->msix_entries, req_vectors) < 0) {
		/* Roll back to msi */
		kfree(priv->msix_entries);
		priv->msix_entries = NULL;
		dev_err(priv->dev, "Enable MSIx failed, clear msix entries.\n");
		goto enable_msi_interrupt;
	}

	priv->int_flag &= ~INT_FLAG_INTERRUPT;
	priv->int_flag |= INT_FLAG_MSIX;
	priv->per_channel_irq = 1;
	return;

enable_msi_interrupt:
	priv->int_flag &= ~INT_FLAG_INTERRUPT;
	if (pci_enable_msi(pdev) < 0) {
		priv->int_flag |= INT_FLAG_LEGACY;
		dev_err(priv->dev, "rollback to LEGACY.\n");
	} else {
		priv->int_flag |= INT_FLAG_MSI;
		dev_err(priv->dev, "rollback to MSI.\n");
		priv->dev_irq = pdev->irq;
	}
}

static int fxgmac_drv_probe(struct device *dev, struct fxgmac_resources *res)
{
	struct fxgmac_pdata *priv;
	struct net_device *ndev;
	int ret;

	ndev = alloc_etherdev_mq(sizeof(struct fxgmac_pdata),
				 FXGMAC_MAX_DMA_RX_CHANNELS);
	if (!ndev)
		return -ENOMEM;

	SET_NETDEV_DEV(ndev, dev);
	priv = netdev_priv(ndev);

	priv->dev = dev;
	priv->ndev = ndev;
	priv->dev_irq = res->irq;
	priv->hw_addr = res->addr;
	priv->msg_enable = NETIF_MSG_DRV;
	priv->dev_state = FXGMAC_DEV_PROBE;

	/* Default to legacy interrupt */
	priv->int_flag &= ~INT_FLAG_INTERRUPT;
	priv->int_flag |= INT_FLAG_LEGACY;

	pci_set_drvdata(to_pci_dev(priv->dev), priv);

	if (IS_ENABLED(CONFIG_PCI_MSI))
		fxgmac_init_interrupt_scheme(priv);

	ret = fxgmac_init(priv, true);
	if (ret < 0) {
		dev_err(dev, "fxgmac init failed:%d\n", ret);
		goto err_free_netdev;
	}

	fxgmac_phy_reset(priv);
	fxgmac_phy_release(priv);
	ret = fxgmac_mdio_register(priv);
	if (ret < 0) {
		dev_err(dev, "Register fxgmac mdio failed:%d\n", ret);
		goto err_free_netdev;
	}

	netif_carrier_off(ndev);
	ret = register_netdev(ndev);
	if (ret) {
		dev_err(dev, "Register ndev failed:%d\n", ret);
		goto err_free_netdev;
	}

	return 0;

err_free_netdev:
	free_netdev(ndev);
	return ret;
}

static void fxgmac_dbg_pkt(struct fxgmac_pdata *priv, struct sk_buff *skb,
			   bool tx_rx)
{
	struct ethhdr *eth = (struct ethhdr *)skb->data;
	unsigned char buffer[128];

	dev_dbg(priv->dev, "\n************** SKB dump ****************\n");
	dev_dbg(priv->dev, "%s, packet of %d bytes\n", (tx_rx ? "TX" : "RX"),
		skb->len);
	dev_dbg(priv->dev, "Dst MAC addr: %pM\n", eth->h_dest);
	dev_dbg(priv->dev, "Src MAC addr: %pM\n", eth->h_source);
	dev_dbg(priv->dev, "Protocol: %#06x\n", ntohs(eth->h_proto));

	for (u32 i = 0; i < skb->len; i += 32) {
		unsigned int len = min(skb->len - i, 32U);

		hex_dump_to_buffer(&skb->data[i], len, 32, 1, buffer,
				   sizeof(buffer), false);
		dev_dbg(priv->dev, "  %#06x: %s\n", i, buffer);
	}

	dev_dbg(priv->dev, "\n************** SKB dump ****************\n");
}

static void fxgmac_dev_xmit(struct fxgmac_channel *channel)
{
	struct fxgmac_pdata *priv = channel->priv;
	struct fxgmac_ring *ring = channel->tx_ring;
	unsigned int tso_context, vlan_context;
	struct fxgmac_desc_data *desc_data;
	struct fxgmac_dma_desc *dma_desc;
	struct fxgmac_pkt_info *pkt_info;
	unsigned int csum, tso, vlan;
	int i, start_index = ring->cur;
	int cur_index = ring->cur;

	pkt_info = &ring->pkt_info;
	csum =  field_get(ATTR_TX_CSUM_ENABLE, pkt_info->attr);
	tso = field_get(ATTR_TX_TSO_ENABLE, pkt_info->attr);
	vlan = field_get(ATTR_TX_VLAN_CTAG, pkt_info->attr);

	if (tso && pkt_info->mss != ring->tx.cur_mss)
		tso_context = 1;
	else
		tso_context = 0;

	if (vlan && pkt_info->vlan_ctag != ring->tx.cur_vlan_ctag)
		vlan_context = 1;
	else
		vlan_context = 0;

	desc_data = FXGMAC_GET_DESC_DATA(ring, cur_index);
	dma_desc = desc_data->dma_desc;

	/* Create a context descriptor if this is a TSO pkt_info */
	if (tso_context) {
		/* Set the MSS size */
		fxgmac_desc_wr_bits(&dma_desc->desc2, TX_CONTEXT_DESC2_MSS,
				    pkt_info->mss);

		/* Mark it as a CONTEXT descriptor */
		fxgmac_desc_wr_bits(&dma_desc->desc3, TX_CONTEXT_DESC3_CTXT, 1);

		/* Indicate this descriptor contains the MSS */
		fxgmac_desc_wr_bits(&dma_desc->desc3, TX_CONTEXT_DESC3_TCMSSV,
				    1);

		ring->tx.cur_mss = pkt_info->mss;
	}

	if (vlan_context) {
		/* Mark it as a CONTEXT descriptor */
		fxgmac_desc_wr_bits(&dma_desc->desc3, TX_CONTEXT_DESC3_CTXT, 1);

		/* Set the VLAN tag */
		fxgmac_desc_wr_bits(&dma_desc->desc3, TX_CONTEXT_DESC3_VT,
				    pkt_info->vlan_ctag);

		/* Indicate this descriptor contains the VLAN tag */
		fxgmac_desc_wr_bits(&dma_desc->desc3, TX_CONTEXT_DESC3_VLTV, 1);

		ring->tx.cur_vlan_ctag = pkt_info->vlan_ctag;
	}
	if (tso_context || vlan_context) {
		cur_index = FXGMAC_GET_ENTRY(cur_index, ring->dma_desc_count);
		desc_data = FXGMAC_GET_DESC_DATA(ring, cur_index);
		dma_desc = desc_data->dma_desc;
	}

	/* Update buffer address (for TSO this is the header) */
	dma_desc->desc0 = cpu_to_le32(lower_32_bits(desc_data->skb_dma));
	dma_desc->desc1 = cpu_to_le32(upper_32_bits(desc_data->skb_dma));

	/* Update the buffer length */
	fxgmac_desc_wr_bits(&dma_desc->desc2, TX_DESC2_HL_B1L,
			    desc_data->skb_dma_len);

	/* VLAN tag insertion check */
	if (vlan)
		fxgmac_desc_wr_bits(&dma_desc->desc2, TX_DESC2_VTIR, 2);

	/* Timestamp enablement check */
	if (field_get(ATTR_TX_PTP, pkt_info->attr))
		fxgmac_desc_wr_bits(&dma_desc->desc2, TX_DESC2_TTSE, 1);

	/* Mark it as First Descriptor */
	fxgmac_desc_wr_bits(&dma_desc->desc3, TX_DESC3_FD, 1);

	/* Mark it as a NORMAL descriptor */
	fxgmac_desc_wr_bits(&dma_desc->desc3, TX_DESC3_CTXT, 0);

	/* Set OWN bit if not the first descriptor */
	if (cur_index != start_index)
		fxgmac_desc_wr_bits(&dma_desc->desc3, TX_DESC3_OWN, 1);

	if (tso) {
		/* Enable TSO */
		fxgmac_desc_wr_bits(&dma_desc->desc3, TX_DESC3_TSE, 1);
		fxgmac_desc_wr_bits(&dma_desc->desc3, TX_DESC3_TCPPL,
				    pkt_info->tcp_payload_len);
		fxgmac_desc_wr_bits(&dma_desc->desc3, TX_DESC3_TCPHDRLEN,
				    pkt_info->tcp_header_len / 4);
	} else {
		/* Enable CRC and Pad Insertion */
		fxgmac_desc_wr_bits(&dma_desc->desc3, TX_DESC3_CPC, 0);

		/* Enable HW CSUM */
		if (csum)
			fxgmac_desc_wr_bits(&dma_desc->desc3, TX_DESC3_CIC,
					    0x3);

		/* Set the total length to be transmitted */
		fxgmac_desc_wr_bits(&dma_desc->desc3, TX_DESC3_FL,
				    pkt_info->length);
	}

	if (start_index <= cur_index)
		i = cur_index - start_index + 1;
	else
		i = ring->dma_desc_count - start_index + cur_index;

	for (; i < pkt_info->desc_count; i++) {
		cur_index = FXGMAC_GET_ENTRY(cur_index, ring->dma_desc_count);
		desc_data = FXGMAC_GET_DESC_DATA(ring, cur_index);
		dma_desc = desc_data->dma_desc;

		/* Update buffer address */
		dma_desc->desc0 =
			cpu_to_le32(lower_32_bits(desc_data->skb_dma));
		dma_desc->desc1 =
			cpu_to_le32(upper_32_bits(desc_data->skb_dma));

		/* Update the buffer length */
		fxgmac_desc_wr_bits(&dma_desc->desc2, TX_DESC2_HL_B1L,
				    desc_data->skb_dma_len);

		/* Set OWN bit */
		fxgmac_desc_wr_bits(&dma_desc->desc3, TX_DESC3_OWN, 1);

		/* Mark it as NORMAL descriptor */
		fxgmac_desc_wr_bits(&dma_desc->desc3, TX_DESC3_CTXT, 0);

		/* Enable HW CSUM */
		if (csum)
			fxgmac_desc_wr_bits(&dma_desc->desc3, TX_DESC3_CIC,
					    0x3);
	}

	/* Set LAST bit for the last descriptor */
	fxgmac_desc_wr_bits(&dma_desc->desc3, TX_DESC3_LD, 1);

	fxgmac_desc_wr_bits(&dma_desc->desc2, TX_DESC2_IC, 1);

	/* Save the Tx info to report back during cleanup */
	desc_data->tx.packets = pkt_info->tx_packets;
	desc_data->tx.bytes = pkt_info->tx_bytes;

	/* In case the Tx DMA engine is running, make sure everything
	 * is written to the descriptor(s) before setting the OWN bit
	 * for the first descriptor
	 */
	dma_wmb();

	/* Set OWN bit for the first descriptor */
	desc_data = FXGMAC_GET_DESC_DATA(ring, start_index);
	dma_desc = desc_data->dma_desc;
	fxgmac_desc_wr_bits(&dma_desc->desc3, TX_DESC3_OWN, 1);

	if (netif_msg_tx_queued(priv))
		fxgmac_dump_tx_desc(priv, ring, start_index,
				    pkt_info->desc_count, 1);

	smp_wmb();  /* Make sure ownership is written to the descriptor */

	ring->cur = FXGMAC_GET_ENTRY(cur_index, ring->dma_desc_count);
	fxgmac_tx_start_xmit(channel, ring);
}

static void fxgmac_prep_vlan(struct sk_buff *skb,
			     struct fxgmac_pkt_info *pkt_info)
{
	if (skb_vlan_tag_present(skb))
		pkt_info->vlan_ctag = skb_vlan_tag_get(skb);
}

static int fxgmac_prep_tso(struct fxgmac_pdata *priv, struct sk_buff *skb,
			   struct fxgmac_pkt_info *pkt_info)
{
	int ret;

	if (!field_get(ATTR_TX_TSO_ENABLE, pkt_info->attr))
		return 0;

	ret = skb_cow_head(skb, 0);
	if (ret)
		return ret;

	pkt_info->header_len = skb_transport_offset(skb) + tcp_hdrlen(skb);
	pkt_info->tcp_header_len = tcp_hdrlen(skb);
	pkt_info->tcp_payload_len = skb->len - pkt_info->header_len;
	pkt_info->mss = skb_shinfo(skb)->gso_size;

	/* Update the number of packets that will ultimately be transmitted
	 * along with the extra bytes for each extra packet
	 */
	pkt_info->tx_packets = skb_shinfo(skb)->gso_segs;
	pkt_info->tx_bytes += (pkt_info->tx_packets - 1) * pkt_info->header_len;

	return 0;
}

static int fxgmac_is_tso(struct sk_buff *skb)
{
	if (skb->ip_summed != CHECKSUM_PARTIAL)
		return 0;

	if (!skb_is_gso(skb))
		return 0;

	return 1;
}

static void fxgmac_prep_tx_pkt(struct fxgmac_pdata *priv,
			       struct fxgmac_ring *ring, struct sk_buff *skb,
			       struct fxgmac_pkt_info *pkt_info)
{
	u32 len, context_desc = 0;

	pkt_info->skb = skb;
	pkt_info->desc_count = 0;
	pkt_info->tx_packets = 1;
	pkt_info->tx_bytes = skb->len;

	if (fxgmac_is_tso(skb)) {
		/* TSO requires an extra descriptor if mss is different */
		if (skb_shinfo(skb)->gso_size != ring->tx.cur_mss) {
			context_desc = 1;
			pkt_info->desc_count++;
		}

		/* TSO requires an extra descriptor for TSO header */
		pkt_info->desc_count++;
		pkt_info->attr |= (ATTR_TX_TSO_ENABLE | ATTR_TX_CSUM_ENABLE);
	} else if (skb->ip_summed == CHECKSUM_PARTIAL) {
		pkt_info->attr |= ATTR_TX_CSUM_ENABLE;
	}

	if (skb_vlan_tag_present(skb)) {
		/* VLAN requires an extra descriptor if tag is different */
		if (skb_vlan_tag_get(skb) != ring->tx.cur_vlan_ctag)
			/* We can share with the TSO context descriptor */
			if (!context_desc)
				pkt_info->desc_count++;

		pkt_info->attr |= ATTR_TX_VLAN_CTAG;
	}

	for (len = skb_headlen(skb); len;) {
		pkt_info->desc_count++;
		len -= min_t(unsigned int, len, FXGMAC_TX_MAX_BUF_SIZE);
	}

	for (u32 i = 0; i < skb_shinfo(skb)->nr_frags; i++)
		for (len = skb_frag_size(&skb_shinfo(skb)->frags[i]); len;) {
			pkt_info->desc_count++;
			len -= min_t(unsigned int, len, FXGMAC_TX_MAX_BUF_SIZE);
		}
}

static netdev_tx_t fxgmac_xmit(struct sk_buff *skb, struct net_device *ndev)
{
	struct fxgmac_pdata *priv = netdev_priv(ndev);
	struct fxgmac_pkt_info *tx_pkt_info;
	struct fxgmac_channel *channel;
	struct netdev_queue *txq;
	struct fxgmac_ring *ring;
	int ret;

	channel = priv->channel_head + skb->queue_mapping;
	txq = netdev_get_tx_queue(ndev, channel->queue_index);
	ring = channel->tx_ring;
	tx_pkt_info = &ring->pkt_info;

	if (skb->len == 0) {
		netdev_err(priv->ndev, "empty skb received from stack\n");
		dev_kfree_skb_any(skb);
		return NETDEV_TX_OK;
	}

	/* Prepare preliminary packet info for TX */
	memset(tx_pkt_info, 0, sizeof(*tx_pkt_info));
	fxgmac_prep_tx_pkt(priv, ring, skb, tx_pkt_info);

	/* Check that there are enough descriptors available */
	ret = fxgmac_maybe_stop_tx_queue(channel, ring,
					 tx_pkt_info->desc_count);
	if (ret == NETDEV_TX_BUSY)
		return ret;

	ret = fxgmac_prep_tso(priv, skb, tx_pkt_info);
	if (ret < 0) {
		netdev_err(priv->ndev, "processing TSO packet failed\n");
		dev_kfree_skb_any(skb);
		return NETDEV_TX_OK;
	}
	fxgmac_prep_vlan(skb, tx_pkt_info);

	if (!fxgmac_tx_skb_map(channel, skb)) {
		dev_kfree_skb_any(skb);
		netdev_err(priv->ndev, "xmit, map tx skb failed\n");
		return NETDEV_TX_OK;
	}

	/* Report on the actual number of bytes (to be) sent */
	netdev_tx_sent_queue(txq, tx_pkt_info->tx_bytes);

	/* Configure required descriptor fields for transmission */
	fxgmac_dev_xmit(channel);

	if (netif_msg_pktdata(priv))
		fxgmac_dbg_pkt(priv, skb, true);

	/* Stop the queue in advance if there may not be enough descriptors */
	fxgmac_maybe_stop_tx_queue(channel, ring, FXGMAC_TX_MAX_DESC_NR);

	return NETDEV_TX_OK;
}

#ifdef CONFIG_NET_POLL_CONTROLLER
static void fxgmac_poll_controller(struct net_device *ndev)
{
	struct fxgmac_pdata *priv = netdev_priv(ndev);
	struct fxgmac_channel *channel;

	if (priv->per_channel_irq) {
		channel = priv->channel_head;
		for (u32 i = 0; i < priv->channel_count; i++, channel++)
			fxgmac_dma_isr(channel->dma_irq_rx, channel);
	} else {
		disable_irq(priv->dev_irq);
		fxgmac_isr(priv->dev_irq, priv);
		enable_irq(priv->dev_irq);
	}
}
#endif /* CONFIG_NET_POLL_CONTROLLER */

static const struct net_device_ops fxgmac_netdev_ops = {
	.ndo_open		= fxgmac_open,
	.ndo_stop		= fxgmac_close,
	.ndo_start_xmit		= fxgmac_xmit,
	.ndo_tx_timeout		= fxgmac_tx_timeout,
	.ndo_validate_addr	= eth_validate_addr,
#ifdef CONFIG_NET_POLL_CONTROLLER
	.ndo_poll_controller	= fxgmac_poll_controller,
#endif
};

const struct net_device_ops *fxgmac_get_netdev_ops(void)
{
	return &fxgmac_netdev_ops;
}

static void fxgmac_rx_refresh(struct fxgmac_channel *channel)
{
	struct fxgmac_ring *ring = channel->rx_ring;
	struct fxgmac_pdata *priv = channel->priv;
	struct fxgmac_desc_data *desc_data;

	while (ring->dirty != ring->cur) {
		desc_data = FXGMAC_GET_DESC_DATA(ring, ring->dirty);

		/* Reset desc_data values */
		fxgmac_desc_data_unmap(priv, desc_data);

		if (fxgmac_rx_buffe_map(priv, ring, desc_data))
			break;

		fxgmac_desc_rx_reset(desc_data);
		ring->dirty =
			FXGMAC_GET_ENTRY(ring->dirty, ring->dma_desc_count);
	}

	/* Make sure everything is written before the register write */
	wmb();

	/* Update the Rx Tail Pointer Register with address of
	 * the last cleaned entry
	 */
	desc_data = FXGMAC_GET_DESC_DATA(ring, (ring->dirty - 1) &
					 (ring->dma_desc_count - 1));
	fxgmac_dma_io_wr(channel, DMA_CH_RDTR_LO,
			 lower_32_bits(desc_data->dma_desc_addr));
}

static struct sk_buff *fxgmac_create_skb(struct fxgmac_pdata *priv,
					 struct napi_struct *napi,
					 struct fxgmac_desc_data *desc_data,
					 unsigned int len)
{
	unsigned int copy_len;
	struct sk_buff *skb;
	u8 *packet;

	skb = napi_alloc_skb(napi, desc_data->rx.hdr.dma_len);
	if (!skb)
		return NULL;

	/* Start with the header buffer which may contain just the header
	 * or the header plus data
	 */
	dma_sync_single_range_for_cpu(priv->dev, desc_data->rx.hdr.dma_base,
				      desc_data->rx.hdr.dma_off,
				      desc_data->rx.hdr.dma_len,
				      DMA_FROM_DEVICE);

	packet = page_address(desc_data->rx.hdr.pa.pages) +
		 desc_data->rx.hdr.pa.pages_offset;
	copy_len = min(desc_data->rx.hdr.dma_len, len);
	skb_copy_to_linear_data(skb, packet, copy_len);
	skb_put(skb, copy_len);

	return skb;
}

static int fxgmac_tx_poll(struct fxgmac_channel *channel)
{
	struct fxgmac_pdata *priv = channel->priv;
	unsigned int cur, tx_packets = 0, tx_bytes = 0;
	struct fxgmac_ring *ring = channel->tx_ring;
	struct net_device *ndev = priv->ndev;
	struct fxgmac_desc_data *desc_data;
	struct fxgmac_dma_desc *dma_desc;
	struct netdev_queue *txq;
	int processed = 0;

	/* Nothing to do if there isn't a Tx ring for this channel */
	if (!ring)
		return 0;

	if (ring->cur != ring->dirty && (netif_msg_tx_done(priv)))
		netdev_dbg(priv->ndev, "%s, ring_cur=%d,ring_dirty=%d,qIdx=%d\n",
			   __func__, ring->cur, ring->dirty,
			   channel->queue_index);

	cur = ring->cur;

	/* Be sure we get ring->cur before accessing descriptor data */
	smp_rmb();

	txq = netdev_get_tx_queue(ndev, channel->queue_index);
	while (ring->dirty != cur) {
		desc_data = FXGMAC_GET_DESC_DATA(ring, ring->dirty);
		dma_desc = desc_data->dma_desc;

		if (!fxgmac_is_tx_complete(dma_desc))
			break;

		/* Make sure descriptor fields are read after reading
		 * the OWN bit
		 */
		dma_rmb();

		if (netif_msg_tx_done(priv))
			fxgmac_dump_tx_desc(priv, ring, ring->dirty, 1, 0);

		if (fxgmac_is_last_desc(dma_desc)) {
			tx_packets += desc_data->tx.packets;
			tx_bytes += desc_data->tx.bytes;
		}

		/* Free the SKB and reset the descriptor for re-use */
		fxgmac_desc_data_unmap(priv, desc_data);
		fxgmac_desc_tx_reset(desc_data);

		processed++;
		ring->dirty =
			FXGMAC_GET_ENTRY(ring->dirty, ring->dma_desc_count);
	}

	if (!processed)
		return 0;

	netdev_tx_completed_queue(txq, tx_packets, tx_bytes);

	/* Make sure ownership is written to the descriptor */
	smp_wmb();
	if (ring->tx.queue_stopped == 1 &&
	    (fxgmac_desc_tx_avail(ring) > FXGMAC_TX_DESC_MIN_FREE)) {
		ring->tx.queue_stopped = 0;
		netif_tx_wake_queue(txq);
	}

	return processed;
}

static int fxgmac_one_poll_tx(struct napi_struct *napi, int budget)
{
	struct fxgmac_channel *channel =
		container_of(napi, struct fxgmac_channel, napi_tx);
	struct fxgmac_pdata *priv = channel->priv;
	int ret;

	ret = fxgmac_tx_poll(channel);
	if (napi_complete_done(napi, 0))
		fxgmac_enable_msix_one_irq(priv, MSI_ID_TXQ0);

	return ret;
}

static int fxgmac_dev_read(struct fxgmac_channel *channel)
{
	struct fxgmac_pdata *priv = channel->priv;
	struct fxgmac_ring *ring = channel->rx_ring;
	struct net_device *ndev = priv->ndev;
	static unsigned int cnt_incomplete;
	struct fxgmac_desc_data *desc_data;
	struct fxgmac_dma_desc *dma_desc;
	struct fxgmac_pkt_info *pkt_info;
	u32 ipce, iphe, rxparser;
	unsigned int err, etlt;

	desc_data = FXGMAC_GET_DESC_DATA(ring, ring->cur);
	dma_desc = desc_data->dma_desc;
	pkt_info = &ring->pkt_info;

	/* Check for data availability */
	if (fxgmac_desc_rd_bits(dma_desc->desc3, RX_DESC3_OWN))
		return 1;

	/* Make sure descriptor fields are read after reading the OWN bit */
	dma_rmb();

	if (netif_msg_rx_status(priv))
		fxgmac_dump_rx_desc(priv, ring, ring->cur);

	/* Normal Descriptor, be sure Context Descriptor bit is off */
	pkt_info->attr &= ~ATTR_RX_CONTEXT;

	/* Indicate if a Context Descriptor is next */
	/* Get the header length */
	if (fxgmac_desc_rd_bits(dma_desc->desc3, RX_DESC3_FD)) {
		desc_data->rx.hdr_len = fxgmac_desc_rd_bits(dma_desc->desc2,
							    RX_DESC2_HL);
	}

	/* Get the pkt_info length */
	desc_data->rx.len =
		fxgmac_desc_rd_bits(dma_desc->desc3, RX_DESC3_PL);

	if (!fxgmac_desc_rd_bits(dma_desc->desc3, RX_DESC3_LD)) {
		/* Not all the data has been transferred for this pkt_info */
		pkt_info->attr |= ATTR_RX_INCOMPLETE;
		cnt_incomplete++;
		return 0;
	}

	if ((cnt_incomplete) && netif_msg_rx_status(priv))
		netdev_dbg(priv->ndev, "%s, rx back to normal and incomplete cnt=%u\n",
			   __func__, cnt_incomplete);
	cnt_incomplete = 0;

	/* This is the last of the data for this pkt_info */
	pkt_info->attr &= ~ATTR_RX_INCOMPLETE;

	/* Set checksum done indicator as appropriate */
	if (ndev->features & NETIF_F_RXCSUM) {
		ipce = fxgmac_desc_rd_bits(dma_desc->desc1, RX_DESC1_WB_IPCE);
		iphe = fxgmac_desc_rd_bits(dma_desc->desc1, RX_DESC1_WB_IPHE);
		if (!ipce && !iphe)
			pkt_info->attr |= ATTR_RX_CSUM_DONE;
		else
			return 0;
	}

	/* Check for errors (only valid in last descriptor) */
	err = fxgmac_desc_rd_bits(dma_desc->desc3, RX_DESC3_ES);
	rxparser = fxgmac_desc_rd_bits(dma_desc->desc2, RX_DESC2_WB_RAPARSER);
	/* Error or incomplete parsing due to ECC error */
	if (err || rxparser == 0x7) {
		pkt_info->errors |= ERRORS_RX_FRAME;
		return 0;
	}

	etlt = fxgmac_desc_rd_bits(dma_desc->desc3, RX_DESC3_ETLT);
	if (etlt == 0x4 && (ndev->features & NETIF_F_HW_VLAN_CTAG_RX)) {
		pkt_info->attr |= ATTR_RX_VLAN_CTAG;
		pkt_info->vlan_ctag = fxgmac_desc_rd_bits(dma_desc->desc0,
							  RX_DESC0_OVT);
	}

	return 0;
}

static unsigned int fxgmac_desc_rx_dirty(struct fxgmac_ring *ring)
{
	unsigned int dirty;

	if (ring->dirty <= ring->cur)
		dirty = ring->cur - ring->dirty;
	else
		dirty = ring->dma_desc_count - ring->dirty + ring->cur;

	return dirty;
}

static int fxgmac_rx_poll(struct fxgmac_channel *channel, int budget)
{
	struct fxgmac_pdata *priv = channel->priv;
	struct fxgmac_ring *ring = channel->rx_ring;
	struct net_device *ndev = priv->ndev;
	u32 context_next, context, incomplete;
	struct fxgmac_desc_data *desc_data;
	struct fxgmac_pkt_info *pkt_info;
	struct napi_struct *napi;
	u32 len, max_len;
	int packet_count = 0;

	struct sk_buff *skb;

	/* Nothing to do if there isn't a Rx ring for this channel */
	if (!ring)
		return 0;

	napi = (priv->per_channel_irq) ? &channel->napi_rx : &priv->napi;
	pkt_info = &ring->pkt_info;

	while (packet_count < budget) {
		memset(pkt_info, 0, sizeof(*pkt_info));
		skb = NULL;
		len = 0;

read_again:
		desc_data = FXGMAC_GET_DESC_DATA(ring, ring->cur);

		if (fxgmac_desc_rx_dirty(ring) > FXGMAC_RX_DESC_MAX_DIRTY)
			fxgmac_rx_refresh(channel);

		if (fxgmac_dev_read(channel))
			break;

		ring->cur = FXGMAC_GET_ENTRY(ring->cur, ring->dma_desc_count);
		incomplete =  field_get(ATTR_RX_INCOMPLETE, pkt_info->attr);
		context_next = field_get(ATTR_RX_CONTEXT_NEXT, pkt_info->attr);
		context = field_get(ATTR_RX_CONTEXT, pkt_info->attr);

		if (incomplete || context_next)
			goto read_again;

		if (pkt_info->errors) {
			dev_kfree_skb(skb);
			priv->ndev->stats.rx_dropped++;
			netdev_err(priv->ndev, "Received packet failed\n");
			goto next_packet;
		}

		if (!context) {
			len = desc_data->rx.len;
			if (len == 0) {
				if (net_ratelimit())
					netdev_err(priv->ndev, "A packet of length 0 was received\n");
				priv->ndev->stats.rx_length_errors++;
				priv->ndev->stats.rx_dropped++;
				goto next_packet;
			}

			if (len && !skb) {
				skb = fxgmac_create_skb(priv, napi, desc_data,
							len);
				if (unlikely(!skb)) {
					if (net_ratelimit())
						netdev_err(priv->ndev, "create skb failed\n");
					priv->ndev->stats.rx_dropped++;
					goto next_packet;
				}
			}
			max_len = ndev->mtu + ETH_HLEN;
			if (!(ndev->features & NETIF_F_HW_VLAN_CTAG_RX) &&
			    skb->protocol == htons(ETH_P_8021Q))
				max_len += VLAN_HLEN;

			if (len > max_len) {
				if (net_ratelimit())
					netdev_err(priv->ndev, "len %d larger than max size %d\n",
						   len, max_len);
				priv->ndev->stats.rx_length_errors++;
				priv->ndev->stats.rx_dropped++;
				dev_kfree_skb(skb);
				goto next_packet;
			}
		}

		if (!skb) {
			priv->ndev->stats.rx_dropped++;
			goto next_packet;
		}

		if (netif_msg_pktdata(priv))
			fxgmac_dbg_pkt(priv, skb, false);

		skb_checksum_none_assert(skb);
		if (ndev->features & NETIF_F_RXCSUM)
			skb->ip_summed = CHECKSUM_UNNECESSARY;

		if (field_get(ATTR_RX_VLAN_CTAG, pkt_info->attr))
			__vlan_hwaccel_put_tag(skb, htons(ETH_P_8021Q),
					       pkt_info->vlan_ctag);

		if (field_get(ATTR_RX_RSS_HASH, pkt_info->attr))
			skb_set_hash(skb, pkt_info->rss_hash,
				     pkt_info->rss_hash_type);

		skb->dev = ndev;
		skb->protocol = eth_type_trans(skb, ndev);
		skb_record_rx_queue(skb, channel->queue_index);
		napi_gro_receive(napi, skb);

next_packet:
		packet_count++;
		priv->ndev->stats.rx_packets++;
		priv->ndev->stats.rx_bytes += len;
	}

	return packet_count;
}

static int fxgmac_one_poll_rx(struct napi_struct *napi, int budget)
{
	struct fxgmac_channel *channel =
		container_of(napi, struct fxgmac_channel, napi_rx);
	int processed = fxgmac_rx_poll(channel, budget);

	if (processed < budget && (napi_complete_done(napi, processed)))
		fxgmac_enable_msix_one_irq(channel->priv, channel->queue_index);

	return processed;
}

static int fxgmac_all_poll(struct napi_struct *napi, int budget)
{
	struct fxgmac_channel *channel;
	struct fxgmac_pdata *priv;
	int processed = 0;

	priv = container_of(napi, struct fxgmac_pdata, napi);
	do {
		channel = priv->channel_head;
		/* Only support 1 tx channel, poll ch 0. */
		fxgmac_tx_poll(priv->channel_head + 0);
		for (u32 i = 0; i < priv->channel_count; i++, channel++)
			processed += fxgmac_rx_poll(channel, budget);
	} while (false);

	/* If we processed everything, we are done */
	if (processed < budget) {
		/* Turn off polling */
		if (napi_complete_done(napi, processed))
			fxgmac_enable_mgm_irq(priv);
	}

	if ((processed) && (netif_msg_rx_status(priv)))
		netdev_dbg(priv->ndev, "%s,received:%d\n", __func__, processed);

	return processed;
}

static void napi_add_enable(struct fxgmac_pdata *priv, struct napi_struct *napi,
			    int (*poll)(struct napi_struct *, int),
			    u32 flag)
{
	netif_napi_add(priv->ndev, napi, poll);
	napi_enable(napi);
	priv->int_flag |= flag;
}

static void fxgmac_napi_enable(struct fxgmac_pdata *priv)
{
	u32 rx_napi[] = {INT_FLAG_RX0_NAPI, INT_FLAG_RX1_NAPI,
			 INT_FLAG_RX2_NAPI, INT_FLAG_RX3_NAPI};
	struct fxgmac_channel *channel = priv->channel_head;

	if (!priv->per_channel_irq) {
		if (field_get(INT_FLAG_LEGACY_NAPI, priv->int_flag))
			return;

		napi_add_enable(priv, &priv->napi, fxgmac_all_poll,
				INT_FLAG_LEGACY_NAPI);
		return;
	}

	if (!field_get(INT_FLAG_TX_NAPI, priv->int_flag))
		napi_add_enable(priv, &channel->napi_tx, fxgmac_one_poll_tx,
				INT_FLAG_TX_NAPI);

	for (u32 i = 0; i < priv->channel_count; i++, channel++)
		if (!(priv->int_flag & rx_napi[i]))
			napi_add_enable(priv, &channel->napi_rx,
					fxgmac_one_poll_rx, rx_napi[i]);
}

static int fxgmac_probe(struct pci_dev *pcidev, const struct pci_device_id *id)
{
	struct device *dev = &pcidev->dev;
	struct fxgmac_resources res;
	int i, ret;

	ret = pcim_enable_device(pcidev);
	if (ret) {
		dev_err(dev, "%s pcim_enable_device err:%d\n", __func__, ret);
		return ret;
	}

	for (i = 0; i < PCI_STD_NUM_BARS; i++) {
		if (pci_resource_len(pcidev, i) == 0)
			continue;

		ret = pcim_iomap_regions(pcidev, BIT(i), FXGMAC_DRV_NAME);
		if (ret) {
			dev_err(dev, "%s, pcim_iomap_regions err:%d\n",
				__func__, ret);
			return ret;
		}
		break;
	}

	pci_set_master(pcidev);

	memset(&res, 0, sizeof(res));
	res.irq = pcidev->irq;
	res.addr = pcim_iomap_table(pcidev)[i];

	return fxgmac_drv_probe(&pcidev->dev, &res);
}

static void fxgmac_remove(struct pci_dev *pcidev)
{
	struct fxgmac_pdata *priv = dev_get_drvdata(&pcidev->dev);
	struct net_device *ndev = priv->ndev;

	unregister_netdev(ndev);
	fxgmac_phy_reset(priv);
	free_netdev(ndev);

	if (IS_ENABLED(CONFIG_PCI_MSI) &&
	    FIELD_GET(INT_FLAG_MSIX, priv->int_flag)) {
		pci_disable_msix(pcidev);
		kfree(priv->msix_entries);
		priv->msix_entries = NULL;
	}
}

static void __fxgmac_shutdown(struct pci_dev *pcidev)
{
	struct fxgmac_pdata *priv = dev_get_drvdata(&pcidev->dev);
	struct net_device *ndev = priv->ndev;

	fxgmac_net_powerdown(priv);
	netif_device_detach(ndev);
}

static void fxgmac_shutdown(struct pci_dev *pcidev)
{
	rtnl_lock();
	 __fxgmac_shutdown(pcidev);
	if (system_state == SYSTEM_POWER_OFF) {
		pci_wake_from_d3(pcidev, false);
		pci_set_power_state(pcidev, PCI_D3hot);
	}
	rtnl_unlock();
}

static int fxgmac_suspend(struct device *device)
{
	struct fxgmac_pdata *priv = dev_get_drvdata(device);
	struct net_device *ndev = priv->ndev;

	rtnl_lock();
	if (priv->dev_state != FXGMAC_DEV_START)
		goto unlock;

	if (netif_running(ndev))
		__fxgmac_shutdown(to_pci_dev(device));

	priv->dev_state = FXGMAC_DEV_SUSPEND;
unlock:
	rtnl_unlock();

	return 0;
}

static int fxgmac_resume(struct device *device)
{
	struct fxgmac_pdata *priv = dev_get_drvdata(device);
	struct net_device *ndev = priv->ndev;
	int ret = 0;

	rtnl_lock();
	if (priv->dev_state != FXGMAC_DEV_SUSPEND)
		goto unlock;

	priv->dev_state = FXGMAC_DEV_RESUME;
	__clear_bit(FXGMAC_POWER_STATE_DOWN, &priv->power_state);
	rtnl_lock();
	if (netif_running(ndev)) {
		ret = fxgmac_net_powerup(priv);
		if (ret < 0) {
			netdev_err(priv->ndev, "%s, fxgmac net powerup failed:%d\n",
				   __func__, ret);
			goto unlock;
		}
	}

	netif_device_attach(ndev);
unlock:
	rtnl_unlock();

	return ret;
}

#define MOTORCOMM_PCI_ID			0x1f0a
#define YT6801_PCI_DEVICE_ID			0x6801

static const struct pci_device_id fxgmac_pci_tbl[] = {
	{ PCI_DEVICE(MOTORCOMM_PCI_ID, YT6801_PCI_DEVICE_ID) },
	{ 0 }
};

MODULE_DEVICE_TABLE(pci, fxgmac_pci_tbl);

static const struct dev_pm_ops fxgmac_pm_ops = {
	SYSTEM_SLEEP_PM_OPS(fxgmac_suspend, fxgmac_resume)
};

static struct pci_driver fxgmac_pci_driver = {
	.name		= FXGMAC_DRV_NAME,
	.id_table	= fxgmac_pci_tbl,
	.probe		= fxgmac_probe,
	.remove		= fxgmac_remove,
	.driver.pm	= pm_ptr(&fxgmac_pm_ops),
	.shutdown	= fxgmac_shutdown,
};

module_pci_driver(fxgmac_pci_driver);

MODULE_AUTHOR("Motorcomm Electronic Tech. Co., Ltd.");
MODULE_DESCRIPTION(FXGMAC_DRV_DESC);
MODULE_LICENSE("GPL");
MODULE_SOFTDEP("pre: motorcomm  post: yt6801");
