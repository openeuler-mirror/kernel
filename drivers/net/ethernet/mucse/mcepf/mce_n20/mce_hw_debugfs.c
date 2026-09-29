// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024-2026 Mucse Corporation. */

#include "../mce.h"
#include "../mce_base.h"
#include "mce_hw_n20.h"
#include "mce_hw_debugfs.h"

static void n20_dump_rings_regs(struct mce_hw *hw)
{
	struct mce_ring *tx_ring = NULL;
	struct mce_ring *rx_ring = NULL;
	struct mce_pf *pf = hw->back;
	struct device *dev = hw->dev;
	struct mce_vsi *vsi = NULL;
	u32 head_val = 0;
	u32 tail_val = 0;
	u32 drop_val = 0;
	u16 q_idx = 0;

	if (!pf)
		return;

	vsi = mce_get_main_vsi(pf);

	if (!vsi)
		return;

	dev_info(dev, "Debug - Dump Ring Regs :\n");
	mce_for_each_txq_new(vsi, q_idx) {
		if (!vsi->tx_rings[q_idx])
			continue;
		tx_ring = vsi->tx_rings[q_idx];
		if (!tx_ring->q_vector)
			continue;
		head_val = ring_rd32(tx_ring, N20_DMA_REG_TX_DESC_HEAD);
		tail_val = ring_rd32(tx_ring, N20_DMA_REG_TX_DESC_TAIL);
		dev_info(dev,
			 "\tTxq-%-3u (0x%08x)-head : 0x%08x (%4u),\t"
			 "(0x%08x)-tail : 0x%08x (%4u)\n",
			 tx_ring->q_index,
			 N20_RING_OFF(tx_ring->q_index) +
				 N20_DMA_REG_TX_DESC_HEAD,
			 head_val, head_val,
			 N20_RING_OFF(tx_ring->q_index) +
				 N20_DMA_REG_TX_DESC_TAIL,
			 tail_val, tail_val);
	}

	mce_for_each_txq_new(vsi, q_idx) {
		if (!vsi->tx_rings[q_idx])
			continue;
		tx_ring = vsi->tx_rings[q_idx];
		if (!tx_ring->q_vector)
			continue;
		dev_info(dev, "\tTxq-%-3u next_to_clean 0x%08x (%4u)\n",
			 tx_ring->q_index, tx_ring->next_to_clean,
			 tx_ring->next_to_clean);
	}

	mce_for_each_rxq_new(vsi, q_idx) {
		rx_ring = vsi->rx_rings[q_idx];
		if (!rx_ring->q_vector)
			continue;
		head_val = ring_rd32(rx_ring, N20_DMA_REG_RX_DESC_HEAD);
		tail_val = ring_rd32(rx_ring, N20_DMA_REG_RX_DESC_TAIL);
		dev_info(dev,
			 "\tRxq-%-3u (0x%08x)-head : 0x%08x (%4u),\t"
			 "(0x%08x)-tail : 0x%08x (%4u)\n",
			 rx_ring->q_index,
			 N20_RING_OFF(rx_ring->q_index) +
				 N20_DMA_REG_RX_DESC_HEAD,
			 head_val, head_val,
			 N20_RING_OFF(rx_ring->q_index) +
				 N20_DMA_REG_RX_DESC_TAIL,
			 tail_val, tail_val);
	}

	mce_for_each_rxq_new(vsi, q_idx) {
		rx_ring = vsi->rx_rings[q_idx];
		if (!rx_ring->q_vector)
			continue;
		drop_val = ring_rd32(rx_ring, N20_DMA_REG_RX_TIMEOUT_DROP);
		dev_info(dev, "\tRxq-%-3u timeout drop 0x%08x (%4u)\n",
			 rx_ring->q_index, drop_val, drop_val);
	}

	mce_for_each_rxq_new(vsi, q_idx) {
		rx_ring = vsi->rx_rings[q_idx];
		if (!rx_ring->q_vector)
			continue;
		dev_info(dev, "\tRxq-%-3u next_to_clean 0x%08x (%4u)\n",
			 rx_ring->q_index, rx_ring->next_to_clean,
			 rx_ring->next_to_clean);
	}
}

static void n20_dump_dma_regs(struct mce_hw *hw)
{
	struct device *dev = hw->dev;
	u32 val = 0;

	dev_info(dev, "Debug - Dump DMA Regs :\n");
	val = rd32(hw, N20_DMA_D_TX_IRQ_CNT);
	dev_info(dev, "\t(0x%08x) tx irq cnt\t\t\t\t: 0x%08x (%u)\n",
		 N20_DMA_D_TX_IRQ_CNT, val, val);
	val = rd32(hw, N20_DMA_D_RX_IRQ_CNT);
	dev_info(dev, "\t(0x%08x) rx irq cnt\t\t\t\t: 0x%08x (%u)\n",
		 N20_DMA_D_RX_IRQ_CNT, val, val);
	val = rd32(hw, N20_DMA_D_CH0_TX_CTRL_DATA_FRAG_CNT);
	dev_info(dev,
		 "\t(0x%08x) chanel-0 tx ctrl data frag cnt\t: 0x%08x (%u)\n",
		 N20_DMA_D_CH0_TX_CTRL_DATA_FRAG_CNT, val, val);
	val = rd32(hw, N20_DMA_D_CH1_TX_CTRL_DATA_FRAG_CNT);
	dev_info(dev,
		 "\t(0x%08x) chanel-1 tx ctrl data frag cnt\t: 0x%08x (%u)\n",
		 N20_DMA_D_CH1_TX_CTRL_DATA_FRAG_CNT, val, val);
	val = rd32(hw, N20_DMA_D_CH2_TX_CTRL_DATA_FRAG_CNT);
	dev_info(dev,
		 "\t(0x%08x) chanel-2 tx ctrl data frag cnt\t: 0x%08x (%u)\n",
		 N20_DMA_D_CH2_TX_CTRL_DATA_FRAG_CNT, val, val);
	val = rd32(hw, N20_DMA_D_CH3_TX_CTRL_DATA_FRAG_CNT);
	dev_info(dev,
		 "\t(0x%08x) chanel-3 tx ctrl data frag cnt\t: 0x%08x (%u)\n",
		 N20_DMA_D_CH3_TX_CTRL_DATA_FRAG_CNT, val, val);
	val = rd32(hw, N20_DMA_D_TX_CTRL_RD_DESC_CNT);
	dev_info(dev, "\t(0x%08x) tx ctrl read desc cnt\t\t: 0x%08x (%u)\n",
		 N20_DMA_D_TX_CTRL_RD_DESC_CNT, val, val);
	val = rd32(hw, N20_DMA_D_TX_CTRL_RD_PKGS_CNT);
	dev_info(dev, "\t(0x%08x) tx ctrl read pkgs cnt\t\t: 0x%08x (%u)\n",
		 N20_DMA_D_TX_CTRL_RD_PKGS_CNT, val, val);
	val = rd32(hw, N20_DMA_D_TX_CTRL_FIFO0_DESC_AVG);
	dev_info(dev, "\t(0x%08x) tx ctrl fifo-0 desc average\t: 0x%08x (%u)\n",
		 N20_DMA_D_TX_CTRL_FIFO0_DESC_AVG, val, val);
	val = rd32(hw, N20_DMA_D_TX_CTRL_FIFO1_DESC_AVG);
	dev_info(dev, "\t(0x%08x) tx ctrl fifo-1 desc average\t: 0x%08x (%u)\n",
		 N20_DMA_D_TX_CTRL_FIFO1_DESC_AVG, val, val);
	val = rd32(hw, N20_DMA_D_TX_CTRL_FIFO2_DESC_AVG);
	dev_info(dev, "\t(0x%08x) tx ctrl fifo-2 desc average\t: 0x%08x (%u)\n",
		 N20_DMA_D_TX_CTRL_FIFO2_DESC_AVG, val, val);
	val = rd32(hw, N20_DMA_D_TX_CTRL_FIFO3_DESC_AVG);
	dev_info(dev, "\t(0x%08x) tx ctrl fifo-3 desc average\t: 0x%08x (%u)\n",
		 N20_DMA_D_TX_CTRL_FIFO3_DESC_AVG, val, val);
	val = rd32(hw, N20_DMA_D_RX_CTRL_PCIE_RD_REQ);
	dev_info(dev, "\t(0x%08x) rx ctrl pcie read req cnt\t\t: 0x%08x (%u)\n",
		 N20_DMA_D_RX_CTRL_PCIE_RD_REQ, val, val);
	val = rd32(hw, N20_DMA_D_RX_CTRL_PCIE_WR_REQ);
	dev_info(dev,
		 "\t(0x%08x) rx ctrl pcie write req cnt\t\t: 0x%08x (%u)\n",
		 N20_DMA_D_RX_CTRL_PCIE_WR_REQ, val, val);
	val = rd32(hw, N20_DMA_D_RX_CTRL_WR_DESC_CNT);
	dev_info(dev, "\t(0x%08x) rx ctrl received desc cnt\t\t: 0x%08x (%u)\n",
		 N20_DMA_D_RX_CTRL_WR_DESC_CNT, val, val);
	val = rd32(hw, N20_DMA_D_RX_CTRL_RD_PKGS_CNT);
	dev_info(dev, "\t(0x%08x) rx ctrl read pkgs cnt\t\t: 0x%08x (%u)\n",
		 N20_DMA_D_RX_CTRL_RD_PKGS_CNT, val, val);
	val = rd32(hw, N20_DMA_D_RX_CTRL_FIFO0_DESC_AVG);
	dev_info(dev, "\t(0x%08x) rx ctrl fifo-0 desc average\t: 0x%08x (%u)\n",
		 N20_DMA_D_RX_CTRL_FIFO0_DESC_AVG, val, val);
	val = rd32(hw, N20_DMA_D_RX_CTRL_FIFO1_DESC_AVG);
	dev_info(dev, "\t(0x%08x) rx ctrl fifo-1 desc average\t: 0x%08x (%u)\n",
		 N20_DMA_D_RX_CTRL_FIFO1_DESC_AVG, val, val);
	val = rd32(hw, N20_DMA_D_RX_CTRL_FIFO2_DESC_AVG);
	dev_info(dev, "\t(0x%08x) rx ctrl fifo-2 desc average\t: 0x%08x (%u)\n",
		 N20_DMA_D_RX_CTRL_FIFO2_DESC_AVG, val, val);
	val = rd32(hw, N20_DMA_D_RX_CTRL_FIFO3_DESC_AVG);
	dev_info(dev, "\t(0x%08x) rx ctrl fifo-3 desc average\t: 0x%08x (%u)\n",
		 N20_DMA_D_RX_CTRL_FIFO3_DESC_AVG, val, val);
	val = rd32(hw, N20_DMA_D_RX_CTRL_RING0_NO_DESC_AVG);
	dev_info(dev,
		 "\t(0x%08x) rx ctrl ring-0 no desc average\t: 0x%08x (%u)\n",
		 N20_DMA_D_RX_CTRL_RING0_NO_DESC_AVG, val, val);
	val = rd32(hw, N20_DMA_D_RX_CTRL_RING1_NO_DESC_AVG);
	dev_info(dev,
		 "\t(0x%08x) rx ctrl ring-1 no desc average\t: 0x%08x (%u)\n",
		 N20_DMA_D_RX_CTRL_RING1_NO_DESC_AVG, val, val);
	val = rd32(hw, N20_DMA_D_RX_CTRL_RING2_NO_DESC_AVG);
	dev_info(dev,
		 "\t(0x%08x) rx ctrl ring-2 no desc average\t: 0x%08x (%u)\n",
		 N20_DMA_D_RX_CTRL_RING2_NO_DESC_AVG, val, val);
	val = rd32(hw, N20_DMA_D_RX_CTRL_RING3_NO_DESC_AVG);
	dev_info(dev,
		 "\t(0x%08x) rx ctrl ring-3 no desc average\t: 0x%08x (%u)\n",
		 N20_DMA_D_RX_CTRL_RING3_NO_DESC_AVG, val, val);
	val = rd32(hw, N20_DMA_D_TX_AXI_RD_CMD_CNT);
	dev_info(dev, "\t(0x%08x) tx axi read cmd cnt\t\t: 0x%08x (%u)\n",
		 N20_DMA_D_TX_AXI_RD_CMD_CNT, val, val);
	val = rd32(hw, N20_DMA_D_TX_AXI_WR_CMD_CNT);
	dev_info(dev, "\t(0x%08x) tx axi write cmd cnt\t\t: 0x%08x (%u)\n",
		 N20_DMA_D_TX_AXI_WR_CMD_CNT, val, val);
	val = rd32(hw, N20_DMA_D_TX_AXI_RD_PKGS_CNT);
	dev_info(dev, "\t(0x%08x) tx axi read pkgs cnt\t\t: 0x%08x (%u)\n",
		 N20_DMA_D_TX_AXI_RD_PKGS_CNT, val, val);
	val = rd32(hw, N20_DMA_D_TX_AXI_WR_PKGS_CNT);
	dev_info(dev, "\t(0x%08x) tx axi write pkgs cnt\t\t: 0x%08x (%u)\n",
		 N20_DMA_D_TX_AXI_WR_PKGS_CNT, val, val);
	val = rd32(hw, N20_DMA_D_TX_AXI_RD_CMD_AVG);
	dev_info(dev, "\t(0x%08x) tx axi read cmd average\t\t: 0x%08x (%u)\n",
		 N20_DMA_D_TX_AXI_RD_CMD_AVG, val, val);
	val = rd32(hw, N20_DMA_D_TX_AXI_WR_CMD_AVG);
	dev_info(dev, "\t(0x%08x) tx axi write cmd average\t\t: 0x%08x (%u)\n",
		 N20_DMA_D_TX_AXI_WR_CMD_AVG, val, val);
	val = rd32(hw, N20_DMA_D_TX_AXI_RD_PKGS_AVG);
	dev_info(dev, "\t(0x%08x) tx axi read pkgs average\t\t: 0x%08x (%u)\n",
		 N20_DMA_D_TX_AXI_RD_PKGS_AVG, val, val);
	val = rd32(hw, N20_DMA_D_TX_AXI_WR_PKGS_AVG);
	dev_info(dev, "\t(0x%08x) tx axi write pkgs average\t\t: 0x%08x (%u)\n",
		 N20_DMA_D_TX_AXI_WR_PKGS_AVG, val, val);
	val = rd32(hw, N20_DMA_D_RX_AXI_RD_CMD_CNT);
	dev_info(dev, "\t(0x%08x) rx axi read cmd cnt\t\t: 0x%08x (%u)\n",
		 N20_DMA_D_RX_AXI_RD_CMD_CNT, val, val);
	val = rd32(hw, N20_DMA_D_RX_AXI_WR_CMD_CNT);
	dev_info(dev, "\t(0x%08x) rx axi write cmd cnt\t\t: 0x%08x (%u)\n",
		 N20_DMA_D_RX_AXI_WR_CMD_CNT, val, val);
	val = rd32(hw, N20_DMA_D_RX_AXI_RD_PKGS_CNT);
	dev_info(dev, "\t(0x%08x) rx axi read pkgs cnt\t\t: 0x%08x (%u)\n",
		 N20_DMA_D_RX_AXI_RD_PKGS_CNT, val, val);
	val = rd32(hw, N20_DMA_D_RX_AXI_WR_PKGS_CNT);
	dev_info(dev, "\t(0x%08x) rx axi write pkgs cnt\t\t: 0x%08x (%u)\n",
		 N20_DMA_D_RX_AXI_WR_PKGS_CNT, val, val);
	val = rd32(hw, N20_DMA_D_RX_AXI_RD_CMD_AVG);
	dev_info(dev, "\t(0x%08x) rx axi read cmd average\t\t: 0x%08x (%u)\n",
		 N20_DMA_D_RX_AXI_RD_CMD_AVG, val, val);
	val = rd32(hw, N20_DMA_D_RX_AXI_WR_CMD_AVG);
	dev_info(dev, "\t(0x%08x) rx axi write cmd average\t\t: 0x%08x (%u)\n",
		 N20_DMA_D_RX_AXI_WR_CMD_AVG, val, val);
	val = rd32(hw, N20_DMA_D_RX_AXI_RD_PKGS_AVG);
	dev_info(dev, "\t(0x%08x) rx axi read pkgs average\t\t: 0x%08x (%u)\n",
		 N20_DMA_D_RX_AXI_RD_PKGS_AVG, val, val);
	val = rd32(hw, N20_DMA_D_RX_AXI_WR_PKGS_AVG);
	dev_info(dev, "\t(0x%08x) rx axi write pkgs average\t\t: 0x%08x (%u)\n",
		 N20_DMA_D_RX_AXI_WR_PKGS_AVG, val, val);
	val = rd32(hw, N20_DMA_D_RX_IFIFO_PKGS_IN_CNT);
	dev_info(dev, "\t(0x%08x) rx ififo pkgs in cnt\t\t: 0x%08x (%u)\n",
		 N20_DMA_D_RX_IFIFO_PKGS_IN_CNT, val, val);
	val = rd32(hw, N20_DMA_D_RX_IFIFO_PKGS_OUT_CNT);
	dev_info(dev, "\t(0x%08x) rx ififo pkgs out cnt\t\t: 0x%08x (%u)\n",
		 N20_DMA_D_RX_IFIFO_PKGS_OUT_CNT, val, val);
	val = rd32(hw, N20_DMA_D_RX_OFIFO_PKGS_IN_CNT);
	dev_info(dev, "\t(0x%08x) rx ofifo pkgs in cnt\t\t: 0x%08x (%u)\n",
		 N20_DMA_D_RX_OFIFO_PKGS_IN_CNT, val, val);
	val = rd32(hw, N20_DMA_D_RX_OFIFO_PKGS_OUT_CNT);
	dev_info(dev, "\t(0x%08x) rx ofifo pkgs out cnt\t\t: 0x%08x (%u)\n",
		 N20_DMA_D_RX_OFIFO_PKGS_OUT_CNT, val, val);
	val = rd32(hw, N20_DMA_D_TX_RING0_INT_STATUS);
	dev_info(dev, "\t(0x%08x) tx int ring-0 irq status\t\t: 0x%08x\n",
		 N20_DMA_D_TX_RING0_INT_STATUS, val);
	val = rd32(hw, N20_DMA_D_TX_RING1_INT_STATUS);
	dev_info(dev, "\t(0x%08x) tx int ring-1 irq status\t\t: 0x%08x\n",
		 N20_DMA_D_TX_RING1_INT_STATUS, val);
	val = rd32(hw, N20_DMA_D_TX_RING2_INT_STATUS);
	dev_info(dev, "\t(0x%08x) tx int ring-2 irq status\t\t: 0x%08x\n",
		 N20_DMA_D_TX_RING2_INT_STATUS, val);
	val = rd32(hw, N20_DMA_D_TX_RING3_INT_STATUS);
	dev_info(dev, "\t(0x%08x) tx int ring-3 irq status\t\t: 0x%08x\n",
		 N20_DMA_D_TX_RING3_INT_STATUS, val);
	val = rd32(hw, N20_DMA_D_RX_RING0_INT_STATUS);
	dev_info(dev, "\t(0x%08x) rx int ring-0 irq status\t\t: 0x%08x\n",
		 N20_DMA_D_RX_RING0_INT_STATUS, val);
	val = rd32(hw, N20_DMA_D_RX_RING1_INT_STATUS);
	dev_info(dev, "\t(0x%08x) rx int ring-1 irq status\t\t: 0x%08x\n",
		 N20_DMA_D_RX_RING1_INT_STATUS, val);
	val = rd32(hw, N20_DMA_D_RX_RING2_INT_STATUS);
	dev_info(dev, "\t(0x%08x) rx int ring-2 irq status\t\t: 0x%08x\n",
		 N20_DMA_D_RX_RING2_INT_STATUS, val);
	val = rd32(hw, N20_DMA_D_RX_RING3_INT_STATUS);
	dev_info(dev, "\t(0x%08x) rx int ring-3 irq status\t\t: 0x%08x\n",
		 N20_DMA_D_RX_RING3_INT_STATUS, val);
}

static void n20_dump_mux_regs(struct mce_hw *hw)
{
	struct device *dev = hw->dev;
	u32 val = 0;

	dev_info(dev, "Debug - Dump mux Regs :\n");
	val = rd32(hw, N20_ETH_PORT0_RX_PKTS);
	dev_info(dev, "\t(0x%08x) rx port0 pkts\t\t\t: 0x%08x (%u)\n",
		 N20_ETH_PORT0_RX_PKTS, val, val);
	val = rd32(hw, N20_ETH_PORT1_RX_PKTS);
	dev_info(dev, "\t(0x%08x) rx port1 pkts\t\t\t: 0x%08x (%u)\n",
		 N20_ETH_PORT1_RX_PKTS, val, val);
}

static void n20_dump_parser_regs(struct mce_hw *hw)
{
	struct device *dev = hw->dev;
	u32 val = 0;

	dev_info(dev, "Debug - Dump parser Regs :\n");
	val = rd32(hw, N20_ETH_RX_PKTS_INGRESS);
	dev_info(dev, "\t(0x%08x) rx ingress pkts\t\t\t: 0x%08x (%u)\n",
		 N20_ETH_RX_PKTS_INGRESS, val, val);
	val = rd32(hw, N20_ETH_RX_PKTS_EGRESS);
	dev_info(dev, "\t(0x%08x) rx egress pkts\t\t\t: 0x%08x (%u)\n",
		 N20_ETH_RX_PKTS_EGRESS, val, val);
	val = rd32(hw, N20_ETH_RX_EXCEPT_SHORT);
	dev_info(dev, "\t(0x%08x) rx except short pkts\t\t: 0x%08x (%u)\n",
		 N20_ETH_RX_EXCEPT_SHORT, val, val);
	val = rd32(hw, N20_ETH_RX_INNER_SCTP);
	dev_info(dev, "\t(0x%08x) rx inner sctp pkts\t\t\t: 0x%08x (%u)\n",
		 N20_ETH_RX_INNER_SCTP, val, val);
	val = rd32(hw, N20_ETH_RX_INNER_TCPSYN);
	dev_info(dev, "\t(0x%08x) rx inner tcpsyn pkts\t\t: 0x%08x (%u)\n",
		 N20_ETH_RX_INNER_TCPSYN, val, val);
	val = rd32(hw, N20_ETH_RX_INNER_TCP);
	dev_info(dev, "\t(0x%08x) rx inner tcp pkts\t\t\t: 0x%08x (%u)\n",
		 N20_ETH_RX_INNER_TCP, val, val);
	val = rd32(hw, N20_ETH_RX_INNER_UDP);
	dev_info(dev, "\t(0x%08x) rx inner udp pkts\t\t\t: 0x%08x (%u)\n",
		 N20_ETH_RX_INNER_UDP, val, val);
}

static void n20_dump_fwd_proc_regs(struct mce_hw *hw)
{
	struct device *dev = hw->dev;
	u32 val = 0;

	dev_info(dev, "Debug - Dump fwd proc Regs :\n");
	val = rd32(hw, N20_ETH_RX_INGRESS_PKT_IN);
	dev_info(dev, "\t(0x%08x) rx ingress pkt in\t\t\t: 0x%08x (%u)\n",
		 N20_ETH_RX_INGRESS_PKT_IN, val, val);
	val = rd32(hw, N20_ETH_RX_INGRESS_PKT_DROP);
	dev_info(dev, "\t(0x%08x) rx egress pkt drop\t\t\t: 0x%08x (%u)\n",
		 N20_ETH_RX_INGRESS_PKT_DROP, val, val);
}

static void n20_dump_editor_regs(struct mce_hw *hw)
{
	struct device *dev = hw->dev;
	u32 val = 0;

	dev_info(dev, "Debug - Dump editor Regs :\n");
	val = rd32(hw, N20_ETH_RX_EDTUP_PKT_IN);
	dev_info(dev, "\t(0x%08x) rx edtup pkt in\t\t\t: 0x%08x (%u)\n",
		 N20_ETH_RX_EDTUP_PKT_IN, val, val);
	val = rd32(hw, N20_ETH_RX_EDTUP_PKT_OUT);
	dev_info(dev, "\t(0x%08x) rx edtup pkt out\t\t\t: 0x%08x (%u)\n",
		 N20_ETH_RX_EDTUP_PKT_OUT, val, val);
}

static void n20_dump_fwd_attr_regs(struct mce_hw *hw)
{
	struct device *dev = hw->dev;
	u32 val = 0;

	dev_info(dev, "Debug - Dump fwd attr Regs :\n");
	val = rd32(hw, N20_ETH_RX_ATTR_INGRESS_PKT_IN);
	dev_info(dev, "\t(0x%08x) rx attr ingress pkt in\t\t: 0x%08x (%u)\n",
		 N20_ETH_RX_ATTR_INGRESS_PKT_IN, val, val);
	val = rd32(hw, N20_ETH_RX_ATTR_EGRESS_PKT_OUT);
	dev_info(dev, "\t(0x%08x) rx attr egress pkt out\t\t: 0x%08x (%u)\n",
		 N20_ETH_RX_ATTR_EGRESS_PKT_OUT, val, val);
	val = rd32(hw, N20_ETH_RX_ATTR_EGRESS_PKT_DROP);
	dev_info(dev, "\t(0x%08x) rx attr egress pkt drop\t\t: 0x%08x (%u)\n",
		 N20_ETH_RX_ATTR_EGRESS_PKT_DROP, val, val);
}

static void n20_dump_opp_regs(struct mce_hw *hw)
{
	struct device *dev = hw->dev;
	u32 val = 0;

	dev_info(dev, "Debug - Dump opp Regs :\n");
	val = rd32(hw, N20_ETH_TSO_MAX_LEN);
	dev_info(dev, "\t(0x%08x) tso max len\t\t\t: 0x%08x (%u)\n",
		 N20_ETH_TSO_MAX_LEN, val, val);
	val = rd32(hw, N20_ETH_TX_DBG_INPUT_PKTS);
	dev_info(dev, "\t(0x%08x) tx debug input pkts\t\t: 0x%08x (%u)\n",
		 N20_ETH_TX_DBG_INPUT_PKTS, val, val);
	val = rd32(hw, N20_ETH_TX_DBG_OUTPUT_PKTS);
	dev_info(dev, "\t(0x%08x) tx debug output pkts\t\t: 0x%08x (%u)\n",
		 N20_ETH_TX_DBG_OUTPUT_PKTS, val, val);
	val = rd32(hw, N20_ETH_TX_DBG_STATE_STATUS);
	dev_info(dev, "\t(0x%08x) tx debug state status\t\t: 0x%08x (%u)\n",
		 N20_ETH_TX_DBG_STATE_STATUS, val, val);
}

static void __maybe_unused n20_dump_tc_regs(struct mce_hw *hw)
{
	struct mce_pf *pf = (struct mce_pf *)(hw->back);
	struct mce_ets_cfg *etscfg = NULL;
	struct mce_pfc_cfg *pfccfg = NULL;
	struct mce_vsi *vsi = pf->vsi[0];
	struct mce_tc_cfg *tccfg = NULL;
	int q_base = vsi->num_tc_offset;
	struct mce_dcb *dcb = pf->dcb;
	struct device *dev = hw->dev;
	int qg_base = 0;
	u8 i = 0;
	u8 j = 0;
	u8 k = 0;

	dev_info(dev, "Debug - tc state :\n");

	if (test_bit(MCE_DCB_EN, dcb->flags))
		dev_info(dev, "\tDCB is enabled dcbx mode is %u\n",
			 dcb->dcbx_cap);
	else
		dev_info(dev, "\tDCB is disabled dcbx mode is %u\n",
			 dcb->dcbx_cap);

	if (test_bit(MCE_DSCP_EN, dcb->flags))
		dev_info(dev, "\tDSCP is enabled\n");
	else
		dev_info(dev, "\tDSCP is disabled\n");

	for (i = 0; i < 8; i++) {
		dev_info(dev,
			 "\tdscp-%02u: %u, "
			 "dscp-%02u: %u, "
			 "dscp-%02u: %u, "
			 "dscp-%02u: %u, "
			 "dscp-%02u: %u, "
			 "dscp-%02u: %u, "
			 "dscp-%02u: %u, "
			 "dscp-%02u: %u\n",
			 ((i * 8) + 0), dcb->dscp_map[(i * 8) + 0],
			 ((i * 8) + 1), dcb->dscp_map[(i * 8) + 1],
			 ((i * 8) + 2), dcb->dscp_map[(i * 8) + 2],
			 ((i * 8) + 3), dcb->dscp_map[(i * 8) + 3],
			 ((i * 8) + 4), dcb->dscp_map[(i * 8) + 4],
			 ((i * 8) + 5), dcb->dscp_map[(i * 8) + 5],
			 ((i * 8) + 6), dcb->dscp_map[(i * 8) + 6],
			 ((i * 8) + 7), dcb->dscp_map[(i * 8) + 7]);
	}

	if (test_bit(MCE_PFC_EN, dcb->flags))
		dev_info(dev, "\tPFC is enabled\n");
	else
		dev_info(dev, "\tPFC is disabled\n");

	pfccfg = &dcb->cur_pfccfg;
	etscfg = &dcb->cur_etscfg;
	tccfg = &dcb->cur_tccfg;
	if (test_bit(MCE_ETS_EN, dcb->flags)) {
		for (j = 0; j < tccfg->ntc_cnt; j++) {
			dev_info(dev, "\t\t tc num %u\n", j);
			for (i = 0; i < MCE_MAX_PRIORITY; i++) {
				if ((tccfg->tc_prios_bit[j] & (1 << i)) ==
				    0)
					continue;
				if (pfccfg->pfcena & (1 << i))
					dev_info(dev,
						 "\t\t\tpriority:%u - pfc on\n",
						i);
				else
					dev_info(dev,
						 "\t\t\tpriority:%u - pfc off\n",
						i);
				dev_info(dev,
					 "\t\t\tpriority:%u - q_base %u, q_cnt %u\n",
					i,
					q_base * j +
						tccfg->pfc_txq_base[j][i],
					tccfg->pfc_txq_count[j][i]);
			}
		}
	} else {
		for (i = 0; i < MCE_MAX_PRIORITY; i++) {
			if (pfccfg->pfcena & (1 << i))
				dev_info(dev,
					 "\t\t\tpriority:%u - pfc on\n",
					 i);
			else
				dev_info(dev,
					 "\t\t\tpriority:%u - pfc off\n",
					 i);
			dev_info(dev,
				 "\t\t\tpriority:%u - q_base %u, q_cnt %u\n",
				i, tccfg->pfc_txq_base[0][i],
				tccfg->pfc_txq_count[0][i]);
		}
	}

	if (test_bit(MCE_ETS_EN, dcb->flags))
		dev_info(dev, "\tETS is enabled\n");
	else
		dev_info(dev, "\tETS is disabled\n");

	dev_info(dev, "\tthe number of TCS that ETS can use is %u\n",
		 etscfg->ets_cap);

	for (i = 0; i < IEEE_8021QAZ_MAX_TCS; i++) {
		char tsa[4];
		u8 t = 0;

		if ((!test_bit(i, etscfg->etc_state)) &&
		    test_bit(MCE_ETS_EN, dcb->flags))
			continue;

		switch (etscfg->tsatable[i]) {
		case IEEE_8021QAZ_TSA_ETS:
			strcpy(tsa, "ets");
			break;
		case IEEE_8021QAZ_TSA_STRICT:
			strcpy(tsa, "sp");
			break;
		default:
			strcpy(tsa, "xxx");
			break;
		}

		t = tccfg->etc_tc[i];

		dev_info(dev, "\tets-tc: %u hwtc: %u tsa: %s bw: %u\n", i,
			 t, tsa, etscfg->tcbwtable[i]);

		for (j = 0; j < MCE_MAX_PRIORITY; j++) {
			if (etscfg->prio_table[j] == i) {
				u8 nt = tccfg->prio_ntc[j];

				dev_info(dev,
					 "\t\tpriority: %u ntc: %u q_base: %-3u q_cnt: %u\n",
					 j, nt,
					 tccfg->ntc_txq_base[nt] +
						 nt * q_base,
					 tccfg->ntc_txq_cunt[nt]);
			}
		}

		if (!test_bit(i, etscfg->etc_state))
			continue;

		for (j = 0; j < tccfg->tc_qgs[t]; j++) {
			/*  */
			k = j + qg_base;
			dev_info(dev,
				 "\t\tqueue_group: %-3u "
				 "q_cnt: %-3u "
				 "minrate: %-3u(Mb) "
				 "maxrate: %-3u(Mb)\n",
				 k, tccfg->qg_qs[k], tccfg->min_rate[k],
				 tccfg->max_rate[k]);
		}
		qg_base += tccfg->tc_qgs[t];
	}
}

static void n20_dump_db_regs(struct mce_hw *hw)
{
	struct device *dev = hw->dev;
	u64 sum = 0;
	u32 val = 0;
	u32 i = 0;

	dev_info(dev, "Debug - db state :\n");

	val = rd32(hw, _ETH_F_(0x6510));
	dev_info(dev, "\tto txtrans pkt: 0x%-8x\t(%u)\n", val, val);

	val = rd32(hw, _ETH_F_(0x0474));
	MODIFY_BITFIELD(val, 2, 5, 24);
	wr32(hw, _ETH_F_(0x0474), val);
	val = rd32(hw, _ETH_F_(0x6554));
	dev_info(dev, "\trecv sop pkt cnt: 0x%-8x\t(%u)\n", val, val);

	val = rd32(hw, _ETH_F_(0x0474));
	MODIFY_BITFIELD(val, 3, 5, 24);
	wr32(hw, _ETH_F_(0x0474), val);
	val = rd32(hw, _ETH_F_(0x6554));
	dev_info(dev, "\trecv eop pkt cnt: 0x%-8x\t(%u)\n", val, val);

	for (i = 4; i < 12; i++) {
		val = rd32(hw, _ETH_F_(0x0474));
		MODIFY_BITFIELD(val, i, 5, 24);
		wr32(hw, _ETH_F_(0x0474), val);
		val = rd32(hw, _ETH_F_(0x6554));
		dev_info(dev, "\tsend pkt-%u cnt: 0x%-8x\t(%u)\n", (i - 4),
			 val, val);
		sum += val;
	}
	dev_info(dev, "\tsend pkt sum: 0x%-8llx\t(%llu)\n", sum, sum);

	for (i = 0; i < 5; i++) {
		dev_info(dev, "\ttso-%u\n", i);
		val = rd32(hw, _ETH_F_(0x80f8));
		MODIFY_BITFIELD(val, i, 4, 28);
		wr32(hw, _ETH_F_(0x80f8), val);
		val = rd32(hw, _ETH_F_(0x6500));
		dev_info(dev, "\t\ttso input h-pkt: 0x%-8x\t(%u)\n",
			 (val >> 16), (val >> 16));
		dev_info(dev, "\t\ttso input l-pkt: 0x%-8x\t(%u)\n",
			 (val & 0xffff), (val & 0xffff));
		dev_info(dev, "\t\ttso input  pkt: 0x%-8x\t(%u)\n", val,
			 val);
		val = rd32(hw, _ETH_F_(0x6504));
		dev_info(dev, "\t\ttso output pkt: 0x%-8x\t(%u)\n", val,
			 val);
		val = rd32(hw, _ETH_F_(0x6508));
		dev_info(dev, "\t\ttso state stat: 0x%-8x\t(%u)\n", val,
			 val);
	}
}

static u32 mce_switch_debug_cmd(struct mce_hw *hw, u32 cmd)
{
	u32 ctrl = 0;

	ctrl = rd32(hw, 0x88038);
	ctrl &= ~0x3ff0000;
	ctrl |= cmd;
	wr32(hw, 0x88038, ctrl);

	return 0;
}

static void n20_dump_switch_regs(struct mce_hw *hw)
{
	struct device *dev = hw->dev;
	int i = 0;

	mce_switch_debug_cmd(hw, 0 << 24);
	dev_info(dev, "switch eswitch[0] match 0x%.2x\n",
		 rd32(hw, 0x93900));
	mce_switch_debug_cmd(hw, 1 << 24);
	dev_info(dev, "switch eswitch[1] match 0x%.2x\n",
		 rd32(hw, 0x93900));
	mce_switch_debug_cmd(hw, 2 << 24);
	dev_info(dev, "switch eswitch[2] match 0x%.2x\n",
		 rd32(hw, 0x93900));
	mce_switch_debug_cmd(hw, 3 << 24);
	dev_info(dev, "switch eswitch[2] match 0x%.2x\n",
		 rd32(hw, 0x93900));

	for (i = 0; i < 16; i++) {
		mce_switch_debug_cmd(hw, i << 20);
		dev_info(dev, "switch legacy[%d] up match 0x%.2x\n", i,
			 rd32(hw, 0x93904));
	}
	for (i = 0; i < 16; i++) {
		mce_switch_debug_cmd(hw, i << 16);
		dev_info(dev, "switch legacy[%d] down match 0x%.2x\n", i,
			 rd32(hw, 0x93908));
	}
}

int n20_dump_debug_regs(struct mce_hw *hw, char *cmd)
{
	int ret = -1;

	if (!strncmp(cmd, "ring", 4) || !strncmp(cmd, "all", 3)) {
		n20_dump_rings_regs(hw);
		ret = 0;
	}

	if (!strncmp(cmd, "dma", 3) || !strncmp(cmd, "all", 3)) {
		n20_dump_dma_regs(hw);
		ret = 0;
	}

	if (!strncmp(cmd, "mux", 3) || !strncmp(cmd, "all", 3)) {
		n20_dump_mux_regs(hw);
		ret = 0;
	}

	if (!strncmp(cmd, "parser", 6) || !strncmp(cmd, "all", 3)) {
		n20_dump_parser_regs(hw);
		ret = 0;
	}

	if (!strncmp(cmd, "fwd_proc", 8) || !strncmp(cmd, "all", 3)) {
		n20_dump_fwd_proc_regs(hw);
		ret = 0;
	}

	if (!strncmp(cmd, "editor", 6) || !strncmp(cmd, "all", 3)) {
		n20_dump_editor_regs(hw);
		ret = 0;
	}

	if (!strncmp(cmd, "fwd_attr", 8) || !strncmp(cmd, "all", 3)) {
		n20_dump_fwd_attr_regs(hw);
		ret = 0;
	}

	if (!strncmp(cmd, "opp", 3) || !strncmp(cmd, "all", 3)) {
		n20_dump_opp_regs(hw);
		ret = 0;
	}

	if (!strncmp(cmd, "db", 2)) {
		n20_dump_db_regs(hw);
		ret = 0;
	}
	if (!strncmp(cmd, "switch", 6)) {
		n20_dump_switch_regs(hw);
		ret = 0;
	}

	return ret;
}
