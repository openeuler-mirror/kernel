/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __YS_K2_CORE_H__
#define __YS_K2_CORE_H__

#include "../platform/ys_auxiliary.h"
#include "../platform/ys_intr.h"
#include "../platform/ys_ndev.h"
#include "../platform/ys_pdev.h"
#include "ys_adapter.h"
#include "ys_debug.h"
#include "ys_reg_ops.h"
#include "ys_k2_hw.h"

/* chmode_0 bit field */
#define CHMODE0_MODE(val)				((val) << 0)
#define CHMODE0_TXSWRST(val)				((val) << 6)
#define CHMODE0_RXSWRST(val)				((val) << 7)
#define CHMODE0_TXEN(val)				((val) << 8)
#define CHMODE0_TXDRAIN(val)				((val) << 9)
#define CHMODE0_RXEN(val)				((val) << 10)
#define CHMODE0_GMIILPBK(val)				((val) << 11)
#define CHMODE0_TXJABBER(val)				((val) << 12)

#define CHMODE0_RXJABBER(val)				((val) << 0)
#define CHMODE0_DISFCS(val)				((val) << 12)
#define CHMODE0_INVFCS(val)				((val) << 13)
#define CHMODE0_IGNFCS(val)				((val) << 14)
#define CHMODE0_STRIPFCS(val)				((val) << 15)
#define CHMODE0_IFGLEN(val)				((val) << 16)
#define CHMODE0_IFGPACING(val)			((val) << 24)

#define CHMODE0_CFG0_L	(CHMODE0_MODE(0x15) | CHMODE0_TXSWRST(0x1) | \
		CHMODE0_RXSWRST(0x1) | CHMODE0_TXEN(0x1) | \
		CHMODE0_TXDRAIN(0x0) | CHMODE0_RXEN(0x1) | \
		CHMODE0_GMIILPBK(0x0) | CHMODE0_TXJABBER(0x640))
#define CHMODE0_CFG0_H	(CHMODE0_RXJABBER(0x64) | \
		CHMODE0_DISFCS(0x0) | CHMODE0_INVFCS(0x0) | \
		CHMODE0_IGNFCS(0x0) | CHMODE0_STRIPFCS(0x0) | \
		CHMODE0_IFGLEN(0xC) | CHMODE0_IFGPACING(0x1))

#define CHMODE0_CFG1_L	(CHMODE0_MODE(0x15) | \
		CHMODE0_TXSWRST(0x0) | CHMODE0_RXSWRST(0x0) | \
		CHMODE0_TXEN(0x1) | CHMODE0_TXDRAIN(0x0) | \
		CHMODE0_RXEN(0x1) | CHMODE0_GMIILPBK(0x0) | \
		CHMODE0_TXJABBER(0x3640))
#define CHMODE0_CFG1_H	(CHMODE0_RXJABBER(0x364) | \
		CHMODE0_DISFCS(0x0) | CHMODE0_INVFCS(0x0) | \
		CHMODE0_IGNFCS(0x0) | CHMODE0_STRIPFCS(0x1) | \
		CHMODE0_IFGLEN(0xC) | CHMODE0_IFGPACING(0x1))

/* maccfg_0 bit field */
#define MACCFG0_DISFCSONERR(val)			((val) << 5)
#define MACCFG0_TXFCEN(val)				((val) << 8)
#define MACCFG0_RXFCEN(val)				((val) << 10)
#define MACCFG0_RXPFCEN(val)				((val) << 11)
#define MACCFG0_RXFCTOTX(val)				((val) << 12)
#define MACCFG0_RXFILTERFC(val)			((val) << 13)
#define MACCFG0_RXFILTERPFC(val)			((val) << 14)
#define MACCFG0_TXPADRUNT(val)			((val) << 15)
#define MACCFG0_TXRDTHRESH(val)			((val) << 23)

#define MACCFG0_TXLFAULT(val)				((val) << 7)
#define MACCFG0_TXRFAULT(val)				((val) << 8)
#define MACCFG0_TXIDLE(val)				((val) << 9)
#define MACCFG0_RXLFAULT(val)				((val) << 18)
#define MACCFG0_RXRFAULT(val)				((val) << 19)
#define MACCFG0_RXIDLE(val)				((val) << 20)
#define MACCFG0_TXSTRICTFAULT(val)			((val) << 21)
#define MACCFG0_STATSCLR(val)				((val) << 22)
#define MACCFG0_TXIGNORERX(val)			((val) << 23)
#define MACCFG0_TXPFCEN(val)				((val) << 24)

#define MACCFG0_CFG_L	(MACCFG0_DISFCSONERR(0x1) | \
		MACCFG0_TXFCEN(0x0) | MACCFG0_RXFCEN(0x0) | \
		MACCFG0_RXPFCEN(0x0) | MACCFG0_RXFCTOTX(0x0) | \
		MACCFG0_RXFILTERFC(0x0) | MACCFG0_RXFILTERPFC(0x0) | \
		MACCFG0_TXPADRUNT(0x40) | MACCFG0_TXRDTHRESH(0x2))
#define MACCFG0_CFG_H	(MACCFG0_TXLFAULT(0x0) | MACCFG0_TXRFAULT(0x0) | \
		MACCFG0_TXIDLE(0x80) | MACCFG0_RXLFAULT(0x0) | \
		MACCFG0_RXRFAULT(0x0) | MACCFG0_RXIDLE(0x0) | \
		MACCFG0_TXSTRICTFAULT(0x0) | MACCFG0_STATSCLR(0x0) | \
		MACCFG0_TXIGNORERX(0x0) | MACCFG0_TXPFCEN(0x0))

/* chconfig3_0 bit field */
#define CHCONFIG3_0_IFG0B(val)			((val) << 0)
#define CHCONFIG3_0_COUNTERRVLAN(val)			((val) << 1)
#define CHCONFIG3_0_RXMAXFRMSIZE(val)			((val) << 16)

#define CHCONFIG3_0_TXPREAMBLE(val)			((val) << 0)
#define CHCONFIG3_0_TXDRAINONFAULT(val)		((val) << 5)
#define CHCONFIG3_0_RXERRMASK(val)			((val) << 7)
#define CHCONFIG3_0_SJSIZE(val)			((val) << 12)
#define CHCONFIG3_0_TXREPCRCOVRD(val)			((val) << 24)
#define CHCONFIG3_0_EXCLPFCGLBLSTATS(val)		((val) << 25)
#define CHCONFIG3_0_CLRSTATSONSWRST(val)		((val) << 26)
#define CHCONFIG3_0_ALWAYSFILTERFC(val)		((val) << 27)

#define CHCONFIG3_0_CFG_L	(CHCONFIG3_0_IFG0B(0x0) | \
		CHCONFIG3_0_COUNTERRVLAN(0x0) | CHCONFIG3_0_RXMAXFRMSIZE(0x5ee))
#define CHCONFIG3_0_CFG_H	(CHCONFIG3_0_TXPREAMBLE(0x8) | \
		CHCONFIG3_0_TXDRAINONFAULT(0x0) | CHCONFIG3_0_RXERRMASK(0x0) | \
		CHCONFIG3_0_SJSIZE(0x0) | CHCONFIG3_0_TXREPCRCOVRD(0x0) | \
		CHCONFIG3_0_EXCLPFCGLBLSTATS(0x0) | \
		CHCONFIG3_0_CLRSTATSONSWRST(0x0) | \
		CHCONFIG3_0_ALWAYSFILTERFC(0x1))

/* chconfig4_0 bit field */
#define CHCONFIG4_0_MACADDR_L(val)			((val) << 0)

#define CHCONFIG4_0_MACADDR_H(val)			((val) << 0)
#define CHCONFIG4_0_PAUSEONTIME(val)			((val) << 16)

#define CHCONFIG4_0_CFG_L	(CHCONFIG4_0_MACADDR_L(0x04030201))
#define CHCONFIG4_0_CFG_H	(CHCONFIG4_0_MACADDR_H(0x605) | \
		CHCONFIG4_0_PAUSEONTIME(0xffff))

/* chconfig8_0 bit field */
#define CHCONFIG8_0_VLANTAG1(val)			((val) << 0)
#define CHCONFIG8_0_VLANTAG2(val)			((val) << 16)

#define CHCONFIG8_0_VLANTAG3(val)			((val) << 0)
#define CHCONFIG8_0_MAXVLANCNT(val)			((val) << 16)
#define CHCONFIG8_0_USCLKCNT(val)			((val) << 18)

#define CHCONFIG8_0_CFG_L	(CHCONFIG8_0_VLANTAG1(0x8100) | \
		CHCONFIG8_0_VLANTAG2(0x8100))
#define CHCONFIG8_0_CFG_H	(CHCONFIG8_0_VLANTAG3(0x8100) | \
		CHCONFIG8_0_MAXVLANCNT(0x0) | CHCONFIG8_0_USCLKCNT(0x339))

/* txfifocfg_0 bit field */
#define TXFIFOCFG_0_TXWRTHRESH(val)			((val) << 0)
#define TXFIFOCFG_0_RESERVED(val)			((val) << 0)

#define TXFIFOCFG_0_CFG_L	TXFIFOCFG_0_TXWRTHRESH(0x0001000a)
#define TXFIFOCFG_0_CFG_H	TXFIFOCFG_0_RESERVED(0x00000000)

/* pcstxoverride1 bit field */
#define PCSTXOVERRIDE1_CFG_L	(0x600322c0)
#define PCSTXOVERRIDE1_CFG_H	(0x0000005a)

/* pcsrxoverride0_0 bit field */
#define PCSRXOVERRIDE0_0_RXOVERRIDE_L(val)		((val) << 0)
#define PCSRXOVERRIDE0_0_RXOVERRIDE_H(val)		((val) << 0)

#define PCSRXOVERRIDE0_0_CFG_L	PCSRXOVERRIDE0_0_RXOVERRIDE_L(0x7F010663)
#define PCSRXOVERRIDE0_0_CFG_H	PCSRXOVERRIDE0_0_RXOVERRIDE_H(0x0007F480)

/* chconfig31_0 bit field */
#define CHCONFIG31_0_MACOVERRIDE_L(val)		((val) << 0)
#define CHCONFIG31_0_MACOVERRIDE_H(val)		((val) << 0)

#define CHCONFIG31_0_CFG_L	CHCONFIG31_0_MACOVERRIDE_L(0x6000007f)
#define CHCONFIG31_0_CFG_H	CHCONFIG31_0_MACOVERRIDE_H(0x00000002)

#define MAC_OFFSET(i) (((i) == 0) ? 0x6000000 : 0x6080000)
/* chmode_0 registers */
#define MAC_CHMODE0_L(i) (MAC_OFFSET(i) + 0x0000)
#define MAC_CHMODE0_H(i) (MAC_OFFSET(i) + 0x0004)

/* maccfg_0 registers */
#define MAC_MACCFG0_L(i) (MAC_OFFSET(i) + 0x0008)
#define MAC_MACCFG0_H(i) (MAC_OFFSET(i) + 0x000C)

/* chsts_0 registers */
#define MAC_CHSTS_0_L(i) (MAC_OFFSET(i) + 0x0010)
#define MAC_CHSTS_0_H(i) (MAC_OFFSET(i) + 0x0014)

/* chconfig3_0 registers */
#define MAC_CHCONFIG3_0_L(i) (MAC_OFFSET(i) + 0x0018)
#define MAC_CHCONFIG3_0_H(i) (MAC_OFFSET(i) + 0x001C)

/* chconfig4_0 registers */
#define MAC_CHCONFIG4_0_L(i) (MAC_OFFSET(i) + 0x0020)
#define MAC_CHCONFIG4_0_H(i) (MAC_OFFSET(i) + 0x0024)

/* chconfig8_0 registers */
#define MAC_CHCONFIG8_0_L(i) (MAC_OFFSET(i) + 0x0040)
#define MAC_CHCONFIG8_0_H(i) (MAC_OFFSET(i) + 0x0044)

/* txfifocfg_0 registers */
#define MAC_TXFIFOCFG_0_L(i) (MAC_OFFSET(i) + 0x00C0)
#define MAC_TXFIFOCFG_0_H(i) (MAC_OFFSET(i) + 0x00C4)

/* pcstxoverride1 registers */
#define MAC_PCSTXOVERRIDE1_L(i) (MAC_OFFSET(i) + 0x00C8)
#define MAC_PCSTXOVERRIDE1_H(i) (MAC_OFFSET(i) + 0x00CC)

/* pcsrxoverride0_0 registers */
#define MAC_PCSRXOVERRIDE0_0_L(i) (MAC_OFFSET(i) + 0x00E0)
#define MAC_PCSRXOVERRIDE0_0_H(i) (MAC_OFFSET(i) + 0x00E4)

/* chconfig31_0 registers */
#define MAC_CHCONFIG31_0_L(i) (MAC_OFFSET(i) + 0x00F8)
#define MAC_CHCONFIG31_0_H(i) (MAC_OFFSET(i) + 0x00FC)

/*  big endian converte registers */
#define MAC_BIGENDIAN_CONVERTE(i) (MAC_OFFSET(i) + 0x8018)

#define YSK2_DEFAULT_FRAGS 4
#define YSK2_DEFAULT_Q_CNT 4

/* mac only used inner-hardware */
#define YSK2_PORTID_IS_MAC BIT(31)
#define YSK2_PORTID_MACID GENMASK(27, 24)

#define YSK2_PORTID_PASSTHROUGH BIT(30)
#define YSK2_PORTID_IS_SOCREP BIT(29)
#define YSK2_PORTID_IS_SOC BIT(28)
#define YSK2_PORTID_PFID GENMASK(27, 24)
/* PF:		vfid = 0
 * VFn:		vfid = n + 1
 * soc uplink:	vfid = 0xfff
 */
#define YSK2_PORTID_VFID GENMASK(23, 12)
#define YSK2_SOC_UPLINK_VFID 0xfff

/* PF:		sfid = 0
 * VF:		sfid = 0
 * SFn:		sfid = n + 1
 *
 * vf_id and pf_id do not use the same field, if there is need for vf
 * growing sf?
 *
 * if no. vf_sf_id[0:15] pf_id[16:23] uplink_vf=0xffff
 */
#define YSK2_PORTID_SFID GENMASK(11, 0)

struct ysk2_nic {
	struct device *dev;
	struct pci_dev *pdev;

	/* Unique qid/vfid base, hardware use absolute value. May removed in
	 * the future.
	 */
	u16 hw_qbase;
	/* valid only for pf with sriov */
	u16 vfbase;

	/* mmio register base */
	void __iomem *hw_addr;
};

/* each port have unique id for hardware forward
 * For example, host pf0 grow sf0 and vf0, soc pf0 grow sf0 and sfn.
 *
 * Soc pf0 structure as follows:
 *	k2nic ------- k2port (p0 0x50fff000)
 *		|
 *		|
 *		|	(struct ys_rep without device)
 *		---- rep_list ------- pf_rep ---- k2port (pf0hpf 0x50000000)
 *		|	|
 *		|	---- vf0_rep ---- k2port (pf0vf0 0x50001000)
 *		|	|
 *		|	---- sf0_rep ---- k2port (en6f0c1pf0sf2 0x50000001)
 *		|	|
 *		|	---- s_sf0_rep ---- k2port (en6f0pf0sf0 0x70000001)
 *		|	|
 *		|	---- s_sfn_rep ---- k2port (en6f0pf0sfn 0x70000nnn)
 *		|
 *		|
 *		|	(sfdev->dev.parnet = &pdev->dev)
 *		---- sfdev_list ----- sfdev_0
 *		|
 *		---- sfdev_n
 *
 *
 * Soc sfn structure as follows:
 *	sfdev ------- k2port (enp6s0f0sn 0x10000nnn)
 *
 * Host pf0 structure as follows:
 *	k2nic ------- k2port (enp1s0f0 0x00000000)
 *		|
 *		|	(sfdev->dev.parnet = &pdev->dev)
 *		---- sfdev_list ---- sfdev_0
 *
 * Host sf0 structure as follows:
 *	sfdev ------- k2port (enp1s0f0s0 0x00000001)
 *
 * Host vf0 structure as follows:
 *	k2nic ------- k2port (enp1s0f0v0 0x00001000)
 *
 */
struct ysk2_port {
	struct device *dev;
	union {
		struct pci_dev *pdev;
		struct ys_adev *sfdev;
	};
	struct net_device *ndev;
	struct ysk2_nic *k2nic;

	/* ndev_priv->qbase = k2port->k2nic->hw_qbase + k2port->qbase
	 *
	 * For example:
	 *      pf1 owns queue 512-1023, k2nic->hw_qbase = 512;
	 *      pf1sf0 use the second 64 queues, k2port->qbase = 64;
	 *      so pf1sf0->ndev_priv->qbase = 576;
	 *
	 * Because ndev_priv->qbase may be used for other modules such as lan.
	 * if absolute offset is not more needed in the future,
	 * ndev_priv->qbase will be equal with k2port->qbase.
	 */
	u16 qbase;
	u32 port_id;

	/* ysk2 rings */
	struct ysk2_qp *qps;
};

struct ysk2_frag {
	dma_addr_t dma_addr;
	u32 len;
};

struct ysk2_tx_info {
	struct sk_buff *skb;
	dma_addr_t dma_addr;
	u32 len;
	u8 ts_requested;
	u8 frag_count;
	struct ysk2_frag frags[YSK2_MAX_FRAGS - 1];
};

struct ysk2_rx_info {
	struct page *page;
	u32 page_order;
	u32 page_offset;
	dma_addr_t dma_addr;
	u32 len;
};

struct ysk2_ring {
	u32 head_ptr;
	u32 tail_ptr;
	/* valid for desc ring, sw producer */
	u32 clean_tail_ptr;

	/* qid = ndev->qid + ndev_priv->qbase */
	u32 qid;
	u32 active : 1;

	/* ring parameters */
	u32 size;
	u32 size_mask;
	u32 stride;

	/* descripter ring buffer for hw */
	void *buf;
	dma_addr_t buf_dma_addr;

	/* mmio register base */
	void __iomem *hw_addr;

	struct ysk2_port *k2port;
} ____cacheline_aligned_in_smp;

/* software check whether is the rx/tx desc ring empty or not */
static inline bool ysk2_is_ring_empty(const struct ysk2_ring *ring)
{
	return ring->head_ptr == ring->clean_tail_ptr;
}

/* software check whether is the rx/tx desc ring full or not */
static inline bool ysk2_is_ring_full(const struct ysk2_ring *ring)
{
	return ring->head_ptr - ring->clean_tail_ptr >= ring->size;
}

/* software read cq/eq producer head pointer */
static inline void ysk2_read_head_ptr(struct ysk2_ring *ring)
{
	ring->head_ptr += ((ys_rd32(ring->hw_addr, YSK2_QUEUE_HEAD_PTR) -
			    ring->head_ptr) &
			   YSK2_RING_PTR_MASK);
	/* ensure cq/eq content is read after hardware head update */
	dma_rmb();
}

/* software read rx/tx consumer tail pointer */
static inline void ysk2_read_tail_ptr(struct ysk2_ring *ring)
{
	ring->tail_ptr += ((ys_rd32(ring->hw_addr, YSK2_QUEUE_TAIL_PTR) -
			    ring->tail_ptr) &
			   YSK2_RING_PTR_MASK);
}

/* software write rx/tx producer head pointer */
static inline void ysk2_write_head_ptr(struct ysk2_ring *ring)
{
	/* ensure desc are visible to device before updating doorbell record.
	 * NOTE: if the device is not dma-coherent, wmb() should be
	 * used for arm arch
	 */
	dma_wmb();
	ys_wr32(ring->hw_addr, YSK2_QUEUE_HEAD_PTR,
		ring->head_ptr & YSK2_RING_PTR_MASK);
}

/* software write cq/eq consumer tail pointer */
static inline void ysk2_write_tail_ptr(struct ysk2_ring *ring)
{
	ys_wr32(ring->hw_addr, YSK2_QUEUE_TAIL_PTR,
		ring->tail_ptr & YSK2_RING_PTR_MASK);
}

/* enable cq/eq interrupt */
static inline void ysk2_arm_ring_irq(struct ysk2_ring *ring)
{
	if (!ring->active)
		return;

	ys_wr32(ring->hw_addr, YSK2_QUEUE_TARGET_QUEUE_INDEX,
		YSK2_QUEUE_ARM_IRQ_MASK | ring->qid);
}

/* disenable cq/eq interrupt */
static inline void ysk2_unarm_ring_irq(struct ysk2_ring *ring)
{
	if (!ring->active)
		return;

	ys_wr32(ring->hw_addr, YSK2_QUEUE_TARGET_QUEUE_INDEX, ring->qid);
}

static inline int ysk2_alloc_ring(struct ysk2_ring *ring, u32 size, u32 stride)
{
	struct ysk2_port *k2port = ring->k2port;
	struct ys_ndev_priv *ndev_priv = netdev_priv(k2port->ndev);

	/* size must be whole power of 2 */
	ring->size = roundup_pow_of_two(size);
	ring->size_mask = ring->size - 1;
	ring->stride = roundup_pow_of_two(stride);
	/* alloc event dma buffer */
	ring->buf = dma_alloc_coherent(&ndev_priv->pdev->dev,
				       ring->stride * ring->size,
				       &ring->buf_dma_addr, GFP_KERNEL);
	if (!ring->buf)
		return -ENOMEM;

	/* realloc ring need reset pointer */
	ring->head_ptr = 0;
	ring->tail_ptr = 0;
	ring->clean_tail_ptr = 0;

	return 0;
}

static inline void ysk2_free_ring(struct ysk2_ring *ring)
{
	struct ysk2_port *k2port = ring->k2port;
	struct ys_ndev_priv *ndev_priv = netdev_priv(k2port->ndev);

	dma_free_coherent(&ndev_priv->pdev->dev, ring->stride * ring->size,
			  ring->buf, ring->buf_dma_addr);
	ring->buf = NULL;
	ring->buf_dma_addr = 0;
}

static inline int ysk2_activate_ring(struct ysk2_ring *ring, bool is_txring)
{
	u64 dma_addr;
	u32 val;

	/* deactivate queue */
	ys_wr32(ring->hw_addr, YSK2_QUEUE_ACTIVE_LOG_SIZE, 0);
	/* set base address */
	dma_addr = ring->buf_dma_addr;
	ys_wr32(ring->hw_addr, YSK2_QUEUE_BASE_ADDR_LOW,
		(u32)dma_addr);
	ys_wr32(ring->hw_addr, YSK2_QUEUE_BASE_ADDR_HIGH,
		(u32)(dma_addr >> 32));
	/* set target queue index */
	ys_wr32(ring->hw_addr, YSK2_QUEUE_TARGET_QUEUE_INDEX, ring->qid);
	/* set pointers */
	ys_wr32(ring->hw_addr, YSK2_QUEUE_HEAD_PTR,
		ring->head_ptr & YSK2_RING_PTR_MASK);
	ys_wr32(ring->hw_addr, YSK2_QUEUE_TAIL_PTR,
		ring->tail_ptr & YSK2_RING_PTR_MASK);

	/* set size and activate queue */
	val = FIELD_PREP(YSK2_QUEUE_LOG_QUEUE_SIZE_MASK, ilog2(ring->size)) |
	      FIELD_PREP(YSK2_QUEUE_ACTIVE_MASK, 1);
	/* block_size is only valid on tx queue for sgdma */
	if (is_txring)
		val |= FIELD_PREP(YSK2_QUEUE_LOG_BLOCK_SIZE_MASK,
				  ilog2(ring->stride / YSK2_DESC_SIZE));

	ys_wr32(ring->hw_addr, YSK2_QUEUE_ACTIVE_LOG_SIZE, val);

	ring->active = 1;

	return 0;
}

static inline void ysk2_deactivate_ring(struct ysk2_ring *ring)
{
	/* deactivate queue */
	ys_wr32(ring->hw_addr, YSK2_QUEUE_ACTIVE_LOG_SIZE, 0);

	ring->active = 0;
}

/* RX/TX desc ring */
struct ysk2_desc_ring {
	/* head ptr for producer(sw). written on enqueue (i.e. start_xmit)
	 * tail ptr for consumer(hw). written from completion
	 * Generally, head_ptr(sw) > tail_ptr(hw) > clean_tail_ptr(sw)
	 */
	struct ysk2_ring ring;

	/* transmission statistics */
	u64 bytes;
	u64 packets;
	u64 dropped_packets;

	/* packet buffer info for skb */
	u32 is_txring : 1;
	union {
		struct {
			struct ysk2_tx_info *tx_info;
			struct netdev_queue *tx_queue;
			u32 tx_max_sg_frags;
		};
		struct {
			struct ysk2_rx_info *rx_info;
			u32 page_order;
		};
	};
};

struct ysk2_cq_ring {
	/* head ptr for producer(hw). written from completion
	 * tail ptr for consumer(sw). written on dequeue
	 */
	struct ysk2_ring ring;
	struct napi_struct napi;
	struct ysk2_desc_ring *src_ring;
	void (*handler)(struct ysk2_cq_ring *ring);
};

struct ysk2_eq_ring {
	/* head ptr for producer(hw). written from completion
	 * tail ptr for consumer(sw). written on dequeue
	 */
	struct ysk2_ring ring;
};

struct ysk2_qp {
	struct ysk2_desc_ring *tx_ring;
	struct ysk2_cq_ring *tx_cpl_ring;
	struct ysk2_desc_ring *rx_ring;
	struct ysk2_cq_ring *rx_cpl_ring;
	struct ysk2_eq_ring *event_ring;
};

int ysk2_pdev_init(struct ys_pdev_priv *pdev_priv);
void ysk2_pdev_uninit(struct ys_pdev_priv *pdev_priv);

/* ysk2_eq.c */
int ysk2_create_eq_ring(struct ysk2_port *k2port, u32 index, u32 size);
void ysk2_destroy_eq_ring(struct ysk2_eq_ring **ring_ptr);
void ysk2_process_eq(struct ysk2_eq_ring *eq_ring);

/* ysk2_cq.c */
int ysk2_create_txcq_ring(struct ysk2_port *k2port, u32 index, u32 size);
int ysk2_create_rxcq_ring(struct ysk2_port *k2port, u32 index, u32 size);
void ysk2_destroy_cq_ring(struct ysk2_cq_ring **ring_ptr);
void ysk2_cq_irq_handler(struct ysk2_cq_ring *cq_ring);
int ysk2_napi_poll_cq(struct napi_struct *napi, int napi_budget);

/* ysk2_tx.c */
int ysk2_create_tx_ring(struct ysk2_port *k2port, u32 index, u32 size,
			u8 max_frags);
void ysk2_destroy_tx_ring(struct ysk2_desc_ring **ring_ptr);
netdev_tx_t ysk2_start_xmit(struct sk_buff *skb, struct net_device *ndev);
int ysk2_free_tx_buf(struct ysk2_desc_ring *ring);
int ysk2_process_tx_cq(struct ysk2_cq_ring *cq_ring, int napi_budget);

/* ysk2_rx.c */
int ysk2_create_rx_ring(struct ysk2_port *k2port, u32 index, u32 size);
void ysk2_destroy_rx_ring(struct ysk2_desc_ring **ring_ptr);
int ysk2_init_rx_buf(struct ysk2_desc_ring *ring);
int ysk2_free_rx_buf(struct ysk2_desc_ring *ring);
int ysk2_process_rx_cq(struct ysk2_cq_ring *cq_ring, int napi_budget);

#endif /*__YS_K2_CORE_H__*/
