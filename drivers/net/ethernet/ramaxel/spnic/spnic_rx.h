/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2021 Ramaxel Memory Technology, Ltd */

#ifndef SPNIC_RX_H
#define SPNIC_RX_H

#include <linux/types.h>

/*rx cqe checksum err*/
#define SPNIC_RX_CSUM_IP_CSUM_ERR	BIT(0)
#define SPNIC_RX_CSUM_TCP_CSUM_ERR	BIT(1)
#define SPNIC_RX_CSUM_UDP_CSUM_ERR	BIT(2)
#define SPNIC_RX_CSUM_IGMP_CSUM_ERR	BIT(3)
#define SPNIC_RX_CSUM_ICMPV4_CSUM_ERR	BIT(4)
#define SPNIC_RX_CSUM_ICMPV6_CSUM_ERR	BIT(5)
#define SPNIC_RX_CSUM_SCTP_CRC_ERR	BIT(6)
#define SPNIC_RX_CSUM_HW_CHECK_NONE	BIT(7)
#define SPNIC_RX_CSUM_IPSU_OTHER_ERR	BIT(8)

#define SPNIC_HEADER_DATA_UNIT 2

struct spnic_rxq_stats {
	u64	packets;
	u64	bytes;
	u64	errors;
	u64	csum_errors;
	u64	other_errors;
	u64	dropped;
	u64	xdp_dropped;
	u64	rx_buf_empty;

	u64	alloc_skb_err;
	u64	alloc_rx_buf_err;
	u64	xdp_large_pkt;
	struct u64_stats_sync		syncp;
};

struct spnic_rx_info {
	dma_addr_t		buf_dma_addr;

	struct spnic_rq_cqe	*cqe;
	dma_addr_t		cqe_dma;
	struct page		*page;
	u32			page_offset;
	struct spnic_rq_wqe	*rq_wqe;
	struct sk_buff		*saved_skb;
	u32			skb_len;
};

struct spnic_rxq {
	struct net_device	*netdev;

	u16			q_id;
	u32			q_depth;
	u32			q_mask;

	u16			buf_len;
	u32			rx_buff_shift;
	u32			dma_rx_buff_size;

	struct spnic_rxq_stats	rxq_stats;
	u32			cons_idx;
	u32			delta;

	u32			irq_id;
	u16			msix_entry_idx;

	struct spnic_rx_info	*rx_info;
	struct spnic_io_queue	*rq;
	struct bpf_prog		*xdp_prog;

	struct spnic_irq	*irq_cfg;
	u16			next_to_alloc;
	u16			next_to_update;
	struct device		*dev;		/* device for DMA mapping */

	unsigned long		status;
	dma_addr_t		cqe_start_paddr;
	void			*cqe_start_vaddr;

	u64			last_moder_packets;
	u64			last_moder_bytes;
	u8			last_coalesc_timer_cfg;
	u8			last_pending_limt;
} ____cacheline_aligned;

struct spnic_dyna_rxq_res {
	u16			next_to_alloc;
	struct spnic_rx_info	*rx_info;
	dma_addr_t		cqe_start_paddr;
	void			*cqe_start_vaddr;
};

int spnic_alloc_rxqs(struct net_device *netdev);

void spnic_free_rxqs(struct net_device *netdev);

int spnic_alloc_rxqs_res(struct spnic_nic_dev *nic_dev, u16 num_rq,
			 u32 rq_depth, struct spnic_dyna_rxq_res *rxqs_res);

void spnic_free_rxqs_res(struct spnic_nic_dev *nic_dev, u16 num_rq,
			 u32 rq_depth, struct spnic_dyna_rxq_res *rxqs_res);

int spnic_configure_rxqs(struct spnic_nic_dev *nic_dev, u16 num_rq,
			 u32 rq_depth, struct spnic_dyna_rxq_res *rxqs_res);

int spnic_rx_configure(struct net_device *netdev);

void spnic_rx_remove_configure(struct net_device *netdev);

int spnic_rx_poll(struct spnic_rxq *rxq, int budget);
int stub_spnic_rx_poll(struct spnic_rxq *rxq, int budget);

void spnic_rxq_get_stats(struct spnic_rxq *rxq, struct spnic_rxq_stats *stats);

void spnic_rxq_clean_stats(struct spnic_rxq_stats *rxq_stats);

#endif
