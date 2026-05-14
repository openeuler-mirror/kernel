// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved.
 *
 */

#define dev_fmt(fmt) "unic: (pid %d) " fmt, current->pid

#include <linux/etherdevice.h>
#include <linux/jiffies.h>
#include <linux/limits.h>
#include <net/page_pool/helpers.h>
#if IS_ENABLED(CONFIG_UB_UNIC_UBL)
#include <net/ub/ubl.h>
#endif
#include <ub/ubase/ubase_comm_mbx.h>

#include "unic_dev.h"
#include "unic_trace.h"
#include "unic_rx.h"

#define UNIC_RX_HEAD_SIZE	256
#define UNIC_RQ_CI_REVERSE	(USHRT_MAX + 1)

#define UNIC_RX_PTYPE_ENTRY(ptype, csum_level, ip_summed, l3type, hash_type) \
	{ ptype, csum_level, CHECKSUM_##ip_summed, UNIC_L3_TYPE_##l3type, \
	  1, hash_type, 0 }

#define UNIC_RX_PTYPE_UNUSED_ENTRY(ptype) \
	{ ptype, 0, CHECKSUM_NONE, UNIC_L3_TYPE_RESV, \
	  0, PKT_HASH_TYPE_NONE, 0 }

static const struct unic_rx_ptype unic_rx_ptype_tbl[] = {
	UNIC_RX_PTYPE_UNUSED_ENTRY(0),
	UNIC_RX_PTYPE_ENTRY(1, 0, NONE, ARP, PKT_HASH_TYPE_NONE),
	UNIC_RX_PTYPE_ENTRY(2, 0, NONE, RARP, PKT_HASH_TYPE_NONE),
	UNIC_RX_PTYPE_ENTRY(3, 0, NONE, LLDP, PKT_HASH_TYPE_NONE),
	UNIC_RX_PTYPE_ENTRY(4, 0, NONE, STP, PKT_HASH_TYPE_NONE),
	UNIC_RX_PTYPE_ENTRY(5, 0, NONE, MAC_PAUSE, PKT_HASH_TYPE_NONE),
	UNIC_RX_PTYPE_ENTRY(6, 0, NONE, PFC_PAUSE, PKT_HASH_TYPE_NONE),
	UNIC_RX_PTYPE_ENTRY(7, 0, NONE, CNM, PKT_HASH_TYPE_NONE),
	UNIC_RX_PTYPE_ENTRY(8, 0, NONE, PTP, PKT_HASH_TYPE_NONE),
	UNIC_RX_PTYPE_UNUSED_ENTRY(9),
	UNIC_RX_PTYPE_UNUSED_ENTRY(10),
	UNIC_RX_PTYPE_UNUSED_ENTRY(11),
	UNIC_RX_PTYPE_UNUSED_ENTRY(12),
	UNIC_RX_PTYPE_UNUSED_ENTRY(13),
	UNIC_RX_PTYPE_UNUSED_ENTRY(14),
	UNIC_RX_PTYPE_UNUSED_ENTRY(15),
	UNIC_RX_PTYPE_UNUSED_ENTRY(16),
	UNIC_RX_PTYPE_ENTRY(17, 0, NONE, IPV4, PKT_HASH_TYPE_NONE),
	UNIC_RX_PTYPE_ENTRY(18, 0, NONE, IPV4, PKT_HASH_TYPE_NONE),
	UNIC_RX_PTYPE_ENTRY(19, 0, UNNECESSARY, IPV4, PKT_HASH_TYPE_L4),
	UNIC_RX_PTYPE_ENTRY(20, 0, UNNECESSARY, IPV4, PKT_HASH_TYPE_L4),
	UNIC_RX_PTYPE_ENTRY(21, 0, NONE, IPV4, PKT_HASH_TYPE_NONE),
	UNIC_RX_PTYPE_ENTRY(22, 0, NONE, IPV4, PKT_HASH_TYPE_L4),
	UNIC_RX_PTYPE_ENTRY(23, 0, NONE, IPV4, PKT_HASH_TYPE_L3),
	UNIC_RX_PTYPE_ENTRY(24, 0, NONE, IPV4, PKT_HASH_TYPE_L3),
	UNIC_RX_PTYPE_ENTRY(25, 0, NONE, IPV4, PKT_HASH_TYPE_L4),
	UNIC_RX_PTYPE_UNUSED_ENTRY(26),
	UNIC_RX_PTYPE_UNUSED_ENTRY(27),
	UNIC_RX_PTYPE_UNUSED_ENTRY(28),
	UNIC_RX_PTYPE_ENTRY(29, 0, NONE, IPV4, PKT_HASH_TYPE_NONE),
	UNIC_RX_PTYPE_ENTRY(30, 0, NONE, IPV4, PKT_HASH_TYPE_NONE),
	UNIC_RX_PTYPE_ENTRY(31, 0, NONE, IPV4, PKT_HASH_TYPE_L3),
	UNIC_RX_PTYPE_ENTRY(32, 0, NONE, IPV4, PKT_HASH_TYPE_L3),
	UNIC_RX_PTYPE_ENTRY(33, 0, UNNECESSARY, IPV4, PKT_HASH_TYPE_L4),
	UNIC_RX_PTYPE_ENTRY(34, 0, UNNECESSARY, IPV4, PKT_HASH_TYPE_L4),
	UNIC_RX_PTYPE_ENTRY(35, 0, NONE, IPV4, PKT_HASH_TYPE_L4),
	UNIC_RX_PTYPE_ENTRY(36, 0, NONE, IPV4, PKT_HASH_TYPE_L3),
	UNIC_RX_PTYPE_ENTRY(37, 0, NONE, IPV4, PKT_HASH_TYPE_L3),
	UNIC_RX_PTYPE_UNUSED_ENTRY(38),
	UNIC_RX_PTYPE_ENTRY(39, 0, NONE, IPV4, PKT_HASH_TYPE_L3),
	UNIC_RX_PTYPE_ENTRY(40, 0, NONE, IPV4, PKT_HASH_TYPE_L3),
	UNIC_RX_PTYPE_ENTRY(41, 0, UNNECESSARY, IPV4, PKT_HASH_TYPE_L4),
	UNIC_RX_PTYPE_ENTRY(42, 0, UNNECESSARY, IPV4, PKT_HASH_TYPE_L4),
	UNIC_RX_PTYPE_ENTRY(43, 0, NONE, IPV4, PKT_HASH_TYPE_L4),
	UNIC_RX_PTYPE_ENTRY(44, 0, NONE, IPV4, PKT_HASH_TYPE_L3),
	UNIC_RX_PTYPE_ENTRY(45, 0, NONE, IPV4, PKT_HASH_TYPE_L3),
	UNIC_RX_PTYPE_UNUSED_ENTRY(46),
	UNIC_RX_PTYPE_UNUSED_ENTRY(47),
	UNIC_RX_PTYPE_UNUSED_ENTRY(48),
	UNIC_RX_PTYPE_UNUSED_ENTRY(49),
	UNIC_RX_PTYPE_UNUSED_ENTRY(50),
	UNIC_RX_PTYPE_UNUSED_ENTRY(51),
	UNIC_RX_PTYPE_UNUSED_ENTRY(52),
	UNIC_RX_PTYPE_UNUSED_ENTRY(53),
	UNIC_RX_PTYPE_UNUSED_ENTRY(54),
	UNIC_RX_PTYPE_UNUSED_ENTRY(55),
	UNIC_RX_PTYPE_UNUSED_ENTRY(56),
	UNIC_RX_PTYPE_UNUSED_ENTRY(57),
	UNIC_RX_PTYPE_UNUSED_ENTRY(58),
	UNIC_RX_PTYPE_UNUSED_ENTRY(59),
	UNIC_RX_PTYPE_UNUSED_ENTRY(60),
	UNIC_RX_PTYPE_UNUSED_ENTRY(61),
	UNIC_RX_PTYPE_UNUSED_ENTRY(62),
	UNIC_RX_PTYPE_UNUSED_ENTRY(63),
	UNIC_RX_PTYPE_UNUSED_ENTRY(64),
	UNIC_RX_PTYPE_UNUSED_ENTRY(65),
	UNIC_RX_PTYPE_UNUSED_ENTRY(66),
	UNIC_RX_PTYPE_UNUSED_ENTRY(67),
	UNIC_RX_PTYPE_UNUSED_ENTRY(68),
	UNIC_RX_PTYPE_UNUSED_ENTRY(69),
	UNIC_RX_PTYPE_UNUSED_ENTRY(70),
	UNIC_RX_PTYPE_UNUSED_ENTRY(71),
	UNIC_RX_PTYPE_UNUSED_ENTRY(72),
	UNIC_RX_PTYPE_UNUSED_ENTRY(73),
	UNIC_RX_PTYPE_UNUSED_ENTRY(74),
	UNIC_RX_PTYPE_UNUSED_ENTRY(75),
	UNIC_RX_PTYPE_UNUSED_ENTRY(76),
	UNIC_RX_PTYPE_UNUSED_ENTRY(77),
	UNIC_RX_PTYPE_UNUSED_ENTRY(78),
	UNIC_RX_PTYPE_UNUSED_ENTRY(79),
	UNIC_RX_PTYPE_UNUSED_ENTRY(80),
	UNIC_RX_PTYPE_UNUSED_ENTRY(81),
	UNIC_RX_PTYPE_UNUSED_ENTRY(82),
	UNIC_RX_PTYPE_UNUSED_ENTRY(83),
	UNIC_RX_PTYPE_UNUSED_ENTRY(84),
	UNIC_RX_PTYPE_UNUSED_ENTRY(85),
	UNIC_RX_PTYPE_UNUSED_ENTRY(86),
	UNIC_RX_PTYPE_UNUSED_ENTRY(87),
	UNIC_RX_PTYPE_UNUSED_ENTRY(88),
	UNIC_RX_PTYPE_UNUSED_ENTRY(89),
	UNIC_RX_PTYPE_UNUSED_ENTRY(90),
	UNIC_RX_PTYPE_UNUSED_ENTRY(91),
	UNIC_RX_PTYPE_UNUSED_ENTRY(92),
	UNIC_RX_PTYPE_UNUSED_ENTRY(93),
	UNIC_RX_PTYPE_UNUSED_ENTRY(94),
	UNIC_RX_PTYPE_UNUSED_ENTRY(95),
	UNIC_RX_PTYPE_UNUSED_ENTRY(96),
	UNIC_RX_PTYPE_UNUSED_ENTRY(97),
	UNIC_RX_PTYPE_UNUSED_ENTRY(98),
	UNIC_RX_PTYPE_UNUSED_ENTRY(99),
	UNIC_RX_PTYPE_UNUSED_ENTRY(100),
	UNIC_RX_PTYPE_UNUSED_ENTRY(101),
	UNIC_RX_PTYPE_UNUSED_ENTRY(102),
	UNIC_RX_PTYPE_UNUSED_ENTRY(103),
	UNIC_RX_PTYPE_UNUSED_ENTRY(104),
	UNIC_RX_PTYPE_UNUSED_ENTRY(105),
	UNIC_RX_PTYPE_UNUSED_ENTRY(106),
	UNIC_RX_PTYPE_UNUSED_ENTRY(107),
	UNIC_RX_PTYPE_UNUSED_ENTRY(108),
	UNIC_RX_PTYPE_UNUSED_ENTRY(109),
	UNIC_RX_PTYPE_UNUSED_ENTRY(110),
	UNIC_RX_PTYPE_ENTRY(111, 0, NONE, IPV6, PKT_HASH_TYPE_L3),
	UNIC_RX_PTYPE_ENTRY(112, 0, NONE, IPV6, PKT_HASH_TYPE_L3),
	UNIC_RX_PTYPE_ENTRY(113, 0, UNNECESSARY, IPV6, PKT_HASH_TYPE_L4),
	UNIC_RX_PTYPE_ENTRY(114, 0, UNNECESSARY, IPV6, PKT_HASH_TYPE_L4),
	UNIC_RX_PTYPE_ENTRY(115, 0, NONE, IPV6, PKT_HASH_TYPE_L3),
	UNIC_RX_PTYPE_ENTRY(116, 0, NONE, IPV6, PKT_HASH_TYPE_L4),
	UNIC_RX_PTYPE_ENTRY(117, 0, NONE, IPV6, PKT_HASH_TYPE_L3),
	UNIC_RX_PTYPE_ENTRY(118, 0, NONE, IPV6, PKT_HASH_TYPE_L3),
	UNIC_RX_PTYPE_ENTRY(119, 0, NONE, IPV6, PKT_HASH_TYPE_L4),
	UNIC_RX_PTYPE_UNUSED_ENTRY(120),
	UNIC_RX_PTYPE_UNUSED_ENTRY(121),
	UNIC_RX_PTYPE_UNUSED_ENTRY(122),
	UNIC_RX_PTYPE_ENTRY(123, 0, NONE, IPV6, PKT_HASH_TYPE_NONE),
	UNIC_RX_PTYPE_ENTRY(124, 0, NONE, IPV6, PKT_HASH_TYPE_NONE),
	UNIC_RX_PTYPE_ENTRY(125, 0, NONE, IPV6, PKT_HASH_TYPE_L3),
	UNIC_RX_PTYPE_ENTRY(126, 0, NONE, IPV6, PKT_HASH_TYPE_L3),
	UNIC_RX_PTYPE_ENTRY(127, 0, UNNECESSARY, IPV6, PKT_HASH_TYPE_L4),
	UNIC_RX_PTYPE_ENTRY(128, 0, UNNECESSARY, IPV6, PKT_HASH_TYPE_L4),
	UNIC_RX_PTYPE_ENTRY(129, 0, NONE, IPV6, PKT_HASH_TYPE_L4),
	UNIC_RX_PTYPE_ENTRY(130, 0, NONE, IPV6, PKT_HASH_TYPE_L3),
	UNIC_RX_PTYPE_ENTRY(131, 0, NONE, IPV6, PKT_HASH_TYPE_L3),
	UNIC_RX_PTYPE_UNUSED_ENTRY(132),
	UNIC_RX_PTYPE_ENTRY(133, 0, NONE, IPV6, PKT_HASH_TYPE_L3),
	UNIC_RX_PTYPE_ENTRY(134, 0, NONE, IPV6, PKT_HASH_TYPE_L3),
	UNIC_RX_PTYPE_ENTRY(135, 0, UNNECESSARY, IPV6, PKT_HASH_TYPE_L4),
	UNIC_RX_PTYPE_ENTRY(136, 0, UNNECESSARY, IPV6, PKT_HASH_TYPE_L4),
	UNIC_RX_PTYPE_ENTRY(137, 0, NONE, IPV6, PKT_HASH_TYPE_L4),
	UNIC_RX_PTYPE_ENTRY(138, 0, NONE, IPV6, PKT_HASH_TYPE_L3),
	UNIC_RX_PTYPE_ENTRY(139, 0, NONE, IPV6, PKT_HASH_TYPE_L3),
	UNIC_RX_PTYPE_UNUSED_ENTRY(140),
	UNIC_RX_PTYPE_UNUSED_ENTRY(141),
	UNIC_RX_PTYPE_UNUSED_ENTRY(142),
	UNIC_RX_PTYPE_UNUSED_ENTRY(143),
	UNIC_RX_PTYPE_UNUSED_ENTRY(144),
	UNIC_RX_PTYPE_UNUSED_ENTRY(145),
	UNIC_RX_PTYPE_UNUSED_ENTRY(146),
	UNIC_RX_PTYPE_UNUSED_ENTRY(147),
	UNIC_RX_PTYPE_UNUSED_ENTRY(148),
	UNIC_RX_PTYPE_UNUSED_ENTRY(149),
	UNIC_RX_PTYPE_UNUSED_ENTRY(150),
	UNIC_RX_PTYPE_UNUSED_ENTRY(151),
	UNIC_RX_PTYPE_UNUSED_ENTRY(152),
	UNIC_RX_PTYPE_UNUSED_ENTRY(153),
	UNIC_RX_PTYPE_UNUSED_ENTRY(154),
	UNIC_RX_PTYPE_UNUSED_ENTRY(155),
	UNIC_RX_PTYPE_UNUSED_ENTRY(156),
	UNIC_RX_PTYPE_UNUSED_ENTRY(157),
	UNIC_RX_PTYPE_UNUSED_ENTRY(158),
	UNIC_RX_PTYPE_UNUSED_ENTRY(159),
	UNIC_RX_PTYPE_UNUSED_ENTRY(160),
	UNIC_RX_PTYPE_UNUSED_ENTRY(161),
	UNIC_RX_PTYPE_UNUSED_ENTRY(162),
	UNIC_RX_PTYPE_UNUSED_ENTRY(163),
	UNIC_RX_PTYPE_UNUSED_ENTRY(164),
	UNIC_RX_PTYPE_UNUSED_ENTRY(165),
	UNIC_RX_PTYPE_UNUSED_ENTRY(166),
	UNIC_RX_PTYPE_UNUSED_ENTRY(167),
	UNIC_RX_PTYPE_UNUSED_ENTRY(168),
	UNIC_RX_PTYPE_UNUSED_ENTRY(169),
	UNIC_RX_PTYPE_UNUSED_ENTRY(170),
	UNIC_RX_PTYPE_UNUSED_ENTRY(171),
	UNIC_RX_PTYPE_UNUSED_ENTRY(172),
	UNIC_RX_PTYPE_UNUSED_ENTRY(173),
	UNIC_RX_PTYPE_UNUSED_ENTRY(174),
	UNIC_RX_PTYPE_UNUSED_ENTRY(175),
	UNIC_RX_PTYPE_UNUSED_ENTRY(176),
	UNIC_RX_PTYPE_UNUSED_ENTRY(177),
	UNIC_RX_PTYPE_UNUSED_ENTRY(178),
	UNIC_RX_PTYPE_UNUSED_ENTRY(179),
	UNIC_RX_PTYPE_UNUSED_ENTRY(180),
	UNIC_RX_PTYPE_UNUSED_ENTRY(181),
	UNIC_RX_PTYPE_UNUSED_ENTRY(182),
	UNIC_RX_PTYPE_UNUSED_ENTRY(183),
	UNIC_RX_PTYPE_UNUSED_ENTRY(184),
	UNIC_RX_PTYPE_UNUSED_ENTRY(185),
	UNIC_RX_PTYPE_UNUSED_ENTRY(186),
	UNIC_RX_PTYPE_UNUSED_ENTRY(187),
	UNIC_RX_PTYPE_UNUSED_ENTRY(188),
	UNIC_RX_PTYPE_UNUSED_ENTRY(189),
	UNIC_RX_PTYPE_UNUSED_ENTRY(190),
	UNIC_RX_PTYPE_UNUSED_ENTRY(191),
	UNIC_RX_PTYPE_UNUSED_ENTRY(192),
	UNIC_RX_PTYPE_UNUSED_ENTRY(193),
	UNIC_RX_PTYPE_UNUSED_ENTRY(194),
	UNIC_RX_PTYPE_UNUSED_ENTRY(195),
	UNIC_RX_PTYPE_UNUSED_ENTRY(196),
	UNIC_RX_PTYPE_UNUSED_ENTRY(197),
	UNIC_RX_PTYPE_UNUSED_ENTRY(198),
	UNIC_RX_PTYPE_UNUSED_ENTRY(199),
	UNIC_RX_PTYPE_UNUSED_ENTRY(200),
	UNIC_RX_PTYPE_UNUSED_ENTRY(201),
	UNIC_RX_PTYPE_UNUSED_ENTRY(202),
	UNIC_RX_PTYPE_UNUSED_ENTRY(203),
	UNIC_RX_PTYPE_UNUSED_ENTRY(204),
	UNIC_RX_PTYPE_UNUSED_ENTRY(205),
	UNIC_RX_PTYPE_UNUSED_ENTRY(206),
	UNIC_RX_PTYPE_UNUSED_ENTRY(207),
	UNIC_RX_PTYPE_UNUSED_ENTRY(208),
	UNIC_RX_PTYPE_UNUSED_ENTRY(209),
	UNIC_RX_PTYPE_UNUSED_ENTRY(210),
	UNIC_RX_PTYPE_UNUSED_ENTRY(211),
	UNIC_RX_PTYPE_UNUSED_ENTRY(212),
	UNIC_RX_PTYPE_UNUSED_ENTRY(213),
	UNIC_RX_PTYPE_UNUSED_ENTRY(214),
	UNIC_RX_PTYPE_UNUSED_ENTRY(215),
	UNIC_RX_PTYPE_UNUSED_ENTRY(216),
	UNIC_RX_PTYPE_UNUSED_ENTRY(217),
	UNIC_RX_PTYPE_UNUSED_ENTRY(218),
	UNIC_RX_PTYPE_UNUSED_ENTRY(219),
	UNIC_RX_PTYPE_UNUSED_ENTRY(220),
	UNIC_RX_PTYPE_UNUSED_ENTRY(221),
	UNIC_RX_PTYPE_UNUSED_ENTRY(222),
	UNIC_RX_PTYPE_UNUSED_ENTRY(223),
	UNIC_RX_PTYPE_UNUSED_ENTRY(224),
	UNIC_RX_PTYPE_UNUSED_ENTRY(225),
	UNIC_RX_PTYPE_UNUSED_ENTRY(226),
	UNIC_RX_PTYPE_UNUSED_ENTRY(227),
	UNIC_RX_PTYPE_UNUSED_ENTRY(228),
	UNIC_RX_PTYPE_UNUSED_ENTRY(229),
	UNIC_RX_PTYPE_UNUSED_ENTRY(230),
	UNIC_RX_PTYPE_UNUSED_ENTRY(231),
	UNIC_RX_PTYPE_UNUSED_ENTRY(232),
	UNIC_RX_PTYPE_UNUSED_ENTRY(233),
	UNIC_RX_PTYPE_UNUSED_ENTRY(234),
	UNIC_RX_PTYPE_UNUSED_ENTRY(235),
	UNIC_RX_PTYPE_UNUSED_ENTRY(236),
	UNIC_RX_PTYPE_UNUSED_ENTRY(237),
	UNIC_RX_PTYPE_UNUSED_ENTRY(238),
	UNIC_RX_PTYPE_UNUSED_ENTRY(239),
	UNIC_RX_PTYPE_UNUSED_ENTRY(240),
	UNIC_RX_PTYPE_UNUSED_ENTRY(241),
	UNIC_RX_PTYPE_UNUSED_ENTRY(242),
	UNIC_RX_PTYPE_UNUSED_ENTRY(243),
	UNIC_RX_PTYPE_UNUSED_ENTRY(244),
	UNIC_RX_PTYPE_UNUSED_ENTRY(245),
	UNIC_RX_PTYPE_UNUSED_ENTRY(246),
	UNIC_RX_PTYPE_UNUSED_ENTRY(247),
	UNIC_RX_PTYPE_UNUSED_ENTRY(248),
	UNIC_RX_PTYPE_UNUSED_ENTRY(249),
	UNIC_RX_PTYPE_UNUSED_ENTRY(250),
	UNIC_RX_PTYPE_UNUSED_ENTRY(251),
	UNIC_RX_PTYPE_UNUSED_ENTRY(252),
	UNIC_RX_PTYPE_UNUSED_ENTRY(253),
	UNIC_RX_PTYPE_UNUSED_ENTRY(254),
	UNIC_RX_PTYPE_UNUSED_ENTRY(255),
};

static inline u16 unic_get_rqe_depth(struct unic_rq *rq)
{
	struct unic_dev *unic_dev = netdev_priv(rq->netdev);

	return unic_dev->channels.rqe_depth;
}

static inline u16 unic_get_rqe_mask(struct unic_rq *rq)
{
	return unic_get_rqe_depth(rq) - 1;
}

static inline u16 unic_get_rx_buff_len(struct unic_rq *rq)
{
	struct unic_dev *unic_dev = netdev_priv(rq->netdev);

	return unic_dev->channels.rx_buff_len;
}

static unsigned int unic_page_order(struct unic_channels *channels)
{
#if (PAGE_SIZE < 8192)
	if (channels->rx_buff_len > (PAGE_SIZE / 2))
		return 1;
#endif
	return 0;
}

static void unic_init_jfr_ctx(struct unic_rq *rq, u16 rqe_depth,
			      u16 channels_num, u32 idx, u32 tid)
{
	dma_addr_t rqe_dma_addr = rq->rqe_base_dma_addr;
	dma_addr_t db_dma_addr = rq->sw_db.db_dma_addr;
	struct unic_jfr_ctx *ctx = &rq->jfr_ctx;
	u32 jfcn = idx + channels_num;

	ctx->state = UNIC_JFR_STATE_READY;
	ctx->token_en = 0;
	ctx->rqe_shift = ilog2(roundup_pow_of_two(rqe_depth));
	ctx->jfcn_l = jfcn & (u32)UNIC_JFR_JFCN_L_VALID_BIT;
	ctx->jfcn_h = (jfcn >> UNIC_JFR_JFCN_H_OFFSET) &
		      (u32)UNIC_JFR_JFCN_H_VALID_BIT;
	ctx->rqe_base_addr_l = (rqe_dma_addr >> UNIC_RQE_VA_L_PAGE_4K_OFFSET) &
				UNIC_RQE_VA_L_VALID_BIT;
	ctx->rqe_base_addr_h = (rqe_dma_addr >> UNIC_RQE_VA_H_PAGE_4K_OFFSET) &
				UNIC_RQE_VA_H_VALID_BIT;
	ctx->rqe_token_id_l = tid & (u32)UNIC_RQE_TOKEN_ID_L_MASK;
	ctx->rqe_token_id_h = (tid >> UNIC_RQE_TOKEN_ID_H_OFFSET) &
			       (u32)UNIC_RQE_TOKEN_ID_H_MASK;
	ctx->idx_que_addr_l = unic_get_rx_buff_len(rq);

	ctx->pld_token_id = tid;
	ctx->pi = rqe_depth;
	ctx->ci = 0;
	ctx->record_db_en = UNIC_RECORD_EN;
	ctx->record_db_addr_l = (db_dma_addr >> UNIC_RQE_DB_VA_L_64B_OFFSET) &
				 UNIC_RQE_DB_VA_L_VALID_BIT;
	ctx->record_db_addr_m = (db_dma_addr >> UNIC_RQE_DB_VA_M_64B_OFFSET) &
				 UNIC_RQE_DB_VA_M_VALID_BIT;
	ctx->record_db_addr_h = (db_dma_addr >> UNIC_RQE_DB_VA_H_64B_OFFSET) &
				 UNIC_RQE_DB_VA_H_VALID_BIT;
	ctx->cqeie = 0;
	ctx->cqesz = 0;
}

static int unic_rq_alloc_resource(struct unic_dev *unic_dev, struct unic_rq *rq)
{
	struct auxiliary_device *adev = unic_dev->comdev.adev;
	u16 rqe_depth;
	u32 size;
	int ret;

	rqe_depth = unic_dev->channels.rqe_depth;
	rq->rqe_info = devm_kcalloc(&adev->dev, rqe_depth,
				    sizeof(struct unic_rqe_info), GFP_KERNEL);
	if (!rq->rqe_info) {
		dev_err(adev->dev.parent, "failed to alloc unic rqe info.\n");
		ret = -ENOMEM;
		goto err_alloc_rqe_info;
	}

	size = rqe_depth * sizeof(struct unic_rqe);
	rq->rqe = dma_alloc_coherent(adev->dev.parent, size,
				     &rq->rqe_base_dma_addr, unic_dev->gfp);
	if (!rq->rqe) {
		dev_err(adev->dev.parent, "failed to dma alloc unic rqe.\n");
		ret = -ENOMEM;
		goto err_alloc_rqe;
	}

	rq->sw_db.db_addr = dma_alloc_coherent(adev->dev.parent,
					       UNIC_JFR_DB_SIZE,
					       &rq->sw_db.db_dma_addr,
					       unic_dev->gfp);
	if (!rq->sw_db.db_addr) {
		dev_err(adev->dev.parent,
			"failed to dma alloc software db addr.\n");
		ret = -ENOMEM;
		goto err_alloc_sw_db;
	}

	return 0;

err_alloc_sw_db:
	dma_free_coherent(adev->dev.parent, size, rq->rqe,
			  rq->rqe_base_dma_addr);
err_alloc_rqe:
	devm_kfree(&adev->dev, rq->rqe_info);
err_alloc_rqe_info:
	return ret;
}

static void unic_rq_free_resource(struct unic_dev *unic_dev, struct unic_rq *rq)
{
	struct auxiliary_device *adev = unic_dev->comdev.adev;
	struct unic_sw_db *sw_db = &rq->sw_db;
	u32 size;

	size = unic_dev->channels.rqe_depth * sizeof(struct unic_rqe);
	dma_free_coherent(rq->parent_dev, UNIC_JFR_DB_SIZE, sw_db->db_addr,
			  sw_db->db_dma_addr);
	dma_free_coherent(rq->parent_dev, size, rq->rqe,
			  rq->rqe_base_dma_addr);
	devm_kfree(&adev->dev, rq->rqe_info);
}

static int unic_mbx_create_jfr_context(struct auxiliary_device *adev,
				       struct unic_rq *rq, u32 idx)
{
	struct ubase_cmd_mailbox *mailbox;
	struct ubase_mbx_attr attr = {0};
	int ret;

	mailbox = ubase_alloc_cmd_mailbox(adev);
	if (IS_ERR_OR_NULL(mailbox)) {
		dev_err(adev->dev.parent,
			"failed to alloc mailbox for create jfr context, idx = %u.\n",
			idx);
		return -ENOMEM;
	}

	memcpy(mailbox->buf, &rq->jfr_ctx, sizeof(struct unic_jfr_ctx));
	ubase_fill_mbx_attr(&attr, idx, UBASE_MB_CREATE_JFR_CONTEXT, 0);
	ret = ubase_hw_upgrade_ctx_ex(adev, &attr, mailbox);
	if (ret)
		dev_err(adev->dev.parent,
			"failed to post create jfr ctx mbx, idx = %u, ret = %d.\n",
			idx, ret);

	ubase_free_cmd_mailbox(adev, mailbox);
	return ret;
}

static void unic_modify_jfr_state(struct auxiliary_device *adev, u32 idx,
				  enum unic_jfr_state state)
{
	struct unic_jfr_ctx *ctx, *ctx_mask;
	struct ubase_cmd_mailbox *mailbox;
	struct ubase_mbx_attr attr = {0};
	int ret;

	mailbox = ubase_alloc_cmd_mailbox(adev);
	if (IS_ERR_OR_NULL(mailbox)) {
		dev_err(adev->dev.parent,
			"failed to alloc mbx for modify jfr(%u) state\n", idx);
		return;
	}

	ctx = (struct unic_jfr_ctx *)mailbox->buf;
	ctx_mask = ctx + 1;
	memset(ctx_mask, 0xff, sizeof(struct unic_jfr_ctx));
	ctx->state = state;
	ctx_mask->state = 0;

	ubase_fill_mbx_attr(&attr, idx, UBASE_MB_MODIFY_JFR_CONTEXT, 0);
	ret = ubase_hw_upgrade_ctx_ex(adev, &attr, mailbox);
	if (ret)
		dev_err(adev->dev.parent,
			"failed to upgrade jfr(%u) ctx state, ret=%d.\n", idx,
			ret);

	ubase_free_cmd_mailbox(adev, mailbox);
}

static int unic_get_last_rqe_idx(struct unic_dev *unic_dev, struct unic_rq *rq)
{
	u8 jfc_shift = unic_dev->channels.rq_jfc_shift;
	u16 buff_len = unic_get_rx_buff_len(rq);
	struct unic_cq *cq = rq->cq;
	u16 pkt_len, rqe_num;
	union unic_cqe *cqe;
	int rqe_idx = -1;
	u32 cq_mask, ci;

	ci = cq->ci;
	cq_mask = unic_get_rq_cqe_mask(unic_dev);
	dma_rmb(); /* Memory barrier before read cqe */
	cqe = &cq->cqe[ci & cq_mask];
	while (unic_cqe_owner_is_soft(jfc_shift, ci, cqe->rx.owner)) {
		pkt_len = cqe->rx.packet_len;
		rqe_num = DIV_ROUND_UP(pkt_len, buff_len);
		rqe_idx = cqe->rx.start_rqe_idx + rqe_num;
		ci++;
		cqe = &cq->cqe[ci & cq_mask];
	}

	return rqe_idx;
}

static int unic_jfr_wait_flush_done(struct unic_dev *unic_dev, u32 idx,
				    struct unic_rq *rq)
{
	struct auxiliary_device *adev = unic_dev->comdev.adev;
	struct ubase_cmd_mailbox *mailbox;
	struct ubase_mbx_attr attr = {0};
	struct unic_jfr_ctx *ctx;
	int rqe_idx = -1;
	int ret;

	mailbox = ubase_alloc_cmd_mailbox(adev);
	if (IS_ERR_OR_NULL(mailbox))
		return -ENOMEM;

	ubase_fill_mbx_attr(&attr, idx, UBASE_MB_QUERY_JFR_CONTEXT, 0);

	ret = ubase_hw_upgrade_ctx_ex(adev, &attr, mailbox);
	if (ret)
		goto out;

	ctx = (struct unic_jfr_ctx *)mailbox->buf;
	if (rq->ci == ctx->ci)
		goto out;

	rqe_idx = unic_get_last_rqe_idx(unic_dev, rq);
	if ((rqe_idx != -1) && ((rqe_idx & USHRT_MAX) == ctx->ci))
		goto out;

	ret = -EBUSY;
out:
	ubase_free_cmd_mailbox(adev, mailbox);
	return ret;
}

static void unic_mbx_destroy_jfr_context(struct auxiliary_device *adev, u32 idx)
{
	struct ubase_cmd_mailbox *mailbox;
	struct ubase_mbx_attr attr = {0};
	int ret;

	mailbox = ubase_alloc_cmd_mailbox(adev);
	if (IS_ERR_OR_NULL(mailbox)) {
		dev_err(adev->dev.parent,
			"failed to alloc mailbox for destroy jfr(%u) context.\n",
			idx);
		return;
	}

	ubase_fill_mbx_attr(&attr, idx, UBASE_MB_DESTROY_JFR_CONTEXT, 0);
	ret = ubase_hw_upgrade_ctx_ex(adev, &attr, mailbox);
	if (ret)
		dev_err(adev->dev.parent,
			"failed to post destroy jfr(%u) mailbox, ret: %d.\n",
			idx, ret);

	ubase_free_cmd_mailbox(adev, mailbox);
}

static void unic_multi_jfr_wait_flush(struct unic_dev *unic_dev, u32 num)
{
#define UNIC_WAIT_JFR_FLUSH_DONE_TIME	100
#define UNIC_WAIT_JFR_FLUSH_EVERY_TIME	10

	struct auxiliary_device *adev = unic_dev->comdev.adev;
	unsigned long end_jiffies, fd_bitmap = 0;
	struct unic_channel *c;
	bool timeout = false;
	u32 i, fd_cnt = 0;

	end_jiffies = jiffies + msecs_to_jiffies(UNIC_WAIT_JFR_FLUSH_DONE_TIME);
	while (!timeout) {
		/* check the last result after waiting enough timeout */
		if (time_is_before_eq_jiffies(end_jiffies))
			timeout = true;

		for (i = 0; i < num; i++) {
			c = &unic_dev->channels.c[i];
			if (test_bit(i, &fd_bitmap))
				continue;

			c->ret = unic_jfr_wait_flush_done(unic_dev, i, c->rq);
			if (c->ret)
				continue;

			fd_cnt++;
			set_bit(i, &fd_bitmap);
		}

		if (fd_cnt == num)
			return;

		msleep(UNIC_WAIT_JFR_FLUSH_EVERY_TIME);
	}

	for (i = 0; i < num; i++) {
		c = &unic_dev->channels.c[i];
		if (!test_bit(i, &fd_bitmap))
			dev_err(adev->dev.parent,
				"wait jfr(%u) flush timeout, ret=%d\n", i,
				c->ret);
	}
}

static void unic_destroy_multi_jfr_context(struct unic_dev *unic_dev, u32 num)
{
	struct auxiliary_device *adev = unic_dev->comdev.adev;
	u32 i;

	for (i = 0; i < num; i++)
		unic_modify_jfr_state(adev, i, UNIC_JFR_STATE_ERROR);

	unic_multi_jfr_wait_flush(unic_dev, num);

	for (i = 0; i < num; i++)
		unic_mbx_destroy_jfr_context(adev, i);
}

static int unic_rq_create_page_pool(struct unic_dev *unic_dev, u16 rqe_depth,
				    struct unic_rq *rq)
{
	struct auxiliary_device *adev = unic_dev->comdev.adev;
	struct unic_channels *channels = &unic_dev->channels;
	u32 order = unic_page_order(channels);
	struct page_pool_params pp_params = {
		.flags = PP_FLAG_DMA_MAP | PP_FLAG_PAGE_FRAG |
			 PP_FLAG_DMA_SYNC_DEV,
		.order = order,
		.pool_size = rqe_depth * channels->rx_buff_len /
			     (PAGE_SIZE << order),
		.nid = dev_to_node(adev->dev.parent),
		.dev = adev->dev.parent,
		.dma_dir = DMA_FROM_DEVICE,
		.max_len = PAGE_SIZE << order,
		.offset = 0,
	};

	rq->page_pool = page_pool_create(&pp_params);
	if (IS_ERR(rq->page_pool)) {
		dev_warn(adev->dev.parent,
			 "failed to create page pool, ret = %ld.\n",
			 PTR_ERR(rq->page_pool));
		rq->page_pool = NULL;
		return -ENOMEM;
	}

	return 0;
}

static void unic_rq_free_page_pool(struct unic_rq *rq)
{
	page_pool_destroy(rq->page_pool);
	rq->page_pool = NULL;
}

static int unic_page_pool_alloc_frag(struct unic_dev *unic_dev,
				     struct unic_rq *rq,
				     struct unic_rqe_info *rqe_info)
{
	struct auxiliary_device *adev = unic_dev->comdev.adev;
	struct unic_channels *channels = &unic_dev->channels;

	rqe_info->page_offset = 0;
	rqe_info->p = page_pool_dev_alloc_frag(rq->page_pool,
					       &rqe_info->page_offset,
					       channels->rx_buff_len);
	if (unlikely(!rqe_info->p)) {
		dev_err(adev->dev.parent, "failed to alloc page pool frag.\n");
		return -ENOMEM;
	}

	rqe_info->buf = page_address(rqe_info->p);
	rqe_info->rqe_dma_addr = page_pool_get_dma_addr(rqe_info->p);

	return 0;
}

static void unic_page_pool_put_frags(struct unic_rq *rq, u32 rqe_num)
{
	u16 rqe_mask = unic_get_rqe_mask(rq);
	u32 i;

	for (i = 0; i < rqe_num; i++, rq->ci++)
		page_pool_put_full_page(rq->page_pool,
					rq->rqe_info[rq->ci & rqe_mask].p, false);
}

static void unic_rq_free_rx_buffers(struct unic_rq *rq)
{
	u32 rqe_num = rq->pi < rq->ci ? rq->pi + UNIC_RQ_CI_REVERSE - rq->ci :
					rq->pi - rq->ci;

	unic_page_pool_put_frags(rq, rqe_num);
	unic_rq_free_page_pool(rq);
}

static int unic_rq_fill_rx_buffers(struct unic_dev *unic_dev, struct unic_rq *rq)
{
#define UNIC_RESCHED_BD_NUM 1024

	struct unic_rqe *rqe;
	u16 i, rqe_depth;
	int ret;

	rqe_depth = unic_dev->channels.rqe_depth;
	ret = unic_rq_create_page_pool(unic_dev, rqe_depth, rq);
	if (ret)
		return ret;

	rqe = rq->rqe;
	for (i = 0; i < rqe_depth; i++, rq->pi++) {
		ret = unic_page_pool_alloc_frag(unic_dev, rq, &rq->rqe_info[i]);
		if (ret)
			goto err_alloc_page;

		rqe[i].buff_addr = cpu_to_le64(rq->rqe_info[i].rqe_dma_addr +
					       rq->rqe_info[i].page_offset);
		if (!(i % UNIC_RESCHED_BD_NUM))
			cond_resched();
	}

	return 0;

err_alloc_page:
	unic_rq_free_rx_buffers(rq);

	return ret;
}

int unic_create_rq(struct unic_dev *unic_dev, u32 idx)
{
	struct unic_channel *channel = &unic_dev->channels.c[idx];
	struct auxiliary_device *adev = unic_dev->comdev.adev;
	u16 rqe_depth = unic_dev->channels.rqe_depth;
	struct unic_rq *rq;
	u16 channels_num;
	int ret;

	rq = devm_kzalloc(&adev->dev, sizeof(*rq), GFP_KERNEL);
	if (!rq)
		return -ENOMEM;

	rq->parent_dev = adev->dev.parent;

	ret = unic_rq_alloc_resource(unic_dev, rq);
	if (ret)
		goto err_alloc_rq_buf;

	rq->netdev = unic_dev->comdev.netdev;
	rq->queue_index = idx & U16_MAX;
	ret = unic_rq_fill_rx_buffers(unic_dev, rq);
	if (ret)
		goto err_fill_rqe_buff;

	channels_num = unic_dev->channels.num;
	unic_init_jfr_ctx(rq, rqe_depth, channels_num, idx, unic_dev->tid);

	*(u16 *)(rq->sw_db.db_addr) = rqe_depth;

	ret = unic_mbx_create_jfr_context(adev, rq, idx);
	if (ret)
		goto err_fill_send_rq_mbx;

	channel->rq = rq;
	return 0;

err_fill_send_rq_mbx:
	unic_rq_free_rx_buffers(rq);
err_fill_rqe_buff:
	unic_rq_free_resource(unic_dev, rq);
err_alloc_rq_buf:
	devm_kfree(&adev->dev, rq);
	return ret;
}

static void unic_free_multi_rq_resource(struct unic_dev *unic_dev, u32 num)
{
	struct auxiliary_device *adev = unic_dev->comdev.adev;
	struct unic_channel *channel;
	u32 i;

	if (ubase_adev_shutting_down(unic_dev->comdev.adev))
		return;

	for (i = 0; i < num; i++) {
		channel = &unic_dev->channels.c[i];
		if (!channel->rq) {
			dev_err(adev->dev.parent,
				"failed to get channel rq(%u).\n", i);
			continue;
		}
		unic_rq_free_rx_buffers(channel->rq);
		unic_rq_free_resource(unic_dev, channel->rq);
		devm_kfree(&adev->dev, channel->rq);
		channel->rq = NULL;
	}
}

void unic_destroy_rq(struct unic_dev *unic_dev, u32 num)
{
	struct auxiliary_device *adev = unic_dev->comdev.adev;
	enum ubase_reset_stage reset_stage;

	if (!num)
		return;

	reset_stage = ubase_get_reset_stage(adev);
	if (reset_stage != UBASE_RESET_STAGE_UNINIT)
		unic_destroy_multi_jfr_context(unic_dev, num);

	unic_free_multi_rq_resource(unic_dev, num);
}

static void unic_handle_rx_csum(struct net_device *netdev, struct sk_buff *skb,
				union unic_cqe *cqe, struct unic_rq *rq)
{
#define UNIC_RX_CQE_L3L4P_ENABLE 1

	u16 csum = cqe->rx.unknown_pkt_l2_checksum;

	skb->ip_summed = CHECKSUM_NONE;

	if (!(netdev->features & NETIF_F_RXCSUM))
		return;

	if (!(cqe->rx.l3l4p & UNIC_RX_CQE_L3L4P_ENABLE))
		return;

	if (unlikely(cqe->rx.l3_err || cqe->rx.l4_err || cqe->rx.ol3_err ||
		     cqe->rx.ol4_err)) {
		unic_rq_stats_inc(rq, l3_l4_csum_err);
		return;
	}

	skb->ip_summed = unic_rx_ptype_tbl[cqe->rx.ptype].ip_summed;
	skb->csum_level = unic_rx_ptype_tbl[cqe->rx.ptype].csum_level;
	if (skb->ip_summed == CHECKSUM_COMPLETE) {
		unic_rq_stats_inc(rq, csum_complete);
		skb->csum = csum_unfold((__force __sum16)csum);
	}
}

#if IS_ENABLED(CONFIG_UB_UNIC_UBL)
static __be16 unic_assign_ub_proto(struct net_device *netdev,
				   struct sk_buff *skb, u32 l3_type)
{
	u8 ub_type;

	if (l3_type == UNIC_L3_TYPE_IPV4)
		ub_type = UB_IPV4_CFG_TYPE;
	else if (l3_type == UNIC_L3_TYPE_IPV6)
		ub_type = UB_IPV6_CFG_TYPE;
	else
		ub_type = UB_NOIP_CFG_TYPE;

	return ubl_type_trans(skb, netdev, ub_type);
}
#endif

static int unic_handle_cqe(struct unic_rq *rq, union unic_cqe *cqe)
{
	struct unic_dev *unic_dev = netdev_priv(rq->netdev);
	struct net_device *netdev = rq->netdev;
	struct sk_buff *skb = rq->skb;
	enum pkt_hash_types rss_type;

	if (unlikely(!cqe->rx.packet_len || cqe->rx.l2_err || cqe->rx.trunc)) {
		if (!cqe->rx.packet_len)
			unic_rq_stats_inc(rq, err_pkt_len_cnt);
		else if (cqe->rx.l2_err)
			unic_rq_stats_inc(rq, l2_err);
		else
			unic_rq_stats_inc(rq, trunc_cnt);

		return -EFAULT;
	}

#if IS_ENABLED(CONFIG_UB_UNIC_UBL)
	if (unic_dev_ubl_supported(unic_dev))
		skb->protocol = unic_assign_ub_proto(netdev, skb,
						     unic_rx_ptype_tbl[cqe->rx.ptype].l3_type);
	else
		skb->protocol = eth_type_trans(skb, netdev);
#else
	skb->protocol = eth_type_trans(skb, netdev);
#endif

	unic_handle_rx_csum(netdev, skb, cqe, rq);

	rss_type = unic_rx_ptype_tbl[cqe->rx.ptype].hash_type;

	skb_set_hash(skb, le32_to_cpu(cqe->rx.rss_hash), rss_type);

	skb_record_rx_queue(skb, rq->queue_index);

	return 0;
}

static void unic_fill_skb_frags(struct unic_rq *rq, struct sk_buff *skb,
				struct unic_rqe_info *rqe_info,
				u32 frag_index, u32 frag_size)
{
	u16 buff_len = unic_get_rx_buff_len(rq);
	u32 page_offset = rqe_info->page_offset;
	struct page *page = rqe_info->p;

	dma_sync_single_for_cpu(rq->parent_dev,
				rqe_info->rqe_dma_addr + page_offset, frag_size,
				DMA_FROM_DEVICE);

	skb_add_rx_frag(skb, frag_index, page, page_offset, frag_size,
			buff_len);
}

static int unic_add_skb_frags(struct unic_rq *rq, struct napi_struct *napi,
			      u16 pkt_len, u32 pull_len)
{
	u16 buff_len = unic_get_rx_buff_len(rq);
	u16 rqe_num = DIV_ROUND_UP(pkt_len, buff_len);
	u16 rqe_mask = unic_get_rqe_mask(rq);
	struct sk_buff *head_skb = rq->skb;
	u16 i, frag_size, frag_index = 0;
	struct unic_rqe_info *rqe_info;
	struct sk_buff *skb = head_skb;
	struct sk_buff *new_skb;
	u16 last_ci = rq->ci;

	/* add skb first frag */
	frag_size = rqe_num == 1 ? pkt_len : buff_len;
	rqe_info = &rq->rqe_info[last_ci++ & rqe_mask];
	rqe_info->page_offset += pull_len;
	unic_fill_skb_frags(rq, skb, rqe_info, frag_index++,
			    frag_size - pull_len);

	for (i = 1; i < rqe_num; i++, frag_index++, last_ci++) {
		if (unlikely(frag_index >= MAX_SKB_FRAGS)) {
			new_skb = napi_alloc_skb(napi, 0);
			if (unlikely(!new_skb)) {
				unic_rq_stats_inc(rq, alloc_skb_err);
				return -ENOMEM;
			}

			skb_mark_for_recycle(new_skb);
			frag_index = 0;

			if (skb == head_skb)
				skb_shinfo(skb)->frag_list = new_skb;
			else
				skb->next = new_skb;

			skb = new_skb;
		}

		pkt_len = pkt_len - buff_len;
		frag_size = i < rqe_num - 1 ? buff_len : pkt_len;

		if (unlikely(skb != head_skb)) {
			head_skb->len += frag_size;
			head_skb->data_len += frag_size;
			head_skb->truesize += buff_len;
		}

		rqe_info = &rq->rqe_info[last_ci & rqe_mask];
		unic_fill_skb_frags(rq, skb, rqe_info, frag_index, frag_size);
	}

	return 0;
}

static u32 unic_get_skb_linear_len(struct unic_rq *rq, u8 *va,
				   struct unic_dev *unic_dev)
{
	u32 pull_len;

	if (unic_dev_ubl_supported(unic_dev))
		pull_len = UNIC_RX_HEAD_SIZE;
	else
		pull_len = eth_get_headlen(rq->netdev, va, UNIC_RX_HEAD_SIZE);

	return pull_len;
}

static int unic_create_skb(struct unic_rq *rq, struct napi_struct *napi,
			   u16 pkt_len)
{
	struct unic_dev *unic_dev = netdev_priv(rq->netdev);
	struct unic_rqe_info *rqe_info;
	struct sk_buff *skb;
	u32 pull_len;
	u16 rqe_mask;
	int ret;
	u8 *va;

	rqe_mask = unic_get_rqe_mask(rq);
	rqe_info = &rq->rqe_info[rq->ci & rqe_mask];

	skb = napi_alloc_skb(napi, UNIC_RX_HEAD_SIZE);
	if (unlikely(!skb)) {
		unic_rq_stats_inc(rq, alloc_skb_err);
		return -ENOMEM;
	}

	rq->skb = skb;
	va = rqe_info->buf + rqe_info->page_offset;

	if (pkt_len <= UNIC_RX_HEAD_SIZE) {
		dma_sync_single_for_cpu(rq->parent_dev,
					rqe_info->rqe_dma_addr + rqe_info->page_offset,
					ALIGN(pkt_len, sizeof(long)),
					DMA_FROM_DEVICE);

		memcpy(__skb_put(skb, pkt_len), va, ALIGN(pkt_len, sizeof(long)));

		page_pool_put_full_page(rq->page_pool, rqe_info->p, false);
		return 0;
	}

	skb_mark_for_recycle(skb);

	pull_len = unic_get_skb_linear_len(rq, va, unic_dev);
	__skb_put(skb, pull_len);
	ret = unic_add_skb_frags(rq, napi, pkt_len, pull_len);
	if (unlikely(ret)) {
		dev_kfree_skb_any(rq->skb);
		rq->skb = NULL;
		return ret;
	}

	memcpy(skb->data, va, ALIGN(pull_len, sizeof(long)));

	return 0;
}

static void unic_fix_rq_ci(struct unic_rq *rq, union unic_cqe *cqe)
{
	u32 start_rqe_idx = cqe->rx.start_rqe_idx;
	u32 put_page_num;

	if (unlikely(rq->ci != cqe->rx.start_rqe_idx)) {
		trace_unic_rq_ci_mismatch(rq, start_rqe_idx);
		if (start_rqe_idx < rq->ci)
			start_rqe_idx += UNIC_RQ_CI_REVERSE;
		put_page_num = start_rqe_idx - rq->ci;
		unic_page_pool_put_frags(rq, put_page_num);
		rq->pending_buf += put_page_num;
		rq->ci = cqe->rx.start_rqe_idx;
	}
}

static int unic_rx_construct_skb(struct unic_rq *rq, struct napi_struct *napi,
				 union unic_cqe *cqe, u64 *bytes)
{
	u16 buff_len = unic_get_rx_buff_len(rq);
	u16 pkt_len = cqe->rx.packet_len;
	u16 rqe_num;
	int ret;

	rq->cq->ci++;
	if (unlikely(cqe->rx.doi)) {
		unic_rq_stats_inc(rq, doi_cnt);
		return -EFAULT;
	}

	unic_fix_rq_ci(rq, cqe);
	rqe_num = DIV_ROUND_UP(pkt_len, buff_len);
	rq->pending_buf += rqe_num;
	ret = unic_create_skb(rq, napi, pkt_len);
	if (unlikely(ret))
		return ret;

	ret = unic_handle_cqe(rq, cqe);
	if (unlikely(ret))
		goto destroy_skb;

	*bytes += pkt_len;
	rq->ci += rqe_num;

	return 0;

destroy_skb:
	dev_kfree_skb_any(rq->skb);
	rq->skb = NULL;
	unic_page_pool_put_frags(rq, rqe_num);
	return ret;
}

static bool unic_refill_rx_buffers(struct unic_rq *rq)
{
	struct unic_dev *unic_dev = netdev_priv(rq->netdev);
	u16 rqe_mask = unic_get_rqe_mask(rq);
	struct unic_rqe_info *rqe_info;
	u16 pd_buff = rq->pending_buf;
	u32 i, rq_ci = rq->ci;
	struct unic_rqe *rqe;
	bool ret = false;

	if (unlikely(rq_ci < pd_buff))
		rq_ci += UNIC_RQ_CI_REVERSE;

	for (i = rq_ci - pd_buff; i < rq_ci; i++) {
		rqe_info = &rq->rqe_info[i & rqe_mask];
		if (unlikely(unic_page_pool_alloc_frag(unic_dev, rq, rqe_info))) {
			unic_rq_stats_inc(rq, alloc_frag_err);
			ret = true;
			break;
		}

		rqe = &rq->rqe[i & rqe_mask];
		rqe->buff_addr = rqe_info->rqe_dma_addr + rqe_info->page_offset;
		rq->pi++;
	}

	if (likely(i > rq_ci - pd_buff)) {
		rq->pending_buf = rq_ci - i;
		*(u16 *)(rq->sw_db.db_addr) = rq->pi;
	}

	return ret;
}

void unic_send_skb_to_stack(struct unic_channel *c, struct sk_buff *skb)
{
	struct napi_struct *napi = &c->napi;

	if (skb_has_frag_list(skb))
		napi_gro_flush(napi, false);

	napi_gro_receive(napi, skb);
}

int unic_poll_rx(struct unic_channel *c, int budget,
		 void (*rx_fn)(struct unic_channel *, struct sk_buff *))
{
#define UNIC_RX_BUFFER_WRITE	16

	struct unic_rq *rq = c->rq;
	struct unic_dev *unic_dev = netdev_priv(rq->netdev);
	u8 jfc_shift = unic_dev->channels.rq_jfc_shift;
	struct unic_cq *cq = rq->cq;
	struct napi_struct *napi;
	u32 last_ci = cq->ci;
	bool failure = false;
	union unic_cqe *cqe;
	int packets = 0;
	u64 bytes = 0;
	u32 cq_mask;

	napi = &c->napi;
	cq_mask = unic_get_rq_cqe_mask(unic_dev);

	while (packets < budget) {
		if (rq->pending_buf >= UNIC_RX_BUFFER_WRITE) {
			unic_cq_doorbell(cq, last_ci);
			last_ci = cq->ci;
			failure = failure || unic_refill_rx_buffers(rq);
		}

		dma_rmb(); /* Memory barrier before read cqe */
		cqe = &cq->cqe[cq->ci & cq_mask];
		if (!unic_cqe_owner_is_soft(jfc_shift, cq->ci, cqe->rx.owner))
			break;

		trace_unic_rx_cqe(rq->netdev, cq, rq->pi, rq->ci, cq_mask);
		if (unic_rx_construct_skb(rq, napi, cqe, &bytes)) {
			failure = true;
			break;
		}

		rx_fn(c, rq->skb);

		rq->skb = NULL;

		packets++;
	}

	if (rq->pending_buf) {
		unic_cq_doorbell(cq, last_ci);
		failure = failure || unic_refill_rx_buffers(rq);
	}

	u64_stats_update_begin(&rq->syncp);
	rq->stats.packets += (u64)packets;
	rq->stats.bytes += bytes;
	u64_stats_update_end(&rq->syncp);

	return failure ? budget : packets;
}

static void unic_clear_rq_buffers(struct unic_rq *rq, union unic_cqe *cqe)
{
	u16 buff_len = unic_get_rx_buff_len(rq);
	u16 pkt_len, rqe_num;

	if (cqe->rx.doi) {
		unic_rq_stats_inc(rq, doi_cnt);
		return;
	}

	unic_fix_rq_ci(rq, cqe);
	pkt_len = le16_to_cpu(cqe->rx.packet_len);
	rqe_num = DIV_ROUND_UP(pkt_len, buff_len);
	unic_page_pool_put_frags(rq, rqe_num);

	rq->pending_buf += rqe_num;
}

void unic_clear_rq(struct unic_rq *rq)
{
	struct unic_dev *unic_dev = netdev_priv(rq->netdev);
	u8 jfc_shift = unic_dev->channels.rq_jfc_shift;
	u32 cq_mask = unic_get_rq_cqe_mask(unic_dev);
	struct unic_cq *cq = rq->cq;
	u32 last_ci = cq->ci;
	union unic_cqe *cqe;

	cqe = &cq->cqe[cq->ci & cq_mask];
	while (unic_cqe_owner_is_soft(jfc_shift, cq->ci, cqe->rx.owner)) {
		unic_clear_rq_buffers(rq, cqe);
		cq->ci++;
		cqe = &cq->cqe[cq->ci & cq_mask];
	}

	unic_cq_doorbell(cq, last_ci);

	unic_refill_rx_buffers(rq);
}
