// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2018 - 2021 Beijing WangXun Technology Co., Ltd. */

#include "nse_base.h"
#include "nse_irq.h"
#include "nse_lib.h"
#include "nse_dcb_lib.h"
#include "nse_sriov.h"

static void rxq_ctx_dump_amber(struct nse_hw *hw, struct nse_lan_rxq_ctx_amber *rlan_ctx,
			       unsigned int dump_dword_bitmap)
{
	struct device *dev = nse_hw_to_dev(hw);
	u64 val64;
	u32 val32;

	/* DATA[0]: BASE_low */
	/* DATA[1]: BASE_high, TPHRDesc, TPHWDesc, Desc_coalesc_en, Cause_en */

	if ((dump_dword_bitmap & BIT(0)) ||
		(dump_dword_bitmap & BIT(1))) {
		dev_info(dev, "\t raw_data[0]: %X\n", rlan_ctx->data[0]);
		dev_info(dev, "\t raw_data[1]: %X\n", rlan_ctx->data[1]);

		/* get the base */
		val64 = rlan_ctx->data[1] & AMBER_LAN_RXQ_CTX_BASE_HIGH_M;
		val64 <<= 32;
		val64 |= rlan_ctx->data[0];
		val64 <<= AMBER_LAN_RXQ_BASE_SHIFT;

		dev_info(dev, "BASE: 0x%lX\n", (unsigned long)val64);

		val32 = (rlan_ctx->data[1] & AMBER_LAN_RXQ_CTX_TPHRDESC_M) >>
			AMBER_LAN_RXQ_CTX_TPHRDESC_S;
		dev_info(dev, "TPHRDESC: %d\n", val32);

		val32 = (rlan_ctx->data[1] & AMBER_LAN_RXQ_CTX_TPHWDESC_M) >>
			AMBER_LAN_RXQ_CTX_TPHWDESC_S;
		dev_info(dev, "TPHWDESC: %d\n", val32);

		val32 = (rlan_ctx->data[1] & AMBER_LAN_RXQ_CTX_DESC_COALESC_EN_M) >>
			AMBER_LAN_RXQ_CTX_DESC_COALESC_EN_S;
		dev_info(dev, "DESC_COALESC_EN: %d\n", val32);

		val32 = (rlan_ctx->data[1] & AMBER_LAN_RXQ_CTX_CAUSE_EN_M) >>
			AMBER_LAN_RXQ_CTX_CAUSE_EN_S;
		dev_info(dev, "CAUSE_EN: %d\n\n", val32);
	}

	/* DATA[2]: Msix_idx, DBUFF, HBUFF, CPUID, TS */

	if (dump_dword_bitmap & BIT(2)) {
		dev_info(dev, "\t raw_data[2]: %X\n", rlan_ctx->data[2]);

		val32 = (rlan_ctx->data[2] & AMBER_LAN_RXQ_CTX_MSIX_IDX_M) >>
			AMBER_LAN_RXQ_CTX_MSIX_IDX_S;
		dev_info(dev, "MSIX_IDX: %d\n", val32);

		val32 = (rlan_ctx->data[2] & AMBER_LAN_RXQ_CTX_DBUFF_M) >>
			AMBER_LAN_RXQ_CTX_DBUFF_S;
		dev_info(dev, "DBUFF: %d\n", val32);

		val32 = (rlan_ctx->data[2] & AMBER_LAN_RXQ_CTX_HBUFF_M) >>
			AMBER_LAN_RXQ_CTX_HBUFF_S;
		dev_info(dev, "HBUFF: %d\n", val32);

		val32 = (rlan_ctx->data[2] & AMBER_LAN_RXQ_CTX_CPUID_M) >>
			AMBER_LAN_RXQ_CTX_CPUID_S;
		dev_info(dev, "CPUID: %d\n", val32);

		val32 = (rlan_ctx->data[2] & AMBER_LAN_RXQ_CTX_TS_M) >> AMBER_LAN_RXQ_CTX_TS_S;
		dev_info(dev, "TS: %d\n\n", val32);
	}

	if (dump_dword_bitmap & BIT(3)) {
		dev_info(dev, "\t raw_data[3]: %X\n", rlan_ctx->data[3]);

		val32 = (rlan_ctx->data[3] & AMBER_LAN_RXQ_CTX_QLEN_M) >> AMBER_LAN_RXQ_CTX_QLEN_S;
		dev_info(dev, "QLEN: %d\n", val32);

		val32 = (rlan_ctx->data[3] & AMBER_LAN_RXQ_CTX_RSC_EN_M) >>
			AMBER_LAN_RXQ_CTX_RSC_EN_S;
		dev_info(dev, "RSC_EN: %d\n", val32);

		val32 = (rlan_ctx->data[3] & AMBER_LAN_RXQ_CTX_RSC_MAX_BUF_M) >>
			AMBER_LAN_RXQ_CTX_RSC_MAX_BUF_S;
		dev_info(dev, "RSC_MAX_BUF: %d\n", val32);

		val32 = (rlan_ctx->data[3] & AMBER_LAN_RXQ_CTX_RSC_OVERFLOW_M) >>
			AMBER_LAN_RXQ_CTX_RSC_OVERFLOW_S;
		dev_info(dev, "RSC_OVERFLOW: %d\n", val32);

		val32 = (rlan_ctx->data[3] & AMBER_LAN_RXQ_CTX_DTYPE_M) >>
			AMBER_LAN_RXQ_CTX_DTYPE_S;
		dev_info(dev, "DTYPE: %d\n", val32);

		val32 = (rlan_ctx->data[3] & AMBER_LAN_RXQ_CTX_DSIZE_M) >>
			AMBER_LAN_RXQ_CTX_DSIZE_S;
		dev_info(dev, "DSIZE: %d\n", val32);

		val32 = (rlan_ctx->data[3] & AMBER_LAN_RXQ_CTX_L2TSEL_M) >>
			AMBER_LAN_RXQ_CTX_L2TSEL_S;
		dev_info(dev, "L2TSEL: %d\n", val32);

		val32 = (rlan_ctx->data[3] & AMBER_LAN_RXQ_CTX_L2TAG_STRIP_EN_M) >>
			AMBER_LAN_RXQ_CTX_L2TAG_STRIP_EN_S;
		dev_info(dev, "L2TAG_STRIP_EN: %d\n", val32);

		val32 = (rlan_ctx->data[3] & AMBER_LAN_RXQ_CTX_TPHDATA_M) >>
			AMBER_LAN_RXQ_CTX_TPHDATA_S;
		dev_info(dev, "TPHDATA: %d\n", val32);

		val32 = (rlan_ctx->data[3] & AMBER_LAN_RXQ_CTX_TPHHEAD_M) >>
			AMBER_LAN_RXQ_CTX_TPHHEAD_S;
		dev_info(dev, "TPHHEAD: %d\n", val32);

		val32 = (rlan_ctx->data[3] & AMBER_LAN_RXQ_CTX_LRXQTRESH_M) >>
			AMBER_LAN_RXQ_CTX_LRXQTRESH_S;
		dev_info(dev, "LRXQTRESH: %d\n", val32);

		val32 = (rlan_ctx->data[3] & AMBER_LAN_RXQ_CTX_LL_M) >> AMBER_LAN_RXQ_CTX_LL_S;
		dev_info(dev, "LL: %d\n", val32);

		val32 = (rlan_ctx->data[3] & AMBER_LAN_RXQ_CTX_PF_NUM_M) >>
			AMBER_LAN_RXQ_CTX_PF_NUM_S;
		dev_info(dev, "PF_NUM: %d\n", val32);

		val32 = (rlan_ctx->data[3] & AMBER_LAN_RXQ_CTX_DROP_CTRL_M) >>
			AMBER_LAN_RXQ_CTX_DROP_CTRL_S;
		dev_info(dev, "DROP_CTRL: %d\n", val32);

		val32 = (rlan_ctx->data[3] & AMBER_LAN_RXQ_CTX_QTYPE_M) >>
			AMBER_LAN_RXQ_CTX_QTYPE_S;
		dev_info(dev, "QTYPE: %d\n\n", val32);
	}

	/* DATA[4]: RXDID, HSPLIT_0, HSPLIT_1, VSI, Statistic_cnt_id, Statistic_en */

	if (dump_dword_bitmap & BIT(4)) {
		dev_info(dev, "\t raw_data[4]: %X\n", rlan_ctx->data[4]);

		val32 = (rlan_ctx->data[4] & AMBER_LAN_RXQ_CTX_RXDID_M) >>
			AMBER_LAN_RXQ_CTX_RXDID_S;
		dev_info(dev, "RXDID: %d\n", val32);

		val32 = (rlan_ctx->data[4] & AMBER_LAN_RXQ_CTX_HSPLIT0_M) >>
			AMBER_LAN_RXQ_CTX_HSPLIT0_S;
		dev_info(dev, "HSPLIT0: %d\n", val32);

		val32 = (rlan_ctx->data[4] & AMBER_LAN_RXQ_CTX_HSPLIT1_M) >>
			AMBER_LAN_RXQ_CTX_HSPLIT1_S;
		dev_info(dev, "HSPLIT1: %d\n", val32);

		val32 = (rlan_ctx->data[4] & AMBER_LAN_RXQ_CTX_VSI_M) >> AMBER_LAN_RXQ_CTX_VSI_S;
		dev_info(dev, "VSI: %d\n", val32);

		val32 = (rlan_ctx->data[4] & AMBER_LAN_RXQ_CTX_STATS_CNT_ID_M) >>
			AMBER_LAN_RXQ_CTX_STATS_CNT_ID_S;
		dev_info(dev, "STATS_CNT_ID: %d\n", val32);

		val32 = (rlan_ctx->data[4] & AMBER_LAN_RXQ_CTX_STATS_EN_M) >>
			AMBER_LAN_RXQ_CTX_STATS_EN_S;
		dev_info(dev, "STATS_EN: %d\n\n", val32);
	}

	/* DATA[5]: vis_addr_l */
	/* DATA[6]: vis_addr_h */
	if (dump_dword_bitmap & BIT(5)) {
		dev_info(dev, "\t raw_data[5]: %X\n", rlan_ctx->data[5]);
		dev_info(dev, "vis_addr_l: %X\n", rlan_ctx->data[5]);
	}
	if (dump_dword_bitmap & BIT(6)) {
		dev_info(dev, "\t raw_data[6]: %X\n", rlan_ctx->data[6]);
		dev_info(dev, "vis_addr_h: %X\n", rlan_ctx->data[6]);
	}

	/* DATA[7]: TAIL, TAIL_WRAP_CNT, HEAD, HEAD_WRAP_CNT */
	if (dump_dword_bitmap & BIT(7)) {
		dev_info(dev, "\t raw_data[7]: %X\n", rlan_ctx->data[7]);

		val32 = (rlan_ctx->data[7] & AMBER_LAN_RXQ_CTX_TAIL_M) >> AMBER_LAN_RXQ_CTX_TAIL_S;
		dev_info(dev, "TAIL: %d\n", val32);

		val32 = (rlan_ctx->data[7] & AMBER_LAN_RXQ_CTX_TAIL_WRAP_CNT_M) >>
			AMBER_LAN_RXQ_CTX_TAIL_WRAP_CNT_S;
		dev_info(dev, "TAIL_WRAP_CNT: %d\n", val32);

		val32 = (rlan_ctx->data[7] & AMBER_LAN_RXQ_CTX_HEAD_M) >> AMBER_LAN_RXQ_CTX_HEAD_S;
		dev_info(dev, "HEAD: %d\n", val32);

		val32 = (rlan_ctx->data[7] & AMBER_LAN_RXQ_CTX_HEAD_WRAP_CNT_M) >>
			AMBER_LAN_RXQ_CTX_HEAD_WRAP_CNT_S;
		dev_info(dev, "HEAD_WRAP_CNT: %d\n\n", val32);
	}

	if (dump_dword_bitmap & BIT(8)) {
		dev_info(dev, "\t raw_data[8]: %X\n", rlan_ctx->data[8]);

		val32 = (rlan_ctx->data[8] & AMBER_LAN_RXQ_CTX_PRE_USED_WRAP_CNT_M) >>
			AMBER_LAN_RXQ_CTX_PRE_USED_WRAP_CNT_S;
		dev_info(dev, "PRE_USED_WRAP_CNT: %d\n", val32);

		val32 = (rlan_ctx->data[8] & AMBER_LAN_RXQ_CTX_PRE_USED_M) >>
			AMBER_LAN_RXQ_CTX_PRE_USED_S;
		dev_info(dev, "PRE_USED: %d\n", val32);

		val32 = (rlan_ctx->data[8] & AMBER_LAN_RXQ_CTX_FETCH_WRAP_CNT_M) >>
			AMBER_LAN_RXQ_CTX_FETCH_WRAP_CNT_S;
		dev_info(dev, "FETCH_WRAP_CNT: %d\n", val32);

		val32 = (rlan_ctx->data[8] & AMBER_LAN_RXQ_CTX_FETCH_M) >>
			AMBER_LAN_RXQ_CTX_FETCH_S;
		dev_info(dev, "FETCH: %d\n\n", val32);
	}

	if (dump_dword_bitmap & BIT(9)) {
		dev_info(dev, "\t raw_data[9]: %X\n", rlan_ctx->data[9]);

		val32 = (rlan_ctx->data[9] & AMBER_LAN_RXQ_CTX_QMRD_CNT_M) >>
			AMBER_LAN_RXQ_CTX_QMRD_CNT_S;
		dev_info(dev, "QMRD_CNT: %d\n", val32);

		val32 = (rlan_ctx->data[9] & AMBER_LAN_RXQ_CTX_REAL_CNT_M) >>
			AMBER_LAN_RXQ_CTX_REAL_CNT_S;
		dev_info(dev, "REAL_CNT: %d\n\n", val32);
	}

	if (dump_dword_bitmap & BIT(10)) {
		dev_info(dev, "\t raw_data[10]: %X\n", rlan_ctx->data[10]);

		val32 = (rlan_ctx->data[10] & AMBER_LAN_RXQ_CTX_VIRTIO_DESC_LEN_M) >>
			AMBER_LAN_RXQ_CTX_VIRTIO_DESC_LEN_S;
		dev_info(dev, "VIRTIO_DESC_LEN: %d\n", val32);

		val32 = (rlan_ctx->data[10] & AMBER_LAN_RXQ_CTX_EST_CNT_M) >>
			AMBER_LAN_RXQ_CTX_EST_CNT_S;
		dev_info(dev, "REAL_CNT: %d\n\n", val32);
	}
}

static void rxq_ctx_dump_ms(struct nse_hw *hw, struct nse_lan_rxq_ctx_ms *rlan_ctx,
			    unsigned int dump_dword_bitmap)
{
	struct device *dev = nse_hw_to_dev(hw);
	u64 val64;
	u32 val32;

	/* DATA[0]: */
	/* DATA[1]: */
	if ((dump_dword_bitmap & BIT(0)) ||
		(dump_dword_bitmap & BIT(1))) {
		dev_info(dev, "\t raw_data[0]: %X\n", rlan_ctx->data[0]);
		dev_info(dev, "\t raw_data[1]: %X\n", rlan_ctx->data[1]);

		/* get the base */
		val64 = rlan_ctx->data[1] & MS_LAN_RXQ_CTX_BASE_HIGH_M;
		val64 <<= 32;
		val64 |= rlan_ctx->data[0];
		val64 <<= MS_LAN_RXQ_BASE_SHIFT;

		dev_info(dev, "BASE: 0x%lX\n", (unsigned long)val64);

		val32 = (rlan_ctx->data[1] & MS_LAN_RXQ_CTX_CAUSE_EN_M) >>
			MS_LAN_RXQ_CTX_CAUSE_EN_S;
		dev_info(dev, "CAUSE_EN: %d\n\n", val32);

		val32 = (rlan_ctx->data[1] & MS_LAN_RXQ_CTX_DESC_COALESC_EN_M) >>
			MS_LAN_RXQ_CTX_DESC_COALESC_EN_S;
		dev_info(dev, "DESC_COALESC_EN: %d\n", val32);

		val32 = (rlan_ctx->data[1] & MS_LAN_RXQ_CTX_TPHWDESC_M) >>
			MS_LAN_RXQ_CTX_TPHWDESC_S;
		dev_info(dev, "TPHWDESC: %d\n", val32);

		val32 = (rlan_ctx->data[1] & MS_LAN_RXQ_CTX_TPHRDESC_M) >>
			MS_LAN_RXQ_CTX_TPHRDESC_S;
		dev_info(dev, "TPHRDESC: %d\n", val32);
	}

	/* DATA[2]: */
	if (dump_dword_bitmap & BIT(2)) {
		dev_info(dev, "\t raw_data[2]: %X\n", rlan_ctx->data[2]);

		val32 = (rlan_ctx->data[2] & MS_LAN_RXQ_CTX_TS_M) >> MS_LAN_RXQ_CTX_TS_S;
		dev_info(dev, "TS: %d\n\n", val32);

		val32 = (rlan_ctx->data[2] & MS_LAN_RXQ_CTX_CPUID_M) >> MS_LAN_RXQ_CTX_CPUID_S;
		dev_info(dev, "CPUID: %d\n", val32);

		val32 = (rlan_ctx->data[2] & MS_LAN_RXQ_CTX_DBUFF_M) >> MS_LAN_RXQ_CTX_DBUFF_S;
		dev_info(dev, "DBUFF: %d\n", val32);

		val32 = (rlan_ctx->data[2] & MS_LAN_RXQ_CTX_MSIX_IDX_M) >>
			MS_LAN_RXQ_CTX_MSIX_IDX_S;
		dev_info(dev, "MSIX_IDX: %d\n", val32);
	}

	/* DATA[3]: */
	if (dump_dword_bitmap & BIT(3)) {
		dev_info(dev, "\t raw_data[3]: %X\n", rlan_ctx->data[3]);

		val32 = (rlan_ctx->data[3] & MS_LAN_RXQ_CTX_DROP_CTRL_M) >>
			MS_LAN_RXQ_CTX_DROP_CTRL_S;
		dev_info(dev, "DROP_CTRL: %d\n", val32);

		val32 = (rlan_ctx->data[3] & MS_LAN_RXQ_CTX_PF_NUM_M) >> MS_LAN_RXQ_CTX_PF_NUM_S;
		dev_info(dev, "PF_NUM: %d\n", val32);

		val32 = (rlan_ctx->data[3] & MS_LAN_RXQ_CTX_LRXQTRESH_M) >>
			MS_LAN_RXQ_CTX_LRXQTRESH_S;
		dev_info(dev, "LRXQTRESH: %d\n", val32);

		val32 = (rlan_ctx->data[3] & MS_LAN_RXQ_CTX_TPHDATA_M) >> MS_LAN_RXQ_CTX_TPHDATA_S;
		dev_info(dev, "TPHDATA: %d\n", val32);

		val32 = (rlan_ctx->data[3] & MS_LAN_RXQ_CTX_L2TAG_STRIP_EN_M) >>
			MS_LAN_RXQ_CTX_L2TAG_STRIP_EN_S;
		dev_info(dev, "L2TAG_STRIP_EN: %d\n", val32);

		val32 = (rlan_ctx->data[3] & MS_LAN_RXQ_CTX_L2TSEL_M) >> MS_LAN_RXQ_CTX_L2TSEL_S;
		dev_info(dev, "L2TSEL: %d\n", val32);

		val32 = (rlan_ctx->data[3] & MS_LAN_RXQ_CTX_DSIZE_M) >> MS_LAN_RXQ_CTX_DSIZE_S;
		dev_info(dev, "DSIZE: %d\n", val32);

		val32 = (rlan_ctx->data[3] & MS_LAN_RXQ_CTX_QLEN_M) >> MS_LAN_RXQ_CTX_QLEN_S;
		dev_info(dev, "QLEN: %d\n", val32);
	}

	/* DATA[4]: */
	if (dump_dword_bitmap & BIT(4)) {
		dev_info(dev, "\t raw_data[4]: %X\n", rlan_ctx->data[4]);

		val32 = (rlan_ctx->data[4] & MS_LAN_RXQ_CTX_VSI_M) >> MS_LAN_RXQ_CTX_VSI_S;
		dev_info(dev, "VSI: %d\n", val32);
	}

	/* DATA[5]: not used in ms */
	/* DATA[6]: not used in ms  */

	/* DATA[7]: */
	if (dump_dword_bitmap & BIT(7)) {
		dev_info(dev, "\t raw_data[7]: %X\n", rlan_ctx->data[7]);

		val32 = (rlan_ctx->data[7] & MS_LAN_RXQ_CTX_HEAD_WRAP_CNT_M) >>
			MS_LAN_RXQ_CTX_HEAD_WRAP_CNT_S;
		dev_info(dev, "HEAD_WRAP_CNT: %d\n\n", val32);

		val32 = (rlan_ctx->data[7] & MS_LAN_RXQ_CTX_HEAD_M) >> MS_LAN_RXQ_CTX_HEAD_S;
		dev_info(dev, "HEAD: %d\n", val32);

		val32 = (rlan_ctx->data[7] & MS_LAN_RXQ_CTX_TAIL_WRAP_CNT_M) >>
			MS_LAN_RXQ_CTX_TAIL_WRAP_CNT_S;
		dev_info(dev, "TAIL_WRAP_CNT: %d\n", val32);

		val32 = (rlan_ctx->data[7] & MS_LAN_RXQ_CTX_TAIL_M) >> MS_LAN_RXQ_CTX_TAIL_S;
		dev_info(dev, "TAIL: %d\n", val32);
	}

	/* DATA[8]: */
	if (dump_dword_bitmap & BIT(8)) {
		dev_info(dev, "\t raw_data[8]: %X\n", rlan_ctx->data[8]);

		val32 = (rlan_ctx->data[8] & MS_LAN_RXQ_CTX_PRE_USED_WRAP_CNT_M) >>
			MS_LAN_RXQ_CTX_PRE_USED_WRAP_CNT_S;
		dev_info(dev, "PRE_USED_WRAP_CNT: %d\n", val32);

		val32 = (rlan_ctx->data[8] & MS_LAN_RXQ_CTX_PRE_USED_M) >>
			MS_LAN_RXQ_CTX_PRE_USED_S;
		dev_info(dev, "PRE_USED: %d\n", val32);

		val32 = (rlan_ctx->data[8] & MS_LAN_RXQ_CTX_FETCH_WRAP_CNT_M) >>
			MS_LAN_RXQ_CTX_FETCH_WRAP_CNT_S;
		dev_info(dev, "FETCH_WRAP_CNT: %d\n", val32);

		val32 = (rlan_ctx->data[8] & MS_LAN_RXQ_CTX_FETCH_M) >> MS_LAN_RXQ_CTX_FETCH_S;
		dev_info(dev, "FETCH: %d\n\n", val32);
	}

	if (dump_dword_bitmap & BIT(9)) {
		dev_info(dev, "\t raw_data[9]: %X\n", rlan_ctx->data[9]);

		val32 = (rlan_ctx->data[9] & MS_LAN_RXQ_CTX_QMRD_CNT_M) >>
			MS_LAN_RXQ_CTX_QMRD_CNT_S;
		dev_info(dev, "QMRD_CNT: %d\n", val32);

		val32 = (rlan_ctx->data[9] & MS_LAN_RXQ_CTX_REAL_CNT_M) >>
			MS_LAN_RXQ_CTX_REAL_CNT_S;
		dev_info(dev, "REAL_CNT: %d\n\n", val32);
	}

	if (dump_dword_bitmap & BIT(10)) {
		dev_info(dev, "\t raw_data[10]: %X\n", rlan_ctx->data[10]);

		val32 = (rlan_ctx->data[10] & MS_LAN_RXQ_CTX_EST_CNT_M) >> MS_LAN_RXQ_CTX_EST_CNT_S;
		dev_info(dev, "REAL_CNT: %d\n\n", val32);
	}
}

void nse_lan_rxq_ctx_dump(struct nse_hw *hw, u16 qid_pf, u16 qid_abs,
			  struct nse_lan_rxq_ctx *rlan_ctx, unsigned int dump_dword_bitmap)
{
	struct device *dev = nse_hw_to_dev(hw);

	/* don't dump qid because caller don't provid valid one */
	if (qid_pf == -1 || qid_abs == -1)
		dev_info(dev, "=== RXQ context\n");
	else
		dev_info(dev, "=== RXQ context: qid_pf=%d, qid_abs=%d\n", qid_pf, qid_abs);

	if (hw->mac_type == NSE_MAC_TYPE_AMBER)
		rxq_ctx_dump_amber(hw, &rlan_ctx->amber, dump_dword_bitmap);
	else if (hw->mac_type == NSE_MAC_TYPE_MOONSTONE)
		rxq_ctx_dump_ms(hw, &rlan_ctx->ms, dump_dword_bitmap);
}

void nse_lan_rxq_ctx_compare(struct nse_hw *hw, struct nse_lan_rxq_ctx *ctx_0,
			     struct nse_lan_rxq_ctx *ctx_1, unsigned int dword_num)
{
	struct device *dev = nse_hw_to_dev(hw);
	unsigned int dword_num_max = 0;
	unsigned int diff_dword_bitmap = 0;
	unsigned int i;

	if (hw->mac_type == NSE_MAC_TYPE_AMBER)
		dword_num_max = NSE_LAN_RXQ_CTX_LEN_IN_DWORD_AMBER;
	else if (hw->mac_type == NSE_MAC_TYPE_MOONSTONE)
		dword_num_max = NSE_LAN_RXQ_CTX_LEN_IN_DWORD_MS;

	dev_info(dev, "=== Compare RXQ context: ctx_0 is saved one, ctx_1 is newly read one\n");

	for (i = 0; i < dword_num_max && i < dword_num; i++) {
		if (ctx_0->data[i] != ctx_1->data[i])
			diff_dword_bitmap |= BIT(i);
	}

	if (!diff_dword_bitmap) {
		dev_info(dev, "Result: Same\n");
	} else {
		dev_err(dev, "!!! Result: Different, dump different parts\n");

		nse_lan_rxq_ctx_dump(hw, -1, -1, ctx_0, diff_dword_bitmap);

		nse_lan_rxq_ctx_dump(hw, -1, -1, ctx_1, diff_dword_bitmap);
	}
}

static void rxq_ctx_generate_amber(struct nse_ring *ring, struct nse_lan_rxq_ctx_amber *ctx)
{
	struct nse_vsi *vsi = ring->vsi;
	struct nse_pf *pf = vsi->back;
	struct nse_hw *hw = &pf->hw;
	u64 base;

	/* clear the context structure first */
	memset(ctx, 0, sizeof(*ctx));

	/* DATA[0]: BASE_low */

	/* BASE scale down to 16-bytes unit, leaving 60 bits */
	base = (ring->dma >> AMBER_LAN_RXQ_BASE_SHIFT);

	ctx->data[0] = (u32)(base & AMBER_LAN_RXQ_CTX_BASE_LOW_M);

	/* DATA[1]: BASE_high, TPHRDesc, TPHWDesc, Desc_coalesc_en, Cause_en */
	/* explicitly set:
	 *		BASE_high
	 *		Desc_coalesc_en
	 *		Cause_en
	 *
	 * implicit:
	 *		TPHRDesc = 0
	 *		TPHWDesc = 0
	 */
	ctx->data[1] = (u32)((base >> 32) & AMBER_LAN_RXQ_CTX_BASE_HIGH_M);

	if (nse_lan_desc_cache & NSE_LAN_DESC_CACHE_RX)
		ctx->data[1] |= AMBER_LAN_RXQ_CTX_DESC_COALESC_EN_M;

	if (ring->q_vector) {
		ctx->data[1] |= AMBER_LAN_RXQ_CTX_CAUSE_EN_M;
	} else {
		dev_info(nse_pf_to_dev(pf), "VSI(abs_id=%d, rel_id=%d) RXQ(idx=%d) does not have q_vector ?\n",
					vsi->vsi_abs_num, vsi->vsi_rel_num, ring->q_index);
	}

	/* DATA[2]: Msix_idx, DBUFF, HBUFF, CPUID, TS */
	/* explicitly set:
	 *		Msix_idx
	 *		DBUFF
	 *		TS
	 *
	 * implicit:
	 *		HBUFF = 0		# we don't use header split
	 *		CPUID = 0
	 */
	if (ring->q_vector) {
		ctx->data[2] = ((u32)(vsi->base_vector +
				ring->q_vector->v_idx) & AMBER_LAN_RXQ_CTX_MSIX_IDX_M);
	} else {
		dev_info(nse_pf_to_dev(pf), "VSI(abs_id=%d, rel_id=%d) RXQ(idx=%d) does not have q_vector ?\n",
					vsi->vsi_abs_num, vsi->vsi_rel_num, ring->q_index);
	}

	ctx->data[2] |= ((((u32)ring->rx_buf_len >>
			 AMBER_LAN_RXQ_CTX_DBUFF_SHIFT) << AMBER_LAN_RXQ_CTX_DBUFF_S)
							& AMBER_LAN_RXQ_CTX_DBUFF_M);

	if (vsi->type == NSE_VSI_PF)
		ctx->data[2] |= AMBER_LAN_RXQ_CTX_TS_M;

	/* explicitly set:
	 *		QLEN
	 *		DTYPE, DSIZE
	 *		L2TSEL, L2TAG_STRIP_EN
	 *		LRXQTRESH
	 *		Pf_num
	 *		Drop_ctrl
	 *		QTYPE(native or virtio)
	 *
	 * implicit:
	 *		TPHData, TPHHead,
	 *		LL,
	 */

	ctx->data[3] = (ring->count & AMBER_LAN_RXQ_CTX_QLEN_M);

	ctx->data[3] |= (AMBER_LAN_RXQ_CTX_DTYPE_SINGLE_BUF_DESC << AMBER_LAN_RXQ_CTX_DTYPE_S);

	if (vsi->vsi_mode == NSE_VSI_MODE_VIRTIO)
		ctx->data[3] |= (AMBER_LAN_RXQ_CTX_DSIZE_16B << AMBER_LAN_RXQ_CTX_DSIZE_S);
	else
		ctx->data[3] |= (AMBER_LAN_RXQ_CTX_DSIZE_32B << AMBER_LAN_RXQ_CTX_DSIZE_S);

	ctx->data[3] &= ~(AMBER_LAN_RXQ_CTX_L2TSEL_M);

	ctx->data[3] |= AMBER_LAN_RXQ_CTX_L2TAG_STRIP_EN_M;

	/* Rx queue threshold in units of 64 */
	ctx->data[3] |= (1 << AMBER_LAN_RXQ_CTX_LRXQTRESH_S);

	ctx->data[3] |= (((u32)hw->pcore_pf_id <<
			 AMBER_LAN_RXQ_CTX_PF_NUM_S) & AMBER_LAN_RXQ_CTX_PF_NUM_M);

	ctx->data[3] |= (AMBER_LAN_RXQ_CTX_DROP_CTRL_ALLOW_DROP << AMBER_LAN_RXQ_CTX_DROP_CTRL_S);

	if (vsi->vsi_mode == NSE_VSI_MODE_VIRTIO)
		ctx->data[3] |= (AMBER_LAN_RXQ_CTX_QTYPE_VIRTIO << AMBER_LAN_RXQ_CTX_QTYPE_S);
	else
		ctx->data[3] |= (AMBER_LAN_RXQ_CTX_QTYPE_NATIVE << AMBER_LAN_RXQ_CTX_QTYPE_S);

	if (pf->sw_conf.lan_rx_ena_rsc && vsi->sw_conf.lan_rx_ena_rsc &&
	    vsi->vsi_mode == NSE_VSI_MODE_NATIVE) {
		ctx->data[3] |= AMBER_LAN_RXQ_CTX_RSC_EN_M;
#if (MAX_SKB_FRAGS >= 16)
		ctx->data[3] |= (AMBER_LAN_RXQ_CTX_RSC_MAX_BUF_16_BUF <<
				 AMBER_LAN_RXQ_CTX_RSC_MAX_BUF_S);
#elif (MAX_SKB_FRAGS >= 8)
		ctx->data[3] |= (AMBER_LAN_RXQ_CTX_RSC_MAX_BUF_8_BUF <<
				 AMBER_LAN_RXQ_CTX_RSC_MAX_BUF_S);
#elif (MAX_SKB_FRAGS >= 4)
		ctx->data[3] |= (AMBER_LAN_RXQ_CTX_RSC_MAX_BUF_4_BUF <<
				 AMBER_LAN_RXQ_CTX_RSC_MAX_BUF_S);
#else
		ctx->data[3] |= (AMBER_LAN_RXQ_CTX_RSC_MAX_BUF_1_BUF <<
				 AMBER_LAN_RXQ_CTX_RSC_MAX_BUF_S);
#endif

		ctx->data[3] |= AMBER_LAN_RXQ_CTX_RSC_OVERFLOW_M;
	}

	/* DATA[4]: RXDID, HSPLIT_0, HSPLIT_1, VSI, Statistic_cnt_id, Statistic_en */

	ctx->data[4] = (vsi->rxdid << AMBER_LAN_RXQ_CTX_RXDID_S) & AMBER_LAN_RXQ_CTX_RXDID_M;

	ctx->data[4] |= (((u32)vsi->vsi_abs_num <<
			 AMBER_LAN_RXQ_CTX_VSI_S) & AMBER_LAN_RXQ_CTX_VSI_M);

	if (vsi->vsi_mode == NSE_VSI_MODE_VIRTIO) {
		/* DATA[5]: vis_addr_l */
		/* DATA[6]: vis_addr_h */
		ctx->data[5] = (u32)(ring->vtio_dma_drv_addr);
		ctx->data[6] = (u32)(ring->vtio_dma_drv_addr >> 32);

		/* DATA[7]: TAIL, TAIL_WRAP_CNT, HEAD, HEAD_WRAP_CNT */
		/* vtio_head and vtio_tail are 16 bits, including their wrap_cnt inside */
		ctx->data[7] = ((u32)ring->vtio_head << AMBER_LAN_RXQ_CTX_HEAD_S) |
						((u32)ring->vtio_tail << AMBER_LAN_RXQ_CTX_TAIL_S);
	}
}

static void rxq_ctx_generate_ms(struct nse_ring *ring, struct nse_lan_rxq_ctx_ms *ctx)
{
	struct nse_vsi *vsi = ring->vsi;
	struct nse_pf *pf = vsi->back;
	struct nse_hw *hw = &pf->hw;
	u64 base;

	/* clear the context structure first */
	memset(ctx, 0, sizeof(*ctx));

	/* DATA[0]: BASE_low */

	/* BASE scale down to 16-bytes unit, leaving 60 bits */
	base = (ring->dma >> MS_LAN_RXQ_BASE_SHIFT);

	ctx->data[0] = (u32)(base & MS_LAN_RXQ_CTX_BASE_LOW_M);

	/* DATA[1]: BASE_high, TPHRDesc, TPHWDesc, Desc_coalesc_en, Cause_en */
	/* explicitly set:
	 *		BASE_high
	 *		Desc_coalesc_en
	 *		Cause_en
	 *
	 * implicit:
	 *		TPHRDesc = 0
	 *		TPHWDesc = 0
	 */
	ctx->data[1] = (u32)((base >> 32) & MS_LAN_RXQ_CTX_BASE_HIGH_M);

	if (nse_lan_desc_cache & NSE_LAN_DESC_CACHE_RX)
		ctx->data[1] |= MS_LAN_RXQ_CTX_DESC_COALESC_EN_M;

	if (ring->q_vector) {
		ctx->data[1] |= MS_LAN_RXQ_CTX_CAUSE_EN_M;
	} else {
		dev_info(nse_pf_to_dev(pf), "VSI(abs_id=%d, rel_id=%d) RXQ(idx=%d) does not have q_vector ?\n",
					vsi->vsi_abs_num, vsi->vsi_rel_num, ring->q_index);
	}

	/* DATA[2]: Msix_idx, DBUFF, HBUFF, CPUID, TS */
	/* explicitly set:
	 *		Msix_idx
	 *		DBUFF
	 *		TS
	 *
	 * implicit:
	 *		HBUFF = 0		# we don't use header split
	 *		CPUID = 0
	 */
	if (ring->q_vector) {
		ctx->data[2] = ((u32)(vsi->base_vector +
				ring->q_vector->v_idx) & MS_LAN_RXQ_CTX_MSIX_IDX_M);
	} else {
		dev_info(nse_pf_to_dev(pf), "VSI(abs_id=%d, rel_id=%d) RXQ(idx=%d) does not have q_vector ?\n",
					vsi->vsi_abs_num, vsi->vsi_rel_num, ring->q_index);
	}

	ctx->data[2] |= ((((u32)ring->rx_buf_len >>
			 MS_LAN_RXQ_CTX_DBUFF_SHIFT) << MS_LAN_RXQ_CTX_DBUFF_S)
							& MS_LAN_RXQ_CTX_DBUFF_M);

	if (vsi->type == NSE_VSI_PF)
		ctx->data[2] |= MS_LAN_RXQ_CTX_TS_M;

	/* explicitly set:
	 *		QLEN
	 *		DTYPE, DSIZE
	 *		L2TSEL, L2TAG_STRIP_EN
	 *		LRXQTRESH
	 *		Pf_num
	 *		Drop_ctrl
	 *		QTYPE(native or virtio)
	 *
	 * implicit:
	 *		TPHData, TPHHead,
	 *		LL,
	 */

	ctx->data[3] = (ring->count & MS_LAN_RXQ_CTX_QLEN_M);

	ctx->data[3] |= (MS_LAN_RXQ_CTX_DSIZE_32B << MS_LAN_RXQ_CTX_DSIZE_S);

	ctx->data[3] &= ~(MS_LAN_RXQ_CTX_L2TSEL_M);

	ctx->data[3] |= MS_LAN_RXQ_CTX_L2TAG_STRIP_EN_M;

	/* Rx queue threshold in units of 64 */
	ctx->data[3] |= (1 << MS_LAN_RXQ_CTX_LRXQTRESH_S);

	ctx->data[3] |= (((u32)hw->pcore_pf_id <<
			 MS_LAN_RXQ_CTX_PF_NUM_S) & MS_LAN_RXQ_CTX_PF_NUM_M);

	ctx->data[3] |= (MS_LAN_RXQ_CTX_DROP_CTRL_ALLOW_DROP << MS_LAN_RXQ_CTX_DROP_CTRL_S);

	/* DATA[4]: RXDID, HSPLIT_0, HSPLIT_1, VSI, Statistic_cnt_id, Statistic_en */

	ctx->data[4] |= (((u32)vsi->vsi_abs_num << MS_LAN_RXQ_CTX_VSI_S) & MS_LAN_RXQ_CTX_VSI_M);
}

static void nse_lan_rxq_ctx_generate(struct nse_ring *ring, struct nse_lan_rxq_ctx *ctx)
{
	struct nse_hw *hw = &ring->pf->hw;

	if (hw->mac_type == NSE_MAC_TYPE_AMBER) {
		rxq_ctx_generate_amber(ring, &ctx->amber);
		ctx->ctx_data_len = NSE_LAN_RXQ_CTX_LEN_IN_DWORD_AMBER;
	} else if (hw->mac_type == NSE_MAC_TYPE_MOONSTONE) {
		rxq_ctx_generate_ms(ring, &ctx->ms);
		ctx->ctx_data_len = NSE_LAN_RXQ_CTX_LEN_IN_DWORD_MS;
	}
}

static void nse_lan_rxq_determine_irqll(struct nse_hw *hw, struct nse_vsi *vsi,
					struct nse_ring *ring);

/**
 * nse_setup_rx_ctx - Configure a receive ring context
 * @ring: The Rx ring to configure
 *
 * Configure the Rx descriptor ring in RLAN context.
 */
static int nse_setup_rx_ctx(struct nse_ring *ring)
{
	struct nse_vsi *vsi = ring->vsi;
	struct nse_lan_rxq_ctx rlan_ctx;
	struct nse_pf *pf = vsi->back;
	struct nse_hw *hw = &pf->hw;
	u16 pf_q;
	u16 rxq_abs_id;
	int err;

	/* intentionally, do not use: vsi->vsi_rxq_space_start + ring->q_index; */
	/* rel ID inside PF rxq space */
	pf_q = ring->reg_idx;
	rxq_abs_id = pf->lan_rxq_space_start + pf_q;		/* abs ID insider LAN rxq space */

	nse_lan_rxq_ctx_generate(ring, &rlan_ctx);

	if (hw->debug_mask & NSE_DBG_LAN)
		nse_lan_rxq_ctx_dump(hw, pf_q, rxq_abs_id, &rlan_ctx, 0xFF);

	/* here, for satety, we set TAIL to 0 before write rxq context */
	if (!(vsi->type == NSE_VSI_VF || vsi->type == NSE_VSI_ADI)) {
		/* init queue specific tail register */
		ring->tail = hw->hw_addr + NSE_REG_QRX_TAIL(pf_q);
		writel(0, ring->tail);
	}

	if (nse_lan_disable_q_before_cfg) {
		(void)nse_aq_lan_disable_rxq(hw, rxq_abs_id,
				ring->already_in_irqll ? ring->irqll_msix :
					NSE_AQC_CONF_IRQLL_INVALID_MSIX);

		ring->already_in_irqll = false;
	}

	err = nse_write_rxq_ctx(hw, vsi, &rlan_ctx, rxq_abs_id);
	if (err) {
		dev_err(nse_pf_to_dev(pf), "[%s, %d] FAIL: Write LAN RXQ context for RXQ (qid_abs=%d), error: %d\n",
									__func__, __LINE__,
									rxq_abs_id, err);
		return -EIO;
	}

	memcpy(&ring->saved_lan_rxq_ctx, &rlan_ctx, sizeof(rlan_ctx));

	nse_lan_rxq_determine_irqll(hw, vsi, ring);

	/* here make a check */
	if (hw->debug_mask & NSE_DBG_LAN) {
		err = nse_read_rxq_ctx(hw, &rlan_ctx, rxq_abs_id);
		if (err) {
			dev_err(nse_pf_to_dev(pf), "[%s, %d] FAIL: Read LAN RXQ context for RXQ (qid_abs=%d), error: %d\n",
										__func__,
											__LINE__,
										rxq_abs_id, err);
		} else {
			nse_lan_rxq_ctx_compare(hw, &ring->saved_lan_rxq_ctx, &rlan_ctx,
						NSE_LAN_RXQ_CTX_LEN_IN_DWORD_MAX);
		}

		/* we continue, later can check in debugfs */
		err = 0;
	}

	if (vsi->type == NSE_VSI_VF || vsi->type == NSE_VSI_ADI)
		return 0;

	/* configure Rx buffer alignment */
	if (!vsi->netdev || test_bit(NSE_FLAG_LEGACY_RX, vsi->back->flags))
		nse_clear_ring_build_skb_ena(ring);
	else
		nse_set_ring_build_skb_ena(ring);

	if (nse_vsi_is_any_xdp_enabled(vsi))
		nse_clear_ring_build_skb_ena(ring);

	/* again, init queue specific tail register */
	ring->tail = hw->hw_addr + NSE_REG_QRX_TAIL(pf_q);
	writel(0, ring->tail);

	return 0;
}

static bool rxq_is_need_irqll_amber(struct nse_lan_rxq_ctx_amber *rctx, u16 *msix)
{
	bool ret = false;

	if (rctx->data[1] & AMBER_LAN_RXQ_CTX_DESC_COALESC_EN_M)	/* q.ctxt.coals_en */
		ret = true;

	if (rctx->data[3] & AMBER_LAN_RXQ_CTX_RSC_EN_M)		/* q.ctxt.rsc_en */
		ret = true;

	if ((rctx->data[3] & AMBER_LAN_RXQ_CTX_QTYPE_M) &&	/* QTYPE_VIRTIO = 0x1 */
		(rctx->data[5] || rctx->data[6]))			/* q.ctxt.virt_vis_en */
		ret = true;

	/* relative ID inside PCI function */
	if (ret)
		*msix = (rctx->data[2] & AMBER_LAN_RXQ_CTX_MSIX_IDX_M) >>
			AMBER_LAN_RXQ_CTX_MSIX_IDX_S;

	return ret;
}

static bool rxq_is_need_irqll_ms(struct nse_lan_rxq_ctx_ms *rctx, u16 *msix)
{
	bool ret = false;

	if (rctx->data[1] & MS_LAN_RXQ_CTX_DESC_COALESC_EN_M)	/* q.ctxt.coals_en */
		ret = true;

	/* relative ID inside PCI function */
	if (ret)
		*msix = (rctx->data[2] & MS_LAN_RXQ_CTX_MSIX_IDX_M) >> MS_LAN_RXQ_CTX_MSIX_IDX_S;

	return ret;
}

static bool rxq_is_need_irqll(struct nse_hw *hw, struct nse_lan_rxq_ctx *rctx, u16 *msix)
{
	if (hw->mac_type == NSE_MAC_TYPE_AMBER)
		return rxq_is_need_irqll_amber(&rctx->amber, msix);
	else if (hw->mac_type == NSE_MAC_TYPE_MOONSTONE)
		return rxq_is_need_irqll_ms(&rctx->ms, msix);
	else
		return false;
}

static void nse_lan_rxq_determine_irqll(struct nse_hw *hw, struct nse_vsi *vsi,
					struct nse_ring *ring)
{
	struct nse_pf *pf = vsi->back;
	struct nse_vfs *vfs = &pf->vfs;
	struct nse_vf *vf;
	struct nse_lan_rxq_ctx *rctx = &ring->saved_lan_rxq_ctx;
	u16 msix;

	ring->need_irqll = false;
	ring->irqll_msix = NSE_AQC_CONF_IRQLL_INVALID_MSIX;

	if (nse_lan_no_irqll)
		goto out;

	if (!rxq_is_need_irqll(hw, rctx, &msix))
		goto out;

	if (vsi->type == NSE_VSI_VF) {
		vf = vsi->vf;
		if (!vf)
			goto out;

		msix += pf->irq_space_start;
		msix += pf->sriov_base_vector;
		msix += (vfs->num_msix_per * vf->vf_id);
	} else {
		msix += pf->irq_space_start;
	}

	ring->need_irqll = true;
	ring->irqll_msix = msix;

out:
	nse_debug(hw, NSE_DBG_LAN, "[%s] VSI(abs_id=%d), RXQ(idx=%d, abs_id=%d): need_irqll=%d, irqll_msix=%d\n",
								__func__, vsi->vsi_abs_num,
									ring->q_index, ring->abs_id,
								ring->need_irqll, ring->irqll_msix);
}

int nse_cfg_rxq_irqll(struct nse_ring *ring, bool add)
{
	struct nse_vsi *vsi = ring->vsi;
	struct nse_pf *pf = vsi->back;
	struct nse_hw *hw = &pf->hw;
	u16 rxq_abs_id;
	u8 op;
	enum nse_status status;
	int ret = 0;

	if (!ring->need_irqll)
		goto out;

	op = add ? NSE_AQC_CONF_IRQLL_OP_ADD : NSE_AQC_CONF_IRQLL_OP_DEL;

	/* reg_idx is rel ID inside PF rxq space,
	 * compute abs ID insider LAN rxq space
	 */
	rxq_abs_id = pf->lan_rxq_space_start + ring->reg_idx;

	nse_debug(hw, NSE_DBG_LAN, "[%s]: conf_irqll_lanq(op=%d, qtype=rxq, q_abs_id=%d, irqll_msix=%d)\n",
								__func__, op, rxq_abs_id,
									ring->irqll_msix);

	status = nse_conf_irqll_lanq(hw, op, NSE_AQC_CONF_IRQLL_QTYPE_LAN_RXQ,
									rxq_abs_id,
										ring->irqll_msix);
	if (status) {
		dev_err(nse_pf_to_dev(pf), "[%s] FAIL: conf_irqll_lanq(op=%d, qtype=rxq, q_abs_id=%d, irqll_msix=%d)\n",
								__func__, op, rxq_abs_id,
									ring->irqll_msix);
		ret = -EIO;
	}

out:
	return ret;
}

static void txq_ctx_dump_amber(struct nse_hw *hw, struct nse_lan_txq_ctx_amber *tlan_ctx,
			       unsigned int dump_dword_bitmap)
{
	struct device *dev = nse_hw_to_dev(hw);
	u64 val64;
	u32 val32;

	/* DATA[0]: BASE_low */
	/* DATA[1]: BASE_high, Port_id, Port_lock, Port_vld */

	if ((dump_dword_bitmap & BIT(0)) ||
		(dump_dword_bitmap & BIT(1))) {
		dev_info(dev, "\t raw_data[0]: %X\n", tlan_ctx->data[0]);
		dev_info(dev, "\t raw_data[1]: %X\n", tlan_ctx->data[1]);

		/* get the base */
		val64 = tlan_ctx->data[1] & AMBER_LAN_TXQ_CTX_BASE_HIGH_M;
		val64 <<= 32;
		val64 |= tlan_ctx->data[0];
		val64 <<= AMBER_LAN_TXQ_BASE_SHIFT;

		dev_info(dev, "BASE: 0x%lX\n", (unsigned long)val64);

		val32 = (tlan_ctx->data[1] & AMBER_LAN_TXQ_CTX_PORT_ID_M) >>
			AMBER_LAN_TXQ_CTX_PORT_ID_S;
		dev_info(dev, "PORT_ID: %d\n", val32);

		val32 = (tlan_ctx->data[1] & AMBER_LAN_TXQ_CTX_PORT_LOCK_M) >>
			AMBER_LAN_TXQ_CTX_PORT_LOCK_S;
		dev_info(dev, "PORT_LOCK: %d\n", val32);

		val32 = (tlan_ctx->data[1] & AMBER_LAN_TXQ_CTX_PORT_VLD_M) >>
			AMBER_LAN_TXQ_CTX_PORT_VLD_S;
		dev_info(dev, "PORT_VLD: %d\n\n", val32);
	}

	/* DATA[2]: TC, SRC_VSI, TSYN_ENA, CPUID, WB_mode, TPHRDdesc, TPHRDdata, TPHWRdesc */

	if (dump_dword_bitmap & BIT(2)) {
		dev_info(dev, "\t raw_data[2]: %X\n", tlan_ctx->data[2]);

		val32 = (tlan_ctx->data[2] & AMBER_LAN_TXQ_CTX_TC_M) >> AMBER_LAN_TXQ_CTX_TC_S;
		dev_info(dev, "TC: %d\n", val32);

		val32 = (tlan_ctx->data[2] & AMBER_LAN_TXQ_CTX_SRC_VSI_M) >>
			AMBER_LAN_TXQ_CTX_SRC_VSI_S;
		dev_info(dev, "SRC_VSI: %d\n", val32);

		val32 = (tlan_ctx->data[2] & AMBER_LAN_TXQ_CTX_TSYN_ENA_M) >>
			AMBER_LAN_TXQ_CTX_TSYN_ENA_S;
		dev_info(dev, "TSYN_ENA: %d\n", val32);

		val32 = (tlan_ctx->data[2] & AMBER_LAN_TXQ_CTX_CPUID_M) >>
			AMBER_LAN_TXQ_CTX_CPUID_S;
		dev_info(dev, "CPUID: %d\n", val32);

		val32 = (tlan_ctx->data[2] & AMBER_LAN_TXQ_CTX_WB_MODE_M) >>
			AMBER_LAN_TXQ_CTX_WB_MODE_S;
		dev_info(dev, "WB_MODE: %d\n", val32);

		val32 = (tlan_ctx->data[2] & AMBER_LAN_TXQ_CTX_TPHRDDESC_M) >>
			AMBER_LAN_TXQ_CTX_TPHRDDESC_S;
		dev_info(dev, "TPHRDDESC: %d\n", val32);

		val32 = (tlan_ctx->data[2] & AMBER_LAN_TXQ_CTX_TPHRDDATA_M) >>
			AMBER_LAN_TXQ_CTX_TPHRDDATA_S;
		dev_info(dev, "TPHRDDATA: %d\n", val32);

		val32 = (tlan_ctx->data[2] & AMBER_LAN_TXQ_CTX_TPHWRDESC_M) >>
			AMBER_LAN_TXQ_CTX_TPHWRDESC_S;
		dev_info(dev, "TPHWRDESC: %d\n\n", val32);
	}

	/* DATA[3]: CMPQ_ID, Qnum_in_func */

	if (dump_dword_bitmap & BIT(3)) {
		dev_info(dev, "\t raw_data[3]: %X\n", tlan_ctx->data[3]);

		val32 = (tlan_ctx->data[3] & AMBER_LAN_TXQ_CTX_CMPQ_ID_M) >>
			AMBER_LAN_TXQ_CTX_CMPQ_ID_S;
		dev_info(dev, "CMPQ_ID: %d\n", val32);

		val32 = (tlan_ctx->data[3] & AMBER_LAN_TXQ_CTX_QNUM_IN_FUNC_M) >>
			AMBER_LAN_TXQ_CTX_QNUM_IN_FUNC_S;
		dev_info(dev, "QNUM_IN_FUNC: %d\n\n", val32);
	}

	/* DATA[4]: Queue length, TSO_enabled_queue, Queue_type, LL */
	if (dump_dword_bitmap & BIT(4)) {
		dev_info(dev, "\t raw_data[4]: %X\n", tlan_ctx->data[4]);

		val32 = (tlan_ctx->data[4] & AMBER_LAN_TXQ_CTX_QLEN_M) >> AMBER_LAN_TXQ_CTX_QLEN_S;
		dev_info(dev, "QLEN: %d\n", val32);

		val32 = (tlan_ctx->data[4] & AMBER_LAN_TXQ_CTX_TSO_ENA_QUEUE_M) >>
			AMBER_LAN_TXQ_CTX_TSO_ENA_QUEUE_S;
		dev_info(dev, "TSO_ENA: %d\n", val32);

		val32 = (tlan_ctx->data[4] & AMBER_LAN_TXQ_CTX_QTYPE_M) >>
			AMBER_LAN_TXQ_CTX_QTYPE_S;
		dev_info(dev, "QTYPE: %d\n", val32);

		val32 = (tlan_ctx->data[4] & AMBER_LAN_TXQ_CTX_LL_M) >> AMBER_LAN_TXQ_CTX_LL_S;
		dev_info(dev, "LL: %d\n\n", val32);
	}

	/*  DATA[5]: MSIx_idx, Cause_en, PF_NUM, Local_desc, desc_coalesce_en, statistic_en,
	 * statistic_cnt_id
	 */

	if (dump_dword_bitmap & BIT(5)) {
		dev_info(dev, "\t raw_data[5]: %X\n", tlan_ctx->data[5]);

		val32 = (tlan_ctx->data[5] & AMBER_LAN_TXQ_CTX_MSIX_IDX_M) >>
			AMBER_LAN_TXQ_CTX_MSIX_IDX_S;
		dev_info(dev, "MSIX_IDX: %d\n", val32);

		val32 = (tlan_ctx->data[5] & AMBER_LAN_TXQ_CTX_PF_ID_M) >>
			AMBER_LAN_TXQ_CTX_PF_ID_S;
		dev_info(dev, "PF_ID: %d\n", val32);

		val32 = (tlan_ctx->data[5] & AMBER_LAN_TXQ_CTX_CAUSE_EN_M) >>
			AMBER_LAN_TXQ_CTX_CAUSE_EN_S;
		dev_info(dev, "CAUSE_EN: %d\n", val32);

		val32 = (tlan_ctx->data[5] & AMBER_LAN_TXQ_CTX_LOCAL_DESC_M) >>
			AMBER_LAN_TXQ_CTX_LOCAL_DESC_S;
		dev_info(dev, "LOCAL_DESC: %d\n", val32);

		val32 = (tlan_ctx->data[5] & AMBER_LAN_TXQ_CTX_DESC_COALESCE_EN_M) >>
			AMBER_LAN_TXQ_CTX_DESC_COALESCE_EN_S;
		dev_info(dev, "DESC_COALESCE_EN: %d\n", val32);

		val32 = (tlan_ctx->data[5] & AMBER_LAN_TXQ_CTX_STATS_EN_M) >>
			AMBER_LAN_TXQ_CTX_STATS_EN_S;
		dev_info(dev, "STATS_EN: %d\n", val32);

		val32 = (tlan_ctx->data[5] & AMBER_LAN_TXQ_CTX_STATS_CNT_ID_M) >>
			AMBER_LAN_TXQ_CTX_STATS_CNT_ID_S;
		dev_info(dev, "STATS_CNT_ID: %d\n\n", val32);
	}

	if (dump_dword_bitmap & BIT(6)) {
		dev_info(dev, "\t raw_data[6]: %X\n", tlan_ctx->data[6]);

		dev_info(dev, "vis_addr_lsb: %X\n", tlan_ctx->data[6]);
	}

	if (dump_dword_bitmap & BIT(7)) {
		dev_info(dev, "\t raw_data[7]: %X\n", tlan_ctx->data[7]);

		dev_info(dev, "vis_addr_msb: %X\n", tlan_ctx->data[7]);
	}

	if (dump_dword_bitmap & BIT(8)) {
		dev_info(dev, "\t raw_data[8]: %X\n", tlan_ctx->data[8]);

		val32 = (tlan_ctx->data[8] & AMBER_LAN_TXQ_CTX_DEV_WRAP_CNT_M) >>
			AMBER_LAN_TXQ_CTX_DEV_WRAP_CNT_S;
		dev_info(dev, "DEV_WRAP_CNT: %d\n", val32);

		val32 = (tlan_ctx->data[8] & AMBER_LAN_TXQ_CTX_WBPTR_M) >>
			AMBER_LAN_TXQ_CTX_WBPTR_S;
		dev_info(dev, "WBPTR: %d\n", val32);

		val32 = (tlan_ctx->data[8] & AMBER_LAN_TXQ_CTX_DRV_WRAP_CNT_M) >>
			AMBER_LAN_TXQ_CTX_DRV_WRAP_CNT_S;
		dev_info(dev, "DRV_WRAP_CNT: %d\n", val32);

		val32 = (tlan_ctx->data[8] & AMBER_LAN_TXQ_CTX_WPTR_M) >> AMBER_LAN_TXQ_CTX_WPTR_S;
		dev_info(dev, "WPTR: %d\n\n", val32);
	}

	if (dump_dword_bitmap & BIT(9)) {
		dev_info(dev, "\t raw_data[9]: %X\n", tlan_ctx->data[9]);

		val32 = (tlan_ctx->data[9] & AMBER_LAN_TXQ_CTX_RPTR_M) >> AMBER_LAN_TXQ_CTX_RPTR_S;
		dev_info(dev, "RPTR: %d\n", val32);

		val32 = (tlan_ctx->data[9] & AMBER_LAN_TXQ_CTX_FPTR_M) >> AMBER_LAN_TXQ_CTX_FPTR_S;
		dev_info(dev, "FPTR: %d\n\n", val32);
	}

	if (dump_dword_bitmap & BIT(10)) {
		dev_info(dev, "\t raw_data[10]: %X\n", tlan_ctx->data[10]);

		val32 = (tlan_ctx->data[10] & AMBER_LAN_TXQ_CTX_RCV_QUANTA_CNT_UNFL_M) >>
			AMBER_LAN_TXQ_CTX_RCV_QUANTA_CNT_UNFL_S;
		dev_info(dev, "RCV_QUANTA_CNT_UNFL: %d\n", val32);

		val32 = (tlan_ctx->data[10] & AMBER_LAN_TXQ_CTX_RCV_QUANTA_BYTE_M) >>
			AMBER_LAN_TXQ_CTX_RCV_QUANTA_BYTE_S;
		dev_info(dev, "RCV_QUANTA_BYTE: %d\n", val32);
	}

	if (dump_dword_bitmap & BIT(11)) {
		dev_info(dev, "\t raw_data[11]: %X\n", tlan_ctx->data[11]);

		val32 = (tlan_ctx->data[11] & AMBER_LAN_TXQ_CTX_ADJ_CNT_M) >>
			AMBER_LAN_TXQ_CTX_ADJ_CNT_S;
		dev_info(dev, "ADJ_CNT: %d\n\n", val32);
	}

	if (dump_dword_bitmap & BIT(12)) {
		dev_info(dev, "\t raw_data[12]: %X\n", tlan_ctx->data[12]);

		val32 = (tlan_ctx->data[12] & AMBER_LAN_TXQ_CTX_ACC_QUANTA_CONSUME_DESC_CNT_M) >>
			AMBER_LAN_TXQ_CTX_ACC_QUANTA_CONSUME_DESC_CNT_S;
		dev_info(dev, "ACC_QUANTA_CONSUME_DESC_CNT: %d\n", val32);

		val32 = (tlan_ctx->data[12] & AMBER_LAN_TXQ_CTX_ACC_QUANTA_CNT_M) >>
			AMBER_LAN_TXQ_CTX_ACC_QUANTA_CNT_S;
		dev_info(dev, "ACC_QUANTA_CNT: %d\n", val32);

		val32 = (tlan_ctx->data[12] & AMBER_LAN_TXQ_CTX_PREDICT_DESC_NUM_M) >>
			AMBER_LAN_TXQ_CTX_PREDICT_DESC_NUM_S;
		dev_info(dev, "PREDICT_DESC_NUM: %d\n\n", val32);
	}

	if (dump_dword_bitmap & BIT(13)) {
		dev_info(dev, "\t raw_data[13]: %X\n", tlan_ctx->data[13]);

		val32 = (tlan_ctx->data[13] & AMBER_LAN_TXQ_CTX_SUM_DESC_BSIZE_M) >>
			AMBER_LAN_TXQ_CTX_SUM_DESC_BSIZE_S;
		dev_info(dev, "SUM_DESC_BSIZE: %d\n", val32);
	}

	if (dump_dword_bitmap & BIT(14)) {
		dev_info(dev, "\t raw_data[14]: %X\n", tlan_ctx->data[14]);

		val32 = (tlan_ctx->data[14] & AMBER_LAN_TXQ_CTX_PENDING_BYTE_M) >>
			AMBER_LAN_TXQ_CTX_PENDING_BYTE_S;
		dev_info(dev, "PENDING_BYTE: %d\n", val32);
	}
}

static void txq_ctx_dump_ms(struct nse_hw *hw, struct nse_lan_txq_ctx_ms *tlan_ctx,
			    unsigned int dump_dword_bitmap)
{
	struct device *dev = nse_hw_to_dev(hw);
	u64 val64;
	u32 val32;

	/* DATA[0]: */
	/* DATA[1]: */
	if ((dump_dword_bitmap & BIT(0)) ||
		(dump_dword_bitmap & BIT(1))) {
		dev_info(dev, "\t raw_data[0]: %X\n", tlan_ctx->data[0]);
		dev_info(dev, "\t raw_data[1]: %X\n", tlan_ctx->data[1]);

		/* get the base */
		val64 = tlan_ctx->data[1] & MS_LAN_TXQ_CTX_BASE_HIGH_M;
		val64 <<= 32;
		val64 |= tlan_ctx->data[0];
		val64 <<= MS_LAN_TXQ_BASE_SHIFT;

		dev_info(dev, "BASE: 0x%lX\n", (unsigned long)val64);
	}

	/* DATA[2]: */

	if (dump_dword_bitmap & BIT(2)) {
		dev_info(dev, "\t raw_data[2]: %X\n", tlan_ctx->data[2]);

		val32 = (tlan_ctx->data[2] & MS_LAN_TXQ_CTX_TPHWRDESC_M) >>
			MS_LAN_TXQ_CTX_TPHWRDESC_S;
		dev_info(dev, "TPHWRDESC: %d\n\n", val32);

		val32 = (tlan_ctx->data[2] & MS_LAN_TXQ_CTX_TPHRDDATA_M) >>
			MS_LAN_TXQ_CTX_TPHRDDATA_S;
		dev_info(dev, "TPHRDDATA: %d\n", val32);

		val32 = (tlan_ctx->data[2] & MS_LAN_TXQ_CTX_TPHRDDESC_M) >>
			MS_LAN_TXQ_CTX_TPHRDDESC_S;
		dev_info(dev, "TPHRDDESC: %d\n", val32);

		val32 = (tlan_ctx->data[2] & MS_LAN_TXQ_CTX_WB_MODE_M) >> MS_LAN_TXQ_CTX_WB_MODE_S;
		dev_info(dev, "WB_MODE: %d\n", val32);

		val32 = (tlan_ctx->data[2] & MS_LAN_TXQ_CTX_CPUID_M) >> MS_LAN_TXQ_CTX_CPUID_S;
		dev_info(dev, "CPUID: %d\n", val32);

		val32 = (tlan_ctx->data[2] & MS_LAN_TXQ_CTX_TSYN_ENA_M) >>
			MS_LAN_TXQ_CTX_TSYN_ENA_S;
		dev_info(dev, "TSYN_ENA: %d\n", val32);

		val32 = (tlan_ctx->data[2] & MS_LAN_TXQ_CTX_SRC_VSI_M) >> MS_LAN_TXQ_CTX_SRC_VSI_S;
		dev_info(dev, "SRC_VSI: %d\n", val32);

		val32 = (tlan_ctx->data[2] & MS_LAN_TXQ_CTX_TC_M) >> MS_LAN_TXQ_CTX_TC_S;
		dev_info(dev, "TC: %d\n", val32);
	}

	/* DATA[3]: */

	if (dump_dword_bitmap & BIT(3)) {
		dev_info(dev, "\t raw_data[3]: %X\n", tlan_ctx->data[3]);

		val32 = (tlan_ctx->data[3] & MS_LAN_TXQ_CTX_QNUM_IN_FUNC_M) >>
			MS_LAN_TXQ_CTX_QNUM_IN_FUNC_S;
		dev_info(dev, "QNUM_IN_FUNC: %d\n\n", val32);

		val32 = (tlan_ctx->data[3] & MS_LAN_TXQ_CTX_CMPQ_ID_M) >> MS_LAN_TXQ_CTX_CMPQ_ID_S;
		dev_info(dev, "CMPQ_ID: %d\n", val32);
	}

	/* DATA[4]: */
	if (dump_dword_bitmap & BIT(4)) {
		dev_info(dev, "\t raw_data[4]: %X\n", tlan_ctx->data[4]);

		val32 = (tlan_ctx->data[4] & MS_LAN_TXQ_CTX_LL_M) >> MS_LAN_TXQ_CTX_LL_S;
		dev_info(dev, "LL: %d\n\n", val32);

		val32 = (tlan_ctx->data[4] & MS_LAN_TXQ_CTX_QTYPE_M) >> MS_LAN_TXQ_CTX_QTYPE_S;
		dev_info(dev, "QTYPE: %d\n", val32);

		val32 = (tlan_ctx->data[4] & MS_LAN_TXQ_CTX_TSO_ENA_QUEUE_M) >>
			MS_LAN_TXQ_CTX_TSO_ENA_QUEUE_S;
		dev_info(dev, "TSO_ENA: %d\n", val32);

		val32 = (tlan_ctx->data[4] & MS_LAN_TXQ_CTX_QLEN_M) >> MS_LAN_TXQ_CTX_QLEN_S;
		dev_info(dev, "QLEN: %d\n", val32);
	}

	/*  DATA[5]: MSIx_idx, Cause_en, PF_NUM, Local_desc, desc_coalesce_en, statistic_en,
	 * statistic_cnt_id
	 */

	if (dump_dword_bitmap & BIT(5)) {
		dev_info(dev, "\t raw_data[5]: %X\n", tlan_ctx->data[5]);

		val32 = (tlan_ctx->data[5] & MS_LAN_TXQ_CTX_DESC_COALESCE_EN_M) >>
			MS_LAN_TXQ_CTX_DESC_COALESCE_EN_S;
		dev_info(dev, "DESC_COALESCE_EN: %d\n", val32);

		val32 = (tlan_ctx->data[5] & MS_LAN_TXQ_CTX_CAUSE_EN_M) >>
			MS_LAN_TXQ_CTX_CAUSE_EN_S;
		dev_info(dev, "CAUSE_EN: %d\n", val32);

		val32 = (tlan_ctx->data[5] & MS_LAN_TXQ_CTX_PF_ID_M) >> MS_LAN_TXQ_CTX_PF_ID_S;
		dev_info(dev, "PF_ID: %d\n", val32);

		val32 = (tlan_ctx->data[5] & MS_LAN_TXQ_CTX_MSIX_IDX_M) >>
			MS_LAN_TXQ_CTX_MSIX_IDX_S;
		dev_info(dev, "MSIX_IDX: %d\n", val32);
	}

	if (dump_dword_bitmap & BIT(8)) {
		dev_info(dev, "\t raw_data[8]: %X\n", tlan_ctx->data[8]);

		val32 = (tlan_ctx->data[8] & MS_LAN_TXQ_CTX_DEV_WRAP_CNT_M) >>
			MS_LAN_TXQ_CTX_DEV_WRAP_CNT_S;
		dev_info(dev, "DEV_WRAP_CNT: %d\n", val32);

		val32 = (tlan_ctx->data[8] & MS_LAN_TXQ_CTX_WBPTR_M) >> MS_LAN_TXQ_CTX_WBPTR_S;
		dev_info(dev, "WBPTR: %d\n", val32);

		val32 = (tlan_ctx->data[8] & MS_LAN_TXQ_CTX_DRV_WRAP_CNT_M) >>
			MS_LAN_TXQ_CTX_DRV_WRAP_CNT_S;
		dev_info(dev, "DRV_WRAP_CNT: %d\n", val32);

		val32 = (tlan_ctx->data[8] & MS_LAN_TXQ_CTX_WPTR_M) >> MS_LAN_TXQ_CTX_WPTR_S;
		dev_info(dev, "WPTR: %d\n\n", val32);
	}

	if (dump_dword_bitmap & BIT(9)) {
		dev_info(dev, "\t raw_data[9]: %X\n", tlan_ctx->data[9]);

		val32 = (tlan_ctx->data[9] & MS_LAN_TXQ_CTX_RPTR_M) >> MS_LAN_TXQ_CTX_RPTR_S;
		dev_info(dev, "RPTR: %d\n", val32);

		val32 = (tlan_ctx->data[9] & MS_LAN_TXQ_CTX_FPTR_M) >> MS_LAN_TXQ_CTX_FPTR_S;
		dev_info(dev, "FPTR: %d\n\n", val32);
	}

	if (dump_dword_bitmap & BIT(10)) {
		dev_info(dev, "\t raw_data[10]: %X\n", tlan_ctx->data[10]);

		val32 = (tlan_ctx->data[10] & MS_LAN_TXQ_CTX_RCV_QUANTA_CNT_UNFL_M) >>
			MS_LAN_TXQ_CTX_RCV_QUANTA_CNT_UNFL_S;
		dev_info(dev, "RCV_QUANTA_CNT_UNFL: %d\n", val32);

		val32 = (tlan_ctx->data[10] & MS_LAN_TXQ_CTX_RCV_QUANTA_BYTE_M) >>
			MS_LAN_TXQ_CTX_RCV_QUANTA_BYTE_S;
		dev_info(dev, "RCV_QUANTA_BYTE: %d\n", val32);
	}
}

void nse_lan_txq_ctx_dump(struct nse_hw *hw, u16 qid_pf, u16 qid_abs,
			  struct nse_lan_txq_ctx *tlan_ctx, unsigned int dump_dword_bitmap)
{
	struct device *dev = nse_hw_to_dev(hw);

	/* don't dump qid because caller don't provid valid one */
	if (qid_pf == -1 || qid_abs == -1)
		dev_info(dev, "=== TXQ context\n");
	else
		dev_info(dev, "=== TXQ context: qid_pf=%d, qid_abs=%d\n", qid_pf, qid_abs);

	if (hw->mac_type == NSE_MAC_TYPE_AMBER)
		txq_ctx_dump_amber(hw, &tlan_ctx->amber, dump_dword_bitmap);
	else if (hw->mac_type == NSE_MAC_TYPE_MOONSTONE)
		txq_ctx_dump_ms(hw, &tlan_ctx->ms, dump_dword_bitmap);
}

void nse_lan_txq_ctx_compare(struct nse_hw *hw, struct nse_lan_txq_ctx *ctx_0,
			     struct nse_lan_txq_ctx *ctx_1, unsigned int dword_num)
{
	struct device *dev = nse_hw_to_dev(hw);
	unsigned int dword_num_max = 0;
	unsigned int diff_dword_bitmap = 0;
	unsigned int i;

	if (hw->mac_type == NSE_MAC_TYPE_AMBER)
		dword_num_max = NSE_LAN_TXQ_CTX_LEN_IN_DWORD_AMBER;
	else if (hw->mac_type == NSE_MAC_TYPE_MOONSTONE)
		dword_num_max = NSE_LAN_TXQ_CTX_LEN_IN_DWORD_MS;

	dev_info(dev, "=== Compare TXQ context: ctx_0 is saved one, ctx_1 is newly read one\n");

	for (i = 0; i < dword_num_max && i < dword_num; i++) {
		if (ctx_0->data[i] != ctx_1->data[i])
			diff_dword_bitmap |= BIT(i);
	}

	if (!diff_dword_bitmap) {
		dev_info(dev, "Result: Same\n");
	} else {
		dev_err(dev, "!!! Result: Different, dump different parts\n");

		nse_lan_txq_ctx_dump(hw, -1, -1, ctx_0, diff_dword_bitmap);

		nse_lan_txq_ctx_dump(hw, -1, -1, ctx_1, diff_dword_bitmap);
	}
}

static void txq_ctx_generate_amber(struct nse_ring *ring, struct nse_lan_txq_ctx_amber *ctx)
{
	struct nse_vsi *vsi = ring->vsi;
	struct nse_pf *pf = vsi->back;
	struct nse_hw *hw = &pf->hw;
	u64 base;

	/* clear the context structure first */
	memset(ctx, 0, sizeof(*ctx));

	/* DATA[0]: BASE_low */

	/* BASE scale down to 16-bytes unit, leaving 60 bits */
	base = (ring->dma >> AMBER_LAN_TXQ_BASE_SHIFT);

	ctx->data[0] = (u32)(base & AMBER_LAN_TXQ_CTX_BASE_LOW_M);

	/* DATA[1]: BASE_high, Port_id, Port_lock, Port_vld */

	ctx->data[1] = (u32)(base >> 32) & AMBER_LAN_TXQ_CTX_BASE_HIGH_M;

	if (vsi->type != NSE_VSI_VF && vsi->type != NSE_VSI_ADI) {
		/* only traffic of VF/ADI need hw lag hash and remap, so we skip it
		 * traffic of others is decided by software bond in OS
		 * roce traffic is not influenced here.
		 */
		ctx->data[1] |= (((u32)hw->lan_id <<
				 AMBER_LAN_TXQ_CTX_PORT_ID_S) & AMBER_LAN_TXQ_CTX_PORT_ID_M);
		ctx->data[1] |= AMBER_LAN_TXQ_CTX_PORT_VLD_M;
		ctx->data[1] |= AMBER_LAN_TXQ_CTX_PORT_LOCK_M;
	}

	/* DATA[2]: TC, SRC_VSI, TSYN_ENA, CPUID, WB_mode, TPHRDdesc, TPHRDdata, TPHWRdesc */
	/* explicitly set:
	 *		TC
	 *		SRC_VSI
	 *		TSYN_ENA
	 *		WB_mode
	 *
	 * implicit = 0:
	 *		CPUID
	 *		TPHRDdesc, TPHRDdata, TPHWRdesc
	 */
#ifdef CONFIG_DCB
	ctx->data[2] |= ((ring->dcb_tc << AMBER_LAN_TXQ_CTX_TC_S) & AMBER_LAN_TXQ_CTX_TC_M);
#endif

	ctx->data[2] |= (((u32)vsi->vsi_abs_num <<
			 AMBER_LAN_TXQ_CTX_SRC_VSI_S) & AMBER_LAN_TXQ_CTX_SRC_VSI_M);

	if (vsi->type == NSE_VSI_PF)
		ctx->data[2] |= AMBER_LAN_TXQ_CTX_TSYN_ENA_M;

	if (vsi->sw_conf.lan_tx_use_cq) {
		ctx->data[2] |= (AMBER_LAN_TXQ_CTX_WB_MODE_CMPQ << AMBER_LAN_TXQ_CTX_WB_MODE_S);
	} else {
		ctx->data[2] |= (AMBER_LAN_TXQ_CTX_WB_MODE_DESCRIPTOR <<
				 AMBER_LAN_TXQ_CTX_WB_MODE_S);
	}

	/* DATA[3]: CMPQ_ID, Qnum_in_func */
	/*		CMPQ_ID, Qnum_in_func
	 */
	if (vsi->sw_conf.lan_tx_use_cq) {
		ctx->data[3] |= (((u32)ring->q_vector->txcq->cq_abs_id <<
				 AMBER_LAN_TXQ_CTX_CMPQ_ID_S) & AMBER_LAN_TXQ_CTX_CMPQ_ID_M);

		ctx->data[3] |= (((u32)ring->q_index << AMBER_LAN_TXQ_CTX_QNUM_IN_FUNC_S) &
				 AMBER_LAN_TXQ_CTX_QNUM_IN_FUNC_M);
	}

	/* DATA[4]: Queue length, TSO_enabled_queue, Queue_type, LL */
	/* explicitly set:
	 *		Queue length
	 *		TSO_enabled_queue
	 *		Queue_type = 0b = native descriptor
	 *
	 * implicit = 0:
	 *		LL
	 */

	ctx->data[4] = (((u32)ring->count << AMBER_LAN_TXQ_CTX_QLEN_S) & AMBER_LAN_TXQ_CTX_QLEN_M);

	ctx->data[4] |= AMBER_LAN_TXQ_CTX_TSO_ENA_QUEUE_M;

	if (vsi->vsi_mode == NSE_VSI_MODE_VIRTIO)
		ctx->data[4] |= (AMBER_LAN_TXQ_CTX_QTYPE_VIRTIO << AMBER_LAN_TXQ_CTX_QTYPE_S);
	else
		ctx->data[4] |= (AMBER_LAN_TXQ_CTX_QTYPE_NATIVE << AMBER_LAN_TXQ_CTX_QTYPE_S);

	/*  DATA[5]: MSIx_idx, Cause_en, PF_NUM, Local_desc, desc_coalesce_en, statistic_en,
	 * statistic_cnt_id
	 */
	/* explicitly set:
	 *		MSIx_idx, Cause_en,		# if CQ writeback, then no need to set.
	 *		PF_NUM
	 *		desc_coalesce en
	 *
	 * implicit = 0:
	 *		Local_desc
	 *		statistic_en, statistic_cnt_id
	 */
	if (ring->q_vector) {
		if (!vsi->sw_conf.lan_tx_use_cq) {
			ctx->data[5] |= ((u32)(vsi->base_vector +
					 ring->q_vector->v_idx) & AMBER_LAN_TXQ_CTX_MSIX_IDX_M);
			ctx->data[5] |= AMBER_LAN_TXQ_CTX_CAUSE_EN_M;
		}
	} else {
		dev_info(nse_pf_to_dev(pf), "VSI(abs_id=%d, rel_id=%d) TXQ(idx=%d) does not have q_vector ?\n",
					vsi->vsi_abs_num, vsi->vsi_rel_num, ring->q_index);
	}

	ctx->data[5] |= (((u32)hw->pcore_pf_id <<
			 AMBER_LAN_TXQ_CTX_PF_ID_S) & AMBER_LAN_TXQ_CTX_PF_ID_M);

	if (nse_lan_desc_cache & NSE_LAN_DESC_CACHE_TX)
		ctx->data[5] |= AMBER_LAN_TXQ_CTX_DESC_COALESCE_EN_M;

#if defined(NSE_DEBUG_EXT)
	if (nse_lan_debug_hw_qstat) {
		u32 hw_qstat_id;

		hw_qstat_id = (ring->abs_id % NSE_LAN_DEBUG_HW_QSTAT_TDM_CNT);

		ctx->data[5] |= AMBER_LAN_TXQ_CTX_STATS_EN_M;

		ctx->data[5] |= ((hw_qstat_id << AMBER_LAN_TXQ_CTX_STATS_CNT_ID_S) &
				 AMBER_LAN_TXQ_CTX_STATS_CNT_ID_M);
	}
#endif

	if (vsi->vsi_mode == NSE_VSI_MODE_VIRTIO) {
		/* DATA[6]: vis_addr_lsb */
		/* DATA[7]: vis_addr_msb */
		ctx->data[6] = (u32)ring->vtio_dma_drv_addr;
		ctx->data[7] = (u32)(ring->vtio_dma_drv_addr >> 32);

		/* DATA[8]: wptr, driver_wrap_cnt, wbptr, device_wrap_cnt */
		/* vtio_head and vtio_tail are 16 bits, including their wrap_cnt inside */
		ctx->data[8] = ((u32)ring->vtio_head << AMBER_LAN_TXQ_CTX_WBPTR_S) |
						((u32)ring->vtio_tail << AMBER_LAN_TXQ_CTX_WPTR_S);
	}
}

static void txq_ctx_generate_ms(struct nse_ring *ring, struct nse_lan_txq_ctx_ms *ctx)
{
	struct nse_vsi *vsi = ring->vsi;
	struct nse_pf *pf = vsi->back;
	struct nse_hw *hw = &pf->hw;
	u64 base;

	/* clear the context structure first */
	memset(ctx, 0, sizeof(*ctx));

	/* DATA[0]: BASE_low */

	/* BASE scale down to 16-bytes unit, leaving 60 bits */
	base = (ring->dma >> MS_LAN_TXQ_BASE_SHIFT);

	ctx->data[0] = (u32)(base & MS_LAN_TXQ_CTX_BASE_LOW_M);

	/* DATA[1]: BASE_high  */

	ctx->data[1] = (u32)(base >> 32) & MS_LAN_TXQ_CTX_BASE_HIGH_M;

	/* DATA[2]: TC, SRC_VSI, TSYN_ENA, CPUID, WB_mode, TPHRDdesc, TPHRDdata, TPHWRdesc */

	if (vsi->sw_conf.lan_tx_use_cq)
		ctx->data[2] |= (MS_LAN_TXQ_CTX_WB_MODE_CMPQ << MS_LAN_TXQ_CTX_WB_MODE_S);
	else
		ctx->data[2] |= (MS_LAN_TXQ_CTX_WB_MODE_DESCRIPTOR << MS_LAN_TXQ_CTX_WB_MODE_S);

	if (vsi->type == NSE_VSI_PF)
		ctx->data[2] |= MS_LAN_TXQ_CTX_TSYN_ENA_M;

	ctx->data[2] |= (((u32)vsi->vsi_abs_num <<
			 MS_LAN_TXQ_CTX_SRC_VSI_S) & MS_LAN_TXQ_CTX_SRC_VSI_M);

#ifdef CONFIG_DCB
	ctx->data[2] |= ((ring->dcb_tc << MS_LAN_TXQ_CTX_TC_S) & MS_LAN_TXQ_CTX_TC_M);
#endif

	/* DATA[3]: CMPQ_ID, Qnum_in_func */

	if (vsi->sw_conf.lan_tx_use_cq) {
		ctx->data[3] |= (((u32)ring->q_index <<
				 MS_LAN_TXQ_CTX_QNUM_IN_FUNC_S) & MS_LAN_TXQ_CTX_QNUM_IN_FUNC_M);

		ctx->data[3] |= (((u32)ring->q_vector->txcq->cq_abs_id <<
				 MS_LAN_TXQ_CTX_CMPQ_ID_S) & MS_LAN_TXQ_CTX_CMPQ_ID_M);
	}

	/* DATA[4]: Queue length, TSO_enabled_queue, Queue_type, LL */

	ctx->data[4] |= (MS_LAN_TXQ_CTX_QTYPE_NATIVE << MS_LAN_TXQ_CTX_QTYPE_S);

	ctx->data[4] |= MS_LAN_TXQ_CTX_TSO_ENA_QUEUE_M;

	ctx->data[4] |= (((u32)ring->count << MS_LAN_TXQ_CTX_QLEN_S) & MS_LAN_TXQ_CTX_QLEN_M);

	/*  DATA[5]: MSIx_idx, Cause_en, PF_NUM, Local_desc, desc_coalesce_en, statistic_en,
	 * statistic_cnt_id
	 */

	if (nse_lan_desc_cache & NSE_LAN_DESC_CACHE_TX)
		ctx->data[5] |= MS_LAN_TXQ_CTX_DESC_COALESCE_EN_M;

	if (ring->q_vector) {
		if (!vsi->sw_conf.lan_tx_use_cq) {
			ctx->data[5] |= ((u32)(vsi->base_vector +
					 ring->q_vector->v_idx) & MS_LAN_TXQ_CTX_MSIX_IDX_M);
			ctx->data[5] |= MS_LAN_TXQ_CTX_CAUSE_EN_M;
		}
	} else {
		dev_info(nse_pf_to_dev(pf), "VSI(abs_id=%d, rel_id=%d) TXQ(idx=%d) does not have q_vector ?\n",
					vsi->vsi_abs_num, vsi->vsi_rel_num, ring->q_index);
	}

	ctx->data[5] |= (((u32)hw->pcore_pf_id << MS_LAN_TXQ_CTX_PF_ID_S) & MS_LAN_TXQ_CTX_PF_ID_M);
}

static void nse_lan_txq_ctx_generate(struct nse_ring *ring, struct nse_lan_txq_ctx *ctx)
{
	struct nse_hw *hw = &ring->pf->hw;

	if (hw->mac_type == NSE_MAC_TYPE_AMBER) {
		txq_ctx_generate_amber(ring, &ctx->amber);
		ctx->ctx_data_len = NSE_LAN_TXQ_CTX_LEN_IN_DWORD_AMBER;
	} else if (hw->mac_type == NSE_MAC_TYPE_MOONSTONE) {
		txq_ctx_generate_ms(ring, &ctx->ms);
		ctx->ctx_data_len = NSE_LAN_TXQ_CTX_LEN_IN_DWORD_MS;
	}
}

static void nse_lan_txq_determine_irqll(struct nse_hw *hw, struct nse_vsi *vsi,
					struct nse_ring *ring);

/**
 * nse_setup_tx_ctx - Configure a transmit ring context
 * @ring: The Tx ring to configure
 *
 * Configure the Tx descriptor ring in RLAN context.
 */
static int nse_setup_tx_ctx(struct nse_ring *ring)
{
	struct nse_vsi *vsi = ring->vsi;
	struct nse_lan_txq_ctx tlan_ctx;
	struct nse_pf *pf = vsi->back;
	struct nse_hw *hw = &pf->hw;
	u16 pf_q;
	u16 txq_abs_id;
	int err;

	/* rel ID inside PF txq space */
	pf_q = ring->reg_idx;
	txq_abs_id = pf->lan_txq_space_start + pf_q;		/* abs ID insider LAN txq space */

	nse_lan_txq_ctx_generate(ring, &tlan_ctx);

	if (hw->debug_mask & NSE_DBG_LAN)
		nse_lan_txq_ctx_dump(hw, pf_q, txq_abs_id, &tlan_ctx, 0xFF);

	/* here, for satety, we set TAIL to 0 before write txq context */
	if (!(vsi->type == NSE_VSI_VF || vsi->type == NSE_VSI_ADI)) {
		/* init queue specific tail register */
		ring->tail = hw->hw_addr + NSE_REG_QTX_DBELL(pf_q);
		writel(0, ring->tail);
	}

	if (nse_lan_disable_q_before_cfg) {
		(void)nse_aq_lan_disable_txq(hw, txq_abs_id,
				ring->already_in_irqll ? ring->irqll_msix :
					NSE_AQC_CONF_IRQLL_INVALID_MSIX);

		ring->already_in_irqll = false;
	}

	/* Write into TXQ context */
	err = nse_write_txq_ctx(hw, vsi, &tlan_ctx, txq_abs_id);
	if (err) {
		dev_err(nse_pf_to_dev(pf), "[%s, %d] FAIL: Write LAN TXQ context for TXQ (qid_abs=%d), error: %d\n",
									__func__, __LINE__,
									txq_abs_id, err);
		return -EIO;
	}

	memcpy(&ring->saved_lan_txq_ctx, &tlan_ctx, sizeof(tlan_ctx));

	nse_lan_txq_determine_irqll(hw, vsi, ring);

	/* here make a check */
	if (hw->debug_mask & NSE_DBG_LAN) {
		err = nse_read_txq_ctx(hw, &tlan_ctx, txq_abs_id);
		if (err) {
			dev_err(nse_pf_to_dev(pf), "[%s, %d] FAIL: Read LAN TXQ context for TXQ (qid_abs=%d), error: %d\n",
										__func__,
											__LINE__,
										txq_abs_id, err);
		} else {
			nse_lan_txq_ctx_compare(hw, &ring->saved_lan_txq_ctx, &tlan_ctx,
						NSE_LAN_TXQ_CTX_LEN_IN_DWORD_MAX);
		}

		/* we continue, later can check in debugfs */
		err = 0;
	}

	ring->tail = hw->hw_addr + NSE_REG_QTX_DBELL(pf_q);
	writel(0, ring->tail);

	return 0;
}

static bool txq_is_need_irqll_amber(struct nse_lan_txq_ctx_amber *tctx, u16 *msix)
{
	bool ret = false;

	if (!(tctx->data[2] & AMBER_LAN_TXQ_CTX_WB_MODE_M) &&	/* WB_MODE_DESCRIPTOR = 0x0 */
		!(tctx->data[4] & AMBER_LAN_TXQ_CTX_QTYPE_M))		/* QTYPE_NATIVE	= 0x0 */
		ret = true;

	if ((tctx->data[4] & AMBER_LAN_TXQ_CTX_QTYPE_M) &&		/* VIRTIO 0x1 */
		(tctx->data[5] & AMBER_LAN_TXQ_CTX_DESC_COALESCE_EN_M))	/* q.ctxt.coals_en */
		ret = true;

	if ((tctx->data[4] & AMBER_LAN_TXQ_CTX_QTYPE_M) &&		/* VIRTIO 0x1 */
		(tctx->data[7] || tctx->data[8]))
		ret = true;

	/* relative ID inside PCI function */
	if (ret)
		*msix = (tctx->data[5] & AMBER_LAN_TXQ_CTX_MSIX_IDX_M) >>
			AMBER_LAN_TXQ_CTX_MSIX_IDX_S;

	return ret;
}

static bool txq_is_need_irqll_ms(struct nse_lan_txq_ctx_ms *tctx, u16 *msix)
{
	bool ret = false;

	if (!(tctx->data[2] & MS_LAN_TXQ_CTX_WB_MODE_M) &&	/* WB_MODE_DESCRIPTOR = 0x0 */
		!(tctx->data[4] & MS_LAN_TXQ_CTX_QTYPE_M))		/* QTYPE_NATIVE	= 0x0 */
		ret = true;

	/* relative ID inside PCI function */
	if (ret)
		*msix = (tctx->data[5] & MS_LAN_TXQ_CTX_MSIX_IDX_M) >> MS_LAN_TXQ_CTX_MSIX_IDX_S;

	return ret;
}

static bool txq_is_need_irqll(struct nse_hw *hw, struct nse_lan_txq_ctx *rctx, u16 *msix)
{
	if (hw->mac_type == NSE_MAC_TYPE_AMBER)
		return txq_is_need_irqll_amber(&rctx->amber, msix);
	else if (hw->mac_type == NSE_MAC_TYPE_MOONSTONE)
		return txq_is_need_irqll_ms(&rctx->ms, msix);
	else
		return false;
}

static void nse_lan_txq_determine_irqll(struct nse_hw *hw, struct nse_vsi *vsi,
					struct nse_ring *ring)
{
	struct nse_pf *pf = vsi->back;
	struct nse_vfs *vfs = &pf->vfs;
	struct nse_vf *vf;
	struct nse_lan_txq_ctx *tctx = &ring->saved_lan_txq_ctx;
	u16 msix;

	ring->need_irqll = false;
	ring->irqll_msix = NSE_AQC_CONF_IRQLL_INVALID_MSIX;

	if (nse_lan_no_irqll)
		goto out;

	if (!txq_is_need_irqll(hw, tctx, &msix))
		goto out;

	if (vsi->type == NSE_VSI_VF) {
		vf = vsi->vf;
		if (!vf)
			goto out;

		msix += pf->irq_space_start;
		msix += pf->sriov_base_vector;
		msix += (vfs->num_msix_per * vf->vf_id);
	} else {
		msix += pf->irq_space_start;
	}

	ring->need_irqll = true;
	ring->irqll_msix = msix;

out:
	nse_debug(hw, NSE_DBG_LAN, "[%s] VSI(abs_id=%d), TXQ(idx=%d, abs_id=%d): need_irqll=%d, irqll_msix=%d\n",
								__func__, vsi->vsi_abs_num,
									ring->q_index, ring->abs_id,
								ring->need_irqll, ring->irqll_msix);
}

int nse_cfg_txq_irqll(struct nse_ring *ring, bool add)
{
	struct nse_vsi *vsi = ring->vsi;
	struct nse_pf *pf = vsi->back;
	struct nse_hw *hw = &pf->hw;
	u8 op;
	u16 txq_abs_id;
	enum nse_status status;
	int ret = 0;

	if (!ring->need_irqll)
		goto out;

	op = add ? NSE_AQC_CONF_IRQLL_OP_ADD : NSE_AQC_CONF_IRQLL_OP_DEL;

	/* reg_idx is rel ID inside PF txq space,
	 * compute abs ID insider LAN txq space
	 */
	txq_abs_id = pf->lan_txq_space_start + ring->reg_idx;

	nse_debug(hw, NSE_DBG_LAN, "[%s] conf_irqll_lanq(op=%d, qtype=txq, q_abs_id=%d, irqll_msix=%d)\n",
								__func__, op, txq_abs_id,
									ring->irqll_msix);

	status = nse_conf_irqll_lanq(hw, op, NSE_AQC_CONF_IRQLL_QTYPE_LAN_TXQ,
								txq_abs_id, ring->irqll_msix);
	if (status) {
		dev_err(nse_pf_to_dev(pf), "[%s] FAIL: conf_irqll_lanq(op=%d, qtype=txq, q_abs_id=%d, irqll_msix=%d)\n",
								__func__, op, txq_abs_id,
									ring->irqll_msix);
		ret = -EIO;
	}

out:
	return ret;
}

void nse_vsi_clear_q_irqll_status(struct nse_vsi *vsi)
{
	struct nse_hw *hw = &vsi->back->hw;
	struct nse_ring *q;
	struct nse_txcq_ring *cq;
	int i;

	nse_debug(hw, NSE_DBG_SYS, "[%s] vsi (idx=%u, rel_id=%u, abs_id=%u)\n",
							__func__, vsi->idx, vsi->vsi_rel_num,
								vsi->vsi_abs_num);

	if (vsi->rx_rings) {
		nse_for_each_rxq(vsi, i) {
			q = vsi->rx_rings[i];

			if (!q)
				continue;

			q->already_in_irqll = false;
		}
	}

	if (vsi->tx_rings) {
		nse_for_each_txq(vsi, i) {
			q = vsi->tx_rings[i];

			if (!q)
				continue;

			q->already_in_irqll = false;
		}
	}

	if (vsi->xdp_rings) {
		nse_for_each_xdp_txq(vsi, i) {
			q = vsi->xdp_rings[i];

			if (!q)
				continue;

			q->already_in_irqll = false;
		}
	}

	if (vsi->txcq_rings) {
		nse_for_each_lan_txcq(vsi, i) {
			cq = vsi->txcq_rings[i];

			if (!cq)
				continue;

			cq->already_in_irqll = false;
		}
	}
}

/**
 * nse_calc_q_handle - calculate the queue handle
 * @vsi: VSI that ring belongs to
 * @ring: ring to get the absolute queue index
 * @tc: traffic class number
 */
static u16 nse_calc_q_handle(struct nse_vsi *vsi, struct nse_ring *ring, u8 tc)
{
	WARN_ONCE(nse_ring_is_xdp(ring) && tc, "XDP ring can't belong to TC other than 0\n");

	/* Idea here for calculation is that we subtract the number of queue
	 * count from TC that ring belongs to from it's absolute queue index
	 * and as a result we get the queue's index within TC.
	 */
	return ring->q_index - vsi->tc_cfg.tc_info[tc].qoffset;
}

/**
 * nse_eswitch_calc_q_handle
 * @ring: pointer to ring which unique index is needed
 *
 * To correctly work with many netdevs
 * ring->q_index of Tx rings on switchdev VSI can repeat. Hardware ring setup
 * requires unique q_index. Calculate it here by finding index in vsi->tx_rings
 * of this ring.
 *
 * Return -1 when index wasn't found. Should never happen, because vsi is get
 * from ring->vsi, so it has to be present in this vsi.
 */
static u16 nse_eswitch_calc_q_handle(struct nse_ring *ring)
{
	struct nse_vsi *vsi = ring->vsi;
	int i;

	nse_for_each_txq(vsi, i) {
		if (vsi->tx_rings[i] == ring)
			return i;
	}

	return -1;
}

/**
 * nse_cfg_xps_tx_ring - Configure XPS for a Tx ring
 * @ring: The Tx ring to configure
 *
 * This enables/disables XPS for a given Tx descriptor ring
 * based on the TCs enabled for the VSI that ring belongs to.
 */
static void nse_cfg_xps_tx_ring(struct nse_ring *ring)
{
	int cpu;

	if (!ring->q_vector || !ring->netdev)
		return;

	/* We only initialize XPS once, so as not to overwrite user settings */
	if (test_and_set_bit(NSE_TX_XPS_INIT_DONE, ring->xps_state))
		return;

	cpu = cpumask_local_spread(ring->q_vector->v_idx, -1);
	netif_set_xps_queue(ring->netdev, get_cpu_mask(cpu), ring->q_index);
}

/**
 * nse_vsi_cfg_rxq - Configure an Rx queue
 * @ring: the ring being configured
 *
 * Return 0 on success and a negative value on error.
 */
int nse_vsi_cfg_rxq(struct nse_ring *ring)
{
	struct nse_vsi *vsi = ring->vsi;
	struct nse_pf *pf = vsi->back;
	struct nse_hw *hw = &pf->hw;
	struct device *dev = nse_pf_to_dev(pf);
	u16 num_bufs = NSE_DESC_UNUSED(ring);
	int err;

	nse_debug(hw, NSE_DBG_LAN, "[%s]: VSI (rel_id=%d, abs_id=%d), rxq (idx=%d)\n",
				__func__, vsi->vsi_rel_num, vsi->vsi_abs_num, ring->q_index);

	ring->rx_buf_len = ring->vsi->rx_buf_len;

	if (ring->vsi->type == NSE_VSI_PF) {
		if (!xdp_rxq_info_is_reg(&ring->xdp_rxq))
			/* coverity[check_return] */
			xdp_rxq_info_reg(&ring->xdp_rxq, ring->netdev,
					 ring->q_index, ring->q_vector->napi.napi_id);

		ring->xsk_pool = nse_xsk_umem(ring);
		if (ring->xsk_pool) {
			xdp_rxq_info_unreg_mem_model(&ring->xdp_rxq);

			ring->rx_buf_len =
				xsk_pool_get_rx_frame_size(ring->xsk_pool);
			err = xdp_rxq_info_reg_mem_model(&ring->xdp_rxq,
							 MEM_TYPE_XSK_BUFF_POOL,
							 NULL);
			if (err)
				return err;
			xsk_pool_set_rxq_info(ring->xsk_pool, &ring->xdp_rxq);

			dev_info(dev, "Registered XDP mem model MEM_TYPE_XSK_BUFF_POOL on Rx ring %d\n",
				 ring->q_index);
		} else {
			if (!xdp_rxq_info_is_reg(&ring->xdp_rxq))
				/* coverity[check_return] */
				xdp_rxq_info_reg(&ring->xdp_rxq,
						 ring->netdev,
						 ring->q_index, ring->q_vector->napi.napi_id);

			err = xdp_rxq_info_reg_mem_model(&ring->xdp_rxq,
							 MEM_TYPE_PAGE_SHARED,
							 NULL);
			if (err)
				return err;
		}
	}

	err = nse_setup_rx_ctx(ring);
	if (err) {
		nse_dev_err_errno(dev, err,
				  "setup_rx_ctx() failed for: VSI(abs_id=%d, rel_id=%d) RXQ(idx=%d)",
				  vsi->vsi_abs_num, vsi->vsi_rel_num, ring->q_index);
		return err;
	}

	if (ring->xsk_pool) {
		if (!xsk_buff_can_alloc(ring->xsk_pool, num_bufs)) {
			dev_warn(dev, "UMEM does not provide enough addresses to fill %d buffers on Rx ring %d\n",
				 num_bufs, ring->q_index);
			dev_warn(dev, "Change Rx ring/fill queue size to avoid performance issues\n");

			return 0;
		}

		err = nse_alloc_rx_bufs_zc(ring, NSE_DESC_UNUSED(ring));
		if (err) {
			u16 pf_q = ring->reg_idx;

			dev_info(dev, "Failed to allocate some buffers on UMEM enabled Rx ring %d (pf_q %d)\n",
				 ring->q_index, pf_q);
		}

		return 0;
	}

	(void)nse_alloc_rx_bufs(ring, num_bufs);

	return 0;
}

/**
 * nse_vsi_cfg_txq - Configure single Tx queue
 * @tx_ring: Tx ring to be configured
 */
int
nse_vsi_cfg_txq(struct nse_ring *tx_ring)
{
	struct nse_vsi *vsi = tx_ring->vsi;
	struct nse_pf *pf = vsi->back;
	struct nse_hw *hw = &pf->hw;
	struct device *dev = nse_pf_to_dev(pf);
	u32 leaf_node_tnid;
	enum nse_status status;
	int err = 0;
	u8 tc;

	nse_debug(hw, NSE_DBG_LAN, "[%s]: VSI (rel_id=%d, abs_id=%d), txq (idx=%d)\n",
				__func__, vsi->vsi_rel_num, vsi->vsi_abs_num, tx_ring->q_index);

	/* Configure XPS */
	nse_cfg_xps_tx_ring(tx_ring);

	/* write TXQ context*/
	err = nse_setup_tx_ctx(tx_ring);
	if (err) {
		nse_dev_err_errno(dev, err,
				  "setup_tx_ctx() failed for: VSI(abs_id=%d, rel_id=%d) TXQ(idx=%d)",
				  vsi->vsi_abs_num, vsi->vsi_rel_num, tx_ring->q_index);
		return err;
	}

	/* no need to alloc sched node in every config */
	if ((vsi->type == NSE_VSI_VF) &&
		(vsi->vsi_mode == NSE_VSI_MODE_VIRTIO) &&
		(tx_ring->txq_tnid != NSE_SCHED_INVAL_TNID)) {
		dev_info(dev, "ena_vsi_txq(txq rel_id=%d, abs_id=%d) sched node exist, skip allocing\n",
						tx_ring->reg_idx, tx_ring->abs_id);
		return 0;
		}

	/* determine TXQ's tc and q_handle */
	if (IS_ENABLED(CONFIG_DCB))
		tc = tx_ring->dcb_tc;
	else
		tc = 0;

	/* Add unique software queue handle of the Tx queue per
	 * TC into the VSI Tx ring
	 */
	if (vsi->type == NSE_VSI_SWITCHDEV_CTRL)
		tx_ring->q_handle = nse_eswitch_calc_q_handle(tx_ring);
	else
		tx_ring->q_handle = nse_calc_q_handle(vsi, tx_ring, tc);

	status = nse_ena_vsi_txq(vsi->port_info, vsi->idx, tc,
					 tx_ring, &leaf_node_tnid);
	if (status) {
		dev_err(dev, "ena_vsi_txq(txq rel_id=%d, abs_id=%d) failed, error: %d(%s)\n",
					tx_ring->reg_idx, tx_ring->abs_id,
					status, nse_stat_str(status));
		return -ENODEV;
	}

	/* Add Tx Queue TEID into the VSI Tx ring from the
	 * response. This will complete configuring and
	 * enabling the queue.
	 */
	tx_ring->txq_tnid = leaf_node_tnid;

	return 0;
}

static void nse_lan_txcq_ctx_generate(struct nse_txcq_ring *ring, struct nse_lan_txcq_ctx *ctx)
{
	struct nse_vsi *vsi = ring->vsi;
	struct nse_pf *pf = vsi->back;
	u64 base;

	/* clear the context structure first */
	memset(ctx, 0, sizeof(*ctx));

	/* DATA[0]: BASE_low */
	base = (ring->dma >> LAN_TXCQ_BASE_SHIFT);

	ctx->data[0] = (u32)(base & LAN_TXCQ_CTX_BASE_LOW_M);

	/* DATA[1]: BASE_high */
	ctx->data[1] = (u32)((base >> 32) & LAN_TXCQ_CTX_BASE_HIGH_M);

	/* DATA[2]: Queue length */
	ctx->data[2] = ((u32)ring->count >> LAN_TXCQ_QLEN_SHIFT) & LAN_TXCQ_CTX_QLEN_M;

	/* DATA[3]: src_vsi, desc_coalesce_en, cause_en, msix_idx, tphwr_desc, cpuid */
	/* implicily:
	 *		tphwr_desc = 0
	 *		cpuid = 0
	 */
	ctx->data[3] = ((u32)vsi->vsi_abs_num << LAN_TXCQ_CTX_SRC_VSI_S) & LAN_TXCQ_CTX_SRC_VSI_M;

	if (nse_lan_desc_cache & NSE_LAN_DESC_CACHE_TX)
		ctx->data[3] |= LAN_TXCQ_CTX_DESC_COALESCE_EN_M;

	if (ring->q_vector) {
		ctx->data[3] |= LAN_TXCQ_CTX_CAUSE_EN_M;
		ctx->data[3] |= ((u32)(vsi->base_vector + ring->q_vector->v_idx) <<
				 LAN_TXCQ_CTX_MSIX_IDX_S) & LAN_TXCQ_CTX_MSIX_IDX_M;
	} else {
		dev_info(nse_pf_to_dev(pf), "VSI(abs_id=%d, rel_id=%d) LAN-CQ(idx=%d, abs_id=%d) does not have q_vector ?\n",
					vsi->vsi_abs_num, vsi->vsi_rel_num,
						ring->q_index, ring->cq_abs_id);
	}

	/* DATA[4]: cq_wptr, generation */
	if (nse_lan_txcq_initial_hw_gen)
		ctx->data[4] = LAN_TXCQ_CTX_GENERATION_M;
}

static void nse_lan_txcq_determine_irqll(struct nse_hw *hw, struct nse_vsi *vsi,
					 struct nse_txcq_ring *cq_ring);

static int nse_setup_lan_txcq_ctx(struct nse_txcq_ring *cq_ring)
{
	struct nse_vsi *vsi = cq_ring->vsi;
	struct nse_lan_txcq_ctx cq_ctx;
	struct nse_pf *pf = vsi->back;
	struct nse_hw *hw = &pf->hw;
	int err = 0;

	nse_lan_txcq_ctx_generate(cq_ring, &cq_ctx);

	if (hw->debug_mask & NSE_DBG_LAN)
		nse_lan_txcq_ctx_dump(hw, cq_ring->cq_rel_id, cq_ring->cq_abs_id, &cq_ctx, 0xFF);

	if (nse_lan_disable_q_before_cfg) {
		(void)nse_disable_lan_txcq(hw, vsi, cq_ring->cq_abs_id,
					cq_ring->already_in_irqll ? cq_ring->irqll_msix :
						NSE_AQC_CONF_IRQLL_INVALID_MSIX);

		cq_ring->already_in_irqll = false;
	}

	err = nse_write_lan_txcq_ctx(hw, vsi, &cq_ctx, cq_ring->cq_abs_id);
	if (err) {
		dev_err(nse_pf_to_dev(pf), "[%s, %d] FAIL: Write LAN-TX-CQ context for CQ (qid_abs=%d), error: %d\n",
					__func__, __LINE__,
					cq_ring->cq_abs_id, err);
		return -EIO;
	}

	memcpy(&cq_ring->saved_txcq_ctx, &cq_ctx, sizeof(cq_ctx));

	nse_lan_txcq_determine_irqll(hw, vsi, cq_ring);

	/* here make a check */
	if (hw->debug_mask & NSE_DBG_LAN) {
		err = nse_read_lan_txcq_ctx(hw, &cq_ctx, cq_ring->cq_abs_id);
		if (err) {
			dev_err(nse_pf_to_dev(pf), "[%s, %d] FAIL: Read LAN-TX-CQ context for CQ (qid_abs=%d), error: %d\n",
										__func__,
											__LINE__,
										cq_ring->cq_abs_id,
											err);
		} else {
			nse_lan_txcq_ctx_compare(hw, &cq_ring->saved_txcq_ctx, &cq_ctx, 5);
		}

		/* we continue, later can check again in debugfs */
		err = 0;
	}

	return err;	// = 0 surely.
}

int
nse_vsi_cfg_lan_txcq(struct nse_txcq_ring *cq_ring)
{
	struct nse_vsi *vsi = cq_ring->vsi;
	struct nse_pf *pf = vsi->back;
	struct device *dev = nse_pf_to_dev(pf);
	int err = 0;

	err = nse_setup_lan_txcq_ctx(cq_ring);
	if (err) {
		nse_dev_err_errno(dev, err,
				  "setup_lan_txcq_ctx() failed for: VSI(abs_id=%d, rel_id=%d) LAN-TX-CQ(idx=%d, abs_id=%d)",
				  vsi->vsi_abs_num, vsi->vsi_rel_num,
					  cq_ring->q_index, cq_ring->cq_abs_id);
		return err;
	}

	cq_ring->flags |= NSE_TX_CQ_FLAGS_CFGED;

	return 0;
}

static bool txcq_is_need_irqll(struct nse_lan_txcq_ctx *cqctx, u16 *msix)
{
	bool ret = false;

	if (cqctx->data[3] & LAN_TXCQ_CTX_DESC_COALESCE_EN_M)
		ret = true;

	/* relative ID inside PCI function */
	if (ret)
		*msix = (cqctx->data[3] & LAN_TXCQ_CTX_MSIX_IDX_M) >> LAN_TXCQ_CTX_MSIX_IDX_S;

	return ret;
}

static void nse_lan_txcq_determine_irqll(struct nse_hw *hw, struct nse_vsi *vsi,
					 struct nse_txcq_ring *cq_ring)
{
	struct nse_pf *pf = vsi->back;
	struct nse_vfs *vfs = &pf->vfs;
	struct nse_vf *vf;
	struct nse_lan_txcq_ctx *cqctx = &cq_ring->saved_txcq_ctx;
	u16 msix;

	cq_ring->need_irqll = false;
	cq_ring->irqll_msix = NSE_AQC_CONF_IRQLL_INVALID_MSIX;

	if (nse_lan_no_irqll)
		goto out;

	if (!txcq_is_need_irqll(cqctx, &msix))
		goto out;

	if (vsi->type == NSE_VSI_VF) {
		vf = vsi->vf;
		if (!vf)
			goto out;

		msix += pf->irq_space_start;
		msix += pf->sriov_base_vector;
		msix += (vfs->num_msix_per * vf->vf_id);
	} else {
		msix += pf->irq_space_start;
	}

	cq_ring->need_irqll = true;
	cq_ring->irqll_msix = msix;

out:
	nse_debug(hw, NSE_DBG_LAN, "[%s] VSI(abs_id=%d), CQ(idx=%d, abs_id=%d): need_irqll=%d, irqll_msix=%d\n",
								__func__, vsi->vsi_abs_num,
									cq_ring->q_index,
									cq_ring->cq_abs_id,
								cq_ring->need_irqll,
									cq_ring->irqll_msix);
}

int nse_cfg_lan_txcq_irqll(struct nse_txcq_ring *cq_ring, bool add)
{
	struct nse_vsi *vsi = cq_ring->vsi;
	struct nse_pf *pf = vsi->back;
	struct nse_hw *hw = &pf->hw;
	u8 op;
	enum nse_status status;
	int ret = 0;

	if (!cq_ring->need_irqll)
		goto out;

	op = add ? NSE_AQC_CONF_IRQLL_OP_ADD : NSE_AQC_CONF_IRQLL_OP_DEL;

	nse_debug(hw, NSE_DBG_LAN, "[%s] conf_irqll_lanq(op=%d, qtype=cq, q_abs_id=%d, irqll_msix=%d)\n",
								__func__, op,
									cq_ring->cq_abs_id,
									cq_ring->irqll_msix);

	status = nse_conf_irqll_lanq(hw, op, NSE_AQC_CONF_IRQLL_QTYPE_LAN_CQ,
				     cq_ring->cq_abs_id, cq_ring->irqll_msix);
	if (status) {
		dev_err(nse_pf_to_dev(pf), "[%s] FAIL: conf_irqll_lanq(op=%d, qtype=cq, q_abs_id=%d, irqll_msix=%d)\n",
								__func__, op,
									cq_ring->cq_abs_id,
									cq_ring->irqll_msix);
		ret = -EIO;
	}

out:
	return ret;
}

/**
 * nse_vsi_alloc_q_vector - Allocate memory for a single interrupt vector
 * @vsi: the VSI being configured
 * @v_idx: index of the vector in the VSI struct
 *
 * We allocate one q_vector and set default value for ITR setting associated
 * with this q_vector. If allocation fails we return -ENOMEM.
 */
static int nse_vsi_alloc_q_vector(struct nse_vsi *vsi, u16 v_idx)
{
	struct nse_pf *pf = vsi->back;
	struct nse_q_vector *q_vector;

	/* allocate q_vector */
	q_vector = devm_kzalloc(nse_pf_to_dev(pf), sizeof(*q_vector),
				GFP_KERNEL);
	if (!q_vector)
		return -ENOMEM;

	q_vector->vsi = vsi;
	q_vector->v_idx = v_idx;

	if (pf->sw_conf.min_itr_no_intrl) {
		q_vector->itr_setting = NSE_ITR_INTERVAL_MIN_USEC;
		q_vector->itr_mode = ITR_STATIC;
	} else {
		q_vector->itr_setting = NSE_ITR_INTERVAL_DEFAULT;
		q_vector->itr_mode = ITR_DYNAMIC;
	}

	q_vector->intrl = NSE_INTRL_INTERVAL_NO_USEC;

	if (vsi->type == NSE_VSI_VF)
		goto out;

	cpumask_copy(&q_vector->affinity_mask, cpu_possible_mask);

	/* This will not be called in the driver load path because the netdev
	 * will not be created yet. All other cases with register the NAPI
	 * handler here (i.e. resume, reset/rebuild, etc.)
	 */
	if (vsi->netdev)
		netif_napi_add(vsi->netdev, &q_vector->napi, nse_napi_poll);

out:
	/* tie q_vector and VSI together */
	vsi->q_vectors[v_idx] = q_vector;

	return 0;
}

/**
 * nse_free_q_vector - Free memory allocated for a specific interrupt vector
 * @vsi: VSI having the memory freed
 * @v_idx: index of the vector to be freed
 */
static void nse_free_q_vector(struct nse_vsi *vsi, int v_idx)
{
	struct nse_q_vector *q_vector;
	struct nse_pf *pf = vsi->back;
	struct nse_ring *ring;
	struct device *dev;

	if (vsi->type == NSE_VSI_LB)
		return;

	dev = nse_pf_to_dev(pf);
	if (!vsi->q_vectors[v_idx]) {
		dev_dbg(dev, "Queue vector at index %d not found\n", v_idx);
		return;
	}
	q_vector = vsi->q_vectors[v_idx];

	nse_for_each_ring(ring, q_vector->tx)
		ring->q_vector = NULL;
	nse_for_each_ring(ring, q_vector->rx)
		ring->q_vector = NULL;

	/* only VSI with an associated netdev is set up with NAPI */
	if (vsi->netdev)
		netif_napi_del(&q_vector->napi);

	devm_kfree(dev, q_vector);
	vsi->q_vectors[v_idx] = NULL;
}

/**
 * nse_vsi_alloc_q_vectors - Allocate memory for interrupt vectors
 * @vsi: the VSI being configured
 *
 * We allocate one q_vector per queue interrupt. If allocation fails we
 * return -ENOMEM.
 */
int nse_vsi_alloc_q_vectors(struct nse_vsi *vsi)
{
	struct device *dev = nse_pf_to_dev(vsi->back);
	u16 v_idx;
	int err;

	if (vsi->q_vectors[0]) {
		dev_dbg(dev, "VSI %d has existing q_vectors\n", vsi->vsi_abs_num);
		return -EEXIST;
	}

	for (v_idx = 0; v_idx < vsi->num_q_vectors; v_idx++) {
		err = nse_vsi_alloc_q_vector(vsi, v_idx);
		if (err)
			goto err_out;
	}

	return 0;

err_out:
	while (v_idx--)
		nse_free_q_vector(vsi, v_idx);

	nse_dev_err_errno(dev, err,
			  "Failed to allocate %d q_vector for VSI %d",
			  vsi->num_q_vectors, vsi->vsi_abs_num);
	vsi->num_q_vectors = 0;
	return err;
}

static int nse_vsi_map_txcq_rings_to_vectors_for_nonvf(struct nse_vsi *vsi)
{
	struct nse_pf *pf = vsi->back;
	struct nse_hw *hw = &pf->hw;
	struct device *dev = nse_pf_to_dev(pf);
	int q_vectors = vsi->num_q_vectors;
	struct nse_q_vector *q_vector = NULL;
	struct nse_txcq_ring *cq_ring = NULL;
	int v_id;
	int ret = -EIO;

	nse_debug(hw, NSE_DBG_LAN, "[%s] non-VF-VSI(idx=%d, type=%d), alloc_txcq=%d, num_q_vectors=%d\n",
								__func__, vsi->idx, vsi->type,
									vsi->alloc_txq,
									vsi->num_q_vectors);

	if (!vsi->alloc_txcq || !vsi->num_q_vectors || (vsi->alloc_txcq != vsi->num_q_vectors)) {
		dev_err(dev, "[%s] BAD: vsi(idx=%d, type=%d, alloc_txcq(%d), num_q_vectors(%d)\n",
					__func__, vsi->idx, vsi->type,
						vsi->alloc_txcq, vsi->num_q_vectors);
		goto out;
	}

	/* 1-to-1 map LAN-CQ to LAN-irq-vector */
	for (v_id = 0; v_id < q_vectors; v_id++) {
		q_vector = vsi->q_vectors[v_id];

		cq_ring = vsi->txcq_rings[v_id];

		if (cq_ring) {
			q_vector->txcq = cq_ring;
			cq_ring->q_vector = q_vector;
		} else {
			dev_err(dev, "[%s] BAD: vsi(idx=%d), txcq_rings[%d] is NULL, not allocated\n",
						__func__, vsi->idx, v_id);
			goto out;
		}
	}

	vsi->num_txcq = q_vectors;	// for non-VSI VSI, vsi->alloc_txcq == vsi->num_q_vectors

	ret = 0;

out:
	return ret;
}

static int nse_vsi_map_txcq_rings_to_vectors_for_vf(struct nse_vsi *vsi)
{
	struct nse_pf *pf = vsi->back;
	struct nse_hw *hw = &pf->hw;
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_q_vector *q_vector = NULL;
	struct nse_txcq_ring *cq_ring = NULL;
	int q_vectors;
	int v_id;
	int ret = -EIO;

	nse_debug(hw, NSE_DBG_LAN, "[%s] VF-VSI(vf_id=%d), alloc_txcq=%d, num_q_vectors=%d, max_lan_msix_per=%d\n",
								__func__, vsi->vf->vf_id,
									vsi->alloc_txq,
									vsi->num_q_vectors,
								pf->vfs.max_lan_msix_per);

	/* sanity check, should pass */
	if (!vsi->alloc_txq || !vsi->num_q_vectors || !pf->vfs.max_lan_msix_per) {
		dev_err(dev, "[%s] VF-VSI(vf_id=%d), BAD setting, check code.\n",
						__func__, vsi->vf->vf_id);
	}

	q_vectors = vsi->num_q_vectors;
	if (q_vectors > vsi->alloc_txcq)	//pf->vfs.num_txcq_per
		q_vectors = vsi->alloc_txcq;

	if (q_vectors > pf->vfs.max_lan_msix_per)
		q_vectors = pf->vfs.max_lan_msix_per;

	/* 1-to-1 map LAN-CQ to LAN-irq-vector */
	for (v_id = 0; v_id < q_vectors; v_id++) {
		q_vector = vsi->q_vectors[v_id];

		cq_ring = vsi->txcq_rings[v_id];

		if (cq_ring) {
			q_vector->txcq = cq_ring;
			cq_ring->q_vector = q_vector;
		} else {
			dev_err(dev, "[%s] BAD: vsi(idx=%d), txcq_rings[%d] is NULL, not allocated\n",
						__func__, vsi->idx, v_id);
			goto out;
		}
	}

	// for VF-VSI, = alloc_txcq, should not use vsi->num_q_vectors (== (vfs->num_msix_per - 1))
	vsi->num_txcq = q_vectors;

	ret = 0;

out:
	return ret;
}

int nse_vsi_map_txcq_rings_to_vectors(struct nse_vsi *vsi)
{
	if (!vsi->sw_conf.lan_tx_use_cq)
		return 0;

	if (!vsi->alloc_txcq) {
		dev_err(nse_pf_to_dev(vsi->back), "[%s] BAD: VSI(idx=%d), expect use TXCQ, but TXCQ not allocated\n",
									__func__, vsi->idx);
		return -ENOSPC;
	}

	if (vsi->type == NSE_VSI_VF)
		return nse_vsi_map_txcq_rings_to_vectors_for_vf(vsi);
	else
		return nse_vsi_map_txcq_rings_to_vectors_for_nonvf(vsi);
}

/**
 * nse_vsi_map_rings_to_vectors - Map VSI rings to interrupt vectors
 * @vsi: the VSI being configured
 *
 * This function maps descriptor rings to the queue-specific vectors allotted
 * through the MSI-X enabling code. On a constrained vector budget, we map Tx
 * and Rx rings to the vector as "efficiently" as possible.
 */
int nse_vsi_map_rings_to_vectors(struct nse_vsi *vsi)
{
	int q_vectors = vsi->num_q_vectors;
	struct nse_q_vector *q_vector = NULL;
	u16 tx_rings_rem, rx_rings_rem;
	int v_id;
	int ret = 0;

	/* initially assigning remaining rings count to VSIs num queue value */
	tx_rings_rem = vsi->num_txq;
	rx_rings_rem = vsi->num_rxq;

	for (v_id = 0; v_id < q_vectors; v_id++) {
		u8 tx_rings_per_v, rx_rings_per_v;
		u16 q_id, q_base;

		q_vector = vsi->q_vectors[v_id];

		/* Tx rings mapping to vector */
		tx_rings_per_v = (u8)DIV_ROUND_UP(tx_rings_rem,
						  q_vectors - v_id);
		q_vector->num_ring_tx = tx_rings_per_v;
		q_vector->tx.ring = NULL;
		q_base = vsi->num_txq - tx_rings_rem;

		for (q_id = q_base; q_id < (q_base + tx_rings_per_v); q_id++) {
			struct nse_ring *tx_ring = vsi->tx_rings[q_id];

			if (tx_ring) {
				tx_ring->q_vector = q_vector;
				tx_ring->next = q_vector->tx.ring;
				q_vector->tx.ring = tx_ring;
			} else {
				dev_err(nse_pf_to_dev(vsi->back), "NULL Tx ring found\n");
				break;
			}
		}
		tx_rings_rem -= tx_rings_per_v;

		/* Rx rings mapping to vector */
		rx_rings_per_v = (u8)DIV_ROUND_UP(rx_rings_rem,
						  q_vectors - v_id);
		q_vector->num_ring_rx = rx_rings_per_v;
		q_vector->rx.ring = NULL;
		q_base = vsi->num_rxq - rx_rings_rem;

		for (q_id = q_base; q_id < (q_base + rx_rings_per_v); q_id++) {
			struct nse_ring *rx_ring = vsi->rx_rings[q_id];

			if (rx_ring) {
				rx_ring->q_vector = q_vector;
				rx_ring->next = q_vector->rx.ring;
				q_vector->rx.ring = rx_ring;
			} else {
				dev_err(nse_pf_to_dev(vsi->back), "NULL Rx ring found\n");
				break;
			}
		}
		rx_rings_rem -= rx_rings_per_v;
	}

	ret = nse_vsi_map_txcq_rings_to_vectors(vsi);
	if (ret)
		dev_err(nse_pf_to_dev(vsi->back), "[%s] FAIL: vsi_map_txcq_rings_to_vectors(vsi idx=%d)\n",
			__func__, vsi->idx);

	return ret;
}

/**
 * nse_vsi_free_q_vectors - Free memory allocated for interrupt vectors
 * @vsi: the VSI having memory freed
 */
void nse_vsi_free_q_vectors(struct nse_vsi *vsi)
{
	int v_idx;

	nse_for_each_q_vector(vsi, v_idx)
		nse_free_q_vector(vsi, v_idx);
}

/**
 * nse_cfg_itr - configure the initial interrupt throttle values
 * @hw: pointer to the HW structure
 * @q_vector: interrupt vector that's being configured
 *
 * Configure interrupt throttling values for the ring containers that are
 * associated with the interrupt vector passed in.
 */
void nse_cfg_itr(struct nse_hw *hw, struct nse_q_vector *q_vector)
{
	if (q_vector->num_ring_rx || q_vector->num_ring_tx)
		nse_write_itr(q_vector, q_vector->itr_setting);

	nse_write_intrl(q_vector, q_vector->intrl);
}

/**
 * nse_cfg_txq_interrupt - configure interrupt on Tx queue
 * @vsi: the VSI being configured
 * @txq: Tx queue being mapped to MSI-X vector
 * @msix_idx: MSI-X vector index within the function
 *
 * Configure interrupt on Tx queue by associating Tx queue to MSI-X vector
 * within the function space.
 */
void
nse_cfg_txq_interrupt(struct nse_vsi *vsi, u16 txq, u16 msix_idx)
{
	struct nse_hw *hw = &vsi->back->hw;

	nse_debug(hw, NSE_DBG_LAN, "[%s]: VSI(abs_id=%d, rel_id=%d) TXQ(idx=%d), to msix_idx(%d)\n",
							__func__, vsi->vsi_abs_num,
								vsi->vsi_rel_num, txq, msix_idx);
}

/**
 * nse_cfg_rxq_interrupt - configure interrupt on Rx queue
 * @vsi: the VSI being configured
 * @rxq: Rx queue being mapped to MSI-X vector
 * @msix_idx: MSI-X vector index within the function
 *
 * Configure interrupt on Rx queue by associating Rx queue to MSI-X vector
 * within the function space.
 */
void
nse_cfg_rxq_interrupt(struct nse_vsi *vsi, u16 rxq, u16 msix_idx)
{
	struct nse_hw *hw = &vsi->back->hw;

	nse_debug(hw, NSE_DBG_LAN, "[%s]: VSI(abs_id=%d, rel_id=%d) RXQ(idx=%d), to msix_idx(%d)\n",
							__func__, vsi->vsi_abs_num,
								vsi->vsi_rel_num, rxq, msix_idx);
}

/**
 * nse_trigger_sw_intr - trigger a software interrupt
 * @hw: pointer to the HW structure
 * @q_vector: interrupt vector to trigger the software interrupt for
 */
void nse_trigger_sw_intr(struct nse_hw *hw, struct nse_q_vector *q_vector)
{
	u32 val;

	/* INTMSK_VLD=1, INTMSK = 0 (unmask), and SWINT_TRIG = 1, to trigger a SW interrupt */
	val = NSE_REG_INT_DYN_CTLN_SWINT_TRIG_M |
			NSE_REG_INT_DYN_CTLN_INTMSK_VLD_M;

	wr32(hw, NSE_REG_INT_DYN_CTLN(q_vector->reg_idx), val);
}

int
nse_vsi_start_tx_ring(struct nse_vsi *vsi, struct nse_ring *ring)
{
	/* reg_idx is common to both of regular-txq and xdp-txq */
	u16 txq_abs_id = vsi->back->lan_txq_space_start + ring->reg_idx;
	int ret;

	ret = nse_aq_lan_enable_txq(&vsi->back->hw, txq_abs_id, ring->irqll_msix);

	if (!ret && ring->need_irqll)
		ring->already_in_irqll = true;
	else
		ring->already_in_irqll = false;

	return ret;
}

/**
 * nse_vsi_stop_tx_ring - Disable single Tx ring
 * @vsi: the VSI being configured
 * @rst_src: reset source
 * @rel_vmvf_num: Relative ID of VF/VM
 * @ring: Tx ring to be stopped
 * @txq_meta: Meta data of Tx ring to be stopped
 */
int
nse_vsi_stop_tx_ring(struct nse_vsi *vsi,
		     struct nse_ring *ring,
		     struct nse_txq_meta *txq_meta, bool tdm_stopped)
{
	struct nse_pf *pf = vsi->back;
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_q_vector *q_vector;
	struct nse_hw *hw = &pf->hw;
	enum nse_status status = 0;

	if (!tdm_stopped) {
		(void)nse_aq_lan_disable_txq(hw, txq_meta->q_abs_id,
					ring->already_in_irqll ? ring->irqll_msix :
						NSE_AQC_CONF_IRQLL_INVALID_MSIX);

		ring->already_in_irqll = false;
	}

	/* trigger a software interrupt for the vector
	 * associated to the queue to schedule NAPI handler
	 */
	q_vector = ring->q_vector;
	if (q_vector)
		nse_trigger_sw_intr(hw, q_vector);

	/* destroy LEAF-node */
	status = nse_dis_vsi_txq(vsi->port_info, txq_meta->vsi_idx,
				 txq_meta->tc, txq_meta->q_handle,
				 txq_meta->q_abs_id, txq_meta->q_tnid);

	ring->txq_tnid = NSE_SCHED_INVAL_TNID;

	/* if the disable queue command was exercised during an
	 * active reset flow, NSE_ERR_RESET_ONGOING is returned.
	 * This is not an error as the reset operation disables
	 * queues at the hardware level anyway.
	 */
	if (status == NSE_ERR_HIGH_RESET_ONGOING) {
		dev_dbg(dev, "High_Reset in progress. LAN Tx queues already disabled\n");
	} else if (status == NSE_ERR_DOES_NOT_EXIST) {
		dev_dbg(dev, "LAN Tx queues do not exist, nothing to disable\n");
	} else if (status) {
		dev_err(dev, "Failed to disable LAN Tx queues, error: %s\n",
			nse_stat_str(status));
		return -EIO;
	}

	return 0;
}

/**
 * nse_fill_txq_meta - Prepare the Tx queue's meta data
 * @vsi: VSI that ring belongs to
 * @ring: ring that txq_meta will be based on
 * @txq_meta: a helper struct that wraps Tx queue's information
 *
 * Set up a helper struct that will contain all the necessary fields that
 * are needed for stopping Tx queue
 */
void
nse_fill_txq_meta(struct nse_vsi *vsi, struct nse_ring *ring,
		  struct nse_txq_meta *txq_meta)
{
	u8 tc;

	if (IS_ENABLED(CONFIG_DCB))
		tc = ring->dcb_tc;
	else
		tc = 0;
	txq_meta->q_abs_id = ring->abs_id;
	txq_meta->q_tnid = ring->txq_tnid;
	txq_meta->q_handle = ring->q_handle;

	txq_meta->vsi_idx = vsi->idx;
	txq_meta->tc = tc;
}

