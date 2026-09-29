// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024-2026 Mucse Corporation. */

#include <linux/fs.h>
#include <linux/debugfs.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include "mce.h"
#include "mce_fwchnl.h"
#include "mce_debugfs_regs.h"
#include "mce_n20/mce_hw_n20.h"
#include "mce_base.h"

struct item {
	unsigned char hi;
	unsigned char lo;
	char func_id;
	const char *value_fmt;
	const char *item_descript;
} __packed;

#define FIELD(bit_hi, bit_lo, fmt_str, descript) \
	(&((struct item){ bit_hi, bit_lo, -1, fmt_str, descript }))

#define F32(fmt_str, descript) \
	(&((struct item){ 31, 0, -1, fmt_str, descript }))
#define D32(descript) \
	(&((struct item){ 31, 0, -1, "%u", descript }))
#define D_32BIT (&((struct item){ 31, 0, -1, "%u", "" }))
#define D_FIELD(descript, bit_hi, bit_lo) \
	(&((struct item){ bit_hi, bit_lo, -1, "%u", descript }))
#define H32(descript) \
	(&((struct item){ 31, 0, -1, "0x%x", descript }))
#define Hex_32BIT (&((struct item){ 31, 0, -1, "0x%x", "" }))

#define FUNC_FIELD(func_id, descript, bit_hi, bit_lo, fmt_str) \
	(&((struct item){ bit_hi, bit_lo, func_id, fmt_str, descript }))

#define FUNC_D32(func_id) \
	(&((struct item){ 31, 0, func_id, "%u", "" }))
#define FUNC_D32_DESC(func_id, desc) \
	(&((struct item){ 31, 0, func_id, "%u", desc }))

#define CFG_RXMUX_CTRL_REG 0x8e584
#define DEBUG_RXMUX_BUS 0x86304

#define DEBUG_TXMUX_BUS 0x86550
#define CFG_TXMUX_CTRL_REG 0x8e588

#define DEBUG_RXTRANS_BUS 0x86300
#define CFG_RXTRANS_CTRL_REG 0x80470

#define DEBUG_TXTRANS_BUS 0x86554
#define CFG_TXTRANS_CTRL_REG 0x80474

#define EMAC_POST_CRTL_REG 0x8047c
#define RX_DEBUG24_REG 0x86460
#define RX_DEBUG25_REG 0x86464
#define RX_DEBUG26_REG 0x86468
#define RX_DEBUG27_REG 0x8646c

#define DBG_RX_SWITCH_BUS 0x73004
#define CFG_RX_SWITCH_CTRL_REG 0x73000

static inline unsigned int value_pick_bits(unsigned int v, int bit_hi,
					   int bit_lo)
{
	v = v >> bit_lo;

	return v & GENMASK(bit_hi - bit_lo, 0);
}

static inline unsigned int reg_read_bits(char *reg, int bit_hi, int bit_lo)
{
	unsigned int v;

	v = raw_rd32(reg);
	return value_pick_bits(v, bit_hi, bit_lo);
}

static inline void reg_modify_bits(u8 __iomem *reg, int bit_hi, int bit_lo,
				   int value_no_shift)
{
	unsigned int v, mask;

	mask = GENMASK(bit_hi, bit_lo);

	value_no_shift &= GENMASK(bit_hi - bit_lo, 0);

	v = raw_rd32(reg);
	v &= ~((unsigned int)mask);
	v |= value_no_shift << bit_lo;
	raw_wr32(v, reg);
}

static int do_indir_func_reg_read(struct mce_hw *hw, int reg, int func_id,
				  int *v)
{
	if (!(reg >= 0 && reg < 2 * 1024 * 1024))
		return -EINVAL;

	switch (reg) {
	case DEBUG_RXMUX_BUS: {
		reg_modify_bits(hw->eth_bar_base + CFG_RXMUX_CTRL_REG, 31, 27,
				func_id);

		*v = raw_rd32(hw->eth_bar_base + reg);
		break;
	}
	case DEBUG_TXMUX_BUS: {
		reg_modify_bits(hw->eth_bar_base + CFG_TXMUX_CTRL_REG, 31, 27,
				func_id);

		*v = raw_rd32(hw->eth_bar_base + reg);
		break;
	}
	case DEBUG_RXTRANS_BUS: {
		reg_modify_bits(hw->eth_bar_base + CFG_RXTRANS_CTRL_REG, 29, 24,
				func_id);

		*v = raw_rd32(hw->eth_bar_base + reg);
		break;
	}
	case RX_DEBUG24_REG:
	case RX_DEBUG25_REG:
	case RX_DEBUG26_REG:
	case RX_DEBUG27_REG: {
		reg_modify_bits(hw->eth_bar_base + EMAC_POST_CRTL_REG, 23, 16,
				func_id);

		*v = raw_rd32(hw->eth_bar_base + reg);
		break;
	}
	case 0x86500:
	case 0x86504:
	case 0x86508: {
		reg_modify_bits(hw->eth_bar_base + 0x880f8, 31, 28, func_id);

		*v = raw_rd32(hw->eth_bar_base + reg);
		break;
	}

	case DEBUG_TXTRANS_BUS: {
		reg_modify_bits(hw->eth_bar_base + CFG_TXTRANS_CTRL_REG, 29, 24,
				func_id);

		*v = raw_rd32(hw->eth_bar_base + reg);
		break;
	}
	case DBG_RX_SWITCH_BUS: {
		reg_modify_bits(hw->eth_bar_base + CFG_RX_SWITCH_CTRL_REG, 21,
				16, func_id);

		*v = raw_rd32(hw->eth_bar_base + reg);
		break;
	}
	default: {
		return -EINVAL;
	}
	}

	return 0;
}

static int do_normal_reg_read(struct mce_hw *hw, int reg, int *v)
{
	if (reg >= 0 && reg < 2 * 1024 * 1024) { /* bar4 reg */
		*v = raw_rd32(hw->eth_bar_base + reg);
	} else if (reg >= 0x30000000 && reg < 0x80000000) {
		/* soc reg */
		if (mce_soc_ioread32(hw, reg, v))
			return -EIO;
	} else {
		return -EINVAL;
	}
	return 0;
}

static int snprintf_reg(struct mce_hw *hw, char *big_buf, int big_buf_sz,
			const char *descript, int reg, ...)
{
	int i, cnt = 0, v, err, fun_id_printed = 0;
	int bsz = 4096;
	va_list args;
	char *buf = kmalloc(bsz, GFP_KERNEL);

	if (!buf)
		return 0;

	va_start(args, reg);

	cnt += snprintf(buf + cnt, bsz - cnt, "%-30s 0x%-8x: ", descript, reg);

	for (i = 0; i < 32; i++) {
		struct item *it = va_arg(args, struct item *);

		if (!it)
			break;

		if (i != 0) {
			cnt += snprintf(buf + cnt, bsz - cnt, ",\t");
			if ((i % 3) == 0) {
				cnt += snprintf(buf + cnt, bsz - cnt,
						"\n\t\t\t\t\t\t\t");
			}
		}

		if (it->func_id >= 0 && it->func_id < 250 &&
		    fun_id_printed == 0) {
			cnt += snprintf(buf + cnt, bsz - cnt, "F%-2d ",
					it->func_id);
			fun_id_printed = 1;
			err = do_indir_func_reg_read(hw, reg, it->func_id, &v);
		} else {
			err = do_normal_reg_read(hw, reg, &v);
		}

		if (it->item_descript && strlen(it->item_descript) >= 1) {
			cnt += snprintf(buf + cnt, bsz - cnt, "%s",
					it->item_descript);
		}

		if (err) {
			cnt += snprintf(buf + cnt, bsz - cnt, " !read error!");
			continue;
		}

		if (!(it->hi == 31 && it->lo == 0)) {
			if (it->hi == it->lo) {
				cnt += snprintf(buf + cnt, bsz - cnt,
						"[%d]=", it->hi);
			} else {
				cnt += snprintf(buf + cnt, bsz - cnt,
						"[%d:%d]=", it->hi, it->lo);
			}
		}

		v = value_pick_bits(v, it->hi, it->lo);
		if (!it->value_fmt || strlen(it->value_fmt) == 0) {
			cnt += snprintf(buf + cnt, bsz - cnt, "%u / 0x%x", v,
					v);
		} else {
			cnt += snprintf(buf + cnt, bsz - cnt, it->value_fmt, v);
		}
	}

	cnt += snprintf(buf + cnt, bsz - cnt, "\n");
	buf[cnt] = 0;

	va_end(args);

	if (cnt > big_buf_sz)
		cnt = big_buf_sz;
	strncpy(big_buf, buf, cnt);

	kfree(buf);

	return cnt;
}

static int snprintf_reg_array(struct mce_hw *hw, char *big_buf, int big_buf_sz,
			      const char *descript, int reg, const struct item *items)
{
	int i, cnt = 0, v, err, fun_id_printed = 0;
	int bsz = 4096;
	char *buf = kmalloc(bsz, GFP_KERNEL);

	if (!buf)
		return 0;

	cnt += snprintf(buf + cnt, bsz - cnt, "%-30s 0x%-8x: ", descript, reg);

	for (i = 0; items[i].item_descript; i++) {
		const struct item *it = &items[i];

		if (!it)
			break;

		if (i != 0) {
			cnt += snprintf(buf + cnt, bsz - cnt, ",\t");
			if ((i % 3) == 0) {
				cnt += snprintf(buf + cnt, bsz - cnt,
						"\n\t\t\t\t\t\t\t");
			}
		}

		if (it->func_id >= 0 && it->func_id < 250 &&
		    fun_id_printed == 0) {
			cnt += snprintf(buf + cnt, bsz - cnt, "F%-2d ",
					it->func_id);
			fun_id_printed = 1;
			err = do_indir_func_reg_read(hw, reg, it->func_id, &v);
		} else {
			err = do_normal_reg_read(hw, reg, &v);
		}

		if (it->item_descript && strlen(it->item_descript) >= 1) {
			cnt += snprintf(buf + cnt, bsz - cnt, "%s",
					it->item_descript);
		}

		if (err) {
			cnt += snprintf(buf + cnt, bsz - cnt, " !read error!");
			continue;
		}

		if (!(it->hi == 31 && it->lo == 0)) {
			if (it->hi == it->lo) {
				cnt += snprintf(buf + cnt, bsz - cnt,
						"[%d]=", it->hi);
			} else {
				cnt += snprintf(buf + cnt, bsz - cnt,
						"[%d:%d]=", it->hi, it->lo);
			}
		}

		v = value_pick_bits(v, it->hi, it->lo);
		if (!it->value_fmt || strlen(it->value_fmt) == 0) {
			cnt += snprintf(buf + cnt, bsz - cnt, "%u / 0x%x", v,
					v);
		} else {
			cnt += snprintf(buf + cnt, bsz - cnt, it->value_fmt, v);
		}
	}

	cnt += snprintf(buf + cnt, bsz - cnt, "\n");
	buf[cnt] = 0;

	if (cnt > big_buf_sz)
		cnt = big_buf_sz;
	strncpy(big_buf, buf, cnt);

	kfree(buf);

	return cnt;
}

#define SNPRINTF_REG(args...) \
	snprintf_reg(hw, buf + cnt, buf_sz - cnt, args, NULL)
#define SNPRINTF(args...) snprintf(buf + cnt, buf_sz - cnt, args)
#define SNPRINTF_REG_ARRAY(desc, reg, arrary) \
	snprintf_reg_array(hw, buf + cnt, buf_sz - cnt, desc, reg, arrary)

static int sprint_n20_rx_dma_status_counters1_2(struct mce_pf *pf,
						struct mce_hw *hw, char *buf,
						int buf_sz)
{
	int cnt = 0;
	{
		cnt += SNPRINTF_REG("dma_axi_state_p1", 0x40104,
				    D_FIELD("axi_rd_record_cnt", 15, 0),
				    D_FIELD("axi_wr_record_cnt", 31, 16));
		cnt += SNPRINTF_REG("dma_queue_rx_p0", 0x40108,
				    D_FIELD("desc_req[0]", 0, 0),
				    D_FIELD("desc_req[1]", 1, 1),
				    D_FIELD("desc_req[2]", 2, 2),
				    D_FIELD("desc_req[3]", 3, 3),
				    D_FIELD("gnt_occur_0", 4, 4),
				    D_FIELD("gnt_occur_1", 5, 5),
				    D_FIELD("gnt_occur_2", 6, 6),
				    D_FIELD("gnt_occur_3", 7, 7),
				    D_FIELD("gnt_reqing_0", 8, 8),
				    D_FIELD("gnt_reqing_1", 9, 9),
				    D_FIELD("gnt_reqing_2", 10, 10),
				    D_FIELD("gnt_reqing_3", 11, 11),
				    D_FIELD("gnt_occur", 12, 12),
				    D_FIELD("gnt_reqing", 13, 13),
				    D_FIELD("|desc_rq", 14, 14),
				    D_FIELD("dma_fetch_cnt", 31, 16));
	}

	{
		cnt += SNPRINTF_REG("dma_queue_rx_p1", 0x4010c,
			D_FIELD("((desc_req_len[0]+queue_desc_fetch_cnt[0])<="
				"dma_desc_fifo_unuse[0])",
				0, 0),
			D_FIELD("#1", 1, 1), D_FIELD("#2", 2, 2),
			D_FIELD("#3", 3, 3), D_FIELD("#4", 4, 4),
			D_FIELD("#5", 5, 5), D_FIELD("#6", 6, 6),
			D_FIELD("#7", 7, 7), D_FIELD("#8", 8, 8),
			D_FIELD("#9", 9, 9), D_FIELD("#10", 10, 10),
			D_FIELD("#11", 11, 11), D_FIELD("#12", 12, 12),
			D_FIELD("#13", 13, 13), D_FIELD("#14", 14, 14),
			D_FIELD("#15", 15, 15), D_FIELD("#16", 16, 16),
			D_FIELD("#17", 17, 17), D_FIELD("#18", 18, 18),
			D_FIELD("#19", 19, 19), D_FIELD("#20", 20, 20),
			D_FIELD("#21", 21, 21), D_FIELD("#22", 22, 22),
			D_FIELD("#23", 23, 23),
			D_FIELD("(queue_desc_fetch_cnt[0] == 0)", 24, 24),
			D_FIELD("(queue_desc_fetch_cnt[1] == 0)", 25, 25),
			D_FIELD("(queue_desc_fetch_cnt[2] == 0)", 26, 26),
			D_FIELD("(queue_desc_fetch_cnt[3] == 0)", 27, 27),
			D_FIELD("(queue_desc_fetch_cnt[4] == 0)", 28, 28),
			D_FIELD("(queue_desc_fetch_cnt[5] == 0)", 29, 29),
			D_FIELD("(queue_desc_fetch_cnt[6] == 0)", 30, 30),
			D_FIELD("(queue_desc_fetch_cnt[7] == 0)", 31, 31));
	}

	return cnt;
}

static int sprint_n20_rx_dma_status_counters2(struct mce_pf *pf,
					      struct mce_hw *hw, char *buf,
					      int buf_sz)
{
	int cnt = 0;

	if (buf_sz <= 0)
		return 0;
	cnt += SNPRINTF_REG("dma_ctrl_rx_p0", 0x40110,
			    D_FIELD("req_state", 1, 0),
			    D_FIELD("rxpkt_state", 4, 2),
			    D_FIELD("desc_req", 5, 5),
			    D_FIELD("new_rxpkt_desc_empty", 6, 6),
			    D_FIELD("new_rxpkt_desc_lost", 7, 7),
			    D_FIELD("desc_fifo_empty[0]", 8, 8),
			    D_FIELD("desc_fifo_empty[1]", 9, 9),
			    D_FIELD("desc_fifo_empty[2]", 10, 10),
			    D_FIELD("desc_fifo_empty[3]", 11, 11),
			    D_FIELD("desc_fifo_full[0]", 12, 12),
			    D_FIELD("desc_fifo_full[1]", 13, 13),
			    D_FIELD("desc_fifo_full[2]", 14, 14),
			    D_FIELD("desc_fifo_full[3]", 15, 15),
			    D_FIELD("desc_fifo_lost[0]", 16, 16),
			    D_FIELD("desc_fifo_lost[1]", 17, 17),
			    D_FIELD("desc_fifo_lost[2]", 18, 18),
			    D_FIELD("desc_fifo_lost[3]", 19, 19),
			    D_FIELD("rx_desc_len_err", 20, 20),
			    D_FIELD("rx_rxpkt_len_err", 21, 21),
			    D_FIELD("rx_rxpkt_sop_err", 22, 22),
			    D_FIELD("rx_rxpkt_eop_err", 23, 23),
			    D_FIELD("new_rxpkt_desc_id", 31, 24));

	cnt += SNPRINTF_REG("dma_ififo_rx_p0", 0x40118,
			    D_FIELD("data_fifo_full", 0, 0),
			    D_FIELD("data_fifo_empty", 1, 1),
			    D_FIELD("len_fifo_full", 2, 2),
			    D_FIELD("len_fifo_empty", 3, 3),
			    D_FIELD("len_fifo_cmax", 11, 4),
			    D_FIELD("data_fifo_full_occur", 14, 14),
			    D_FIELD("len_fifo_full_occur", 15, 15),
			    D_FIELD("data_fifo_full_wr", 16, 16),
			    D_FIELD("data_fifo_empty_rd", 17, 17),
			    D_FIELD("len_fifo_full_wr", 18, 18),
			    D_FIELD("len_fifo_empty_rd", 19, 19));

	cnt += SNPRINTF_REG("dma_ofifo_rx_p0", 0x40120,
			    D_FIELD("ofifo_data_fifo_full", 0, 0),
			    D_FIELD("ofifo_data_fifo_empty", 1, 1),
			    D_FIELD("ofifo_len_fifo_full", 2, 2),
			    D_FIELD("ofifo_len_fifo_empty", 3, 3),
			    D_FIELD("ofifo_len_fifo_cmax", 11, 4),
			    D_FIELD("ofifo_data_fifo_full_occur", 14, 14),
			    D_FIELD("ofifo_len_fifo_full_occur", 15, 15),
			    D_FIELD("ofifo_data_fifo_full_wr", 16, 16),
			    D_FIELD("ofifo_data_fifo_empty_rd", 17, 17),
			    D_FIELD("ofifo_len_fifo_full_wr", 18, 18),
			    D_FIELD("ofifo_len_fifo_empty_rd", 19, 19));
	return cnt;
}

static int sprint_n20_rx_dma_status_counters2_2(struct mce_pf *pf,
						struct mce_hw *hw, char *buf,
						int buf_sz)
{
	int cnt = 0;

	if (buf_sz <= 0)
		return 0;

	cnt += SNPRINTF_REG("dma_ctrl_rx_p1", 0x40114,
			    D_FIELD("rx_rxpkt_drop_cnt", 15, 0),
			    D_FIELD("desc_resp_cnt", 31, 16));

	cnt += SNPRINTF_REG("dma_ififo_rx_p1", 0x4011c,
			    D_FIELD("ififo_rx_data_sop_wcnt", 7, 0),
			    D_FIELD("ififo_rx_data_sop_rnt", 15, 8),
			    D_FIELD("ififo_rx_data_eop_wcnt", 23, 16),
			    D_FIELD("ififo_rx_data_eop_rnt", 31, 24));

	cnt += SNPRINTF_REG("dma_ofifo_rx_p1", 0x40124,
			    D_FIELD("data_sop_wcnt", 7, 0),
			    D_FIELD("data_sop_rcnt", 15, 8),
			    D_FIELD("data_eop_wcnt", 23, 16),
			    D_FIELD("data_eop_rcnt", 31, 24));

	cnt += SNPRINTF_REG("dma_axi_tx_p0", 0x40138, D_FIELD("rd_cmd_state", 1, 0),
		D_FIELD("wr_cmd_state", 3, 2), D_FIELD("wr_pkt_state", 5, 4),
		D_FIELD("bfifo_id_empty", 6, 6), D_FIELD("bfifo_id_full", 7, 7),
		D_FIELD("bfifo_id_full_occur", 8, 8),
		D_FIELD("rd_addr_len_verify_2", 10, 10),
		D_FIELD("wr_addr_len_verify_2", 11, 11),
		D_FIELD("rd_addr_len_verify_0", 12, 12),
		D_FIELD("rd_addr_len_verify_1", 13, 13),
		D_FIELD("wr_addr_len_verify_0", 14, 14),
		D_FIELD("wr_addr_len_verify_1", 15, 15),
		D_FIELD("dma_rd_aready", 16, 16), D_FIELD("dma_rd_rdy", 17, 17),
		D_FIELD("dma_wr_aready", 18, 18), D_FIELD("dma_wr_rdy", 19, 19),
		D_FIELD("arready", 20, 20), D_FIELD("rready", 21, 21),
		D_FIELD("awready", 22, 22), D_FIELD("wready", 23, 23),
		D_FIELD("rresp_result_0 rresp==0", 24, 24),
		D_FIELD("rresp_result_1 rresp==0", 25, 25),
		D_FIELD("rresp_result_2 rresp==0", 26, 26),
		D_FIELD("rresp_result_3 rresp==0", 27, 27),
		D_FIELD("bresp_result_0 bresp==0", 28, 28),
		D_FIELD("bresp_result_1 bresp==0", 29, 29),
		D_FIELD("bresp_result_2 bresp==0", 30, 30),
		D_FIELD("bresp_result_3 bresp==0", 31, 31));

	return cnt;
}

static int sprint_n20_rx_dma_status_counters3(struct mce_pf *pf,
					      struct mce_hw *hw, char *buf,
					      int buf_sz)
{
	int cnt = 0;

	if (buf_sz <= 0)
		return 0;

	cnt += SNPRINTF_REG("dma_axi_tx_p1", 0x4013c,
			    D_FIELD("axi_rd_record_cnt", 15, 0),
			    D_FIELD("axi_wr_record_cnt", 31, 16));

	cnt += SNPRINTF_REG("count_dma_ctrl_tx_3_p0", 0x40214,
			    D_FIELD("req-pkt-len", 17, 0),
			    D_FIELD("FIFO-out", 29, 20),
			    D_FIELD("queu-ctl-fifo-empty-signal", 31, 31));

	cnt += SNPRINTF_REG("dma_queue_tx_irq_0", 0x40200, D_32BIT);
	cnt += SNPRINTF_REG("dma_queue_rx_irq_0", 0x40204, D_32BIT);
	cnt += SNPRINTF_REG("dma_ctrl_tx_0:ch0 tx segments", 0x40208, D_32BIT);
	cnt += SNPRINTF_REG("1:que-desc write-full", 0x4020c, D_32BIT);
	cnt += SNPRINTF_REG("2:queu-descs read-empty", 0x40210, D_32BIT);
	cnt += SNPRINTF_REG("4:read queue-desc cnt", 0x40218, D_32BIT);
	cnt += SNPRINTF_REG("5:write queue-desc cnt", 0x4021c, D_32BIT);

	cnt += SNPRINTF_REG("6:tx fifo 0 desc-avg-cnt", 0x40220, D_32BIT);
	cnt += SNPRINTF_REG("7:tx fifo 1 desc-avg-cnt", 0x40224, D_32BIT);
	cnt += SNPRINTF_REG("8:tx fifo 2 desc-avg-cnt", 0x40228, D_32BIT);
	cnt += SNPRINTF_REG("9:tx fifo 3 desc-avg-cnt", 0x4023c, D_32BIT);

	cnt += SNPRINTF_REG("dma_ctrl_rx_0:pcie read-req-cnt", 0x40230,
			    D_32BIT);
	cnt += SNPRINTF_REG("dma_ctrl_rx_1:pcie write-req-cnt", 0x40234,
			    D_32BIT);
	cnt += SNPRINTF_REG("dma_ctrl_rx2:desc-write(|received_desc_wr)",
			    0x40238, D_32BIT);
	cnt += SNPRINTF_REG("dma_ctrl_rx_3:desc-read(|cur_desc_rd)", 0x4023c,
			    D_32BIT);

	cnt += SNPRINTF_REG("rx fifo 0 avg-desc cnt", 0x40240, D_32BIT);
	cnt += SNPRINTF_REG("rx fifo 1 avg-desc cnt", 0x40244, D_32BIT);
	cnt += SNPRINTF_REG("rx fifo 2 avg-desc cnt", 0x40248, D_32BIT);
	cnt += SNPRINTF_REG("rx fifo 3 avg-desc cnt", 0x4024c, D_32BIT);

	cnt += SNPRINTF_REG("rx ring 0 data-no-desc-avg-cnt", 0x250, D_32BIT);
	cnt += SNPRINTF_REG("rx ring 1 data-no-desc-avg-cnt", 0x254, D_32BIT);
	cnt += SNPRINTF_REG("rx ring 2 data-no-desc-avg-cnt", 0x258, D_32BIT);
	cnt += SNPRINTF_REG("rx ring 3 data-no-desc-avg-cnt", 0x25c, D_32BIT);
	return cnt;
}

static int sprint_n20_rx_dma_status_counters3_2(struct mce_pf *pf,
						struct mce_hw *hw, char *buf,
						int buf_sz)
{
	int cnt = 0;

	if (buf_sz <= 0)
		return 0;

	cnt += SNPRINTF_REG("tx:cmd-read-cnt", 0x40260, D_32BIT);
	cnt += SNPRINTF_REG("tx:write-cmd-cnt", 0x40264, D_32BIT);
	cnt += SNPRINTF_REG("tx:read-cmd-respond", 0x40268, D_32BIT);
	cnt += SNPRINTF_REG("tx:write-cmd-respond", 0x4026c, D_32BIT);

	cnt += SNPRINTF_REG("tx:read-cmd-avg", 0x40270, D_32BIT);
	cnt += SNPRINTF_REG("tx:write-cmd-avg", 0x40274, D_32BIT);
	cnt += SNPRINTF_REG("tx:read-data-avg", 0x40278, D_32BIT);
	cnt += SNPRINTF_REG("tx:write-data-avg", 0x4027c, D_32BIT);

	cnt += SNPRINTF_REG("rx:read-cmd", 0x40280, D_32BIT);
	cnt += SNPRINTF_REG("rx:write-cmd", 0x40284, D_32BIT);
	cnt += SNPRINTF_REG("rx:read-cmd-respond", 0x40288, D_32BIT);
	cnt += SNPRINTF_REG("rx:write-cmd-respond", 0x4028c, D_32BIT);

	cnt += SNPRINTF_REG("rx:read-cmd-avg", 0x40290, D_32BIT);
	cnt += SNPRINTF_REG("rx:write-cmd-avg", 0x40294, D_32BIT);
	cnt += SNPRINTF_REG("rx:read-data-avg", 0x40298, D_32BIT);
	cnt += SNPRINTF_REG("rx:write-data-avg", 0x4029c, D_32BIT);

	cnt += SNPRINTF_REG("dma_ififo_rx_0:rx:data in-pkt", 0x402a0, D_32BIT);
	cnt += SNPRINTF_REG("dma_ififo_rx_1:rx:data out-pkt", 0x402a4, D_32BIT);
	cnt += SNPRINTF_REG("dma_ofifo_rx_0:rx:data in-pkt", 0x402a8, D_32BIT);
	cnt += SNPRINTF_REG("dma_ofifo_rx_1:rx:data out-pkt", 0x402ac, D_32BIT);

	cnt += SNPRINTF_REG("count_dma_scatter_0", 0x402b0, D_32BIT);
	cnt += SNPRINTF_REG("count_dma_scatter_1", 0x402b4, D_32BIT);
	cnt += SNPRINTF_REG("dma_input_unuse0", 0x402b8, D_32BIT);
	cnt += SNPRINTF_REG("dma_input_unuse1", 0x402bc, D_32BIT);

	cnt += SNPRINTF_REG("dma_axi_tx_8:tx: last-desc dd-flag time-take",
			    0x402c0, D_32BIT);
	cnt += SNPRINTF_REG("dma_axi_rx_8:rx: last-desc dd-flag time-take",
			    0x402c4, D_32BIT);
	cnt += SNPRINTF_REG("dma_debug_int_cnt_tx_0:tx ring0 irq-stat", 0x402c8,
			    D_32BIT);
	cnt += SNPRINTF_REG("tx ring1 irq-stat", 0x402cc, D_32BIT);
	cnt += SNPRINTF_REG("tx ring2 irq-stat", 0x402d0, D_32BIT);
	cnt += SNPRINTF_REG("tx ring3 irq-stat", 0x402d4, D_32BIT);

	cnt += SNPRINTF_REG("dma_debug_int_cnt_rx_0:rx ring0 irq-stat", 0x402d8,
			    D_32BIT);
	cnt += SNPRINTF_REG("rx ring1 irq-stat", 0x402e0, D_32BIT);
	cnt += SNPRINTF_REG("rx ring2 irq-stat", 0x402e4, D_32BIT);
	cnt += SNPRINTF_REG("rx ring3 irq-stat", 0x402e8, D_32BIT);
	return cnt;
}

static int sprint_n20_rx_dma_status_counters(struct mce_pf *pf,
					     struct mce_hw *hw, char *buf,
					     int buf_sz)
{
	int cnt = 0;

	if (buf_sz <= 0)
		return 0;

	cnt += SNPRINTF_REG("dma_axi_state_p0", 0x40100, D_FIELD("rd_cmd_state", 1, 0),
		D_FIELD("wr_cmd_state", 3, 2), D_FIELD("wr_pkt_state", 5, 4),
		D_FIELD("bfifo_id_empty", 6, 6), D_FIELD("bfifo_id_full", 7, 7),
		D_FIELD("bfifo_id_full_occur", 8, 8),
		D_FIELD("rd_addr_len_verify_2", 10, 10),
		D_FIELD("wr_addr_len_verify_2", 11, 11),
		D_FIELD("rd_addr_len_verify_0", 12, 12),
		D_FIELD("rd_addr_len_verify_1", 13, 13),
		D_FIELD("wr_addr_len_verify_0", 14, 14),
		D_FIELD("wr_addr_len_verify_1", 15, 15),
		D_FIELD("dma_rd_aready", 16, 16), D_FIELD("dma_rd_rdy", 17, 17),
		D_FIELD("dma_wr_aready", 18, 18), D_FIELD("dma_wr_rdy", 19, 19),
		D_FIELD("arready", 20, 20), D_FIELD("rready", 21, 21),
		D_FIELD("awready", 22, 22), D_FIELD("wready", 23, 23),
		D_FIELD("rresp_result_0 rresp==0", 24, 24),
		D_FIELD("rresp_result_1 rresp==0", 25, 25),
		D_FIELD("rresp_result_2 rresp==0", 26, 26),
		D_FIELD("rresp_result_3 rresp==0", 27, 27),
		D_FIELD("bresp_result_0 bresp==0", 28, 28),
		D_FIELD("bresp_result_1 bresp==0", 29, 29),
		D_FIELD("bresp_result_2 bresp==0", 30, 30),
		D_FIELD("bresp_result_3 bresp==0", 31, 31));

	cnt += sprint_n20_rx_dma_status_counters1_2(pf, hw, buf + cnt,
						    buf_sz - cnt);
	cnt += sprint_n20_rx_dma_status_counters2(pf, hw, buf + cnt,
						  buf_sz - cnt);
	cnt += sprint_n20_rx_dma_status_counters2_2(pf, hw, buf + cnt,
						    buf_sz - cnt);
	cnt += sprint_n20_rx_dma_status_counters3(pf, hw, buf + cnt,
						  buf_sz - cnt);
	cnt += sprint_n20_rx_dma_status_counters3_2(pf, hw, buf + cnt,
						    buf_sz - cnt);
	return cnt;
}

int debugfs_tx_queue_show(struct mce_pf *pf, struct mce_hw *hw, char *buf,
			  int buf_sz)
{
	int cnt = 0, i;

	int queue_cnt = pf->debugfs_queue_end - pf->debugfs_queue_start + 1;
	int start_queue_id = pf->debugfs_queue_start;

	if (buf_sz <= 0)
		return 0;

	cnt += SNPRINTF("\n=dma tx queue:(%d~%d)==\n", start_queue_id,
			start_queue_id + queue_cnt - 1);

	for (i = 0; i < queue_cnt; i++) {
		int queue_addr_off = 0x100 * (i + start_queue_id);

		cnt += SNPRINTF("=queue%d=\n", i + start_queue_id);

		cnt += SNPRINTF_REG("tx_queue_enabled", 0x018 + queue_addr_off,
				    D_32BIT);
		cnt += SNPRINTF_REG("tx_queue_empty", 0x01c + queue_addr_off,
				    D_32BIT);
		cnt += SNPRINTF_REG("tx_queue_base_addr_hi",
				    0x060 + queue_addr_off, Hex_32BIT);
		cnt += SNPRINTF_REG("tx_queue_base_addr_lo",
				    0x064 + queue_addr_off, Hex_32BIT);
		cnt += SNPRINTF_REG("tx_queue_len", 0x068 + queue_addr_off,
				    D_32BIT);
		cnt += SNPRINTF_REG("tx_queue_hw_head", 0x06c + queue_addr_off,
				    D_32BIT);
		cnt += SNPRINTF_REG("tx_queue_hw_tail", 0x070 + queue_addr_off,
				    D_32BIT);

		cnt += SNPRINTF_REG("tx_hw_fetch_ctr", 0x074 + queue_addr_off,
				    D_FIELD("burst_size", 31, 16),
				    D_FIELD("stop fetch thresh", 15, 0));

		cnt += SNPRINTF_REG("tx_fetch_priority_lv",
				    0x080 + queue_addr_off, D_32BIT);
		cnt += SNPRINTF_REG("tx_reset_vf_to_vf", 0x2cc + queue_addr_off,
				    D_32BIT);
		cnt += SNPRINTF_REG("rx_reset_recv_vf", 0x2d4 + queue_addr_off,
				    D_32BIT);
		cnt += SNPRINTF_REG("dma_queue_interrupt_stat",
				    0x020 + queue_addr_off, D_32BIT);
		cnt += SNPRINTF_REG("dma_queue_interrupt_mask",
				    0x024 + queue_addr_off, Hex_32BIT);
		cnt += SNPRINTF_REG("dma_queue_interrupt_clear",
				    0x028 + queue_addr_off, Hex_32BIT);
		cnt += SNPRINTF_REG("tx_int_delay_timer",
				    0x074 + queue_addr_off,
				    D_FIELD("fifo-flow", 15, 0),
				    D_FIELD("max-fetch-descrpts", 31, 16));
		cnt += SNPRINTF_REG("tx_int_delay_timer",
				    0x078 + queue_addr_off, D_32BIT);
		cnt += SNPRINTF_REG("tx_int_delay_pkt", 0x07c + queue_addr_off,
				    D_32BIT);

		cnt += SNPRINTF_REG("dma_queue_tx_bytes_lo",
				    0x0e0 + queue_addr_off, D_32BIT);
		cnt += SNPRINTF_REG("dma_queue_tx_bytes_hi",
				    0x0e0 + 4 + queue_addr_off, D_32BIT);
		cnt += SNPRINTF_REG("dma_queue_tx_unicast_lo",
				    0x0e8 + queue_addr_off, D_32BIT);
		cnt += SNPRINTF_REG("dma_queue_tx_unicast_hi",
				    0x0e8 + 4 + queue_addr_off, D_32BIT);
		cnt += SNPRINTF_REG("dma_queue_tx_mucast_lo",
				    0x0f0 + queue_addr_off, D_32BIT);
		cnt += SNPRINTF_REG("dma_queue_tx_mucast_hi",
				    0x0f0 + 4 + queue_addr_off, D_32BIT);
		cnt += SNPRINTF_REG("dma_queue_tx_broadcast_lo",
				    0x0f8 + queue_addr_off, D_32BIT);
		cnt += SNPRINTF_REG("dma_queue_tx_broadcast_hi",
				    0x0f8 + 4 + queue_addr_off, D_32BIT);
	}

	return cnt;
}

int debugfs_rx_queue_show(struct mce_pf *pf, struct mce_hw *hw, char *buf,
			  int buf_sz)
{
	int queue_cnt = pf->debugfs_queue_end - pf->debugfs_queue_start + 1;
	int start_queue_id = pf->debugfs_queue_start;
	int cnt = 0, i;

	if (buf_sz <= 0)
		return 0;

	cnt += SNPRINTF("\n=dma rx queue:(%d~%d)==\n", start_queue_id,
			start_queue_id + queue_cnt - 1);

	for (i = 0; i < queue_cnt; i++) {
		int queue_addr_off = 0x100 * (i + start_queue_id);

		cnt += SNPRINTF("=queue%d=\n", i + start_queue_id);

		cnt += SNPRINTF_REG("rx_queue_enabled", 0x010 + queue_addr_off,
				    D_32BIT);
		cnt += SNPRINTF_REG("rx_queue_empty", 0x014 + queue_addr_off,
				    D_32BIT);
		cnt += SNPRINTF_REG("rx_queue_base_addr_hi",
				    0x030 + queue_addr_off, Hex_32BIT);
		cnt += SNPRINTF_REG("rx_queue_base_addr_lo",
				    0x034 + queue_addr_off, Hex_32BIT);
		cnt += SNPRINTF_REG("rx_queue_len", 0x038 + queue_addr_off,
				    D_32BIT);
		cnt += SNPRINTF_REG("rx_queue_hw_head", 0x03c + queue_addr_off,
				    D_32BIT);
		cnt += SNPRINTF_REG("rx_queue_hw_tail", 0x040 + queue_addr_off,
				    D_32BIT);

		cnt += SNPRINTF_REG("rx_hw_fetch_ctr", 0x044 + queue_addr_off,
				    D_FIELD("burst_size", 31, 16),
				    D_FIELD("stop fetch thresh", 15, 0));

		cnt += SNPRINTF_REG("rx_fetch_priority_lv",
				    0x050 + queue_addr_off, D_32BIT);
		cnt += SNPRINTF_REG("rx_queue_timeout_thresh",
				    0x054 + queue_addr_off, D_32BIT);
		cnt += SNPRINTF_REG("rx_dma_fifo_in", 0x280 + queue_addr_off,
				    D_32BIT);
		cnt += SNPRINTF_REG("rx_no_descs", 0x2e8 + queue_addr_off,
				    D_32BIT);
		cnt += SNPRINTF_REG("dma_queue_interrupt",
				    0x020 + queue_addr_off, D_32BIT);
		cnt += SNPRINTF_REG("dma_queue_interrupt_mask",
				    0x024 + queue_addr_off, Hex_32BIT);
		cnt += SNPRINTF_REG("dma_queue_interrupt_clear",
				    0x028 + queue_addr_off, Hex_32BIT);
		cnt += SNPRINTF_REG("dma_queue_rx_pkt_intx",
				    0x048 + queue_addr_off, D_32BIT);
		cnt += SNPRINTF_REG("dma_queue_rx_delay_pkt",
				    0x04c + queue_addr_off, D_32BIT);

		cnt += SNPRINTF_REG("dma_queue_drop_no_desc",
				    0x05c + queue_addr_off, D_32BIT);

		cnt += SNPRINTF_REG("dma_queue_rx_bytes_lo",
				    0x0c0 + queue_addr_off, D_32BIT);
		cnt += SNPRINTF_REG("dma_queue_rx_bytes_hi",
				    0x0c0 + 4 + queue_addr_off, D_32BIT);
		cnt += SNPRINTF_REG("dma_queue_rx_unicast_lo",
				    0x0c8 + queue_addr_off, D_32BIT);
		cnt += SNPRINTF_REG("dma_queue_rx_unicast_hi",
				    0x0c8 + 4 + queue_addr_off, D_32BIT);
		cnt += SNPRINTF_REG("dma_queue_rx_mucast_lo",
				    0x0d0 + queue_addr_off, D_32BIT);
		cnt += SNPRINTF_REG("dma_queue_rx_mucast_hi",
				    0x0d0 + 4 + queue_addr_off, D_32BIT);
		cnt += SNPRINTF_REG("dma_queue_rx_broadcast_lo",
				    0x0d8 + queue_addr_off, D_32BIT);
		cnt += SNPRINTF_REG("dma_queue_rx_broadcast_hi",
				    0x0d8 + 4 + queue_addr_off, D_32BIT);
	}

	return cnt;
}

static struct item rx_progfull_status_items[] = {
	{ 0, 0, -1, "%u", "port_rx_info_fifo_progfull" },
	{ 1, 1, -1, "%u", "port_rx_fifo_progfull" },
	{ 2, 2, -1, "%u", "ovsb_rx_info_fifo_progfull" },
	{ 3, 3, -1, "%u", "ovsb_rx_fifo_progfull" },
	{ 4, 4, -1, "%u", "fwd_info_fifo_progfull" },
	{ 5, 5, -1, "%u", "fwd_data_fifo_progfull" },
	{ 6, 6, -1, "%u", "fwd_key_fifo_progfull" },
	{ 7, 7, -1, "%u", "ups_info_fifo_progfull" },
	{ 8, 8, -1, "%u", "ups_data_fifo_progfull" },
	{ 9, 9, -1, "%u", "ups_key_fifo_progfull" },
	{ 10, 10, -1, "%u", "attr_info_fifo_progfull" },
	{ 11, 11, -1, "%u", "attr_data_fifo_progfull" },
	{ 12, 12, -1, "%u", "attr_key_fifo_progfull" },
	{ 13, 13, -1, "%u", "rqa_cov_fifo_progfull" },
	{ 14, 14, -1, "%u", "swcup0_info_fifo_progfull" },
	{ 15, 15, -1, "%u", "swcup0_fifo_progfull" },
	{ 16, 16, -1, "%u", "swcup1_info_fifo_progfull" },
	{ 17, 17, -1, "%u", "swcup1_fifo_progfull" },
	{ 18, 18, -1, "%u", "emac_sw2fc_info_fifo_progfull" },
	{ 19, 19, -1, "%u", "emac_sw2fc_fifo_progfull" },
	{ 20, 20, -1, "%u", "edtup_info_fifo_progfull" },
	{ 21, 21, -1, "%u", "edtup_data_fifo_progfull" },
	{ 22, 22, -1, "%u", "pfc0_gat_fifo_progfull" },
	{ 23, 23, -1, "%u", "pfc1_gat_fifo_progfull" },
	{ 24, 24, -1, "%u", "pfc0_gat_info_fifo_progfull" },
	{ 25, 25, -1, "%u", "pfc1_gat_info_fifo_progfull" },
	{ 26, 26, -1, "%u", "bmc_gat_info_fifo_progfull" },
	{ 27, 27, -1, "%u", "bmc_gat_fifo_progfull" },
	{ 28, 28, -1, "%u", "emac_bmc_info_fifo_progfull" },
	{ 29, 29, -1, "%u", "emac_bmc_fifo_progfull" },
	{ 0, 0, -1, NULL, NULL }
};

static struct item rx_fifo_full_status_items[] = {
	{ 0, 0, -1, "%u", "wr_port_rx_info_fifo_full" },
	{ 1, 1, -1, "%u", "wr_port_rx_fifo_full" },
	{ 2, 2, -1, "%u", "wr_ovsb_info_fifo_full" },
	{ 3, 3, -1, "%u", "wr_ovsb_fifo_full" },
	{ 4, 4, -1, "%u", "wr_fwd_info_full" },
	{ 5, 5, -1, "%u", "wr_fwd_data_full" },
	{ 6, 6, -1, "%u", "wr_fwd_key_full" },
	{ 7, 7, -1, "%u", "wr_ups_info_full" },
	{ 8, 8, -1, "%u", "wr_ups_data_full" },
	{ 9, 9, -1, "%u", "wr_ups_key_full" },
	{ 10, 10, -1, "%u", "wr_attr_info_full" },
	{ 11, 11, -1, "%u", "wr_attr_data_full" },
	{ 12, 12, -1, "%u", "wr_attr_key_full" },
	{ 13, 13, -1, "%u", "wr_rqa_cov_fifo_full" },
	{ 14, 14, -1, "%u", "wr_swcup0_info_fifo_full" },
	{ 15, 15, -1, "%u", "wr_swcup0_data_fifo_full" },
	{ 16, 16, -1, "%u", "wr_swcup1_info_fifo_full" },
	{ 17, 17, -1, "%u", "wr_swcup1_data_fifo_full" },
	{ 18, 18, -1, "%u", "wr_emac_sw2fc_info_fifo_full" },
	{ 19, 19, -1, "%u", "wr_emac_sw2fc_fifo_full" },
	{ 20, 20, -1, "%u", "wr_edtup_info_fifo_full" },
	{ 21, 21, -1, "%u", "wr_edtup_data_fifo_full" },
	{ 22, 22, -1, "%u", "wr_pfc0_gat_fifo_full" },
	{ 23, 23, -1, "%u", "wr_pfc1_gat_fifo_full" },
	{ 24, 24, -1, "%u", "wr_pfc0_gat_info_fifo_full" },
	{ 25, 25, -1, "%u", "wr_pfc1_gat_info_fifo_full" },
	{ 26, 26, -1, "%u", "wr_bmc_gat_info_fifo_full" },
	{ 27, 27, -1, "%u", "wr_bmc_gat_fifo_full" },
	{ 28, 28, -1, "%u", "wr_emac_bmc_info_fifo_full" },
	{ 29, 29, -1, "%u", "wr_emac_bmc_fifo_full" },
	{ 0, 0, -1, NULL, NULL }
};

static int sprint_n20_rx_debug1_0(struct mce_pf *pf, struct mce_hw *hw,
				  char *buf, int buf_sz)
{
	int cnt = 0;

	cnt += SNPRINTF_REG("emac_rx_fifo_extend_states", 0x8640c,
			    D_FIELD("wr_port_rx_info_fifo_pfull", 7, 0),
			    D_FIELD("wr_port_rx_data_fifo_pfull", 15, 8),
			    D_FIELD("wr_port_rx_info_fifo_full", 23, 16),
			    D_FIELD("wr_port_rx_data_fifo_full", 31, 24));

	cnt += SNPRINTF_REG("emac_rx_fifo_empty_status0", 0x86410,
			    D_FIELD("port_rx_data_fifo_empty_w", 0, 0),
			    D_FIELD("port_rx_info_fifo_empty_w", 1, 1),
			    D_FIELD("port_rx_info_fifo_empty", 2, 2),
			    D_FIELD("port_rx_fifo_empty", 3, 3),
			    D_FIELD("ovsb_rx_info_fifo_empty", 4, 4),
			    D_FIELD("ovsb_rx_fifo_empty", 5, 5),
			    D_FIELD("fwd_info_fifo_empty", 6, 6),
			    D_FIELD("fwd_data_fifo_empty", 7, 7),
			    D_FIELD("fwd_key_fifo_empty", 8, 8),
			    D_FIELD("ups_info_fifo_empty", 9, 9),
			    D_FIELD("ups_data_fifo_empty", 10, 10),
			    D_FIELD("ups_key_fifo_empty", 11, 11),
			    D_FIELD("attr_info_fifo_empty", 12, 12),
			    D_FIELD("attr_data_fifo_empty", 13, 13),
			    D_FIELD("attr_key_fifo_empty", 14, 14),
			    D_FIELD("rqa_cov_fifo_empty", 15, 15),
			    D_FIELD("swcup0_info_fifo_empty", 16, 16),
			    D_FIELD("swcup0_data_fifo_empty", 17, 17));

	return cnt;
}

static int sprint_n20_rx_debug1_1(struct mce_pf *pf, struct mce_hw *hw,
				  char *buf, int buf_sz)
{
	int cnt = 0;

	cnt += SNPRINTF_REG("emac_rx_fifo_empty_status1", 0x86414,
			    D_FIELD("swcpu1_info_fifo_empty", 0, 0),
			    D_FIELD("swcpu1_data_fifo_empty", 1, 1),
			    D_FIELD("emac_sw2fc_info_fifo_empty", 2, 2),
			    D_FIELD("emac_sw2fc_fifo_empty", 3, 3),
			    D_FIELD("edtup_info_fifo_empty", 4, 4),
			    D_FIELD("edtup_data_fifo_empty", 5, 5),
			    D_FIELD("pfc0_gat_info_fifo_empty", 6, 6),
			    D_FIELD("pfc0_gat_fifo_empty", 7, 7),
			    D_FIELD("pfc1_gat_info_fifo_empty", 8, 8),
			    D_FIELD("pfc1_gat_fifo_empty", 9, 9),
			    D_FIELD("bmc_gat_info_fifo_empty", 10, 10),
			    D_FIELD("bmc_gat_fifo_empty", 11, 11),
			    D_FIELD("emac_bmc_info_fifo_empty", 12, 12),
			    D_FIELD("emac_bmc_fifo_empty", 13, 13),
			    D_FIELD("rd_port_rx_info_fifo_empty", 16, 16),
			    D_FIELD("rd_port_rx_fifo_empty", 17, 17),
			    D_FIELD("rd_ovsb_rx_info_fifo_empty", 18, 18),
			    D_FIELD("rd_ovsb_rx_fifo_empty", 19, 19),
			    D_FIELD("rd_fwd_info_fifo_empty", 20, 20),
			    D_FIELD("rd_fwd_data_fifo_empty", 21, 21),
			    D_FIELD("rd_fwd_key_fifo_empty", 22, 22),
			    D_FIELD("rd_ups_info_fifo_empty", 23, 23),
			    D_FIELD("rd_ups_data_fifo_empty", 24, 24),
			    D_FIELD("rd_ups_key_fifo_empty", 25, 25),
			    D_FIELD("rd_attr_info_fifo_empty", 26, 26),
			    D_FIELD("rd_attr_data_fifo_empty", 27, 27),
			    D_FIELD("rd_attr_key_fifo_empty", 28, 28),
			    D_FIELD("rd_arqa_cov_fifo_empty", 29, 29),
			    D_FIELD("rd_swcup0_info_fifo_empty", 30, 30),
			    D_FIELD("rd_swcup0_data_empty", 31, 31));
	return cnt;
}

static int sprint_n20_rx_debug2(struct mce_pf *pf, struct mce_hw *hw, char *buf,
				int buf_sz)
{
	int cnt = 0;

	if (buf_sz <= 0)
		return 0;

	cnt += SNPRINTF_REG_ARRAY("emac_rx_fifo_progfull_status", 0x86418,
				  rx_progfull_status_items);
	cnt += SNPRINTF_REG("emac_rx_fifo_progfull_status", 0x86418,
			    D_FIELD("port_rx_info_fifo_progfull", 0, 0),
			    D_FIELD("port_rx_fifo_progfull", 1, 1),
			    D_FIELD("ovsb_rx_info_fifo_progfull", 2, 2),
			    D_FIELD("ovsb_rx_fifo_progfull", 3, 3),
			    D_FIELD("fwd_info_fifo_progfull", 4, 4),
			    D_FIELD("fwd_data_fifo_progfull", 5, 5),
			    D_FIELD("fwd_key_fifo_progfull", 6, 6),
			    D_FIELD("ups_info_fifo_progfull", 7, 7),
			    D_FIELD("ups_data_fifo_progfull", 8, 8),
			    D_FIELD("ups_key_fifo_progfull", 9, 9),
			    D_FIELD("attr_info_fifo_progfull", 10, 10),
			    D_FIELD("attr_data_fifo_progfull", 11, 11),
			    D_FIELD("attr_key_fifo_progfull", 12, 12),
			    D_FIELD("rqa_cov_fifo_progfull", 13, 13),
			    D_FIELD("swcup0_info_fifo_progfull", 14, 14),
			    D_FIELD("swcup0_fifo_progfull", 15, 15),
			    D_FIELD("swcup1_info_fifo_progfull", 16, 16),
			    D_FIELD("swcup1_fifo_progfull", 17, 17),
			    D_FIELD("emac_sw2fc_info_fifo_progfull", 18, 18),
			    D_FIELD("emac_sw2fc_fifo_progfull", 19, 19),
			    D_FIELD("edtup_info_fifo_progfull", 20, 20),
			    D_FIELD("edtup_data_fifo_progfull", 21, 21),
			    D_FIELD("pfc0_gat_fifo_progfull", 22, 22),
			    D_FIELD("pfc1_gat_fifo_progfull", 23, 23),
			    D_FIELD("pfc0_gat_info_fifo_progfull", 24, 24),
			    D_FIELD("pfc1_gat_info_fifo_progfull", 25, 25),
			    D_FIELD("bmc_gat_info_fifo_progfull", 26, 26),
			    D_FIELD("bmc_gat_fifo_progfull", 27, 27),
			    D_FIELD("emac_bmc_info_fifo_progfull", 28, 28),
			    D_FIELD("emac_bmc_fifo_progfull", 29, 29));

	cnt += SNPRINTF_REG_ARRAY("emac_rx_fifo_full_status", 0x8641c,
				  rx_fifo_full_status_items);

	return cnt;
}

static int sprint_n20_rx_debug2_2(struct mce_pf *pf, struct mce_hw *hw,
				  char *buf, int buf_sz)
{
	int cnt = 0;

	cnt += SNPRINTF_REG("emac_rx_fifo_full_status", 0x8641c,
			    D_FIELD("wr_port_rx_info_fifo_full", 0, 0),
			    D_FIELD("wr_port_rx_fifo_full", 1, 1),
			    D_FIELD("wr_ovsb_info_fifo_full", 2, 2),
			    D_FIELD("wr_ovsb_fifo_full", 3, 3),
			    D_FIELD("wr_fwd_info_full", 4, 4),
			    D_FIELD("wr_fwd_data_full", 5, 5),
			    D_FIELD("wr_fwd_key_full", 6, 6),
			    D_FIELD("wr_ups_info_full", 7, 7),
			    D_FIELD("wr_ups_data_full", 8, 8),
			    D_FIELD("wr_ups_key_full", 9, 9),
			    D_FIELD("wr_attr_info_full", 10, 10),
			    D_FIELD("wr_attr_data_full", 11, 11),
			    D_FIELD("wr_attr_key_full", 12, 12),
			    D_FIELD("wr_rqa_cov_fifo_full", 13, 13),
			    D_FIELD("wr_swcup0_info_fifo_full", 14, 14),
			    D_FIELD("wr_swcup0_data_fifo_full", 15, 15),
			    D_FIELD("wr_swcup1_info_fifo_full", 16, 16),
			    D_FIELD("wr_swcup1_data_fifo_full", 17, 17),
			    D_FIELD("wr_emac_sw2fc_info_fifo_full", 18, 18),
			    D_FIELD("wr_emac_sw2fc_fifo_full", 19, 19),
			    D_FIELD("wr_edtup_info_fifo_full", 20, 20),
			    D_FIELD("wr_edtup_data_fifo_full", 21, 21),
			    D_FIELD("wr_pfc0_gat_fifo_full", 22, 22),
			    D_FIELD("wr_pfc1_gat_fifo_full", 23, 23),
			    D_FIELD("wr_pfc0_gat_info_fifo_full", 24, 24),
			    D_FIELD("wr_pfc1_gat_info_fifo_full", 25, 25),
			    D_FIELD("wr_bmc_gat_info_fifo_full", 26, 26),
			    D_FIELD("wr_bmc_gat_fifo_full", 27, 27),
			    D_FIELD("wr_emac_bmc_info_fifo_full", 28, 28),
			    D_FIELD("wr_emac_bmc_fifo_full", 29, 29));
	cnt += SNPRINTF("\n== eth_parse_module ==\n");
	cnt += SNPRINTF_REG("parser-SOP", 0x6000, D_32BIT);
	cnt += SNPRINTF_REG("parser-EOP", 0x6004, D_32BIT);
	cnt += SNPRINTF_REG("parser-len-err", 0x6008, D_32BIT);
	cnt += SNPRINTF_REG("parser-tunnel-exception", 0x600c, D_32BIT);
	cnt += SNPRINTF_REG("parser-vlan-cnt-exception", 0x6010, D_32BIT);
	cnt += SNPRINTF_REG("parser-sctp csum err", 0x6014, D_32BIT);
	cnt += SNPRINTF_REG("parser-TCPorUDP-csum err", 0x6018, D_32BIT);
	cnt += SNPRINTF_REG("parser-IPV4csum err", 0x601c, D_32BIT);
	cnt += SNPRINTF_REG("parser-pkt-len", 0x6020, D_32BIT);
	cnt += SNPRINTF_REG("parser IPV4 hdr-len-err", 0x6024, D_32BIT);
	cnt += SNPRINTF_REG("parser 802.3 pkts", 0x6028, D_32BIT);
	cnt += SNPRINTF_REG("parser PTP pkts", 0x602c, D_32BIT);
	cnt += SNPRINTF_REG("parser RDMA pkts", 0x6030, D_32BIT);
	return cnt;
}

static int sprint_n20_rx_debug3(struct mce_pf *pf, struct mce_hw *hw, char *buf,
				int buf_sz)
{
	int cnt = 0;

	if (buf_sz <= 0)
		return 0;

	cnt += SNPRINTF_REG("parser GTP-U pkts", 0x86034, D_32BIT);
	cnt += SNPRINTF_REG("parser GTP-C pkts", 0x86038, D_32BIT);
	cnt += SNPRINTF_REG("parser GENEVE pkts", 0x8603c, D_32BIT);
	cnt += SNPRINTF_REG("parser VXLAN pkts", 0x86040, D_32BIT);
	cnt += SNPRINTF_REG("parser GRE pkts", 0x86044, D_32BIT);
	cnt += SNPRINTF_REG("parser ESP pkts", 0x86048, D_32BIT);
	cnt += SNPRINTF_REG("parser SCTP pkts", 0x8604c, D_32BIT);
	cnt += SNPRINTF_REG("parser TCP SYN pkts", 0x86050, D_32BIT);
	cnt += SNPRINTF_REG("parser TCP pkts", 0x86054, D_32BIT);
	cnt += SNPRINTF_REG("parser UDP pkts", 0x86058, D_32BIT);
	cnt += SNPRINTF_REG("parser ICMPV6 pkts", 0x8605c, D_32BIT);
	cnt += SNPRINTF_REG("parser ICMPV4 pkts", 0x86060, D_32BIT);
	cnt += SNPRINTF_REG("parser segment pkts", 0x86064, D_32BIT);
	cnt += SNPRINTF_REG("parser ARP pkts", 0x86068, D_32BIT);
	cnt += SNPRINTF_REG("parser IPV6 with ext-hdr", 0x8606c, D_32BIT);
	cnt += SNPRINTF_REG("parser IPV6 pkts", 0x86070, D_32BIT);
	cnt += SNPRINTF_REG("parser IPV4 pkts", 0x86074, D_32BIT);
	cnt += SNPRINTF_REG("parser 3-level-VLAN pkts", 0x86078, D_32BIT);
	cnt += SNPRINTF_REG("parser 2-level-vlan pkts", 0x8607c, D_32BIT);
	cnt += SNPRINTF_REG("parser 1-level-vlan pkts", 0x86080, D_32BIT);
	cnt += SNPRINTF_REG("parser SCTP-in-tunnel", 0x86084, D_32BIT);
	cnt += SNPRINTF_REG("parser TCP SYN in-tunnel", 0x86088, D_32BIT);
	cnt += SNPRINTF_REG("parser TCP in-tunnel", 0x8608c, D_32BIT);
	cnt += SNPRINTF_REG("parser UDP in-tunnel", 0x86090, D_32BIT);
	cnt += SNPRINTF_REG("parser ICMPV6 in-tunnel", 0x86094, D_32BIT);
	cnt += SNPRINTF_REG("parser ICMPV4 in-tunnel", 0x86098, D_32BIT);
	cnt += SNPRINTF_REG("parser fragments in-tunnel", 0x8609c, D_32BIT);

	cnt += SNPRINTF_REG("parser ARP in-tunnel", 0x860a0, D_32BIT);
	cnt += SNPRINTF_REG("parser IPV6 ext-hdr in-tunnel", 0x860a4, D_32BIT);
	cnt += SNPRINTF_REG("parser IPV6 in-tunnel", 0x860a8, D_32BIT);
	cnt += SNPRINTF_REG("parser IPV4 in-tunnel", 0x860ac, D_32BIT);
	cnt += SNPRINTF_REG("parser 3-lvl-VLAN in-tunnel", 0x860b0, D_32BIT);
	cnt += SNPRINTF_REG("parser 2-lvl-VLAN in-tunnel", 0x860b4, D_32BIT);
	cnt += SNPRINTF_REG("parser 1-lvl-VLAN in-tunnel", 0x860b8, D_32BIT);
	cnt += SNPRINTF_REG("parser lookup Write SOP", 0x86100, D_32BIT);
	cnt += SNPRINTF_REG("parser loopup Write EOP", 0x86104, D_32BIT);
	cnt += SNPRINTF_REG("parser_engine_pre in SOP", 0x86110, D_32BIT);
	cnt += SNPRINTF_REG("parser_engine_pre in EOP", 0x86118, D_32BIT);
	cnt += SNPRINTF_REG("parser_engine_pre out SOP", 0x86114, D_32BIT);
	cnt += SNPRINTF_REG("parser_engine_pre out EOP", 0x8612c, D_32BIT);
	cnt += SNPRINTF("\n== eth_fc_gat ==\n");
	cnt += SNPRINTF_REG("pfc0_gat_pkt_in", 0x86250, D_32BIT);
	cnt += SNPRINTF_REG("pfc1_gat_pkt_in ", 0x86254, D_32BIT);
	cnt += SNPRINTF_REG("rx drop pkt", 0x86258, D_32BIT);
	cnt += SNPRINTF_REG("tx2rx drop pkt", 0x8625c, D_32BIT);

	cnt += SNPRINTF("\n== eth_flow_ctrl ==\n");
	cnt += SNPRINTF_REG("emac_flow_ctrl_infifo_o_dma", 0x86260, D_32BIT);
	cnt += SNPRINTF_REG("emac_flow_ctrl_ofif_o_dma", 0x86264, D_32BIT);
	cnt += SNPRINTF_REG("emac_flow_ctrl_drop", 0x86268, D_32BIT);

	return cnt;
}

static int sprint_n20_rx_debug4(struct mce_pf *pf, struct mce_hw *hw, char *buf,
				int buf_sz)
{
	int cnt = 0;

	if (buf_sz <= 0)
		return 0;

	cnt += SNPRINTF("\n== eth_fwd_attr ==\n");
	cnt += SNPRINTF_REG("attr_rx_ingress_pkt_in", 0x86230, D_32BIT);
	cnt += SNPRINTF_REG("attr_rx_egress_pkt_out", 0x86234, D_32BIT);
	cnt += SNPRINTF_REG("attr_rx_egress_pkt_drop", 0x86238, D_32BIT);
	cnt += SNPRINTF_REG("rx_ingress_bypass", 0x8623c, D_32BIT);
	cnt += SNPRINTF_REG("rx_verb_backup_flow_cnt", 0x86240, D_32BIT);
	cnt += SNPRINTF_REG("rx_verb_backup_pkts", 0x86244, D_32BIT);

	cnt += SNPRINTF("\n== eth_fwd_proc ==\n");
	cnt += SNPRINTF_REG("rx_ingress_pkt_in", 0x861a0, D_32BIT);
	cnt += SNPRINTF_REG("rx_ingress_drop(mac l2_filter_drop)", 0x861a4,
			    D_32BIT);
	cnt += SNPRINTF_REG("rx2bmc_pkt", 0x861a8, D_32BIT);
	cnt += SNPRINTF_REG("rx bmc_busy_drop", 0x861b8, D_32BIT);
	cnt += SNPRINTF_REG("rx2dma_pkt", 0x861ac, D_32BIT);
	cnt += SNPRINTF_REG("rx ups_dma_busy_drop", 0x861bc, D_32BIT);
	cnt += SNPRINTF_REG("rx2swich_pkt", 0x861b0, D_32BIT);
	cnt += SNPRINTF_REG("rx switch_busy_drop ", 0x861c0, D_32BIT);
	cnt += SNPRINTF_REG("rx2rdma_pkt", 0x861b4, D_32BIT);
	cnt += SNPRINTF_REG("rx rdma_busy_drop", 0x861c4, D_32BIT);
	cnt += SNPRINTF("\n== eth_rqa_top ==\n");
	cnt += SNPRINTF_REG("parser SCTP-in-tunnel", 0x86084, D_32BIT);
	cnt += SNPRINTF_REG("rqa redir-flag(Etype:0x1 tcp_syn:0x2 tuple5:0x4,fd:0x8,rss:0x10)",
		0x6170, D_32BIT);
	cnt += SNPRINTF_REG("RQA vport plicy_drop", 0x86174, D_32BIT);
	cnt += SNPRINTF_REG("RQA etype plicy_drop", 0x86178, D_32BIT);
	cnt += SNPRINTF_REG("RQA tcp_syn plicy_drop", 0x8617c, D_32BIT);
	cnt += SNPRINTF_REG("RQA tuple5 plicy_drop)", 0x86180, D_32BIT);
	cnt += SNPRINTF_REG("RQA fd  plicy_drop)", 0x86184, D_32BIT);
	cnt += SNPRINTF_REG("RQA rss plicy_drop)", 0x86188, D_32BIT);
	cnt += SNPRINTF_REG("RQA bypass sumary)", 0x8618c, D_32BIT);
	cnt += SNPRINTF_REG("RQA except-pkts)", 0x86190, D_32BIT);
	cnt += SNPRINTF_REG("RQA processing-pkts", 0x86194, D_32BIT);
	cnt += SNPRINTF_REG("RQA vf-filter group-drop", 0x86198, D_32BIT);
	cnt += SNPRINTF_REG("RQA vf-filter vlan drop", 0x8619c, D_32BIT);

	return cnt;
}

static int sprint_n20_rx_debug4_2(struct mce_pf *pf, struct mce_hw *hw,
				  char *buf, int buf_sz)
{
	int cnt = 0;

	cnt += SNPRINTF("\n== eth_mux ==\n");
	cnt += SNPRINTF_REG("port0_rx_pkt", 0x86200, D_32BIT);
	cnt += SNPRINTF_REG("port1_rx_pkt", 0x86204, D_32BIT);
	cnt += SNPRINTF_REG("total_mux_rx_pkt", 0x8620c, D_32BIT);

	cnt += SNPRINTF("\n== rx_mux_bus ==\n");
	cnt += SNPRINTF_REG("rx-mux-fsm", DEBUG_RXMUX_BUS,
			    FUNC_FIELD(0, "fsm_cs", 2, 0, "%d"),
			    FUNC_FIELD(0, "fsm_ns", 5, 3, "%d"));

	cnt += SNPRINTF_REG("rx_mux_lerr_pkt_num", DEBUG_RXMUX_BUS,
			    FUNC_D32(1));
	cnt += SNPRINTF_REG("rx_mux_drop_pkt_num", DEBUG_RXMUX_BUS,
			    FUNC_D32(2));
	cnt += SNPRINTF_REG("rx_mux_recv_sop_pkts", DEBUG_RXMUX_BUS,
			    FUNC_D32(3));
	cnt += SNPRINTF_REG("rx_mux_recv_eop_pkts", DEBUG_RXMUX_BUS,
			    FUNC_D32(4));
	cnt += SNPRINTF_REG("rx_mux_send_sop_pkts", DEBUG_RXMUX_BUS,
			    FUNC_D32(5));
	cnt += SNPRINTF_REG("rx_mux_send_eop_pkts", DEBUG_RXMUX_BUS,
			    FUNC_D32(6));
	cnt += SNPRINTF_REG("rx_mux_send_pkts_num0", DEBUG_RXMUX_BUS,
			    FUNC_D32(7));
	cnt += SNPRINTF_REG("rx_mux_send_pkts_num1", DEBUG_RXMUX_BUS,
			    FUNC_D32(8));
	cnt += SNPRINTF_REG("rx_mux_send_pkts_num2", DEBUG_RXMUX_BUS,
			    FUNC_D32(9));
	cnt += SNPRINTF_REG("rx_mux_send_pkts_num3", DEBUG_RXMUX_BUS,
			    FUNC_D32(10));
	cnt += SNPRINTF_REG("rx_mux_send_pkts_num4", DEBUG_RXMUX_BUS,
			    FUNC_D32(11));
	cnt += SNPRINTF_REG("rx_mux_send_pkts_num5", DEBUG_RXMUX_BUS,
			    FUNC_D32(12));
	cnt += SNPRINTF_REG("rx_mux_send_pkts_num6", DEBUG_RXMUX_BUS,
			    FUNC_D32(13));
	cnt += SNPRINTF_REG("rx_mux_send_pkts_num7", DEBUG_RXMUX_BUS,
			    FUNC_D32(14));
	cnt += SNPRINTF_REG("channel_count_r[0]", DEBUG_RXMUX_BUS,
			    FUNC_D32(15));
	cnt += SNPRINTF_REG("channel_count_r[1]", DEBUG_RXMUX_BUS,
			    FUNC_D32(16));
	cnt += SNPRINTF_REG("channel_count_r[2]", DEBUG_RXMUX_BUS,
			    FUNC_D32(17));
	cnt += SNPRINTF_REG("channel_count_r[3]", DEBUG_RXMUX_BUS,
			    FUNC_D32(18));
	cnt += SNPRINTF_REG("channel_count_r[4]", DEBUG_RXMUX_BUS,
			    FUNC_D32(19));
	cnt += SNPRINTF_REG("channel_count_r[5]", DEBUG_RXMUX_BUS,
			    FUNC_D32(20));
	cnt += SNPRINTF_REG("channel_count_r[6]", DEBUG_RXMUX_BUS,
			    FUNC_D32(21));
	cnt += SNPRINTF_REG("channel_count_r[7]", DEBUG_RXMUX_BUS,
			    FUNC_D32(22));

	cnt += SNPRINTF("\n== eth_editor_up ==\n");
	cnt += SNPRINTF_REG("rx_edtup_pkt_in", 0x861d0, D_32BIT);
	cnt += SNPRINTF_REG("rx_edtup_pkt_out", 0x861d4, D_32BIT);
	cnt += SNPRINTF_REG("rx_edtup_pkt_drop", 0x861d8, D_32BIT);
	cnt += SNPRINTF_REG("rx_edtup_rm_all_vlan", 0x861dc, D_32BIT);
	cnt += SNPRINTF_REG("rx_edtup_rm_ex1_vlan", 0x861e0, D_32BIT);
	cnt += SNPRINTF_REG("rx_edtup_rm_ex2_vlan", 0x861e4, D_32BIT);
	cnt += SNPRINTF_REG("rx_edtup_rm_ex3_vlan", 0x861e8, D_32BIT);
	cnt += SNPRINTF_REG("rx_swcup_pkt_out", 0x861ec, D_32BIT);

	return cnt;
}

static int sprint_n20_rx_debug5(struct mce_pf *pf, struct mce_hw *hw, char *buf,
				int buf_sz)
{
	int cnt = 0;

	if (buf_sz <= 0)
		return 0;

	cnt += SNPRINTF("\n== rx_switch_bus ==\n");
	cnt += SNPRINTF_REG("nic0_pkt_in", DBG_RX_SWITCH_BUS, FUNC_D32(0));
	cnt += SNPRINTF_REG("nic0_pkt_out", DBG_RX_SWITCH_BUS, FUNC_D32(9));
	cnt += SNPRINTF_REG("nic0_pkt_in_sop", DBG_RX_SWITCH_BUS, FUNC_D32(27));
	cnt += SNPRINTF_REG("nic0_pkt_in_eop", DBG_RX_SWITCH_BUS, FUNC_D32(36));
	cnt += SNPRINTF_REG("nic0_pkt_drop", DBG_RX_SWITCH_BUS, FUNC_D32(18));
	cnt += SNPRINTF_REG("nic0_l2drop", DBG_RX_SWITCH_BUS, FUNC_D32(45));
	cnt += SNPRINTF_REG("nic1_pkt_in", DBG_RX_SWITCH_BUS, FUNC_D32(1));
	cnt += SNPRINTF_REG("nic1_pkt_out", DBG_RX_SWITCH_BUS, FUNC_D32(10));
	cnt += SNPRINTF_REG("nic1_pkt_drop", DBG_RX_SWITCH_BUS, FUNC_D32(19));
	cnt += SNPRINTF_REG("nic1_pkt_in_sop", DBG_RX_SWITCH_BUS, FUNC_D32(28));
	cnt += SNPRINTF_REG("nic1_pkt_in_eop", DBG_RX_SWITCH_BUS, FUNC_D32(37));
	cnt += SNPRINTF_REG("nic1_l2drop", DBG_RX_SWITCH_BUS, FUNC_D32(46));
	cnt += SNPRINTF_REG("nic2_pkt_in", DBG_RX_SWITCH_BUS, FUNC_D32(2));
	cnt += SNPRINTF_REG("nic2_pkt_out", DBG_RX_SWITCH_BUS, FUNC_D32(11));
	cnt += SNPRINTF_REG("nic2_pkt_drop", DBG_RX_SWITCH_BUS, FUNC_D32(20));
	cnt += SNPRINTF_REG("nic2_pkt_in_sop", DBG_RX_SWITCH_BUS, FUNC_D32(29));
	cnt += SNPRINTF_REG("nic2_pkt_in_eop", DBG_RX_SWITCH_BUS, FUNC_D32(38));
	cnt += SNPRINTF_REG("nic3_pkt_in", DBG_RX_SWITCH_BUS, FUNC_D32(3));
	cnt += SNPRINTF_REG("nic3_pkt_out", DBG_RX_SWITCH_BUS, FUNC_D32(12));
	cnt += SNPRINTF_REG("nic3_pkt_drop", DBG_RX_SWITCH_BUS, FUNC_D32(21));
	cnt += SNPRINTF_REG("nic3_pkt_in_sop", DBG_RX_SWITCH_BUS, FUNC_D32(30));
	cnt += SNPRINTF_REG("nic3_pkt_in_eop", DBG_RX_SWITCH_BUS, FUNC_D32(39));
	cnt += SNPRINTF_REG("npu0_pkt_in", DBG_RX_SWITCH_BUS, FUNC_D32(4));
	cnt += SNPRINTF_REG("npu0_pkt_out", DBG_RX_SWITCH_BUS, FUNC_D32(13));
	cnt += SNPRINTF_REG("npu0_pkt_drop", DBG_RX_SWITCH_BUS, FUNC_D32(22));
	cnt += SNPRINTF_REG("npu0_pkt_in_sop", DBG_RX_SWITCH_BUS, FUNC_D32(31));
	cnt += SNPRINTF_REG("npu0_pkt_in_eop", DBG_RX_SWITCH_BUS, FUNC_D32(40));
	cnt += SNPRINTF_REG("npu1_pkt_in", DBG_RX_SWITCH_BUS, FUNC_D32(5));
	cnt += SNPRINTF_REG("npu1_pkt_out", DBG_RX_SWITCH_BUS, FUNC_D32(14));
	cnt += SNPRINTF_REG("npu1_pkt_drop", DBG_RX_SWITCH_BUS, FUNC_D32(23));
	cnt += SNPRINTF_REG("npu1_pkt_in_sop", DBG_RX_SWITCH_BUS, FUNC_D32(32));
	cnt += SNPRINTF_REG("npu1_pkt_in_eop", DBG_RX_SWITCH_BUS, FUNC_D32(41));
	cnt += SNPRINTF_REG("npu2_pkt_in", DBG_RX_SWITCH_BUS, FUNC_D32(6));
	cnt += SNPRINTF_REG("npu2_pkt_out", DBG_RX_SWITCH_BUS, FUNC_D32(15));
	cnt += SNPRINTF_REG("npu2_pkt_drop", DBG_RX_SWITCH_BUS, FUNC_D32(24));
	cnt += SNPRINTF_REG("npu2_pkt_in_sop", DBG_RX_SWITCH_BUS, FUNC_D32(33));
	cnt += SNPRINTF_REG("npu2_pkt_in_eop", DBG_RX_SWITCH_BUS, FUNC_D32(42));
	cnt += SNPRINTF_REG("npu3_pkt_in", DBG_RX_SWITCH_BUS, FUNC_D32(7));
	cnt += SNPRINTF_REG("npu3_pkt_out", DBG_RX_SWITCH_BUS, FUNC_D32(16));
	cnt += SNPRINTF_REG("npu3_pkt_drop", DBG_RX_SWITCH_BUS, FUNC_D32(25));
	cnt += SNPRINTF_REG("npu3_pkt_in_sop", DBG_RX_SWITCH_BUS, FUNC_D32(34));
	cnt += SNPRINTF_REG("npu3_pkt_in_eop", DBG_RX_SWITCH_BUS, FUNC_D32(43));
	cnt += SNPRINTF_REG("aux_pkt_in", DBG_RX_SWITCH_BUS, FUNC_D32(8));
	cnt += SNPRINTF_REG("aux_pkt_out", DBG_RX_SWITCH_BUS, FUNC_D32(17));
	cnt += SNPRINTF_REG("aux_pkt_drop", DBG_RX_SWITCH_BUS, FUNC_D32(26));
	cnt += SNPRINTF_REG("aut_pkt_in_sop", DBG_RX_SWITCH_BUS, FUNC_D32(35));
	cnt += SNPRINTF_REG("aut_pkt_in_eop", DBG_RX_SWITCH_BUS, FUNC_D32(44));

	return cnt;
}

static int sprint_n20_rx_mac(struct mce_pf *pf, struct mce_hw *hw, char *buf,
			     int buf_sz)
{
	int cnt = 0;

	if (buf_sz <= 0)
		return 0;

	cnt += SNPRINTF("\n----mac-rx---\n");
	cnt += SNPRINTF_REG("mac-cfg", 0x64000, Hex_32BIT, D_FIELD("rx-en", 27, 27),
		D_FIELD("tx-en", 26, 26), D_FIELD("pause-disable", 20, 20),
		D_FIELD("pfc-rx-en", 12, 12), D_FIELD("pfc-tx-en", 11, 11),
		D_FIELD("pause-stop-en", 10, 10), D_FIELD("pause-en", 9, 9),
		D_FIELD("jumbo-en", 6, 6), D_FIELD("truncate-en", 5, 5),
		D_FIELD("mac-loopback", 3, 3));

	cnt += SNPRINTF_REG("RxOct", 0x64000 + 0x180, D_32BIT);
	cnt += SNPRINTF_REG("RxErrs", 0x64000 + 0x184, D_32BIT);
	cnt += SNPRINTF_REG("oversize", 0x64000 + 0x1c0, D_32BIT);
	cnt += SNPRINTF_REG("aFrameCheckSeqErrs", 0x64000 + 0x1a0, D_32BIT);
	cnt += SNPRINTF_REG("aAlignErr", 0x64000 + 0x88, D_32BIT);
	cnt += SNPRINTF_REG("aTooLongErr", 0x64000 + 0x98, D_32BIT);
	cnt += SNPRINTF_REG("aInRangLenErr", 0x64000 + 0x9c, D_32BIT);
	cnt += SNPRINTF_REG("smallDrop", 0x64000 + 0x1fc, D_32BIT);
	cnt += SNPRINTF_REG("jumbers", 0x64000 + 0x1c4, D_32BIT);
	cnt += SNPRINTF_REG("fragments", 0x64000 + 0x1c8, D_32BIT);
	cnt += SNPRINTF_REG("pause rx", 0x64000 + 0x94, D_32BIT);
	cnt += SNPRINTF_REG("vlan ok", 0x64000 + 0xA4, D_32BIT);
	cnt += SNPRINTF_REG("PFC0", 0x64000 + 0xe0 + 4 * 0, D_32BIT);
	cnt += SNPRINTF_REG("PFC1", 0x64000 + 0xe0 + 4 * 1, D_32BIT);
	cnt += SNPRINTF_REG("PFC2", 0x64000 + 0xe0 + 4 * 2, D_32BIT);
	cnt += SNPRINTF_REG("PFC3", 0x64000 + 0xe0 + 4 * 3, D_32BIT);
	cnt += SNPRINTF_REG("PFC4", 0x64000 + 0xe0 + 4 * 4, D_32BIT);
	cnt += SNPRINTF_REG("PFC5", 0x64000 + 0xe0 + 4 * 5, D_32BIT);
	cnt += SNPRINTF_REG("PFC6", 0x64000 + 0xe0 + 4 * 6, D_32BIT);
	cnt += SNPRINTF_REG("RxOk_hi", 0x64000 + 0xAC, D_32BIT);
	cnt += SNPRINTF_REG("RxOk_lo", 0x64000 + 0x84, D_32BIT);
	cnt += SNPRINTF_REG("rxtrans_sop", DEBUG_RXTRANS_BUS, FUNC_D32(18));
	cnt += SNPRINTF_REG("rxtrans_eop", DEBUG_RXTRANS_BUS, FUNC_D32(19));
	cnt += SNPRINTF_REG("rx_ingress_pkt_in", 0x61a0, D_32BIT);
	cnt += SNPRINTF_REG("rx_ingress_drop", 0x61a4, D_32BIT);
	cnt += SNPRINTF_REG("rx2dma_pkt", 0x61ac, D_32BIT);
	cnt += SNPRINTF_REG("rx_mux_recv_sop_pkts", DEBUG_RXMUX_BUS,
			    FUNC_D32(3));
	cnt += SNPRINTF_REG("rx_mux_recv_eop_pkts", DEBUG_RXMUX_BUS,
			    FUNC_D32(4));
	cnt += SNPRINTF("\n");
	cnt += SNPRINTF("\n==eth tx==\n");
	if (hw->nr_pf == 0) {
		cnt += SNPRINTF_REG("port0 tx sop", 0x86460, FUNC_D32(13));
		cnt += SNPRINTF_REG("port0 tx eop", 0x86464, FUNC_D32(13));
	} else {
		cnt += SNPRINTF_REG("port1 tx sop", 0x86468, FUNC_D32(13));
		cnt += SNPRINTF_REG("port1 tx eop", 0x8646c, FUNC_D32(13));
	}
	cnt += SNPRINTF_REG("TxOk_hi", 0x64000 + 0xA8, D_32BIT);
	cnt += SNPRINTF_REG("TxOk_lo", 0x64000 + 0x80, D_32BIT);

	return cnt;
}

static int sprint_n20_rx_debug(struct mce_pf *pf, struct mce_hw *hw, char *buf,
			       int buf_sz)
{
	int cnt = 0;

	if (buf_sz <= 0)
		return 0;

	cnt += SNPRINTF("\n== rx_trans_bus ==\n");
	cnt += SNPRINTF_REG("rxtrans_pkt_drop_num", DEBUG_RXTRANS_BUS,
			    FUNC_D32(0));
	cnt += SNPRINTF_REG("rxtrans_pkt_in", DEBUG_RXTRANS_BUS, FUNC_D32(1));
	cnt += SNPRINTF_REG("rxtrans_pkt_out", DEBUG_RXTRANS_BUS, FUNC_D32(2));
	cnt += SNPRINTF_REG(" rxtrans_other_err", DEBUG_RXTRANS_BUS,
			    FUNC_D32(3));
	cnt += SNPRINTF_REG(" rx_trans_pkt_crc_err", DEBUG_RXTRANS_BUS,
			    FUNC_D32(4));
	cnt += SNPRINTF_REG(" rx_trans_pkt_nosym_err", DEBUG_RXTRANS_BUS,
			    FUNC_D32(5));
	cnt += SNPRINTF_REG(" rx_trans_pkt_undersize_err", DEBUG_RXTRANS_BUS,
			    FUNC_D32(6));
	cnt += SNPRINTF_REG(" rx_trans_pkt_oversize_err", DEBUG_RXTRANS_BUS,
			    FUNC_D32(7));
	cnt += SNPRINTF_REG(" rx_trans_pkt_len_err", DEBUG_RXTRANS_BUS,
			    FUNC_D32(8));
	cnt += SNPRINTF_REG(" rx_trans_pkt_wpi_err", DEBUG_RXTRANS_BUS,
			    FUNC_D32(9));
	cnt += SNPRINTF_REG(" rx_trans_pkt_magic_err", DEBUG_RXTRANS_BUS,
			    FUNC_D32(10));
	cnt += SNPRINTF_REG(" rx_trans_pkt_unmatch_da_err", DEBUG_RXTRANS_BUS,
			    FUNC_D32(11));
	cnt += SNPRINTF_REG(" rx_trans_pkt_slen_err", DEBUG_RXTRANS_BUS,
			    FUNC_D32(12));
	cnt += SNPRINTF_REG(" rx_trans_pkt_glen_err", DEBUG_RXTRANS_BUS,
			    FUNC_D32(13));
	cnt += SNPRINTF_REG("rx_trans_pkt_frag", DEBUG_RXTRANS_BUS,
			    FUNC_D32(14));
	cnt += SNPRINTF_REG(" rx_trans_pkt_len_except", DEBUG_RXTRANS_BUS,
			    FUNC_D32(15));
	cnt += SNPRINTF_REG("rxtrans_pkt_sop", DEBUG_RXTRANS_BUS, FUNC_D32(16));
	cnt += SNPRINTF_REG("rxtrans_pkt_eop", DEBUG_RXTRANS_BUS, FUNC_D32(17));
	cnt += SNPRINTF_REG("rxtrans_sop", DEBUG_RXTRANS_BUS, FUNC_D32(18));
	cnt += SNPRINTF_REG("rxtrans_eop", DEBUG_RXTRANS_BUS, FUNC_D32(19));
	cnt += SNPRINTF_REG("rxtrans_wpi_status", DEBUG_RXTRANS_BUS,
			    FUNC_FIELD(20, "", 31, 0, "0x%x"),
			    FUNC_FIELD(20, "wpi_flag", 1, 1, "%d"),
			    FUNC_FIELD(20, "magic_flag", 0, 0, "%d"));
	cnt += SNPRINTF_REG(" rx_trans_pri0_pkt_drop", DEBUG_RXTRANS_BUS,
			    FUNC_D32(24));
	cnt += SNPRINTF_REG(" rx_trans_pri1_pkt_drop", DEBUG_RXTRANS_BUS,
			    FUNC_D32(25));
	cnt += SNPRINTF_REG(" rx_trans_pri2_pkt_drop", DEBUG_RXTRANS_BUS,
			    FUNC_D32(26));
	cnt += SNPRINTF_REG(" rx_trans_pri3_pkt_drop", DEBUG_RXTRANS_BUS,
			    FUNC_D32(27));
	cnt += SNPRINTF_REG(" rx_trans_pri4_pkt_drop", DEBUG_RXTRANS_BUS,
			    FUNC_D32(28));
	cnt += SNPRINTF_REG(" rx_trans_pri5_pkt_drop", DEBUG_RXTRANS_BUS,
			    FUNC_D32(29));
	cnt += SNPRINTF_REG(" rx_trans_pri6_pkt_drop", DEBUG_RXTRANS_BUS,
			    FUNC_D32(30));
	cnt += SNPRINTF_REG(" rx_trans_pri7_pkt_drop", DEBUG_RXTRANS_BUS,
			    FUNC_D32(31));

	cnt += sprint_n20_rx_debug1_0(pf, hw, buf + cnt, buf_sz - cnt);
	cnt += sprint_n20_rx_debug1_1(pf, hw, buf + cnt, buf_sz - cnt);
	cnt += sprint_n20_rx_debug2(pf, hw, buf + cnt, buf_sz - cnt);
	cnt += sprint_n20_rx_debug2_2(pf, hw, buf + cnt, buf_sz - cnt);
	cnt += sprint_n20_rx_debug3(pf, hw, buf + cnt, buf_sz - cnt);
	cnt += sprint_n20_rx_debug4(pf, hw, buf + cnt, buf_sz - cnt);
	cnt += sprint_n20_rx_debug4_2(pf, hw, buf + cnt, buf_sz - cnt);
	cnt += sprint_n20_rx_debug5(pf, hw, buf + cnt, buf_sz - cnt);
	return cnt;
}

int debugfs_rx_states_show(struct mce_pf *pf, struct mce_hw *hw, char *buf,
			   int buf_sz)
{
	int cnt = 0;

	if (!buf || buf_sz == 0)
		return 0;

	cnt += sprint_n20_rx_mac(pf, hw, buf + cnt, buf_sz - cnt);
	cnt += sprint_n20_rx_debug(pf, hw, buf + cnt, buf_sz - cnt);
	cnt += sprint_n20_rx_dma_status_counters(pf, hw, buf + cnt,
						 buf_sz - cnt);
	cnt += debugfs_rx_queue_show(pf, hw, buf + cnt, buf_sz - cnt);

	cnt += sprint_n20_rx_mac(pf, hw, buf + cnt, buf_sz - cnt);

	return cnt;
}

/* clang-format on */
static struct item dma_ctrl_tx_p0_items[] = {
	{ 4, 0, -1, "%u", "reg_state" },
	{ 7, 5, -1, "%u", "txpkt_state" },
	{ 10, 8, -1, "%u", "resp_state" },
	{ 11, 11, -1, "%u", "desc_req" },
	{ 12, 12, -1, "%u", "p0_desc_fifo_empty" },
	{ 13, 13, -1, "%u", "p1_desc_fifo_empty" },
	{ 14, 14, -1, "%u", "p2_desc_fifo_empty" },
	{ 16, 16, -1, "%u", "p0_desc_fifo_prog_full" },
	{ 17, 17, -1, "%u", "p1_desc_fifo_prog_full" },
	{ 18, 18, -1, "%u", "p2_desc_fifo_prog_full" },
	{ 20, 20, -1, "%u", "wait_desc_empty[0]" },
	{ 21, 21, -1, "%u", "wait_desc_empty[1]" },
	{ 22, 22, -1, "%u", "wait_desc_empty[2]" },
	{ 23, 23, -1, "%u", "wait_desc_empty[3]" },
	{ 24, 24, -1, "%u", "wait_desc_full[0]" },
	{ 25, 25, -1, "%u", "wait_desc_full[1]" },
	{ 26, 26, -1, "%u", "wait_desc_full[2]" },
	{ 27, 27, -1, "%u", "wait_desc_full[3]" },
	{ 28, 28, -1, "%u", "req_fifo_empty" },
	{ 29, 29, -1, "%u", "req_fifo_full" },
	{ 30, 30, -1, "%u", "p2_desc_fifo_full_occur" },
	{ 31, 31, -1, "%u", "p2_desc_fifo_empty_occur" },
	{ 0, -0, 1, "%u", NULL }
};

static struct item dma_ctrl_tx_p1_items[] = {
	{ 0, 0, -1, "%u", "resp_fifo_empty" },
	{ 1, 1, -1, "%u", "resp_fifo_full" },
	{ 2, 2, -1, "%u", "pcie_rd_already" },
	{ 3, 3, -1, "%u", "pcie_wr_already" },
	{ 4, 4, -1, "%u", "p0_desc_fifo_full_occur" },
	{ 5, 5, -1, "%u", "p1_desc_fifo_full_occur" },
	{ 6, 6, -1, "%u", "p0_desc_fifo_empty_occur" },
	{ 7, 7, -1, "%u", "p1_desc_fifo_empty_occur" },
	{ 8, 8, -1, "%u", "p0_txpkt_req" },
	{ 9, 9, -1, "%u", "p0_txpkt_req_zero" },
	{ 10, 10, -1, "%u", "(p0_new_txpkt_need <= dma_ql_wr_unuse_0)" },
	{ 11, 11, -1, "%u", "p1_txpkt_req" },
	{ 12, 12, -1, "%u", "ast_pkt_req_finished[0]" },
	{ 13, 13, -1, "%u", "ast_pkt_req_finished[1]" },
	{ 14, 14, -1, "%u", "ast_pkt_req_finished[2]" },
	{ 15, 15, -1, "%u", "ast_pkt_req_finished[3]" },
	{ 16, 16, -1, "%u", "p0_pcie_rd_wait" },
	{ 17, 17, -1, "%u", "p1_pcie_rd_wait" },
	{ 18, 18, -1, "%u", "pcie_rd_desc_aready" },
	{ 19, 19, -1, "%u", "p2 new txpkt need <=dma ql wr unuse 1)" },
	{ 20, 20, -1, "%u", "txpkt_pend_full_occur" },
	{ 21, 21, -1, "%u", "wait_desc_fifo_err_occur" },
	{ 22, 22, -1, "%u", "resp_fifo_full_occur" },
	{ 23, 23, -1, "%u", "resp_desc_rd_flip" },
	{ 31, 24, -1, "%u", "resp_desc_rd_id" },
	{ 0, 0, -1, "%u", NULL }
};

static struct item dma_queue_tx_p0_items[] = {
	{ 0, 0, -1, "%u", "desc_req[0]" },
	{ 1, 1, -1, "%u", "desc_req[1]" },
	{ 2, 2, -1, "%u", "desc_req[2]" },
	{ 3, 3, -1, "%u", "desc_req[3]" },
	{ 4, 4, -1, "%u", "gnt_occur_0" },
	{ 5, 5, -1, "%u", "gnt_occur_1" },
	{ 6, 6, -1, "%u", "gnt_occur_2" },
	{ 7, 7, -1, "%u", "gnt_occur_3" },
	{ 8, 8, -1, "%u", "gnt_reqing_0" },
	{ 9, 9, -1, "%u", "gnt_reqing_1" },
	{ 10, 10, -1, "%u", "gnt_reqing_2" },
	{ 11, 11, -1, "%u", "gnt_reqing_3" },
	{ 12, 12, -1, "%u", "gnt_occur" },
	{ 13, 13, -1, "%u", "gnt_reqing" },
	{ 14, 14, -1, "%u", "|desc_rq" },
	{ 31, 16, -1, "%u", "dma_fetch_cnt" },
	{ 0, 0, -1, NULL, NULL }
};

static struct item dma_queue_tx_p1_items[] = {
	{ 0, 0, -1, "%u",
	  "(desc_req_len[0] + queue_desc_fetch_cnt[0]) <= dma_desc_fifo_unuse[0])" },
	{ 1, 1, -1, "%u", "#1" },
	{ 2, 2, -1, "%u", "#2" },
	{ 3, 3, -1, "%u", "#3" },
	{ 4, 4, -1, "%u", "#4" },
	{ 5, 5, -1, "%u", "#5" },
	{ 6, 6, -1, "%u", "#6" },
	{ 7, 7, -1, "%u", "#7" },
	{ 8, 8, -1, "%u",
	  "(queue_desc_fetch_cnt[0] < dma_desc_fetch_trig[0])" },
	{ 9, 9, -1, "%u", "#1" },
	{ 10, 10, -1, "%u", "#2" },
	{ 11, 11, -1, "%u", "#3" },
	{ 12, 12, -1, "%u", "#4" },
	{ 13, 13, -1, "%u", "#5" },
	{ 14, 14, -1, "%u", "#6" },
	{ 15, 15, -1, "%u", "#7" },
	{ 16, 16, -1, "%u",
	  "(dma_desc_next_fetch_ptr[0] == dma_desc_buf_tail_ptr[0])" },
	{ 17, 17, -1, "%u", "#1" },
	{ 18, 18, -1, "%u", "#2" },
	{ 19, 19, -1, "%u", "#3" },
	{ 20, 20, -1, "%u", "#4" },
	{ 21, 21, -1, "%u", "#5" },
	{ 22, 22, -1, "%u", "#6" },
	{ 23, 23, -1, "%u", "#7" },
	{ 24, 24, -1, "%u", "(queue_desc_fetch_cnt[0] == 0)" },
	{ 25, 25, -1, "%u", "#1" },
	{ 26, 26, -1, "%u", "#2" },
	{ 27, 27, -1, "%u", "#3" },
	{ 28, 28, -1, "%u", "#4" },
	{ 29, 29, -1, "%u", "#5" },
	{ 30, 30, -1, "%u", "#6" },
	{ 31, 31, -1, "%u", "#7" },
	{ 0, 0, -1, NULL, NULL }
};

static int sprint_n20_tx_dma_status_counters_1(struct mce_pf *pf,
					       struct mce_hw *hw, char *buf,
					       int buf_sz)
{
	int cnt = 0;

	if (buf_sz <= 0)
		return 0;

	cnt += SNPRINTF_REG_ARRAY("dma_queue_tx_p0", 0x40140,
				  dma_queue_tx_p0_items);
	cnt += SNPRINTF_REG("dma_queue_tx_p0", 0x40140, D_FIELD("desc_req[0]", 0, 0),
		D_FIELD("desc_req[1]", 1, 1), D_FIELD("desc_req[2]", 2, 2),
		D_FIELD("desc_req[3]", 3, 3), D_FIELD("gnt_occur_0", 4, 4),
		D_FIELD("gnt_occur_1", 5, 5), D_FIELD("gnt_occur_2", 6, 6),
		D_FIELD("gnt_occur_3", 7, 7), D_FIELD("gnt_reqing_0", 8, 8),
		D_FIELD("gnt_reqing_1", 9, 9), D_FIELD("gnt_reqing_2", 10, 10),
		D_FIELD("gnt_reqing_3", 11, 11), D_FIELD("gnt_occur", 12, 12),
		D_FIELD("gnt_reqing", 13, 13), D_FIELD("|desc_rq", 14, 14),
		D_FIELD("dma_fetch_cnt", 31, 16));

	cnt += SNPRINTF_REG_ARRAY("dma_queue_tx_p1", 0x40144,
				  dma_queue_tx_p1_items);
	cnt += SNPRINTF_REG("dma_queue_tx_p1", 0x40144,
		D_FIELD("(desc_req_len[0] + queue_desc_fetch_cnt[0]) <= dma_desc_fifo_unuse[0])",
			0, 0),
		D_FIELD("#1", 1, 1), D_FIELD("#2", 2, 2), D_FIELD("#3", 3, 3),
		D_FIELD("#4", 4, 4), D_FIELD("#5", 5, 5), D_FIELD("#6", 6, 6),
		D_FIELD("#7", 7, 7),
		D_FIELD("(queue_desc_fetch_cnt[0] < dma_desc_fetch_trig[0])", 8,
			8),
		D_FIELD("#1", 9, 9), D_FIELD("#2", 10, 10),
		D_FIELD("#3", 11, 11), D_FIELD("#4", 12, 12),
		D_FIELD("#5", 13, 13), D_FIELD("#6", 14, 14),
		D_FIELD("#7", 15, 15),
		D_FIELD("(dma_desc_next_fetch_ptr[0] == dma_desc_buf_tail_ptr[0])",
			16, 16),
		D_FIELD("#1", 17, 17), D_FIELD("#2", 18, 18),
		D_FIELD("#3", 19, 19), D_FIELD("#4", 20, 20),
		D_FIELD("#5", 21, 21), D_FIELD("#6", 22, 22),
		D_FIELD("#7", 23, 23),
		D_FIELD("(queue_desc_fetch_cnt[0] == 0)", 24, 24),
		D_FIELD("#1", 25, 25), D_FIELD("#2", 26, 26),
		D_FIELD("#3", 27, 27), D_FIELD("#4", 28, 28),
		D_FIELD("#5", 29, 29), D_FIELD("#6", 30, 30),
		D_FIELD("#7", 31, 31));

	return cnt;
}

static int sprint_n20_tx_dma_status_counters(struct mce_pf *pf,
					     struct mce_hw *hw, char *buf,
					     int buf_sz)
{
	int cnt = 0;

	if (buf_sz <= 0)
		return 0;

	cnt += SNPRINTF("\n== tx-dma-status==\n");

	cnt += SNPRINTF_REG_ARRAY("dma_ctrl_tx_p0", 0x40148,
				  dma_ctrl_tx_p0_items);
	cnt += SNPRINTF_REG("dma_ctrl_tx_p0", 0x40148,
			    D_FIELD("reg_state", 4, 0),
			    D_FIELD("txpkt_state", 7, 5),
			    D_FIELD("resp_state", 10, 8),
			    D_FIELD("desc_req", 11, 11),
			    D_FIELD("p0_desc_fifo_empty", 12, 12),
			    D_FIELD("p1_desc_fifo_empty", 13, 13),
			    D_FIELD("p2_desc_fifo_empty", 14, 14),
			    D_FIELD("p0_desc_fifo_prog_full", 16, 16),
			    D_FIELD("p1_desc_fifo_prog_full", 17, 17),
			    D_FIELD("p2_desc_fifo_prog_full", 18, 18),
			    D_FIELD("wait_desc_empty[0]", 20, 20),
			    D_FIELD("wait_desc_empty[1]", 21, 21),
			    D_FIELD("wait_desc_empty[2]", 22, 22),
			    D_FIELD("wait_desc_empty[3]", 23, 23),
			    D_FIELD("wait_desc_full[0]", 24, 24),
			    D_FIELD("wait_desc_full[1]", 25, 25),
			    D_FIELD("wait_desc_full[2]", 26, 26),
			    D_FIELD("wait_desc_full[3]", 27, 27),
			    D_FIELD("req_fifo_empty", 28, 28),
			    D_FIELD("req_fifo_full", 29, 29),
			    D_FIELD("p2_desc_fifo_full_occur", 30, 30),
			    D_FIELD("p2_desc_fifo_empty_occur", 31, 31));

	cnt += SNPRINTF_REG_ARRAY("dma_ctrl_tx_p1 ", 0x4014c,
				  dma_ctrl_tx_p1_items);
	cnt += SNPRINTF_REG("dma_ctrl_tx_p1 ", 0x4014c, D_FIELD("resp_fifo_empty", 0, 0),
		D_FIELD("resp_fifo_full", 1, 1),
		D_FIELD("pcie_rd_already", 2, 2),
		D_FIELD("pcie_wr_already", 3, 3),
		D_FIELD("p0_desc_fifo_full_occur", 4, 4),
		D_FIELD("p1_desc_fifo_full_occur", 5, 5),
		D_FIELD("p0_desc_fifo_empty_occur", 6, 6),
		D_FIELD("p1_desc_fifo_empty_occur", 7, 7),
		D_FIELD("p0_txpkt_req", 8, 8),
		D_FIELD("p0_txpkt_req_zero", 9, 9),
		D_FIELD("(p0_new_txpkt_need <= dma_ql_wr_unuse_0)", 10, 10),
		D_FIELD("p1_txpkt_req", 11, 11),
		D_FIELD("ast_pkt_req_finished[0]", 12, 12),
		D_FIELD("ast_pkt_req_finished[1]", 13, 13),
		D_FIELD("ast_pkt_req_finished[2]", 14, 14),
		D_FIELD("ast_pkt_req_finished[3]", 15, 15),
		D_FIELD("p0_pcie_rd_wait", 16, 16),
		D_FIELD("p1_pcie_rd_wait", 17, 17),
		D_FIELD("pcie_rd_desc_aready", 18, 18),
		D_FIELD("p2 new txpkt need <=dma ql wr unuse 1)", 19, 19),
		D_FIELD("txpkt_pend_full_occur", 20, 20),
		D_FIELD("wait_desc_fifo_err_occur", 21, 21),
		D_FIELD("resp_fifo_full_occur", 22, 22),
		D_FIELD("resp_desc_rd_flip", 23, 23),
		D_FIELD("resp_desc_rd_id", 31, 24));

	cnt += sprint_n20_tx_dma_status_counters_1(pf, hw, buf + cnt,
						   buf_sz - cnt);

	return cnt;
}

static int sprint_n20_tx_debug1(struct mce_pf *pf, struct mce_hw *hw, char *buf,
				int buf_sz)
{
	int cnt = 0;

	if (buf_sz <= 0)
		return 0;

	cnt += SNPRINTF_REG("debug_input_pkt_count", 0x86500, D_32BIT);
	cnt += SNPRINTF_REG("debug_output_pkt_count", 0x86504, D_32BIT);
	cnt += SNPRINTF_REG("debug_state_status", 0x86508, D_32BIT);
	cnt += SNPRINTF_REG("debug_fifo_status", 0x8650c, D_32BIT);
	cnt += SNPRINTF_REG("post:to txtrans", 0x86510, D_32BIT);
	cnt += SNPRINTF_REG("post:to down_uplink", 0x86514, D_32BIT);
	cnt += SNPRINTF_REG("post:to SWC_bridge", 0x86518, D_32BIT);
	cnt += SNPRINTF_REG("post:from host/tso", 0x8651c, D_32BIT);
	cnt += SNPRINTF_REG("post:from bmc", 0x86520, D_32BIT);
	cnt += SNPRINTF_REG("post:from rdma", 0x86524, D_32BIT);
	cnt += SNPRINTF_REG("post:from switch", 0x86528, D_32BIT);
	cnt += SNPRINTF_REG("post:drop from host/tso", 0x86530, D_32BIT);
	cnt += SNPRINTF_REG("post:drop from bmc", 0x86534, D_32BIT);
	cnt += SNPRINTF_REG("post:drop from rdma", 0x86538, D_32BIT);
	cnt += SNPRINTF_REG("post:drop from switch", 0x8653c, D_32BIT);

	cnt += SNPRINTF_REG("tx_post_bus", DEBUG_TXTRANS_BUS, FUNC_D32(0));
	cnt += SNPRINTF_REG("port0_antispoof_drop", 0x86460, FUNC_D32(1));
	cnt += SNPRINTF_REG("port2_antispoof_drop", 0x86464, FUNC_D32(1));
	cnt += SNPRINTF_REG("port_0_cmd_dim_p0", 0x86460, FUNC_D32(5));
	cnt += SNPRINTF_REG("port_0_cmd_dim_p0", 0x86464, FUNC_D32(5));
	cnt += SNPRINTF_REG("port_0_cmd_dim_p0", 0x86468, FUNC_D32(5));
	cnt += SNPRINTF_REG("port_0_cmd_dim_p0", 0x8646c, FUNC_D32(5));

	cnt += SNPRINTF_REG("pkt0_drop_nosop_num", 0x86460, FUNC_D32(9));
	cnt += SNPRINTF_REG("pkt1_drop_nosop_num", 0x86464, FUNC_D32(9));
	cnt += SNPRINTF_REG("pkt2_drop_nosop_num", 0x86468, FUNC_D32(9));
	cnt += SNPRINTF_REG("pkt3_drop_nosop_num", 0x8646c, FUNC_D32(9));

	cnt += SNPRINTF_REG("host_len_com_result_counter", 0x86460,
			    FUNC_FIELD(10, "host_cmd_count_lock", 15, 0, "%u"),
			    FUNC_FIELD(10, "host_rden_count_lock", 31, 16,
				       "%u"));
	cnt += SNPRINTF_REG("tx_post_debug_10_p0", 0x86464, FUNC_D32(10));
	cnt += SNPRINTF_REG("host2_len_com_result_counter", 0x86468,
			    FUNC_FIELD(10, "host_cmd_count_lock", 15, 0, "%u"),
			    FUNC_FIELD(10, "host_rden_count_lock", 31, 16,
				       "%u"));
	cnt += SNPRINTF_REG("tx_post_debug_10_p1", 0x8646c, FUNC_D32(10));

	cnt += SNPRINTF_REG("pkt0_sop_num", 0x86460, FUNC_D32(11));
	cnt += SNPRINTF_REG("pkt0_eop_num", 0x86464, FUNC_D32(11));
	cnt += SNPRINTF_REG("pkt1_sop_num", 0x86468, FUNC_D32(11));
	cnt += SNPRINTF_REG("pkt1_eop_num", 0x8646c, FUNC_D32(11));
	cnt += SNPRINTF_REG("pkt2_sop_num", 0x86460, FUNC_D32(12));
	cnt += SNPRINTF_REG("pkt2_eop_num", 0x86464, FUNC_D32(12));
	cnt += SNPRINTF_REG("pkt3_sop_num", 0x86468, FUNC_D32(12));
	cnt += SNPRINTF_REG("pkt3_eop_num", 0x8646c, FUNC_D32(12));
	cnt += SNPRINTF_REG("port0_sop_num", 0x86460, FUNC_D32(13));
	cnt += SNPRINTF_REG("port0_eop_num", 0x86464, FUNC_D32(13));
	cnt += SNPRINTF_REG("port1_sop_num", 0x86468, FUNC_D32(13));
	cnt += SNPRINTF_REG("port1_eop_num", 0x8646c, FUNC_D32(13));
	cnt += SNPRINTF_REG("port2_sop_num", 0x86460, FUNC_D32(14));
	cnt += SNPRINTF_REG("port2_eop_num", 0x86464, FUNC_D32(14));

	return cnt;
}

static int sprint_n20_tx_debug2(struct mce_pf *pf, struct mce_hw *hw, char *buf,
				int buf_sz)
{
	int cnt = 0;

	if (buf_sz <= 0)
		return 0;
	cnt += SNPRINTF_REG("tx_fifo_empty_statuse", 0x86400,
			    D_FIELD("port_txmux_info_fifo_empty", 7, 0),
			    D_FIELD("port_txmux_data_fifo_empty", 15, 8),
			    D_FIELD("emac_sw2bmc_info_fifo_empty", 16, 16),
			    D_FIELD("emac_sw2bmc_fifo_empty", 17, 17),
			    D_FIELD("emac_swc_info_fifo_empty", 20, 20),
			    D_FIELD("emac_swc_fifo_empty", 21, 21),
			    D_FIELD("emac_port_info_fifo_empty", 22, 22),
			    D_FIELD("emac_port_fifo_empty", 23, 23),
			    D_FIELD("emac_bmc_info_fifo_empty", 24, 24),
			    D_FIELD("emac_bmc_fifo_empty", 25, 25),
			    D_FIELD("emac_rdma_info_fifo_empty", 26, 26),
			    D_FIELD("emac_rdma_fifo_empty", 27, 27),
			    D_FIELD("emac_host_info_fifo_empty", 28, 28),
			    D_FIELD("emac_host_fifo_empty", 29, 29));
	cnt += SNPRINTF_REG("debug_tx_fifo_progfull_status", 0x86404,
			    D_FIELD("port_txmux_info_fifo_progfull", 7, 0),
			    D_FIELD("port_txmux_data_fifo_progfull", 15, 8),
			    D_FIELD("emac_sw2bmc_info_fifo_progfull", 16, 16),
			    D_FIELD("emac_sw2bmc_fifo_progfull", 17, 17),
			    D_FIELD("emac_sw2dma_info_fifo_progfull", 18, 18),
			    D_FIELD("emac_sw2dma_fifo_progfull", 19, 19),
			    D_FIELD("emac_swc_tx1_info_fifo_progfull", 20, 20),
			    D_FIELD("emac_swc_tx1_fifo_progfull_tmp", 21, 21),
			    D_FIELD("emac_swc_tx0_info_fifo_progfull", 22, 22),
			    D_FIELD("emac_swc_tx0_fifo_progfull", 23, 23),
			    D_FIELD("emac_bmc_info_fifo_progfull", 24, 24),
			    D_FIELD("emac_bmc_fifo_progfull", 25, 25),
			    D_FIELD("emac_rdma_info_fifo_progfull", 26, 26),
			    D_FIELD("emac_rdma_fifo_progfull", 27, 27),
			    D_FIELD("emac_fd_fifo_progfull", 28, 28),
			    D_FIELD("emac_tso_key_fifo_afull", 29, 29),
			    D_FIELD("emac_tso_fifo_afull", 30, 30),
			    D_FIELD("emac_host_fifo_afull", 31, 31));

	return cnt;
}

static int sprint_n20_tx_debug3(struct mce_pf *pf, struct mce_hw *hw, char *buf,
				int buf_sz)
{
	int cnt = 0;

	if (buf_sz <= 0)
		return 0;
	cnt += SNPRINTF_REG("debug_tx_fifo_full_status", 0x86408,
			    D_FIELD("port_txmux_info_fifo_full", 7, 0),
			    D_FIELD("port_txmux_data_fifo_full", 15, 8),
			    D_FIELD("emac_sw2bmc_info_fifo_full", 16, 16),
			    D_FIELD("emac_sw2bmc_fifo_full", 17, 17),
			    D_FIELD("emac_sw2dma_info_fifo_full", 18, 18),
			    D_FIELD("emac_sw2dma_fifo_full", 19, 19),
			    D_FIELD("emac_swc_tx1_info_fifo_full", 20, 20),
			    D_FIELD("emac_swc_tx1_fifo_full_tmp", 21, 21),
			    D_FIELD("emac_swc_tx0_info_fifo_full", 22, 22),
			    D_FIELD("emac_swc_tx0_fifo_full", 23, 23),
			    D_FIELD("emac_bmc_info_fifo_full", 24, 24),
			    D_FIELD("emac_bmc_fifo_full", 25, 25),
			    D_FIELD("emac_rdma_info_fifo_full", 26, 26),
			    D_FIELD("emac_rdma_fifo_full", 27, 27),
			    D_FIELD("emac_fd_fifo_full", 28, 28),
			    D_FIELD("emac_tso_key_fifo_full", 29, 29),
			    D_FIELD("emac_tso_fifo_full", 30, 30),
			    D_FIELD("emac_host_fifo_full", 31, 31));
	cnt += SNPRINTF_REG("debug_tx_tso", 0x86508,
			    D_FIELD("frame_segment_dfifo_full", 0, 0),
			    D_FIELD("frame_segment_dfifo_afull", 1, 1),
			    D_FIELD("frame_segment_ififo_afull", 2, 2),
			    D_FIELD("pkt_fd_data_ofifo_progfull", 3, 3),
			    D_FIELD("pkt_data_ofifo_afull", 4, 4),
			    D_FIELD("pkt_key_ofifo_afull", 5, 5));

	cnt += SNPRINTF_REG("tso_gather_debug_0", 0x86500, FUNC_D32(0));
	cnt += SNPRINTF_REG("tso_gather_debug_1", 0x86504, FUNC_D32(0));
	cnt += SNPRINTF_REG("tso_segment_pre_0", 0x86500, FUNC_D32(1));
	cnt += SNPRINTF_REG("tso_segment_pre_1", 0x86504, FUNC_D32(1));
	cnt += SNPRINTF_REG("tso_segment_ctrl_0", 0x86500, FUNC_D32(2));
	cnt += SNPRINTF_REG("tso_segment_ctrl_1", 0x86504, FUNC_D32(2));
	cnt += SNPRINTF_REG("tso_checksum_p0", 0x86500, FUNC_D32(3));
	cnt += SNPRINTF_REG("tso_checksum_p1", 0x86504, FUNC_D32(3));
	cnt += SNPRINTF_REG("tso_modify_p0", 0x86500, FUNC_D32(4));
	cnt += SNPRINTF_REG("tso_modify_p1", 0x86504, FUNC_D32(4));
	cnt += SNPRINTF_REG("tso_debug", 0x86508,
			    FUNC_FIELD(4, "cmd_l3_ver", 1, 0, "%d"),
			    FUNC_FIELD(4, "cmd_l4_type", 7, 4, "%d"),
			    FUNC_FIELD(4, "cmd_out_l3_ver", 9, 8, "%d"),
			    FUNC_FIELD(4, "cmd_out_l4_type", 15, 12, "%d"),
			    FUNC_FIELD(4, "tunnel_type", 19, 16, "%d"));

	cnt += SNPRINTF_REG("tso_debug", 0x86508,
			    FUNC_FIELD(5, "ip_len/in_ip_len", 8, 0, "%d"),
			    FUNC_FIELD(5, "cmd_l4_len", 15, 9, "%d"),
			    FUNC_FIELD(5, "out_ip_len", 24, 16, "%d"),
			    FUNC_FIELD(5, "out_mac_len", 31, 25, "%d"));

	cnt += SNPRINTF_REG("tso_debug", 0x86508,
			    FUNC_FIELD(6, "mdy_tunnel_len", 7, 0, "%d"),
			    FUNC_FIELD(6, "cmd_l4_len", 15, 8, "%d"),
			    FUNC_FIELD(6, "mss", 31, 16, "%d"));
	return cnt;
}

static int sprint_n20_tx_mac(struct mce_pf *pf, struct mce_hw *hw, char *buf,
			     int buf_sz)
{
	int cnt = 0;

	if (buf_sz <= 0)
		return 0;

	cnt += SNPRINTF("\n==eth tx==\n");
	if (hw->nr_pf == 0) {
		cnt += SNPRINTF_REG("port0 tx sop", 0x86460, FUNC_D32(13));
		cnt += SNPRINTF_REG("port0 tx eop", 0x86464, FUNC_D32(13));
	} else {
		cnt += SNPRINTF_REG("port1 tx sop", 0x86468, FUNC_D32(13));
		cnt += SNPRINTF_REG("port1 tx eop", 0x8646c, FUNC_D32(13));
	}

	cnt += SNPRINTF("\n==mac-tx==\n");
	cnt += SNPRINTF_REG("mac-cfg", 0x64000, Hex_32BIT, D_FIELD("rx-en", 27, 27),
		D_FIELD("tx-en", 26, 26), D_FIELD("pause-disable", 20, 20),
		D_FIELD("pfc-rx-en", 12, 12), D_FIELD("pfc-tx-en", 11, 11),
		D_FIELD("pause-stop-en", 10, 10), D_FIELD("pause-en", 9, 9),
		D_FIELD("jumbo-en", 6, 6), D_FIELD("truncate-en", 5, 5),
		D_FIELD("mac-loopback", 3, 3));

	cnt += SNPRINTF_REG("txOct", 0x64000 + 0x100, D_32BIT);
	cnt += SNPRINTF_REG("txErrs", 0x64000 + 0x104, D_32BIT);
	cnt += SNPRINTF_REG("PauseTx", 0x64000 + 0x90, D_32BIT);
	cnt += SNPRINTF_REG("vlanOk", 0x64000 + 0xA0, D_32BIT);
	cnt += SNPRINTF_REG("PFC0", 0x64000 + 0xC0 + 4 * 0, D_32BIT);
	cnt += SNPRINTF_REG("PFC1", 0x64000 + 0xC0 + 4 * 1, D_32BIT);
	cnt += SNPRINTF_REG("PFC2", 0x64000 + 0xC0 + 4 * 2, D_32BIT);
	cnt += SNPRINTF_REG("PFC3", 0x64000 + 0xC0 + 4 * 3, D_32BIT);
	cnt += SNPRINTF_REG("PFC4", 0x64000 + 0xC0 + 4 * 4, D_32BIT);
	cnt += SNPRINTF_REG("PFC5", 0x64000 + 0xC0 + 4 * 5, D_32BIT);
	cnt += SNPRINTF_REG("PFC6", 0x64000 + 0xC0 + 4 * 6, D_32BIT);

	cnt += SNPRINTF_REG("TxOk_hi", 0x64000 + 0xA8, D_32BIT);
	cnt += SNPRINTF_REG("TxOk_lo", 0x64000 + 0x80, D_32BIT);

	cnt += SNPRINTF("\n");
	cnt += SNPRINTF_REG("RxOk_hi", 0x64000 + 0xAC, D_32BIT);
	cnt += SNPRINTF_REG("RxOk_lo", 0x64000 + 0x84, D_32BIT);

	return cnt;
}

static int sprint_n20_tx_debug(struct mce_pf *pf, struct mce_hw *hw, char *buf,
			       int buf_sz)
{
	int cnt = 0;

	if (buf_sz <= 0)
		return 0;

	cnt += SNPRINTF_REG("dma_axi_state_p0", 0x86488,
			    D_FIELD("cesoc_tx_timestamp_val", 0, 0),
			    D_FIELD("emac_rxfifo_full", 1, 1),
			    D_FIELD("emac_txfifo_full", 2, 2),
			    D_FIELD("emac_rxfifo_empty", 3, 3),
			    D_FIELD("emac_txfifo_empty", 4, 4),
			    D_FIELD("emac_txfifo_ecc", 5, 5),
			    D_FIELD("emac_rxfifo_ecc", 6, 6),
			    D_FIELD("cesoc_tx_rdy", 7, 7),
			    D_FIELD("tx_timestamp_wptr", 11, 8),
			    D_FIELD("tx_timestamp_rptr", 15, 12));

	cnt += SNPRINTF_REG("tx_trans_send_sop", DEBUG_TXTRANS_BUS,
			    FUNC_D32(0));
	cnt += SNPRINTF_REG("tx_trans_send_eop", DEBUG_TXTRANS_BUS,
			    FUNC_D32(1));
	cnt += SNPRINTF_REG("tx_trans_recv_sop", DEBUG_TXTRANS_BUS,
			    FUNC_D32(2));
	cnt += SNPRINTF_REG("tx_trans_recv_eop", DEBUG_TXTRANS_BUS,
			    FUNC_D32(3));
	cnt += SNPRINTF_REG("tx_trans_send_pkt_num0", DEBUG_TXTRANS_BUS,
			    FUNC_D32(4));
	cnt += SNPRINTF_REG("tx_trans_send_pkt_num1", DEBUG_TXTRANS_BUS,
			    FUNC_D32(5));
	cnt += SNPRINTF_REG("tx_trans_send_pkt_num2", DEBUG_TXTRANS_BUS,
			    FUNC_D32(6));
	cnt += SNPRINTF_REG("tx_trans_send_pkt_num3", DEBUG_TXTRANS_BUS,
			    FUNC_D32(7));
	cnt += SNPRINTF_REG("tx_trans_send_pkt_num4", DEBUG_TXTRANS_BUS,
			    FUNC_D32(8));
	cnt += SNPRINTF_REG("tx_trans_send_pkt_num5", DEBUG_TXTRANS_BUS,
			    FUNC_D32(9));
	cnt += SNPRINTF_REG("tx_trans_send_pkt_num6", DEBUG_TXTRANS_BUS,
			    FUNC_D32(10));
	cnt += SNPRINTF_REG("tx_trans_send_pkt_num7", DEBUG_TXTRANS_BUS,
			    FUNC_D32(11));
	cnt += SNPRINTF_REG("tx_trans_port_tx_status_reg_num",
			    DEBUG_TXTRANS_BUS, FUNC_D32(12));
	cnt += SNPRINTF_REG("tx_trans_port_tx_timestamp_hreg",
			    DEBUG_TXTRANS_BUS, FUNC_D32(13));
	cnt += SNPRINTF_REG("tx_trans_port_tx_timestamp_lreg",
			    DEBUG_TXTRANS_BUS, FUNC_D32(14));
	cnt += SNPRINTF_REG("tx_trans_port_tx_timestamp_val", DEBUG_TXTRANS_BUS,
			    FUNC_D32(15));
	cnt += SNPRINTF_REG("tx_trans_fsm_ns fsm_cs", DEBUG_TXTRANS_BUS,
			    FUNC_D32(16));
	cnt += SNPRINTF_REG("tx_trans_len_mon", DEBUG_TXTRANS_BUS,
			    FUNC_FIELD(17, "", 31, 0, "0x%x"),
			    FUNC_FIELD(17, "len-getted", 15, 0, "%u"),
			    FUNC_FIELD(17, "cal-len", 30, 16, "%u"),
			    FUNC_FIELD(17, "len-no-match", 31, 31, "%u"));
	cnt += SNPRINTF_REG("tx_trans_lerr_pkt_num", DEBUG_TXTRANS_BUS,
			    FUNC_D32(18));
	cnt += SNPRINTF_REG("tx_trans_pkt_len_max", DEBUG_TXTRANS_BUS,
			    FUNC_D32(19));
	cnt += SNPRINTF_REG("tx_trans_fsm_cnt_max", DEBUG_TXTRANS_BUS,
			    FUNC_D32(20));
	cnt += SNPRINTF_REG("tx_trans_len_is_zero", DEBUG_TXTRANS_BUS,
			    FUNC_D32(21));
	cnt += SNPRINTF_REG("pause xon2xoff", DEBUG_TXTRANS_BUS, FUNC_D32(23));
	cnt += SNPRINTF_REG("pfc-pri0 xon2xoff", DEBUG_TXTRANS_BUS,
			    FUNC_D32(24));
	cnt += SNPRINTF_REG("pfc-pri1 xon2xoff", DEBUG_TXTRANS_BUS,
			    FUNC_D32(25));
	cnt += SNPRINTF_REG("pfc-pri2 xon2xoff", DEBUG_TXTRANS_BUS,
			    FUNC_D32(26));
	cnt += SNPRINTF_REG("pfc-pri3 xon2xoff", DEBUG_TXTRANS_BUS,
			    FUNC_D32(27));
	cnt += SNPRINTF_REG("pfc-pri4 xon2xoff", DEBUG_TXTRANS_BUS,
			    FUNC_D32(28));
	cnt += SNPRINTF_REG("pfc-pri5 xon2xoff", DEBUG_TXTRANS_BUS,
			    FUNC_D32(29));
	cnt += SNPRINTF_REG("pfc-pri6 xon2xoff", DEBUG_TXTRANS_BUS,
			    FUNC_D32(30));
	cnt += SNPRINTF_REG("pfc-pri7 xon2xoff", DEBUG_TXTRANS_BUS,
			    FUNC_D32(31));

	cnt += sprint_n20_tx_debug1(pf, hw, buf + cnt, buf_sz - cnt);
	cnt += sprint_n20_tx_debug2(pf, hw, buf + cnt, buf_sz - cnt);
	cnt += sprint_n20_tx_debug3(pf, hw, buf + cnt, buf_sz - cnt);
	cnt += sprint_n20_tx_mac(pf, hw, buf + cnt, buf_sz - cnt);
	return cnt;
}

static u32 mce_fd_debug_cmd(struct mce_hw *hw, u32 cmd)
{
	u32 ctrl = 0;

	ctrl = rd32(hw, 0xf0000);
	ctrl &= ~GENMASK(31, 27);
	ctrl |= cmd << 27;
	wr32(hw, 0xf0000, ctrl);

	return 0;
}

struct mce_reg_info {
	u8 log_info[32];
	u32 cond;
	bool verbose_en;
	u16 offset;
};

static int mce_dump_logs(struct mce_hw *hw, struct mce_reg_info *data_base,
			 u16 item_num, u32 dump_reg, char *buf, int ret)
{
	u32 value = 0;
	u16 i = 0;

	value = rd32(hw, dump_reg);
	for (i = 0; i < item_num; i++) {
		if (data_base[i].cond & value) {
			if (data_base[i].verbose_en) {
				ret += sprintf(buf + ret, "%s 0x%x\n",
					       data_base[i].log_info,
					       (value & data_base[i].cond) >>
						       data_base[i].offset);
			} else {
				ret += sprintf(buf + ret, "%s\n",
					       data_base[i].log_info);
			}
		}
	}

	return ret;
}

static struct mce_reg_info mce_fd_profileid_debug[] = {
	{ "fsm_cnt", GENMASK(1, 0), true, 0 },
	{ "fsm_nt", GENMASK(3, 2), true, 2 },
	{ "entry_match", GENMASK(4, 4), true, 4 },
	{ "entry_end", GENMASK(5, 5), true, 5 },
	{ "entry_timeout", GENMASK(6, 6), true, 6 },
	{ "pkt_port_ena_r", GENMASK(7, 7), true, 7 },
	{ "pkt_ipv6_ena_r", GENMASK(8, 8), true, 8 },
	{ "pkt_port_r", GENMASK(15, 9), true, 9 },
	{ "pkt_profile_r", GENMASK(21, 16), true, 16 },
};

int fd_rx_debug_show(struct mce_pf *pf, struct mce_hw *hw, char *buf,
		     int buf_sz)
{
	int ret = 0;

	mce_fd_debug_cmd(hw, 0 << 1);
	ret = mce_dump_logs(hw, mce_fd_profileid_debug,
			    ARRAY_SIZE(mce_fd_profileid_debug), 0xf0004, buf,
			    ret);
	mce_fd_debug_cmd(hw, 1 << 1);
	ret += sprintf(buf + ret, "status hash 0x%.2x\n", rd32(hw, 0xf0004));
	mce_fd_debug_cmd(hw, 2 << 1);
	ret += sprintf(buf + ret, "status sign_hash 0x%.2x\n",
		       rd32(hw, 0xf0004));
	mce_fd_debug_cmd(hw, 3 << 1);
	ret += sprintf(buf + ret, "status match 0x%.2x\n", rd32(hw, 0xf0004));
	ret += sprintf(buf + ret, "-------- input --------\n");
	mce_fd_debug_cmd(hw, 6 << 1);
	ret += sprintf(buf + ret, "inpt_data0 0x%.2x\n", rd32(hw, 0xf0004));
	mce_fd_debug_cmd(hw, 7 << 1);
	ret += sprintf(buf + ret, "inpt_data1 0x%.2x\n", rd32(hw, 0xf0004));
	mce_fd_debug_cmd(hw, 8 << 1);
	ret += sprintf(buf + ret, "inpt_data2 0x%.2x\n", rd32(hw, 0xf0004));
	mce_fd_debug_cmd(hw, 9 << 1);
	ret += sprintf(buf + ret, "inpt_data3 0x%.2x\n", rd32(hw, 0xf0004));
	mce_fd_debug_cmd(hw, 10 << 1);
	ret += sprintf(buf + ret, "inpt_data4 0x%.2x\n", rd32(hw, 0xf0004));
	mce_fd_debug_cmd(hw, 11 << 1);
	ret += sprintf(buf + ret, "inpt_data5 0x%.2x\n", rd32(hw, 0xf0004));
	mce_fd_debug_cmd(hw, 12 << 1);
	ret += sprintf(buf + ret, "inpt_data6 0x%.2x\n", rd32(hw, 0xf0004));
	mce_fd_debug_cmd(hw, 13 << 1);
	ret += sprintf(buf + ret, "inpt_data7 0x%.2x\n", rd32(hw, 0xf0004));
	mce_fd_debug_cmd(hw, 14 << 1);
	ret += sprintf(buf + ret, "inpt_data8 0x%.2x\n", rd32(hw, 0xf0004));
	mce_fd_debug_cmd(hw, 15 << 1);
	ret += sprintf(buf + ret, "inpt_data9 0x%.2x\n", rd32(hw, 0xf0004));
	mce_fd_debug_cmd(hw, 16 << 1);
	ret += sprintf(buf + ret, "inpt_dataa 0x%.2x\n", rd32(hw, 0xf0004));
	ret += sprintf(buf + ret, "-------- mask ---------\n");
	mce_fd_debug_cmd(hw, 6 << 1 | 1);
	ret += sprintf(buf + ret, "mask_data0 0x%.2x\n", rd32(hw, 0xf0004));
	mce_fd_debug_cmd(hw, 7 << 1 | 1);
	ret += sprintf(buf + ret, "mask_data1 0x%.2x\n", rd32(hw, 0xf0004));
	mce_fd_debug_cmd(hw, 8 << 1 | 1);
	ret += sprintf(buf + ret, "mask_data2 0x%.2x\n", rd32(hw, 0xf0004));
	mce_fd_debug_cmd(hw, 9 << 1 | 1);
	ret += sprintf(buf + ret, "mask_data3 0x%.2x\n", rd32(hw, 0xf0004));
	mce_fd_debug_cmd(hw, 10 << 1 | 1);
	ret += sprintf(buf + ret, "mask_data4 0x%.2x\n", rd32(hw, 0xf0004));
	mce_fd_debug_cmd(hw, 11 << 1 | 1);
	ret += sprintf(buf + ret, "mask_data5 0x%.2x\n", rd32(hw, 0xf0004));
	mce_fd_debug_cmd(hw, 12 << 1 | 1);
	ret += sprintf(buf + ret, "mask_data6 0x%.2x\n", rd32(hw, 0xf0004));
	mce_fd_debug_cmd(hw, 13 << 1 | 1);
	ret += sprintf(buf + ret, "mask_data7 0x%.2x\n", rd32(hw, 0xf0004));
	mce_fd_debug_cmd(hw, 14 << 1 | 1);
	ret += sprintf(buf + ret, "mask_data8 0x%.2x\n", rd32(hw, 0xf0004));
	mce_fd_debug_cmd(hw, 15 << 1 | 1);
	ret += sprintf(buf + ret, "mask_data9 0x%.2x\n", rd32(hw, 0xf0004));
	mce_fd_debug_cmd(hw, 16 << 1 | 1);
	ret += sprintf(buf + ret, "mask_dataa 0x%.2x\n", rd32(hw, 0xf0004));
	return ret;
}

int fd_query_rule_show(struct mce_pf *pf, struct mce_hw *hw, char *buf,
		       int buf_sz)
{
	int ret = 0;

	ret += sprintf(buf + ret,
		       "not support tc clsflower, cannot query fdir rule!\n");
	return ret;
}

int mce_debugfs_queue_write(struct mce_pf *pf, struct mce_hw *hw, char *buf,
			    size_t count)
{
	int queue_start = 0, queue_end, cnt = 0;
	struct device *dev = mce_pf_to_dev(pf);

	/* echo "1 2 > /sys/kernel/debug/mcepf/xxxx/[tx_states|rx_queue_state|tx_queue_state]" */
	cnt = sscanf(buf, "%d %d", &queue_start, &queue_end);
	if (cnt != 2 || queue_start < 0 || queue_start > queue_end ||
	    queue_start >= 512 || queue_end >= 512) {
		dev_err(dev,
			"Usage: \"queue <start_queue:0~127> <queue_end:0~127>\"");
		return -EINVAL;
	}
	pf->debugfs_queue_start = queue_start;
	pf->debugfs_queue_end = queue_end;
	pf->debugfs_queue_setted = 1;

	return count;
}

int debugfs_tx_states_show(struct mce_pf *pf, struct mce_hw *hw, char *buf,
			   int buf_sz)
{
	int cnt = 0;

	if (!buf || buf_sz == 0)
		return 0;
	cnt += debugfs_tx_queue_show(pf, hw, buf + cnt, buf_sz - cnt);
	cnt += sprint_n20_tx_dma_status_counters(pf, hw, buf + cnt,
						 buf_sz - cnt);
	cnt += sprint_n20_tx_debug(pf, hw, buf + cnt, buf_sz - cnt);
	return cnt;
}

int tc_states_show(struct mce_pf *pf, struct mce_hw *hw, char *buf,
		   int buf_sz)
{
	struct mce_ets_cfg *etscfg = NULL;
	struct mce_pfc_cfg *pfccfg = NULL;
	struct mce_vsi *vsi = pf->vsi[0];
	int q_base = vsi->num_tc_offset;
	struct mce_tc_cfg *tccfg = NULL;
	struct mce_dcb *dcb = pf->dcb;
	int qg_base = 0;
	int cnt = 0;
	u8 i = 0;
	u8 j = 0;
	u8 k = 0;

	if (!buf || buf_sz == 0)
		return 0;

	if (test_bit(MCE_DCB_EN, dcb->flags)) {
		cnt += SNPRINTF("\tDCB is enabled dcbx mode is %u\n",
			 dcb->dcbx_cap);
	} else {
		cnt += SNPRINTF("\tDCB is disabled dcbx mode is %u\n",
			 dcb->dcbx_cap);
	}

	if (test_bit(MCE_DSCP_EN, dcb->flags))
		cnt += SNPRINTF("\tDSCP is enabled\n");
	else
		cnt += SNPRINTF("\tDSCP is disabled\n");

	for (i = 0; i < 8; i++) {
		cnt += SNPRINTF("\tdscp-%02u: %u, "
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
		cnt += SNPRINTF("\tPFC is enabled\n");
	else
		cnt += SNPRINTF("\tPFC is disabled\n");

	pfccfg = &dcb->cur_pfccfg;
	etscfg = &dcb->cur_etscfg;
	tccfg = &dcb->cur_tccfg;
	if (test_bit(MCE_ETS_EN, dcb->flags)) {
		for (j = 0; j < tccfg->ntc_cnt; j++) {
			cnt += SNPRINTF("\t\t tc num %u\n", j);
			for (i = 0; i < MCE_MAX_PRIORITY; i++) {
				if ((tccfg->tc_prios_bit[j] & (1 << i)) ==
				    0)
					continue;
				if (pfccfg->pfcena & (1 << i))
					cnt += SNPRINTF("\t\t\tpriority:%u - pfc on\n",
						i);
				else
					cnt += SNPRINTF("\t\t\tpriority:%u - pfc off\n",
						i);
				cnt += SNPRINTF("\t\t\tpriority:%u - q_base %u, q_cnt %u\n",
					i,
					q_base * j +
						tccfg->pfc_txq_base[j][i],
					tccfg->pfc_txq_count[j][i]);
			}
		}
	} else {
		for (i = 0; i < MCE_MAX_PRIORITY; i++) {
			if (pfccfg->pfcena & (1 << i))
				cnt += SNPRINTF("\t\t\tpriority:%u - pfc on\n",
					 i);
			else
				cnt += SNPRINTF("\t\t\tpriority:%u - pfc off\n",
					 i);
			cnt += SNPRINTF("\t\t\tpriority:%u - q_base %u, q_cnt %u\n",
				i, tccfg->pfc_txq_base[0][i],
				tccfg->pfc_txq_count[0][i]);
		}
	}

	if (test_bit(MCE_ETS_EN, dcb->flags))
		cnt += SNPRINTF("\tETS is enabled\n");
	else
		cnt += SNPRINTF("\tETS is disabled\n");

	cnt += SNPRINTF("\tthe number of TCS that ETS can use is %u\n",
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

		cnt += SNPRINTF("\tets-tc: %u hwtc: %u tsa: %s bw: %u\n", i,
			 t, tsa, etscfg->tcbwtable[i]);

		for (j = 0; j < MCE_MAX_PRIORITY; j++) {
			if (etscfg->prio_table[j] == i) {
				u8 nt = tccfg->prio_ntc[j];

				cnt += SNPRINTF("\t\tpriority: %u ntc: %u q_base: %-3u q_cnt: %u\n",
					 j, nt,
					 tccfg->ntc_txq_base[nt] +
						 nt * q_base,
					 tccfg->ntc_txq_cunt[nt]);
			}
		}

		if (!test_bit(i, etscfg->etc_state))
			continue;

		for (j = 0; j < tccfg->tc_qgs[t]; j++) {
			k = j + qg_base;
			cnt += SNPRINTF("\t\tqueue_group: %-3u "
				 "q_cnt: %-3u "
				 "minrate: %-3u(Mb) "
				 "maxrate: %-3u(Mb)\n",
				 k, tccfg->qg_qs[k], tccfg->min_rate[k],
				 tccfg->max_rate[k]);
		}
		qg_base += tccfg->tc_qgs[t];
	}

	return cnt;
}

int hwpfc_states_show(struct mce_pf *pf, struct mce_hw *hw, char *buf,
		      int buf_sz)
{
	struct mce_dcb *dcb = pf->dcb;
	u32 val = 0;
	int cnt = 0;
	int i;

	/* show fifo status */
	if (test_bit(MCE_PFC_EN, dcb->flags))
		cnt += SNPRINTF("\tPFC is enabled\n");
	else
		cnt += SNPRINTF("\tPFC is disabled\n");
	cnt += SNPRINTF("Debug pfc :\n");

	val = rd32(hw, N20_ETH_PAUSE_CTRL);

	cnt += SNPRINTF("reg 0x%x, val 0x%x\n", N20_ETH_PAUSE_CTRL, val);
	cnt += SNPRINTF("rx pause is %s, tx pause is %s, pfc mode is %s\n",
			val & BIT(0) ? "on" : "off",
			val & BIT(1) ? "on" : "off",
			val & BIT(2) ? "dscp" : "vlan");
	cnt += SNPRINTF("rx pfc bitmap 0x%x", (val >> 16) & 0xff);
	cnt += SNPRINTF("tx pfc bitmap 0x%x", (val >> 24) & 0xff);

	for (i = 0; i < N20_HW_FIFO_CNT; i++) {
		val = rd32(hw, N20_ETH_TXADDR_N_RAM(i));
		cnt += SNPRINTF("reg 0x%x val 0x%x\n", N20_ETH_TXADDR_N_RAM(i), val);
		cnt += SNPRINTF("tx %d fifo head %d tail %d\n", i, val >> 16,
			 val & 0xffff);
		val = rd32(hw, N20_ETH_RXADDR_N_RAM(i));
		cnt += SNPRINTF("rx %d fifo head %d tail %d\n", i, val >> 16,
			 val & 0xffff);
		val = rd32(hw, N20_ETH_RXFIFO_N_LEAVEL(i));
		cnt += SNPRINTF("rx %d downline %d highline %d\n", i,
			 val >> 16, val & 0xffff);
	}
	/* show fifo map */
	val = rd32(hw, N20_ETH_TX_UP2FIFO_MAP);
	cnt += SNPRINTF("reg 0x%x val 0x%x\n", N20_ETH_TX_UP2FIFO_MAP, val);
	for (i = 0; i < N20_HW_FIFO_CNT; i++)
		cnt += SNPRINTF("tx map pri %d to fifo %d\n", i,
			 (val >> (i * 4)) & 0xf);
	val = rd32(hw, N20_ETH_RX_UP2FIFO_MAP);
	cnt += SNPRINTF("reg 0x%x val 0x%x\n", N20_ETH_RX_UP2FIFO_MAP, val);
	for (i = 0; i < N20_HW_FIFO_CNT; i++)
		cnt += SNPRINTF("rx map pri %d to fifo %d\n", i,
			 (val >> (i * 4)) & 0xf);
	/* show rx mode */
	val = rd32(hw, N20_ETH_RXMUX_CTRL);
	cnt += SNPRINTF("reg 0x%x val 0x%x\n", N20_ETH_RXMUX_CTRL, val);
	if (val & BIT(1))
		cnt += SNPRINTF("rx rr enabled\n");
	if (val & BIT(0)) {
		cnt += SNPRINTF("rx wrr enabled\n");
		cnt += SNPRINTF("wrr_timer %d\n", (val >> 2) & 0xffffff);
		for (i = 0; i < 8; i++) {
			val = rd32(hw, N20_ETH_RXMUX_WRR(i));
			cnt += SNPRINTF("reg 0x%x val 0x%x\n", N20_ETH_RXMUX_WRR(i), val);
			cnt += SNPRINTF("rx[%d] %d\n", i, val);
		}
	}
	/* show queue to pfc map */
	for (i = 0; i < MAX_RING_CNT; i++) {
		/* not so good */
		val = rd32(hw, N20_DMA_REG_TX_PRIO_LVL + 0x100 * i);
		cnt += SNPRINTF("hw idx %d, map to pfc %d(0x%x) with %s\n", i,
				val & 0xff, val & 0xff,
				(val & BIT(30)) ? "enable" : "disable");
	}
	/* show dma fifo map */
	val = rd32(hw, N20_PFC_FIFO_DEPTH(0));
	cnt += SNPRINTF("reg 0x%x val 0x%x\n", N20_PFC_FIFO_DEPTH(0), val);
	cnt += SNPRINTF("dma fifo1 0 -depth %d %d\n", (val >> 16) & 0x3fff,
		 val & 0x3fff);
	val = rd32(hw, N20_PFC_FIFO_DEPTH(1));
	cnt += SNPRINTF("reg 0x%x val 0x%x\n", N20_PFC_FIFO_DEPTH(1), val);
	cnt += SNPRINTF("dma fifo3 2 -depth %d %d\n", (val >> 16) & 0x3fff,
		 val & 0x3fff);
	val = rd32(hw, N20_PFC_FIFO_DEPTH(2));
	cnt += SNPRINTF("reg 0x%x val 0x%x\n", N20_PFC_FIFO_DEPTH(2), val);
	cnt += SNPRINTF("dma fifo5 4 -depth %d %d\n", (val >> 16) & 0x3fff,
		 val & 0x3fff);
	val = rd32(hw, N20_PFC_FIFO_DEPTH(3));
	cnt += SNPRINTF("reg 0x%x val 0x%x\n", N20_PFC_FIFO_DEPTH(3), val);
	cnt += SNPRINTF("dma fifo7 6 -depth %d %d\n", (val >> 16) & 0x3fff,
		 val & 0x3fff);
	val = rd32(hw, N20_PFC_FIFO_SELECT);
	cnt += SNPRINTF("reg 0x%x val 0x%x\n", N20_PFC_FIFO_SELECT, val);
	for (i = 0; i < MCE_MAX_PRIORITY; i++) {
		cnt += SNPRINTF("pri %d en %s map to fifo %d\n", i,
			 (val >> (i * 4)) & 0x8 ? "ON" : "OFF",
			 (val >> (i * 4)) & 0x7);
	}
	cnt += SNPRINTF("dma_pfc_control:\n");

	cnt += SNPRINTF("rdma pfc:\n");
	/* show rdma pfifo setup */
	for (i = 0; i < N20_HW_FIFO_CNT; i++) {
		val = rdma_rd32(hw,
				N20_RDMA_DCNQCN_OFF(N20_RDMA_CFG_PRIO(i)));
		cnt += SNPRINTF("rdma %d pfifo val %d\n", i, val);
	}
	for (i = 0; i < N20_HW_FIFO_CNT; i++) {
		val = rdma_rd32(hw, N20_RDMA_DCNQCN_OFF(N20_RDMA_FIFO_FULL_TH(i)));
		cnt += SNPRINTF("rdma %d fifo full %d\n", i, val);
	}
	return cnt;
}

int hwets_states_show(struct mce_pf *pf, struct mce_hw *hw, char *buf,
		      int buf_sz)
{
	struct mce_vsi *vsi = pf->vsi[0];
	struct mce_dcb *dcb = pf->dcb;
	struct mce_ets_cfg *etscfg = &dcb->cur_etscfg;
	int cnt = 0;
	u32 val = 0;
	int i, j;

	if (test_bit(MCE_ETS_EN, dcb->flags))
		cnt += SNPRINTF("\tETS is enabled\n");
	else
		cnt += SNPRINTF("\tETS is disabled\n");
	cnt += SNPRINTF("Debug ETS nic :\n");

	for (i = 0; i < MCE_MAX_PRIORITY; i++)
		cnt += SNPRINTF("prio_table[%d] : %d\n", i,
			 etscfg->prio_table[i]);

	cnt += SNPRINTF("q_base is %d\n", vsi->num_tc_offset);

	for (i = 0; i < MCE_MAX_TC_CNT_NIC; i++) {
		val = rd32(hw, N20_DMA_TC_BW(i));
		cnt += SNPRINTF("tc %d bw percent %d burst_len %d\n", i,
			 val & 0x7f, 2 ^ ((val >> 12) & 7));
	}
	val = rd32(hw, N20_DMA_TC_CTRL);
	if (val & BIT(31)) {
		cnt += SNPRINTF("tc is enable\n");
		cnt += SNPRINTF("tc mode is %s\n",
			 val & BIT(30) ? "bps" : "not bps");
		cnt += SNPRINTF("tc mode is %s\n",
			 val & BIT(29) ? "pps" : "not pps");
		cnt += SNPRINTF("len consider crc:%s\n",
			 val & BIT(28) ? "yes" : "no");
		cnt += SNPRINTF("tc valid : 0x%x\n", (val >> 8) & 0xff);
		for (j = 0; j < 7; j++) {
			cnt += SNPRINTF("tc %d mode : %s\n", j,
					val & BIT(j) ? "ets" : "sp");
		}
	} else {
		cnt += SNPRINTF("tc is disable\n");
	}

	val = rd32(hw, N20_DMA_TC_TIMEOUT);
	cnt += SNPRINTF("sp timeout %d, ets timeout %d\n", val >> 16,
		 val & 0xffff);

	cnt += SNPRINTF("qg info:\n");

	for (i = 0; i < pf->max_pf_txqs / MCE_MAX_QCNT_IN_QG; i++) {
		val = rd32(hw, N20_DMA_TC_QG_CTRL(i));
		cnt += SNPRINTF("qg %i ctrl %x\n", i, val);
		cnt += SNPRINTF("qg %i %s, queue valid %x\n", i,
			 (val & F_RESTRIC_BYTE) ? "enable" : "disable",
			 (val >> 8) & 0xf);
		val = rd32(hw, N20_DMA_TC_QG_BPS_CIR(i));
		cnt += SNPRINTF("qg %i bps cir %d\n", i, val);
		val = rd32(hw, N20_DMA_TC_QG_BPS_PIR(i));
		cnt += SNPRINTF("qg %i bps pir %d\n", i, val);
	}

	for (i = 0; i < pf->max_pf_txqs; i++) {
		/* not so good */
		val = rd32(hw, N20_DMA_REG_TX_PRIO_LVL + 0x100 * i);
		cnt += SNPRINTF("hw idx %d, map to tc %d with %s\n", i,
			 fls((val & 0xff0000) >> 16) - 1,
			 (val & BIT(31)) ? "enable" : "disable");
	}

	cnt += SNPRINTF("Debug ETS rdma :\n");
	for (i = 0; i < MCE_MAX_TC_CNT_RDMA; i++) {
		val = rdma_rd32(hw, N20_RDMA_DCNQCN_OFF(N20_RDMA_CFG_PRIO_TC(i)));
		cnt += SNPRINTF("pri %d to tc %d\n", i, val);
		val = rdma_rd32(hw,
				N20_RDMA_DCNQCN_OFF(N20_RDMA_BYTES_TC(i)));
		cnt += SNPRINTF("tc %d max bytes %d\n", i, val);
	}
	val = rdma_rd32(hw, N20_RDMA_DCNQCN_OFF(N20_RDMA_TOTAL_BYTE));
	cnt += SNPRINTF("total bytes %d\n", val);
	val = rdma_rd32(hw, N20_RDMA_DCNQCN_OFF(N20_RDMA_TC_MODE));
	cnt += SNPRINTF("tc en %s, mode %x\n", (val & BIT(8)) ? "on" : "off",
		 val);
	val = rdma_rd32(hw, N20_RDMA_DCNQCN_OFF(N20_RDMA_TC_TIME));
	cnt += SNPRINTF("time cnt %d\n", val);

	return cnt;
}
