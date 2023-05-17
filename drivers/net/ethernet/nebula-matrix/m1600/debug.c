// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2022 nebula-matrix Limited.
 * Author: David Miao <david.miao@nebula-matrix.com>
 */

#ifdef CONFIG_NBL_DEBUGFS
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/debugfs.h>
#include <linux/pci.h>
#include <linux/device.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>

#include "hw.h"
#include "common.h"
#include "ethtool.h"
#include "interrupt.h"
#include "txrx.h"
#include "mailbox.h"
#include "hwmon.h"

static struct dentry *nblx4_debug_root;

#define SINGLE_FOPS_RW(_fops_, _open_, _write_) \
	static const struct file_operations _fops_ = { \
		.open = _open_,         \
		.write = _write_,       \
		.read = seq_read,       \
		.llseek = seq_lseek,    \
		.release = seq_release, \
	}

#define SINGLE_FOPS_RO(_fops_, _open_) \
	static const struct file_operations _fops_ = { \
		.open = _open_,        \
		.read = seq_read,      \
		.llseek = seq_lseek,   \
		.release = seq_release, \
	}

/* dvn */
static int dvn_seq_show(struct seq_file *m, void *v)
{
	int i, j;
	struct nbl_hw *hw = m->private;
	struct tx_queue_info q;
	struct nbl_tx_queue_stat qs;

	for (i = 0; i < NBL_MAX_TXRX_QUEUE; i++) {
		rd32_for_each(hw, NBL_DVN_QUEUE_INFO_ARR(i),
			      (u32 *)&q, sizeof(struct tx_queue_info));
		seq_printf(m, "QueueID: %03d - ", i);
		for (j = 0; j < sizeof(struct tx_queue_info) / sizeof(u32); j++)
			seq_printf(m, "%08X ", ((u32 *)&q)[j]);
		seq_printf(m, "size:%d ", q.log2_size);
		seq_printf(m, "vsi_idx:%d ", q.src_vsi_idx);
		seq_printf(m, "pri:%d ", q.priority);
		seq_printf(m, "en:%d ", q.enable);
		seq_printf(m, "tail_ptr:%d ", q.tail_ptr);
		seq_printf(m, "head_ptr:%d\n", q.head_ptr);
	}
	seq_puts(m, "\n");

	seq_puts(m, "=== statistics ===\n");
	for (i = 0; i < NBL_MAX_TXRX_QUEUE; i++) {
		rd32_for_each(hw, NBL_DVN_QUEUE_STAT_REG_ARR(i),
			      (u32 *)&qs, sizeof(struct nbl_tx_queue_stat));
		seq_printf(m, "QueueID: %03d - ", i);
		seq_printf(m, "pkt_get: %d ", qs.pkt_get);
		seq_printf(m, "pkt_out: %d ", qs.pkt_out);
		seq_printf(m, "pkt_drop: %d ", qs.pkt_drop);
		seq_printf(m, "sw_notify: %d ", qs.sw_notify);
		seq_printf(m, "pkt_dsch: %d ", qs.pkt_dsch);
		seq_printf(m, "hd_notify: %d ", qs.hd_notify);
		seq_printf(m, "hd_notify_empty: %d\n", qs.hd_notify_empty);
	}

	return 0;
}

static int debugfs_dvn_open(struct inode *inode, struct file *file)
{
	return single_open(file, dvn_seq_show, inode->i_private);
}

SINGLE_FOPS_RO(dvn_fops, debugfs_dvn_open);

/* uvn */
#define TABLE_UVN_ATTR(n, b, l)	\
	{ .name = n, .base = NBL_UVN_MODULE + (b), .len = l, }
static struct uvn_table {
	char *name;
	long base;
	int len;
} tables[] = {
	TABLE_UVN_ATTR("rd_diff_err_state",       0x2000, NBL_MAX_TXRX_QUEUE),
	TABLE_UVN_ATTR("queue_pkt_drop",          0x3000, NBL_MAX_TXRX_QUEUE),
	TABLE_UVN_ATTR("queue_desc_no_available", 0x3200, NBL_MAX_TXRX_QUEUE),
	TABLE_UVN_ATTR("queue_pkt_in_cnt",        0x3400, NBL_MAX_TXRX_QUEUE),
	TABLE_UVN_ATTR("queue_pkt_out_cnt",       0x3600, NBL_MAX_TXRX_QUEUE),
	TABLE_UVN_ATTR("queue_desc_rd_cnt",       0x3800, NBL_MAX_TXRX_QUEUE),
	TABLE_UVN_ATTR("queue_desc_wb_cnt",       0x3A00, NBL_MAX_TXRX_QUEUE),
	TABLE_UVN_ATTR("queue_notify_cnt",        0x3C00, NBL_MAX_TXRX_QUEUE),
	TABLE_UVN_ATTR("queue_desc_merge_cnt",    0x3E00, NBL_MAX_TXRX_QUEUE),
};

static int uvn_seq_show(struct seq_file *m, void *v)
{
	int i, j;
	struct nbl_hw *hw = m->private;
	struct rx_queue_info q;

	for (i = 0; i < NBL_MAX_TXRX_QUEUE; i++) {
		rd32_for_each(hw, NBL_UVN_QUEUE_INFO_ARR(i),
			      (u32 *)&q, sizeof(struct rx_queue_info));
		seq_printf(m, "QueueID: %03d - ", i);
		for (j = 0; j < sizeof(struct rx_queue_info) / sizeof(u32); j++)
			seq_printf(m, "%08X ", ((u32 *)&q)[j]);
		seq_printf(m, "size:%d ", q.log2_size);
		seq_printf(m, "buf_len:%d ", q.buf_length_pow);
		seq_printf(m, "en:%d ", q.enable);
		seq_printf(m, "tail_ptr:%d ", q.tail_ptr);
		seq_printf(m, "head_ptr:%d\n", q.head_ptr);
	}
	seq_puts(m, "\n");

	#define LINE_RECORD_NUM	8
	for (i = 0; i < ARRAY_SIZE(tables); i++) {
		seq_printf(m, "=== %s ===\n", tables[i].name);
		for (j = 0; j < tables[i].len; j++) {
			if (j % LINE_RECORD_NUM == 0)
				seq_printf(m, "QueueID %03d:", j);
			seq_printf(m, " %d", rd32(hw, tables[i].base + j * 4));
			if (((j + 1) % LINE_RECORD_NUM == 0) || ((j + 1) == LINE_RECORD_NUM))
				seq_puts(m, "\n");
		}
		if ((i + 1) != ARRAY_SIZE(tables))
			seq_puts(m, "\n");
	}

	return 0;
}

static int debugfs_uvn_open(struct inode *inode, struct file *file)
{
	return single_open(file, uvn_seq_show, inode->i_private);
}

SINGLE_FOPS_RO(uvn_fops, debugfs_uvn_open);

/* nic statistics */
static int nic_statistics_seq_show(struct seq_file *m, void *v)
{
	int epid;
	struct nbl_hw *hw = m->private;

	WARN_ON(!is_af(hw));

	for (epid = 0; epid < 4; epid++) {
		seq_printf(m, "======== port %d ========\n", epid);

		/* tx */
		seq_printf(m, "tx_total_packets=%lld\n",
			   ((u64)rd32(hw, NBL_ETH_TX_TOTAL_PKT_CNT_L_REG(epid)) |
			    (((u64)rd32(hw, NBL_ETH_TX_TOTAL_PKT_CNT_H_REG(epid)) &
			      0xFFFF) << 32)));

		seq_printf(m, "tx_total_bytes=%lld\n",
			   ((u64)rd32(hw, NBL_ETH_TX_TOTAL_BYTES_CNT_L_REG(epid)) |
			    (((u64)rd32(hw, NBL_ETH_TX_TOTAL_BYTES_CNT_H_REG(epid)) &
			      0xFFFF) << 32)));

		seq_printf(m, "tx_total_good_packets=%lld\n",
			   ((u64)rd32(hw, NBL_ETH_TX_TOTAL_GOOD_PKT_CNT_L_REG(epid)) |
			    (((u64)rd32(hw, NBL_ETH_TX_TOTAL_GOOD_PKT_CNT_H_REG(epid)) &
			      0xFFFF) << 32)));

		seq_printf(m, "tx_frame_error=%lld\n",
			   ((u64)rd32(hw, NBL_ETH_TX_FRAME_ERROR_CNT_L_REG(epid)) |
			    (((u64)rd32(hw, NBL_ETH_TX_FRAME_ERROR_CNT_H_REG(epid)) &
			      0xFFFF) << 32)));

		seq_printf(m, "tx_bad_fcs=%lld\n",
			   ((u64)rd32(hw, NBL_ETH_TX_BAD_FCS_CNT_L_REG(epid)) |
			    (((u64)rd32(hw, NBL_ETH_TX_BAD_FCS_CNT_H_REG(epid)) &
			      0xFFFF) << 32)));

		seq_printf(m, "rx_bad_code=%lld\n",
			   ((u64)rd32(hw, NBL_ETH_RX_BADCODE_CNT_L_REG(epid)) |
			    (((u64)rd32(hw, NBL_ETH_RX_BADCODE_CNT_H_REG(epid)) &
			      0xFFFF) << 32)));

		seq_puts(m, "-----\n");

		/* rx */
		seq_printf(m, "rx_total_packets=%lld\n",
			   ((u64)rd32(hw, NBL_ETH_RX_TOTAL_PKT_CNT_L_REG(epid)) |
			    (((u64)rd32(hw, NBL_ETH_RX_TOTAL_PKT_CNT_H_REG(epid)) &
			      0xFFFF) << 32)));

		seq_printf(m, "rx_total_bytes=%lld\n",
			   ((u64)rd32(hw, NBL_ETH_RX_TOTAL_BYTES_CNT_L_REG(epid)) |
			    (((u64)rd32(hw, NBL_ETH_RX_TOTAL_BYTES_CNT_H_REG(epid)) &
			      0xFFFF) << 32)));

		seq_printf(m, "rx_total_good_packets=%lld\n",
			   ((u64)rd32(hw, NBL_ETH_RX_TOTAL_GOOD_PKT_CNT_L_REG(epid)) |
			    (((u64)rd32(hw, NBL_ETH_RX_TOTAL_GOOD_PKT_CNT_H_REG(epid)) &
			      0xFFFF) << 32)));

		seq_printf(m, "rx_total_good_bytes=%lld\n",
			   ((u64)rd32(hw, NBL_ETH_RX_TOTAL_GOOD_BYTES_CNT_L_REG(epid)) |
			    (((u64)rd32(hw, NBL_ETH_RX_TOTAL_GOOD_BYTES_CNT_H_REG(epid)) &
			      0xFFFF) << 32)));

		seq_printf(m, "rx_frame_err=%lld\n",
			   ((u64)rd32(hw, NBL_ETH_RX_FRAMING_ERR_CNT_L_REG(epid)) |
			    (((u64)rd32(hw, NBL_ETH_RX_FRAMING_ERR_CNT_H_REG(epid)) &
			      0xFFFF) << 32)));

		seq_printf(m, "rx_bad_fcs=%lld\n",
			   ((u64)rd32(hw, NBL_ETH_RX_BAD_FCS_CNT_L_REG(epid)) |
			    (((u64)rd32(hw, NBL_ETH_RX_BAD_FCS_CNT_H_REG(epid)) &
			      0xFFFF) << 32)));

		seq_printf(m, "rx_oversize=%lld\n",
			   ((u64)rd32(hw, NBL_ETH_RX_OVERSIZE_CNT_L_REG(epid)) |
			    (((u64)rd32(hw, NBL_ETH_RX_OVERSIZE_CNT_H_REG(epid)) &
			      0xFFFF) << 32)));

		seq_printf(m, "rx_undersize=%lld\n",
			   ((u64)rd32(hw, NBL_ETH_RX_UNDERSIZE_CNT_L_REG(epid)) |
			    (((u64)rd32(hw, NBL_ETH_RX_UNDERSIZE_CNT_H_REG(epid)) &
			      0xFFFF) << 32)));

		if (epid != 3)
			seq_puts(m, "\n");
	}

	return 0;
}

static int debugfs_nic_statistics_open(struct inode *inode, struct file *file)
{
	return single_open(file, nic_statistics_seq_show, inode->i_private);
}

SINGLE_FOPS_RO(nic_statistics_fops, debugfs_nic_statistics_open);

/* ring */
static int ring_seq_show(struct seq_file *m, void *v)
{
	int i, j, n;
	struct nbl_rx_desc *rx_desc;
	struct nbl_tx_desc *tx_desc;
	struct nbl_ring *ring = m->private;

	seq_printf(m, "size=%d\n", ring->size);
	seq_printf(m, "dma=0x%llX\n", (unsigned long long)ring->dma);
	seq_printf(m, "desc=0x%llX\n", (unsigned long long)ring->desc);
	seq_printf(m, "desc_num=%d\n", ring->desc_num);
	seq_printf(m, "local_qid=%d\n", ring->local_qid);
	seq_printf(m, "queue_index=%d\n", ring->queue_index);
	seq_printf(m, "notify_addr=0x%llX\n",
		   (unsigned long long)ring->notify_addr);
	seq_printf(m, "buf_len=%d\n", ring->buf_len);
	seq_printf(m, "next_to_use=%d\n", ring->next_to_use);
	seq_printf(m, "next_to_clean=%d\n", ring->next_to_clean);
	seq_printf(m, "next_to_alloc=%d\n", ring->next_to_alloc);
	seq_printf(m, "tail_ptr=%d\n", ring->tail_ptr);
	if (!ring->desc) {
		seq_puts(m, "[Unallocated]\n");
		return 0;
	}

	if (ring->local_qid & 1) {
		tx_desc = (struct nbl_tx_desc *)ring->desc;
		n = sizeof(struct nbl_tx_desc) / sizeof(u32);
		for (i = 0; i < ring->desc_num; i++) {
			seq_printf(m, "[desc-%03d]: ", i);
			for (j = 0; j < n; j++)
				seq_printf(m, "%08X ", ((u32 *)tx_desc)[j]);
			seq_printf(m, "dlen:%d ", tx_desc->data_len);
			seq_printf(m, "plen:%d ", tx_desc->pkt_len);
			seq_printf(m, "dd:%d ", tx_desc->dd);
			seq_printf(m, "eop:%d ", tx_desc->eop);
			seq_printf(m, "sop:%d ", tx_desc->sop);
			seq_printf(m, "fwd:%d ", tx_desc->fwd);
			seq_printf(m, "dp:%d ", tx_desc->dport);
			seq_printf(m, "dpi:%d ", tx_desc->dport_id);
			seq_printf(m, "l3c:%d ", tx_desc->l3_checksum);
			seq_printf(m, "l4c:%d ", tx_desc->l4_checksum);
			seq_printf(m, "rsslag:%d ", tx_desc->rss_lag);
			seq_printf(m, "l3_off:%d\n", tx_desc->l3_start_offset);
			tx_desc++;
		}
	} else {
		rx_desc = (struct nbl_rx_desc *)ring->desc;
		n = sizeof(struct nbl_rx_desc) / sizeof(u32);
		for (i = 0; i < ring->desc_num; i++) {
			seq_printf(m, "[desc-%03d]: ", i);
			for (j = 0; j < n; j++)
				seq_printf(m, "%08X ", ((u32 *)rx_desc)[j]);
			seq_printf(m, "dlen:%d ", rx_desc->data_len);
			seq_printf(m, "dd:%d ", rx_desc->dd);
			seq_printf(m, "eop:%d ", rx_desc->eop);
			seq_printf(m, "sop:%d ", rx_desc->sop);
			seq_printf(m, "fwd:%d ", rx_desc->fwd);
			seq_printf(m, "sp:%d ", rx_desc->sport);
			seq_printf(m, "spi:%d ", rx_desc->sport_id);
			seq_printf(m, "cks:%d ", rx_desc->checksum_status);
			seq_printf(m, "ptype:%d ", rx_desc->ptype);
			seq_printf(m, "lag:%d ", rx_desc->lag);
			seq_printf(m, "lagid:%d\n", rx_desc->lag_id);
			rx_desc++;
		}
	}

	return 0;
}

static int debugfs_ring_open(struct inode *inode, struct file *file)
{
	return single_open(file, ring_seq_show, inode->i_private);
}

SINGLE_FOPS_RO(ring_fops, debugfs_ring_open);

/* function_msix_map_table  */
static int tables_seq_show(struct seq_file *m, void *v)
{
	int i, j, k;
	struct nbl_hw *hw;
	struct nbl_adapter *adapter;
	struct nbl_function_msix_map function_msix_map;
	struct nbl_qid_map qid_map;
	struct nbl_msix_entry msix_entry;
	struct nbl_msix_info msix_info;
	struct nbl_queue_map queue_map;

	hw = m->private;
	adapter = (struct nbl_adapter *)hw->back;

	seq_puts(m, "===== function_msix_map_table at 0x0013_4000 =====\n");
	for (i = 0; i < NBL_MAX_FUNC; i++) {
		struct nbl_func_res *funs_res = hw->af_res->res_record[i];

		rd32_for_each(hw, NBL_PCOMPLETER_FUNCTION_MSIX_MAP_REG_ARR(i),
			      (u32 *)&function_msix_map,
			      sizeof(struct nbl_function_msix_map));
		seq_printf(m, "[%03d] base:0x%llX bus:%d dev:%d func:%d valid:%d\n",
			   i,
			   function_msix_map.msix_map_base_addr,
			   function_msix_map.bus,
			   function_msix_map.devid,
			   function_msix_map.function,
			   function_msix_map.valid);

		if (funs_res) {
			seq_printf(m, "    queues:%d irqs:%d\n",
				   funs_res->num_txrx_queues, funs_res->num_interrupts);

			for (j = 0; j < adapter->num_q_vectors + 1; j++) {
				seq_printf(m, "    [%03d] global_msix_index:%d valid:%d\n", j,
					   funs_res->msix_map_table.base_addr[j].global_msix_index,
					   funs_res->msix_map_table.base_addr[j].valid);
			}
		}
	}
	seq_puts(m, "\n");

	for (k = 0; k < 2; k++) {
		seq_printf(m, "===== qid_map_table %d at 0x0013_8000 now %d =====\n",
			   k, rd32(hw, NBL_PCOMPLETER_QUEUE_TABLE_SELECT_REG) & 1);
		for (i = 0; i < NBL_MAX_TXRX_QUEUE; i++) {
			rd32_for_each(hw, NBL_PCOMPLETER_QID_MAP_REG_ARR(k, i),
				      (u32 *)&qid_map, sizeof(struct nbl_qid_map));
			seq_printf(m, "[%03d] local_qid:%d notify_addr_l:0x%X notify_addr_h:0x%X global_qid:%d notify_addr:0x%llX\n",
				   i,
				   qid_map.local_qid,
				   qid_map.notify_addr_l,
				   qid_map.notify_addr_h,
				   qid_map.global_qid,
				   (((u64)qid_map.notify_addr_h << 27) |
				    qid_map.notify_addr_l) << 5);
		}
		seq_puts(m, "\n");
	}

	seq_puts(m, "===== msix_table at 0x0015_4000 =====\n");
	for (i = 0; i < NBL_MAX_INTERRUPT; i++) {
		rd32_for_each(hw, NBL_PADPT_MSIX_TABLE_REG_ADDR(i),
			      (u32 *)&msix_entry, sizeof(struct nbl_msix_entry));
		seq_printf(m, "[%03d] addr:0x%016llX msg_data:%d mask:%d\n", i,
			   ((u64)msix_entry.upper_address << 32) | msix_entry.lower_address,
			   msix_entry.message_data, msix_entry.vector_mask);
	}
	seq_puts(m, "\n");

	seq_puts(m, "===== msix_info_table at 0x0015_8000 =====\n");
	for (i = 0; i < NBL_MAX_INTERRUPT; i++) {
		rd32_for_each(hw, NBL_PADPT_MSIX_INFO_REG_ARR(i),
			      (u32 *)&msix_info, sizeof(struct nbl_msix_info));
		seq_printf(m, "[%03d] intrl_pnum:%d intrl_rate:%d bus:%d dev:%d func:%d valid:%d\n",
			   i,
			   msix_info.intrl_pnum, msix_info.intrl_rate,
			   msix_info.bus, msix_info.devid, msix_info.function, msix_info.valid);
	}
	seq_puts(m, "\n");

	seq_puts(m, "===== queue_map_table at 0x0015_C000 =====\n");
	for (i = 0; i < NBL_MAX_TXRX_QUEUE * 2; i++) {
		rd32_for_each(hw, NBL_PADPT_QUEUE_MAP_REG_ARR(i),
			      (u32 *)&queue_map, sizeof(struct nbl_queue_map));
		seq_printf(m, "[%03d] bus:%d dev:%d func:%d msix_idx:%d valid:%d\n", i,
			   queue_map.bus, queue_map.devid, queue_map.function,
			   queue_map.msix_idx, queue_map.msix_idx_valid);
	}

	return 0;
}

static int debugfs_tables_open(struct inode *inode, struct file *file)
{
	return single_open(file, tables_seq_show, inode->i_private);
}

SINGLE_FOPS_RO(tables_fops, debugfs_tables_open);

/* bar */
static int bar_seq_show(struct seq_file *m, void *v)
{
	struct nbl_hw *hw = m->private;
	struct nbl_adapter *adapter = hw->back;

	seq_printf(m, "BAR0 - phy: 0x%llX virt: 0x%llX len: 0x%llX\n",
		   pci_resource_start(adapter->pdev, NBL_X4_MEMORY_BAR),
		   (u64)hw->hw_addr,
		   pci_resource_len(adapter->pdev, NBL_X4_MEMORY_BAR));
	seq_printf(m, "BAR2 - phy: 0x%llX virt: 0x%llX len: 0x%llX\n",
		   pci_resource_start(adapter->pdev, NBL_X4_MAILBOX_BAR),
		   (u64)hw->mailbox_bar_hw_addr,
		   pci_resource_len(adapter->pdev, NBL_X4_MAILBOX_BAR));

	return 0;
}

static int debugfs_bar_open(struct inode *inode, struct file *file)
{
	return single_open(file, bar_seq_show, inode->i_private);
}

SINGLE_FOPS_RO(bar_fops, debugfs_bar_open);

/* register
 * echo offset > register           - BAR 0 and 4B
 * echo offset,length > register    - BAR 0 and length
 * echo bB,offset > register        - BAR B (0 or 2) and 4B
 * echo bB,offset,length > register - BAR B (0 or 2) and length
 */
static int register_seq_show(struct seq_file *m, void *v)
{
	int i;
	struct nbl_hw *hw = m->private;

	seq_printf(m, "BAR %d off 0x%lX len 0x%lX:\n",
		   hw->debugfs_reg_bar, hw->debugfs_reg_offset, hw->debugfs_reg_length);
	for (i = 0; i < hw->debugfs_reg_length; i += 4) {
		seq_printf(m, "[%08X]: ", (unsigned int)hw->debugfs_reg_offset + i);
		if (hw->debugfs_reg_bar == 0)
			seq_printf(m, "%08X\n", rd32(hw, hw->debugfs_reg_offset + i));
		else if (hw->debugfs_reg_bar == 2)
			seq_printf(m, "%08X\n", mb_rd32(hw, hw->debugfs_reg_offset + i));
	}

	return 0;
}

static ssize_t debugfs_register_write(struct file *file,
				      const char __user *buf, size_t count, loff_t *ppos)
{
	int err;
	char *p, *p1, line[16] = { 0, };
	struct nbl_hw *hw = ((struct seq_file *)(file->private_data))->private;

	if (copy_from_user(line, buf, count))
		return -EFAULT;

	p = line;
	/* BAR */
	if (line[0] == 'b') {
		if (line[2] != ',')
			return -EINVAL;
		if (line[1] == '0')
			hw->debugfs_reg_bar = 0;
		else if (line[1] == '2')
			hw->debugfs_reg_bar = 2;
		else
			return -EINVAL;
		p = line + 3;
	}
	/* offset */
	p1 = strchr(p, ',');
	if (p1) {
		*p1 = 0;
		p1++;
	}
	err = kstrtol(p, 0, &hw->debugfs_reg_offset);
	if (err)
		return err;
	/* length */
	if (p1) {
		err = kstrtol(p1, 0, &hw->debugfs_reg_length);
		if (err)
			return err;
	}

	hw->debugfs_reg_offset = ALIGN_DOWN(hw->debugfs_reg_offset, 4);
	hw->debugfs_reg_length = ALIGN(hw->debugfs_reg_length, 4);
	if (!hw->debugfs_reg_length)
		hw->debugfs_reg_length = 4;

	return count;
}

static int debugfs_register_open(struct inode *inode, struct file *file)
{
	return single_open(file, register_seq_show, inode->i_private);
}

SINGLE_FOPS_RW(reg_fops, debugfs_register_open, debugfs_register_write);

/* function init and cleanup */
void nbl_debugfs_hw_init(struct nbl_hw *hw)
{
	int i;
	char buf[16];
	struct nbl_adapter *adapter;

	adapter = (struct nbl_adapter *)hw->back;

	if (!nblx4_debug_root)
		return;

	snprintf(buf, sizeof(buf), "%04x:%02x:%02x.%x",
		 pci_domain_nr(adapter->pdev->bus), hw->bus, hw->devid, hw->function);
	hw->nbl_debug_root = debugfs_create_dir(buf, nblx4_debug_root);

	if (is_af(hw)) {
		debugfs_create_file("dvn", 0444,
				    hw->nbl_debug_root, hw, &dvn_fops);
		debugfs_create_file("uvn", 0644,
				    hw->nbl_debug_root, hw, &uvn_fops);
		debugfs_create_file("nic-statistics", 0444,
				    hw->nbl_debug_root, hw, &nic_statistics_fops);
		debugfs_create_file("tables", 0644,
				    hw->nbl_debug_root, hw, &tables_fops);
	}

	if (adapter->num_txq) {
		for (i = 0; i < adapter->num_txq; i++) {
			snprintf(buf, sizeof(buf), "txring-%d", i);
			debugfs_create_file(buf, 0444,
					    hw->nbl_debug_root,
					    adapter->tx_rings[i], &ring_fops);
		}
	}

	if (adapter->num_rxq) {
		for (i = 0; i < adapter->num_rxq; i++) {
			snprintf(buf, sizeof(buf), "rxring-%d", i);
			debugfs_create_file(buf, 0444,
					    hw->nbl_debug_root,
					    adapter->rx_rings[i], &ring_fops);
		}
	}

	debugfs_create_file("bar", 0444, hw->nbl_debug_root, hw, &bar_fops);

	hw->debugfs_reg_bar = 0;
	hw->debugfs_reg_offset = 0;
	hw->debugfs_reg_length = 8;
	debugfs_create_file("reg", 0444, hw->nbl_debug_root, hw, &reg_fops);
}

void nbl_debugfs_hw_exit(struct nbl_hw *hw)
{
	debugfs_remove_recursive(hw->nbl_debug_root);
	hw->nbl_debug_root = NULL;
}

/* module init and cleanup */
void nbl_debugfs_init(void)
{
	nblx4_debug_root = debugfs_create_dir("nblx4", NULL);
	if (!nblx4_debug_root)
		pr_info("init of nbl X4 debugfs failed\n");
}

void nbl_debugfs_exit(void)
{
	debugfs_remove_recursive(nblx4_debug_root);
	nblx4_debug_root = NULL;
}
#endif	/* CONFIG_NBL_DEBUGFS */
