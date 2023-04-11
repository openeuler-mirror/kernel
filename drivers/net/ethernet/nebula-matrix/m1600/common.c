// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2022 nebula-matrix Limited.
 * Author: Monte Song <monte.song@nebula-matrix.com>
 */

#include <linux/pci.h>
#include <linux/netdevice.h>
#include <linux/delay.h>

#include "hw.h"
#include "common.h"
#include "txrx.h"
#include "mailbox.h"

#ifndef ETH_P_LLDP
#define ETH_P_LLDP 0x88CC
#endif

void nbl_af_configure_fc_cplh_up_th(struct nbl_hw *hw)
{
	wr32(hw, NBL_FC_CPLH_UP_TH_REG_ADDR, NBL_FC_CPLH_UP_TH_B8);
}

void nbl_firmware_init(struct nbl_hw *hw)
{
	u32 init_status;
	u32 i = 0;

	do {
		init_status = rd32(hw, NBL_GREG_DYNAMIC_INIT_REG);
		i++;
		if (i % 10 == 0)
			pr_warn("Tried %u times already, but firmware has not been initialized yet\n",
				i);
	} while (init_status != NBL_DYNAMIC_INIT_DONE);
}

static void nbl_af_capture_broadcast_packets(struct nbl_hw *hw)
{
	struct nbl_pcmrt_action pcmrt_action;
	struct nbl_pcmrt_mask pcmrt_mask;
	struct nbl_pcmrt_key pcmrt_key;
	unsigned int slot = NBL_PCMRT_BROADCAST_SLOT;

	memset(&pcmrt_key, 0, sizeof(pcmrt_key));
	pcmrt_key.dmac_type = NBL_PCMRT_DMAC_BROADCAST;
	pcmrt_key.valid = 1;

	memset(&pcmrt_mask, 0, sizeof(pcmrt_mask));
	pcmrt_mask.dmac_mask = 0;
	pcmrt_mask.etype_mask = 1;
	pcmrt_mask.ip_protocol_mask = 1;
	pcmrt_mask.dport_mask = 1;
	pcmrt_mask.tcp_ctrl_bits_mask = 1;
	pcmrt_mask.up_down_mask = 1;

	rd32_for_each(hw, NBL_PA_PCMRT_ACTION_REG, (u32 *)&pcmrt_action, sizeof(pcmrt_action));
	pcmrt_action.action_bitmap &= ~(NBL_PCMRT_ACTION_MASK << (slot * NBL_PCMRT_ACTION_BIT_LEN));
	pcmrt_action.action_bitmap |= ((u64)NBL_PCMRT_ACTION_CAPTURE) <<
				       (slot * NBL_PCMRT_ACTION_BIT_LEN);

	wr32_for_each(hw, NBL_PA_PCMRT_ACTION_REG, (u32 *)&pcmrt_action, sizeof(pcmrt_action));
	wr32_for_each(hw, NBL_PA_PCMRT_MASK_REG_ARR(slot), (u32 *)&pcmrt_mask, sizeof(pcmrt_mask));
	wr32_for_each(hw, NBL_PA_PCMRT_KEY_REG_ARR(slot), (u32 *)&pcmrt_key, sizeof(pcmrt_key));
}

static void nbl_af_capture_multicast_packets(struct nbl_hw *hw)
{
	struct nbl_pcmrt_action pcmrt_action;
	struct nbl_pcmrt_mask pcmrt_mask;
	struct nbl_pcmrt_key pcmrt_key;
	unsigned int slot = NBL_PCMRT_MULTICAST_SLOT;

	memset(&pcmrt_key, 0, sizeof(pcmrt_key));
	pcmrt_key.dmac_type = NBL_PCMRT_DMAC_MULTICAST;
	pcmrt_key.valid = 1;

	memset(&pcmrt_mask, 0, sizeof(pcmrt_mask));
	pcmrt_mask.dmac_mask = 0;
	pcmrt_mask.etype_mask = 1;
	pcmrt_mask.ip_protocol_mask = 1;
	pcmrt_mask.dport_mask = 1;
	pcmrt_mask.tcp_ctrl_bits_mask = 1;
	pcmrt_mask.up_down_mask = 1;

	rd32_for_each(hw, NBL_PA_PCMRT_ACTION_REG, (u32 *)&pcmrt_action, sizeof(pcmrt_action));
	pcmrt_action.action_bitmap &= ~(NBL_PCMRT_ACTION_MASK <<
				       (slot * NBL_PCMRT_ACTION_BIT_LEN));
	pcmrt_action.action_bitmap |= ((u64)NBL_PCMRT_ACTION_CAPTURE) <<
					(slot * NBL_PCMRT_ACTION_BIT_LEN);

	wr32_for_each(hw, NBL_PA_PCMRT_ACTION_REG, (u32 *)&pcmrt_action, sizeof(pcmrt_action));
	wr32_for_each(hw, NBL_PA_PCMRT_MASK_REG_ARR(slot), (u32 *)&pcmrt_mask, sizeof(pcmrt_mask));
	wr32_for_each(hw, NBL_PA_PCMRT_KEY_REG_ARR(slot), (u32 *)&pcmrt_key, sizeof(pcmrt_key));
}

static void nbl_af_capture_lacp_packets(struct nbl_hw *hw)
{
	u32 etype_ext;
	struct nbl_pcmrt_action pcmrt_action;
	struct nbl_pcmrt_mask pcmrt_mask;
	struct nbl_pcmrt_key pcmrt_key;
	unsigned int etype_ext_slot = NBL_ETYPE_EXT_LACP_SLOT;
	unsigned int index;
	unsigned int offset;
	unsigned int slot = NBL_PCMRT_LACP_SLOT;

	index = etype_ext_slot / NBL_ETYPE_EXTS_PER_REG;
	offset = etype_ext_slot % NBL_ETYPE_EXTS_PER_REG;
	etype_ext = rd32(hw, NBL_PA_ETYPE_EXT_REG_ARR(index));
	etype_ext &= ~(NBL_ETYPE_EXT_MASK << (offset * NBL_ETYPE_EXT_BIT_LEN));
	etype_ext |= ETH_P_SLOW << (offset * NBL_ETYPE_EXT_BIT_LEN);
	wr32(hw, NBL_PA_ETYPE_EXT_REG_ARR(index), etype_ext);

	memset(&pcmrt_key, 0, sizeof(pcmrt_key));
	pcmrt_key.etype_type = NBL_PCMRT_ETYPE_EXT_BASE + etype_ext_slot;
	pcmrt_key.valid = 1;

	memset(&pcmrt_mask, 0, sizeof(pcmrt_mask));
	pcmrt_mask.dmac_mask = 1;
	pcmrt_mask.etype_mask = 0;
	pcmrt_mask.ip_protocol_mask = 1;
	pcmrt_mask.dport_mask = 1;
	pcmrt_mask.tcp_ctrl_bits_mask = 1;
	pcmrt_mask.up_down_mask = 1;

	rd32_for_each(hw, NBL_PA_PCMRT_ACTION_REG, (u32 *)&pcmrt_action, sizeof(pcmrt_action));
	pcmrt_action.action_bitmap &= ~(NBL_PCMRT_ACTION_MASK << (slot * NBL_PCMRT_ACTION_BIT_LEN));
	pcmrt_action.action_bitmap |= ((u64)NBL_PCMRT_ACTION_CAPTURE) <<
				      (slot * NBL_PCMRT_ACTION_BIT_LEN);

	wr32_for_each(hw, NBL_PA_PCMRT_ACTION_REG, (u32 *)&pcmrt_action, sizeof(pcmrt_action));
	wr32_for_each(hw, NBL_PA_PCMRT_MASK_REG_ARR(slot), (u32 *)&pcmrt_mask, sizeof(pcmrt_mask));
	wr32_for_each(hw, NBL_PA_PCMRT_KEY_REG_ARR(slot), (u32 *)&pcmrt_key, sizeof(pcmrt_key));
}

static void nbl_af_capture_lldp_packets(struct nbl_hw *hw)
{
	u32 etype_ext;
	struct nbl_pcmrt_action pcmrt_action;
	struct nbl_pcmrt_mask pcmrt_mask;
	struct nbl_pcmrt_key pcmrt_key;
	unsigned int etype_ext_slot = NBL_ETYPE_EXT_LLDP_SLOT;
	unsigned int index;
	unsigned int offset;
	unsigned int slot = NBL_PCMRT_LLDP_SLOT;

	index = etype_ext_slot / NBL_ETYPE_EXTS_PER_REG;
	offset = etype_ext_slot % NBL_ETYPE_EXTS_PER_REG;
	etype_ext = rd32(hw, NBL_PA_ETYPE_EXT_REG_ARR(index));
	etype_ext &= ~(NBL_ETYPE_EXT_MASK << (offset * NBL_ETYPE_EXT_BIT_LEN));
	etype_ext |= ETH_P_LLDP << (offset * NBL_ETYPE_EXT_BIT_LEN);
	wr32(hw, NBL_PA_ETYPE_EXT_REG_ARR(index), etype_ext);

	memset(&pcmrt_key, 0, sizeof(pcmrt_key));
	pcmrt_key.etype_type = NBL_PCMRT_ETYPE_EXT_BASE + etype_ext_slot;
	pcmrt_key.valid = 1;

	memset(&pcmrt_mask, 0, sizeof(pcmrt_mask));
	pcmrt_mask.dmac_mask = 1;
	pcmrt_mask.etype_mask = 0;
	pcmrt_mask.ip_protocol_mask = 1;
	pcmrt_mask.dport_mask = 1;
	pcmrt_mask.tcp_ctrl_bits_mask = 1;
	pcmrt_mask.up_down_mask = 1;

	rd32_for_each(hw, NBL_PA_PCMRT_ACTION_REG, (u32 *)&pcmrt_action, sizeof(pcmrt_action));
	pcmrt_action.action_bitmap &= ~(NBL_PCMRT_ACTION_MASK << (slot * NBL_PCMRT_ACTION_BIT_LEN));
	pcmrt_action.action_bitmap |= ((u64)NBL_PCMRT_ACTION_CAPTURE) <<
				      (slot * NBL_PCMRT_ACTION_BIT_LEN);

	wr32_for_each(hw, NBL_PA_PCMRT_ACTION_REG, (u32 *)&pcmrt_action, sizeof(pcmrt_action));
	wr32_for_each(hw, NBL_PA_PCMRT_MASK_REG_ARR(slot), (u32 *)&pcmrt_mask, sizeof(pcmrt_mask));
	wr32_for_each(hw, NBL_PA_PCMRT_KEY_REG_ARR(slot), (u32 *)&pcmrt_key, sizeof(pcmrt_key));
}

static void nbl_af_clear_capture_broadcast_packets_conf(struct nbl_hw *hw)
{
	struct nbl_pcmrt_key pcmrt_key;
	unsigned int slot = NBL_PCMRT_BROADCAST_SLOT;

	memset(&pcmrt_key, 0, sizeof(pcmrt_key));
	pcmrt_key.valid = 0;
	wr32_for_each(hw, NBL_PA_PCMRT_KEY_REG_ARR(slot), (u32 *)&pcmrt_key, sizeof(pcmrt_key));
}

static void nbl_af_clear_capture_multicast_packets_conf(struct nbl_hw *hw)
{
	struct nbl_pcmrt_key pcmrt_key;
	unsigned int slot = NBL_PCMRT_MULTICAST_SLOT;

	memset(&pcmrt_key, 0, sizeof(pcmrt_key));
	pcmrt_key.valid = 0;
	wr32_for_each(hw, NBL_PA_PCMRT_KEY_REG_ARR(slot), (u32 *)&pcmrt_key, sizeof(pcmrt_key));
}

static void nbl_af_clear_capture_lacp_packets_conf(struct nbl_hw *hw)
{
	struct nbl_pcmrt_key pcmrt_key;
	unsigned int slot = NBL_PCMRT_LACP_SLOT;

	memset(&pcmrt_key, 0, sizeof(pcmrt_key));
	pcmrt_key.valid = 0;
	wr32_for_each(hw, NBL_PA_PCMRT_KEY_REG_ARR(slot), (u32 *)&pcmrt_key, sizeof(pcmrt_key));
}

static void nbl_af_clear_capture_lldp_packets_conf(struct nbl_hw *hw)
{
	struct nbl_pcmrt_key pcmrt_key;
	unsigned int slot = NBL_PCMRT_LLDP_SLOT;

	memset(&pcmrt_key, 0, sizeof(pcmrt_key));
	pcmrt_key.valid = 0;
	wr32_for_each(hw, NBL_PA_PCMRT_KEY_REG_ARR(slot), (u32 *)&pcmrt_key, sizeof(pcmrt_key));
}

void nbl_af_configure_captured_packets(struct nbl_hw *hw)
{
	nbl_af_capture_broadcast_packets(hw);
	nbl_af_capture_multicast_packets(hw);
	nbl_af_capture_lacp_packets(hw);
	nbl_af_capture_lldp_packets(hw);
}

void nbl_af_clear_captured_packets_conf(struct nbl_hw *hw)
{
	nbl_af_clear_capture_broadcast_packets_conf(hw);
	nbl_af_clear_capture_multicast_packets_conf(hw);
	nbl_af_clear_capture_lacp_packets_conf(hw);
	nbl_af_clear_capture_lldp_packets_conf(hw);
}

u32 nbl_af_get_firmware_version(struct nbl_hw *hw)
{
	return rd32(hw, NBL_GREG_DYNAMIC_VERSION_REG);
}

int nbl_af_res_mng_init(struct nbl_hw *hw)
{
	struct nbl_af_res_info *af_res;
	struct nbl_qid_map invalid_qid_map;
	struct nbl_func_res *func_res;
	u16 i;

	af_res = kmalloc(sizeof(*af_res), GFP_KERNEL);
	if (!af_res)
		return -ENOMEM;

	spin_lock_init(&af_res->func_res_lock);
	bitmap_zero(af_res->interrupt_bitmap, NBL_MAX_INTERRUPT);
	bitmap_zero(af_res->txrx_queue_bitmap, NBL_MAX_TXRX_QUEUE);

	af_res->qid_map_ready = 0;
	af_res->qid_map_select = NBL_MASTER_QID_MAP_TABLE;

	memset(&invalid_qid_map, 0, sizeof(invalid_qid_map));
	invalid_qid_map.local_qid = 0x1F;
	invalid_qid_map.notify_addr_l = 0x7FFFFFF;
	invalid_qid_map.notify_addr_h = 0xFFFF;
	invalid_qid_map.global_qid = 0x7F;
	invalid_qid_map.rsv = 0x1FF;
	for (i = 0; i < NBL_QID_MAP_TABLE_ENTRIES; i++)
		af_res->qid_map_table[i] = invalid_qid_map;

	memset(af_res->res_record, 0, sizeof(af_res->res_record));

	for (i = 0; i < NBL_ETH_PORT_NUM; i++) {
		atomic_set(&af_res->eth_port_tx_refcount[i], 0);
		atomic_set(&af_res->eth_port_rx_refcount[i], 0);
	}

	for (i = 0; i < NBL_MAX_FUNC; i++) {
		func_res = kmalloc(sizeof(*func_res), GFP_ATOMIC | __GFP_ZERO);
		if (!func_res)
			goto all_mem_failed;
		af_res->res_record[i] = func_res;
	}

	hw->af_res = af_res;
	return 0;

all_mem_failed:
	for (i = 0; i < NBL_MAX_PF_FUNC; i++)
		kfree(af_res->res_record[i]);
	kfree(af_res);
	return -ENOMEM;
}

void nbl_af_free_res(struct nbl_hw *hw)
{
	struct nbl_af_res_info *af_res;
	struct nbl_func_res *func_res;
	u8 i;

	af_res = hw->af_res;
	for (i = 0; i < NBL_MAX_FUNC; i++) {
		func_res = af_res->res_record[i];
		kfree(func_res);
	}

	kfree(af_res);
	hw->af_res = NULL;
}

void nbl_af_compute_bdf(struct nbl_hw *hw, u16 func_id,
			u8 *bus, u8 *devid, u8 *function)
{
	u16 af_bdf;
	u16 function_bdf;

	af_bdf = (((u16)hw->bus) << 8) | PCI_DEVFN((u16)hw->devid, (u16)hw->function);
	function_bdf = af_bdf + func_id;

	if (function_bdf < af_bdf)
		pr_alert("Compute BDF number for mailbox function %u error\n", func_id);

	*bus = function_bdf >> 8;
	*devid = PCI_SLOT(function_bdf);
	*function = PCI_FUNC(function_bdf);
}

bool nbl_check_golden_version(struct nbl_hw *hw)
{
	struct nbl_dynamic_version version;

	rd32_for_each(hw, NBL_GREG_DYNAMIC_VERSION_REG, (u32 *)&version,
		      sizeof(version));
	return version.sub_version == NBL_GOLDEN_SUB_VERSION;
}

static inline u64 nbl_get_qid_map_key(struct nbl_qid_map qid_map)
{
	u64 key;
	u64 notify_addr_l;
	u64 notify_addr_h;

	notify_addr_l = qid_map.notify_addr_l;
	notify_addr_h = qid_map.notify_addr_h;
	key = (notify_addr_h << NBL_QID_MAP_NOTIFY_ADDR_LOW_PART_LEN) | notify_addr_l;

	return key;
}

static void nbl_af_fill_qid_map_table(struct nbl_hw *hw, u16 func_id, u64 notify_addr)
{
	struct nbl_af_res_info *af_res = hw->af_res;
	struct nbl_func_res *func_res = af_res->res_record[func_id];
	struct nbl_qid_map qid_map;
	struct nbl_queue_table_ready queue_table_ready;
	struct nbl_queue_table_select queue_table_select;
	unsigned long flags;
	u8 *txrx_queues;
	u64 key;
	u8 qid_map_entries;
	u8 qid_map_base;
	u8 i;
	u8 j;

	spin_lock_irqsave(&af_res->func_res_lock, flags);

	qid_map_base = NBL_QID_MAP_TABLE_ENTRIES;
	key = notify_addr >> NBL_QID_MAP_NOTIFY_ADDR_SHIFT;
	for (i = 0; i < NBL_QID_MAP_TABLE_ENTRIES; i++) {
		WARN_ON(key == nbl_get_qid_map_key(af_res->qid_map_table[i]));
		if (key < nbl_get_qid_map_key(af_res->qid_map_table[i])) {
			qid_map_base = i;
			break;
		}
	}

	if (unlikely(qid_map_base == NBL_QID_MAP_TABLE_ENTRIES)) {
		pr_alert("Can not insert key corresponding to notify addr %llx\n", notify_addr);
		spin_unlock_irqrestore(&af_res->func_res_lock, flags);
		return;
	}

	qid_map_entries = func_res->num_txrx_queues;
	for (i = NBL_QID_MAP_TABLE_ENTRIES - qid_map_entries; i > qid_map_base; i--)
		af_res->qid_map_table[i - 1 + qid_map_entries] = af_res->qid_map_table[i - 1];

	txrx_queues = func_res->txrx_queues;
	memset(&qid_map, 0, sizeof(qid_map));
	for (i = 0; i < qid_map_entries; i++) {
		qid_map.local_qid = 2 * i + 1;
		qid_map.notify_addr_l = key;
		qid_map.notify_addr_h = key >> NBL_QID_MAP_NOTIFY_ADDR_LOW_PART_LEN;
		qid_map.global_qid = txrx_queues[i];
		af_res->qid_map_table[qid_map_base + i] = qid_map;
	}

	for (i = 0; i < NBL_QID_MAP_TABLE_ENTRIES; i++) {
		j = 0;

		do {
			wr32_for_each(hw, NBL_PCOMPLETER_QID_MAP_REG_ARR(af_res->qid_map_select, i),
				      (u32 *)(af_res->qid_map_table + i), sizeof(qid_map));
			udelay(5);
			rd32_for_each(hw, NBL_PCOMPLETER_QID_MAP_REG_ARR(af_res->qid_map_select, i),
				      (u32 *)&qid_map, sizeof(qid_map));
			if (likely(!memcmp(&qid_map, af_res->qid_map_table + i, sizeof(qid_map))))
				break;
			j++;
		} while (j < NBL_REG_WRITE_MAX_TRY_TIMES);

		if (j == NBL_REG_WRITE_MAX_TRY_TIMES)
			pr_err("Write to qid map table entry %hhu failed\n", i);
	}

	memset(&queue_table_select, 0, sizeof(queue_table_select));
	queue_table_select.select = af_res->qid_map_select;
	wr32_and_verify(hw, NBL_PCOMPLETER_QUEUE_TABLE_SELECT_REG, *(u32 *)&queue_table_select);
	af_res->qid_map_select = !af_res->qid_map_select;

	if (!af_res->qid_map_ready) {
		memset(&queue_table_ready, 0, sizeof(queue_table_ready));
		queue_table_ready.ready = 1;
		wr32_for_each(hw, NBL_PCOMPLETER_QUEUE_TABLE_READY_REG,
			      (u32 *)&queue_table_ready, sizeof(queue_table_ready));
		af_res->qid_map_ready = 1;
	}

	spin_unlock_irqrestore(&af_res->func_res_lock, flags);
}

static void nbl_af_remove_qid_map_table(struct nbl_hw *hw, u16 func_id, u64 notify_addr)
{
	struct nbl_af_res_info *af_res = hw->af_res;
	struct nbl_func_res *func_res = af_res->res_record[func_id];
	struct nbl_qid_map qid_map;
	struct nbl_qid_map invalid_qid_map;
	struct nbl_queue_table_ready queue_table_ready;
	struct nbl_queue_table_select queue_table_select;
	unsigned long flags;
	u64 key;
	u8 qid_map_entries;
	u8 qid_map_base;
	u8 i;
	u8 j;

	spin_lock_irqsave(&af_res->func_res_lock, flags);

	qid_map_base = NBL_QID_MAP_TABLE_ENTRIES;
	key = notify_addr >> NBL_QID_MAP_NOTIFY_ADDR_SHIFT;
	for (i = 0; i < NBL_QID_MAP_TABLE_ENTRIES; i++) {
		if (key == nbl_get_qid_map_key(af_res->qid_map_table[i])) {
			qid_map_base = i;
			break;
		}
	}

	if (unlikely(qid_map_base == NBL_QID_MAP_TABLE_ENTRIES)) {
		pr_alert("Can not find key corresponding to notify addr %llx\n", notify_addr);
		spin_unlock_irqrestore(&af_res->func_res_lock, flags);
		return;
	}

	qid_map_entries = func_res->num_txrx_queues;
	invalid_qid_map.local_qid = 0x1F;
	invalid_qid_map.notify_addr_l = 0x7FFFFFF;
	invalid_qid_map.notify_addr_h = 0xFFFF;
	invalid_qid_map.global_qid = 0x7F;
	invalid_qid_map.rsv = 0x1FF;
	for (i = qid_map_base; i < NBL_QID_MAP_TABLE_ENTRIES - qid_map_entries; i++)
		af_res->qid_map_table[i] = af_res->qid_map_table[i + qid_map_entries];
	for (; i < NBL_QID_MAP_TABLE_ENTRIES; i++)
		af_res->qid_map_table[i] = invalid_qid_map;

	for (i = 0; i < NBL_QID_MAP_TABLE_ENTRIES; i++) {
		j = 0;

		do {
			wr32_for_each(hw, NBL_PCOMPLETER_QID_MAP_REG_ARR(af_res->qid_map_select, i),
				      (u32 *)(af_res->qid_map_table + i), sizeof(qid_map));
			udelay(5);
			rd32_for_each(hw, NBL_PCOMPLETER_QID_MAP_REG_ARR(af_res->qid_map_select, i),
				      (u32 *)&qid_map, sizeof(qid_map));
			if (likely(!memcmp(&qid_map, af_res->qid_map_table + i, sizeof(qid_map))))
				break;
			j++;
		} while (j < NBL_REG_WRITE_MAX_TRY_TIMES);

		if (j == NBL_REG_WRITE_MAX_TRY_TIMES)
			pr_err("Write to qid map table entry %hhu failed when remove entries\n", i);
	}

	memset(&queue_table_select, 0, sizeof(queue_table_select));
	queue_table_select.select = af_res->qid_map_select;
	wr32_and_verify(hw, NBL_PCOMPLETER_QUEUE_TABLE_SELECT_REG, *(u32 *)&queue_table_select);
	af_res->qid_map_select = !af_res->qid_map_select;

	if (!func_id) {
		WARN_ON(!af_res->qid_map_ready);
		memset(&queue_table_ready, 0, sizeof(queue_table_ready));
		queue_table_ready.ready = 0;
		wr32_for_each(hw, NBL_PCOMPLETER_QUEUE_TABLE_READY_REG,
			      (u32 *)&queue_table_ready, sizeof(queue_table_ready));
		af_res->qid_map_ready = 0;
	}

	spin_unlock_irqrestore(&af_res->func_res_lock, flags);
}

int nbl_af_configure_func_msix_map(struct nbl_hw *hw, u16 func_id, u16 requested)
{
	struct nbl_adapter *adapter = hw->back;
	struct device *dev = &adapter->pdev->dev;
	struct nbl_af_res_info *af_res = hw->af_res;
	struct nbl_func_res *func_res = af_res->res_record[func_id];
	struct nbl_msix_map_table *msix_map_table;
	struct nbl_msix_map *msix_map_entries;
	struct nbl_function_msix_map function_msix_map;
	u16 *interrupts;
	unsigned long flags;
	u16 intr_index;
	u16 i;
	int err;

	msix_map_table = &func_res->msix_map_table;
	msix_map_table->size = sizeof(struct nbl_msix_map) * NBL_MSIX_MAP_TABLE_MAX_ENTRIES;
	msix_map_table->base_addr = dma_alloc_coherent(dev, msix_map_table->size,
						       &msix_map_table->dma,
						       GFP_ATOMIC | __GFP_ZERO);
	if (!msix_map_table->base_addr) {
		msix_map_table->size = 0;
		return -ENOMEM;
	}

	interrupts = kcalloc(requested, sizeof(interrupts[0]), GFP_ATOMIC);
	if (!interrupts) {
		err = -ENOMEM;
		goto alloc_interrupts_err;
	}
	func_res->num_interrupts = requested;
	func_res->interrupts = interrupts;

	spin_lock_irqsave(&af_res->func_res_lock, flags);

	for (i = 0; i < requested; i++) {
		intr_index = find_first_zero_bit(af_res->interrupt_bitmap, NBL_MAX_INTERRUPT);
		if (intr_index == NBL_MAX_INTERRUPT) {
			pr_err("There is no available interrupt left\n");
			err = -EAGAIN;
			goto get_interrupt_err;
		}
		interrupts[i] = intr_index;
		set_bit(intr_index, af_res->interrupt_bitmap);
	}

	spin_unlock_irqrestore(&af_res->func_res_lock, flags);

	msix_map_entries = msix_map_table->base_addr;
	for (i = 0; i < requested; i++) {
		msix_map_entries[i].global_msix_index = interrupts[i];
		msix_map_entries[i].valid = 1;
	}

	function_msix_map.msix_map_base_addr = msix_map_table->dma;
	function_msix_map.function = hw->function;
	function_msix_map.devid = hw->devid;
	function_msix_map.bus = hw->bus;
	function_msix_map.valid = 1;
	wr32_for_each(hw, NBL_PCOMPLETER_FUNCTION_MSIX_MAP_REG_ARR(func_id),
		      (u32 *)&function_msix_map, sizeof(function_msix_map));

	return 0;

get_interrupt_err:
	while (i--) {
		intr_index = interrupts[i];
		clear_bit(intr_index, af_res->interrupt_bitmap);
	}
	spin_unlock_irqrestore(&af_res->func_res_lock, flags);

	kfree(interrupts);
	func_res->num_interrupts = 0;
	func_res->interrupts = NULL;

alloc_interrupts_err:
	dma_free_coherent(dev, msix_map_table->size, msix_map_table->base_addr,
			  msix_map_table->dma);
	msix_map_table->size = 0;
	msix_map_table->base_addr = NULL;
	msix_map_table->dma = 0;

	return err;
}

void nbl_af_destroy_func_msix_map(struct nbl_hw *hw, u16 func_id)
{
	struct nbl_af_res_info *af_res = hw->af_res;
	struct nbl_func_res *func_res = af_res->res_record[func_id];
	struct nbl_function_msix_map function_msix_map;
	struct nbl_msix_map_table *msix_map_table;
	struct device *dev = nbl_hw_to_dev(hw);
	u16 *interrupts;
	u16 intr_num;
	unsigned long flags;
	u16 i;

	memset(&function_msix_map, 0, sizeof(function_msix_map));
	wr32_for_each(hw, NBL_PCOMPLETER_FUNCTION_MSIX_MAP_REG_ARR(func_id),
		      (u32 *)&function_msix_map, sizeof(function_msix_map));

	if (!func_res)
		return;
	/* NOTICE: DMA memory for msix map table is release when AF is removed
	 *         because there is WARN message if it is released when interrupt
	 *         is disabled.
	 */

	intr_num = func_res->num_interrupts;
	interrupts = func_res->interrupts;
	if (!interrupts)
		return;
	spin_lock_irqsave(&af_res->func_res_lock, flags);
	for (i = 0; i < intr_num; i++)
		clear_bit(interrupts[i], af_res->interrupt_bitmap);
	spin_unlock_irqrestore(&af_res->func_res_lock, flags);
	kfree(interrupts);
	func_res->interrupts = NULL;
	func_res->num_interrupts = 0;

	WARN_ON(func_res->txrx_queues);
	msix_map_table = &func_res->msix_map_table;
	WARN_ON(!msix_map_table->base_addr);
	dma_free_coherent(dev, msix_map_table->size, msix_map_table->base_addr,
			  msix_map_table->dma);
	msix_map_table->size = 0;
	msix_map_table->base_addr = NULL;
	msix_map_table->dma = 0;
}

int nbl_configure_msix_map(struct nbl_hw *hw)
{
	struct nbl_adapter *adapter = hw->back;
	int num_cpus;
	int needed;
	int err;

	num_cpus = num_online_cpus();
	needed = num_cpus > adapter->num_rxq ? adapter->num_rxq : num_cpus;
	if (needed <= 0 || needed > U16_MAX - 1) {
		pr_err("There are %d cpus online and %d rx queue(s), which is invalid\n",
		       num_cpus, adapter->num_rxq);
		return -EINVAL;
	}

	adapter->num_lan_msix = (u16)needed;
	adapter->num_q_vectors = adapter->num_lan_msix;

	adapter->num_mailbox_msix = 1;
	needed += 1;

	if (is_af(hw)) {
		/* An additional interrupt is used by AF protocol packet
		 * such as ARP packet forward queue.
		 */
		needed += 1;
		err = nbl_af_configure_func_msix_map(hw, 0, (u16)needed);
		if (err) {
			pr_err("AF configure function msix map table failed\n");
			goto err_out;
		}
	} else {
		err = nbl_mailbox_req_cfg_msix_map_table(hw, (u16)needed);
		if (err) {
			pr_err("PF %u configure function msix map table failed\n", hw->function);
			goto err_out;
		}
	}

	return 0;

err_out:
	adapter->num_lan_msix = 0;
	adapter->num_q_vectors = 0;
	adapter->num_mailbox_msix = 0;
	return err;
}

void nbl_destroy_msix_map(struct nbl_hw *hw)
{
	if (is_af(hw))
		nbl_af_destroy_func_msix_map(hw, 0);
	else
		nbl_mailbox_req_destroy_msix_map_table(hw);
}

int nbl_af_configure_qid_map(struct nbl_hw *hw, u16 func_id, u8 num_queues, u64 notify_addr)
{
	struct nbl_af_res_info *af_res = hw->af_res;
	struct nbl_func_res *func_res = af_res->res_record[func_id];
	unsigned long flags;
	u8 queue_index;
	u8 *txrx_queues;
	u8 i;
	int err;

	WARN_ON(!func_res || func_res->num_txrx_queues);

	txrx_queues = kcalloc(num_queues, sizeof(txrx_queues[0]), GFP_ATOMIC);
	if (!txrx_queues)
		return -ENOMEM;
	func_res->num_txrx_queues = num_queues;
	func_res->txrx_queues = txrx_queues;

	spin_lock_irqsave(&af_res->func_res_lock, flags);

	for (i = 0; i < num_queues; i++) {
		queue_index = find_first_zero_bit(af_res->txrx_queue_bitmap, NBL_MAX_TXRX_QUEUE);
		if (queue_index == NBL_MAX_TXRX_QUEUE) {
			pr_err("There is no available txrx queues left\n");
			err = -EAGAIN;
			goto get_txrx_queue_err;
		}
		txrx_queues[i] = queue_index;
		set_bit(queue_index, af_res->txrx_queue_bitmap);
	}

	spin_unlock_irqrestore(&af_res->func_res_lock, flags);

	nbl_af_fill_qid_map_table(hw, func_id, notify_addr);

	return 0;

get_txrx_queue_err:
	while (i--) {
		queue_index = txrx_queues[i];
		clear_bit(queue_index, af_res->txrx_queue_bitmap);
	}
	spin_unlock_irqrestore(&af_res->func_res_lock, flags);

	kfree(txrx_queues);
	func_res->num_txrx_queues = 0;
	func_res->txrx_queues = NULL;

	return err;
}

void nbl_af_clear_qid_map(struct nbl_hw *hw, u16 func_id, u64 notify_addr)
{
	struct nbl_af_res_info *af_res = hw->af_res;
	struct nbl_func_res *func_res = af_res->res_record[func_id];
	unsigned long flags;
	u8 queue_index;
	u8 num_queues;
	u8 *txrx_queues;
	u8 i;

	WARN_ON(!func_res || !func_res->num_txrx_queues);

	nbl_af_remove_qid_map_table(hw, func_id, notify_addr);

	num_queues = func_res->num_txrx_queues;
	txrx_queues = func_res->txrx_queues;
	spin_lock_irqsave(&af_res->func_res_lock, flags);
	for (i = 0; i < num_queues; i++) {
		queue_index = txrx_queues[i];
		clear_bit(queue_index, af_res->txrx_queue_bitmap);
	}
	spin_unlock_irqrestore(&af_res->func_res_lock, flags);

	kfree(txrx_queues);
	func_res->txrx_queues = NULL;
	func_res->num_txrx_queues = 0;
}

static u64 nbl_read_real_bar_base_addr(struct pci_dev *pdev)
{
	u32 val;
	u64 addr;

	pci_read_config_dword(pdev, PCI_BASE_ADDRESS_0, &val);
	addr = (u64)(val & PCI_BASE_ADDRESS_MEM_MASK);

	pci_read_config_dword(pdev, PCI_BASE_ADDRESS_0 + 4, &val);
	addr |= ((u64)val << 32);

	return addr;
}

int nbl_get_vsi_id(struct nbl_hw *hw)
{
	int err;

	if (!is_vf(hw)) {
		hw->vsi_id = hw->function;
	} else {
		err = nbl_mailbox_req_get_vsi_id(hw);
		if (err < 0) {
			pr_err("Get vsi id failed with error %d\n", err);
			return err;
		}
		hw->vsi_id = (u8)(unsigned int)err;
	}

	return 0;
}

#ifdef CONFIG_PCI_IOV
static u64 nbl_read_real_vf_bar_base_addr(struct pci_dev *pdev)
{
	int pos;
	u32 val;
	u64 addr;

	pos = pci_find_ext_capability(pdev, PCI_EXT_CAP_ID_SRIOV);
	pci_read_config_dword(pdev, pos + PCI_SRIOV_BAR, &val);
	addr = (u64)(val & PCI_BASE_ADDRESS_MEM_MASK);

	pci_read_config_dword(pdev, pos + PCI_SRIOV_BAR + 4, &val);
	addr |= ((u64)val << 32);

	return addr;
}
#endif

void nbl_af_register_vf_bar_info(struct nbl_hw *hw, u16 func_id,
				 u64 vf_bar_start, u64 vf_bar_len)
{
	struct nbl_af_res_info *af_res = hw->af_res;

	af_res->vf_bar_info[func_id].vf_bar_start = vf_bar_start;
	af_res->vf_bar_info[func_id].vf_bar_len = vf_bar_len;
}

#ifdef CONFIG_PCI_IOV
int nbl_register_vf_bar_info(struct nbl_hw *hw)
{
	struct nbl_adapter *adapter;
	struct pci_dev *pdev;
	u64 vf_bar_len;
	u64 vf_bar_start;
	struct resource *res;
	int err = 0;

	if (is_vf(hw))
		return 0;

	adapter = hw->back;
	pdev = adapter->pdev;

	vf_bar_start = nbl_read_real_vf_bar_base_addr(pdev);
	res = &pdev->resource[PCI_IOV_RESOURCES];
	vf_bar_len = resource_size(res) / NBL_MAX_VF_PER_PF;
	if (is_af(hw))
		nbl_af_register_vf_bar_info(hw, 0, vf_bar_start, vf_bar_len);
	else
		err = nbl_mailbox_req_register_vf_bar_info(hw, vf_bar_start, vf_bar_len);

	return err;
}
#else
int nbl_register_vf_bar_info(struct nbl_hw *hw)
{
	return 0;
}
#endif

u64 nbl_af_compute_vf_bar_base_addr(struct nbl_hw *hw, u16 func_id)
{
	struct nbl_af_res_info *af_res = hw->af_res;
	struct nbl_vf_bar_info *vf_bar_info;
	u8 pf_func_id;
	u8 vf_offset;
	u64 base_addr;

	WARN_ON(func_id < NBL_MAX_PF_FUNC);
	pf_func_id = (func_id - NBL_MAX_PF_FUNC) / NBL_MAX_VF_PER_PF;
	vf_offset = (func_id - NBL_MAX_PF_FUNC) % NBL_MAX_VF_PER_PF;
	vf_bar_info = &af_res->vf_bar_info[pf_func_id];
	base_addr = vf_bar_info->vf_bar_start + vf_bar_info->vf_bar_len * vf_offset;

	return base_addr;
}

int nbl_configure_notify_addr(struct nbl_hw *hw)
{
	struct nbl_adapter *adapter;
	struct pci_dev *pdev;
	u64 real_addr;
	u64 notify_addr;
	u8 num_txq;
	u8 num_rxq;
	int err = 0;

	adapter = hw->back;
	pdev = adapter->pdev;
	num_txq = adapter->num_txq;
	num_rxq = adapter->num_rxq;
	if (num_txq != num_rxq) {
		pr_err("The number of TX queues must equal to RX queues\n");
		return -EINVAL;
	}

	if (!is_vf(hw))
		real_addr = nbl_read_real_bar_base_addr(pdev);
	else
		err = nbl_mailbox_req_get_vf_bar_base_addr(hw, &real_addr);

	if (err) {
		pr_err("Get VF BAR base address failed with error %d\n", err);
		return err;
	}

	if (is_af(hw)) {
		notify_addr = real_addr + NBL_PCOMPLETER_AF_NOTIFY_REG;
		if (real_addr <= U32_MAX && notify_addr > U32_MAX)
			pr_warn("Maybe we can not successfully kick the doorbell\n");
		/* AF have an additional queue used for
		 * protocol packet forwarding.
		 */
		num_rxq += 1;
		err = nbl_af_configure_qid_map(hw, 0, num_rxq, notify_addr);
	} else {
		notify_addr = real_addr;
		err = nbl_mailbox_req_cfg_qid_map(hw, num_rxq, notify_addr);
	}

	return err;
}

void nbl_clear_notify_addr(struct nbl_hw *hw)
{
	struct nbl_adapter *adapter;
	struct pci_dev *pdev;
	u64 real_addr;
	u64 notify_addr;
	int err = 0;

	adapter = hw->back;
	pdev = adapter->pdev;
	if (!is_vf(hw))
		real_addr = nbl_read_real_bar_base_addr(pdev);
	else
		err = nbl_mailbox_req_get_vf_bar_base_addr(hw, &real_addr);

	if (err) {
		pr_err("Failed to get VF BAR base address when clear notify address\n");
		return;
	}

	if (is_af(hw)) {
		notify_addr = real_addr + NBL_PCOMPLETER_AF_NOTIFY_REG;
		nbl_af_clear_qid_map(hw, 0, notify_addr);
	} else {
		notify_addr = real_addr;
		nbl_mailbox_req_clear_qid_map(hw, notify_addr);
	}
}

void nbl_af_enable_promisc(struct nbl_hw *hw, u8 eth_port_id)
{
	struct nbl_pro_ctrl ctrl;

	rd32_for_each(hw, NBL_PRO_CTRL_REG, (u32 *)&ctrl, sizeof(ctrl));
	ctrl.mac_mismatch_drop_en &= ~BIT(eth_port_id);
	wr32_for_each(hw, NBL_PRO_CTRL_REG, (u32 *)&ctrl, sizeof(ctrl));
}

void nbl_af_disable_promisc(struct nbl_hw *hw, u8 eth_port_id)
{
	struct nbl_pro_ctrl ctrl;

	rd32_for_each(hw, NBL_PRO_CTRL_REG, (u32 *)&ctrl, sizeof(ctrl));
	ctrl.mac_mismatch_drop_en |= BIT(eth_port_id);
	wr32_for_each(hw, NBL_PRO_CTRL_REG, (u32 *)&ctrl, sizeof(ctrl));
}

void nbl_enable_promisc(struct nbl_hw *hw)
{
	struct nbl_adapter *adapter = hw->back;
	u8 eth_port_id = hw->eth_port_id;

	if (is_vf(hw)) {
		pr_info("VF is not allowed to set promiscuous mode\n");
		return;
	}

	if (test_and_set_bit(NBL_PROMISC, adapter->state))
		return;

	if (is_af(hw))
		nbl_af_enable_promisc(hw, eth_port_id);
	else
		nbl_mailbox_req_enable_promisc(hw, eth_port_id);
}

void nbl_disable_promisc(struct nbl_hw *hw)
{
	struct nbl_adapter *adapter = hw->back;
	u8 eth_port_id = hw->eth_port_id;

	if (is_vf(hw)) {
		pr_info("VF is not allowed to set promiscuous mode\n");
		return;
	}

	if (!test_and_clear_bit(NBL_PROMISC, adapter->state))
		return;

	if (is_af(hw))
		nbl_af_disable_promisc(hw, eth_port_id);
	else
		nbl_mailbox_req_disable_promisc(hw, eth_port_id);
}

void nbl_af_configure_ingress_eth_port_table(struct nbl_hw *hw, u8 eth_port_id, u8 vsi_id)
{
	struct nbl_ingress_eth_port port_config;
	struct nbl_ingress_eth_port_fwd port_fwd_config;
	u32 reg;

	memset(&port_config, 0, sizeof(port_config));

	port_config.default_vlan_en = 1;
	port_config.default_vlanid = 0;

	port_config.vlan_check_en = 0;

	port_config.lag = 0;

	port_config.cos_map_mode = NBL_COS_MODE_DEFAULT_ETH_PRI;
	port_config.default_pri = 7;

	port_config.veb_num = eth_port_id;

	reg = NBL_PRO_INGRESS_ETH_PORT_REG_ARR(eth_port_id);
	wr32_for_each(hw, reg, (u32 *)&port_config, sizeof(port_config));

	memset(&port_fwd_config, 0, sizeof(port_fwd_config));

	port_fwd_config.dport = NBL_PORT_HOST;
	port_fwd_config.dport_id = vsi_id;
	port_fwd_config.fwd = NBL_INGRESS_FWD_NORMAL;

	reg = NBL_PRO_INGRESS_ETH_PORT_FWD_REG_ARR(eth_port_id);
	wr32_for_each(hw, reg, (u32 *)&port_fwd_config, sizeof(port_fwd_config));
}

static void nbl_configure_ingress_eth_port_table(struct nbl_hw *hw)
{
	if (is_af(hw))
		nbl_af_configure_ingress_eth_port_table(hw, hw->eth_port_id, hw->vsi_id);
	else
		nbl_mailbox_req_cfg_ingress_eth_port_table(hw, hw->eth_port_id, hw->vsi_id);
}

static void nbl_configure_egress_eth_port_table(struct nbl_hw __maybe_unused *hw)
{
}

static void nbl_configure_eth_port_table(struct nbl_hw *hw)
{
	if (is_vf(hw))
		return;

	nbl_configure_ingress_eth_port_table(hw);
	nbl_configure_egress_eth_port_table(hw);
}

void nbl_af_configure_src_vsi_table(struct nbl_hw *hw, u8 eth_port_id, u8 vsi_id)
{
	struct nbl_af_res_info *af_res = hw->af_res;
	u8 forward_ring_index = af_res->forward_ring_index;
	struct nbl_src_vsi_port src_vsi_port_config;

	memset(&src_vsi_port_config, 0, sizeof(src_vsi_port_config));

	src_vsi_port_config.default_vlanid = 0;

	src_vsi_port_config.vlan_check_en = 0;

	src_vsi_port_config.cos_map_mode = NBL_SRC_VSI_COS_MODE_DEFAULT_PORT_PRI;
	src_vsi_port_config.default_pri = 7;

	if (vsi_id < NBL_MAX_PF_FUNC) {
		src_vsi_port_config.mac_lut_en = 0;
	} else {
		src_vsi_port_config.mac_lut_en = 1;
		src_vsi_port_config.forward_queue_id_en = 1;
		src_vsi_port_config.forward_queue_id = forward_ring_index;
	}

	src_vsi_port_config.lag = 0;
	src_vsi_port_config.dport_id = eth_port_id;

	src_vsi_port_config.default_vlan_en = 1;

	src_vsi_port_config.vlan_push_en = 0;

	src_vsi_port_config.veb_num = eth_port_id;

	src_vsi_port_config.catch_vsi_idx = vsi_id;

	src_vsi_port_config.vlanid_match_en = 0;

	src_vsi_port_config.smac_match_en = 0;

	wr32_for_each(hw, NBL_PRO_SRC_VSI_PORT_REG_ARR(vsi_id),
		      (u32 *)&src_vsi_port_config, sizeof(src_vsi_port_config));
}

static void nbl_configure_src_vsi_table(struct nbl_hw *hw)
{
	if (is_af(hw))
		nbl_af_configure_src_vsi_table(hw, hw->eth_port_id, hw->vsi_id);
	else
		nbl_mailbox_req_cfg_src_vsi_table(hw, hw->eth_port_id, hw->vsi_id);
}

void nbl_af_configure_dest_vsi_table(struct nbl_hw *hw, u8 eth_port_id, u8 vsi_id)
{
	struct nbl_dest_vsi_port dest_vsi_port_config;

	memset(&dest_vsi_port_config, 0, sizeof(dest_vsi_port_config));

	dest_vsi_port_config.vlan_push_cnt = 0;

	dest_vsi_port_config.vsi_en = 1;

	dest_vsi_port_config.pkt_len_chk_en = 0;

	dest_vsi_port_config.pf_id = eth_port_id;

	wr32_for_each(hw, NBL_PRO_DEST_VSI_PORT_REG_ARR(vsi_id),
		      (u32 *)&dest_vsi_port_config, sizeof(dest_vsi_port_config));
}

static void nbl_configure_dest_vsi_table(struct nbl_hw *hw)
{
	if (is_af(hw))
		nbl_af_configure_dest_vsi_table(hw, hw->eth_port_id, hw->vsi_id);
	else
		nbl_mailbox_req_cfg_dest_vsi_table(hw, hw->eth_port_id, hw->vsi_id);
}

static void nbl_configure_vsi_table(struct nbl_hw *hw)
{
	nbl_configure_src_vsi_table(hw);
	nbl_configure_dest_vsi_table(hw);
}

void nbl_datapath_init(struct nbl_hw *hw)
{
	struct nbl_adapter *adapter = hw->back;

	set_bit(NBL_PROMISC, adapter->state);
	nbl_disable_promisc(hw);

	nbl_configure_eth_port_table(hw);

	nbl_configure_vsi_table(hw);
}

bool nbl_af_query_link_status(struct nbl_hw *hw, u8 eth_port_id)
{
	struct device *dev = nbl_hw_to_dev(hw);
	struct nbl_loopback_mode loopback_mode;
	struct nbl_eth_rx_stat rx_stat;
	enum nbl_eth_speed_mode selected_speed;
	enum nbl_eth_speed_mode current_speed;
	bool link_up;

	rd32_for_each(hw, NBL_ETH_LOOPBACK_MODE_REG(eth_port_id),
		      (u32 *)&loopback_mode, sizeof(loopback_mode));
	selected_speed = loopback_mode.speed_sel;
	current_speed = loopback_mode.speed_stat;
	if (selected_speed != current_speed) {
		dev_info(dev, "Selected speed %u doest not match current speed %u\n",
			 selected_speed, current_speed);
		return false;
	}
	if (selected_speed == NBL_ETH_SPEED_MODE_25G) {
		dev_info(dev, "25GE speed is not supported\n");
		return false;
	}

	rd32_for_each(hw, NBL_ETH_RX_STAT_REG(eth_port_id), (u32 *)&rx_stat,
		      sizeof(rx_stat));
	if (selected_speed == NBL_ETH_SPEED_MODE_10G)
		link_up = !!rx_stat.rx_status;
	else
		link_up = !!(rx_stat.ge_pcs_pma_status &
			     (1 << NBL_GE_PCS_PMA_LINK_STATUS_SHIFT));

	return link_up;
}

bool nbl_query_link_status(struct nbl_hw *hw)
{
	bool link_up;

	if (is_af(hw))
		link_up = nbl_af_query_link_status(hw, hw->eth_port_id);
	else
		link_up = nbl_mailbox_req_query_link_status(hw, hw->eth_port_id);

	return link_up;
}

void nbl_query_link_status_subtask(struct nbl_adapter *adapter)
{
	struct nbl_hw *hw = &adapter->hw;
	struct net_device *netdev = adapter->netdev;
	bool link_up;

	if (test_bit(NBL_DOWN, adapter->state))
		return;

	link_up = nbl_query_link_status(hw);
	if (link_up == netif_carrier_ok(netdev))
		return;
	if (link_up)
		netif_carrier_on(netdev);
	else
		netif_carrier_off(netdev);
}

void nbl_af_init_pkt_len_limit(struct nbl_hw *hw, u8 eth_port_id,
			       struct nbl_pkt_len_limit pkt_len_limit)
{
	wr32_for_each(hw, NBL_ETH_PKT_LEN_LIMIT(eth_port_id),
		      (u32 *)&pkt_len_limit, sizeof(pkt_len_limit));
}

static void nbl_set_pkt_max_limit(struct nbl_hw *hw)
{
	wr32(hw, NBL_PRO_MAX_PKT_LEN_REG, NBL_URMUX_MAX_PKT_LEN);
	wr32(hw, NBL_URMUX_PRO_MAX_PKT_KEN_REG, NBL_URMUX_MAX_PKT_LEN);
	wr32(hw, NBL_URMUX_CFG_SYNC_REG, 0);
	wr32(hw, NBL_URMUX_CFG_SYNC_REG, 1);
}

void nbl_init_pkt_len_limit(struct nbl_hw *hw)
{
	struct nbl_pkt_len_limit pkt_len_limit = { 0 };

	if (is_vf(hw))
		return;

	pkt_len_limit.max_pkt_len = NBL_MAX_FRAME_SIZE;
	pkt_len_limit.min_pkt_len = NBL_MIN_FRAME_SIZE;
	if (is_af(hw)) {
		nbl_af_init_pkt_len_limit(hw, hw->eth_port_id, pkt_len_limit);
		nbl_set_pkt_max_limit(hw);
	} else {
		nbl_mailbox_req_init_pkt_len_limit(hw, hw->eth_port_id, pkt_len_limit);
	}
}

int nbl_af_get_eth_stats(struct nbl_hw *hw, u8 eth_port_id, struct nbl_hw_stats *hw_stats)
{
	u64 value_low;
	u64 value_high;
	int i;
	struct nbl_eth_reset_ctl_and_status eth_reset;

	for (i = 0; i < 3; i++) {
		rd32_for_each(hw, NBL_ETH_RESET_REG(eth_port_id), (u32 *)&eth_reset,
			      sizeof(struct nbl_eth_reset_ctl_and_status));
		if (eth_reset.eth_statistics_vld == 1)
			break;
		usleep_range(100000, 200000);
	}

	if (i == 3) {
		pr_warn("port %d wait statistics_vld timed out\n", eth_port_id);
		return -ETIMEDOUT;
	}

	value_low = rd32(hw, NBL_PED_ETH_PAUSE_TX_L_REG(eth_port_id));
	value_high = rd32(hw, NBL_PED_ETH_PAUSE_TX_H_REG(eth_port_id)) & 0xFFFF;
	hw_stats->tx_fc_pause = (value_high << 32) + value_low;

	value_low = rd32(hw, NBL_ETH_TX_FRAME_ERROR_CNT_L_REG(eth_port_id));
	value_high = rd32(hw, NBL_ETH_TX_FRAME_ERROR_CNT_H_REG(eth_port_id)) & 0xFFFF;
	hw_stats->tx_frame_error = (value_high << 32) + value_low;

	value_low = rd32(hw, NBL_ETH_TX_TOTAL_GOOD_PKT_CNT_L_REG(eth_port_id));
	value_high = rd32(hw, NBL_ETH_TX_TOTAL_GOOD_PKT_CNT_H_REG(eth_port_id)) & 0xFFFF;
	hw_stats->tx_total_good_packets = (value_high << 32) + value_low;

	value_low = rd32(hw, NBL_ETH_TX_TOTAL_GOOD_BYTES_CNT_L_REG(eth_port_id));
	value_high = rd32(hw, NBL_ETH_TX_TOTAL_GOOD_BYTES_CNT_H_REG(eth_port_id)) & 0xFFFF;
	hw_stats->tx_total_good_bytes = (value_high << 32) + value_low;

	value_low = rd32(hw, NBL_ETH_TX_BAD_FCS_CNT_L_REG(eth_port_id));
	value_high = rd32(hw, NBL_ETH_TX_BAD_FCS_CNT_H_REG(eth_port_id)) & 0xFFFF;
	hw_stats->tx_bad_fcs = (value_high << 32) + value_low;

	value_low = rd32(hw, NBL_ETH_TX_UNICAST_CNT_L_REG(eth_port_id));
	value_high = rd32(hw, NBL_ETH_TX_UNICAST_CNT_H_REG(eth_port_id)) & 0xFFFF;
	hw_stats->tx_unicast = (value_high << 32) + value_low;

	value_low = rd32(hw, NBL_ETH_TX_MULTICAST_CNT_L_REG(eth_port_id));
	value_high = rd32(hw, NBL_ETH_TX_MULTICAST_CNT_H_REG(eth_port_id)) & 0xFFFF;
	hw_stats->tx_multicast = (value_high << 32) + value_low;

	value_low = rd32(hw, NBL_ETH_TX_BROADCAST_CNT_L_REG(eth_port_id));
	value_high = rd32(hw, NBL_ETH_TX_BROADCAST_CNT_H_REG(eth_port_id)) & 0xFFFF;
	hw_stats->tx_broadcast = (value_high << 32) + value_low;

	value_low = rd32(hw, NBL_ETH_TX_VLAN_CNT_L_REG(eth_port_id));
	value_high = rd32(hw, NBL_ETH_TX_VLAN_CNT_H_REG(eth_port_id)) & 0xFFFF;
	hw_stats->tx_vlan = (value_high << 32) + value_low;

	/* read total stats lastly, ensure total stats is bigger than others */
	value_low = rd32(hw, NBL_ETH_TX_TOTAL_PKT_CNT_L_REG(eth_port_id));
	value_high = rd32(hw, NBL_ETH_TX_TOTAL_PKT_CNT_H_REG(eth_port_id)) & 0xFFFF;
	hw_stats->tx_total_packets = (value_high << 32) + value_low;

	value_low = rd32(hw, NBL_ETH_TX_TOTAL_BYTES_CNT_L_REG(eth_port_id));
	value_high = rd32(hw, NBL_ETH_TX_TOTAL_BYTES_CNT_H_REG(eth_port_id)) & 0xFFFF;
	hw_stats->tx_total_bytes = (value_high << 32) + value_low;

	value_low = rd32(hw, NBL_PA_ETH_PAUSE_RX_L_REG(eth_port_id));
	value_high = rd32(hw, NBL_PA_ETH_PAUSE_RX_H_REG(eth_port_id)) & 0xFFFF;
	hw_stats->rx_fc_pause = (value_high << 32) + value_low;

	value_low = rd32(hw, NBL_ETH_RX_BADCODE_CNT_L_REG(eth_port_id));
	value_high = rd32(hw, NBL_ETH_RX_BADCODE_CNT_H_REG(eth_port_id)) & 0xFFFF;
	hw_stats->rx_bad_code = (value_high << 32) + value_low;

	value_low = rd32(hw, NBL_ETH_RX_TOTAL_GOOD_PKT_CNT_L_REG(eth_port_id));
	value_high = rd32(hw, NBL_ETH_RX_TOTAL_GOOD_PKT_CNT_H_REG(eth_port_id)) & 0xFFFF;
	hw_stats->rx_total_good_packets = (value_high << 32) + value_low;

	value_low = rd32(hw, NBL_ETH_RX_TOTAL_GOOD_BYTES_CNT_L_REG(eth_port_id));
	value_high = rd32(hw, NBL_ETH_RX_TOTAL_GOOD_BYTES_CNT_H_REG(eth_port_id)) & 0xFFFF;
	hw_stats->rx_total_good_bytes = (value_high << 32) + value_low;

	value_low = rd32(hw, NBL_ETH_RX_BAD_FCS_CNT_L_REG(eth_port_id));
	value_high = rd32(hw, NBL_ETH_RX_BAD_FCS_CNT_H_REG(eth_port_id)) & 0xFFFF;
	hw_stats->rx_bad_fcs = (value_high << 32) + value_low;

	value_low = rd32(hw, NBL_ETH_RX_FRAMING_ERR_CNT_L_REG(eth_port_id));
	value_high = rd32(hw, NBL_ETH_RX_FRAMING_ERR_CNT_H_REG(eth_port_id)) & 0xFFFF;
	hw_stats->rx_frame_err = (value_high << 32) + value_low;

	value_low = rd32(hw, NBL_ETH_RX_UNICAST_CNT_L_REG(eth_port_id));
	value_high = rd32(hw, NBL_ETH_RX_UNICAST_CNT_H_REG(eth_port_id)) & 0xFFFF;
	hw_stats->rx_unicast = (value_high << 32) + value_low;

	value_low = rd32(hw, NBL_ETH_RX_MULTICAST_CNT_L_REG(eth_port_id));
	value_high = rd32(hw, NBL_ETH_RX_MULTICAST_CNT_H_REG(eth_port_id)) & 0xFFFF;
	hw_stats->rx_multicast = (value_high << 32) + value_low;

	value_low = rd32(hw, NBL_ETH_RX_BROADCAST_CNT_L_REG(eth_port_id));
	value_high = rd32(hw, NBL_ETH_RX_BROADCAST_CNT_H_REG(eth_port_id)) & 0xFFFF;
	hw_stats->rx_broadcast = (value_high << 32) + value_low;

	value_low = rd32(hw, NBL_ETH_RX_VLAN_CNT_L_REG(eth_port_id));
	value_high = rd32(hw, NBL_ETH_RX_VLAN_CNT_H_REG(eth_port_id)) & 0xFFFF;
	hw_stats->rx_vlan = (value_high << 32) + value_low;

	/* read total stats lastly, ensure total stats is bigger than others */
	value_low = rd32(hw, NBL_ETH_RX_TOTAL_PKT_CNT_L_REG(eth_port_id));
	value_high = rd32(hw, NBL_ETH_RX_TOTAL_PKT_CNT_H_REG(eth_port_id)) & 0xFFFF;
	hw_stats->rx_total_packets = (value_high << 32) + value_low;

	value_low = rd32(hw, NBL_ETH_RX_TOTAL_BYTES_CNT_L_REG(eth_port_id));
	value_high = rd32(hw, NBL_ETH_RX_TOTAL_BYTES_CNT_H_REG(eth_port_id)) & 0xFFFF;
	hw_stats->rx_total_bytes = (value_high << 32) + value_low;

	value_low = rd32(hw, NBL_ETH_RX_OVERSIZE_CNT_L_REG(eth_port_id));
	value_high = rd32(hw, NBL_ETH_RX_OVERSIZE_CNT_H_REG(eth_port_id)) & 0xFFFF;
	hw_stats->rx_oversize = (value_high << 32) + value_low;

	value_low = rd32(hw, NBL_ETH_RX_UNDERSIZE_CNT_L_REG(eth_port_id));
	value_high = rd32(hw, NBL_ETH_RX_UNDERSIZE_CNT_H_REG(eth_port_id)) & 0xFFFF;
	hw_stats->rx_undersize = (value_high << 32) + value_low;

	return 0;
}

static inline u64 dec_compare48(struct nbl_hw *hw, u64 a, u64 b, char *reg)
{
	if (a >= b)
		return (a - b);

	pr_info("Dec compare overflow correction, port: %d, reg: %s\n",
		hw->eth_port_id, reg);
	return (BIT_ULL(48) - b + a);
}

static void nbl_correct_eth_stat(struct nbl_hw *hw, u64 *old, u64 *new, char *reg)
{
	u64 value;

	value = *new;
	if (((value & 0xFFFFFFFF) == 0xDEADBEEF) || ((value & 0xFFFF00000000) == 0xBEEF00000000)) {
		pr_warn("ETH port %d maybe read abnormal value %llx from reg %s\n", hw->eth_port_id,
			*new, reg);
		*new = *old;
	}
}

static void nbl_correct_eth_stats(struct nbl_hw *hw, struct nbl_hw_stats *hw_stats)
{
	nbl_correct_eth_stat(hw, &hw->hw_stats.tx_total_packets, &hw_stats->tx_total_packets,
			     "tx_total_packets");
	nbl_correct_eth_stat(hw, &hw->hw_stats.tx_total_good_packets,
			     &hw_stats->tx_total_good_packets,
			     "tx_total_good_packets");
	nbl_correct_eth_stat(hw, &hw->hw_stats.rx_total_packets, &hw_stats->rx_total_packets,
			     "rx_total_packets");
	nbl_correct_eth_stat(hw, &hw->hw_stats.rx_total_good_packets,
			     &hw_stats->rx_total_good_packets,
			     "rx_total_good_packets");
	nbl_correct_eth_stat(hw, &hw->hw_stats.tx_bad_fcs, &hw_stats->tx_bad_fcs,
			     "tx_bad_fcs");
	nbl_correct_eth_stat(hw, &hw->hw_stats.rx_bad_fcs, &hw_stats->rx_bad_fcs,
			     "rx_bad_fcs");

	nbl_correct_eth_stat(hw, &hw->hw_stats.tx_total_bytes, &hw_stats->tx_total_bytes,
			     "tx_total_bytes");
	nbl_correct_eth_stat(hw, &hw->hw_stats.tx_total_good_bytes, &hw_stats->tx_total_good_bytes,
			     "tx_total_good_bytes");
	nbl_correct_eth_stat(hw, &hw->hw_stats.rx_total_bytes, &hw_stats->rx_total_bytes,
			     "rx_total_bytes");
	nbl_correct_eth_stat(hw, &hw->hw_stats.rx_total_good_bytes, &hw_stats->rx_total_good_bytes,
			     "rx_total_good_bytes");

	nbl_correct_eth_stat(hw, &hw->hw_stats.tx_frame_error, &hw_stats->tx_frame_error,
			     "tx_frame_error");
	nbl_correct_eth_stat(hw, &hw->hw_stats.tx_unicast, &hw_stats->tx_unicast,
			     "tx_unicast");
	nbl_correct_eth_stat(hw, &hw->hw_stats.tx_multicast, &hw_stats->tx_multicast,
			     "tx_multicast");
	nbl_correct_eth_stat(hw, &hw->hw_stats.tx_broadcast, &hw_stats->tx_broadcast,
			     "tx_broadcast");
	nbl_correct_eth_stat(hw, &hw->hw_stats.tx_vlan, &hw_stats->tx_vlan,
			     "tx_vlan");
	nbl_correct_eth_stat(hw, &hw->hw_stats.tx_fc_pause, &hw_stats->tx_fc_pause,
			     "tx_fc_pause");

	nbl_correct_eth_stat(hw, &hw->hw_stats.rx_oversize, &hw_stats->rx_oversize,
			     "rx_oversize");
	nbl_correct_eth_stat(hw, &hw->hw_stats.rx_undersize, &hw_stats->rx_undersize,
			     "rx_undersize");
	nbl_correct_eth_stat(hw, &hw->hw_stats.rx_frame_err, &hw_stats->rx_frame_err,
			     "rx_frame_err");
	nbl_correct_eth_stat(hw, &hw->hw_stats.rx_bad_code, &hw_stats->rx_bad_code,
			     "rx_bad_code");
	nbl_correct_eth_stat(hw, &hw->hw_stats.rx_unicast, &hw_stats->rx_unicast,
			     "rx_unicast");
	nbl_correct_eth_stat(hw, &hw->hw_stats.rx_multicast, &hw_stats->rx_multicast,
			     "rx_multicast");
	nbl_correct_eth_stat(hw, &hw->hw_stats.rx_broadcast, &hw_stats->rx_broadcast,
			     "rx_broadcast");
	nbl_correct_eth_stat(hw, &hw->hw_stats.rx_vlan, &hw_stats->rx_vlan,
			     "rx_vlan");
	nbl_correct_eth_stat(hw, &hw->hw_stats.rx_fc_pause, &hw_stats->rx_fc_pause,
			     "rx_fc_pause");
}

void nbl_update_stats_subtask(struct nbl_adapter *adapter)
{
	struct nbl_hw *hw = &adapter->hw;
	struct nbl_hw_stats hw_stats;
	struct net_device *netdev = adapter->netdev;
	struct nbl_ring *ring;
	u8 ring_count;
	u8 ring_index;
	u64 tx_busy, tx_linearize, tx_dma_err;
	u64 tx_csum_pkts = 0, rx_csum_pkts = 0;
	u64 alloc_page_failed;
	u64 alloc_skb_failed;
	u64 rx_dma_err;
	int ret;

	if (test_bit(NBL_DOWN, adapter->state) ||
	    test_bit(NBL_RESETTING, adapter->state))
		return;

	if (is_af(hw))
		ret = nbl_af_get_eth_stats(hw, hw->eth_port_id, &hw_stats);
	else
		ret = nbl_mailbox_req_get_eth_stats(hw, hw->eth_port_id, &hw_stats);

	if (ret < 0)
		memcpy(&hw_stats, &hw->hw_stats, sizeof(hw_stats));
	else
		nbl_correct_eth_stats(hw, &hw_stats);

	mutex_lock(&adapter->stats.lock);
	adapter->stats.tx_total_packets += dec_compare48(hw, hw_stats.tx_total_packets,
							 hw->hw_stats.tx_total_packets,
							 "tx_total_packets");
	adapter->stats.tx_total_good_packets += dec_compare48(hw, hw_stats.tx_total_good_packets,
							      hw->hw_stats.tx_total_good_packets,
							      "tx_total_good_packets");
	adapter->stats.tx_bad_fcs += dec_compare48(hw, hw_stats.tx_bad_fcs,
						   hw->hw_stats.tx_bad_fcs,
						   "tx_bad_fcs");
	adapter->stats.tx_total_bytes += dec_compare48(hw, hw_stats.tx_total_bytes,
						       hw->hw_stats.tx_total_bytes,
						       "tx_total_bytes");
	adapter->stats.tx_total_good_bytes += dec_compare48(hw, hw_stats.tx_total_good_bytes,
							    hw->hw_stats.tx_total_good_bytes,
							    "tx_total_good_bytes");
	adapter->stats.tx_frame_error += dec_compare48(hw, hw_stats.tx_frame_error,
						       hw->hw_stats.tx_frame_error,
						       "tx_frame_error");
	adapter->stats.tx_unicast += dec_compare48(hw, hw_stats.tx_unicast,
						   hw->hw_stats.tx_unicast,
						   "tx_unicast");
	adapter->stats.tx_multicast += dec_compare48(hw, hw_stats.tx_multicast,
						     hw->hw_stats.tx_multicast,
						     "tx_multicast");
	adapter->stats.tx_broadcast += dec_compare48(hw, hw_stats.tx_broadcast,
						     hw->hw_stats.tx_broadcast,
						     "tx_broadcast");
	adapter->stats.tx_vlan += dec_compare48(hw, hw_stats.tx_vlan,
						hw->hw_stats.tx_vlan,
						"tx_vlan");
	adapter->stats.tx_fc_pause += dec_compare48(hw, hw_stats.tx_fc_pause,
						    hw->hw_stats.tx_fc_pause,
						    "tx_fc_pause");

	adapter->stats.rx_bad_code += dec_compare48(hw, hw_stats.rx_bad_code,
						    hw->hw_stats.rx_bad_code,
						    "rx_bad_code");
	adapter->stats.rx_total_packets += dec_compare48(hw, hw_stats.rx_total_packets,
							 hw->hw_stats.rx_total_packets,
							 "rx_total_packets");
	adapter->stats.rx_total_bytes += dec_compare48(hw, hw_stats.rx_total_bytes,
						       hw->hw_stats.rx_total_bytes,
						       "rx_total_bytes");
	adapter->stats.rx_total_good_packets += dec_compare48(hw, hw_stats.rx_total_good_packets,
							      hw->hw_stats.rx_total_good_packets,
							      "rx_total_good_packets");
	adapter->stats.rx_total_good_bytes += dec_compare48(hw, hw_stats.rx_total_good_bytes,
							    hw->hw_stats.rx_total_good_bytes,
							    "rx_total_good_bytes");
	adapter->stats.rx_bad_fcs += dec_compare48(hw, hw_stats.rx_bad_fcs,
						   hw->hw_stats.rx_bad_fcs,
						   "rx_bad_fcs");
	adapter->stats.rx_frame_err += dec_compare48(hw, hw_stats.rx_frame_err,
						     hw->hw_stats.rx_frame_err,
						     "rx_frame_err");
	adapter->stats.rx_unicast += dec_compare48(hw, hw_stats.rx_unicast,
						   hw->hw_stats.rx_unicast,
						   "rx_unicast");
	adapter->stats.rx_multicast += dec_compare48(hw, hw_stats.rx_multicast,
						     hw->hw_stats.rx_multicast,
						     "rx_multicast");
	adapter->stats.rx_broadcast += dec_compare48(hw, hw_stats.rx_broadcast,
						     hw->hw_stats.rx_broadcast,
						     "rx_broadcast");
	adapter->stats.rx_vlan += dec_compare48(hw, hw_stats.rx_vlan,
						hw->hw_stats.rx_vlan,
						"rx_vlan");
	adapter->stats.rx_oversize += dec_compare48(hw, hw_stats.rx_oversize,
						    hw->hw_stats.rx_oversize,
						    "rx_oversize");
	adapter->stats.rx_undersize += dec_compare48(hw, hw_stats.rx_undersize,
						     hw->hw_stats.rx_undersize,
						     "rx_undersize");
	adapter->stats.rx_fc_pause += dec_compare48(hw, hw_stats.rx_fc_pause,
						    hw->hw_stats.rx_fc_pause,
						    "rx_rc_pause");
	adapter->stats.tx_error_packets = adapter->stats.tx_bad_fcs +
					  adapter->stats.tx_frame_error;
	adapter->stats.rx_error_packets = adapter->stats.rx_frame_err +
					  adapter->stats.rx_bad_fcs +
					  adapter->stats.rx_oversize +
					  adapter->stats.rx_undersize;

	memcpy(&hw->hw_stats, &hw_stats, sizeof(hw_stats));

	netdev->stats.multicast = adapter->stats.rx_multicast;
	netdev->stats.rx_errors = adapter->stats.rx_error_packets;
	netdev->stats.tx_errors = adapter->stats.tx_error_packets;
	netdev->stats.rx_length_errors = adapter->stats.rx_oversize +
					 adapter->stats.rx_undersize;
	netdev->stats.rx_crc_errors = adapter->stats.rx_bad_fcs;
	netdev->stats.rx_frame_errors = adapter->stats.rx_frame_err;

	ring_count = adapter->num_txq;
	tx_busy = 0;
	tx_linearize = 0;
	tx_dma_err = 0;
	for (ring_index = 0; ring_index < ring_count; ring_index++) {
		ring = READ_ONCE(adapter->tx_rings[ring_index]);
		if (!ring)
			continue;
		tx_busy += ring->tx_stats.tx_busy;
		tx_linearize += ring->tx_stats.tx_linearize;
		tx_csum_pkts += ring->tx_stats.tx_csum_pkts;
		tx_dma_err += ring->tx_stats.tx_dma_err;
	}
	adapter->stats.tx_busy = tx_busy;
	adapter->stats.tx_linearize = tx_linearize;
	adapter->stats.tx_csum_pkts = tx_csum_pkts;
	adapter->stats.tx_dma_err = tx_dma_err;

	ring_count = adapter->num_rxq;
	alloc_page_failed = 0;
	alloc_skb_failed = 0;
	rx_dma_err = 0;
	for (ring_index = 0; ring_index < ring_count; ring_index++) {
		ring = READ_ONCE(adapter->rx_rings[ring_index]);
		if (!ring)
			continue;
		rx_csum_pkts += ring->rx_stats.rx_csum_pkts;
		alloc_page_failed += ring->rx_stats.alloc_page_failed;
		alloc_skb_failed += ring->rx_stats.alloc_skb_failed;
		rx_dma_err += ring->rx_stats.rx_dma_err;
	}
	adapter->stats.rx_csum_pkts = rx_csum_pkts;
	adapter->stats.alloc_page_failed = alloc_page_failed;
	adapter->stats.alloc_skb_failed = alloc_skb_failed;
	adapter->stats.rx_dma_err = rx_dma_err;

	mutex_unlock(&adapter->stats.lock);
}

void nbl_init_hw_stats(struct nbl_hw *hw)
{
	int ret;

	if (is_af(hw))
		ret = nbl_af_get_eth_stats(hw, hw->eth_port_id, &hw->hw_stats);
	else
		ret = nbl_mailbox_req_get_eth_stats(hw, hw->eth_port_id, &hw->hw_stats);

	if (ret < 0)
		pr_err("nbl init hw_stat failed, port: %d\n", hw->eth_port_id);
}

void nbl_reset_subtask(struct nbl_adapter *adapter)
{
	if (!test_and_clear_bit(NBL_RESET_REQUESTED, adapter->state))
		return;

	rtnl_lock();
	if (test_bit(NBL_DOWN, adapter->state) ||
	    test_bit(NBL_RESETTING, adapter->state)) {
		rtnl_unlock();
		return;
	}

	adapter->stats.tx_timeout++;

	nbl_do_reset(adapter);

	rtnl_unlock();
}
