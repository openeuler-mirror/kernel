/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (c) HiSilicon Technologies Co., Ltd. 2025. All rights reserved.
 */

#ifndef __UBUS_CONTROLLER_H__
#define __UBUS_CONTROLLER_H__

#include <ub/ubus/ubus.h>
#include "decoder.h"

/**
 * struct ub_bus_controller_ops - Vendor-specific operation callbacks for ubus bus controller
 * @eu_table_init: Initialize EU (EID-UPI) table private data. Called during EU
 *		table initialization for ub bus controller entity.
 * @eu_table_uninit: De-initialize EU table private data. Called during ub bus
 *		controller entity teardown.
 * @eu_cfg:	Configure an EU table entry to add or remove the mapping between
 *		the specified eid and upi. Flag true to add, false to remove.
 * @mem_decoder_create: Initialize the memory device of ubus controller. Called
 *		during ubus memory device probe.
 * @mem_decoder_remove: Remove the memory device of ubus controller and release
 *		associated resources. Called during ubus memory device removal.
 * @register_ubmem_irq: Register interrupt handler for ubus memory device.
 *		Called during ubus controller setup.
 * @unregister_ubmem_irq: Unregister interrupt handler for ubus memory device.
 *		Called during ubus controller unset.
 * @init_decoder_queue: Initialize decoder command queue (cmdq) and event queue
 *		(evtq), get the virtual address for the queue base address.
 * @uninit_decoder_queue: De-initialize decoder queues and unmap the virtual
 *		address.
 * @entity_enable: Enable or disable a ubus entity.
 *		Enable with value 1, disable with value 0.
 * @create_decoder_table: Create decoder page table, allocate page table memory
 *		and initialize page table structures for physical address to
 *		ubus address mapping.
 * @free_decoder_table: Free decoder page table resources.
 * @decoder_map: Establish ubus address mapping from host physical address to
 *		ubus address. The info parameter carries address, size, eid and
 *		other mapping details.
 * @decoder_unmap: Tear down ubus address mapping and release mappings within
 *		the specified physical address range.
 * @decoder_event_deal: Process events from the decoder event queue. Called in
 *		decoder interrupt context to read and handle event queue
 *		responses.
 */
struct ub_bus_controller_ops {
	int (*eu_table_init)(struct ub_bus_controller *ubc);
	void (*eu_table_uninit)(struct ub_bus_controller *ubc);
	int (*eu_cfg)(struct ub_bus_controller *ubc, bool flag, u32 eid, u16 upi);
	int (*mem_decoder_create)(struct ub_bus_controller *ubc);
	void (*mem_decoder_remove)(struct ub_bus_controller *ubc);
	void (*register_ubmem_irq)(struct ub_bus_controller *ubc);
	void (*unregister_ubmem_irq)(struct ub_bus_controller *ubc);
	int (*init_decoder_queue)(struct ub_decoder *decoder);
	void (*uninit_decoder_queue)(struct ub_decoder *decoder);
	int (*entity_enable)(struct ub_entity *uent, u8 enable);
	int (*create_decoder_table)(struct ub_decoder *decoder);
	void (*free_decoder_table)(struct ub_decoder *decoder);
	int (*decoder_map)(struct ub_decoder *decoder,
			   struct decoder_map_info *info);
	int (*decoder_unmap)(struct ub_decoder *decoder, phys_addr_t addr,
			     u64 size);
	void (*decoder_event_deal)(struct ub_decoder *decoder);

	KABI_RESERVE(1)
	KABI_RESERVE(2)
	KABI_RESERVE(3)
	KABI_RESERVE(4)
	KABI_RESERVE(5)
	KABI_RESERVE(6)
	KABI_RESERVE(7)
	KABI_RESERVE(8)
};

struct ub_bus_controller *ub_find_bus_controller_by_cna(u32 cna);
void ub_bus_controllers_remove(void);
int ub_bus_controllers_probe(void);
int ub_ubc_to_node(struct ub_bus_controller *ubc);

#endif /* __UBUS_CONTROLLER_H__  */
