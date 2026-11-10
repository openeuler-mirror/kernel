/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (c) HiSilicon Technologies Co., Ltd. 2025. All rights reserved.
 */

#ifndef _UB_UBFI_UBFI_H_
#define _UB_UBFI_UBFI_H_

#include <linux/device.h>
#include <linux/ioport.h>
#include <linux/irqdomain_defs.h>
#include <linux/list.h>
#include <linux/types.h>

#define UMMU_RSV_LEN 26
#define UMMU_VEND_LEN 10

enum ubrt_node_type {
	UBRT_UBC,
	UBRT_UMMU,
	UBRT_UMMU_PMU,
};

/*
 * struct ubrt_fwnode - Structure to store nodes of the UBRT table reported by
 *                      the BIOS. The UBRT nodes describe hardware information
 *                      for UB system devices, such as UBC devices, UMMU
 *                      devices, etc.
 *
 * @type: Type of the UBRT node.
 * @index: Index of the UBRT node within its type.
 * @fwnode: fwnode_handle of the device corresponding to the UBRT node.
 * @ubrt_node: Pointer to the UBRT node, e.g., an ummu_node.
 * @list: List node of ubrt_fwnode_list.
 */
struct ubrt_fwnode {
	enum ubrt_node_type type;
	u32 index;
	struct fwnode_handle *fwnode;
	void *ubrt_node;
	struct list_head list;
};

/*
 * struct ummu_node - Structure to store hardware information nodes reported
 *                    by the BIOS to the UMMU device.
 *
 * @base_addr: Base address of the UMMU register space.
 * @addr_size: Size of the UMMU register space.
 * @intr_id: Interrupt ID for the UMMU device, used for device interrupt
 *           request in the OS.
 * @pxm: Proximity Domain (PXM) identifier of the UMMU device. If the value is
 *       0xFFFF, it indicates an invalid PXM.
 * @its_index: Index of the Interrupt Translation Service (ITS) associated with
 *             the UMMU device.
 * @pmu_addr: Base address of the PMU register space associated with the UMMU
 *            device.
 * @pmu_size: Size of the PMU register space associated with the UMMU device.
 * @pmu_intr_id: Interrupt ID for the PMU associated with the UMMU device.
 * @min_tid: Minimum Token ID that can be allocated.
 * @max_tid: Maximum Token ID that can be allocated.
 * @reserved: Reserved bytes.
 * @vendor_id: Vendor ID, reused from the Vendor ID definition in GUID, see
 *             "UB Base Specification 2.0".
 * @vendor_info: Vendor-specific information.
 */
struct ummu_node {
	u64 base_addr;
	u64 addr_size;
	u32 intr_id;
	u16 pxm;
	u16 its_index;
	u64 pmu_addr;
	u64 pmu_size;
	u32 pmu_intr_id;
	u32 min_tid;
	u32 max_tid;
	u8 reserved[UMMU_RSV_LEN];
	u16 vendor_id;
	u64 vendor_info[UMMU_VEND_LEN];
};

/**
 * ubrt_register_gsi() - Registering UBC's interrupt into the kernel via ACPI
 * @hwirq: GSI IRQ number reported by BIOS
 * @trigger: trigger type of the GSI number to be mapped
 * @polarity: polarity of the GSI to be mapped
 * @name: GSI IRQ name
 * @res: Record the soft interrupt number obtained after registration into res
 *
 * Return: 0 if success or other if failed
 */
int ubrt_register_gsi(u32 hwirq, int trigger, int polarity, const char *name,
		      struct resource *res);

/**
 * ubrt_unregister_gsi() - Unregistering UBC's interrupt into the kernel via ACPI
 * @hwirq: GSI IRQ number reported by BIOS
 */
void ubrt_unregister_gsi(u32 hwirq);

/**
 * ub_update_msi_domain() - Update the MSI domain of UBC
 * @dev: device with ub msi domain
 * @bus_token: DOMAIN_BUS_UB_MSI
 *
 * Used when booting via ACPI. The MSI domain of the UB is reported by a
 * platform device to the driver, and this function passes the MSI domain of the
 * platform device to the UBC.
 *
 * Return: 0 if success or other if failed
 */
int ub_update_msi_domain(struct device *dev,
			 enum irq_domain_bus_token bus_token);

/**
 * ubrt_fwnode_set() - Associate a device's fwnode with an UBRT node
 * @index: Index of the UBRT node within its type.
 * @type: Type of the UBRT node.
 * @fwnode: fwnode_handle associated with a device.
 *
 * Finds an UBRT node by index and type, and associates the device's
 * fwnode with the UBRT node. This allows subsequent lookups of
 * the UBRT node using the device's fwnode.
 *
 * Return: 0 if success, or error code if failed.
 */
int ubrt_fwnode_set(u32 index, enum ubrt_node_type type,
		    struct fwnode_handle *fwnode);

/**
 * ubrt_fwnode_get_by_idx() - Get an UBRT node by index and type
 * @index: Index of the UBRT node within its type.
 * @type: Type of the UBRT node.
 *
 * Finds an UBRT node by index and type.
 *
 * Return: Pointer to the struct ubrt_fwnode if found, or NULL if not found.
 */
struct ubrt_fwnode *ubrt_fwnode_get_by_idx(u32 index,
					   enum ubrt_node_type type);

/**
 * ubrt_fwnode_get() - Get an UBRT node by fwnode_handle
 * @fwnode: fwnode_handle associated with a device.
 *
 * Finds an UBRT node by the device's fwnode.
 *
 * Return: Pointer to struct ubrt_fwnode if found, or NULL if not found.
 */
struct ubrt_fwnode *ubrt_fwnode_get(struct fwnode_handle *fwnode);

/**
 * ubrt_fwnode_get_count() - Get the count of UBRT nodes of a specific type
 * @type: Type of the UBRT node.
 *
 * Return: The count of UBRT nodes of the specified type.
 */
u32 ubrt_fwnode_get_count(enum ubrt_node_type type);

/**
 * ubrt_fwnode_add() - Add an UBRT node to the ubrt_fwnode_list
 * @node: Pointer to the UBRT node.
 * @index: Index of the UBRT node within its type.
 * @size: Size of the UBRT node.
 * @type: Type of the UBRT node.
 *
 * Adds an UBRT node to the ubrt_fwnode_list, associating it with the
 * specified index and type.
 *
 * Return: 0 if success, or error code if failed.
 */
int ubrt_fwnode_add(void *node, u32 index, int size, enum ubrt_node_type type);

/**
 * ubrt_fwnode_del() - Delete an UBRT node from the ubrt_fwnode_list
 * @index: Index of the UBRT node within its type.
 * @type: Type of the UBRT node.
 */
void ubrt_fwnode_del(u32 index, enum ubrt_node_type type);

/**
 * ubrt_fwnode_del_all() - Clear the ubrt_fwnode_list
 *
 * Clears all UBRT nodes from the ubrt_fwnode_list.
 */
void ubrt_fwnode_del_all(void);

/**
 * struct ub_irqs_affinity - Irqs affinity node of a bus controller
 * @node:		List node of ubc_irqs_affinity_list
 * @irqs_affinity:	CPU affinity cpumask of the controller's irqs
 * @ctl_no:		Bus controller number, used as the key
 */
struct ub_irqs_affinity {
	struct list_head node;
	cpumask_t irqs_affinity;
	u32 ctl_no;
};

#if IS_ENABLED(CONFIG_UB_UBFI)
extern struct list_head ubc_list;
extern struct list_head ubc_irqs_affinity_list;
extern u32 ubc_eid_start;
extern u32 ubc_eid_end;
extern u32 ubc_cna_start;
extern u32 ubc_cna_end;
extern u8 ubc_feature;

/**
 * ubrt_iommu_get_resv_regions() - Get reserved memory regions from UBRT table.
 * @dev: Pointer to the device.
 * @list: List used to store reserved memory regions.
 *
 * In virtualization scenarios, the host OS should describe the available
 * memory regions for UBC to the guest OS through the UB Reserved Memory
 * information table in the UBRT table. This information table is reported by
 * the VM BIOS; the physical machine BIOS does not need to report this
 * information table.
 */
void ubrt_iommu_get_resv_regions(struct device *dev, struct list_head *list);

#else /* !CONFIG_UB_UBFI */

static inline
void ubrt_iommu_get_resv_regions(struct device *dev, struct list_head *list) {}

#endif /* CONFIG_UB_UBFI */

#endif /* _UB_UBFI_UBFI_H_ */
