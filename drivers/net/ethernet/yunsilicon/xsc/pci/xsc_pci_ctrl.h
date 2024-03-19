/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#ifndef XSC_PCI_CTRL_H
#define XSC_PCI_CTRL_H

#include <linux/bitmap.h>
#include <linux/percpu.h>
#include <linux/cpu.h>

//for x86
#ifndef NR_VECTORS
#define NR_VECTORS				256
#endif
#define IRQ_MATRIX_BITS			NR_VECTORS
#define IRQ_MATRIX_SIZE (BITS_TO_LONGS(IRQ_MATRIX_BITS))

struct db_cpumap {
	unsigned int			available;
	unsigned int			allocated;
	unsigned int			managed;
	unsigned int			managed_allocated;
	u8				initialized;
	u8				online;
	unsigned long			alloc_map[IRQ_MATRIX_SIZE];
	unsigned long			managed_map[IRQ_MATRIX_SIZE];
};

struct db_irq_matrix {
	unsigned int			matrix_bits;
	unsigned int			alloc_start;
	unsigned int			alloc_end;
	unsigned int			alloc_size;
	unsigned int			global_available;
	unsigned int			global_reserved;
	unsigned int			systembits_inalloc;
	unsigned int			total_allocated;
	unsigned int			online_maps;
	struct db_cpumap __percpu		*maps;
	unsigned long			scratch_map[IRQ_MATRIX_SIZE];
	unsigned long			system_map[IRQ_MATRIX_SIZE];
};

u16 xsc_get_irq_matrix_global_available(struct xsc_core_device *dev);

int xsc_pci_ctrl_init(void);
void xsc_pci_ctrl_fini(void);

#endif
