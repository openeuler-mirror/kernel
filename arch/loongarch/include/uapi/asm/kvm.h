/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * Copyright (C) 2020  Loongson Technologies, Inc.  All rights reserved.
 * Authors: Sanjay Lal <sanjayl@kymasys.com>
 * Authors: Xing Li <lixing@loongson.cn>
 */

#ifndef __LINUX_KVM_LOONGARCH_H
#define __LINUX_KVM_LOONGARCH_H

#include <linux/types.h>
#ifndef __KERNEL__
#include <stdint.h>
#endif

#define __KVM_HAVE_GUEST_DEBUG
#define KVM_GUESTDBG_USE_SW_BP 0x00010000
#define KVM_GUESTDBG_USE_HW_BP 0x00020000
#define KVM_DATA_HW_BREAKPOINT_NUM 8
#define KVM_INST_HW_BREAKPOINT_NUM 8

/*
 * KVM Loongarch specific structures and definitions.
 *
 * Some parts derived from the x86 version of this file.
 */

#define __KVM_HAVE_READONLY_MEM

#define KVM_COALESCED_MMIO_PAGE_OFFSET 1

/*
 * for KVM_GET_REGS and KVM_SET_REGS
 */
struct kvm_regs {
	/* out (KVM_GET_REGS) / in (KVM_SET_REGS) */
	__u64 gpr[32];
	__u64 pc;
};

/*
 * for KVM_GET_CPUCFG
 */
struct kvm_cpucfg {
	/* out (KVM_GET_CPUCFG) */
	__u32 cpucfg[64];
};

/*
 * for KVM_GET_FPU and KVM_SET_FPU
 */
struct kvm_fpu {
	__u32 fcsr;
	__u32 none;
	__u64 fcc;    /* 8x8 */
	struct kvm_fpureg {
		__u64 val64[4];	//support max 256 bits
	} fpr[32];
};

/*
 * For LOONGARCH, we use KVM_SET_ONE_REG and KVM_GET_ONE_REG to access various
 * registers.  The id field is broken down as follows:
 *
 *  bits[63..52] - As per linux/kvm.h
 *  bits[51..32] - Must be zero.
 *  bits[31..16] - Register set.
 *
 * Register set = 0: GP registers from kvm_regs (see definitions below).
 *
 * Register set = 1: CSR registers.
 *
 * Register set = 2: KVM specific registers (see definitions below).
 *
 * Register set = 3: FPU / SIMD registers (see definitions below).
 *
 * Other sets registers may be added in the future.  Each set would
 * have its own identifier in bits[31..16].
 */

#define KVM_REG_LOONGARCH_GP		(KVM_REG_LOONGARCH | 0x00000ULL)
#define KVM_REG_LOONGARCH_CSR		(KVM_REG_LOONGARCH | 0x10000ULL)
#define KVM_REG_LOONGARCH_KVM		(KVM_REG_LOONGARCH | 0x20000ULL)
#define KVM_REG_LOONGARCH_FPU		(KVM_REG_LOONGARCH | 0x30000ULL)
#define KVM_REG_LOONGARCH_MASK		(KVM_REG_LOONGARCH | 0x30000ULL)
#define KVM_CSR_IDX_MASK		(0x10000 - 1)

/*
 * KVM_REG_LOONGARCH_KVM - KVM specific control registers.
 */

#define KVM_REG_LOONGARCH_COUNTER	(KVM_REG_LOONGARCH_KVM | KVM_REG_SIZE_U64 | 3)
#define KVM_REG_LOONGARCH_VCPU_RESET	(KVM_REG_LOONGARCH_KVM | KVM_REG_SIZE_U64 | 4)

#define __KVM_HAVE_IRQ_LINE

struct kvm_debug_exit_arch {
	__u64 era;
	__u32 fwps;
	__u32 mwps;
	__u32 exception;
};

/* for KVM_SET_GUEST_DEBUG */
struct hw_breakpoint {
    __u64 addr;
    __u64 mask;
    __u32 asid;
    __u32 ctrl;
};

struct kvm_guest_debug_arch {
	struct hw_breakpoint data_breakpoint[KVM_DATA_HW_BREAKPOINT_NUM];
	struct hw_breakpoint inst_breakpoint[KVM_INST_HW_BREAKPOINT_NUM];
	int inst_bp_nums, data_bp_nums;
};

/* definition of registers in kvm_run */
struct kvm_sync_regs {
};

/* dummy definition */
struct kvm_sregs {
};

struct kvm_iocsr_entry {
	__u32 addr;
	__u32 pad;
	__u64 data;
};

struct kvm_csr_entry {
	__u32 index;
	__u32 reserved;
	__u64 data;
};

/* for KVM_GET_MSRS and KVM_SET_MSRS */
struct kvm_msrs {
	__u32 ncsrs; /* number of msrs in entries */
	__u32 pad;

	struct kvm_csr_entry entries[0];
};

struct kvm_loongarch_interrupt {
	/* in */
	__u32 cpu;
	__u32 irq;
};

#define KVM_IRQCHIP_LS7A_IOAPIC	0x0
#define KVM_IRQCHIP_LS3A_GIPI	0x1
#define KVM_IRQCHIP_LS3A_HT_IRQ	0x2
#define KVM_IRQCHIP_LS3A_ROUTE	0x3
#define KVM_IRQCHIP_LS3A_EXTIRQ	0x4
#define KVM_IRQCHIP_LS3A_IPMASK	0x5
#define KVM_NR_IRQCHIPS          1
#define KVM_IRQCHIP_NUM_PINS    64

#define KVM_MAX_CORES			256
#define KVM_EXTIOI_IRQS			(256)
#define KVM_EXTIOI_IRQS_BITMAP_SIZE	(KVM_EXTIOI_IRQS / 8)
/* map to ipnum per 32 irqs */
#define KVM_EXTIOI_IRQS_IPMAP_SIZE	(KVM_EXTIOI_IRQS / 32)
#define KVM_EXTIOI_IRQS_PER_GROUP	32
#define KVM_EXTIOI_IRQS_COREMAP_SIZE	(KVM_EXTIOI_IRQS)
#define KVM_EXTIOI_IRQS_NODETYPE_SIZE	16

struct ls7a_ioapic_state {
	/* 0x000 interrupt id register */
	__u64 int_id;
	/* 0x020 interrupt mask register */
	__u64 int_mask;
	/* 0x040 1=msi */
	__u64 htmsi_en;
	/* 0x060 edge=1 level  =0 */
	__u64 intedge;
	/* 0x080 for clean edge int,set 1 clean,set 0 is noused */
	__u64 intclr;
	/* 0x0c0 */
	__u64 auto_crtl0;
	/* 0x0e0 */
	__u64 auto_crtl1;
	/* 0x100 - 0x140 */
	__u8 route_entry[64];
	/* 0x200 - 0x240 */
	__u8 htmsi_vector[64];
	/* 0x300 */
	__u64 intisr_chip0;
	/* 0x320 */
	__u64 intisr_chip1;
	/* edge detection */
	__u64 last_intirr;
	/* 0x380 interrupt request register */
	__u64 intirr;
	/* 0x3a0 interrupt service register */
	__u64 intisr;
	/* 0x3e0 interrupt level polarity selection register,
	 * 0 for high level tirgger
	 */
	__u64 int_polarity;
};

struct loongarch_gipi_single {
	__u32 status;
	__u32 en;
	__u32 set;
	__u32 clear;
	__u64 buf[4];
};

struct loongarch_gipiState {
	struct loongarch_gipi_single core[KVM_MAX_CORES];
};

struct kvm_loongarch_ls3a_extirq_state {
	union ext_en_r {
		uint64_t reg_u64[KVM_EXTIOI_IRQS_BITMAP_SIZE / 8];
		uint32_t reg_u32[KVM_EXTIOI_IRQS_BITMAP_SIZE / 4];
		uint8_t reg_u8[KVM_EXTIOI_IRQS_BITMAP_SIZE];
	} ext_en_r;
	union bounce_r {
		uint64_t reg_u64[KVM_EXTIOI_IRQS_BITMAP_SIZE / 8];
		uint32_t reg_u32[KVM_EXTIOI_IRQS_BITMAP_SIZE / 4];
		uint8_t reg_u8[KVM_EXTIOI_IRQS_BITMAP_SIZE];
	} bounce_r;
	union ext_isr_r {
		uint64_t reg_u64[KVM_EXTIOI_IRQS_BITMAP_SIZE / 8];
		uint32_t reg_u32[KVM_EXTIOI_IRQS_BITMAP_SIZE / 4];
		uint8_t reg_u8[KVM_EXTIOI_IRQS_BITMAP_SIZE];
	} ext_isr_r;
	union ext_core_isr_r {
		uint64_t reg_u64[KVM_MAX_CORES][KVM_EXTIOI_IRQS_BITMAP_SIZE / 8];
		uint32_t reg_u32[KVM_MAX_CORES][KVM_EXTIOI_IRQS_BITMAP_SIZE / 4];
		uint8_t reg_u8[KVM_MAX_CORES][KVM_EXTIOI_IRQS_BITMAP_SIZE];
	} ext_core_isr_r;
	union ip_map_r {
		uint64_t reg_u64;
		uint32_t reg_u32[KVM_EXTIOI_IRQS_IPMAP_SIZE / 4];
		uint8_t reg_u8[KVM_EXTIOI_IRQS_IPMAP_SIZE];
	} ip_map_r;
	union core_map_r {
		uint64_t reg_u64[KVM_EXTIOI_IRQS_COREMAP_SIZE / 8];
		uint32_t reg_u32[KVM_EXTIOI_IRQS_COREMAP_SIZE / 4];
		uint8_t reg_u8[KVM_EXTIOI_IRQS_COREMAP_SIZE];
	} core_map_r;
	union node_type_r {
		uint64_t reg_u64[KVM_EXTIOI_IRQS_NODETYPE_SIZE / 4];
		uint32_t reg_u32[KVM_EXTIOI_IRQS_NODETYPE_SIZE / 2];
		uint16_t reg_u16[KVM_EXTIOI_IRQS_NODETYPE_SIZE];
		uint8_t reg_u8[KVM_EXTIOI_IRQS_NODETYPE_SIZE * 2];
	} node_type_r;
};

struct loongarch_kvm_irqchip {
	__u16 chip_id;
	__u16 len;
	__u16 vcpu_id;
	__u16 reserved;
	char data[0];
};

#endif /* __LINUX_KVM_LOONGARCH_H */
