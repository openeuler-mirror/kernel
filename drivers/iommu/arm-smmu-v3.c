/*
 * IOMMU API for ARM architected SMMUv3 implementations.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * Copyright (C) 2015 ARM Limited
 *
 * Author: Will Deacon <will.deacon@arm.com>
 *
 * This driver is powered by bad coffee and bombay mix.
 */

#include <linux/acpi.h>
#include <linux/acpi_iort.h>
#include <linux/bitfield.h>
#include <linux/bitops.h>
#include <linux/cpufeature.h>
#include <linux/crash_dump.h>
#include <linux/delay.h>
#include <linux/dma-iommu.h>
#include <linux/err.h>
#include <linux/interrupt.h>
#include <linux/iommu.h>
#include <linux/iopoll.h>
#include <linux/mmu_context.h>
#include <linux/module.h>
#include <linux/msi.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/of_iommu.h>
#include <linux/of_platform.h>
#include <linux/pci.h>
#include <linux/pci-ats.h>
#include <linux/platform_device.h>
#include <linux/sched/mm.h>

#include <linux/amba/bus.h>

#include "io-pgtable.h"
#include "iommu-pasid-table.h"

/* MMIO registers */
#define ARM_SMMU_IDR0			0x0
#define IDR0_ST_LVL			GENMASK(28, 27)
#define IDR0_ST_LVL_2LVL		1
#define IDR0_STALL_MODEL		GENMASK(25, 24)
#define IDR0_STALL_MODEL_STALL		0
#define IDR0_STALL_MODEL_FORCE		2
#define IDR0_TTENDIAN			GENMASK(22, 21)
#define IDR0_TTENDIAN_MIXED		0
#define IDR0_TTENDIAN_LE		2
#define IDR0_TTENDIAN_BE		3
#define IDR0_CD2L			(1 << 19)
#define IDR0_VMID16			(1 << 18)
#define IDR0_PRI			(1 << 16)
#define IDR0_SEV			(1 << 14)
#define IDR0_MSI			(1 << 13)
#define IDR0_ASID16			(1 << 12)
#define IDR0_ATS			(1 << 10)
#define IDR0_HYP			(1 << 9)
#define IDR0_HD				(1 << 7)
#define IDR0_HA				(1 << 6)
#define IDR0_BTM			(1 << 5)
#define IDR0_COHACC			(1 << 4)
#define IDR0_TTF			GENMASK(3, 2)
#define IDR0_TTF_AARCH64		2
#define IDR0_TTF_AARCH32_64		3
#define IDR0_S1P			(1 << 1)
#define IDR0_S2P			(1 << 0)

#define ARM_SMMU_IDR1			0x4
#define IDR1_TABLES_PRESET		(1 << 30)
#define IDR1_QUEUES_PRESET		(1 << 29)
#define IDR1_REL			(1 << 28)
#define IDR1_CMDQS			GENMASK(25, 21)
#define IDR1_EVTQS			GENMASK(20, 16)
#define IDR1_PRIQS			GENMASK(15, 11)
#define IDR1_SSIDSIZE			GENMASK(10, 6)
#define IDR1_SIDSIZE			GENMASK(5, 0)

#define ARM_SMMU_IDR5			0x14
#define IDR5_STALL_MAX			GENMASK(31, 16)
#define IDR5_GRAN64K			(1 << 6)
#define IDR5_GRAN16K			(1 << 5)
#define IDR5_GRAN4K			(1 << 4)
#define IDR5_OAS			GENMASK(2, 0)
#define IDR5_OAS_32_BIT			0
#define IDR5_OAS_36_BIT			1
#define IDR5_OAS_40_BIT			2
#define IDR5_OAS_42_BIT			3
#define IDR5_OAS_44_BIT			4
#define IDR5_OAS_48_BIT			5
#define IDR5_OAS_52_BIT			6
#define IDR5_VAX			GENMASK(11, 10)
#define IDR5_VAX_52_BIT			1

#define ARM_SMMU_CR0			0x20
#define CR0_ATSCHK			(1 << 4)
#define CR0_CMDQEN			(1 << 3)
#define CR0_EVTQEN			(1 << 2)
#define CR0_PRIQEN			(1 << 1)
#define CR0_SMMUEN			(1 << 0)

#define ARM_SMMU_CR0ACK			0x24

#define ARM_SMMU_CR1			0x28
#define CR1_TABLE_SH			GENMASK(11, 10)
#define CR1_TABLE_OC			GENMASK(9, 8)
#define CR1_TABLE_IC			GENMASK(7, 6)
#define CR1_QUEUE_SH			GENMASK(5, 4)
#define CR1_QUEUE_OC			GENMASK(3, 2)
#define CR1_QUEUE_IC			GENMASK(1, 0)
/* CR1 cacheability fields don't quite follow the usual TCR-style encoding */
#define CR1_CACHE_NC			0
#define CR1_CACHE_WB			1
#define CR1_CACHE_WT			2

#define ARM_SMMU_CR2			0x2c
#define CR2_PTM				(1 << 2)
#define CR2_RECINVSID			(1 << 1)
#define CR2_E2H				(1 << 0)

#define ARM_SMMU_GBPA			0x44
#define GBPA_UPDATE			(1 << 31)
#define GBPA_ABORT			(1 << 20)

#define ARM_SMMU_IRQ_CTRL		0x50
#define IRQ_CTRL_EVTQ_IRQEN		(1 << 2)
#define IRQ_CTRL_PRIQ_IRQEN		(1 << 1)
#define IRQ_CTRL_GERROR_IRQEN		(1 << 0)

#define ARM_SMMU_IRQ_CTRLACK		0x54

#define ARM_SMMU_GERROR			0x60
#define GERROR_SFM_ERR			(1 << 8)
#define GERROR_MSI_GERROR_ABT_ERR	(1 << 7)
#define GERROR_MSI_PRIQ_ABT_ERR		(1 << 6)
#define GERROR_MSI_EVTQ_ABT_ERR		(1 << 5)
#define GERROR_MSI_CMDQ_ABT_ERR		(1 << 4)
#define GERROR_PRIQ_ABT_ERR		(1 << 3)
#define GERROR_EVTQ_ABT_ERR		(1 << 2)
#define GERROR_CMDQ_ERR			(1 << 0)
#define GERROR_ERR_MASK			0xfd

#define ARM_SMMU_GERRORN		0x64

#define ARM_SMMU_GERROR_IRQ_CFG0	0x68
#define ARM_SMMU_GERROR_IRQ_CFG1	0x70
#define ARM_SMMU_GERROR_IRQ_CFG2	0x74

#define ARM_SMMU_STRTAB_BASE		0x80
#define STRTAB_BASE_RA			(1UL << 62)
#define STRTAB_BASE_ADDR_MASK		GENMASK_ULL(51, 6)

#define ARM_SMMU_STRTAB_BASE_CFG	0x88
#define STRTAB_BASE_CFG_FMT		GENMASK(17, 16)
#define STRTAB_BASE_CFG_FMT_LINEAR	0
#define STRTAB_BASE_CFG_FMT_2LVL	1
#define STRTAB_BASE_CFG_SPLIT		GENMASK(10, 6)
#define STRTAB_BASE_CFG_LOG2SIZE	GENMASK(5, 0)

#define ARM_SMMU_CMDQ_BASE		0x90
#define ARM_SMMU_CMDQ_PROD		0x98
#define ARM_SMMU_CMDQ_CONS		0x9c

#define ARM_SMMU_EVTQ_BASE		0xa0
#define ARM_SMMU_EVTQ_PROD		0x100a8
#define ARM_SMMU_EVTQ_CONS		0x100ac
#define ARM_SMMU_EVTQ_IRQ_CFG0		0xb0
#define ARM_SMMU_EVTQ_IRQ_CFG1		0xb8
#define ARM_SMMU_EVTQ_IRQ_CFG2		0xbc

#define ARM_SMMU_PRIQ_BASE		0xc0
#define ARM_SMMU_PRIQ_PROD		0x100c8
#define ARM_SMMU_PRIQ_CONS		0x100cc
#define ARM_SMMU_PRIQ_IRQ_CFG0		0xd0
#define ARM_SMMU_PRIQ_IRQ_CFG1		0xd8
#define ARM_SMMU_PRIQ_IRQ_CFG2		0xdc

/* Common MSI config fields */
#define MSI_CFG0_ADDR_MASK		GENMASK_ULL(51, 2)
#define MSI_CFG2_SH			GENMASK(5, 4)
#define MSI_CFG2_MEMATTR		GENMASK(3, 0)

/* Common memory attribute values */
#define ARM_SMMU_SH_NSH			0
#define ARM_SMMU_SH_OSH			2
#define ARM_SMMU_SH_ISH			3
#define ARM_SMMU_MEMATTR_DEVICE_nGnRE	0x1
#define ARM_SMMU_MEMATTR_OIWB		0xf

#define Q_IDX(q, p)			((p) & ((1 << (q)->max_n_shift) - 1))
#define Q_WRP(q, p)			((p) & (1 << (q)->max_n_shift))
#define Q_OVERFLOW_FLAG			(1 << 31)
#define Q_OVF(q, p)			((p) & Q_OVERFLOW_FLAG)
#define Q_ENT(q, p)			((q)->base +			\
					 Q_IDX(q, p) * (q)->ent_dwords)

#define Q_BASE_RWA			(1UL << 62)
#define Q_BASE_ADDR_MASK		GENMASK_ULL(51, 5)
#define Q_BASE_LOG2SIZE			GENMASK(4, 0)

/*
 * Stream table.
 *
 * Linear: Enough to cover 1 << IDR1.SIDSIZE entries
 * 2lvl: 128k L1 entries,
 *       256 lazy entries per table (each table covers a PCI bus)
 */
#define STRTAB_L1_SZ_SHIFT		20
#define STRTAB_SPLIT			8

#define STRTAB_L1_DESC_DWORDS		1
#define STRTAB_L1_DESC_SPAN		GENMASK_ULL(4, 0)
#define STRTAB_L1_DESC_L2PTR_MASK	GENMASK_ULL(51, 6)

#define STRTAB_STE_DWORDS		8
#define STRTAB_STE_0_V			(1UL << 0)
#define STRTAB_STE_0_CFG		GENMASK_ULL(3, 1)
#define STRTAB_STE_0_CFG_ABORT		0
#define STRTAB_STE_0_CFG_BYPASS		4
#define STRTAB_STE_0_CFG_S1_TRANS	5
#define STRTAB_STE_0_CFG_S2_TRANS	6

#define STRTAB_STE_0_S1FMT		GENMASK_ULL(5, 4)
#define STRTAB_STE_0_S1CTXPTR_MASK	GENMASK_ULL(51, 6)
#define STRTAB_STE_0_S1CDMAX		GENMASK_ULL(63, 59)

#define STRTAB_STE_1_S1DSS		GENMASK_ULL(1, 0)
#define STRTAB_STE_1_S1DSS_TERMINATE	0x0
#define STRTAB_STE_1_S1DSS_BYPASS	0x1
#define STRTAB_STE_1_S1DSS_SSID0	0x2

#define STRTAB_STE_1_S1C_CACHE_NC	0UL
#define STRTAB_STE_1_S1C_CACHE_WBRA	1UL
#define STRTAB_STE_1_S1C_CACHE_WT	2UL
#define STRTAB_STE_1_S1C_CACHE_WB	3UL
#define STRTAB_STE_1_S1CIR		GENMASK_ULL(3, 2)
#define STRTAB_STE_1_S1COR		GENMASK_ULL(5, 4)
#define STRTAB_STE_1_S1CSH		GENMASK_ULL(7, 6)

#define STRTAB_STE_1_S1STALLD		(1UL << 27)

#define STRTAB_STE_1_EATS		GENMASK_ULL(29, 28)
#define STRTAB_STE_1_EATS_ABT		0UL
#define STRTAB_STE_1_EATS_TRANS		1UL
#define STRTAB_STE_1_EATS_S1CHK		2UL

#define STRTAB_STE_1_STRW		GENMASK_ULL(31, 30)
#define STRTAB_STE_1_STRW_NSEL1		0UL
#define STRTAB_STE_1_STRW_EL2		2UL

#define STRTAB_STE_1_SHCFG		GENMASK_ULL(45, 44)
#define STRTAB_STE_1_SHCFG_INCOMING	1UL

#define STRTAB_STE_2_S2VMID		GENMASK_ULL(15, 0)
#define STRTAB_STE_2_VTCR		GENMASK_ULL(50, 32)
#define STRTAB_STE_2_S2AA64		(1UL << 51)
#define STRTAB_STE_2_S2ENDI		(1UL << 52)
#define STRTAB_STE_2_S2PTW		(1UL << 54)
#define STRTAB_STE_2_S2R		(1UL << 58)

#define STRTAB_STE_3_S2TTB_MASK		GENMASK_ULL(51, 4)

/* Command queue */
#define CMDQ_ENT_DWORDS			2
#define CMDQ_MAX_SZ_SHIFT		8

#define CMDQ_CONS_ERR			GENMASK(30, 24)
#define CMDQ_ERR_CERROR_NONE_IDX	0
#define CMDQ_ERR_CERROR_ILL_IDX		1
#define CMDQ_ERR_CERROR_ABT_IDX		2
#define CMDQ_ERR_CERROR_ATC_INV_IDX	3

#define CMDQ_0_OP			GENMASK_ULL(7, 0)
#define CMDQ_0_SSV			(1UL << 11)

#define CMDQ_PREFETCH_0_SID		GENMASK_ULL(63, 32)
#define CMDQ_PREFETCH_1_SIZE		GENMASK_ULL(4, 0)
#define CMDQ_PREFETCH_1_ADDR_MASK	GENMASK_ULL(63, 12)

#define CMDQ_CFGI_0_SSID		GENMASK_ULL(31, 12)
#define CMDQ_CFGI_0_SID			GENMASK_ULL(63, 32)
#define CMDQ_CFGI_1_LEAF		(1UL << 0)
#define CMDQ_CFGI_1_RANGE		GENMASK_ULL(4, 0)

#define CMDQ_TLBI_0_VMID		GENMASK_ULL(47, 32)
#define CMDQ_TLBI_0_ASID		GENMASK_ULL(63, 48)
#define CMDQ_TLBI_1_LEAF		(1UL << 0)
#define CMDQ_TLBI_1_VA_MASK		GENMASK_ULL(63, 12)
#define CMDQ_TLBI_1_IPA_MASK		GENMASK_ULL(51, 12)

#define CMDQ_ATC_0_SSID			GENMASK_ULL(31, 12)
#define CMDQ_ATC_0_SID			GENMASK_ULL(63, 32)
#define CMDQ_ATC_0_GLOBAL		(1UL << 9)
#define CMDQ_ATC_1_SIZE			GENMASK_ULL(5, 0)
#define CMDQ_ATC_1_ADDR_MASK		GENMASK_ULL(63, 12)

#define CMDQ_PRI_0_SSID			GENMASK_ULL(31, 12)
#define CMDQ_PRI_0_SID			GENMASK_ULL(63, 32)
#define CMDQ_PRI_1_GRPID		GENMASK_ULL(8, 0)
#define CMDQ_PRI_1_RESP			GENMASK_ULL(13, 12)

#define CMDQ_RESUME_0_SID		GENMASK_ULL(63, 32)
#define CMDQ_RESUME_0_ACTION_RETRY	(1UL << 12)
#define CMDQ_RESUME_0_ACTION_ABORT	(1UL << 13)
#define CMDQ_RESUME_1_STAG		GENMASK_ULL(15, 0)

#define CMDQ_SYNC_0_CS			GENMASK_ULL(13, 12)
#define CMDQ_SYNC_0_CS_NONE		0
#define CMDQ_SYNC_0_CS_IRQ		1
#define CMDQ_SYNC_0_CS_SEV		2
#define CMDQ_SYNC_0_MSH			GENMASK_ULL(23, 22)
#define CMDQ_SYNC_0_MSIATTR		GENMASK_ULL(27, 24)
#define CMDQ_SYNC_0_MSIDATA		GENMASK_ULL(63, 32)
#define CMDQ_SYNC_1_MSIADDR_MASK	GENMASK_ULL(51, 2)

/* Event queue */
#define EVTQ_ENT_DWORDS			4
#define EVTQ_MAX_SZ_SHIFT		7

#define EVTQ_0_ID			GENMASK_ULL(7, 0)
#define EVT_ID_TRANSLATION_FAULT	0x10
#define EVT_ID_ADDR_SIZE_FAULT		0x11
#define EVT_ID_ACCESS_FAULT		0x12
#define EVT_ID_PERMISSION_FAULT		0x13

#define EVTQ_0_SSV			GENMASK_ULL(11, 11)
#define EVTQ_0_SSID			GENMASK_ULL(31, 12)
#define EVTQ_0_SID			GENMASK_ULL(63, 32)
#define EVTQ_1_STAG			GENMASK_ULL(15, 0)
#define EVTQ_1_STALL			(1UL << 31)
#define EVTQ_1_PRIV			(1UL << 33)
#define EVTQ_1_EXEC			(1UL << 34)
#define EVTQ_1_READ			(1UL << 35)
#define EVTQ_1_S2			(1UL << 39)
#define EVTQ_1_CLASS			GENMASK_ULL(41, 40)
#define EVTQ_1_TT_READ			(1UL << 44)
#define EVTQ_2_ADDR			GENMASK_ULL(63, 0)
#define EVTQ_3_IPA			GENMASK_ULL(51, 12)

/* PRI queue */
#define PRIQ_ENT_DWORDS			2
#define PRIQ_MAX_SZ_SHIFT		8

#define PRIQ_0_SID			GENMASK_ULL(31, 0)
#define PRIQ_0_SSID			GENMASK_ULL(51, 32)
#define PRIQ_0_PERM_PRIV		(1UL << 58)
#define PRIQ_0_PERM_EXEC		(1UL << 59)
#define PRIQ_0_PERM_READ		(1UL << 60)
#define PRIQ_0_PERM_WRITE		(1UL << 61)
#define PRIQ_0_PRG_LAST			(1UL << 62)
#define PRIQ_0_SSID_V			(1UL << 63)

#define PRIQ_1_PRG_IDX			GENMASK_ULL(8, 0)
#define PRIQ_1_ADDR_MASK		GENMASK_ULL(63, 12)

/* High-level queue structures */
#define ARM_SMMU_POLL_TIMEOUT_US	100
#define ARM_SMMU_CMDQ_SYNC_TIMEOUT_US	1000000 /* 1s! */
#define ARM_SMMU_CMDQ_SYNC_SPIN_COUNT	10

#define MSI_IOVA_BASE			0x8000000
#define MSI_IOVA_LENGTH			0x100000

static bool disable_bypass = 1;
module_param_named(disable_bypass, disable_bypass, bool, S_IRUGO);
MODULE_PARM_DESC(disable_bypass,
	"Disable bypass streams such that incoming transactions from devices that are not attached to an iommu domain will report an abort back to the device and will not be allowed to pass through the SMMU.");

static bool disable_ats_check;
module_param_named(disable_ats_check, disable_ats_check, bool, S_IRUGO);
MODULE_PARM_DESC(disable_ats_check,
	"By default, the SMMU checks whether each incoming transaction marked as translated is allowed by the stream configuration. This option disables the check.");

enum pri_resp {
	PRI_RESP_DENY = 0,
	PRI_RESP_FAIL = 1,
	PRI_RESP_SUCC = 2,
};

enum arm_smmu_msi_index {
	EVTQ_MSI_INDEX,
	GERROR_MSI_INDEX,
	PRIQ_MSI_INDEX,
	ARM_SMMU_MAX_MSIS,
};

static phys_addr_t arm_smmu_msi_cfg[ARM_SMMU_MAX_MSIS][3] = {
	[EVTQ_MSI_INDEX] = {
		ARM_SMMU_EVTQ_IRQ_CFG0,
		ARM_SMMU_EVTQ_IRQ_CFG1,
		ARM_SMMU_EVTQ_IRQ_CFG2,
	},
	[GERROR_MSI_INDEX] = {
		ARM_SMMU_GERROR_IRQ_CFG0,
		ARM_SMMU_GERROR_IRQ_CFG1,
		ARM_SMMU_GERROR_IRQ_CFG2,
	},
	[PRIQ_MSI_INDEX] = {
		ARM_SMMU_PRIQ_IRQ_CFG0,
		ARM_SMMU_PRIQ_IRQ_CFG1,
		ARM_SMMU_PRIQ_IRQ_CFG2,
	},
};

struct arm_smmu_cmdq_ent {
	/* Common fields */
	u8				opcode;
	bool				substream_valid;

	/* Command-specific fields */
	union {
		#define CMDQ_OP_PREFETCH_CFG	0x1
		struct {
			u32			sid;
			u8			size;
			u64			addr;
		} prefetch;

		#define CMDQ_OP_CFGI_STE	0x3
		#define CMDQ_OP_CFGI_ALL	0x4
		#define CMDQ_OP_CFGI_CD		0x5
		#define CMDQ_OP_CFGI_CD_ALL	0x6
		struct {
			u32			sid;
			u32			ssid;
			union {
				bool		leaf;
				u8		span;
			};
		} cfgi;

		#define CMDQ_OP_TLBI_NH_ASID	0x11
		#define CMDQ_OP_TLBI_NH_VA	0x12
		#define CMDQ_OP_TLBI_EL2_ALL	0x20
		#define CMDQ_OP_TLBI_EL2_ASID	0x21
		#define CMDQ_OP_TLBI_EL2_VA	0x22
		#define CMDQ_OP_TLBI_S12_VMALL	0x28
		#define CMDQ_OP_TLBI_S2_IPA	0x2a
		#define CMDQ_OP_TLBI_NSNH_ALL	0x30
		struct {
			u16			asid;
			u16			vmid;
			bool			leaf;
			u64			addr;
		} tlbi;

		#define CMDQ_OP_ATC_INV		0x40
		#define ATC_INV_SIZE_ALL	52
		struct {
			u32			sid;
			u32			ssid;
			u64			addr;
			u8			size;
			bool			global;
		} atc;

		#define CMDQ_OP_PRI_RESP	0x41
		struct {
			u32			sid;
			u32			ssid;
			u16			grpid;
			enum pri_resp		resp;
		} pri;

		#define CMDQ_OP_RESUME		0x44
		struct {
			u32			sid;
			u16			stag;
			enum page_response_code	resp;
		} resume;

		#define CMDQ_OP_CMD_SYNC	0x46
		struct {
			u32			msidata;
			u64			msiaddr;
		} sync;
	};
};

struct arm_smmu_queue {
	int				irq; /* Wired interrupt */

	__le64				*base;
	dma_addr_t			base_dma;
	u64				q_base;

	size_t				ent_dwords;
	u32				max_n_shift;
	u32				prod;
	u32				cons;

	u32 __iomem			*prod_reg;
	u32 __iomem			*cons_reg;

	/* Event and PRI */
	u64				batch;
	wait_queue_head_t		wq;
};

struct arm_smmu_cmdq {
	struct arm_smmu_queue		q;
	spinlock_t			lock;
};

struct arm_smmu_evtq {
	struct arm_smmu_queue		q;
	u32				max_stalls;
};

struct arm_smmu_priq {
	struct arm_smmu_queue		q;
};

/* High-level stream table and context descriptor structures */
struct arm_smmu_strtab_l1_desc {
	u8				span;

	__le64				*l2ptr;
	dma_addr_t			l2ptr_dma;
};

struct arm_smmu_s1_cfg {
	struct iommu_pasid_table_cfg	tables;
	struct iommu_pasid_table_ops	*ops;
	struct iommu_pasid_entry	*cd0; /* Default context */
};

struct arm_smmu_s2_cfg {
	u16				vmid;
	u64				vttbr;
	u64				vtcr;
};

struct arm_smmu_strtab_ent {
	/*
	 * An STE is "assigned" if the master emitting the corresponding SID
	 * is attached to a domain. The behaviour of an unassigned STE is
	 * determined by the disable_bypass parameter, whereas an assigned
	 * STE behaves according to s1_cfg/s2_cfg, which themselves are
	 * configured according to the domain type.
	 */
	bool				assigned;
	struct arm_smmu_s1_cfg		*s1_cfg;
	struct arm_smmu_s2_cfg		*s2_cfg;

	bool				can_stall;
};

struct arm_smmu_strtab_cfg {
	__le64				*strtab;
	dma_addr_t			strtab_dma;
	struct arm_smmu_strtab_l1_desc	*l1_desc;
	unsigned int			num_l1_ents;

	u64				strtab_base;
	u32				strtab_base_cfg;
};

/* An SMMUv3 instance */
struct arm_smmu_device {
	struct device			*dev;
	void __iomem			*base;

#define ARM_SMMU_FEAT_2_LVL_STRTAB	(1 << 0)
#define ARM_SMMU_FEAT_2_LVL_CDTAB	(1 << 1)
#define ARM_SMMU_FEAT_TT_LE		(1 << 2)
#define ARM_SMMU_FEAT_TT_BE		(1 << 3)
#define ARM_SMMU_FEAT_PRI		(1 << 4)
#define ARM_SMMU_FEAT_ATS		(1 << 5)
#define ARM_SMMU_FEAT_SEV		(1 << 6)
#define ARM_SMMU_FEAT_MSI		(1 << 7)
#define ARM_SMMU_FEAT_COHERENCY		(1 << 8)
#define ARM_SMMU_FEAT_TRANS_S1		(1 << 9)
#define ARM_SMMU_FEAT_TRANS_S2		(1 << 10)
#define ARM_SMMU_FEAT_STALLS		(1 << 11)
#define ARM_SMMU_FEAT_HYP		(1 << 12)
#define ARM_SMMU_FEAT_STALL_FORCE	(1 << 13)
#define ARM_SMMU_FEAT_VAX		(1 << 14)
#define ARM_SMMU_FEAT_E2H		(1 << 15)
#define ARM_SMMU_FEAT_BTM		(1 << 16)
#define ARM_SMMU_FEAT_SVA		(1 << 17)
#define ARM_SMMU_FEAT_HA		(1 << 18)
#define ARM_SMMU_FEAT_HD		(1 << 19)
	u32				features;

#define ARM_SMMU_OPT_SKIP_PREFETCH	(1 << 0)
#define ARM_SMMU_OPT_PAGE0_REGS_ONLY	(1 << 1)
	u32				options;

	struct arm_smmu_cmdq		cmdq;
	struct arm_smmu_evtq		evtq;
	struct arm_smmu_priq		priq;

	int				gerr_irq;
	int				combined_irq;
	u32				sync_nr;
	u8				prev_cmd_opcode;

	unsigned long			ias; /* IPA */
	unsigned long			oas; /* PA */
	unsigned long			pgsize_bitmap;

	unsigned int			asid_bits;

#define ARM_SMMU_MAX_VMIDS		(1 << 16)
	unsigned int			vmid_bits;
	DECLARE_BITMAP(vmid_map, ARM_SMMU_MAX_VMIDS);

	unsigned int			ssid_bits;
	unsigned int			sid_bits;

	struct arm_smmu_strtab_cfg	strtab_cfg;

	/*
	 * The member "padding" is used to make sure the member "sync_count" to
	 * be aligned at 8 bytes boundary, and 4 bytes padding memory followed.
	 *
	 * These are required by hi1620 and earlier of Hisilicon. Because the
	 * ITS hardware on hi1620 and earlier will truncate the MSIAddress(Here
	 * it's the address of "sync_count") to 8 bytes boundary first, then
	 * write 32 bits MSIdata at offset 0, and 32 bits IMPDEF data at offset
	 * 4. Without this workaround, the adjacent member maybe overwritten.
	 *
	 *                    |---4bytes---|---4bytes---|
	 * MSIAddress & (~0x7):   MSIdata  | IMPDEF data|
	 */
	union {
		u32			sync_count;
		u64			padding;
	};

	/* IOMMU core code handle */
	struct iommu_device		iommu;

	struct rb_root			streams;
	struct mutex			streams_mutex;

	struct iopf_queue		*iopf_queue;
};

struct arm_smmu_stream {
	u32				id;
	struct arm_smmu_master_data	*master;
	struct rb_node			node;
};

/* SMMU private data for each master */
struct arm_smmu_master_data {
	struct arm_smmu_device		*smmu;
	struct arm_smmu_strtab_ent	ste;

	struct arm_smmu_domain		*domain;
	struct list_head		list; /* domain->devices */
	struct arm_smmu_stream		*streams;

	struct device			*dev;
	size_t				ssid_bits;
	bool				can_fault;
};

/* SMMU private data for an IOMMU domain */
enum arm_smmu_domain_stage {
	ARM_SMMU_DOMAIN_S1 = 0,
	ARM_SMMU_DOMAIN_S2,
	ARM_SMMU_DOMAIN_NESTED,
	ARM_SMMU_DOMAIN_BYPASS,
};

struct arm_smmu_domain {
	struct arm_smmu_device		*smmu;
	struct mutex			init_mutex; /* Protects smmu pointer */

	struct io_pgtable_ops		*pgtbl_ops;
	bool				non_strict;

	enum arm_smmu_domain_stage	stage;
	union {
		struct arm_smmu_s1_cfg	s1_cfg;
		struct arm_smmu_s2_cfg	s2_cfg;
	};

	struct iommu_domain		domain;

	struct list_head		devices;
	spinlock_t			devices_lock;
};

struct arm_smmu_mm {
	struct io_mm			io_mm;
	struct iommu_pasid_entry	*cd;
};

struct arm_smmu_option_prop {
	u32 opt;
	const char *prop;
};

static struct arm_smmu_option_prop arm_smmu_options[] = {
	{ ARM_SMMU_OPT_SKIP_PREFETCH, "hisilicon,broken-prefetch-cmd" },
	{ ARM_SMMU_OPT_PAGE0_REGS_ONLY, "cavium,cn9900-broken-page1-regspace"},
	{ 0, NULL},
};

static inline void __iomem *arm_smmu_page1_fixup(unsigned long offset,
						 struct arm_smmu_device *smmu)
{
	if ((offset > SZ_64K) &&
	    (smmu->options & ARM_SMMU_OPT_PAGE0_REGS_ONLY))
		offset -= SZ_64K;

	return smmu->base + offset;
}

static struct arm_smmu_domain *to_smmu_domain(struct iommu_domain *dom)
{
	return container_of(dom, struct arm_smmu_domain, domain);
}

static struct arm_smmu_mm *to_smmu_mm(struct io_mm *io_mm)
{
	return container_of(io_mm, struct arm_smmu_mm, io_mm);
}

static void parse_driver_options(struct arm_smmu_device *smmu)
{
	int i = 0;

	do {
		if (of_property_read_bool(smmu->dev->of_node,
						arm_smmu_options[i].prop)) {
			smmu->options |= arm_smmu_options[i].opt;
			dev_notice(smmu->dev, "option %s\n",
				arm_smmu_options[i].prop);
		}
	} while (arm_smmu_options[++i].opt);
}

/* Low-level queue manipulation functions */
static bool queue_full(struct arm_smmu_queue *q)
{
	return Q_IDX(q, q->prod) == Q_IDX(q, q->cons) &&
	       Q_WRP(q, q->prod) != Q_WRP(q, q->cons);
}

static bool queue_empty(struct arm_smmu_queue *q)
{
	return Q_IDX(q, q->prod) == Q_IDX(q, q->cons) &&
	       Q_WRP(q, q->prod) == Q_WRP(q, q->cons);
}

static void queue_sync_cons(struct arm_smmu_queue *q)
{
	q->cons = readl_relaxed(q->cons_reg);
}

static void queue_inc_cons(struct arm_smmu_queue *q)
{
	u32 cons = (Q_WRP(q, q->cons) | Q_IDX(q, q->cons)) + 1;

	q->cons = Q_OVF(q, q->cons) | Q_WRP(q, cons) | Q_IDX(q, cons);

	/*
	 * Ensure that all CPU accesses (reads and writes) to the queue
	 * are complete before we update the cons pointer.
	 */
	mb();
	writel_relaxed(q->cons, q->cons_reg);
}

static int queue_sync_prod(struct arm_smmu_queue *q)
{
	int ret = 0;
	u32 prod = readl_relaxed(q->prod_reg);

	if (Q_OVF(q, prod) != Q_OVF(q, q->prod))
		ret = -EOVERFLOW;

	q->prod = prod;
	return ret;
}

static void queue_inc_prod(struct arm_smmu_queue *q)
{
	u32 prod = (Q_WRP(q, q->prod) | Q_IDX(q, q->prod)) + 1;

	q->prod = Q_OVF(q, q->prod) | Q_WRP(q, prod) | Q_IDX(q, prod);
	writel(q->prod, q->prod_reg);
}

/*
 * Wait for the SMMU to consume items. If sync is true, wait until the queue
 * is empty. Otherwise, wait until there is at least one free slot.
 */
static int queue_poll_cons(struct arm_smmu_queue *q, bool sync, bool wfe)
{
	ktime_t timeout;
	unsigned int delay = 1, spin_cnt = 0;

	/* Wait longer if it's a CMD_SYNC */
	timeout = ktime_add_us(ktime_get(), sync ?
					    ARM_SMMU_CMDQ_SYNC_TIMEOUT_US :
					    ARM_SMMU_POLL_TIMEOUT_US);

	while (queue_sync_cons(q), (sync ? !queue_empty(q) : queue_full(q))) {
		if (ktime_compare(ktime_get(), timeout) > 0)
			return -ETIMEDOUT;

		if (wfe) {
			wfe();
		} else if (++spin_cnt < ARM_SMMU_CMDQ_SYNC_SPIN_COUNT) {
			cpu_relax();
			continue;
		} else {
			udelay(delay);
			delay *= 2;
			spin_cnt = 0;
		}
	}

	return 0;
}

static void queue_write(__le64 *dst, u64 *src, size_t n_dwords)
{
	int i;

	for (i = 0; i < n_dwords; ++i)
		*dst++ = cpu_to_le64(*src++);
}

static int queue_insert_raw(struct arm_smmu_queue *q, u64 *ent)
{
	if (queue_full(q))
		return -ENOSPC;

	queue_write(Q_ENT(q, q->prod), ent, q->ent_dwords);
	queue_inc_prod(q);
	return 0;
}

static void queue_read(__le64 *dst, u64 *src, size_t n_dwords)
{
	int i;

	for (i = 0; i < n_dwords; ++i)
		*dst++ = le64_to_cpu(*src++);
}

static int queue_remove_raw(struct arm_smmu_queue *q, u64 *ent)
{
	if (queue_empty(q))
		return -EAGAIN;

	queue_read(ent, Q_ENT(q, q->cons), q->ent_dwords);
	queue_inc_cons(q);
	return 0;
}

/* High-level queue accessors */
static int arm_smmu_cmdq_build_cmd(u64 *cmd, struct arm_smmu_cmdq_ent *ent)
{
	memset(cmd, 0, CMDQ_ENT_DWORDS << 3);
	cmd[0] |= FIELD_PREP(CMDQ_0_OP, ent->opcode);

	switch (ent->opcode) {
	case CMDQ_OP_TLBI_EL2_ALL:
	case CMDQ_OP_TLBI_NSNH_ALL:
		break;
	case CMDQ_OP_PREFETCH_CFG:
		cmd[0] |= FIELD_PREP(CMDQ_PREFETCH_0_SID, ent->prefetch.sid);
		cmd[1] |= FIELD_PREP(CMDQ_PREFETCH_1_SIZE, ent->prefetch.size);
		cmd[1] |= ent->prefetch.addr & CMDQ_PREFETCH_1_ADDR_MASK;
		break;
	case CMDQ_OP_CFGI_CD:
		cmd[0] |= FIELD_PREP(CMDQ_CFGI_0_SSID, ent->cfgi.ssid);
		/* Fallthrough */
	case CMDQ_OP_CFGI_STE:
		cmd[0] |= FIELD_PREP(CMDQ_CFGI_0_SID, ent->cfgi.sid);
		cmd[1] |= FIELD_PREP(CMDQ_CFGI_1_LEAF, ent->cfgi.leaf);
		break;
	case CMDQ_OP_CFGI_CD_ALL:
		cmd[0] |= FIELD_PREP(CMDQ_CFGI_0_SID, ent->cfgi.sid);
		break;
	case CMDQ_OP_CFGI_ALL:
		/* Cover the entire SID range */
		cmd[1] |= FIELD_PREP(CMDQ_CFGI_1_RANGE, 31);
		break;
	case CMDQ_OP_TLBI_NH_VA:
	case CMDQ_OP_TLBI_EL2_VA:
		cmd[0] |= FIELD_PREP(CMDQ_TLBI_0_ASID, ent->tlbi.asid);
		cmd[1] |= FIELD_PREP(CMDQ_TLBI_1_LEAF, ent->tlbi.leaf);
		cmd[1] |= ent->tlbi.addr & CMDQ_TLBI_1_VA_MASK;
		break;
	case CMDQ_OP_TLBI_S2_IPA:
		cmd[0] |= FIELD_PREP(CMDQ_TLBI_0_VMID, ent->tlbi.vmid);
		cmd[1] |= FIELD_PREP(CMDQ_TLBI_1_LEAF, ent->tlbi.leaf);
		cmd[1] |= ent->tlbi.addr & CMDQ_TLBI_1_IPA_MASK;
		break;
	case CMDQ_OP_TLBI_NH_ASID:
		cmd[0] |= FIELD_PREP(CMDQ_TLBI_0_ASID, ent->tlbi.asid);
		/* Fallthrough */
	case CMDQ_OP_TLBI_S12_VMALL:
		cmd[0] |= FIELD_PREP(CMDQ_TLBI_0_VMID, ent->tlbi.vmid);
		break;
	case CMDQ_OP_TLBI_EL2_ASID:
		cmd[0] |= FIELD_PREP(CMDQ_TLBI_0_ASID, ent->tlbi.asid);
		break;
	case CMDQ_OP_ATC_INV:
		cmd[0] |= FIELD_PREP(CMDQ_0_SSV, ent->substream_valid);
		cmd[0] |= FIELD_PREP(CMDQ_ATC_0_GLOBAL, ent->atc.global);
		cmd[0] |= FIELD_PREP(CMDQ_ATC_0_SSID, ent->atc.ssid);
		cmd[0] |= FIELD_PREP(CMDQ_ATC_0_SID, ent->atc.sid);
		cmd[1] |= FIELD_PREP(CMDQ_ATC_1_SIZE, ent->atc.size);
		cmd[1] |= ent->atc.addr & CMDQ_ATC_1_ADDR_MASK;
		break;
	case CMDQ_OP_PRI_RESP:
		cmd[0] |= FIELD_PREP(CMDQ_0_SSV, ent->substream_valid);
		cmd[0] |= FIELD_PREP(CMDQ_PRI_0_SSID, ent->pri.ssid);
		cmd[0] |= FIELD_PREP(CMDQ_PRI_0_SID, ent->pri.sid);
		cmd[1] |= FIELD_PREP(CMDQ_PRI_1_GRPID, ent->pri.grpid);
		switch (ent->pri.resp) {
		case PRI_RESP_DENY:
		case PRI_RESP_FAIL:
		case PRI_RESP_SUCC:
			break;
		default:
			return -EINVAL;
		}
		cmd[1] |= FIELD_PREP(CMDQ_PRI_1_RESP, ent->pri.resp);
		break;
	case CMDQ_OP_RESUME:
		cmd[0] |= FIELD_PREP(CMDQ_RESUME_0_SID, ent->resume.sid);
		cmd[1] |= FIELD_PREP(CMDQ_RESUME_1_STAG, ent->resume.stag);
		switch (ent->resume.resp) {
		case IOMMU_PAGE_RESP_INVALID:
		case IOMMU_PAGE_RESP_FAILURE:
			cmd[0] |= CMDQ_RESUME_0_ACTION_ABORT;
			break;
		case IOMMU_PAGE_RESP_SUCCESS:
			cmd[0] |= CMDQ_RESUME_0_ACTION_RETRY;
			break;
		default:
			return -EINVAL;
		}
		break;
	case CMDQ_OP_CMD_SYNC:
		if (ent->sync.msiaddr)
			cmd[0] |= FIELD_PREP(CMDQ_SYNC_0_CS, CMDQ_SYNC_0_CS_IRQ);
		else
			cmd[0] |= FIELD_PREP(CMDQ_SYNC_0_CS, CMDQ_SYNC_0_CS_SEV);
		cmd[0] |= FIELD_PREP(CMDQ_SYNC_0_MSH, ARM_SMMU_SH_ISH);
		cmd[0] |= FIELD_PREP(CMDQ_SYNC_0_MSIATTR, ARM_SMMU_MEMATTR_OIWB);
		/*
		 * Commands are written little-endian, but we want the SMMU to
		 * receive MSIData, and thus write it back to memory, in CPU
		 * byte order, so big-endian needs an extra byteswap here.
		 */
		cmd[0] |= FIELD_PREP(CMDQ_SYNC_0_MSIDATA,
				     cpu_to_le32(ent->sync.msidata));
		cmd[1] |= ent->sync.msiaddr & CMDQ_SYNC_1_MSIADDR_MASK;
		break;
	default:
		return -ENOENT;
	}

	return 0;
}

static void arm_smmu_cmdq_skip_err(struct arm_smmu_device *smmu)
{
	static const char *cerror_str[] = {
		[CMDQ_ERR_CERROR_NONE_IDX]	= "No error",
		[CMDQ_ERR_CERROR_ILL_IDX]	= "Illegal command",
		[CMDQ_ERR_CERROR_ABT_IDX]	= "Abort on command fetch",
		[CMDQ_ERR_CERROR_ATC_INV_IDX]	= "ATC invalidate timeout",
	};

	int i;
	u64 cmd[CMDQ_ENT_DWORDS];
	struct arm_smmu_queue *q = &smmu->cmdq.q;
	u32 cons = readl_relaxed(q->cons_reg);
	u32 idx = FIELD_GET(CMDQ_CONS_ERR, cons);
	struct arm_smmu_cmdq_ent cmd_sync = {
		.opcode = CMDQ_OP_CMD_SYNC,
	};

	dev_err(smmu->dev, "CMDQ error (cons 0x%08x): %s\n", cons,
		idx < ARRAY_SIZE(cerror_str) ?  cerror_str[idx] : "Unknown");

	switch (idx) {
	case CMDQ_ERR_CERROR_ABT_IDX:
		dev_err(smmu->dev, "retrying command fetch\n");
	case CMDQ_ERR_CERROR_NONE_IDX:
		return;
	case CMDQ_ERR_CERROR_ATC_INV_IDX:
		/*
		 * ATC Invalidation Completion timeout. CONS is still pointing
		 * at the CMD_SYNC. Attempt to complete other pending commands
		 * by repeating the CMD_SYNC, though we might well end up back
		 * here since the ATC invalidation may still be pending.
		 */
		return;
	case CMDQ_ERR_CERROR_ILL_IDX:
		/* Fallthrough */
	default:
		break;
	}

	/*
	 * We may have concurrent producers, so we need to be careful
	 * not to touch any of the shadow cmdq state.
	 */
	queue_read(cmd, Q_ENT(q, cons), q->ent_dwords);
	dev_err(smmu->dev, "skipping command in error state:\n");
	for (i = 0; i < ARRAY_SIZE(cmd); ++i)
		dev_err(smmu->dev, "\t0x%016llx\n", (unsigned long long)cmd[i]);

	/* Convert the erroneous command into a CMD_SYNC */
	if (arm_smmu_cmdq_build_cmd(cmd, &cmd_sync)) {
		dev_err(smmu->dev, "failed to convert to CMD_SYNC\n");
		return;
	}

	queue_write(Q_ENT(q, cons), cmd, q->ent_dwords);
}

static void arm_smmu_cmdq_insert_cmd(struct arm_smmu_device *smmu, u64 *cmd)
{
	struct arm_smmu_queue *q = &smmu->cmdq.q;
	bool wfe = !!(smmu->features & ARM_SMMU_FEAT_SEV);

	smmu->prev_cmd_opcode = FIELD_GET(CMDQ_0_OP, cmd[0]);

	while (queue_insert_raw(q, cmd) == -ENOSPC) {
		if (queue_poll_cons(q, false, wfe))
			dev_err_ratelimited(smmu->dev, "CMDQ timeout\n");
	}
}

static void arm_smmu_cmdq_issue_cmd(struct arm_smmu_device *smmu,
				    struct arm_smmu_cmdq_ent *ent)
{
	u64 cmd[CMDQ_ENT_DWORDS];
	unsigned long flags;

	if (arm_smmu_cmdq_build_cmd(cmd, ent)) {
		dev_warn(smmu->dev, "ignoring unknown CMDQ opcode 0x%x\n",
			 ent->opcode);
		return;
	}

	spin_lock_irqsave(&smmu->cmdq.lock, flags);
	arm_smmu_cmdq_insert_cmd(smmu, cmd);
	spin_unlock_irqrestore(&smmu->cmdq.lock, flags);
}

/*
 * The difference between val and sync_idx is bounded by the maximum size of
 * a queue at 2^20 entries, so 32 bits is plenty for wrap-safe arithmetic.
 */
static int __arm_smmu_sync_poll_msi(struct arm_smmu_device *smmu, u32 sync_idx)
{
	ktime_t timeout;
	u32 val;

	timeout = ktime_add_us(ktime_get(), ARM_SMMU_CMDQ_SYNC_TIMEOUT_US);
	val = smp_cond_load_acquire(&smmu->sync_count,
				    (int)(VAL - sync_idx) >= 0 ||
				    !ktime_before(ktime_get(), timeout));

	return (int)(val - sync_idx) < 0 ? -ETIMEDOUT : 0;
}

static int __arm_smmu_cmdq_issue_sync_msi(struct arm_smmu_device *smmu)
{
	u64 cmd[CMDQ_ENT_DWORDS];
	unsigned long flags;
	struct arm_smmu_cmdq_ent ent = {
		.opcode = CMDQ_OP_CMD_SYNC,
		.sync	= {
			.msiaddr = virt_to_phys(&smmu->sync_count),
		},
	};

	spin_lock_irqsave(&smmu->cmdq.lock, flags);

	/* Piggy-back on the previous command if it's a SYNC */
	if (smmu->prev_cmd_opcode == CMDQ_OP_CMD_SYNC) {
		ent.sync.msidata = smmu->sync_nr;
	} else {
		ent.sync.msidata = ++smmu->sync_nr;
		arm_smmu_cmdq_build_cmd(cmd, &ent);
		arm_smmu_cmdq_insert_cmd(smmu, cmd);
	}

	spin_unlock_irqrestore(&smmu->cmdq.lock, flags);

	return __arm_smmu_sync_poll_msi(smmu, ent.sync.msidata);
}

static int __arm_smmu_cmdq_issue_sync(struct arm_smmu_device *smmu)
{
	u64 cmd[CMDQ_ENT_DWORDS];
	unsigned long flags;
	bool wfe = !!(smmu->features & ARM_SMMU_FEAT_SEV);
	struct arm_smmu_cmdq_ent ent = { .opcode = CMDQ_OP_CMD_SYNC };
	int ret;

	arm_smmu_cmdq_build_cmd(cmd, &ent);

	spin_lock_irqsave(&smmu->cmdq.lock, flags);
	arm_smmu_cmdq_insert_cmd(smmu, cmd);
	ret = queue_poll_cons(&smmu->cmdq.q, true, wfe);
	spin_unlock_irqrestore(&smmu->cmdq.lock, flags);

	return ret;
}

static void arm_smmu_cmdq_issue_sync(struct arm_smmu_device *smmu)
{
	int ret;
	bool msi = (smmu->features & ARM_SMMU_FEAT_MSI) &&
		   (smmu->features & ARM_SMMU_FEAT_COHERENCY);

	ret = msi ? __arm_smmu_cmdq_issue_sync_msi(smmu)
		  : __arm_smmu_cmdq_issue_sync(smmu);
	if (ret)
		dev_err_ratelimited(smmu->dev, "CMD_SYNC timeout\n");
}

static int arm_smmu_page_response(struct device *dev,
				  struct page_response_msg *resp)
{
	int sid = dev->iommu_fwspec->ids[0];
	struct arm_smmu_cmdq_ent cmd = {0};
	struct arm_smmu_master_data *master = dev->iommu_fwspec->iommu_priv;

	if (master->ste.can_stall) {
		cmd.opcode		= CMDQ_OP_RESUME;
		cmd.resume.sid		= sid;
		cmd.resume.stag		= resp->page_req_group_id;
		cmd.resume.resp		= resp->resp_code;
	} else {
		/* TODO: put PRI response here */
		return -ENODEV;
	}

	arm_smmu_cmdq_issue_cmd(master->smmu, &cmd);
	/*
	 * Don't send a SYNC, it doesn't do anything for RESUME or PRI_RESP.
	 * RESUME consumption guarantees that the stalled transaction will be
	 * terminated... at some point in the future. PRI_RESP is fire and
	 * forget.
	 */

	return 0;
}

/* Stream table manipulation functions */
static void
arm_smmu_write_strtab_l1_desc(__le64 *dst, struct arm_smmu_strtab_l1_desc *desc)
{
	u64 val = 0;

	val |= FIELD_PREP(STRTAB_L1_DESC_SPAN, desc->span);
	val |= desc->l2ptr_dma & STRTAB_L1_DESC_L2PTR_MASK;

	*dst = cpu_to_le64(val);
}

static void arm_smmu_sync_ste_for_sid(struct arm_smmu_device *smmu, u32 sid)
{
	struct arm_smmu_cmdq_ent cmd = {
		.opcode	= CMDQ_OP_CFGI_STE,
		.cfgi	= {
			.sid	= sid,
			.leaf	= true,
		},
	};

	arm_smmu_cmdq_issue_cmd(smmu, &cmd);
	arm_smmu_cmdq_issue_sync(smmu);
}

static void arm_smmu_write_strtab_ent(struct arm_smmu_device *smmu, u32 sid,
				      __le64 *dst, struct arm_smmu_strtab_ent *ste)
{
	/*
	 * This is hideously complicated, but we only really care about
	 * three cases at the moment:
	 *
	 * 1. Invalid (all zero) -> bypass/fault (init)
	 * 2. Bypass/fault -> translation/bypass (attach)
	 * 3. Translation/bypass -> bypass/fault (detach)
	 *
	 * Given that we can't update the STE atomically and the SMMU
	 * doesn't read the thing in a defined order, that leaves us
	 * with the following maintenance requirements:
	 *
	 * 1. Update Config, return (init time STEs aren't live)
	 * 2. Write everything apart from dword 0, sync, write dword 0, sync
	 * 3. Update Config, sync
	 */
	u64 val = le64_to_cpu(dst[0]);
	bool ste_live = false;
	struct arm_smmu_cmdq_ent prefetch_cmd = {
		.opcode		= CMDQ_OP_PREFETCH_CFG,
		.prefetch	= {
			.sid	= sid,
		},
	};

	if (val & STRTAB_STE_0_V) {
		switch (FIELD_GET(STRTAB_STE_0_CFG, val)) {
		case STRTAB_STE_0_CFG_BYPASS:
			break;
		case STRTAB_STE_0_CFG_S1_TRANS:
		case STRTAB_STE_0_CFG_S2_TRANS:
			ste_live = true;
			break;
		case STRTAB_STE_0_CFG_ABORT:
			if (disable_bypass)
				break;
		default:
			BUG(); /* STE corruption */
		}
	}

	/* Nuke the existing STE_0 value, as we're going to rewrite it */
	val = STRTAB_STE_0_V;

	/* Bypass/fault */
	if (!ste->assigned || !(ste->s1_cfg || ste->s2_cfg)) {
		if (!ste->assigned && disable_bypass)
			val |= FIELD_PREP(STRTAB_STE_0_CFG, STRTAB_STE_0_CFG_ABORT);
		else
			val |= FIELD_PREP(STRTAB_STE_0_CFG, STRTAB_STE_0_CFG_BYPASS);

		dst[0] = cpu_to_le64(val);
		dst[1] = cpu_to_le64(FIELD_PREP(STRTAB_STE_1_SHCFG,
						STRTAB_STE_1_SHCFG_INCOMING));
		dst[2] = 0; /* Nuke the VMID */
		/*
		 * The SMMU can perform negative caching, so we must sync
		 * the STE regardless of whether the old value was live.
		 */
		if (smmu)
			arm_smmu_sync_ste_for_sid(smmu, sid);
		return;
	}

	if (ste->s1_cfg) {
		struct iommu_pasid_table_cfg *cfg = &ste->s1_cfg->tables;
		int strw = smmu->features & ARM_SMMU_FEAT_E2H ?
			STRTAB_STE_1_STRW_EL2 : STRTAB_STE_1_STRW_NSEL1;

		BUG_ON(ste_live);
		dst[1] = cpu_to_le64(
			 FIELD_PREP(STRTAB_STE_1_S1DSS, STRTAB_STE_1_S1DSS_SSID0) |
			 FIELD_PREP(STRTAB_STE_1_S1CIR, STRTAB_STE_1_S1C_CACHE_WBRA) |
			 FIELD_PREP(STRTAB_STE_1_S1COR, STRTAB_STE_1_S1C_CACHE_WBRA) |
			 FIELD_PREP(STRTAB_STE_1_S1CSH, ARM_SMMU_SH_ISH) |
			 FIELD_PREP(STRTAB_STE_1_STRW, strw));

		if (smmu->features & ARM_SMMU_FEAT_STALLS &&
		   !(smmu->features & ARM_SMMU_FEAT_STALL_FORCE) &&
		   !ste->can_stall)
			dst[1] |= cpu_to_le64(STRTAB_STE_1_S1STALLD);

		val |= (ste->s1_cfg->tables.base & STRTAB_STE_0_S1CTXPTR_MASK) |
			FIELD_PREP(STRTAB_STE_0_CFG, STRTAB_STE_0_CFG_S1_TRANS) |
			FIELD_PREP(STRTAB_STE_0_S1CDMAX, cfg->order) |
			FIELD_PREP(STRTAB_STE_0_S1FMT, cfg->arm_smmu.s1fmt);
	}

	if (ste->s2_cfg) {
		BUG_ON(ste_live);
		dst[2] = cpu_to_le64(
			 FIELD_PREP(STRTAB_STE_2_S2VMID, ste->s2_cfg->vmid) |
			 FIELD_PREP(STRTAB_STE_2_VTCR, ste->s2_cfg->vtcr) |
#ifdef __BIG_ENDIAN
			 STRTAB_STE_2_S2ENDI |
#endif
			 STRTAB_STE_2_S2PTW | STRTAB_STE_2_S2AA64 |
			 STRTAB_STE_2_S2R);

		dst[3] = cpu_to_le64(ste->s2_cfg->vttbr & STRTAB_STE_3_S2TTB_MASK);

		val |= FIELD_PREP(STRTAB_STE_0_CFG, STRTAB_STE_0_CFG_S2_TRANS);
	}

	if (IS_ENABLED(CONFIG_PCI_ATS))
		dst[1] |= cpu_to_le64(FIELD_PREP(STRTAB_STE_1_EATS,
						 STRTAB_STE_1_EATS_TRANS));

	arm_smmu_sync_ste_for_sid(smmu, sid);
	dst[0] = cpu_to_le64(val);
	arm_smmu_sync_ste_for_sid(smmu, sid);

	/* It's likely that we'll want to use the new STE soon */
	if (!(smmu->options & ARM_SMMU_OPT_SKIP_PREFETCH))
		arm_smmu_cmdq_issue_cmd(smmu, &prefetch_cmd);
}

static void arm_smmu_init_bypass_stes(u64 *strtab, unsigned int nent)
{
	unsigned int i;
	struct arm_smmu_strtab_ent ste = { .assigned = false };

	for (i = 0; i < nent; ++i) {
		arm_smmu_write_strtab_ent(NULL, -1, strtab, &ste);
		strtab += STRTAB_STE_DWORDS;
	}
}

static int arm_smmu_init_l2_strtab(struct arm_smmu_device *smmu, u32 sid)
{
	size_t size;
	void *strtab;
	struct arm_smmu_strtab_cfg *cfg = &smmu->strtab_cfg;
	struct arm_smmu_strtab_l1_desc *desc = &cfg->l1_desc[sid >> STRTAB_SPLIT];

	if (desc->l2ptr)
		return 0;

	size = 1 << (STRTAB_SPLIT + ilog2(STRTAB_STE_DWORDS) + 3);
	strtab = &cfg->strtab[(sid >> STRTAB_SPLIT) * STRTAB_L1_DESC_DWORDS];

	desc->span = STRTAB_SPLIT + 1;
	desc->l2ptr = dmam_alloc_coherent(smmu->dev, size, &desc->l2ptr_dma,
					  GFP_KERNEL | __GFP_ZERO);
	if (!desc->l2ptr) {
		dev_err(smmu->dev,
			"failed to allocate l2 stream table for SID %u\n",
			sid);
		return -ENOMEM;
	}

	arm_smmu_init_bypass_stes(desc->l2ptr, 1 << STRTAB_SPLIT);
	arm_smmu_write_strtab_l1_desc(strtab, desc);
	return 0;
}

static struct arm_smmu_master_data *
arm_smmu_find_master(struct arm_smmu_device *smmu, u32 sid)
{
	struct rb_node *node;
	struct arm_smmu_stream *stream;
	struct arm_smmu_master_data *master = NULL;

	mutex_lock(&smmu->streams_mutex);
	node = smmu->streams.rb_node;
	while (node) {
		stream = rb_entry(node, struct arm_smmu_stream, node);
		if (stream->id < sid) {
			node = node->rb_right;
		} else if (stream->id > sid) {
			node = node->rb_left;
		} else {
			master = stream->master;
			break;
		}
	}
	mutex_unlock(&smmu->streams_mutex);

	return master;
}

static int arm_smmu_handle_evt(struct arm_smmu_device *smmu, u64 *evt)
{
	int ret;
	struct arm_smmu_master_data *master;
	u8 type = FIELD_GET(EVTQ_0_ID, evt[0]);
	u32 sid = FIELD_GET(EVTQ_0_SID, evt[0]);

	struct iommu_fault_event fault = {
		.page_req_group_id	= FIELD_GET(EVTQ_1_STAG, evt[1]),
		.addr			= FIELD_GET(EVTQ_2_ADDR, evt[2]),
		.last_req		= true,
	};

	switch (type) {
	case EVT_ID_TRANSLATION_FAULT:
	case EVT_ID_ADDR_SIZE_FAULT:
	case EVT_ID_ACCESS_FAULT:
		fault.reason = IOMMU_FAULT_REASON_PTE_FETCH;
		break;
	case EVT_ID_PERMISSION_FAULT:
		fault.reason = IOMMU_FAULT_REASON_PERMISSION;
		break;
	default:
		/* TODO: report other unrecoverable faults. */
		return -EFAULT;
	}

	/* Stage-2 is always pinned at the moment */
	if (evt[1] & EVTQ_1_S2)
		return -EFAULT;

	master = arm_smmu_find_master(smmu, sid);
	if (!master)
		return -EINVAL;

	/*
	 * The domain is valid until the fault returns, because detach() flushes
	 * the fault queue.
	 */
	if (evt[1] & EVTQ_1_STALL)
		fault.type = IOMMU_FAULT_PAGE_REQ;
	else
		fault.type = IOMMU_FAULT_DMA_UNRECOV;

	if (evt[1] & EVTQ_1_READ)
		fault.prot |= IOMMU_FAULT_READ;
	else
		fault.prot |= IOMMU_FAULT_WRITE;

	if (evt[1] & EVTQ_1_EXEC)
		fault.prot |= IOMMU_FAULT_EXEC;

	if (evt[1] & EVTQ_1_PRIV)
		fault.prot |= IOMMU_FAULT_PRIV;

	if (evt[0] & EVTQ_0_SSV) {
		fault.pasid_valid = true;
		fault.pasid = FIELD_GET(EVTQ_0_SSID, evt[0]);
	}

	ret = iommu_report_device_fault(master->dev, &fault);
	if (ret && fault.type == IOMMU_FAULT_PAGE_REQ) {
		/* Nobody cared, abort the access */
		struct page_response_msg resp = {
			.addr			= fault.addr,
			.pasid			= fault.pasid,
			.pasid_present		= fault.pasid_valid,
			.page_req_group_id	= fault.page_req_group_id,
			.resp_code		= IOMMU_PAGE_RESP_FAILURE,
		};
		arm_smmu_page_response(master->dev, &resp);
	}

	return ret;
}

/* IRQ and event handlers */
static irqreturn_t arm_smmu_evtq_thread(int irq, void *dev)
{
	int i, ret;
	int num_handled = 0;
	struct arm_smmu_device *smmu = dev;
	struct arm_smmu_queue *q = &smmu->evtq.q;
	size_t queue_size = 1 << q->max_n_shift;
	u64 evt[EVTQ_ENT_DWORDS];

	spin_lock(&q->wq.lock);
	do {
		while (!queue_remove_raw(q, evt)) {
			u8 id = FIELD_GET(EVTQ_0_ID, evt[0]);

			spin_unlock(&q->wq.lock);
			ret = arm_smmu_handle_evt(smmu, evt);
			spin_lock(&q->wq.lock);

			if (++num_handled == queue_size) {
				q->batch++;
				wake_up_all_locked(&q->wq);
				num_handled = 0;
			}

			if (!ret)
				continue;

			dev_info(smmu->dev, "event 0x%02x received:\n", id);
			for (i = 0; i < ARRAY_SIZE(evt); ++i)
				dev_info(smmu->dev, "\t0x%016llx\n",
					 (unsigned long long)evt[i]);

		}

		/*
		 * Not much we can do on overflow, so scream and pretend we're
		 * trying harder.
		 */
		if (queue_sync_prod(q) == -EOVERFLOW)
			dev_err(smmu->dev, "EVTQ overflow detected -- events lost\n");
	} while (!queue_empty(q));

	/* Sync our overflow flag, as we believe we're up to speed */
	q->cons = Q_OVF(q, q->prod) | Q_WRP(q, q->cons) | Q_IDX(q, q->cons);

	q->batch++;
	wake_up_all_locked(&q->wq);
	spin_unlock(&q->wq.lock);

	return IRQ_HANDLED;
}

static void arm_smmu_handle_ppr(struct arm_smmu_device *smmu, u64 *evt)
{
	u32 sid, ssid;
	u16 grpid;
	bool ssv, last;

	sid = FIELD_GET(PRIQ_0_SID, evt[0]);
	ssv = FIELD_GET(PRIQ_0_SSID_V, evt[0]);
	ssid = ssv ? FIELD_GET(PRIQ_0_SSID, evt[0]) : 0;
	last = FIELD_GET(PRIQ_0_PRG_LAST, evt[0]);
	grpid = FIELD_GET(PRIQ_1_PRG_IDX, evt[1]);

	dev_info(smmu->dev, "unexpected PRI request received:\n");
	dev_info(smmu->dev,
		 "\tsid 0x%08x.0x%05x: [%u%s] %sprivileged %s%s%s access at iova 0x%016llx\n",
		 sid, ssid, grpid, last ? "L" : "",
		 evt[0] & PRIQ_0_PERM_PRIV ? "" : "un",
		 evt[0] & PRIQ_0_PERM_READ ? "R" : "",
		 evt[0] & PRIQ_0_PERM_WRITE ? "W" : "",
		 evt[0] & PRIQ_0_PERM_EXEC ? "X" : "",
		 evt[1] & PRIQ_1_ADDR_MASK);

	if (last) {
		struct arm_smmu_cmdq_ent cmd = {
			.opcode			= CMDQ_OP_PRI_RESP,
			.substream_valid	= ssv,
			.pri			= {
				.sid	= sid,
				.ssid	= ssid,
				.grpid	= grpid,
				.resp	= PRI_RESP_DENY,
			},
		};

		arm_smmu_cmdq_issue_cmd(smmu, &cmd);
	}
}

static irqreturn_t arm_smmu_priq_thread(int irq, void *dev)
{
	int num_handled = 0;
	struct arm_smmu_device *smmu = dev;
	struct arm_smmu_queue *q = &smmu->priq.q;
	size_t queue_size = 1 << q->max_n_shift;
	u64 evt[PRIQ_ENT_DWORDS];

	spin_lock(&q->wq.lock);
	do {
		while (!queue_remove_raw(q, evt)) {
			spin_unlock(&q->wq.lock);
			arm_smmu_handle_ppr(smmu, evt);
			spin_lock(&q->wq.lock);
			if (++num_handled == queue_size) {
				q->batch++;
				wake_up_all_locked(&q->wq);
				num_handled = 0;
			}
		}

		if (queue_sync_prod(q) == -EOVERFLOW)
			dev_err(smmu->dev, "PRIQ overflow detected -- requests lost\n");
	} while (!queue_empty(q));

	/* Sync our overflow flag, as we believe we're up to speed */
	q->cons = Q_OVF(q, q->prod) | Q_WRP(q, q->cons) | Q_IDX(q, q->cons);
	writel(q->cons, q->cons_reg);

	q->batch++;
	wake_up_all_locked(&q->wq);
	spin_unlock(&q->wq.lock);

	return IRQ_HANDLED;
}

/*
 * arm_smmu_flush_queue - wait until all events/PPRs currently in the queue have
 * been consumed.
 *
 * Wait until the queue thread finished a batch, or until the queue is empty.
 * Note that we don't handle overflows on q->batch. If it occurs, just wait for
 * the queue to be empty.
 */
static int arm_smmu_flush_queue(struct arm_smmu_device *smmu,
				struct arm_smmu_queue *q, const char *name)
{
	int ret;
	u64 batch;

	spin_lock(&q->wq.lock);
	if (queue_sync_prod(q) == -EOVERFLOW)
		dev_err(smmu->dev, "%s overflow detected -- requests lost\n",
			name);

	batch = q->batch;
	ret = wait_event_interruptible_locked(q->wq, queue_empty(q) ||
					      q->batch >= batch + 2);
	spin_unlock(&q->wq.lock);

	return ret;
}

static int arm_smmu_flush_queues(void *cookie, struct device *dev)
{
	struct arm_smmu_master_data *master;
	struct arm_smmu_device *smmu = cookie;

	if (dev) {
		master = dev->iommu_fwspec->iommu_priv;
		if (master->ste.can_stall)
			arm_smmu_flush_queue(smmu, &smmu->evtq.q, "evtq");
		/* TODO: add support for PRI */
		return 0;
	}

	/* No target device, flush all queues. */
	if (smmu->features & ARM_SMMU_FEAT_STALLS)
		arm_smmu_flush_queue(smmu, &smmu->evtq.q, "evtq");
	if (smmu->features & ARM_SMMU_FEAT_PRI)
		arm_smmu_flush_queue(smmu, &smmu->priq.q, "priq");

	return 0;
}

static int arm_smmu_device_disable(struct arm_smmu_device *smmu);

static irqreturn_t arm_smmu_gerror_handler(int irq, void *dev)
{
	u32 gerror, gerrorn, active;
	struct arm_smmu_device *smmu = dev;

	gerror = readl_relaxed(smmu->base + ARM_SMMU_GERROR);
	gerrorn = readl_relaxed(smmu->base + ARM_SMMU_GERRORN);

	active = gerror ^ gerrorn;
	if (!(active & GERROR_ERR_MASK))
		return IRQ_NONE; /* No errors pending */

	dev_warn(smmu->dev,
		 "unexpected global error reported (0x%08x), this could be serious\n",
		 active);

	if (active & GERROR_SFM_ERR) {
		dev_err(smmu->dev, "device has entered Service Failure Mode!\n");
		arm_smmu_device_disable(smmu);
	}

	if (active & GERROR_MSI_GERROR_ABT_ERR)
		dev_warn(smmu->dev, "GERROR MSI write aborted\n");

	if (active & GERROR_MSI_PRIQ_ABT_ERR)
		dev_warn(smmu->dev, "PRIQ MSI write aborted\n");

	if (active & GERROR_MSI_EVTQ_ABT_ERR)
		dev_warn(smmu->dev, "EVTQ MSI write aborted\n");

	if (active & GERROR_MSI_CMDQ_ABT_ERR)
		dev_warn(smmu->dev, "CMDQ MSI write aborted\n");

	if (active & GERROR_PRIQ_ABT_ERR)
		dev_err(smmu->dev, "PRIQ write aborted -- events may have been lost\n");

	if (active & GERROR_EVTQ_ABT_ERR)
		dev_err(smmu->dev, "EVTQ write aborted -- events may have been lost\n");

	if (active & GERROR_CMDQ_ERR)
		arm_smmu_cmdq_skip_err(smmu);

	writel(gerror, smmu->base + ARM_SMMU_GERRORN);
	return IRQ_HANDLED;
}

static irqreturn_t arm_smmu_combined_irq_thread(int irq, void *dev)
{
	struct arm_smmu_device *smmu = dev;

	arm_smmu_evtq_thread(irq, dev);
	if (smmu->features & ARM_SMMU_FEAT_PRI)
		arm_smmu_priq_thread(irq, dev);

	return IRQ_HANDLED;
}

static irqreturn_t arm_smmu_combined_irq_handler(int irq, void *dev)
{
	arm_smmu_gerror_handler(irq, dev);
	return IRQ_WAKE_THREAD;
}

/* ATS invalidation */
static bool arm_smmu_master_has_ats(struct arm_smmu_master_data *master)
{
	return dev_is_pci(master->dev) && to_pci_dev(master->dev)->ats_enabled;
}

static void
arm_smmu_atc_inv_to_cmd(int ssid, unsigned long iova, size_t size,
			struct arm_smmu_cmdq_ent *cmd)
{
	size_t log2_span;
	size_t span_mask;
	/* ATC invalidates are always on 4096 bytes pages */
	size_t inval_grain_shift = 12;
	unsigned long page_start, page_end;

	*cmd = (struct arm_smmu_cmdq_ent) {
		.opcode			= CMDQ_OP_ATC_INV,
		.substream_valid	= !!ssid,
		.atc.ssid		= ssid,
	};

	if (!size) {
		cmd->atc.size = ATC_INV_SIZE_ALL;
		return;
	}

	page_start	= iova >> inval_grain_shift;
	page_end	= (iova + size - 1) >> inval_grain_shift;

	/*
	 * Find the smallest power of two that covers the range. Most
	 * significant differing bit between start and end address indicates the
	 * required span, ie. fls(start ^ end). For example:
	 *
	 * We want to invalidate pages [8; 11]. This is already the ideal range:
	 *		x = 0b1000 ^ 0b1011 = 0b11
	 *		span = 1 << fls(x) = 4
	 *
	 * To invalidate pages [7; 10], we need to invalidate [0; 15]:
	 *		x = 0b0111 ^ 0b1010 = 0b1101
	 *		span = 1 << fls(x) = 16
	 */
	log2_span	= fls_long(page_start ^ page_end);
	span_mask	= (1ULL << log2_span) - 1;

	page_start	&= ~span_mask;

	cmd->atc.addr	= page_start << inval_grain_shift;
	cmd->atc.size	= log2_span;
}

static int arm_smmu_atc_inv_master(struct arm_smmu_master_data *master,
				   struct arm_smmu_cmdq_ent *cmd)
{
	int i;
	struct iommu_fwspec *fwspec = master->dev->iommu_fwspec;

	if (!arm_smmu_master_has_ats(master))
		return 0;

	for (i = 0; i < fwspec->num_ids; i++) {
		cmd->atc.sid = fwspec->ids[i];
		arm_smmu_cmdq_issue_cmd(master->smmu, cmd);
	}

	arm_smmu_cmdq_issue_sync(master->smmu);

	return 0;
}

static int arm_smmu_atc_inv_master_all(struct arm_smmu_master_data *master,
				       int ssid)
{
	struct arm_smmu_cmdq_ent cmd;

	arm_smmu_atc_inv_to_cmd(ssid, 0, 0, &cmd);
	return arm_smmu_atc_inv_master(master, &cmd);
}

static size_t
arm_smmu_atc_inv_domain(struct arm_smmu_domain *smmu_domain, int ssid,
			unsigned long iova, size_t size)
{
	unsigned long flags;
	struct arm_smmu_cmdq_ent cmd;
	struct arm_smmu_master_data *master;

	arm_smmu_atc_inv_to_cmd(ssid, iova, size, &cmd);

	spin_lock_irqsave(&smmu_domain->devices_lock, flags);
	list_for_each_entry(master, &smmu_domain->devices, list)
		arm_smmu_atc_inv_master(master, &cmd);
	spin_unlock_irqrestore(&smmu_domain->devices_lock, flags);

	return size;
}

/* IO_PGTABLE API */
static void __arm_smmu_tlb_sync(struct arm_smmu_device *smmu)
{
	arm_smmu_cmdq_issue_sync(smmu);
}

static void arm_smmu_tlb_sync(void *cookie)
{
	struct arm_smmu_domain *smmu_domain = cookie;
	__arm_smmu_tlb_sync(smmu_domain->smmu);
}

static void arm_smmu_tlb_inv_context(void *cookie)
{
	struct arm_smmu_domain *smmu_domain = cookie;
	struct arm_smmu_device *smmu = smmu_domain->smmu;
	struct arm_smmu_cmdq_ent cmd;

	if (smmu_domain->stage == ARM_SMMU_DOMAIN_S1) {
		if (unlikely(!smmu_domain->s1_cfg.cd0))
			return;
		cmd.opcode	= smmu->features & ARM_SMMU_FEAT_E2H ?
				  CMDQ_OP_TLBI_EL2_ASID : CMDQ_OP_TLBI_NH_ASID;
		cmd.tlbi.asid	= smmu_domain->s1_cfg.cd0->tag;
		cmd.tlbi.vmid	= 0;
	} else {
		cmd.opcode	= CMDQ_OP_TLBI_S12_VMALL;
		cmd.tlbi.vmid	= smmu_domain->s2_cfg.vmid;
	}

	/*
	 * NOTE: when io-pgtable is in non-strict mode, we may get here with
	 * PTEs previously cleared by unmaps on the current CPU not yet visible
	 * to the SMMU. We are relying on the DSB implicit in queue_inc_prod()
	 * to guarantee those are observed before the TLBI. Do be careful, 007.
	 */
	arm_smmu_cmdq_issue_cmd(smmu, &cmd);
	__arm_smmu_tlb_sync(smmu);
}

static void arm_smmu_tlb_inv_range_nosync(unsigned long iova, size_t size,
					  size_t granule, bool leaf, void *cookie)
{
	struct arm_smmu_domain *smmu_domain = cookie;
	struct arm_smmu_device *smmu = smmu_domain->smmu;
	struct arm_smmu_cmdq_ent cmd = {
		.tlbi = {
			.leaf	= leaf,
			.addr	= iova,
		},
	};

	if (smmu_domain->stage == ARM_SMMU_DOMAIN_S1) {
		if (unlikely(!smmu_domain->s1_cfg.cd0))
			return;
		cmd.opcode	= smmu->features & ARM_SMMU_FEAT_E2H ?
				  CMDQ_OP_TLBI_EL2_VA : CMDQ_OP_TLBI_NH_VA;
		cmd.tlbi.asid	= smmu_domain->s1_cfg.cd0->tag;
	} else {
		cmd.opcode	= CMDQ_OP_TLBI_S2_IPA;
		cmd.tlbi.vmid	= smmu_domain->s2_cfg.vmid;
	}

	do {
		arm_smmu_cmdq_issue_cmd(smmu, &cmd);
		cmd.tlbi.addr += granule;
	} while (size -= granule);
}

static const struct iommu_gather_ops arm_smmu_gather_ops = {
	.tlb_flush_all	= arm_smmu_tlb_inv_context,
	.tlb_add_flush	= arm_smmu_tlb_inv_range_nosync,
	.tlb_sync	= arm_smmu_tlb_sync,
};

/* PASID TABLE API */
static void __arm_smmu_sync_cd(struct arm_smmu_domain *smmu_domain,
			       struct arm_smmu_cmdq_ent *cmd)
{
	size_t i;
	unsigned long flags;
	struct arm_smmu_master_data *master;
	struct arm_smmu_device *smmu = smmu_domain->smmu;

	spin_lock_irqsave(&smmu_domain->devices_lock, flags);
	list_for_each_entry(master, &smmu_domain->devices, list) {
		struct iommu_fwspec *fwspec = master->dev->iommu_fwspec;

		for (i = 0; i < fwspec->num_ids; i++) {
			cmd->cfgi.sid = fwspec->ids[i];
			arm_smmu_cmdq_issue_cmd(smmu, cmd);
		}
	}
	spin_unlock_irqrestore(&smmu_domain->devices_lock, flags);

	__arm_smmu_tlb_sync(smmu);
}

static void arm_smmu_sync_cd(void *cookie, int ssid, bool leaf)
{
	struct arm_smmu_cmdq_ent cmd = {
		.opcode	= CMDQ_OP_CFGI_CD_ALL,
		.cfgi	= {
			.ssid	= ssid,
			.leaf	= leaf,
		},
	};

	__arm_smmu_sync_cd(cookie, &cmd);
}

static void arm_smmu_sync_cd_all(void *cookie)
{
	struct arm_smmu_cmdq_ent cmd = {
		.opcode	= CMDQ_OP_CFGI_CD_ALL,
	};

	__arm_smmu_sync_cd(cookie, &cmd);
}

static void arm_smmu_tlb_inv_ssid(void *cookie, int ssid,
				  struct iommu_pasid_entry *entry)
{
	struct arm_smmu_domain *smmu_domain = cookie;
	struct arm_smmu_device *smmu = smmu_domain->smmu;
	struct arm_smmu_cmdq_ent cmd = {
		.opcode		= smmu->features & ARM_SMMU_FEAT_E2H ?
				  CMDQ_OP_TLBI_EL2_ASID : CMDQ_OP_TLBI_NH_ASID,
		.tlbi.asid	= entry->tag,
	};

	arm_smmu_cmdq_issue_cmd(smmu, &cmd);
	__arm_smmu_tlb_sync(smmu);
}

static struct iommu_pasid_sync_ops arm_smmu_ctx_sync = {
	.cfg_flush	= arm_smmu_sync_cd,
	.cfg_flush_all	= arm_smmu_sync_cd_all,
	.tlb_flush	= arm_smmu_tlb_inv_ssid,
};

/* IOMMU API */
static bool arm_smmu_capable(enum iommu_cap cap)
{
	switch (cap) {
	case IOMMU_CAP_CACHE_COHERENCY:
		return true;
	case IOMMU_CAP_NOEXEC:
		return true;
	default:
		return false;
	}
}

static struct iommu_domain *arm_smmu_domain_alloc(unsigned type)
{
	struct arm_smmu_domain *smmu_domain;

	if (type != IOMMU_DOMAIN_UNMANAGED &&
	    type != IOMMU_DOMAIN_DMA &&
	    type != IOMMU_DOMAIN_IDENTITY)
		return NULL;

	/*
	 * Allocate the domain and initialise some of its data structures.
	 * We can't really do anything meaningful until we've added a
	 * master.
	 */
	smmu_domain = kzalloc(sizeof(*smmu_domain), GFP_KERNEL);
	if (!smmu_domain)
		return NULL;

	if (type == IOMMU_DOMAIN_DMA &&
	    iommu_get_dma_cookie(&smmu_domain->domain)) {
		kfree(smmu_domain);
		return NULL;
	}

	mutex_init(&smmu_domain->init_mutex);
	INIT_LIST_HEAD(&smmu_domain->devices);
	spin_lock_init(&smmu_domain->devices_lock);

	return &smmu_domain->domain;
}

static int arm_smmu_bitmap_alloc(unsigned long *map, int span)
{
	int idx, size = 1 << span;

	do {
		idx = find_first_zero_bit(map, size);
		if (idx == size)
			return -ENOSPC;
	} while (test_and_set_bit(idx, map));

	return idx;
}

static void arm_smmu_bitmap_free(unsigned long *map, int idx)
{
	clear_bit(idx, map);
}

static void arm_smmu_domain_free(struct iommu_domain *domain)
{
	struct arm_smmu_domain *smmu_domain = to_smmu_domain(domain);
	struct arm_smmu_device *smmu = smmu_domain->smmu;

	iommu_put_dma_cookie(domain);
	free_io_pgtable_ops(smmu_domain->pgtbl_ops);

	/* Free the CD and ASID, if we allocated them */
	if (smmu_domain->stage == ARM_SMMU_DOMAIN_S1) {
		struct iommu_pasid_table_ops *ops = smmu_domain->s1_cfg.ops;

		if (ops) {
			iommu_free_pasid_entry(smmu_domain->s1_cfg.cd0);
			iommu_free_pasid_ops(ops);
		}
	} else {
		struct arm_smmu_s2_cfg *cfg = &smmu_domain->s2_cfg;
		if (cfg->vmid)
			arm_smmu_bitmap_free(smmu->vmid_map, cfg->vmid);
	}

	kfree(smmu_domain);
}

static int arm_smmu_domain_finalise_s1(struct arm_smmu_domain *smmu_domain,
				       struct arm_smmu_master_data *master,
				       struct io_pgtable_cfg *pgtbl_cfg)
{
	int ret;
	struct iommu_pasid_entry *entry;
	struct iommu_pasid_table_ops *ops;
	struct arm_smmu_device *smmu = smmu_domain->smmu;
	struct arm_smmu_s1_cfg *cfg = &smmu_domain->s1_cfg;
	struct iommu_pasid_table_cfg pasid_cfg = {
		.iommu_dev		= smmu->dev,
		.order			= master->ssid_bits,
		.sync			= &arm_smmu_ctx_sync,
		.arm_smmu = {
			.stall		= !!(smmu->features &
					  ARM_SMMU_FEAT_STALL_FORCE) ||
					  master->ste.can_stall,
			.asid_bits	= smmu->asid_bits,
			.hw_access	= !!(smmu->features & ARM_SMMU_FEAT_HA),
			.hw_dirty	= !!(smmu->features & ARM_SMMU_FEAT_HD),
		},
	};

	ops = iommu_alloc_pasid_ops(PASID_TABLE_ARM_SMMU_V3, &pasid_cfg,
				    smmu_domain);
	if (!ops)
		return -ENOMEM;

	/* Create default entry */
	entry = ops->alloc_priv_entry(ops, ARM_64_LPAE_S1, pgtbl_cfg);
	if (IS_ERR(entry)) {
		iommu_free_pasid_ops(ops);
		return PTR_ERR(entry);
	}

	ret = ops->set_entry(ops, 0, entry);
	if (ret) {
		iommu_free_pasid_entry(entry);
		iommu_free_pasid_ops(ops);
		return ret;
	}

	cfg->tables	= pasid_cfg;
	cfg->ops	= ops;
	cfg->cd0	= entry;

	return ret;
}

static int arm_smmu_domain_finalise_s2(struct arm_smmu_domain *smmu_domain,
				       struct arm_smmu_master_data *master,
				       struct io_pgtable_cfg *pgtbl_cfg)
{
	int vmid;
	struct arm_smmu_device *smmu = smmu_domain->smmu;
	struct arm_smmu_s2_cfg *cfg = &smmu_domain->s2_cfg;

	vmid = arm_smmu_bitmap_alloc(smmu->vmid_map, smmu->vmid_bits);
	if (vmid < 0)
		return vmid;

	cfg->vmid	= (u16)vmid;
	cfg->vttbr	= pgtbl_cfg->arm_lpae_s2_cfg.vttbr;
	cfg->vtcr	= pgtbl_cfg->arm_lpae_s2_cfg.vtcr;
	return 0;
}

static int arm_smmu_domain_finalise(struct iommu_domain *domain,
				    struct arm_smmu_master_data *master)
{
	int ret;
	unsigned long ias, oas;
	enum io_pgtable_fmt fmt;
	struct io_pgtable_cfg pgtbl_cfg;
	struct io_pgtable_ops *pgtbl_ops;
	int (*finalise_stage_fn)(struct arm_smmu_domain *,
				 struct arm_smmu_master_data *,
				 struct io_pgtable_cfg *);
	struct arm_smmu_domain *smmu_domain = to_smmu_domain(domain);
	struct arm_smmu_device *smmu = smmu_domain->smmu;

	if (domain->type == IOMMU_DOMAIN_IDENTITY) {
		smmu_domain->stage = ARM_SMMU_DOMAIN_BYPASS;
		return 0;
	}

	/* Restrict the stage to what we can actually support */
	if (!(smmu->features & ARM_SMMU_FEAT_TRANS_S1))
		smmu_domain->stage = ARM_SMMU_DOMAIN_S2;
	if (!(smmu->features & ARM_SMMU_FEAT_TRANS_S2))
		smmu_domain->stage = ARM_SMMU_DOMAIN_S1;

	switch (smmu_domain->stage) {
	case ARM_SMMU_DOMAIN_S1:
		ias = (smmu->features & ARM_SMMU_FEAT_VAX) ? 52 : 48;
		ias = min_t(unsigned long, ias, VA_BITS);
		oas = smmu->ias;
		fmt = ARM_64_LPAE_S1;
		finalise_stage_fn = arm_smmu_domain_finalise_s1;
		break;
	case ARM_SMMU_DOMAIN_NESTED:
	case ARM_SMMU_DOMAIN_S2:
		ias = smmu->ias;
		oas = smmu->oas;
		fmt = ARM_64_LPAE_S2;
		finalise_stage_fn = arm_smmu_domain_finalise_s2;
		break;
	default:
		return -EINVAL;
	}

	pgtbl_cfg = (struct io_pgtable_cfg) {
		.pgsize_bitmap	= smmu->pgsize_bitmap,
		.ias		= ias,
		.oas		= oas,
		.tlb		= &arm_smmu_gather_ops,
		.iommu_dev	= smmu->dev,
	};

	if (smmu->features & ARM_SMMU_FEAT_COHERENCY)
		pgtbl_cfg.quirks = IO_PGTABLE_QUIRK_NO_DMA;

	if (smmu_domain->non_strict)
		pgtbl_cfg.quirks |= IO_PGTABLE_QUIRK_NON_STRICT;

	pgtbl_ops = alloc_io_pgtable_ops(fmt, &pgtbl_cfg, smmu_domain);
	if (!pgtbl_ops)
		return -ENOMEM;

	domain->pgsize_bitmap = pgtbl_cfg.pgsize_bitmap;
	domain->geometry.aperture_end = (1UL << pgtbl_cfg.ias) - 1;
	domain->geometry.force_aperture = true;

	ret = finalise_stage_fn(smmu_domain, master, &pgtbl_cfg);
	if (ret < 0) {
		free_io_pgtable_ops(pgtbl_ops);
		return ret;
	}

	smmu_domain->pgtbl_ops = pgtbl_ops;
	return 0;
}

static __le64 *arm_smmu_get_step_for_sid(struct arm_smmu_device *smmu, u32 sid)
{
	__le64 *step;
	struct arm_smmu_strtab_cfg *cfg = &smmu->strtab_cfg;

	if (smmu->features & ARM_SMMU_FEAT_2_LVL_STRTAB) {
		struct arm_smmu_strtab_l1_desc *l1_desc;
		int idx;

		/* Two-level walk */
		idx = (sid >> STRTAB_SPLIT) * STRTAB_L1_DESC_DWORDS;
		l1_desc = &cfg->l1_desc[idx];
		idx = (sid & ((1 << STRTAB_SPLIT) - 1)) * STRTAB_STE_DWORDS;
		step = &l1_desc->l2ptr[idx];
	} else {
		/* Simple linear lookup */
		step = &cfg->strtab[sid * STRTAB_STE_DWORDS];
	}

	return step;
}

static void arm_smmu_install_ste_for_dev(struct iommu_fwspec *fwspec)
{
	int i, j;
	struct arm_smmu_master_data *master = fwspec->iommu_priv;
	struct arm_smmu_device *smmu = master->smmu;

	for (i = 0; i < fwspec->num_ids; ++i) {
		u32 sid = fwspec->ids[i];
		__le64 *step = arm_smmu_get_step_for_sid(smmu, sid);

		/* Bridged PCI devices may end up with duplicated IDs */
		for (j = 0; j < i; j++)
			if (fwspec->ids[j] == sid)
				break;
		if (j < i)
			continue;

		arm_smmu_write_strtab_ent(smmu, sid, step, &master->ste);
	}
}

static void arm_smmu_detach_dev(struct device *dev)
{
	unsigned long flags;
	struct arm_smmu_master_data *master = dev->iommu_fwspec->iommu_priv;
	struct arm_smmu_domain *smmu_domain = master->domain;

	if (smmu_domain) {
		__iommu_sva_unbind_dev_all(dev);

		arm_smmu_atc_inv_master_all(master, 0);

		spin_lock_irqsave(&smmu_domain->devices_lock, flags);
		list_del(&master->list);
		spin_unlock_irqrestore(&smmu_domain->devices_lock, flags);

		master->domain = NULL;
	}

	master->ste.assigned = false;
	arm_smmu_install_ste_for_dev(dev->iommu_fwspec);
}

static int arm_smmu_attach_dev(struct iommu_domain *domain, struct device *dev)
{
	int ret = 0;
	unsigned long flags;
	struct arm_smmu_device *smmu;
	struct arm_smmu_domain *smmu_domain = to_smmu_domain(domain);
	struct arm_smmu_master_data *master;
	struct arm_smmu_strtab_ent *ste;

	if (!dev->iommu_fwspec)
		return -ENOENT;

	master = dev->iommu_fwspec->iommu_priv;
	smmu = master->smmu;
	ste = &master->ste;

	/* Already attached to a different domain? */
	if (ste->assigned)
		arm_smmu_detach_dev(dev);

	mutex_lock(&smmu_domain->init_mutex);

	if (!smmu_domain->smmu) {
		smmu_domain->smmu = smmu;
		ret = arm_smmu_domain_finalise(domain, master);
		if (ret) {
			smmu_domain->smmu = NULL;
			goto out_unlock;
		}
	} else if (smmu_domain->smmu != smmu) {
		dev_err(dev,
			"cannot attach to SMMU %s (upstream of %s)\n",
			dev_name(smmu_domain->smmu->dev),
			dev_name(smmu->dev));
		ret = -ENXIO;
		goto out_unlock;
	}

	ste->assigned = true;
	master->domain = smmu_domain;

	spin_lock_irqsave(&smmu_domain->devices_lock, flags);
	list_add(&master->list, &smmu_domain->devices);
	spin_unlock_irqrestore(&smmu_domain->devices_lock, flags);

	if (smmu_domain->stage == ARM_SMMU_DOMAIN_BYPASS) {
		ste->s1_cfg = NULL;
		ste->s2_cfg = NULL;
	} else if (smmu_domain->stage == ARM_SMMU_DOMAIN_S1) {
		ste->s1_cfg = &smmu_domain->s1_cfg;
		ste->s2_cfg = NULL;
	} else {
		ste->s1_cfg = NULL;
		ste->s2_cfg = &smmu_domain->s2_cfg;
	}

	arm_smmu_install_ste_for_dev(dev->iommu_fwspec);
out_unlock:
	mutex_unlock(&smmu_domain->init_mutex);
	return ret;
}

static int arm_smmu_map(struct iommu_domain *domain, unsigned long iova,
			phys_addr_t paddr, size_t size, int prot)
{
	struct io_pgtable_ops *ops = to_smmu_domain(domain)->pgtbl_ops;

	if (!ops)
		return -ENODEV;

	return ops->map(ops, iova, paddr, size, prot);
}

static size_t
arm_smmu_unmap(struct iommu_domain *domain, unsigned long iova, size_t size)
{
	int ret;
	struct arm_smmu_domain *smmu_domain = to_smmu_domain(domain);
	struct io_pgtable_ops *ops = smmu_domain->pgtbl_ops;

	if (!ops)
		return 0;

	ret = ops->unmap(ops, iova, size);

	if (ret && smmu_domain->smmu->features & ARM_SMMU_FEAT_ATS)
		ret = arm_smmu_atc_inv_domain(smmu_domain, 0, iova, size);

	return ret;
}

static void arm_smmu_flush_iotlb_all(struct iommu_domain *domain)
{
	struct arm_smmu_domain *smmu_domain = to_smmu_domain(domain);

	if (smmu_domain->smmu)
		arm_smmu_tlb_inv_context(smmu_domain);
}

static void arm_smmu_iotlb_sync(struct iommu_domain *domain)
{
	struct arm_smmu_device *smmu = to_smmu_domain(domain)->smmu;

	if (smmu)
		__arm_smmu_tlb_sync(smmu);
}

static phys_addr_t
arm_smmu_iova_to_phys(struct iommu_domain *domain, dma_addr_t iova)
{
	struct io_pgtable_ops *ops = to_smmu_domain(domain)->pgtbl_ops;

	if (domain->type == IOMMU_DOMAIN_IDENTITY)
		return iova;

	if (!ops)
		return 0;

	return ops->iova_to_phys(ops, iova);
}

static int arm_smmu_sva_init(struct device *dev, struct iommu_sva_param *param)
{
	int ret;
	struct arm_smmu_master_data *master = dev->iommu_fwspec->iommu_priv;

	/* SSID support is mandatory for the moment */
	if (!master->ssid_bits)
		return -EINVAL;

	if (param->features & ~IOMMU_SVA_FEAT_IOPF)
		return -EINVAL;

	if (param->features & IOMMU_SVA_FEAT_IOPF) {
		if (!master->can_fault)
			return -EINVAL;
		ret = iopf_queue_add_device(master->smmu->iopf_queue, dev);
		if (ret)
			return ret;
	}

	if (!param->max_pasid)
		param->max_pasid = 0xfffffU;

	/* SSID support in the SMMU requires at least one SSID bit */
	param->min_pasid = max(param->min_pasid, 1U);
	param->max_pasid = min(param->max_pasid, (1U << master->ssid_bits) - 1);

	return 0;
}

static void arm_smmu_sva_shutdown(struct device *dev,
				  struct iommu_sva_param *param)
{
	iopf_queue_remove_device(dev);
}

static struct io_mm *arm_smmu_mm_alloc(struct iommu_domain *domain,
				       struct mm_struct *mm,
				       unsigned long flags)
{
	struct arm_smmu_mm *smmu_mm;
	struct iommu_pasid_entry *cd;
	struct iommu_pasid_table_ops *ops;
	struct arm_smmu_domain *smmu_domain = to_smmu_domain(domain);

	if (smmu_domain->stage != ARM_SMMU_DOMAIN_S1)
		return NULL;

	smmu_mm = kzalloc(sizeof(*smmu_mm), GFP_KERNEL);
	if (!smmu_mm)
		return NULL;

	ops = smmu_domain->s1_cfg.ops;
	cd = ops->alloc_shared_entry(ops, mm);
	if (IS_ERR(cd)) {
		kfree(smmu_mm);
		return ERR_CAST(cd);
	}

	smmu_mm->cd = cd;
	return &smmu_mm->io_mm;
}

static void arm_smmu_mm_free(struct io_mm *io_mm)
{
	struct arm_smmu_mm *smmu_mm = to_smmu_mm(io_mm);

	iommu_free_pasid_entry(smmu_mm->cd);
	kfree(smmu_mm);
}

static int arm_smmu_mm_attach(struct iommu_domain *domain, struct device *dev,
			      struct io_mm *io_mm, bool attach_domain)
{
	struct arm_smmu_mm *smmu_mm = to_smmu_mm(io_mm);
	struct arm_smmu_domain *smmu_domain = to_smmu_domain(domain);
	struct iommu_pasid_table_ops *ops = smmu_domain->s1_cfg.ops;
	struct arm_smmu_master_data *master = dev->iommu_fwspec->iommu_priv;

	if (smmu_domain->stage != ARM_SMMU_DOMAIN_S1)
		return -EINVAL;

	if (!(master->smmu->features & ARM_SMMU_FEAT_SVA))
		return -ENODEV;

	if (!attach_domain)
		return 0;

	return ops->set_entry(ops, io_mm->pasid, smmu_mm->cd);
}

static void arm_smmu_mm_detach(struct iommu_domain *domain, struct device *dev,
			       struct io_mm *io_mm, bool detach_domain)
{
	struct arm_smmu_mm *smmu_mm = to_smmu_mm(io_mm);
	struct arm_smmu_domain *smmu_domain = to_smmu_domain(domain);
	struct iommu_pasid_table_ops *ops = smmu_domain->s1_cfg.ops;

	if (detach_domain)
		ops->clear_entry(ops, io_mm->pasid, smmu_mm->cd);

	/* TODO: Invalidate ATC. */
	/* TODO: Invalidate all mappings if last and not DVM. */
}

static void arm_smmu_mm_invalidate(struct iommu_domain *domain,
				   struct device *dev, struct io_mm *io_mm,
				   unsigned long iova, size_t size)
{
	/*
	 * TODO: Invalidate ATC.
	 * TODO: Invalidate mapping if not DVM
	 */
}

static struct platform_driver arm_smmu_driver;

static int arm_smmu_match_node(struct device *dev, void *data)
{
	return dev->fwnode == data;
}

static
struct arm_smmu_device *arm_smmu_get_by_fwnode(struct fwnode_handle *fwnode)
{
	struct device *dev = driver_find_device(&arm_smmu_driver.driver, NULL,
						fwnode, arm_smmu_match_node);
	put_device(dev);
	return dev ? dev_get_drvdata(dev) : NULL;
}

static bool arm_smmu_sid_in_range(struct arm_smmu_device *smmu, u32 sid)
{
	unsigned long limit = smmu->strtab_cfg.num_l1_ents;

	if (smmu->features & ARM_SMMU_FEAT_2_LVL_STRTAB)
		limit *= 1UL << STRTAB_SPLIT;

	return sid < limit;
}

static int arm_smmu_enable_ats(struct arm_smmu_master_data *master)
{
	size_t stu;
	int ret, pos;
	struct pci_dev *pdev;
	struct arm_smmu_device *smmu = master->smmu;
	struct iommu_fwspec *fwspec = master->dev->iommu_fwspec;

	if (!(smmu->features & ARM_SMMU_FEAT_ATS) || !dev_is_pci(master->dev) ||
	    (fwspec->flags & IOMMU_FWSPEC_PCI_NO_ATS))
		return -ENOSYS;

	pdev = to_pci_dev(master->dev);

	pos = pci_find_ext_capability(pdev, PCI_EXT_CAP_ID_ATS);
	if (!pos)
		return -ENOSYS;

	/* Smallest Translation Unit: log2 of the smallest supported granule */
	stu = __ffs(smmu->pgsize_bitmap);

	ret = pci_enable_ats(pdev, stu);
	if (ret) {
		dev_err(&pdev->dev, "could not enable ATS: %d\n", ret);
		return ret;
	}

	dev_dbg(&pdev->dev, "enabled ATS (STU=%zu, QDEP=%d)\n", stu,
		pci_ats_queue_depth(pdev));

	return 0;
}

static void arm_smmu_disable_ats(struct arm_smmu_master_data *master)
{
	struct pci_dev *pdev;

	if (!dev_is_pci(master->dev))
		return;

	pdev = to_pci_dev(master->dev);

	if (!pdev->ats_enabled)
		return;

	pci_disable_ats(pdev);
}

static int arm_smmu_insert_master(struct arm_smmu_device *smmu,
				  struct arm_smmu_master_data *master)
{
	int i;
	int ret = 0;
	struct arm_smmu_stream *new_stream, *cur_stream;
	struct rb_node **new_node, *parent_node = NULL;
	struct iommu_fwspec *fwspec = master->dev->iommu_fwspec;

	master->streams = kcalloc(fwspec->num_ids,
				  sizeof(struct arm_smmu_stream), GFP_KERNEL);
	if (!master->streams)
		return -ENOMEM;

	mutex_lock(&smmu->streams_mutex);
	for (i = 0; i < fwspec->num_ids && !ret; i++) {
		new_stream = &master->streams[i];
		new_stream->id = fwspec->ids[i];
		new_stream->master = master;

		new_node = &(smmu->streams.rb_node);
		while (*new_node) {
			cur_stream = rb_entry(*new_node, struct arm_smmu_stream,
					      node);
			parent_node = *new_node;
			if (cur_stream->id > new_stream->id) {
				new_node = &((*new_node)->rb_left);
			} else if (cur_stream->id < new_stream->id) {
				new_node = &((*new_node)->rb_right);
			} else {
				dev_warn(master->dev,
					 "stream %u already in tree\n",
					 cur_stream->id);
				ret = -EINVAL;
				break;
			}
		}

		if (!ret) {
			rb_link_node(&new_stream->node, parent_node, new_node);
			rb_insert_color(&new_stream->node, &smmu->streams);
		}
	}
	mutex_unlock(&smmu->streams_mutex);

	return ret;
}

static void arm_smmu_remove_master(struct arm_smmu_device *smmu,
				   struct arm_smmu_master_data *master)
{
	int i;
	struct iommu_fwspec *fwspec = master->dev->iommu_fwspec;

	if (!master->streams)
		return;

	mutex_lock(&smmu->streams_mutex);
	for (i = 0; i < fwspec->num_ids; i++)
		rb_erase(&master->streams[i].node, &smmu->streams);
	mutex_unlock(&smmu->streams_mutex);

	kfree(master->streams);
}

static struct iommu_ops arm_smmu_ops;

static int arm_smmu_add_device(struct device *dev)
{
	int i, ret;
	struct arm_smmu_device *smmu;
	struct arm_smmu_master_data *master;
	struct iommu_fwspec *fwspec = dev->iommu_fwspec;
	struct iommu_group *group;

	if (!fwspec || fwspec->ops != &arm_smmu_ops)
		return -ENODEV;
	/*
	 * We _can_ actually withstand dodgy bus code re-calling add_device()
	 * without an intervening remove_device()/of_xlate() sequence, but
	 * we're not going to do so quietly...
	 */
	if (WARN_ON_ONCE(fwspec->iommu_priv)) {
		master = fwspec->iommu_priv;
		smmu = master->smmu;
	} else {
		smmu = arm_smmu_get_by_fwnode(fwspec->iommu_fwnode);
		if (!smmu)
			return -ENODEV;
		master = kzalloc(sizeof(*master), GFP_KERNEL);
		if (!master)
			return -ENOMEM;

		master->smmu = smmu;
		master->dev = dev;
		fwspec->iommu_priv = master;
	}

	/* Check the SIDs are in range of the SMMU and our stream table */
	for (i = 0; i < fwspec->num_ids; i++) {
		u32 sid = fwspec->ids[i];

		if (!arm_smmu_sid_in_range(smmu, sid)) {
			ret = -ERANGE;
			goto err_free_master;
		}

		/* Ensure l2 strtab is initialised */
		if (smmu->features & ARM_SMMU_FEAT_2_LVL_STRTAB) {
			ret = arm_smmu_init_l2_strtab(smmu, sid);
			if (ret)
				goto err_free_master;
		}
	}

	master->ssid_bits = min(smmu->ssid_bits, fwspec->num_pasid_bits);

	if (fwspec->can_stall && smmu->features & ARM_SMMU_FEAT_STALLS) {
		master->can_fault = true;
		master->ste.can_stall = true;
	}

	arm_smmu_enable_ats(master);

	ret = iommu_device_link(&smmu->iommu, dev);
	if (ret)
		goto err_disable_ats;

	group = iommu_group_get_for_dev(dev);
	if (IS_ERR(group)) {
		ret = PTR_ERR(group);
		goto err_remove_master;
	}

	arm_smmu_insert_master(smmu, master);
	iommu_group_put(group);

	return 0;

err_remove_master:
	arm_smmu_remove_master(smmu, master);
	iommu_device_unlink(&smmu->iommu, dev);

err_disable_ats:
	arm_smmu_disable_ats(master);

err_free_master:
	kfree(master);
	fwspec->iommu_priv = NULL;

	return ret;
}

static void arm_smmu_remove_device(struct device *dev)
{
	struct iommu_fwspec *fwspec = dev->iommu_fwspec;
	struct arm_smmu_master_data *master;
	struct arm_smmu_device *smmu;

	if (!fwspec || fwspec->ops != &arm_smmu_ops)
		return;

	master = fwspec->iommu_priv;
	if (!master)
		return;

	smmu = master->smmu;
	iopf_queue_remove_device(dev);
	if (master->ste.assigned)
		arm_smmu_detach_dev(dev);
	iommu_group_remove_device(dev);
	arm_smmu_remove_master(smmu, master);
	iommu_device_unlink(&smmu->iommu, dev);
	arm_smmu_disable_ats(master);
	kfree(master);
	iommu_fwspec_free(dev);
}

static struct iommu_group *arm_smmu_device_group(struct device *dev)
{
	struct iommu_group *group;

	/*
	 * We don't support devices sharing stream IDs other than PCI RID
	 * aliases, since the necessary ID-to-device lookup becomes rather
	 * impractical given a potential sparse 32-bit stream ID space.
	 */
	if (dev_is_pci(dev))
		group = pci_device_group(dev);
	else
		group = generic_device_group(dev);

	return group;
}

static int arm_smmu_domain_get_attr(struct iommu_domain *domain,
				    enum iommu_attr attr, void *data)
{
	struct arm_smmu_domain *smmu_domain = to_smmu_domain(domain);

	switch (domain->type) {
	case IOMMU_DOMAIN_UNMANAGED:
		switch (attr) {
		case DOMAIN_ATTR_NESTING:
			*(int *)data = (smmu_domain->stage == ARM_SMMU_DOMAIN_NESTED);
			return 0;
		default:
			return -ENODEV;
		}
		break;
	case IOMMU_DOMAIN_DMA:
		switch (attr) {
		case DOMAIN_ATTR_DMA_USE_FLUSH_QUEUE:
			*(int *)data = smmu_domain->non_strict;
			return 0;
		default:
			return -ENODEV;
		}
		break;
	default:
		return -EINVAL;
	}
}

static int arm_smmu_domain_set_attr(struct iommu_domain *domain,
				    enum iommu_attr attr, void *data)
{
	int ret = 0;
	struct arm_smmu_domain *smmu_domain = to_smmu_domain(domain);

	mutex_lock(&smmu_domain->init_mutex);

	switch (domain->type) {
	case IOMMU_DOMAIN_UNMANAGED:
		switch (attr) {
		case DOMAIN_ATTR_NESTING:
			if (smmu_domain->smmu) {
				ret = -EPERM;
				goto out_unlock;
			}

			if (*(int *)data)
				smmu_domain->stage = ARM_SMMU_DOMAIN_NESTED;
			else
				smmu_domain->stage = ARM_SMMU_DOMAIN_S1;
			break;
		default:
			ret = -ENODEV;
		}
		break;
	case IOMMU_DOMAIN_DMA:
		switch(attr) {
		case DOMAIN_ATTR_DMA_USE_FLUSH_QUEUE:
			smmu_domain->non_strict = *(int *)data;
			break;
		default:
			ret = -ENODEV;
		}
		break;
	default:
		ret = -EINVAL;
	}

out_unlock:
	mutex_unlock(&smmu_domain->init_mutex);
	return ret;
}

static int arm_smmu_of_xlate(struct device *dev, struct of_phandle_args *args)
{
	return iommu_fwspec_add_ids(dev, args->args, 1);
}

static void arm_smmu_get_resv_regions(struct device *dev,
				      struct list_head *head)
{
	struct iommu_resv_region *region;
	int prot = IOMMU_WRITE | IOMMU_NOEXEC | IOMMU_MMIO;

	region = iommu_alloc_resv_region(MSI_IOVA_BASE, MSI_IOVA_LENGTH,
					 prot, IOMMU_RESV_SW_MSI);
	if (!region)
		return;

	list_add_tail(&region->list, head);

	iommu_dma_get_resv_regions(dev, head);
}

static void arm_smmu_put_resv_regions(struct device *dev,
				      struct list_head *head)
{
	struct iommu_resv_region *entry, *next;

	list_for_each_entry_safe(entry, next, head, list)
		kfree(entry);
}

static struct iommu_ops arm_smmu_ops = {
	.capable		= arm_smmu_capable,
	.domain_alloc		= arm_smmu_domain_alloc,
	.domain_free		= arm_smmu_domain_free,
	.attach_dev		= arm_smmu_attach_dev,
	.sva_device_init	= arm_smmu_sva_init,
	.sva_device_shutdown	= arm_smmu_sva_shutdown,
	.mm_alloc		= arm_smmu_mm_alloc,
	.mm_free		= arm_smmu_mm_free,
	.mm_attach		= arm_smmu_mm_attach,
	.mm_detach		= arm_smmu_mm_detach,
	.mm_invalidate		= arm_smmu_mm_invalidate,
	.page_response		= arm_smmu_page_response,
	.map			= arm_smmu_map,
	.unmap			= arm_smmu_unmap,
	.flush_iotlb_all	= arm_smmu_flush_iotlb_all,
	.iotlb_sync		= arm_smmu_iotlb_sync,
	.iova_to_phys		= arm_smmu_iova_to_phys,
	.add_device		= arm_smmu_add_device,
	.remove_device		= arm_smmu_remove_device,
	.device_group		= arm_smmu_device_group,
	.domain_get_attr	= arm_smmu_domain_get_attr,
	.domain_set_attr	= arm_smmu_domain_set_attr,
	.of_xlate		= arm_smmu_of_xlate,
	.get_resv_regions	= arm_smmu_get_resv_regions,
	.put_resv_regions	= arm_smmu_put_resv_regions,
	.pgsize_bitmap		= -1UL, /* Restricted during device attach */
};

/* Probing and initialisation functions */
static int arm_smmu_init_one_queue(struct arm_smmu_device *smmu,
				   struct arm_smmu_queue *q,
				   unsigned long prod_off,
				   unsigned long cons_off,
				   size_t dwords)
{
	size_t qsz = ((1 << q->max_n_shift) * dwords) << 3;

	q->base = dmam_alloc_coherent(smmu->dev, qsz, &q->base_dma, GFP_KERNEL);
	if (!q->base) {
		dev_err(smmu->dev, "failed to allocate queue (0x%zx bytes)\n",
			qsz);
		return -ENOMEM;
	}

	q->prod_reg	= arm_smmu_page1_fixup(prod_off, smmu);
	q->cons_reg	= arm_smmu_page1_fixup(cons_off, smmu);
	q->ent_dwords	= dwords;

	q->q_base  = Q_BASE_RWA;
	q->q_base |= q->base_dma & Q_BASE_ADDR_MASK;
	q->q_base |= FIELD_PREP(Q_BASE_LOG2SIZE, q->max_n_shift);

	q->prod = q->cons = 0;

	init_waitqueue_head(&q->wq);
	q->batch = 0;

	return 0;
}

static int arm_smmu_init_queues(struct arm_smmu_device *smmu)
{
	int ret;

	/* cmdq */
	spin_lock_init(&smmu->cmdq.lock);
	ret = arm_smmu_init_one_queue(smmu, &smmu->cmdq.q, ARM_SMMU_CMDQ_PROD,
				      ARM_SMMU_CMDQ_CONS, CMDQ_ENT_DWORDS);
	if (ret)
		return ret;

	/* evtq */
	ret = arm_smmu_init_one_queue(smmu, &smmu->evtq.q, ARM_SMMU_EVTQ_PROD,
				      ARM_SMMU_EVTQ_CONS, EVTQ_ENT_DWORDS);
	if (ret)
		return ret;

	/* priq */
	if (!(smmu->features & ARM_SMMU_FEAT_PRI))
		return 0;

	return arm_smmu_init_one_queue(smmu, &smmu->priq.q, ARM_SMMU_PRIQ_PROD,
				       ARM_SMMU_PRIQ_CONS, PRIQ_ENT_DWORDS);
}

static int arm_smmu_init_l1_strtab(struct arm_smmu_device *smmu)
{
	unsigned int i;
	struct arm_smmu_strtab_cfg *cfg = &smmu->strtab_cfg;
	size_t size = sizeof(*cfg->l1_desc) * cfg->num_l1_ents;
	void *strtab = smmu->strtab_cfg.strtab;

	cfg->l1_desc = devm_kzalloc(smmu->dev, size, GFP_KERNEL);
	if (!cfg->l1_desc) {
		dev_err(smmu->dev, "failed to allocate l1 stream table desc\n");
		return -ENOMEM;
	}

	for (i = 0; i < cfg->num_l1_ents; ++i) {
		arm_smmu_write_strtab_l1_desc(strtab, &cfg->l1_desc[i]);
		strtab += STRTAB_L1_DESC_DWORDS << 3;
	}

	return 0;
}

static int arm_smmu_init_strtab_2lvl(struct arm_smmu_device *smmu)
{
	void *strtab;
	u64 reg;
	u32 size, l1size;
	struct arm_smmu_strtab_cfg *cfg = &smmu->strtab_cfg;

	/* Calculate the L1 size, capped to the SIDSIZE. */
	size = STRTAB_L1_SZ_SHIFT - (ilog2(STRTAB_L1_DESC_DWORDS) + 3);
	size = min(size, smmu->sid_bits - STRTAB_SPLIT);
	cfg->num_l1_ents = 1 << size;

	size += STRTAB_SPLIT;
	if (size < smmu->sid_bits)
		dev_warn(smmu->dev,
			 "2-level strtab only covers %u/%u bits of SID\n",
			 size, smmu->sid_bits);

	l1size = cfg->num_l1_ents * (STRTAB_L1_DESC_DWORDS << 3);
	strtab = dmam_alloc_coherent(smmu->dev, l1size, &cfg->strtab_dma,
				     GFP_KERNEL | __GFP_ZERO);
	if (!strtab) {
		dev_err(smmu->dev,
			"failed to allocate l1 stream table (%u bytes)\n",
			size);
		return -ENOMEM;
	}
	cfg->strtab = strtab;

	/* Configure strtab_base_cfg for 2 levels */
	reg  = FIELD_PREP(STRTAB_BASE_CFG_FMT, STRTAB_BASE_CFG_FMT_2LVL);
	reg |= FIELD_PREP(STRTAB_BASE_CFG_LOG2SIZE, size);
	reg |= FIELD_PREP(STRTAB_BASE_CFG_SPLIT, STRTAB_SPLIT);
	cfg->strtab_base_cfg = reg;

	return arm_smmu_init_l1_strtab(smmu);
}

static int arm_smmu_init_strtab_linear(struct arm_smmu_device *smmu)
{
	void *strtab;
	u64 reg;
	u32 size;
	struct arm_smmu_strtab_cfg *cfg = &smmu->strtab_cfg;

	size = (1 << smmu->sid_bits) * (STRTAB_STE_DWORDS << 3);
	strtab = dmam_alloc_coherent(smmu->dev, size, &cfg->strtab_dma,
				     GFP_KERNEL | __GFP_ZERO);
	if (!strtab) {
		dev_err(smmu->dev,
			"failed to allocate linear stream table (%u bytes)\n",
			size);
		return -ENOMEM;
	}
	cfg->strtab = strtab;
	cfg->num_l1_ents = 1 << smmu->sid_bits;

	/* Configure strtab_base_cfg for a linear table covering all SIDs */
	reg  = FIELD_PREP(STRTAB_BASE_CFG_FMT, STRTAB_BASE_CFG_FMT_LINEAR);
	reg |= FIELD_PREP(STRTAB_BASE_CFG_LOG2SIZE, smmu->sid_bits);
	cfg->strtab_base_cfg = reg;

	arm_smmu_init_bypass_stes(strtab, cfg->num_l1_ents);
	return 0;
}

static int arm_smmu_init_strtab(struct arm_smmu_device *smmu)
{
	u64 reg;
	int ret;

	if (smmu->features & ARM_SMMU_FEAT_2_LVL_STRTAB)
		ret = arm_smmu_init_strtab_2lvl(smmu);
	else
		ret = arm_smmu_init_strtab_linear(smmu);

	if (ret)
		return ret;

	/* Set the strtab base address */
	reg  = smmu->strtab_cfg.strtab_dma & STRTAB_BASE_ADDR_MASK;
	reg |= STRTAB_BASE_RA;
	smmu->strtab_cfg.strtab_base = reg;

	/* Allocate the first VMID for stage-2 bypass STEs */
	set_bit(0, smmu->vmid_map);
	return 0;
}

static int arm_smmu_init_structures(struct arm_smmu_device *smmu)
{
	int ret;

	mutex_init(&smmu->streams_mutex);
	smmu->streams = RB_ROOT;

	ret = arm_smmu_init_queues(smmu);
	if (ret)
		return ret;

	return arm_smmu_init_strtab(smmu);
}

static int arm_smmu_write_reg_sync(struct arm_smmu_device *smmu, u32 val,
				   unsigned int reg_off, unsigned int ack_off)
{
	u32 reg;

	writel_relaxed(val, smmu->base + reg_off);
	return readl_relaxed_poll_timeout(smmu->base + ack_off, reg, reg == val,
					  1, ARM_SMMU_POLL_TIMEOUT_US);
}

/* GBPA is "special" */
static int arm_smmu_update_gbpa(struct arm_smmu_device *smmu, u32 set, u32 clr)
{
	int ret;
	u32 reg, __iomem *gbpa = smmu->base + ARM_SMMU_GBPA;

	ret = readl_relaxed_poll_timeout(gbpa, reg, !(reg & GBPA_UPDATE),
					 1, ARM_SMMU_POLL_TIMEOUT_US);
	if (ret)
		return ret;

	reg &= ~clr;
	reg |= set;
	writel_relaxed(reg | GBPA_UPDATE, gbpa);
	ret = readl_relaxed_poll_timeout(gbpa, reg, !(reg & GBPA_UPDATE),
					 1, ARM_SMMU_POLL_TIMEOUT_US);

	if (ret)
		dev_err(smmu->dev, "GBPA not responding to update\n");
	return ret;
}

static void arm_smmu_free_msis(void *data)
{
	struct device *dev = data;
	platform_msi_domain_free_irqs(dev);
}

static void arm_smmu_write_msi_msg(struct msi_desc *desc, struct msi_msg *msg)
{
	phys_addr_t doorbell;
	struct device *dev = msi_desc_to_dev(desc);
	struct arm_smmu_device *smmu = dev_get_drvdata(dev);
	phys_addr_t *cfg = arm_smmu_msi_cfg[desc->platform.msi_index];

	doorbell = (((u64)msg->address_hi) << 32) | msg->address_lo;
	doorbell &= MSI_CFG0_ADDR_MASK;

	writeq_relaxed(doorbell, smmu->base + cfg[0]);
	writel_relaxed(msg->data, smmu->base + cfg[1]);
	writel_relaxed(ARM_SMMU_MEMATTR_DEVICE_nGnRE, smmu->base + cfg[2]);
}

static void arm_smmu_setup_msis(struct arm_smmu_device *smmu)
{
	struct msi_desc *desc;
	int ret, nvec = ARM_SMMU_MAX_MSIS;
	struct device *dev = smmu->dev;

	/* Clear the MSI address regs */
	writeq_relaxed(0, smmu->base + ARM_SMMU_GERROR_IRQ_CFG0);
	writeq_relaxed(0, smmu->base + ARM_SMMU_EVTQ_IRQ_CFG0);

	if (smmu->features & ARM_SMMU_FEAT_PRI)
		writeq_relaxed(0, smmu->base + ARM_SMMU_PRIQ_IRQ_CFG0);
	else
		nvec--;

	if (!(smmu->features & ARM_SMMU_FEAT_MSI))
		return;

	if (!dev->msi_domain) {
		dev_info(smmu->dev, "msi_domain absent - falling back to wired irqs\n");
		return;
	}

	/* Allocate MSIs for evtq, gerror and priq. Ignore cmdq */
	ret = platform_msi_domain_alloc_irqs(dev, nvec, arm_smmu_write_msi_msg);
	if (ret) {
		dev_warn(dev, "failed to allocate MSIs - falling back to wired irqs\n");
		return;
	}

	for_each_msi_entry(desc, dev) {
		switch (desc->platform.msi_index) {
		case EVTQ_MSI_INDEX:
			smmu->evtq.q.irq = desc->irq;
			break;
		case GERROR_MSI_INDEX:
			smmu->gerr_irq = desc->irq;
			break;
		case PRIQ_MSI_INDEX:
			smmu->priq.q.irq = desc->irq;
			break;
		default:	/* Unknown */
			continue;
		}
	}

	/* Add callback to free MSIs on teardown */
	devm_add_action(dev, arm_smmu_free_msis, dev);
}

static void arm_smmu_setup_unique_irqs(struct arm_smmu_device *smmu)
{
	int irq, ret;

	arm_smmu_setup_msis(smmu);

	/* Request interrupt lines */
	irq = smmu->evtq.q.irq;
	if (irq) {
		ret = devm_request_threaded_irq(smmu->dev, irq, NULL,
						arm_smmu_evtq_thread,
						IRQF_ONESHOT,
						"arm-smmu-v3-evtq", smmu);
		if (ret < 0)
			dev_warn(smmu->dev, "failed to enable evtq irq\n");
	} else {
		dev_warn(smmu->dev, "no evtq irq - events will not be reported!\n");
	}

	irq = smmu->gerr_irq;
	if (irq) {
		ret = devm_request_irq(smmu->dev, irq, arm_smmu_gerror_handler,
				       0, "arm-smmu-v3-gerror", smmu);
		if (ret < 0)
			dev_warn(smmu->dev, "failed to enable gerror irq\n");
	} else {
		dev_warn(smmu->dev, "no gerr irq - errors will not be reported!\n");
	}

	if (smmu->features & ARM_SMMU_FEAT_PRI) {
		irq = smmu->priq.q.irq;
		if (irq) {
			ret = devm_request_threaded_irq(smmu->dev, irq, NULL,
							arm_smmu_priq_thread,
							IRQF_ONESHOT,
							"arm-smmu-v3-priq",
							smmu);
			if (ret < 0)
				dev_warn(smmu->dev,
					 "failed to enable priq irq\n");
		} else {
			dev_warn(smmu->dev, "no priq irq - PRI will be broken\n");
		}
	}
}

static int arm_smmu_setup_irqs(struct arm_smmu_device *smmu)
{
	int ret, irq;
	u32 irqen_flags = IRQ_CTRL_EVTQ_IRQEN | IRQ_CTRL_GERROR_IRQEN;

	/* Disable IRQs first */
	ret = arm_smmu_write_reg_sync(smmu, 0, ARM_SMMU_IRQ_CTRL,
				      ARM_SMMU_IRQ_CTRLACK);
	if (ret) {
		dev_err(smmu->dev, "failed to disable irqs\n");
		return ret;
	}

	irq = smmu->combined_irq;
	if (irq) {
		/*
		 * Cavium ThunderX2 implementation doesn't support unique irq
		 * lines. Use a single irq line for all the SMMUv3 interrupts.
		 */
		ret = devm_request_threaded_irq(smmu->dev, irq,
					arm_smmu_combined_irq_handler,
					arm_smmu_combined_irq_thread,
					IRQF_ONESHOT,
					"arm-smmu-v3-combined-irq", smmu);
		if (ret < 0)
			dev_warn(smmu->dev, "failed to enable combined irq\n");
	} else
		arm_smmu_setup_unique_irqs(smmu);

	if (smmu->features & ARM_SMMU_FEAT_PRI)
		irqen_flags |= IRQ_CTRL_PRIQ_IRQEN;

	/* Enable interrupt generation on the SMMU */
	ret = arm_smmu_write_reg_sync(smmu, irqen_flags,
				      ARM_SMMU_IRQ_CTRL, ARM_SMMU_IRQ_CTRLACK);
	if (ret)
		dev_warn(smmu->dev, "failed to enable irqs\n");

	return 0;
}

static int arm_smmu_device_disable(struct arm_smmu_device *smmu)
{
	int ret;

	ret = arm_smmu_write_reg_sync(smmu, 0, ARM_SMMU_CR0, ARM_SMMU_CR0ACK);
	if (ret)
		dev_err(smmu->dev, "failed to clear cr0\n");

	return ret;
}

static int arm_smmu_device_reset(struct arm_smmu_device *smmu, bool bypass)
{
	int ret;
	u32 reg, enables;
	struct arm_smmu_cmdq_ent cmd;

	/* Clear CR0 and sync (disables SMMU and queue processing) */
	reg = readl_relaxed(smmu->base + ARM_SMMU_CR0);
	if (reg & CR0_SMMUEN) {
		dev_warn(smmu->dev, "SMMU currently enabled! Resetting...\n");
		WARN_ON(is_kdump_kernel() && !disable_bypass);
		arm_smmu_update_gbpa(smmu, GBPA_ABORT, 0);
	}

	ret = arm_smmu_device_disable(smmu);
	if (ret)
		return ret;

	/* CR1 (table and queue memory attributes) */
	reg = FIELD_PREP(CR1_TABLE_SH, ARM_SMMU_SH_ISH) |
	      FIELD_PREP(CR1_TABLE_OC, CR1_CACHE_WB) |
	      FIELD_PREP(CR1_TABLE_IC, CR1_CACHE_WB) |
	      FIELD_PREP(CR1_QUEUE_SH, ARM_SMMU_SH_ISH) |
	      FIELD_PREP(CR1_QUEUE_OC, CR1_CACHE_WB) |
	      FIELD_PREP(CR1_QUEUE_IC, CR1_CACHE_WB);
	writel_relaxed(reg, smmu->base + ARM_SMMU_CR1);

	/* CR2 (random crap) */
	reg = CR2_RECINVSID;

	if (smmu->features & ARM_SMMU_FEAT_E2H)
		reg |= CR2_E2H;

	if (!(smmu->features & ARM_SMMU_FEAT_BTM))
		reg |= CR2_PTM;

	writel_relaxed(reg, smmu->base + ARM_SMMU_CR2);

	/* Stream table */
	writeq_relaxed(smmu->strtab_cfg.strtab_base,
		       smmu->base + ARM_SMMU_STRTAB_BASE);
	writel_relaxed(smmu->strtab_cfg.strtab_base_cfg,
		       smmu->base + ARM_SMMU_STRTAB_BASE_CFG);

	/* Command queue */
	writeq_relaxed(smmu->cmdq.q.q_base, smmu->base + ARM_SMMU_CMDQ_BASE);
	writel_relaxed(smmu->cmdq.q.prod, smmu->base + ARM_SMMU_CMDQ_PROD);
	writel_relaxed(smmu->cmdq.q.cons, smmu->base + ARM_SMMU_CMDQ_CONS);

	enables = CR0_CMDQEN;
	ret = arm_smmu_write_reg_sync(smmu, enables, ARM_SMMU_CR0,
				      ARM_SMMU_CR0ACK);
	if (ret) {
		dev_err(smmu->dev, "failed to enable command queue\n");
		return ret;
	}

	/* Invalidate any cached configuration */
	cmd.opcode = CMDQ_OP_CFGI_ALL;
	arm_smmu_cmdq_issue_cmd(smmu, &cmd);
	arm_smmu_cmdq_issue_sync(smmu);

	/* Invalidate any stale TLB entries */
	if (smmu->features & ARM_SMMU_FEAT_HYP) {
		cmd.opcode = CMDQ_OP_TLBI_EL2_ALL;
		arm_smmu_cmdq_issue_cmd(smmu, &cmd);
	}

	cmd.opcode = CMDQ_OP_TLBI_NSNH_ALL;
	arm_smmu_cmdq_issue_cmd(smmu, &cmd);
	arm_smmu_cmdq_issue_sync(smmu);

	/* Event queue */
	writeq_relaxed(smmu->evtq.q.q_base, smmu->base + ARM_SMMU_EVTQ_BASE);
	writel_relaxed(smmu->evtq.q.prod,
		       arm_smmu_page1_fixup(ARM_SMMU_EVTQ_PROD, smmu));
	writel_relaxed(smmu->evtq.q.cons,
		       arm_smmu_page1_fixup(ARM_SMMU_EVTQ_CONS, smmu));

	enables |= CR0_EVTQEN;
	ret = arm_smmu_write_reg_sync(smmu, enables, ARM_SMMU_CR0,
				      ARM_SMMU_CR0ACK);
	if (ret) {
		dev_err(smmu->dev, "failed to enable event queue\n");
		return ret;
	}

	/* PRI queue */
	if (smmu->features & ARM_SMMU_FEAT_PRI) {
		writeq_relaxed(smmu->priq.q.q_base,
			       smmu->base + ARM_SMMU_PRIQ_BASE);
		writel_relaxed(smmu->priq.q.prod,
			       arm_smmu_page1_fixup(ARM_SMMU_PRIQ_PROD, smmu));
		writel_relaxed(smmu->priq.q.cons,
			       arm_smmu_page1_fixup(ARM_SMMU_PRIQ_CONS, smmu));

		enables |= CR0_PRIQEN;
		ret = arm_smmu_write_reg_sync(smmu, enables, ARM_SMMU_CR0,
					      ARM_SMMU_CR0ACK);
		if (ret) {
			dev_err(smmu->dev, "failed to enable PRI queue\n");
			return ret;
		}
	}

	if (smmu->features & ARM_SMMU_FEAT_ATS && !disable_ats_check) {
		enables |= CR0_ATSCHK;
		ret = arm_smmu_write_reg_sync(smmu, enables, ARM_SMMU_CR0,
					      ARM_SMMU_CR0ACK);
		if (ret) {
			dev_err(smmu->dev, "failed to enable ATS check\n");
			return ret;
		}
	}

	ret = arm_smmu_setup_irqs(smmu);
	if (ret) {
		dev_err(smmu->dev, "failed to setup irqs\n");
		return ret;
	}

	if (is_kdump_kernel())
		enables &= ~(CR0_EVTQEN | CR0_PRIQEN);

	/* Enable the SMMU interface, or ensure bypass */
	if (!bypass || disable_bypass) {
		enables |= CR0_SMMUEN;
	} else {
		ret = arm_smmu_update_gbpa(smmu, 0, GBPA_ABORT);
		if (ret)
			return ret;
	}
	ret = arm_smmu_write_reg_sync(smmu, enables, ARM_SMMU_CR0,
				      ARM_SMMU_CR0ACK);
	if (ret) {
		dev_err(smmu->dev, "failed to enable SMMU interface\n");
		return ret;
	}

	return 0;
}

static bool arm_smmu_supports_sva(struct arm_smmu_device *smmu)
{
	unsigned long reg, fld;
	unsigned long oas;
	unsigned long asid_bits;

	u32 feat_mask = ARM_SMMU_FEAT_BTM | ARM_SMMU_FEAT_COHERENCY;

	if ((smmu->features & feat_mask) != feat_mask)
		return false;

	if (!(smmu->pgsize_bitmap & PAGE_SIZE))
		return false;

	/*
	 * Get the smallest PA size of all CPUs (sanitized by cpufeature). We're
	 * not even pretending to support AArch32 here.
	 */
	reg = read_sanitised_ftr_reg(SYS_ID_AA64MMFR0_EL1);
	fld = cpuid_feature_extract_unsigned_field(reg,
				ID_AA64MMFR0_PARANGE_SHIFT);
	switch (fld) {
	case 0x0:
		oas = 32;
		break;
	case 0x1:
		oas = 36;
		break;
	case 0x2:
		oas = 40;
		break;
	case 0x3:
		oas = 42;
		break;
	case 0x4:
		oas = 44;
		break;
	case 0x5:
		oas = 48;
		break;
	case 0x6:
		oas = 52;
		break;
	default:
		return false;
	}

	/* abort if MMU outputs addresses greater than what we support. */
	if (smmu->oas < oas)
		return false;

	/* We can support bigger ASIDs than the CPU, but not smaller */
	fld = cpuid_feature_extract_unsigned_field(reg,
				ID_AA64MMFR0_ASID_SHIFT);
	asid_bits = fld ? 16 : 8;
	if (smmu->asid_bits < asid_bits)
		return false;

	/*
	 * See max_pinned_asids in arch/arm64/mm/context.c. The following is
	 * generally the maximum number of bindable processes.
	 */
	if (IS_ENABLED(CONFIG_UNMAP_KERNEL_AT_EL0))
		asid_bits--;
	dev_dbg(smmu->dev, "%d shared contexts\n", (1 << asid_bits) -
		num_possible_cpus() - 2);

	return true;
}

static int arm_smmu_device_hw_probe(struct arm_smmu_device *smmu)
{
	u32 reg;
	bool coherent = smmu->features & ARM_SMMU_FEAT_COHERENCY;
	bool vhe = cpus_have_cap(ARM64_HAS_VIRT_HOST_EXTN);

	/* IDR0 */
	reg = readl_relaxed(smmu->base + ARM_SMMU_IDR0);

	/* 2-level structures */
	if (FIELD_GET(IDR0_ST_LVL, reg) == IDR0_ST_LVL_2LVL)
		smmu->features |= ARM_SMMU_FEAT_2_LVL_STRTAB;

	if (reg & IDR0_CD2L)
		smmu->features |= ARM_SMMU_FEAT_2_LVL_CDTAB;

	/*
	 * Translation table endianness.
	 * We currently require the same endianness as the CPU, but this
	 * could be changed later by adding a new IO_PGTABLE_QUIRK.
	 */
	switch (FIELD_GET(IDR0_TTENDIAN, reg)) {
	case IDR0_TTENDIAN_MIXED:
		smmu->features |= ARM_SMMU_FEAT_TT_LE | ARM_SMMU_FEAT_TT_BE;
		break;
#ifdef __BIG_ENDIAN
	case IDR0_TTENDIAN_BE:
		smmu->features |= ARM_SMMU_FEAT_TT_BE;
		break;
#else
	case IDR0_TTENDIAN_LE:
		smmu->features |= ARM_SMMU_FEAT_TT_LE;
		break;
#endif
	default:
		dev_err(smmu->dev, "unknown/unsupported TT endianness!\n");
		return -ENXIO;
	}

	/* Boolean feature flags */
	if (IS_ENABLED(CONFIG_PCI_PRI) && reg & IDR0_PRI)
		smmu->features |= ARM_SMMU_FEAT_PRI;

	if (IS_ENABLED(CONFIG_PCI_ATS) && reg & IDR0_ATS)
		smmu->features |= ARM_SMMU_FEAT_ATS;

	if (reg & IDR0_SEV)
		smmu->features |= ARM_SMMU_FEAT_SEV;

	if (reg & IDR0_MSI)
		smmu->features |= ARM_SMMU_FEAT_MSI;

	if (reg & IDR0_HYP) {
		smmu->features |= ARM_SMMU_FEAT_HYP;
		if (vhe)
			smmu->features |= ARM_SMMU_FEAT_E2H;
	}

	if (reg & (IDR0_HA | IDR0_HD)) {
		smmu->features |= ARM_SMMU_FEAT_HA;
		if (reg & IDR0_HD)
			smmu->features |= ARM_SMMU_FEAT_HD;
	}

	/*
	 * If the CPU is using VHE, but the SMMU doesn't support it, the SMMU
	 * will create TLB entries for NH-EL1 world and will miss the
	 * broadcasted TLB invalidations that target EL2-E2H world. Don't enable
	 * BTM in that case.
	 */
	if (reg & IDR0_BTM && (!vhe || reg & IDR0_HYP))
		smmu->features |= ARM_SMMU_FEAT_BTM;

	/*
	 * The coherency feature as set by FW is used in preference to the ID
	 * register, but warn on mismatch.
	 */
	if (!!(reg & IDR0_COHACC) != coherent)
		dev_warn(smmu->dev, "IDR0.COHACC overridden by FW configuration (%s)\n",
			 coherent ? "true" : "false");

	switch (FIELD_GET(IDR0_STALL_MODEL, reg)) {
	case IDR0_STALL_MODEL_FORCE:
		smmu->features |= ARM_SMMU_FEAT_STALL_FORCE;
		/* Fallthrough */
	case IDR0_STALL_MODEL_STALL:
		smmu->features |= ARM_SMMU_FEAT_STALLS;
	}

	if (reg & IDR0_S1P)
		smmu->features |= ARM_SMMU_FEAT_TRANS_S1;

	if (reg & IDR0_S2P)
		smmu->features |= ARM_SMMU_FEAT_TRANS_S2;

	if (!(reg & (IDR0_S1P | IDR0_S2P))) {
		dev_err(smmu->dev, "no translation support!\n");
		return -ENXIO;
	}

	/* We only support the AArch64 table format at present */
	switch (FIELD_GET(IDR0_TTF, reg)) {
	case IDR0_TTF_AARCH32_64:
		smmu->ias = 40;
		/* Fallthrough */
	case IDR0_TTF_AARCH64:
		break;
	default:
		dev_err(smmu->dev, "AArch64 table format not supported!\n");
		return -ENXIO;
	}

	/* ASID/VMID sizes */
	smmu->asid_bits = reg & IDR0_ASID16 ? 16 : 8;
	smmu->vmid_bits = reg & IDR0_VMID16 ? 16 : 8;

	/* IDR1 */
	reg = readl_relaxed(smmu->base + ARM_SMMU_IDR1);
	if (reg & (IDR1_TABLES_PRESET | IDR1_QUEUES_PRESET | IDR1_REL)) {
		dev_err(smmu->dev, "embedded implementation not supported\n");
		return -ENXIO;
	}

	/* Queue sizes, capped at 4k */
	smmu->cmdq.q.max_n_shift = min_t(u32, CMDQ_MAX_SZ_SHIFT,
					 FIELD_GET(IDR1_CMDQS, reg));
	if (!smmu->cmdq.q.max_n_shift) {
		/* Odd alignment restrictions on the base, so ignore for now */
		dev_err(smmu->dev, "unit-length command queue not supported\n");
		return -ENXIO;
	}

	smmu->evtq.q.max_n_shift = min_t(u32, EVTQ_MAX_SZ_SHIFT,
					 FIELD_GET(IDR1_EVTQS, reg));
	smmu->priq.q.max_n_shift = min_t(u32, PRIQ_MAX_SZ_SHIFT,
					 FIELD_GET(IDR1_PRIQS, reg));

	/* SID/SSID sizes */
	smmu->ssid_bits = FIELD_GET(IDR1_SSIDSIZE, reg);
	smmu->sid_bits = FIELD_GET(IDR1_SIDSIZE, reg);

	/*
	 * If the SMMU supports fewer bits than would fill a single L2 stream
	 * table, use a linear table instead.
	 */
	if (smmu->sid_bits <= STRTAB_SPLIT)
		smmu->features &= ~ARM_SMMU_FEAT_2_LVL_STRTAB;

	/* IDR5 */
	reg = readl_relaxed(smmu->base + ARM_SMMU_IDR5);

	/* Maximum number of outstanding stalls */
	smmu->evtq.max_stalls = FIELD_GET(IDR5_STALL_MAX, reg);

	/* Page sizes */
	if (reg & IDR5_GRAN64K)
		smmu->pgsize_bitmap |= SZ_64K | SZ_512M;
	if (reg & IDR5_GRAN16K)
		smmu->pgsize_bitmap |= SZ_16K | SZ_32M;
	if (reg & IDR5_GRAN4K)
		smmu->pgsize_bitmap |= SZ_4K | SZ_2M | SZ_1G;

	/* Input address size */
	if (FIELD_GET(IDR5_VAX, reg) == IDR5_VAX_52_BIT)
		smmu->features |= ARM_SMMU_FEAT_VAX;

	/* Output address size */
	switch (FIELD_GET(IDR5_OAS, reg)) {
	case IDR5_OAS_32_BIT:
		smmu->oas = 32;
		break;
	case IDR5_OAS_36_BIT:
		smmu->oas = 36;
		break;
	case IDR5_OAS_40_BIT:
		smmu->oas = 40;
		break;
	case IDR5_OAS_42_BIT:
		smmu->oas = 42;
		break;
	case IDR5_OAS_44_BIT:
		smmu->oas = 44;
		break;
	case IDR5_OAS_52_BIT:
		smmu->oas = 52;
		smmu->pgsize_bitmap |= 1ULL << 42; /* 4TB */
		break;
	default:
		dev_info(smmu->dev,
			"unknown output address size. Truncating to 48-bit\n");
		/* Fallthrough */
	case IDR5_OAS_48_BIT:
		smmu->oas = 48;
	}

	if (arm_smmu_ops.pgsize_bitmap == -1UL)
		arm_smmu_ops.pgsize_bitmap = smmu->pgsize_bitmap;
	else
		arm_smmu_ops.pgsize_bitmap |= smmu->pgsize_bitmap;

	/* Set the DMA mask for our table walker */
	if (dma_set_mask_and_coherent(smmu->dev, DMA_BIT_MASK(smmu->oas)))
		dev_warn(smmu->dev,
			 "failed to set DMA mask for table walker\n");

	smmu->ias = max(smmu->ias, smmu->oas);

	if (arm_smmu_supports_sva(smmu))
		smmu->features |= ARM_SMMU_FEAT_SVA;

	dev_info(smmu->dev, "ias %lu-bit, oas %lu-bit (features 0x%08x)\n",
		 smmu->ias, smmu->oas, smmu->features);
	return 0;
}

#ifdef CONFIG_ACPI
static void acpi_smmu_get_options(u32 model, struct arm_smmu_device *smmu)
{
	switch (model) {
	case ACPI_IORT_SMMU_V3_CAVIUM_CN99XX:
		smmu->options |= ARM_SMMU_OPT_PAGE0_REGS_ONLY;
		break;
	case ACPI_IORT_SMMU_V3_HISILICON_HI161X:
		smmu->options |= ARM_SMMU_OPT_SKIP_PREFETCH;
		break;
	}

	dev_notice(smmu->dev, "option mask 0x%x\n", smmu->options);
}

static int arm_smmu_device_acpi_probe(struct platform_device *pdev,
				      struct arm_smmu_device *smmu)
{
	struct acpi_iort_smmu_v3 *iort_smmu;
	struct device *dev = smmu->dev;
	struct acpi_iort_node *node;

	node = *(struct acpi_iort_node **)dev_get_platdata(dev);

	/* Retrieve SMMUv3 specific data */
	iort_smmu = (struct acpi_iort_smmu_v3 *)node->node_data;

	acpi_smmu_get_options(iort_smmu->model, smmu);

	if (iort_smmu->flags & ACPI_IORT_SMMU_V3_COHACC_OVERRIDE)
		smmu->features |= ARM_SMMU_FEAT_COHERENCY;

	return 0;
}
#else
static inline int arm_smmu_device_acpi_probe(struct platform_device *pdev,
					     struct arm_smmu_device *smmu)
{
	return -ENODEV;
}
#endif

static int arm_smmu_device_dt_probe(struct platform_device *pdev,
				    struct arm_smmu_device *smmu)
{
	struct device *dev = &pdev->dev;
	u32 cells;
	int ret = -EINVAL;

	if (of_property_read_u32(dev->of_node, "#iommu-cells", &cells))
		dev_err(dev, "missing #iommu-cells property\n");
	else if (cells != 1)
		dev_err(dev, "invalid #iommu-cells value (%d)\n", cells);
	else
		ret = 0;

	parse_driver_options(smmu);

	if (of_dma_is_coherent(dev->of_node))
		smmu->features |= ARM_SMMU_FEAT_COHERENCY;

	return ret;
}

static unsigned long arm_smmu_resource_size(struct arm_smmu_device *smmu)
{
	if (smmu->options & ARM_SMMU_OPT_PAGE0_REGS_ONLY)
		return SZ_64K;
	else
		return SZ_128K;
}

static int arm_smmu_device_probe(struct platform_device *pdev)
{
	int irq, ret;
	struct resource *res;
	resource_size_t ioaddr;
	struct arm_smmu_device *smmu;
	struct device *dev = &pdev->dev;
	bool bypass;

	smmu = devm_kzalloc(dev, sizeof(*smmu), GFP_KERNEL);
	if (!smmu) {
		dev_err(dev, "failed to allocate arm_smmu_device\n");
		return -ENOMEM;
	}
	smmu->dev = dev;

	if (dev->of_node) {
		ret = arm_smmu_device_dt_probe(pdev, smmu);
	} else {
		ret = arm_smmu_device_acpi_probe(pdev, smmu);
		if (ret == -ENODEV)
			return ret;
	}

	/* Set bypass mode according to firmware probing result */
	bypass = !!ret;

	/* Base address */
	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	if (resource_size(res) + 1 < arm_smmu_resource_size(smmu)) {
		dev_err(dev, "MMIO region too small (%pr)\n", res);
		return -EINVAL;
	}
	ioaddr = res->start;

	smmu->base = devm_ioremap_resource(dev, res);
	if (IS_ERR(smmu->base))
		return PTR_ERR(smmu->base);

	/* Interrupt lines */

	irq = platform_get_irq_byname(pdev, "combined");
	if (irq > 0)
		smmu->combined_irq = irq;
	else {
		irq = platform_get_irq_byname(pdev, "eventq");
		if (irq > 0)
			smmu->evtq.q.irq = irq;

		irq = platform_get_irq_byname(pdev, "priq");
		if (irq > 0)
			smmu->priq.q.irq = irq;

		irq = platform_get_irq_byname(pdev, "gerror");
		if (irq > 0)
			smmu->gerr_irq = irq;
	}
	/* Probe the h/w */
	ret = arm_smmu_device_hw_probe(smmu);
	if (ret)
		return ret;

	/* Initialise in-memory data structures */
	ret = arm_smmu_init_structures(smmu);
	if (ret)
		return ret;

	/* Record our private device structure */
	platform_set_drvdata(pdev, smmu);

	/* Reset the device */
	ret = arm_smmu_device_reset(smmu, bypass);
	if (ret)
		return ret;

	if (smmu->features & (ARM_SMMU_FEAT_STALLS | ARM_SMMU_FEAT_PRI)) {
		smmu->iopf_queue = iopf_queue_alloc(dev_name(dev),
						    arm_smmu_flush_queues,
						    smmu);
		if (!smmu->iopf_queue)
			return -ENOMEM;
	}

	/* And we're up. Go go go! */
	ret = iommu_device_sysfs_add(&smmu->iommu, dev, NULL,
				     "smmu3.%pa", &ioaddr);
	if (ret)
		return ret;

	iommu_device_set_ops(&smmu->iommu, &arm_smmu_ops);
	iommu_device_set_fwnode(&smmu->iommu, dev->fwnode);

	ret = iommu_device_register(&smmu->iommu);
	if (ret) {
		dev_err(dev, "Failed to register iommu\n");
		return ret;
	}

#ifdef CONFIG_PCI
	if (pci_bus_type.iommu_ops != &arm_smmu_ops) {
		pci_request_acs();
		ret = bus_set_iommu(&pci_bus_type, &arm_smmu_ops);
		if (ret)
			return ret;
	}
#endif
#ifdef CONFIG_ARM_AMBA
	if (amba_bustype.iommu_ops != &arm_smmu_ops) {
		ret = bus_set_iommu(&amba_bustype, &arm_smmu_ops);
		if (ret)
			return ret;
	}
#endif
	if (platform_bus_type.iommu_ops != &arm_smmu_ops) {
		ret = bus_set_iommu(&platform_bus_type, &arm_smmu_ops);
		if (ret)
			return ret;
	}
	return 0;
}

static int arm_smmu_device_remove(struct platform_device *pdev)
{
	struct arm_smmu_device *smmu = platform_get_drvdata(pdev);

	iopf_queue_free(smmu->iopf_queue);
	arm_smmu_device_disable(smmu);

	return 0;
}

static void arm_smmu_device_shutdown(struct platform_device *pdev)
{
	arm_smmu_device_remove(pdev);
}

static const struct of_device_id arm_smmu_of_match[] = {
	{ .compatible = "arm,smmu-v3", },
	{ },
};
MODULE_DEVICE_TABLE(of, arm_smmu_of_match);

static struct platform_driver arm_smmu_driver = {
	.driver	= {
		.name		= "arm-smmu-v3",
		.of_match_table	= of_match_ptr(arm_smmu_of_match),
	},
	.probe	= arm_smmu_device_probe,
	.remove	= arm_smmu_device_remove,
	.shutdown = arm_smmu_device_shutdown,
};
module_platform_driver(arm_smmu_driver);

MODULE_DESCRIPTION("IOMMU API for ARM architected SMMUv3 implementations");
MODULE_AUTHOR("Will Deacon <will.deacon@arm.com>");
MODULE_LICENSE("GPL v2");
