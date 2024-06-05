/* SPDX-License-Identifier: GPL-2.0 */
/*
 * spe.h: Arm Statistical Profiling Extensions support
 * Copyright (c) 2019-2020, Arm Ltd.
 * Copyright (c) 2024-2025, Huawei Technologies Ltd.
 */

#ifndef __SPE_H
#define __SPE_H

#define SPE_BUFFER_MAX_SIZE		(PAGE_SIZE)
#define SPE_BUFFER_SIZE		(PAGE_SIZE / 32)

#define SPE_SAMPLE_PERIOD		1024

#define SPE_RECORD_BUFFER_MAX_RECORDS	(100)
#define SPE_RECORD_ENTRY_SIZE		sizeof(struct arm_spe_record)

#define SPE_PMU_FEAT_FILT_EVT		(1UL << 0)
#define SPE_PMU_FEAT_FILT_TYP		(1UL << 1)
#define SPE_PMU_FEAT_FILT_LAT		(1UL << 2)
#define SPE_PMU_FEAT_ARCH_INST		(1UL << 3)
#define SPE_PMU_FEAT_LDS		(1UL << 4)
#define SPE_PMU_FEAT_ERND		(1UL << 5)
#define SPE_PMU_FEAT_INV_FILT_EVT	(1UL << 6)
#define SPE_PMU_FEAT_DEV_PROBED	(1UL << 63)
#define PMBLIMITR_EL1_E			GENMASK(0, 0)
#define PMBSR_EL1_S			GENMASK(17, 17)
#define PMBSR_EL1_EC			GENMASK(31, 26)
#define PMBSR_EL1_EC_BUF		UL(0b000000)
#define PMBSR_EL1_EC_FAULT_S1		UL(0b100100)
#define PMBSR_EL1_EC_FAULT_S2		UL(0b100101)
#define PMBSR_EL1_MSS_MASK		GENMASK(15, 0)
#define PMBSR_EL1_BUF_BSC_MASK		PMBSR_EL1_MSS_MASK
#define PMBSR_EL1_BUF_BSC_FULL		0x1UL
#define PMSFCR_EL1_LD			GENMASK(17, 17)
#define PMSFCR_EL1_ST			GENMASK(18, 18)
#define PMSFCR_EL1_B			GENMASK(16, 16)
#define PMSFCR_EL1_FnE			GENMASK(3, 3)
#define PMSFCR_EL1_FT			GENMASK(1, 1)
#define PMSFCR_EL1_FE			GENMASK(0, 0)
#define PMSFCR_EL1_FL			GENMASK(2, 2)
#define PMSIRR_EL1_INTERVAL_MASK	GENMASK(31, 8)
#define PMSCR_EL1_TS			GENMASK(5, 5)
#define PMSCR_EL1_PA			GENMASK(4, 4)
#define PMSCR_EL1_CX			GENMASK(3, 3)
#define PMSCR_EL1_E1SPE			GENMASK(1, 1)
#define PMSCR_EL1_E0SPE			GENMASK(0, 0)
#define ID_AA64DFR0_EL1_PMSVer_SHIFT	32
#define PMBIDR_EL1_P			GENMASK(4, 4)
#define PMBIDR_EL1_ALIGN		GENMASK(3, 0)
#define PMSIDR_EL1_FE			GENMASK(0, 0)
#define PMSIDR_EL1_FnE			GENMASK(6, 6)
#define PMSIDR_EL1_FT			GENMASK(1, 1)
#define PMSIDR_EL1_ARCHINST		GENMASK(3, 3)
#define PMSIDR_EL1_LDS			GENMASK(4, 4)
#define PMSIDR_EL1_ERND			GENMASK(5, 5)
#define PMSIDR_EL1_INTERVAL		GENMASK(11, 8)
#define PMSIDR_EL1_INTERVAL_256		UL(0b0000)
#define PMSIDR_EL1_INTERVAL_512		UL(0b0010)
#define PMSIDR_EL1_INTERVAL_768		UL(0b0011)
#define PMSIDR_EL1_INTERVAL_1024	UL(0b0100)
#define PMSIDR_EL1_INTERVAL_1536	UL(0b0101)
#define PMSIDR_EL1_INTERVAL_2048	UL(0b0110)
#define PMSIDR_EL1_INTERVAL_3072	UL(0b0111)
#define PMSIDR_EL1_INTERVAL_4096	UL(0b1000)
#define PMSIDR_EL1_MAXSIZE		GENMASK(15, 12)
#define PMSIDR_EL1_COUNTSIZE		GENMASK(19, 16)
#define PMSIDR_EL1_COUNTSIZE_12_BIT_SAT	UL(0b0010)
#define PMSIDR_EL1_COUNTSIZE_16_BIT_SAT	UL(0b0011)
#define PMSIDR_EL1_FL			GENMASK(2, 2)
#define SYS_PMSNEVFR_EL1		sys_reg(3, 0, 9, 9, 1)
#define SPE_PMU_FEAT_INV_FILT_EVT	(1UL << 6)

enum arm_spe_buf_fault_action {
	SPE_PMU_BUF_FAULT_ACT_SPURIOUS,
	SPE_PMU_BUF_FAULT_ACT_FATAL,
	SPE_PMU_BUF_FAULT_ACT_OK,
};

struct arm_spe {
	struct pmu			pmu;
	struct platform_device		*pdev;
	cpumask_t			supported_cpus;
	struct hlist_node		hotplug_node;
	int				irq; /* PPI */
	u16				pmsver;
	u16				min_period;
	u16				counter_sz;
	u64				features;
	u16				max_record_sz;
	u16				align;
	u64				sample_period;
	local64_t			period_left;
	bool				jitter;
	bool				load_filter;
	bool				store_filter;
	bool				branch_filter;
	u64				inv_event_filter;
	u16				min_latency;
	u64				event_filter;
	bool				ts_enable;
	bool				pa_enable;
	u8				pct_enable;
	bool				exclude_user;
	bool				exclude_kernel;
};

struct arm_spe_buf {
	void				*cur;		/* for spe raw data buffer */
	int				size;
	int				period;
	void				*base;

	void				*record_base;	/* for spe record buffer */
	int				record_size;
	int				nr_records;
};

#endif /* __SPE_H */
