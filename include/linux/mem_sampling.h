/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * mem_sampling.h: declare the mem_sampling abstract layer and provide
 * unified pmu sampling for NUMA, DAMON, etc.
 *
 * Sample records are converted to mem_sampling_record, and then
 * mem_sampling_record_captured_cb_type invoke the callbacks to
 * pass the record.
 *
 * Copyright (c) 2024-2025, Huawei Technologies Ltd.
 */
#ifndef __MEM_SAMPLING_H
#define __MEM_SAMPLING_H

DECLARE_STATIC_KEY_FALSE(sched_numabalancing_mem_sampling);

enum mem_sampling_sample_type {
	MEM_SAMPLING_L1D_ACCESS		= 1 << 0,
	MEM_SAMPLING_L1D_MISS		= 1 << 1,
	MEM_SAMPLING_LLC_ACCESS		= 1 << 2,
	MEM_SAMPLING_LLC_MISS		= 1 << 3,
	MEM_SAMPLING_TLB_ACCESS		= 1 << 4,
	MEM_SAMPLING_TLB_MISS		= 1 << 5,
	MEM_SAMPLING_BRANCH_MISS	= 1 << 6,
	MEM_SAMPLING_REMOTE_ACCESS	= 1 << 7,
};

enum mem_sampling_op_type {
	MEM_SAMPLING_LD	= 1 << 0,
	MEM_SAMPLING_ST	= 1 << 1,
};

struct mem_sampling_record {
	enum mem_sampling_sample_type	type;
	int				err;
	u32				op;
	u32				latency;
	u64				from_ip;
	u64				to_ip;
	u64				timestamp;
	u64				virt_addr;
	u64				phys_addr;
	u64				context_id;
	u16				source;
};

/*
 * Callbacks should be registered using mem_sampling_record_cb_register()
 * by NUMA, DAMON and etc during their initialisation.
 * Callbacks will be invoked on new hardware pmu records caputured.
 */
typedef void (*mem_sampling_record_cb_type)(struct mem_sampling_record *record);
void mem_sampling_record_cb_register(mem_sampling_record_cb_type cb);
void mem_sampling_record_cb_unregister(mem_sampling_record_cb_type cb);

#ifdef CONFIG_MEM_SAMPLING
void mem_sampling_sched_in(struct task_struct *prev, struct task_struct *curr);
#else
static inline void mem_sampling_sched_in(struct task_struct *prev, struct task_struct *curr) { }
#endif

#ifdef CONFIG_MEM_SAMPLING
bool mem_sampling_enabled(void);
#else
static inline bool mem_sampling_enabled(void)
{
	return false;
}
#endif

/* invoked by specific mem_sampling */
typedef void (*mem_sampling_cb_type)(struct mem_sampling_record *record_base,
				     int n_records);

struct mem_sampling_ops_struct {
	int (*sampling_start)(void);
	void (*sampling_stop)(void);
	void (*sampling_continue)(void);
};
extern struct mem_sampling_ops_struct mem_sampling_ops;

enum mem_sampling_type_enum {
	MEM_SAMPLING_ARM_SPE,
	MEM_SAMPLING_UNSUPPORTED
};

#ifdef CONFIG_ARM_SPE_MEM_SAMPLING
int arm_spe_start(void);
void arm_spe_stop(void);
void arm_spe_continue(void);
int arm_spe_enabled(void);
void arm_spe_record_capture_callback_register(mem_sampling_cb_type cb);
#else
static inline void arm_spe_stop(void) { }
static inline void arm_spe_continue(void) { }
static inline void arm_spe_record_capture_callback_register(mem_sampling_cb_type cb) { }

static inline int arm_spe_start(void)
{
	return 0;
}

static inline int arm_spe_enabled(void)
{
	return 0;
}
#endif /* CONFIG_ARM_SPE_MEM_SAMPLING */
#endif	/* __MEM_SAMPLING_H */
