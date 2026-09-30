/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2026 Huawei Ltd.
 */
#ifndef __ASM_TLBID_H
#define __ASM_TLBID_H

#include <linux/types.h>

#ifdef CONFIG_ARM64_TLBID

struct tlbi_target {
	u32 identifier;
	s32 *domains;
	s32 nr_domain;
	struct list_head list;
};

int add_target(int type, struct tlbi_target *target);
void tlbid_data_reset(void);
int __init parse_tlbid_topology(void);
int pick_best_domain(const cpumask_t *active_cpus);

#else
static inline int pick_best_domain(const cpumask_t *active_cpus) { return 0; }

#endif /* ! CONFIG_ARM64_TLBID */
#endif
