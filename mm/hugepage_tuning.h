/*
 * Copyright (C) Huawei Technologies Co., Ltd. 2019. All rights reserved.
 * Author: Huawei OS Kernel Lab
 * Create: Fri Jan 11 10:45:12 2019
 */
#ifndef __MM_HUGEPAGE_TUNING_H__
#define __MM_HUGEPAGE_TUNING_H__

#define BUFF_LEN (32)
#define PATH_LEN (128)
#define SIZE_MB (1024 * 1024)
#define SIZE_KB (1024)
#define MMAP_MAX (100)
#define MMAP_MIN (10)
#define PATH_DROP "/proc/sys/vm/drop_caches"
#define PATH_COMPAT "/proc/sys/vm/compact_memory"
#define MEMCGR "/sys/fs/cgroup/memory/%s/memory.limit_in_bytes"

/* extern funcs */
extern int register_mmap_notifier(struct notifier_block *nb);
extern int unregister_mmap_notifier(struct notifier_block *nb);
extern int hugetlb_sysctl_store(size_t length);
extern int register_hisi_oom_notifier(struct notifier_block *nb);
extern int unregister_hisi_oom_notifier(struct notifier_block *nb);
extern gfp_t hugepage_gfp_mask;
extern int mmap_notifier_enable;

/* base funcs */
int hugepage_tuning_config(void);
int hugepage_tuning_enable(void);
void hugepage_tuning_disable(void);

/* for shrink */
unsigned long hugepage_tuning_shrink(struct shrinker *s,
				     struct shrink_control *sc);
unsigned long hugepage_tuning_scan(struct shrinker *s,
				     struct shrink_control *sc);

/* hugepage tuning control main struct */
struct hugepage_tuning {
	/* for compatibility, initnr is 25% sys mem*/
	u64 init_nr;
	/* max hugepage num, set by user */
	u64 max_nr;
	/* max hugepage num(ratio), set by user */
	int ratio;
	/* last mmap len */
	u64 mmap_last;
	/* mmap count */
	u64 mmap_succ;
	/* mmap fail */
	u64 mmap_fail;
	/* these misses will be ignore */
	u64 mmap_fail_hot;
	/* wake */
	u64 stat_wake;
	/* adjust huge page nr fail */
	u64 adjust_fail;
	/* adjust huge page nr count */
	u64 adjust_count;
	/* adjust time */
	unsigned long adjust_time;
	/* shrink hugepage number count */
	u64 shrink_count;
	/* drop and compat count */
	u64 stat_drop_compat;
	/* hot flag */
	int hot;
};
#endif
