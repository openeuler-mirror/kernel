/*
 * Copyright (C) Huawei Technologies Co., Ltd. 2019. All rights reserved.
 * Author: Huawei OS Kernel Lab
 * Create: Fri Jan 11 10:45:12 2019
 */
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/freezer.h>
#include <linux/fs.h>
#include <linux/stat.h>
#include <linux/buffer_head.h>
#include <linux/hugetlb.h>
#include <linux/mm.h>
#include <linux/cgroup.h>
#include <linux/memcontrol.h>
#include <linux/sched/mm.h>
#include <asm/segment.h>
#include <linux/uaccess.h>
#include "hugepage_tuning.h"

MODULE_LICENSE("GPL");
MODULE_VERSION("0.01");

/* config huge page number */
/* We had a hard limit: 50% * total memory */
static unsigned long config_hugepage_nr;
module_param(config_hugepage_nr, ulong, 0644);

/* max hugepages. ratio from 1-50 */
static unsigned int config_ratio = 50;
module_param(config_ratio, int, 0644);

/* config memcgroup */
static char *config_memcgroup = "usermemory";
module_param(config_memcgroup, charp, 0644);

/* cooldown time */
static unsigned int config_cooldown_time = 60;
module_param(config_cooldown_time, int, 0644);

/* cpu mask */
static unsigned int config_cpu_mask;
module_param(config_cpu_mask, int, 0644);

/* auto drop cache */
static unsigned int config_drop_cache = 1;
module_param(config_drop_cache, int, 0644);

/* auto compat */
static unsigned int config_mem_compat;
module_param(config_mem_compat, int, 0644);

static struct shrinker huge_tuning_shrinker = {
	.count_objects = hugepage_tuning_shrink,
	.scan_objects = hugepage_tuning_scan,
	.seeks = DEFAULT_SEEKS,
};

/* pointer to hugepage status */
static const struct hstate *hs;
/* pointer to hugepage tuning sysfs node */
static struct kobject *hp_sysfs_node;

/* kernel hugepage tuning main worker thrad */
static struct task_struct *khptuning_thread __read_mostly;

/* used to wakeup */
static int notify_flag;
static int cooldown_time;
static DECLARE_WAIT_QUEUE_HEAD(khptuning_wait);
static DEFINE_MUTEX(tuning_lock);
static struct hugepage_tuning hp;

static char buff[BUFF_LEN];
/* this function used to write sys file. */
int sysctl_write_file(char *path, int nr)
{
	struct file *filp = NULL;
	int err;
	mm_segment_t oldfs;

	oldfs = get_fs();
	set_fs(KERNEL_DS);
	filp = filp_open(path, O_WRONLY, 0200);
	if (IS_ERR(filp)) {
		err = PTR_ERR(filp);
		pr_info("hugepage_tuning: open file %s failed err %d\n",
			 path, err);
		return err;
	}
	memset(buff, 0, sizeof(buff));
	sprintf(buff, "%d\n", nr);
	err = filp->f_op->write(filp, buff, sizeof(buff), &filp->f_pos);
	if (err < 0) {
		pr_err("hugepage_tuning: write file %s faild err %d]n",
			path, err);
	}

	set_fs(oldfs);
	filp_close(filp, NULL);
	return err;
}

static struct kernfs_open_file *kernfs_of(struct file *file)
{
	return ((struct seq_file *)file->private_data)->private;
}

/* get memory cgroup from /sys/fs/cgroup */
struct mem_cgroup *get_mem_cgroup_from_path(void)
{
	struct file *filp = NULL;
	int err;
	char path[PATH_LEN];
	struct kernfs_open_file *of;
	struct mem_cgroup *mcg;

	strreplace(config_memcgroup, '\n', '\0');
	snprintf(path, sizeof(path), MEMCGR, config_memcgroup);
	filp = filp_open(path, O_WRONLY, 0200);
	if (IS_ERR(filp)) {
		err = PTR_ERR(filp);
		pr_info("hugepage_tuning: open file %s failed err %d\n",
			path, err);
		return NULL;
	}
	of = kernfs_of(filp);
	mcg = mem_cgroup_from_css(of_css(of));
	filp_close(filp, NULL);

	return mcg;
}
/*
 * This function call sysctl_set_hugepage to increase or reduce the total num
 * of hugepage.
nr: total hugepage nr
ret val: diff of total hugepage nr
 */
s64 sysctl_set_hugepage(u64 nr)
{
	int err;
	u64 total = hs->nr_huge_pages;

	if (total == nr) {
		/* nothing todo */
		err = 0;
		goto out;
	}
	/* call sysctrl to change hugepage num */
	err = hugetlb_sysctl_store(nr);
	if (err < 0)
		goto out;

	/* return diff nr */
	err = hs->nr_huge_pages - total;
out:
	return err;
}
/* shrink as soon as possible */
unsigned long hugepage_tuning_shrink(struct shrinker *s,
				     struct shrink_control *sc)
{
	int free_nr = 0;

	/* do not shrink when the tuning thread is hot, wait 10 seconds */
	if (!time_after(jiffies, hp.adjust_time + 10 * HZ) || hp.hot)
		return 0;

	/* free 10% * free huge page */
	if (hs->free_huge_pages > hp.mmap_last) {
		/* reserve at least one mmap step */
		free_nr = (hs->free_huge_pages - hp.mmap_last) / 10;
	}

	if (free_nr > 0) {
		/* free hugepage, no need to count */
		sysctl_set_hugepage(hs->nr_huge_pages - free_nr);
		hp.shrink_count += free_nr;
	}

	return free_nr;
}

unsigned long hugepage_tuning_scan(struct shrinker *s,
				   struct shrink_control *sc)
{
	/* just retuern 0 */
	return 0;
}

static int mmap_notifier(struct notifier_block *self, unsigned long arg1,
		void *arg2)
{
	u64 nr = arg1 / (2 * SIZE_MB);

	/* record max step tied by [MMAP_MIN, MMAP_MAX]*/
	if (nr > MMAP_MAX)
		hp.mmap_last = MMAP_MAX;
	else if (nr > MMAP_MIN)
		hp.mmap_last = nr;
	else
		hp.mmap_last = MMAP_MIN;

	/* if there's not enough free huge page */
	if (nr > hs->free_huge_pages) {
		/* wakeup cool worker to alloc more hugepage */
		if (!cooldown_time) {
			hp.mmap_fail++;
			/* don't bother a hot worker */
			notify_flag = 1;
			wake_up(&khptuning_wait);
		} else {
			/* the worker is hot, just ignore */
			hp.mmap_fail_hot++;
		}
	} else {
		/* nice try */
		hp.mmap_succ++;
	}
	return 0;
}
static struct notifier_block mmap_handle = {
	.notifier_call = mmap_notifier
};

static int oom_notifier(struct notifier_block *self,
		unsigned long arg1, void *arg2)
{
	*(unsigned long *)arg2 = hugepage_tuning_shrink(NULL, NULL);
	return 0;
}
static struct notifier_block oom_handle = {
	.notifier_call = oom_notifier
};

static void hugepage_tuning_shake(struct hugepage_tuning *hp)
{
	int err;
	/* there's enough memory, but fragmentization */
	/* drop cache and compact_memory and retry */
	if (config_drop_cache) {
		err = sysctl_write_file(PATH_DROP, 3);
		if (!err)
			pr_info("hugepage_tuning: do drop cache!\n");

		cooldown_time = config_cooldown_time;
		hp->stat_drop_compat++;
	}
	if (config_mem_compat) {
		err = sysctl_write_file(PATH_COMPAT, 1);
		if (!err)
			pr_info("hugepage_tuning: do memory compat!\n");

		cooldown_time = config_cooldown_time * 10;
		hp->stat_drop_compat++;
	}
}
/*
 * main worker thread
 * drop cache and compat memory are hard work, we should prevent the
 * shaking by cooldown_time
 */
static int khptuningd(void *none)
{
	struct mem_cgroup *memcg;
	u64 last_miss;
	u64 want = 0;
	u64 available;
	u64 step_nr;
	s64 num;
	struct sysinfo i;
	u64 system_free;

	set_freezable();
	set_user_nice(current, MAX_NICE);
	last_miss = hp.mmap_fail;

	/* setup memcgroup */
	memcg = get_mem_cgroup_from_path();
	if (!memcg) {
		pr_err("hugepage_tuning: can't find memcgroup [%s]\n",
			config_memcgroup);
		khptuning_thread = NULL;
		return -EINVAL;
	}
	memalloc_use_memcg(memcg);

	/* create huge page */
	hp.hot = 1;
	sysctl_set_hugepage(hp.init_nr);
	hp.hot = 0;

	/* check if we should stop */
	while (!kthread_should_stop()) {
		/* 1st. each cycle we count 'available' and system free */
		hp.hot = 1;
		available = hp.max_nr > hs->nr_huge_pages ?
				hp.max_nr - hs->nr_huge_pages : 0;
		/* system memory threadhold */
		si_meminfo(&i);
		system_free = (i.freeram + i.bufferram) * 4 * SIZE_KB /
			(2 * SIZE_MB);

		/* 2nd. mmap_fail more than last_miss means in the last cycle
		 * there's new mmap fail occur, so we need more page.
		 */
		if (hp.mmap_fail > last_miss) {
			/* max step, should not bigger than MMAP_MAX */
			step_nr = hp.mmap_last > MMAP_MAX ?
					MMAP_MAX : hp.mmap_last;
			want = (hp.mmap_fail - last_miss) * step_nr;
		}

		/* 3rd. now we hava available, wanted, free. only free < want
		 * < available + free we can create new huge page
		 */
		if (want > 0 && want <= (available + hs->free_huge_pages)) {
			if (want < (system_free / 2)) {
				num = sysctl_set_hugepage(hs->nr_huge_pages + want);
				hp.adjust_count += num;
				hp.adjust_time = jiffies;
			} else {
				num = 0;
				hp.adjust_fail++;
			}

			if (num + hs->free_huge_pages >= want) {
				/* very good, there's enough memory */
				last_miss = hp.mmap_fail;
			} else {
				/* do drop cache and compat when there's at
				 * least 1GB memory
				 */
				if (cooldown_time == 0 && system_free > 500) {
					hugepage_tuning_shake(&hp);
				} else {
					/* very bad. retry fail. */
					last_miss = hp.mmap_fail;
					hp.adjust_fail++;
				}
			}
		} else {
			/* there' no work to do or no enough memory:
			 * 1. mmap is too large, more than hs->free_huge_pages.
			 * 2. reach the max_nr limit
			 * just update stat miss
			 */
			last_miss = hp.mmap_fail;
			if (want > 0)
				hp.adjust_fail++;
		}

		/* cycle done, reset all vals */
		if (notify_flag == 0 && cooldown_time > 0) {
			/* only timeout process can reduce cooldown time */
			cooldown_time--;
		}
		want = 0;
		notify_flag = 0;
		hp.stat_wake++;
		hp.hot = 0;
		/* start cycle every second or wake up by notify_flag */
		wait_event_timeout(khptuning_wait, (notify_flag == 1), 10 * HZ);
	}

	memalloc_unuse_memcg();
	mem_cgroup_put(memcg);
	return 0;
}

/* unregister sysfs */
static void hp_sysfs_release(struct kobject *kobj)
{
	kfree(kobj);
}

static ssize_t hugepage_tuning_attr_show(struct kobject *kobj,
					 struct attribute *attr,
					 char *buf)
{
	struct kobj_attribute *kattr;
	ssize_t ret = -EIO;

	kattr = container_of(attr, struct kobj_attribute, attr);
	if (kattr->show)
		ret = kattr->show(kobj, kattr, buf);
	return ret;
}

static ssize_t hugepage_tuning_attr_store(struct kobject *kobj,
					  struct attribute *attr,
					  const char *buf,
					  size_t count)
{
	struct kobj_attribute *kattr;
	ssize_t ret = -EIO;

	kattr = container_of(attr, struct kobj_attribute, attr);
	if (kattr->store)
		ret = kattr->store(kobj, kattr, buf, count);
	return ret;
}

static const struct sysfs_ops hp_sysfs_ops = {
	.show = hugepage_tuning_attr_show,
	.store = hugepage_tuning_attr_store,
};

static ssize_t hp_stat_show(struct kobject *kobj,
		struct kobj_attribute *attr, char *buf)
{
	return sprintf(buf, "initnr: %lld\n"
			"maxnr: %lld\n"
			"ratio: %d\n"
			"huge_nr: %ld\n"
			"free_nr: %ld\n"
			"mmap_last: %lld\n"
			"mmap_succ: %lld\n"
			"mmap_fail: %lld\n"
			"mmap_fail_hot: %lld\n"
			"shrink_count: %lld\n"
			"wake: %lld\n"
			"adjust_count: %lld\n"
			"adjust_fail: %lld\n"
			"drop_compat: %lld\n",
			hp.init_nr, hp.max_nr, hp.ratio, hs->nr_huge_pages,
			hs->free_huge_pages,
			hp.mmap_last, hp.mmap_succ, hp.mmap_fail,
			hp.mmap_fail_hot,
			hp.shrink_count,
			hp.stat_wake, hp.adjust_count, hp.adjust_fail,
			hp.stat_drop_compat);
}

static ssize_t hp_stat_store(struct kobject *kobj,
		struct kobj_attribute *attr, const char *buf, size_t len)
{
	return -EACCES;
}

static struct kobj_attribute hugepage_tuning_attr_name =
__ATTR(status, 0444, hp_stat_show, hp_stat_store);

static char hp_enable[BUFF_LEN] = "0\n";

static ssize_t hp_enable_show(struct kobject *kobj,
		struct kobj_attribute *attr, char *buf)
{
	return sprintf(buf, hp_enable);
}

static ssize_t hp_enable_store(struct kobject *kobj,
		struct kobj_attribute *attr, const char *buf, size_t len)
{
	int err = 0;

	if (strcmp(buf, "1\n") == 0) {
		err = hugepage_tuning_enable();
		if (err < 0)
			return err;
		hp_enable[0] = '1';
	} else if (strcmp(buf, "0\n") == 0) {
		hugepage_tuning_disable();
		hp_enable[0] = '0';
	} else {
		pr_err("hugepage_tuning: invalid val to enable: %s(len %ld)\n",
			buf, len);
		return -EINVAL;
	}
	return len;
}

static struct kobj_attribute hugepage_tuning_attr_string =
__ATTR(enable, 0644, hp_enable_show, hp_enable_store);

static struct attribute *default_attr[] = {
	&hugepage_tuning_attr_name.attr,
	&hugepage_tuning_attr_string.attr,
	NULL,
};

static struct kobj_type hp_sysfs_type = {
	.sysfs_ops = &hp_sysfs_ops,
	.release = hp_sysfs_release,
	.default_attrs = default_attr
};

/* config hugepage tuning thread */
int hugepage_tuning_config(void)
{
	int err = 0;
	struct sysinfo i;
	u64 half;

	memset(&hp, 0, sizeof(hp));

	/* 1st. we use ratio to config max nr */
	hp.ratio = config_ratio;
	si_meminfo(&i);
	half = (i.totalram * 50 * 4 * SIZE_KB) / (100 * SIZE_MB * 2);

	if (hp.ratio >= 0 && hp.ratio <= 50) {
		/* get sys meminfo, scale KB */
		hp.max_nr = (i.totalram * hp.ratio * 4 * SIZE_KB) /
				(100 * SIZE_MB * 2);

	} else {
		pr_info("hugepage_tuning: invalid ratio (%d), should in [0,50]\n", hp.ratio);
		err = -EINVAL;
		goto out;
	}

	/* 2nd. config_hugepage_nr */
	if (config_hugepage_nr > half) {
		pr_info("hugepage_tuning: invalid config_hugepage_nr (%ld), should less than half total memory.\n", config_hugepage_nr);
		err = -EINVAL;
		goto out;
	}
	if (config_hugepage_nr > 0)
		hp.max_nr = config_hugepage_nr;

	/* 3rd. config init nr not more than 25% * total for compatibility */
	if (config_ratio > 25)
		hp.init_nr = (i.totalram * 25 * 4 * SIZE_KB) / (100 * SIZE_MB * 2);

	hp.init_nr = hp.init_nr < hp.max_nr ? hp.init_nr : hp.max_nr;

	/* 4th. left */
	hp.mmap_last = MMAP_MIN; //default to MMAP_MIN to prevent too small step

out:
	return err;
}

/* create tuning thread and enable worker */
int hugepage_tuning_enable(void)
{
	int err = 0;

	/* lock */
	mutex_lock(&tuning_lock);

	if (khptuning_thread) {
		/* dup enable */
		pr_info("hugepage_tuning: hugepage tuning dup enable!\n");
		err = -EINVAL;
		goto out;
	}

	/* 1st. config tuning's hugepage nr */
	err = hugepage_tuning_config();
	if (err < 0)
		goto fail;

	/* 2nd. register shrinker */
	err = register_shrinker(&huge_tuning_shrinker);
	if (err < 0) {
		pr_info("hugepage_tuning: register shrinker failed! err = %d\n", err);
		goto fail;
	}

	/* 3rd. register mmap notifier */
	err = register_mmap_notifier(&mmap_handle);
	if (err < 0) {
		/* roll back register */
		unregister_shrinker(&huge_tuning_shrinker);

		pr_info("hugepage_tuning: register mmap handle failed! err = %d\n", err);
		goto fail;
	}
	/* 3rd. register mmap notifier */
	err = register_hisi_oom_notifier(&oom_handle);
	if (err < 0) {
		/* roll back register */
		unregister_shrinker(&huge_tuning_shrinker);
		unregister_mmap_notifier(&mmap_handle);

		pr_info("hugepage_tuning: register oom handle failed! err = %d\n", err);
		goto fail;
	}
	/* 4th. create and start thread */
	khptuning_thread = kthread_run(khptuningd, NULL, "khptuningd");
	if (IS_ERR(khptuning_thread)) {
		/* roll back register */
		unregister_shrinker(&huge_tuning_shrinker);
		unregister_mmap_notifier(&mmap_handle);
		unregister_hisi_oom_notifier(&oom_handle);

		err = PTR_ERR(khptuning_thread);
		khptuning_thread = NULL;
		pr_info("hugepage_tuning: kthread_run(khugepaged) failed err = %d\n", err);
		goto fail;
	}
	/* default bind to cpu 0 */
	err = set_cpus_allowed_ptr(khptuning_thread, cpumask_of(config_cpu_mask));
	if (err < 0) {
		/* roll back register */
		unregister_shrinker(&huge_tuning_shrinker);
		unregister_mmap_notifier(&mmap_handle);
		unregister_hisi_oom_notifier(&oom_handle);
		/* stop thread */
		kthread_stop(khptuning_thread);
		khptuning_thread = NULL;

		pr_err("Failed to set affinity to 0x%x CPU\n", config_cpu_mask);
		goto fail;
	}

	hugepage_gfp_mask = __GFP_ACCOUNT;
	mmap_notifier_enable = 1;
	/* unlock */
	mutex_unlock(&tuning_lock);
	return 0;
fail:
	/* reset all hugepage */
	sysctl_set_hugepage(0);
out:
	/* unlock */
	mutex_unlock(&tuning_lock);
	return err;
}

/* disable worker and destroy tuning thread */
void hugepage_tuning_disable(void)
{
	/* lock */
	mutex_lock(&tuning_lock);

	/* 1nd. unregister */
	unregister_shrinker(&huge_tuning_shrinker);
	unregister_mmap_notifier(&mmap_handle);
	unregister_hisi_oom_notifier(&oom_handle);

	/* 2nd. stop thread */
	if (khptuning_thread) {
		kthread_stop(khptuning_thread);
		khptuning_thread = NULL;
	}

	/* 3nd. free all hugepage */
	sysctl_set_hugepage(0);

	/* reset */
	hugepage_gfp_mask = 0;
	mmap_notifier_enable = 0;

	/* unlock */
	mutex_unlock(&tuning_lock);
}

/* module init */
static int __init hugepage_tuning_init(void)
{
	int err = 0;

	/* clean */
	memset(&hp, 0, sizeof(hp));

	/* global get hstate once */
	hs = hugetlb_get_hstate();

	/* sysfs create */
	hp_sysfs_node = kzalloc(sizeof(*hp_sysfs_node), GFP_KERNEL);
	if (!hp_sysfs_node) {
		pr_err("hugepage_tuning: alloc hp_sysfs_node faile!\n");
		return -EINVAL;
	}

	err = kobject_init_and_add(hp_sysfs_node, &hp_sysfs_type,
			NULL, "hugepage_tuning");
	if (err) {
		pr_err("hugepage_tuning: add hp_sysfs_node faile! err = %d.\n", err);
		/* free the mem */
		kobject_put(hp_sysfs_node);
		return -EINVAL;
	}
	return 0;
}

/* module exit */
static void __exit hugepage_tuning_exit(void)
{
	/* disable tuning thread */
	hugepage_tuning_disable();

	/* unlink kobject from hierarchy */
	kobject_del(hp_sysfs_node);
}

module_init(hugepage_tuning_init);
module_exit(hugepage_tuning_exit);
