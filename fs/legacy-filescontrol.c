// SPDX-License-Identifier: GPL-2.0
/* legacy-filescontrol.c - Cgroup controller for open file handles.
 *
 * Copyright 2014 Google Inc.
 * Author: Brian Makin <merimus@google.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <linux/page_counter.h>
#include <linux/legacy-filescontrol.h>
#include <linux/filescontrol.h>
#include <linux/cgroup.h>
#include <linux/export.h>
#include <linux/printk.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/seq_file.h>
#include <linux/fdtable.h>
#include <linux/sched/signal.h>
#include <linux/module.h>

#define FILES_MAX D_COUNT_MAX
#define FILES_MAX_STR "max"

static bool no_acct;
struct cgroup_subsys files_cgrp_subsys __read_mostly;

module_param(no_acct, bool, 0444);

struct files_cgroup {
	struct cgroup_subsys_state css;
	struct page_counter open_handles;
};

static inline bool files_cgroup_enabled(void)
{
	return cgroup_subsys_enabled(files_cgrp_subsys);
}

static inline struct files_cgroup *css_fcg(struct cgroup_subsys_state *css)
{
	return css ? container_of(css, struct files_cgroup, css) : NULL;
}

static inline struct page_counter *
css_res_open_handles(struct cgroup_subsys_state *css)
{
	return &css_fcg(css)->open_handles;
}

static inline struct files_cgroup *
files_cgroup_from_files(struct files_struct *files)
{
	return files->files_cgroup;
}


static struct cgroup_subsys_state *
files_cgroup_css_alloc(struct cgroup_subsys_state *parent_css)
{
	struct files_cgroup *parent_fcg;
	struct files_cgroup *fcg;

	parent_fcg = css_fcg(parent_css);
	fcg = kzalloc(sizeof(*fcg), GFP_KERNEL);
	if (!fcg)
		goto out;

	if (!parent_fcg) {
		page_counter_init(&fcg->open_handles, NULL);
		page_counter_set_max(&fcg->open_handles, FILES_MAX);
	} else {
		struct page_counter *p_counter = &parent_fcg->open_handles;

		page_counter_init(&fcg->open_handles, p_counter);
		page_counter_set_max(&fcg->open_handles, FILES_MAX);
	}
	return &fcg->css;

out:
	return ERR_PTR(-ENOMEM);
}

static void files_cgroup_css_free(struct cgroup_subsys_state *css)
{
	kfree(css_fcg(css));
}

/*
 * A files migration performed by ->can_attach(), recording the migrated
 * files_struct and the css it is moved from/to so that the move can be
 * rolled back later.
 */
struct files_migrate_entry {
	struct files_struct *files;
	struct cgroup_subsys_state *from_css;
	struct cgroup_subsys_state *to_css;
	struct list_head node;
};

static LIST_HEAD(files_migrate_entries);

/* Undo exactly the files_structs ->can_attach() actually migrated. */
static void files_migrate_rollback(void)
{
	struct files_migrate_entry *mig_entry, *next_entry;
	struct cgroup_subsys_state *from_css, *to_css;
	struct page_counter *from_res, *to_res;
	struct files_struct *files;
	u64 num_files;
	LIST_HEAD(list);

	list_splice_init(&files_migrate_entries, &list);

	list_for_each_entry_safe(mig_entry, next_entry, &list, node) {
		from_css = mig_entry->from_css;
		to_css = mig_entry->to_css;
		files = mig_entry->files;

		list_del(&mig_entry->node);

		from_res = css_res_open_handles(from_css);
		to_res = css_res_open_handles(to_css);

		spin_lock(&files->file_lock);
		num_files = file_cg_count_fds(files);
		page_counter_uncharge(to_res, num_files);
		page_counter_charge(from_res, num_files);
		css_put(to_css);
		files->files_cgroup = css_fcg(from_css);
		spin_unlock(&files->file_lock);

		/*
		 * Drop the references taken when the move was recorded:
		 * the pin on @files (this may free it, which uncharges
		 * the just-restored css).
		 */
		put_files_struct(files);
		kfree(mig_entry);
	}
}

/* Migration committed: the moves are final, just drop the records. */
static void files_migrate_commit(void)
{
	struct files_migrate_entry *mig_entry, *next_entry;
	LIST_HEAD(list);

	list_splice_init(&files_migrate_entries, &list);

	list_for_each_entry_safe(mig_entry, next_entry, &list, node) {
		list_del(&mig_entry->node);
		/*
		 * The moves are final: the files_struct keeps its
		 * reference on @to_css, only the pin and the reference
		 * transferred from the pre-migration state are dropped.
		 */
		put_files_struct(mig_entry->files);
		css_put(mig_entry->from_css);
		kfree(mig_entry);
	}
}

static void files_cgroup_cancel_attach(struct cgroup_taskset *tset __always_unused)
{
	files_migrate_rollback();
}

static void files_cgroup_attach(struct cgroup_taskset *tset __always_unused)
{
	files_migrate_commit();
}

/*
 * files_cgroup_can_attach_one_task - judge one task can attach to files cgroup
 * @task: the task is judged whether can attach
 * @mig_entry: files_migrate_entry record
 * @to_css: the css migrate to
 * @skip: if task files is NULL or files->files_cgroup is NULL or files == init_files
 *	  or already on target css, skip attach is true
 */
static int files_cgroup_can_attach_one_task(struct task_struct *task,
					    struct files_migrate_entry *mig_entry,
					    struct cgroup_subsys_state *to_css,
					    bool *skip)
{
	int ret = 0;
	u64 num_files;
	struct page_counter *from_res, *to_res, *fail_res;
	struct files_struct *files;
	struct cgroup_subsys_state *from_css;
	*skip = false;

	task_lock(task);
	files = task->files;
	if (!files || !files->files_cgroup || files == &init_files) {
		*skip = true;
		goto skip;
	}

	from_css = &files_cgroup_from_files(files)->css;
	/* Already on the target css, or handled via a shared files_struct. */
	if (from_css == to_css) {
		*skip = true;
		goto skip;
	}

	from_res = css_res_open_handles(from_css);
	to_res = css_res_open_handles(to_css);

	spin_lock(&files->file_lock);
	num_files = file_cg_count_fds(files);
	page_counter_uncharge(from_res, num_files);

	if (!page_counter_try_charge(to_res, num_files, &fail_res)) {
		page_counter_charge(from_res, num_files);
		pr_err("Open files limit overcommited\n");
		ret = -ENOSPC;
		goto overcommited;
	}

	/*
	 * The files_struct's reference on @from_css is transferred to
	 * the rollback record; @to_css is referenced by the
	 * files_struct from now on.
	 */
	css_get(to_css);
	files->files_cgroup = css_fcg(to_css);

	atomic_inc(&files->count);
	mig_entry->files = files;
	mig_entry->from_css = from_css;
	mig_entry->to_css = to_css;

overcommited:
	spin_unlock(&files->file_lock);
skip:
	task_unlock(task);
	return ret;
}

/*
 * If attaching this cgroup would overcommit the resource then deny
 * the attach. If not, attach the file resource into new cgroup.
 */
static int files_cgroup_can_attach(struct cgroup_taskset *tset)
{
	struct task_struct *task;
	struct cgroup_subsys_state *to_css;
	struct files_migrate_entry *mig_entry;
	int ret = 0;
	bool skip = false;

	cgroup_taskset_for_each(task, to_css, tset) {
		mig_entry = kzalloc(sizeof(*mig_entry), GFP_KERNEL);
		if (!mig_entry) {
			ret = -ENOMEM;
			break;
		}

		ret = files_cgroup_can_attach_one_task(task, mig_entry, to_css, &skip);
		if (ret) {
			kfree(mig_entry);
			break;
		}

		if (skip) {
			kfree(mig_entry);
			continue;
		}

		list_add_tail(&mig_entry->node, &files_migrate_entries);
	}

	if (ret)
		files_migrate_rollback();

	return ret;
}

int files_cgroup_alloc_fd(struct files_struct *files, u64 n)
{
	if (!files_cgroup_enabled())
		return 0;
	/*
	 * Kernel threads which are forked by kthreadd inherited the
	 * const files_struct 'init_files', we didn't wrap it so
	 * there's no associated files_cgroup.
	 *
	 *  Kernel threads always stay in root cgroup, and we don't
	 *  have limit for root files cgroup, so it won't hurt if
	 *  we don't charge their fds, only issue is that files.usage
	 *  won't be accurate in root files cgroup.
	 */
	if (!no_acct && files != &init_files) {
		struct page_counter *fail_res;
		struct files_cgroup *files_cgroup =
			files_cgroup_from_files(files);
		if (!page_counter_try_charge(&files_cgroup->open_handles,
				       n, &fail_res))
			return -ENOMEM;
	}
	return 0;
}

void files_cgroup_unalloc_fd(struct files_struct *files, u64 n)
{
	if (!files_cgroup_enabled())
		return;
	/*
	 * It's not charged so no need to uncharge, see comments in
	 * files_cgroup_alloc_fd.
	 */
	if (!no_acct && files != &init_files) {
		struct files_cgroup *files_cgroup =
		       files_cgroup_from_files(files);
		page_counter_uncharge(&files_cgroup->open_handles, n);
	}
}

void files_cgroup_put_fd(struct files_struct *files, unsigned int fd)
{
	struct fdtable *fdt = files_fdtable(files);

	if (!files_cgroup_enabled())
		return;

	if (test_bit(fd, fdt->open_fds))
		return files_cgroup_unalloc_fd(files, 1);
}

int files_cgroup_dup_fds(struct files_struct *newf)
{
	int err;

	if (!files_cgroup_enabled())
		return 0;
	spin_lock(&newf->file_lock);
	err = files_cgroup_alloc_fd(newf, file_cg_count_fds(newf));
	spin_unlock(&newf->file_lock);
	return err;
}

static u64 files_disabled_read(struct cgroup_subsys_state *css,
			       struct cftype *cft)
{
	return no_acct;
}

static int files_disabled_write(struct cgroup_subsys_state *css,
				    struct cftype *cft, u64 val)
{
	if (!val)
		return -EINVAL;
	no_acct = true;

	return 0;
}

static int files_limit_read(struct seq_file *sf, void *v)
{
	struct files_cgroup *fcg = css_fcg(seq_css(sf));
	struct page_counter *counter = &fcg->open_handles;
	u64 limit = counter->max;

	if (limit >= FILES_MAX)
		seq_printf(sf, "%s\n", FILES_MAX_STR);
	else
		seq_printf(sf, "%llu\n", limit);

	return 0;
}

static ssize_t files_limit_write(struct kernfs_open_file *of,
			char *buf, size_t nbytes, loff_t off)
{
	struct files_cgroup *fcg = css_fcg(of_css(of));
	u64 limit;
	int err;

	buf = strstrip((char *)buf);
	if (!strcmp(buf, FILES_MAX_STR)) {
		limit = FILES_MAX;
		goto set_limit;
	}

	err = kstrtoull(buf, 0, &limit);
	if (err)
		return err;

set_limit:
	/*
	 * Limit updates don't need to be mutex'd, since it isn't
	 * critical that any racing fork()s follow the new limit.
	 */
	page_counter_set_max(&fcg->open_handles, limit);
	return nbytes;
}


static u64 files_usage_read(struct cgroup_subsys_state *css,
			struct cftype *cft)
{
	struct files_cgroup *fcg = css_fcg(css);

	return page_counter_read(&fcg->open_handles);
}

static struct cftype files[] = {
	{
		.name = "limit",
		.seq_show  = files_limit_read,
		.write = files_limit_write,
		.flags = CFTYPE_NOT_ON_ROOT,
	},
	{
		.name = "usage",
		.read_u64 = files_usage_read,
	},
	{
		.name = "no_acct",
		.flags = CFTYPE_ONLY_ON_ROOT,
		.read_u64 = files_disabled_read,
		.write_u64 = files_disabled_write,
	},
	{ }
};

struct cgroup_subsys files_cgrp_subsys = {
	.css_alloc = files_cgroup_css_alloc,
	.css_free = files_cgroup_css_free,
	.can_attach = files_cgroup_can_attach,
	/*
	 * Not reachable today because files has the highest ssid among the
	 * subsystems implementing ->can_attach(); kept for forward
	 * compatibility.  See the comment above struct files_migrate_entry.
	 */
	.cancel_attach = files_cgroup_cancel_attach,
	.attach = files_cgroup_attach,
	.legacy_cftypes = files,
};

/*
 * It could race against cgroup migration of current task, and
 * using task_get_css() to get a valid css.
 */
void files_cgroup_assign(struct files_struct *files)
{
	struct cgroup_subsys_state *css;

	if (!files_cgroup_enabled())
		return;

	if (files == &init_files)
		return;

	css = task_get_css(current, files_cgrp_id);
	files->files_cgroup = container_of(css, struct files_cgroup, css);
}

void files_cgroup_remove(struct files_struct *files)
{
	struct task_struct *tsk = current;
	struct files_cgroup *fcg;

	if (!files_cgroup_enabled())
		return;

	if (files == &init_files)
		return;

	task_lock(tsk);
	spin_lock(&files->file_lock);
	fcg = files_cgroup_from_files(files);
	css_put(&fcg->css);
	spin_unlock(&files->file_lock);
	task_unlock(tsk);
}
