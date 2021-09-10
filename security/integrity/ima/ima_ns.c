// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2019-2020 Huawei Technologies Duesseldorf GmbH
 *
 * Author: Krzysztof Struczynski <krzysztof.struczynski@huawei.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 *
 * File: ima_ns.c
 *      Functions to manage the IMA namespace.
 */

#include <linux/export.h>
#include <linux/ima.h>
#include <linux/kref.h>
#include <linux/proc_ns.h>
#include <linux/slab.h>
#include <linux/user_namespace.h>
#include <linux/nsproxy.h>
#include <linux/sched.h>
#include <linux/list.h>
#include <linux/llist.h>
#include <linux/rwsem.h>
#include <linux/workqueue.h>
#include <linux/mutex.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/kernel.h>

#include "ima.h"

static LLIST_HEAD(cleanup_list);
static struct workqueue_struct *imans_wq;

/* Protects tasks entering the same, not yet active namespace */
static DEFINE_MUTEX(frozen_lock);

static struct ucounts *inc_ima_namespaces(struct user_namespace *ns)
{
	return inc_ucount(ns, current_euid(), UCOUNT_IMA_NAMESPACES);
}

static void dec_ima_namespaces(struct ucounts *ucounts)
{
	return dec_ucount(ucounts, UCOUNT_IMA_NAMESPACES);
}

static struct ima_namespace *ima_ns_alloc(void)
{
	struct ima_namespace *ima_ns;

	ima_ns = kzalloc(sizeof(*ima_ns), GFP_KERNEL);
	if (!ima_ns)
		goto out;

	ima_ns->policy_data = kzalloc(sizeof(struct ima_policy_data),
				      GFP_KERNEL);
	if (!ima_ns->policy_data)
		goto ns_free;

	ima_ns->iint_tree = kzalloc(sizeof(struct integrity_iint_tree),
				    GFP_KERNEL);
	if (!ima_ns->iint_tree)
		goto policy_free;

	return ima_ns;

policy_free:
	kfree(ima_ns->policy_data);
ns_free:
	kfree(ima_ns);
out:
	return NULL;
}

static void ima_set_ns_policy(struct ima_namespace *ima_ns)
{
	struct ima_policy_setup_data setup_data = {0};

	if (!ima_ns->policy_setup_for_children) {
#ifdef CONFIG_IMA_APPRAISE
		setup_data.ima_appraise = IMA_APPRAISE_ENFORCE;
#endif
		ima_init_ns_policy(ima_ns, &setup_data);
	} else
		ima_init_ns_policy(ima_ns, ima_ns->policy_setup_for_children);
}

static int ima_swap_user_ns(struct ima_namespace *ima_ns,
			    struct user_namespace *user_ns)
{
	struct ucounts *ucounts;

	dec_ima_namespaces(ima_ns->ucounts);
	put_user_ns(ima_ns->user_ns);

	ucounts = inc_ima_namespaces(user_ns);
	if (!ucounts)
		return -ENOSPC;

	ima_ns->user_ns = get_user_ns(user_ns);
	ima_ns->ucounts = ucounts;

	return 0;
}

/**
 * Clone a new ns copying an original ima namespace, setting refcount to 1
 *
 * @user_ns:	User namespace that current task runs in
 * @old_ns:	Old ima namespace to clone
 * Return:	ERR_PTR(-ENOMEM) on error (failure to kmalloc), new ns otherwise
 */
static struct ima_namespace *clone_ima_ns(struct user_namespace *user_ns,
					  struct ima_namespace *old_ns)
{
	struct ima_namespace *ns;
	struct ucounts *ucounts;
	int err;

	err = -ENOSPC;
	ucounts = inc_ima_namespaces(user_ns);
	if (!ucounts)
		goto fail;

	err = -ENOMEM;
	ns = ima_ns_alloc();
	if (!ns)
		goto fail_dec;

	kref_init(&ns->kref);

	err = ns_alloc_inum(&ns->ns);
	if (err)
		goto fail_free;

	ns->ns.ops = &imans_operations;
	ns->user_ns = get_user_ns(user_ns);
	ns->ucounts = ucounts;
	ns->frozen = false;
	atomic_long_set(&ns->ml_len, 0);
	atomic_long_set(&ns->violations, 0);

	rwlock_init(&ns->iint_tree->lock);
	ns->iint_tree->root = RB_ROOT;

	ns->x509_path_for_children = NULL;
	ns->policy_setup_for_children = NULL;

	INIT_LIST_HEAD(&ns->ns_measurements);
	INIT_LIST_HEAD(&ns->policy_data->ima_default_rules);
	INIT_LIST_HEAD(&ns->policy_data->ima_policy_rules);
	INIT_LIST_HEAD(&ns->policy_data->ima_temp_rules);

	return ns;

fail_free:
	kfree(ns->iint_tree);
	kfree(ns->policy_data);
	kfree(ns);
fail_dec:
	dec_ima_namespaces(ucounts);
fail:
	return ERR_PTR(err);
}

/**
 * Copy task's ima namespace, or clone it if flags specifies CLONE_NEWNS.
 *
 * @flags:      Cloning flags
 * @user_ns:	User namespace that current task runs in
 * @old_ns:	Old ima namespace to clone
 *
 * Return: IMA namespace or ERR_PTR.
 */

struct ima_namespace *copy_ima_ns(unsigned long flags,
				  struct user_namespace *user_ns,
				  struct ima_namespace *old_ns)
{
	if (!(flags & CLONE_NEWIMA))
		return get_ima_ns(old_ns);

	return clone_ima_ns(user_ns, old_ns);
}

int __init ima_init_namespace(void)
{
	/* Create workqueue for cleanup */
	imans_wq = create_singlethread_workqueue("imans");
	if (unlikely(!imans_wq))
		return -ENOMEM;

	/* No other reader or writer at this stage */
	list_add_tail(&init_ima_ns.list, &ima_ns_list);

	return 0;
}

static void imans_remove_hash_entries(struct ima_namespace *ima_ns)
{
	struct list_head *ele;
	struct ima_queue_entry *qe;

	/* The namespace is inactive, no lock is needed */
	list_for_each(ele, &ima_ns->ns_measurements) {
		qe = list_entry(ele, struct ima_queue_entry, ns_later);
		/* Don't free the queue entry, it should stay on the global
		 * measurement list, remove only the hash table entry */
		spin_lock(&ima_htable_lock);
		hlist_del_rcu(&qe->hnext);
		spin_unlock(&ima_htable_lock);
		atomic_long_dec(&ima_htable.len);
	}
}

static void destroy_child_config(struct ima_namespace *ima_ns)
{
	kfree(ima_ns->x509_path_for_children);
	ima_ns->x509_path_for_children = NULL;
	kfree(ima_ns->policy_setup_for_children);
	ima_ns->policy_setup_for_children = NULL;
}

static void destroy_ima_ns(struct ima_namespace *ns)
{
	bool is_init_ns = (ns == &init_ima_ns);

	imans_remove_hash_entries(ns);
	dec_ima_namespaces(ns->ucounts);
	put_user_ns(ns->user_ns);
	ns_free_inum(&ns->ns);
	integrity_iint_tree_free(ns->iint_tree);
	kfree(ns->iint_tree);
	ima_delete_ns_rules(ns->policy_data, is_init_ns);
	kfree(ns->policy_data);
	destroy_child_config(ns);
	kfree(ns);
}

static void cleanup_ima(struct work_struct *work)
{
	struct ima_namespace *ima_ns, *tmp;
	struct llist_node *ima_kill_list;

	/* Atomically snapshot the list of namespaces to cleanup */
	ima_kill_list = llist_del_all(&cleanup_list);

	/* Remove ima namespace from the namespace list */
	down_write(&ima_ns_list_lock);
	llist_for_each_entry(ima_ns, ima_kill_list, cleanup_list)
		list_del(&ima_ns->list);
	up_write(&ima_ns_list_lock);

	/* After removing ima namespace from the ima_ns_list, memory can be
	 * freed. At this stage nothing should keep a reference to the given
	 * namespace.
	 */
	llist_for_each_entry_safe(ima_ns, tmp, ima_kill_list, cleanup_list)
		destroy_ima_ns(ima_ns);
}

static DECLARE_WORK(ima_cleanup_work, cleanup_ima);

void free_ima_ns(struct kref *kref)
{
	struct ima_namespace *ima_ns;

	ima_ns = container_of(kref, struct ima_namespace, kref);
	/* Namespace can be destroyed instantly if no process ever was born
	 * into it - it was never added to the ima_ns_list.
	 */
	if (!ima_ns->frozen) {
		destroy_ima_ns(ima_ns);
		return;
	}

	atomic_set(&ima_ns->inactive, 1);
	if (llist_add(&ima_ns->cleanup_list, &cleanup_list))
		queue_work(imans_wq, &ima_cleanup_work);
}

static inline struct ima_namespace *to_ima_ns(struct ns_common *ns)
{
	return container_of(ns, struct ima_namespace, ns);
}

static struct ns_common *imans_get(struct task_struct *task)
{
	struct ima_namespace *ns = NULL;
	struct nsproxy *nsproxy;

	task_lock(task);
	nsproxy = task->nsproxy;
	if (nsproxy) {
		ns = nsproxy->ima_ns;
		get_ima_ns(ns);
	}
	task_unlock(task);

	return ns ? &ns->ns : NULL;
}

static struct ns_common *imans_for_children_get(struct task_struct *task)
{
	struct ima_namespace *ns = NULL;
	struct nsproxy *nsproxy;

	task_lock(task);
	nsproxy = task->nsproxy;
	if (nsproxy) {
		ns = nsproxy->ima_ns_for_children;
		get_ima_ns(ns);
	}
	task_unlock(task);

	return ns ? &ns->ns : NULL;
}

static void imans_put(struct ns_common *ns)
{
	put_ima_ns(to_ima_ns(ns));
}

static int imans_activate(struct ima_namespace *ima_ns)
{
	int res = 0;

	if (ima_ns == &init_ima_ns)
		return res;

	if (ima_ns->frozen)
		return res;

	mutex_lock(&frozen_lock);
	if (ima_ns->frozen)
		goto out;

	ima_set_ns_policy(ima_ns);

	ima_ns->frozen = true;

	down_write(&ima_ns_list_lock);
	list_add_tail(&ima_ns->list, &ima_ns_list);
	up_write(&ima_ns_list_lock);

	destroy_child_config(ima_ns);
out:
	mutex_unlock(&frozen_lock);

	return res;
}

static int imans_install(struct nsset *nsset, struct ns_common *new)
{
	int res;
	struct nsproxy *nsproxy = nsset->nsproxy;
	struct ima_namespace *ns = to_ima_ns(new);

	if (!current_is_single_threaded())
		return -EUSERS;

	if (!ns_capable(ns->user_ns, CAP_SYS_ADMIN) ||
	    !ns_capable(nsset->cred->user_ns, CAP_SYS_ADMIN))
		return -EPERM;

	res = imans_activate(ns);
	if (res)
		return res;

	get_ima_ns(ns);
	put_ima_ns(nsproxy->ima_ns);
	nsproxy->ima_ns = ns;

	get_ima_ns(ns);
	put_ima_ns(nsproxy->ima_ns_for_children);
	nsproxy->ima_ns_for_children = ns;

	return res;
}

int imans_on_fork(struct nsproxy *nsproxy, struct task_struct *tsk,
		  struct user_namespace *user_ns)
{
	int res;
	struct ima_namespace *ima_ns = nsproxy->ima_ns_for_children;

	/* create_new_namespaces() already incremented the ref counter */
	if (nsproxy->ima_ns == ima_ns)
		return 0;

	/* It's possible that the user first unshares the IMA namespace and
	 * then creates a new user namespace on clone3(). In that case swap
	 * user namespace for the "current" one.
	 */
	if (ima_ns->user_ns != user_ns) {
		res = ima_swap_user_ns(ima_ns, user_ns);
		if (res)
			return res;
	}

	res = imans_activate(ima_ns);
	if (res)
		return res;

	get_ima_ns(ima_ns);
	put_ima_ns(nsproxy->ima_ns);
	nsproxy->ima_ns = ima_ns;

	return res;
}

static struct user_namespace *imans_owner(struct ns_common *ns)
{
	return to_ima_ns(ns)->user_ns;
}

const struct proc_ns_operations imans_operations = {
	.name = "ima",
	.type = CLONE_NEWIMA,
	.get = imans_get,
	.put = imans_put,
	.install = imans_install,
	.owner = imans_owner,
};

const struct proc_ns_operations imans_for_children_operations = {
	.name = "ima_for_children",
	.type = CLONE_NEWIMA,
	.get = imans_for_children_get,
	.put = imans_put,
	.install = imans_install,
	.owner = imans_owner,
};

struct ima_kernel_param {
	const char *name;
	int (*set)(char *val, struct ima_namespace *ima_ns);
};

/* TODO: add ima_template, ima_template_fmt, ima_hash, ... */
static const struct ima_kernel_param ima_kernel_params[] = {
	{"ima_appraise", ima_default_appraise_setup},
	{"ima_policy", ima_policy_setup},
};
static const size_t ima_kernel_params_size = ARRAY_SIZE(ima_kernel_params);

ssize_t ima_ns_write_x509_for_children(struct ima_namespace *ima_ns,
				       char *x509_path)
{
	ssize_t retval = 0;

	mutex_lock(&frozen_lock);
	if (ima_ns->frozen) {
		retval = -EACCES;
		goto out;
	}

	kfree(ima_ns->x509_path_for_children);
	ima_ns->x509_path_for_children = x509_path;
out:
	mutex_unlock(&frozen_lock);

	return retval;
}

ssize_t ima_ns_write_kcmd_for_children(struct ima_namespace *ima_ns,
				       char *kcmd)
{
	u32 i;
	char *param, *val;
	ssize_t ret = 0;

	mutex_lock(&frozen_lock);
	if (ima_ns->frozen) {
		ret = -EACCES;
		goto err_unlock;
	}

	if (!ima_ns->policy_setup_for_children) {
		ima_ns->policy_setup_for_children =
			kmalloc(sizeof(struct ima_policy_setup_data),
				GFP_KERNEL);
		if (!ima_ns->policy_setup_for_children) {
			ret = -ENOMEM;
			goto err_unlock;
		}
	}

	memset(ima_ns->policy_setup_for_children,
	       0, sizeof(struct ima_policy_setup_data));

#ifdef CONFIG_IMA_APPRAISE
	ima_ns->policy_setup_for_children->ima_appraise = IMA_APPRAISE_ENFORCE;
#endif

	kcmd = skip_spaces(kcmd);
	while (*kcmd) {
		kcmd = next_arg(kcmd, &param, &val);
		if (!val) {
			ret = -EINVAL;
			goto err_free;
		}

		for (i = 0; i < ima_kernel_params_size; i++) {
			if (strcmp(param, ima_kernel_params[i].name) == 0)
				break;
		}

		if (i == ima_kernel_params_size) {
			ret = -EINVAL;
			goto err_free;
		}

		ima_kernel_params[i].set(val, ima_ns);
	}
	mutex_unlock(&frozen_lock);

	return ret;

err_free:
	kfree(ima_ns->policy_setup_for_children);
	ima_ns->policy_setup_for_children = NULL;
err_unlock:
	mutex_unlock(&frozen_lock);

	return ret;
}

