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

static void ima_set_ns_policy(struct ima_namespace *ima_ns,
			      char *policy_setup_str)
{
	struct ima_policy_setup_data setup_data;

#ifdef CONFIG_IMA_APPRAISE
	setup_data.ima_appraise = IMA_APPRAISE_ENFORCE;
#endif
	/* Configuring IMA namespace will be implemented in the following
	 * patches. When it is done, parse configuration string and store result
	 * in setup_data. Temporarily use init_policy_setup_data.
	 */
	setup_data = init_policy_setup_data;
	ima_ns->policy_data->ima_fail_unverifiable_sigs =
		init_ima_ns.policy_data->ima_fail_unverifiable_sigs;

	ima_init_ns_policy(ima_ns, &setup_data);
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

	rwlock_init(&ns->iint_tree->lock);
	ns->iint_tree->root = RB_ROOT;

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

static void destroy_ima_ns(struct ima_namespace *ns)
{
	bool is_init_ns = (ns == &init_ima_ns);

	dec_ima_namespaces(ns->ucounts);
	put_user_ns(ns->user_ns);
	ns_free_inum(&ns->ns);
	integrity_iint_tree_free(ns->iint_tree);
	kfree(ns->iint_tree);
	ima_delete_ns_rules(ns->policy_data, is_init_ns);
	kfree(ns->policy_data);
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
	if (ima_ns == &init_ima_ns)
		return 0;

	if (ima_ns->frozen)
		return 0;

	mutex_lock(&frozen_lock);
	if (ima_ns->frozen)
		goto out;

	ima_set_ns_policy(ima_ns, NULL);

	ima_ns->frozen = true;

	down_write(&ima_ns_list_lock);
	list_add_tail(&ima_ns->list, &ima_ns_list);
	up_write(&ima_ns_list_lock);
out:
	mutex_unlock(&frozen_lock);

	return 0;
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

int imans_on_fork(struct nsproxy *nsproxy, struct task_struct *tsk)
{
	int res;
	struct ns_common *nsc = &nsproxy->ima_ns_for_children->ns;
	struct ima_namespace *ns = to_ima_ns(nsc);

	/* create_new_namespaces() already incremented the ref counter */
	if (nsproxy->ima_ns == nsproxy->ima_ns_for_children)
		return 0;

	res = imans_activate(ns);
	if (res)
		return res;

	get_ima_ns(ns);
	put_ima_ns(nsproxy->ima_ns);
	nsproxy->ima_ns = ns;

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

