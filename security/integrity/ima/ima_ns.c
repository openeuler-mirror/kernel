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

#include "ima.h"

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
		return NULL;

	return ima_ns;
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

	return ns;

fail_free:
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

static void destroy_ima_ns(struct ima_namespace *ns)
{
	dec_ima_namespaces(ns->ucounts);
	put_user_ns(ns->user_ns);
	ns_free_inum(&ns->ns);
	kfree(ns);
}

void free_ima_ns(struct kref *kref)
{
	struct ima_namespace *ns;

	ns = container_of(kref, struct ima_namespace, kref);

	destroy_ima_ns(ns);
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

static int imans_install(struct nsset *nsset, struct ns_common *new)
{
	struct nsproxy *nsproxy = nsset->nsproxy;
	struct ima_namespace *ns = to_ima_ns(new);

	if (!current_is_single_threaded())
		return -EUSERS;

	if (!ns_capable(ns->user_ns, CAP_SYS_ADMIN) ||
	    !ns_capable(nsset->cred->user_ns, CAP_SYS_ADMIN))
		return -EPERM;

	get_ima_ns(ns);
	put_ima_ns(nsproxy->ima_ns);
	nsproxy->ima_ns = ns;

	get_ima_ns(ns);
	put_ima_ns(nsproxy->ima_ns_for_children);
	nsproxy->ima_ns_for_children = ns;

	return 0;
}

int imans_on_fork(struct nsproxy *nsproxy, struct task_struct *tsk)
{
	struct ns_common *nsc = &nsproxy->ima_ns_for_children->ns;
	struct ima_namespace *ns = to_ima_ns(nsc);

	/* create_new_namespaces() already incremented the ref counter */
	if (nsproxy->ima_ns == nsproxy->ima_ns_for_children)
		return 0;

	get_ima_ns(ns);
	put_ima_ns(nsproxy->ima_ns);
	nsproxy->ima_ns = ns;

	return 0;
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

