// SPDX-License-Identifier: GPL-2.0+
/*
 * Common code for task relationship aware
 *
 * Copyright (C) 2023-2024 Huawei Technologies Co., Ltd
 *
 * Author: Hui Tang <tanghui20@huawei.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 */
#include <linux/bpf_sched.h>
#include <linux/sort.h>

#include "sched.h"

#define RXTX_BYTES_PERIOD_MS	(1000)
#define RXTX_BYTES_DECAY_RATIO	(2)

DEFINE_STATIC_KEY_FALSE(__relationship_switch);

void task_relationship_enable(void)
{
	static_branch_enable(&__relationship_switch);
}

void task_relationship_disable(void)
{
	static_branch_disable(&__relationship_switch);
}

bool task_relationship_supported(struct task_struct *tsk)
{
	if (!task_relationship_used())
		return false;

	if (!tsk->rship || !tsk->mm ||
		!cpumask_subset(cpu_online_mask, tsk->cpus_ptr) ||
		!nodes_subset(node_online_map, tsk->mems_allowed) ||
		get_task_policy(tsk)->mode == MPOL_BIND ||
		get_task_policy(tsk)->mode == MPOL_INTERLEAVE)
		return false;

	return true;
}

static inline int get_net_group(struct net_group *grp)
{
	return refcount_inc_not_zero(&grp->hdr.refcount);
}

static inline void put_net_group(struct net_group *grp)
{
	if (refcount_dec_and_test(&grp->hdr.refcount))
		kfree_rcu(grp, rcu);
}

static inline void put_task_net_group(struct task_struct *tsk, bool reset)
{
	struct net_group *grp;
	unsigned long flags;

	spin_lock_irqsave(&tsk->rship->net_lock, flags);

	grp = rcu_dereference_protected(tsk->rship->net_group,
					lockdep_is_held(&tsk->rship->net_lock));
	if (grp) {
		spin_lock(&grp->hdr.lock);
		grp->rxtx_bytes -= tsk->rship->rxtx_bytes;
		grp->hdr.nr_tasks--;
		spin_unlock(&grp->hdr.lock);
		put_net_group(grp);
		RCU_INIT_POINTER(tsk->rship->net_group, NULL);
	}

	if (reset) {
		tsk->rship->rxtx_bytes = 0;
		tsk->rship->rxtx_remote_bytes = 0;
		tsk->rship->rx_dev_idx = -1;
		tsk->rship->rx_dev_queue_idx = -1;
		tsk->rship->nic_nid = -1;
		tsk->rship->rx_dev_netns_cookie = 0;
	}

	spin_unlock_irqrestore(&tsk->rship->net_lock, flags);
}

static inline int remote_rxtx_process(struct net_relationship_req *req)
{
	struct task_relationship *rship;
	struct task_struct *tsk;
	unsigned long flags;
	pid_t pid;
	long diff;

	rcu_read_lock();

	pid = req->net_rship_type == NET_RS_TYPE_RX ? req->rx_pid : req->tx_pid;
	tsk = find_task_by_pid_ns(pid, &init_pid_ns);
	if (!tsk || !task_relationship_supported(tsk))
		goto out_unlock;

	rship = tsk->rship;
	if (time_after(jiffies, rship->rxtx_remote_update_next)) {
		diff = rship->rxtx_remote_buffer - rship->rxtx_remote_bytes / 2;

		spin_lock_irqsave(&rship->net_lock, flags);
		rship->nic_nid = req->nic_nid;
		if (req->net_rship_type == NET_RS_TYPE_RX) {
			rship->rx_dev_idx = req->rx_dev_idx;
			rship->rx_dev_queue_idx = req->rx_dev_queue_idx;
			rship->rx_dev_netns_cookie = req->rx_dev_netns_cookie;
		}
		rship->rxtx_remote_bytes += diff;
		rship->rxtx_remote_buffer = 0;
		spin_unlock_irqrestore(&rship->net_lock, flags);
	}

	rship->rxtx_remote_buffer += req->rxtx_bytes;

out_unlock:
	rcu_read_unlock();

	return 0;
}

int sched_net_relationship_submit(struct net_relationship_req *req)
{
	struct task_struct *rx_tsk, *tx_tsk, *dst_tsk;
	struct net_group *rx_grp, *tx_grp;
	int ret;

	if (req->net_rship_type == NET_RS_TYPE_RX ||
	    req->net_rship_type == NET_RS_TYPE_TX)
		return remote_rxtx_process(req);

	rcu_read_lock();

	rx_tsk = find_task_by_pid_ns(req->rx_pid, &init_pid_ns);
	tx_tsk = find_task_by_pid_ns(req->tx_pid, &init_pid_ns);
	if (!rx_tsk || !tx_tsk) {
		ret = -ESRCH;
		goto out_unlock;
	}

	if (!task_relationship_supported(rx_tsk) ||
	    !task_relationship_supported(tx_tsk)) {
		ret = -EPERM;
		goto out_unlock;
	}

	if (atomic_read(&rx_tsk->rship->cb.active) &&
	    atomic_read(&tx_tsk->rship->cb.active)) {
		ret = -EBUSY;
		goto out_unlock;
	}

	rx_grp = rcu_dereference(rx_tsk->rship->net_group);
	tx_grp = rcu_dereference(tx_tsk->rship->net_group);
	if (rx_grp && tx_grp) {
		dst_tsk = rx_grp->hdr.nr_tasks >= tx_grp->hdr.nr_tasks ?
			rx_tsk : tx_tsk;
	} else if (rx_grp) {
		dst_tsk = rx_tsk;
	} else if (tx_grp) {
		dst_tsk = tx_tsk;
	} else {
		dst_tsk = !atomic_read(&rx_tsk->rship->cb.active) ?
			rx_tsk : tx_tsk;
	}

	if (atomic_cmpxchg(&dst_tsk->rship->cb.active, 0, 1)) {
		ret = -EBUSY;
		goto out_unlock;
	}

	memcpy(&dst_tsk->rship->cb.req, req, sizeof(*req));
	dst_tsk->rship->cb.src_pid = dst_tsk == rx_tsk ?
		req->tx_pid : req->rx_pid;
	task_work_add(dst_tsk, &dst_tsk->rship->cb.twork, TWA_RESUME);
	ret = 0;

out_unlock:
	rcu_read_unlock();
	return ret;
}

static void task_net_group(struct task_struct *curr, struct task_struct *src)
{
	struct net_group *src_grp, *curr_grp, *grp;

	double_lock_irq(&src->rship->net_lock, &curr->rship->net_lock);
	curr_grp = rcu_dereference_protected(curr->rship->net_group,
			lockdep_is_held(&curr->rship->net_lock));
	src_grp = rcu_dereference_protected(src->rship->net_group,
			lockdep_is_held(&src->rship->net_lock));

	if (!curr_grp) {
		grp = kzalloc(sizeof(*grp), GFP_ATOMIC | __GFP_NOWARN);
		if (!grp)
			goto out_unlock;

		refcount_set(&grp->hdr.refcount, 1);
		spin_lock_init(&grp->hdr.lock);
		grp->hdr.gid = curr->pid;
		grp->hdr.preferred_nid = NODE_MASK_NONE;
		node_set(task_node(curr), grp->hdr.preferred_nid);
		grp->hdr.nr_tasks = 1;
		rcu_assign_pointer(curr->rship->net_group, grp);
		curr_grp = rcu_dereference_protected(curr->rship->net_group,
				lockdep_is_held(&curr->rship->net_lock));
	}

	if (curr_grp == src_grp)
		goto out_unlock;

	if (!get_net_group(curr_grp))
		goto out_unlock;

	spin_lock(&curr_grp->hdr.lock);
	curr_grp->hdr.nr_tasks++;
	curr_grp->rxtx_bytes += src->rship->rxtx_bytes;
	spin_unlock(&curr_grp->hdr.lock);

	if (src_grp) {
		spin_lock(&src_grp->hdr.lock);
		src_grp->hdr.nr_tasks--;
		src_grp->rxtx_bytes -= src->rship->rxtx_bytes;
		spin_unlock(&src_grp->hdr.lock);
		put_net_group(src_grp);
	}

	rcu_assign_pointer(src->rship->net_group, curr_grp);
out_unlock:
	spin_unlock(&src->rship->net_lock);
	spin_unlock_irq(&curr->rship->net_lock);
}

static void task_rxtx_data_update(struct task_struct *tsk)
{
	struct net_group *grp;
	long bytes_diff;

	spin_lock_irq(&tsk->rship->net_lock);
	bytes_diff = tsk->rship->rxtx_buffer -
		tsk->rship->rxtx_bytes / RXTX_BYTES_DECAY_RATIO;
	tsk->rship->rxtx_bytes += bytes_diff;
	tsk->rship->rxtx_buffer = 0;
	tsk->rship->rxtx_update_next = jiffies +
		msecs_to_jiffies(RXTX_BYTES_PERIOD_MS);

	grp = rcu_dereference_protected(tsk->rship->net_group,
			lockdep_is_held(&tsk->rship->net_lock));
	if (grp) {
		spin_lock(&grp->hdr.lock);
		grp->rxtx_bytes += bytes_diff;
		spin_unlock(&grp->hdr.lock);
	}

	spin_unlock_irq(&tsk->rship->net_lock);
}

static void task_net_relationship_work(struct callback_head *work)
{
	struct net_relationship_callback *ncb;
	struct task_struct *curr = current;
	struct net_relationship_req req;
	struct task_struct *src;

	ncb = container_of(work, struct net_relationship_callback, twork);
	req = ncb->req;
	atomic_set(&ncb->active, 0);

	rcu_read_lock();
	src = find_task_by_pid_ns(ncb->src_pid, &init_pid_ns);
	if (!src) {
		rcu_read_unlock();
		return;
	}

	if (!task_relationship_supported(src) ||
	    !task_relationship_supported(curr)) {
		rcu_read_unlock();
		return;
	}

	/* prevent src going away */
	get_task_struct(src);

	rcu_read_unlock();

	/* build net relationship */
	task_net_group(src, curr);

	if (time_after(jiffies, curr->rship->rxtx_update_next))
		task_rxtx_data_update(curr);

	if (time_after(jiffies, src->rship->rxtx_update_next))
		task_rxtx_data_update(src);

	double_lock_irq(&src->rship->net_lock, &curr->rship->net_lock);
	curr->rship->rxtx_buffer += req.rxtx_bytes;
	src->rship->rxtx_buffer += req.rxtx_bytes;
	spin_unlock(&src->rship->net_lock);
	spin_unlock_irq(&curr->rship->net_lock);

	put_task_struct(src);
}

static int cmp_fault_stats(const void *a, const void *b)
{
	return ((struct fault_array_info *)b)->val -
		((struct fault_array_info *)a)->val;
}

void numa_faults_update_and_sort(int nid, int new,
				 struct fault_array_info *stats)
{
	int nodes, i;

	if (!task_relationship_used())
		return;

	if (nid == first_online_node) {
		for (i = 0; i < FAULT_NODES_MAX; i++) {
			stats[i].nid = -1;
			stats[i].val = 0;
		}
	}

	nodes = min(FAULT_NODES_MAX, num_online_nodes());
	if (new <= stats[nodes - 1].val)
		return;

	stats[nodes - 1].nid = nid;
	stats[nodes - 1].val = new;
	sort(stats, nodes, sizeof(stats[0]), cmp_fault_stats, NULL);
}

void sched_get_relationship(struct task_struct *tsk,
			    struct bpf_relationship_get_args *args)
{
	struct net_group *ngrp;

	rcu_read_lock();

	/* memory relationship */
	sched_get_mm_relationship(tsk, args);

	/* net relationship */
	ngrp = rcu_dereference(tsk->rship->net_group);
	if (ngrp) {
		args->net.comm.gid = ngrp->hdr.gid;
		args->net.comm.nr_tasks = ngrp->hdr.nr_tasks;
		args->net.comm.preferred_node = ngrp->hdr.preferred_nid;
		args->net.grp_rxtx_bytes = ngrp->rxtx_bytes;
	}

	rcu_read_unlock();
}

void sctl_sched_get_net_relationship(struct task_struct *tsk,
				     struct sctl_net_relationship_info *info)
{
	struct task_relationship *rship = tsk->rship;
	struct net_group *grp;

	memset(info, 0, sizeof(*info));
	info->valid = true;
	info->nic_nid = rship->nic_nid;
	info->rx_dev_idx = rship->rx_dev_idx;
	info->rx_dev_queue_idx = rship->rx_dev_queue_idx;
	info->rx_dev_netns_cookie = rship->rx_dev_netns_cookie;
	info->rxtx_remote_bytes = rship->rxtx_remote_bytes;
	info->rxtx_bytes = rship->rxtx_bytes;

	info->grp_hdr.gid = NO_RSHIP;

	rcu_read_lock();

	grp = rcu_dereference(rship->net_group);
	if (grp) {
		info->grp_hdr.gid = grp->hdr.gid;
		info->grp_hdr.nr_tasks = grp->hdr.nr_tasks;
		snprintf(info->grp_hdr.preferred_nid, SCTL_STR_MAX, "%*pbl",
			nodemask_pr_args(&grp->hdr.preferred_nid));
		info->grp_rxtx_bytes = grp->rxtx_bytes;
	}

	rcu_read_unlock();
}

void task_relationship_free(struct task_struct *tsk, bool reset)
{
	if (!task_relationship_used())
		return;

	put_task_net_group(tsk, reset);
}

int sched_relationship_fork(struct task_struct *p)
{
	int i;

	p->rship = kzalloc(sizeof(struct task_relationship), GFP_KERNEL);
	if (!p->rship)
		return -ENOMEM;

	for (i = 0; i < FAULT_NODES_MAX; i++)
		p->rship->faults.faults_ordered[i].nid = -1;

	p->rship->nic_nid = -1;
	p->rship->rx_dev_idx = -1;
	p->rship->rx_dev_queue_idx = -1;

	spin_lock_init(&p->rship->net_lock);
	init_task_work(&p->rship->cb.twork, task_net_relationship_work);
#ifdef CONFIG_NUMA_BALANCING
	p->rship->node_work.next		= &p->rship->node_work;
	init_task_work(&p->rship->node_work, task_preferred_node_work);
#endif
	return 0;
}

void sched_relationship_free(struct task_struct *p)
{
	kfree(p->rship);
	p->rship = NULL;
}
