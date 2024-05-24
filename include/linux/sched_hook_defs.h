/* SPDX-License-Identifier: GPL-2.0 */
BPF_SCHED_HOOK(int, 0, cfs_check_preempt_tick, struct sched_entity *curr, unsigned long delta_exec)
BPF_SCHED_HOOK(int, 0, cfs_check_preempt_wakeup, struct task_struct *curr, struct task_struct *p)
BPF_SCHED_HOOK(int, 0, cfs_wakeup_preempt_entity, struct sched_entity *curr,
	struct sched_entity *se)
BPF_SCHED_HOOK(int, 0, cfs_tag_pick_next_entity, struct sched_entity *curr,
	       struct sched_entity *next)
BPF_SCHED_HOOK(void, (void) 0, cfs_enqueue_task, struct rq *rq, struct task_struct *p)
BPF_SCHED_HOOK(void, (void) 0, cfs_dequeue_task, struct rq *rq, struct task_struct *p)
BPF_SCHED_HOOK(int, -1, cfs_select_rq, struct sched_migrate_ctx *ctx)
BPF_SCHED_HOOK(int, -1, cfs_wake_affine, struct sched_affine_ctx *ctx)
BPF_SCHED_HOOK(int, -1, cfs_select_rq_exit, struct sched_migrate_ctx *ctx)
BPF_SCHED_HOOK(int, -1, cfs_can_migrate_task, struct task_struct *p,
	struct sched_migrate_node *migrate_node)
