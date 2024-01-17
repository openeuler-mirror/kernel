/* SPDX-License-Identifier: GPL-2.0 */
BPF_SCHED_HOOK(int, -1, cfs_select_rq, struct sched_migrate_ctx *ctx)
