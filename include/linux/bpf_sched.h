/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_BPF_SCHED_H
#define _LINUX_BPF_SCHED_H

#include <linux/bpf.h>

#ifdef CONFIG_BPF_SCHED

#define BPF_SCHED_HOOK(RET, DEFAULT, NAME, ...) \
	RET bpf_sched_##NAME(__VA_ARGS__);
#include <linux/sched_hook_defs.h>
#undef BPF_SCHED_HOOK

int bpf_sched_verify_prog(struct bpf_verifier_log *vlog,
			  const struct bpf_prog *prog);

#else /* !CONFIG_BPF_SCHED */

static inline int bpf_sched_verify_prog(struct bpf_verifier_log *vlog,
			  const struct bpf_prog *prog)
{
	return -EOPNOTSUPP;
}

#endif /* CONFIG_BPF_SCHED */
#endif /* _LINUX_BPF_SCHED_H */
