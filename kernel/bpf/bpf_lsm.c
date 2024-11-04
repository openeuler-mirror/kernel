// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (C) 2020 Google LLC.
 */

#include <linux/filter.h>
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/lsm_hooks.h>
#include <linux/bpf_lsm.h>
#include <linux/kallsyms.h>
#include <net/bpf_sk_storage.h>
#include <linux/bpf_local_storage.h>
#include <linux/btf_ids.h>

/* For every LSM hook that allows attachment of BPF programs, declare a nop
 * function where a BPF program can be attached.
 */
#define LSM_HOOK(RET, DEFAULT, NAME, ...)	\
noinline RET bpf_lsm_##NAME(__VA_ARGS__)	\
{						\
	return DEFAULT;				\
}

#include <linux/lsm_hook_defs.h>
#undef LSM_HOOK

#define LSM_HOOK(RET, DEFAULT, NAME, ...) BTF_ID(func, bpf_lsm_##NAME)
BTF_SET_START(bpf_lsm_hooks)
#include <linux/lsm_hook_defs.h>
#undef LSM_HOOK
BTF_SET_END(bpf_lsm_hooks)

BTF_SET_START(bpf_lsm_disabled_hooks)
BTF_ID(func, bpf_lsm_vm_enough_memory)
BTF_ID(func, bpf_lsm_inode_need_killpriv)
BTF_ID(func, bpf_lsm_inode_getsecurity)
BTF_ID(func, bpf_lsm_inode_listsecurity)
BTF_ID(func, bpf_lsm_inode_copy_up_xattr)
BTF_ID(func, bpf_lsm_getprocattr)
BTF_ID(func, bpf_lsm_setprocattr)
#ifdef CONFIG_KEYS
BTF_ID(func, bpf_lsm_key_getsecurity)
#endif
#ifdef CONFIG_AUDIT
BTF_ID(func, bpf_lsm_audit_rule_match)
#endif
BTF_ID(func, bpf_lsm_ismaclabel)
BTF_SET_END(bpf_lsm_disabled_hooks)

int bpf_lsm_verify_prog(struct bpf_verifier_log *vlog,
			const struct bpf_prog *prog)
{
	u32 btf_id = prog->aux->attach_btf_id;
	const char *func_name = prog->aux->attach_func_name;

	if (!prog->gpl_compatible) {
		bpf_log(vlog,
			"LSM programs must have a GPL compatible license\n");
		return -EINVAL;
	}

	if (btf_id_set_contains(&bpf_lsm_disabled_hooks, btf_id)) {
		bpf_log(vlog, "attach_btf_id %u points to disabled hook %s\n",
			btf_id, func_name);
		return -EINVAL;
	}

	if (!btf_id_set_contains(&bpf_lsm_hooks, btf_id)) {
		bpf_log(vlog, "attach_btf_id %u points to wrong type name %s\n",
			btf_id, func_name);
		return -EINVAL;
	}

	return 0;
}

static const struct bpf_func_proto *
bpf_lsm_func_proto(enum bpf_func_id func_id, const struct bpf_prog *prog)
{
	switch (func_id) {
	case BPF_FUNC_inode_storage_get:
		return &bpf_inode_storage_get_proto;
	case BPF_FUNC_inode_storage_delete:
		return &bpf_inode_storage_delete_proto;
	case BPF_FUNC_sk_storage_get:
		return &bpf_sk_storage_get_proto;
	case BPF_FUNC_sk_storage_delete:
		return &bpf_sk_storage_delete_proto;
	default:
		return tracing_prog_func_proto(func_id, prog);
	}
}

const struct bpf_prog_ops lsm_prog_ops = {
};

const struct bpf_verifier_ops lsm_verifier_ops = {
	.get_func_proto = bpf_lsm_func_proto,
	.is_valid_access = btf_ctx_access,
};

/* hooks return 0 or 1 */
BTF_SET_START(bool_lsm_hooks)
#ifdef CONFIG_SECURITY_NETWORK_XFRM
BTF_ID(func, bpf_lsm_xfrm_state_pol_flow_match)
#endif
#ifdef CONFIG_AUDIT
BTF_ID(func, bpf_lsm_audit_rule_known)
#endif
BTF_SET_END(bool_lsm_hooks)

int bpf_lsm_get_retval_range(const struct bpf_prog *prog,
			     struct bpf_retval_range *retval_range)
{
	/* no return value range for void hooks */
	if (!prog->aux->attach_func_proto->type)
		return -EINVAL;

	if (btf_id_set_contains(&bool_lsm_hooks, prog->aux->attach_btf_id)) {
		retval_range->minval = 0;
		retval_range->maxval = 1;
	} else {
		/* All other available LSM hooks, except task_prctl, return 0
		 * on success and negative error code on failure.
		 * To keep things simple, we only allow bpf progs to return 0
		 * or negative errno for task_prctl too.
		 */
		retval_range->minval = -MAX_ERRNO;
		retval_range->maxval = 0;
	}
	return 0;
}
