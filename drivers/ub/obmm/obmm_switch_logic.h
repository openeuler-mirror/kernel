/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
 * Switch/capability predicates. obmm_core.h includes this header, so it takes
 * minimal types and must never include obmm_core.h back.
 */
#ifndef OBMM_SWITCH_LOGIC_H
#define OBMM_SWITCH_LOGIC_H

#include <linux/errno.h>
#include <linux/types.h>

/* Kernel-internal cacheability-class bits; not part of the uapi. */
#define OBMM_MEM_ALLOW_CACHEABLE_MMAP 0x1
#define OBMM_MEM_ALLOW_NONCACHEABLE_MMAP 0x2

/* Two-phase switch state machine; written under switch_lock(write), except
 * the teardown force-strand's defensive STRANDED publish.
 */
enum obmm_switch_state {
	OBMM_SWITCH_IDLE = 0,
	OBMM_SWITCH_SWAPPING,
	OBMM_SWITCH_AWAIT_READY,
	OBMM_SWITCH_FINISHING,	/* armed by switch_end; kworker finishing */
	OBMM_SWITCH_STRANDED,
};

/* IDLE is the only state from which begin may start a switch. */
static inline bool obmm_switch_state_can_begin(enum obmm_switch_state state)
{
	return state == OBMM_SWITCH_IDLE;
}

/* A finisher acts only in the gap it was armed for, never in a newer SWAPPING. */
static inline bool obmm_switch_finisher_applies(enum obmm_switch_state state)
{
	return state == OBMM_SWITCH_AWAIT_READY ||
	       state == OBMM_SWITCH_FINISHING;
}

/* Faults block while a switch is in flight; IDLE and STRANDED do not. */
static inline bool obmm_switch_state_transitional(enum obmm_switch_state state)
{
	return state == OBMM_SWITCH_SWAPPING ||
	       obmm_switch_finisher_applies(state);
}

/* Gate errno: -EAGAIN while transitional, -EIO when STRANDED, 0 at IDLE. */
static inline int obmm_switch_state_gate_err(enum obmm_switch_state state)
{
	if (obmm_switch_state_transitional(state))
		return -EAGAIN;
	if (state == OBMM_SWITCH_STRANDED)
		return -EIO;
	return 0;
}

/* O_SYNC/OSYNC fd needs the NONCACHEABLE cap bit, a plain fd CACHEABLE. */
static inline u32 obmm_mode_cap_bit(bool osync)
{
	return osync ? OBMM_MEM_ALLOW_NONCACHEABLE_MMAP :
		       OBMM_MEM_ALLOW_CACHEABLE_MMAP;
}

/* cap(backend) & (switch_old ? cap(old) : ~0), NULL-guarded on old presence;
 * evaluated at every INIT->mode selection, because an abort may restore a
 * weaker backend under an fd opened while the gap promised more.
 */
static inline bool obmm_mmap_cap_check(u32 backend_cap, u32 old_cap,
				       bool old_present, bool osync)
{
	u32 eff = backend_cap & (old_present ? old_cap : ~(u32)0);

	return eff & obmm_mode_cap_bit(osync);
}

/* The committed backend must serve every capability the old backend
 * promised; an fd with no VMA yet has no mmap_mode to reveal its cap.
 */
static inline bool obmm_switch_mem_cap_preserved(u32 old_cap, u32 new_cap)
{
	return (new_cap & old_cap) == old_cap;
}

#endif /* OBMM_SWITCH_LOGIC_H */
