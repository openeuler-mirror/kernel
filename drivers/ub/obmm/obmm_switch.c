// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
 *
 * Unified two-phase backend switch: IDLE/SWAPPING/AWAIT_READY/FINISHING/
 * STRANDED, switch_begin/switch_end and the workqueue finisher.
 *
 * Lock order: begin and the finisher hold state_mutex -> switch_lock(write)
 * across every flip they publish, while the teardown force-strand publishes
 * STRANDED lock-free; the fault gate takes switch_lock(read) and derives its
 * pfn under it. The gap is held by the state value alone -- begin returns
 * with both locks released -- and has no kernel-side timeout: only
 * switch_end closes it, an abandoned gap blocks faults killably and fails
 * the backend-touching ioctls, and any privileged switch_end(success = 0)
 * closes it, restoring the old backend when it was kept alive and its
 * re-attach succeeds (a failure strands the region).
 */

#include <linux/capability.h>
#include <linux/err.h>
#include <linux/kernel.h>
#include <linux/lockdep.h>
#include <linux/mm.h>
#include <linux/numa.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/workqueue.h>

#include "obmm_backend.h"
#include "obmm_core.h"
#include "obmm_export.h"
#include "obmm_switch.h"
#include "obmm_switch_logic.h"

static int obmm_copy_priv_from_user(unsigned char *dst, const void __user *src,
				    unsigned int priv_len)
{
	if (priv_len > OBMM_MAX_PRIV_LEN)
		return -EINVAL;
	if (priv_len && copy_from_user(dst, src, priv_len))
		return -EFAULT;
	return 0;
}

static void stage_switch_priv(struct obmm_region *reg, const unsigned char *priv,
			      unsigned int priv_len)
{
	memcpy(reg->switch_pending_priv, priv, priv_len);
	reg->switch_pending_priv_len = priv_len;
}

/* Sole commit point: priv goes live before the IDLE publish, never mid-gap. */
static void commit_switch_priv(struct obmm_region *reg)
{
	memcpy(reg->priv, reg->switch_pending_priv, reg->switch_pending_priv_len);
	reg->priv_len = reg->switch_pending_priv_len;
	reg->switch_pending_priv_len = 0;
}

static void discard_switch_priv(struct obmm_region *reg)
{
	reg->switch_pending_priv_len = 0;
}

/* Record the first negative errno of the generation; log every failure. */
static void switch_record_flush_err(struct obmm_region *reg, int fret,
				    const char *what)
{
	if (!fret)
		return;
	if (READ_ONCE(reg->switch_flush_result) >= 0)
		WRITE_ONCE(reg->switch_flush_result, fret);
	pr_err("switch: mem_id=%d %s: %pe\n",
	       reg->regionid, what, ERR_PTR(fret));
}

/* the caller's gap reference, or ERR_PTR(-ENOENT); failures log */
static struct obmm_region *switch_lookup_region(u64 mem_id)
{
	struct obmm_region *reg;

	if (!validate_obmm_mem_id(mem_id)) {	/* no u64->int truncation */
		pr_err("switch: mem_id=%llu out of range, ret=%pe\n",
		       mem_id, ERR_PTR(-ENOENT));
		return ERR_PTR(-ENOENT);
	}
	reg = search_get_obmm_region(mem_id);
	if (!reg) {
		pr_err("switch: mem_id=%llu not found\n", mem_id);
		return ERR_PTR(-ENOENT);
	}
	return reg;
}

/* One terminal full-range flush, staged under the locks, run after unlock. */
struct switch_flush_stage {
	struct obmm_backend *be;
	u8 cache_ops;
	const char *what;
	int ret;
};

/* Zap every mapping through the cached i_mapping; alias inodes are refused at open. */
static void obmm_zap_region_mappings(struct obmm_region *reg)
{
	if (READ_ONCE(reg->i_mapping))
		unmap_mapping_range(reg->i_mapping, 0, 0, 0);
}

/* ---- switch state machine ---- */

/* Publish IDLE with the pre-attach promised-cap snapshot and drop staged
 * priv; begin's failure paths only, since the finisher's abort restore must
 * keep the entitlements of fds opened during the gap.
 */
static void obmm_switch_to_idle_locked(struct obmm_region *reg, u32 saved_promised)
{
	lockdep_assert_held(&reg->state_mutex);
	lockdep_assert_held_write(&reg->switch_lock);

	reg->promised_cap = saved_promised;
	discard_switch_priv(reg);
	WRITE_ONCE(reg->switch_state, OBMM_SWITCH_IDLE);
	wake_up_all(&reg->switch_wqh);
}

/* Terminal: NULLs switch_old so the caller's staged pointer is the sole
 * existence reference for the post-unlock put; the CALLER wakes the blocked
 * faults after the unlock (they re-check and SIGBUS).
 */
static void obmm_switch_strand_locked(struct obmm_region *reg)
{
	lockdep_assert_held(&reg->state_mutex);
	lockdep_assert_held_write(&reg->switch_lock);

	reg->backend = NULL;
	reg->switch_old = NULL;
	reg->switch_keep_old_alive = false;
	reg->switch_old_mapped = false;
	reg->switch_new_mapped = false;
	discard_switch_priv(reg);
	WRITE_ONCE(reg->switch_state, OBMM_SWITCH_STRANDED);
}

void obmm_promised_cap_shrink_maybe(struct obmm_region *reg)
{
	if (!atomic_read(&reg->fd_count) && !atomic_read(&reg->mmap_count) &&
	    reg->backend)
		reg->promised_cap = reg->backend->mem_cap;
}

/* Defensive, publish-only strand for teardown: drain a pending or running
 * finisher, then force STRANDED and wake. The caller already deactivated the
 * region, so no switch actor or fault can exist.
 */
void obmm_switch_force_strand(struct obmm_region *reg)
{
	cancel_work_sync(&reg->switch_work);
	if (!obmm_switch_state_can_begin(READ_ONCE(reg->switch_state))) {
		WRITE_ONCE(reg->switch_state, OBMM_SWITCH_STRANDED);
		wake_up_all(&reg->switch_wqh);
	}
}

/* Drop both locks, drain a pending or running finisher, re-acquire: the
 * drain must not hold state_mutex, which a stale finisher may be waiting on.
 */
static void switch_drop_locks_drain_work(struct obmm_region *reg)
{
	up_write(&reg->switch_lock);
	mutex_unlock(&reg->state_mutex);
	cancel_work_sync(&reg->switch_work);
	mutex_lock(&reg->state_mutex);
	down_write(&reg->switch_lock);
}

/* Reserve SWAPPING before draining, so a stale finisher that later acquires
 * the locks sees an unowned state and no-ops. Both locks are held here; the
 * drain runs unlocked, and a moved reservation forces IDLE and wakes.
 */
static int quiesce_old_switch_work(struct obmm_region *reg)
{
	enum obmm_switch_state state = READ_ONCE(reg->switch_state);

	if (!obmm_switch_state_can_begin(state)) {
		pr_err_ratelimited("switch: mem_id=%d cannot begin: state=%d is not IDLE, ret=%pe\n",
				   reg->regionid, state, ERR_PTR(-EBUSY));
		return -EBUSY;
	}

	WRITE_ONCE(reg->switch_state, OBMM_SWITCH_SWAPPING);
	switch_drop_locks_drain_work(reg);

	/* gap reference blocks unimport; SWAPPING rejects every competitor */
	state = READ_ONCE(reg->switch_state);	/* re-read: the drain may have moved it */
	if (WARN_ON_ONCE(state != OBMM_SWITCH_SWAPPING)) {
		pr_err("switch: mem_id=%d quiesce raced, state=%d, ret=%pe\n",
		       reg->regionid, state, ERR_PTR(-EIO));
		WRITE_ONCE(reg->switch_state, OBMM_SWITCH_IDLE);
		wake_up_all(&reg->switch_wqh);
		return -EIO;
	}
	return 0;
}

/* Fill the pool spec and validate what the shared validator cannot express
 * (pads, node_count bounds as -EINVAL, trailing sizes) plus the switch-only
 * FAST mask; shell-relative checks stay in the shared validator.
 */
static int exp_spec_from_cmd(const struct obmm_cmd_switch_begin *param,
			     struct obmm_export_pool_spec *spec, u64 mem_size)
{
	unsigned int i;

	if (memchr_inv(param->exp.pad, 0, sizeof(param->exp.pad))) {
		pr_err("switch: exp target pad must be zero\n");
		return -EINVAL;
	}
	if (param->exp.tokenid_pad) {
		pr_err("switch: exp target tokenid_pad must be zero\n");
		return -EINVAL;
	}
	if (param->exp.node_count == 0 ||
	    param->exp.node_count > OBMM_MAX_LOCAL_NUMA_NODES) {
		pr_err("switch: exp target node_count=%u out of range [1, %d]\n",
		       param->exp.node_count, OBMM_MAX_LOCAL_NUMA_NODES);
		return -EINVAL;
	}
	if (param->exp.export_flags & ~OBMM_EXPORT_FLAG_FAST) {
		pr_err("switch: exp target flags=%#llx beyond FAST\n",
		       param->exp.export_flags);
		return -EINVAL;
	}

	memset(spec, 0, sizeof(*spec));
	memcpy(spec->size, param->exp.size, sizeof(spec->size));
	spec->node_count = param->exp.node_count;
	spec->pxm_numa = param->exp.pxm_numa;
	spec->export_flags = param->exp.export_flags;
	memcpy(spec->deid, param->exp.deid, sizeof(spec->deid));

	for (i = spec->node_count; i < OBMM_MAX_LOCAL_NUMA_NODES; i++) {
		if (spec->size[i]) {
			pr_err("switch: exp target size[%u] must be zero past node_count\n", i);
			return -EINVAL;
		}
	}

	return obmm_export_pool_validate_spec(spec, mem_size, true, NULL);
}

static void obmm_switch_stage_outputs(struct obmm_cmd_switch_begin *param,
				       struct obmm_backend *new_be)
{
	struct obmm_export_common *exp;

	if (param->target_type != OBMM_SWITCH_TARGET_EXPORT_POOLED)
		return;

	exp = obmm_backend_to_export_common(new_be);
	param->exp.tokenid = exp->tokenid;
	param->exp.uba = exp->uba;
}

/* Fill the import spec and create the backend; ERR_PTR carries its errno. */
static struct obmm_backend *
imp_backend_from_cmd(const struct obmm_cmd_switch_begin *param, u64 mem_size)
{
	struct obmm_import_spec spec;

	if (memchr_inv(param->imp.pad, 0, sizeof(param->imp.pad))) {
		pr_err("switch: imp target pad must be zero\n");
		return ERR_PTR(-EINVAL);
	}
	spec.addr = param->imp.new_pa;
	spec.scna = param->imp.new_scna;
	spec.dcna = param->imp.new_dcna;
	spec.numa_id = NUMA_NO_NODE;
	spec.base_dist = param->imp.base_dist;
	memcpy(spec.seid, param->imp.new_seid, sizeof(spec.seid));
	memcpy(spec.deid, param->imp.new_deid, sizeof(spec.deid));
	spec.remote = false;
	spec.preimport = false;
	/* -EINVAL/-ENODEV(scna)/-EEXIST(occupancy, maple verbatim) */
	return obmm_import_backend_create(&spec, mem_size, false);
}

/* Rollback mirror of window 2: flush the old backend with the
 * caller-chosen strength, outside the region locks (the flush chunks under
 * the global cache semaphore). SWAPPING still blocks every PTE installer and
 * the gap reference blocks teardown, so the state cannot move underneath;
 * the errno lands in switch_flush_result under the re-acquired locks.
 */
static void switch_rollback_flush_old(struct obmm_region *reg,
				      struct obmm_backend *old_be, bool wb)
{
	int fret;

	up_write(&reg->switch_lock);
	mutex_unlock(&reg->state_mutex);
	fret = old_be->ops->flush_range(old_be, 0, old_be->mem_size,
					wb ? OBMM_SHM_CACHE_WB_INVAL :
					     OBMM_SHM_CACHE_INVAL);
	mutex_lock(&reg->state_mutex);
	down_write(&reg->switch_lock);
	WARN_ON_ONCE(READ_ONCE(reg->switch_state) != OBMM_SWITCH_SWAPPING);
	/* staged store + log, under locks (KCSAN) */
	switch_record_flush_err(reg, fret, "old-backend rollback flush failed");
}

/* Swap the shell's backend. The search_get reference is the gap reference:
 * only the finisher invocation that owns the generation drops it; every
 * error path here does too.
 */
int obmm_switch_begin(struct obmm_cmd_switch_begin *param,
		      struct obmm_cmd_switch_begin __user *uarg)
{
	struct obmm_export_pool_spec exp_spec;
	struct obmm_region *reg;
	struct obmm_backend *new_be = NULL, *old_be;
	struct obmm_backend *deferred_put = NULL;	/* destroyed after unlock */
	struct obmm_backend *deferred_put_old = NULL;	/* old backend's existence ref */
	unsigned char priv_tmp[OBMM_MAX_PRIV_LEN];
	unsigned int priv_len;
	void *vendor;
	enum obmm_switch_state state;
	u32 saved_promised;
	bool old_flush_wb;	/* window-2 flush strength, captured below */
	bool rollback_wb;	/* rollback strength, same capture point */
	int ret, fret_local = 0;

	if (!capable(CAP_SYS_ADMIN)) {
		pr_err_ratelimited("switch: begin requires CAP_SYS_ADMIN, ret=%pe\n",
				   ERR_PTR(-EPERM));
		return -EPERM;
	}
	if (param->flags & ~OBMM_SWITCH_FLAG_MASK) {
		pr_err("switch: invalid flags=%#llx\n", param->flags);
		return -EINVAL;
	}
	if (memchr_inv(param->reserved, 0, sizeof(param->reserved)) ||
	    memchr_inv(param->pad2, 0, sizeof(param->pad2))) {
		pr_err("switch: reserved/pad2 must be zero\n");
		return -EINVAL;
	}
	/* Per-branch pad check: a union-wide check would reject multi-node
	 * export specs (imp.pad overlaps exp.size[6]).
	 */
	ret = obmm_copy_priv_from_user(priv_tmp, param->priv, param->priv_len);
	if (ret) {				/* -EINVAL/-EFAULT before any state */
		pr_err("switch: mem_id=%llu priv_len=%u copy failed, ret=%pe\n",
		       param->mem_id, param->priv_len, ERR_PTR(ret));
		return ret;
	}
	priv_len = param->priv_len;

	reg = switch_lookup_region(param->mem_id);	/* the gap reference */
	if (IS_ERR(reg))
		return PTR_ERR(reg);

	/* advisory fast-fail; authoritative checks under the locks below */
	state = READ_ONCE(reg->switch_state);
	if (!obmm_switch_state_can_begin(state)) {
		pr_err_ratelimited("switch: mem_id=%llu busy: state=%d is not IDLE, ret=%pe\n",
				   param->mem_id, state, ERR_PTR(-EBUSY));
		ret = -EBUSY;
		goto out_put;
	}
	if (reg->created_as != OBMM_IMPORT_REGION || !region_allow_mmap(reg) ||
	    region_numa_remote(reg) || region_preimport(reg)) {
		pr_err("switch: mem_id=%llu is not a plain mmapable import shell\n",
		       param->mem_id);
		ret = -EOPNOTSUPP;
		goto out_put;
	}

	/* ---- lock-free: build the new backend from the inline spec ---- */
	switch (param->target_type) {
	case OBMM_SWITCH_TARGET_IMPORT:
		new_be = imp_backend_from_cmd(param, reg->mem_size);
		break;
	case OBMM_SWITCH_TARGET_EXPORT_POOLED:
		ret = exp_spec_from_cmd(param, &exp_spec, reg->mem_size);
		if (ret)
			goto out_put;
		/* The creator owns the vendor buffer from here on, error paths
		 * included (obmm_backend.h) -- never free it here.
		 */
		vendor = dup_export_vendor(param->exp.vendor_info,
					   param->exp.vendor_len);
		if (IS_ERR(vendor)) {
			ret = PTR_ERR(vendor);
			goto out_put;
		}
		exp_spec.vendor_info = vendor;
		exp_spec.vendor_len = param->exp.vendor_len;
		/* -EINVAL/-ENOMEM(max_total)/-ENODEV(node)/-EPERM(ummu) */
		new_be = obmm_export_pool_backend_create(&exp_spec, reg->mem_size);
		break;
	default:
		pr_err("switch: invalid target_type=%u\n", param->target_type);
		ret = -EINVAL;
		goto out_put;
	}
	if (IS_ERR(new_be)) {
		ret = PTR_ERR(new_be);
		goto out_put;
	}

	mutex_lock(&reg->state_mutex);
	down_write(&reg->switch_lock);

	/*
	 * Capture both flush strengths before quiesce opens window 1: a
	 * last-VMA obmm_vma_close resets mmap_mode to INIT and skips its own
	 * flush while transitional, so only a WB_INVAL taken from the pre-gap
	 * mode carries those dirty lines; re-reading mmap_mode at any flush
	 * site past the quiesce would lose them. Window 2 and the strand
	 * paths may use the KEEP_OLD_ALIVE-gated strength -- there the old
	 * backend is dead or dying, so INVAL loses nothing its destroy would
	 * not. The rollback paths republish or re-attach the old backend as
	 * the region's live memory, so they flush at the mode-only strength
	 * instead (NORMAL always writes back); no path out of begin loses
	 * dirty lines. The plain read is safe: vma_close, fops_mmap and this
	 * site hold state_mutex. INIT -> NORMAL needs no flush: such a
	 * mapping installs no PTEs yet.
	 */
	rollback_wb = reg->mmap_mode == OBMM_MMAP_NORMAL;
	old_flush_wb = rollback_wb &&
		       (param->flags & OBMM_SWITCH_FLAG_KEEP_OLD_ALIVE);

	ret = quiesce_old_switch_work(reg);		/* window 1 */
	if (ret) {
		deferred_put = new_be;
		goto out_unlock;
	}
	/* generation boundary: a rollback below must not keep a previous
	 * generation's errno (first-errno guard)
	 */
	reg->switch_flush_result = 0;

	saved_promised = reg->promised_cap;		/* rollback restore point */
	/* Authoritative attach validation: the backend must serve every
	 * entitlement granted so far; mem_size equality is defensive.
	 */
	if (new_be->mem_size != reg->mem_size ||
	    !obmm_switch_mem_cap_preserved(reg->promised_cap, new_be->mem_cap)) {
		struct obmm_backend *be =
			rcu_dereference_protected(reg->backend,
						  lockdep_is_held(&reg->state_mutex));

		/* Nothing is staged yet, so the snapshot restore and priv
		 * discard are no-ops. Zap under the held locks first: the
		 * rollback flush below runs unlocked, so a store landing after
		 * its chunk was flushed -- with the last VMA closing while
		 * SWAPPING suppresses its close-flush -- would escape it. The
		 * flush then carries both the close-flushes window 1 suppressed
		 * and the just-zapped dirty lines.
		 */
		pr_err("switch: mem_id=%llu target backend insufficient:\n"
		       "shell %#llx/%#x target %#llx/%#x, ret=%pe\n",
		       param->mem_id, reg->mem_size, reg->promised_cap,
		       new_be->mem_size, new_be->mem_cap, ERR_PTR(-EINVAL));
		if (be) {
			obmm_zap_region_mappings(reg);
			switch_rollback_flush_old(reg, be, rollback_wb);
		}
		obmm_switch_to_idle_locked(reg, saved_promised);
		deferred_put = new_be;
		ret = -EINVAL;
		goto out_unlock;
	}

	stage_switch_priv(reg, priv_tmp, priv_len);
	reg->switch_keep_old_alive = (param->flags & OBMM_SWITCH_FLAG_KEEP_OLD_ALIVE) != 0;
	reg->switch_old_mapped = false;
	reg->switch_new_mapped = false;
	reg->switch_generation++;	/* scopes this gap's OLD/NEW VMAs */

	obmm_zap_region_mappings(reg);	/* zap #1 */

	old_be = obmm_backend_detach(reg, NULL);	/* MEMID leaf dropped */
	if (WARN_ON_ONCE(!old_be)) {
		/* detach returns NULL only when reg->backend was already NULL
		 * (it WARNed); window 2's flush needs old_be, so strand.
		 */
		pr_err("switch: mem_id=%llu detach got no backend,\n"
		       "stranding region, ret=%pe\n",
		       param->mem_id, ERR_PTR(-EINVAL));
		obmm_switch_strand_locked(reg);
		deferred_put = new_be;
		ret = -EINVAL;
		goto out_unlock_strand;
	}
	ret = obmm_backend_attach(reg, new_be);		/* MEMID recreate is fallible */
	if (ret) {
		/* Roll back to old, else strand. The attach(new) errno is
		 * returned either way; a re-attach failure shows only in the log.
		 */
		int rollback_ret = obmm_backend_attach(reg, old_be);

		if (rollback_ret == 0) {
			/* The close-flushes that window 1 suppressed ride this
			 * rollback flush (zap #1 already dropped the PTEs, so
			 * no line can escape it).
			 */
			switch_rollback_flush_old(reg, old_be, rollback_wb);
			obmm_switch_to_idle_locked(reg, saved_promised);
			deferred_put = new_be;
			goto out_unlock;
		}
		pr_err("switch: mem_id=%llu attach failed, ret=%pe; rollback\n"
		       "failed too, ret=%pe; stranding region\n",
		       param->mem_id, ERR_PTR(ret), ERR_PTR(rollback_ret));
		obmm_switch_strand_locked(reg);		/* put both after unlock */
		deferred_put = new_be;
		deferred_put_old = old_be;
		goto out_unlock_strand;
	}
	reg->switch_old = old_be;	/* existence ref retained: alive through the gap */

	/* ---- window 2: old-backend flush, possibly seconds ---- */
	up_write(&reg->switch_lock);
	mutex_unlock(&reg->state_mutex);
	fret_local = old_be->ops->flush_range(old_be, 0, old_be->mem_size,
					      old_flush_wb ?
					      OBMM_SHM_CACHE_WB_INVAL :
					      OBMM_SHM_CACHE_INVAL);
	mutex_lock(&reg->state_mutex);
	down_write(&reg->switch_lock);
	WARN_ON_ONCE(READ_ONCE(reg->switch_state) != OBMM_SWITCH_SWAPPING);
	if (fret_local)				/* staged store, under locks (KCSAN) */
		reg->switch_flush_result = fret_local;
	/* No cap re-validation: vacuous after the attach check above. */

	obmm_switch_stage_outputs(param, new_be);	/* tokenid/uba into kernel copy */
	WRITE_ONCE(reg->switch_state, OBMM_SWITCH_AWAIT_READY);

	up_write(&reg->switch_lock);
	mutex_unlock(&reg->state_mutex);
	/* copy_to_user after unlock so a faulting destination cannot wedge the
	 * gap; the outputs are advisory, so -EFAULT is not fatal here.
	 */
	if (param->target_type == OBMM_SWITCH_TARGET_EXPORT_POOLED &&
	    (copy_to_user(&uarg->exp.tokenid, &param->exp.tokenid,
			  sizeof(param->exp.tokenid)) ||
	     copy_to_user(&uarg->exp.uba, &param->exp.uba,
			  sizeof(param->exp.uba))))
		pr_warn("switch: mem_id=%llu failed to copy exp outputs back\n",
			param->mem_id);
	return 0;		/* the gap ref transfers to the finisher */

out_unlock:
	up_write(&reg->switch_lock);
	mutex_unlock(&reg->state_mutex);
	if (deferred_put)
		obmm_backend_put(deferred_put);		/* destroy outside the locks */
	goto out_put;
out_unlock_strand:					/* STRANDED already published */
	up_write(&reg->switch_lock);
	mutex_unlock(&reg->state_mutex);
	wake_up_all(&reg->switch_wqh);
	if (deferred_put_old) {
		/* Write back what the suppressed close-flushes left dirty: the
		 * destroy below only invalidates, which would discard them.
		 */
		fret_local = deferred_put_old->ops->flush_range(
			deferred_put_old, 0, deferred_put_old->mem_size,
			old_flush_wb ? OBMM_SHM_CACHE_WB_INVAL :
				       OBMM_SHM_CACHE_INVAL);
		if (fret_local)
			switch_record_flush_err(reg, fret_local,
						"old-backend flush before strand destroy failed");
	}
	if (deferred_put)
		obmm_backend_put(deferred_put);
	if (deferred_put_old)
		obmm_backend_put(deferred_put_old);
out_put:
	put_obmm_region(reg);
	return ret;
}

/* Rendezvous via mutex_trylock: non-blocking, so no self-deadlock; the
 * mutex orders the success bit. A busy finisher means -EAGAIN without
 * writing.
 */
int obmm_switch_end(const struct obmm_cmd_switch_end *param)
{
	struct obmm_region *reg;
	enum obmm_switch_state state;
	int ret;

	if (!capable(CAP_SYS_ADMIN)) {
		pr_err_ratelimited("switch: end requires CAP_SYS_ADMIN, ret=%pe\n",
				   ERR_PTR(-EPERM));
		return -EPERM;
	}
	if (param->success > 1 || param->reserved) {
		pr_err("switch: end success=%u reserved=%u invalid\n",
		       param->success, param->reserved);
		return -EINVAL;
	}

	reg = switch_lookup_region(param->mem_id);
	if (IS_ERR(reg))
		return PTR_ERR(reg);

	if (!mutex_trylock(&reg->state_mutex)) {
		pr_debug_ratelimited("switch: mem_id=%llu finisher busy,\n"
				     "retry later, ret=%pe\n",
				     param->mem_id, ERR_PTR(-EAGAIN));
		ret = -EAGAIN;
		goto out_put;
	}
	down_write(&reg->switch_lock);

	state = READ_ONCE(reg->switch_state);
	if (state != OBMM_SWITCH_AWAIT_READY) {
		pr_err_ratelimited("switch: mem_id=%llu not in AWAIT_READY (state=%d), ret=%pe\n",
				   param->mem_id, state, ERR_PTR(-ESTALE));
		up_write(&reg->switch_lock);
		mutex_unlock(&reg->state_mutex);
		ret = -ESTALE;
		goto out_put;
	}

	reg->switch_finish_success = (param->success == 1);
	/*
	 * Flip AWAIT_READY -> FINISHING before releasing state_mutex so a second
	 * switch_end gets -ESTALE instead of overwriting the success bit.
	 */
	WRITE_ONCE(reg->switch_state, OBMM_SWITCH_FINISHING);
	up_write(&reg->switch_lock);

	/*
	 * The only armer; begin's quiesce drained the previous invocation, so
	 * the arm cannot fail -- assert rather than build a recovery path.
	 */
	if (WARN_ON_ONCE(!queue_work(obmm_switch_wq, &reg->switch_work)))
		pr_err("switch: mem_id=%d finisher already queued; "
		       "the pending invocation owns the gap\n", reg->regionid);
	mutex_unlock(&reg->state_mutex);
	ret = 0;

out_put:
	put_obmm_region(reg);
	return ret;
}

/*
 * The finisher: one code path, one owner, in the dedicated obmm_switch_wq
 * kworker, queued only by switch_end after FINISHING is published; there is
 * no kernel-side timeout. Only the invocation that armed the gap drops the
 * gap reference; a stale one exits via out_unlock_noput with no wake, no
 * put, no change. The gap-ref drop follows put_after[], so
 * unimport stays -EBUSY while the destroys run.
 * Two critical sections with the full-range flushes between them, unlocked
 * (mirroring begin's window 2): FINISHING is already published, so a racing
 * switch_end gets -ESTALE; the flushes chunk under a global cache semaphore
 * with msleep retries and must not hold the region locks, which would stall
 * faults, mmap/ioctl and switch_end; the second section records the flush
 * errnos and publishes the terminal state. Across the unlocked window the
 * transitional state blocks every PTE installer and the gap reference blocks
 * unimport, so nothing observes a half-finished transition.
 */
void obmm_switch_finish_fn(struct work_struct *work)
{
	struct obmm_region *reg = container_of(work, struct obmm_region, switch_work);
	struct obmm_backend *cur, *old, *put_after[2] = { NULL };
	struct switch_flush_stage flushes[2] = { };
	bool success, stranded = false;
	enum obmm_switch_state state;
	int nput = 0, nflush = 0, i, ret;

	/* No ref taken: begin's gap reference pins the region against unimport. */
	mutex_lock(&reg->state_mutex);
	down_write(&reg->switch_lock);

	state = READ_ONCE(reg->switch_state);
	if (!obmm_switch_finisher_applies(state)) {
		pr_debug("switch: mem_id=%d stale finisher ignored (state=%d)\n",
			 reg->regionid, state);
		goto out_unlock_noput;		/* stale/redundant: no wake, no put */
	}

	/* Defensive: switch_end publishes FINISHING before arming; normally a no-op. */
	if (READ_ONCE(reg->switch_state) == OBMM_SWITCH_AWAIT_READY)
		WRITE_ONCE(reg->switch_state, OBMM_SWITCH_FINISHING);

	success = reg->switch_finish_success;	/* mutex-ordered read */
	cur = reg->backend;			/* == the new backend */
	old = reg->switch_old;

	/* Terminal zap: unconditional; gap-scoped mappings carry PTEs that
	 * must not survive the terminal flip.
	 */
	obmm_zap_region_mappings(reg);

	if (success) {
		/* FINALIZE: commit priv before IDLE, stage flushes, destroy old after unlock. */
		commit_switch_priv(reg);
		if (reg->switch_new_mapped)
			flushes[nflush++] = (struct switch_flush_stage){
				.be = cur, .cache_ops = OBMM_SHM_CACHE_WB_ONLY,
				.what = "new-backend WB flush failed on commit" };
		if (reg->switch_old_mapped)
			flushes[nflush++] = (struct switch_flush_stage){
				.be = old, .cache_ops = OBMM_SHM_CACHE_WB_INVAL,
				.what = "old-backend WB_INVAL failed on commit" };
		reg->switch_old = NULL;
		put_after[nput++] = old;		/* destroy after unlock */
		reg->switch_old_mapped = false;
		reg->switch_new_mapped = false;
	} else {
		/* ABORT: discard migration data before the pool return -- dirty
		 * NORMAL-mode lines must never reach the allocator.
		 */
		discard_switch_priv(reg);
		if (reg->switch_new_mapped)
			flushes[nflush++] = (struct switch_flush_stage){
				.be = cur, .cache_ops = OBMM_SHM_CACHE_INVAL,
				.what = "new-backend INVAL failed on abort" };
		obmm_backend_detach(reg, NULL);
		put_after[nput++] = cur;
		if (reg->switch_keep_old_alive &&
		    obmm_backend_attach(reg, old) == 0) {
			/* Restore the OLD OBJECT; a failed re-attach strands the region. */
			if (reg->switch_old_mapped) {	/* symmetric WB_INVAL */
				flushes[nflush++] = (struct switch_flush_stage){
					.be = old, .cache_ops = OBMM_SHM_CACHE_WB_INVAL,
					.what = "old-backend WB_INVAL failed on abort" };
			}
			reg->switch_old = NULL;	/* ownership moved to backend */
			reg->switch_old_mapped = false;
			reg->switch_new_mapped = false;
			/* Deflate the abort-inflated promise when nothing is open. */
			obmm_promised_cap_shrink_maybe(reg);
		} else {
			/* Keep-old-alive off or re-attach failed: strand_locked
			 * NULLs switch_old; the staged pointer is the sole ref put.
			 */
			if (reg->switch_old) {
				/* Dirty NORMAL-mode lines must not die with the
				 * put below: stage the same WB_INVAL the commit
				 * and abort-restore branches stage.
				 */
				if (reg->switch_old_mapped)
					flushes[nflush++] = (struct switch_flush_stage){
						.be = old, .cache_ops = OBMM_SHM_CACHE_WB_INVAL,
						.what = "old-backend WB_INVAL failed on strand" };
				put_after[nput++] = old;
			}
			obmm_switch_strand_locked(reg);
			stranded = true;
		}
	}
	up_write(&reg->switch_lock);
	mutex_unlock(&reg->state_mutex);

	/* Unlocked flush window (mirrors begin's window 2): the flushes chunk
	 * under a global cache semaphore; backends stay alive through their
	 * staged references and the region locks stay dropped.
	 */
	for (i = 0; i < nflush; i++)
		flushes[i].ret = flushes[i].be->ops->flush_range(
			flushes[i].be, 0, flushes[i].be->mem_size,
			flushes[i].cache_ops);

	mutex_lock(&reg->state_mutex);
	down_write(&reg->switch_lock);
	WARN_ON_ONCE(!stranded &&
		     READ_ONCE(reg->switch_state) != OBMM_SWITCH_FINISHING);
	for (i = 0; i < nflush; i++)
		switch_record_flush_err(reg, flushes[i].ret, flushes[i].what);
	if (!stranded)
		WRITE_ONCE(reg->switch_state, OBMM_SWITCH_IDLE);
	up_write(&reg->switch_lock);
	mutex_unlock(&reg->state_mutex);
	wake_up_all(&reg->switch_wqh);	/* faults re-check: IDLE serves the
					 * survivor, STRANDED SIGBUSes
					 */
	for (i = 0; i < nput; i++) {
		ret = obmm_backend_put(put_after[i]);	/* pr_err inside on
							 * destroy failure
							 */
		if (ret) {
			/* Accepted-leak policy: surfaced, not retried; the store is
			 * atomic and the gap ref still pins the shell.
			 */
			switch_record_flush_err(reg, ret,
						"backend destroy failed (accepted leak)");
		}
	}
	put_obmm_region(reg);		/* sole gap-ref drop */
	return;

out_unlock_noput:
	up_write(&reg->switch_lock);
	mutex_unlock(&reg->state_mutex);
	/* no wake, no put: a prior finish already handled the transition. */
}
