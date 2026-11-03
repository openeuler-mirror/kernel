// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
 * Description: OBMM memory backend attach/detach/put lifetime glue.
 */

#include <linux/bug.h>
#include <linux/err.h>
#include <linux/lockdep.h>
#include <linux/mutex.h>
#include <linux/refcount.h>
#include <linux/slab.h>

#include "obmm_backend.h"
#include "obmm_resource.h"
#include "obmm_shm_dev.h"	/* obmm_shm_dev_put for obmm_region_publish */

/*
 * Attach a created backend to its shell region. The only fallible step is the
 * MEMID_{regionid} iomem leaf insertion for import backends (request_resource
 * conflict or kasprintf ENOMEM); it runs BEFORE any state change so that a
 * failed attach is reference-neutral and side-effect-free: no refcount_inc,
 * no promised_cap change, no shell pointer, reg->backend unchanged, no leaf.
 */
int obmm_backend_attach(struct obmm_region *reg, struct obmm_backend *be)
{
	struct resource *memdev_res = NULL;

	lockdep_assert_held(&reg->state_mutex);

	if (WARN_ON_ONCE(reg->backend || be->shell))
		return -EINVAL;

	if (WARN_ON_ONCE(be->mem_size != reg->mem_size))
		return -EINVAL;

	if (be->type == OBMM_BACKEND_IMPORT) {
		struct obmm_import_backend *imp = obmm_backend_to_import(be);

		memdev_res = setup_memdev_resource(imp->ubmem_res, imp->pa,
						   be->mem_size, reg->regionid);
		if (IS_ERR(memdev_res)) {
			pr_err("memid=%d: failed to setup memdev resource: %pe\n",
			       reg->regionid, memdev_res);
			return PTR_ERR(memdev_res);
		}
	}

	be->shell = reg;
	be->regionid = reg->regionid;
	refcount_inc(&be->refcnt);
	/* only after the fallible step: a failed attach must not inflate it */
	reg->promised_cap |= be->mem_cap;
	reg->backend = be;
	reg->memdev_res = memdev_res;

	return 0;
}

/*
 * Detach the region's backend. ALWAYS returns the detached backend, still
 * alive through its existence reference (the caller must eventually
 * obmm_backend_put it) even when *errp is set; only the attachment reference
 * is dropped here. Never treat a NULL return or *errp as "object consumed".
 *
 * @errp: nullable. Non-NULL receives the MEMID release errno verbatim;
 * NULL means log-and-continue (switch paths).
 */
struct obmm_backend *obmm_backend_detach(struct obmm_region *reg, int *errp)
{
	struct obmm_backend *be = reg->backend;

	lockdep_assert_held(&reg->state_mutex);

	if (errp)
		*errp = 0;

	if (WARN_ON_ONCE(!be))
		return NULL;

	if (be->type == OBMM_BACKEND_IMPORT) {
		struct obmm_import_backend *imp = obmm_backend_to_import(be);
		int ret;

		ret = release_memdev_resource(imp->ubmem_res, reg->memdev_res);
		if (ret) {
			pr_err("memid=%d: failed to release memdev resource: %pe\n",
			       reg->regionid, ERR_PTR(ret));
			if (errp)
				*errp = ret;
			/* release failed: the leaf is still inserted */
		} else {
			reg->memdev_res = NULL;
		}
	}

	be->shell = NULL;
	reg->backend = NULL;
	/*
	 * Drop only the attachment reference; the caller's existence reference
	 * keeps @be alive, so refcount_dec() must never reach zero here.
	 */
	refcount_dec(&be->refcnt);

	return be;
}

/* Final put: run the per-type destroy, then free @be regardless of result.
 * Destroying an attached backend is a caller bug: detach() first.
 */
static int obmm_backend_destroy(struct obmm_backend *be)
{
	int ret;

	WARN_ON_ONCE(be->shell);

	ret = be->ops->destroy(be);
	if (ret)
		pr_err("backend type=%d destroy failed, ret=%pe.\n",
		       be->type, ERR_PTR(ret));

	kfree(be);
	return ret;
}

/*
 * Drop one reference; the final put runs ops->destroy and returns its result
 * (0 otherwise). A raw refcount_t, not kref: the destroy result must leave the
 * winning decrement, which a kref release function cannot do.
 */
int obmm_backend_put(struct obmm_backend *be)
{
	if (refcount_dec_and_test(&be->refcnt))
		return obmm_backend_destroy(be);

	return 0;
}

/* Attach under state_mutex; on failure drop the existence reference,
 * upgrading the error to a failing destroy's errno.
 */
static int obmm_backend_attach_or_put(struct obmm_region *reg,
				      struct obmm_backend *be, const char *kind)
{
	int ret, rollback_ret;

	mutex_lock(&reg->state_mutex);
	ret = obmm_backend_attach(reg, be);
	mutex_unlock(&reg->state_mutex);
	if (ret) {
		pr_err("Failed to attach %s backend: ret=%pe\n", kind, ERR_PTR(ret));
		/* a failing destroy on the unwind upgrades the error */
		rollback_ret = obmm_backend_put(be);
		if (rollback_ret)
			ret = rollback_ret;
	}

	return ret;
}

/* Publish tail for the creation ioctls: attach @be (destroying it on failure),
 * then register and activate @reg; failure unwinds the shell fully, so the
 * caller only returns the errno. Output fields come from @be before this call.
 */
int obmm_region_publish(struct obmm_region *reg, struct obmm_backend *be,
			const char *kind)
{
	int ret;

	ret = obmm_backend_attach_or_put(reg, be, kind);
	if (ret)
		goto out_unwind;

	ret = register_obmm_region(reg);
	if (ret) {
		pr_err("Failed to create %s device. ret=%pe\n", kind, ERR_PTR(ret));
		goto out_release_memory;
	}
	activate_obmm_region(reg);
	return 0;

out_release_memory:
	/* register error stays the ioctl error (nothing was published);
	 * unwind failures are warn-only (obmm_region_release_backend)
	 */
	obmm_region_release_backend(reg, false);
out_unwind:
	uninit_obmm_region(reg);
	/* frees the region via the device release callback */
	obmm_shm_dev_put(reg);
	return ret;
}

/*
 * Unified release of a region's backend: detach under state_mutex, then drop
 * the existence reference. The detach NULLs reg->backend inside that same
 * critical section, so every state_mutex-held reader (vma close flush, query,
 * sysfs) observes the NULL backend from here on and its dispatch NULL-guard
 * takes over - even on the destroy-failure corner, where put() frees the
 * backend object, no reader can reach it through the shell.
 *
 * Error policy matrix (encoded ONCE here; the call sites pick a row):
 *
 *                       detach failed                put/destroy failed
 * unimport/unexport      abort: detach errno          abort: destroy errno
 * (propagate == true)    verbatim, backend           verbatim; the backend
 *                        leaked alive                object is freed, its
 *                                                    resources leak loudly
 * register-failure       leak + pr_err, return 0:    put, pr_warn, return 0:
 * unwinds                the register errno stays    the register errno stays
 * (propagate == false)   the ioctl error             the ioctl error
 *
 * Why a failed detach must never proceed to the put: destroy would run
 * teardown_pa -> release_ubmem_resource (remove_resource + kfree of the
 * PARENT ubmem resource) while the un-released MEMID leaf still hangs off
 * it and reg->memdev_res still points at it, corrupting the resource tree.
 * The existence reference leaks loudly instead.
 *
 * A NULL detached backend (detach already warned; unreachable while attach
 * precedes a successful creation composition) maps to the propagate row's
 * -EINVAL / the unwind row's 0.
 */
int obmm_region_release_backend(struct obmm_region *reg, bool propagate_detach_err)
{
	struct obmm_backend *be;
	int detach_err, ret;

	mutex_lock(&reg->state_mutex);
	be = obmm_backend_detach(reg, &detach_err);
	mutex_unlock(&reg->state_mutex);

	if (detach_err) {
		if (propagate_detach_err)
			return detach_err;	/* abort: backend leaked alive */
		pr_err("%s: backend detach failed, ret=%pe; backend leaked.\n",
		       __func__, ERR_PTR(detach_err));
		return 0;
	}

	if (!be)
		return propagate_detach_err ? -EINVAL : 0;

	ret = obmm_backend_put(be);
	if (ret && propagate_detach_err)
		return ret;		/* abort: errno verbatim */
	if (ret)
		pr_warn("%s: backend destroy failed, ret=%pe.\n",
			__func__, ERR_PTR(ret));

	return 0;
}
