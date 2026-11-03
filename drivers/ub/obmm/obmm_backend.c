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

/* Attach @be to its shell: the fallible MEMID leaf insertion for import
 * backends runs first, so a failed attach changes no reference or state.
 */
int obmm_backend_attach(struct obmm_region *reg, struct obmm_backend *be)
{
	struct resource *memdev_res = NULL;

	/*
	 * state_mutex only: the unimport/unexport release path calls
	 * attach/detach with just state_mutex held, and the switch paths hold
	 * both locks by protocol, so a switch_lock assertion would misfire.
	 */
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
 * Detach @reg's backend and return it alive through its existence reference;
 * only the attachment reference is dropped. On success the caller owns that
 * reference and must eventually obmm_backend_put() it; a MEMID release
 * failure sets *errp and the put must not follow (leak policy in
 * obmm_region_release_backend). *errp NULL means log-and-continue (switch).
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
 * Detach under state_mutex, then drop the existence reference; detach clears
 * reg->backend in the same critical section, so readers observe NULL after.
 *
 * @propagate_detach_err picks a row of this policy table (canonical here):
 *
 *                    detach failed              put/destroy failed
 * unimport/unexport  detach errno verbatim,     destroy errno verbatim;
 * (true)             backend leaks alive        object freed, resources
 *                                               leak loudly
 * register unwind    leak + pr_err, return 0    put, pr_warn, return 0
 * (false)
 *
 * The shell teardown completes in every row. A failed detach is never
 * followed by the put, because destroy would free the parent ubmem resource
 * under the un-released MEMID leaf; the backend leaks loudly instead. The
 * switch paths pass errp == NULL and do stage that put anyway: a deliberate
 * deviation, accepted because release_resource() on a well-formed DIRECT
 * leaf essentially never fails. A NULL detached backend maps to -EINVAL
 * (true) or 0 (false).
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
