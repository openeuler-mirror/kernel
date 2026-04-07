// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved.
 * Description：ubdevshm core function
 */
#define pr_fmt(fmt) "UBDEVSHM: " fmt

#include <linux/init.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/rbtree.h>
#include <linux/pid.h>
#include <linux/pid_namespace.h>
#include <linux/mutex.h>
#include <linux/idr.h>
#include <linux/kthread.h>
#include <ub/ubdevshm/ubdevshm.h>
#include "ubdevshm_attr.h"
#include "ubdevshm_main.h"

#define UBDEVSHM_IDR_MIN_ID	0
#define UBDEVSHM_IDR_MAX_ID	INT_MAX
#define INVALID_LITE_ROLE ULONG_MAX
#define LITE_ROLE_TGID_SHIFT 32
#define LITE_ROLE_AUX_MASK GENMASK(LITE_ROLE_TGID_SHIFT - 1, 0)
#define LITE_ROLE_TGID(l)  ((l) >> LITE_ROLE_TGID_SHIFT)
#define LITE_ROLE_AUX(l)  ((l) & LITE_ROLE_AUX_MASK)

static bool ubdevshm_init_state;

/* To protect the global resource *_list and *_idr */
struct rw_semaphore ubdevshm_rw_semlock;

struct list_head provider_list = LIST_HEAD_INIT(provider_list);
struct list_head container_list = LIST_HEAD_INIT(container_list);

struct idr shm_container_idr;
struct idr mem_provider_idr;
static struct idr access_ctx_idr;

bool ubdevshm_is_inited(void)
{
	return ubdevshm_init_state;
}
EXPORT_SYMBOL_GPL(ubdevshm_is_inited);

static bool check_provider_registered(struct ubdevshm_mem_ops *ops)
{
	struct mem_provider *pos = NULL;
	bool found = false;

	list_for_each_entry(pos, &provider_list, node) {
		if (pos->ops == ops || pos->ops->acquire == ops->acquire ||
		    pos->ops->release == ops->release) {
			found = true;
			break;
		}
	}

	return found;
}

int ubdevshm_register_ops(struct ubdevshm_mem_ops *ops, unsigned long *handle)
{
	struct mem_provider *provider;
	int ret;

	if (!ops || !ops->acquire || !ops->release || !handle) {
		pr_err("invalid param\n");
		return -EINVAL;
	}

	down_write(&ubdevshm_rw_semlock);
	if (check_provider_registered(ops)) {
		pr_err("ops already registered\n");
		up_write(&ubdevshm_rw_semlock);
		return -EEXIST;
	}

	provider = kzalloc(sizeof(*provider), GFP_KERNEL);
	if (!provider) {
		up_write(&ubdevshm_rw_semlock);
		return -ENOMEM;
	}

	refcount_set(&provider->refcnt, 1);
	provider->ops = ops;
	INIT_LIST_HEAD(&provider->node);
	ret = idr_alloc_cyclic(&mem_provider_idr, provider, UBDEVSHM_IDR_MIN_ID,
			       UBDEVSHM_IDR_MAX_ID, GFP_ATOMIC);
	if (ret < 0) {
		pr_err("shm provider id_alloc err=%d\n", ret);
		kfree(provider);
	} else {
		provider->handle_id = ret;
		list_add_tail(&provider->node, &provider_list);
		*handle = (unsigned long)ret;
		ret = 0;
	}
	up_write(&ubdevshm_rw_semlock);

	return ret;
}
EXPORT_SYMBOL_GPL(ubdevshm_register_ops);

int ubdevshm_unregister_ops(unsigned long *handle)
{
	struct mem_provider *provider;
	int handle_id;
	int ret;

	if (!handle) {
		pr_err("handle is NULL\n");
		return -EINVAL;
	}
	handle_id = (int)*handle;

	down_write(&ubdevshm_rw_semlock);
	provider = idr_find(&mem_provider_idr, handle_id);
	if (!provider) {
		pr_err("invalid handle[%d] without matching provider\n", handle_id);
		ret = -EINVAL;
		goto out;
	}

	if (refcount_dec_if_one(&provider->refcnt)) {
		(void)idr_remove(&mem_provider_idr, (unsigned long)handle_id);
		list_del(&provider->node);
		ret = 0;
	} else {
		pr_err("provider is still used by others\n");
		ret = -EBUSY;
		goto out;
	}

	up_write(&ubdevshm_rw_semlock);
	kfree(provider);
	return ret;

out:
	up_write(&ubdevshm_rw_semlock);
	return ret;
}
EXPORT_SYMBOL_GPL(ubdevshm_unregister_ops);

#define fill_role_info(role, task)	\
({						\
	role.tgid = task_tgid_nr_ns(task, &init_pid_ns); \
	role.aux = task->group_leader->start_time; \
	role.lite = false; \
	get_task_comm(role.name, task); \
	&role; \
})

static void set_role(struct role_info *role, struct task_struct *task)
{
	role->tgid = task_tgid_nr_ns(task, &init_pid_ns);
	role->aux = task->group_leader->start_time;
	get_task_comm(role->name, task);
}

static bool is_same_role(struct role_info *a, struct role_info *b)
{
	if (b->lite)
		return (a->tgid == b->tgid) &&
		       ((a->aux & LITE_ROLE_AUX_MASK) == (b->aux & LITE_ROLE_AUX_MASK));
	return a->tgid == b->tgid && a->aux == b->aux;
}

static bool is_same_role_cb(struct role_info *a, void *b)
{
	return is_same_role(a, (struct role_info *)b);
}

static bool is_same_role_task(struct role_info *role, void *task)
{
	struct task_struct *tsk = (struct task_struct *)task;

	if (role->tgid == task_tgid_nr_ns(tsk, &init_pid_ns) &&
		((role->aux == tsk->group_leader->start_time) ||
		(role->lite && role->aux == (u32)tsk->group_leader->start_time)))
		return true;

	return false;
}

static int find_get_shm_provider(unsigned long *handle,
				 struct mem_provider **rprovider)
{
	struct mem_provider *provider;
	int handle_id;
	int ret = 0;

	if (!handle) {
		pr_err("handle is NULL\n");
		return -EINVAL;
	}
	handle_id = (int)*handle;

	down_read(&ubdevshm_rw_semlock);
	provider = idr_find(&mem_provider_idr, handle_id);
	if (!provider) {
		pr_err("invalid handle[%d] without matching provider\n", handle_id);
		ret = -EINVAL;
		goto out;
	}

	if (!refcount_inc_not_zero(&provider->refcnt)) {
		pr_err("provider[%d] ref is zero\n", handle_id);
		ret = -EINVAL;
		goto out;
	}
	*rprovider = provider;

out:
	up_read(&ubdevshm_rw_semlock);
	return ret;
}

// paired with find_get_shm_provider
static inline void shm_provider_put(struct mem_provider *provider)
{
	refcount_dec(&provider->refcnt);
}

// get before use and put after use.
static struct shm_container *find_get_shm_container(bool (*equal)(struct role_info *, void *),
						    void *arg)
{
	struct shm_container *cntr = NULL, *pos = NULL;

	down_read(&ubdevshm_rw_semlock);
	list_for_each_entry(pos, &container_list, node)	{
		if (equal(&pos->owner, arg)) {
			cntr = pos;
			break;
		}
	}
	if (cntr) {
		if (!refcount_inc_not_zero(&cntr->refcnt)) {
			pr_err("cnt ref is zero\n");
			cntr = NULL;
		}
	}
	up_read(&ubdevshm_rw_semlock);
	return cntr;
}

static inline void shm_container_get(struct shm_container *cntr)
{
	refcount_inc(&cntr->refcnt);
}

static inline void shm_container_put(struct shm_container *cntr)
{
	refcount_dec(&cntr->refcnt);
}

#define __node_2_sa(rb_node)	rb_entry((rb_node), struct shm_area, node)

static inline bool shm_area_less(struct rb_node *a, const struct rb_node *b)
{
	struct shm_area *aa = __node_2_sa(a);
	struct shm_area *ab = __node_2_sa(b);

	return aa->va < ab->va;
}

struct va_area {
	u64 va;
	u64 size;
};

static inline int shm_area_find_overlap(const void *key, const struct rb_node *node)
{
	struct va_area *a = (struct va_area *)key;
	struct shm_area *b = __node_2_sa(node);
	u64 end_area = min(a->va + a->size, b->va + b->size);
	u64 start_area = max(a->va, b->va);

	if (end_area >= start_area)
		return 0;

	return (a->va < b->va) ? -1 : 1;
}

static inline int shm_area_cmp(const void *key, const struct rb_node *node)
{
	struct va_area *a = (struct va_area *)key;
	struct shm_area *b = __node_2_sa(node);

	if (a->va != b->va)
		return (a->va < b->va) ? -1 : 1;

	if (a->size != b->size)
		return (a->size < b->size) ? -1 : 1;

	return 0;
}

static struct shm_area *shm_area_find(struct shm_container *cntr, u64 va, u64 size, bool equal)
{
	const struct va_area area = {
		.va = va,
		.size = size,
	};
	struct rb_node *node;

	if (equal)
		node = rb_find((const void *)&area, &cntr->shm_area_root, shm_area_cmp);
	else
		node = rb_find((const void *)&area, &cntr->shm_area_root, shm_area_find_overlap);

	if (!node)
		return NULL;

	return __node_2_sa(node);
}

// lock hold by caller, protected by cntr->lock
static int shm_area_insert(struct shm_container *cntr, u64 va, u64 size,
				    struct shm_area **rsa)
{
	struct shm_area *sa;

	sa = shm_area_find(cntr, va, size, true);
	if (sa) {
		pr_err("area[%pK, %llx] already exist\n", (void *)va, size);
		return -EEXIST;
	}

	sa = kzalloc(sizeof(*sa), GFP_KERNEL);
	if (!sa)
		return -ENOMEM;

	sa->va = va;
	sa->size = size;
	INIT_LIST_HEAD(&sa->ctx_list);
	rb_add(&sa->node, &cntr->shm_area_root, shm_area_less);
	*rsa = sa;
	return 0;
}

static void __shm_area_delete(struct shm_container *cntr, struct shm_area *sa)
{
	rb_erase(&sa->node, &cntr->shm_area_root);
}

static inline void access_ctx_put(struct access_ctx_inner *ctx)
{
	refcount_dec(&ctx->refcnt);
}

static bool role_equal(struct access_ctx_inner *ctx, void *arg)
{
	struct role_info *role = (struct role_info *)arg;

	return is_same_role(&ctx->user, role);
}

struct role_provider {
	struct role_info *role;
	struct mem_provider *provider;
};

static bool role_provider_equal(struct access_ctx_inner *ctx, void *arg)
{
	struct role_provider *rp = (struct role_provider *)arg;

	return is_same_role(&ctx->user, rp->role) && ctx->provider == rp->provider;
}

static struct access_ctx_inner *find_get_access_ctx(struct shm_container *cntr,
						struct mem_uva *va, bool unique, bool is_equal,
						bool (*equal)(struct access_ctx_inner *, void *),
						void *arg)
{
	struct access_ctx_inner *ctx = NULL, *pos = NULL, *n = NULL;
	struct shm_area *sa;

	mutex_lock(&cntr->lock);
	sa = shm_area_find(cntr, va->va, va->size, is_equal);
	if (!sa) {
		pr_err("area with size[%llx] does not exist\n", va->size);
		mutex_unlock(&cntr->lock);
		return NULL;
	}

	if (unique && !list_is_singular(&sa->ctx_list)) {
		pr_err("ctx matching va not unique, so not allowed to use lite mode\n");
		mutex_unlock(&cntr->lock);
		return NULL;
	}

	list_for_each_entry_safe(pos, n, &sa->ctx_list, node) {
		if (equal(pos, arg)) {
			ctx = pos;
			break;
		}
	}
	if (ctx && !refcount_inc_not_zero(&ctx->refcnt)) {
		pr_err("ctx refcnt is zero\n");
		ctx = NULL;
	}

	mutex_unlock(&cntr->lock);
	return ctx;
}

static struct access_ctx_inner *find_get_access_ctx_by_id(u32 access_ctx_id)
{
	struct access_ctx_inner *ctx;

	down_read(&ubdevshm_rw_semlock);
	ctx = idr_find(&access_ctx_idr, access_ctx_id);
	if (ctx && !refcount_inc_not_zero(&ctx->refcnt)) {
		pr_err("ctx refcnt is zero\n");
		ctx = NULL;
	}
	up_read(&ubdevshm_rw_semlock);

	return ctx;
}

static int create_and_link_access_ctx(struct shm_container *cntr, struct mem_provider *provider,
	struct task_struct *user, bool sa_exit, u64 va, u64 size, struct access_ctx_inner **rctx)
{
	struct access_ctx_inner *ctx;
	struct shm_area *sa;
	int ret;

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return -ENOMEM;

	ctx->provider = provider;
	INIT_LIST_HEAD(&ctx->node);
	set_role(&ctx->user, current);
	refcount_set(&ctx->refcnt, 1);
	refcount_set(&ctx->acquire_refcnt, 1);

	down_write(&ubdevshm_rw_semlock);
	ret = idr_alloc_cyclic(&access_ctx_idr, ctx, UBDEVSHM_IDR_MIN_ID,
			       UBDEVSHM_IDR_MAX_ID, GFP_ATOMIC);
	up_write(&ubdevshm_rw_semlock);
	if (ret < 0) {
		pr_err("shm access ctx id_alloc err=%d\n", ret);
		goto fail;
	}
	ctx->id = ret;
	ctx->seg.va = va;
	ctx->seg.size = size;
	set_role(&ctx->user, user);

	mutex_lock(&cntr->lock);

	sa = shm_area_find(cntr, va, size, true);
	if (!sa) {
		if (sa_exit) {
			pr_err("expect sa exit\n");
			ret = -EEXIST;
			goto fail_idr_remove;
		}
		ret = shm_area_insert(cntr, va, size, &sa);
		if (ret)
			goto fail_idr_remove;
	}

	list_add_tail(&ctx->node, &sa->ctx_list);
	ctx->sa = sa;
	mutex_unlock(&cntr->lock);

	if (rctx)
		*rctx = ctx;
	return 0;

fail_idr_remove:
	mutex_unlock(&cntr->lock);
	down_write(&ubdevshm_rw_semlock);
	(void)idr_remove(&access_ctx_idr, (unsigned long)ctx->id);
	up_write(&ubdevshm_rw_semlock);
fail:
	kfree(ctx);
	return ret;
}

static int create_shm_container(struct shm_container **rcntr)
{
	struct shm_container *cntr;
	int ret;

	cntr = kzalloc(sizeof(*cntr), GFP_KERNEL);
	if (!cntr)
		return -ENOMEM;

	INIT_LIST_HEAD(&cntr->node);
	cntr->shm_area_root = RB_ROOT;
	mutex_init(&cntr->lock);
	set_role(&cntr->owner, current);
	refcount_set(&cntr->refcnt, 1);
	cntr->mode = USE_MODE_NOGRANT;

	down_write(&ubdevshm_rw_semlock);
	ret = idr_alloc_cyclic(&shm_container_idr, cntr, UBDEVSHM_IDR_MIN_ID,
			       UBDEVSHM_IDR_MAX_ID, GFP_ATOMIC);
	if (ret < 0) {
		pr_err("shm container id_alloc err=%d\n", ret);
		up_write(&ubdevshm_rw_semlock);
		goto fail;
	} else {
		cntr->id = ret;
		ret = 0;
		list_add_tail(&cntr->node, &container_list);
		shm_container_get(cntr);
		*rcntr = cntr;
	}
	up_write(&ubdevshm_rw_semlock);
	return ret;

fail:
	kfree(cntr);
	return ret;
}

static struct task_struct *get_task_by_tgid(pid_t tgid)
{
	struct task_struct *tsk;

	rcu_read_lock();
	tsk = get_pid_task(find_pid_ns(tgid, &init_pid_ns), PIDTYPE_TGID);
	if (tsk)
		get_task_struct(tsk);

	rcu_read_unlock();

	return tsk;
}

static bool extract_lite_role(struct mem_uva *va, struct role_info *role)
{
	u64 lite_role = va->invalidate_tag;

	if (lite_role != INVALID_LITE_ROLE) {
		role->tgid = LITE_ROLE_TGID(lite_role);
		role->aux = LITE_ROLE_AUX(lite_role);
		role->lite = true;
		return true;
	}

	return false;
}

// if task exist, get_task_struct otherwise not.
static bool lite_role_get_task_exist(struct role_info *role, struct task_struct **otask,
				     bool *task_get)
{
	struct task_struct *task = NULL;

	*task_get = false;
	task = get_task_by_tgid(role->tgid);
	if (!task)
		return false;

	if (role->aux != (u32)task->group_leader->start_time) {
		put_task_struct(task);
		return false;
	}
	if (otask && task_get) {
		*otask = task;
		*task_get = true;
	} else
		put_task_struct(task);
	return true;
}

int ubdevshm_register_segment(unsigned long *handle, struct mem_uva *va)
{
	bool found = false, task_get = false, is_exist = false;
	struct mem_provider *provider = NULL;
	struct access_ctx_inner *ctx_inner;
	struct role_provider rp = {};
	struct shm_container *cntr;
	struct task_struct *task = NULL;
	struct role_info role;
	int ret;

	if (!handle || !va) {
		pr_err("invalid param\n");
		return -EINVAL;
	}

	if (extract_lite_role(va, &role)) {
		is_exist = lite_role_get_task_exist(&role, &task, &task_get);
		if (!is_exist || !is_same_role_task(&role, current)) {
			pr_err("register segment can not find task: is_exist: %d, current tgid: %d,\n"
				"start_time: %llx, role.tgid: %d, role.aux: %llx\n", is_exist,
				current->tgid, current->group_leader->start_time, role.tgid,
				role.aux);
			if (task)
				put_task_struct(task);
			return -EINVAL;
		}
		if (task_get)
			put_task_struct(task);
	}

	ret = find_get_shm_provider(handle, &provider);
	if (ret)
		return ret;

	cntr = find_get_shm_container(is_same_role_task, current);
	if (cntr) {
		found = true;
	} else {
		ret = create_shm_container(&cntr);
		if (ret)
			goto fail;
	}

	// check segment register repeatly
	if (found) {
		rp.role = fill_role_info(role, current);
		rp.provider = provider;

		ctx_inner = find_get_access_ctx(cntr, va, false, false, role_provider_equal, &rp);
		if (ctx_inner) {
			ret = -EEXIST;
			access_ctx_put(ctx_inner);
			goto fail_cntr;
		}
	}

	ret = create_and_link_access_ctx(cntr, provider, current, false, va->va, va->size, NULL);
	if (ret)
		goto fail_cntr;

	shm_container_put(cntr);

	return ret;

fail_cntr:
	if (!found)
		kfree(cntr);
	if (cntr)
		shm_container_put(cntr);
fail:
	shm_provider_put(provider);
	return ret;
}
EXPORT_SYMBOL_GPL(ubdevshm_register_segment);

static int destroy_access_ctx(struct access_ctx_inner *ctx, struct shm_container *cntr)
{
	mutex_lock(&cntr->lock);
	if (!refcount_dec_if_one(&ctx->acquire_refcnt)) {
		pr_err("ctx is still used by acquire\n");
		mutex_unlock(&cntr->lock);
		return -EBUSY;
	}
	if (!refcount_dec_if_one(&ctx->refcnt)) {
		pr_err("ctx is still used by others\n");
		refcount_set(&ctx->acquire_refcnt, 1);
		mutex_unlock(&cntr->lock);
		return -EBUSY;
	}
	list_del(&ctx->node);
	mutex_unlock(&cntr->lock);

	down_write(&ubdevshm_rw_semlock);
	(void)idr_remove(&access_ctx_idr, (unsigned long)ctx->id);
	shm_provider_put(ctx->provider);
	up_write(&ubdevshm_rw_semlock);

	kfree(ctx);
	return 0;
}

static void shm_area_cleanup(struct shm_area *sa, struct shm_container *cntr)
{
	mutex_lock(&cntr->lock);
	if (list_empty(&sa->ctx_list)) {
		__shm_area_delete(cntr, sa);
		kfree(sa);
	}
	mutex_unlock(&cntr->lock);
}

static bool is_shm_container_free(struct shm_container *cntr)
{
	return RB_EMPTY_ROOT(&cntr->shm_area_root) && refcount_read(&cntr->refcnt) == 1;
}

static void destroy_shm_container(struct shm_container *cntr)
{
	if (!refcount_dec_if_one(&cntr->refcnt)) {
		pr_err("cntr refcnt dec if one failed\n");
		return;
	}
	list_del(&cntr->node);
	(void)idr_remove(&shm_container_idr, (unsigned long)cntr->id);
	kfree(cntr);
}

static void __shm_container_cleanup(struct shm_container *cntr)
{
	if (is_shm_container_free(cntr))
		destroy_shm_container(cntr);
}

static void shm_container_cleanup(void)
{
	struct shm_container *pos = NULL, *n = NULL;

	down_write(&ubdevshm_rw_semlock);
	list_for_each_entry_safe(pos, n, &container_list, node) {
		__shm_container_cleanup(pos);
	}
	up_write(&ubdevshm_rw_semlock);
}

int ubdevshm_unregister_segment(unsigned long *handle, struct mem_uva *va)
{
	struct mem_provider *provider = NULL;
	bool lite = false, task_get = false;
	struct task_struct *task = current;
	struct access_ctx_inner *ctx_inner;
	struct shm_container *cntr;
	struct role_provider rp;
	struct role_info role;
	struct shm_area *sa;
	int ret;

	if (!handle || !va) {
		pr_err("invalid param\n");
		return -EINVAL;
	}

	if (find_get_shm_provider(handle, &provider))
		return -EINVAL;

	if (extract_lite_role(va, &role))
		lite = !lite_role_get_task_exist(&role, &task, &task_get);

	// lite: true means the process has exited.
	cntr = lite ? find_get_shm_container(is_same_role_cb, &role) :
	       find_get_shm_container(is_same_role_task, task);
	if (!cntr) {
		ret = -EINVAL;
		goto out;
	}

	rp.role = lite ? &role : fill_role_info(role, task);
	rp.provider = provider;
	ctx_inner = find_get_access_ctx(cntr, va, false, true, role_provider_equal, &rp);
	if (!ctx_inner) {
		ret = -EINVAL;
		goto out;
	}

	if (task && !is_same_role_task(&ctx_inner->user, task)) {
		ret = -EPERM;
		access_ctx_put(ctx_inner);
		goto out;
	}
	sa = ctx_inner->sa;
	access_ctx_put(ctx_inner);
	ret = destroy_access_ctx(ctx_inner, cntr);
	if (!ret)
		shm_area_cleanup(sa, cntr);

out:
	if (cntr)
		shm_container_put(cntr);

	if (task && task_get)
		put_task_struct(task);
	shm_provider_put(provider);
	shm_container_cleanup();
	return ret;
}
EXPORT_SYMBOL_GPL(ubdevshm_unregister_segment);

static struct shm_container *find_get_shm_container_by_id(u32 cntr_id)
{
	struct shm_container *cntr;

	down_read(&ubdevshm_rw_semlock);
	cntr = idr_find(&shm_container_idr, cntr_id);
	if (cntr) {
		if (!refcount_inc_not_zero(&cntr->refcnt)) {
			pr_err("cnt ref is zero\n");
			cntr = NULL;
		}
	}
	up_read(&ubdevshm_rw_semlock);
	return cntr;
}

static int find_get_shm_context(struct access_ctx *ctx,
		    struct shm_container **rcntr, struct access_ctx_inner **rctx_inner)
{
	struct access_ctx_inner *ctx_inner;
	struct shm_container *cntr;
	int ret;

	cntr = find_get_shm_container_by_id(ctx->shm_container_id);
	if (!cntr) {
		pr_err("invalid shm_container_id[%d] without matching cntr\n",
		       ctx->shm_container_id);
		return -ENOENT;
	}

	ctx_inner = find_get_access_ctx_by_id(ctx->access_ctx_id);
	if (!ctx_inner) {
		pr_err("find access ctx inner[%d] failed\n", ctx->access_ctx_id);
		ret = -ENOENT;
		goto out;
	}

	*rcntr = cntr;
	*rctx_inner = ctx_inner;

	return 0;

out:
	shm_container_put(cntr);
	return ret;
}

static void mem_uba_cpy(struct mem_uba *dst, struct mem_uba *src)
{
	dst->uba = src->uba;
	dst->size = src->size;
	dst->token_id = src->token_id;
	dst->eid = src->eid;
	dst->attr.value = src->attr.value;
	dst->mem_handle = src->mem_handle;
}

/*
 * if ctx is null, it means that there is only one mem provider,
 * and sharer and user is the same process.
 */
int ubdevshm_acquire_uba(struct access_ctx *ctx, struct mem_uva *va, union acquire_attr *attr,
			 invalidate func, struct mem_uba *uba)
{
	struct access_ctx_inner *ctx_inner;
	struct shm_container *cntr;
	struct role_info role;
	int ret;

	if (!va || !attr || !uba) {
		pr_err("invalid param\n");
		return -EINVAL;
	}

	if (!ctx) { // simple mode
		cntr = find_get_shm_container(is_same_role_task, current);
		if (!cntr) {
			pr_err("find cntr failed: current tgid:%d, start_time: %llx\n",
				current->tgid, current->group_leader->start_time);
			return -ENOENT;
		}

		ctx_inner = find_get_access_ctx(cntr, va, true, true, role_equal,
						fill_role_info(role, current));
		if (!ctx_inner) {
			pr_err("find ctx_inner failed: role.tgid: %d, role.aux: %llx\n",
				role.tgid, role.aux);
			ret = -ENOENT;
			goto out;
		}
	} else { // grant mode
		ret = find_get_shm_context(ctx, &cntr, &ctx_inner);
		if (ret)
			return ret;
		if (ctx_inner->sa->size != va->size || ctx_inner->sa->va != va->va) {
			pr_err("area does not exist\n");
			ret = -EINVAL;
			access_ctx_put(ctx_inner);
			goto out;
		}
	}

	if (!is_same_role_task(&ctx_inner->user, current)) {
		ret = -EINVAL;
		access_ctx_put(ctx_inner);
		goto out;
	}

	ret = ctx_inner->provider->ops->acquire(va, attr, func, &ctx_inner->seg.uba);
	if (!ret) {
		if (refcount_inc_not_zero(&ctx_inner->acquire_refcnt)) {
			ctx_inner->seg.uba.mem_handle = (void *)ctx_inner->id;
			mem_uba_cpy(uba, &ctx_inner->seg.uba);
		} else {
			pr_err("ctx acquire ref is zero\n");
			ctx_inner->provider->ops->release(&ctx_inner->seg.uba);
			ret = -ENOENT;
		}
	}
	access_ctx_put(ctx_inner);

out:
	shm_container_put(cntr);
	return ret;
}
EXPORT_SYMBOL_GPL(ubdevshm_acquire_uba);

static bool is_equal_uba(struct mem_uba *a, struct mem_uba *b)
{
	if (a->uba == b->uba && a->size == b->size &&
		a->token_id == b->token_id &&
		a->eid.eid == b->eid.eid &&
		a->attr.bs.readable == b->attr.bs.readable &&
		a->attr.bs.executeable == b->attr.bs.executeable &&
		a->attr.bs.token_value_required == b->attr.bs.token_value_required &&
		a->attr.value == b->attr.value &&
		a->attr.bs.writeable == b->attr.bs.writeable)
		return true;

	return false;
}

static int find_get_shm_container_context(struct access_ctx *ctx, struct mem_uba *uba,
			 struct shm_container **rcntr, struct access_ctx_inner **rctx_inner)
{
	struct access_ctx_inner *ctx_inner;
	struct shm_container *cntr;
	void *mem_handle = uba->mem_handle;
	int ret;

	if (!ctx) { // simple mode
		uintptr_t handle = (uintptr_t)mem_handle;

		ctx_inner = find_get_access_ctx_by_id(handle);
		if (!ctx_inner) {
			pr_err("find access ctx inner failed\n");
			return -ENOENT;
		}
		cntr = find_get_shm_container(is_same_role_cb, &ctx_inner->user);
		if (!cntr) {
			access_ctx_put(ctx_inner);
			return -ENOENT;
		}
	} else { // grant mode
		ret = find_get_shm_context(ctx, &cntr, &ctx_inner);
		if (ret)
			return ret;
		if (!is_same_role_task(&ctx_inner->user, current)) {
			ret = -EINVAL;
			access_ctx_put(ctx_inner);
			goto out;
		}
	}

	*rcntr = cntr;
	*rctx_inner = ctx_inner;

	return 0;

out:
	shm_container_put(cntr);
	return ret;
}

int ubdevshm_release_uba(struct access_ctx *ctx, struct mem_uba *uba)
{
	struct access_ctx_inner *ctx_inner;
	struct shm_container *cntr;
	int ret;

	if (!uba) {
		pr_err("uba is NULL\n");
		return -EINVAL;
	}

	ret = find_get_shm_container_context(ctx, uba, &cntr, &ctx_inner);
	if (ret)
		return ret;

	if (!is_equal_uba(&ctx_inner->seg.uba, uba)) {
		ret = -EINVAL;
		pr_err("uba not matching access uba\n");
		access_ctx_put(ctx_inner);
		goto out;
	}

	if (!refcount_dec_not_one(&ctx_inner->acquire_refcnt)) {
		pr_err("the number of releases is more than acquires.\n");
		ret = -EINVAL;
		access_ctx_put(ctx_inner);
		goto out;
	}

	ret = ctx_inner->provider->ops->release(uba);
	if (!ret) {
		uba->mem_handle = NULL;
	} else {
		/* Without this lock, destroy_access_ctx might decrement acquire reference
		 * counting to zero if it happens to execute the current line of code.
		 */
		mutex_lock(&cntr->lock);
		// This situtation should not have happened.
		if (refcount_inc_not_zero(&ctx_inner->acquire_refcnt))
			pr_warn("refcnt is not zero, refcount is fail.\n");
		mutex_unlock(&cntr->lock);
	}
	access_ctx_put(ctx_inner);
out:
	shm_container_put(cntr);
	return ret;
}
EXPORT_SYMBOL_GPL(ubdevshm_release_uba);

static struct task_struct *get_task_by_peer_tgid(struct task_struct *peer, pid_t tgid)
{
	struct task_struct *tsk;

	rcu_read_lock();
	tsk = get_pid_task(find_pid_ns(tgid, task_active_pid_ns(peer)), PIDTYPE_PID);
	if (tsk == peer) {
		pr_err("tgid[%d] is same with peer task\n", tgid);
		tsk = NULL;
	} else {
		if (tsk)
			get_task_struct(tsk);
	}
	rcu_read_unlock();

	return tsk;
}

static inline int user_tgid(struct shm_user *user, pid_t *rtgid)
{
	if (user->type != IDENTIY_TGID || user->user_len != sizeof(*rtgid))
		return -EINVAL;

	*rtgid = *((pid_t *)user->user);
	return 0;
}

int ubdevshm_grant_access(unsigned long *handle, struct shm_user *user,
			  struct mem_uva *va, struct access_ctx *ctx)
{
	struct access_ctx_inner *ctx_inner, *ctx_parent;
	struct mem_provider *provider;
	struct shm_container *cntr;
	struct task_struct *utask;
	struct role_provider rp;
	struct role_info role;
	pid_t tgid;
	int ret;

	if (!handle || !user || !va || !ctx || user->type != IDENTIY_TGID) {
		pr_err("invalid param\n");
		return -EINVAL;
	}

	ret = find_get_shm_provider(handle, &provider);
	if (ret)
		return ret;

	ret = user_tgid(user, &tgid);
	if (ret) {
		pr_err("user tgid trans failed\n");
		goto out_put_provider;
	}

	utask = get_task_by_peer_tgid(current, tgid);
	if (!utask) {
		ret = -EINVAL;
		goto out_put_provider;
	}

	cntr = find_get_shm_container(is_same_role_task, current);
	if (!cntr) {
		pr_err("find cntr failed: current tgid:%d, start_time: %llx\n",
			current->tgid, current->group_leader->start_time);
		ret = -EINVAL;
		goto out_put_task_provider;
	}

	rp.role = fill_role_info(role, utask);
	rp.provider = provider;
	ctx_inner = find_get_access_ctx(cntr, va, false, true, role_provider_equal, &rp);
	if (ctx_inner) {
		ret = -EEXIST;
		access_ctx_put(ctx_inner);
		goto out;
	}

	rp.role = fill_role_info(role, current);
	ctx_parent = find_get_access_ctx(cntr, va, false, true, role_provider_equal, &rp);
	if (!ctx_parent) {
		ret = -EINVAL;
		goto out;
	}
	ret = create_and_link_access_ctx(cntr, provider, utask, true, va->va, va->size, &ctx_inner);
	if (ret) {
		access_ctx_put(ctx_parent);
		goto out;
	}

	ctx->access_ctx_id = ctx_inner->id;
	ctx->shm_container_id = cntr->id;

	cntr->mode = USE_MODE_GRANT;
	put_task_struct(utask);
	shm_container_put(cntr);
	pr_info("grant area with size[%llx] success\n", va->size);
	return 0;

out:
	shm_container_put(cntr);
out_put_task_provider:
	put_task_struct(utask);
out_put_provider:
	shm_provider_put(provider);
	return ret;
}
EXPORT_SYMBOL_GPL(ubdevshm_grant_access);

static struct access_ctx_inner *find_cntr_owner_access_ctx(struct shm_container *cntr,
							   struct shm_area *sa)
{
	struct access_ctx_inner *ctx = NULL, *pos = NULL;

	mutex_lock(&cntr->lock);
	list_for_each_entry(pos, &sa->ctx_list, node) {
		if (is_same_role(&pos->user, &cntr->owner)) {
			ctx = pos;
			break;
		}
	}
	mutex_unlock(&cntr->lock);
	return ctx;
}

int ubdevshm_ungrant_access(struct access_ctx *ctx)
{
	struct access_ctx_inner *ctx_inner, *ctx_parent;
	struct shm_container *cntr;
	int ret = 0;

	if (!ctx) {
		pr_err("invalid param\n");
		return -EINVAL;
	}

	cntr = find_get_shm_container_by_id(ctx->shm_container_id);
	if (!cntr) {
		pr_err("invalid shm_container_id[%d] without matching cntr\n",
		       ctx->shm_container_id);
		return -ENOENT;
	}

	if (!is_same_role_task(&cntr->owner, current)) {
		ret = -EPERM;
		goto out;
	}

	ctx_inner = find_get_access_ctx_by_id(ctx->access_ctx_id);
	if (!ctx_inner) {
		pr_err("find access ctx inner failed\n");
		ret = -ENOENT;
		goto out;
	}

	ctx_parent = find_cntr_owner_access_ctx(cntr, ctx_inner->sa);
	if (!ctx_parent) {
		pr_err("FATAL err: find cntr owner access ctx failed\n");
		ret = -ENOENT;
		goto out;
	}

	access_ctx_put(ctx_inner);
	ret = destroy_access_ctx(ctx_inner, cntr);
	if (ret) {
		pr_err("destroy access ctx failed=%d\n", ret);
		goto out;
	}
	access_ctx_put(ctx_parent); // matching with grant
	pr_info("ungrant area with size[%llx] success\n", ctx_parent->sa->size);

out:
	shm_container_put(cntr);
	return ret;
}
EXPORT_SYMBOL_GPL(ubdevshm_ungrant_access);

static int __init ubdevshm_init(void)
{
	int ret;

	idr_init(&shm_container_idr);
	idr_init(&mem_provider_idr);
	idr_init(&access_ctx_idr);

	ret = ubdevshm_attr_file_init();
	if (ret)
		return ret;

	init_rwsem(&ubdevshm_rw_semlock);
	ubdevshm_init_state = true;
	return ret;
}

static void __exit ubdevshm_exit(void)
{
	ubdevshm_init_state = false;

	ubdevshm_attr_file_uninit();
	idr_destroy(&access_ctx_idr);
	idr_destroy(&mem_provider_idr);
	idr_destroy(&shm_container_idr);
}

module_init(ubdevshm_init);
module_exit(ubdevshm_exit);

MODULE_DESCRIPTION("Hisilicon ubdevshm");
MODULE_LICENSE("GPL");
