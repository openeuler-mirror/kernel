/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
 * for more details.
 *
 * Description: uobj framework in uburma
 * Author: Chen yujie
 * Create: 2022-8-11
 * Note:
 * History: 2022-8-11: Create file
 */

#ifndef UBURMA_UOBJ_H
#define UBURMA_UOBJ_H

#include <urma/ubcore_types.h>

enum UOBJ_CLASS_ID {
	UOBJ_CLASS_ROOT, /* used by framework */
	UOBJ_CLASS_TOKEN,
	UOBJ_CLASS_SEG,
	UOBJ_CLASS_TARGET_SEG,
	UOBJ_CLASS_JFR,
	UOBJ_CLASS_JFS,
	UOBJ_CLASS_JFC,
	UOBJ_CLASS_JFCE,
	UOBJ_CLASS_JFAE,
	UOBJ_CLASS_TARGET_JFR,
	UOBJ_CLASS_JETTY,
	UOBJ_CLASS_TARGET_JETTY,
	UOBJ_CLASS_JETTY_GRP
};

enum uobj_access {
	UOBJ_ACCESS_NOLOCK,
	UOBJ_ACCESS_READ, /* LOCK READ */
	UOBJ_ACCESS_WRITE /* LOCK WRITE */
};

struct uburma_uobj {
	struct uburma_file *ufile; /* associated uburma file */
	void *object; /* containing object */
	struct list_head list; /* link to context's list */
	int id; /* index into kernel idr */
	struct kref ref; /* ref of object associated with uobj */
	atomic_t rcnt; /* protects exclusive access */
	struct rcu_head rcu; /* kfree_rcu() overhead */

	const struct uobj_type *type;
	struct ubcore_cg_object cg_obj; /* cgroup control */
};

struct uobj_type {
	const struct uobj_type_class *const type_class;
	size_t obj_size;
	unsigned int destroy_order;
};

struct uobj_type_class {
	struct uburma_uobj *(*alloc_begin)(const struct uobj_type *type, struct uburma_file *ufile);
	void (*alloc_commit)(struct uburma_uobj *uobj);
	void (*alloc_abort)(struct uburma_uobj *uobj);
	struct uburma_uobj *(*lookup_get)(const struct uobj_type *type, struct uburma_file *ufile,
					  int id, enum uobj_access flag);
	void (*lookup_put)(struct uburma_uobj *uobj, enum uobj_access flag);
	int __must_check (*remove_commit)(struct uburma_uobj *uobj, enum uburma_remove_reason why);
};

struct uobj_idr_type {
	struct uobj_type type;
	int __must_check (*destroy_func)(struct uburma_uobj *uobj, enum uburma_remove_reason why);
};

struct uobj_fd_type {
	struct uobj_type type;
	const char *name;
	const struct file_operations *fops;
	int flags;
	int (*context_closed)(struct uburma_uobj *uobj, enum uburma_remove_reason why);
};

struct uobj_class_def {
	uint16_t id;
	const struct uobj_type *type_attrs;
};

struct uburma_jfe {
	spinlock_t lock;
	struct list_head event_list;
	wait_queue_head_t poll_wait;
	bool deleting;
	struct fasync_struct *async_queue;
};

struct uburma_jfce_uobj {
	struct uburma_uobj uobj;
	struct uburma_jfe jfe;
};

struct uburma_jfc_uobj {
	struct uburma_uobj uobj;
	struct uburma_uobj *jfce; /* associated jfce uobj */
	struct list_head comp_event_list;
	struct list_head async_event_list;
	uint32_t comp_events_reported;
	uint32_t async_events_reported;
};

struct uburma_jfs_uobj {
	struct uburma_uobj uobj;
	struct list_head async_event_list;
	uint32_t async_events_reported;
};

struct uburma_jfr_uobj {
	struct uburma_uobj uobj;
	struct list_head async_event_list;
	uint32_t async_events_reported;
};

struct uburma_jetty_uobj {
	struct uburma_uobj uobj;
	struct list_head async_event_list;
	uint32_t async_events_reported;
};

struct uburma_jetty_grp_uobj {
	struct uburma_uobj uobj;
	struct list_head async_event_list;
	uint32_t async_events_reported;
};

struct uburma_tjetty_uobj {
	struct uburma_uobj uobj;
	struct uburma_jetty_uobj *jetty_uobj;
};

struct uburma_jfae_uobj {
	struct uburma_uobj uobj;
	struct uburma_jfe jfe;
	struct ubcore_event_handler event_handler;
	struct ubcore_device *dev;
};

extern const struct uobj_type_class uobj_idr_type_class;
extern const struct uobj_type_class uobj_fd_type_class;

/* uobj base ops */
struct uburma_uobj *uobj_alloc_begin(const struct uobj_type *type, struct uburma_file *ufile);
void uobj_alloc_commit(struct uburma_uobj *uobj);
void uobj_alloc_abort(struct uburma_uobj *uobj);
struct uburma_uobj *uobj_lookup_get(const struct uobj_type *type,
	struct uburma_file *ufile, int id, enum uobj_access flag);
void uobj_lookup_put(struct uburma_uobj *uobj, enum uobj_access flag);
int __must_check uobj_remove_commit(struct uburma_uobj *uobj);
void uobj_get(struct uburma_uobj *uobj);
void uobj_put(struct uburma_uobj *uobj);

/* internal api */
void uburma_init_uobj_context(struct uburma_file *ufile);
void uburma_cleanup_uobjs(struct uburma_file *ufile, enum uburma_remove_reason why);

void uburma_close_uobj_fd(struct file *f);

#define uobj_class_name(class_id) uobj_class_##class_id

#define uobj_get_type(class_id) uobj_class_name(class_id).type_attrs

#define _uobj_class_set(_id, _type_attrs)                                     \
	((const struct uobj_class_def){ .id = (_id), .type_attrs = (_type_attrs) })

#define _declare_uobj_class(_name, _id, _type_attrs)                         \
	const struct uobj_class_def _name = _uobj_class_set(_id, _type_attrs)

#define declare_uobj_class(class_id, ...)                                    \
	_declare_uobj_class(uobj_class_name(class_id), class_id, ##__VA_ARGS__)

#define uobj_type_alloc_idr(_size, _order, _destroy_func)                    \
	((&((const struct uobj_idr_type) {                          \
			.type = {                                      \
				.type_class = &uobj_idr_type_class,        \
				.obj_size = (_size),                       \
				.destroy_order = (_order),                 \
			},                                             \
			.destroy_func = (_destroy_func),               \
		}))->type)

#define uobj_type_alloc_fd(_order, _obj_size, _context_closed, _fops, _name, _flags)   \
	((&((const struct uobj_fd_type) {                                        \
			.type = {                                                        \
				.destroy_order = (_order),                                   \
				.type_class = &uobj_fd_type_class,                           \
				.obj_size = (_obj_size),                                     \
			},                                                               \
			.context_closed = (_context_closed),                             \
			.fops = (_fops),                                                 \
			.name = (_name),                                                 \
			.flags = (_flags)                                                \
		}))->type)

static inline bool uobj_type_is_fd(const struct uburma_uobj *uobj)
{
	return uobj->type->type_class == &uobj_fd_type_class;
}

#define uobj_alloc(class_id, ufile) uobj_alloc_begin(uobj_get_type(class_id), ufile)

#define uobj_get_read(class_id, _id, ufile)                                \
	uobj_lookup_get(uobj_get_type(class_id), ufile, _id, UOBJ_ACCESS_READ)

#define uobj_put_read(uobj) uobj_lookup_put(uobj, UOBJ_ACCESS_READ)

#define uobj_get_write(class_id, _id, ufile)                               \
	uobj_lookup_get(uobj_get_type(class_id), ufile, _id, UOBJ_ACCESS_WRITE)

#define uobj_put_write(uobj) uobj_lookup_put(uobj, UOBJ_ACCESS_WRITE)

/* Do not lock uobj without cleanup_rwsem locked */
#define uobj_get_del(class_id, _id, ufile)                                \
	uobj_lookup_get(uobj_get_type(class_id), ufile, _id, UOBJ_ACCESS_NOLOCK)

#define uobj_put_del(uobj)  uobj_put(uobj)

extern const struct uobj_class_def uobj_class_UOBJ_CLASS_TOKEN;
extern const struct uobj_class_def uobj_class_UOBJ_CLASS_SEG;
extern const struct uobj_class_def uobj_class_UOBJ_CLASS_JFCE;
extern const struct uobj_class_def uobj_class_UOBJ_CLASS_JFAE;
extern const struct uobj_class_def uobj_class_UOBJ_CLASS_JFC;
extern const struct uobj_class_def uobj_class_UOBJ_CLASS_JFR;
extern const struct uobj_class_def uobj_class_UOBJ_CLASS_JFS;
extern const struct uobj_class_def uobj_class_UOBJ_CLASS_JETTY;
extern const struct uobj_class_def uobj_class_UOBJ_CLASS_JETTY_GRP;
extern const struct uobj_class_def uobj_class_UOBJ_CLASS_TARGET_JFR;
extern const struct uobj_class_def uobj_class_UOBJ_CLASS_TARGET_SEG;
extern const struct uobj_class_def uobj_class_UOBJ_CLASS_TARGET_JETTY;

extern const struct file_operations uburma_jfce_fops;
extern const struct file_operations uburma_jfae_fops;

#endif /* UBURMA_UOBJ_H */
