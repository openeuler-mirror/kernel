/* SPDX-License-Identifier: GPL-2.0+ */
/* Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved.
 * Description：ubdevshm defines and function prototypes
 */

#ifndef _UB_UBDEVSHM_UBDEVSHM_H_
#define _UB_UBDEVSHM_UBDEVSHM_H_

#include <linux/kernel.h>

#define UBDEVSHM_VERSION_MAJOR 1
#define UBDEVSHM_VERSION_MINOR 0

/**
 * struct uba_eid - eid info of ub address.
 * @eid: eid info.
 * @reserved0: will be ignored.
 * @reserved1: will be ignored.
 */
struct uba_eid {
	u64 eid : 20; /* bus_instance_eid */
	u64 reserved0 : 44;
	u64 reserved1 : 64;
};

/**
 * union uba_attr - permissions info of ub address.
 * @bs.readable: read permissions.
 * @bs.writeable: write permissions.
 * @bs.executeable: execute permissions.
 * @bs.token_value_required: enable token value.
 * @reserved: will be ignored.
 * @value:This parameter is used when the detail permission information
 * is not concerned.
 */
union uba_attr {
	struct {
		u64 readable : 1;
		u64 writeable : 1;
		u64 executeable : 1;
		u64 token_value_required : 1;
		u64 reserved : 60;
	} bs;
	u64 value;
};

/**
 * union acquire_attr - acquire uba address info.
 * @bs.require_pin: memory should pin when memory user acquire uba address.
 * @bs.reserved: will be ignored.
 * @value: This parameter is used when the acquire information
 * is not concerned.
 */
union acquire_attr {
	struct {
		u64 require_pin : 1;
		u64 require_invalidate : 1;
		u64 reserved : 62;
	} bs;
	u64 value;
};

/**
 * struct mem_uva - share memory info.
 * @va: va start.
 * @size: va size.
 */
struct mem_uva {
	u64 va;
	u64 size;
	u64 invalidate_tag;
};

/**
 * struct mem_uba - uba address info.
 * @uba: uba start.
 * @size: uba size.
 * @token_id: token value.
 * @eid: eid info.
 * @attr: permissions info.
 * @mem_handle: corresponding memory provider handle.
 */

struct mem_uba {
	u64 uba;
	u64 size;
	u32 token_id; /* BIT[0:19] is valid for token_id */
	struct uba_eid eid;
	union uba_attr attr;

	void *mem_handle; /* used by ubdevshm inner */
};

enum identity_type {
	/*
	 * IDENTIY_TGID constraint:
	 * The shared and user processes must reside within the same PID namespace.
	 */
	IDENTIY_TGID,
	IDENTIY_TYPE_MAX,
};

/**
 * struct shm_user - share memory user info.
 * @type: constraint.
 * @user_len: user info length.
 * @user: user pid info.
 */
struct shm_user {
	enum identity_type type;
	u32 user_len;
	void *user;
};

/**
 * struct access_ctx - share memory user access info.
 * @shm_container_id: container index.
 * @access_ctx_id: access index.
 */

struct access_ctx {
	u32 shm_container_id;
	u32 access_ctx_id;

};

typedef int (*invalidate)(u64 invalidate_tag);

#define UBDEV_SHM_DRIVER_NAME_LENGTH 128

struct ubdevshm_mem_ops {
	char name[UBDEV_SHM_DRIVER_NAME_LENGTH];
	u32 version;

	/* Request access to the virtual address range of the given VA */
	int (*acquire)(struct mem_uva *va, union acquire_attr *attr,
		       invalidate func, struct mem_uba *uba);

	/* Release the uba address */
	int (*release)(struct mem_uba *uba);
};

/**
 * ubdevshm_is_inited() - ubdevshm initialization check interface.
 *
 * Return whether ubdevshm is initialization.
 *
 * Context: Any context.
 * Return: true indicates ubdevshm is avaialbe, false indicates not.
 */
bool ubdevshm_is_inited(void);

/*
 * NOTE:
 * pid/tgid is implicit in the calling context and not passed explicitly
 * in the following interfaces.
 */

/**
 * ubdevshm_register_ops() - Memory provider registration interface.
 * @ops: memory provider specific alloc/free callbacks.
 * @handle: corresponding memory provider handle.
 *
 * Memory provider registration address acquire function.
 *
 * Context: Any context.
 * return: 0 indicates success, while any other value indicates failure.
 */
int ubdevshm_register_ops(struct ubdevshm_mem_ops *ops, unsigned long *handle);

/**
 * ubdevshm_unregister_ops() - Memory provider unregistration interface.
 * @handle: corresponding memory provider handle.
 *
 * Memory provider unregistration address acquire function, Use
 * the corresponding handle to apply for memory.
 *
 * Context: Any context.
 * return: 0 indicates success, while any other value indicates failure.
 */
int ubdevshm_unregister_ops(unsigned long *handle);

/**
 * ubdevshm_register_segment() - Share memory segment registration interface.
 * @handle: corresponding memory provider handle.
 * @va: virtual address range of the given VA.
 *
 * After applying for memory, the memory applicant invokes this API to bind
 * the memory applicant, memory provider, and share memory.
 *
 * Context: Any context.
 * return: 0 indicates success, while any other value indicates failure.
 */
int ubdevshm_register_segment(unsigned long *handle, struct mem_uva *va);

/**
 * ubdevshm_unregister_segment() - Share memory segment unregistration interface.
 * @handle: corresponding memory provider handle.
 * @va: virtual address range of the given VA.
 *
 * Before releasing the share memory, memory applicant need to invoke this
 * interface to unbind the share memory.
 *
 * Context: Any context.
 * return: 0 indicates success, while any other value indicates failure.
 */
int ubdevshm_unregister_segment(unsigned long *handle, struct mem_uva *va);

/**
 * ubdevshm_grant_access() - Authorize the share memory to memory user.
 * @handle: corresponding memory provider handle.
 * @user: corresponding authorized process information.
 * @va: virtual address range of the given VA.
 * @ctx: the context of the segment obtained after authorization.
 *
 * After register segment, the memory applicant invokes this API to
 * Authorize the share memory to memory user.
 *
 * Context: Any context.
 * return: 0 indicates success, while any other value indicates failure
 */
int ubdevshm_grant_access(unsigned long *handle, struct shm_user *user,
			  struct mem_uva *va, struct access_ctx *ctx);

/**
 * ubdevshm_ungrant_access() - De-authorize the shared memory associated
 * with access_ctx.
 * @ctx: the context of the segment obtained after authorization
 *
 * Before releasing the share memory, memory applicant need to invoke this
 * interface to De-authorize the shared memory associated with access_ctx.
 *
 * Context: Any context.
 * return: 0 indicates success, while any other value indicates failure
 */
int ubdevshm_ungrant_access(struct access_ctx *ctx);

/**
 * ubdevshm_acquire_uba() - Request to acqurie the address corresponding to
 * share memory and convert it into a ub address.
 * @ctx: the context of the segment
 * @va: virtual address range of the given VA
 * @attr: request attributes
 * @func: When require_invalidate in acquire_attr is set to 1,
 *         this function must not be NULL, and is used as a callback
 *         for the memory provider to release memory.
 * @uba: the ub address corresponding to the virtual address va
 *
 * Memory user invoke this interface to convert share memory into a ub address.
 *
 * Context: Any context.
 * return: 0 indicates success, while any other value indicates failure
 */
int ubdevshm_acquire_uba(struct access_ctx *ctx, struct mem_uva *va,
			 union acquire_attr *attr, invalidate func, struct mem_uba *uba);

/**
 * ubdevshm_release_uba() - Request to release the address corresponding to mem_uba
 * @ctx: the context of the segment
 * @uba: the ub address to be released
 *
 * Before releasing the share memory, memory user invoke this interface to
 * release mem_uba.
 *
 * Context: Any context.
 * return: 0 indicates success, while any other value indicates failure
 */
int ubdevshm_release_uba(struct access_ctx *ctx, struct mem_uba *uba);

/**
 * ubdevshm_check_version() - version check
 * @app_major: major version from user
 * @app_minor: minor version from user
 *
 * Before using the functions of this module, user must call this
 * interface to check the version
 *
 * return: 0 indicates pass, while any other value indicates failure
 */
int ubdevshm_check_version(uint32_t app_major, uint32_t app_minor);

#endif /*_UB_UBDEVSHM_UBDEVSHM_H_*/
