/* SPDX-License-Identifier: GPL-2.0 */
/**
 * Copyright (C), 2020, sxe2rdma Technologies Co., Ltd.
 *
 * @file: sxe2_drv_rdma_inject.h
 * @author: sxe2rdma
 * @date: 2025.02.16
 * @brief:
 * @note:
 */
#ifndef _SXE2_DRV_INJECT_H_
#define _SXE2_DRV_INJECT_H_

#include <linux/list.h>
#include "sxe2_drv_rdma_log.h"

struct sxe2_rdma_pci_f;

#if defined(SXE2_SUPPORT_INJECT) && defined(SXE2_CFG_DEBUG)
enum { SXE2_INJECT_MID_MQ,
		SXE2_INJECT_MID_RCMS,
};

#define SXE2_INJECT_STRTOL_BASE	 (0)
#define SXE2_INJECT_USR_DATA_LEN (128)
#define SXE2_INJECT_NAME_MAX_LEN (120)
#define INJECT_CMD_MAX_LEN	 (200)

#if defined(SXE2_SUPPORT_DEBUG) && !defined(PCLINT)
#define SXE2_INJECT_BUG()   (*(int *)0 = 0)

#define SXE2_INJECT_BUG_ON(_cond)    \
	do {                             \
		if (unlikely(_cond))         \
			SXE2_INJECT_BUG();       \
	} while (0)
#else
#define SXE2_INJECT_BUG()
#endif

struct sxe2_inject_usable_array {
	u64 *array_addr;
	spinlock_t array_lock;
};

struct sxe2_inject_mem_mgr {
	char *base_addr;
	char *end_addr;
	char *cursor;
	struct sxe2_inject_usable_array
		usable_array;
};

struct sxe2_inject_mem {
	struct sxe2_inject_mem_mgr inject_mem_mgr;
	struct list_head *g_inject_hash_table;
	struct list_head g_inject_list;
	spinlock_t list_lock;
};

struct sxe2_inject_debug {
	struct dentry *dbg_root;
	spinlock_t dbg_lock;
	char inject_cmd[INJECT_CMD_MAX_LEN];
};

enum { SXE2_INJECT_MID_CQ,
		SXE2_INJECT_MID_RESET,
		SXE2_INJECT_MID_EQ,
		SXE2_INJECT_MID_QP,
		SXE2_INJECT_MID_MR,
		SXE2_INJECT_MID_CEQ,
};

typedef void (*inject_callback)(char *user_data, ...);

struct inject_name {
	const char *name;
	u32 hash_code;
};

enum inject_type {
	INJECT_TYPE_CALLBACK = 0,
	INJECT_TYPE_PAUSE = 1,
	INJECT_TYPE_ABORT = 2,
	INJECT_TYPE_RESET = 3,
	INJECT_TYPE_BUTT
};

struct sxe2_injection {
	struct list_head hash_node;
	struct list_head list_node;
	struct inject_name inject_name;
	s32 mid;
	char user_data[SXE2_INJECT_USR_DATA_LEN];
	s32 alive;
	enum inject_type type;
	inject_callback callback;
	spinlock_t lock;
};

void inject_lock(struct sxe2_injection *injection, unsigned long *flags);

void inject_unlock(struct sxe2_injection *injection, unsigned long *flags);

s32 inject_init(struct sxe2_rdma_pci_f *dev);

struct sxe2_injection *inject_find(struct sxe2_rdma_pci_f *dev, const char *name);

s32 inject_register(struct sxe2_rdma_pci_f *dev, const char *name,
		    inject_callback callback, s32 mid);

s32 inject_unregister(struct sxe2_rdma_pci_f *dev, const char *name);

void inject_fill(struct sxe2_injection *src, struct sxe2_injection *dst);

void inject_active_intf(struct sxe2_rdma_pci_f *dev, const char *name,
			const char *cmd);

void inject_deactive_intf(struct sxe2_rdma_pci_f *dev, const char *name);

bool inject_execute_callback(struct sxe2_rdma_pci_f *dev, const char *name);

s32 inject_count(struct sxe2_rdma_pci_f *dev);

void inject_clear_intf(struct sxe2_rdma_pci_f *dev);

s32 inject_uninit(struct sxe2_rdma_pci_f *dev);

#define INJECT_INIT(dev)   inject_init(dev)
#define INJECT_UNINIT(dev) inject_uninit(dev)
#define INJECT_REG(dev, name, callback, mid)                    \
	inject_register(dev, name, (inject_callback)callback, mid)
#define INJECT_UNREG(dev, name) inject_unregister(dev, name)

#define INJECT_START(dev, name, ...)                           \
	do {                                                       \
		if (inject_execute_callback(dev, name)) {              \
			struct sxe2_injection *injection = inject_find(dev, name); \
			DRV_RDMA_LOG_INFO("inject(%s) active, alive dec=%d,\n"    \
					  "\ttype=%u, user_data=%s\n",                    \
					  name, injection->alive, injection->type,        \
					  injection->user_data);                          \
			injection->callback(injection->user_data, __VA_ARGS__);   \
		}                          \
	} while (0)

#define INJECT_END

#define INJECT_GET_ALIVE(dev, name)             \
	({                                          \
		struct sxe2_injection *injection = inject_find(dev, name); \
		injection->alive;                                          \
	})

#define INJECT_ACTIVE(dev, name, cmd) inject_active_intf(dev, name, cmd)
#define INJECT_DEACTIVE(dev, name)    inject_deactive_intf(dev, name)
#define INJECT_COUNT(dev)	      inject_count(dev)
#define INJECT_CLEAR(dev)	      inject_clear_intf(dev)

#else
typedef void (*inject_callback)(char *user_data, ...);

static inline s32 inject_init(struct sxe2_rdma_pci_f *dev)
{
	(void)dev;
	return 0;
}

static inline s32 inject_uninit(struct sxe2_rdma_pci_f *dev)
{
	(void)dev;
	return 0;
}

static inline s32 inject_register(struct sxe2_rdma_pci_f *dev, const char *name,
				  inject_callback callback, s32 mid)
{
	(void)dev;
	(void)name;
	(void)callback;
	(void)mid;
	return 0;
}

static inline s32 inject_unregister(struct sxe2_rdma_pci_f *dev,
				    const char *name)
{
	(void)dev;
	(void)name;
	return 0;
}

#define INJECT_INIT(dev)   inject_init(dev)
#define INJECT_UNINIT(dev) inject_uninit(dev)
#define INJECT_REG(dev, name, callback, mid)                                   \
	inject_register(dev, name, (inject_callback)callback, mid)
#define INJECT_UNREG(dev, name) inject_unregister(dev, name)
#define INJECT_START(dev, name, ...)
#define INJECT_END
#define INJECT_GET_ALIVE(dev, name) 0
#define INJECT_ACTIVE(dev, name, cmd)
#define INJECT_DEACTIVE(dev, name)
#define INJECT_COUNT(dev) 0
#define INJECT_CLEAR(dev)
#endif

#endif
