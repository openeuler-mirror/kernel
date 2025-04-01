/* SPDX-License-Identifier: GPL-2.0 */
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe_log.h
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */
#ifndef _SXE_LOG_H_
#define _SXE_LOG_H_

#include <linux/stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define LOG_INFO_PREFIX_LEN 32
#define LOG_ERROR_PREFIX_LEN 33
#define MEGABYTE 20

enum debug_level {
	LEVEL_ERROR,
	LEVEL_WARN,
	LEVEL_INFO,
	LEVEL_DEBUG,
};

static inline const s8 *sxe_debug_level_name(enum debug_level lv)
{
	static const s8 *level[] = {
		[LEVEL_ERROR] = "ERROR",
		[LEVEL_WARN] = "WARN",
		[LEVEL_INFO] = "INFO",
		[LEVEL_DEBUG] = "DEBUG",
	};

	return level[lv];
}

#define LOG_BUG_ON(cond, fmt, ...)                                           \
	do {                                                                   \
		if ((cond)) {                                                  \
			LOG_ERROR(fmt, ##__VA_ARGS__);                         \
			LOG_SYNC();                                            \
			BUG();                                                 \
		}                                                              \
	} while (0)

#define DEBUG_TRACE_MAGIC 0x456789
#define BUF_SIZE (1024LL << 10)

#define PAGE_ORDER 2
#define PER_CPU_PAGE_SIZE (PAGE_SIZE * (1 << 2))

#define LOG_FILE_SIZE (200LL << 20)
#define BINARY_FILE_SIZE (200LL << 20)

#define VF_LOG_FILE_PATH "/var/log/sxevf.log"
#define VF_LOG_FILE_PREFIX "sxevf.log"
#define VF_BINARY_FILE_PATH "/var/log/sxevf.bin"
#define VF_BINARY_FILE_PREFIX "sxevf.bin"

#define LOG_FILE_PATH "/var/log/sxe.log"
#define LOG_FILE_PREFIX "sxe.log"
#define BINARY_FILE_PATH "/var/log/sxe.bin"
#define BINARY_FILE_PREFIX "sxe.bin"

#define DEBUG_DROP_LOG_STRING "\nwarnning:drop some logs\n\n"

enum {
	DEBUG_TYPE_STRING,
	DEBUG_TYPE_BINARY,
	DEBUG_TYPE_NR,
};

struct debug_func {
	struct list_head list;
	char name[64];
};

struct debug_file {
	struct list_head list;
	char name[64];
};

struct sxe_log {
	struct {
		char *buf;
		int buf_size;
		long long head;
		long long tail;
		/* in order to protect the data */
		spinlock_t lock;
		unsigned char is_drop;
	};

	struct {
		char *file_path;
		struct file *file;
		long long file_pos;
		long long file_size;
		u32 file_num;
		u32 index;
	};
};

struct sxe_thread_local {
	s32 magic;
	char data[0];
};

struct sxe_ctxt {
	struct page *page;
	void *buff;
};

struct sxe_thread_key {
	s32 offset;
};

struct sxe_debug {
	enum debug_level level;
	bool status;
	u16 key_offset;
	struct sxe_ctxt __percpu *ctxt;
	struct list_head filter_func;
	struct list_head filter_file;
	struct task_struct *task;
	struct sxe_log log[DEBUG_TYPE_NR];
};

void sxe_level_set(int level);
s32 sxe_level_get(void);

void sxe_bin_status_set(bool status);
s32 sxe_bin_status_get(void);

int sxe_log_init(bool is_vf);
void sxe_log_exit(void);
void sxe_log_binary(const char *file, const char *func, int line, u8 *ptr,
		    u64 addr, u32 size, char *str);

void sxe_log_sync(void);

#define LOG_DEBUG(fmt, ...)
#define LOG_INFO(fmt, ...)
#define LOG_WARN(fmt, ...)
#define LOG_ERROR(fmt, ...)

#define UNUSED(x) ((void)(x))

#define LOG_DEBUG_BDF(fmt, ...) UNUSED(adapter)
#define LOG_INFO_BDF(fmt, ...) UNUSED(adapter)
#define LOG_WARN_BDF(fmt, ...) UNUSED(adapter)
#define LOG_ERROR_BDF(fmt, ...) UNUSED(adapter)

#define LOG_DEV_DEBUG(format, arg...)                                          \
	dev_dbg(&adapter->pdev->dev, format, ##arg)

#define LOG_DEV_INFO(format, arg...)                                           \
	dev_info(&adapter->pdev->dev, format, ##arg)

#define LOG_DEV_WARN(format, arg...)                                           \
	dev_warn(&adapter->pdev->dev, format, ##arg)

#define LOG_DEV_ERR(format, arg...) dev_err(&adapter->pdev->dev, format, ##arg)

#define LOG_MSG_DEBUG(msglvl, format, arg...)                                  \
	netif_dbg(adapter, msglvl, adapter->netdev, format, ##arg)

#define LOG_MSG_INFO(msglvl, format, arg...)                                   \
	netif_info(adapter, msglvl, adapter->netdev, format, ##arg)

#define LOG_MSG_WARN(msglvl, format, arg...)                                   \
	netif_warn(adapter, msglvl, adapter->netdev, format, ##arg)

#define LOG_MSG_ERR(msglvl, format, arg...)                                    \
	netif_err(adapter, msglvl, adapter->netdev, format, ##arg)

#define LOG_PR_DEBUG(format, arg...) pr_debug("sxe: " format, ##arg)
#define LOG_PR_INFO(format, arg...) pr_info("sxe: " format, ##arg)
#define LOG_PR_WARN(format, arg...) pr_warn("sxe: " format, ##arg)
#define LOG_PR_ERR(format, arg...) pr_err("sxe: " format, ##arg)
#define LOG_PRVF_DEBUG(format, arg...) pr_debug("sxevf: " format, ##arg)
#define LOG_PRVF_INFO(format, arg...) pr_info("sxevf: " format, ##arg)
#define LOG_PRVF_WARN(format, arg...) pr_warn("sxevf: " format, ##arg)
#define LOG_PRVF_ERR(format, arg...) pr_err("sxevf: " format, ##arg)

#define LOG_SYNC()

#define SXE_BUG()
#define SXE_BUG_NO_SYNC()

#ifdef __cplusplus
}
#endif
#endif
