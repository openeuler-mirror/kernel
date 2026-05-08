/* SPDX-License-Identifier: GPL-2.0 */
/**
 * Copyright (C), 2020, sxe2rdma Technologies Co., Ltd.
 *
 * @file: sxe2_drv_rdma_log.h
 * @author: sxe2rdma
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#ifndef _SXE2_DRV_RDMA_LOG_H_
#define _SXE2_DRV_RDMA_LOG_H_

#include <linux/types.h>
#include <linux/spinlock.h>

#ifdef SXE2_UT
#define STATIC
#else
#ifndef STATIC
#define STATIC static
#endif
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define SXE2_HOST(ins)  ((ins)->host->host_no)

#define LOG_INFO_PREFIX_LEN  32
#define LOG_ERROR_PREFIX_LEN 33
#define MEGABYTE	     20

enum debug_level {
	LEVEL_ERROR,
	LEVEL_WARN,
	LEVEL_INFO,
	LEVEL_DEBUG,
};

static const char * const sxe2_rdma_level[] = {
	[LEVEL_ERROR] = "ERROR",
	[LEVEL_WARN]  = "WARN",
	[LEVEL_INFO]  = "INFO",
	[LEVEL_DEBUG] = "DEBUG",
};

static inline const char *sxe2_debug_level_name(enum debug_level lv)
{
	return sxe2_rdma_level[lv];
}

#ifdef __KERNEL__

#define PRINT_DEBUG KERN_DEBUG
#define PRINT_INFO  KERN_INFO
#define PRINT_WARN  KERN_WARNING
#define PRINT_ERR   KERN_ERR

#define sxe2_print(level, bdf, fmt, ...)                             \
	do {                                 \
		if (!level) {                                            \
			if (!strcmp(level, KERN_DEBUG)) {                           \
				pr_debug("[SXE2][%s]%s():%d:" fmt, bdf ? bdf : "unknown", \
		       __func__, __LINE__, ##__VA_ARGS__);                      \
			} else if (!strcmp(level, KERN_INFO)) {                       \
				pr_info("[SXE2][%s]%s():%d:" fmt, bdf ? bdf : "unknown", \
		       __func__, __LINE__, ##__VA_ARGS__);                        \
			} else if (!strcmp(level, KERN_WARNING)) {                     \
				pr_warn("[SXE2][%s]%s():%d:" fmt, bdf ? bdf : "unknown", \
		       __func__, __LINE__, ##__VA_ARGS__);                          \
			} else if (!strcmp(level, KERN_ERR)) {                       \
				pr_err("[SXE2][%s]%s():%d:" fmt, bdf ? bdf : "unknown", \
		       __func__, __LINE__, ##__VA_ARGS__);                         \
			}                                 \
		}                                     \
	} while (0)
#else

#define PRINT_DEBUG LEVEL_DEBUG
#define PRINT_INFO  LEVEL_INFO
#define PRINT_WARN  LEVEL_WARN
#define PRINT_ERR   LEVEL_ERROR

#include <assert.h>
#include <sys/time.h>
#include <string.h>
#include <pthread.h>

#define __percpu

static inline U64 get_now_ms(void)
{
	struct timeval tv;
	U64 timestamp = 0;

	gettimeofday(&tv, NULL);
	timestamp = tv.tv_sec * 1000 + tv.tv_usec / 1000;
	return timestamp;
}

#define filename_printf(x) (strrchr((x), '/') ? strrchr((x), '/') + 1 : (x))

#define sxe2_print(level, bdf, fmt, ...)                     \
	do {                             \
		if (level <= 4) {                             \
			if (level == LEVEL_DEBUG) {                        \
				printf("DEBUG:%llu:%s:%s():%d:[%lu][%s];" fmt, \
				       get_now_ms(),                           \
				       filename_printf(__FILE__),             \
				       __func__, __LINE__, pthread_self(),              \
				       bdf ? bdf : "unknown", ##__VA_ARGS__);         \
			} else if (level == LEVEL_INFO) {                             \
				printf("INFO:%llu:%s:%s():%d:[%lu][%s];" fmt,      \
				       get_now_ms(),                             \
				       filename_printf(__FILE__),                 \
				       __func__, __LINE__, pthread_self(),          \
				       bdf ? bdf : "unknown", ##__VA_ARGS__);        \
			} else if (level == LEVEL_WARN) {                    \
				printf("WARN:%llu:%s:%s():%d:[%lu][%s];" fmt,     \
				       get_now_ms(),                             \
				       filename_printf(__FILE__),               \
				       __func__, __LINE__, pthread_self(),      \
				       bdf ? bdf : "unknown", ##__VA_ARGS__);     \
			} else if (level == LEVEL_ERROR) {                    \
				printf("ERROR:%llu:%s:%s():%d:[%lu][%s];" fmt,     \
				       get_now_ms(),                             \
				       filename_printf(__FILE__),                   \
				       __func__, __LINE__, pthread_self(),       \
				       bdf ? bdf : "unknown", ##__VA_ARGS__);     \
			}                             \
		}                             \
	} while (0)

#endif

#define LOG_BUG_ON(cond, fmt, ...)                             \
	do {                             \
		if ((cond)) {                             \
			DRV_RDMA_LOG_ERROR(fmt, ##__VA_ARGS__);     \
			LOG_SYNC();                             \
			BUG();                             \
		}                             \
	} while (0)

#define DEBUG_TRACE_MAGIC 0x456789
#define BUF_SIZE	  (1024LL << 10)

#define PAGE_ORDER	  2
#define PER_CPU_PAGE_SIZE (PAGE_SIZE * (1 << 2))

#define LOG_FILE_SIZE	 (200LL << 20)
#define BINARY_FILE_SIZE (200LL << 20)

#define VF_LOG_FILE_PATH      "/var/log/sxe2_drv_rdma_vf.log"
#define VF_LOG_FILE_PREFIX    "sxe2_drv_rdma_vf.log"
#define VF_BINARY_FILE_PATH   "/var/log/sxe2_drv_rdma_vf.bin"
#define VF_BINARY_FILE_PREFIX "sxe2_drv_rdma_vf.bin"

#define LOG_FILE_PATH	   "/var/log/sxe2_drv_rdma.log"
#define LOG_FILE_PREFIX	   "sxe2_drv_rdma.log"
#define BINARY_FILE_PATH   "/var/log/sxe2_drv_rdma.bin"
#define BINARY_FILE_PREFIX "sxe2_drv_rdma.bin"

#define DEBUG_DROP_LOG_STRING "\nwarnning:drop some logs\n\n"

extern u32 g_sxe2_rdma_dmesg_level;

enum { DEBUG_TYPE_STRING,
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

struct sxe2_log {
	struct {
		char *buf;
		int buf_size;
		long long head;
		long long tail;
		spinlock_t lock;
		unsigned char is_drop;
	};
	struct {
		char *file_path;
		struct file *file;
		long long file_pos;
		long long file_size;
		unsigned int file_num;
		unsigned int index;
	};
};

struct sxe2_thread_local {
	int magic;
	char data[];
};

struct sxe2_ctxt {
	struct page *page;
	void *buff;
};

struct sxe2_thread_key {
	int offset;
};

struct sxe2_debug {
	enum debug_level level;
	bool status;
	u16 key_offset;
	struct sxe2_ctxt __percpu *ctxt;
	struct list_head filter_func;
	struct list_head filter_file;
	struct task_struct *task;
	struct sxe2_log log[DEBUG_TYPE_NR];
};

void sxe2_level_set(int level);
int sxe2_level_get(void);

void sxe2_bin_status_set(bool status);
int sxe2_bin_status_get(void);

int sxe2_log_init(bool is_vf);
void sxe2_log_exit(void);

void sxe2_log_string(enum debug_level level, const char *dev_name, const char *bdf,
		     const char *file, const char *func, int line,
		     const char *fmt, ...);
#ifdef SXE2_CFG_DEBUG

void sxe2_log_binary(const char *file, const char *func, int line, u8 *ptr,
		     u64 addr, u32 size, char *str);

#define DATA_DUMP(ptr, size, str)                    \
	sxe2_log_binary(__FILE__, __func__, __LINE__, (u8 *)ptr, 0, size, \
			str)
#endif

void sxe2_log_sync(void);

#if (defined SXE2_CFG_DEBUG && defined __KERNEL__)
int time_for_file_name(char *buff, int buf_len);
int sxe2_file_write(struct file *file, char *buf, int len);
void sxe2_filter_func_clear(void);

#endif

#if defined SXE2_CFG_DEBUG && defined __KERNEL__

#define WRITE_LOG(level, devname, bdf, fmt, ...)                    \
	sxe2_log_string(level, devname, bdf, __FILE__, __func__, __LINE__, \
			fmt, ##__VA_ARGS__)

#define LOG_SYNC() sxe2_log_sync()

#define DRV_RDMA_LOG_DEBUG(fmt, ...)                              \
	WRITE_LOG(LEVEL_DEBUG, NULL, NULL, fmt, ##__VA_ARGS__)
#define DRV_RDMA_LOG_INFO(fmt, ...)                             \
	WRITE_LOG(LEVEL_INFO, NULL, NULL, fmt, ##__VA_ARGS__)
#define DRV_RDMA_LOG_WARN(fmt, ...)                             \
	WRITE_LOG(LEVEL_WARN, NULL, NULL, fmt, ##__VA_ARGS__)
#define DRV_RDMA_LOG_ERROR(fmt, ...)                             \
	WRITE_LOG(LEVEL_ERROR, NULL, NULL, fmt, ##__VA_ARGS__)

#define DRV_RDMA_LOG_DEBUG_BDF(fmt, ...)                             \
	WRITE_LOG(LEVEL_DEBUG, rdma_dev->ibdev.name, rdma_dev->bdf, fmt, \
		  ##__VA_ARGS__)
#define DRV_RDMA_LOG_INFO_BDF(fmt, ...)                             \
	WRITE_LOG(LEVEL_INFO, rdma_dev->ibdev.name, rdma_dev->bdf, fmt, \
		  ##__VA_ARGS__)
#define DRV_RDMA_LOG_WARN_BDF(fmt, ...)                             \
	WRITE_LOG(LEVEL_WARN, rdma_dev->ibdev.name, rdma_dev->bdf, fmt, \
		  ##__VA_ARGS__)
#define DRV_RDMA_LOG_ERROR_BDF(fmt, ...)                             \
	WRITE_LOG(LEVEL_ERROR, rdma_dev->ibdev.name, rdma_dev->bdf, fmt, \
		  ##__VA_ARGS__)

#define DRV_RDMA_LOG_DEV_DEBUG(format, arg...)                    \
	do {                             \
		if (!rdma_dev)                             \
			break;                             \
		if (g_sxe2_rdma_dmesg_level >= LOGLEVEL_DEBUG)             \
			dev_dbg(&rdma_dev->rdma_func->pcidev->dev, format,     \
				##arg);                             \
		DRV_RDMA_LOG_DEBUG_BDF(format, ##arg);                     \
	} while (0)

#define DRV_RDMA_LOG_DEV_INFO(format, arg...)                    \
	do {                    \
		if (!rdma_dev)                    \
			break;                    \
		if (g_sxe2_rdma_dmesg_level >= LOGLEVEL_INFO)              \
			dev_info(&rdma_dev->rdma_func->pcidev->dev, format,     \
				 ##arg);                    \
		DRV_RDMA_LOG_INFO_BDF(format, ##arg);                    \
	} while (0)

#define DRV_RDMA_LOG_DEV_WARN(format, arg...)                    \
	do {                    \
		if (!rdma_dev)                    \
			break;                    \
		if (g_sxe2_rdma_dmesg_level >= LOGLEVEL_WARNING)        \
			dev_warn(&rdma_dev->rdma_func->pcidev->dev, format,  \
				 ##arg);                    \
		DRV_RDMA_LOG_WARN_BDF(format, ##arg);                    \
	} while (0)

#define DRV_RDMA_LOG_DEV_ERR(format, arg...)                    \
	do {                    \
		if (!rdma_dev)                    \
			break;                    \
		if (g_sxe2_rdma_dmesg_level >= LOGLEVEL_ERR)              \
			dev_err(&rdma_dev->rdma_func->pcidev->dev, format,     \
				##arg);                    \
		DRV_RDMA_LOG_ERROR_BDF(format, ##arg);              \
	} while (0)

#define DRV_RDMA_LOG_PR_DEBUG(format, arg...)                    \
	pr_debug("sxe2_rdma: " format, ##arg)
#define DRV_RDMA_LOG_PR_INFO(format, arg...)                    \
	pr_info("sxe2_rdma: " format, ##arg)
#define DRV_RDMA_LOG_PR_WARN(format, arg...)                    \
	pr_warn("sxe2_rdma: " format, ##arg)
#define DRV_RDMA_LOG_PR_ERR(format, arg...) pr_err("sxe2_rdma: " format, ##arg)
#define DRV_RDMA_LOG_PRVF_DEBUG(format, arg...)                    \
	pr_debug("sxe2_rdmavf: " format, ##arg)
#define DRV_RDMA_LOG_PRVF_INFO(format, arg...)                    \
	pr_info("sxe2_rdmavf: " format, ##arg)
#define DRV_RDMA_LOG_PRVF_WARN(format, arg...)                    \
	pr_warn("sxe2_rdmavf: " format, ##arg)
#define DRV_RDMA_LOG_PRVF_ERR(format, arg...)                    \
	pr_err("sxe2_rdmavf: " format, ##arg)

#else

#if defined SXE2_CFG_RELEASE

#define UNUSED1(x)		((void)(x))

#define DRV_RDMA_LOG_DEBUG(fmt, ...) UNUSED1(fmt)
#define DRV_RDMA_LOG_INFO(fmt, ...) UNUSED1(fmt)
#define DRV_RDMA_LOG_WARN(fmt, ...) UNUSED1(fmt)
#define DRV_RDMA_LOG_ERROR(fmt, ...) UNUSED1(fmt)

#define UNUSED(x, y)      \
	do {            \
		(void)(x);    \
		(void)(y);   \
	} while (0)

#define DRV_RDMA_LOG_DEBUG_BDF(fmt, ...) UNUSED(fmt, rdma_dev)
#define DRV_RDMA_LOG_INFO_BDF(fmt, ...)	 UNUSED(fmt, rdma_dev)
#define DRV_RDMA_LOG_WARN_BDF(fmt, ...)	 UNUSED(fmt, rdma_dev)
#define DRV_RDMA_LOG_ERROR_BDF(fmt, ...) UNUSED(fmt, rdma_dev)

#define DRV_RDMA_LOG_DEV_DEBUG(format, arg...)                    \
	do {                    \
		if (!rdma_dev)                    \
			break;                    \
		if (g_sxe2_rdma_dmesg_level >= LOGLEVEL_DEBUG)             \
			dev_dbg(&rdma_dev->rdma_func->pcidev->dev, format,     \
				##arg);                    \
	} while (0)

#define DRV_RDMA_LOG_DEV_INFO(format, arg...)                    \
	do {                    \
		if (!rdma_dev)                    \
			break;                    \
		if (g_sxe2_rdma_dmesg_level >= LOGLEVEL_INFO)              \
			dev_info(&rdma_dev->rdma_func->pcidev->dev, format,     \
				 ##arg);                    \
	} while (0)

#define DRV_RDMA_LOG_DEV_WARN(format, arg...)                    \
	do {                    \
		if (!rdma_dev)                    \
			break;                    \
		if (g_sxe2_rdma_dmesg_level >= LOGLEVEL_WARNING)        \
			dev_warn(&rdma_dev->rdma_func->pcidev->dev, format,  \
				 ##arg);                    \
	} while (0)

#define DRV_RDMA_LOG_DEV_ERR(format, arg...)                    \
	do {                    \
		if (!rdma_dev)                    \
			break;                    \
		if (g_sxe2_rdma_dmesg_level >= LOGLEVEL_ERR)           \
			dev_err(&rdma_dev->rdma_func->pcidev->dev, format,  \
				##arg);                    \
	} while (0)

#define DRV_RDMA_LOG_PR_DEBUG(format, arg...)                    \
	pr_debug("sxe2_rdma: " format, ##arg)
#define DRV_RDMA_LOG_PR_INFO(format, arg...)                    \
	pr_info("sxe2_rdma: " format, ##arg)
#define DRV_RDMA_LOG_PR_WARN(format, arg...)                    \
	pr_warn("sxe2_rdma: " format, ##arg)
#define DRV_RDMA_LOG_PR_ERR(format, arg...) pr_err("sxe2_rdma: " format, ##arg)
#define DRV_RDMA_LOG_PRVF_DEBUG(format, arg...)                    \
	pr_debug("sxe2_rdmavf: " format, ##arg)
#define DRV_RDMA_LOG_PRVF_INFO(format, arg...)                    \
	pr_info("sxe2_rdmavf: " format, ##arg)
#define DRV_RDMA_LOG_PRVF_WARN(format, arg...)                    \
	pr_warn("sxe2_rdmavf: " format, ##arg)
#define DRV_RDMA_LOG_PRVF_ERR(format, arg...)                    \
	pr_err("sxe2_rdmavf: " format, ##arg)

#else

#define WRITE_LOG(level, devname, bdf, fmt, ...)                    \
	sxe2_log_string(level, devname, bdf ? bdf : "unknown", __FILE__, \
			__func__, __LINE__, fmt, ##__VA_ARGS__)

#define SXE2_DRV_TEST_LOG_PATH	     "./sxe2_drv_rdma_test.log"
#define LOG_NAME_LEN		     64
#define LOG_LEVEL(log_lvl, fmt, ...) sxe2_print(log_lvl, fmt, ##__VA_ARGS__)
#define LOG_SYNC()
#define LOG_DEBUG_DATA_DUMP(ptr, size, str)

static inline BOOL sxe2_fs_requires_dev(struct file *fp)
{
	(void)fp;
	return SHCA_TRUE;
}

void sxe2_set_log_loop_flag(bool flag);
void sxe2_set_log_loop_index(int index);
int sxe2_debug_init(void);
void sxe2_debug_exit(void);

#define DRV_RDMA_LOG_DEBUG(fmt, ...)                    \
	WRITE_LOG(LEVEL_DEBUG, NULL, NULL, fmt, ##__VA_ARGS__)
#define DRV_RDMA_LOG_INFO(fmt, ...)                    \
	WRITE_LOG(LEVEL_INFO, NULL, NULL, fmt, ##__VA_ARGS__)
#define DRV_RDMA_LOG_WARN(fmt, ...)                    \
	WRITE_LOG(LEVEL_WARN, NULL, NULL, fmt, ##__VA_ARGS__)
#define DRV_RDMA_LOG_ERROR(fmt, ...)                    \
	WRITE_LOG(LEVEL_ERROR, NULL, NULL, fmt, ##__VA_ARGS__)

#define DRV_RDMA_LOG_DEBUG_BDF(fmt, ...)                    \
	WRITE_LOG(LEVEL_DEBUG, rdma_dev->ibdev.name, rdma_dev->bdf, fmt, \
		  ##__VA_ARGS__)
#define DRV_RDMA_LOG_INFO_BDF(fmt, ...)                    \
	WRITE_LOG(LEVEL_INFO, rdma_dev->ibdev.name, rdma_dev->bdf, fmt, \
		  ##__VA_ARGS__)
#define DRV_RDMA_LOG_WARN_BDF(fmt, ...)                    \
	WRITE_LOG(LEVEL_WARN, rdma_dev->ibdev.name, rdma_dev->bdf, fmt, \
		  ##__VA_ARGS__)
#define DRV_RDMA_LOG_ERROR_BDF(fmt, ...)                    \
	WRITE_LOG(LEVEL_ERROR, rdma_dev->ibdev.name, rdma_dev->bdf, fmt, \
		  ##__VA_ARGS__)

#define DRV_RDMA_LOG_DEV_DEBUG(format, arg...)                    \
	DRV_RDMA_LOG_DEBUG_BDF(format, ##arg)
#define DRV_RDMA_LOG_DEV_INFO(format, arg...)                    \
	DRV_RDMA_LOG_INFO_BDF(format, ##arg)
#define DRV_RDMA_LOG_DEV_WARN(format, arg...)                    \
	DRV_RDMA_LOG_WARN_BDF(format, ##arg)
#define DRV_RDMA_LOG_DEV_ERR(format, arg...)                    \
	DRV_RDMA_LOG_ERROR_BDF(format, ##arg)

#define DRV_RDMA_LOG_PR_DEBUG(format, arg...)                    \
	pr_debug("sxe2_rdma: " format, ##arg)
#define DRV_RDMA_LOG_PR_INFO(format, arg...)                    \
	pr_info("sxe2_rdma: " format, ##arg)
#define DRV_RDMA_LOG_PR_WARN(format, arg...)                    \
	pr_warn("sxe2_rdma: " format, ##arg)
#define DRV_RDMA_LOG_PR_ERR(format, arg...) pr_err("sxe2_rdma: " format, ##arg)
#endif

#define LOG_SYNC()

#endif

#if defined SXE2_CFG_RELEASE
#define SXE2_BUG_ON(cond)                                 \
	do {                                 \
		if ((cond)) {                                 \
			pr_err(                                 \
			       "BUG_ON's condition(%s) has been triggered\n", \
			       #cond);                                 \
			LOG_ERROR(                                 \
				"BUG_ON's condition(%s) has been triggered\n", \
				#cond);                                 \
		}                                 \
	} while (0)

#define SXE2_BUG()
#define SXE2_BUG_ON_NO_SYNC(cond)                                 \
	do {                                                          \
		if ((cond)) {                                            \
			pr_err(                                               \
			       "BUG_ON's condition(%s) has been triggered\n",  \
			       #cond);                                        \
			LOG_ERROR(                                          \
				"BUG_ON's condition(%s) has been triggered\n",  \
				#cond);                                         \
		}                                                       \
	} while (0)

#define SXE2_BUG_NO_SYNC()
#else
#define SXE2_BUG_ON(cond)                                        \
	do {                                                         \
		if ((cond)) {                                            \
			pr_err(                                              \
			       "BUG_ON's condition(%s) has been triggered\n", \
			       #cond);                                        \
			LOG_ERROR(                                            \
				"BUG_ON's condition(%s) has been triggered\n",    \
				#cond);                                           \
			LOG_SYNC();                                           \
		}                                                         \
		BUG_ON(cond);                                            \
	} while (0)

#define SXE2_BUG(void)     \
	do {                   \
		LOG_SYNC();        \
		BUG(void);         \
	} while (0)

#define SXE2_BUG_ON_NO_SYNC(cond)                               \
	do {                                                         \
		if ((cond)) {                                            \
			pr_err(                                              \
			       "BUG_ON's condition(%s) has been triggered\n", \
			       #cond);                                        \
			LOG_ERROR(                                            \
				"BUG_ON's condition(%s) has been triggered\n",    \
				#cond);                                           \
		}                                                         \
		BUG_ON(cond);                                             \
	} while (0)

#define SXE2_BUG_NO_SYNC(void)		BUG(void)

#endif

#ifdef __cplusplus
}
#endif
#endif
