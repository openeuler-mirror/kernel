/* SPDX-License-Identifier: GPL-2.0 */
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2_log.h
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#ifndef _SXE2_LOG_H_
#define _SXE2_LOG_H_

#ifdef SXE2_TEST
#define STATIC
#define pr_err printf
#else
#define STATIC static
#endif

#ifdef __cplusplus
extern "C"{
#endif

#define SXE2_HOST(ins) ((ins)->host->host_no)

#define LOG_INFO_PREFIX_LEN	32
#define LOG_ERROR_PREFIX_LEN	33
#define MEGABYTE		20

enum debug_level_e {
	LEVEL_ERROR,
	LEVEL_WARN,
	LEVEL_INFO,
	LEVEL_DEBUG,
};

static inline const char *sxe2_debug_level_name(enum debug_level_e lv)
{
	static const char * const level[] = {
		[LEVEL_ERROR] = "ERROR",
		[LEVEL_WARN]  = "WARN",
		[LEVEL_INFO]  = "INFO",
		[LEVEL_DEBUG] = "DEBUG",
	};

	return level[lv];
}

#ifdef __KERNEL__

#define PRINT_DEBUG LEVEL_DEBUG
#define PRINT_INFO  LEVEL_INFO
#define PRINT_WARN  LEVEL_WARN
#define PRINT_ERR   LEVEL_ERROR

#define sxe2_print(level, bdf, type, ...) do { \
	typeof(level) _level = (level); \
	char *_bdf = (bdf); \
	if (_level == LEVEL_DEBUG) { \
		pr_debug("[SXE2]%s():%d %s:" type, __func__, \
			__LINE__, _bdf ? _bdf : "", ##__VA_ARGS__); \
	} else if (_level == LEVEL_INFO) { \
		pr_info("[SXE2]%s():%d %s:" type, __func__, \
			__LINE__, _bdf ? _bdf : "", ##__VA_ARGS__); \
	} else if (_level == LEVEL_WARN) { \
		pr_warn("[SXE2]%s():%d %s:" type, __func__, \
			__LINE__, _bdf ? _bdf : "", ##__VA_ARGS__); \
	} else if (_level == LEVEL_ERROR) { \
		pr_err("[SXE2]%s():%d %s:" type, __func__, \
			__LINE__, _bdf ? _bdf : "", ##__VA_ARGS__); \
	} \
} while (0)

#else

#define PRINT_DEBUG    LEVEL_DEBUG
#define PRINT_INFO     LEVEL_INFO
#define PRINT_WARN     LEVEL_WARN
#define PRINT_ERR      LEVEL_ERROR

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

static inline const char *filename_printf(const char *x)
{
	return strrchr((x), '/') ? strrchr((x), '/') + 1 : (x);
}

#define sxe2_print(level, bdf, type, ...) do { \
	typeof(level) _level = (level); \
	char *_bdf = (bdf); \
	if (_level <= sxe2_level_get()) { \
		if (_level == LEVEL_DEBUG) { \
			(void)printf("DEBUG:%llu:%s:%s():%d:[%lu][%s];" type, get_now_ms(), \
				     filename_printf(__FILE__), \
				     __func__, __LINE__, pthread_self(), \
				     _bdf ? _bdf : "", ##__VA_ARGS__); \
		} else if (_level == LEVEL_INFO) { \
			(void)printf("INFO:%llu:%s:%s():%d:[%lu][%s];" type, get_now_ms(), \
				     filename_printf(__FILE__), \
				     __func__, __LINE__, pthread_self(), \
				     _bdf ? _bdf : "",  ##__VA_ARGS__); \
		} else if (_level == LEVEL_WARN) { \
			(void)printf("WARN:%llu:%s:%s():%d:[%lu][%s];" type, get_now_ms(), \
				     filename_printf(__FILE__), \
				     __func__, __LINE__, pthread_self(), \
				_bdf ? _bdf : "",  ##__VA_ARGS__); \
		} else if (_level == LEVEL_ERROR) { \
			(void)printf("ERROR:%llu:%s:%s():%d:[%lu][%s];" type, get_now_ms(), \
				     filename_printf(__FILE__), \
				     __func__, __LINE__, pthread_self(), \
				     _bdf ? _bdf : "",  ##__VA_ARGS__); \
		} \
	} \
} while (0)

#endif

#define LOG_BUG_ON(cond, fmt, ...) do { \
	if ((cond)) { \
		LOG_ERROR(fmt, ##__VA_ARGS__); \
		LOG_SYNC();							\
		BUG();								\
	}									\
} while (0)

#define DEBUG_TRACE_MAGIC 0x456789
#define BUF_SIZE		 (1024LL << 10)

#define PAGE_ORDER   2
#define PER_CPU_PAGE_SIZE  (PAGE_SIZE * (1 << 2))

#define LOG_FILE_SIZE	 (200LL << 20)
#define BINARY_FILE_SIZE (200LL << 20)

#define VF_LOG_FILE_PATH	 "/var/log/sxe2vf.log"
#define VF_LOG_FILE_PREFIX       "sxe2vf.log"
#define VF_BINARY_FILE_PATH      "/var/log/sxe2vf.bin"
#define VF_BINARY_FILE_PREFIX    "sxe2vf.bin"

#define LOG_FILE_PATH	         "/var/log/sxe2.log"
#define LOG_FILE_PREFIX          "sxe2.log"
#define BINARY_FILE_PATH         "/var/log/sxe2.bin"
#define BINARY_FILE_PREFIX       "sxe2.bin"

#define DEBUG_DROP_LOG_STRING "\nwarnning:drop some logs\n\n"

enum {
	DEBUG_TYPE_STRING,
	DEBUG_TYPE_BINARY,
	DEBUG_TYPE_NR,
};

struct debug_func_t {
	struct list_head list;
	char name[64];
};

struct debug_file_t {
	struct list_head list;
	char name[64];
};

struct sxe2_log_t {
	struct {
		char		*buf;
		int		buf_size;
		long long  head;
		long long  tail;
		/* in order to protect the data */
		spinlock_t lock;
		unsigned char	   is_drop;
	};
	struct {
		char		*file_path;
		struct file	*file;
		long long	file_pos;
		long long	file_size;
		unsigned int	file_num;
		unsigned int	index;
	};
};

struct sxe2_thread_local_t {
	s32  magic;
	char data[];
};

struct sxe2_ctxt_t {
	struct page *page;
	void *buff;
	unsigned int len;
};

struct sxe2_thread_key_t {
	s32  offset;
};

struct sxe2_debug_t {
	enum debug_level_e	level;
	bool status;
	u16					key_offset;
	struct sxe2_ctxt_t __percpu *ctxt;
	struct list_head		filter_func;
	struct list_head		filter_file;
	struct task_struct  *task;
	struct sxe2_log_t			log[DEBUG_TYPE_NR];
};

void sxe2_level_set(int level);
s32 sxe2_level_get(void);

void sxe2_bin_status_set(bool status);
s32 sxe2_bin_status_get(void);

int  sxe2_log_init(bool is_vf);
void sxe2_log_exit(void);

void sxe2_log_string(enum debug_level_e level,
		     const char *dev_name, const char *file, const char *func,
		     int line, const char *fmt, ...);

void sxe2_log_binary(const char *file, const char *func, int line, u8 *ptr,
		     u64 addr, u32 size, char *str);

#ifndef SXE2_CFG_RELEASE
#define DATA_DUMP(ptr, size, str) \
	sxe2_log_binary(__FILE__, __func__, __LINE__, (u8 *)ptr, 0, size, str)
#else
#define DATA_DUMP(ptr, size, str)
#endif
void sxe2_log_sync(void);

void sxe2_thread_key_create(int size, struct sxe2_thread_key_t *key);

void *sxe2_thread_get_specific(struct sxe2_thread_key_t *key);

void sxe2_thread_clear_specific(struct sxe2_thread_key_t *key);

int sxe2_filter_file_add(char *name);

void sxe2_filter_file_del(char *filename);

void sxe2_log_level_modify(u32 level);

void sxe2_filter_file_clear(void);

int sxe2_filter_func_add(char *name);

void sxe2_filter_func_del(char *name);

void sxe2_filter_func_clear(void);

#ifdef SXE2_DRIVER_TRACE
int time_for_file_name(char *buff, int buf_len);
int sxe2_file_write(struct file *file, char *buf, int len);
#endif

#if defined __KERNEL__
extern u32 g_sxe2_dmesg_level;

#if defined SXE2_CFG_DEBUG
int time_for_file_name(char *buff, int buf_len);
int sxe2_file_write(struct file *file, char *buf, int len);

#define WRITE_LOG(level, bdf, fmt, ...) \
	sxe2_log_string(level, bdf, __FILE__, __func__, __LINE__, fmt, ##__VA_ARGS__)
#define LOG_SYNC()			sxe2_log_sync()
#define LOG_DEBUG_BDF(fmt, ...) WRITE_LOG(LEVEL_DEBUG, adapter->dev_name, fmt, ##__VA_ARGS__)
#define LOG_INFO_BDF(fmt, ...)	WRITE_LOG(LEVEL_INFO, adapter->dev_name,  fmt, ##__VA_ARGS__)
#define LOG_WARN_BDF(fmt, ...)	WRITE_LOG(LEVEL_WARN, adapter->dev_name,  fmt, ##__VA_ARGS__)
#define LOG_ERROR_BDF(fmt, ...) WRITE_LOG(LEVEL_ERROR, adapter->dev_name, fmt, ##__VA_ARGS__)
#else
#define UNUSED(x) ((void)(x))
#define WRITE_LOG(level, bdf, fmt, ...) do {\
	UNUSED(level); \
	UNUSED(bdf); \
	UNUSED(fmt); \
} while (0)
#define LOG_SYNC()
#define LOG_DEBUG_BDF(fmt, ...) do {\
	UNUSED(adapter); \
	UNUSED(fmt); \
} while (0)

#define LOG_INFO_BDF(fmt, ...) do {\
	UNUSED(adapter); \
	UNUSED(fmt); \
} while (0)
#define LOG_WARN_BDF(fmt, ...) do {\
	UNUSED(adapter); \
	UNUSED(fmt); \
} while (0)
#define LOG_ERROR_BDF(fmt, ...) do {\
	UNUSED(adapter); \
	UNUSED(fmt); \
} while (0)
#endif

#define FL_PR_DEBUG(fmt, ...) do {\
	if (g_sxe2_dmesg_level >= LOGLEVEL_DEBUG) {\
		pr_debug(fmt, ##__VA_ARGS__); } \
} while (0)
#define FL_PR_INFO(fmt, ...) do {\
	if (g_sxe2_dmesg_level >= LOGLEVEL_INFO) {\
		pr_info(fmt, ##__VA_ARGS__); } \
} while (0)
#define FL_PR_WARN(fmt, ...)  do {\
	if (g_sxe2_dmesg_level >= LOGLEVEL_WARNING) {\
		pr_warn(fmt, ##__VA_ARGS__); } \
} while (0)
#define FL_PR_ERR(fmt, ...)  do {\
	if (g_sxe2_dmesg_level >= LOGLEVEL_ERR) {\
		pr_err(fmt, ##__VA_ARGS__); } \
} while (0)

#define FL_DEV_DBG(dev, fmt, ...) do {\
	if (g_sxe2_dmesg_level >= LOGLEVEL_DEBUG) {\
		dev_dbg(dev, fmt, ##__VA_ARGS__); } \
} while (0)
#define FL_DEV_INFO(dev, fmt, ...) do {\
	if (g_sxe2_dmesg_level >= LOGLEVEL_INFO) {\
		dev_info(dev, fmt, ##__VA_ARGS__); } \
} while (0)
#define FL_DEV_WARN(dev, fmt, ...)  do {\
	if (g_sxe2_dmesg_level >= LOGLEVEL_WARNING) {\
		dev_warn(dev, fmt, ##__VA_ARGS__); } \
} while (0)
#define FL_DEV_ERR(dev, fmt, ...)  do {\
	if (g_sxe2_dmesg_level >= LOGLEVEL_ERR) {\
		dev_err(dev, fmt, ##__VA_ARGS__); } \
} while (0)

#define FL_NETDEV_DBG(netdev, fmt, ...)  do {\
	if (g_sxe2_dmesg_level >= LOGLEVEL_DEBUG) {\
		netdev_dbg(netdev, fmt, ##__VA_ARGS__); } \
} while (0)
#define FL_NETDEV_INFO(netdev, fmt, ...)  do {\
	if (g_sxe2_dmesg_level >= LOGLEVEL_INFO) {\
		netdev_info(netdev, fmt, ##__VA_ARGS__); } \
} while (0)
#define FL_NETDEV_WARN(netdev, fmt, ...)  do {\
	if (g_sxe2_dmesg_level >= LOGLEVEL_WARNING) {\
		netdev_warn(netdev, fmt, ##__VA_ARGS__); } \
} while (0)
#define FL_NETDEV_ERR(netdev, fmt, ...)  do {\
	if (g_sxe2_dmesg_level >= LOGLEVEL_ERR) {\
		netdev_err(netdev, fmt, ##__VA_ARGS__); } \
} while (0)

#define LOG_DEBUG(fmt, ...) \
	WRITE_LOG(LEVEL_DEBUG, NULL, fmt, ##__VA_ARGS__)

#define LOG_INFO(fmt, ...) \
	WRITE_LOG(LEVEL_INFO, NULL,  fmt, ##__VA_ARGS__)

#define LOG_WARN(fmt, ...) \
	WRITE_LOG(LEVEL_WARN, NULL,  fmt, ##__VA_ARGS__)

#define LOG_ERROR(fmt, ...) \
	WRITE_LOG(LEVEL_ERROR, NULL, fmt, ##__VA_ARGS__)

#define LOG_DEBUG_IRQ(fmt, ...) \
	WRITE_LOG(LEVEL_DEBUG, NULL, fmt, ##__VA_ARGS__)
#define LOG_INFO_IRQ(fmt, ...) \
	WRITE_LOG(LEVEL_INFO, NULL,  fmt, ##__VA_ARGS__)

#define LOG_WARN_IRQ(fmt, ...) \
	WRITE_LOG(LEVEL_WARN, NULL,  fmt, ##__VA_ARGS__)

#define LOG_ERROR_IRQ(fmt, ...) \
	WRITE_LOG(LEVEL_ERROR, NULL, fmt, ##__VA_ARGS__)

#define LOG_DEBUG_D(type, ...) do {\
	WRITE_LOG(LEVEL_DEBUG, NULL, type, ##__VA_ARGS__);\
	FL_PR_DEBUG(type, ##__VA_ARGS__);\
} while (0)
#define LOG_INFO_D(type, ...)	do {\
	WRITE_LOG(LEVEL_INFO, NULL, type, ##__VA_ARGS__);\
	FL_PR_INFO(type, ##__VA_ARGS__);\
} while (0)
#define LOG_WARN_D(type, ...)	do {\
	WRITE_LOG(LEVEL_WARN, NULL, type, ##__VA_ARGS__);\
	FL_PR_WARN(type, ##__VA_ARGS__);\
} while (0)
#define LOG_ERROR_D(type, ...) do {\
	WRITE_LOG(LEVEL_ERROR, NULL, type, ##__VA_ARGS__);\
	FL_PR_ERR(type, ##__VA_ARGS__);\
} while (0)

#define LOG_DEV_DEBUG(type, arg...) do {\
	FL_DEV_DBG(&adapter->pdev->dev, type, ## arg); \
	LOG_DEBUG_BDF(type, ## arg); \
} while (0)

#define LOG_DEV_INFO(type, arg...) do {\
	FL_DEV_INFO(&adapter->pdev->dev, type, ## arg); \
	LOG_INFO_BDF(type, ## arg); \
} while (0)

#define LOG_DEV_WARN(type, arg...) do {\
	FL_DEV_WARN(&adapter->pdev->dev, type, ## arg); \
	LOG_WARN_BDF(type, ## arg); \
} while (0)

#define LOG_DEV_ERR(type, arg...) do {\
	FL_DEV_ERR(&adapter->pdev->dev, type, ## arg); \
	LOG_ERROR_BDF(type, ## arg); \
} while (0)

#define LOG_MSG_DEBUG(msglvl, type, arg...) do {\
	netif_dbg(adapter, msglvl, adapter->netdev, type, ## arg); \
	LOG_DEBUG_BDF(type, ## arg); \
} while (0)

#define LOG_MSG_INFO(msglvl, type, arg...) do {\
	netif_info(adapter, msglvl, adapter->netdev, type, ## arg); \
	LOG_INFO_BDF(type, ## arg); \
} while (0)

#define LOG_MSG_WARN(msglvl, type, arg...) do {\
	netif_warn(adapter, msglvl, adapter->netdev, type, ## arg); \
	LOG_WARN_BDF(type, ## arg); \
} while (0)

#define LOG_MSG_ERR(msglvl, type, arg...) do {\
	netif_err(adapter, msglvl, adapter->netdev, type, ## arg); \
	LOG_ERROR_BDF(type, ## arg); \
} while (0)

#define LOG_PR_DEBUG(format, arg...)    FL_PR_DEBUG("sxe2: " format, ## arg)
#define LOG_PR_INFO(format, arg...)     FL_PR_INFO("sxe2: " format, ## arg)
#define LOG_PR_WARN(format, arg...)     FL_PR_WARN("sxe2: " format, ## arg)
#define LOG_PR_ERR(format, arg...)      FL_PR_ERR("sxe2: " format, ## arg)
#define LOG_PRVF_DEBUG(format, arg...)  FL_PR_DEBUG("sxe2vf: " format, ## arg)
#define LOG_PRVF_INFO(format, arg...)   FL_PR_INFO("sxe2vf: " format, ## arg)
#define LOG_PRVF_WARN(format, arg...)   FL_PR_WARN("sxe2vf: " format, ## arg)
#define LOG_PRVF_ERR(format, arg...)    FL_PR_ERR("sxe2vf: " format, ## arg)

#define LOG_NETDEV_DEBUG(type, arg...) do {\
	FL_NETDEV_DBG(netdev, type, ## arg); \
	LOG_DEBUG_BDF(type, ## arg); \
	(void)netdev; \
} while (0)

#define LOG_NETDEV_INFO(type, arg...) do {\
	FL_NETDEV_INFO(netdev, type, ## arg); \
	LOG_INFO_BDF(type, ## arg); \
	(void)netdev; \
} while (0)

#define LOG_NETDEV_WARN(type, arg...) do {\
	FL_NETDEV_WARN(netdev, type, ## arg); \
	LOG_WARN_BDF(type, ## arg); \
	(void)netdev; \
} while (0)

#define LOG_NETDEV_ERR(type, arg...) do {\
	FL_NETDEV_ERR(netdev, type, ## arg); \
	LOG_ERROR_BDF(type, ## arg); \
	(void)netdev; \
} while (0)

#else

#define LOG_DEBUG(fmt, ...)       sxe2_print(PRINT_DEBUG,  "",  fmt, ##__VA_ARGS__)
#define LOG_INFO(fmt, ...)	  sxe2_print(PRINT_INFO,	  "", fmt, ##__VA_ARGS__)
#define LOG_WARN(fmt, ...)	  sxe2_print(PRINT_WARN, "", fmt, ##__VA_ARGS__)
#define LOG_ERROR(fmt, ...)	  sxe2_print(PRINT_ERR,	"",   fmt, ##__VA_ARGS__)

#define LOG_DEBUG_IRQ(fmt, ...)   sxe2_print(PRINT_DEBUG,  "",  fmt, ##__VA_ARGS__)
#define LOG_INFO_IRQ(fmt, ...)	  sxe2_print(PRINT_INFO,	  "", fmt, ##__VA_ARGS__)
#define LOG_WARN_IRQ(fmt, ...)	  sxe2_print(PRINT_WARN, "", fmt, ##__VA_ARGS__)
#define LOG_ERROR_IRQ(fmt, ...)	  sxe2_print(PRINT_ERR,	"",   fmt, ##__VA_ARGS__)

#define LOG_DEBUG_BDF(fmt, ...)   sxe2_print(LEVEL_DEBUG, adapter->dev_name, fmt, ##__VA_ARGS__)
#define LOG_INFO_BDF(fmt, ...)	  sxe2_print(LEVEL_INFO, adapter->dev_name,  fmt, ##__VA_ARGS__)
#define LOG_WARN_BDF(fmt, ...)	  sxe2_print(LEVEL_WARN, adapter->dev_name,  fmt, ##__VA_ARGS__)
#define LOG_ERROR_BDF(fmt, ...)   sxe2_print(LEVEL_ERROR, adapter->dev_name, fmt, ##__VA_ARGS__)

#define LOG_DEV_DEBUG(fmt, ...) \
	sxe2_print(LEVEL_DEBUG, adapter->dev_name, fmt, ##__VA_ARGS__)
#define LOG_DEV_INFO(fmt, ...) \
	sxe2_print(LEVEL_INFO, adapter->dev_name,  fmt, ##__VA_ARGS__)
#define LOG_DEV_WARN(fmt, ...) \
	sxe2_print(LEVEL_WARN, adapter->dev_name,  fmt, ##__VA_ARGS__)
#define LOG_DEV_ERR(fmt, ...) \
	sxe2_print(LEVEL_ERROR, adapter->dev_name, fmt, ##__VA_ARGS__)

#define LOG_MSG_DEBUG(msglvl, fmt, ...) do {\
	sxe2_print(LEVEL_DEBUG, adapter->dev_name, fmt, ##__VA_ARGS__); \
	(void)msglvl; \
} while (0)
#define LOG_MSG_INFO(msglvl, fmt, ...) do {\
	sxe2_print(LEVEL_INFO, adapter->dev_name, fmt, ##__VA_ARGS__); \
	(void)msglvl; \
} while (0)
#define LOG_MSG_WARN(msglvl, fmt, ...) do {\
	sxe2_print(LEVEL_WARN, adapter->dev_name, fmt, ##__VA_ARGS__); \
	(void)msglvl; \
} while (0)
#define LOG_MSG_ERR(msglvl, fmt, ...) do {\
	sxe2_print(LEVEL_ERROR, adapter->dev_name, fmt, ##__VA_ARGS__); \
		(void)msglvl; \
} while (0)

#define LOG_NETDEV_DEBUG(fmt, ...) do {\
	sxe2_print(LEVEL_DEBUG, adapter->dev_name, fmt, ##__VA_ARGS__); \
	(void)netdev; \
} while (0)

#define LOG_NETDEV_INFO(fmt, ...) do {\
	sxe2_print(LEVEL_INFO, adapter->dev_name,  fmt, ##__VA_ARGS__); \
	(void)netdev; \
} while (0)

#define LOG_NETDEV_WARN(fmt, ...) do {\
	sxe2_print(LEVEL_WARN, adapter->dev_name,  fmt, ##__VA_ARGS__); \
	(void)netdev; \
} while (0)

#define LOG_NETDEV_ERR(fmt, ...) do {\
	sxe2_print(LEVEL_ERROR, adapter->dev_name, fmt, ##__VA_ARGS__); \
	(void)netdev; \
} while (0)

#define LOG_DEBUG_D(fmt, ...) UNUSED(fmt)
#define LOG_INFO_D(fmt, ...) UNUSED(fmt)
#define LOG_WARN_D(fmt, ...) UNUSED(fmt)
#define LOG_ERROR_D(fmt, ...) UNUSED(fmt)

#define LOG_PR_DEBUG(fmt, ...) \
	sxe2_print(PRINT_DEBUG,	"sxe2",  fmt, ##__VA_ARGS__)

#define LOG_PR_INFO(fmt, ...) \
	sxe2_print(PRINT_INFO,	"sxe2",  fmt, ##__VA_ARGS__)

#define LOG_PR_WARN(fmt, ...) \
	sxe2_print(PRINT_WARN,	"sxe2",  fmt, ##__VA_ARGS__)

#define LOG_PR_ERR(fmt, ...) \
	sxe2_print(PRINT_ERR,	"sxe2",  fmt, ##__VA_ARGS__)
#define LOG_PRVF_DEBUG(fmt, ...) \
	sxe2_print(PRINT_DEBUG,	"sxe2vf",	fmt, ##__VA_ARGS__)

#define LOG_PRVF_INFO(fmt, ...) \
	sxe2_print(PRINT_INFO,	"sxe2vf",	fmt, ##__VA_ARGS__)

#define LOG_PRVF_WARN(fmt, ...) \
	sxe2_print(PRINT_WARN,	"sxe2vf",	fmt, ##__VA_ARGS__)

#define LOG_PRVF_ERR(fmt, ...) \
	sxe2_print(PRINT_ERR,	"sxe2vf",	fmt, ##__VA_ARGS__)

#define LOG_SYNC()

#endif

#if defined SXE2_CFG_RELEASE
#define SXE2_BUG_ON(type) \
do { \
	if ((type)) { \
		pr_err("BUG_ON's condition(%s) has been triggered\n", #type); \
		LOG_ERROR("BUG_ON's condition(%s) has been triggered\n", #type); \
	}									\
} while (0)

#define SXE2_BUG() {pr_err("trigger bug on test.\n"); }
#define SXE2_BUG_ON_NO_SYNC(type) \
do {	\
	if ((type)) { \
		pr_err("BUG_ON's condition(%s) has been triggered\n", #type); \
		LOG_ERROR("BUG_ON's condition(%s) has been triggered\n", #type); \
	}									\
} while (0)

#define SXE2_BUG_NO_SYNC()
#else
#define SXE2_BUG_ON(type) \
do { \
	if ((type)) { \
		pr_err("BUG_ON's condition(%s) has been triggered\n", #type); \
		LOG_ERROR("BUG_ON's condition(%s) has been triggered\n", #type); \
		LOG_SYNC();							\
	}									\
	BUG_ON(type);							\
} while (0)

#define SXE2_BUG() do {	\
	LOG_SYNC();		\
	BUG();		\
} while (0)

#define SXE2_BUG_ON_NO_SYNC(type) \
do {	\
	if ((type)) { \
		pr_err("BUG_ON's condition(%s) has been triggered\n", #type); \
		LOG_ERROR("BUG_ON's condition(%s) has been triggered\n", #type); \
	}									\
	BUG_ON(type);								\
} while (0)

#define SXE2_BUG_NO_SYNC(void)	\
	BUG(void)

#endif

#ifdef __cplusplus
}
#endif
#endif

