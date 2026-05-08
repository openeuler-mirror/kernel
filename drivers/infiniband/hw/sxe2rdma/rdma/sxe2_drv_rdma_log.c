// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (C), 2020, sxe2rdma Technologies Co., Ltd.
 *
 * @file: sxe2_drv_rdma_log.c
 * @author: sxe2rdma
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#include <linux/moduleparam.h>
#include <linux/kthread.h>
#include <linux/pagemap.h>
#include <linux/fsnotify.h>
#include <linux/rtc.h>
#include <linux/vmalloc.h>
#include <linux/kernel.h>

#include "sxe2_drv_rdma_log.h"

#if (defined SXE2_CFG_DEBUG && defined __KERNEL__)

int time_for_file_name(char *buff, int buf_len)
{
	struct timespec64 tv;
	struct tm td;

	ktime_get_real_ts64(&tv);
	time64_to_tm(tv.tv_sec, -sys_tz.tz_minuteswest * 60, &td);

	return snprintf(buff, buf_len, "%04ld-%02d-%02d_%02d:%02d:%02d",
			td.tm_year + 1900, td.tm_mon + 1, td.tm_mday,
			td.tm_hour, td.tm_min, td.tm_sec);
}

int sxe2_file_write(struct file *file, char *buf, int len)
{
	int ret = 0;

	void *journal;

	journal		      = current->journal_info;
	current->journal_info = NULL;

	if (!file)
		return 0;

	do {
		ret = kernel_write(file, buf, len, &file->f_pos);
	} while (ret == -EINTR);

	if (ret >= 0)
		fsnotify_modify(file);

	current->journal_info = journal;

	return ret;
}
#endif

u32 g_sxe2_rdma_dmesg_level = LOGLEVEL_WARNING;

#if defined SXE2_CFG_DEBUG && defined __KERNEL__

#define FILE_NAME_SIZE	   128
#define SXE2_KLOG_OUT_WAIT (5 * HZ)
#define SWITCH_FILE
#define LOG_PATH_LEN		 100
#define DRV_LOG_FILE_SIZE_MIN_MB 10
#define DRV_LOG_FILE_SIZE_MAX_MB 200

struct sxe2_debug g_sxe2_debug_rdma;
char g_log_path_str_rdma[LOG_PATH_LEN] = { 0 };
char g_log_path_bin_rdma[LOG_PATH_LEN] = { 0 };

static char g_log_path_rdma[80] = { 0 };
static u32 g_log_space_size_rdma;
static u32 g_log_file_size_rdma;

#ifdef SXE2_CFG_DEBUG
module_param_string(g_log_path_rdma, g_log_path_rdma, 80, 0644);
MODULE_PARM_DESC(
	g_log_path_rdma,
	"the path host driver will be saved(<80 chars) Default: /var/log");

module_param(g_log_file_size_rdma, uint, 0644);
MODULE_PARM_DESC(
	g_log_file_size_rdma,
	"single driver log file size(10MB ~ 200MB), Default: 200, Unit: MB");

module_param(g_log_space_size_rdma, uint, 0644);
MODULE_PARM_DESC(g_log_space_size_rdma,
	 "the space allowed host driver log to be store, Default: 0(unlimited), Unit: MB");
#endif

static inline int time_for_log(char *buff, int buf_len)
{
	struct timespec64 tv;
	struct tm td;

	ktime_get_real_ts64(&tv);
	time64_to_tm(tv.tv_sec, -sys_tz.tz_minuteswest * 60, &td);
	return snprintf(buff, buf_len, "[%04ld-%02d-%02d;%02d:%02d:%02d.%ld]",
			td.tm_year + 1900, td.tm_mon + 1, td.tm_mday,
			td.tm_hour, td.tm_min, td.tm_sec, tv.tv_nsec * 1000);
}

static inline char *sxe2_stack_top(void)
{
	unsigned long *ptr = (unsigned long *)(task_thread_info(current) + 1);

	return (char *)(ptr + 1);
}

static inline struct sxe2_thread_local *sxe2_thread_local_get(struct sxe2_thread_key *key)
{
	return (struct sxe2_thread_local *)(sxe2_stack_top() + key->offset);
}

static __maybe_unused void sxe2_thread_key_create(int size,
						  struct sxe2_thread_key *key)
{
	key->offset = g_sxe2_debug_rdma.key_offset;
	g_sxe2_debug_rdma.key_offset += sizeof(struct sxe2_thread_local) + size;
}

static __maybe_unused void *sxe2_thread_get_specific(struct sxe2_thread_key *key)
{
	struct sxe2_thread_local *local = sxe2_thread_local_get(key);

	if (local->magic != DEBUG_TRACE_MAGIC)
		return NULL;

	return (void *)local->data;
}

static __maybe_unused void sxe2_thread_clear_specific(struct sxe2_thread_key *key)
{
	struct sxe2_thread_local *local = sxe2_thread_local_get(key);

	local->magic		   = 0;
}

static __maybe_unused int sxe2_filter_file_add(char *name)
{
	struct debug_file *file = NULL;

	file = kmalloc(sizeof(struct debug_file), GFP_ATOMIC);
	if (!file) {
		sxe2_print(KERN_ERR, NULL, "kmalloc size %lu failed\n",
			   PAGE_SIZE);
		return -ENOMEM;
	}
	strscpy(file->name, name, sizeof(file->name));
	INIT_LIST_HEAD(&file->list);

	list_add_rcu(&file->list, &g_sxe2_debug_rdma.filter_file);
	return 0;
}

static __maybe_unused void sxe2_filter_file_del(char *filename)
{
	struct debug_file *file = NULL;

	list_for_each_entry_rcu(file, &g_sxe2_debug_rdma.filter_file, list) {
		if (!strcmp(file->name, filename)) {
			list_del_rcu(&file->list);
			synchronize_rcu();
			kfree(file);
			return;
		}
	}
}

static __maybe_unused void sxe2_log_level_modify(u32 level)
{
	sxe2_level_set(level);
}

static char *sxe2_log_path_query(void)
{
#ifndef __cplusplus
	return g_log_path_rdma;
#else
	return NULL;
#endif
}

static u32 sxe2_log_space_size_query(void)
{
	return g_log_space_size_rdma;
}

static u32 sxe2_log_file_size_query(void)
{
	return g_log_file_size_rdma;
}

static void sxe2_log_file_size_modify(u32 size)
{
	g_log_file_size_rdma = size;
}

#ifndef SXE2_CFG_RELEASE
static inline int sxe2_filter_file_print(const char *filename)
{
	struct debug_file *file = NULL;

	rcu_read_lock();
	list_for_each_entry_rcu(file, &g_sxe2_debug_rdma.filter_file, list) {
		if (!strcmp(file->name, filename)) {
			rcu_read_unlock();
			return 1;
		}
	}
	rcu_read_unlock();
	return 0;
}

static inline int sxe2_filter_func_print(const char *name)
{
	struct debug_func *func = NULL;

	rcu_read_lock();
	list_for_each_entry_rcu(func, &g_sxe2_debug_rdma.filter_func, list) {
		if (!strcmp(func->name, name)) {
			rcu_read_unlock();
			return 1;
		}
	}
	rcu_read_unlock();
	return 0;
}

#endif
static __maybe_unused void sxe2_filter_file_clear(void)
{
	struct debug_file *file = NULL;

	do {
		file = list_first_or_null_rcu(&g_sxe2_debug_rdma.filter_file,
					      struct debug_file, list);
		if (file) {
			list_del_rcu(&file->list);
			synchronize_rcu();
			kfree(file);
		}
	} while (file);

}

static __maybe_unused int sxe2_filter_func_add(char *name)
{
	struct debug_func *func = NULL;

	func = kmalloc(sizeof(struct debug_func), GFP_ATOMIC);
	if (!func) {
		sxe2_print(KERN_ERR, NULL, "kmalloc size %lu failed\n",
			   PAGE_SIZE);
		return -ENOMEM;
	}
	strscpy(func->name, name, sizeof(func->name));
	INIT_LIST_HEAD(&func->list);

	list_add_rcu(&func->list, &g_sxe2_debug_rdma.filter_func);
	return 0;
}

static __maybe_unused void sxe2_filter_func_del(char *name)
{
	struct debug_func *func = NULL;

	list_for_each_entry_rcu(func, &g_sxe2_debug_rdma.filter_func, list) {
		if (!strcmp(func->name, name)) {
			list_del_rcu(&func->list);
			synchronize_rcu();
			kfree(func);
			return;
		}
	}
}

void sxe2_filter_func_clear(void)
{
	struct debug_func *func = NULL;

	do {
		func = list_first_or_null_rcu(&g_sxe2_debug_rdma.filter_func,
					      struct debug_func, list);
		if (func) {
			list_del_rcu(&func->list);
			synchronize_rcu();
			kfree(func);
		}
	} while (func);

}

static void sxe2_file_close(struct file **file)
{
	filp_close(*file, NULL);
	*file = NULL;
}

static int sxe2_file_open(struct sxe2_log *log, struct file **pp_file)
{
	struct file *file;
	int flags_new	  = O_CREAT | O_RDWR | O_APPEND | O_LARGEFILE;
	int flags_rewrite = O_CREAT | O_RDWR | O_LARGEFILE | O_TRUNC;
	int err		  = 0;
	int len		  = 0;
	char filename[FILE_NAME_SIZE];

#ifdef SWITCH_FILE
	memset(filename, 0, FILE_NAME_SIZE);
	len += snprintf(filename, PAGE_SIZE, "%s", log->file_path);
	if (log->file_num == 0) {
		time_for_file_name(filename + len, FILE_NAME_SIZE - len);
	} else {
		snprintf(filename + len, FILE_NAME_SIZE - len, "%04d",
			 log->index++);
		log->index = log->index % log->file_num;
	}

	if (log->file_num == 1 && log->file != NULL) {
		sxe2_file_close(&log->file);
		log->file_pos = 0;
	}
#else
	memset(filename, 0, FILE_NAME_SIZE);
	strscpy(filename, path, FILE_NAME_SIZE);
#endif
	if (log->file_num == 0) {
		file = filp_open(filename, flags_new, 0666);
	} else {
		file = filp_open(filename, flags_rewrite, 0666);
		if (IS_ERR(file)) {
			err = (int)PTR_ERR(file);
			if (err == -ENOENT)
				file = filp_open(filename, flags_new, 0666);
		}
	}
	if (IS_ERR(file)) {
		err = (int)PTR_ERR(file);
		sxe2_print(KERN_ERR, NULL, "open file:%s failed[errno:%d]\n",
			   filename, err);
		goto l_out;
	}
	mapping_set_gfp_mask(file->f_path.dentry->d_inode->i_mapping, GFP_NOFS);

	sxe2_print(KERN_DEBUG, NULL, "redirect file %s\n", filename);

	*pp_file = file;

l_out:
	return err;
}

static void sxe2_file_sync(struct file *file)
{
	struct address_space *mapping;
	void *journal;
	int ret = 0;
	int err;

	(void)ret;
	(void)err;

	if (!file || !file->f_op || !file->f_op->fsync)
		goto l_end;

	journal		      = current->journal_info;
	current->journal_info = NULL;

	mapping = file->f_mapping;

	ret = filemap_fdatawrite(mapping);

	err = file->f_op->fsync(file, 0, file->f_mapping->host->i_size, 1);

	current->journal_info = journal;

l_end:
	return;
}

static void sxe2_klog_in(struct sxe2_log *log, char *buf, const int len)
{
	int begin = 0;
	int end	  = 0;
	int free_size;
	unsigned long flags;

	spin_lock_irqsave(&log->lock, flags);

	if (log->head > log->tail) {
		sxe2_print(KERN_WARNING, NULL,
			   "FAILURE: log head exceeds log tail\n");
		SXE2_BUG_NO_SYNC();
	}

	free_size = log->buf_size - (log->tail - log->head);

	if (free_size <= len) {
		log->is_drop = 1;
		spin_unlock_irqrestore(&log->lock, flags);
		return;
	}

	begin = log->tail % log->buf_size;
	end   = (log->tail + len) % log->buf_size;

	if (begin < end) {
		memcpy(log->buf + begin, buf, len);
	} else {
		memcpy(log->buf + begin, buf, log->buf_size - begin);
		memcpy(log->buf, buf + log->buf_size - begin, end);
	}

	log->tail = log->tail + len;

	spin_unlock_irqrestore(&log->lock, flags);

}

static void sxe2_klog_out(struct sxe2_log *log)
{
	int len = 0;
	int rc	= 0;
	long long tail;
	int begin;
	int end;
	int schedule_count_th = 0;
	const int max_loop    = 4096;

#ifdef SWITCH_FILE
	struct file *file = NULL;
#endif

	if (log->file == NULL) {
		rc = sxe2_file_open(log, &log->file);
		if (log->file != NULL)
			log->file_pos = 0;
		else
			return;
	}

	do {
		tail  = log->tail;
		begin = log->head % log->buf_size;
		end   = tail % log->buf_size;
		len   = 0;
		rc    = 0;

		schedule_count_th++;
		if (schedule_count_th >= max_loop) {
			schedule_count_th = 0;
			schedule_timeout_interruptible(SXE2_KLOG_OUT_WAIT);
		}

		if (log->is_drop) {
			rc = sxe2_file_write(log->file, DEBUG_DROP_LOG_STRING,
					     strlen(DEBUG_DROP_LOG_STRING));
			if (rc < 0)
				break;
			log->is_drop = 0;
		}

		if (begin < end) {
			rc = sxe2_file_write(log->file, log->buf + begin,
					     end - begin);
			if (rc > 0)
				len += rc;
		} else if (begin > end) {
			rc = sxe2_file_write(log->file, log->buf + begin,
					     log->buf_size - begin);
			if (rc > 0) {
				len += rc;
				rc = sxe2_file_write(log->file, log->buf, end);
				if (rc > 0)
					len += rc;
			}
		}
		log->head += len;
		log->file_pos += len;

		LOG_BUG_ON(log->head > log->tail,
			   "FAILURE: log head exceeds log tail\n");
	} while (log->head != log->tail && rc > 0);

	if (rc < 0) {
		sxe2_print(KERN_ERR, NULL, "write file %s error %d\n",
			   log->file_path, rc);
		return;
	}

#ifdef SWITCH_FILE
	if (log->file_pos >= log->file_size) {
		rc = sxe2_file_open(log, &file);
		if (rc >= 0 && log->file != NULL && log->file_num != 1) {
			sxe2_file_close(&log->file);
			log->file     = file;
			log->file_pos = 0;
		}
	}
#endif
}

static int sxe2_klog_flush(void *arg)
{
	int i;

	while (!kthread_should_stop()) {
		schedule_timeout_interruptible(SXE2_KLOG_OUT_WAIT);

		for (i = 0; i < ARRAY_SIZE(g_sxe2_debug_rdma.log); i++)
			sxe2_klog_out(&g_sxe2_debug_rdma.log[i]);
	}
	return 0;
}

static int sxe2_klog_init(struct sxe2_log *log, long long buf_size, char *file_path,
			  long long file_size, u32 file_num)
{
	int rc = 0;

	memset(log, 0, sizeof(*log));
	spin_lock_init(&log->lock);

	log->buf = vmalloc(buf_size + PER_CPU_PAGE_SIZE);
	if (!log->buf) {
		rc = -ENOMEM;
		goto l_end;
	}

	log->file     = NULL;
	log->head     = 0;
	log->tail     = 0;
	log->buf_size = buf_size;

	log->file_path = file_path;
	log->file_pos  = 0;
	log->file_size = file_size;
	log->file_num = file_num;
	log->index    = 0;
l_end:
	return rc;
}

static void sxe2_klog_exit(struct sxe2_log *log)
{
	if (log->buf) {
		vfree(log->buf);
		log->buf = NULL;
	}
	if (log->file)
		sxe2_file_close(&log->file);
}

static inline char *sxe2_file_name_locale(char *file)
{
	char *p_slash = strrchr(file, '/');

	return (p_slash == NULL) ? file : (p_slash + 1);
}

void sxe2_level_set(int level)
{
	g_sxe2_debug_rdma.level = level;
}
EXPORT_SYMBOL(sxe2_level_set);

s32 sxe2_level_get(void)
{
	return (s32)g_sxe2_debug_rdma.level;
}
EXPORT_SYMBOL(sxe2_level_get);

void sxe2_bin_status_set(bool status)
{
	g_sxe2_debug_rdma.status = status;
}

s32 sxe2_bin_status_get(void)
{
	return (s32)g_sxe2_debug_rdma.status;
}

void sxe2_log_string(enum debug_level level, const char *dev_name, const char *bdf,
		     const char *file, const char *func, int line,
		     const char *fmt, ...)
{
	struct sxe2_ctxt *ctxt   = NULL;
	char *buf	    = NULL;
	int len		    = 0;
	unsigned long flags = 0;
	const char *name    = dev_name ? dev_name : "";

	va_list args;

	if (level > g_sxe2_debug_rdma.level) {
#ifndef SXE2_CFG_RELEASE
		if (!sxe2_filter_file_print(file) &&
		    !sxe2_filter_func_print(func)) {
			return;
		}
#else
		return;
#endif
	}

	if (!in_interrupt())
		local_irq_save(flags);

	ctxt = per_cpu_ptr(g_sxe2_debug_rdma.ctxt, get_cpu());
	put_cpu();

	buf = (char *)ctxt->buff;
	len = snprintf(buf, PAGE_SIZE, "%s", sxe2_debug_level_name(level));
	len += time_for_log(buf + len, PAGE_SIZE - len);

	if (bdf != NULL) {
		len += snprintf(
			buf + len, PAGE_SIZE - len,
			"[%d][%d][%s][%s]%s:%4d:%s:", raw_smp_processor_id(),
			current->pid, name, bdf,
			sxe2_file_name_locale((char *)file), line, func);
	} else {
		len += snprintf(
			buf + len, PAGE_SIZE - len,
			"[%d][%d][%s]%s:%4d:%s:", raw_smp_processor_id(),
			current->pid, name, sxe2_file_name_locale((char *)file),
			line, func);
	}

	va_start(args, fmt);
	len += vsnprintf(buf + len, PAGE_SIZE - len, fmt, args);
	va_end(args);

	if (!in_interrupt())
		local_irq_restore(flags);

	sxe2_klog_in(&g_sxe2_debug_rdma.log[DEBUG_TYPE_STRING], buf, len);

	wake_up_process(g_sxe2_debug_rdma.task);

}
EXPORT_SYMBOL(sxe2_log_string);

void sxe2_log_binary(const char *file, const char *func, int line, u8 *ptr,
		     u64 addr, u32 size, char *str)
{
#define LINE_TOTAL 16
	struct sxe2_ctxt *ctxt   = NULL;
	char *buf	    = NULL;
	int len		    = 0;
	unsigned long flags = 0;
	u32 i		    = 0;
	u32 j		    = 0;
	u32 max;
	u32 mod;

	if (sxe2_bin_status_get() != true)
		return;

	max = size / LINE_TOTAL;
	mod = size % LINE_TOTAL;

	if (!in_interrupt())
		local_irq_save(flags);

	ctxt = per_cpu_ptr(g_sxe2_debug_rdma.ctxt, get_cpu());
	put_cpu();

	buf = ctxt->buff;

	len += time_for_log(buf + len, PER_CPU_PAGE_SIZE - len);
	if (len >= PER_CPU_PAGE_SIZE)
		goto l_end;

	len += snprintf(buf + len, PER_CPU_PAGE_SIZE - len,
			"[%d] %s %s():%d %s size:%d\n", current->pid,
			sxe2_file_name_locale((char *)file), func, line, str,
			size);
	if (len >= PER_CPU_PAGE_SIZE)
		goto l_end;

	for (i = 0; i < max; i++) {
		j = i * LINE_TOTAL;

		len += snprintf(buf + len, PER_CPU_PAGE_SIZE - len,
				"0x%llx 0x%llx: ", addr, (u64)&ptr[j]);
		if (len >= PER_CPU_PAGE_SIZE)
			goto l_end;

		for (; j < (i + 1) * LINE_TOTAL; j++) {
			len += snprintf(buf + len, PER_CPU_PAGE_SIZE - len,
					"0x%02x%c ", ptr[j], ',');
			if (len >= PER_CPU_PAGE_SIZE)
				goto l_end;
		}
		len += snprintf(buf + len, PER_CPU_PAGE_SIZE - len, "%c", '\n');
		if (len >= PER_CPU_PAGE_SIZE)
			goto l_end;
	}

	if (mod) {
		len += snprintf(buf + len, PER_CPU_PAGE_SIZE - len,
				"0x%llx  0x%llx: ", addr, (u64)&ptr[j]);
		if (len >= PER_CPU_PAGE_SIZE)
			goto l_end;

		for (; j < size; j++) {
			len += snprintf(buf + len, PER_CPU_PAGE_SIZE - len,
					"0x%02x%c ", ptr[j], ',');
			if (len >= PER_CPU_PAGE_SIZE)
				goto l_end;
		}

		len += snprintf(buf + len, PER_CPU_PAGE_SIZE - len, "%c", '\n');
		if (len >= PER_CPU_PAGE_SIZE)
			goto l_end;
	}

l_end:
	if (!in_interrupt())
		local_irq_restore(flags);

	sxe2_klog_in(&g_sxe2_debug_rdma.log[DEBUG_TYPE_BINARY], buf, len);

	wake_up_process(g_sxe2_debug_rdma.task);

}
EXPORT_SYMBOL(sxe2_log_binary);

void sxe2_log_sync(void)
{
	sxe2_file_sync(g_sxe2_debug_rdma.log[DEBUG_TYPE_STRING].file);
	sxe2_file_sync(g_sxe2_debug_rdma.log[DEBUG_TYPE_BINARY].file);
}
EXPORT_SYMBOL(sxe2_log_sync);

static void sxe2_log_file_prefix_add(bool is_vf, char *log_path_p)
{
	if (is_vf) {
		snprintf(g_log_path_str_rdma, LOG_PATH_LEN, "%s%s.", log_path_p,
			 VF_LOG_FILE_PREFIX);
		snprintf(g_log_path_bin_rdma, LOG_PATH_LEN, "%s%s.", log_path_p,
			 VF_BINARY_FILE_PREFIX);
	} else {
		snprintf(g_log_path_str_rdma, LOG_PATH_LEN, "%s%s.", log_path_p,
			 LOG_FILE_PREFIX);
		snprintf(g_log_path_bin_rdma, LOG_PATH_LEN, "%s%s.", log_path_p,
			 BINARY_FILE_PREFIX);
	}

}

static void sxe2_log_file_prefix_add_default(bool is_vf, char *log_path_p)
{
	if (is_vf) {
		snprintf(g_log_path_str_rdma, LOG_PATH_LEN, "%s/%s.",
			 log_path_p, VF_LOG_FILE_PREFIX);
		snprintf(g_log_path_bin_rdma, LOG_PATH_LEN, "%s/%s.",
			 log_path_p, VF_BINARY_FILE_PREFIX);
	} else {
		snprintf(g_log_path_str_rdma, LOG_PATH_LEN, "%s/%s.",
			 log_path_p, LOG_FILE_PREFIX);
		snprintf(g_log_path_bin_rdma, LOG_PATH_LEN, "%s/%s.",
			 log_path_p, BINARY_FILE_PREFIX);
	}

}

static void sxe2_log_file_path_set(bool is_vf)
{
	if (is_vf) {
		snprintf(g_log_path_str_rdma, LOG_PATH_LEN, "%s.",
			 VF_LOG_FILE_PATH);
		snprintf(g_log_path_bin_rdma, LOG_PATH_LEN, "%s.",
			 VF_BINARY_FILE_PATH);
	} else {
		snprintf(g_log_path_str_rdma, LOG_PATH_LEN, "%s.",
			 LOG_FILE_PATH);
		snprintf(g_log_path_bin_rdma, LOG_PATH_LEN, "%s.",
			 BINARY_FILE_PATH);
	}

}

static void sxe2_log_info_set(void)
{
#ifdef SXE2_CFG_RELEASE
	g_sxe2_debug_rdma.level	 = LEVEL_INFO;
	g_sxe2_debug_rdma.status = false;
#else
	g_sxe2_debug_rdma.level	 = LEVEL_DEBUG;
	g_sxe2_debug_rdma.status = true;
#endif
}

static int sxe2_log_alloc_res_per_cpu(void)
{
	int rc		  = 0;
	struct sxe2_ctxt *ctxt = NULL;
	int i;
	int nid;

	for_each_possible_cpu(i) {
		ctxt = per_cpu_ptr(g_sxe2_debug_rdma.ctxt, i);
		memset(ctxt, 0, sizeof(*ctxt));
	}

	for_each_possible_cpu(i) {
		ctxt	   = per_cpu_ptr(g_sxe2_debug_rdma.ctxt, i);
		nid	   = cpu_to_node(i);
		ctxt->page = alloc_pages_node(nid, GFP_ATOMIC, PAGE_ORDER);
		if (!ctxt->page) {
			rc = -ENOMEM;
			sxe2_print(KERN_ERR, NULL, "kmalloc size %lu failed\n",
				   PER_CPU_PAGE_SIZE);
			goto free_cpu_buff;
		}
		ctxt->buff = page_address(ctxt->page);
	}

end:
	return rc;
free_cpu_buff:
	for_each_possible_cpu(i) {
		ctxt = per_cpu_ptr(g_sxe2_debug_rdma.ctxt, i);
		if (ctxt && ctxt->page)
			__free_pages(ctxt->page, PAGE_ORDER);
	}
	goto end;
}

static void sxe2_log_free_res_per_cpu(void)
{
	struct sxe2_ctxt *ctxt = NULL;
	int i;

	for_each_possible_cpu(i) {
		ctxt = per_cpu_ptr(g_sxe2_debug_rdma.ctxt, i);
		if (ctxt && ctxt->page)
			__free_pages(ctxt->page, PAGE_ORDER);
	}
}

int sxe2_log_init(bool is_vf)
{
	struct task_struct *task   = NULL;
	int rc			   = 0;
	u32 file_num		   = 0;
	u32 log_path_len	   = 0;
	u32 input_log_space	   = sxe2_log_space_size_query();
	u32 input_log_file_size	   = sxe2_log_file_size_query();
	unsigned int log_file_size = 0;
	char *log_path_p	   = NULL;
	struct sxe2_log *log_bin	   = &g_sxe2_debug_rdma.log[DEBUG_TYPE_BINARY];
	struct sxe2_log *log_str	   = &g_sxe2_debug_rdma.log[DEBUG_TYPE_STRING];

	INIT_LIST_HEAD(&g_sxe2_debug_rdma.filter_file);
	INIT_LIST_HEAD(&g_sxe2_debug_rdma.filter_func);
	sxe2_log_info_set();

	g_sxe2_debug_rdma.ctxt = alloc_percpu(struct sxe2_ctxt);
	if (!g_sxe2_debug_rdma.ctxt) {
		rc = -ENOMEM;
		sxe2_print(KERN_ERR, NULL, "alloc percpu failed\n");
		goto l_end;
	}

	rc = sxe2_log_alloc_res_per_cpu();
	if (rc)
		goto l_free_cpu_buff;

	log_path_p   = sxe2_log_path_query();
	log_path_len = strlen(log_path_p);
	if (log_path_p != NULL && log_path_p[0] == '/') {
		if (log_path_p[log_path_len] == '/')
			sxe2_log_file_prefix_add(is_vf, log_path_p);
		else
			sxe2_log_file_prefix_add_default(is_vf, log_path_p);
	} else {
		sxe2_log_file_path_set(is_vf);
	}
	if (input_log_file_size < DRV_LOG_FILE_SIZE_MIN_MB ||
	    input_log_file_size > DRV_LOG_FILE_SIZE_MAX_MB) {
		sxe2_log_file_size_modify(LOG_FILE_SIZE >> MEGABYTE);
		input_log_file_size = LOG_FILE_SIZE >> MEGABYTE;
	}
	if (input_log_space && input_log_space < input_log_file_size) {
		sxe2_log_file_size_modify(input_log_space);
		input_log_file_size = input_log_space;
	}
	log_file_size = input_log_file_size << MEGABYTE;
	if (input_log_space) {
		file_num = input_log_space / input_log_file_size;
		if (file_num == 0) {
			sxe2_print(KERN_ERR, NULL, "filenum shouldnot be 0\n");
			SXE2_BUG();
		}
	} else {
		file_num = 0;
	}

	rc = sxe2_klog_init(log_str, BUF_SIZE, g_log_path_str_rdma,
			    log_file_size, file_num);
	if (rc < 0)
		goto l_free_cpu_ctxt_pages;

	rc = sxe2_klog_init(log_bin, BUF_SIZE, g_log_path_bin_rdma,
			    BINARY_FILE_SIZE, 0);
	if (rc < 0)
		goto l_free_string;

	task = kthread_create(sxe2_klog_flush, NULL, "sxe2_klog_flush");
	if (IS_ERR(task)) {
		rc = (int)PTR_ERR(task);
		sxe2_print(KERN_ERR, NULL, "Create kernel thread, err: %d\n",
			   rc);
		goto l_free_binary;
	}
	wake_up_process(task);
	g_sxe2_debug_rdma.task = task;
	rc		       = 0;
	sxe2_print(KERN_INFO, NULL,
		   "sxe2 debug init logpath[%s] strlogsize[%dM] filenum[%d]\n",
		   g_log_path_str_rdma, (log_file_size >> MEGABYTE),
		   log_str->file_num);
l_end:
	return rc;
l_free_binary:
	sxe2_klog_exit(&g_sxe2_debug_rdma.log[DEBUG_TYPE_BINARY]);
l_free_string:
	sxe2_klog_exit(&g_sxe2_debug_rdma.log[DEBUG_TYPE_STRING]);
l_free_cpu_ctxt_pages:
	sxe2_log_free_res_per_cpu();
l_free_cpu_buff:
	free_percpu(g_sxe2_debug_rdma.ctxt);
	goto l_end;
}
EXPORT_SYMBOL(sxe2_log_init);

void sxe2_log_exit(void)
{
	int i = 0;
	struct sxe2_ctxt *ctxt;

	if (g_sxe2_debug_rdma.task == NULL)
		return;

	kthread_stop(g_sxe2_debug_rdma.task);

	for (i = 0; i < ARRAY_SIZE(g_sxe2_debug_rdma.log); i++)
		sxe2_klog_exit(&g_sxe2_debug_rdma.log[i]);

	if (g_sxe2_debug_rdma.ctxt) {
		for_each_possible_cpu(i) {
			ctxt = per_cpu_ptr(g_sxe2_debug_rdma.ctxt, i);
			if (ctxt && ctxt->page)
				__free_pages(ctxt->page, PAGE_ORDER);
		}

		free_percpu(g_sxe2_debug_rdma.ctxt);
		g_sxe2_debug_rdma.ctxt = NULL;
	}

	sxe2_print(KERN_INFO, NULL, "sxe2 debug exit\n");
}
EXPORT_SYMBOL(sxe2_log_exit);

#elif !defined SXE2_CFG_RELEASE

s32 g_sxe2_bin_status_rdma;
char *test_bin_buf_rdma;
#define DRV_TEST_LOG_PATH_LEN (100)
enum debug_level g_sxe2_log_level_rdma		     = LEVEL_DEBUG;
char g_test_log_path_str_rdma[DRV_TEST_LOG_PATH_LEN] = { 0 };
FILE *g_file_test_rdma;
static int g_loop_index_rdma;
static bool g_loop_flag_rdma;

s32 sxe2_log_init(bool is_vf)
{
	return 0;
}

void sxe2_level_set(s32 level)
{
	g_sxe2_log_level_rdma = level;
}

s32 sxe2_level_get(void)
{
	return (s32)g_sxe2_log_level_rdma;
}

void sxe2_bin_status_set(bool status)
{
	g_sxe2_bin_status_rdma = status;
}

s32 sxe2_bin_status_get(void)
{
	return g_sxe2_bin_status_rdma;
}

void sxe2_log_sync(void)
{
}

void sxe2_log_exit(void)
{
	if (test_bin_buf_rdma != NULL) {
		free(test_bin_buf_rdma);
		test_bin_buf_rdma = NULL;
	}
}

void sxe2_log_binary(const char *file, const char *func, int line, u8 *ptr,
		     u64 addr, u32 size, char *str)
{
#define LINE_TOTAL	      16
	u32 i = 0;
	u32 j = 0;
	u32 iMax;
	u32 mod;
	char *buf = NULL;
	int len	  = 0;

	if (sxe2_bin_status_get() != true)
		return;

	buf		  = zalloc(PER_CPU_PAGE_SIZE);
	test_bin_buf_rdma = buf;

	iMax = size / LINE_TOTAL;
	mod  = size % LINE_TOTAL;

	len += snprintf(buf + len, (size_t)(PER_CPU_PAGE_SIZE - len),
			"%s size:%d\n", str, size);
	if (len >= PER_CPU_PAGE_SIZE)
		goto l_end;

	for (i = 0; i < iMax; i++) {
		j = i * LINE_TOTAL;

		len += snprintf(buf + len, (size_t)(PER_CPU_PAGE_SIZE - len),
				"0x%llx 0x%llx: ", addr, (u64)&ptr[j]);
		if (len >= PER_CPU_PAGE_SIZE)
			goto l_end;

		for (; j < (i + 1) * LINE_TOTAL; j++) {
			len += snprintf(buf + len,
					(size_t)(PER_CPU_PAGE_SIZE - len),
					"0x%02x%c ", ptr[j], ',');
			if (len >= PER_CPU_PAGE_SIZE)
				goto l_end;
		}
		len += snprintf(buf + len, (size_t)(PER_CPU_PAGE_SIZE - len),
				"%c", '\n');
		if (len >= PER_CPU_PAGE_SIZE)
			goto l_end;
	}

	if (mod) {
		len += snprintf(buf + len, (size_t)(PER_CPU_PAGE_SIZE - len),
				"0x%llx  0x%llx: ", addr, (u64)&ptr[j]);
		if (len >= PER_CPU_PAGE_SIZE)
			goto l_end;

		for (; j < size; j++) {
			len += snprintf(buf + len,
					(size_t)(PER_CPU_PAGE_SIZE - len),
					"0x%02x%c ", ptr[j], ',');
			if (len >= PER_CPU_PAGE_SIZE)
				goto l_end;
		}

		len += snprintf(buf + len, (size_t)(PER_CPU_PAGE_SIZE - len),
				"%c", '\n');
		if (len >= PER_CPU_PAGE_SIZE)
			goto l_end;
	}

l_end:
	printf("buf:%s", buf);
}

S8 *sxe2_log_path_query(void)
{
	return NULL;
}

STATIC S32 get_now_ms_int(S8 *buff, size_t buf_len)
{
	struct timeval tv;
	struct tm td;

	gettimeofday(&tv, NULL);
	(void)localtime_r(&tv.tv_sec, &td);

	return snprintf(buff, buf_len, "[%04d-%02d-%02d;%02d:%02d:%02d.%06ld]",
			td.tm_year + 1900, td.tm_mon + 1, td.tm_mday,
			td.tm_hour, td.tm_min, td.tm_sec, tv.tv_usec);
}

STATIC S32 get_now_sec(S8 *buff, S32 buf_len)
{
	struct timeval tv;
	struct tm td;

	gettimeofday(&tv, NULL);
	(void)localtime_r(&tv.tv_sec, &td);

	return snprintf(buff, (size_t)buf_len, "%04d-%02d-%02d_%02d:%02d:%02d",
			td.tm_year + 1900, td.tm_mon + 1, td.tm_mday,
			td.tm_hour, td.tm_min, td.tm_sec);
}

void sxe2_log_string(enum debug_level level, const char *dev_name, const char *bdf,
		     const char *file, const char *func, int line,
		     const char *fmt, ...)
{
	size_t ret;
	S32 len	    = 0;
	S8 *log_buf = kzalloc(PAGE_SIZE, GFP_ATOMIC);

	if (log_buf == NULL)
		return;
	va_list args;
	const char *name = dev_name ? dev_name : "";

	if (level > g_sxe2_log_level_rdma)
		return;

	len = snprintf(log_buf, PAGE_SIZE, "%s", sxe2_debug_level_name(level));
	len += get_now_ms_int(log_buf + len, (size_t)(PAGE_SIZE - len));

	if (bdf != NULL) {
		len += snprintf(log_buf + len, (size_t)(PAGE_SIZE - len),
				"[%d][%s][%s]%s:%4d:%s:", (int)pthread_self(),
				name, bdf, filename_printf((S8 *)file), line,
				func);
	} else {
		len += snprintf(log_buf + len, (size_t)(PAGE_SIZE - len),
				"[%d][%s]%s:%4d:%s:", (int)pthread_self(), name,
				filename_printf((S8 *)file), line, func);
	}

	va_start(args, fmt);
	len += vsnprintf(log_buf + len, (size_t)(PAGE_SIZE - len), fmt, args);
	va_end(args);

	if (g_file_test_rdma == NULL) {
		g_file_test_rdma = fopen(g_test_log_path_str_rdma, "ab");
		if (g_file_test_rdma == NULL) {
			perror("fopen");
			goto out;
		}
	}

	ret = fwrite(log_buf, (size_t)len, 1, g_file_test_rdma);
	if (ret != 1)
		perror("fwrite");

	fflush(g_file_test_rdma);

out:
	kfree(log_buf);
}

void sxe2_set_log_loop_index(S32 index)
{
	g_loop_index_rdma = index;
}

void sxe2_set_log_loop_flag(bool flag)
{
	g_loop_flag_rdma = flag;
}

int sxe2_debug_init(void)
{
	S32 file_name_len = 0;

	g_sxe2_log_level_rdma = LEVEL_DEBUG;

	if (g_file_test_rdma == NULL) {
		file_name_len += snprintf(g_test_log_path_str_rdma,
					  DRV_TEST_LOG_PATH_LEN, "%s.",
					  SXE2_DRV_TEST_LOG_PATH);
		file_name_len +=
			get_now_sec(g_test_log_path_str_rdma + file_name_len,
				    DRV_TEST_LOG_PATH_LEN - file_name_len);
		if (g_loop_flag_rdma) {
			snprintf(
				g_test_log_path_str_rdma + file_name_len,
				(size_t)(DRV_TEST_LOG_PATH_LEN - file_name_len),
				"-loop%d", g_loop_index_rdma);
		}

		g_file_test_rdma = fopen(g_test_log_path_str_rdma, "ab");
		if (g_file_test_rdma == NULL) {
			perror("fopen");
			return -1;
		}
	}
	return 0;
}

void sxe2_debug_exit(void)
{
	if (g_file_test_rdma != NULL) {
		fclose(g_file_test_rdma);
		g_file_test_rdma = NULL;
	}
}

#endif
