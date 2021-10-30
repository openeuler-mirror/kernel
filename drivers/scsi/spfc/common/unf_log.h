/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2021 Ramaxel Memory Technology, Ltd */

#ifndef UNF_LOG_H
#define UNF_LOG_H
#include "unf_type.h"

#define UNF_CRITICAL 1
#define UNF_ERR 2
#define UNF_WARN 3
#define UNF_KEVENT 4
#define UNF_MAJOR 5
#define UNF_MINOR 6
#define UNF_INFO 7
#define UNF_DATA 7
#define UNF_ALL 7

enum unf_debug_type {
	UNF_DEBUG_TYPE_MML = 0,
	UNF_DEBUG_TYPE_DIAGNOSE = 1,
	UNF_DEBUG_TYPE_MESSAGE = 2,
	UNF_DEBUG_TYPE_BUTT
};

enum unf_log_attr {
	UNF_LOG_LOGIN_ATT = 0x1,
	UNF_LOG_IO_ATT = 0x2,
	UNF_LOG_EQUIP_ATT = 0x4,
	UNF_LOG_REG_ATT = 0x8,
	UNF_LOG_REG_MML_TEST = 0x10,
	UNF_LOG_EVENT = 0x20,
	UNF_LOG_NORMAL = 0x40,
	UNF_LOG_ABNORMAL = 0X80,
	UNF_LOG_BUTT
};

enum event_log {
	UNF_EVTLOG_DRIVER_SUC = 0,
	UNF_EVTLOG_DRIVER_INFO,
	UNF_EVTLOG_DRIVER_WARN,
	UNF_EVTLOG_DRIVER_ERR,
	UNF_EVTLOG_LINK_SUC,
	UNF_EVTLOG_LINK_INFO,
	UNF_EVTLOG_LINK_WARN,
	UNF_EVTLOG_LINK_ERR,
	UNF_EVTLOG_IO_SUC,
	UNF_EVTLOG_IO_INFO,
	UNF_EVTLOG_IO_WARN,
	UNF_EVTLOG_IO_ERR,
	UNF_EVTLOG_TOOL_SUC,
	UNF_EVTLOG_TOOL_INFO,
	UNF_EVTLOG_TOOL_WARN,
	UNF_EVTLOG_TOOL_ERR,
	UNF_EVTLOG_BUT
};

#define UNF_IO_ATT_PRINT_TIMES 2
#define UNF_LOGIN_ATT_PRINT_TIMES 100

#define UNF_IO_ATT_PRINT_LIMIT msecs_to_jiffies(2 * 1000)

extern u32 unf_dgb_level;
extern u32 log_print_level;
extern u32 log_limited_times;

#define DRV_LOG_LIMIT(module_id, log_level, log_att, format, ...)      \
	do {                                                                   \
		static unsigned long pre;                                  \
		static int should_print = UNF_LOGIN_ATT_PRINT_TIMES;           \
		if (time_after_eq(jiffies, pre + (UNF_IO_ATT_PRINT_LIMIT))) {  \
			if (log_att == UNF_LOG_ABNORMAL) {                     \
				should_print = UNF_IO_ATT_PRINT_TIMES;         \
			} else {                                               \
				should_print = log_limited_times;             \
			}                                                      \
		}                                                              \
		if (should_print < 0) {                                        \
			if (log_att != UNF_LOG_ABNORMAL)                     \
				pre = jiffies;                                 \
			break;                                                 \
		}                                                              \
		if (should_print-- > 0) {                                      \
			printk(log_level "[%d][FC_UNF]" format "[%s][%-5d]\n", \
			       smp_processor_id(), ##__VA_ARGS__, __func__,    \
			       __LINE__);                                      \
		}                                                              \
		if (should_print == 0) {                                       \
			printk(log_level "[FC_UNF]log is limited[%s][%-5d]\n", \
			       __func__, __LINE__);                            \
		}                                                              \
		pre = jiffies;                                                 \
	} while (0)

#define FC_CHECK_RETURN_VALUE(condition, ret)                            \
	do {                                                            \
		if (unlikely(!(condition))) {                           \
			FC_DRV_PRINT(UNF_LOG_REG_ATT,                   \
				     UNF_ERR, "Para check(%s) invalid", \
				     #condition);                       \
			return ret;                                     \
		}                                                       \
	} while (0)

#define FC_CHECK_RETURN_VOID(condition)                                 \
	do {                                                            \
		if (unlikely(!(condition))) {                           \
			FC_DRV_PRINT(UNF_LOG_REG_ATT,                   \
				     UNF_ERR, "Para check(%s) invalid", \
				     #condition);                       \
			return;                                         \
		}                                                       \
	} while (0)

#define FC_DRV_PRINT(log_att, log_level, format, ...)                  \
	do {                                                                   \
		if (unlikely((log_level) <= log_print_level)) {              \
			if (log_level == UNF_CRITICAL) {                       \
				DRV_LOG_LIMIT(UNF_PID, KERN_CRIT,              \
					      log_att, format, ##__VA_ARGS__); \
			} else if (log_level == UNF_WARN) {                    \
				DRV_LOG_LIMIT(UNF_PID, KERN_WARNING,           \
					      log_att, format, ##__VA_ARGS__); \
			} else if (log_level == UNF_ERR) {                     \
				DRV_LOG_LIMIT(UNF_PID, KERN_ERR,               \
					      log_att, format, ##__VA_ARGS__); \
			} else if (log_level == UNF_MAJOR ||                   \
				   log_level == UNF_MINOR ||                   \
				   log_level == UNF_KEVENT) {                  \
				DRV_LOG_LIMIT(UNF_PID, KERN_NOTICE,            \
					      log_att, format, ##__VA_ARGS__); \
			} else if (log_level == UNF_INFO ||                    \
				   log_level == UNF_DATA) {                    \
				DRV_LOG_LIMIT(UNF_PID, KERN_INFO,              \
					      log_att, format, ##__VA_ARGS__); \
			}                                                      \
		}                                                              \
	} while (0)

#define UNF_PRINT_SFS(dbg_level, portid, data, size)                           \
	do {                                                                   \
		if ((dbg_level) <= log_print_level) {                        \
			u32 cnt = 0;                                           \
			printk(KERN_INFO "[INFO]Port(0x%x) sfs:0x", (portid)); \
			for (cnt = 0; cnt < (size) / 4; cnt++) {               \
				printk(KERN_INFO "%08x ",                      \
				       ((u32 *)(data))[cnt]);                  \
			}                                                      \
			printk(KERN_INFO "[FC_UNF][%s]\n", __func__);      \
		}                                                              \
	} while (0)

#define UNF_PRINT_SFS_LIMIT(dbg_level, portid, data, size)                    \
	do {                                                                  \
		if ((dbg_level) <= log_print_level) {                       \
			static ulong pre;                                     \
			static int should_print = UNF_LOGIN_ATT_PRINT_TIMES;  \
			if (time_after_eq(                            \
				jiffies, pre + UNF_IO_ATT_PRINT_LIMIT)) {     \
				should_print = log_limited_times;            \
			}                                                     \
			if (should_print < 0) {                               \
				pre = jiffies;                                \
				break;                                        \
			}                                                     \
			if (should_print-- > 0) {                             \
				UNF_PRINT_SFS(dbg_level, portid, data, size); \
			}                                                     \
			if (should_print == 0) {                              \
				printk(                                       \
				    KERN_INFO                                 \
				    "[FC_UNF]sfs log is limited[%s][%-5d]\n", \
				    __func__, __LINE__);                      \
			}                                                     \
			pre = jiffies;                                        \
		}                                                             \
	} while (0)

#endif
