/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2020 - 2023, Chengdu BeiZhongWangXin Technology Co., Ltd. */

#ifndef CONFIG_TRACEPOINTS
#if !defined(_NE6X_TRACE_H_)
#define _NE6X_TRACE_H_

#define ne6x_trace(trace_name, args...)
#define ne6x_trace_enabled(trace_name) (0)
#endif /* !defined(_NE6X_TRACE_H_) */
#else  /* CONFIG_TRACEPOINTS */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM ne6x

#if !defined(_NE6X_VF_TRACE_H_) || defined(TRACE_HEADER_MULTI_READ)
#define _NE6X_TRACE_H_

#include <linux/tracepoint.h>
#include "trace_comm.h"
#endif /* _NE6X_TRACE_H_ */
/* This must be outside ifdef _NE6X_TRACE_H_ */

#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH .
#undef TRACE_INCLUDE_FILE
#define TRACE_INCLUDE_FILE ne6x_trace
#include <trace/define_trace.h>
#endif /* CONFIG_TRACEPOINTS */
