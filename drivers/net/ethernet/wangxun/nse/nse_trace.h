/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2018 - 2021 Beijing WangXun Technology Co., Ltd. */

/*  @xzhao - todo-99: I guess no one would use kernel CONFIG_TRACEPOINTS, here simply define them as
 * nops, and put it to quite low priority
 */

#if !defined(_NSE_TRACE_H_)
#define _NSE_TRACE_H_
/* If the Linux kernel tracepoints are not available then the nse_trace*
 * macros become nops.
 */

#define nse_trace(trace_name, args...)
#define nse_trace_enabled(trace_name) (0)
#endif /* !defined(_NSE_TRACE_H_) */

