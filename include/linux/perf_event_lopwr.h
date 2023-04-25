/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _PERF_EVENT_LOPWR_H
#define _PERF_EVENT_LOPWR_H

#include <linux/static_call.h>

#if defined(CONFIG_PERF_EVENTS_AMD_BRS)
#define PERF_NEEDS_LOPWR_CB 1
/*
 * architectural low power callback impacts
 * drivers/acpi/processor_idle.c
 * drivers/acpi/acpi_pad.c
 */
extern void perf_amd_brs_lopwr_cb(bool lopwr_in);

DECLARE_STATIC_CALL(perf_lopwr_cb, perf_amd_brs_lopwr_cb);

static inline void perf_lopwr_cb(bool lopwr_in)
{
	static_call_mod(perf_lopwr_cb)(lopwr_in);
}

#endif /* PERF_NEEDS_LOPWR_CB */

#ifndef PERF_NEEDS_LOPWR_CB
static inline void perf_lopwr_cb(bool mode)
{
}
#endif

#endif /*_PERF_EVENT_LOPWR_H*/
