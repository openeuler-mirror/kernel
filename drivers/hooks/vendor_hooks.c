// SPDX-License-Identifier: GPL-2.0-only
/* vendor_hook.c
 *
 * Vendor Hook Support
 *
 * Copyright (C) 2020 Google, Inc.
 */

#define CREATE_TRACE_POINTS
#include <trace/hooks/vendor_hooks.h>
#include <trace/hooks/bonding.h>

/*
 * Export tracepoints that act as a bare tracehook (ie: have no trace event
 * associated with them) to allow external modules to probe them.
 */

#ifdef CONFIG_VENDOR_BOND_HOOKS
EXPORT_TRACEPOINT_SYMBOL_GPL(vendor_bond_check_dev_link);
#endif
