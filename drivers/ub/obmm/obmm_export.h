/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2026. All rights reserved.
 * Description：OBMM Framework's implementations.
 */

#ifndef OBMM_EXPORT_C_H
#define OBMM_EXPORT_C_H

struct obmm_export_common;

int export_flags_to_region_flags(unsigned long *region_flags, unsigned long user_flags);

/* shared export glue (obmm_export.c), used by both export backend creators */

/* Register the backend's memory with UMMU and DMA-map its sg_table; the
 * tokenid/uba outputs land in @exp.
 */
int setup_ummu(struct obmm_export_common *exp);
/* Undo setup_ummu, incl. the re-map rollback on tdev-free failure. */
int teardown_ummu(struct obmm_export_common *exp);
/* Copy the uapi vendor blob into a fresh kernel buffer (NULL for a zero
 * length; -EINVAL over OBMM_MAX_VENDOR_LEN, -ENOMEM, -EFAULT); the creator
 * consumes it past the call, so never free it ioctl-side (obmm_backend.h).
 */
void *dup_export_vendor(const void __user *vendor_info, unsigned int vendor_len);

int obmm_export_from_pool(struct obmm_cmd_export *cmd_export);
int obmm_export_pid(struct obmm_cmd_export_pid *export_pid);
int obmm_unexport(const struct obmm_cmd_unexport *cmd_unexport);
#endif
