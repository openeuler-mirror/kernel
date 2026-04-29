/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved.
 *
 */

#ifndef __UBASE_CTX_DEBUGFS_H__
#define __UBASE_CTX_DEBUGFS_H__

struct device;

int ubase_dbg_dump_aeq_context(struct seq_file *s, void *data);
int ubase_dbg_dump_ceq_context(struct seq_file *s, void *data);
int ubase_dbg_dump_tpg_ctx(struct seq_file *s, void *data);
int ubase_dbg_dump_aeq_ctx_hw(struct seq_file *s, void *data);
int ubase_dbg_dump_ceq_ctx_hw(struct seq_file *s, void *data);

#endif
