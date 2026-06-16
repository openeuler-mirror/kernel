/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2026 - Huawei LLC
 * Author: Kunkun Jiang <Jiangkunkun@huawei.com>
 */
#ifndef __ARM64_KVM_PVM_ID_REGS_H
#define __ARM64_KVM_PVM_ID_REGS_H

#include <linux/types.h>

u64 kvm_pvm_filter_id_reg(u32 id, u64 val);

#endif /* __ARM64_KVM_PVM_ID_REGS_H */
