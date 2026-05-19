// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 Huawei Technologies Co., Ltd.
 * Author: Kunkun Jiang <jiangkunkun@huawei.com>
 */

#include <linux/kvm_host.h>

#include <asm/kvm_pvm.h>

DEFINE_STATIC_KEY_FALSE(kvm_pvm_is_available);

void kvm_arm_init_pvm(void)
{
	static_branch_enable(&kvm_pvm_is_available);
}

void kvm_arm_destroy_pvm(void)
{
	static_branch_disable(&kvm_pvm_is_available);
}
