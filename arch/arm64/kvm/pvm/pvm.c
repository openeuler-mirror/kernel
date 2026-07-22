// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 Huawei Technologies Co., Ltd.
 * Author: Kunkun Jiang <jiangkunkun@huawei.com>
 */

#include <linux/kvm_host.h>

#include <asm/kvm_pvm.h>
#include <kvm/arm_rv_timer.h>

DEFINE_STATIC_KEY_FALSE(kvm_pvm_is_available);

void __init kvm_arm_init_pvm(void)
{
	int ret;

	ret = kvm_rv_timer_hyp_init();
	if (ret) {
		pr_err("pvm: failed to init kvm rv timer, err = %d\n", ret);
		return;
	}
	static_branch_enable(&kvm_pvm_is_available);
}

void kvm_arm_destroy_pvm(void)
{
	static_branch_disable(&kvm_pvm_is_available);
}
