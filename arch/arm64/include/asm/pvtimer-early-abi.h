/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright(c) 2026 Huawei Technologies Co., Ltd
 * Author: Jia Qingtong <jiaqingtong@huawei.com>
 */

#ifndef __ASM_PVTIMER_EARLY_ABI_H
#define __ASM_PVTIMER_EARLY_ABI_H

#ifdef CONFIG_VIRT_TIMER_EARLY_INJECT
struct pvtimer_early_vcpu_state {
	__le64 early_ns;
	u8 padding[56];
} __packed;
#endif /* CONFIG_VIRT_TIMER_EARLY_INJECT */

#endif
