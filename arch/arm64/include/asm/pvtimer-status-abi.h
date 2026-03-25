/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright(c) 2026 Huawei Technologies Co., Ltd
 * Author: Jia Qingtong <jiaqingtong@huawei.com>
 */

#ifndef __ASM_PVTIMER_STATUS_ABI_H
#define __ASM_PVTIMER_STATUS_ABI_H

#ifdef CONFIG_VIRT_VTIMER_PV_STATUS
struct pvtimer_status_vcpu_state {
	__le32 active;
	/* Structure must be 64 byte aligned, pad to that size */
	u8 padding[60];
} __packed;
#endif /* CONFIG_VIRT_VTIMER_PV_STATUS */

#endif
