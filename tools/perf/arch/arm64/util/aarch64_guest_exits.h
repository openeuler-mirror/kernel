// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright(c) 2019 Huawei Technologies Co., Ltd
 */

#ifndef ARCH_PERF_AARCH64_GUEST_EXITS_H
#define ARCH_PERF_AARCH64_GUEST_EXITS_H

/* virt.h */
/* Error returned when an invalid stub number is passed into x0 */
#define HVC_STUB_ERR	0xbadca11

/* kvm_asm.h */
#define ARM_EXCEPTION_IRQ         0
#define ARM_EXCEPTION_EL1_SERROR  1
#define ARM_EXCEPTION_TRAP        2
#define ARM_EXCEPTION_IL          3
/* The hyp-stub will return this for any kvm_call_hyp() call */
#define ARM_EXCEPTION_HYP_GONE    HVC_STUB_ERR

#define kvm_arm_exception_type					\
	{ARM_EXCEPTION_IRQ,		"IRQ"		},	\
	{ARM_EXCEPTION_EL1_SERROR,	"SERROR"	},	\
	{ARM_EXCEPTION_TRAP,		"TRAP"		},	\
	{ARM_EXCEPTION_HYP_GONE,	"HYP_GONE"	}

#endif /* ARCH_PERF_AARCH64_GUEST_EXITS_H */
