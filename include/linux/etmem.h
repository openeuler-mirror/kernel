/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __MM_ETMEM_H_
#define __MM_ETMEM_H_

#include <linux/list.h>
#include <asm/page.h>
#include <linux/mmzone.h>
#include <linux/memcontrol.h>
#include <linux/page-flags.h>

#ifdef CONFIG_ETMEM

#if IS_ENABLED(CONFIG_KVM)
static inline struct kvm *mm_kvm(struct mm_struct *mm)
{
	return mm->kvm;
}
#else
static inline struct kvm *mm_kvm(struct mm_struct *mm)
{
	return NULL;
}
#endif


#endif /* #ifdef CONFIG_ETMEM */
#endif /* define __MM_ETMEM_H_ */
