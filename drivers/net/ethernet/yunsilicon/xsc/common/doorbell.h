/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#ifndef XSC_DOORBELL_H
#define XSC_DOORBELL_H

#if BITS_PER_LONG == 64
/* Assume that we can just write a 64-bit doorbell atomically.  s390
 * actually doesn't have writeq() but S/390 systems don't even have
 * PCI so we won't worry about it.
 */

#define XSC_DECLARE_DOORBELL_LOCK(name)
#define XSC_INIT_DOORBELL_LOCK(ptr)    do { } while (0)
#define XSC_GET_DOORBELL_LOCK(ptr)      (NULL)

static inline void xsc_write64(__be32 val[2], void __iomem *dest,
			       spinlock_t *doorbell_lock)
{
	__raw_writeq(*(u64 *)val, dest);
}

#else

/* Just fall back to a spinlock to protect the doorbell if
 * BITS_PER_LONG is 32 -- there's no portable way to do atomic 64-bit
 * MMIO writes.
 */

#define XSC_DECLARE_DOORBELL_LOCK(name) spinlock_t name
#define XSC_INIT_DOORBELL_LOCK(ptr)     spin_lock_init(ptr)
#define XSC_GET_DOORBELL_LOCK(ptr)      (ptr)

static inline void xsc_write64(__be32 val[2], void __iomem *dest,
			       spinlock_t *doorbell_lock)
{
	unsigned long flags;

	spin_lock_irqsave(doorbell_lock, flags);
	__raw_writel((__force u32)val[0], dest);
	__raw_writel((__force u32)val[1], dest + 4);
	spin_unlock_irqrestore(doorbell_lock, flags);
}

#endif

#endif /* XSC_DOORBELL_H */
