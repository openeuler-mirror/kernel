/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#ifndef XSC_DOORBELL_H
#define XSC_DOORBELL_H

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

#endif /* XSC_DOORBELL_H */
