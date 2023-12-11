/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __YS_REG_OPS_H_
#define __YS_REG_OPS_H_

#include "ys_debug.h"

#include <linux/bitfield.h>

#define ys_rd32(base, reg) \
	ioread32((void __iomem *)((uintptr_t)(base) + (reg)))
#define ys_wr32(base, reg, value) \
	iowrite32(value, (void __iomem *)((uintptr_t)(base) + (reg)))

#define ys_rd32_s(reg) ys_rd32(reg, 0)
#define ys_wr32_s(reg, value) ys_wr32(reg, 0, value)

#endif /* __YS_REG_OPS_H_ */
