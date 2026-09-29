/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2018 - 2021 Beijing WangXun Technology Co., Ltd. */

#ifndef _NSEVF_OSDEP_H_
#define _NSEVF_OSDEP_H_

#include <linux/types.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/tcp.h>
#include <linux/pci.h>
#include <linux/highuid.h>

#include <linux/io.h>
#include <asm-generic/int-ll64.h>

#define NSEVF_M(m, s) ((m) << (s))
#define NSEVF_M_64(m, s) (U64_C(m) << (s))

#define NSE_M NSEVF_M
#define NSE_M_64 NSEVF_M_64

/* File to be the magic between shared code and
 * actual OS primitives
 */

#define hw_dbg(h, s, ...)                                                \
	pr_debug("nsevf %02x:%02x.%x " s, (h)->bus.bus_id,               \
		 (h)->bus.device, (h)->bus.func, ##__VA_ARGS__)

#define wr32(a, reg, value) writel((value), ((a)->hw_addr + (reg)))
#define rd32(a, reg) readl((a)->hw_addr + (reg))

#define wr64(a, reg, value) writeq((value), ((a)->hw_addr + (reg)))
#define rd64(a, reg) readq((a)->hw_addr + (reg))
#define nsevf_flush(a) readl((a)->hw_addr + NSEVF_REG_ST)
/* memory allocation tracking */
struct nsevf_dma_mem {
	void *va;
	dma_addr_t pa;
	u32 size;
};

#define nsevf_allocate_dma_mem(h, m, unused, s, a) \
	nsevf_allocate_dma_mem_d(h, m, unused, s, a)

#define nsevf_free_dma_mem(h, m) nsevf_free_dma_mem_d(h, m)

struct nsevf_virt_mem {
	void *va;
	u32 size;
};

#define nsevf_allocate_virt_mem(h, m, s) nsevf_allocate_virt_mem_d(h, m, s)
#define nsevf_free_virt_mem(h, m) nsevf_free_virt_mem_d(h, m)

#define nsevf_debug(_hw, type, fmt, args...)                     \
	do {                                                     \
		struct nsevf_hw *__hw = (struct nsevf_hw *)_hw;  \
		if (__hw) {                                      \
			if ((type) & (__hw)->debug_mask)         \
				dev_info(nsevf_hw_to_dev(__hw),  \
					 "nsevf: " fmt, ##args); \
		} else {                                         \
			dev_info(NULL, "nsevf: " fmt, ##args);   \
		}                                                \
	} while (0)

/* SW spinlock */
struct nsevf_spinlock {
	struct mutex spinlock; /* serializes access to shared driver state */
};

static inline void nsevf_no_action(struct nsevf_spinlock *sp)
{
	/* nothing */
}

/* the locks are initialized in _probe and destroyed in _remove
 * so make sure NOT to implement init/destroy here, as to
 * avoid the nsevf_init_adminq code trying to reinitialize
 * the persistent lock memory
 */
#define nsevf_init_spinlock(_sp) nsevf_no_action(_sp)
#define nsevf_acquire_spinlock(_sp) nsevf_acquire_spinlock_d(_sp)
#define nsevf_release_spinlock(_sp) nsevf_release_spinlock_d(_sp)
#define nsevf_destroy_spinlock(_sp) nsevf_no_action(_sp)

#define NSEVF_HTONL(a) htonl(a)

#define nsevf_memset(a, b, c, d) memset((a), (b), (c))
#define nsevf_memcpy(a, b, c, d) memcpy((a), (b), (c))

#ifdef DEBUG
#define nsevf_debug_array(hw, type, rowsize, groupsize, buf, len)         \
	do {                                                              \
		if ((type) & (hw)->debug_mask)                            \
			print_hex_dump_debug(KBUILD_MODNAME,              \
					     DUMP_PREFIX_OFFSET, rowsize, \
					     groupsize, buf, len, false); \
	} while (0)

#else
#define nsevf_debug_array(hw, type, rowsize, groupsize, buf, len)             \
	do {                                                                  \
		struct nsevf_hw *hw_l = hw;                                   \
		if ((type) & (hw_l)->debug_mask) {                            \
			u16 len_l = len;                                      \
			u8 *buf_l = buf;                                      \
			int i;                                                \
			for (i = 0; i < (len_l - 16); i += 16)                \
				nsevf_debug(hw_l, type, "0x%04X  %16ph\n", i, \
					    ((buf_l) + i));                   \
			if (i < len_l)                                        \
				nsevf_debug(hw_l, type, "0x%04X  %*ph\n", i,  \
					    ((len_l) - i), ((buf_l) + i));    \
		}                                                             \
	} while (0)

#endif /* DEBUG */

#endif /* _NSEVF_OSDEP_H_ */
