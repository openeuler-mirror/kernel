/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_MICROCODE_ZHAOXIN_H
#define _ASM_X86_MICROCODE_ZHAOXIN_H

#include <asm/microcode.h>

struct microcode_header_zhaoxin {
	u32 signature;
	u32 reserved1;
	u32 year : 16;
	u32 day : 8;
	u32 month : 8;
	u32 applicable_processor;
	u32 checksum;
	u32 ldr_rev;
	u8 chip_pf;
	u8 sku_flag;
	u16 update_rev_small_low;
	u32 data_size;
	u32 total_size;
	u16 reserved2;
	u32 update_rev;
	u16 reserved3;
	u16 signed_flag;
	u16 update_rev_small_high;
} __packed;

struct microcode_zhaoxin {
	struct microcode_header_zhaoxin hdr;
	unsigned int                 data[];
};

#define ZHAOXIN_MICROCODE_HEADER 0x53415252
#define ZHAOXIN_MC_HEADER_SIZE sizeof(struct microcode_header_zhaoxin)
#define UCODE_BSP_LOADED ((struct microcode_zhaoxin *)0x1UL)
#define ZHAOXIN_MSR_PF 0x1631
#define ZHAOXIN_MSR_FCR5_PATCH_ERROR_CODE 0x1205
#define IS_HEX(c) (((c) >= '0' && (c) <= '9') || \
		   ((c) >= 'A' && (c) <= 'F') || \
		   ((c) >= 'a' && (c) <= 'f'))

#ifdef CONFIG_MICROCODE_ZHAOXIN
void load_ucode_zhaoxin_bsp(void);
void load_ucode_zhaoxin_ap(void);
int save_microcode_in_initrd_zhaoxin(void);
void reload_ucode_zhaoxin(void);
struct microcode_ops *init_zhaoxin_microcode(void);
#else /* CONFIG_MICROCODE_ZHAOXIN */
static inline void load_ucode_zhaoxin_bsp(void) { }
static inline void load_ucode_zhaoxin_ap(void) { }
static inline int save_microcode_in_initrd_zhaoxin(void) { return -EINVAL; }
static inline void reload_ucode_zhaoxin(void) { }
static inline struct microcode_ops *init_zhaoxin_microcode(void)
{
	return NULL;
}
#endif  /* !CONFIG_MICROCODE_ZHAOXIN */
#endif /* _ASM_X86_MICROCODE_ZHAOXIN_H */
