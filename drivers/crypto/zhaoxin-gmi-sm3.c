// SPDX-License-Identifier: GPL-2.0-only
/*
 * zx-gmi-sm4.c - wrapper code for Zhaoxin GMI.
 *
 * Copyright (C) 2023 Shanghai Zhaoxin Semiconductor LTD.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <crypto/internal/hash.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/mm.h>
#include <linux/types.h>
#include <crypto/sm3.h>
#include <crypto/sm3_base.h>
#include <linux/bitops.h>
#include <asm/byteorder.h>
#include <asm/unaligned.h>

static u8 use_ccs;

const u8 zx_sm3_zero_message_hash[SM3_DIGEST_SIZE] = {
	0x1A, 0xB2, 0x1D, 0x83, 0x55, 0xCF, 0xA1, 0x7F,
	0x8e, 0x61, 0x19, 0x48, 0x31, 0xE8, 0x1A, 0x8F,
	0x22, 0xBE, 0xC8, 0xC7, 0x28, 0xFE, 0xFB, 0x74,
	0x7E, 0xD0, 0x35, 0xEB, 0x50, 0x82, 0xAA, 0x2B
};
EXPORT_SYMBOL_GPL(zx_sm3_zero_message_hash);

u32 zx_gmi_capability(void)
{
	u32 eax = 0;
	u32 ebx, ecx, edx = 0;

	// 1. check vendor ID string
	__asm__ __volatile__ ("cpuid" : "=b"(ebx), "=c"(ecx), "=d"(edx) : "a"(eax) : );

	if (((ebx == 0x746e6543) && (ecx == 0x736c7561) && (edx == 0x48727561)) ||
		((ebx == 0x68532020) && (ecx == 0x20206961) && (edx == 0x68676e61))) {
		// 2. check whether support SM3/SM4/SM2 Instructions
		eax = 0xC0000001;
		__asm__ __volatile__ ("cpuid":"=d"(edx):"a"(eax) : );
	} else {
		pr_warn("This is not a ZX CPU! Return!\n");
		return 0;
	}

	return edx;
}

static u32 get_cpu_fms(u32 *eax, u32 *leaf)
{
	u32 eax_tmp = *eax, leaf_tmp = *leaf;

	__asm__ __volatile__ (
		"cpuid"
		: "=a"(eax_tmp)
		: "0"(leaf_tmp)
		: "ebx", "ecx");

	*eax = eax_tmp;
	return eax_tmp;
}

/*
 * Load supported features of the CPU to see if the SM3/SM4 is available.
 */
static int gmi_available(void)
{
	u32 eax = 0;
	u32 edx = 0;
	u8  family, model;

	/* Diff ZXC with ZXD */
	u32 leaf = 0x1;

	get_cpu_fms(&eax, &leaf);
	family = (eax & 0xf00) >> 8;  /* bit 11-08 */
	model = (eax & 0xf0) >> 4; /* bit 7-4 */

	edx = zx_gmi_capability();

	if (((family == 7) && (model == 0xb))
		|| ((family == 6) && (model == 0xf))
		|| ((family == 6) && (model == 9)))
		use_ccs = ((edx & (0x3 << 4)) == (0x3 << 4));
	else
		use_ccs = 0;

	return use_ccs;
}

void sm3_generic_block_fn(struct sm3_state *sst, const u8 *inp, int blockcnt)
{
	u64 in, out, cnt;

	if (!inp) {
		pr_warn("GMI-SM3: input is null\n");
		return;
	}

	if (!(sst)) {
		pr_warn("GMI-SM3: sst is null\n");
		return;
	}

	if (!blockcnt) {
		pr_warn("GMI-SM3: cnt is 0\n");
		return;
	}

	in  = (u64)inp;
	out = (u64)(sst->state);
	cnt = (u64)blockcnt;

	//printk(KERN_INFO "ZX-GMI-SM3 is called\n");

	__asm__ __volatile__(
		"movq %2, %%rdi\n"
		"movq %0, %%rsi\n"
		"movq %1, %%rcx\n"
		"movq $-1, %%rax\n"
		"movq $0x20, %%rbx\n"
		".byte 0xf3, 0x0f, 0xa6, 0xe8"
		:
		: "r"(in), "r"(cnt), "r"(out)
		: "%rdi", "%rsi", "%rcx", "rbx", "%rax", "memory"
	);
}

static inline int zx_sm3_init(struct shash_desc *desc)
{
	struct sm3_state *sctx;

	if (!desc)
		return -EINVAL;

	sctx = shash_desc_ctx(desc);

	sctx->state[0] = 0x6f168073UL;
	sctx->state[1] = 0xb9b21449UL;
	sctx->state[2] = 0xd7422417UL;
	sctx->state[3] = 0x00068adaUL;
	sctx->state[4] = 0xbc306fa9UL;
	sctx->state[5] = 0xaa383116UL;
	sctx->state[6] = 0x4dee8de3UL;
	sctx->state[7] = 0x4e0efbb0UL;

	sctx->count = 0;

	return 0;
}

static inline int zx_sm3_base_finish(struct shash_desc *desc, u8 *out)
{
	struct sm3_state *sctx = shash_desc_ctx(desc);
	__be32 *digest = (__be32 *)out;

	memcpy(digest, sctx->state, 32);

	*sctx = (struct sm3_state){};
	return 0;
}

int zx_sm3_update(struct shash_desc *desc, const u8 *data,
		unsigned int len)
{
	if (!data || !len)
		return -EINVAL;

	return sm3_base_do_update(desc, data, len, sm3_generic_block_fn);
}
EXPORT_SYMBOL(zx_sm3_update);

static int zx_sm3_final(struct shash_desc *desc, u8 *out)
{
	if (!desc || !out)
		return -EINVAL;

	sm3_base_do_finalize(desc, sm3_generic_block_fn);

	return zx_sm3_base_finish(desc, out);
}

int zx_sm3_finup(struct shash_desc *desc, const u8 *data,
	unsigned int len, u8 *hash)
{
	if (!desc || !data || !len || !hash)
		return -EINVAL;

	sm3_base_do_update(desc, data, len, sm3_generic_block_fn);

	return zx_sm3_final(desc, hash);
}
EXPORT_SYMBOL(zx_sm3_finup);

static struct shash_alg zx_sm3_alg = {
	.digestsize	= SM3_DIGEST_SIZE,
	.init		= zx_sm3_init,
	.update		= zx_sm3_update,
	.final		= zx_sm3_final,
	.finup		= zx_sm3_finup,
	.descsize	= sizeof(struct sm3_state),
	.base = {
		.cra_name			= "sm3",
		.cra_driver_name	= "zhaoxin-gmi-sm3",
		.cra_priority		= 300,
		.cra_blocksize		= SM3_BLOCK_SIZE,
		.cra_module			= THIS_MODULE,
	}
};

static int __init zx_sm3_generic_mod_init(void)
{
	if (!gmi_available()) {
		pr_warn("GMI is unavailable on this platform.");
		return -ENODEV;
	}
	return crypto_register_shash(&zx_sm3_alg);
}

static void __exit zx_sm3_generic_mod_fini(void)
{
	crypto_unregister_shash(&zx_sm3_alg);
}

module_init(zx_sm3_generic_mod_init);
module_exit(zx_sm3_generic_mod_fini);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("SM3 Secure Hash Algorithm");

MODULE_ALIAS_CRYPTO("zx-sm3");
MODULE_ALIAS_CRYPTO("zhaoxin-gmi-sm3");
