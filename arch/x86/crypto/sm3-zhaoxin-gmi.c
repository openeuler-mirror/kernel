// SPDX-License-Identifier: GPL-2.0
/*
 * sm3_zhaoxin_gmi.c - wrapper code for Zhaoxin GMI.
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
#include <linux/cpufeature.h>
#include <linux/processor.h>


const u8 zx_sm3_zero_message_hash[SM3_DIGEST_SIZE] = {
	0x1A, 0xB2, 0x1D, 0x83, 0x55, 0xCF, 0xA1, 0x7F,
	0x8e, 0x61, 0x19, 0x48, 0x31, 0xE8, 0x1A, 0x8F,
	0x22, 0xBE, 0xC8, 0xC7, 0x28, 0xFE, 0xFB, 0x74,
	0x7E, 0xD0, 0x35, 0xEB, 0x50, 0x82, 0xAA, 0x2B
};
EXPORT_SYMBOL_GPL(zx_sm3_zero_message_hash);

/*
 * Load supported features of the CPU to see if the SM3/SM4 is available.
 */
static int gmi_available(void)
{
	struct cpuinfo_x86 *c = &cpu_data(0);
	u32 eax, edx;

	if (((c->x86 == 6) && (c->x86_model >= 0x0f))
		|| ((c->x86 == 6) && (c->x86_model == 0x09))
		|| (c->x86 > 6)) {

		if (!boot_cpu_has(X86_FEATURE_CCS) ||
			!boot_cpu_has(X86_FEATURE_CCS_EN)) {

			eax = 0xC0000001;
			__asm__ __volatile__ ("cpuid":"=d"(edx):"a"(eax) : );

			if ((edx & 0x0030) != 0x0030)
				return -ENODEV;

			pr_notice("GMI SM3 detected by CPUID\n");
			return 0;
		}
		pr_notice("GMI SM3 is available\n");
		return 0;
	}
	return -ENODEV;
}

void sm3_generic_block_fn(struct sm3_state *sst, const u8 *inp, int blockcnt)
{
	unsigned long in, out, cnt;

	if (!blockcnt)
		return;

	in  = (unsigned long)inp;
	out = (unsigned long)(sst->state);
	cnt = (unsigned long)blockcnt;

	__asm__ __volatile__(
		#ifdef __x86_64__
			"pushq %%rbp\n"
			"pushq %%rbx\n"
			"pushq %%rsi\n"
			"pushq %%rdi\n"
			"movq $-1, %%rax\n"
			"movq $0x20, %%rbx\n"
      #else
			"pushl %%ebp\n"
			"pushl %%ebx\n"
			"pushl %%esi\n"
			"pushl %%edi\n"
			"movl $-1, %%eax\n"
			"movl $0x20, %%ebx\n"
		#endif
		".byte 0xf3,0x0f,0xa6,0xe8\n"
		#ifdef __x86_64__
			"popq %%rdi\n"
			"popq %%rsi\n"
			"popq %%rbx\n"
			"popq %%rbp\n"
      #else
			"popl %%edi\n"
			"popl %%esi\n"
			"popl %%ebx\n"
			"popl %%ebp\n"
		#endif
		:
		: "S"(in), "D"(out), "c"(cnt)
		:
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

	memcpy(digest, sctx->state, SM3_DIGEST_SIZE);

	*sctx = (struct sm3_state){};
	return 0;
}

int zx_sm3_update(struct shash_desc *desc, const u8 *data,
		unsigned int len)
{
	return sm3_base_do_update(desc, data, len, sm3_generic_block_fn);
}
EXPORT_SYMBOL(zx_sm3_update);

static int zx_sm3_final(struct shash_desc *desc, u8 *out)
{
	sm3_base_do_finalize(desc, sm3_generic_block_fn);

	return zx_sm3_base_finish(desc, out);
}

int zx_sm3_finup(struct shash_desc *desc, const u8 *data,
	unsigned int len, u8 *hash)
{
	sm3_base_do_update(desc, data, len, sm3_generic_block_fn);

	return zx_sm3_final(desc, hash);
}
EXPORT_SYMBOL(zx_sm3_finup);

static struct shash_alg zx_sm3_alg = {
	.digestsize = SM3_DIGEST_SIZE,
	.init     = zx_sm3_init,
	.update   = zx_sm3_update,
	.final    = zx_sm3_final,
	.finup    = zx_sm3_finup,
	.descsize = sizeof(struct sm3_state),
	.base   = {
		.cra_name        =  "sm3",
		.cra_driver_name =  "sm3-zhaoxin-gmi",
		.cra_priority    =  300,
		.cra_blocksize   =  SM3_BLOCK_SIZE,
		.cra_module      =  THIS_MODULE,
	}
};

static int __init zx_sm3_generic_mod_init(void)
{
	if (gmi_available() == 0)
		return crypto_register_shash(&zx_sm3_alg);

	pr_warn("GMI is unavailable on this platform.");
	return -ENODEV;
}

static void __exit zx_sm3_generic_mod_fini(void)
{
	crypto_unregister_shash(&zx_sm3_alg);
}

module_init(zx_sm3_generic_mod_init);
module_exit(zx_sm3_generic_mod_fini);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("SM3 Secure Hash Algorithm");

MODULE_ALIAS_CRYPTO("sm3-zhaoxin");
MODULE_ALIAS_CRYPTO("sm3-zhaoxin-gmi");
