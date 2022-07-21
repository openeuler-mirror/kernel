// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2016-2017 Hisilicon Limited.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */


#include <linux/types.h>
#include <linux/module.h>
#include <linux/crc-t10dif.h>
#include <crypto/internal/hash.h>
#include <linux/init.h>
#include <linux/string.h>
#include <linux/kernel.h>

asmlinkage __u16 crc_t10dif_neon(__u16 crc, const unsigned char *buf,
				size_t len);

struct chksum_desc_ctx {
	__u16 crc;
};

/*
 * Steps through buffer one byte at at time, calculates reflected
 * crc using table.
 */

static int chksum_init(struct shash_desc *desc)
{
	struct chksum_desc_ctx *ctx = shash_desc_ctx(desc);

	ctx->crc = 0;

	return 0;
}

static int chksum_update(struct shash_desc *desc, const u8 *data,
			 unsigned int length)
{
	struct chksum_desc_ctx *ctx = shash_desc_ctx(desc);

	ctx->crc = crc_t10dif_neon(ctx->crc, data, length);
	return 0;
}

static int chksum_final(struct shash_desc *desc, u8 *out)
{
	struct chksum_desc_ctx *ctx = shash_desc_ctx(desc);

	*(__u16 *)out = ctx->crc;
	return 0;
}

static int __chksum_finup(__u16 crc, const u8 *data, unsigned int len,
			u8 *out)
{
	*(__u16 *)out = crc_t10dif_neon(crc, data, len);
	return 0;
}

static int chksum_finup(struct shash_desc *desc, const u8 *data,
			unsigned int len, u8 *out)
{
	struct chksum_desc_ctx *ctx = shash_desc_ctx(desc);

	return __chksum_finup(ctx->crc, data, len, out);
}

static int chksum_digest(struct shash_desc *desc, const u8 *data,
			 unsigned int length, u8 *out)
{
	return __chksum_finup(0, data, length, out);
}

static struct shash_alg alg = {
	.digestsize		=	CRC_T10DIF_DIGEST_SIZE,
	.init		=	chksum_init,
	.update		=	chksum_update,
	.final		=	chksum_final,
	.finup		=	chksum_finup,
	.digest		=	chksum_digest,
	.descsize		=	sizeof(struct chksum_desc_ctx),
	.base			=	{
		.cra_name		=	"crct10dif",
		.cra_driver_name	=	"crct10dif-neon",
		.cra_priority		=	200,
		.cra_blocksize		=	CRC_T10DIF_BLOCK_SIZE,
		.cra_module		=	THIS_MODULE,
	}
};

static int __init crct10dif_arm64_mod_init(void)
{
	if (cpu_have_named_feature(PMULL)) {
		return crypto_register_shash(&alg);
	} else {
		return -ENODEV;
	}
}

static void __exit crct10dif_arm64_mod_fini(void)
{
	crypto_unregister_shash(&alg);
}

module_init(crct10dif_arm64_mod_init);
module_exit(crct10dif_arm64_mod_fini);

MODULE_AUTHOR("YueHaibing <yuehaibing@huawei.com>");
MODULE_DESCRIPTION("T10 DIF CRC calculation accelerated with ARM64 NEON instruction.");
MODULE_LICENSE("GPL");

MODULE_ALIAS_CRYPTO("crct10dif");
MODULE_ALIAS_CRYPTO("crct10dif-neon");
