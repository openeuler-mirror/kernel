// SPDX-License-Identifier: GPL-2.0
/*
 * crc32.c - CRC32 and CRC32C using LoongArch crc* instructions
 *
 * Module based on mips/crypto/crc32-mips.c
 *
 * Copyright (C) 2014 Linaro Ltd <yazen.ghannam@linaro.org>
 * Copyright (C) 2018 MIPS Tech, LLC
 * Copyright (C) 2020-2023 Loongson Technology Corporation Limited
 */

#include <linux/crc32.h>
#include <linux/module.h>
#include <crypto/internal/hash.h>

#include <asm/cpu-features.h>
#include <asm/unaligned.h>

#define CHKSUM_BLOCK_SIZE	1
#define CHKSUM_DIGEST_SIZE	4

struct chksum_ctx {
	u32 key;
};

struct chksum_desc_ctx {
	u32 crc;
};

static int chksum_init(struct shash_desc *desc)
{
	struct chksum_ctx *mctx = crypto_shash_ctx(desc->tfm);
	struct chksum_desc_ctx *ctx = shash_desc_ctx(desc);

	ctx->crc = mctx->key;

	return 0;
}

/*
 * Setting the seed allows arbitrary accumulators and flexible XOR policy
 * If your algorithm starts with ~0, then XOR with ~0 before you set the seed.
 */
static int chksum_setkey(struct crypto_shash *tfm, const u8 *key, unsigned int keylen)
{
	struct chksum_ctx *mctx = crypto_shash_ctx(tfm);

	if (keylen != sizeof(mctx->key))
		return -EINVAL;

	mctx->key = get_unaligned_le32(key);

	return 0;
}

static int chksum_update(struct shash_desc *desc, const u8 *data, unsigned int length)
{
	struct chksum_desc_ctx *ctx = shash_desc_ctx(desc);

	ctx->crc = crc32_le(ctx->crc, data, length);
	return 0;
}

static int chksumc_update(struct shash_desc *desc, const u8 *data, unsigned int length)
{
	struct chksum_desc_ctx *ctx = shash_desc_ctx(desc);

	ctx->crc = __crc32c_le(ctx->crc, data, length);
	return 0;
}

static int chksum_final(struct shash_desc *desc, u8 *out)
{
	struct chksum_desc_ctx *ctx = shash_desc_ctx(desc);

	put_unaligned_le32(ctx->crc, out);
	return 0;
}

static int chksumc_final(struct shash_desc *desc, u8 *out)
{
	struct chksum_desc_ctx *ctx = shash_desc_ctx(desc);

	put_unaligned_le32(~ctx->crc, out);
	return 0;
}

static int __chksum_finup(u32 crc, const u8 *data, unsigned int len, u8 *out)
{
	put_unaligned_le32(crc32_le(crc, data, len), out);
	return 0;
}

static int __chksumc_finup(u32 crc, const u8 *data, unsigned int len, u8 *out)
{
	put_unaligned_le32(~__crc32c_le(crc, data, len), out);
	return 0;
}

static int chksum_finup(struct shash_desc *desc, const u8 *data, unsigned int len, u8 *out)
{
	struct chksum_desc_ctx *ctx = shash_desc_ctx(desc);

	return __chksum_finup(ctx->crc, data, len, out);
}

static int chksumc_finup(struct shash_desc *desc, const u8 *data, unsigned int len, u8 *out)
{
	struct chksum_desc_ctx *ctx = shash_desc_ctx(desc);

	return __chksumc_finup(ctx->crc, data, len, out);
}

static int chksum_digest(struct shash_desc *desc, const u8 *data, unsigned int length, u8 *out)
{
	struct chksum_ctx *mctx = crypto_shash_ctx(desc->tfm);

	return __chksum_finup(mctx->key, data, length, out);
}

static int chksumc_digest(struct shash_desc *desc, const u8 *data, unsigned int length, u8 *out)
{
	struct chksum_ctx *mctx = crypto_shash_ctx(desc->tfm);

	return __chksumc_finup(mctx->key, data, length, out);
}

static int chksum_cra_init(struct crypto_tfm *tfm)
{
	struct chksum_ctx *mctx = crypto_tfm_ctx(tfm);

	mctx->key = 0;
	return 0;
}

static int chksumc_cra_init(struct crypto_tfm *tfm)
{
	struct chksum_ctx *mctx = crypto_tfm_ctx(tfm);

	mctx->key = ~0;
	return 0;
}

static struct shash_alg crc32_alg = {
	.digestsize		=	CHKSUM_DIGEST_SIZE,
	.setkey			=	chksum_setkey,
	.init			=	chksum_init,
	.update			=	chksum_update,
	.final			=	chksum_final,
	.finup			=	chksum_finup,
	.digest			=	chksum_digest,
	.descsize		=	sizeof(struct chksum_desc_ctx),
	.base			=	{
		.cra_name		=	"crc32",
		.cra_driver_name	=	"crc32-loongarch",
		.cra_priority		=	300,
		.cra_flags		=	CRYPTO_ALG_OPTIONAL_KEY,
		.cra_blocksize		=	CHKSUM_BLOCK_SIZE,
		.cra_alignmask		=	0,
		.cra_ctxsize		=	sizeof(struct chksum_ctx),
		.cra_module		=	THIS_MODULE,
		.cra_init		=	chksum_cra_init,
	}
};

static struct shash_alg crc32c_alg = {
	.digestsize		=	CHKSUM_DIGEST_SIZE,
	.setkey			=	chksum_setkey,
	.init			=	chksum_init,
	.update			=	chksumc_update,
	.final			=	chksumc_final,
	.finup			=	chksumc_finup,
	.digest			=	chksumc_digest,
	.descsize		=	sizeof(struct chksum_desc_ctx),
	.base			=	{
		.cra_name		=	"crc32c",
		.cra_driver_name	=	"crc32c-loongarch",
		.cra_priority		=	300,
		.cra_flags		=	CRYPTO_ALG_OPTIONAL_KEY,
		.cra_blocksize		=	CHKSUM_BLOCK_SIZE,
		.cra_alignmask		=	0,
		.cra_ctxsize		=	sizeof(struct chksum_ctx),
		.cra_module		=	THIS_MODULE,
		.cra_init		=	chksumc_cra_init,
	}
};

static int __init crc32_mod_init(void)
{
	int err;

	if (!cpu_has(CPU_FEATURE_CRC32))
		return 0;

	err = crypto_register_shash(&crc32_alg);
	if (err)
		return err;

	err = crypto_register_shash(&crc32c_alg);
	if (err)
		return err;

	return 0;
}

static void __exit crc32_mod_exit(void)
{
	if (!cpu_has(CPU_FEATURE_CRC32))
		return;

	crypto_unregister_shash(&crc32_alg);
	crypto_unregister_shash(&crc32c_alg);
}

module_init(crc32_mod_init);
module_exit(crc32_mod_exit);

MODULE_AUTHOR("Min Zhou <zhoumin@loongson.cn>");
MODULE_AUTHOR("Huacai Chen <chenhuacai@loongson.cn>");
MODULE_DESCRIPTION("CRC32 and CRC32C using LoongArch crc* instructions");
MODULE_LICENSE("GPL v2");
