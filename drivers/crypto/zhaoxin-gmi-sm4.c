// SPDX-License-Identifier: GPL-2.0-only
/*
 * zhaoxin-gmi-sm4.c - wrapper code for Zhaoxin GMI.
 *
 * Copyright (C) 2023 Shanghai Zhaoxin Semiconductor LTD.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/types.h>
#include <linux/module.h>
#include <linux/err.h>
#include <crypto/cryptd.h>
#include <crypto/scatterwalk.h>
#include <crypto/algapi.h>
#include <crypto/internal/simd.h>
#include <crypto/internal/skcipher.h>
#include <linux/workqueue.h>
#include <crypto/sm4.h>
#include <asm/unaligned.h>

#define SM4_ECB  (1<<6)
#define SM4_CBC  (1<<7)
#define SM4_CFB  (1<<8)
#define SM4_OFB  (1<<9)
#define SM4_CTR  (1<<10)

#define ZX_GMI_ALIGNMENT 16

#define GETU16(p)  ((u16)(p)[0]<<8 | (u16)(p)[1])
#define GETU32(p)  ((u32)(p)[0]<<24|(u32)(p)[1]<<16|(u32)(p)[2]<<8|(u32)(p)[3])

/* Control word. */
struct sm4_cipher_data {
	u8 iv[SM4_BLOCK_SIZE]; /* Initialization vector */
	union {
		u32 pad;
		struct {
			u32 encdec:1;
			u32 func:5;
			u32 mode:5;
			u32 digest:1;
		} b;
	} cword;                    /* Control word */
	struct crypto_sm4_ctx  keys;  /* Encryption key */
};

static inline u8 *rep_xcrypt(const u8 *input, u8 *output, void *key, u8 *iv,
				struct sm4_cipher_data *sm4_data, int count)
{
	int eax = sm4_data->cword.pad;

    // Set the flag for encryption or decryption
	if (sm4_data->cword.b.encdec == 1)
		eax &= ~0x01;
	else
		eax |= 0x01;

	asm volatile (".byte 0xf3, 0x0f, 0xa7, 0xf0"  /* rep xcryptcbc */
		: "+S" (input), "+D" (output), "+a" (eax)
		: "d" (iv), "b" (key), "c" (count));

	return iv;
}

static inline u8 *rep_xcrypt_ctr(const u8 *input, u8 *output, void *key, u8 *iv,
				struct sm4_cipher_data *sm4_data, int count)
{
	int eax = sm4_data->cword.pad;
	u8 oiv[SM4_BLOCK_SIZE] = {0};
	u32 cnt_tmp;
	u32 i;

    //Backup the original IV if it is not NULL.
	if (iv)
		memcpy(oiv,  iv, SM4_BLOCK_SIZE);

	// Set the flag for encryption or decryption
	if (sm4_data->cword.b.encdec == 1)
		eax &= ~0x01;
	else
		eax |= 0x01;

	// Get the current counter.
	cnt_tmp = GETU16(&iv[14]);

	// Get the available counter space before overflow.
	cnt_tmp = 0x10000 - cnt_tmp;

	//
	// Check there is enough counter space for the required blocks.
	//
	if (cnt_tmp < count) {

		// Process the first part of data blocks.
		asm volatile (".byte 0xf3,0x0f,0xa7,0xf0"  /* rep xcryptcbc */
			: "+S" (input), "+D" (output), "+a" (eax)
			: "d" (iv), "b" (key), "c" (cnt_tmp));

		// The IV's lower 16 bits should be 0x0000 NOW. Check it
		//if (GETU16(&iv[14]) != 0)
		//	printk(KERN_WARNING "ZX-GMI: Counter should be 0, please check\n");

		// Only increase the counter by SW when overflow occurs.
		memcpy(iv, oiv, SM4_BLOCK_SIZE);
		for (i = 0; i < cnt_tmp; i++)
			crypto_inc(iv, SM4_BLOCK_SIZE);

		// Get the number of data blocks that have not beed encrypted.
		cnt_tmp = count - cnt_tmp;

		// Process the remaining part of data blocks.
		asm volatile (".byte 0xf3,0x0f,0xa7,0xf0"  /* rep xcryptcbc */
			: "+S" (input), "+D" (output), "+a" (eax)
			: "d" (iv), "b" (key), "c" (cnt_tmp));
	} else {
		// Counter space is big enough, the counter will not overflow.
		asm volatile (".byte 0xf3,0x0f,0xa7,0xf0"  /* rep xcryptcbc */
			: "+S" (input), "+D" (output), "+a" (eax)
			: "d" (iv), "b" (key), "c" (count));
	}

	// Restore the iv if not null
	if (iv)
		memcpy(iv, oiv, SM4_BLOCK_SIZE);

	return iv;
}

static u8 *rep_xcrypt_ebc_ONE(const u8 *input, u8 *output, void *key,
						u8 *iv, struct sm4_cipher_data *sm4_data, int count)
{
	u64 in, out, enkey, ivec;

	in  = (u64)input;
	out = (u64)(output);
	enkey = (u64)key;
	ivec = (u64)iv;

	__asm__ __volatile__(
		"movq %2, %%rdi\n"
		"movq %0, %%rsi\n"
		"movq $1, %%rcx\n"
		"movq $0x60, %%rax\n"
		"movq %1, %%rbx\n"
		"movq %3, %%rdx\n"
		".byte 0xf3, 0x0f, 0xa7, 0xf0"
		:
		: "r"(in), "r"(enkey), "r"(out), "r"(ivec)
		: "%rdi", "%rsi", "%rdx", "%rcx", "rbx", "%rax", "memory"
	);

	return iv;
}

/**
 * gmi_sm4_set_key - Set the sm4 key.
 * @tfm:  The %crypto_skcipher that is used in the context.
 * @in_key: The input key.
 * @key_len:The size of the key.
 */
int gmi_sm4_set_key(struct crypto_skcipher  *tfm, const u8 *in_key,
					unsigned int key_len)
{
	struct crypto_sm4_ctx *ctx = crypto_skcipher_ctx(tfm);

	if (key_len != SM4_KEY_SIZE) {
		pr_err("The key_len must be 16 bytes. please check\n");
		return -EINVAL;
	}

	memcpy(ctx->rkey_enc, in_key, key_len);
	memcpy(ctx->rkey_dec, in_key, key_len);

	return 0;
}
EXPORT_SYMBOL_GPL(gmi_sm4_set_key);


static int sm4_cipher_common(struct skcipher_request *req, struct sm4_cipher_data *cw)
{
	struct crypto_skcipher *tfm = crypto_skcipher_reqtfm(req);
	struct crypto_sm4_ctx *ctx = crypto_skcipher_ctx(tfm);
	struct skcipher_walk walk;
	unsigned int blocks;
	int err;
	u8 *iv;

	err = skcipher_walk_virt(&walk, req, true);

	while ((blocks = (walk.nbytes / SM4_BLOCK_SIZE))) {
		iv = rep_xcrypt(walk.src.virt.addr, walk.dst.virt.addr, ctx->rkey_enc,
						walk.iv, cw, blocks);

		err = skcipher_walk_done(&walk, walk.nbytes % SM4_BLOCK_SIZE);
	}

	return err;
}


static int ebc_encrypt(struct skcipher_request *req)
{
	int err;
	struct sm4_cipher_data cw;

	cw.cword.pad      = 0;
	cw.cword.b.encdec = 1;
	cw.cword.pad     |= 0x20|SM4_ECB;

	err = sm4_cipher_common(req, &cw);

	return err;
}

static int ebc_decrypt(struct skcipher_request *req)
{
	int err;
	struct sm4_cipher_data cw;

	cw.cword.pad  = 0;
	cw.cword.pad |= 0x20|SM4_ECB;

	err = sm4_cipher_common(req, &cw);

	return err;
}

static int cbc_encrypt(struct skcipher_request *req)
{
	int err;
	struct sm4_cipher_data cw;

	cw.cword.pad      = 0;
	cw.cword.b.encdec = 1;
	cw.cword.pad     |= 0x20|SM4_CBC;

	err = sm4_cipher_common(req, &cw);

	return err;
}

static int cbc_decrypt(struct skcipher_request *req)
{
	int err;
	struct sm4_cipher_data cw;

	cw.cword.pad  = 0;
	cw.cword.pad |= 0x20|SM4_CBC;

	err = sm4_cipher_common(req, &cw);

	return err;
}

static void ctr_crypt_final(struct crypto_sm4_ctx *ctx,
							struct skcipher_walk *walk)
{
	u8 *ctrblk = walk->iv;
	u8 keystream[SM4_BLOCK_SIZE];
	u8 *src = walk->src.virt.addr;
	u8 *dst = walk->dst.virt.addr;
	u8 iv_temp[16];
	unsigned int nbytes = walk->nbytes;
	struct sm4_cipher_data cw;

	cw.cword.pad      = 0;
	cw.cword.b.encdec = 1;
	cw.cword.pad     |= 0x20|SM4_ECB;

	memcpy(iv_temp, ctrblk, 16);

	rep_xcrypt_ebc_ONE(ctrblk, keystream, ctx->rkey_enc, walk->iv, &cw, 1);

	crypto_xor_cpy(dst, keystream, src, nbytes);

	crypto_inc(ctrblk, SM4_BLOCK_SIZE);
}

/*
 *  sm4_cipher_ctr is usef for ZX-E or newer
 */
static int sm4_cipher_ctr(struct skcipher_request *req, struct sm4_cipher_data *cw)
{
	struct crypto_skcipher *tfm = crypto_skcipher_reqtfm(req);
	struct crypto_sm4_ctx *ctx = crypto_skcipher_ctx(tfm);
	struct skcipher_walk walk;
	unsigned int blocks;
	int err;
	u8 *iv;
	u32 i;

	err = skcipher_walk_virt(&walk, req, true);

	while ((blocks = (walk.nbytes / SM4_BLOCK_SIZE))) {
		iv = rep_xcrypt_ctr(walk.src.virt.addr, walk.dst.virt.addr,
		ctx->rkey_enc, walk.iv, cw, blocks);

		// Update the counter.
		for (i = 0; i < blocks; i++)
			crypto_inc(walk.iv, SM4_BLOCK_SIZE);

		err = skcipher_walk_done(&walk, walk.nbytes % SM4_BLOCK_SIZE);
	}

	if (walk.nbytes) {
		ctr_crypt_final(ctx, &walk);
		err = skcipher_walk_done(&walk, 0);
	}

	return err;
}

/*
 *  ctr_encrypt is usef for ZX-E or newer
 */
static int ctr_encrypt(struct skcipher_request *req)
{
	int err;
	struct sm4_cipher_data cw;

	cw.cword.pad      = 0;
	cw.cword.b.encdec = 1;
	cw.cword.pad     |= 0x20|SM4_CTR;

	err = sm4_cipher_ctr(req, &cw);

	return err;
}

/*
 *  ctr_decrypt is usef for ZX-E or newer
 */
static int ctr_decrypt(struct skcipher_request *req)
{
	int err;
	struct sm4_cipher_data cw;

	cw.cword.pad  = 0;
	cw.cword.pad |= 0x20|SM4_CTR;

	err = sm4_cipher_ctr(req, &cw);

	return err;
}

/*
 *  sm4_ctr_zxc is used for ZXC+
 */
static int sm4_ctr_zxc(struct skcipher_request *req, struct sm4_cipher_data *cw)
{
	struct crypto_skcipher *tfm = crypto_skcipher_reqtfm(req);
	struct crypto_sm4_ctx *ctx = crypto_skcipher_ctx(tfm);
	struct skcipher_walk walk;
	unsigned int blocks;
	int err;
	u8 *iv = NULL;
	u32 n;
	u8 en_iv[SM4_BLOCK_SIZE] = {0};

	err = skcipher_walk_virt(&walk, req, true);

	while ((blocks = (walk.nbytes / SM4_BLOCK_SIZE))) {
		while (blocks--) {

			iv = rep_xcrypt_ebc_ONE(walk.iv, en_iv, ctx->rkey_enc, walk.iv, cw, 1);
			crypto_inc(walk.iv, SM4_BLOCK_SIZE);

			for (n = 0; n < 16; n += sizeof(size_t))
				*(size_t *)(walk.dst.virt.addr + n) = *(size_t *)(en_iv + n)
				^ *(size_t *)(walk.src.virt.addr + n);

			walk.src.virt.addr += SM4_BLOCK_SIZE;
			walk.dst.virt.addr += SM4_BLOCK_SIZE;

		}

		err = skcipher_walk_done(&walk, walk.nbytes % SM4_BLOCK_SIZE);
	}

	if (walk.nbytes) {
		ctr_crypt_final(ctx, &walk);
		err = skcipher_walk_done(&walk, 0);
	}

	return err;
}

/*
 * ctr_encrypt_zxc is usef for ZX-C+
 */
static int ctr_encrypt_zxc(struct skcipher_request *req)
{
	int err;
	struct sm4_cipher_data cw;

	cw.cword.pad      = 0;
	cw.cword.b.encdec = 1;
	cw.cword.pad     |= 0x20|SM4_CTR;

	err = sm4_ctr_zxc(req, &cw);

	return err;
}

/*
 * ctr_decrypt_zxc is usef for ZX-C+
 */
static int ctr_decrypt_zxc(struct skcipher_request *req)
{
	int err;
	struct sm4_cipher_data cw;

	cw.cword.pad      = 0;
	cw.cword.b.encdec = 0;
	cw.cword.pad     |= 0x20|SM4_CTR;

	err = sm4_ctr_zxc(req, &cw);

	return err;
}

/*
 *  ofb_encrypt is usef for ZX-E or newer
 */
static int ofb_encrypt(struct skcipher_request *req)
{
	int err;
	struct sm4_cipher_data cw;

	cw.cword.pad      = 0;
	cw.cword.b.encdec = 1;
	cw.cword.pad     |= 0x20|SM4_OFB;

	err = sm4_cipher_common(req, &cw);

	return err;
}

/*
 *  ofb_decrypt is usef for ZX-E or newer
 */
static int ofb_decrypt(struct skcipher_request *req)
{
	int err;
	struct sm4_cipher_data cw;

	cw.cword.pad  = 0;
	cw.cword.pad |= 0x20|SM4_OFB;

	err = sm4_cipher_common(req, &cw);

	return err;
}

/*
 * sm4_ofb_zxc is usef for ZX-C+
 */
static int sm4_ofb_zxc(struct skcipher_request *req, struct sm4_cipher_data *cw)
{
	struct crypto_skcipher *tfm = crypto_skcipher_reqtfm(req);
	struct crypto_sm4_ctx *ctx = crypto_skcipher_ctx(tfm);
	struct skcipher_walk walk;
	unsigned int blocks;
	int err;
	u8 *iv = NULL;
	u32 n;

	err = skcipher_walk_virt(&walk, req, true);

	while ((blocks = (walk.nbytes / SM4_BLOCK_SIZE))) {
		while (blocks--) {
			iv = rep_xcrypt_ebc_ONE(walk.iv, walk.iv, ctx->rkey_enc, walk.iv, cw, 1);

			for (n = 0; n < 16; n += sizeof(size_t))
				*(size_t *)(walk.dst.virt.addr + n) = *(size_t *)(walk.iv + n)
				^ *(size_t *)(walk.src.virt.addr + n);

			walk.src.virt.addr += SM4_BLOCK_SIZE;
			walk.dst.virt.addr += SM4_BLOCK_SIZE;

		}

		err = skcipher_walk_done(&walk, walk.nbytes % SM4_BLOCK_SIZE);
	}

	return err;
}

/*
 *  ofb_encrypt_zxc is usef for ZX-C+
 */
static int ofb_encrypt_zxc(struct skcipher_request *req)
{
	int err;
	struct sm4_cipher_data cw;

	cw.cword.pad      = 0;
	cw.cword.b.encdec = 1;
	cw.cword.pad     |= 0x20|SM4_OFB;

	err = sm4_ofb_zxc(req, &cw);

	return err;
}

/*
 * ofb_decrypt_zxc is usef for ZX-C+
 */
static int ofb_decrypt_zxc(struct skcipher_request *req)
{
	int err;
	struct sm4_cipher_data cw;

	cw.cword.pad      = 0;
	cw.cword.b.encdec = 0;
	cw.cword.pad     |= 0x20|SM4_OFB;

	err = sm4_ofb_zxc(req, &cw);

	return err;
}


/*
 * cfb_encrypt is usef for ZX-E or newer.
 */
static int cfb_encrypt(struct skcipher_request *req)
{
	int err;
	struct sm4_cipher_data cw;

	cw.cword.pad      = 0;
	cw.cword.b.encdec = 1;
	cw.cword.pad     |= 0x20|SM4_CFB;

	err = sm4_cipher_common(req, &cw);

	return err;
}

/*
 * cfb_decrypt is usef for ZX-E or newer.
 */

static int cfb_decrypt(struct skcipher_request *req)
{
	int err;
	struct sm4_cipher_data cw;

	cw.cword.pad  = 0;
	cw.cword.pad |= 0x20|SM4_CFB;

	err = sm4_cipher_common(req, &cw);

	return err;

}

/*
 * sm4_cfb_zxc is usef for ZX-C+
 */
static int sm4_cfb_zxc(struct skcipher_request *req, struct sm4_cipher_data *cw)
{
	struct crypto_skcipher *tfm = crypto_skcipher_reqtfm(req);
	struct crypto_sm4_ctx *ctx = crypto_skcipher_ctx(tfm);
	struct skcipher_walk walk;
	unsigned int blocks;
	int err;
	u8 *iv = NULL;
	u32 n;
	size_t t;

	err = skcipher_walk_virt(&walk, req, true);

	while ((blocks = (walk.nbytes / SM4_BLOCK_SIZE))) {
		while (blocks--) {

			iv = rep_xcrypt_ebc_ONE(walk.iv, walk.iv, ctx->rkey_enc, walk.iv, cw, 1);

			if (cw->cword.b.encdec)
				for (n = 0; n < 16; n += sizeof(size_t))
					*(size_t *)(walk.dst.virt.addr + n) =
						*(size_t *)(walk.iv + n)
					^= *(size_t *)(walk.src.virt.addr + n);
			else
				for (n = 0; n < 16; n += sizeof(size_t)) {
					t = *(size_t *)(walk.src.virt.addr + n);
					*(size_t *)(walk.dst.virt.addr + n) =
						*(size_t *)(walk.iv + n) ^ t;
					*(size_t *)(walk.iv + n) = t;
				}

			walk.src.virt.addr += SM4_BLOCK_SIZE;
			walk.dst.virt.addr += SM4_BLOCK_SIZE;
		}

		err = skcipher_walk_done(&walk, walk.nbytes % SM4_BLOCK_SIZE);
	}

	return err;
}

/*
 * cfb_encrypt_zxc is usef for ZX-C+
 */
static int cfb_encrypt_zxc(struct skcipher_request *req)
{
	int err;
	struct sm4_cipher_data cw;

	cw.cword.pad      = 0;
	cw.cword.b.encdec = 1;
	cw.cword.pad     |= 0x20|SM4_CFB;

	err = sm4_cfb_zxc(req, &cw);

	return err;
}

/*
 * cfb_decrypt_zxc is usef for ZX-C+
 */
static int cfb_decrypt_zxc(struct skcipher_request *req)
{
	int err;
	struct sm4_cipher_data cw;

	cw.cword.pad      = 0;
	cw.cword.b.encdec = 0;
	cw.cword.pad     |= 0x20|SM4_CFB;

	err = sm4_cfb_zxc(req, &cw);

	return err;
}


static struct skcipher_alg aes_algs[] = {
	{
		.base = {
			.cra_name           = "__ecb(sm4)",
			.cra_driver_name    = "__ecb-sm4-gmi",
			.cra_priority       = 300,
			.cra_flags          = CRYPTO_ALG_INTERNAL,
			.cra_blocksize      = SM4_BLOCK_SIZE,
			.cra_ctxsize        = sizeof(struct crypto_sm4_ctx),
			.cra_module         = THIS_MODULE,
		},
		.min_keysize    = SM4_KEY_SIZE,
		.max_keysize    = SM4_KEY_SIZE,
		.ivsize         = SM4_BLOCK_SIZE,
		.setkey         = gmi_sm4_set_key,
		.encrypt        = ebc_encrypt,
		.decrypt        = ebc_decrypt,
	},

	{
		.base = {
			.cra_name           = "__cbc(sm4)",
			.cra_driver_name    = "__cbc-sm4-gmi",
			.cra_priority       = 300,
			.cra_flags          = CRYPTO_ALG_INTERNAL,
			.cra_blocksize      = SM4_BLOCK_SIZE,
			.cra_ctxsize        = sizeof(struct crypto_sm4_ctx),
			.cra_module         = THIS_MODULE,
		},
		.min_keysize    = SM4_KEY_SIZE,
		.max_keysize    = SM4_KEY_SIZE,
		.ivsize         = SM4_BLOCK_SIZE,
		.setkey         = gmi_sm4_set_key,
		.encrypt        = cbc_encrypt,
		.decrypt        = cbc_decrypt,
	},

	{
		.base = {
			.cra_name           = "__ctr(sm4)",
			.cra_driver_name    = "__ctr-sm4-gmi",
			.cra_priority       = 300,
			.cra_flags          = CRYPTO_ALG_INTERNAL,
			.cra_blocksize      = 1, //SM4_BLOCK_SIZE,
			.cra_ctxsize        = sizeof(struct crypto_sm4_ctx),
			.cra_module         = THIS_MODULE,
		},
		.min_keysize    = SM4_KEY_SIZE,
		.max_keysize    = SM4_KEY_SIZE,
		.ivsize         = SM4_BLOCK_SIZE,
		.setkey         = gmi_sm4_set_key,
		.encrypt        = ctr_encrypt,
		.decrypt        = ctr_decrypt,
	},

	{
		.base = {
			.cra_name           = "__ofb(sm4)",
			.cra_driver_name    = "__ofb-sm4-gmi",
			.cra_priority       = 300,
			.cra_flags          = CRYPTO_ALG_INTERNAL,
			.cra_blocksize      = SM4_BLOCK_SIZE,
			.cra_ctxsize        = sizeof(struct crypto_sm4_ctx),
			.cra_module         = THIS_MODULE,
		},
		.min_keysize    = SM4_KEY_SIZE,
		.max_keysize    = SM4_KEY_SIZE,
		.ivsize         = SM4_BLOCK_SIZE,
		.setkey         = gmi_sm4_set_key,
		.encrypt        = ofb_encrypt,
		.decrypt        = ofb_decrypt,
	},

	{
		.base = {
			.cra_name           = "__cfb(sm4)",
			.cra_driver_name    = "__cfb-sm4-gmi",
			.cra_priority       = 300,
			.cra_flags          = CRYPTO_ALG_INTERNAL,
			.cra_blocksize      = SM4_BLOCK_SIZE,
			.cra_ctxsize        = sizeof(struct crypto_sm4_ctx),
			.cra_module         = THIS_MODULE,
		},
		.min_keysize    = SM4_KEY_SIZE,
		.max_keysize    = SM4_KEY_SIZE,
		.ivsize         = SM4_BLOCK_SIZE,
		.setkey         = gmi_sm4_set_key,
		.encrypt        = cfb_encrypt,
		.decrypt        = cfb_decrypt,
	}
};

static struct simd_skcipher_alg *sm4_simd_algs[ARRAY_SIZE(aes_algs)];


static int zx_gmi_capability(void)
{
	int eax = 0;
	int ebx, ecx, edx = 0;
	// 1. check vendor ID string
	asm volatile ("cpuid":"=b"(ebx), "=c"(ecx), "=d"(edx):"a"(eax) : );

	if (((ebx == 0x746e6543) && (ecx == 0x736c7561) && (edx == 0x48727561)) ||
		((ebx == 0x68532020) && (ecx == 0x20206961) && (edx == 0x68676e61))) {
		// 2. check whether support SM3/SM4/SM2 Instructions
		eax = 0xC0000001;
		__asm__ __volatile__ ("cpuid":"=d"(edx):"a"(eax) : );

	} else {
		pr_warn("This is not a ZX CPU!\n");
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

static int gmi_zxc_check(void)
{
	u32 eax = 0;
	char family, model;
	u32 leaf = 0x1;
	int f_zxc = 0;

	get_cpu_fms(&eax, &leaf);
	family = (eax & 0xf00) >> 8;  /* bit 11-08 */
	model = (eax & 0xf0) >> 4; /* bit 7-4 */

	if ((family == 7) && (model == 0xb))
		f_zxc = 0;
	else if (((family == 6) && (model == 0xf)) ||
			((family == 6) && (model == 9)))
		f_zxc = 1;

	return f_zxc;
}

/*
 * Load supported features of the CPU to see if the SM3/SM4 is available.
 */
static int gmi_ccs_available(void)
{
	unsigned int zx_gmi_use_ccs = 0; /* Chinese Cipher Standard SM3 and SM4 Support */

	zx_gmi_use_ccs = ((zx_gmi_capability() & (0x3 << 4)) == (0x3 << 4));

	return zx_gmi_use_ccs;
}

static void gmi_sm4_exit(void)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(sm4_simd_algs) && sm4_simd_algs[i]; i++)
		simd_skcipher_free(sm4_simd_algs[i]);

	crypto_unregister_skciphers(aes_algs, ARRAY_SIZE(aes_algs));
}
static int __init gmi_sm4_init(void)
{
	struct simd_skcipher_alg *simd;
	const char *basename;
	const char *algname;
	const char *drvname;
	int err;
	int i;

	if (!gmi_ccs_available())
		return -ENODEV;

	if (gmi_zxc_check()) {

		for (i = 0; i < ARRAY_SIZE(aes_algs); i++) {
			if (!strcmp(aes_algs[i].base.cra_name, "__ctr(sm4)")) {
				pr_info("GRX: zxc gmi sm4 ctr FOUND\n");
				aes_algs[i].encrypt = ctr_encrypt_zxc;
				aes_algs[i].decrypt = ctr_decrypt_zxc;
			} else if (!strcmp(aes_algs[i].base.cra_name, "__cfb(sm4)")) {
				pr_info("GRX: zxc gmi sm4 cfb FOUND\n");
				aes_algs[i].encrypt = cfb_encrypt_zxc;
				aes_algs[i].decrypt = cfb_decrypt_zxc;
			} else if (!strcmp(aes_algs[i].base.cra_name, "__ofb(sm4)")) {
				pr_info("GRX: zxc gmi sm4 ofb FOUND\n");
				aes_algs[i].encrypt = ofb_encrypt_zxc;
				aes_algs[i].decrypt = ofb_decrypt_zxc;
			}
		}
	}

	err = crypto_register_skciphers(aes_algs, ARRAY_SIZE(aes_algs));
	if (err)
		return err;

	for (i = 0; i < ARRAY_SIZE(aes_algs); i++) {
		algname = aes_algs[i].base.cra_name + 2;
		drvname = aes_algs[i].base.cra_driver_name + 2;
		basename = aes_algs[i].base.cra_driver_name;
		simd = simd_skcipher_create_compat(algname, drvname, basename);
		err = PTR_ERR(simd);
		if (IS_ERR(simd))
			goto unregister_simds;

		sm4_simd_algs[i] = simd;
	}

	return 0;

unregister_simds:
	gmi_sm4_exit();
	return err;
}

late_initcall(gmi_sm4_init);
module_exit(gmi_sm4_exit);

MODULE_DESCRIPTION("AES-ECB/CBC/CTR/XTS using Zhaoxin GMI");
MODULE_AUTHOR("GRX");
MODULE_LICENSE("GPL");
