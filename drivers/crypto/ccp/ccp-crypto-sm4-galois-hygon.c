// SPDX-License-Identifier: GPL-2.0-only
/*
 * Hygon Cryptographic Coprocessor (CCP) SM4 GCM crypto API support
 *
 * Copyright (C) 2022 Hygon Information Technology Co., Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/module.h>
#include <linux/sched.h>
#include <linux/delay.h>
#include <linux/scatterlist.h>
#include <linux/crypto.h>
#include <crypto/algapi.h>
#include <crypto/scatterwalk.h>

#include "ccp-crypto.h"
#include "ccp-dev.h"

static int ccp_sm4_gcm_complete(struct crypto_async_request *async_req, int ret)
{
	return ret;
}

static int ccp_sm4_gcm_setkey(struct crypto_aead *tfm, const u8 *key,
			      unsigned int key_len)
{
	struct ccp_ctx *ctx = crypto_aead_ctx(tfm);

	ctx->u.sm4.mode = CCP_SM4_MODE_GCM;
	ctx->u.sm4.key_len = key_len;

	memcpy(ctx->u.sm4.key, key, key_len);
	sg_init_one(&ctx->u.sm4.key_sg, ctx->u.sm4.key, key_len);

	return 0;
}

static int ccp_sm4_gcm_setauthsize(struct crypto_aead *tfm,
				   unsigned int authsize)
{
	switch (authsize) {
	case 16:
	case 15:
	case 14:
	case 13:
	case 12:
	case 8:
	case 4:
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

static int ccp_sm4_gcm_crypt(struct aead_request *req, bool encrypt)
{
	struct crypto_aead *tfm = crypto_aead_reqtfm(req);
	struct ccp_ctx *ctx = crypto_aead_ctx(tfm);
	struct ccp_sm4_req_ctx *rctx = aead_request_ctx(req);
	struct scatterlist *iv_sg = NULL;
	unsigned int iv_len = 0;

	if (!ctx->u.sm4.key_len)
		return -EINVAL;

	if (ctx->u.sm4.mode != CCP_SM4_MODE_GCM)
		return -EINVAL;

	if (!req->iv)
		return -EINVAL;

	/*
	 * encrypt:
	 *       AAD & PT  =>  AAD, CT & TAG
	 * decrypt:
	 *      AAD & [CT + TAG]  =>  AAD & PT
	 */

	/* Prepare the IV (12 byte iv only)*/
	memcpy(rctx->iv, req->iv, HYGON_CCP_SM4GCM_IV_LEN);
	iv_sg = &rctx->iv_sg;
	iv_len = HYGON_CCP_SM4GCM_IV_LEN;
	sg_init_one(iv_sg, rctx->iv, iv_len);

	memset(&rctx->cmd, 0, sizeof(rctx->cmd));
	INIT_LIST_HEAD(&rctx->cmd.entry);
	rctx->cmd.engine = CCP_ENGINE_SM4_GCM;
	rctx->cmd.u.sm4_gcm.authsize = crypto_aead_authsize(tfm);
	rctx->cmd.u.sm4_gcm.mode = ctx->u.sm4.mode;
	rctx->cmd.u.sm4_gcm.action = encrypt;
	rctx->cmd.u.sm4_gcm.key = &ctx->u.sm4.key_sg;
	rctx->cmd.u.sm4_gcm.key_len = ctx->u.sm4.key_len;
	rctx->cmd.u.sm4_gcm.iv = iv_sg;
	rctx->cmd.u.sm4_gcm.iv_len = iv_len;
	rctx->cmd.u.sm4_gcm.src = req->src;
	rctx->cmd.u.sm4_gcm.src_len = req->cryptlen;
	rctx->cmd.u.sm4_gcm.aad_len = req->assoclen;
	rctx->cmd.u.sm4_gcm.dst = req->dst;

	return ccp_crypto_enqueue_request(&req->base, &rctx->cmd);
}

static int ccp_sm4_gcm_encrypt(struct aead_request *req)
{
	return ccp_sm4_gcm_crypt(req, CCP_SM4_ACTION_ENCRYPT);
}

static int ccp_sm4_gcm_decrypt(struct aead_request *req)
{
	return ccp_sm4_gcm_crypt(req, CCP_SM4_ACTION_DECRYPT);
}

static int ccp_sm4_gcm_cra_init(struct crypto_aead *tfm)
{
	struct ccp_ctx *ctx = crypto_aead_ctx(tfm);

	ctx->complete = ccp_sm4_gcm_complete;
	ctx->u.sm4.key_len = 0;

	crypto_aead_set_reqsize(tfm, sizeof(struct ccp_sm4_req_ctx));
	return 0;
}

static void ccp_sm4_gcm_cra_exit(struct crypto_tfm *tfm)
{
}

static struct aead_alg ccp_sm4_gcm_defaults = {
	.setkey		= ccp_sm4_gcm_setkey,
	.setauthsize	= ccp_sm4_gcm_setauthsize,
	.encrypt	= ccp_sm4_gcm_encrypt,
	.decrypt	= ccp_sm4_gcm_decrypt,
	.init		= ccp_sm4_gcm_cra_init,
	.ivsize		= HYGON_CCP_SM4GCM_IV_LEN,
	.maxauthsize	= SM4_BLOCK_SIZE,
	.base = {
		.cra_flags	= CRYPTO_ALG_ASYNC |
				  CRYPTO_ALG_ALLOCATES_MEMORY |
				  CRYPTO_ALG_KERN_DRIVER_ONLY |
				  CRYPTO_ALG_NEED_FALLBACK,
		.cra_blocksize	= SM4_BLOCK_SIZE,
		.cra_ctxsize	= sizeof(struct ccp_ctx),
		.cra_priority	= CCP_CRA_PRIORITY,
		.cra_exit	= ccp_sm4_gcm_cra_exit,
		.cra_module	= THIS_MODULE,
	},
};

struct ccp_sm4_aead_def {
	enum ccp_sm4_aead_mode mode;
	unsigned int version;
	const char *name;
	const char *driver_name;
	unsigned int blocksize;
	unsigned int ivsize;
	struct aead_alg *alg_defaults;
};

static struct ccp_sm4_aead_def sm4_aead_algs[] = {
	{
		.mode		= CCP_SM4_MODE_GCM,
		.version	= CCP_VERSION(5, 0),
		.name		= "gcm(sm4)",
		.driver_name	= "gcm-sm4-ccp",
		.blocksize	= SM4_BLOCK_SIZE,
		.ivsize		= HYGON_CCP_SM4GCM_IV_LEN,
		.alg_defaults	= &ccp_sm4_gcm_defaults,
	},
};

static int ccp_register_sm4_aead(struct list_head *head,
				 const struct ccp_sm4_aead_def *def)
{
	struct ccp_crypto_aead *ccp_aead;
	struct aead_alg *alg;
	int ret;

	ccp_aead = kzalloc(sizeof(*ccp_aead), GFP_KERNEL);
	if (!ccp_aead)
		return -ENOMEM;

	INIT_LIST_HEAD(&ccp_aead->entry);

	ccp_aead->mode = def->mode;

	/* Copy the defaults and override as necessary */
	alg = &ccp_aead->alg;
	*alg = *def->alg_defaults;
	snprintf(alg->base.cra_name, CRYPTO_MAX_ALG_NAME, "%s", def->name);
	snprintf(alg->base.cra_driver_name, CRYPTO_MAX_ALG_NAME, "%s",
		 def->driver_name);
	alg->base.cra_blocksize = def->blocksize;

	ret = crypto_register_aead(alg);
	if (ret) {
		pr_err("%s aead algorithm registration error (%d)\n",
		       alg->base.cra_name, ret);
		kfree(ccp_aead);
		return ret;
	}

	list_add(&ccp_aead->entry, head);

	return 0;
}

int ccp_register_sm4_hygon_aeads(struct list_head *head)
{
	int i, ret;
	unsigned int ccpversion = ccp_version();
	unsigned int pspccp_version_reg = 0;

	pspccp_version_reg = get_ccp_version_reg_val();
	if (!(pspccp_version_reg & HYGON_RI_SM4GCM_PRESENT)) {
		pr_warn("SM4 GCM CCP ENGINE NOT SUPPORTED!\n");
		return 0;
	}

	for (i = 0; i < ARRAY_SIZE(sm4_aead_algs); i++) {
		if (sm4_aead_algs[i].version > ccpversion)
			continue;
		ret = ccp_register_sm4_aead(head, &sm4_aead_algs[i]);
		if (ret)
			return ret;
	}

	return 0;
}
