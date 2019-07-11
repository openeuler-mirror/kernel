// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) 2019 HiSilicon Limited.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 */

#include <linux/crypto.h>
#include <linux/dma-mapping.h>
#include <linux/atomic.h>

#include <crypto/aes.h>
#include <crypto/algapi.h>
#include <crypto/des.h>
#include <crypto/skcipher.h>
#include <crypto/xts.h>
#include <crypto/internal/skcipher.h>

#include "sec.h"
#include "sec_crypto.h"

#define SEC_ASYNC
#define SEC_INVLD_REQ_ID -1

#define SEC_DEBUG

#ifdef SEC_DEBUG
#define dbg(msg, ...) pr_info(msg, ##__VA_ARGS__)
#else
#define dbg(msg, ...)
#endif

struct hisi_sec_cipher_req {
	struct acc_hw_sgl *c_in;
	dma_addr_t c_in_dma;
	struct acc_hw_sgl *c_out;
	dma_addr_t c_out_dma;
	u8 *c_ivin;
	dma_addr_t c_ivin_dma;
	u32 c_len;
	bool encrypt;
};

struct hisi_sec_ctx;
struct hisi_sec_qp_ctx;

struct hisi_sec_req {
	struct hisi_sec_sqe sec_sqe;
	struct hisi_sec_ctx *ctx;
	struct hisi_sec_qp_ctx *qp_ctx;
	struct skcipher_request *sk_req;
	struct hisi_sec_cipher_req c_req;
	int err;
	int req_id;
	bool fake_busy;
};

struct hisi_sec_cipher_ctx {
	u8 *c_key;
	dma_addr_t c_key_dma;
	u8 c_mode;
	u8 c_alg;
	u8 c_key_len;
};

struct hisi_sec_qp_ctx {
	struct hisi_qp *qp;
	struct hisi_sec_req **req_list;
	unsigned long *req_bitmap;
	spinlock_t req_lock;
	atomic_t req_cnt;
};

struct hisi_sec_ctx {
	struct hisi_sec_qp_ctx *qp_ctx;
	struct hisi_sec *sec;
	struct device *sec_dev;
	atomic_t thread_cnt;
	int max_thread_cnt;
	int req_fake_limit;
	int req_limit;
	int q_num;
	atomic_t q_id;
	struct hisi_sec_cipher_ctx c_ctx;
};

static void dump_data(unsigned char *buf, unsigned int len)
{
	unsigned int i;

	for (i = 0; i < len; i += 8)
		dbg("0x%llx: \t%02x %02x %02x %02x %02x %02x %02x %02x\n",
			(unsigned long long)(buf + i),
			*(buf + i), (*(buf + i + 1)),
			*(buf + i + 2), *(buf + i + 3),
			*(buf + i + 4), *(buf + i + 5),
			*(buf + i + 6), *(buf + i + 7));

	dbg("\n");
}

static void dump_sec_bd(unsigned int *bd)
{
	unsigned int i;

	for (i = 0; i < 32; i++)
		dbg("Word[%d] 0x%08x\n", i, bd[i]);

	dbg("\n");
}

static void sec_update_iv(struct hisi_sec_req *req, u8 *iv)
{
	// todo: update iv by cbc/ctr mode
}

static void sec_cipher_cb(struct hisi_qp *qp, void *);
static void sec_sg_unmap(struct device *dev,
	struct skcipher_request *sk_req,
	struct hisi_sec_cipher_req *creq,
	struct dma_pool *pool)
{
	if (sk_req->dst != sk_req->src)
		acc_sg_buf_unmap(dev, sk_req->dst,
			creq->c_out, creq->c_out_dma, pool);

	acc_sg_buf_unmap(dev, sk_req->src, creq->c_in, creq->c_in_dma, pool);
}

static int hisi_sec_alloc_req_id(struct hisi_sec_req *req,
	struct hisi_sec_qp_ctx *qp_ctx)
{
	struct hisi_sec_ctx *ctx = req->ctx;
	int req_id;
	unsigned long flags;

	spin_lock_irqsave(&qp_ctx->req_lock, flags);
	req_id = find_first_zero_bit(qp_ctx->req_bitmap, ctx->req_limit);
	if (req_id >= ctx->req_limit) {
		spin_unlock_irqrestore(&qp_ctx->req_lock, flags);
		dump_data((uint8_t *)qp_ctx->req_bitmap, ctx->req_limit / 8);
		pr_info("[%s][%d] used[%d]\n", __func__, __LINE__,
			atomic_read(&qp_ctx->qp->qp_status.used));
		dev_err(ctx->sec_dev, "no free req id\n");
		pr_info("[%s][%d] max_thread_cnt[%d]\n", __func__, __LINE__,
			ctx->max_thread_cnt);
		return -ENOBUFS;
	}
	set_bit(req_id, qp_ctx->req_bitmap);
	spin_unlock_irqrestore(&qp_ctx->req_lock, flags);

	qp_ctx->req_list[req_id] = req;
	req->req_id = req_id;
	req->qp_ctx = qp_ctx;

	return 0;
}

static void hisi_sec_free_req_id(struct hisi_sec_req *req)
{
	struct hisi_sec_ctx *ctx = req->ctx;
	int req_id = req->req_id;
	struct hisi_sec_qp_ctx *qp_ctx = req->qp_ctx;
	unsigned long flags;

	if (req_id < 0) {
		dev_err(ctx->sec_dev, "invalid req id %d\n", req_id);
		return;
	}

	req->req_id = SEC_INVLD_REQ_ID;
	qp_ctx->req_list[req_id] = NULL;

	spin_lock_irqsave(&qp_ctx->req_lock, flags);
	clear_bit(req_id, qp_ctx->req_bitmap);
	atomic_dec(&qp_ctx->req_cnt);
	spin_unlock_irqrestore(&qp_ctx->req_lock, flags);
}

static int hisi_sec_create_qp_ctx(struct hisi_qm *qm, struct hisi_sec_ctx *ctx,
			      int qp_ctx_id, int alg_type, int req_type)
{
	struct hisi_qp *qp;
	struct hisi_sec_qp_ctx *qp_ctx;
	int ret;

	qp = hisi_qm_create_qp(qm, alg_type);
	if (IS_ERR(qp))
		return PTR_ERR(qp);

	qp_ctx = &ctx->qp_ctx[qp_ctx_id];
	qp->req_type = req_type;
	qp->qp_ctx = qp_ctx;
#ifdef SEC_ASYNC
	qp->req_cb = sec_cipher_cb;
#endif
	qp_ctx->qp = qp;

	spin_lock_init(&qp_ctx->req_lock);
	atomic_set(&qp_ctx->req_cnt, 0);

	qp_ctx->req_bitmap = kcalloc(BITS_TO_LONGS(QM_Q_DEPTH), sizeof(long),
				  GFP_KERNEL);
	if (!qp_ctx->req_bitmap) {
		ret = -ENOMEM;
		goto err_qm_release_qp;
	}

	qp_ctx->req_list = kcalloc(QM_Q_DEPTH, sizeof(void *), GFP_KERNEL);
	if (!qp_ctx->req_list) {
		ret = -ENOMEM;
		goto err_free_req_bitmap;
	}

	ret = hisi_qm_start_qp(qp, 0);
	if (ret < 0)
		goto err_free_req_list;

	return 0;

err_free_req_list:
	kfree(qp_ctx->req_list);
err_free_req_bitmap:
	kfree(qp_ctx->req_bitmap);
err_qm_release_qp:
	hisi_qm_release_qp(qp);
	return ret;
}

static void hisi_sec_release_qp_ctx(struct hisi_sec_qp_ctx *qp_ctx)
{
	hisi_qm_stop_qp(qp_ctx->qp);
	kfree(qp_ctx->req_bitmap);
	kfree(qp_ctx->req_list);
	hisi_qm_release_qp(qp_ctx->qp);
}

static int __hisi_sec_ctx_init(struct hisi_sec_ctx *ctx, int qlen)
{
	if (!ctx || qlen < 0)
		return -EINVAL;

	ctx->req_limit = qlen;
	ctx->req_fake_limit = qlen / 2;
	atomic_set(&ctx->thread_cnt, 0);
	ctx->max_thread_cnt = 0;
	atomic_set(&ctx->q_id, 0);

	return 0;
}

static int hisi_sec_cipher_ctx_init(struct crypto_skcipher *tfm)
{
	struct hisi_sec_ctx *ctx = crypto_skcipher_ctx(tfm);
	struct hisi_qm *qm;
	struct hisi_sec_cipher_ctx *c_ctx;
	struct hisi_sec *sec;
	int i, ret;

	crypto_skcipher_set_reqsize(tfm, sizeof(struct hisi_sec_req));

	sec = find_sec_device(cpu_to_node(smp_processor_id()));
	if (!sec) {
		pr_err("failed to find a proper sec device!\n");
		return -ENODEV;
	}
	ctx->sec = sec;

	qm = &sec->qm;
	ctx->sec_dev = &qm->pdev->dev;

	ctx->q_num = sec->ctx_q_num;
	ctx->qp_ctx = kcalloc(ctx->q_num, sizeof(struct hisi_sec_qp_ctx),
		GFP_KERNEL);
	if (!ctx->qp_ctx)
		return -ENOMEM;

	for (i = 0; i < ctx->q_num; i++) {
		ret = hisi_sec_create_qp_ctx(qm, ctx, i, 0, 0);
		if (ret)
			goto err_sec_release_qp_ctx;
	}

	c_ctx = &ctx->c_ctx;
	c_ctx->c_key = dma_alloc_coherent(ctx->sec_dev,
		SEC_MAX_KEY_SIZE, &c_ctx->c_key_dma, GFP_KERNEL);

	if (!ctx->c_ctx.c_key) {
		ret = -ENOMEM;
		goto err_sec_release_qp_ctx;
	}

	return __hisi_sec_ctx_init(ctx, QM_Q_DEPTH);

err_sec_release_qp_ctx:
	i = i - 1;
	for (; i >= 0; i--)
		hisi_sec_release_qp_ctx(&ctx->qp_ctx[i]);

	kfree(ctx->qp_ctx);
	return ret;
}

static void hisi_sec_cipher_ctx_exit(struct crypto_skcipher *tfm)
{
	struct hisi_sec_ctx *ctx = crypto_skcipher_ctx(tfm);
	struct hisi_sec_cipher_ctx *c_ctx;
	int i = 0;

	c_ctx = &ctx->c_ctx;

	if (c_ctx->c_key) {
		dma_free_coherent(ctx->sec_dev, SEC_MAX_KEY_SIZE, c_ctx->c_key,
			c_ctx->c_key_dma);
		c_ctx->c_key = NULL;
	}

	for (i = 0; i < ctx->q_num; i++)
		hisi_sec_release_qp_ctx(&ctx->qp_ctx[i]);

	kfree(ctx->qp_ctx);
}

static int sec_alloc_cipher_req(struct hisi_sec_req *req)
{
	struct hisi_sec_cipher_req *c_req = &req->c_req;
	struct hisi_sec_sqe *sec_sqe = &req->sec_sqe;
	struct device *sec_dev = req->ctx->sec_dev;

	c_req->c_ivin = dma_alloc_coherent(sec_dev, SEC_IV_SIZE,
					    &c_req->c_ivin_dma, GFP_KERNEL);
	if (!c_req->c_ivin)
		return -ENOMEM;

	sec_sqe->type2.c_ivin_addr_l = lower_32_bits(c_req->c_ivin_dma);
	sec_sqe->type2.c_ivin_addr_h = upper_32_bits(c_req->c_ivin_dma);

	return 0;
}

static int sec_free_cipher_req(struct hisi_sec_req *req)
{
	struct hisi_sec_cipher_req *c_req = &req->c_req;
	struct device *sec_dev = req->ctx->sec_dev;

	if (c_req->c_ivin) {
		dma_free_coherent(sec_dev, SEC_IV_SIZE,
			c_req->c_ivin, c_req->c_ivin_dma);
		c_req->c_ivin = NULL;
	}

	return 0;
}

static void sec_cipher_cb(struct hisi_qp *qp, void *resp)
{
	struct hisi_sec_sqe *sec_sqe = (struct hisi_sec_sqe *)resp;
	u32 req_id = sec_sqe->type2.tag;
	struct hisi_sec_qp_ctx *qp_ctx = qp->qp_ctx;
	struct dma_pool *pool;
	struct hisi_sec_req *req;
	int ret = 0;

	req = qp_ctx->req_list[req_id];
	pool = req->ctx->sec->sgl_pool;

	if (sec_sqe->type2.done != 0x1 || sec_sqe->type2.flag != 0x2) {
		ret = sec_sqe->type2.error_type;
		dump_sec_bd((uint32_t *)sec_sqe);
		dump_data((unsigned char *)sec_sqe,
			sizeof(struct hisi_sec_sqe));
	}

	sec_update_iv(req, req->sk_req->iv);
	sec_sg_unmap(&qp->qm->pdev->dev, req->sk_req, &req->c_req, pool);
	sec_free_cipher_req(req);

	hisi_sec_free_req_id(req);

	if (req->fake_busy) {
		req->sk_req->base.complete(&req->sk_req->base, -EINPROGRESS);
		req->fake_busy = 0;
	}

	req->sk_req->base.complete(&req->sk_req->base, ret);
}

static int sec_skcipher_setkey(struct hisi_sec_ctx *sec_ctx,
					   const u8 *key, u32 keylen)
{
	struct hisi_sec_cipher_ctx *c_ctx = &sec_ctx->c_ctx;

	switch (keylen) {
	case AES_KEYSIZE_128:
		c_ctx->c_key_len = 0;
		break;
	case AES_KEYSIZE_192:
		c_ctx->c_key_len = 1;
		break;
	case AES_KEYSIZE_256:
		c_ctx->c_key_len = 2;
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

static int sec_skcipher_setkey_aes_ecb(struct crypto_skcipher *tfm,
					   const u8 *key, u32 keylen)
{
	struct hisi_sec_ctx *ctx = crypto_skcipher_ctx(tfm);

	memcpy(ctx->c_ctx.c_key, key, keylen);
	ctx->c_ctx.c_mode = ECB;
	ctx->c_ctx.c_alg  = AES;

	return sec_skcipher_setkey(ctx, key, keylen);
}

static int sec_skcipher_setkey_aes_cbc(struct crypto_skcipher *tfm,
					   const u8 *key, u32 keylen)
{
	struct hisi_sec_ctx *ctx = crypto_skcipher_ctx(tfm);

	memcpy(ctx->c_ctx.c_key, key, keylen);
	ctx->c_ctx.c_mode = CBC;
	ctx->c_ctx.c_alg  = AES;

	return sec_skcipher_setkey(ctx, key, keylen);
}

static int sec_skcipher_setkey_aes_ctr(struct crypto_skcipher *tfm,
					   const u8 *key, u32 keylen)
{
	struct hisi_sec_ctx *ctx = crypto_skcipher_ctx(tfm);

	memcpy(ctx->c_ctx.c_key, key, keylen);

	ctx->c_ctx.c_mode = CTR;
	ctx->c_ctx.c_alg  = AES;

	return sec_skcipher_setkey(ctx, key, keylen);
}

static int sec_skcipher_setkey_aes_xts(struct crypto_skcipher *tfm,
					   const u8 *key, u32 keylen)
{
	struct hisi_sec_ctx *ctx = crypto_skcipher_ctx(tfm);
	int ret = 0;

	ret = xts_verify_key(tfm, key, keylen);
	if (ret)
		return ret;

	memcpy(ctx->c_ctx.c_key, key, keylen);

	ctx->c_ctx.c_mode = XTS;
	ctx->c_ctx.c_alg  = AES;

	return sec_skcipher_setkey(ctx, key, keylen / 2);
}

static int sec_skcipher_setkey_sm4_xts(struct crypto_skcipher *tfm,
					   const u8 *key, u32 keylen)
{
	struct hisi_sec_ctx *ctx = crypto_skcipher_ctx(tfm);
	int ret = 0;

	ret = xts_verify_key(tfm, key, keylen);
	if (ret)
		return ret;

	memcpy(ctx->c_ctx.c_key, key, keylen);

	ctx->c_ctx.c_mode = XTS;
	ctx->c_ctx.c_alg  = SM4;

	return sec_skcipher_setkey(ctx, key, keylen / 2);
}

static int sec_cipher_fill_sqe(struct hisi_sec_sqe *sec_sqe,
	struct hisi_sec_ctx *ctx, struct hisi_sec_cipher_req *c_req)
{
	struct hisi_sec_cipher_ctx *c_ctx = &ctx->c_ctx;

	if (!c_req->c_len)
		return -EINVAL;

	sec_sqe->type2.c_key_addr_l    = lower_32_bits(c_ctx->c_key_dma);
	sec_sqe->type2.c_key_addr_h    = upper_32_bits(c_ctx->c_key_dma);
	sec_sqe->type2.data_src_addr_l = lower_32_bits(c_req->c_in_dma);
	sec_sqe->type2.data_src_addr_h = upper_32_bits(c_req->c_in_dma);
	sec_sqe->type2.data_dst_addr_l = lower_32_bits(c_req->c_out_dma);
	sec_sqe->type2.data_dst_addr_h = upper_32_bits(c_req->c_out_dma);

	sec_sqe->type2.c_mode       = c_ctx->c_mode;
	sec_sqe->type2.c_alg        = c_ctx->c_alg;
	sec_sqe->type2.c_key_len    = c_ctx->c_key_len;

	sec_sqe->src_addr_type = 1;
	sec_sqe->dst_addr_type = 1;
	sec_sqe->type          = 2;
	sec_sqe->scene         = 1;
	sec_sqe->de            = 1;

	if (c_req->encrypt == 1)
		sec_sqe->cipher = 1;
	else
		sec_sqe->cipher = 2;

	sec_sqe->type2.c_len = c_req->c_len;

	return 0;
}

static int sec_skcipher_crypto(struct skcipher_request *sk_req,
				   bool encrypt)
{
	int ret = 0;
	struct crypto_skcipher *atfm = crypto_skcipher_reqtfm(sk_req);
	struct hisi_sec_ctx *ctx = crypto_skcipher_ctx(atfm);
	struct hisi_sec_req *req = skcipher_request_ctx(sk_req);
	struct hisi_sec_sqe *sec_sqe = &req->sec_sqe;
	struct device *dev = ctx->sec_dev;
	struct hisi_sec_cipher_req *c_req = &req->c_req;
	struct dma_pool *pool = ctx->sec->sgl_pool;
	struct hisi_sec_qp_ctx *qp_ctx;
	unsigned long flags;
	int req_cnt;
	int thread_cnt;
	int issue_id;

	if (!sk_req->src || !sk_req->dst || !sk_req->cryptlen)
		return -EINVAL;

	thread_cnt = atomic_inc_return(&ctx->thread_cnt);
	if (thread_cnt > ctx->max_thread_cnt)
		ctx->max_thread_cnt = thread_cnt;

	req->sk_req = sk_req;
	req->ctx    = ctx;

	memset(sec_sqe, 0, sizeof(struct hisi_sec_sqe));

	ret = sec_alloc_cipher_req(req);
	if (ret) {
		dev_err(dev, "sec alloc cipher request failed\n");
		atomic_dec(&ctx->thread_cnt);
		return ret;
	}

	c_req->c_in = acc_sg_buf_map_to_hw_sgl(dev, sk_req->src, pool,
		&c_req->c_in_dma);
	if (IS_ERR(c_req->c_in)) {
		ret = PTR_ERR(c_req->c_in);
		goto err_free_cipher_req;
	}

	if (sk_req->dst == sk_req->src) {
		c_req->c_out = c_req->c_in;
		c_req->c_out_dma = c_req->c_in_dma;
	} else {
		c_req->c_out = acc_sg_buf_map_to_hw_sgl(dev, sk_req->dst, pool,
			&c_req->c_out_dma);
		if (IS_ERR(c_req->c_out)) {
			ret = PTR_ERR(c_req->c_out);
			goto err_unmap_src_sg;
		}
	}

	c_req->c_len = sk_req->cryptlen;
	c_req->encrypt = encrypt;

	ret = sec_cipher_fill_sqe(sec_sqe, ctx, c_req);
	if (ret) {
		dev_err(dev, "sec cipher fill sqe failed\n");
		goto err_unmap_dst_sg;
	}

	if (!crypto_skcipher_ivsize(atfm)) {
		ret = -EINVAL;
		goto err_unmap_dst_sg;
	} else
		memcpy(c_req->c_ivin, sk_req->iv, crypto_skcipher_ivsize(atfm));

	/* get issue_id */
	issue_id = atomic_fetch_inc(&ctx->q_id) % ctx->q_num;
	if (issue_id % ctx->q_num == 0 && ctx->q_id.counter > ctx->q_num)
		atomic_sub(ctx->q_num, &ctx->q_id);

	qp_ctx = &ctx->qp_ctx[issue_id];
#ifdef SEC_ASYNC
	ret = hisi_sec_alloc_req_id(req, qp_ctx);
	if (ret) {
		dev_err(dev, "sec alloc req id failed\n");
		goto err_unmap_dst_sg;
	}

	req->fake_busy = 0;

	req_cnt = atomic_inc_return(&qp_ctx->req_cnt);
	if (req_cnt >= ctx->req_fake_limit)
		req->fake_busy = 1;

	sec_sqe->type2.tag = req->req_id;
#endif
	spin_lock_irqsave(&qp_ctx->req_lock, flags);
	ret = hisi_qp_send(qp_ctx->qp, sec_sqe);
	spin_unlock_irqrestore(&qp_ctx->req_lock, flags);

	if (ret < 0) {
#ifdef SEC_ASYNC
		if (ret == -EBUSY)
			ret = -ENOBUFS;
		goto err_free_req_id;
#else
		goto err_unmap_dst_sg;
#endif
	}

#ifdef SEC_ASYNC
	if (req_cnt >= ctx->req_fake_limit)
		ret = -EBUSY;
	else
		ret = -EINPROGRESS;
#else
	ret = hisi_qp_wait(qp_ctx->qp);
	if (ret < 0)
		goto err_unmap_dst_sg;

	sec_update_iv(req, sk_req->iv);
	sec_sg_unmap(dev, sk_req, c_req, pool);

	sec_free_cipher_req(req);
#endif

	atomic_dec(&ctx->thread_cnt);
	return ret;

#ifdef SEC_ASYNC
err_free_req_id:
	hisi_sec_free_req_id(req);
#endif
err_unmap_dst_sg:
	if (sk_req->dst != sk_req->src)
		acc_sg_buf_unmap(dev, sk_req->dst,
			c_req->c_out, c_req->c_out_dma, pool);
err_unmap_src_sg:
	acc_sg_buf_unmap(dev, sk_req->src,
		c_req->c_in, c_req->c_in_dma, pool);
err_free_cipher_req:
	sec_free_cipher_req(req);

	atomic_dec(&ctx->thread_cnt);
	return ret;
}

static int sec_skcipher_encrypt(struct skcipher_request *req)
{
	return sec_skcipher_crypto(req, true);
}

static int sec_skcipher_decrypt(struct skcipher_request *req)
{
	return sec_skcipher_crypto(req, false);
}

static struct skcipher_alg sec_algs[] = {
	{
		.base = {
			.cra_name = "ecb(aes)",
			.cra_driver_name = "hisi_sec_aes_ecb",
			.cra_priority = 4001,
			.cra_flags = CRYPTO_ALG_ASYNC,
			.cra_blocksize = AES_BLOCK_SIZE,
			.cra_ctxsize = sizeof(struct hisi_sec_ctx),
			.cra_alignmask = 0,
			.cra_module = THIS_MODULE,
		},
		.init = hisi_sec_cipher_ctx_init,
		.exit = hisi_sec_cipher_ctx_exit,
		.setkey = sec_skcipher_setkey_aes_ecb,
		.decrypt = sec_skcipher_decrypt,
		.encrypt = sec_skcipher_encrypt,
		.min_keysize = AES_MIN_KEY_SIZE,
		.max_keysize = AES_MAX_KEY_SIZE,
		.ivsize = AES_BLOCK_SIZE,
	}, {
		.base = {
			.cra_name = "cbc(aes)",
			.cra_driver_name = "hisi_sec_aes_cbc",
			.cra_priority = 4001,
			.cra_flags = CRYPTO_ALG_ASYNC,
			.cra_blocksize = AES_BLOCK_SIZE,
			.cra_ctxsize = sizeof(struct hisi_sec_ctx),
			.cra_alignmask = 0,
			.cra_module = THIS_MODULE,
		},
		.init = hisi_sec_cipher_ctx_init,
		.exit = hisi_sec_cipher_ctx_exit,
		.setkey = sec_skcipher_setkey_aes_cbc,
		.decrypt = sec_skcipher_decrypt,
		.encrypt = sec_skcipher_encrypt,
		.min_keysize = AES_MIN_KEY_SIZE,
		.max_keysize = AES_MAX_KEY_SIZE,
		.ivsize = AES_BLOCK_SIZE,
	}, {
		.base = {
			.cra_name = "ctr(aes)",
			.cra_driver_name = "hisi_sec_aes_ctr",
			.cra_priority = 4001,
			.cra_flags = CRYPTO_ALG_ASYNC,
			.cra_blocksize = AES_BLOCK_SIZE,
			.cra_ctxsize = sizeof(struct hisi_sec_ctx),
			.cra_alignmask = 0,
			.cra_module = THIS_MODULE,
		},
		.init = hisi_sec_cipher_ctx_init,
		.exit = hisi_sec_cipher_ctx_exit,
		.setkey = sec_skcipher_setkey_aes_ctr,
		.decrypt = sec_skcipher_decrypt,
		.encrypt = sec_skcipher_encrypt,
		.min_keysize = AES_MIN_KEY_SIZE,
		.max_keysize = AES_MAX_KEY_SIZE,
		.ivsize = AES_BLOCK_SIZE,
	}, {
		.base = {
			.cra_name = "xts(aes)",
			.cra_driver_name = "hisi_sec_aes_xts",
			.cra_priority = 4001,
			.cra_flags = CRYPTO_ALG_ASYNC,
			.cra_blocksize = AES_BLOCK_SIZE,
			.cra_ctxsize = sizeof(struct hisi_sec_ctx),
			.cra_alignmask = 0,
			.cra_module = THIS_MODULE,
		},
		.init = hisi_sec_cipher_ctx_init,
		.exit = hisi_sec_cipher_ctx_exit,
		.setkey = sec_skcipher_setkey_aes_xts,
		.decrypt = sec_skcipher_decrypt,
		.encrypt = sec_skcipher_encrypt,
		.min_keysize = 2 * AES_MIN_KEY_SIZE,
		.max_keysize = 2 * AES_MAX_KEY_SIZE,
		.ivsize = AES_BLOCK_SIZE,
	}, {
		.base = {
			.cra_name = "xts(sm4)",
			.cra_driver_name = "hisi_sec_sm4_xts",
			.cra_priority = 4001,
			.cra_flags = CRYPTO_ALG_ASYNC,
			.cra_blocksize = AES_BLOCK_SIZE,
			.cra_ctxsize = sizeof(struct hisi_sec_ctx),
			.cra_alignmask = 0,
			.cra_module = THIS_MODULE,
		},
		.init = hisi_sec_cipher_ctx_init,
		.exit = hisi_sec_cipher_ctx_exit,
		.setkey = sec_skcipher_setkey_sm4_xts,
		.decrypt = sec_skcipher_decrypt,
		.encrypt = sec_skcipher_encrypt,
		.min_keysize = 2 * AES_MIN_KEY_SIZE,
		.max_keysize = 2 * AES_MAX_KEY_SIZE,
		.ivsize = AES_BLOCK_SIZE,
	},

};

int hisi_sec_register_to_crypto(void)
{
	return crypto_register_skciphers(sec_algs, ARRAY_SIZE(sec_algs));
}

void hisi_sec_unregister_from_crypto(void)
{
	crypto_unregister_skciphers(sec_algs, ARRAY_SIZE(sec_algs));
}
