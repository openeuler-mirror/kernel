// SPDX-License-Identifier: GPL-2.0+
#include <linux/crypto.h>
#include <linux/dma-mapping.h>

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

#define SEC_DEBUG_LOG

#ifdef SEC_DEBUG_LOG
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

struct hisi_sec_req {
	struct hisi_sec_sqe sec_sqe;
	struct hisi_sec_ctx *ctx;
	struct skcipher_request *sk_req;
	struct hisi_sec_cipher_req c_req;
	int err;
	int req_id;
};

struct hisi_sec_cipher_ctx {
	u8 *c_key;
	dma_addr_t c_key_dma;
	u8 c_mode;
	u8 c_alg;
	u8 c_key_len;
};

struct hisi_sec_ctx {
	struct hisi_qp *qp;
	struct hisi_sec *sec;
	struct device *sec_dev;
	struct hisi_sec_req **req_list;
	unsigned long *req_bitmap;
	spinlock_t req_lock;
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

static int hisi_sec_alloc_req_id(struct hisi_sec_req *req)
{
	struct hisi_sec_ctx *ctx = req->ctx;
	int req_id;
	unsigned long flags;

	spin_lock_irqsave(&ctx->req_lock, flags);
	req_id = find_first_zero_bit(ctx->req_bitmap, QM_Q_DEPTH);
	if (req_id >= QM_Q_DEPTH) {
		spin_unlock_irqrestore(&ctx->req_lock, flags);
		dev_err(ctx->sec_dev, "no free req id\n");
		return -EBUSY;
	}
	set_bit(req_id, ctx->req_bitmap);
	spin_unlock_irqrestore(&ctx->req_lock, flags);

	ctx->req_list[req_id] = req;
	req->req_id = req_id;

	return 0;
}

static void hisi_sec_free_req_id(struct hisi_sec_req *req)
{
	struct hisi_sec_ctx *ctx = req->ctx;
	int req_id = req->req_id;
	unsigned long flags;

	if (req_id < 0) {
		dev_err(ctx->sec_dev, "invalid req id %d\n", req_id);
		return;
	}

	req->req_id = SEC_INVLD_REQ_ID;
	ctx->req_list[req_id] = NULL;

	spin_lock_irqsave(&ctx->req_lock, flags);
	bitmap_clear(ctx->req_bitmap, req_id, 1);
	spin_unlock_irqrestore(&ctx->req_lock, flags);
}

static int hisi_sec_create_qp(struct hisi_qm *qm, struct hisi_sec_ctx *ctx,
			      int alg_type, int req_type)
{
	struct hisi_qp *qp;
	int ret;

	qp = hisi_qm_create_qp(qm, alg_type);
	if (IS_ERR(qp))
		return PTR_ERR(qp);

	qp->req_type = req_type;
	qp->qp_ctx = ctx;
#ifdef SEC_ASYNC
	qp->req_cb = sec_cipher_cb;
#endif
	ctx->qp = qp;

	ret = hisi_qm_start_qp(qp, 0);
	if (ret < 0)
		goto err_qm_release_qp;

	return 0;

err_qm_release_qp:
	hisi_qm_release_qp(qp);
	return ret;
}

static void hisi_sec_release_qp(struct hisi_sec_ctx *ctx)
{
	hisi_qm_stop_qp(ctx->qp);
	hisi_qm_release_qp(ctx->qp);
}

static int __hisi_sec_ctx_init(struct hisi_sec_ctx *ctx, int qlen)
{
	if (!ctx || qlen < 0)
		return -EINVAL;

	spin_lock_init(&ctx->req_lock);
	ctx->req_bitmap = kcalloc(BITS_TO_LONGS(qlen), sizeof(long),
				  GFP_KERNEL);
	if (!ctx->req_bitmap)
		return -ENOMEM;

	ctx->req_list = kcalloc(qlen, sizeof(void *), GFP_KERNEL);
	if (!ctx->req_list) {
		kfree(ctx->req_bitmap);
		return -ENOMEM;
	}

	return 0;
}

static int hisi_sec_cipher_ctx_init(struct crypto_skcipher *tfm)
{
	struct hisi_sec_ctx *ctx = crypto_skcipher_ctx(tfm);
	struct hisi_qm *qm;
	struct hisi_sec_cipher_ctx *c_ctx;
	struct hisi_sec *sec;
	int ret;

	crypto_skcipher_set_reqsize(tfm, sizeof(struct hisi_sec_req));

	sec = find_sec_device(cpu_to_node(smp_processor_id()));
	if (!sec) {
		pr_err("failed to find a proper sec device!\n");
		return -ENODEV;
	}
	ctx->sec = sec;

	qm = &sec->qm;
	ctx->sec_dev = &qm->pdev->dev;

	ret = hisi_sec_create_qp(qm, ctx, 0, 0);
	if (ret)
		return ret;

	c_ctx = &ctx->c_ctx;
	c_ctx->c_key = dma_alloc_coherent(ctx->sec_dev,
		SEC_MAX_KEY_SIZE, &c_ctx->c_key_dma, GFP_KERNEL);

	if (!ctx->c_ctx.c_key) {
		ret = -ENOMEM;
		goto err_sec_release_qp;
	}

	return __hisi_sec_ctx_init(ctx, QM_Q_DEPTH);

err_sec_release_qp:
	hisi_sec_release_qp(ctx);
	return ret;
}

static void hisi_sec_cipher_ctx_exit(struct crypto_skcipher *tfm)
{
	struct hisi_sec_ctx *ctx = crypto_skcipher_ctx(tfm);
	struct hisi_sec_cipher_ctx *c_ctx;

	c_ctx = &ctx->c_ctx;

	if (c_ctx->c_key) {
		dma_free_coherent(ctx->sec_dev, SEC_MAX_KEY_SIZE, c_ctx->c_key,
			c_ctx->c_key_dma);
		c_ctx->c_key = NULL;
	}

	kfree(ctx->req_bitmap);
	ctx->req_bitmap = NULL;

	kfree(ctx->req_list);
	ctx->req_list = NULL;

	hisi_sec_release_qp(ctx);
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
	struct hisi_sec_ctx *ctx = qp->qp_ctx;
	struct dma_pool *pool = ctx->sec->sgl_pool;
	struct hisi_sec_req *req;
	int ret = 0;

	req = ctx->req_list[req_id];

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
	struct hisi_qp *qp = ctx->qp;
	struct device *dev = &qp->qm->pdev->dev;
	struct hisi_sec_cipher_req *c_req = &req->c_req;
	struct dma_pool *pool = ctx->sec->sgl_pool;

	if (!sk_req->src || !sk_req->dst || !sk_req->cryptlen)
		return -EINVAL;

	req->sk_req = sk_req;
	req->ctx    = ctx;

	memset(sec_sqe, 0, sizeof(struct hisi_sec_sqe));

	ret = sec_alloc_cipher_req(req);
	if (ret) {
		dev_err(dev, "sec alloc cipher request failed\n");
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

#ifdef SEC_ASYNC
	ret = hisi_sec_alloc_req_id(req);
	if (ret) {
		dev_err(dev, "sec alloc req id failed\n");
		goto err_unmap_dst_sg;
	}
	sec_sqe->type2.tag = req->req_id;
#endif

	ret = hisi_qp_send(qp, sec_sqe);
	if (ret < 0) {
		dev_err(dev, "hisi_qp_send failed\n");
		goto err_unmap_dst_sg;
	}

#ifdef SEC_ASYNC
	ret = -EINPROGRESS;
#else
	ret = hisi_qp_wait(qp);
	if (ret < 0)
		goto err_unmap_dst_sg;

	sec_update_iv(req, sk_req->iv);
	sec_sg_unmap(dev, sk_req, c_req, pool);
	sec_free_cipher_req(req);
#endif

	return ret;

err_unmap_dst_sg:
	if (sk_req->dst != sk_req->src)
		acc_sg_buf_unmap(dev, sk_req->dst,
			c_req->c_out, c_req->c_out_dma, pool);
err_unmap_src_sg:
	acc_sg_buf_unmap(dev, sk_req->src,
		c_req->c_in, c_req->c_in_dma, pool);
err_free_cipher_req:
	sec_free_cipher_req(req);

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
