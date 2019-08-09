// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) 2018-2019 HiSilicon Limited.
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

#define SEC_INVLD_REQ_ID (-1)
#define SEC_PRIORITY (4001)
#define SEC_XTS_MIN_KEY_SIZE (2 * AES_MIN_KEY_SIZE)
#define SEC_XTS_MAX_KEY_SIZE (2 * AES_MAX_KEY_SIZE)
#define SEC_DES3_2KEY_SIZE (2 * DES_KEY_SIZE)
#define SEC_DES3_3KEY_SIZE (3 * DES_KEY_SIZE)

// #define USE_DM_CRYPT_OPTIMIZE
#define SEC_FUSION_BD

#define SEC_DEBUG

#ifdef SEC_DEBUG
#define dbg(msg, ...) pr_err(msg, ##__VA_ARGS__)
#else
#define dbg(msg, ...)
#endif

enum {
	SEC_NO_FUSION = 0x0,
	SEC_IV_FUSION = 0x1,
	SEC_FUSION_BUTT
};

enum SEC_REQ_OPS_TYPE {
	SEC_OPS_SKCIPHER_ALG = 0x0,
	SEC_OPS_DMCRYPT      = 0x1,
	SEC_OPS_MULTI_IV     = 0x2,
	SEC_OPS_BUTT
};

enum cipher_flags {
	CRYPT_MODE_INTEGRITY_AEAD,
	CRYPT_IV_LARGE_SECTORS,
};

enum setkey_op {
	SETKEY_OP_INIT,
	SETKEY_OP_SET,
	SETKEY_OP_WIPE,
};

struct geniv_key_info {
	enum setkey_op keyop;
	unsigned int tfms_count;
	u8 *key;
	char *ivopts;
	sector_t iv_offset;
	unsigned long cipher_flags;

	unsigned short int sector_size;
	unsigned int key_size;
	unsigned int key_parts;
	unsigned int key_mac_size;
	unsigned int on_disk_tag_size;
};

struct geniv_req_info {
	sector_t cc_sector;
	unsigned int nents;
	u8 *integrity_metadata;
};

struct hisi_sec_cipher_req {
	struct acc_hw_sgl *c_in;
	dma_addr_t c_in_dma;
	struct acc_hw_sgl *c_out;
	dma_addr_t c_out_dma;
	u8 *c_ivin;
	dma_addr_t c_ivin_dma;
	struct skcipher_request *sk_req;
	struct scatterlist *src;
	struct scatterlist *dst;
	u32 c_len;
	u32 gran_num;
	u64 lba;
	bool encrypt;
};

struct hisi_sec_ctx;
struct hisi_sec_qp_ctx;

struct hisi_sec_req {
	struct hisi_sec_sqe sec_sqe;
	struct hisi_sec_ctx *ctx;
	struct hisi_sec_qp_ctx *qp_ctx;
	void **priv;
	struct hisi_sec_cipher_req c_req;
	int err_type;
	int req_id;
	int req_cnt;
	int fusion_num;
	int fake_busy;
};

struct hisi_sec_req_op {
	int fusion_type;
	int (*alloc)(struct hisi_sec_ctx *ctx, struct hisi_sec_req *req);
	int (*free)(struct hisi_sec_ctx *ctx, struct hisi_sec_req *req);
	int (*buf_map)(struct hisi_sec_ctx *ctx, struct hisi_sec_req *req);
	int (*buf_unmap)(struct hisi_sec_ctx *ctx, struct hisi_sec_req *req);
	int (*do_transfer)(struct hisi_sec_ctx *ctx, struct hisi_sec_req *req);
	int (*bd_fill)(struct hisi_sec_ctx *ctx, struct hisi_sec_req *req);
	int (*bd_send)(struct hisi_sec_ctx *ctx, struct hisi_sec_req *req);
	int (*callback)(struct hisi_sec_ctx *ctx, struct hisi_sec_req *req);
};

struct hisi_sec_cipher_ctx {
	u8 *c_key;
	dma_addr_t c_key_dma;
	sector_t iv_offset;
	u32 c_gran_size;
	u8 c_mode;
	u8 c_alg;
	u8 c_key_len;
};

struct hisi_sec_qp_ctx {
	struct hisi_qp *qp;
	struct hisi_sec_req **req_list;
	struct hisi_sec_req *fusion_req;
	unsigned long *req_bitmap;
	spinlock_t req_lock;
	atomic_t req_cnt;
	struct hisi_sec_sqe *sqe_list;
	struct delayed_work work;
	int work_cnt;
	int fusion_num;
};

struct hisi_sec_ctx {
	struct hisi_sec_qp_ctx *qp_ctx;
	struct hisi_sec *sec;
	struct device *sec_dev;
	struct hisi_sec_req_op *req_op;
	atomic_t thread_cnt;
	int req_fake_limit;
	int req_limit;
	int q_num;
	int enc_q_num;
	atomic_t enc_qid;
	atomic_t dec_qid;
	struct hisi_sec_cipher_ctx c_ctx;
	int fusion_tmout_usec;
	int fusion_limit;
	u64 fusion_cnt;
	bool is_fusion;
};

#define DES_WEAK_KEY_NUM (4)
u64 des_weak_key[DES_WEAK_KEY_NUM] = {0x0101010101010101, 0xFEFEFEFEFEFEFEFE,
	0xE0E0E0E0F1F1F1F1, 0x1F1F1F1F0E0E0E0E};

static void sec_update_iv(struct hisi_sec_req *req, u8 *iv)
{
	// todo: update iv by cbc/ctr mode
}

static void hisi_sec_req_cb(struct hisi_qp *qp, void *);

static int hisi_sec_alloc_req_id(struct hisi_sec_req *req,
	struct hisi_sec_qp_ctx *qp_ctx)
{
	struct hisi_sec_ctx *ctx = req->ctx;
	int req_id;

	req_id = find_first_zero_bit(qp_ctx->req_bitmap, ctx->req_limit);
	if (req_id >= ctx->req_limit || req_id < 0) {
		dev_err(ctx->sec_dev, "no free req id\n");
		return -ENOBUFS;
	}
	set_bit(req_id, qp_ctx->req_bitmap);

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

static int sec_request_transfer(struct hisi_sec_ctx *, struct hisi_sec_req *);
static int sec_request_send(struct hisi_sec_ctx *, struct hisi_sec_req *);

void qp_ctx_work_delayed_process(struct work_struct *work)
{
	struct hisi_sec_qp_ctx *qp_ctx;
	struct hisi_sec_req *req;
	struct hisi_sec_ctx *ctx;
	struct delayed_work *dwork;
	unsigned long flags;
	int ret;

	dwork = container_of(work, struct delayed_work, work);
	qp_ctx = container_of(dwork, struct hisi_sec_qp_ctx, work);

	spin_lock_irqsave(&qp_ctx->req_lock, flags);

	req = qp_ctx->fusion_req;
	if (req == NULL) {
		spin_unlock_irqrestore(&qp_ctx->req_lock, flags);
		return;
	}

	ctx = req->ctx;
	if (ctx == NULL || req->fusion_num == ctx->fusion_limit) {
		spin_unlock_irqrestore(&qp_ctx->req_lock, flags);
		return;
	}

	qp_ctx->fusion_req = NULL;

	spin_unlock_irqrestore(&qp_ctx->req_lock, flags);

	ret = sec_request_transfer(ctx, req);
	if (ret)
		goto err_free_req;

	ret = sec_request_send(ctx, req);
	if (ret != -EBUSY && ret != -EINPROGRESS) {
		dev_err(ctx->sec_dev, "[%s][%d] ret[%d]\n", __func__,
			__LINE__, ret);
		goto err_unmap_req;
	}

	return;

err_unmap_req:
	ctx->req_op->buf_unmap(ctx, req);
err_free_req:
	ctx->req_op->free(ctx, req);
	hisi_sec_free_req_id(req);
	atomic_dec(&ctx->thread_cnt);
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
	qp->req_cb = hisi_sec_req_cb;
#endif
	qp_ctx->qp = qp;
	qp_ctx->fusion_num = 0;
	qp_ctx->fusion_req = NULL;

	spin_lock_init(&qp_ctx->req_lock);
	atomic_set(&qp_ctx->req_cnt, 0);

	qp_ctx->req_bitmap = kcalloc(BITS_TO_LONGS(QM_Q_DEPTH), sizeof(long),
				  GFP_ATOMIC);
	if (!qp_ctx->req_bitmap) {
		ret = -ENOMEM;
		goto err_qm_release_qp;
	}

	qp_ctx->req_list = kcalloc(QM_Q_DEPTH, sizeof(void *), GFP_ATOMIC);
	if (!qp_ctx->req_list) {
		ret = -ENOMEM;
		goto err_free_req_bitmap;
	}

	qp_ctx->sqe_list = kcalloc(ctx->fusion_limit,
		sizeof(struct hisi_sec_sqe), GFP_KERNEL);
	if (!qp_ctx->sqe_list) {
		ret = -ENOMEM;
		goto err_free_req_list;
	}

	ret = hisi_qm_start_qp(qp, 0);
	if (ret < 0)
		goto err_free_sqe_list;

	if (ctx->fusion_limit > 1 && ctx->fusion_tmout_usec) {
		INIT_DELAYED_WORK(&qp_ctx->work, qp_ctx_work_delayed_process);
		qp_ctx->work_cnt = 0;
	}

	return 0;

err_free_sqe_list:
	kfree(qp_ctx->sqe_list);
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
	kfree(qp_ctx->sqe_list);
	hisi_qm_release_qp(qp_ctx->qp);
}

static int __hisi_sec_ctx_init(struct hisi_sec_ctx *ctx, int qlen)
{
	if (!ctx || qlen < 0)
		return -EINVAL;

	ctx->req_limit = qlen;
	ctx->req_fake_limit = qlen / 2;
	atomic_set(&ctx->thread_cnt, 0);
	atomic_set(&ctx->enc_qid, 0);
	atomic_set(&ctx->dec_qid, ctx->enc_q_num);

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
	ctx->enc_q_num = ctx->q_num / 2;
	ctx->qp_ctx = kcalloc(ctx->q_num, sizeof(struct hisi_sec_qp_ctx),
		GFP_KERNEL);
	if (!ctx->qp_ctx) {
		dev_err(ctx->sec_dev, "failed to alloc qp_ctx");
		return -ENOMEM;
	}

	ctx->fusion_tmout_usec = sec->fusion_tmout_usec;
	ctx->fusion_limit = sec->fusion_limit;
	ctx->fusion_cnt = 0;
	ctx->is_fusion = 0;

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
	for (i = i - 1; i >= 0; i--)
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

	mutex_lock(ctx->sec->hisi_sec_list_lock);
	ctx->sec->q_ref -= ctx->sec->ctx_q_num;
	mutex_unlock(ctx->sec->hisi_sec_list_lock);
}

static void hisi_sec_req_cb(struct hisi_qp *qp, void *resp)
{
	struct hisi_sec_sqe *sec_sqe = (struct hisi_sec_sqe *)resp;
	u32 req_id;
	struct hisi_sec_qp_ctx *qp_ctx = qp->qp_ctx;
	struct hisi_sec_req *req;
	struct hisi_sec_dfx *dfx;

	if (sec_sqe->type == 1) {
		req_id = sec_sqe->type1.tag;
		req = qp_ctx->req_list[req_id];

		req->err_type = sec_sqe->type1.error_type;
		if (req->err_type || sec_sqe->type1.done != 0x1 ||
			sec_sqe->type1.flag != 0x2) {
			pr_err("err_type[%d] done[%d] flag[%d]\n",
				req->err_type, sec_sqe->type1.done,
				sec_sqe->type1.flag);
		}
	} else if (sec_sqe->type == 2) {
		req_id = sec_sqe->type2.tag;
		req = qp_ctx->req_list[req_id];

		req->err_type = sec_sqe->type2.error_type;
		if (req->err_type || sec_sqe->type2.done != 0x1 ||
			sec_sqe->type2.flag != 0x2) {
			pr_err("err_type[%d] done[%d] flag[%d]\n",
				req->err_type, sec_sqe->type2.done,
				sec_sqe->type2.flag);
		}
	} else {
		pr_err("err bd type [%d]\n", sec_sqe->type);
		return;
	}

	dfx = &req->ctx->sec->sec_dfx;

	sec_update_iv(req, req->c_req.sk_req->iv);

	req->ctx->req_op->buf_unmap(req->ctx, req);
	req->ctx->req_op->callback(req->ctx, req);

	__sync_add_and_fetch(&dfx->recv_cnt, 1);
}

static int sec_des_weak_key(const u64 *key, const u32 keylen)
{
	int i;

	for (i = 0; i < DES_WEAK_KEY_NUM; i++)
		if (*key == des_weak_key[i])
			return 1;

	return 0;
}

static int sec_skcipher_des_setkey(struct hisi_sec_cipher_ctx *c_ctx,
	const u32 keylen, const u8 *key)
{
	if (keylen != DES_KEY_SIZE)
		return -EINVAL;

	if (sec_des_weak_key((const u64 *)key, keylen))
		return -EKEYREJECTED;

	c_ctx->c_key_len = CKEY_LEN_DES;

	return 0;
}

static int sec_skcipher_3des_setkey(struct hisi_sec_cipher_ctx *c_ctx,
	const u32 keylen, const enum C_MODE c_mode)
{
	switch (keylen) {
	case SEC_DES3_2KEY_SIZE:
		c_ctx->c_key_len = CKEY_LEN_3DES_2KEY;
		break;
	case SEC_DES3_3KEY_SIZE:
		c_ctx->c_key_len = CKEY_LEN_3DES_3KEY;
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

static int sec_skcipher_aes_sm4_setkey(struct hisi_sec_cipher_ctx *c_ctx,
	const u32 keylen, const enum C_MODE c_mode)
{
	if (c_mode == C_MODE_XTS) {
		switch (keylen) {
		case SEC_XTS_MIN_KEY_SIZE:
			c_ctx->c_key_len = CKEY_LEN_128_BIT;
			break;
		case SEC_XTS_MAX_KEY_SIZE:
			c_ctx->c_key_len = CKEY_LEN_256_BIT;
			break;
		default:
			return -EINVAL;
		}
	} else {
		switch (keylen) {
		case AES_KEYSIZE_128:
			c_ctx->c_key_len = CKEY_LEN_128_BIT;
			break;
		case AES_KEYSIZE_192:
			c_ctx->c_key_len = CKEY_LEN_192_BIT;
			break;
		case AES_KEYSIZE_256:
			c_ctx->c_key_len = CKEY_LEN_256_BIT;
			break;
		default:
			return -EINVAL;
		}
	}

	return 0;
}

static int sec_skcipher_setkey(struct crypto_skcipher *tfm, const u8 *key,
	const u32 keylen, const enum C_ALG c_alg, const enum C_MODE c_mode)
{
	struct hisi_sec_ctx *ctx = crypto_skcipher_ctx(tfm);
	struct hisi_sec_cipher_ctx *c_ctx = &ctx->c_ctx;
	int ret;

	if (c_mode == C_MODE_XTS) {
		ret = xts_verify_key(tfm, key, keylen);
		if (ret)
			return ret;
	}

	c_ctx->c_alg  = c_alg;
	c_ctx->c_mode = c_mode;

	switch (c_alg) {
	case C_ALG_DES:
		ret = sec_skcipher_des_setkey(c_ctx, keylen, key);
		break;
	case C_ALG_3DES:
		ret = sec_skcipher_3des_setkey(c_ctx, keylen, c_mode);
		break;
	case C_ALG_AES:
	case C_ALG_SM4:
		ret = sec_skcipher_aes_sm4_setkey(c_ctx, keylen, c_mode);
		break;
	default:
		return -EINVAL;
	}

	if (ret)
		return ret;

	memcpy(c_ctx->c_key, key, keylen);

	return 0;
}

#define GEN_SEC_SETKEY_FUNC(name, c_alg, c_mode)			\
static int sec_setkey_##name(struct crypto_skcipher *tfm, const u8 *key,\
	u32 keylen)\
{									\
	return sec_skcipher_setkey(tfm, key, keylen, c_alg, c_mode);	\
}

GEN_SEC_SETKEY_FUNC(aes_ecb, C_ALG_AES, C_MODE_ECB)
GEN_SEC_SETKEY_FUNC(aes_cbc, C_ALG_AES, C_MODE_CBC)
GEN_SEC_SETKEY_FUNC(aes_ctr, C_ALG_AES, C_MODE_CTR)
GEN_SEC_SETKEY_FUNC(sm4_cbc, C_ALG_SM4, C_MODE_CBC)

GEN_SEC_SETKEY_FUNC(des_ecb, C_ALG_DES, C_MODE_ECB)
GEN_SEC_SETKEY_FUNC(des_cbc, C_ALG_DES, C_MODE_CBC)
GEN_SEC_SETKEY_FUNC(3des_ecb, C_ALG_3DES, C_MODE_ECB)
GEN_SEC_SETKEY_FUNC(3des_cbc, C_ALG_3DES, C_MODE_CBC)

GEN_SEC_SETKEY_FUNC(aes_xts, C_ALG_AES, C_MODE_XTS)
GEN_SEC_SETKEY_FUNC(sm4_xts, C_ALG_SM4, C_MODE_XTS)

#ifdef USE_DM_CRYPT_OPTIMIZE
static int sec_setkey_plain64_sm4_xts(struct crypto_skcipher *tfm,
					   const u8 *key, u32 keylen)
{
	struct hisi_sec_ctx *ctx = crypto_skcipher_ctx(tfm);
	struct geniv_key_info *info = (struct geniv_key_info *)key;
	int ret;

	keylen = info->key_size;
	key    = info->key;
	ctx->c_ctx.iv_offset = info->iv_offset;
	ctx->c_ctx.c_gran_size = info->sector_size;

	ret = xts_verify_key(tfm, key, keylen);
	if (ret)
		return ret;

	return sec_skcipher_setkey(ctx, key, keylen, C_ALG_SM4, C_MODE_XTS);
}
#endif

static int hisi_sec_get_async_ret(int ret, int req_cnt, int req_fake_limit)
{
	if (ret == 0) {
		if (req_cnt >= req_fake_limit)
			ret = -EBUSY;
		else
			ret = -EINPROGRESS;
	} else {
		if (ret == -EBUSY)
			ret = -ENOBUFS;
	}

	return ret;
}

static int hisi_sec_skcipher_alloc(struct hisi_sec_ctx *ctx,
	struct hisi_sec_req *req)
{
	struct hisi_sec_cipher_req *c_req = &req->c_req;
	struct device *sec_dev = ctx->sec_dev;

	c_req->c_ivin = dma_alloc_coherent(sec_dev,
		SEC_IV_SIZE * ctx->fusion_limit, &c_req->c_ivin_dma,
		GFP_ATOMIC);

	if (!c_req->c_ivin)
		return -ENOMEM;

	req->priv = kcalloc(ctx->fusion_limit, sizeof(void *),
		GFP_ATOMIC);
	if (!req->priv) {
		dma_free_coherent(sec_dev, SEC_IV_SIZE * ctx->fusion_limit,
			c_req->c_ivin, c_req->c_ivin_dma);
		return -ENOMEM;
	}

	return 0;
}

static int hisi_sec_skcipher_free(struct hisi_sec_ctx *ctx,
	struct hisi_sec_req *req)
{
	struct hisi_sec_cipher_req *c_req = &req->c_req;
	struct device *sec_dev = req->ctx->sec_dev;

	kfree(req->priv);
	dma_free_coherent(sec_dev, SEC_IV_SIZE * ctx->fusion_limit,
		c_req->c_ivin, c_req->c_ivin_dma);

	return 0;
}

static int hisi_sec_skcipher_buf_map(struct hisi_sec_ctx *ctx,
	struct hisi_sec_req *req)
{
	struct hisi_sec_cipher_req *c_req = &req->c_req;
	struct device *dev = ctx->sec_dev;
	struct dma_pool *pool = ctx->sec->sgl_pool;
	struct skcipher_request *sk_req =
		(struct skcipher_request *)req->priv[0];
	struct skcipher_request *sk_next;
	int i, ret = 0;

	c_req->src = sk_req->src;
	c_req->dst = sk_req->dst;

	if (ctx->is_fusion && req->fusion_num > 1) {
		int src_nents, copyed_src_nents = 0, src_nents_sum = 0;
		int dst_nents, copyed_dst_nents = 0, dst_nents_sum = 0;
		int sg_size = sizeof(struct scatterlist);

		for (i = 0; i < req->fusion_num; i++) {
			sk_next = (struct skcipher_request *)req->priv[i];
			if (sk_next == NULL) {
				dev_err(ctx->sec_dev, "nullptr at [%d]\n", i);
				return -EFAULT;
			}
			src_nents_sum += sg_nents(sk_next->src);
			dst_nents_sum += sg_nents(sk_next->dst);
			if (sk_next->src == sk_next->dst) {
				dev_err(ctx->sec_dev, "err: src == dst\n");
				return -EFAULT;
			}
		}

		c_req->src = kcalloc(src_nents_sum, sg_size, GFP_KERNEL);
		if (ZERO_OR_NULL_PTR(c_req->src))
			return -ENOMEM;

		c_req->dst = kcalloc(dst_nents_sum, sg_size, GFP_KERNEL);
		if (ZERO_OR_NULL_PTR(c_req->dst))
			return -ENOMEM;


		for (i = 0; i < req->fusion_num; i++) {
			sk_next = (struct skcipher_request *)req->priv[i];
			src_nents = sg_nents(sk_next->src);
			dst_nents = sg_nents(sk_next->dst);
			if (i != req->fusion_num - 1) {
				sg_unmark_end(&sk_next->src[src_nents - 1]);
				sg_unmark_end(&sk_next->dst[dst_nents - 1]);
			}

			memcpy(c_req->src + copyed_src_nents, sk_next->src,
				src_nents * sg_size);
			memcpy(c_req->dst + copyed_dst_nents, sk_next->dst,
				dst_nents * sg_size);

			copyed_src_nents += src_nents;
			copyed_dst_nents += dst_nents;
		}
		/* ensure copy of sg already done */
		mb();
	}

	c_req->c_in = acc_sg_buf_map_to_hw_sgl(dev, c_req->src, pool,
		&c_req->c_in_dma);
	if (IS_ERR(c_req->c_in)) {
		ret = PTR_ERR(c_req->c_in);
		goto err_free_sg_table;
	}

	if (c_req->dst == c_req->src) {
		c_req->c_out = c_req->c_in;
		c_req->c_out_dma = c_req->c_in_dma;
	} else {
		c_req->c_out = acc_sg_buf_map_to_hw_sgl(dev, c_req->dst, pool,
			&c_req->c_out_dma);
		if (IS_ERR(c_req->c_out)) {
			ret = PTR_ERR(c_req->c_out);
			goto err_unmap_src;
		}
	}

	return 0;

err_unmap_src:
	acc_sg_buf_unmap(dev, c_req->src, c_req->c_in, c_req->c_in_dma, pool);
err_free_sg_table:
	if (ctx->is_fusion && req->fusion_num > 1) {
		kfree(c_req->src);
		kfree(c_req->dst);
	}

	return ret;
}

static int hisi_sec_skcipher_buf_unmap(struct hisi_sec_ctx *ctx,
	struct hisi_sec_req *req)
{
	struct hisi_sec_cipher_req *c_req = &req->c_req;
	struct device *dev = ctx->sec_dev;
	struct dma_pool *pool = ctx->sec->sgl_pool;

	if (c_req->dst != c_req->src)
		acc_sg_buf_unmap(dev, c_req->dst, c_req->c_out,
			c_req->c_out_dma, pool);

	acc_sg_buf_unmap(dev, c_req->src, c_req->c_in, c_req->c_in_dma, pool);

	if (ctx->is_fusion && req->fusion_num > 1) {
		kfree(c_req->src);
		kfree(c_req->dst);
	}

	return 0;
}

static int hisi_sec_skcipher_copy_iv(struct hisi_sec_ctx *ctx,
	struct hisi_sec_req *req)
{
	struct hisi_sec_cipher_ctx *c_ctx = &ctx->c_ctx;
	struct hisi_sec_cipher_req *c_req = &req->c_req;
	struct skcipher_request *sk_req =
		(struct skcipher_request *)req->priv[0];
	struct crypto_skcipher *atfm = crypto_skcipher_reqtfm(sk_req);
	struct skcipher_request *sk_next;
	int i, iv_size;

	c_req->c_len = sk_req->cryptlen;

	iv_size = crypto_skcipher_ivsize(atfm);
	if (iv_size > SEC_IV_SIZE)
		return -EINVAL;

	memcpy(c_req->c_ivin, sk_req->iv, iv_size);

	if (ctx->is_fusion) {
		for (i = 1; i < req->fusion_num; i++) {
			sk_next = (struct skcipher_request *)req->priv[i];
			memcpy(c_req->c_ivin + i * iv_size, sk_next->iv,
				iv_size);
		}

		c_req->gran_num = req->fusion_num;
		c_ctx->c_gran_size = sk_req->cryptlen;
	}

	return 0;
}

static int hisi_sec_skcipher_copy_iv_dmcrypt(struct hisi_sec_ctx *ctx,
	struct hisi_sec_req *req)
{
	struct skcipher_request *sk_req =
		(struct skcipher_request *)req->priv[0];
	struct hisi_sec_cipher_req *c_req = &req->c_req;
	struct geniv_req_info *info = (struct geniv_req_info *)(sk_req->iv);

	c_req->lba = info->cc_sector + ctx->c_ctx.iv_offset;
	c_req->gran_num = sk_req->cryptlen / ctx->c_ctx.c_gran_size;

	return 0;
}

static int hisi_sec_skcipher_bd_fill_storage(struct hisi_sec_ctx *ctx,
	struct hisi_sec_req *req)
{
	struct hisi_sec_cipher_ctx *c_ctx = &ctx->c_ctx;
	struct hisi_sec_cipher_req *c_req = &req->c_req;
	struct hisi_sec_sqe *sec_sqe = &req->sec_sqe;

	if (!c_req->c_len)
		return -EINVAL;

	sec_sqe->type1.c_key_addr_l    = lower_32_bits(c_ctx->c_key_dma);
	sec_sqe->type1.c_key_addr_h    = upper_32_bits(c_ctx->c_key_dma);
	sec_sqe->type1.c_ivin_addr_l   = lower_32_bits(c_req->c_ivin_dma);
	sec_sqe->type1.c_ivin_addr_h   = upper_32_bits(c_req->c_ivin_dma);
	sec_sqe->type1.data_src_addr_l = lower_32_bits(c_req->c_in_dma);
	sec_sqe->type1.data_src_addr_h = upper_32_bits(c_req->c_in_dma);
	sec_sqe->type1.data_dst_addr_l = lower_32_bits(c_req->c_out_dma);
	sec_sqe->type1.data_dst_addr_h = upper_32_bits(c_req->c_out_dma);

	sec_sqe->type1.c_mode       = c_ctx->c_mode;
	sec_sqe->type1.c_alg        = c_ctx->c_alg;
	sec_sqe->type1.c_key_len    = c_ctx->c_key_len;

	sec_sqe->src_addr_type = 1;
	sec_sqe->dst_addr_type = 1;
	sec_sqe->type          = 1;
	sec_sqe->scene         = 5;
	sec_sqe->de	= c_req->c_in_dma != c_req->c_out_dma;

	if (c_req->encrypt == 1)
		sec_sqe->cipher = 1;
	else
		sec_sqe->cipher = 2;

	if (c_ctx->c_mode == C_MODE_XTS)
		sec_sqe->type1.ci_gen = 0x3;

	sec_sqe->type1.cipher_gran_size = c_ctx->c_gran_size;
	sec_sqe->type1.gran_num         = c_req->gran_num;
	__sync_fetch_and_add(&ctx->sec->sec_dfx.gran_task_cnt, c_req->gran_num);
	sec_sqe->type1.block_size       = 512;

	sec_sqe->type1.lba_l            = lower_32_bits(c_req->lba);
	sec_sqe->type1.lba_h            = upper_32_bits(c_req->lba);

	sec_sqe->type1.tag               = req->req_id;

	return 0;
}

static int hisi_sec_skcipher_bd_fill_multi_iv(struct hisi_sec_ctx *ctx,
	struct hisi_sec_req *req)
{
	int ret;

	ret  = hisi_sec_skcipher_bd_fill_storage(ctx, req);
	if (ret)
		return ret;

	req->sec_sqe.type1.ci_gen = 0x0;

	return 0;
}

static int hisi_sec_skcipher_bd_fill_base(struct hisi_sec_ctx *ctx,
	struct hisi_sec_req *req)
{
	struct hisi_sec_cipher_ctx *c_ctx = &ctx->c_ctx;
	struct hisi_sec_cipher_req *c_req = &req->c_req;
	struct hisi_sec_sqe *sec_sqe = &req->sec_sqe;

	if (!c_req->c_len)
		return -EINVAL;

	sec_sqe->type2.c_key_addr_l    = lower_32_bits(c_ctx->c_key_dma);
	sec_sqe->type2.c_key_addr_h    = upper_32_bits(c_ctx->c_key_dma);
	sec_sqe->type2.c_ivin_addr_l   = lower_32_bits(c_req->c_ivin_dma);
	sec_sqe->type2.c_ivin_addr_h   = upper_32_bits(c_req->c_ivin_dma);
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
	sec_sqe->de = c_req->c_in_dma != c_req->c_out_dma;

	__sync_fetch_and_add(&ctx->sec->sec_dfx.gran_task_cnt, 1);

	if (c_req->encrypt == 1)
		sec_sqe->cipher = 1;
	else
		sec_sqe->cipher = 2;

	sec_sqe->type2.c_len = c_req->c_len;
	sec_sqe->type2.tag   = req->req_id;

	return 0;
}

static int hisi_sec_bd_send_asyn(struct hisi_sec_ctx *ctx,
	struct hisi_sec_req *req)
{
	struct hisi_sec_qp_ctx *qp_ctx = req->qp_ctx;
	unsigned long flags;
	int req_cnt = req->req_cnt;
	int ret;

	spin_lock_irqsave(&qp_ctx->req_lock, flags);
	ret = hisi_qp_send(qp_ctx->qp, &req->sec_sqe);
	__sync_add_and_fetch(&ctx->sec->sec_dfx.send_cnt, 1);
	spin_unlock_irqrestore(&qp_ctx->req_lock, flags);

	return hisi_sec_get_async_ret(ret, req_cnt, ctx->req_fake_limit);
}

static int hisi_sec_skcipher_complete(struct hisi_sec_ctx *ctx,
	struct hisi_sec_req *req, int err_code)
{
	struct skcipher_request **sk_reqs =
		(struct skcipher_request **)req->priv;
	int i, req_fusion_num;

	if (ctx->is_fusion == SEC_NO_FUSION)
		req_fusion_num = 1;
	else
		req_fusion_num = req->fusion_num;

	/* ensure data already writeback */
	mb();

	for (i = 0; i < req_fusion_num; i++)
		sk_reqs[i]->base.complete(&sk_reqs[i]->base, err_code);

	/* free sk_reqs if this request is completed */
	if (err_code != -EINPROGRESS) {
		__sync_add_and_fetch(&ctx->sec->sec_dfx.put_task_cnt,
			req_fusion_num);
		kfree(sk_reqs);
	} else {
		__sync_add_and_fetch(&ctx->sec->sec_dfx.busy_comp_cnt,
			req_fusion_num);
	}

	return 0;
}

static int hisi_sec_skcipher_callback(struct hisi_sec_ctx *ctx,
	struct hisi_sec_req *req)
{
	struct hisi_sec_cipher_req *c_req = &req->c_req;
	struct device *sec_dev = req->ctx->sec_dev;

	dma_free_coherent(sec_dev, SEC_IV_SIZE * ctx->fusion_limit,
		c_req->c_ivin, c_req->c_ivin_dma);

	hisi_sec_free_req_id(req);

	if (__sync_bool_compare_and_swap(&req->fake_busy, 1, 0))
		hisi_sec_skcipher_complete(ctx, req, -EINPROGRESS);

	hisi_sec_skcipher_complete(ctx, req, req->err_type);

	return 0;
}

static int sec_get_issue_id_range(atomic_t *qid, int start, int end)
{
	int issue_id;
	int issue_len = end - start;

	issue_id = (atomic_inc_return(qid) - start) % issue_len + start;
	if (issue_id % issue_len == 0 && atomic_read(qid) > issue_len)
		atomic_sub(issue_len, qid);

	return issue_id;
}

static inline int sec_get_issue_id(struct hisi_sec_ctx *ctx,
	struct hisi_sec_req *req)
{
	int issue_id;

	if (req->c_req.encrypt == 1)
		issue_id = sec_get_issue_id_range(&ctx->enc_qid, 0,
			ctx->enc_q_num);
	else
		issue_id = sec_get_issue_id_range(&ctx->dec_qid, ctx->enc_q_num,
			ctx->q_num);

	return issue_id;
}

static inline int hisi_sec_inc_thread_cnt(struct hisi_sec_ctx *ctx)
{
	int thread_cnt;

	thread_cnt = atomic_inc_return(&ctx->thread_cnt);
	if (thread_cnt > ctx->sec->sec_dfx.thread_cnt)
		ctx->sec->sec_dfx.thread_cnt = thread_cnt;

	return 0;
}

static struct hisi_sec_req *sec_request_alloc(struct hisi_sec_ctx *ctx,
	struct hisi_sec_req *in_req, int *fusion_send, int *fake_busy)
{
	struct hisi_sec_qp_ctx *qp_ctx;
	struct hisi_sec_req *req;
	unsigned long flags;
	int issue_id, ret;

	__sync_add_and_fetch(&ctx->sec->sec_dfx.get_task_cnt, 1);

	issue_id = sec_get_issue_id(ctx, in_req);

	qp_ctx = &ctx->qp_ctx[issue_id];

	spin_lock_irqsave(&qp_ctx->req_lock, flags);

	if (in_req->c_req.sk_req->src == in_req->c_req.sk_req->dst) {
		*fusion_send = 1;
	} else if (qp_ctx->fusion_req &&
		qp_ctx->fusion_req->fusion_num < ctx->fusion_limit) {
		req = qp_ctx->fusion_req;

		*fake_busy = req->fake_busy;
		__sync_add_and_fetch(&ctx->sec->sec_dfx.fake_busy_cnt,
			*fake_busy);

		req->priv[req->fusion_num] = in_req->c_req.sk_req;
		req->fusion_num++;
		in_req->fusion_num = req->fusion_num;
		if (req->fusion_num == ctx->fusion_limit) {
			*fusion_send = 1;
			qp_ctx->fusion_req = NULL;
		}
		spin_unlock_irqrestore(&qp_ctx->req_lock, flags);
		return req;
	}

	req = in_req;

	hisi_sec_inc_thread_cnt(ctx);

	if (hisi_sec_alloc_req_id(req, qp_ctx)) {
		spin_unlock_irqrestore(&qp_ctx->req_lock, flags);
		return NULL;
	}

	req->fake_busy = 0;

	req->req_cnt = atomic_inc_return(&qp_ctx->req_cnt);
	if (req->req_cnt >= ctx->req_fake_limit) {
		req->fake_busy = 1;
		*fake_busy = 1;
		__sync_add_and_fetch(&ctx->sec->sec_dfx.fake_busy_cnt, 1);
	}

	ret = ctx->req_op->alloc(ctx, req);
	if (ret) {
		dev_err(ctx->sec_dev, "req_op alloc failed\n");
		spin_unlock_irqrestore(&qp_ctx->req_lock, flags);
		goto err_free_req_id;
	}

	if (ctx->is_fusion && *fusion_send == 0)
		qp_ctx->fusion_req = req;

	req->fusion_num = 1;

	req->priv[0] = in_req->c_req.sk_req;
	spin_unlock_irqrestore(&qp_ctx->req_lock, flags);

	if (ctx->is_fusion && *fusion_send == 0) {
		if (ctx->sec->qm.wq)
			queue_delayed_work(ctx->sec->qm.wq, &qp_ctx->work,
				nsecs_to_jiffies(ctx->fusion_tmout_usec));
		else
			schedule_delayed_work(&qp_ctx->work,
				nsecs_to_jiffies(ctx->fusion_tmout_usec));
	}

	return req;

err_free_req_id:
	hisi_sec_free_req_id(req);
	return NULL;
}

static int sec_request_transfer(struct hisi_sec_ctx *ctx,
	struct hisi_sec_req *req)
{
	int ret;

	ret = ctx->req_op->buf_map(ctx, req);
	if (ret)
		return ret;

	ret = ctx->req_op->do_transfer(ctx, req);
	if (ret)
		goto unmap_req_buf;

	memset(&req->sec_sqe, 0, sizeof(struct hisi_sec_sqe));
	ret = ctx->req_op->bd_fill(ctx, req);
	if (ret)
		goto unmap_req_buf;

	return 0;

unmap_req_buf:
	ctx->req_op->buf_unmap(ctx, req);
	return ret;
}

static int sec_request_send(struct hisi_sec_ctx *ctx, struct hisi_sec_req *req)
{
	int ret;

	ret = ctx->req_op->bd_send(ctx, req);

	if (ret == 0 || ret == -EBUSY || ret == -EINPROGRESS)
		atomic_dec(&ctx->thread_cnt);

	return ret;
}

static int sec_io_proc(struct hisi_sec_ctx *ctx, struct hisi_sec_req *in_req)
{
	struct hisi_sec_req *req;
	int ret, fusion_send = 0, fake_busy = 0;

	in_req->fusion_num = 1;

	req = sec_request_alloc(ctx, in_req, &fusion_send, &fake_busy);

	if (!req) {
		dev_err(ctx->sec_dev, "sec_request_alloc failed\n");
		return -ENOMEM;
	}

	if (ctx->is_fusion && fusion_send == 0)
		return fake_busy ? -EBUSY : -EINPROGRESS;

	ret = sec_request_transfer(ctx, req);
	if (ret) {
		dev_err(ctx->sec_dev, "sec_transfer failed! ret[%d]\n", ret);
		goto err_free_req;
	}

	ret = sec_request_send(ctx, req);
	if (ret != -EBUSY && ret != -EINPROGRESS) {
		dev_err(ctx->sec_dev, "sec_send failed ret[%d]\n", ret);
		goto err_unmap_req;
	}

	return ret;

err_unmap_req:
	ctx->req_op->buf_unmap(ctx, req);
err_free_req:
	ctx->req_op->free(ctx, req);
	hisi_sec_free_req_id(req);
	atomic_dec(&ctx->thread_cnt);
	return ret;
}

struct hisi_sec_req_op sec_req_ops_tbl[] = {
	{
		.fusion_type = SEC_NO_FUSION,
		.alloc       = hisi_sec_skcipher_alloc,
		.free        = hisi_sec_skcipher_free,
		.buf_map     = hisi_sec_skcipher_buf_map,
		.buf_unmap   = hisi_sec_skcipher_buf_unmap,
		.do_transfer = hisi_sec_skcipher_copy_iv,
		.bd_fill     = hisi_sec_skcipher_bd_fill_base,
		.bd_send     = hisi_sec_bd_send_asyn,
		.callback    = hisi_sec_skcipher_callback,
	}, {
		.fusion_type = SEC_NO_FUSION,
		.alloc       = hisi_sec_skcipher_alloc,
		.free        = hisi_sec_skcipher_free,
		.buf_map     = hisi_sec_skcipher_buf_map,
		.buf_unmap   = hisi_sec_skcipher_buf_unmap,
		.do_transfer = hisi_sec_skcipher_copy_iv_dmcrypt,
		.bd_fill     = hisi_sec_skcipher_bd_fill_storage,
		.bd_send     = hisi_sec_bd_send_asyn,
		.callback    = hisi_sec_skcipher_callback,
	}, {
		.fusion_type = SEC_IV_FUSION,
		.alloc       = hisi_sec_skcipher_alloc,
		.free        = hisi_sec_skcipher_free,
		.buf_map     = hisi_sec_skcipher_buf_map,
		.buf_unmap   = hisi_sec_skcipher_buf_unmap,
		.do_transfer = hisi_sec_skcipher_copy_iv,
		.bd_fill     = hisi_sec_skcipher_bd_fill_multi_iv,
		.bd_send     = hisi_sec_bd_send_asyn,
		.callback    = hisi_sec_skcipher_callback,
	}
};

static int sec_skcipher_crypto(struct skcipher_request *sk_req,
			bool encrypt, enum SEC_REQ_OPS_TYPE req_ops_type)
{
	struct crypto_skcipher *atfm = crypto_skcipher_reqtfm(sk_req);
	struct hisi_sec_ctx *ctx = crypto_skcipher_ctx(atfm);
	struct hisi_sec_req *req = skcipher_request_ctx(sk_req);

	if (!sk_req->src || !sk_req->dst || !sk_req->cryptlen)
		return -EINVAL;

	req->c_req.sk_req  = sk_req;
	req->c_req.encrypt = encrypt;
	req->ctx           = ctx;
	ctx->req_op        = &sec_req_ops_tbl[req_ops_type];
	ctx->is_fusion     = ctx->req_op->fusion_type;

	return sec_io_proc(ctx, req);
}

#define SEC_SKCIPHER_GEN_CRYPT(suffix, encrypt, fusion_type)	\
static int sec_skcipher_##suffix(struct skcipher_request *req)	\
{								\
	return sec_skcipher_crypto(req, encrypt, fusion_type);	\
}

SEC_SKCIPHER_GEN_CRYPT(alg_encrypt, true, SEC_OPS_SKCIPHER_ALG)
SEC_SKCIPHER_GEN_CRYPT(alg_decrypt, false, SEC_OPS_SKCIPHER_ALG)

#ifdef USE_DM_CRYPT_OPTIMIZE
SEC_SKCIPHER_GEN_CRYPT(dm_encrypt, true, SEC_OPS_DMCRYPT)
SEC_SKCIPHER_GEN_CRYPT(dm_decrypt, false, SEC_OPS_DMCRYPT)
#endif

SEC_SKCIPHER_GEN_CRYPT(fusion_encrypt, true, SEC_OPS_MULTI_IV)
SEC_SKCIPHER_GEN_CRYPT(fusion_decrypt, false, SEC_OPS_MULTI_IV)

#define SEC_SKCIPHER_GEN_ALG(sec_cra_name, sec_set_key, sec_min_key_size, \
	sec_max_key_size, sec_decrypt, sec_encrypt, blk_size, iv_size)\
{\
	.base = {\
		.cra_name = sec_cra_name,\
		.cra_driver_name = "hisi_sec_"sec_cra_name,\
		.cra_priority = SEC_PRIORITY,\
		.cra_flags = CRYPTO_ALG_ASYNC,\
		.cra_blocksize = blk_size,\
		.cra_ctxsize = sizeof(struct hisi_sec_ctx),\
		.cra_alignmask = 0,\
		.cra_module = THIS_MODULE,\
	},\
	.init = hisi_sec_cipher_ctx_init,\
	.exit = hisi_sec_cipher_ctx_exit,\
	.setkey = sec_set_key,\
	.decrypt = sec_decrypt,\
	.encrypt = sec_encrypt,\
	.min_keysize = sec_min_key_size,\
	.max_keysize = sec_max_key_size,\
	.ivsize = iv_size,\
},

#define SEC_SKCIPHER_NORMAL_ALG(name, key_func, min_key_size, \
	max_key_size, blk_size, iv_size) \
	SEC_SKCIPHER_GEN_ALG(name, key_func, min_key_size, max_key_size, \
	sec_skcipher_alg_decrypt, sec_skcipher_alg_encrypt, blk_size, iv_size)

#define SEC_SKCIPHER_DM_ALG(name, key_func, min_key_size, \
	max_key_size, blk_size, iv_size) \
	SEC_SKCIPHER_GEN_ALG(name, key_func, min_key_size, max_key_size, \
	sec_skcipher_dm_decrypt, sec_skcipher_dm_encrypt, blk_size, iv_size)

#define SEC_SKCIPHER_FUSION_ALG(name, key_func, min_key_size, \
	max_key_size, blk_size, iv_size) \
	SEC_SKCIPHER_GEN_ALG(name, key_func, min_key_size, max_key_size, \
	sec_skcipher_fusion_decrypt, sec_skcipher_fusion_encrypt, blk_size, \
	iv_size)

static struct skcipher_alg sec_algs[] = {
	SEC_SKCIPHER_NORMAL_ALG("ecb(aes)", sec_setkey_aes_ecb,
		AES_MIN_KEY_SIZE, AES_MAX_KEY_SIZE, AES_BLOCK_SIZE, 0)
	SEC_SKCIPHER_NORMAL_ALG("cbc(aes)", sec_setkey_aes_cbc,
		AES_MIN_KEY_SIZE, AES_MAX_KEY_SIZE, AES_BLOCK_SIZE,
		AES_BLOCK_SIZE)
	SEC_SKCIPHER_NORMAL_ALG("ctr(aes)", sec_setkey_aes_ctr,
		AES_MIN_KEY_SIZE, AES_MAX_KEY_SIZE, AES_BLOCK_SIZE,
		AES_BLOCK_SIZE)
	SEC_SKCIPHER_NORMAL_ALG("xts(aes)", sec_setkey_aes_xts,
		SEC_XTS_MIN_KEY_SIZE, SEC_XTS_MAX_KEY_SIZE, AES_BLOCK_SIZE,
		AES_BLOCK_SIZE)
	SEC_SKCIPHER_NORMAL_ALG("ecb(des)", sec_setkey_des_ecb,
		DES_KEY_SIZE, DES_KEY_SIZE, DES_BLOCK_SIZE, 0)
	SEC_SKCIPHER_NORMAL_ALG("cbc(des)", sec_setkey_des_cbc,
		DES_KEY_SIZE, DES_KEY_SIZE, DES_BLOCK_SIZE, DES_BLOCK_SIZE)
	SEC_SKCIPHER_NORMAL_ALG("ecb(des3_ede)", sec_setkey_3des_ecb,
		SEC_DES3_2KEY_SIZE, SEC_DES3_3KEY_SIZE, DES3_EDE_BLOCK_SIZE, 0)
	SEC_SKCIPHER_NORMAL_ALG("cbc(des3_ede)", sec_setkey_3des_cbc,
		SEC_DES3_2KEY_SIZE, SEC_DES3_3KEY_SIZE, DES3_EDE_BLOCK_SIZE,
		DES3_EDE_BLOCK_SIZE)
#ifndef SEC_FUSION_BD
	SEC_SKCIPHER_NORMAL_ALG("xts(sm4)", sec_setkey_sm4_xts,
		SEC_XTS_MIN_KEY_SIZE, SEC_XTS_MIN_KEY_SIZE, AES_BLOCK_SIZE,
		AES_BLOCK_SIZE)
	SEC_SKCIPHER_NORMAL_ALG("cbc(sm4)", sec_setkey_sm4_cbc,
		AES_MIN_KEY_SIZE, AES_MIN_KEY_SIZE, AES_BLOCK_SIZE,
		AES_BLOCK_SIZE)
#else
	SEC_SKCIPHER_FUSION_ALG("xts(sm4)", sec_setkey_sm4_xts,
		SEC_XTS_MIN_KEY_SIZE, SEC_XTS_MIN_KEY_SIZE, AES_BLOCK_SIZE,
		AES_BLOCK_SIZE)
	SEC_SKCIPHER_FUSION_ALG("cbc(sm4)", sec_setkey_sm4_cbc,
		AES_MIN_KEY_SIZE, AES_MIN_KEY_SIZE, AES_BLOCK_SIZE,
		AES_BLOCK_SIZE)
#endif

#ifdef USE_DM_CRYPT_OPTIMIZE
	SEC_SKCIPHER_DM_ALG("plain64(xts(sm4))", sec_setkey_plain64_sm4_xts,
		sizeof(struct geniv_key_info), sizeof(struct geniv_key_info),
		AES_BLOCK_SIZE, AES_BLOCK_SIZE)
#endif
};

int hisi_sec_register_to_crypto(void)
{
	return crypto_register_skciphers(sec_algs, ARRAY_SIZE(sec_algs));
}

void hisi_sec_unregister_from_crypto(void)
{
	crypto_unregister_skciphers(sec_algs, ARRAY_SIZE(sec_algs));
}
