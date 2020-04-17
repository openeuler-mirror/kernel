// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2019 HiSilicon Limited. */

#include <crypto/aes.h>
#include <crypto/algapi.h>
#include <crypto/des.h>
#include <crypto/skcipher.h>
#include <crypto/xts.h>
#include <linux/crypto.h>
#include <linux/dma-mapping.h>
#include <linux/idr.h>

#include "sec.h"
#include "sec_crypto.h"

#define SEC_PRIORITY		4001
#define SEC_XTS_MIN_KEY_SIZE	(2 * AES_MIN_KEY_SIZE)
#define SEC_XTS_MAX_KEY_SIZE	(2 * AES_MAX_KEY_SIZE)
#define SEC_DES3_2KEY_SIZE	(2 * DES_KEY_SIZE)
#define SEC_DES3_3KEY_SIZE	(3 * DES_KEY_SIZE)

/* SEC sqe(bd) bit operational relative MACRO */
#define SEC_DE_OFFSET		1
#define SEC_CI_GEN_OFFSET	6
#define SEC_CIPHER_OFFSET	4
#define SEC_SCENE_OFFSET	3
#define SEC_DST_SGL_OFFSET	2
#define SEC_SRC_SGL_OFFSET	7
#define SEC_CKEY_OFFSET		9
#define SEC_CMODE_OFFSET	12
#define SEC_AKEY_OFFSET         5
#define SEC_AEAD_ALG_OFFSET     11
#define SEC_AUTH_OFFSET		6

#define SEC_FLAG_OFFSET		7
#define SEC_FLAG_MASK		0x0780
#define SEC_TYPE_MASK		0x0F
#define SEC_DONE_MASK		0x0001

#define SEC_TOTAL_IV_SZ		(SEC_IV_SIZE * QM_Q_DEPTH)
#define SEC_SGL_SGE_NR		128
#define SEC_CTX_DEV(ctx)	(&(ctx)->sec->qm.pdev->dev)
#define SEC_CIPHER_AUTH		0xfe
#define SEC_AUTH_CIPHER		0x1
#define SEC_MAX_MAC_LEN		64
#define SEC_MAX_AAD_LEN		65535
#define SEC_TOTAL_MAC_SZ	(SEC_MAX_MAC_LEN * QM_Q_DEPTH)

#define SEC_PBUF_SZ		512
#define SEC_PBUF_IV_OFFSET	SEC_PBUF_SZ
#define SEC_PBUF_MAC_OFFSET	(SEC_PBUF_SZ + SEC_IV_SIZE)
#define SEC_PBUF_PKG		(SEC_PBUF_SZ + SEC_IV_SIZE + \
				SEC_MAX_MAC_LEN * 2)
#define SEC_PBUF_NUM		(PAGE_SIZE / SEC_PBUF_PKG)
#define SEC_PBUF_PAGE_NUM	(QM_Q_DEPTH / SEC_PBUF_NUM)
#define SEC_PBUF_LEFT_SZ	(SEC_PBUF_PKG * (QM_Q_DEPTH - \
				SEC_PBUF_PAGE_NUM * SEC_PBUF_NUM))
#define SEC_TOTAL_PBUF_SZ	(PAGE_SIZE * SEC_PBUF_PAGE_NUM + \
				SEC_PBUF_LEFT_SZ)

#define SEC_SQE_LEN_RATE	4
#define SEC_SQE_CFLAG		2
#define SEC_SQE_AEAD_FLAG	3
#define SEC_SQE_DONE		0x1

static atomic_t sec_active_devs;

/* Get an en/de-cipher queue cyclically to balance load over queues of TFM */
static inline int sec_alloc_queue_id(struct sec_ctx *ctx, struct sec_req *req)
{
	if (req->c_req.encrypt)
		return atomic_inc_return(&ctx->enc_qcyclic) % ctx->hlf_q_num;

	return atomic_inc_return(&ctx->dec_qcyclic) % ctx->hlf_q_num +
				 ctx->hlf_q_num;
}

static inline void sec_free_queue_id(struct sec_ctx *ctx, struct sec_req *req)
{
	if (req->c_req.encrypt)
		atomic_dec(&ctx->enc_qcyclic);
	else
		atomic_dec(&ctx->dec_qcyclic);
}

static int sec_alloc_req_id(struct sec_req *req, struct sec_qp_ctx *qp_ctx)
{
	int req_id;

	mutex_lock(&qp_ctx->req_lock);

	req_id = idr_alloc_cyclic(&qp_ctx->req_idr, NULL,
				  0, QM_Q_DEPTH, GFP_ATOMIC);
	mutex_unlock(&qp_ctx->req_lock);
	if (unlikely(req_id < 0)) {
		dev_err(SEC_CTX_DEV(req->ctx), "alloc req id fail!\n");
		return req_id;
	}

	req->qp_ctx = qp_ctx;
	qp_ctx->req_list[req_id] = req;
	return req_id;
}

static void sec_free_req_id(struct sec_req *req)
{
	struct sec_qp_ctx *qp_ctx = req->qp_ctx;
	int req_id = req->req_id;

	if (unlikely(req_id < 0 || req_id >= QM_Q_DEPTH)) {
		dev_err(SEC_CTX_DEV(req->ctx), "free request id invalid!\n");
		return;
	}

	qp_ctx->req_list[req_id] = NULL;
	req->qp_ctx = NULL;

	mutex_lock(&qp_ctx->req_lock);
	idr_remove(&qp_ctx->req_idr, req_id);
	mutex_unlock(&qp_ctx->req_lock);
}

static void sec_req_cb(struct hisi_qp *qp, void *resp)
{
	struct sec_qp_ctx *qp_ctx = qp->qp_ctx;
	struct sec_dfx *dfx = &qp_ctx->ctx->sec->debug.dfx;
	struct sec_sqe *bd = resp;
	struct sec_ctx *ctx;
	struct sec_req *req;
	u16 done, flag;
	int err = 0;
	u8 type;

	type = bd->type_cipher_auth & SEC_TYPE_MASK;
	if (unlikely(type != SEC_BD_TYPE2)) {
		atomic64_inc(&dfx->err_bd_cnt);
		pr_err("err bd type [%d]\n", type);
		return;
	}

	req = qp_ctx->req_list[le16_to_cpu(bd->type2.tag)];
	if (unlikely(!req)) {
		atomic64_inc(&dfx->invalid_req_cnt);
		atomic_inc(&qp->qp_status.used);
		return;
	}

	req->err_type = bd->type2.error_type;
	ctx = req->ctx;
	done = le16_to_cpu(bd->type2.done_flag) & SEC_DONE_MASK;
	flag = (le16_to_cpu(bd->type2.done_flag) &
		SEC_FLAG_MASK) >> SEC_FLAG_OFFSET;
	if (unlikely(req->err_type || done != SEC_SQE_DONE ||
	    (ctx->alg_type == SEC_SKCIPHER && flag != SEC_SQE_CFLAG))) {
		dev_err_ratelimited(SEC_CTX_DEV(ctx),
			"err_type[%d],done[%d],flag[%d]\n",
			req->err_type, done, flag);
		err = -EIO;
		atomic64_inc(&dfx->done_flag_cnt);
	}

	atomic64_inc(&dfx->recv_cnt);

	ctx->req_op->buf_unmap(ctx, req);

	ctx->req_op->callback(ctx, req, err);
}

static int sec_bd_send(struct sec_ctx *ctx, struct sec_req *req)
{
	struct sec_qp_ctx *qp_ctx = req->qp_ctx;
	int ret;

	mutex_lock(&qp_ctx->req_lock);

	ret = hisi_qp_send(qp_ctx->qp, &req->sec_sqe);

	if (ctx->fake_req_limit <=
	    atomic_read(&qp_ctx->qp->qp_status.used) && !ret) {
		list_add_tail(&req->backlog_head, &qp_ctx->backlog);
		atomic64_inc(&ctx->sec->debug.dfx.send_cnt);
		atomic64_inc(&ctx->sec->debug.dfx.send_busy_cnt);
		mutex_unlock(&qp_ctx->req_lock);
		return -EBUSY;
	}
	mutex_unlock(&qp_ctx->req_lock);

	if (unlikely(ret == -EBUSY))
		return -ENOBUFS;

	if (likely(!ret)) {
		ret = -EINPROGRESS;
		atomic64_inc(&ctx->sec->debug.dfx.send_cnt);
	}

	return ret;
}

/* Get DMA memory resources */
static int sec_alloc_civ_resource(struct device *dev, struct sec_alg_res *res)
{
	int i;

	res->c_ivin = dma_alloc_coherent(dev, SEC_TOTAL_IV_SZ,
					 &res->c_ivin_dma, GFP_KERNEL);
	if (!res->c_ivin)
		return -ENOMEM;

	for (i = 1; i < QM_Q_DEPTH; i++) {
		res[i].c_ivin_dma = res->c_ivin_dma + i * SEC_IV_SIZE;
		res[i].c_ivin = res->c_ivin + i * SEC_IV_SIZE;
	}

	return 0;
}

static void sec_free_civ_resource(struct device *dev, struct sec_alg_res *res)
{
	if (res->c_ivin)
		dma_free_coherent(dev, SEC_TOTAL_IV_SZ,
				  res->c_ivin, res->c_ivin_dma);
}

static void sec_free_pbuf_resource(struct device *dev, struct sec_alg_res *res)
{
	if (res->pbuf)
		dma_free_coherent(dev, SEC_TOTAL_PBUF_SZ,
				  res->pbuf, res->pbuf_dma);
}

/*
 * To improve performance, pbuffer is used for
 * small packets (< 512Bytes) as IOMMU translation using.
 */
static int sec_alloc_pbuf_resource(struct device *dev, struct sec_alg_res *res)
{
	int pbuf_page_offset;
	int i, j, k;

	res->pbuf = dma_alloc_coherent(dev, SEC_TOTAL_PBUF_SZ,
				       &res->pbuf_dma, GFP_KERNEL);
	if (!res->pbuf)
		return -ENOMEM;

	/*
	 * SEC_PBUF_PKG contains data pbuf, iv and
	 * out_mac : <SEC_PBUF|SEC_IV|SEC_MAC>
	 * Every PAGE contains six SEC_PBUF_PKG
	 * The sec_qp_ctx contains QM_Q_DEPTH numbers of SEC_PBUF_PKG
	 * So we need SEC_PBUF_PAGE_NUM numbers of PAGE
	 * for the SEC_TOTAL_PBUF_SZ
	 */
	for (i = 0; i <= SEC_PBUF_PAGE_NUM; i++) {
		pbuf_page_offset = PAGE_SIZE * i;
		for (j = 0; j < SEC_PBUF_NUM; j++) {
			k = i * SEC_PBUF_NUM + j;
			if (k == QM_Q_DEPTH)
				break;
			res[k].pbuf = res->pbuf +
				j * SEC_PBUF_PKG + pbuf_page_offset;
			res[k].pbuf_dma = res->pbuf_dma +
				j * SEC_PBUF_PKG + pbuf_page_offset;
		}
	}
	return 0;
}

static int sec_alg_resource_alloc(struct sec_ctx *ctx,
				  struct sec_qp_ctx *qp_ctx)
{
	struct device *dev = SEC_CTX_DEV(ctx);
	struct sec_alg_res *res = qp_ctx->res;
	int ret;

	ret = sec_alloc_civ_resource(dev, res);
	if (ret)
		return ret;

	if (ctx->pbuf_supported) {
		ret = sec_alloc_pbuf_resource(dev, res);
		if (ret) {
			dev_err(dev, "fail to alloc pbuf dma resource!\n");
			goto alloc_fail;
		}
	}

	return 0;
alloc_fail:
	sec_free_civ_resource(dev, res);

	return ret;
}

static void sec_alg_resource_free(struct sec_ctx *ctx,
				  struct sec_qp_ctx *qp_ctx)
{
	struct device *dev = SEC_CTX_DEV(ctx);

	sec_free_civ_resource(dev, qp_ctx->res);

	if (ctx->pbuf_supported)
		sec_free_pbuf_resource(dev, qp_ctx->res);
}

static int sec_create_qp_ctx(struct sec_ctx *ctx, int qp_ctx_id, int alg_type)
{
	struct device *dev = SEC_CTX_DEV(ctx);
	struct sec_qp_ctx *qp_ctx;
	struct hisi_qp *qp;
	int ret = -ENOMEM;

	qp_ctx = &ctx->qp_ctx[qp_ctx_id];
	qp = ctx->qps[qp_ctx_id];
	qp->req_type = 0;
	qp->qp_ctx = qp_ctx;
	qp->req_cb = sec_req_cb;
	qp_ctx->qp = qp;
	qp_ctx->ctx = ctx;

	mutex_init(&qp_ctx->req_lock);
	idr_init(&qp_ctx->req_idr);
	INIT_LIST_HEAD(&qp_ctx->backlog);

	qp_ctx->c_in_pool = hisi_acc_create_sgl_pool(dev, QM_Q_DEPTH,
						     SEC_SGL_SGE_NR);
	if (IS_ERR(qp_ctx->c_in_pool)) {
		dev_err(dev, "fail to create sgl pool for input!\n");
		goto err_destroy_idr;
	}

	qp_ctx->c_out_pool = hisi_acc_create_sgl_pool(dev, QM_Q_DEPTH,
						      SEC_SGL_SGE_NR);
	if (IS_ERR(qp_ctx->c_out_pool)) {
		dev_err(dev, "fail to create sgl pool for output!\n");
		goto err_free_c_in_pool;
	}

	ret = sec_alg_resource_alloc(ctx, qp_ctx);
	if (ret)
		goto err_free_c_out_pool;

	ret = hisi_qm_start_qp(qp, 0);
	if (ret < 0)
		goto err_queue_free;

	return 0;

err_queue_free:
	sec_alg_resource_free(ctx, qp_ctx);
err_free_c_out_pool:
	hisi_acc_free_sgl_pool(dev, qp_ctx->c_out_pool);
err_free_c_in_pool:
	hisi_acc_free_sgl_pool(dev, qp_ctx->c_in_pool);
err_destroy_idr:
	idr_destroy(&qp_ctx->req_idr);

	return ret;
}

static void sec_release_qp_ctx(struct sec_ctx *ctx,
			       struct sec_qp_ctx *qp_ctx)
{
	struct device *dev = SEC_CTX_DEV(ctx);

	hisi_qm_stop_qp(qp_ctx->qp);
	sec_alg_resource_free(ctx, qp_ctx);

	hisi_acc_free_sgl_pool(dev, qp_ctx->c_out_pool);
	hisi_acc_free_sgl_pool(dev, qp_ctx->c_in_pool);

	idr_destroy(&qp_ctx->req_idr);
}

static int sec_ctx_base_init(struct sec_ctx *ctx)
{
	struct sec_dev *sec;
	int i, ret;

	ctx->qps = sec_create_qps();
	if (!ctx->qps) {
		pr_err("Can not create sec qps!\n");
		return -ENODEV;
	}

	sec = container_of(ctx->qps[0]->qm, struct sec_dev, qm);
	ctx->sec = sec;
	ctx->hlf_q_num = sec->ctx_q_num >> 1;

	ctx->pbuf_supported = ctx->sec->iommu_used;

	/* Half of queue depth is taken as fake requests limit in the queue. */
	ctx->fake_req_limit = QM_Q_DEPTH >> 1;
	ctx->qp_ctx = kcalloc(sec->ctx_q_num, sizeof(struct sec_qp_ctx),
			      GFP_KERNEL);
	if (!ctx->qp_ctx)
		return -ENOMEM;

	for (i = 0; i < sec->ctx_q_num; i++) {
		ret = sec_create_qp_ctx(ctx, i, 0);
		if (ret)
			goto err_sec_release_qp_ctx;
	}
	return 0;
err_sec_release_qp_ctx:
	for (i = i - 1; i >= 0; i--)
		sec_release_qp_ctx(ctx, &ctx->qp_ctx[i]);

	sec_destroy_qps(ctx->qps, sec->ctx_q_num);
	kfree(ctx->qp_ctx);

	return ret;
}

static void sec_ctx_base_uninit(struct sec_ctx *ctx)
{
	int i;

	for (i = 0; i < ctx->sec->ctx_q_num; i++)
		sec_release_qp_ctx(ctx, &ctx->qp_ctx[i]);

	sec_destroy_qps(ctx->qps, ctx->sec->ctx_q_num);
	kfree(ctx->qp_ctx);
}

static int sec_cipher_init(struct sec_ctx *ctx)
{
	struct sec_cipher_ctx *c_ctx = &ctx->c_ctx;

	c_ctx->c_key = dma_alloc_coherent(SEC_CTX_DEV(ctx), SEC_MAX_KEY_SIZE,
					  &c_ctx->c_key_dma, GFP_KERNEL);
	if (!c_ctx->c_key)
		return -ENOMEM;

	return 0;
}

static void sec_cipher_uninit(struct sec_ctx *ctx)
{
	struct sec_cipher_ctx *c_ctx = &ctx->c_ctx;

	memzero_explicit(c_ctx->c_key, SEC_MAX_KEY_SIZE);
	dma_free_coherent(SEC_CTX_DEV(ctx), SEC_MAX_KEY_SIZE,
			  c_ctx->c_key, c_ctx->c_key_dma);
}

static int sec_skcipher_init(struct crypto_skcipher *tfm)
{
	struct sec_ctx *ctx = crypto_skcipher_ctx(tfm);
	int ret;

	ctx->alg_type = SEC_SKCIPHER;
	crypto_skcipher_set_reqsize(tfm, sizeof(struct sec_req));
	ctx->c_ctx.ivsize = crypto_skcipher_ivsize(tfm);
	if (ctx->c_ctx.ivsize > SEC_IV_SIZE) {
		dev_err(SEC_CTX_DEV(ctx), "get error skcipher iv size!\n");
		return -EINVAL;
	}

	ret = sec_ctx_base_init(ctx);
	if (ret)
		return ret;

	ret = sec_cipher_init(ctx);
	if (ret)
		goto err_cipher_init;

	return 0;
err_cipher_init:
	sec_ctx_base_uninit(ctx);

	return ret;
}

static void sec_skcipher_uninit(struct crypto_skcipher *tfm)
{
	struct sec_ctx *ctx = crypto_skcipher_ctx(tfm);

	sec_cipher_uninit(ctx);
	sec_ctx_base_uninit(ctx);
}

static int sec_skcipher_3des_setkey(struct sec_cipher_ctx *c_ctx,
				    const u32 keylen,
				    const enum sec_cmode c_mode)
{
	switch (keylen) {
	case SEC_DES3_2KEY_SIZE:
		c_ctx->c_key_len = SEC_CKEY_3DES_2KEY;
		break;
	case SEC_DES3_3KEY_SIZE:
		c_ctx->c_key_len = SEC_CKEY_3DES_3KEY;
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

static int sec_skcipher_aes_sm4_setkey(struct sec_cipher_ctx *c_ctx,
				       const u32 keylen,
				       const enum sec_cmode c_mode)
{
	if (c_mode == SEC_CMODE_XTS) {
		switch (keylen) {
		case SEC_XTS_MIN_KEY_SIZE:
			c_ctx->c_key_len = SEC_CKEY_128BIT;
			break;
		case SEC_XTS_MAX_KEY_SIZE:
			c_ctx->c_key_len = SEC_CKEY_256BIT;
			break;
		default:
			pr_err("hisi_sec2: xts mode key error!\n");
			return -EINVAL;
		}
	} else {
		switch (keylen) {
		case AES_KEYSIZE_128:
			c_ctx->c_key_len = SEC_CKEY_128BIT;
			break;
		case AES_KEYSIZE_192:
			c_ctx->c_key_len = SEC_CKEY_192BIT;
			break;
		case AES_KEYSIZE_256:
			c_ctx->c_key_len = SEC_CKEY_256BIT;
			break;
		default:
			pr_err("hisi_sec2: aes key error!\n");
			return -EINVAL;
		}
	}

	return 0;
}

static int sec_skcipher_setkey(struct crypto_skcipher *tfm, const u8 *key,
			       const u32 keylen, const enum sec_calg c_alg,
			       const enum sec_cmode c_mode)
{
	struct sec_ctx *ctx = crypto_skcipher_ctx(tfm);
	struct sec_cipher_ctx *c_ctx = &ctx->c_ctx;
	int ret;

	if (c_mode == SEC_CMODE_XTS) {
		ret = xts_verify_key(tfm, key, keylen);
		if (ret) {
			dev_err(SEC_CTX_DEV(ctx), "xts mode key err!\n");
			return ret;
		}
	}

	c_ctx->c_alg  = c_alg;
	c_ctx->c_mode = c_mode;

	switch (c_alg) {
	case SEC_CALG_3DES:
		ret = sec_skcipher_3des_setkey(c_ctx, keylen, c_mode);
		break;
	case SEC_CALG_AES:
	case SEC_CALG_SM4:
		ret = sec_skcipher_aes_sm4_setkey(c_ctx, keylen, c_mode);
		break;
	default:
		return -EINVAL;
	}

	if (ret) {
		dev_err(SEC_CTX_DEV(ctx), "set sec key err!\n");
		return ret;
	}

	memcpy(c_ctx->c_key, key, keylen);

	return 0;
}

#define GEN_SEC_SETKEY_FUNC(name, c_alg, c_mode)			\
static int sec_setkey_##name(struct crypto_skcipher *tfm, const u8 *key,\
	u32 keylen)							\
{									\
	return sec_skcipher_setkey(tfm, key, keylen, c_alg, c_mode);	\
}

GEN_SEC_SETKEY_FUNC(aes_ecb, SEC_CALG_AES, SEC_CMODE_ECB)
GEN_SEC_SETKEY_FUNC(aes_cbc, SEC_CALG_AES, SEC_CMODE_CBC)
GEN_SEC_SETKEY_FUNC(aes_xts, SEC_CALG_AES, SEC_CMODE_XTS)

GEN_SEC_SETKEY_FUNC(3des_ecb, SEC_CALG_3DES, SEC_CMODE_ECB)
GEN_SEC_SETKEY_FUNC(3des_cbc, SEC_CALG_3DES, SEC_CMODE_CBC)

GEN_SEC_SETKEY_FUNC(sm4_xts, SEC_CALG_SM4, SEC_CMODE_XTS)
GEN_SEC_SETKEY_FUNC(sm4_cbc, SEC_CALG_SM4, SEC_CMODE_CBC)

static int sec_cipher_pbuf_map(struct sec_ctx *ctx, struct sec_req *req,
			       struct scatterlist *src)
{
	struct sec_cipher_req *c_req = &req->c_req;
	struct sec_qp_ctx *qp_ctx = req->qp_ctx;
	struct device *dev = SEC_CTX_DEV(ctx);
	int copy_size, pbuf_length;
	int req_id = req->req_id;

	copy_size = c_req->c_len;

	pbuf_length = sg_copy_to_buffer(src, sg_nents(src),
				qp_ctx->res[req_id].pbuf,
				copy_size);

	if (unlikely(pbuf_length != copy_size)) {
		dev_err(dev, "copy src data to pbuf error!\n");
		return -EINVAL;
	}

	c_req->c_in_dma = qp_ctx->res[req_id].pbuf_dma;
	if (!c_req->c_in_dma) {
		dev_err(dev, "fail to set pbuffer address!\n");
		return -ENOMEM;
	}

	c_req->c_out_dma = c_req->c_in_dma;

	return 0;
}

static void sec_cipher_pbuf_unmap(struct sec_ctx *ctx, struct sec_req *req,
				  struct scatterlist *dst)
{
	struct sec_cipher_req *c_req = &req->c_req;
	struct sec_qp_ctx *qp_ctx = req->qp_ctx;
	struct device *dev = SEC_CTX_DEV(ctx);
	int copy_size, pbuf_length;
	int req_id = req->req_id;

	copy_size = c_req->c_len;

	pbuf_length = sg_copy_from_buffer(dst, sg_nents(dst),
				qp_ctx->res[req_id].pbuf,
				copy_size);

	if (unlikely(pbuf_length != copy_size))
		dev_err(dev, "copy pbuf data to dst error!\n");
}

static int sec_cipher_map(struct sec_ctx *ctx, struct sec_req *req,
			  struct scatterlist *src, struct scatterlist *dst)
{
	struct sec_cipher_req *c_req = &req->c_req;
	struct sec_qp_ctx *qp_ctx = req->qp_ctx;
	struct sec_alg_res *res = &qp_ctx->res[req->req_id];
	struct device *dev = SEC_CTX_DEV(ctx);
	int ret;

	if (req->use_pbuf) {
		ret = sec_cipher_pbuf_map(ctx, req, src);
		c_req->c_ivin = res->pbuf + SEC_PBUF_IV_OFFSET;
		c_req->c_ivin_dma = res->pbuf_dma + SEC_PBUF_IV_OFFSET;

		return ret;
	}
	c_req->c_ivin = res->c_ivin;
	c_req->c_ivin_dma = res->c_ivin_dma;

	c_req->c_in = hisi_acc_sg_buf_map_to_hw_sgl(dev, src,
						    qp_ctx->c_in_pool,
						    req->req_id,
						    &c_req->c_in_dma);

	if (IS_ERR(c_req->c_in)) {
		dev_err(dev, "fail to dma map input sgl buffers!\n");
		return PTR_ERR(c_req->c_in);
	}

	if (dst == src) {
		c_req->c_out = c_req->c_in;
		c_req->c_out_dma = c_req->c_in_dma;
	} else {
		c_req->c_out = hisi_acc_sg_buf_map_to_hw_sgl(dev, dst,
							     qp_ctx->c_out_pool,
							     req->req_id,
							     &c_req->c_out_dma);

		if (IS_ERR(c_req->c_out)) {
			dev_err(dev, "fail to dma map output sgl buffers!\n");
			hisi_acc_sg_buf_unmap(dev, src, c_req->c_in);
			return PTR_ERR(c_req->c_out);
		}
	}

	return 0;
}

static void sec_cipher_unmap(struct sec_ctx *ctx, struct sec_req *req,
			     struct scatterlist *src, struct scatterlist *dst)
{
	struct sec_cipher_req *c_req = &req->c_req;
	struct device *dev = SEC_CTX_DEV(ctx);

	if (req->use_pbuf) {
		sec_cipher_pbuf_unmap(ctx, req, dst);
	} else {
		if (dst != src)
			hisi_acc_sg_buf_unmap(dev, src, c_req->c_in);

		hisi_acc_sg_buf_unmap(dev, dst, c_req->c_out);
	}
}

static int sec_skcipher_sgl_map(struct sec_ctx *ctx, struct sec_req *req)
{
	struct skcipher_request *sq = req->c_req.sk_req;

	return sec_cipher_map(ctx, req, sq->src, sq->dst);
}

static void sec_skcipher_sgl_unmap(struct sec_ctx *ctx, struct sec_req *req)
{
	struct skcipher_request *sq = req->c_req.sk_req;

	sec_cipher_unmap(ctx, req, sq->src, sq->dst);
}

static int sec_request_transfer(struct sec_ctx *ctx, struct sec_req *req)
{
	int ret;

	ret = ctx->req_op->buf_map(ctx, req);
	if (unlikely(ret))
		return ret;

	ctx->req_op->do_transfer(ctx, req);

	ret = ctx->req_op->bd_fill(ctx, req);
	if (unlikely(ret))
		goto unmap_req_buf;

	return ret;

unmap_req_buf:
	ctx->req_op->buf_unmap(ctx, req);

	return ret;
}

static void sec_request_untransfer(struct sec_ctx *ctx, struct sec_req *req)
{
	ctx->req_op->buf_unmap(ctx, req);
}

static void sec_skcipher_copy_iv(struct sec_ctx *ctx, struct sec_req *req)
{
	struct skcipher_request *sk_req = req->c_req.sk_req;
	struct sec_cipher_req *c_req = &req->c_req;

	memcpy(c_req->c_ivin, sk_req->iv, ctx->c_ctx.ivsize);
}

static int sec_skcipher_bd_fill(struct sec_ctx *ctx, struct sec_req *req)
{
	struct sec_cipher_ctx *c_ctx = &ctx->c_ctx;
	struct sec_cipher_req *c_req = &req->c_req;
	struct sec_sqe *sec_sqe = &req->sec_sqe;
	u8 scene, sa_type, da_type;
	u8 bd_type, cipher;
	u8 de = 0;

	memset(sec_sqe, 0, sizeof(struct sec_sqe));

	sec_sqe->type2.c_key_addr = cpu_to_le64(c_ctx->c_key_dma);
	sec_sqe->type2.c_ivin_addr = cpu_to_le64(c_req->c_ivin_dma);
	sec_sqe->type2.data_src_addr = cpu_to_le64(c_req->c_in_dma);
	sec_sqe->type2.data_dst_addr = cpu_to_le64(c_req->c_out_dma);

	sec_sqe->type2.icvw_kmode |= cpu_to_le16(((u16)c_ctx->c_mode) <<
						SEC_CMODE_OFFSET);
	sec_sqe->type2.c_alg = c_ctx->c_alg;
	sec_sqe->type2.icvw_kmode |= cpu_to_le16(((u16)c_ctx->c_key_len) <<
						SEC_CKEY_OFFSET);

	bd_type = SEC_BD_TYPE2;
	if (c_req->encrypt)
		cipher = SEC_CIPHER_ENC << SEC_CIPHER_OFFSET;
	else
		cipher = SEC_CIPHER_DEC << SEC_CIPHER_OFFSET;
	sec_sqe->type_cipher_auth = bd_type | cipher;

	if (req->use_pbuf)
		sa_type = SEC_PBUF << SEC_SRC_SGL_OFFSET;
	else
		sa_type = SEC_SGL << SEC_SRC_SGL_OFFSET;
	scene = SEC_COMM_SCENE << SEC_SCENE_OFFSET;
	if (c_req->c_in_dma != c_req->c_out_dma)
		de = 0x1 << SEC_DE_OFFSET;

	sec_sqe->sds_sa_type = (de | scene | sa_type);

	/* Just set DST address type */
	if (req->use_pbuf)
		da_type = SEC_PBUF << SEC_DST_SGL_OFFSET;
	else
		da_type = SEC_SGL << SEC_DST_SGL_OFFSET;
	sec_sqe->sdm_addr_type |= da_type;

	sec_sqe->type2.clen_ivhlen |= cpu_to_le32(c_req->c_len);
	sec_sqe->type2.tag = cpu_to_le16((u16)req->req_id);

	return 0;
}

static void sec_update_iv(struct sec_req *req, enum sec_alg_type alg_type)
{
	struct skcipher_request *sk_req = req->c_req.sk_req;
	u32 iv_size = req->ctx->c_ctx.ivsize;
	struct scatterlist *sgl;
	unsigned int cryptlen;
	size_t sz;
	u8 *iv;

	if (req->c_req.encrypt)
		sgl = sk_req->dst;
	else
		sgl = sk_req->src;

	iv = sk_req->iv;
	cryptlen = sk_req->cryptlen;

	sz = sg_pcopy_to_buffer(sgl, sg_nents(sgl), iv, iv_size,
				cryptlen - iv_size);
	if (unlikely(sz != iv_size))
		dev_err(SEC_CTX_DEV(req->ctx), "copy output iv error!\n");
}

static struct sec_req *sec_back_req_clear(struct sec_ctx *ctx,
				struct sec_qp_ctx *qp_ctx)
{
	struct sec_req *backlog_req = NULL;

	mutex_lock(&qp_ctx->req_lock);
	if (ctx->fake_req_limit >=
	    atomic_read(&qp_ctx->qp->qp_status.used) &&
	    !list_empty(&qp_ctx->backlog)) {
		backlog_req = list_first_entry(&qp_ctx->backlog,
				typeof(*backlog_req), backlog_head);
		list_del(&backlog_req->backlog_head);
	}
	mutex_unlock(&qp_ctx->req_lock);

	return backlog_req;
}

static void sec_skcipher_callback(struct sec_ctx *ctx, struct sec_req *req,
				  int err)
{
	struct skcipher_request *sk_req = req->c_req.sk_req;
	struct sec_qp_ctx *qp_ctx = req->qp_ctx;
	struct skcipher_request *backlog_sk_req;
	struct sec_req *backlog_req;

	sec_free_req_id(req);

	/* IV output at encrypto of CBC mode */
	if (!err && ctx->c_ctx.c_mode == SEC_CMODE_CBC && req->c_req.encrypt)
		sec_update_iv(req, SEC_SKCIPHER);

	while (1) {
		backlog_req = sec_back_req_clear(ctx, qp_ctx);
		if (!backlog_req)
			break;

		backlog_sk_req = backlog_req->c_req.sk_req;
		backlog_sk_req->base.complete(&backlog_sk_req->base,
						-EINPROGRESS);
		atomic64_inc(&ctx->sec->debug.dfx.recv_busy_cnt);
	}

	sk_req->base.complete(&sk_req->base, err);
}

static void sec_request_uninit(struct sec_ctx *ctx, struct sec_req *req)
{
	sec_free_req_id(req);
	sec_free_queue_id(ctx, req);
}

static int sec_request_init(struct sec_ctx *ctx, struct sec_req *req)
{
	struct sec_qp_ctx *qp_ctx;
	int queue_id;

	/* To load balance */
	queue_id = sec_alloc_queue_id(ctx, req);
	qp_ctx = &ctx->qp_ctx[queue_id];

	req->req_id = sec_alloc_req_id(req, qp_ctx);
	if (unlikely(req->req_id < 0)) {
		sec_free_queue_id(ctx, req);
		return req->req_id;
	}

	return 0;
}

static int sec_process(struct sec_ctx *ctx, struct sec_req *req)
{
	struct sec_cipher_req *c_req = &req->c_req;
	int ret;

	ret = sec_request_init(ctx, req);
	if (unlikely(ret))
		return ret;

	ret = sec_request_transfer(ctx, req);
	if (unlikely(ret))
		goto err_uninit_req;

	/* Output IV as decrypto */
	if (ctx->c_ctx.c_mode == SEC_CMODE_CBC && !req->c_req.encrypt)
		sec_update_iv(req, ctx->alg_type);

	ret = ctx->req_op->bd_send(ctx, req);
	if (unlikely(ret != -EBUSY && ret != -EINPROGRESS)) {
		dev_err_ratelimited(SEC_CTX_DEV(ctx),
				    "send sec request failed!\n");
		goto err_send_req;
	}

	return ret;

err_send_req:
	/* As failing, restore the IV from user */
	if (ctx->c_ctx.c_mode == SEC_CMODE_CBC && !req->c_req.encrypt) {
		if (ctx->alg_type == SEC_SKCIPHER)
			memcpy(req->c_req.sk_req->iv, c_req->c_ivin,
			       ctx->c_ctx.ivsize);
	}

	sec_request_untransfer(ctx, req);
err_uninit_req:
	sec_request_uninit(ctx, req);

	return ret;
}

static const struct sec_req_op sec_skcipher_req_ops = {
	.buf_map	= sec_skcipher_sgl_map,
	.buf_unmap	= sec_skcipher_sgl_unmap,
	.do_transfer	= sec_skcipher_copy_iv,
	.bd_fill	= sec_skcipher_bd_fill,
	.bd_send	= sec_bd_send,
	.callback	= sec_skcipher_callback,
	.process	= sec_process,
};

static int sec_skcipher_ctx_init(struct crypto_skcipher *tfm)
{
	struct sec_ctx *ctx = crypto_skcipher_ctx(tfm);

	ctx->req_op = &sec_skcipher_req_ops;

	return sec_skcipher_init(tfm);
}

static void sec_skcipher_ctx_exit(struct crypto_skcipher *tfm)
{
	sec_skcipher_uninit(tfm);
}

static int sec_skcipher_param_check(struct sec_ctx *ctx, struct sec_req *sreq)
{
	struct skcipher_request *sk_req = sreq->c_req.sk_req;
	struct device *dev = SEC_CTX_DEV(ctx);
	u8 c_alg = ctx->c_ctx.c_alg;

	if (unlikely(!sk_req->src || !sk_req->dst)) {
		dev_err(dev, "skcipher input param error!\n");
		return -EINVAL;
	}
	sreq->c_req.c_len = sk_req->cryptlen;

	if (ctx->pbuf_supported && sk_req->cryptlen <= SEC_PBUF_SZ)
		sreq->use_pbuf = true;
	else
		sreq->use_pbuf = false;

	if (c_alg == SEC_CALG_3DES) {
		if (unlikely(sk_req->cryptlen & (DES3_EDE_BLOCK_SIZE - 1))) {
			dev_err(dev, "skcipher 3des input length error!\n");
			return -EINVAL;
		}
		return 0;
	} else if (c_alg == SEC_CALG_AES || c_alg == SEC_CALG_SM4) {
		if (unlikely(sk_req->cryptlen & (AES_BLOCK_SIZE - 1))) {
			dev_err(dev, "skcipher aes input length error!\n");
			return -EINVAL;
		}
		return 0;
	}

	dev_err(dev, "skcipher algorithm error!\n");
	return -EINVAL;
}

static int sec_skcipher_crypto(struct skcipher_request *sk_req, bool encrypt)
{
	struct crypto_skcipher *tfm = crypto_skcipher_reqtfm(sk_req);
	struct sec_req *req = skcipher_request_ctx(sk_req);
	struct sec_ctx *ctx = crypto_skcipher_ctx(tfm);
	int ret;

	if (!sk_req->cryptlen)
		return 0;

	req->c_req.sk_req = sk_req;
	req->c_req.encrypt = encrypt;
	req->ctx = ctx;

	ret = sec_skcipher_param_check(ctx, req);
	if (unlikely(ret))
		return -EINVAL;

	return ctx->req_op->process(ctx, req);
}

static int sec_skcipher_encrypt(struct skcipher_request *sk_req)
{
	return sec_skcipher_crypto(sk_req, true);
}

static int sec_skcipher_decrypt(struct skcipher_request *sk_req)
{
	return sec_skcipher_crypto(sk_req, false);
}

#define SEC_SKCIPHER_GEN_ALG(sec_cra_name, sec_set_key, sec_min_key_size, \
	sec_max_key_size, ctx_init, ctx_exit, blk_size, iv_size)\
{\
	.base = {\
		.cra_name = sec_cra_name,\
		.cra_driver_name = "hisi_sec_"sec_cra_name,\
		.cra_priority = SEC_PRIORITY,\
		.cra_flags = CRYPTO_ALG_ASYNC,\
		.cra_blocksize = blk_size,\
		.cra_ctxsize = sizeof(struct sec_ctx),\
		.cra_module = THIS_MODULE,\
	},\
	.init = ctx_init,\
	.exit = ctx_exit,\
	.setkey = sec_set_key,\
	.decrypt = sec_skcipher_decrypt,\
	.encrypt = sec_skcipher_encrypt,\
	.min_keysize = sec_min_key_size,\
	.max_keysize = sec_max_key_size,\
	.ivsize = iv_size,\
},

#define SEC_SKCIPHER_ALG(name, key_func, min_key_size, \
	max_key_size, blk_size, iv_size) \
	SEC_SKCIPHER_GEN_ALG(name, key_func, min_key_size, max_key_size, \
	sec_skcipher_ctx_init, sec_skcipher_ctx_exit, blk_size, iv_size)

static struct skcipher_alg sec_skciphers[] = {
	SEC_SKCIPHER_ALG("ecb(aes)", sec_setkey_aes_ecb,
			 AES_MIN_KEY_SIZE, AES_MAX_KEY_SIZE,
			 AES_BLOCK_SIZE, 0)

	SEC_SKCIPHER_ALG("cbc(aes)", sec_setkey_aes_cbc,
			 AES_MIN_KEY_SIZE, AES_MAX_KEY_SIZE,
			 AES_BLOCK_SIZE, AES_BLOCK_SIZE)

	SEC_SKCIPHER_ALG("xts(aes)", sec_setkey_aes_xts,
			 SEC_XTS_MIN_KEY_SIZE, SEC_XTS_MAX_KEY_SIZE,
			 AES_BLOCK_SIZE, AES_BLOCK_SIZE)

	SEC_SKCIPHER_ALG("ecb(des3_ede)", sec_setkey_3des_ecb,
			 SEC_DES3_2KEY_SIZE, SEC_DES3_3KEY_SIZE,
			 DES3_EDE_BLOCK_SIZE, 0)

	SEC_SKCIPHER_ALG("cbc(des3_ede)", sec_setkey_3des_cbc,
			 SEC_DES3_2KEY_SIZE, SEC_DES3_3KEY_SIZE,
			 DES3_EDE_BLOCK_SIZE, DES3_EDE_BLOCK_SIZE)

	SEC_SKCIPHER_ALG("xts(sm4)", sec_setkey_sm4_xts,
			 SEC_XTS_MIN_KEY_SIZE, SEC_XTS_MIN_KEY_SIZE,
			 AES_BLOCK_SIZE, AES_BLOCK_SIZE)

	SEC_SKCIPHER_ALG("cbc(sm4)", sec_setkey_sm4_cbc,
			 AES_MIN_KEY_SIZE, AES_MIN_KEY_SIZE,
			 AES_BLOCK_SIZE, AES_BLOCK_SIZE)

};

int sec_register_to_crypto(void)
{
	/* To avoid repeat register */
	if (atomic_add_return(1, &sec_active_devs) == 1)
		return crypto_register_skciphers(sec_skciphers,
						 ARRAY_SIZE(sec_skciphers));

	return 0;
}

void sec_unregister_from_crypto(void)
{
	if (atomic_sub_return(1, &sec_active_devs) == 0)
		crypto_unregister_skciphers(sec_skciphers,
					    ARRAY_SIZE(sec_skciphers));
}
