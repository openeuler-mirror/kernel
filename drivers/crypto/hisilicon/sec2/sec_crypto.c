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
#define SEC_FLAG_OFFSET		7
#define SEC_FLAG_MASK		0x0780
#define SEC_TYPE_MASK		0x0F
#define SEC_DONE_MASK		0x0001

#define SEC_TOTAL_IV_SZ		(SEC_IV_SIZE * QM_Q_DEPTH)
#define SEC_SGL_SGE_NR		128
#define SEC_CTX_DEV(ctx)	(&(ctx)->sec->qm.pdev->dev)

static DEFINE_MUTEX(sec_algs_lock);
static unsigned int sec_active_devs;

/* Get an en/de-cipher queue cyclically to balance load over queues of TFM */
static inline int sec_get_queue_id(struct sec_ctx *ctx, struct sec_req *req)
{
	if (req->c_req.encrypt)
		return (u32)atomic_inc_return(&ctx->enc_qcyclic) %
					      ctx->hlf_q_num;

	return (u32)atomic_inc_return(&ctx->dec_qcyclic) % ctx->hlf_q_num +
				      ctx->hlf_q_num;
}

static inline void sec_put_queue_id(struct sec_ctx *ctx, struct sec_req *req)
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
	if (req_id < 0) {
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

	if (req_id < 0 || req_id >= QM_Q_DEPTH) {
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
	struct sec_sqe *bd = resp;
	u16 done, flag;
	u8 type;
	struct sec_req *req;

	type = bd->type_cipher_auth & SEC_TYPE_MASK;
	if (type == SEC_BD_TYPE2) {
		req = qp_ctx->req_list[le16_to_cpu(bd->type2.tag)];
		req->err_type = bd->type2.error_type;

		done = le16_to_cpu(bd->type2.done_flag) & SEC_DONE_MASK;
		flag = (le16_to_cpu(bd->type2.done_flag) &
				   SEC_FLAG_MASK) >> SEC_FLAG_OFFSET;
		if (req->err_type || done != 0x1 || flag != 0x2)
			dev_err(SEC_CTX_DEV(req->ctx),
				"err_type[%d],done[%d],flag[%d]\n",
				req->err_type, done, flag);
	} else {
		pr_err("err bd type [%d]\n", type);
		return;
	}

	__sync_add_and_fetch(&req->ctx->sec->debug.dfx.recv_cnt, 1);

	req->ctx->req_op->buf_unmap(req->ctx, req);

	req->ctx->req_op->callback(req->ctx, req);
}

static int sec_bd_send(struct sec_ctx *ctx, struct sec_req *req)
{
	struct sec_qp_ctx *qp_ctx = req->qp_ctx;
	int ret;

	mutex_lock(&qp_ctx->req_lock);
	ret = hisi_qp_send(qp_ctx->qp, &req->sec_sqe);
	mutex_unlock(&qp_ctx->req_lock);
	__sync_add_and_fetch(&ctx->sec->debug.dfx.send_cnt, 1);

	if (ret == -EBUSY)
		return -ENOBUFS;

	if (!ret) {
		if (req->fake_busy)
			ret = -EBUSY;
		else
			ret = -EINPROGRESS;
	}

	return ret;
}

static int sec_create_qp_ctx(struct hisi_qm *qm, struct sec_ctx *ctx,
			     int qp_ctx_id, int alg_type)
{
	struct device *dev = SEC_CTX_DEV(ctx);
	struct sec_qp_ctx *qp_ctx;
	struct hisi_qp *qp;
	int ret = -ENOMEM;

	qp = hisi_qm_create_qp(qm, alg_type);
	if (IS_ERR(qp))
		return PTR_ERR(qp);

	qp_ctx = &ctx->qp_ctx[qp_ctx_id];
	qp->req_type = 0;
	qp->qp_ctx = qp_ctx;
	qp->req_cb = sec_req_cb;
	qp_ctx->qp = qp;
	qp_ctx->ctx = ctx;

	mutex_init(&qp_ctx->req_lock);
	atomic_set(&qp_ctx->pending_reqs, 0);
	idr_init(&qp_ctx->req_idr);

	qp_ctx->req_list = kcalloc(QM_Q_DEPTH, sizeof(void *), GFP_ATOMIC);
	if (!qp_ctx->req_list)
		goto err_destroy_idr;

	qp_ctx->c_in_pool = hisi_acc_create_sgl_pool(dev, QM_Q_DEPTH,
						     SEC_SGL_SGE_NR);
	if (!qp_ctx->c_in_pool) {
		dev_err(dev, "fail to create sgl pool for input!\n");
		goto err_free_req_list;
	}

	qp_ctx->c_out_pool = hisi_acc_create_sgl_pool(dev, QM_Q_DEPTH,
						      SEC_SGL_SGE_NR);
	if (!qp_ctx->c_out_pool) {
		dev_err(dev, "fail to create sgl pool for output!\n");
		goto err_free_c_in_pool;
	}

	ret = ctx->req_op->resource_alloc(ctx, qp_ctx);
	if (ret)
		goto err_free_c_out_pool;

	ret = hisi_qm_start_qp(qp, 0);
	if (ret < 0)
		goto err_queue_free;

	return 0;

err_queue_free:
	ctx->req_op->resource_free(ctx, qp_ctx);
err_free_c_out_pool:
	hisi_acc_free_sgl_pool(dev, qp_ctx->c_out_pool);
err_free_c_in_pool:
	hisi_acc_free_sgl_pool(dev, qp_ctx->c_in_pool);
err_free_req_list:
	kfree(qp_ctx->req_list);
err_destroy_idr:
	idr_destroy(&qp_ctx->req_idr);
	hisi_qm_release_qp(qp);

	return ret;
}

static void sec_release_qp_ctx(struct sec_ctx *ctx,
			       struct sec_qp_ctx *qp_ctx)
{
	struct device *dev = SEC_CTX_DEV(ctx);

	hisi_qm_stop_qp(qp_ctx->qp);
	ctx->req_op->resource_free(ctx, qp_ctx);

	hisi_acc_free_sgl_pool(dev, qp_ctx->c_out_pool);
	hisi_acc_free_sgl_pool(dev, qp_ctx->c_in_pool);

	idr_destroy(&qp_ctx->req_idr);
	kfree(qp_ctx->req_list);
	hisi_qm_release_qp(qp_ctx->qp);
}

static int sec_skcipher_init(struct crypto_skcipher *tfm)
{
	struct sec_ctx *ctx = crypto_skcipher_ctx(tfm);
	struct sec_cipher_ctx *c_ctx;
	struct sec_dev *sec;
	struct device *dev;
	struct hisi_qm *qm;
	int i, ret;

	crypto_skcipher_set_reqsize(tfm, sizeof(struct sec_req));

	sec = sec_find_device(cpu_to_node(smp_processor_id()));
	if (!sec) {
		pr_err("find no Hisilicon SEC device!\n");
		return -ENODEV;
	}
	ctx->sec = sec;
	qm = &sec->qm;
	dev = &qm->pdev->dev;
	ctx->hlf_q_num = sec->ctx_q_num >> 0x1;

	/* Half of queue depth is taken as fake requests limit in the queue. */
	ctx->fake_req_limit = QM_Q_DEPTH >> 0x1;
	ctx->qp_ctx = kcalloc(sec->ctx_q_num, sizeof(struct sec_qp_ctx),
			      GFP_KERNEL);
	if (!ctx->qp_ctx)
		return -ENOMEM;

	for (i = 0; i < sec->ctx_q_num; i++) {
		ret = sec_create_qp_ctx(qm, ctx, i, 0);
		if (ret)
			goto err_sec_release_qp_ctx;
	}

	c_ctx = &ctx->c_ctx;
	c_ctx->ivsize = crypto_skcipher_ivsize(tfm);
	if (c_ctx->ivsize > SEC_IV_SIZE) {
		dev_err(dev, "get error iv size!\n");
		ret = -EINVAL;
		goto err_sec_release_qp_ctx;
	}
	c_ctx->c_key = dma_alloc_coherent(dev, SEC_MAX_KEY_SIZE,
					  &c_ctx->c_key_dma, GFP_KERNEL);
	if (!c_ctx->c_key) {
		ret = -ENOMEM;
		goto err_sec_release_qp_ctx;
	}

	return 0;

err_sec_release_qp_ctx:
	for (i = i - 1; i >= 0; i--)
		sec_release_qp_ctx(ctx, &ctx->qp_ctx[i]);

	kfree(ctx->qp_ctx);
	return ret;
}

static void sec_skcipher_exit(struct crypto_skcipher *tfm)
{
	struct sec_ctx *ctx = crypto_skcipher_ctx(tfm);
	struct sec_cipher_ctx *c_ctx = &ctx->c_ctx;
	int i = 0;

	if (c_ctx->c_key) {
		dma_free_coherent(SEC_CTX_DEV(ctx), SEC_MAX_KEY_SIZE,
				  c_ctx->c_key, c_ctx->c_key_dma);
		c_ctx->c_key = NULL;
	}

	for (i = 0; i < ctx->sec->ctx_q_num; i++)
		sec_release_qp_ctx(ctx, &ctx->qp_ctx[i]);

	kfree(ctx->qp_ctx);
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

static int sec_skcipher_get_res(struct sec_ctx *ctx,
				struct sec_req *req)
{
	struct sec_qp_ctx *qp_ctx = req->qp_ctx;
	struct sec_cipher_res *c_res = qp_ctx->alg_meta_data;
	struct sec_cipher_req *c_req = &req->c_req;
	int req_id = req->req_id;

	c_req->c_ivin = c_res[req_id].c_ivin;
	c_req->c_ivin_dma = c_res[req_id].c_ivin_dma;

	return 0;
}

static int sec_skcipher_resource_alloc(struct sec_ctx *ctx,
				       struct sec_qp_ctx *qp_ctx)
{
	struct device *dev = SEC_CTX_DEV(ctx);
	struct sec_cipher_res *res;
	int i;

	res = kcalloc(QM_Q_DEPTH, sizeof(struct sec_cipher_res), GFP_KERNEL);
	if (!res)
		return -ENOMEM;

	res->c_ivin = dma_alloc_coherent(dev, SEC_TOTAL_IV_SZ,
					   &res->c_ivin_dma, GFP_KERNEL);
	if (!res->c_ivin) {
		kfree(res);
		return -ENOMEM;
	}

	for (i = 1; i < QM_Q_DEPTH; i++) {
		res[i].c_ivin_dma = res->c_ivin_dma + i * SEC_IV_SIZE;
		res[i].c_ivin = res->c_ivin + i * SEC_IV_SIZE;
	}
	qp_ctx->alg_meta_data = res;

	return 0;
}

static void sec_skcipher_resource_free(struct sec_ctx *ctx,
				      struct sec_qp_ctx *qp_ctx)
{
	struct sec_cipher_res *res = qp_ctx->alg_meta_data;
	struct device *dev = SEC_CTX_DEV(ctx);

	if (!res)
		return;

	dma_free_coherent(dev, SEC_TOTAL_IV_SZ, res->c_ivin, res->c_ivin_dma);
	kfree(res);
}

static int sec_skcipher_map(struct device *dev, struct sec_req *req,
			    struct scatterlist *src, struct scatterlist *dst)
{
	struct sec_cipher_req *c_req = &req->c_req;
	struct sec_qp_ctx *qp_ctx = req->qp_ctx;

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

static int sec_skcipher_sgl_map(struct sec_ctx *ctx, struct sec_req *req)
{
	struct sec_cipher_req *c_req = &req->c_req;

	return sec_skcipher_map(SEC_CTX_DEV(ctx), req,
				c_req->sk_req->src, c_req->sk_req->dst);
}

static void sec_skcipher_sgl_unmap(struct sec_ctx *ctx, struct sec_req *req)
{
	struct device *dev = SEC_CTX_DEV(ctx);
	struct sec_cipher_req *c_req = &req->c_req;
	struct skcipher_request *sk_req = c_req->sk_req;

	if (sk_req->dst != sk_req->src)
		hisi_acc_sg_buf_unmap(dev, sk_req->src, c_req->c_in);

	hisi_acc_sg_buf_unmap(dev, sk_req->dst, c_req->c_out);
}

static int sec_request_transfer(struct sec_ctx *ctx, struct sec_req *req)
{
	int ret;

	ret = ctx->req_op->buf_map(ctx, req);
	if (ret)
		return ret;

	ctx->req_op->do_transfer(ctx, req);

	ret = ctx->req_op->bd_fill(ctx, req);
	if (ret)
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

#ifdef CONFIG_CRYPTO_DEV_HISI_SEC2_FUSION
static int sec_alloc_req_id_nolock(struct sec_req *req,
					struct sec_qp_ctx *qp_ctx)
{
	int req_id;

	req_id = idr_alloc_cyclic(&qp_ctx->req_idr, NULL, 0,
			QM_Q_DEPTH, GFP_ATOMIC);
	if (req_id < 0) {
		pr_err("fail to alloc request id[%d]!\n", req_id);
		return req_id;
	}

	req->qp_ctx = qp_ctx;
	qp_ctx->req_list[req_id] = req;

	return req_id;
}
static void sec_fusion_req_cb(struct hisi_qp *qp, void *resp)
{
	struct sec_qp_ctx *qp_ctx = qp->qp_ctx;
	struct sec_sqe *bd = resp;
	struct sec_req *req;
	u8 done, flag, type;

	type = bd->type_cipher_auth & SEC_TYPE_MASK;
	if (type == SEC_BD_TYPE1) {
		req = qp_ctx->req_list[bd->type1.tag];
		req->err_type = bd->type1.error_type;

		done = bd->type1.dn_icvflg_dif & SEC_DONE_MASK;
		flag = (bd->type1.dn_icvflg_dif & SEC_FLAG_MASK) >>
			SEC_FLAG_OFFSET;
		if (req->err_type || done != 0x1 || flag != 0x2)
			pr_err("err_type[%d] done[%d] flag[%d]\n",
				req->err_type, done, flag);
	} else {
		pr_err("fusion bd type [%d] error!\n", type);
		return;
	}
	req->ctx->req_op->buf_unmap(req->ctx, req);
	req->ctx->req_op->callback(req->ctx, req);

	__sync_add_and_fetch(&req->ctx->sec->debug.dfx.recv_cnt, 1);
}

static int sec_skcipher_get_fusion_res(struct sec_ctx *ctx,
				struct sec_req *req)
{
	struct sec_qp_ctx *qp_ctx = req->qp_ctx;
	struct sec_cipher_res *c_res = qp_ctx->alg_meta_data;
	struct sec_cipher_req *c_req = &req->c_req;
	int req_id = req->req_id;

	c_req->c_ivin = c_res[req_id].c_ivin;
	c_req->c_ivin_dma = c_res[req_id].c_ivin_dma;
	req->sk_reqs = c_res[req_id].sk_reqs;
	c_req->src = c_res[req_id].src;
	c_req->dst = c_res[req_id].dst;

	return 0;
}
void sec_qp_ctx_work_process(struct sec_qp_ctx *qp_ctx)
{
	ktime_t cur_time = ktime_get();
	struct sec_req *req;
	struct sec_ctx *ctx;
	int ret;

	mutex_lock(&qp_ctx->req_lock);

	req = qp_ctx->fusion_req;
	if (!req) {
		mutex_unlock(&qp_ctx->req_lock);
		return;
	}

	ctx = req->ctx;
	if (!ctx || req->fusion_num == ctx->sec->fusion_limit) {
		mutex_unlock(&qp_ctx->req_lock);
		return;
	}

	if (cur_time - qp_ctx->fusion_req->st_time < ctx->sec->fusion_time) {
		mutex_unlock(&qp_ctx->req_lock);
		return;
	}

	qp_ctx->fusion_req = NULL;

	mutex_unlock(&qp_ctx->req_lock);

	ret = sec_request_transfer(ctx, req);
	if (ret)
		goto err_free_req;

	ret = ctx->req_op->bd_send(ctx, req);

	if (!ret || ret == -EBUSY || ret == -EINPROGRESS)
		atomic_dec(&ctx->thread_cnt);

	__sync_add_and_fetch(&ctx->sec->debug.dfx.send_by_tmout, 1);
	if (ret != -EBUSY && ret != -EINPROGRESS) {
		dev_err(SEC_CTX_DEV(ctx), "send sqe fail!\n");
		goto err_unmap_req;
	}

	return;

err_unmap_req:
	ctx->req_op->buf_unmap(ctx, req);
err_free_req:
	sec_free_req_id(req);
	atomic_dec(&ctx->thread_cnt);
}

void sec_ctx_work_process(struct work_struct *work)
{
	struct sec_ctx *ctx;
	int i;

	ctx = container_of(work, struct sec_ctx, work);
	for (i = 0; i < ctx->sec->ctx_q_num; i++)
		sec_qp_ctx_work_process(&ctx->qp_ctx[i]);
}

static enum hrtimer_restart sec_hrtimer_handler(struct hrtimer *timer)
{
	struct sec_ctx *ctx;
	ktime_t tim;

	ctx = container_of(timer, struct sec_ctx, timer);
	tim = ktime_set(0, ctx->sec->fusion_time);

	if (ctx->sec->wq)
		queue_work(ctx->sec->wq, &ctx->work);
	else
		schedule_work(&ctx->work);

	hrtimer_forward(timer, timer->base->get_time(), tim);

	return HRTIMER_RESTART;
}

static int sec_ctx_fusion_init(struct sec_ctx *ctx, int qlen)
{
	int i;

	if (!ctx || qlen < 0)
		return -EINVAL;

	for (i = 0; i < ctx->sec->ctx_q_num; i++) {
		ctx->qp_ctx[i].fusion_num = 0;
		ctx->qp_ctx[i].fusion_req = NULL;

		/* Replace the call back function set before */
		ctx->qp_ctx[i].qp->req_cb = sec_fusion_req_cb;
	}

	ctx->fake_req_limit = qlen >> 0x1;
	atomic_set(&ctx->thread_cnt, 0);

	if (ctx->sec->fusion_limit > 1 && ctx->sec->fusion_time > 0) {
		ktime_t tim = ktime_set(0, ctx->sec->fusion_time);

		hrtimer_init(&ctx->timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
		ctx->timer.function = sec_hrtimer_handler;
		hrtimer_start(&ctx->timer, tim, HRTIMER_MODE_REL);
		INIT_WORK(&ctx->work, sec_ctx_work_process);
	}

	return 0;
}

static void sec_ctx_fusion_exit(struct crypto_skcipher *tfm)
{
	struct sec_ctx *ctx = crypto_skcipher_ctx(tfm);

	if (ctx->sec->fusion_limit > 1 && ctx->sec->fusion_time > 0)
		hrtimer_cancel(&ctx->timer);
}

static int sec_fusion_skcipher_bd_fill(struct sec_ctx *ctx,
					struct sec_req *req)
{
	struct sec_cipher_ctx *c_ctx = &ctx->c_ctx;
	struct sec_cipher_req *c_req = &req->c_req;
	struct sec_sqe *sec_sqe = &req->sec_sqe;
	u8 de, scene, cipher, ci_gen;

	if (!c_req->c_len)
		return -EINVAL;
	memset(sec_sqe, 0, sizeof(struct sec_sqe));

	sec_sqe->type1.c_key_addr = cpu_to_le64(c_ctx->c_key_dma);
	sec_sqe->type1.c_ivin_addr = cpu_to_le64(c_req->c_ivin_dma);
	sec_sqe->type1.data_src_addr = cpu_to_le64(c_req->c_in_dma);
	sec_sqe->type1.data_dst_addr = cpu_to_le64(c_req->c_out_dma);

	sec_sqe->type1.icvw_kmode |=
		cpu_to_le16(((u16)c_ctx->c_mode) << SEC_CMODE_OFFSET);
	sec_sqe->type1.c_alg = cpu_to_le16((u16)c_ctx->c_alg);
	sec_sqe->type1.icvw_kmode |=
		cpu_to_le16(((u16)c_ctx->c_key_len) << SEC_CKEY_OFFSET);

	if (c_req->encrypt)
		cipher = SEC_CIPHER_ENC << SEC_CIPHER_OFFSET;
	else
		cipher = SEC_CIPHER_DEC << SEC_CIPHER_OFFSET;
	sec_sqe->type_cipher_auth = SEC_BD_TYPE1 | cipher;

	scene = SEC_SCENE_STORAGE << SEC_SCENE_OFFSET;
	de = (c_req->c_in_dma != c_req->c_out_dma) << SEC_DE_OFFSET;
	sec_sqe->sds_sa_type = (de | scene | (SEC_SGL << SEC_SRC_SGL_OFFSET));
	sec_sqe->sdm_addr_type |= (SEC_SGL << SEC_DST_SGL_OFFSET);

	ci_gen = SEC_CI_GEN_BY_ADDR << SEC_CI_GEN_OFFSET;
	if (c_ctx->c_mode == SEC_CMODE_XTS && c_req->lba) {
		ci_gen = SEC_CI_GEN_BY_LBA << SEC_CI_GEN_OFFSET;
		sec_sqe->type1.lba = cpu_to_le64(c_req->lba);
	}
	sec_sqe->huk_key_ci = ci_gen;

	sec_sqe->type1.cipher_gran_size = cpu_to_le32(c_ctx->c_gran_size);
	sec_sqe->type1.gran_num = cpu_to_le16((u16)c_req->gran_num);
	sec_sqe->type1.block_size = cpu_to_le16((u16)c_req->c_len);
	sec_sqe->type1.tag = cpu_to_le16((u16)req->req_id);
	__sync_fetch_and_add(&ctx->sec->debug.dfx.gran_task_cnt,
			     c_req->gran_num);

	return 0;
}

static int sec_skcipher_fusion_resource_alloc(struct sec_ctx *ctx,
				    struct sec_qp_ctx *qp_ctx)
{
	int i, ret;
	struct device *dev = SEC_CTX_DEV(ctx);
	int req_num = ctx->sec->fusion_limit;
	struct sec_cipher_res *res = qp_ctx->alg_meta_data;
	int alloc_num = QM_Q_DEPTH * req_num;

	res = kcalloc(QM_Q_DEPTH, sizeof(struct sec_cipher_res), GFP_KERNEL);
	if (!res)
		return -ENOMEM;

	res->sk_reqs = kcalloc(alloc_num,
		sizeof(struct skcipher_request *), GFP_KERNEL);
	if (!res->sk_reqs) {
		ret = -ENOMEM;
		goto err_free_c_res;
	}
	res->c_ivin = dma_alloc_coherent(dev,
		SEC_IV_SIZE * alloc_num, &res->c_ivin_dma, GFP_KERNEL);
	if (!res->c_ivin) {
		ret = -ENOMEM;
		goto err_free_sk_reqs;
	}
	res->src = kcalloc(alloc_num, sizeof(struct scatterlist), GFP_KERNEL);
	if (!res->src) {
		ret = -ENOMEM;
		goto err_free_c_ivin;
	}
	res->dst = kcalloc(alloc_num, sizeof(struct scatterlist), GFP_KERNEL);
	if (!res->dst) {
		ret = -ENOMEM;
		goto err_free_src;
	}
	for (i = 1; i < QM_Q_DEPTH; i++) {
		res[i].sk_reqs = res->sk_reqs + i * req_num;
		res[i].c_ivin = res->c_ivin + i * req_num * SEC_IV_SIZE;
		res[i].c_ivin_dma = res->c_ivin_dma + i * req_num *
				    SEC_IV_SIZE;
		res[i].src = res->src + i * req_num;
		res[i].dst = res->dst + i * req_num;
	}
	qp_ctx->alg_meta_data = res;
	return 0;

err_free_src:
	kfree(res->src);
err_free_c_ivin:
	dma_free_coherent(dev, SEC_IV_SIZE * alloc_num, res->c_ivin,
		res->c_ivin_dma);
err_free_sk_reqs:
	kfree(res->sk_reqs);
err_free_c_res:
	kfree(res);

	return ret;
}

static void sec_skcipher_fusion_resource_free(struct sec_ctx *ctx,
				    struct sec_qp_ctx *qp_ctx)
{
	struct sec_cipher_res *res = qp_ctx->alg_meta_data;
	int alloc_num = QM_Q_DEPTH * ctx->sec->fusion_limit;
	struct device *dev = SEC_CTX_DEV(ctx);

	if (!res)
		return;
	kfree(res->dst);
	kfree(res->src);
	dma_free_coherent(dev, SEC_IV_SIZE * alloc_num, res->c_ivin,
		res->c_ivin_dma);
	kfree(res->sk_reqs);
	kfree(res);
}

static struct sec_req *sec_fusion_request_init(struct sec_ctx *ctx,
				struct sec_req *in_req, int *fusion_send)
{
	struct sec_qp_ctx *qp_ctx;
	int issue_id, ret, thread_cnt;
	struct sec_req *req;

	__sync_add_and_fetch(&ctx->sec->debug.dfx.get_task_cnt, 1);

	issue_id = sec_get_queue_id(ctx, in_req);
	thread_cnt = atomic_inc_return(&ctx->thread_cnt);
	if (thread_cnt > ctx->sec->debug.dfx.thread_cnt)
		ctx->sec->debug.dfx.thread_cnt = thread_cnt;
	qp_ctx = &ctx->qp_ctx[issue_id];

	in_req->fusion_num = 1;
	mutex_lock(&qp_ctx->req_lock);
	if (in_req->c_req.sk_req->src == in_req->c_req.sk_req->dst) {
		*fusion_send = 1;
	} else if (qp_ctx->fusion_req &&
		qp_ctx->fusion_req->fusion_num < ctx->sec->fusion_limit) {
		req = qp_ctx->fusion_req;

		__sync_add_and_fetch(&ctx->sec->debug.dfx.fake_busy_cnt, 1);

		req->sk_reqs[req->fusion_num] = in_req->c_req.sk_req;
		req->fusion_num++;
		in_req->fusion_num = req->fusion_num;
		if (req->fusion_num == ctx->sec->fusion_limit) {
			*fusion_send = 1;
			qp_ctx->fusion_req = NULL;
		}
		mutex_unlock(&qp_ctx->req_lock);
		return req;
	}

	req = in_req;
	req->req_id = sec_alloc_req_id_nolock(req, qp_ctx);
	if (req->req_id < 0) {
		mutex_unlock(&qp_ctx->req_lock);
		return NULL;
	}

	if (ctx->fake_req_limit <= atomic_inc_return(&qp_ctx->pending_reqs)) {
		req->fake_busy = 1;
		__sync_add_and_fetch(&ctx->sec->debug.dfx.fake_busy_cnt, 1);
	} else {
		req->fake_busy = 0;
	}

	ret = ctx->req_op->get_res(ctx, req);
	if (ret) {
		dev_err(SEC_CTX_DEV(ctx), "req_op get_res failed\n");
		mutex_unlock(&qp_ctx->req_lock);
		goto err_free_req_id;
	}

	if (ctx->sec->fusion_limit <= 1 || !ctx->sec->fusion_time)
		*fusion_send = 1;

	if (ctx->is_fusion && *fusion_send == 0)
		qp_ctx->fusion_req = req;

	req->fusion_num = 1;

	/* Not storage scenario */
	req->c_req.lba = 0;
	req->sk_reqs[0] = in_req->c_req.sk_req;
	req->st_time = ktime_get();

	mutex_unlock(&qp_ctx->req_lock);

	return req;

err_free_req_id:
	atomic_dec(&qp_ctx->pending_reqs);
	sec_free_req_id(req);
	sec_put_queue_id(ctx, req);
	return NULL;
}

static int sec_fusion_process(struct sec_ctx *ctx, struct sec_req *in_req)
{
	struct device *dev = SEC_CTX_DEV(ctx);
	struct sec_req *req;
	int fusion_send = 0;
	int ret;

	req = sec_fusion_request_init(ctx, in_req, &fusion_send);
	if (!req) {
		dev_err(dev, "sec_request_alloc failed\n");
		return -ENOMEM;
	}

	if (ctx->is_fusion && !fusion_send)
		return req->fake_busy ? -EBUSY : -EINPROGRESS;

	ret = sec_request_transfer(ctx, req);
	if (ret) {
		dev_err(dev, "sec_transfer failed! ret[%d]\n", ret);
		goto err_with_req;
	}

	ret = ctx->req_op->bd_send(ctx, req);

	if (!ret || ret == -EBUSY || ret == -EINPROGRESS)
		atomic_dec(&ctx->thread_cnt);
	__sync_add_and_fetch(&ctx->sec->debug.dfx.send_by_full, 1);
	if (ret != -EBUSY && ret != -EINPROGRESS) {
		dev_err(dev, "sec_send failed ret[%d]\n", ret);
		goto err_send_req;
	}

	return ret;

err_send_req:
	sec_request_untransfer(ctx, req);
err_with_req:
	sec_free_req_id(req);
	sec_put_queue_id(ctx, req);
	atomic_dec(&ctx->thread_cnt);
	return ret;
}

static void sec_fusion_skcipher_copy_iv(struct sec_ctx *ctx,
					       struct sec_req *req)
{
	struct sec_cipher_ctx *c_ctx = &ctx->c_ctx;
	struct skcipher_request *sk_req = req->c_req.sk_req;
	struct sec_cipher_req *c_req = &req->c_req;
	u32 ivsize = ctx->c_ctx.ivsize;
	struct skcipher_request *sk_next;
	int i;

	c_req->c_len = sk_req->cryptlen;

	memcpy(c_req->c_ivin, sk_req->iv, ivsize);

	if (ctx->is_fusion) {
		for (i = 1; i < req->fusion_num; i++) {
			sk_next = req->sk_reqs[i];
			memcpy(c_req->c_ivin + i * ivsize, sk_next->iv,
				ivsize);
		}

		c_req->gran_num = req->fusion_num;
		c_ctx->c_gran_size = sk_req->cryptlen;
	}
}

static int sec_fusion_skcipher_sgl_map(struct sec_ctx *ctx, struct sec_req *req)
{
	struct sec_cipher_req *c_req = &req->c_req;
	struct device *dev = SEC_CTX_DEV(ctx);
	struct skcipher_request *sk_next;
	int src_nents = 0, dst_nents = 0, i;
	int dst_nents_cp = 0;
	int src_nents_cp = 0;

	for (i = 0; i < req->fusion_num; i++) {
		sk_next = req->sk_reqs[i];
		if (!sk_next) {
			dev_err(dev, "nullptr at [%d]\n", i);
			return -EFAULT;
		}
		src_nents += sg_nents(sk_next->src);
		dst_nents += sg_nents(sk_next->dst);
		if (sk_next->src == sk_next->dst && !i) {
			dev_err(dev, "err: src == dst\n");
			return -EFAULT;
		}
	}

	if (src_nents > SEC_FUSION_LIMIT || dst_nents > SEC_FUSION_LIMIT) {
		dev_err(dev, "src[%d] or dst[%d] bigger than %d\n",
			src_nents, dst_nents, SEC_FUSION_LIMIT);
		return -ENOBUFS;
	}

	for (i = 0; i < req->fusion_num; i++) {
		sk_next = req->sk_reqs[i];
		src_nents = sg_nents(sk_next->src);
		dst_nents = sg_nents(sk_next->dst);

		if (i != req->fusion_num - 1) {
			sg_unmark_end(&sk_next->src[src_nents - 1]);
			sg_unmark_end(&sk_next->dst[dst_nents - 1]);
		}

		memcpy(c_req->src + src_nents_cp, sk_next->src,
			src_nents * sizeof(struct scatterlist));
		memcpy(c_req->dst + dst_nents_cp, sk_next->dst,
			dst_nents * sizeof(struct scatterlist));

		src_nents_cp += src_nents;
		dst_nents_cp += dst_nents;
	}

	return sec_skcipher_map(dev, req, c_req->src, c_req->dst);
}

static void sec_fusion_skcipher_sgl_unmap(struct sec_ctx *ctx,
				struct sec_req *req)
{

	struct sec_cipher_req *c_req = &req->c_req;
	struct device *dev = SEC_CTX_DEV(ctx);

	if (c_req->dst != c_req->src)
		hisi_acc_sg_buf_unmap(dev, c_req->src, c_req->c_in);

	hisi_acc_sg_buf_unmap(dev, c_req->dst, c_req->c_out);
}

static void sec_fusion_skcipher_complete(struct sec_ctx *ctx,
	struct sec_req *req, int err_code)
{
	struct skcipher_request **sk_reqs = req->sk_reqs;
	int i, req_fusion_num;

	req_fusion_num = req->fusion_num;

	for (i = 0; i < req_fusion_num; i++)
		sk_reqs[i]->base.complete(&sk_reqs[i]->base, err_code);

	/* free sk_reqs if this request is completed */
	if (err_code != -EINPROGRESS)
		__sync_add_and_fetch(&ctx->sec->debug.dfx.put_task_cnt,
			req_fusion_num);
	else
		__sync_add_and_fetch(&ctx->sec->debug.dfx.busy_comp_cnt,
			req_fusion_num);
}

static void sec_fusion_skcipher_callback(struct sec_ctx *ctx,
					struct sec_req *req)
{
	struct sec_qp_ctx *qp_ctx = req->qp_ctx;

	atomic_dec(&qp_ctx->pending_reqs);
	sec_free_req_id(req);

	if (__sync_bool_compare_and_swap(&req->fake_busy, 1, 0))
		sec_fusion_skcipher_complete(ctx, req, -EINPROGRESS);

	sec_fusion_skcipher_complete(ctx, req, req->err_type);
}

static struct sec_req_op sec_fusion_req_ops = {
	.get_res = sec_skcipher_get_fusion_res,
	.resource_alloc = sec_skcipher_fusion_resource_alloc,
	.resource_free = sec_skcipher_fusion_resource_free,
	.buf_map = sec_fusion_skcipher_sgl_map,
	.buf_unmap = sec_fusion_skcipher_sgl_unmap,
	.do_transfer = sec_fusion_skcipher_copy_iv,
	.bd_fill = sec_fusion_skcipher_bd_fill,
	.bd_send = sec_bd_send,
	.callback = sec_fusion_skcipher_callback,
	.process = sec_fusion_process,
};

static int sec_skcipher_fusion_ctx_init(struct crypto_skcipher *tfm)
{
	struct sec_ctx *ctx = crypto_skcipher_ctx(tfm);
	int ret;

	ctx->req_op  = &sec_fusion_req_ops;
	ctx->is_fusion = SEC_IV_FUSION;

	ret = sec_skcipher_init(tfm);
	if (ret)
		return ret;

	ret = sec_ctx_fusion_init(ctx, QM_Q_DEPTH);
	if (ret) {
		(void)sec_skcipher_exit(tfm);
		return ret;
	}
	return ret;
}

static void sec_skcipher_fusion_ctx_exit(struct crypto_skcipher *tfm)
{
	sec_ctx_fusion_exit(tfm);
	sec_skcipher_exit(tfm);
}
#endif

static void sec_skcipher_copy_iv(struct sec_ctx *ctx, struct sec_req *req)
{
	struct skcipher_request *sk_req = req->c_req.sk_req;
	struct sec_cipher_req *c_req = &req->c_req;

	c_req->c_len = sk_req->cryptlen;
	memcpy(c_req->c_ivin, sk_req->iv, ctx->c_ctx.ivsize);
}

static int sec_skcipher_bd_fill(struct sec_ctx *ctx, struct sec_req *req)
{
	struct sec_cipher_ctx *c_ctx = &ctx->c_ctx;
	struct sec_cipher_req *c_req = &req->c_req;
	struct sec_sqe *sec_sqe = &req->sec_sqe;
	u8 de = 0;
	u8 scene, sa_type, da_type;
	u8 bd_type, cipher;

	if (!c_req->c_len) {
		dev_err(SEC_CTX_DEV(ctx), "cipher length is zero!\n");
		return -EINVAL;
	}

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

	sa_type = SEC_SGL << SEC_SRC_SGL_OFFSET;
	scene = SEC_COMM_SCENE << SEC_SCENE_OFFSET;
	if (c_req->c_in_dma != c_req->c_out_dma)
		de = 0x1 << SEC_DE_OFFSET;

	sec_sqe->sds_sa_type = (de | scene | sa_type);

	/* Just set DST address type */
	da_type = SEC_SGL << SEC_DST_SGL_OFFSET;
	sec_sqe->sdm_addr_type |= da_type;

	sec_sqe->type2.clen_ivhlen |= cpu_to_le32(c_req->c_len);
	sec_sqe->type2.tag = cpu_to_le16((u16)req->req_id);

	return 0;
}

static void sec_update_iv(struct sec_req *req)
{
	struct skcipher_request *sk_req = req->c_req.sk_req;
	u32 iv_size = req->ctx->c_ctx.ivsize;
	struct scatterlist *sgl;
	size_t sz;

	if (req->c_req.encrypt)
		sgl = sk_req->dst;
	else
		sgl = sk_req->src;

	sz = sg_pcopy_to_buffer(sgl, sg_nents(sgl), sk_req->iv,
				iv_size, sk_req->cryptlen - iv_size);
	if (sz != iv_size)
		dev_err(SEC_CTX_DEV(req->ctx), "copy output iv error!\n");
}

static void sec_skcipher_callback(struct sec_ctx *ctx, struct sec_req *req)
{
	struct skcipher_request *sk_req = req->c_req.sk_req;
	struct sec_qp_ctx *qp_ctx = req->qp_ctx;

	atomic_dec(&qp_ctx->pending_reqs);
	sec_free_req_id(req);

	/* IV output at encrypto of CBC mode */
	if (ctx->c_ctx.c_mode == SEC_CMODE_CBC && req->c_req.encrypt)
		sec_update_iv(req);

	if (__sync_bool_compare_and_swap(&req->fake_busy, 1, 0))
		sk_req->base.complete(&sk_req->base, -EINPROGRESS);

	sk_req->base.complete(&sk_req->base, req->err_type);
}

static void sec_request_uninit(struct sec_ctx *ctx, struct sec_req *req)
{
	struct sec_qp_ctx *qp_ctx = req->qp_ctx;

	atomic_dec(&qp_ctx->pending_reqs);
	sec_free_req_id(req);
	sec_put_queue_id(ctx, req);
}

static int sec_request_init(struct sec_ctx *ctx, struct sec_req *req)
{
	struct sec_qp_ctx *qp_ctx;
	int issue_id, ret;

	/* To load balance */
	issue_id = sec_get_queue_id(ctx, req);
	qp_ctx = &ctx->qp_ctx[issue_id];

	req->req_id = sec_alloc_req_id(req, qp_ctx);
	if (req->req_id < 0) {
		sec_put_queue_id(ctx, req);
		return req->req_id;
	}

	if (ctx->fake_req_limit <= atomic_inc_return(&qp_ctx->pending_reqs))
		req->fake_busy = 1;
	else
		req->fake_busy = 0;

	ret = ctx->req_op->get_res(ctx, req);
	if (ret) {
		atomic_dec(&qp_ctx->pending_reqs);
		sec_request_uninit(ctx, req);
		dev_err(SEC_CTX_DEV(ctx), "get resources failed!\n");
	}

	return ret;
}

static int sec_process(struct sec_ctx *ctx, struct sec_req *req)
{
	int ret;

	ret = sec_request_init(ctx, req);
	if (ret)
		return ret;

	ret = sec_request_transfer(ctx, req);
	if (ret)
		goto err_uninit_req;

	/* Output IV as decrypto */
	if (ctx->c_ctx.c_mode == SEC_CMODE_CBC && !req->c_req.encrypt)
		sec_update_iv(req);

	ret = ctx->req_op->bd_send(ctx, req);
	if (ret != -EBUSY && ret != -EINPROGRESS) {
		dev_err(SEC_CTX_DEV(ctx), "send sec request failed!\n");
		goto err_send_req;
	}

	return ret;

err_send_req:
	/* As failing, restore the IV from user */
	if (ctx->c_ctx.c_mode == SEC_CMODE_CBC && !req->c_req.encrypt)
		memcpy(req->c_req.sk_req->iv, req->c_req.c_ivin,
		       ctx->c_ctx.ivsize);

	sec_request_untransfer(ctx, req);
err_uninit_req:
	sec_request_uninit(ctx, req);

	return ret;
}

static struct sec_req_op sec_req_ops_tbl = {
	.get_res	= sec_skcipher_get_res,
	.resource_alloc	= sec_skcipher_resource_alloc,
	.resource_free	= sec_skcipher_resource_free,
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

	ctx->req_op = &sec_req_ops_tbl;

	return sec_skcipher_init(tfm);
}

static void sec_skcipher_ctx_exit(struct crypto_skcipher *tfm)
{
	sec_skcipher_exit(tfm);
}

static int sec_skcipher_crypto(struct skcipher_request *sk_req, bool encrypt)
{
	struct crypto_skcipher *tfm = crypto_skcipher_reqtfm(sk_req);
	struct sec_ctx *ctx = crypto_skcipher_ctx(tfm);
	struct sec_req *req = skcipher_request_ctx(sk_req);

	if (!sk_req->src || !sk_req->dst || !sk_req->cryptlen) {
		dev_err(SEC_CTX_DEV(ctx), "skcipher input param error!\n");
		return -EINVAL;
	}

	req->c_req.sk_req = sk_req;
	req->c_req.encrypt = encrypt;
	req->ctx = ctx;

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

#define SEC_SKCIPHER_FUSION_ALG(name, key_func, min_key_size, \
	max_key_size, blk_size, iv_size) \
	SEC_SKCIPHER_GEN_ALG(name, key_func, min_key_size, max_key_size, \
	sec_skcipher_fusion_ctx_init, sec_skcipher_fusion_ctx_exit, blk_size, \
	iv_size)

static struct skcipher_alg sec_algs[] = {
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

#ifndef CONFIG_CRYPTO_DEV_HISI_SEC2_FUSION
	SEC_SKCIPHER_ALG("xts(sm4)", sec_setkey_sm4_xts,
			 SEC_XTS_MIN_KEY_SIZE, SEC_XTS_MIN_KEY_SIZE,
			 AES_BLOCK_SIZE, AES_BLOCK_SIZE)

	SEC_SKCIPHER_ALG("cbc(sm4)", sec_setkey_sm4_cbc,
			 AES_MIN_KEY_SIZE, AES_MIN_KEY_SIZE,
			 AES_BLOCK_SIZE, AES_BLOCK_SIZE)
#else
	SEC_SKCIPHER_FUSION_ALG("xts(sm4)", sec_setkey_sm4_xts,
		SEC_XTS_MIN_KEY_SIZE, SEC_XTS_MIN_KEY_SIZE,
		AES_BLOCK_SIZE, AES_BLOCK_SIZE)

	SEC_SKCIPHER_FUSION_ALG("cbc(sm4)", sec_setkey_sm4_cbc,
		AES_MIN_KEY_SIZE, AES_MIN_KEY_SIZE,
		AES_BLOCK_SIZE, AES_BLOCK_SIZE)
#endif
};

int sec_register_to_crypto(void)
{
	int ret = 0;

	/* To avoid repeat register */
	mutex_lock(&sec_algs_lock);
	if (++sec_active_devs == 1)
		ret = crypto_register_skciphers(sec_algs, ARRAY_SIZE(sec_algs));
	mutex_unlock(&sec_algs_lock);

	return ret;
}

void sec_unregister_from_crypto(void)
{
	mutex_lock(&sec_algs_lock);
	if (--sec_active_devs == 0)
		crypto_unregister_skciphers(sec_algs, ARRAY_SIZE(sec_algs));
	mutex_unlock(&sec_algs_lock);
}
