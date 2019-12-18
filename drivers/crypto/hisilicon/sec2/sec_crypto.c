// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2019 HiSilicon Limited. */

#include <linux/crypto.h>
#include <linux/hrtimer.h>
#include <linux/dma-mapping.h>
#include <linux/ktime.h>

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

#define BUF_MAP_PER_SGL 64
#define SEC_FUSION_BD

enum C_ALG {
	C_ALG_DES  = 0x0,
	C_ALG_3DES = 0x1,
	C_ALG_AES  = 0x2,
	C_ALG_SM4  = 0x3,
};

enum C_MODE {
	C_MODE_ECB    = 0x0,
	C_MODE_CBC    = 0x1,
	C_MODE_CTR    = 0x4,
	C_MODE_CCM    = 0x5,
	C_MODE_GCM    = 0x6,
	C_MODE_XTS    = 0x7,
	C_MODE_CBC_CS = 0x9,
};

enum CKEY_LEN {
	CKEY_LEN_128_BIT = 0x0,
	CKEY_LEN_192_BIT = 0x1,
	CKEY_LEN_256_BIT = 0x2,
	CKEY_LEN_DES     = 0x1,
	CKEY_LEN_3DES_3KEY = 0x1,
	CKEY_LEN_3DES_2KEY = 0x3,
};

enum SEC_BD_TYPE {
	BD_TYPE1 = 0x1,
	BD_TYPE2 = 0x2,
};

enum SEC_CIPHER_TYPE {
	SEC_CIPHER_ENC = 0x1,
	SEC_CIPHER_DEC = 0x2,
};

enum SEC_ADDR_TYPE {
	PBUF = 0x0,
	SGL  = 0x1,
	PRP  = 0x2,
};

enum SEC_CI_GEN {
	CI_GEN_BY_ADDR = 0x0,
	CI_GEN_BY_LBA  = 0X3,
};

enum SEC_SCENE {
	SCENE_IPSEC   = 0x0,
	SCENE_STORAGE = 0x5,
};

enum {
	SEC_NO_FUSION = 0x0,
	SEC_IV_FUSION = 0x1,
	SEC_FUSION_BUTT
};

enum SEC_REQ_OPS_TYPE {
	SEC_OPS_SKCIPHER_ALG = 0x0,
	SEC_OPS_MULTI_IV     = 0x1,
	SEC_OPS_BUTT
};

struct cipher_res {
	struct skcipher_request_ctx **sk_reqs;
	u8 *c_ivin;
	dma_addr_t c_ivin_dma;
	struct scatterlist *src;
	struct scatterlist *dst;
};

struct hisi_sec_cipher_req {
	struct hisi_acc_hw_sgl *c_in;
	dma_addr_t c_in_dma;
	struct hisi_acc_hw_sgl *c_out;
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
	ktime_t st_time;
	int err_type;
	int req_id;
	int req_cnt;
	int fusion_num;
	int fake_busy;
};

struct hisi_sec_req_op {
	int fusion_type;
	int (*get_res)(struct hisi_sec_ctx *ctx, struct hisi_sec_req *req);
	int (*queue_alloc)(struct hisi_sec_ctx *ctx,
		struct hisi_sec_qp_ctx *qp_ctx);
	int (*queue_free)(struct hisi_sec_ctx *ctx,
		struct hisi_sec_qp_ctx *qp_ctx);
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
	void *priv_req_res;
	struct hisi_sec_ctx *ctx;
	struct mutex req_lock;
	atomic_t req_cnt;
	struct hisi_sec_sqe *sqe_list;
	struct hisi_acc_sgl_pool *c_in_pool;
	struct hisi_acc_sgl_pool *c_out_pool;
	int fusion_num;
	int fusion_limit;
};

struct hisi_sec_ctx {
	struct hisi_sec_qp_ctx *qp_ctx;
	struct hisi_sec *sec;
	struct device *dev;
	struct hisi_sec_req_op *req_op;
	struct hrtimer timer;
	struct work_struct work;
	atomic_t thread_cnt;
	int req_fake_limit;
	int req_limit;
	int q_num;
	int enc_q_num;
	atomic_t enc_qid;
	atomic_t dec_qid;
	struct hisi_sec_cipher_ctx c_ctx;
	int fusion_tmout_nsec;
	int fusion_limit;
	u64 enc_fusion_num;
	u64 dec_fusion_num;
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
		dev_err(ctx->dev, "no free req id\n");
		return -ENOBUFS;
	}
	set_bit(req_id, qp_ctx->req_bitmap);

	qp_ctx->req_list[req_id] = req;
	req->req_id = req_id;
	req->qp_ctx = qp_ctx;

	return 0;
}

static void hisi_sec_free_req_id(struct hisi_sec_qp_ctx *qp_ctx, int req_id)
{
	if (req_id < 0 || req_id >= qp_ctx->ctx->req_limit) {
		pr_err("invalid req_id[%d]\n", req_id);
		return;
	}

	qp_ctx->req_list[req_id] = NULL;

	mutex_lock(&qp_ctx->req_lock);
	clear_bit(req_id, qp_ctx->req_bitmap);
	atomic_dec(&qp_ctx->req_cnt);
	mutex_unlock(&qp_ctx->req_lock);
}

static int sec_request_transfer(struct hisi_sec_ctx *, struct hisi_sec_req *);
static int sec_request_send(struct hisi_sec_ctx *, struct hisi_sec_req *);

void qp_ctx_work_process(struct hisi_sec_qp_ctx *qp_ctx)
{
	struct hisi_sec_req *req;
	struct hisi_sec_ctx *ctx;
	ktime_t cur_time = ktime_get();
	int ret;

	mutex_lock(&qp_ctx->req_lock);

	req = qp_ctx->fusion_req;
	if (req == NULL) {
		mutex_unlock(&qp_ctx->req_lock);
		return;
	}

	ctx = req->ctx;
	if (ctx == NULL || req->fusion_num == qp_ctx->fusion_limit) {
		mutex_unlock(&qp_ctx->req_lock);
		return;
	}

	if (cur_time - qp_ctx->fusion_req->st_time < ctx->fusion_tmout_nsec) {
		mutex_unlock(&qp_ctx->req_lock);
		return;
	}

	qp_ctx->fusion_req = NULL;

	mutex_unlock(&qp_ctx->req_lock);

	ret = sec_request_transfer(ctx, req);
	if (ret)
		goto err_free_req;

	ret = sec_request_send(ctx, req);
	__sync_add_and_fetch(&ctx->sec->sec_dfx.send_by_tmout, 1);
	if (ret != -EBUSY && ret != -EINPROGRESS) {
		dev_err(ctx->dev, "[%s][%d] ret[%d]\n", __func__,
			__LINE__, ret);
		goto err_unmap_req;
	}

	return;

err_unmap_req:
	ctx->req_op->buf_unmap(ctx, req);
err_free_req:
	hisi_sec_free_req_id(qp_ctx, req->req_id);
	atomic_dec(&ctx->thread_cnt);
}

void ctx_work_process(struct work_struct *work)
{
	struct hisi_sec_ctx *ctx;
	int i;

	ctx = container_of(work, struct hisi_sec_ctx, work);
	for (i = 0; i < ctx->q_num; i++)
		qp_ctx_work_process(&ctx->qp_ctx[i]);
}

static enum hrtimer_restart hrtimer_handler(struct hrtimer *timer)
{
	struct hisi_sec_ctx *ctx;
	ktime_t tim;

	ctx = container_of(timer, struct hisi_sec_ctx, timer);
	tim = ktime_set(0, ctx->fusion_tmout_nsec);

	if (ctx->sec->qm.wq)
		queue_work(ctx->sec->qm.wq, &ctx->work);
	else
		schedule_work(&ctx->work);

	hrtimer_forward(timer, timer->base->get_time(), tim);

	return HRTIMER_RESTART;
}

static int hisi_sec_create_qp_ctx(struct hisi_qm *qm, struct hisi_sec_ctx *ctx,
			      int qp_ctx_id, int alg_type, int req_type)
{
	struct hisi_qp *qp;
	struct hisi_sec_qp_ctx *qp_ctx;
	struct device *dev = ctx->dev;
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
	qp_ctx->fusion_limit = ctx->fusion_limit;
	qp_ctx->ctx = ctx;

	mutex_init(&qp_ctx->req_lock);
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

	qp_ctx->c_in_pool = hisi_acc_create_sgl_pool(dev, QM_Q_DEPTH,
		FUSION_LIMIT_MAX);
	if (IS_ERR(qp_ctx->c_in_pool)) {
		ret = PTR_ERR(qp_ctx->c_in_pool);
		goto err_free_sqe_list;
	}

	qp_ctx->c_out_pool = hisi_acc_create_sgl_pool(dev, QM_Q_DEPTH,
		FUSION_LIMIT_MAX);
	if (IS_ERR(qp_ctx->c_out_pool)) {
		ret = PTR_ERR(qp_ctx->c_out_pool);
		goto err_free_c_in_pool;
	}

	ret = ctx->req_op->queue_alloc(ctx, qp_ctx);
	if (ret)
		goto err_free_c_out_pool;

	ret = hisi_qm_start_qp(qp, 0);
	if (ret < 0)
		goto err_queue_free;

	return 0;

err_queue_free:
	ctx->req_op->queue_free(ctx, qp_ctx);
err_free_c_out_pool:
	hisi_acc_free_sgl_pool(dev, qp_ctx->c_out_pool);
err_free_c_in_pool:
	hisi_acc_free_sgl_pool(dev, qp_ctx->c_in_pool);
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

static void hisi_sec_release_qp_ctx(struct hisi_sec_ctx *ctx,
	struct hisi_sec_qp_ctx *qp_ctx)
{
	struct device *dev = ctx->dev;

	hisi_qm_stop_qp(qp_ctx->qp);
	ctx->req_op->queue_free(ctx, qp_ctx);
	hisi_acc_free_sgl_pool(dev, qp_ctx->c_out_pool);
	hisi_acc_free_sgl_pool(dev, qp_ctx->c_in_pool);
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

	if (ctx->fusion_limit > 1 && ctx->fusion_tmout_nsec > 0) {
		ktime_t tim = ktime_set(0, ctx->fusion_tmout_nsec);

		hrtimer_init(&ctx->timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
		ctx->timer.function = hrtimer_handler;
		hrtimer_start(&ctx->timer, tim, HRTIMER_MODE_REL);
		INIT_WORK(&ctx->work, ctx_work_process);
	}

	return 0;
}

static void hisi_sec_get_fusion_param(struct hisi_sec_ctx *ctx,
	struct hisi_sec *sec)
{
	if (ctx->is_fusion) {
		ctx->fusion_tmout_nsec = sec->fusion_tmout_nsec;
		ctx->fusion_limit = sec->fusion_limit;
	} else {
		ctx->fusion_tmout_nsec = 0;
		ctx->fusion_limit = 1;
	}
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
	ctx->dev = &qm->pdev->dev;

	ctx->q_num = sec->ctx_q_num;

	ctx->enc_q_num = ctx->q_num / 2;
	ctx->qp_ctx = kcalloc(ctx->q_num, sizeof(struct hisi_sec_qp_ctx),
		GFP_KERNEL);
	if (!ctx->qp_ctx)
		return -ENOMEM;

	hisi_sec_get_fusion_param(ctx, sec);

	for (i = 0; i < ctx->q_num; i++) {
		ret = hisi_sec_create_qp_ctx(qm, ctx, i, 0, 0);
		if (ret)
			goto err_sec_release_qp_ctx;
	}

	c_ctx = &ctx->c_ctx;
	c_ctx->c_key = dma_alloc_coherent(ctx->dev,
		SEC_MAX_KEY_SIZE, &c_ctx->c_key_dma, GFP_KERNEL);

	if (!ctx->c_ctx.c_key) {
		ret = -ENOMEM;
		goto err_sec_release_qp_ctx;
	}

	return __hisi_sec_ctx_init(ctx, QM_Q_DEPTH);

err_sec_release_qp_ctx:
	for (i = i - 1; i >= 0; i--)
		hisi_sec_release_qp_ctx(ctx, &ctx->qp_ctx[i]);

	kfree(ctx->qp_ctx);
	return ret;
}

static void hisi_sec_cipher_ctx_exit(struct crypto_skcipher *tfm)
{
	struct hisi_sec_ctx *ctx = crypto_skcipher_ctx(tfm);
	struct hisi_sec_cipher_ctx *c_ctx;
	int i = 0;

	c_ctx = &ctx->c_ctx;

	if (ctx->fusion_limit > 1 && ctx->fusion_tmout_nsec > 0)
		hrtimer_cancel(&ctx->timer);

	if (c_ctx->c_key) {
		dma_free_coherent(ctx->dev, SEC_MAX_KEY_SIZE, c_ctx->c_key,
			c_ctx->c_key_dma);
		c_ctx->c_key = NULL;
	}

	for (i = 0; i < ctx->q_num; i++)
		hisi_sec_release_qp_ctx(ctx, &ctx->qp_ctx[i]);

	kfree(ctx->qp_ctx);

	mutex_lock(ctx->sec->hisi_sec_list_lock);
	ctx->sec->q_ref -= ctx->sec->ctx_q_num;
	mutex_unlock(ctx->sec->hisi_sec_list_lock);
}

static int hisi_sec_skcipher_get_res(struct hisi_sec_ctx *ctx,
	struct hisi_sec_req *req);
static int hisi_sec_skcipher_queue_alloc(struct hisi_sec_ctx *ctx,
	struct hisi_sec_qp_ctx *qp_ctx);
static int hisi_sec_skcipher_queue_free(struct hisi_sec_ctx *ctx,
	struct hisi_sec_qp_ctx *qp_ctx);
static int hisi_sec_skcipher_buf_map(struct hisi_sec_ctx *ctx,
	struct hisi_sec_req *req);
static int hisi_sec_skcipher_buf_unmap(struct hisi_sec_ctx *ctx,
	struct hisi_sec_req *req);
static int hisi_sec_skcipher_copy_iv(struct hisi_sec_ctx *ctx,
	struct hisi_sec_req *req);
static int hisi_sec_skcipher_bd_fill_base(struct hisi_sec_ctx *ctx,
	struct hisi_sec_req *req);
static int hisi_sec_skcipher_bd_fill_storage(struct hisi_sec_ctx *ctx,
	struct hisi_sec_req *req);
static int hisi_sec_skcipher_bd_fill_multi_iv(struct hisi_sec_ctx *ctx,
	struct hisi_sec_req *req);
static int hisi_sec_bd_send_asyn(struct hisi_sec_ctx *ctx,
	struct hisi_sec_req *req);
static int hisi_sec_skcipher_callback(struct hisi_sec_ctx *ctx,
	struct hisi_sec_req *req);

struct hisi_sec_req_op sec_req_ops_tbl[] = {
	{
		.fusion_type = SEC_NO_FUSION,
		.get_res     = hisi_sec_skcipher_get_res,
		.queue_alloc = hisi_sec_skcipher_queue_alloc,
		.queue_free  = hisi_sec_skcipher_queue_free,
		.buf_map     = hisi_sec_skcipher_buf_map,
		.buf_unmap   = hisi_sec_skcipher_buf_unmap,
		.do_transfer = hisi_sec_skcipher_copy_iv,
		.bd_fill     = hisi_sec_skcipher_bd_fill_base,
		.bd_send     = hisi_sec_bd_send_asyn,
		.callback    = hisi_sec_skcipher_callback,
	}, {
		.fusion_type = SEC_IV_FUSION,
		.get_res     = hisi_sec_skcipher_get_res,
		.queue_alloc = hisi_sec_skcipher_queue_alloc,
		.queue_free  = hisi_sec_skcipher_queue_free,
		.buf_map     = hisi_sec_skcipher_buf_map,
		.buf_unmap   = hisi_sec_skcipher_buf_unmap,
		.do_transfer = hisi_sec_skcipher_copy_iv,
		.bd_fill     = hisi_sec_skcipher_bd_fill_multi_iv,
		.bd_send     = hisi_sec_bd_send_asyn,
		.callback    = hisi_sec_skcipher_callback,
	}
};

static int hisi_sec_cipher_ctx_init_alg(struct crypto_skcipher *tfm)
{
	struct hisi_sec_ctx *ctx = crypto_skcipher_ctx(tfm);

	ctx->req_op        = &sec_req_ops_tbl[SEC_OPS_SKCIPHER_ALG];
	ctx->is_fusion     = ctx->req_op->fusion_type;

	return hisi_sec_cipher_ctx_init(tfm);
}

static int hisi_sec_cipher_ctx_init_multi_iv(struct crypto_skcipher *tfm)
{
	struct hisi_sec_ctx *ctx = crypto_skcipher_ctx(tfm);

	ctx->req_op        = &sec_req_ops_tbl[SEC_OPS_MULTI_IV];
	ctx->is_fusion     = ctx->req_op->fusion_type;

	return hisi_sec_cipher_ctx_init(tfm);
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
GEN_SEC_SETKEY_FUNC(sm4_cbc, C_ALG_SM4, C_MODE_CBC)

GEN_SEC_SETKEY_FUNC(des_ecb, C_ALG_DES, C_MODE_ECB)
GEN_SEC_SETKEY_FUNC(des_cbc, C_ALG_DES, C_MODE_CBC)
GEN_SEC_SETKEY_FUNC(3des_ecb, C_ALG_3DES, C_MODE_ECB)
GEN_SEC_SETKEY_FUNC(3des_cbc, C_ALG_3DES, C_MODE_CBC)

GEN_SEC_SETKEY_FUNC(aes_xts, C_ALG_AES, C_MODE_XTS)
GEN_SEC_SETKEY_FUNC(sm4_xts, C_ALG_SM4, C_MODE_XTS)

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

static int hisi_sec_skcipher_get_res(struct hisi_sec_ctx *ctx,
	struct hisi_sec_req *req)
{
	struct hisi_sec_cipher_req *c_req = &req->c_req;
	struct hisi_sec_qp_ctx *qp_ctx = req->qp_ctx;
	struct cipher_res *c_res = (struct cipher_res *)qp_ctx->priv_req_res;
	int req_id = req->req_id;

	c_req->c_ivin = c_res[req_id].c_ivin;
	c_req->c_ivin_dma = c_res[req_id].c_ivin_dma;
	req->priv = (void **)c_res[req_id].sk_reqs;
	c_req->src = c_res[req_id].src;
	c_req->dst = c_res[req_id].dst;

	return 0;
}

static int hisi_sec_skcipher_queue_alloc(struct hisi_sec_ctx *ctx,
	struct hisi_sec_qp_ctx *qp_ctx)
{
	struct cipher_res *c_res;
	int req_num = ctx->fusion_limit;
	int alloc_num = QM_Q_DEPTH * ctx->fusion_limit;
	int buf_map_num = QM_Q_DEPTH * ctx->fusion_limit;
	struct device *dev = ctx->dev;
	int i, ret;

	c_res = kcalloc(QM_Q_DEPTH, sizeof(struct cipher_res), GFP_KERNEL);
	if (!c_res)
		return -ENOMEM;

	qp_ctx->priv_req_res = (void *)c_res;

	c_res[0].sk_reqs = kcalloc(alloc_num,
		sizeof(struct skcipher_request_ctx *), GFP_KERNEL);
	if (!c_res[0].sk_reqs) {
		ret = -ENOMEM;
		goto err_free_c_res;
	}

	c_res[0].c_ivin = dma_alloc_coherent(dev,
		SEC_IV_SIZE * alloc_num, &c_res[0].c_ivin_dma, GFP_KERNEL);
	if (!c_res[0].c_ivin) {
		ret = -ENOMEM;
		goto err_free_sk_reqs;
	}

	c_res[0].src = kcalloc(buf_map_num, sizeof(struct scatterlist),
		GFP_KERNEL);
	if (!c_res[0].src) {
		ret = -ENOMEM;
		goto err_free_c_ivin;
	}

	c_res[0].dst = kcalloc(buf_map_num, sizeof(struct scatterlist),
		GFP_KERNEL);
	if (!c_res[0].dst) {
		ret = -ENOMEM;
		goto err_free_src;
	}

	for (i = 1; i < QM_Q_DEPTH; i++) {
		c_res[i].sk_reqs     = c_res[0].sk_reqs + i * req_num;
		c_res[i].c_ivin      = c_res[0].c_ivin
			+ i * req_num * SEC_IV_SIZE;
		c_res[i].c_ivin_dma  = c_res[0].c_ivin_dma
			+ i * req_num * SEC_IV_SIZE;
		c_res[i].src         = c_res[0].src       + i * req_num;
		c_res[i].dst         = c_res[0].dst       + i * req_num;
	}

	return 0;

err_free_src:
	kfree(c_res[0].src);
err_free_c_ivin:
	dma_free_coherent(dev, SEC_IV_SIZE * alloc_num, c_res[0].c_ivin,
		c_res[0].c_ivin_dma);
err_free_sk_reqs:
	kfree(c_res[0].sk_reqs);
err_free_c_res:
	kfree(c_res);

	return ret;
}

static int hisi_sec_skcipher_queue_free(struct hisi_sec_ctx *ctx,
	struct hisi_sec_qp_ctx *qp_ctx)
{
	struct cipher_res *c_res = (struct cipher_res *)qp_ctx->priv_req_res;
	struct device *dev = ctx->dev;
	int alloc_num = QM_Q_DEPTH * ctx->fusion_limit;

	kfree(c_res[0].dst);
	kfree(c_res[0].src);
	dma_free_coherent(dev, SEC_IV_SIZE * alloc_num, c_res[0].c_ivin,
		c_res[0].c_ivin_dma);
	kfree(c_res[0].sk_reqs);
	kfree(c_res);

	return 0;
}

static int hisi_sec_skcipher_buf_map(struct hisi_sec_ctx *ctx,
	struct hisi_sec_req *req)
{
	struct hisi_sec_cipher_req *c_req = &req->c_req;
	struct device *dev = ctx->dev;
	struct skcipher_request *sk_next;
	struct hisi_sec_qp_ctx *qp_ctx = req->qp_ctx;
	int src_nents, src_nents_sum, copyed_src_nents;
	int dst_nents, dst_nents_sum, copyed_dst_nents;
	int i, ret, buf_map_limit;

	src_nents_sum = 0;
	dst_nents_sum = 0;
	for (i = 0; i < req->fusion_num; i++) {
		sk_next = (struct skcipher_request *)req->priv[i];
		if (sk_next == NULL) {
			dev_err(ctx->dev, "nullptr at [%d]\n", i);
			return -EFAULT;
		}
		src_nents_sum += sg_nents(sk_next->src);
		dst_nents_sum += sg_nents(sk_next->dst);
		if (sk_next->src == sk_next->dst && i > 0) {
			dev_err(ctx->dev, "err: src == dst\n");
			return -EFAULT;
		}
	}

	buf_map_limit = FUSION_LIMIT_MAX;
	if (src_nents_sum > buf_map_limit || dst_nents_sum > buf_map_limit) {
		dev_err(ctx->dev, "src[%d] or dst[%d] bigger than %d\n",
			src_nents_sum, dst_nents_sum, buf_map_limit);
		return -ENOBUFS;
	}

	copyed_src_nents = 0;
	copyed_dst_nents = 0;
	for (i = 0; i < req->fusion_num; i++) {
		sk_next = (struct skcipher_request *)req->priv[i];
		src_nents = sg_nents(sk_next->src);
		dst_nents = sg_nents(sk_next->dst);

		if (i != req->fusion_num - 1) {
			sg_unmark_end(&sk_next->src[src_nents - 1]);
			sg_unmark_end(&sk_next->dst[dst_nents - 1]);
		}

		memcpy(c_req->src + copyed_src_nents, sk_next->src,
			src_nents * sizeof(struct scatterlist));
		memcpy(c_req->dst + copyed_dst_nents, sk_next->dst,
			dst_nents * sizeof(struct scatterlist));

		copyed_src_nents += src_nents;
		copyed_dst_nents += dst_nents;
	}

	c_req->c_in = hisi_acc_sg_buf_map_to_hw_sgl(dev, c_req->src,
		qp_ctx->c_in_pool, req->req_id, &c_req->c_in_dma);

	if (IS_ERR(c_req->c_in))
		return PTR_ERR(c_req->c_in);

	if (c_req->dst == c_req->src) {
		c_req->c_out = c_req->c_in;
		c_req->c_out_dma = c_req->c_in_dma;
	} else {
		c_req->c_out = hisi_acc_sg_buf_map_to_hw_sgl(dev, c_req->dst,
			qp_ctx->c_out_pool, req->req_id, &c_req->c_out_dma);
		if (IS_ERR(c_req->c_out)) {
			ret = PTR_ERR(c_req->c_out);
			goto err_unmap_src;
		}
	}

	return 0;

err_unmap_src:
	hisi_acc_sg_buf_unmap(dev, c_req->src, c_req->c_in);

	return ret;
}

static int hisi_sec_skcipher_buf_unmap(struct hisi_sec_ctx *ctx,
	struct hisi_sec_req *req)
{
	struct hisi_sec_cipher_req *c_req = &req->c_req;
	struct device *dev = ctx->dev;

	if (c_req->dst != c_req->src)
		hisi_acc_sg_buf_unmap(dev, c_req->src, c_req->c_in);

	hisi_acc_sg_buf_unmap(dev, c_req->dst, c_req->c_out);

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

	sec_sqe->src_addr_type = SGL;
	sec_sqe->dst_addr_type = SGL;
	sec_sqe->type          = BD_TYPE1;
	sec_sqe->scene         = SCENE_STORAGE;
	sec_sqe->de	= c_req->c_in_dma != c_req->c_out_dma;

	if (c_req->encrypt)
		sec_sqe->cipher = SEC_CIPHER_ENC;
	else
		sec_sqe->cipher = SEC_CIPHER_DEC;

	if (c_ctx->c_mode == C_MODE_XTS)
		sec_sqe->type1.ci_gen = CI_GEN_BY_LBA;

	sec_sqe->type1.cipher_gran_size = c_ctx->c_gran_size;
	sec_sqe->type1.gran_num         = c_req->gran_num;
	__sync_fetch_and_add(&ctx->sec->sec_dfx.gran_task_cnt, c_req->gran_num);
	sec_sqe->type1.block_size       = c_req->c_len;

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

	req->sec_sqe.type1.ci_gen = CI_GEN_BY_ADDR;

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

	sec_sqe->src_addr_type = SGL;
	sec_sqe->dst_addr_type = SGL;
	sec_sqe->type          = BD_TYPE2;
	sec_sqe->scene         = SCENE_IPSEC;
	sec_sqe->de = c_req->c_in_dma != c_req->c_out_dma;

	__sync_fetch_and_add(&ctx->sec->sec_dfx.gran_task_cnt, 1);

	if (c_req->encrypt)
		sec_sqe->cipher = SEC_CIPHER_ENC;
	else
		sec_sqe->cipher = SEC_CIPHER_DEC;

	sec_sqe->type2.c_len = c_req->c_len;
	sec_sqe->type2.tag   = req->req_id;

	return 0;
}

static int hisi_sec_bd_send_asyn(struct hisi_sec_ctx *ctx,
	struct hisi_sec_req *req)
{
	struct hisi_sec_qp_ctx *qp_ctx = req->qp_ctx;
	int req_cnt = req->req_cnt;
	int ret;

	mutex_lock(&qp_ctx->req_lock);
	ret = hisi_qp_send(qp_ctx->qp, &req->sec_sqe);
	__sync_add_and_fetch(&ctx->sec->sec_dfx.send_cnt, 1);
	mutex_unlock(&qp_ctx->req_lock);

	return hisi_sec_get_async_ret(ret, req_cnt, ctx->req_fake_limit);
}

static void hisi_sec_skcipher_complete(struct hisi_sec_ctx *ctx,
	struct hisi_sec_req *req, int err_code)
{
	struct skcipher_request **sk_reqs =
		(struct skcipher_request **)req->priv;
	int i, req_fusion_num;

	if (ctx->is_fusion == SEC_NO_FUSION)
		req_fusion_num = 1;
	else
		req_fusion_num = req->fusion_num;

	for (i = 0; i < req_fusion_num; i++)
		sk_reqs[i]->base.complete(&sk_reqs[i]->base, err_code);

	/* free sk_reqs if this request is completed */
	if (err_code != -EINPROGRESS)
		__sync_add_and_fetch(&ctx->sec->sec_dfx.put_task_cnt,
			req_fusion_num);
	else
		__sync_add_and_fetch(&ctx->sec->sec_dfx.busy_comp_cnt,
			req_fusion_num);
}

static int hisi_sec_skcipher_callback(struct hisi_sec_ctx *ctx,
	struct hisi_sec_req *req)
{
	struct hisi_sec_qp_ctx *qp_ctx = req->qp_ctx;
	int req_id = req->req_id;

	if (__sync_bool_compare_and_swap(&req->fake_busy, 1, 0))
		hisi_sec_skcipher_complete(ctx, req, -EINPROGRESS);

	hisi_sec_skcipher_complete(ctx, req, req->err_type);

	hisi_sec_free_req_id(qp_ctx, req_id);

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

static inline void hisi_sec_inc_thread_cnt(struct hisi_sec_ctx *ctx)
{
	int thread_cnt = atomic_inc_return(&ctx->thread_cnt);

	if (thread_cnt > ctx->sec->sec_dfx.thread_cnt)
		ctx->sec->sec_dfx.thread_cnt = thread_cnt;
}

static struct hisi_sec_req *sec_request_alloc(struct hisi_sec_ctx *ctx,
	struct hisi_sec_req *in_req, int *fusion_send, int *fake_busy)
{
	struct hisi_sec_qp_ctx *qp_ctx;
	struct hisi_sec_req *req;
	int issue_id, ret;

	__sync_add_and_fetch(&ctx->sec->sec_dfx.get_task_cnt, 1);

	issue_id = sec_get_issue_id(ctx, in_req);
	hisi_sec_inc_thread_cnt(ctx);

	qp_ctx = &ctx->qp_ctx[issue_id];

	mutex_lock(&qp_ctx->req_lock);

	if (in_req->c_req.sk_req->src == in_req->c_req.sk_req->dst) {
		*fusion_send = 1;
	} else if (qp_ctx->fusion_req &&
		qp_ctx->fusion_req->fusion_num < qp_ctx->fusion_limit) {
		req = qp_ctx->fusion_req;

		*fake_busy = req->fake_busy;
		__sync_add_and_fetch(&ctx->sec->sec_dfx.fake_busy_cnt,
			*fake_busy);

		req->priv[req->fusion_num] = in_req->c_req.sk_req;
		req->fusion_num++;
		in_req->fusion_num = req->fusion_num;
		if (req->fusion_num == qp_ctx->fusion_limit) {
			*fusion_send = 1;
			qp_ctx->fusion_req = NULL;
		}
		mutex_unlock(&qp_ctx->req_lock);
		return req;
	}

	req = in_req;

	if (hisi_sec_alloc_req_id(req, qp_ctx)) {
		mutex_unlock(&qp_ctx->req_lock);
		return NULL;
	}

	req->fake_busy = 0;

	req->req_cnt = atomic_inc_return(&qp_ctx->req_cnt);
	if (req->req_cnt >= ctx->req_fake_limit) {
		req->fake_busy = 1;
		*fake_busy = 1;
		__sync_add_and_fetch(&ctx->sec->sec_dfx.fake_busy_cnt, 1);
	}

	ret = ctx->req_op->get_res(ctx, req);
	if (ret) {
		dev_err(ctx->dev, "req_op get_res failed\n");
		mutex_unlock(&qp_ctx->req_lock);
		goto err_free_req_id;
	}

	if (ctx->fusion_limit <= 1 || ctx->fusion_tmout_nsec == 0)
		*fusion_send = 1;

	if (ctx->is_fusion && *fusion_send == 0)
		qp_ctx->fusion_req = req;

	req->fusion_num = 1;

	req->priv[0] = in_req->c_req.sk_req;
	req->st_time = ktime_get();

	mutex_unlock(&qp_ctx->req_lock);

	return req;

err_free_req_id:
	hisi_sec_free_req_id(qp_ctx, req->req_id);
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
	int fusion_send = 0;
	int fake_busy = 0;
	int ret;

	in_req->fusion_num = 1;

	req = sec_request_alloc(ctx, in_req, &fusion_send, &fake_busy);

	if (!req) {
		dev_err(ctx->dev, "sec_request_alloc failed\n");
		return -ENOMEM;
	}

	if (ctx->is_fusion && fusion_send == 0)
		return fake_busy ? -EBUSY : -EINPROGRESS;

	ret = sec_request_transfer(ctx, req);
	if (ret) {
		dev_err(ctx->dev, "sec_transfer failed! ret[%d]\n", ret);
		goto err_free_req;
	}

	ret = sec_request_send(ctx, req);
	__sync_add_and_fetch(&ctx->sec->sec_dfx.send_by_full, 1);
	if (ret != -EBUSY && ret != -EINPROGRESS) {
		dev_err(ctx->dev, "sec_send failed ret[%d]\n", ret);
		goto err_unmap_req;
	}

	return ret;

err_unmap_req:
	ctx->req_op->buf_unmap(ctx, req);
err_free_req:
	hisi_sec_free_req_id(req->qp_ctx, req->req_id);
	atomic_dec(&ctx->thread_cnt);
	return ret;
}

static int sec_skcipher_crypto(struct skcipher_request *sk_req, bool encrypt)
{
	struct crypto_skcipher *atfm = crypto_skcipher_reqtfm(sk_req);
	struct hisi_sec_ctx *ctx = crypto_skcipher_ctx(atfm);
	struct hisi_sec_req *req = skcipher_request_ctx(sk_req);

	if (!sk_req->src || !sk_req->dst || !sk_req->cryptlen)
		return -EINVAL;

	req->c_req.sk_req  = sk_req;
	req->c_req.encrypt = encrypt;
	req->ctx           = ctx;

	return sec_io_proc(ctx, req);
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
	sec_max_key_size, hisi_sec_cipher_ctx_init_func, blk_size, iv_size)\
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
	.init = hisi_sec_cipher_ctx_init_func,\
	.exit = hisi_sec_cipher_ctx_exit,\
	.setkey = sec_set_key,\
	.decrypt = sec_skcipher_decrypt,\
	.encrypt = sec_skcipher_encrypt,\
	.min_keysize = sec_min_key_size,\
	.max_keysize = sec_max_key_size,\
	.ivsize = iv_size,\
},

#define SEC_SKCIPHER_NORMAL_ALG(name, key_func, min_key_size, \
	max_key_size, blk_size, iv_size) \
	SEC_SKCIPHER_GEN_ALG(name, key_func, min_key_size, max_key_size, \
	hisi_sec_cipher_ctx_init_alg, blk_size, iv_size)

#define SEC_SKCIPHER_FUSION_ALG(name, key_func, min_key_size, \
	max_key_size, blk_size, iv_size) \
	SEC_SKCIPHER_GEN_ALG(name, key_func, min_key_size, max_key_size, \
	hisi_sec_cipher_ctx_init_multi_iv, blk_size, iv_size)

static struct skcipher_alg sec_normal_algs[] = {
	SEC_SKCIPHER_NORMAL_ALG("ecb(aes)", sec_setkey_aes_ecb,
		AES_MIN_KEY_SIZE, AES_MAX_KEY_SIZE, AES_BLOCK_SIZE, 0)
	SEC_SKCIPHER_NORMAL_ALG("cbc(aes)", sec_setkey_aes_cbc,
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
	SEC_SKCIPHER_NORMAL_ALG("xts(sm4)", sec_setkey_sm4_xts,
		SEC_XTS_MIN_KEY_SIZE, SEC_XTS_MIN_KEY_SIZE, AES_BLOCK_SIZE,
		AES_BLOCK_SIZE)
	SEC_SKCIPHER_NORMAL_ALG("cbc(sm4)", sec_setkey_sm4_cbc,
		AES_MIN_KEY_SIZE, AES_MIN_KEY_SIZE, AES_BLOCK_SIZE,
		AES_BLOCK_SIZE)
};

static struct skcipher_alg sec_fusion_algs[] = {
	SEC_SKCIPHER_FUSION_ALG("xts(sm4)", sec_setkey_sm4_xts,
		SEC_XTS_MIN_KEY_SIZE, SEC_XTS_MIN_KEY_SIZE, AES_BLOCK_SIZE,
		AES_BLOCK_SIZE)
	SEC_SKCIPHER_FUSION_ALG("cbc(sm4)", sec_setkey_sm4_cbc,
		AES_MIN_KEY_SIZE, AES_MIN_KEY_SIZE, AES_BLOCK_SIZE,
		AES_BLOCK_SIZE)
};

int hisi_sec_register_to_crypto(int fusion_limit)
{
	if (fusion_limit == 1)
		return crypto_register_skciphers(sec_normal_algs,
			ARRAY_SIZE(sec_normal_algs));
	else
		return crypto_register_skciphers(sec_fusion_algs,
			ARRAY_SIZE(sec_fusion_algs));
}

void hisi_sec_unregister_from_crypto(int fusion_limit)
{
	if (fusion_limit == 1)
		crypto_unregister_skciphers(sec_normal_algs,
			ARRAY_SIZE(sec_normal_algs));
	else
		crypto_unregister_skciphers(sec_fusion_algs,
			ARRAY_SIZE(sec_fusion_algs));
}
