// SPDX-License-Identifier: GPL-2.0+
#include <linux/module.h>
#include <crypto/internal/rsa.h>
#include <crypto/internal/akcipher.h>
#include <crypto/akcipher.h>
#include <crypto/kpp.h>
#include <crypto/internal/kpp.h>
#include <crypto/dh.h>
#include <linux/dma-mapping.h>
#include <linux/fips.h>
#include <crypto/scatterwalk.h>

#include "hpre.h"

struct hpre_ctx;

#define HPRE_CRYPTO_ALG_PRI	1000
#define HPRE_ALIGN_SZ		64
#define HPRE_BITS_2_BYTES_SHIFT	3
#define HPRE_RSA_INVLD_KEY_SZ	64
#define _CRT_PRMS		5
#define _CRT_Q			2
#define _CRT_P			3
#define _CRT_INV			4
#define _DH_G_FLAG		0x02
#define HPRE_TRY_SEND_TIMES	100
#define HPRE_INVLD_REQ_ID		-1
#define GET_DEV(ctx)		((ctx)->qp->qm->pdev->dev)

#define BITS64_MERGE(low_32, high_32)	(((u64)(low_32)) | \
					(((u64)(high_32)) << 32))
typedef void (*hpre_cb)(struct hpre_ctx *ctx, void *sqe);

struct _rsa_ctx {
	/* low address: e--->n */
	char *pubkey;

	/* low address: d--->n */
	char *prikey;

	/* low address: dq->dp->q->p->qinv */
	char *crt_prikey;
	dma_addr_t dma_pubkey;
	dma_addr_t dma_prikey;
	dma_addr_t dma_crt_prikey;
	struct crypto_akcipher *soft_tfm;
};

struct _dh_ctx {
	/*
	 * If base is g we compute the public key
	 *	ya = g^xa mod p; [RFC2631 sec 2.1.1]
	 * else if base if the counterpart public key we
	 * compute the shared secret
	 *	ZZ = yb^xa mod p; [RFC2631 sec 2.1.1]
	 */
	char *xa_p; /* low address: d--->n */
	char *g; /* m */
	dma_addr_t dma_xa_p;
	dma_addr_t dma_g;
};

struct hpre_ctx {
	struct hisi_qp *qp;
	struct hpre_asym_request **req_list;
	unsigned long *req_bitmap;
	spinlock_t req_lock;
	unsigned int key_sz;
	bool crt_g2_mode;
	union {
		struct _rsa_ctx rsa;
		struct _dh_ctx dh;
	};
};

struct hpre_asym_request {
	char *src_align;
	char *dst_align;
	struct hpre_sqe req;
	struct hpre_ctx *ctx;
	union {
		struct akcipher_request *rsa;
		struct kpp_request *dh;
	} areq;
	int err;
	int req_id;
	hpre_cb cb;
};

static void _rsa_cb(struct hpre_ctx *ctx, void *resp);

void hpre_bn_format(void *buff, int len)
{
	int i = len - 1;
	int j;
	unsigned char *buf = buff;

	while (!buf[i] && i >= 0)
		i--;
	if (i == len - 1)
		return;
	for (j = len - 1; j >= 0; j--, i--) {
		if (i >= 0)
			buf[j] = buf[i];
		else
			buf[j] = 0;
	}
}

static int hpre_alloc_req_id(struct hpre_ctx *ctx)
{
	int id;
	unsigned long flags;

	spin_lock_irqsave(&ctx->req_lock, flags);
	id = find_first_zero_bit(ctx->req_bitmap, QM_Q_DEPTH);
	if (id >= QM_Q_DEPTH) {
		spin_unlock_irqrestore(&ctx->req_lock, flags);
		pr_err("nno free req id!\n");
		return -EBUSY;
	}
	set_bit(id, ctx->req_bitmap);
	spin_unlock_irqrestore(&ctx->req_lock, flags);

	return id;
}

static void hpre_free_req_id(struct hpre_ctx *ctx, int req_id)
{
	unsigned long flags;

	spin_lock_irqsave(&ctx->req_lock, flags);
	bitmap_clear(ctx->req_bitmap, req_id, 1);
	spin_unlock_irqrestore(&ctx->req_lock, flags);
}

static int hpre_add_req_to_ctx(struct hpre_asym_request *hpre_req)
{
	struct hpre_ctx *ctx;
	int id;

	ctx = hpre_req->ctx;
	id = hpre_alloc_req_id(ctx);
	if (id < 0)
		return -EINVAL;

	ctx->req_list[id] = hpre_req;
	hpre_req->req_id = id;

	return id;
}

static void hpre_rm_req_from_ctx(struct hpre_asym_request *hpre_req)
{
	int id = hpre_req->req_id;
	struct hpre_ctx *ctx = hpre_req->ctx;

	if (hpre_req->req_id >= 0) {
		hpre_req->req_id = HPRE_INVLD_REQ_ID;
		ctx->req_list[id] = NULL;
		hpre_free_req_id(ctx, id);
	}
}

static struct hisi_qp *hpre_get_qp(void)
{
	struct hisi_qp *qp = NULL;
	struct hpre *hpre;
	int ret;

	/* find the proper hpre device */
	hpre = find_hpre_device(cpu_to_node(smp_processor_id()));
	if (!hpre) {
		pr_err("Can not find proper hpre device!\n");
		return ERR_PTR(-ENODEV);
	}
	qp = hisi_qm_create_qp(&hpre->qm, 0);
	if (IS_ERR(qp)) {
		dev_err(&hpre->qm.pdev->dev, "Can not create qp!\n");
		return ERR_PTR(-ENODEV);
	}
	ret = hisi_qm_start_qp(qp, 0);
	if (ret < 0) {
		hisi_qm_release_qp(qp);
		dev_err(&hpre->qm.pdev->dev, "Can not start qp!\n");
		return ERR_PTR(-EINVAL);
	}

	return qp;
}

static int _hw_data_init(struct hpre_asym_request *hpre_req,
			 struct scatterlist *data, unsigned int len,
			 int is_src, int is_dh)
{
	struct hpre_sqe *msg = &hpre_req->req;
	struct hpre_ctx *ctx = hpre_req->ctx;
	struct device *dev = &GET_DEV(ctx);
	enum dma_data_direction dma_dir;
	dma_addr_t tmp;
	char *ptr;
	int shift;

	/* when the data is dh's source, we should format it */
	if ((sg_is_last(data) && len == ctx->key_sz) &&
	    ((is_dh && !is_src) || !is_dh)) {
		if (is_src) {
			hpre_req->src_align = NULL;
			dma_dir = DMA_TO_DEVICE;
		} else {
			hpre_req->dst_align = NULL;
			dma_dir = DMA_FROM_DEVICE;
		}
		tmp = dma_map_single(dev, sg_virt(data),
				     len, dma_dir);
		if (unlikely(dma_mapping_error(dev, tmp))) {
			dev_err(dev, "\ndma map data err!");
			return -ENOMEM;
		}
	} else {
		shift = ctx->key_sz - len;
		if (shift < 0)
			return -EINVAL;

		ptr = dma_alloc_coherent(dev, ctx->key_sz, &tmp, GFP_KERNEL);
		if (unlikely(!ptr)) {
			dev_err(dev, "\ndma alloc data err!");
			return -ENOMEM;
		}
		if (is_src) {
			scatterwalk_map_and_copy(ptr + shift, data, 0, len, 0);
			if (is_dh)
				(void)hpre_bn_format(ptr, ctx->key_sz);
			hpre_req->src_align = ptr;
		} else {
			hpre_req->dst_align = ptr;
		}
	}
	if (is_src) {
		msg->low_in = lower_32_bits(tmp);
		msg->hi_in = upper_32_bits(tmp);
	} else {
		msg->low_out = lower_32_bits(tmp);
		msg->hi_out = upper_32_bits(tmp);
	}

	return 0;
}

static void _hw_data_clr_all(struct hpre_ctx *ctx,
			     struct hpre_asym_request *req,
			     struct scatterlist *dst, struct scatterlist *src)
{
	dma_addr_t tmp;
	struct device *dev = &GET_DEV(ctx);
	struct hpre_sqe *sqe = &req->req;

	tmp = BITS64_MERGE(sqe->low_in, sqe->hi_in);
	if (src && tmp) {
		if (req->src_align)
			dma_free_coherent(dev, ctx->key_sz,
					  req->src_align, tmp);
		else
			dma_unmap_single(dev, tmp,
					 ctx->key_sz, DMA_TO_DEVICE);
	}
	tmp = BITS64_MERGE(sqe->low_out, sqe->hi_out);
	if (req->dst_align && tmp) {
		if (dst)
			scatterwalk_map_and_copy(req->dst_align, dst, 0,
						 ctx->key_sz, 1);
		dma_free_coherent(dev, ctx->key_sz, req->dst_align, tmp);
	} else if (!req->dst_align && tmp) {
		dma_unmap_single(dev, tmp, ctx->key_sz, DMA_FROM_DEVICE);
	}
}

static int _alg_res_post_hf(struct hpre_ctx *ctx, struct hpre_sqe *sqe,
			    void **kreq)
{
	struct hpre_asym_request *req;
	int err, id;

#define HPRE_NO_HW_ERR		0
#define HPRE_HW_TASK_DONE	3
	id = (int)sqe->tag;
	req = ctx->req_list[id];
	hpre_rm_req_from_ctx(req);
	*kreq = req;
	err = sqe->etype;
	err = (err == HPRE_NO_HW_ERR && sqe->done ==
		HPRE_HW_TASK_DONE) ? 0 : -EINVAL;

	return err;
}

static int _ctx_init(struct hpre_ctx *ctx, struct hisi_qp *qp, int qlen)
{
	if (!ctx || !qp || qlen < 0)
		return -EINVAL;

	spin_lock_init(&ctx->req_lock);
	ctx->req_bitmap = kcalloc(BITS_TO_LONGS(qlen), sizeof(long),
				  GFP_KERNEL);
	if (!ctx->req_bitmap)
		return -ENOMEM;
	ctx->qp = qp;
	ctx->req_list = kcalloc(qlen, sizeof(void *), GFP_KERNEL);
	if (!ctx->req_list) {
		kfree(ctx->req_bitmap);
		return -ENOMEM;
	}
	ctx->key_sz = 0;
	ctx->crt_g2_mode = false;

	return 0;
}

static void _ctx_clear(struct hpre_ctx *ctx, int is_exit)
{
	if (is_exit) {
		kfree(ctx->req_bitmap);
		kfree(ctx->req_list);
		hisi_qm_release_qp(ctx->qp);
	}

	ctx->crt_g2_mode = false;
	ctx->key_sz = 0;
}

static void _dh_cb(struct hpre_ctx *ctx, void *resp)
{
	struct kpp_request *areq;
	struct hpre_asym_request *req;
	int ret;

	ret = _alg_res_post_hf(ctx, resp, (void **)&req);
	areq = req->areq.dh;
	areq->dst_len = ctx->key_sz;
	_hw_data_clr_all(ctx, req, areq->dst, areq->src);
	kpp_request_complete(areq, ret);
}

void hpre_alg_cb(struct hisi_qp *qp, void *_resp)
{
	struct hpre_sqe *sqe = _resp;
	struct hpre_asym_request *areq;
	struct hpre_ctx *ctx = qp->qp_ctx;
	u32 id = sqe->tag;

	areq = ctx->req_list[id];
	areq->cb(ctx, _resp);
}

static int hpre_ctx_init(struct hpre_ctx *ctx)
{
	struct hisi_qp *qp;

	qp = hpre_get_qp();
	if (IS_ERR(qp))
		return PTR_ERR(qp);
	qp->qp_ctx = ctx;
	qp->req_cb = hpre_alg_cb;

	return _ctx_init(ctx, qp, QM_Q_DEPTH);
}

static int hpre_msg_comm_set(struct hpre_ctx *ctx, void *req, int is_rsa)
{
	struct hpre_asym_request *h_req;
	struct hpre_sqe *msg;
	struct kpp_request *kreq = req;
	struct akcipher_request *akreq = req;
	int req_id;

	if (!req || !ctx)
		return -EINVAL;
	if (is_rsa) {
		if (akreq->dst_len < ctx->key_sz) {
			akreq->dst_len = ctx->key_sz;
			return -EOVERFLOW;
		}
		h_req = PTR_ALIGN(akcipher_request_ctx(akreq), HPRE_ALIGN_SZ);
		h_req->cb = _rsa_cb;
		h_req->areq.rsa = akreq;
		msg = &h_req->req;
		memset(msg, '\0', sizeof(*msg));
	} else {
		if (kreq->dst_len < ctx->key_sz) {
			kreq->dst_len = ctx->key_sz;
			return -EOVERFLOW;
		}
		h_req = PTR_ALIGN(kpp_request_ctx(kreq), HPRE_ALIGN_SZ);
		h_req->cb = _dh_cb;
		h_req->areq.dh = kreq;
		msg = &h_req->req;
		memset(msg, '\0', sizeof(*msg));
		msg->low_key = lower_32_bits(ctx->dh.dma_xa_p);
		msg->hi_key = upper_32_bits(ctx->dh.dma_xa_p);
	}
	msg->done = 1;
	msg->task_len1 = (ctx->key_sz >> HPRE_BITS_2_BYTES_SHIFT) - 1;
	h_req->ctx = ctx;
	req_id = hpre_add_req_to_ctx(h_req);
	if (req_id < 0)
		return -EBUSY;
	msg->tag = (u16)req_id;

	return 0;
}

static int hpre_dh_compute_value(struct kpp_request *req)
{
	struct crypto_kpp *tfm = crypto_kpp_reqtfm(req);
	struct hpre_ctx *ctx = kpp_tfm_ctx(tfm);
	struct hpre_asym_request *hpre_req =
		PTR_ALIGN(kpp_request_ctx(req), HPRE_ALIGN_SZ);
	struct hpre_sqe *msg = &hpre_req->req;
	int ret;
	int ctr = 0;

	ret = hpre_msg_comm_set(ctx, req, 0);
	if (ret)
		return ret;
	if (req->src) {
		ret = _hw_data_init(hpre_req, req->src, req->src_len, 1, 1);
		if (ret)
			goto clear_all;
	}
	ret = _hw_data_init(hpre_req, req->dst, req->dst_len, 0, 1);
	if (ret)
		goto clear_all;
	if (ctx->crt_g2_mode && !req->src)
		msg->alg = HPRE_ALG_DH_G2;
	else
		msg->alg = HPRE_ALG_DH;
	do {
		ret = hisi_qp_send(ctx->qp, msg);
	} while (ret == -EBUSY && ctr++ < HPRE_TRY_SEND_TIMES);

	if (!ret)
		return -EINPROGRESS;
clear_all:
	hpre_rm_req_from_ctx(hpre_req);
	_hw_data_clr_all(ctx, hpre_req, req->dst, req->src);
	return ret;
}

static int hpre_dh_check_params_length(unsigned int key_sz)
{
#define _HPRE_DH_GRP1		768
#define _HPRE_DH_GRP2		1024
#define _HPRE_DH_GRP5		1536
#define _HPRE_DH_GRP14		2048
#define _HPRE_DH_GRP15		3072
#define _HPRE_DH_GRP16		4096
	switch (key_sz) {
	case _HPRE_DH_GRP1:
	case _HPRE_DH_GRP2:
	case _HPRE_DH_GRP5:
	case _HPRE_DH_GRP14:
	case _HPRE_DH_GRP15:
	case _HPRE_DH_GRP16:
		return 0;
	}

	return -EINVAL;
}

static int hpre_dh_set_params(struct hpre_ctx *ctx, struct dh *params)
{
	struct device *dev = &GET_DEV(ctx);
	unsigned int sz;

	if (hpre_dh_check_params_length(params->p_size <<
		HPRE_BITS_2_BYTES_SHIFT))
		return -EINVAL;

	sz = ctx->key_sz = params->p_size;
	ctx->dh.xa_p = dma_alloc_coherent(dev, sz << 1,
					  &ctx->dh.dma_xa_p, GFP_KERNEL);
	if (!ctx->dh.xa_p)
		return -ENOMEM;
	memcpy(ctx->dh.xa_p + sz, params->p, sz);
	hpre_bn_format((unsigned char *)ctx->dh.xa_p + sz, sz);

	/* If g equals 2 don't copy it */
	if (params->g_size == 1 && *(char *)params->g == _DH_G_FLAG) {
		ctx->crt_g2_mode = true;
		return 0;
	}

	ctx->dh.g = dma_alloc_coherent(dev, sz, &ctx->dh.dma_g, GFP_KERNEL);
	if (!ctx->dh.g)
		return -ENOMEM;
	memcpy(ctx->dh.g + (sz - params->g_size), params->g,
	       params->g_size);
	hpre_bn_format(ctx->dh.g, ctx->key_sz);

	return 0;
}

static void hpre_dh_clear_ctx(struct hpre_ctx *ctx, int is_exit)
{
	unsigned int sz = ctx->key_sz;
	struct device *dev = &GET_DEV(ctx);

	if (ctx->dh.g) {
		dma_free_coherent(dev, sz, ctx->dh.g, ctx->dh.dma_g);
		ctx->dh.g = NULL;
	}
	if (ctx->dh.xa_p) {
		dma_free_coherent(dev, sz << 1, ctx->dh.xa_p,
				ctx->dh.dma_xa_p);
		ctx->dh.xa_p = NULL;
	}
	_ctx_clear(ctx, is_exit);
}

static int hpre_dh_set_secret(struct crypto_kpp *tfm, const void *buf,
			      unsigned int len)
{
	struct hpre_ctx *ctx = kpp_tfm_ctx(tfm);
	struct dh params;
	int ret;

	if (crypto_dh_decode_key(buf, len, &params) < 0)
		return -EINVAL;

	/* Free old secret if any */
	hpre_dh_clear_ctx(ctx, 0);

	ret = hpre_dh_set_params(ctx, &params);
	if (ret < 0)
		goto err_clear_ctx;

	memcpy(ctx->dh.xa_p + (ctx->key_sz - params.key_size), params.key,
	       params.key_size);
	hpre_bn_format((unsigned char *)ctx->dh.xa_p, ctx->key_sz);

	return 0;

err_clear_ctx:
	hpre_dh_clear_ctx(ctx, 0);
	return ret;
}

static unsigned int hpre_dh_max_size(struct crypto_kpp *tfm)
{
	struct hpre_ctx *ctx = kpp_tfm_ctx(tfm);

	return ctx->key_sz;
}

static int hpre_dh_init_tfm(struct crypto_kpp *tfm)
{
	struct hpre_ctx *ctx = kpp_tfm_ctx(tfm);

	return hpre_ctx_init(ctx);
}

static void hpre_dh_exit_tfm(struct crypto_kpp *tfm)
{
	struct hpre_ctx *ctx = kpp_tfm_ctx(tfm);

	hpre_dh_clear_ctx(ctx, 1);
}

static void _rsa_cb(struct hpre_ctx *ctx, void *resp)
{
	struct akcipher_request *areq;
	struct hpre_asym_request *req;
	int ret;

	ret = _alg_res_post_hf(ctx, resp, (void **)&req);
	areq = req->areq.rsa;
	areq->dst_len = ctx->key_sz;
	_hw_data_clr_all(ctx, req, areq->dst, areq->src);
	akcipher_request_complete(areq, ret);
}

static unsigned long hpre_rsa_key_size_check(unsigned int len)
{
	unsigned int bitslen = len << HPRE_BITS_2_BYTES_SHIFT;

#define _RSA_512BITS_KEY_WDTH		512
#define _RSA_1024BITS_KEY_WDTH		1024
#define _RSA_2048BITS_KEY_WDTH		2048
#define _RSA_3072BITS_KEY_WDTH		3072
#define _RSA_4096BITS_KEY_WDTH		4096

	switch (bitslen) {
	/* 512bits is not supported by HPRE now! */
	case _RSA_512BITS_KEY_WDTH:
	case _RSA_1024BITS_KEY_WDTH:
	case _RSA_2048BITS_KEY_WDTH:
	case _RSA_3072BITS_KEY_WDTH:
	case _RSA_4096BITS_KEY_WDTH:
		return 0;
	default:
		return -1;
	};
}

static int hpre_rsa_enc(struct akcipher_request *req)
{
	struct crypto_akcipher *tfm = crypto_akcipher_reqtfm(req);
	struct hpre_ctx *ctx = akcipher_tfm_ctx(tfm);
	struct hpre_asym_request *hpre_req =
		PTR_ALIGN(akcipher_request_ctx(req), HPRE_ALIGN_SZ);
	struct hpre_sqe *msg = &hpre_req->req;
	int ret;
	int ctr = 0;

	if (ctx->key_sz == HPRE_RSA_INVLD_KEY_SZ && ctx->rsa.soft_tfm) {
		akcipher_request_set_tfm(req, ctx->rsa.soft_tfm);
		ret = crypto_akcipher_encrypt(req);
		akcipher_request_set_tfm(req, tfm);
		return ret;
	}
	if (unlikely(!ctx->rsa.pubkey))
		return -EINVAL;
	ret = hpre_msg_comm_set(ctx, req, 1);
	if (ret)
		return ret;
	msg->alg = HPRE_ALG_NC_NCRT;
	msg->low_key = lower_32_bits(ctx->rsa.dma_pubkey);
	msg->hi_key = upper_32_bits(ctx->rsa.dma_pubkey);
	ret = _hw_data_init(hpre_req, req->src, req->src_len, 1, 0);
	if (ret)
		goto clear_all;
	ret = _hw_data_init(hpre_req, req->dst, req->dst_len, 0, 0);
	if (ret)
		goto clear_all;
	do {
		ret = hisi_qp_send(ctx->qp, msg);
	} while (ret == -EBUSY && ctr++ < HPRE_TRY_SEND_TIMES);

	if (!ret)
		return -EINPROGRESS;
clear_all:
	hpre_rm_req_from_ctx(hpre_req);
	_hw_data_clr_all(ctx, hpre_req, req->dst, req->src);

	return ret;
}

static int hpre_rsa_dec(struct akcipher_request *req)
{
	struct crypto_akcipher *tfm = crypto_akcipher_reqtfm(req);
	struct hpre_ctx *ctx = akcipher_tfm_ctx(tfm);
	struct hpre_asym_request *hpre_req =
		PTR_ALIGN(akcipher_request_ctx(req), HPRE_ALIGN_SZ);
	struct hpre_sqe *msg = &hpre_req->req;
	int ret;
	int ctr = 0;

	if (ctx->key_sz == HPRE_RSA_INVLD_KEY_SZ && ctx->rsa.soft_tfm) {
		akcipher_request_set_tfm(req, ctx->rsa.soft_tfm);
		ret = crypto_akcipher_decrypt(req);
		akcipher_request_set_tfm(req, tfm);
		return ret;
	}
	if (unlikely(!ctx->rsa.prikey))
		return -EINVAL;
	ret = hpre_msg_comm_set(ctx, req, 1);
	if (ret)
		return ret;
	if (ctx->crt_g2_mode) {
		msg->low_key = lower_32_bits(ctx->rsa.dma_crt_prikey);
		msg->hi_key = upper_32_bits(ctx->rsa.dma_crt_prikey);
		msg->alg = HPRE_ALG_NC_CRT;
	} else {
		msg->low_key = lower_32_bits(ctx->rsa.dma_prikey);
		msg->hi_key = upper_32_bits(ctx->rsa.dma_prikey);
		msg->alg = HPRE_ALG_NC_NCRT;
	}
	ret = _hw_data_init(hpre_req, req->src, req->src_len, 1, 0);
	if (ret)
		goto clear_all;
	ret = _hw_data_init(hpre_req, req->dst, req->dst_len, 0, 0);
	if (ret)
		goto clear_all;

	do {
		ret = hisi_qp_send(ctx->qp, msg);
	} while (ret == -EBUSY && ctr++ < HPRE_TRY_SEND_TIMES);

	if (!ret)
		return -EINPROGRESS;
clear_all:
	hpre_rm_req_from_ctx(hpre_req);
	_hw_data_clr_all(ctx, hpre_req, req->dst, req->src);

	return ret;
}

static int hpre_rsa_set_n(struct hpre_ctx *ctx, const char *value,
			  size_t vlen, bool private)
{
	const char *ptr = value;
	int ret = -EINVAL;

	while (!*ptr && vlen) {
		ptr++;
		vlen--;
	}
	ctx->key_sz = vlen;

	/* invalid key size provided */
	if (hpre_rsa_key_size_check(ctx->key_sz))
		goto err;
	if (private) {
		ctx->rsa.prikey = dma_alloc_coherent(&GET_DEV(ctx), vlen << 1,
						     &ctx->rsa.dma_prikey,
						     GFP_KERNEL);
		if (!ctx->rsa.prikey)
			return -ENOMEM;
	}
	ctx->rsa.pubkey = dma_alloc_coherent(&GET_DEV(ctx), vlen << 1,
					     &ctx->rsa.dma_pubkey,
					     GFP_KERNEL);
	if (!ctx->rsa.pubkey)
		return -ENOMEM;
	memcpy(ctx->rsa.pubkey + vlen, ptr, vlen);
	hpre_bn_format((unsigned char *)ctx->rsa.pubkey + vlen, vlen);
	if (ctx->rsa.prikey) {
		memcpy(ctx->rsa.prikey + vlen, ptr, vlen);
		hpre_bn_format((unsigned char *)ctx->rsa.prikey + vlen, vlen);
	}

	return 0;
err:
	ctx->key_sz = 0;

	return ret;
}

static int hpre_rsa_set_e(struct hpre_ctx *ctx, const char *value,
			  size_t vlen)
{
	const char *ptr = value;

	while (!*ptr && vlen) {
		ptr++;
		vlen--;
	}
	if (!ctx->key_sz || !vlen || vlen > ctx->key_sz) {
		ctx->rsa.pubkey = NULL;
		return -EINVAL;
	}

	memcpy(ctx->rsa.pubkey, ptr, vlen);
	hpre_bn_format((unsigned char *)ctx->rsa.pubkey, ctx->key_sz);

	return 0;
}

static int hpre_rsa_set_d(struct hpre_ctx *ctx, const char *value,
			  size_t vlen)
{
	const char *ptr = value;

	while (!*ptr && vlen) {
		ptr++;
		vlen--;
	}
	if (!ctx->key_sz || !vlen || vlen > ctx->key_sz)
		goto err;

	memcpy(ctx->rsa.prikey, ptr, vlen);
	hpre_bn_format((unsigned char *)ctx->rsa.prikey, ctx->key_sz);
	return 0;
err:
	ctx->rsa.prikey = NULL;
	return -EINVAL;
}

static void hpre_rsa_drop_leading_zeros(const char **ptr, unsigned int *len)
{
	while (!**ptr && *len) {
		(*ptr)++;
		(*len)--;
	}
}

static int hpre_crt_para_get(char *para, const char *raw,
			     unsigned int raw_sz, unsigned int para_size)
{
	const char *ptr = raw;
	unsigned int len = raw_sz;

	hpre_rsa_drop_leading_zeros(&ptr, &len);
	if (!len)
		return -EINVAL;

	memcpy(para, ptr, len);
	hpre_bn_format(para, para_size);

	return 0;
}
static int hpre_rsa_setkey_crt(struct hpre_ctx *ctx, struct rsa_key *rsa_key)
{
	struct device *dev = &GET_DEV(ctx);
	unsigned int hlf_ksz = ctx->key_sz >> 1;
	int ret;

	ctx->rsa.crt_prikey = dma_alloc_coherent(dev, hlf_ksz * _CRT_PRMS,
						 &ctx->rsa.dma_crt_prikey,
						 GFP_KERNEL);
	if (!ctx->rsa.crt_prikey)
		return -ENOMEM;

	/* dq */
	ret = hpre_crt_para_get(ctx->rsa.crt_prikey, rsa_key->dq,
				rsa_key->dq_sz, hlf_ksz);
	if (ret)
		goto free_key;

	/* dp */
	ret = hpre_crt_para_get(ctx->rsa.crt_prikey + hlf_ksz, rsa_key->dp,
				rsa_key->dp_sz, hlf_ksz);
	if (ret)
		goto free_key;

	/* q */
	ret = hpre_crt_para_get(ctx->rsa.crt_prikey + hlf_ksz * _CRT_Q,
				rsa_key->q, rsa_key->q_sz, hlf_ksz);
	if (ret)
		goto free_key;

	/* p */
	ret = hpre_crt_para_get(ctx->rsa.crt_prikey + hlf_ksz * _CRT_P,
				rsa_key->p, rsa_key->p_sz, hlf_ksz);
	if (ret)
		goto free_key;

	/* qinv */
	ret = hpre_crt_para_get(ctx->rsa.crt_prikey + hlf_ksz * _CRT_INV,
				rsa_key->qinv, rsa_key->qinv_sz, hlf_ksz);
	if (ret)
		goto free_key;
	ctx->crt_g2_mode = true;

	return 0;
free_key:
	memset(ctx->rsa.crt_prikey + hlf_ksz * _CRT_PRMS, '\0', hlf_ksz);
	dma_free_coherent(dev, hlf_ksz * _CRT_PRMS, ctx->rsa.crt_prikey,
			  ctx->rsa.dma_crt_prikey);
	ctx->rsa.crt_prikey = NULL;
	ctx->crt_g2_mode = false;

	return ret;
}

static void hpre_rsa_clear_ctx(struct hpre_ctx *ctx, int is_exit)
{
	unsigned int half_key_sz = ctx->key_sz >> 1;
	struct device *dev = &GET_DEV(ctx);

	if (ctx->rsa.pubkey) {
		dma_free_coherent(dev, ctx->key_sz << 1,
				  ctx->rsa.pubkey, ctx->rsa.dma_pubkey);
		ctx->rsa.pubkey = NULL;
	}
	if (ctx->rsa.crt_prikey) {
		memset(ctx->rsa.crt_prikey, '\0', half_key_sz * _CRT_PRMS);
		dma_free_coherent(dev, half_key_sz * _CRT_PRMS,
				  ctx->rsa.crt_prikey, ctx->rsa.dma_crt_prikey);
		ctx->rsa.crt_prikey = NULL;
	}
	if (ctx->rsa.prikey) {
		memset(ctx->rsa.prikey, '\0', ctx->key_sz);
		dma_free_coherent(dev, ctx->key_sz << 1, ctx->rsa.prikey,
				  ctx->rsa.dma_prikey);
		ctx->rsa.prikey = NULL;
	}

	_ctx_clear(ctx, is_exit);
}

static int hpre_rsa_setkey(struct hpre_ctx *ctx, const void *key,
			   unsigned int keylen, bool private)
{
	struct rsa_key rsa_key;
	int ret;

	hpre_rsa_clear_ctx(ctx, 0);

	if (private)
		ret = rsa_parse_priv_key(&rsa_key, key, keylen);
	else
		ret = rsa_parse_pub_key(&rsa_key, key, keylen);
	if (ret < 0)
		goto free;

	ret = hpre_rsa_set_n(ctx, rsa_key.n, rsa_key.n_sz, private);
	if (ret < 0)
		goto free;

	if (private) {
		ret = hpre_rsa_set_d(ctx, rsa_key.d, rsa_key.d_sz);
		if (ret < 0)
			goto free;
		hpre_rsa_setkey_crt(ctx, &rsa_key);
	}
	ret = hpre_rsa_set_e(ctx, rsa_key.e, rsa_key.e_sz);
	if (ret < 0)
		goto free;

	if (!ctx->rsa.pubkey) {
		/* invalid key provided */
		ret = -EINVAL;
		goto free;
	}
	if (private && !ctx->rsa.prikey) {
		/* invalid private key provided */
		ret = -EINVAL;
		goto free;
	}

	return 0;
free:
	hpre_rsa_clear_ctx(ctx, 0);
	return ret;
}

static int hpre_rsa_setpubkey(struct crypto_akcipher *tfm, const void *key,
			      unsigned int keylen)
{
	struct hpre_ctx *ctx = akcipher_tfm_ctx(tfm);
	int ret;

	ret = crypto_akcipher_set_pub_key(ctx->rsa.soft_tfm, key, keylen);
	if (ret)
		return ret;
	return hpre_rsa_setkey(ctx, key, keylen, false);
}

static int hpre_rsa_setprivkey(struct crypto_akcipher *tfm, const void *key,
			       unsigned int keylen)
{
	struct hpre_ctx *ctx = akcipher_tfm_ctx(tfm);
	int ret;

	ret = crypto_akcipher_set_priv_key(ctx->rsa.soft_tfm, key, keylen);
	if (ret)
		return ret;

	return hpre_rsa_setkey(ctx, key, keylen, true);
}

static unsigned int hpre_rsa_max_size(struct crypto_akcipher *tfm)
{
	struct hpre_ctx *ctx = akcipher_tfm_ctx(tfm);

	if (ctx->rsa.soft_tfm && ctx->key_sz == HPRE_RSA_INVLD_KEY_SZ)
		return crypto_akcipher_maxsize(ctx->rsa.soft_tfm);

	return ctx->key_sz;
}

static int hpre_rsa_init_tfm(struct crypto_akcipher *tfm)
{
	struct hpre_ctx *ctx = akcipher_tfm_ctx(tfm);

	ctx->rsa.soft_tfm = crypto_alloc_akcipher("rsa-generic", 0, 0);
	if (IS_ERR(ctx->rsa.soft_tfm)) {
		pr_err("Can not alloc_akcipher!\n");
		return PTR_ERR(tfm);
	}

	return hpre_ctx_init(ctx);
}

static void hpre_rsa_exit_tfm(struct crypto_akcipher *tfm)
{
	struct hpre_ctx *ctx = akcipher_tfm_ctx(tfm);

	hpre_rsa_clear_ctx(ctx, 1);
	if (ctx->rsa.soft_tfm)
		crypto_free_akcipher(ctx->rsa.soft_tfm);
}

static struct akcipher_alg rsa = {
	.encrypt = hpre_rsa_enc,
	.decrypt = hpre_rsa_dec,
	.sign = hpre_rsa_dec,
	.verify = hpre_rsa_enc,
	.set_pub_key = hpre_rsa_setpubkey,
	.set_priv_key = hpre_rsa_setprivkey,
	.max_size = hpre_rsa_max_size,
	.init = hpre_rsa_init_tfm,
	.exit = hpre_rsa_exit_tfm,
	.reqsize = sizeof(struct hpre_asym_request) + HPRE_ALIGN_SZ,
	.base = {
		.cra_name = "rsa",
		.cra_driver_name = "hpre-rsa",
		.cra_priority = HPRE_CRYPTO_ALG_PRI,
		.cra_module = THIS_MODULE,
		.cra_ctxsize = sizeof(struct hpre_ctx),
	},
};

static struct kpp_alg dh = {
	.set_secret = hpre_dh_set_secret,
	.generate_public_key = hpre_dh_compute_value,
	.compute_shared_secret = hpre_dh_compute_value,
	.max_size = hpre_dh_max_size,
	.init = hpre_dh_init_tfm,
	.exit = hpre_dh_exit_tfm,
	.reqsize = sizeof(struct hpre_asym_request) + HPRE_ALIGN_SZ,
	.base = {
		.cra_name = "dh",
		.cra_driver_name = "hpre-dh",
		.cra_priority = HPRE_CRYPTO_ALG_PRI,
		.cra_module = THIS_MODULE,
		.cra_ctxsize = sizeof(struct hpre_ctx),
	},
};

int hpre_algs_register(void)
{
	int ret;

	rsa.base.cra_flags = 0;
	ret = crypto_register_akcipher(&rsa);
	if (ret)
		return ret;

	return crypto_register_kpp(&dh);
}

void hpre_algs_unregister(void)
{
	crypto_unregister_akcipher(&rsa);
	crypto_unregister_kpp(&dh);
}
