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

#define HSEC_SGL_CACHE_SIZE	(SEC_MAX_SGL_NUM * sizeof(struct sgl))

// #define SEC_DEBUG_LOG

#ifdef SEC_DEBUG_LOG
#define dbg(msg, ...) pr_info(msg, ##__VA_ARGS__)
#else
#define dbg(msg, ...)
#endif

struct hisi_sec_buffer {
	struct sgl *c_in;
	dma_addr_t c_in_dma;
	struct sgl *c_out;
	dma_addr_t c_out_dma;
	u8 *c_key;
	dma_addr_t c_key_dma;
	u8 *c_ivin;
	dma_addr_t c_ivin_dma;
};

struct hisi_sec_qp_ctx {
	struct hisi_sec_buffer buffer;
	struct hisi_qp *qp;
	struct hisi_sec_sqe sec_sqe;
};

static void dump_sec_bd(unsigned int *bd)
{
	unsigned int i;

	for (i = 0; i < 32; i++)
		dbg("Word[%d] 0x%08x\n", i, bd[i]);

	dbg("\n");
}

/* let's allocate one buffer now, may have problem in async case */
static int hisi_sec_alloc_qp_buffer(struct hisi_sec_qp_ctx *hisi_sec_qp_ctx)
{
	struct hisi_sec_buffer *buf = &hisi_sec_qp_ctx->buffer;
	struct hisi_qp *qp = hisi_sec_qp_ctx->qp;
	struct device *dev = &qp->qm->pdev->dev;
	struct hisi_sec_sqe *sec_sqe = &hisi_sec_qp_ctx->sec_sqe;
	int ret;
	int i;

	buf->c_in = dma_alloc_coherent(dev, HSEC_SGL_CACHE_SIZE,
				       &buf->c_in_dma, GFP_KERNEL);
	if (!buf->c_in)
		return -ENOMEM;

	buf->c_out = dma_alloc_coherent(dev, HSEC_SGL_CACHE_SIZE,
					&buf->c_out_dma, GFP_KERNEL);
	if (!buf->c_out) {
		ret = -ENOMEM;
		goto err_alloc_output;
	}

	for (i = 0; i < SEC_MAX_SGL_NUM - 1; i++) {
		buf->c_in[i].next = (struct sgl *)(buf->c_in_dma +
						   (i +
						    1) * sizeof(struct sgl));
		buf->c_out[i].next =
		    (struct sgl *)(buf->c_out_dma +
				   (i + 1) * sizeof(struct sgl));
	}

	buf->c_key = dma_alloc_coherent(dev, SEC_MAX_KEY_SIZE,
					&buf->c_key_dma, GFP_KERNEL);
	if (!buf->c_key) {
		ret = -ENOMEM;
		goto err_alloc_key;
	}

	buf->c_ivin = dma_alloc_coherent(dev, SEC_MAX_IV_SIZE,
					 &buf->c_ivin_dma, GFP_KERNEL);
	if (!buf->c_ivin) {
		ret = -ENOMEM;
		goto err_alloc_ivin;
	}

	sec_sqe->type2.data_src_addr_l = lower_32_bits(buf->c_in_dma);
	sec_sqe->type2.data_src_addr_h = upper_32_bits(buf->c_in_dma);
	sec_sqe->type2.data_dst_addr_l = lower_32_bits(buf->c_out_dma);
	sec_sqe->type2.data_dst_addr_h = upper_32_bits(buf->c_out_dma);
	sec_sqe->type2.c_key_addr_l = lower_32_bits(buf->c_key_dma);
	sec_sqe->type2.c_key_addr_h = upper_32_bits(buf->c_key_dma);
	sec_sqe->type2.c_ivin_addr_l = lower_32_bits(buf->c_ivin_dma);
	sec_sqe->type2.c_ivin_addr_h = upper_32_bits(buf->c_ivin_dma);

	return 0;

 err_alloc_ivin:
	dma_free_coherent(dev, SEC_MAX_KEY_SIZE, buf->c_key, buf->c_key_dma);
 err_alloc_key:
	dma_free_coherent(dev, HSEC_SGL_CACHE_SIZE, buf->c_out, buf->c_out_dma);
 err_alloc_output:
	dma_free_coherent(dev, HSEC_SGL_CACHE_SIZE, buf->c_in, buf->c_in_dma);

	return ret;
}

static void hisi_sec_free_qp_buffer(struct hisi_sec_qp_ctx *hisi_sec_qp_ctx)
{
	struct hisi_sec_buffer *buf = &hisi_sec_qp_ctx->buffer;
	struct hisi_qp *qp = hisi_sec_qp_ctx->qp;
	struct device *dev = &qp->qm->pdev->dev;

	if (buf->c_in) {
		dma_free_coherent(dev, HSEC_SGL_CACHE_SIZE, buf->c_in,
				  buf->c_in_dma);
		buf->c_in = NULL;
	}
	if (buf->c_out) {
		dma_free_coherent(dev, HSEC_SGL_CACHE_SIZE, buf->c_out,
				  buf->c_out_dma);
		buf->c_out = NULL;
	}
	if (buf->c_key) {
		dma_free_coherent(dev, SEC_MAX_KEY_SIZE, buf->c_key,
				  buf->c_key_dma);
		buf->c_key = NULL;
	}
	if (buf->c_ivin) {
		dma_free_coherent(dev, SEC_MAX_IV_SIZE, buf->c_ivin,
				  buf->c_ivin_dma);
		buf->c_ivin = NULL;
	}
}

static int hisi_sec_create_qp(struct hisi_qm *qm, struct hisi_sec_qp_ctx *ctx,
			      int alg_type, int req_type)
{
	struct hisi_qp *qp;
	int ret;

	qp = hisi_qm_create_qp(qm, alg_type);
	if (IS_ERR(qp))
		return PTR_ERR(qp);

	qp->req_type = req_type;
	qp->qp_ctx = ctx;
	ctx->qp = qp;

	ret = hisi_sec_alloc_qp_buffer(ctx);
	if (ret)
		goto err_release_qp;

	ret = hisi_qm_start_qp(qp, 0);
	if (ret < 0)
		goto err_free_qp_buffer;

	return 0;

 err_free_qp_buffer:
	hisi_sec_free_qp_buffer(ctx);
 err_release_qp:
	hisi_qm_release_qp(qp);
	return ret;
}

static void hisi_sec_release_qp(struct hisi_sec_qp_ctx *ctx)
{
	hisi_qm_stop_qp(ctx->qp);
	hisi_sec_free_qp_buffer(ctx);
	hisi_qm_release_qp(ctx->qp);
}

static int hisi_sec_alloc_cipher_ctx(struct crypto_skcipher *tfm)
{
	struct hisi_sec_qp_ctx *hisi_sec_qp_ctx = crypto_skcipher_ctx(tfm);
	// const char *alg_name = crypto_tfm_alg_name(tfm);
	struct hisi_sec *hisi_sec;
	struct hisi_qm *qm;
	int ret;

	/* find the proper sec device */
	hisi_sec = find_sec_device(cpu_to_node(smp_processor_id()));
	if (!hisi_sec) {
		pr_err("Failed to find a proper SEC device!\n");
		return -ENODEV;
	}
	qm = &hisi_sec->qm;

	ret = hisi_sec_create_qp(qm, hisi_sec_qp_ctx, 0, 0);
	if (ret)
		goto err;

	return 0;
 err:
	hisi_sec_release_qp(hisi_sec_qp_ctx);

	return ret;
}

static void hisi_sec_free_cipher_ctx(struct crypto_skcipher *tfm)
{
	struct hisi_sec_qp_ctx *hisi_sec_qp_ctx = crypto_skcipher_ctx(tfm);

	hisi_sec_release_qp(hisi_sec_qp_ctx);
}

static int sec_skcipher_setkey(struct crypto_skcipher *tfm,
			       const u8 *key, unsigned int keylen)
{
	struct hisi_sec_qp_ctx *hisi_sec_qp_ctx = crypto_skcipher_ctx(tfm);
	struct hisi_sec_sqe *sec_sqe = &hisi_sec_qp_ctx->sec_sqe;

	switch (keylen) {
	case AES_KEYSIZE_128:
		sec_sqe->type2.c_key_len = 0;
		break;
	case AES_KEYSIZE_192:
		sec_sqe->type2.c_key_len = 1;
		break;
	case AES_KEYSIZE_256:
		sec_sqe->type2.c_key_len = 2;
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

static int sec_skcipher_setkey_aes_ecb(struct crypto_skcipher *tfm,
				       const u8 *key, unsigned int keylen)
{
	struct hisi_sec_qp_ctx *hisi_sec_qp_ctx = crypto_skcipher_ctx(tfm);
	struct hisi_sec_sqe *sec_sqe = &hisi_sec_qp_ctx->sec_sqe;
	struct hisi_sec_buffer *buf = &hisi_sec_qp_ctx->buffer;

	memcpy(buf->c_key, key, keylen);
	sec_sqe->type2.c_mode = ECB;
	sec_sqe->type2.c_alg = AES;

	return sec_skcipher_setkey(tfm, key, keylen);
}

static int sec_skcipher_setkey_aes_cbc(struct crypto_skcipher *tfm,
				       const u8 *key, unsigned int keylen)
{
	struct hisi_sec_qp_ctx *hisi_sec_qp_ctx = crypto_skcipher_ctx(tfm);
	struct hisi_sec_sqe *sec_sqe = &hisi_sec_qp_ctx->sec_sqe;
	struct hisi_sec_buffer *buf = &hisi_sec_qp_ctx->buffer;

	memcpy(buf->c_key, key, keylen);
	sec_sqe->type2.c_mode = CBC;
	sec_sqe->type2.c_alg = AES;

	return sec_skcipher_setkey(tfm, key, keylen);
}

static int sec_skcipher_setkey_aes_ctr(struct crypto_skcipher *tfm,
				       const u8 *key, unsigned int keylen)
{
	struct hisi_sec_qp_ctx *hisi_sec_qp_ctx = crypto_skcipher_ctx(tfm);
	struct hisi_sec_sqe *sec_sqe = &hisi_sec_qp_ctx->sec_sqe;
	struct hisi_sec_buffer *buf = &hisi_sec_qp_ctx->buffer;

	memcpy(buf->c_key, key, keylen);

	sec_sqe->type2.c_mode = CTR;
	sec_sqe->type2.c_alg = AES;

	return sec_skcipher_setkey(tfm, key, keylen);
}

static int sec_skcipher_setkey_aes_xts(struct crypto_skcipher *tfm,
				       const u8 *key, unsigned int keylen)
{
	struct hisi_sec_qp_ctx *hisi_sec_qp_ctx = crypto_skcipher_ctx(tfm);
	struct hisi_sec_sqe *sec_sqe = &hisi_sec_qp_ctx->sec_sqe;
	struct hisi_sec_buffer *buf = &hisi_sec_qp_ctx->buffer;
	int ret = 0;

	ret = xts_verify_key(tfm, key, keylen);
	if (ret)
		return ret;

	memcpy(buf->c_key, key, keylen);

	sec_sqe->type2.c_mode = XTS;
	sec_sqe->type2.c_alg = AES;

	return sec_skcipher_setkey(tfm, key, keylen / 2);
}

static int sec_skcipher_setkey_sm4_xts(struct crypto_skcipher *tfm,
				       const u8 *key, unsigned int keylen)
{
	struct hisi_sec_qp_ctx *hisi_sec_qp_ctx = crypto_skcipher_ctx(tfm);
	struct hisi_sec_sqe *sec_sqe = &hisi_sec_qp_ctx->sec_sqe;
	struct hisi_sec_buffer *buf = &hisi_sec_qp_ctx->buffer;
	int ret = 0;

	ret = xts_verify_key(tfm, key, keylen);
	if (ret)
		return ret;

	memcpy(buf->c_key, key, keylen);

	sec_sqe->type2.c_mode = XTS;
	sec_sqe->type2.c_alg = SM4;

	return sec_skcipher_setkey(tfm, key, keylen / 2);
}

static int sec_sg_to_hw_sgl(struct device *sec_dev, struct scatterlist *sg_list,
			    struct sgl *sgl)
{
	int ret = 0;
	int i = 0;
	int sgl_pos = 0;
	int sge_pos = 0;
	int sg_num = sg_nents(sg_list);
	struct scatterlist *sg;

	// todo: return sg_num is too large error
	if (sg_num > SEC_MAX_SGL_NUM * SEC_MAX_SGE_NUM)
		return -1;

	// todo: return dma_mag_sg failed error
	if (dma_map_sg(sec_dev, sg_list, sg_num, DMA_BIDIRECTIONAL) == 0)
		return -1;

	sgl->entrySumInChain = sg_num;

	for_each_sg(sg_list, sg, sg_num, i) {
		sgl_pos = i / SEC_MAX_SGL_NUM;
		sge_pos = i % SEC_MAX_SGL_NUM;
		dbg("sgl_pos[%d] sge_pos[%d]\n", sgl_pos, sge_pos);
		sgl[sgl_pos].entrySumInSgl = sge_pos + 1;
		sgl[sgl_pos].entryNumInSgl = sge_pos + 1;
		sgl[sgl_pos].entry[sge_pos].buf = (u8 *) sg_dma_address(sg);
		sgl[sgl_pos].entry[sge_pos].len = sg_dma_len(sg);
	}

	return ret;
}

static int sec_skcipher_crypto(struct skcipher_request *skreq, bool encrypt)
{
	int ret = 0;
	struct crypto_skcipher *atfm = crypto_skcipher_reqtfm(skreq);
	struct hisi_sec_qp_ctx *hisi_sec_qp_ctx = crypto_skcipher_ctx(atfm);
	struct hisi_sec_buffer *buf = &hisi_sec_qp_ctx->buffer;
	struct hisi_sec_sqe *sec_sqe = &hisi_sec_qp_ctx->sec_sqe;
	struct hisi_qp *qp = hisi_sec_qp_ctx->qp;
	struct device *dev = &qp->qm->pdev->dev;

	dbg("[%s] encrypt : %d\n", __func__, encrypt);

	if (sec_sg_to_hw_sgl(dev, skreq->src, buf->c_in))
		return -EFAULT;

	if (sec_sg_to_hw_sgl(dev, skreq->dst, buf->c_out))
		return -EFAULT;

	sec_sqe->src_addr_type = 1;
	sec_sqe->dst_addr_type = 1;
	sec_sqe->type = 2;
	sec_sqe->scene = 1;
	sec_sqe->de = 1;

	if (encrypt == 1)
		sec_sqe->cipher = 1;
	else
		sec_sqe->cipher = 2;

	sec_sqe->type2.c_len = skreq->cryptlen;

	if (crypto_skcipher_ivsize(atfm))
		memcpy(buf->c_ivin, skreq->iv, crypto_skcipher_ivsize(atfm));

	dbg("Dump c_ivin:");

	ret = hisi_qp_send(qp, sec_sqe);
	if (ret < 0)
		return ret;

	ret = hisi_qp_wait(qp);
	if (ret < 0)
		return ret;

	if (sec_sqe->type2.c_mode == 0x4)
		crypto_inc(skreq->iv, 16);

	dump_sec_bd((uint32_t *) sec_sqe);

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
		  .cra_ctxsize = sizeof(struct hisi_sec_qp_ctx),
		  .cra_alignmask = 0,
		  .cra_module = THIS_MODULE,
		  },
	 .init = hisi_sec_alloc_cipher_ctx,
	 .exit = hisi_sec_free_cipher_ctx,
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
		      .cra_ctxsize = sizeof(struct hisi_sec_qp_ctx),
		      .cra_alignmask = 0,
		      .cra_module = THIS_MODULE,
		      },
	     .init = hisi_sec_alloc_cipher_ctx,
	     .exit = hisi_sec_free_cipher_ctx,
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
			  .cra_ctxsize = sizeof(struct hisi_sec_qp_ctx),
			  .cra_alignmask = 0,
			  .cra_module = THIS_MODULE,
			  },
		 .init = hisi_sec_alloc_cipher_ctx,
		 .exit = hisi_sec_free_cipher_ctx,
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
			      .cra_ctxsize = sizeof(struct hisi_sec_qp_ctx),
			      .cra_alignmask = 0,
			      .cra_module = THIS_MODULE,
			      },
		     .init = hisi_sec_alloc_cipher_ctx,
		     .exit = hisi_sec_free_cipher_ctx,
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
				  .cra_ctxsize = sizeof(struct hisi_sec_qp_ctx),
				  .cra_alignmask = 0,
				  .cra_module = THIS_MODULE,
				  },
			 .init = hisi_sec_alloc_cipher_ctx,
			 .exit = hisi_sec_free_cipher_ctx,
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
	int ret = 0;

	ret = crypto_register_skciphers(sec_algs, ARRAY_SIZE(sec_algs));
	if (ret)
		return ret;

	return ret;
}

void hisi_sec_unregister_from_crypto(void)
{
	crypto_unregister_skciphers(sec_algs, ARRAY_SIZE(sec_algs));
}
