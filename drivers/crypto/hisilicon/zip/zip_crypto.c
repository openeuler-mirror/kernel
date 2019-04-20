// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2018 Hisilicon Limited. */
#include <linux/crypto.h>
#include <linux/dma-mapping.h>
#include "zip.h"

#define HZIP_INPUT_BUFFER_SIZE			SZ_4M
#define HZIP_OUTPUT_BUFFER_SIZE			SZ_4M

#define HZIP_ALG_TYPE_ZLIB			0x02
#define HZIP_ALG_TYPE_GZIP			0x03

#define GZIP_HEAD_FHCRC_BIT			BIT(1)
#define GZIP_HEAD_FEXTRA_BIT			BIT(2)
#define GZIP_HEAD_FNAME_BIT			BIT(3)
#define GZIP_HEAD_FCOMMENT_BIT			BIT(4)

const u8 zlib_head[2] = {0x78, 0x9c};
const u8 gzip_head[10] = {0x1f, 0x8b, 0x08, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x03};

#define COMP_NAME_TO_TYPE(alg_name)					\
	(!strcmp((alg_name), "zlib-deflate") ? HZIP_ALG_TYPE_ZLIB :	\
	 !strcmp((alg_name), "gzip") ? HZIP_ALG_TYPE_GZIP : 0)		\

#define TO_HEAD_SIZE(req_type)						\
	(((req_type) == HZIP_ALG_TYPE_ZLIB) ? sizeof(zlib_head) :	\
	 ((req_type) == HZIP_ALG_TYPE_GZIP) ? sizeof(gzip_head) : 0)	\

#define TO_HEAD(req_type)						\
	(((req_type) == HZIP_ALG_TYPE_ZLIB) ? zlib_head :		\
	 ((req_type) == HZIP_ALG_TYPE_GZIP) ? gzip_head : 0)		\

struct hisi_zip_buffer {
	u8 *input;
	dma_addr_t input_dma;
	u8 *output;
	dma_addr_t output_dma;
};

struct hisi_zip_qp_ctx {
	struct hisi_zip_buffer buffer;
	struct hisi_qp *qp;
	struct hisi_zip_sqe zip_sqe;
};

struct hisi_zip_ctx {
#define QPC_COMP	0
#define QPC_DECOMP	1
	struct hisi_zip_qp_ctx qp_ctx[2];
};

static void hisi_zip_fill_sqe(struct hisi_zip_sqe *sqe,
			      struct hisi_zip_qp_ctx *qp_ctx, u32 len)
{
	struct hisi_zip_buffer *buffer = &qp_ctx->buffer;

	memset(sqe, 0, sizeof(struct hisi_zip_sqe));

	sqe->input_data_length = len;
	sqe->dw9 = qp_ctx->qp->req_type;
	sqe->dest_avail_out = HZIP_OUTPUT_BUFFER_SIZE;
	sqe->source_addr_l = lower_32_bits(buffer->input_dma);
	sqe->source_addr_h = upper_32_bits(buffer->input_dma);
	sqe->dest_addr_l = lower_32_bits(buffer->output_dma);
	sqe->dest_addr_h = upper_32_bits(buffer->output_dma);
}

/* let's allocate one buffer now, may have problem in async case */
static int hisi_zip_alloc_qp_buffer(struct hisi_zip_qp_ctx *hisi_zip_qp_ctx)
{
	struct hisi_zip_buffer *buffer = &hisi_zip_qp_ctx->buffer;
	struct hisi_qp *qp = hisi_zip_qp_ctx->qp;
	struct device *dev = &qp->qm->pdev->dev;
	int ret;

	buffer->input = dma_alloc_coherent(dev, HZIP_INPUT_BUFFER_SIZE,
					   &buffer->input_dma, GFP_KERNEL);
	if (!buffer->input)
		return -ENOMEM;

	buffer->output = dma_alloc_coherent(dev, HZIP_OUTPUT_BUFFER_SIZE,
					    &buffer->output_dma, GFP_KERNEL);
	if (!buffer->output) {
		ret = -ENOMEM;
		goto err_alloc_output_buffer;
	}

	return 0;

err_alloc_output_buffer:
	dma_free_coherent(dev, HZIP_INPUT_BUFFER_SIZE, buffer->input,
			  buffer->input_dma);
	return ret;
}

static void hisi_zip_free_qp_buffer(struct hisi_zip_qp_ctx *hisi_zip_qp_ctx)
{
	struct hisi_zip_buffer *buffer = &hisi_zip_qp_ctx->buffer;
	struct hisi_qp *qp = hisi_zip_qp_ctx->qp;
	struct device *dev = &qp->qm->pdev->dev;

	dma_free_coherent(dev, HZIP_INPUT_BUFFER_SIZE, buffer->input,
			  buffer->input_dma);
	dma_free_coherent(dev, HZIP_OUTPUT_BUFFER_SIZE, buffer->output,
			  buffer->output_dma);
}

static int hisi_zip_create_qp(struct hisi_qm *qm, struct hisi_zip_qp_ctx *ctx,
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

	ret = hisi_zip_alloc_qp_buffer(ctx);
	if (ret)
		goto err_release_qp;

	ret = hisi_qm_start_qp(qp, 0);
	if (ret < 0)
		goto err_free_qp_buffer;

	return 0;

err_free_qp_buffer:
	hisi_zip_free_qp_buffer(ctx);
err_release_qp:
	hisi_qm_release_qp(qp);
	return ret;
}

static void hisi_zip_release_qp(struct hisi_zip_qp_ctx *ctx)
{
	hisi_qm_stop_qp(ctx->qp);
	hisi_zip_free_qp_buffer(ctx);
	hisi_qm_release_qp(ctx->qp);
}

static int hisi_zip_alloc_comp_ctx(struct crypto_tfm *tfm)
{
	struct hisi_zip_ctx *hisi_zip_ctx = crypto_tfm_ctx(tfm);
	const char *alg_name = crypto_tfm_alg_name(tfm);
	struct hisi_zip *hisi_zip;
	struct hisi_qm *qm;
	int ret, i, j;

	u8 req_type = COMP_NAME_TO_TYPE(alg_name);

	/* find the proper zip device */
	hisi_zip = find_zip_device(cpu_to_node(smp_processor_id()));
	if (!hisi_zip) {
		pr_err("Failed to find a proper ZIP device!\n");
		return -ENODEV;
	}
	qm = &hisi_zip->qm;

	for (i = 0; i < 2; i++) {
	/* it is just happen that 0 is compress, 1 is decompress on alg_type */
		ret = hisi_zip_create_qp(qm, &hisi_zip_ctx->qp_ctx[i], i,
					 req_type);
		if (ret)
			goto err;
	}

	return 0;
err:
	for (j = i - 1; j >= 0; j--)
		hisi_zip_release_qp(&hisi_zip_ctx->qp_ctx[j]);

	return ret;
}

static void hisi_zip_free_comp_ctx(struct crypto_tfm *tfm)
{
	struct hisi_zip_ctx *hisi_zip_ctx = crypto_tfm_ctx(tfm);
	int i;

	/* release the qp */
	for (i = 1; i >= 0; i--)
		hisi_zip_release_qp(&hisi_zip_ctx->qp_ctx[i]);
}

static int hisi_zip_copy_data_to_buffer(struct hisi_zip_qp_ctx *qp_ctx,
					const u8 *src, unsigned int slen)
{
	struct hisi_zip_buffer *buffer = &qp_ctx->buffer;

	if (slen > HZIP_INPUT_BUFFER_SIZE)
		return -ENOSPC;

	memcpy(buffer->input, src, slen);

	return 0;
}

static struct hisi_zip_sqe *hisi_zip_get_writeback_sqe(struct hisi_qp *qp)
{
	struct hisi_qp_status *qp_status = &qp->qp_status;
	struct hisi_zip_sqe *sq_base = qp->sqe;
	u16 sq_head = qp_status->sq_head;

	return sq_base + sq_head;
}

static void hisi_zip_add_comp_head(struct hisi_qp *qp, u8 *dst)
{
	u8 head_size = TO_HEAD_SIZE(qp->req_type);
	const u8 *head = TO_HEAD(qp->req_type);

	memcpy(dst, head, head_size);
}

static void hisi_zip_copy_data_from_buffer(struct hisi_zip_qp_ctx *qp_ctx,
					   u8 *dst)
{
	struct hisi_zip_buffer *buffer = &qp_ctx->buffer;
	struct hisi_qp *qp = qp_ctx->qp;
	struct hisi_zip_sqe *zip_sqe = hisi_zip_get_writeback_sqe(qp);
	u16 sq_head;

	memcpy(dst, buffer->output, zip_sqe->produced);

	sq_head = qp->qp_status.sq_head;
	if (sq_head == QM_Q_DEPTH - 1)
		qp->qp_status.sq_head = 0;
	else
		qp->qp_status.sq_head++;

	if (unlikely(test_bit(QP_FULL, &qp->qp_status.flags)))
		clear_bit(QP_FULL, &qp->qp_status.flags);
}

static int hisi_zip_compress_data_output(struct hisi_zip_qp_ctx *qp_ctx,
					 u8 *dst, unsigned int *dlen)
{
	struct hisi_qp *qp = qp_ctx->qp;
	struct hisi_zip_sqe *zip_sqe = hisi_zip_get_writeback_sqe(qp);
	u32 status = zip_sqe->dw3 & 0xff;
	u8 head_size = TO_HEAD_SIZE(qp->req_type);

	if (status != 0 && status != HZIP_NC_ERR) {
		dev_err(&qp->qm->pdev->dev, "Compression failed in qp%d!\n",
			qp->qp_id);
		return status;
	}

	if (zip_sqe->produced + head_size > *dlen)
		return -ENOMEM;

	hisi_zip_add_comp_head(qp, dst);
	hisi_zip_copy_data_from_buffer(qp_ctx, dst + head_size);

	*dlen = zip_sqe->produced + head_size;

	return 0;
}

static int hisi_zip_compress(struct crypto_tfm *tfm, const u8 *src,
			     unsigned int slen, u8 *dst, unsigned int *dlen)
{
	struct hisi_zip_ctx *hisi_zip_ctx = crypto_tfm_ctx(tfm);
	struct hisi_zip_qp_ctx *qp_ctx = &hisi_zip_ctx->qp_ctx[QPC_COMP];
	struct hisi_qp *qp = qp_ctx->qp;
	struct hisi_zip_sqe *zip_sqe = &qp_ctx->zip_sqe;
	int ret;

	if (!src || !slen || !dst || !dlen)
		return -ENOMEM;

	ret = hisi_zip_copy_data_to_buffer(qp_ctx, src, slen);
	if (ret < 0)
		return ret;

	hisi_zip_fill_sqe(zip_sqe, qp_ctx, slen);

	/* send command to start the compress job */
	ret = hisi_qp_send(qp, zip_sqe);
	if (ret < 0)
		return ret;

	ret = hisi_qp_wait(qp);
	if (ret < 0)
		return ret;

	return hisi_zip_compress_data_output(qp_ctx, dst, dlen);
}

static u16 get_extra_field_size(const u8 *start)
{
	return *((u16 *)start) + 2;
}

static u32 get_name_field_size(const u8 *start)
{
	return strlen(start) + 1;
}

static u32 get_comment_field_size(const u8 *start)
{
	return strlen(start) + 1;
}

static u32 get_gzip_head_size(const u8 *src)
{
	u8 head_flg = *(src + 3);
	u32 size = 10;

	if (head_flg & GZIP_HEAD_FEXTRA_BIT)
		size += get_extra_field_size(src + size);
	if (head_flg & GZIP_HEAD_FNAME_BIT)
		size += get_name_field_size(src + size);
	if (head_flg & GZIP_HEAD_FCOMMENT_BIT)
		size += get_comment_field_size(src + size);
	if (head_flg & GZIP_HEAD_FHCRC_BIT)
		size += 2;

	return size;
}

static int hisi_zip_get_comp_head_size(struct hisi_qp *qp, const u8 *src)
{
	switch (qp->req_type) {
	case HZIP_ALG_TYPE_ZLIB:
		return TO_HEAD_SIZE(HZIP_ALG_TYPE_ZLIB);
	case HZIP_ALG_TYPE_GZIP:
		return get_gzip_head_size(src);
	default:
		dev_err(&qp->qm->pdev->dev, "request type does not support!");
		return -EINVAL;
	}
}

static int hisi_zip_decompress_data_output(struct hisi_zip_qp_ctx *qp_ctx,
					   u8 *dst, unsigned int *dlen)
{
	struct hisi_qp *qp = qp_ctx->qp;
	struct hisi_zip_sqe *zip_sqe = hisi_zip_get_writeback_sqe(qp);
	u32 status = zip_sqe->dw3 & 0xff;

	if (status != 0) {
		dev_err(&qp->qm->pdev->dev, "Decompression fail in qp%u!\n",
			qp->qp_id);
		return status;
	}

	if (zip_sqe->produced > *dlen)
		return -ENOMEM;

	hisi_zip_copy_data_from_buffer(qp_ctx, dst);

	*dlen = zip_sqe->produced;

	return 0;
}

static int hisi_zip_decompress(struct crypto_tfm *tfm, const u8 *src,
			       unsigned int slen, u8 *dst, unsigned int *dlen)
{
	struct hisi_zip_ctx *hisi_zip_ctx = crypto_tfm_ctx(tfm);
	struct hisi_zip_qp_ctx *qp_ctx = &hisi_zip_ctx->qp_ctx[QPC_DECOMP];
	struct hisi_qp *qp = qp_ctx->qp;
	struct hisi_zip_sqe *zip_sqe = &qp_ctx->zip_sqe;
	u16 size;
	int ret;

	if (!src || !slen || !dst || !dlen)
		return -ENOMEM;

	size = hisi_zip_get_comp_head_size(qp, src);

	ret = hisi_zip_copy_data_to_buffer(qp_ctx, src + size, slen - size);
	if (ret < 0)
		return ret;

	hisi_zip_fill_sqe(zip_sqe, qp_ctx, slen - size);

	/* send command to start the decompress job */
	ret = hisi_qp_send(qp, zip_sqe);
	if (ret < 0)
		return ret;

	ret = hisi_qp_wait(qp);
	if (ret < 0)
		return ret;

	return hisi_zip_decompress_data_output(qp_ctx, dst, dlen);
}

static struct crypto_alg hisi_zip_zlib = {
	.cra_name		= "zlib-deflate",
	.cra_flags		= CRYPTO_ALG_TYPE_COMPRESS,
	.cra_ctxsize		= sizeof(struct hisi_zip_ctx),
	.cra_priority           = 300,
	.cra_module		= THIS_MODULE,
	.cra_init		= hisi_zip_alloc_comp_ctx,
	.cra_exit		= hisi_zip_free_comp_ctx,
	.cra_u			= {
		.compress = {
			.coa_compress	= hisi_zip_compress,
			.coa_decompress	= hisi_zip_decompress
		}
	}
};

static struct crypto_alg hisi_zip_gzip = {
	.cra_name		= "gzip",
	.cra_flags		= CRYPTO_ALG_TYPE_COMPRESS,
	.cra_ctxsize		= sizeof(struct hisi_zip_ctx),
	.cra_priority           = 300,
	.cra_module		= THIS_MODULE,
	.cra_init		= hisi_zip_alloc_comp_ctx,
	.cra_exit		= hisi_zip_free_comp_ctx,
	.cra_u			= {
		.compress = {
			.coa_compress	= hisi_zip_compress,
			.coa_decompress	= hisi_zip_decompress
		}
	}
};

int hisi_zip_register_to_crypto(void)
{
	int ret;

	ret = crypto_register_alg(&hisi_zip_zlib);
	if (ret < 0) {
		pr_err("Zlib algorithm registration failed\n");
		return ret;
	}

	ret = crypto_register_alg(&hisi_zip_gzip);
	if (ret < 0) {
		pr_err("Gzip algorithm registration failed\n");
		goto err_unregister_zlib;
	}

	return 0;

err_unregister_zlib:
	crypto_unregister_alg(&hisi_zip_zlib);

	return ret;
}

void hisi_zip_unregister_from_crypto(void)
{
	crypto_unregister_alg(&hisi_zip_gzip);
	crypto_unregister_alg(&hisi_zip_zlib);
}
