// SPDX-License-Identifier: GPL-2.0+
#include <linux/crypto.h>
#include <linux/dma-mapping.h>
#include <linux/pci.h>
#include <linux/topology.h>
#include "../qm.h"
#include "zip.h"

#define INPUT_BUFFER_SIZE	(64 * 1024)
#define OUTPUT_BUFFER_SIZE	(64 * 1024)

#define COMP_NAME_TO_TYPE(alg_name)			\
	(!strcmp((alg_name), "zlib-deflate") ? 0x02 :	\
	 !strcmp((alg_name), "gzip") ? 0x03 : 0)	\

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

static struct hisi_zip *find_zip_device(int node)
{
	struct hisi_zip *hisi_zip, *ret = NULL;
	struct device *dev;
	int min_distance = 100;
	int dev_node = 0;

	list_for_each_entry(hisi_zip, &hisi_zip_list, list) {
		dev = &hisi_zip->qm.pdev->dev;
#ifdef CONFIG_NUMA
		dev_node = dev->numa_node;
#endif
		if (node_distance(dev_node, node) < min_distance) {
			ret = hisi_zip;
			min_distance = node_distance(dev_node, node);
		}
	}

	return ret;
}

static void hisi_zip_qp_event_notifier(struct hisi_qp *qp)
{
	complete(&qp->completion);
}

static int hisi_zip_fill_sqe_v1(void *sqe, void *q_parm, u32 len)
{
	struct hisi_zip_sqe *zip_sqe = (struct hisi_zip_sqe *)sqe;
	struct hisi_zip_qp_ctx *qp_ctx = (struct hisi_zip_qp_ctx *)q_parm;
	struct hisi_zip_buffer *buffer = &qp_ctx->buffer;

	memset(zip_sqe, 0, sizeof(struct hisi_zip_sqe));

	zip_sqe->input_data_length = len;
	zip_sqe->dw9 = qp_ctx->qp->req_type;
	zip_sqe->dest_avail_out = OUTPUT_BUFFER_SIZE;
	zip_sqe->source_addr_l = lower_32_bits(buffer->input_dma);
	zip_sqe->source_addr_h = upper_32_bits(buffer->input_dma);
	zip_sqe->dest_addr_l = lower_32_bits(buffer->output_dma);
	zip_sqe->dest_addr_h = upper_32_bits(buffer->output_dma);

	return 0;
}

/* let's allocate one buffer now, may have problem in async case */
static int hisi_zip_alloc_qp_buffer(struct hisi_zip_qp_ctx *hisi_zip_qp_ctx)
{
	struct hisi_zip_buffer *buffer = &hisi_zip_qp_ctx->buffer;
	struct hisi_qp *qp = hisi_zip_qp_ctx->qp;
	struct device *dev = &qp->qm->pdev->dev;
	int ret;

	buffer->input = dma_alloc_coherent(dev, INPUT_BUFFER_SIZE,
					   &buffer->input_dma, GFP_KERNEL);
	if (!buffer->input)
		return -ENOMEM;

	buffer->output = dma_alloc_coherent(dev, OUTPUT_BUFFER_SIZE,
					    &buffer->output_dma, GFP_KERNEL);
	if (!buffer->output) {
		ret = -ENOMEM;
		goto err_alloc_output_buffer;
	}

	return 0;

err_alloc_output_buffer:
	dma_free_coherent(dev, INPUT_BUFFER_SIZE, buffer->input,
			  buffer->input_dma);
	return ret;
}

static void hisi_zip_free_qp_buffer(struct hisi_zip_qp_ctx *hisi_zip_qp_ctx)
{
	struct hisi_zip_buffer *buffer = &hisi_zip_qp_ctx->buffer;
	struct hisi_qp *qp = hisi_zip_qp_ctx->qp;
	struct device *dev = &qp->qm->pdev->dev;

	dma_free_coherent(dev, INPUT_BUFFER_SIZE, buffer->input,
			  buffer->input_dma);
	dma_free_coherent(dev, OUTPUT_BUFFER_SIZE, buffer->output,
			  buffer->output_dma);
}

static int hisi_zip_create_qp(struct qm_info *qm, struct hisi_zip_qp_ctx *ctx,
			      int alg_type, int req_type)
{
	struct hisi_qp *qp;
	int ret;

	qp = hisi_qm_create_qp(qm, alg_type);

	if (IS_ERR(qp))
		return PTR_ERR(qp);

	qp->event_cb = hisi_zip_qp_event_notifier;
	qp->req_type = req_type;

	qp->qp_ctx = ctx;
	ctx->qp = qp;

	ret = hisi_zip_alloc_qp_buffer(ctx);
	if (ret)
		goto err_with_qp;

	ret = hisi_qm_start_qp(qp, 0);
	if (ret < 0)
		goto err_with_qp_buffer;

	return 0;
err_with_qp_buffer:
	hisi_zip_free_qp_buffer(ctx);
err_with_qp:
	hisi_qm_release_qp(qp);
	return ret;
}

static void hisi_zip_release_qp(struct hisi_zip_qp_ctx *ctx)
{
	hisi_qm_release_qp(ctx->qp);
	hisi_zip_free_qp_buffer(ctx);
}

static int hisi_zip_alloc_comp_ctx(struct crypto_tfm *tfm)
{
	struct hisi_zip_ctx *hisi_zip_ctx = crypto_tfm_ctx(tfm);
	const char *alg_name = crypto_tfm_alg_name(tfm);
	struct hisi_zip *hisi_zip;
	struct qm_info *qm;
	int ret, i, j;

	u8 req_type = COMP_NAME_TO_TYPE(alg_name);

	/* find the proper zip device */
	hisi_zip = find_zip_device(cpu_to_node(smp_processor_id()));
	if (!hisi_zip) {
		pr_err("Can not find proper ZIP device!\n");
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
	for (j = i-1; j >= 0; j--)
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

	if (slen > INPUT_BUFFER_SIZE)
		return -EINVAL;

	memcpy(buffer->input, src, slen);

	return 0;
}

static struct hisi_zip_sqe *hisi_zip_get_writeback_sqe(struct hisi_qp *qp)
{
	struct hisi_acc_qp_status *qp_status = &qp->qp_status;
	struct hisi_zip_sqe *sq_base = QP_SQE_ADDR(qp);
	u16 sq_head = qp_status->sq_head;

	return sq_base + sq_head;
}

static int hisi_zip_copy_data_from_buffer(struct hisi_zip_qp_ctx *qp_ctx,
					  u8 *dst, unsigned int *dlen)
{
	struct hisi_zip_buffer *buffer = &qp_ctx->buffer;
	struct hisi_qp *qp = qp_ctx->qp;
	struct hisi_zip_sqe *zip_sqe = hisi_zip_get_writeback_sqe(qp);
	u32 status = zip_sqe->dw3 & 0xff;
	u16 sq_head;

	if (status != 0) {
		pr_err("hisi zip: %s fail!\n", (qp->alg_type == 0) ?
		       "compression" : "decompression");
		return status;
	}

	if (zip_sqe->produced > OUTPUT_BUFFER_SIZE)
		return -ENOMEM;

	memcpy(dst, buffer->output, zip_sqe->produced);
	*dlen = zip_sqe->produced;

	sq_head = qp->qp_status.sq_head;
	if (sq_head == QM_Q_DEPTH - 1)
		qp->qp_status.sq_head = 0;
	else
		qp->qp_status.sq_head++;

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

	ret = hisi_zip_copy_data_to_buffer(qp_ctx, src, slen);
	if (ret < 0)
		return ret;

	hisi_zip_fill_sqe_v1(zip_sqe, qp_ctx, slen);

	/* send command to start the compress job */
	hisi_qp_send(qp, zip_sqe);

	return hisi_zip_copy_data_from_buffer(qp_ctx, dst, dlen);
}

static int hisi_zip_decompress(struct crypto_tfm *tfm, const u8 *src,
			       unsigned int slen, u8 *dst, unsigned int *dlen)
{
	struct hisi_zip_ctx *hisi_zip_ctx = crypto_tfm_ctx(tfm);
	struct hisi_zip_qp_ctx *qp_ctx = &hisi_zip_ctx->qp_ctx[QPC_DECOMP];
	struct hisi_qp *qp = qp_ctx->qp;
	struct hisi_zip_sqe *zip_sqe = &qp_ctx->zip_sqe;
	int ret;

	ret = hisi_zip_copy_data_to_buffer(qp_ctx, src, slen);
	if (ret < 0)
		return ret;

	hisi_zip_fill_sqe_v1(zip_sqe, qp_ctx, slen);

	/* send command to start the decompress job */
	hisi_qp_send(qp, zip_sqe);

	return hisi_zip_copy_data_from_buffer(qp_ctx, dst, dlen);
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
	crypto_unregister_alg(&hisi_zip_zlib);
	crypto_unregister_alg(&hisi_zip_gzip);
}
