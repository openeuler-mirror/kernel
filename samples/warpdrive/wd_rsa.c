// SPDX-License-Identifier: GPL-2.0+
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/mman.h>

#include "wd.h"
#include "wd_rsa.h"
#include "wd_util.h"


struct wd_rsa_udata {
	void *tag;
	struct wd_rsa_op_data *opdata;
};

struct wd_rsa_ctx {
	struct wd_rsa_msg cache_msg;
	struct wd_queue *q;
	char  alg[32];
	wd_rsa_cb cb;
	__u32 key_size;
	__u32 is_crt;
	struct wd_rsa_pubkey pubkey;
	union wd_rsa_prikey prikey;
};


/* Before initiate this context, we should get a queue from WD */
void *wd_create_rsa_ctx(struct wd_queue *q, struct wd_rsa_ctx_setup *setup)
{
	struct wd_rsa_ctx *ctx;
	__u32 prikey_size, pubkey_size;

	if (!q || !setup) {
		WD_ERR("%s(): input param err!\n", __func__);
		return NULL;
	}
	if (strncmp(setup->alg, "rsa", 3) || strncmp(q->capa.alg, "rsa", 3)) {
		WD_ERR("%s(): algorithm mismatching!\n", __func__);
		return NULL;
	}
	if (setup->is_crt)
		prikey_size = 5 * (setup->key_bits >> 4);
	else
		prikey_size = 2 * (setup->key_bits >> 3);
	pubkey_size = 2 * (setup->key_bits >> 3);
	ctx = malloc(sizeof(*ctx) + pubkey_size + prikey_size);
	if (!ctx) {
		WD_ERR("Alloc ctx memory fail!\n");
		return ctx;
	}
	memset(ctx, 0, sizeof(*ctx) + pubkey_size + prikey_size);
	ctx->q = q;
	strncpy(ctx->alg, q->capa.alg, strlen(q->capa.alg));
	if (setup->is_crt)
		ctx->cache_msg.prikey_type = WD_RSA_PRIKEY2;
	else
		ctx->cache_msg.prikey_type = WD_RSA_PRIKEY1;
	ctx->cache_msg.aflags = setup->aflags;
	ctx->cache_msg.pubkey = (__u64)&ctx->pubkey;
	ctx->pubkey.e = (__u8 *)ctx + sizeof(*ctx);
	ctx->pubkey.n = ctx->pubkey.e + (setup->key_bits >> 3);
	ctx->cache_msg.prikey = (__u64)&ctx->prikey;
	if (setup->is_crt) {
		ctx->prikey.pkey2.dq = ctx->pubkey.n + (setup->key_bits >> 3);
		ctx->prikey.pkey2.dp = ctx->prikey.pkey2.dq +
				       (setup->key_bits >> 4);
		ctx->prikey.pkey2.q = ctx->prikey.pkey2.dp +
				      (setup->key_bits >> 4);
		ctx->prikey.pkey2.p = ctx->prikey.pkey2.q +
				      (setup->key_bits >> 4);
		ctx->prikey.pkey2.qinv = ctx->prikey.pkey2.p +
					 (setup->key_bits >> 4);
	} else {
		ctx->prikey.pkey1.d = ctx->pubkey.n + (setup->key_bits >> 3);
		ctx->prikey.pkey1.n = ctx->prikey.pkey1.d +
				      (setup->key_bits >> 3);
	}
	ctx->cache_msg.nbytes = setup->key_bits >> 3;
	ctx->cache_msg.alg = ctx->alg;
	ctx->cb = setup->cb;
	ctx->is_crt = setup->is_crt;
	ctx->key_size = setup->key_bits >> 3;
	q->ctx = ctx;

	return ctx;
}

int wd_rsa_is_crt(void *ctx)
{
	if (ctx)
		return ((struct wd_rsa_ctx *)ctx)->is_crt;
	else
		return 0;
}

int wd_rsa_key_bits(void *ctx)
{
	if (ctx)
		return	(((struct wd_rsa_ctx *)ctx)->key_size) << 3;
	else
		return 0;
}

int wd_set_rsa_pubkey(void *ctx, struct wd_rsa_pubkey *pubkey)
{
	void *p;

	if (ctx && pubkey && pubkey->e && pubkey->n) {
		p = (void *)((struct wd_rsa_ctx *)ctx)->cache_msg.pubkey;
		memcpy(p,  (void *)pubkey, sizeof(struct wd_rsa_pubkey));
		return 0;
	}

	return -1;
}

void wd_get_rsa_pubkey(void *ctx, struct wd_rsa_pubkey **pubkey)
{
	if (ctx && pubkey)
		*pubkey = (void *)((struct wd_rsa_ctx *)ctx)->cache_msg.pubkey;
}

int wd_set_rsa_prikey(void *ctx, union wd_rsa_prikey *prikey)
{
	void *p;

	if (!ctx && !prikey)
		return -1;

	if (wd_rsa_is_crt(ctx)) {
		if (!(prikey->pkey2.dp) || !(prikey->pkey2.dq) ||
		    !(prikey->pkey2.p) || !(prikey->pkey2.q) ||
		    !(prikey->pkey2.qinv))
			return -1;

	} else {
		if (!(prikey->pkey1.n) || !(prikey->pkey1.d))
			return -1;

	}
	p = (void *)((struct wd_rsa_ctx *)ctx)->cache_msg.prikey;
	memcpy(p, (void *)prikey, sizeof(union wd_rsa_prikey));

	return 0;
}

void wd_get_rsa_prikey(void *ctx, union wd_rsa_prikey **prikey)
{
	if (ctx && prikey)
		*prikey = (void *)((struct wd_rsa_ctx *)ctx)->cache_msg.prikey;
}

int wd_do_rsa(void *ctx, struct wd_rsa_op_data *opdata)
{
	struct wd_rsa_ctx *ctxt = ctx;
	struct wd_rsa_msg *resp;
	int ret;

	if (opdata->op_type == WD_RSA_SIGN ||
	    opdata->op_type == WD_RSA_VERIFY) {
		ctxt->cache_msg.in = (__u64)opdata->in;
		ctxt->cache_msg.inbytes = (__u16)opdata->in_bytes;
		ctxt->cache_msg.out = (__u64)opdata->out;
	}
	ctxt->cache_msg.op_type = (__u8)opdata->op_type;
	ctxt->cache_msg.status = -1;

	ret = wd_send(ctxt->q, &ctxt->cache_msg);
	if (ret) {
		WD_ERR("%s():wd_send err!\n", __func__);
		return ret;
	}

recv_again:
	ret = wd_recv(ctxt->q, (void **)&resp);
	if (!ret) {
		usleep(1);
		goto recv_again;
	} else if (ret < 0) {
		return ret;
	}
	opdata->out = (void *)resp->out;
	opdata->out_bytes = resp->outbytes;

	return 0;
}

int wd_rsa_op(void *ctx, struct wd_rsa_op_data *opdata, void *tag)
{
	struct wd_rsa_ctx *context = ctx;
	struct wd_rsa_msg *msg = &context->cache_msg;
	int ret;
	struct wd_rsa_udata *udata;

	if (!ctx || !opdata) {
		WD_ERR("param err!\n");
		return -1;
	}
	msg->status = 0;

	/* malloc now, as need performance we should rewrite mem management */
	udata = malloc(sizeof(*udata));
	if (!udata) {
		WD_ERR("malloc udata fail!\n");
		return -1;
	}
	udata->tag = tag;
	udata->opdata = opdata;
	if (opdata->op_type == WD_RSA_SIGN ||
	    opdata->op_type == WD_RSA_VERIFY) {
		msg->in = (__u64)opdata->in;
		msg->inbytes = (__u16)opdata->in_bytes;
		msg->out = (__u64)opdata->out;
	}
	//msg->pubkey = (__u64)opdata->pubkey;
	//msg->prikey = (__u64)opdata->prikey;
	msg->udata = (__u64)udata;
	msg->op_type = (__u8)opdata->op_type;
	ret = wd_send(context->q, (void *)msg);
	if (ret < 0) {
		WD_ERR("wd send request fail!\n");
		return -1;
	}

	return 0;
}

int wd_rsa_poll(struct wd_queue *q, int num)
{
	int ret, count = 0;
	struct wd_rsa_msg *resp;
	struct wd_rsa_ctx *ctx = q->ctx;
	unsigned int status;
	struct wd_rsa_udata *udata;

	do {
		ret = wd_recv(q, (void **)&resp);
		if (ret < 1)
			break;
		count++;
		udata = (void *)resp->udata;
		udata->opdata->out_bytes = (__u32)resp->outbytes;
		status = resp->status;
		ctx->cb(udata->tag, status, udata->opdata);
		free(udata);
	} while (--num);

	return count;
}

void wd_del_rsa_ctx(void *ctx)
{
	if (ctx)
		free(ctx);
}
