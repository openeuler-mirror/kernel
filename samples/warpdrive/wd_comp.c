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
#include "wd_comp.h"
#include "wd_util.h"


struct wd_comp_udata {
	void *tag;
	struct wd_comp_opdata *opdata;
};

struct wd_comp_ctx {
	struct wd_comp_msg cache_msg;
	struct wd_queue *q;
	wd_comp_cb cb;
	char  alg[32];
};


/* Before initiate this context, we should get a queue from WD */
void *wd_create_comp_ctx(struct wd_queue *q, struct wd_comp_ctx_setup *setup)
{
	struct wd_comp_ctx *ctx;

	if (!q || !setup) {
		WD_ERR("%s(): input param err!\n", __func__);
		return NULL;
	}
	ctx = malloc(sizeof(*ctx));
	if (!ctx) {
		WD_ERR("Alloc ctx memory fail!\n");
		return ctx;
	}
	memset(ctx, 0, sizeof(*ctx));
	ctx->q = q;
	strncpy(ctx->alg, q->capa.alg, strlen(q->capa.alg));
	ctx->cache_msg.aflags = setup->aflags;
	ctx->cache_msg.comp_lv = setup->comp_lv;
	ctx->cache_msg.humm_type = setup->humm_type;
	ctx->cache_msg.win_size = setup->win_size;
	ctx->cache_msg.file_type = setup->file_type;
	ctx->cache_msg.alg = ctx->alg;
	ctx->cb = setup->cb;
	q->ctx = ctx;

	return ctx;
}

int wd_do_comp(void *ctx, struct wd_comp_opdata *opdata)
{
	struct wd_comp_ctx *ctxt = ctx;
	struct wd_comp_msg *resp;
	int ret;

	if (!ctx || !opdata) {
		WD_ERR("%s(): input param err!\n", __func__);
		return -1;
	}
	ctxt->cache_msg.cflags = *(opdata->cflush);
	ctxt->cache_msg.src = (__u64)opdata->in;
	ctxt->cache_msg.dst = (__u64)opdata->out;
	ctxt->cache_msg.in_bytes = (__u32)opdata->in_bytes;

	ret = wd_send(ctxt->q, &ctxt->cache_msg);
	if (ret) {
		WD_ERR("%s():wd_send err!\n", __func__);
		return ret;
	}
	ret = wd_recv_sync(ctxt->q, (void **)&resp, 0);
	if (ret != 1) {
		WD_ERR("%s():wd_recv_sync err!ret=%d\n", __func__, ret);
		return ret;
	}

	*(opdata->out_bytes) = resp->out_bytes;
	*(opdata->comsumed) = resp->in_coms;
	*(opdata->cflush) = resp->cflags;

	return 0;
}

int wd_comp_op(void *ctx, struct wd_comp_opdata *opdata, void *tag)
{
	struct wd_comp_ctx *context = ctx;
	struct wd_comp_msg *msg = &context->cache_msg;
	int ret;
	struct wd_comp_udata *udata;

	if (!ctx || !opdata) {
		WD_ERR("%s(): input param err!\n", __func__);
		return -1;
	}

	msg->cflags = *(opdata->cflush);
	msg->src = (__u64)opdata->in;
	msg->dst = (__u64)opdata->out;
	msg->in_bytes = (__u32)opdata->in_bytes;

	/* malloc now, as need performance we should rewrite mem management */
	udata = malloc(sizeof(*udata));
	if (!udata) {
		WD_ERR("malloc udata fail!\n");
		return -1;
	}
	udata->tag = tag;
	udata->opdata = opdata;

	msg->udata = (__u64)udata;
	ret = wd_send(context->q, (void *)msg);
	if (ret < 0) {
		WD_ERR("wd send request fail!\n");
		return -1;
	}

	return 0;
}

int wd_comp_poll(struct wd_queue *q, int num)
{
	int ret, count = 0, status = 0;
	struct wd_comp_msg *resp;
	struct wd_comp_ctx *ctx = q->ctx;
	struct wd_comp_udata *udata;

	do {
		ret = wd_recv(q, (void **)&resp);
		if (ret < 1)
			break;
		count++;
		udata = (void *)resp->udata;
		status = (int)resp->status;
		*(udata->opdata->cflush) = resp->cflags;
		*(udata->opdata->out_bytes) = resp->out_bytes;
		*(udata->opdata->comsumed) = resp->in_coms;
		ctx->cb(udata->tag, status, (void *)udata->opdata);
		free(udata);
	} while (--num);

	return count;
}

void wd_del_comp_ctx(void *ctx)
{
	if (ctx)
		free(ctx);
}
