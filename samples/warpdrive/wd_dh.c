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
#include "wd_dh.h"
#include "wd_util.h"


struct wd_dh_udata {
	void *tag;
	struct wd_dh_op_data *opdata;
};

struct wd_dh_ctx {
	struct wd_dh_msg cache_msg;
	struct wd_queue *q;
	wd_dh_cb cb;
	char  alg[32];
};


/* Before initiate this context, we should get a queue from WD */
void *wd_create_dh_ctx(struct wd_queue *q, struct wd_dh_ctx_setup *setup)
{
	struct wd_dh_ctx *ctx;

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

	ctx->cache_msg.alg = ctx->alg;
	ctx->cb = setup->cb;
	q->ctx = ctx;

	return ctx;
}

int wd_do_dh(void *ctx, struct wd_dh_op_data *opdata)
{
	struct wd_dh_ctx *ctxt = ctx;
	struct wd_dh_msg *resp;
	int ret;

	if (!ctx || !opdata) {
		WD_ERR("%s(): input param err!\n", __func__);
		return -1;
	}
	if (opdata->op_type == WD_DH_PHASE1 ||
	    opdata->op_type == WD_DH_PHASE2) {
		ctxt->cache_msg.p = (__u64)opdata->p;
		ctxt->cache_msg.g = (__u64)opdata->g;
		ctxt->cache_msg.x = (__u64)opdata->x;
		ctxt->cache_msg.pbytes = (__u16)opdata->pbytes;
		ctxt->cache_msg.gbytes = (__u16)opdata->gbytes;
		ctxt->cache_msg.xbytes = (__u16)opdata->xbytes;
		ctxt->cache_msg.pri = (__u64)opdata->pri;
	} else {
		WD_ERR("%s():operatinal type err!\n", __func__);
		return -1;
	}

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

	*(opdata->pri_bytes) = resp->pribytes;

	return 0;
}

int wd_dh_op(void *ctx, struct wd_dh_op_data *opdata, void *tag)
{
	struct wd_dh_ctx *context = ctx;
	struct wd_dh_msg *msg = &context->cache_msg;
	int ret;
	struct wd_dh_udata *udata;


	msg->status = 0;

	/* malloc now, as need performance we should rewrite mem management */
	udata = malloc(sizeof(*udata));
	if (!udata) {
		WD_ERR("malloc udata fail!\n");
		return -1;
	}
	udata->tag = tag;
	udata->opdata = opdata;
	if (opdata->op_type == WD_DH_PHASE1 ||
	    opdata->op_type == WD_DH_PHASE2) {
		msg->p = (__u64)opdata->p;
		msg->g = (__u64)opdata->g;
		msg->x = (__u64)opdata->x;
		msg->pbytes = (__u16)opdata->pbytes;
		msg->gbytes = (__u16)opdata->gbytes;
		msg->xbytes = (__u16)opdata->xbytes;
		msg->pri = (__u64)opdata->pri;
	} else {
		WD_ERR("%s():operatinal type err!\n", __func__);
		return -1;
	}

	msg->udata = (__u64)udata;
	ret = wd_send(context->q, (void *)msg);
	if (ret < 0) {
		WD_ERR("wd send request fail!\n");
		return -1;
	}

	return 0;
}

int wd_dh_poll(struct wd_queue *q, int num)
{
	int ret, count = 0;
	struct wd_dh_msg *resp;
	struct wd_dh_ctx *ctx = q->ctx;
	unsigned int status;
	struct wd_dh_udata *udata;

	do {
		ret = wd_recv(q, (void **)&resp);
		if (ret < 1)
			break;
		count++;
		udata = (void *)resp->udata;
		*(udata->opdata->pri_bytes) = (__u16)resp->pribytes;
		status = resp->status;
		ctx->cb(udata->tag, status, (void *)udata->opdata);
		free(udata);
	} while (--num);

	return count;
}

void wd_del_dh_ctx(void *ctx)
{
	if (ctx)
		free(ctx);
}
