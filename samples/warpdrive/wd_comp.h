/* SPDX-License-Identifier: GPL-2.0+ */
#ifndef __WD_COMP_H
#define __WD_COMP_H

#include <stdlib.h>
#include <errno.h>

#include "wd.h"


/* compressing algorithms' parameters */
struct wd_comp_param {
	__u32 win_size;
	__u32 comp_lv;
	__u32 mode;
	__u32 alg;
};

enum wd_comp_op {
	WD_COMP_INVALID,
	WD_COMP_PRESS,
	WD_COMP_INFLATE,
	WD_COMP_PSSTHRH,
};

enum wd_comp_flush {
	WD_INVALID_CFLUSH,
	WD_NO_CFLUSH,
	WD_PARTIAL_CFLUSH,
	WD_FULL_CFLUSH,
	WD_FINISH,
};

typedef void (*wd_comp_cb)(void *tag, int status, void *opdata);

struct wd_comp_ctx_setup {
	char  *alg;
	wd_comp_cb cb;
	__u32 win_size;
	__u32 aflags;
	__u8 op_type;
	__u8 humm_type;
	__u8 comp_lv;
	__u8 file_type;
};

struct wd_comp_opdata {
	__u32 *cflush;
	__u8 *in;
	__u32 in_bytes;
	__u32 *comsumed;
	__u8 *out;
	__u32 *out_bytes;
};

struct wd_comp_msg {

	/* First 8 bytes of the message must indicate algorithm */
	union {
		char  *alg;
		__u64 pading;
	};

	/* address type */
	__u32 aflags;

	/* Comsumed bytes of input data */
	__u32 in_coms;
	__u32 in_bytes;
	__u32 out_bytes;
	__u64 src;
	__u64 dst;
	__u8 comp_lv;
	__u8 file_type;
	__u8 humm_type;
	__u8 op_type;
	__u32 win_size;

	/* This flag indicates the output mode, from enum wd_comp_flush */
	__u32 cflags;
	__u32 status;
	__u64 udata;
};

void *wd_create_comp_ctx(struct wd_queue *q, struct wd_comp_ctx_setup *setup);

int wd_do_comp(void *ctx, struct wd_comp_opdata *opdata);
int wd_comp_op(void *ctx, struct wd_comp_opdata *opdata, void *tag);
int wd_comp_poll(struct wd_queue *q, int num);
void wd_del_comp_ctx(void *ctx);
#endif
