/* SPDX-License-Identifier: GPL-2.0+ */
#ifndef __WD_DH_H
#define __WD_DH_H

#include <stdlib.h>
#include <errno.h>

#include "../../include/uapi/linux/vfio_spimdev.h"

enum wd_dh_op {
	WD_DH_INVALID,
	WD_DH_PHASE1,
	WD_DH_PHASE2,
};

typedef void (*wd_dh_cb)(void *tag, int status,  void *opdata);

struct wd_dh_ctx_setup {
	char  *alg;
	wd_dh_cb cb;
	__u16 aflags;
};

struct wd_dh_op_data {
	void *p;
	void *x;

	/* it is PV also at phase 2 */
	void *g;

	/* phase 1&&2 output */
	void *pri;
	__u16 *pri_bytes;

	__u16 pbytes;
	__u16 xbytes;
	__u16 gbytes;

	enum wd_dh_op op_type;
};

struct wd_dh_msg {

	/* First 8 bytes of the message must indicate algorithm */
	union {
		char  *alg;
		__u64 pading;
	};

	/* address type */
	__u16 aflags;
	__u8 op_type;
	__u8 resv;
	__u32 status;

	__u64 p;
	__u64 x;

	/* is PV also at phase 2 */
	__u64 g;

	/* result address */
	__u64 pri;

	__u16 pbytes;
	__u16 xbytes;
	__u16 gbytes;
	__u16 pribytes;
	__u64 udata;
};

void *wd_create_dh_ctx(struct wd_queue *q, struct wd_dh_ctx_setup *setup);

/* Synchronous mode API of DH*/
int wd_do_dh(void *ctx, struct wd_dh_op_data *opdata);

/* Asynchronous mode APIs of DH */
int wd_dh_op(void *ctx, struct wd_dh_op_data *opdata, void *tag);
int wd_dh_poll(struct wd_queue *q, int num);


void wd_del_dh_ctx(void *ctx);
#endif
