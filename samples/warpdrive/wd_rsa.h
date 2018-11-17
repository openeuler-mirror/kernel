/* SPDX-License-Identifier: GPL-2.0+ */
#ifndef __WD_RSA_H
#define __WD_RSA_H

#include <stdlib.h>
#include <errno.h>

#include "../../include/uapi/linux/vfio_spimdev.h"

enum wd_rsa_op {
	WD_RSA_INVALID,
	WD_RSA_SIGN,
	WD_RSA_VERIFY,
	WD_RSA_GENKEY,
};

enum wd_rsa_prikey_type {
	WD_RSA_PRIKEY1 = 1,
	WD_RSA_PRIKEY2 = 2,
};

typedef void (*wd_rsa_cb)(void *tag, int status, void *opdata);

struct wd_rsa_ctx_setup {
	char  *alg;
	wd_rsa_cb cb;
	__u16 aflags;
	__u16 key_bits;
	__u32 is_crt;
};

struct wd_rsa_pubkey {
	__u8 *n;
	__u8 *e;
	__u32 bytes;
};

struct wd_rsa_prikey1 {
	__u8 *n;
	__u8 *d;
	__u32 bytes;
};

struct wd_rsa_prikey2 {
	__u8 *p;
	__u8 *q;
	__u8 *dp;
	__u8 *dq;
	__u8 *qinv;
	__u32 bytes;
};

union wd_rsa_prikey {
	struct wd_rsa_prikey1 pkey1;
	struct wd_rsa_prikey2 pkey2;
};

struct wd_rsa_op_data {
	enum wd_rsa_op op_type;
	int status;
	void *in;
	void *out;
	__u32 in_bytes;
	__u32 out_bytes;
};

struct wd_rsa_msg {

	/* First 8 bytes of the message must indicate algorithm */
	union {
		char  *alg;
		__u64 pading;
	};

	/* address type */
	__u16 aflags;
	__u8 op_type;
	__u8 prikey_type;
	__u32 status;

	__u64 in;
	__u64 out;
	__u64 pubkey;

	/* private key */
	__u64 prikey;

	__u16 nbytes;
	__u16 inbytes;
	__u16 outbytes;
	__u16 resv;

	__u64 udata;
};

int wd_rsa_is_crt(void *ctx);
int wd_rsa_key_bits(void *ctx);
void *wd_create_rsa_ctx(struct wd_queue *q, struct wd_rsa_ctx_setup *setup);
int wd_set_rsa_pubkey(void *ctx, struct wd_rsa_pubkey *pubkey);
void wd_get_rsa_pubkey(void *ctx, struct wd_rsa_pubkey **pubkey);
int wd_set_rsa_prikey(void *ctx, union wd_rsa_prikey *prikey);
void wd_get_rsa_prikey(void *ctx, union wd_rsa_prikey **prikey);

/* this is a synchronous mode RSA API */
int wd_do_rsa(void *ctx, struct wd_rsa_op_data *opdata);

/* this is a pair of asynchronous mode RSA APIs */
int wd_rsa_op(void *ctx, struct wd_rsa_op_data *opdata, void *tag);
int wd_rsa_poll(struct wd_queue *q, int num);

void wd_del_rsa_ctx(void *ctx);
#endif
