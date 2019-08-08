/* SPDX-License-Identifier: GPL-2.0 */
/*
 * geniv.h: common interface for IV generation algorithms
 *
 * Copyright (C) 2018, Linaro
 *
 * This file define the data structure the user should pass to the template.
 */

#ifndef _CRYPTO_GENIV_H
#define _CRYPTO_GENIV_H

#include <linux/types.h>

enum setkey_op {
	SETKEY_OP_INIT,
	SETKEY_OP_SET,
	SETKEY_OP_WIPE,
};

struct geniv_key_info {
	enum setkey_op keyop;
	unsigned int tfms_count;
	u8 *key;
	char *ivopts;
	sector_t iv_offset;
	unsigned long cipher_flags;

	unsigned short int sector_size;
	unsigned int key_size;
	unsigned int key_parts;
	unsigned int key_mac_size;
	unsigned int on_disk_tag_size;
};

struct geniv_req_info {
	sector_t cc_sector;
	unsigned int nents;
	u8 *integrity_metadata;
};

#endif
