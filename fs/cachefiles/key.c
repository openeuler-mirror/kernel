// SPDX-License-Identifier: GPL-2.0-or-later
/* Key to pathname encoder
 *
 * Copyright (C) 2007 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#include <linux/slab.h>
#include "internal.h"

static const char cachefiles_charmap[64] =
	"0123456789"			/* 0 - 9 */
	"abcdefghijklmnopqrstuvwxyz"	/* 10 - 35 */
	"ABCDEFGHIJKLMNOPQRSTUVWXYZ"	/* 36 - 61 */
	"_-"				/* 62 - 63 */
	;

static const char cachefiles_filecharmap[256] = {
	/* we skip space and tab and control chars */
	[33 ... 46] = 1,		/* '!' -> '.' */
	/* we skip '/' as it's significant to pathwalk */
	[48 ... 127] = 1,		/* '0' -> '~' */
};

static void cachefiles_cook_acc(char *key, unsigned int acc, int *len)
{
	key[*len + 1] = cachefiles_charmap[acc & 63];
	acc >>= 6;
	key[*len] = cachefiles_charmap[acc & 63];
	*len += 2;
}

static int cachefiles_cook_csum(struct fscache_cookie *cookie, const u8 *raw,
				int keylen, char *key)
{
	unsigned char csum = 0;
	int loop;

	if (volume_new_location(cookie))
		return 1;

	for (loop = 0; loop < keylen; loop++)
		csum += raw[loop];
	sprintf(key, "@%02x%c+", (unsigned int) csum, 0);

	return 5;
}

/*
 * turn the raw key into something cooked
 * - the raw key should include the length in the two bytes at the front
 * - the key may be up to 514 bytes in length (including the length word)
 *   - "base64" encode the strange keys, mapping 3 bytes of raw to four of
 *     cooked
 *   - need to cut the cooked key into 252 char lengths (189 raw bytes)
 */
char *cachefiles_cook_key(struct cachefiles_object *object,
			  const u8 *raw, int keylen)
{
	unsigned int acc;
	char *key;
	int loop, len, max, seg, mark, print;
	uint8_t type = object->type;
	struct fscache_cookie *cookie = object->fscache.cookie;

	_enter(",%d", keylen);

	BUG_ON(keylen < 2 || keylen > 514);

	print = 1;
	if (!volume_new_location(cookie)) {
		for (loop = 2; loop < keylen; loop++)
			print &= cachefiles_filecharmap[raw[loop]];
	}

	if (print) {
		/* if the path is usable ASCII, then we render it directly */
		max = keylen - 2;
		max += 2;	/* two base64'd length chars on the front */
		max += 5;	/* @checksum/M */
		max += 3 * 2;	/* maximum number of segment dividers (".../M")
				 * is ((514 + 251) / 252) = 3
				 */
		max += 1;	/* NUL on end */
	} else {
		/* calculate the maximum length of the cooked key */
		keylen = (keylen + 2) / 3;

		max = keylen * 4;
		max += 5;	/* @checksum/M */
		max += 3 * 2;	/* maximum number of segment dividers (".../M")
				 * is ((514 + 188) / 189) = 3
				 */
		max += 1;	/* NUL on end */
	}

	max += 1;	/* 2nd NUL on end */

	_debug("max: %d", max);

	key = kmalloc(max, cachefiles_gfp);
	if (!key)
		return NULL;

	len = cachefiles_cook_csum(cookie, raw, keylen, key);
	mark = len - 1;

	if (print) {
		if (!volume_new_location(cookie) && !data_new_location(cookie))
			cachefiles_cook_acc(key, *(uint16_t *) raw, &len);
		raw += 2;
		seg = 250;
		for (loop = keylen; loop > 0; loop--) {
			if (seg <= 0) {
				key[len++] = '\0';
				mark = len;
				key[len++] = '+';
				seg = 252;
			}

			key[len++] = *raw++;
			ASSERT(len < max);
		}

		switch (type) {
		case FSCACHE_COOKIE_TYPE_INDEX:		type = 'I';	break;
		case FSCACHE_COOKIE_TYPE_DATAFILE:	type = 'D';	break;
		default:				type = 'S';	break;
		}
	} else {
		seg = 252;
		for (loop = keylen; loop > 0; loop--) {
			if (seg <= 0) {
				key[len++] = '\0';
				mark = len;
				key[len++] = '+';
				seg = 252;
			}

			acc = *raw++;
			acc |= *raw++ << 8;
			acc |= *raw++ << 16;

			_debug("acc: %06x", acc);

			key[len++] = cachefiles_charmap[acc & 63];
			acc >>= 6;
			key[len++] = cachefiles_charmap[acc & 63];
			acc >>= 6;
			key[len++] = cachefiles_charmap[acc & 63];
			acc >>= 6;
			key[len++] = cachefiles_charmap[acc & 63];

			ASSERT(len < max);
		}

		switch (type) {
		case FSCACHE_COOKIE_TYPE_INDEX:		type = 'J';	break;
		case FSCACHE_COOKIE_TYPE_DATAFILE:	type = 'E';	break;
		default:				type = 'T';	break;
		}
	}

	key[mark] = type;
	key[len++] = 0;
	key[len] = 0;

	_leave(" = %p %d", key, len);
	return key;
}
