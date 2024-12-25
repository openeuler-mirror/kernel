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

static inline unsigned int how_many_hex_digits(unsigned int x)
{
	return x ? round_up(ilog2(x) + 1, 4) / 4 : 0;
}

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

	if (volume_new_version(cookie))
		return 1;

	if (data_new_version(cookie)) {
		csum = (u8)cookie->key_hash;
	} else {
		for (loop = 0; loop < keylen; loop++)
			csum += raw[loop];
	}
	sprintf(key, "@%02x%c+", (unsigned int) csum, 0);

	return 5;
}

static char *cachefiles_cook_data_key(const u8 *key, int keylen)
{
	const u8 *kend;
	unsigned int acc, i, n, nle, nbe;
	unsigned int b64len, len, pad;
	char *name, sep;

	/* See if it makes sense to encode it as "hex,hex,hex" for each 32-bit
	 * chunk.  We rely on the key having been padded out to a whole number
	 * of 32-bit words.
	 */
	n = round_up(keylen, 4);
	nbe = nle = 0;
	for (i = 0; i < n; i += 4) {
		u32 be = be32_to_cpu(*(__be32 *)(key + i));
		u32 le = le32_to_cpu(*(__le32 *)(key + i));

		nbe += 1 + how_many_hex_digits(be);
		nle += 1 + how_many_hex_digits(le);
	}

	b64len = DIV_ROUND_UP(keylen, 3);
	pad = b64len * 3 - keylen;
	b64len = 2 + b64len * 4; /* Length if we base64-encode it */
	_debug("len=%u nbe=%u nle=%u b64=%u", keylen, nbe, nle, b64len);
	if (nbe < b64len || nle < b64len) {
		unsigned int nlen = min(nbe, nle) + 1;

		name = kmalloc(nlen, GFP_KERNEL);
		if (!name)
			return NULL;
		sep = (nbe <= nle) ? 'S' : 'T'; /* Encoding indicator */
		len = 0;
		for (i = 0; i < n; i += 4) {
			u32 x;

			if (nbe <= nle)
				x = be32_to_cpu(*(__be32 *)(key + i));
			else
				x = le32_to_cpu(*(__le32 *)(key + i));
			name[len++] = sep;
			if (x != 0)
				len += snprintf(name + len, nlen - len, "%x", x);
			sep = ',';
		}
		name[len] = 0;
		return name;
	}

	/* We need to base64-encode it */
	name = kmalloc(b64len + 1, GFP_KERNEL);
	if (!name)
		return NULL;

	name[0] = 'E';
	name[1] = '0' + pad;
	len = 2;
	kend = key + keylen;
	do {
		acc  = *key++;
		if (key < kend) {
			acc |= *key++ << 8;
			if (key < kend)
				acc |= *key++ << 16;
		}

		name[len++] = cachefiles_charmap[acc & 63];
		acc >>= 6;
		name[len++] = cachefiles_charmap[acc & 63];
		acc >>= 6;
		name[len++] = cachefiles_charmap[acc & 63];
		acc >>= 6;
		name[len++] = cachefiles_charmap[acc & 63];
	} while (key < kend);

	name[len] = 0;
	return name;
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
	if (!volume_new_version(cookie)) {
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
	} else if (data_new_version(cookie)) {
		max = 5;	/* @checksum/M */
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
		if (!volume_new_version(cookie) && !data_new_version(cookie))
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
	} else if (data_new_version(cookie)) {
		int nlen;
		char *name = cachefiles_cook_data_key(raw + 2, keylen - 2);
		char *new_key;

		if (!name) {
			kfree(key);
			return NULL;
		}

		nlen = max + strlen(name) - 1;
		new_key = krealloc(key, nlen, GFP_KERNEL);
		if (!new_key) {
			kfree(key);
			kfree(name);
			return NULL;
		}

		key = new_key;
		type = name[0];
		for (loop = 1; loop < strlen(name); loop++)
			key[len++] = name[loop];
		kfree(name);
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
