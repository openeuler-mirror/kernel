/*
 * Copyright (C) 2003 Jana Saout <jana@saout.de>
 * Copyright (C) 2004 Clemens Fruhwirth <clemens@endorphin.org>
 * Copyright (C) 2006-2017 Red Hat, Inc. All rights reserved.
 * Copyright (C) 2013-2017 Milan Broz <gmazyland@gmail.com>
 *
 * This file is released under the GPL.
 */

#include <linux/completion.h>
#include <linux/err.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/key.h>
#include <linux/bio.h>
#include <linux/blkdev.h>
#include <linux/mempool.h>
#include <linux/slab.h>
#include <linux/crypto.h>
#include <linux/workqueue.h>
#include <linux/kthread.h>
#include <linux/backing-dev.h>
#include <linux/atomic.h>
#include <linux/scatterlist.h>
#include <linux/rbtree.h>
#include <linux/ctype.h>
#include <asm/page.h>
#include <asm/unaligned.h>
#include <crypto/hash.h>
#include <crypto/md5.h>
#include <crypto/algapi.h>
#include <crypto/skcipher.h>
#include <crypto/aead.h>
#include <crypto/authenc.h>
#include <crypto/geniv.h>
#include <crypto/internal/aead.h>
#include <crypto/internal/skcipher.h>
#include <linux/rtnetlink.h> /* for struct rtattr and RTA macros only */
#include <keys/user-type.h>
#include <linux/backing-dev.h>
#include <linux/device-mapper.h>
#include <linux/log2.h>

#define DM_MSG_PREFIX "crypt"

struct geniv_ctx;
struct geniv_req_ctx;

/* Sub request for each of the skcipher_request's for a segment */
struct geniv_subreq {
	struct scatterlist sg_in[4];
	struct scatterlist sg_out[4];
	sector_t iv_sector;
	struct geniv_req_ctx *rctx;
	union {
		struct skcipher_request req;
		struct aead_request req_aead;
	} r CRYPTO_MINALIGN_ATTR;
};

/* used to iter the src scatterlist of the input parent request */
struct scatterlist_iter {
	/* current segment to be processed */
	unsigned int seg_no;
	/* bytes had been processed in current segment */
	unsigned int done;
	/* bytes to be processed in the next request */
	unsigned int len;
};

/* contex of the input parent request */
struct geniv_req_ctx {
	struct geniv_subreq *subreq;
	bool is_write;
	bool is_aead_request;
	sector_t cc_sector;
	/* array size of src scatterlist of parent request */
	unsigned int nents;
	struct scatterlist_iter iter;
	struct completion restart;
	atomic_t req_pending;
	u8 *integrity_metadata;
	/* point to the input parent request */
	union {
		struct skcipher_request *req;
		struct aead_request *req_aead;
	} r;
};
/*
 * context holding the current state of a multi-part conversion
 */
struct convert_context {
	struct completion restart;
	struct bio *bio_in;
	struct bio *bio_out;
	struct bvec_iter iter_in;
	struct bvec_iter iter_out;
	u64 cc_sector;
	atomic_t cc_pending;
	union {
		struct skcipher_request *req;
		struct aead_request *req_aead;
	} r;

};

/*
 * per bio private data
 */
struct dm_crypt_io {
	struct crypt_config *cc;
	struct bio *base_bio;
	u8 *integrity_metadata;
	bool integrity_metadata_from_pool;
	struct work_struct work;

	struct convert_context ctx;

	atomic_t io_pending;
	blk_status_t error;
	sector_t sector;

	struct rb_node rb_node;
} CRYPTO_MINALIGN_ATTR;

struct dm_crypt_request {
	struct convert_context *ctx;
	struct scatterlist *sg_in;
	struct scatterlist *sg_out;
	u64 iv_sector;
};

struct crypt_config;

struct crypt_iv_operations {
	int (*ctr)(struct geniv_ctx *ctx);
	void (*dtr)(struct geniv_ctx *ctx);
	int (*init)(struct geniv_ctx *ctx);
	int (*wipe)(struct geniv_ctx *ctx);
	int (*generator)(struct geniv_ctx *ctx,
			struct geniv_req_ctx *rctx,
			struct geniv_subreq *subreq, u8 *iv);
	int (*post)(struct geniv_ctx *ctx,
			struct geniv_req_ctx *rctx,
			struct geniv_subreq *subreq, u8 *iv);
};

struct iv_essiv_private {
	struct crypto_shash *hash_tfm;
	u8 *salt;
};

struct iv_benbi_private {
	int shift;
};

#define LMK_SEED_SIZE 64 /* hash + 0 */
struct iv_lmk_private {
	struct crypto_shash *hash_tfm;
	u8 *seed;
};

#define TCW_WHITENING_SIZE 16
struct iv_tcw_private {
	struct crypto_shash *crc32_tfm;
	u8 *iv_seed;
	u8 *whitening;
};

/*
 * Crypt: maps a linear range of a block device
 * and encrypts / decrypts at the same time.
 */
enum flags { DM_CRYPT_SUSPENDED, DM_CRYPT_KEY_VALID,
	     DM_CRYPT_SAME_CPU, DM_CRYPT_NO_OFFLOAD };

enum cipher_flags {
	CRYPT_MODE_INTEGRITY_AEAD,	/* Use authenticated mode for cihper */
	CRYPT_IV_LARGE_SECTORS,		/* Calculate IV from sector_size, not 512B sectors */
};

/*
 * The fields in here must be read only after initialization.
 */
struct crypt_config {
	struct dm_dev *dev;
	sector_t start;

	struct percpu_counter n_allocated_pages;

	struct workqueue_struct *io_queue;
	struct workqueue_struct *crypt_queue;

	spinlock_t write_thread_lock;
	struct task_struct *write_thread;
	struct rb_root write_tree;

	char *cipher_string;
	char *cipher_auth;
	char *key_string;

	u64 iv_offset;
	unsigned int iv_size;
	unsigned short int sector_size;
	unsigned char sector_shift;

	/* ESSIV: struct crypto_cipher *essiv_tfm */
	void *iv_private;
	union {
		struct crypto_skcipher *tfm;
		struct crypto_aead *tfm_aead;
	} cipher_tfm;
	unsigned int tfms_count;
	unsigned long cipher_flags;

	/*
	 * Layout of each crypto request:
	 *
	 *   struct skcipher_request
	 *      context
	 *      padding
	 *   struct dm_crypt_request
	 *      padding
	 *   IV
	 *
	 * The padding is added so that dm_crypt_request and the IV are
	 * correctly aligned.
	 */
	unsigned int dmreq_start;

	unsigned int per_bio_data_size;

	unsigned long flags;
	unsigned int key_size;
	unsigned int key_parts;      /* independent parts in key buffer */
	unsigned int key_extra_size; /* additional keys length */
	unsigned int key_mac_size;   /* MAC key size for authenc(...) */

	unsigned int integrity_tag_size;
	unsigned int integrity_iv_size;
	unsigned int on_disk_tag_size;

	/*
	 * pool for per bio private data, crypto requests,
	 * encryption requeusts/buffer pages and integrity tags
	 */
	unsigned tag_pool_max_sectors;
	mempool_t tag_pool;
	mempool_t req_pool;
	mempool_t page_pool;

	struct bio_set bs;
	struct mutex bio_alloc_lock;

	u8 key[0];
};

#define MIN_IOS		64
#define MAX_TAG_SIZE	480
#define POOL_ENTRY_SIZE	512
#define SECTOR_MASK	((1 << SECTOR_SHIFT) - 1)
#define MAX_SG_LIST     (BIO_MAX_PAGES * 8)

static DEFINE_SPINLOCK(dm_crypt_clients_lock);
static unsigned dm_crypt_clients_n = 0;
static volatile unsigned long dm_crypt_pages_per_client;
#define DM_CRYPT_MEMORY_PERCENT			2
#define DM_CRYPT_MIN_PAGES_PER_CLIENT		(BIO_MAX_PAGES * 16)

static void clone_init(struct dm_crypt_io *, struct bio *);
static void kcryptd_queue_crypt(struct dm_crypt_io *io);
static struct scatterlist *crypt_get_sg_data(struct geniv_ctx *ctx,
					     struct scatterlist *sg);

/*
 * Use this to access cipher attributes that are independent of the key.
 */
static struct crypto_skcipher *any_tfm(struct crypt_config *cc)
{
	return cc->cipher_tfm.tfm;
}

static struct crypto_aead *any_tfm_aead(struct crypt_config *cc)
{
	return cc->cipher_tfm.tfm_aead;
}

/* context of geniv tfm */
struct geniv_ctx {
	unsigned int tfms_count;
	union {
		struct crypto_skcipher *tfm;
		struct crypto_aead *tfm_aead;
	} tfm_child;
	union {
		struct crypto_skcipher **tfms;
		struct crypto_aead **tfms_aead;
	} tfms;

	char *ivmode;
	unsigned int iv_size;
	unsigned int iv_start;
	unsigned int rctx_start;
	sector_t iv_offset;
	unsigned short int sector_size;
	unsigned char sector_shift;
	char *algname;
	char *ivopts;
	char *cipher;
	char *ciphermode;
	unsigned long cipher_flags;

	const struct crypt_iv_operations *iv_gen_ops;
	union {
		struct iv_essiv_private essiv;
		struct iv_benbi_private benbi;
		struct iv_lmk_private lmk;
		struct iv_tcw_private tcw;
	} iv_gen_private;
	void *iv_private;

	mempool_t *subreq_pool;
	unsigned int key_size;
	unsigned int key_parts;      /* independent parts in key buffer */
	unsigned int key_extra_size; /* additional keys length */
	unsigned int key_mac_size;

	unsigned int integrity_tag_size;
	unsigned int integrity_iv_size;
	unsigned int on_disk_tag_size;

	char *msg;
	u8 *authenc_key; /* space for keys in authenc() format (if used) */
	u8 *key;
};

/*
 * Different IV generation algorithms:
 *
 * plain: the initial vector is the 32-bit little-endian version of the sector
 *        number, padded with zeros if necessary.
 *
 * plain64: the initial vector is the 64-bit little-endian version of the sector
 *        number, padded with zeros if necessary.
 *
 * plain64be: the initial vector is the 64-bit big-endian version of the sector
 *        number, padded with zeros if necessary.
 *
 * essiv: "encrypted sector|salt initial vector", the sector number is
 *        encrypted with the bulk cipher using a salt as key. The salt
 *        should be derived from the bulk cipher's key via hashing.
 *
 * benbi: the 64-bit "big-endian 'narrow block'-count", starting at 1
 *        (needed for LRW-32-AES and possible other narrow block modes)
 *
 * null: the initial vector is always zero.  Provides compatibility with
 *       obsolete loop_fish2 devices.  Do not use for new devices.
 *
 * lmk:  Compatible implementation of the block chaining mode used
 *       by the Loop-AES block device encryption system
 *       designed by Jari Ruusu. See http://loop-aes.sourceforge.net/
 *       It operates on full 512 byte sectors and uses CBC
 *       with an IV derived from the sector number, the data and
 *       optionally extra IV seed.
 *       This means that after decryption the first block
 *       of sector must be tweaked according to decrypted data.
 *       Loop-AES can use three encryption schemes:
 *         version 1: is plain aes-cbc mode
 *         version 2: uses 64 multikey scheme with lmk IV generator
 *         version 3: the same as version 2 with additional IV seed
 *                   (it uses 65 keys, last key is used as IV seed)
 *
 * tcw:  Compatible implementation of the block chaining mode used
 *       by the TrueCrypt device encryption system (prior to version 4.1).
 *       For more info see: https://gitlab.com/cryptsetup/cryptsetup/wikis/TrueCryptOnDiskFormat
 *       It operates on full 512 byte sectors and uses CBC
 *       with an IV derived from initial key and the sector number.
 *       In addition, whitening value is applied on every sector, whitening
 *       is calculated from initial key, sector number and mixed using CRC32.
 *       Note that this encryption scheme is vulnerable to watermarking attacks
 *       and should be used for old compatible containers access only.
 *
 * plumb: unimplemented, see:
 * http://article.gmane.org/gmane.linux.kernel.device-mapper.dm-crypt/454
 */

static int crypt_iv_plain_gen(struct geniv_ctx *ctx,
				struct geniv_req_ctx *rctx,
				struct geniv_subreq *subreq, u8 *iv)
{
	memset(iv, 0, ctx->iv_size);
	*(__le32 *)iv = cpu_to_le32(subreq->iv_sector & 0xffffffff);

	return 0;
}

static int crypt_iv_plain64_gen(struct geniv_ctx *ctx,
				struct geniv_req_ctx *rctx,
				struct geniv_subreq *subreq, u8 *iv)
{
	memset(iv, 0, ctx->iv_size);
	*(__le64 *)iv = cpu_to_le64(subreq->iv_sector);

	return 0;
}

static int crypt_iv_plain64be_gen(struct geniv_ctx *ctx,
				struct geniv_req_ctx *rctx,
				struct geniv_subreq *subreq, u8 *iv)
{
	memset(iv, 0, ctx->iv_size);
	/* iv_size is at least of size u64; usually it is 16 bytes */
	*(__be64 *)&iv[ctx->iv_size - sizeof(u64)] = cpu_to_be64(subreq->iv_sector);

	return 0;
}

/* Initialise ESSIV - compute salt but no local memory allocations */
static int crypt_iv_essiv_init(struct geniv_ctx *ctx)
{
	struct iv_essiv_private *essiv = &ctx->iv_gen_private.essiv;
	SHASH_DESC_ON_STACK(desc, essiv->hash_tfm);
	struct crypto_cipher *essiv_tfm;
	int err;

	desc->tfm = essiv->hash_tfm;
	desc->flags = 0;

	err = crypto_shash_digest(desc, ctx->key, ctx->key_size, essiv->salt);
	shash_desc_zero(desc);
	if (err)
		return err;

	essiv_tfm = ctx->iv_private;

	return crypto_cipher_setkey(essiv_tfm, essiv->salt,
			    crypto_shash_digestsize(essiv->hash_tfm));
}

/* Wipe salt and reset key derived from volume key */
static int crypt_iv_essiv_wipe(struct geniv_ctx *ctx)
{
	struct iv_essiv_private *essiv = &ctx->iv_gen_private.essiv;
	unsigned int salt_size = crypto_shash_digestsize(essiv->hash_tfm);
	struct crypto_cipher *essiv_tfm;

	memset(essiv->salt, 0, salt_size);

	essiv_tfm = ctx->iv_private;
	return crypto_cipher_setkey(essiv_tfm, essiv->salt, salt_size);
}

/* Allocate the cipher for ESSIV */
static struct crypto_cipher *alloc_essiv_cipher(struct geniv_ctx *ctx,
					u8 *salt, unsigned int saltsize)
{
	struct crypto_cipher *essiv_tfm;
	int err;

	/* Setup the essiv_tfm with the given salt */
	essiv_tfm = crypto_alloc_cipher(ctx->cipher, 0, CRYPTO_ALG_ASYNC);
	if (IS_ERR(essiv_tfm)) {
		DMERR("Error allocating crypto tfm for ESSIV\n");
		return essiv_tfm;
	}

	if (crypto_cipher_blocksize(essiv_tfm) != ctx->iv_size) {
		DMERR("Block size of ESSIV cipher does "
			    "not match IV size of block cipher\n");
		crypto_free_cipher(essiv_tfm);
		return ERR_PTR(-EINVAL);
	}

	err = crypto_cipher_setkey(essiv_tfm, salt, saltsize);
	if (err) {
		DMERR("Failed to set key for ESSIV cipher\n");
		crypto_free_cipher(essiv_tfm);
		return ERR_PTR(err);
	}

	return essiv_tfm;
}

static void crypt_iv_essiv_dtr(struct geniv_ctx *ctx)
{
	struct crypto_cipher *essiv_tfm;
	struct iv_essiv_private *essiv = &ctx->iv_gen_private.essiv;

	crypto_free_shash(essiv->hash_tfm);
	essiv->hash_tfm = NULL;

	kzfree(essiv->salt);
	essiv->salt = NULL;

	essiv_tfm = ctx->iv_private;

	if (essiv_tfm)
		crypto_free_cipher(essiv_tfm);

	ctx->iv_private = NULL;
}

static int crypt_iv_essiv_ctr(struct geniv_ctx *ctx)
{
	struct crypto_cipher *essiv_tfm = NULL;
	struct crypto_shash *hash_tfm = NULL;
	u8 *salt = NULL;
	int err;

	if (!ctx->ivopts) {
		DMERR("Digest algorithm missing for ESSIV mode\n");
		return -EINVAL;
	}

	/* Allocate hash algorithm */
	hash_tfm = crypto_alloc_shash(ctx->ivopts, 0, 0);
	if (IS_ERR(hash_tfm)) {
		DMERR("Error initializing ESSIV hash\n");
		err = PTR_ERR(hash_tfm);
		goto bad;
	}

	salt = kzalloc(crypto_shash_digestsize(hash_tfm), GFP_KERNEL);
	if (!salt) {
		DMERR("Error kmallocing salt storage in ESSIV\n");
		err = -ENOMEM;
		goto bad;
	}

	ctx->iv_gen_private.essiv.salt = salt;
	ctx->iv_gen_private.essiv.hash_tfm = hash_tfm;

	essiv_tfm = alloc_essiv_cipher(ctx, salt,
				       crypto_shash_digestsize(hash_tfm));
	if (IS_ERR(essiv_tfm)) {
		crypt_iv_essiv_dtr(ctx);
		return PTR_ERR(essiv_tfm);
	}
	ctx->iv_private = essiv_tfm;

	return 0;

bad:
	if (hash_tfm && !IS_ERR(hash_tfm))
		crypto_free_shash(hash_tfm);
	kfree(salt);
	return err;
}

static int crypt_iv_essiv_gen(struct geniv_ctx *ctx,
				struct geniv_req_ctx *rctx,
				struct geniv_subreq *subreq, u8 *iv)
{
	struct crypto_cipher *essiv_tfm = ctx->iv_private;

	memset(iv, 0, ctx->iv_size);
	*(__le64 *)iv = cpu_to_le64(subreq->iv_sector);
	crypto_cipher_encrypt_one(essiv_tfm, iv, iv);

	return 0;
}

static int crypt_iv_benbi_ctr(struct geniv_ctx *ctx)
{
	unsigned bs;
	int log;

	if (test_bit(CRYPT_MODE_INTEGRITY_AEAD, &ctx->cipher_flags))
		bs = crypto_aead_blocksize(ctx->tfms.tfms_aead[0]);
	else
		bs = crypto_skcipher_blocksize(ctx->tfms.tfms[0]);
	log = ilog2(bs);

	/* we need to calculate how far we must shift the sector count
	 * to get the cipher block count, we use this shift in _gen */

	if (1 << log != bs) {
		DMERR("cypher blocksize is not a power of 2\n");
		return -EINVAL;
	}

	if (log > 9) {
		DMERR("cypher blocksize is > 512\n");
		return -EINVAL;
	}

	ctx->iv_gen_private.benbi.shift = 9 - log;

	return 0;
}

static void crypt_iv_benbi_dtr(struct geniv_ctx *ctx)
{
}

static int crypt_iv_benbi_gen(struct geniv_ctx *ctx,
				struct geniv_req_ctx *rctx,
				struct geniv_subreq *subreq, u8 *iv)
{
	__be64 val;

	memset(iv, 0, ctx->iv_size - sizeof(u64)); /* rest is cleared below */

	val = cpu_to_be64(((u64)subreq->iv_sector << ctx->iv_gen_private.benbi.shift) + 1);
	put_unaligned(val, (__be64 *)(iv + ctx->iv_size - sizeof(u64)));

	return 0;
}

static int crypt_iv_null_gen(struct geniv_ctx *ctx,
				struct geniv_req_ctx *rctx,
				struct geniv_subreq *subreq, u8 *iv)
{
	memset(iv, 0, ctx->iv_size);

	return 0;
}

static void crypt_iv_lmk_dtr(struct geniv_ctx *ctx)
{
	struct iv_lmk_private *lmk = &ctx->iv_gen_private.lmk;

	if (lmk->hash_tfm && !IS_ERR(lmk->hash_tfm))
		crypto_free_shash(lmk->hash_tfm);
	lmk->hash_tfm = NULL;

	kzfree(lmk->seed);
	lmk->seed = NULL;
}

static int crypt_iv_lmk_ctr(struct geniv_ctx *ctx)
{
	struct iv_lmk_private *lmk = &ctx->iv_gen_private.lmk;

	if (ctx->sector_size != (1 << SECTOR_SHIFT)) {
		DMERR("Unsupported sector size for LMK\n");
		return -EINVAL;
	}

	lmk->hash_tfm = crypto_alloc_shash("md5", 0, 0);
	if (IS_ERR(lmk->hash_tfm)) {
		DMERR("Error initializing LMK hash, err=%ld\n",
			PTR_ERR(lmk->hash_tfm));
		return PTR_ERR(lmk->hash_tfm);
	}

	/* No seed in LMK version 2 */
	if (ctx->key_parts == ctx->tfms_count) {
		lmk->seed = NULL;
		return 0;
	}

	lmk->seed = kzalloc(LMK_SEED_SIZE, GFP_KERNEL);
	if (!lmk->seed) {
		crypt_iv_lmk_dtr(ctx);
		DMERR("Error kmallocing seed storage in LMK\n");
		return -ENOMEM;
	}

	return 0;
}

static int crypt_iv_lmk_init(struct geniv_ctx *ctx)
{
	struct iv_lmk_private *lmk = &ctx->iv_gen_private.lmk;
	int subkey_size = ctx->key_size / ctx->key_parts;

	/* LMK seed is on the position of LMK_KEYS + 1 key */
	if (lmk->seed)
		memcpy(lmk->seed, ctx->key + (ctx->tfms_count * subkey_size),
		       crypto_shash_digestsize(lmk->hash_tfm));

	return 0;
}

static int crypt_iv_lmk_wipe(struct geniv_ctx *ctx)
{
	struct iv_lmk_private *lmk = &ctx->iv_gen_private.lmk;

	if (lmk->seed)
		memset(lmk->seed, 0, LMK_SEED_SIZE);

	return 0;
}

static int crypt_iv_lmk_one(struct geniv_ctx *ctx, u8 *iv,
				struct geniv_subreq *subreq, u8 *data)
{
	struct iv_lmk_private *lmk = &ctx->iv_gen_private.lmk;
	SHASH_DESC_ON_STACK(desc, lmk->hash_tfm);
	struct md5_state md5state;
	__le32 buf[4];
	int i, r;

	desc->tfm = lmk->hash_tfm;
	desc->flags = 0;

	r = crypto_shash_init(desc);
	if (r)
		return r;

	if (lmk->seed) {
		r = crypto_shash_update(desc, lmk->seed, LMK_SEED_SIZE);
		if (r)
			return r;
	}

	/* Sector is always 512B, block size 16, add data of blocks 1-31 */
	r = crypto_shash_update(desc, data + 16, 16 * 31);
	if (r)
		return r;

	/* Sector is cropped to 56 bits here */
	buf[0] = cpu_to_le32(subreq->iv_sector & 0xFFFFFFFF);
	buf[1] = cpu_to_le32((((u64)subreq->iv_sector >> 32) & 0x00FFFFFF) | 0x80000000);
	buf[2] = cpu_to_le32(4024);
	buf[3] = 0;
	r = crypto_shash_update(desc, (u8 *)buf, sizeof(buf));
	if (r)
		return r;

	/* No MD5 padding here */
	r = crypto_shash_export(desc, &md5state);
	if (r)
		return r;

	for (i = 0; i < MD5_HASH_WORDS; i++)
		__cpu_to_le32s(&md5state.hash[i]);
	memcpy(iv, &md5state.hash, ctx->iv_size);

	return 0;
}

static int crypt_iv_lmk_gen(struct geniv_ctx *ctx,
				struct geniv_req_ctx *rctx,
				struct geniv_subreq *subreq, u8 *iv)
{
	struct scatterlist *sg;
	u8 *src;
	int r = 0;

	if (rctx->is_write) {
		sg = crypt_get_sg_data(ctx, subreq->sg_in);
		src = kmap_atomic(sg_page(sg));
		r = crypt_iv_lmk_one(ctx, iv, subreq, src + sg->offset);
		kunmap_atomic(src);
	} else
		memset(iv, 0, ctx->iv_size);

	return r;
}

static int crypt_iv_lmk_post(struct geniv_ctx *ctx,
				struct geniv_req_ctx *rctx,
				struct geniv_subreq *subreq, u8 *iv)
{
	struct scatterlist *sg;
	u8 *dst;
	int r;

	if (rctx->is_write)
		return 0;

	sg = crypt_get_sg_data(ctx, subreq->sg_out);
	dst = kmap_atomic(sg_page(sg));
	r = crypt_iv_lmk_one(ctx, iv, subreq, dst + sg->offset);

	/* Tweak the first block of plaintext sector */
	if (!r)
		crypto_xor(dst + sg->offset, iv, ctx->iv_size);

	kunmap_atomic(dst);
	return r;
}

static void crypt_iv_tcw_dtr(struct geniv_ctx *ctx)
{
	struct iv_tcw_private *tcw = &ctx->iv_gen_private.tcw;

	kzfree(tcw->iv_seed);
	tcw->iv_seed = NULL;
	kzfree(tcw->whitening);
	tcw->whitening = NULL;

	if (tcw->crc32_tfm && !IS_ERR(tcw->crc32_tfm))
		crypto_free_shash(tcw->crc32_tfm);
	tcw->crc32_tfm = NULL;
}

static int crypt_iv_tcw_ctr(struct geniv_ctx *ctx)
{
	struct iv_tcw_private *tcw = &ctx->iv_gen_private.tcw;

	if (ctx->sector_size != (1 << SECTOR_SHIFT)) {
		DMERR("Unsupported sector size for TCW\n");
		return -EINVAL;
	}

	if (ctx->key_size <= (ctx->iv_size + TCW_WHITENING_SIZE)) {
		DMERR("Wrong key size (%d) for TCW. Choose a value > %d bytes\n",
			ctx->key_size, ctx->iv_size + TCW_WHITENING_SIZE);
		return -EINVAL;
	}

	tcw->crc32_tfm = crypto_alloc_shash("crc32", 0, 0);
	if (IS_ERR(tcw->crc32_tfm)) {
		DMERR("Error initializing CRC32 in TCW; err=%ld\n",
			PTR_ERR(tcw->crc32_tfm));
		return PTR_ERR(tcw->crc32_tfm);
	}

	tcw->iv_seed = kzalloc(ctx->iv_size, GFP_KERNEL);
	tcw->whitening = kzalloc(TCW_WHITENING_SIZE, GFP_KERNEL);
	if (!tcw->iv_seed || !tcw->whitening) {
		crypt_iv_tcw_dtr(ctx);
		DMERR("Error allocating seed storage in TCW\n");
		return -ENOMEM;
	}

	return 0;
}

static int crypt_iv_tcw_init(struct geniv_ctx *ctx)
{
	struct iv_tcw_private *tcw = &ctx->iv_gen_private.tcw;
	int key_offset = ctx->key_size - ctx->iv_size - TCW_WHITENING_SIZE;

	memcpy(tcw->iv_seed, &ctx->key[key_offset], ctx->iv_size);
	memcpy(tcw->whitening, &ctx->key[key_offset + ctx->iv_size],
	       TCW_WHITENING_SIZE);

	return 0;
}

static int crypt_iv_tcw_wipe(struct geniv_ctx *ctx)
{
	struct iv_tcw_private *tcw = &ctx->iv_gen_private.tcw;

	memset(tcw->iv_seed, 0, ctx->iv_size);
	memset(tcw->whitening, 0, TCW_WHITENING_SIZE);

	return 0;
}

static int crypt_iv_tcw_whitening(struct geniv_ctx *ctx,
				struct geniv_subreq *subreq, u8 *data)
{
	struct iv_tcw_private *tcw = &ctx->iv_gen_private.tcw;
	__le64 sector = cpu_to_le64(subreq->iv_sector);
	u8 buf[TCW_WHITENING_SIZE];
	SHASH_DESC_ON_STACK(desc, tcw->crc32_tfm);
	int i, r;

	/* xor whitening with sector number */
	crypto_xor_cpy(buf, tcw->whitening, (u8 *)&sector, 8);
	crypto_xor_cpy(&buf[8], tcw->whitening + 8, (u8 *)&sector, 8);

	/* calculate crc32 for every 32bit part and xor it */
	desc->tfm = tcw->crc32_tfm;
	desc->flags = 0;
	for (i = 0; i < 4; i++) {
		r = crypto_shash_init(desc);
		if (r)
			goto out;
		r = crypto_shash_update(desc, &buf[i * 4], 4);
		if (r)
			goto out;
		r = crypto_shash_final(desc, &buf[i * 4]);
		if (r)
			goto out;
	}
	crypto_xor(&buf[0], &buf[12], 4);
	crypto_xor(&buf[4], &buf[8], 4);

	/* apply whitening (8 bytes) to whole sector */
	for (i = 0; i < ((1 << SECTOR_SHIFT) / 8); i++)
		crypto_xor(data + i * 8, buf, 8);
out:
	memzero_explicit(buf, sizeof(buf));
	return r;
}

static int crypt_iv_tcw_gen(struct geniv_ctx *ctx,
				struct geniv_req_ctx *rctx,
				struct geniv_subreq *subreq, u8 *iv)
{
	struct scatterlist *sg;
	struct iv_tcw_private *tcw = &ctx->iv_gen_private.tcw;
	__le64 sector = cpu_to_le64(subreq->iv_sector);
	u8 *src;
	int r = 0;

	/* Remove whitening from ciphertext */
	if (!rctx->is_write) {
		sg = crypt_get_sg_data(ctx, subreq->sg_in);
		src = kmap_atomic(sg_page(sg));
		r = crypt_iv_tcw_whitening(ctx, subreq, src + sg->offset);
		kunmap_atomic(src);
	}

	/* Calculate IV */
	crypto_xor_cpy(iv, tcw->iv_seed, (u8 *)&sector, 8);
	if (ctx->iv_size > 8)
		crypto_xor_cpy(&iv[8], tcw->iv_seed + 8, (u8 *)&sector,
			       ctx->iv_size - 8);

	return r;
}

static int crypt_iv_tcw_post(struct geniv_ctx *ctx,
				struct geniv_req_ctx *rctx,
				struct geniv_subreq *subreq, u8 *iv)
{
	struct scatterlist *sg;
	u8 *dst;
	int r;

	if (!rctx->is_write)
		return 0;

	/* Apply whitening on ciphertext */
	sg = crypt_get_sg_data(ctx, subreq->sg_out);
	dst = kmap_atomic(sg_page(sg));
	r = crypt_iv_tcw_whitening(ctx, subreq, dst + sg->offset);
	kunmap_atomic(dst);

	return r;
}

static int crypt_iv_random_gen(struct geniv_ctx *ctx,
				struct geniv_req_ctx *rctx,
				struct geniv_subreq *subreq, u8 *iv)
{
	/* Used only for writes, there must be an additional space to store IV */
	get_random_bytes(iv, ctx->iv_size);
	return 0;
}

static const struct crypt_iv_operations crypt_iv_plain_ops = {
	.generator = crypt_iv_plain_gen
};

static const struct crypt_iv_operations crypt_iv_plain64_ops = {
	.generator = crypt_iv_plain64_gen
};

static const struct crypt_iv_operations crypt_iv_plain64be_ops = {
	.generator = crypt_iv_plain64be_gen
};

static const struct crypt_iv_operations crypt_iv_essiv_ops = {
	.ctr       = crypt_iv_essiv_ctr,
	.dtr       = crypt_iv_essiv_dtr,
	.init      = crypt_iv_essiv_init,
	.wipe      = crypt_iv_essiv_wipe,
	.generator = crypt_iv_essiv_gen
};

static const struct crypt_iv_operations crypt_iv_benbi_ops = {
	.ctr	   = crypt_iv_benbi_ctr,
	.dtr	   = crypt_iv_benbi_dtr,
	.generator = crypt_iv_benbi_gen
};

static const struct crypt_iv_operations crypt_iv_null_ops = {
	.generator = crypt_iv_null_gen
};

static const struct crypt_iv_operations crypt_iv_lmk_ops = {
	.ctr	   = crypt_iv_lmk_ctr,
	.dtr	   = crypt_iv_lmk_dtr,
	.init	   = crypt_iv_lmk_init,
	.wipe	   = crypt_iv_lmk_wipe,
	.generator = crypt_iv_lmk_gen,
	.post	   = crypt_iv_lmk_post
};

static const struct crypt_iv_operations crypt_iv_tcw_ops = {
	.ctr	   = crypt_iv_tcw_ctr,
	.dtr	   = crypt_iv_tcw_dtr,
	.init	   = crypt_iv_tcw_init,
	.wipe	   = crypt_iv_tcw_wipe,
	.generator = crypt_iv_tcw_gen,
	.post	   = crypt_iv_tcw_post
};

static struct crypt_iv_operations crypt_iv_random_ops = {
	.generator = crypt_iv_random_gen
};


static bool geniv_integrity_aead(struct geniv_ctx *ctx)
{
	return test_bit(CRYPT_MODE_INTEGRITY_AEAD, &ctx->cipher_flags);
}

static bool geniv_integrity_hmac(struct geniv_ctx *ctx)
{
	return geniv_integrity_aead(ctx) && ctx->key_mac_size;
}

static struct geniv_req_ctx *geniv_skcipher_req_ctx(struct skcipher_request *req)
{
	return (void *)PTR_ALIGN((u8 *)skcipher_request_ctx(req),  __alignof__(struct geniv_req_ctx));
}

static struct geniv_req_ctx *geniv_aead_req_ctx(struct aead_request *req)
{
	return (void *)PTR_ALIGN((u8 *)aead_request_ctx(req), __alignof__(struct geniv_req_ctx));
}

static u8 *iv_of_subreq(struct geniv_ctx *ctx, struct geniv_subreq *subreq)
{
	if (geniv_integrity_aead(ctx))
		return (u8 *)ALIGN((unsigned long)((char *)subreq + ctx->iv_start),
			crypto_aead_alignmask(crypto_aead_reqtfm(subreq->rctx->r.req_aead)) + 1);
	else
		return (u8 *)ALIGN((unsigned long)((char *)subreq + ctx->iv_start),
			crypto_skcipher_alignmask(crypto_skcipher_reqtfm(subreq->rctx->r.req)) + 1);
}

static int geniv_init_iv(struct geniv_ctx *ctx)
{
	int ret;

	DMDEBUG("IV Generation algorithm : %s\n", ctx->ivmode);

	if (ctx->ivmode == NULL)
		ctx->iv_gen_ops = NULL;
	else if (strcmp(ctx->ivmode, "plain") == 0)
		ctx->iv_gen_ops = &crypt_iv_plain_ops;
	else if (strcmp(ctx->ivmode, "plain64") == 0)
		ctx->iv_gen_ops = &crypt_iv_plain64_ops;
	else if (strcmp(ctx->ivmode, "essiv") == 0)
		ctx->iv_gen_ops = &crypt_iv_essiv_ops;
	else if (strcmp(ctx->ivmode, "benbi") == 0)
		ctx->iv_gen_ops = &crypt_iv_benbi_ops;
	else if (strcmp(ctx->ivmode, "null") == 0)
		ctx->iv_gen_ops = &crypt_iv_null_ops;
	else if (strcmp(ctx->ivmode, "lmk") == 0) {
		ctx->iv_gen_ops = &crypt_iv_lmk_ops;
		/*
		 * Version 2 and 3 is recognised according
		 * to length of provided multi-key string.
		 * If present (version 3), last key is used as IV seed.
		 * All keys (including IV seed) are always the same size.
		 */
		if (ctx->key_size % ctx->key_parts) {
			ctx->key_parts++;
			ctx->key_extra_size = ctx->key_size / ctx->key_parts;
		}
	} else if (strcmp(ctx->ivmode, "tcw") == 0) {
		ctx->iv_gen_ops = &crypt_iv_tcw_ops;
		ctx->key_parts += 2; /* IV + whitening */
		ctx->key_extra_size = ctx->iv_size + TCW_WHITENING_SIZE;
	} else if (strcmp(ctx->ivmode, "random") == 0) {
		ctx->iv_gen_ops = &crypt_iv_random_ops;
		/* Need storage space in integrity fields. */
		ctx->integrity_iv_size = ctx->iv_size;
	} else {
		DMERR("Invalid IV mode %s\n", ctx->ivmode);
		return -EINVAL;
	}

	/* Allocate IV */
	if (ctx->iv_gen_ops && ctx->iv_gen_ops->ctr) {
		ret = ctx->iv_gen_ops->ctr(ctx);
		if (ret < 0) {
			DMERR("Error creating IV for %s\n", ctx->ivmode);
			return ret;
		}
	}

	/* Initialize IV (set keys for ESSIV etc) */
	if (ctx->iv_gen_ops && ctx->iv_gen_ops->init) {
		ret = ctx->iv_gen_ops->init(ctx);
		if (ret < 0) {
			DMERR("Error creating IV for %s\n", ctx->ivmode);
			return ret;
		}
	}

	return 0;
}

static void geniv_free_tfms_aead(struct geniv_ctx *ctx)
{
	if (!ctx->tfms.tfms_aead)
		return;

	if (ctx->tfms.tfms_aead[0] && IS_ERR(ctx->tfms.tfms_aead[0])) {
		crypto_free_aead(ctx->tfms.tfms_aead[0]);
		ctx->tfms.tfms_aead[0] = NULL;
	}

	kfree(ctx->tfms.tfms_aead);
	ctx->tfms.tfms_aead = NULL;
}

static void geniv_free_tfms_skcipher(struct geniv_ctx *ctx)
{
	unsigned int i;

	if (!ctx->tfms.tfms)
		return;

	for (i = 0; i < ctx->tfms_count; i++)
		if (ctx->tfms.tfms[i] && IS_ERR(ctx->tfms.tfms[i])) {
			crypto_free_skcipher(ctx->tfms.tfms[i]);
			ctx->tfms.tfms[i] = NULL;
		}

	kfree(ctx->tfms.tfms);
	ctx->tfms.tfms = NULL;
}

static void geniv_free_tfms(struct geniv_ctx *ctx)
{
	if (geniv_integrity_aead(ctx))
		geniv_free_tfms_aead(ctx);
	else
		geniv_free_tfms_skcipher(ctx);
}

static int geniv_alloc_tfms_aead(struct crypto_aead *parent,
			    struct geniv_ctx *ctx)
{
	unsigned int reqsize, align;

	ctx->tfms.tfms_aead = kcalloc(1, sizeof(struct crypto_aead *),
			   GFP_KERNEL);
	if (!ctx->tfms.tfms_aead)
		return -ENOMEM;

	/* First instance is already allocated in geniv_init_tfm */
	ctx->tfms.tfms_aead[0] = ctx->tfm_child.tfm_aead;

	/* Setup the current cipher's request structure */
	align = crypto_aead_alignmask(parent);
	align &= ~(crypto_tfm_ctx_alignment() - 1);
	reqsize = align + sizeof(struct geniv_req_ctx) +
		  crypto_aead_reqsize(ctx->tfms.tfms_aead[0]);

	crypto_aead_set_reqsize(parent, reqsize);

	return 0;
}

/*
 * Allocate memory for the underlying cipher algorithm. Ex: cbc(aes)
 */
static int geniv_alloc_tfms_skcipher(struct crypto_skcipher *parent,
			    struct geniv_ctx *ctx)
{
	unsigned int i, reqsize, align, err;

	ctx->tfms.tfms = kcalloc(ctx->tfms_count, sizeof(struct crypto_skcipher *),
			   GFP_KERNEL);
	if (!ctx->tfms.tfms)
		return -ENOMEM;

	/* First instance is already allocated in geniv_init_tfm */
	ctx->tfms.tfms[0] = ctx->tfm_child.tfm;
	for (i = 1; i < ctx->tfms_count; i++) {
		ctx->tfms.tfms[i] = crypto_alloc_skcipher(ctx->ciphermode, 0, 0);
		if (IS_ERR(ctx->tfms.tfms[i])) {
			err = PTR_ERR(ctx->tfms.tfms[i]);
			geniv_free_tfms(ctx);
			return err;
		}

		/* Setup the current cipher's request structure */
		align = crypto_skcipher_alignmask(parent);
		align &= ~(crypto_tfm_ctx_alignment() - 1);
		reqsize = align + sizeof(struct geniv_req_ctx) +
			  crypto_skcipher_reqsize(ctx->tfms.tfms[i]);

		crypto_skcipher_set_reqsize(parent, reqsize);
	}

	return 0;
}

static unsigned int geniv_authenckey_size(struct geniv_ctx *ctx)
{
	return ctx->key_size - ctx->key_extra_size +
		RTA_SPACE(sizeof(struct crypto_authenc_key_param));
}

/*
 * Initialize the cipher's context with the key, ivmode and other parameters.
 * Also allocate IV generation template ciphers and initialize them.
 */
static int geniv_setkey_init(void *parent, struct geniv_key_info *info)
{
	struct geniv_ctx *ctx;
	int ret;

	if (test_bit(CRYPT_MODE_INTEGRITY_AEAD, &info->cipher_flags))
		ctx = crypto_aead_ctx((struct crypto_aead *)parent);
	else
		ctx = crypto_skcipher_ctx((struct crypto_skcipher *)parent);

	ctx->tfms_count = info->tfms_count;
	ctx->key = info->key;
	ctx->cipher_flags = info->cipher_flags;
	ctx->ivopts = info->ivopts;
	ctx->iv_offset = info->iv_offset;
	ctx->sector_size = info->sector_size;
	ctx->sector_shift = __ffs(ctx->sector_size) - SECTOR_SHIFT;

	ctx->key_size = info->key_size;
	ctx->key_parts = info->key_parts;
	ctx->key_mac_size = info->key_mac_size;
	ctx->on_disk_tag_size = info->on_disk_tag_size;

	if (geniv_integrity_hmac(ctx)) {
		ctx->authenc_key = kmalloc(geniv_authenckey_size(ctx), GFP_KERNEL);
		if (!ctx->authenc_key)
			return -ENOMEM;
	}

	if (geniv_integrity_aead(ctx))
		ret = geniv_alloc_tfms_aead((struct crypto_aead *)parent, ctx);
	else
		ret = geniv_alloc_tfms_skcipher((struct crypto_skcipher *)parent, ctx);
	if (ret)
		return ret;

	ret = geniv_init_iv(ctx);

	if (geniv_integrity_aead(ctx))
		ctx->integrity_tag_size = ctx->on_disk_tag_size - ctx->integrity_iv_size;

	return ret;
}

/*
 * If AEAD is composed like authenc(hmac(sha256),xts(aes)),
 * the key must be for some reason in special format.
 * This function converts cc->key to this special format.
 */
static void crypt_copy_authenckey(char *p, const void *key,
			unsigned int enckeylen, unsigned int authkeylen)
{
	struct crypto_authenc_key_param *param;
	struct rtattr *rta;

	rta = (struct rtattr *)p;
	param = RTA_DATA(rta);
	param->enckeylen = cpu_to_be32(enckeylen);
	rta->rta_len = RTA_LENGTH(sizeof(*param));
	rta->rta_type = CRYPTO_AUTHENC_KEYA_PARAM;
	p += RTA_SPACE(sizeof(*param));
	memcpy(p, key + enckeylen, authkeylen);
	p += authkeylen;
	memcpy(p, key, enckeylen);
}

static int geniv_setkey_tfms_aead(struct crypto_aead *parent, struct geniv_ctx *ctx,
			     struct geniv_key_info *info)
{
	unsigned int key_size;
	unsigned int authenc_key_size;
	struct crypto_aead *child_aead;
	int ret = 0;

	/* Ignore extra keys (which are used for IV etc) */
	key_size = ctx->key_size - ctx->key_extra_size;
	authenc_key_size = key_size + RTA_SPACE(sizeof(struct crypto_authenc_key_param));

	child_aead = ctx->tfms.tfms_aead[0];
	crypto_aead_clear_flags(child_aead, CRYPTO_TFM_REQ_MASK);
	crypto_aead_set_flags(child_aead, crypto_aead_get_flags(parent) & CRYPTO_TFM_REQ_MASK);

	if (geniv_integrity_hmac(ctx)) {
		if (key_size < ctx->key_mac_size)
			return -EINVAL;

		crypt_copy_authenckey(ctx->authenc_key, ctx->key, key_size - ctx->key_mac_size,
				      ctx->key_mac_size);
	}

	if (geniv_integrity_hmac(ctx))
		ret = crypto_aead_setkey(child_aead, ctx->authenc_key, authenc_key_size);
	else
		ret = crypto_aead_setkey(child_aead, ctx->key, key_size);
	if (ret) {
		DMERR("Error setting key for tfms[0]\n");
		goto out;
	}

	crypto_aead_set_flags(parent, crypto_aead_get_flags(child_aead) & CRYPTO_TFM_RES_MASK);

out:
	if (geniv_integrity_hmac(ctx))
		memzero_explicit(ctx->authenc_key, authenc_key_size);

	return ret;
}

static int geniv_setkey_tfms_skcipher(struct crypto_skcipher *parent, struct geniv_ctx *ctx,
			     struct geniv_key_info *info)
{
	unsigned int subkey_size;
	char *subkey;
	struct crypto_skcipher *child;
	int ret, i;

	/* Ignore extra keys (which are used for IV etc) */
	subkey_size = (ctx->key_size - ctx->key_extra_size)
		      >> ilog2(ctx->tfms_count);

	for (i = 0; i < ctx->tfms_count; i++) {
		child = ctx->tfms.tfms[i];
		crypto_skcipher_clear_flags(child, CRYPTO_TFM_REQ_MASK);
		crypto_skcipher_set_flags(child,
			crypto_skcipher_get_flags(parent) & CRYPTO_TFM_REQ_MASK);

		subkey = ctx->key + (subkey_size) * i;

		ret = crypto_skcipher_setkey(child, subkey, subkey_size);
		if (ret) {
			DMERR("Error setting key for tfms[%d]\n", i);
			return ret;
		}

		crypto_skcipher_set_flags(parent, crypto_skcipher_get_flags(child) &
					  CRYPTO_TFM_RES_MASK);
	}

	return 0;
}

static int geniv_setkey_set(struct geniv_ctx *ctx)
{
	if (ctx->iv_gen_ops && ctx->iv_gen_ops->init)
		return ctx->iv_gen_ops->init(ctx);
	else
		return 0;
}

static int geniv_setkey_wipe(struct geniv_ctx *ctx)
{
	int ret;

	if (ctx->iv_gen_ops && ctx->iv_gen_ops->wipe) {
		ret = ctx->iv_gen_ops->wipe(ctx);
		if (ret)
			return ret;
	}

	if (geniv_integrity_hmac(ctx))
		kzfree(ctx->authenc_key);

	return 0;
}

static int geniv_setkey(void *parent, const u8 *key, unsigned int keylen)
{
	int err = 0;
	struct geniv_ctx *ctx;
	struct geniv_key_info *info = (struct geniv_key_info *) key;

	if (test_bit(CRYPT_MODE_INTEGRITY_AEAD, &info->cipher_flags))
		ctx = crypto_aead_ctx((struct crypto_aead *)parent);
	else
		ctx = crypto_skcipher_ctx((struct crypto_skcipher *)parent);

	DMDEBUG("SETKEY Operation : %d\n", info->keyop);

	switch (info->keyop) {
	case SETKEY_OP_INIT:
		err = geniv_setkey_init(parent, info);
		break;
	case SETKEY_OP_SET:
		err = geniv_setkey_set(ctx);
		break;
	case SETKEY_OP_WIPE:
		err = geniv_setkey_wipe(ctx);
		break;
	}

	if (err)
		return err;

	if (test_bit(CRYPT_MODE_INTEGRITY_AEAD, &info->cipher_flags))
		return geniv_setkey_tfms_aead((struct crypto_aead *)parent, ctx, info);
	else
		return geniv_setkey_tfms_skcipher((struct crypto_skcipher *)parent, ctx, info);
}

static int geniv_aead_setkey(struct crypto_aead *parent,
				const u8 *key, unsigned int keylen)
{
	return geniv_setkey(parent, key, keylen);
}

static int geniv_skcipher_setkey(struct crypto_skcipher *parent,
				const u8 *key, unsigned int keylen)
{
	return geniv_setkey(parent, key, keylen);
}

static void geniv_async_done(struct crypto_async_request *async_req, int error);

static int geniv_alloc_subreq_aead(struct geniv_ctx *ctx,
					struct geniv_req_ctx *rctx,
					u32 req_flags)
{
	struct aead_request *req;

	if (!rctx->subreq) {
		rctx->subreq = mempool_alloc(ctx->subreq_pool, GFP_NOIO);
		if (!rctx->subreq)
			return -ENOMEM;
	}

	req = &rctx->subreq->r.req_aead;
	rctx->subreq->rctx = rctx;

	aead_request_set_tfm(req, ctx->tfms.tfms_aead[0]);
	aead_request_set_callback(req, req_flags,
					geniv_async_done, rctx->subreq);

	return 0;
}

/* req_flags: flags from parent request */
static int geniv_alloc_subreq_skcipher(struct geniv_ctx *ctx,
					struct geniv_req_ctx *rctx,
					u32 req_flags)
{
	int key_index;
	struct skcipher_request *req;

	if (!rctx->subreq) {
		rctx->subreq = mempool_alloc(ctx->subreq_pool, GFP_NOIO);
		if (!rctx->subreq)
			return -ENOMEM;
	}

	req = &rctx->subreq->r.req;
	rctx->subreq->rctx = rctx;

	key_index = rctx->cc_sector & (ctx->tfms_count - 1);

	skcipher_request_set_tfm(req, ctx->tfms.tfms[key_index]);
	skcipher_request_set_callback(req, req_flags,
					geniv_async_done, rctx->subreq);

	return 0;
}

/*
 * Asynchronous IO completion callback for each sector in a segment. When all
 * pending i/o are completed the parent cipher's async function is called.
 */
static void geniv_async_done(struct crypto_async_request *async_req, int error)
{
	struct geniv_subreq *subreq = async_req->data;
	struct geniv_req_ctx *rctx = subreq->rctx;
	struct skcipher_request *req = NULL;
	struct aead_request *req_aead = NULL;
	struct geniv_ctx *ctx;
	u8 *iv;

	if (!rctx->is_aead_request) {
		req = rctx->r.req;
		ctx = crypto_skcipher_ctx(crypto_skcipher_reqtfm(req));
	} else {
		req_aead = rctx->r.req_aead;
		ctx = crypto_aead_ctx(crypto_aead_reqtfm(req_aead));
	}

	/*
	 * A request from crypto driver backlog is going to be processed now,
	 * finish the completion and continue in crypt_convert().
	 * (Callback will be called for the second time for this request.)
	 */
	if (error == -EINPROGRESS) {
		complete(&rctx->restart);
		return;
	}

	iv = iv_of_subreq(ctx, subreq);
	if (!error && ctx->iv_gen_ops && ctx->iv_gen_ops->post)
		error = ctx->iv_gen_ops->post(ctx, rctx, subreq, iv);

	mempool_free(subreq, ctx->subreq_pool);

	/*
	 * req_pending needs to be checked before req->base.complete is called
	 * as we need 'req_pending' to be equal to 1 to ensure all subrequests
	 * are processed.
	 */
	if (atomic_dec_and_test(&rctx->req_pending)) {
		/* Call the parent cipher's completion function */
		if (!rctx->is_aead_request)
			skcipher_request_complete(req, error);
		else
			aead_request_complete(req_aead, error);

	}
}

static unsigned int geniv_get_sectors(struct scatterlist *sg1,
				      struct scatterlist *sg2,
				      unsigned int segments)
{
	unsigned int i, n1, n2;

	n1 = n2 = 0;
	for (i = 0; i < segments ; i++) {
		n1 += sg1[i].length >> SECTOR_SHIFT;
		n1 += (sg1[i].length & SECTOR_MASK) ? 1 : 0;
	}

	for (i = 0; i < segments ; i++) {
		n2 += sg2[i].length >> SECTOR_SHIFT;
		n2 += (sg2[i].length & SECTOR_MASK) ? 1 : 0;
	}

	return max(n1, n2);
}

/*
 * Iterate scatterlist of segments to retrieve the 512-byte sectors so that
 * unique IVs could be generated for each 512-byte sector. This split may not
 * be necessary e.g. when these ciphers are modelled in hardware, where it can
 * make use of the hardware's IV generation capabilities.
 */
static int geniv_iter_block(void *req_in,
			struct geniv_ctx *ctx, struct geniv_req_ctx *rctx)

{
	unsigned int rem;
	struct scatterlist *src_org, *dst_org;
	struct scatterlist *src1, *dst1;
	struct scatterlist_iter *iter = &rctx->iter;

	if (unlikely(iter->seg_no >= rctx->nents))
		return 0;

	if (geniv_integrity_aead(ctx)) {
		struct aead_request *req_aead = (struct aead_request *)req_in;
		src_org = &req_aead->src[0];
		dst_org = &req_aead->dst[0];
	} else {
		struct skcipher_request *req = (struct skcipher_request *)req_in;
		src_org = &req->src[0];
		dst_org = &req->dst[0];
	}

	src1 = &src_org[iter->seg_no];
	dst1 = &dst_org[iter->seg_no];
	iter->done += iter->len;

	if (iter->done >= src1->length) {
		iter->seg_no++;

		if (iter->seg_no >= rctx->nents)
			return 0;

		src1 = &src_org[iter->seg_no];
		dst1 = &dst_org[iter->seg_no];
		iter->done = 0;
	}

	rem = src1->length - iter->done;

	iter->len = rem > ctx->sector_size ? ctx->sector_size : rem;

	DMDEBUG("segment:(%d/%u),  done:%d, rem:%d\n",
		iter->seg_no, rctx->nents, iter->done, rem);

	return iter->len;
}

static u8 *org_iv_of_subreq(struct geniv_ctx *ctx, struct geniv_subreq *subreq)
{
	return iv_of_subreq(ctx, subreq) + ctx->iv_size;
}

static uint64_t *org_sector_of_subreq(struct geniv_ctx *ctx, struct geniv_subreq *subreq)
{
	u8 *ptr = iv_of_subreq(ctx, subreq) + ctx->iv_size + ctx->iv_size;

	return (uint64_t *) ptr;
}

static unsigned int *org_tag_of_subreq(struct geniv_ctx *ctx, struct geniv_subreq *subreq)
{
	u8 *ptr = iv_of_subreq(ctx, subreq) + ctx->iv_size +
		  ctx->iv_size + sizeof(uint64_t);

	return (unsigned int *)ptr;
}

static void *tag_from_subreq(struct geniv_ctx *ctx, struct geniv_subreq *subreq)
{
	return &subreq->rctx->integrity_metadata[*org_tag_of_subreq(ctx, subreq) *
		ctx->on_disk_tag_size];
}

static void *iv_tag_from_subreq(struct geniv_ctx *ctx, struct geniv_subreq *subreq)
{
	return tag_from_subreq(ctx, subreq) + ctx->integrity_tag_size;
}

static int geniv_convert_block_aead(struct geniv_ctx *ctx,
				     struct geniv_req_ctx *rctx,
				     struct geniv_subreq *subreq,
				     unsigned int tag_offset)
{
	struct scatterlist *sg_in, *sg_out;
	u8 *iv, *org_iv, *tag_iv, *tag;
	uint64_t *sector;
	int r = 0;
	struct scatterlist_iter *iter = &rctx->iter;
	struct aead_request *req_aead;
	struct aead_request *parent_req = rctx->r.req_aead;

	BUG_ON(ctx->integrity_iv_size && ctx->integrity_iv_size != ctx->iv_size);

	/* Reject unexpected unaligned bio. */
	if (unlikely(iter->len & (ctx->sector_size - 1)))
		return -EIO;

	subreq->iv_sector = rctx->cc_sector;
	if (test_bit(CRYPT_IV_LARGE_SECTORS, &ctx->cipher_flags))
		subreq->iv_sector >>= ctx->sector_shift;

	*org_tag_of_subreq(ctx, subreq) = tag_offset;

	sector = org_sector_of_subreq(ctx, subreq);
	*sector = cpu_to_le64(rctx->cc_sector - ctx->iv_offset);

	iv = iv_of_subreq(ctx, subreq);
	org_iv = org_iv_of_subreq(ctx, subreq);
	tag = tag_from_subreq(ctx, subreq);
	tag_iv = iv_tag_from_subreq(ctx, subreq);

	sg_in = subreq->sg_in;
	sg_out = subreq->sg_out;

	/*
	 * AEAD request:
	 *  |----- AAD -------|------ DATA -------|-- AUTH TAG --|
	 *  | (authenticated) | (auth+encryption) |              |
	 *  | sector_LE |  IV |  sector in/out    |  tag in/out  |
	 */
	sg_init_table(sg_in, 4);
	sg_set_buf(&sg_in[0], sector, sizeof(uint64_t));
	sg_set_buf(&sg_in[1], org_iv, ctx->iv_size);
	sg_set_page(&sg_in[2], sg_page(&parent_req->src[iter->seg_no]),
			iter->len, parent_req->src[iter->seg_no].offset + iter->done);
	sg_set_buf(&sg_in[3], tag, ctx->integrity_tag_size);

	sg_init_table(sg_out, 4);
	sg_set_buf(&sg_out[0], sector, sizeof(uint64_t));
	sg_set_buf(&sg_out[1], org_iv, ctx->iv_size);
	sg_set_page(&sg_out[2], sg_page(&parent_req->dst[iter->seg_no]),
			iter->len, parent_req->dst[iter->seg_no].offset + iter->done);
	sg_set_buf(&sg_out[3], tag, ctx->integrity_tag_size);

	if (ctx->iv_gen_ops) {
		/* For READs use IV stored in integrity metadata */
		if (ctx->integrity_iv_size && !rctx->is_write) {
			memcpy(org_iv, tag_iv, ctx->iv_size);
		} else {
			r = ctx->iv_gen_ops->generator(ctx, rctx, subreq, org_iv);
			if (r < 0)
				return r;
			/* Store generated IV in integrity metadata */
			if (ctx->integrity_iv_size)
				memcpy(tag_iv, org_iv, ctx->iv_size);
		}
		/* Working copy of IV, to be modified in crypto API */
		memcpy(iv, org_iv, ctx->iv_size);
	}

	req_aead = &subreq->r.req_aead;
	aead_request_set_ad(req_aead, sizeof(uint64_t) + ctx->iv_size);
	if (rctx->is_write) {
		aead_request_set_crypt(req_aead, subreq->sg_in, subreq->sg_out,
				       ctx->sector_size, iv);
		r = crypto_aead_encrypt(req_aead);
		if (ctx->integrity_tag_size + ctx->integrity_iv_size != ctx->on_disk_tag_size)
			memset(tag + ctx->integrity_tag_size + ctx->integrity_iv_size, 0,
			       ctx->on_disk_tag_size - (ctx->integrity_tag_size + ctx->integrity_iv_size));
	} else {
		aead_request_set_crypt(req_aead, subreq->sg_in, subreq->sg_out,
				       ctx->sector_size + ctx->integrity_tag_size, iv);
		r = crypto_aead_decrypt(req_aead);
	}

	if (r == -EBADMSG)
		DMERR_LIMIT("INTEGRITY AEAD ERROR, sector %llu",
			    (unsigned long long)le64_to_cpu(*sector));

	if (!r && ctx->iv_gen_ops && ctx->iv_gen_ops->post)
		r = ctx->iv_gen_ops->post(ctx, rctx, subreq, org_iv);

	return r;
}

static int geniv_convert_block_skcipher(struct geniv_ctx *ctx,
					struct geniv_req_ctx *rctx,
					struct geniv_subreq *subreq,
					unsigned int tag_offset)
{
	struct scatterlist *sg_in, *sg_out;
	u8 *iv, *org_iv, *tag_iv;
	uint64_t *sector;
	int r = 0;
	struct scatterlist_iter *iter = &rctx->iter;
	struct skcipher_request *req;
	struct skcipher_request *parent_req = rctx->r.req;

	/* Reject unexpected unaligned bio. */
	if (unlikely(iter->len & (ctx->sector_size - 1)))
		return -EIO;

	subreq->iv_sector = rctx->cc_sector;
	if (test_bit(CRYPT_IV_LARGE_SECTORS, &ctx->cipher_flags))
		subreq->iv_sector >>= ctx->sector_shift;

	*org_tag_of_subreq(ctx, subreq) = tag_offset;

	iv = iv_of_subreq(ctx, subreq);
	org_iv = org_iv_of_subreq(ctx, subreq);
	tag_iv = iv_tag_from_subreq(ctx, subreq);

	sector = org_sector_of_subreq(ctx, subreq);
	*sector = cpu_to_le64(rctx->cc_sector - ctx->iv_offset);

	/* For skcipher we use only the first sg item */
	sg_in = subreq->sg_in;
	sg_out = subreq->sg_out;

	sg_init_table(sg_in, 1);
	sg_set_page(sg_in, sg_page(&parent_req->src[iter->seg_no]),
			iter->len, parent_req->src[iter->seg_no].offset + iter->done);

	sg_init_table(sg_out, 1);
	sg_set_page(sg_out, sg_page(&parent_req->dst[iter->seg_no]),
			iter->len, parent_req->dst[iter->seg_no].offset + iter->done);

	if (ctx->iv_gen_ops) {
		/* For READs use IV stored in integrity metadata */
		if (ctx->integrity_iv_size && !rctx->is_write) {
			memcpy(org_iv, tag_iv, ctx->integrity_iv_size);
		} else {
			r = ctx->iv_gen_ops->generator(ctx, rctx, subreq, org_iv);
			if (r < 0)
				return r;
			/* Store generated IV in integrity metadata */
			if (ctx->integrity_iv_size)
				memcpy(tag_iv, org_iv, ctx->integrity_iv_size);
		}
		/* Working copy of IV, to be modified in crypto API */
		memcpy(iv, org_iv, ctx->iv_size);
	}

	req = &subreq->r.req;
	skcipher_request_set_crypt(req, sg_in, sg_out, ctx->sector_size, iv);

	if (rctx->is_write)
		r = crypto_skcipher_encrypt(req);
	else
		r = crypto_skcipher_decrypt(req);

	if (!r && ctx->iv_gen_ops && ctx->iv_gen_ops->post)
		r = ctx->iv_gen_ops->post(ctx, rctx, subreq, org_iv);

	return r;
}

/*
 * Common encryt/decrypt function for geniv template cipher. Before the crypto
 * operation, it splits the memory segments (in the scatterlist) into 512 byte
 * sectors. The initialization vector(IV) used is based on a unique sector
 * number which is generated here.
 */
static int geniv_crypt(struct geniv_ctx *ctx, void *parent_req, bool is_encrypt)
{
	struct skcipher_request *req = NULL;
	struct aead_request *req_aead = NULL;
	struct geniv_req_ctx *rctx;
	struct geniv_req_info *rinfo;
	int i, bytes, cryptlen, ret = 0;
	unsigned int sectors;
	unsigned int tag_offset = 0;
	unsigned int sector_step = ctx->sector_size >> SECTOR_SHIFT;
	char *str __maybe_unused = is_encrypt ? "encrypt" : "decrypt";

	if (geniv_integrity_aead(ctx)) {
		req_aead = (struct aead_request *)parent_req;
		rctx = geniv_aead_req_ctx(req_aead);
		rctx->r.req_aead = req_aead;
		rinfo = (struct geniv_req_info *)req_aead->iv;
	} else {
		req = (struct skcipher_request *)parent_req;
		rctx = geniv_skcipher_req_ctx(req);
		rctx->r.req = req;
		rinfo = (struct geniv_req_info *)req->iv;
	}

	/* Instance of 'struct geniv_req_info' is stored in IV ptr */
	rctx->is_write = is_encrypt;
	rctx->is_aead_request = geniv_integrity_aead(ctx);
	rctx->cc_sector = rinfo->cc_sector;
	rctx->nents = rinfo->nents;
	rctx->integrity_metadata = rinfo->integrity_metadata;
	rctx->subreq = NULL;
	cryptlen = req->cryptlen;

	rctx->iter.seg_no = 0;
	rctx->iter.done = 0;
	rctx->iter.len = 0;

	DMDEBUG("geniv:%s: starting sector=%d, #segments=%u\n", str,
		(unsigned int)rctx->cc_sector, rctx->nents);

	if (geniv_integrity_aead(ctx))
		sectors = geniv_get_sectors(req_aead->src, req_aead->dst, rctx->nents);
	else
		sectors = geniv_get_sectors(req->src, req->dst, rctx->nents);

	init_completion(&rctx->restart);
	atomic_set(&rctx->req_pending, 1);

	for (i = 0; i < sectors; i++) {
		struct geniv_subreq *subreq;

		if (geniv_integrity_aead(ctx))
			ret = geniv_alloc_subreq_aead(ctx, rctx, req_aead->base.flags);
		else
			ret = geniv_alloc_subreq_skcipher(ctx, rctx, req->base.flags);
		if (ret)
			return -ENOMEM;

		subreq = rctx->subreq;

		if (geniv_integrity_aead(ctx))
			bytes = geniv_iter_block(req_aead, ctx, rctx);
		else
			bytes = geniv_iter_block(req, ctx, rctx);

		if (bytes == 0)
			break;

		cryptlen -= bytes;
		atomic_inc(&rctx->req_pending);

		if (geniv_integrity_aead(ctx))
			ret = geniv_convert_block_aead(ctx, rctx, subreq, tag_offset);
		else
			ret = geniv_convert_block_skcipher(ctx, rctx, subreq, tag_offset);

		switch (ret) {
		/*
		 * The request was queued by a crypto driver
		 * but the driver request queue is full, let's wait.
		 */
		case -EBUSY:
			wait_for_completion(&rctx->restart);
			reinit_completion(&rctx->restart);
			/* fall through */
		/*
		 * The request is queued and processed asynchronously,
		 * completion function geniv_async_done() is called.
		 */
		case -EINPROGRESS:
			/* Marking this NULL lets the creation of a new sub-
			 * request when 'geniv_alloc_subreq' is called.
			 */
			rctx->subreq = NULL;
			rctx->cc_sector += sector_step;
			tag_offset++;
			cond_resched();
			break;
		/*
		 * The request was already processed (synchronously).
		 */
		case 0:
			atomic_dec(&rctx->req_pending);
			rctx->cc_sector += sector_step;
			tag_offset++;
			cond_resched();
			continue;

		/* There was an error while processing the request. */
		default:
			atomic_dec(&rctx->req_pending);
			mempool_free(rctx->subreq, ctx->subreq_pool);
			atomic_dec(&rctx->req_pending);
			return ret;
		}
	}

	if (rctx->subreq)
		mempool_free(rctx->subreq, ctx->subreq_pool);

	if (atomic_dec_and_test(&rctx->req_pending))
		return 0;
	else
		return -EINPROGRESS;
}

static int geniv_skcipher_encrypt(struct skcipher_request *req)
{
	struct crypto_skcipher *tfm = crypto_skcipher_reqtfm(req);
	struct geniv_ctx *ctx = crypto_skcipher_ctx(tfm);

	return geniv_crypt(ctx, req, true);
}

static int geniv_skcipher_decrypt(struct skcipher_request *req)
{
	struct crypto_skcipher *tfm = crypto_skcipher_reqtfm(req);
	struct geniv_ctx *ctx = crypto_skcipher_ctx(tfm);

	return geniv_crypt(ctx, req, false);
}

static int geniv_aead_encrypt(struct aead_request *req)
{
	struct crypto_aead *tfm = crypto_aead_reqtfm(req);
	struct geniv_ctx *ctx = crypto_aead_ctx(tfm);

	return geniv_crypt(ctx, req, true);
}

static int geniv_aead_decrypt(struct aead_request *req)
{
	struct crypto_aead *tfm = crypto_aead_reqtfm(req);
	struct geniv_ctx *ctx = crypto_aead_ctx(tfm);

	return geniv_crypt(ctx, req, false);
}

/*
 * Workaround to parse cipher algorithm from crypto API spec.
 * The ctx->cipher is currently used only in ESSIV.
 * This should be probably done by crypto-api calls (once available...)
 */
static int geniv_blkdev_cipher(struct geniv_ctx *ctx, bool is_crypto_aead)
{
	const char *alg_name = NULL;
	char *start, *end;

	alg_name = ctx->ciphermode;
	if (!alg_name)
		return -EINVAL;

	if (is_crypto_aead) {
		alg_name = strchr(alg_name, ',');
		if (!alg_name)
			alg_name = ctx->ciphermode;
		alg_name++;
	}

	start = strchr(alg_name, '(');
	end = strchr(alg_name, ')');

	if (!start && !end) {
		ctx->cipher = kstrdup(alg_name, GFP_KERNEL);
		return ctx->cipher ? 0 : -ENOMEM;
	}

	if (!start || !end || ++start >= end)
		return -EINVAL;

	ctx->cipher = kzalloc(end - start + 1, GFP_KERNEL);
	if (!ctx->cipher)
		return -ENOMEM;

	strncpy(ctx->cipher, start, end - start);

	return 0;
}

static int geniv_init_tfm(void *tfm_tmp, bool is_crypto_aead)
{
	struct geniv_ctx *ctx;
	struct crypto_skcipher *tfm;
	struct crypto_aead *tfm_aead;
	unsigned int reqsize;
	size_t iv_size_padding;
	char *algname;
	int psize, ret;

	if (is_crypto_aead) {
		tfm_aead = (struct crypto_aead *)tfm_tmp;
		ctx = crypto_aead_ctx(tfm_aead);
		algname = (char *) crypto_tfm_alg_name(crypto_aead_tfm(tfm_aead));
	} else {
		tfm = (struct crypto_skcipher *)tfm_tmp;
		ctx = crypto_skcipher_ctx(tfm);
		algname = (char *) crypto_tfm_alg_name(crypto_skcipher_tfm(tfm));
	}

	ctx->ciphermode = kmalloc(CRYPTO_MAX_ALG_NAME, GFP_KERNEL);
	if (!ctx->ciphermode)
		return -ENOMEM;

	ctx->algname = kmalloc(CRYPTO_MAX_ALG_NAME, GFP_KERNEL);
	if (!ctx->algname) {
		ret = -ENOMEM;
		goto free_ciphermode;
	}

	strlcpy(ctx->algname, algname, CRYPTO_MAX_ALG_NAME);
	algname = ctx->algname;

	/* Parse the algorithm name 'ivmode(ciphermode)' */
	ctx->ivmode = strsep(&algname, "(");
	strlcpy(ctx->ciphermode, algname, CRYPTO_MAX_ALG_NAME);
	ctx->ciphermode[strlen(algname) - 1] = '\0';

	DMDEBUG("ciphermode=%s, ivmode=%s\n", ctx->ciphermode, ctx->ivmode);

	/*
	 * Usually the underlying cipher instances are spawned here, but since
	 * the value of tfms_count (which is equal to the key_count) is not
	 * known yet, create only one instance and delay the creation of the
	 * rest of the instances of the underlying cipher 'cbc(aes)' until
	 * the setkey operation is invoked.
	 * The first instance created i.e. ctx->child will later be assigned as
	 * the 1st element in the array ctx->tfms. Creation of atleast one
	 * instance of the cipher is necessary to be created here to uncover
	 * any errors earlier than during the setkey operation later where the
	 * remaining instances are created.
	 */
	if (is_crypto_aead)
		ctx->tfm_child.tfm_aead = crypto_alloc_aead(ctx->ciphermode, 0, 0);
	else
		ctx->tfm_child.tfm = crypto_alloc_skcipher(ctx->ciphermode, 0, 0);
	if (IS_ERR(ctx->tfm_child.tfm)) {
		ret = PTR_ERR(ctx->tfm_child.tfm);
		DMERR("Failed to create cipher %s. err %d\n",
		      ctx->ciphermode, ret);
		goto free_algname;
	}

	/* Setup the current cipher's request structure */
	if (is_crypto_aead) {
		reqsize = sizeof(struct geniv_req_ctx) + __alignof__(struct geniv_req_ctx);
		crypto_aead_set_reqsize(tfm_aead, reqsize);

		ctx->iv_start = sizeof(struct geniv_subreq);
		ctx->iv_start += crypto_aead_reqsize(ctx->tfm_child.tfm_aead);

		ctx->iv_size = crypto_aead_ivsize(tfm_aead);
	} else {
		reqsize = sizeof(struct geniv_req_ctx) + __alignof__(struct geniv_req_ctx);
		crypto_skcipher_set_reqsize(tfm, reqsize);

		ctx->iv_start = sizeof(struct geniv_subreq);
		ctx->iv_start += crypto_skcipher_reqsize(ctx->tfm_child.tfm);

		ctx->iv_size = crypto_skcipher_ivsize(tfm);
	}
	/* at least a 64 bit sector number should fit in our buffer */
	if (ctx->iv_size)
		ctx->iv_size = max(ctx->iv_size,
				  (unsigned int)(sizeof(u64) / sizeof(u8)));

	if (is_crypto_aead) {
		if (crypto_aead_alignmask(tfm_aead) < CRYPTO_MINALIGN) {
			/* Allocate the padding exactly */
			iv_size_padding = -ctx->iv_start
					& crypto_aead_alignmask(ctx->tfm_child.tfm_aead);
		} else {
			/*
			 * If the cipher requires greater alignment than kmalloc
			 * alignment, we don't know the exact position of the
			 * initialization vector. We must assume worst case.
			 */
			iv_size_padding = crypto_aead_alignmask(ctx->tfm_child.tfm_aead);
		}
	} else {
		if (crypto_skcipher_alignmask(tfm) < CRYPTO_MINALIGN) {
			iv_size_padding = -ctx->iv_start
					& crypto_skcipher_alignmask(ctx->tfm_child.tfm);
		} else {
			iv_size_padding = crypto_skcipher_alignmask(ctx->tfm_child.tfm);
		}
	}

	/*
	 * create memory pool for sub-request structure
	 *  ...| IV + padding | original IV | original sec. number | bio tag offset |
	 */
	psize = ctx->iv_start + iv_size_padding + ctx->iv_size + ctx->iv_size +
		sizeof(uint64_t) + sizeof(unsigned int);

	ctx->subreq_pool = mempool_create_kmalloc_pool(MIN_IOS, psize);
	if (!ctx->subreq_pool) {
		ret = -ENOMEM;
		DMERR("Could not allocate crypt sub-request mempool\n");
		goto free_tfm;
	}

	ret = geniv_blkdev_cipher(ctx, is_crypto_aead);
	if (ret < 0) {
		ret = -ENOMEM;
		DMERR("Cannot allocate cipher string\n");
		goto free_tfm;
	}

	return 0;

free_tfm:
	if (is_crypto_aead)
		crypto_free_aead(ctx->tfm_child.tfm_aead);
	else
		crypto_free_skcipher(ctx->tfm_child.tfm);
free_algname:
	kfree(ctx->algname);
free_ciphermode:
	kfree(ctx->ciphermode);
	return ret;
}

static int geniv_skcipher_init_tfm(struct crypto_skcipher *tfm)
{
	return geniv_init_tfm(tfm, 0);
}

static int geniv_aead_init_tfm(struct crypto_aead *tfm)
{
	return geniv_init_tfm(tfm, 1);
}

static void geniv_exit_tfm(struct geniv_ctx *ctx)
{
	if (ctx->iv_gen_ops && ctx->iv_gen_ops->dtr)
		ctx->iv_gen_ops->dtr(ctx);

	mempool_destroy(ctx->subreq_pool);
	geniv_free_tfms(ctx);
	kzfree(ctx->ciphermode);
	kzfree(ctx->algname);
	kzfree(ctx->cipher);
}

static void geniv_skcipher_exit_tfm(struct crypto_skcipher *tfm)
{
	struct geniv_ctx *ctx = crypto_skcipher_ctx(tfm);

	geniv_exit_tfm(ctx);
}

static void geniv_aead_exit_tfm(struct crypto_aead *tfm)
{
	struct geniv_ctx *ctx = crypto_aead_ctx(tfm);

	geniv_exit_tfm(ctx);
}

static void geniv_skcipher_free(struct skcipher_instance *inst)
{
	struct crypto_skcipher_spawn *spawn = skcipher_instance_ctx(inst);

	crypto_drop_skcipher(spawn);
	kfree(inst);
}

static void geniv_aead_free(struct aead_instance *inst)
{
	struct crypto_aead_spawn *spawn = aead_instance_ctx(inst);

	crypto_drop_aead(spawn);
	kfree(inst);
}

static int geniv_skcipher_create(struct crypto_template *tmpl,
			struct rtattr **tb, char *algname)
{
	struct crypto_attr_type *algt;
	struct skcipher_instance *inst;
	struct skcipher_alg *alg;
	struct crypto_skcipher_spawn *spawn;
	const char *cipher_name;
	int err;

	algt = crypto_get_attr_type(tb);

	cipher_name = crypto_attr_alg_name(tb[1]);

	if (IS_ERR(cipher_name))
		return PTR_ERR(cipher_name);

	inst = kzalloc(sizeof(*inst) + sizeof(*spawn), GFP_KERNEL);
	if (!inst)
		return -ENOMEM;

	spawn = skcipher_instance_ctx(inst);

	crypto_set_skcipher_spawn(spawn, skcipher_crypto_instance(inst));
	err = crypto_grab_skcipher(spawn, cipher_name, 0,
				    crypto_requires_sync(algt->type,
							 algt->mask));

	if (err)
		goto err_free_inst;

	alg = crypto_spawn_skcipher_alg(spawn);

	err = -EINVAL;

	/* Only support blocks of size which is of a power of 2 */
	if (!is_power_of_2(alg->base.cra_blocksize))
		goto err_drop_spawn;

	/* algname: essiv, base.cra_name: cbc(aes) */
	err = -ENAMETOOLONG;
	if (snprintf(inst->alg.base.cra_name, CRYPTO_MAX_ALG_NAME, "%s(%s)",
		     algname, alg->base.cra_name) >= CRYPTO_MAX_ALG_NAME)
		goto err_drop_spawn;
	if (snprintf(inst->alg.base.cra_driver_name, CRYPTO_MAX_ALG_NAME,
		     "%s(%s)", algname, alg->base.cra_driver_name) >=
	    CRYPTO_MAX_ALG_NAME)
		goto err_drop_spawn;

	inst->alg.base.cra_flags = CRYPTO_ALG_TYPE_BLKCIPHER;
	inst->alg.base.cra_priority = alg->base.cra_priority;
	inst->alg.base.cra_blocksize = alg->base.cra_blocksize;
	inst->alg.base.cra_alignmask = alg->base.cra_alignmask;
	inst->alg.base.cra_flags = alg->base.cra_flags & CRYPTO_ALG_ASYNC;
	inst->alg.ivsize = alg->base.cra_blocksize;
	inst->alg.chunksize = crypto_skcipher_alg_chunksize(alg);
	inst->alg.min_keysize = sizeof(struct geniv_key_info);
	inst->alg.max_keysize = sizeof(struct geniv_key_info);

	inst->alg.setkey = geniv_skcipher_setkey;
	inst->alg.encrypt = geniv_skcipher_encrypt;
	inst->alg.decrypt = geniv_skcipher_decrypt;

	inst->alg.base.cra_ctxsize = sizeof(struct geniv_ctx);

	inst->alg.init = geniv_skcipher_init_tfm;
	inst->alg.exit = geniv_skcipher_exit_tfm;

	inst->free = geniv_skcipher_free;

	err = skcipher_register_instance(tmpl, inst);
	if (err)
		goto err_drop_spawn;

out:
	return err;

err_drop_spawn:
	crypto_drop_skcipher(spawn);
err_free_inst:
	kfree(inst);
	goto out;
}


static int geniv_aead_create(struct crypto_template *tmpl,
			struct rtattr **tb, char *algname)
{
	struct crypto_attr_type *algt;
	struct aead_instance *inst;
	struct aead_alg *alg;
	struct crypto_aead_spawn *spawn;
	const char *cipher_name;
	int err;

	algt = crypto_get_attr_type(tb);

	cipher_name = crypto_attr_alg_name(tb[1]);
	if (IS_ERR(cipher_name))
		return PTR_ERR(cipher_name);

	inst = kzalloc(sizeof(*inst) + sizeof(*spawn), GFP_KERNEL);
	if (!inst)
		return -ENOMEM;

	spawn = aead_instance_ctx(inst);

	crypto_set_aead_spawn(spawn, aead_crypto_instance(inst));
	err = crypto_grab_aead(spawn, cipher_name, 0,
				    crypto_requires_sync(algt->type,
							 algt->mask));
	if (err)
		goto err_free_inst;

	alg = crypto_spawn_aead_alg(spawn);

	/* Only support blocks of size which is of a power of 2 */
	if (!is_power_of_2(alg->base.cra_blocksize)) {
		err = -EINVAL;
		goto err_drop_spawn;
	}

	/* algname: essiv, base.cra_name: cbc(aes) */
	if (snprintf(inst->alg.base.cra_name, CRYPTO_MAX_ALG_NAME, "%s(%s)",
		     algname, alg->base.cra_name) >= CRYPTO_MAX_ALG_NAME) {
		err = -ENAMETOOLONG;
		goto err_drop_spawn;
	}

	if (snprintf(inst->alg.base.cra_driver_name, CRYPTO_MAX_ALG_NAME,
		     "%s(%s)", algname, alg->base.cra_driver_name) >=
	    CRYPTO_MAX_ALG_NAME) {
		err = -ENAMETOOLONG;
		goto err_drop_spawn;
	}

	inst->alg.base.cra_flags = CRYPTO_ALG_TYPE_BLKCIPHER;
	inst->alg.base.cra_priority = alg->base.cra_priority;
	inst->alg.base.cra_blocksize = alg->base.cra_blocksize;
	inst->alg.base.cra_alignmask = alg->base.cra_alignmask;
	inst->alg.base.cra_flags = alg->base.cra_flags & CRYPTO_ALG_ASYNC;
	inst->alg.ivsize = crypto_aead_alg_ivsize(alg);
	inst->alg.chunksize = crypto_aead_alg_chunksize(alg);
	inst->alg.maxauthsize = crypto_aead_alg_maxauthsize(alg);

	inst->alg.setkey = geniv_aead_setkey;
	inst->alg.encrypt = geniv_aead_encrypt;
	inst->alg.decrypt = geniv_aead_decrypt;

	inst->alg.base.cra_ctxsize = sizeof(struct geniv_ctx);

	inst->alg.init = geniv_aead_init_tfm;
	inst->alg.exit = geniv_aead_exit_tfm;

	inst->free = geniv_aead_free;

	err = aead_register_instance(tmpl, inst);
	if (err)
		goto err_drop_spawn;

	return 0;

err_drop_spawn:
	crypto_drop_aead(spawn);
err_free_inst:
	kfree(inst);
	return err;
}

static int geniv_create(struct crypto_template *tmpl,
			struct rtattr **tb, char *algname)
{
	if (!crypto_check_attr_type(tb, CRYPTO_ALG_TYPE_SKCIPHER))
		return geniv_skcipher_create(tmpl, tb, algname);
	else if (!crypto_check_attr_type(tb, CRYPTO_ALG_TYPE_AEAD))
		return geniv_aead_create(tmpl, tb, algname);
	else
		return -EINVAL;
}

static int geniv_template_create(struct crypto_template *tmpl,
			       struct rtattr **tb)
{
	return geniv_create(tmpl, tb, tmpl->name);
}

#define DECLARE_CRYPTO_TEMPLATE(type) \
	{ .name = type, \
	.create = geniv_template_create, \
	.module = THIS_MODULE, },

static struct crypto_template geniv_tmpl[] = {
	DECLARE_CRYPTO_TEMPLATE("plain")
	DECLARE_CRYPTO_TEMPLATE("plain64")
	DECLARE_CRYPTO_TEMPLATE("essiv")
	DECLARE_CRYPTO_TEMPLATE("benbi")
	DECLARE_CRYPTO_TEMPLATE("null")
	DECLARE_CRYPTO_TEMPLATE("lmk")
	DECLARE_CRYPTO_TEMPLATE("tcw")
	DECLARE_CRYPTO_TEMPLATE("random")
};

/*
 * Integrity extensions
 */
static bool crypt_integrity_aead(struct crypt_config *cc)
{
	return test_bit(CRYPT_MODE_INTEGRITY_AEAD, &cc->cipher_flags);
}

/* Get sg containing data */
static struct scatterlist *crypt_get_sg_data(struct geniv_ctx *ctx,
					     struct scatterlist *sg)
{
	if (unlikely(geniv_integrity_aead(ctx)))
		return &sg[2];

	return sg;
}

static int dm_crypt_integrity_io_alloc(struct dm_crypt_io *io, struct bio *bio)
{
	struct bio_integrity_payload *bip;
	unsigned int tag_len;
	int ret;

	if (!bio_sectors(bio) || !io->cc->on_disk_tag_size)
		return 0;

	bip = bio_integrity_alloc(bio, GFP_NOIO, 1);
	if (IS_ERR(bip))
		return PTR_ERR(bip);

	tag_len = io->cc->on_disk_tag_size * (bio_sectors(bio) >> io->cc->sector_shift);

	bip->bip_iter.bi_size = tag_len;
	bip->bip_iter.bi_sector = io->cc->start + io->sector;

	ret = bio_integrity_add_page(bio, virt_to_page(io->integrity_metadata),
				     tag_len, offset_in_page(io->integrity_metadata));
	if (unlikely(ret != tag_len))
		return -ENOMEM;

	return 0;
}

static int crypt_integrity_ctr(struct crypt_config *cc, struct dm_target *ti)
{
#ifdef CONFIG_BLK_DEV_INTEGRITY
	struct blk_integrity *bi = blk_get_integrity(cc->dev->bdev->bd_disk);
	struct mapped_device *md = dm_table_get_md(ti->table);

	/* From now we require underlying device with our integrity profile */
	if (!bi || strcasecmp(bi->profile->name, "DM-DIF-EXT-TAG")) {
		ti->error = "Integrity profile not supported.";
		return -EINVAL;
	}

	if (bi->tag_size != cc->on_disk_tag_size ||
	    bi->tuple_size != cc->on_disk_tag_size) {
		ti->error = "Integrity profile tag size mismatch.";
		return -EINVAL;
	}
	if (1 << bi->interval_exp != cc->sector_size) {
		ti->error = "Integrity profile sector size mismatch.";
		return -EINVAL;
	}

	if (crypt_integrity_aead(cc)) {
		cc->integrity_tag_size = cc->on_disk_tag_size - cc->integrity_iv_size;
		DMDEBUG("%s: Integrity AEAD, tag size %u, IV size %u.", dm_device_name(md),
		       cc->integrity_tag_size, cc->integrity_iv_size);

		if (crypto_aead_setauthsize(any_tfm_aead(cc), cc->integrity_tag_size)) {
			ti->error = "Integrity AEAD auth tag size is not supported.";
			return -EINVAL;
		}
	} else if (cc->integrity_iv_size)
		DMDEBUG("%s: Additional per-sector space %u bytes for IV.", dm_device_name(md),
		       cc->integrity_iv_size);

	if ((cc->integrity_tag_size + cc->integrity_iv_size) != bi->tag_size) {
		ti->error = "Not enough space for integrity tag in the profile.";
		return -EINVAL;
	}

	return 0;
#else
	ti->error = "Integrity profile not supported.";
	return -EINVAL;
#endif
}

static void crypt_convert_init(struct crypt_config *cc,
			       struct convert_context *ctx,
			       struct bio *bio_out, struct bio *bio_in,
			       sector_t sector)
{
	ctx->bio_in = bio_in;
	ctx->bio_out = bio_out;
	if (bio_in)
		ctx->iter_in = bio_in->bi_iter;
	if (bio_out)
		ctx->iter_out = bio_out->bi_iter;
	ctx->cc_sector = sector + cc->iv_offset;
	init_completion(&ctx->restart);
}

static struct dm_crypt_request *dmreq_of_req(struct crypt_config *cc,
					     void *req)
{
	return (struct dm_crypt_request *)((char *)req + cc->dmreq_start);
}

static void *req_of_dmreq(struct crypt_config *cc, struct dm_crypt_request *dmreq)
{
	return (void *)((char *)dmreq - cc->dmreq_start);
}


static void kcryptd_async_done(struct crypto_async_request *async_req,
			       int error);

static void crypt_alloc_req_skcipher(struct crypt_config *cc,
				     struct convert_context *ctx)
{
	if (!ctx->r.req)
		ctx->r.req = mempool_alloc(&cc->req_pool, GFP_NOIO);

	skcipher_request_set_tfm(ctx->r.req, cc->cipher_tfm.tfm);

	/*
	 * Use REQ_MAY_BACKLOG so a cipher driver internally backlogs
	 * requests if driver request queue is full.
	 */
	skcipher_request_set_callback(ctx->r.req,
	    CRYPTO_TFM_REQ_MAY_BACKLOG,
	    kcryptd_async_done, dmreq_of_req(cc, ctx->r.req));
}

static void crypt_alloc_req_aead(struct crypt_config *cc,
				 struct convert_context *ctx)
{
	if (!ctx->r.req_aead)
		ctx->r.req_aead = mempool_alloc(&cc->req_pool, GFP_NOIO);

	aead_request_set_tfm(ctx->r.req_aead, cc->cipher_tfm.tfm_aead);

	/*
	 * Use REQ_MAY_BACKLOG so a cipher driver internally backlogs
	 * requests if driver request queue is full.
	 */
	aead_request_set_callback(ctx->r.req_aead,
	    CRYPTO_TFM_REQ_MAY_BACKLOG,
	    kcryptd_async_done, dmreq_of_req(cc, ctx->r.req_aead));
}

static void crypt_alloc_req(struct crypt_config *cc,
			    struct convert_context *ctx)
{
	if (crypt_integrity_aead(cc))
		crypt_alloc_req_aead(cc, ctx);
	else
		crypt_alloc_req_skcipher(cc, ctx);
}

static void crypt_free_req_skcipher(struct crypt_config *cc,
				    struct skcipher_request *req, struct bio *base_bio)
{
	struct dm_crypt_io *io = dm_per_bio_data(base_bio, cc->per_bio_data_size);

	if ((struct skcipher_request *)(io + 1) != req)
		mempool_free(req, &cc->req_pool);
}

static void crypt_free_req_aead(struct crypt_config *cc,
				struct aead_request *req, struct bio *base_bio)
{
	struct dm_crypt_io *io = dm_per_bio_data(base_bio, cc->per_bio_data_size);

	if ((struct aead_request *)(io + 1) != req)
		mempool_free(req, &cc->req_pool);
}

static void crypt_free_req(struct crypt_config *cc, void *req, struct bio *base_bio)
{
	if (crypt_integrity_aead(cc))
		crypt_free_req_aead(cc, req, base_bio);
	else
		crypt_free_req_skcipher(cc, req, base_bio);
}

/*
 * Encrypt / decrypt data from one bio to another one (can be the same one)
 */
static blk_status_t crypt_convert_bio(struct crypt_config *cc,
					struct convert_context *ctx)
{
	unsigned int cryptlen, n1, n2, nents, i = 0, bytes = 0;
	struct skcipher_request *req = NULL;
	struct aead_request *req_aead = NULL;
	struct dm_crypt_request *dmreq;
	struct dm_crypt_io *io = container_of(ctx, struct dm_crypt_io, ctx);
	struct geniv_req_info rinfo;
	struct bio_vec bv_in, bv_out;
	int r;

	atomic_set(&ctx->cc_pending, 1);
	crypt_alloc_req(cc, ctx);

	if (crypt_integrity_aead(cc)) {
		req_aead = ctx->r.req_aead;
		dmreq = dmreq_of_req(cc, req_aead);
	} else {
		req = ctx->r.req;
		dmreq = dmreq_of_req(cc, req);
	}

	n1 = bio_segments(ctx->bio_in);
	n2 = bio_segments(ctx->bio_out);
	nents = max(n1, n2);
	nents = min((unsigned int)MAX_SG_LIST, nents);
	cryptlen = ctx->iter_in.bi_size;

	DMDEBUG("dm-crypt:%s: segments:[in=%u, out=%u] bi_size=%u\n",
		bio_data_dir(ctx->bio_in) == WRITE ? "write" : "read",
		n1, n2, cryptlen);

	dmreq->sg_in = kcalloc(nents, sizeof(struct scatterlist), GFP_KERNEL);
	dmreq->sg_out = kcalloc(nents, sizeof(struct scatterlist), GFP_KERNEL);
	if (!dmreq->sg_in || !dmreq->sg_out) {
		DMERR("dm-crypt: Failed to allocate scatterlist\n");
		r = -ENOMEM;
		return r;
	}
	dmreq->ctx = ctx;

	sg_init_table(dmreq->sg_in, nents);
	sg_init_table(dmreq->sg_out, nents);

	while (ctx->iter_in.bi_size && ctx->iter_out.bi_size && i < nents) {
		bv_in = bio_iter_iovec(ctx->bio_in, ctx->iter_in);
		bv_out = bio_iter_iovec(ctx->bio_out, ctx->iter_out);

		sg_set_page(&dmreq->sg_in[i], bv_in.bv_page, bv_in.bv_len,
				bv_in.bv_offset);
		sg_set_page(&dmreq->sg_out[i], bv_out.bv_page, bv_out.bv_len,
				bv_out.bv_offset);

		bio_advance_iter(ctx->bio_in, &ctx->iter_in, bv_in.bv_len);
		bio_advance_iter(ctx->bio_out, &ctx->iter_out, bv_out.bv_len);

		bytes += bv_in.bv_len;
		i++;
	}

	DMDEBUG("dm-crypt: Processed %u of %u bytes\n", bytes, cryptlen);

	rinfo.cc_sector = ctx->cc_sector;
	rinfo.nents = nents;
	rinfo.integrity_metadata = io->integrity_metadata;

	atomic_inc(&ctx->cc_pending);
	if (crypt_integrity_aead(cc)) {
		aead_request_set_crypt(req_aead, dmreq->sg_in, dmreq->sg_out,
					bytes, (u8 *)&rinfo);
		if (bio_data_dir(ctx->bio_in) == WRITE)
			r = crypto_aead_encrypt(req_aead);
		else
			r = crypto_aead_decrypt(req_aead);
	} else {
		skcipher_request_set_crypt(req, dmreq->sg_in, dmreq->sg_out,
					bytes, (u8 *)&rinfo);
		if (bio_data_dir(ctx->bio_in) == WRITE)
			r = crypto_skcipher_encrypt(req);
		else
			r = crypto_skcipher_decrypt(req);
	}

	switch (r) {
	/* The request was queued so wait. */
	case -EBUSY:
		wait_for_completion(&ctx->restart);
		reinit_completion(&ctx->restart);
		/* fall through */
	/*
	 * The request is queued and processed asynchronously,
	 * completion function kcryptd_async_done() is called.
	 */
	case -EINPROGRESS:
		ctx->r.req = NULL;
		cond_resched();
		return 0;
	/* The requeest was already processed (synchronously). */
	case 0:
		atomic_dec(&ctx->cc_pending);
		return 0;
	/* There was a data integrity error. */
	case -EBADMSG:
		atomic_dec(&ctx->cc_pending);
		return BLK_STS_PROTECTION;
	/* There was an error while processing the request. */
	default:
		atomic_dec(&ctx->cc_pending);
		return BLK_STS_IOERR;
	}
}

static void crypt_free_buffer_pages(struct crypt_config *cc, struct bio *clone);

/*
 * Generate a new unfragmented bio with the given size
 * This should never violate the device limitations (but only because
 * max_segment_size is being constrained to PAGE_SIZE).
 *
 * This function may be called concurrently. If we allocate from the mempool
 * concurrently, there is a possibility of deadlock. For example, if we have
 * mempool of 256 pages, two processes, each wanting 256, pages allocate from
 * the mempool concurrently, it may deadlock in a situation where both processes
 * have allocated 128 pages and the mempool is exhausted.
 *
 * In order to avoid this scenario we allocate the pages under a mutex.
 *
 * In order to not degrade performance with excessive locking, we try
 * non-blocking allocations without a mutex first but on failure we fallback
 * to blocking allocations with a mutex.
 */
static struct bio *crypt_alloc_buffer(struct dm_crypt_io *io, unsigned size)
{
	struct crypt_config *cc = io->cc;
	struct bio *clone;
	unsigned int nr_iovecs = (size + PAGE_SIZE - 1) >> PAGE_SHIFT;
	gfp_t gfp_mask = GFP_NOWAIT | __GFP_HIGHMEM;
	unsigned i, len, remaining_size;
	struct page *page;

retry:
	if (unlikely(gfp_mask & __GFP_DIRECT_RECLAIM))
		mutex_lock(&cc->bio_alloc_lock);

	clone = bio_alloc_bioset(GFP_NOIO, nr_iovecs, &cc->bs);
	if (!clone)
		goto out;

	clone_init(io, clone);

	remaining_size = size;

	for (i = 0; i < nr_iovecs; i++) {
		page = mempool_alloc(&cc->page_pool, gfp_mask);
		if (!page) {
			crypt_free_buffer_pages(cc, clone);
			bio_put(clone);
			gfp_mask |= __GFP_DIRECT_RECLAIM;
			goto retry;
		}

		len = (remaining_size > PAGE_SIZE) ? PAGE_SIZE : remaining_size;

		bio_add_page(clone, page, len, 0);

		remaining_size -= len;
	}

	/* Allocate space for integrity tags */
	if (dm_crypt_integrity_io_alloc(io, clone)) {
		crypt_free_buffer_pages(cc, clone);
		bio_put(clone);
		clone = NULL;
	}
out:
	if (unlikely(gfp_mask & __GFP_DIRECT_RECLAIM))
		mutex_unlock(&cc->bio_alloc_lock);

	return clone;
}

static void crypt_free_buffer_pages(struct crypt_config *cc, struct bio *clone)
{
	unsigned int i;
	struct bio_vec *bv;

	bio_for_each_segment_all(bv, clone, i) {
		BUG_ON(!bv->bv_page);
		mempool_free(bv->bv_page, &cc->page_pool);
	}
}

static void crypt_io_init(struct dm_crypt_io *io, struct crypt_config *cc,
			  struct bio *bio, sector_t sector)
{
	io->cc = cc;
	io->base_bio = bio;
	io->sector = sector;
	io->error = 0;
	io->ctx.r.req = NULL;
	io->integrity_metadata = NULL;
	io->integrity_metadata_from_pool = false;
	atomic_set(&io->io_pending, 0);
}

static void crypt_inc_pending(struct dm_crypt_io *io)
{
	atomic_inc(&io->io_pending);
}

/*
 * One of the bios was finished. Check for completion of
 * the whole request and correctly clean up the buffer.
 */
static void crypt_dec_pending(struct dm_crypt_io *io)
{
	struct crypt_config *cc = io->cc;
	struct bio *base_bio = io->base_bio;
	struct dm_crypt_request *dmreq;
	blk_status_t error = io->error;

	if (!atomic_dec_and_test(&io->io_pending))
		return;

	if (io->ctx.r.req) {
		crypt_free_req(cc, io->ctx.r.req, base_bio);

		if (crypt_integrity_aead(cc))
			dmreq = dmreq_of_req(cc, io->ctx.r.req_aead);
		else
			dmreq = dmreq_of_req(cc, io->ctx.r.req);
		DMDEBUG("dm-crypt: Freeing scatterlists [sync]\n");
		kfree(dmreq->sg_in);
		kfree(dmreq->sg_out);
	}

	if (unlikely(io->integrity_metadata_from_pool))
		mempool_free(io->integrity_metadata, &io->cc->tag_pool);
	else
		kfree(io->integrity_metadata);

	base_bio->bi_status = error;
	bio_endio(base_bio);
}

/*
 * kcryptd/kcryptd_io:
 *
 * Needed because it would be very unwise to do decryption in an
 * interrupt context.
 *
 * kcryptd performs the actual encryption or decryption.
 *
 * kcryptd_io performs the IO submission.
 *
 * They must be separated as otherwise the final stages could be
 * starved by new requests which can block in the first stages due
 * to memory allocation.
 *
 * The work is done per CPU global for all dm-crypt instances.
 * They should not depend on each other and do not block.
 */
static void crypt_endio(struct bio *clone)
{
	struct dm_crypt_io *io = clone->bi_private;
	struct crypt_config *cc = io->cc;
	unsigned rw = bio_data_dir(clone);
	blk_status_t error;

	/*
	 * free the processed pages
	 */
	if (rw == WRITE)
		crypt_free_buffer_pages(cc, clone);

	error = clone->bi_status;
	bio_put(clone);

	if (rw == READ && !error) {
		kcryptd_queue_crypt(io);
		return;
	}

	if (unlikely(error))
		io->error = error;

	crypt_dec_pending(io);
}

static void clone_init(struct dm_crypt_io *io, struct bio *clone)
{
	struct crypt_config *cc = io->cc;

	clone->bi_private = io;
	clone->bi_end_io  = crypt_endio;
	bio_set_dev(clone, cc->dev->bdev);
	clone->bi_opf	  = io->base_bio->bi_opf;
}

static int kcryptd_io_read(struct dm_crypt_io *io, gfp_t gfp)
{
	struct crypt_config *cc = io->cc;
	struct bio *clone;

	/*
	 * We need the original biovec array in order to decrypt
	 * the whole bio data *afterwards* -- thanks to immutable
	 * biovecs we don't need to worry about the block layer
	 * modifying the biovec array; so leverage bio_clone_fast().
	 */
	clone = bio_clone_fast(io->base_bio, gfp, &cc->bs);
	if (!clone)
		return 1;

	crypt_inc_pending(io);

	clone_init(io, clone);
	clone->bi_iter.bi_sector = cc->start + io->sector;

	if (dm_crypt_integrity_io_alloc(io, clone)) {
		crypt_dec_pending(io);
		bio_put(clone);
		return 1;
	}

	generic_make_request(clone);
	return 0;
}

static void kcryptd_io_read_work(struct work_struct *work)
{
	struct dm_crypt_io *io = container_of(work, struct dm_crypt_io, work);

	crypt_inc_pending(io);
	if (kcryptd_io_read(io, GFP_NOIO))
		io->error = BLK_STS_RESOURCE;
	crypt_dec_pending(io);
}

static void kcryptd_queue_read(struct dm_crypt_io *io)
{
	struct crypt_config *cc = io->cc;

	INIT_WORK(&io->work, kcryptd_io_read_work);
	queue_work(cc->io_queue, &io->work);
}

static void kcryptd_io_write(struct dm_crypt_io *io)
{
	struct bio *clone = io->ctx.bio_out;

	generic_make_request(clone);
}

#define crypt_io_from_node(node) rb_entry((node), struct dm_crypt_io, rb_node)

static int dmcrypt_write(void *data)
{
	struct crypt_config *cc = data;
	struct dm_crypt_io *io;

	while (1) {
		struct rb_root write_tree;
		struct blk_plug plug;

		spin_lock_irq(&cc->write_thread_lock);
continue_locked:

		if (!RB_EMPTY_ROOT(&cc->write_tree))
			goto pop_from_list;

		set_current_state(TASK_INTERRUPTIBLE);

		spin_unlock_irq(&cc->write_thread_lock);

		if (unlikely(kthread_should_stop())) {
			set_current_state(TASK_RUNNING);
			break;
		}

		schedule();

		set_current_state(TASK_RUNNING);
		spin_lock_irq(&cc->write_thread_lock);
		goto continue_locked;

pop_from_list:
		write_tree = cc->write_tree;
		cc->write_tree = RB_ROOT;
		spin_unlock_irq(&cc->write_thread_lock);

		BUG_ON(rb_parent(write_tree.rb_node));

		/*
		 * Note: we cannot walk the tree here with rb_next because
		 * the structures may be freed when kcryptd_io_write is called.
		 */
		blk_start_plug(&plug);
		do {
			io = crypt_io_from_node(rb_first(&write_tree));
			rb_erase(&io->rb_node, &write_tree);
			kcryptd_io_write(io);
		} while (!RB_EMPTY_ROOT(&write_tree));
		blk_finish_plug(&plug);
	}
	return 0;
}

static void kcryptd_crypt_write_io_submit(struct dm_crypt_io *io, int async)
{
	struct bio *clone = io->ctx.bio_out;
	struct crypt_config *cc = io->cc;
	unsigned long flags;
	sector_t sector;
	struct rb_node **rbp, *parent;

	if (unlikely(io->error)) {
		crypt_free_buffer_pages(cc, clone);
		bio_put(clone);
		crypt_dec_pending(io);
		return;
	}

	/* crypt_convert should have filled the clone bio */
	BUG_ON(io->ctx.iter_out.bi_size);

	clone->bi_iter.bi_sector = cc->start + io->sector;

	if (likely(!async) && test_bit(DM_CRYPT_NO_OFFLOAD, &cc->flags)) {
		generic_make_request(clone);
		return;
	}

	spin_lock_irqsave(&cc->write_thread_lock, flags);
	if (RB_EMPTY_ROOT(&cc->write_tree))
		wake_up_process(cc->write_thread);
	rbp = &cc->write_tree.rb_node;
	parent = NULL;
	sector = io->sector;
	while (*rbp) {
		parent = *rbp;
		if (sector < crypt_io_from_node(parent)->sector)
			rbp = &(*rbp)->rb_left;
		else
			rbp = &(*rbp)->rb_right;
	}
	rb_link_node(&io->rb_node, parent, rbp);
	rb_insert_color(&io->rb_node, &cc->write_tree);
	spin_unlock_irqrestore(&cc->write_thread_lock, flags);
}

static void kcryptd_crypt_write_convert(struct dm_crypt_io *io)
{
	struct crypt_config *cc = io->cc;
	struct bio *clone;
	int crypt_finished;
	sector_t sector = io->sector;
	blk_status_t r;

	/*
	 * Prevent io from disappearing until this function completes.
	 */
	crypt_inc_pending(io);
	crypt_convert_init(cc, &io->ctx, NULL, io->base_bio, sector);

	clone = crypt_alloc_buffer(io, io->base_bio->bi_iter.bi_size);
	if (unlikely(!clone)) {
		io->error = BLK_STS_IOERR;
		goto dec;
	}

	io->ctx.bio_out = clone;
	io->ctx.iter_out = clone->bi_iter;

	sector += bio_sectors(clone);

	crypt_inc_pending(io);
	r = crypt_convert_bio(cc, &io->ctx);
	if (r)
		io->error = r;
	crypt_finished = atomic_dec_and_test(&io->ctx.cc_pending);

	/* Encryption was already finished, submit io now */
	if (crypt_finished) {
		kcryptd_crypt_write_io_submit(io, 0);
		io->sector = sector;
	}

dec:
	crypt_dec_pending(io);
}

static void kcryptd_crypt_read_done(struct dm_crypt_io *io)
{
	crypt_dec_pending(io);
}

static void kcryptd_crypt_read_convert(struct dm_crypt_io *io)
{
	struct crypt_config *cc = io->cc;
	blk_status_t r;

	crypt_inc_pending(io);

	crypt_convert_init(cc, &io->ctx, io->base_bio, io->base_bio,
			   io->sector);

	r = crypt_convert_bio(cc, &io->ctx);
	if (r)
		io->error = r;

	if (atomic_dec_and_test(&io->ctx.cc_pending))
		kcryptd_crypt_read_done(io);

	crypt_dec_pending(io);
}

static void kcryptd_async_done(struct crypto_async_request *async_req,
			       int error)
{
	struct dm_crypt_request *dmreq = async_req->data;
	struct convert_context *ctx = dmreq->ctx;
	struct dm_crypt_io *io = container_of(ctx, struct dm_crypt_io, ctx);
	struct crypt_config *cc = io->cc;

	/*
	 * A request from crypto driver backlog is going to be processed now,
	 * finish the completion and continue in crypt_convert().
	 * (Callback will be called for the second time for this request.)
	 */
	if (error == -EINPROGRESS) {
		complete(&ctx->restart);
		return;
	}

	if (error == -EBADMSG) {
		DMERR("INTEGRITY AEAD ERROR\n");
		io->error = BLK_STS_PROTECTION;
	} else if (error < 0)
		io->error = BLK_STS_IOERR;

	DMDEBUG("dm-crypt: Freeing scatterlists and request struct [async]\n");
	kfree(dmreq->sg_in);
	kfree(dmreq->sg_out);

	crypt_free_req(cc, req_of_dmreq(cc, dmreq), io->base_bio);

	if (!atomic_dec_and_test(&ctx->cc_pending))
		return;

	if (bio_data_dir(io->base_bio) == READ)
		kcryptd_crypt_read_done(io);
	else
		kcryptd_crypt_write_io_submit(io, 1);
}

static void kcryptd_crypt(struct work_struct *work)
{
	struct dm_crypt_io *io = container_of(work, struct dm_crypt_io, work);

	if (bio_data_dir(io->base_bio) == READ)
		kcryptd_crypt_read_convert(io);
	else
		kcryptd_crypt_write_convert(io);
}

static void kcryptd_queue_crypt(struct dm_crypt_io *io)
{
	struct crypt_config *cc = io->cc;

	INIT_WORK(&io->work, kcryptd_crypt);
	queue_work(cc->crypt_queue, &io->work);
}

static void crypt_free_tfm(struct crypt_config *cc)
{
	if (crypt_integrity_aead(cc)) {
		if (!cc->cipher_tfm.tfm_aead)
			return;
		if (cc->cipher_tfm.tfm_aead && !IS_ERR(cc->cipher_tfm.tfm_aead)) {
			crypto_free_aead(cc->cipher_tfm.tfm_aead);
			cc->cipher_tfm.tfm_aead = NULL;
		}
	} else {
		if (!cc->cipher_tfm.tfm)
			return;
		if (cc->cipher_tfm.tfm && !IS_ERR(cc->cipher_tfm.tfm)) {
			crypto_free_skcipher(cc->cipher_tfm.tfm);
			cc->cipher_tfm.tfm = NULL;
		}
	}
}

static int crypt_alloc_tfm(struct crypt_config *cc, char *ciphermode)
{
	int err;

	if (crypt_integrity_aead(cc)) {
		cc->cipher_tfm.tfm_aead = crypto_alloc_aead(ciphermode, 0, 0);
		if (IS_ERR(cc->cipher_tfm.tfm_aead)) {
			err = PTR_ERR(cc->cipher_tfm.tfm_aead);
			crypt_free_tfm(cc);
			return err;
		}
	} else {
		cc->cipher_tfm.tfm = crypto_alloc_skcipher(ciphermode, 0, 0);
		if (IS_ERR(cc->cipher_tfm.tfm)) {
			err = PTR_ERR(cc->cipher_tfm.tfm);
			crypt_free_tfm(cc);
			return err;
		}
	}

	return 0;
}

static void init_key_info(struct crypt_config *cc, enum setkey_op keyop,
			char *ivopts, struct geniv_key_info *kinfo)
{
	kinfo->keyop = keyop;
	kinfo->tfms_count = cc->tfms_count;
	kinfo->key = cc->key;
	kinfo->cipher_flags = cc->cipher_flags;
	kinfo->ivopts = ivopts;
	kinfo->iv_offset = cc->iv_offset;
	kinfo->sector_size = cc->sector_size;
	kinfo->key_size = cc->key_size;
	kinfo->key_parts = cc->key_parts;
	kinfo->key_mac_size = cc->key_mac_size;
	kinfo->on_disk_tag_size = cc->on_disk_tag_size;
}

static int crypt_setkey(struct crypt_config *cc, enum setkey_op keyop,
			char *ivopts)
{
	int r = 0;
	struct geniv_key_info kinfo;

	init_key_info(cc, keyop, ivopts, &kinfo);

	if (crypt_integrity_aead(cc))
		r = crypto_aead_setkey(cc->cipher_tfm.tfm_aead, (u8 *)&kinfo, sizeof(kinfo));
	else
		r = crypto_skcipher_setkey(cc->cipher_tfm.tfm, (u8 *)&kinfo, sizeof(kinfo));

	return r;
}

#ifdef CONFIG_KEYS

static bool contains_whitespace(const char *str)
{
	while (*str)
		if (isspace(*str++))
			return true;
	return false;
}

static int crypt_set_keyring_key(struct crypt_config *cc,
				const char *key_string,
				enum setkey_op keyop, char *ivopts)
{
	char *new_key_string, *key_desc;
	int ret;
	struct key *key;
	const struct user_key_payload *ukp;

	/*
	 * Reject key_string with whitespace. dm core currently lacks code for
	 * proper whitespace escaping in arguments on DM_TABLE_STATUS path.
	 */
	if (contains_whitespace(key_string)) {
		DMERR("whitespace chars not allowed in key string");
		return -EINVAL;
	}

	/* look for next ':' separating key_type from key_description */
	key_desc = strpbrk(key_string, ":");
	if (!key_desc || key_desc == key_string || !strlen(key_desc + 1))
		return -EINVAL;

	if (strncmp(key_string, "logon:", key_desc - key_string + 1) &&
	    strncmp(key_string, "user:", key_desc - key_string + 1))
		return -EINVAL;

	new_key_string = kstrdup(key_string, GFP_KERNEL);
	if (!new_key_string)
		return -ENOMEM;

	key = request_key(key_string[0] == 'l' ? &key_type_logon : &key_type_user,
			  key_desc + 1, NULL);
	if (IS_ERR(key)) {
		kzfree(new_key_string);
		return PTR_ERR(key);
	}

	down_read(&key->sem);

	ukp = user_key_payload_locked(key);
	if (!ukp) {
		up_read(&key->sem);
		key_put(key);
		kzfree(new_key_string);
		return -EKEYREVOKED;
	}

	if (cc->key_size != ukp->datalen) {
		up_read(&key->sem);
		key_put(key);
		kzfree(new_key_string);
		return -EINVAL;
	}

	memcpy(cc->key, ukp->data, cc->key_size);

	up_read(&key->sem);
	key_put(key);

	/* clear the flag since following operations may invalidate previously valid key */
	clear_bit(DM_CRYPT_KEY_VALID, &cc->flags);

	ret = crypt_setkey(cc, keyop, ivopts);

	if (!ret) {
		set_bit(DM_CRYPT_KEY_VALID, &cc->flags);
		kzfree(cc->key_string);
		cc->key_string = new_key_string;
	} else
		kzfree(new_key_string);

	return ret;
}

static int get_key_size(char **key_string)
{
	char *colon, dummy;
	int ret;

	if (*key_string[0] != ':')
		return strlen(*key_string) >> 1;

	/* look for next ':' in key string */
	colon = strpbrk(*key_string + 1, ":");
	if (!colon)
		return -EINVAL;

	if (sscanf(*key_string + 1, "%u%c", &ret, &dummy) != 2 || dummy != ':')
		return -EINVAL;

	*key_string = colon;

	/* remaining key string should be :<logon|user>:<key_desc> */

	return ret;
}

#else

static int crypt_set_keyring_key(struct crypt_config *cc,
				const char *key_string,
				enum setkey_op keyop, char *ivopts)
{
	return -EINVAL;
}

static int get_key_size(char **key_string)
{
	return (*key_string[0] == ':') ? -EINVAL : strlen(*key_string) >> 1;
}

#endif

static int crypt_set_key(struct crypt_config *cc, enum setkey_op keyop,
			char *key, char *ivopts)
{
	int r = -EINVAL;
	int key_string_len = strlen(key);

	/* Hyphen (which gives a key_size of zero) means there is no key. */
	if (!cc->key_size && strcmp(key, "-"))
		goto out;

	/* ':' means the key is in kernel keyring, short-circuit normal key processing */
	if (key[0] == ':') {
		r = crypt_set_keyring_key(cc, key + 1, keyop, ivopts);
		goto out;
	}

	/* clear the flag since following operations may invalidate previously valid key */
	clear_bit(DM_CRYPT_KEY_VALID, &cc->flags);

	/* wipe references to any kernel keyring key */
	kzfree(cc->key_string);
	cc->key_string = NULL;

	/* Decode key from its hex representation. */
	if (cc->key_size && hex2bin(cc->key, key, cc->key_size) < 0)
		goto out;

	r = crypt_setkey(cc, keyop, ivopts);
	if (!r)
		set_bit(DM_CRYPT_KEY_VALID, &cc->flags);

out:
	/* Hex key string not needed after here, so wipe it. */
	memset(key, '0', key_string_len);

	return r;
}

static int crypt_init_key(struct dm_target *ti, char *key, char *ivopts)
{
	struct crypt_config *cc = ti->private;
	int ret;

	ret = crypt_set_key(cc, SETKEY_OP_INIT, key, ivopts);
	if (ret < 0)
		ti->error = "Error decoding and setting key";
	return ret;
}

static int crypt_wipe_key(struct crypt_config *cc)
{
	int r;

	clear_bit(DM_CRYPT_KEY_VALID, &cc->flags);
	get_random_bytes(&cc->key, cc->key_size);
	kzfree(cc->key_string);
	cc->key_string = NULL;
	r = crypt_setkey(cc, SETKEY_OP_WIPE, NULL);
	memset(&cc->key, 0, cc->key_size * sizeof(u8));

	return r;
}

static void crypt_calculate_pages_per_client(void)
{
	unsigned long pages = (totalram_pages - totalhigh_pages) * DM_CRYPT_MEMORY_PERCENT / 100;

	if (!dm_crypt_clients_n)
		return;

	pages /= dm_crypt_clients_n;
	if (pages < DM_CRYPT_MIN_PAGES_PER_CLIENT)
		pages = DM_CRYPT_MIN_PAGES_PER_CLIENT;
	dm_crypt_pages_per_client = pages;
}

static void *crypt_page_alloc(gfp_t gfp_mask, void *pool_data)
{
	struct crypt_config *cc = pool_data;
	struct page *page;

	if (unlikely(percpu_counter_compare(&cc->n_allocated_pages, dm_crypt_pages_per_client) >= 0) &&
	    likely(gfp_mask & __GFP_NORETRY))
		return NULL;

	page = alloc_page(gfp_mask);
	if (likely(page != NULL))
		percpu_counter_add(&cc->n_allocated_pages, 1);

	return page;
}

static void crypt_page_free(void *page, void *pool_data)
{
	struct crypt_config *cc = pool_data;

	__free_page(page);
	percpu_counter_sub(&cc->n_allocated_pages, 1);
}

static void crypt_dtr(struct dm_target *ti)
{
	struct crypt_config *cc = ti->private;

	ti->private = NULL;

	if (!cc)
		return;

	if (cc->write_thread)
		kthread_stop(cc->write_thread);

	if (cc->io_queue)
		destroy_workqueue(cc->io_queue);
	if (cc->crypt_queue)
		destroy_workqueue(cc->crypt_queue);

	crypt_free_tfm(cc);

	bioset_exit(&cc->bs);

	mempool_exit(&cc->page_pool);
	mempool_exit(&cc->req_pool);
	mempool_exit(&cc->tag_pool);

	WARN_ON(percpu_counter_sum(&cc->n_allocated_pages) != 0);
	percpu_counter_destroy(&cc->n_allocated_pages);

	if (cc->dev)
		dm_put_device(ti, cc->dev);

	kzfree(cc->cipher_string);
	kzfree(cc->key_string);
	kzfree(cc->cipher_auth);

	mutex_destroy(&cc->bio_alloc_lock);

	/* Must zero key material before freeing */
	kzfree(cc);

	spin_lock(&dm_crypt_clients_lock);
	WARN_ON(!dm_crypt_clients_n);
	dm_crypt_clients_n--;
	crypt_calculate_pages_per_client();
	spin_unlock(&dm_crypt_clients_lock);
}

static int get_iv_size_by_name(struct crypt_config *cc, char *alg_name)
{
	unsigned int iv_size;
	struct crypto_aead *tfm_aead;
	struct crypto_skcipher *tfm;

	if (crypt_integrity_aead(cc)) {
		tfm_aead = crypto_alloc_aead(alg_name, 0, 0);
		if (IS_ERR(tfm_aead))
			return -ENOMEM;

		iv_size = crypto_aead_ivsize(tfm_aead);
		crypto_free_aead(tfm_aead);
	} else {
		tfm = crypto_alloc_skcipher(alg_name, 0, 0);
		if (IS_ERR(tfm))
			return -ENOMEM;

		iv_size = crypto_skcipher_ivsize(tfm);
		crypto_free_skcipher(tfm);
	}

	return iv_size;

}

static int crypt_ctr_ivmode(struct dm_target *ti, const char *ivmode)
{
	struct crypt_config *cc = ti->private;

	if (crypt_integrity_aead(cc))
		cc->iv_size = crypto_aead_ivsize(any_tfm_aead(cc));
	else
		cc->iv_size = crypto_skcipher_ivsize(any_tfm(cc));

	if (cc->iv_size)
		/* at least a 64 bit sector number should fit in our buffer */
		cc->iv_size = max(cc->iv_size,
				  (unsigned int)(sizeof(u64) / sizeof(u8)));

	if (strcmp(ivmode, "random") == 0) {
		/* Need storage space in integrity fields. */
		cc->integrity_iv_size = cc->iv_size;
	}

	return 0;
}

/*
 * Workaround to parse HMAC algorithm from AEAD crypto API spec.
 * The HMAC is needed to calculate tag size (HMAC digest size).
 * This should be probably done by crypto-api calls (once available...)
 */
static int crypt_ctr_auth_cipher(struct crypt_config *cc, char *cipher_api)
{
	char *start, *end, *mac_alg = NULL;
	struct crypto_ahash *mac;

	if (!strstarts(cipher_api, "authenc("))
		return 0;

	start = strchr(cipher_api, '(');
	end = strchr(cipher_api, ',');
	if (!start || !end || ++start > end)
		return -EINVAL;

	mac_alg = kzalloc(end - start + 1, GFP_KERNEL);
	if (!mac_alg)
		return -ENOMEM;
	strncpy(mac_alg, start, end - start);

	mac = crypto_alloc_ahash(mac_alg, 0, 0);
	kfree(mac_alg);

	if (IS_ERR(mac))
		return PTR_ERR(mac);

	cc->key_mac_size = crypto_ahash_digestsize(mac);
	crypto_free_ahash(mac);

	return 0;
}

static int crypt_ctr_cipher_new(struct dm_target *ti, char *cipher_in, char *key,
				char **ivmode, char **ivopts)
{
	struct crypt_config *cc = ti->private;
	char *tmp, *cipher_api;
	char cipher_name[CRYPTO_MAX_ALG_NAME];
	int ret = -EINVAL;

	cc->tfms_count = 1;

	/*
	 * New format (capi: prefix)
	 * capi:cipher_api_spec-iv:ivopts
	 */
	tmp = &cipher_in[strlen("capi:")];

	/* Separate IV options if present, it can contain another '-' in hash name */
	*ivopts = strrchr(tmp, ':');
	if (*ivopts) {
		**ivopts = '\0';
		(*ivopts)++;
	}
	/* Parse IV mode */
	*ivmode = strrchr(tmp, '-');
	if (*ivmode) {
		**ivmode = '\0';
		(*ivmode)++;
	}
	/* The rest is crypto API spec */
	cipher_api = tmp;

	if (*ivmode && !strcmp(*ivmode, "lmk"))
		cc->tfms_count = 64;

	cc->key_parts = cc->tfms_count;

	if (!*ivmode)
		*ivmode = "null";

	/*
	 * For those ciphers which do not support IVs, but input ivmode is not
	 * NULL, use "null" as ivmode compulsively.
	 */
	cc->iv_size = get_iv_size_by_name(cc, cipher_api);
	if (cc->iv_size < 0)
		return -ENOMEM;
	if (!cc->iv_size && ivmode) {
		DMWARN("Selected cipher does not support IVs");
		*ivmode = "null";
	}

	/* Allocate cipher */
	ret = snprintf(cipher_name, CRYPTO_MAX_ALG_NAME, "%s(%s)",
			*ivmode, cipher_api);
	if (ret < 0) {
		ti->error = "Cannot allocate cipher strings";
		return -ENOMEM;
	}
	ret = crypt_alloc_tfm(cc, cipher_name);
	if (ret < 0) {
		ti->error = "Error allocating crypto tfm";
		return ret;
	}

	/* Alloc AEAD, can be used only in new format. */
	if (crypt_integrity_aead(cc)) {
		ret = crypt_ctr_auth_cipher(cc, cipher_api);
		if (ret < 0) {
			ti->error = "Invalid AEAD cipher spec";
			return -ENOMEM;
		}
		cc->iv_size = crypto_aead_ivsize(any_tfm_aead(cc));
	} else
		cc->iv_size = crypto_skcipher_ivsize(any_tfm(cc));

	return 0;
}

static int crypt_ctr_cipher_old(struct dm_target *ti, char *cipher_in, char *key,
				char **ivmode, char **ivopts)
{
	struct crypt_config *cc = ti->private;
	char *tmp, *cipher, *chainmode, *keycount;
	char *cipher_api = NULL;
	int ret = -EINVAL;
	char dummy;

	if (strchr(cipher_in, '(') || crypt_integrity_aead(cc)) {
		ti->error = "Bad cipher specification";
		return -EINVAL;
	}

	/*
	 * Legacy dm-crypt cipher specification
	 * cipher[:keycount]-mode-iv:ivopts
	 */
	tmp = cipher_in;
	keycount = strsep(&tmp, "-");
	cipher = strsep(&keycount, ":");

	if (!keycount)
		cc->tfms_count = 1;
	else if (sscanf(keycount, "%u%c", &cc->tfms_count, &dummy) != 1 ||
		 !is_power_of_2(cc->tfms_count)) {
		ti->error = "Bad cipher key count specification";
		return -EINVAL;
	}
	cc->key_parts = cc->tfms_count;

	chainmode = strsep(&tmp, "-");
	*ivmode = strsep(&tmp, ":");
	*ivopts = tmp;

	/*
	 * For compatibility with the original dm-crypt mapping format, if
	 * only the cipher name is supplied, use cbc-plain.
	 */
	if (!chainmode || (!strcmp(chainmode, "plain") && !*ivmode)) {
		chainmode = "cbc";
		*ivmode = "plain";
	}

	if (strcmp(chainmode, "ecb") && !*ivmode) {
		ti->error = "IV mechanism required";
		return -EINVAL;
	}

	cipher_api = kmalloc(CRYPTO_MAX_ALG_NAME, GFP_KERNEL);
	if (!cipher_api)
		goto bad_mem;

	/* For those ciphers which do not support IVs,
	 * use the 'null' template cipher
	 */
	if (!*ivmode)
		*ivmode = "null";

	/*
	 * For those ciphers which do not support IVs, but input ivmode is not
	 * NULL, use "null" as ivmode compulsively.
	 */
	ret = snprintf(cipher_api, CRYPTO_MAX_ALG_NAME,
		       "%s(%s)", chainmode, cipher);
	cc->iv_size = get_iv_size_by_name(cc, cipher_api);
	if (cc->iv_size < 0)
		return -ENOMEM;
	if (!cc->iv_size && ivmode) {
		DMWARN("Selected cipher does not support IVs");
		*ivmode = "null";
	}

	ret = snprintf(cipher_api, CRYPTO_MAX_ALG_NAME,
		       "%s(%s(%s))", *ivmode, chainmode, cipher);
	if (ret < 0) {
		kfree(cipher_api);
		goto bad_mem;
	}

	/* Allocate cipher */
	ret = crypt_alloc_tfm(cc, cipher_api);
	if (ret < 0) {
		ti->error = "Error allocating crypto tfm";
		kfree(cipher_api);
		return ret;
	}
	kfree(cipher_api);

	return 0;
bad_mem:
	ti->error = "Cannot allocate cipher strings";
	return -ENOMEM;
}

static int crypt_ctr_cipher(struct dm_target *ti, char *cipher_in, char *key)
{
	struct crypt_config *cc = ti->private;
	char *ivmode = NULL, *ivopts = NULL;
	int ret;

	cc->cipher_string = kstrdup(cipher_in, GFP_KERNEL);
	if (!cc->cipher_string) {
		ti->error = "Cannot allocate cipher strings";
		return -ENOMEM;
	}

	if (strstarts(cipher_in, "capi:"))
		ret = crypt_ctr_cipher_new(ti, cipher_in, key, &ivmode, &ivopts);
	else
		ret = crypt_ctr_cipher_old(ti, cipher_in, key, &ivmode, &ivopts);
	if (ret)
		return ret;

	/* Initialize IV */
	ret = crypt_ctr_ivmode(ti, ivmode);
	if (ret < 0)
		return ret;

	/* Initialize and set key */
	ret = crypt_init_key(ti, key, ivopts);
	if (ret < 0) {
		ti->error = "Error decoding and setting key";
		return ret;
	}

	/* wipe the kernel key payload copy */
	if (cc->key_string)
		memset(cc->key, 0, cc->key_size * sizeof(u8));

	return ret;
}

static int crypt_ctr_optional(struct dm_target *ti, unsigned int argc, char **argv)
{
	struct crypt_config *cc = ti->private;
	struct dm_arg_set as;
	static const struct dm_arg _args[] = {
		{0, 6, "Invalid number of feature args"},
	};
	unsigned int opt_params, val;
	const char *opt_string, *sval;
	char dummy;
	int ret;

	/* Optional parameters */
	as.argc = argc;
	as.argv = argv;

	ret = dm_read_arg_group(_args, &as, &opt_params, &ti->error);
	if (ret)
		return ret;

	while (opt_params--) {
		opt_string = dm_shift_arg(&as);
		if (!opt_string) {
			ti->error = "Not enough feature arguments";
			return -EINVAL;
		}

		if (!strcasecmp(opt_string, "allow_discards"))
			ti->num_discard_bios = 1;

		else if (!strcasecmp(opt_string, "same_cpu_crypt"))
			set_bit(DM_CRYPT_SAME_CPU, &cc->flags);

		else if (!strcasecmp(opt_string, "submit_from_crypt_cpus"))
			set_bit(DM_CRYPT_NO_OFFLOAD, &cc->flags);
		else if (sscanf(opt_string, "integrity:%u:", &val) == 1) {
			if (val == 0 || val > MAX_TAG_SIZE) {
				ti->error = "Invalid integrity arguments";
				return -EINVAL;
			}
			cc->on_disk_tag_size = val;
			sval = strchr(opt_string + strlen("integrity:"), ':') + 1;
			if (!strcasecmp(sval, "aead")) {
				set_bit(CRYPT_MODE_INTEGRITY_AEAD, &cc->cipher_flags);
			} else  if (strcasecmp(sval, "none")) {
				ti->error = "Unknown integrity profile";
				return -EINVAL;
			}

			cc->cipher_auth = kstrdup(sval, GFP_KERNEL);
			if (!cc->cipher_auth)
				return -ENOMEM;
		} else if (sscanf(opt_string, "sector_size:%hu%c", &cc->sector_size, &dummy) == 1) {
			if (cc->sector_size < (1 << SECTOR_SHIFT) ||
			    cc->sector_size > 4096 ||
			    (cc->sector_size & (cc->sector_size - 1))) {
				ti->error = "Invalid feature value for sector_size";
				return -EINVAL;
			}
			if (ti->len & ((cc->sector_size >> SECTOR_SHIFT) - 1)) {
				ti->error = "Device size is not multiple of sector_size feature";
				return -EINVAL;
			}
			cc->sector_shift = __ffs(cc->sector_size) - SECTOR_SHIFT;
		} else if (!strcasecmp(opt_string, "iv_large_sectors"))
			set_bit(CRYPT_IV_LARGE_SECTORS, &cc->cipher_flags);
		else {
			ti->error = "Invalid feature arguments";
			return -EINVAL;
		}
	}

	return 0;
}

/*
 * Construct an encryption mapping:
 * <cipher> [<key>|:<key_size>:<user|logon>:<key_description>] <iv_offset> <dev_path> <start>
 */
static int crypt_ctr(struct dm_target *ti, unsigned int argc, char **argv)
{
	struct crypt_config *cc;
	int key_size;
	unsigned int align_mask;
	unsigned long long tmpll;
	int ret;
	size_t additional_req_size;
	char dummy;

	if (argc < 5) {
		ti->error = "Not enough arguments";
		return -EINVAL;
	}

	key_size = get_key_size(&argv[1]);
	if (key_size < 0) {
		ti->error = "Cannot parse key size";
		return -EINVAL;
	}

	cc = kzalloc(sizeof(*cc) + key_size * sizeof(u8), GFP_KERNEL);
	if (!cc) {
		ti->error = "Cannot allocate encryption context";
		return -ENOMEM;
	}
	cc->key_size = key_size;
	cc->sector_size = (1 << SECTOR_SHIFT);
	cc->sector_shift = 0;

	ti->private = cc;

	spin_lock(&dm_crypt_clients_lock);
	dm_crypt_clients_n++;
	crypt_calculate_pages_per_client();
	spin_unlock(&dm_crypt_clients_lock);

	ret = percpu_counter_init(&cc->n_allocated_pages, 0, GFP_KERNEL);
	if (ret < 0)
		goto bad;

	/* Optional parameters need to be read before cipher constructor */
	if (argc > 5) {
		ret = crypt_ctr_optional(ti, argc - 5, &argv[5]);
		if (ret)
			goto bad;
	}

	ret = crypt_ctr_cipher(ti, argv[0], argv[1]);
	if (ret < 0)
		goto bad;

	if (crypt_integrity_aead(cc)) {
		cc->dmreq_start = sizeof(struct aead_request);
		cc->dmreq_start += crypto_aead_reqsize(any_tfm_aead(cc));
		align_mask = crypto_aead_alignmask(any_tfm_aead(cc));
	} else {
		cc->dmreq_start = sizeof(struct skcipher_request);
		cc->dmreq_start += crypto_skcipher_reqsize(any_tfm(cc));
		align_mask = crypto_skcipher_alignmask(any_tfm(cc));
	}
	cc->dmreq_start = ALIGN(cc->dmreq_start, __alignof__(struct dm_crypt_request));

	additional_req_size = sizeof(struct dm_crypt_request);

	ret = mempool_init_kmalloc_pool(&cc->req_pool, MIN_IOS, cc->dmreq_start + additional_req_size);
	if (ret) {
		ti->error = "Cannot allocate crypt request mempool";
		goto bad;
	}

	cc->per_bio_data_size = ti->per_io_data_size =
		ALIGN(sizeof(struct dm_crypt_io) + cc->dmreq_start + additional_req_size,
		      ARCH_KMALLOC_MINALIGN);

	ret = mempool_init(&cc->page_pool, BIO_MAX_PAGES, crypt_page_alloc, crypt_page_free, cc);
	if (ret) {
		ti->error = "Cannot allocate page mempool";
		goto bad;
	}

	ret = bioset_init(&cc->bs, MIN_IOS, 0, BIOSET_NEED_BVECS);
	if (ret) {
		ti->error = "Cannot allocate crypt bioset";
		goto bad;
	}

	mutex_init(&cc->bio_alloc_lock);

	ret = -EINVAL;
	if ((sscanf(argv[2], "%llu%c", &tmpll, &dummy) != 1) ||
	    (tmpll & ((cc->sector_size >> SECTOR_SHIFT) - 1))) {
		ti->error = "Invalid iv_offset sector";
		goto bad;
	}
	cc->iv_offset = tmpll;

	ret = dm_get_device(ti, argv[3], dm_table_get_mode(ti->table), &cc->dev);
	if (ret) {
		ti->error = "Device lookup failed";
		goto bad;
	}

	ret = -EINVAL;
	if (sscanf(argv[4], "%llu%c", &tmpll, &dummy) != 1 || tmpll != (sector_t)tmpll) {
		ti->error = "Invalid device sector";
		goto bad;
	}
	cc->start = tmpll;

	if (crypt_integrity_aead(cc) || cc->integrity_iv_size) {
		ret = crypt_integrity_ctr(cc, ti);
		if (ret)
			goto bad;

		cc->tag_pool_max_sectors = POOL_ENTRY_SIZE / cc->on_disk_tag_size;
		if (!cc->tag_pool_max_sectors)
			cc->tag_pool_max_sectors = 1;

		ret = mempool_init_kmalloc_pool(&cc->tag_pool, MIN_IOS,
			cc->tag_pool_max_sectors * cc->on_disk_tag_size);
		if (ret) {
			ti->error = "Cannot allocate integrity tags mempool";
			goto bad;
		}

		cc->tag_pool_max_sectors <<= cc->sector_shift;
	}

	ret = -ENOMEM;
	cc->io_queue = alloc_workqueue("kcryptd_io", WQ_HIGHPRI | WQ_CPU_INTENSIVE | WQ_MEM_RECLAIM, 1);
	if (!cc->io_queue) {
		ti->error = "Couldn't create kcryptd io queue";
		goto bad;
	}

	if (test_bit(DM_CRYPT_SAME_CPU, &cc->flags))
		cc->crypt_queue = alloc_workqueue("kcryptd", WQ_HIGHPRI | WQ_CPU_INTENSIVE | WQ_MEM_RECLAIM, 1);
	else
		cc->crypt_queue = alloc_workqueue("kcryptd",
						  WQ_HIGHPRI | WQ_CPU_INTENSIVE | WQ_MEM_RECLAIM | WQ_UNBOUND,
						  num_online_cpus());
	if (!cc->crypt_queue) {
		ti->error = "Couldn't create kcryptd queue";
		goto bad;
	}

	spin_lock_init(&cc->write_thread_lock);
	cc->write_tree = RB_ROOT;

	cc->write_thread = kthread_create(dmcrypt_write, cc, "dmcrypt_write");
	if (IS_ERR(cc->write_thread)) {
		ret = PTR_ERR(cc->write_thread);
		cc->write_thread = NULL;
		ti->error = "Couldn't spawn write thread";
		goto bad;
	}
	wake_up_process(cc->write_thread);

	ti->num_flush_bios = 1;

	return 0;

bad:
	crypt_dtr(ti);
	return ret;
}

static int crypt_map(struct dm_target *ti, struct bio *bio)
{
	struct dm_crypt_io *io;
	struct crypt_config *cc = ti->private;

	/*
	 * If bio is REQ_PREFLUSH or REQ_OP_DISCARD, just bypass crypt queues.
	 * - for REQ_PREFLUSH device-mapper core ensures that no IO is in-flight
	 * - for REQ_OP_DISCARD caller must use flush if IO ordering matters
	 */
	if (unlikely(bio->bi_opf & REQ_PREFLUSH ||
	    bio_op(bio) == REQ_OP_DISCARD)) {
		bio_set_dev(bio, cc->dev->bdev);
		if (bio_sectors(bio))
			bio->bi_iter.bi_sector = cc->start +
				dm_target_offset(ti, bio->bi_iter.bi_sector);
		return DM_MAPIO_REMAPPED;
	}

	/*
	 * Check if bio is too large, split as needed.
	 */
	if (unlikely(bio->bi_iter.bi_size > (BIO_MAX_PAGES << PAGE_SHIFT)) &&
	    (bio_data_dir(bio) == WRITE || cc->on_disk_tag_size))
		dm_accept_partial_bio(bio, ((BIO_MAX_PAGES << PAGE_SHIFT) >> SECTOR_SHIFT));

	/*
	 * Ensure that bio is a multiple of internal sector encryption size
	 * and is aligned to this size as defined in IO hints.
	 */
	if (unlikely((bio->bi_iter.bi_sector & ((cc->sector_size >> SECTOR_SHIFT) - 1)) != 0))
		return DM_MAPIO_KILL;

	if (unlikely(bio->bi_iter.bi_size & (cc->sector_size - 1)))
		return DM_MAPIO_KILL;

	io = dm_per_bio_data(bio, cc->per_bio_data_size);
	crypt_io_init(io, cc, bio, dm_target_offset(ti, bio->bi_iter.bi_sector));

	if (cc->on_disk_tag_size) {
		unsigned tag_len = cc->on_disk_tag_size * (bio_sectors(bio) >> cc->sector_shift);

		if (unlikely(tag_len > KMALLOC_MAX_SIZE) ||
		    unlikely(!(io->integrity_metadata = kmalloc(tag_len,
				GFP_NOIO | __GFP_NORETRY | __GFP_NOMEMALLOC | __GFP_NOWARN)))) {
			if (bio_sectors(bio) > cc->tag_pool_max_sectors)
				dm_accept_partial_bio(bio, cc->tag_pool_max_sectors);
			io->integrity_metadata = mempool_alloc(&cc->tag_pool, GFP_NOIO);
			io->integrity_metadata_from_pool = true;
		}
	}

	if (crypt_integrity_aead(cc))
		io->ctx.r.req_aead = (struct aead_request *)(io + 1);
	else
		io->ctx.r.req = (struct skcipher_request *)(io + 1);

	if (bio_data_dir(io->base_bio) == READ) {
		if (kcryptd_io_read(io, GFP_NOWAIT))
			kcryptd_queue_read(io);
	} else
		kcryptd_queue_crypt(io);

	return DM_MAPIO_SUBMITTED;
}

static void crypt_status(struct dm_target *ti, status_type_t type,
			 unsigned status_flags, char *result, unsigned maxlen)
{
	struct crypt_config *cc = ti->private;
	unsigned i, sz = 0;
	int num_feature_args = 0;

	switch (type) {
	case STATUSTYPE_INFO:
		result[0] = '\0';
		break;

	case STATUSTYPE_TABLE:
		DMEMIT("%s ", cc->cipher_string);

		if (cc->key_size > 0) {
			if (cc->key_string)
				DMEMIT(":%u:%s", cc->key_size, cc->key_string);
			else
				for (i = 0; i < cc->key_size; i++)
					DMEMIT("%02x", cc->key[i]);
		} else
			DMEMIT("-");

		DMEMIT(" %llu %s %llu", (unsigned long long)cc->iv_offset,
				cc->dev->name, (unsigned long long)cc->start);

		num_feature_args += !!ti->num_discard_bios;
		num_feature_args += test_bit(DM_CRYPT_SAME_CPU, &cc->flags);
		num_feature_args += test_bit(DM_CRYPT_NO_OFFLOAD, &cc->flags);
		num_feature_args += cc->sector_size != (1 << SECTOR_SHIFT);
		num_feature_args += test_bit(CRYPT_IV_LARGE_SECTORS, &cc->cipher_flags);
		if (cc->on_disk_tag_size)
			num_feature_args++;
		if (num_feature_args) {
			DMEMIT(" %d", num_feature_args);
			if (ti->num_discard_bios)
				DMEMIT(" allow_discards");
			if (test_bit(DM_CRYPT_SAME_CPU, &cc->flags))
				DMEMIT(" same_cpu_crypt");
			if (test_bit(DM_CRYPT_NO_OFFLOAD, &cc->flags))
				DMEMIT(" submit_from_crypt_cpus");
			if (cc->on_disk_tag_size)
				DMEMIT(" integrity:%u:%s", cc->on_disk_tag_size, cc->cipher_auth);
			if (cc->sector_size != (1 << SECTOR_SHIFT))
				DMEMIT(" sector_size:%d", cc->sector_size);
			if (test_bit(CRYPT_IV_LARGE_SECTORS, &cc->cipher_flags))
				DMEMIT(" iv_large_sectors");
		}

		break;
	}
}

static void crypt_postsuspend(struct dm_target *ti)
{
	struct crypt_config *cc = ti->private;

	set_bit(DM_CRYPT_SUSPENDED, &cc->flags);
}

static int crypt_preresume(struct dm_target *ti)
{
	struct crypt_config *cc = ti->private;

	if (!test_bit(DM_CRYPT_KEY_VALID, &cc->flags)) {
		DMERR("aborting resume - crypt key is not set.");
		return -EAGAIN;
	}

	return 0;
}

static void crypt_resume(struct dm_target *ti)
{
	struct crypt_config *cc = ti->private;

	clear_bit(DM_CRYPT_SUSPENDED, &cc->flags);
}

/* Message interface
 *	key set <key>
 *	key wipe
 */
static int crypt_message(struct dm_target *ti, unsigned argc, char **argv,
			 char *result, unsigned maxlen)
{
	struct crypt_config *cc = ti->private;
	int key_size, ret = -EINVAL;

	if (argc < 2)
		goto error;

	if (!strcasecmp(argv[0], "key")) {
		if (!test_bit(DM_CRYPT_SUSPENDED, &cc->flags)) {
			DMWARN("not suspended during key manipulation.");
			return -EINVAL;
		}
		if (argc == 3 && !strcasecmp(argv[1], "set")) {
			/* The key size may not be changed. */
			key_size = get_key_size(&argv[2]);
			if (key_size < 0 || cc->key_size != key_size) {
				memset(argv[2], '0', strlen(argv[2]));
				return -EINVAL;
			}

			ret = crypt_set_key(cc, SETKEY_OP_SET, argv[2], NULL);
			/* wipe the kernel key payload copy */
			if (cc->key_string)
				memset(cc->key, 0, cc->key_size * sizeof(u8));
			return ret;
		}
		if (argc == 2 && !strcasecmp(argv[1], "wipe")) {
			return crypt_wipe_key(cc);
		}
	}

error:
	DMWARN("unrecognised message received.");
	return -EINVAL;
}

static int crypt_iterate_devices(struct dm_target *ti,
				 iterate_devices_callout_fn fn, void *data)
{
	struct crypt_config *cc = ti->private;

	return fn(ti, cc->dev, cc->start, ti->len, data);
}

static void crypt_io_hints(struct dm_target *ti, struct queue_limits *limits)
{
	struct crypt_config *cc = ti->private;

	/*
	 * Unfortunate constraint that is required to avoid the potential
	 * for exceeding underlying device's max_segments limits -- due to
	 * crypt_alloc_buffer() possibly allocating pages for the encryption
	 * bio that are not as physically contiguous as the original bio.
	 */
	limits->max_segment_size = PAGE_SIZE;

	limits->logical_block_size =
		max_t(unsigned short, limits->logical_block_size, cc->sector_size);
	limits->physical_block_size =
		max_t(unsigned, limits->physical_block_size, cc->sector_size);
	limits->io_min = max_t(unsigned, limits->io_min, cc->sector_size);
}

static struct target_type crypt_target = {
	.name   = "crypt",
	.version = {1, 19, 1},
	.module = THIS_MODULE,
	.ctr    = crypt_ctr,
	.dtr    = crypt_dtr,
	.map    = crypt_map,
	.status = crypt_status,
	.postsuspend = crypt_postsuspend,
	.preresume = crypt_preresume,
	.resume = crypt_resume,
	.message = crypt_message,
	.iterate_devices = crypt_iterate_devices,
	.io_hints = crypt_io_hints,
};

static int __init dm_crypt_init(void)
{
	int r;

	r = crypto_register_templates(geniv_tmpl, ARRAY_SIZE(geniv_tmpl));
	if (r) {
		DMERR("register template failed %d", r);
		return r;
	}

	r = dm_register_target(&crypt_target);
	if (r < 0)
		DMERR("register failed %d", r);

	return r;
}

static void __exit dm_crypt_exit(void)
{
	dm_unregister_target(&crypt_target);
	crypto_unregister_templates(geniv_tmpl, ARRAY_SIZE(geniv_tmpl));
}

module_init(dm_crypt_init);
module_exit(dm_crypt_exit);

MODULE_AUTHOR("Jana Saout <jana@saout.de>");
MODULE_DESCRIPTION(DM_NAME " target for transparent encryption / decryption");
MODULE_LICENSE("GPL");
