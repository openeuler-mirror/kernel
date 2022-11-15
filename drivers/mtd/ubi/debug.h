/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (c) International Business Machines Corp., 2006
 *
 * Author: Artem Bityutskiy (Битюцкий Артём)
 */

#ifndef __UBI_DEBUG_H__
#define __UBI_DEBUG_H__

/**
 * MASK_XXX: Mask for emulate_failures in ubi_debug_info.The mask is used to
 * precisely control the type and process of fault injection.
 */
/* Emulate bit-flips */
#define MASK_BITFLIPS			(1 << 0)
/* Emulate ecc error */
#define MASK_ECCERR			(1 << 1)
/* Emulates -EIO during data read */
#define MASK_READ_FAILURE		(1 << 2)
#define MASK_READ_FAILURE_EC		(1 << 3)
#define MASK_READ_FAILURE_VID		(1 << 4)
/* Emulates -EIO during data write */
#define MASK_WRITE_FAILURE		(1 << 5)
/* Emulates -EIO during erase a PEB*/
#define MASK_ERASE_FAILURE		(1 << 6)
/* Emulate a power cut when writing EC/VID header */
#define MASK_POWER_CUT_EC		(1 << 7)
#define MASK_POWER_CUT_VID		(1 << 8)
/* Emulate a power cut when writing data*/
#define MASK_POWER_CUT_DATA		(1 << 9)
/* Return UBI_IO_FF when reading EC/VID header */
#define MASK_IO_FF_EC			(1 << 10)
#define MASK_IO_FF_VID			(1 << 11)
/* Return UBI_IO_FF_BITFLIPS when reading EC/VID header */
#define MASK_IO_FF_BITFLIPS_EC		(1 << 12)
#define MASK_IO_FF_BITFLIPS_VID		(1 << 13)
/* Return UBI_IO_BAD_HDR when reading EC/VID header */
#define MASK_BAD_HDR_EC			(1 << 14)
#define MASK_BAD_HDR_VID		(1 << 15)
/* Return UBI_IO_BAD_HDR_EBADMSG when reading EC/VID header */
#define MASK_BAD_HDR_EBADMSG_EC		(1 << 16)
#define MASK_BAD_HDR_EBADMSG_VID	(1 << 17)

void ubi_dump_flash(struct ubi_device *ubi, int pnum, int offset, int len);
void ubi_dump_ec_hdr(const struct ubi_ec_hdr *ec_hdr);
void ubi_dump_vid_hdr(const struct ubi_vid_hdr *vid_hdr);

#include <linux/random.h>

#define ubi_assert(expr)  do {                                               \
	if (unlikely(!(expr))) {                                             \
		pr_crit("UBI assert failed in %s at %u (pid %d)\n",          \
		       __func__, __LINE__, current->pid);                    \
		dump_stack();                                                \
	}                                                                    \
} while (0)

#define ubi_dbg_print_hex_dump(l, ps, pt, r, g, b, len, a)                   \
		print_hex_dump(l, ps, pt, r, g, b, len, a)

#define ubi_dbg_msg(type, fmt, ...) \
	pr_debug("UBI DBG " type " (pid %d): " fmt "\n", current->pid,       \
		 ##__VA_ARGS__)

/* General debugging messages */
#define dbg_gen(fmt, ...) ubi_dbg_msg("gen", fmt, ##__VA_ARGS__)
/* Messages from the eraseblock association sub-system */
#define dbg_eba(fmt, ...) ubi_dbg_msg("eba", fmt, ##__VA_ARGS__)
/* Messages from the wear-leveling sub-system */
#define dbg_wl(fmt, ...)  ubi_dbg_msg("wl", fmt, ##__VA_ARGS__)
/* Messages from the input/output sub-system */
#define dbg_io(fmt, ...)  ubi_dbg_msg("io", fmt, ##__VA_ARGS__)
/* Initialization and build messages */
#define dbg_bld(fmt, ...) ubi_dbg_msg("bld", fmt, ##__VA_ARGS__)

void ubi_dump_vol_info(const struct ubi_volume *vol);
void ubi_dump_vtbl_record(const struct ubi_vtbl_record *r, int idx);
void ubi_dump_av(const struct ubi_ainf_volume *av);
void ubi_dump_aeb(const struct ubi_ainf_peb *aeb, int type);
void ubi_dump_mkvol_req(const struct ubi_mkvol_req *req);
int ubi_self_check_all_ff(struct ubi_device *ubi, int pnum, int offset,
			  int len);
int ubi_debugfs_init(void);
void ubi_debugfs_exit(void);
int ubi_debugfs_init_dev(struct ubi_device *ubi);
void ubi_debugfs_exit_dev(struct ubi_device *ubi);

/**
 * ubi_dbg_is_bgt_disabled - if the background thread is disabled.
 * @ubi: UBI device description object
 *
 * Returns non-zero if the UBI background thread is disabled for testing
 * purposes.
 */
static inline int ubi_dbg_is_bgt_disabled(const struct ubi_device *ubi)
{
	return ubi->dbg.disable_bgt;
}

#ifdef CONFIG_MTD_UBI_FAULT_INJECTION

extern bool should_fail_eccerr(void);
extern bool should_fail_bitflips(void);
extern bool should_fail_read_failure(void);
extern bool should_fail_write_failure(void);
extern bool should_fail_erase_failure(void);
extern bool should_fail_power_cut(void);
extern bool should_fail_io_ff(void);
extern bool should_fail_io_ff_bitflips(void);
extern bool should_fail_bad_hdr(void);
extern bool should_fail_bad_hdr_ebadmsg(void);

/**
 * ubi_dbg_is_bitflip - if it is time to emulate a bit-flip.
 * @ubi: UBI device description object
 *
 * Returns true if a bit-flip should be emulated, otherwise returns false.
 */
static inline bool ubi_dbg_is_bitflip(const struct ubi_device *ubi)
{
	if (ubi->dbg.emulate_failures & MASK_BITFLIPS)
		return should_fail_bitflips();
	return false;
}

/**
 * ubi_dbg_is_eccerr - if it is time to emulate ECC error.
 * @ubi: UBI device description object
 *
 * Returns true if a ECC error should be emulated, otherwise returns false.
 */
static inline bool ubi_dbg_is_eccerr(const struct ubi_device *ubi)
{
	if (ubi->dbg.emulate_failures & MASK_ECCERR)
		return should_fail_eccerr();
	return false;
}

/**
 * ubi_dbg_is_read_failure - if it is time to emulate a read failure.
 * @ubi: UBI device description object
 *
 * Returns true if a read failure should be emulated, otherwise returns
 * false.
 */
static inline bool ubi_dbg_is_read_failure(const struct ubi_device *ubi,
					   unsigned int caller)
{
	if (ubi->dbg.emulate_failures & caller)
		return should_fail_read_failure();
	return false;
}

/**
 * ubi_dbg_is_write_failure - if it is time to emulate a write failure.
 * @ubi: UBI device description object
 *
 * Returns true if a write failure should be emulated, otherwise returns
 * false.
 */
static inline bool ubi_dbg_is_write_failure(const struct ubi_device *ubi)
{
	if (ubi->dbg.emulate_failures & MASK_WRITE_FAILURE)
		return should_fail_write_failure();
	return false;
}

/**
 * ubi_dbg_is_erase_failure - if its time to emulate an erase failure.
 * @ubi: UBI device description object
 *
 * Returns true if an erase failure should be emulated, otherwise returns
 * false.
 */
static inline bool ubi_dbg_is_erase_failure(const struct ubi_device *ubi)
{
	if (ubi->dbg.emulate_failures & MASK_ERASE_FAILURE)
		return should_fail_erase_failure();
	return false;
}

/**
 * ubi_dbg_power_cut - if it is time to emulate power cut.
 * @ubi: UBI device description object
 *
 * Returns true if power cut should be emulated, otherwise returns false.
 */
static inline bool ubi_dbg_power_cut(const struct ubi_device *ubi,
				     unsigned int caller)
{
	if (ubi->dbg.emulate_failures & caller)
		return should_fail_power_cut();
	return false;
}

/**
 * ubi_dbg_is_ff - if it is time to emulate that read region is only 0xFF.
 * @ubi: UBI device description object
 *
 * Returns true if read region should be emulated 0xFF, otherwise
 * returns false.
 */
static inline bool ubi_dbg_is_ff(const struct ubi_device *ubi,
				 unsigned int caller)
{
	if (ubi->dbg.emulate_failures & caller)
		return should_fail_io_ff();
	return false;
}

/**
 * ubi_dbg_is_ff_bitflips - if it is time to emulate that read region is only 0xFF
 * with error reported by the MTD driver
 *
 * @ubi: UBI device description object
 *
 * Returns true if read region should be emulated 0xFF and error
 * reported by the MTD driver, otherwise returns false.
 */
static inline bool ubi_dbg_is_ff_bitflips(const struct ubi_device *ubi,
					  unsigned int caller)
{
	if (ubi->dbg.emulate_failures & caller)
		return should_fail_io_ff_bitflips();
	return false;
}

/**
 * ubi_dbg_is_bad_hdr - if it is time to emulate a bad header
 * @ubi: UBI device description object
 *
 * Returns true if a bad header error should be emulated, otherwise
 * returns false.
 */
static inline bool ubi_dbg_is_bad_hdr(const struct ubi_device *ubi,
				      unsigned int caller)
{
	if (ubi->dbg.emulate_failures & caller)
		return should_fail_bad_hdr();
	return false;
}

/**
 * ubi_dbg_is_bad_hdr_ebadmsg - if it is time to emulate a bad header with
 * ECC error.
 *
 * @ubi: UBI device description object
 *
 * Returns true if a bad header with ECC error should be emulated, otherwise
 * returns false.
 */
static inline bool ubi_dbg_is_bad_hdr_ebadmsg(const struct ubi_device *ubi,
					      unsigned int caller)
{
	if (ubi->dbg.emulate_failures & caller)
		return should_fail_bad_hdr_ebadmsg();
	return false;
}

#else /* CONFIG_MTD_UBI_FAULT_INJECTION */

static inline bool ubi_dbg_is_bitflip(const struct ubi_device *ubi)
{
	return false;
}

static inline bool ubi_dbg_is_eccerr(const struct ubi_device *ubi)
{
	return false;
}

static inline bool ubi_dbg_is_read_failure(const struct ubi_device *ubi,
					   unsigned int caller)
{
	return false;
}

static inline bool ubi_dbg_is_write_failure(const struct ubi_device *ubi)
{
	return false;
}

static inline bool ubi_dbg_is_erase_failure(const struct ubi_device *ubi)
{
	return false;
}

static inline bool ubi_dbg_power_cut(const struct ubi_device *ubi,
				     unsigned int caller)
{
	return false;
}

static inline bool ubi_dbg_is_ff(const struct ubi_device *ubi,
				 unsigned int caller)
{
	return false;
}

static inline bool ubi_dbg_is_ff_bitflips(const struct ubi_device *ubi,
					  unsigned int caller)
{
	return false;
}

static inline bool ubi_dbg_is_bad_hdr(const struct ubi_device *ubi,
				      unsigned int caller)
{
	return false;
}

static inline bool ubi_dbg_is_bad_hdr_ebadmsg(const struct ubi_device *ubi,
					      unsigned int caller)
{
	return false;
}

#endif
static inline int ubi_dbg_chk_io(const struct ubi_device *ubi)
{
	return ubi->dbg.chk_io;
}

static inline int ubi_dbg_chk_gen(const struct ubi_device *ubi)
{
	return ubi->dbg.chk_gen;
}

static inline int ubi_dbg_chk_fastmap(const struct ubi_device *ubi)
{
	return ubi->dbg.chk_fastmap;
}

static inline void ubi_enable_dbg_chk_fastmap(struct ubi_device *ubi)
{
	ubi->dbg.chk_fastmap = 1;
}

#endif /* !__UBI_DEBUG_H__ */
