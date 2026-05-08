/* SPDX-License-Identifier: GPL-2.0 */
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2_ddp_common.h
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#ifndef _SXE2_DDP_COMMON_H_
#define _SXE2_DDP_COMMON_H_

#ifdef SXE2_FW
#include "sxe2_drv_type.h"
#endif

#ifdef SXE2_LINUX_DRIVER
#include <linux/types.h>
#endif

#ifdef SXE2_DPDK_DRIVER
#include "sxe2_type.h"
#include "sxe2_common.h"
#endif

#define SXE2_DDP_DRV_VER_MAJ	1
#define SXE2_DDP_DRV_VER_MNR	0

#define SXE2_DDP_FW_VER_MAJ	1
#define SXE2_DDP_FW_VER_MNR	0

enum sxe2_ddp_error {
	SXE2_DDP_PKG_SUCCESS                       = 0,

	SXE2_DDP_PKG_ALREADY_LOADED			    = 1,

	SXE2_DDP_PKG_SAME_VERSION_ALREADY_LOADED   = 2,

	SXE2_DDP_PKG_ALREADY_LOADED_NOT_SUPPORTED	= 3,

	SXE2_DDP_PKG_COMPATIBLE_ALREADY_LOADED		= 4,

	SXE2_DDP_PKG_FW_MISMATCH				    = 5,

	SXE2_DDP_PKG_INVALID_FILE			        = 6,

	SXE2_DDP_PKG_FILE_VERSION_TOO_HIGH		    = 7,

	SXE2_DDP_PKG_FILE_VERSION_TOO_LOW		    = 8,

	SXE2_DDP_PKG_NO_SEC_MANIFEST			    = 9,

	SXE2_DDP_PKG_MANIFEST_INVALID			    = 10,

	SXE2_DDP_PKG_BUFFER_INVALID			    = 11,

	SXE2_DDP_PKG_BUSY					        = 12,

	SXE2_DDP_PKG_ERR					        = 13,
};

enum sxe2_ddp_state {
	SXE2_DDP_STATE_UNINIT,
	SXE2_DDP_STATE_PROC,
	SXE2_DDP_STATE_FINISH,
	SXE2_DDP_STATE_ERROR,
	SXE2_DDP_STATE_INVALID = 0xFFFFFFFF,
};

struct sxe2_ddp_pkg_ver {
	__le16  major;
	__le16  minor;
};

union sxe2_device_id {
	struct {
		__le16 device_id;
		__le16 vendor_id;
	} dev_vend_id;
	__le32 id;
};

struct sxe2_device_id_entry {
	union sxe2_device_id device;
	union sxe2_device_id sub_device;
};

struct sxe2_pkg_hdr {
	struct sxe2_ddp_pkg_ver pkg_drv_ver;
	struct sxe2_ddp_pkg_ver pkg_fw_ver;
	struct sxe2_device_id_entry dev_vend_id;
	__le32 seg_count;

	__le32 seg_offset[];
};

#define SEGMENT_SIGN_TYPE_NONE      0x00000000
#define SEGMENT_SIGN_TYPE_RSA2K     0x00000001
#define SEGMENT_SIGN_TYPE_RSA3K     0x00000002
#define SEGMENT_SIGN_TYPE_RSA3K_SBB	0x00000003
#define SEGMENT_SIGN_TYPE_RSA3K_E825    0x00000005

struct sxe2_generic_seg_hdr {
#define	SEGMENT_TYPE_INVALID	0x00000000
#define SEGMENT_TYPE_METADATA	0x00000001
#define SEGMENT_TYPE_SXE2_DDP	0x00000010
#define SEGMENT_TYPE_SXE2_RUN_TIME_CFG 0x00000020
	__le32 seg_id;
	__le32 seg_type;
	__le32 seg_size;
};

struct sxe2_buf {
#define SXE2_PKG_BUF_SIZE	4096
	u8 buf[SXE2_PKG_BUF_SIZE];
};

struct sxe2_buf_table {
	__le32 buf_count;
	struct sxe2_buf buf_array[];
};

struct sxe2_seg {
	struct sxe2_generic_seg_hdr hdr;
	u8 rsvd[8];
	struct sxe2_buf_table buf_table;
};

#define SXE2_MIN_S_OFF		12
#define SXE2_MAX_S_OFF		4095
#define SXE2_MIN_S_SZ		1
#define SXE2_MAX_S_SZ		4084
#define SXE2_MIN_CFG_SZ    (sizeof(struct sxe2_pkg_hdr) + sizeof(struct sxe2_seg))

struct sxe2_section_entry {
	__le16 type;
	__le16 unit_size;

	__le16 offset;
	__le16 size;
};

#define SXE2_MIN_SECT_COUNT        1
#define SXE2_MAX_SECT_COUNT        512
#define SXE2_MIN_SECT_DATA_END     12
#define SXE2_MAX_SECT_DATA_END     4096

struct sxe2_buf_hdr {
	__le16 section_count;

	__le16 data_end;
	__le32 buf_idx;

	__le32 crc;
	struct sxe2_section_entry section_entry[];
};

enum sxe2_segment_type {
	SXE2_SGM_BLK_DP = 0,
	SXE2_SGM_BLK_MAX
};

enum sxe2_section_type {
	SXE2_SECT_SWPTG_TYPE = 0,
	SXE2_SECT_SWVSIG_TYPE,
	SXE2_SECT_SWTCAM_TYPE,
	SXE2_SECT_SWEXTRACTOR_TYPE,
	SXE2_SECT_SWMAP_TYPE,
	SXE2_SECT_SWRCP_TYPE,
	SXE2_SECT_SWPROFILERCPBITMAP_TYPE,
	SXE2_SECT_RSSPTG_TYPE,
	SXE2_SECT_RSSVSIG_TYPE,
	SXE2_SECT_RSSTCAM_TYPE,
	SXE2_SECT_RSSEXTRACTOR_TYPE,
	SXE2_SECT_RSSMAP_TYPE,
	SXE2_SECT_RSSIPSET_TYPE,
	SXE2_SECT_FNAVPTG_TYPE,
	SXE2_SECT_FNAVMASK_TYPE,
	SXE2_SECT_ACLPTG_TYPE = 16,
	SXE2_SECT_TYPE_MAX,
};
#endif
