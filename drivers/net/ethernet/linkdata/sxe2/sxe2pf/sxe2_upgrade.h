/* SPDX-License-Identifier: GPL-2.0 */
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2_upgrade.h
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#ifndef __SXE2_UPGRADE_H__
#define __SXE2_UPGRADE_H__

#include "sxe2.h"
#include "sxe2_netdev.h"
#include "sxe2_common.h"
#include "sxe2_log.h"

#define SXE2_MAX_UPDATE_FWTYPE (64)
#define SXE2_UPGRADE_PKGS_NAME_LEN (256)
#define SXE2_FRAG_LEN (2048)
#define SXE2_FW_VENDOR_LEN (8U)
#define SXE2_FW_SIGN_LEN (64U)
#define SXE2_FW_PKEY_LEN (68U)
#define SXE2_BIT_MAP_64 (64)

#define SXE2_PAD_1_K (1024U)
#define SXE2_PACK_DATA_BEGIN_NUM (0x327f68cd)
#define SXE2_DATABEGIN_NUM (0x327f68ab)

#define SXE2_UPGRADE_PROTOCAL_VERSION (0x00000001)
#define SXE2_FRAG_ENABLE (1)
#define SXE2_ETH_UPGRADE_DEV_TYPE_CTRL (1)

#define SXE2_FWHEADER_IMAGETYPE(fw_header) ((fw_header)->image_type_append)
#define SXE2_SET_BIT64(x, y) ((x) |= ((u64)1 << (y)))
#define SXE2_UPDATE_FWTYPE_FW_PACKAGE (34)

struct sxe2_update_flash_param {
	u64 uuid;
	u32 frag_index;
	u32 pack_len;
	u32 frag_num;
	u32 fw_type;
	u8 *pack_data;
	u8 *raw_data;
};

struct sxe2_upgd_image_info {
	__le32 offset;
	__le32 image_len;
	__le32 fw_type;
};

struct sxe2_upgrade_fw_array {
	__le32 fw_cnt;
	struct sxe2_upgd_image_info
		fw_arr[SXE2_MAX_UPDATE_FWTYPE];
};

struct sxe2_pkg_header {
	__le32 magic;
	__le32 fw_count;
	__le32 pack_time;
	__le32 pack_len;
	__le32 pkg_check_sum;
	__le32 pkg_version;
	s8 pkg_name[SXE2_UPGRADE_PKGS_NAME_LEN];
	u8 reserved[4];
};

struct sxe2_region_header {
	__le32 magic;
	u8 vendor[SXE2_FW_VENDOR_LEN];
	__le32 timestamp;
	__le32 image_len;
	__le32 image_type_append;
	u8 signature[SXE2_FW_SIGN_LEN];
	u8 publickey[SXE2_FW_PKEY_LEN];
	__le32 check_sum_file;
	__le32 image_type;
	__le32 image_format;
	__le32 entry_point;
	__le32 load_addr;
	__le32 reserved2;
	__le32 image_version;
	u8 reserved[68];
	__le32 check_sum_header;
};

struct sxe2_fw_header_with_sign {
	__le32 header_over_sign[16];
	struct sxe2_region_header fw_header;
};

struct sxe2_upgrade_prepare_cmd {
	__le64 uuid;
	__le32 fw_type_cnt;
	u8 pad[4];
	__le64 fw_type_bitmap;
	bool is_pkg;
	u8 pad2[4];
	struct sxe2_pkg_header pkg_hdr_info;
	u8 pad3[4];
};

struct sxe2_upgrade_open_cmd {
	__le32 dev_type;
	__le32 fw_type;
	u8 pad1[SXE2_PAD_1_K];
	__le32 pad2[2];
	u64 uuid;
	__le32 frag_num;
	__le32 frag_len;
	__le32 fw_len;
	__le32 no_sign_chk : 1;
	__le32 no_ver_chk : 1;
	__le32 force : 1;
	__le32 all : 1;
	__le32 backup : 1;
	__le32 is_fw_head : 1;
	__le32 no_reset : 1;
	__le32 forcehcb : 1;
	__le32 resetnow : 1;
	__le32 forceclose : 1;
	__le32 ispacket : 1;
	__le32 reserved : 21;
};

struct sxe2_frag_head {
	__le64 uuid;
	__le32 version;
	__le32 frag_sid;
	__le32 frag_len;
	__le32 checksum;
	__le32 symbol_enable : 1;
	__le32 symbol_more : 1;
	__le32 symbol_reserve : 6;
	__le32 reserved : 24;
	u8 pad[4];
};

struct sxe2_upgrade_flash_cmd {
	struct sxe2_frag_head frag_head;
	u8 raw_data[SXE2_FRAG_LEN];
};

struct sxe2_upgrade_close_cmd {
	__le64 uuid;
	__le32 err_code;
	__le32 reset_now : 1;
	__le32 reserved : 31;
};

struct sxe2_upgrade_end_cmd {
	__le64 uuid;
	__le32 err_code;
	__le32 fw_type;
};

s32 sxe2_flash_package_from_file(struct net_device *dev, const char *filename,
				 __le32 install_type);

s32 sxe2_upgrade_prepare(struct sxe2_adapter *adapter,
			 struct sxe2_upgrade_fw_array *fw_arr, u64 uuid,
			 struct sxe2_pkg_header *pkg_hdr);

s32 sxe2_upgrade_open(struct sxe2_adapter *adapter, u32 frag_num, u32 pack_len,
		      u32 fw_type, u64 uuid);

s32 sxe2_upgrade_flash(struct sxe2_adapter *adapter,
		       struct sxe2_update_flash_param *upgd_flash_obj);

s32 sxe2_upgrade_close(struct sxe2_adapter *adapter, u64 uuid, u32 err);

s32 sxe2_upgrade_end(struct sxe2_adapter *adapter, u32 err, u32 fw_type,
		     u64 uuid);

#endif
