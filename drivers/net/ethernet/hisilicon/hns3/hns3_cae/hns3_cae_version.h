/* SPDX-License-Identifier: GPL-2.0+ */
/* Copyright (c) 2016-2019 Hisilicon Limited. */

#ifndef __HNS3_CAE_VERSION_H__
#define __HNS3_CAE_VERSION_H__

#define HNS3_CAE_MOD_VERSION "1.9.36.0"

#define CMT_ID_LEN 8
#define RESV_LEN 3
#define FW_CMT_ID_LEN 9
#define FW_RESV_LEN 3

struct hns3_cae_commit_id_param {
	u8 commit_id[CMT_ID_LEN];
	u32 ncl_version;
	u32 rsv[RESV_LEN];
};

struct hns3_cae_firmware_ver_param {
	u32 imp_ver;
	u8 commit_id[FW_CMT_ID_LEN];
	u8 rsv[FW_RESV_LEN];
	u32 ncl_version;
};

int hns3_cae_get_fw_ver(const struct hns3_nic_priv *nic_dev, void *buf_in,
			u32 in_size, void *buf_out, u32 out_size);
int hns3_cae_get_driver_ver(const struct hns3_nic_priv *nic_dev,
			    void *buf_in, u32 in_size, void *buf_out,
			    u32 out_size);

#endif
