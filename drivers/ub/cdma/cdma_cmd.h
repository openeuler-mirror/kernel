/* SPDX-License-Identifier: GPL-2.0+ */
/* Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved. */

#ifndef __CDMA_CMD_H__
#define __CDMA_CMD_H__

#include <uapi/ub/cdma/cdma_abi.h>

struct cdma_dev;

struct cdma_ue_info {
	/* BD0 */
	u16 jfs_num_shift : 4;
	u16 jfr_num_shift : 4;
	u16 jfc_num_shift : 4;
	u16 jetty_num_shift : 4;

	u16 jetty_grp_num;

	u16 jfs_depth_shift : 4;
	u16 jfr_depth_shift : 4;
	u16 jfc_depth_shift : 4;
	u16 cqe_size_shift : 4;

	u16 jfs_sge : 5;
	u16 jfr_sge : 5;
	u16 jfs_rsge : 6;

	u16 max_jfs_inline_sz;
	u16 max_jfc_inline_sz;
	u32 cap_info;

	u16 trans_mode : 5;
	u16 ue_num : 8;
	u16 virtualization : 1;
	u16 rsvd0 : 2;

	u16 ue_cnt;
	u8 ue_id;
	u8 default_cong_alg;
	u8 cons_ctrl_alg;
	u8 cc_priority_cnt;
	/* BD1 */
	u16 src_addr_tbl_sz;
	u16 src_addr_tbl_num;
	u16 dest_addr_tbl_sz;
	u16 dest_addr_tbl_num;
	u16 seid_upi_tbl_sz;
	u16 seid_upi_tbl_num;
	u16 tpm_tbl_sz;
	u16 tpm_tbl_num;
	u32 tp_range;
	u8 port_num;
	u8 port_id;
	u8 rsvd1[2];
	u16 rc_queue_num;
	u16 rc_depth;
	u8 rc_entry;
	u8 rsvd2[3];
	/* BD2 */
	u32 rsvd3[8];
	/* BD3 */
	u32 rsvd4[8];
};

struct eu_query_in {
	u32 cmd : 8;
	u32 rsv : 24;
};

struct eu_query_out {
	u32 seid_num : 8;
	u32 rsv : 24;
	struct eu_info eus[CDMA_MAX_EU_NUM];
};

int cdma_init_dev_caps(struct cdma_dev *cdev);
int cdma_ctrlq_query_eu(struct cdma_dev *cdev);
void cdma_cmd_flush(struct cdma_dev *cdev);
void cdma_kcmd_flush(struct cdma_dev *cdev);

static inline void cdma_ref_inc(atomic_t *cnt)
{
	atomic_inc(cnt);
}

static inline void cdma_ref_dec(atomic_t *cnt, struct completion *done)
{
	if (atomic_add_unless(cnt, -1, 1))
		return;
	complete(done);
}

#endif /* __CDMA_CMD_H__ */
