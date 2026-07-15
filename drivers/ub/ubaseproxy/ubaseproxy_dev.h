/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (c) 2026 HiSilicon Technologies Co., Ltd. All rights reserved.
 */

#ifndef __UBASEPROXY_DEV_H__
#define __UBASEPROXY_DEV_H__

#include <ub/ubase/ubase_comm_cmd.h>
#include <ub/ubase/ubase_comm_debugfs.h>
#include <ub/ubase/ubase_comm_dev.h>

#include "ubaseproxy_log.h"

#define UBASEPROXY_MAX_DEV_NAME		64
#define UBASEPROXY_ERR_MSG_LEN		128
#define UBASEPROXY_MAX_SEID_TABLE_SIZE	1024

enum ubaseproxy_dev_state {
	UBASEPROXY_STATE_INITED,
	UBASEPROXY_STATE_REMOVING,
	UBASEPROXY_STATE_RESETTING,
	UBASEPROXY_STATE_DISABLED,
};

struct ubaseproxy_ue_caps {
	u8	ceq_vector_num;
	u8	aeq_vector_num;
	u32	aeqe_depth;
	u32	ceqe_depth;
	u32	jfs_max_cnt;
	u32	jfs_depth;
	u32	jfr_max_cnt;
	u32	jfr_depth;
	u32	jfc_max_cnt;
	u32	jfc_depth;
	u32	rc_max_cnt;
	u32	rc_depth;
	u32	jtg_max_cnt;
};

struct ubaseproxy_ue_default {
	struct ubaseproxy_jfc_default	*jfc_default;
	struct ubaseproxy_jfr_default	*jfr_default;
	struct ubaseproxy_jetty_default	*jetty_default;
};

struct ubaseproxy_dev_caps {
	struct ubaseproxy_ue_caps	ue_caps;
	struct ubaseproxy_ue_default	ue_default;
};

struct ubaseproxy_ue_ctx_xarray {
	struct xarray	jfc;
	struct xarray	jfr;
	struct xarray	jetty;
	struct xarray	jetty_grp;
	struct xarray	rc;
	struct xarray	aeq;
	struct xarray	ceq;
};

struct ubase_ctx_result {
	u16 opcode;
	int ret;
	u16 len;
};

struct ubaseproxy_ue_ctx_buf {
	struct ubase_ctx_buf_cap jfs;
	struct ubase_ctx_buf_cap jfr;
	struct ubase_ctx_buf_cap jfc;
	struct ubase_ctx_buf_cap jtg;
	struct ubase_ctx_buf_cap rc;
};

struct ubaseproxy_ue_ctx_qos {
	unsigned long	um_sl_bitmap;
	unsigned long	tp_sl_bitmap;
	unsigned long	ctp_sl_bitmap;
	unsigned long	total_sl_bitmap;
};

struct ubaseproxy_ue_seid_table {
	spinlock_t	seid_lock;
	unsigned long	seid_bmap[BITS_TO_LONGS(UBASEPROXY_MAX_SEID_TABLE_SIZE)];
};

struct ubaseproxy_ue_res_info {
	struct ubaseproxy_ue_ctx_qos	ue_ctx_qos;
	struct ubaseproxy_ue_seid_table	ue_seid_table;
	struct ubaseproxy_ue_ctx_buf	ue_ctx_buf;
	struct ubaseproxy_ue_ctx_xarray	ue_ctx_xa;
	struct ubaseproxy_ue_risk_stats	risk_stats;
	struct ratelimit_state		rl_state;
};

struct ubaseproxy_dev {
	struct ubase_adev_com		comdev;
	struct ubase_dbgfs		dbgfs;
	char				dev_name[UBASEPROXY_MAX_DEV_NAME];
	unsigned long			state;
	struct ubaseproxy_dev_caps	caps;
	struct ubaseproxy_ue_res_info	*ue_res_info;
	u32				tid;
	gfp_t				gfp;
	atomic_t			virt_refcnt;
};

struct ubaseproxy_func_map {
	char err_msg[UBASEPROXY_ERR_MSG_LEN];
	int (*init_func)(struct ubaseproxy_dev *udev);
	void (*uninit_func)(struct ubaseproxy_dev *udev);
};

struct ubaseproxy_query_ue_res_cmd {
	u8 rsv[2];
	u8 ceq_vector_num;
	u8 aeq_vector_num;
	__le32 aeqe_depth;
	__le32 ceqe_depth;
	__le32 jfs_max_cnt;
	__le32 jfs_depth;
	__le32 jfr_max_cnt;

	__le32 jfr_depth;
	__le32 jfc_max_cnt;
	__le32 jfc_depth;
	__le32 rc_max_cnt;
	__le32 rc_depth;
	__le32 jtg_max_cnt;
	u8 rsv1[8];
};

static inline void ubaseproxy_fill_ctx_result(struct ubase_ctx_result *ctx_res,
					      u16 opcode, u16 len, int ret)
{
	ctx_res->opcode = opcode;
	ctx_res->len = len;
	ctx_res->ret = ret;
}

static inline struct ubaseproxy_dev *get_ubaseproxy_dev(struct auxiliary_device *adev)
{
	return (struct ubaseproxy_dev *)dev_get_drvdata(&adev->dev);
}

static inline struct ubaseproxy_ue_res_info*
ubaseproxy_get_ue_ctx(struct ubaseproxy_dev *udev, u16 mbx_ue_id)
{
	/* The mbx_ue_id is 1-based, so we subtract 1 to index the array */
	return &udev->ue_res_info[mbx_ue_id - 1];
}

static inline struct ubaseproxy_ue_ctx_xarray*
ubaseproxy_get_ue_ctx_xa(struct ubaseproxy_dev *udev, u16 mbx_ue_id)
{
	struct ubaseproxy_ue_res_info *ue_res_info;

	ue_res_info = ubaseproxy_get_ue_ctx(udev, mbx_ue_id);
	return &ue_res_info->ue_ctx_xa;
}

static inline struct ubaseproxy_ue_ctx_buf*
ubaseproxy_get_ue_ctx_buf(struct ubaseproxy_dev *udev, u16 mbx_ue_id)
{
	struct ubaseproxy_ue_res_info *ue_res_info;

	ue_res_info = ubaseproxy_get_ue_ctx(udev, mbx_ue_id);
	return &ue_res_info->ue_ctx_buf;
}

int ubaseproxy_dev_init(struct ubaseproxy_dev *udev);
void ubaseproxy_dev_uninit(struct ubaseproxy_dev *udev);
int ubaseproxy_dbg_log(void);

#endif /* __UBASEPROXY_DEV_H__ */
