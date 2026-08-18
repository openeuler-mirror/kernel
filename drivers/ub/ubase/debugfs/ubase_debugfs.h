/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved.
 *
 */

#ifndef __UBASE_DEBUGFS_H__
#define __UBASE_DEBUGFS_H__

#include <linux/debugfs.h>
#include <linux/kernel.h>
#include <ub/ubase/ubase_comm_debugfs.h>

#include "ubase_dev.h"

enum ubase_dbg_dentry_type {
	UBASE_DBG_DENTRY_CONTEXT = 0,
	UBASE_DBG_DENTRY_QOS,
	UBASE_DBG_DENTRY_MAC,
	/* must be the last entry. */
	UBASE_DBG_DENTRY_ROOT,
};

#define UBASE_DBG_MAC_NUM	4
#define UBASE_QUERY_MAC_LEN	(sizeof(struct ubase_dbg_udma_mac_head) + \
				 sizeof(struct ubase_dbg_udma_mac_entry) * \
				 UBASE_DBG_MAC_NUM)

struct ubase_dbg_udma_mac_entry {
	u8 mac_addr[ETH_ALEN];
	u8 nl_port_id;
	u8 rsv;
	__le32 mac_ad;
};

struct ubase_dbg_udma_mac_head {
	__le32 mac_idx;
	u8 cur_mac_cnt;
	u8 rsv[3];
	struct ubase_dbg_udma_mac_entry mac_entry[];
};

static inline bool ubase_udma_mac_tbl_list_support(struct ubase_dev *udev)
{
	u32 hw_ver = udev->caps.hw_ver;

	return hw_ver >= UBASE_HW_VER_A_1 && hw_ver < UBASE_HW_VER_K_0;
}

static inline void ubase_dbg_dump_arr_info(struct seq_file *s, u8 *arr, u8 arr_num)
{
	u8 i;

	for (i = 0; i < arr_num; i++)
		seq_printf(s, " %u", arr[i]);

	seq_puts(s, "\n");
}

int ubase_dbg_init(struct ubase_dev *udev);
void ubase_dbg_uninit(struct ubase_dev *udev);
int ubase_dbg_register_debugfs(void);
void ubase_dbg_unregister_debugfs(void);

#endif /* __UBASE_DEBUGFS_H__ */
