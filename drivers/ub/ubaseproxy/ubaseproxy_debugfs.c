// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) 2026 HiSilicon Technologies Co., Ltd. All rights reserved.
 */

#include <linux/debugfs.h>
#include <linux/time.h>
#include <ub/ubase/ubase_comm_cmd.h>
#include <ub/ubase/ubase_comm_dev.h>
#include <ub/ubase/ubase_comm_mbx.h>

#include "ubaseproxy_debugfs.h"

static bool ubaseproxy_dbg_dentry_support(struct device *dev, u32 property)
{
	struct ubaseproxy_dev *udev = dev_get_drvdata(dev);

	return ubase_dbg_dentry_support(udev->comdev.adev, property);
}

static struct ubase_dbg_dentry_info ubaseproxy_dbg_dentry[] = {
	/* keep ubaseproxy at the bottom and add new directory above */
	{
		.name = "ubaseproxy",
		.property = UBASE_SUP_UDMA | UBASE_SUP_UBL,
		.support = ubaseproxy_dbg_dentry_support,
	},
};

static int ubaseproxy_dbg_dump_ue_ctx_res(struct seq_file *s, void *data)
{
	struct ubaseproxy_dev *udev = dev_get_drvdata(s->private);
	struct ubaseproxy_ue_caps *ue_caps = &udev->caps.ue_caps;

	seq_printf(s, "aeq_vector_num: %u\n", ue_caps->aeq_vector_num);
	seq_printf(s, "ceq_vector_num: %u\n", ue_caps->ceq_vector_num);
	seq_printf(s, "aeqe_depth: %u\n", ue_caps->aeqe_depth);
	seq_printf(s, "ceqe_depth: %u\n", ue_caps->ceqe_depth);
	seq_printf(s, "jfs_max_cnt: %u\n", ue_caps->jfs_max_cnt);
	seq_printf(s, "jfs_depth: %u\n", ue_caps->jfs_depth);
	seq_printf(s, "jfr_max_cnt: %u\n", ue_caps->jfr_max_cnt);
	seq_printf(s, "jfr_depth: %u\n", ue_caps->jfr_depth);
	seq_printf(s, "jfc_max_cnt: %u\n", ue_caps->jfc_max_cnt);
	seq_printf(s, "jfc_depth: %u\n", ue_caps->jfc_depth);
	seq_printf(s, "rc_depth: %u\n", ue_caps->rc_depth);
	seq_printf(s, "jtg_max_cnt: %u\n", ue_caps->jtg_max_cnt);

	return 0;
}

static int ubaseproxy_dbg_dump_ue_qos_info(struct seq_file *s, void *data)
{
	struct ubaseproxy_dev *udev = dev_get_drvdata(s->private);
	struct ubase_caps *ubase_caps = ubase_get_dev_caps(udev->comdev.adev);
	u8 managed_ue_num = ubase_caps->ue_num - 1, i;

	for (i = 0; i < managed_ue_num; i++) {
		seq_printf(s, "UE%u:\n", i);
		seq_printf(s, "\tum_sl_bitmap: 0x%lx\n",
			   udev->ue_res_info[i].ue_ctx_qos.um_sl_bitmap);
		seq_printf(s, "\ttp_sl_bitmap: 0x%lx\n",
			   udev->ue_res_info[i].ue_ctx_qos.tp_sl_bitmap);
		seq_printf(s, "\tctp_sl_bitmap: 0x%lx\n",
			   udev->ue_res_info[i].ue_ctx_qos.ctp_sl_bitmap);
		seq_printf(s, "\ttotal_sl_bitmap: 0x%lx\n",
			   udev->ue_res_info[i].ue_ctx_qos.total_sl_bitmap);
		seq_printf(s, "\trc_max_cnt: %u\n",
			   udev->ue_res_info[i].ue_ctx_buf.rc.entry_cnt);
	}

	return 0;
}

static int ubaseproxy_dbg_dump_ue_seid_idx(struct seq_file *s, void *data)
{
#define SEID_NUM_PER_LINE	10

	struct ubaseproxy_dev *udev = dev_get_drvdata(s->private);
	struct ubase_caps *ubase_caps = ubase_get_dev_caps(udev->comdev.adev);
	struct ubaseproxy_ue_seid_table	*ue_seid_table;
	u8 managed_ue_num = ubase_caps->ue_num - 1, i;
	u16 j, count;

	for (i = 0; i < managed_ue_num; i++) {
		seq_printf(s, "ue_num: %u\n", i);
		seq_puts(s, "seid idx:\n");
		ue_seid_table = &udev->ue_res_info[i].ue_seid_table;
		count = 0;
		spin_lock_bh(&ue_seid_table->seid_lock);
		for (j = 0; j < UBASEPROXY_MAX_SEID_TABLE_SIZE; j++) {
			if (test_bit(j, ue_seid_table->seid_bmap)) {
				seq_printf(s, "%6u", j);
				count++;
			}

			if (count == SEID_NUM_PER_LINE) {
				seq_puts(s, "\n");
				count = 0;
			}
		}
		spin_unlock_bh(&ue_seid_table->seid_lock);
		seq_puts(s, "\n\n");
	}

	return 0;
}

static struct ubase_dbg_cmd_info ubaseproxy_dbg_cmd[] = {
	{
		.name = "ue_context_spec",
		.dentry_index = UBASEPROXY_DBG_DENTRY_ROOT,
		.property = UBASE_SUP_UDMA | UBASE_SUP_UBL,
		.support = ubaseproxy_dbg_dentry_support,
		.init = ubase_dbg_seq_file_init,
		.read_func = ubaseproxy_dbg_dump_ue_ctx_res,
	},
	{
		.name = "ue_qos_info",
		.dentry_index = UBASEPROXY_DBG_DENTRY_ROOT,
		.property = UBASE_SUP_UDMA | UBASE_SUP_UBL,
		.support = ubaseproxy_dbg_dentry_support,
		.init = ubase_dbg_seq_file_init,
		.read_func = ubaseproxy_dbg_dump_ue_qos_info,
	},
	{
		.name = "ue_seid_idx",
		.dentry_index = UBASEPROXY_DBG_DENTRY_ROOT,
		.property = UBASE_SUP_UDMA | UBASE_SUP_UBL,
		.support = ubaseproxy_dbg_dentry_support,
		.init = ubase_dbg_seq_file_init,
		.read_func = ubaseproxy_dbg_dump_ue_seid_idx,
	},
};

int ubaseproxy_dbg_init(struct auxiliary_device *adev)
{
	struct dentry *ubase_root_dentry = ubaseproxy_get_ubase_root_dentry(adev);
	struct ubase_dbg_dentry_info dentry[UBASEPROXY_DBG_DENTRY_ROOT + 1] = {0};
	u8 dentry_num = ARRAY_SIZE(ubaseproxy_dbg_dentry);
	struct device *dev = &adev->dev;
	struct ubaseproxy_dev *udev;
	int ret;

	udev = (struct ubaseproxy_dev *)dev_get_drvdata(dev);

	if (!ubase_root_dentry) {
		ubaseproxy_err(udev, "dbgfs root dentry does not exist.\n");
		return -ENOENT;
	}

	udev->dbgfs.dentry = debugfs_create_dir(ubaseproxy_dbg_dentry[dentry_num - 1].name,
						ubase_root_dentry);
	if (IS_ERR(udev->dbgfs.dentry)) {
		ubaseproxy_err(udev, "failed to create ubaseproxy debugfs root dir.\n");
		return PTR_ERR(udev->dbgfs.dentry);
	}

	memcpy(dentry, ubaseproxy_dbg_dentry, sizeof(dentry));
	dentry[UBASEPROXY_DBG_DENTRY_ROOT].dentry = udev->dbgfs.dentry;
	udev->dbgfs.cmd_info = ubaseproxy_dbg_cmd;
	udev->dbgfs.cmd_info_size = ARRAY_SIZE(ubaseproxy_dbg_cmd);

	ret = ubase_dbg_create_dentry(dev, &udev->dbgfs, dentry,
				      ARRAY_SIZE(dentry) - 1);
	if (ret) {
		ubaseproxy_err(udev,
			       "failed to create ubaseproxy debugfs dentry, ret = %d.\n",
			       ret);
		goto create_dentry_err;
	}

	return 0;

create_dentry_err:
	debugfs_remove_recursive(udev->dbgfs.dentry);

	return ret;
}

void ubaseproxy_dbg_uninit(struct auxiliary_device *adev)
{
	struct ubaseproxy_dev *udev = dev_get_drvdata(&adev->dev);

	debugfs_remove_recursive(udev->dbgfs.dentry);
}
