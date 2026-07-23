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

#define ubaseproxy_risk_printf(s, ue_id, name)                                 \
	seq_printf(s, "\t%s: %llu\n",                                          \
		   #name, udev->ue_res_info[(ue_id)].risk_stats.name)

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

static void ubaseproxy_dump_ue_risk_jfc(struct seq_file *s, u8 ue_id)
{
	struct ubaseproxy_dev *udev = dev_get_drvdata(s->private);

	ubaseproxy_risk_printf(s, ue_id, jfc_req_len);
	ubaseproxy_risk_printf(s, ue_id, jfc_req_tag);
	ubaseproxy_risk_printf(s, ue_id, jfc_ctx_fixed);
	ubaseproxy_risk_printf(s, ue_id, jfc_field_cnt);
	ubaseproxy_risk_printf(s, ue_id, jfc_field_shift);
	ubaseproxy_risk_printf(s, ue_id, jfc_field_cqe_coalesce_cnt);
	ubaseproxy_risk_printf(s, ue_id, jfc_modify_cqe_coalesce_cnt);
	ubaseproxy_risk_printf(s, ue_id, jfc_create_jfc_already_exists);
	ubaseproxy_risk_printf(s, ue_id, jfc_create_eq_inc);
	ubaseproxy_risk_printf(s, ue_id, jfc_destroy_jfc_not_exists);
	ubaseproxy_risk_printf(s, ue_id, jfc_destroy_eq_dec);
	ubaseproxy_risk_printf(s, ue_id, jfc_modify_jfc_not_exists);
	ubaseproxy_risk_printf(s, ue_id, jfc_query_jfc_not_exists);
	ubaseproxy_risk_printf(s, ue_id, jfc_ref_inc);
	ubaseproxy_risk_printf(s, ue_id, jfc_ref_dec);
}

static void ubaseproxy_dump_ue_risk_jfs(struct seq_file *s, u8 ue_id)
{
	struct ubaseproxy_dev *udev = dev_get_drvdata(s->private);

	ubaseproxy_risk_printf(s, ue_id, jfs_req_len);
	ubaseproxy_risk_printf(s, ue_id, jfs_req_tag);
	ubaseproxy_risk_printf(s, ue_id, jfs_ctx_fixed);
	ubaseproxy_risk_printf(s, ue_id, jfs_field_type);
	ubaseproxy_risk_printf(s, ue_id, jfs_field_sqe_bb_shift);
	ubaseproxy_risk_printf(s, ue_id, jfs_field_state);
	ubaseproxy_risk_printf(s, ue_id, jfs_field_mode);
	ubaseproxy_risk_printf(s, ue_id, jfs_create_jetty_already_exists);
	ubaseproxy_risk_printf(s, ue_id, jfs_destroy_jetty_not_exists);
	ubaseproxy_risk_printf(s, ue_id, jfs_modify_jetty_not_exists);
	ubaseproxy_risk_printf(s, ue_id, jfs_modify_check_state);
	ubaseproxy_risk_printf(s, ue_id, jfs_query_jetty_not_exists);
	ubaseproxy_risk_printf(s, ue_id, jfs_bind_jetty_not_exists);
	ubaseproxy_risk_printf(s, ue_id, jfs_bind_not_in_jetty_mode);
	ubaseproxy_risk_printf(s, ue_id, jfs_bind_already_bound_group);
	ubaseproxy_risk_printf(s, ue_id, jfs_unbind_jetty_not_exists);
	ubaseproxy_risk_printf(s, ue_id, jfs_check_tx_jfc_not_exists);
	ubaseproxy_risk_printf(s, ue_id, jfs_check_rx_jfc_not_exists);
	ubaseproxy_risk_printf(s, ue_id, jfs_check_sl_not_valid);
	ubaseproxy_risk_printf(s, ue_id, jfs_check_jfs_seid);
	ubaseproxy_risk_printf(s, ue_id, jfs_check_jfr_not_exists);
	ubaseproxy_risk_printf(s, ue_id, jfs_check_jfr_type_not_match);
	ubaseproxy_risk_printf(s, ue_id, jfs_tx_jfc_ref_inc);
	ubaseproxy_risk_printf(s, ue_id, jfs_rx_jfc_ref_inc);
	ubaseproxy_risk_printf(s, ue_id, jfs_init_load_tx_jfc);
	ubaseproxy_risk_printf(s, ue_id, jfs_init_load_rx_jfc);
	ubaseproxy_risk_printf(s, ue_id, jfs_init_load_jfr_xa);
	ubaseproxy_risk_printf(s, ue_id, jfs_reduce_tx_jfc_dec);
	ubaseproxy_risk_printf(s, ue_id, jfs_reduce_rx_jfc_dec);
}

static void ubaseproxy_dump_ue_risk_jfr(struct seq_file *s, u8 ue_id)
{
	struct ubaseproxy_dev *udev = dev_get_drvdata(s->private);

	ubaseproxy_risk_printf(s, ue_id, jfr_req_len);
	ubaseproxy_risk_printf(s, ue_id, jfr_req_tag);
	ubaseproxy_risk_printf(s, ue_id, jfr_ctx_fixed);
	ubaseproxy_risk_printf(s, ue_id, jfr_field_rqe_shift);
	ubaseproxy_risk_printf(s, ue_id, jfr_field_rqe_size_shift);
	ubaseproxy_risk_printf(s, ue_id, jfr_field_rnr_timer);
	ubaseproxy_risk_printf(s, ue_id, jfr_field_type);
	ubaseproxy_risk_printf(s, ue_id, jfr_field_cqeie);
	ubaseproxy_risk_printf(s, ue_id, jfr_field_state);
	ubaseproxy_risk_printf(s, ue_id, jfr_rqe_depth_limit);
	ubaseproxy_risk_printf(s, ue_id, jfr_create_jfr_already_exists);
	ubaseproxy_risk_printf(s, ue_id, jfr_create_jfc_not_exists);
	ubaseproxy_risk_printf(s, ue_id, jfr_create_jfc_inc);
	ubaseproxy_risk_printf(s, ue_id, jfr_destroy_jfr_not_exists);
	ubaseproxy_risk_printf(s, ue_id, jfr_destroy_jfc_dec);
	ubaseproxy_risk_printf(s, ue_id, jfr_modify_jfr_not_exists);
	ubaseproxy_risk_printf(s, ue_id, jfr_modify_state_ctx_mask);
	ubaseproxy_risk_printf(s, ue_id, jfr_modify_state_check);
	ubaseproxy_risk_printf(s, ue_id, jfr_modify_limit_wl_ctx_mask);
	ubaseproxy_risk_printf(s, ue_id, jfr_modify_limit_wl_check);
	ubaseproxy_risk_printf(s, ue_id, jfr_query_jfr_not_exists);
}

static void ubaseproxy_dump_ue_risk_rc(struct seq_file *s, u8 ue_id)
{
	struct ubaseproxy_dev *udev = dev_get_drvdata(s->private);

	ubaseproxy_risk_printf(s, ue_id, rc_req_len);
	ubaseproxy_risk_printf(s, ue_id, rc_req_tag);
	ubaseproxy_risk_printf(s, ue_id, rc_ctx_fixed);
	ubaseproxy_risk_printf(s, ue_id, rc_field_rce_shift);
	ubaseproxy_risk_printf(s, ue_id, rc_create_rc_already_exists);
	ubaseproxy_risk_printf(s, ue_id, rc_destroy_rc_not_exists);
	ubaseproxy_risk_printf(s, ue_id, rc_query_rc_not_exists);
}

static void ubaseproxy_dump_ue_risk_jtg(struct seq_file *s, u8 ue_id)
{
	struct ubaseproxy_dev *udev = dev_get_drvdata(s->private);

	ubaseproxy_risk_printf(s, ue_id, jtg_req_len);
	ubaseproxy_risk_printf(s, ue_id, jtg_req_tag);
	ubaseproxy_risk_printf(s, ue_id, jtg_ctx_fixed);
	ubaseproxy_risk_printf(s, ue_id, jtg_field_start_jetty_id);
	ubaseproxy_risk_printf(s, ue_id, jtg_field_rsv);
	ubaseproxy_risk_printf(s, ue_id, jtg_field_jetty_number);
	ubaseproxy_risk_printf(s, ue_id, jtg_create_jtg_already_exists);
	ubaseproxy_risk_printf(s, ue_id, jtg_destroy_jtg_not_exists);
	ubaseproxy_risk_printf(s, ue_id, jtg_modify_jtg_not_exists);
	ubaseproxy_risk_printf(s, ue_id, jtg_query_jtg_not_exists);
	ubaseproxy_risk_printf(s, ue_id, jtg_check_jetty_group_valid);
	ubaseproxy_risk_printf(s, ue_id, jtg_check_jetty_num_mask);
	ubaseproxy_risk_printf(s, ue_id, jtg_check_jetty_num);
	ubaseproxy_risk_printf(s, ue_id, jtg_check_jtg_valid_mask);
	ubaseproxy_risk_printf(s, ue_id, jtg_check_jtg_valid);
	ubaseproxy_risk_printf(s, ue_id, jtg_bound_add);
	ubaseproxy_risk_printf(s, ue_id, jtg_bound_del);
	ubaseproxy_risk_printf(s, ue_id, jtg_del_jetty_bound);
	ubaseproxy_risk_printf(s, ue_id, jtg_add_jetty_bound);
	ubaseproxy_risk_printf(s, ue_id, jtg_evt_added_jetty);
	ubaseproxy_risk_printf(s, ue_id, jtg_evt_deled_jetty);
}

static void ubaseproxy_dump_ue_risk_eq(struct seq_file *s, u8 ue_id)
{
	struct ubaseproxy_dev *udev = dev_get_drvdata(s->private);

	ubaseproxy_risk_printf(s, ue_id, eq_req_len);
	ubaseproxy_risk_printf(s, ue_id, eq_req_tag);
	ubaseproxy_risk_printf(s, ue_id, eq_ctx_fixed);
	ubaseproxy_risk_printf(s, ue_id, eq_field_shift);
	ubaseproxy_risk_printf(s, ue_id, eq_field_eqe_coalesce_period);
	ubaseproxy_risk_printf(s, ue_id, eq_field_eqe_coalesce_cnt);
	ubaseproxy_risk_printf(s, ue_id, eq_field_eqn);
	ubaseproxy_risk_printf(s, ue_id, eq_create_eq_already_exists);
	ubaseproxy_risk_printf(s, ue_id, eq_destroy_eq_not_exists);
	ubaseproxy_risk_printf(s, ue_id, eq_destroy_jfc_not_empty);
	ubaseproxy_risk_printf(s, ue_id, eq_query_eq_not_exists);
	ubaseproxy_risk_printf(s, ue_id, eq_ceq_ref_dec);
	ubaseproxy_risk_printf(s, ue_id, eq_ceq_ref_inc);
}

static void ubaseproxy_dump_ue_risk_misc(struct seq_file *s, u8 ue_id)
{
	struct ubaseproxy_dev *udev = dev_get_drvdata(s->private);

	ubaseproxy_risk_printf(s, ue_id, reset_len);
	ubaseproxy_risk_printf(s, ue_id, mbx_opcode);
	ubaseproxy_risk_printf(s, ue_id, crq_msg_len);
	ubaseproxy_risk_printf(s, ue_id, crq_data_len);
	ubaseproxy_risk_printf(s, ue_id, crq_req_module);
	ubaseproxy_risk_printf(s, ue_id, ctx_msg_len);
	ubaseproxy_risk_printf(s, ue_id, ctx_ctx_type);
	ubaseproxy_risk_printf(s, ue_id, ctx_slot);
}

static int ubaseproxy_dbg_dump_risk_stats(struct seq_file *s, void *data)
{
	struct ubaseproxy_dev *udev = dev_get_drvdata(s->private);
	struct ubase_caps *ubase_caps;
	u8 managed_ue_num, i;

	ubase_caps = ubase_get_dev_caps(udev->comdev.adev);
	managed_ue_num = ubase_caps->ue_num - 1;
	for (i = 0; i < managed_ue_num; i++) {
		seq_printf(s, "\nUE(%u) risk stats:\n", i);
		ubaseproxy_dump_ue_risk_jfc(s, i);
		ubaseproxy_dump_ue_risk_jfs(s, i);
		ubaseproxy_dump_ue_risk_jfr(s, i);
		ubaseproxy_dump_ue_risk_rc(s, i);
		ubaseproxy_dump_ue_risk_jtg(s, i);
		ubaseproxy_dump_ue_risk_eq(s, i);
		ubaseproxy_dump_ue_risk_misc(s, i);
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
	{
		.name = "risk_stats",
		.dentry_index = UBASEPROXY_DBG_DENTRY_ROOT,
		.property = UBASE_SUP_UDMA | UBASE_SUP_UBL,
		.support = ubaseproxy_dbg_dentry_support,
		.init = ubase_dbg_seq_file_init,
		.read_func = ubaseproxy_dbg_dump_risk_stats,
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
