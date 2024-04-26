// SPDX-License-Identifier: GPL-2.0+
/* Hisilicon UNIC Linux driver
 * Copyright (c) 2023-2023 Hisilicon Limited.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 *
 */

#include <linux/debugfs.h>

#include "hnae3.h"
#include "hns3_debugfs.h"
#include "hns3_enet.h"
#include "hns3_unic_debugfs.h"

static const char ub_dbg_root_name[] = "ub";
static struct dentry *ub_dbg_root;

static struct hns3_dbg_dentry_info ub_dbg_dentry[] = {
	{
		.name = "ip_tbl"
	},
	{
		.name = "guid_tbl"
	},
	{
		.name = "fastpath_info"
	},
};

static int hns3_unic_dbg_file_init(struct hnae3_handle *handle, u32 cmd);

static const struct hns3_dbg_cmd_info ub_dbg_cmd[] = {
	{
		.name = "ip_tbl_spec",
		.cmd = HNAE3_DBG_CMD_IP_SPEC,
		.dentry = UB_DBG_DENTRY_IP,
		.buf_len = HNS3_DBG_READ_LEN,
		.init = hns3_unic_dbg_file_init,
	},
	{
		.name = "guid_tbl_spec",
		.cmd = HNAE3_DBG_CMD_GUID_SPEC,
		.dentry = UB_DBG_DENTRY_GUID,
		.buf_len = HNS3_DBG_READ_LEN,
		.init = hns3_unic_dbg_file_init,
	},
	{
		.name = "ip_tbl_list",
		.cmd = HNAE3_DBG_CMD_IP_LIST,
		.dentry = UB_DBG_DENTRY_IP,
		.buf_len = HNS3_DBG_READ_LEN,
		.init = hns3_unic_dbg_file_init,
	},
	{
		.name = "guid_tbl_list",
		.cmd = HNAE3_DBG_CMD_GUID_LIST,
		.dentry = UB_DBG_DENTRY_GUID,
		.buf_len = HNS3_DBG_READ_LEN,
		.init = hns3_unic_dbg_file_init,
	},
	{
		.name = "fastpath_info",
		.cmd = HNAE3_DBG_CMD_FASTPATH_INFO,
		.dentry = UB_DBG_DENTRY_FASTPATH,
		.buf_len = HNS3_DBG_READ_LEN,
		.init = hns3_unic_dbg_file_init,
	},
};

static int hns3_unic_dbg_get_cmd_index(struct hns3_dbg_data *dbg_data,
				       u32 *index)
{
	u32 i;

	for (i = 0; i < ARRAY_SIZE(ub_dbg_cmd); i++) {
		if (ub_dbg_cmd[i].cmd == dbg_data->cmd) {
			*index = i;
			return 0;
		}
	}

	dev_err(&dbg_data->handle->pdev->dev, "unknown unic command(%d)\n",
		dbg_data->cmd);
	return -EINVAL;
}

static int hns3_unic_dbg_read_cmd(struct hns3_dbg_data *dbg_data,
				  enum hnae3_dbg_cmd cmd, char *buf, int len)
{
	const struct hnae3_ae_ops *ops = dbg_data->handle->ae_algo->ops;

	if (!ops->dbg_read_cmd)
		return -EOPNOTSUPP;

	return ops->dbg_read_cmd(dbg_data->handle, cmd, buf, len);
}

static ssize_t hns3_unic_dbg_read(struct file *filp, char __user *buffer,
				  size_t count, loff_t *ppos)
{
	struct hns3_dbg_data *dbg_data = filp->private_data;
	struct hnae3_handle *handle = dbg_data->handle;
	struct hns3_nic_priv *priv = handle->priv;
	char **save_buf;
	char *read_buf;
	ssize_t size;
	u32 index;
	int ret;

	ret = hns3_unic_dbg_get_cmd_index(dbg_data, &index);
	if (ret)
		return ret;

	mutex_lock(&handle->dbgfs_lock);
	save_buf = &handle->ub_dbgfs_buf[index];

	if (!test_bit(HNS3_NIC_STATE_INITED, &priv->state) ||
	    test_bit(HNS3_NIC_STATE_RESETTING, &priv->state)) {
		ret = -EBUSY;
		goto out;
	}

	if (*save_buf) {
		read_buf = *save_buf;
	} else {
		read_buf = kvzalloc(ub_dbg_cmd[index].buf_len, GFP_KERNEL);
		if (!read_buf) {
			ret = -ENOMEM;
			goto out;
		}

		/* save the buffer addr until the last read operation */
		*save_buf = read_buf;

		/* get data ready for the first time to read */
		ret = hns3_unic_dbg_read_cmd(dbg_data, ub_dbg_cmd[index].cmd,
					     read_buf,
					     ub_dbg_cmd[index].buf_len);
		if (ret)
			goto out;
	}

	size = simple_read_from_buffer(buffer, count, ppos, read_buf,
				       strlen(read_buf));
	if (size > 0) {
		mutex_unlock(&handle->dbgfs_lock);
		return size;
	}

out:
	/* free the buffer for the last read operation */
	if (*save_buf) {
		kvfree(*save_buf);
		*save_buf = NULL;
	}

	mutex_unlock(&handle->dbgfs_lock);
	return ret;
}

static const struct file_operations ub_dbg_fops = {
	.owner = THIS_MODULE,
	.open  = simple_open,
	.read  = hns3_unic_dbg_read,
};

static int hns3_unic_dbg_file_init(struct hnae3_handle *handle, u32 cmd)
{
	struct hns3_dbg_data *data;
	struct dentry *entry_dir;

	data = devm_kzalloc(&handle->pdev->dev, sizeof(*data), GFP_KERNEL);
	if (!data)
		return -ENOMEM;

	data->handle = handle;
	data->cmd = ub_dbg_cmd[cmd].cmd;
	entry_dir = ub_dbg_dentry[ub_dbg_cmd[cmd].dentry].dentry;
	debugfs_create_file(ub_dbg_cmd[cmd].name, 0400, entry_dir,
			    data, &ub_dbg_fops);

	return 0;
}

int hns3_unic_dbg_init(struct hnae3_handle *handle, struct dentry *parent)
{
	int ret = 0;
	u32 i;

	if (!parent)
		return -EINVAL;

	handle->ub_dbgfs_buf = devm_kcalloc(&handle->pdev->dev,
					    ARRAY_SIZE(ub_dbg_cmd),
					    sizeof(*handle->ub_dbgfs_buf),
					    GFP_KERNEL);
	if (!handle->ub_dbgfs_buf)
		return -ENOMEM;

	ub_dbg_root = debugfs_create_dir(ub_dbg_root_name, parent);

	for (i = 0; i < UB_DBG_DENTRY_END; i++)
		ub_dbg_dentry[i].dentry =
			debugfs_create_dir(ub_dbg_dentry[i].name, ub_dbg_root);

	for (i = 0; i < ARRAY_SIZE(ub_dbg_cmd); i++) {
		if (!ub_dbg_cmd[i].init) {
			dev_err(&handle->pdev->dev,
				"cmd %s lack of init func\n",
				ub_dbg_cmd[i].name);
			ret = -EINVAL;
			break;
		}

		ret = ub_dbg_cmd[i].init(handle, i);
		if (ret) {
			dev_err(&handle->pdev->dev, "failed to init cmd %s\n",
				ub_dbg_cmd[i].name);
			break;
		}
	}

	return ret;
}

void hns3_unic_dbg_uninit(struct hnae3_handle *handle)
{
	u32 i;

	for (i = 0; i < ARRAY_SIZE(ub_dbg_cmd); i++)
		if (handle->ub_dbgfs_buf[i]) {
			kvfree(handle->ub_dbgfs_buf[i]);
			handle->ub_dbgfs_buf[i] = NULL;
		}
}
