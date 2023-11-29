// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2022 - 2023 Mucse Corporation. */

#include <linux/debugfs.h>
#include <linux/module.h>

#include "rnp.h"

static struct dentry *rnp_dbg_root;

static char rnp_dbg_reg_ops_buf[256] = "";

/**
 * rnp_dbg_reg_ops_read - read for reg_ops datum
 * @filp: the opened file
 * @buffer: where to write the data for the user to read
 * @count: the size of the user's buffer
 * @ppos: file position offset
 **/
static ssize_t rnp_dbg_reg_ops_read(struct file *filp, char __user *buffer,
				    size_t count, loff_t *ppos)
{
	struct rnp_adapter *adapter = filp->private_data;
	char *buf;
	int len;

	/* don't allow partial reads */
	if (*ppos != 0)
		return 0;

	buf = kasprintf(GFP_KERNEL, "%s: %s\n", adapter->name,
			rnp_dbg_reg_ops_buf);
	if (!buf)
		return -ENOMEM;

	if (count < strlen(buf)) {
		kfree(buf);
		return -ENOSPC;
	}

	len = simple_read_from_buffer(buffer, count, ppos, buf,
				      strlen(buf));

	kfree(buf);
	return len;
}

/**
 * rnp_dbg_reg_ops_write - write into reg_ops datum
 * @filp: the opened file
 * @buffer: where to find the user's data
 * @count: the length of the user's data
 * @ppos: file position offset
 **/
static ssize_t rnp_dbg_reg_ops_write(struct file *filp,
				     const char __user *buffer,
				     size_t count, loff_t *ppos)
{
	struct rnp_adapter *adapter = filp->private_data;
	struct rnp_hw *hw = &adapter->hw;
	int len;

	/* don't allow partial writes */
	if (*ppos != 0)
		return 0;
	if (count >= sizeof(rnp_dbg_reg_ops_buf))
		return -ENOSPC;

	len = simple_write_to_buffer(rnp_dbg_reg_ops_buf,
				     sizeof(rnp_dbg_reg_ops_buf) - 1, ppos,
				     buffer, count);
	if (len < 0)
		return len;

	rnp_dbg_reg_ops_buf[len] = '\0';

	if (strncmp(rnp_dbg_reg_ops_buf, "write", 5) == 0) {
		u32 reg, value;
		int cnt;

		cnt = sscanf(&rnp_dbg_reg_ops_buf[5], "%x %x", &reg,
			     &value);
		if (cnt == 2) {
			if (reg >= 0x30000000) {
				rnp_mbx_reg_write(hw, reg, value);
				e_dev_info("write: 0x%08x = 0x%08x\n", reg,
					   value);
			} else {
				rnp_wr_reg(hw->hw_addr + reg, value);
				value = rnp_rd_reg(hw->hw_addr + reg);
				e_dev_info("write: 0x%08x = 0x%08x\n", reg,
					   value);
			}
		} else {
			e_dev_info("write <reg> <value>\n");
		}
	} else if (strncmp(rnp_dbg_reg_ops_buf, "read", 4) == 0) {
		u32 reg, value;
		int cnt;

		cnt = sscanf(&rnp_dbg_reg_ops_buf[4], "%x", &reg);
		if (cnt == 1) {
			if (reg >= 0x30000000)
				value = rnp_mbx_fw_reg_read(hw, reg);
			else
				value = rnp_rd_reg(hw->hw_addr + reg);
			snprintf(rnp_dbg_reg_ops_buf,
				 sizeof(rnp_dbg_reg_ops_buf),
				 "0x%08x: 0x%08x", reg, value);
			e_dev_info("read 0x%08x = 0x%08x\n", reg, value);
		} else {
			e_dev_info("read <reg>\n");
		}
	} else {
		e_dev_info("Unknown command %s\n", rnp_dbg_reg_ops_buf);
		e_dev_info("Available commands:\n");
		e_dev_info("   read <reg>\n");
		e_dev_info("   write <reg> <value>\n");
	}
	return count;
}

static const struct file_operations rnp_dbg_reg_ops_fops = {
	.owner = THIS_MODULE,
	.open = simple_open,
	.read = rnp_dbg_reg_ops_read,
	.write = rnp_dbg_reg_ops_write,
};

static char rnp_dbg_netdev_ops_buf[256] = "";

/**
 * rnp_dbg_netdev_ops_read - read for netdev_ops datum
 * @filp: the opened file
 * @buffer: where to write the data for the user to read
 * @count: the size of the user's buffer
 * @ppos: file position offset
 **/
static ssize_t rnp_dbg_netdev_ops_read(struct file *filp,
				       char __user *buffer, size_t count,
				       loff_t *ppos)
{
	struct rnp_adapter *adapter = filp->private_data;
	char *buf;
	int len;

	/* don't allow partial reads */
	if (*ppos != 0)
		return 0;

	buf = kasprintf(GFP_KERNEL, "%s: %s\n", adapter->name,
			rnp_dbg_netdev_ops_buf);
	if (!buf)
		return -ENOMEM;

	if (count < strlen(buf)) {
		kfree(buf);
		return -ENOSPC;
	}

	len = simple_read_from_buffer(buffer, count, ppos, buf,
				      strlen(buf));

	kfree(buf);
	return len;
}

/**
 * rnp_dbg_netdev_ops_write - write into netdev_ops datum
 * @filp: the opened file
 * @buffer: where to find the user's data
 * @count: the length of the user's data
 * @ppos: file position offset
 **/
static ssize_t rnp_dbg_netdev_ops_write(struct file *filp,
					const char __user *buffer,
					size_t count, loff_t *ppos)
{
	struct rnp_adapter *adapter = filp->private_data;
	int len;

	/* don't allow partial writes */
	if (*ppos != 0)
		return 0;
	if (count >= sizeof(rnp_dbg_netdev_ops_buf))
		return -ENOSPC;

	len = simple_write_to_buffer(rnp_dbg_netdev_ops_buf,
				     sizeof(rnp_dbg_netdev_ops_buf) - 1,
				     ppos, buffer, count);
	if (len < 0)
		return len;

	rnp_dbg_netdev_ops_buf[len] = '\0';

	if (strncmp(rnp_dbg_netdev_ops_buf, "stat", 4) == 0) {
		rnp_info("adapter->stat=0x%lx\n", adapter->state);
		rnp_info("adapter->tx_timeout_count=%d\n",
			 adapter->tx_timeout_count);
	} else if (strncmp(rnp_dbg_netdev_ops_buf, "tx_timeout", 10) ==
		   0) {
		adapter->netdev->netdev_ops->ndo_tx_timeout(
			adapter->netdev, UINT_MAX);
		e_dev_info("tx_timeout called\n");
	} else {
		e_dev_info("Unknown command: %s\n",
			   rnp_dbg_netdev_ops_buf);
		e_dev_info("Available commands:\n");
		e_dev_info("    tx_timeout\n");
	}
	return count;
}

static const struct file_operations rnp_dbg_netdev_ops_fops = {
	.owner = THIS_MODULE,
	.open = simple_open,
	.read = rnp_dbg_netdev_ops_read,
	.write = rnp_dbg_netdev_ops_write,
};

static ssize_t rnp_dbg_netdev_temp_read(struct file *filp,
					char __user *buffer, size_t count,
					loff_t *ppos)
{
	struct rnp_adapter *adapter = filp->private_data;
	struct rnp_hw *hw = &adapter->hw;
	char *buf;
	int len;
	int temp = 0, voltage = 0;

	/* don't allow partial reads */
	if (*ppos != 0)
		return 0;

	temp = rnp_mbx_get_temp(hw, &voltage);

	buf = kasprintf(GFP_KERNEL, "%s: temp: %d oC voltage:%d mV\n",
			adapter->name, temp, voltage);
	if (!buf)
		return -ENOMEM;

	if (count < strlen(buf)) {
		kfree(buf);
		return -ENOSPC;
	}

	len = simple_read_from_buffer(buffer, count, ppos, buf,
				      strlen(buf));

	kfree(buf);
	return len;
}
static const struct file_operations rnp_dbg_netdev_temp = {
	.owner = THIS_MODULE,
	.open = simple_open,
	.read = rnp_dbg_netdev_temp_read,
};

/**
 * rnp_dbg_adapter_init - setup the debugfs directory for the adapter
 * @adapter: the adapter that is starting up
 **/
void rnp_dbg_adapter_init(struct rnp_adapter *adapter)
{
	const char *name = adapter->name;
	//const char *name = pci_name(adapter->pdev);
	struct dentry *pfile;

	adapter->rnp_dbg_adapter = debugfs_create_dir(name, rnp_dbg_root);
	if (adapter->rnp_dbg_adapter) {
		pfile = debugfs_create_file("reg_ops", 0600,
					    adapter->rnp_dbg_adapter,
					    adapter,
					    &rnp_dbg_reg_ops_fops);
		if (!pfile)
			e_dev_err("debugfs reg_ops for %s failed\n", name);
		pfile = debugfs_create_file("netdev_ops", 0600,
					    adapter->rnp_dbg_adapter,
					    adapter,
					    &rnp_dbg_netdev_ops_fops);
		if (!pfile)
			e_dev_err("debugfs netdev_ops for %s failed\n",
				  name);

		pfile = debugfs_create_file("temp", 0600,
					    adapter->rnp_dbg_adapter,
					    adapter, &rnp_dbg_netdev_temp);
		if (!pfile)
			e_dev_err("debugfs temp for %s failed\n", name);
	} else {
		e_dev_err("debugfs entry for %s failed\n", name);
	}
}

/**
 * rnp_dbg_adapter_exit - clear out the adapter's debugfs entries
 * @pf: the pf that is stopping
 **/
void rnp_dbg_adapter_exit(struct rnp_adapter *adapter)
{
	debugfs_remove_recursive(adapter->rnp_dbg_adapter);
	adapter->rnp_dbg_adapter = NULL;
}

/**
 * rnp_dbg_init - start up debugfs for the driver
 **/
void rnp_dbg_init(void)
{
	rnp_dbg_root = debugfs_create_dir(rnp_driver_name, NULL);
	if (rnp_dbg_root == NULL)
		pr_err("init of debugfs failed\n");
}

/**
 * rnp_dbg_exit - clean out the driver's debugfs entries
 **/
void rnp_dbg_exit(void)
{
	debugfs_remove_recursive(rnp_dbg_root);
}
