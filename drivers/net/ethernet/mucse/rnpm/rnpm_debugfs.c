// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2022 - 2024 Mucse Corporation. */
#include <linux/debugfs.h>
#include <linux/module.h>

#include "rnpm.h"
#include "rnpm_mbx_fw.h"

#ifdef CONFIG_DEBUG_FS
static struct dentry *rnpm_dbg_root;

static char rnpm_dbg_reg_ops_buf[256] = "";

/**
 * rnpm_dbg_reg_ops_read - read for reg_ops datum
 * @filp: the opened file
 * @buffer: where to write the data for the user to read
 * @count: the size of the user's buffer
 * @ppos: file position offset
 **/
static ssize_t rnpm_dbg_reg_ops_read(struct file *filp, char __user *buffer,
				     size_t count, loff_t *ppos)
{
	struct rnpm_adapter *adapter = filp->private_data;
	char *buf;
	int len;

	/* don't allow partial reads */
	if (*ppos != 0)
		return 0;

	buf = kasprintf(GFP_KERNEL, "%s: %s\n", adapter->name,
			rnpm_dbg_reg_ops_buf);
	if (!buf)
		return -ENOMEM;

	if (count < strlen(buf)) {
		kfree(buf);
		return -ENOSPC;
	}

	len = simple_read_from_buffer(buffer, count, ppos, buf, strlen(buf));

	kfree(buf);
	return len;
}

/**
 * rnpm_dbg_reg_ops_write - write into reg_ops datum
 * @filp: the opened file
 * @buffer: where to find the user's data
 * @count: the length of the user's data
 * @ppos: file position offset
 **/
static ssize_t rnpm_dbg_reg_ops_write(struct file *filp,
				      const char __user *buffer, size_t count,
				      loff_t *ppos)
{
	struct rnpm_adapter *adapter = filp->private_data;
	struct rnpm_hw *hw = &adapter->hw;
	int len;

	/* don't allow partial writes */
	if (*ppos != 0)
		return 0;
	if (count >= sizeof(rnpm_dbg_reg_ops_buf))
		return -ENOSPC;

	len = simple_write_to_buffer(rnpm_dbg_reg_ops_buf,
				     sizeof(rnpm_dbg_reg_ops_buf) - 1, ppos,
				     buffer, count);
	if (len < 0)
		return len;

	rnpm_dbg_reg_ops_buf[len] = '\0';

	if (strncmp(rnpm_dbg_reg_ops_buf, "write", 5) == 0) {
		u32 reg, value;
		int cnt;

		cnt = sscanf(&rnpm_dbg_reg_ops_buf[5], "%x %x", &reg, &value);
		if (cnt == 2) {
			if (reg >= 0x30000000) {
				rnpm_mbx_reg_write(hw, reg, value);
			} else {
				rnpm_wr_reg(hw->hw_addr + reg, value);
				value = rnpm_rd_reg(hw->hw_addr + reg);
			}
			e_dev_info("write: 0x%08x = 0x%08x\n", reg, value);
		} else {
			e_dev_info("write <reg> <value>\n");
		}
	} else if (strncmp(rnpm_dbg_reg_ops_buf, "read", 4) == 0) {
		u32 reg, value;
		int cnt;

		cnt = sscanf(&rnpm_dbg_reg_ops_buf[4], "%x", &reg);
		if (cnt == 1) {
			if (reg >= 0x30000000)
				value = rnpm_mbx_fw_reg_read(hw, reg);
			else
				value = rnpm_rd_reg(hw->hw_addr + reg);
			snprintf(rnpm_dbg_reg_ops_buf,
				 sizeof(rnpm_dbg_reg_ops_buf), "0x%08x: 0x%08x",
				 reg, value);
			e_dev_info("read 0x%08x = 0x%08x\n", reg, value);
		} else {
			e_dev_info("read <reg>\n");
		}
	} else {
		e_dev_info("Unknown command %s\n", rnpm_dbg_reg_ops_buf);
		e_dev_info("Available commands:\n");
		e_dev_info("   read <reg>\n");
		e_dev_info("   write <reg> <value>\n");
	}
	return count;
}

static const struct file_operations rnpm_dbg_reg_ops_fops = {
	.owner = THIS_MODULE,
	.open = simple_open,
	.read = rnpm_dbg_reg_ops_read,
	.write = rnpm_dbg_reg_ops_write,
};

static char rnpm_dbg_netdev_ops_buf[256] = "";

/**
 * rnpm_dbg_netdev_ops_read - read for netdev_ops datum
 * @filp: the opened file
 * @buffer: where to write the data for the user to read
 * @count: the size of the user's buffer
 * @ppos: file position offset
 **/
static ssize_t rnpm_dbg_netdev_ops_read(struct file *filp, char __user *buffer,
					size_t count, loff_t *ppos)
{
	struct rnpm_adapter *adapter = filp->private_data;
	// struct rnpm_hw *hw = &adapter->hw;
	char *buf;
	int len;

	/* don't allow partial reads */
	if (*ppos != 0)
		return 0;

	buf = kasprintf(GFP_KERNEL, "%s: %s\n", adapter->name,
			rnpm_dbg_netdev_ops_buf);
	if (!buf)
		return -ENOMEM;

	if (count < strlen(buf)) {
		kfree(buf);
		return -ENOSPC;
	}

	len = simple_read_from_buffer(buffer, count, ppos, buf, strlen(buf));

	kfree(buf);
	return len;
}

/**
 * rnpm_dbg_netdev_ops_write - write into netdev_ops datum
 * @filp: the opened file
 * @buffer: where to find the user's data
 * @count: the length of the user's data
 * @ppos: file position offset
 **/
static ssize_t rnpm_dbg_netdev_ops_write(struct file *filp,
					 const char __user *buffer,
					 size_t count, loff_t *ppos)
{
	struct rnpm_adapter *adapter = filp->private_data;
	int len;

	/* don't allow partial writes */
	if (*ppos != 0)
		return 0;
	if (count >= sizeof(rnpm_dbg_netdev_ops_buf))
		return -ENOSPC;

	len = simple_write_to_buffer(rnpm_dbg_netdev_ops_buf,
				     sizeof(rnpm_dbg_netdev_ops_buf) - 1, ppos,
				     buffer, count);
	if (len < 0)
		return len;

	rnpm_dbg_netdev_ops_buf[len] = '\0';

	if (strncmp(rnpm_dbg_netdev_ops_buf, "stat", 4) == 0) {
		rnpm_info("adapter->stat=0x%lx\n", adapter->state);
		rnpm_info("adapter->tx_timeout_count=%d\n",
			  adapter->tx_timeout_count);
	} else if (strncmp(rnpm_dbg_netdev_ops_buf, "tx_timeout", 10) == 0) {
		adapter->netdev->netdev_ops->ndo_tx_timeout(adapter->netdev,
							    UINT_MAX);
		e_dev_info("tx_timeout called\n");
	} else {
		e_dev_info("Unknown command: %s\n", rnpm_dbg_netdev_ops_buf);
		e_dev_info("Available commands:\n");
		e_dev_info("    tx_timeout\n");
	}
	return count;
}

static const struct file_operations rnpm_dbg_netdev_ops_fops = {
	.owner = THIS_MODULE,
	.open = simple_open,
	.read = rnpm_dbg_netdev_ops_read,
	.write = rnpm_dbg_netdev_ops_write,
};

static char rnpm_dbg_phy_ops_buf[256] = "";

/**
 * rnpm_dbg_phy_ops_read - read for reg_ops datum
 * @filp: the opened file
 * @buffer: where to write the data for the user to read
 * @count: the size of the user's buffer
 * @ppos: file position offset
 **/
static ssize_t rnpm_dbg_phy_ops_read(struct file *filp, char __user *buffer,
				     size_t count, loff_t *ppos)
{
	struct rnpm_adapter *adapter = filp->private_data;
	char *buf;
	int len;

	/* don't allow partial reads */
	if (*ppos != 0)
		return 0;

	buf = kasprintf(GFP_KERNEL, "%s: %s\n", adapter->name,
			rnpm_dbg_phy_ops_buf);
	if (!buf)
		return -ENOMEM;

	if (count < strlen(buf)) {
		kfree(buf);
		return -ENOSPC;
	}

	len = simple_read_from_buffer(buffer, count, ppos, buf, strlen(buf));

	kfree(buf);
	return len;
}

/**
 * rnpm_dbg_reg_ops_write - write into reg_ops datum
 * @filp: the opened file
 * @buffer: where to find the user's data
 * @count: the length of the user's data
 * @ppos: file position offset
 **/
static ssize_t rnpm_dbg_phy_ops_write(struct file *filp,
				      const char __user *buffer, size_t count,
				      loff_t *ppos)
{
	struct rnpm_adapter *adapter = filp->private_data;
	struct rnpm_hw *hw = &adapter->hw;
	int len;

	/* don't allow partial writes */
	if (*ppos != 0)
		return 0;
	if (count >= sizeof(rnpm_dbg_phy_ops_buf))
		return -ENOSPC;

	len = simple_write_to_buffer(rnpm_dbg_phy_ops_buf,
				     sizeof(rnpm_dbg_phy_ops_buf) - 1, ppos,
				     buffer, count);
	if (len < 0)
		return len;

	rnpm_dbg_phy_ops_buf[len] = '\0';

	if (strncmp(rnpm_dbg_phy_ops_buf, "write", 5) == 0) {
		u32 reg, value;
		int cnt;

		cnt = sscanf(&rnpm_dbg_phy_ops_buf[5], "%x %x", &reg, &value);

		if (cnt == 2) {
			if (rnpm_mbx_phy_write(hw, reg, value) == 0)
				e_dev_info("write phy: 0x%08x = 0x%08x\n", reg,
					   value);
			else
				e_dev_info(
					"write phy failed: 0x%08x = 0x%08x\n",
					reg, value);
		} else {
			e_dev_info("write phy <reg> <value>\n");
		}

	} else if (strncmp(rnpm_dbg_phy_ops_buf, "read", 4) == 0) {
		u32 reg, value;
		int cnt;

		cnt = sscanf(&rnpm_dbg_phy_ops_buf[4], "%x", &reg);
		if (cnt == 1) {
			if (rnpm_mbx_phy_read(hw, reg, &value) == 0) {
				sprintf(rnpm_dbg_phy_ops_buf,
					"read phy 0x%08x = 0x%08x\n", reg,
					value);
				rnpm_info("read phy 0x%08x = 0x%08x\n", reg,
					  value);
			} else
				e_dev_info("read phy failed 0x%08x = 0x%08x\n",
					   reg, value);
		} else {
			e_dev_info("read phy <reg>\n");
		}
	} else {
		e_dev_info("Unknown command %s\n", rnpm_dbg_phy_ops_buf);
		e_dev_info("Available commands:\n");
		e_dev_info("   read <phyreg>\n");
		e_dev_info("   write <phyreg> <value>\n");
	}
	return count;
}

static const struct file_operations rnpm_dbg_phy_ops_fops = {
	.owner = THIS_MODULE,
	.open = simple_open,
	.read = rnpm_dbg_phy_ops_read,
	.write = rnpm_dbg_phy_ops_write,
};

/**
 * rnpm_dbg_adapter_init - setup the debugfs directory for the adapter
 * @adapter: the adapter that is starting up
 **/
void rnpm_dbg_adapter_init(struct rnpm_adapter *adapter)
{
	const char *name = adapter->name;
	struct dentry *pfile;

	adapter->rnpm_dbg_adapter = debugfs_create_dir(name, rnpm_dbg_root);
	if (adapter->rnpm_dbg_adapter) {
		pfile = debugfs_create_file("reg_ops", 0600,
					    adapter->rnpm_dbg_adapter, adapter,
					    &rnpm_dbg_reg_ops_fops);
		if (!pfile)
			e_dev_err("debugfs reg_ops for %s failed\n", name);
		pfile = debugfs_create_file("netdev_ops", 0600,
					    adapter->rnpm_dbg_adapter, adapter,
					    &rnpm_dbg_netdev_ops_fops);
		if (!pfile)
			e_dev_err("debugfs netdev_ops for %s failed\n", name);
		pfile = debugfs_create_file("phy_ops", 0600,
					    adapter->rnpm_dbg_adapter, adapter,
					    &rnpm_dbg_phy_ops_fops);
		if (!pfile)
			e_dev_err("debugfs netdev_ops for %s failed\n", name);
	} else {
		e_dev_err("debugfs entry for %s failed\n", name);
	}
}

/**
 * rnpm_dbg_adapter_exit - clear out the adapter's debugfs entries
 * @pf: the pf that is stopping
 **/
void rnpm_dbg_adapter_exit(struct rnpm_adapter *adapter)
{
	debugfs_remove_recursive(adapter->rnpm_dbg_adapter);
	adapter->rnpm_dbg_adapter = NULL;
}

/**
 * rnpm_dbg_init - start up debugfs for the driver
 **/
void rnpm_dbg_init(void)
{
	rnpm_dbg_root = debugfs_create_dir(rnpm_driver_name, NULL);
	if (rnpm_dbg_root == NULL)
		pr_err("init of debugfs failed\n");
}

/**
 * rnpm_dbg_exit - clean out the driver's debugfs entries
 **/
void rnpm_dbg_exit(void)
{
	debugfs_remove_recursive(rnpm_dbg_root);
}
#endif
