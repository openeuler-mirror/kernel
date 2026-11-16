// SPDX-License-Identifier: GPL-2.0-only
#include "nsevf.h"

#include <linux/fs.h>
#include <linux/debugfs.h>
#include <linux/random.h>

#include "nsevf_type.h"
#include "nsevf_fdir.h"
#include "nsevf_prototype.h"

#ifdef CONFIG_DEBUG_FS

static struct dentry *nsevf_debugfs_root;

static ssize_t nsevf_debugfs_vf_info_wfunc(struct file *filp,
					   const char __user *buf, size_t count,
					   loff_t *ppos)
{
	struct nsevf_adapter *adapter = filp->private_data;
	struct device *dev = nsevf_adapter_to_dev(adapter);
	char *cmd_buf, *cmd_buf_tmp;
	ssize_t ret;
	char **argv;
	int argc;

	cmd_buf = memdup_user(buf, count + 1);
	if (IS_ERR(cmd_buf))
		return PTR_ERR(cmd_buf);
	cmd_buf[count] = '\0';

	cmd_buf_tmp = strchr(cmd_buf, '\n');
	if (cmd_buf_tmp) {
		*cmd_buf_tmp = '\0';
		count = (size_t)cmd_buf_tmp - (size_t)cmd_buf + 1;
	}

	argv = argv_split(GFP_KERNEL, cmd_buf, &argc);
	if (!argv) {
		ret = -ENOMEM;
		goto err_copy_from_user;
	}

	if (argc != 1)
		goto bad_usage;

	dev_info(dev, "num_active_queues: %d\n", adapter->num_active_queues);

	dev_info(dev, "num_req_queues: %d\n", adapter->num_req_queues);

	dev_info(dev, "tx_timeout_count: %d\n", adapter->tx_timeout_count);

	dev_info(dev, "rx_desc_count: %d, tx_desc_count: %d\n",
		 adapter->rx_desc_count, adapter->tx_desc_count);

	dev_info(dev, "num_msix_vectors: %d\n", adapter->num_msix_vectors);

	dev_info(dev, "netdev_registered: %d\n", adapter->netdev_registered);

	dev_info(dev, "link_up: %d, link_speed: %d\n", adapter->link_up,
		 adapter->link_speed);

	dev_info(dev, "lan_tx_use_cq: %d\n", adapter->sw_conf.lan_tx_use_cq);

	dev_info(dev, "lan_rx_ena_rsc: %d\n", adapter->sw_conf.lan_rx_ena_rsc);

	if (adapter->vf_res)
		dump_vf_res(adapter, adapter->vf_res);

	dev_info(dev, "pf_version: major=%d, minor=%d\n",
		 adapter->pf_version.major, adapter->pf_version.minor);

	dev_info(dev, "supported_rxdids: %lX\n",
		 (unsigned long)adapter->supported_rxdids.supported_rxdids);

	dev_info(dev, "current_op: %d (%s)\n", adapter->current_op,
		 virtchnl_op_str(adapter->current_op));

	dev_info(dev, "flags: %X\n", adapter->flags);
	dev_info(dev, "\t NSEVF_FLAG_PF_COMMS_FAILED: %d\n",
		 !!(adapter->flags & NSEVF_FLAG_PF_COMMS_FAILED));
	dev_info(dev, "\t NSEVF_FLAG_RESET_PENDING: %d\n",
		 !!(adapter->flags & NSEVF_FLAG_RESET_PENDING));
	dev_info(dev, "\t NSEVF_FLAG_RESET_NEEDED: %d\n",
		 !!(adapter->flags & NSEVF_FLAG_RESET_NEEDED));
	dev_info(dev, "\t NSEVF_FLAG_BYPASS_SWITCH: %d\n",
		 !!(adapter->flags & NSEVF_FLAG_BYPASS_SWITCH));
	dev_info(dev, "\t NSEVF_FLAG_REINIT_ITR_NEEDED: %d\n",
		 !!(adapter->flags & NSEVF_FLAG_REINIT_ITR_NEEDED));
	dev_info(dev, "\t NSEVF_FLAG_QUEUES_ENABLED: %d\n",
		 !!(adapter->flags & NSEVF_FLAG_QUEUES_ENABLED));
	dev_info(dev, "\t NSEVF_FLAG_QUEUES_DISABLED: %d\n",
		 !!(adapter->flags & NSEVF_FLAG_QUEUES_DISABLED));
	dev_info(dev, "\t NSEVF_FLAG_REINIT_MSIX_NEEDED: %d\n",
		 !!(adapter->flags & NSEVF_FLAG_REINIT_MSIX_NEEDED));
	dev_info(dev, "\t NSEVF_FLAG_RESET_DETECTED: %d\n",
		 !!(adapter->flags & NSEVF_FLAG_RESET_DETECTED));
	dev_info(dev, "\t NSEVF_FLAG_SUSPEND_RUNNING: %d\n",
		 !!(adapter->flags & NSEVF_FLAG_SUSPEND_RUNNING));
	dev_info(dev, "\t NSEVF_FLAG_RESET_FAILED_DEV_UP: %d\n",
		 !!(adapter->flags & NSEVF_FLAG_RESET_FAILED_DEV_UP));
	dev_info(dev, "\t NSEVF_FLAG_FDIR_CAPABLE: %d\n",
		 !!(adapter->flags & NSEVF_FLAG_FDIR_CAPABLE));

	dev_info(dev, "aq_required: %lX\n",
		 (unsigned long)adapter->aq_required);

	dev_info(dev, "state: %d (%s), last_state: %d (%s)\n", adapter->state,
		 nsevf_state_str(adapter->state), adapter->last_state,
		 nsevf_state_str(adapter->last_state));

	dev_info(dev, "crit_section: %lX\n", adapter->crit_section);

	/* if we get here, nothing went wrong; return bytes copied */
	ret = (ssize_t)count;

command_write_done:
	argv_free(argv);
err_copy_from_user:
	kfree(cmd_buf);
	return ret;

bad_usage:
	dev_info(dev, "invalid input, usage: echo 'any words'\n");
	ret = -EINVAL;
	goto command_write_done;
}

static const struct file_operations nsevf_debugfs_vf_info_fops = {
	.owner = THIS_MODULE,
	.open = simple_open,
	.write = nsevf_debugfs_vf_info_wfunc,
	.llseek = default_llseek,
};

static ssize_t nsevf_debugfs_vf_params_rfunc(struct file *filp, char __user *to,
					     size_t count, loff_t *ppos)
{
	struct nsevf_adapter *adapter = filp->private_data;
	struct nsevf_hw *hw = &adapter->hw;
	char *buf = NULL;
	int desc = 0;
	int ret;

	buf = kzalloc(4096, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	desc += sprintf(buf + desc, "wq_low_interval: %d\n",
			adapter->wq_low_interval);

	desc += sprintf(buf + desc, "wq_low_mid_interval: %d\n",
			adapter->wq_low_mid_interval);

	desc += sprintf(buf + desc, "wq_mid_interval: %d\n",
			adapter->wq_mid_interval);

	desc += sprintf(buf + desc, "wq_mid_high_interval: %d\n",
			adapter->wq_mid_high_interval);

	desc += sprintf(buf + desc, "wq_high_interval: %d\n",
			adapter->wq_high_interval);

	desc += sprintf(buf + desc, "lan_no_xmit: %d\n",
			adapter->debug_lan_no_xmit);

	desc += sprintf(buf + desc, "debug_mask: %lX\n",
			(unsigned long)hw->debug_mask);

	ret = simple_read_from_buffer(to, count, ppos, buf, desc);

	kfree(buf);

	return ret;
}

static ssize_t nsevf_debugfs_vf_params_wfunc(struct file *filp,
					     const char __user *buf,
					     size_t count, loff_t *ppos)
{
	struct nsevf_adapter *adapter = filp->private_data;
	struct nsevf_hw *hw = &adapter->hw;
	struct device *dev = nsevf_adapter_to_dev(adapter);
	char *cmd_buf, *cmd_buf_tmp;
	ssize_t ret;
	char **argv;
	int argc;
	unsigned int new_val;

	if (*ppos != 0)
		return 0;

	cmd_buf = memdup_user(buf, count + 1);
	if (IS_ERR(cmd_buf))
		return PTR_ERR(cmd_buf);
	cmd_buf[count] = '\0';

	cmd_buf_tmp = strchr(cmd_buf, '\n');
	if (cmd_buf_tmp) {
		*cmd_buf_tmp = '\0';
		count = (size_t)cmd_buf_tmp - (size_t)cmd_buf + 1;
	}

	argv = argv_split(GFP_KERNEL, cmd_buf, &argc);
	if (!argv) {
		ret = -ENOMEM;
		goto err_copy_from_user;
	}

	if (argc < 2)
		goto bad_usage;

	if (!strcmp(argv[0], "debug_mask")) {
		if (kstrtouint(argv[1], 16, &new_val))
			goto bad_usage;
		hw->debug_mask = new_val;
	} else if (!strcmp(argv[0], "lan_no_xmit")) {
		if (kstrtouint(argv[1], 10, &new_val))
			goto bad_usage;
		adapter->debug_lan_no_xmit = new_val;
	} else {
		goto bad_usage;
	}

	/* if we get here, nothing went wrong; return bytes copied */
	ret = (ssize_t)count;

command_write_done:
	argv_free(argv);
err_copy_from_user:
	kfree(cmd_buf);
	return ret;

bad_usage:
	dev_info(dev,
		 "invalid input, usage: echo the following options to change per-PF parameters\n");
	dev_info(dev, "\t debug_mask $N\n");
	dev_info(dev, "\t lan_no_xmit $N\n");

	ret = -EINVAL;
	goto command_write_done;
}

static const struct file_operations nsevf_debugfs_vf_params_fops = {
	.owner = THIS_MODULE,
	.open = simple_open,
	.read = nsevf_debugfs_vf_params_rfunc,
	.write = nsevf_debugfs_vf_params_wfunc,
	.llseek = default_llseek,
};

static ssize_t nsevf_debugfs_bar0_read_wfunc(struct file *filp,
					     const char __user *buf,
					     size_t count, loff_t *ppos)
{
	struct nsevf_adapter *adapter = filp->private_data;
	struct nsevf_hw *hw = &adapter->hw;
	struct device *dev = nsevf_adapter_to_dev(adapter);
	char *cmd_buf, *cmd_buf_tmp;
	ssize_t ret;
	char **argv;
	int argc;
	u32 bar0_addr, bar0_val;

	cmd_buf = memdup_user(buf, count + 1);
	if (IS_ERR(cmd_buf))
		return PTR_ERR(cmd_buf);
	cmd_buf[count] = '\0';

	cmd_buf_tmp = strchr(cmd_buf, '\n');
	if (cmd_buf_tmp) {
		*cmd_buf_tmp = '\0';
		count = (size_t)cmd_buf_tmp - (size_t)cmd_buf + 1;
	}

	argv = argv_split(GFP_KERNEL, cmd_buf, &argc);
	if (!argv) {
		ret = -ENOMEM;
		goto err_copy_from_user;
	}

	if (argc == 1) {
		if (kstrtou32(argv[0], 16, &bar0_addr))
			goto bad_usage;

		bar0_val = rd32(hw, bar0_addr);

		dev_info(dev, "BAR0 reg: %X = %X\n", bar0_addr, bar0_val);
	} else {
		goto bad_usage;
	}

	/* if we get here, nothing went wrong; return bytes copied */
	ret = (ssize_t)count;

command_write_done:
	argv_free(argv);
err_copy_from_user:
	kfree(cmd_buf);
	return ret;

bad_usage:
	dev_info(dev, "invalid input, usage: echo 'addr(HEX)' > bar0_read\n");
	ret = -EINVAL;
	goto command_write_done;
}

static const struct file_operations nsevf_debugfs_bar0_read_fops = {
	.owner = THIS_MODULE,
	.open = simple_open,
	.write = nsevf_debugfs_bar0_read_wfunc,
	.llseek = default_llseek,
};

static ssize_t nsevf_debugfs_bar0_read_all_wfunc(struct file *filp,
						 const char __user *buf,
						 size_t count, loff_t *ppos)
{
	struct nsevf_adapter *adapter = filp->private_data;
	struct nsevf_hw *hw = &adapter->hw;
	struct device *dev = nsevf_adapter_to_dev(adapter);
	char *cmd_buf, *cmd_buf_tmp;
	ssize_t ret;
	char **argv;
	int argc;

	cmd_buf = memdup_user(buf, count + 1);
	if (IS_ERR(cmd_buf))
		return PTR_ERR(cmd_buf);
	cmd_buf[count] = '\0';

	cmd_buf_tmp = strchr(cmd_buf, '\n');
	if (cmd_buf_tmp) {
		*cmd_buf_tmp = '\0';
		count = (size_t)cmd_buf_tmp - (size_t)cmd_buf + 1;
	}

	argv = argv_split(GFP_KERNEL, cmd_buf, &argc);
	if (!argv) {
		ret = -ENOMEM;
		goto err_copy_from_user;
	}

	if (argc != 1)
		goto bad_usage;

	/* hw->hw_addr */
	dev_info(dev, "hw->hw_addr(BAR0 vaddr): %lX\n",
		 (unsigned long)hw->hw_addr);

	/* basic regs */
	dev_info(dev, "ST(%X): %X\n", NSEVF_REG_ST, rd32(hw, NSEVF_REG_ST));

	dev_info(dev, "CTL(%X): %X\n", NSEVF_REG_CTL, rd32(hw, NSEVF_REG_CTL));

	/* aq-sq, aq-sq regs */
	dev_info(dev, "MBX_ATQBAH(%X): %X\n", MBX_ATQBAH(hw),
		 rd32(hw, MBX_ATQBAH(hw)));

	dev_info(dev, "MBX_ATQBAL(%X): %X\n", MBX_ATQBAL(hw),
		 rd32(hw, MBX_ATQBAL(hw)));

	dev_info(dev, "MBX_ATQLEN(%X): %X\n", MBX_ATQLEN(hw),
		 rd32(hw, MBX_ATQLEN(hw)));

	dev_info(dev, "MBX_ATQH(%X): %X\n", MBX_ATQH(hw),
		 rd32(hw, MBX_ATQH(hw)));

	dev_info(dev, "MBX_ATQT(%X): %X\n", MBX_ATQT(hw),
		 rd32(hw, MBX_ATQT(hw)));

	dev_info(dev, "MBX_ARQBAH(%X): %X\n", MBX_ARQBAH(hw),
		 rd32(hw, MBX_ARQBAH(hw)));

	dev_info(dev, "MBX_ARQBAL(%X): %X\n", MBX_ARQBAL(hw),
		 rd32(hw, MBX_ARQBAL(hw)));

	dev_info(dev, "MBX_ARQLEN(%X): %X\n", MBX_ARQLEN(hw),
		 rd32(hw, MBX_ARQLEN(hw)));

	dev_info(dev, "MBX_ARQH(%X): %X\n", MBX_ARQH(hw),
		 rd32(hw, MBX_ARQH(hw)));

	dev_info(dev, "MBX_ARQT(%X): %X\n", MBX_ARQT(hw),
		 rd32(hw, MBX_ARQT(hw)));

	/* aq-ctl/cxt */
	dev_info(dev, "MBX_CTL(%X): %X\n", MBX_CTL(hw), rd32(hw, MBX_CTL(hw)));

	dev_info(dev, "UTI_ATQBAH(%X): %X\n", NSEVF_REG_UTI_ATQBAH,
		 rd32(hw, NSEVF_REG_UTI_ATQBAH));

	dev_info(dev, "UTI_ATQBAL(%X): %X\n", NSEVF_REG_UTI_ATQBAL,
		 rd32(hw, NSEVF_REG_UTI_ATQBAL));

	dev_info(dev, "UTI_ATQLEN(%X): %X\n", NSEVF_REG_UTI_ATQLEN,
		 rd32(hw, NSEVF_REG_UTI_ATQLEN));

	dev_info(dev, "UTI_ATQH(%X): %X\n", NSEVF_REG_UTI_ATQH,
		 rd32(hw, NSEVF_REG_UTI_ATQH));

	dev_info(dev, "UTI_ATQT(%X): %X\n", NSEVF_REG_UTI_ATQT,
		 rd32(hw, NSEVF_REG_UTI_ATQT));

	dev_info(dev, "UTI_CTL(%X): %X\n", NSEVF_REG_UTI_CTL,
		 rd32(hw, NSEVF_REG_UTI_CTL));

	/* interrupt */
	dev_info(dev, "INT_DYN_CTLN(0)(%X): %X\n", INT_DYN_CTLN(hw, 0),
		 rd32(hw, INT_DYN_CTLN(hw, 0)));

	/* if we get here, nothing went wrong; return bytes copied */
	ret = (ssize_t)count;

command_write_done:
	argv_free(argv);
err_copy_from_user:
	kfree(cmd_buf);
	return ret;

bad_usage:
	dev_info(dev,
		 "invalid input, usage: echo 'any words' > bar0_read_all\n");
	ret = -EINVAL;
	goto command_write_done;
}

static const struct file_operations nsevf_debugfs_bar0_read_all_fops = {
	.owner = THIS_MODULE,
	.open = simple_open,
	.write = nsevf_debugfs_bar0_read_all_wfunc,
	.llseek = default_llseek,
};

static ssize_t nsevf_debugfs_bar0_write_wfunc(struct file *filp,
					      const char __user *buf,
					      size_t count, loff_t *ppos)
{
	struct nsevf_adapter *adapter = filp->private_data;
	struct nsevf_hw *hw = &adapter->hw;
	struct device *dev = nsevf_adapter_to_dev(adapter);
	char *cmd_buf, *cmd_buf_tmp;
	ssize_t ret;
	char **argv;
	int argc;
	u32 bar0_addr, bar0_val;

	cmd_buf = memdup_user(buf, count + 1);
	if (IS_ERR(cmd_buf))
		return PTR_ERR(cmd_buf);
	cmd_buf[count] = '\0';

	cmd_buf_tmp = strchr(cmd_buf, '\n');
	if (cmd_buf_tmp) {
		*cmd_buf_tmp = '\0';
		count = (size_t)cmd_buf_tmp - (size_t)cmd_buf + 1;
	}

	argv = argv_split(GFP_KERNEL, cmd_buf, &argc);
	if (!argv) {
		ret = -ENOMEM;
		goto err_copy_from_user;
	}

	if (argc == 2) {
		if (kstrtou32(argv[0], 16, &bar0_addr))
			goto bad_usage;

		if (kstrtou32(argv[1], 16, &bar0_val))
			goto bad_usage;

		dev_info(dev, "gonna write BAR0 reg: %X = %X\n", bar0_addr,
			 bar0_val);

		wr32(hw, bar0_addr, bar0_val);
	} else {
		goto bad_usage;
	}

	/* if we get here, nothing went wrong; return bytes copied */
	ret = (ssize_t)count;

command_write_done:
	argv_free(argv);
err_copy_from_user:
	kfree(cmd_buf);
	return ret;

bad_usage:
	dev_info(dev, "invalid input, usage: echo 'addr value' > bar0_write\n");
	ret = -EINVAL;
	goto command_write_done;
}

static const struct file_operations nsevf_debugfs_bar0_write_fops = {
	.owner = THIS_MODULE,
	.open = simple_open,
	.write = nsevf_debugfs_bar0_write_wfunc,
};

static ssize_t nsevf_debugfs_mq_cmd_wfunc(struct file *filp,
					  const char __user *buf, size_t count,
					  loff_t *ppos)
{
	struct nsevf_adapter *adapter = filp->private_data;
	struct device *dev = nsevf_adapter_to_dev(adapter);
	char *cmd_buf = NULL, *cmd_buf_tmp = NULL;
	ssize_t ret;
	char **argv = NULL;
	int argc;
	int func_ret;

	cmd_buf = memdup_user(buf, count + 1);
	if (IS_ERR(cmd_buf))
		return PTR_ERR(cmd_buf);
	cmd_buf[count] = '\0';

	cmd_buf_tmp = strchr(cmd_buf, '\n');
	if (cmd_buf_tmp) {
		*cmd_buf_tmp = '\0';
		count = (size_t)cmd_buf_tmp - (size_t)cmd_buf + 1;
	}

	argv = argv_split(GFP_KERNEL, cmd_buf, &argc);
	if (!argv) {
		ret = -ENOMEM;
		goto err_copy_from_user;
	}

	if (argc < 1)
		goto bad_usage;

	if (!strcmp(argv[0], "ver")) {
		func_ret = nsevf_send_api_ver(adapter);

		if (!func_ret) {
			dev_info(dev,
				 "vch-op ( ver ) - send_to_pf: get FW writeback, now check adminq-RQ receiving\n");
		} else {
			dev_info(dev,
				 "vch-op ( ver ) - send_to_pf: FAIL, status = %d\n",
				func_ret);
		}

		dev_info(dev,
			 "now, no matter req success or not, check mailbox-RQ\n");
	} else {
		goto bad_usage;
	}

	/* if we get here, nothing went wrong; return bytes copied */
	ret = (ssize_t)count;

command_write_done:
	if (argv)
		argv_free(argv);
err_copy_from_user:
	kfree(cmd_buf);

	return ret;

bad_usage:
	dev_info(dev, "unknown or invalid aq_cmd '%s'\n", argv[1]);
	dev_info(dev, "available aq_cmd\n");
	dev_info(dev, "    ver - send vch-req (VIRTCHNL_OP_VERSION)\n");

	ret = -EINVAL;

	goto command_write_done;
}

static const struct file_operations nsevf_debugfs_mq_cmd_fops = {
	.owner = THIS_MODULE,
	.open = simple_open,
	.write = nsevf_debugfs_mq_cmd_wfunc,
	.llseek = default_llseek,
};

void nsevf_aq_cmd_background_task(struct work_struct *work)
{
	struct nsevf_hw *hw =
		container_of(work, struct nsevf_hw, aq_cmd_background_task);
	struct nsevf_adapter *adapter = (struct nsevf_adapter *)hw->back;
	struct device *dev = nsevf_adapter_to_dev(adapter);
	unsigned int already_run_cnt = 0;
	int func_ret = 0;

	if (hw->aq_cmd_background_task_cancelling) {
		dev_info(dev, "[%s, %d] cancel mq_cmd_background_task\n",
			 __func__, __LINE__);
		goto out_done;
	}

	if (!hw->aq_cmd_background_task_cmd_cnt_count_down) {
		dev_info(dev, "[%s, %d] the whole %d loop execute DONE\n",
			 __func__, __LINE__,
			 hw->aq_cmd_background_task_cmd_cnt);
		goto out_done;
	}

	hw->aq_cmd_background_task_cmd_cnt_count_down--;

	if (hw->aq_cmd_background_task_cmd_period)
		msleep(hw->aq_cmd_background_task_cmd_period);

	dev_info(dev, "[%s, %d] execute on CPU: %d\n", __func__, __LINE__,
		 smp_processor_id());

	already_run_cnt = (hw->aq_cmd_background_task_cmd_cnt -
			   hw->aq_cmd_background_task_cmd_cnt_count_down);

	if (hw->aq_cmd_background_task_cmd_type == 1) {
		func_ret = nsevf_send_api_ver(adapter);

		if (func_ret) {
			dev_err(dev,
				"[%s, %d] FAIL: mq_cmd_background - vch-op ( ver ) - send_to_pf, ret = %d, at %d times\n",
				__func__, __LINE__, func_ret, already_run_cnt);

			goto out_done;
		}
	} else if (hw->aq_cmd_background_task_cmd_type == 2) {
		func_ret = nsevf_send_vf_config_msg(adapter);

		if (func_ret) {
			dev_err(dev,
				"[%s, %d] FAIL: mq_cmd_background - vch-op ( get_config ) - send_to_pf, ret = %d, at %d times\n",
				__func__, __LINE__, func_ret, already_run_cnt);

			goto out_done;
		}
	} else {
		dev_err(dev,
			"invalid setting for: aq_cmd_background_task_cmd_type = %d",
			hw->aq_cmd_background_task_cmd_type);

		goto out_done;
	}

	/* reschedule myself */
	schedule_work_on((adapter->probed_id % num_online_cpus()),
			 &hw->aq_cmd_background_task);

	return;

out_done:
	hw->aq_cmd_background_task_cancelling = 0;
	hw->aq_cmd_background_task_cmd_cnt_count_down = 0;
}

static ssize_t nsevf_debugfs_mq_cmd_background_rfunc(struct file *filp,
						     char __user *to,
						     size_t count, loff_t *ppos)
{
	struct nsevf_adapter *adapter = filp->private_data;
	struct nsevf_hw *hw = &adapter->hw;
	char buf[64];
	int len, ret;

	len = scnprintf(buf, sizeof(buf),
			"work_busy() = %d, cancelling=%d, cnt_down=%d\n",
			work_busy(&hw->aq_cmd_background_task),
			hw->aq_cmd_background_task_cancelling,
			hw->aq_cmd_background_task_cmd_cnt_count_down);

	ret = simple_read_from_buffer(to, count, ppos, buf, len);

	return ret;
}

static ssize_t nsevf_debugfs_mq_cmd_background_wfunc(struct file *filp,
						     const char __user *buf,
						     size_t count, loff_t *ppos)
{
	struct nsevf_adapter *adapter = filp->private_data;
	struct nsevf_hw *hw = &adapter->hw;
	struct device *dev = nsevf_adapter_to_dev(adapter);
	char *cmd_buf = NULL, *cmd_buf_tmp = NULL;
	ssize_t ret;
	char **argv = NULL;
	int argc;
	int start_work = 0;

	hw->aq_cmd_background_task_cancelling = 0;

	cmd_buf = memdup_user(buf, count + 1);
	if (IS_ERR(cmd_buf))
		return PTR_ERR(cmd_buf);
	cmd_buf[count] = '\0';

	cmd_buf_tmp = strchr(cmd_buf, '\n');
	if (cmd_buf_tmp) {
		*cmd_buf_tmp = '\0';
		count = (size_t)cmd_buf_tmp - (size_t)cmd_buf + 1;
	}

	argv = argv_split(GFP_KERNEL, cmd_buf, &argc);
	if (!argv) {
		ret = -ENOMEM;
		goto err_copy_from_user;
	}

	if (argc < 1)
		goto bad_usage;

	if (!strcmp(argv[0], "cancel")) {
		hw->aq_cmd_background_task_cancelling = 1;

		cancel_work_sync(&hw->aq_cmd_background_task);

		hw->aq_cmd_background_task_cmd_type = 0;

		goto ok_out;
	}

	if (hw->aq_cmd_background_task_cmd_cnt_count_down) {
		dev_info(dev,
			 "aq_cmd_background_task still running, count_down = %d\n",
			hw->aq_cmd_background_task_cmd_cnt_count_down);
		ret = -EINVAL;
		goto command_write_done;
	}

	if (argc >= 2) {
		if (kstrtouint(argv[1], 10,
			       &hw->aq_cmd_background_task_cmd_cnt)) {
			hw->aq_cmd_background_task_cmd_cnt = 100;
		}
	} else {
		hw->aq_cmd_background_task_cmd_cnt = 100;
	}

	if (argc >= 3) {
		if (kstrtouint(argv[2], 10,
			       &hw->aq_cmd_background_task_cmd_period)) {
			hw->aq_cmd_background_task_cmd_period = 100;
		}
	} else {
		hw->aq_cmd_background_task_cmd_period = 100;
	}

	dev_info(dev, "gonna loop for %d times\n",
		 hw->aq_cmd_background_task_cmd_cnt);
	dev_info(dev, "each iteration would msleep(%d)\n",
		 hw->aq_cmd_background_task_cmd_period);

	if (!strcmp(argv[0], "ver")) {
		hw->aq_cmd_background_task_cmd_type = 1;

		start_work = 1;
	} else if (!strcmp(argv[0], "get_config")) {
		hw->aq_cmd_background_task_cmd_type = 2;

		start_work = 1;
	} else {
		goto bad_usage;
	}

	if (start_work) {
		hw->aq_cmd_background_task_cmd_cnt_count_down =
			hw->aq_cmd_background_task_cmd_cnt;

		schedule_work_on((adapter->probed_id % num_online_cpus()),
				 &hw->aq_cmd_background_task);
	}

ok_out:
	/* if we get here, nothing went wrong; return bytes copied */
	ret = (ssize_t)count;

command_write_done:
	if (argv)
		argv_free(argv);
err_copy_from_user:
	kfree(cmd_buf);

	return ret;

bad_usage:
	dev_info(dev, "unknown or invalid aq_cmd_background '%s'\n", argv[1]);
	dev_info(dev, "available aq_cmd_background\n");
	dev_info(dev, "\t cancel\n");
	dev_info(dev,
		 "\t ver $(N times - optional, default 1000) $(X period - optional, default 100 ms)\n");
	dev_info(dev,
		 "\t get_config $(N times - optional, default 100) $(X period - optional, default 100 ms)\n");

	ret = -EINVAL;

	goto command_write_done;
}

static const struct file_operations nsevf_debugfs_mq_cmd_background_fops = {
	.owner = THIS_MODULE,
	.open = simple_open,
	.read = nsevf_debugfs_mq_cmd_background_rfunc,
	.write = nsevf_debugfs_mq_cmd_background_wfunc,
	.llseek = default_llseek,
};

static ssize_t nsevf_debugfs_mq_stats_rfunc(struct file *filp, char __user *to,
					    size_t count, loff_t *ppos)
{
	struct nsevf_adapter *adapter = filp->private_data;
	struct nsevf_hw *hw = &adapter->hw;
	char *buf = NULL;
	int desc = 0;
	int ret;

	buf = kzalloc(4096, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	desc += sprintf(buf + desc, "sq_total_wait_cnt: %ld\n",
			(unsigned long)hw->controlq_stats.sq_total_wait_cnt);

	desc += sprintf(buf + desc, "mq_cmd_shutdown_cnt: %ld\n",
			(unsigned long)hw->controlq_stats.mq_cmd_shutdown_cnt);

	desc += sprintf(buf + desc, "mq_cmd_shutdown_time: %ld\n",
			(unsigned long)hw->controlq_stats.mq_cmd_shutdown_time);

	desc += sprintf(buf + desc,
			"mq_sq_wait_for_fw_pause_disable_fail_cnt: %ld\n",
			(unsigned long)hw->controlq_stats
				.mq_sq_wait_for_fw_pause_disable_fail_cnt);
	desc += sprintf(buf + desc,
			"mq_sq_wait_for_fw_pause_disable_fail_time: %ld\n",
			(unsigned long)hw->controlq_stats
				.mq_sq_wait_for_fw_pause_disable_fail_time);

	desc += sprintf(buf + desc, "mq_sq_wait_for_sw_pause_fail_cnt: %ld\n",
			(unsigned long)hw->controlq_stats
				.mq_sq_wait_for_sw_pause_fail_cnt);
	desc += sprintf(buf + desc, "mq_sq_wait_for_sw_pause_fail_time: %ld\n",
			(unsigned long)hw->controlq_stats
				.mq_sq_wait_for_sw_pause_fail_time);

	desc += sprintf(buf + desc, "mq_sq_wait_for_sw_disable_fail_cnt: %ld\n",
			(unsigned long)hw->controlq_stats
				.mq_sq_wait_for_sw_disable_fail_cnt);
	desc += sprintf(buf + desc, "mq_sq_wait_for_sw_disable_fail_time: %ld\n",
		(unsigned long)
			hw->controlq_stats.mq_sq_wait_for_sw_disable_fail_time);

	desc += sprintf(buf + desc,
			"mq_rq_wait_for_fw_pause_disable_fail_cnt: %ld\n",
			(unsigned long)hw->controlq_stats
				.mq_rq_wait_for_fw_pause_disable_fail_cnt);
	desc += sprintf(buf + desc,
			"mq_rq_wait_for_fw_pause_disable_fail_time: %ld\n",
			(unsigned long)hw->controlq_stats
				.mq_rq_wait_for_fw_pause_disable_fail_time);

	desc += sprintf(buf + desc, "mq_rq_wait_for_sw_pause_fail_cnt: %ld\n",
			(unsigned long)hw->controlq_stats
				.mq_rq_wait_for_sw_pause_fail_cnt);
	desc += sprintf(buf + desc, "mq_rq_wait_for_sw_pause_fail_time: %ld\n",
			(unsigned long)hw->controlq_stats
				.mq_rq_wait_for_sw_pause_fail_time);

	desc += sprintf(buf + desc, "mq_rq_wait_for_sw_disable_fail_cnt: %ld\n",
			(unsigned long)hw->controlq_stats
				.mq_rq_wait_for_sw_disable_fail_cnt);
	desc += sprintf(buf + desc, "mq_rq_wait_for_sw_disable_fail_time: %ld\n",
		(unsigned long)
			hw->controlq_stats.mq_rq_wait_for_sw_disable_fail_time);

	ret = simple_read_from_buffer(to, count, ppos, buf, desc);

	kfree(buf);

	return ret;
}

static ssize_t nsevf_debugfs_mq_stats_wfunc(struct file *filp,
					    const char __user *buf,
					    size_t count, loff_t *ppos)
{
	struct nsevf_adapter *adapter = filp->private_data;
	struct device *dev = nsevf_adapter_to_dev(adapter);
	char *cmd_buf = NULL, *cmd_buf_tmp = NULL;
	ssize_t ret;
	char **argv = NULL;
	int argc;

	cmd_buf = memdup_user(buf, count + 1);
	if (IS_ERR(cmd_buf))
		return PTR_ERR(cmd_buf);
	cmd_buf[count] = '\0';

	cmd_buf_tmp = strchr(cmd_buf, '\n');
	if (cmd_buf_tmp) {
		*cmd_buf_tmp = '\0';
		count = (size_t)cmd_buf_tmp - (size_t)cmd_buf + 1;
	}

	argv = argv_split(GFP_KERNEL, cmd_buf, &argc);
	if (!argv) {
		ret = -ENOMEM;
		goto err_copy_from_user;
	}

	if (argc < 1)
		goto bad_usage;

	memset(&adapter->hw.controlq_stats, 0,
	       sizeof(adapter->hw.controlq_stats));

	/* if we get here, nothing went wrong; return bytes copied */
	ret = (ssize_t)count;

command_write_done:
	if (argv)
		argv_free(argv);
err_copy_from_user:
	kfree(cmd_buf);

	return ret;

bad_usage:
	dev_info(dev,
		 "invalid input, usage: echo 'any words' > controlq_stats to clear controlq_stats\n");
	ret = -EINVAL;

	goto command_write_done;
}

static const struct file_operations nsevf_debugfs_mq_stats_fops = {
	.owner = THIS_MODULE,
	.open = simple_open,
	.read = nsevf_debugfs_mq_stats_rfunc,
	.write = nsevf_debugfs_mq_stats_wfunc,
	.llseek = default_llseek,
};

static void nsevf_dump_rxq_txq_info(struct nsevf_ring *q, bool rxq_or_txq)
{
	struct device *dev = q->dev;

	dev_info(dev, "=== %s-%d info\n", rxq_or_txq ? "RXQ" : "TXQ",
		 q->queue_index);
	dev_info(dev, "desc = 0x%lX\n", (unsigned long)q->desc);
	dev_info(dev, "desc_dma = 0x%lX\n", (unsigned long)q->dma);
	dev_info(dev, "count = %d\n", q->count);
	dev_info(dev, "next_to_use = %d\n", q->next_to_use);
	dev_info(dev, "next_to_clean = %d\n", q->next_to_clean);
	dev_info(dev, "next_to_alloc = %d\n", q->next_to_alloc);
	dev_info(dev, "tail(vaddr) = %p\n", q->tail);
	dev_info(dev, "reg_idx = %d\n", q->reg_idx);
	if (q->q_vector) {
		dev_info(dev, "q_vector->v_idx = %d\n", q->q_vector->v_idx);
	} else {
		dev_info(dev,
			 "q_vector = NULL? how come this Q not bound to a q_vector?\n");
	}
	dev_info(dev, "q_index = %d\n", q->queue_index);
	dev_info(dev, "flags = %X\n", q->flags);
	dev_info(dev, "dcb_tc = %d\n", q->dcb_tc);

	if (rxq_or_txq) { //rxq-only info
		dev_info(dev, "rx_bi = %p\n", q->rx_bi);
		dev_info(dev, "rx_buf_len = %d\n", q->rx_buf_len);

		dev_info(dev, "rx_stats:\n");
		dev_info(dev, "\t non_eop_descs: %ld\n",
			 (unsigned long)q->rx_stats.non_eop_descs);
		dev_info(dev, "\t alloc_page_failed: %ld\n",
			 (unsigned long)q->rx_stats.alloc_page_failed);
		dev_info(dev, "\t alloc_buf_failed: %ld\n",
			 (unsigned long)q->rx_stats.alloc_buff_failed);
		dev_info(dev, "\t page_reuse_count: %ld\n",
			 (unsigned long)q->rx_stats.page_reuse_count);
		dev_info(dev, "\t realloc_count: %ld\n",
			 (unsigned long)q->rx_stats.realloc_count);
		dev_info(dev, "\t rsc_count: %ld\n",
			 (unsigned long)q->rx_stats.rsc_count);
		dev_info(dev, "\t rsc_flush: %ld\n",
			 (unsigned long)q->rx_stats.rsc_flush);
		dev_info(dev, "\t qsrc_cnt[SW=%d]: %ld\n", NSE_RXD_QSRC_SW,
			 (unsigned long)q->rx_stats.qsrc_cnt[NSE_RXD_QSRC_SW]);
		dev_info(dev, "\t qsrc_cnt[ACL=%d]: %ld\n", NSE_RXD_QSRC_ACL,
			 (unsigned long)q->rx_stats.qsrc_cnt[NSE_RXD_QSRC_ACL]);
		dev_info(dev, "\t qsrc_cnt[FD=%d]: %ld\n", NSE_RXD_QSRC_FD,
			 (unsigned long)q->rx_stats.qsrc_cnt[NSE_RXD_QSRC_FD]);
		dev_info(dev, "\t qsrc_cnt[RSS=%d]: %ld\n", NSE_RXD_QSRC_RSS,
			 (unsigned long)q->rx_stats.qsrc_cnt[NSE_RXD_QSRC_RSS]);
	} else { //txq-only info
		dev_info(dev, "tx_bi = %p\n", q->tx_bi);

		dev_info(dev, "tx_rs_ntu = %d\n", q->tx_rs_ntu);
		dev_info(dev, "tx_rs_ntc = %d\n", q->tx_rs_ntc);

		dev_info(dev, "tx_stats:\n");
		dev_info(dev, "\t restart_queue: %ld\n",
			 (unsigned long)q->tx_stats.restart_queue);
		dev_info(dev, "\t tx_busy: %ld\n",
			 (unsigned long)q->tx_stats.tx_busy);
		dev_info(dev, "\t tx_linearize: %ld\n",
			 (unsigned long)q->tx_stats.tx_linearize);

		dev_info(dev, "\t tx_use_ctx_desc: %ld\n",
			 (unsigned long)q->tx_stats.tx_use_ctx_desc);
		dev_info(dev, "\t tx_not_use_ctx_desc: %ld\n",
			 (unsigned long)q->tx_stats.tx_not_use_ctx_desc);
		dev_info(dev, "\t tx_tso: %ld\n",
			 (unsigned long)q->tx_stats.tx_tso);
		dev_info(dev, "\t tx_tso_tnl: %ld\n",
			 (unsigned long)q->tx_stats.tx_tso_tnl);
		dev_info(dev, "\t tx_tso_non_tnl: %ld\n",
			 (unsigned long)q->tx_stats.tx_tso_non_tnl);
		dev_info(dev, "\t tx_tcsum: %ld\n",
			 (unsigned long)q->tx_stats.tx_tcsum);
		dev_info(dev, "\t tx_tcsum_tnl: %ld\n",
			 (unsigned long)q->tx_stats.tx_tcsum_tnl);
		dev_info(dev, "\t tx_tcsum_non_tnl: %ld\n",
			 (unsigned long)q->tx_stats.tx_tcsum_non_tnl);
		dev_info(dev, "\t tx_tvlan: %ld\n",
			 (unsigned long)q->tx_stats.tx_tvlan);
		dev_info(dev, "\t tx_tsyn: %ld\n",
			 (unsigned long)q->tx_stats.tx_tsyn);
		dev_info(dev, "\t tx_offload: %ld\n",
			 (unsigned long)q->tx_stats.tx_offload);
		dev_info(dev, "\t tx_non_offload: %ld\n",
			 (unsigned long)q->tx_stats.tx_non_offload);

		dev_info(dev, "\t tx_rs: %ld\n",
			 (unsigned long)q->tx_stats.tx_rs);
		dev_info(dev, "\t tx_no_rs: %ld\n",
			 (unsigned long)q->tx_stats.tx_no_rs);

		dev_info(dev, "\t clean_tx_irq_legacy_cnt: %ld\n",
			 (unsigned long)q->tx_stats.clean_tx_irq_legacy_cnt);
		dev_info(dev, "\t clean_tx_irq_legacy_rs_cnt: %ld\n",
			 (unsigned long)q->tx_stats.clean_tx_irq_legacy_rs_cnt);
		dev_info(dev, "\t clean_tx_irq_legacy_rs_raw_cnt: %ld\n",
			 (unsigned long)
				 q->tx_stats.clean_tx_irq_legacy_rs_raw_cnt);
		dev_info(dev, "\t clean_tx_irq_legacy_rs_agg_cnt: %ld\n",
			 (unsigned long)
				 q->tx_stats.clean_tx_irq_legacy_rs_agg_cnt);
		dev_info(dev, "\t clean_tx_irq_zc_cnt: %ld\n",
			 (unsigned long)q->tx_stats.clean_tx_irq_zc_cnt);
		dev_info(dev, "\t clean_txcq_irq_cnt: %ld\n",
			 (unsigned long)q->tx_stats.clean_txcq_irq_cnt);
		dev_info(dev, "\t clean_txcq_irq_zc_cnt: %ld\n",
			 (unsigned long)q->tx_stats.clean_txcq_irq_zc_cnt);
	}
}

static void nsevf_dump_rxq_txq_desc(struct nsevf_ring *q, bool rxq_or_txq,
				    u16 max_desc_cnt)
{
	struct device *dev = q->dev;
	u16 ntc, ntu;
	struct nse_tx_desc *tx_desc;
	union nse_32b_rx_desc *rx_desc;

	if (!q->desc || !q->count) {
		dev_info(dev,
			 "VSI lanQ descriptor memory not allocated, may be this Q not used or enabled\n");
		return;
	}

	ntc = q->next_to_clean;
	ntu = q->next_to_use;

	dev_info(dev,
		 "next_to_clean = %d, next_to_use = %d, max_desc_cnt(to dump) = %d\n",
		ntc, ntu, max_desc_cnt);

	while (max_desc_cnt && ntc != ntu) {
		if (rxq_or_txq) {
			rx_desc = NSEVF_RX_DESC(q, ntc);
			nse_dump_rx_desc(dev, q->queue_index, ntc, rx_desc);
		} else {
			tx_desc = NSEVF_TX_DESC(q, ntc);
			nse_dump_tx_desc(dev, q->queue_index, ntc, tx_desc);
		}

		max_desc_cnt--;

		ntc++;
		if (ntc == q->count) /* wrap around */
			ntc = 0;
	}
}

static void nsevf_dump_rxq_txq_desc_raw(struct nsevf_ring *q, bool rxq_or_txq,
					u16 start_idx, u16 max_desc_cnt)
{
	struct device *dev = q->dev;
	struct nse_tx_desc *tx_desc;
	union nse_32b_rx_desc *rx_desc;

	if (!q->desc || !q->count) {
		dev_info(dev,
			 "VSI lanQ descriptor memory not allocated, may be this Q not used or enabled\n");
		return;
	}

	dev_info(dev, "next_to_clean = %d, next_to_use = %d\n",
		 q->next_to_clean, q->next_to_use);
	dev_info(dev, "we dump: start_idx = %d, number = %d\n", start_idx,
		 max_desc_cnt);

	while (max_desc_cnt) {
		if (rxq_or_txq) {
			rx_desc = NSEVF_RX_DESC(q, start_idx);
			nse_dump_rx_desc(dev, q->queue_index, start_idx,
					 rx_desc);
		} else {
			tx_desc = NSEVF_TX_DESC(q, start_idx);
			nse_dump_tx_desc(dev, q->queue_index, start_idx,
					 tx_desc);
		}

		max_desc_cnt--;

		start_idx++;
		if (start_idx == q->count) /* wrap around */
			start_idx = 0;
	}
}

static ssize_t nsevf_debugfs_dump_rxq_wfunc(struct file *filp,
					    const char __user *buf,
					    size_t count, loff_t *ppos)
{
	struct nsevf_adapter *adapter = filp->private_data;
	struct nsevf_ring *rxq = NULL;
	struct device *dev = nsevf_adapter_to_dev(adapter);
	char *cmd_buf, *cmd_buf_tmp;
	ssize_t ret;
	char **argv;
	int argc;
	u16 qid;
	u16 desc_idx;
	u16 max_desc_cnt;
	int dump_all = 0;
	int i;
	bool dumped = false;

	if (*ppos != 0)
		return 0;

	cmd_buf = memdup_user(buf, count + 1);
	if (IS_ERR(cmd_buf))
		return PTR_ERR(cmd_buf);
	cmd_buf[count] = '\0';

	cmd_buf_tmp = strchr(cmd_buf, '\n');
	if (cmd_buf_tmp) {
		*cmd_buf_tmp = '\0';
		count = (size_t)cmd_buf_tmp - (size_t)cmd_buf + 1;
	}

	argv = argv_split(GFP_KERNEL, cmd_buf, &argc);
	if (!argv) {
		ret = -ENOMEM;
		goto err_copy_from_user;
	}

	if (argc < 2)
		goto bad_usage;

	if (!strcmp(argv[0], "all")) {
		dump_all = 1;
	} else {
		if (kstrtou16(argv[0], 10, &qid))
			goto bad_usage;

		if (qid >= adapter->num_active_queues) {
			dev_info(dev, "input RXQ number out of range\n");

			ret = -EINVAL;
			goto command_write_done;
		}

		rxq = &adapter->rx_rings[qid];
	}

	if (strstr(argv[1], "info")) {
		if (dump_all) {
			nsevf_for_each_rxq(adapter, i) {
				rxq = &adapter->rx_rings[i];
				nsevf_dump_rxq_txq_info(rxq, true);
			}
		} else {
			nsevf_dump_rxq_txq_info(rxq, true);
		}

		dumped = true;
	}

	if (strstr(argv[1], "desc")) {
		if (argc >= 3) {
			if (kstrtou16(argv[2], 10, &max_desc_cnt))
				goto bad_usage;
		} else {
			max_desc_cnt = adapter->rx_rings[0].count;
		}

		if (max_desc_cnt > adapter->rx_rings[0].count) {
			dev_info(dev,
				 "input max X count out of range, should not larger than q->count(%d)\n",
				adapter->rx_rings[0].count);
			ret = -EINVAL;
			goto command_write_done;
		}

		if (dump_all) {
			nsevf_for_each_rxq(adapter, i) {
				rxq = &adapter->rx_rings[i];
				if (!rxq)
					continue;
				nsevf_dump_rxq_txq_desc(rxq, true,
							max_desc_cnt);
			}
		} else {
			nsevf_dump_rxq_txq_desc(rxq, true, max_desc_cnt);
		}

		dumped = true;
	}

	if (strstr(argv[1], "desc_raw")) {
		if (argc < 3)
			goto bad_usage;

		if (kstrtou16(argv[2], 10, &desc_idx))
			goto bad_usage;

		if (argc >= 4) {
			if (kstrtou16(argv[3], 10, &max_desc_cnt))
				goto bad_usage;
		} else {
			max_desc_cnt = 1;
		}

		if (desc_idx >= adapter->rx_rings[0].count ||
		    max_desc_cnt > adapter->rx_rings[0].count ||
		    ((desc_idx + max_desc_cnt) > adapter->rx_rings[0].count)) {
			dev_info(dev,
				 "input number X and Y out of range, should not exceed q->count(%d)\n",
				adapter->rx_rings[0].count);
			ret = -EINVAL;
			goto command_write_done;
		}

		if (dump_all) {
			nsevf_for_each_rxq(adapter, i) {
				rxq = &adapter->rx_rings[i];
				if (!rxq)
					continue;
				nsevf_dump_rxq_txq_desc_raw(rxq, true, desc_idx,
							    max_desc_cnt);
			}
		} else {
			nsevf_dump_rxq_txq_desc_raw(rxq, true, desc_idx,
						    max_desc_cnt);
		}

		dumped = true;
	}

	if (!dumped) /* nothing dumped ? */
		goto bad_usage;

	ret = (ssize_t)count;

command_write_done:
	if (argv)
		argv_free(argv);
err_copy_from_user:
	kfree(cmd_buf);

	return ret;

bad_usage:
	dev_info(dev, "support usage\n");
	dev_info(dev, "\t echo '#N|all info' - dump RXQ-#N info\n");
	dev_info(dev,
		 "\t echo '#N|all desc #X' - dump RXQ-#N descriptor, from next_to_clean to next_to_use, max X count\n");
	dev_info(dev,
		 "\t echo '#N|all desc_raw #X #Y' - dump RXQ-#N descriptors at specified index(X), number(Y)\n");

	ret = -EINVAL;

	goto command_write_done;
}

static const struct file_operations nsevf_debugfs_dump_rxq_fops = {
	.owner = THIS_MODULE,
	.open = simple_open,
	.write = nsevf_debugfs_dump_rxq_wfunc,
	.llseek = default_llseek,
};

static ssize_t nsevf_debugfs_dump_txq_wfunc(struct file *filp,
					    const char __user *buf,
					    size_t count, loff_t *ppos)
{
	struct nsevf_adapter *adapter = filp->private_data;
	struct nsevf_ring *txq = NULL;
	struct device *dev = nsevf_adapter_to_dev(adapter);
	char *cmd_buf, *cmd_buf_tmp;
	ssize_t ret;
	char **argv;
	int argc;
	u16 qid;
	u16 desc_idx;
	u16 max_desc_cnt;
	int dump_all = 0;
	int i;
	bool dumped = false;

	/* don't allow partial write. */
	if (*ppos != 0)
		return 0;

	cmd_buf = memdup_user(buf, count + 1);
	if (IS_ERR(cmd_buf))
		return PTR_ERR(cmd_buf);
	cmd_buf[count] = '\0';

	cmd_buf_tmp = strchr(cmd_buf, '\n');
	if (cmd_buf_tmp) {
		*cmd_buf_tmp = '\0';
		count = (size_t)cmd_buf_tmp - (size_t)cmd_buf + 1;
	}

	argv = argv_split(GFP_KERNEL, cmd_buf, &argc);
	if (!argv) {
		ret = -ENOMEM;
		goto err_copy_from_user;
	}

	if (argc < 2)
		goto bad_usage;

	if (!strcmp(argv[0], "all")) {
		dump_all = 1;
	} else {
		if (kstrtou16(argv[0], 10, &qid))
			goto bad_usage;

		if (qid >= adapter->num_active_queues) {
			dev_info(dev, "input TXQ number out of range\n");

			ret = -EINVAL;
			goto command_write_done;
		}

		txq = &adapter->tx_rings[qid];
	}

	if (strstr(argv[1], "info")) {
		if (dump_all) {
			nsevf_for_each_txq(adapter, i) {
				txq = &adapter->tx_rings[i];
				nsevf_dump_rxq_txq_info(txq, false);
			}
		} else {
			nsevf_dump_rxq_txq_info(txq, false);
		}

		dumped = true;
	}

	if (strstr(argv[1], "desc")) {
		if (argc >= 3) {
			if (kstrtou16(argv[2], 10, &max_desc_cnt))
				goto bad_usage;
		} else {
			max_desc_cnt = adapter->tx_rings[0].count;
		}

		if (max_desc_cnt > adapter->tx_rings[0].count) {
			dev_info(dev,
				 "input max X count out of range, should not larger than q->count(%d)\n",
				adapter->tx_rings[0].count);
			ret = -EINVAL;
			goto command_write_done;
		}

		if (dump_all) {
			nsevf_for_each_txq(adapter, i) {
				txq = &adapter->tx_rings[i];

				nsevf_dump_rxq_txq_desc(txq, false,
							max_desc_cnt);
			}
		} else {
			nsevf_dump_rxq_txq_desc(txq, false, max_desc_cnt);
		}

		dumped = true;
	}

	if (strstr(argv[1], "desc_raw")) {
		if (argc < 3)
			goto bad_usage;

		if (kstrtou16(argv[2], 10, &desc_idx))
			goto bad_usage;

		if (argc >= 4) {
			if (kstrtou16(argv[3], 10, &max_desc_cnt))
				goto bad_usage;
		} else {
			max_desc_cnt = 1;
		}

		if (desc_idx >= adapter->tx_rings[0].count ||
		    max_desc_cnt > adapter->tx_rings[0].count ||
		    ((desc_idx + max_desc_cnt) > adapter->tx_rings[0].count)) {
			dev_info(dev,
				 "input number X and Y out of range, should not exceed q->count(%d)\n",
				adapter->tx_rings[0].count);
			ret = -EINVAL;
			goto command_write_done;
		}

		if (dump_all) {
			nsevf_for_each_txq(adapter, i) {
				txq = &adapter->rx_rings[i];

				nsevf_dump_rxq_txq_desc_raw(txq, false, desc_idx, max_desc_cnt);
			}
		} else {
			nsevf_dump_rxq_txq_desc_raw(txq, false, desc_idx,
						    max_desc_cnt);
		}

		dumped = true;
	}

	if (!dumped) /* nothing dumped ? */
		goto bad_usage;

	/* if we get here, nothing went wrong; return bytes copied */
	ret = (ssize_t)count;

command_write_done:
	if (argv)
		argv_free(argv);
err_copy_from_user:
	kfree(cmd_buf);

	return ret;

bad_usage:
	dev_info(dev, "support usage\n");
	dev_info(dev, "\t echo '#N|all info' - dump TXQ-#N info\n");
	dev_info(dev,
		 "\t echo '#N|all desc #X' - dump TXQ-#N descriptor, from next_to_clean to next_to_use, max X count\n");
	dev_info(dev,
		 "\t echo '#N|all desc_raw #X #Y' - dump TXQ-#N descriptors at specified index(X), number(Y)\n");

	ret = -EINVAL;

	goto command_write_done;
}

static const struct file_operations nsevf_debugfs_dump_txq_fops = {
	.owner = THIS_MODULE,
	.open = simple_open,
	.write = nsevf_debugfs_dump_txq_wfunc,
	.llseek = default_llseek,
};

static void nsevf_dump_txcq_info(struct nsevf_txcq_ring *q)
{
	struct device *dev = q->dev;

	dev_info(dev, "=== LAN-TX-CQ-%d info\n", q->queue_index);
	dev_info(dev, "q_index = %d\n", q->queue_index);
	dev_info(dev, "cq_abs_id = %d\n", q->cq_abs_id);
	dev_info(dev, "desc = 0x%lX\n", (unsigned long)q->desc);
	dev_info(dev, "desc_dma = 0x%lX\n", (unsigned long)q->dma);
	dev_info(dev, "count = %d\n", q->count);
	dev_info(dev, "next_to_clean = %d\n", q->next_to_clean);
	dev_info(dev, "generation = %d\n", q->generation);
	if (q->q_vector) {
		dev_info(dev, "q_vector->v_idx = %d\n", q->q_vector->v_idx);
	} else {
		dev_info(dev,
			 "q_vector = NULL? how come this Q not bound to a q_vector?\n");
	}

	dev_info(dev, "stats:\n");
	dev_info(dev, "\t pkts=%lld\n", q->stats.pkts);
	dev_info(dev, "\t bytes=%lld\n", q->stats.bytes);
	dev_info(dev, "\t cqe_cnt=%lld\n", q->stats.cqe_cnt);
	dev_info(dev, "\t gen_flip_cnt=%lld\n", q->stats.gen_flip_cnt);
	dev_info(dev, "\t txqe_cnt=%lld\n", q->stats.txqe_cnt);
}

static void nsevf_dump_txcq_desc(struct nsevf_txcq_ring *q, u16 max_desc_cnt)
{
	struct device *dev = q->dev;
	u32 ntc;
	struct nse_lan_txcq_desc *cq_desc = NULL;

	if (!q->desc || !q->count) {
		dev_info(dev,
			 "VSI lanQ descriptor memory not allocated, may be this Q not used or enabled\n");
		return;
	}

	ntc = q->next_to_clean;

	dev_info(dev, "next_to_clean = %d, max_desc_cnt(to dump) = %d\n", ntc,
		 max_desc_cnt);

	while (max_desc_cnt) {
		cq_desc = NSEVF_TXCQ_DESC(q, ntc);
		nse_dump_lan_txcq_desc(dev, q->queue_index, ntc, cq_desc);

		max_desc_cnt--;

		ntc++;
		if (ntc == q->count) /* wrap around */
			ntc = 0;
	}
}

static void nsevf_dump_txcq_desc_raw(struct nsevf_txcq_ring *q, u32 start_idx,
				     u32 max_desc_cnt)
{
	struct device *dev = q->dev;
	struct nse_lan_txcq_desc *cq_desc = NULL;

	if (!q->desc || !q->count) {
		dev_info(dev,
			 "VSI lanQ descriptor memory not allocated, may be this Q not used or enabled\n");
		return;
	}

	dev_info(dev, "next_to_clean = %d\n", q->next_to_clean);
	dev_info(dev, "we dump: start_idx = %d, number = %d\n", start_idx,
		 max_desc_cnt);

	while (max_desc_cnt) {
		cq_desc = NSEVF_TXCQ_DESC(q, start_idx);
		nse_dump_lan_txcq_desc(dev, q->queue_index, start_idx, cq_desc);

		max_desc_cnt--;

		start_idx++;
		if (start_idx == q->count) /* wrap around */
			start_idx = 0;
	}
}

static ssize_t nsevf_debugfs_dump_txcq_wfunc(struct file *filp,
					     const char __user *buf,
					     size_t count, loff_t *ppos)
{
	struct nsevf_adapter *adapter = filp->private_data;
	struct nsevf_txcq_ring *cq = NULL;
	struct device *dev = nsevf_adapter_to_dev(adapter);
	char *cmd_buf, *cmd_buf_tmp;
	ssize_t ret;
	char **argv;
	int argc;
	u16 qid;
	u16 desc_idx;
	u16 max_desc_cnt;
	int dump_all = 0;
	int i;
	bool dumped = false;

	/* don't allow partial write. */
	if (*ppos != 0)
		return 0;

	if (!adapter->sw_conf.lan_tx_use_cq) {
		dev_info(dev, "this VSI does not support LAN-TX-CQ\n");
		return (ssize_t)count;
	}

	cmd_buf = memdup_user(buf, count + 1);
	if (IS_ERR(cmd_buf))
		return PTR_ERR(cmd_buf);
	cmd_buf[count] = '\0';

	cmd_buf_tmp = strchr(cmd_buf, '\n');
	if (cmd_buf_tmp) {
		*cmd_buf_tmp = '\0';
		count = (size_t)cmd_buf_tmp - (size_t)cmd_buf + 1;
	}

	argv = argv_split(GFP_KERNEL, cmd_buf, &argc);
	if (!argv) {
		ret = -ENOMEM;
		goto err_copy_from_user;
	}

	if (argc < 2)
		goto bad_usage;

	if (!strcmp(argv[0], "all")) {
		dump_all = 1;
	} else {
		if (kstrtou16(argv[0], 10, &qid))
			goto bad_usage;

		if (qid >= adapter->vf_res->lan_txcq_num) {
			dev_info(dev, "input TX-CQ number out of range\n");

			ret = -EINVAL;
			goto command_write_done;
		}

		cq = &adapter->txcq_rings[qid];
	}

	if (strstr(argv[1], "info")) {
		if (dump_all) {
			nsevf_for_each_txcq(adapter, i) {
				cq = &adapter->txcq_rings[i];
				nsevf_dump_txcq_info(cq);
			}
		} else {
			nsevf_dump_txcq_info(cq);
		}

		dumped = true;
	}

	if (strstr(argv[1], "desc")) {
		if (argc >= 3) {
			if (kstrtou16(argv[2], 10, &max_desc_cnt))
				goto bad_usage;
		} else {
			max_desc_cnt = adapter->txcq_desc_count;
		}

		if (max_desc_cnt > adapter->txcq_desc_count) {
			dev_info(dev,
				 "input max X count out of range, should not be larger than q->count(%d)\n",
				adapter->txcq_desc_count);
			ret = -EINVAL;
			goto command_write_done;
		}

		if (dump_all) {
			nsevf_for_each_txcq(adapter, i) {
				cq = &adapter->txcq_rings[i];

				nsevf_dump_txcq_desc(cq, max_desc_cnt);
			}
		} else {
			nsevf_dump_txcq_desc(cq, max_desc_cnt);
		}

		dumped = true;
	}

	if (strstr(argv[1], "desc_raw")) {
		if (argc < 3)
			goto bad_usage;

		if (kstrtou16(argv[2], 10, &desc_idx))
			goto bad_usage;

		if (argc >= 4) {
			if (kstrtou16(argv[3], 10, &max_desc_cnt))
				goto bad_usage;
		} else {
			max_desc_cnt = 1;
		}

		if (desc_idx >= adapter->txcq_desc_count ||
		    max_desc_cnt > adapter->txcq_desc_count ||
		    ((desc_idx + max_desc_cnt) > adapter->txcq_desc_count)) {
			dev_info(dev,
				 "input number X and Y out of range, should not be larger than q->count(%d)\n",
				adapter->txcq_desc_count);
			ret = -EINVAL;
			goto command_write_done;
		}

		if (dump_all) {
			nsevf_for_each_txcq(adapter, i) {
				cq = &adapter->txcq_rings[i];

				nsevf_dump_txcq_desc_raw(cq, desc_idx,
							 max_desc_cnt);
			}
		} else {
			nsevf_dump_txcq_desc_raw(cq, desc_idx, max_desc_cnt);
		}

		dumped = true;
	}

	if (!dumped) /* nothing dumped ? */
		goto bad_usage;

	/* if we get here, nothing went wrong; return bytes copied */
	ret = (ssize_t)count;

command_write_done:
	if (argv)
		argv_free(argv);
err_copy_from_user:
	kfree(cmd_buf);

	return ret;

bad_usage:
	dev_info(dev, "support usage\n");
	dev_info(dev, "\t echo '#N|all info' - dump TXQ-#N info\n");
	dev_info(dev,
		 "\t echo '#N|all desc #X' - dump TXQ-#N descriptor, from next_to_clean to next_to_use, max X count\n");
	dev_info(dev,
		 "\t echo '#N|all desc_raw #X #Y' - dump TXQ-#N descriptors at specified index(X), number(Y)\n");

	ret = -EINVAL;

	goto command_write_done;
}

static const struct file_operations nsevf_debugfs_dump_txcq_fops = {
	.owner = THIS_MODULE,
	.open = simple_open,
	.write = nsevf_debugfs_dump_txcq_wfunc,
	.llseek = default_llseek,
};

static void nsevf_dump_qvec(struct nsevf_q_vector *qvec)
{
	struct nsevf_adapter *adapter = qvec->adapter;
	struct device *dev = nsevf_adapter_to_dev(adapter);
	struct nsevf_ring *ring = NULL;
	struct nsevf_hw *hw = &adapter->hw;
	struct timespec64 ts_spec;

	dev_info(dev, "====== qvec info (v_idx=%d, reg_idx=%d)\n", qvec->v_idx,
		 qvec->reg_idx);

	dev_info(dev, "name: %s\n", qvec->name);
	dev_info(dev, "total_events: %d\n", qvec->total_events);
	dev_info(dev, "v_idx: %d\n", qvec->v_idx);
	dev_info(dev, "reg_idx: %d\n", qvec->reg_idx);
	dev_info(dev, "num_ringpairs: %d\n", qvec->num_ringpairs);
	dev_info(dev, "ring_mask: %X\n", qvec->ring_mask);
	dev_info(dev, "wb_on_itr: %d\n", qvec->wb_on_itr);
	dev_info(dev, "intrl: %d\n", qvec->intrl);
	dev_info(dev, "itr_settings: 0x%X\n", qvec->itr_settings);
	dev_info(dev, "\t itr_setting: 0x%X\n", qvec->itr_setting);
	dev_info(dev, "\t itr_mode: 0x%X\n", qvec->itr_mode);
	dev_info(dev, "best_local_cpu_id: %d\n", qvec->best_local_cpu_id);

	dev_info(dev, "rx_rings:\n");
	ring = qvec->rx.ring;
	while (ring) {
		dev_info(dev, "\t q_index: %d\n", ring->queue_index);
		ring = ring->next;
	}

	dev_info(dev, "tx_rings:\n");
	ring = qvec->tx.ring;
	while (ring) {
		dev_info(dev, "\t q_index: %d\n", ring->queue_index);
		ring = ring->next;
	}

	if (adapter->sw_conf.lan_tx_use_cq && adapter->txcq_rings) {
		dev_info(dev, "txcq_ring:\n");
		if (!qvec->txcq)
			dev_info(dev, "\t HOW COME qvec->txcq == NULL?\n");
		else
			dev_info(dev, "\t q_index: %d, abs_id: %d\n",
				 qvec->txcq->queue_index,
				 qvec->txcq->cq_abs_id);
	}
	dev_info(dev, "dbg_stats:\n");
	dev_info(dev, "\t hardirq_total_cnt = %ld\n",
		 qvec->dbg_stats.hardirq_total_cnt);
	dev_info(dev, "\t napi_poll_total_cnt = %ld\n",
		 qvec->dbg_stats.napi_poll_total_cnt);

	ts_spec = ns_to_timespec64(qvec->dbg_stats.napi_poll_last_ns);
	dev_info(dev, "\t napi_poll_last_ns=%ld (sec=%ld, nsec=%ld)\n",
		 (unsigned long)qvec->dbg_stats.napi_poll_last_ns,
		 (unsigned long)ts_spec.tv_sec, (unsigned long)ts_spec.tv_nsec);

	dev_info(dev, "\t napi_poll_txq_clean_done_cnt = %ld\n",
		 qvec->dbg_stats.napi_poll_txq_clean_done_cnt);
	dev_info(dev, "\t napi_poll_txq_clean_not_done_cnt = %ld\n",
		 qvec->dbg_stats.napi_poll_txq_clean_not_done_cnt);
	dev_info(dev, "\t napi_poll_txcq_clean_done_cnt = %ld\n",
		 qvec->dbg_stats.napi_poll_txcq_clean_done_cnt);
	dev_info(dev, "\t napi_poll_txcq_clean_not_done_cnt = %ld\n",
		 qvec->dbg_stats.napi_poll_txcq_clean_not_done_cnt);
	dev_info(dev, "\t napi_poll_rxq_clean_done_cnt = %ld\n",
		 qvec->dbg_stats.napi_poll_rxq_clean_done_cnt);
	dev_info(dev, "\t napi_poll_rxq_clean_not_done_cnt = %ld\n",
		 qvec->dbg_stats.napi_poll_rxq_clean_not_done_cnt);

	dev_info(dev, "\t napi_poll_clean_done_cnt = %ld\n",
		 qvec->dbg_stats.napi_poll_clean_done_cnt);
	dev_info(dev, "\t napi_poll_clean_not_done_cnt = %ld\n",
		 qvec->dbg_stats.napi_poll_clean_not_done_cnt);

	dev_info(dev, "\t napi_poll_clean_done_unmask_irq_cnt = %ld\n",
		 qvec->dbg_stats.napi_poll_clean_done_unmask_irq_cnt);
	dev_info(dev, "\t napi_poll_clean_done_keep_wb_on_itr_cnt = %ld\n",
		 qvec->dbg_stats.napi_poll_clean_done_keep_wb_on_itr_cnt);

	dev_info(dev, "\t napi_poll_budeget_less_0_cnt = %ld\n",
		 qvec->dbg_stats.napi_poll_budeget_less_0_cnt);
	dev_info(dev, "\t napi_poll_budeget_less_0_last_poll_cnt = %ld\n",
		 (unsigned long)qvec->dbg_stats
			 .napi_poll_budeget_less_0_last_poll_cnt);
	ts_spec = ns_to_timespec64(qvec->dbg_stats.napi_poll_budeget_less_0_last_ns);
	dev_info(dev,
		 "\t napi_poll_budeget_less_0_last_ns=%ld (sec=%ld, nsec=%ld)\n",
		(unsigned long)qvec->dbg_stats.napi_poll_budeget_less_0_last_ns,
		(unsigned long)ts_spec.tv_sec, (unsigned long)ts_spec.tv_nsec);

	dev_info(dev, "\t napi_poll_cpu_change_cnt = %ld\n",
		 qvec->dbg_stats.napi_poll_cpu_change_cnt);
	dev_info(dev, "\t napi_poll_cpu_change_last_poll_cnt = %ld\n",
		 qvec->dbg_stats.napi_poll_cpu_change_last_poll_cnt);
	ts_spec =
		ns_to_timespec64(qvec->dbg_stats.napi_poll_cpu_change_last_ns);
	dev_info(dev,
		 "\t napi_poll_cpu_change_last_ns=%ld (sec=%ld, nsec=%ld)\n",
		 (unsigned long)qvec->dbg_stats.napi_poll_cpu_change_last_ns,
		 (unsigned long)ts_spec.tv_sec, (unsigned long)ts_spec.tv_nsec);

	dev_info(dev, "\t napi_poll_last_ret_event=%ld\n",
		 qvec->dbg_stats.napi_poll_last_ret_event);

	dev_info(dev, "register: INT_DYN_CTLN(%d): %X\n", qvec->reg_idx,
		 rd32(hw, INT_DYN_CTLN(hw, qvec->reg_idx)));
}

static ssize_t nsevf_debugfs_dump_qvec_wfunc(struct file *filp,
					     const char __user *buf,
					     size_t count, loff_t *ppos)
{
	struct nsevf_adapter *adapter = filp->private_data;
	struct device *dev = nsevf_adapter_to_dev(adapter);
	char *cmd_buf, *cmd_buf_tmp;
	ssize_t ret;
	char **argv;
	int argc;
	u16 qvec_id;
	struct nsevf_q_vector *qvec = NULL;
	int num_q_vectors;
	int i;
	int dump_all = 0;

	/* don't allow partial write. */
	if (*ppos != 0)
		return 0;

	cmd_buf = memdup_user(buf, count + 1);
	if (IS_ERR(cmd_buf))
		return PTR_ERR(cmd_buf);
	cmd_buf[count] = '\0';

	cmd_buf_tmp = strchr(cmd_buf, '\n');
	if (cmd_buf_tmp) {
		*cmd_buf_tmp = '\0';
		count = (size_t)cmd_buf_tmp - (size_t)cmd_buf + 1;
	}

	argv = argv_split(GFP_KERNEL, cmd_buf, &argc);
	if (!argv) {
		ret = -ENOMEM;
		goto err_copy_from_user;
	}

	if (argc < 1)
		goto bad_usage;

	num_q_vectors = adapter->num_msix_vectors - NONQ_VECS;

	if (!strcmp(argv[0], "all")) {
		dump_all = 1;
	} else {
		if (kstrtou16(argv[0], 10, &qvec_id))
			goto bad_usage;

		if (qvec_id >= num_q_vectors) {
			dev_info(dev, "input qvector number out of range\n");

			ret = -EINVAL;
			goto command_write_done;
		}

		qvec = &adapter->q_vectors[qvec_id];
	}

	if (dump_all) {
		nsevf_for_each_q_vector(adapter, i) {
			qvec = &adapter->q_vectors[i];
			nsevf_dump_qvec(qvec);
		}
	} else {
		nsevf_dump_qvec(qvec);
	}

	/* if we get here, nothing went wrong; return bytes copied */
	ret = (ssize_t)count;

command_write_done:
	if (argv)
		argv_free(argv);
err_copy_from_user:
	kfree(cmd_buf);

	return ret;

bad_usage:
	dev_info(dev, "support usage\n");
	dev_info(dev, "    echo '#N' - dump qvec-#N info\n");

	ret = -EINVAL;

	goto command_write_done;
}

static const struct file_operations nsevf_debugfs_dump_qvec_fops = {
	.owner = THIS_MODULE,
	.open = simple_open,
	.write = nsevf_debugfs_dump_qvec_wfunc,
	.llseek = default_llseek,
};

static ssize_t nsevf_debugfs_fdir_dump_info_wfunc(struct file *filp,
						  const char __user *buf,
						  size_t count, loff_t *ppos)
{
	struct nsevf_adapter *adapter = filp->private_data;
	struct device *dev = nsevf_adapter_to_dev(adapter);
	char *cmd_buf, *cmd_buf_tmp;
	ssize_t ret;
	char **argv;
	int argc;

	cmd_buf = memdup_user(buf, count + 1);
	if (IS_ERR(cmd_buf))
		return PTR_ERR(cmd_buf);
	cmd_buf[count] = '\0';

	cmd_buf_tmp = strchr(cmd_buf, '\n');
	if (cmd_buf_tmp) {
		*cmd_buf_tmp = '\0';
		count = (size_t)cmd_buf_tmp - (size_t)cmd_buf + 1;
	}

	argv = argv_split(GFP_KERNEL, cmd_buf, &argc);
	if (!argv) {
		ret = -ENOMEM;
		goto err_copy_from_user;
	}

	if (argc != 1)
		goto bad_usage;

	nsevf_fdir_dump_cb(adapter);

	/* if we get here, nothing went wrong; return bytes copied */
	ret = (ssize_t)count;

command_write_done:
	argv_free(argv);
err_copy_from_user:
	kfree(cmd_buf);
	return ret;

bad_usage:
	dev_info(dev, "invalid input, usage: echo 'any words'\n");
	ret = -EINVAL;
	goto command_write_done;
}

static const struct file_operations nsevf_debugfs_fdir_dump_info_fops = {
	.owner = THIS_MODULE,
	.open = simple_open,
	.write = nsevf_debugfs_fdir_dump_info_wfunc,
	.llseek = default_llseek,
};

static ssize_t nsevf_debugfs_dump_filters_wfunc(struct file *filp,
						const char __user *buf,
						size_t count, loff_t *ppos)
{
	struct nsevf_adapter *adapter = filp->private_data;
	struct device *dev = nsevf_adapter_to_dev(adapter);
	char *cmd_buf, *cmd_buf_tmp;
	ssize_t ret;
	char **argv;
	int argc;
	unsigned int dump_op;

	cmd_buf = memdup_user(buf, count + 1);
	if (IS_ERR(cmd_buf))
		return PTR_ERR(cmd_buf);
	cmd_buf[count] = '\0';

	cmd_buf_tmp = strchr(cmd_buf, '\n');
	if (cmd_buf_tmp) {
		*cmd_buf_tmp = '\0';
		count = (size_t)cmd_buf_tmp - (size_t)cmd_buf + 1;
	}

	argv = argv_split(GFP_KERNEL, cmd_buf, &argc);
	if (!argv) {
		ret = -ENOMEM;
		goto err_copy_from_user;
	}

	if (argc != 1)
		goto bad_usage;

	if (kstrtouint(argv[0], 10, &dump_op))
		goto bad_usage;

	if (!dump_op)
		nsevf_dump_mac_filters(adapter);
	else
		nsevf_dump_vlan_filters(adapter);

	/* if we get here, nothing went wrong; return bytes copied */
	ret = (ssize_t)count;

command_write_done:
	argv_free(argv);
err_copy_from_user:
	kfree(cmd_buf);
	return ret;

bad_usage:
	dev_info(dev,
		 "invalid input, usage: echo 'N' (0 for mac-filters, 1 for vlan-filters\n");
	ret = -EINVAL;
	goto command_write_done;
}

static const struct file_operations nsevf_debugfs_dump_filters_fops = {
	.owner = THIS_MODULE,
	.open = simple_open,
	.write = nsevf_debugfs_dump_filters_wfunc,
	.llseek = default_llseek,
};

static ssize_t nsevf_debugfs_vfr_wfunc(struct file *filp,
				       const char __user *buf, size_t count,
				       loff_t *ppos)
{
	struct nsevf_adapter *adapter = filp->private_data;
	struct device *dev = nsevf_adapter_to_dev(adapter);
	char *cmd_buf, *cmd_buf_tmp;
	ssize_t ret;
	char **argv;
	int argc;

	/* don't allow partial writes and writes when reset is in progress*/
	if (*ppos != 0 || nsevf_is_reset_in_progress(adapter))
		return 0;

	cmd_buf = memdup_user(buf, count + 1);
	if (IS_ERR(cmd_buf))
		return PTR_ERR(cmd_buf);
	cmd_buf[count] = '\0';

	cmd_buf_tmp = strchr(cmd_buf, '\n');
	if (cmd_buf_tmp) {
		*cmd_buf_tmp = '\0';
		count = (size_t)cmd_buf_tmp - (size_t)cmd_buf + 1;
	}

	argv = argv_split(GFP_KERNEL, cmd_buf, &argc);
	if (!argv) {
		ret = -ENOMEM;
		goto err_copy_from_user;
	}

	if (argc < 1)
		goto bad_usage;

	nsevf_schedule_reset(adapter, NSEVF_FLAG_RESET_NEEDED);

	dev_info(dev,
		 "OK: request_VFR, wait PF driver and FW's cleanup, poll on CTL->frtrig (status)\n");

	/* if we get here, nothing went wrong; return bytes copied */
	ret = (ssize_t)count;

command_write_done:
	if (argv)
		argv_free(argv);
err_copy_from_user:
	kfree(cmd_buf);

	return ret;

bad_usage:
	dev_info(dev, "support usage\n");
	dev_info(dev, "    echo anything > this file\n");

	ret = -EINVAL;

	goto command_write_done;
}

static const struct file_operations nsevf_debugfs_vfr_fops = {
	.owner = THIS_MODULE,
	.open = simple_open,
	.write = nsevf_debugfs_vfr_wfunc,
	.llseek = default_llseek,
};

void nsevf_debugfs_vf_init(struct nsevf_adapter *adapter)
{
	const char *name = pci_name(adapter->pdev);

	if (!nsevf_debugfs_root)
		goto fail;

	adapter->vf_dbgfs_dir = debugfs_create_dir(name, nsevf_debugfs_root);
	if (IS_ERR(adapter->vf_dbgfs_dir))
		goto fail;

	(void)debugfs_create_file("info", 0600, adapter->vf_dbgfs_dir, adapter,
				  &nsevf_debugfs_vf_info_fops);

	(void)debugfs_create_file("params", 0600, adapter->vf_dbgfs_dir,
				  adapter, &nsevf_debugfs_vf_params_fops);

	(void)debugfs_create_file("bar0_read", 0600, adapter->vf_dbgfs_dir,
				  adapter, &nsevf_debugfs_bar0_read_fops);
	(void)debugfs_create_file("bar0_read_all", 0600, adapter->vf_dbgfs_dir,
				  adapter, &nsevf_debugfs_bar0_read_all_fops);
	(void)debugfs_create_file("bar0_write", 0600, adapter->vf_dbgfs_dir,
				  adapter, &nsevf_debugfs_bar0_write_fops);

	(void)debugfs_create_file("mq_cmd", 0600, adapter->vf_dbgfs_dir,
				  adapter, &nsevf_debugfs_mq_cmd_fops);
	(void)debugfs_create_file("mq_cmd_background", 0600,
				  adapter->vf_dbgfs_dir, adapter,
				  &nsevf_debugfs_mq_cmd_background_fops);

	(void)debugfs_create_file("mq_stats", 0600, adapter->vf_dbgfs_dir,
				  adapter, &nsevf_debugfs_mq_stats_fops);

	(void)debugfs_create_file("dump_rxq", 0600, adapter->vf_dbgfs_dir,
				  adapter, &nsevf_debugfs_dump_rxq_fops);
	(void)debugfs_create_file("dump_txq", 0600, adapter->vf_dbgfs_dir,
				  adapter, &nsevf_debugfs_dump_txq_fops);
	(void)debugfs_create_file("dump_txcq", 0600, adapter->vf_dbgfs_dir,
				  adapter, &nsevf_debugfs_dump_txcq_fops);
	(void)debugfs_create_file("dump_qvec", 0600, adapter->vf_dbgfs_dir,
				  adapter, &nsevf_debugfs_dump_qvec_fops);

	(void)debugfs_create_file("fdir_dump_info", 0600, adapter->vf_dbgfs_dir,
				  adapter, &nsevf_debugfs_fdir_dump_info_fops);

	(void)debugfs_create_file("dump_filters", 0600, adapter->vf_dbgfs_dir,
				  adapter, &nsevf_debugfs_dump_filters_fops);

	(void)debugfs_create_file("vfr", 0600, adapter->vf_dbgfs_dir, adapter,
				  &nsevf_debugfs_vfr_fops);

	nsevf_msgbox_debugfs_init(adapter);

	return;

fail:
	dev_err(nsevf_adapter_to_dev(adapter),
		"debugfs dir/file for %s failed\n", name);

	adapter->vf_dbgfs_dir = NULL;
}

void nsevf_debugfs_vf_exit(struct nsevf_adapter *adapter)
{
	debugfs_remove_recursive(adapter->vf_dbgfs_dir);

	adapter->vf_dbgfs_dir = NULL;
}

void nsevf_debugfs_init(void)
{
	nsevf_debugfs_root = debugfs_create_dir(KBUILD_MODNAME, NULL);
	if (IS_ERR(nsevf_debugfs_root)) {
		pr_info("init of debugfs failed\n");
		nsevf_debugfs_root = NULL;
	}
}

void nsevf_debugfs_exit(void)
{
	debugfs_remove_recursive(nsevf_debugfs_root);

	nsevf_debugfs_root = NULL;
}

#endif
