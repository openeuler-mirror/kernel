// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2018 - 2021 Beijing WangXun Technology Co., Ltd. */

#include <linux/fs.h>
#include <linux/debugfs.h>
#include <linux/random.h>
#include <linux/inet.h>

#include "nse.h"
#include "nse_base.h"
#include "nse_common.h"
#include "nse_dcb_lib.h"
#include "nse_irq.h"
#include "nse_lib.h"
#include "nse_sched.h"
#include "nse_sched_aqc.h"
#include "nse_txrx_lib.h"
#include "nse_fdir.h"
#include "nse_fltr.h"
#include "nse_lpm.h"
#include "nse_tc_lib.h"
#include "nse_neigh.h"
#include "nse_lag.h"
#include "nse_acl.h"
#include "nse_msgbox.h"

static struct dentry *nse_debugfs_root;

static ssize_t nse_debugfs_pf_params_rfunc(struct file *filp,
				 char __user *to, size_t count, loff_t *ppos)
{
	struct nse_pf *pf = filp->private_data;
	struct nse_hw *hw = &pf->hw;
	char *buf = NULL;
	int desc = 0;
	int ret;

	buf = kzalloc(4096, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	desc += sprintf(buf + desc, "debug_mask: %lX\n",
				    (unsigned long)hw->debug_mask);

	desc += sprintf(buf + desc, "lan_tx_use_cq: %d\n",
				    pf->sw_conf.lan_tx_use_cq);

	desc += sprintf(buf + desc, "lan_tx_use_cq_for_vf: %d\n",
				    pf->sw_conf.lan_tx_use_cq_for_vf);

	desc += sprintf(buf + desc, "lan_rx_ena_rsc: %d\n",
				    pf->sw_conf.lan_rx_ena_rsc);

	desc += sprintf(buf + desc, "lan_txq_dflt_len: %d\n",
				    pf->sw_conf.lan_txq_dflt_len);

	desc += sprintf(buf + desc, "lan_rxq_dflt_len: %d\n",
				    pf->sw_conf.lan_rxq_dflt_len);

	desc += sprintf(buf + desc, "serv_tmr_period: %ld\n",
				    (pf->serv_tmr_period / HZ));

	desc += sprintf(buf + desc, "poll_link_info_period: %ld\n",
				    (hw->port_info->lmac_phy_info.poll_link_info_period / HZ));

#if defined(NSE_DEBUG_EXT)
	/* test_suite boolean flag */
	desc += sprintf(buf + desc, "test_rss: %d\n",
				pf->test_rss);

	desc += sprintf(buf + desc, "test_fdir: %d\n",
				pf->test_fdir);

	desc += sprintf(buf + desc, "test_rcsum: %d dport: %d\n",
				pf->test_rcsum, pf->test_rcsum_dport);

	desc += sprintf(buf + desc, "test_rvlan: %d dport: %d\n",
				pf->test_rvlan, pf->test_rvlan_dport);

	desc += sprintf(buf + desc, "test_tvlan: %d\n",
				pf->test_tvlan);

	desc += sprintf(buf + desc, "test_tcsum: %d interval: %d\n",
				pf->test_tcsum, pf->test_tcsum_pktcnt_interval);

	desc += sprintf(buf + desc, "test_tcsum_force_l3: %d\n",
				nse_lan_tcsum_force_l3);

	desc += sprintf(buf + desc, "test_tso: %d interval: %d\n",
				pf->test_tso, pf->test_tso_pktcnt_interval);

	desc += sprintf(buf + desc, "tdm_check_desc_err: %d\n",
				nse_lan_tdm_check_desc_err);

	desc += sprintf(buf + desc, "test_tdm_desc_err: %d cntdown: %d\n",
				pf->test_tdm_desc_err, pf->test_tdm_desc_err_cntdown);
#endif

	ret = simple_read_from_buffer(to, count, ppos, buf, desc);

	kfree(buf);

	return ret;
}

static ssize_t
nse_debugfs_pf_params_wfunc(struct file *filp, const char __user *buf,
			  size_t count, loff_t *ppos)
{
	struct nse_pf *pf = filp->private_data;
	struct nse_hw *hw = &pf->hw;
	struct device *dev = nse_pf_to_dev(pf);
	char *cmd_buf, *cmd_buf_tmp;
	ssize_t ret;
	char **argv;
	int argc;
	unsigned int new_val;
	unsigned int new_val_hex;
	struct nse_vsi *vsi = nse_get_main_vsi(pf);
	struct nse_ring *txq = NULL;
	int i;

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

	{
		int ret_dec, ret_hex;

		ret_dec = kstrtouint(argv[1], 10, &new_val);
		ret_hex = kstrtouint(argv[1], 16, &new_val_hex);
		if (ret_dec)
			new_val = 0;
		if (ret_hex)
			new_val_hex = 0;
		if (ret_dec && ret_hex)
			goto bad_usage;
	}

	if (!strcmp(argv[0], "debug_mask")) {
		hw->debug_mask = new_val_hex;
	} else if (!strcmp(argv[0], "serv_tmr_period")) {
		if (new_val > 1)
			pf->serv_tmr_period = (new_val * HZ);
	} else if (!strcmp(argv[0], "poll_link_info_period")) {
		if (new_val > 1)
			hw->port_info->lmac_phy_info.poll_link_info_period = (new_val * HZ);
	}
#if defined(NSE_DEBUG_EXT)
	else if (!strcmp(argv[0], "test_rss")) {
		pf->test_rss = new_val;
	} else if (!strcmp(argv[0], "test_fdir")) {
		pf->test_fdir = new_val;
	} else if (!strcmp(argv[0], "test_rvlan")) {
		if (new_val && argc < 3) {	//need specify dport in argv[2]
			goto bad_usage;
		}

		pf->test_rvlan = new_val;

		if (pf->test_rvlan) {
			if (kstrtouint(argv[2], 10, &new_val)) {
				pf->test_rvlan = 0;
				goto bad_usage;
			}

			pf->test_rvlan_dport = new_val;
		}
	} else if (!strcmp(argv[0], "test_tvlan")) {
		pf->test_tvlan = new_val;
	} else if (!strcmp(argv[0], "test_rcsum")) {
		if (new_val && argc < 3) {	//need specify dport in argv[2]
			goto bad_usage;
		}

		pf->test_rcsum = new_val;

		if (pf->test_rcsum) {
			if (kstrtouint(argv[2], 10, &new_val)) {
				pf->test_rcsum = 0;
				goto bad_usage;
			}

			pf->test_rcsum_dport = new_val;
		}
	} else if (!strcmp(argv[0], "test_tcsum")) {
		if (new_val && argc < 3) {	//need specify dport in argv[2]
			goto bad_usage;
		}

		pf->test_tcsum = new_val;

		if (pf->test_tcsum) {
			if (kstrtouint(argv[2], 10, &new_val)) {
				pf->test_tcsum = 0;
				goto bad_usage;
			}
			if (new_val == 0) {
				pf->test_tcsum = 0;
				goto bad_usage;
			}

			pf->test_tcsum_pktcnt_interval = new_val;

			nse_for_each_txq(vsi, i) {
				txq = vsi->tx_rings[i];
				txq->test_tcsum_pktcnt_cntdown = pf->test_tcsum_pktcnt_interval;
			}
		}
	} else if (!strcmp(argv[0], "test_tcsum_force_l3")) {
		nse_lan_tcsum_force_l3 = new_val;
	} else if (!strcmp(argv[0], "test_tso")) {
		if (new_val && argc < 3) {	//need specify dport in argv[2]
			goto bad_usage;
		}

		pf->test_tso = new_val;

		if (pf->test_tso) {
			if (kstrtouint(argv[2], 10, &new_val)) {
				pf->test_tso = 0;
				goto bad_usage;
			}
			if (new_val == 0) {
				pf->test_tso = 0;
				goto bad_usage;
			}

			pf->test_tso_pktcnt_interval = new_val;

			nse_for_each_txq(vsi, i) {
				txq = vsi->tx_rings[i];
				txq->test_tso_pktcnt_cntdown = pf->test_tso_pktcnt_interval;
			}
		}
	} else if (!strcmp(argv[0], "test_tdm_desc_err")) {
		pf->test_tdm_desc_err = new_val;

		if (argc < 3)
			pf->test_tdm_desc_err_cntdown = 10;
		else {
			if (kstrtouint(argv[2], 10, &new_val))
				pf->test_tdm_desc_err_cntdown = 10;
			else
				pf->test_tdm_desc_err_cntdown = new_val;
		}
	}
#endif
	else
		goto bad_usage;

	/* if we get here, nothing went wrong; return bytes copied */
	ret = (ssize_t)count;

command_write_done:
	argv_free(argv);
err_copy_from_user:
	kfree(cmd_buf);
	return ret;

bad_usage:
	dev_info(dev, "invalid input, usage: echo the following options to change per-PF parameters\n");
	dev_info(dev, "\t debug_mask $X\n");
	dev_info(dev, "\t serv_tmr_period $N\n");
	dev_info(dev, "\t poll_link_info_period $N\n");
#if defined(NSE_DEBUG_EXT)
	dev_info(dev, "\t test_rss $on_or_off\n");
	dev_info(dev, "\t test_rvlan $on_or_off $dport\n");
	dev_info(dev, "\t test_tvlan $on_or_off\n");
	dev_info(dev, "\t test_rcsum $on_or_off $dport\n");
	dev_info(dev, "\t test_tcsum $on_or_off $pkt_interval\n");
	dev_info(dev, "\t test_tcsum_force_l3 $on_or_off\n");
	dev_info(dev, "\t test_tso $on_or_off $pkt_interval\n");
#endif
	ret = -EINVAL;
	goto command_write_done;
}

static const struct file_operations nse_debugfs_pf_params_fops = {
	.owner = THIS_MODULE,
	.open  = simple_open,
	.read = nse_debugfs_pf_params_rfunc,
	.write = nse_debugfs_pf_params_wfunc,
	.llseek = default_llseek,
};

static ssize_t
nse_debugfs_bar0_read_wfunc(struct file *filp, const char __user *buf,
			  size_t count, loff_t *ppos)
{
	struct nse_pf *pf = filp->private_data;
	struct nse_hw *hw = &pf->hw;
	struct device *dev = nse_pf_to_dev(pf);
	char *cmd_buf, *cmd_buf_tmp;
	ssize_t ret;
	char **argv;
	int argc;
	u32 bar0_addr, bar0_val;

	/* don't allow partial writes and writes when reset is in progress*/
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

	if (argc == 1) {
		if (kstrtouint(argv[0], 16, &bar0_addr))

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

static const struct file_operations nse_debugfs_bar0_read_fops = {
	.owner = THIS_MODULE,
	.open  = simple_open,
	.write = nse_debugfs_bar0_read_wfunc,
	.llseek = default_llseek,
};

static ssize_t
nse_debugfs_bar0_read_all_wfunc(struct file *filp, const char __user *buf,
			  size_t count, loff_t *ppos)
{
	struct nse_pf *pf = filp->private_data;
	struct nse_hw *hw = &pf->hw;
	struct device *dev = nse_pf_to_dev(pf);
	char *cmd_buf, *cmd_buf_tmp;
	ssize_t ret;
	char **argv;
	int argc;

	/* don't allow partial writes and writes when reset is in progress*/
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

	if (argc != 1)
		goto bad_usage;

    /* hw->hw_addr */
	dev_info(dev, "hw->hw_addr(BAR0 vaddr): %lX\n",
		 (unsigned long)hw->hw_addr);

	dev_info(dev, "hw->hw_addr_bar2(BAR2 vaddr): %lX\n",
		 (unsigned long)hw->hw_addr_bar2);

	/* basic regs */
	dev_info(dev, "ST(%X): %X\n",
					NSE_REG_ST, rd32(hw, NSE_REG_ST));

	dev_info(dev, "CTL(%X): %X\n",
					NSE_REG_CTL, rd32(hw, NSE_REG_CTL));

	/* oicr regs */
	dev_info(dev, "OICR_CTL(%X): %X\n",
					NSE_REG_OICR_CTL, rd32(hw, NSE_REG_OICR_CTL));

	dev_info(dev, "OICR_ENA(%X): %X\n",
					NSE_REG_OICR_ENA, rd32(hw, NSE_REG_OICR_ENA));

	dev_info(dev, "OICR_MASK(%X): %X\n",
					NSE_REG_OICR_MASK, rd32(hw, NSE_REG_OICR_MASK));

	/* aq-sq regs */
	dev_info(dev, "PMBX_ATQBAH(%X): %X\n",
					NSE_REG_PMBX_ATQBAH, rd32(hw, NSE_REG_PMBX_ATQBAH));

	dev_info(dev, "PMBX_ATQBAL(%X): %X\n",
					NSE_REG_PMBX_ATQBAL, rd32(hw, NSE_REG_PMBX_ATQBAL));

	dev_info(dev, "PMBX_ATQLEN(%X): %X\n",
					NSE_REG_PMBX_ATQLEN, rd32(hw, NSE_REG_PMBX_ATQLEN));

	dev_info(dev, "PMBX_ATQH(%X): %X\n",
					NSE_REG_PMBX_ATQH, rd32(hw, NSE_REG_PMBX_ATQH));

	dev_info(dev, "PMBX_ATQT(%X): %X\n",
					NSE_REG_PMBX_ATQT, rd32(hw, NSE_REG_PMBX_ATQT));

	/* aq-rq regs */
	dev_info(dev, "PMBX_ARQBAH(%X): %X\n",
					NSE_REG_PMBX_ARQBAH, rd32(hw, NSE_REG_PMBX_ARQBAH));

	dev_info(dev, "PMBX_ARQBAL(%X): %X\n",
					NSE_REG_PMBX_ARQBAL, rd32(hw, NSE_REG_PMBX_ARQBAL));

	dev_info(dev, "PMBX_ARQLEN(%X): %X\n",
					NSE_REG_PMBX_ARQLEN, rd32(hw, NSE_REG_PMBX_ARQLEN));

	dev_info(dev, "PMBX_ARQH(%X): %X\n",
					NSE_REG_PMBX_ARQH, rd32(hw, NSE_REG_PMBX_ARQH));

	dev_info(dev, "PMBX_ARQT(%X): %X\n",
					NSE_REG_PMBX_ARQT, rd32(hw, NSE_REG_PMBX_ARQT));

	/* aq-ctl/cxt */
	dev_info(dev, "PMBX_CTL(%X): %X\n",
					NSE_REG_PMBX_CTL, rd32(hw, NSE_REG_PMBX_CTL));

	/* utilq regs */
	dev_info(dev, "NSE_REG_UTI_ATQBAH(%X): %X\n",
					NSE_REG_UTI_ATQBAH(0), rd32(hw, NSE_REG_UTI_ATQBAH(0)));

	dev_info(dev, "NSE_REG_UTI_ATQBAL(%X): %X\n",
					NSE_REG_UTI_ATQBAL(0), rd32(hw, NSE_REG_UTI_ATQBAL(0)));

	dev_info(dev, "NSE_REG_UTI_ATQLEN(%X): %X\n",
					NSE_REG_UTI_ATQLEN(0), rd32(hw, NSE_REG_UTI_ATQLEN(0)));

	dev_info(dev, "NSE_REG_UTI_ATQH(%X): %X\n",
					NSE_REG_UTI_ATQH(0), rd32(hw, NSE_REG_UTI_ATQH(0)));

	dev_info(dev, "NSE_REG_UTI_ATQT(%X): %X\n",
					NSE_REG_UTI_ATQT(0), rd32(hw, NSE_REG_UTI_ATQT(0)));

	dev_info(dev, "NSE_REG_UTI_CTL(%X): %X\n",
					NSE_REG_UTI_CTL(0), rd32(hw, NSE_REG_UTI_CTL(0)));

	/* interrupt */
	dev_info(dev, "NSE_REG_INT_DYN_CTLN(0)(%X): %X\n",
					NSE_REG_INT_DYN_CTLN(0), rd32(hw, NSE_REG_INT_DYN_CTLN(0)));

	/* if we get here, nothing went wrong; return bytes copied */
	ret = (ssize_t)count;

command_write_done:
	argv_free(argv);
err_copy_from_user:
	kfree(cmd_buf);
	return ret;

bad_usage:
	dev_info(dev, "invalid input, usage: echo 'any words' > bar0_read_all\n");
	ret = -EINVAL;
	goto command_write_done;
}

static const struct file_operations nse_debugfs_bar0_read_all_fops = {
	.owner = THIS_MODULE,
	.open  = simple_open,
	.write = nse_debugfs_bar0_read_all_wfunc,
	.llseek = default_llseek,
};

static ssize_t
nse_debugfs_bar0_write_wfunc(struct file *filp, const char __user *buf,
			  size_t count, loff_t *ppos)
{
	struct nse_pf *pf = filp->private_data;
	struct nse_hw *hw = &pf->hw;
	struct device *dev = nse_pf_to_dev(pf);
	char *cmd_buf, *cmd_buf_tmp;
	ssize_t ret;
	char **argv;
	int argc;
	u32 bar0_addr, bar0_val;

	/* don't allow partial writes and writes when reset is in progress*/
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

	if (argc == 2) {
		if (kstrtouint(argv[0], 16, &bar0_addr))

			goto bad_usage;

		if (kstrtouint(argv[1], 16, &bar0_val))

			goto bad_usage;

		dev_info(dev, "gonna write BAR0 reg: %X = %X\n", bar0_addr, bar0_val);

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

static const struct file_operations nse_debugfs_bar0_write_fops = {
	.owner = THIS_MODULE,
	.open  = simple_open,
	.write = nse_debugfs_bar0_write_wfunc,
};

static ssize_t nse_debugfs_reset_rfunc(struct file *filp,
				 char __user *to, size_t count, loff_t *ppos)
{
	struct nse_pf *pf = filp->private_data;
	char *buf = NULL;
	int desc = 0;
	int ret;

	buf = kzalloc(4096, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	desc += sprintf(buf + desc, "PF-RESET count: %d\n",
				pf->pf_reset_count);
	desc += sprintf(buf + desc, "\t PFR count: %d\n",
				pf->pfr_count);
	desc += sprintf(buf + desc, "\t PFLR count: %d\n",
				pf->pflr_count);

	desc += sprintf(buf + desc, "CORE-RESET count: %d\n",
				/* should use high_reset_count, but it is not implemented yet. */
				pf->high_reset_oicr_corer_count);

	desc += sprintf(buf + desc, "last-time-reset-fail: %d\n",
				!!test_bit(NSE_RESET_FAILED, pf->state));

	ret = simple_read_from_buffer(to, count, ppos, buf, desc);

	kfree(buf);

	return ret;
}

static ssize_t
nse_debugfs_reset_wfunc(struct file *filp, const char __user *buf,
			  size_t count, loff_t *ppos)
{
	struct nse_pf *pf = filp->private_data;
	struct device *dev = nse_pf_to_dev(pf);
	char *cmd_buf, *cmd_buf_tmp;
	ssize_t ret;
	char **argv;
	int argc;
	int func_ret;
	unsigned int reset_request = 0;
	enum nse_reset_req reset_type;

	/* don't allow partial writes and writes when reset is in progress*/
	if (*ppos != 0 || nse_is_reset_in_progress(pf->state))
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

	if (argc != 1)
		goto bad_usage;

	if (kstrtouint(argv[0], 16, &reset_request))
		goto bad_usage;

	if (reset_request == 1)
		reset_type = NSE_RESET_PFR;
	else if (reset_request == 2)
		reset_type = NSE_RESET_HIGH_RESET_CORER;
	else
		goto bad_usage;

	func_ret = nse_schedule_reset(pf, reset_type);
	if (func_ret)
		dev_err(dev, "[%s] FAIL: schedule_reset(reset_type=%d), ret=%d\n",
						__func__, reset_type, func_ret);
	else
		dev_info(dev, "[%s] schedule_reset(reset_type=%d), see log and what may happen\n",
						__func__, reset_type);

	/* if we get here, nothing went wrong; return bytes copied */
	ret = (ssize_t)count;

command_write_done:
	argv_free(argv);
err_copy_from_user:
	kfree(cmd_buf);
	return ret;

bad_usage:
	dev_info(dev, "invalid input, usage: echo '1(pfr)| 2(core_reset)' > this file\n");
	ret = -EINVAL;
	goto command_write_done;
}

static const struct file_operations nse_debugfs_reset_fops = {
	.owner = THIS_MODULE,
	.open  = simple_open,
	.read = nse_debugfs_reset_rfunc,
	.write = nse_debugfs_reset_wfunc,
	.llseek = default_llseek,
};

static ssize_t
nse_debugfs_check_temp_test_wfunc(struct file *filp, const char __user *buf,
			  size_t count, loff_t *ppos)
{
	struct nse_pf *pf = filp->private_data;
	struct nse_hw *hw = &pf->hw;
	struct device *dev = nse_pf_to_dev(pf);
	char *cmd_buf, *cmd_buf_tmp;
	ssize_t ret;
	char **argv;
	int argc;
	unsigned int val = 0;
	int chip_temp = 0, ephy_temp = 0;
	enum nse_status status;

	/* don't allow partial writes and writes when reset is in progress*/
	if (*ppos != 0 || nse_is_reset_in_progress(pf->state))
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

	if (argc != 1)
		goto bad_usage;

	if (kstrtouint(argv[0], 16, &val))
		goto bad_usage;

	dev_info(dev, "run_cnt=%ld\n", pf->check_temp_run_cnt);
	dev_info(dev, "high_cnt=%ld\n", pf->check_temp_high_cnt);
	dev_info(dev, "low_cnt=%ld\n", pf->check_temp_low_cnt);
	dev_info(dev, "enable oicr->overheat=%d\n", !!(pf->oicr_ena & NSE_REG_OICR_OVERHEAT_M));

	status = nse_aq_read_chip_temperature(hw, &chip_temp);
	if (status)
		dev_err(dev, "FAIL: aq_read_chip_temperature(), status=%d\n", status);
	else
		dev_info(dev, "chip_temp=%d\n", chip_temp);

	if (nse_is_nic_use_ephy(hw->nic_type)) {
		status = nse_lmac_phy_ephy_read_temperature(hw, &ephy_temp);
		if (status)
			dev_err(dev, "FAIL: ephy_read_temperature(), status=%d\n", status);
		else
			dev_info(dev, "ephy_temp=%d\n", ephy_temp);
	}

	if (!nse_misc_check_temp)
		goto skip_test;

	if (val == 0) {
		wd_subtask_check_temp_chip_high_thres = WD_SUBTASK_CHECK_TEMP_CHIP_HIGH_THRES;
		wd_subtask_check_temp_chip_low_thres = WD_SUBTASK_CHECK_TEMP_CHIP_LOW_THRES;
		wd_subtask_check_temp_ephy_high_thres = WD_SUBTASK_CHECK_TEMP_EPHY_HIGH_THRES;
		wd_subtask_check_temp_ephy_low_thres = WD_SUBTASK_CHECK_TEMP_EPHY_LOW_THRES;

		pf->wd_subtask_check_temp_prev = 0;	//let it run fast

	} else if (val == 1) {
		wd_subtask_check_temp_chip_high_thres = 30;
		wd_subtask_check_temp_chip_low_thres = 20;
		wd_subtask_check_temp_ephy_high_thres = 30;
		wd_subtask_check_temp_ephy_low_thres = 20;

		pf->wd_subtask_check_temp_prev = 0;	//let it run fast

	} else if (val == 2) {
		wd_subtask_check_temp_chip_high_thres = -10;
		wd_subtask_check_temp_chip_low_thres = -20;

		wr32(hw, NSE_REG_OICR_SET, NSE_REG_OICR_OVERHEAT_M);

	} else if (val == 255) {
		wd_subtask_check_temp_chip_high_thres = 255;
		wd_subtask_check_temp_chip_low_thres = 255;
		wd_subtask_check_temp_ephy_high_thres = 255;
		wd_subtask_check_temp_ephy_low_thres = 255;

		pf->check_temp_force_cancel_rl_after_reset = true;
		pf->wd_subtask_check_temp_prev = 0;	//let it run fast
	}

skip_test:

	/* if we get here, nothing went wrong; return bytes copied */
	ret = (ssize_t)count;

command_write_done:
	argv_free(argv);
err_copy_from_user:
	kfree(cmd_buf);
	return ret;

bad_usage:
	dev_info(dev, "invalid input, usage: echo '[0|1]' > this file\n");
	ret = -EINVAL;
	goto command_write_done;
}

static const struct file_operations nse_debugfs_check_temp_test_fops = {
	.owner = THIS_MODULE,
	.open  = simple_open,
	.write = nse_debugfs_check_temp_test_wfunc,
	.llseek = default_llseek,
};

static ssize_t
nse_debugfs_ephy_info_wfunc(struct file *filp, const char __user *buf,
			    size_t count, loff_t *ppos)
{
	struct nse_pf *pf = filp->private_data;
	struct nse_hw *hw = &pf->hw;
	struct device *dev = nse_pf_to_dev(pf);
	char *cmd_buf, *cmd_buf_tmp;
	ssize_t ret;
	char **argv;
	int argc;

	/* don't allow partial writes and writes when reset is in progress*/
	if (*ppos != 0 || nse_is_reset_in_progress(pf->state))
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

	if (argc != 1)
		goto bad_usage;

	nse_lmac_phy_ephy_dump_info(hw);

	/* if we get here, nothing went wrong; return bytes copied */
	ret = (ssize_t)count;

command_write_done:
	argv_free(argv);
err_copy_from_user:
	kfree(cmd_buf);
	return ret;

bad_usage:
	dev_info(dev, "invalid input, usage: echo 'any thing' > this file\n");
	ret = -EINVAL;
	goto command_write_done;
}

static const struct file_operations nse_debugfs_ephy_info_fops = {
	.owner = THIS_MODULE,
	.open  = simple_open,
	.write = nse_debugfs_ephy_info_wfunc,
	.llseek = default_llseek,
};

static ssize_t
nse_debugfs_up_enforce_wfunc(struct file *filp, const char __user *buf,
			  size_t count, loff_t *ppos)
{
	struct nse_pf *pf = filp->private_data;
	struct device *dev = nse_pf_to_dev(pf);
	char *cmd_buf, *cmd_buf_tmp;
	ssize_t ret;
	char **argv;
	int argc;
	unsigned int op = 0;
	enum nse_status status;

	/* don't allow partial writes and writes when reset is in progress*/
	if (*ppos != 0 || nse_is_reset_in_progress(pf->state))
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

	if (argc != 1)
		goto bad_usage;

	if (kstrtouint(argv[0], 16, &op))
		goto bad_usage;

	if (op)
		status = nse_set_dcb_up_enforcement(&pf->hw,
						    &pf->hw.port_info->qos_cfg.local_dcbx_cfg);
	else
		status = nse_set_dcb_up_enforcement_force_off(&pf->hw);

	/* if we get here, nothing went wrong; return bytes copied */
	ret = (ssize_t)count;

command_write_done:
	argv_free(argv);
err_copy_from_user:
	kfree(cmd_buf);
	return ret;

bad_usage:
	dev_info(dev, "invalid input, usage: echo '0|1' > this file\n");
	ret = -EINVAL;
	goto command_write_done;
}

static const struct file_operations nse_debugfs_up_enforce_fops = {
	.owner = THIS_MODULE,
	.open  = simple_open,
	.write = nse_debugfs_up_enforce_wfunc,
	.llseek = default_llseek,
};

static ssize_t
nse_debugfs_int_dyn_ctl_wfunc(struct file *filp, const char __user *buf,
			  size_t count, loff_t *ppos)
{
	struct nse_pf *pf = filp->private_data;
	struct nse_hw *hw = &pf->hw;
	struct device *dev = nse_pf_to_dev(pf);
	char *cmd_buf, *cmd_buf_tmp;
	ssize_t ret;
	char **argv;
	int argc;
	u32 irq_id_in_pf, regval;

	/* don't allow partial writes and writes when reset is in progress*/
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

	if (kstrtouint(argv[1], 10, &irq_id_in_pf))
		goto bad_usage;

	if (!strcmp(argv[0], "r")) {
		regval = rd32(hw, NSE_REG_INT_DYN_CTLN(irq_id_in_pf));

		dev_info(dev, "NSE_REG_INT_DYN_CTLN(%d): %X\n",
						irq_id_in_pf, regval);

		dev_info(dev, "    wb_on_itr: %d\n",
						(regval & NSE_REG_INT_DYN_CTLN_WB_ON_ITR_M) ?
							1 : 0);

		dev_info(dev, "    swint_trig: %d\n",
						(regval & NSE_REG_INT_DYN_CTLN_SWINT_TRIG_M) ?
							1 : 0);

		dev_info(dev, "    clearpba: %d\n",
						(regval & NSE_REG_INT_DYN_CTLN_CLEARPBA_M) ? 1 : 0);
	} else if (!strcmp(argv[0], "w")) {
		regval = 0;

		if (argc < 3)
			goto bad_usage;

		if (strstr(argv[2], "wb_on_itr"))
			regval |= NSE_REG_INT_DYN_CTLN_WB_ON_ITR_M;
		if (strstr(argv[2], "swint_trig"))
			regval |= NSE_REG_INT_DYN_CTLN_SWINT_TRIG_M;
		if (strstr(argv[2], "clearpba"))
			regval |= NSE_REG_INT_DYN_CTLN_CLEARPBA_M;

		/* if no above options, then regval = 0 --- means: intmask = 0 */

		wr32(hw, NSE_REG_INT_DYN_CTLN(irq_id_in_pf), regval);
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
	dev_info(dev, "invalid input, usage: echo '[r|w] irq_id [wb_on_itr|swint_trig|clearpba|intmask]' > int_dyn_ctl\n");
	ret = -EINVAL;
	goto command_write_done;
}

static const struct file_operations nse_debugfs_int_dyn_ctl_fops = {
	.owner = THIS_MODULE,
	.open  = simple_open,
	.write = nse_debugfs_int_dyn_ctl_wfunc,
};

static ssize_t
nse_debugfs_reg_read_wfunc(struct file *filp, const char __user *buf,
			  size_t count, loff_t *ppos)
{
	struct nse_pf *pf = filp->private_data;
	struct nse_hw *hw = &pf->hw;
	struct device *dev = nse_pf_to_dev(pf);
	char *cmd_buf, *cmd_buf_tmp;
	char **argv;
	int argc;
	int i;
	u32 reg_base_addr, reg_cnt;
	u32 *reg_values = NULL;
	enum nse_status status;
	ssize_t ret;

	/* don't allow partial writes and writes when reset is in progress*/
	if (*ppos != 0 || nse_is_reset_in_progress(pf->state))
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

	if (kstrtouint(argv[0], 16, &reg_base_addr))
		goto bad_usage;

	if (argc == 1) {
		reg_cnt = 1;
	} else {
		if (kstrtouint(argv[1], 10, &reg_cnt) ||
			reg_cnt <= 0)
			goto bad_usage;
	}

	reg_values = kmalloc_array(reg_cnt, sizeof(u32), GFP_KERNEL);
	if (!reg_values) {
		ret = -ENOMEM;
		goto command_write_done;
	}

	status = nse_aq_dbg_rw_registers(hw, (FW_RNOC_BASE + reg_base_addr),
					 reg_cnt, 0, reg_values, 0);
	if (status) {
		dev_info(dev, "[%s, %d] aq_dbg_rw_registers() read registers from HW fails\n",
					__func__, __LINE__);
	} else {
		for (i = 0; i < reg_cnt; i++) {
			dev_info(dev, "reg(%X) = %X\n",
						reg_base_addr + (i * 4),
						reg_values[i]);
		}
	}

	/* return bytes copied */
	ret = (ssize_t)count;

command_write_done:
	argv_free(argv);
err_copy_from_user:
	kfree(cmd_buf);

	kfree(reg_values);

	return ret;

bad_usage:
	dev_info(dev, "invalid input, usage: echo 'reg_base_addr(HEX) reg_cnt(DEC)' > reg_read\n");
	ret = -EINVAL;
	goto command_write_done;
}

static const struct file_operations nse_debugfs_reg_read_fops = {
	.owner = THIS_MODULE,
	.open  = simple_open,
	.write = nse_debugfs_reg_read_wfunc,
	.llseek = default_llseek,
};

static ssize_t
nse_debugfs_reg_write_wfunc(struct file *filp, const char __user *buf,
			  size_t count, loff_t *ppos)
{
	struct nse_pf *pf = filp->private_data;
	struct nse_hw *hw = &pf->hw;
	struct device *dev = nse_pf_to_dev(pf);
	char *cmd_buf, *cmd_buf_tmp;
	char **argv;
	int argc;
	int i;
	u32 reg_base_addr, reg_cnt;
	u32 *reg_values = NULL;
	enum nse_status status;
	ssize_t ret;

	/* don't allow partial writes and writes when reset is in progress*/
	if (*ppos != 0 || nse_is_reset_in_progress(pf->state))
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

	if (kstrtouint(argv[0], 16, &reg_base_addr))
		goto bad_usage;

	reg_cnt = argc - 1;

	reg_values = kmalloc_array(reg_cnt, sizeof(u32), GFP_KERNEL);
	if (!reg_values) {
		ret = -ENOMEM;
		goto command_write_done;
	}

	for (i = 0; i < reg_cnt; i++) {
		/* starting from argv[1] */
		if (kstrtouint(argv[1 + i], 16, &reg_values[i]))
			goto bad_usage;
	}

	status = nse_aq_dbg_rw_registers(hw, (FW_RNOC_BASE + reg_base_addr), reg_cnt, 1,
					 reg_values, NSE_CTLQ_SQ_SEND_CMD_FLAG_NO_WAIT);
	if (status) {
		dev_info(dev, "[%s, %d] aq_dbg_rw_registers() write registers from HW fails\n",
					__func__, __LINE__);
	}

	/* return bytes copied */
	ret = (ssize_t)count;

command_write_done:
	argv_free(argv);
err_copy_from_user:
	kfree(cmd_buf);

	kfree(reg_values);

	return ret;

bad_usage:
	dev_info(dev, "invalid input, usage: echo 'reg_base_addr(HEX) reg_val_0(HEX) reg_val_1 .....' > reg_write\n");
	ret = -EINVAL;
	goto command_write_done;
}

static const struct file_operations nse_debugfs_reg_write_fops = {
	.owner = THIS_MODULE,
	.open  = simple_open,
	.write = nse_debugfs_reg_write_wfunc,
	.llseek = default_llseek,
};

static ssize_t
nse_debugfs_aq_cmd_wfunc(struct file *filp, const char __user *buf,
			  size_t count, loff_t *ppos)
{
	struct nse_pf *pf = filp->private_data;
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_hw *hw = &pf->hw;
	char *cmd_buf = NULL, *cmd_buf_tmp = NULL;
	u8 *aq_cmd_buf = NULL;
	u32 aq_cmd_buf_len = 0;
	u16 val16;
	ssize_t ret;
	char **argv = NULL;
	int argc;
	enum nse_status status = NSE_SUCCESS;

	u16 qid_pf, qid_abs;
	bool rxq_or_txq;

	/* don't allow partial writes and writes when reset is in progress*/
	if (*ppos != 0 || nse_is_reset_in_progress(pf->state))
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

	if (!strcmp(argv[0], "xchg_sw_fw_ver")) {
		status = nse_aq_xchg_sw_fw_ver(hw);
		if (status == NSE_SUCCESS) {
			dev_info(dev, "aq_cmd - xchg_sw_fw_ver: success\n");

			dev_info(dev, "\t fw version:\n");
			dev_info(dev, "\t\t major_ver: %x\n", (int)hw->fw_ver.major_ver);
			dev_info(dev, "\t\t minor_ver: %x\n", (int)hw->fw_ver.minor_ver);
			dev_info(dev, "\t\t mini_ver: %x\n", (int)hw->fw_ver.mini_ver);
			dev_info(dev, "\t\t build_ver: %x\n", (int)hw->fw_ver.build_ver);

			dev_info(dev, "\t\t private_major_ver: %x\n",
				 (int)hw->fw_ver.private_major_ver);
			dev_info(dev, "\t\t private_minor_ver: %x\n",
				 (int)hw->fw_ver.private_minor_ver);
			dev_info(dev, "\t\t private_mini_ver: %x\n",
				 (int)hw->fw_ver.private_mini_ver);
			dev_info(dev, "\t\t private_build_ver: %x\n",
				 (int)hw->fw_ver.private_build_ver);
		} else {
			dev_info(dev, "aq_cmd - xchg_sw_fw_ver: fail, status = %d (%s)\n",
				(int)status, nse_stat_str(status));
		}
	} else if (!strcmp(argv[0], "ping_fw")) {
		status = nse_aq_ping_fw(hw);
		if (status == NSE_SUCCESS) {
			dev_info(dev, "aq_cmd - ping_fw: success\n");
		} else {
			dev_info(dev, "aq_cmd - ping_fw: fail, status = %d (%s)\n",
				(int)status, nse_stat_str(status));
		}
	} else if (!strcmp(argv[0], "discover_func_caps")) {
		status = nse_get_caps(hw);

		if (status == NSE_SUCCESS) {
			dev_info(dev, "aq_cmd - discover_func_caps: success\n");

			nse_dump_caps(hw);
		} else {
			dev_info(dev, "aq_cmd - discover_func_caps: fail, status = %d (%s)\n",
				(int)status, nse_stat_str(status));
		}
	} else if (!strcmp(argv[0], "ping_fw_with_buf")) {
		if (argc == 1) {
			aq_cmd_buf_len = NSE_AQ_MAX_BUF_LEN;
		} else {
			if (kstrtouint(argv[1], 10, &aq_cmd_buf_len))
				aq_cmd_buf_len = NSE_AQ_MAX_BUF_LEN;
		}

		if (aq_cmd_buf_len <= 0 || aq_cmd_buf_len > NSE_AQ_MAX_BUF_LEN)
			goto bad_usage;

		aq_cmd_buf = kmalloc(aq_cmd_buf_len, GFP_KERNEL);
		if (aq_cmd_buf == NULL) {
			ret = -ENOMEM;
			goto command_write_done;
		}

		get_random_bytes(aq_cmd_buf, aq_cmd_buf_len);

		status = nse_aq_dbg_ping_fw_with_buf(hw, aq_cmd_buf, aq_cmd_buf_len);

		if (status == NSE_SUCCESS) {
			dev_info(dev, "aq_cmd - ping_fw_with_buf: success\n");
			dev_info(dev, "   ping_fw_with_buf write-back content (first 8 bytes):\n");
			dev_info(dev, "    %02X %02X %02X %02X %02X %02X %02X %02X\n",
								aq_cmd_buf[0], aq_cmd_buf[1],
									aq_cmd_buf[2],
									aq_cmd_buf[3],
								aq_cmd_buf[4], aq_cmd_buf[5],
									aq_cmd_buf[6],
									aq_cmd_buf[7]);

		} else {
			dev_info(dev, "aq_cmd - ping_fw_with_buf: fail, status = %d (%s)\n",
				(int)status, nse_stat_str(status));
		}
	} else if (!strcmp(argv[0], "ping_fw_rq_req")) {
		if (argc == 1)
			aq_cmd_buf_len = NSE_AQ_MAX_BUF_LEN;
		else if (kstrtouint(argv[1], 10, &aq_cmd_buf_len))
			goto bad_usage;
		if (aq_cmd_buf_len <= 0 || aq_cmd_buf_len > NSE_AQ_MAX_BUF_LEN)
			goto bad_usage;

		aq_cmd_buf = kmalloc(aq_cmd_buf_len, GFP_KERNEL);
		if (aq_cmd_buf == NULL) {
			ret = -ENOMEM;
			goto command_write_done;
		}

		get_random_bytes(aq_cmd_buf, aq_cmd_buf_len);

		status = nse_aq_dbg_ping_fw_rq_req(hw, aq_cmd_buf, aq_cmd_buf_len);

		if (status == NSE_SUCCESS) {
			dev_info(dev, "aq_cmd - ping_fw_rq_req: success\n");
			dev_info(dev, "   ping_fw_rq_req cmd_buffer data (first 8 bytes):\n");
			dev_info(dev, "    %02X %02X %02X %02X %02X %02X %02X %02X\n",
								aq_cmd_buf[0], aq_cmd_buf[1],
									aq_cmd_buf[2],
									aq_cmd_buf[3],
								aq_cmd_buf[4], aq_cmd_buf[5],
									aq_cmd_buf[6],
									aq_cmd_buf[7]);

			dev_info(dev, "nse_clean_adminq_subtask() should soon get FW_RQ_RSP sent by FW to adminq-RQ\n");
		} else {
			dev_info(dev, "aq_cmd - ping_fw_rq_req: fail, status = %d (%s)\n",
				(int)status, nse_stat_str(status));
		}
	} else if (!strcmp(argv[0], "read_lan_rxq_context") ||
		   !strcmp(argv[0], "read_lan_txq_context")) {
		if (argc <= 2)
			goto bad_usage;

		/* borrow argc: argc = 0 for lan_rxq, argc = 1 for lan_txq */
		if (!strcmp(argv[0], "read_lan_rxq_context"))
			rxq_or_txq = 1;
		else
			rxq_or_txq = 0;

		/* borrow aq_cmd_buf_len as RXQ/TXQ abs id */
		if (kstrtou16(argv[1], 10, &qid_abs))
			goto bad_usage;

		if (qid_abs >= hw->hw_conf.max_lan_rxq_space ||
			qid_abs >= hw->hw_conf.max_lan_txq_space)
			goto bad_usage;

		/* sizeof(struct nse_lan_rxq_ctx) == sizeof(struct nse_lan_txq_ctx ) */
		aq_cmd_buf = kzalloc(sizeof(struct nse_lan_txq_ctx), GFP_KERNEL);
		if (!aq_cmd_buf) {
			ret = -ENOMEM;
			goto command_write_done;
		}

		if (rxq_or_txq)
			status = nse_read_rxq_ctx(hw, (struct nse_lan_rxq_ctx *)aq_cmd_buf,
						  qid_abs);
		else
			status = nse_read_txq_ctx(hw, (struct nse_lan_txq_ctx *)aq_cmd_buf,
						  qid_abs);

		if (status == NSE_SUCCESS) {
			if (rxq_or_txq) {
				if (qid_abs >= pf->lan_rxq_space_start &&
					qid_abs < (pf->lan_rxq_space_start +
						   pf->lan_rxq_space_size)) {
					qid_pf = qid_abs - pf->lan_rxq_space_start;
				} else {
					dev_info(dev, "qid_abs is out of this PF's RXQ space, should print qid_pf as 0\n");

					qid_pf = -1;
				}

				nse_lan_rxq_ctx_dump(hw, qid_pf, qid_abs,
						     (struct nse_lan_rxq_ctx *)aq_cmd_buf, 0xFF);
			} else {
				if (qid_abs >= pf->lan_txq_space_start &&
					qid_abs < (pf->lan_txq_space_start +
						   pf->lan_txq_space_size)) {
					qid_pf = qid_abs - pf->lan_txq_space_start;
				} else {
					dev_info(dev, "qid_abs is out of this PF's TXQ space, should print qid_pf as 0\n");

					qid_pf = -1;
				}

				nse_lan_txq_ctx_dump(hw, qid_pf, qid_abs,
						     (struct nse_lan_txq_ctx *)aq_cmd_buf, 0xFF);
			}
		} else {
			dev_info(dev, "aq_cmd - read_lan_rxq/txq_context: fail, status = %d (%s)\n",
				(int)status, nse_stat_str(status));
		}

	} else if (!strcmp(argv[0], "read_lan_rxq_status") ||
		   !strcmp(argv[0], "read_lan_txq_status")) {
		if (argc <= 2)
			goto bad_usage;

		/* borrow argc: argc = 0 for lan_rxq, argc = 1 for lan_txq */
		if (!strcmp(argv[0], "read_lan_rxq_status"))
			argc = 0;
		else
			argc = 1;

		/* borrow aq_cmd_buf_len as RXQ/TXQ abs id */
		if (kstrtouint(argv[1], 10, &aq_cmd_buf_len))
			goto bad_usage;

		if (aq_cmd_buf_len >= hw->hw_conf.max_lan_rxq_space ||
		    aq_cmd_buf_len >= hw->hw_conf.max_lan_txq_space)
			goto bad_usage;

		if (!argc)
			status = nse_aq_lan_read_rxq_status(hw, aq_cmd_buf_len, &val16);
		else
			status = nse_aq_lan_read_txq_status(hw, aq_cmd_buf_len, &val16);

		if (status == NSE_SUCCESS) {
			dev_info(dev, "aq_cmd - read_lan_rxq/txq_status: success, q_status = %d\n",
				val16);
		} else {
			dev_info(dev, "aq_cmd - read_lan_rxq/txq_status: fail, status = %d (%s)\n",
				(int)status, nse_stat_str(status));
		}
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

	kfree(aq_cmd_buf);

	return ret;

bad_usage:
	dev_info(dev, "unknown or invalid aq_cmd '%s'\n", argv[1]);
	dev_info(dev, "available aq_cmd\n");
	dev_info(dev, "    xchg_sw_fw_ver\n");
	dev_info(dev, "    ping_fw\n");
	dev_info(dev, "    ping_fw_with_buf $(aq_cmd_buf_len - optional, less than 4096, default 4096)\n");
	dev_info(dev, "    ping_fw_rq_req $(aq_cmd_buf_len - optional, less than 4096, default 4096)\n");
	dev_info(dev, "    discover_func_caps\n");
	dev_info(dev, "    ping_fw_with_buf $(aq_cmd_buf_len - optional, less than 4096, default 4096)\n");
	dev_info(dev, "    read_lan_rxq_context | read_lan_txq_context $(rxq or txq *** absolute ID ***, must less than 1024)\n");
	dev_info(dev, "    read_lan_rxq_status | read_lan_txq_status $(rxq or txq *** absolute ID ***, must less than 1024)\n");

	ret = -EINVAL;

	goto command_write_done;
}

static const struct file_operations nse_debugfs_aq_cmd_fops = {
	.owner = THIS_MODULE,
	.open  = simple_open,
	.write = nse_debugfs_aq_cmd_wfunc,
	.llseek = default_llseek,
};

static ssize_t nse_debugfs_ctlq_stats_rfunc(struct file *filp,
				 char __user *to, size_t count, loff_t *ppos)
{
	struct nse_pf *pf = filp->private_data;
	struct nse_hw *hw = &pf->hw;
	char *buf = NULL;
	int desc = 0;
	int ret;
	unsigned long average_ns = 0;

	buf = kzalloc(4096, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	desc += sprintf(buf + desc, "sq_total_cnt: %lld\n",
		(unsigned long long)hw->controlq_stats.sq_total_cnt);

	desc += sprintf(buf + desc, "sq_success_cnt: %lld\n",
		(unsigned long long)hw->controlq_stats.sq_success_cnt);

	desc += sprintf(buf + desc, "sq_fail_cnt: %lld\n",
		(unsigned long long)hw->controlq_stats.sq_fail_cnt);

	desc += sprintf(buf + desc, "sq_fail_timeout_cnt: %lld\n",
		(unsigned long long)hw->controlq_stats.sq_fail_timeout_cnt);

	desc += sprintf(buf + desc, "sq_total_ns: %lld\n",
		(unsigned long long)hw->controlq_stats.sq_total_ns);

	desc += sprintf(buf + desc, "sq_success_ns: %lld\n",
		(unsigned long long)hw->controlq_stats.sq_success_ns);

	desc += sprintf(buf + desc, "sq_fail_ns: %lld\n",
		(unsigned long long)hw->controlq_stats.sq_fail_ns);

	desc += sprintf(buf + desc, "sq_fail_timeout_ns: %lld\n",
		(unsigned long long)hw->controlq_stats.sq_fail_timeout_ns);

	desc += sprintf(buf + desc, "\nAverage (in ns):\n");

	if (hw->controlq_stats.sq_total_ns && hw->controlq_stats.sq_total_cnt) {
		average_ns = div64_ul(hw->controlq_stats.sq_total_ns,
				      hw->controlq_stats.sq_total_cnt);
	} else {
		average_ns = 0;
	}
	desc += sprintf(buf + desc, "\t sq_total_average: %ld\n", average_ns);

	if (hw->controlq_stats.sq_success_ns && hw->controlq_stats.sq_success_cnt) {
		average_ns = div64_ul(hw->controlq_stats.sq_success_ns,
				      hw->controlq_stats.sq_success_cnt);
	} else {
		average_ns = 0;
	}
	desc += sprintf(buf + desc, "\t sq_success_average: %ld\n", average_ns);

	if (hw->controlq_stats.sq_fail_ns && hw->controlq_stats.sq_fail_cnt) {
		average_ns = div64_ul(hw->controlq_stats.sq_fail_ns,
				      hw->controlq_stats.sq_fail_cnt);
	} else {
		average_ns = 0;
	}
	desc += sprintf(buf + desc, "\t sq_fail_average: %ld\n", average_ns);

	if (hw->controlq_stats.sq_fail_timeout_ns && hw->controlq_stats.sq_fail_timeout_cnt) {
		average_ns = div64_ul(hw->controlq_stats.sq_fail_timeout_ns,
				      hw->controlq_stats.sq_fail_timeout_cnt);
	} else {
		average_ns = 0;
	}
	desc += sprintf(buf + desc, "\t sq_fail_timeout_average: %ld\n", average_ns);

	desc += sprintf(buf + desc, "aq_cmd_shutdown_cnt: %ld\n",
		(unsigned long)hw->controlq_stats.aq_cmd_shutdown_cnt);

	desc += sprintf(buf + desc, "aq_cmd_shutdown_time: %ld\n",
		(unsigned long)hw->controlq_stats.aq_cmd_shutdown_time);

	desc += sprintf(buf + desc, "aq_sq_wait_for_fw_pause_disable_fail_cnt: %ld\n",
		(unsigned long)hw->controlq_stats.aq_sq_wait_for_fw_pause_disable_fail_cnt);
	desc += sprintf(buf + desc, "aq_sq_wait_for_fw_pause_disable_fail_time: %ld\n",
		(unsigned long)hw->controlq_stats.aq_sq_wait_for_fw_pause_disable_fail_time);

	desc += sprintf(buf + desc, "aq_sq_wait_for_sw_pause_fail_cnt: %ld\n",
		(unsigned long)hw->controlq_stats.aq_sq_wait_for_sw_pause_fail_cnt);
	desc += sprintf(buf + desc, "aq_sq_wait_for_sw_pause_fail_time: %ld\n",
		(unsigned long)hw->controlq_stats.aq_sq_wait_for_sw_pause_fail_time);

	desc += sprintf(buf + desc, "aq_sq_wait_for_sw_disable_fail_cnt: %ld\n",
		(unsigned long)hw->controlq_stats.aq_sq_wait_for_sw_disable_fail_cnt);
	desc += sprintf(buf + desc, "aq_sq_wait_for_sw_disable_fail_time: %ld\n",
		(unsigned long)hw->controlq_stats.aq_sq_wait_for_sw_disable_fail_time);

	desc += sprintf(buf + desc, "aq_rq_wait_for_fw_pause_disable_fail_cnt: %ld\n",
		(unsigned long)hw->controlq_stats.aq_rq_wait_for_fw_pause_disable_fail_cnt);
	desc += sprintf(buf + desc, "aq_rq_wait_for_fw_pause_disable_fail_time: %ld\n",
		(unsigned long)hw->controlq_stats.aq_rq_wait_for_fw_pause_disable_fail_time);

	desc += sprintf(buf + desc, "aq_rq_wait_for_sw_pause_fail_cnt: %ld\n",
		(unsigned long)hw->controlq_stats.aq_rq_wait_for_sw_pause_fail_cnt);
	desc += sprintf(buf + desc, "aq_rq_wait_for_sw_pause_fail_time: %ld\n",
		(unsigned long)hw->controlq_stats.aq_rq_wait_for_sw_pause_fail_time);

	desc += sprintf(buf + desc, "aq_rq_wait_for_sw_disable_fail_cnt: %ld\n",
		(unsigned long)hw->controlq_stats.aq_rq_wait_for_sw_disable_fail_cnt);
	desc += sprintf(buf + desc, "aq_rq_wait_for_sw_disable_fail_time: %ld\n",
		(unsigned long)hw->controlq_stats.aq_rq_wait_for_sw_disable_fail_time);

	desc += sprintf(buf + desc, "mq_cmd_shutdown_cnt: %ld\n",
		(unsigned long)hw->controlq_stats.mq_cmd_shutdown_cnt);

	desc += sprintf(buf + desc, "mq_cmd_shutdown_time: %ld\n",
		(unsigned long)hw->controlq_stats.mq_cmd_shutdown_time);

	desc += sprintf(buf + desc, "mq_sq_wait_for_fw_pause_disable_fail_cnt: %ld\n",
		(unsigned long)hw->controlq_stats.mq_sq_wait_for_fw_pause_disable_fail_cnt);
	desc += sprintf(buf + desc, "mq_sq_wait_for_fw_pause_disable_fail_time: %ld\n",
		(unsigned long)hw->controlq_stats.mq_sq_wait_for_fw_pause_disable_fail_time);

	desc += sprintf(buf + desc, "mq_sq_wait_for_sw_pause_fail_cnt: %ld\n",
		(unsigned long)hw->controlq_stats.mq_sq_wait_for_sw_pause_fail_cnt);
	desc += sprintf(buf + desc, "mq_sq_wait_for_sw_pause_fail_time: %ld\n",
		(unsigned long)hw->controlq_stats.mq_sq_wait_for_sw_pause_fail_time);

	desc += sprintf(buf + desc, "mq_sq_wait_for_sw_disable_fail_cnt: %ld\n",
		(unsigned long)hw->controlq_stats.mq_sq_wait_for_sw_disable_fail_cnt);
	desc += sprintf(buf + desc, "mq_sq_wait_for_sw_disable_fail_time: %ld\n",
		(unsigned long)hw->controlq_stats.mq_sq_wait_for_sw_disable_fail_time);

	desc += sprintf(buf + desc, "mq_rq_wait_for_fw_pause_disable_fail_cnt: %ld\n",
		(unsigned long)hw->controlq_stats.mq_rq_wait_for_fw_pause_disable_fail_cnt);
	desc += sprintf(buf + desc, "mq_rq_wait_for_fw_pause_disable_fail_time: %ld\n",
		(unsigned long)hw->controlq_stats.mq_rq_wait_for_fw_pause_disable_fail_time);

	desc += sprintf(buf + desc, "mq_rq_wait_for_sw_pause_fail_cnt: %ld\n",
		(unsigned long)hw->controlq_stats.mq_rq_wait_for_sw_pause_fail_cnt);
	desc += sprintf(buf + desc, "mq_rq_wait_for_sw_pause_fail_time: %ld\n",
		(unsigned long)hw->controlq_stats.mq_rq_wait_for_sw_pause_fail_time);

	desc += sprintf(buf + desc, "mq_rq_wait_for_sw_disable_fail_cnt: %ld\n",
		(unsigned long)hw->controlq_stats.mq_rq_wait_for_sw_disable_fail_cnt);
	desc += sprintf(buf + desc, "mq_rq_wait_for_sw_disable_fail_time: %ld\n",
		(unsigned long)hw->controlq_stats.mq_rq_wait_for_sw_disable_fail_time);

	desc += sprintf(buf + desc, "uq_sq_wait_for_sw_pause_fail_cnt: %ld\n",
		(unsigned long)hw->controlq_stats.uq_sq_wait_for_sw_pause_fail_cnt);
	desc += sprintf(buf + desc, "uq_sq_wait_for_sw_pause_fail_time: %ld\n",
		(unsigned long)hw->controlq_stats.uq_sq_wait_for_sw_pause_fail_time);

	desc += sprintf(buf + desc, "uq_sq_wait_for_sw_disable_fail_cnt: %ld\n",
		(unsigned long)hw->controlq_stats.uq_sq_wait_for_sw_disable_fail_cnt);
	desc += sprintf(buf + desc, "uq_sq_wait_for_sw_disable_fail_time: %ld\n",
		(unsigned long)hw->controlq_stats.uq_sq_wait_for_sw_disable_fail_time);

	ret = simple_read_from_buffer(to, count, ppos, buf, desc);

	kfree(buf);

	return ret;
}

static ssize_t
nse_debugfs_ctlq_stats_wfunc(struct file *filp, const char __user *buf,
			  size_t count, loff_t *ppos)
{
	struct nse_pf *pf = filp->private_data;
	struct nse_hw *hw = &pf->hw;
	struct device *dev = nse_pf_to_dev(pf);
	char *cmd_buf, *cmd_buf_tmp;
	ssize_t ret;
	char **argv;
	int argc;

	/* don't allow partial writes and writes when reset is in progress*/
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

	if (argc != 1)
		goto bad_usage;

	memset(&hw->controlq_stats, 0, sizeof(hw->controlq_stats));

	/* if we get here, nothing went wrong; return bytes copied */
	ret = (ssize_t)count;

command_write_done:
	argv_free(argv);
err_copy_from_user:
	kfree(cmd_buf);
	return ret;

bad_usage:
	dev_info(dev, "invalid input, usage: echo 'any words' > ctlq_stats to clear ctlq_stats\n");
	ret = -EINVAL;
	goto command_write_done;
}

static const struct file_operations nse_debugfs_ctlq_stats_fops = {
	.owner = THIS_MODULE,
	.open  = simple_open,
	.read = nse_debugfs_ctlq_stats_rfunc,
	.write = nse_debugfs_ctlq_stats_wfunc,
	.llseek = default_llseek,
};

static ssize_t
nse_debugfs_qos_db_dump_cfg_wfunc(struct file *filp, const char __user *buf,
			  size_t count, loff_t *ppos)
{
	struct nse_pf *pf = filp->private_data;
	struct nse_hw *hw = &pf->hw;
	struct device *dev = nse_pf_to_dev(pf);
	char *cmd_buf, *cmd_buf_tmp;
	ssize_t ret;
	char **argv;
	int argc;
	struct nse_aqc_qos_db_cfg *db_cfg = NULL;
	struct nse_aqc_qos_db_conf_up_enforcement *upe = NULL;
	enum nse_status status = NSE_SUCCESS;

	/* don't allow partial writes and writes when reset is in progress*/
	if (*ppos != 0 || nse_is_reset_in_progress(pf->state))
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

	if (argc != 1)
		goto bad_usage;

	db_cfg = kzalloc(sizeof(*db_cfg), GFP_KERNEL);
	upe = kzalloc(sizeof(*upe), GFP_KERNEL);
	if (!db_cfg || !upe) {
		ret = -ENOMEM;
		dev_info(dev, "[%s, %d] memory allocation fails\n",
						__func__, __LINE__);
		goto command_write_done;
	}

	status = nse_aq_qos_db_get_cfg(hw, db_cfg);
	if (status) {
		dev_info(dev, "nse_aq_qos_db_get_cfg(): fail, status = %d (%s)\n",
				(int)status, nse_stat_str(status));

	} else {
		nse_dump_dcbcfg_and_dbcfg(hw, &hw->port_info->qos_cfg.local_dcbx_cfg, db_cfg);

		if (nse_is_hw_static_fea_set(hw, NSE_HW_STATIC_FEA_TDM_SUPPORT_UP_ENFORCE)) {
			nse_dcbcfg_to_up_enforcement_registers(hw,
				&hw->port_info->qos_cfg.local_dcbx_cfg, upe);
			nse_dump_up_enforcement(hw, upe);
		}
	}

	/* if we get here, nothing went wrong; return bytes copied */
	ret = (ssize_t)count;

command_write_done:
	argv_free(argv);
err_copy_from_user:
	kfree(cmd_buf);

	kfree(db_cfg);

	kfree(upe);

	return ret;

bad_usage:
	dev_info(dev, "invalid input, usage: echo 'any words' > this debugfs file\n");
	ret = -EINVAL;
	goto command_write_done;
}

static const struct file_operations nse_debugfs_qos_db_dump_cfg_fops = {
	.owner = THIS_MODULE,
	.open  = simple_open,
	.write = nse_debugfs_qos_db_dump_cfg_wfunc,
	.llseek = default_llseek,
};

static ssize_t
nse_debugfs_qos_db_dump_stat_cnt_wfunc(struct file *filp, const char __user *buf,
			  size_t count, loff_t *ppos)
{
	struct nse_pf *pf = filp->private_data;
	struct nse_hw *hw = &pf->hw;
	struct device *dev = nse_pf_to_dev(pf);
	char *cmd_buf, *cmd_buf_tmp;
	ssize_t ret;
	char **argv;
	int argc;
	struct nse_aqc_qos_db_stat_cnt *db_stat_cnt = NULL;
	enum nse_status status = NSE_SUCCESS;

	/* don't allow partial writes and writes when reset is in progress*/
	if (*ppos != 0 || nse_is_reset_in_progress(pf->state))
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

	if (argc != 1)
		goto bad_usage;

	db_stat_cnt = kzalloc(sizeof(*db_stat_cnt), GFP_KERNEL);
	if (!db_stat_cnt) {
		ret = -ENOMEM;
		dev_info(dev, "[%s, %d] memory allocation fails\n",
						__func__, __LINE__);
		goto command_write_done;
	}

	status = nse_aq_qos_db_get_stat_cnt(hw, db_stat_cnt);
	if (status) {
		dev_info(dev, "nse_aq_qos_db_get_stat_cnt(): fail, status = %d (%s)\n",
				(int)status, nse_stat_str(status));
	} else {
		nse_qos_db_dump_stat_cnt(hw, db_stat_cnt);
	}

	/* if we get here, nothing went wrong; return bytes copied */
	ret = (ssize_t)count;

command_write_done:
	argv_free(argv);
err_copy_from_user:
	kfree(cmd_buf);

	kfree(db_stat_cnt);

	return ret;

bad_usage:
	dev_info(dev, "invalid input, usage: echo 'any words' > this debugfs file\n");
	ret = -EINVAL;
	goto command_write_done;
}

static const struct file_operations nse_debugfs_qos_db_dump_stat_cnt_fops = {
	.owner = THIS_MODULE,
	.open  = simple_open,
	.write = nse_debugfs_qos_db_dump_stat_cnt_wfunc,
	.llseek = default_llseek,
};

static ssize_t
nse_debugfs_info_basic_wfunc(struct file *filp, const char __user *buf,
			  size_t count, loff_t *ppos)
{
	struct nse_pf *pf = filp->private_data;
	struct nse_hw *hw = &pf->hw;
	struct device *dev = nse_pf_to_dev(pf);
	char *cmd_buf, *cmd_buf_tmp;
	ssize_t ret;
	char **argv;
	int argc;
	unsigned int i;

	/* don't allow partial writes and writes when reset is in progress*/
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

	if (argc != 1)
		goto bad_usage;

	dev_info(dev, "pf->flags:");
	for (i = 0; i < NSE_PF_FLAGS_NBITS; i++) {
		dev_info(dev, "\t %s (%d): %d\n",
						nse_pf_flag_str(i), i, test_bit(i, pf->flags));
	}

	dev_info(dev, "pf->state:\n");
	for (i = 0; i < NSE_STATE_NBITS; i++) {
		dev_info(dev, "\t %s (%d): %d\n",
						nse_pf_state_str(i), i, test_bit(i, pf->state));
	}

	dev_info(dev, "pf->misc_intr_run_cnt = %ld\n", pf->misc_intr_run_cnt);

	dev_info(dev, "pf->oicr_hi_int_cnt = %d\n", pf->oicr_hi_int_cnt);
	dev_info(dev, "pf->oicr_me_int_cnt = %d\n", pf->oicr_me_int_cnt);
	dev_info(dev, "pf->oicr_lo_int_cnt = %d\n", pf->oicr_lo_int_cnt);
	dev_info(dev, "pf->oicr_sw_int_cnt = %d\n", pf->oicr_sw_int_cnt);

	dev_info(dev, "pf->pf_reset_count = %d\n", pf->pf_reset_count);
	dev_info(dev, "\t pf->pfr_count = %d\n", pf->pfr_count);
	dev_info(dev, "\t pf->pflr_count = %d\n", pf->pflr_count);
	dev_info(dev, "pf->high_reset_count = %d\n", pf->high_reset_count);
	dev_info(dev, "pf->high_reset_oicr_swint_count = %d\n", pf->high_reset_oicr_swint_count);
	dev_info(dev, "pf->high_reset_oicr_corer_count = %d\n", pf->high_reset_oicr_corer_count);

	dev_info(dev, "pf->serv_tmr_run_cnt = %ld\n", pf->serv_tmr_run_cnt);
	dev_info(dev, "pf->serv_task_run_cnt = %ld\n", pf->serv_task_run_cnt);
	dev_info(dev, "pf->serv_task_resched_imm_cnt = %ld\n", pf->serv_task_resched_imm_cnt);
	dev_info(dev, "pf->serv_bh_run_cnt = %ld\n", pf->serv_bh_run_cnt);

	dev_info(dev, "pf->oicr_sw_int_tmp_poll_timer_run_cnt = %ld\n",
		 pf->oicr_sw_int_tmp_poll_timer_run_cnt);

	dev_info(dev, "jiffies = %ld (jiffies)\n", (unsigned long)jiffies);

	dev_info(dev, "pf->main_vsi_lan_qps_dflt = %d\n", pf->main_vsi_lan_qps_dflt);
	dev_info(dev, "pf->main_vsi_lan_rxqs_max = %d\n", pf->main_vsi_lan_rxqs_max);
	dev_info(dev, "pf->main_vsi_lan_txqs_max = %d\n", pf->main_vsi_lan_txqs_max);

	dev_info(dev, "hw->stag_ethertype = 0x%X\n", hw->stag_ethertype);

	dev_info(dev, "pf->misc_irq_idx = %d\n", pf->misc_irq_idx);

	dev_info(dev, "pf->msix_entries[] content:\n");
	for (i = 0; i < pf->irq_tracker_self_region->num_entries; i++) {
		dev_info(dev, "\t[%d]: CPU-irq-vector: %d\n",
						i, nse_get_irq_num(pf, i));
	}

	/* if we get here, nothing went wrong; return bytes copied */
	ret = (ssize_t)count;

command_write_done:
	argv_free(argv);
err_copy_from_user:
	kfree(cmd_buf);
	return ret;

bad_usage:
	dev_info(dev, "invalid input, usage: echo 'any words' > info_basic\n");
	ret = -EINVAL;
	goto command_write_done;
}

static const struct file_operations nse_debugfs_info_basic_fops = {
	.owner = THIS_MODULE,
	.open  = simple_open,
	.write = nse_debugfs_info_basic_wfunc,
	.llseek = default_llseek,
};

static void
nse_dump_resource_info(struct nse_pf *pf)
{
	struct device *dev = nse_pf_to_dev(pf);

	dev_info(dev, "=== PF resource info\n");

	dev_info(dev, "vsi_space_start=%d, vsi_space_size=%d\n",
		 pf->vsi_space_start, pf->vsi_space_size);
	dev_info(dev, "next_nonvf_vsi=%d, nonvf_vsi_region_size=%d\n",
		 pf->next_nonvf_vsi, pf->nonvf_vsi_region_size);

	dev_info(dev, "lan_rxq_space_start=%d, lan_rxq_space_size=%d\n",
		 pf->lan_rxq_space_start, pf->lan_rxq_space_size);
	dev_info(dev, "lan_txq_space_start=%d, lan_txq_space_size=%d\n",
		 pf->lan_txq_space_start, pf->lan_txq_space_size);
	dev_info(dev, "lan_txcq_space_valid=%d, lan_txcq_space_start=%d, lan_txcq_space_size=%d\n",
					pf->lan_txcq_space_valid, pf->lan_txcq_space_start,
						pf->lan_txcq_space_size);

	dev_info(dev, "rdma_qset_space_valid=%d, rdma_qset_space_start=%d, rdma_qset_space_size=%d\n",
					pf->rdma_qset_space_valid, pf->rdma_qset_space_start,
						pf->rdma_qset_space_size);

	dev_info(dev, "irq_space_start=%d, irq_space_size=%d\n",
					pf->irq_space_start, pf->irq_space_size);
}

static void
nse_dump_resource_misc(struct nse_pf *pf)
{
	struct device *dev = nse_pf_to_dev(pf);

	/* RSS LUT space */
	dev_info(dev, "=== RSS LUT space\n");
	dev_info(dev, "rss_lut_start=%d, rss_lut_size=%d\n",
					pf->rss_lut_start, pf->rss_lut_size);

	/* Maybe future tx-scheduler, FDir space */
}

static void
nse_dump_resource_sriov(struct nse_pf *pf)
{
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_vfs *vfs = &pf->vfs;

	dev_info(dev, "=== SRIOV resources\n");

	if (!pf->sriov_res_planned) {
		dev_info(dev, "SRIOV not enabled, SRIOV resource not planned\n");
		return;
	}

	dev_info(dev, "SRIOV enabled, SRIOV resource planned\n");

	dev_info(dev, "pf->sriov_base_vector=%d\n", pf->sriov_base_vector);

	dev_info(dev, "VF num_supported=%d\n", vfs->num_supported);
	dev_info(dev, "num_qps_per=%d\n", vfs->num_qps_per);
	dev_info(dev, "num_txcq_per=%d\n", vfs->num_txcq_per);
	dev_info(dev, "num_msix_per=%d\n", vfs->num_msix_per);
	dev_info(dev, "max_lan_msix_per=%d\n", vfs->max_lan_msix_per);
	dev_info(dev, "vf_vsialloc_firstvsi=%d\n", vfs->vf_vsialloc_firstvsi);
	dev_info(dev, "vf_rx_qbase_firstq=%d\n", vfs->vf_rx_qbase_firstq);
	dev_info(dev, "vf_rx_qbase_numq=%d (value - 1 actually set into HW)\n",
		 vfs->vf_rx_qbase_numq);
	dev_info(dev, "vf_tx_qbase_firstq=%d\n", vfs->vf_tx_qbase_firstq);
	dev_info(dev, "vf_tx_qbase_numq=%d (value - 1 actually set into HW)\n",
		 vfs->vf_tx_qbase_numq);
	dev_info(dev, "vfint_alloc_first=%d\n", vfs->vfint_alloc_first);
	dev_info(dev, "vfint_alloc_vecnum=%d (value - 1 actually set into HW)\n",
		 vfs->vfint_alloc_vecnum);
}

static void
nse_dump_resource_tracker(struct nse_pf *pf)
{
	struct device *dev = nse_pf_to_dev(pf);

	dev_info(dev, "=== various nse_res_tracker\n");

	/* the following dump does not acquire mutex of various nse_res_tracker,
	 *
	 * printf while holding mutext is not good. but hoping nobody would alloc or free when
	 * we are printf.
	 */
	dev_info(dev, "====== vsi_tracker:\n");
	nse_dump_res_tracker(pf, pf->vsi_tracker);

	dev_info(dev, "====== lan_rxq_tracker:\n");
	nse_dump_res_tracker(pf, pf->lan_rxq_tracker);

	dev_info(dev, "====== lan_txq_tracker:\n");
	nse_dump_res_tracker(pf, pf->lan_txq_tracker);

	if (pf->lan_txcq_tracker) {
		dev_info(dev, "====== lan_txcq_tracker:\n");
		nse_dump_res_tracker(pf, pf->lan_txcq_tracker);
	}

	dev_info(dev, "====== irq_tracker_self_region:\n");
	nse_dump_res_tracker(pf, pf->irq_tracker_self_region);

	dev_info(dev, "====== rss_lut_tracker:\n");
	nse_dump_res_tracker(pf, pf->rss_lut_tracker);
}

static ssize_t
nse_debugfs_info_resource_wfunc(struct file *filp, const char __user *buf,
			  size_t count, loff_t *ppos)
{
	struct nse_pf *pf = filp->private_data;
	struct nse_hw *hw = &pf->hw;
	struct device *dev = nse_pf_to_dev(pf);
	char *cmd_buf, *cmd_buf_tmp;
	ssize_t ret;
	char **argv;
	int argc;

	/* don't allow partial writes and writes when reset is in progress*/
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

	if (argc != 1)
		goto bad_usage;

	dev_info(dev, "=== func_caps (including VSI, RXQ, TXQ,IRQ, VF spaces)\n");
	nse_dump_caps(hw);	/* total resource in caps*/

	nse_dump_resource_info(pf);

	nse_dump_resource_misc(pf);

	nse_dump_resource_sriov(pf);

	nse_dump_resource_tracker(pf);

	/* if we get here, nothing went wrong; return bytes copied */
	ret = (ssize_t)count;

command_write_done:
	argv_free(argv);
err_copy_from_user:
	kfree(cmd_buf);
	return ret;

bad_usage:
	dev_info(dev, "invalid input, usage: echo 'any words' > resource\n");
	ret = -EINVAL;
	goto command_write_done;
}

static const struct file_operations nse_debugfs_info_resource_fops = {
	.owner = THIS_MODULE,
	.open  = simple_open,
	.write = nse_debugfs_info_resource_wfunc,
	.llseek = default_llseek,
};

static ssize_t
nse_debugfs_ptp_cur_time_wfunc(struct file *filp, const char __user *buf,
			  size_t count, loff_t *ppos)
{
	struct nse_pf *pf = filp->private_data;
	struct device *dev = nse_pf_to_dev(pf);
	char *cmd_buf, *cmd_buf_tmp;
	ssize_t ret;
	char **argv;
	int argc;
	unsigned int op;
	u64 cur_ts_ns;
	struct timespec64 ts_spec;
	u32 sec_part, sec_7b_part, nsec_part;
	enum nse_status status = NSE_SUCCESS;

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

	if (kstrtouint(argv[0], 10, &op))
		goto bad_usage;

	if (!test_bit(NSE_FLAG_PTP_SUPPORTED, pf->flags) || !test_bit(NSE_FLAG_PTP, pf->flags)) {
		dev_info(dev, "PTP not supported or init on this PF/port\n");
	} else {
		cur_ts_ns = ktime_get_real_ns();
		ts_spec = ns_to_timespec64(cur_ts_ns);
		sec_part = ts_spec.tv_sec;
		sec_7b_part = (sec_part & 0x7F);
		nsec_part = ts_spec.tv_nsec;

		dev_info(dev, "cur time (OS): ns: %ld (sec=%d(0x%08X), lowest_7b=%d(0x%08X), nsec=%d(0x%08X))\n",
						(unsigned long)cur_ts_ns,
						sec_part, sec_part,
						sec_7b_part, sec_7b_part,
						nsec_part, nsec_part);

		if (op == 0) {	/* Read current HW time */
			status = nse_ptp_read_src_clk_reg(pf, NULL, &sec_part,
							  &nsec_part, &cur_ts_ns);
			if (status) {
				dev_err(dev, "cur time (HW): FAIL: read PTP time from HW\n");
			} else {
				sec_7b_part = (sec_part & 0x7F);
				dev_info(dev, "cur time (HW): ns: %ld (sec=%d(0x%08X), lowest_7b=%d(0x%08X), nsec=%d(0x%08X))\n",
								(unsigned long)cur_ts_ns,
								sec_part, sec_part,
								sec_7b_part, sec_7b_part,
								nsec_part, nsec_part);
			}
		} else if (op == 1) {	/* Sync current OS time to HW */
			dev_info(dev, "sync OS time to HW\n");

			status = nse_aq_ptp_set_sys_time_by_sec_nsec(&pf->hw, (u32)ts_spec.tv_sec,
								     (u32)ts_spec.tv_nsec);
			if (status)
				dev_err(dev, "FAIL: sync OS time to MAC\n");
		} else if (op == 2) {	/* Adjust current HW time by 100 sec */
			if (pf->hw.mac_type == NSE_MAC_TYPE_AMBER)
				status = nse_aq_ptp_adj_sys_time_amber(&pf->hw, 100, 0);
			else if (pf->hw.mac_type == NSE_MAC_TYPE_MOONSTONE)
				status = nse_aq_ptp_adj_sys_time_ms(&pf->hw, 100, 0);

			if (status)
				dev_err(dev, "FAIL: adjust(+100 sec) to MAC\n");
		}
	}

	/* if we get here, nothing went wrong; return bytes copied */
	ret = (ssize_t)count;

command_write_done:
	argv_free(argv);
err_copy_from_user:
	kfree(cmd_buf);
	return ret;

bad_usage:
	dev_info(dev, "invalid input, usage: echo '[0|1]' > this file\n");
	ret = -EINVAL;
	goto command_write_done;
}

static const struct file_operations nse_debugfs_ptp_cur_time_fops = {
	.owner = THIS_MODULE,
	.open  = simple_open,
	.write = nse_debugfs_ptp_cur_time_wfunc,
	.llseek = default_llseek,
};

static ssize_t
nse_debugfs_ptp_info_wfunc(struct file *filp, const char __user *buf,
			  size_t count, loff_t *ppos)
{
	struct nse_pf *pf = filp->private_data;
	struct nse_hw *hw = &pf->hw;
	struct nse_ptp *ptp = &pf->ptp;
	struct device *dev = nse_pf_to_dev(pf);
	char *cmd_buf, *cmd_buf_tmp;
	ssize_t ret;
	char **argv;
	int argc;
	enum nse_status status;
	u32 val;

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

	if (!test_bit(NSE_FLAG_PTP_SUPPORTED, pf->flags) || !test_bit(NSE_FLAG_PTP, pf->flags)) {
		dev_info(dev, "PTP not supported or init on this PF/port\n");
	} else {
		dev_info(dev, "ptp_fine_mode=%d\n", pf->sw_conf.ptp_fine_mode);

		dev_info(dev, "ref_freq=%d\n", ptp->ref_freq);
		dev_info(dev, "ptp_freq=%d\n", ptp->ptp_freq);
		dev_info(dev, "dflt_fine_addend=%d (0x%X)\n",
			 ptp->dflt_fine_addend, ptp->dflt_fine_addend);

		dev_info(dev, "cached_phc_time=%ld ns\n", (unsigned long)ptp->cached_phc_time);
		dev_info(dev, "cached_phc_time_sec_part=%d\n", ptp->cached_phc_time_sec_part);
		dev_info(dev, "cached_phc_time_nsec_part=%d\n", ptp->cached_phc_time_nsec_part);

		dev_info(dev, "tstamp_config\n");
		dev_info(dev, "\t flags=%X\n", ptp->tstamp_config.flags);
		dev_info(dev, "\t tx_type=%X\n", ptp->tstamp_config.tx_type);
		dev_info(dev, "\t rx_filter=%X\n", ptp->tstamp_config.rx_filter);

		status = nse_aq_ptp_get_control(hw, &val);
		if (!status) {
			dev_info(dev, "HW reg: control=%X\n", val);
			/* NSE_AQC_PTP_CONTROL_TSENA */
			dev_info(dev, "\t TSENA=%d\n", val & 0x1);
			/* NSE_AQC_PTP_CONTROL_TSCFUPDT */
			dev_info(dev, "\t TSCFUPDT=%d\n", (val >> 1) & 0x1);
			/* NSE_AQC_PTP_CONTROL_TSENALL */
			dev_info(dev, "\t TSENALL=%d\n", (val >> 8) & 0x1);
			/* NSE_AQC_PTP_CONTROL_TSCTRLSSR */
			dev_info(dev, "\t TSCTRLSSR=%d\n", (val >> 9) & 0x1);
		}

		status = nse_aq_ptp_get_incval(hw, &val);
		if (status) {
			dev_info(dev, "HW reg: incval --- FAIL to get\n");
		} else {
			dev_info(dev, "HW reg: incval=%X\n", val);

			if (hw->mac_type == NSE_MAC_TYPE_AMBER) {
				dev_info(dev, "\t SSINC=%d\n", (val >> 16) & 0xFF);
				dev_info(dev, "\t SNSINC=%d\n", (val >> 8) & 0xFF);
			} else if (hw->mac_type == NSE_MAC_TYPE_MOONSTONE) {
				dev_info(dev, "\t INCPERIOD=0x%X\n", (val >> 24));
				dev_info(dev, "\t INCVALUE=0x%X\n", (val & 0xFFFFFF));
			}
		}

		status = nse_aq_ptp_get_addend(hw, &val);
		if (!status)
			dev_info(dev, "HW reg: addend=%X (dec: %d)\n", val, val);
	}

	/* if we get here, nothing went wrong; return bytes copied */
	ret = (ssize_t)count;

command_write_done:
	argv_free(argv);
err_copy_from_user:
	kfree(cmd_buf);
	return ret;

bad_usage:
	dev_info(dev, "invalid input, usage: echo anything > this file\n");
	ret = -EINVAL;
	goto command_write_done;
}

static const struct file_operations nse_debugfs_ptp_info_fops = {
	.owner = THIS_MODULE,
	.open  = simple_open,
	.write = nse_debugfs_ptp_info_wfunc,
	.llseek = default_llseek,
};

#if defined(NSE_DEBUG_EXT)

static void ptp_rx_dump_rx_ts(struct nse_pf *pf)
{
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_hw *hw = &pf->hw;
	struct nse_ptp *ptp = &pf->ptp;
	int i;
	u64 ts_ns;
	struct timespec64 ts_spec;
	u32 sec_part, sec_7b_part, nsec_part;
	enum nse_status status;

	if (!test_bit(NSE_FLAG_PTP_SUPPORTED, pf->flags) || !test_bit(NSE_FLAG_PTP, pf->flags)) {
		dev_info(dev, "PTP not supported or init on this PF/port\n");
	} else {
		if (!ptp->debug_rx_ts) {
			dev_info(dev, "ptp->debug_rx_ts not allocated ?\n");
		} else {
			ts_ns = ktime_get_real_ns();
			ts_spec = ns_to_timespec64(ts_ns);
			sec_part = ts_spec.tv_sec;
			sec_7b_part = (sec_part & 0x7F);
			nsec_part = ts_spec.tv_nsec;

			dev_info(dev, "cur time (OS): ns: %ld (sec=%d(0x%08X), sec_7b=%d(0x%08X), nsec=%d(0x%08X))\n",
						(unsigned long)(ts_ns),
						sec_part, sec_part,
						sec_7b_part, sec_7b_part,
						nsec_part, nsec_part);

			status = nse_ptp_read_src_clk_reg(pf, NULL, &sec_part, &nsec_part, &ts_ns);
			sec_7b_part = (sec_part & 0x7F);
			if (status)
				dev_info(dev, "cur time (HW): FAIL to read HW time\n");
			else
				dev_info(dev, "cur time (HW): ns: %ld (sec=%d(0x%08X), sec_7b=%d(0x%08X), nsec=%d(0x%08X))\n",
							(unsigned long)(ts_ns),
							sec_part, sec_part,
							sec_7b_part, sec_7b_part,
							nsec_part, nsec_part);

			dev_info(dev, "recent RX packet time:\n");

			for_each_online_cpu(i) {
				struct debug_rx_ts_s *debug_ts = per_cpu_ptr(ptp->debug_rx_ts, i);

				if (!debug_ts->desc_ns)
					continue;

				dev_info(dev, "\t CPU-%d\n", i);

				ts_spec = ns_to_timespec64(debug_ts->os_ns);
				sec_part = ts_spec.tv_sec;
				sec_7b_part = (sec_part & 0x7F);
				nsec_part = ts_spec.tv_nsec;
				dev_info(dev, "\t\t os_ns: ns: %ld (sec=%d(0x%08X), sec_7b=%d(0x%08X), nsec=%d(0x%08X))\n",
					 (unsigned long)(debug_ts->os_ns),
									sec_part, sec_part,
									sec_7b_part, sec_7b_part,
									nsec_part, nsec_part);

				ts_spec = ns_to_timespec64(debug_ts->desc_ns);
				sec_part = ts_spec.tv_sec;
				sec_7b_part = (sec_part & 0x7F);
				nsec_part = ts_spec.tv_nsec;
				dev_info(dev, "\t\t desc_ns: %ld (sec=%d(0x%08X), sec_7b=%d(0x%08X), nsec=%d(0x%08X))\n",
					 (unsigned long)(debug_ts->desc_ns),
									sec_part, sec_part,
									sec_7b_part, sec_7b_part,
									nsec_part, nsec_part);

				dev_info(dev, "\t\t\t desc_md4=%d(0x%04X), desc_md5=%d(0x%04X), desc_ts_high(md4, md5)=%d(0x%08X)\n",
									debug_ts->desc_md4,
										debug_ts->desc_md4,
									debug_ts->desc_md5,
										debug_ts->desc_md5,
					 debug_ts->desc_ts_high, debug_ts->desc_ts_high);

				dev_info(dev, "\t\t\t desc_ts_low=%d(0x%02X), desc_ts_low_7b_part=%d(0x%02X)\n",
					 debug_ts->desc_ts_low, debug_ts->desc_ts_low,
					 (debug_ts->desc_ts_low >>
					  1), (debug_ts->desc_ts_low >> 1));

				if (hw->mac_type == NSE_MAC_TYPE_AMBER)
					dev_info(dev, "\t\t\t desc_7b_sec=%d(0x%08X), desc_32b_nsec=%d(0x%08X)\n\n",
						 debug_ts->amber.desc_7b_sec_part,
							 debug_ts->amber.desc_7b_sec_part,
						 debug_ts->amber.desc_nsec_part,
							 debug_ts->amber.desc_nsec_part);
				else if (hw->mac_type == NSE_MAC_TYPE_MOONSTONE)
					dev_info(dev, "\t\t\t desc_h_32b_part=%d(0x%08X), desc_l_7b_part=%d(0x%08X)\n\n",
						 debug_ts->ms.desc_h_32b_part,
							 debug_ts->ms.desc_h_32b_part,
						 debug_ts->ms.desc_l_7b_part,
							 debug_ts->ms.desc_l_7b_part);

				nse_dump_rx_desc(dev, -1, -1, &debug_ts->saved_desc);
			}
		}
	}
}
#endif

static ssize_t
nse_debugfs_ptp_rx_wfunc(struct file *filp, const char __user *buf,
			  size_t count, loff_t *ppos)
{
	struct nse_pf *pf = filp->private_data;
	struct device *dev = nse_pf_to_dev(pf);
	char *cmd_buf, *cmd_buf_tmp;
	ssize_t ret;
	char **argv;
	int argc;
	unsigned int new_val;

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

	if (kstrtouint(argv[0], 10, &new_val))
		goto bad_usage;

	if (!test_bit(NSE_FLAG_PTP_SUPPORTED, pf->flags) || !test_bit(NSE_FLAG_PTP, pf->flags)) {
		dev_info(dev, "PTP not supported or init on this PF/port\n");
	} else {
		if (!new_val)
			nse_set_rx_tstamp(pf, false);
		else if (new_val == 1)
			nse_set_rx_tstamp(pf, true);
#if defined(NSE_DEBUG_EXT)
		else
			ptp_rx_dump_rx_ts(pf);
#endif
	}

	/* if we get here, nothing went wrong; return bytes copied */
	ret = (ssize_t)count;

command_write_done:
	argv_free(argv);
err_copy_from_user:
	kfree(cmd_buf);
	return ret;

bad_usage:
	dev_info(dev, "invalid input, usage: echo '[0|1]' > this file\n");
	ret = -EINVAL;
	goto command_write_done;
}

static const struct file_operations nse_debugfs_ptp_rx_fops = {
	.owner = THIS_MODULE,
	.open  = simple_open,
	.write = nse_debugfs_ptp_rx_wfunc,
	.llseek = default_llseek,
};

static void hack_send_magic_pkt(struct net_device *dev, unsigned int pkt_size, bool tx_ptp);

static ssize_t
nse_debugfs_ptp_tx_wfunc(struct file *filp, const char __user *buf,
			  size_t count, loff_t *ppos)
{
	struct nse_pf *pf = filp->private_data;
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_vsi *vsi;
	struct net_device *netdev;
	char *cmd_buf, *cmd_buf_tmp;
	ssize_t ret;
	char **argv;
	int argc;
	unsigned int new_val;

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

	if (kstrtouint(argv[0], 10, &new_val))
		goto bad_usage;

	if (!test_bit(NSE_FLAG_PTP_SUPPORTED, pf->flags) || !test_bit(NSE_FLAG_PTP, pf->flags)) {
		dev_info(dev, "PTP not supported or init on this PF/port\n");
	} else {
		if (new_val == 0)
			nse_set_tx_tstamp(pf, false);
		else if (new_val == 1)
			nse_set_tx_tstamp(pf, true);
		else {
			vsi = nse_get_main_vsi(pf);
			if (vsi) {
				netdev = vsi->netdev;

				if (netif_carrier_ok(netdev)) {
					while (--new_val)
						hack_send_magic_pkt(netdev, 256, true);
				}
			}
		}
	}

	/* if we get here, nothing went wrong; return bytes copied */
	ret = (ssize_t)count;

command_write_done:
	argv_free(argv);
err_copy_from_user:
	kfree(cmd_buf);
	return ret;

bad_usage:
	dev_info(dev, "invalid input, usage: echo '[0|1|N for send TX packet]' > this file\n");
	ret = -EINVAL;
	goto command_write_done;
}

static const struct file_operations nse_debugfs_ptp_tx_fops = {
	.owner = THIS_MODULE,
	.open  = simple_open,
	.write = nse_debugfs_ptp_tx_wfunc,
	.llseek = default_llseek,
};

static ssize_t
nse_debugfs_test_phy_startup_wfunc(struct file *filp, const char __user *buf,
			  size_t count, loff_t *ppos)
{
	struct nse_pf *pf = filp->private_data;
	struct nse_hw *hw = &pf->hw;
	struct nse_lmac_phy_info *lpinfo = &hw->port_info->lmac_phy_info;
	struct device *dev = nse_pf_to_dev(pf);
	char *cmd_buf, *cmd_buf_tmp;
	ssize_t ret;
	char **argv;
	int argc;

	/* don't allow partial writes and writes when reset is in progress*/
	if (*ppos != 0 || nse_is_reset_in_progress(pf->state))
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

	nse_lmac_phy_lock(hw);

	nse_lmac_phy_ephy_reset_info(hw);

	/* replace calling nse_aq_test_phy_startup() directly, let subtask call it */
	/* this flag is set for test flow */
	lpinfo->dyn_flags |= (LMAC_PHY_DYN_FLAG_NEED_FIRST_FORCE_NOTIFY_LINK_DOWN |
							LMAC_PHY_DYN_FLAG_NEED_UPDATE_EPHY_STATUS |
							LMAC_PHY_DYN_FLAG_NEED_START_LINK_OR_AN |
							LMAC_PHY_DYN_FLAG_NEED_UPDATE_LINK_INFO);

	nse_lmac_phy_unlock(hw);

	/* if we get here, nothing went wrong; return bytes copied */
	ret = (ssize_t)count;

command_write_done:
	argv_free(argv);
err_copy_from_user:
	kfree(cmd_buf);
	return ret;

bad_usage:
	dev_info(dev, "invalid input, usage: echo 'anything' > test_phy_startup\n");
	ret = -EINVAL;
	goto command_write_done;
}

static const struct file_operations nse_debugfs_test_phy_startup_fops = {
	.owner = THIS_MODULE,
	.open  = simple_open,
	.write = nse_debugfs_test_phy_startup_wfunc,
	.llseek = default_llseek,
};

static ssize_t
nse_debugfs_test_phy_get_link_status_wfunc(struct file *filp, const char __user *buf,
			  size_t count, loff_t *ppos)
{
	struct nse_pf *pf = filp->private_data;
	struct nse_hw *hw = &pf->hw;
	struct device *dev = nse_pf_to_dev(pf);
	enum nse_status status;
	u32 ls, speed;
	char *cmd_buf, *cmd_buf_tmp;
	ssize_t ret;
	char **argv;
	int argc;

	/* don't allow partial writes and writes when reset is in progress*/
	if (*ppos != 0 || nse_is_reset_in_progress(pf->state))
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

	status = nse_aq_test_phy_get_link_status(hw, &ls, &speed);
	if (!status) {
		dev_info(dev, "calling aq_test_phy_get_link_status() success, link=%s, speed=%d\n",
						ls ? "UP" : "DOWN", speed);

		dev_info(dev, "if link=UP, now you can echo 1 > netif_carrier\n");
		dev_info(dev, "if link=DOWN, you can echo 0 > netif_carrier\n");
	} else {
		dev_info(dev, "calling aq_test_phy_get_link_status() fails, %d(%s)\n",
					status, nse_stat_str(status));
	}

	/* if we get here, nothing went wrong; return bytes copied */
	ret = (ssize_t)count;

command_write_done:
	argv_free(argv);
err_copy_from_user:
	kfree(cmd_buf);
	return ret;

bad_usage:
	dev_info(dev, "invalid input, usage: echo 'anything' > test_phy_get_link_status\n");
	ret = -EINVAL;
	goto command_write_done;
}

static const struct file_operations nse_debugfs_test_phy_get_link_status_fops = {
	.owner = THIS_MODULE,
	.open  = simple_open,
	.write = nse_debugfs_test_phy_get_link_status_wfunc,
	.llseek = default_llseek,
};

static ssize_t
nse_debugfs_test_phy_set_loopback_wfunc(struct file *filp, const char __user *buf,
			  size_t count, loff_t *ppos)
{
	struct nse_pf *pf = filp->private_data;
	struct nse_hw *hw = &pf->hw;
	struct device *dev = nse_pf_to_dev(pf);
	enum nse_status status;
	char *cmd_buf, *cmd_buf_tmp;
	ssize_t ret;
	char **argv;
	int argc;
	u32 on_or_off;

	/* don't allow partial writes and writes when reset is in progress*/
	if (*ppos != 0 || nse_is_reset_in_progress(pf->state))
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

	if (kstrtouint(argv[0], 10, &on_or_off))
		goto bad_usage;

	status = nse_aq_test_phy_set_loopback(hw, on_or_off);
	if (!status) {
		dev_info(dev, "calling nse_aq_test_phy_set_loopback(%d) success\n",
					on_or_off);
	} else {
		dev_info(dev, "calling nse_aq_test_phy_set_loopback(%d) fails, %d(%s)\n",
					on_or_off, status, nse_stat_str(status));
	}

	/* if we get here, nothing went wrong; return bytes copied */
	ret = (ssize_t)count;

command_write_done:
	argv_free(argv);
err_copy_from_user:
	kfree(cmd_buf);
	return ret;

bad_usage:
	dev_info(dev, "invalid input, usage: echo '1|0' > netif_carrier\n");
	ret = -EINVAL;
	goto command_write_done;
}

static const struct file_operations nse_debugfs_test_phy_set_loopback_fops = {
	.owner = THIS_MODULE,
	.open  = simple_open,
	.write = nse_debugfs_test_phy_set_loopback_wfunc,
	.llseek = default_llseek,
};

static ssize_t
nse_debugfs_lmac_phy_update_link_info_wfunc(struct file *filp, const char __user *buf,
			  size_t count, loff_t *ppos)
{
	struct nse_pf *pf = filp->private_data;
	struct nse_hw *hw = &pf->hw;
	struct device *dev = nse_pf_to_dev(pf);
	char *cmd_buf, *cmd_buf_tmp;
	ssize_t ret;
	char **argv;
	int argc;

	/* don't allow partial writes and writes when reset is in progress*/
	if (*ppos != 0 || nse_is_reset_in_progress(pf->state))
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

	nse_lmac_phy_lock(hw);

	hw->port_info->lmac_phy_info.dyn_flags |= LMAC_PHY_DYN_FLAG_NEED_UPDATE_LINK_INFO;

	nse_lmac_phy_unlock(hw);

	/* if we get here, nothing went wrong; return bytes copied */
	ret = (ssize_t)count;

command_write_done:
	argv_free(argv);
err_copy_from_user:
	kfree(cmd_buf);
	return ret;

bad_usage:
	dev_info(dev, "invalid input, usage: echo 'anything' > this file\n");
	ret = -EINVAL;
	goto command_write_done;
}

static const struct file_operations nse_debugfs_lmac_phy_update_link_info_fops = {
	.owner = THIS_MODULE,
	.open  = simple_open,
	.write = nse_debugfs_lmac_phy_update_link_info_wfunc,
	.llseek = default_llseek,
};

static ssize_t nse_debugfs_oicr_ena_rfunc(struct file *filp,
				 char __user *to, size_t count, loff_t *ppos)
{
	struct nse_pf *pf = filp->private_data;
	struct nse_hw *hw = &pf->hw;
	char *buf = NULL;
	int desc = 0;
	int ret;
	u32 val32;

	buf = kzalloc(4096, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	val32 = pf->oicr_ena;

	desc += sprintf(buf + desc, "val32: %X\n",
				val32);

	desc += sprintf(buf + desc, "    CORE_RESET (bit: %d): %d\n",
				NSE_REG_OICR_CORE_RESET_S,
				(val32 & NSE_REG_OICR_CORE_RESET_M) ? 1 : 0);

	desc += sprintf(buf + desc, "    OVERHEAT (bit: %d): %d\n",
				NSE_REG_OICR_OVERHEAT_S,
				(val32 & NSE_REG_OICR_OVERHEAT_M) ? 1 : 0);

	desc += sprintf(buf + desc, "    SPI (bit: %d): %d\n",
				NSE_REG_OICR_SPI_S,
				(val32 & NSE_REG_OICR_SPI_M) ? 1 : 0);

	desc += sprintf(buf + desc, "    REG_TIMEOUT (bit: %d): %d\n",
				NSE_REG_OICR_REG_TIMEOUT_S,
				(val32 & NSE_REG_OICR_REG_TIMEOUT_M) ? 1 : 0);

	desc += sprintf(buf + desc, "    HI_INT (bit: %d): %d\n",
				NSE_REG_OICR_HI_INT_S,
				(val32 & NSE_REG_OICR_HI_INT_M) ? 1 : 0);

	desc += sprintf(buf + desc, "    ME_INT (bit: %d): %d\n",
				NSE_REG_OICR_ME_INT_S,
				(val32 & NSE_REG_OICR_ME_INT_M) ? 1 : 0);

	desc += sprintf(buf + desc, "    LO_INT (bit: %d): %d\n",
				NSE_REG_OICR_LO_INT_S,
				(val32 & NSE_REG_OICR_LO_INT_M) ? 1 : 0);

	desc += sprintf(buf + desc, "    INT_FLUSH_DN (bit: %d): %d\n",
				NSE_REG_OICR_INT_FLUSH_DN_S,
				(val32 & NSE_REG_OICR_INT_FLUSH_DN_M) ? 1 : 0);

	desc += sprintf(buf + desc, "    PCORE_EVENT (bit: %d): %d\n",
				NSE_REG_OICR_PCORE_EVENT_S,
				(val32 & NSE_REG_OICR_PCORE_EVENT_M) ? 1 : 0);

	desc += sprintf(buf + desc, "    TCP_TIMER (bit: %d): %d\n",
				NSE_REG_OICR_TCP_TIMER_S,
				(val32 & NSE_REG_OICR_TCP_TIMER_M) ? 1 : 0);

	desc += sprintf(buf + desc, "    SWINT (bit: %d): %d\n",
				NSE_REG_OICR_SWINT_S,
				(val32 & NSE_REG_OICR_SWINT_M) ? 1 : 0);

	desc += sprintf(buf + desc, "    PAUSE_DN (bit: %d): %d\n",
				NSE_REG_OICR_PAUSE_DN_S,
				(val32 & NSE_REG_OICR_PAUSE_DN_M) ? 1 : 0);

	desc += sprintf(buf + desc, "    RPB_B_RX_MISS (bit: %d): %d\n",
				NSE_REG_OICR_RPB_B_RX_MISS_S,
				(val32 & NSE_REG_OICR_RPB_B_RX_MISS_M) ? 1 : 0);

	desc += sprintf(buf + desc, "    RPB_A_RX_MISS (bit: %d): %d\n",
				NSE_REG_OICR_RPB_A_RX_MISS_S,
				(val32 & NSE_REG_OICR_RPB_A_RX_MISS_M) ? 1 : 0);

	desc += sprintf(buf + desc, "    ETH_PCS_B (bit: %d): %d\n",
				NSE_REG_OICR_ETH_PCS_B_S,
				(val32 & NSE_REG_OICR_ETH_PCS_B_M) ? 1 : 0);

	desc += sprintf(buf + desc, "    ETH_PCS_A (bit: %d): %d\n",
				NSE_REG_OICR_ETH_PCS_A_S,
				(val32 & NSE_REG_OICR_ETH_PCS_A_M) ? 1 : 0);

	desc += sprintf(buf + desc, "    MNG_WDT (bit: %d): %d\n",
				NSE_REG_OICR_MNG_WDT_S,
				(val32 & NSE_REG_OICR_MNG_WDT_M) ? 1 : 0);

	desc += sprintf(buf + desc, "    PFC_DEADLOCK (bit: %d): %d\n",
				NSE_REG_OICR_PFC_DEADLOCK_S,
				(val32 & NSE_REG_OICR_PFC_DEADLOCK_M) ? 1 : 0);

	desc += sprintf(buf + desc, "    ETH_PHY_EVENT (bit: %d): %d\n",
				NSE_REG_OICR_ETH_PHY_EVENT_S,
				(val32 & NSE_REG_OICR_ETH_PHY_EVENT_M) ? 1 : 0);

	desc += sprintf(buf + desc, "    ETH_MAC_B_EVENT (bit: %d): %d\n",
				NSE_REG_OICR_ETH_MAC_B_EVENT_S,
				(val32 & NSE_REG_OICR_ETH_MAC_B_EVENT_M) ? 1 : 0);

	desc += sprintf(buf + desc, "    ETH_MAC_A (bit: %d): %d\n",
				NSE_REG_OICR_ETH_MAC_A_EVENT_S,
				(val32 & NSE_REG_OICR_ETH_MAC_A_EVENT_M) ? 1 : 0);

	desc += sprintf(buf + desc, "    TSC_REKEY (bit: %d): %d\n",
				NSE_REG_OICR_TSC_REKEY_S,
				(val32 & NSE_REG_OICR_TSC_REKEY_M) ? 1 : 0);

	desc += sprintf(buf + desc, "    FDIR (bit: %d): %d\n",
				NSE_REG_OICR_FDIR_S,
				(val32 & NSE_REG_OICR_FDIR_M) ? 1 : 0);

	desc += sprintf(buf + desc, "    TC_MRK (bit: %d): %d\n",
				NSE_REG_OICR_TC_MRK_S,
				(val32 & NSE_REG_OICR_TC_MRK_M) ? 1 : 0);

	desc += sprintf(buf + desc, "    STORM_DETECT (bit: %d): %d\n",
				NSE_REG_OICR_STORM_DETECT_S,
				(val32 & NSE_REG_OICR_STORM_DETECT_M) ? 1 : 0);

	desc += sprintf(buf + desc, "    WAKE (bit: %d): %d\n",
				NSE_REG_OICR_WAKE_S,
				(val32 & NSE_REG_OICR_WAKE_M) ? 1 : 0);

	desc += sprintf(buf + desc, "    HMC_ERR (bit: %d): %d\n",
				NSE_REG_OICR_HMC_ERR_S,
				(val32 & NSE_REG_OICR_HMC_ERR_M) ? 1 : 0);

	desc += sprintf(buf + desc, "    PEC_WDT (bit: %d): %d\n",
				NSE_REG_OICR_PEC_WDT_S,
				(val32 & NSE_REG_OICR_PEC_WDT_M) ? 1 : 0);

	desc += sprintf(buf + desc, "    QUEUE_TIMEOUT (bit: %d): %d\n",
				NSE_REG_OICR_QUEUE_TIMEOUT_S,
				(val32 & NSE_REG_OICR_QUEUE_TIMEOUT_M) ? 1 : 0);

	desc += sprintf(buf + desc, "    MAL_DETECT (bit: %d): %d\n",
				NSE_REG_OICR_MAL_DETECT_S,
				(val32 & NSE_REG_OICR_MAL_DETECT_M) ? 1 : 0);

	desc += sprintf(buf + desc, "    QUEUE (bit: %d): %d\n",
				NSE_REG_OICR_QUEUE_S,
				(val32 & NSE_REG_OICR_QUEUE_M) ? 1 : 0);

	val32 = rd32(hw, NSE_REG_OICR_ENA);
	desc += sprintf(buf + desc, "register: OICR_ENA = %X\n", val32);
	if (val32 != pf->oicr_ena) {
		desc += sprintf(buf + desc,
				"!!! HOW come register: OICR_ENA not equal to pf->oicr_ena: %X\n",
								pf->oicr_ena);
	}

	ret = simple_read_from_buffer(to, count, ppos, buf, desc);

	kfree(buf);

	return ret;
}

static ssize_t
nse_debugfs_oicr_ena_wfunc(struct file *filp, const char __user *buf,
			  size_t count, loff_t *ppos)
{
	struct nse_pf *pf = filp->private_data;
	struct nse_hw *hw = &pf->hw;
	struct device *dev = nse_pf_to_dev(pf);
	char *cmd_buf, *cmd_buf_tmp;
	ssize_t ret;
	char **argv;
	int argc;
	unsigned int change_bit;
	bool set;

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

	if (argc != 2)
		goto bad_usage;

	if (kstrtouint(argv[1], 10, &change_bit))
		goto bad_usage;

	if (change_bit > 31)
		goto bad_usage;

	if (!strcmp(argv[0], "+"))
		set = true;
	else if (!strcmp(argv[0], "-"))
		set = false;
	else
		goto bad_usage;

	if (set)
		pf->oicr_ena |= BIT(change_bit);
	else
		pf->oicr_ena &= ~(BIT(change_bit));

	wr32(hw, NSE_REG_OICR_ENA, pf->oicr_ena);
	wr32(hw, NSE_REG_OICR_MASK, ~(pf->oicr_ena));	/* unmask all ENA, mask !ENA */
	nse_irq_dynamic_ena(hw, NULL, NULL);

	/* if we get here, nothing went wrong; return bytes copied */
	ret = (ssize_t)count;

command_write_done:
	argv_free(argv);
err_copy_from_user:
	kfree(cmd_buf);
	return ret;

bad_usage:
	dev_info(dev, "invalid input, usage: echo +|- bit number\n");
	ret = -EINVAL;
	goto command_write_done;
}

static const struct file_operations nse_debugfs_oicr_ena_fops = {
	.owner = THIS_MODULE,
	.open  = simple_open,
	.read = nse_debugfs_oicr_ena_rfunc,
	.write = nse_debugfs_oicr_ena_wfunc,
	.llseek = default_llseek,
};

static ssize_t
nse_debugfs_stats_lmac_wfunc(struct file *filp, const char __user *buf,
			  size_t count, loff_t *ppos)
{
	struct nse_pf *pf = filp->private_data;
	struct nse_hw *hw = &pf->hw;
	char *cmd_buf, *cmd_buf_tmp;
	ssize_t ret;
	char **argv;
	int argc;
	struct nse_aqc_lmac_stats *stats = NULL;
	enum nse_status status;

	/* don't allow partial writes and writes when reset is in progress*/
	if (*ppos != 0 || nse_is_reset_in_progress(pf->state))
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

	stats = kmalloc(sizeof(*stats), GFP_KERNEL);
	if (!stats) {
		ret = -ENOMEM;
		goto command_write_done;
	}

	status = nse_aq_lmac_read_stats(hw, stats);
	if (status) {
		dev_info(nse_pf_to_dev(pf), "[%s, %d] aq_lmac_read_stats() fails, %d(%s)\n",
				__func__, __LINE__,
				status, nse_stat_str(status));
	} else {
		nse_lmac_dump_stats(hw, stats);
	}

	/* if we get here, nothing went wrong; return bytes copied */
	ret = (ssize_t)count;

command_write_done:
	argv_free(argv);
err_copy_from_user:
	kfree(cmd_buf);

	kfree(stats);

	return ret;

bad_usage:
	dev_info(nse_pf_to_dev(pf), "invalid input, usage: echo 'anything' > stats_lmac\n");
	ret = -EINVAL;
	goto command_write_done;
}

static const struct file_operations nse_debugfs_stats_lmac_fops = {
	.owner = THIS_MODULE,
	.open  = simple_open,
	.write = nse_debugfs_stats_lmac_wfunc,
	.llseek = default_llseek,
};

static ssize_t
nse_debugfs_stats_lan_channel_wfunc(struct file *filp, const char __user *buf,
			  size_t count, loff_t *ppos)
{
	struct nse_pf *pf = filp->private_data;
	struct nse_hw *hw = &pf->hw;
	char *cmd_buf, *cmd_buf_tmp;
	ssize_t ret;
	char **argv;
	int argc;
	struct nse_aqc_rc_dma_chan_total_stats *stats = NULL;
	enum nse_status status;

	/* don't allow partial writes and writes when reset is in progress*/
	if (*ppos != 0 || nse_is_reset_in_progress(pf->state))
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

	stats = kmalloc(sizeof(*stats), GFP_KERNEL);
	if (!stats) {
		ret = -ENOMEM;
		goto command_write_done;
	}

	status = nse_read_dma_chan_total_stats(hw, stats);
	if (status) {
		dev_info(nse_pf_to_dev(pf), "[%s, %d] nse_read_lan_channel_total_stats() fails, %d(%s)\n",
				__func__, __LINE__,
				status, nse_stat_str(status));
	} else {
		nse_dump_dma_chan_total_stats(hw, stats);
	}

	/* if we get here, nothing went wrong; return bytes copied */
	ret = (ssize_t)count;

command_write_done:
	argv_free(argv);
err_copy_from_user:
	kfree(cmd_buf);

	kfree(stats);

	return ret;

bad_usage:
	dev_info(nse_pf_to_dev(pf), "invalid input, usage: echo 'anything' > stats_lan_channel\n");
	ret = -EINVAL;
	goto command_write_done;
}

static const struct file_operations nse_debugfs_stats_lan_channel_fops = {
	.owner = THIS_MODULE,
	.open  = simple_open,
	.write = nse_debugfs_stats_lan_channel_wfunc,
	.llseek = default_llseek,
};

static ssize_t
nse_debugfs_stats_pf_wfunc(struct file *filp, const char __user *buf,
			  size_t count, loff_t *ppos)
{
	struct nse_pf *pf = filp->private_data;
	char *cmd_buf, *cmd_buf_tmp;
	ssize_t ret;
	char **argv;
	int argc;

	/* don't allow partial writes and writes when reset is in progress*/
	if (*ppos != 0 || nse_is_reset_in_progress(pf->state))
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

	nse_update_pf_stats(pf);

	nse_dump_pf_stats(pf, &pf->stats);

	/* if we get here, nothing went wrong; return bytes copied */
	ret = (ssize_t)count;

command_write_done:
	argv_free(argv);
err_copy_from_user:
	kfree(cmd_buf);

	return ret;

bad_usage:
	dev_info(nse_pf_to_dev(pf), "invalid input, usage: echo 'anything' > stats_lan_channel\n");
	ret = -EINVAL;
	goto command_write_done;
}

static const struct file_operations nse_debugfs_stats_pf_fops = {
	.owner = THIS_MODULE,
	.open  = simple_open,
	.write = nse_debugfs_stats_pf_wfunc,
	.llseek = default_llseek,
};

static ssize_t
nse_debugfs_psr_set_ctrl_wfunc(struct file *filp, const char __user *buf,
			  size_t count, loff_t *ppos)
{
	struct nse_pf *pf = filp->private_data;
	struct nse_hw *hw = &pf->hw;
	char *cmd_buf, *cmd_buf_tmp;
	ssize_t ret;
	char **argv;
	int argc;
	struct nse_aqc_psr_set_ctrl psr_cmd_buf;
	unsigned int val;
	enum nse_status status;

	/* don't allow partial writes and writes when reset is in progress*/
	if (*ppos != 0 || nse_is_reset_in_progress(pf->state))
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

	if (kstrtouint(argv[1], 10, &val))
		goto bad_usage;

	memset(&psr_cmd_buf, 0, sizeof(psr_cmd_buf));

	psr_cmd_buf.flags = cpu_to_le32(NSE_AQC_PSR_SET_CTRL_FLAG_RPSR |
					NSE_AQC_PSR_SET_CTRL_FLAG_TPSR);
	psr_cmd_buf.dis_or_en = !!val;

	if (!strcmp(argv[0], "vxlan")) {
		//if dis = false, then need specify a UDP port number
		if (!psr_cmd_buf.dis_or_en) {
			if (argc < 3)
				goto bad_usage;

			if (kstrtouint(argv[2], 10, &val))
				goto bad_usage;

			psr_cmd_buf.port_or_etype = cpu_to_le16((u16)val);
		}

		psr_cmd_buf.ctrl_type = NSE_AQC_PSR_CTRL_TYPE_VXLAN_UDP;

		status = nse_aq_psr_set_ctrl(hw, &psr_cmd_buf);
		if (status)
			nse_printk("fail to set parser: vxlan_udp_ctrl, status = %d\n", status);

		psr_cmd_buf.ctrl_type = NSE_AQC_PSR_CTRL_TYPE_VXLAN_GPE_UDP;

		status = nse_aq_psr_set_ctrl(hw, &psr_cmd_buf);
		if (status)
			nse_printk("fail to set parser: gpe_udp_ctrl, status = %d\n", status);
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
	dev_info(nse_pf_to_dev(pf), "invalid input, usage:\n");
	dev_info(nse_pf_to_dev(pf), "    echo 'vxlan dis[0|1] port[#] > this file':\n");
	ret = -EINVAL;
	goto command_write_done;
}

static const struct file_operations nse_debugfs_psr_set_ctrl_fops = {
	.owner = THIS_MODULE,
	.open  = simple_open,
	.write = nse_debugfs_psr_set_ctrl_wfunc,
	.llseek = default_llseek,
};

void nse_debugfs_ovs_dump_encap_entry(struct nse_hw *hw)
{
	struct nse_sw_encap_entry *encap_entry = NULL;
	struct list_head *list_head = &hw->switch_info->encap_list_head;
	struct list_head *fltr_head = NULL;
	struct nse_sw_encap_item *encap_item = NULL;
	struct nse_tc_flower_fltr *fltr;
	u32 i, data = 0, index = 0;

	if (list_empty(list_head)) {
		dev_info(nse_hw_to_dev(hw), "There is no encap entry!\n");
		return;
	}

	mutex_lock(&hw->switch_info->encap_tbl_lock);
	list_for_each_entry(encap_entry, list_head, list_entry) {
		u32 fltr_idx = 0;

		dev_info(nse_hw_to_dev(hw),
			"encap_entry[%d]'s addr = %p\n", index, encap_entry);
		dev_info(nse_hw_to_dev(hw),
			"\t hw_id = %d, data size = %d, valid = %d, ref_cnt = %d, neigh addr = %p\n",
			encap_entry->du_desc.du_data_id,
			encap_entry->du_desc.data_size,
			encap_entry->valid,
			refcount_read(&encap_entry->ref_cnt),
			encap_entry->neigh_entry);

		for (i = 0; i < encap_entry->du_desc.data_size; i++) {
			u32 j;

			j = 0x3 - (i & 0x3);
			j = j << 0x3;

			data |= encap_entry->du_desc.data[i]<< j;
			if (j == 0) {
				dev_info(nse_hw_to_dev(hw),
					"\t encap_entry's content(BE) = 0x%08x\n", data);
				data = 0;
			}
		}

		fltr_head = &encap_entry->fltr_list;

		if (list_empty(fltr_head)) {
			dev_info(nse_hw_to_dev(hw), "There is no fltr in cur encap entry!\n");
			continue;
		}

		mutex_lock(&encap_entry->fltr_list_lock);

		list_for_each_entry(encap_item, fltr_head, list_entry) {
			u16 tmp;

			dev_info(nse_hw_to_dev(hw), "\t cur encap item: addr = %p, idx = %d, e = %p\n",
				encap_item, encap_item->index, encap_item->e);

			if (encap_item->e != encap_entry) {
				dev_err(nse_hw_to_dev(hw), "Encap entry is not in cur encap item!\n");
				continue;
			}

			fltr = container_of(encap_item, struct nse_tc_flower_fltr,
							action.encaps[encap_item->index]);
			nse_get_tc_fltr(fltr);

			dev_info(nse_hw_to_dev(hw),
				"\t fltr[%d]: cookie = %lx, lut_id = %d, node_id = 0x%x, node_state_id = 0x%x, ref_cnt = %d, encap_cnt = %d, cur encap idx = %d\n",
				fltr_idx, fltr->cookie, fltr->lut_id, fltr->node_id,
				fltr->action.large_act_id, refcount_read(&fltr->ref_cnt),
				fltr->action.encap_cnt, encap_item->index);

			for (tmp = 0; tmp < fltr->action.encap_cnt; tmp++) {
				dev_info(nse_hw_to_dev(hw),
					"\t\t fltr[%d]'s encaps[%d]: addr = %p, index = %d\n",
					fltr_idx, tmp, fltr->action.encaps[tmp].e,
					fltr->action.encaps[tmp].index);
			}

			nse_put_tc_fltr(fltr->src_vsi, fltr);
			fltr_idx++;
		}
		mutex_unlock(&encap_entry->fltr_list_lock);
		index++;
	}
	mutex_unlock(&hw->switch_info->encap_tbl_lock);
}

void nse_debugfs_ovs_fltr_action_vxlan_v6_encap(struct nse_hw *hw, const char *name)
{
	struct nse_pf *pf = (struct nse_pf *)hw->back;
	struct nse_vsi *vsi;
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_tc_flower_fltr *fltr;
	struct ip_tunnel_info *tun_info = NULL;
	u8 mac_addr[ETH_ALEN] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
	u8 mac_mask[ETH_ALEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xf0};
	u8 ipv6_saddr[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
						0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x64};
	u8 ipv6_daddr[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
						0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc8};
	int err;

	fltr = kzalloc(sizeof(*fltr), GFP_KERNEL);
	if (!fltr)
		return;

	vsi = nse_get_main_vsi(pf);
	if (!vsi) {
		dev_err(dev, "get src vsi err!\n");
		kfree(fltr);
		return;
	}

	/*for initial*/
	fltr->src_vsi = vsi;
	INIT_HLIST_NODE(&fltr->tc_flower_node);
	fltr->action.large_act_id = NSE_TC_FLWR_LARGE_ACTION_INVALID;
	fltr->action.vsi_list_id = NSE_TC_FLWR_VSI_LIST_ID_INVALID;

	/*for current test case*/
	fltr->tunnel_type = TNL_LAST;
	fltr->flags |= NSE_TC_FLWR_FIELD_DST_MAC;
	ether_addr_copy(fltr->outer_headers.l2_key.dst_mac, mac_addr);
	ether_addr_copy(fltr->outer_headers.l2_mask.dst_mac, mac_mask);

	fltr->action.flags |= NSE_TC_FLWR_ACTION_FWD_VSI | NSE_TC_FLWR_ACTION_COUNT |
		NSE_TC_FLWR_ACTION_SINGLE_ENCAP;
	fltr->action.fltr_act = NSE_FWD_TO_VSI;
	fltr->action.dest_cnt = 1;
	fltr->action.encap_cnt = 1;
	fltr->action.dests[0].dest_vsi = vsi;
	fltr->action.dests[0].flags |= NSE_TC_FLWR_ACTION_DEST_ENCAP_VLD;
	tun_info = kzalloc(sizeof(*tun_info), GFP_KERNEL);
	if (!tun_info) {
		kfree(fltr);
		return;
	}
	fltr->action.dests[0].tun_info = tun_info;
	tun_info->mode = IP_TUNNEL_INFO_IPV6;
	tun_info->key.tun_id = key32_to_tunnel_id(cpu_to_be32(0x10));
	memcpy(tun_info->key.u.ipv6.dst.s6_addr, ipv6_daddr, 16);
	memcpy(tun_info->key.u.ipv6.src.s6_addr, ipv6_saddr, 16);
	tun_info->key.ttl = 100;

	fltr->action.dests[0].target_dev =
			dev_get_by_name(dev_net(vsi->netdev), name);
	if (!fltr->action.dests[0].target_dev) {
		dev_err(dev, "Failed to get target netdev\n");
		kfree(fltr);
		return;
	}

	dev_info(dev, "Start to vxlan_v6_encap:\n");
	dev_info(dev, "\t match: dmac(0x00, 0x11, 0x22, 0x33, 0x44, 0x5*)/44\n");
	dev_info(dev, "\t action: forward to main Vsi with default count\n");
	dev_info(dev, "\t action: vxlan_v6_encap(enc dst: 0::200, enc src: 0::100)\n");

	err = nse_eswitch_add_tc_fltr(vsi, fltr);
	if (err)
		dev_err(dev, "Failed to vxlan_v6_encap, err = %d\n", err);

	kfree(fltr);
	kfree(tun_info);
}

void nse_debugfs_ovs_fltr_action_enc_push(struct nse_hw *hw, const char *name)
{
	struct nse_pf *pf = (struct nse_pf *)hw->back;
	struct nse_vsi *vsi;
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_tc_flower_fltr *fltr;
	struct ip_tunnel_info *tun_info = NULL;
	struct nse_pedit_headers *hdrs;	/* = &fltr->action.hdrs;*/
	int err;

	fltr = kzalloc(sizeof(*fltr), GFP_KERNEL);
	if (!fltr)
		return;

	vsi = nse_get_main_vsi(pf);
	if (!vsi) {
		dev_err(dev, "get src vsi err!\n");
		kfree(fltr);
		return;
	}

	/*for initial*/
	fltr->src_vsi = vsi;
	INIT_HLIST_NODE(&fltr->tc_flower_node);
	fltr->action.large_act_id = NSE_TC_FLWR_LARGE_ACTION_INVALID;
	fltr->action.vsi_list_id = NSE_TC_FLWR_VSI_LIST_ID_INVALID;

	/*for current test case*/
	fltr->tunnel_type = TNL_LAST;
	fltr->flags |= NSE_TC_FLWR_FIELD_DEST_L4_PORT;
	fltr->outer_headers.l3_key.ip_proto = IPPROTO_TCP;
	fltr->outer_headers.l3_mask.ip_proto = 0xFF;
	fltr->outer_headers.l4_key.dst_port = htons(0x1234);
	fltr->outer_headers.l4_mask.dst_port = htons(0xFFFF);

	fltr->action.flags |= NSE_TC_FLWR_ACTION_FWD_VSI | NSE_TC_FLWR_ACTION_COUNT |
		NSE_TC_FLWR_ACTION_SINGLE_ENCAP | NSE_TC_FLWR_ACTION_REWRITE |
		NSE_TC_FLWR_ACTION_VLAN_PUSH;
	fltr->action.fltr_act = NSE_FWD_TO_VSI;
	fltr->action.dest_cnt = 1;
	fltr->action.encap_cnt = 1;
	fltr->action.dests[0].dest_vsi = vsi;
	fltr->action.dests[0].flags |= NSE_TC_FLWR_ACTION_DEST_ENCAP_VLD;

	tun_info = kzalloc(sizeof(*tun_info), GFP_KERNEL);
	if (!tun_info) {
		kfree(fltr);
		return;
	}
	fltr->action.dests[0].tun_info = tun_info;
	tun_info->mode = 0;
	tun_info->key.tun_id = key32_to_tunnel_id(cpu_to_be32(0x10));
	tun_info->key.u.ipv4.dst = in_aton("192.168.199.200");
	tun_info->key.u.ipv4.src = in_aton("192.168.199.100");
	tun_info->key.ttl = 100;

	fltr->action.dests[0].target_dev =
			dev_get_by_name(dev_net(vsi->netdev), name);
	if (!fltr->action.dests[0].target_dev) {
		dev_err(dev, "Failed to get target netdev\n");
		kfree(fltr);
		return;
	}

	fltr->action.rw_flag |= NSE_SW_REWRITE_L4_DPORT;
	hdrs = &fltr->action.hdrs;
	hdrs->vals.tcp.dest = htons(0x5678);
	hdrs->masks.tcp.dest = htons(0xFFFF);
	hdrs->pedits++;

	fltr->action.rw_flag |= NSE_SW_REWRITE_L3_DIP_V4;
	hdrs = &fltr->action.hdrs;
	hdrs->vals.ip4.daddr = in_aton("10.11.12.13");
	hdrs->masks.ip4.daddr = in_aton("255.255.255.255");
	hdrs->pedits++;

	fltr->action.vlan_proto = htons(ETH_P_8021AD);
	fltr->action.vlan_vid = 100;

	dev_info(dev, "Start to action_enc_dnat:\n");
	dev_info(dev, "\t match: tcp dport(0x1234)/16\n");
	dev_info(dev, "\t action: forward to main Vsi with default count\n");
	dev_info(dev, "\t action: rewrite tcp_dport(0x5678) dip(10.11.12.13)\n");
	dev_info(dev, "\t action: vlan push(0x88a8, vid:100)\n");
	dev_info(dev, "\t action: vxlan_v4_encap(enc dst: 192.168.199.200, enc src: 192.168.199.100)\n");

	err = nse_eswitch_add_tc_fltr(vsi, fltr);
	if (err)
		dev_err(dev, "Failed to action_enc_dnat, err = %d\n", err);

	kfree(fltr);
	kfree(tun_info);
}

void nse_debugfs_ovs_fltr_action_enc_dnat(struct nse_hw *hw, const char *name)
{
	struct nse_pf *pf = (struct nse_pf *)hw->back;
	struct nse_vsi *vsi;
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_tc_flower_fltr *fltr;
	struct ip_tunnel_info *tun_info = NULL;
	struct nse_pedit_headers *hdrs;	/* = &fltr->action.hdrs;*/
	int err;

	fltr = kzalloc(sizeof(*fltr), GFP_KERNEL);
	if (!fltr)
		return;

	vsi = nse_get_main_vsi(pf);
	if (!vsi) {
		dev_err(dev, "get src vsi err!\n");
		kfree(fltr);
		return;
	}

	/*for initial*/
	fltr->src_vsi = vsi;
	INIT_HLIST_NODE(&fltr->tc_flower_node);
	fltr->action.large_act_id = NSE_TC_FLWR_LARGE_ACTION_INVALID;
	fltr->action.vsi_list_id = NSE_TC_FLWR_VSI_LIST_ID_INVALID;

	/*for current test case*/
	fltr->tunnel_type = TNL_LAST;
	fltr->flags |= NSE_TC_FLWR_FIELD_DEST_L4_PORT;
	fltr->outer_headers.l3_key.ip_proto = IPPROTO_TCP;
	fltr->outer_headers.l3_mask.ip_proto = 0xFF;
	fltr->outer_headers.l4_key.dst_port = htons(0x1234);
	fltr->outer_headers.l4_mask.dst_port = htons(0xFFFF);

	fltr->action.flags |= NSE_TC_FLWR_ACTION_FWD_VSI | NSE_TC_FLWR_ACTION_COUNT |
		NSE_TC_FLWR_ACTION_SINGLE_ENCAP | NSE_TC_FLWR_ACTION_REWRITE;
	fltr->action.fltr_act = NSE_FWD_TO_VSI;
	fltr->action.dest_cnt = 1;
	fltr->action.encap_cnt = 1;
	fltr->action.dests[0].dest_vsi = vsi;
	fltr->action.dests[0].flags |= NSE_TC_FLWR_ACTION_DEST_ENCAP_VLD;

	tun_info = kzalloc(sizeof(*tun_info), GFP_KERNEL);
	if (!tun_info) {
		kfree(fltr);
		return;
	}
	fltr->action.dests[0].tun_info = tun_info;
	tun_info->mode = 0;
	tun_info->key.tun_id = key32_to_tunnel_id(cpu_to_be32(0x10));
	tun_info->key.u.ipv4.dst = in_aton("192.168.199.200");
	tun_info->key.u.ipv4.src = in_aton("192.168.199.100");
	tun_info->key.ttl = 100;

	fltr->action.dests[0].target_dev =
			dev_get_by_name(dev_net(vsi->netdev), name);
	if (!fltr->action.dests[0].target_dev) {
		dev_err(dev, "Failed to get target netdev\n");
		kfree(fltr);
		return;
	}

	fltr->action.rw_flag |= NSE_SW_REWRITE_L4_DPORT;
	hdrs = &fltr->action.hdrs;
	hdrs->vals.tcp.dest = htons(0x5678);
	hdrs->masks.tcp.dest = htons(0xFFFF);
	hdrs->pedits++;

	fltr->action.rw_flag |= NSE_SW_REWRITE_L3_DIP_V4;
	hdrs = &fltr->action.hdrs;
	hdrs->vals.ip4.daddr = in_aton("10.11.12.13");
	hdrs->masks.ip4.daddr = in_aton("255.255.255.255");
	hdrs->pedits++;

	dev_info(dev, "Start to action_enc_dnat:\n");
	dev_info(dev, "\t match: tcp dport(0x1234)/16\n");
	dev_info(dev, "\t action: forward to main Vsi with default count\n");
	dev_info(dev, "\t action: rewrite tcp_dport(0x5678) dip(10.11.12.13)\n");
	dev_info(dev, "\t action: vxlan_v4_encap(enc dst: 192.168.199.200, enc src: 192.168.199.100)\n");

	err = nse_eswitch_add_tc_fltr(vsi, fltr);
	if (err)
		dev_err(dev, "Failed to action_enc_dnat, err = %d\n", err);

	kfree(fltr);
	kfree(tun_info);
}

void nse_debugfs_ovs_fltr_action_vxlan_enc(struct nse_hw *hw, const char *name)
{
	struct nse_pf *pf = (struct nse_pf *)hw->back;
	struct nse_vsi *vsi;
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_tc_flower_fltr *fltr;
	struct ip_tunnel_info *tun_info = NULL;
	u8 mac_addr[ETH_ALEN] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
	u8 mac_mask[ETH_ALEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xf0};
	int err;

	fltr = kzalloc(sizeof(*fltr), GFP_KERNEL);
	if (!fltr)
		return;

	vsi = nse_get_main_vsi(pf);
	if (!vsi) {
		dev_err(dev, "get src vsi err!\n");
		kfree(fltr);
		return;
	}

	/*for initial*/
	fltr->src_vsi = vsi;
	INIT_HLIST_NODE(&fltr->tc_flower_node);
	fltr->action.large_act_id = NSE_TC_FLWR_LARGE_ACTION_INVALID;
	fltr->action.vsi_list_id = NSE_TC_FLWR_VSI_LIST_ID_INVALID;

	/*for current test case*/
	fltr->tunnel_type = TNL_LAST;
	fltr->flags |= NSE_TC_FLWR_FIELD_DST_MAC;
	ether_addr_copy(fltr->outer_headers.l2_key.dst_mac, mac_addr);
	ether_addr_copy(fltr->outer_headers.l2_mask.dst_mac, mac_mask);

	fltr->action.flags |= NSE_TC_FLWR_ACTION_FWD_VSI | NSE_TC_FLWR_ACTION_COUNT |
		NSE_TC_FLWR_ACTION_SINGLE_ENCAP;
	fltr->action.fltr_act = NSE_FWD_TO_VSI;
	fltr->action.dest_cnt = 1;
	fltr->action.encap_cnt = 1;
	fltr->action.dests[0].dest_vsi = vsi;
	fltr->action.dests[0].flags |= NSE_TC_FLWR_ACTION_DEST_ENCAP_VLD;

	tun_info = kzalloc(sizeof(*tun_info), GFP_KERNEL);
	if (!tun_info) {
		kfree(fltr);
		return;
	}
	fltr->action.dests[0].tun_info = tun_info;
	tun_info->mode = 0;
	tun_info->key.tun_id = key32_to_tunnel_id(cpu_to_be32(0x10));
	tun_info->key.u.ipv4.dst = in_aton("192.168.199.200");
	tun_info->key.u.ipv4.src = in_aton("192.168.199.100");
	tun_info->key.ttl = 100;

	fltr->action.dests[0].target_dev =
			dev_get_by_name(dev_net(vsi->netdev), name);
	if (!fltr->action.dests[0].target_dev) {
		dev_err(dev, "Failed to get target netdev\n");
		kfree(fltr);
		return;
	}

	dev_info(dev, "Start to vxlan_v4_encap:\n");
	dev_info(dev, "\t match: dmac(0x00, 0x11, 0x22, 0x33, 0x44, 0x5*)/44\n");
	dev_info(dev, "\t action: forward to main Vsi with default count\n");
	dev_info(dev, "\t action: vxlan_v4_encap(enc dst: 192.168.199.200, enc src: 192.168.199.100)\n");

	err = nse_eswitch_add_tc_fltr(vsi, fltr);
	if (err)
		dev_err(dev, "Failed to vxlan_v4_encap, err = %d\n", err);

	kfree(fltr);
	kfree(tun_info);
}

void nse_debugfs_ovs_fltr_action_vlan_push(struct nse_hw *hw)
{
	struct nse_pf *pf = (struct nse_pf *)hw->back;
	struct nse_vsi *vsi;
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_tc_flower_fltr *fltr;
	u8 mac_addr[ETH_ALEN] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
	u8 mac_mask[ETH_ALEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xf0};
	int err;

	fltr = kzalloc(sizeof(*fltr), GFP_KERNEL);
	if (!fltr)
		return;

	vsi = nse_get_main_vsi(pf);
	if (!vsi) {
		dev_err(dev, "get src vsi err!\n");
		kfree(fltr);
		return;
	}
	/*for initial*/
	fltr->src_vsi = vsi;
	INIT_HLIST_NODE(&fltr->tc_flower_node);
	fltr->action.large_act_id = NSE_TC_FLWR_LARGE_ACTION_INVALID;
	fltr->action.vsi_list_id = NSE_TC_FLWR_VSI_LIST_ID_INVALID;

	/*for current test case*/
	fltr->tunnel_type = TNL_LAST;
	fltr->flags |= NSE_TC_FLWR_FIELD_DST_MAC;
	ether_addr_copy(fltr->outer_headers.l2_key.dst_mac, mac_addr);
	ether_addr_copy(fltr->outer_headers.l2_mask.dst_mac, mac_mask);

	fltr->action.flags |= NSE_TC_FLWR_ACTION_FWD_VSI | NSE_TC_FLWR_ACTION_COUNT |
		NSE_TC_FLWR_ACTION_VLAN_PUSH;
	fltr->action.fltr_act = NSE_FWD_TO_VSI;
	fltr->action.dest_cnt = 1;
	fltr->action.dests[0].dest_vsi = vsi;

	fltr->action.vlan_proto = htons(ETH_P_8021AD);
	fltr->action.vlan_vid = 100;

	dev_info(dev, "Start to action_vlan_push:\n");
	dev_info(dev, "\t match: dmac(0x00, 0x11, 0x22, 0x33, 0x44, 0x5*)/44\n");
	dev_info(dev, "\t action: forward to main Vsi with default count\n");
	dev_info(dev, "\t action: vlan push(0x88a8, vid:100)\n");

	err = nse_eswitch_add_tc_fltr(vsi, fltr);
	if (err)
		dev_err(dev, "Failed to action_vlan_pop, err = %d\n", err);

	kfree(fltr);
}

void nse_debugfs_ovs_fltr_action_vlan_pop(struct nse_hw *hw)
{
	struct nse_pf *pf = (struct nse_pf *)hw->back;
	struct nse_vsi *vsi;
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_tc_flower_fltr *fltr;
	int err;

	fltr = kzalloc(sizeof(*fltr), GFP_KERNEL);
	if (!fltr)
		return;

	vsi = nse_get_main_vsi(pf);
	if (!vsi) {
		dev_err(dev, "get src vsi err!\n");
		kfree(fltr);
		return;
	}
	/*for initial*/
	fltr->src_vsi = vsi;
	INIT_HLIST_NODE(&fltr->tc_flower_node);
	fltr->action.large_act_id = NSE_TC_FLWR_LARGE_ACTION_INVALID;
	fltr->action.vsi_list_id = NSE_TC_FLWR_VSI_LIST_ID_INVALID;

	/*for current test case*/
	fltr->tunnel_type = TNL_LAST;
	fltr->flags |= NSE_TC_FLWR_FIELD_VLAN;
	fltr->outer_headers.vlan_hdr.vlan_id = cpu_to_be16(100 & VLAN_VID_MASK);

	fltr->action.flags |= NSE_TC_FLWR_ACTION_FWD_VSI | NSE_TC_FLWR_ACTION_COUNT |
		NSE_TC_FLWR_ACTION_VLAN_POP;
	fltr->action.fltr_act = NSE_FWD_TO_VSI;
	fltr->action.dest_cnt = 1;
	fltr->action.dests[0].dest_vsi = vsi;

	dev_info(dev, "Start to action_vlan_pop:\n");
	dev_info(dev, "\t match: vlan(type:0x88a8 id:100)\n");
	dev_info(dev, "\t action: forward to main Vsi with default count\n");
	dev_info(dev, "\t action: vlan pop\n");

	err = nse_eswitch_add_tc_fltr(vsi, fltr);
	if (err)
		dev_err(dev, "Failed to action_vlan_pop, err = %d\n", err);

	kfree(fltr);
}

void nse_debugfs_ovs_fltr_action_vlan_pop_push(struct nse_hw *hw)
{
	struct nse_pf *pf = (struct nse_pf *)hw->back;
	struct nse_vsi *vsi;
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_tc_flower_fltr *fltr;
	int err;

	fltr = kzalloc(sizeof(*fltr), GFP_KERNEL);
	if (!fltr)
		return;

	vsi = nse_get_main_vsi(pf);
	if (!vsi) {
		dev_err(dev, "get src vsi err!\n");
		kfree(fltr);
		return;
	}
	/*for initial*/
	fltr->src_vsi = vsi;
	INIT_HLIST_NODE(&fltr->tc_flower_node);
	fltr->action.large_act_id = NSE_TC_FLWR_LARGE_ACTION_INVALID;
	fltr->action.vsi_list_id = NSE_TC_FLWR_VSI_LIST_ID_INVALID;

	/*for current test case*/
	fltr->tunnel_type = TNL_LAST;
	fltr->flags |= NSE_TC_FLWR_FIELD_VLAN;
	fltr->outer_headers.vlan_hdr.vlan_id = cpu_to_be16(100 & VLAN_VID_MASK);

	fltr->action.flags |= NSE_TC_FLWR_ACTION_FWD_VSI | NSE_TC_FLWR_ACTION_COUNT |
		NSE_TC_FLWR_ACTION_VLAN_POP | NSE_TC_FLWR_ACTION_VLAN_PUSH;
	fltr->action.fltr_act = NSE_FWD_TO_VSI;
	fltr->action.dest_cnt = 1;
	fltr->action.dests[0].dest_vsi = vsi;

	fltr->action.vlan_proto = htons(ETH_P_8021Q);
	fltr->action.vlan_vid = 200;

	dev_info(dev, "Start to action_vlan_pop_push:\n");
	dev_info(dev, "\t match: vlan(type:0x88a8 id:100)\n");
	dev_info(dev, "\t action: forward to main Vsi with default count\n");
	dev_info(dev, "\t action: vlan pop\n");
	dev_info(dev, "\t action: vlan push(0x8100, vid:200)\n");

	err = nse_eswitch_add_tc_fltr(vsi, fltr);
	if (err)
		dev_err(dev, "Failed to action_vlan_pop_push, err = %d\n", err);

	kfree(fltr);
}

void nse_debugfs_ovs_fltr_action_rw_decap_dnat(struct nse_hw *hw)
{
	struct nse_pf *pf = (struct nse_pf *)hw->back;
	struct nse_vsi *vsi;
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_tc_flower_fltr *fltr;
	struct nse_pedit_headers *hdrs;	/* = &fltr->action.hdrs;*/
	u8 dmac_addr[ETH_ALEN] = {0x00, 0x55, 0x44, 0x33, 0x22, 0x11};
	u8 dmac_mask[ETH_ALEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
	u8 smac_addr[ETH_ALEN] = {0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb};
	u8 smac_mask[ETH_ALEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

	int err;

	fltr = kzalloc(sizeof(*fltr), GFP_KERNEL);
	if (!fltr)
		return;

	vsi = nse_get_main_vsi(pf);
	if (!vsi) {
		dev_err(dev, "get src vsi err!\n");
		kfree(fltr);
		return;
	}
	/*for initial*/
	fltr->src_vsi = vsi;
	INIT_HLIST_NODE(&fltr->tc_flower_node);
	fltr->action.large_act_id = NSE_TC_FLWR_LARGE_ACTION_INVALID;
	fltr->action.vsi_list_id = NSE_TC_FLWR_VSI_LIST_ID_INVALID;

	/*for current test case*/
	fltr->tunnel_type = TNL_VXLAN;
	fltr->flags |= NSE_TC_FLWR_FIELD_SRC_L4_PORT;
	fltr->inner_headers.l3_key.ip_proto = IPPROTO_TCP;
	fltr->inner_headers.l3_mask.ip_proto = 0xFF;
	fltr->inner_headers.l4_key.src_port = htons(0xe2ba);
	fltr->inner_headers.l4_mask.src_port = htons(0xFFFF);

	fltr->action.flags |= NSE_TC_FLWR_ACTION_FWD_VSI_LIST | NSE_TC_FLWR_ACTION_COUNT |
						NSE_TC_FLWR_ACTION_DECAP |
							NSE_TC_FLWR_ACTION_REWRITE;
	fltr->action.fltr_act = NSE_FWD_TO_VSI;
	fltr->action.dest_cnt = 1;
	fltr->action.dests[0].dest_vsi = vsi;

	fltr->action.rw_flag |= NSE_SW_REWRITE_L2_DMAC;
	hdrs = &fltr->action.hdrs;
	ether_addr_copy(hdrs->vals.eth.h_dest, dmac_addr);
	ether_addr_copy(hdrs->masks.eth.h_dest, dmac_mask);
	hdrs->pedits++;

	fltr->action.rw_flag |= NSE_SW_REWRITE_L2_SMAC;
	hdrs = &fltr->action.hdrs;
	ether_addr_copy(hdrs->vals.eth.h_source, smac_addr);
	ether_addr_copy(hdrs->masks.eth.h_source, smac_mask);
	hdrs->pedits++;

	fltr->action.rw_flag |= NSE_SW_REWRITE_L3_DIP_V4;
	hdrs = &fltr->action.hdrs;
	hdrs->vals.ip4.daddr = in_aton("5.6.7.8");
	hdrs->masks.ip4.daddr = in_aton("255.255.255.255");
	hdrs->pedits++;

	fltr->action.rw_flag |= NSE_SW_REWRITE_L4_DPORT;
	hdrs = &fltr->action.hdrs;
	hdrs->vals.udp.dest = htons(0x5678);
	hdrs->masks.udp.dest = htons(0xFFFF);
	hdrs->pedits++;

	dev_info(dev, "Start to action_rw_decap_dnat:\n");
	dev_info(dev, "\tvxlan_i_tcp_sport(0xe2ba/16)\n");
	dev_info(dev, "\t action: forward to Vsi with default count, and decap\n");
	dev_info(dev, "\t action: rewrite dmac(0x00, 0x55, 0x44, 0x33, 0x22, 0x11)\n");
	dev_info(dev, "\t action: rewrite smac(0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb)\n");
	dev_info(dev, "\t action: rewrite dip(5.6.7.8)\n");
	dev_info(dev, "\t action: rewrite tcp_dport(0x5678)\n");

	err = nse_eswitch_add_tc_fltr(vsi, fltr);
	if (err)
		dev_err(dev, "Failed to action_rw_decap_dnat, err = %d\n", err);

	kfree(fltr);
}

void nse_debugfs_ovs_fltr_action_rw_tcp_dnat(struct nse_hw *hw)
{
	struct nse_pf *pf = (struct nse_pf *)hw->back;
	struct nse_vsi *vsi;
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_tc_flower_fltr *fltr;
	struct nse_pedit_headers *hdrs;	/* = &fltr->action.hdrs;*/
	int err;

	fltr = kzalloc(sizeof(*fltr), GFP_KERNEL);
	if (!fltr)
		return;

	vsi = nse_get_main_vsi(pf);
	if (!vsi) {
		dev_err(dev, "get src vsi err!\n");
		kfree(fltr);
		return;
	}
	/*for initial*/
	fltr->src_vsi = vsi;
	INIT_HLIST_NODE(&fltr->tc_flower_node);
	fltr->action.large_act_id = NSE_TC_FLWR_LARGE_ACTION_INVALID;
	fltr->action.vsi_list_id = NSE_TC_FLWR_VSI_LIST_ID_INVALID;

	/*for current test case*/
	fltr->tunnel_type = TNL_LAST;
	fltr->flags |= NSE_TC_FLWR_FIELD_DEST_L4_PORT;
	fltr->outer_headers.l3_key.ip_proto = IPPROTO_TCP;
	fltr->outer_headers.l3_mask.ip_proto = 0xFF;
	fltr->outer_headers.l4_key.dst_port = htons(0x1234);
	fltr->outer_headers.l4_mask.dst_port = htons(0xFFFF);

	fltr->action.flags |= NSE_TC_FLWR_ACTION_FWD_VSI | NSE_TC_FLWR_ACTION_COUNT |
		NSE_TC_FLWR_ACTION_REWRITE;
	fltr->action.fltr_act = NSE_FWD_TO_VSI;
	fltr->action.dest_cnt = 1;
	fltr->action.dests[0].dest_vsi = vsi;

	fltr->action.rw_flag |= NSE_SW_REWRITE_L4_DPORT;
	hdrs = &fltr->action.hdrs;
	hdrs->vals.tcp.dest = htons(0x5678);
	hdrs->masks.tcp.dest = htons(0xFFFF);
	hdrs->pedits++;

	fltr->action.rw_flag |= NSE_SW_REWRITE_L3_DIP_V4;
	hdrs = &fltr->action.hdrs;
	hdrs->vals.ip4.daddr = in_aton("10.11.12.13");
	hdrs->masks.ip4.daddr = in_aton("255.255.255.255");
	hdrs->pedits++;

	dev_info(dev, "Start to action_rw_tcp_dnat:\n");
	dev_info(dev, "\t match: dport(0x1234)/16\n");
	dev_info(dev, "\t action: forward to main Vsi with default count, and rewrite tcp_dnat\n");
	dev_info(dev, "\t action: rewrite tcp_dport(0x5678) dip(10.11.12.13)\n");

	err = nse_eswitch_add_tc_fltr(vsi, fltr);
	if (err)
		dev_err(dev, "Failed to action_rw_tcp_dnat, err = %d\n", err);

	kfree(fltr);
}

void nse_debugfs_ovs_fltr_action_rw_tcp_snat(struct nse_hw *hw)
{
	struct nse_pf *pf = (struct nse_pf *)hw->back;
	struct nse_vsi *vsi;
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_tc_flower_fltr *fltr;
	struct nse_pedit_headers *hdrs;	/* = &fltr->action.hdrs;*/
	int err;

	fltr = kzalloc(sizeof(*fltr), GFP_KERNEL);
	if (!fltr)
		return;

	vsi = nse_get_main_vsi(pf);
	if (!vsi) {
		dev_err(dev, "get src vsi err!\n");
		kfree(fltr);
		return;
	}
	/*for initial*/
	fltr->src_vsi = vsi;
	INIT_HLIST_NODE(&fltr->tc_flower_node);
	fltr->action.large_act_id = NSE_TC_FLWR_LARGE_ACTION_INVALID;
	fltr->action.vsi_list_id = NSE_TC_FLWR_VSI_LIST_ID_INVALID;

	/*for current test case*/
	fltr->tunnel_type = TNL_LAST;
	fltr->flags |= NSE_TC_FLWR_FIELD_DEST_L4_PORT;
	fltr->outer_headers.l3_key.ip_proto = IPPROTO_TCP;
	fltr->outer_headers.l3_mask.ip_proto = 0xFF;
	fltr->outer_headers.l4_key.dst_port = htons(0x1234);
	fltr->outer_headers.l4_mask.dst_port = htons(0xFFFF);

	fltr->action.flags |= NSE_TC_FLWR_ACTION_FWD_VSI | NSE_TC_FLWR_ACTION_COUNT |
		NSE_TC_FLWR_ACTION_REWRITE;
	fltr->action.fltr_act = NSE_FWD_TO_VSI;
	fltr->action.dest_cnt = 1;
	fltr->action.dests[0].dest_vsi = vsi;

	fltr->action.rw_flag |= NSE_SW_REWRITE_L4_SPORT;
	hdrs = &fltr->action.hdrs;
	hdrs->vals.tcp.source = htons(0x5678);
	hdrs->masks.tcp.source = htons(0xFFFF);
	hdrs->pedits++;

	fltr->action.rw_flag |= NSE_SW_REWRITE_L3_SIP_V4;
	hdrs = &fltr->action.hdrs;
	hdrs->vals.ip4.saddr = in_aton("10.11.12.13");
	hdrs->masks.ip4.saddr = in_aton("255.255.255.255");
	hdrs->pedits++;

	dev_info(dev, "Start to action_rw_tcp_snat:\n");
	dev_info(dev, "\t match: dport(0x1234)/16\n");
	dev_info(dev, "\t action: forward to main Vsi with default count, and rewrite tcp_snat\n");
	dev_info(dev, "\t action: rewrite tcp_sport(0x5678) sip(10.11.12.13)\n");

	err = nse_eswitch_add_tc_fltr(vsi, fltr);
	if (err)
		dev_err(dev, "Failed to action_rw_tcp_snat, err = %d\n", err);

	kfree(fltr);
}

void nse_debugfs_ovs_fltr_action_rw_udp_dnat(struct nse_hw *hw)
{
	struct nse_pf *pf = (struct nse_pf *)hw->back;
	struct nse_vsi *vsi;
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_tc_flower_fltr *fltr;
	struct nse_pedit_headers *hdrs;	/* = &fltr->action.hdrs;*/
	int err;

	fltr = kzalloc(sizeof(*fltr), GFP_KERNEL);
	if (!fltr)
		return;

	vsi = nse_get_main_vsi(pf);
	if (!vsi) {
		dev_err(dev, "get src vsi err!\n");
		kfree(fltr);
		return;
	}
	/*for initial*/
	fltr->src_vsi = vsi;
	INIT_HLIST_NODE(&fltr->tc_flower_node);
	fltr->action.large_act_id = NSE_TC_FLWR_LARGE_ACTION_INVALID;
	fltr->action.vsi_list_id = NSE_TC_FLWR_VSI_LIST_ID_INVALID;

	/*for current test case*/
	fltr->tunnel_type = TNL_LAST;
	fltr->flags |= NSE_TC_FLWR_FIELD_DEST_L4_PORT;
	fltr->outer_headers.l3_key.ip_proto = IPPROTO_UDP;
	fltr->outer_headers.l3_mask.ip_proto = 0xFF;
	fltr->outer_headers.l4_key.dst_port = htons(0x1234);
	fltr->outer_headers.l4_mask.dst_port = htons(0xFFFF);

	fltr->action.flags |= NSE_TC_FLWR_ACTION_FWD_VSI | NSE_TC_FLWR_ACTION_COUNT |
		NSE_TC_FLWR_ACTION_REWRITE;
	fltr->action.fltr_act = NSE_FWD_TO_VSI;
	fltr->action.dest_cnt = 1;
	fltr->action.dests[0].dest_vsi = vsi;

	fltr->action.rw_flag |= NSE_SW_REWRITE_L4_DPORT;
	hdrs = &fltr->action.hdrs;
	hdrs->vals.udp.dest = htons(0x5678);
	hdrs->masks.udp.dest = htons(0xFFFF);
	hdrs->pedits++;

	fltr->action.rw_flag |= NSE_SW_REWRITE_L3_DIP_V4;
	hdrs = &fltr->action.hdrs;
	hdrs->vals.ip4.daddr = in_aton("10.11.12.13");
	hdrs->masks.ip4.daddr = in_aton("255.255.255.255");
	hdrs->pedits++;

	dev_info(dev, "Start to action_rw_udp_dnat:\n");
	dev_info(dev, "\t match: dport(0x1234)/16\n");
	dev_info(dev, "\t action: forward to main Vsi with default count, and rewrite udp_dnat\n");
	dev_info(dev, "\t action: rewrite udp_dport(0x5678) dip(10.11.12.13)\n");

	err = nse_eswitch_add_tc_fltr(vsi, fltr);
	if (err)
		dev_err(dev, "Failed to action_rw_udp_dnat, err = %d\n", err);

	kfree(fltr);
}

void nse_debugfs_ovs_fltr_action_rw_udp_snat(struct nse_hw *hw)
{
	struct nse_pf *pf = (struct nse_pf *)hw->back;
	struct nse_vsi *vsi;
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_tc_flower_fltr *fltr;
	struct nse_pedit_headers *hdrs;	/* = &fltr->action.hdrs;*/
	int err;

	fltr = kzalloc(sizeof(*fltr), GFP_KERNEL);
	if (!fltr)
		return;

	vsi = nse_get_main_vsi(pf);
	if (!vsi) {
		dev_err(dev, "get src vsi err!\n");
		kfree(fltr);
		return;
	}
	/*for initial*/
	fltr->src_vsi = vsi;
	INIT_HLIST_NODE(&fltr->tc_flower_node);
	fltr->action.large_act_id = NSE_TC_FLWR_LARGE_ACTION_INVALID;
	fltr->action.vsi_list_id = NSE_TC_FLWR_VSI_LIST_ID_INVALID;

	/*for current test case*/
	fltr->tunnel_type = TNL_LAST;
	fltr->flags |= NSE_TC_FLWR_FIELD_DEST_L4_PORT;
	fltr->outer_headers.l3_key.ip_proto = IPPROTO_UDP;
	fltr->outer_headers.l3_mask.ip_proto = 0xFF;
	fltr->outer_headers.l4_key.dst_port = htons(0x1234);
	fltr->outer_headers.l4_mask.dst_port = htons(0xFFFF);

	fltr->action.flags |= NSE_TC_FLWR_ACTION_FWD_VSI | NSE_TC_FLWR_ACTION_COUNT |
		NSE_TC_FLWR_ACTION_REWRITE;
	fltr->action.fltr_act = NSE_FWD_TO_VSI;
	fltr->action.dest_cnt = 1;
	fltr->action.dests[0].dest_vsi = vsi;

	fltr->action.rw_flag |= NSE_SW_REWRITE_L4_SPORT;
	hdrs = &fltr->action.hdrs;
	hdrs->vals.udp.source = htons(0x5678);
	hdrs->masks.udp.source = htons(0xFFFF);
	hdrs->pedits++;

	fltr->action.rw_flag |= NSE_SW_REWRITE_L3_SIP_V4;
	hdrs = &fltr->action.hdrs;
	hdrs->vals.ip4.saddr = in_aton("10.11.12.13");
	hdrs->masks.ip4.saddr = in_aton("255.255.255.255");
	hdrs->pedits++;

	dev_info(dev, "Start to action_rw_udp_snat:\n");
	dev_info(dev, "\t match: dport(0x1234)/16\n");
	dev_info(dev, "\t action: forward to main Vsi with default count, and rewrite udp_snat\n");
	dev_info(dev, "\t action: rewrite udp_sport(0x5678) sip(10.11.12.13)\n");

	err = nse_eswitch_add_tc_fltr(vsi, fltr);
	if (err)
		dev_err(dev, "Failed to action_rw_udp_snat, err = %d\n", err);

	kfree(fltr);
}

void nse_debugfs_ovs_fltr_action_rw_tcp_dport(struct nse_hw *hw)
{
	struct nse_pf *pf = (struct nse_pf *)hw->back;
	struct nse_vsi *vsi;
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_tc_flower_fltr *fltr;
	struct nse_pedit_headers *hdrs;	/* = &fltr->action.hdrs;*/
	int err;

	fltr = kzalloc(sizeof(*fltr), GFP_KERNEL);
	if (!fltr)
		return;

	vsi = nse_get_main_vsi(pf);
	if (!vsi) {
		dev_err(dev, "get src vsi err!\n");
		kfree(fltr);
		return;
	}
	/*for initial*/
	fltr->src_vsi = vsi;
	INIT_HLIST_NODE(&fltr->tc_flower_node);
	fltr->action.large_act_id = NSE_TC_FLWR_LARGE_ACTION_INVALID;
	fltr->action.vsi_list_id = NSE_TC_FLWR_VSI_LIST_ID_INVALID;

	/*for current test case*/
	fltr->tunnel_type = TNL_LAST;
	fltr->flags |= NSE_TC_FLWR_FIELD_DEST_L4_PORT;
	fltr->outer_headers.l3_key.ip_proto = IPPROTO_TCP;
	fltr->outer_headers.l3_mask.ip_proto = 0xFF;
	fltr->outer_headers.l4_key.dst_port = htons(0x1234);
	fltr->outer_headers.l4_mask.dst_port = htons(0xFFFF);

	fltr->action.flags |= NSE_TC_FLWR_ACTION_FWD_VSI | NSE_TC_FLWR_ACTION_COUNT |
		NSE_TC_FLWR_ACTION_REWRITE;
	fltr->action.fltr_act = NSE_FWD_TO_VSI;
	fltr->action.dest_cnt = 1;
	fltr->action.dests[0].dest_vsi = vsi;

	fltr->action.rw_flag |= NSE_SW_REWRITE_L4_DPORT;
	hdrs = &fltr->action.hdrs;
	hdrs->vals.tcp.dest = htons(0x5678);
	hdrs->masks.tcp.dest = htons(0xFFFF);
	hdrs->pedits++;

	dev_info(dev, "Start to action_rw_tcp_dport:\n");
	dev_info(dev, "\t match: dport(0x1234)/16\n");
	dev_info(dev, "\t action: forward to main Vsi with default count, and rewrite tcp_dport\n");
	dev_info(dev, "\t action: rewrite tcp_dport(0x5678)\n");

	err = nse_eswitch_add_tc_fltr(vsi, fltr);
	if (err)
		dev_err(dev, "Failed to action_rw_tcp_dport, err = %d\n", err);

	kfree(fltr);
}

void nse_debugfs_ovs_fltr_action_rw_tcp_sport(struct nse_hw *hw)
{
	struct nse_pf *pf = (struct nse_pf *)hw->back;
	struct nse_vsi *vsi;
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_tc_flower_fltr *fltr;
	struct nse_pedit_headers *hdrs;	/* = &fltr->action.hdrs;*/
	int err;

	fltr = kzalloc(sizeof(*fltr), GFP_KERNEL);
	if (!fltr)
		return;

	vsi = nse_get_main_vsi(pf);
	if (!vsi) {
		dev_err(dev, "get src vsi err!\n");
		kfree(fltr);
		return;
	}
	/*for initial*/
	fltr->src_vsi = vsi;
	INIT_HLIST_NODE(&fltr->tc_flower_node);
	fltr->action.large_act_id = NSE_TC_FLWR_LARGE_ACTION_INVALID;
	fltr->action.vsi_list_id = NSE_TC_FLWR_VSI_LIST_ID_INVALID;

	/*for current test case*/
	fltr->tunnel_type = TNL_LAST;
	fltr->flags |= NSE_TC_FLWR_FIELD_DEST_L4_PORT;
	fltr->outer_headers.l3_key.ip_proto = IPPROTO_TCP;
	fltr->outer_headers.l3_mask.ip_proto = 0xFF;
	fltr->outer_headers.l4_key.dst_port = htons(0x1234);
	fltr->outer_headers.l4_mask.dst_port = htons(0xFFFF);

	fltr->action.flags |= NSE_TC_FLWR_ACTION_FWD_VSI | NSE_TC_FLWR_ACTION_COUNT |
		NSE_TC_FLWR_ACTION_REWRITE;
	fltr->action.fltr_act = NSE_FWD_TO_VSI;
	fltr->action.dest_cnt = 1;
	fltr->action.dests[0].dest_vsi = vsi;

	fltr->action.rw_flag |= NSE_SW_REWRITE_L4_SPORT;
	hdrs = &fltr->action.hdrs;
	hdrs->vals.tcp.source = htons(0x5678);
	hdrs->masks.tcp.source = htons(0xFFFF);
	hdrs->pedits++;

	dev_info(dev, "Start to action_rw_tcp_sport:\n");
	dev_info(dev, "\t match: dport(0x1234)/16\n");
	dev_info(dev, "\t action: forward to main Vsi with default count, and rewrite tcp_sport\n");
	dev_info(dev, "\t action: rewrite tcp_sport(0x5678)\n");

	err = nse_eswitch_add_tc_fltr(vsi, fltr);
	if (err)
		dev_err(dev, "Failed to action_rw_tcp_sport, err = %d\n", err);

	kfree(fltr);
}

void nse_debugfs_ovs_fltr_action_rw_udp_dport(struct nse_hw *hw)
{
	struct nse_pf *pf = (struct nse_pf *)hw->back;
	struct nse_vsi *vsi;
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_tc_flower_fltr *fltr;
	struct nse_pedit_headers *hdrs;	/* = &fltr->action.hdrs;*/
	int err;

	fltr = kzalloc(sizeof(*fltr), GFP_KERNEL);
	if (!fltr)
		return;

	vsi = nse_get_main_vsi(pf);
	if (!vsi) {
		dev_err(dev, "get src vsi err!\n");
		kfree(fltr);
		return;
	}
	/*for initial*/
	fltr->src_vsi = vsi;
	INIT_HLIST_NODE(&fltr->tc_flower_node);
	fltr->action.large_act_id = NSE_TC_FLWR_LARGE_ACTION_INVALID;
	fltr->action.vsi_list_id = NSE_TC_FLWR_VSI_LIST_ID_INVALID;

	/*for current test case*/
	fltr->tunnel_type = TNL_LAST;
	fltr->flags |= NSE_TC_FLWR_FIELD_DEST_L4_PORT;
	fltr->outer_headers.l3_key.ip_proto = IPPROTO_UDP;
	fltr->outer_headers.l3_mask.ip_proto = 0xFF;
	fltr->outer_headers.l4_key.dst_port = htons(0x1234);
	fltr->outer_headers.l4_mask.dst_port = htons(0xFFFF);

	fltr->action.flags |= NSE_TC_FLWR_ACTION_FWD_VSI | NSE_TC_FLWR_ACTION_COUNT |
		NSE_TC_FLWR_ACTION_REWRITE;
	fltr->action.fltr_act = NSE_FWD_TO_VSI;
	fltr->action.dest_cnt = 1;
	fltr->action.dests[0].dest_vsi = vsi;

	fltr->action.rw_flag |= NSE_SW_REWRITE_L4_DPORT;
	hdrs = &fltr->action.hdrs;
	hdrs->vals.udp.dest = htons(0x5678);
	hdrs->masks.udp.dest = htons(0xFFFF);
	hdrs->pedits++;

	dev_info(dev, "Start to action_rw_udp_dport:\n");
	dev_info(dev, "\t match: dport(0x1234)/16\n");
	dev_info(dev, "\t action: forward to main Vsi with default count, and rewrite udp_dport\n");
	dev_info(dev, "\t action: rewrite udp_dport(0x5678)\n");

	err = nse_eswitch_add_tc_fltr(vsi, fltr);
	if (err)
		dev_err(dev, "Failed to action_rw_udp_dport, err = %d\n", err);

	kfree(fltr);
}

void nse_debugfs_ovs_fltr_action_rw_udp_sport(struct nse_hw *hw)
{
	struct nse_pf *pf = (struct nse_pf *)hw->back;
	struct nse_vsi *vsi;
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_tc_flower_fltr *fltr;
	struct nse_pedit_headers *hdrs;	/* = &fltr->action.hdrs;*/
	int err;

	fltr = kzalloc(sizeof(*fltr), GFP_KERNEL);
	if (!fltr)
		return;

	vsi = nse_get_main_vsi(pf);
	if (!vsi) {
		dev_err(dev, "get src vsi err!\n");
		kfree(fltr);
		return;
	}
	/*for initial*/
	fltr->src_vsi = vsi;
	INIT_HLIST_NODE(&fltr->tc_flower_node);
	fltr->action.large_act_id = NSE_TC_FLWR_LARGE_ACTION_INVALID;
	fltr->action.vsi_list_id = NSE_TC_FLWR_VSI_LIST_ID_INVALID;

	/*for current test case*/
	fltr->tunnel_type = TNL_LAST;
	fltr->flags |= NSE_TC_FLWR_FIELD_DEST_L4_PORT;
	fltr->outer_headers.l3_key.ip_proto = IPPROTO_UDP;
	fltr->outer_headers.l3_mask.ip_proto = 0xFF;
	fltr->outer_headers.l4_key.dst_port = htons(0x1234);
	fltr->outer_headers.l4_mask.dst_port = htons(0xFFFF);

	fltr->action.flags |= NSE_TC_FLWR_ACTION_FWD_VSI | NSE_TC_FLWR_ACTION_COUNT |
		NSE_TC_FLWR_ACTION_REWRITE;
	fltr->action.fltr_act = NSE_FWD_TO_VSI;
	fltr->action.dest_cnt = 1;
	fltr->action.dests[0].dest_vsi = vsi;

	fltr->action.rw_flag |= NSE_SW_REWRITE_L4_SPORT;
	hdrs = &fltr->action.hdrs;
	hdrs->vals.udp.source = htons(0x5678);
	hdrs->masks.udp.source = htons(0xFFFF);
	hdrs->pedits++;

	dev_info(dev, "Start to action_rw_udp_sport:\n");
	dev_info(dev, "\t match: dport(0x1234)/16\n");
	dev_info(dev, "\t action: forward to main Vsi with default count, and rewrite udp_sport\n");
	dev_info(dev, "\t action: rewrite udp_sport(0x5678)\n");

	err = nse_eswitch_add_tc_fltr(vsi, fltr);
	if (err)
		dev_err(dev, "Failed to action_rw_udp_sport, err = %d\n", err);

	kfree(fltr);
}

void nse_debugfs_ovs_fltr_action_rw_dip(struct nse_hw *hw)
{
	struct nse_pf *pf = (struct nse_pf *)hw->back;
	struct nse_vsi *vsi;
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_tc_flower_fltr *fltr;
	struct nse_pedit_headers *hdrs;	/* = &fltr->action.hdrs;*/
	int err;

	fltr = kzalloc(sizeof(*fltr), GFP_KERNEL);
	if (!fltr)
		return;

	vsi = nse_get_main_vsi(pf);
	if (!vsi) {
		dev_err(dev, "get src vsi err!\n");
		kfree(fltr);
		return;
	}
	/*for initial*/
	fltr->src_vsi = vsi;
	INIT_HLIST_NODE(&fltr->tc_flower_node);
	fltr->action.large_act_id = NSE_TC_FLWR_LARGE_ACTION_INVALID;
	fltr->action.vsi_list_id = NSE_TC_FLWR_VSI_LIST_ID_INVALID;

	/*for current test case*/
	fltr->tunnel_type = TNL_LAST;
	fltr->flags |= NSE_TC_FLWR_FIELD_DEST_IPV4;
	fltr->outer_headers.l3_key.dst_ipv4 = in_aton("1.2.3.4");
	fltr->outer_headers.l3_mask.dst_ipv4 = in_aton("255.255.255.255");

	fltr->action.flags |= NSE_TC_FLWR_ACTION_FWD_VSI | NSE_TC_FLWR_ACTION_COUNT |
		NSE_TC_FLWR_ACTION_REWRITE;
	fltr->action.fltr_act = NSE_FWD_TO_VSI;
	fltr->action.dest_cnt = 1;
	fltr->action.dests[0].dest_vsi = vsi;

	fltr->action.rw_flag |= NSE_SW_REWRITE_L3_DIP_V4;
	hdrs = &fltr->action.hdrs;
	hdrs->vals.ip4.daddr = in_aton("10.11.12.13");
	hdrs->masks.ip4.daddr = in_aton("255.255.255.255");
	hdrs->pedits++;

	dev_info(dev, "Start to action_rw_dip:\n");
	dev_info(dev, "\t match: dip(1.2.3.4)/32\n");
	dev_info(dev, "\t action: forward to main Vsi with default count, and rewrite dip\n");
	dev_info(dev, "\t action: rewrite dip(10.11.12.13)\n");

	err = nse_eswitch_add_tc_fltr(vsi, fltr);
	if (err)
		dev_err(dev, "Failed to action_rw_dip, err = %d\n", err);

	kfree(fltr);
}

void nse_debugfs_ovs_fltr_action_rw_sip(struct nse_hw *hw)
{
	struct nse_pf *pf = (struct nse_pf *)hw->back;
	struct nse_vsi *vsi;
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_tc_flower_fltr *fltr;
	struct nse_pedit_headers *hdrs;	/* = &fltr->action.hdrs;*/
	int err;

	fltr = kzalloc(sizeof(*fltr), GFP_KERNEL);
	if (!fltr)
		return;

	vsi = nse_get_main_vsi(pf);
	if (!vsi) {
		dev_err(dev, "get src vsi err!\n");
		kfree(fltr);
		return;
	}
	/*for initial*/
	fltr->src_vsi = vsi;
	INIT_HLIST_NODE(&fltr->tc_flower_node);
	fltr->action.large_act_id = NSE_TC_FLWR_LARGE_ACTION_INVALID;
	fltr->action.vsi_list_id = NSE_TC_FLWR_VSI_LIST_ID_INVALID;

	/*for current test case*/
	fltr->tunnel_type = TNL_LAST;
	fltr->flags |= NSE_TC_FLWR_FIELD_DEST_IPV4;
	fltr->outer_headers.l3_key.dst_ipv4 = in_aton("1.2.3.4");
	fltr->outer_headers.l3_mask.dst_ipv4 = in_aton("255.255.255.255");

	fltr->action.flags |= NSE_TC_FLWR_ACTION_FWD_VSI | NSE_TC_FLWR_ACTION_COUNT |
		NSE_TC_FLWR_ACTION_REWRITE;
	fltr->action.fltr_act = NSE_FWD_TO_VSI;
	fltr->action.dest_cnt = 1;
	fltr->action.dests[0].dest_vsi = vsi;

	fltr->action.rw_flag |= NSE_SW_REWRITE_L3_SIP_V4;
	hdrs = &fltr->action.hdrs;
	hdrs->vals.ip4.saddr = in_aton("10.11.12.13");
	hdrs->masks.ip4.saddr = in_aton("255.255.255.255");
	hdrs->pedits++;

	dev_info(dev, "Start to action_rw_sip:\n");
	dev_info(dev, "\t match: dip(1.2.3.4)/32\n");
	dev_info(dev, "\t action: forward to main Vsi with default count, and rewrite sip\n");
	dev_info(dev, "\t action: rewrite sip(10.11.12.13)\n");

	err = nse_eswitch_add_tc_fltr(vsi, fltr);
	if (err)
		dev_err(dev, "Failed to action_rw_sip, err = %d\n", err);

	kfree(fltr);
}

void nse_debugfs_ovs_fltr_action_rw_mac(struct nse_hw *hw)
{
	struct nse_pf *pf = (struct nse_pf *)hw->back;
	struct nse_vsi *vsi;
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_tc_flower_fltr *fltr;
	u8 mac_addr[ETH_ALEN] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
	u8 mac_mask[ETH_ALEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xf0};
	u8 dmac_addr[ETH_ALEN] = {0x66, 0x55, 0x44, 0x33, 0x22, 0x11};
	u8 dmac_mask[ETH_ALEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
	u8 smac_addr[ETH_ALEN] = {0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc};
	u8 smac_mask[ETH_ALEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
	struct nse_pedit_headers *hdrs;	/* = &fltr->action.hdrs;*/
	int err;

	fltr = kzalloc(sizeof(*fltr), GFP_KERNEL);
	if (!fltr)
		return;

	vsi = nse_get_main_vsi(pf);
	if (!vsi) {
		dev_err(dev, "get src vsi err!\n");
		kfree(fltr);
		return;
	}
	/*for initial*/
	fltr->src_vsi = vsi;
	INIT_HLIST_NODE(&fltr->tc_flower_node);
	fltr->action.large_act_id = NSE_TC_FLWR_LARGE_ACTION_INVALID;
	fltr->action.vsi_list_id = NSE_TC_FLWR_VSI_LIST_ID_INVALID;

	/*for current test case*/
	fltr->tunnel_type = TNL_LAST;
	fltr->flags |= NSE_TC_FLWR_FIELD_DST_MAC;
	ether_addr_copy(fltr->outer_headers.l2_key.dst_mac, mac_addr);
	ether_addr_copy(fltr->outer_headers.l2_mask.dst_mac, mac_mask);

	fltr->action.flags |= NSE_TC_FLWR_ACTION_FWD_VSI | NSE_TC_FLWR_ACTION_COUNT |
		NSE_TC_FLWR_ACTION_REWRITE;
	fltr->action.fltr_act = NSE_FWD_TO_VSI;
	fltr->action.dest_cnt = 1;
	fltr->action.dests[0].dest_vsi = vsi;

	fltr->action.rw_flag |= NSE_SW_REWRITE_L2_DMAC;
	hdrs = &fltr->action.hdrs;
	ether_addr_copy(hdrs->vals.eth.h_dest, dmac_addr);
	ether_addr_copy(hdrs->masks.eth.h_dest, dmac_mask);
	hdrs->pedits++;

	fltr->action.rw_flag |= NSE_SW_REWRITE_L2_SMAC;
	hdrs = &fltr->action.hdrs;
	ether_addr_copy(hdrs->vals.eth.h_source, smac_addr);
	ether_addr_copy(hdrs->masks.eth.h_source, smac_mask);
	hdrs->pedits++;

	dev_info(dev, "Start to action_rw_smac_dmac:\n");
	dev_info(dev, "\t match: dmac(0x00, 0x11, 0x22, 0x33, 0x44, 0x5*)/44\n");
	dev_info(dev, "\t action: forward to main Vsi with default count, and rewrite smac&dmac\n");
	dev_info(dev, "\t action: rewrite smac(0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc)\n");
	dev_info(dev, "\t action: rewrite dmac(0x66, 0x55, 0x44, 0x33, 0x22, 0x11)\n");

	err = nse_eswitch_add_tc_fltr(vsi, fltr);
	if (err)
		dev_err(dev, "Failed to action_rw_smac_dmac, err = %d\n", err);

	kfree(fltr);
}

void nse_debugfs_ovs_fltr_action_rw_dmac(struct nse_hw *hw)
{
	struct nse_pf *pf = (struct nse_pf *)hw->back;
	struct nse_vsi *vsi;
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_tc_flower_fltr *fltr;
	u8 mac_addr[ETH_ALEN] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
	u8 mac_mask[ETH_ALEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xf0};
	u8 dmac_addr[ETH_ALEN] = {0x66, 0x55, 0x44, 0x33, 0x22, 0x11};
	u8 dmac_mask[ETH_ALEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
	struct nse_pedit_headers *hdrs;	/* = &fltr->action.hdrs;*/
	int err;

	fltr = kzalloc(sizeof(*fltr), GFP_KERNEL);
	if (!fltr)
		return;

	vsi = nse_get_main_vsi(pf);
	if (!vsi) {
		dev_err(dev, "get src vsi err!\n");
		kfree(fltr);
		return;
	}
	/*for initial*/
	fltr->src_vsi = vsi;
	INIT_HLIST_NODE(&fltr->tc_flower_node);
	fltr->action.large_act_id = NSE_TC_FLWR_LARGE_ACTION_INVALID;
	fltr->action.vsi_list_id = NSE_TC_FLWR_VSI_LIST_ID_INVALID;

	/*for current test case*/
	fltr->tunnel_type = TNL_LAST;
	fltr->flags |= NSE_TC_FLWR_FIELD_DST_MAC;
	ether_addr_copy(fltr->outer_headers.l2_key.dst_mac, mac_addr);
	ether_addr_copy(fltr->outer_headers.l2_mask.dst_mac, mac_mask);

	fltr->action.flags |= NSE_TC_FLWR_ACTION_FWD_VSI | NSE_TC_FLWR_ACTION_COUNT |
		NSE_TC_FLWR_ACTION_REWRITE;
	fltr->action.fltr_act = NSE_FWD_TO_VSI;
	fltr->action.dest_cnt = 1;
	fltr->action.dests[0].dest_vsi = vsi;

	fltr->action.rw_flag |= NSE_SW_REWRITE_L2_DMAC;
	hdrs = &fltr->action.hdrs;
	ether_addr_copy(hdrs->vals.eth.h_dest, dmac_addr);
	ether_addr_copy(hdrs->masks.eth.h_dest, dmac_mask);
	hdrs->pedits++;

	dev_info(dev, "Start to action_rw_dmac:\n");
	dev_info(dev, "\t match: dmac(0x00, 0x11, 0x22, 0x33, 0x44, 0x5*)/44\n");
	dev_info(dev, "\t action: forward to main Vsi with default count, and rewrite dmac\n");
	dev_info(dev, "\t action: rewrite dmac(0x66, 0x55, 0x44, 0x33, 0x22, 0x11)\n");

	err = nse_eswitch_add_tc_fltr(vsi, fltr);
	if (err)
		dev_err(dev, "Failed to action_rw_dmac, err = %d\n", err);

	kfree(fltr);
}

void nse_debugfs_ovs_fltr_action_rw_smac(struct nse_hw *hw)
{
	struct nse_pf *pf = (struct nse_pf *)hw->back;
	struct nse_vsi *vsi;
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_tc_flower_fltr *fltr;
	u8 mac_addr[ETH_ALEN] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
	u8 mac_mask[ETH_ALEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xf0};
	u8 smac_addr[ETH_ALEN] = {0x00, 0x55, 0x44, 0x33, 0x22, 0x11};
	u8 smac_mask[ETH_ALEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
	struct nse_pedit_headers *hdrs;	/* = &fltr->action.hdrs;*/
	int err;

	fltr = kzalloc(sizeof(*fltr), GFP_KERNEL);
	if (!fltr)
		return;

	vsi = nse_get_main_vsi(pf);
	if (!vsi) {
		dev_err(dev, "get src vsi err!\n");
		kfree(fltr);
		return;
	}
	/*for initial*/
	fltr->src_vsi = vsi;
	INIT_HLIST_NODE(&fltr->tc_flower_node);
	fltr->action.large_act_id = NSE_TC_FLWR_LARGE_ACTION_INVALID;
	fltr->action.vsi_list_id = NSE_TC_FLWR_VSI_LIST_ID_INVALID;

	/*for current test case*/
	fltr->tunnel_type = TNL_LAST;
	fltr->flags |= NSE_TC_FLWR_FIELD_DST_MAC;
	ether_addr_copy(fltr->outer_headers.l2_key.dst_mac, mac_addr);
	ether_addr_copy(fltr->outer_headers.l2_mask.dst_mac, mac_mask);

	fltr->action.flags |= NSE_TC_FLWR_ACTION_FWD_VSI | NSE_TC_FLWR_ACTION_COUNT |
		NSE_TC_FLWR_ACTION_REWRITE;
	fltr->action.fltr_act = NSE_FWD_TO_VSI;
	fltr->action.dest_cnt = 1;
	fltr->action.dests[0].dest_vsi = vsi;

	fltr->action.rw_flag |= NSE_SW_REWRITE_L2_SMAC;
	hdrs = &fltr->action.hdrs;
	ether_addr_copy(hdrs->vals.eth.h_source, smac_addr);
	ether_addr_copy(hdrs->masks.eth.h_source, smac_mask);
	hdrs->pedits++;

	dev_info(dev, "Start to action_rw_smac:\n");
	dev_info(dev, "\t match: dmac(0x00, 0x11, 0x22, 0x33, 0x44, 0x5*)/44\n");
	dev_info(dev, "\t action: forward to main Vsi with default count, and rewrite smac\n");
	dev_info(dev, "\t action: rewrite smac(0x00, 0x55, 0x44, 0x33, 0x22, 0x11)\n");

	err = nse_eswitch_add_tc_fltr(vsi, fltr);
	if (err)
		dev_err(dev, "Failed to action_rw_smac, err = %d\n", err);

	kfree(fltr);
}

void nse_debugfs_ovs_fltr_action_au_nop(struct nse_hw *hw)
{
	struct nse_pf *pf = (struct nse_pf *)hw->back;
	struct nse_vsi *vsi;
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_tc_flower_fltr *fltr;
	u8 mac_addr[ETH_ALEN] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
	u8 mac_mask[ETH_ALEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xf0};
	int err;

	fltr = kzalloc(sizeof(*fltr), GFP_KERNEL);
	if (!fltr)
		return;

	vsi = nse_get_main_vsi(pf);
	if (!vsi) {
		dev_err(dev, "get src vsi err!\n");
		kfree(fltr);
		return;
	}
	/*for initial*/
	fltr->src_vsi = vsi;
	INIT_HLIST_NODE(&fltr->tc_flower_node);
	fltr->action.large_act_id = NSE_TC_FLWR_LARGE_ACTION_INVALID;
	fltr->action.vsi_list_id = NSE_TC_FLWR_VSI_LIST_ID_INVALID;

	/*for current test case*/
	fltr->tunnel_type = TNL_LAST;
	fltr->flags |= NSE_TC_FLWR_FIELD_DST_MAC;
	ether_addr_copy(fltr->outer_headers.l2_key.dst_mac, mac_addr);
	ether_addr_copy(fltr->outer_headers.l2_mask.dst_mac, mac_mask);

	fltr->action.flags |= NSE_TC_FLWR_ACTION_FWD_VSI | NSE_TC_FLWR_ACTION_COUNT |
		NSE_TC_FLWR_ACTION_ALLOW;
	fltr->action.fltr_act = NSE_FWD_TO_VSI;
	fltr->action.dest_cnt = 1;
	fltr->action.dests[0].dest_vsi = vsi;

	dev_info(dev, "Start to action_au_nop:\n");
	dev_info(dev, "\t match: dmac(0x00, 0x11, 0x22, 0x33, 0x44, 0x5*)/44\n");
	dev_info(dev, "\t action: forward to main Vsi with default count\n");
	dev_info(dev, "\t action: nop task(through AU but do nothing)\n");

	err = nse_eswitch_add_tc_fltr(vsi, fltr);
	if (err)
		dev_err(dev, "Failed to action_au_nop, err = %d\n", err);

	kfree(fltr);
}

void nse_debugfs_ovs_fltr_action_meter(struct nse_hw *hw,
		u32 rate, u32 burst)
{
	struct nse_pf *pf = (struct nse_pf *)hw->back;
	struct nse_vsi *vsi;
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_tc_flower_fltr *fltr;
	u8 mac_addr[ETH_ALEN] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
	u8 mac_mask[ETH_ALEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xf0};
	int err;
	static u32 index;

	fltr = kzalloc(sizeof(*fltr), GFP_KERNEL);
	if (!fltr)
		return;

	vsi = nse_get_main_vsi(pf);
	if (!vsi) {
		dev_err(dev, "get src vsi err!\n");
		kfree(fltr);
		return;
	}
	/*for initial*/
	fltr->src_vsi = vsi;
	INIT_HLIST_NODE(&fltr->tc_flower_node);
	fltr->action.large_act_id = NSE_TC_FLWR_LARGE_ACTION_INVALID;
	fltr->action.vsi_list_id = NSE_TC_FLWR_VSI_LIST_ID_INVALID;

	/*for current test case*/
	fltr->tunnel_type = TNL_LAST;
	fltr->flags |= NSE_TC_FLWR_FIELD_DST_MAC;
	ether_addr_copy(fltr->outer_headers.l2_key.dst_mac, mac_addr);
	ether_addr_copy(fltr->outer_headers.l2_mask.dst_mac, mac_mask);

	fltr->action.flags |= NSE_TC_FLWR_ACTION_FWD_VSI | NSE_TC_FLWR_ACTION_COUNT |
		NSE_TC_FLWR_ACTION_METER;
	fltr->action.fltr_act = NSE_FWD_TO_VSI;
	fltr->action.dest_cnt = 1;
	fltr->action.dests[0].dest_vsi = vsi;
	fltr->action.meter_param.mode = NSE_RATE_LIMIT_BPS;
	fltr->action.meter_param.index = ++index;
	fltr->action.meter_param.burst = burst;
	fltr->action.meter_param.rate = (u64)rate;

	dev_info(dev, "Start to action_meter:\n");
	dev_info(dev, "\t match: dmac(0x00, 0x11, 0x22, 0x33, 0x44, 0x5*)/44\n");
	dev_info(dev, "\t action: forward to main Vsi with default count\n");
	dev_info(dev, "\t action: meter(rate = %d, burst = %d)\n", rate, burst);

	err = nse_eswitch_add_tc_fltr(vsi, fltr);
	if (err)
		dev_err(dev, "Failed to action_meter, err = %d\n", err);

	kfree(fltr);
}

void nse_debugfs_ovs_fltr_action_decap(struct nse_hw *hw)
{
	struct nse_pf *pf = (struct nse_pf *)hw->back;
	struct nse_vsi *vsi;
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_tc_flower_fltr *fltr;
	int err;

	fltr = kzalloc(sizeof(*fltr), GFP_KERNEL);
	if (!fltr)
		return;

	vsi = nse_get_main_vsi(pf);
	if (!vsi) {
		dev_err(dev, "get src vsi err!\n");
		kfree(fltr);
		return;
	}
	/*for initial*/
	fltr->src_vsi = vsi;
	INIT_HLIST_NODE(&fltr->tc_flower_node);
	fltr->action.large_act_id = NSE_TC_FLWR_LARGE_ACTION_INVALID;
	fltr->action.vsi_list_id = NSE_TC_FLWR_VSI_LIST_ID_INVALID;

	/*for current test case*/
	fltr->tunnel_type = TNL_VXLAN;
	fltr->flags |= NSE_TC_FLWR_FIELD_ENC_SRC_IPV4;
	fltr->outer_headers.l3_key.src_ipv4 = in_aton("10.11.12.13");
	fltr->outer_headers.l3_mask.src_ipv4 = in_aton("255.255.255.255");

	fltr->action.flags |= NSE_TC_FLWR_ACTION_FWD_VSI_LIST | NSE_TC_FLWR_ACTION_COUNT |
						NSE_TC_FLWR_ACTION_DECAP;
	fltr->action.fltr_act = NSE_FWD_TO_VSI;
	fltr->action.dest_cnt = 1;
	fltr->action.dests[0].dest_vsi = vsi;

	dev_info(dev, "Start to action_decap:\n");
	dev_info(dev, "\tvxlan_o_sip(10.11.12.13/32)\n");
	dev_info(dev, "\t action: forward to Vsi with default count, and decap\n");

	err = nse_eswitch_add_tc_fltr(vsi, fltr);
	if (err)
		dev_err(dev, "Failed to action_decap, err = %d\n", err);

	kfree(fltr);
}

void nse_debugfs_ovs_fltr_action_tovsilist(struct nse_hw *hw)
{
	struct nse_pf *pf = (struct nse_pf *)hw->back;
	struct nse_vsi *vsi;
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_tc_flower_fltr *fltr;
	u8 mac_addr[ETH_ALEN] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
	u8 mac_mask[ETH_ALEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xf0};
	int err;

	fltr = kzalloc(sizeof(*fltr), GFP_KERNEL);
	if (!fltr)
		return;

	vsi = nse_get_main_vsi(pf);
	if (!vsi) {
		dev_err(dev, "get src vsi err!\n");
		kfree(fltr);
		return;
	}
	/*for initial*/
	fltr->src_vsi = vsi;
	INIT_HLIST_NODE(&fltr->tc_flower_node);
	fltr->action.large_act_id = NSE_TC_FLWR_LARGE_ACTION_INVALID;
	fltr->action.vsi_list_id = NSE_TC_FLWR_VSI_LIST_ID_INVALID;

	/*for current test case*/
	fltr->tunnel_type = TNL_LAST;
	fltr->flags |= NSE_TC_FLWR_FIELD_DST_MAC;
	ether_addr_copy(fltr->outer_headers.l2_key.dst_mac, mac_addr);
	ether_addr_copy(fltr->outer_headers.l2_mask.dst_mac, mac_mask);

	fltr->action.flags |= NSE_TC_FLWR_ACTION_FWD_VSI_LIST | NSE_TC_FLWR_ACTION_COUNT;
	fltr->action.fltr_act = NSE_FWD_TO_VSI_LIST;
	fltr->action.dest_cnt = 1;
	fltr->action.dests[0].dest_vsi = vsi;

	dev_info(dev, "Start to action_tovsilist:\n");
	dev_info(dev, "\t match: dmac(0x00, 0x11, 0x22, 0x33, 0x44, 0x5*)/44\n");
	dev_info(dev, "\t action: forward to Vsi List with default count\n");

	err = nse_eswitch_add_tc_fltr(vsi, fltr);
	if (err)
		dev_err(dev, "Failed to action_tovsilist, err = %d\n", err);

	kfree(fltr);
}

void nse_debugfs_ovs_fltr_action_add_del2(struct nse_hw *hw,
	u32 num, u32 loop, u32 delay)
{
	struct nse_pf *pf = (struct nse_pf *)hw->back;
	struct nse_vsi *vsi;
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_tc_flower_fltr **fltr = NULL;
	u8 mac_addr[ETH_ALEN] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x00};
	u8 mac_mask[ETH_ALEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
	int err, i, j;
	unsigned long start, end;
	u32 ori_lp = loop;

	if (!loop) {
		dev_err(dev, "loop = 0 is not supported\n");
		return;
	}

	fltr = kcalloc(num, sizeof(struct nse_tc_flower_fltr *), GFP_KERNEL);
	if (!fltr)
		return;
	for (i = 0; i < num; i++) {
		fltr[i] = kzalloc(sizeof(struct nse_tc_flower_fltr), GFP_KERNEL);
		if (!fltr[i]) {
			for (j = 0; j < i; j++)
				kfree(fltr[j]);
			return;
		}
	}

	vsi = nse_get_main_vsi(pf);
	if (!vsi) {
		dev_err(dev, "get src vsi err!\n");
		goto free_fltr;
	}

	dev_info(dev, "Start to add_del %d Nodes, Loop %d times, delay %d ms\n",
		num, loop, delay);

	start = jiffies;

	do {
		for (i = 0; i < num; i++) {
			eth_random_addr(mac_addr);

			/*for initial*/
			memset(fltr[i], 0, sizeof(struct nse_tc_flower_fltr));
			fltr[i]->src_vsi = vsi;
			INIT_HLIST_NODE(&fltr[i]->tc_flower_node);
			fltr[i]->action.large_act_id = NSE_TC_FLWR_LARGE_ACTION_INVALID;
			fltr[i]->action.vsi_list_id = NSE_TC_FLWR_VSI_LIST_ID_INVALID;

			/*for current test case*/
			fltr[i]->tunnel_type = TNL_LAST;
			fltr[i]->flags |= NSE_TC_FLWR_FIELD_DST_MAC;
			ether_addr_copy(fltr[i]->outer_headers.l2_key.dst_mac, mac_addr);
			ether_addr_copy(fltr[i]->outer_headers.l2_mask.dst_mac, mac_mask);

			fltr[i]->action.flags |= NSE_TC_FLWR_ACTION_FWD_VSI |
				NSE_TC_FLWR_ACTION_COUNT;
			fltr[i]->action.fltr_act = NSE_FWD_TO_VSI;
			fltr[i]->action.dest_cnt = 1;
			fltr[i]->action.dests[0].dest_vsi = vsi;

			err = nse_eswitch_add_tc_fltr(vsi, fltr[i]);
			if (err)
				dev_err(dev, "Failed to action_add_del, err = %d\n", err);
		}

		mdelay(delay);

		for (i = 0; i < num; i++)
			nse_del_tc_fltr(vsi, fltr[i]);

	} while (--loop);

	end = jiffies;

	dev_info(dev, "takes %u msecs to operate node %d times\n",
		jiffies_to_msecs(end - start), num * ori_lp * 2);

free_fltr:
	for (i = 0; i < num; i++)
		kfree(fltr[i]);

	kfree(fltr);
}

void nse_debugfs_ovs_fltr_action_add_del(struct nse_hw *hw,
	u32 num, u32 loop, u32 delay)
{
	struct nse_pf *pf = (struct nse_pf *)hw->back;
	struct nse_vsi *vsi;
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_tc_flower_fltr *fltr[100];
	u8 mac_addr[ETH_ALEN] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x00};
	u8 mac_mask[ETH_ALEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
	int err, i, j;
	unsigned long start, end;
	u32 ori_lp = loop;

	if (num > 100 || !loop) {
		dev_err(dev, "Mac addr count is up to 100\n");
		return;
	}

	if (!loop) {
		dev_err(dev, "loop = 0 is not supported\n");
		return;
	}
	for (i = 0; i < num; i++) {
		fltr[i] = kzalloc(sizeof(struct nse_tc_flower_fltr), GFP_KERNEL);
		if (!fltr[i]) {
			for (j = 0; j < i; j++)
				kfree(fltr[j]);
			return;
		}
	}
	vsi = nse_get_main_vsi(pf);
	if (!vsi) {
		dev_err(dev, "get src vsi err!\n");
		goto free_fltr;
	}

	dev_info(dev, "Start to add_del %d Nodes, Loop %d times, delay %d ms\n",
		num, loop, delay);
	dev_info(dev, "Mac address from %pM\n", mac_addr);

	start = jiffies;

	do {
		mac_addr[5] = 0;

		for (i = 0; i < num; i++) {
			/*for initial*/
			memset(fltr[i], 0, sizeof(struct nse_tc_flower_fltr));
			fltr[i]->src_vsi = vsi;
			INIT_HLIST_NODE(&fltr[i]->tc_flower_node);
			fltr[i]->action.large_act_id = NSE_TC_FLWR_LARGE_ACTION_INVALID;
			fltr[i]->action.vsi_list_id = NSE_TC_FLWR_VSI_LIST_ID_INVALID;

			/*for current test case*/
			fltr[i]->tunnel_type = TNL_LAST;
			fltr[i]->flags |= NSE_TC_FLWR_FIELD_DST_MAC;
			ether_addr_copy(fltr[i]->outer_headers.l2_key.dst_mac, mac_addr);
			ether_addr_copy(fltr[i]->outer_headers.l2_mask.dst_mac, mac_mask);

			fltr[i]->action.flags |= NSE_TC_FLWR_ACTION_FWD_VSI |
				NSE_TC_FLWR_ACTION_COUNT;
			fltr[i]->action.fltr_act = NSE_FWD_TO_VSI;
			fltr[i]->action.dest_cnt = 1;
			fltr[i]->action.dests[0].dest_vsi = vsi;

			err = nse_eswitch_add_tc_fltr(vsi, fltr[i]);
			if (err)
				dev_err(dev, "Failed to action_add_del, err = %d\n", err);

			mac_addr[5]++;
		}

		mdelay(delay);

		for (i = 0; i < num; i++)
			nse_del_tc_fltr(vsi, fltr[i]);

	} while (--loop);

	end = jiffies;

	dev_info(dev, "takes %u msecs to operate node %d times\n",
		jiffies_to_msecs(end - start), num * ori_lp * 2);

free_fltr:
	for (i = 0; i < num; i++)
		kfree(fltr[i]);
}

void nse_debugfs_ovs_fltr_action_tovsi(struct nse_hw *hw)
{
	struct nse_pf *pf = (struct nse_pf *)hw->back;
	struct nse_vsi *vsi;
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_tc_flower_fltr *fltr;
	u8 mac_addr[ETH_ALEN] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
	u8 mac_mask[ETH_ALEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xf0};
	int err;

	fltr = kzalloc(sizeof(*fltr), GFP_KERNEL);
	if (!fltr)
		return;

	vsi = nse_get_main_vsi(pf);
	if (!vsi) {
		dev_err(dev, "get src vsi err!\n");
		kfree(fltr);
		return;
	}
	/*for initial*/
	fltr->src_vsi = vsi;
	INIT_HLIST_NODE(&fltr->tc_flower_node);
	fltr->action.large_act_id = NSE_TC_FLWR_LARGE_ACTION_INVALID;
	fltr->action.vsi_list_id = NSE_TC_FLWR_VSI_LIST_ID_INVALID;

	/*for current test case*/
	fltr->tunnel_type = TNL_LAST;
	fltr->flags |= NSE_TC_FLWR_FIELD_DST_MAC;
	ether_addr_copy(fltr->outer_headers.l2_key.dst_mac, mac_addr);
	ether_addr_copy(fltr->outer_headers.l2_mask.dst_mac, mac_mask);

	fltr->action.flags |= NSE_TC_FLWR_ACTION_FWD_VSI | NSE_TC_FLWR_ACTION_COUNT;
	fltr->action.fltr_act = NSE_FWD_TO_VSI;
	fltr->action.dest_cnt = 1;
	fltr->action.dests[0].dest_vsi = vsi;

	dev_info(dev, "Start to action_tovsi:\n");
	dev_info(dev, "\t match: dmac(0x00, 0x11, 0x22, 0x33, 0x44, 0x5*)/44\n");
	dev_info(dev, "\t action: forward to main Vsi with default count\n");

	err = nse_eswitch_add_tc_fltr(vsi, fltr);
	if (err)
		dev_err(dev, "Failed to action_tovsi, err = %d\n", err);

	kfree(fltr);
}

void nse_debugfs_ovs_fltr_action_tovsilist_wo_cnt(struct nse_hw *hw)
{
	struct nse_pf *pf = (struct nse_pf *)hw->back;
	struct nse_vsi *vsi;
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_tc_flower_fltr *fltr;
	u8 mac_addr[ETH_ALEN] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
	u8 mac_mask[ETH_ALEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xf0};
	int err;

	fltr = kzalloc(sizeof(*fltr), GFP_KERNEL);
	if (!fltr)
		return;

	vsi = nse_get_main_vsi(pf);
	if (!vsi) {
		dev_err(dev, "get src vsi err!\n");
		kfree(fltr);
		return;
	}
	/*for initial*/
	fltr->src_vsi = vsi;
	INIT_HLIST_NODE(&fltr->tc_flower_node);
	fltr->action.large_act_id = NSE_TC_FLWR_LARGE_ACTION_INVALID;
	fltr->action.vsi_list_id = NSE_TC_FLWR_VSI_LIST_ID_INVALID;

	/*for current test case*/
	fltr->tunnel_type = TNL_LAST;
	fltr->flags |= NSE_TC_FLWR_FIELD_DST_MAC;
	ether_addr_copy(fltr->outer_headers.l2_key.dst_mac, mac_addr);
	ether_addr_copy(fltr->outer_headers.l2_mask.dst_mac, mac_mask);

	fltr->action.flags |= NSE_TC_FLWR_ACTION_FWD_VSI_LIST;
	fltr->action.fltr_act = NSE_FWD_TO_VSI_LIST;
	fltr->action.dest_cnt = 1;
	fltr->action.dests[0].dest_vsi = vsi;

	dev_info(dev, "Start to action_tovsilist_wo_cnt:\n");
	dev_info(dev, "\t match: dmac(0x00, 0x11, 0x22, 0x33, 0x44, 0x5*)/44\n");
	dev_info(dev, "\t action: forward to Vsi List without default count\n");

	err = nse_eswitch_add_tc_fltr(vsi, fltr);
	if (err)
		dev_err(dev, "Failed to action_tovsilist_wo_cnt, err = %d\n", err);

	kfree(fltr);
}

void nse_debugfs_ovs_fltr_action_tovsi_wo_cnt(struct nse_hw *hw)
{
	struct nse_pf *pf = (struct nse_pf *)hw->back;
	struct nse_vsi *vsi;
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_tc_flower_fltr *fltr;
	u8 mac_addr[ETH_ALEN] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
	u8 mac_mask[ETH_ALEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xf0};
	int err;

	fltr = kzalloc(sizeof(*fltr), GFP_KERNEL);
	if (!fltr)
		return;

	vsi = nse_get_main_vsi(pf);
	if (!vsi) {
		dev_err(dev, "get src vsi err!\n");
		kfree(fltr);
		return;
	}
	/*for initial*/
	fltr->src_vsi = vsi;
	INIT_HLIST_NODE(&fltr->tc_flower_node);
	fltr->action.large_act_id = NSE_TC_FLWR_LARGE_ACTION_INVALID;
	fltr->action.vsi_list_id = NSE_TC_FLWR_VSI_LIST_ID_INVALID;

	/*for current test case*/
	fltr->tunnel_type = TNL_LAST;
	fltr->flags |= NSE_TC_FLWR_FIELD_DST_MAC;
	ether_addr_copy(fltr->outer_headers.l2_key.dst_mac, mac_addr);
	ether_addr_copy(fltr->outer_headers.l2_mask.dst_mac, mac_mask);

	fltr->action.flags |= NSE_TC_FLWR_ACTION_FWD_VSI;
	fltr->action.fltr_act = NSE_FWD_TO_VSI;
	fltr->action.dest_cnt = 1;
	fltr->action.dests[0].dest_vsi = vsi;

	dev_info(dev, "Start to action_tovsi_wo_cnt:\n");
	dev_info(dev, "\t match: dmac(0x00, 0x11, 0x22, 0x33, 0x44, 0x5*)/44\n");
	dev_info(dev, "\t action: forward to main Vsi without default count\n");

	err = nse_eswitch_add_tc_fltr(vsi, fltr);
	if (err)
		dev_err(dev, "Failed to action_tovsi_wo_cnt, err = %d\n", err);

	kfree(fltr);
}

void nse_debugfs_ovs_fltr_add_vxlan_i_dipv6_rx(struct nse_hw *hw)
{
	struct nse_pf *pf = (struct nse_pf *)hw->back;
	struct nse_vsi *vsi;
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_tc_flower_fltr *fltr;
	u8 ipv6_addr[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
						0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
	u8 ipv6_mask[16] = {0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
						0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff};
	int err;

	fltr = kzalloc(sizeof(*fltr), GFP_KERNEL);
	if (!fltr)
		return;

	vsi = nse_get_main_vsi(pf);
	if (!vsi) {
		dev_err(dev, "get src vsi err!\n");
		kfree(fltr);
		return;
	}
	/*for initial*/
	fltr->src_vsi = vsi;
	INIT_HLIST_NODE(&fltr->tc_flower_node);
	fltr->action.large_act_id = NSE_TC_FLWR_LARGE_ACTION_INVALID;
	fltr->action.vsi_list_id = NSE_TC_FLWR_VSI_LIST_ID_INVALID;

	/*for current test case*/
	fltr->tunnel_type = TNL_VXLAN;
	fltr->flags |= NSE_TC_FLWR_FIELD_DEST_IPV6;
	memcpy(fltr->inner_headers.l3_key.dst_ipv6_addr, ipv6_addr, 16);
	memcpy(fltr->inner_headers.l3_mask.dst_ipv6_addr, ipv6_mask, 16);

	fltr->action.flags |= NSE_TC_FLWR_ACTION_DROP | NSE_TC_FLWR_ACTION_COUNT;
	fltr->action.fltr_act = NSE_DROP_PACKET;

	dev_info(dev, "Start to add_vxlan_i_dipv6_rx:\n");

	dev_info(dev, "\tvxlan_i_dipv6(0011::eeff): aciton(drop)\n");

	err = nse_eswitch_add_tc_fltr(vsi, fltr);
	if (err)
		dev_err(dev, "Failed to add_vxlan_i_dipv6_rx, err = %d\n", err);

	kfree(fltr);
}

void nse_debugfs_ovs_fltr_add_vxlan_i_tcp_sport_rx(struct nse_hw *hw)
{
	struct nse_pf *pf = (struct nse_pf *)hw->back;
	struct nse_vsi *vsi;
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_tc_flower_fltr *fltr;
	int err;

	fltr = kzalloc(sizeof(*fltr), GFP_KERNEL);
	if (!fltr)
		return;

	vsi = nse_get_main_vsi(pf);
	if (!vsi) {
		dev_err(dev, "get src vsi err!\n");
		kfree(fltr);
		return;
	}
	/*for initial*/
	fltr->src_vsi = vsi;
	INIT_HLIST_NODE(&fltr->tc_flower_node);
	fltr->action.large_act_id = NSE_TC_FLWR_LARGE_ACTION_INVALID;
	fltr->action.vsi_list_id = NSE_TC_FLWR_VSI_LIST_ID_INVALID;

	/*for current test case*/
	fltr->tunnel_type = TNL_VXLAN;
	fltr->flags |= NSE_TC_FLWR_FIELD_SRC_L4_PORT;

	fltr->inner_headers.l3_key.ip_proto = IPPROTO_TCP;
	fltr->inner_headers.l3_mask.ip_proto = 0xFF;
	fltr->inner_headers.l4_key.src_port = htons(0xe2ba);
	fltr->inner_headers.l4_mask.src_port = htons(0xFFFF);

	fltr->action.flags |= NSE_TC_FLWR_ACTION_DROP | NSE_TC_FLWR_ACTION_COUNT;
	fltr->action.fltr_act = NSE_DROP_PACKET;

	dev_info(dev, "Start to add_vxlan_i_sport_rx:\n");

	dev_info(dev, "\tvxlan_i_sport(0xe2ba/16): aciton(drop)\n");

	err = nse_eswitch_add_tc_fltr(vsi, fltr);
	if (err)
		dev_err(dev, "Failed to add_vxlan_i_sport_rx, err = %d\n", err);

	kfree(fltr);
}

void nse_debugfs_ovs_fltr_add_vxlan_i_udp_sport_rx(struct nse_hw *hw)
{
	struct nse_pf *pf = (struct nse_pf *)hw->back;
	struct nse_vsi *vsi;
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_tc_flower_fltr *fltr;
	int err;

	fltr = kzalloc(sizeof(*fltr), GFP_KERNEL);
	if (!fltr)
		return;

	vsi = nse_get_main_vsi(pf);
	if (!vsi) {
		dev_err(dev, "get src vsi err!\n");
		kfree(fltr);
		return;
	}
	/*for initial*/
	fltr->src_vsi = vsi;
	INIT_HLIST_NODE(&fltr->tc_flower_node);
	fltr->action.large_act_id = NSE_TC_FLWR_LARGE_ACTION_INVALID;
	fltr->action.vsi_list_id = NSE_TC_FLWR_VSI_LIST_ID_INVALID;

	/*for current test case*/
	fltr->tunnel_type = TNL_VXLAN;
	fltr->flags |= NSE_TC_FLWR_FIELD_SRC_L4_PORT;

	fltr->inner_headers.l3_key.ip_proto = IPPROTO_UDP;
	fltr->inner_headers.l3_mask.ip_proto = 0xFF;
	fltr->inner_headers.l4_key.src_port = htons(0x1234);
	fltr->inner_headers.l4_mask.src_port = htons(0xFFFF);

	fltr->action.flags |= NSE_TC_FLWR_ACTION_DROP  | NSE_TC_FLWR_ACTION_COUNT;
	fltr->action.fltr_act = NSE_DROP_PACKET;

	dev_info(dev, "Start to add_vxlan_i_sport_rx:\n");

	dev_info(dev, "\tvxlan_i_sport(0x1234/16): aciton(drop)\n");

	err = nse_eswitch_add_tc_fltr(vsi, fltr);
	if (err)
		dev_err(dev, "Failed to add_vxlan_i_sport_rx, err = %d\n", err);

	kfree(fltr);
}

void nse_debugfs_ovs_fltr_add_vxlan_i_dip_rx(struct nse_hw *hw)
{
	struct nse_pf *pf = (struct nse_pf *)hw->back;
	struct nse_vsi *vsi;
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_tc_flower_fltr *fltr;
	int err;

	fltr = kzalloc(sizeof(*fltr), GFP_KERNEL);
	if (!fltr)
		return;

	vsi = nse_get_main_vsi(pf);
	if (!vsi) {
		dev_err(dev, "get src vsi err!\n");
		kfree(fltr);
		return;
	}
	/*for initial*/
	fltr->src_vsi = vsi;
	INIT_HLIST_NODE(&fltr->tc_flower_node);
	fltr->action.large_act_id = NSE_TC_FLWR_LARGE_ACTION_INVALID;
	fltr->action.vsi_list_id = NSE_TC_FLWR_VSI_LIST_ID_INVALID;

	/*for current test case*/
	fltr->tunnel_type = TNL_VXLAN;
	fltr->flags |= NSE_TC_FLWR_FIELD_DEST_IPV4;

	fltr->inner_headers.l3_key.dst_ipv4 = in_aton("1.2.3.4");
	fltr->inner_headers.l3_mask.dst_ipv4 = in_aton("255.255.255.255");

	fltr->action.flags |= NSE_TC_FLWR_ACTION_DROP | NSE_TC_FLWR_ACTION_COUNT;
	fltr->action.fltr_act = NSE_DROP_PACKET;

	dev_info(dev, "Start to add_vxlan_i_dip_rx:\n");

	dev_info(dev, "\tvxlan_i_dip(1.2.3.4/32): aciton(drop)\n");

	err = nse_eswitch_add_tc_fltr(vsi, fltr);
	if (err)
		dev_err(dev, "Failed to add_vxlan_i_dip_rx, err = %d\n", err);

	kfree(fltr);
}

void nse_debugfs_ovs_fltr_add_vxlan_i_ethtype_rx(struct nse_hw *hw)
{
	struct nse_pf *pf = (struct nse_pf *)hw->back;
	struct nse_vsi *vsi;
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_tc_flower_fltr *fltr;
	int err;

	fltr = kzalloc(sizeof(*fltr), GFP_KERNEL);
	if (!fltr)
		return;

	vsi = nse_get_main_vsi(pf);
	if (!vsi) {
		dev_err(dev, "get src vsi err!\n");
		kfree(fltr);
		return;
	}
	/*for initial*/
	fltr->src_vsi = vsi;
	INIT_HLIST_NODE(&fltr->tc_flower_node);
	fltr->action.large_act_id = NSE_TC_FLWR_LARGE_ACTION_INVALID;
	fltr->action.vsi_list_id = NSE_TC_FLWR_VSI_LIST_ID_INVALID;

	/*for current test case*/
	fltr->tunnel_type = TNL_VXLAN;
	fltr->flags |= NSE_TC_FLWR_FIELD_ETH_TYPE;

	fltr->inner_headers.l2_key.n_proto = cpu_to_be16(0x0806);
	fltr->inner_headers.l2_mask.n_proto = cpu_to_be16(0xFFFF);

	fltr->action.flags |= NSE_TC_FLWR_ACTION_DROP | NSE_TC_FLWR_ACTION_COUNT;
	fltr->action.fltr_act = NSE_DROP_PACKET;

	dev_info(dev, "Start to add_vxlan_i_ethtype_rx:\n");

	dev_info(dev, "\tvxlan_i_ethtype(0x0806/16): aciton(drop)\n");

	err = nse_eswitch_add_tc_fltr(vsi, fltr);
	if (err)
		dev_err(dev, "Failed to add_vxlan_i_ethtype_rx, err = %d\n", err);

	kfree(fltr);
}

void nse_debugfs_ovs_fltr_add_vxlan_i_dmac_rx(struct nse_hw *hw)
{
	struct nse_pf *pf = (struct nse_pf *)hw->back;
	struct nse_vsi *vsi;
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_tc_flower_fltr *fltr;
	int err;
	u8 mac_addr[ETH_ALEN] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
	u8 mac_mask[ETH_ALEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xf0};

	fltr = kzalloc(sizeof(*fltr), GFP_KERNEL);
	if (!fltr)
		return;

	vsi = nse_get_main_vsi(pf);
	if (!vsi) {
		dev_err(dev, "get src vsi err!\n");
		kfree(fltr);
		return;
	}
	/*for initial*/
	fltr->src_vsi = vsi;
	INIT_HLIST_NODE(&fltr->tc_flower_node);
	fltr->action.large_act_id = NSE_TC_FLWR_LARGE_ACTION_INVALID;
	fltr->action.vsi_list_id = NSE_TC_FLWR_VSI_LIST_ID_INVALID;

	/*for current test case*/
	fltr->tunnel_type = TNL_VXLAN;
	fltr->flags |= NSE_TC_FLWR_FIELD_DST_MAC;
	ether_addr_copy(fltr->inner_headers.l2_key.dst_mac, mac_addr);
	ether_addr_copy(fltr->inner_headers.l2_mask.dst_mac, mac_mask);

	fltr->action.flags |= NSE_TC_FLWR_ACTION_DROP | NSE_TC_FLWR_ACTION_COUNT;
	fltr->action.fltr_act = NSE_DROP_PACKET;

	dev_info(dev, "Start to add_vxlan_i_dmac_rx:\n");

	dev_info(dev, "\tvxlan_i_dmac(0x00, 0x11, 0x22, 0x33, 0x44, 0x55/44): aciton(drop)\n");

	err = nse_eswitch_add_tc_fltr(vsi, fltr);
	if (err)
		dev_err(dev, "Failed to add_vxlan_i_dmac_rx, err = %d\n", err);

	kfree(fltr);
}

void nse_debugfs_ovs_fltr_add_vxlan_key_id_rx(struct nse_hw *hw)
{
	struct nse_pf *pf = (struct nse_pf *)hw->back;
	struct nse_vsi *vsi;
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_tc_flower_fltr *fltr;
	int err;

	fltr = kzalloc(sizeof(*fltr), GFP_KERNEL);
	if (!fltr)
		return;

	vsi = nse_get_main_vsi(pf);
	if (!vsi) {
		dev_err(dev, "get src vsi err!\n");
		kfree(fltr);
		return;
	}
	/*for initial*/
	fltr->src_vsi = vsi;
	INIT_HLIST_NODE(&fltr->tc_flower_node);
	fltr->action.large_act_id = NSE_TC_FLWR_LARGE_ACTION_INVALID;
	fltr->action.vsi_list_id = NSE_TC_FLWR_VSI_LIST_ID_INVALID;

	/*for current test case*/
	fltr->tunnel_type = TNL_VXLAN;
	fltr->flags |= NSE_TC_FLWR_FIELD_TENANT_ID;
	fltr->tenant_id = cpu_to_be32(0x10);

	fltr->action.flags |= NSE_TC_FLWR_ACTION_DROP | NSE_TC_FLWR_ACTION_COUNT;
	fltr->action.fltr_act = NSE_DROP_PACKET;

	dev_info(dev, "Start to add_vxlan_key_id_rx:\n");

	dev_info(dev, "\tvxlan_key_id(val=16): aciton(drop)\n");

	err = nse_eswitch_add_tc_fltr(vsi, fltr);
	if (err)
		dev_err(dev, "Failed to add_vxlan_key_id_rx, err = %d\n", err);

	kfree(fltr);
}

void nse_debugfs_ovs_fltr_add_vxlan_o_dport_rx(struct nse_hw *hw)
{
	struct nse_pf *pf = (struct nse_pf *)hw->back;
	struct nse_vsi *vsi;
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_tc_flower_fltr *fltr;
	int err;

	fltr = kzalloc(sizeof(*fltr), GFP_KERNEL);
	if (!fltr)
		return;

	vsi = nse_get_main_vsi(pf);
	if (!vsi) {
		dev_err(dev, "get src vsi err!\n");
		kfree(fltr);
		return;
	}
	/*for initial*/
	fltr->src_vsi = vsi;
	INIT_HLIST_NODE(&fltr->tc_flower_node);
	fltr->action.large_act_id = NSE_TC_FLWR_LARGE_ACTION_INVALID;
	fltr->action.vsi_list_id = NSE_TC_FLWR_VSI_LIST_ID_INVALID;

	/*for current test case*/
	fltr->tunnel_type = TNL_VXLAN;
	fltr->flags |= NSE_TC_FLWR_FIELD_ENC_DEST_L4_PORT;

	fltr->outer_headers.l3_key.ip_proto = IPPROTO_UDP;
	fltr->outer_headers.l3_mask.ip_proto = 0xFF;
	fltr->outer_headers.l4_key.dst_port = htons(4789);
	fltr->outer_headers.l4_mask.dst_port = htons(0xFFFF);

	fltr->action.flags |= NSE_TC_FLWR_ACTION_DROP | NSE_TC_FLWR_ACTION_COUNT;
	fltr->action.fltr_act = NSE_DROP_PACKET;

	dev_info(dev, "Start to add_vxlan_o_dport_rx:\n");

	dev_info(dev, "\tvxlan_o_dport(val=4789): aciton(drop)\n");

	err = nse_eswitch_add_tc_fltr(vsi, fltr);
	if (err)
		dev_err(dev, "Failed to add_vxlan_o_dport_rx, err = %d\n", err);

	kfree(fltr);
}

void nse_debugfs_ovs_fltr_add_vxlan_o_sip_rx(struct nse_hw *hw)
{
	struct nse_pf *pf = (struct nse_pf *)hw->back;
	struct nse_vsi *vsi;
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_tc_flower_fltr *fltr;
	int err;

	fltr = kzalloc(sizeof(*fltr), GFP_KERNEL);
	if (!fltr)
		return;

	vsi = nse_get_main_vsi(pf);
	if (!vsi) {
		dev_err(dev, "get src vsi err!\n");
		kfree(fltr);
		return;
	}
	/*for initial*/
	fltr->src_vsi = vsi;
	INIT_HLIST_NODE(&fltr->tc_flower_node);
	fltr->action.large_act_id = NSE_TC_FLWR_LARGE_ACTION_INVALID;
	fltr->action.vsi_list_id = NSE_TC_FLWR_VSI_LIST_ID_INVALID;

	/*for current test case*/
	fltr->tunnel_type = TNL_VXLAN;
	fltr->flags |= NSE_TC_FLWR_FIELD_ENC_SRC_IPV4;

	fltr->outer_headers.l3_key.src_ipv4 = in_aton("10.11.12.13");
	fltr->outer_headers.l3_mask.src_ipv4 = in_aton("255.255.255.255");
	fltr->action.flags |= NSE_TC_FLWR_ACTION_DROP | NSE_TC_FLWR_ACTION_COUNT;
	fltr->action.fltr_act = NSE_DROP_PACKET;

	dev_info(dev, "Start to add_vxlan_o_sip_rx:\n");

	dev_info(dev, "\tvxlan_o_sip(10.11.12.13/32): aciton(drop)\n");

	err = nse_eswitch_add_tc_fltr(vsi, fltr);
	if (err)
		dev_err(dev, "Failed to add_vxlan_o_sip_rx, err = %d\n", err);

	kfree(fltr);
}

void nse_debugfs_ovs_fltr_add_vxlan_o_dmac_rx(struct nse_hw *hw)
{
	struct nse_pf *pf = (struct nse_pf *)hw->back;
	struct nse_vsi *vsi;
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_tc_flower_fltr *fltr;
	int err;
	u8 mac_addr[ETH_ALEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
	u8 mac_mask[ETH_ALEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

	fltr = kzalloc(sizeof(*fltr), GFP_KERNEL);
	if (!fltr)
		return;

	vsi = nse_get_main_vsi(pf);
	if (!vsi) {
		dev_err(dev, "get src vsi err!\n");
		kfree(fltr);
		return;
	}
	/*for initial*/
	fltr->src_vsi = vsi;
	INIT_HLIST_NODE(&fltr->tc_flower_node);
	fltr->action.large_act_id = NSE_TC_FLWR_LARGE_ACTION_INVALID;
	fltr->action.vsi_list_id = NSE_TC_FLWR_VSI_LIST_ID_INVALID;

	/*for current test case*/
	fltr->tunnel_type = TNL_VXLAN;
	fltr->flags |= NSE_TC_FLWR_FIELD_ENC_DST_MAC;
	ether_addr_copy(fltr->outer_headers.l2_key.dst_mac, mac_addr);
	ether_addr_copy(fltr->outer_headers.l2_mask.dst_mac, mac_mask);

	fltr->action.flags |= NSE_TC_FLWR_ACTION_DROP | NSE_TC_FLWR_ACTION_COUNT;
	fltr->action.fltr_act = NSE_DROP_PACKET;

	dev_info(dev, "Start to add_vxlan_o_dmac_rx(:\n");

	dev_info(dev, "\tvxlan_i_dmac(0xff, 0xff, 0xff, 0xff, 0xff, 0xff/48): aciton(drop)\n");

	err = nse_eswitch_add_tc_fltr(vsi, fltr);
	if (err)
		dev_err(dev, "Failed to add_vxlan_o_dmac_rx(, err = %d\n", err);

	kfree(fltr);
}

void nse_debugfs_ovs_fltr_add_sip_smac_rx(struct nse_hw *hw)
{
	struct nse_pf *pf = (struct nse_pf *)hw->back;
	struct nse_vsi *vsi;
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_tc_flower_fltr *fltr;
	u8 mac_addr[ETH_ALEN] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
	u8 mac_mask[ETH_ALEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
	int err;

	fltr = kzalloc(sizeof(*fltr), GFP_KERNEL);
	if (!fltr)
		return;

	vsi = nse_get_main_vsi(pf);
	if (!vsi) {
		dev_err(dev, "get src vsi err!\n");
		kfree(fltr);
		return;
	}
	/*for initial*/
	fltr->src_vsi = vsi;
	INIT_HLIST_NODE(&fltr->tc_flower_node);
	fltr->action.large_act_id = NSE_TC_FLWR_LARGE_ACTION_INVALID;
	fltr->action.vsi_list_id = NSE_TC_FLWR_VSI_LIST_ID_INVALID;

	/*for current test case*/
	fltr->tunnel_type = TNL_LAST;
	fltr->flags |= NSE_TC_FLWR_FIELD_SRC_IPV4;
	fltr->flags |= NSE_TC_FLWR_FIELD_SRC_MAC;
	ether_addr_copy(fltr->outer_headers.l2_key.src_mac, mac_addr);
	ether_addr_copy(fltr->outer_headers.l2_mask.src_mac, mac_mask);

	fltr->outer_headers.l3_key.src_ipv4 = in_aton("10.11.12.13");
	fltr->outer_headers.l3_mask.src_ipv4 = in_aton("255.255.255.255");
	fltr->action.flags |= NSE_TC_FLWR_ACTION_DROP | NSE_TC_FLWR_ACTION_COUNT;
	fltr->action.fltr_act = NSE_DROP_PACKET;

	dev_info(dev, "Start to add_sip_smac_rx:\n");

	dev_info(dev, "\tsip(10.11.12.13/32), smac(0x00, 0x11, 0x22, 0x33, 0x44, 0x55): aciton(drop)\n");

	err = nse_eswitch_add_tc_fltr(vsi, fltr);
	if (err)
		dev_err(dev, "Failed to add_sip_smac_rx, err = %d\n", err);

	kfree(fltr);
}

void nse_debugfs_ovs_fltr_add_dport_udp_rx(struct nse_hw *hw)
{
	struct nse_pf *pf = (struct nse_pf *)hw->back;
	struct nse_vsi *vsi;
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_tc_flower_fltr *fltr;
	int err;

	fltr = kzalloc(sizeof(*fltr), GFP_KERNEL);
	if (!fltr)
		return;

	vsi = nse_get_main_vsi(pf);
	if (!vsi) {
		dev_err(dev, "get src vsi err!\n");
		kfree(fltr);
		return;
	}
	/*for initial*/
	fltr->src_vsi = vsi;
	INIT_HLIST_NODE(&fltr->tc_flower_node);
	fltr->action.large_act_id = NSE_TC_FLWR_LARGE_ACTION_INVALID;
	fltr->action.vsi_list_id = NSE_TC_FLWR_VSI_LIST_ID_INVALID;

	/*for current test case*/
	fltr->tunnel_type = TNL_LAST;
	fltr->flags |= NSE_TC_FLWR_FIELD_DEST_L4_PORT;
	fltr->outer_headers.l3_key.ip_proto = IPPROTO_UDP;
	fltr->outer_headers.l3_mask.ip_proto = 0xFF;
	fltr->outer_headers.l4_key.dst_port = htons(0x1234);
	fltr->outer_headers.l4_mask.dst_port = htons(0xFFFF);
	fltr->action.flags |= NSE_TC_FLWR_ACTION_DROP | NSE_TC_FLWR_ACTION_COUNT;
	fltr->action.fltr_act = NSE_DROP_PACKET;

	dev_info(dev, "Start to add_dport_rx: match(udp, dport=0x1234/16) aciton(drop)\n");

	err = nse_eswitch_add_tc_fltr(vsi, fltr);
	if (err)
		dev_err(dev, "Failed to add_dport_rx, err = %d\n", err);

	kfree(fltr);
}

void nse_debugfs_ovs_fltr_add_dport_tcp_rx(struct nse_hw *hw)
{
	struct nse_pf *pf = (struct nse_pf *)hw->back;
	struct nse_vsi *vsi;
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_tc_flower_fltr *fltr;
	int err;

	fltr = kzalloc(sizeof(*fltr), GFP_KERNEL);
	if (!fltr)
		return;

	vsi = nse_get_main_vsi(pf);
	if (!vsi) {
		dev_err(dev, "get src vsi err!\n");
		kfree(fltr);
		return;
	}
	/*for initial*/
	fltr->src_vsi = vsi;
	INIT_HLIST_NODE(&fltr->tc_flower_node);
	fltr->action.large_act_id = NSE_TC_FLWR_LARGE_ACTION_INVALID;
	fltr->action.vsi_list_id = NSE_TC_FLWR_VSI_LIST_ID_INVALID;

	/*for current test case*/
	fltr->tunnel_type = TNL_LAST;
	fltr->flags |= NSE_TC_FLWR_FIELD_DEST_L4_PORT;
	fltr->outer_headers.l3_key.ip_proto = IPPROTO_TCP;
	fltr->outer_headers.l3_mask.ip_proto = 0xFF;
	fltr->outer_headers.l4_key.dst_port = htons(0x1234);
	fltr->outer_headers.l4_mask.dst_port = htons(0xFFFF);
	fltr->action.flags |= NSE_TC_FLWR_ACTION_DROP | NSE_TC_FLWR_ACTION_COUNT;
	fltr->action.fltr_act = NSE_DROP_PACKET;

	dev_info(dev, "Start to add_dport_rx: match(tcp, dport=0x1234/16) aciton(drop)\n");

	err = nse_eswitch_add_tc_fltr(vsi, fltr);
	if (err)
		dev_err(dev, "Failed to add_dport_rx, err = %d\n", err);

	kfree(fltr);
}

void nse_debugfs_ovs_fltr_add_dipv6_rx(struct nse_hw *hw)
{
	struct nse_pf *pf = (struct nse_pf *)hw->back;
	struct nse_vsi *vsi;
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_tc_flower_fltr *fltr;
	u8 ipv6_addr[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
						0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
	u8 ipv6_mask[16] = {0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
						0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff};
	int err;

	fltr = kzalloc(sizeof(*fltr), GFP_KERNEL);
	if (!fltr)
		return;

	vsi = nse_get_main_vsi(pf);
	if (!vsi) {
		dev_err(dev, "get src vsi err!\n");
		kfree(fltr);
		return;
	}
	/*for initial*/
	fltr->src_vsi = vsi;
	INIT_HLIST_NODE(&fltr->tc_flower_node);
	fltr->action.large_act_id = NSE_TC_FLWR_LARGE_ACTION_INVALID;
	fltr->action.vsi_list_id = NSE_TC_FLWR_VSI_LIST_ID_INVALID;

	/*for current test case*/
	fltr->tunnel_type = TNL_LAST;
	fltr->flags |= NSE_TC_FLWR_FIELD_DEST_IPV6;
	memcpy(fltr->outer_headers.l3_key.dst_ipv6_addr, ipv6_addr, 16);
	memcpy(fltr->outer_headers.l3_mask.dst_ipv6_addr, ipv6_mask, 16);

	fltr->action.flags |= NSE_TC_FLWR_ACTION_DROP | NSE_TC_FLWR_ACTION_COUNT;
	fltr->action.fltr_act = NSE_DROP_PACKET;

	dev_info(dev, "Start to add_dipv6_rx:(0011::eeff) aciton(drop)\n");

	err = nse_eswitch_add_tc_fltr(vsi, fltr);
	if (err)
		dev_err(dev, "Failed to add_dipv6_rx, err = %d\n", err);

	kfree(fltr);
}

void nse_debugfs_ovs_fltr_add_dip_rx(struct nse_hw *hw)
{
	struct nse_pf *pf = (struct nse_pf *)hw->back;
	struct nse_vsi *vsi;
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_tc_flower_fltr *fltr;
	int err;

	fltr = kzalloc(sizeof(*fltr), GFP_KERNEL);
	if (!fltr)
		return;

	vsi = nse_get_main_vsi(pf);
	if (!vsi) {
		dev_err(dev, "get src vsi err!\n");
		kfree(fltr);
		return;
	}
	/*for initial*/
	fltr->src_vsi = vsi;
	INIT_HLIST_NODE(&fltr->tc_flower_node);
	fltr->action.large_act_id = NSE_TC_FLWR_LARGE_ACTION_INVALID;
	fltr->action.vsi_list_id = NSE_TC_FLWR_VSI_LIST_ID_INVALID;

	/*for current test case*/
	fltr->tunnel_type = TNL_LAST;
	fltr->flags |= NSE_TC_FLWR_FIELD_DEST_IPV4;
	fltr->outer_headers.l3_key.dst_ipv4 = in_aton("1.2.3.4");
	fltr->outer_headers.l3_mask.dst_ipv4 = in_aton("255.255.255.255");
	fltr->action.flags |= NSE_TC_FLWR_ACTION_DROP | NSE_TC_FLWR_ACTION_COUNT;
	fltr->action.fltr_act = NSE_DROP_PACKET;

	dev_info(dev, "Start to add_dip_rx: match(1.2.3.4/32) aciton(drop)\n");

	err = nse_eswitch_add_tc_fltr(vsi, fltr);
	if (err)
		dev_err(dev, "Failed to add_dip_rx, err = %d\n", err);

	kfree(fltr);
}

void nse_debugfs_ovs_fltr_add_ethtype_rx(struct nse_hw *hw)
{
	struct nse_pf *pf = (struct nse_pf *)hw->back;
	struct nse_vsi *vsi;
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_tc_flower_fltr *fltr;
	int err;

	fltr = kzalloc(sizeof(*fltr), GFP_KERNEL);
	if (!fltr)
		return;

	vsi = nse_get_main_vsi(pf);
	if (!vsi) {
		dev_err(dev, "get src vsi err!\n");
		kfree(fltr);
		return;
	}
	/*for initial*/
	fltr->src_vsi = vsi;
	INIT_HLIST_NODE(&fltr->tc_flower_node);
	fltr->action.large_act_id = NSE_TC_FLWR_LARGE_ACTION_INVALID;
	fltr->action.vsi_list_id = NSE_TC_FLWR_VSI_LIST_ID_INVALID;

	/*for current test case*/
	fltr->tunnel_type = TNL_LAST;
	fltr->flags |= NSE_TC_FLWR_FIELD_ETH_TYPE;
	fltr->outer_headers.l2_key.n_proto = cpu_to_be16(0x0807);
	fltr->outer_headers.l2_mask.n_proto = cpu_to_be16(0xFFFF);

	fltr->action.flags |= NSE_TC_FLWR_ACTION_DROP | NSE_TC_FLWR_ACTION_COUNT;
	fltr->action.fltr_act = NSE_DROP_PACKET;

	dev_info(dev, "Start to add_ethtype_rx:(0x0807/16) aciton(drop)\n");

	err = nse_eswitch_add_tc_fltr(vsi, fltr);
	if (err)
		dev_err(dev, "Failed to add_ethtype_rx, err = %d\n", err);

	kfree(fltr);
}

void nse_debugfs_ovs_fltr_add_smac_rx(struct nse_hw *hw)
{
	struct nse_pf *pf = (struct nse_pf *)hw->back;
	struct nse_vsi *vsi;
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_tc_flower_fltr *fltr;
	u8 mac_addr[ETH_ALEN] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
	u8 mac_mask[ETH_ALEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xf0};
	int err;

	fltr = kzalloc(sizeof(*fltr), GFP_KERNEL);
	if (!fltr)
		return;

	vsi = nse_get_main_vsi(pf);
	if (!vsi) {
		dev_err(dev, "get src vsi err!\n");
		kfree(fltr);
		return;
	}
	/*for initial*/
	fltr->src_vsi = vsi;
	INIT_HLIST_NODE(&fltr->tc_flower_node);
	fltr->action.large_act_id = NSE_TC_FLWR_LARGE_ACTION_INVALID;
	fltr->action.vsi_list_id = NSE_TC_FLWR_VSI_LIST_ID_INVALID;

	/*for current test case*/
	fltr->tunnel_type = TNL_LAST;
	fltr->flags |= NSE_TC_FLWR_FIELD_SRC_MAC;
	ether_addr_copy(fltr->outer_headers.l2_key.src_mac, mac_addr);
	ether_addr_copy(fltr->outer_headers.l2_mask.src_mac, mac_mask);

	fltr->action.flags |= NSE_TC_FLWR_ACTION_DROP | NSE_TC_FLWR_ACTION_COUNT;
	fltr->action.fltr_act = NSE_DROP_PACKET;

	dev_info(dev, "Start to add_smac_rx:\n");

	dev_info(dev, "\tsmac(0x00, 0x11, 0x22, 0x33, 0x44, 0x5*)/44: aciton(drop)\n");

	err = nse_eswitch_add_tc_fltr(vsi, fltr);
	if (err)
		dev_err(dev, "Failed to add_smac_rx, err = %d\n", err);

	kfree(fltr);
}

void
nse_debugfs_ovs_fltr_del_single(struct nse_hw *hw, u8 lut_id, u16 node_id)
{
	struct nse_pf *pf = (struct nse_pf *)hw->back;
	struct nse_vsi *vsi;
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_tc_flower_fltr *fltr;

	fltr = kzalloc(sizeof(*fltr), GFP_KERNEL);
	if (!fltr)
		return;

	vsi = nse_get_main_vsi(pf);
	if (!vsi) {
		dev_err(dev, "get src vsi err!\n");
		kfree(fltr);
		return;
	}
	/*for initial*/
	fltr->src_vsi = vsi;
	INIT_HLIST_NODE(&fltr->tc_flower_node);
	fltr->action.large_act_id = NSE_TC_FLWR_LARGE_ACTION_INVALID;
	fltr->action.vsi_list_id = NSE_TC_FLWR_VSI_LIST_ID_INVALID;

	fltr->lut_id = lut_id;
	fltr->node_id = node_id;

	dev_info(dev, "Start to delete LUT[%d]_Node[%d]\n", lut_id, node_id);

	nse_del_tc_fltr(vsi, fltr);

	kfree(fltr);
}

void
nse_debugfs_ovs_fltr_del_du_data(struct nse_hw *hw)
{
	struct nse_pf *pf = (struct nse_pf *)hw->back;
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_sw_du_data *du_data = NULL;
	struct list_head *list_head = &hw->switch_info->ddata_list_head;
	int ret = 0;

	mutex_lock(&hw->switch_info->du_data_lock);
	list_for_each_entry(du_data, list_head, list_entry) {
		dev_info(dev, "Request to destroy du_data[%d], data_size = %d\n",
			du_data->du_desc.du_data_id, du_data->du_desc.data_size);

		ret = nse_sw_destroy_du_data(hw, du_data);
		if (ret)
			dev_err(dev, "Failed to destroy du_data, err = %d\n", ret);
	}
	mutex_unlock(&hw->switch_info->du_data_lock);
}

void
nse_debugfs_ovs_fltr_del_task_list(struct nse_hw *hw)
{
	struct nse_pf *pf = (struct nse_pf *)hw->back;
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_sw_task_list *task_list = NULL;
	struct list_head *list_head = &hw->switch_info->task_list_head;
	int ret = 0;

	mutex_lock(&hw->switch_info->task_list_lock);
	list_for_each_entry(task_list, list_head, list_entry) {
		dev_info(dev, "Request to destroy task_list[%d], ref_cnt = %d, task_cnt = 0x%x\n",
			task_list->task_list_id, refcount_read(&task_list->ref_cnt),
				task_list->task_cnt);

		ret = nse_sw_destroy_task_list(hw, task_list);
		if (ret)
			dev_err(dev, "Failed to destroy task_list, err = %d\n", ret);
	}
	mutex_unlock(&hw->switch_info->task_list_lock);
}

void
nse_debugfs_ovs_fltr_del_meter(struct nse_hw *hw)
{
	struct nse_pf *pf = (struct nse_pf *)hw->back;
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_sw_meter *meter = NULL;
	struct list_head *list_head = &hw->switch_info->meter_list_head;
	int ret = 0;

	mutex_lock(&hw->switch_info->meter_list_lock);
	list_for_each_entry(meter, list_head, list_entry) {
		dev_info(dev, "Request to destroy meter[%d], ref_cnt = %d, index= 0x%x, u_rate = %llu, burst = 0x%x\n",
			meter->meter_id, refcount_read(&meter->ref_cnt), meter->meter_param.index,
			meter->meter_param.rate, meter->meter_param.burst);

		ret = nse_sw_destroy_meter(hw, meter);
		if (ret)
			dev_err(dev, "Failed to destroy meter, err = %d\n", ret);
	}
	mutex_unlock(&hw->switch_info->meter_list_lock);
}

void
nse_debugfs_ovs_fltr_del_cnt_p(struct nse_hw *hw)
{
	struct nse_pf *pf = (struct nse_pf *)hw->back;
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_sw_counter *counter;
	struct nse_sw_counter_pair *counter_p;
	struct nse_sw_stats *sw_stats = &hw->switch_info->sw_stats;
	int ret = 0;

	list_for_each_entry(counter, &sw_stats->counters, list) {
		if (counter->cnt_type == NSE_SW_CNTR_TYPE_BYTE) {
			counter_p = container_of(counter, struct nse_sw_counter_pair,
				b_counter);

			dev_info(dev, "Request to free hw cnt[%d] and cnt[%d]\n",
				 counter_p->p_counter.hw_id,
				counter_p->b_counter.hw_id);
			ret = nse_sw_destroy_counter_pair(hw, counter_p);
			if (ret)
				dev_err(dev, "Failed to destroy hw counter, err = %d\n", ret);
		}
	}
}

void
nse_debugfs_ovs_fltr_del_nd_state(struct nse_hw *hw, u16 nd_state_id)
{
	struct nse_pf *pf = (struct nse_pf *)hw->back;
	struct device *dev = nse_pf_to_dev(pf);
	int ret = 0;

	if (nd_state_id != NSE_TC_FLWR_LARGE_ACTION_INVALID) {
		dev_info(dev, "Start to delete Node State [%d]\n", nd_state_id);
		ret = nse_sw_rem_node_state(hw, &nd_state_id);
		if (ret)
			dev_err(dev, "Failed to destroy hw counter, err = %d\n", ret);
	} else
		dev_info(dev, "It is an invalid node state id [%d]\n", nd_state_id);
}

void
nse_debugfs_ovs_fltr_enable_uplink(struct nse_pf *pf)
{
	struct device *dev = nse_pf_to_dev(pf);

	pf->switchdev.uplink_vsi = nse_get_main_vsi(pf);
	if (!pf->switchdev.uplink_vsi)
		dev_info(dev, "Failed to enable uplink vsi\n");
	else
		dev_info(dev, "Success to enable uplink vsi\n");
}

void
nse_debugfs_ovs_fltr_set_mode(struct nse_pf *pf, u32 mode)
{
	struct device *dev = nse_pf_to_dev(pf);
	int ret;
	u32 devlink_mode;

	if (mode == 0) {
		devlink_mode = DEVLINK_ESWITCH_MODE_LEGACY;
		dev_info(dev, "Start to set switch mode to Legacy\n");
	} else if (mode == 1) {
		devlink_mode = DEVLINK_ESWITCH_MODE_SWITCHDEV;
		dev_info(dev, "Start to set switch mode to Switchdev\n");
	} else
		dev_err(dev, "Mode value is invalid, 0 for legacy and 1 for switchdev\n");

	ret = nse_eswitch_set_mode(pf, devlink_mode);

	if (ret)
		dev_err(dev, "Failed to set switch mode, mode = %d\n", mode);
}

static ssize_t
nse_debugfs_sw_ovs_wfunc(struct file *filp, const char __user *buf,
			  size_t count, loff_t *ppos)
{
	struct nse_pf *pf = filp->private_data;
	struct nse_hw *hw = &pf->hw;
	struct device *dev = nse_pf_to_dev(pf);
	char *cmd_buf, *cmd_buf_tmp;
	ssize_t ret;
	char **argv;
	int argc;
	unsigned int val;
	unsigned int val1, val2;

	/* don't allow partial writes and writes when reset is in progress*/
	if (*ppos != 0 || nse_is_reset_in_progress(pf->state))
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

	if (!strncmp(argv[0], "enable", 6)) { /*1. enable*/
		if (argc != 2)
			goto bad_usage;

		if (!strncmp(argv[1], "uplink", 6)) /*1.1 uplink*/
			nse_debugfs_ovs_fltr_enable_uplink(pf);
		else
			goto bad_usage;

	} else if (!strncmp(argv[0], "add_smac", 8)) { /* 2. add_smac */
		if (argc != 2)
			goto bad_usage;

		if (!strncmp(argv[1], "rx", 2))
			nse_debugfs_ovs_fltr_add_smac_rx(hw);
		else
			goto bad_usage;

	} else if (!strncmp(argv[0], "add_ethtype", 11)) { /* 3. add_ethtype */
		if (argc != 2)
			goto bad_usage;

		if (!strncmp(argv[1], "rx", 2))
			nse_debugfs_ovs_fltr_add_ethtype_rx(hw);
		else
			goto bad_usage;

	} else if (!strncmp(argv[0], "add_dipv6", 9)) { /* 4. add_dipv6 */
		if (argc != 2)
			goto bad_usage;

		if (!strncmp(argv[1], "rx", 2))
			nse_debugfs_ovs_fltr_add_dipv6_rx(hw);
		else
			goto bad_usage;

	} else if (!strncmp(argv[0], "add_dip", 7)) { /* 5. add_dip */
		if (argc != 2)
			goto bad_usage;

		if (!strncmp(argv[1], "rx", 2))
			nse_debugfs_ovs_fltr_add_dip_rx(hw);
		else
			goto bad_usage;

	} else if (!strncmp(argv[0], "add_dport", 9)) { /* 6. add_dport */
		if (argc != 2)
			goto bad_usage;

		if (!strncmp(argv[1], "tcp_rx", 6))
			nse_debugfs_ovs_fltr_add_dport_tcp_rx(hw);
		else if (!strncmp(argv[1], "udp_rx", 6))
			nse_debugfs_ovs_fltr_add_dport_udp_rx(hw);
		else
			goto bad_usage;

	} else if (!strncmp(argv[0], "add_sip_smac", 12)) { /* 7. add_sip_smac */
		if (argc != 2)
			goto bad_usage;

		if (!strncmp(argv[1], "rx", 2))
			nse_debugfs_ovs_fltr_add_sip_smac_rx(hw);
		else
			goto bad_usage;

	} else if (!strncmp(argv[0], "add_vxlan", 9)) { /* 8. add_vxlan */
		if (argc < 2)
			goto bad_usage;

		if (!strncmp(argv[1], "o_dmac", 6)) { /* 8.1 add_vxlan  o_dmac*/
			if (argc < 3)
				goto bad_usage;

			if (!strncmp(argv[2], "rx", 2))
				nse_debugfs_ovs_fltr_add_vxlan_o_dmac_rx(hw);
			else
				goto bad_usage;

		} else if (!strncmp(argv[1], "o_sip", 5)) { /* 8.2 add_vxlan  o_sip*/
			if (argc < 3)
				goto bad_usage;

			if (!strncmp(argv[2], "rx", 2))
				nse_debugfs_ovs_fltr_add_vxlan_o_sip_rx(hw);
			else
				goto bad_usage;

		} else if (!strncmp(argv[1], "o_dport", 7)) { /* 8.3 add_vxlan  o_dport*/
			if (argc < 3)
				goto bad_usage;

			if (!strncmp(argv[2], "rx", 2))
				nse_debugfs_ovs_fltr_add_vxlan_o_dport_rx(hw);
			else
				goto bad_usage;

		} else if (!strncmp(argv[1], "key_id", 6)) { /* 8.4 add_vxlan  key_id*/
			if (argc < 3)
				goto bad_usage;

			if (!strncmp(argv[2], "rx", 2))
				nse_debugfs_ovs_fltr_add_vxlan_key_id_rx(hw);
			else
				goto bad_usage;

		} else if (!strncmp(argv[1], "i_dmac", 6)) { /* 8.5 add_vxlan  i_dmac*/
			if (argc < 3)
				goto bad_usage;

			if (!strncmp(argv[2], "rx", 2))
				nse_debugfs_ovs_fltr_add_vxlan_i_dmac_rx(hw);
			else
				goto bad_usage;

		} else if (!strncmp(argv[1], "i_ethtype", 9)) { /* 8.6 add_vxlan  i_ethtype*/
			if (argc < 3)
				goto bad_usage;

			if (!strncmp(argv[2], "rx", 2))
				nse_debugfs_ovs_fltr_add_vxlan_i_ethtype_rx(hw);
			else
				goto bad_usage;

		} else if (!strncmp(argv[1], "i_dipv6", 7)) { /* 8.7 add_vxlan  i_dipv6*/
			if (argc < 3)
				goto bad_usage;

			if (!strncmp(argv[2], "rx", 2))
				nse_debugfs_ovs_fltr_add_vxlan_i_dipv6_rx(hw);
			else
				goto bad_usage;

		} else if (!strncmp(argv[1], "i_dip", 5)) { /* 8.8 add_vxlan  i_dip*/
			if (argc < 3)
				goto bad_usage;

			if (!strncmp(argv[2], "rx", 2))
				nse_debugfs_ovs_fltr_add_vxlan_i_dip_rx(hw);
			else
				goto bad_usage;

		} else if (!strncmp(argv[1], "i_udp_sport", 11)) { /* 8.9 add_vxlan  i_udp_sport*/
			if (argc < 3)
				goto bad_usage;

			if (!strncmp(argv[2], "rx", 2))
				nse_debugfs_ovs_fltr_add_vxlan_i_udp_sport_rx(hw);
			else
				goto bad_usage;

		} else if (!strncmp(argv[1], "i_tcp_sport", 11)) { /* 8.10 add_vxlan  i_tcp_sport*/
			if (argc < 3)
				goto bad_usage;

			if (!strncmp(argv[2], "rx", 2))
				nse_debugfs_ovs_fltr_add_vxlan_i_tcp_sport_rx(hw);
			else
				goto bad_usage;

		} else
			goto bad_usage;

	} else if (!strncmp(argv[0], "del", 3)) { /* del cmd*/
		if (argc < 2)
			goto bad_usage;

		if (!strncmp(argv[1], "single", 6)) {
			if (argc < 4)
				goto bad_usage;

			if (kstrtouint(argv[2], 10, &val))
				goto bad_usage;

			if (kstrtouint(argv[3], 10, &val1))
				goto bad_usage;

			nse_debugfs_ovs_fltr_del_single(hw, val, val1);
		} else if (!strncmp(argv[1], "adv_fltr", 8)) {
			nse_cleanup_tc_fltrs((struct nse_pf *)hw->back);
		} else if (!strncmp(argv[1], "adv_rcp", 7)) {
			nse_del_all_adv_rcp_per_profile(hw);
		} else if (!strncmp(argv[1], "adv_lut", 7)) {
			nse_del_all_adv_luts(hw);
		} else if (!strncmp(argv[1], "cnt_p", 5)) {
			nse_debugfs_ovs_fltr_del_cnt_p(hw);
		} else if (!strncmp(argv[1], "meter", 5)) {
			nse_debugfs_ovs_fltr_del_meter(hw);
		} else if (!strncmp(argv[1], "task_list", 9)) {
			nse_debugfs_ovs_fltr_del_task_list(hw);
		} else if (!strncmp(argv[1], "du_data", 7)) {
			nse_debugfs_ovs_fltr_del_du_data(hw);
		} else if (!strncmp(argv[1], "nd_state", 8)) {
			if (argc < 3)
				goto bad_usage;

			if (kstrtouint(argv[2], 10, &val))
				goto bad_usage;

			nse_debugfs_ovs_fltr_del_nd_state(hw, val);
		} else
			goto bad_usage;

	} else if (!strncmp(argv[0], "dump", 4)) { /* dump cmd*/
		if (argc < 2)
			goto bad_usage;

		if (!strncmp(argv[1], "profiles", 8))
			nse_dump_all_profiles(hw);
		else if (!strncmp(argv[1], "luts", 4))
			nse_dump_all_adv_luts(hw);
		else if (!strncmp(argv[1], "rt_luts", 7))
			nse_dump_root_adv_luts(hw);
		else if (!strncmp(argv[1], "stats", 5))
			nse_sw_dump_stats(hw);
		else if (!strncmp(argv[1], "meters", 6))
			nse_sw_dump_meters(hw);
		else if (!strncmp(argv[1], "vsilists", 8))
			nse_sw_dump_vsi_list(hw);
		else if (!strncmp(argv[1], "tasklists", 9))
			nse_sw_dump_task_lists(hw);
		else if (!strncmp(argv[1], "du_datas", 8))
			nse_sw_dump_du_datas(hw);
		else if (!strncmp(argv[1], "encap", 5))
			nse_debugfs_ovs_dump_encap_entry(hw);
		else if (!strncmp(argv[1], "neigh", 5))
			nse_neigh_dump_neigh_entry(pf);
		else if (!strncmp(argv[1], "lut_nodes", 9)) {
			if (argc != 3)
				goto bad_usage;

			if (kstrtouint(argv[2], 10, &val))
				goto bad_usage;

			nse_dump_adv_lut_nodes(hw, val);

		} else
			goto bad_usage;

	} else if (!strncmp(argv[0], "action", 6)) { /* action cmd*/
		if (argc < 2)
			goto bad_usage;

		if (!strncmp(argv[1], "vsi_wo_cnt", 10))
			nse_debugfs_ovs_fltr_action_tovsi_wo_cnt(hw);
		else if (!strncmp(argv[1], "vlist_wo_cnt", 12))
			nse_debugfs_ovs_fltr_action_tovsilist_wo_cnt(hw);
		else if (!strncmp(argv[1], "vsi", 3))
			nse_debugfs_ovs_fltr_action_tovsi(hw);
		else if (!strncmp(argv[1], "vlist", 5))
			nse_debugfs_ovs_fltr_action_tovsilist(hw);
		else if (!strncmp(argv[1], "decap", 5))
			nse_debugfs_ovs_fltr_action_decap(hw);
		else if (!strncmp(argv[1], "meter", 5)) {
			if (argc < 4)
				goto bad_usage;

			if (kstrtouint(argv[2], 10, &val))
				goto bad_usage;

			if (kstrtouint(argv[3], 10, &val1))
				goto bad_usage;

			nse_debugfs_ovs_fltr_action_meter(hw, val, val1);
		} else if (!strncmp(argv[1], "add_del2", 8)) {
			if (argc < 5)
				goto bad_usage;

			if (kstrtouint(argv[2], 10, &val))
				goto bad_usage;

			if (kstrtouint(argv[3], 10, &val1))
				goto bad_usage;

			if (kstrtouint(argv[4], 10, &val2))
				goto bad_usage;

			nse_debugfs_ovs_fltr_action_add_del2(hw, val, val1, val2);

		} else if (!strncmp(argv[1], "add_del", 7)) {
			if (argc < 5)
				goto bad_usage;

			if (kstrtouint(argv[2], 10, &val))
				goto bad_usage;

			if (kstrtouint(argv[3], 10, &val1))
				goto bad_usage;

			if (kstrtouint(argv[4], 10, &val2))
				goto bad_usage;

			nse_debugfs_ovs_fltr_action_add_del(hw, val, val1, val2);
		} else if (!strncmp(argv[1], "au_nop", 6))
			nse_debugfs_ovs_fltr_action_au_nop(hw);
	else if (!strncmp(argv[1], "rw_smac_dmac", 12))
		nse_debugfs_ovs_fltr_action_rw_mac(hw);
		else if (!strncmp(argv[1], "rw_smac", 7))
			nse_debugfs_ovs_fltr_action_rw_smac(hw);
		else if (!strncmp(argv[1], "rw_dmac", 7))
			nse_debugfs_ovs_fltr_action_rw_dmac(hw);
		else if (!strncmp(argv[1], "rw_sip", 6))
			nse_debugfs_ovs_fltr_action_rw_sip(hw);
		else if (!strncmp(argv[1], "rw_dip", 6))
			nse_debugfs_ovs_fltr_action_rw_dip(hw);
		else if (!strncmp(argv[1], "rw_udp_sport", 12))
			nse_debugfs_ovs_fltr_action_rw_udp_sport(hw);
		else if (!strncmp(argv[1], "rw_udp_dport", 12))
			nse_debugfs_ovs_fltr_action_rw_udp_dport(hw);
		else if (!strncmp(argv[1], "rw_tcp_sport", 12))
			nse_debugfs_ovs_fltr_action_rw_tcp_sport(hw);
		else if (!strncmp(argv[1], "rw_tcp_dport", 12))
			nse_debugfs_ovs_fltr_action_rw_tcp_dport(hw);
		else if (!strncmp(argv[1], "rw_udp_snat", 11))
			nse_debugfs_ovs_fltr_action_rw_udp_snat(hw);
		else if (!strncmp(argv[1], "rw_udp_dnat", 11))
			nse_debugfs_ovs_fltr_action_rw_udp_dnat(hw);
		else if (!strncmp(argv[1], "rw_tcp_snat", 11))
			nse_debugfs_ovs_fltr_action_rw_tcp_snat(hw);
		else if (!strncmp(argv[1], "rw_tcp_dnat", 11))
			nse_debugfs_ovs_fltr_action_rw_tcp_dnat(hw);
		else if (!strncmp(argv[1], "rw_decap_dnat", 13))
			nse_debugfs_ovs_fltr_action_rw_decap_dnat(hw);
		else if (!strncmp(argv[1], "vlan_pop_push", 13))
			nse_debugfs_ovs_fltr_action_vlan_pop_push(hw);
		else if (!strncmp(argv[1], "vlan_pop", 8))
			nse_debugfs_ovs_fltr_action_vlan_pop(hw);
		else if (!strncmp(argv[1], "vlan_push", 9))
			nse_debugfs_ovs_fltr_action_vlan_push(hw);
		else if (!strncmp(argv[1], "enc_dnat", 8)) {
			if (argc < 3)
				goto bad_usage;
			nse_debugfs_ovs_fltr_action_enc_dnat(hw, argv[2]);
		} else if (!strncmp(argv[1], "enc_push", 8)) {
			if (argc < 3)
				goto bad_usage;
			nse_debugfs_ovs_fltr_action_enc_push(hw, argv[2]);
		} else if (!strncmp(argv[1], "vxlan_enc", 9)) {
			if (argc < 3)
				goto bad_usage;
			nse_debugfs_ovs_fltr_action_vxlan_enc(hw, argv[2]);
		} else if (!strncmp(argv[1], "vxlan_v6_enc", 12)) {
			if (argc < 3)
				goto bad_usage;
			nse_debugfs_ovs_fltr_action_vxlan_v6_encap(hw, argv[2]);
		} else
			goto bad_usage;

	} else if (!strncmp(argv[0], "set_mode", 8)) { /* set mode cmd*/
		if (argc < 2)
			goto bad_usage;

		if (kstrtouint(argv[1], 10, &val))
			goto bad_usage;
		nse_debugfs_ovs_fltr_set_mode(pf, val);

	} else
		goto bad_usage;

	/* if we get here, nothing went wrong; return bytes copied */
	ret = (ssize_t)count;

command_write_done:
	argv_free(argv);
err_copy_from_user:
	kfree(cmd_buf);
	return ret;

bad_usage:
	dev_info(dev, "unknown or invalid input: '%s'\n", cmd_buf);
	dev_info(dev, "common commands:\n");
	dev_info(dev, "\t enable uplink\n");
	dev_info(dev, "\t set_mode $mode\n");
	dev_info(dev, "\t del single $lut_id $node_id\n");
	dev_info(dev, "\t del adv_rcp\n");
	dev_info(dev, "\t del adv_lut\n");
	dev_info(dev, "\t del cnt_p\n");
	dev_info(dev, "\t del meter\n");
	dev_info(dev, "\t del task_list\n");
	dev_info(dev, "\t del du_data\n");
	dev_info(dev, "\t del nd_state $nds_id\n");
	dev_info(dev, "commands of action test:\n");
	dev_info(dev, "\t action add_del $cnt $loop $delay\n");
	dev_info(dev, "\t action add_del2 $cnt $loop $delay\n");
	dev_info(dev, "\t action vsi_wo_cnt\n");
	dev_info(dev, "\t action vlist_wo_cnt\n");
	dev_info(dev, "\t action vsi\n");
	dev_info(dev, "\t action vlist\n");
	dev_info(dev, "\t action decap\n");
	dev_info(dev, "\t action meter $Rate $Burst\n");
	dev_info(dev, "\t action au_nop\n");
	dev_info(dev, "\t action rw_smac\n");
	dev_info(dev, "\t action rw_dmac\n");
	dev_info(dev, "\t action rw_smac_dmac\n");
	dev_info(dev, "\t action rw_sip\n");
	dev_info(dev, "\t action rw_dip\n");
	dev_info(dev, "\t action rw_udp_sport\n");
	dev_info(dev, "\t action rw_udp_dport\n");
	dev_info(dev, "\t action rw_tcp_sport\n");
	dev_info(dev, "\t action rw_tcp_dport\n");
	dev_info(dev, "\t action rw_udp_snat\n");
	dev_info(dev, "\t action rw_udp_dnat\n");
	dev_info(dev, "\t action rw_tcp_snat\n");
	dev_info(dev, "\t action rw_tcp_dnat\n");
	dev_info(dev, "\t action rw_decap_dnat\n");
	dev_info(dev, "\t action vlan_pop\n");
	dev_info(dev, "\t action vlan_push\n");
	dev_info(dev, "\t action vlan_pop_push\n");
	dev_info(dev, "\t action vxlan_enc $net_name\n");
	dev_info(dev, "\t action enc_dnat $net_name\n");
	dev_info(dev, "\t action enc_push $net_name\n");
	dev_info(dev, "\t action vxlan_v6_enc $net_name\n");
	dev_info(dev, "commands of match test:\n");
	dev_info(dev, "\t add_smac rx\n");
	dev_info(dev, "\t add_ethtype rx\n");
	dev_info(dev, "\t add_dip rx\n");
	dev_info(dev, "\t add_dipv6 rx\n");
	dev_info(dev, "\t add_dport tcp_rx\n");
	dev_info(dev, "\t add_dport udp_rx\n");
	dev_info(dev, "\t add_sip_smac rx\n");
	dev_info(dev, "\t add_vxlan o_dmac rx\n");
	dev_info(dev, "\t add_vxlan o_sip rx\n");
	dev_info(dev, "\t add_vxlan o_dport rx\n");
	dev_info(dev, "\t add_vxlan key_id rx\n");
	dev_info(dev, "\t add_vxlan i_dmac rx\n");
	dev_info(dev, "\t add_vxlan i_ethtype rx\n");
	dev_info(dev, "\t add_vxlan i_dip rx\n");
	dev_info(dev, "\t add_vxlan i_udp_sport rx\n");
	dev_info(dev, "\t add_vxlan i_tcp_sport rx\n");
	dev_info(dev, "\t add_vxlan i_dipv6 rx\n");
	dev_info(dev, "dump available commands(dump software DB):\n");
	dev_info(dev, "\t dump profiles\n");
	dev_info(dev, "\t dump luts\n");
	dev_info(dev, "\t dump rt_luts\n");
	dev_info(dev, "\t dump lut_nodes $lut_id\n");
	dev_info(dev, "\t dump stats\n");
	dev_info(dev, "\t dump meters\n");
	dev_info(dev, "\t dump vsilists\n");
	dev_info(dev, "\t dump tasklists\n");
	dev_info(dev, "\t dump du_datas\n");
	dev_info(dev, "\t dump encap\n");
	dev_info(dev, "\t dump neigh\n");
	ret = -EINVAL;
	goto command_write_done;
}

static const struct file_operations nse_debugfs_sw_ovs_fops = {
	.owner = THIS_MODULE,
	.open  = simple_open,
	.write = nse_debugfs_sw_ovs_wfunc,
	.llseek = default_llseek,
};

void nse_debugfs_sw_fltr_src_prune_tx_en(struct nse_hw *hw)
{
	struct nse_pf *pf = (struct nse_pf *)hw->back;
	struct nse_vsi *vsi;
	struct device *dev = nse_pf_to_dev(pf);
	int err;

	vsi = nse_get_main_vsi(pf);
	if (!vsi) {
		dev_err(dev, "get main vsi err!\n");
		return;
	}

	dev_info(dev, "Start to fltr_src_prune_tx_en\n");

	err = nse_vsi_update_switch(vsi, nse_vsi_ctx_set_src_prune_tx);
	if (err)
		dev_err(dev, "Fail to fltr_src_prune_tx_en\n");
}

void nse_debugfs_sw_fltr_src_prune_tx_dis(struct nse_hw *hw)
{
	struct nse_pf *pf = (struct nse_pf *)hw->back;
	struct nse_vsi *vsi;
	struct device *dev = nse_pf_to_dev(pf);
	int err;

	vsi = nse_get_main_vsi(pf);
	if (!vsi) {
		dev_err(dev, "get main vsi err!\n");
		return;
	}

	dev_info(dev, "Start to fltr_clear_src_prune_tx\n");

	err = nse_vsi_update_switch(vsi, nse_vsi_ctx_clear_src_prune_tx);
	if (err)
		dev_err(dev, "Fail to fltr_clear_src_prune_tx\n");
}

void nse_debugfs_sw_fltr_src_prune_rx_en(struct nse_hw *hw)
{
	struct nse_pf *pf = (struct nse_pf *)hw->back;
	struct nse_vsi *vsi;
	struct device *dev = nse_pf_to_dev(pf);
	int err;

	vsi = nse_get_main_vsi(pf);
	if (!vsi) {
		dev_err(dev, "get main vsi err!\n");
		return;
	}

	dev_info(dev, "Start to fltr_src_prune_rx_en\n");

	err = nse_vsi_update_switch(vsi, nse_vsi_ctx_set_src_prune_rx);
	if (err)
		dev_err(dev, "Fail to fltr_src_prune_rx_en\n");
}

void nse_debugfs_sw_fltr_src_prune_rx_dis(struct nse_hw *hw)
{
	struct nse_pf *pf = (struct nse_pf *)hw->back;
	struct nse_vsi *vsi;
	struct device *dev = nse_pf_to_dev(pf);
	int err;

	vsi = nse_get_main_vsi(pf);
	if (!vsi) {
		dev_err(dev, "get main vsi err!\n");
		return;
	}

	dev_info(dev, "Start to fltr_clear_src_prune_rx\n");

	err = nse_vsi_update_switch(vsi, nse_vsi_ctx_clear_src_prune_rx);
	if (err)
		dev_err(dev, "Fail to fltr_clear_src_prune_rx\n");
}

void nse_debugfs_sw_fltr_vlan_rx_fltr_en(struct nse_hw *hw)
{
	struct nse_pf *pf = (struct nse_pf *)hw->back;
	struct nse_vsi *vsi;
	struct device *dev = nse_pf_to_dev(pf);
	int err;

	vsi = nse_get_main_vsi(pf);
	if (!vsi) {
		dev_err(dev, "get main vsi err!\n");
		return;
	}

	dev_info(dev, "Start to enable vlan_rx_fltr\n");

	err = nse_vsi_update_switch(vsi, nse_vsi_ctx_set_vlan_rx_filter);
	if (err)
		dev_err(dev, "Failed to enable vlan_rx_fltr\n");
}

void nse_debugfs_sw_fltr_vlan_rx_fltr_dis(struct nse_hw *hw)
{
	struct nse_pf *pf = (struct nse_pf *)hw->back;
	struct nse_vsi *vsi;
	struct device *dev = nse_pf_to_dev(pf);
	int err;

	vsi = nse_get_main_vsi(pf);
	if (!vsi) {
		dev_err(dev, "get main vsi err!\n");
		return;
	}

	dev_info(dev, "Start to clear vlan_rx_fltr\n");

	err = nse_vsi_update_switch(vsi, nse_vsi_ctx_clear_vlan_rx_filter);
	if (err)
		dev_err(dev, "Failed to clear vlan_rx_fltr\n");
}

void nse_debugfs_sw_fltr_antispoof_en(struct nse_hw *hw)
{
	struct nse_pf *pf = (struct nse_pf *)hw->back;
	struct nse_vsi *vsi;
	struct device *dev = nse_pf_to_dev(pf);
	int err;

	vsi = nse_get_main_vsi(pf);
	if (!vsi) {
		dev_err(dev, "get main vsi err!\n");
		return;
	}

	dev_info(dev, "Start to fltr_set_antispoof\n");

	err = nse_vsi_update_switch(vsi, nse_vsi_ctx_set_antispoof);
	if (err)
		dev_err(dev, "Fail to fltr_set_antispoof\n");
}

void nse_debugfs_sw_fltr_antispoof_dis(struct nse_hw *hw)
{
	struct nse_pf *pf = (struct nse_pf *)hw->back;
	struct nse_vsi *vsi;
	struct device *dev = nse_pf_to_dev(pf);
	int err;

	vsi = nse_get_main_vsi(pf);
	if (!vsi) {
		dev_err(dev, "get main vsi err!\n");
		return;
	}

	dev_info(dev, "Start to fltr_clear_antispoof\n");

	err = nse_vsi_update_switch(vsi, nse_vsi_ctx_clear_antispoof);
	if (err)
		dev_err(dev, "Fail to fltr_clear_antispoof\n");
}

void nse_debugfs_sw_fltr_dflt_vsi_en(struct nse_hw *hw)
{
	struct nse_pf *pf = (struct nse_pf *)hw->back;
	struct nse_vsi *vsi;
	struct device *dev = nse_pf_to_dev(pf);
	int err;

	vsi = nse_get_main_vsi(pf);
	if (!vsi) {
		dev_err(dev, "get main vsi err!\n");
		return;
	}

	dev_info(dev, "Start to fltr_set_dflt_vsi\n");

	err = nse_vsi_update_switch(vsi, nse_vsi_ctx_set_rx_dflt_vsi);
	if (err)
		dev_err(dev, "Fail to fltr_set_dflt_vsi\n");
}

void nse_debugfs_sw_fltr_dflt_vsi_dis(struct nse_hw *hw)
{
	struct nse_pf *pf = (struct nse_pf *)hw->back;
	struct nse_vsi *vsi;
	struct device *dev = nse_pf_to_dev(pf);
	int err;

	vsi = nse_get_main_vsi(pf);
	if (!vsi) {
		dev_err(dev, "get main vsi err!\n");
		return;
	}

	dev_info(dev, "Start to fltr_clear_dflt_vsi\n");

	err = nse_vsi_update_switch(vsi, nse_vsi_ctx_clear_rx_dflt_vsi);
	if (err)
		dev_err(dev, "Fail to fltr_clear_dflt_vsi\n");
}

void nse_debugfs_sw_fltr_vlan_promis_uni_en(struct nse_hw *hw, u16 vid)
{
	struct nse_pf *pf = (struct nse_pf *)hw->back;
	struct nse_vsi *vsi;
	struct device *dev = nse_pf_to_dev(pf);
	enum nse_status status = NSE_SUCCESS;
	u8 promisc_m = NSE_UCAST_VLAN_PROMISC_BITS;

	vsi = nse_get_main_vsi(pf);
	if (!vsi) {
		dev_err(dev, "get main vsi err!\n");
		return;
	}

	dev_info(dev, "Start to fltr_set_vsi_vlan_promisc: promisc_m = 0x%x, vlan id = %d\n",
			promisc_m, vid);

	status = nse_fltr_set_vsi_promisc(hw, vsi->idx, promisc_m, vid);
	if (status)
		dev_err(dev, "Fail to fltr_set_vsi_vlan_promisc: promisc_m = 0x%x, vlan id = %d\n",
			promisc_m, vid);
}

void nse_debugfs_sw_fltr_vlan_promis_uni_dis(struct nse_hw *hw, u16 vid)
{
	struct nse_pf *pf = (struct nse_pf *)hw->back;
	struct nse_vsi *vsi;
	struct device *dev = nse_pf_to_dev(pf);
	enum nse_status status = NSE_SUCCESS;
	u8 promisc_m = NSE_UCAST_VLAN_PROMISC_BITS;

	vsi = nse_get_main_vsi(pf);
	if (!vsi) {
		dev_err(dev, "get main vsi err!\n");
		return;
	}
	dev_info(dev, "Start to fltr_clear_vsi_vlan_promisc: promisc_m = 0x%x, vlan id = %d\n",
		promisc_m, vid);

	status = nse_fltr_clear_vsi_promisc(hw, vsi->idx, promisc_m, vid);
	if (status)
		dev_err(dev, "Fail to fltr_clear_vsi_vlan_promisc: promisc_m = 0x%x, vlan id = %d\n",
		promisc_m, vid);
}

void nse_debugfs_sw_fltr_vlan_promis_mc_en(struct nse_hw *hw, u16 vid)
{
	struct nse_pf *pf = (struct nse_pf *)hw->back;
	struct nse_vsi *vsi;
	struct device *dev = nse_pf_to_dev(pf);
	enum nse_status status = NSE_SUCCESS;
	u8 promisc_m = NSE_MCAST_VLAN_PROMISC_BITS;

	vsi = nse_get_main_vsi(pf);
	if (!vsi) {
		dev_err(dev, "get main vsi err!\n");
		return;
	}

	dev_info(dev, "Start to fltr_set_vsi_vlan_promisc: promisc_m = 0x%x, vlan id = %d\n",
		promisc_m, vid);

	status = nse_fltr_set_vsi_promisc(hw, vsi->idx, promisc_m, vid);
	if (status)
		dev_err(dev, "Fail to fltr_set_vsi_vlan_promisc: promisc_m = 0x%x, vlan id = %d\n",
			promisc_m, vid);
}

void nse_debugfs_sw_fltr_vlan_promis_mc_dis(struct nse_hw *hw, u16 vid)
{
	struct nse_pf *pf = (struct nse_pf *)hw->back;
	struct nse_vsi *vsi;
	struct device *dev = nse_pf_to_dev(pf);
	enum nse_status status = NSE_SUCCESS;
	u8 promisc_m = NSE_MCAST_VLAN_PROMISC_BITS;

	vsi = nse_get_main_vsi(pf);
	if (!vsi) {
		dev_err(dev, "get main vsi err!\n");
		return;
	}
	dev_info(dev, "Start to fltr_clear_vsi_vlan_promisc: promisc_m = 0x%x, vlan id = %d\n",
		promisc_m, vid);

	status = nse_fltr_clear_vsi_promisc(hw, vsi->idx, promisc_m, vid);
	if (status)
		dev_err(dev, "Fail to fltr_clear_vsi_vlan_promisc: promisc_m = 0x%x, vlan id = %d\n",
			promisc_m, vid);
}

void nse_debugfs_sw_fltr_promis_uni_en(struct nse_hw *hw)
{
	struct nse_pf *pf = (struct nse_pf *)hw->back;
	struct nse_vsi *vsi;
	struct device *dev = nse_pf_to_dev(pf);
	enum nse_status status = NSE_SUCCESS;
	u8 promisc_m = NSE_UCAST_PROMISC_BITS;

	vsi = nse_get_main_vsi(pf);
	if (!vsi) {
		dev_err(dev, "get main vsi err!\n");
		return;
	}

	dev_info(dev, "Start to fltr_set_vsi_promisc: promisc_m = 0x%x\n", promisc_m);

	status = nse_fltr_set_vsi_promisc(hw, vsi->idx, promisc_m, 0);
	if (status)
		dev_err(dev, "Fail to fltr_set_vsi_promisc: promisc_m = 0x%x\n", promisc_m);
}

void nse_debugfs_sw_fltr_promis_uni_dis(struct nse_hw *hw)
{
	struct nse_pf *pf = (struct nse_pf *)hw->back;
	struct nse_vsi *vsi;
	struct device *dev = nse_pf_to_dev(pf);
	enum nse_status status = NSE_SUCCESS;
	u8 promisc_m = NSE_UCAST_PROMISC_BITS;

	vsi = nse_get_main_vsi(pf);
	if (!vsi) {
		dev_err(dev, "get main vsi err!\n");
		return;
	}
	dev_info(dev, "Start to fltr_clear_vsi_promisc: promisc_m = 0x%x\n", promisc_m);

	status = nse_fltr_clear_vsi_promisc(hw, vsi->idx, promisc_m, 0);
	if (status)
		dev_err(dev, "Fail to fltr_clear_vsi_promisc: promisc_m = 0x%x\n", promisc_m);
}

void nse_debugfs_sw_fltr_promis_mc_en(struct nse_hw *hw)
{
	struct nse_pf *pf = (struct nse_pf *)hw->back;
	struct nse_vsi *vsi;
	struct device *dev = nse_pf_to_dev(pf);
	enum nse_status status = NSE_SUCCESS;
	u8 promisc_m = NSE_MCAST_PROMISC_BITS;

	vsi = nse_get_main_vsi(pf);
	if (!vsi) {
		dev_err(dev, "get main vsi err!\n");
		return;
	}

	dev_info(dev, "Start to fltr_set_vsi_promisc: promisc_m = 0x%x\n", promisc_m);

	status = nse_fltr_set_vsi_promisc(hw, vsi->idx, promisc_m, 0);
	if (status)
		dev_err(dev, "Fail to fltr_set_vsi_promisc: promisc_m = 0x%x\n", promisc_m);
}

void nse_debugfs_sw_fltr_promis_mc_dis(struct nse_hw *hw)
{
	struct nse_pf *pf = (struct nse_pf *)hw->back;
	struct nse_vsi *vsi;
	struct device *dev = nse_pf_to_dev(pf);
	enum nse_status status = NSE_SUCCESS;
	u8 promisc_m = NSE_MCAST_PROMISC_BITS;

	vsi = nse_get_main_vsi(pf);
	if (!vsi) {
		dev_err(dev, "get main vsi err!\n");
		return;
	}
	dev_info(dev, "Start to fltr_clear_vsi_promisc: promisc_m = 0x%x\n", promisc_m);

	status = nse_fltr_clear_vsi_promisc(hw, vsi->idx, promisc_m, 0);
	if (status)
		dev_err(dev, "Fail to fltr_clear_vsi_promisc: promisc_m = 0x%x\n", promisc_m);
}

void nse_debugfs_sw_fltr_vf_vlan_del(struct nse_hw *hw, u16 vsiid, u16 vid)
{
	struct nse_pf *pf = (struct nse_pf *)hw->back;
	struct nse_vsi *vsi;
	struct device *dev = nse_pf_to_dev(pf);
	enum nse_status status = NSE_SUCCESS;
	struct nse_vlan vlan;

	vsi = nse_find_vsi_by_rel_id(pf, vsiid);
	if (!vsi) {
		dev_err(dev, "get vsi(id = %d) err!\n", vsiid);
		return;
	}

	dev_info(dev, "stag_ethertype is 0x%x\n", hw->stag_ethertype);

	vlan = NSE_VLAN(hw->stag_ethertype, vid, 0, NSE_FWD_TO_VSI);

	status = nse_fltr_remove_vlan(vsi, &vlan);
	if (status)
		dev_err(dev, "Fail to fltr_remove_vf_vlan: VSIID = 0x%x, VID = 0x%x\n", vsiid, vid);
}

void nse_debugfs_sw_fltr_vf_vlan_add(struct nse_hw *hw, u16 vsiid, u16 vid)
{
	struct nse_pf *pf = (struct nse_pf *)hw->back;
	struct nse_vsi *vsi;
	struct device *dev = nse_pf_to_dev(pf);
	enum nse_status status = NSE_SUCCESS;
	struct nse_vlan vlan;

	vsi = nse_find_vsi_by_rel_id(pf, vsiid);
	if (!vsi) {
		dev_err(dev, "get vsi(id = %d) err!\n", vsiid);
		return;
	}

	dev_info(dev, "stag_ethertype is 0x%x\n", hw->stag_ethertype);

	vlan = NSE_VLAN(hw->stag_ethertype, vid, 0, NSE_FWD_TO_VSI);

	status = nse_fltr_add_vlan(vsi, &vlan);
	if (status)
		dev_err(dev, "Fail to fltr_add_vf_vlan: VSIID = 0x%x, VID = 0x%x\n", vsiid, vid);
}

void nse_debugfs_sw_fltr_vlan_del(struct nse_hw *hw, u32 val)
{
	struct nse_pf *pf = (struct nse_pf *)hw->back;
	struct nse_vsi *vsi;
	struct device *dev = nse_pf_to_dev(pf);
	enum nse_status status = NSE_SUCCESS;
	struct nse_vlan vlan;

	vsi = nse_get_main_vsi(pf);
	if (!vsi) {
		dev_err(dev, "get main vsi err!\n");
		return;
	}

	dev_info(dev, "stag_ethertype is 0x%x\n", hw->stag_ethertype);

	vlan = NSE_VLAN(hw->stag_ethertype, (u16)val, 0, NSE_FWD_TO_VSI);

	status = nse_fltr_remove_vlan(vsi, &vlan);
	if (status)
		dev_err(dev, "Fail to fltr_remove_vlan: VID = 0x%x\n", (u16)val);
}

void nse_debugfs_sw_fltr_vlan_add(struct nse_hw *hw, u32 val)
{
	struct nse_pf *pf = (struct nse_pf *)hw->back;
	struct nse_vsi *vsi;
	struct device *dev = nse_pf_to_dev(pf);
	enum nse_status status = NSE_SUCCESS;
	struct nse_vlan vlan;

	vsi = nse_get_main_vsi(pf);
	if (!vsi) {
		dev_err(dev, "get main vsi err!\n");
		return;
	}

	dev_info(dev, "stag_ethertype is 0x%x\n", hw->stag_ethertype);

	vlan = NSE_VLAN(hw->stag_ethertype, (u16)val, 0, NSE_FWD_TO_VSI);

	status = nse_fltr_add_vlan(vsi, &vlan);
	if (status)
		dev_err(dev, "Fail to fltr_add_vlan: VID = 0x%x\n", (u16)val);
}

void nse_debugfs_sw_fltr_ethtype_del(struct nse_hw *hw, bool rx, u32 val)
{
	struct nse_pf *pf = (struct nse_pf *)hw->back;
	struct nse_vsi *vsi;
	struct device *dev = nse_pf_to_dev(pf);
	enum nse_status status = NSE_SUCCESS;

	vsi = nse_get_main_vsi(pf);
	if (!vsi) {
		dev_err(dev, "get main vsi err!\n");
		return;
	}

	if (rx)
		status = nse_fltr_remove_eth(vsi, val, NSE_FLTR_RX,
		  NSE_FWD_TO_VSI);
	else
		status = nse_fltr_remove_eth(vsi, val, NSE_FLTR_TX,
		  NSE_FWD_TO_VSI);
}

void nse_debugfs_sw_fltr_ethtype_add(struct nse_hw *hw, bool rx, u32 val)
{
	struct nse_pf *pf = (struct nse_pf *)hw->back;
	struct nse_vsi *vsi;
	struct device *dev = nse_pf_to_dev(pf);
	enum nse_status status = NSE_SUCCESS;

	vsi = nse_get_main_vsi(pf);
	if (!vsi) {
		dev_err(dev, "get main vsi err!\n");
		return;
	}

	if (rx)
		status = nse_fltr_add_eth(vsi, val, NSE_FLTR_RX,
		  NSE_FWD_TO_VSI);
	else
		status = nse_fltr_add_eth(vsi, val, NSE_FLTR_TX,
		  NSE_FWD_TO_VSI);
}

void nse_debugfs_sw_fltr_mac_del(struct nse_hw *hw, u32 val)
{
	struct nse_pf *pf = (struct nse_pf *)hw->back;
	struct nse_vsi *vsi;
	struct device *dev = nse_pf_to_dev(pf);
	enum nse_status status = NSE_SUCCESS;
	u8 mac[ETH_ALEN] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x00};
	int i;
	unsigned long start, end;

	if (val > 256) {
		dev_err(dev, "Mac addr count is up to 256\n");
		return;
	}

	vsi = nse_get_main_vsi(pf);
	if (!vsi) {
		dev_err(dev, "get main vsi err!\n");
		return;
	}

	start = jiffies;

	for (i = 0; i < val; i++) {
		status = nse_fltr_remove_mac(vsi, mac, NSE_FWD_TO_VSI);
		if (status)
			dev_err(dev, "Fail to fltr_remove_mac [0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x]\n",
				mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

		mac[5]++;
	}

	end = jiffies;

	dev_info(dev, "takes %u msecs to del node %d times\n",
		jiffies_to_msecs(end - start), val);
}

void nse_debugfs_sw_fltr_mac_add(struct nse_hw *hw, u32 val)
{
	struct nse_pf *pf = (struct nse_pf *)hw->back;
	struct nse_vsi *vsi;
	struct device *dev = nse_pf_to_dev(pf);
	u8 mac[ETH_ALEN] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x00};
	int i;
	enum nse_status status = NSE_SUCCESS;
	unsigned long start, end;

	if (val > 256) {
		dev_err(dev, "Mac addr count is up to 256\n");
		return;
	}

	vsi = nse_get_main_vsi(pf);
	if (!vsi) {
		dev_err(dev, "get main vsi err!\n");
		return;
	}

	start = jiffies;

	for (i = 0; i < val; i++) {
		status = nse_fltr_add_mac(vsi, mac, NSE_FWD_TO_VSI);
		if (status)
			dev_err(dev, "Fail to fltr_add_mac [0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x]\n",
				mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

		mac[5]++;
	}
	end = jiffies;

	dev_info(dev, "takes %u msecs to add node %d times\n",
		jiffies_to_msecs(end - start), val);
}

static ssize_t
nse_debugfs_sw_fltr_wfunc(struct file *filp, const char __user *buf,
			  size_t count, loff_t *ppos)
{
	struct nse_pf *pf = filp->private_data;
	struct nse_hw *hw = &pf->hw;
	struct device *dev = nse_pf_to_dev(pf);
	char *cmd_buf, *cmd_buf_tmp;
	ssize_t ret;
	char **argv;
	int argc;
	unsigned int val;
	unsigned int val1;

	/* don't allow partial writes and writes when reset is in progress*/
	if (*ppos != 0 || nse_is_reset_in_progress(pf->state))
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

	if (!strncmp(argv[0], "add_mac", 7)) { /*1. add_mac*/
		if (argc != 2)
			goto bad_usage;

		if (kstrtouint(argv[1], 10, &val))
			goto bad_usage;

		nse_debugfs_sw_fltr_mac_add(hw, val);
	} else if (!strncmp(argv[0], "del_mac", 7)) { /*2. del_mac*/
		if (argc != 2)
			goto bad_usage;

		if (kstrtouint(argv[1], 10, &val))
			goto bad_usage;

		nse_debugfs_sw_fltr_mac_del(hw, val);
	} else if (!strncmp(argv[0], "add_ethtype", 11)) { /*3. add_ethtype*/
		if (argc != 3)
			goto bad_usage;

		if (!strncmp(argv[1], "rx", 2)) {
			if (kstrtouint(argv[2], 16, &val))
				goto bad_usage;

			nse_debugfs_sw_fltr_ethtype_add(hw, true, val);
		} else if (!strncmp(argv[1], "tx", 2)) {
			if (kstrtouint(argv[2], 16, &val))
				goto bad_usage;

			nse_debugfs_sw_fltr_ethtype_add(hw, false, val);
		} else
			goto bad_usage;
	} else if (!strncmp(argv[0], "del_ethtype", 11)) { /*4. del_ethtype*/
		if (argc != 3)
			goto bad_usage;

		if (!strncmp(argv[1], "rx", 2)) {
			if (kstrtouint(argv[2], 16, &val))
				goto bad_usage;

			nse_debugfs_sw_fltr_ethtype_del(hw, true, val);
		} else if (!strncmp(argv[1], "tx", 2)) {
			if (kstrtouint(argv[2], 16, &val))
				goto bad_usage;

			nse_debugfs_sw_fltr_ethtype_del(hw, false, val);
		} else
			goto bad_usage;
	} else if (!strncmp(argv[0], "add_vlan", 8)) {  /*5. add_vlan*/
		if (argc != 2)
			goto bad_usage;

		if (kstrtouint(argv[1], 10, &val))
			goto bad_usage;

		nse_debugfs_sw_fltr_vlan_add(hw, val);
	} else if (!strncmp(argv[0], "del_vlan", 8)) {  /*6. del_vlan*/
		if (argc != 2)
			goto bad_usage;

		if (kstrtouint(argv[1], 10, &val))
			goto bad_usage;

		nse_debugfs_sw_fltr_vlan_del(hw, val);

	} else if (!strncmp(argv[0], "add_vf_vlan", 11)) {  /*add_vf_vlan*/
		if (argc != 3)
			goto bad_usage;

		if (kstrtouint(argv[1], 10, &val))
			goto bad_usage;

		if (kstrtouint(argv[2], 10, &val1))
			goto bad_usage;

		nse_debugfs_sw_fltr_vf_vlan_add(hw, val, val1);
	} else if (!strncmp(argv[0], "del_vf_vlan", 11)) {  /* del_vf_vlan*/
		if (argc != 3)
			goto bad_usage;

		if (kstrtouint(argv[1], 10, &val))
			goto bad_usage;

		if (kstrtouint(argv[2], 10, &val1))
			goto bad_usage;

		nse_debugfs_sw_fltr_vf_vlan_del(hw, val, val1);
	} else if (!strncmp(argv[0], "promisc", 7)) {		/*7. promisc*/
		if (argc != 2)
			goto bad_usage;

		if (!strncmp(argv[1], "uni_en", 6))
			nse_debugfs_sw_fltr_promis_uni_en(hw);
		else if (!strncmp(argv[1], "uni_dis", 7))
			nse_debugfs_sw_fltr_promis_uni_dis(hw);
		else if (!strncmp(argv[1], "mc_en", 5))
			nse_debugfs_sw_fltr_promis_mc_en(hw);
		else if (!strncmp(argv[1], "mc_dis", 6))
			nse_debugfs_sw_fltr_promis_mc_dis(hw);
		else
			goto bad_usage;
	} else if (!strncmp(argv[0], "vlan_promisc", 12)) {		/*8. vlan_promisc*/
		if (argc != 3)
			goto bad_usage;

		if (kstrtouint(argv[1], 10, &val))
			goto bad_usage;

		if (!strncmp(argv[2], "uni_en", 6))
			nse_debugfs_sw_fltr_vlan_promis_uni_en(hw, val);
		else if (!strncmp(argv[2], "uni_dis", 7))
			nse_debugfs_sw_fltr_vlan_promis_uni_dis(hw, val);
		else if (!strncmp(argv[2], "mc_en", 5))
			nse_debugfs_sw_fltr_vlan_promis_mc_en(hw, val);
		else if (!strncmp(argv[2], "mc_dis", 6))
			nse_debugfs_sw_fltr_vlan_promis_mc_dis(hw, val);
		else
			goto bad_usage;
	} else if (!strncmp(argv[0], "dflt_vsi", 8)) {	/*9. dflt_vsi*/
		if (argc != 2)
			goto bad_usage;

		if (!strncmp(argv[1], "en", 2))
			nse_debugfs_sw_fltr_dflt_vsi_en(hw);
		else if (!strncmp(argv[1], "dis", 3))
			nse_debugfs_sw_fltr_dflt_vsi_dis(hw);
		else
			goto bad_usage;
	} else if (!strncmp(argv[0], "antispoof", 9)) {	/*10. antispoof*/
		if (argc != 2)
			goto bad_usage;

		if (!strncmp(argv[1], "en", 2))
			nse_debugfs_sw_fltr_antispoof_en(hw);
		else if (!strncmp(argv[1], "dis", 3))
			nse_debugfs_sw_fltr_antispoof_dis(hw);
		else
			goto bad_usage;
	} else if (!strncmp(argv[0], "vlan_rx_fltr", 12)) { /*11. vlan_rx_fltr*/
		if (argc != 2)
			goto bad_usage;

		if (!strncmp(argv[1], "en", 2))
			nse_debugfs_sw_fltr_vlan_rx_fltr_en(hw);
		else if (!strncmp(argv[1], "dis", 3))
			nse_debugfs_sw_fltr_vlan_rx_fltr_dis(hw);
		else
			goto bad_usage;
	} else if (!strncmp(argv[0], "src_prune", 9)) { /*12. src_prune*/
		if (argc != 2)
			goto bad_usage;

		if (!strncmp(argv[1], "rx_en", 5))
			nse_debugfs_sw_fltr_src_prune_rx_en(hw);
		else if (!strncmp(argv[1], "rx_dis", 6))
			nse_debugfs_sw_fltr_src_prune_rx_dis(hw);
		else if (!strncmp(argv[1], "tx_en", 5))
			nse_debugfs_sw_fltr_src_prune_tx_en(hw);
		else if (!strncmp(argv[1], "tx_dis", 6))
			nse_debugfs_sw_fltr_src_prune_tx_dis(hw);
		else
			goto bad_usage;

	} else if (argc == 2 && !strncmp(argv[0], "dump", 4)) { /*dump cmd*/

		if (!strncmp(argv[1], "mac", 3))
			nse_dump_sw_fltr_rules(hw, NSE_SW_LKUP_MAC);
		else if (!strncmp(argv[1], "bmc", 3))
			nse_dump_sw_fltr_rules(hw, NSE_SW_LKUP_BMC_MAC);
		else if (!strncmp(argv[1], "vlan", 4))
			nse_dump_sw_fltr_rules(hw, NSE_SW_LKUP_VLAN);
		else if (!strncmp(argv[1], "ethtype", 7))
			nse_dump_sw_fltr_rules(hw, NSE_SW_LKUP_ETHERTYPE);
		else if (!strncmp(argv[1], "promisc", 7))
			nse_dump_sw_fltr_rules(hw, NSE_SW_LKUP_PROMISC);
		else if (!strncmp(argv[1], "promisc_vlan", 12))
			nse_dump_sw_fltr_rules(hw, NSE_SW_LKUP_PROMISC_VLAN);
		else
			goto bad_usage;
	} else
		goto bad_usage;

	/* if we get here, nothing went wrong; return bytes copied */
	ret = (ssize_t)count;

command_write_done:
	argv_free(argv);
err_copy_from_user:
	kfree(cmd_buf);
	return ret;

bad_usage:
	dev_info(dev, "unknown or invalid input: '%s'\n", cmd_buf);
	dev_info(dev, "add/del available commands(dest VSI is pf main VSI-0):\n");
	dev_info(dev, "\t add_mac $Cnt - from 00:11:22:33:44:00\n");
	dev_info(dev, "\t del_mac $Cnt - from 00:11:22:33:44:00\n");
	dev_info(dev, "\t add_ethtype rx 0x$TYPE\n");
	dev_info(dev, "\t add_ethtype tx 0x$TYPE\n");
	dev_info(dev, "\t del_ethtype rx 0x$TYPE\n");
	dev_info(dev, "\t del_ethtype tx 0x$TYPE\n");
	dev_info(dev, "\t add_vlan $VID\n");
	dev_info(dev, "\t del_vlan $VID\n");
	dev_info(dev, "\t add_vf_vlan $VSIID $VID\n");
	dev_info(dev, "\t del_vf_vlan $VSIID $VID\n");
	dev_info(dev, "\t promisc uni_en\n");
	dev_info(dev, "\t promisc uni_dis\n");
	dev_info(dev, "\t promisc mc_en\n");
	dev_info(dev, "\t promisc mc_dis\n");
	dev_info(dev, "\t vlan_promisc $VID uni_en\n");
	dev_info(dev, "\t vlan_promisc $VID uni_dis\n");
	dev_info(dev, "\t vlan_promisc $VID mc_en\n");
	dev_info(dev, "\t vlan_promisc $VID mc_dis\n");
	dev_info(dev, "\t dflt_vsi en\n");
	dev_info(dev, "\t dflt_vsi dis\n");
	dev_info(dev, "\t antispoof en\n");
	dev_info(dev, "\t antispoof dis\n");
	dev_info(dev, "\t vlan_rx_fltr en\n");
	dev_info(dev, "\t vlan_rx_fltr dis\n");
	dev_info(dev, "\t src_prune rx_en\n");
	dev_info(dev, "\t src_prune rx_dis\n");
	dev_info(dev, "\t src_prune tx_en\n");
	dev_info(dev, "\t src_prune tx_dis\n");
	dev_info(dev, "dump available commands(dump software DB):\n");
	dev_info(dev, "\t dump mac\n");
	dev_info(dev, "\t dump vlan\n");
	dev_info(dev, "\t dump ethtype\n");
	dev_info(dev, "\t dump promisc\n");
	dev_info(dev, "\t dump promisc_vlan\n");
	ret = -EINVAL;
	goto command_write_done;
}

static const struct file_operations nse_debugfs_sw_fltr_fops = {
	.owner = THIS_MODULE,
	.open  = simple_open,
	.write = nse_debugfs_sw_fltr_wfunc,
	.llseek = default_llseek,
};

int
nse_debugfs_sw_lpm_parse_rt(struct nse_hw *hw,
	char *arg, struct nse_ip_route_addr *ip_addr, int family)
{
	struct nse_pf *pf = (struct nse_pf *)hw->back;
	struct device *dev = nse_pf_to_dev(pf);
	char *split;
	int err = 0;
	unsigned int val;

	dev_info(dev, "origal route string: %s\n", arg);

	split = strchr(arg, '/');
	if (split)
		*split = '\0';

	switch (family) {
	case AF_INET:
		dev_info(dev, "route string before in4_pton: %s\n", arg);
		if (in4_pton(arg, strlen(arg), (u8 *)&ip_addr->dst_ip.v4, -1, NULL) == 0) {
			err = -EINVAL;
			dev_info(dev, "Failed to parse ipv4 addr(%s) through in4_pton, err = %d\n",
				arg, err);
			goto out;
		}
		ip_addr->family = AF_INET;
		if (!split)
			ip_addr->prefix_len = 32;
		break;
	case AF_INET6:
		dev_info(dev, "route string before in6_pton: %s\n", arg);
		if (in6_pton(arg, strlen(arg), (u8 *)&ip_addr->dst_ip.v6, -1, NULL) == 0) {
			err = -EINVAL;
			dev_info(dev, "Failed to parse ipv6 addr(%s) through in6_pton, err = %d\n",
				arg, err);
			goto out;
		}
		ip_addr->family = AF_INET6;
		if (!split)
			ip_addr->prefix_len = 128;
		break;
	default:
		dev_info(dev, "family is not AF_INET and AF_INET6!\n");
		err = -EINVAL;
		goto out;
	}

	if (split) {
		*split = '/';
		split++;
		dev_info(dev, "prefix string before simple_strtoul: %s\n", split);
		if (kstrtouint(split, 10, &val)) {
			dev_info(dev, "Fail to parse prefix of route!\n");
			err = -EINVAL;
			goto out;
		}
		ip_addr->prefix_len = val;
		if (family == AF_INET && ip_addr->prefix_len > 32)
			ip_addr->prefix_len = 32;
		if (family == AF_INET6 && ip_addr->prefix_len > 128)
			ip_addr->prefix_len = 128;
	}

	dev_info(dev, "prefix len after parse: %d\n", ip_addr->prefix_len);

out:
	return err;
}

void
nse_debugfs_sw_lpm_print_rt(struct nse_hw *hw,
			struct nse_ip_route_addr *ip_addr)
{
	struct nse_pf *pf = (struct nse_pf *)hw->back;
	struct device *dev = nse_pf_to_dev(pf);

	dev_info(dev, "Start to print route info after parse\n");
	if (ip_addr->family == AF_INET) {
		dev_info(dev, "\t route's family is AF_INET, prefix_len is %d\n",
			 ip_addr->prefix_len);
		dev_info(dev, "\t IPV4 Value = %pI4\n", &ip_addr->dst_ip.v4);
	} else {
		dev_info(dev, "\t route's family is AF_INET6, prefix_len is %d\n",
			 ip_addr->prefix_len);
		dev_info(dev, "\t IPV6 Value = %pI6c\n", &ip_addr->dst_ip.v6);
	}
}

static struct nse_lpm_fltr *
nse_find_lpm_fltr(struct nse_ip_route_addr *ip_addr)
{
	struct nse_lpm_fltr *fltr = NULL;

	hlist_for_each_entry(fltr, &lpm_fltr_list, lpm_node)
		if (!memcmp(&fltr->ip_key, ip_addr,
			    sizeof(fltr->ip_key))) {
			return fltr;
		}

	return NULL;
}

void
nse_debugfs_sw_lpm_add_dmac_ipv4_rt(struct nse_hw *hw,
			char *arg, char *act_type, u32 dest_vsi)
{
#if NSE_LPM_FLWR_DYNAMIC_SUPPORT
	struct nse_pf *pf = (struct nse_pf *)hw->back;
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_vsi *vsi = NULL;
	struct nse_ip_route_addr *ip_addr = NULL;
	struct nse_lpm_fltr *fltr = NULL, *old_fltr = NULL;
	u8 mac_addr[ETH_ALEN] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
	int err = 0;
	u32 dip = 0, shift_len = 0;

	dev_info(dev, "Start to add ipv4 route\n");

	fltr = kzalloc(sizeof(*fltr), GFP_KERNEL);
	if (!fltr)
		return;

	ip_addr = &fltr->ip_key;

	err = nse_debugfs_sw_lpm_parse_rt(hw, arg, ip_addr, AF_INET);
	if (err) {
		dev_err(dev, "Fail to parse route when add ipv4 route\n");
		goto out;
	}

	if (ip_addr->prefix_len <= 0 || ip_addr->prefix_len > 32) {
		dev_err(dev, "ipv4's prefix_len should be in [1,32], cur len = %d\n",
			ip_addr->prefix_len);
		goto out;
	}

	/* value should be cleared based on prefix_len*/
	shift_len = 32 - ip_addr->prefix_len;
	dip = ntohl(ip_addr->dst_ip.v4);
	dip = (dip >> shift_len) << shift_len;
	ip_addr->dst_ip.v4 = htonl(dip);

	nse_debugfs_sw_lpm_print_rt(hw, ip_addr);

	ip_addr->is_w_dmac = true;
	ether_addr_copy(ip_addr->dst_mac, mac_addr);
	ip_addr->prefix_len += NSE_LPM_DMAC_BIT_LEN;

	old_fltr = nse_find_lpm_fltr(ip_addr);
	if (old_fltr) {
		dev_err(dev, "Current dmac_ipv4 lpm fltr is existed, please delete then add\n");
		goto out;
	}

	if (!strncmp(act_type, "vsi", 3)) {
		vsi = nse_find_vsi_by_rel_id(pf, dest_vsi);
		if (!vsi) {
			dev_err(dev, "get vsi(id = %d) err!\n", dest_vsi);
			goto out;
		}
		if (!nse_is_vsi_valid(hw, vsi->idx)) {
			dev_err(dev, "vsi(id = %d) is invalid!\n", vsi->idx);
			goto out;
		}
		fltr->action.fltr_act = NSE_FWD_TO_VSI;
		fltr->action.dest_vsi = vsi;
		fltr->action.flags |= NSE_LPM_ACTION_FWD_VSI |
						NSE_LPM_ACTION_DEC_TTL | NSE_LPM_ACTION_COUNT;
	} else if (!strncmp(act_type, "lan", 3)) {
		fltr->action.fltr_act = NSE_FWD_TO_LAN;
		fltr->action.flags |= NSE_LPM_ACTION_TO_LAN |
						NSE_LPM_ACTION_DEC_TTL | NSE_LPM_ACTION_COUNT;
	} else {
		fltr->action.fltr_act = NSE_DROP_PACKET;
		fltr->action.flags |= NSE_LPM_ACTION_DROP |
							NSE_LPM_ACTION_COUNT;
	}

	fltr->action.large_act_id = NSE_NODE_STATE_ID_INVALID;

	err = nse_erouter_add_lpm_fltr(hw, fltr);
	if (err) {
		dev_err(dev, "Fail to add ipv4 lpm address, err = %d\n", err);
		nse_erouter_del_lpm_fltr(hw, fltr);
		goto out;
	}

	g_nse_dmac_ipv4_rt_lut_id = fltr->lut_id;

	dev_info(dev, "Success to add dmac_ipv4 route, lut_id = %d, node_id = %d\n",
		fltr->lut_id, fltr->node_id);

	hlist_add_head(&fltr->lpm_node, &lpm_fltr_list);

	return;

out:
	kfree(fltr);
	return;
#else
	return;
#endif
}

void
nse_debugfs_sw_lpm_del_dmac_ipv4_rt(struct nse_hw *hw,
			char *arg)
{
#if NSE_LPM_FLWR_DYNAMIC_SUPPORT
	struct nse_pf *pf = (struct nse_pf *)hw->back;
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_ip_route_addr *ip_addr = NULL;
	struct nse_lpm_fltr *fltr = NULL;
	u8 mac_addr[ETH_ALEN] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
	int err = 0;
	u32 dip = 0, shift_len = 0;

	dev_info(dev, "Start to del ipv4 route\n");

	ip_addr = kzalloc(sizeof(*ip_addr), GFP_KERNEL);
	if (!ip_addr)
		return;

	err = nse_debugfs_sw_lpm_parse_rt(hw, arg, ip_addr, AF_INET);
	if (err) {
		dev_err(dev, "Fail to parse route when del ipv4 route\n");
		goto out;
	}

	if (ip_addr->prefix_len <= 0 || ip_addr->prefix_len > 32) {
		dev_err(dev, "ipv4's prefix_len should be in [1,32], cur len = %d\n",
			ip_addr->prefix_len);
		goto out;
	}

	/* value should be cleared based on prefix_len*/
	shift_len = 32 - ip_addr->prefix_len;
	dip = ntohl(ip_addr->dst_ip.v4);
	dip = (dip >> shift_len) << shift_len;
	ip_addr->dst_ip.v4 = htonl(dip);

	nse_debugfs_sw_lpm_print_rt(hw, ip_addr);

	if (g_nse_dmac_ipv4_rt_lut_id == -1) {
		dev_err(dev,
			"ipv4 rt is not created yet, please add ipv4 rt first\n");
		goto out;
	}

	ip_addr->is_w_dmac = true;
	ether_addr_copy(ip_addr->dst_mac, mac_addr);
	ip_addr->prefix_len += NSE_LPM_DMAC_BIT_LEN;

	fltr = nse_find_lpm_fltr(ip_addr);
	if (!fltr) {
		dev_info(dev, "Current ipv4 lpm fltr is not existed\n");
		goto out;
	}

	fltr->lut_id = g_nse_dmac_ipv4_rt_lut_id;
	nse_erouter_del_lpm_fltr(hw, fltr);
	hlist_del(&fltr->lpm_node);
	kfree(fltr);
out:
	kfree(ip_addr);
	return;
#else
	return;
#endif
}

void
nse_debugfs_sw_lpm_add_dmac_ipv6_rt(struct nse_hw *hw,
			char *arg, char *act_type, u32 dest_vsi)
{
#if NSE_LPM_FLWR_DYNAMIC_SUPPORT
	struct nse_pf *pf = (struct nse_pf *)hw->back;
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_vsi *vsi = NULL;
	struct nse_ip_route_addr *ip_addr = NULL;
	struct nse_lpm_fltr *fltr = NULL, *old_fltr = NULL;
	u8 mac_addr[ETH_ALEN] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
	int err = 0, i;
	u8 byte, bit;

	dev_info(dev, "Start to add ipv6 route\n");

	fltr = kzalloc(sizeof(*fltr), GFP_KERNEL);
	if (!fltr)
		return;

	ip_addr = &fltr->ip_key;

	err = nse_debugfs_sw_lpm_parse_rt(hw, arg, ip_addr, AF_INET6);
	if (err) {
		dev_err(dev, "Fail to parse route when add ipv6 route\n");
		goto out;
	}

	if (ip_addr->prefix_len <= 0 || ip_addr->prefix_len > 128) {
		dev_err(dev, "ipv6's prefix_len should be in [1,128], cur len = %d\n",
			ip_addr->prefix_len);
		goto out;
	}

	/* value should be cleared based on prefix_len*/
	byte = (u8)(ip_addr->prefix_len - 1) >> 3;
	bit = (u8)(~(ip_addr->prefix_len - 1)) & 0x7;
	for (i = 15; i > byte; i--)
		ip_addr->dst_ip.v6.s6_addr[i] = 0;
	ip_addr->dst_ip.v6.s6_addr[i] = (ip_addr->dst_ip.v6.s6_addr[i] >> bit) << bit;

	nse_debugfs_sw_lpm_print_rt(hw, ip_addr);

	ip_addr->is_w_dmac = true;
	ether_addr_copy(ip_addr->dst_mac, mac_addr);
	ip_addr->prefix_len += NSE_LPM_DMAC_BIT_LEN;

	old_fltr = nse_find_lpm_fltr(ip_addr);
	if (old_fltr) {
		dev_err(dev, "Current ipv6 lpm fltr is existed, please delete then add\n");
		goto out;
	}

	if (!strncmp(act_type, "vsi", 3)) {
		vsi = nse_find_vsi_by_rel_id(pf, dest_vsi);
		if (!vsi) {
			dev_err(dev, "get vsi(id = %d) err!\n", dest_vsi);
			goto out;
		}
		if (!nse_is_vsi_valid(hw, vsi->idx)) {
			dev_err(dev, "vsi(id = %d) is invalid!\n", vsi->idx);
			goto out;
		}
		fltr->action.fltr_act = NSE_FWD_TO_VSI;
		fltr->action.dest_vsi = vsi;
		fltr->action.flags |= NSE_LPM_ACTION_FWD_VSI |
				 NSE_LPM_ACTION_DEC_HLIMIT | NSE_LPM_ACTION_COUNT;
	} else if (!strncmp(act_type, "lan", 3)) {
		fltr->action.fltr_act = NSE_FWD_TO_LAN;
		fltr->action.flags |= NSE_LPM_ACTION_TO_LAN |
				NSE_LPM_ACTION_DEC_HLIMIT | NSE_LPM_ACTION_COUNT;
	} else {
		fltr->action.fltr_act = NSE_DROP_PACKET;
		fltr->action.flags |= NSE_LPM_ACTION_DROP |
							NSE_LPM_ACTION_COUNT;
	}

	fltr->action.large_act_id = NSE_NODE_STATE_ID_INVALID;

	err = nse_erouter_add_lpm_fltr(hw, fltr);
	if (err) {
		dev_err(dev, "Fail to add ipv6 lpm address, err = %d\n", err);
		nse_erouter_del_lpm_fltr(hw, fltr);
		goto out;
	}

	g_nse_dmac_ipv6_rt_lut_id = fltr->lut_id;

	dev_info(dev, "Success to add ipv6 route, lut_id = %d, node_id = %d\n",
		fltr->lut_id, fltr->node_id);

	hlist_add_head(&fltr->lpm_node, &lpm_fltr_list);

	return;

out:
	kfree(fltr);
	return;

#else

	return;

#endif
}

void
nse_debugfs_sw_lpm_del_dmac_ipv6_rt(struct nse_hw *hw,
			char *arg)
{
#if NSE_LPM_FLWR_DYNAMIC_SUPPORT
	struct nse_pf *pf = (struct nse_pf *)hw->back;
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_ip_route_addr *ip_addr = NULL;
	struct nse_lpm_fltr *fltr = NULL;
	u8 mac_addr[ETH_ALEN] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
	int err = 0, i;
	u8 byte, bit;

	dev_info(dev, "Start to del ipv6 route\n");

	ip_addr = kzalloc(sizeof(*ip_addr), GFP_KERNEL);
	if (!ip_addr)
		return;

	err = nse_debugfs_sw_lpm_parse_rt(hw, arg, ip_addr, AF_INET6);
	if (err) {
		dev_err(dev, "Fail to parse route when del ipv6 route\n");
		goto out;
	}

	if (ip_addr->prefix_len <= 0 || ip_addr->prefix_len > 128) {
		dev_err(dev, "ipv6's prefix_len should be in [1,128], cur len = %d\n",
			ip_addr->prefix_len);
		goto out;
	}

	/* value should be cleared based on prefix_len*/
	byte = (u8)(ip_addr->prefix_len - 1) >> 3;
	bit = (u8)(~(ip_addr->prefix_len - 1)) & 0x7;
	for (i = 15; i > byte; i--)
		ip_addr->dst_ip.v6.s6_addr[i] = 0;
	ip_addr->dst_ip.v6.s6_addr[i] = (ip_addr->dst_ip.v6.s6_addr[i] >> bit) << bit;

	nse_debugfs_sw_lpm_print_rt(hw, ip_addr);

	if (g_nse_dmac_ipv6_rt_lut_id == -1) {
		dev_err(dev,
			"ipv6 rt is not created yet, please add ipv6 rt first\n");
		goto out;
	}

	ip_addr->is_w_dmac = true;
	ether_addr_copy(ip_addr->dst_mac, mac_addr);
	ip_addr->prefix_len += NSE_LPM_DMAC_BIT_LEN;

	fltr = nse_find_lpm_fltr(ip_addr);
	if (!fltr) {
		dev_info(dev, "Current ipv6 lpm fltr is not existed\n");
		goto out;
	}

	fltr->lut_id = g_nse_dmac_ipv6_rt_lut_id;

	nse_erouter_del_lpm_fltr(hw, fltr);

	hlist_del(&fltr->lpm_node);

	kfree(fltr);

out:
	kfree(ip_addr);
	return;
#else
	return;
#endif
}

int
nse_debugfs_sw_lpm_add_ipv4_rt(struct nse_hw *hw,
			char *arg, char *act_type, u32 dest_vsi)
{
#if NSE_LPM_FLWR_DYNAMIC_SUPPORT
	struct nse_pf *pf = (struct nse_pf *)hw->back;
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_vsi *vsi = NULL;
	struct nse_ip_route_addr *ip_addr = NULL;
	struct nse_lpm_fltr *fltr = NULL, *old_fltr = NULL;
	int err = 0;
	u32 dip = 0, shift_len = 0;

	dev_info(dev, "Start to add ipv4 route\n");

	fltr = kzalloc(sizeof(*fltr), GFP_KERNEL);
	if (!fltr)
		return -ENOMEM;

	ip_addr = &fltr->ip_key;

	err = nse_debugfs_sw_lpm_parse_rt(hw, arg, ip_addr, AF_INET);
	if (err) {
		dev_err(dev, "Fail to parse route when add ipv4 route\n");
		goto out;
	}

	if (ip_addr->prefix_len <= 0 || ip_addr->prefix_len > 32) {
		dev_err(dev, "ipv4's prefix_len should be in [1,32], cur len = %d\n",
			ip_addr->prefix_len);
		err = -EINVAL;
		goto out;
	}

	/* value should be cleared based on prefix_len*/
	shift_len = 32 - ip_addr->prefix_len;
	dip = ntohl(ip_addr->dst_ip.v4);
	dip = (dip >> shift_len) << shift_len;
	ip_addr->dst_ip.v4 = htonl(dip);

	nse_debugfs_sw_lpm_print_rt(hw, ip_addr);

	old_fltr = nse_find_lpm_fltr(ip_addr);
	if (old_fltr) {
		dev_err(dev, "Current ipv4 lpm fltr is existed, please delete then add\n");
		err = -EINVAL;
		goto out;
	}

	if (!strncmp(act_type, "vsi", 3)) {
		vsi = nse_find_vsi_by_rel_id(pf, dest_vsi);
		if (!vsi) {
			dev_err(dev, "get vsi(id = %d) err!\n", dest_vsi);
			err = -EINVAL;
			goto out;
		}
		if (!nse_is_vsi_valid(hw, vsi->idx)) {
			dev_err(dev, "vsi(id = %d) is invalid!\n", vsi->idx);
			err = -EINVAL;
			goto out;
		}
		fltr->action.fltr_act = NSE_FWD_TO_VSI;
		fltr->action.dest_vsi = vsi;
		fltr->action.flags |= NSE_LPM_ACTION_FWD_VSI |
						NSE_LPM_ACTION_DEC_TTL | NSE_LPM_ACTION_COUNT;
	} else if (!strncmp(act_type, "lan", 3)) {
		fltr->action.fltr_act = NSE_FWD_TO_LAN;
		fltr->action.flags |= NSE_LPM_ACTION_TO_LAN |
						NSE_LPM_ACTION_DEC_TTL | NSE_LPM_ACTION_COUNT;
	} else {
		fltr->action.fltr_act = NSE_DROP_PACKET;
		fltr->action.flags |= NSE_LPM_ACTION_DROP |
							NSE_LPM_ACTION_COUNT;
	}

	fltr->action.large_act_id = NSE_NODE_STATE_ID_INVALID;

	err = nse_erouter_add_lpm_fltr(hw, fltr);
	if (err) {
		dev_err(dev, "Fail to add ipv4 lpm address, err = %d\n", err);
		nse_erouter_del_lpm_fltr(hw, fltr);
		goto out;
	}

	g_nse_ipv4_rt_lut_id = fltr->lut_id;

	dev_info(dev, "Success to add ipv4 route, lut_id = %d, node_id = %d\n",
		fltr->lut_id, fltr->node_id);

	hlist_add_head(&fltr->lpm_node, &lpm_fltr_list);

	return err;

out:
	kfree(fltr);
	return err;

#else
	struct nse_pf *pf = (struct nse_pf *)hw->back;
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_vsi *vsi = NULL;
	struct nse_ip_route_addr *ip_addr = NULL;
	struct nse_lpm_info *lpm_entry = NULL;
	int err = 0;

	dev_info(dev, "Start to add ipv4 route\n");

	lpm_entry = kzalloc(sizeof(*lpm_entry), GFP_KERNEL);
	if (!lpm_entry)
		return -ENOMEM;

	ip_addr = &lpm_entry->ip_addr;

	err = nse_debugfs_sw_lpm_parse_rt(hw, arg, ip_addr, AF_INET);
	if (err) {
		dev_err(dev, "Fail to parse route when add ipv4 route\n");
		err = -EINVAL;
		goto out;
	}

	nse_debugfs_sw_lpm_print_rt(hw, ip_addr);

	if (!strncmp(act_type, "vsi", 3)) {
		vsi = nse_find_vsi_by_rel_id(pf, dest_vsi);
		if (!vsi) {
			dev_err(dev, "get vsi(id = %d) err!\n", dest_vsi);
			err = -EINVAL;
			goto out;
		}

		if (!nse_is_vsi_valid(hw, vsi->idx)) {
			dev_err(dev, "vsi(id = %d) is invalid!\n", vsi->idx);
			err = -EINVAL;
			goto out;
		}

		lpm_entry->fltr_act = NSE_FWD_TO_VSI;
		lpm_entry->lb_en = true;
		lpm_entry->lan_en = false;
		lpm_entry->dst_vsi_id = nse_get_hw_vsi_num(hw, vsi->idx);
	} else if (!strncmp(act_type, "lan", 3)) {
		lpm_entry->fltr_act = NSE_FWD_TO_LAN;
		lpm_entry->lb_en = false;
		lpm_entry->lan_en = true;
	} else {
		lpm_entry->fltr_act = NSE_DROP_PACKET;
		lpm_entry->lb_en = false;
		lpm_entry->lan_en = false;
	}

	lpm_entry->lkup_type = NSE_LPM_LKUP_IPV4;

	err = nse_lpm_add_ipv4_addr(hw, lpm_entry);
	if (err) {
		dev_err(dev, "Fail to add ipv4 lpm address, err = %d\n", err);
		err = -EINVAL;
		goto out;
	}

out:
	kfree(lpm_entry);
	return err;
#endif
}

void
nse_debugfs_sw_lpm_del_ipv4_rt(struct nse_hw *hw,
			char *arg)
{
#if NSE_LPM_FLWR_DYNAMIC_SUPPORT
	struct nse_pf *pf = (struct nse_pf *)hw->back;
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_ip_route_addr *ip_addr = NULL;
	struct nse_lpm_fltr *fltr = NULL;
	int err = 0;
	u32 dip = 0, shift_len = 0;

	dev_info(dev, "Start to del ipv4 route\n");

	ip_addr = kzalloc(sizeof(*ip_addr), GFP_KERNEL);
	if (!ip_addr)
		return;

	err = nse_debugfs_sw_lpm_parse_rt(hw, arg, ip_addr, AF_INET);
	if (err) {
		dev_err(dev, "Fail to parse route when del ipv4 route\n");
		goto out;
	}

	if (ip_addr->prefix_len <= 0 || ip_addr->prefix_len > 32) {
		dev_err(dev, "ipv4's prefix_len should be in [1,32], cur len = %d\n",
			ip_addr->prefix_len);
		goto out;
	}

	/* value should be cleared based on prefix_len*/
	shift_len = 32 - ip_addr->prefix_len;
	dip = ntohl(ip_addr->dst_ip.v4);
	dip = (dip >> shift_len) << shift_len;
	ip_addr->dst_ip.v4 = htonl(dip);

	nse_debugfs_sw_lpm_print_rt(hw, ip_addr);

	if (g_nse_ipv4_rt_lut_id == -1) {
		dev_err(dev,
			"ipv4 rt is not created yet, please add ipv4 rt first\n");
		goto out;
	}

	fltr = nse_find_lpm_fltr(ip_addr);
	if (!fltr) {
		dev_info(dev, "Current ipv4 lpm fltr is not existed\n");
		goto out;
	}

	fltr->lut_id = g_nse_ipv4_rt_lut_id;
	nse_erouter_del_lpm_fltr(hw, fltr);
	hlist_del(&fltr->lpm_node);
	kfree(fltr);

out:
	kfree(ip_addr);
	return;
#else
	struct nse_pf *pf = (struct nse_pf *)hw->back;
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_ip_route_addr *ip_addr = NULL;
	struct nse_lpm_info *lpm_entry = NULL;
	int err = 0;

	dev_info(dev, "Start to del ipv4 route\n");

	lpm_entry = kzalloc(sizeof(*lpm_entry), GFP_KERNEL);
	if (!lpm_entry)
		return;

	ip_addr = &lpm_entry->ip_addr;

	err = nse_debugfs_sw_lpm_parse_rt(hw, arg, ip_addr, AF_INET);
	if (err) {
		dev_err(dev, "Fail to parse route when del ipv4 route\n");
		goto out;
	}

	nse_debugfs_sw_lpm_print_rt(hw, ip_addr);

	lpm_entry->lkup_type = NSE_LPM_LKUP_IPV4;

	err = nse_lpm_del_ipv4_addr(hw, lpm_entry);
	if (err) {
		dev_err(dev, "Fail to del ipv4 lpm address, err = %d\n", err);
		goto out;
	}

out:
	kfree(lpm_entry);
	return;
#endif
}

int
nse_debugfs_sw_lpm_add_ipv6_rt(struct nse_hw *hw,
			char *arg, char *act_type, u32 dest_vsi)
{
#if NSE_LPM_FLWR_DYNAMIC_SUPPORT
	struct nse_pf *pf = (struct nse_pf *)hw->back;
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_vsi *vsi = NULL;
	struct nse_ip_route_addr *ip_addr = NULL;
	struct nse_lpm_fltr *fltr = NULL, *old_fltr = NULL;
	int err = 0, i;
	u8 byte, bit;

	dev_info(dev, "Start to add ipv6 route\n");

	fltr = kzalloc(sizeof(*fltr), GFP_KERNEL);
	if (!fltr)
		return -ENOMEM;

	ip_addr = &fltr->ip_key;

	err = nse_debugfs_sw_lpm_parse_rt(hw, arg, ip_addr, AF_INET6);
	if (err) {
		dev_err(dev, "Fail to parse route when add ipv6 route\n");
		goto out;
	}

	if (ip_addr->prefix_len <= 0 || ip_addr->prefix_len > 128) {
		dev_err(dev, "ipv6's prefix_len should be in [1,128], cur len = %d\n",
			ip_addr->prefix_len);
		err = -EINVAL;
		goto out;
	}

	/* value should be cleared based on prefix_len*/
	byte = (u8)(ip_addr->prefix_len - 1) >> 3;
	bit = (u8)(~(ip_addr->prefix_len - 1)) & 0x7;
	for (i = 15; i > byte; i--)
		ip_addr->dst_ip.v6.s6_addr[i] = 0;
	ip_addr->dst_ip.v6.s6_addr[i] = (ip_addr->dst_ip.v6.s6_addr[i] >> bit) << bit;

	nse_debugfs_sw_lpm_print_rt(hw, ip_addr);

	old_fltr = nse_find_lpm_fltr(ip_addr);
	if (old_fltr) {
		dev_err(dev, "Current ipv6 lpm fltr is existed, please delete then add\n");
		err = -EINVAL;
		goto out;
	}

	if (!strncmp(act_type, "vsi", 3)) {
		vsi = nse_find_vsi_by_rel_id(pf, dest_vsi);
		if (!vsi) {
			dev_err(dev, "get vsi(id = %d) err!\n", dest_vsi);
			err = -EINVAL;
			goto out;
		}
		if (!nse_is_vsi_valid(hw, vsi->idx)) {
			dev_err(dev, "vsi(id = %d) is invalid!\n", vsi->idx);
			err = -EINVAL;
			goto out;
		}
		fltr->action.fltr_act = NSE_FWD_TO_VSI;
		fltr->action.dest_vsi = vsi;
		fltr->action.flags |= NSE_LPM_ACTION_FWD_VSI |
				 NSE_LPM_ACTION_DEC_HLIMIT | NSE_LPM_ACTION_COUNT;
	} else if (!strncmp(act_type, "lan", 3)) {
		fltr->action.fltr_act = NSE_FWD_TO_LAN;
		fltr->action.flags |= NSE_LPM_ACTION_TO_LAN |
				NSE_LPM_ACTION_DEC_HLIMIT | NSE_LPM_ACTION_COUNT;
	} else {
		fltr->action.fltr_act = NSE_DROP_PACKET;
		fltr->action.flags |= NSE_LPM_ACTION_DROP |
							NSE_LPM_ACTION_COUNT;
	}

	fltr->action.large_act_id = NSE_NODE_STATE_ID_INVALID;

	err = nse_erouter_add_lpm_fltr(hw, fltr);
	if (err) {
		dev_err(dev, "Fail to add ipv6 lpm address, err = %d\n", err);
		nse_erouter_del_lpm_fltr(hw, fltr);
		goto out;
	}

	g_nse_ipv6_rt_lut_id = fltr->lut_id;

	dev_info(dev, "Success to add ipv6 route, lut_id = %d, node_id = %d\n",
		fltr->lut_id, fltr->node_id);

	hlist_add_head(&fltr->lpm_node, &lpm_fltr_list);

	return err;

out:
	kfree(fltr);
	return err;

#else
	struct nse_pf *pf = (struct nse_pf *)hw->back;
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_ip_route_addr ip_addr = { 0 };
	int err = 0;

	dev_info(dev, "Start to add ipv6 route\n");

	err = nse_debugfs_sw_lpm_parse_rt(hw, arg, &ip_addr, AF_INET6);
	if (err) {
		dev_info(dev, "Fail to parse route when add ipv6 route\n");
		return err;
	}

	nse_debugfs_sw_lpm_print_rt(hw, &ip_addr);

	return err;

#endif
}

void
nse_debugfs_sw_lpm_del_ipv6_rt(struct nse_hw *hw,
			char *arg)
{
#if NSE_LPM_FLWR_DYNAMIC_SUPPORT
	struct nse_pf *pf = (struct nse_pf *)hw->back;
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_ip_route_addr *ip_addr = NULL;
	struct nse_lpm_fltr *fltr = NULL;
	int err = 0, i;
	u8 byte, bit;

	dev_info(dev, "Start to del ipv6 route\n");

	ip_addr = kzalloc(sizeof(*ip_addr), GFP_KERNEL);
	if (!ip_addr)
		return;

	err = nse_debugfs_sw_lpm_parse_rt(hw, arg, ip_addr, AF_INET6);
	if (err) {
		dev_err(dev, "Fail to parse route when del ipv6 route\n");
		goto out;
	}

	if (ip_addr->prefix_len <= 0 || ip_addr->prefix_len > 128) {
		dev_err(dev, "ipv6's prefix_len should be in [1,128], cur len = %d\n",
			ip_addr->prefix_len);
		goto out;
	}

	/* value should be cleared based on prefix_len*/
	byte = (u8)(ip_addr->prefix_len - 1) >> 3;
	bit = (u8)(~(ip_addr->prefix_len - 1)) & 0x7;
	for (i = 15; i > byte; i--)
		ip_addr->dst_ip.v6.s6_addr[i] = 0;
	ip_addr->dst_ip.v6.s6_addr[i] = (ip_addr->dst_ip.v6.s6_addr[i] >> bit) << bit;

	nse_debugfs_sw_lpm_print_rt(hw, ip_addr);

	if (g_nse_ipv6_rt_lut_id == -1) {
		dev_err(dev,
			"ipv6 rt is not created yet, please add ipv6 rt first\n");
		goto out;
	}

	fltr = nse_find_lpm_fltr(ip_addr);
	if (!fltr) {
		dev_info(dev, "Current ipv6 lpm fltr is not existed\n");
		goto out;
	}

	fltr->lut_id = g_nse_ipv6_rt_lut_id;

	nse_erouter_del_lpm_fltr(hw, fltr);

	hlist_del(&fltr->lpm_node);

	kfree(fltr);

out:
	kfree(ip_addr);
	return;
#else
	return;
#endif
}

static ssize_t
nse_debugfs_sw_lpm_wfunc(struct file *filp, const char __user *buf,
			  size_t count, loff_t *ppos)
{
	struct nse_pf *pf = filp->private_data;
	struct nse_hw *hw = &pf->hw;
	struct device *dev = nse_pf_to_dev(pf);
	char *cmd_buf, *cmd_buf_tmp;
	ssize_t ret;
	char **argv;
	int argc;
	unsigned int val = 0;

	/* don't allow partial writes and writes when reset is in progress*/
	if (*ppos != 0 || nse_is_reset_in_progress(pf->state))
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

	if (!strncmp(argv[0], "ipv4_rt_add", 11)) { /* lpm: ipv4 route add*/
		if (argc < 3)
			goto bad_usage;

		if (strncmp(argv[2], "vsi", 3) &&
			strncmp(argv[2], "drop", 4) &&
			strncmp(argv[2], "lan", 3))
			goto bad_usage;

		if (!strncmp(argv[2], "vsi", 3)) {
			if (argc < 4)
				goto bad_usage;

			if (kstrtouint(argv[3], 10, &val))
				goto bad_usage;
		}

		ret = nse_debugfs_sw_lpm_add_ipv4_rt(hw, argv[1], argv[2], val);
		if (ret)
			goto command_write_done;

	} else if (!strncmp(argv[0], "ipv4_rt_del", 11)) { /* lpm: ipv4 route del*/
		if (argc < 2)
			goto bad_usage;

		nse_debugfs_sw_lpm_del_ipv4_rt(hw, argv[1]);

	} else if (!strncmp(argv[0], "ipv6_rt_add", 11)) { /* lpm: ipv6 route add*/
		if (argc < 3)
			goto bad_usage;

		if (strncmp(argv[2], "vsi", 3) &&
			strncmp(argv[2], "drop", 4) &&
			strncmp(argv[2], "lan", 3))
			goto bad_usage;

		if (!strncmp(argv[2], "vsi", 3)) {
			if (argc < 4)
				goto bad_usage;

			if (kstrtouint(argv[3], 10, &val))
				goto bad_usage;
		}

		ret = nse_debugfs_sw_lpm_add_ipv6_rt(hw, argv[1], argv[2], val);
		if (ret)
			goto command_write_done;

	} else if (!strncmp(argv[0], "ipv6_rt_del", 11)) { /* lpm: ipv6 route del*/
		if (argc < 2)
			goto bad_usage;

		nse_debugfs_sw_lpm_del_ipv6_rt(hw, argv[1]);

	} else if (!strncmp(argv[0], "dmac_ipv4_rt_add", 16)) { /* lpm: ipv4 route add*/
		if (argc < 3)
			goto bad_usage;

		if (strncmp(argv[2], "vsi", 3) &&
			strncmp(argv[2], "drop", 4) &&
			strncmp(argv[2], "lan", 3))
			goto bad_usage;

		if (!strncmp(argv[2], "vsi", 3)) {
			if (argc < 4)
				goto bad_usage;

			if (kstrtouint(argv[3], 10, &val))
				goto bad_usage;
		}

		nse_debugfs_sw_lpm_add_dmac_ipv4_rt(hw, argv[1], argv[2], val);

	} else if (!strncmp(argv[0], "dmac_ipv4_rt_del", 16)) { /* lpm: ipv4 route del*/
		if (argc < 2)
			goto bad_usage;

		nse_debugfs_sw_lpm_del_dmac_ipv4_rt(hw, argv[1]);

	} else if (!strncmp(argv[0], "dmac_ipv6_rt_add", 16)) { /* lpm: ipv6 route add*/
		if (argc < 3)
			goto bad_usage;

		if (strncmp(argv[2], "vsi", 3) &&
			strncmp(argv[2], "drop", 4) &&
			strncmp(argv[2], "lan", 3))
			goto bad_usage;

		if (!strncmp(argv[2], "vsi", 3)) {
			if (argc < 4)
				goto bad_usage;

			if (kstrtouint(argv[3], 10, &val))
				goto bad_usage;
		}

		nse_debugfs_sw_lpm_add_dmac_ipv6_rt(hw, argv[1], argv[2], val);

	} else if (!strncmp(argv[0], "dmac_ipv6_rt_del", 16)) { /* lpm: ipvdmac_6 route del*/
		if (argc < 2)
			goto bad_usage;

		nse_debugfs_sw_lpm_del_dmac_ipv6_rt(hw, argv[1]);

	} else if (!strncmp(argv[0], "dump", 4)) { /*dump cmd*/

		if (!strncmp(argv[1], "ipv4_rt", 7)) {
			nse_dump_lpm_ipv4_entry(hw);

		} else if (!strncmp(argv[1], "lpm_nodes", 9)) {
			if (argc != 3)
				goto bad_usage;

			if (kstrtouint(argv[2], 10, &val))
				goto bad_usage;

			nse_dump_adv_lpm_lut_nodes(hw, val);

		} else
			goto bad_usage;

	} else if (!strncmp(argv[0], "lpm", 3)) { /*lpm mode enable/disable cmd*/

		if (!strncmp(argv[1], "enable", 6))
			nse_enable_erouter_mode(hw);

		else if (!strncmp(argv[1], "disable", 7))
			nse_disable_erouter_mode(hw);

		else
			goto bad_usage;

	} else
		goto bad_usage;

	/* if we get here, nothing went wrong; return bytes copied */
	ret = (ssize_t)count;

command_write_done:
	argv_free(argv);
err_copy_from_user:
	kfree(cmd_buf);
	return ret;

bad_usage:
	dev_info(dev, "unknown or invalid input: '%s'\n", cmd_buf);
	dev_info(dev, "commands of lpm test:\n");
	dev_info(dev, "\t lpm enable\n");
	dev_info(dev, "\t lpm disable\n");
	dev_info(dev, "\t ipv4_rt_add *.*.*.*/mask vsi $N\n");
	dev_info(dev, "\t ipv4_rt_add *.*.*.*/mask lan\n");
	dev_info(dev, "\t ipv4_rt_add *.*.*.*/mask drop\n");
	dev_info(dev, "\t ipv4_rt_del *.*.*.*/mask\n");
	dev_info(dev, "\t ipv6_rt_add *.*.*.*/mask vsi $N\n");
	dev_info(dev, "\t ipv6_rt_add *.*.*.*/mask lan\n");
	dev_info(dev, "\t ipv6_rt_add *.*.*.*/mask drop\n");
	dev_info(dev, "\t ipv6_rt_del *::*/mask\n");
	dev_info(dev, "commands of lpm dump:\n");
	dev_info(dev, "\t dump lpm_nodes $lut_id\n");
	ret = -EINVAL;
	goto command_write_done;
}

static const struct file_operations nse_debugfs_sw_lpm_fops = {
	.owner = THIS_MODULE,
	.open  = simple_open,
	.write = nse_debugfs_sw_lpm_wfunc,
	.llseek = default_llseek,
};

static struct hlist_head nse_acl_fltr_rx_list;
static struct hlist_head nse_acl_fltr_tx_list;

struct nse_acl_fltr {
	struct hlist_node acl_node;
	u32 vsi_id;
	struct nse_acl_fltr_info fltr_info;
};

static struct nse_acl_fltr *
nse_find_rx_acl_fltr(u32 vsi_id)
{
	struct nse_acl_fltr *fltr = NULL;

	hlist_for_each_entry(fltr, &nse_acl_fltr_rx_list, acl_node) {
		if (fltr->vsi_id == vsi_id)
			return fltr;
	}

	return NULL;
}

static struct nse_acl_fltr *
nse_find_tx_acl_fltr(u32 vsi_id)
{
	struct nse_acl_fltr *fltr = NULL;

	hlist_for_each_entry(fltr, &nse_acl_fltr_tx_list, acl_node) {
		if (fltr->vsi_id == vsi_id)
			return fltr;
	}

	return NULL;
}

void
nse_debugfs_acl_fltr_rx_del(struct nse_hw *hw,
						u32 dest_vsi)
{
	struct nse_pf *pf = (struct nse_pf *)hw->back;
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_acl_fltr *fltr = NULL;

	fltr = nse_find_rx_acl_fltr(dest_vsi);
	if (!fltr) {
		dev_info(dev,
			"[%s, %d] dest_vsi %d acl entry is not existed!\n",
			__func__, __LINE__, dest_vsi);
		goto err;
	}

	dev_info(dev,
		"[%s, %d] Start to remove dest_vsi %d rx acl entry, node_id = %d\n",
		__func__, __LINE__, dest_vsi, fltr->fltr_info.node_id);

	nse_acl_remove_fltr(hw, &fltr->fltr_info);
	hlist_del(&fltr->acl_node);
	kfree(fltr);
err:
	return;
}

void
nse_debugfs_acl_fltr_rx_add_drop(struct nse_hw *hw,
						u32 dest_vsi)
{
	struct nse_pf *pf = (struct nse_pf *)hw->back;
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_acl_fltr *fltr = NULL, *old_fltr = NULL;
	int err = 0;

	fltr = kzalloc(sizeof(*fltr), GFP_KERNEL);
	if (!fltr)
		return;

	old_fltr = nse_find_rx_acl_fltr(dest_vsi);
	if (old_fltr) {
		dev_err(dev,
			"[%s, %d] dest_vsi %d acl entry is existed!\n",
			__func__, __LINE__, dest_vsi);
		goto err;
	}

	fltr->vsi_id = dest_vsi;
	fltr->fltr_info.lkup_type = NSE_ACL_LKUP_RX_DEST_VSI;
	fltr->fltr_info.fltr_act = NSE_ACL_DROP;
	fltr->fltr_info.sw_id = hw->port_info->sw_id;
	fltr->fltr_info.dst_hw_vsi = (u16)dest_vsi;

	err = nse_acl_add_fltr(hw, &fltr->fltr_info);
	if (err) {
		dev_err(dev,
			"[%s, %d] dest_vsi %d rx drop action is added fail!\n",
			__func__, __LINE__, dest_vsi);
		goto err;
	}

	dev_info(dev,
		"[%s, %d] dest_vsi %d rx drop action is added successfully, node_id = %d\n",
		__func__, __LINE__, dest_vsi, fltr->fltr_info.node_id);

	hlist_add_head(&fltr->acl_node, &nse_acl_fltr_rx_list);
	return;

err:
	kfree(fltr);
}

void
nse_debugfs_acl_fltr_rx_add_meter(struct nse_hw *hw,
						u32 dest_vsi, bool is_pps)
{
	struct nse_pf *pf = (struct nse_pf *)hw->back;
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_acl_fltr *fltr = NULL, *old_fltr = NULL;
	int err = 0;

	fltr = kzalloc(sizeof(*fltr), GFP_KERNEL);
	if (!fltr)
		return;

	old_fltr = nse_find_rx_acl_fltr(dest_vsi);
	if (old_fltr) {
		dev_err(dev,
			"[%s, %d] dest_vsi %d acl entry is existed!\n",
			__func__, __LINE__, dest_vsi);
		goto err;
	}

	fltr->vsi_id = dest_vsi;
	fltr->fltr_info.lkup_type = NSE_ACL_LKUP_RX_DEST_VSI;
	fltr->fltr_info.fltr_act = NSE_ACL_METER;
	fltr->fltr_info.sw_id = hw->port_info->sw_id;
	fltr->fltr_info.dst_hw_vsi = (u16)dest_vsi;

	if (is_pps)
		fltr->fltr_info.meter_param.mode = NSE_RATE_LIMIT_PPS;
	else
		fltr->fltr_info.meter_param.mode = NSE_RATE_LIMIT_BPS;

	fltr->fltr_info.meter_param.rate = 1000;
	fltr->fltr_info.meter_param.burst = 1000;

	err = nse_acl_add_fltr(hw, &fltr->fltr_info);
	if (err) {
		dev_err(dev,
			"[%s, %d] dest_vsi %d rx meter action is added fail!\n",
			__func__, __LINE__, dest_vsi);
		goto err;
	}

	dev_info(dev,
		"[%s, %d] dest_vsi %d rx meter action is added successfully, node_id = %d\n",
		__func__, __LINE__, dest_vsi, fltr->fltr_info.node_id);

	hlist_add_head(&fltr->acl_node, &nse_acl_fltr_rx_list);
	return;

err:
	kfree(fltr);
}

void
nse_debugfs_acl_fltr_rx_add_multi_meters(struct nse_hw *hw,
						u32 dest_vsi)
{
	struct nse_pf *pf = (struct nse_pf *)hw->back;
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_acl_fltr *fltr = NULL, *old_fltr = NULL;
	int err = 0;

	fltr = kzalloc(sizeof(*fltr), GFP_KERNEL);
	if (!fltr)
		return;

	old_fltr = nse_find_rx_acl_fltr(dest_vsi);
	if (old_fltr) {
		dev_err(dev,
			"[%s, %d] dest_vsi %d acl entry is existed!\n",
			__func__, __LINE__, dest_vsi);
		goto err;
	}

	fltr->vsi_id = dest_vsi;

	/*lut id and key for match*/
	fltr->fltr_info.lkup_type = NSE_ACL_LKUP_RX_DEST_VSI;
	fltr->fltr_info.sw_id = hw->port_info->sw_id;
	fltr->fltr_info.dst_hw_vsi = (u16)dest_vsi;

	/*parameter and flags for action*/
	fltr->fltr_info.fltr_act = NSE_ACL_LARGE_ACT;
	fltr->fltr_info.lg_action.flags = NSE_ACL_LARGE_ACTION_DU_METER;
	fltr->fltr_info.lg_action.du_meter_cnt = NSE_ACL_MAX_DU_METER_ACTIONS;
	fltr->fltr_info.lg_action.du_meter_param[0].mode = NSE_RATE_LIMIT_PPS;
	fltr->fltr_info.lg_action.du_meter_param[0].rate = 1000;
	fltr->fltr_info.lg_action.du_meter_param[0].burst = 1000;
	fltr->fltr_info.lg_action.du_meter_param[1].mode = NSE_RATE_LIMIT_BPS;
	fltr->fltr_info.lg_action.du_meter_param[1].rate = 1000;
	fltr->fltr_info.lg_action.du_meter_param[1].burst = 1000;

	err = nse_acl_add_fltr(hw, &fltr->fltr_info);
	if (err) {
		dev_err(dev,
			"[%s, %d] dest_vsi %d rx meter action is added fail!\n",
			__func__, __LINE__, dest_vsi);
		goto err;
	}

	dev_info(dev,
		"[%s, %d] dest_vsi %d rx meter action is added successfully, node_id = %d\n",
		__func__, __LINE__, dest_vsi, fltr->fltr_info.node_id);

	hlist_add_head(&fltr->acl_node, &nse_acl_fltr_rx_list);
	return;

err:
	kfree(fltr);
}

void
nse_debugfs_acl_fltr_rx_add_drop_stats(struct nse_hw *hw,
						u32 dest_vsi)
{
	struct nse_pf *pf = (struct nse_pf *)hw->back;
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_acl_fltr *fltr = NULL, *old_fltr = NULL;
	int err = 0;

	fltr = kzalloc(sizeof(*fltr), GFP_KERNEL);
	if (!fltr)
		return;

	old_fltr = nse_find_rx_acl_fltr(dest_vsi);
	if (old_fltr) {
		dev_err(dev,
			"[%s, %d] dest_vsi %d acl entry is existed!\n",
			__func__, __LINE__, dest_vsi);
		goto err;
	}

	fltr->vsi_id = dest_vsi;

	/*lut id and key for match*/
	fltr->fltr_info.lkup_type = NSE_ACL_LKUP_RX_DEST_VSI;
	fltr->fltr_info.sw_id = hw->port_info->sw_id;
	fltr->fltr_info.dst_hw_vsi = (u16)dest_vsi;

	/*parameter and flags for action*/
	fltr->fltr_info.fltr_act = NSE_ACL_LARGE_ACT;
	fltr->fltr_info.lg_action.flags = NSE_ACL_LARGE_ACTION_DROP |
			NSE_ACL_LARGE_ACTION_COUNT;

	err = nse_acl_add_fltr(hw, &fltr->fltr_info);
	if (err) {
		dev_err(dev,
			"[%s, %d] dest_vsi %d rx drop_stats action is added fail!\n",
			__func__, __LINE__, dest_vsi);
		goto err;
	}

	dev_info(dev,
		"[%s, %d] dest_vsi %d rx drop_stats action is added successfully, node_id = %d\n",
		__func__, __LINE__, dest_vsi, fltr->fltr_info.node_id);

	hlist_add_head(&fltr->acl_node, &nse_acl_fltr_rx_list);
	return;

err:
	kfree(fltr);
}

void
nse_debugfs_acl_fltr_rx_add_redir_vsi(struct nse_hw *hw,
						u32 dest_vsi, u32 redir_vsi)
{
	struct nse_pf *pf = (struct nse_pf *)hw->back;
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_acl_fltr *fltr = NULL, *old_fltr = NULL;
	int err = 0;

	fltr = kzalloc(sizeof(*fltr), GFP_KERNEL);
	if (!fltr)
		return;

	old_fltr = nse_find_rx_acl_fltr(dest_vsi);
	if (old_fltr) {
		dev_err(dev,
			"[%s, %d] dest_vsi %d acl entry is existed!\n",
			__func__, __LINE__, dest_vsi);
		goto err;
	}

	fltr->vsi_id = dest_vsi;

	/*lut id and key for match*/
	fltr->fltr_info.lkup_type = NSE_ACL_LKUP_RX_DEST_VSI;
	fltr->fltr_info.sw_id = hw->port_info->sw_id;
	fltr->fltr_info.dst_hw_vsi = (u16)dest_vsi;

	/*parameter and flags for action*/
	fltr->fltr_info.fltr_act = NSE_ACL_LARGE_ACT;
	fltr->fltr_info.lg_action.flags = NSE_ACL_LARGE_ACTION_FWD_VSI |
			NSE_ACL_LARGE_ACTION_COUNT;
	fltr->fltr_info.lg_action.redirect_vsi = (u16)redir_vsi;

	err = nse_acl_add_fltr(hw, &fltr->fltr_info);
	if (err) {
		dev_err(dev,
			"[%s, %d] dest_vsi %d rx redir_vsi action is added fail!\n",
			__func__, __LINE__, dest_vsi);
		goto err;
	}

	dev_info(dev,
		"[%s, %d] dest_vsi %d rx redir_vsi action is added successfully, node_id = %d\n",
		__func__, __LINE__, dest_vsi, fltr->fltr_info.node_id);

	hlist_add_head(&fltr->acl_node, &nse_acl_fltr_rx_list);
	return;

err:
	kfree(fltr);
}

void
nse_debugfs_acl_fltr_rx_add_au_smac_rw(struct nse_hw *hw,
						u32 dest_vsi)
{
	struct nse_pf *pf = (struct nse_pf *)hw->back;
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_acl_fltr *fltr = NULL, *old_fltr = NULL;
	u8 smac_addr[ETH_ALEN] = {0x00, 0x55, 0x44, 0x33, 0x22, 0x11};
	u8 smac_mask[ETH_ALEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
	struct nse_acl_pedit_headers *hdrs;
	int err = 0;

	fltr = kzalloc(sizeof(*fltr), GFP_KERNEL);
	if (!fltr)
		return;

	old_fltr = nse_find_rx_acl_fltr(dest_vsi);
	if (old_fltr) {
		dev_err(dev,
			"[%s, %d] dest_vsi %d acl entry is existed!\n",
			__func__, __LINE__, dest_vsi);
		goto err;
	}

	fltr->vsi_id = dest_vsi;

	/*lut id and key for match*/
	fltr->fltr_info.lkup_type = NSE_ACL_LKUP_RX_DEST_VSI;
	fltr->fltr_info.sw_id = hw->port_info->sw_id;
	fltr->fltr_info.dst_hw_vsi = (u16)dest_vsi;

	/*parameter and flags for action*/
	fltr->fltr_info.fltr_act = NSE_ACL_LARGE_ACT;
	fltr->fltr_info.lg_action.flags = NSE_ACL_LARGE_ACTION_AU_SMAC_RW |
			NSE_ACL_LARGE_ACTION_COUNT;

	hdrs = &fltr->fltr_info.lg_action.hdrs;
	ether_addr_copy(hdrs->vals.eth.h_source, smac_addr);
	ether_addr_copy(hdrs->masks.eth.h_source, smac_mask);
	hdrs->pedits++;

	err = nse_acl_add_fltr(hw, &fltr->fltr_info);
	if (err) {
		dev_err(dev,
			"[%s, %d] dest_vsi %d rx au_smac_rw action is added fail!\n",
			__func__, __LINE__, dest_vsi);
		goto err;
	}

	dev_info(dev,
		"[%s, %d] dest_vsi %d rx au_smac_rw action is added successfully, node_id = %d\n",
		__func__, __LINE__, dest_vsi, fltr->fltr_info.node_id);

	hlist_add_head(&fltr->acl_node, &nse_acl_fltr_rx_list);
	return;

err:
	kfree(fltr);
}

void
nse_debugfs_acl_fltr_rx_add_au_mac_rw(struct nse_hw *hw,
						u32 dest_vsi)
{
	struct nse_pf *pf = (struct nse_pf *)hw->back;
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_acl_fltr *fltr = NULL, *old_fltr = NULL;
	u8 smac_addr[ETH_ALEN] = {0x00, 0x55, 0x44, 0x33, 0x22, 0x11};
	u8 smac_mask[ETH_ALEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
	u8 dmac_addr[ETH_ALEN] = {0x66, 0x55, 0x44, 0x33, 0x22, 0x11};
	u8 dmac_mask[ETH_ALEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
	struct nse_acl_pedit_headers *hdrs;
	int err = 0;

	fltr = kzalloc(sizeof(*fltr), GFP_KERNEL);
	if (!fltr)
		return;

	old_fltr = nse_find_rx_acl_fltr(dest_vsi);
	if (old_fltr) {
		dev_err(dev,
			"[%s, %d] dest_vsi %d acl entry is existed!\n",
			__func__, __LINE__, dest_vsi);
		goto err;
	}

	fltr->vsi_id = dest_vsi;

	/*lut id and key for match*/
	fltr->fltr_info.lkup_type = NSE_ACL_LKUP_RX_DEST_VSI;
	fltr->fltr_info.sw_id = hw->port_info->sw_id;
	fltr->fltr_info.dst_hw_vsi = (u16)dest_vsi;

	/*parameter and flags for action*/
	fltr->fltr_info.fltr_act = NSE_ACL_LARGE_ACT;
	fltr->fltr_info.lg_action.flags = NSE_ACL_LARGE_ACTION_AU_SMAC_RW |
			NSE_ACL_LARGE_ACTION_AU_DMAC_RW |
			NSE_ACL_LARGE_ACTION_COUNT;

	hdrs = &fltr->fltr_info.lg_action.hdrs;
	ether_addr_copy(hdrs->vals.eth.h_source, smac_addr);
	ether_addr_copy(hdrs->masks.eth.h_source, smac_mask);
	hdrs->pedits++;

	ether_addr_copy(hdrs->vals.eth.h_dest, dmac_addr);
	ether_addr_copy(hdrs->masks.eth.h_dest, dmac_mask);
	hdrs->pedits++;

	err = nse_acl_add_fltr(hw, &fltr->fltr_info);
	if (err) {
		dev_err(dev,
			"[%s, %d] dest_vsi %d rx au_mac_rw action is added fail!\n",
			__func__, __LINE__, dest_vsi);
		goto err;
	}

	dev_info(dev,
		"[%s, %d] dest_vsi %d rx au_mac_rw action is added successfully, node_id = %d\n",
		__func__, __LINE__, dest_vsi, fltr->fltr_info.node_id);

	hlist_add_head(&fltr->acl_node, &nse_acl_fltr_rx_list);
	return;

err:
	kfree(fltr);
}

void
nse_debugfs_acl_fltr_rx_add_goto(struct nse_hw *hw,
						u32 dest_vsi)
{
	struct nse_pf *pf = (struct nse_pf *)hw->back;
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_acl_fltr *fltr = NULL, *old_fltr = NULL;
	int err = 0;

	fltr = kzalloc(sizeof(*fltr), GFP_KERNEL);
	if (!fltr)
		return;

	old_fltr = nse_find_rx_acl_fltr(dest_vsi);
	if (old_fltr) {
		dev_err(dev,
			"[%s, %d] dest_vsi %d acl entry is existed!\n",
			__func__, __LINE__, dest_vsi);
		goto err;
	}

	fltr->vsi_id = dest_vsi;

	/*lut id and key for match*/
	fltr->fltr_info.lkup_type = NSE_ACL_LKUP_RX_DEST_VSI;
	fltr->fltr_info.sw_id = hw->port_info->sw_id;
	fltr->fltr_info.dst_hw_vsi = (u16)dest_vsi;

	/*parameter and flags for action*/
	fltr->fltr_info.fltr_act = NSE_ACL_LARGE_ACT;
	fltr->fltr_info.lg_action.flags = NSE_ACL_LARGE_ACTION_GOTO |
			NSE_ACL_LARGE_ACTION_COUNT;

	err = nse_acl_add_fltr(hw, &fltr->fltr_info);
	if (err) {
		dev_err(dev,
			"[%s, %d] dest_vsi %d rx goto action is added fail!\n",
			__func__, __LINE__, dest_vsi);
		goto err;
	}

	dev_info(dev,
		"[%s, %d] dest_vsi %d rx goto action is added successfully, node_id = %d\n",
		__func__, __LINE__, dest_vsi, fltr->fltr_info.node_id);

	hlist_add_head(&fltr->acl_node, &nse_acl_fltr_rx_list);
	return;

err:
	kfree(fltr);
}

/*tx direction*/
void
nse_debugfs_acl_fltr_tx_del(struct nse_hw *hw,
						u32 src_vsi)
{
	struct nse_pf *pf = (struct nse_pf *)hw->back;
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_acl_fltr *fltr = NULL;

	fltr = nse_find_tx_acl_fltr(src_vsi);
	if (!fltr) {
		dev_info(dev,
			"[%s, %d] src_vsi %d acl entry is not existed!\n",
			__func__, __LINE__, src_vsi);
		goto err;
	}

	dev_info(dev,
		"[%s, %d] Start to remove src_vsi %d tx acl entry, node_id = %d\n",
		__func__, __LINE__, src_vsi, fltr->fltr_info.node_id);

	nse_acl_remove_fltr(hw, &fltr->fltr_info);
	hlist_del(&fltr->acl_node);
	kfree(fltr);
err:
	return;
}

void
nse_debugfs_acl_fltr_tx_add_drop(struct nse_hw *hw,
						u32 src_vsi)
{
	struct nse_pf *pf = (struct nse_pf *)hw->back;
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_acl_fltr *fltr = NULL, *old_fltr = NULL;
	int err = 0;

	fltr = kzalloc(sizeof(*fltr), GFP_KERNEL);
	if (!fltr)
		return;

	old_fltr = nse_find_tx_acl_fltr(src_vsi);
	if (old_fltr) {
		dev_err(dev,
			"[%s, %d] src_vsi %d acl entry is existed!\n",
			__func__, __LINE__, src_vsi);
		goto err;
	}

	fltr->vsi_id = src_vsi;
	fltr->fltr_info.lkup_type = NSE_ACL_LKUP_TX_SRC_VSI;
	fltr->fltr_info.fltr_act = NSE_ACL_DROP;
	fltr->fltr_info.sw_id = hw->port_info->sw_id;
	fltr->fltr_info.src_hw_vsi = (u16)src_vsi;
	fltr->fltr_info.src_hw_vsi |= (NSE_IN_PORT_TYPE_HOST <<
			NSE_IN_PORT_TYPE_S) & NSE_IN_PORT_TYPE_M;

	err = nse_acl_add_fltr(hw, &fltr->fltr_info);
	if (err) {
		dev_err(dev,
			"[%s, %d] src_vsi %d tx drop action is added fail!\n",
			__func__, __LINE__, src_vsi);
		goto err;
	}

	dev_info(dev,
		"[%s, %d] src_vsi %d tx drop action is added successfully, node_id = %d\n",
		__func__, __LINE__, src_vsi, fltr->fltr_info.node_id);

	hlist_add_head(&fltr->acl_node, &nse_acl_fltr_tx_list);
	return;

err:
	kfree(fltr);
}

void
nse_debugfs_acl_fltr_tx_add_meter(struct nse_hw *hw,
						u32 src_vsi, bool is_pps)
{
	struct nse_pf *pf = (struct nse_pf *)hw->back;
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_acl_fltr *fltr = NULL, *old_fltr = NULL;
	int err = 0;

	fltr = kzalloc(sizeof(*fltr), GFP_KERNEL);
	if (!fltr)
		return;

	old_fltr = nse_find_tx_acl_fltr(src_vsi);
	if (old_fltr) {
		dev_err(dev,
			"[%s, %d] src_vsi %d acl entry is existed!\n",
			__func__, __LINE__, src_vsi);
		goto err;
	}

	fltr->vsi_id = src_vsi;
	fltr->fltr_info.lkup_type = NSE_ACL_LKUP_TX_SRC_VSI;
	fltr->fltr_info.fltr_act = NSE_ACL_METER;
	fltr->fltr_info.sw_id = hw->port_info->sw_id;
	fltr->fltr_info.src_hw_vsi = (u16)src_vsi;
	fltr->fltr_info.src_hw_vsi |= (NSE_IN_PORT_TYPE_HOST <<
			NSE_IN_PORT_TYPE_S) & NSE_IN_PORT_TYPE_M;

	if (is_pps)
		fltr->fltr_info.meter_param.mode = NSE_RATE_LIMIT_PPS;
	else
		fltr->fltr_info.meter_param.mode = NSE_RATE_LIMIT_BPS;

	fltr->fltr_info.meter_param.rate = 1000;
	fltr->fltr_info.meter_param.burst = 1000;

	err = nse_acl_add_fltr(hw, &fltr->fltr_info);
	if (err) {
		dev_err(dev,
			"[%s, %d] src_vsi %d tx meter action is added fail!\n",
			__func__, __LINE__, src_vsi);
		goto err;
	}

	dev_info(dev,
		"[%s, %d] src_vsi %d tx meter action is added successfully, node_id = %d\n",
		__func__, __LINE__, src_vsi, fltr->fltr_info.node_id);

	hlist_add_head(&fltr->acl_node, &nse_acl_fltr_tx_list);
	return;

err:
	kfree(fltr);
}

void
nse_debugfs_acl_fltr_tx_add_multi_meters(struct nse_hw *hw,
						u32 src_vsi)
{
	struct nse_pf *pf = (struct nse_pf *)hw->back;
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_acl_fltr *fltr = NULL, *old_fltr = NULL;
	int err = 0;

	fltr = kzalloc(sizeof(*fltr), GFP_KERNEL);
	if (!fltr)
		return;

	old_fltr = nse_find_tx_acl_fltr(src_vsi);
	if (old_fltr) {
		dev_err(dev,
			"[%s, %d] src_vsi %d acl entry is existed!\n",
			__func__, __LINE__, src_vsi);
		goto err;
	}

	fltr->vsi_id = src_vsi;

	/*lut id and key for match*/
	fltr->fltr_info.lkup_type = NSE_ACL_LKUP_TX_SRC_VSI;
	fltr->fltr_info.sw_id = hw->port_info->sw_id;
	fltr->fltr_info.src_hw_vsi = (u16)src_vsi;
	fltr->fltr_info.src_hw_vsi |= (NSE_IN_PORT_TYPE_HOST <<
			NSE_IN_PORT_TYPE_S) & NSE_IN_PORT_TYPE_M;

	/*parameter and flags for action*/
	fltr->fltr_info.fltr_act = NSE_ACL_LARGE_ACT;
	fltr->fltr_info.lg_action.flags = NSE_ACL_LARGE_ACTION_DU_METER;
	fltr->fltr_info.lg_action.du_meter_cnt = NSE_ACL_MAX_DU_METER_ACTIONS;
	fltr->fltr_info.lg_action.du_meter_param[0].mode = NSE_RATE_LIMIT_PPS;
	fltr->fltr_info.lg_action.du_meter_param[0].rate = 1000;
	fltr->fltr_info.lg_action.du_meter_param[0].burst = 1000;
	fltr->fltr_info.lg_action.du_meter_param[1].mode = NSE_RATE_LIMIT_BPS;
	fltr->fltr_info.lg_action.du_meter_param[1].rate = 1000;
	fltr->fltr_info.lg_action.du_meter_param[1].burst = 1000;

	err = nse_acl_add_fltr(hw, &fltr->fltr_info);
	if (err) {
		dev_err(dev,
			"[%s, %d] src_vsi %d tx multi meter action is added fail!\n",
			__func__, __LINE__, src_vsi);
		goto err;
	}

	dev_info(dev,
		"[%s, %d] src_vsi %d tx multi meter action is added successfully, node_id = %d\n",
		__func__, __LINE__, src_vsi, fltr->fltr_info.node_id);

	hlist_add_head(&fltr->acl_node, &nse_acl_fltr_tx_list);
	return;

err:
	kfree(fltr);
}

void
nse_debugfs_acl_fltr_tx_add_drop_stats(struct nse_hw *hw,
						u32 src_vsi)
{
	struct nse_pf *pf = (struct nse_pf *)hw->back;
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_acl_fltr *fltr = NULL, *old_fltr = NULL;
	int err = 0;

	fltr = kzalloc(sizeof(*fltr), GFP_KERNEL);
	if (!fltr)
		return;

	old_fltr = nse_find_tx_acl_fltr(src_vsi);
	if (old_fltr) {
		dev_err(dev,
			"[%s, %d] src_vsi %d acl entry is existed!\n",
			__func__, __LINE__, src_vsi);
		goto err;
	}

	fltr->vsi_id = src_vsi;

	/*lut id and key for match*/
	fltr->fltr_info.lkup_type = NSE_ACL_LKUP_TX_SRC_VSI;
	fltr->fltr_info.sw_id = hw->port_info->sw_id;
	fltr->fltr_info.src_hw_vsi = (u16)src_vsi;
	fltr->fltr_info.src_hw_vsi |= (NSE_IN_PORT_TYPE_HOST <<
			NSE_IN_PORT_TYPE_S) & NSE_IN_PORT_TYPE_M;

	/*parameter and flags for action*/
	fltr->fltr_info.fltr_act = NSE_ACL_LARGE_ACT;
	fltr->fltr_info.lg_action.flags = NSE_ACL_LARGE_ACTION_DROP |
			NSE_ACL_LARGE_ACTION_COUNT;

	err = nse_acl_add_fltr(hw, &fltr->fltr_info);
	if (err) {
		dev_err(dev,
			"[%s, %d] src_vsi %d tx drop_stats action is added fail!\n",
			__func__, __LINE__, src_vsi);
		goto err;
	}

	dev_info(dev,
		"[%s, %d] src_vsi %d tx drop_stats action is added successfully, node_id = %d\n",
		__func__, __LINE__, src_vsi, fltr->fltr_info.node_id);

	hlist_add_head(&fltr->acl_node, &nse_acl_fltr_tx_list);
	return;

err:
	kfree(fltr);
}

void
nse_debugfs_acl_fltr_tx_add_au_dmac_rw(struct nse_hw *hw,
						u32 src_vsi)
{
	struct nse_pf *pf = (struct nse_pf *)hw->back;
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_acl_fltr *fltr = NULL, *old_fltr = NULL;
	u8 dmac_addr[ETH_ALEN] = {0x66, 0x55, 0x44, 0x33, 0x22, 0x11};
	u8 dmac_mask[ETH_ALEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
	struct nse_acl_pedit_headers *hdrs;
	int err = 0;

	fltr = kzalloc(sizeof(*fltr), GFP_KERNEL);
	if (!fltr)
		return;

	old_fltr = nse_find_tx_acl_fltr(src_vsi);
	if (old_fltr) {
		dev_err(dev,
			"[%s, %d] src_vsi %d acl entry is existed!\n",
			__func__, __LINE__, src_vsi);
		goto err;
	}

	fltr->vsi_id = src_vsi;

	/*lut id and key for match*/
	fltr->fltr_info.lkup_type = NSE_ACL_LKUP_TX_SRC_VSI;
	fltr->fltr_info.sw_id = hw->port_info->sw_id;
	fltr->fltr_info.src_hw_vsi = (u16)src_vsi;
	fltr->fltr_info.src_hw_vsi |= (NSE_IN_PORT_TYPE_HOST <<
			NSE_IN_PORT_TYPE_S) & NSE_IN_PORT_TYPE_M;

	/*parameter and flags for action*/
	fltr->fltr_info.fltr_act = NSE_ACL_LARGE_ACT;
	fltr->fltr_info.lg_action.flags = NSE_ACL_LARGE_ACTION_AU_DMAC_RW |
			NSE_ACL_LARGE_ACTION_COUNT;

	hdrs = &fltr->fltr_info.lg_action.hdrs;
	ether_addr_copy(hdrs->vals.eth.h_dest, dmac_addr);
	ether_addr_copy(hdrs->masks.eth.h_dest, dmac_mask);
	hdrs->pedits++;

	err = nse_acl_add_fltr(hw, &fltr->fltr_info);
	if (err) {
		dev_err(dev,
			"[%s, %d] src_vsi %d tx au_dmac_rw action is added fail!\n",
			__func__, __LINE__, src_vsi);
		goto err;
	}

	dev_info(dev,
		"[%s, %d] src_vsi %d tx au_dmac_rw action is added successfully, node_id = %d\n",
		__func__, __LINE__, src_vsi, fltr->fltr_info.node_id);

	hlist_add_head(&fltr->acl_node, &nse_acl_fltr_tx_list);
	return;

err:
	kfree(fltr);
}

void
nse_debugfs_acl_fltr_tx_add_goto(struct nse_hw *hw,
						u32 src_vsi)
{
	struct nse_pf *pf = (struct nse_pf *)hw->back;
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_acl_fltr *fltr = NULL, *old_fltr = NULL;
	int err = 0;

	fltr = kzalloc(sizeof(*fltr), GFP_KERNEL);
	if (!fltr)
		return;

	old_fltr = nse_find_tx_acl_fltr(src_vsi);
	if (old_fltr) {
		dev_err(dev,
			"[%s, %d] src_vsi %d acl entry is existed!\n",
			__func__, __LINE__, src_vsi);
		goto err;
	}

	fltr->vsi_id = src_vsi;

	/*lut id and key for match*/
	fltr->fltr_info.lkup_type = NSE_ACL_LKUP_TX_SRC_VSI;
	fltr->fltr_info.sw_id = hw->port_info->sw_id;
	fltr->fltr_info.src_hw_vsi = (u16)src_vsi;
	fltr->fltr_info.src_hw_vsi |= (NSE_IN_PORT_TYPE_HOST <<
			NSE_IN_PORT_TYPE_S) & NSE_IN_PORT_TYPE_M;

	/*parameter and flags for action*/
	fltr->fltr_info.fltr_act = NSE_ACL_LARGE_ACT;
	fltr->fltr_info.lg_action.flags = NSE_ACL_LARGE_ACTION_GOTO |
			NSE_ACL_LARGE_ACTION_COUNT;

	err = nse_acl_add_fltr(hw, &fltr->fltr_info);
	if (err) {
		dev_err(dev,
			"[%s, %d] src_vsi %d tx goto action is added fail!\n",
			__func__, __LINE__, src_vsi);
		goto err;
	}

	dev_info(dev,
		"[%s, %d] src_vsi %d tx goto action is added successfully, node_id = %d\n",
		__func__, __LINE__, src_vsi, fltr->fltr_info.node_id);

	hlist_add_head(&fltr->acl_node, &nse_acl_fltr_tx_list);
	return;

err:
	kfree(fltr);
}

static ssize_t
nse_debugfs_acl_fltr_wfunc(struct file *filp, const char __user *buf,
			  size_t count, loff_t *ppos)
{
	struct nse_pf *pf = filp->private_data;
	struct nse_hw *hw = &pf->hw;
	struct device *dev = nse_pf_to_dev(pf);
	char *cmd_buf, *cmd_buf_tmp;
	ssize_t ret;
	char **argv;
	int argc;
	unsigned int val = 0;
	unsigned int val1 = 0;

	/* don't allow partial writes and writes when reset is in progress*/
	if (*ppos != 0 || nse_is_reset_in_progress(pf->state))
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

	if (!strncmp(argv[0], "rx_action_add", 13)) {
		if (argc < 3)
			goto bad_usage;

		if (!strncmp(argv[1], "drop", 4)) {
			if (kstrtouint(argv[2], 10, &val))
				goto bad_usage;

			nse_debugfs_acl_fltr_rx_add_drop(hw, val);

		} else if (!strncmp(argv[1], "bps_meter", 9)) {
			if (kstrtouint(argv[2], 10, &val))
				goto bad_usage;

			nse_debugfs_acl_fltr_rx_add_meter(hw, val, false);

		} else if (!strncmp(argv[1], "pps_meter", 9)) {
			if (kstrtouint(argv[2], 10, &val))
				goto bad_usage;

			nse_debugfs_acl_fltr_rx_add_meter(hw, val, true);

		} else if (!strncmp(argv[1], "both_meter", 10)) {
			if (kstrtouint(argv[2], 10, &val))
				goto bad_usage;

			nse_debugfs_acl_fltr_rx_add_multi_meters(hw, val);

		} else if (!strncmp(argv[1], "stats_drop", 10)) {
			if (kstrtouint(argv[2], 10, &val))
				goto bad_usage;

			nse_debugfs_acl_fltr_rx_add_drop_stats(hw, val);

		} else if (!strncmp(argv[1], "redir_vsi", 7)) {
			if (argc < 3)
				goto bad_usage;

			if (kstrtouint(argv[2], 10, &val))
				goto bad_usage;

			if (kstrtouint(argv[3], 10, &val1))
				goto bad_usage;

			nse_debugfs_acl_fltr_rx_add_redir_vsi(hw, val, val1);

		} else if (!strncmp(argv[1], "au_smac_rw", 10)) {
			if (kstrtouint(argv[2], 10, &val))
				goto bad_usage;

			nse_debugfs_acl_fltr_rx_add_au_smac_rw(hw, val);

		} else if (!strncmp(argv[1], "goto", 4)) {
			if (kstrtouint(argv[2], 10, &val))
				goto bad_usage;

			nse_debugfs_acl_fltr_rx_add_goto(hw, val);

		} else if (!strncmp(argv[1], "au_mac_rw", 9)) {
			if (kstrtouint(argv[2], 10, &val))
				goto bad_usage;

			nse_debugfs_acl_fltr_rx_add_au_mac_rw(hw, val);

		} else
			goto bad_usage;

	} else if (!strncmp(argv[0], "rx_action_del", 13)) {
		if (argc < 2)
			goto bad_usage;

		if (kstrtouint(argv[1], 10, &val))
			goto bad_usage;

		nse_debugfs_acl_fltr_rx_del(hw, val);

	} else if (!strncmp(argv[0], "tx_action_add", 13)) {
		if (argc < 3)
			goto bad_usage;

		if (!strncmp(argv[1], "drop", 4)) {
			if (kstrtouint(argv[2], 10, &val))
				goto bad_usage;

			nse_debugfs_acl_fltr_tx_add_drop(hw, val);

		} else if (!strncmp(argv[1], "bps_meter", 9)) {
			if (kstrtouint(argv[2], 10, &val))
				goto bad_usage;

			nse_debugfs_acl_fltr_tx_add_meter(hw, val, false);

		} else if (!strncmp(argv[1], "pps_meter", 9)) {
			if (kstrtouint(argv[2], 10, &val))
				goto bad_usage;

			nse_debugfs_acl_fltr_tx_add_meter(hw, val, true);

		} else if (!strncmp(argv[1], "both_meter", 10)) {
			if (kstrtouint(argv[2], 10, &val))
				goto bad_usage;

			nse_debugfs_acl_fltr_tx_add_multi_meters(hw, val);

		} else if (!strncmp(argv[1], "stats_drop", 10)) {
			if (kstrtouint(argv[2], 10, &val))
				goto bad_usage;

			nse_debugfs_acl_fltr_tx_add_drop_stats(hw, val);

		} else if (!strncmp(argv[1], "au_dmac_rw", 10)) {
			if (kstrtouint(argv[2], 10, &val))
				goto bad_usage;

			nse_debugfs_acl_fltr_tx_add_au_dmac_rw(hw, val);

		} else if (!strncmp(argv[1], "goto", 4)) {
			if (kstrtouint(argv[2], 10, &val))
				goto bad_usage;

			nse_debugfs_acl_fltr_tx_add_goto(hw, val);

		} else
			goto bad_usage;

	} else if (!strncmp(argv[0], "tx_action_del", 13)) {
		if (argc < 2)
			goto bad_usage;

		if (kstrtouint(argv[1], 10, &val))
			goto bad_usage;

		nse_debugfs_acl_fltr_tx_del(hw, val);

	} else
		goto bad_usage;

	/* if we get here, nothing went wrong; return bytes copied */
	ret = (ssize_t)count;

command_write_done:
	argv_free(argv);
err_copy_from_user:
	kfree(cmd_buf);
	return ret;

bad_usage:
	dev_info(dev, "unknown or invalid input: '%s'\n", cmd_buf);
	dev_info(dev, "commands of rx action:\n");
	dev_info(dev, "\t rx_action_del $VSI-N\n");
	dev_info(dev, "\t rx_action_add drop $VSI-N\n"); /*single action*/
	dev_info(dev, "\t rx_action_add bps_meter $VSI-N\n");/*single action*/
	dev_info(dev, "\t rx_action_add pps_meter $VSI-N\n"); /*single action*/
	/* large aciton, two du meter actions */
	dev_info(dev, "\t rx_action_add both_meter $VSI-N\n");
	dev_info(dev, "\t rx_action_add stats_drop $VSI-N\n"); /*drop with du stats*/
	dev_info(dev, "\t rx_action_add redir_vsi $VSI-N $RedirVsi\n"); /*fwd with du stats*/
	dev_info(dev, "\t rx_action_add au_smac_rw $VSI-N\n"); /*au smac_rw with du stats*/
	/* au smac_rw & au dmac_rw with du stats */
	dev_info(dev, "\t rx_action_add au_mac_rw $VSI-N\n");
	dev_info(dev, "\t rx_action_add goto $VSI-N\n"); /*du goto with du stats*/
	dev_info(dev, "commands of tx action:\n");
	dev_info(dev, "\t tx_action_del $VSI-N\n");
	dev_info(dev, "\t tx_action_add drop $VSI-N\n"); /*single action*/
	dev_info(dev, "\t tx_action_add bps_meter $VSI-N\n");/*single action*/
	dev_info(dev, "\t tx_action_add pps_meter $VSI-N\n"); /*single action*/
	dev_info(dev, "\t tx_action_add both_meter $VSI-N\n"); /*large aciton, two meter action*/
	dev_info(dev, "\t tx_action_add stats_drop $VSI-N\n"); /*drop with du stats*/
	dev_info(dev, "\t tx_action_add au_dmac_rw $VSI-N\n"); /*au dmac_rw with du stats*/
	dev_info(dev, "\t tx_action_add goto $VSI-N\n"); /*du goto with du stats*/

	ret = -EINVAL;
	goto command_write_done;
}

static const struct file_operations nse_debugfs_acl_fltr_fops = {
	.owner = THIS_MODULE,
	.open  = simple_open,
	.write = nse_debugfs_acl_fltr_wfunc,
	.llseek = default_llseek,
};

void nse_debugfs_sw_aq_get_res(struct nse_hw *hw)
{
	struct nse_aqc_sw_usage *buf;
	enum nse_status status = NSE_SUCCESS;

	buf = devm_kzalloc(nse_hw_to_dev(hw), sizeof(*buf), GFP_KERNEL);
	if (!buf)
		return;

	status = nse_aq_get_res_usage(hw, buf, sizeof(*buf));
	if (status) {
		dev_err(nse_hw_to_dev(hw),
			"Failed to get switch resource usage, err = %d\n", status);
		goto get_res_fail;
	}

	dev_info(nse_hw_to_dev(hw), "Success to get switch resource usage\n");
	dev_info(nse_hw_to_dev(hw), "\t total = %d\n", le16_to_cpu(buf->total));

get_res_fail:
	devm_kfree(nse_hw_to_dev(hw), buf);
}

void nse_debugfs_sw_aq_get_cap(struct nse_hw *hw)
{
	struct nse_aqc_sw_cap *buf;
	enum nse_status status = NSE_SUCCESS;

	buf = devm_kzalloc(nse_hw_to_dev(hw), sizeof(*buf), GFP_KERNEL);
	if (!buf)
		return;

	status = nse_aq_get_sw_cap(hw, buf, sizeof(*buf));
	if (status) {
		dev_err(nse_hw_to_dev(hw),
			"Failed to get switch capbility, err = %d\n", status);
		goto get_cap_fail;
	}

	dev_info(nse_hw_to_dev(hw), "Success to get switch capbility\n");
	dev_info(nse_hw_to_dev(hw), "\t max_lut = %d\n", le16_to_cpu(buf->max_lut));
	dev_info(nse_hw_to_dev(hw), "\t max_tnode = %d\n", le16_to_cpu(buf->max_tnode));
	dev_info(nse_hw_to_dev(hw), "\t max_recipe	= %d\n", le16_to_cpu(buf->max_recipe));
	dev_info(nse_hw_to_dev(hw), "\t max_profile	= %d\n", le16_to_cpu(buf->max_profile));
	dev_info(nse_hw_to_dev(hw), "\t max_node = %d\n", le16_to_cpu(buf->max_node));
	dev_info(nse_hw_to_dev(hw), "\t max_au_data	= %d\n", le16_to_cpu(buf->max_au_data));
	dev_info(nse_hw_to_dev(hw), "\t max_vsi_list = %d\n", le16_to_cpu(buf->max_vsi_list));
	dev_info(nse_hw_to_dev(hw), "\t max_node_state = %d\n", le16_to_cpu(buf->max_node_state));
	dev_info(nse_hw_to_dev(hw), "\t max_task_list = %d\n", le16_to_cpu(buf->max_task_list));
	dev_info(nse_hw_to_dev(hw), "\t max_counter	= %d\n", le16_to_cpu(buf->max_counter));
	dev_info(nse_hw_to_dev(hw), "\t max_meter = %d\n", le16_to_cpu(buf->max_meter));
	dev_info(nse_hw_to_dev(hw), "\t share_ratio	= %d\n", le16_to_cpu(buf->share_ratio));

get_cap_fail:
	devm_kfree(nse_hw_to_dev(hw), buf);
}

void nse_debugfs_sw_aq_read_pol_counter(struct nse_hw *hw,
	u16 pol_id)
{
	enum nse_status status = NSE_SUCCESS;
	struct nse_aqc_policy_counters *buf;
	struct nse_aqc_policy_counter_elem *elem;
	u16 buf_size;

	buf_size = struct_size(buf, elem, 1);
	buf = devm_kzalloc(nse_hw_to_dev(hw), buf_size, GFP_KERNEL);
	if (!buf)
		return;

	elem = buf->elem;
	buf->count = cpu_to_le16(1);
	elem->policy_id = cpu_to_le16(pol_id);

	status = nse_aq_get_pol_counter_val(hw, buf, buf_size);
	if (status) {
		dev_err(nse_hw_to_dev(hw),
			"Failed to query policy counter val, err = %d\n", status);
		goto read_fail;
	}

	dev_info(nse_hw_to_dev(hw),
		"Success to read policy counter!\n");

	dev_info(nse_hw_to_dev(hw),
		"\tpolicy id = 0x%x, Packet Counter Val = 0x%016llx, Byte Counter Val = 0x%016llx\n",
			pol_id, le64_to_cpu(elem->p_counter_val), le64_to_cpu(elem->b_counter_val));

read_fail:
	devm_kfree(nse_hw_to_dev(hw), buf);
}

void nse_debugfs_sw_aq_read_counter(struct nse_hw *hw,
	u16 start_id, u16 len)
{
	struct nse_sw_stats *sw_stats = &hw->switch_info->sw_stats;
#ifdef NSE_SUPPORT_DMA_RD_STATS
	struct nse_dma_mem *dma = &sw_stats->dma_buf;
	struct nse_aqc_sw_dma_counters *buf;
#else
	struct nse_aqc_sw_counters *buf;
#endif
	struct nse_aqc_sw_counter_elem *elem;
	enum nse_status status = NSE_SUCCESS;
	u16 buf_size, cntr_num;
#ifndef NSE_SUPPORT_RD_STATS_ASYN
	u16 index;
#endif

	if (!len)
		return;

	cntr_num = len;
#ifdef NSE_SUPPORT_DMA_RD_STATS
	buf_size = sizeof(*buf);
#else
	buf_size = struct_size(buf, elem, cntr_num);
#endif

	buf = devm_kzalloc(nse_hw_to_dev(hw), buf_size, GFP_KERNEL);
	if (!buf)
		return;

#ifdef NSE_SUPPORT_DMA_RD_STATS
	elem = (struct nse_aqc_sw_counter_elem *)dma->va;
	buf->count = cpu_to_le16(cntr_num);
	buf->start_id = cpu_to_le16(start_id);
	buf->addr_low =	cpu_to_le32(lower_32_bits(dma->pa));
	buf->addr_high = cpu_to_le32(upper_32_bits(dma->pa));
#else
	elem = buf->elem;
	buf->count = cpu_to_le16(cntr_num);
	buf->start_id = cpu_to_le16(start_id);
#endif

	mutex_lock(&sw_stats->rd_lock);

	status = nse_aq_get_counter_val(hw, buf, buf_size);
	if (status) {
		dev_err(nse_hw_to_dev(hw),	"Failed to query counter val, err = %d\n", status);
		goto read_range_fail;
	}

	dev_info(nse_hw_to_dev(hw), "Success to read %d counters, from ID 0x%x\n",
		cntr_num, start_id);

	dev_info(nse_hw_to_dev(hw),
		"Host Buf address = 0x%lx, Host elem address = 0x%lx, DMA high address = 0x%x, low address = 0x%x\n",
		(unsigned long)buf, (unsigned long)elem,
		upper_32_bits(dma->pa), lower_32_bits(dma->pa));

#ifndef NSE_SUPPORT_RD_STATS_ASYN
	for (index = 0; index < cntr_num; index++) {
		dev_info(nse_hw_to_dev(hw), "\tCounter id = 0x%x, Counter Val = 0x%016llx\n",
			start_id + index, le64_to_cpu(elem[index].counter_val));
	}
#endif

read_range_fail:
	mutex_unlock(&sw_stats->rd_lock);

	devm_kfree(nse_hw_to_dev(hw), buf);
}

void nse_debugfs_sw_aq_show_counter(struct nse_hw *hw,
	u16 start_id, u16 len)
{
#if defined(NSE_SUPPORT_RD_STATS_ASYN) && defined(NSE_SUPPORT_DMA_RD_STATS)
	struct nse_sw_stats *sw_stats = &hw->switch_info->sw_stats;
	struct nse_dma_mem *dma = &sw_stats->dma_buf;
	struct nse_aqc_sw_counter_elem *elem;
	u16 cntr_num, index;

	if (!len)
		return;

	if (start_id + len >= NSE_MAX_DMA_RD_STATS_NUM)
		return;

	cntr_num = len;
	elem = (struct nse_aqc_sw_counter_elem *)dma->va;

	for (index = 0; index < cntr_num; index++) {
		dev_info(nse_hw_to_dev(hw), "\tCounter id = 0x%x, Counter Val = 0x%016llx\n",
			start_id + index, le64_to_cpu(elem[start_id + index].counter_val));
	}

	return;
#else
	dev_err(nse_hw_to_dev(hw), "show_cnt is used to asyn dma read stats only!\n");
	return;
#endif
}

void nse_debugfs_sw_aq_get_vlist(struct nse_hw *hw, u16 vsi_list_id)
{
	u32 vsi_bm_arr[NSE_AQC_MAX_VSI_BM_BYTE_SIZE] = { 0 };
	enum nse_status status;
	int i;

	dev_info(nse_hw_to_dev(hw),
		"[%s, %d] Start to get vsi list's content, id = %d\n",
		__func__, __LINE__, vsi_list_id);

	status = nse_get_remove_vsi_list(hw, vsi_list_id, NSE_AQ_OPC_GET_VSI_LIST,
				 vsi_bm_arr, NSE_AQC_MAX_VSI_BM_BYTE_SIZE);
	if (status) {
		dev_err(nse_hw_to_dev(hw),
			"[%s, %d] Failed to get vsi list's content, id = %d\n",
			__func__, __LINE__, vsi_list_id);
		return;
	}

	dev_info(nse_hw_to_dev(hw),
		"[%s, %d] Success to get vsi list's content, id = %d\n",
		__func__, __LINE__, vsi_list_id);

	for (i = 0; i < NSE_AQC_MAX_VSI_BM_BYTE_SIZE; i++) {
		dev_info(nse_hw_to_dev(hw),
			"[%s, %d] \t Vsi Bitmap [%d] content = 0x%x\n",
			__func__, __LINE__, i, vsi_bm_arr[i]);
	}
}

void nse_debugfs_sw_aq_remove_vlist(struct nse_hw *hw, u16 vsi_list_id)
{
	u32 vsi_bm_arr[NSE_AQC_MAX_VSI_BM_BYTE_SIZE] = { 0 };
	enum nse_status status;
	int i;

	dev_info(nse_hw_to_dev(hw),
		"[%s, %d] Start to remove vsi list's content, id = %d\n",
		__func__, __LINE__, vsi_list_id);

	status = nse_get_remove_vsi_list(hw, vsi_list_id, NSE_AQ_OPC_REMOVE_VSI_LIST,
				 vsi_bm_arr, NSE_AQC_MAX_VSI_BM_BYTE_SIZE);
	if (status) {
		dev_err(nse_hw_to_dev(hw),
			"[%s, %d] Failed to remove vsi list's content, id = %d\n",
			__func__, __LINE__, vsi_list_id);
		return;
	}

	dev_info(nse_hw_to_dev(hw),
		"[%s, %d] Success to remove vsi list's content, id = %d\n",
		__func__, __LINE__, vsi_list_id);

	for (i = 0; i < NSE_AQC_MAX_VSI_BM_BYTE_SIZE; i++) {
		dev_info(nse_hw_to_dev(hw),
			"[%s, %d] \t Vsi Bitmap [%d] content = 0x%x\n",
			__func__, __LINE__, i, vsi_bm_arr[i]);
	}
}

void nse_debugfs_sw_aq_res_alloc(struct nse_hw *hw, u16 res_type)
{
	struct nse_aqc_alloc_free_res_elem *buf;
	u16 buf_size;
	enum nse_status status;

	buf_size = struct_size(buf, res_id, 1);

	buf = devm_kzalloc(nse_hw_to_dev(hw), buf_size, GFP_KERNEL);
	if (!buf)
		return;

	buf->num_elems = cpu_to_le16(1);
	buf->res_type = cpu_to_le16(res_type);

	if (res_type == NSE_AQC_RES_TYPE_DU_DATA_ID)
		buf->res_id[0] = 32;

	if (res_type == NSE_AQC_RES_TYPE_COUNTER_ID)
		buf->res_id[0] = 1;

	status = nse_aq_alloc_free_res(hw, 1, buf, buf_size, NSE_AQ_OPC_ALLOC_RESOURCE, NULL);
	if (status) {
		dev_info(nse_hw_to_dev(hw), "nse_aq_alloc_res fail, status = 0x%x\n", status);
		goto nse_debugfs_sw_aq_res_alloc_exit;
	}

	dev_info(nse_hw_to_dev(hw), "nse_aq_alloc_res success, res_type[%d]'s ID = 0x%x\n",
		res_type, le16_to_cpu(buf->res_id[0]));

nse_debugfs_sw_aq_res_alloc_exit:
	devm_kfree(nse_hw_to_dev(hw), buf);
}

void nse_debugfs_sw_aq_res_free(struct nse_hw *hw, u16 res_type, u16 id)
{
	struct nse_aqc_alloc_free_res_elem *buf;
	u16 buf_size;
	enum nse_status status;

	buf_size = struct_size(buf, res_id, 1);

	buf = devm_kzalloc(nse_hw_to_dev(hw), buf_size, GFP_KERNEL);
	if (!buf)
		return;

	buf->num_elems = cpu_to_le16(1);
	buf->res_type = cpu_to_le16(res_type);
	buf->res_id[0] = cpu_to_le16(id);

	status = nse_aq_alloc_free_res(hw, 1, buf, buf_size, NSE_AQ_OPC_FREE_RESOURCE, NULL);
	if (status) {
		dev_info(nse_hw_to_dev(hw), "nse_aq_free_res fail, status = 0x%x\n", status);
		goto nse_debugfs_sw_aq_res_alloc_exit;
	}

	dev_info(nse_hw_to_dev(hw), "nse_aq_free_res success, res_type[%d]'s ID = 0x%x\n",
		res_type, id);

nse_debugfs_sw_aq_res_alloc_exit:
	devm_kfree(nse_hw_to_dev(hw), buf);
}

static ssize_t
nse_debugfs_sw_aq_wfunc(struct file *filp, const char __user *buf,
			  size_t count, loff_t *ppos)
{
	struct nse_pf *pf = filp->private_data;
	struct nse_hw *hw = &pf->hw;
	struct device *dev = nse_pf_to_dev(pf);
	char *cmd_buf, *cmd_buf_tmp;
	ssize_t ret;
	char **argv;
	int argc;
	unsigned int val;
	unsigned int val1;

	/* don't allow partial writes and writes when reset is in progress*/
	if (*ppos != 0 || nse_is_reset_in_progress(pf->state))
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

	if (!strncmp(argv[0], "dump", 4)) {
		/*1. dump branch*/
		if (!strncmp(argv[1], "sw_cfg", 6)) /*1.1 dump sw_cfg*/
			nse_dump_sw_aq_cfg(hw);
		else if (!strncmp(argv[1], "profile", 7)) /*1.2 dump profile*/
			nse_dump_sw_aq_profile_all(hw);
		else if (!strncmp(argv[1], "node", 4)) { /*1.3 dump node*/
			if (argc != 3)
				goto bad_usage;
			if (kstrtouint(argv[2], 10, &val))
				goto bad_usage;
			nse_dump_sw_aq_lut_node(hw, val);
		} else if (!strncmp(argv[1], "rcp", 4)) {
			if (argc != 3)
				goto bad_usage;
			if (kstrtouint(argv[2], 10, &val))
				goto bad_usage;
			nse_dump_sw_aq_recipe(hw, val);

		} else if (!strncmp(argv[1], "sw_cap", 6)) {
			nse_debugfs_sw_aq_get_cap(hw);
		} else
			goto bad_usage;
	} else if (!strncmp(argv[0], "test", 4)) {
		/*2. do test for adminq cmd*/
#if defined(NSE_DEBUG_EXT)
		dev_info(dev, "switch test is started\n");
		dev_info(dev, "switch test is done, need reset!\n");
#else
		dev_info(dev, "switch test is not supported in current version\n");
		goto bad_usage;
#endif

	} else if (!strncmp(argv[0], "rd_pol_cnt", 10)) {
		if (argc != 2)
			goto bad_usage;

		if (kstrtouint(argv[1], 10, &val))
			goto bad_usage;

		nse_debugfs_sw_aq_read_pol_counter(hw, val);

	} else if (!strncmp(argv[0], "rd_cnt", 6)) {
		if (argc != 3)
			goto bad_usage;

		if (kstrtouint(argv[1], 10, &val))
			goto bad_usage;

		if (kstrtouint(argv[2], 10, &val1))
			goto bad_usage;

		nse_debugfs_sw_aq_read_counter(hw, val, val1);
	} else if (!strncmp(argv[0], "show_cnt", 8)) {
		if (argc != 3)
			goto bad_usage;

		if (kstrtouint(argv[1], 10, &val))
			goto bad_usage;

		if (kstrtouint(argv[2], 10, &val1))
			goto bad_usage;

		nse_debugfs_sw_aq_show_counter(hw, val, val1);

	} else if (!strncmp(argv[0], "get_vlist", 9)) {
		if (argc != 2)
			goto bad_usage;
		if (kstrtouint(argv[1], 10, &val))
			goto bad_usage;
		nse_debugfs_sw_aq_get_vlist(hw, val);

	} else if (!strncmp(argv[0], "remove_vlist", 12)) {
		if (argc != 2)
			goto bad_usage;
		if (kstrtouint(argv[1], 10, &val))
			goto bad_usage;
		nse_debugfs_sw_aq_remove_vlist(hw, val);

	} else if (!strncmp(argv[0], "res_alloc", 9)) {
		if (argc != 2)
			goto bad_usage;
		if (kstrtouint(argv[1], 10, &val))
			goto bad_usage;
		nse_debugfs_sw_aq_res_alloc(hw, val);
	} else if (!strncmp(argv[0], "res_free", 8)) {
		if (argc != 3)
			goto bad_usage;
		if (kstrtouint(argv[1], 10, &val))
			goto bad_usage;

		if (kstrtouint(argv[2], 10, &val1))
			goto bad_usage;

		nse_debugfs_sw_aq_res_free(hw, val, val1);
	} else
		goto bad_usage;

	/* if we get here, nothing went wrong; return bytes copied */
	ret = (ssize_t)count;

command_write_done:
	argv_free(argv);
err_copy_from_user:
	kfree(cmd_buf);
	return ret;

bad_usage:
	dev_info(dev, "unknown or invalid input: '%s'\n", cmd_buf);
	dev_info(dev, "available commands:\n");
	dev_info(dev, "\t dump sw_cfg\n");
	dev_info(dev, "\t dump sw_cap\n");
	dev_info(dev, "\t dump profile\n");
	dev_info(dev, "\t dump node $N\n");
	dev_info(dev, "\t dump rcp $N\n");
	dev_info(dev, "\t rd_pol_cnt $PolicyID\n");
	dev_info(dev, "\t rd_cnt $StartID $Cnt_num\n");
	dev_info(dev, "\t show_cnt $StartID $Cnt_num\n");
	dev_info(dev, "\t get_vlist $vlist_ID\n");
	dev_info(dev, "\t remove_vlist $vlist_ID\n");
	dev_info(dev, "\t res_alloc $Type\n");
	dev_info(dev, "\t res_free $Type $ID\n");
	dev_info(dev, "\t\t Value \t Type\n");
	dev_info(dev, "\t\t 0 \t VSI_LIST\n");
	dev_info(dev, "\t\t 1 \t LUT\n");
	dev_info(dev, "\t\t 2 \t NODE_STATE\n");
	dev_info(dev, "\t\t 3 \t TASK_LIST\n");
	dev_info(dev, "\t\t 4 \t DU_DATA\n");
	dev_info(dev, "\t\t 5 \t COUNTER\n");
	dev_info(dev, "\t\t 6 \t METER\n");
	ret = -EINVAL;
	goto command_write_done;
}

/**
 * nse_debugfs_sw_aq_fops
 *	- used for debuging switch adminq cmd directly
 */
static const struct file_operations nse_debugfs_sw_aq_fops = {
	.owner = THIS_MODULE,
	.open  = simple_open,
	.write = nse_debugfs_sw_aq_wfunc,
	.llseek = default_llseek,
};

/**
 * nse_debugfs_get_lag_from_fw -
 *		this function is used to get hw lag information from fw
 * @ldev: nse lag struct for this chip
 */
void
nse_debugfs_get_lag_from_fw(struct nse_pf *pf)
{
	struct nse_lag *ldev = pf->lag;
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_hw *hw = &pf->hw;
	struct nse_aqc_hw_lag_cfg *buf;
	int i;
	enum nse_status status = NSE_SUCCESS;

	if (!ldev) {
		dev_err(dev, "Failed to get lag info due to pf's lag is NULL\n");
		return;
	}

	if (!nse_lag_is_active(ldev)) {
		dev_err(dev, "Failed to get lag info due to lag is not active\n");
		return;
	}

	buf = devm_kzalloc(nse_hw_to_dev(hw), sizeof(*buf), GFP_KERNEL);
	if (!buf)
		return;

	buf->lag_id = ldev->hw_lag_id;
	buf->tbl.hash_tbl.vld_entries = cpu_to_le16(NSE_LAG_HASH_MAX_ENTRY);

	dev_info(dev,
		"Start to aqc get hw lag [hw_id = %d]:\n", buf->lag_id);

	status = nse_aq_hw_lag(hw, buf, sizeof(*buf), NSE_AQ_OPC_GET_HW_LAG, NULL);
	if (status) {
		dev_err(dev, "Failed to aqc get hw lag\n");
		goto nse_aqc_get_lag_exit;
	}

	dev_info(dev, "Success to get hw lag [hw_id = %d]:\n", buf->lag_id);
	dev_info(dev,
		"\t hw_lag_id = %d, port_num = %d, lan_id[%d,%d,%d,%d]\n",
		buf->lag_id, buf->lan_port_num,
		buf->lan_id[0], buf->lan_id[1], buf->lan_id[2], buf->lan_id[3]);

	if (buf->tx_type == NSE_AQC_LAG_TX_TYPE_ACT_BKUP) {
		dev_info(dev,
			"\t tx_type = %d, remap_port[%d,%d]\n",
			buf->tx_type, buf->tbl.remap.remap_port[0], buf->tbl.remap.remap_port[1]);
	} else {
		dev_info(dev,
			"\t tx_type = %d, hash_type = %d\n",
			buf->tx_type, buf->tbl.hash_tbl.hash_type);

		dev_info(dev, "Hash Entry(index-value):\n");
		for (i = 0; i < NSE_LAG_HASH_MAX_ENTRY; i = i+16) {
			dev_info(dev,
				"\t%d-%d, \t%d-%d, \t%d-%d, \t%d-%d, \t%d-%d, \t%d-%d, \t%d-%d, \t%d-%d, ",
				buf->tbl.hash_tbl.entry[i].entry_idx,
				buf->tbl.hash_tbl.entry[i].dst_port,
				buf->tbl.hash_tbl.entry[i+1].entry_idx,
				buf->tbl.hash_tbl.entry[i+1].dst_port,
				buf->tbl.hash_tbl.entry[i+2].entry_idx,
				buf->tbl.hash_tbl.entry[i+2].dst_port,
				buf->tbl.hash_tbl.entry[i+3].entry_idx,
				buf->tbl.hash_tbl.entry[i+3].dst_port,
				buf->tbl.hash_tbl.entry[i+4].entry_idx,
				buf->tbl.hash_tbl.entry[i+4].dst_port,
				buf->tbl.hash_tbl.entry[i+5].entry_idx,
				buf->tbl.hash_tbl.entry[i+5].dst_port,
				buf->tbl.hash_tbl.entry[i+6].entry_idx,
				buf->tbl.hash_tbl.entry[i+6].dst_port,
				buf->tbl.hash_tbl.entry[i+7].entry_idx,
				buf->tbl.hash_tbl.entry[i+7].dst_port);

			dev_info(dev,
				"\t%d-%d, \t%d-%d, \t%d-%d, \t%d-%d, \t%d-%d, \t%d-%d, \t%d-%d, \t%d-%d\n",
				buf->tbl.hash_tbl.entry[i+8].entry_idx,
				buf->tbl.hash_tbl.entry[i+8].dst_port,
				buf->tbl.hash_tbl.entry[i+9].entry_idx,
				buf->tbl.hash_tbl.entry[i+9].dst_port,
				buf->tbl.hash_tbl.entry[i+10].entry_idx,
				buf->tbl.hash_tbl.entry[i+10].dst_port,
				buf->tbl.hash_tbl.entry[i+11].entry_idx,
				buf->tbl.hash_tbl.entry[i+11].dst_port,
				buf->tbl.hash_tbl.entry[i+12].entry_idx,
				buf->tbl.hash_tbl.entry[i+12].dst_port,
				buf->tbl.hash_tbl.entry[i+13].entry_idx,
				buf->tbl.hash_tbl.entry[i+13].dst_port,
				buf->tbl.hash_tbl.entry[i+14].entry_idx,
				buf->tbl.hash_tbl.entry[i+14].dst_port,
				buf->tbl.hash_tbl.entry[i+15].entry_idx,
				buf->tbl.hash_tbl.entry[i+15].dst_port);
		}
	}

nse_aqc_get_lag_exit:
	devm_kfree(nse_hw_to_dev(hw), buf);
}

/**
 * nse_debugfs_dump_hw_lag_info -
 *		this function is used to dump hw lag information from driver
 * @ldev: nse lag struct for this chip
 */
void
nse_debugfs_dump_hw_lag_info(struct nse_pf *pf)
{
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_lag *ldev = pf->lag;
	struct lag_tracker	*tracker;
	unsigned long slave_bitmap = 0;
	u8 idx;
	int i = 0;

	if (!ldev)
		return;

	dev_info(dev, "PF[%d]'s memory addr is %p, its lag struct addr is %p\n",
		pf->hw.pcore_pf_id, pf, ldev);

	dev_info(dev, "Lag has total %d PFs, ref_cnt = %d, ready flag = %lu (1->ready):\n",
		ldev->ports, kref_read(&ldev->ref), ldev->flags);

	for (i = 0; i < ldev->ports; i++) {
		struct nse_pf *tmp_pf = ldev->lag_func[i].pf;
		struct net_device *tmp_nd = ldev->lag_func[i].netdev;

		dev_info(dev,
			"\t member[%d]: pf_id = %d, pf_addr = %p, main netdev = %s\n",
			i, tmp_pf->hw.pcore_pf_id, tmp_pf, tmp_nd->name);
	}

	dev_info(dev,
		"Start to print dynamic lag information (via bond event)\n");
	dev_info(dev,
		"Current Bond mode = %d (0-inactive), first_pf addr = %p, hw_lag_id = %d\n",
		ldev->mode, ldev->first_pf, ldev->hw_lag_id);

	tracker = &ldev->tracker;
	dev_info(dev,
		"Current Bond is_bonded(%d), vld_ports = %d, bitmap = 0x%lx, buckets(per-slave) = %d\n",
		tracker->is_bonded, tracker->vld_ports, tracker->slave_bitmap, tracker->buckets);
	dev_info(dev,
		"Current Bond tx_type = %d, hash_type = %d\n",
		tracker->tx_type, tracker->hash_type);

	slave_bitmap = tracker->slave_bitmap;
	i = 0;
	for_each_set_bit(idx, &slave_bitmap, NSE_LAG_MAX_PORT) {
		struct nse_pf *pf = ldev->lag_func[idx].pf;

		dev_info(dev,
			"Slave[%d]'s pf_addr = %p, lan_id = %d, tx_enabled = %d, link_up = %d\n",
			i, pf, pf->hw.lan_id, tracker->netdev_state[idx].tx_enabled,
			tracker->netdev_state[idx].link_up);
		i++;
	}

	//Hash Table
	if (tracker->tx_type == NETDEV_LAG_TX_TYPE_HASH) {
		dev_info(dev, "Hash Entry Table:\n");
		for (i = 0; i < NSE_LAG_HASH_MAX_ENTRY; i = i+16) {
			dev_info(dev,
				"\t%d, \t%d, \t%d, \t%d, \t%d, \t%d, \t%d, \t%d, \t%d, \t%d, \t%d, \t%d, \t%d, \t%d, \t%d, \t%d\n",
				ldev->v2p_map[i],  ldev->v2p_map[i+1],
					ldev->v2p_map[i+2], ldev->v2p_map[i+3],
				ldev->v2p_map[i+4], ldev->v2p_map[i+5],
					ldev->v2p_map[i+6], ldev->v2p_map[i+7],
				ldev->v2p_map[i+8], ldev->v2p_map[i+9],
					ldev->v2p_map[i+10], ldev->v2p_map[i+11],
				ldev->v2p_map[i+12], ldev->v2p_map[i+13],
					ldev->v2p_map[i+14], ldev->v2p_map[i+15]);
		}
	}

	//Remap Table
	if (tracker->tx_type == NETDEV_LAG_TX_TYPE_ACTIVEBACKUP)
		dev_info(dev, "Remap Port: %d\n", ldev->v2p_map[0]);
}

static ssize_t
nse_debugfs_hw_lag_wfunc(struct file *filp, const char __user *buf,
			  size_t count, loff_t *ppos)
{
	struct nse_pf *pf = filp->private_data;
	//struct nse_hw *hw = &pf->hw;
	struct device *dev = nse_pf_to_dev(pf);
	char *cmd_buf, *cmd_buf_tmp;
	ssize_t ret;
	char **argv;
	int argc;

	/* don't allow partial writes and writes when reset is in progress*/
	if (*ppos != 0 || nse_is_reset_in_progress(pf->state))
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

	if (!strncmp(argv[0], "dump", 4)) { /*dump from driver*/

		nse_debugfs_dump_hw_lag_info(pf);

	} else if (!strncmp(argv[0], "get_aqc", 7)) { /*get from fw by aqc*/

		nse_debugfs_get_lag_from_fw(pf);

	} else if (!strncmp(argv[0], "unplug_aux", 10)) { /*unplug_aux*/

		nse_unplug_aux_devs(pf, 0, 0);

	} else if (!strncmp(argv[0], "plug_aux", 8)) { /*plug_aux*/

		nse_plug_aux_devs(pf);

	} else if (!strncmp(argv[0], "is_rtnl_lock", 12)) { /*plug_aux*/

		dev_info(nse_pf_to_dev(pf),
			"is_rtnl_lock = %d\n", rtnl_is_locked());

	} else
		goto bad_usage;

	/* if we get here, nothing went wrong; return bytes copied */
	ret = (ssize_t)count;

command_write_done:
	argv_free(argv);
err_copy_from_user:
	kfree(cmd_buf);
	return ret;

bad_usage:
	dev_info(dev, "unknown or invalid input: '%s'\n", cmd_buf);
	dev_info(dev, "commands of hw lag:\n");
	dev_info(dev, "\t dump\n");
	dev_info(dev, "\t get_aqc\n");
	dev_info(dev, "\t is_rtnl_lock\n");
	dev_info(dev, "\t unplug_aux\n");
	dev_info(dev, "\t plug_aux\n");
	ret = -EINVAL;
	goto command_write_done;
}

static const struct file_operations nse_debugfs_hw_lag_fops = {
	.owner = THIS_MODULE,
	.open  = simple_open,
	.write = nse_debugfs_hw_lag_wfunc,
	.llseek = default_llseek,
};

static ssize_t
nse_debugfs_sw_bypass_rpp_wfunc(struct file *filp, const char __user *buf,
			  size_t count, loff_t *ppos)
{
	struct nse_pf *pf = filp->private_data;
	struct nse_hw *hw = &pf->hw;
	struct device *dev = nse_pf_to_dev(pf);
	char *cmd_buf, *cmd_buf_tmp;
	ssize_t ret;
	int vsi_rel_id;
	u16 vsi_abs_id;
	char **argv;
	int argc;
	enum nse_status status;

	/* don't allow partial writes and writes when reset is in progress*/
	if (*ppos != 0 || nse_is_reset_in_progress(pf->state))
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

	if (kstrtoint(argv[0], 10, &vsi_rel_id))
		goto bad_usage;

	if (vsi_rel_id < 0) {
		status = nse_switch_rpp_set_bypass(hw, false, 0, 0xFF);
		if (status)
			dev_err(dev, "FAIL: switch_rpp_set_bypass( false ), status=%d\n", status);

		pf->bypass_switch_vsi_abs_id = NSE_VSI_INVAL_ID;

	} else {
		if ((u16)vsi_rel_id > pf->vsi_space_size) {
			dev_err(dev, "BAD vsi_rel_id = %d, should less than PF VSI space size: %d\n",
							vsi_rel_id, pf->vsi_space_size);
			goto bad_usage;
		}

		vsi_abs_id = pf->vsi_space_start + (u16)vsi_rel_id;

		status = nse_switch_rpp_set_bypass(hw, true, vsi_abs_id, 0xFF);
		if (status)
			dev_err(dev, "FAIL: switch_rpp_set_bypass( true, vsi_rel_id=%d, vsi_abs_id=%d), status=%d\n",
							vsi_rel_id, vsi_abs_id, status);
		else
			pf->bypass_switch_vsi_abs_id = vsi_abs_id;
	}

	ret = (ssize_t)count;

command_write_done:
	if (argv)
		argv_free(argv);
err_copy_from_user:
	kfree(cmd_buf);

	return ret;

bad_usage:
	dev_info(dev, "echo [VSI_rel_id or -1 for disable] - RX bypass switch for this VSI\n");

	ret = -EINVAL;

	goto command_write_done;
}

static const struct file_operations nse_debugfs_sw_bypass_rpp_fops = {
	.owner = THIS_MODULE,
	.open  = simple_open,
	.write = nse_debugfs_sw_bypass_rpp_wfunc,
	.llseek = default_llseek,
};

static ssize_t
nse_debugfs_lan_ena_dis_rxq_txq_many_wfunc(struct file *filp, const char __user *buf,
			  size_t count, loff_t *ppos)
{
	struct nse_pf *pf = filp->private_data;
	struct nse_hw *hw = &pf->hw;
	struct device *dev = nse_pf_to_dev(pf);
	char *cmd_buf, *cmd_buf_tmp;
	ssize_t ret;
	u32 ena_or_dis;
	u32 qtype;
	u16 firstq_abs_id, lastq_abs_id;
	char **argv;
	int argc;
	enum nse_status status;

	/* don't allow partial writes and writes when reset is in progress*/
	if (*ppos != 0 || nse_is_reset_in_progress(pf->state))
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

	if (argc < 4)
		goto bad_usage;

	if (kstrtouint(argv[0], 10, &ena_or_dis))
		goto bad_usage;

	if (kstrtouint(argv[1], 10, &qtype))
		goto bad_usage;

	if (kstrtou16(argv[2], 10, &firstq_abs_id))
		goto bad_usage;

	if (kstrtou16(argv[3], 10, &lastq_abs_id))
		goto bad_usage;

	if (qtype >= 2 ||
		firstq_abs_id >= hw->hw_conf.max_lan_rxq_space ||
		lastq_abs_id >= hw->hw_conf.max_lan_rxq_space ||
		firstq_abs_id > lastq_abs_id)
		goto bad_usage;

	status = __nse_aq_lan_ena_dis_rxq_txq_many(hw, !!ena_or_dis, qtype,
						   firstq_abs_id, lastq_abs_id, NULL);
	if (status)
		dev_err(dev, "FAIL: aq_lan_ena_dis_rxq_txq_many(), status=%d\n", status);

	ret = (ssize_t)count;

command_write_done:
	if (argv)
		argv_free(argv);
err_copy_from_user:
	kfree(cmd_buf);

	return ret;

bad_usage:
	dev_info(dev, "echo [0|1] [0 for rxq, 1 for txq] [firstq_abs_id] [lastq_abs_id]\n");

	ret = -EINVAL;

	goto command_write_done;
}

static const struct file_operations nse_debugfs_lan_ena_dis_rxq_txq_many = {
	.owner = THIS_MODULE,
	.open  = simple_open,
	.write = nse_debugfs_lan_ena_dis_rxq_txq_many_wfunc,
	.llseek = default_llseek,
};

static ssize_t
nse_debugfs_lan_get_status_rxq_txq_many_wfunc(struct file *filp, const char __user *buf,
			  size_t count, loff_t *ppos)
{
	struct nse_pf *pf = filp->private_data;
	struct nse_hw *hw = &pf->hw;
	struct device *dev = nse_pf_to_dev(pf);
	char *cmd_buf, *cmd_buf_tmp;
	ssize_t ret;
	u32 qtype;
	u16 firstq_abs_id, lastq_abs_id, q_stat;
	char **argv;
	int argc;
	enum nse_status status;

	/* don't allow partial writes and writes when reset is in progress*/
	if (*ppos != 0 || nse_is_reset_in_progress(pf->state))
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

	if (argc < 3)
		goto bad_usage;

	if (kstrtouint(argv[0], 10, &qtype))
		goto bad_usage;

	if (kstrtou16(argv[1], 10, &firstq_abs_id))
		goto bad_usage;

	if (kstrtou16(argv[2], 10, &lastq_abs_id))
		goto bad_usage;

	if (qtype >= 2 ||
		firstq_abs_id >= hw->hw_conf.max_lan_rxq_space ||
		lastq_abs_id >= hw->hw_conf.max_lan_rxq_space ||
		firstq_abs_id > lastq_abs_id)
		goto bad_usage;

	if (qtype == 0) {
		for (; firstq_abs_id <= lastq_abs_id; firstq_abs_id++) {
			status = nse_aq_lan_read_rxq_status(hw, firstq_abs_id, &q_stat);
			if (!status)
				dev_info(dev, "RXQ-%d status: 0x%X\n", firstq_abs_id, q_stat);
			else
				dev_info(dev, "RXQ-%d status: FAIL to read\n", firstq_abs_id);
		}
	} else {
		for (; firstq_abs_id <= lastq_abs_id; firstq_abs_id++) {
			status = nse_aq_lan_read_txq_status(hw, firstq_abs_id, &q_stat);
			if (!status)
				dev_info(dev, "TXQ-%d status: 0x%X\n", firstq_abs_id, q_stat);
			else
				dev_info(dev, "TXQ-%d status: FAIL to read\n", firstq_abs_id);
		}
	}

	ret = (ssize_t)count;

command_write_done:
	if (argv)
		argv_free(argv);
err_copy_from_user:
	kfree(cmd_buf);

	return ret;

bad_usage:
	dev_info(dev, "echo [0 for rxq, 1 for txq] [firstq_abs_id] [lastq_abs_id]\n");

	ret = -EINVAL;

	goto command_write_done;
}

static const struct file_operations nse_debugfs_lan_get_status_rxq_txq_many = {
	.owner = THIS_MODULE,
	.open  = simple_open,
	.write = nse_debugfs_lan_get_status_rxq_txq_many_wfunc,
	.llseek = default_llseek,
};

static ssize_t
nse_debugfs_lan_get_ctx_rxq_txq_many_wfunc(struct file *filp, const char __user *buf,
			  size_t count, loff_t *ppos)
{
	struct nse_pf *pf = filp->private_data;
	struct nse_hw *hw = &pf->hw;
	struct device *dev = nse_pf_to_dev(pf);
	char *cmd_buf, *cmd_buf_tmp;
	ssize_t ret;
	u32 qtype;
	u16 firstq_abs_id, lastq_abs_id;
	struct nse_lan_rxq_ctx *rxq_ctx = NULL;
	struct nse_lan_txq_ctx *txq_ctx = NULL;
	char **argv;
	int argc;
	enum nse_status status;

	/* don't allow partial writes and writes when reset is in progress*/
	if (*ppos != 0 || nse_is_reset_in_progress(pf->state))
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

	if (argc < 3)
		goto bad_usage;

	if (kstrtouint(argv[0], 10, &qtype))
		goto bad_usage;

	if (kstrtou16(argv[1], 10, &firstq_abs_id))
		goto bad_usage;

	if (kstrtou16(argv[2], 10, &lastq_abs_id))
		goto bad_usage;

	if (qtype >= 2 ||
		firstq_abs_id >= hw->hw_conf.max_lan_rxq_space ||
		lastq_abs_id >= hw->hw_conf.max_lan_rxq_space ||
		firstq_abs_id > lastq_abs_id)
		goto bad_usage;

	if (qtype == 0) {
		rxq_ctx = kzalloc(sizeof(*rxq_ctx), GFP_KERNEL);
		if (!rxq_ctx)
			goto bad_usage;

		for (; firstq_abs_id <= lastq_abs_id; firstq_abs_id++) {
			status = nse_read_rxq_ctx(hw, rxq_ctx, firstq_abs_id);
			if (!status)
				nse_lan_rxq_ctx_dump(hw, -1, firstq_abs_id, rxq_ctx, 0xFF);
			else
				dev_info(dev, "=== RXQ-%d context: FAIL to read\n", firstq_abs_id);
		}
	} else {
		txq_ctx = kzalloc(sizeof(*txq_ctx), GFP_KERNEL);
		if (!txq_ctx)
			goto bad_usage;

		for (; firstq_abs_id <= lastq_abs_id; firstq_abs_id++) {
			status = nse_read_txq_ctx(hw, txq_ctx, firstq_abs_id);
			if (!status)
				nse_lan_txq_ctx_dump(hw, -1, firstq_abs_id, txq_ctx, 0xFF);
			else
				dev_info(dev, "=== TXQ-%d context: FAIL to read\n", firstq_abs_id);
		}
	}

	ret = (ssize_t)count;

command_write_done:
	if (argv)
		argv_free(argv);
err_copy_from_user:
	kfree(cmd_buf);

	kfree(rxq_ctx);

	kfree(txq_ctx);

	return ret;

bad_usage:
	dev_info(dev, "echo [0 for rxq, 1 for txq] [firstq_abs_id] [lastq_abs_id]\n");

	ret = -EINVAL;

	goto command_write_done;
}

static const struct file_operations nse_debugfs_lan_get_ctx_rxq_txq_many = {
	.owner = THIS_MODULE,
	.open  = simple_open,
	.write = nse_debugfs_lan_get_ctx_rxq_txq_many_wfunc,
	.llseek = default_llseek,
};

#if defined(NSE_DEBUG_EXT)

struct tdm_hw_qstat {
	u32 que_gptc_lo[NSE_LAN_DEBUG_HW_QSTAT_TDM_CNT];
	u32 que_gptc_hi[NSE_LAN_DEBUG_HW_QSTAT_TDM_CNT];
	u64 que_gptc[NSE_LAN_DEBUG_HW_QSTAT_TDM_CNT];

	u32 que_dptc_lo[NSE_LAN_DEBUG_HW_QSTAT_TDM_CNT];
	u32 que_dptc_hi[NSE_LAN_DEBUG_HW_QSTAT_TDM_CNT];
	u64 que_dptc[NSE_LAN_DEBUG_HW_QSTAT_TDM_CNT];

	u32 que_mptc_lo[NSE_LAN_DEBUG_HW_QSTAT_TDM_CNT];
	u32 que_mptc_hi[NSE_LAN_DEBUG_HW_QSTAT_TDM_CNT];
	u64 que_mptc[NSE_LAN_DEBUG_HW_QSTAT_TDM_CNT];

	u32 que_gotc_lo[NSE_LAN_DEBUG_HW_QSTAT_TDM_CNT];
	u32 que_gotc_hi[NSE_LAN_DEBUG_HW_QSTAT_TDM_CNT];
	u64 que_gotc[NSE_LAN_DEBUG_HW_QSTAT_TDM_CNT];

	u32 que_bptc_lo[NSE_LAN_DEBUG_HW_QSTAT_TDM_CNT];
	u32 que_bptc_hi[NSE_LAN_DEBUG_HW_QSTAT_TDM_CNT];
	u64 que_bptc[NSE_LAN_DEBUG_HW_QSTAT_TDM_CNT];
};

static void lan_tdm_qstat_read(struct nse_hw *hw, struct tdm_hw_qstat *stat)
{
	unsigned int i = 0;

	for (i = 0; i < NSE_LAN_DEBUG_HW_QSTAT_TDM_CNT; i++) {
		stat->que_gptc_lo[i] = rd32(hw, NSE_RNOC_REG_TDM_QUE_GPTC_LO(hw->dma_id, i));
		stat->que_gptc_hi[i] = rd32(hw, NSE_RNOC_REG_TDM_QUE_GPTC_HI(hw->dma_id, i));
		stat->que_gptc[i] = ((u64)stat->que_gptc_hi[i] << 32) | (u64)stat->que_gptc_lo[i];

		stat->que_gotc_lo[i] = rd32(hw, NSE_RNOC_REG_TDM_QUE_GOTC_LO(hw->dma_id, i));
		stat->que_gotc_hi[i] = rd32(hw, NSE_RNOC_REG_TDM_QUE_GOTC_HI(hw->dma_id, i));
		stat->que_gotc[i] = ((u64)stat->que_gptc_hi[i] << 32) | (u64)stat->que_gotc_lo[i];
	}
}

static void lan_tdm_hw_qstat_dump(struct nse_pf *pf, unsigned int dump_delta,
				  unsigned int delta_sec)
{
	struct nse_hw *hw = &pf->hw;
	struct tdm_hw_qstat *qstat_prev = NULL, *qstat_post = NULL;
	struct device *dev = nse_pf_to_dev(pf);
	unsigned int i = 0;
	u64 delta;

	qstat_prev = kzalloc(sizeof(*qstat_prev), GFP_KERNEL);
	qstat_post = kzalloc(sizeof(*qstat_post), GFP_KERNEL);
	if (!qstat_prev || !qstat_post) {
		dev_info(dev, "[%s] qstat_prev or qstat_post alloc fail\n", __func__);
		goto out;
	}

	lan_tdm_qstat_read(hw, qstat_prev);

	dev_info(dev, "Previous/Current TDM HW qstat of dma-%d:\n", hw->dma_id);

	for (i = 0; i < NSE_LAN_DEBUG_HW_QSTAT_TDM_CNT; i++) {
		dev_info(dev, "\t que_gptc_lo[%d]=0x%X (%d)\n", i,
			 qstat_prev->que_gptc_lo[i], qstat_prev->que_gptc_lo[i]);
		dev_info(dev, "\t que_gptc_hi[%d]=0x%X (%d)\n", i,
			 qstat_prev->que_gptc_hi[i], qstat_prev->que_gptc_hi[i]);
		dev_info(dev, "\t que_gptc[%d]=0x%lX (%ld)\n", i,
			 (unsigned long)qstat_prev->que_gptc[i],
			(unsigned long)qstat_prev->que_gptc[i]);

		dev_info(dev, "\t que_gotc_lo[%d]=0x%X (%d)\n", i,
			 qstat_prev->que_gotc_lo[i], qstat_prev->que_gotc_lo[i]);
		dev_info(dev, "\t que_gotc_hi[%d]=0x%X (%d)\n", i,
			 qstat_prev->que_gotc_hi[i], qstat_prev->que_gotc_hi[i]);
		dev_info(dev, "\t que_gotc[%d]=0x%lX (%ld)\n", i,
			 (unsigned long)qstat_prev->que_gotc[i],
			(unsigned long)qstat_prev->que_gotc[i]);
	}

	if (dump_delta) {
		if (delta_sec)
			msleep((1000 * delta_sec));

		lan_tdm_qstat_read(hw, qstat_post);

		dev_info(dev, "Post/Current TDM HW qstat of dma-%d:\n", hw->dma_id);

		for (i = 0; i < NSE_LAN_DEBUG_HW_QSTAT_TDM_CNT; i++) {
			dev_info(dev, "\t que_gptc_lo[%d]=0x%X (%d)\n", i,
				 qstat_post->que_gptc_lo[i], qstat_post->que_gptc_lo[i]);
			dev_info(dev, "\t que_gptc_hi[%d]=0x%X (%d)\n", i,
				 qstat_post->que_gptc_hi[i], qstat_post->que_gptc_hi[i]);
			dev_info(dev, "\t que_gptc[%d]=0x%lX (%ld)\n", i,
				 (unsigned long)qstat_post->que_gptc[i],
				(unsigned long)qstat_post->que_gptc[i]);

			dev_info(dev, "\t que_gotc_lo[%d]=0x%X (%d)\n", i,
				 qstat_post->que_gotc_lo[i], qstat_post->que_gotc_lo[i]);
			dev_info(dev, "\t que_gotc_hi[%d]=0x%X (%d)\n", i,
				 qstat_post->que_gotc_hi[i], qstat_post->que_gotc_hi[i]);
			dev_info(dev, "\t que_gotc[%d]=0x%lX (%ld)\n", i,
				 (unsigned long)qstat_post->que_gotc[i],
				(unsigned long)qstat_post->que_gotc[i]);
		}

		dev_info(dev, "Delta TDM HW qstat of dma-%d:\n", hw->dma_id);

		for (i = 0; i < NSE_LAN_DEBUG_HW_QSTAT_TDM_CNT; i++) {
			delta = qstat_post->que_gptc[i] - qstat_prev->que_gptc[i];
			dev_info(dev, "\t que_gptc[%d]=0x%lX (%ld)\n", i,
				 (unsigned long)delta, (unsigned long)delta);

			delta = qstat_post->que_gotc[i] - qstat_prev->que_gotc[i];
			dev_info(dev, "\t que_gotc[%d]=0x%lX (%ld)\n", i,
				 (unsigned long)delta, (unsigned long)delta);
		}
	}

out:
	kfree(qstat_prev);

	kfree(qstat_post);
}

static ssize_t
nse_debugfs_lan_hw_qstat_wfunc(struct file *filp, const char __user *buf,
			  size_t count, loff_t *ppos)
{
	struct nse_pf *pf = filp->private_data;
	struct device *dev = nse_pf_to_dev(pf);
	char *cmd_buf, *cmd_buf_tmp;
	ssize_t ret;
	char **argv;
	int argc;
	unsigned int qstat_op = 0;
	unsigned int delta_sec;

	/* don't allow partial writes and writes when reset is in progress*/
	if (*ppos != 0 || nse_is_reset_in_progress(pf->state))
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

	if (kstrtouint(argv[0], 10, &qstat_op))
		goto bad_usage;

	if (qstat_op == 0) {
		lan_tdm_hw_qstat_dump(pf, 0, 0);
	} else if (qstat_op == 1) {
		delta_sec = 1;
		if (argc >= 2) {
			if (kstrtouint(argv[1], 10, &delta_sec))
				goto bad_usage;
		}

		lan_tdm_hw_qstat_dump(pf, 1, delta_sec);
	} else {
		dev_info(dev, "[%s] unsupported op=%d\n", __func__, qstat_op);
	}

	/* if we get here, nothing went wrong; return bytes copied */
	ret = (ssize_t)count;

command_write_done:
	argv_free(argv);
err_copy_from_user:
	kfree(cmd_buf);
	return ret;

bad_usage:
	dev_info(dev, "invalid input, usage: echo '0(TDM)| 1(RDM)' > this file\n");
	ret = -EINVAL;
	goto command_write_done;
}

static const struct file_operations nse_debugfs_lan_hw_qstat_fops = {
	.owner = THIS_MODULE,
	.open  = simple_open,
	.write = nse_debugfs_lan_hw_qstat_wfunc,
	.llseek = default_llseek,
};

#endif	/* #if defined(NSE_DEBUG_EXT) */

static ssize_t
nse_debugfs_sched_dump_layers_info_wfunc(struct file *filp, const char __user *buf,
			  size_t count, loff_t *ppos)
{
	struct nse_pf *pf = filp->private_data;
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_hw *hw = &pf->hw;
	char *cmd_buf, *cmd_buf_tmp;
	ssize_t ret;
	char **argv;
	int argc;

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

	nse_sched_dump_layer_infos(hw);

	/* if we get here, nothing went wrong; return bytes copied */
	ret = (ssize_t)count;

command_write_done:
	argv_free(argv);
err_copy_from_user:
	kfree(cmd_buf);
	return ret;

bad_usage:
	dev_info(dev, "invalid input, usage: echo 'anything' > this_file\n");

	ret = -EINVAL;
	goto command_write_done;
}

static const struct file_operations nse_debugfs_sched_dump_layers_info_fops = {
	.owner = THIS_MODULE,
	.open  = simple_open,
	.write = nse_debugfs_sched_dump_layers_info_wfunc,
	.llseek = default_llseek,
};

static ssize_t
nse_debugfs_sched_dump_subtree_wfunc(struct file *filp, const char __user *buf,
			  size_t count, loff_t *ppos)
{
	struct nse_pf *pf = filp->private_data;
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_hw *hw = &pf->hw;
	struct nse_sched_info *si = &hw->port_info->sched_info;
	char *cmd_buf, *cmd_buf_tmp;
	ssize_t ret;
	char **argv;
	int argc;
	u32 tnid;
	struct nse_sched_node *n = NULL;
	char *linebuf = NULL;

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

	linebuf = kzalloc(512, GFP_KERNEL);	//should be enough
	if (!linebuf) {
		ret = -ENOMEM;
		goto command_write_done;
	}

	if (!si->root) {
		dev_err(dev, "SCHED tree empty, not initialized?\n");
		ret = -ENOENT;
		goto command_write_done;
	}

	if (kstrtouint(argv[0], 10, &tnid))
		goto bad_usage;

	mutex_lock(&si->sched_lock);

	n = nse_sched_find_node_by_tnid(si->root, tnid);
	if (!n) {
		mutex_unlock(&si->sched_lock);

		dev_err(dev, "Node of TNID=%d not exist\n", tnid);
		ret = -ENOENT;
		goto command_write_done;
	}

	nse_sched_dump_node_subtree(n, 0, linebuf);

	mutex_unlock(&si->sched_lock);

	/* if we get here, nothing went wrong; return bytes copied */
	ret = (ssize_t)count;

command_write_done:
	argv_free(argv);
err_copy_from_user:
	kfree(cmd_buf);

	kfree(linebuf);

	return ret;

bad_usage:
	dev_info(dev, "invalid input, usage: echo 'TNID (0 for root)' > this_file\n");

	ret = -EINVAL;
	goto command_write_done;
}

static const struct file_operations nse_debugfs_sched_dump_subtree_fops = {
	.owner = THIS_MODULE,
	.open  = simple_open,
	.write = nse_debugfs_sched_dump_subtree_wfunc,
	.llseek = default_llseek,
};

static ssize_t
nse_debugfs_sched_dump_node_wfunc(struct file *filp, const char __user *buf,
			  size_t count, loff_t *ppos)
{
	struct nse_pf *pf = filp->private_data;
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_hw *hw = &pf->hw;
	struct nse_sched_info *si = &hw->port_info->sched_info;
	char *cmd_buf, *cmd_buf_tmp;
	ssize_t ret;
	char **argv;
	int argc;
	u32 tnid;
	struct nse_sched_node *n = NULL;

	if (*ppos != 0)
		return -EINVAL;

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

	if (!si->root) {
		dev_info(dev, "SCHED tree empty, not initialized?\n");
		ret = -ENOENT;
		goto command_write_done;
	}

	if (kstrtouint(argv[0], 10, &tnid))
		goto bad_usage;

	mutex_lock(&si->sched_lock);

	n = nse_sched_find_node_by_tnid(si->root, tnid);
	if (!n) {
		mutex_unlock(&si->sched_lock);

		dev_info(dev, "Node of TNID=%d not exist\n", tnid);
		ret = -ENOENT;

		goto command_write_done;
	}

	(void)nse_sched_get_node_sch_param(hw, tnid, &n->sch_param);

	nse_sched_dump_node(n);

	mutex_unlock(&si->sched_lock);

	/* if we get here, nothing went wrong; return bytes copied */
	ret = (ssize_t)count;

command_write_done:
	argv_free(argv);
err_copy_from_user:
	kfree(cmd_buf);

	return ret;

bad_usage:
	dev_info(dev, "invalid input, usage: echo 'TNID (0 for root)' > this_file\n");

	ret = -EINVAL;
	goto command_write_done;
}

static const struct file_operations nse_debugfs_sched_dump_node_fops = {
	.owner = THIS_MODULE,
	.open  = simple_open,
	.write = nse_debugfs_sched_dump_node_wfunc,
	.llseek = default_llseek,
};

static ssize_t
nse_debugfs_sched_conf_node_pir_wfunc(struct file *filp, const char __user *buf,
			  size_t count, loff_t *ppos)
{
	struct nse_pf *pf = filp->private_data;
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_hw *hw = &pf->hw;
	struct nse_sched_info *si = &hw->port_info->sched_info;
	char *cmd_buf, *cmd_buf_tmp;
	ssize_t ret;
	char **argv;
	int argc;
	u32 tnid;
	u32 kbps;
	struct nse_sched_rl_factor rlf;
	struct nse_sched_node *node = NULL;
	enum nse_status status;

	if (*ppos != 0)
		return -EINVAL;

	cmd_buf = memdup_user(buf, count + 1);
	if (IS_ERR(cmd_buf))
		return PTR_ERR(cmd_buf);
	cmd_buf[count] = '\0';

	cmd_buf_tmp = strchr(cmd_buf, '\n');
	if (cmd_buf_tmp) {
		*cmd_buf_tmp = '\0';
		count = (size_t)cmd_buf_tmp - (size_t)cmd_buf + 1;
	}

	mutex_lock(&si->sched_lock);

	argv = argv_split(GFP_KERNEL, cmd_buf, &argc);
	if (!argv) {
		ret = -ENOMEM;
		goto err_copy_from_user;
	}

	if (argc < 2)
		goto bad_usage;

	if (!si->root) {
		dev_info(dev, "SCHED tree empty, not initialized?\n");
		ret = -ENOENT;
		goto command_write_done;
	}

	if (kstrtouint(argv[0], 10, &tnid))
		goto bad_usage;

	if (kstrtouint(argv[1], 10, &kbps) ||
		kbps > si->max_bandwidth_per_lan_port) {
		goto bad_usage;
	}

	node = nse_sched_find_node_by_tnid(si->root, tnid);
	if (!node) {
		dev_info(dev, "Node of TNID=%d not exist\n", tnid);
		ret = -ENOENT;

		goto command_write_done;
	}

	nse_sched_node_sch_param_compute_pir_cir(hw->port_info, kbps, &rlf);

	status = nse_sched_conf_node_sch_param_pir(hw, node,
				rlf.factor_idx ? NSE_AQC_QOS_SCH_CONF_PIR_OP_SET :
					NSE_AQC_QOS_SCH_CONF_PIR_OP_RESET,
				&rlf);
	if (status) {
		dev_info(dev, "FAIL: sched_conf_node_sch_param_pir(tnid=%d, pir=%d)\n",
					tnid, rlf.factor_idx);
	} else {
		if (rlf.factor_idx)
			node->sch_param.valid_section |= cpu_to_le16(NSE_SCH_NODE_PARAM_SECTION_PIR_VALID);
		else
			node->sch_param.valid_section &= ~cpu_to_le16(NSE_SCH_NODE_PARAM_SECTION_PIR_VALID);

		node->sch_param.pir = cpu_to_le16(rlf.factor_idx);
		node->sch_param.pir_factor_int = cpu_to_le16(rlf.factor_int);
		node->sch_param.pir_factor_df_int = cpu_to_le16(rlf.factor_df_int);
		node->sch_param.pir_factor_df_df = cpu_to_le16(rlf.factor_df_df);
	}

	/* if we get here, nothing went wrong; return bytes copied */
	ret = (ssize_t)count;

command_write_done:
	argv_free(argv);
err_copy_from_user:
	kfree(cmd_buf);

	mutex_unlock(&si->sched_lock);

	return ret;

bad_usage:
	dev_info(dev, "invalid input, usage: echo 'TNID PIR(kpps)' > this_file\n");

	ret = -EINVAL;
	goto command_write_done;
}

static const struct file_operations nse_debugfs_sched_conf_node_pir_fops = {
	.owner = THIS_MODULE,
	.open  = simple_open,
	.write = nse_debugfs_sched_conf_node_pir_wfunc,
	.llseek = default_llseek,
};

static enum nse_status
nse_debugfs_sched_conf_node_cir_recursive(struct nse_port_info *pi, u32 tnid, u16 cir)
{
	struct nse_hw *hw = pi->hw;
	struct nse_sched_info *si = &pi->sched_info;
	struct device *dev = nse_hw_to_dev(hw);
	u16 cir_delta, parent_cir;
	bool add_or_sub;	/* 1 for add, 0 for sub */
	u16 op;
	struct nse_sched_node *node = NULL, *parent_node = NULL;
	struct nse_sched_rl_factor rlf;
	enum nse_status status;
	u8 conf_status = 0;

	node = nse_sched_find_node_by_tnid(si->root, tnid);
	if (!node) {
		dev_info(dev, "Node of TNID=%d not exist\n", tnid);
		status = NSE_ERR_DOES_NOT_EXIST;

		goto out;
	}

	if (cir) {
		if (node->sch_param.valid_section &
		    le16_to_cpu(NSE_SCH_NODE_PARAM_SECTION_CIR_VALID)) {
			if (cir > le16_to_cpu(node->sch_param.cir)) {
				add_or_sub = true;
				cir_delta = cir - le16_to_cpu(node->sch_param.cir);
			} else if (cir < le16_to_cpu(node->sch_param.cir)) {
				add_or_sub = false;
				cir_delta = le16_to_cpu(node->sch_param.cir) - cir;
			} else {	/* ==, do nothing. */
				status = NSE_SUCCESS;
				dev_info(dev, "Current CIR no change.\n");
				goto out;
			}
		} else {
			add_or_sub = true;
			cir_delta = cir;
		}
	} else {
		if (node->sch_param.valid_section &
		    le16_to_cpu(NSE_SCH_NODE_PARAM_SECTION_CIR_VALID)) {
			add_or_sub = false;
			cir_delta = le16_to_cpu(node->sch_param.cir);
		} else {
			status = NSE_SUCCESS;
			dev_info(dev, "Current CIR no change.\n");
			goto out;
		}
	}

	/* check subtree (including port-node) to see if OK to add
	 */
	if (add_or_sub) {
		status = nse_sched_get_node_sch_param(hw, si->port_node->tnid,
						      &si->port_node->sch_param);
		if (status) {
			dev_info(dev, "FAIL: get current sch-param of port-node(TNID=%d)\n",
				 si->port_node->tnid);
			goto out;
		}

		parent_node = node->parent;

		while (parent_node != si->root) {
			if (parent_node->sch_param.valid_section &
			    le16_to_cpu(NSE_SCH_NODE_PARAM_SECTION_CIR_VALID)) {
				parent_cir = le16_to_cpu(parent_node->sch_param.cir);

				if ((parent_cir + cir_delta) > NSE_SCH_NODE_PARAM_PIR_CIR_MAX_VAL) {
					dev_err(dev, "[%s] a ancestor (tnid=%d, in layer=%d) can not afford ADD this CIR: avail_cir=%d (ask cir=%d, ADD cir_delta=%d)\n",
								__func__, parent_node->tnid,
									parent_node->layer_id,
						(NSE_SCH_NODE_PARAM_PIR_CIR_MAX_VAL -
						 parent_cir), cir, cir_delta);

					status = NSE_ERR_OUT_OF_RANGE;

					goto out;
				}
			}

			parent_node = parent_node->parent;
		}
	}

	/* conf_cir to all intermediate parent_node and this node itself.
	 */
	parent_node = node;
	while (parent_node != si->root) {
		if (add_or_sub) {
			rlf.factor_idx = le16_to_cpu(parent_node->sch_param.cir) + cir_delta;
		} else {
			if (le16_to_cpu(parent_node->sch_param.cir) > cir_delta)
				rlf.factor_idx = le16_to_cpu(parent_node->sch_param.cir) -
					cir_delta;
			else
				rlf.factor_idx = 0;
		}

		nse_sched_node_sch_param_compute_pir_cir_by_idx(pi, &rlf);

		op = (rlf.factor_idx) ? NSE_AQC_QOS_SCH_CONF_CIR_OP_SET :
			NSE_AQC_QOS_SCH_CONF_CIR_OP_RESET;

		status = nse_sched_conf_node_sch_param_cir(hw, parent_node, op,
							   &rlf, &conf_status);
		if (status) {
			dev_err(dev, "[%s] FAIL: status=%d(%s), sched_conf_node_sch_param_cir(node=%d, op=%d, cir=%d)\n",
							__func__, status, nse_stat_str(status),
							parent_node->tnid, op, cir);
			goto out;
		}

		/* No need to sync get port_node's param from HW,
		 * because they are all in this PF instance's control,
		 * so we just update its param in SW-level
		 */
		if (add_or_sub) {
			parent_cir = le16_to_cpu(parent_node->sch_param.cir) + cir_delta;

			parent_node->sch_param.cir = cpu_to_le16(parent_cir);

			parent_node->sch_param.valid_section |= le16_to_cpu(NSE_SCH_NODE_PARAM_SECTION_CIR_VALID);
		} else {
			parent_cir = le16_to_cpu(parent_node->sch_param.cir);

			if (!parent_cir ||
				cir_delta >= parent_cir) {
				parent_node->sch_param.cir = 0;

				parent_node->sch_param.valid_section &= ~(le16_to_cpu(NSE_SCH_NODE_PARAM_SECTION_CIR_VALID));
			} else {
				parent_cir -= cir_delta;

				parent_node->sch_param.cir = cpu_to_le16(parent_cir);

				parent_node->sch_param.valid_section |= (le16_to_cpu(NSE_SCH_NODE_PARAM_SECTION_CIR_VALID));
			}
		}

		parent_node = parent_node->parent;
	}

out:
	return status;
}

static enum nse_status
nse_debugfs_sched_conf_node_cir_direct(struct nse_port_info *pi, u32 tnid, u16 cir)
{
	struct nse_hw *hw = pi->hw;
	struct nse_sched_info *si = &pi->sched_info;
	struct device *dev = nse_hw_to_dev(hw);
	u16 op;
	struct nse_sched_node *node = NULL;
	struct nse_sched_rl_factor rlf;
	enum nse_status status;
	u8 conf_status = 0;

	node = nse_sched_find_node_by_tnid(si->root, tnid);
	if (!node) {
		dev_info(dev, "Node of TNID=%d not exist\n", tnid);
		status = NSE_ERR_DOES_NOT_EXIST;

		goto out;
	}

	if (cir) {
		if ((node->sch_param.valid_section &
		    le16_to_cpu(NSE_SCH_NODE_PARAM_SECTION_CIR_VALID)) ||
			(cir == le16_to_cpu(node->sch_param.cir))) {
			/* ==, do nothing. */
			status = NSE_SUCCESS;
			dev_info(dev, "Current CIR no change.\n");
			goto out;
		}
	} else {
		if (!(node->sch_param.valid_section &
		    le16_to_cpu(NSE_SCH_NODE_PARAM_SECTION_CIR_VALID))) {
			status = NSE_SUCCESS;
			dev_info(dev, "Current CIR no change.\n");
			goto out;
		}
	}

	rlf.factor_idx = cir;

	nse_sched_node_sch_param_compute_pir_cir_by_idx(pi, &rlf);

	op = (rlf.factor_idx) ? NSE_AQC_QOS_SCH_CONF_CIR_OP_SET : NSE_AQC_QOS_SCH_CONF_CIR_OP_RESET;

	status = nse_sched_conf_node_sch_param_cir(hw, node, op,
						   &rlf, &conf_status);
	if (status) {
		dev_err(dev, "[%s] FAIL: status=%d(%s), sched_conf_node_sch_param_cir(node=%d, op=%d, cir=%d)\n",
						__func__, status, nse_stat_str(status),
						node->tnid, op, cir);
	} else {
		node->sch_param.cir = cpu_to_le16(cir);
		if (cir)
			node->sch_param.valid_section |= le16_to_cpu(NSE_SCH_NODE_PARAM_SECTION_CIR_VALID);
		else
			node->sch_param.valid_section &= ~(le16_to_cpu(NSE_SCH_NODE_PARAM_SECTION_CIR_VALID));
	}

out:
	return status;
}

static ssize_t
nse_debugfs_sched_conf_node_cir_wfunc(struct file *filp, const char __user *buf,
			  size_t count, loff_t *ppos)
{
	struct nse_pf *pf = filp->private_data;
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_hw *hw = &pf->hw;
	struct nse_port_info *pi = hw->port_info;
	struct nse_sched_info *si = &pi->sched_info;
	char *cmd_buf, *cmd_buf_tmp;
	ssize_t ret;
	char **argv;
	int argc;
	u32 tnid;
	u16 cir;
	enum nse_status status;

	if (*ppos != 0)
		return -EINVAL;

	cmd_buf = memdup_user(buf, count + 1);
	if (IS_ERR(cmd_buf))
		return PTR_ERR(cmd_buf);
	cmd_buf[count] = '\0';

	cmd_buf_tmp = strchr(cmd_buf, '\n');
	if (cmd_buf_tmp) {
		*cmd_buf_tmp = '\0';
		count = (size_t)cmd_buf_tmp - (size_t)cmd_buf + 1;
	}

	mutex_lock(&si->sched_lock);

	argv = argv_split(GFP_KERNEL, cmd_buf, &argc);
	if (!argv) {
		ret = -ENOMEM;
		goto err_copy_from_user;
	}

	if (argc < 2)
		goto bad_usage;

	if (!si->root) {
		dev_info(dev, "SCHED tree empty, not initialized?\n");
		ret = -ENOENT;
		goto command_write_done;
	}

	if (kstrtouint(argv[0], 10, &tnid))
		goto bad_usage;

	if (kstrtou16(argv[1], 10, &cir) ||
		cir > NSE_SCH_NODE_PARAM_PIR_CIR_MAX_VAL) {
		goto bad_usage;
	}

	if (nse_sch_use_cir_transfer)
		status = nse_debugfs_sched_conf_node_cir_direct(pi, tnid, cir);
	else
		status = nse_debugfs_sched_conf_node_cir_recursive(pi, tnid, cir);

	/* if we get here, nothing went wrong; return bytes copied */
	ret = (ssize_t)count;

command_write_done:
	argv_free(argv);
err_copy_from_user:
	kfree(cmd_buf);

	mutex_unlock(&si->sched_lock);

	return ret;

bad_usage:
	dev_info(dev, "invalid input, usage: echo 'TNID CIR[0, 1000]' > this_file\n");

	ret = -EINVAL;
	goto command_write_done;
}

static const struct file_operations nse_debugfs_sched_conf_node_cir_fops = {
	.owner = THIS_MODULE,
	.open  = simple_open,
	.write = nse_debugfs_sched_conf_node_cir_wfunc,
	.llseek = default_llseek,
};

static ssize_t
nse_debugfs_fdir_dump_info_wfunc(struct file *filp, const char __user *buf,
			  size_t count, loff_t *ppos)
{
	struct nse_pf *pf = filp->private_data;
	struct nse_hw *hw = &pf->hw;
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_vsi *vsi = NULL;
	struct nse_aqc_fdir_query_setting *fdir_setting = NULL;
	struct nse_aqc_fdir_query_stats *fdir_stats = NULL;
	struct nse_aqc_fdir_get_set_vsi_input_mask *hw_input_mask = NULL;
	u32 qid;
	u32 gs_size;
	enum nse_status status;
	char *cmd_buf, *cmd_buf_tmp;
	ssize_t ret;
	char **argv;
	int argc;

	/* don't allow partial writes and writes when reset is in progress*/
	if (*ppos != 0 || nse_is_reset_in_progress(pf->state))
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

	if (argc != 1)
		goto bad_usage;

	fdir_setting = kzalloc(sizeof(*fdir_setting), GFP_KERNEL);
	fdir_stats = kzalloc(sizeof(*fdir_stats), GFP_KERNEL);
	hw_input_mask = kzalloc(sizeof(*hw_input_mask), GFP_KERNEL);
	if (!fdir_setting || !fdir_stats || !hw_input_mask) {
		ret = -ENOMEM;
		goto err_copy_from_user;
	}

	nse_fdir_dump_cb(hw);

	status = nse_aq_fdir_query_setting(hw, fdir_setting);
	if (status)
		dev_err(dev, "FAIL: aq_fdir_query_setting\n");
	else
		nse_fdir_dump_setting(hw, fdir_setting);

	status = nse_aq_fdir_get_drop_q(hw, &qid);
	if (status)
		dev_err(dev, "FAIL: aq_fdir_get_drop_q\n");
	else {
		dev_info(dev, "====== PF's drp_vsi_q=0x%X\n", qid);

		dev_info(dev, "\t drp_vsi=%d\n", (qid & FDIR_DRP_VSI_M) >> FDIR_DRP_VSI_S);
		dev_info(dev, "\t drp_q=%d\n", (qid & FDIR_DRP_QUEUE_M) >> FDIR_DRP_QUEUE_S);
	}

	vsi = nse_get_main_vsi(pf);

	status = nse_aq_fdir_get_vsi_space(hw, vsi->vsi_abs_num, &gs_size);
	if (status)
		dev_err(dev, "FAIL: aq_fdir_get_vsi_space\n");
	else
		dev_info(dev, "====== VSI gs_size=%d\n", gs_size);

	status = nse_aq_fdir_get_vsi_input_mask(hw, vsi->vsi_abs_num, hw_input_mask);
	if (status)
		dev_err(dev, "FAIL: aq_fdir_get_vsi_input_mask\n");
	else {
		dev_info(dev, "====== HW input mask\n");

		dev_info(dev, "flex_cfg=%08X\n", le32_to_cpu(hw_input_mask->flex_cfg));

		for (qid = 0; qid < 7; qid++)
			dev_info(dev, "mask[%d]=%08X", qid, le32_to_cpu(hw_input_mask->mask[qid]));
	}

	status = nse_aq_fdir_query_stats(hw, fdir_stats);
	if (status)
		dev_err(dev, "FAIL: aq_fdir_query_stats\n");
	else
		nse_fdir_dump_stats(hw, fdir_stats);

	/* if we get here, nothing went wrong; return bytes copied */
	ret = (ssize_t)count;

command_write_done:
	argv_free(argv);
err_copy_from_user:
	kfree(cmd_buf);
	kfree(fdir_setting);
	kfree(fdir_stats);
	kfree(hw_input_mask);

	return ret;

bad_usage:
	dev_info(dev, "invalid input, usage: echo 'any words' > this file\n");
	ret = -EINVAL;
	goto command_write_done;
}

static const struct file_operations nse_debugfs_fdir_dump_info_fops = {
	.owner = THIS_MODULE,
	.open  = simple_open,
	.write = nse_debugfs_fdir_dump_info_wfunc,
	.llseek = default_llseek,
};

/* like nse_get_ethtool_ntuple(), but dump some more internal info */
static ssize_t
nse_debugfs_fdir_dump_filter_wfunc(struct file *filp, const char __user *buf,
			  size_t count, loff_t *ppos)
{
	struct nse_pf *pf = filp->private_data;
	struct nse_hw *hw = &pf->hw;
	struct nse_fdir_cb *cb = &hw->fdir_cb;
	struct device *dev = nse_pf_to_dev(pf);
	char *cmd_buf, *cmd_buf_tmp;
	ssize_t ret;
	char **argv;
	int argc;
	int dump_all = 0;
	u32 filter_id = 0;
	struct hlist_node *node;
	struct nse_fdir_filter *f;

	/* don't allow partial writes and writes when reset is in progress*/
	if (*ppos != 0 || nse_is_reset_in_progress(pf->state))
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

	if (argc != 1)
		goto bad_usage;

	if (!strcmp(argv[0], "all")) {
		dump_all = 1;
	} else {
		if (kstrtouint(argv[0], 10, &filter_id))
			goto bad_usage;
	}

	mutex_lock(&cb->lock);

	if (dump_all) {
		hlist_for_each_entry_safe(f, node,
					  &cb->filter_list, hnode) {
			nse_fdir_dump_filter(hw, f, false);
		}
	} else {
		hlist_for_each_entry_safe(f, node,
					  &cb->filter_list, hnode) {
			if (filter_id == f->sw_idx)
				break;
		}

		if (!f || f->sw_idx != filter_id)
			dev_info(dev, "filter not exist\n");
		else
			nse_fdir_dump_filter(hw, f, true);
	}

	mutex_unlock(&cb->lock);

	/* if we get here, nothing went wrong; return bytes copied */
	ret = (ssize_t)count;

command_write_done:
	argv_free(argv);
err_copy_from_user:
	kfree(cmd_buf);

	return ret;

bad_usage:
	dev_info(dev, "invalid input, usage:\n");
	dev_info(dev, "\t echo '[all|$filter_id]' > this file");
	ret = -EINVAL;
	goto command_write_done;
}

static const struct file_operations nse_debugfs_fdir_dump_filter_fops = {
	.owner = THIS_MODULE,
	.open  = simple_open,
	.write = nse_debugfs_fdir_dump_filter_wfunc,
	.llseek = default_llseek,
};

static ssize_t nse_debugfs_vsi_params_rfunc(struct file *filp,
				 char __user *to, size_t count, loff_t *ppos)
{
	struct nse_vsi *vsi = filp->private_data;
	char *buf = NULL;
	int desc = 0;
	int ret;

	buf = kzalloc(4096, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	desc += sprintf(buf + desc, "VSI params:\n");

#if defined(NSE_DEBUG_EXT)
	desc += sprintf(buf + desc, "lan_no_xmit: %d\n",
		vsi->debug_lan_no_xmit);
#endif

	ret = simple_read_from_buffer(to, count, ppos, buf, desc);

	kfree(buf);

	return ret;
}

static ssize_t
nse_debugfs_vsi_params_wfunc(struct file *filp, const char __user *buf,
			  size_t count, loff_t *ppos)
{
	struct nse_vsi *vsi = filp->private_data;
	struct device *dev = nse_pf_to_dev(vsi->back);
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

	if (kstrtouint(argv[1], 10, &new_val))
		goto bad_usage;

	if (!strcmp(argv[0], "dummy"))
		dev_info(dev, "dummy input\n");
#if defined(NSE_DEBUG_EXT)
	if (!strcmp(argv[0], "lan_no_xmit"))
		vsi->debug_lan_no_xmit = new_val;
#endif
	else
		goto bad_usage;

	/* if we get here, nothing went wrong; return bytes copied */
	ret = (ssize_t)count;

command_write_done:
	argv_free(argv);
err_copy_from_user:
	kfree(cmd_buf);
	return ret;

bad_usage:
	dev_info(dev, "invalid input, usage: echo the following options to change per-VSI parameters\n");
	dev_info(dev, "    lan_no_xmit $N\n");
	ret = -EINVAL;
	goto command_write_done;
}

static const struct file_operations nse_debugfs_vsi_params_fops = {
	.owner = THIS_MODULE,
	.open  = simple_open,
	.read = nse_debugfs_vsi_params_rfunc,
	.write = nse_debugfs_vsi_params_wfunc,
	.llseek = default_llseek,
};

static void
nse_dump_vsi_info(struct nse_vsi *vsi)
{
	struct nse_pf *pf = vsi->back;
	struct device *dev = nse_pf_to_dev(pf);

	dev_info(dev, "=== VSI-%d info of this PF\n", vsi->idx);

	dev_info(dev, "vsi_type=%s\n", nse_vsi_type_str(vsi->type));
	if (vsi->type == NSE_VSI_VF)
		dev_info(dev, "\tVF_id=%d\n", vsi->vf->vf_id);

	if (vsi->netdev)
		dev_info(dev, "netdev: %s\n", vsi->netdev->name);

	dev_info(dev, "state=%s, %s\n",
		test_bit(NSE_VSI_DOWN, vsi->state) ? "DOWN" : "!DOWN",
		test_bit(NSE_VSI_NEEDS_RESTART, vsi->state) ? "NEEDS_RESTART" : "!NEEDS_RESTART");

	dev_info(dev, "vsi_abs_num=%d\n", vsi->vsi_abs_num);
	dev_info(dev, "vsi_rel_num=%d\n", vsi->vsi_rel_num);
	dev_info(dev, "base_vector=%d\n", vsi->base_vector);
	dev_info(dev, "num_q_vectors=%d\n", vsi->num_q_vectors);
	dev_info(dev, "nonvf_vsi_res_owner_id=0x%X\n", vsi->nonvf_vsi_res_owner_id);

	dev_info(dev, "rss_lut_start=%d\n", vsi->rss_lut_start);
	dev_info(dev, "rss_lut_size=%d\n", vsi->rss_lut_size);
	dev_info(dev, "rss_lut_size_log2=%d\n", vsi->rss_lut_size_log2);
	dev_info(dev, "rss_lut_size_aligned=%d\n", vsi->rss_lut_size_aligned);
	dev_info(dev, "rss_ctl=0x%X\n", vsi->rss_ctl);
	dev_info(dev, "rss_ctl_user_req_alg=0x%X\n", vsi->rss_ctl_user_req_alg);

	dev_info(dev, "max_frame=%d\n", vsi->max_frame);
	dev_info(dev, "rx_buf_len=%d\n", vsi->rx_buf_len);

	dev_info(dev, "vsi_rxq_space_start=%d\n", vsi->vsi_rxq_space_start);
	dev_info(dev, "alloc_rxq=%d\n", vsi->alloc_rxq);
	dev_info(dev, "num_rxq=%d\n", vsi->num_rxq);
	dev_info(dev, "req_rxq=%d\n", vsi->req_rxq);

	dev_info(dev, "vsi_txq_space_start=%d\n", vsi->vsi_txq_space_start);
	dev_info(dev, "alloc_txq=%d\n", vsi->alloc_txq);
	dev_info(dev, "num_txq=%d\n", vsi->num_txq);
	dev_info(dev, "req_txq=%d\n", vsi->req_txq);

	dev_info(dev, "vsi_xdp_txq_space_start=%d\n", vsi->vsi_xdp_txq_start);
	dev_info(dev, "num_xdp_txq=%d\n", vsi->num_xdp_txq);

	dev_info(dev, "lan_tx_use_cq=%d\n", vsi->sw_conf.lan_tx_use_cq);
	dev_info(dev, "vsi_txcq_space_start=%d\n", vsi->vsi_txcq_space_start);
	dev_info(dev, "alloc_txcq=%d\n", vsi->alloc_txcq);
	dev_info(dev, "num_txcq=%d\n", vsi->num_txcq);

	dev_info(dev, "fdir_ena=%d\n", vsi->sw_conf.fdir_ena);
	dev_info(dev, "fdir_use_utilq=%d\n", vsi->sw_conf.fdir_use_utilq);
	dev_info(dev, "fdir_max_num_pfilter_vsi=%d\n", vsi->sw_conf.fdir_max_num_pfilter_vsi);
	dev_info(dev, "fdir_max_num_sfilter_vsi=%d\n", vsi->sw_conf.fdir_max_num_sfilter_vsi);

	dev_info(dev, "lan_rx_ena_rsc=%d\n", vsi->sw_conf.lan_rx_ena_rsc);

	nse_dump_vsi_props(&pf->hw, &vsi->info);
}

static ssize_t
nse_debugfs_vsi_info_wfunc(struct file *filp, const char __user *buf,
			  size_t count, loff_t *ppos)
{
	struct nse_vsi *vsi = filp->private_data;
	struct nse_pf *pf = vsi->back;
	struct device *dev = nse_pf_to_dev(pf);
	char *cmd_buf, *cmd_buf_tmp;
	ssize_t ret;
	char **argv;
	int argc;

	/* don't allow partial writes and writes when reset is in progress*/
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

	if (argc != 1)
		goto bad_usage;

	nse_dump_vsi_info(vsi);

	/* if we get here, nothing went wrong; return bytes copied */
	ret = (ssize_t)count;

command_write_done:
	argv_free(argv);
err_copy_from_user:
	kfree(cmd_buf);
	return ret;

bad_usage:
	dev_info(dev, "invalid input, usage: echo 'any words' > vsi-N\n");
	ret = -EINVAL;
	goto command_write_done;
}

static const struct file_operations nse_debugfs_vsi_info_fops = {
	.owner = THIS_MODULE,
	.open  = simple_open,
	.write = nse_debugfs_vsi_info_wfunc,
	.llseek = default_llseek,
};

static void
nse_dump_vsi_info_rss(struct nse_vsi *vsi)
{
	struct nse_pf *pf = vsi->back;
	struct device *dev = nse_pf_to_dev(pf);
	enum nse_status	status;
	u32 hw_rss_ctl;
	u8 *hw_rss_key = NULL;
	u16 *hw_rss_lut = NULL;
	int i = 0;

	dev_info(dev, "=== VSI-%d RSS info of this PF\n", vsi->idx);

	dev_info(dev, "rss_lut_start=%d\n", vsi->rss_lut_start);
	dev_info(dev, "rss_lut_size=%d\n", vsi->rss_lut_size);
	dev_info(dev, "rss_lut_size_log2=%d\n", vsi->rss_lut_size_log2);
	dev_info(dev, "rss_lut_size_aligned=%d\n", vsi->rss_lut_size_aligned);
	dev_info(dev, "rss_ctl=0x%X\n", vsi->rss_ctl);
	dev_info(dev, "rss_ctl_user_req_alg=0x%X\n", vsi->rss_ctl_user_req_alg);

	if (vsi->rss_hkey_user) {
		dev_info(dev, "rss_hkey_user (user explicitly configured key):\n");
		for (i = 0; i < NSE_RSS_KEY_SIZE; i += 8) {
			dev_info(dev, "\t%X %X %X %X %X %X %X %X\n",
							vsi->rss_hkey_user[i],
							vsi->rss_hkey_user[i+1],
							vsi->rss_hkey_user[i+2],
							vsi->rss_hkey_user[i+3],
							vsi->rss_hkey_user[i+4],
							vsi->rss_hkey_user[i+5],
							vsi->rss_hkey_user[i+6],
							vsi->rss_hkey_user[i+7]);
		}
	} else {
		dev_info(dev, "rss_hkey_user=NULL (user does not explicitly configure key, hw rss_key is generated random)\n");
	}

	if (vsi->rss_lut_user) {
		dev_info(dev, "rss_lut_user (user explicitly configured LUT, print as RELATIVE ID in VSI):\n");
		for (i = 0; i < vsi->rss_lut_size_aligned; i += 8) {
			dev_info(dev, "\t%d %d %d %d %d %d %d %d\n",
							vsi->rss_lut_user[i],
							vsi->rss_lut_user[i+1],
							vsi->rss_lut_user[i+2],
							vsi->rss_lut_user[i+3],
							vsi->rss_lut_user[i+4],
							vsi->rss_lut_user[i+5],
							vsi->rss_lut_user[i+6],
							vsi->rss_lut_user[i+7]);
		}
	} else {
		dev_info(dev, "rss_lut_user=NULL (user does not explicitly configure LUT, hw rss_lut is generated as default)\n");
	}

	/* below dump content in HW, check whether SW-level setting is already configured to HW
	 */
	status = nse_aq_rss_get_ctl(vsi, &hw_rss_ctl);
	if (status) {
		dev_info(dev, "(hw)rss_ctl: get from HW fails\n");
	} else {
		dev_info(dev, "(hw)rss_ctl=0x%X\n", hw_rss_ctl);
		dev_info(dev, "\tEN=0x%X\n", (unsigned int)(hw_rss_ctl & NSE_VSI_RSS_CTL_EN_M));
		dev_info(dev, "\tTCBIT=0x%X\n",
			 (unsigned int)((hw_rss_ctl & NSE_VSI_RSS_CTL_TCBIT_M) >>
					NSE_VSI_RSS_CTL_TCBIT_S));
		dev_info(dev, "\tRSSBIT=0x%X\n",
			 (unsigned int)((hw_rss_ctl & NSE_VSI_RSS_CTL_RSSBIT_M) >>
					NSE_VSI_RSS_CTL_RSSBIT_S));
		dev_info(dev, "\tFIRST_LUT=0x%X\n",
			 (unsigned int)((hw_rss_ctl & NSE_VSI_RSS_CTL_FIRST_LUT_M) >>
					NSE_VSI_RSS_CTL_FIRST_LUT_S));
		dev_info(dev, "\tALG=0x%X\n", (unsigned int)((hw_rss_ctl & NSE_VSI_RSS_CTL_ALG_M) >>
			 NSE_VSI_RSS_CTL_ALG_S));
	}

	hw_rss_key = kmalloc(NSE_RSS_KEY_SIZE, GFP_KERNEL);
	if (!hw_rss_key)
		goto dump_hw_lut;

	status = nse_aq_rss_get_key(vsi, hw_rss_key);
	if (status) {
		dev_info(dev, "(hw)rss_key: get from HW fails\n");
	} else {
		dev_info(dev, "(hw)rss_key:\n");
		for (i = 0; i < NSE_RSS_KEY_SIZE; i += 8) {
			dev_info(dev, "\t%X %X %X %X %X %X %X %X\n",
							hw_rss_key[i],
							hw_rss_key[i+1],
							hw_rss_key[i+2],
							hw_rss_key[i+3],
							hw_rss_key[i+4],
							hw_rss_key[i+5],
							hw_rss_key[i+6],
							hw_rss_key[i+7]);
		}
	}

dump_hw_lut:

	hw_rss_lut = kmalloc_array(vsi->rss_lut_size_aligned, sizeof(u16), GFP_KERNEL);
	if (!hw_rss_lut)
		goto out;

	status = nse_aq_rss_get_lut(vsi, vsi->rss_lut_start + pf->rss_lut_start,
				    vsi->rss_lut_size_aligned, hw_rss_lut);
	if (status) {
		dev_info(dev, "(hw)rss_lut: get from HW fails\n");
	} else {
		dev_info(dev, "(hw)rss_lut (print as ABSOLUTE ID in LAN-channel):\n");
		for (i = 0; i < vsi->rss_lut_size_aligned; i += 8) {
			dev_info(dev, "\t%d %d %d %d %d %d %d %d\n",
							hw_rss_lut[i],
							hw_rss_lut[i+1],
							hw_rss_lut[i+2],
							hw_rss_lut[i+3],
							hw_rss_lut[i+4],
							hw_rss_lut[i+5],
							hw_rss_lut[i+6],
							hw_rss_lut[i+7]);
		}
	}

out:
	kfree(hw_rss_key);

	kfree(hw_rss_lut);
}

static ssize_t
nse_debugfs_vsi_info_rss_wfunc(struct file *filp, const char __user *buf,
			  size_t count, loff_t *ppos)
{
	struct nse_vsi *vsi = filp->private_data;
	struct nse_pf *pf = vsi->back;
	struct device *dev = nse_pf_to_dev(pf);
	char *cmd_buf, *cmd_buf_tmp;
	ssize_t ret;
	char **argv;
	int argc;

	/* don't allow partial writes and writes when reset is in progress*/
	if (*ppos != 0 || nse_is_reset_in_progress(pf->state))
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

	if (argc != 1)
		goto bad_usage;

	nse_dump_vsi_info_rss(vsi);

	/* if we get here, nothing went wrong; return bytes copied */
	ret = (ssize_t)count;

command_write_done:
	argv_free(argv);
err_copy_from_user:
	kfree(cmd_buf);
	return ret;

bad_usage:
	dev_info(dev, "invalid input, usage: echo 'any words' > vsi-N\n");
	ret = -EINVAL;
	goto command_write_done;
}

static const struct file_operations nse_debugfs_vsi_info_rss_fops = {
	.owner = THIS_MODULE,
	.open  = simple_open,
	.write = nse_debugfs_vsi_info_rss_wfunc,
	.llseek = default_llseek,
};

static void
nse_dump_rxq_txq_info(struct nse_ring *q, bool rxq_or_txq)
{
	struct device *dev = q->dev;
	int i = 0;

	dev_info(dev, "=== %s-%d info\n", rxq_or_txq ? "RXQ" : "TXQ", q->q_index);
	dev_info(dev, "desc = 0x%lX\n", (unsigned long)q->desc);
	dev_info(dev, "desc_dma = 0x%lX\n", (unsigned long)q->dma);
	dev_info(dev, "count = %d\n", q->count);
	dev_info(dev, "next_to_use = %d\n", q->next_to_use);
	dev_info(dev, "next_to_clean = %d\n", q->next_to_clean);
	dev_info(dev, "next_to_alloc = %d\n", q->next_to_alloc);
	dev_info(dev, "tail(vaddr) = %p\n", q->tail);
	dev_info(dev, "reg_idx = %d\n", q->reg_idx);
	dev_info(dev, "abs_id = %d\n", q->abs_id);
	if (q->q_vector)
		dev_info(dev, "q_vector->v_idx = %d\n", q->q_vector->v_idx);
	else
		dev_info(dev, "q_vector = NULL? how come this Q not bound to a q_vector?\n");
	dev_info(dev, "q_index = %d\n", q->q_index);
	dev_info(dev, "q_handle = %d\n", q->q_handle);
	dev_info(dev, "flags = %X\n", q->flags);
	dev_info(dev, "dcb_tc = %d\n", q->dcb_tc);

	dev_info(dev, "need_irqll = %d\n", q->need_irqll);
	dev_info(dev, "irqll_msix = %d\n", q->irqll_msix);
	dev_info(dev, "already_in_irqll = %d\n", q->already_in_irqll);

	if (rxq_or_txq) {	//rxq-only info
		dev_info(dev, "rx_buf = %p\n", q->rx_buf);
		dev_info(dev, "xdp_prog = %p\n", q->xdp_prog);
		dev_info(dev, "rx_buf_len = %d\n", q->rx_buf_len);
		dev_info(dev, "ptp_rx = %d\n", q->ptp_rx);
		dev_info(dev, "cached_phctime = %ld\n", (unsigned long)q->cached_phctime);
		dev_info(dev, "cached_phctime_sec_part = %d\n", q->cached_phctime_sec_part);
		dev_info(dev, "cached_phctime_nsec_part = %d\n", q->cached_phctime_nsec_part);

		dev_info(dev, "rx_stats:\n");
		dev_info(dev, "\t non_eop_descs: %ld\n", (unsigned long)q->rx_stats.non_eop_descs);
		dev_info(dev, "\t alloc_page_failed: %ld\n",
			 (unsigned long)q->rx_stats.alloc_page_failed);
		dev_info(dev, "\t alloc_buf_failed: %ld\n",
			 (unsigned long)q->rx_stats.alloc_buf_failed);
		dev_info(dev, "\t qsrc_cnt[SW=%d]: %ld\n", NSE_RXD_QSRC_SW,
			 (unsigned long)q->rx_stats.qsrc_cnt[NSE_RXD_QSRC_SW]);
		dev_info(dev, "\t qsrc_cnt[ACL=%d]: %ld\n", NSE_RXD_QSRC_ACL,
			 (unsigned long)q->rx_stats.qsrc_cnt[NSE_RXD_QSRC_ACL]);
		dev_info(dev, "\t qsrc_cnt[FD=%d]: %ld\n", NSE_RXD_QSRC_FD,
			 (unsigned long)q->rx_stats.qsrc_cnt[NSE_RXD_QSRC_FD]);
		dev_info(dev, "\t qsrc_cnt[RSS=%d]: %ld\n", NSE_RXD_QSRC_RSS,
			 (unsigned long)q->rx_stats.qsrc_cnt[NSE_RXD_QSRC_RSS]);
		dev_info(dev, "\t rsc_merge_cnt: %ld\n", (unsigned long)q->rx_stats.rsc_merge_cnt);
		dev_info(dev, "\t rsc_flush: %ld\n", (unsigned long)q->rx_stats.rsc_flush);
#if defined(NSE_DEBUG_EXT)
		for (i = 0; i < 16; i++)
			dev_info(dev, "\t rsc_cnt_desc_cnt[%d]=%ld\n", i,
				 (unsigned long)q->rx_stats.rsc_cnt_desc_cnt[i]);
		dev_info(dev, "\t rsc_cnt_total_accum: %ld\n",
			 (unsigned long)q->rx_stats.rsc_cnt_total_accum);

		dev_info(dev, "\t rxdid_dbg_0_cnt: %ld\n",
			 (unsigned long)q->rx_stats.rxdid_dbg_0_cnt);
		dev_info(dev, "\t\t non_zero_poh_md_37: %ld\n",
			 (unsigned long)q->rx_stats.non_zero_poh_md_37);
		dev_info(dev, "\t\t rscfv_cnt[0]: %ld, rscfv_cnt[1]: %ld\n",
			 (unsigned long)q->rx_stats.rscfv_cnt[0],
				 (unsigned long)q->rx_stats.rscfv_cnt[1]);
#endif
	} else {	//txq-only info
		dev_info(dev, "tx_buf = %p\n", q->tx_buf);
		dev_info(dev, "ptp_tx = %d\n", q->ptp_tx);

		dev_info(dev, "tx_rs_ntu = %d\n", q->tx_rs_ntu);
		dev_info(dev, "tx_rs_ntc = %d\n", q->tx_rs_ntc);

		dev_info(dev, "tx_stats:\n");
		dev_info(dev, "\t restart_q: %ld\n", (unsigned long)q->tx_stats.restart_q);
		dev_info(dev, "\t tx_busy: %ld\n", (unsigned long)q->tx_stats.tx_busy);
		dev_info(dev, "\t tx_linearize: %ld\n", (unsigned long)q->tx_stats.tx_linearize);

#if defined(NSE_DEBUG_EXT)
		dev_info(dev, "\t tx_use_ctx_desc: %ld\n",
			 (unsigned long)q->tx_stats.tx_use_ctx_desc);
		dev_info(dev, "\t tx_not_use_ctx_desc: %ld\n",
			 (unsigned long)q->tx_stats.tx_not_use_ctx_desc);
		dev_info(dev, "\t tx_tso: %ld\n", (unsigned long)q->tx_stats.tx_tso);
		dev_info(dev, "\t tx_tso_tnl: %ld\n", (unsigned long)q->tx_stats.tx_tso_tnl);
		dev_info(dev, "\t tx_tso_non_tnl: %ld\n",
			 (unsigned long)q->tx_stats.tx_tso_non_tnl);
		dev_info(dev, "\t tx_tcsum: %ld\n", (unsigned long)q->tx_stats.tx_tcsum);
		dev_info(dev, "\t tx_tcsum_tnl: %ld\n", (unsigned long)q->tx_stats.tx_tcsum_tnl);
		dev_info(dev, "\t tx_tcsum_non_tnl: %ld\n",
			 (unsigned long)q->tx_stats.tx_tcsum_non_tnl);
		dev_info(dev, "\t tx_tvlan: %ld\n", (unsigned long)q->tx_stats.tx_tvlan);
		dev_info(dev, "\t tx_tsyn: %ld\n", (unsigned long)q->tx_stats.tx_tsyn);
		dev_info(dev, "\t tx_offload: %ld\n", (unsigned long)q->tx_stats.tx_offload);
		dev_info(dev, "\t tx_non_offload: %ld\n",
			 (unsigned long)q->tx_stats.tx_non_offload);

		dev_info(dev, "\t tx_rs: %ld\n", (unsigned long)q->tx_stats.tx_rs);
		dev_info(dev, "\t tx_no_rs: %ld\n", (unsigned long)q->tx_stats.tx_no_rs);

		dev_info(dev, "\t clean_tx_irq_legacy_cnt: %ld\n",
			 (unsigned long)q->tx_stats.clean_tx_irq_legacy_cnt);
		dev_info(dev, "\t clean_tx_irq_legacy_rs_cnt: %ld\n",
			 (unsigned long)q->tx_stats.clean_tx_irq_legacy_rs_cnt);
		dev_info(dev, "\t clean_tx_irq_legacy_rs_raw_cnt: %ld\n",
			 (unsigned long)q->tx_stats.clean_tx_irq_legacy_rs_raw_cnt);
		dev_info(dev, "\t clean_tx_irq_legacy_rs_agg_cnt: %ld\n",
			 (unsigned long)q->tx_stats.clean_tx_irq_legacy_rs_agg_cnt);
		dev_info(dev, "\t clean_tx_irq_zc_cnt: %ld\n",
			 (unsigned long)q->tx_stats.clean_tx_irq_zc_cnt);
		dev_info(dev, "\t clean_txcq_irq_cnt: %ld\n",
			 (unsigned long)q->tx_stats.clean_txcq_irq_cnt);
		dev_info(dev, "\t clean_txcq_irq_zc_cnt: %ld\n",
			 (unsigned long)q->tx_stats.clean_txcq_irq_zc_cnt);
#endif
	}
}

static void
nse_dump_rxq_txq_status(struct nse_ring *q, bool rxq_or_txq)
{
	struct device *dev = q->dev;
	struct nse_pf *pf = q->vsi->back;
	struct nse_hw *hw = &pf->hw;
	u16 q_abs_id = 0;
	u16 q_status;
	enum nse_status status;

	if (rxq_or_txq) {
		q_abs_id = q->reg_idx + pf->lan_rxq_space_start;
		status = nse_aq_lan_read_rxq_status(hw, q_abs_id, &q_status);
	} else {
		q_abs_id = q->reg_idx + pf->lan_txq_space_start;
		status = nse_aq_lan_read_txq_status(hw, q_abs_id, &q_status);
	}

	if (!status) {
		dev_info(dev, "read_lan_rxq/txq_status: success\n");
		dev_info(dev, "\t q_status=%d\n", q_status);
	} else {
		dev_info(dev, "read_lan_rxq/txq_status: fail, status = %d (%s)\n",
				(int)status, nse_stat_str(status));
	}
}

static void
nse_dump_rxq_txq_context(struct nse_ring *q, bool rxq_or_txq)
{
	struct device *dev = q->dev;
	struct nse_pf *pf = q->vsi->back;
	struct nse_hw *hw = &pf->hw;
	u16 qid_abs = 0;
	u16 q_status = 0;
	void *aq_cmd_buf;
	unsigned int aq_cmd_buf_size = max(sizeof(struct nse_lan_rxq_ctx),
					   sizeof(struct nse_lan_txq_ctx));
	enum nse_status status;

	aq_cmd_buf = kzalloc(aq_cmd_buf_size, GFP_KERNEL);
	if (!aq_cmd_buf)
		return;

	if (rxq_or_txq) {
		qid_abs = q->reg_idx + pf->lan_rxq_space_start;
		status = nse_read_rxq_ctx(hw, (struct nse_lan_rxq_ctx *)aq_cmd_buf, qid_abs);
	} else {
		qid_abs = q->reg_idx + pf->lan_txq_space_start;
		status = nse_read_txq_ctx(hw, (struct nse_lan_txq_ctx *)aq_cmd_buf, qid_abs);
	}

	if (!status) {
		dev_info(dev, "read_lan_rxq/txq_context: success\n");

		if (rxq_or_txq) {
			nse_lan_rxq_ctx_dump(hw, q->reg_idx, qid_abs,
					     (struct nse_lan_rxq_ctx *)aq_cmd_buf, 0xFFFF);

			if (nse_aq_lan_read_rxq_status(hw, qid_abs, &q_status) == NSE_SUCCESS) {
				if (q_status & BIT(NSE_LANQ_STAT_BIT_IDX_Q_EN)) {
					/*  only compare 7, because starting from DATA[7] are
					 * dynamic fields
					 */
					nse_lan_rxq_ctx_compare(hw, &q->saved_lan_rxq_ctx,
						(struct nse_lan_rxq_ctx *)aq_cmd_buf, 7);
				} else {
					dev_err(dev,
				"rxq/txq_status: %d --- not enable --- don't compare\n", q_status);
				}
			} else {
				dev_err(dev, "read_lan_rxq/txq_status: fail\n");
			}
		} else {
			nse_lan_txq_ctx_dump(hw, q->reg_idx, qid_abs,
					     (struct nse_lan_txq_ctx *)aq_cmd_buf, 0xFFFF);

			if (nse_aq_lan_read_txq_status(hw, qid_abs, &q_status) == NSE_SUCCESS) {
				if (q_status & BIT(NSE_LANQ_STAT_BIT_IDX_Q_EN)) {
					/*  only compare 9, because starting from DATA[9] are
					 * dynamic fields, not used by SW
					 */
					nse_lan_txq_ctx_compare(hw, &q->saved_lan_txq_ctx,
						(struct nse_lan_txq_ctx *)aq_cmd_buf, 8);
				} else {
					dev_err(dev,
				"rxq/txq_status: %d --- not enable --- don't compare\n", q_status);
				}
			} else {
				dev_err(dev, "read_lan_rxq/txq_status: fail\n");
			}
		}
	} else {
		dev_info(dev, "read_lan_rxq/txq_context: fail, status = %d (%s)\n",
				(int)status, nse_stat_str(status));
	}

	kfree(aq_cmd_buf);
}

static void
nse_dump_rxq_txq_desc(struct nse_ring *q, bool rxq_or_txq, u16 max_desc_cnt, bool from_ntc_to_ntu)
{
	struct device *dev = q->dev;
	struct nse_vsi *vsi = q->vsi;
	u16 ntc, ntu;
	struct nse_tx_desc *tx_desc;
	union nse_32b_rx_desc *rx_desc;

	if (vsi->type == NSE_VSI_VF || vsi->type == NSE_VSI_ADI) {
		dev_info(dev, "VF-VSI and ADI-VSI lanQ descriptor memory may not in current OS, don't support dump\n");
		return;
	}

	if (!q->desc || !q->count) {
		dev_info(dev, "VSI lanQ descriptor memory not allocated, may be this Q not used or enabled\n");
		return;
	}

	ntc = q->next_to_clean;
	ntu = q->next_to_use;

	dev_info(dev, "next_to_clean = %d, next_to_use = %d, max_desc_cnt(to dump) = %d\n",
			ntc, ntu, max_desc_cnt);

	if (from_ntc_to_ntu) {
		while (max_desc_cnt && ntc != ntu) {
			if (rxq_or_txq) {
				rx_desc = NSE_RX_DESC(q, ntc);
				nse_dump_rx_desc(dev, q->q_index, ntc, rx_desc);
			} else {
				tx_desc = NSE_TX_DESC(q, ntc);
				nse_dump_tx_desc(dev, q->q_index, ntc, tx_desc);
			}

			max_desc_cnt--;

			ntc++;
			if (ntc == q->count)	/* wrap around */
				ntc = 0;
		}
	} else {
		while (max_desc_cnt && ntu != ntc) {
			if (ntu == 0)
				ntu = q->count;

			ntu--;

			if (rxq_or_txq) {
				rx_desc = NSE_RX_DESC(q, ntu);
				nse_dump_rx_desc(dev, q->q_index, ntu, rx_desc);
			} else {
				tx_desc = NSE_TX_DESC(q, ntu);
				nse_dump_tx_desc(dev, q->q_index, ntu, tx_desc);
			}

			max_desc_cnt--;
		}
	}
}

static void
nse_dump_rxq_txq_desc_raw(struct nse_ring *q, bool rxq_or_txq, u16 start_idx, u16 max_desc_cnt)
{
	struct device *dev = q->dev;
	struct nse_vsi *vsi = q->vsi;
	struct nse_tx_desc *tx_desc;
	union nse_32b_rx_desc *rx_desc;

	if (vsi->type == NSE_VSI_VF || vsi->type == NSE_VSI_ADI) {
		dev_info(dev, "VF-VSI and ADI-VSI lanQ descriptor memory may not in current OS, don't support dump\n");
		return;
	}

	if (!q->desc || !q->count) {
		dev_info(dev, "VSI lanQ descriptor memory not allocated, may be this Q not used or enabled\n");
		return;
	}

	dev_info(dev, "next_to_clean = %d, next_to_use = %d\n", q->next_to_clean, q->next_to_use);
	dev_info(dev, "we dump: start_idx = %d, number = %d\n", start_idx, max_desc_cnt);

	while (max_desc_cnt) {
		if (rxq_or_txq) {
			rx_desc = NSE_RX_DESC(q, start_idx);
			nse_dump_rx_desc(dev, q->q_index, start_idx, rx_desc);
		} else {
			tx_desc = NSE_TX_DESC(q, start_idx);
			nse_dump_tx_desc(dev, q->q_index, start_idx, tx_desc);
		}

		max_desc_cnt--;

		start_idx++;
		if (start_idx == q->count)	/* wrap around */
			start_idx = 0;
	}
}

#if defined(NSE_DEBUG_EXT)
static void
nse_dump_txq_used_record(struct nse_ring *txq, u16 entry_cnt)
{
	struct device *dev = txq->dev;
	u16 cur_idx, prev_idx;
	unsigned long ns_delta = 0, max_ns_delta = 0, total_ns_delta = 0;
	struct nse_tx_ring_used_record *rec = NULL, *prev_rec = NULL;
	unsigned long orig_entry_cnt = entry_cnt;

	if (!txq->txr_used_records)
		return;

	dev_info(dev, "TXQ-%d used_records\n", txq->q_index);

	cur_idx = txq->txr_used_rec_cur_idx;

	while (entry_cnt) {
		if (cur_idx == 0)
			cur_idx = NSE_TX_RING_USED_RECORD_LEN;

		cur_idx--;

		if (cur_idx == 0)
			prev_idx = (NSE_TX_RING_USED_RECORD_LEN - 1);
		else
			prev_idx = (cur_idx - 1);

		rec = &txq->txr_used_records[cur_idx];
		prev_rec = &txq->txr_used_records[prev_idx];

		ns_delta = rec->raw_ns - prev_rec->raw_ns;

		dev_info(dev, "\t used=%d, ns_rec=%ld, ns_delta=%ld\n",
							rec->used_desc, (unsigned long)rec->raw_ns,
							ns_delta);

		if (ns_delta > max_ns_delta)
			max_ns_delta = ns_delta;

		total_ns_delta += ns_delta;

		entry_cnt--;
	}

	ns_delta = total_ns_delta / orig_entry_cnt;	/* average */

	dev_info(dev, "[timing] total_ns_delta=%ld, max_ns_delta=%ld, average_ns_delta=%ld\n\n",
						total_ns_delta, max_ns_delta, ns_delta);
}

static void
nse_dump_txq_clean_record(struct nse_ring *txq, u16 entry_cnt)
{
	struct device *dev = txq->dev;
	u16 cur_idx, prev_idx;
	unsigned long ns_delta = 0, max_ns_delta = 0, total_ns_delta = 0;
	struct nse_tx_ring_clean_record *rec = NULL, *prev_rec = NULL;
	unsigned long orig_entry_cnt = entry_cnt;

	if (!txq->txr_clean_records)
		return;

	dev_info(dev, "TXQ-%d clean_records\n", txq->q_index);

	cur_idx = txq->txr_clean_rec_cur_idx;

	while (entry_cnt) {
		if (cur_idx == 0)
			cur_idx = NSE_TX_RING_CLEAN_RECORD_LEN;

		cur_idx--;

		if (cur_idx == 0)
			prev_idx = (NSE_TX_RING_CLEAN_RECORD_LEN - 1);
		else
			prev_idx = (cur_idx - 1);

		rec = &txq->txr_clean_records[cur_idx];
		prev_rec = &txq->txr_clean_records[prev_idx];

		ns_delta = rec->raw_ns - prev_rec->raw_ns;

		dev_info(dev, "\t clean_desc=%d, clean_pkt=%d, clean_all_dd=%d, used=%d, ns_rec=%ld, ns_delta=%ld\n",
							rec->clean_desc, rec->clean_pkt,
								rec->clean_all_dd_this_time,
							rec->used_desc,
							(unsigned long)rec->raw_ns,
							ns_delta);

		if (ns_delta > max_ns_delta)
			max_ns_delta = ns_delta;

		total_ns_delta += ns_delta;

		entry_cnt--;
	}

	ns_delta = total_ns_delta / orig_entry_cnt;	/* average */

	dev_info(dev, "[timing] total_ns_delta=%ld, max_ns_delta=%ld, average_ns_delta=%ld\n\n",
						total_ns_delta, max_ns_delta, ns_delta);
}
#endif

static ssize_t
nse_debugfs_vsi_dump_rxq_wfunc(struct file *filp, const char __user *buf,
			  size_t count, loff_t *ppos)
{
	struct nse_vsi *vsi = filp->private_data;
	struct nse_pf *pf = vsi->back;
	struct nse_ring *rxq = NULL;
	struct device *dev = nse_pf_to_dev(pf);
	char *cmd_buf, *cmd_buf_tmp;
	ssize_t ret;
	char **argv;
	int argc;
	u16 qid_vsi;
	u16 desc_idx;
	u16 max_desc_cnt;
	int dump_all = 0;
	int i;
	bool dumped = false;
	int dump_dir_from_ntc_to_ntu = 1;

	/* don't allow partial writes and writes when reset is in progress*/
	if (*ppos != 0)
		return -EINVAL;

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
		if (kstrtou16(argv[0], 10, &qid_vsi))
			goto bad_usage;

		if (qid_vsi >= vsi->alloc_rxq) {
			dev_info(dev, "input RXQ number out of range\n");

			ret = -EINVAL;
			goto command_write_done;
		}

		rxq = vsi->rx_rings[qid_vsi];
		if (!rxq) {
			dev_info(dev, "input RXQ not used or enabled\n");

			ret = -EINVAL;
			goto command_write_done;
		}
	}

	if (strstr(argv[1], "info")) {
		if (dump_all) {
			nse_for_each_rxq(vsi, i) {
				rxq = vsi->rx_rings[i];
				if (!rxq)
					continue;
				nse_dump_rxq_txq_info(rxq, true);
			}
		} else {
			nse_dump_rxq_txq_info(rxq, true);
		}

		dumped = true;
	}

	if (strstr(argv[1], "status")) {
		if (dump_all) {
			nse_for_each_rxq(vsi, i) {
				rxq = vsi->rx_rings[i];
				if (!rxq)
					continue;
				nse_dump_rxq_txq_status(rxq, true);
			}
		} else {
			nse_dump_rxq_txq_status(rxq, true);
		}

		dumped = true;
	}

	if (strstr(argv[1], "context")) {
		if (dump_all) {
			nse_for_each_rxq(vsi, i) {
				rxq = vsi->rx_rings[i];
				if (!rxq)
					continue;
				nse_dump_rxq_txq_context(rxq, true);
			}
		} else {
			nse_dump_rxq_txq_context(rxq, true);
		}

		dumped = true;
	}

	if (!strcmp(argv[1], "desc")) {
		if (!vsi->rx_rings[0]) {
			/*  need this for max_desc_cnt comparition. if special "all", then local
			 * var: rxq is unset
			 */
			ret = -EINVAL;
			goto command_write_done;
		}

		if (argc >= 3) {
			if (kstrtou16(argv[2], 10, &max_desc_cnt))
				goto bad_usage;
		} else {
			max_desc_cnt = vsi->rx_rings[0]->count;
		}

		if (argc >= 4) {
			if (kstrtoint(argv[3], 10, &dump_dir_from_ntc_to_ntu))
				dump_dir_from_ntc_to_ntu = 0;
		}

		if (max_desc_cnt > vsi->rx_rings[0]->count) {
			dev_info(dev, "input max X count out of range, should not larger than q->count(%d)\n",
						vsi->rx_rings[0]->count);
			ret = -EINVAL;
			goto command_write_done;
		}

		if (dump_all) {
			nse_for_each_rxq(vsi, i) {
				rxq = vsi->rx_rings[i];
				if (!rxq)
					continue;
				nse_dump_rxq_txq_desc(rxq, true, max_desc_cnt,
						      !!dump_dir_from_ntc_to_ntu);
			}
		} else {
			nse_dump_rxq_txq_desc(rxq, true, max_desc_cnt, !!dump_dir_from_ntc_to_ntu);
		}

		dumped = true;
	}

	if (!strcmp(argv[1], "desc_raw")) {
		if (!vsi->rx_rings[0]) {
			/*  need this for max_desc_cnt comparition. if special "all", then local
			 * var: rxq is unset
			 */
			ret = -EINVAL;
			goto command_write_done;
		}

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

		if ((desc_idx >= vsi->rx_rings[0]->count) ||
			(max_desc_cnt > vsi->rx_rings[0]->count) ||
			((desc_idx + max_desc_cnt) > vsi->rx_rings[0]->count)) {
			dev_info(dev, "input number X and Y out of range, should not exceed q->count(%d)\n",
						vsi->tx_rings[0]->count);
			ret = -EINVAL;
			goto command_write_done;
		}

		if (dump_all) {
			nse_for_each_rxq(vsi, i) {
				rxq = vsi->rx_rings[i];
				if (!rxq)
					continue;
				nse_dump_rxq_txq_desc_raw(rxq, true, desc_idx, max_desc_cnt);
			}
		} else {
			nse_dump_rxq_txq_desc_raw(rxq, true, desc_idx, max_desc_cnt);
		}

		dumped = true;
	}

	if (strstr(argv[1], "force_stop")) {
		if (dump_all) {
			(void)nse_vsi_stop_all_rx_rings(vsi, false);
			//(void)nse_vsi_stop_xdp_tx_rings(vsi);
		} else {
			(void)nse_vsi_ctrl_one_rx_ring(vsi, false, qid_vsi);
		}

		dumped = true;
	}

	if (strstr(argv[1], "force_conf")) {
		if (dump_all)
			(void)nse_vsi_cfg_rxqs(vsi);
		else
			(void)nse_vsi_cfg_rxq(rxq);

		dumped = true;
	}

	if (!dumped)	/* nothing dumped ? */
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
	dev_info(dev, "\t echo '#N|all status' - dump RXQ-#N status\n");
	dev_info(dev, "\t echo '#N|all context' - dump RXQ-#N context\n");
	dev_info(dev, "\t echo '#N|all desc #X #Y' - dump RXQ-#N descriptor, max X count, Y - direction, from ntc to ntu or reverse\n");
	dev_info(dev, "\t echo '#N|all desc_raw #X #Y' - dump RXQ-#N descriptors at specified index(X), number(Y)\n");
	dev_info(dev, "\t echo '#N|all force_stop' - force_stop RXQ-#N\n");
	dev_info(dev, "\t echo '#N|all force_conf' - force_conf RXQ-#N\n");

	ret = -EINVAL;

	goto command_write_done;
}

static const struct file_operations nse_debugfs_vsi_dump_rxq_fops = {
	.owner = THIS_MODULE,
	.open  = simple_open,
	.write = nse_debugfs_vsi_dump_rxq_wfunc,
	.llseek = default_llseek,
};

static ssize_t
nse_debugfs_vsi_dump_txq_wfunc(struct file *filp, const char __user *buf,
			  size_t count, loff_t *ppos)
{
	struct nse_vsi *vsi = filp->private_data;
	struct nse_pf *pf = vsi->back;
	struct nse_ring *txq = NULL;
	struct device *dev = nse_pf_to_dev(pf);
	char *cmd_buf, *cmd_buf_tmp;
	ssize_t ret;
	char **argv;
	int argc;
	u16 qid_vsi;
	u16 desc_idx;
	u16 max_desc_cnt;
	int dump_all = 0;
	int i;
	bool dumped = false;
	int dump_dir_from_ntc_to_ntu = 0;

	/* don't allow partial writes and writes when reset is in progress*/
	if (*ppos != 0)
		return -EINVAL;

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
		if (kstrtou16(argv[0], 10, &qid_vsi))
			goto bad_usage;

		if (qid_vsi >= vsi->alloc_txq) {
			dev_info(dev, "input TXQ number out of range\n");

			ret = -EINVAL;
			goto command_write_done;
		}

		txq = vsi->tx_rings[qid_vsi];
		if (!txq) {
			dev_info(dev, "input TXQ not used or enabled\n");

			ret = -EINVAL;
			goto command_write_done;
		}
	}

	if (strstr(argv[1], "info")) {
		if (dump_all) {
			nse_for_each_txq(vsi, i) {
				txq = vsi->tx_rings[i];
				if (!txq)
					continue;
				nse_dump_rxq_txq_info(txq, false);
			}
		} else {
			nse_dump_rxq_txq_info(txq, false);
		}

		dumped = true;
	}

	if (strstr(argv[1], "status")) {
		if (dump_all) {
			nse_for_each_txq(vsi, i) {
				txq = vsi->tx_rings[i];
				if (!txq)
					continue;
				nse_dump_rxq_txq_status(txq, false);
			}
		} else {
			nse_dump_rxq_txq_status(txq, false);
		}

		dumped = true;
	}

	if (strstr(argv[1], "context")) {
		if (dump_all) {
			nse_for_each_txq(vsi, i) {
				txq = vsi->tx_rings[i];
				if (!txq)
					continue;
				nse_dump_rxq_txq_context(txq, false);
			}
		} else {
			nse_dump_rxq_txq_context(txq, false);
		}

		dumped = true;
	}

	if (!strcmp(argv[1], "desc")) {
		if (!vsi->tx_rings[0]) {
			/*  need this for max_desc_cnt comparition. if special "all", then local
			 * var: txq is unset
			 */
			ret = -EINVAL;
			goto command_write_done;
		}

		if (argc >= 3) {
			if (kstrtou16(argv[2], 10, &max_desc_cnt))
				goto bad_usage;
		} else {
			max_desc_cnt = vsi->tx_rings[0]->count;
		}

		if (argc >= 4) {
			if (kstrtoint(argv[3], 10, &dump_dir_from_ntc_to_ntu))
				dump_dir_from_ntc_to_ntu = 0;
		}

		if (max_desc_cnt > vsi->tx_rings[0]->count) {
			dev_info(dev, "input max X count out of range, should not larger than q->count(%d)\n",
						vsi->tx_rings[0]->count);
			ret = -EINVAL;
			goto command_write_done;
		}

		if (dump_all) {
			nse_for_each_txq(vsi, i) {
				txq = vsi->tx_rings[i];
				if (!txq)
					continue;
				nse_dump_rxq_txq_desc(txq, false, max_desc_cnt,
						      !!dump_dir_from_ntc_to_ntu);
			}
		} else {
			nse_dump_rxq_txq_desc(txq, false, max_desc_cnt, !!dump_dir_from_ntc_to_ntu);
		}

		dumped = true;
	}

	if (!strcmp(argv[1], "desc_raw")) {
		if (!vsi->tx_rings[0]) {
			/*  need this for max_desc_cnt comparition. if special "all", then local
			 * var: txq is unset
			 */
			ret = -EINVAL;
			goto command_write_done;
		}

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

		if ((desc_idx >= vsi->tx_rings[0]->count) ||
			(max_desc_cnt > vsi->tx_rings[0]->count) ||
			((desc_idx + max_desc_cnt) > vsi->tx_rings[0]->count)) {
			dev_info(dev, "input number X and Y out of range, should not exceed q->count(%d)\n",
						vsi->tx_rings[0]->count);
			ret = -EINVAL;
			goto command_write_done;
		}

		if (dump_all) {
			nse_for_each_txq(vsi, i) {
				txq = vsi->tx_rings[i];
				if (!txq)
					continue;
				nse_dump_rxq_txq_desc_raw(txq, false, desc_idx, max_desc_cnt);
			}
		} else {
			nse_dump_rxq_txq_desc_raw(txq, false, desc_idx, max_desc_cnt);
		}

		dumped = true;
	}

#if defined(NSE_DEBUG_EXT)
	if (!strcmp(argv[1], "desc_used")) {
		if (!vsi->tx_rings[0]) {
			/*  need this for max_desc_cnt comparition. if special "all", then local
			 * var: txq is unset
			 */
			ret = -EINVAL;
			goto command_write_done;
		}

		if (argc >= 3) {
			if (kstrtou16(argv[2], 10, &max_desc_cnt))
				goto bad_usage;
		} else {
			max_desc_cnt = NSE_TX_RING_USED_RECORD_LEN;
		}

		if (max_desc_cnt > NSE_TX_RING_USED_RECORD_LEN)
			max_desc_cnt = NSE_TX_RING_USED_RECORD_LEN;

		if (dump_all) {
			nse_for_each_txq(vsi, i) {
				txq = vsi->tx_rings[i];
				if (!txq)
					continue;
				nse_dump_txq_used_record(txq, max_desc_cnt);
			}
		} else {
			nse_dump_txq_used_record(txq, max_desc_cnt);
		}

		dumped = true;
	}

	if (!strcmp(argv[1], "desc_clean")) {
		if (!vsi->tx_rings[0]) {
			/*  need this for max_desc_cnt comparition. if special "all", then local
			 * var: txq is unset
			 */
			ret = -EINVAL;
			goto command_write_done;
		}

		if (argc >= 3) {
			if (kstrtou16(argv[2], 10, &max_desc_cnt))
				goto bad_usage;
		} else {
			max_desc_cnt = NSE_TX_RING_CLEAN_RECORD_LEN;
		}

		if (max_desc_cnt > NSE_TX_RING_CLEAN_RECORD_LEN)
			max_desc_cnt = NSE_TX_RING_CLEAN_RECORD_LEN;

		if (dump_all) {
			nse_for_each_txq(vsi, i) {
				txq = vsi->tx_rings[i];
				if (!txq)
					continue;
				nse_dump_txq_clean_record(txq, max_desc_cnt);
			}
		} else {
			nse_dump_txq_clean_record(txq, max_desc_cnt);
		}

		dumped = true;
	}
#endif

	if (strstr(argv[1], "force_stop")) {
		if (dump_all) {
			(void)nse_vsi_stop_lan_tx_rings(vsi, false);
			//(void)nse_vsi_stop_xdp_tx_rings(vsi);
		} else {
			struct nse_txq_meta txq_meta = { };

			nse_fill_txq_meta(vsi, txq, &txq_meta);
			(void)nse_vsi_stop_tx_ring(vsi, txq, &txq_meta, false);
		}

		dumped = true;
	}

	if (strstr(argv[1], "force_conf")) {
		if (dump_all)
			(void)nse_vsi_cfg_lan_txqs(vsi);
		else
			(void)nse_vsi_cfg_txq(txq);

		dumped = true;
	}

	if (!dumped)	/* nothing dumped ? */
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
	dev_info(dev, "\t echo '#N|all status' - dump TXQ-#N status\n");
	dev_info(dev, "\t echo '#N|all context' - dump TXQ-#N context\n");
	dev_info(dev, "\t echo '#N|all desc #X #Y' - dump TXQ-#N descriptor, max X count, Y - direction, from ntc to ntu or reverse\n");
	dev_info(dev, "\t echo '#N|all desc_raw #X #Y' - dump TXQ-#N descriptors at specified index(X), number(Y)\n");
#if defined(NSE_DEBUG_EXT)
	dev_info(dev, "\t echo '#N|all desc_used #X'\n");
	dev_info(dev, "\t echo '#N|all desc_used #X'\n");
#endif
	dev_info(dev, "\t echo '#N|all force_stop' - force_stop TXQ-#N\n");
	dev_info(dev, "\t echo '#N|all force_conf' - force_conf TXQ-#N\n");

	ret = -EINVAL;

	goto command_write_done;
}

static const struct file_operations nse_debugfs_vsi_dump_txq_fops = {
	.owner = THIS_MODULE,
	.open  = simple_open,
	.write = nse_debugfs_vsi_dump_txq_wfunc,
	.llseek = default_llseek,
};

static void nse_dump_txcq_info(struct nse_txcq_ring *q)
{
	struct device *dev = q->dev;

	dev_info(dev, "=== LAN-TX-CQ-%d info\n", q->q_index);
	dev_info(dev, "cq_rel_id = %d\n", q->cq_rel_id);
	dev_info(dev, "cq_abs_id = %d\n", q->cq_abs_id);
	dev_info(dev, "desc = 0x%lX\n", (unsigned long)q->desc);
	dev_info(dev, "desc_dma = 0x%lX\n", (unsigned long)q->dma);
	dev_info(dev, "count = %d\n", q->count);
	dev_info(dev, "next_to_clean = %d\n", q->next_to_clean);
	dev_info(dev, "generation = %d\n", q->generation);
	if (q->q_vector)
		dev_info(dev, "q_vector->v_idx = %d\n", q->q_vector->v_idx);
	else
		dev_info(dev, "q_vector = NULL? how come this Q not bound to a q_vector?\n");
	dev_info(dev, "q_index = %d\n", q->q_index);
	dev_info(dev, "flags = %X\n", q->flags);

	dev_info(dev, "need_irqll = %d\n", q->need_irqll);
	dev_info(dev, "irqll_msix = %d\n", q->irqll_msix);
	dev_info(dev, "already_in_irqll = %d\n", q->already_in_irqll);

	dev_info(dev, "stats:\n");
	dev_info(dev, "\t pkts=%lld\n", q->stats.pkts);
	dev_info(dev, "\t bytes=%lld\n", q->stats.bytes);
	dev_info(dev, "\t cqe_cnt=%lld\n", q->stats.cqe_cnt);
	dev_info(dev, "\t gen_flip_cnt=%lld\n", q->stats.gen_flip_cnt);
	dev_info(dev, "\t txqe_cnt=%lld\n", q->stats.txqe_cnt);
#ifdef NSE_ADD_PROBES
	dev_info(dev, "\t napi_poll_cnt=%lld\n", q->stats.napi_poll_cnt);
#endif
}

static void
nse_dump_txcq_status(struct nse_txcq_ring *q)
{
	struct device *dev = q->dev;
	struct nse_pf *pf = q->vsi->back;
	struct nse_hw *hw = &pf->hw;
	u16 q_status;
	enum nse_status status;

	status = nse_read_lan_txcq_status(hw, q->vsi, q->cq_abs_id, &q_status);

	if (!status) {
		dev_info(dev, "read_lan_txcq_status: success\n");
		dev_info(dev, "\t q_status=%d\n", q_status);
	} else {
		dev_info(dev, "read_lan_txcq_status: fail, status = %d (%s)\n",
				(int)status, nse_stat_str(status));
	}
}

static void
nse_dump_txcq_context(struct nse_txcq_ring *q)
{
	struct device *dev = q->dev;
	struct nse_pf *pf = q->vsi->back;
	struct nse_hw *hw = &pf->hw;
	struct nse_lan_txcq_ctx cq_ctx;
	enum nse_status status;

	status = nse_read_lan_txcq_ctx(hw, &cq_ctx, q->cq_abs_id);
	if (!status) {
		dev_info(dev, "read_lan_txcq_ctx: success\n");

		nse_lan_txcq_ctx_dump(hw, q->cq_rel_id, q->cq_abs_id, &cq_ctx, 0xFFFF);

		nse_lan_txcq_ctx_compare(hw, &q->saved_txcq_ctx, &cq_ctx, 0xF);
	} else {
		dev_info(dev, "read_lan_txcq_ctx: fail, status = %d (%s)\n",
				(int)status, nse_stat_str(status));
	}
}

static void
nse_dump_txcq_desc(struct nse_txcq_ring *q, u16 max_desc_cnt)
{
	struct device *dev = q->dev;
	struct nse_vsi *vsi = q->vsi;
	u32 ntc;
	struct nse_lan_txcq_desc *cq_desc = NULL;

	if (vsi->type == NSE_VSI_VF || vsi->type == NSE_VSI_ADI) {
		dev_info(dev, "VF-VSI and ADI-VSI lanQ descriptor memory may not in current OS, don't support dump\n");
		return;
	}

	if (!q->desc || !q->count) {
		dev_info(dev, "VSI lanQ descriptor memory not allocated, may be this Q not used or enabled\n");
		return;
	}

	ntc = q->next_to_clean;

	dev_info(dev, "next_to_clean = %d, max_desc_cnt(to dump) = %d\n",
			ntc, max_desc_cnt);

	while (max_desc_cnt) {
		cq_desc = NSE_TXCQ_DESC(q, ntc);
		nse_dump_lan_txcq_desc(dev, q->q_index, ntc, cq_desc);

		max_desc_cnt--;

		ntc++;
		if (ntc == q->count)	/* wrap around */
			ntc = 0;
	}
}

static void
nse_dump_txcq_desc_raw(struct nse_txcq_ring *q, u32 start_idx, u32 max_desc_cnt)
{
	struct device *dev = q->dev;
	struct nse_vsi *vsi = q->vsi;
	struct nse_lan_txcq_desc *cq_desc = NULL;

	if (vsi->type == NSE_VSI_VF || vsi->type == NSE_VSI_ADI) {
		dev_info(dev, "VF-VSI and ADI-VSI lanQ descriptor memory may not in current OS, don't support dump\n");
		return;
	}

	if (!q->desc || !q->count) {
		dev_info(dev, "VSI lanQ descriptor memory not allocated, may be this Q not used or enabled\n");
		return;
	}

	dev_info(dev, "next_to_clean = %d\n", q->next_to_clean);
	dev_info(dev, "we dump: start_idx = %d, number = %d\n", start_idx, max_desc_cnt);

	while (max_desc_cnt) {
		cq_desc = NSE_TXCQ_DESC(q, start_idx);
		nse_dump_lan_txcq_desc(dev, q->q_index, start_idx, cq_desc);

		max_desc_cnt--;

		start_idx++;
		if (start_idx == q->count)	/* wrap around */
			start_idx = 0;
	}
}

static ssize_t
nse_debugfs_vsi_dump_txcq_wfunc(struct file *filp, const char __user *buf,
			  size_t count, loff_t *ppos)
{
	struct nse_vsi *vsi = filp->private_data;
	struct nse_pf *pf = vsi->back;
	struct nse_txcq_ring *cq = NULL;
	struct device *dev = nse_pf_to_dev(pf);
	char *cmd_buf, *cmd_buf_tmp;
	ssize_t ret;
	char **argv;
	int argc;
	u16 q_idx;
	u32 desc_idx;
	u32 max_desc_cnt;
	int dump_all = 0;
	int i;
	bool dumped = false;

	/* don't allow partial writes and writes when reset is in progress*/
	if (*ppos != 0)
		return (ssize_t)count;

	if (!vsi->sw_conf.lan_tx_use_cq) {
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
		if (kstrtou16(argv[0], 10, &q_idx))
			goto bad_usage;

		if (q_idx >= vsi->num_txcq) {
			dev_info(dev, "input LAN-TX-CQ number out of range\n");

			ret = -EINVAL;
			goto command_write_done;
		}

		cq = vsi->txcq_rings[q_idx];
		if (!cq) {
			dev_info(dev, "input LAN-TX-CQ not used or enabled\n");

			ret = -EINVAL;
			goto command_write_done;
		}
	}

	if (strstr(argv[1], "info")) {
		if (dump_all) {
			nse_for_each_lan_txcq(vsi, i) {
				cq = vsi->txcq_rings[i];
				if (!cq)
					continue;
				nse_dump_txcq_info(cq);
			}
		} else {
			nse_dump_txcq_info(cq);
		}

		dumped = true;
	}

	if (strstr(argv[1], "status")) {
		if (dump_all) {
			nse_for_each_lan_txcq(vsi, i) {
				cq = vsi->txcq_rings[i];
				if (!cq)
					continue;
				nse_dump_txcq_status(cq);
			}
		} else {
			nse_dump_txcq_status(cq);
		}

		dumped = true;
	}

	if (strstr(argv[1], "context")) {
		if (dump_all) {
			nse_for_each_lan_txcq(vsi, i) {
				cq = vsi->txcq_rings[i];
				if (!cq)
					continue;
				nse_dump_txcq_context(cq);
			}
		} else {
			nse_dump_txcq_context(cq);
		}

		dumped = true;
	}

	if (!strcmp(argv[1], "desc")) {
		if (!vsi->txcq_rings[0]) {
			/*  need this for max_desc_cnt comparition. if special "all", then local
			 * var: txq is unset
			 */
			ret = -EINVAL;
			goto command_write_done;
		}

		if (argc >= 3) {
			if (kstrtouint(argv[2], 10, &max_desc_cnt))
				goto bad_usage;
		} else {
			max_desc_cnt = vsi->num_txcq_desc;
		}

		if (max_desc_cnt > vsi->num_txcq_desc) {
			dev_info(dev, "input max X count out of range, should not larger than q->count(%d)\n",
						vsi->txcq_rings[0]->count);
			ret = -EINVAL;
			goto command_write_done;
		}

		if (dump_all) {
			nse_for_each_lan_txcq(vsi, i) {
				cq = vsi->txcq_rings[i];
				if (!cq)
					continue;
				nse_dump_txcq_desc(cq, max_desc_cnt);
			}
		} else {
			nse_dump_txcq_desc(cq, max_desc_cnt);
		}

		dumped = true;
	}

	if (!strcmp(argv[1], "desc_raw")) {
		if (!vsi->txcq_rings[0]) {
			/*  need this for max_desc_cnt comparition. if special "all", then local
			 * var: txq is unset
			 */
			ret = -EINVAL;
			goto command_write_done;
		}

		if (argc < 3)
			goto bad_usage;

		if (kstrtouint(argv[2], 10, &desc_idx))
			goto bad_usage;

		if (argc >= 4) {
			if (kstrtouint(argv[3], 10, &max_desc_cnt))
				goto bad_usage;
		} else {
			max_desc_cnt = 1;
		}

		if ((desc_idx >= vsi->num_txcq_desc) ||
			(max_desc_cnt > vsi->num_txcq_desc) ||
			((desc_idx + max_desc_cnt) > vsi->num_txcq_desc)) {
			dev_info(dev, "input number X and Y out of range, should not exceed q->count(%d)\n",
						vsi->txcq_rings[0]->count);
			ret = -EINVAL;
			goto command_write_done;
		}

		if (dump_all) {
			nse_for_each_lan_txcq(vsi, i) {
				cq = vsi->txcq_rings[i];
				if (!cq)
					continue;
				nse_dump_txcq_desc_raw(cq, desc_idx, max_desc_cnt);
			}
		} else {
			nse_dump_txcq_desc_raw(cq, desc_idx, max_desc_cnt);
		}

		dumped = true;
	}

	if (!dumped)	/* nothing dumped ? */
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
	dev_info(dev, "\t echo '#N|all info' - dump TX-CQ-#N info\n");
	dev_info(dev, "\t echo '#N|all status' - dump TX-CQ-#N status\n");
	dev_info(dev, "\t echo '#N|all context' - dump TX-CQ-#N context\n");
	dev_info(dev, "\t echo '#N|all desc #X' - dump TX-CQ-#N descriptor, from next_to_clean to next_to_use, max X count\n");
	dev_info(dev, "\t echo '#N|all desc_raw #X #Y' - dump TX-CQ-#N descriptors at specified index(X), number(Y)\n");

	ret = -EINVAL;

	goto command_write_done;
}

static const struct file_operations nse_debugfs_vsi_dump_txcq_fops = {
	.owner = THIS_MODULE,
	.open  = simple_open,
	.write = nse_debugfs_vsi_dump_txcq_wfunc,
	.llseek = default_llseek,
};

static void
nse_dump_qvec(struct nse_q_vector *qvec)
{
	struct nse_vsi *vsi = qvec->vsi;
	struct nse_pf *pf = vsi->back;
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_ring *ring = NULL;
#if defined(NSE_DEBUG_EXT)
	struct timespec64 ts_spec;
#endif

	dev_info(dev, "====== qvec info (id_in_vsi=%d, reg_idx(id_in_pf)=%d)\n",
						qvec->v_idx, qvec->reg_idx);

	dev_info(dev, "name: %s\n", qvec->name);
	dev_info(dev, "total_events: %d\n", qvec->total_events);
	dev_info(dev, "v_idx: %d\n", qvec->v_idx);
	dev_info(dev, "reg_idx: %d (should be equal to id_in_pf: %d)\n",
		 qvec->reg_idx, qvec->v_idx + vsi->base_vector);
	dev_info(dev, "num_ring_rx: %d\n", qvec->num_ring_rx);
	dev_info(dev, "num_ring_tx: %d\n", qvec->num_ring_tx);
	dev_info(dev, "wb_on_itr: %d\n", qvec->wb_on_itr);
	dev_info(dev, "intrl: %d\n", qvec->intrl);
	dev_info(dev, "itr_settings: 0x%X\n", qvec->itr_settings);
	dev_info(dev, "\t itr_setting (us): %d\n", qvec->itr_setting);
	dev_info(dev, "\t itr_mode: %d (0 for static, 1 for dynamic)\n", qvec->itr_mode);
	dev_info(dev, "dyn_itr_refresh: %d\n", qvec->dyn_itr_refresh);
	dev_info(dev, "dyn_itr_val (us): %d\n", (qvec->dyn_itr_val << 1));

	dev_info(dev, "rx_rings:\n");
	ring = qvec->rx.ring;
	while (ring) {
		dev_info(dev, "\t q_index: %d\n", ring->q_index);
		ring = ring->next;
	}

	dev_info(dev, "tx_rings:\n");
	ring = qvec->tx.ring;
	while (ring) {
		dev_info(dev, "\t q_index: %d\n", ring->q_index);
		ring = ring->next;
	}

	if (vsi->sw_conf.lan_tx_use_cq) {
		dev_info(dev, "txcq_ring:\n");
		if (!qvec->txcq) {
			dev_info(dev, "\t HOW COME qvec->txcq == NULL?\n");
		} else {
			dev_info(dev, "\t q_index: %d, rel_id: %d, abs_id: %d\n",
							qvec->txcq->q_index, qvec->txcq->cq_rel_id,
								qvec->txcq->cq_abs_id);
		}
	}

#if defined(NSE_DEBUG_EXT)
	dev_info(dev, "dbg_stats:\n");
	dev_info(dev, "\t hardirq_total_cnt = %ld\n", qvec->dbg_stats.hardirq_total_cnt);
	dev_info(dev, "\t napi_poll_total_cnt = %ld\n", qvec->dbg_stats.napi_poll_total_cnt);

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
		 (unsigned long)qvec->dbg_stats.napi_poll_budeget_less_0_last_poll_cnt);
	ts_spec = ns_to_timespec64(qvec->dbg_stats.napi_poll_budeget_less_0_last_ns);
	dev_info(dev, "\t napi_poll_budeget_less_0_last_ns=%ld (sec=%ld, nsec=%ld)\n",
		 (unsigned long)qvec->dbg_stats.napi_poll_budeget_less_0_last_ns,
		 (unsigned long)ts_spec.tv_sec, (unsigned long)ts_spec.tv_nsec);

	dev_info(dev, "\t napi_poll_cpu_change_cnt = %ld\n",
		 qvec->dbg_stats.napi_poll_cpu_change_cnt);
	dev_info(dev, "\t napi_poll_cpu_change_last_poll_cnt = %ld\n",
		 qvec->dbg_stats.napi_poll_cpu_change_last_poll_cnt);
	ts_spec = ns_to_timespec64(qvec->dbg_stats.napi_poll_cpu_change_last_ns);
	dev_info(dev, "\t napi_poll_cpu_change_last_ns=%ld (sec=%ld, nsec=%ld)\n",
		 (unsigned long)qvec->dbg_stats.napi_poll_cpu_change_last_ns,
		 (unsigned long)ts_spec.tv_sec, (unsigned long)ts_spec.tv_nsec);

	dev_info(dev, "\t napi_poll_last_ret_event=%ld\n",
		 qvec->dbg_stats.napi_poll_last_ret_event);

	dev_info(dev, "register: INT_DYN_CTLN(%d): %X\n", qvec->reg_idx,
		 rd32(&pf->hw, NSE_REG_INT_DYN_CTLN(qvec->reg_idx)));
#endif
}

static ssize_t
nse_debugfs_vsi_dump_qvec_wfunc(struct file *filp, const char __user *buf,
			  size_t count, loff_t *ppos)
{
	struct nse_vsi *vsi = filp->private_data;
	struct nse_pf *pf = vsi->back;
	struct device *dev = nse_pf_to_dev(pf);
	char *cmd_buf, *cmd_buf_tmp;
	ssize_t ret;
	char **argv;
	int argc;
	u16 qvec_id_in_vsi;
	struct nse_q_vector *qvec = NULL;
	int dump_all = 0;
	int i = 0;

	/* don't allow partial writes and writes when reset is in progress*/
	if (*ppos != 0)
		return -EINVAL;

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

	if (!strcmp(argv[0], "all")) {
		dump_all = 1;
	} else {
		if (kstrtou16(argv[0], 10, &qvec_id_in_vsi))
			goto bad_usage;

		if (qvec_id_in_vsi >= vsi->num_q_vectors) {
			dev_info(dev, "input qvector number out of range\n");

			ret = -EINVAL;
			goto command_write_done;
		}

		qvec = vsi->q_vectors[qvec_id_in_vsi];
		if (!qvec) {
			dev_info(dev, "input qvec not used or enabled\n");

			ret = -EINVAL;
			goto command_write_done;
		}
	}

	if (dump_all) {
		nse_for_each_q_vector(vsi, i) {
			qvec = vsi->q_vectors[i];
			if (!qvec)
				continue;
			nse_dump_qvec(qvec);
		}
	} else {
		nse_dump_qvec(qvec);
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

static const struct file_operations nse_debugfs_vsi_dump_qvec_fops = {
	.owner = THIS_MODULE,
	.open  = simple_open,
	.write = nse_debugfs_vsi_dump_qvec_wfunc,
	.llseek = default_llseek,
};

#if defined(NSE_DEBUG_EXT)

static void hack_send_magic_pkt(struct net_device *dev, unsigned int pkt_size, bool tx_ptp)
{
	int hlen = LL_RESERVED_SPACE(dev);
	int tlen = dev->needed_tailroom;
	struct sk_buff *skb = NULL;
	void *ptr = NULL;
	struct ethhdr *eh = NULL;
	struct iphdr *iph = NULL;
	struct udphdr *udph = NULL;
	unsigned int l4_payload_len;
	__wsum csum;
	__le32 saddr, daddr;

	if (pkt_size > (sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr))) {
		l4_payload_len = pkt_size - (sizeof(struct ethhdr) +
					     sizeof(struct iphdr) + sizeof(struct udphdr));
	} else {
		nse_printk("skb length error");
		goto error_out;
	}

	skb = alloc_skb(hlen + sizeof(struct iphdr) + sizeof(struct udphdr) +
			l4_payload_len + tlen, GFP_ATOMIC);
	if (!skb)
		goto error_out;

	skb->protocol = htons(ETH_P_IP);
	skb->dev = dev;
	skb->pkt_type = PACKET_HOST;

	skb_reserve(skb, hlen + sizeof(struct iphdr) + sizeof(struct udphdr));

	skb_reserve(skb, l4_payload_len);

	/* construct payload */
	ptr = skb_push(skb, l4_payload_len);
	get_random_bytes(ptr, l4_payload_len);

	/* construct UDP header */
	udph = skb_push(skb, sizeof(struct udphdr));

	skb_reset_transport_header(skb);

	udph->source = htons(0x8088);
	udph->dest = htons(0x8088);
	udph->len = htons(l4_payload_len + sizeof(struct udphdr));

	saddr = (0x1) | (0x1 << 8) | (0x1 << 16) | (0x1 << 24);	/* 1.1.1.1 */
	saddr = cpu_to_be32(saddr);

	/* random DIP */
	get_random_bytes(&daddr, sizeof(daddr));

	csum = skb_checksum(skb, skb_transport_offset(skb), l4_payload_len + 8, 0);
	udph->check = csum_tcpudp_magic(saddr, daddr, l4_payload_len + 8, IPPROTO_UDP, csum);

	/* construct IPv4 header */
	iph = skb_push(skb, sizeof(struct iphdr));

	skb_reset_network_header(skb);

	iph->ihl = 5;
	iph->version = 4;
	iph->ttl = 32;
	iph->protocol = IPPROTO_UDP;	/* UDP */
	iph->saddr = saddr;
	iph->daddr = daddr;
	iph->id = htons(0x8088);
	iph->frag_off = 0;
	iph->tot_len = htons((20 + 8 + l4_payload_len));
	ip_send_check(iph);

	/* construct Ethernet header */
	eh = skb_push(skb, sizeof(struct ethhdr));

	skb_reset_mac_header(skb);
	skb_reset_mac_len(skb);

	memcpy(eh->h_source, dev->dev_addr, ETH_ALEN);

	eh->h_dest[0] = 0x00;
	eh->h_dest[1] = 0x19;
	eh->h_dest[2] = 0x77;
	eh->h_dest[3] = 0xAA;
	eh->h_dest[4] = 0xBB;
	eh->h_dest[5] = 0xCC;

	eh->h_proto = htons(ETH_P_IP);

	/* use these 2 as magic check */
	skb->wifi_acked_valid = 1;
	skb->wifi_acked = 1;

	if (tx_ptp)
		skb_shinfo(skb)->tx_flags |= SKBTX_HW_TSTAMP;

	dev_queue_xmit(skb);

	return;

error_out:
	if (!skb)
		kfree_skb(skb);
}

static void hack_send_magic_pkt_task_func(struct work_struct *work)
{
	struct nse_vsi *vsi = container_of(work, struct nse_vsi, hack_send_magic_pkt_task);
	struct net_device *netdev = vsi->netdev;
	int i = 0;

	for (i = 0; i < vsi->hack_send_magic_pkt_per_round_budget; i++) {
		if (vsi->hack_send_magic_pkt_task_cancelling)
			goto end;

		if (!vsi->hack_send_magic_pkt_cnt)
			goto end;
		vsi->hack_send_magic_pkt_cnt--;

		if (vsi->hack_send_magic_pkt_interval)
			msleep(vsi->hack_send_magic_pkt_interval);

		if (!netif_carrier_ok(netdev)) {
			nse_printk("!netif_carrier_ok(), end send\n");
			goto end;
		}

		hack_send_magic_pkt(netdev, vsi->hack_send_magic_pkt_size, false);
	}

	schedule_work(work);	/* schedule myself again */

end:
	vsi->hack_send_magic_pkt_task_cancelling = 0;
}

static ssize_t nse_debugfs_vsi_hack_send_magic_pkt_rfunc(struct file *filp,
				 char __user *to, size_t count, loff_t *ppos)
{
	struct nse_vsi *vsi = filp->private_data;
	char buf[64];
	int len, ret;

	len = scnprintf(buf, sizeof(buf), "busy = %d, hack_send_magic_pkt_cnt=%d\n",
				work_busy(&vsi->hack_send_magic_pkt_task),
				vsi->hack_send_magic_pkt_cnt);

	ret = simple_read_from_buffer(to, count, ppos, buf, len);

	return ret;
}

static ssize_t
nse_debugfs_vsi_hack_send_magic_pkt_wfunc(struct file *filp, const char __user *buf,
			  size_t count, loff_t *ppos)
{
	struct nse_vsi *vsi = filp->private_data;
	struct nse_pf *pf = vsi->back;
	struct net_device *netdev = vsi->netdev;
	struct device *dev = nse_pf_to_dev(pf);
	char *cmd_buf, *cmd_buf_tmp;
	ssize_t ret;
	char **argv;
	int argc;
	unsigned int val = 0;

	/* don't allow partial writes and writes when reset is in progress*/
	if (*ppos != 0 || nse_is_reset_in_progress(pf->state))
		return 0;

	if (vsi->type != NSE_VSI_PF) {
		nse_printk("only PF-main-VSI support this operation.\n");
		return 0;
	}

	if (!netdev) {
		nse_printk("No PF-netdev ?\n");
		return 0;
	}

	if (test_bit(NSE_VSI_DOWN, vsi->state)) {
		nse_printk("VSI not open\n");
		return 0;
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

	if (argc < 1)
		goto bad_usage;

	if (!strcmp(argv[0], "cancel")) {
		vsi->hack_send_magic_pkt_task_cancelling = 1;
		cancel_work_sync(&vsi->hack_send_magic_pkt_task);

		goto out;
	}

	if (kstrtouint(argv[0], 10, &val))
		val = 64;
	if (val < 64) {
		nse_printk("pkt_size: %d, increase to 64\n", val);
		val = 64;
	}

	if (val > (NSE_AQ_SET_MAC_FRAME_SIZE_MAX - ETH_FCS_LEN)) {
		nse_printk("pkt_size: %d, decrease to %d\n", val,
			   (NSE_AQ_SET_MAC_FRAME_SIZE_MAX - ETH_FCS_LEN));
		val = (NSE_AQ_SET_MAC_FRAME_SIZE_MAX - ETH_FCS_LEN);
	}

	vsi->hack_send_magic_pkt_size = val;

	vsi->hack_send_magic_pkt_cnt = 1;

	if (argc >= 2) {
		if (kstrtouint(argv[1], 10, &val))
			val = 1;
		if (val > 1000000)
			val = 1000000;

		vsi->hack_send_magic_pkt_cnt = val;
	}

	vsi->hack_send_magic_pkt_interval = 0;

	if (argc >= 3) {
		if (kstrtouint(argv[2], 10, &val))
			val = 0;
		if (val > 100)
			val = 100;

		vsi->hack_send_magic_pkt_interval = val;
	}

	vsi->hack_send_magic_pkt_per_round_budget = 100;
	if (argc >= 4) {
		if (kstrtouint(argv[3], 10, &val))
			val = 100;
		if (val > 5000)
			val = 5000;

		vsi->hack_send_magic_pkt_per_round_budget = val;
	}

	vsi->hack_send_magic_pkt_task_cancelling = 0;

	schedule_work(&vsi->hack_send_magic_pkt_task);

out:
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
	dev_info(dev, "    echo [pkt_size] [cnt] [interval] - send magic packets\n");

	ret = -EINVAL;

	goto command_write_done;
}

static const struct file_operations nse_debugfs_vsi_hack_send_magic_pkt_fops = {
	.owner = THIS_MODULE,
	.open  = simple_open,
	.read = nse_debugfs_vsi_hack_send_magic_pkt_rfunc,
	.write = nse_debugfs_vsi_hack_send_magic_pkt_wfunc,
	.llseek = default_llseek,
};

#endif	/* #if defined(NSE_DEBUG_EXT) */

static ssize_t
nse_debugfs_stats_vsi_wfunc(struct file *filp, const char __user *buf,
			  size_t count, loff_t *ppos)
{
	struct nse_vsi *vsi = filp->private_data;
	struct nse_pf *pf = vsi->back;
	struct nse_hw *hw = &pf->hw;
	struct device *dev = nse_pf_to_dev(pf);
	char *cmd_buf, *cmd_buf_tmp;
	ssize_t ret;
	char **argv;
	int argc;
	struct nse_aqc_rc_dma_chan_per_vsi_stats *stats = NULL;
	struct nse_vsi_sw_stats *ss = NULL;
	enum nse_status status;

	/* don't allow partial writes and writes when reset is in progress*/
	if (*ppos != 0 || nse_is_reset_in_progress(pf->state))
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

	stats = kmalloc(sizeof(*stats), GFP_KERNEL);
	if (!stats) {
		ret = -ENOMEM;
		goto command_write_done;
	}

	status = nse_read_dma_chan_per_vsi_stats(hw, vsi->vsi_abs_num, stats);
	if (status) {
		dev_info(dev, "[%s, %d] read_dma_chan_per_vsi_stats() fails, %d(%s)\n",
				__func__, __LINE__,
				status, nse_stat_str(status));
	} else {
		dev_info(dev, "====== VSI hw_stats(raw)\n");

		dev_info(dev, "\t rdm_vsi_drop_err: 0x%X (%d)\n",
			 le32_to_cpu(stats->rdm_vsi_drop_err),
			le32_to_cpu(stats->rdm_vsi_drop_err));
		dev_info(dev, "\t rdm_vsi_dpkt_lo: 0x%X (%d)\n",
			 le32_to_cpu(stats->rdm_vsi_dpkt_lo), le32_to_cpu(stats->rdm_vsi_dpkt_lo));
		dev_info(dev, "\t rdm_vsi_dpkt_hi: 0x%X (%d)\n",
			 le32_to_cpu(stats->rdm_vsi_dpkt_hi), le32_to_cpu(stats->rdm_vsi_dpkt_hi));
		dev_info(dev, "\t rdm_vsi_goct_lo: 0x%X (%d)\n",
			 le32_to_cpu(stats->rdm_vsi_goct_lo), le32_to_cpu(stats->rdm_vsi_goct_lo));
		dev_info(dev, "\t rdm_vsi_goct_hi: 0x%X (%d)\n",
			 le32_to_cpu(stats->rdm_vsi_goct_hi), le32_to_cpu(stats->rdm_vsi_goct_hi));
		dev_info(dev, "\t rdm_vsi_gpkt_lo: 0x%X (%d)\n",
			 le32_to_cpu(stats->rdm_vsi_gpkt_lo), le32_to_cpu(stats->rdm_vsi_gpkt_lo));
		dev_info(dev, "\t rdm_vsi_gpkt_hi: 0x%X (%d)\n",
			 le32_to_cpu(stats->rdm_vsi_gpkt_hi), le32_to_cpu(stats->rdm_vsi_gpkt_hi));
		dev_info(dev, "\t rdm_vsi_mpkt_lo: 0x%X (%d)\n",
			 le32_to_cpu(stats->rdm_vsi_mpkt_lo), le32_to_cpu(stats->rdm_vsi_mpkt_lo));
		dev_info(dev, "\t rdm_vsi_mpkt_hi: 0x%X (%d)\n",
			 le32_to_cpu(stats->rdm_vsi_mpkt_hi), le32_to_cpu(stats->rdm_vsi_mpkt_hi));
		dev_info(dev, "\t rdm_vsi_bpkt_lo: 0x%X (%d)\n",
			 le32_to_cpu(stats->rdm_vsi_bpkt_lo), le32_to_cpu(stats->rdm_vsi_bpkt_lo));
		dev_info(dev, "\t rdm_vsi_bpkt_hi: 0x%X (%d)\n",
			 le32_to_cpu(stats->rdm_vsi_bpkt_hi), le32_to_cpu(stats->rdm_vsi_bpkt_hi));

		dev_info(dev, "\t tdm_vsi_gptc_lo: 0x%X (%d)\n",
			 le32_to_cpu(stats->tdm_vsi_gptc_lo), le32_to_cpu(stats->tdm_vsi_gptc_lo));
		dev_info(dev, "\t tdm_vsi_gptc_hi: 0x%X (%d)\n",
			 le32_to_cpu(stats->tdm_vsi_gptc_hi), le32_to_cpu(stats->tdm_vsi_gptc_hi));
		dev_info(dev, "\t tdm_vsi_dptc_lo: 0x%X (%d)\n",
			 le32_to_cpu(stats->tdm_vsi_dptc_lo), le32_to_cpu(stats->tdm_vsi_dptc_lo));
		dev_info(dev, "\t tdm_vsi_dptc_hi: 0x%X (%d)\n",
			 le32_to_cpu(stats->tdm_vsi_dptc_hi), le32_to_cpu(stats->tdm_vsi_dptc_hi));
		dev_info(dev, "\t tdm_vsi_gotc_lo: 0x%X (%d)\n",
			 le32_to_cpu(stats->tdm_vsi_gotc_lo), le32_to_cpu(stats->tdm_vsi_gotc_lo));
		dev_info(dev, "\t tdm_vsi_gotc_hi: 0x%X (%d)\n",
			 le32_to_cpu(stats->tdm_vsi_gotc_hi), le32_to_cpu(stats->tdm_vsi_gotc_hi));
		dev_info(dev, "\t tdm_vsi_mptc_lo: 0x%X (%d)\n",
			 le32_to_cpu(stats->tdm_vsi_mptc_lo), le32_to_cpu(stats->tdm_vsi_mptc_lo));
		dev_info(dev, "\t tdm_vsi_mptc_hi: 0x%X (%d)\n",
			 le32_to_cpu(stats->tdm_vsi_mptc_hi), le32_to_cpu(stats->tdm_vsi_mptc_hi));
	}

	nse_update_vsi_stats(vsi);

	ss = &vsi->sw_stats;

	dev_info(dev, "====== VSI sw_stats\n");
	dev_info(dev, "\t rx_pkts: %ld\n", (unsigned long)ss->rx_pkts);
	dev_info(dev, "\t rx_bytes: %ld\n", (unsigned long)ss->rx_bytes);
	dev_info(dev, "\t tx_pkts: %ld\n", (unsigned long)ss->tx_pkts);
	dev_info(dev, "\t tx_bytes: %ld\n", (unsigned long)ss->tx_bytes);
	dev_info(dev, "\t tx_linearize: %ld\n", (unsigned long)ss->tx_linearize);
	dev_info(dev, "\t tx_restart: %ld\n", (unsigned long)ss->tx_restart);
	dev_info(dev, "\t tx_busy: %ld\n", (unsigned long)ss->tx_busy);
	dev_info(dev, "\t rx_csum_good: %ld\n", (unsigned long)ss->rx_csum_good);
	dev_info(dev, "\t rx_csum_bad: %ld\n", (unsigned long)ss->rx_csum_bad);
	dev_info(dev, "\t fdir_match: %ld\n", (unsigned long)ss->fdir_match);
	dev_info(dev, "\t fdir_miss: %ld\n", (unsigned long)ss->fdir_miss);
	dev_info(dev, "\t rx_buf_failed: %ld\n", (unsigned long)ss->rx_buf_failed);
	dev_info(dev, "\t rx_page_failed: %ld\n", (unsigned long)ss->rx_page_failed);
#ifdef NSE_ADD_PROBES
	dev_info(dev, "\t rx_page_reuse: %ld\n", (unsigned long)ss->rx_page_reuse);
#endif

	/* if we get here, nothing went wrong; return bytes copied */
	ret = (ssize_t)count;

command_write_done:
	argv_free(argv);
err_copy_from_user:
	kfree(cmd_buf);

	kfree(stats);

	return ret;

bad_usage:
	dev_info(dev, "invalid input, usage: echo 'anything' > stats_vsi\n");
	ret = -EINVAL;
	goto command_write_done;
}

static const struct file_operations nse_debugfs_stats_vsi_fops = {
	.owner = THIS_MODULE,
	.open  = simple_open,
	.write = nse_debugfs_stats_vsi_wfunc,
	.llseek = default_llseek,
};

static ssize_t
nse_debugfs_sched_conf_vsi_pir_wfunc(struct file *filp, const char __user *buf,
			  size_t count, loff_t *ppos)
{
	struct nse_vsi *vsi = filp->private_data;
	struct nse_pf *pf = vsi->back;
	struct nse_hw *hw = &pf->hw;
	struct nse_port_info *pi = hw->port_info;
	struct nse_sched_info *si = &pi->sched_info;
	struct device *dev = nse_pf_to_dev(pf);
	char *cmd_buf = NULL, *cmd_buf_tmp = NULL;
	ssize_t ret;
	int func_ret;
	char **argv = NULL;
	int argc;
	u32 speed_mbps = 0;

	if (*ppos != 0)
		return -EINVAL;

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

	if (!si->root) {
		dev_info(dev, "SCHED tree empty, not initialized?\n");
		ret = -ENOENT;
		goto command_write_done;
	}

	if (kstrtouint(argv[0], 10, &speed_mbps))
		goto bad_usage;

	func_ret = nse_set_max_bw_limit(vsi, (speed_mbps * 1000));
	if (func_ret)
		dev_err(dev, "FAIL to set VSI PIR\n");

	/* if we get here, nothing went wrong; return bytes copied */
	ret = (ssize_t)count;

command_write_done:
	argv_free(argv);
err_copy_from_user:
	kfree(cmd_buf);

	return ret;

bad_usage:
	dev_info(dev, "invalid input, usage: echo '[N Mbps]' > this_file\n");

	ret = -EINVAL;
	goto command_write_done;
}

static const struct file_operations nse_debugfs_sched_conf_vsi_pir_fops = {
	.owner = THIS_MODULE,
	.open  = simple_open,
	.write = nse_debugfs_sched_conf_vsi_pir_wfunc,
	.llseek = default_llseek,
};

static ssize_t
nse_debugfs_sched_conf_vsi_q_pir_wfunc(struct file *filp, const char __user *buf,
			  size_t count, loff_t *ppos)
{
	struct nse_vsi *vsi = filp->private_data;
	struct nse_pf *pf = vsi->back;
	struct nse_hw *hw = &pf->hw;
	struct nse_port_info *pi = hw->port_info;
	struct nse_sched_info *si = &pi->sched_info;
	struct device *dev = nse_pf_to_dev(pf);
	char *cmd_buf = NULL, *cmd_buf_tmp = NULL;
	ssize_t ret;
	enum nse_status status;
	char **argv = NULL;
	int argc;
	u32 speed_mbps = 0;
	u16 qid_vsi;
	u8 tc;

	if (*ppos != 0)
		return -EINVAL;

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

	if (!si->root) {
		dev_info(dev, "SCHED tree empty, not initialized?\n");
		ret = -ENOENT;
		goto command_write_done;
	}

	if (kstrtou16(argv[0], 10, &qid_vsi))
		goto bad_usage;

	if (kstrtouint(argv[1], 10, &speed_mbps))
		goto bad_usage;

	if (qid_vsi >= vsi->num_txq) {
		dev_err(dev, "QID out of range\n");
		goto bad_usage;
	}

	tc = nse_dcb_get_tc(vsi, qid_vsi);

	status = nse_sched_set_q_pir(pi, vsi->idx, tc,
								qid_vsi, (speed_mbps * 1000));
	if (status)
		dev_err(dev, "FAIL to set VSI Q PIR\n");

	/* if we get here, nothing went wrong; return bytes copied */
	ret = (ssize_t)count;

command_write_done:
	argv_free(argv);
err_copy_from_user:
	kfree(cmd_buf);

	return ret;

bad_usage:
	dev_info(dev, "invalid input, usage: echo 'qid [N Mbps]' > this_file\n");

	ret = -EINVAL;
	goto command_write_done;
}

static const struct file_operations nse_debugfs_sched_conf_vsi_q_pir_fops = {
	.owner = THIS_MODULE,
	.open  = simple_open,
	.write = nse_debugfs_sched_conf_vsi_q_pir_wfunc,
	.llseek = default_llseek,
};

static ssize_t
nse_debugfs_sched_conf_vsi_cir_wfunc(struct file *filp, const char __user *buf,
			  size_t count, loff_t *ppos)
{
	struct nse_vsi *vsi = filp->private_data;
	struct nse_pf *pf = vsi->back;
	struct nse_hw *hw = &pf->hw;
	struct nse_port_info *pi = hw->port_info;
	struct nse_sched_info *si = &pi->sched_info;
	struct device *dev = nse_pf_to_dev(pf);
	char *cmd_buf = NULL, *cmd_buf_tmp = NULL;
	ssize_t ret;
	int func_ret;
	char **argv = NULL;
	int argc;
	u32 speed_mbps = 0;

	if (*ppos != 0)
		return -EINVAL;

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

	if (!si->root) {
		dev_info(dev, "SCHED tree empty, not initialized?\n");
		ret = -ENOENT;
		goto command_write_done;
	}

	if (kstrtouint(argv[0], 10, &speed_mbps))
		goto bad_usage;

	func_ret = nse_set_min_bw_limit(vsi, (speed_mbps * 1000));
	if (func_ret)
		dev_err(dev, "FAIL to set VSI CIR\n");

	/* if we get here, nothing went wrong; return bytes copied */
	ret = (ssize_t)count;

command_write_done:
	argv_free(argv);
err_copy_from_user:
	kfree(cmd_buf);

	return ret;

bad_usage:
	dev_info(dev, "invalid input, usage: echo '[N Mbps]' > this_file\n");

	ret = -EINVAL;
	goto command_write_done;
}

static const struct file_operations nse_debugfs_sched_conf_vsi_cir_fops = {
	.owner = THIS_MODULE,
	.open  = simple_open,
	.write = nse_debugfs_sched_conf_vsi_cir_wfunc,
	.llseek = default_llseek,
};

static ssize_t
nse_debugfs_sched_conf_vsi_q_cir_wfunc(struct file *filp, const char __user *buf,
			  size_t count, loff_t *ppos)
{
	struct nse_vsi *vsi = filp->private_data;
	struct nse_pf *pf = vsi->back;
	struct nse_hw *hw = &pf->hw;
	struct nse_port_info *pi = hw->port_info;
	struct nse_sched_info *si = &pi->sched_info;
	struct device *dev = nse_pf_to_dev(pf);
	char *cmd_buf = NULL, *cmd_buf_tmp = NULL;
	ssize_t ret;
	enum nse_status status;
	char **argv = NULL;
	int argc;
	u32 speed_mbps = 0;
	u16 qid_vsi;
	u8 tc;

	if (*ppos != 0)
		return -EINVAL;

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

	if (!si->root) {
		dev_info(dev, "SCHED tree empty, not initialized?\n");
		ret = -ENOENT;
		goto command_write_done;
	}

	if (kstrtou16(argv[0], 10, &qid_vsi))
		goto bad_usage;

	if (kstrtouint(argv[1], 10, &speed_mbps))
		goto bad_usage;

	if (qid_vsi >= vsi->num_txq) {
		dev_err(dev, "QID out of range\n");
		goto bad_usage;
	}

	tc = nse_dcb_get_tc(vsi, qid_vsi);

	status = nse_sched_set_q_cir(pi, vsi->idx, tc,
								qid_vsi, (speed_mbps * 1000));
	if (status)
		dev_err(dev, "FAIL to set VSI Q CIR\n");

	/* if we get here, nothing went wrong; return bytes copied */
	ret = (ssize_t)count;

command_write_done:
	argv_free(argv);
err_copy_from_user:
	kfree(cmd_buf);

	return ret;

bad_usage:
	dev_info(dev, "invalid input, usage: echo 'qid [N Mbps]' > this_file\n");

	ret = -EINVAL;
	goto command_write_done;
}

static const struct file_operations nse_debugfs_sched_conf_vsi_q_cir_fops = {
	.owner = THIS_MODULE,
	.open  = simple_open,
	.write = nse_debugfs_sched_conf_vsi_q_cir_wfunc,
	.llseek = default_llseek,
};

#if defined(NSE_DEBUG_EXT)

static ssize_t
nse_debugfs_vlan_rx_outer_strip_wfunc(struct file *filp, const char __user *buf,
			  size_t count, loff_t *ppos)
{
	struct nse_vsi *vsi = filp->private_data;
	struct nse_pf *pf = vsi->back;
	struct nse_hw *hw = &pf->hw;
	struct device *dev = nse_pf_to_dev(pf);
	char *cmd_buf, *cmd_buf_tmp;
	ssize_t ret;
	char **argv;
	int argc;
	unsigned long val = 0;
	int func_ret;

	/* don't allow partial writes and writes when reset is in progress*/
	if (*ppos != 0 || nse_is_reset_in_progress(pf->state))
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

	if (kstrtoul(argv[0], 10, &val))
		goto bad_usage;

	if (vsi->vf && nse_vf_is_port_vlan_ena(vsi->vf)) {
		dev_info(dev, "can not do this operation, because VF-VSI port-based VLAN is enabled.\n");

		ret = -EINVAL;
		goto command_write_done;
	}

	if (val) {
		func_ret = nse_vsi_ena_outer_stripping(vsi, hw->stag_ethertype);
		if (func_ret)
			dev_err(dev, "FAIL: ena_outer_stripping(), func_ret=%d\n", func_ret);
	} else {
		func_ret = nse_vsi_dis_outer_stripping(vsi);
		if (func_ret)
			dev_err(dev, "FAIL: dis_outer_stripping(), func_ret=%d\n", func_ret);
	}

	ret = (ssize_t)count;

command_write_done:
	if (argv)
		argv_free(argv);
err_copy_from_user:
	kfree(cmd_buf);

	return ret;

bad_usage:
	dev_info(dev, "echo [0|1] - disable/enable\n");

	ret = -EINVAL;

	goto command_write_done;
}

static const struct file_operations nse_debugfs_vlan_rx_outer_strip_fops = {
	.owner = THIS_MODULE,
	.open  = simple_open,
	.write = nse_debugfs_vlan_rx_outer_strip_wfunc,
	.llseek = default_llseek,
};

static ssize_t
nse_debugfs_vlan_pvid_wfunc(struct file *filp, const char __user *buf,
			  size_t count, loff_t *ppos)
{
	struct nse_vsi *vsi = filp->private_data;
	struct nse_pf *pf = vsi->back;
	struct nse_hw *hw = &pf->hw;
	struct device *dev = nse_pf_to_dev(pf);
	char *cmd_buf, *cmd_buf_tmp;
	ssize_t ret;
	char **argv;
	int argc;
	unsigned long val = 0;
	int i;
	struct nse_ring *txq;
	int func_ret;

	/* don't allow partial writes and writes when reset is in progress*/
	if (*ppos != 0 || nse_is_reset_in_progress(pf->state))
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

	if (kstrtoul(argv[0], 10, &val))
		goto bad_usage;

	if (val >= 4096)
		goto bad_usage;

	if (val) {
		func_ret = __nse_vsi_set_outer_port_vlan(vsi, (u16)val, hw->stag_ethertype);
		if (func_ret)
			dev_err(dev, "FAIL: vsi_set_outer_port_vlan(), func_ret=%d\n", func_ret);

		nse_for_each_txq(vsi, i) {
			txq = vsi->tx_rings[i];
			txq->flags &= ~(NSE_TX_FLAGS_VLAN_TAG_LOC_L2TAG2);
			txq->flags |= NSE_TXRX_FLAGS_VLAN_TAG_LOC_L2TAG1;
		}

		if (nse_lan_vlan_pvid_inner_strip) {
			(void)nse_vsi_ena_inner_stripping(vsi, ETH_P_8021Q);
			(void)nse_vsi_ena_inner_insertion(vsi, ETH_P_8021Q);
		}
	} else {
		vsi->info.stag_port_based = 0;
		vsi->info.stag_port_based_tci = 0;

		func_ret = nse_vsi_ena_outer_stripping(vsi, hw->stag_ethertype);
		if (func_ret)
			dev_err(dev, "FAIL: vsi_ena_outer_stripping(), func_ret=%d\n", func_ret);

		func_ret = nse_vsi_ena_outer_insertion(vsi, hw->stag_ethertype);
		if (func_ret)
			dev_err(dev, "FAIL: vsi_ena_outer_insertion(), func_ret=%d\n", func_ret);

		nse_for_each_txq(vsi, i) {
			txq = vsi->tx_rings[i];
			txq->flags &= ~(NSE_TXRX_FLAGS_VLAN_TAG_LOC_L2TAG1);
			txq->flags |= NSE_TX_FLAGS_VLAN_TAG_LOC_L2TAG2;
		}

		if (nse_lan_vlan_pvid_inner_strip) {
			(void)nse_vsi_dis_inner_stripping(vsi);
			(void)nse_vsi_dis_inner_insertion(vsi);
		}
	}

	ret = (ssize_t)count;

command_write_done:
	if (argv)
		argv_free(argv);
err_copy_from_user:
	kfree(cmd_buf);

	return ret;

bad_usage:
	dev_info(dev, "echo [0|N < 4096] - disable/enable\n");

	ret = -EINVAL;

	goto command_write_done;
}

static const struct file_operations nse_debugfs_vlan_pvid_fops = {
	.owner = THIS_MODULE,
	.open  = simple_open,
	.write = nse_debugfs_vlan_pvid_wfunc,
	.llseek = default_llseek,
};

#endif

static void
nse_dump_vf(struct nse_vf *vf)
{
	struct nse_pf *pf = vf->pf;
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_vsi *vsi = nse_get_vf_vsi(vf);

	if (!vsi) {
		dev_info(dev, "[%s, %d] BAD VF/VSI\n", __func__, __LINE__);
		return;
	}

	dev_info(dev, "=== VF-%d info of this PF\n", vf->vf_id);
	dev_info(dev, "\t vf_ver.major = %d vf_ver.minor = %d\n",
		 vf->vf_ver.major, vf->vf_ver.minor);
	dev_info(dev, "\t driver_caps = 0x%lX\n", (unsigned long)vf->driver_caps);
	dev_info(dev, "\t driver_req_caps = 0x%lX\n", (unsigned long)vf->driver_req_caps);
	dev_info(dev, "\t vf_caps = 0x%08lx\n", vf->vf_caps);

	dev_info(dev, "\t vf_states:\n");
	dev_info(dev, "\t\t NSE_VF_STATE_INIT = %d\n",
		 !!test_bit(NSE_VF_STATE_INIT, vf->vf_states));
	dev_info(dev, "\t\t NSE_VF_STATE_ACTIVE = %d\n",
		 !!test_bit(NSE_VF_STATE_ACTIVE, vf->vf_states));
	dev_info(dev, "\t\t NSE_VF_STATE_QS_ENA = %d\n",
		 !!test_bit(NSE_VF_STATE_QS_ENA, vf->vf_states));
	dev_info(dev, "\t\t NSE_VF_STATE_MC_PROMISC = %d\n",
		 !!test_bit(NSE_VF_STATE_MC_PROMISC, vf->vf_states));
	dev_info(dev, "\t\t NSE_VF_STATE_UC_PROMISC = %d\n",
		 !!test_bit(NSE_VF_STATE_UC_PROMISC, vf->vf_states));

	dev_info(dev, "\t vsi = %p, vsi->idx = %d, vsi_rel_num = %d, vsi_abs_num = %d\n",
		 vsi, vsi->idx, vsi->vsi_rel_num, vsi->vsi_abs_num);
	dev_info(dev, "\t lan_vsi_idx = %d\n", vf->lan_vsi_idx);

	dev_info(dev, "\t num_mac = %d\n", vf->num_mac);
	dev_info(dev, "\t dev_lan_addr = %pM\n", &vf->dev_lan_addr.addr[0]);
	dev_info(dev, "\t hw_lan_addr = %pM\n", &vf->hw_lan_addr.addr[0]);
	dev_info(dev, "\t rxq_ena = 0x%lx\n", *vf->rxq_ena);
	dev_info(dev, "\t txq_ena = 0x%lx\n", *vf->txq_ena);
	dev_info(dev, "\t Port VLAN status: %s\n",
		 nse_vf_is_port_vlan_ena(vf) ? "enabled" : "disabled");
	dev_info(dev, "\t\t Port VLAN ID = %d\n", nse_vf_get_port_vlan_id(vf));
	dev_info(dev, "\t\t QoS = %d\n", nse_vf_get_port_vlan_prio(vf));
	dev_info(dev, "\t\t TPID = 0x%x", nse_vf_get_port_vlan_tpid(vf));
	dev_info(dev, "\t pf_set_mac = %d\n", vf->pf_set_mac);
	dev_info(dev, "\t trusted = %s\n", vf->trusted ? "true" : "false");
	dev_info(dev, "\t spoofchk = %s\n", vf->spoofchk ? "true" : "false");
	dev_info(dev, "\t link_forced = %d, link_up (only valid when link_forced is true) = %d\n",
						vf->link_forced, vf->link_up);
	dev_info(dev, "\tmax_tx_rate = %d\n", vf->max_tx_rate);
	dev_info(dev, "\tmin_tx_rate = %d\n", vf->min_tx_rate);

	dev_info(dev, "\tfirst_vector_idx = %d\n", vf->first_vector_idx);
	dev_info(dev, "\tvf_sw_id = %p\n", vf->vf_sw_id);
}

static ssize_t
nse_debugfs_vf_info_wfunc(struct file *filp, const char __user *buf,
			  size_t count, loff_t *ppos)
{
	struct nse_vf *vf = filp->private_data;
	struct nse_pf *pf = vf->pf;
	struct device *dev = nse_pf_to_dev(pf);
	char *cmd_buf, *cmd_buf_tmp;
	ssize_t ret;
	char **argv;
	int argc;

	/* don't allow partial writes and writes when reset is in progress*/
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

	if (argc != 1)
		goto bad_usage;

	nse_dump_vf(vf);

	/* if we get here, nothing went wrong; return bytes copied */
	ret = (ssize_t)count;

command_write_done:
	argv_free(argv);
err_copy_from_user:
	kfree(cmd_buf);
	return ret;

bad_usage:
	dev_info(dev, "invalid input, usage: echo 'any words' > vf-N\n");
	ret = -EINVAL;
	goto command_write_done;
}

static const struct file_operations nse_debugfs_vf_info_fops = {
	.owner = THIS_MODULE,
	.open  = simple_open,
	.write = nse_debugfs_vf_info_wfunc,
	.llseek = default_llseek,
};

static ssize_t nse_debugfs_vf_vfr_rfunc(struct file *filp,
				 char __user *to, size_t count, loff_t *ppos)
{
	struct nse_vf *vf = filp->private_data;
	char *buf = NULL;
	int desc = 0;
	int ret;

	buf = kzalloc(4096, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	desc += sprintf(buf + desc, "VF-RESET count: %d\n",
				vf->vf_reset_count);
	desc += sprintf(buf + desc, "\t VFR count: %d\n",
				vf->vfr_count);
	desc += sprintf(buf + desc, "\t VFLR count: %d\n",
				vf->vflr_count);

	ret = simple_read_from_buffer(to, count, ppos, buf, desc);

	kfree(buf);

	return ret;
}

static ssize_t
nse_debugfs_vf_vfr_wfunc(struct file *filp, const char __user *buf,
			  size_t count, loff_t *ppos)
{
	struct nse_vf *vf = filp->private_data;
	struct nse_pf *pf = vf->pf;
	struct device *dev = nse_pf_to_dev(pf);
	char *cmd_buf, *cmd_buf_tmp;
	ssize_t ret;
	char **argv;
	int argc;

	/* don't allow partial writes and writes when reset is in progress*/
	if (*ppos != 0 || nse_is_reset_in_progress(pf->state))
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

	if (argc != 1)
		goto bad_usage;

	/* PF-initiate-VFR */
	nse_reset_vf(vf, NSE_VF_RESET_NOTIFY | NSE_VF_RESET_LOCK);

	/* if we get here, nothing went wrong; return bytes copied */
	ret = (ssize_t)count;

command_write_done:
	argv_free(argv);
err_copy_from_user:
	kfree(cmd_buf);
	return ret;

bad_usage:
	dev_info(dev, "invalid input, usage: echo 'any words' > vf-N\n");
	ret = -EINVAL;
	goto command_write_done;
}

static const struct file_operations nse_debugfs_vf_vfr_fops = {
	.owner = THIS_MODULE,
	.open  = simple_open,
	.read = nse_debugfs_vf_vfr_rfunc,
	.write = nse_debugfs_vf_vfr_wfunc,
	.llseek = default_llseek,
};

void nse_debugfs_vsi_init(struct nse_vsi *vsi)
{
	struct nse_pf *pf = vsi->back;
	char vsi_name[16];

	sprintf(vsi_name, "vsi-%d", vsi->idx);

	if (!pf || !pf->pf_dbgfs_dir)
		goto fail;

	vsi->vsi_dbgfs_dir = debugfs_create_dir(vsi_name, pf->pf_dbgfs_dir);
	if (IS_ERR(vsi->vsi_dbgfs_dir))
		goto fail;

	(void)debugfs_create_file("params", 0600, vsi->vsi_dbgfs_dir,
				  vsi, &nse_debugfs_vsi_params_fops);

	(void)debugfs_create_file("info", 0600, vsi->vsi_dbgfs_dir,
				  vsi, &nse_debugfs_vsi_info_fops);
	(void)debugfs_create_file("info_rss", 0600, vsi->vsi_dbgfs_dir,
				  vsi, &nse_debugfs_vsi_info_rss_fops);

	(void)debugfs_create_file("dump_rxq", 0600, vsi->vsi_dbgfs_dir,
				  vsi, &nse_debugfs_vsi_dump_rxq_fops);
	(void)debugfs_create_file("dump_txq", 0600, vsi->vsi_dbgfs_dir,
				  vsi, &nse_debugfs_vsi_dump_txq_fops);
	if (pf->sw_conf.lan_tx_use_cq)
		(void)debugfs_create_file("dump_txcq", 0600, vsi->vsi_dbgfs_dir,
					  vsi, &nse_debugfs_vsi_dump_txcq_fops);
	(void)debugfs_create_file("dump_qvec", 0600, vsi->vsi_dbgfs_dir,
				  vsi, &nse_debugfs_vsi_dump_qvec_fops);

	(void)debugfs_create_file("stats_vsi", 0600, vsi->vsi_dbgfs_dir,
				  vsi, &nse_debugfs_stats_vsi_fops);

	(void)debugfs_create_file("sched_conf_vsi_pir", 0600, vsi->vsi_dbgfs_dir,
				  vsi, &nse_debugfs_sched_conf_vsi_pir_fops);
	(void)debugfs_create_file("sched_conf_vsi_q_pir", 0600, vsi->vsi_dbgfs_dir,
				  vsi, &nse_debugfs_sched_conf_vsi_q_pir_fops);
	(void)debugfs_create_file("sched_conf_vsi_cir", 0600, vsi->vsi_dbgfs_dir,
				  vsi, &nse_debugfs_sched_conf_vsi_cir_fops);
	(void)debugfs_create_file("sched_conf_vsi_q_cir", 0600, vsi->vsi_dbgfs_dir,
				  vsi, &nse_debugfs_sched_conf_vsi_q_cir_fops);

#if defined(NSE_DEBUG_EXT)
	INIT_WORK(&vsi->hack_send_magic_pkt_task, hack_send_magic_pkt_task_func);
	vsi->hack_send_magic_pkt_task_cancelling = 0;

	if (vsi->type == NSE_VSI_PF) {
		(void)debugfs_create_file("hack_send_magic_pkt", 0600, vsi->vsi_dbgfs_dir,
					  vsi, &nse_debugfs_vsi_hack_send_magic_pkt_fops);
	}

	if (vsi->type == NSE_VSI_PF) {
		(void)debugfs_create_file("vlan_rx_outer_strip", 0600, vsi->vsi_dbgfs_dir,
					  vsi, &nse_debugfs_vlan_rx_outer_strip_fops);

		if (nse_is_hw_static_fea_set(&vsi->back->hw, NSE_HW_STATIC_FEA_TDM_SUPPORT_PVID))
			(void)debugfs_create_file("vlan_pvid", 0600, vsi->vsi_dbgfs_dir,
						  vsi, &nse_debugfs_vlan_pvid_fops);
	}
#endif

	return;

fail:
	dev_err(nse_pf_to_dev(pf), "debugfs dir/file for VSI: %s failed\n", vsi_name);

	vsi->vsi_dbgfs_dir = NULL;
}

void nse_debugfs_vsi_exit(struct nse_vsi *vsi)
{
	debugfs_remove(vsi->vsi_netdev_symlink);

	debugfs_remove_recursive(vsi->vsi_dbgfs_dir);

	vsi->vsi_netdev_symlink = NULL;
	vsi->vsi_dbgfs_dir = NULL;
}

void nse_debugfs_vf_init(struct nse_vf *vf)
{
	struct nse_pf *pf = vf->pf;
	char vf_name[16];

	sprintf(vf_name, "vf-%d", vf->vf_id);

	if (!pf || !pf->pf_dbgfs_dir)
		goto fail;

	vf->vf_dbgfs_dir = debugfs_create_dir(vf_name, pf->pf_dbgfs_dir);
	if (IS_ERR(vf->vf_dbgfs_dir))
		goto fail;

	(void)debugfs_create_file("info", 0600, vf->vf_dbgfs_dir, vf, &nse_debugfs_vf_info_fops);
	(void)debugfs_create_file("vfr", 0600, vf->vf_dbgfs_dir, vf, &nse_debugfs_vf_vfr_fops);

	return;

fail:
	dev_err(nse_pf_to_dev(pf), "debugfs dir/file for VF: %s failed\n", vf_name);

	vf->vf_dbgfs_dir = NULL;
}

void nse_debugfs_vf_exit(struct nse_vf *vf)
{
	debugfs_remove_recursive(vf->vf_dbgfs_dir);

	vf->vf_dbgfs_dir = NULL;
}

/**
 * nse_debugfs_pf_init - setup the debugfs directory
 * @pf: the ice that is starting up
 */
void nse_debugfs_pf_init(struct nse_pf *pf)
{
	const char *name = pci_name(pf->pdev);
	struct nse_hw *hw = &pf->hw;

	if (!nse_debugfs_root)
		goto fail;

	pf->pf_dbgfs_dir = debugfs_create_dir(name, nse_debugfs_root);
	if (IS_ERR(pf->pf_dbgfs_dir))
		goto fail;

	(void)debugfs_create_file("params", 0600, pf->pf_dbgfs_dir,
				  pf, &nse_debugfs_pf_params_fops);

	(void)debugfs_create_file("bar0_read", 0600, pf->pf_dbgfs_dir,
				  pf, &nse_debugfs_bar0_read_fops);
	(void)debugfs_create_file("bar0_read_all", 0600, pf->pf_dbgfs_dir,
				  pf, &nse_debugfs_bar0_read_all_fops);
	(void)debugfs_create_file("bar0_write", 0600, pf->pf_dbgfs_dir,
				  pf, &nse_debugfs_bar0_write_fops);

	(void)debugfs_create_file("int_dyn_ctl", 0600, pf->pf_dbgfs_dir,
				  pf, &nse_debugfs_int_dyn_ctl_fops);

	(void)debugfs_create_file("reg_read", 0600, pf->pf_dbgfs_dir,
				  pf, &nse_debugfs_reg_read_fops);
	(void)debugfs_create_file("reg_write", 0600, pf->pf_dbgfs_dir,
				  pf, &nse_debugfs_reg_write_fops);

	(void)debugfs_create_file("aq_cmd", 0600, pf->pf_dbgfs_dir, pf, &nse_debugfs_aq_cmd_fops);
	(void)debugfs_create_file("ctlq_stats", 0600, pf->pf_dbgfs_dir,
				  pf, &nse_debugfs_ctlq_stats_fops);

	(void)debugfs_create_file("qos_db_dump_cfg", 0600, pf->pf_dbgfs_dir,
				  pf, &nse_debugfs_qos_db_dump_cfg_fops);
	(void)debugfs_create_file("qos_db_dump_stat_cnt", 0600, pf->pf_dbgfs_dir,
				  pf, &nse_debugfs_qos_db_dump_stat_cnt_fops);

	(void)debugfs_create_file("info_basic", 0600, pf->pf_dbgfs_dir,
				  pf, &nse_debugfs_info_basic_fops);
	(void)debugfs_create_file("info_resource", 0600, pf->pf_dbgfs_dir,
				  pf, &nse_debugfs_info_resource_fops);

	(void)debugfs_create_file("ptp_info", 0600, pf->pf_dbgfs_dir,
				  pf, &nse_debugfs_ptp_info_fops);
	(void)debugfs_create_file("ptp_cur_time", 0600, pf->pf_dbgfs_dir,
				  pf, &nse_debugfs_ptp_cur_time_fops);
	(void)debugfs_create_file("ptp_rx", 0600, pf->pf_dbgfs_dir, pf, &nse_debugfs_ptp_rx_fops);
	(void)debugfs_create_file("ptp_tx", 0600, pf->pf_dbgfs_dir, pf, &nse_debugfs_ptp_tx_fops);

	if (hw->port_info->lmac_phy_info.static_flags & LMAC_PHY_STATIC_FLAG_USE_TEST_PHY) {
		(void)debugfs_create_file("test_phy_startup", 0600, pf->pf_dbgfs_dir,
					  pf, &nse_debugfs_test_phy_startup_fops);
		(void)debugfs_create_file("test_phy_get_link_status", 0600, pf->pf_dbgfs_dir,
					  pf, &nse_debugfs_test_phy_get_link_status_fops);
		(void)debugfs_create_file("test_phy_set_loopback", 0600, pf->pf_dbgfs_dir,
					  pf, &nse_debugfs_test_phy_set_loopback_fops);
	}

	(void)debugfs_create_file("lmac_phy_update_info", 0600, pf->pf_dbgfs_dir,
				  pf, &nse_debugfs_lmac_phy_update_link_info_fops);

	(void)debugfs_create_file("oicr_ena", 0600, pf->pf_dbgfs_dir,
				  pf, &nse_debugfs_oicr_ena_fops);

	(void)debugfs_create_file("stats_lmac", 0600, pf->pf_dbgfs_dir,
				  pf, &nse_debugfs_stats_lmac_fops);
	(void)debugfs_create_file("stats_lan_channel", 0600, pf->pf_dbgfs_dir,
				  pf, &nse_debugfs_stats_lan_channel_fops);
	(void)debugfs_create_file("stats_pf", 0600, pf->pf_dbgfs_dir,
				  pf, &nse_debugfs_stats_pf_fops);

	(void)debugfs_create_file("psr_set_ctrl", 0600, pf->pf_dbgfs_dir,
				  pf, &nse_debugfs_psr_set_ctrl_fops);

	if (nse_is_hw_static_fea_set(hw, NSE_HW_STATIC_FEA_SWITCH_FLEX)) {
		(void)debugfs_create_file("sw_aq", 0600, pf->pf_dbgfs_dir,
					  pf, &nse_debugfs_sw_aq_fops);
		(void)debugfs_create_file("sw_fltr", 0600, pf->pf_dbgfs_dir,
					  pf, &nse_debugfs_sw_fltr_fops);
		(void)debugfs_create_file("sw_ovs", 0600, pf->pf_dbgfs_dir,
					  pf, &nse_debugfs_sw_ovs_fops);
		(void)debugfs_create_file("sw_lpm", 0600, pf->pf_dbgfs_dir,
					  pf, &nse_debugfs_sw_lpm_fops);
		(void)debugfs_create_file("acl_fltr", 0600, pf->pf_dbgfs_dir,
					  pf, &nse_debugfs_acl_fltr_fops);
		(void)debugfs_create_file("bypass_switch_rpp", 0600, pf->pf_dbgfs_dir,
					  pf, &nse_debugfs_sw_bypass_rpp_fops);
	}

	if (nse_is_hw_static_fea_set(hw, NSE_HW_STATIC_FEA_MISC_SUPPORT_HW_LAG))
		(void)debugfs_create_file("hw_lag", 0600, pf->pf_dbgfs_dir,
					  pf, &nse_debugfs_hw_lag_fops);

	(void)debugfs_create_file("sched_dump_layers_info", 0600, pf->pf_dbgfs_dir,
				  pf, &nse_debugfs_sched_dump_layers_info_fops);
	(void)debugfs_create_file("sched_dump_subtree", 0600, pf->pf_dbgfs_dir,
				  pf, &nse_debugfs_sched_dump_subtree_fops);
	(void)debugfs_create_file("sched_dump_node", 0600, pf->pf_dbgfs_dir,
				  pf, &nse_debugfs_sched_dump_node_fops);

	(void)debugfs_create_file("sched_conf_node_pir", 0600, pf->pf_dbgfs_dir,
				  pf, &nse_debugfs_sched_conf_node_pir_fops);
	(void)debugfs_create_file("sched_conf_node_cir", 0600, pf->pf_dbgfs_dir,
				  pf, &nse_debugfs_sched_conf_node_cir_fops);

	if (pf->sw_conf.fdir_ena) {
		(void)debugfs_create_file("fdir_dump_info", 0600, pf->pf_dbgfs_dir,
					  pf, &nse_debugfs_fdir_dump_info_fops);
		(void)debugfs_create_file("fdir_dump_filter", 0600, pf->pf_dbgfs_dir,
					  pf, &nse_debugfs_fdir_dump_filter_fops);
	}

#if defined(NSE_DEBUG_EXT)
	(void)debugfs_create_file("lan_ena_dis_rxq_txq_many", 0600, pf->pf_dbgfs_dir,
				  pf, &nse_debugfs_lan_ena_dis_rxq_txq_many);
	(void)debugfs_create_file("lan_get_status_rxq_txq_many", 0600, pf->pf_dbgfs_dir,
				  pf, &nse_debugfs_lan_get_status_rxq_txq_many);
	(void)debugfs_create_file("lan_get_ctx_rxq_txq_many", 0600, pf->pf_dbgfs_dir,
				  pf, &nse_debugfs_lan_get_ctx_rxq_txq_many);
#endif

#if defined(NSE_DEBUG_EXT)
	if (nse_lan_debug_hw_qstat)
		(void)debugfs_create_file("lan_hw_qstat", 0600, pf->pf_dbgfs_dir,
					  pf, &nse_debugfs_lan_hw_qstat_fops);
#endif

	if (nse_is_hw_static_fea_set(hw, NSE_HW_STATIC_FEA_TDM_SUPPORT_UP_ENFORCE))
		(void)debugfs_create_file("up_enforce", 0600, pf->pf_dbgfs_dir,
					  pf, &nse_debugfs_up_enforce_fops);

	(void)debugfs_create_file("reset", 0600, pf->pf_dbgfs_dir, pf, &nse_debugfs_reset_fops);

	(void)debugfs_create_file("check_temp_test", 0600, pf->pf_dbgfs_dir,
				  pf, &nse_debugfs_check_temp_test_fops);

	(void)debugfs_create_file("ephy_info", 0600, pf->pf_dbgfs_dir, pf,
				  &nse_debugfs_ephy_info_fops);

	nse_msgbox_debugfs_init(pf);

	return;

fail:
	dev_err(nse_pf_to_dev(pf), "debugfs dir/file for %s failed\n", name);

	pf->pf_dbgfs_dir = NULL;
}

/**
 * nse_debugfs_pf_exit - clear out the ices debugfs entries
 * @pf: the ice that is stopping
 */
void nse_debugfs_pf_exit(struct nse_pf *pf)
{
	debugfs_remove_recursive(pf->pf_dbgfs_dir);

	pf->pf_dbgfs_dir = NULL;
}

/**
 * nse_debugfs_init - create root directory for debugfs entries
 */
void nse_debugfs_init(void)
{
	nse_debugfs_root = debugfs_create_dir(KBUILD_MODNAME, NULL);
	if (IS_ERR(nse_debugfs_root)) {
		pr_info("init of debugfs failed\n");
		nse_debugfs_root = NULL;
	}
}

/**
 * nse_debugfs_exit - remove debugfs entries
 */
void nse_debugfs_exit(void)
{
	debugfs_remove_recursive(nse_debugfs_root);

	nse_debugfs_root = NULL;
}

