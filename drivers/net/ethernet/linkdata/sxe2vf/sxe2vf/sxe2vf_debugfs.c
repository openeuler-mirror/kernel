// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2vf_debugfs.c
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#include <linux/debugfs.h>
#include <linux/cpu_rmap.h>
#include <linux/cpumask.h>
#include <linux/atomic.h>

#include "sxe2_version.h"
#include "sxe2vf.h"
#include "sxe2_log.h"
#include "sxe2vf_debugfs.h"
#include "sxe2_com_cdev.h"

static struct dentry *sxe2vf_debugfs_root;
#ifdef SXE2_CFG_DEBUG
extern int g_vf_switch_stats;
#endif

static char *g_sxe2vf_com_mode_to_str[] = {
		[SXE2_COM_MODULE_KERNEL] = SXE2_COM_KERNEL_MODE_NAME,
		[SXE2_COM_MODULE_DPDK] = SXE2_COM_DPDK_MODE_NAME,
		[SXE2_COM_MODULE_RDMA] = SXE2_COM_RDMA_MODE_NAME,
		[SXE2_COM_MODULE_MIXED] = SXE2_COM_MIXED_MODE_NAME,
		[SXE2_COM_MODULE_UNDEFINED] = SXE2_COM_UNDEFINED_MODE_NAME,
};

void sxe2vf_info_dump(struct sxe2vf_adapter *adapter)
{
	LOG_DEV_INFO("\t info dump start.\n");

	LOG_DEV_INFO("\t adapter=%p\n", adapter);
	LOG_DEV_INFO("\t adapter.dev_name=%s\n", adapter->dev_name);
	LOG_DEV_INFO("\t adapter.pdev=%p\n", adapter->pdev);
	LOG_DEV_INFO("\t adapter.netdev=%p\n", adapter->netdev);
	LOG_DEV_INFO("\t adapter mode:%d\n", sxe2vf_com_mode_get(adapter));

	LOG_DEV_INFO("\t adapter.irq_ctxt.max_cnt=%d\n", adapter->irq_ctxt.max_cnt);
	LOG_DEV_INFO("\t adapter.irq_ctxt.event_irq_cnt=%d\n",
		     SXE2VF_EVENT_MSIX_CNT);
	LOG_DEV_INFO("\t adapter.irq_ctxt.event_offset=%d\n", 0);
	LOG_DEV_INFO("\t adapter.irq_ctxt.eth_irq_cnt=%d\n",
		     adapter->irq_ctxt.eth_irq_cnt);
	LOG_DEV_INFO("\t adapter.irq_ctxt.eth_offset=%d\n",
		     adapter->irq_ctxt.eth_offset);
	LOG_DEV_INFO("\t adapter.irq_ctxt.dpdk_irq_cnt=%d\n",
		     adapter->irq_ctxt.dpdk_irq_cnt);
	LOG_DEV_INFO("\t adapter.irq_ctxt.dpdk_offset=%d\n",
		     adapter->irq_ctxt.dpdk_offset);
	LOG_DEV_INFO("\t adapter.irq_ctxt.rdma_irq_cnt=%d\n",
		     adapter->irq_ctxt.rdma_irq_cnt);
	LOG_DEV_INFO("\t adapter.irq_ctxt.rdma_offset=%d\n",
		     adapter->irq_ctxt.rdma_offset);
	LOG_DEV_INFO("\t adapter.irq_ctxt.msix_cnt=%d\n",
		     adapter->irq_ctxt.msix_cnt);

	LOG_DEV_INFO("\t adapter.q_ctxt.max_cnt=%d\n", adapter->q_ctxt.max_cnt);
	LOG_DEV_INFO("\t adapter.q_ctxt.q_cnt_req=%d\n", adapter->q_ctxt.q_cnt_req);
	LOG_DEV_INFO("\t adapter.q_ctxt.eth_q_cnt=%d\n", adapter->q_ctxt.eth_q_cnt);
	LOG_DEV_INFO("\t adapter.q_ctxt.eth_offset=%d\n",
		     adapter->q_ctxt.eth_offset);
	LOG_DEV_INFO("\t adapter.q_ctxt.dpdk_q_cnt=%d\n",
		     adapter->q_ctxt.dpdk_q_cnt);
	LOG_DEV_INFO("\t adapter.q_ctxt.dpdk_offset=%d\n",
		     adapter->q_ctxt.dpdk_offset);

	LOG_DEV_INFO("\t adapter.vsi_ctxt.vsi_cnt_max=%d\n",
		     adapter->vsi_ctxt.vsi_cnt_max);
	LOG_DEV_INFO("\t adapter.vsi_ctxt.vsi_ids[0]=%d\n",
		     adapter->vsi_ctxt.vsi_ids[0]);
	LOG_DEV_INFO("\t adapter.vsi_ctxt.vsi_ids[1]=%d\n",
		     adapter->vsi_ctxt.vsi_ids[1]);

	LOG_DEV_INFO("\t adapter.work_ctxt.dev_state=%d\n",
		     adapter->work_ctxt.dev_state);
	LOG_DEV_INFO("\t adapter.work_ctxt.failed_cnt=%d\n",
		     adapter->work_ctxt.failed_cnt);
	LOG_DEV_INFO("\t adapter.work_ctxt.is_send=%d\n",
		     adapter->work_ctxt.is_send);

	LOG_DEV_INFO("\t adapter.link_ctxt.link_up=%d\n",
		     adapter->link_ctxt.link_up);
	LOG_DEV_INFO("\t adapter.link_ctxt.speed=%d\n", adapter->link_ctxt.speed);

	LOG_DEV_INFO("\t adapter.aux_ctxt.num_msix=%d\n",
		     adapter->aux_ctxt.num_msix);
	LOG_DEV_INFO("\t adapter.aux_ctxt.aux_idx=%d\n", adapter->aux_ctxt.aux_idx);
	LOG_DEV_INFO("\t adapter.aux_ctxt.init=%d\n", adapter->aux_ctxt.init);
	LOG_DEV_INFO("\t adapter.dev_ctxt.remove=%d\n", adapter->dev_ctxt.remove);

	LOG_DEV_INFO("\t info dump end.\n");
}

void sxe2vf_vsi_dump(struct sxe2vf_adapter *adapter)
{
	u16 i;

	struct sxe2vf_vsi *vsi = adapter->vsi_ctxt.vf_vsi;
	struct netdev_queue *ntxq = NULL;

	if (!vsi) {
		LOG_DEV_INFO("\t mode:%d, eth vsi null\n",
			     sxe2vf_com_mode_get(adapter));
		return;
	}
	LOG_DEV_INFO("\t vsi dump start.\n");

	LOG_DEV_INFO("\t vsi=%p\n", vsi);
	LOG_DEV_INFO("\t ----vsi[%d]----\n", vsi->vsi_id);
	LOG_DEV_INFO("\t vsi->vsi_type=%d\n", vsi->vsi_type);

	LOG_DEV_INFO("\t vsi->irqs.cnt=%d\n", vsi->irqs.cnt);
	mutex_lock(&adapter->vsi_ctxt.lock);
	sxe2vf_for_each_vsi_irq(vsi, i)
	{
		LOG_DEV_INFO("\t ----vsi irq_data[%d]----\n",
			     vsi->irqs.irq_data[i]->irq_idx);
		LOG_DEV_INFO("\t\t irq_data[%d]->name=%s\n", i,
			     vsi->irqs.irq_data[i]->name);
		LOG_DEV_INFO("\t\t irq_data[%d]->q_cnt=%d\n", i,
			     vsi->irqs.irq_data[i]->q_cnt);
		LOG_DEV_INFO("\t\t irq_data[%d]->rate_limit=%d\n", i,
			     vsi->irqs.irq_data[i]->rate_limit);
		LOG_DEV_INFO("\t\t irq_data[%d]->multiple_polling=%d\n", i,
			     vsi->irqs.irq_data[i]->multiple_polling);
		LOG_DEV_INFO("\t\t irq_data[%d]->q_bitmap=%d\n", i,
			     vsi->irqs.irq_data[i]->q_bitmap);
		LOG_DEV_INFO("\t\t irq_data[%d]->tx.itr_mode=%d\n", i,
			     vsi->irqs.irq_data[i]->tx.itr_mode);
		LOG_DEV_INFO("\t\t irq_data[%d]->tx.itr_idx=%d\n", i,
			     vsi->irqs.irq_data[i]->tx.itr_idx);
		LOG_DEV_INFO("\t\t irq_data[%d]->tx.itr_setting=%d\n", i,
			     vsi->irqs.irq_data[i]->tx.itr_setting);
		LOG_DEV_INFO("\t\t irq_data[%d]->rx.itr_mode=%d\n", i,
			     vsi->irqs.irq_data[i]->rx.itr_mode);
		LOG_DEV_INFO("\t\t irq_data[%d]->rx.itr_idx=%d\n", i,
			     vsi->irqs.irq_data[i]->rx.itr_idx);
		LOG_DEV_INFO("\t\t irq_data[%d]->rx.itr_setting=%d\n", i,
			     vsi->irqs.irq_data[i]->rx.itr_setting);
	}

	LOG_DEV_INFO("\t vsi->txqs.q_cnt=%d\n", vsi->txqs.q_cnt);
	LOG_DEV_INFO("\t vsi->txqs.depth=%d\n", vsi->txqs.depth);
	sxe2vf_for_each_vsi_txq(vsi, i)
	{
		LOG_DEV_INFO("\t ----vsi txq[%d]----\n", vsi->txqs.q[i]->idx_in_vsi);
		LOG_DEV_INFO("\t\t txq[%d]->depth=%d\n", i, vsi->txqs.q[i]->depth);
		LOG_DEV_INFO("\t\t txq[%d]->next_to_use=%d\n", i,
			     vsi->txqs.q[i]->next_to_use);
		LOG_DEV_INFO("\t\t txq[%d]->next_to_clean=%d\n", i,
			     vsi->txqs.q[i]->next_to_clean);
		if (vsi->txqs.q[i]->netdev) {
			ntxq = netdev_get_tx_queue(vsi->txqs.q[i]->netdev,
						   vsi->txqs.q[i]->idx_in_vsi);
			if (ntxq)
				LOG_DEV_INFO("txq[%d] netdev st=%lu \t"
					     "(BIT: 0 - DRV_XOFF; 1 - STACK_XOFF; \t"
					     "2- FROZEN)\n",
					     i, ntxq->state);
		}
	}

	LOG_DEV_INFO("\t vsi->rxqs.q_cnt=%d\n", vsi->rxqs.q_cnt);
	LOG_DEV_INFO("\t vsi->rxqs.depth=%d\n", vsi->rxqs.depth);
	sxe2vf_for_each_vsi_rxq(vsi, i)
	{
		LOG_DEV_INFO("\t ----vsi rxq[%d]----\n", vsi->rxqs.q[i]->idx_in_vsi);
		LOG_DEV_INFO("\t\t rxq[%d]->depth=%d\n", i, vsi->rxqs.q[i]->depth);
		LOG_DEV_INFO("\t\t rxq[%d]->next_to_use=%d\n", i,
			     vsi->rxqs.q[i]->next_to_use);
		LOG_DEV_INFO("\t\t rxq[%d]->next_to_clean=%d\n", i,
			     vsi->rxqs.q[i]->next_to_clean);
	}
	mutex_unlock(&adapter->vsi_ctxt.lock);
	LOG_DEV_INFO("\t vsi dump end.\n");
}

STATIC void sxe2vf_com_info(struct sxe2vf_adapter *adapter)
{
	sxe2_com_info_print(&adapter->com_ctxt);
}

#ifdef SXE2_CFG_DEBUG
static void sxe2vf_monitor_stats_open(struct sxe2vf_adapter *adapter)
{
	g_vf_switch_stats = 1;
}

static void sxe2vf_monitor_stats_close(struct sxe2vf_adapter *adapter)
{
	g_vf_switch_stats = 0;
}
#endif

static struct sxe2vf_debugfs_command command[] = {
		{"info dump", sxe2vf_info_dump},
		{"vsi dump", sxe2vf_vsi_dump},
#ifdef SXE2_CFG_DEBUG
		{"stats open", sxe2vf_monitor_stats_open},
		{"stats close", sxe2vf_monitor_stats_close},
#endif
		{"com info", sxe2vf_com_info},
		{"", NULL},
};

static s32 sxe2vf_debugfs_command_match(struct sxe2vf_adapter *adapter, s8 *cmd_buf,
					size_t size)
{
	u32 i;

	for (i = 0; strlen(command[i].string) != 0; i++) {
		if (!strcmp(cmd_buf, command[i].string)) {
			command[i].debugfs_cb(adapter);
			goto l_end;
		}
	}

	return -EINVAL;

l_end:
	return 0;
}

static void sxe2vf_debugfs_command_help_info(struct sxe2vf_adapter *adapter)
{
	u32 i;

	LOG_DEV_INFO("available commands:\n");

	for (i = 0; strlen(command[i].string) != 0; i++)
		LOG_DEV_INFO("\t %s\n", command[i].string);
}

STATIC ssize_t sxe2vf_debugfs_command_write(struct file *file,
					    const char __user *buf, size_t count,
					    loff_t *ppos)
{
	ssize_t ret;
	s8 *cmd_buf, *cmd_buf_tmp;
	struct sxe2vf_adapter *adapter = file->private_data;

	if (*ppos != 0) {
		LOG_DEV_ERR(" don't allow partial writes\n, *ppos!=NULL");
		return -EINVAL;
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
	ret = (ssize_t)count;

	if (sxe2vf_debugfs_command_match(adapter, cmd_buf, count)) {
		LOG_DEV_INFO("unknown or invalid command '%s'\n", cmd_buf);
		sxe2vf_debugfs_command_help_info(adapter);
		ret = -EINVAL;
	}

	kfree(cmd_buf);
	return ret;
}

static const struct file_operations sxe2vf_debugfs_command_fops = {
		.owner = THIS_MODULE,
		.open = simple_open,
		.write = sxe2vf_debugfs_command_write,
};

void sxe2vf_debugfs_create_common_file(struct sxe2vf_adapter *adapter)
{
#if defined(CONFIG_DEBUG_FS) || defined(PCLINT)
	if (IS_ERR(debugfs_create_file("command", 0600, adapter->sxe2vf_debugfs_vf,
				       adapter, &sxe2vf_debugfs_command_fops))) {
		LOG_DEV_ERR("debugfs file create failed\n");
	}

	return;
#endif
}

static char *sxe2vf_com_mode_to_str(enum sxe2_com_module com_mode)
{
	if (com_mode >= ARRAY_SIZE(g_sxe2vf_com_mode_to_str))
		return "unknown";

	return g_sxe2vf_com_mode_to_str[com_mode];
}

STATIC bool sxe2vf_drv_mode_check(char *cmd_buf)
{
	if ((!strcmp(cmd_buf, SXE2_COM_KERNEL_MODE_NAME)) ||
	    (!strcmp(cmd_buf, SXE2_COM_MIXED_MODE_NAME)) ||
	    (!strcmp(cmd_buf, SXE2_COM_DPDK_MODE_NAME)) ||
	    (!strcmp(cmd_buf, SXE2_COM_UNDEFINED_MODE_NAME)))
		return true;

	return false;
}

static s32 sxe2vf_com_str_to_mode(char *cmd_buf, enum sxe2_com_module *new_mode)
{
	s32 ret;
	u32 i;

	for (i = 0; i < SXE2_COM_MODULE_INVAL; i++) {
		if (!strcmp(cmd_buf, g_sxe2vf_com_mode_to_str[i])) {
			*new_mode = (enum sxe2_com_module)i;
			ret = 0;
			goto end;
		}
	}

	ret = -EINVAL;

end:
	return ret;
}

STATIC s32 sxe2vf_debugfs_drv_mode_set(struct sxe2vf_adapter *adapter, char *cmd_buf)
{
	s32 ret = 0;
	enum sxe2_com_module new_mode = SXE2_COM_MODULE_INVAL;

	if (sxe2vf_drv_mode_check(cmd_buf)) {
		ret = sxe2vf_com_str_to_mode(cmd_buf, &new_mode);
		if (ret) {
			LOG_ERROR_BDF("drv mode buf error.\n");
			goto end;
		}

		ret = sxe2vf_drv_mode_set(adapter, new_mode);
		if (ret) {
			LOG_ERROR_BDF("drv mode configurate failed.\n");
			goto end;
		}

		LOG_DEV_INFO("current mode:%s configured mode:%s\n",
			     g_sxe2vf_com_mode_to_str[adapter->drv_mode],
			     g_sxe2vf_com_mode_to_str[new_mode]);
	} else {
		LOG_DEV_INFO("unknown or invalid command '%s'\n", cmd_buf);
		LOG_DEV_INFO("supported commands: %s、%s、%s.\n",
			     SXE2_COM_KERNEL_MODE_NAME, SXE2_COM_MIXED_MODE_NAME,
			     SXE2_COM_DPDK_MODE_NAME);
		ret = -EINVAL;
	}

end:
	return ret;
}

STATIC ssize_t sxe2vf_debugfs_drv_mode_read(struct file *file, char __user *buf,
					    size_t count, loff_t *ppos)
{
	struct sxe2vf_adapter *adapter = file->private_data;
	struct sxe2_vf_drv_mode_resp vf_resp = {0};
	char tmp_buf[SXE2_COM_MODE_NAME_SIZE];
	ssize_t len = 0;
	s32 ret = 0;

	len = snprintf(tmp_buf, SXE2_COM_MODE_NAME_SIZE, "current mode:%s\n",
		       sxe2vf_com_mode_to_str(adapter->drv_mode));
	ret = __sxe2vf_drv_mode_get(adapter, &vf_resp, sizeof(vf_resp),
				    SXE2VF_MSG_RESP_WAIT_NOTIFY);
	len += snprintf(tmp_buf + len, SXE2_COM_MODE_NAME_SIZE - len,
			"configured mode:%s\n",
			ret ? "get failed"
			    : sxe2vf_com_mode_to_str(vf_resp.drv_mode));

	return simple_read_from_buffer(buf, count, ppos, &tmp_buf, len);
}

STATIC ssize_t sxe2vf_debugfs_drv_mode_write(struct file *file,
					     const char __user *buf, size_t count,
					     loff_t *ppos)
{
	ssize_t ret, tmp_ret;
	s8 *cmd_buf, *cmd_buf_tmp;
	struct sxe2vf_adapter *adapter = file->private_data;

	if (*ppos != 0) {
		LOG_DEV_ERR("dont't allow partial writes.\n, *ppos!=NULL");
		return -EINVAL;
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

	ret = (ssize_t)count;

	tmp_ret = sxe2vf_debugfs_drv_mode_set(adapter, cmd_buf);
	if (tmp_ret)
		ret = tmp_ret;

	kfree(cmd_buf);
	return ret;
}

static const struct file_operations sxe2vf_debugfs_drv_mode_fops = {
		.owner = THIS_MODULE,
		.open = simple_open,
		.read = sxe2vf_debugfs_drv_mode_read,
		.write = sxe2vf_debugfs_drv_mode_write,
};

void sxe2vf_debugfs_create_drv_mode_file(struct sxe2vf_adapter *adapter)
{
#if defined(CONFIG_DEBUG_FS) || defined(PCLINT)
	if (IS_ERR(debugfs_create_file("drv_mode", 0600, adapter->sxe2vf_debugfs_vf,
				       adapter, &sxe2vf_debugfs_drv_mode_fops))) {
		LOG_DEV_ERR("debugfs file create failed\n");
	}

	return;
#endif
}

void sxe2vf_debugfs_vf_init(struct sxe2vf_adapter *adapter)
{
#if defined(CONFIG_DEBUG_FS) || defined(PCLINT)
	const char *name = pci_name(adapter->pdev);

	adapter->sxe2vf_debugfs_vf = debugfs_create_dir(name, sxe2vf_debugfs_root);
	if (IS_ERR(adapter->sxe2vf_debugfs_vf)) {
		LOG_ERROR("init of vf debugfs failed\n");
		goto l_end;
	}

	sxe2vf_debugfs_create_common_file(adapter);
	sxe2vf_debugfs_create_drv_mode_file(adapter);

l_end:
	return;

#endif
}

void sxe2vf_debugfs_vf_exit(struct sxe2vf_adapter *adapter)
{
#if defined(CONFIG_DEBUG_FS) || defined(PCLINT)
	debugfs_remove_recursive(adapter->sxe2vf_debugfs_vf);
	adapter->sxe2vf_debugfs_vf = NULL;
#endif
}

void sxe2vf_debugfs_init(void)
{
	sxe2vf_debugfs_root = debugfs_create_dir(SXE2VF_DRV_NAME, NULL);
	if (IS_ERR(sxe2vf_debugfs_root))
		LOG_ERROR_D("init of debugfs failed\n");
}

void sxe2vf_debugfs_exit(void)
{
	debugfs_remove_recursive(sxe2vf_debugfs_root);
	sxe2vf_debugfs_root = NULL;
}
