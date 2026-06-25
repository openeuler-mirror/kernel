// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (C), 2020, sxe2rdma Technologies Co., Ltd.
 *
 * @file: sxe2_drv_common_debugfs.c
 * @author: sxe2rdma
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#include <linux/debugfs.h>
#include "sxe2_compat.h"
#ifdef NOT_SUPPORT_AUXILIARY_BUS
#include "auxiliary_bus.h"
#else
#include <linux/auxiliary_bus.h>
#endif
#include "sxe2_drv_rdma_log.h"
#include "sxe2_drv_rdma_debugfs.h"
#include "sxe2_drv_common_debugfs.h"
#include "sxe2_drv_aux.h"

#ifndef ether_addr_copy
#define ether_addr_copy(mac_addr, new_mac_addr)                                \
	memcpy(mac_addr, new_mac_addr, ETH_ALEN)
#endif

#ifdef SXE2_CFG_DEBUG
static ssize_t drv_rdma_common_reset_en_write(struct file *filp,
					      const char __user *buf,
					      size_t count, loff_t *off)
{
	ssize_t ret					    = SXE2_OK;
	char cmd[COMMON_RESET_EN_DEBUGFS_WRITE_BUF_MAX_LEN] = { 0 };
	struct sxe2_rdma_device *rdma_dev;
	u32 input_val;

	if (*off != 0)
		goto end;

	if (count >= COMMON_RESET_EN_DEBUGFS_WRITE_BUF_MAX_LEN) {
		ret = -ENOSPC;
		goto end;
	}

	rdma_dev = (struct sxe2_rdma_device *)filp->private_data;
	if (!rdma_dev) {
		ret = -ENXIO;
		goto end;
	}

	if (copy_from_user(cmd, buf, count)) {
		ret = -EFAULT;
		DRV_RDMA_LOG_DEV_ERR(
			"common debugfs:Cmd copy from user failed err\n");
		goto end;
	}
	ret = sscanf(cmd, "%u", &input_val);
	if (ret != 1) {
		ret = -ENODATA;
		DRV_RDMA_LOG_DEV_ERR(
			"common debugfs:analyze cmd err please input enable:1 disable:0\n");
		goto end;
	}

	if (input_val) {
		if (!rdma_dev->rdma_func->reset) {
			rdma_dev->rdma_func->reset = true;
			rdma_dev->rdma_func->gen_ops.request_reset(
				rdma_dev->rdma_func);
			DRV_RDMA_LOG_DEV_DEBUG("common debugfs:start reset\n");
		} else {
			DRV_RDMA_LOG_DEV_DEBUG(
				"common debugfs:already reset\n");
		}
	} else {
		DRV_RDMA_LOG_DEV_DEBUG(
			"common debugfs:input 1 reset function\n");
	}

	ret  = (ssize_t)count;
	*off = (loff_t)count;

end:
	return ret;
}

static ssize_t drv_rdma_common_reset_en_read(struct file *filp,
					     char __user *buf, size_t count,
					     loff_t *off)
{
	ssize_t ret	 = SXE2_OK;
	size_t len_total = 0;
	char *rsp	 = NULL;
	char *rsp_end;
	struct sxe2_rdma_device *rdma_dev;

	if (*off != 0)
		goto end;

	rdma_dev = (struct sxe2_rdma_device *)filp->private_data;
	if (!rdma_dev) {
		ret = -ENXIO;
		goto end;
	}

	rsp = kzalloc(sizeof(char) * SXE2_DEBUG_DUMP_BUF_SIZE, GFP_KERNEL);
	if (!rsp) {
		ret = -ENOMEM;
		DRV_RDMA_LOG_DEV_ERR(
			"common debugfs:rcms info rsp kmalloc failed err\n");
		goto end;
	}
	rsp_end = rsp;

	if (rdma_dev->rdma_func->reset)
		len_total += dbg_vsnprintf(rsp_end, len_total, "ready reset\n");
	else
		len_total +=
			dbg_vsnprintf(rsp_end, len_total, "not ready reset\n");

	ret = simple_read_from_buffer(buf, count, off, rsp, len_total);
	if (ret < 0)
		DRV_RDMA_LOG_DEV_ERR("common debugfs:simple read error %zu\n",
				     ret);

	kfree(rsp);
	rsp = NULL;

end:
	return ret;
}

static const struct file_operations sxe2_rdma_common_reset_en_fops = {
	.owner = THIS_MODULE,
	.open  = simple_open,
	.read  = drv_rdma_common_reset_en_read,
	.write = drv_rdma_common_reset_en_write,
};

static ssize_t drv_rdma_common_reset_info_read(struct file *filp,
					       char __user *buf, size_t count,
					       loff_t *off)
{
	ssize_t ret	 = SXE2_OK;
	size_t len_total = 0;
	char *rsp	 = NULL;
	char *rsp_end;
	int i;
	u32 reset_cnt;
	struct sxe2_rdma_device *rdma_dev;
	struct sxe2_reset_debug_func_info *reset_func_info;

	if (*off != 0)
		goto end;

	rdma_dev = (struct sxe2_rdma_device *)filp->private_data;
	if (!rdma_dev) {
		ret = -ENXIO;
		goto end;
	}

	reset_func_info = rdma_dev->reset_func_info;
	if (!reset_func_info) {
		ret = -EINVAL;
		DRV_RDMA_LOG_DEV_ERR(
			"common debugfs:reset func info ptr is null\n");
		goto end;
	}

	mutex_lock(&g_reset_debug.reset_debug_mutex);
	if (reset_func_info->reset_info_idx >= MAX_RESET_INFO_CNT) {
		ret = -EINVAL;
		DRV_RDMA_LOG_DEV_ERR(
			"common debugfs:reset info idx err idx=%u\n",
			reset_func_info->reset_info_idx);
		mutex_unlock(&g_reset_debug.reset_debug_mutex);
		goto end;
	}
	DRV_RDMA_LOG_DEV_DEBUG(
		"common debugfs:reset cnt=%u reset info idx=%i\n",
		reset_func_info->reset_cnt, reset_func_info->reset_info_idx);

	rsp = kzalloc(sizeof(char) * SXE2_DEBUG_DUMP_BUF_SIZE, GFP_KERNEL);
	if (!rsp) {
		ret = -ENOMEM;
		DRV_RDMA_LOG_DEV_ERR(
			"common debugfs:rcms info rsp kmalloc failed err\n");
		mutex_unlock(&g_reset_debug.reset_debug_mutex);
		goto end;
	}
	rsp_end = rsp;
	len_total += dbg_vsnprintf(rsp_end, len_total, "reset info:\n");
	len_total += dbg_vsnprintf(rsp_end, len_total, "bdf:%s\n",
				   reset_func_info->bdf);
	len_total += dbg_vsnprintf(rsp_end, len_total, "reset cnt=%u\n",
				   reset_func_info->reset_cnt);

	if (!reset_func_info->reset_cnt) {
		mutex_unlock(&g_reset_debug.reset_debug_mutex);
		goto show_to_buf;
	}
	reset_cnt = reset_func_info->reset_cnt;
	if (reset_func_info->reset_info_idx > 0) {
		for (i = reset_func_info->reset_info_idx - 1; i >= 0; i--) {
			len_total += dbg_vsnprintf(
				rsp_end, len_total,
				"reset %u  entry type: %s    time: %s\n",
				reset_cnt,
				reset_func_info->reset_info[i].reset_type ==
						FUNC_REQUEST_RESET ?
					"request reset" :
					"warning reset",
				reset_func_info->reset_info[i].time);
			reset_cnt--;
		}
	}

	if (reset_func_info->reset_cnt >= MAX_RESET_INFO_CNT) {
		for (i = MAX_RESET_INFO_CNT - 1;
		     i >= reset_func_info->reset_info_idx; i--) {
			len_total += dbg_vsnprintf(
				rsp_end, len_total,
				"reset %u  entry type: %s    time: %s\n",
				reset_cnt,
				reset_func_info->reset_info[i].reset_type ==
						FUNC_REQUEST_RESET ?
					"request reset" :
					"warning reset",
				reset_func_info->reset_info[i].time);
			reset_cnt--;
		}
	}
	mutex_unlock(&g_reset_debug.reset_debug_mutex);
show_to_buf:
	ret = simple_read_from_buffer(buf, count, off, rsp, len_total);
	if (ret < 0)
		DRV_RDMA_LOG_DEV_ERR("common debugfs:simple read error %zu\n",
				     ret);

	kfree(rsp);
	rsp = NULL;
end:
	return ret;
}

static const struct file_operations sxe2_rdma_common_reset_info_fops = {
	.owner = THIS_MODULE,
	.open  = simple_open,
	.read  = drv_rdma_common_reset_info_read,
};
#endif

static ssize_t drv_rdma_common_dump_pcap_en_write(struct file *filp,
						  const char __user *buf,
						  size_t count, loff_t *off)
{
	ssize_t ret						= SXE2_OK;
	char cmd[COMMON_DUMP_PCAP_EN_DEBUGFS_WRITE_BUF_MAX_LEN] = { 0 };
	struct sxe2_rdma_device *rdma_dev;
	u32 input_val;
	struct aux_core_dev_info *cdev_info;
	u8 mac_addr[ETH_ALEN];

	if (*off != 0)
		goto end;

	if (count >= COMMON_DUMP_PCAP_EN_DEBUGFS_WRITE_BUF_MAX_LEN) {
		ret = -ENOSPC;
		DRV_RDMA_LOG_ERROR(
			"common debugfs:cmd exceeded length limit err\n");
		goto end;
	}

	rdma_dev = (struct sxe2_rdma_device *)filp->private_data;
	if (!rdma_dev) {
		ret = -ENXIO;
		DRV_RDMA_LOG_ERROR("common debugfs:dev find failed err\n");
		goto end;
	}
	cdev_info = rdma_dev->rdma_func->cdev;

	if (copy_from_user(cmd, buf, count)) {
		ret = -EFAULT;
		DRV_RDMA_LOG_ERROR_BDF(
			"common debugfs:Cmd copy from user failed err\n");
		goto end;
	}
	ret = sscanf(cmd, "%u", &input_val);
	if (ret != 1) {
		ret = -ENODATA;
		DRV_RDMA_LOG_ERROR_BDF(
			"common debugfs:analyze cmd err please input enable:1 disable:0\n");
		goto end;
	}

	ether_addr_copy(mac_addr, rdma_dev->netdev->dev_addr);
	if (cdev_info == NULL) {
		DRV_RDMA_LOG_ERROR("common debugfs:cdev_info is NULL\n");
		goto end;
	}
	if (cdev_info->ops == NULL) {
		DRV_RDMA_LOG_ERROR("common debugfs:cdev_info->ops is NULL\n");
		goto end;
	}
	if (cdev_info->ops->dump_pcap_cmd == NULL) {
		DRV_RDMA_LOG_ERROR(
			"common debugfs:cdev_info->ops->dump_pcap_cmd is NULL\n");
		goto end;
	}
	if (input_val) {
		ret = cdev_info->ops->dump_pcap_cmd(cdev_info, mac_addr, true);
		if (ret) {
			DRV_RDMA_LOG_ERROR(
				"common debugfs:dump_pcap_cmd, ret %d err\n",
				ret);
			goto end;
		}
		rdma_dev->rdma_dump_pcap = true;
		DRV_RDMA_LOG_DEBUG_BDF(
			"common debugfs:enable dump pcap success\n");
	} else {
		ret = cdev_info->ops->dump_pcap_cmd(cdev_info, mac_addr, false);
		if (ret) {
			DRV_RDMA_LOG_ERROR(
				"common debugfs:dump_pcap_cmd, ret %d err\n",
				ret);
			goto end;
		}
		rdma_dev->rdma_dump_pcap = false;
		DRV_RDMA_LOG_DEBUG_BDF(
			"common debugfs:disable dump pcap success\n");
	}

	ret  = (ssize_t)count;
	*off = (loff_t)count;

end:
	return ret;
}

static ssize_t drv_rdma_common_dump_pcap_en_read(struct file *filp,
						 char __user *buf, size_t count,
						 loff_t *off)
{
	ssize_t ret	 = SXE2_OK;
	size_t len_total = 0;
	char *rsp	 = NULL;
	char *rsp_end;
	struct sxe2_rdma_device *rdma_dev;

	if (*off != 0)
		goto end;

	rdma_dev = (struct sxe2_rdma_device *)filp->private_data;
	if (!rdma_dev) {
		ret = -ENXIO;
		DRV_RDMA_LOG_ERROR(
			"common debugfs:find dev struct from private_data failed err\n");
		goto end;
	}

	rsp = kzalloc(sizeof(char) * SXE2_DEBUG_DUMP_BUF_SIZE, GFP_KERNEL);
	if (!rsp) {
		ret = -ENOMEM;
		DRV_RDMA_LOG_ERROR("common debugfs:rsp kmalloc failed err\n");
		goto end;
	}
	rsp_end = rsp;

	if (rdma_dev->rdma_dump_pcap)
		len_total +=
			dbg_vsnprintf(rsp_end, len_total, "dump pcap enable\n");
	else
		len_total += dbg_vsnprintf(rsp_end, len_total,
					   "dump pcap disable\n");

	ret = simple_read_from_buffer(buf, count, off, rsp, len_total);
	if (ret < 0)
		DRV_RDMA_LOG_ERROR("common debugfs:simple read error %zu\n",
				   ret);

	kfree(rsp);
	rsp = NULL;

end:
	return ret;
}

static const struct file_operations sxe2_rdma_common_dump_pcap_en_fops = {
	.owner = THIS_MODULE,
	.open  = simple_open,
	.read  = drv_rdma_common_dump_pcap_en_read,
	.write = drv_rdma_common_dump_pcap_en_write,
};

int drv_rdma_debug_common_add(struct sxe2_rdma_device *rdma_dev)
{
	int ret = SXE2_OK;

	if (!sxe2_rdma_debugfs_get_dev_root(rdma_dev)) {
		ret = -EINVAL;
		DRV_RDMA_LOG_DEV_ERR(
			"mac loop back debugfs:debugfs root dir not exist ret=%d\n",
			ret);
		goto end;
	}

	if (!rdma_dev->hdl->common_debugfs) {
		ret = -EINVAL;
		DRV_RDMA_LOG_DEV_ERR(
			"mac loop back debugfs:dir not exist ret=%d\n", ret);
		goto end;
	}
#ifdef SXE2_CFG_DEBUG
	debugfs_create_file("reset_en", SXE2_DEBUG_FILE_READ_WRITE,
			    rdma_dev->hdl->common_debugfs, rdma_dev,
			    &sxe2_rdma_common_reset_en_fops);
	debugfs_create_file("reset_info", SXE2_DEBUG_FILE_READ_WRITE,
			    rdma_dev->hdl->common_debugfs, rdma_dev,
			    &sxe2_rdma_common_reset_info_fops);
#endif
	debugfs_create_file("dump_pcap_en", SXE2_DEBUG_FILE_READ_WRITE,
			    rdma_dev->hdl->common_debugfs, rdma_dev,
			    &sxe2_rdma_common_dump_pcap_en_fops);
end:
	return ret;
}

