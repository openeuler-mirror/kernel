// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (C), 2020, sxe2rdma Technologies Co., Ltd.
 *
 * @file: sxe2_drv_stats_debugfs.c
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
#include "sxe2_drv_stats.h"
#include "sxe2_drv_mq.h"
#include "sxe2_drv_hw.h"
#include "sxe2_drv_rdma_log.h"
#include "sxe2_drv_rdma_debugfs.h"

#ifdef SXE2_CFG_DEBUG

#ifdef ALLOC_HW_STATS_STRUCT_V1
extern const char *const sxe2_rdma_hw_stat_names[];
#else
extern const struct rdma_stat_desc sxe2_rdma_hw_stat_descs[];
#endif

#define SECOND_TO_MS(val) (1000 * (val))
#define MS_TO_SECOND(val) ((val) / 1000)

static ssize_t drv_rdma_stats_read(struct file *filp, char __user *buf,
				   size_t count, loff_t *off)
{
	ssize_t ret	 = 0;
	size_t len_total = 0;
	char *rsp	 = NULL;
	char *rsp_end;
	int i = 0;
	struct sxe2_rdma_device *rdma_dev;
	struct sxe2_rdma_ctx_dev *dev;
	struct sxe2_rdma_vsi_pestat *devstat;
	struct sxe2_rdma_dev_hw_stats *hw_stats;

	if (*off != 0)
		goto end;

	rdma_dev = (struct sxe2_rdma_device *)filp->private_data;
	if (!rdma_dev) {
		ret = -ENXIO;
		DRV_RDMA_LOG_ERROR(
			"STATS DEBUGFS:find dev struct from private_data failed, ret %zu\n",
			ret);
		goto end;
	}

	dev	 = &rdma_dev->rdma_func->ctx_dev;
	devstat	 = rdma_dev->vsi.pestat;
	hw_stats = &devstat->hw_stats;

	rsp = kzalloc(sizeof(char) * SXE2_DEBUG_DUMP_BUF_SIZE,
			      GFP_KERNEL);
	if (!rsp) {
		ret = -ENOMEM;
		DRV_RDMA_LOG_DEV_ERR(
			"STATS DEBUGFS:stats rsp kmalloc failed, ret %zu\n",
			ret);
		goto end;
	}
	rsp_end = rsp;

	if (dev->privileged)
		sxe2_kgather_stats_mq_cmd(dev, devstat, true);
	else
		sxe2_kgather_vf_stats_mq_cmd(dev, devstat, true);

	len_total += dbg_vsnprintf(rsp_end, len_total, "STATS :\n");
	for (i = 0; i < SXE2_RDMA_HW_STAT_INDEX_MAX; i++) {
#ifdef ALLOC_HW_STATS_STRUCT_V1
		len_total +=
			dbg_vsnprintf(rsp_end, len_total, "%d. %s: %#llx\n", i,
				      sxe2_rdma_hw_stat_names[i],
				      hw_stats->stats_val[i]);
#else
		len_total +=
			dbg_vsnprintf(rsp_end, len_total, "%d. %s: %#llx\n", i,
				      sxe2_rdma_hw_stat_descs[i].name,
				      hw_stats->stats_val[i]);
#endif
	}

	ret = simple_read_from_buffer(buf, count, off, rsp, len_total);
	if (ret < 0)
		DRV_RDMA_LOG_DEV_ERR("DB DEBUGFS:simple read error %zu\n", ret);

	kfree(rsp);

end:
	return ret;
}

static const struct file_operations sxe2_rdma_gather_stats_fops = {
	.owner = THIS_MODULE,
	.open  = simple_open,
	.read  = drv_rdma_stats_read,
};

int drv_rdma_debug_stats_add(struct sxe2_rdma_device *rdma_dev)
{
	int ret			      = 0;
	struct sxe2_rdma_handler *hdl = rdma_dev->hdl;

	if (!sxe2_rdma_debugfs_get_dev_root(rdma_dev)) {
		ret = -EINVAL;
		DRV_RDMA_LOG_DEV_ERR(
			"STATS DEBUGFS:debugfs root dir not exist, ret (%d)\n",
			ret);
		goto end;
	}

	if (!hdl->stats_debugfs) {
		ret = -EINVAL;
		DRV_RDMA_LOG_DEV_ERR("stats debugfs dir not exist, ret (%d)\n",
				     ret);
		goto end;
	}

	debugfs_create_file("hw_stats", SXE2_DEBUG_FILE_ONLY_READ,
			    hdl->stats_debugfs, rdma_dev,
			    &sxe2_rdma_gather_stats_fops);

end:
	return ret;
}

#ifdef SXE2_SUPPORT_INJECT
enum { STATS_INJECT_OVERFLOW_ENABLE,
		STATS_INJECT_GATHER_INTERVAL,
};

static char *stats_inject_fields[] = {
	[STATS_INJECT_OVERFLOW_ENABLE] = "overflow_enable",
	[STATS_INJECT_GATHER_INTERVAL] = "gather_interval",
};

STATIC ssize_t drv_stats_overflow_inject_read(struct file *filp,
					      char __user *buf, size_t count,
					      loff_t *pos)
{
	ssize_t ret;
	char *rsp = NULL;
	char *rsp_end;
	size_t len = 0;
	struct sxe2_rdma_device *rdma_dev;

	rdma_dev = filp->private_data;

	rsp = kzalloc(sizeof(char) * SXE2_DEBUG_DUMP_BUF_SIZE,
			      GFP_KERNEL);
	if (!rsp) {
		ret = -ENOMEM;
		DRV_RDMA_LOG_DEV_ERR(
			"STATS DEBUGFS:stats status rsp kmalloc failed, ret %zu\n",
			ret);
		goto end;
	}
	rsp_end = rsp;

	len += dbg_vsnprintf(rsp_end, len, "stats inject info\n");
	len += dbg_vsnprintf(rsp_end, len, "gather_interval:  %d\n",
			     MS_TO_SECOND(rdma_dev->vsi.pestat->timer_delay));

	ret = simple_read_from_buffer(buf, count, pos, rsp, len);
	if (ret < 0) {
		DRV_RDMA_LOG_DEV_ERR("STATS DEBUGFS:simple read error %zu\n",
				     ret);
	}

	kfree(rsp);

end:
	return ret;
}

STATIC ssize_t drv_stats_overflow_inject_write(struct file *filp,
					       const char __user *buf,
					       size_t count, loff_t *pos)
{
	ssize_t ret;
	char in_buf[64] = { 0 };
	u32 i;
	u64 temp_value;
	int argc;
	char *argv[DEBUG_ARGV_COUNT_MAX] = { 0 };
	struct sxe2_rdma_device *rdma_dev;
	struct sxe2_rdma_vsi_pestat *devstat;
	struct sxe2_rdma_dev_hw_stats *hw_stats;

	rdma_dev = filp->private_data;
	devstat	 = rdma_dev->vsi.pestat;
	hw_stats = &devstat->hw_stats;

	if (copy_from_user(in_buf, buf, count)) {
		ret = -EFAULT;
		goto end;
	}

	argc = 0;
	memset(argv, 0, sizeof(*argv) * DEBUG_ARGV_COUNT_MAX);
	ret = split_command(in_buf, &argc, argv);
	if (ret)
		goto end;

	if (argc != DEBUG_PARA_CONT2) {
		ret = -EINVAL;
		DRV_RDMA_LOG_DEV_ERR("invalid param nums\n");
		goto end;
	}

	for (i = 0; i < ARRAY_SIZE(stats_inject_fields); i++) {
		if (!strncmp(argv[0], stats_inject_fields[i],
			     strlen(stats_inject_fields[i]))) {
			break;
		}
	}

	ret = kstrtoull(argv[1], 10, &temp_value);
	if (ret != 0) {
		DRV_RDMA_LOG_DEV_ERR("get param value failed, ret (%zd)\n",
				     ret);
		goto end;
	}

	DRV_RDMA_LOG_DEV_INFO("inject field i:%d, to temp_value:%llx\n", i,
			      temp_value);

	switch (i) {
	case STATS_INJECT_OVERFLOW_ENABLE:
		if (temp_value) {
			for (i = 0; i < SXE2_RDMA_HW_STAT_INDEX_MAX; i++) {
				memset(&(hw_stats->stats_val[i]), 0xFF,
				       sizeof(u64));
			};
		}
		break;
	case STATS_INJECT_GATHER_INTERVAL:
		if (temp_value)
			devstat->timer_delay = (u32)SECOND_TO_MS(temp_value);
		break;
	default:
		DRV_RDMA_LOG_DEV_WARN("invalid index %d\n", i);
		ret = -EINVAL;
		goto end;
	}

	*pos = (loff_t)count;
	ret  = (ssize_t)count;

end:
	return ret;
}

static const struct file_operations stats_overflow_inject_fops = {
	.owner = THIS_MODULE,
	.open  = simple_open,
	.read  = drv_stats_overflow_inject_read,
	.write = drv_stats_overflow_inject_write,
};

int drv_rdma_stats_overflow_inject_debugfs_add(struct sxe2_rdma_device *rdma_dev)
{
	int ret			      = 0;
	struct sxe2_rdma_handler *hdl = rdma_dev->hdl;

	if (!sxe2_rdma_debugfs_get_dev_root(rdma_dev)) {
		ret = -EINVAL;
		DRV_RDMA_LOG_DEV_ERR("root dir not exist, ret (%d)\n", ret);
		goto end;
	}

	if (!hdl->stats_debugfs) {
		ret = -EINVAL;
		DRV_RDMA_LOG_DEV_ERR("stats debugfs dir not exist, ret (%d)\n",
				     ret);
		goto end;
	}

	debugfs_create_file("stats_inject", SXE2_DEBUG_FILE_READ_WRITE,
			    hdl->stats_debugfs, rdma_dev,
			    &stats_overflow_inject_fops);

end:
	return ret;
}
#endif

#endif
