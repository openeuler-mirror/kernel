// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (C), 2020, sxe2rdma Technologies Co., Ltd.
 *
 * @file: sxe2_drv_rdma_debugfs.c
 * @author: sxe2rdma
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#include <linux/fs.h>
#include <linux/debugfs.h>
#include <linux/list.h>
#include "sxe2_compat.h"
#ifdef NOT_SUPPORT_AUXILIARY_BUS
#include "auxiliary_bus.h"
#else
#include <linux/auxiliary_bus.h>
#endif
#include "sxe2_drv_cq.h"
#include "sxe2_drv_rdma_log.h"
#include "sxe2_drv_rdma_debugfs.h"
#include "sxe2_drv_eq_debugfs.h"
#include "sxe2_drv_mq_debugfs.h"
#include "sxe2_drv_rdma_inject_debugfs.h"

#define SXE2_DEBUG_RSC_FILE_NAME_LEN (32)

static struct dentry *sxe2_rdma_dbg_root;
static const char sxe2_rdma_driver_name[] = "sxe2rdma";

size_t dbg_vsnprintf(char *buf, size_t len, char *fmt, ...)
{
	size_t cnt = 0;
	int ret;
	va_list args;

	va_start(args, fmt);
	ret = vsnprintf(buf + len, SXE2_DEBUG_DUMP_BUF_SIZE - len, fmt, args);
	if (ret >= 0) {
		cnt = (size_t)ret;
	} else {
		DRV_RDMA_LOG_ERROR("vsnprintf format err %d\n", ret);
		;
	}
	va_end(args);

	return cnt;
}

int split_command(char *cmd, int *argc, char *argv[])
{
	int ret	    = 0;
	char *token = NULL;

	cmd[strlen(cmd) - 1] = '\0';
	token		     = strsep(&cmd, " ");
	while (token != NULL) {
		if (*argc >= DEBUG_ARGV_COUNT_MAX) {
			ret = -EINVAL;
			DRV_RDMA_LOG_ERROR("too many arguments: '%s'\n", token);
			goto end;
		}

		argv[*argc] = token;

		token = strsep(&cmd, " ");
		(*argc)++;
	}

end:
	return ret;
}

STATIC ssize_t drv_sceq_break_moderation_en_read(struct file *filp,
						 char __user *buf, size_t count,
						 loff_t *pos)
{
	u32 ret;
	u8 sceq_break_moderation_en;
	char out_buf[8];
	struct sxe2_rdma_device *rdma_dev;

	rdma_dev = filp->private_data;
	sceq_break_moderation_en =
		rdma_dev->rdma_func->scqe_break_moderation_en;
	ret = (u32)snprintf(out_buf, sizeof(out_buf), "%d\n",
			    sceq_break_moderation_en);
	return simple_read_from_buffer(buf, count, pos, out_buf, ret);
}

STATIC ssize_t drv_sceq_break_moderation_en_write(struct file *filp,
						  const char __user *buf,
						  size_t count, loff_t *pos)
{
	ssize_t ret;
	char in_buf[8] = { 0 };
	u32 sceq_break_moderation_en;
	struct sxe2_rdma_device *rdma_dev;

	rdma_dev = filp->private_data;

	if (copy_from_user(in_buf, buf, count)) {
		ret = -EFAULT;
		goto out;
	}

	ret = sscanf(in_buf, "%u", &sceq_break_moderation_en);
	if (ret != 1) {
		ret = -EINVAL;
		goto out;
	}

	rdma_dev->rdma_func->scqe_break_moderation_en =
		(u8)sceq_break_moderation_en;
	DRV_RDMA_LOG_DEV_WARN("set sceq_break_moderation_en to %d\n",
			      sceq_break_moderation_en);

	*pos = (loff_t)count;
	ret  = (ssize_t)count;
out:
	return ret;
}

static const struct file_operations sceq_break_moderation_en_fops = {
	.owner = THIS_MODULE,
	.open  = simple_open,
	.read  = drv_sceq_break_moderation_en_read,
	.write = drv_sceq_break_moderation_en_write,
};

STATIC ssize_t drv_aeq_pble_en_read(struct file *filp, char __user *buf,
				    size_t count, loff_t *pos)
{
	u32 ret;
	u8 aeq_pble_en;
	char out_buf[8];
	struct sxe2_rdma_device *rdma_dev;

	rdma_dev    = filp->private_data;
	aeq_pble_en = rdma_dev->rdma_func->aeq_pble_en;
	ret = (u32)snprintf(out_buf, sizeof(out_buf), "%d\n", aeq_pble_en);
	return simple_read_from_buffer(buf, count, pos, out_buf, ret);
}

STATIC ssize_t drv_aeq_pble_en_write(struct file *filp, const char __user *buf,
				     size_t count, loff_t *pos)
{
	ssize_t ret;
	char in_buf[8] = { 0 };
	u32 aeq_pble_en;
	struct sxe2_rdma_device *rdma_dev;

	rdma_dev = filp->private_data;

	if (copy_from_user(in_buf, buf, count)) {
		ret = -EFAULT;
		goto out;
	}

	ret = sscanf(in_buf, "%u", &aeq_pble_en);
	if (ret != 1) {
		ret = -EINVAL;
		goto out;
	}

	rdma_dev->rdma_func->aeq_pble_en = (u8)aeq_pble_en;
	DRV_RDMA_LOG_DEV_WARN("set aeq_pble_en to %d\n", aeq_pble_en);

	*pos = (loff_t)count;
	ret  = (ssize_t)count;
out:
	return ret;
}

static const struct file_operations aeq_pble_en_fops = {
	.owner = THIS_MODULE,
	.open  = simple_open,
	.read  = drv_aeq_pble_en_read,
	.write = drv_aeq_pble_en_write,
};

STATIC ssize_t drv_ceq_itr_read(struct file *filp, char __user *buf,
				size_t count, loff_t *pos)
{
	u32 ret;
	u8 ceq_itr;
	char out_buf[8];
	struct sxe2_rdma_device *rdma_dev;

	rdma_dev = filp->private_data;
	ceq_itr	 = (u8)rdma_dev->rdma_func->ctx_dev.ceq_itr;
	ret	 = (u32)snprintf(out_buf, sizeof(out_buf), "%d\n", ceq_itr);
	return simple_read_from_buffer(buf, count, pos, out_buf, ret);
}

STATIC ssize_t drv_ceq_itr_write(struct file *filp, const char __user *buf,
				 size_t count, loff_t *pos)
{
	ssize_t ret;
	char in_buf[8] = { 0 };
	u32 ceq_itr;
	struct sxe2_rdma_device *rdma_dev;

	rdma_dev = filp->private_data;

	if (copy_from_user(in_buf, buf, count)) {
		ret = -EFAULT;
		goto out;
	}

	ret = sscanf(in_buf, "%u", &ceq_itr);
	if (ret != 1) {
		ret = -EINVAL;
		goto out;
	}

	rdma_dev->rdma_func->ctx_dev.ceq_itr = ceq_itr;
	DRV_RDMA_LOG_DEV_WARN("set ceq_itr to %d\n", ceq_itr);

	*pos = (loff_t)count;
	ret  = (ssize_t)count;
out:
	return ret;
}

static const struct file_operations ceq_itr_fops = {
	.owner = THIS_MODULE,
	.open  = simple_open,
	.read  = drv_ceq_itr_read,
	.write = drv_ceq_itr_write,
};

STATIC ssize_t drv_ack_mode_read(struct file *filp, char __user *buf,
				 size_t count, loff_t *pos)
{
	u32 ret;
	u8 ack_mode;
	char out_buf[8];
	struct sxe2_rdma_device *rdma_dev;

	rdma_dev = filp->private_data;
	ack_mode = rdma_dev->rdma_func->ack_mode;
	ret	 = (u32)snprintf(out_buf, sizeof(out_buf), "%d\n", ack_mode);
	return simple_read_from_buffer(buf, count, pos, out_buf, ret);
}

STATIC ssize_t drv_ack_mode_write(struct file *filp, const char __user *buf,
				  size_t count, loff_t *pos)
{
	ssize_t ret;
	char in_buf[8] = { 0 };
	u32 ack_mode;
	struct sxe2_rdma_device *rdma_dev;

	rdma_dev = filp->private_data;

	if (copy_from_user(in_buf, buf, count)) {
		ret = -EFAULT;
		goto out;
	}

	ret = sscanf(in_buf, "%u", &ack_mode);
	if (ret != 1) {
		ret = -EINVAL;
		goto out;
	}

	rdma_dev->rdma_func->ack_mode = ack_mode;
	DRV_RDMA_LOG_DEV_WARN("set ack_mode to %d\n", ack_mode);

	*pos = (loff_t)count;
	ret  = (ssize_t)count;
out:
	return ret;
}

static const struct file_operations ack_mode_fops = {
	.owner = THIS_MODULE,
	.open  = simple_open,
	.read  = drv_ack_mode_read,
	.write = drv_ack_mode_write,
};

STATIC ssize_t drv_log_ack_req_freq_read(struct file *filp, char __user *buf,
					 size_t count, loff_t *pos)
{
	u32 ret;
	u8 log_ack_req_freq;
	char out_buf[8];
	struct sxe2_rdma_device *rdma_dev;

	rdma_dev	 = filp->private_data;
	log_ack_req_freq = rdma_dev->rdma_func->log_ack_req_freq;
	ret = (u32)snprintf(out_buf, sizeof(out_buf), "%d\n", log_ack_req_freq);
	return simple_read_from_buffer(buf, count, pos, out_buf, ret);
}

STATIC ssize_t drv_log_ack_req_freq_write(struct file *filp,
					  const char __user *buf, size_t count,
					  loff_t *pos)
{
	ssize_t ret;
	char in_buf[8] = { 0 };
	u32 log_ack_req_freq;
	struct sxe2_rdma_device *rdma_dev;

	rdma_dev = filp->private_data;

	if (copy_from_user(in_buf, buf, count)) {
		ret = -EFAULT;
		goto out;
	}

	ret = sscanf(in_buf, "%u", &log_ack_req_freq);
	if (ret != 1) {
		ret = -EINVAL;
		goto out;
	}

	rdma_dev->rdma_func->log_ack_req_freq = (u8)log_ack_req_freq;
	DRV_RDMA_LOG_DEV_WARN("set log_ack_req_freq to %d\n", log_ack_req_freq);

	*pos = (loff_t)count;
	ret  = (ssize_t)count;
out:
	return ret;
}

static const struct file_operations log_ack_req_freq_fops = {
	.owner = THIS_MODULE,
	.open  = simple_open,
	.read  = drv_log_ack_req_freq_read,
	.write = drv_log_ack_req_freq_write,
};

STATIC ssize_t drv_UDPriv_CQEnable_read(struct file *filp, char __user *buf,
					size_t count, loff_t *pos)
{
	u32 ret;
	u8 UDPriv_CQEnable;
	char out_buf[8];
	struct sxe2_rdma_device *rdma_dev;

	rdma_dev	= filp->private_data;
	UDPriv_CQEnable = rdma_dev->rdma_func->UDPriv_CQEnable;
	ret = (u32)snprintf(out_buf, sizeof(out_buf), "%d\n", UDPriv_CQEnable);
	return simple_read_from_buffer(buf, count, pos, out_buf, ret);
}

STATIC ssize_t drv_UDPriv_CQEnable_write(struct file *filp,
					 const char __user *buf, size_t count,
					 loff_t *pos)
{
	ssize_t ret;
	char in_buf[8] = { 0 };
	u32 UDPriv_CQEnable;
	struct sxe2_rdma_device *rdma_dev;

	rdma_dev = filp->private_data;

	if (copy_from_user(in_buf, buf, count)) {
		ret = -EFAULT;
		goto out;
	}

	ret = sscanf(in_buf, "%u", &UDPriv_CQEnable);
	if (ret != 1) {
		ret = -EINVAL;
		goto out;
	}

	rdma_dev->rdma_func->UDPriv_CQEnable = UDPriv_CQEnable;
	DRV_RDMA_LOG_DEV_WARN("set UDPriv_CQEnable to %d\n", UDPriv_CQEnable);

	*pos = (loff_t)count;
	ret  = (ssize_t)count;
out:
	return ret;
}

static const struct file_operations UDPriv_CQEnable_fops = {
	.owner = THIS_MODULE,
	.open  = simple_open,
	.read  = drv_UDPriv_CQEnable_read,
	.write = drv_UDPriv_CQEnable_write,
};

STATIC ssize_t drv_rdma_dbg_read(struct file *filp, char __user *buf,
				 size_t count, loff_t *pos)
{
	ssize_t ret;
	u64 field     = 0;
	char *out_buf = NULL;
	struct sxe2_rdma_rsc_debug *dbg_node;
	struct sxe2_rdma_device *rdma_dev;

	if (*pos != 0) {
		ret = 0;
		goto end;
	}

	dbg_node = filp->private_data;
	rdma_dev = dbg_node->dev;

	if (dbg_node->type >= SXE2_DBG_RSC_MAX) {
		ret = 0;
		DRV_RDMA_LOG_DEV_ERR("read invalid type %d\n", dbg_node->type);
		goto end;
	}

	out_buf = kzalloc(SXE2_DEBUG_DUMP_BUF_SIZE, GFP_KERNEL);
	if (!out_buf) {
		DRV_RDMA_LOG_DEV_ERR("debugfs memory alloc failed.\n");
		ret = -ENOMEM;
		goto end;
	}

	if (dbg_node->func_tab.read_func) {
		field = dbg_node->func_tab.read_func(dbg_node->dev,
						     dbg_node->object,
						     dbg_node->type, out_buf);
		if (field == 0 || field >= SXE2_DEBUG_DUMP_BUF_SIZE) {
			DRV_RDMA_LOG_DEV_ERR(
				"debugfs read failed. field %llu\n", field);
			ret = -EFAULT;
			kfree(out_buf);
			out_buf = NULL;
			goto end;
		}
	}

	ret = simple_read_from_buffer(buf, count, pos, out_buf, field);
	kfree(out_buf);
	out_buf = NULL;

end:
	return ret;
}

STATIC ssize_t drv_rdma_dbg_write(struct file *filp, const char __user *buf,
				  size_t count, loff_t *pos)
{
	ssize_t ret;
	char log_buf[64] = { 0 };
	struct sxe2_rdma_rsc_debug *dbg_node;
	struct sxe2_rdma_device *rdma_dev;

	(void)filp;

	dbg_node = filp->private_data;
	rdma_dev = dbg_node->dev;

	if (count >= sizeof(log_buf)) {
		ret = -ENOSPC;
		goto end;
	}

	if (copy_from_user(log_buf, buf, count)) {
		ret = -EFAULT;
		goto end;
	}

	if (dbg_node->func_tab.write_func) {
		ret = dbg_node->func_tab.write_func(dbg_node->dev,
						    dbg_node->object,
						    dbg_node->type, log_buf);
		if (ret != 0) {
			DRV_RDMA_LOG_DEV_ERR("debugfs write failed.\n");
			ret = -EFAULT;
			goto end;
		}
	}

	*pos = (loff_t)count;
	ret  = (ssize_t)count;

end:
	return ret;
}

static const struct file_operations sxe2_rdma_fops = {
	.owner = THIS_MODULE,
	.open  = simple_open,
	.read  = drv_rdma_dbg_read,
	.write = drv_rdma_dbg_write,
};

struct sxe2_rdma_rsc_debug *
drv_rdma_add_res_tree(struct sxe2_rdma_device *rdma_dev,
		      enum drv_rdma_dbg_rsc_type type, struct dentry *root,
		      sxe2_drv_rdma_debugfs_read rfunc,
		      sxe2_drv_rdma_debugfs_write wfunc, int rsn, void *data)
{
	char resn[SXE2_DEBUG_RSC_FILE_NAME_LEN];
	struct sxe2_rdma_rsc_debug *dbg_node = NULL;

	if (type >= SXE2_DBG_RSC_MAX) {
		DRV_RDMA_LOG_DEV_ERR("cmr debugfs reg invalid type %d\n", type);
		goto end;
	}

	dbg_node = kzalloc(sizeof(*dbg_node), GFP_KERNEL);
	if (!dbg_node) {
		DRV_RDMA_LOG_DEV_ERR("dbg node buf alloc error sz %lu\n",
				     sizeof(*dbg_node));
		goto end;
	}

	dbg_node->dev		      = rdma_dev;
	dbg_node->object	      = data;
	dbg_node->type		      = type;
	dbg_node->func_tab.read_func  = rfunc;
	dbg_node->func_tab.write_func = wfunc;

	if (type == SXE2_DBG_RSC_AEQ) {
		dbg_node->root = root;
		goto create_file;
	} else {
		sprintf(resn, "0x%x", rsn);

		dbg_node->root = debugfs_create_dir(resn, root);
		if (!dbg_node->root) {
			DRV_RDMA_LOG_DEV_ERR("debugfs create %s dir failed.\n",
					     resn);
			kfree(dbg_node);
			dbg_node = NULL;
			goto end;
		}
	}

create_file:
	debugfs_create_file("context", SXE2_DEBUG_FILE_READ_WRITE,
			    dbg_node->root, dbg_node, &sxe2_rdma_fops);

end:
	return dbg_node;
}

void drv_rdma_rm_res_tree(struct sxe2_rdma_rsc_debug *dbg)
{
	debugfs_remove_recursive(dbg->root);
	dbg->root = NULL;
	kfree(dbg);
	dbg = NULL;
}

struct dentry *sxe2_rdma_debugfs_get_dev_root(struct sxe2_rdma_device *rdma_dev)
{
	return rdma_dev->hdl->sxe2_rdma_dbg_dentry;
}

#ifdef SXE2_CFG_DEBUG
void sxe2_debug_file_creat(struct sxe2_rdma_device *rdma_dev)
{
	debugfs_create_file("ack_mode", SXE2_DEBUG_FILE_READ_WRITE,
			    rdma_dev->hdl->qp_debugfs, rdma_dev,
			    &ack_mode_fops);

	debugfs_create_file("log_ack_req_freq", SXE2_DEBUG_FILE_READ_WRITE,
			    rdma_dev->hdl->qp_debugfs, rdma_dev,
			    &log_ack_req_freq_fops);

	debugfs_create_file("UDPriv_CQEnable", SXE2_DEBUG_FILE_READ_WRITE,
			    rdma_dev->hdl->qp_debugfs, rdma_dev,
			    &UDPriv_CQEnable_fops);

	debugfs_create_file("scqe_break_moderation_en",
			    SXE2_DEBUG_FILE_READ_WRITE,
			    rdma_dev->hdl->cq_debugfs, rdma_dev,
			    &sceq_break_moderation_en_fops);

	debugfs_create_file("aeq_pble_en", SXE2_DEBUG_FILE_READ_WRITE,
			    rdma_dev->hdl->aeq_debugfs, rdma_dev,
			    &aeq_pble_en_fops);

	debugfs_create_file("ceq_itr", SXE2_DEBUG_FILE_READ_WRITE,
			    rdma_dev->hdl->eq_debugfs, rdma_dev, &ceq_itr_fops);
}
#endif

int sxe2_rdma_dbg_pf_init(struct sxe2_rdma_device *rdma_dev)
{
	int ret			      = 0;
	struct sxe2_rdma_handler *hdl = rdma_dev->hdl;
	const char *name	      = pci_name(hdl->dev->rdma_func->pcidev);
	struct dentry *pfile __always_unused;

	DRV_RDMA_LOG_DEV_DEBUG("debugfs pf init start.\n");

	spin_lock_init(&hdl->uctx_list_lock);
	INIT_LIST_HEAD(&hdl->ucontext_list);

	hdl->sxe2_rdma_dbg_dentry =
		debugfs_create_dir(name, sxe2_rdma_dbg_root);
	if (!hdl->sxe2_rdma_dbg_dentry) {
		DRV_RDMA_LOG_DEV_ERR("debugfs create %s dir failed.\n", name);
		ret = -ENOMEM;
		goto end;
	}

	hdl->cq_debugfs = debugfs_create_dir("CQs", hdl->sxe2_rdma_dbg_dentry);
	if (!hdl->cq_debugfs) {
		DRV_RDMA_LOG_DEV_ERR("debugfs create CQ dir failed.\n");
		ret = -ENOMEM;
		goto remove_root;
	}

	hdl->qp_debugfs = debugfs_create_dir("QPs", hdl->sxe2_rdma_dbg_dentry);
	if (!hdl->qp_debugfs) {
		DRV_RDMA_LOG_DEV_ERR("debugfs create QP dir failed.\n");
		ret = -ENOMEM;
		goto remove_cq_debug;
	}

	hdl->eq_debugfs = debugfs_create_dir("EQs", hdl->sxe2_rdma_dbg_dentry);
	if (!hdl->eq_debugfs) {
		DRV_RDMA_LOG_DEV_ERR("debugfs create EQ dir failed.\n");
		ret = -ENOMEM;
		goto remove_qp_debug;
	}

	hdl->ceq_debugfs = debugfs_create_dir("ceqs", hdl->eq_debugfs);
	if (!hdl->ceq_debugfs) {
		DRV_RDMA_LOG_DEV_ERR("debugfs create ceq dir failed.\n");
		ret = -ENOMEM;
		goto remove_eq_debug;
	}

	hdl->aeq_debugfs = debugfs_create_dir("aeq", hdl->eq_debugfs);
	if (!hdl->aeq_debugfs) {
		DRV_RDMA_LOG_DEV_ERR("debugfs create aeq dir failed.\n");
		ret = -ENOMEM;
		goto remove_ceq_debug;
	}

#if defined(SXE2_SUPPORT_INJECT) && defined(SXE2_CFG_DEBUG)
	ret = sxe2_rdma_aeq_codes_inject_add(rdma_dev);
	if (ret) {
		DRV_RDMA_LOG_DEV_ERR("aeq codes inject add failed.\n");
		goto remove_aeq_debug;
	}
	sxe2_drv_inject_create_debugfs_files(rdma_dev);
#endif

	hdl->mq_debugfs = debugfs_create_dir("MQ", hdl->sxe2_rdma_dbg_dentry);
	if (!hdl->mq_debugfs) {
		DRV_RDMA_LOG_DEV_ERR("debugfs create MQ dir failed.\n");
		ret = -ENOMEM;
#if defined(SXE2_SUPPORT_INJECT) && defined(SXE2_CFG_DEBUG)
		goto remove_aeq_codes_inject_debug;
#else
		goto remove_aeq_debug;
#endif
	}

#if defined(SXE2_SUPPORT_INJECT) && defined(SXE2_CFG_DEBUG)
	sxe2_kadd_mq_nop_debugfs_files(rdma_dev);

	ret = sxe2_kadd_mq_err_debugfs(rdma_dev);
	if (ret) {
		DRV_RDMA_LOG_DEV_ERR("debugfs create MQ Err dirs failed.\n");
		ret = -ENOMEM;
		goto remove_mq_debug;
	}
#endif

#ifdef SXE2_CFG_DEBUG
	hdl->db_debugfs = debugfs_create_dir("DB", hdl->sxe2_rdma_dbg_dentry);
	if (!hdl->db_debugfs) {
		DRV_RDMA_LOG_DEV_ERR("debugfs create DB dir failed.\n");
		ret = -ENOMEM;
#ifdef SXE2_SUPPORT_INJECT
		goto remove_mq_err_debug;
#else
		goto remove_mq_debug;
#endif
	}
#endif

	hdl->mr_debugfs = debugfs_create_dir("MRs", hdl->sxe2_rdma_dbg_dentry);
	if (!hdl->mr_debugfs) {
		DRV_RDMA_LOG_DEV_ERR("debugfs create mr dir failed.\n");
		ret = -ENOMEM;
		goto remove_db_debug;
	}

	hdl->rcms_debugfs =
		debugfs_create_dir("RCMS", hdl->sxe2_rdma_dbg_dentry);
	if (!hdl->rcms_debugfs) {
		DRV_RDMA_LOG_DEV_ERR("debugfs create RCMS dir failed.\n");
		ret = -ENOMEM;
		goto remove_mr_debug;
	}
#ifdef SXE2_CFG_DEBUG
	hdl->ah_debugfs = debugfs_create_dir("AHs", hdl->sxe2_rdma_dbg_dentry);
	if (!hdl->ah_debugfs) {
		DRV_RDMA_LOG_DEV_ERR("debugfs create ah dir failed.\n");
		ret = -ENOMEM;
		goto remove_rcms_debug;
	}
#endif
	hdl->srq_debugfs =
		debugfs_create_dir("SRQs", hdl->sxe2_rdma_dbg_dentry);
	if (!hdl->srq_debugfs) {
		DRV_RDMA_LOG_DEV_ERR("debugfs create srq dir failed.\n");
		ret = -ENOMEM;
#ifdef SXE2_CFG_DEBUG
		goto remove_ah_debug;
#else
		goto remove_rcms_debug;
#endif
	}

#ifdef SXE2_CFG_DEBUG
	sxe2_debug_file_creat(rdma_dev);
#endif

	hdl->qos_debugfs = debugfs_create_dir("QOS", hdl->sxe2_rdma_dbg_dentry);
	if (!hdl->qos_debugfs) {
		DRV_RDMA_LOG_DEV_ERR("debugfs create QOS dir failed.\n");
		ret = -ENOMEM;
		goto remove_srq_debug;
	}

#ifdef SXE2_CFG_DEBUG
	hdl->stats_debugfs =
		debugfs_create_dir("STATS", hdl->sxe2_rdma_dbg_dentry);
	if (!hdl->stats_debugfs) {
		DRV_RDMA_LOG_DEV_ERR("debugfs create STATS dir failed.\n");
		ret = -ENOMEM;
		goto remove_qos_debug;
	}
#endif

	hdl->cc_debugfs = debugfs_create_dir("CC", hdl->sxe2_rdma_dbg_dentry);
	if (!hdl->cc_debugfs) {
		DRV_RDMA_LOG_ERROR_BDF("debugfs create CC dir failed.\n");
		ret = -ENOMEM;
		goto remove_stats_debug;
	}

	hdl->common_debugfs =
		debugfs_create_dir("COMMON", hdl->sxe2_rdma_dbg_dentry);
	if (!hdl->common_debugfs) {
		DRV_RDMA_LOG_DEV_ERR("debugfs create COMMON dir failed.\n");
		ret = -ENOMEM;
		goto remove_cc_debug;
	}

	DRV_RDMA_LOG_DEV_DEBUG("debugfs pf init end.\n");

#if defined(SXE2_SUPPORT_INJECT) && defined(SXE2_CFG_DEBUG)
	if (rdma_dev->rdma_func->inject_sleep_time)
		msleep(rdma_dev->rdma_func->inject_sleep_time);
#endif

	goto end;

remove_cc_debug:
	debugfs_remove_recursive(hdl->cc_debugfs);
	hdl->cc_debugfs = NULL;

remove_stats_debug:
#ifdef SXE2_CFG_DEBUG
	debugfs_remove_recursive(hdl->stats_debugfs);
	hdl->stats_debugfs = NULL;
#endif

#ifdef SXE2_CFG_DEBUG
remove_qos_debug:
	debugfs_remove_recursive(hdl->qos_debugfs);
	hdl->qos_debugfs = NULL;
#endif

remove_srq_debug:
	debugfs_remove_recursive(hdl->srq_debugfs);
	hdl->srq_debugfs = NULL;

#ifdef SXE2_CFG_DEBUG
remove_ah_debug:
	debugfs_remove_recursive(hdl->ah_debugfs);
	hdl->ah_debugfs = NULL;
#endif

remove_rcms_debug:
	debugfs_remove_recursive(hdl->rcms_debugfs);
	hdl->rcms_debugfs = NULL;

remove_mr_debug:
	debugfs_remove_recursive(hdl->mr_debugfs);
	hdl->mr_debugfs = NULL;

remove_db_debug:
#ifdef SXE2_CFG_DEBUG
	debugfs_remove_recursive(hdl->db_debugfs);
	hdl->db_debugfs = NULL;
#endif

#if defined(SXE2_SUPPORT_INJECT) && defined(SXE2_CFG_DEBUG)
remove_mq_err_debug:
	sxe2_kremove_mq_err_debugfs(rdma_dev);
#endif

#ifdef SXE2_CFG_DEBUG
remove_mq_debug:
	debugfs_remove_recursive(hdl->mq_debugfs);
	hdl->mq_debugfs = NULL;
#endif

#if defined(SXE2_SUPPORT_INJECT) && defined(SXE2_CFG_DEBUG)
remove_aeq_codes_inject_debug:
	drv_rdma_aeq_codes_inject_del(rdma_dev);
#endif

remove_aeq_debug:
	debugfs_remove_recursive(hdl->aeq_debugfs);
	hdl->aeq_debugfs = NULL;

remove_ceq_debug:
	debugfs_remove_recursive(hdl->ceq_debugfs);
	hdl->ceq_debugfs = NULL;

remove_eq_debug:
	debugfs_remove_recursive(hdl->eq_debugfs);
	hdl->eq_debugfs = NULL;

remove_qp_debug:
	debugfs_remove_recursive(hdl->qp_debugfs);
	hdl->qp_debugfs = NULL;

remove_cq_debug:
	debugfs_remove_recursive(hdl->cq_debugfs);
	hdl->cq_debugfs = NULL;

remove_root:
	debugfs_remove_recursive(hdl->sxe2_rdma_dbg_dentry);
	hdl->sxe2_rdma_dbg_dentry = NULL;

end:
	return ret;
}

void sxe2_rdma_dgb_pf_exit(struct sxe2_rdma_device *rdma_dev)
{
	struct sxe2_rdma_handler *hdl = rdma_dev->hdl;

	DRV_RDMA_LOG_DEV_DEBUG("debugfs remove entries start.\n");

	debugfs_remove_recursive(hdl->cq_debugfs);
	hdl->cq_debugfs = NULL;

	debugfs_remove_recursive(hdl->qp_debugfs);
	hdl->qp_debugfs = NULL;

	debugfs_remove_recursive(hdl->ceq_debugfs);
	hdl->ceq_debugfs = NULL;

#if defined(SXE2_SUPPORT_INJECT) && defined(SXE2_CFG_DEBUG)
	drv_rdma_aeq_codes_inject_del(rdma_dev);
#endif

	debugfs_remove_recursive(hdl->aeq_debugfs);
	hdl->aeq_debugfs = NULL;

	debugfs_remove_recursive(hdl->eq_debugfs);
	hdl->eq_debugfs = NULL;

#if defined(SXE2_SUPPORT_INJECT) && defined(SXE2_CFG_DEBUG)
	sxe2_kremove_mq_err_debugfs(rdma_dev);
#endif

	debugfs_remove_recursive(hdl->mq_debugfs);
	hdl->mq_debugfs = NULL;

	debugfs_remove_recursive(hdl->rcms_debugfs);
	hdl->rcms_debugfs = NULL;

#ifdef SXE2_CFG_DEBUG
	debugfs_remove_recursive(hdl->db_debugfs);
	hdl->db_debugfs = NULL;
#endif

	debugfs_remove_recursive(hdl->srq_debugfs);
	hdl->srq_debugfs = NULL;

	debugfs_remove_recursive(hdl->mr_debugfs);
	hdl->mr_debugfs = NULL;
#ifdef SXE2_CFG_DEBUG
	debugfs_remove_recursive(hdl->ah_debugfs);
	hdl->ah_debugfs = NULL;
#endif
	debugfs_remove_recursive(hdl->qos_debugfs);
	hdl->qos_debugfs = NULL;

#ifdef SXE2_CFG_DEBUG
	debugfs_remove_recursive(hdl->stats_debugfs);
	hdl->stats_debugfs = NULL;
#endif
	debugfs_remove_recursive(hdl->cc_debugfs);
	hdl->cc_debugfs = NULL;

	debugfs_remove_recursive(hdl->common_debugfs);
	hdl->common_debugfs = NULL;
#if defined(SXE2_SUPPORT_INJECT) && defined(SXE2_CFG_DEBUG)
	sxe2_drv_inject_clean_debug_files(rdma_dev);
#endif

	debugfs_remove_recursive(hdl->sxe2_rdma_dbg_dentry);
	hdl->sxe2_rdma_dbg_dentry = NULL;
}

int sxe2_rdma_dbg_init(void)
{
	sxe2_rdma_dbg_root = debugfs_create_dir(sxe2_rdma_driver_name, NULL);
	if (!sxe2_rdma_dbg_root) {
		DRV_RDMA_LOG_ERROR("debugfs create sxe2 dir failed.\n");
		return -ENOMEM;
	}
	return 0;
}

void sxe2_rdma_dbg_exit(void)
{
	debugfs_remove_recursive(sxe2_rdma_dbg_root);
}
