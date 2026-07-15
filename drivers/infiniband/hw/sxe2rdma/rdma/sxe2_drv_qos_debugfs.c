// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (C), 2020, sxe2rdma Technologies Co., Ltd.
 *
 * @file: sxe2_drv_qos_debugfs.c
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
#include "sxe2_drv_qos_debugfs.h"
#include "sxe2_drv_rdma_common.h"

static struct sxe2_rdma_ctx_qp *sxe2_get_qp_from_entry(struct list_head *entry)
{
	struct sxe2_rdma_ctx_qp *qp = NULL;

	if (entry == NULL)
		return NULL;

	qp = container_of(entry, struct sxe2_rdma_ctx_qp, list);

	return qp;
}

static struct sxe2_rdma_ctx_qp *
sxe2_qos_get_qp_from_list(struct list_head *head, struct sxe2_rdma_ctx_qp *qp)
{
	struct list_head *last_entry;
	struct list_head *entry = NULL;

	if (list_empty(head))
		return NULL;

	if (!qp) {
		entry = (head)->next;
	} else {
		last_entry = &qp->list;
		entry	   = (last_entry)->next;
		if (entry == head)
			return NULL;
	}

	return sxe2_get_qp_from_entry(entry);
}

static ssize_t drv_rdma_qos_info_read(struct file *filp, char __user *buf,
				      size_t count, loff_t *off)
{
	ssize_t ret	 = SXE2_OK;
	size_t len_total = 0;
	char *rsp	 = NULL;
	char *rsp_end;
	struct sxe2_rdma_device *rdma_dev;
	struct sxe2_rdma_ctx_vsi *vsi_ctx;
	struct sxe2_rdma_ctx_qp *qp = NULL;
	int i;
	int j;
	int qset_idx_cnt = 0;

	if (*off != 0)
		goto end;

	rdma_dev = (struct sxe2_rdma_device *)filp->private_data;
	if (!rdma_dev) {
		ret = -ENXIO;
		DRV_RDMA_LOG_ERROR(
			"qos debugfs:find dev struct from private_data failed err\n");
		goto end;
	}

	vsi_ctx = &rdma_dev->vsi;

	rsp = kzalloc(sizeof(char) * SXE2_DEBUG_DUMP_BUF_SIZE,
			      GFP_KERNEL);
	if (!rsp) {
		ret = -ENOMEM;
		DRV_RDMA_LOG_DEV_ERR(
			"qos debugfs:rcms info rsp kmalloc failed err\n");
		goto end;
	}
	rsp_end = rsp;

	len_total += dbg_vsnprintf(rsp_end, len_total, "qos info:\n");

	if (vsi_ctx->lag_aa)
		qset_idx_cnt = SXE2_QSET_PER_USER_PRI_BOND;
	else
		qset_idx_cnt = SXE2_QSET_PER_USER_PRI;
	for (j = 0; j < qset_idx_cnt; j++) {
		len_total += dbg_vsnprintf(rsp_end, len_total, "dscp mode:%u\n",
				   vsi_ctx->dscp_mode[j]);
	}
	for (i = 0; i < SXE2_MAX_USER_PRIORITY; i++) {
		mutex_lock(&vsi_ctx->qos[i].qos_mutex);
		if (!vsi_ctx->qos[i].valid) {
			len_total +=
				dbg_vsnprintf(rsp_end, len_total,
					      "user pri %u is invalid\n", i);
			mutex_unlock(&vsi_ctx->qos[i].qos_mutex);
			continue;
		}
		len_total += dbg_vsnprintf(
			rsp_end, len_total,
			"user pri=%u:qp cnt=%u\n",
			i, vsi_ctx->qos[i].qp_cnt);
		for (j = 0; j < qset_idx_cnt; j++) {
			len_total += dbg_vsnprintf(
				rsp_end, len_total,
				"user pri=%u:tc=%u pri type=%u rel bw=%u qp cnt=%u\n",
				i, vsi_ctx->qos[i].qset[j].traffic_class,
				vsi_ctx->qos[i].prio_type[j], vsi_ctx->qos[i].rel_bw[j],
				vsi_ctx->qos[i].qset[j].qset_qp_cnt);

			len_total += dbg_vsnprintf(
				rsp_end, len_total,
				"qset idx %u:qset num=%u qset id=%u teid=%u qset bind qp cnt=%u\n",
				j, vsi_ctx->qos[i].qset[j].qset_num,
				vsi_ctx->qos[i].qset[j].qset_id,
				vsi_ctx->qos[i].qset[j].teid,
				vsi_ctx->qos[i].qset[j].qset_qp_cnt);
			qp = sxe2_qos_get_qp_from_list(
				&vsi_ctx->qos[i].qset[j].qp_list, qp);
			if (qp) {
				len_total += dbg_vsnprintf(rsp_end, len_total,
							   "qpn: ");
			}
			while (qp) {
				len_total +=
					dbg_vsnprintf(rsp_end, len_total, "%u ",
						      qp->qp_common.qpn);
				qp = sxe2_qos_get_qp_from_list(
					&vsi_ctx->qos[i].qset[j].qp_list, qp);
			}
			len_total += dbg_vsnprintf(rsp_end, len_total, "\n");
		}
		mutex_unlock(&vsi_ctx->qos[i].qos_mutex);
	}

	ret = simple_read_from_buffer(buf, count, off, rsp, len_total);
	if (ret < 0) {
		DRV_RDMA_LOG_DEV_ERR("qos debugfs:simple read error %zu\n",
				     ret);
	}

	kfree(rsp);

end:
	return ret;
}

static const struct file_operations sxe2_rdma_qos_info_fops = {
	.owner = THIS_MODULE,
	.open  = simple_open,
	.read  = drv_rdma_qos_info_read,
};

int drv_rdma_debug_qos_add(struct sxe2_rdma_device *rdma_dev)
{
	int ret = SXE2_OK;

	if (!sxe2_rdma_debugfs_get_dev_root(rdma_dev)) {
		ret = -EINVAL;
		DRV_RDMA_LOG_DEV_ERR(
			"qos debugfs:debugfs root dir not exist ret=%d\n", ret);
		goto end;
	}

	if (!rdma_dev->hdl->qos_debugfs) {
		ret = -EINVAL;
		DRV_RDMA_LOG_DEV_ERR("qos debugfs:dir not exist ret=%d\n", ret);
		goto end;
	}

	debugfs_create_file("qos_info", SXE2_DEBUG_FILE_ONLY_READ,
			    rdma_dev->hdl->qos_debugfs, rdma_dev,
			    &sxe2_rdma_qos_info_fops);
end:
	return ret;
}

#if defined(SXE2_SUPPORT_INJECT) && defined(SXE2_CFG_DEBUG)

enum { OQS_INJECT_APPLY_QSET_ERR_CODE,
		QOS_INJECT_RELEASE_QSET_ERR_CODE,
		QOS_INJECT_QP_BIND_QSET_ERR_CODE,

};

enum { MAX_INJECT_APPLY_QSET_ERR_CODE	= 2,
		MAX_INJECT_RELEASE_QSET_ERR_CODE = 2,
		MAX_INJECT_QP_BIND_QSET_ERR_CODE = 8,
};

static char *qos_inject_fields[] = {
	[OQS_INJECT_APPLY_QSET_ERR_CODE]   = "apply_qset_err_code",
	[QOS_INJECT_RELEASE_QSET_ERR_CODE] = "release_qset_err_code",
	[QOS_INJECT_QP_BIND_QSET_ERR_CODE] = "qp_bind_qset_err_code",
};

STATIC ssize_t drv_qset_errcode_inject_read(struct file *filp, char __user *buf,
					    size_t count, loff_t *pos)
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
			"MQ DEBUGFS:mq status rsp kmalloc failed, ret %zu\n",
			ret);
		goto end;
	}
	rsp_end = rsp;

	len += dbg_vsnprintf(rsp_end, len, "qset errcodes inject info\n");
	len += dbg_vsnprintf(
		rsp_end, len, "apply_qset_err_code:    %d\n",
		rdma_dev->rdma_func->inject_qos.apply_qset_err_code);
	len += dbg_vsnprintf(
		rsp_end, len, "release_qset_err_code:  %d\n",
		rdma_dev->rdma_func->inject_qos.release_qset_err_code);
	len += dbg_vsnprintf(
		rsp_end, len, "qp_bind_qset_err_code:  %d\n",
		rdma_dev->rdma_func->inject_qos.qp_bind_qset_err_code);

	ret = simple_read_from_buffer(buf, count, pos, rsp, len);
	if (ret < 0)
		DRV_RDMA_LOG_DEV_ERR("MQ DEBUGFS:simple read error %zu\n", ret);

	kfree(rsp);

end:
	return ret;
}

STATIC ssize_t drv_qset_errcode_inject_write(struct file *filp,
					     const char __user *buf,
					     size_t count, loff_t *pos)
{
	ssize_t ret;
	char in_buf[64] = { 0 };
	size_t i;
	u64 temp_value;
	int argc;
	char *argv[DEBUG_ARGV_COUNT_MAX] = { 0 };
	struct sxe2_rdma_device *rdma_dev;

	rdma_dev = filp->private_data;

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

	for (i = 0; i < ARRAY_SIZE(qos_inject_fields); i++) {
		if (!strncmp(argv[0], qos_inject_fields[i],
			     strlen(qos_inject_fields[i]))) {
			break;
		}
	}

	ret = kstrtoull(argv[1], 10, &temp_value);
	if (ret != 0) {
		DRV_RDMA_LOG_DEV_ERR("get param value failed, ret (%zd)\n",
				     ret);
		goto end;
	}

	DRV_RDMA_LOG_DEV_INFO("inject field i:%zu, to temp_value:%llx\n", i,
			      temp_value);

	switch (i) {
	case OQS_INJECT_APPLY_QSET_ERR_CODE:
		if (temp_value > MAX_INJECT_APPLY_QSET_ERR_CODE) {
			DRV_RDMA_LOG_DEV_DEBUG("exceed max val,set default\n");
			temp_value = MAX_INJECT_APPLY_QSET_ERR_CODE;
		}
		rdma_dev->rdma_func->inject_qos.apply_qset_err_code =
			(u8)temp_value;
		break;
	case QOS_INJECT_RELEASE_QSET_ERR_CODE:
		if (temp_value > MAX_INJECT_RELEASE_QSET_ERR_CODE) {
			DRV_RDMA_LOG_DEV_DEBUG("exceed max val,set default\n");
			temp_value = MAX_INJECT_RELEASE_QSET_ERR_CODE;
		}
		rdma_dev->rdma_func->inject_qos.release_qset_err_code =
			(u8)temp_value;
		break;
	case QOS_INJECT_QP_BIND_QSET_ERR_CODE:
		if (temp_value > MAX_INJECT_QP_BIND_QSET_ERR_CODE) {
			DRV_RDMA_LOG_DEV_DEBUG("exceed max val,set default\n");
			temp_value = MAX_INJECT_QP_BIND_QSET_ERR_CODE;
		}
		rdma_dev->rdma_func->inject_qos.qp_bind_qset_err_code =
			(u8)temp_value;
		break;
	default:
		DRV_RDMA_LOG_DEV_WARN("invalid index %zu\n", i);
		ret = -EINVAL;
		goto end;
	}

	*pos = (loff_t)count;
	ret  = (ssize_t)count;

end:
	return ret;
}

static const struct file_operations qset_errcode_inject_fops = {
	.owner = THIS_MODULE,
	.open  = simple_open,
	.read  = drv_qset_errcode_inject_read,
	.write = drv_qset_errcode_inject_write,
};

int drv_rdma_qos_err_code_inject_add(struct sxe2_rdma_device *rdma_dev)
{
	int ret			      = 0;
	struct sxe2_rdma_handler *hdl = rdma_dev->hdl;

	if (!sxe2_rdma_debugfs_get_dev_root(rdma_dev)) {
		ret = -EINVAL;
		DRV_RDMA_LOG_DEV_ERR("root dir not exist, ret (%d)\n", ret);
		goto end;
	}

	if (!hdl->qos_debugfs) {
		ret = -EINVAL;
		DRV_RDMA_LOG_DEV_ERR("qos debugfs dir not exist, ret (%d)\n",
				     ret);
		goto end;
	}

	debugfs_create_file("qset_errcode_inject", SXE2_DEBUG_FILE_READ_WRITE,
			    hdl->qos_debugfs, rdma_dev,
			    &qset_errcode_inject_fops);

end:
	return ret;
}

#endif
