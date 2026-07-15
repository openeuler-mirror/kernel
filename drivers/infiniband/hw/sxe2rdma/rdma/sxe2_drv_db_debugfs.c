// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (C), 2020, sxe2rdma Technologies Co., Ltd.
 *
 * @file: sxe2_drv_db_debugfs.c
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
#include "sxe2_drv_db.h"
#include "sxe2_drv_rdma_log.h"
#include "sxe2_drv_rdma_debugfs.h"

#ifdef SXE2_CFG_DEBUG

static ssize_t drv_rdma_db_read_bitmap(struct file *filp, char __user *buf,
				       size_t count, loff_t *off)
{
	ssize_t ret	 = 0;
	size_t len_total = 0;
	char *rsp	 = NULL;
	char *rsp_end;
	u32 zero_count = 0;
	u32 used_count = 0;
	u32 i	       = 0;
	struct sxe2_rdma_device *rdma_dev;
	struct sxe2_rdma_pci_f *rdma_func;

	if (*off != 0)
		goto end;

	rdma_dev = (struct sxe2_rdma_device *)filp->private_data;
	if (!rdma_dev) {
		ret = -ENXIO;
		DRV_RDMA_LOG_ERROR(
			"DB DEBUGFS:find dev struct from private_data failed, ret %zu\n",
			ret);
		goto end;
	}

	rdma_func = rdma_dev->rdma_func;

	rsp = kzalloc(sizeof(char) * SXE2_DEBUG_DUMP_BUF_SIZE, GFP_KERNEL);
	if (!rsp) {
		ret = -ENOMEM;
		DRV_RDMA_LOG_DEV_ERR(
			"DB DEBUGFS:db bitmap rsp kmalloc failed, ret %zu\n",
			ret);
		goto end;
	}
	rsp_end = rsp;

	len_total += dbg_vsnprintf(rsp_end, len_total, "DB Status:\n");
	len_total +=
		dbg_vsnprintf(rsp_end, len_total, "Max DB Page count: %#x\n",
			      rdma_func->max_dbs);

	len_total += dbg_vsnprintf(rsp_end, len_total,
				   "Bar DB Phys Addr is from: %#llx\n",
				   (u64)rdma_func->bar_db_addr);
	len_total += dbg_vsnprintf(
		rsp_end, len_total,
		"Kernel DB Page :Index %#x, Vir Map Addr %#llx, wc %d\n"
		"ll_wqe num%#x, ll_wqe avail %#x, ref_count %#x\n",
		rdma_func->db->index, rdma_func->db->map, rdma_func->db->wc,
		rdma_func->db->llwqe_num, rdma_func->db->llwqe_avail,
		refcount_read(&rdma_func->db->ref_count.refcount));

	len_total += dbg_vsnprintf(rsp_end, len_total, "DB Bitmap:\n");
	for (i = 0; i < rdma_func->max_dbs; i++) {
		if (!test_bit((int)i, rdma_func->allocated_dbs))
			zero_count++;
		else
			used_count++;
	}
	len_total += dbg_vsnprintf(rsp_end, len_total,
				   "DB Page USED %#x, NULL %#x\n", used_count,
				   zero_count);

	ret = simple_read_from_buffer(buf, count, off, rsp, len_total);
	if (ret < 0)
		DRV_RDMA_LOG_DEV_ERR("DB DEBUGFS:simple read error %zu\n", ret);

	kfree(rsp);

end:
	return ret;
}

static const struct file_operations sxe2_rdma_db_bitmap_fops = {
	.owner = THIS_MODULE,
	.open  = simple_open,
	.read  = drv_rdma_db_read_bitmap,
};

int drv_rdma_debug_db_add(struct sxe2_rdma_device *rdma_dev)
{
	int ret = 0;

	if (!sxe2_rdma_debugfs_get_dev_root(rdma_dev)) {
		ret = -EINVAL;
		DRV_RDMA_LOG_DEV_ERR(
			"DB DEBUGFS:debugfs root dir not exist, ret (%d)\n",
			ret);
		goto end;
	}

	if (!rdma_dev->hdl->db_debugfs) {
		ret = -EINVAL;
		DRV_RDMA_LOG_DEV_ERR(
			"DB DEBUGFS:db debugfs dir not exist, ret (%d)\n", ret);
		goto end;
	}

	debugfs_create_file("db_bitmap", SXE2_DEBUG_FILE_ONLY_READ,
			    rdma_dev->hdl->db_debugfs, rdma_dev,
			    &sxe2_rdma_db_bitmap_fops);

end:
	return ret;
}

#endif
