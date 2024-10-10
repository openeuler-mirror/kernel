// SPDX-License-Identifier: GPL-2.0-or-later
#include <linux/acpi.h>
#include <linux/debugfs.h>
#include <linux/seq_file.h>

#include "sdma_hal.h"

#define LINE_LEN 10
#define CQE_ERR_MAX_CNT 100
#define ALL_CHANNEL_SELECTED 0
#define SINGLE_CHANNEL_SELECTED 1
#define R_R_R 0444

static struct hisi_sdma_global_info dbg_g_info;
static u32 debug_mode;
static u32 device_id;
static u32 channel_id;

static void split_line(struct seq_file *f)
{
	int i = 0;

	while (i++ < LINE_LEN)
		seq_puts(f, "---------");

	seq_puts(f, "\n");
}

static struct hisi_sdma_chn_num sdma_chn_info(struct seq_file *f, struct hisi_sdma_device *dev)
{
	struct hisi_sdma_chn_num chn_num;

	chn_num.total_chn_num = dev->nr_channel;
	chn_num.share_chn_num = *(dbg_g_info.share_chns);
	split_line(f);
	seq_printf(f, "SDMA[%u] Total channel num = %u,", dev->idx, chn_num.total_chn_num);
	seq_printf(f, "share channel num = %u, exclusive channel num = %u\n",
		   chn_num.share_chn_num, chn_num.total_chn_num - chn_num.share_chn_num);
	split_line(f);

	return chn_num;
}

static void sdma_scan_channel_status(struct seq_file *f, struct hisi_sdma_device *psdma_dev,
				     u32 share_chn_num)
{
	u32 channel_num = psdma_dev->nr_channel;
	u32 available_exclusive_chn_num = 0;
	struct hisi_sdma_channel *pchan;
	u32 available_share_chn_num = 0;
	u32 i;

	seq_printf(f, "SDMA[%u] channel status:\n", psdma_dev->idx);
	for (i = 0; i < channel_num; i++) {
		pchan = psdma_dev->channels + i;
		if (sdma_channel_is_quiescent(pchan) && sdma_channel_is_idle(pchan)) {
			if (i < share_chn_num)
				available_share_chn_num++;
			else
				available_exclusive_chn_num++;
		} else {
			seq_printf(f, "chn[%u] not in quiescent but in ", pchan->idx);
			if (sdma_channel_is_running(pchan))
				seq_puts(f, "running! pls check sq/cq head/tail...\n");
			else if (sdma_channel_is_abort(pchan))
				seq_puts(f, "abort! not reusable channel!\n");
			else if (sdma_channel_is_paused(pchan))
				seq_puts(f, "pause! maybe reusable after module reset\n");
		}
	}
	seq_printf(f, "\nSDMA[%u] has %u share_chn usable, %u exclusive_chn unusable\n",
		   psdma_dev->idx, available_share_chn_num, available_exclusive_chn_num);
	split_line(f);
}

static int sdma_debugfs_stats_show(struct seq_file *f, void *data SDMA_UNUSED)
{
	u32 num = dbg_g_info.core_dev->sdma_device_num;
	struct hisi_sdma_chn_num chn_num;
	struct hisi_sdma_channel *pchan;
	struct hisi_sdma_device *dev;
	u32 exclusive_chn_used_nr;
	u32 share_chn_used_nr;
	u32 exclusive_chn_num;
	u32 chn_idx;
	u32 i;

	split_line(f);
	seq_printf(f, "SDMA Devices Num = %u\n", num);
	if (num == 0)
		return 0;

	for (i = 0; i < num; i++) {
		spin_lock(&dbg_g_info.core_dev->device_lock);
		dev = dbg_g_info.core_dev->sdma_devices[i];
		if (!dev) {
			seq_puts(f, "sdma_devices already released!\n");
			spin_unlock(&dbg_g_info.core_dev->device_lock);
			return -ENXIO;
		}
		chn_num = sdma_chn_info(f, dev);
		exclusive_chn_num = chn_num.total_chn_num - chn_num.share_chn_num;
		exclusive_chn_used_nr = dev->nr_channel_used;
		seq_printf(f, "Used exclusive chn total num = %u\n", exclusive_chn_used_nr);
		seq_puts(f, "\n");
		split_line(f);
		share_chn_used_nr = 0;
		chn_idx = 0;
		seq_printf(f, "SDMA[%u] Used share chn id:\n", i);
		while (chn_idx < chn_num.share_chn_num) {
			pchan = dev->channels + chn_idx;
			if (pchan->cnt_used != 0) {
				share_chn_used_nr++;
				seq_printf(f, "%u\t", chn_idx);
			}
			++chn_idx;
		}
		seq_printf(f, "\nSDMA[%u] Used share chn total num = %u\n", i, share_chn_used_nr);
		split_line(f);
		sdma_scan_channel_status(f, dev, chn_num.share_chn_num);
		spin_unlock(&dbg_g_info.core_dev->device_lock);
	}

	return 0;
}

static int sdma_debugfs_stats_open(struct inode *inode SDMA_UNUSED, struct file *file)
{
	return single_open(file, sdma_debugfs_stats_show, NULL);
}

static const struct file_operations hisi_sdma_stats_fops = {
	.open = sdma_debugfs_stats_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
	.owner  = THIS_MODULE,
};

static void sdma_sqe_hexdump(struct seq_file *f, struct hisi_sdma_sq_entry *sqe)
{
	seq_printf(f, "sqeid = %u, opcode = %u, ie = %u, comp_en = %u\n", sqe->sqe_id, sqe->opcode,
		   sqe->ie, sqe->comp_en);
	seq_printf(f, "mpam_partid = %u, mpamns = %u, pmg = %u, qos = %u\n", sqe->mpam_partid,
		   sqe->mpamns, sqe->pmg, sqe->qos);
	seq_printf(f, "source stride length = %u, destination stride length = %u\n",
		   sqe->src_stride_len, sqe->dst_stride_len);
	seq_printf(f, "source streamid = %u, destination streamid = %u\n",
		   sqe->src_streamid, sqe->dst_streamid);
	seq_printf(f, "source substreamid = %u, destination substreamid = %u\n",
		   sqe->src_substreamid, sqe->dst_substreamid);
	seq_printf(f, "stride num = %u, stride = %u, length move = %u\n", sqe->stride_num,
		   sqe->stride, sqe->length_move);
	split_line(f);
}

static void sdma_cqe_hexdump(struct seq_file *f, struct hisi_sdma_cq_entry *cqe)
{
	seq_printf(f, "sqe_id = %u, opcode = %u\n", cqe->sqe_id, cqe->opcode);
	seq_printf(f, "status = %u, vld = %u\n", cqe->status, cqe->vld);
	split_line(f);
}

static u32 check_chn_all_cqe_status(struct hisi_sdma_channel *chn)
{
	struct hisi_sdma_cq_entry *cqe;
	u32 ret = 0;
	u32 i;

	for (i = 0; i < HISI_SDMA_CQ_LENGTH; i++) {
		cqe = chn->cq_base + i;
		if (cqe->status)
			ret++;
	}

	return ret;
}

static void sdma_err_sqe_info(struct seq_file *f, struct hisi_sdma_channel *chn)
{
	struct hisi_sdma_sq_entry *sqe;
	struct hisi_sdma_cq_entry *cqe;
	u32 err_cnt = 0;
	u32 h_cq_tail;
	u32 sq_idx;
	u32 cq_idx;

	h_cq_tail = sdma_channel_get_cq_tail(chn);
	seq_printf(f, "  chn%u hardware cq tail = %u\n", chn->idx, h_cq_tail);
	cq_idx = (h_cq_tail - 1) & (HISI_SDMA_CQ_LENGTH - 1);
	seq_printf(f, "  chn%u lastest cqe idx = %u\n", chn->idx, cq_idx);
	split_line(f);
	while (err_cnt < CQE_ERR_MAX_CNT) {
		cqe = chn->cq_base + cq_idx;
		if (cqe->status) {
			seq_printf(f, "  chn%u cqe%u err status = %u\n", chn->idx, cq_idx,
				   cqe->status);
			err_cnt++;
			sq_idx = cqe->sqe_id;
			sqe = chn->sq_base + sq_idx;
			sdma_sqe_hexdump(f, sqe);
		}
		cq_idx = ((cq_idx - 1) & (HISI_SDMA_CQ_LENGTH - 1));
		if (cq_idx == ((h_cq_tail - 1) & (HISI_SDMA_CQ_LENGTH - 1)))
			break;
	}
}

static u32 check_chn_err_info(struct seq_file *f, u32 dev_idx, u32 chn_idx)
{
	struct hisi_sdma_channel *chn;
	u32 cqe_err_cnt;
	u32 ch_cqe_status;
	u32 irq_status;

	chn = dbg_g_info.core_dev->sdma_devices[dev_idx]->channels + chn_idx;
	cqe_err_cnt = check_chn_all_cqe_status(chn);
	if (cqe_err_cnt) {
		seq_printf(f, "SDMA[%u] chn%u err count = %u\n", dev_idx, chn->idx, cqe_err_cnt);
		irq_status = chn->sync_info_base->ioe.ch_err_status;
		seq_printf(f, "SDMA[%u] chn%u software irq status = %u\n", dev_idx, chn->idx,
			   irq_status);
		ch_cqe_status = chn->sync_info_base->ioe.ch_cqe_status;
		seq_printf(f, "SDMA[%u] chn%u software cqe status = %u\n", dev_idx, chn->idx,
			   ch_cqe_status);
		split_line(f);
		sdma_err_sqe_info(f, chn);
	}

	return cqe_err_cnt;
}

static int sdma_debugfs_error_show(struct seq_file *f, void *data SDMA_UNUSED)
{
	u32 num = dbg_g_info.core_dev->sdma_device_num;
	struct hisi_sdma_chn_num chn_num;
	struct hisi_sdma_device *dev;
	u32 total_err_cnt;
	u32 err_cnt;
	u32 chn_idx;
	u32 i;

	split_line(f);
	seq_printf(f, "SDMA Devices Num = %u\n", num);
	if (num == 0)
		return 0;

	for (i = 0; i < num; i++) {
		spin_lock(&dbg_g_info.core_dev->device_lock);
		dev = dbg_g_info.core_dev->sdma_devices[i];
		if (!dev) {
			seq_puts(f, "sdma_devices already released!\n");
			spin_unlock(&dbg_g_info.core_dev->device_lock);
			return -ENXIO;
		}
		chn_num = sdma_chn_info(f, dev);
		total_err_cnt = 0;
		chn_idx = 0;
		while (chn_idx < chn_num.total_chn_num) {
			err_cnt = check_chn_err_info(f, i, chn_idx);
			total_err_cnt += err_cnt;
			chn_idx++;
		}
		seq_printf(f, "SDMA[%u] channel total cqe err count = %u\n", i, total_err_cnt);
		split_line(f);
		if (total_err_cnt == 0) {
			seq_printf(f, "SDMA[%u] device is ok\n", i);
			split_line(f);
		}
		spin_unlock(&dbg_g_info.core_dev->device_lock);
	}

	return 0;
}

static int sdma_debugfs_error_open(struct inode *inode SDMA_UNUSED, struct file *file)
{
	return single_open(file, sdma_debugfs_error_show, NULL);
}

static const struct file_operations hisi_sdma_error_fops = {
	.open = sdma_debugfs_error_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
	.owner  = THIS_MODULE,
};

static void sdma_chn_head_tail(struct seq_file *f, struct hisi_sdma_channel *pchan, u16 dev_id)
{
	u32 h_sq_head, h_sq_tail;
	u32 h_cq_head, h_cq_tail;

	if (pchan == NULL) {
		seq_puts(f, "pchan is NULL!\n");
		return;
	}

	h_sq_head = sdma_channel_get_sq_head(pchan);
	h_sq_tail = sdma_channel_get_sq_tail(pchan);
	h_cq_head = sdma_channel_get_cq_head(pchan);
	h_cq_tail = sdma_channel_get_cq_tail(pchan);
	seq_printf(f, "SDMA[%u] chn id = %u\n", dev_id, pchan->idx);
	seq_printf(f, "hardware sq head = %u\n", h_sq_head);
	seq_printf(f, "hardware sq tail = %u\n", h_sq_tail);
	seq_printf(f, "hardware cq head = %u\n", h_cq_head);
	seq_printf(f, "hardware cq tail = %u\n", h_cq_tail);
	split_line(f);
	seq_printf(f, "software sq head = %u\n", pchan->sync_info_base->sq_head);
	seq_printf(f, "software sq tail = %u\n", pchan->sync_info_base->sq_tail);
	seq_printf(f, "software cq head = %u\n", pchan->sync_info_base->cq_head);
	seq_printf(f, "software cq tail = %u\n", pchan->sync_info_base->cq_tail);
	split_line(f);
}

static u32 sdma_queue_count(u32 head, u32 tail, u32 len)
{
	return (tail - head) & (len - 1);
}

static void sdma_unfinish_sqe(struct seq_file *f, struct hisi_sdma_channel *pchan)
{
	struct hisi_sdma_sq_entry *h_head_sqe;
	u32 h_sq_tail, h_sq_head;
	u32 unfinish_byte = 0;
	u32 h_sub, s_sub;
	u32 i;

	if (pchan == NULL) {
		seq_puts(f, "pchan is NULL!\n");
		return;
	}

	h_sq_tail = sdma_channel_get_sq_tail(pchan);
	h_sq_head = sdma_channel_get_sq_head(pchan);
	s_sub = sdma_queue_count(pchan->sync_info_base->sq_head, h_sq_tail, HISI_SDMA_SQ_LENGTH);
	h_sub = sdma_queue_count(h_sq_head, h_sq_tail, HISI_SDMA_SQ_LENGTH);

	if (s_sub == 0)
		seq_puts(f, "all sdma task finish\n");
	else {
		if (h_sub) {
			seq_puts(f, "sdma hardware unfinish\n");
			seq_printf(f, "hardware unfinish sdma task number = %u\n", h_sub);
			for (i = 0; i < h_sub; i++) {
				h_head_sqe = pchan->sq_base + h_sq_head + i;
				unfinish_byte += h_head_sqe->length_move;
			}
			seq_printf(f, "hardware unfinish sdma byte = %u\n", unfinish_byte);
		}
		seq_printf(f, "software sqe head not updata yet, unfinish sdma task number:%u\n",
			   s_sub);
	}
	split_line(f);
}

static void sdma_sqe_cqe_list(struct seq_file *f, struct hisi_sdma_channel *pchan)
{
	struct hisi_sdma_sq_entry *sqe;
	struct hisi_sdma_cq_entry *cqe;
	u32 i;

	for (i = 0; i < HISI_SDMA_SQ_LENGTH; i++) {
		sqe = pchan->sq_base + i;
		cqe = pchan->cq_base + i;
		sdma_sqe_hexdump(f, sqe);
		sdma_cqe_hexdump(f, cqe);
		split_line(f);
	}
}

static void sdma_debugfs_get_channel_dfx(struct seq_file *f, struct hisi_sdma_channel *chn,
					 u16 dev_id)
{
	u32 normal_sqe_cnt;
	u32 err_sqe_cnt;

	sdma_chn_head_tail(f, chn, dev_id);
	normal_sqe_cnt = sdma_channel_get_normal_sqe_cnt(chn);
	err_sqe_cnt = sdma_channel_get_err_sqe_cnt(chn);
	seq_printf(f, "chn%u dfx info about normal sqe count = %u\n", chn->idx, normal_sqe_cnt);
	seq_printf(f, "chn%u dfx info about error sqe count = %u\n", chn->idx, err_sqe_cnt);
	split_line(f);
}

static int sdma_debugfs_channels_show(struct seq_file *f, void *data SDMA_UNUSED)
{
	u32 num = dbg_g_info.core_dev->sdma_device_num;
	struct hisi_sdma_chn_num chn_num;
	struct hisi_sdma_device *sdev;
	struct hisi_sdma_channel *chn;
	u32 dbg_mode = debug_mode;
	u32 chn_idx;
	u32 dev_idx;
	u32 i;

	split_line(f);
	seq_printf(f, "SDMA Devices Num = %u\n", num);
	if (num == 0 || num > HISI_SDMA_MAX_DEVS)
		return -ENOENT;

	if (dbg_mode == ALL_CHANNEL_SELECTED) {
		for (i = 0; i < num; i++) {
			spin_lock(&dbg_g_info.core_dev->device_lock);
			sdev = dbg_g_info.core_dev->sdma_devices[i];
			if (!sdev) {
				seq_puts(f, "sdma_devices already released!\n");
				spin_unlock(&dbg_g_info.core_dev->device_lock);
				return -ENXIO;
			}
			chn_num = sdma_chn_info(f, sdev);
			chn_idx = 0;
			while (chn_idx < chn_num.total_chn_num) {
				chn = sdev->channels + chn_idx;
				split_line(f);
				sdma_debugfs_get_channel_dfx(f, chn, sdev->idx);
				sdma_unfinish_sqe(f, chn);
				chn_idx++;
			}
			spin_unlock(&dbg_g_info.core_dev->device_lock);
		}
	} else if (dbg_mode == SINGLE_CHANNEL_SELECTED) {
		chn_idx = channel_id;
		dev_idx = device_id;
		if (dev_idx >= HISI_SDMA_MAX_DEVS ||
		    chn_idx >= HISI_SDMA_DEFAULT_CHANNEL_NUM) {
			seq_puts(f, "Unsupported device or channel!\n");
			return -EINVAL;
		}
		spin_lock(&dbg_g_info.core_dev->device_lock);
		sdev = dbg_g_info.core_dev->sdma_devices[dev_idx];
		if (!sdev) {
			seq_puts(f, "sdma_devices already released!\n");
			spin_unlock(&dbg_g_info.core_dev->device_lock);
			return -ENXIO;
		}
		chn_num = sdma_chn_info(f, sdev);
		chn = sdev->channels + chn_idx;
		split_line(f);
		sdma_debugfs_get_channel_dfx(f, chn, sdev->idx);
		sdma_sqe_cqe_list(f, chn);
		split_line(f);
		spin_unlock(&dbg_g_info.core_dev->device_lock);
	} else {
		seq_puts(f, "Unsupported debug mode!\n");
		return -EINVAL;
	}

	return 0;
}

static int sdma_debugfs_channels_open(struct inode *inode SDMA_UNUSED, struct file *file)
{
	return single_open(file, sdma_debugfs_channels_show, NULL);
}

static const struct file_operations hisi_sdma_channels_fops = {
	.open = sdma_debugfs_channels_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
	.owner  = THIS_MODULE,
};

int sdma_create_dbg_node(struct dentry *sdma_dbgfs_dir)
{
	struct dentry *entry;

	entry = debugfs_create_file("sdma_stats", R_R_R, sdma_dbgfs_dir, NULL,
				    &hisi_sdma_stats_fops);
	if (IS_ERR(entry))
		return PTR_ERR(entry);
	entry = debugfs_create_file("sdma_error", R_R_R, sdma_dbgfs_dir, NULL,
				    &hisi_sdma_error_fops);
	if (IS_ERR(entry))
		return PTR_ERR(entry);
	entry = debugfs_create_file("sdma_channels", R_R_R, sdma_dbgfs_dir, NULL,
				    &hisi_sdma_channels_fops);
	if (IS_ERR(entry))
		return PTR_ERR(entry);

	debugfs_create_u32("debug_mode", RW_R_R, sdma_dbgfs_dir, &debug_mode);
	debugfs_create_u32("device_id", RW_R_R, sdma_dbgfs_dir, &device_id);
	debugfs_create_u32("channel_id", RW_R_R, sdma_dbgfs_dir, &channel_id);
	debug_mode = 0;
	device_id = 0;
	channel_id = 0;

	return 0;
}

void sdma_info_sync_dbg(struct hisi_sdma_core_device *p, u32 *share_chns)
{
	dbg_g_info.core_dev = p;
	dbg_g_info.share_chns = share_chns;
}
