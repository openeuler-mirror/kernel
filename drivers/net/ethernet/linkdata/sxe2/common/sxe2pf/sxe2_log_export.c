// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2_log_export.c
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#define SXE2_DUMP_FILE_DIR "/var/log/"
#define SXE2_DUMP_FILE_SIZE_LIMIT (200 * 1024 * 1024)
#define SXE2_SINCE_YEAR (1900)
#define SXE2_SINCE_MONTH (1)
#define SXE2_MINUTE_TO_SECES (60)

#include <linux/rtc.h>
#include <linux/fsnotify.h>

#include "sxe2.h"
#include "sxe2_log.h"
#include "sxe2_event.h"
#include "sxe2_log_export.h"
#include "sxe2_cmd_channel.h"
#include "sxe2_compat.h"

static s32 sxe2_export_local_time(struct rtc_time *tm)
{
	struct timespec64 time;
	time64_t local_time;

	ktime_get_real_ts64(&time);
	local_time = (time64_t)(time.tv_sec -
				(sys_tz.tz_minuteswest * SXE2_MINUTE_TO_SECES));
	rtc_time64_to_tm(local_time, tm);

	tm->tm_mon += SXE2_SINCE_MONTH;
	tm->tm_year += SXE2_SINCE_YEAR;
	return 0;
}

static void sxe2_export_filename_build(struct sxe2_export_context *ctxt,
				       s8 *filename, u32 len)
{
	struct sxe2_adapter *adapter = ctxt->adapter;
	struct rtc_time tm;
	struct pci_dev *pdev = adapter->pdev;
	s8 *p_str = filename;

	(void)sxe2_export_local_time(&tm);
	p_str += snprintf(p_str, len - (p_str - filename), "%s", SXE2_DUMP_FILE_DIR);
	p_str += snprintf(p_str, len - (p_str - filename), "sxe2-fw");
	p_str += snprintf(p_str, len - (p_str - filename), "-%04x:%02x:%02x.%x.log.",
			  pci_domain_nr(pdev->bus), pdev->bus->number,
			  PCI_SLOT(pdev->devfn), PCI_FUNC(pdev->devfn));
	p_str += snprintf(p_str, len - (p_str - filename),
			  "%04d%02d%02d-%02d%02d%02d", tm.tm_year, tm.tm_mon,
			  tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);
}

static void sxe2_export_file_close(struct sxe2_export_file_info *file_info)
{
	bool err = IS_ERR(file_info->fp);

	if (file_info && file_info->fp) {
		SXE2_BUG_ON(err);
		(void)filp_close(file_info->fp, NULL);

		file_info->fp = NULL;
	}
}

static s32 sxe2_export_file_open(struct sxe2_export_context *ctxt)
{
	struct sxe2_adapter *adapter = ctxt->adapter;
	struct sxe2_export_file_info *file_info = &ctxt->file;
	s8 filename[SXE2_DUMP_FILE_NAME_LEN] = {0};
	s32 ret = 0;
	struct file *filp = NULL;

	if (file_info->fp && file_info->file_size < ctxt->file_size_limit)
		goto l_out;

	sxe2_export_file_close(file_info);

	memset(file_info, 0, sizeof(struct sxe2_export_file_info));

	sxe2_export_filename_build(ctxt, filename, SXE2_DUMP_FILE_NAME_LEN);

	filp = (struct file *)filp_open(filename,
					O_CREAT | O_RDWR | O_TRUNC | O_LARGEFILE, 0);
	if (IS_ERR(filp)) {
		LOG_ERROR_BDF("export file create: filp_open error filename %s\t"
			      "errno %d\n",
			      filename, (int)PTR_ERR(filp));
		ret = -EIO;
		goto l_out;
	}

	memcpy(file_info->filename, filename, sizeof(filename));
	file_info->fp = filp;

l_out:
	return ret;
}

static s32 sxe2_export_file_write(struct sxe2_export_file_info *file_info, u8 *buf,
				  u32 len)
{
	struct file *filp = file_info->fp;
	s32 ret = 0;
	u32 pos = 0;

	while (pos < len) {
		do {
#ifdef KERNEL_WRITE_POS_LOFF
			ret = (s32)kernel_write(filp, buf + pos, len - pos,
						filp->f_pos);
#else
			ret = (s32)kernel_write(filp, buf + pos, len - pos,
						&filp->f_pos);
#endif
		} while (ret == -EINTR);

		if (ret < 0)
			return ret;
		if (ret == 0)
			return -EIO;

		fsnotify_modify(filp);
		file_info->file_size += len;
		file_info->file_w_cnt++;
		pos += ret;
	}

	return 0;
}

s32 sxe2_log_export_init(struct sxe2_adapter *adapter)
{
	s32 ret;
	struct sxe2_export_context *ctxt = &adapter->export_ctxt;
	struct sxe2_fwc_event event = {};

	event.count = 1;
	event.code[0] = cpu_to_le16(SXE2_EVENT_CODE_AUTO_LOG);
	ret = sxe2_fwc_event_subscribe(adapter, &event);
	if (ret)
		goto l_subscribe_failed;

	ctxt->adapter = adapter;
	ctxt->file_size_limit = SXE2_DUMP_FILE_SIZE_LIMIT;
	(void)sxe2_set_event_status(adapter, SXE2_EVENT_CODE_AUTO_LOG,
				    SXE2_CMD_EVENT_STATUS_SUB);

	return 0;

l_subscribe_failed:
	return ret;
}

void sxe2_log_export_deinit(struct sxe2_adapter *adapter)
{
	struct sxe2_export_context *ctxt = &adapter->export_ctxt;
	struct sxe2_fwc_event event = {};

	(void)sxe2_set_event_status(adapter, SXE2_EVENT_CODE_AUTO_LOG,
				    SXE2_CMD_EVENT_STATUS_UNSUB);

	ctxt->adapter = NULL;
	sxe2_export_file_close(&ctxt->file);

	event.count = 1;
	event.code[0] = cpu_to_le16(SXE2_EVENT_CODE_AUTO_LOG);
	(void)sxe2_fwc_event_unsubscribe(adapter, &event);
}

static s32 sxe2_fwc_log_export_ack(struct sxe2_adapter *adapter,
				   struct sxe2_fwc_fw_log_ack *ack)
{
	s32 ret;
	struct sxe2_cmd_params cmd = {};

	sxe2_cmd_params_fill(&cmd, SXE2_CMD_EVENT_FW_LOG_ACK, ack, sizeof(*ack),
			     NULL, 0, SXE2_DRV_CMD_DFLT_TIMEOUT, false, true);

	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret) {
		LOG_ERROR_BDF("export log ack failed, ret=%d\n", ret);
		ret = -EIO;
	}

	return ret;
}

s32 sxe2_event_log_export(struct sxe2_adapter *adapter, void *buf, u32 buf_len)
{
	s32 ret;
	struct sxe2_export_context *ctxt = &adapter->export_ctxt;
	struct sxe2_fwc_fw_log_ack ack = {};
	s32 result;

	if (!ctxt->adapter) {
		ret = -EINVAL;
		goto l_end;
	}

	ret = sxe2_export_file_open(ctxt);
	if (ret)
		goto l_ack;

	ret = sxe2_export_file_write(&ctxt->file, buf, buf_len);
	if (ret) {
		LOG_ERROR_BDF("file %s write %d failed: %d\n", ctxt->file.filename,
			      buf_len, ret);
	}

l_ack:
	result = ret ? -SXE2_CMD_DUMP_LOG_FAILED : 0;
	ack.result = cpu_to_le32((u32)result);
	ret = sxe2_fwc_log_export_ack(adapter, &ack);
l_end:
	return ret;
}
