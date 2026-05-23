/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hinic5_micro_log.c
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   : Save parsed information to log file
 */

#include <linux/module.h>
#include <linux/device.h>
#include <linux/delay.h>
#include <linux/time.h>
#include <linux/timex.h>
#include <linux/rtc.h>
#include <linux/string.h>

#include "comm_defs.h"
#include "ossl_knl.h"
#include "hinic5_hw.h"
#include "hinic5_hwdev.h"
#include "hinic5_chip_info.h"
#include "hinic5_micro_log.h"
#include "hinic5_comm_cmd.h"
#include "mpu_inband_cmd_defs.h"
#include "micro_log_comm.h"
#include "micro_log_procfs_cmd.h"
#include "micro_log_index.h"

static bool micro_log_en;
module_param(micro_log_en, bool, 0444);
MODULE_PARM_DESC(micro_log_en, "Enable micorlog write to host - default is false");

static bool micro_asm_mode; // 0: Default from flash; 1: Select /home/microcode.asm
module_param(micro_asm_mode, bool, 0444);
MODULE_PARM_DESC(micro_asm_mode, "default micro asm from flash");

char log_file_path[MAX_PATH_NAME] = "/home/microcode.log";
char asm_file_path[MAX_PATH_NAME] = "/home/microcode.asm";

#define NIC_MICRO_ASM_START_ADDR 0x10000000

const char *micro_log_level[] = {"ERR", "WARN", "INFO", "DEBUG"};

u8 nic_micro_log_dbg;
u32 poll_log_cnt;

int nic_micro_log_write_log_write_file(struct micro_log_info *log_info,
				       const u8 *func_name, micro_log_item_s *log_item,
				       struct file *fp_log_file)
{
	u32 err = 0;
	unsigned int level_index = 0;
	struct timeval txc;
	struct rtc_time time;
	u64 localtime;

/*lint -restore*/
	level_index = log_item->ctrl_info.bs.type;
	if (level_index > ULOG_DEBUG) {
		microlog_warning("level_index(%d) err.", level_index);
		level_index = ULOG_DEBUG;
	}

	/* Get current UTC time */
	do_gettimeofday(&(txc));

	/* Convert UTC time to local time */
	hinic5_utctime_to_localtime((u64)txc.tv_sec, &localtime);

	/* Beijing timezone adjustment. */
	localtime = TIMEZONE_ADJUSTMENT(localtime);

	/* Calculate year, month, day and other time values into tm */
	rtc_time_to_tm((time64_t)localtime, &time);

	(void)snprintf(log_info->micro_log_tmpbuf, (unsigned long)MICRO_LOG_MAX_STRING_LEN * 8,
		"[%02u:%02u:%02u.%06u](tile_core_tc:%d_%d_%d)[%d][%s](%s:%d) :",
		time.tm_hour, time.tm_min, time.tm_sec, (u32)txc.tv_usec % 1000000,
		log_item->ctrl_info.bs.tile_id, log_item->ctrl_info.bs.core_id,
		log_item->ctrl_info.bs.thread_id,
		log_item->line_and_pi.bs.log_seq, micro_log_level[level_index],
		func_name, log_item->line_and_pi.bs.line);

	err = hinic5_file_write(fp_log_file, log_info->micro_log_tmpbuf,
			 (u32)strlen(log_info->micro_log_tmpbuf)); //lint !e712
	if (err != strlen(log_info->micro_log_tmpbuf)) {
		microlog_err("Can't write the cal data to file");
		return -EFAULT;
	}
	return 0;
}

/*
 * Function : nic_micro_log_write_log_file
 * Description : Save parsed information to log file
 * Type :
 * Input : u8 *buf
 * u8 *func_name
 * micro_log_item_s *log_item
 * Output : None
 * Return :
 * Restriction :
 * History :
 * 1.Date : 2015/10/19
 * Modification : Created function
 */
int nic_micro_log_write_log_file(struct micro_log_info *log_info, u8 *buf,
				 u8 *func_name, micro_log_item_s *log_item)
{
	u32 err = 0;
	struct file *fp;
#if defined(HAVE_MM_SEGMENT_T)
	mm_segment_t old_fs;
#endif

	if (nic_micro_log_dbg == 1)
		microlog_info("nic_micro_log_dbg in");

	if (!buf || !func_name || !log_item) {
		microlog_err("input buf, func_name or log_item is null");
		return -EFAULT;
	}
	if (!log_info->fp_log_file) {
		microlog_err("fp_log_file is NULL");
		return -EFAULT;
	}

	fp = log_info->fp_log_file;

/*lint -save -e501*/
#if defined(HAVE_MM_SEGMENT_T)
#if !defined(CONFIG_UACCESS_MEMCPY) && !defined(CONFIG_SET_FS)
	old_fs = get_fs();
	set_fs(get_ds());
#elif defined(CONFIG_UACCESS_MEMCPY)
	old_fs = get_fs();
	set_fs(KERNEL_DS);
#elif defined(CONFIG_SET_FS)
	old_fs = force_uaccess_begin();
#endif
#endif

	if (nic_micro_log_write_log_write_file(log_info, func_name, log_item, fp) == -EFAULT)
		return -EFAULT;
	memset(log_info->micro_log_tmpbuf, 0, sizeof(log_info->micro_log_tmpbuf));

/*lint -save -e668*/
	(void)snprintf(log_info->micro_log_tmpbuf,
		       (unsigned long)MICRO_LOG_MAX_STRING_LEN * 8, (char *)buf,
		       log_item->data[0], log_item->data[1], log_item->data[2], log_item->data[3],
		       log_item->data[4], log_item->data[5], log_item->data[6], log_item->data[7]);
/*lint -restore*/
	err = hinic5_file_write(fp, log_info->micro_log_tmpbuf,
			 (u32)strlen(log_info->micro_log_tmpbuf));  //lint !e712
	if (err != strlen(log_info->micro_log_tmpbuf)) {
		microlog_err("Can't write the cal data to file ERR:[0x%x]", err);
		return -EFAULT;
	}

#if defined(HAVE_MM_SEGMENT_T)
#if !defined(CONFIG_SET_FS)
	set_fs(old_fs);
#else
	force_uaccess_end(old_fs);
#endif
#endif

	return 0;
}

/*
 * Function : nic_micro_log_get_string_from_data
 * Description : Get string start address
 * Type :
 * Input : struct micro_log_info *log_info
 * unsigned int data_addr
 * Output : None
 * Return :
 * Restriction :
 * History :
 * 1.Date : 2015/10/19
 * Modification : Created function
 */
char *nic_micro_log_get_string_from_data(struct micro_log_info *log_info, unsigned int data_addr)
{
	unsigned int offset;
	char *out_buf;
	char *tmp_char;

	u32 i;
	char err_string[] = "string has %%s\n";
	u32 err_string_len = sizeof("string has %%s\n");

	offset = data_addr - NIC_MICRO_ASM_START_ADDR;
	out_buf = (char *)(log_info->micro_log_data_addr + offset);

	tmp_char = out_buf;
	for (i = 0; i < strlen((char *)out_buf); i++, tmp_char++) {
		if (('%' == *tmp_char) && (('s' == *(tmp_char + 1)) || ('S' == *(tmp_char + 1))))
			memcpy(out_buf, err_string, err_string_len);
	}

	if (nic_micro_log_dbg == 1) {
		pr_info("%s(%d): micro addr : 0x%x\n", __func__, __LINE__, data_addr);
		tmp_char = out_buf;
		pr_info("%s(%d)get asm data as:\n", __func__, __LINE__);
		for (i = 0; i < strlen(out_buf); i++) {
			pr_info("0x%02x ", *(tmp_char + i));
			if (0 == ((i + 1) % 16))
				pr_info("\n");
		}
	}

	return out_buf;
}

/*
 * Function : nic_micro_log_parse_microcode_log
 * Description : Parse microcode log
 * Type :
 * Input : struct micro_log_info *log_info
 * micro_log_item_s *log_item
 * Output : None
 * Return :
 * Restriction :
 * History :
 * 1.Date : 2015/10/19
 * Modification : Created function
 */
int nic_micro_log_parse_microcode_log(struct micro_log_info *log_info, micro_log_item_s *log_item)
{
	int err;

	char *log_str;
	char *log_file;

	if (!log_item) {
		microlog_err("input log_item is NULL!");
		return -EFAULT;
	}

	if (nic_micro_log_dbg == 1)
		microlog_info("nic_micro_log_dbg in!");

	/** String address must be greater than first line data address, and must be multiple of 4*/
	if (log_item->string_addr < NIC_MICRO_ASM_START_ADDR ||
	    log_item->func_name_addr < NIC_MICRO_ASM_START_ADDR) {
		microlog_err("string_addr[%x], func_name_addr[%x]",
			     log_item->string_addr, log_item->func_name_addr);
		return -EFAULT;
	}

	if (!log_info->micro_log_data_addr) {
		microlog_err("asm file has no data, micro_log_data_addr is NULL");
		return -EFAULT;
	}

	log_str = nic_micro_log_get_string_from_data(log_info, log_item->string_addr);
	log_file = nic_micro_log_get_string_from_data(log_info, log_item->func_name_addr);

	err = nic_micro_log_write_log_file(log_info, (u8 *)log_str, (u8 *)log_file, log_item);
	if (err != 0) {
		microlog_err("write log file fail.");
		return err;
	}

	if (nic_micro_log_dbg == 1)
		microlog_info("nic_micro_log_dbg out!");
	return 0;
}

int check_param_for_get_asm(struct micro_log_info *log_info)
{
	if (!log_info->fp_asm_file) {
		log_info->fp_asm_file = hinic5_file_open(asm_file_path);
		if (IS_ERR(log_info->fp_asm_file)) {
			microlog_err("Can't open /home/microcode.asm file.");
			log_info->fp_asm_file = NULL;
			return -EFAULT;
		}
	}
	return 0;
}

/*
 * Function : process_per_line_data
 * Description : process_per_line_data for function `nic_micro_log_get_asm_file_data`
 * Type : struct micro_log_info *log_info, u64 datalen
 * Input : void
 * Output : None
 * Return : void
 * Restriction :None
 * History :
 * 1.Date : 2016/3/6
 * Modification : Created function
 */
int process_per_line_data(struct micro_log_info *log_info, u32 all_line, u64 file_size)
{
	int read_byte;
	u32 i;
	u32 file_ops = 0;
	u64 datalen = 0;
	unsigned int addr;
	unsigned int data;
	char tmpbuf[MICRO_LOG_MAX_STRING_LEN] = {0};

	/* Get 4 bytes of data from each line */
	for (i = 0; i < all_line; i++) {
		read_byte = hinic5_file_read(log_info->fp_asm_file, tmpbuf, LINE_CHAR_NUM, &file_ops);
		if (read_byte < 0) {
			microlog_err("Can't read the cal data:%d from file %d.", read_byte, i);
			return -EFAULT;
		}

		if (read_byte < LINE_CHAR_NUM) {
			microlog_err("end file.");
			return 0;
		}

		(void)sscanf(tmpbuf, "%x : %x", &addr, &data);

		if (nic_micro_log_dbg == 1)
			microlog_info("0x%x", data);

		(void)snprintf((char *)(log_info->micro_log_data_addr + datalen),
			       file_size, "%c%c%c%c", (u8)(data >> 24),
			       (u8)((data & 0x00ff0000) >> 16),
			       (u8)((data & 0x0000ff00) >> 8), (u8)(data & 0xff));
		datalen += sizeof(data);

		if (file_size < datalen) {
			microlog_err("datalen too large");
			return -EFAULT;
		}
	}
	return 0;
}

/*
 * Function : nic_micro_log_get_asm_file_data
 * Description : get microcode.asm data
 * Type :
 * Input : void
 * Output : None
 * Return :
 * Restriction :
 * History :
 * 1.Date : 2016/3/6
 * Modification : Created function
 */
int nic_micro_log_get_asm_file_data(struct micro_log_info *log_info)
{
	u64 file_size;
	u32 all_line;
#if defined(HAVE_MM_SEGMENT_T)
	mm_segment_t old_fs;
#endif

	if (check_param_for_get_asm(log_info) != 0)
		return -EFAULT;

/*lint -save -e501*/
#if defined(HAVE_MM_SEGMENT_T)
#if !defined(CONFIG_UACCESS_MEMCPY) && !defined(CONFIG_SET_FS)
	old_fs = get_fs();
	set_fs(get_ds());
#elif defined(CONFIG_UACCESS_MEMCPY)
	old_fs = get_fs();
	set_fs(KERNEL_DS);
#elif defined(CONFIG_SET_FS)
	old_fs = force_uaccess_begin();
#endif
#endif
/*lint -restore*/

	file_size = hinic5_get_file_size(log_info->fp_asm_file);

	/* asm file each line is fixed at 20 bytes, file size is multiple of 20.
	 * The last line of asm file is time, no need to save in cache
	 */
	all_line = (u32)(file_size - LINE_CHAR_NUM) / LINE_CHAR_NUM;

	/* asm file one line valid string is 4 bytes, allocated memory only needs 1/5 of asm file */
	file_size = (file_size / LINE_CHAR_NUM) * 4;

	log_info->micro_log_data_addr = kzalloc((file_size + 1), GFP_KERNEL);
	if (!log_info->micro_log_data_addr)
		goto err_close_file;

	/*lint -save -e647*/
	hinic5_set_file_position(log_info->fp_asm_file, 0 * LINE_CHAR_NUM);
	/*lint -restore*/
	if (process_per_line_data(log_info, all_line, file_size) != 0) {
		microlog_err("process_per_line_data fail!");
		goto err_free_mem;
	}

#if defined(HAVE_MM_SEGMENT_T)
#if !defined(CONFIG_SET_FS)
	set_fs(old_fs);
#else
	force_uaccess_end(old_fs);
#endif
#endif

	microlog_info("%s success\n", __func__);
	return 0;

err_free_mem:
	if (log_info->micro_log_data_addr) {
		kfree((void *)(log_info->micro_log_data_addr));
		log_info->micro_log_data_addr = NULL;
	}

err_close_file:

#if defined(HAVE_MM_SEGMENT_T)
#if !defined(CONFIG_SET_FS)
	set_fs(old_fs);
#else
	force_uaccess_end(old_fs);
#endif
#endif
	hinic5_file_close(log_info->fp_asm_file);
	log_info->fp_asm_file = NULL;
	microlog_err("close microcode.asm!");
	return -EFAULT;
}

/*
 * Function : nic_micro_log_create_log_file
 * Description : create microlog.log file
 * Type :
 * Input : void
 * Output : None
 * Return :
 * Restriction :
 * History :
 * 1.Date : 2016/3/6
 * Modification : Created function
 */
int nic_micro_log_create_log_file(struct micro_log_info *log_info)
{
	char ulog_file_time[MAX_PATH_NAME] = {0};
	struct timeval txc;
	struct rtc_time time;
	u64 max_time_len;
	u64 path_len;
	u64 localtime;

	/* Get current UTC time */
	do_gettimeofday(&(txc));

	/* Convert UTC time to local time */
	hinic5_utctime_to_localtime(txc.tv_sec, &localtime);

	/* Calculate year, month, day and other time values into tm */
	rtc_time_to_tm(localtime, &time);

	path_len = strlen(log_file_path) - strlen(".log");
	(void)memcpy(ulog_file_time, log_file_path, path_len);

	max_time_len = MAX_PATH_NAME - path_len;
	(void)snprintf(ulog_file_time + path_len, max_time_len,
		"_%s_%04d_%02d_%02d_%02d_%02d_%02d.log",
		log_info->hinic_micro_log_task.name,
		time.tm_year + 1900,
		time.tm_mon + 1, time.tm_mday,
		time.tm_hour, time.tm_min, time.tm_sec);

	if (!log_info->fp_log_file) {
		log_info->fp_log_file = hinic5_file_creat(ulog_file_time);
		if (IS_ERR(log_info->fp_log_file)) {
			microlog_err("Can't create %s file", ulog_file_time);

			return -EFAULT;
		}
	}
	microlog_info("create %s file", ulog_file_time);

	return 0;
}

/*
 * Function : nic_micro_log_create_new_log_file
 * Description : create new microcode.log for overflow 1G
 * Type :
 * Input : void
 * Output : None
 * Return :
 * Restriction :
 * History :
 * 1.Date : 2016/3/6
 * Modification : Created function
 */
int nic_micro_log_create_new_log_file(struct micro_log_info *log_info)
{
	u32 file_size;

	char ulog_file_time[MAX_PATH_NAME] = {0};
	struct timeval txc;
	struct rtc_time time;
	u64 max_time_len;
	u64 path_len;
	u64 localtime;

	if (!log_info->fp_log_file) {
		microlog_err("fp_log_file is NULL!");
		return -EFAULT;
	}
	file_size = hinic5_get_file_size(log_info->fp_log_file);

	if ((MAX_SIZE_OF_LOG_FILE) <= file_size) {
		if (log_info->fp_log_file) {
			hinic5_file_close(log_info->fp_log_file);
			log_info->fp_log_file = NULL;
		}

		/* Get current UTC time */
		do_gettimeofday(&(txc));

		hinic5_utctime_to_localtime(txc.tv_sec, &localtime);

		/* Calculate year, month, day and other time values into tm */
		rtc_time_to_tm(localtime, &time);

		path_len = strlen(log_file_path) - strlen(".log");
		(void)memcpy(ulog_file_time, log_file_path, path_len);

		max_time_len = MAX_PATH_NAME - path_len;
		(void)snprintf(ulog_file_time + path_len, max_time_len,
			"_%s_%04d_%02d_%02d_%02d-%02d.log",
			log_info->hinic_micro_log_task.name,
			time.tm_year + 1900,
			time.tm_mon + 1, time.tm_mday,
			time.tm_hour, time.tm_min);

		log_info->fp_log_file = hinic5_file_creat(ulog_file_time);
		if (IS_ERR(log_info->fp_log_file)) {
			microlog_err("Can't create %s file!", ulog_file_time);
			return -EFAULT;
		}
	}
	return 0;
}

int hinic5_micro_log_init_cnt_set(void *hwdev)
{
	cmdq_microlog_ctrl_info_set_s microlog_ctrl_info = { { 0 } };
	size_t msg_len = sizeof(cmdq_microlog_ctrl_info_set_s);

	microlog_ctrl_info.microlog_init_flag = 1;

	return hinic5_set_microlog_cmdq(hwdev, (void *)&microlog_ctrl_info,
					msg_len, COMM_CMD_MICROLOG_CTRL_INFO_SET);
}

int hinic5_comm_micro_log_init(struct hinic5_hwdev *hwdev)
{
	int err = 0;

	if (!micro_log_en)
		return 0;

	if (hinic5_micro_log_init_cnt_set(hwdev) != 0) {
		microlog_warning("not again enable micro_log");
		return 0;
	}

	err = hinic5_micro_log_init(hwdev);
	if (err) {
		sdk_err(hwdev->dev_hdl, "Failed to initialize micro log\n");
		return err;
	}

	err = hinic5_micro_log_func_en(hwdev, 1);
	if (err) {
		sdk_warn(hwdev->dev_hdl, "Failed to enable micro log\n");
		return err;
	}

	err = micro_log_procfs_init(hwdev);
	return err;
}

/*
 * Function : hinic5_micro_log_init
 * Description : micro code's log init
 * Type : void
 * Input : void
 * Output : None
 * Return : int
 * Restriction :
 * History : void
 * 1.Date : 2015/8/15
 * Modification : Created function
 */
int hinic5_micro_log_init(void *hwdev)
{
	int ret = 0;
	u64 v_addr = 0;
	u64 p_addr = 0;
	u32 i;
	struct card_node *chip_node;
	struct micro_log_info *log_info;

	if (!hwdev) {
		microlog_err("hwdev is NULL!");
		return -EFAULT;
	}

	if (hinic5_ppf_idx(hwdev) != hinic5_global_func_id(hwdev)) {
		microlog_info("Only PPF support micro log init!");
		return 0;
	}

	chip_node = (struct card_node *)(((struct hinic5_hwdev *)hwdev)->chip_node);

	log_info = chip_node->log_info;
	if (log_info) {
		sdk_info(((struct hinic5_hwdev *)hwdev)->dev_hdl,
			 "%s(%d):NIC MICRO LOG has already init!\n",
			 __func__, __LINE__);
		return 0;
	}

	log_info = kzalloc(sizeof(*log_info), GFP_KERNEL);
	if (!log_info)
		return -ENOMEM;

	chip_node->log_info = log_info;

	/* Allocate 256*256*64B=4M space */
	for (i = 0; i < MICRO_LOG_MAX_QUEUE_NUM; i++) {
		v_addr = (u64)dma_zalloc_coherent(((struct hinic5_hwdev *)hwdev)->dev_hdl,
		    (unsigned long)(MICRO_LOG_MAX_QUEUE_DEPTH * MICRO_LOG_ITEM_LEN),
		    &p_addr, GFP_KERNEL);
		if (!v_addr) {
			sdk_err(((struct hinic5_hwdev *)hwdev)->dev_hdl,
				"%s(%d):NIC MICRO LOG alloc queue(%d) reosurce fail!\n",
				__func__, __LINE__, i);
			goto err_free_mem;
		}

		log_info->que_addr[MICRO_LOG_VIR_ADDR][i] = v_addr;
		log_info->que_addr[MICRO_LOG_PHY_ADDR][i] = p_addr;

		/* Maintain software side queue information BD */
		ret = hinic5_microlog_gpa_set(hwdev, p_addr, i);
		if (ret) {
			sdk_err(((struct hinic5_hwdev *)hwdev)->dev_hdl,
				"%s(%d):NIC MICRO LOG write table (Lt index%d)fail(%d)!\n",
				__func__, __LINE__, i, ret);

			dma_free_coherent(((struct hinic5_hwdev *)hwdev)->dev_hdl,
					  (unsigned long)(MICRO_LOG_MAX_QUEUE_DEPTH *
							  MICRO_LOG_ITEM_LEN),
					  (void *)v_addr, p_addr);
			v_addr = 0;
			p_addr = 0;
			log_info->que_addr[MICRO_LOG_VIR_ADDR][i] = v_addr;
			log_info->que_addr[MICRO_LOG_PHY_ADDR][i] = p_addr;
			goto err_free_mem;
		}
	}

	memset((void *)&log_info->log_stati_info, 0, sizeof(struct nic_micro_log_statistics_info));

	log_info->hwdev = hwdev;

	microlog_info("nic micro log init OK!");

	return 0;

err_free_mem:
	if (i == 0) {
		kfree(log_info);
		chip_node->log_info = NULL;
		return -ENOMEM;
	}
	/* first need i-1 */
	while (i--) {
		v_addr = log_info->que_addr[MICRO_LOG_VIR_ADDR][i];
		p_addr = log_info->que_addr[MICRO_LOG_PHY_ADDR][i];

		dma_free_coherent(((struct hinic5_hwdev *)hwdev)->dev_hdl,
				  (unsigned long)(MICRO_LOG_MAX_QUEUE_DEPTH * MICRO_LOG_ITEM_LEN),
				  (void *)v_addr, p_addr);

		v_addr = 0;
		p_addr = 0;

		log_info->que_addr[MICRO_LOG_VIR_ADDR][i] = v_addr;
		log_info->que_addr[MICRO_LOG_PHY_ADDR][i] = p_addr;
	}

	kfree(log_info);
	chip_node->log_info = NULL;
	return -ENOMEM;
}

static void micro_log_clear_ci_entry_data(struct micro_log_info *log_info)
{
	u32 lt_index;
	u32 lt_offset;
	size_t len = sizeof(micro_log_item_s);

	lt_index = (log_info->all_ci / MICRO_LOG_MAX_QUEUE_DEPTH) % MICRO_LOG_MAX_QUEUE_NUM;
	lt_offset = log_info->all_ci % MICRO_LOG_MAX_QUEUE_DEPTH;
	memset((micro_log_item_s *)(log_info->que_addr[MICRO_LOG_VIR_ADDR][lt_index] +
	       (lt_offset * MICRO_LOG_ITEM_LEN)), 0, len);
}

static void micro_log_get_ci_entry_data(struct micro_log_info *log_info, micro_log_item_s *log_item)
{
	u32 i;
	u32 lt_index;
	u32 lt_offset;
	size_t len = sizeof(micro_log_item_s);

	lt_index = (log_info->all_ci / MICRO_LOG_MAX_QUEUE_DEPTH) % MICRO_LOG_MAX_QUEUE_NUM;
	lt_offset = log_info->all_ci % MICRO_LOG_MAX_QUEUE_DEPTH;
	memcpy(log_item,
	       (micro_log_item_s *)(log_info->que_addr[MICRO_LOG_VIR_ADDR][lt_index] +
	       (lt_offset * MICRO_LOG_ITEM_LEN)), len);

	/* First do endian conversion for ctrl info */
	log_item->ctrl_info.value = ntohl(log_item->ctrl_info.value);
	/* Do endian conversion */
	log_item->string_addr = ntohl(log_item->string_addr);
	log_item->func_name_addr = ntohl(log_item->func_name_addr);
	for (i = 0; i < DFX_LOG_PRINT_MAX_PARA; i++)
		log_item->data[i] = ntohl(log_item->data[i]);
	log_item->line_and_pi.value = ntohl(log_item->line_and_pi.value);
}

int micro_log_file_size_check(struct hinic5_hwdev *hwdev, struct micro_log_info *log_info)
{
	int ret;

	ret = hinic5_microlog_ctrl_info_set(hwdev, log_info->nic_micro_log_enable,
					    log_info->all_ci, INFO_LOG_PRINT);
	if (ret) {
		sdk_err(((struct hinic5_hwdev *)hwdev)->dev_hdl, "%s(%d):Write table (It index 0)fail(%d), all_ci:0x%x\n",
			__func__, __LINE__, ret, log_info->all_ci);
		return ret;
	}

	ret = nic_micro_log_create_new_log_file(log_info);
	if (ret)
		sdk_err(((struct hinic5_hwdev *)hwdev)->dev_hdl,
			"%s(%d):nic_micro_log_create_new_log_file fail(%d)!\n",
			__func__, __LINE__, ret);
	return ret;
}

/*
 * Function : nic_micro_log_poll_recv
 * Description : poll receive micro log
 * Type : void
 * Input : void
 * Output : None
 * Return : void
 * Restriction :
 * History : None
 * 1.Date : 2015/8/15
 *  Modification : Created function
 */
static void nic_micro_log_poll_recv(void *hwdev)
{
	int ret;
	struct card_node *chip_node;
	struct micro_log_info *log_info;
	micro_log_item_s log_item;
	static u32 count;

	chip_node = (struct card_node *)(((struct hinic5_hwdev *)hwdev)->chip_node);
	log_info = chip_node->log_info;
	if (!log_info) {
		microlog_err("input param hwdev is illegal!");
		return;
	}

	if (log_info->nic_micro_log_enable == 0) {
		msleep(MICRO_LOG_POLLING_TIME * 1000);
		return;
	}

	while (log_info->nic_micro_log_enable != 0) {
		micro_log_get_ci_entry_data(log_info, &log_item);
		if (log_item.ctrl_info.bs.ctrl_flag == 0)
			break;

		// Parse log
		ret = nic_micro_log_parse_microcode_log(log_info, &log_item);
		if (ret != 0) {
			sdk_err(((struct hinic5_hwdev *)hwdev)->dev_hdl,
				"%s(%d):parse_microcode_log fail(%d)\n",
				__func__, __LINE__, ret);
			return;
		}

		// Clear corresponding buffer
		micro_log_clear_ci_entry_data(log_info);

		log_info->all_ci++;
		count++;
		poll_log_cnt++;
		log_info->log_stati_info.recv_log_num++;

		if (count >= MAX_NUM_OF_ONE_TIME_ULOG) {
			if (micro_log_file_size_check(hwdev, log_info) != 0) {
				sdk_err(((struct hinic5_hwdev *)hwdev)->dev_hdl,
					"%s(%d):micro_log_file_size_check fail.\n",
					__func__, __LINE__);
			} else {
				/* If processing is not successful, the reason poll_log_cnt cannot be cleared
				 * is to try updating ci and other operations again outside the while loop
				 */
				poll_log_cnt = 0;
			}
			count = 0;
			/* change the same priority task for avoiding long time only do this task */
			msleep(100);
		}

		if (count && (!(count % 100)))
			msleep(100);
	}

	/* The interface for updating ci changed from mbox to cmdq, there is a problem of log circular printing,
	 * so added interception: when log accumulates 16K, ci will be updated once
	 */
	if (poll_log_cnt >= MAX_NUM_OF_ONE_TIME_ULOG) {
		if (micro_log_file_size_check(hwdev, log_info) != 0) {
			sdk_err(((struct hinic5_hwdev *)hwdev)->dev_hdl,
				"%s(%d):micro_log_file_size_check fail.\n",
				__func__, __LINE__);
			return;
		}
		poll_log_cnt = 0;
	}

	/* polling timer */
	msleep(MICRO_LOG_POLLING_TIME);
}

static void nic_micro_log_disable_func(void *hwdev)
{
	struct card_node *chip_node;
	struct micro_log_info *log_info;

	chip_node = (struct card_node *)(((struct hinic5_hwdev *)hwdev)->chip_node);
	log_info = chip_node->log_info;

	/* Delete a thread in polling SM table */
	hinic5_stop_thread(&log_info->hinic_micro_log_task);

	hinic5_micro_log_reset(hwdev);

	/* Wait for loop task to stop recording logs, still need to wait 50ms delay */
	msleep(MICRO_LOG_POLLING_TIME * 50);

	if (log_info->fp_asm_file) {
		hinic5_file_close(log_info->fp_asm_file);
		log_info->fp_asm_file = NULL;
		microlog_info("close microcode.asm!");
	}
	if (log_info->micro_log_data_addr) {
		kfree((void *)log_info->micro_log_data_addr);
		log_info->micro_log_data_addr = NULL;
	}
	if (log_info->fp_log_file) {
		hinic5_file_close(log_info->fp_log_file);
		log_info->fp_log_file = NULL;
		microlog_info("close microcode.log!");
	}
}

static int hinic5_micro_log_ctr32_clear(void *hwdev, u8 cmd)
{
	struct hinic5_cmd_buf *cmd_buf = NULL;
	u64 out_param = 0;
	int err;

	if (hinic5_is_chip_present((struct hinic5_hwdev *)hwdev) == false) {
		microlog_warning("chip is absent, microlog not send cmdq to npu!");
		return 0;
	}

	cmd_buf = hinic5_alloc_cmd_buf(hwdev);
	if (!cmd_buf) {
		microlog_err("failed to allocate cmd buf!");
		return -ENOMEM;
	}

	cmd_buf->size = sizeof(u32);

	err = hinic5_cmdq_direct_resp(hwdev, HINIC5_MOD_COMM, cmd, cmd_buf,
				      &out_param, 0, HINIC5_CHANNEL_NIC);
	if ((err) || (out_param)) {
		microlog_err("failed to clear print cnt, err: %d,out_param: 0x%llx!",
			     err, out_param);
		err = -EFAULT;
	}

	hinic5_free_cmd_buf(hwdev, cmd_buf);

	return err;
}

int micro_log_get_asm_file(void *hwdev, struct micro_log_info *log_info)
{
	int ret = 0;

	if (micro_asm_mode == 1) {
		/* Method 1: Default get dictionary file from /home/microcode.asm */
		ret = nic_micro_log_get_asm_file_data(log_info);
	}

	if (ret != 0 || (micro_asm_mode == 0 && !log_info->micro_log_data_addr)) {
		/* Method 2: Method 1 failed (maybe internal processing failed
		 *		   or no microcode.asm file under home),
		 * or user manually selects to get dictionary file from flash
		 */
		ret = mirco_log_get_sim_data_from_flash((struct hinic5_hwdev *)hwdev, log_info);
	}
	return ret;
}

int nic_micro_log_enable_func(void *hwdev)
{
	int ret;
	struct card_node *chip_node;
	struct micro_log_info *log_info;

	if (!hwdev) {
		microlog_err("hwdev is NULL!");
		return -EFAULT;
	}

	chip_node = (struct card_node *)(((struct hinic5_hwdev *)hwdev)->chip_node);
	log_info = chip_node->log_info;

	hinic5_micro_log_reset(hwdev);

	ret = micro_log_get_asm_file(hwdev, log_info);
	if (ret) {
		microlog_err("micro_log_get_asm_file fail(0x%x)\n", ret);
		log_info->nic_micro_log_enable = 0;
		return ret;
	}

	log_info->hinic_micro_log_task.name = (char *)chip_node->chip_name;

	if (!log_info->fp_log_file) {
		ret = nic_micro_log_create_log_file(log_info);
		if (ret) {
			microlog_err("nic_micro_log_create_new_log_file fail(%d)!", ret);
			log_info->nic_micro_log_enable = 0;
			return ret;
		}
	}

	ret = hinic5_microlog_ctrl_info_set(hwdev, log_info->nic_micro_log_enable,
					    log_info->all_ci, INFO_LOG_PRINT);
	if (ret) {
		microlog_err("Write table (It index0)fail(%d)!", ret);
		return ret;
	}

	log_info->hinic_micro_log_task.data = hwdev;
	log_info->hinic_micro_log_task.thread_fn = nic_micro_log_poll_recv;

	ret = hinic5_creat_thread(&log_info->hinic_micro_log_task);
	if (ret) {
		microlog_err("NIC MICRO LOG create thread fail(%d)!", ret);
		return ret;
	}

	return 0;
}

int hinic5_micro_log_func_en(void *hwdev, u8 is_en)
{
	int ret;
	struct card_node *chip_node;
	struct micro_log_info *log_info;

	if (!hwdev) {
		microlog_err("handle is NULL!");
		return -EFAULT;
	}

	if (is_en > 1) {
		microlog_err("is_en(%u) beyond 1!", is_en);
		return -EFAULT;
	}

	chip_node = (struct card_node *)(((struct hinic5_hwdev *)hwdev)->chip_node);
	log_info = chip_node->log_info;

	if (!log_info) {
		microlog_err("micro log is not init!");
		return -EFAULT;
	}

	if (log_info->nic_micro_log_enable == is_en) {
		microlog_err("micro log is already open or close!");
		return 0;
	}

	log_info->nic_micro_log_enable = is_en;

	if (is_en) {
		ret = nic_micro_log_enable_func(hwdev);
		if (ret) {
			microlog_err("nic_micro_log_enable_func fail!");
			return -EFAULT;
		}
	} else {
		nic_micro_log_disable_func(hwdev);
	}

	microlog_info("micro log func is %s\n", is_en ? "enable" : "disable");

	return 0;
}

/*
 * Function : hinic5_micro_log_uninit
 * Description : nic micro code log uninit
 * Type : void
 * Input : eal_handle handle
 * Output : None
 * Return : void
 * Restriction :Null
 * History : None
 * 1.Date : 2015/9/2
 * Modification : Created function
 */
void hinic5_micro_log_uninit(void *hwdev)
{
	int ret;
	u64 v_addr = 0;
	u64 p_addr = 0;
	u32 i;
	struct card_node *chip_node;
	struct micro_log_info *log_info;

	if (!micro_log_en)
		return;

	if (!hwdev) {
		microlog_err("hwdev is NULL!");
		return;
	}

	chip_node = (struct card_node *)(((struct hinic5_hwdev *)hwdev)->chip_node);
	log_info = chip_node->log_info;
	if (!log_info) {
		microlog_warning("micro log is not init!");
		return;
	}

	if (log_info->hwdev != hwdev) {
		microlog_err("micro log is not init in this function!");
		return;
	}

	ret = hinic5_micro_log_func_en(hwdev, 0);
	if (ret)
		microlog_warning("hinic5_micro_log_func_en fail (%d)!", ret);

	/* Free 256*64B*192 space */
	for (i = 0; i < MICRO_LOG_MAX_QUEUE_NUM; i++) {
		v_addr = log_info->que_addr[MICRO_LOG_VIR_ADDR][i];
		p_addr = log_info->que_addr[MICRO_LOG_PHY_ADDR][i];
		dma_free_coherent(((struct hinic5_hwdev *)log_info->hwdev)->dev_hdl,
				  (unsigned long)(MICRO_LOG_MAX_QUEUE_DEPTH * MICRO_LOG_ITEM_LEN),
				  (void *)v_addr, (dma_addr_t)p_addr);
		log_info->que_addr[MICRO_LOG_VIR_ADDR][i] = 0;
		log_info->que_addr[MICRO_LOG_PHY_ADDR][i] = 0;

		/* Update queue information to SM table, call chip interface */
		ret = hinic5_microlog_gpa_set(hwdev, 0 /* p_addr */, i);
		if (ret != 0)
			microlog_warning("Write table (It index%d)fail(%d)!", i, ret);
	}

	kfree(log_info);
	chip_node->log_info = NULL;

	micro_log_procfs_exit();
}

void hinic5_micro_log_reset(void *hwdev)
{
	int ret;
	u64 v_addr = 0;
	u32 i;
	struct card_node *chip_node;
	struct micro_log_info *log_info;

	chip_node = (struct card_node *)(((struct hinic5_hwdev *)hwdev)->chip_node);
	log_info = chip_node->log_info;
	if (!log_info) {
		microlog_err("x86 micro log is not init");
		return;
	}

	/* Maintain software side queue information BD */
	ret = hinic5_microlog_ctrl_info_set(hwdev, log_info->nic_micro_log_enable,
					    0 /* ci_index */, INFO_LOG_PRINT);
	if (ret) {
		microlog_err("Write table (It index 0)fail(%d)!", ret);
		return;
	}

	for (i = 0; i < MICRO_LOG_MAX_QUEUE_NUM; i++) {
		v_addr = log_info->que_addr[MICRO_LOG_VIR_ADDR][i];
		memset((void *)v_addr, 0,
		       (unsigned long)(MICRO_LOG_MAX_QUEUE_DEPTH * MICRO_LOG_ITEM_LEN));
	}

	ret = hinic5_micro_log_ctr32_clear(hwdev, COMM_CMD_MICROLOG_PRINT_CNT_CLEAR);
	if (ret) {
		microlog_err("Read ctr (It index 0)fail(%d)!", ret);
		return;
	}
}
