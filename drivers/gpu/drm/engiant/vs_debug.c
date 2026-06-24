// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2020 VeriSilicon Holdings Co., Ltd.
 */

#include <linux/time.h>
#include <linux/moduleparam.h>
#include <linux/interrupt.h>
#include <linux/slab.h>
#include <linux/ctype.h>
#include <linux/string.h>
#include "vs_debug.h"

#define WRITE_CMD kernel_write

static const char buf[] = "CFG_APB_WR 'h";
static const char buf1[] = "REG_APB_RD 'h";
static const char buf2[] = " 'h";
static const char buf3[] = "\n";

/* for capture dump */
static char log_file_name[256];

/* for capture dump */
static char *capture_path = "/root/";
module_param(capture_path, charp, 0);
MODULE_PARM_DESC(capture_path, "A string passed to the DC capture dump path");

struct _vs_debug_reg {
	u32 addr;
	u32 value;
	bool is_read;
};

struct _vs_debug_intr {
	char event[MAX_DC_INTR_EVENT_SIZE - 20];
	u8 intr_dest;
	enum vs_debug_intr_partition part;
	bool multi_dest;
};

struct _vs_debug_info {
	union {
		struct _vs_debug_intr intr;
		struct _vs_debug_reg reg;
	} info;
	bool is_intr;
};

static struct _vs_debug_info debug_cache[512];
static u32 index;

int vs_egt_debug_file_create(struct file **fp)
{
	struct timespec64 ts;
	ktime_t kt;
	struct tm tm_time;
	char time_str[13];
	int offset;

	if (!capture_path) {
		pr_err("Please specify the path to the capture dump.\n");
		return -1;
	}

	kt = ktime_get_real();
	ts = ktime_to_timespec64(kt);
	time64_to_tm(ts.tv_sec, 0, &tm_time);
	snprintf(time_str, sizeof(time_str), "%02d%02d%02d%02d", tm_time.tm_mday, tm_time.tm_hour,
		 tm_time.tm_min, tm_time.tm_sec);

	offset = snprintf(log_file_name, 256, "%s/Main_Process_%s.txt", capture_path, time_str);

	if (offset > 256) {
		pr_err("Buffer overflow when creating the vs debug file.\n");
		return -1;
	}

	*fp = filp_open(log_file_name, O_RDWR | O_CREAT, 0644);

	if (IS_ERR(*fp)) {
		pr_err("Failed to open the capture path: %s, ret:%d\n", log_file_name, -1);
		return -1;
	}

	return 0;
}

void vs_egt_debug_file_close(struct file **fp)
{
	if (*fp)
		filp_close(*fp, NULL);
}

int vs_egt_debug_reset(struct file **fp)
{
	vs_egt_debug_file_close(fp);
	if (vs_egt_debug_file_create(fp)) {
		pr_err("Failed to reset the vs debug file: ret:%d\n", -1);
		return -1;
	}

	return 0;
}

static void _reverse_str(char *source, char target[], uint length)
{
	uint i;

	for (i = 0; i < length; i++)
		target[i] = source[length - 1 - i];
	target[i] = 0;
}

static void _to_hex(uint num, char hex_str[])
{
	u32 n = num;
	char hextable[] = "0123456789abcdef";
	char temphex[16], hex[16];
	uint i = 0;
	int index = 0;
	int j, k;

	while (n) {
		temphex[i++] = hextable[n % 16];
		n /= 16;
	}

	temphex[i] = 0;
	_reverse_str(temphex, hex, i);
	for (j = 0; j < 8 - i; ++j, index++)
		hex_str[j] = '0';

	for (k = 0; k < i; ++k)
		hex_str[index++] = hex[k];
	hex_str[index] = 0;
}

static void _flush_reg_to_disk(struct file *fp, u32 addr, u32 value, bool is_read)
{
	char addr_str[9];
	char data_str[9];
	loff_t pos;

	_to_hex(addr, addr_str);
	_to_hex(value, data_str);

	if (!fp)
		return;

	pos = fp->f_pos;
	if (is_read)
		WRITE_CMD(fp, buf1, sizeof(buf1) - 1, &pos);
	else
		WRITE_CMD(fp, buf, sizeof(buf) - 1, &pos);
	fp->f_pos = pos;

	pos = fp->f_pos;
	WRITE_CMD(fp, addr_str, 8, &pos);
	fp->f_pos = pos;

	pos = fp->f_pos;
	WRITE_CMD(fp, buf2, sizeof(buf2) - 1, &pos);
	fp->f_pos = pos;

	pos = fp->f_pos;
	WRITE_CMD(fp, data_str, 8, &pos);
	fp->f_pos = pos;

	pos = fp->f_pos;
	WRITE_CMD(fp, buf3, sizeof(buf3) - 1, &pos);
	fp->f_pos = pos;
}

static void _flush_intr_to_disk(struct file *fp, const char *event,
				enum vs_debug_intr_partition part, bool multi_dest, u8 intr_dest)
{
	char buffer[MAX_DC_INTR_EVENT_SIZE] = { 0 };
	char result[MAX_DC_INTR_EVENT_SIZE] = { 0 };
	char *pos = NULL;
	char *temp = NULL;
	char *next_char = NULL;
	char *num_start = NULL;
	char number[4];
	char *part_name[3] = { "irq_dpu_fe0_", "irq_dpu_fe1_", "irq_dpu_be_" };
	char *dest_name[4] = { "NS", "TZ", "GSA", "AOC" };
	size_t len = 0;
	int index = 0;
	int j = 0;
	int len_num = 0;

	if (!fp || !event || intr_dest > 3) {
		pr_err("%s: invalid input param", __func__);
		return;
	}

	/* reserve some space for adding strings */
	len = strnlen(event, MAX_DC_INTR_EVENT_SIZE - 20);
	if (len >= MAX_DC_INTR_EVENT_SIZE - 20) {
		pr_err("%s: input event length overflow", __func__);
		return;
	}

	memset(buffer, 0, MAX_DC_INTR_EVENT_SIZE);
	memset(result, 0, MAX_DC_INTR_EVENT_SIZE);

	strscpy(buffer, event, len);
	buffer[len] = '\0';

	/* convert input string to lowercase */
	for (j = 0; j < len; j++)
		buffer[j] = tolower(buffer[j]);

	/* replace "dcreg" with "irq_dpu" */
	temp = buffer;
	index = 0;
	pos = strstr(buffer, "dcreg");
	if (pos != NULL) {
		strscpy(result + index, buffer, pos - buffer);
		index += pos - buffer;
		strscpy(result + index, "irq_dpu", MAX_DC_INTR_EVENT_SIZE - index);
		index += strlen("irq_dpu");
		temp = pos + strlen("dcreg");
	}
	strscpy(result + index, temp, strlen(temp));

	memset(buffer, 0, MAX_DC_INTR_EVENT_SIZE);
	strscpy(buffer, result, strnlen(result, MAX_DC_INTR_EVENT_SIZE - 1));
	memset(result, 0, MAX_DC_INTR_EVENT_SIZE);

	/* remove "intr_status(1/2/3/...)_" */
	temp = buffer;
	index = 0;
	pos = strstr(buffer, "intr_status");
	if (pos != NULL) {
		strscpy(result + index, buffer, pos - buffer);
		index += pos - buffer;
		next_char = pos + strlen("intr_status");
		while (*next_char >= '0' && *next_char <= '9')
			next_char++;

		if (*next_char == '_')
			next_char++;

		temp = next_char;
	}
	strscpy(result + index, temp, strlen(temp));

	memset(buffer, 0, MAX_DC_INTR_EVENT_SIZE);
	strscpy(buffer, result, strnlen(result, MAX_DC_INTR_EVENT_SIZE - 1));
	memset(result, 0, MAX_DC_INTR_EVENT_SIZE);

	/* handle trailing number */
	pos = buffer + strnlen(buffer, MAX_DC_INTR_EVENT_SIZE - 1) - 1;
	if (pos >= buffer && (*pos >= '0' && *pos <= '9')) {
		num_start = pos;
		while (num_start >= buffer && (*num_start >= '0' && *num_start <= '9'))
			num_start--;

		num_start++;
		len_num = pos - num_start + 1;

		/* 0 - 999, should be enough */
		if (len_num < 4) {
			strscpy(number, num_start, len_num);
			number[len_num] = '\0';
			snprintf(num_start, len_num + 2 + 1, "[%s]", number);
		}
	}

	/* add tag for different intr dest */
	if (multi_dest) {
		if (part == VS_DEBUG_INTR_BE || intr_dest < 3) {
			pos = strstr(buffer, part_name[part]);
			if (pos != NULL) {
				index = 0;
				pos += strlen(part_name[part]);
				strscpy(result + index, buffer, pos - buffer);
				index += pos - buffer;
				strscpy(result + index, dest_name[intr_dest],
						MAX_DC_INTR_EVENT_SIZE - index);
				index += strlen(dest_name[intr_dest]);
				strscpy(result + index, "_", MAX_DC_INTR_EVENT_SIZE - index);
				index += strlen("_");
				strscpy(result + index, pos, strlen(pos));

				memset(buffer, 0, MAX_DC_INTR_EVENT_SIZE);
				strscpy(buffer, result,
					strnlen(result, MAX_DC_INTR_EVENT_SIZE - 1));
				memset(result, 0, MAX_DC_INTR_EVENT_SIZE);
			}
		} else {
			pr_err("%s: there is no fourth intr dest for FE0/1", __func__);
		}
	}

	snprintf(result, MAX_DC_INTR_EVENT_SIZE, "INTR %s 1\n", buffer);

	if (WRITE_CMD(fp, result, strnlen(result, MAX_DC_INTR_EVENT_SIZE - 1), &fp->f_pos) !=
		strnlen(result, MAX_DC_INTR_EVENT_SIZE - 1))
		pr_err("%s: failed to write data to capture", __func__);
}

static void _flush_to_disk(struct file *fp)
{
	u32 i = 0;

	if (irqs_disabled())
		return;
	if (!fp) {
		pr_err("%s: invalid file pointer", __func__);
		return;
	}

	for (i = 0; i < index && i < 512; i++) {
		if (debug_cache[i].is_intr)
			_flush_intr_to_disk(fp, debug_cache[i].info.intr.event,
						debug_cache[i].info.intr.part,
						debug_cache[i].info.intr.multi_dest,
						debug_cache[i].info.intr.intr_dest);
		else
			_flush_reg_to_disk(fp, debug_cache[i].info.reg.addr,
					   debug_cache[i].info.reg.value,
					   debug_cache[i].info.reg.is_read);
	}
	index = 0;
}

void vs_egt_debug_dump_capture(struct file *fp, u32 addr, u32 value, bool is_read)
{
	if (irqs_disabled()) {
		if (index < 512) {
			debug_cache[index].is_intr = false;
			debug_cache[index].info.reg.addr = addr;
			debug_cache[index].info.reg.value = value;
			debug_cache[index].info.reg.is_read = is_read;
			index++;
		} else {
			pr_err("Debug capture dump, out of cache: addr = %08x, value = %08x\n",
				   addr, value);
			return;
		}
	} else {
		if (index)
			_flush_to_disk(fp);

		_flush_reg_to_disk(fp, addr, value, is_read);
	}
}

void vs_egt_debug_dump_interrupt(struct file *fp, const char *event,
				enum vs_debug_intr_partition part,
				bool multi_dest, u8 intr_dest)
{
	size_t len = 0;

	if (!fp || !event || intr_dest > 3) {
		pr_err("%s: invalid input param", __func__);
		return;
	}

	/* reserve some space for adding strings */
	len = strnlen(event, MAX_DC_INTR_EVENT_SIZE - 20);
	if (len >= MAX_DC_INTR_EVENT_SIZE - 20) {
		pr_err("%s: input event length overflow", __func__);
		return;
	}

	if (irqs_disabled()) {
		if (index < 512) {
			debug_cache[index].is_intr = true;
			debug_cache[index].info.intr.part = part;
			debug_cache[index].info.intr.multi_dest = multi_dest;
			debug_cache[index].info.intr.intr_dest = intr_dest;
			strscpy(debug_cache[index].info.intr.event, event, len);
			debug_cache[index].info.intr.event[len] = '\0';
			index++;
		} else {
			pr_err("Debug intr dump, out of cache: event is %s\n", event);
			return;
		}
	} else {
		if (index)
			_flush_to_disk(fp);

		_flush_intr_to_disk(fp, event, part, multi_dest, intr_dest);
	}
}
