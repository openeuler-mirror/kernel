/* SPDX-License-Identifier: GPL-2.0 */
/* Huawei iBMA driver.
 * Copyright (c) 2017, Huawei Technologies Co., Ltd.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#ifndef _KBOX_RAM_OP_H_
#define _KBOX_RAM_OP_H_

#include <asm/ioctls.h>
#include <linux/fs.h>
#include "kbox_printk.h"

#define KBOX_IOC_MAGIC (0xB2)

#define GET_KBOX_TOTAL_LEN _IOR(KBOX_IOC_MAGIC, 0, unsigned long)

#define GET_KBOX_REGION_USER_LEN  _IOR(KBOX_IOC_MAGIC, 1, unsigned long)

#define CLEAR_KBOX_REGION_ALL _IO(KBOX_IOC_MAGIC, 2)

#define CLEAR_KBOX_REGION_USER _IO(KBOX_IOC_MAGIC, 3)

#define KBOX_REGION_READ _IOR(KBOX_IOC_MAGIC, 4, struct kbox_region_arg_s)

#define KBOX_REGION_WRITE _IOW(KBOX_IOC_MAGIC, 5, struct kbox_region_arg_s)

#define KBOX_IOC_MAXNR 6

#define TEMP_BUF_SIZE (32 * 1024)
#define TEMP_BUF_DATA_SIZE (128 * 1024)
#define KBOX_RW_UNIT 4

struct kbox_region_arg_s {
	unsigned long offset;
	unsigned int count;
	char *data;
};

enum kbox_section_e;

int kbox_read_op(long long offset, unsigned int count, char __user *data,
		 enum kbox_section_e section);
int kbox_write_op(long long offset, unsigned int count,
		  const char __user *data, enum kbox_section_e section);
int kbox_read_super_block(void);
int kbox_super_block_init(void);
int kbox_write_panic_info(const char *input_data, unsigned int data_len);
int kbox_write_thread_info(const char *input_data, unsigned int data_len);
int kbox_write_printk_info(const char *input_data,
			   struct printk_ctrl_block_tmp_s
			   *printk_ctrl_block_tmp);
int kbox_read_printk_info(char *input_data,
			  struct printk_ctrl_block_tmp_s
			  *printk_ctrl_block_tmp);
int kbox_ioctl_detail(unsigned int cmd, unsigned long arg);
int kbox_mmap_ram(struct file *file, struct vm_area_struct *vma,
		  enum kbox_section_e section);
char kbox_checksum(const char *input_buf, unsigned int len);
int kbox_write_to_ram(unsigned long offset, unsigned int count,
		      const char *data, enum kbox_section_e section);
int kbox_read_from_ram(unsigned long offset, unsigned int count, char *data,
		       enum kbox_section_e section);
int kbox_clear_region(enum kbox_section_e section);
int kbox_memset_ram(unsigned long offset, unsigned int count,
		    const char set_byte, enum kbox_section_e section);

#endif
