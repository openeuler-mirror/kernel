// SPDX-License-Identifier: GPL-2.0
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

#include <linux/version.h>
#include <linux/semaphore.h>
#include <linux/slab.h>
#include <linux/capability.h>
#include <linux/uaccess.h>		/* copy_*_user */
#include <linux/delay.h>		/* udelay */
#include <linux/mm.h>
#include "kbox_include.h"
#include "kbox_main.h"
#include "kbox_ram_image.h"
#include "kbox_ram_op.h"

#ifndef VM_RESERVED
#define VM_RESERVED 0x00080000
#endif

static DEFINE_SPINLOCK(g_kbox_super_block_lock);
static DEFINE_SEMAPHORE(user_sem, 1);

union char_int_transfer_u {
	int data_int;
	char data_char[KBOX_RW_UNIT];
};

static struct image_super_block_s g_kbox_super_block = { };

void kbox_write_to_pci(void __iomem *dest, const void *src, int len,
		       unsigned long offset)
{
	union char_int_transfer_u transfer = { };
	int idx = 0;
	int j = 0;
	int four_byte_len = 0;
	int left_len = 0;
	char *src_temp = (char *)src;
	char *dest_temp = (char *)dest;
	int first_write_num = 0;

	if ((offset % KBOX_RW_UNIT) != 0) {
		transfer.data_int =
		    *(int *)(dest_temp + offset - (offset % KBOX_RW_UNIT));

		rmb();/* memory barriers. */
		first_write_num =
		    ((len + (offset % KBOX_RW_UNIT)) >
		     KBOX_RW_UNIT) ? (KBOX_RW_UNIT -
				      (offset % KBOX_RW_UNIT)) : len;
		for (idx = (int)(offset % KBOX_RW_UNIT);
		     idx < (int)(first_write_num + (offset % KBOX_RW_UNIT));
		     idx++) {
			if (!src_temp)
				return;

			transfer.data_char[idx] = *src_temp;
			src_temp++;
		}
		*(int *)(dest_temp + offset - (offset % KBOX_RW_UNIT)) =
		    transfer.data_int;
		wmb();/* memory barriers. */
		len -= first_write_num;
		offset += first_write_num;
	}

	four_byte_len = (len / KBOX_RW_UNIT);
	left_len = (len % KBOX_RW_UNIT);
	for (idx = 0; idx < four_byte_len; idx++) {
		for (j = 0; j < KBOX_RW_UNIT; j++) {
			if (!src_temp)
				return;

			transfer.data_char[j] = *src_temp;
			src_temp++;
		}
		*(int *)(dest_temp + offset) = transfer.data_int;
		wmb();/* memory barriers. */
		offset += KBOX_RW_UNIT;
	}

	if (left_len != 0) {
		transfer.data_int = *(int *)(dest_temp + offset);
		rmb();/* memory barriers. */
		for (idx = 0; idx < left_len; idx++) {
			if (!src_temp)
				return;

			transfer.data_char[idx] = *src_temp;
			src_temp++;
		}
		*(int *)(dest_temp + offset) = transfer.data_int;
		wmb();/* memory barriers. */
	}

	udelay(1);
}

void kbox_read_from_pci(void *dest, void __iomem *src, int len,
			unsigned long offset)
{
	union char_int_transfer_u transfer = { };
	int idx = 0;
	int j = 0;
	int four_byte_len = 0;
	int left_len = 0;
	char *dest_temp = (char *)dest;
	char *src_temp = (char *)src;
	int first_read_num = 0;

	if ((offset % KBOX_RW_UNIT) != 0) {
		transfer.data_int =
		    *(int *)(src_temp + offset - (offset % KBOX_RW_UNIT));
		first_read_num =
		    ((len + (offset % KBOX_RW_UNIT)) >
		     KBOX_RW_UNIT) ? (KBOX_RW_UNIT -
				      (offset % KBOX_RW_UNIT)) : len;
		rmb();/* memory barriers. */
		for (idx = (int)(offset % KBOX_RW_UNIT);
		     idx < (int)(first_read_num + (offset % KBOX_RW_UNIT));
		     idx++) {
			if (!dest_temp)
				return;

			*dest_temp = transfer.data_char[idx];
			dest_temp++;
		}
		len -= first_read_num;
		offset += first_read_num;
	}

	four_byte_len = (len / KBOX_RW_UNIT);
	left_len = (len % KBOX_RW_UNIT);
	for (idx = 0; idx < four_byte_len; idx++) {
		transfer.data_int = *(int *)(src_temp + offset);
		rmb();/* memory barriers. */
		for (j = 0; j < KBOX_RW_UNIT; j++) {
			if (!dest_temp)
				return;

			*dest_temp = transfer.data_char[j];
			dest_temp++;
		}
		offset += KBOX_RW_UNIT;
	}

	if (left_len != 0) {
		transfer.data_int = *(int *)(src_temp + offset);
		rmb();/* memory barriers. */
		for (idx = 0; idx < left_len; idx++) {
			if (!dest_temp)
				return;

			*dest_temp = transfer.data_char[idx];
			dest_temp++;
		}
	}
}

void kbox_memset_pci(void __iomem *dest, const char set_byte, int len,
		     unsigned long offset)
{
	union char_int_transfer_u transfer = { };
	int idx = 0;
	int four_byte_len = 0;
	int left_len = 0;
	char *dest_temp = (char *)dest;
	int first_memset_num = 0;

	if ((offset % KBOX_RW_UNIT) != 0) {
		transfer.data_int =
		    *(int *)(dest_temp + offset - (offset % KBOX_RW_UNIT));
		rmb();/* memory barriers. */
		first_memset_num =
		    ((len + (offset % KBOX_RW_UNIT)) >
		     KBOX_RW_UNIT) ? (KBOX_RW_UNIT -
				      (offset % KBOX_RW_UNIT)) : len;
		for (idx = (int)(offset % KBOX_RW_UNIT);
		     idx < (int)(first_memset_num + (offset % KBOX_RW_UNIT));
		     idx++) {
			transfer.data_char[idx] = set_byte;
		}
		*(int *)(dest_temp + offset - (offset % KBOX_RW_UNIT)) =
		    transfer.data_int;
		wmb();/* memory barriers. */
		len -= first_memset_num;
		offset += first_memset_num;
	}

	four_byte_len = (len / KBOX_RW_UNIT);
	left_len = (len % KBOX_RW_UNIT);
	for (idx = 0; idx < KBOX_RW_UNIT; idx++)
		transfer.data_char[idx] = set_byte;

	for (idx = 0; idx < four_byte_len; idx++) {
		*(int *)(dest_temp + offset) = transfer.data_int;
		wmb();/* memory barriers. */
		offset += KBOX_RW_UNIT;
	}

	if (left_len != 0) {
		transfer.data_int = *(int *)(dest_temp + offset);
		rmb();/* memory barriers. */
		for (idx = 0; idx < left_len; idx++)
			transfer.data_char[idx] = set_byte;

		*(int *)(dest_temp + offset) = transfer.data_int;
		wmb();/* memory barriers. */
	}

	udelay(1);
}

int kbox_read_from_ram(unsigned long offset, unsigned int count, char *data,
		       enum kbox_section_e  section)
{
	unsigned int read_len_total = count;
	unsigned long offset_temp = offset;
	void __iomem *kbox_section_addr = kbox_get_section_addr(section);
	unsigned long kbox_section_len = kbox_get_section_len(section);
	unsigned int read_len_real = 0;

	if (!data) {
		KBOX_MSG("input NULL point!\n");
		return -EFAULT;
	}

	if (!kbox_section_addr || kbox_section_len == 0) {
		KBOX_MSG("get kbox_section_addr or kbox_section_len failed!\n");
		return -EFAULT;
	}

	if (offset >= kbox_section_len) {
		KBOX_MSG("input offset is error!\n");
		return -EFAULT;
	}

	if ((offset + count) > kbox_section_len)
		read_len_total = (unsigned int)(kbox_section_len - offset);

	while (1) {
		unsigned int read_bytes = 0;

		if (read_len_real >= count)
			break;

		read_bytes =
		    (read_len_total >
		     TEMP_BUF_SIZE) ? TEMP_BUF_SIZE : read_len_total;

		kbox_read_from_pci(data, kbox_section_addr, read_bytes,
				   offset_temp);

		read_len_total -= read_bytes;
		read_len_real += read_bytes;
		data += read_bytes;
		offset_temp += read_bytes;
	}

	return (int)read_len_real;
}

int kbox_write_to_ram(unsigned long offset, unsigned int count,
		      const char *data, enum kbox_section_e  section)
{
	unsigned int write_len_total = count;
	unsigned long offset_temp = offset;
	void __iomem *kbox_section_addr = kbox_get_section_addr(section);
	unsigned long kbox_section_len = kbox_get_section_len(section);
	unsigned int write_len_real = 0;

	if (!data) {
		KBOX_MSG("input NULL point!\n");
		return -EFAULT;
	}

	if (!kbox_section_addr || kbox_section_len == 0) {
		KBOX_MSG("get kbox_section_addr or kbox_section_len failed!\n");
		return -EFAULT;
	}

	if (offset >= kbox_section_len) {
		KBOX_MSG("input offset is error!\n");
		return -EFAULT;
	}

	if ((offset + count) > kbox_section_len)
		write_len_total = (unsigned int)(kbox_section_len - offset);

	KBOX_MSG("struct image_super_block_s = %x\n", count);
	while (1) {
		unsigned int write_bytes = 0;

		if (write_len_real >= count) {
			KBOX_MSG("write_len_real = %x\n", write_len_real);
			break;
		}
		KBOX_MSG("write_len_total = %x\n", write_len_total);

		write_bytes =
		    (write_len_total >
		     TEMP_BUF_SIZE) ? TEMP_BUF_SIZE : write_len_total;
		KBOX_MSG("write_bytes = %x\n", write_bytes);

		kbox_write_to_pci(kbox_section_addr, data, write_bytes,
				  offset_temp);

		write_len_total -= write_bytes;
		write_len_real += write_bytes;
		data += write_bytes;
		offset_temp += write_bytes;
	}

	return (int)write_len_real;
}

int kbox_memset_ram(unsigned long offset, unsigned int count,
		    const char set_byte, enum kbox_section_e  section)
{
	unsigned int memset_len = count;
	void __iomem *kbox_section_addr = kbox_get_section_addr(section);
	unsigned long kbox_section_len = kbox_get_section_len(section);

	if (!kbox_section_addr || kbox_section_len == 0) {
		KBOX_MSG("get kbox_section_addr or kbox_section_len failed!\n");
		return -EFAULT;
	}

	if (offset >= kbox_section_len) {
		KBOX_MSG("input offset is error!\n");
		return -EFAULT;
	}

	if ((offset + count) > kbox_section_len)
		memset_len = (unsigned int)(kbox_section_len - offset);

	kbox_memset_pci(kbox_section_addr, set_byte, memset_len, offset);

	return KBOX_TRUE;
}

int kbox_read_op(long long offset, unsigned int count, char __user *data,
		 enum kbox_section_e  section)
{
	unsigned int read_bytes = 0;
	unsigned int read_len = 0;
	unsigned int left_len = count;
	char *user_buf = data;
	char *temp_buf_char = NULL;
	unsigned long offset_tmp = offset;

	if (!data) {
		KBOX_MSG("input NULL point!\n");
		return -EFAULT;
	}

	if (down_interruptible(&user_sem) != 0)
		return KBOX_FALSE;

	temp_buf_char = kmalloc(TEMP_BUF_DATA_SIZE, GFP_KERNEL);
	if (!temp_buf_char) {
		KBOX_MSG("kmalloc temp_buf_char fail!\n");
		up(&user_sem);
		return -ENOMEM;
	}

	memset((void *)temp_buf_char, 0, TEMP_BUF_DATA_SIZE);

	while (1) {
		if (read_len >= count)
			break;

		read_bytes =
		    (left_len >
		     TEMP_BUF_DATA_SIZE) ? TEMP_BUF_DATA_SIZE : left_len;

		if (kbox_read_from_ram
		    (offset_tmp, read_bytes, temp_buf_char, section) < 0) {
			KBOX_MSG("kbox_read_from_ram fail!\n");
			break;
		}

		if (copy_to_user(user_buf, temp_buf_char, read_bytes)) {
			KBOX_MSG("copy_to_user fail!\n");
			break;
		}

		left_len -= read_bytes;
		read_len += read_bytes;
		user_buf += read_bytes;

		offset_tmp += read_bytes;
		memset((void *)temp_buf_char, 0, TEMP_BUF_DATA_SIZE);

		msleep(20);
	}

	kfree(temp_buf_char);

	up(&user_sem);

	return (int)read_len;
}

int kbox_write_op(long long offset, unsigned int count,
		  const char __user *data, enum kbox_section_e  section)
{
	unsigned int write_len = 0;
	unsigned int left_len = count;
	const char *user_buf = data;
	char *temp_buf_char = NULL;
	unsigned long offset_tmp = offset;

	if (!data) {
		KBOX_MSG("input NULL point!\n");
		return -EFAULT;
	}

	if (down_interruptible(&user_sem) != 0)
		return KBOX_FALSE;

	temp_buf_char = kmalloc(TEMP_BUF_DATA_SIZE, GFP_KERNEL);
	if (!temp_buf_char) {
		KBOX_MSG("kmalloc temp_buf_char fail!\n");
		up(&user_sem);
		return -ENOMEM;
	}

	memset((void *)temp_buf_char, 0, TEMP_BUF_DATA_SIZE);

	while (1) {
		unsigned int write_bytes = 0;

		if (write_len >= count)
			break;

		write_bytes =
		    (left_len >
		     TEMP_BUF_DATA_SIZE) ? TEMP_BUF_DATA_SIZE : left_len;

		if (copy_from_user(temp_buf_char, user_buf, write_bytes)) {
			KBOX_MSG("copy_from_user fail!\n");
			break;
		}

		if (kbox_write_to_ram
		    (offset_tmp, write_bytes, temp_buf_char, section) < 0) {
			KBOX_MSG("kbox_write_to_ram fail!\n");
			break;
		}

		left_len -= write_bytes;
		write_len += write_bytes;
		user_buf += write_bytes;

		offset_tmp += write_bytes;
		memset((void *)temp_buf_char, 0, TEMP_BUF_DATA_SIZE);

		msleep(20);
	}

	kfree(temp_buf_char);

	up(&user_sem);

	return (int)write_len;
}

char kbox_checksum(const char *input_buf, unsigned int len)
{
	unsigned int idx = 0;
	char checksum = 0;

	for (idx = 0; idx < len; idx++)
		checksum += input_buf[idx];

	return checksum;
}

static int kbox_update_super_block(void)
{
	int write_len = 0;

	g_kbox_super_block.checksum = 0;
	g_kbox_super_block.checksum =
	    ~((unsigned char)
	      kbox_checksum((char *)&g_kbox_super_block,
			    (unsigned int)sizeof(g_kbox_super_block))) + 1;
	write_len =
	    kbox_write_to_ram(SECTION_KERNEL_OFFSET,
			      (unsigned int)sizeof(struct image_super_block_s),
			      (char *)&g_kbox_super_block, KBOX_SECTION_KERNEL);
	if (write_len <= 0) {
		KBOX_MSG("fail to write superblock data!\n");
		return KBOX_FALSE;
	}

	return KBOX_TRUE;
}

int kbox_read_super_block(void)
{
	int read_len = 0;

	read_len =
	    kbox_read_from_ram(SECTION_KERNEL_OFFSET,
			       (unsigned int)sizeof(struct image_super_block_s),
			       (char *)&g_kbox_super_block,
			       KBOX_SECTION_KERNEL);
	if (read_len != sizeof(struct image_super_block_s)) {
		KBOX_MSG("fail to get superblock data!\n");
		return KBOX_FALSE;
	}

	return KBOX_TRUE;
}

static unsigned char kbox_get_byte_order(void)
{
	unsigned short data_short = 0xB22B;
	unsigned char *data_char = (unsigned char *)&data_short;

	return (unsigned char)((*data_char == 0xB2) ? KBOX_BIG_ENDIAN :
			       KBOX_LITTLE_ENDIAN);
}

int kbox_super_block_init(void)
{
	int ret = 0;

	ret = kbox_read_super_block();
	if (ret != KBOX_TRUE) {
		KBOX_MSG("kbox_read_super_block fail!\n");
		return ret;
	}

	if (!VALID_IMAGE(&g_kbox_super_block) ||
	    kbox_checksum((char *)&g_kbox_super_block,
			  (unsigned int)sizeof(g_kbox_super_block)) != 0) {
		if (!VALID_IMAGE(&g_kbox_super_block)) {
			memset((void *)&g_kbox_super_block, 0x00,
			       sizeof(struct image_super_block_s));
		}

		g_kbox_super_block.byte_order = kbox_get_byte_order();
		g_kbox_super_block.version = IMAGE_VER;
		g_kbox_super_block.magic_flag = IMAGE_MAGIC;
	}

	g_kbox_super_block.thread_ctrl_blk.thread_info_len = 0;

	if (kbox_update_super_block() != KBOX_TRUE) {
		KBOX_MSG("kbox_update_super_block failed!\n");
		return KBOX_FALSE;
	}

	return KBOX_TRUE;
}

static unsigned char kbox_get_write_slot_num(void)
{
	struct panic_ctrl_block_s *panic_ctrl_block = NULL;
	unsigned int idx = 0;
	unsigned char slot_num = 0;
	unsigned char min_use_nums = 0;

	panic_ctrl_block = g_kbox_super_block.panic_ctrl_blk;
	min_use_nums = panic_ctrl_block->use_nums;

	for (idx = 1; idx < SLOT_NUM; idx++) {
		panic_ctrl_block++;
		if (panic_ctrl_block->use_nums < min_use_nums) {
			min_use_nums = panic_ctrl_block->use_nums;
			slot_num = (unsigned char)idx;
		}
	}

	if (min_use_nums == MAX_USE_NUMS) {
		panic_ctrl_block = g_kbox_super_block.panic_ctrl_blk;
		for (idx = 0; idx < SLOT_NUM; idx++) {
			panic_ctrl_block->use_nums = 1;
			panic_ctrl_block++;
		}
	}

	return slot_num;
}

static unsigned char kbox_get_new_record_number(void)
{
	struct panic_ctrl_block_s *panic_ctrl_block = NULL;
	unsigned int idx = 0;
	unsigned char max_number = 0;

	panic_ctrl_block = g_kbox_super_block.panic_ctrl_blk;
	for (idx = 0; idx < SLOT_NUM; idx++) {
		if (panic_ctrl_block->number >= max_number)
			max_number = panic_ctrl_block->number;

		panic_ctrl_block++;
	}

	return (unsigned char)((max_number + 1) % MAX_RECORD_NO);
}

int kbox_write_panic_info(const char *input_data, unsigned int data_len)
{
	int write_len = 0;
	unsigned int offset = 0;
	struct panic_ctrl_block_s *panic_ctrl_block = NULL;
	unsigned long time = ktime_get_seconds();
	unsigned char slot_num = 0;
	unsigned long flags = 0;

	if (!input_data || data_len == 0) {
		KBOX_MSG("input parameter error!\n");
		return KBOX_FALSE;
	}

	if (data_len > SLOT_LENGTH)
		data_len = SLOT_LENGTH;

	spin_lock_irqsave(&g_kbox_super_block_lock, flags);

	slot_num = kbox_get_write_slot_num();

	panic_ctrl_block = &g_kbox_super_block.panic_ctrl_blk[slot_num];
	panic_ctrl_block->use_nums++;

	panic_ctrl_block->number = kbox_get_new_record_number();
	panic_ctrl_block->len = 0;
	panic_ctrl_block->time = (unsigned int)time;

	g_kbox_super_block.panic_nums++;

	spin_unlock_irqrestore(&g_kbox_super_block_lock, flags);

	offset = slot_num * SLOT_LENGTH;
	write_len =
	    kbox_write_to_ram(offset, data_len, input_data, KBOX_SECTION_PANIC);
	if (write_len <= 0) {
		KBOX_MSG("fail to save panic information!\n");
		return KBOX_FALSE;
	}

	spin_lock_irqsave(&g_kbox_super_block_lock, flags);

	panic_ctrl_block->len += (unsigned short)write_len;

	if (kbox_update_super_block() != KBOX_TRUE) {
		KBOX_MSG("kbox_update_super_block failed!\n");
		spin_unlock_irqrestore(&g_kbox_super_block_lock, flags);
		return KBOX_FALSE;
	}

	spin_unlock_irqrestore(&g_kbox_super_block_lock, flags);

	return KBOX_TRUE;
}

int kbox_write_thread_info(const char *input_data, unsigned int data_len)
{
	int write_len = 0;
	unsigned int offset = 0;
	unsigned long flags = 0;
	unsigned int date_len_tmp = data_len;

	if (!input_data || date_len_tmp == 0) {
		KBOX_MSG("input parameter error!\n");
		return KBOX_FALSE;
	}

	spin_lock_irqsave(&g_kbox_super_block_lock, flags);

	offset = g_kbox_super_block.thread_ctrl_blk.thread_info_len;
	write_len =
	    kbox_write_to_ram(offset, date_len_tmp, input_data,
			      KBOX_SECTION_THREAD);
	if (write_len <= 0) {
		KBOX_MSG("fail to save thread information!\n");
		spin_unlock_irqrestore(&g_kbox_super_block_lock, flags);
		return KBOX_FALSE;
	}

	g_kbox_super_block.thread_ctrl_blk.thread_info_len += write_len;

	if (kbox_update_super_block() != KBOX_TRUE) {
		KBOX_MSG("kbox_update_super_block failed!\n");
		spin_unlock_irqrestore(&g_kbox_super_block_lock, flags);
		return KBOX_FALSE;
	}

	spin_unlock_irqrestore(&g_kbox_super_block_lock, flags);

	return KBOX_TRUE;
}

int kbox_read_printk_info(char *input_data,
			  struct printk_ctrl_block_tmp_s *printk_ctrl_block_tmp)
{
	int read_len = 0;
	int printk_region = printk_ctrl_block_tmp->printk_region;
	unsigned int len = 0;

	if (!input_data) {
		KBOX_MSG("input parameter error!\n");
		return KBOX_FALSE;
	}

	len = g_kbox_super_block.printk_ctrl_blk[printk_region].len;
	if (len <= 0) {
		printk_ctrl_block_tmp->end = 0;
		printk_ctrl_block_tmp->valid_len = 0;
		return KBOX_TRUE;
	}

	read_len =
	    kbox_read_from_ram(0, len, input_data,
			       printk_ctrl_block_tmp->section);
	if (read_len < 0) {
		KBOX_MSG("fail to read printk information!(1)\n");
		return KBOX_FALSE;
	}

	printk_ctrl_block_tmp->end = len;
	printk_ctrl_block_tmp->valid_len = len;

	return KBOX_TRUE;
}

int kbox_write_printk_info(const char *input_data,
			   struct printk_ctrl_block_tmp_s *
			   printk_ctrl_block_tmp)
{
	int write_len = 0;
	int printk_region = printk_ctrl_block_tmp->printk_region;
	unsigned long flags = 0;
	unsigned int len = 0;

	if (!input_data) {
		KBOX_MSG("input parameter error!\n");
		return KBOX_FALSE;
	}

	len = printk_ctrl_block_tmp->valid_len;
	write_len =
	    kbox_write_to_ram(0, len, input_data,
			      printk_ctrl_block_tmp->section);
	if (write_len <= 0) {
		KBOX_MSG("fail to save printk information!(1)\n");
		return KBOX_FALSE;
	}

	spin_lock_irqsave(&g_kbox_super_block_lock, flags);

	g_kbox_super_block.printk_ctrl_blk[printk_region].len = len;

	if (kbox_update_super_block() != KBOX_TRUE) {
		KBOX_MSG("kbox_update_super_block failed!\n");
		spin_unlock_irqrestore(&g_kbox_super_block_lock, flags);
		return KBOX_FALSE;
	}

	spin_unlock_irqrestore(&g_kbox_super_block_lock, flags);

	return KBOX_TRUE;
}

static int kbox_read_region(unsigned long arg)
{
	unsigned int read_len = 0;
	struct kbox_region_arg_s region_arg = { };

	if (copy_from_user
	    ((void *)&region_arg, (void __user *)arg,
	     sizeof(struct kbox_region_arg_s))) {
		KBOX_MSG("fail to copy_from_user!\n");
		return KBOX_FALSE;
	}

	read_len = kbox_read_op((long long)region_arg.offset, region_arg.count,
				(char __user *)region_arg.data,
				KBOX_SECTION_ALL);
	if (read_len <= 0) {
		KBOX_MSG("fail to get kbox data!\n");
		return KBOX_FALSE;
	}

	if (copy_to_user
	    ((void __user *)arg, (void *)&region_arg,
	     sizeof(struct kbox_region_arg_s))) {
		KBOX_MSG("fail to copy_to_user!\n");
		return KBOX_FALSE;
	}

	return KBOX_TRUE;
}

static int kbox_writer_region(unsigned long arg)
{
	unsigned int write_len = 0;
	struct kbox_region_arg_s region_arg = { };

	if (copy_from_user
	    ((void *)&region_arg, (void __user *)arg,
	     sizeof(struct kbox_region_arg_s))) {
		KBOX_MSG("fail to copy_from_user!\n");
		return KBOX_FALSE;
	}

	write_len = kbox_write_op((long long)region_arg.offset,
				  region_arg.count,
				  (char __user *)region_arg.data,
				  KBOX_SECTION_ALL);
	if (write_len <= 0) {
		KBOX_MSG("fail to write kbox data!\n");
		return KBOX_FALSE;
	}

	if (copy_to_user
	    ((void __user *)arg, (void *)&region_arg,
	     sizeof(struct kbox_region_arg_s))) {
		KBOX_MSG("fail to copy_to_user!\n");
		return KBOX_FALSE;
	}

	return KBOX_TRUE;
}

int kbox_clear_region(enum kbox_section_e  section)
{
	int ret = KBOX_TRUE;
	unsigned long kbox_section_len = kbox_get_section_len(section);

	if (kbox_section_len == 0) {
		KBOX_MSG("get kbox_section_len failed!\n");
		return -EFAULT;
	}

	ret = kbox_memset_ram(0, (unsigned int)kbox_section_len, 0, section);
	if (ret != KBOX_TRUE) {
		KBOX_MSG("kbox_memset_ram failed!\n");
		return -EFAULT;
	}

	return KBOX_TRUE;
}

static int kbox_get_image_len(unsigned long arg)
{
	unsigned long __user *ptr = (unsigned long __user *)arg;
	unsigned long kbox_len = 0;

	kbox_len = kbox_get_section_len(KBOX_SECTION_ALL);
	if (kbox_len == 0) {
		KBOX_MSG("kbox_get_section_len section all fail!\n");
		return -EFAULT;
	}

	return put_user(kbox_len, ptr);
}

static int kbox_get_user_region_len(unsigned long arg)
{
	unsigned long __user *ptr = (unsigned long __user *)arg;
	unsigned long kbox_user_region_len = 0;

	kbox_user_region_len = kbox_get_section_len(KBOX_SECTION_USER);
	if (kbox_user_region_len == 0) {
		KBOX_MSG("kbox_get_section_len section user fail!\n");
		return -EFAULT;
	}

	return put_user(kbox_user_region_len, ptr);
}

static int kbox_ioctl_verify_cmd(unsigned int cmd, unsigned long arg)
{
	if (arg == 0 || (_IOC_TYPE(cmd) != KBOX_IOC_MAGIC))
		return KBOX_FALSE;

	if (_IOC_NR(cmd) > KBOX_IOC_MAXNR)
		return KBOX_FALSE;

	if (!capable(CAP_SYS_ADMIN)) {
		KBOX_MSG("permit error\n");
		return KBOX_FALSE;
	}

	return KBOX_TRUE;
}

int kbox_ioctl_detail(unsigned int cmd, unsigned long arg)
{
	if (kbox_ioctl_verify_cmd(cmd, arg) != KBOX_TRUE)
		return -EFAULT;

	switch (cmd) {
	case GET_KBOX_TOTAL_LEN:
		return kbox_get_image_len(arg);

	case GET_KBOX_REGION_USER_LEN:
		return kbox_get_user_region_len(arg);

	case KBOX_REGION_READ:
		return kbox_read_region(arg);

	case KBOX_REGION_WRITE:
		return kbox_writer_region(arg);

	case CLEAR_KBOX_REGION_ALL:
		return kbox_clear_region(KBOX_SECTION_ALL);

	case CLEAR_KBOX_REGION_USER:
		return kbox_clear_region(KBOX_SECTION_USER);

	default:
		return -ENOTTY;
	}
}

int kbox_mmap_ram(struct file *pfile, struct vm_area_struct *vma,
		  enum kbox_section_e  section)
{
	unsigned long kbox_section_phy_addr =
	    kbox_get_section_phy_addr(section);
	unsigned long kbox_section_len = kbox_get_section_len(section);
	unsigned long offset = 0;
	unsigned long length = 0;
	unsigned long vm_size = 0;
	int ret = 0;

	UNUSED(pfile);

	if (kbox_section_phy_addr == 0 || kbox_section_len == 0) {
		KBOX_MSG
		    ("get kbox_section_phy_addr or kbox_section_len failed!\n");
		return -EFAULT;
	}

	offset = vma->vm_pgoff << PAGE_SHIFT;
	vm_size = vma->vm_end - vma->vm_start;

	if (offset >= kbox_section_len) {
		KBOX_MSG("vma offset is invalid!\n");
		return -ESPIPE;
	}

	if (vma->vm_flags & VM_LOCKED) {
		KBOX_MSG("vma is locked!\n");
		return -EPERM;
	}

	length = kbox_section_len - offset;
	if (vm_size > length) {
		KBOX_MSG("vm_size is invalid!\n");
		return -ENOSPC;
	}

	vm_flags_set(vma, VM_RESERVED);
	vm_flags_set(vma, VM_IO);

	ret = remap_pfn_range(vma,
			      vma->vm_start,
			      (unsigned long)(kbox_section_phy_addr >>
					      PAGE_SHIFT), vm_size,
			      vma->vm_page_prot);
	if (ret) {
		KBOX_MSG("remap_pfn_range failed! ret = %d\n", ret);
		return -EAGAIN;
	}

	return 0;
}
