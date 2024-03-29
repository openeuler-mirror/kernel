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

#include <linux/module.h>
#include <linux/processor.h>	/* for rdmsr and MSR_IA32_MCG_STATUS */
#include <linux/fs.h>		/* everything... */
#include <linux/file.h>		/* for fput */
#include <linux/proc_fs.h>
#include <linux/uaccess.h>		/* copy_*_user */
#include <linux/version.h>
#include "kbox_include.h"
#include "kbox_panic.h"
#include "kbox_main.h"
#include "kbox_printk.h"
#include "kbox_ram_image.h"
#include "kbox_ram_op.h"
#include "kbox_dump.h"
#include "kbox_hook.h"
#include "kbox_ram_drive.h"

#ifdef CONFIG_X86
#include <asm/msr.h>
#include "kbox_mce.h"
#endif

#define KBOX_LOADED_FILE ("/proc/kbox")

#define KBOX_ROOT_ENTRY_NAME ("kbox")

static int kbox_is_loaded(void)
{
	struct file *fp = NULL;

	#ifdef set_fs
	mm_segment_t old_fs;

	old_fs = get_fs();		/* save old flag */
	set_fs(KERNEL_DS);	/* mark data from kernel space */
	#endif

	fp = filp_open(KBOX_LOADED_FILE, O_RDONLY, 0);

	if (IS_ERR(fp)) {
		#ifdef set_fs
		set_fs(old_fs);
		#endif

		return KBOX_FALSE;
	}

	(void)filp_close(fp, NULL);

	#ifdef set_fs
	set_fs(old_fs);		/* restore old flag */
	#endif

	return KBOX_TRUE;
}

static int kbox_printk_proc_init(void)
{
	struct proc_dir_entry *kbox_entry = NULL;

	if (kbox_is_loaded() != KBOX_TRUE) {
		kbox_entry = proc_mkdir(KBOX_ROOT_ENTRY_NAME, NULL);
		if (!kbox_entry) {
			KBOX_MSG("can not create %s entry\n",
				 KBOX_ROOT_ENTRY_NAME);
			return -ENOMEM;
		}
	}

	return KBOX_TRUE;
}

int __init kbox_init(void)
{
	int ret = KBOX_TRUE;
	int kbox_proc_exist = 0;

	if (!kbox_get_base_phy_addr())
		return -ENXIO;

	ret = kbox_super_block_init();
	if (ret) {
		KBOX_MSG("kbox_super_block_init failed!\n");
		return ret;
	}

	if (kbox_is_loaded() == KBOX_TRUE)
		kbox_proc_exist = 1;

	ret = kbox_printk_init(kbox_proc_exist);
	if (ret)
		KBOX_MSG("kbox_printk_init failed!\n");

	ret = kbox_panic_init();
	if (ret) {
		KBOX_MSG("kbox_panic_init failed!\n");
		goto fail1;
	}

	ret = kbox_register_hook();
	if (ret) {
		KBOX_MSG("kbox_register_hook failed!\n");
		goto fail2;
	}

#ifdef CONFIG_X86
	(void)kbox_mce_init();
#endif
	ret = kbox_read_super_block();
	if (ret) {
		KBOX_MSG("update super block failed!\n");
		goto fail3;
	}

	if (kbox_printk_proc_init() != 0) {
		KBOX_MSG("kbox_printk_proc_init failed!\n");
		goto fail4;
	}

	ret = kbox_drive_init();
	if (ret) {
		KBOX_MSG("kbox_drive_init failed!\n");
		goto fail5;
	}

	return KBOX_TRUE;

fail5:
fail4:
fail3:
#ifdef CONFIG_X86
	kbox_mce_exit();
#endif
	kbox_unregister_hook();
fail2:
	kbox_panic_exit();
fail1:
	kbox_printk_exit();

	return ret;
}

void __exit kbox_cleanup(void)
{
	kbox_drive_cleanup();
#ifdef CONFIG_X86
	kbox_mce_exit();
#endif
	kbox_unregister_hook();
	kbox_panic_exit();
	kbox_printk_exit();
}

MODULE_AUTHOR("HUAWEI TECHNOLOGIES CO., LTD.");
MODULE_DESCRIPTION("HUAWEI KBOX DRIVER");
MODULE_LICENSE("GPL");
MODULE_VERSION(KBOX_VERSION);
#ifndef _lint
module_init(kbox_init);
module_exit(kbox_cleanup);
#endif
