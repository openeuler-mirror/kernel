// SPDX-License-Identifier: GPL-2.0-only
/*
 * Generalized Memory Management.
 *
 * Copyright (c) 2023- Huawei, Inc.
 * Author: Chunsheng Luo
 * Co-Author: Jun Chen
 */
#include <linux/module.h>
#include "msg_chan/msg_layer/msg_layer.h"
#include "msg_handler.h"

#if IS_ENABLED(CONFIG_REMOTE_PAGER_SLAVE)
#include "swap/device/swap_manager.h"
#endif

static int __init remote_pager_init(void)
{
	msg_handle_init();

#if IS_ENABLED(CONFIG_REMOTE_PAGER_SLAVE)
	init_swap_manager("list_lru");
#endif
	return 0;
}

static void __exit remote_pager_exit(void)
{
	/*
	 * If module_init() is implemented, module_exit()
	 * should be implemented as well.
	 */
}

module_init(remote_pager_init);
module_exit(remote_pager_exit);

MODULE_AUTHOR("Huawei Tech. Co., Ltd.");
MODULE_DESCRIPTION("Remote-pager");
MODULE_ALIAS("Remote-pager");
MODULE_LICENSE("GPL");

