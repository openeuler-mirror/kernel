// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2022 nebula-matrix Limited.
 * Author:
 */

#include "nbl_queue.h"

/* Structure starts here, adding an op should not modify anything below */
static int nbl_queue_setup_mgt(struct device *dev, struct nbl_queue_mgt **queue_mgt)
{
	*queue_mgt = devm_kzalloc(dev, sizeof(struct nbl_queue_mgt), GFP_KERNEL);
	if (!*queue_mgt)
		return -ENOMEM;

	return 0;
}

static void nbl_queue_remove_mgt(struct device *dev, struct nbl_queue_mgt **queue_mgt)
{
	devm_kfree(dev, *queue_mgt);
	*queue_mgt = NULL;
}

int nbl_queue_mgt_start(struct nbl_resource_mgt *res_mgt)
{
	struct device *dev;
	struct nbl_queue_mgt **queue_mgt;
	struct nbl_res_product_ops *product_ops = NBL_RES_MGT_TO_PROD_OPS(res_mgt);
	int ret = 0;

	dev = NBL_RES_MGT_TO_DEV(res_mgt);
	queue_mgt = &NBL_RES_MGT_TO_QUEUE_MGT(res_mgt);

	ret = nbl_queue_setup_mgt(dev, queue_mgt);
	if (ret)
		return ret;

	NBL_OPS_CALL(product_ops->queue_mgt_init, (*queue_mgt));

	return 0;
}

void nbl_queue_mgt_stop(struct nbl_resource_mgt *res_mgt)
{
	struct device *dev;
	struct nbl_queue_mgt **queue_mgt;

	dev = NBL_RES_MGT_TO_DEV(res_mgt);
	queue_mgt = &NBL_RES_MGT_TO_QUEUE_MGT(res_mgt);

	if (!(*queue_mgt))
		return;

	nbl_queue_remove_mgt(dev, queue_mgt);
}
