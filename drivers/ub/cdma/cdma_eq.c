// SPDX-License-Identifier: GPL-2.0+
/* Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved. */

#define dev_fmt(fmt) "CDMA: " fmt

#include <linux/notifier.h>
#include <linux/slab.h>
#include <ub/ubase/ubase_comm_cmd.h>
#include <ub/ubase/ubase_comm_eq.h>
#include "cdma_jfs.h"
#include "cdma_jfc.h"
#include "cdma.h"
#include "cdma_eq.h"

static int cdma_ae_jfs_check_error(struct auxiliary_device *adev,
				   u32 jetty_id)
{
	struct cdma_dev *cdev = get_cdma_dev(adev);
	struct cdma_base_jfs *base_jfs;
	struct cdma_event ae;
	struct cdma_jfs *jfs;

	spin_lock(&cdev->jfs_table.lock);
	jfs = idr_find(&cdev->jfs_table.idr_tbl.idr, jetty_id);
	if (!jfs) {
		dev_err(cdev->dev, "ae get jfs from table failed, id = %u.\n",
			jetty_id);
		spin_unlock(&cdev->jfs_table.lock);
		return -EINVAL;
	}

	base_jfs = &jfs->base_jfs;

	if (base_jfs->jfae_handler && base_jfs->jfae) {
		refcount_inc(&jfs->ae_ref_cnt);
		spin_unlock(&cdev->jfs_table.lock);
		ae.dev = base_jfs->dev;
		ae.element.jfs = base_jfs;
		ae.event_type = CDMA_EVENT_JFS_ERR;
		base_jfs->jfae_handler(&ae, base_jfs->jfae);
		if (refcount_dec_and_test(&jfs->ae_ref_cnt)) {
			complete(&jfs->ae_comp);
			dev_dbg(cdev->dev, "jfs ae handler done.\n");
		}
	} else {
		spin_unlock(&cdev->jfs_table.lock);
	}

	return 0;
}

static int cdma_ae_jfc_check_error(struct auxiliary_device *adev,
				   u32 jetty_id)
{
	struct cdma_dev *cdev = get_cdma_dev(adev);
	struct cdma_base_jfc *base_jfc;
	struct cdma_event ae;
	struct cdma_jfc *jfc;
	unsigned long flags;

	spin_lock_irqsave(&cdev->jfc_table.lock, flags);
	jfc = idr_find(&cdev->jfc_table.idr_tbl.idr, jetty_id);
	if (!jfc) {
		dev_err(cdev->dev, "get jfc from table failed, id = %u.\n",
			jetty_id);
		spin_unlock_irqrestore(&cdev->jfc_table.lock, flags);
		return -EINVAL;
	}
	base_jfc = &jfc->base;

	if (base_jfc->jfae_handler && base_jfc->jfae) {
		refcount_inc(&jfc->event_refcount);
		spin_unlock_irqrestore(&cdev->jfc_table.lock, flags);
		ae.dev = base_jfc->dev;
		ae.element.jfc = base_jfc;
		ae.event_type = CDMA_EVENT_JFC_ERR;
		base_jfc->jfae_handler(&ae, base_jfc->jfae);
		if (refcount_dec_and_test(&jfc->event_refcount)) {
			complete(&jfc->event_comp);
			dev_dbg(cdev->dev, "jfc ae handler done.\n");
		}
	} else {
		spin_unlock_irqrestore(&cdev->jfc_table.lock, flags);
	}

	return 0;
}

static int cdma_ae_jetty_level_error(struct notifier_block *nb,
				     unsigned long event, void *data)
{
	struct ubase_event_nb *ev_nb = container_of(nb, struct ubase_event_nb, nb);
	struct auxiliary_device *adev = ev_nb->back;
	struct ubase_aeq_notify_info *info = data;
	u32 jetty_id;

	jetty_id = info->aeqe->event.queue_event.num;

	switch (info->sub_type) {
	case UBASE_SUBEVENT_TYPE_JFS_CHECK_ERROR:
		return cdma_ae_jfs_check_error(adev, jetty_id);
	case UBASE_SUBEVENT_TYPE_JFC_CHECK_ERROR:
		return cdma_ae_jfc_check_error(adev, jetty_id);
	default:
		dev_warn(&adev->dev, "cdma get unsupported async event type %u.\n",
				info->sub_type);
		return -EINVAL;
	}
}

static struct cdma_ae_operation cdma_ae_opts[] = {
	{UBASE_EVENT_TYPE_JETTY_LEVEL_ERROR, cdma_ae_jetty_level_error}
};

static int cdma_event_register(struct auxiliary_device *adev,
			       enum ubase_event_type event_type, notifier_fn_t call)
{
	struct cdma_dev *cdma_dev = get_cdma_dev(adev);
	struct ubase_event_nb *event_cb;
	int ret;

	event_cb = kzalloc(sizeof(*event_cb), GFP_KERNEL);
	if (!event_cb)
		return -ENOMEM;

	event_cb->drv_type = UBASE_DRV_CDMA;
	event_cb->event_type = event_type;
	event_cb->back = (void *)adev;
	event_cb->nb.notifier_call = call;

	ret = ubase_event_register(adev, event_cb);
	if (ret) {
		dev_err(cdma_dev->dev,
			"register async event failed, event type = %u, ret = %d.\n",
			event_cb->event_type, ret);
		kfree(event_cb);
		return ret;
	}
	cdma_dev->ae_event_addr[event_type] = event_cb;

	return 0;
}

/* thanks to drivers/infiniband/hw/erdma/erdma_eq.c */
int cdma_reg_ae_event(struct auxiliary_device *adev)
{
	struct cdma_dev *cdma_dev;
	u32 opt_num;
	int ret = 0;
	int i;

	if (!adev)
		return -EINVAL;

	cdma_dev = get_cdma_dev(adev);
	if (!cdma_dev)
		return -EINVAL;

	opt_num = sizeof(cdma_ae_opts) / sizeof(struct cdma_ae_operation);
	for (i = 0; i < opt_num; ++i) {
		ret = cdma_event_register(adev,
			(enum ubase_event_type)cdma_ae_opts[i].op_code,
			cdma_ae_opts[i].call);
		if (ret) {
			cdma_unreg_ae_event(adev);
			return -EINVAL;
		}
	}

	dev_info(cdma_dev->dev, "cdma register ae event, ret = %d.\n", ret);

	return ret;
}

void cdma_unreg_ae_event(struct auxiliary_device *adev)
{
	struct cdma_dev *cdma_dev;
	int i;

	if (!adev)
		return;

	cdma_dev = get_cdma_dev(adev);
	if (!cdma_dev)
		return;

	for (i = 0; i < UBASE_EVENT_TYPE_MAX; i++) {
		if (cdma_dev->ae_event_addr[i]) {
			ubase_event_unregister(adev, cdma_dev->ae_event_addr[i]);
			kfree(cdma_dev->ae_event_addr[i]);
			cdma_dev->ae_event_addr[i] = NULL;
		}
	}
}

/* thanks to drivers/infiniband/hw/erdma/erdma_eq.c */
int cdma_reg_ce_event(struct auxiliary_device *adev)
{
	struct cdma_dev *cdma_dev;
	int ret;

	if (!adev)
		return -EINVAL;

	cdma_dev = get_cdma_dev(adev);
	if (!cdma_dev)
		return -EINVAL;

	ret = ubase_comp_register(adev, cdma_jfc_completion);
	if (ret)
		dev_err(cdma_dev->dev, "register ce event failed, ret = %d.\n",
			ret);

	return ret;
}

void cdma_unreg_ce_event(struct auxiliary_device *adev)
{
	if (!adev)
		return;

	ubase_comp_unregister(adev);
}
