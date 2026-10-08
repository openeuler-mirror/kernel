// SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB
/* Copyright (c) 2021, NEBULARMATRIX */

#include <rdma/nbl-v2-abi.h>
#include <linux/list.h>
#include "nbl_compat.h"
#include "product_internal.h"
#include "shared.h"
#include "device.h"
#include "main.h"
#include "probe.h"
#include "resource.h"

struct list_head nbl_dev_pci_node_head;
struct list_head do_reset_node_head;
struct workqueue_struct *reset_wq;

/*
 * protects nbl_dev_pci_node_head, do_reset_node_head, the pending reset
 * work and the rdma_reset window against the probe/remove paths and the
 * debugfs path
 */
static DEFINE_MUTEX(nbl_reset_mutex);
static struct delayed_work *pending_reset_work;

int nbl_reset_init(void)
{
	INIT_LIST_HEAD(&nbl_dev_pci_node_head);
	INIT_LIST_HEAD(&do_reset_node_head);
	pending_reset_work = NULL;
	reset_wq = create_singlethread_workqueue("rdma reset wq");
	if (!reset_wq)
		return -ENOMEM;

	return 0;
}

void nbl_reset_deinit(void)
{
	struct nbl_dev_pci_node *cur_node, *tmp_node;
	struct list_head *heads[] = { &nbl_dev_pci_node_head, &do_reset_node_head };
	struct delayed_work *dwork;
	int i;

	if (!reset_wq)
		return;

	mutex_lock(&nbl_reset_mutex);
	dwork = pending_reset_work;
	pending_reset_work = NULL;

	/* whatever is left is dropped together with the module, but the device
	 * references taken in nbl_add_dev_pci_node() must be returned
	 */
	for (i = 0; i < ARRAY_SIZE(heads); i++) {
		list_for_each_entry_safe(cur_node, tmp_node, heads[i], list) {
			list_del(&cur_node->list);
			put_device(&cur_node->adev->dev);
			kfree(cur_node);
		}
	}
	mutex_unlock(&nbl_reset_mutex);

	/* dropping the queued work keeps it from re-probing (and re-registering
	 * an ib_device) while the module is going away
	 */
	if (dwork && cancel_delayed_work_sync(dwork))
		kfree(dwork);

	flush_workqueue(reset_wq);
	destroy_workqueue(reset_wq);
	reset_wq = NULL;
}

int nbl_add_dev_pci_node(struct nbl_device *nbl_dev,
						struct auxiliary_device *adev,
						const struct auxiliary_device_id *id)
{
	struct nbl_dev_pci_node *node;

	/* skip vf */
	if (!nbl_product_flag_enabled(nbl_dev->rf, NBL_PRODUCT_F_CTRL_DEV))
		return 0;

	node = kzalloc(sizeof(*node), GFP_KERNEL);
	if (!node)
		return -ENOMEM;

	get_device(&adev->dev);
	node->nbl_dev = nbl_dev;
	node->bus = nbl_dev->rf->pcidev->bus;
	node->slot = nbl_dev->rf->pcidev->slot;
	node->adev = adev;
	node->id = id;

	mutex_lock(&nbl_reset_mutex);
	list_add_tail(&node->list, &nbl_dev_pci_node_head);
	mutex_unlock(&nbl_reset_mutex);

	return 0;
}

/* the node may sit on either list: a debugfs reset moves it to the reset
 * list, and the remove path still has to be able to drop it
 */
void nbl_free_dev_pci_node(struct nbl_device *nbl_dev)
{
	struct nbl_dev_pci_node *cur_node, *tmp_node;
	struct list_head *heads[] = { &nbl_dev_pci_node_head, &do_reset_node_head };
	int i;

	/* skip vf */
	if (!nbl_product_flag_enabled(nbl_dev->rf, NBL_PRODUCT_F_CTRL_DEV))
		return;

	mutex_lock(&nbl_reset_mutex);
	for (i = 0; i < ARRAY_SIZE(heads); i++) {
		list_for_each_entry_safe(cur_node, tmp_node, heads[i], list) {
			if (cur_node->nbl_dev != nbl_dev)
				continue;

			list_del(&cur_node->list);
			put_device(&cur_node->adev->dev);
			kfree(cur_node);
		}
	}
	mutex_unlock(&nbl_reset_mutex);
}

static void do_dev_pci_node_remove_probe_work(struct work_struct *work)
{
	struct nbl_dev_pci_node *cur_node, *tmp_node;
	struct delayed_work *dwork = to_delayed_work(work);
	LIST_HEAD(reset_list);

	nbl_pr_dbg("Run %s...", __func__);

	/* take the nodes off the shared list first: remove/probe below runs the
	 * driver callbacks which take nbl_reset_mutex again
	 */
	mutex_lock(&nbl_reset_mutex);
	list_splice_init(&do_reset_node_head, &reset_list);
	mutex_unlock(&nbl_reset_mutex);

	list_for_each_entry_safe(cur_node, tmp_node, &reset_list, list) {
		list_del(&cur_node->list);

		/* only the (reference held) auxiliary device is known to be alive
		 * here: its pci_bus/pci_slot may already be gone, so don't log them
		 */
		nbl_pr_info("reset, name: %s", dev_name(&cur_node->adev->dev));

		/* the device may have been removed while the work was pending */
		if (dev_get_drvdata(&cur_node->adev->dev)) {
			nbl_remove_v2(cur_node->adev);
			nbl_probe_v2(cur_node->adev, cur_node->id);
		} else {
			nbl_pr_info("reset, %s already removed, skip",
				    dev_name(&cur_node->adev->dev));
		}

		put_device(&cur_node->adev->dev);
		kfree(cur_node);
	}

	mutex_lock(&nbl_reset_mutex);
	pending_reset_work = NULL;
	mutex_unlock(&nbl_reset_mutex);

	kfree(dwork);
}

void nbl_reset_same_pci_dev(struct nbl_device *nbl_dev)
{
	struct nbl_dev_pci_node *cur_node, *tmp_node;
	struct delayed_work *dwork;
	struct nbl_pci_f *rf = nbl_dev->rf;

	/* skip vf */
	if (!nbl_product_flag_enabled(rf, NBL_PRODUCT_F_CTRL_DEV))
		return;

	mutex_lock(&nbl_reset_mutex);

	/* a reset is already in flight: a second one would redo the hw reset on
	 * a device that is half way through the reset
	 */
	if (pending_reset_work) {
		mutex_unlock(&nbl_reset_mutex);
		nbl_pr_warn("rdma reset is already in progress, skip");
		return;
	}

	dwork = kzalloc(sizeof(*dwork), GFP_KERNEL);
	if (!dwork) {
		mutex_unlock(&nbl_reset_mutex);
		nbl_pr_err("alloc rdma reset work err");
		return;
	}

	/* remove same bus dev from old list and add to new list */
	list_for_each_entry_safe(cur_node, tmp_node, &nbl_dev_pci_node_head, list) {
		nbl_pr_dbg("Iter pci dev, bus: %u, slot: %d, name: %s",
			cur_node->bus->primary, cur_node->slot ? cur_node->slot->number : -1,
			cur_node->nbl_dev->ibdev.name);

		if (cur_node->bus == nbl_dev->rf->pcidev->bus &&
			cur_node->slot == nbl_dev->rf->pcidev->slot) {
			list_del(&cur_node->list);
			list_add_tail(&cur_node->list, &do_reset_node_head);

			cur_node->nbl_dev->rf->rdma_reset = 1;
			/* Disable notify */
			nbl_notify_set(cur_node->nbl_dev->rf, false);
			/* Disable DB */
			nbl_set_qm_vfid_vsi_map(cur_node->nbl_dev->rf, 0);
			/* Disable RDMA packet */
			cur_node->nbl_dev->rf->hw.hw_ops->set_hw_dsch_init(
				&cur_node->nbl_dev->rf->hw,
				cur_node->nbl_dev->rf->sc_dev.function_id,
				cur_node->nbl_dev->rf->sc_dev.dport_id,
				cur_node->nbl_dev->rf->product->host_id, false,
				&cur_node->nbl_dev->rf->product->dsch_layout);
		}
	}

	usleep_range(WAIT_RDMA_EMPTY_TIME, WAIT_RDMA_EMPTY_MAX_TIME);
	/* write reset reg */
	rf->product->lifecycle_ops->reset_rdma(rf);

	/* handle reset dev sw resource */
	INIT_DELAYED_WORK(dwork, do_dev_pci_node_remove_probe_work);
	pending_reset_work = dwork;
	queue_delayed_work(reset_wq, dwork,
		msecs_to_jiffies(NBL_RESET_WORK_DELAY_MS));

	mutex_unlock(&nbl_reset_mutex);
}
