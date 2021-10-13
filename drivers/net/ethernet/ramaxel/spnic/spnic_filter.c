// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2021 Ramaxel Memory Technology, Ltd */

#define pr_fmt(fmt) KBUILD_MODNAME ": [NIC]" fmt
#include <linux/kernel.h>
#include <linux/pci.h>
#include <linux/device.h>
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/etherdevice.h>
#include <linux/netdevice.h>
#include <linux/debugfs.h>
#include <linux/module.h>
#include <linux/moduleparam.h>

#include "sphw_hw.h"
#include "sphw_crm.h"
#include "spnic_nic_dev.h"

enum spnic_rx_mod {
	SPNIC_RX_MODE_UC = 1 << 0,
	SPNIC_RX_MODE_MC = 1 << 1,
	SPNIC_RX_MODE_BC = 1 << 2,
	SPNIC_RX_MODE_MC_ALL = 1 << 3,
	SPNIC_RX_MODE_PROMISC = 1 << 4,
};

static int spnic_uc_sync(struct net_device *netdev, u8 *addr)
{
	struct spnic_nic_dev *nic_dev = netdev_priv(netdev);

	return spnic_set_mac(nic_dev->hwdev, addr, 0, sphw_global_func_id(nic_dev->hwdev),
			     SPHW_CHANNEL_NIC);
}

static int spnic_uc_unsync(struct net_device *netdev, u8 *addr)
{
	struct spnic_nic_dev *nic_dev = netdev_priv(netdev);

	/* The addr is in use */
	if (ether_addr_equal(addr, netdev->dev_addr))
		return 0;

	return spnic_del_mac(nic_dev->hwdev, addr, 0, sphw_global_func_id(nic_dev->hwdev),
			     SPHW_CHANNEL_NIC);
}

void spnic_clean_mac_list_filter(struct spnic_nic_dev *nic_dev)
{
	struct net_device *netdev = nic_dev->netdev;
	struct spnic_mac_filter *ftmp = NULL;
	struct spnic_mac_filter *f = NULL;

	list_for_each_entry_safe(f, ftmp, &nic_dev->uc_filter_list, list) {
		if (f->state == SPNIC_MAC_HW_SYNCED)
			spnic_uc_unsync(netdev, f->addr);
		list_del(&f->list);
		kfree(f);
	}

	list_for_each_entry_safe(f, ftmp, &nic_dev->mc_filter_list, list) {
		if (f->state == SPNIC_MAC_HW_SYNCED)
			spnic_uc_unsync(netdev, f->addr);
		list_del(&f->list);
		kfree(f);
	}
}

static struct spnic_mac_filter *spnic_find_mac(struct list_head *filter_list, u8 *addr)
{
	struct spnic_mac_filter *f = NULL;

	list_for_each_entry(f, filter_list, list) {
		if (ether_addr_equal(addr, f->addr))
			return f;
	}
	return NULL;
}

static struct spnic_mac_filter *spnic_add_filter(struct spnic_nic_dev *nic_dev,
						 struct list_head *mac_filter_list, u8 *addr)
{
	struct spnic_mac_filter *f;

	f = kzalloc(sizeof(*f), GFP_ATOMIC);
	if (!f)
		goto out;

	ether_addr_copy(f->addr, addr);

	INIT_LIST_HEAD(&f->list);
	list_add_tail(&f->list, mac_filter_list);

	f->state = SPNIC_MAC_WAIT_HW_SYNC;
	set_bit(SPNIC_MAC_FILTER_CHANGED, &nic_dev->flags);

out:
	return f;
}

static void spnic_del_filter(struct spnic_nic_dev *nic_dev, struct spnic_mac_filter *f)
{
	set_bit(SPNIC_MAC_FILTER_CHANGED, &nic_dev->flags);

	if (f->state == SPNIC_MAC_WAIT_HW_SYNC) {
		/* have not added to hw, delete it directly */
		list_del(&f->list);
		kfree(f);
		return;
	}

	f->state = SPNIC_MAC_WAIT_HW_UNSYNC;
}

static struct spnic_mac_filter *spnic_mac_filter_entry_clone(struct spnic_mac_filter *src)
{
	struct spnic_mac_filter *f;

	f = kzalloc(sizeof(*f), GFP_ATOMIC);
	if (!f)
		return NULL;

	*f = *src;
	INIT_LIST_HEAD(&f->list);

	return f;
}

static void spnic_undo_del_filter_entries(struct list_head *filter_list, struct list_head *from)
{
	struct spnic_mac_filter *ftmp = NULL;
	struct spnic_mac_filter *f = NULL;

	list_for_each_entry_safe(f, ftmp, from, list) {
		if (spnic_find_mac(filter_list, f->addr))
			continue;

		if (f->state == SPNIC_MAC_HW_SYNCED)
			f->state = SPNIC_MAC_WAIT_HW_UNSYNC;

		list_move_tail(&f->list, filter_list);
	}
}

static void spnic_undo_add_filter_entries(struct list_head *filter_list, struct list_head *from)
{
	struct spnic_mac_filter *ftmp = NULL;
	struct spnic_mac_filter *tmp = NULL;
	struct spnic_mac_filter *f = NULL;

	list_for_each_entry_safe(f, ftmp, from, list) {
		tmp = spnic_find_mac(filter_list, f->addr);
		if (tmp && tmp->state == SPNIC_MAC_HW_SYNCED)
			tmp->state = SPNIC_MAC_WAIT_HW_SYNC;
	}
}

static void spnic_cleanup_filter_list(struct list_head *head)
{
	struct spnic_mac_filter *ftmp = NULL;
	struct spnic_mac_filter *f = NULL;

	list_for_each_entry_safe(f, ftmp, head, list) {
		list_del(&f->list);
		kfree(f);
	}
}

static int spnic_mac_filter_sync_hw(struct spnic_nic_dev *nic_dev, struct list_head *del_list,
				    struct list_head *add_list)
{
	struct net_device *netdev = nic_dev->netdev;
	struct spnic_mac_filter *ftmp = NULL;
	struct spnic_mac_filter *f = NULL;
	int err = 0, add_count = 0;

	if (!list_empty(del_list)) {
		list_for_each_entry_safe(f, ftmp, del_list, list) {
			err = spnic_uc_unsync(netdev, f->addr);
			if (err) { /* ignore errors when delete mac */
				nic_err(&nic_dev->pdev->dev, "Failed to delete mac\n");
			}

			list_del(&f->list);
			kfree(f);
		}
	}

	if (!list_empty(add_list)) {
		list_for_each_entry_safe(f, ftmp, add_list, list) {
			err = spnic_uc_sync(netdev, f->addr);
			if (err) {
				nic_err(&nic_dev->pdev->dev, "Failed to add mac\n");
				return err;
			}

			add_count++;
			list_del(&f->list);
			kfree(f);
		}
	}

	return add_count;
}

static int spnic_mac_filter_sync(struct spnic_nic_dev *nic_dev,
				 struct list_head *mac_filter_list, bool uc)
{
	struct net_device *netdev = nic_dev->netdev;
	struct list_head tmp_del_list, tmp_add_list;
	struct spnic_mac_filter *fclone = NULL;
	struct spnic_mac_filter *ftmp = NULL;
	struct spnic_mac_filter *f = NULL;
	int err = 0, add_count = 0;

	INIT_LIST_HEAD(&tmp_del_list);
	INIT_LIST_HEAD(&tmp_add_list);

	list_for_each_entry_safe(f, ftmp, mac_filter_list, list) {
		if (f->state != SPNIC_MAC_WAIT_HW_UNSYNC)
			continue;

		f->state = SPNIC_MAC_HW_UNSYNCED;
		list_move_tail(&f->list, &tmp_del_list);
	}

	list_for_each_entry_safe(f, ftmp, mac_filter_list, list) {
		if (f->state != SPNIC_MAC_WAIT_HW_SYNC)
			continue;

		fclone = spnic_mac_filter_entry_clone(f);
		if (!fclone) {
			err = -ENOMEM;
			break;
		}

		f->state = SPNIC_MAC_HW_SYNCED;
		list_add_tail(&fclone->list, &tmp_add_list);
	}

	if (err) {
		spnic_undo_del_filter_entries(mac_filter_list, &tmp_del_list);
		spnic_undo_add_filter_entries(mac_filter_list, &tmp_add_list);
		nicif_err(nic_dev, drv, netdev, "Failed to clone mac_filter_entry\n");

		spnic_cleanup_filter_list(&tmp_del_list);
		spnic_cleanup_filter_list(&tmp_add_list);
		return -ENOMEM;
	}

	add_count = spnic_mac_filter_sync_hw(nic_dev, &tmp_del_list, &tmp_add_list);
	if (list_empty(&tmp_add_list))
		return add_count;

	/* there are errors when add mac to hw, delete all mac in hw */
	spnic_undo_add_filter_entries(mac_filter_list, &tmp_add_list);
	/* VF don't support to enter promisc mode,
	 * so we can't delete any other uc mac
	 */
	if (!SPNIC_FUNC_IS_VF(nic_dev->hwdev) || !uc) {
		list_for_each_entry_safe(f, ftmp, mac_filter_list, list) {
			if (f->state != SPNIC_MAC_HW_SYNCED)
				continue;

			fclone = spnic_mac_filter_entry_clone(f);
			if (!fclone)
				break;

			f->state = SPNIC_MAC_WAIT_HW_SYNC;
			list_add_tail(&fclone->list, &tmp_del_list);
		}
	}

	spnic_cleanup_filter_list(&tmp_add_list);
	spnic_mac_filter_sync_hw(nic_dev, &tmp_del_list, &tmp_add_list);

	/* need to enter promisc/allmulti mode */
	return -ENOMEM;
}

static void spnic_mac_filter_sync_all(struct spnic_nic_dev *nic_dev)
{
	struct net_device *netdev = nic_dev->netdev;
	int add_count;

	if (test_bit(SPNIC_MAC_FILTER_CHANGED, &nic_dev->flags)) {
		clear_bit(SPNIC_MAC_FILTER_CHANGED, &nic_dev->flags);
		add_count = spnic_mac_filter_sync(nic_dev, &nic_dev->uc_filter_list, true);
		if (add_count < 0 && SPNIC_SUPPORT_PROMISC(nic_dev->hwdev)) {
			set_bit(SPNIC_PROMISC_FORCE_ON, &nic_dev->rx_mod_state);
			nicif_info(nic_dev, drv, netdev, "Promisc mode forced on\n");
		} else if (add_count) {
			clear_bit(SPNIC_PROMISC_FORCE_ON, &nic_dev->rx_mod_state);
		}

		add_count = spnic_mac_filter_sync(nic_dev, &nic_dev->mc_filter_list, false);
		if (add_count < 0 && SPNIC_SUPPORT_ALLMULTI(nic_dev->hwdev)) {
			set_bit(SPNIC_ALLMULTI_FORCE_ON, &nic_dev->rx_mod_state);
			nicif_info(nic_dev, drv, netdev, "All multicast mode forced on\n");
		} else if (add_count) {
			clear_bit(SPNIC_ALLMULTI_FORCE_ON, &nic_dev->rx_mod_state);
		}
	}
}

#define SPNIC_DEFAULT_RX_MODE	(SPNIC_RX_MODE_UC | SPNIC_RX_MODE_MC | \
				SPNIC_RX_MODE_BC)

static void spnic_update_mac_filter(struct spnic_nic_dev *nic_dev,
				    struct netdev_hw_addr_list *src_list,
				    struct list_head *filter_list)
{
	struct spnic_mac_filter *filter = NULL;
	struct spnic_mac_filter *ftmp = NULL;
	struct spnic_mac_filter *f = NULL;
	struct netdev_hw_addr *ha = NULL;

	/* add addr if not already in the filter list */
	netif_addr_lock_bh(nic_dev->netdev);
	netdev_hw_addr_list_for_each(ha, src_list) {
		filter = spnic_find_mac(filter_list, ha->addr);
		if (!filter)
			spnic_add_filter(nic_dev, filter_list, ha->addr);
		else if (filter->state == SPNIC_MAC_WAIT_HW_UNSYNC)
			filter->state = SPNIC_MAC_HW_SYNCED;
	}
	netif_addr_unlock_bh(nic_dev->netdev);

	/* delete addr if not in netdev list */
	list_for_each_entry_safe(f, ftmp, filter_list, list) {
		bool found = false;

		netif_addr_lock_bh(nic_dev->netdev);
		netdev_hw_addr_list_for_each(ha, src_list)
			if (ether_addr_equal(ha->addr, f->addr)) {
				found = true;
				break;
			}
		netif_addr_unlock_bh(nic_dev->netdev);

		if (found)
			continue;

		spnic_del_filter(nic_dev, f);
	}
}

static void update_mac_filter(struct spnic_nic_dev *nic_dev)
{
	struct net_device *netdev = nic_dev->netdev;

	if (test_and_clear_bit(SPNIC_UPDATE_MAC_FILTER, &nic_dev->flags)) {
		spnic_update_mac_filter(nic_dev, &netdev->uc, &nic_dev->uc_filter_list);
		spnic_update_mac_filter(nic_dev, &netdev->mc, &nic_dev->mc_filter_list);
	}
}

static void sync_rx_mode_to_hw(struct spnic_nic_dev *nic_dev, int promisc_en,
			       int allmulti_en)
{
	struct net_device *netdev = nic_dev->netdev;
	u32 rx_mod = SPNIC_DEFAULT_RX_MODE;
	int err;

	rx_mod |= (promisc_en ? SPNIC_RX_MODE_PROMISC : 0);
	rx_mod |= (allmulti_en ? SPNIC_RX_MODE_MC_ALL : 0);

	if (promisc_en != test_bit(SPNIC_HW_PROMISC_ON, &nic_dev->rx_mod_state))
		nicif_info(nic_dev, drv, netdev, "%s promisc mode\n",
			   promisc_en ? "Enter" : "Left");
	if (allmulti_en !=
	    test_bit(SPNIC_HW_ALLMULTI_ON, &nic_dev->rx_mod_state))
		nicif_info(nic_dev, drv, netdev, "%s all_multi mode\n",
			   allmulti_en ? "Enter" : "Left");

	err = spnic_set_rx_mode(nic_dev->hwdev, rx_mod);
	if (err) {
		nicif_err(nic_dev, drv, netdev, "Failed to set rx_mode\n");
		return;
	}

	promisc_en ? set_bit(SPNIC_HW_PROMISC_ON, &nic_dev->rx_mod_state) :
		clear_bit(SPNIC_HW_PROMISC_ON, &nic_dev->rx_mod_state);

	allmulti_en ? set_bit(SPNIC_HW_ALLMULTI_ON, &nic_dev->rx_mod_state) :
		clear_bit(SPNIC_HW_ALLMULTI_ON, &nic_dev->rx_mod_state);
}

void spnic_set_rx_mode_work(struct work_struct *work)
{
	struct spnic_nic_dev *nic_dev =
			container_of(work, struct spnic_nic_dev, rx_mode_work);
	struct net_device *netdev = nic_dev->netdev;
	int promisc_en = 0, allmulti_en = 0;

	update_mac_filter(nic_dev);

	spnic_mac_filter_sync_all(nic_dev);

	if (SPNIC_SUPPORT_PROMISC(nic_dev->hwdev))
		promisc_en = !!(netdev->flags & IFF_PROMISC) ||
			test_bit(SPNIC_PROMISC_FORCE_ON, &nic_dev->rx_mod_state);

	if (SPNIC_SUPPORT_ALLMULTI(nic_dev->hwdev))
		allmulti_en = !!(netdev->flags & IFF_ALLMULTI) ||
			test_bit(SPNIC_ALLMULTI_FORCE_ON, &nic_dev->rx_mod_state);

	if (promisc_en != test_bit(SPNIC_HW_PROMISC_ON, &nic_dev->rx_mod_state) ||
	    allmulti_en != test_bit(SPNIC_HW_ALLMULTI_ON, &nic_dev->rx_mod_state))
		sync_rx_mode_to_hw(nic_dev, promisc_en, allmulti_en);
}
