/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hinic5_filter.c
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   :
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": [NIC]" fmt
#include <linux/kernel.h>
#include <linux/device.h>
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/etherdevice.h>
#include <linux/netdevice.h>
#include <linux/debugfs.h>
#include <linux/module.h>
#include <linux/moduleparam.h>

#include "ossl_knl.h"
#include "hinic5_hw.h"
#include "hinic5_crm.h"
#include "hinic5_nic_dev.h"
#include "hinic5_srv_nic.h"
#include "hinic5_filter.h"

static int hinic5_uc_sync(struct net_device *netdev, u8 *addr)
{
	struct hinic5_nic_dev *nic_dev = netdev_priv(netdev);

	return hinic5_set_mac(nic_dev->hwdev, addr, 0,
			      hinic5_global_func_id(nic_dev->hwdev),
			      HINIC5_CHANNEL_NIC);
}

static int hinic5_uc_unsync(struct net_device *netdev, u8 *addr)
{
	struct hinic5_nic_dev *nic_dev = netdev_priv(netdev);

	/* The addr is in use */
	if (ether_addr_equal(addr, netdev->dev_addr))
		return 0;

	return hinic5_del_mac(nic_dev->hwdev, addr, 0,
			      hinic5_global_func_id(nic_dev->hwdev),
			      HINIC5_CHANNEL_NIC);
}

void hinic5_clean_mac_list_filter(struct hinic5_nic_dev *nic_dev)
{
	struct net_device *netdev = nic_dev->netdev;
	struct hinic5_mac_filter *ftmp = NULL;
	struct hinic5_mac_filter *f = NULL;

	list_for_each_entry_safe(f, ftmp, &nic_dev->uc_filter_list, list) {
		if (f->state == HINIC5_MAC_HW_SYNCED)
			hinic5_uc_unsync(netdev, f->addr);
		list_del(&f->list);
		kfree(f);
	}

	list_for_each_entry_safe(f, ftmp, &nic_dev->mc_filter_list, list) {
		if (f->state == HINIC5_MAC_HW_SYNCED)
			hinic5_uc_unsync(netdev, f->addr);
		list_del(&f->list);
		kfree(f);
	}
}

static struct hinic5_mac_filter *hinic5_find_mac(const struct list_head *filter_list,
						 u8 *addr)
{
	struct hinic5_mac_filter *f = NULL;

	list_for_each_entry(f, filter_list, list) {
		if (ether_addr_equal(addr, f->addr))
			return f;
	}
	return NULL;
}

static void hinic5_add_filter(struct hinic5_nic_dev *nic_dev,
			      struct list_head *mac_filter_list,
			      u8 *addr)
{
	struct hinic5_mac_filter *f = NULL;

	// check if addr is broadcast address
	if (is_broadcast_ether_addr(addr))
		return;

	f = kzalloc(sizeof(*f), GFP_ATOMIC);
	if (!f)
		return;

	ether_addr_copy(f->addr, addr);

	INIT_LIST_HEAD(&f->list);
	list_add_tail(&f->list, mac_filter_list);

	f->state = HINIC5_MAC_WAIT_HW_SYNC;
	set_bit(HINIC5_MAC_FILTER_CHANGED, &nic_dev->flags);
}

static void hinic5_del_filter(struct hinic5_nic_dev *nic_dev,
			      struct hinic5_mac_filter *f)
{
	set_bit(HINIC5_MAC_FILTER_CHANGED, &nic_dev->flags);

	if (f->state == HINIC5_MAC_WAIT_HW_SYNC) {
		/* have not added to hw, delete it directly */
		list_del(&f->list);
		kfree(f);
		return;
	}

	f->state = HINIC5_MAC_WAIT_HW_UNSYNC;
}

static struct hinic5_mac_filter *hinic5_mac_filter_entry_clone(const struct hinic5_mac_filter *src)
{
	struct hinic5_mac_filter *f = NULL;

	f = kzalloc(sizeof(*f), GFP_ATOMIC);
	if (!f)
		return NULL;

	*f = *src;
	INIT_LIST_HEAD(&f->list);

	return f;
}

static void hinic5_undo_del_filter_entries(struct list_head *filter_list,
					   const struct list_head *from)
{
	struct hinic5_mac_filter *ftmp = NULL;
	struct hinic5_mac_filter *f = NULL;

	list_for_each_entry_safe(f, ftmp, from, list) {
		if (hinic5_find_mac(filter_list, f->addr))
			continue;

		if (f->state == HINIC5_MAC_HW_UNSYNCED)
			f->state = HINIC5_MAC_WAIT_HW_UNSYNC;

		list_move_tail(&f->list, filter_list);
	}
}

static void hinic5_undo_add_filter_entries(struct list_head *filter_list,
					   const struct list_head *from)
{
	struct hinic5_mac_filter *ftmp = NULL;
	struct hinic5_mac_filter *tmp = NULL;
	struct hinic5_mac_filter *f = NULL;

	list_for_each_entry_safe(f, ftmp, from, list) {
		tmp = hinic5_find_mac(filter_list, f->addr);
		if (tmp && tmp->state == HINIC5_MAC_HW_SYNCED)
			tmp->state = HINIC5_MAC_WAIT_HW_SYNC;
	}
}

static void hinic5_cleanup_filter_list(const struct list_head *head)
{
	struct hinic5_mac_filter *ftmp = NULL;
	struct hinic5_mac_filter *f = NULL;

	list_for_each_entry_safe(f, ftmp, head, list) {
		list_del(&f->list);
		kfree(f);
	}
}

static int hinic5_mac_filter_sync_hw(struct hinic5_nic_dev *nic_dev,
				     struct list_head *del_list,
				     struct list_head *add_list)
{
	struct net_device *netdev = nic_dev->netdev;
	struct hinic5_mac_filter *ftmp = NULL;
	struct hinic5_mac_filter *f = NULL;
	int err = 0, add_count = 0;

	if (list_empty(del_list) == 0) {
		list_for_each_entry_safe(f, ftmp, del_list, list) {
			err = hinic5_uc_unsync(netdev, f->addr);
			if (err != 0) { /* ignore errors when delete mac */
				nic_err(nic_dev->lld_dev->dev, "Failed to delete mac\n");
			}

			list_del(&f->list);
			kfree(f);
		}
	}

	if (list_empty(add_list) == 0) {
		list_for_each_entry_safe(f, ftmp, add_list, list) {
			err = hinic5_uc_sync(netdev, f->addr);
			if (err != 0) {
				nic_err(nic_dev->lld_dev->dev, "Failed to add mac\n");
				return err;
			}

			add_count++;
			list_del(&f->list);
			kfree(f);
		}
	}

	return add_count;
}

static int hinic5_mac_filter_sync(struct hinic5_nic_dev *nic_dev,
				  struct list_head *mac_filter_list, bool uc)
{
	struct list_head tmp_del_list, tmp_add_list;
	struct hinic5_mac_filter *fclone = NULL;
	struct hinic5_mac_filter *ftmp = NULL;
	struct hinic5_mac_filter *f = NULL;
	int err = 0, add_count = 0;

	INIT_LIST_HEAD(&tmp_del_list);
	INIT_LIST_HEAD(&tmp_add_list);

	list_for_each_entry_safe(f, ftmp, mac_filter_list, list) {
		if (f->state != HINIC5_MAC_WAIT_HW_UNSYNC)
			continue;

		f->state = HINIC5_MAC_HW_UNSYNCED;
		list_move_tail(&f->list, &tmp_del_list);
	}

	list_for_each_entry_safe(f, ftmp, mac_filter_list, list) {
		if (f->state != HINIC5_MAC_WAIT_HW_SYNC)
			continue;

		fclone = hinic5_mac_filter_entry_clone(f);
		if (!fclone) {
			err = -ENOMEM;
			break;
		}

		f->state = HINIC5_MAC_HW_SYNCED;
		list_add_tail(&fclone->list, &tmp_add_list);
	}

	if (err != 0) {
		hinic5_undo_del_filter_entries(mac_filter_list, &tmp_del_list);
		hinic5_undo_add_filter_entries(mac_filter_list, &tmp_add_list);
		nicif_err(nic_dev, drv, nic_dev->netdev, "Failed to clone mac_filter_entry\n");

		hinic5_cleanup_filter_list(&tmp_del_list);
		hinic5_cleanup_filter_list(&tmp_add_list);
		return -ENOMEM;
	}

	add_count = hinic5_mac_filter_sync_hw(nic_dev, &tmp_del_list, &tmp_add_list);
	if (list_empty(&tmp_add_list) != 0)
		return add_count;

	/* there are errors when add mac to hw, delete all mac in hw */
	hinic5_undo_add_filter_entries(mac_filter_list, &tmp_add_list);
	/* VF don't support to enter promisc mode,
	 * so we can't delete any other uc mac
	 */
	if (!HINIC5_FUNC_IS_VF(nic_dev->hwdev) || !uc) {
		list_for_each_entry_safe(f, ftmp, mac_filter_list, list) {
			if (f->state != HINIC5_MAC_HW_SYNCED)
				continue;

			fclone = hinic5_mac_filter_entry_clone(f);
			if (!fclone)
				break;

			f->state = HINIC5_MAC_WAIT_HW_SYNC;
			list_add_tail(&fclone->list, &tmp_del_list);
		}
	}

	hinic5_cleanup_filter_list(&tmp_add_list);
	hinic5_mac_filter_sync_hw(nic_dev, &tmp_del_list, &tmp_add_list);

	/* need to enter promisc/allmulti mode */
	return -ENOMEM;
}

static void hinic5_mac_filter_sync_all(struct hinic5_nic_dev *nic_dev)
{
	struct net_device *netdev = nic_dev->netdev;
	int add_count;

	if (test_bit(HINIC5_MAC_FILTER_CHANGED, &nic_dev->flags) != 0) {
		clear_bit(HINIC5_MAC_FILTER_CHANGED, &nic_dev->flags);
		add_count = hinic5_mac_filter_sync(nic_dev,
						   &nic_dev->uc_filter_list,
						   true);
		if (add_count < 0 && HINIC5_SUPPORT_PROMISC(nic_dev->hwdev)) {
			set_bit(HINIC5_PROMISC_FORCE_ON,
				&nic_dev->rx_mod_state);
			nicif_info(nic_dev, drv, netdev, "Promisc mode forced on\n");
		} else if (add_count != 0) {
			clear_bit(HINIC5_PROMISC_FORCE_ON,
				  &nic_dev->rx_mod_state);
		}

		add_count = hinic5_mac_filter_sync(nic_dev,
						   &nic_dev->mc_filter_list,
						   false);
		if (add_count < 0 && HINIC5_SUPPORT_ALLMULTI(nic_dev->hwdev)) {
			set_bit(HINIC5_ALLMULTI_FORCE_ON,
				&nic_dev->rx_mod_state);
			nicif_info(nic_dev, drv, netdev, "All multicast mode forced on\n");
		} else if (add_count != 0) {
			clear_bit(HINIC5_ALLMULTI_FORCE_ON,
				  &nic_dev->rx_mod_state);
		}
	}
}

static void hinic5_update_mac_filter(struct hinic5_nic_dev *nic_dev,
				     const struct netdev_hw_addr_list *src_list,
				     struct list_head *filter_list)
{
	struct hinic5_mac_filter *filter = NULL;
	struct hinic5_mac_filter *ftmp = NULL;
	struct hinic5_mac_filter *f = NULL;
	struct netdev_hw_addr *ha = NULL;

	/* add addr if not already in the filter list */
	netif_addr_lock_bh(nic_dev->netdev);
	netdev_hw_addr_list_for_each(ha, src_list) {
		filter = hinic5_find_mac(filter_list, ha->addr);
		if (!filter)
			hinic5_add_filter(nic_dev, filter_list, ha->addr);
		else if (filter->state == HINIC5_MAC_WAIT_HW_UNSYNC)
			filter->state = HINIC5_MAC_HW_SYNCED;
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

		hinic5_del_filter(nic_dev, f);
	}
}

#ifndef NETDEV_HW_ADDR_T_MULTICAST
static void hinic5_update_mc_filter(struct hinic5_nic_dev *nic_dev,
				    struct list_head *filter_list)
{
	struct hinic5_mac_filter *filter = NULL;
	struct hinic5_mac_filter *ftmp = NULL;
	struct hinic5_mac_filter *f = NULL;
	struct dev_mc_list *ha = NULL;

	/* add addr if not already in the filter list */
	netif_addr_lock_bh(nic_dev->netdev);
	netdev_for_each_mc_addr(ha, nic_dev->netdev) {
		filter = hinic5_find_mac(filter_list, ha->da_addr);
		if (!filter)
			hinic5_add_filter(nic_dev, filter_list, ha->da_addr);
		else if (filter->state == HINIC5_MAC_WAIT_HW_UNSYNC)
			filter->state = HINIC5_MAC_HW_SYNCED;
	}
	netif_addr_unlock_bh(nic_dev->netdev);
	/* delete addr if not in netdev list */
	list_for_each_entry_safe(f, ftmp, filter_list, list) {
		bool found = false;

		netif_addr_lock_bh(nic_dev->netdev);
		netdev_for_each_mc_addr(ha, nic_dev->netdev)
			if (ether_addr_equal(ha->da_addr, f->addr)) {
				found = true;
				break;
			}
		netif_addr_unlock_bh(nic_dev->netdev);

		if (found)
			continue;

		hinic5_del_filter(nic_dev, f);
	}
}
#endif

static void update_mac_filter(struct hinic5_nic_dev *nic_dev)
{
	struct net_device *netdev = nic_dev->netdev;

	if (test_and_clear_bit(HINIC5_UPDATE_MAC_FILTER, &nic_dev->flags) != 0) {
		hinic5_update_mac_filter(nic_dev, &netdev->uc,
					 &nic_dev->uc_filter_list);

#ifdef NETDEV_HW_ADDR_T_MULTICAST
		hinic5_update_mac_filter(nic_dev, &netdev->mc,
					 &nic_dev->mc_filter_list);
#else
		hinic5_update_mc_filter(nic_dev,
					&nic_dev->mc_filter_list);
#endif
	}
}

static void sync_rx_mode_to_hw(struct hinic5_nic_dev *nic_dev, int promisc_en,
			       int allmulti_en)
{
	struct net_device *netdev = nic_dev->netdev;
	u32 rx_mod = HINIC5_DEFAULT_RX_MODE;
	int err;

	rx_mod |= ((promisc_en != 0) ? NIC_RX_MODE_PROMISC : 0);
	rx_mod |= ((allmulti_en != 0) ? NIC_RX_MODE_MC_ALL : 0);

	if (promisc_en != test_bit(HINIC5_HW_PROMISC_ON,
				   &nic_dev->rx_mod_state))
		nicif_info(nic_dev, drv, netdev,
			   "%s promisc mode\n",
			   (promisc_en != 0) ? "Enter" : "Left");
	if (allmulti_en !=
	    test_bit(HINIC5_HW_ALLMULTI_ON, &nic_dev->rx_mod_state))
		nicif_info(nic_dev, drv, netdev,
			   "%s all_multi mode\n",
			   (allmulti_en != 0) ? "Enter" : "Left");

	err = hinic5_set_rx_mode(nic_dev->hwdev, rx_mod);
	if (err != 0) {
		nicif_err(nic_dev, drv, netdev, "Failed to set rx_mode\n");
		return;
	}

	(promisc_en != 0) ? set_bit(HINIC5_HW_PROMISC_ON, &nic_dev->rx_mod_state) :
		clear_bit(HINIC5_HW_PROMISC_ON, &nic_dev->rx_mod_state);

	(allmulti_en != 0) ? set_bit(HINIC5_HW_ALLMULTI_ON, &nic_dev->rx_mod_state) :
		clear_bit(HINIC5_HW_ALLMULTI_ON, &nic_dev->rx_mod_state);
}

void hinic5_set_rx_mode_work(struct work_struct *work)
{
	struct hinic5_nic_dev *nic_dev =
			container_of(work, struct hinic5_nic_dev, rx_mode_work);
	struct net_device *netdev = nic_dev->netdev;
	int promisc_en = 0, allmulti_en = 0;

	update_mac_filter(nic_dev);

	hinic5_mac_filter_sync_all(nic_dev);

	if (HINIC5_SUPPORT_PROMISC(nic_dev->hwdev))
		promisc_en = ((netdev->flags & IFF_PROMISC) != 0) ||
			test_bit(HINIC5_PROMISC_FORCE_ON,
				 &nic_dev->rx_mod_state);

	if (HINIC5_SUPPORT_ALLMULTI(nic_dev->hwdev))
		allmulti_en = ((netdev->flags & IFF_ALLMULTI) != 0) ||
			test_bit(HINIC5_ALLMULTI_FORCE_ON,
				 &nic_dev->rx_mod_state);

	if (promisc_en !=
	    test_bit(HINIC5_HW_PROMISC_ON, &nic_dev->rx_mod_state) ||
	    allmulti_en !=
	    test_bit(HINIC5_HW_ALLMULTI_ON, &nic_dev->rx_mod_state))
		sync_rx_mode_to_hw(nic_dev, promisc_en, allmulti_en);
}

