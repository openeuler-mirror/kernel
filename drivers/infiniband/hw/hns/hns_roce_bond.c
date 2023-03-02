// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/*
 * Copyright (c) 2022 Hisilicon Limited.
 */

#include <linux/pci.h>
#include "hnae3.h"
#include "hns_roce_device.h"
#include "hns_roce_hw_v2.h"
#include "hns_roce_bond.h"

static DEFINE_MUTEX(roce_bond_mutex);

static struct hns_roce_dev *hns_roce_get_hrdev_by_netdev(struct net_device *net_dev)
{
	struct hns_roce_dev *hr_dev;
	struct ib_device *ibdev;

	ibdev = ib_device_get_by_netdev(net_dev, RDMA_DRIVER_HNS);
	if (!ibdev)
		return NULL;

	hr_dev = container_of(ibdev, struct hns_roce_dev, ib_dev);
	ib_device_put(ibdev);

	return hr_dev;
}

struct hns_roce_bond_group *hns_roce_get_bond_grp(struct hns_roce_dev *hr_dev)
{
	struct hns_roce_bond_group *bond_grp = NULL;
	struct net_device *upper_dev;
	struct net_device *net_dev;

	if (!netif_is_lag_port(hr_dev->iboe.netdevs[0]))
		return NULL;

	rcu_read_lock();

	upper_dev = netdev_master_upper_dev_get_rcu(hr_dev->iboe.netdevs[0]);

	for_each_netdev_in_bond_rcu(upper_dev, net_dev) {
		hr_dev = hns_roce_get_hrdev_by_netdev(net_dev);
		if (hr_dev && hr_dev->bond_grp) {
			bond_grp = hr_dev->bond_grp;
			break;
		}
	}

	rcu_read_unlock();

	return bond_grp;
}

bool hns_roce_bond_is_active(struct hns_roce_dev *hr_dev)
{
	struct hns_roce_bond_group *bond_grp;

	bond_grp = hns_roce_get_bond_grp(hr_dev);

	if (bond_grp &&
	    (bond_grp->bond_state == HNS_ROCE_BOND_REGISTERING ||
	    bond_grp->bond_state == HNS_ROCE_BOND_IS_BONDED))
		return true;

	return false;
}

struct net_device *hns_roce_get_bond_netdev(struct hns_roce_dev *hr_dev)
{
	struct hns_roce_bond_group *bond_grp = hr_dev->bond_grp;
	struct net_device *net_dev = NULL;
	int i;

	if (!(hr_dev->caps.flags & HNS_ROCE_CAP_FLAG_BOND))
		return NULL;

	if (!bond_grp) {
		bond_grp = hns_roce_get_bond_grp(hr_dev);
		if (!bond_grp)
			return NULL;
	}

	mutex_lock(&bond_grp->bond_mutex);

	if (bond_grp->bond_state == HNS_ROCE_BOND_NOT_BONDED)
		goto out;

	if (bond_grp->tx_type == NETDEV_LAG_TX_TYPE_ACTIVEBACKUP) {
		for (i = 0; i < ROCE_BOND_FUNC_MAX; i++) {
			net_dev = bond_grp->bond_func_info[i].net_dev;
			if (net_dev &&
			    bond_grp->bond_func_info[i].state.tx_enabled)
				break;
		}
	} else {
		for (i = 0; i < ROCE_BOND_FUNC_MAX; i++) {
			net_dev = bond_grp->bond_func_info[i].net_dev;
			if (net_dev && get_port_state(net_dev) == IB_PORT_ACTIVE)
				break;
		}
	}

out:
	mutex_unlock(&bond_grp->bond_mutex);

	return net_dev;
}

static void hns_roce_queue_bond_work(struct hns_roce_dev *hr_dev,
				     unsigned long delay)
{
	schedule_delayed_work(&hr_dev->bond_work, delay);
}

static void hns_roce_bond_get_active_slave(struct hns_roce_bond_group *bond_grp)
{
	struct net_device *net_dev;
	u32 active_slave_map = 0;
	u8 active_slave_num = 0;
	bool active;
	u8 i;

	for (i = 0; i < ROCE_BOND_FUNC_MAX; i++) {
		net_dev = bond_grp->bond_func_info[i].net_dev;
		if (net_dev) {
			active = (bond_grp->tx_type == NETDEV_LAG_TX_TYPE_ACTIVEBACKUP) ?
				bond_grp->bond_func_info[i].state.tx_enabled :
				bond_grp->bond_func_info[i].state.link_up;
			if (active) {
				active_slave_num++;
				active_slave_map |= (1 << i);
			}
		}
	}

	bond_grp->active_slave_num = active_slave_num;
	bond_grp->active_slave_map = active_slave_map;
}

static struct hns_roce_dev
		*hns_roce_bond_init_client(struct hns_roce_bond_group *bond_grp,
					   int func_idx)
{
	struct hnae3_handle *handle;
	int ret;

	handle = bond_grp->bond_func_info[func_idx].handle;
	ret = hns_roce_hw_v2_init_instance(handle);
	if (ret)
		return NULL;

	return handle->priv;
}

static void hns_roce_bond_uninit_client(struct hns_roce_bond_group *bond_grp,
					int func_idx)
{
	struct hnae3_handle *handle;

	handle = bond_grp->bond_func_info[func_idx].handle;
	hns_roce_hw_v2_uninit_instance(handle, 0);
}

static void hns_roce_set_bond(struct hns_roce_bond_group *bond_grp)
{
	u8 main_func_idx = PCI_FUNC(bond_grp->main_hr_dev->pci_dev->devfn);
	struct net_device *main_net_dev = bond_grp->main_net_dev;
	struct hns_roce_dev *hr_dev;
	struct net_device *net_dev;
	int ret;
	int i;

	/*
	 * bond_grp will be kfree during uninit_instance of main_hr_dev.
	 * Thus the main_hr_dev is switched before the uninit_instance
	 * of the previous main_hr_dev.
	 */
	for (i = 0; i < ROCE_BOND_FUNC_MAX; i++) {
		net_dev = bond_grp->bond_func_info[i].net_dev;
		if (net_dev && net_dev != main_net_dev)
			hns_roce_bond_uninit_client(bond_grp, i);
	}

	bond_grp->bond_state = HNS_ROCE_BOND_REGISTERING;

	for (i = 0; i < ROCE_BOND_FUNC_MAX; i++) {
		net_dev = bond_grp->bond_func_info[i].net_dev;
		if (net_dev && net_dev != main_net_dev) {
			hr_dev = hns_roce_bond_init_client(bond_grp, i);
			if (hr_dev) {
				bond_grp->bond_id =
					hr_dev->ib_dev.name[ROCE_BOND_NAME_ID_IDX]
						- '0';
				bond_grp->main_hr_dev->bond_grp = NULL;
				bond_grp->main_hr_dev = hr_dev;
				bond_grp->main_net_dev = net_dev;
				hr_dev->bond_grp = bond_grp;
				break;
			}
		}
	}
	if (!hr_dev)
		return;

	hns_roce_bond_uninit_client(bond_grp, main_func_idx);
	hns_roce_bond_get_active_slave(bond_grp);
	ret = hns_roce_cmd_bond(hr_dev, HNS_ROCE_SET_BOND);
	if (ret) {
		ibdev_err(&hr_dev->ib_dev, "failed to set RoCE bond!\n");
		return;
	}

	bond_grp->bond_state = HNS_ROCE_BOND_IS_BONDED;
	ibdev_info(&hr_dev->ib_dev, "RoCE set bond finished!\n");
}

static void hns_roce_clear_bond(struct hns_roce_bond_group *bond_grp)
{
	u8 main_func_idx = PCI_FUNC(bond_grp->main_hr_dev->pci_dev->devfn);
	struct net_device *main_net_dev = bond_grp->main_net_dev;
	struct hnae3_handle *handle;
	struct hns_roce_dev *hr_dev;
	struct net_device *net_dev;
	int ret;
	int i;

	bond_grp->bond_state = HNS_ROCE_BOND_NOT_BONDED;

	for (i = 0; i < ROCE_BOND_FUNC_MAX; i++) {
		net_dev = bond_grp->bond_func_info[i].net_dev;
		if (net_dev && net_dev != main_net_dev)
			hns_roce_bond_init_client(bond_grp, i);
	}

	ret = hns_roce_cmd_bond(bond_grp->main_hr_dev, HNS_ROCE_CLEAR_BOND);
	if (ret)
		return;
	handle = bond_grp->bond_func_info[main_func_idx].handle;

	/* bond_grp will be freed in uninit_instance(main_net_dev) */
	hns_roce_bond_uninit_client(bond_grp, main_func_idx);

	ret = hns_roce_hw_v2_init_instance(handle);
	if (ret) {
		ibdev_err(&hr_dev->ib_dev, "failed to clear RoCE bond!\n");
		return;
	}

	hr_dev = handle->priv;

	ibdev_info(&hr_dev->ib_dev, "RoCE clear bond finished!\n");
}

static void hns_roce_slave_changestate(struct hns_roce_bond_group *bond_grp)
{
	int ret;

	hns_roce_bond_get_active_slave(bond_grp);

	ret = hns_roce_cmd_bond(bond_grp->main_hr_dev, HNS_ROCE_CHANGE_BOND);
	if (ret) {
		ibdev_err(&bond_grp->main_hr_dev->ib_dev,
			  "failed to change RoCE bond slave state!\n");
		return;
	}

	bond_grp->bond_state = HNS_ROCE_BOND_IS_BONDED;
	ibdev_info(&bond_grp->main_hr_dev->ib_dev,
		   "RoCE slave changestate finished!\n");
}

static void hns_roce_slave_inc(struct hns_roce_bond_group *bond_grp)
{
	u32 inc_slave_map = bond_grp->slave_map_diff;
	u8 inc_func_idx = 0;
	int ret;

	while (inc_slave_map > 0) {
		if (inc_slave_map & 1)
			hns_roce_bond_uninit_client(bond_grp, inc_func_idx);
		inc_slave_map >>= 1;
		inc_func_idx++;
	}

	hns_roce_bond_get_active_slave(bond_grp);
	ret = hns_roce_cmd_bond(bond_grp->main_hr_dev, HNS_ROCE_CHANGE_BOND);
	if (ret) {
		ibdev_err(&bond_grp->main_hr_dev->ib_dev,
			  "failed to increase RoCE bond slave!\n");
		return;
	}

	bond_grp->bond_state = HNS_ROCE_BOND_IS_BONDED;
	ibdev_info(&bond_grp->main_hr_dev->ib_dev,
		   "RoCE slave increase finished!\n");
}

static void hns_roce_slave_dec(struct hns_roce_bond_group *bond_grp)
{
	u32 dec_slave_map = bond_grp->slave_map_diff;
	struct hns_roce_dev *hr_dev;
	struct net_device *net_dev;
	u8 main_func_idx = 0;
	u8 dec_func_idx = 0;
	int ret;
	int i;

	bond_grp->bond_state = HNS_ROCE_BOND_IS_BONDED;

	main_func_idx = PCI_FUNC(bond_grp->main_hr_dev->pci_dev->devfn);
	if (dec_slave_map & (1 << main_func_idx)) {
		hns_roce_cmd_bond(hr_dev, HNS_ROCE_CLEAR_BOND);
		for (i = 0; i < ROCE_BOND_FUNC_MAX; i++) {
			net_dev = bond_grp->bond_func_info[i].net_dev;
			if (!(dec_slave_map & (1 << i)) && net_dev) {
				bond_grp->bond_state = HNS_ROCE_BOND_REGISTERING;
				hr_dev = hns_roce_bond_init_client(bond_grp, i);
				if (hr_dev) {
					bond_grp->main_hr_dev = hr_dev;
					bond_grp->main_net_dev = net_dev;
					hr_dev->bond_grp = bond_grp;
					break;
				}
			}
		}
		hns_roce_bond_uninit_client(bond_grp, main_func_idx);
	}

	while (dec_slave_map > 0) {
		if (dec_slave_map & 1) {
			hns_roce_bond_init_client(bond_grp, dec_func_idx);
			bond_grp->bond_func_info[dec_func_idx].net_dev = NULL;
		}
		dec_slave_map >>= 1;
		dec_func_idx++;
	}

	hns_roce_bond_get_active_slave(bond_grp);
	if (bond_grp->slave_map_diff & (1 << main_func_idx))
		ret = hns_roce_cmd_bond(hr_dev, HNS_ROCE_SET_BOND);
	else
		ret = hns_roce_cmd_bond(bond_grp->main_hr_dev,
					HNS_ROCE_CHANGE_BOND);
	if (ret) {
		ibdev_err(&bond_grp->main_hr_dev->ib_dev,
			  "failed to decrease RoCE bond slave!\n");
		return;
	}

	bond_grp->bond_state = HNS_ROCE_BOND_IS_BONDED;
	ibdev_info(&bond_grp->main_hr_dev->ib_dev,
		   "RoCE slave decrease finished!\n");
}

static void hns_roce_do_bond(struct hns_roce_bond_group *bond_grp)
{
	enum hns_roce_bond_state bond_state;
	bool bond_ready;

	bond_ready = bond_grp->bond_ready;
	bond_state = bond_grp->bond_state;
	ibdev_info(&bond_grp->main_hr_dev->ib_dev,
		   "do_bond: bond_ready - %d, bond_state - %d.\n",
		   bond_ready, bond_grp->bond_state);

	if (bond_ready && bond_state == HNS_ROCE_BOND_NOT_BONDED)
		hns_roce_set_bond(bond_grp);
	else if (bond_ready && bond_state == HNS_ROCE_BOND_SLAVE_CHANGESTATE)
		hns_roce_slave_changestate(bond_grp);
	else if (bond_ready && bond_state == HNS_ROCE_BOND_SLAVE_INC)
		hns_roce_slave_inc(bond_grp);
	else if (bond_ready && bond_state == HNS_ROCE_BOND_SLAVE_DEC)
		hns_roce_slave_dec(bond_grp);
	else if (!bond_ready && bond_state != HNS_ROCE_BOND_NOT_BONDED)
		hns_roce_clear_bond(bond_grp);
}

void hns_roce_do_bond_work(struct work_struct *work)
{
	struct delayed_work *delayed_work;
	struct hns_roce_dev *hr_dev;
	int status;

	delayed_work = to_delayed_work(work);
	hr_dev = container_of(delayed_work, struct hns_roce_dev, bond_work);
	status = mutex_trylock(&roce_bond_mutex);
	if (!status) {
		/* delay 1 sec */
		hns_roce_queue_bond_work(hr_dev, HZ);
		return;
	}

	hns_roce_do_bond(hr_dev->bond_grp);
	mutex_unlock(&roce_bond_mutex);
}

int hns_roce_bond_init(struct hns_roce_dev *hr_dev)
{
	int ret;

	INIT_DELAYED_WORK(&hr_dev->bond_work, hns_roce_do_bond_work);

	hr_dev->bond_nb.notifier_call = hns_roce_bond_event;
	ret = register_netdevice_notifier(&hr_dev->bond_nb);
	if (ret) {
		ibdev_err(&hr_dev->ib_dev,
			  "failed to register notifier for RoCE bond!\n");
		hr_dev->bond_nb.notifier_call = NULL;
	}

	return ret;
}

void hns_roce_cleanup_bond(struct hns_roce_dev *hr_dev)
{
	unregister_netdevice_notifier(&hr_dev->bond_nb);
	cancel_delayed_work(&hr_dev->bond_work);

	if (hr_dev->bond_grp && hr_dev == hr_dev->bond_grp->main_hr_dev)
		kfree(hr_dev->bond_grp);

	hr_dev->bond_grp = NULL;
}

static bool hns_roce_bond_lowerstate_event(struct hns_roce_dev *hr_dev,
					   struct netdev_notifier_changelowerstate_info *info)
{
	struct hns_roce_bond_group *bond_grp = hr_dev->bond_grp;
	struct netdev_lag_lower_state_info *bond_lower_info;
	struct net_device *net_dev;
	int i;

	net_dev = netdev_notifier_info_to_dev((struct netdev_notifier_info *)info);
	if (!netif_is_lag_port(net_dev))
		return false;

	bond_lower_info = info->lower_state_info;
	if (!bond_lower_info)
		return false;

	if (!bond_grp) {
		hr_dev->slave_state = *bond_lower_info;
		return false;
	}

	mutex_lock(&bond_grp->bond_mutex);

	for (i = 0; i < ROCE_BOND_FUNC_MAX; i++) {
		if (net_dev == bond_grp->bond_func_info[i].net_dev) {
			bond_grp->bond_func_info[i].state = *bond_lower_info;
			break;
		}
	}

	if (bond_grp->bond_ready &&
	    bond_grp->bond_state == HNS_ROCE_BOND_IS_BONDED)
		bond_grp->bond_state = HNS_ROCE_BOND_SLAVE_CHANGESTATE;

	mutex_unlock(&bond_grp->bond_mutex);

	return true;
}

static inline bool hns_roce_bond_mode_is_supported(enum netdev_lag_tx_type tx_type)
{
	if (tx_type != NETDEV_LAG_TX_TYPE_ACTIVEBACKUP &&
	    tx_type != NETDEV_LAG_TX_TYPE_HASH)
		return false;

	return true;
}

static void hns_roce_bond_info_record(struct hns_roce_bond_group *bond_grp,
				      struct net_device *upper_dev)
{
	struct hns_roce_v2_priv *priv;
	struct hns_roce_dev *hr_dev;
	struct net_device *net_dev;
	u8 func_idx;

	bond_grp->slave_num = 0;
	bond_grp->slave_map = 0;

	rcu_read_lock();
	for_each_netdev_in_bond_rcu(upper_dev, net_dev) {
		hr_dev = hns_roce_get_hrdev_by_netdev(net_dev);
		if (hr_dev) {
			func_idx = PCI_FUNC(hr_dev->pci_dev->devfn);
			bond_grp->slave_map |= (1 << func_idx);
			bond_grp->slave_num++;
			if (!bond_grp->bond_func_info[func_idx].net_dev) {
				priv = hr_dev->priv;

				bond_grp->bond_func_info[func_idx].net_dev =
					net_dev;

				bond_grp->bond_func_info[func_idx].handle =
					priv->handle;

				bond_grp->bond_func_info[func_idx].state =
					hr_dev->slave_state;
			}
		}
	}
	rcu_read_unlock();
}

static bool hns_roce_bond_upper_event(struct hns_roce_dev *hr_dev,
				      struct netdev_notifier_changeupper_info *info)
{
	struct hns_roce_bond_group *bond_grp = hr_dev->bond_grp;
	struct netdev_lag_upper_info *bond_upper_info = NULL;
	struct net_device *upper_dev = info->upper_dev;
	bool changed = false;
	u32 pre_slave_map;
	u8 pre_slave_num;

	if (!bond_grp || !upper_dev || !netif_is_lag_master(upper_dev))
		return false;

	if (info->linking)
		bond_upper_info = info->upper_info;

	mutex_lock(&bond_grp->bond_mutex);

	if (bond_upper_info)
		bond_grp->tx_type = bond_upper_info->tx_type;

	pre_slave_map = bond_grp->slave_map;
	pre_slave_num = bond_grp->slave_num;
	hns_roce_bond_info_record(bond_grp, upper_dev);

	bond_grp->bond = netdev_priv(upper_dev);

	if (bond_grp->bond_state == HNS_ROCE_BOND_NOT_BONDED) {
		bond_grp->bond_ready = true;
		changed = true;
	} else if (bond_grp->bond_state == HNS_ROCE_BOND_IS_BONDED &&
	    bond_grp->slave_num != pre_slave_num) {
		bond_grp->bond_state = bond_grp->slave_num > pre_slave_num ?
				       HNS_ROCE_BOND_SLAVE_INC :
				       HNS_ROCE_BOND_SLAVE_DEC;
		bond_grp->slave_map_diff = pre_slave_map ^ bond_grp->slave_map;
		bond_grp->bond_ready = true;
		changed = true;
	}

	mutex_unlock(&bond_grp->bond_mutex);

	return changed;
}

static struct hns_roce_bond_group *hns_roce_alloc_bond_grp(struct hns_roce_dev *main_hr_dev,
							   struct net_device *upper_dev)
{
	struct hns_roce_bond_group *bond_grp;

	bond_grp = kzalloc(sizeof(*bond_grp), GFP_KERNEL);
	if (!bond_grp)
		return NULL;

	mutex_init(&bond_grp->bond_mutex);
	bond_grp->upper_dev = upper_dev;
	bond_grp->main_hr_dev = main_hr_dev;
	bond_grp->main_net_dev = main_hr_dev->iboe.netdevs[0];
	bond_grp->bond_ready = false;
	bond_grp->bond_state = HNS_ROCE_BOND_NOT_BONDED;

	hns_roce_bond_info_record(bond_grp, upper_dev);

	return bond_grp;
}

static struct net_device *get_upper_dev_from_ndev(struct net_device *net_dev)
{
	struct net_device *upper_dev;

	rcu_read_lock();
	upper_dev = netdev_master_upper_dev_get_rcu(net_dev);
	rcu_read_unlock();

	return upper_dev;
}

static bool hns_roce_is_slave(struct net_device *upper_dev,
			      struct hns_roce_dev *hr_dev)
{
	return (hr_dev->bond_grp && upper_dev == hr_dev->bond_grp->upper_dev) ||
		upper_dev == get_upper_dev_from_ndev(hr_dev->iboe.netdevs[0]);
}

static bool hns_roce_is_bond_grp_exist(struct net_device *upper_dev)
{
	struct hns_roce_dev *hr_dev;
	struct net_device *net_dev;

	rcu_read_lock();
	for_each_netdev_in_bond_rcu(upper_dev, net_dev) {
		hr_dev = hns_roce_get_hrdev_by_netdev(net_dev);
		if (hr_dev && hr_dev->bond_grp) {
			rcu_read_unlock();
			return true;
		}
	}
	rcu_read_unlock();

	return false;
}

static enum bond_support_type
	check_bond_support(struct hns_roce_dev *hr_dev,
			   struct net_device **upper_dev,
			   struct netdev_notifier_changeupper_info *info)
{
	struct netdev_lag_upper_info *bond_upper_info = NULL;
	bool bond_grp_exist = false;
	struct net_device *net_dev;
	bool support = true;
	u8 slave_num = 0;
	int bus_num = -1;

	*upper_dev = info->upper_dev;
	if (hr_dev->bond_grp || hns_roce_is_bond_grp_exist(*upper_dev))
		bond_grp_exist = true;

	if (!info->linking && !bond_grp_exist)
		return BOND_NOT_SUPPORT;

	if (info->linking)
		bond_upper_info = info->upper_info;

	if (bond_upper_info &&
	    !hns_roce_bond_mode_is_supported(bond_upper_info->tx_type))
		return BOND_NOT_SUPPORT;

	rcu_read_lock();
	for_each_netdev_in_bond_rcu(*upper_dev, net_dev) {
		hr_dev = hns_roce_get_hrdev_by_netdev(net_dev);
		if (hr_dev) {
			slave_num++;
			if (bus_num == -1)
				bus_num = hr_dev->pci_dev->bus->number;
			if (hr_dev->is_vf || pci_num_vf(hr_dev->pci_dev) > 0 ||
			    bus_num != hr_dev->pci_dev->bus->number) {
				support = false;
				break;
			}
		}
	}
	rcu_read_unlock();

	if (slave_num <= 1)
		support = false;
	if (support)
		return BOND_SUPPORT;

	return bond_grp_exist ? BOND_EXISTING_NOT_SUPPORT : BOND_NOT_SUPPORT;
}

int hns_roce_bond_event(struct notifier_block *self,
			unsigned long event, void *ptr)
{
	struct net_device *net_dev = netdev_notifier_info_to_dev(ptr);
	struct hns_roce_dev *hr_dev =
		container_of(self, struct hns_roce_dev, bond_nb);
	enum bond_support_type support = BOND_SUPPORT;
	struct net_device *upper_dev;
	bool changed;

	if (event != NETDEV_CHANGEUPPER && event != NETDEV_CHANGELOWERSTATE)
		return NOTIFY_DONE;

	if (event == NETDEV_CHANGEUPPER) {
		support = check_bond_support(hr_dev, &upper_dev, ptr);
		if (support == BOND_NOT_SUPPORT)
			return NOTIFY_DONE;
	} else {
		upper_dev = get_upper_dev_from_ndev(net_dev);
	}

	if (upper_dev && !hns_roce_is_slave(upper_dev, hr_dev))
		return NOTIFY_DONE;
	else if (!upper_dev && hr_dev != hns_roce_get_hrdev_by_netdev(net_dev))
		return NOTIFY_DONE;

	if (event == NETDEV_CHANGEUPPER) {
		if (!hr_dev->bond_grp) {
			if (hns_roce_is_bond_grp_exist(upper_dev))
				return NOTIFY_DONE;
			hr_dev->bond_grp = hns_roce_alloc_bond_grp(hr_dev,
								   upper_dev);
			if (!hr_dev->bond_grp) {
				ibdev_err(&hr_dev->ib_dev,
					  "failed to alloc RoCE bond_grp!\n");
				return NOTIFY_DONE;
			}
		}
		if (support == BOND_EXISTING_NOT_SUPPORT) {
			hr_dev->bond_grp->bond_ready = false;
			hns_roce_queue_bond_work(hr_dev, HZ);
			return NOTIFY_DONE;
		}
		changed = hns_roce_bond_upper_event(hr_dev, ptr);
	} else {
		changed = hns_roce_bond_lowerstate_event(hr_dev, ptr);
	}
	if (changed)
		hns_roce_queue_bond_work(hr_dev, HZ);

	return NOTIFY_DONE;
}
