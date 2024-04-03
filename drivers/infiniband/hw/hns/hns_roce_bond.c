// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/*
 * Copyright (c) 2022 Hisilicon Limited.
 */

#include "hnae3.h"
#include "hns_roce_device.h"
#include "hns_roce_hw_v2.h"
#include "hns_roce_bond.h"

static DEFINE_MUTEX(roce_bond_mutex);
static DEFINE_XARRAY(roce_bond_xa);

static struct hns_roce_dev *hns_roce_get_hrdev_by_netdev(struct net_device *net_dev)
{
	struct ib_device *ibdev =
		ib_device_get_by_netdev(net_dev, RDMA_DRIVER_HNS);
	struct hns_roce_dev *hr_dev;

	if (!ibdev)
		return NULL;

	hr_dev = container_of(ibdev, struct hns_roce_dev, ib_dev);
	ib_device_put(ibdev);

	return hr_dev;
}

static struct net_device *get_upper_dev_from_ndev(struct net_device *net_dev)
{
	struct net_device *upper_dev;

	rcu_read_lock();
	upper_dev = netdev_master_upper_dev_get_rcu(net_dev);
	rcu_read_unlock();

	return upper_dev;
}

static int get_netdev_bond_slave_id(struct net_device *net_dev,
				    struct hns_roce_bond_group *bond_grp)
{
	int i;

	if (!net_dev || !bond_grp)
		return -ENODEV;

	for (i = 0; i < ROCE_BOND_FUNC_MAX; i++)
		if (net_dev == bond_grp->bond_func_info[i].net_dev)
			return i;

	return -ENOENT;
}

static bool is_hrdev_bond_slave(struct hns_roce_dev *hr_dev,
				struct net_device *upper_dev)
{
	struct hns_roce_bond_group *bond_grp;
	struct net_device *net_dev;
	u8 bus_num;

	if (!hr_dev || !upper_dev)
		return false;

	if (!netif_is_lag_master(upper_dev))
		return false;

	net_dev = get_hr_netdev(hr_dev, 0);
	bus_num = get_hr_bus_num(hr_dev);

	if (upper_dev == get_upper_dev_from_ndev(net_dev))
		return true;

	bond_grp = hns_roce_get_bond_grp(net_dev, bus_num);
	if (bond_grp && upper_dev == bond_grp->upper_dev)
		return true;

	return false;
}

struct hns_roce_bond_group *hns_roce_get_bond_grp(struct net_device *net_dev,
						  u8 bus_num)
{
	struct hns_roce_die_info *die_info = xa_load(&roce_bond_xa, bus_num);
	struct hns_roce_bond_group *bond_grp;
	int i;

	if (!die_info)
		return NULL;

	for (i = 0; i < ROCE_BOND_NUM_MAX; i++) {
		bond_grp = die_info->bgrps[i];
		if (!bond_grp)
			continue;
		if (get_netdev_bond_slave_id(net_dev, bond_grp) >= 0 ||
		    (bond_grp->upper_dev == get_upper_dev_from_ndev(net_dev)))
			return bond_grp;
	}

	return NULL;
}

bool hns_roce_bond_is_active(struct hns_roce_dev *hr_dev)
{
	struct net_device *net_dev = get_hr_netdev(hr_dev, 0);
	struct hns_roce_bond_group *bond_grp;
	u8 bus_num = get_hr_bus_num(hr_dev);

	bond_grp = hns_roce_get_bond_grp(net_dev, bus_num);

	if (bond_grp && bond_grp->bond_state != HNS_ROCE_BOND_NOT_BONDED)
		return true;

	return false;
}

static inline bool is_active_slave(struct net_device *net_dev,
				   struct hns_roce_bond_group *bond_grp)
{
	if (!bond_grp || !bond_grp->bond || !bond_grp->bond->curr_active_slave)
		return false;

	return net_dev == bond_grp->bond->curr_active_slave->dev;
}

struct net_device *hns_roce_get_bond_netdev(struct hns_roce_dev *hr_dev)
{
	struct net_device *net_dev = get_hr_netdev(hr_dev, 0);
	struct hns_roce_bond_group *bond_grp;
	u8 bus_num = get_hr_bus_num(hr_dev);
	int i;

	if (!(hr_dev->caps.flags & HNS_ROCE_CAP_FLAG_BOND))
		return NULL;

	bond_grp = hns_roce_get_bond_grp(net_dev, bus_num);
	if (!bond_grp)
		return NULL;

	mutex_lock(&bond_grp->bond_mutex);

	if (bond_grp->bond_state == HNS_ROCE_BOND_NOT_BONDED)
		goto out;

	if (bond_grp->tx_type == NETDEV_LAG_TX_TYPE_ACTIVEBACKUP) {
		for (i = 0; i < ROCE_BOND_FUNC_MAX; i++) {
			net_dev = bond_grp->bond_func_info[i].net_dev;
			if (net_dev && is_active_slave(net_dev, bond_grp) &&
			    get_port_state(net_dev) == IB_PORT_ACTIVE)
				goto out;
		}
	}

	for (i = 0; i < ROCE_BOND_FUNC_MAX; i++) {
		net_dev = bond_grp->bond_func_info[i].net_dev;
		if (net_dev && get_port_state(net_dev) == IB_PORT_ACTIVE)
			goto out;
	}

	net_dev = NULL;
out:
	mutex_unlock(&bond_grp->bond_mutex);

	return net_dev;
}

static void hns_roce_queue_bond_work(struct hns_roce_bond_group *bond_grp,
				     unsigned long delay)
{
	schedule_delayed_work(&bond_grp->bond_work, delay);
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
				is_active_slave(net_dev, bond_grp) :
				(get_port_state(net_dev) == IB_PORT_ACTIVE);
			if (active) {
				active_slave_num++;
				active_slave_map |= (1 << i);
			}
		}
	}

	bond_grp->active_slave_num = active_slave_num;
	bond_grp->active_slave_map = active_slave_map;
}

static int hns_roce_recover_bond(struct hns_roce_bond_group *bond_grp)
{
	hns_roce_bond_get_active_slave(bond_grp);

	return hns_roce_cmd_bond(bond_grp, HNS_ROCE_SET_BOND);
}

static void hns_roce_set_bond(struct hns_roce_bond_group *bond_grp)
{
	struct hns_roce_dev *hr_dev = NULL;
	struct net_device *net_dev;
	int ret;
	int i;

	for (i = ROCE_BOND_FUNC_MAX - 1; i >= 0; i--) {
		net_dev = bond_grp->bond_func_info[i].net_dev;
		if (net_dev) {
			ret = hns_roce_bond_uninit_client(bond_grp, i);
			if (ret)
				goto set_err;
		}
	}

	bond_grp->bond_state = HNS_ROCE_BOND_REGISTERING;
	bond_grp->main_hr_dev = NULL;

	for (i = 0; i < ROCE_BOND_FUNC_MAX; i++) {
		net_dev = bond_grp->bond_func_info[i].net_dev;
		if (net_dev) {
			hr_dev = hns_roce_bond_init_client(bond_grp, i);
			if (hr_dev) {
				bond_grp->main_hr_dev = hr_dev;
				break;
			}
		}
	}

	bond_grp->slave_map_diff = 0;
	hns_roce_bond_get_active_slave(bond_grp);

	ret = bond_grp->main_hr_dev ?
	      hns_roce_cmd_bond(bond_grp, HNS_ROCE_SET_BOND) : -EIO;
	if (ret)
		goto set_err;

	bond_grp->bond_state = HNS_ROCE_BOND_IS_BONDED;
	complete(&bond_grp->bond_work_done);
	ibdev_info(&bond_grp->main_hr_dev->ib_dev, "RoCE set bond finished!\n");

	return;

set_err:
	bond_grp->bond_state = HNS_ROCE_BOND_NOT_BONDED;
	BOND_ERR_LOG("failed to set RoCE bond, ret = %d.\n", ret);
	hns_roce_cleanup_bond(bond_grp);
}

static void hns_roce_clear_bond(struct hns_roce_bond_group *bond_grp)
{
	u8 main_func_idx = PCI_FUNC(bond_grp->main_hr_dev->pci_dev->devfn);
	struct hns_roce_dev *hr_dev = NULL;
	struct net_device *net_dev;
	int i, ret;

	if (bond_grp->bond_state == HNS_ROCE_BOND_NOT_BONDED)
		goto out;

	bond_grp->bond_state = HNS_ROCE_BOND_NOT_BONDED;
	bond_grp->main_hr_dev = NULL;

	ret = hns_roce_bond_uninit_client(bond_grp, main_func_idx);
	if (ret) {
		BOND_ERR_LOG("failed to uninit bond, ret = %d.\n", ret);
		return;
	}

	for (i = 0; i < ROCE_BOND_FUNC_MAX; i++) {
		net_dev = bond_grp->bond_func_info[i].net_dev;
		if (net_dev) {
			hr_dev = hns_roce_bond_init_client(bond_grp, i);
			if (hr_dev)
				bond_grp->main_hr_dev = hr_dev;
		}
	}

out:
	ret = hns_roce_cleanup_bond(bond_grp);
	if (!ret)
		ibdev_info(&bond_grp->main_hr_dev->ib_dev,
			   "RoCE clear bond finished!\n");
}

static void hns_roce_slave_changestate(struct hns_roce_bond_group *bond_grp)
{
	int ret;

	hns_roce_bond_get_active_slave(bond_grp);

	ret = hns_roce_cmd_bond(bond_grp, HNS_ROCE_CHANGE_BOND);

	bond_grp->bond_state = HNS_ROCE_BOND_IS_BONDED;
	complete(&bond_grp->bond_work_done);

	if (ret)
		ibdev_err(&bond_grp->main_hr_dev->ib_dev,
			  "failed to change RoCE bond slave state, ret = %d.\n",
			  ret);
	else
		ibdev_info(&bond_grp->main_hr_dev->ib_dev,
			   "RoCE slave changestate finished!\n");
}

static void hns_roce_slave_inc(struct hns_roce_bond_group *bond_grp)
{
	u32 inc_slave_map = bond_grp->slave_map_diff;
	u8 inc_func_idx = 0;
	int ret;

	while (inc_slave_map > 0) {
		if (inc_slave_map & 1) {
			ret = hns_roce_bond_uninit_client(bond_grp, inc_func_idx);
			if (ret) {
				BOND_ERR_LOG("failed to uninit slave %u, ret = %d.\n",
					     inc_func_idx, ret);
				bond_grp->bond_func_info[inc_func_idx].net_dev = NULL;
				bond_grp->slave_map &= ~(1U << inc_func_idx);
			}
		}
		inc_slave_map >>= 1;
		inc_func_idx++;
	}

	bond_grp->slave_map_diff = 0;
	hns_roce_bond_get_active_slave(bond_grp);

	ret = hns_roce_cmd_bond(bond_grp, HNS_ROCE_CHANGE_BOND);

	bond_grp->bond_state = HNS_ROCE_BOND_IS_BONDED;
	complete(&bond_grp->bond_work_done);

	if (ret)
		ibdev_err(&bond_grp->main_hr_dev->ib_dev,
			  "failed to increase slave, ret = %d.\n", ret);
	else
		ibdev_info(&bond_grp->main_hr_dev->ib_dev,
			   "RoCE slave increase finished!\n");
}

static int switch_main_dev(struct hns_roce_bond_group *bond_grp,
			   u32 *dec_slave_map, u8 main_func_idx)
{
	struct hns_roce_dev *hr_dev;
	struct net_device *net_dev;
	int ret;
	int i;

	bond_grp->main_hr_dev = NULL;
	ret = hns_roce_bond_uninit_client(bond_grp, main_func_idx);
	if (ret) {
		BOND_ERR_LOG("failed to uninit main dev %u, ret = %d.\n",
			     main_func_idx, ret);
		*dec_slave_map &= ~(1U << main_func_idx);
		bond_grp->slave_map |= (1U << main_func_idx);
		return ret;
	}

	for (i = 0; i < ROCE_BOND_FUNC_MAX; i++) {
		net_dev = bond_grp->bond_func_info[i].net_dev;
		if (!(*dec_slave_map & (1 << i)) && net_dev) {
			bond_grp->bond_state = HNS_ROCE_BOND_REGISTERING;
			hr_dev = hns_roce_bond_init_client(bond_grp, i);
			if (hr_dev) {
				bond_grp->main_hr_dev = hr_dev;
				break;
			}
		}
	}

	if (!bond_grp->main_hr_dev)
		return -ENODEV;

	return 0;
}

static void hns_roce_slave_dec(struct hns_roce_bond_group *bond_grp)
{
	u8 main_func_idx = PCI_FUNC(bond_grp->main_hr_dev->pci_dev->devfn);
	u32 dec_slave_map = bond_grp->slave_map_diff;
	struct net_device *net_dev;
	u8 dec_func_idx = 0;
	int ret;

	if (dec_slave_map & (1 << main_func_idx)) {
		ret = switch_main_dev(bond_grp, &dec_slave_map, main_func_idx);
		if (ret == -ENODEV)
			goto dec_err;
	}

	while (dec_slave_map > 0) {
		if (dec_slave_map & 1) {
			net_dev = bond_grp->bond_func_info[dec_func_idx].net_dev;
			bond_grp->bond_func_info[dec_func_idx].net_dev = NULL;
			if (!hns_roce_bond_init_client(bond_grp, dec_func_idx)) {
				BOND_ERR_LOG("failed to re-init slave %u.\n",
					     dec_func_idx);
				bond_grp->slave_map |= (1U << dec_func_idx);
				bond_grp->bond_func_info[dec_func_idx].net_dev = net_dev;
			}
		}
		dec_slave_map >>= 1;
		dec_func_idx++;
	}

	bond_grp->slave_map_diff = 0;
	hns_roce_bond_get_active_slave(bond_grp);

	ret = bond_grp->main_hr_dev ?
	      hns_roce_cmd_bond(bond_grp, HNS_ROCE_CHANGE_BOND) : -EIO;
	if (ret)
		goto dec_err;

	bond_grp->bond_state = HNS_ROCE_BOND_IS_BONDED;
	complete(&bond_grp->bond_work_done);
	ibdev_info(&bond_grp->main_hr_dev->ib_dev,
		   "RoCE slave decrease finished!\n");

	return;

dec_err:
	bond_grp->bond_state = HNS_ROCE_BOND_NOT_BONDED;
	BOND_ERR_LOG("failed to decrease RoCE bond slave, ret = %d.\n", ret);
	hns_roce_cleanup_bond(bond_grp);
}

static void hns_roce_do_bond(struct hns_roce_bond_group *bond_grp)
{
	enum hns_roce_bond_state bond_state = bond_grp->bond_state;
	bool bond_ready = bond_grp->bond_ready;

	if (!bond_grp->main_hr_dev)
		return;

	ibdev_info(&bond_grp->main_hr_dev->ib_dev,
		   "do_bond: bond_ready - %d, bond_state - %d.\n",
		   bond_ready, bond_grp->bond_state);

	reinit_completion(&bond_grp->bond_work_done);

	if (!bond_ready) {
		hns_roce_clear_bond(bond_grp);
		return;
	}

	switch (bond_state) {
	case HNS_ROCE_BOND_NOT_BONDED:
		hns_roce_set_bond(bond_grp);
		return;
	case HNS_ROCE_BOND_SLAVE_CHANGESTATE:
		hns_roce_slave_changestate(bond_grp);
		return;
	case HNS_ROCE_BOND_SLAVE_INC:
		hns_roce_slave_inc(bond_grp);
		return;
	case HNS_ROCE_BOND_SLAVE_DEC:
		hns_roce_slave_dec(bond_grp);
		return;
	default:
		return;
	}
}

bool is_bond_slave_in_reset(struct hns_roce_bond_group *bond_grp)
{
	struct hnae3_handle *handle;
	struct net_device *net_dev;
	int i;

	for (i = 0; i < ROCE_BOND_FUNC_MAX; i++) {
		net_dev = bond_grp->bond_func_info[i].net_dev;
		handle = bond_grp->bond_func_info[i].handle;
		if (net_dev && handle &&
		    handle->rinfo.reset_state != HNS_ROCE_STATE_NON_RST &&
		    handle->rinfo.reset_state != HNS_ROCE_STATE_RST_INITED)
			return true;
	}

	return false;
}

static void hns_roce_do_bond_work(struct work_struct *work)
{
	struct delayed_work *delayed_work = to_delayed_work(work);
	struct hns_roce_bond_group *bond_grp =
		container_of(delayed_work, struct hns_roce_bond_group,
			     bond_work);
	int status;

	if (is_bond_slave_in_reset(bond_grp))
		goto queue_work;

	status = mutex_trylock(&roce_bond_mutex);
	if (!status)
		goto queue_work;

	hns_roce_do_bond(bond_grp);
	mutex_unlock(&roce_bond_mutex);
	return;

queue_work:
	hns_roce_queue_bond_work(bond_grp, HZ);
}

int hns_roce_bond_init(struct hns_roce_dev *hr_dev)
{
	struct net_device *net_dev = get_hr_netdev(hr_dev, 0);
	struct hns_roce_v2_priv *priv = hr_dev->priv;
	struct hns_roce_bond_group *bond_grp;
	u8 bus_num = get_hr_bus_num(hr_dev);
	int ret;

	bond_grp = hns_roce_get_bond_grp(net_dev, bus_num);
	if (priv->handle->rinfo.reset_state == HNS_ROCE_STATE_RST_INIT &&
	    bond_grp) {
		bond_grp->main_hr_dev = hr_dev;
		ret = hns_roce_recover_bond(bond_grp);
		if (ret) {
			ibdev_err(&hr_dev->ib_dev,
				  "failed to recover RoCE bond, ret = %d.\n",
				  ret);
			return ret;
		}
	}

	hr_dev->bond_nb.notifier_call = hns_roce_bond_event;
	ret = register_netdevice_notifier(&hr_dev->bond_nb);
	if (ret) {
		ibdev_err(&hr_dev->ib_dev,
			  "failed to register notifier for RoCE bond, ret = %d.\n",
			  ret);
		hr_dev->bond_nb.notifier_call = NULL;
	}

	return ret;
}

static struct hns_roce_die_info *alloc_die_info(int bus_num)
{
	struct hns_roce_die_info *die_info;
	int ret;

	die_info = kzalloc(sizeof(struct hns_roce_die_info), GFP_KERNEL);
	if (!die_info)
		return NULL;

	ret = xa_err(xa_store(&roce_bond_xa, bus_num, die_info, GFP_KERNEL));
	if (ret) {
		kfree(die_info);
		return NULL;
	}

	return die_info;
}

static void dealloc_die_info(struct hns_roce_die_info *die_info, u8 bus_num)
{
	xa_erase(&roce_bond_xa, bus_num);
	kvfree(die_info);
}

static int alloc_bond_id(struct hns_roce_bond_group *bond_grp)
{
	u8 bus_num = bond_grp->bus_num;
	struct hns_roce_die_info *die_info = xa_load(&roce_bond_xa, bus_num);
	int i;

	if (!die_info) {
		die_info = alloc_die_info(bus_num);
		if (!die_info) {
			ibdev_err(&bond_grp->main_hr_dev->ib_dev,
				  "failed to alloc die_info.\n");
			return -ENOMEM;
		}
	}

	for (i = 0; i < ROCE_BOND_NUM_MAX; i++) {
		if (die_info->bond_id_mask & BOND_ID(i))
			continue;

		die_info->bond_id_mask |= BOND_ID(i);
		die_info->bgrps[i] = bond_grp;
		bond_grp->bond_id = i;

		return 0;
	}

	return -ENOSPC;
}

static int remove_bond_id(int bus_num, u8 bond_id)
{
	struct hns_roce_die_info *die_info = xa_load(&roce_bond_xa, bus_num);

	if (bond_id >= ROCE_BOND_NUM_MAX)
		return -EINVAL;

	if (!die_info)
		return -ENODEV;

	die_info->bond_id_mask &= ~BOND_ID(bond_id);
	die_info->bgrps[bond_id] = NULL;
	if (!die_info->bond_id_mask)
		dealloc_die_info(die_info, bus_num);

	return 0;
}

int hns_roce_cleanup_bond(struct hns_roce_bond_group *bond_grp)
{
	bool completion_no_waiter;
	int ret;

	ret = bond_grp->main_hr_dev ?
	      hns_roce_cmd_bond(bond_grp, HNS_ROCE_CLEAR_BOND) : -EIO;
	if (ret)
		BOND_ERR_LOG("failed to clear RoCE bond, ret = %d.\n", ret);

	cancel_delayed_work(&bond_grp->bond_work);
	ret = remove_bond_id(bond_grp->bus_num, bond_grp->bond_id);
	if (ret)
		BOND_ERR_LOG("failed to remove bond id %u, ret = %d.\n",
			     bond_grp->bond_id, ret);

	completion_no_waiter = completion_done(&bond_grp->bond_work_done);
	complete(&bond_grp->bond_work_done);
	mutex_destroy(&bond_grp->bond_mutex);
	if (completion_no_waiter)
		kfree(bond_grp);

	return ret;
}

static bool hns_roce_bond_lowerstate_event(struct hns_roce_dev *hr_dev,
					   struct hns_roce_bond_group *bond_grp,
					   struct netdev_notifier_changelowerstate_info *info)
{
	struct net_device *net_dev =
		netdev_notifier_info_to_dev((struct netdev_notifier_info *)info);

	if (!netif_is_lag_port(net_dev) ||
	    (!bond_grp || hr_dev != bond_grp->main_hr_dev))
		return false;

	mutex_lock(&bond_grp->bond_mutex);

	if (bond_grp->bond_ready &&
	    bond_grp->bond_state == HNS_ROCE_BOND_IS_BONDED)
		bond_grp->bond_state = HNS_ROCE_BOND_SLAVE_CHANGESTATE;

	mutex_unlock(&bond_grp->bond_mutex);

	return true;
}

static bool is_bond_setting_supported(struct netdev_lag_upper_info *bond_info)
{
	if (!bond_info)
		return false;

	if (bond_info->tx_type != NETDEV_LAG_TX_TYPE_ACTIVEBACKUP &&
	    bond_info->tx_type != NETDEV_LAG_TX_TYPE_HASH)
		return false;

	if (bond_info->tx_type == NETDEV_LAG_TX_TYPE_HASH &&
	    bond_info->hash_type > NETDEV_LAG_HASH_L23)
		return false;

	return true;
}

static void hns_roce_bond_info_update(struct hns_roce_bond_group *bond_grp,
				      struct net_device *upper_dev,
				      bool slave_inc)
{
	struct hns_roce_v2_priv *priv;
	struct hns_roce_dev *hr_dev;
	struct net_device *net_dev;
	u8 func_idx, i;

	if (!slave_inc) {
		for (i = 0; i < ROCE_BOND_FUNC_MAX; ++i) {
			net_dev = bond_grp->bond_func_info[i].net_dev;
			if (net_dev && upper_dev !=
				get_upper_dev_from_ndev(net_dev)) {
				bond_grp->slave_map_diff |= (1U << i);
				bond_grp->slave_map &= ~(1U << i);
			}
		}
		return;
	}

	rcu_read_lock();
	for_each_netdev_in_bond_rcu(upper_dev, net_dev) {
		hr_dev = hns_roce_get_hrdev_by_netdev(net_dev);
		if (hr_dev) {
			func_idx = PCI_FUNC(hr_dev->pci_dev->devfn);
			if (!bond_grp->bond_func_info[func_idx].net_dev) {
				bond_grp->slave_map_diff |= (1U << func_idx);
				bond_grp->slave_map |= (1U << func_idx);
				priv = hr_dev->priv;

				bond_grp->bond_func_info[func_idx].net_dev =
					net_dev;

				bond_grp->bond_func_info[func_idx].handle =
					priv->handle;
			}
		}
	}
	rcu_read_unlock();
}

static bool hns_roce_bond_upper_event(struct hns_roce_bond_group *bond_grp,
				      struct netdev_notifier_changeupper_info *info)
{
	struct netdev_lag_upper_info *bond_upper_info = NULL;
	struct net_device *upper_dev = info->upper_dev;
	bool slave_inc = info->linking;
	bool changed = false;

	if (!bond_grp || !upper_dev || !netif_is_lag_master(upper_dev))
		return false;

	if (slave_inc)
		bond_upper_info = info->upper_info;

	mutex_lock(&bond_grp->bond_mutex);

	if (bond_upper_info)
		bond_grp->tx_type = bond_upper_info->tx_type;

	hns_roce_bond_info_update(bond_grp, upper_dev, slave_inc);

	bond_grp->bond = netdev_priv(upper_dev);

	if (bond_grp->bond_state == HNS_ROCE_BOND_NOT_BONDED) {
		bond_grp->bond_ready = true;
		changed = true;
	} else {
		bond_grp->bond_state = slave_inc ?
				       HNS_ROCE_BOND_SLAVE_INC :
				       HNS_ROCE_BOND_SLAVE_DEC;
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
	int ret;

	bond_grp = kzalloc(sizeof(*bond_grp), GFP_KERNEL);
	if (!bond_grp)
		return NULL;

	mutex_init(&bond_grp->bond_mutex);

	INIT_DELAYED_WORK(&bond_grp->bond_work, hns_roce_do_bond_work);

	init_completion(&bond_grp->bond_work_done);

	bond_grp->upper_dev = upper_dev;
	bond_grp->main_hr_dev = main_hr_dev;
	bond_grp->bond_ready = false;
	bond_grp->bond_state = HNS_ROCE_BOND_NOT_BONDED;
	bond_grp->bus_num = main_hr_dev->pci_dev->bus->number;

	ret = alloc_bond_id(bond_grp);
	if (ret) {
		ibdev_err(&main_hr_dev->ib_dev,
			  "failed to alloc bond ID, ret = %d.\n", ret);
		mutex_destroy(&bond_grp->bond_mutex);
		kfree(bond_grp);
		return NULL;
	}

	hns_roce_bond_info_update(bond_grp, upper_dev, true);

	return bond_grp;
}

static bool is_dev_bond_supported(struct hns_roce_bond_group *bond_grp,
				  struct net_device *net_dev, int bus_num)
{
	struct hns_roce_dev *hr_dev = hns_roce_get_hrdev_by_netdev(net_dev);

	if (!hr_dev) {
		if (bond_grp &&
		    get_netdev_bond_slave_id(net_dev, bond_grp) >= 0)
			return true;
		else
			return false;
	}

	if (!(hr_dev->caps.flags & HNS_ROCE_CAP_FLAG_BOND))
		return false;

	if (hr_dev->is_vf || pci_num_vf(hr_dev->pci_dev) > 0)
		return false;

	if (bus_num != get_hr_bus_num(hr_dev))
		return false;

	return true;
}

static bool check_unlinking_bond_support(struct hns_roce_bond_group *bond_grp)
{
	struct net_device *net_dev;
	u8 slave_num = 0;

	rcu_read_lock();
	for_each_netdev_in_bond_rcu(bond_grp->upper_dev, net_dev) {
		if (get_netdev_bond_slave_id(net_dev, bond_grp) >= 0)
			slave_num++;
	}
	rcu_read_unlock();

	return (slave_num > 1);
}

static bool check_linking_bond_support(struct netdev_lag_upper_info *bond_info,
				       struct hns_roce_bond_group *bond_grp,
				       struct net_device *upper_dev,
				       int bus_num)
{
	struct net_device *net_dev;
	u8 slave_num = 0;

	if (!is_bond_setting_supported(bond_info))
		return false;

	rcu_read_lock();
	for_each_netdev_in_bond_rcu(upper_dev, net_dev) {
		if (is_dev_bond_supported(bond_grp, net_dev, bus_num)) {
			slave_num++;
		} else {
			rcu_read_unlock();
			return false;
		}
	}
	rcu_read_unlock();

	return (slave_num > 1 && slave_num <= ROCE_BOND_FUNC_MAX);
}

static enum bond_support_type
	check_bond_support(struct hns_roce_dev *hr_dev,
			   struct net_device **upper_dev,
			   struct netdev_notifier_changeupper_info *info)
{
	struct net_device *net_dev = get_hr_netdev(hr_dev, 0);
	struct hns_roce_bond_group *bond_grp;
	int bus_num = get_hr_bus_num(hr_dev);
	bool bond_grp_exist = false;
	bool support;

	*upper_dev = info->upper_dev;
	bond_grp = hns_roce_get_bond_grp(net_dev, bus_num);
	if (bond_grp && *upper_dev == bond_grp->upper_dev)
		bond_grp_exist = true;

	if (!info->linking && !bond_grp_exist)
		return BOND_NOT_SUPPORT;

	if (info->linking)
		support = check_linking_bond_support(info->upper_info, bond_grp,
						     *upper_dev, bus_num);
	else
		support = check_unlinking_bond_support(bond_grp);

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
	struct hns_roce_bond_group *bond_grp;
	u8 bus_num = get_hr_bus_num(hr_dev);
	struct net_device *upper_dev;
	bool changed;
	int slave_id;

	if (event != NETDEV_CHANGEUPPER && event != NETDEV_CHANGELOWERSTATE)
		return NOTIFY_DONE;

	if (event == NETDEV_CHANGEUPPER) {
		support = check_bond_support(hr_dev, &upper_dev, ptr);
		if (support == BOND_NOT_SUPPORT)
			return NOTIFY_DONE;
	} else {
		upper_dev = get_upper_dev_from_ndev(net_dev);
	}

	if (upper_dev && !is_hrdev_bond_slave(hr_dev, upper_dev))
		return NOTIFY_DONE;
	else if (!upper_dev && hr_dev != hns_roce_get_hrdev_by_netdev(net_dev))
		return NOTIFY_DONE;

	bond_grp = hns_roce_get_bond_grp(get_hr_netdev(hr_dev, 0), bus_num);
	if (event == NETDEV_CHANGEUPPER) {
		if (!bond_grp) {
			bond_grp = hns_roce_alloc_bond_grp(hr_dev, upper_dev);
			if (!bond_grp) {
				ibdev_err(&hr_dev->ib_dev,
					  "failed to alloc RoCE bond_grp!\n");
				return NOTIFY_DONE;
			}
		} else if (hr_dev != bond_grp->main_hr_dev) {
			return NOTIFY_DONE;
		}
		/* In the case of netdev being unregistered, the roce
		 * instance shouldn't be inited.
		 */
		if (net_dev->reg_state >= NETREG_UNREGISTERING) {
			slave_id = get_netdev_bond_slave_id(net_dev, bond_grp);
			if (slave_id >= 0)
				bond_grp->bond_func_info[slave_id].handle = NULL;
		}

		if (support == BOND_EXISTING_NOT_SUPPORT) {
			bond_grp->bond_ready = false;
			hns_roce_queue_bond_work(bond_grp, HZ);
			return NOTIFY_DONE;
		}
		changed = hns_roce_bond_upper_event(bond_grp, ptr);
	} else {
		changed = hns_roce_bond_lowerstate_event(hr_dev, bond_grp, ptr);
	}
	if (changed)
		hns_roce_queue_bond_work(bond_grp, HZ);

	return NOTIFY_DONE;
}
