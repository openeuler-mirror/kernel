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
		if (get_netdev_bond_slave_id(net_dev, bond_grp) >= 0)
			return bond_grp;
		if (bond_grp->upper_dev &&
		    bond_grp->upper_dev == get_upper_dev_from_ndev(net_dev))
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
	if (bond_grp && bond_grp->bond_state != HNS_ROCE_BOND_NOT_BONDED &&
	    bond_grp->bond_state != HNS_ROCE_BOND_NOT_ATTACHED)
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
		if (!net_dev || !(bond_grp->slave_map & (1U << i)))
			continue;

		active = (bond_grp->tx_type == NETDEV_LAG_TX_TYPE_ACTIVEBACKUP) ?
			 is_active_slave(net_dev, bond_grp) :
			 (get_port_state(net_dev) == IB_PORT_ACTIVE);
		if (active) {
			active_slave_num++;
			active_slave_map |= (1 << i);
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

static int hns_roce_slave_uninit(struct hns_roce_bond_group *bond_grp,
				 u8 func_idx)
{
	struct net_device *net_dev;
	int ret = 0;

	net_dev = bond_grp->bond_func_info[func_idx].net_dev;
	if (hns_roce_get_hrdev_by_netdev(net_dev)) {
		ret = hns_roce_bond_uninit_client(bond_grp, func_idx);
		if (ret) {
			BOND_ERR_LOG("failed to uninit slave %u, ret = %d.\n",
				     func_idx, ret);
			bond_grp->bond_func_info[func_idx].net_dev = NULL;
		}
	}

	return ret;
}

static struct hns_roce_dev
	*hns_roce_slave_init(struct hns_roce_bond_group *bond_grp,
			     u8 func_idx, bool need_switch);

static int switch_main_dev(struct hns_roce_bond_group *bond_grp,
			   u8 main_func_idx)
{
	struct hns_roce_dev *hr_dev;
	struct net_device *net_dev;
	int ret;
	u8 i;

	bond_grp->main_hr_dev = NULL;
	ret = hns_roce_bond_uninit_client(bond_grp, main_func_idx);
	if (ret) {
		BOND_ERR_LOG("failed to uninit main dev %u, ret = %d.\n",
			     main_func_idx, ret);
		return ret;
	}

	for (i = 0; i < ROCE_BOND_FUNC_MAX; i++) {
		net_dev = bond_grp->bond_func_info[i].net_dev;
		if ((bond_grp->slave_map & (1U << i)) && net_dev) {
			/* In case this slave is still being registered as
			 * a non-bonded PF, uninit it first and then re-init
			 * it as the main device.
			 */
			hns_roce_slave_uninit(bond_grp, i);
			hr_dev = hns_roce_slave_init(bond_grp, i, false);
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

static struct hns_roce_dev
	*hns_roce_slave_init(struct hns_roce_bond_group *bond_grp,
			     u8 func_idx, bool need_switch)
{
	struct hns_roce_dev *hr_dev = NULL;
	struct net_device *net_dev;
	u8 main_func_idx;
	int ret;

	if (need_switch) {
		main_func_idx = PCI_FUNC(bond_grp->main_hr_dev->pci_dev->devfn);
		if (func_idx == main_func_idx) {
			ret = switch_main_dev(bond_grp, main_func_idx);
			if (ret == -ENODEV)
				return NULL;
		}
	}

	net_dev = bond_grp->bond_func_info[func_idx].net_dev;
	if (net_dev) {
		hr_dev = hns_roce_get_hrdev_by_netdev(net_dev);
		if (hr_dev)
			return hr_dev;
		if (need_switch)
			bond_grp->bond_func_info[func_idx].net_dev = NULL;
		hr_dev = hns_roce_bond_init_client(bond_grp, func_idx);
		if (!hr_dev) {
			BOND_ERR_LOG("failed to init slave %u.\n", func_idx);
			bond_grp->bond_func_info[func_idx].net_dev = net_dev;
		}
	}

	return hr_dev;
}

static void hns_roce_set_bond(struct hns_roce_bond_group *bond_grp)
{
	struct hns_roce_dev *hr_dev;
	int ret;
	int i;

	for (i = ROCE_BOND_FUNC_MAX - 1; i >= 0; i--) {
		if (bond_grp->slave_map & (1 << i)) {
			ret = hns_roce_slave_uninit(bond_grp, i);
			if (ret)
				goto out;
		}
	}

	mutex_lock(&bond_grp->bond_mutex);
	bond_grp->bond_state = HNS_ROCE_BOND_IS_BONDED;
	mutex_unlock(&bond_grp->bond_mutex);
	bond_grp->main_hr_dev = NULL;

	for (i = 0; i < ROCE_BOND_FUNC_MAX; i++) {
		if (bond_grp->slave_map & (1 << i)) {
			hr_dev = hns_roce_slave_init(bond_grp, i, false);
			if (hr_dev) {
				bond_grp->main_hr_dev = hr_dev;
				break;
			}
		}
	}

	if (!bond_grp->main_hr_dev) {
		ret = -ENODEV;
		goto out;
	}

	hns_roce_bond_get_active_slave(bond_grp);

	ret = hns_roce_cmd_bond(bond_grp, HNS_ROCE_SET_BOND);

out:
	if (ret) {
		BOND_ERR_LOG("failed to set RoCE bond, ret = %d.\n", ret);
		hns_roce_cleanup_bond(bond_grp);
	} else {
		ibdev_info(&bond_grp->main_hr_dev->ib_dev,
			   "RoCE set bond finished!\n");
		complete(&bond_grp->bond_work_done);
	}
}

static void hns_roce_clear_bond(struct hns_roce_bond_group *bond_grp)
{
	u8 main_func_idx = PCI_FUNC(bond_grp->main_hr_dev->pci_dev->devfn);
	struct hns_roce_dev *hr_dev;
	int ret;
	u8 i;

	if (bond_grp->bond_state == HNS_ROCE_BOND_NOT_BONDED)
		goto out;

	bond_grp->bond_state = HNS_ROCE_BOND_NOT_BONDED;
	bond_grp->main_hr_dev = NULL;

	ret = hns_roce_slave_uninit(bond_grp, main_func_idx);
	if (ret) {
		BOND_ERR_LOG("failed to uninit bond, ret = %d.\n", ret);
		return;
	}

	for (i = 0; i < ROCE_BOND_FUNC_MAX; i++) {
		hr_dev = hns_roce_slave_init(bond_grp, i, false);
		if (hr_dev)
			bond_grp->main_hr_dev = hr_dev;
	}

out:
	hns_roce_cleanup_bond(bond_grp);
}

static void hns_roce_slave_changestate(struct hns_roce_bond_group *bond_grp)
{
	int ret;

	hns_roce_bond_get_active_slave(bond_grp);

	ret = hns_roce_cmd_bond(bond_grp, HNS_ROCE_CHANGE_BOND);

	mutex_lock(&bond_grp->bond_mutex);
	if (bond_grp->bond_state == HNS_ROCE_BOND_SLAVE_CHANGESTATE)
		bond_grp->bond_state = HNS_ROCE_BOND_IS_BONDED;
	mutex_unlock(&bond_grp->bond_mutex);
	complete(&bond_grp->bond_work_done);

	if (ret)
		ibdev_err(&bond_grp->main_hr_dev->ib_dev,
			  "failed to change RoCE bond slave state, ret = %d.\n",
			  ret);
	else
		ibdev_info(&bond_grp->main_hr_dev->ib_dev,
			   "RoCE slave changestate finished!\n");
}

static void hns_roce_slave_change_num(struct hns_roce_bond_group *bond_grp)
{
	int ret;
	u8 i;

	for (i = 0; i < ROCE_BOND_FUNC_MAX; i++) {
		if (bond_grp->slave_map & (1U << i)) {
			if (i == PCI_FUNC(bond_grp->main_hr_dev->pci_dev->devfn))
				continue;
			ret = hns_roce_slave_uninit(bond_grp, i);
			if (ret)
				goto out;
		} else {
			hns_roce_slave_init(bond_grp, i, true);
			if (!bond_grp->main_hr_dev) {
				ret = -ENODEV;
				goto out;
			}
		}
	}

	hns_roce_bond_get_active_slave(bond_grp);

	ret = hns_roce_cmd_bond(bond_grp, HNS_ROCE_CHANGE_BOND);

out:
	if (ret) {
		BOND_ERR_LOG("failed to change RoCE bond slave num, ret = %d.\n", ret);
		hns_roce_cleanup_bond(bond_grp);
	} else {
		mutex_lock(&bond_grp->bond_mutex);
		if (bond_grp->bond_state == HNS_ROCE_BOND_SLAVE_CHANGE_NUM)
			bond_grp->bond_state = HNS_ROCE_BOND_IS_BONDED;
		mutex_unlock(&bond_grp->bond_mutex);
		ibdev_info(&bond_grp->main_hr_dev->ib_dev,
			   "RoCE slave change num finished!\n");
		complete(&bond_grp->bond_work_done);
	}
}

static void hns_roce_bond_info_update_nolock(struct hns_roce_bond_group *bond_grp,
					     struct net_device *upper_dev)
{
	struct hns_roce_v2_priv *priv;
	struct hns_roce_dev *hr_dev;
	struct net_device *net_dev;
	int func_idx;

	bond_grp->slave_map = 0;
	rcu_read_lock();
	for_each_netdev_in_bond_rcu(upper_dev, net_dev) {
		hr_dev = hns_roce_get_hrdev_by_netdev(net_dev);
		if (hr_dev) {
			func_idx = PCI_FUNC(hr_dev->pci_dev->devfn);
			if (!bond_grp->bond_func_info[func_idx].net_dev) {
				priv = hr_dev->priv;
				bond_grp->bond_func_info[func_idx].net_dev =
					net_dev;

				bond_grp->bond_func_info[func_idx].handle =
					priv->handle;
			}
		} else {
			func_idx = get_netdev_bond_slave_id(net_dev, bond_grp);
			if (func_idx < 0)
				continue;
		}
		bond_grp->slave_map |= (1 << func_idx);
	}
	rcu_read_unlock();
}

static bool is_dev_bond_supported(struct hns_roce_bond_group *bond_grp,
				  struct net_device *net_dev)
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

	if (bond_grp->bus_num != get_hr_bus_num(hr_dev))
		return false;

	return true;
}

static bool check_slave_support(struct hns_roce_bond_group *bond_grp,
				struct net_device *upper_dev)
{
	struct net_device *net_dev;
	u8 slave_num = 0;

	rcu_read_lock();
	for_each_netdev_in_bond_rcu(upper_dev, net_dev) {
		if (is_dev_bond_supported(bond_grp, net_dev)) {
			slave_num++;
			continue;
		}
		rcu_read_unlock();
		return false;
	}
	rcu_read_unlock();

	return (slave_num > 1 && slave_num <= ROCE_BOND_FUNC_MAX);
}

static void hns_roce_do_bond(struct hns_roce_bond_group *bond_grp)
{
	enum hns_roce_bond_state bond_state;
	bool bond_ready;

	if (!bond_grp->main_hr_dev)
		return;

	bond_ready = check_slave_support(bond_grp, bond_grp->upper_dev);

	mutex_lock(&bond_grp->bond_mutex);
	hns_roce_bond_info_update_nolock(bond_grp, bond_grp->upper_dev);
	bond_state = bond_grp->bond_state;
	bond_grp->bond_ready = bond_ready;
	mutex_unlock(&bond_grp->bond_mutex);

	ibdev_info(&bond_grp->main_hr_dev->ib_dev,
		   "do_bond: bond_ready - %d, bond_state - %d.\n",
		   bond_ready, bond_state);

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
	case HNS_ROCE_BOND_SLAVE_CHANGE_NUM:
		hns_roce_slave_change_num(bond_grp);
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

static int hns_roce_alloc_bond_grp(struct hns_roce_dev *hr_dev)
{
	struct hns_roce_bond_group *bgrps[ROCE_BOND_NUM_MAX];
	struct hns_roce_bond_group *bond_grp;
	int ret;
	int i;

	for (i = 0; i < ROCE_BOND_NUM_MAX; i++) {
		bond_grp = kvzalloc(sizeof(*bond_grp), GFP_KERNEL);
		if (!bond_grp) {
			ret = -ENOMEM;
			goto mem_err;
		}

		mutex_init(&bond_grp->bond_mutex);
		INIT_DELAYED_WORK(&bond_grp->bond_work, hns_roce_do_bond_work);
		init_completion(&bond_grp->bond_work_done);

		bond_grp->bond_ready = false;
		bond_grp->bond_state = HNS_ROCE_BOND_NOT_ATTACHED;
		bond_grp->bus_num = get_hr_bus_num(hr_dev);

		ret = alloc_bond_id(bond_grp);
		if (ret) {
			ibdev_err(&hr_dev->ib_dev,
				  "failed to alloc bond ID, ret = %d.\n", ret);
			goto alloc_id_err;
		}

		bond_grp->bond_nb.notifier_call = hns_roce_bond_event;
		ret = register_netdevice_notifier(&bond_grp->bond_nb);
		if (ret) {
			ibdev_err(&hr_dev->ib_dev,
				  "failed to register bond nb, ret = %d.\n", ret);
			goto register_nb_err;
		}
		bgrps[i] = bond_grp;
	}

	return 0;

register_nb_err:
	remove_bond_id(bond_grp->bus_num, bond_grp->bond_id);
alloc_id_err:
	mutex_destroy(&bond_grp->bond_mutex);
	kvfree(bond_grp);
mem_err:
	for (i--; i >= 0; i--) {
		unregister_netdevice_notifier(&bgrps[i]->bond_nb);
		cancel_delayed_work_sync(&bgrps[i]->bond_work);
		complete(&bgrps[i]->bond_work_done);
		remove_bond_id(bgrps[i]->bus_num, bgrps[i]->bond_id);
		mutex_destroy(&bgrps[i]->bond_mutex);
		kvfree(bgrps[i]);
	}
	return ret;
}

void hns_roce_dealloc_bond_grp(void)
{
	struct hns_roce_bond_group *bond_grp;
	struct hns_roce_die_info *die_info;
	unsigned long id;
	int i;

	xa_for_each(&roce_bond_xa, id, die_info) {
		for (i = 0; i < ROCE_BOND_NUM_MAX; i++) {
			bond_grp = die_info->bgrps[i];
			if (!bond_grp)
				continue;
			unregister_netdevice_notifier(&bond_grp->bond_nb);
			cancel_delayed_work_sync(&bond_grp->bond_work);
			remove_bond_id(bond_grp->bus_num, bond_grp->bond_id);
			mutex_destroy(&bond_grp->bond_mutex);
			kvfree(bond_grp);
		}
	}
}

int hns_roce_bond_init(struct hns_roce_dev *hr_dev)
{
	struct net_device *net_dev = get_hr_netdev(hr_dev, 0);
	struct hns_roce_v2_priv *priv = hr_dev->priv;
	struct hns_roce_bond_group *bond_grp;
	u8 bus_num = get_hr_bus_num(hr_dev);
	int ret = 0;

	if (priv->handle->rinfo.reset_state == HNS_ROCE_STATE_RST_INIT) {
		bond_grp = hns_roce_get_bond_grp(net_dev, bus_num);
		if (!bond_grp)
			return 0;

		bond_grp->main_hr_dev = hr_dev;
		ret = hns_roce_recover_bond(bond_grp);
		if (ret)
			ibdev_err(&hr_dev->ib_dev,
				  "failed to recover RoCE bond, ret = %d.\n",
				  ret);
		return ret;
	}

	if (!xa_load(&roce_bond_xa, bus_num)) {
		ret = hns_roce_alloc_bond_grp(hr_dev);
		if (ret)
			ibdev_err(&hr_dev->ib_dev,
				  "failed to alloc RoCE bond, ret = %d.\n",
				  ret);
	}

	return ret;
}

static void hns_roce_attach_bond_grp(struct hns_roce_bond_group *bond_grp,
				     struct hns_roce_dev *hr_dev,
				     struct net_device *upper_dev)
{
	bond_grp->upper_dev = upper_dev;
	bond_grp->main_hr_dev = hr_dev;
	bond_grp->bond_state = HNS_ROCE_BOND_NOT_BONDED;
	bond_grp->bond_ready = false;
}

static void hns_roce_detach_bond_grp(struct hns_roce_bond_group *bond_grp)
{
	mutex_lock(&bond_grp->bond_mutex);

	cancel_delayed_work(&bond_grp->bond_work);
	bond_grp->upper_dev = NULL;
	bond_grp->main_hr_dev = NULL;
	bond_grp->bond_ready = false;
	bond_grp->bond_state = HNS_ROCE_BOND_NOT_ATTACHED;
	bond_grp->slave_map = 0;
	memset(bond_grp->bond_func_info, 0, sizeof(bond_grp->bond_func_info));

	mutex_unlock(&bond_grp->bond_mutex);
}

void hns_roce_cleanup_bond(struct hns_roce_bond_group *bond_grp)
{
	int ret;

	ret = bond_grp->main_hr_dev ?
	      hns_roce_cmd_bond(bond_grp, HNS_ROCE_CLEAR_BOND) : -EIO;
	if (ret)
		BOND_ERR_LOG("failed to clear RoCE bond, ret = %d.\n", ret);
	else
		ibdev_info(&bond_grp->main_hr_dev->ib_dev,
			   "RoCE clear bond finished!\n");

	hns_roce_detach_bond_grp(bond_grp);
	complete(&bond_grp->bond_work_done);
}

static bool lowerstate_event_filter(struct hns_roce_bond_group *bond_grp,
				    struct net_device *net_dev)
{
	struct hns_roce_bond_group *bond_grp_tmp;

	bond_grp_tmp = hns_roce_get_bond_grp(net_dev, bond_grp->bus_num);
	return bond_grp_tmp == bond_grp;
}

static void lowerstate_event_setting(struct hns_roce_bond_group *bond_grp,
			struct netdev_notifier_changelowerstate_info *info)
{
	mutex_lock(&bond_grp->bond_mutex);

	if (bond_grp->bond_ready &&
	    bond_grp->bond_state == HNS_ROCE_BOND_IS_BONDED)
		bond_grp->bond_state = HNS_ROCE_BOND_SLAVE_CHANGESTATE;

	mutex_unlock(&bond_grp->bond_mutex);
}

static bool hns_roce_bond_lowerstate_event(struct hns_roce_bond_group *bond_grp,
					   struct netdev_notifier_changelowerstate_info *info)
{
	struct net_device *net_dev =
		netdev_notifier_info_to_dev((struct netdev_notifier_info *)info);

	if (!netif_is_lag_port(net_dev))
		return false;

	if (!lowerstate_event_filter(bond_grp, net_dev))
		return false;

	lowerstate_event_setting(bond_grp, info);

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

static void upper_event_setting(struct hns_roce_bond_group *bond_grp,
				struct netdev_notifier_changeupper_info *info)
{
	struct netdev_lag_upper_info *bond_upper_info = NULL;
	struct net_device *upper_dev = info->upper_dev;
	bool slave_inc = info->linking;

	if (slave_inc)
		bond_upper_info = info->upper_info;

	if (bond_upper_info)
		bond_grp->tx_type = bond_upper_info->tx_type;

	bond_grp->bond = netdev_priv(upper_dev);
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
				       struct net_device *upper_dev)
{
	if (!is_bond_setting_supported(bond_info))
		return false;

	return check_slave_support(bond_grp, upper_dev);
}

static enum bond_support_type
	check_bond_support(struct hns_roce_bond_group *bond_grp,
			   struct net_device *upper_dev,
			   struct netdev_notifier_changeupper_info *info)
{
	bool bond_grp_exist = false;
	bool support;

	if (upper_dev == bond_grp->upper_dev)
		bond_grp_exist = true;

	if (!info->linking && !bond_grp_exist)
		return BOND_NOT_SUPPORT;

	if (info->linking)
		support = check_linking_bond_support(info->upper_info, bond_grp,
						     upper_dev);
	else
		support = check_unlinking_bond_support(bond_grp);
	if (support)
		return BOND_SUPPORT;

	return bond_grp_exist ? BOND_EXISTING_NOT_SUPPORT : BOND_NOT_SUPPORT;
}

static bool upper_event_filter(struct netdev_notifier_changeupper_info *info,
			       struct hns_roce_bond_group *bond_grp,
			       struct net_device *net_dev)
{
	struct net_device *upper_dev = info->upper_dev;
	struct hns_roce_bond_group *bond_grp_tmp;
	struct hns_roce_dev *hr_dev;
	u8 bus_num;

	if (!info->linking)
		return bond_grp->upper_dev == upper_dev;

	hr_dev = hns_roce_get_hrdev_by_netdev(net_dev);
	if (!hr_dev)
		return false;

	bus_num = get_hr_bus_num(hr_dev);
	if (bond_grp->bus_num != bus_num)
		return false;

	bond_grp_tmp = hns_roce_get_bond_grp(net_dev, bus_num);
	if (bond_grp_tmp && bond_grp_tmp != bond_grp)
		return false;

	if (bond_grp->bond_state != HNS_ROCE_BOND_NOT_ATTACHED &&
	    bond_grp->upper_dev != upper_dev)
		return false;

	return true;
}

static bool hns_roce_bond_upper_event(struct hns_roce_bond_group *bond_grp,
				struct netdev_notifier_changeupper_info *info)
{
	struct net_device *net_dev =
		netdev_notifier_info_to_dev((struct netdev_notifier_info *)info);
	struct net_device *upper_dev = info->upper_dev;
	enum bond_support_type support = BOND_SUPPORT;
	struct hns_roce_dev *hr_dev;
	int slave_id;

	if (!upper_dev || !netif_is_lag_master(upper_dev))
		return false;

	if (!upper_event_filter(info, bond_grp, net_dev))
		return false;

	mutex_lock(&bond_grp->bond_mutex);
	support = check_bond_support(bond_grp, upper_dev, info);
	if (support == BOND_NOT_SUPPORT) {
		mutex_unlock(&bond_grp->bond_mutex);
		return false;
	}

	if (bond_grp->bond_state == HNS_ROCE_BOND_NOT_ATTACHED) {
		hr_dev = hns_roce_get_hrdev_by_netdev(net_dev);
		if (!hr_dev) {
			mutex_unlock(&bond_grp->bond_mutex);
			return false;
		}
		hns_roce_attach_bond_grp(bond_grp, hr_dev, upper_dev);
	}

	/* In the case of netdev being unregistered, the roce
	 * instance shouldn't be inited.
	 */
	if (net_dev->reg_state >= NETREG_UNREGISTERING) {
		slave_id = get_netdev_bond_slave_id(net_dev, bond_grp);
		if (slave_id >= 0) {
			bond_grp->bond_func_info[slave_id].net_dev = NULL;
			bond_grp->bond_func_info[slave_id].handle = NULL;
		}
	}

	if (support == BOND_SUPPORT) {
		bond_grp->bond_ready = true;
		if (bond_grp->bond_state != HNS_ROCE_BOND_NOT_BONDED)
			bond_grp->bond_state = HNS_ROCE_BOND_SLAVE_CHANGE_NUM;
	}
	mutex_unlock(&bond_grp->bond_mutex);
	if (support == BOND_SUPPORT)
		upper_event_setting(bond_grp, info);

	return true;
}

int hns_roce_bond_event(struct notifier_block *self,
			unsigned long event, void *ptr)
{
	struct hns_roce_bond_group *bond_grp =
		container_of(self, struct hns_roce_bond_group, bond_nb);
	bool changed;

	if (event != NETDEV_CHANGEUPPER && event != NETDEV_CHANGELOWERSTATE)
		return NOTIFY_DONE;

	if (event == NETDEV_CHANGEUPPER)
		changed = hns_roce_bond_upper_event(bond_grp, ptr);
	else
		changed = hns_roce_bond_lowerstate_event(bond_grp, ptr);

	if (changed)
		hns_roce_queue_bond_work(bond_grp, HZ);

	return NOTIFY_DONE;
}
