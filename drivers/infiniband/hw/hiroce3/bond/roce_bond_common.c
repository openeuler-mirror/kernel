// SPDX-License-Identifier: GPL-2.0
// Copyright(c) 2024 Huawei Technologies Co., Ltd

#ifdef ROCE_BONDING_EN

#include <rdma/ib_user_verbs.h>
#include <rdma/ib_addr.h>
#include <rdma/ib_cache.h>

#include <net/bonding.h>

#include "bond_common_defs.h"

#include "hinic3_hw.h"
#include "hinic3_srv_nic.h"

#include "roce_bond.h"
#include "roce_cmd.h"
#include "roce_netdev.h"

static bool g_roce3_bond_ipsurx_en = true;

static LIST_HEAD(g_roce3_bond_list);
static DEFINE_MUTEX(g_roce3_bond_mutex);

static struct workqueue_struct *g_bond_wq;

struct roce3_detach_work {
	u16 bond_id;
	struct work_struct work;
};

struct roce3_bond_work {
	char name[IFNAMSIZ];
	struct work_struct work;
};

bool roce3_get_bond_ipsurx_en(void)
{
	return g_roce3_bond_ipsurx_en;
}

void roce3_set_bond_ipsurx_en(bool ipsurx_en)
{
	g_roce3_bond_ipsurx_en = ipsurx_en;
}

static enum netdev_lag_tx_type roce3_get_tx_type_by_bond_mode(u16 bond_mode)
{
	switch (bond_mode) {
	case BOND_MODE_8023AD:
	case BOND_MODE_XOR:
		return NETDEV_LAG_TX_TYPE_HASH;
	case BOND_MODE_ACTIVEBACKUP:
		return NETDEV_LAG_TX_TYPE_ACTIVEBACKUP;
	default:
		return NETDEV_LAG_TX_TYPE_UNKNOWN;
	}
}

static bool roce3_bond_mode_is_supported(u16 bond_mode)
{
	enum netdev_lag_tx_type tx_type = roce3_get_tx_type_by_bond_mode(bond_mode);

	if ((tx_type != NETDEV_LAG_TX_TYPE_ACTIVEBACKUP) && (tx_type != NETDEV_LAG_TX_TYPE_HASH)) {
		pr_err("[ROCE, ERR] %s: Failed to support bond mode(%d)\n", __func__, tx_type);
		return false;
	}
	return true;
}

static bool is_hinic3_netdev(struct net_device *netdev)
{
	return (hinic3_get_lld_dev_by_netdev(netdev) != NULL);
}

static bool roce3_can_do_bond(struct bonding *bond)
{
	bool ret = false;
	int slave_cnt = 0;
	struct slave *slave = NULL;
	struct list_head *iter = NULL;
	struct hinic3_lld_dev *lld_dev = NULL;
	struct hinic3_lld_dev *ppf_dev = NULL;

	if (!bond || !roce3_bond_mode_is_supported(bond->params.mode))
		return ret;

	rcu_read_lock();
	bond_for_each_slave_rcu(bond, slave, iter) {
		lld_dev = hinic3_get_lld_dev_by_netdev(slave->dev);
		if (!lld_dev)
			goto out;

		if (!hinic3_support_roce(lld_dev->hwdev, NULL))
			goto out;

		if (!ppf_dev) {
			ppf_dev = hinic3_get_ppf_lld_dev(lld_dev);
			if (!ppf_dev)
				goto out;
		}

		if (hinic3_get_ppf_lld_dev(lld_dev) != ppf_dev)
			goto out;

		slave_cnt++;
		pr_info("%s:can do bond? slave_cnt(%d), slave_name(%s)",
			__func__, slave_cnt, slave->dev->name);
	}

	ret = (slave_cnt == ROCE_BOND_2_FUNC_NUM);
out:
	rcu_read_unlock();
	return ret;
}

struct net_device *roce3_bond_get_netdev(struct roce3_device *rdev)
{
	int i;
	struct roce3_bond_device *bond_dev = rdev->bond_dev;
	struct net_device *ret_dev = NULL;
	struct slave *slave = NULL;

	mutex_lock(&g_roce3_bond_mutex);
	if (!bond_dev) {
		mutex_unlock(&g_roce3_bond_mutex);
		return ret_dev;
	}

	mutex_lock(&bond_dev->slave_lock);
	for (i = 0; i < bond_dev->slave_cnt; i++) {
		rcu_read_lock();
		slave = bond_slave_get_rcu(bond_dev->slaves[i].netdev);
		rcu_read_unlock();
		if (!slave)
			continue;

		if (bond_is_active_slave(slave)) {
			if (netif_running(bond_dev->slaves[i].netdev) &&
				netif_carrier_ok(bond_dev->slaves[i].netdev)) {
				ret_dev = bond_dev->slaves[i].netdev;
			} else if (netif_running(bond_dev->slaves[(i + 1) %
				bond_dev->slave_cnt].netdev) &&
				netif_carrier_ok(bond_dev->slaves[(i + 1) %
				bond_dev->slave_cnt].netdev)) {
				ret_dev = bond_dev->slaves[(i + 1) % bond_dev->slave_cnt].netdev;
			} else {
				ret_dev = bond_dev->slaves[i].netdev;
			}
			dev_hold(ret_dev);
			mutex_unlock(&bond_dev->slave_lock);
			mutex_unlock(&g_roce3_bond_mutex);
			return ret_dev;
		}
	}
	mutex_unlock(&bond_dev->slave_lock);
	mutex_unlock(&g_roce3_bond_mutex);
	return ret_dev;
}

void roce3_bond_rr_set_flow(struct roce3_device *rdev, struct roce3_qp *rqp,
	struct tag_roce_verbs_qp_attr *qp_attr)
{
	u32 bond_tx_hash;
	struct roce3_bond_device *bond_dev = rdev->bond_dev;

	if (!bond_dev)
		return;

	bond_tx_hash = (u32)atomic_add_return(1, &bond_dev->next_port);
	rqp->tx_hash_value = bond_tx_hash;

	qp_attr->path_info.dw0.bs.bond_tx_hash_value = (u16)bond_tx_hash;
}

static int roce3_bond_modify_mac_tbl_for_sdi(struct roce3_device *rdev, u8 *mac,
	roce3_modify_mac_tbl modify_mac_tbl)
{
	u16 func_id;
	int ret;

	for (func_id = 0; func_id < SDI_BOND_SLAVES_FUNC_NUM; func_id++) {
		if (func_id == rdev->glb_func_id)
			continue;

		ret = modify_mac_tbl(rdev->hwdev, mac, ROCE_BOND_RSVD_VLAN_ID,
			rdev->glb_func_id, func_id);
		if (ret != 0) {
			pr_err("[ROCE, ERR] %s: Failed to modify mac table, ret(%d)\n",
				__func__, ret);
			return ret;
		}
	}

	return 0;
}

int roce3_add_bond_real_slave_mac(struct roce3_device *rdev, u8 *mac)
{
	struct roce3_bond_device *bond_dev = rdev->bond_dev;
	struct roce3_bond_slave *slave = NULL;
	int ret;
	int i;

	if (!bond_dev) {
		pr_err("[ROCE, ERR] %s: Failed to find bond_dev\n", __func__);
		return -EINVAL;
	}

	mutex_lock(&bond_dev->slave_lock);
	for (i = 0; i < bond_dev->slave_cnt; i++) {
		slave = &bond_dev->slaves[i];
		ret = roce3_add_mac_tbl_mac_entry(rdev->hwdev, mac, ROCE_BOND_RSVD_VLAN_ID,
			rdev->glb_func_id, slave->func_id);
		if (ret != 0) {
			mutex_unlock(&bond_dev->slave_lock);
			pr_err("[ROCE, ERR] %s: Failed to add mac_vlan entry, ret(%d)\n",
				__func__, ret);
			return ret;
		}

		if (slave->func_id != rdev->glb_func_id) {
			/*
			 * The IPSU MAC table is used for fast forwarding. Even
			 * if the addition fails, the forwarding information
			 * can still be obtained by checking the MAC table later,
			 * without judging the execution result.
			 */
			(void)roce3_add_ipsu_tbl_mac_entry(rdev->hwdev, mac, 0,
				rdev->glb_func_id, slave->er_id);
		}
	}
	mutex_unlock(&bond_dev->slave_lock);

	if (rdev->sdi_bond_name != NULL) {
		ret = roce3_bond_modify_mac_tbl_for_sdi(rdev, mac, roce3_add_mac_tbl_mac_entry);
		if (ret != 0) {
			pr_err("[ROCE, ERR] %s: Failed to modify mac table of sdi, ret(%d)\n",
				__func__, ret);
			return ret;
		}
	}

	return 0;
}

int roce3_add_bond_vlan_slave_mac(struct roce3_device *rdev, u8 *mac, u16 vlan_id)
{
	struct roce3_bond_device *bond_dev = rdev->bond_dev;
	struct roce3_bond_slave *slave = NULL;
	int ret;
	int i;

	if (!bond_dev) {
		pr_err("[ROCE, ERR] %s: Failed to find bond_dev\n", __func__);
		return -EINVAL;
	}

	mutex_lock(&bond_dev->slave_lock);
	for (i = 0; i < bond_dev->slave_cnt; i++) {
		slave = &bond_dev->slaves[i];
		if (slave->func_id == rdev->glb_func_id)
			continue;

		ret = roce3_add_mac_tbl_mac_entry(rdev->hwdev, mac, vlan_id,
			slave->func_id, slave->func_id);
		if (ret != 0) {
			mutex_unlock(&bond_dev->slave_lock);
			pr_err("[ROCE, ERR] %s: Failed to add mac_vlan entry, ret(%d)\n",
				__func__, ret);
			return ret;
		}

		/*
		 * The IPSU MAC table is used for fast forwarding. Even
		 * if the addition fails, the forwarding information
		 * can still be obtained by checking the MAC table later,
		 * without judging the execution result.
		 */
		(void)roce3_add_ipsu_tbl_mac_entry(rdev->hwdev, mac, vlan_id,
			rdev->glb_func_id, slave->er_id);
	}
	mutex_unlock(&bond_dev->slave_lock);

	return 0;
}

void roce3_del_bond_real_slave_mac(struct roce3_device *rdev)
{
	int i;
	struct roce3_bond_slave *slave = NULL;
	struct roce3_bond_device *bond_dev = rdev->bond_dev;

	if (!bond_dev)
		return;

	mutex_lock(&bond_dev->slave_lock);
	for (i = 0; i < bond_dev->slave_cnt; i++) {
		slave = &bond_dev->slaves[i];
		if (slave->func_id != rdev->glb_func_id) {
			(void)roce3_del_ipsu_tbl_mac_entry(rdev->hwdev, rdev->mac, 0,
				rdev->glb_func_id, slave->er_id);
		}

		(void)roce3_del_mac_tbl_mac_entry(rdev->hwdev, rdev->mac, ROCE_BOND_RSVD_VLAN_ID,
			rdev->glb_func_id, slave->func_id);
	}
	mutex_unlock(&bond_dev->slave_lock);

	if (rdev->sdi_bond_name != NULL) {
		(void)roce3_bond_modify_mac_tbl_for_sdi(rdev, rdev->mac,
			roce3_del_mac_tbl_mac_entry);
	}
}

void roce3_del_bond_vlan_slave_mac(struct roce3_device *rdev, u8 *mac, u16 vlan_id)
{
	int i;
	struct roce3_bond_slave *slave = NULL;
	struct roce3_bond_device *bond_dev = rdev->bond_dev;

	if (!bond_dev)
		return;

	mutex_lock(&bond_dev->slave_lock);
	for (i = 0; i < bond_dev->slave_cnt; i++) {
		slave = &bond_dev->slaves[i];
		if (slave->func_id == rdev->glb_func_id)
			continue;

		roce3_del_ipsu_tbl_mac_entry(rdev->hwdev, mac, vlan_id,
			slave->func_id, slave->er_id);

		(void)roce3_del_mac_tbl_mac_entry(rdev->hwdev, mac, vlan_id,
			rdev->glb_func_id, slave->er_id);
	}
	mutex_unlock(&bond_dev->slave_lock);
}

bool roce3_bond_is_active(struct roce3_device *rdev)
{
	return (rdev->bond_dev != NULL);
}

int roce3_bond_event_cfg_rdev(struct hinic3_lld_dev *lld_dev, void *uld_dev,
	struct roce3_device **rdev)
{
	int i;
	struct roce3_bond_device *bond_dev = NULL;

	if (lld_dev == NULL) {
		pr_err("[ROCE, ERR] %s: Lld_dev is null\n", __func__);
		return -EINVAL;
	}

	if (uld_dev != NULL) {
		*rdev = (struct roce3_device *)uld_dev;
		return 0;
	}

	mutex_lock(&g_roce3_bond_mutex);
	list_for_each_entry(bond_dev, &g_roce3_bond_list, entry) {
		mutex_lock(&bond_dev->slave_lock);
		for (i = 0; i < bond_dev->slave_cnt; i++) {
			if (bond_dev->slaves[i].lld_dev == lld_dev) {
				*rdev = bond_dev->attached_rdev;
				mutex_unlock(&bond_dev->slave_lock);
				goto out;
			}
		}
		mutex_unlock(&bond_dev->slave_lock);
	}

out:
	mutex_unlock(&g_roce3_bond_mutex);
	return *rdev ? 0 : -EINVAL;
}

int roce3_bonded_port_event_report(struct roce3_device *rdev, const struct hinic3_event_info *event)
{
	u32 type = HINIC3_SRV_EVENT_TYPE(event->service, event->type);

	if ((type != HINIC3_SRV_EVENT_TYPE(EVENT_SRV_NIC, EVENT_NIC_LINK_UP)) &&
		(type != HINIC3_SRV_EVENT_TYPE(EVENT_SRV_NIC, EVENT_NIC_LINK_DOWN))) {
		pr_err("[ROCE] %s: event_service(%d), type(%d)\n",
			__func__, event->service, event->type);
		return -ERANGE;
	}

	return 0;
}

int roce3_bond_is_eth_port_of_netdev(struct roce3_device *rdev, struct net_device *event_ndev)
{
	struct roce3_bond_device *bond_dev = rdev->bond_dev;
	struct net_device *tmp_ndev = NULL;
	int ret;
	int i;
	/* judge current net device */
	tmp_ndev = rdev->ndev;
	ret = roce3_is_eth_port_of_netdev(tmp_ndev, event_ndev);
	if (ret != 0)
		return 1;

	if (!bond_dev)
		return 0;

	mutex_lock(&bond_dev->slave_lock);
	for (i = 0; i < bond_dev->slave_cnt; i++) {
		if (roce3_is_eth_port_of_netdev(bond_dev->slaves[i].netdev, event_ndev)) {
			mutex_unlock(&bond_dev->slave_lock);
			return 1;
		}
	}
	mutex_unlock(&bond_dev->slave_lock);

	return 0;
}

struct roce3_bond_device *roce3_get_bond_dev(const char *bond_name)
{
	struct roce3_bond_device *bdev = NULL;

	list_for_each_entry(bdev, &g_roce3_bond_list, entry) {
		if (!strcmp(bdev->name, bond_name))
			return bdev;
	}

	return NULL;
}

struct roce3_bond_device *roce3_get_bond_dev_by_name(const char *bond_name)
{
	struct roce3_bond_device *bdev = NULL;

	mutex_lock(&g_roce3_bond_mutex);
	bdev = roce3_get_bond_dev(bond_name);
	mutex_unlock(&g_roce3_bond_mutex);
	return bdev;
}

void roce3_bond_init_slave(struct roce3_bond_slave *slave, struct bond_tracker *tracker, int index,
	struct bond_attr *attr)
{
	void *hwdev;

	slave->func_id = index;
	slave->netdev = tracker->ndev[index];

	dev_hold(slave->netdev);
	pr_info("[ROCE, INFO] %s: dev_hold: name(%s),tracker_cnt(%d)\n",
		__func__, slave->netdev->name, tracker->cnt);
	slave->lld_dev = hinic3_get_lld_dev_by_netdev(slave->netdev);
	slave->ppf_dev = hinic3_get_ppf_lld_dev(slave->lld_dev);
	hwdev = slave->lld_dev->hwdev;
	slave->is_ppf = hinic3_func_type(hwdev) == TYPE_PPF;
	slave->er_id = hinic3_er_id(hwdev);
	slave->netdev_state.link_up = tracker->netdev_state[index].link_up;
	slave->netdev_state.tx_enabled = tracker->netdev_state[index].tx_enabled;

	if (slave->is_ppf)
		attr->first_roce_func = slave->func_id;
	else
		hinic3_detach_service(slave->lld_dev, SERVICE_T_ROCE);
}

bool roce3_bond_before_active_check(struct bond_tracker *tracker, struct bond_attr *attr)
{
	int i;
	struct hinic3_lld_dev *lld_dev = NULL;
	struct hinic3_lld_dev *ppf_dev = NULL;

	if (!roce3_bond_mode_is_supported(attr->bond_mode))
		return false;

	for (i = 0; i < ROCE_BOND_2_FUNC_NUM; i++) {
		lld_dev = hinic3_get_lld_dev_by_netdev(tracker->ndev[i]);
		if (!lld_dev) {
			pr_err("[ROCE, ERR] %s: get lld dev err\n", __func__);
			return false;
		}

		if (!hinic3_support_roce(lld_dev->hwdev, NULL)) {
			pr_err("[ROCE, ERR] %s: Not support roce\n", __func__);
			return false;
		}

		if (!ppf_dev) {
			ppf_dev = hinic3_get_ppf_lld_dev(lld_dev);
			if (!ppf_dev) {
				pr_err("[ROCE, ERR] %s: get ppf dev err\n", __func__);
				return false;
			}
		}

		if (hinic3_get_ppf_lld_dev(lld_dev) != ppf_dev)
			return false;
	}

	return true;
}

void roce3_detach_nic_bond_work(struct work_struct *work)
{
	struct roce3_detach_work *detach_work = container_of(work, struct roce3_detach_work, work);

	hinic3_bond_detach(detach_work->bond_id, HINIC3_BOND_USER_ROCE);

	kfree(detach_work);
}

static void roce3_attach_bond_work(struct work_struct *_work)
{
	u16 bond_id;
	struct roce3_bond_work *work = container_of(_work, struct roce3_bond_work, work);

	pr_info("roce_attach: %s: work_name(%s)\n", __func__, work->name);
	hinic3_bond_attach(work->name, HINIC3_BOND_USER_ROCE, &bond_id);

	kfree(work);
}
void roce3_deatch_bond(u16 bond_id)
{
	struct roce3_detach_work *detach_work = NULL;

	detach_work = kmalloc(sizeof(*detach_work), GFP_KERNEL);
	if (!detach_work)
		return;

	detach_work->bond_id = bond_id;
	INIT_WORK(&detach_work->work, roce3_detach_nic_bond_work);
	queue_work(g_bond_wq, &detach_work->work);
}

bool roce3_bond_tracker_get(const char *bond_name, struct bond_tracker *tracker)
{
	int ret = 0;

	ret = hinic3_get_bond_tracker_by_name(bond_name, tracker);
	if (ret != 0) {
		pr_err("[ROCE, ERR] %s: get bond tracker failed name(%s), ret(%d)\n",
			__func__, bond_name, ret);
		return false;
	}
	if (!tracker->is_bonded) {
		pr_err("[ROCE, ERR] %s: tracker is NOT bond (%s)\n", __func__, bond_name);
		return false;
	}
	if (tracker->cnt == ROCE_BOND_2_FUNC_NUM)
		return true;

	pr_err("[ROCE, ERR] %s: get tracker cnt fail, cnt(%d) name(%s)\n",
		__func__, tracker->cnt, bond_name);
	return false;
}

void roce3_before_bond_active(const char *bond_name, struct bond_attr *attr)
{
	struct roce3_bond_device *bond_dev = NULL;
	struct roce3_bond_slave *slave = NULL;
	struct bond_tracker tracker;
	int i;

	if (!roce3_bond_tracker_get(bond_name, &tracker)) {
		pr_err("[ROCE, ERR] %s: get bond tracker failed\n", __func__);
		goto err;
	}

	if (!roce3_bond_before_active_check(&tracker, attr)) {
		pr_err("[ROCE, ERR] %s: active check failed\n", __func__);
		goto err;
	}

	bond_dev = roce3_get_bond_dev_by_name(bond_name);
	if (bond_dev) {
		pr_info("[ROCE, INFO] %s: Find exist bond device\n", __func__);
		return;
	}

	bond_dev = kzalloc(sizeof(*bond_dev), GFP_KERNEL);
	if (!bond_dev)
		goto err;

	strscpy(bond_dev->name, bond_name, sizeof(bond_dev->name));

	bond_dev->attr = *attr;
	bond_dev->slave_cnt = tracker.cnt;
	mutex_init(&bond_dev->slave_lock);

	for (i = 0; i < ROCE_BOND_2_FUNC_NUM; i++) {
		slave = &bond_dev->slaves[i];
		roce3_bond_init_slave(slave, &tracker, i, attr);
	}

	hinic3_detach_service(bond_dev->slaves[0].ppf_dev, SERVICE_T_ROCE);
	mutex_lock(&g_roce3_bond_mutex);
	list_add_tail(&bond_dev->entry, &g_roce3_bond_list);
	mutex_unlock(&g_roce3_bond_mutex);
	return;
err:
	roce3_deatch_bond(attr->bond_id);
}

void roce3_after_bond_active(const char *bond_name, struct bond_attr *attr)
{
	int ret;
	struct roce3_bond_device *bond_dev = NULL;

	bond_dev = roce3_get_bond_dev_by_name(bond_name);
	if (!bond_dev) {
		pr_err("[ROCE, ERR] %s: not find bond device by name(%s)\n", __func__, bond_name);
		return;
	}

	ret = hinic3_attach_service(bond_dev->slaves[0].ppf_dev, SERVICE_T_ROCE);
	if (ret != 0) {
		pr_err("[ROCE, ERR] %s: Failed to attach roce device, ret(%d), bond name(%s)\n",
			__func__, ret, bond_name);
	}
}

void roce3_after_bond_modify(const char *bond_name, struct bond_attr *attr)
{
	struct roce3_bond_device *bond_dev = NULL;
	struct bond_tracker tracker;
	int i;
	int j;

	bond_dev = roce3_get_bond_dev_by_name(bond_name);
	if (!bond_dev) {
		pr_err("[ROCE, ERR] %s: not find bond device by name(%s)\n", __func__, bond_name);
		return;
	}

	if (hinic3_get_bond_tracker_by_name(bond_name, &tracker) != 0) {
		pr_err("[ROCE, ERR] %s: get bond tracker failed\n", __func__);
		return;
	}

	bond_dev->attr = *attr;
	mutex_lock(&bond_dev->slave_lock);
	for (i = 0; i < BOND_PORT_MAX_NUM; i++) {
		for (j = 0; j < bond_dev->slave_cnt; j++) {
			if (bond_dev->slaves[j].netdev != tracker.ndev[i])
				continue;

			bond_dev->slaves[j].netdev_state.link_up = tracker.netdev_state[i].link_up;
			bond_dev->slaves[j].netdev_state.tx_enabled =
				tracker.netdev_state[i].tx_enabled;
			break;
		}
	}
	mutex_unlock(&bond_dev->slave_lock);
}

void roce3_before_bond_deactive(const char *bond_name, struct bond_attr *attr)
{
}

void roce3_after_bond_deactive(const char *bond_name, struct bond_attr *attr)
{
}

void roce3_bond_destroy(const char *bond_name)
{
	int ret;
	int i;
	struct roce3_bond_device *bond_dev = NULL;

	mutex_lock(&g_roce3_bond_mutex);
	bond_dev = roce3_get_bond_dev(bond_name);
	if (bond_dev)
		list_del(&bond_dev->entry);

	if (!bond_dev) {
		pr_err("[ROCE, ERR] %s: not find bond device by name(%s)\n", __func__, bond_name);
		mutex_unlock(&g_roce3_bond_mutex);
		return;
	}
	if (bond_dev->attached_rdev != NULL)
		bond_dev->attached_rdev->bond_dev = NULL;

	mutex_unlock(&g_roce3_bond_mutex);

	hinic3_detach_service(bond_dev->slaves[0].ppf_dev, SERVICE_T_ROCE);
	mutex_lock(&bond_dev->slave_lock);
	for (i = 0; i < bond_dev->slave_cnt; i++) {
		ret = hinic3_attach_service(bond_dev->slaves[i].lld_dev, SERVICE_T_ROCE);
		if (ret != 0) {
			pr_err("[ROCE, ERR] %s: Failed to attach roce device, ret(%d)\n",
				__func__, ret);
		}
		dev_put(bond_dev->slaves[i].netdev);
		pr_info("[ROCE, INFO] %s: dev_put: name(%s),slave_cnt(%d), slave_name(%s)\n",
			__func__, bond_name, bond_dev->slave_cnt, bond_dev->slaves[i].netdev->name);
	}
	bond_dev->slave_cnt = 0;
	mutex_unlock(&bond_dev->slave_lock);

	hinic3_bond_detach(bond_dev->attr.bond_id, HINIC3_BOND_USER_ROCE);
	kfree(bond_dev);
}

void roce3_before_bond_modify(const char *bond_name, struct bond_attr *attr)
{
	struct roce3_bond_device *bond_dev = NULL;
	struct bond_tracker tracker;
	int i;

	bond_dev = roce3_get_bond_dev_by_name(bond_name);
	if (!bond_dev) {
		pr_err("[ROCE, ERR] %s: not find bond device by name(%s)\n", __func__, bond_name);
		return;
	}

	if (hinic3_get_bond_tracker_by_name(bond_name, &tracker) != 0) {
		pr_err("[ROCE, ERR] %s: get bond tracker failed\n", __func__);
		return;
	}

	if (tracker.cnt == bond_dev->slave_cnt) {
		bond_dev->attr = *attr;
		for (i = 0; i < bond_dev->slave_cnt; i++) {
			if (bond_dev->slaves[i].is_ppf) {
				attr->first_roce_func = bond_dev->slaves[i].func_id;
				break;
			}
		}
		return;
	}

	if (tracker.cnt > bond_dev->slave_cnt) {
		pr_err("[ROCE, ERR] %s: Add slave is not support, bond name(%s)\n",
			__func__, bond_name);
		return;
	}

	if (tracker.cnt < ROCE_BOND_2_FUNC_NUM) {
		roce3_bond_destroy(bond_dev->name);
		return;
	}
}

static roce3_bond_service_func g_roce3_bond_proc[] = {
	roce3_before_bond_active,
	roce3_after_bond_active,
	roce3_before_bond_modify,
	roce3_after_bond_modify,
	roce3_before_bond_deactive,
	roce3_after_bond_deactive,
};

void roce3_bond_service_proc(const char *bond_name, void *bond_attr, enum bond_service_proc_pos pos)
{
	struct bond_attr *attr = (struct bond_attr *)bond_attr;

	if (bond_name == NULL) {
		pr_err("[ROCE, ERR] %s: Bond_name is NULL\n", __func__);
		return;
	}

	if (pos >= BOND_POS_MAX) {
		pr_err("[ROCE, ERR] %s: The pos is out of the range of proc_func\n", __func__);
		return;
	}

	if (g_roce3_bond_proc[pos] != NULL)
		g_roce3_bond_proc[pos](bond_name, attr);
}

int roce3_bond_attach(struct roce3_device *rdev)
{
	int i;
	int ret = 0;
	struct roce3_bond_device *bond_dev;

	mutex_lock(&g_roce3_bond_mutex);
	list_for_each_entry(bond_dev, &g_roce3_bond_list, entry) {
		mutex_lock(&bond_dev->slave_lock);
		for (i = 0; i < bond_dev->slave_cnt; i++) {
			if (rdev->ndev != bond_dev->slaves[i].netdev)
				continue;

			if (bond_dev->attached_rdev == NULL) {
				bond_dev->attached_rdev = rdev;
				rdev->bond_dev = bond_dev;
			} else {
				ret = -EEXIST;
			}
			mutex_unlock(&bond_dev->slave_lock);
			goto out;
		}
		mutex_unlock(&bond_dev->slave_lock);
	}
out:
	mutex_unlock(&g_roce3_bond_mutex);
	return ret;
}

static void roce3_detach_bond_work(struct work_struct *_work)
{
	struct roce3_bond_work *work = container_of(_work, struct roce3_bond_work, work);

	roce3_bond_destroy(work->name);

	kfree(work);
}

void roce3_queue_bond_work(struct net_device *upper_netdev, work_func_t func)
{
	struct roce3_bond_work *work;
	struct bonding *bond = netdev_priv(upper_netdev);

	if (!bond) {
		pr_info("%s: (name:%s) has no bond dev.\n", __func__, upper_netdev->name);
		return;
	}

	work = kzalloc(sizeof(*work), GFP_KERNEL);
	if (!work)
		return;

	strscpy(work->name, upper_netdev->name, sizeof(work->name));
	INIT_WORK(&work->work, func);
	queue_work(g_bond_wq, &work->work);
}

int roce3_bond_netdev_event(struct notifier_block *this, unsigned long event, void *ptr)
{
	struct net_device *net_dev = NULL;
	struct netdev_notifier_changeupper_info *info = NULL;
	struct net_device *upper_netdev = NULL;

	info = (struct netdev_notifier_changeupper_info *)ptr;
	net_dev = netdev_notifier_info_to_dev(ptr);
	if (net_eq(dev_net(net_dev), &init_net) == 0)
		return NOTIFY_DONE;

	if (event != NETDEV_CHANGEUPPER)
		return NOTIFY_DONE;

	if (!is_hinic3_netdev(net_dev))
		return NOTIFY_DONE;

	upper_netdev = info->upper_dev;
	if (upper_netdev == NULL)
		return NOTIFY_DONE;

	if (!netif_is_lag_master(upper_netdev))
		return NOTIFY_DONE;

	if (!roce3_can_do_bond(netdev_priv(upper_netdev))) {
		roce3_queue_bond_work(upper_netdev, roce3_detach_bond_work);
		return NOTIFY_DONE;
	}

	roce3_queue_bond_work(upper_netdev, roce3_attach_bond_work);
	return NOTIFY_DONE;
}

static struct notifier_block nb_netdevice = {
	.notifier_call = roce3_bond_netdev_event
};

int roce3_bond_init(void)
{
	int ret;
	struct net_device *upper_netdev;

	g_bond_wq = alloc_ordered_workqueue("roce3-bond-wq", 0);
	if (!g_bond_wq) {
		pr_err("[ROCE, ERR] %s: Failed to alloc workqueue\n", __func__);
		return -ENOMEM;
	}

	ret = register_netdevice_notifier(&nb_netdevice);
	if (ret) {
		pr_err("[ROCE, ERR] %s: Failed to register netdevice notifier(%d)\n",
			__func__, ret);
		goto nb_err;
	}

	ret = hinic3_bond_register_service_func(HINIC3_BOND_USER_ROCE, roce3_bond_service_proc);
	if (ret != 0) {
		pr_err("[ROCE, ERR] %s: Failed to register bond(%d)\n", __func__, ret);
		goto err;
	}

	rtnl_lock();
	for_each_netdev(&init_net, upper_netdev) {
		if (netif_is_bond_master(upper_netdev) &&
			roce3_can_do_bond(netdev_priv(upper_netdev))) {
			roce3_queue_bond_work(upper_netdev, roce3_attach_bond_work);
		}
	}
	rtnl_unlock();

	return 0;
err:
	unregister_netdevice_notifier(&nb_netdevice);
nb_err:
	destroy_workqueue(g_bond_wq);
	return ret;
}

void roce3_bond_pre_exit(void)
{
	int ret;

	ret = hinic3_bond_unregister_service_func(HINIC3_BOND_USER_ROCE);
	if (ret != 0)
		pr_err("[ROCE, ERR] %s: Failed to unregister service func(%d)\n", __func__, ret);

	unregister_netdevice_notifier(&nb_netdevice);
	destroy_workqueue(g_bond_wq);
}

void roce3_bond_exit(void)
{
	struct roce3_bond_device *bond_dev = NULL;
	int i;

	while (!list_empty(&g_roce3_bond_list)) {
		bond_dev = list_first_entry(&g_roce3_bond_list, struct roce3_bond_device, entry);
		list_del(&bond_dev->entry);
		for (i = 0; i < bond_dev->slave_cnt; i++) {
			pr_info("[ROCE, INFO] %s: EXIT dev_put: bond_name(%s),slave_cnt(%d), slave_name(%s)\n",
				__func__, bond_dev->name, bond_dev->slave_cnt,
				bond_dev->slaves[i].netdev->name);
			dev_put(bond_dev->slaves[i].netdev);
		}
		hinic3_bond_detach(bond_dev->attr.bond_id, HINIC3_BOND_USER_ROCE);
		kfree(bond_dev);
	}
}

#endif
