// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2018 - 2021 Beijing WangXun Technology Co., Ltd. */

#include "nse.h"
#include "nse_switch.h"
#include "nse_common.h"
#include "nse_neigh.h"
#include "nse_tc_lib.h"

/**
 * nse_neigh_entry_create -
 *		create a neigh entry and insert to global neigh table.
 * @hw: pointer to the HW struct
 * @neigh_info: global neigh talbe information.
 * @m_neigh: primary key for nse neigh object.
 * @neigh_dev: netdev for neigh
 * @neigh_entry: return created neigh entry.
 *
 */
static int
nse_neigh_entry_create(struct nse_hw *hw,
				 struct nse_neigh_info *neigh_info,
				 struct nse_neigh *m_neigh,
				 struct net_device *neigh_dev,
				 struct nse_neigh_entry **neigh_entry)
{
	struct nse_neigh_entry *new_neigh = NULL;
	struct list_head *list_head = &neigh_info->neigh_list_head;

	*neigh_entry = NULL;
	new_neigh = devm_kzalloc(nse_hw_to_dev(hw), sizeof(*new_neigh), GFP_KERNEL);
	if (!new_neigh)
		return -ENOMEM;

	memcpy(&new_neigh->m_neigh, m_neigh, sizeof(*m_neigh));
	mutex_init(&new_neigh->encap_list_lock);
	INIT_LIST_HEAD(&new_neigh->encap_list);
	refcount_set(&new_neigh->ref_cnt, 1);
	WRITE_ONCE(new_neigh->neigh_dev, neigh_dev);

	list_add_tail(&new_neigh->list_entry, list_head);

	*neigh_entry = new_neigh;
	return 0;
}

/**
 * nse_neigh_entry_destroy -
 *		destroy a neigh entry.
 * @hw: pointer to the HW struct
 * @neigh_entry: neigh entry that will be destroy.
 *
 */
static void
nse_neigh_entry_destroy(struct nse_hw *hw,
			struct nse_neigh_entry *neigh_entry)
{
	struct nse_pf *pf = (struct nse_pf *)hw->back;
	struct nse_switchdev_info *switchdev = &pf->switchdev;
	struct nse_neigh_info *neigh_info = &switchdev->neigh_info;

	spin_lock(&neigh_info->neigh_tbl_lock);
	list_del(&neigh_entry->list_entry);
	spin_unlock(&neigh_info->neigh_tbl_lock);

	devm_kfree(nse_hw_to_dev(hw), neigh_entry);
}

/**
 * nse_neigh_entry_release -
 *		release a neigh entry. if ref_cnt > 1, ref_cnt --, otherwise destroy the neigh.
 * @hw: pointer to the HW struct
 * @neigh_entry: neigh entry that will be released.
 *
 */
static void
nse_neigh_entry_release(struct nse_hw *hw,
		struct nse_neigh_entry *neigh_entry)
{
	if (refcount_dec_and_test(&neigh_entry->ref_cnt))
		nse_neigh_entry_destroy(hw, neigh_entry);
}

/**
 * nse_find_neigh_entry -
 *		lookup global neigh table to find out the existed neigh obj.
 * @hw: pointer to the HW struct
 * @neigh_info: global neigh talbe information.
 * @m_neigh: primary key for nse neigh object.
 * @neigh_dev: netdev for neigh
 *
 */
static struct nse_neigh_entry *
nse_find_neigh_entry(struct nse_hw *hw,
				struct nse_neigh_info *neigh_info,
				struct nse_neigh *m_neigh,
				struct net_device *neigh_dev)
{
	struct nse_neigh_entry *old_list = NULL, *list_itr;
	struct list_head *list_head = &neigh_info->neigh_list_head;

	if (!m_neigh)
		return NULL;

	list_for_each_entry(list_itr, list_head, list_entry) {
		if (!memcmp(m_neigh, &list_itr->m_neigh, sizeof(*m_neigh)) &&
			neigh_dev == list_itr->neigh_dev) {
			old_list = list_itr;
			break;
		}
	}
	return old_list;
}

/**
 * nse_release_neigh_update_work -
 *		release update work structure and decreace ref cnt of neigh entry
 *
 * @hw: pointer to the HW struct
 * @update_work: pointer to neigh update that need to be released.
 */
static void
nse_release_neigh_update_work(struct nse_hw *hw,
				struct neigh_update_work *update_work)
{
	neigh_release(update_work->n);
	nse_neigh_entry_release(hw, update_work->neigh_entry);
	kfree(update_work);
}

/**
 * nse_update_encap_entry_mac -
 *		update a mac-changed encap entry.
 * @hw: pointer to the HW struct
 * @encap_entry: encap entry that will be updated.
 * @ha: new mac of neigh.
 */
static void
nse_update_encap_entry_mac(struct nse_hw *hw,
		struct nse_sw_encap_entry *encap_entry,
		unsigned char ha[ETH_ALEN])
{
	struct ethhdr *eth = NULL;
	struct net_device *route_dev;
	int err;

	if (!encap_entry)
		return;

	eth = (struct ethhdr *)encap_entry->du_desc.data;
	ether_addr_copy(encap_entry->dmac, ha);
	ether_addr_copy(eth->h_dest, ha);
	route_dev = __dev_get_by_index(dev_net(encap_entry->out_dev),
				       encap_entry->route_dev_ifindex);
	if (route_dev)
		ether_addr_copy(eth->h_source, route_dev->dev_addr);

	err = nse_sw_update_encap_entry(hw, encap_entry);
	if (err)
		dev_err(nse_hw_to_dev(hw),
		    "Failed to update encap entry, err = %d\n", err);
}

/**
 * nse_update_encap_entry_down -
 *		update a down encap entry.
 * @hw: pointer to the HW struct
 * @encap_entry: encap entry that will be updated.
 * @ha: new mac of neigh.
 */
static void
nse_update_encap_entry_down(struct nse_hw *hw,
		struct nse_sw_encap_entry *encap_entry,
		unsigned char ha[ETH_ALEN])
{
	struct nse_sw_encap_item *encap_item = NULL;
	struct nse_tc_flower_fltr *fltr = NULL;
	int err = 0;

	if (!encap_entry)
		return;

	mutex_lock(&encap_entry->fltr_list_lock);
	list_for_each_entry(encap_item, &encap_entry->fltr_list, list_entry) {
		dev_info(nse_hw_to_dev(hw), "\t cur encap item: addr = %p, idx = %d, e = %p\n",
			encap_item, encap_item->index, encap_item->e);
		if (encap_entry != encap_item->e) {
			dev_warn(nse_hw_to_dev(hw), "\t encap item is not point to encap entry!\n");
			continue;
		}

		fltr = container_of(encap_item, struct nse_tc_flower_fltr,
						action.encaps[encap_item->index]);

		nse_get_tc_fltr(fltr);

		dev_info(nse_hw_to_dev(hw),
			"\t fltr: cookie = %lx, is_slowpath = %d, lut_id = %d, node_id = 0x%x, node_state_id = 0x%x, ref_cnt = %d, encap_cnt = %d, cur encap idx = %d\n",
			fltr->cookie, fltr->action.node_state.is_slowpath,
			fltr->lut_id, fltr->node_id,
			fltr->action.large_act_id, refcount_read(&fltr->ref_cnt),
			fltr->action.encap_cnt, encap_item->index);

		err = nse_tc_fltr_enable_slowpath(fltr->src_vsi, fltr);
		if (err)
			dev_err(nse_hw_to_dev(hw),
			    "Failed to enable fltr's slowpath, err = %d\n", err);
		nse_put_tc_fltr(fltr->src_vsi, fltr);
	}
	mutex_unlock(&encap_entry->fltr_list_lock);

	encap_entry->valid = false;
}

/**
 * nse_update_encap_entry_up -
 *		update a up encap entry.
 * @hw: pointer to the HW struct
 * @encap_entry: encap entry that will be updated.
 * @ha: new mac of neigh.
 */
static void
nse_update_encap_entry_up(struct nse_hw *hw,
		struct nse_sw_encap_entry *encap_entry,
		unsigned char ha[ETH_ALEN])
{
	struct nse_sw_encap_item *encap_item;
	struct nse_tc_flower_fltr *fltr;
	int err = 0;

	if (!encap_entry)
		return;

	/*need valid encap first*/
	encap_entry->valid = true;

	if (!ether_addr_equal(encap_entry->dmac, ha))
		nse_update_encap_entry_mac(hw, encap_entry, ha);

	mutex_lock(&encap_entry->fltr_list_lock);
	list_for_each_entry(encap_item, &encap_entry->fltr_list, list_entry) {
		dev_info(nse_hw_to_dev(hw), "\t cur encap item: addr = %p, idx = %d, e = %p\n",
			encap_item, encap_item->index, encap_item->e);

		if (encap_entry != encap_item->e) {
			dev_warn(nse_hw_to_dev(hw), "\t encap item is not point to encap entry!\n");
			continue;
		}

		fltr = container_of(encap_item, struct nse_tc_flower_fltr,
						action.encaps[encap_item->index]);

		nse_get_tc_fltr(fltr);

		dev_info(nse_hw_to_dev(hw),
			"\t fltr: cookie = %lx, is_slowpath = %d, lut_id = %d, node_id = 0x%x, node_state_id = 0x%x, ref_cnt = %d, encap_cnt = %d, cur encap idx = %d\n",
			fltr->cookie, fltr->action.node_state.is_slowpath,
			fltr->lut_id, fltr->node_id,
			fltr->action.large_act_id, refcount_read(&fltr->ref_cnt),
			fltr->action.encap_cnt, encap_item->index);

		if (nse_tc_fltr_all_encaps_valid(fltr)) {
			err = nse_tc_fltr_disable_slowpath(fltr->src_vsi, fltr);
			if (err)
				dev_err(nse_hw_to_dev(hw),
				    "Failed to disable fltr's slowpath, err = %d\n", err);
		}
		nse_put_tc_fltr(fltr->src_vsi, fltr);
	}
	mutex_unlock(&encap_entry->fltr_list_lock);
}

/**
 * nse_update_encap_entry -
 *		update a encap entry belong to a given neigh.
 * @hw: pointer to the HW struct
 * @encap_entry: encap entry that will be updated.
 * @new_connected: new neigh status, true is connected, false is disconnected.
 * @ha: new mac of neigh.
 */
static void
nse_update_encap_entry(struct nse_hw *hw,
		struct nse_sw_encap_entry *encap_entry,
		bool new_connected, unsigned char ha[ETH_ALEN])
{
	enum nse_neigh_update_t update_type = NSE_NEIGH_NONE;
	bool old_connected = false;

	if (!encap_entry)
		return;

	old_connected = encap_entry->valid;
	if (old_connected == new_connected && ether_addr_equal(encap_entry->dmac, ha))
		goto out;

	if (old_connected && new_connected && !ether_addr_equal(encap_entry->dmac, ha))
		update_type = NSE_NEIGH_MAC;
	if (old_connected && !new_connected)
		update_type = NSE_NEIGH_DOWN;
	if (!old_connected && new_connected)
		update_type = NSE_NEIGH_UP;

	switch (update_type) {
	case NSE_NEIGH_MAC:
		dev_info(nse_hw_to_dev(hw),	"Encap(%p) start to mac update\n", encap_entry);
		dev_info(nse_hw_to_dev(hw),
			"\t ref_cnt = %d, new_status = %d, new_mac = %pM, old_status = %d, old_mac = %pM\n",
			refcount_read(&encap_entry->ref_cnt), new_connected, ha,
			old_connected, encap_entry->dmac);
		nse_update_encap_entry_mac(hw, encap_entry, ha);
		break;

	case NSE_NEIGH_DOWN:
		dev_info(nse_hw_to_dev(hw), "Encap(%p) start to down update\n", encap_entry);
		dev_info(nse_hw_to_dev(hw),
			"\t ref_cnt = %d, new_status = %d, new_mac = %pM, old_status = %d, old_mac = %pM\n",
			refcount_read(&encap_entry->ref_cnt), new_connected, ha,
			old_connected, encap_entry->dmac);
		nse_update_encap_entry_down(hw, encap_entry, ha);
		break;

	case NSE_NEIGH_UP:
		dev_info(nse_hw_to_dev(hw), "Encap(%p) start to up update\n", encap_entry);
		dev_info(nse_hw_to_dev(hw),
			"\t ref_cnt = %d, new_status = %d, new_mac = %pM, old_status = %d, old_mac = %pM\n",
			refcount_read(&encap_entry->ref_cnt), new_connected, ha,
			old_connected, encap_entry->dmac);
		nse_update_encap_entry_up(hw, encap_entry, ha);
		break;

	default:
		dev_err(nse_hw_to_dev(hw),
		    "NEIGH UPDATE TYPE(%d) is not supported\n", update_type);
		break;
	}

out:
	return;
}

/**
 * nse_update_neigh_entry -
 *		update every neigh and encap entry belong to it.
 * @hw: pointer to the HW struct
 * @neigh_entry: neigh sw entry which encap entries attached on it.
 * @connected: neigh status, true is connected, false is disconnected.
 * @ha: new mac of neigh.
 */
static void
nse_update_neigh_entry(struct nse_hw *hw,
		struct nse_neigh_entry *neigh_entry,
		bool connected, unsigned char ha[ETH_ALEN])
{
	struct nse_sw_encap_entry *encap_entry = NULL;
	struct list_head *list_head = &neigh_entry->encap_list;

	if (!neigh_entry)
		return;

	mutex_lock(&neigh_entry->encap_list_lock);
	list_for_each_entry(encap_entry, list_head, encap_list)
		nse_update_encap_entry(hw, encap_entry, connected, ha);

	mutex_unlock(&neigh_entry->encap_list_lock);
}

/**
 * nse_neigh_update -
 *		update every neigh and encap entry belong to it.
 * @work: pointer to neigh update work structure
 */
static void
nse_neigh_update(struct work_struct *work)
{
	struct neigh_update_work *update_work = container_of(work,
				struct neigh_update_work, work);
	struct nse_neigh_entry *neigh_entry = update_work->neigh_entry;
	struct nse_hw *hw = update_work->hw;
	struct neighbour *n = update_work->n;
	bool neigh_connected, same_dev;
	unsigned char ha[ETH_ALEN];
	u8 nud_state, dead;

	if (!neigh_entry)
		return;

	rtnl_lock();
	read_lock_bh(&n->lock);
	memcpy(ha, n->ha, ETH_ALEN);
	nud_state = n->nud_state;
	dead = n->dead;
	same_dev = neigh_entry->neigh_dev == n->dev;
	read_unlock_bh(&n->lock);

	neigh_connected = (nud_state & NUD_VALID) && !dead;

	if (!same_dev) {
		dev_err(nse_hw_to_dev(hw),
			"Failed to check same dev, updated dev(addr = %p) %s, existed dev(addr = %p) %s\n",
			n->dev, n->dev->name, neigh_entry->neigh_dev, neigh_entry->neigh_dev->name);
		goto out;
	}

	nse_update_neigh_entry(hw, neigh_entry, neigh_connected, ha);

out:
	rtnl_unlock();
	nse_release_neigh_update_work(hw, update_work);
}

/**
 * nse_alloc_neigh_update_work -alloc a new update work
 *
 * @hw: pointer to the HW struct
 * @neigh_info: pointer to global neigh information.
 * @n: pointer to OS neighour obj.
 */
static struct neigh_update_work *
nse_alloc_neigh_update_work(struct nse_hw *hw,
		struct nse_neigh_info *neigh_info, struct neighbour *n)
{
	struct neigh_update_work *update_work = NULL;
	struct nse_neigh_entry *neigh_entry = NULL;
	struct net_device *neigh_dev;
	struct nse_neigh m_neigh = { 0 };

	update_work = kzalloc(sizeof(*update_work), GFP_ATOMIC);
	if (WARN_ON(!update_work))
		return NULL;

	m_neigh.family = n->ops->family;
	memcpy(&m_neigh.dst_ip, n->primary_key, n->tbl->key_len);
	neigh_dev = n->dev;

	spin_lock(&neigh_info->neigh_tbl_lock);
	neigh_entry = nse_find_neigh_entry(hw, neigh_info, &m_neigh, neigh_dev);
	if (!neigh_entry) {
		spin_unlock(&neigh_info->neigh_tbl_lock);
		kfree(update_work);
		return NULL;
	}
	spin_unlock(&neigh_info->neigh_tbl_lock);

	refcount_inc(&neigh_entry->ref_cnt);

	INIT_WORK(&update_work->work, nse_neigh_update);
	neigh_hold(n);
	update_work->n = n;
	update_work->neigh_entry = neigh_entry;
	update_work->hw = hw;

	return update_work;
}

/**
 * nse_encap_entry_attach_neigh -
 *		attach current encap entry to neigh object.
 * @hw: pointer to the HW struct
 * @encap_entry: alloced encap entry, put encap data into it.
 * @m_neigh: primary key for nse neigh object.
 * @neigh_dev: netdev for neigh
 *
 */
int
nse_encap_entry_attach_neigh(struct nse_hw *hw,
		 struct nse_sw_encap_entry *encap_entry,
		 struct nse_neigh *m_neigh, struct net_device *neigh_dev)
{
	struct nse_pf *pf = (struct nse_pf *)hw->back;
	struct nse_switchdev_info *switchdev = &pf->switchdev;
	struct nse_neigh_info *neigh_info = &switchdev->neigh_info;
	struct nse_neigh_entry *neigh_entry = NULL;
	int err;

	if (pf->eswitch_mode == DEVLINK_ESWITCH_MODE_LEGACY ||
		switchdev->is_running == false) {
		dev_err(nse_hw_to_dev(hw),
		    "Encap entry attach to neigh should be in swithdev mode\n");
		return -EIO;
	}

	spin_lock(&neigh_info->neigh_tbl_lock);
	neigh_entry = nse_find_neigh_entry(hw, neigh_info, m_neigh, neigh_dev);
	if (neigh_entry) {
		refcount_inc(&neigh_entry->ref_cnt);
		spin_unlock(&neigh_info->neigh_tbl_lock);
		goto encap_attach_to_neigh;
	}

	err = nse_neigh_entry_create(hw, neigh_info,
						m_neigh, neigh_dev, &neigh_entry);
	spin_unlock(&neigh_info->neigh_tbl_lock);

	if (err || !neigh_entry) {
		dev_err(nse_hw_to_dev(hw),
			"Failed to create neigh entry\n");
		return err;
	}
	dev_info(nse_hw_to_dev(hw),
		"Success to create new neigh entry\n");

encap_attach_to_neigh:
	encap_entry->neigh_entry = neigh_entry;
	mutex_lock(&neigh_entry->encap_list_lock);
	list_add_tail(&encap_entry->encap_list, &neigh_entry->encap_list);
	mutex_unlock(&neigh_entry->encap_list_lock);

	dev_info(nse_hw_to_dev(hw),
		"Success to attach encap(%p) to neigh(%p)\n",
		encap_entry, neigh_entry);

	return 0;
}

/**
 * nse_encap_entry_detach_neigh -
 *		detach current encap entry to neigh object, and release neigh once.
 * @hw: pointer to the HW struct
 * @encap_entry: alloced encap entry, put encap data into it.
 */
int
nse_encap_entry_detach_neigh(struct nse_hw *hw,
		 struct nse_sw_encap_entry *encap_entry)
{
	struct nse_neigh_entry *neigh_entry = encap_entry->neigh_entry;

	if (!neigh_entry)
		return -EINVAL;

	mutex_lock(&neigh_entry->encap_list_lock);
	list_del(&encap_entry->encap_list);
	mutex_unlock(&neigh_entry->encap_list_lock);

	nse_neigh_entry_release(hw, neigh_entry);
	neigh_entry = NULL;

	return 0;
}

/**
 * nse_netevent_event -
 *		neigh notifier block handler function.
 * @nb: pointer to notifier block.
 * @event: notifier event value.
 * @ptr: pointer to neighour object.
 */
static int
nse_netevent_event(struct notifier_block *nb,
				    unsigned long event, void *ptr)
{
	struct nse_switchdev_info *switchdev = container_of(nb, struct nse_switchdev_info,
						    neigh_info.netevent_nb);
	struct nse_pf *pf = container_of(switchdev, struct nse_pf, switchdev);
	struct nse_hw *hw = NULL;
	struct nse_neigh_info *neigh_info = NULL;
	struct neigh_update_work *update_work = NULL;
	struct neighbour *n = NULL;

	if (!switchdev || !pf)
		return NOTIFY_DONE;

	neigh_info = &switchdev->neigh_info;
	hw = &pf->hw;

	switch (event) {
	case NETEVENT_NEIGH_UPDATE:
		n = ptr;

#if IS_ENABLED(CONFIG_IPV6)
		if (n->tbl != ipv6_stub->nd_tbl && n->tbl != &arp_tbl)
#else
		if (n->tbl != &arp_tbl)
#endif
		{
			return NOTIFY_DONE;
		}

		update_work = nse_alloc_neigh_update_work(hw, neigh_info, n);
		if (!update_work)
			return NOTIFY_DONE;

		queue_work(neigh_info->wq, &update_work->work);
		break;
	default:
		break;
	}

	return NOTIFY_DONE;
}

void
nse_neigh_dump_neigh_entry(struct nse_pf *pf)
{
	struct nse_hw *hw = &pf->hw;
	struct nse_switchdev_info *switchdev = &pf->switchdev;
	struct nse_neigh_info *neigh_info = &switchdev->neigh_info;
	struct list_head *list_head = &neigh_info->neigh_list_head;
	struct list_head *encap_head = NULL;
	struct nse_sw_encap_entry *encap_entry = NULL;
	struct nse_neigh_entry *neigh_entry = NULL;
	u32 idx = 0;

	if (list_empty(list_head)) {
		dev_info(nse_hw_to_dev(hw), "There is no neigh entry!\n");
		return;
	}

	spin_lock(&neigh_info->neigh_tbl_lock);

	list_for_each_entry(neigh_entry, list_head, list_entry) {
		u32 encap_idx = 0;

		dev_info(nse_hw_to_dev(hw),
			"Neigh[%d]: addr = %p, ref_cnt = %d, gw_family = %d\n",
			idx, neigh_entry, refcount_read(&neigh_entry->ref_cnt),
				neigh_entry->m_neigh.family);

		if (neigh_entry->m_neigh.family == AF_INET) {
			dev_info(nse_hw_to_dev(hw),
				"\t gw_v4_addr = %pI4\n",
				&neigh_entry->m_neigh.dst_ip.v4);
		}

		if (neigh_entry->m_neigh.family == AF_INET6) {
			dev_info(nse_hw_to_dev(hw),
				"\t gw_v6_addr = %pI6c\n",
				&neigh_entry->m_neigh.dst_ip.v6);
		}

		encap_head = &neigh_entry->encap_list;

		mutex_lock(&neigh_entry->encap_list_lock);
		list_for_each_entry(encap_entry, encap_head, encap_list) {
			dev_info(nse_hw_to_dev(hw),
				"\t encap entry[%d]: addr = %p, dmac = %pM\n",
				encap_idx, encap_entry,
				encap_entry->dmac);
			encap_idx++;
		}
		mutex_unlock(&neigh_entry->encap_list_lock);
		idx++;
	}
	spin_unlock(&neigh_info->neigh_tbl_lock);
}

/**
 * nse_neigh_init -
 *		initial neigh information when setup switchdev env.
 * @hw: pointer to the HW struct
 * @switchdev: pointer to switchdev information
 *
 */
int
nse_neigh_init(struct nse_hw *hw, struct nse_switchdev_info *switchdev)
{
	struct nse_neigh_info *neigh_info = &switchdev->neigh_info;
	int err = 0;

	INIT_LIST_HEAD(&neigh_info->neigh_list_head);
	spin_lock_init(&neigh_info->neigh_tbl_lock);

	neigh_info->netevent_nb.notifier_call = nse_netevent_event;
	err = register_netevent_notifier(&neigh_info->netevent_nb);
	if (err)
		goto out_notifier;

	neigh_info->wq = create_singlethread_workqueue("nse_neigh_update");
	if (!neigh_info->wq) {
		err = -ENOMEM;
		goto err_wq_create;
	}

	return 0;

err_wq_create:
out_notifier:
	neigh_info->netevent_nb.notifier_call = NULL;
	dev_err(nse_hw_to_dev(hw),
	    "Failed to initialize neighbours info\n");
	return err;
}

/**
 * nse_neigh_cleanup -
 *		cleanup neigh information when release switchdev env.
 * @hw: pointer to the HW struct
 * @switchdev: pointer to switchdev information
 *
 */
void
nse_neigh_cleanup(struct nse_hw *hw, struct nse_switchdev_info *switchdev)
{
	struct nse_neigh_info *neigh_info = &switchdev->neigh_info;

	destroy_workqueue(neigh_info->wq);

	//mutex_destroy(&neigh_info->neigh_tbl_lock);
	if (!neigh_info->netevent_nb.notifier_call)
		return;
	unregister_netevent_notifier(&neigh_info->netevent_nb);
}

