// SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB
/* Copyright (c) 2018 - 2025 Beijing WangXun Technology Co., Ltd. */
#include "main.h"

LIST_HEAD(nser_handlers);
DEFINE_SPINLOCK(nser_handler_lock);

/**
 * nser_arp_table -manage arp table
 * @rf: RDMA PCI function
 * @ip_addr: ip address for device
 * @mac_addr: mac address ptr
 * @action: modify, delete or add
 */
int nser_arp_table(struct nser_pci_f *rf, u32 *ip_addr, const u8 *mac_addr,
		    u32 action)
{
	unsigned long flags;
	int arp_index;
	u32 ip[4] = {};

	memcpy(ip, ip_addr, sizeof(ip));

	spin_lock_irqsave(&rf->arp_lock, flags);
	for (arp_index = 0; (u32)arp_index < rf->arp_table_size; arp_index++) {
		if (!memcmp(rf->arp_table[arp_index].ip_addr, ip, sizeof(ip)))
			break;
	}

	switch (action) {
	case NSER_ARP_ADD:
		if (arp_index != rf->arp_table_size) {
			arp_index = -1;
			break;
		}

		arp_index = 0;
		if (nser_alloc_rsrc(rf, rf->allocated_arps, rf->arp_table_size,
				     (u32 *)&arp_index, &rf->next_arp_index)) {
			arp_index = -1;
			break;
		}

		memcpy(rf->arp_table[arp_index].ip_addr, ip,
		       sizeof(rf->arp_table[arp_index].ip_addr));
		ether_addr_copy(rf->arp_table[arp_index].mac_addr, mac_addr);
		break;
	case NSER_ARP_RESOLVE:
		if (arp_index == rf->arp_table_size)
			arp_index = -1;
		break;
	case NSER_ARP_DELETE:
		if (arp_index == rf->arp_table_size) {
			arp_index = -1;
			break;
		}

		memset(rf->arp_table[arp_index].ip_addr, 0,
		       sizeof(rf->arp_table[arp_index].ip_addr));
		eth_zero_addr(rf->arp_table[arp_index].mac_addr);
		nser_free_rsrc(rf, rf->allocated_arps, arp_index);
		break;
	default:
		arp_index = -1;
		break;
	}

	spin_unlock_irqrestore(&rf->arp_lock, flags);
	return arp_index;
}

/**
 * nser_add_arp - add a new arp entry if needed
 * @rf: RDMA function
 * @ip: IP address
 * @mac: MAC address
 */
int nser_add_arp(struct nser_pci_f *rf, u32 *ip, const u8 *mac)
{
	int arpidx;

	arpidx = nser_arp_table(rf, &ip[0], NULL, NSER_ARP_RESOLVE);
	if (arpidx >= 0) {
		if (ether_addr_equal(rf->arp_table[arpidx].mac_addr, mac))
			return arpidx;

		nser_manage_arp_cache(rf, rf->arp_table[arpidx].mac_addr, ip,
				       NSER_ARP_DELETE);
	}

	nser_manage_arp_cache(rf, mac, ip, NSER_ARP_ADD);

	return nser_arp_table(rf, ip, NULL, NSER_ARP_RESOLVE);
}

/**
 * wr32 - write 32 bits to hw register
 * @hw: hardware information including registers
 * @reg: register offset
 * @val: value to write to register
 */
inline void wr32(struct nser_hw *hw, u32 reg, u32 val)
{
	writel(val, hw->hw_addr + reg);
}

/**
 * rd32 - read a 32 bit hw register
 * @hw: hardware information including registers
 * @reg: register offset
 *
 * Return value of register content
 */
inline u32 rd32(struct nser_hw *hw, u32 reg)
{
	return readl(hw->hw_addr + reg);
}

/**
 * rd64 - read a 64 bit hw register
 * @hw: hardware information including registers
 * @reg: register offset
 *
 * Return value of register content
 */
inline u64 rd64(struct nser_hw *hw, u32 reg)
{
	return readq(hw->hw_addr + reg);
}

static void nser_gid_change_event(struct ib_device *ibdev)
{
	struct ib_event ib_event;

	ib_event.event = IB_EVENT_GID_CHANGE;
	ib_event.device = ibdev;
	ib_event.element.port_num = 1;
	ib_dispatch_event(&ib_event);
}

/**
 * nser_inetaddr_event - system notifier for ipv4 addr events
 * @notifier: not used
 * @event: event for notifier
 * @ptr: if address
 */
int nser_inetaddr_event(struct notifier_block *notifier, unsigned long event,
			 void *ptr)
{
	struct in_ifaddr *ifa = ptr;
	struct net_device *netdev = ifa->ifa_dev->dev;
	struct nser_device *iwdev;
	u32 local_ipaddr[4] = {};

	if (is_vlan_dev(netdev))
		netdev = vlan_dev_real_dev(netdev);

	iwdev = container_of(notifier, struct nser_device, nb_inetaddr_event);
	if (iwdev->netdev != netdev)
		return NOTIFY_DONE;

	local_ipaddr[0] = ntohl(ifa->ifa_address);
	nser_dbg(iwdev_to_idev(iwdev),
		  "DEV: netdev %p event %lu local_ip=%pI4 MAC=%pM\n", netdev,
		  event, &local_ipaddr, netdev->dev_addr);
	switch (event) {
	case NETDEV_DOWN:
		nser_manage_arp_cache(iwdev->rf, netdev->dev_addr,
				       local_ipaddr, NSER_ARP_DELETE);
		nser_gid_change_event(&iwdev->ibdev);
		break;
	case NETDEV_UP:
	case NETDEV_CHANGEADDR:
		nser_add_arp(iwdev->rf, local_ipaddr, netdev->dev_addr);
		nser_gid_change_event(&iwdev->ibdev);
		break;
	default:
		break;
	}

	return NOTIFY_DONE;
}

/**
 * nser_inet6addr_event - system notifier for ipv6 addr events
 * @notifier: not used
 * @event: event for notifier
 * @ptr: if address
 */
int nser_inet6addr_event(struct notifier_block *notifier, unsigned long event,
			  void *ptr)
{
	struct inet6_ifaddr *ifa = ptr;
	struct net_device *netdev = ifa->idev->dev;
	struct nser_device *iwdev;
	u32 local_ipaddr6[4];

	if (is_vlan_dev(netdev))
		netdev = vlan_dev_real_dev(netdev);

	iwdev = container_of(notifier, struct nser_device, nb_inet6addr_event);
	if (iwdev->netdev != netdev)
		return NOTIFY_DONE;

	nser_copy_ip_ntohl(local_ipaddr6, ifa->addr.in6_u.u6_addr32);
	nser_dbg(iwdev_to_idev(iwdev),
		  "DEV: netdev %p event %lu local_ip=%pI6 MAC=%pM\n", netdev,
		  event, local_ipaddr6, netdev->dev_addr);
	switch (event) {
	case NETDEV_DOWN:
		nser_manage_arp_cache(iwdev->rf, netdev->dev_addr,
				       local_ipaddr6, NSER_ARP_DELETE);
		nser_gid_change_event(&iwdev->ibdev);
		break;
	case NETDEV_UP:
	case NETDEV_CHANGEADDR:
		nser_add_arp(iwdev->rf, local_ipaddr6, netdev->dev_addr);
		nser_gid_change_event(&iwdev->ibdev);
		break;
	default:
		break;
	}

	return NOTIFY_DONE;
}

/**
 * nser_net_event - system notifier for net events
 * @notifier: not used
 * @event: event for notifier
 * @ptr: neighbor
 */
int nser_net_event(struct notifier_block *notifier, unsigned long event,
		    void *ptr)
{
	struct neighbour *neigh = ptr;
	struct net_device *netdev = (struct net_device *)neigh->dev;
	struct nser_device *iwdev;
	__be32 *p;
	u32 local_ipaddr[4] = {};

	switch (event) {
	case NETEVENT_NEIGH_UPDATE:
		if (is_vlan_dev(netdev))
			netdev = vlan_dev_real_dev(netdev);

		iwdev = container_of(notifier, struct nser_device, nb_net_event);
		if (iwdev->netdev != netdev)
			return NOTIFY_DONE;

		p = (__be32 *)neigh->primary_key;
		if (neigh->tbl->family == AF_INET6)
			nser_copy_ip_ntohl(local_ipaddr, p);
		else
			local_ipaddr[0] = ntohl(*p);

		nser_dbg(iwdev_to_idev(iwdev),
			  "DEV: netdev %p state %d local_ip=%pI4 MAC=%pM\n",
			  iwdev->netdev, neigh->nud_state, local_ipaddr,
			  neigh->ha);

		if (neigh->nud_state & NUD_VALID)
			nser_add_arp(iwdev->rf, local_ipaddr, neigh->ha);
		else
			nser_manage_arp_cache(iwdev->rf, neigh->ha,
					       local_ipaddr, NSER_ARP_DELETE);
		break;
	default:
		break;
	}

	return NOTIFY_DONE;
}

/**
 * nser_netdevice_event - system notifier for netdev events
 * @notifier: not used
 * @event: event for notifier
 * @ptr: netdev
 */
int nser_netdevice_event(struct notifier_block *notifier, unsigned long event,
			  void *ptr)
{
	struct nser_device *iwdev;
	struct net_device *netdev = netdev_notifier_info_to_dev(ptr);

	iwdev = container_of(notifier, struct nser_device, nb_netdevice_event);
	if (iwdev->netdev != netdev)
		return NOTIFY_DONE;

	iwdev->iw_status = 1;
	switch (event) {
	case NETDEV_DOWN:
		iwdev->iw_status = 0;
		fallthrough;
	case NETDEV_UP:
		nser_port_ibevent(iwdev);
		break;
	default:
		break;
	}

	return NOTIFY_DONE;
}

/**
 * nser_find_handler - find a handle given a PCI device
 * @pcidev: pointer to pci dev info
 */
struct nser_handler *nser_find_handler(struct pci_dev *pcidev)
{
	struct nser_handler *hdl;
	unsigned long flags;

	spin_lock_irqsave(&nser_handler_lock, flags);
	list_for_each_entry(hdl, &nser_handlers, list) {
		if (hdl->iwdev->rf->pcidev == pcidev) {
			spin_unlock_irqrestore(&nser_handler_lock, flags);
			return hdl;
		}
	}
	spin_unlock_irqrestore(&nser_handler_lock, flags);

	return NULL;
}

/**
 * nser_add_handler - add a handler to the list
 * @hdl: handler to be added to the handler list
 */
void nser_add_handler(struct nser_handler *hdl)
{
	unsigned long flags;

	spin_lock_irqsave(&nser_handler_lock, flags);
	list_add(&hdl->list, &nser_handlers);
	spin_unlock_irqrestore(&nser_handler_lock, flags);
}

/**
 * nser_del_handler - delete a handler from the list
 * @hdl: handler to be deleted from the handler list
 */
void nser_del_handler(struct nser_handler *hdl)
{
	unsigned long flags;

	spin_lock_irqsave(&nser_handler_lock, flags);
	list_del(&hdl->list);
	spin_unlock_irqrestore(&nser_handler_lock, flags);
}

/**
 * nser_add_ipv6_addr - add ipv6 address to the hw arp table
 * @iwdev: nser device
 */
static void nser_add_ipv6_addr(struct nser_device *iwdev)
{
	struct net_device *ip_dev;
	struct inet6_dev *idev;
	struct inet6_ifaddr *ifp, *tmp;
	u32 local_ipaddr6[4];

	rcu_read_lock();
	for_each_netdev_rcu(&init_net, ip_dev) {
		if (((rdma_vlan_dev_vlan_id(ip_dev) < 0xFFFF &&
		      rdma_vlan_dev_real_dev(ip_dev) == iwdev->netdev) ||
		      ip_dev == iwdev->netdev) &&
		      (READ_ONCE(ip_dev->flags) & IFF_UP)) {
			idev = __in6_dev_get(ip_dev);
			if (!idev) {
				dev_err(idev_to_dev(&iwdev->rf->sc_dev),
					"ipv6 inet device not found\n");
				break;
			}
			list_for_each_entry_safe(ifp, tmp, &idev->addr_list,
						  if_list) {
				nser_dbg(&iwdev->rf->sc_dev,
					  "INIT: IP=%pI6, vlan_id=%d, MAC=%pM\n",
					  &ifp->addr,
					  rdma_vlan_dev_vlan_id(ip_dev),
					  ip_dev->dev_addr);

				nser_copy_ip_ntohl(local_ipaddr6,
						    ifp->addr.in6_u.u6_addr32);
				nser_manage_arp_cache(iwdev->rf,
						       ip_dev->dev_addr,
						       local_ipaddr6,
						       NSER_ARP_ADD);
			}
		}
	}
	rcu_read_unlock();
}

/**
 * nser_add_ipv4_addr - add ipv4 address to the hw arp table
 * @iwdev: nser device
 */
static void nser_add_ipv4_addr(struct nser_device *iwdev)
{
	struct net_device *dev;
	struct in_device *idev;
	u32 local_ipaddr4[4] = {};

	rcu_read_lock();
	for_each_netdev_rcu(&init_net, dev) {
		if (((rdma_vlan_dev_vlan_id(dev) < 0xFFFF &&
		      rdma_vlan_dev_real_dev(dev) == iwdev->netdev) ||
		      dev == iwdev->netdev) && (READ_ONCE(dev->flags) & IFF_UP)) {
			const struct in_ifaddr *ifa;

			idev = __in_dev_get_rcu(dev);
			if (!idev)
				continue;

			in_dev_for_each_ifa_rcu(ifa, idev) {
				nser_dbg(&iwdev->rf->sc_dev,
					  "CM: IP=%pI4, vlan_id=%d, MAC=%pM\n",
					  &ifa->ifa_address,
					  rdma_vlan_dev_vlan_id(dev),
					  dev->dev_addr);

				local_ipaddr4[0] = ntohl(ifa->ifa_address);
				nser_manage_arp_cache(iwdev->rf, dev->dev_addr,
						       local_ipaddr4,
						       NSER_ARP_ADD);
			}
		}
	}
	rcu_read_unlock();
}

/**
 * nser_add_ip - add ip addresses
 * @iwdev: nser device
 *
 * Add ipv4/ipv6 addresses to the arp cache
 */
void nser_add_ip(struct nser_device *iwdev)
{
	nser_add_ipv4_addr(iwdev);
	nser_add_ipv6_addr(iwdev);
}

/**
 * nser_alloc_and_get_cqp_request - get cqp struct
 * @cqp: device cqp ptr
 * @wait: cqp to be used in wait mode
 */
struct nser_cqp_request *nser_alloc_and_get_cqp_request(struct nser_cqp *cqp,
							  bool wait)
{
	struct nser_cqp_request *cqp_request = NULL;
	unsigned long flags;

	spin_lock_irqsave(&cqp->req_lock, flags);
	if (!list_empty(&cqp->cqp_avail_reqs)) {
		cqp_request = list_entry(cqp->cqp_avail_reqs.next,
					 struct nser_cqp_request, list);
		list_del_init(&cqp_request->list);
	}
	spin_unlock_irqrestore(&cqp->req_lock, flags);
	if (!cqp_request) {
		cqp_request = kzalloc(sizeof(*cqp_request), GFP_ATOMIC);
		if (cqp_request) {
			cqp_request->dynamic = true;
			if (wait)
				init_waitqueue_head(&cqp_request->waitq);
		}
	}
	if (!cqp_request) {
		nser_dbg(cqp->sc_cqp.dev, "ERR: CQP Request Fail: No Memory");
		return NULL;
	}

	cqp_request->waiting = wait;
	refcount_set(&cqp_request->refcnt, 1);
	memset(&cqp_request->compl_info, 0, sizeof(cqp_request->compl_info));

	return cqp_request;
}

/**
 * nser_get_cqp_request - increase refcount for cqp_request
 * @cqp_request: pointer to cqp_request instance
 */
static inline void nser_get_cqp_request(struct nser_cqp_request *cqp_request)
{
	refcount_inc(&cqp_request->refcnt);
}

/**
 * nser_free_cqp_request - free cqp request
 * @cqp: cqp ptr
 * @cqp_request: to be put back in cqp list
 */
void nser_free_cqp_request(struct nser_cqp *cqp,
			    struct nser_cqp_request *cqp_request)
{
	unsigned long flags;

	if (cqp_request->dynamic) {
		kfree(cqp_request);
	} else {
		cqp_request->request_done = false;
		cqp_request->callback_fcn = NULL;
		cqp_request->waiting = false;

		spin_lock_irqsave(&cqp->req_lock, flags);
		list_add_tail(&cqp_request->list, &cqp->cqp_avail_reqs);
		spin_unlock_irqrestore(&cqp->req_lock, flags);
	}
	wake_up(&cqp->remove_wq);
}

/**
 * nser_put_cqp_request - dec ref count and free if 0
 * @cqp: cqp ptr
 * @cqp_request: to be put back in cqp list
 */
void nser_put_cqp_request(struct nser_cqp *cqp,
			   struct nser_cqp_request *cqp_request)
{
	if (refcount_dec_and_test(&cqp_request->refcnt))
		nser_free_cqp_request(cqp, cqp_request);
}

/**
 * nser_free_pending_cqp_request -free pending cqp request objs
 * @cqp: cqp ptr
 * @cqp_request: to be put back in cqp list
 */
static void
nser_free_pending_cqp_request(struct nser_cqp *cqp,
			       struct nser_cqp_request *cqp_request)
{
	if (cqp_request->waiting) {
		cqp_request->compl_info.error = true;
		cqp_request->request_done = true;
		wake_up(&cqp_request->waitq);
	}
	wait_event_timeout(cqp->remove_wq,
			   refcount_read(&cqp_request->refcnt) == 1, 1000);
	nser_put_cqp_request(cqp, cqp_request);
}

/**
 * nser_cleanup_pending_cqp_op - clean-up cqp with no
 * completions
 * @rf: RDMA PCI function
 */
void nser_cleanup_pending_cqp_op(struct nser_pci_f *rf)
{
	struct nser_sc_dev *dev = &rf->sc_dev;
	struct nser_cqp *cqp = &rf->cqp;
	struct nser_cqp_request *cqp_request = NULL;
	struct cqp_cmds_info *pcmdinfo = NULL;
	u32 i;

	for (i = 0; i < NSER_CQP_SW_SQSIZE_2048; i++) {
		cqp_request = (struct nser_cqp_request *)(uintptr_t)
				      cqp->scratch_array[i];
		if (cqp_request && refcount_read(&cqp_request->refcnt) > 0)
			nser_free_pending_cqp_request(cqp, cqp_request);
	}

	while (!list_empty(&dev->cqp_cmd_head)) {
		pcmdinfo = nser_remove_cqp_head(dev);
		cqp_request = container_of(pcmdinfo, struct nser_cqp_request, info);
		if (cqp_request && refcount_read(&cqp_request->refcnt) > 0)
			nser_free_pending_cqp_request(cqp, cqp_request);
	}
}
#define MAX_DELAY_FOR_DEREG_MR 100
/**
 * nser_wait_event - wait for completion
 * @rf: RDMA PCI function
 * @cqp_request: cqp request to wait
 */
static int nser_wait_event(struct nser_pci_f *rf,
			    struct nser_cqp_request *cqp_request)
{
	struct nser_cqp_timeout cqp_timeout = {};
	int timeout_threshold = CQP_TIMEOUT_THRESHOLD;
	bool cqp_error = false;
	int err_code = 0;
	//for dereg mr cqp, add 100 us calling ib_umem_release delay to enhance security
	if (cqp_request->info.cqp_cmd == NSER_OP_DEALLOC_STAG)
		udelay(MAX_DELAY_FOR_DEREG_MR);

	cqp_timeout.compl_cqp_cmds = rf->sc_dev.cqp_cmd_stats[NSER_OP_CMPL_CMDS];
	do {
		int wait_time_ms = rf->sc_dev.hw_attrs.max_cqp_compl_wait_time_ms;

		nser_cqp_ce_handler(rf, &rf->ccq.sc_cq);
		if (wait_event_timeout(cqp_request->waitq,
				       cqp_request->request_done,
				       msecs_to_jiffies(wait_time_ms)))
			break;

		nser_check_cqp_progress(&cqp_timeout, &rf->sc_dev);

		if (cqp_timeout.count < timeout_threshold)
			continue;

		if (!rf->reset) {
			rf->reset = true;
			rf->gen_ops.request_reset(rf);
		}
		return -ETIMEDOUT;
	} while (1);

	cqp_error = cqp_request->compl_info.error;
	if (cqp_error) {
		err_code = -EIO;
		if (cqp_request->compl_info.maj_err_code == 0xFFFF) {
			if (cqp_request->compl_info.min_err_code == 0x8002) {
				err_code = -EBUSY;
			} else if (cqp_request->compl_info.min_err_code == 0x8029) {
				if (!rf->reset) {
					rf->reset = true;
					rf->gen_ops.request_reset(rf);
				}
			}
		}
	}

	return err_code;
}

static const char *const nser_cqp_cmd_names[NSER_MAX_CQP_OPS] = {
	[NSER_OP_CEQ_DESTROY] = "Destroy CEQ Cmd",
	[NSER_OP_AEQ_DESTROY] = "Destroy AEQ Cmd",
	[NSER_OP_DELETE_ARP_CACHE_ENTRY] = "Delete ARP Cache Cmd",
	//[NSER_OP_MANAGE_APBVT_ENTRY] = "Manage APBV Table Entry Cmd",
	[NSER_OP_CEQ_CREATE] = "CEQ Create Cmd",
	[NSER_OP_AEQ_CREATE] = "AEQ Destroy Cmd",
	//[NSER_OP_MANAGE_QHASH_TABLE_ENTRY] = "Manage Quad Hash Table Entry Cmd",
	[NSER_OP_QP_MODIFY] = "Modify QP Cmd",
	[NSER_OP_QP_UPLOAD_CONTEXT] = "Upload Context Cmd",
	[NSER_OP_CQ_CREATE] = "Create CQ Cmd",
	[NSER_OP_CQ_DESTROY] = "Destroy CQ Cmd",
	[NSER_OP_QP_CREATE] = "Create QP Cmd",
	[NSER_OP_QP_DESTROY] = "Destroy QP Cmd",
	[NSER_OP_ALLOC_STAG] = "Allocate STag Cmd",
	[NSER_OP_MR_REG_NON_SHARED] = "Register Non-Shared MR Cmd",
	[NSER_OP_DEALLOC_STAG] = "Deallocate STag Cmd",
	[NSER_OP_MW_ALLOC] = "Allocate Memory Window Cmd",
	[NSER_OP_QP_FLUSH_WQES] = "Flush QP Cmd",
	[NSER_OP_ADD_ARP_CACHE_ENTRY] = "Add ARP Cache Cmd",
	//[NSER_OP_MANAGE_PUSH_PAGE] = "Manage Push Page Cmd",
	[NSER_OP_UPDATE_PE_SDS] = "Update PE SDs Cmd",
	[NSER_OP_MANAGE_HMC_PM_FUNC_TABLE] = "Manage HMC PM Function Table Cmd",
	[NSER_OP_SUSPEND] = "Suspend QP Cmd",
	[NSER_OP_RESUME] = "Resume QP Cmd",
	[NSER_OP_MANAGE_VF_PBLE_BP] = "Manage VF PBLE Backing Pages Cmd",
	[NSER_OP_QUERY_FPM_VAL] = "Query FPM Values Cmd",
	[NSER_OP_COMMIT_FPM_VAL] = "Commit FPM Values Cmd",
	[NSER_OP_AH_CREATE] = "Create Address Handle Cmd",
	[NSER_OP_AH_MODIFY] = "Modify Address Handle Cmd",
	[NSER_OP_AH_DESTROY] = "Destroy Address Handle Cmd",
	[NSER_OP_MC_CREATE] = "Create Multicast Group Cmd",
	[NSER_OP_MC_DESTROY] = "Destroy Multicast Group Cmd",
	[NSER_OP_MC_MODIFY] = "Modify Multicast Group Cmd",
	[NSER_OP_STATS_ALLOCATE] = "Add Statistics Instance Cmd",
	[NSER_OP_STATS_FREE] = "Free Statistics Instance Cmd",
	[NSER_OP_STATS_GATHER] = "Gather Statistics Cmd",
	[NSER_OP_WS_ADD_NODE] = "Add Work Scheduler Node Cmd",
	[NSER_OP_WS_MODIFY_NODE] = "Modify Work Scheduler Node Cmd",
	[NSER_OP_WS_DELETE_NODE] = "Delete Work Scheduler Node Cmd",
	[NSER_OP_SET_UP_MAP] = "Set UP-UP Mapping Cmd",
	[NSER_OP_QUERY_RDMA_FEATURES] = "RDMA Get Features Cmd",
	[NSER_OP_ADD_LOCAL_MAC_ENTRY] = "Add Local MAC Entry Cmd",
	[NSER_OP_DELETE_LOCAL_MAC_ENTRY] = "Delete Local MAC Entry Cmd",
	[NSER_OP_CQ_MODIFY] = "CQ Modify Cmd",
};

static const struct nser_cqp_err_info nser_noncrit_err_list[] = {
	{0xffff, 0x8002, "Invalid State"},
	{0xffff, 0x8006, "Flush No Wqe Pending"},
	{0xffff, 0x8007, "Modify QP Bad Close"},
	{0xffff, 0x8009, "LLP Closed"},
	{0xffff, 0x800a, "Reset Not Sent"}
};

/**
 * nser_cqp_crit_err - check if CQP error is critical
 * @dev: pointer to dev structure
 * @cqp_cmd: code for last CQP operation
 * @maj_err_code: major error code
 * @min_err_code: minot error code
 */
bool nser_cqp_crit_err(struct nser_sc_dev *dev, u8 cqp_cmd,
			u16 maj_err_code, u16 min_err_code)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(nser_noncrit_err_list); ++i) {
		if (maj_err_code == nser_noncrit_err_list[i].maj &&
		    min_err_code == nser_noncrit_err_list[i].min) {
			nser_dbg(dev,
				  "CQP: [%s Error][%s] maj=0x%x min=0x%x\n",
				  nser_noncrit_err_list[i].desc,
				  nser_cqp_cmd_names[cqp_cmd], maj_err_code,
				  min_err_code);
			return false;
		}
	}
	return true;
}

/**
 * nser_handle_cqp_op - process cqp command
 * @rf: RDMA PCI function
 * @cqp_request: cqp request to process
 */
int nser_handle_cqp_op(struct nser_pci_f *rf,
			struct nser_cqp_request *cqp_request)
{
	struct nser_sc_dev *dev = &rf->sc_dev;
	struct cqp_cmds_info *info = &cqp_request->info;
	int status;
	bool put_cqp_request = true;

	if (rf->reset)
		return 0;

	nser_get_cqp_request(cqp_request);
	status = nser_process_cqp_cmd(dev, info);
	if (status)
		goto err;

	if (cqp_request->waiting) {
		put_cqp_request = false;
		status = nser_wait_event(rf, cqp_request);
		if (status)
			goto err;
	}

	return 0;

err:
	if (nser_cqp_crit_err(dev, info->cqp_cmd,
			       cqp_request->compl_info.maj_err_code,
			       cqp_request->compl_info.min_err_code))
		dev_err(idev_to_dev(dev),
			"[%s Error][op_code=%d] status=%d waiting=%d completion_err=%d maj=0x%x min=0x%x\n",
			nser_cqp_cmd_names[info->cqp_cmd], info->cqp_cmd,
			status, cqp_request->waiting,
			cqp_request->compl_info.error,
			cqp_request->compl_info.maj_err_code,
			cqp_request->compl_info.min_err_code);

	if (put_cqp_request)
		nser_put_cqp_request(&rf->cqp, cqp_request);

	return status;
}

void nser_qp_add_ref(struct ib_qp *ibqp)
{
	struct nser_qp *iwqp = to_iwqp(ibqp);

	refcount_inc(&iwqp->refcnt);
}

void nser_qp_rem_ref(struct ib_qp *ibqp)
{
	struct nser_qp *iwqp = to_iwqp(ibqp);
	struct nser_device *iwdev = iwqp->iwdev;
	unsigned long flags;

	spin_lock_irqsave(&iwdev->rf->qptable_lock, flags);
	if (!refcount_dec_and_test(&iwqp->refcnt)) {
		spin_unlock_irqrestore(&iwdev->rf->qptable_lock, flags);
		return;
	}

	iwdev->rf->qp_table[iwqp->ibqp.qp_num] = NULL;
	spin_unlock_irqrestore(&iwdev->rf->qptable_lock, flags);
	complete(&iwqp->free_qp);
}

void nser_cq_add_ref(struct ib_cq *ibcq)
{
	struct nser_cq *iwcq = to_iwcq(ibcq);

	refcount_inc(&iwcq->refcnt);
}

void nser_cq_rem_ref(struct ib_cq *ibcq)
{
	struct nser_cq *iwcq = to_iwcq(ibcq);
	struct nser_pci_f *rf = container_of(iwcq->sc_cq.dev, struct nser_pci_f, sc_dev);
	unsigned long flags;

	spin_lock_irqsave(&rf->cqtable_lock, flags);
	if (!refcount_dec_and_test(&iwcq->refcnt)) {
		spin_unlock_irqrestore(&rf->cqtable_lock, flags);
		return;
	}

	rf->cq_table[iwcq->cq_num] = NULL;
	spin_unlock_irqrestore(&rf->cqtable_lock, flags);
	complete(&iwcq->free_cq);
}

struct ib_device *nser_get_ibdev(struct nser_sc_dev *dev)
{
	return &(container_of(dev, struct nser_pci_f, sc_dev))->iwdev->ibdev;
}

/**
 * nser_get_qp - get qp address
 * @device: iwarp device
 * @qpn: qp number
 */
struct ib_qp *nser_get_qp(struct ib_device *device, int qpn)
{
	struct nser_device *iwdev = to_iwdev(device);

	if (qpn < IW_FIRST_QPN || qpn >= iwdev->rf->max_qp)
		return NULL;

	return &iwdev->rf->qp_table[qpn]->ibqp;
}

/**
 * nser_get_hw_addr - return hw addr
 * @par: points to shared dev
 */
u8 __iomem *nser_get_hw_addr(void *par)
{
	struct nser_sc_dev *dev = par;

	return dev->hw->hw_addr;
}

/**
 * nser_remove_cqp_head - return head entry and remove
 * @dev: device
 */
void *nser_remove_cqp_head(struct nser_sc_dev *dev)
{
	struct list_head *entry;
	struct list_head *list = &dev->cqp_cmd_head;

	if (list_empty(list))
		return NULL;

	entry = list->next;
	list_del(entry);

	return entry;
}

/**
 * nser_cqp_sds_cmd - create cqp command for sd
 * @dev: hardware control device structure
 * @sdinfo: information for sd cqp
 *
 */
int nser_cqp_sds_cmd(struct nser_sc_dev *dev,
		      struct nser_update_sds_info *sdinfo)
{
	struct nser_cqp_request *cqp_request;
	struct cqp_cmds_info *cqp_info;
	struct nser_pci_f *rf = dev_to_rf(dev);
	int status;

	cqp_request = nser_alloc_and_get_cqp_request(&rf->cqp, true);
	if (!cqp_request)
		return -ENOMEM;

	cqp_info = &cqp_request->info;
	memcpy(&cqp_info->in.u.update_pe_sds.info, sdinfo,
	       sizeof(cqp_info->in.u.update_pe_sds.info));
	cqp_info->cqp_cmd = NSER_OP_UPDATE_PE_SDS;
	cqp_info->post_sq = 1;
	cqp_info->in.u.update_pe_sds.dev = dev;
	cqp_info->in.u.update_pe_sds.scratch = (uintptr_t)cqp_request;

	status = nser_handle_cqp_op(rf, cqp_request);
	nser_put_cqp_request(&rf->cqp, cqp_request);

	return status;
}

/**
 * nser_cqp_qp_suspend_resume - cqp command for suspend/resume
 * @qp: hardware control qp
 * @op: suspend or resume
 */
int nser_cqp_qp_suspend_resume(struct nser_sc_qp *qp, u8 op)
{
	struct nser_sc_dev *dev = qp->dev;
	struct nser_cqp_request *cqp_request;
	struct nser_sc_cqp *cqp = dev->cqp;
	struct cqp_cmds_info *cqp_info;
	struct nser_pci_f *rf = dev_to_rf(dev);
	int status;

	cqp_request = nser_alloc_and_get_cqp_request(&rf->cqp, false);
	if (!cqp_request)
		return -ENOMEM;

	cqp_info = &cqp_request->info;
	cqp_info->cqp_cmd = op;
	cqp_info->in.u.suspend_resume.cqp = cqp;
	cqp_info->in.u.suspend_resume.qp = qp;
	cqp_info->in.u.suspend_resume.scratch = (uintptr_t)cqp_request;

	status = nser_handle_cqp_op(rf, cqp_request);
	nser_put_cqp_request(&rf->cqp, cqp_request);

	return status;
}

/**
 * nser_cqp_manage_hmc_fcn_cmd - issue cqp command to manage hmc
 * @dev: hardware control device structure
 * @hmcfcninfo: info for hmc
 * @pmf_idx: pmf or hmc function index for the vf_dev
 */
int nser_cqp_manage_hmc_fcn_cmd(struct nser_sc_dev *dev,
				 struct nser_hmc_fcn_info *hmcfcninfo,
				 u16 *pmf_idx)
{
	struct nser_cqp_request *cqp_request;
	struct cqp_cmds_info *cqp_info;
	struct nser_pci_f *rf = dev_to_rf(dev);
	int status;

	cqp_request = nser_alloc_and_get_cqp_request(&rf->cqp, true);
	if (!cqp_request)
		return -ENOMEM;

	cqp_info = &cqp_request->info;
	memcpy(&cqp_info->in.u.manage_hmc_pm.info, hmcfcninfo,
	       sizeof(cqp_info->in.u.manage_hmc_pm.info));
	cqp_info->in.u.manage_hmc_pm.dev = dev;
	cqp_info->cqp_cmd = NSER_OP_MANAGE_HMC_PM_FUNC_TABLE;
	cqp_info->post_sq = 1;
	cqp_info->in.u.manage_hmc_pm.scratch = (uintptr_t)cqp_request;

	status = nser_handle_cqp_op(rf, cqp_request);
	*pmf_idx = cqp_request->compl_info.op_ret_val;
	nser_put_cqp_request(&rf->cqp, cqp_request);

	return status;
}

/**
 * nser_cqp_query_fpm_val_cmd - send cqp command for fpm
 * @dev: function device struct
 * @val_mem: buffer for fpm
 * @hmc_fn_id: function id for fpm
 */
int nser_cqp_query_fpm_val_cmd(struct nser_sc_dev *dev,
				struct nser_dma_mem *val_mem, u8 hmc_fn_id)
{
	struct nser_cqp_request *cqp_request;
	struct cqp_cmds_info *cqp_info;
	struct nser_pci_f *rf = dev_to_rf(dev);
	int status;

	cqp_request = nser_alloc_and_get_cqp_request(&rf->cqp, true);
	if (!cqp_request)
		return -ENOMEM;

	cqp_info = &cqp_request->info;
	cqp_request->param = NULL;
	cqp_info->in.u.query_fpm_val.cqp = dev->cqp;
	cqp_info->in.u.query_fpm_val.fpm_val_pa = val_mem->pa;
	cqp_info->in.u.query_fpm_val.fpm_val_va = val_mem->va;
	cqp_info->in.u.query_fpm_val.hmc_fn_id = hmc_fn_id;
	cqp_info->cqp_cmd = NSER_OP_QUERY_FPM_VAL;
	cqp_info->post_sq = 1;
	cqp_info->in.u.query_fpm_val.scratch = (uintptr_t)cqp_request;

	status = nser_handle_cqp_op(rf, cqp_request);
	nser_put_cqp_request(&rf->cqp, cqp_request);

	return status;
}

/**
 * nser_cqp_commit_fpm_val_cmd - commit fpm values in hw
 * @dev: hardware control device structure
 * @val_mem: buffer with fpm values
 * @hmc_fn_id: function id for fpm
 */
int nser_cqp_commit_fpm_val_cmd(struct nser_sc_dev *dev,
				 struct nser_dma_mem *val_mem, u8 hmc_fn_id)
{
	struct nser_cqp_request *cqp_request;
	struct cqp_cmds_info *cqp_info;
	struct nser_pci_f *rf = dev_to_rf(dev);
	int status;

	cqp_request = nser_alloc_and_get_cqp_request(&rf->cqp, true);
	if (!cqp_request)
		return -ENOMEM;

	cqp_info = &cqp_request->info;
	cqp_request->param = NULL;
	cqp_info->in.u.commit_fpm_val.cqp = dev->cqp;
	cqp_info->in.u.commit_fpm_val.fpm_val_pa = val_mem->pa;
	cqp_info->in.u.commit_fpm_val.fpm_val_va = val_mem->va;
	cqp_info->in.u.commit_fpm_val.hmc_fn_id = hmc_fn_id;
	cqp_info->cqp_cmd = NSER_OP_COMMIT_FPM_VAL;
	cqp_info->post_sq = 1;
	cqp_info->in.u.commit_fpm_val.scratch = (uintptr_t)cqp_request;

	status = nser_handle_cqp_op(rf, cqp_request);
	nser_put_cqp_request(&rf->cqp, cqp_request);

	return status;
}

/**
 * nser_cqp_cq_create_cmd - create a cq for the cqp
 * @dev: device pointer
 * @cq: pointer to created cq
 */
int nser_cqp_cq_create_cmd(struct nser_sc_dev *dev, struct nser_sc_cq *cq)
{
	struct nser_pci_f *rf = dev_to_rf(dev);
	struct nser_cqp *iwcqp = &rf->cqp;
	struct nser_cqp_request *cqp_request;
	struct cqp_cmds_info *cqp_info;
	int status;

	cqp_request = nser_alloc_and_get_cqp_request(iwcqp, true);
	if (!cqp_request)
		return -ENOMEM;

	cqp_info = &cqp_request->info;
	cqp_info->cqp_cmd = NSER_OP_CQ_CREATE;
	cqp_info->post_sq = 1;
	cqp_info->in.u.cq_create.cq = cq;
	cqp_info->in.u.cq_create.scratch = (uintptr_t)cqp_request;

	status = nser_handle_cqp_op(rf, cqp_request);
	nser_put_cqp_request(iwcqp, cqp_request);

	return status;
}

/**
 * nser_cqp_qp_create_cmd - create a qp for the cqp
 * @dev: device pointer
 * @qp: pointer to created qp
 */
int nser_cqp_qp_create_cmd(struct nser_sc_dev *dev, struct nser_sc_qp *qp)
{
	struct nser_pci_f *rf = dev_to_rf(dev);
	struct nser_cqp *iwcqp = &rf->cqp;
	struct nser_cqp_request *cqp_request;
	struct cqp_cmds_info *cqp_info;
	struct nser_create_qp_info *qp_info;
	int status;

	cqp_request = nser_alloc_and_get_cqp_request(iwcqp, true);
	if (!cqp_request)
		return -ENOMEM;

	cqp_info = &cqp_request->info;
	qp_info = &cqp_request->info.in.u.qp_create.info;
	memset(qp_info, 0, sizeof(*qp_info));
	qp_info->cq_num_valid = true;
	qp_info->next_rdma_state = NSER_QP_STATE_RTS;
	cqp_info->cqp_cmd = NSER_OP_QP_CREATE;
	cqp_info->post_sq = 1;
	cqp_info->in.u.qp_create.qp = qp;
	cqp_info->in.u.qp_create.scratch = (uintptr_t)cqp_request;

	status = nser_handle_cqp_op(rf, cqp_request);
	nser_put_cqp_request(iwcqp, cqp_request);

	return status;
}

/**
 * nser_cq_wq_destroy - send cq destroy cqp
 * @rf: RDMA PCI function
 * @cq: hardware control cq
 */
void nser_cq_wq_destroy(struct nser_pci_f *rf, struct nser_sc_cq *cq)
{
	struct nser_cqp_request *cqp_request;
	struct cqp_cmds_info *cqp_info;

	cqp_request = nser_alloc_and_get_cqp_request(&rf->cqp, true);
	if (!cqp_request)
		return;

	cqp_info = &cqp_request->info;
	cqp_info->cqp_cmd = NSER_OP_CQ_DESTROY;
	cqp_info->post_sq = 1;
	cqp_info->in.u.cq_destroy.cq = cq;
	cqp_info->in.u.cq_destroy.scratch = (uintptr_t)cqp_request;

	nser_handle_cqp_op(rf, cqp_request);
	nser_put_cqp_request(&rf->cqp, cqp_request);
}

/**
 * nser_hw_modify_qp_callback - handle state for modifyQPs that don't wait
 * @cqp_request: modify QP completion
 */
static void nser_hw_modify_qp_callback(struct nser_cqp_request *cqp_request)
{
	struct cqp_cmds_info *cqp_info;
	struct nser_qp *iwqp;

	cqp_info = &cqp_request->info;
	iwqp = cqp_info->in.u.qp_modify.qp->qp_uk.back_qp;
	atomic_dec(&iwqp->hw_mod_qp_pend);
	wake_up(&iwqp->mod_qp_waitq);
}

/**
 * nser_hw_modify_qp - setup cqp for modify qp
 * @iwdev: RDMA device
 * @iwqp: qp ptr (user or kernel)
 * @info: info for modify qp
 * @wait: flag to wait or not for modify qp completion
 */
int nser_hw_modify_qp(struct nser_device *iwdev, struct nser_qp *iwqp,
		       struct nser_modify_qp_info *info, bool wait)
{
	int status;
	struct nser_pci_f *rf = iwdev->rf;
	struct nser_cqp_request *cqp_request;
	struct cqp_cmds_info *cqp_info;
	struct nser_modify_qp_info *m_info;

	cqp_request = nser_alloc_and_get_cqp_request(&rf->cqp, wait);
	if (!cqp_request)
		return -ENOMEM;

	if (!wait) {
		cqp_request->callback_fcn = nser_hw_modify_qp_callback;
		atomic_inc(&iwqp->hw_mod_qp_pend);
	}
	cqp_info = &cqp_request->info;
	m_info = &cqp_info->in.u.qp_modify.info;
	memcpy(m_info, info, sizeof(*m_info));
	cqp_info->cqp_cmd = NSER_OP_QP_MODIFY;
	cqp_info->post_sq = 1;
	cqp_info->in.u.qp_modify.qp = &iwqp->sc_qp;
	cqp_info->in.u.qp_modify.scratch = (uintptr_t)cqp_request;
	status = nser_handle_cqp_op(rf, cqp_request);
	nser_put_cqp_request(&rf->cqp, cqp_request);

	return status;
}

/**
 * nser_cqp_cq_destroy_cmd - destroy the cqp cq
 * @dev: device pointer
 * @cq: pointer to cq
 */
void nser_cqp_cq_destroy_cmd(struct nser_sc_dev *dev, struct nser_sc_cq *cq)
{
	struct nser_pci_f *rf = dev_to_rf(dev);

	nser_cq_wq_destroy(rf, cq);
}

/**
 * nser_cqp_qp_destroy_cmd - destroy the cqp
 * @dev: device pointer
 * @qp: pointer to qp
 */
int nser_cqp_qp_destroy_cmd(struct nser_sc_dev *dev, struct nser_sc_qp *qp)
{
	struct nser_pci_f *rf = dev_to_rf(dev);
	struct nser_cqp *iwcqp = &rf->cqp;
	struct nser_cqp_request *cqp_request;
	struct cqp_cmds_info *cqp_info;
	int status;

	cqp_request = nser_alloc_and_get_cqp_request(iwcqp, true);
	if (!cqp_request)
		return -ENOMEM;

	cqp_info = &cqp_request->info;
	memset(cqp_info, 0, sizeof(*cqp_info));
	cqp_info->cqp_cmd = NSER_OP_QP_DESTROY;
	cqp_info->post_sq = 1;
	cqp_info->in.u.qp_destroy.qp = qp;
	cqp_info->in.u.qp_destroy.scratch = (uintptr_t)cqp_request;
	cqp_info->in.u.qp_destroy.remove_hash_idx = true;

	status = nser_handle_cqp_op(rf, cqp_request);
	nser_put_cqp_request(&rf->cqp, cqp_request);

	return status;
}

/**
 * nser_init_hash_desc - initialize hash for crc calculation
 * @desc: cryption type
 */
int nser_init_hash_desc(struct shash_desc **desc)
{
	struct crypto_shash *tfm;
	struct shash_desc *tdesc;

	tfm = crypto_alloc_shash("crc32c", 0, 0);
	if (IS_ERR(tfm))
		return PTR_ERR(tfm);

	tdesc = kzalloc(sizeof(*tdesc) + crypto_shash_descsize(tfm),
			GFP_KERNEL);
	if (!tdesc) {
		crypto_free_shash(tfm);
		return -ENOMEM;
	}

	tdesc->tfm = tfm;
	*desc = tdesc;

	return 0;
}

/**
 * nser_free_hash_desc - free hash desc
 * @desc: to be freed
 */
void nser_free_hash_desc(struct shash_desc *desc)
{
	if (desc) {
		crypto_free_shash(desc->tfm);
		kfree(desc);
	}
}

/**
 * nser_alloc_query_fpm_buf - allocate buffer for fpm
 * @dev: hardware control device structure
 * @mem: buffer ptr for fpm to be allocated
 * @return: memory allocation status
 */
int nser_alloc_query_fpm_buf(struct nser_sc_dev *dev,
			      struct nser_dma_mem *mem)
{
	int status;

	status = nser_obj_aligned_mem(dev_to_rf(dev), mem,
				       NSER_QUERY_FPM_BUF_SIZE,
				       NSER_FPM_QUERY_BUF_ALIGNMENT_M);

	return status;
}

/**
 * nser_hw_stats_timeout - Stats timer-handler which updates all HW stats
 * @t: timer_list pointer
 */
static void nser_hw_stats_timeout(struct timer_list *t)
{
	struct nser_vsi_pestat *pf_devstat =
		from_timer(pf_devstat, t, stats_timer);
	struct nser_sc_vsi *sc_vsi = pf_devstat->vsi;

	nser_cqp_gather_stats_cmd(sc_vsi->dev, sc_vsi->pestat, false);

	mod_timer(&pf_devstat->stats_timer,
		  jiffies + msecs_to_jiffies(STATS_TIMER_DELAY));
}

/**
 * nser_hw_stats_start_timer - Start periodic stats timer
 * @vsi: vsi structure pointer
 */
void nser_hw_stats_start_timer(struct nser_sc_vsi *vsi)
{
	struct nser_vsi_pestat *devstat = vsi->pestat;

	timer_setup(&devstat->stats_timer, nser_hw_stats_timeout, 0);
	mod_timer(&devstat->stats_timer,
		  jiffies + msecs_to_jiffies(STATS_TIMER_DELAY));
}

/**
 * nser_hw_stats_stop_timer - Delete periodic stats timer
 * @vsi: pointer to vsi structure
 */
void nser_hw_stats_stop_timer(struct nser_sc_vsi *vsi)
{
	struct nser_vsi_pestat *devstat = vsi->pestat;

	del_timer_sync(&devstat->stats_timer);
}

/**
 * nser_process_stats - Checking for wrap and update stats
 * @pestat: stats structure pointer
 */
static inline void nser_process_stats(struct nser_vsi_pestat *pestat)
{
	sc_vsi_update_stats(pestat->vsi);
}

/**
 * nser_cqp_gather_stats_gen1 - Gather stats
 * @dev: pointer to device structure
 * @pestat: statistics structure
 */
void nser_cqp_gather_stats_gen1(struct nser_sc_dev *dev,
				 struct nser_vsi_pestat *pestat)
{
	struct nser_gather_stats *gather_stats =
		pestat->gather_info.gather_stats_va;
	const struct nser_hw_stat_map *map = dev->hw_stats_map;
	u16 max_stats_idx = dev->hw_attrs.max_stat_idx;
	u32 stats_inst_offset_32;
	u32 stats_inst_offset_64;
	u64 new_val;
	u16 i;

	stats_inst_offset_32 = (pestat->gather_info.use_stats_inst) ?
				pestat->gather_info.stats_inst_index :
				pestat->hw->hmc.hmc_fn_id;
	stats_inst_offset_32 *= 4;
	stats_inst_offset_64 = stats_inst_offset_32 * 2;

	for (i = 0; i < max_stats_idx; i++) {
		if (map[i].bitmask <= NSER_MAX_STATS_32) {
			new_val = rd32(dev->hw,
				       dev->hw_stats_regs[i] + stats_inst_offset_32);
		} else {
			new_val = rd64(dev->hw,
				       dev->hw_stats_regs[i] + stats_inst_offset_64);
		}
		gather_stats->val[map[i].byteoff / sizeof(u64)] = new_val;
	}

	nser_process_stats(pestat);
}

/**
 * nser_process_cqp_stats - Checking for wrap and update stats
 * @cqp_request: cqp_request structure pointer
 */
static void nser_process_cqp_stats(struct nser_cqp_request *cqp_request)
{
	struct nser_vsi_pestat *pestat = cqp_request->param;

	nser_process_stats(pestat);
}

/**
 * nser_cqp_gather_stats_cmd - Gather stats
 * @dev: pointer to device structure
 * @pestat: pointer to stats info
 * @wait: flag to wait or not wait for stats
 */
int nser_cqp_gather_stats_cmd(struct nser_sc_dev *dev,
			       struct nser_vsi_pestat *pestat, bool wait)

{
	struct nser_pci_f *rf = dev_to_rf(dev);
	struct nser_cqp *iwcqp = &rf->cqp;
	struct nser_cqp_request *cqp_request;
	struct cqp_cmds_info *cqp_info;
	int status;

	cqp_request = nser_alloc_and_get_cqp_request(iwcqp, wait);
	if (!cqp_request)
		return -ENOMEM;

	cqp_info = &cqp_request->info;
	memset(cqp_info, 0, sizeof(*cqp_info));
	cqp_info->cqp_cmd = NSER_OP_STATS_GATHER;
	cqp_info->post_sq = 1;
	cqp_info->in.u.stats_gather.info = pestat->gather_info;
	cqp_info->in.u.stats_gather.scratch = (uintptr_t)cqp_request;
	cqp_info->in.u.stats_gather.cqp = &rf->cqp.sc_cqp;
	cqp_request->param = pestat;
	if (!wait)
		cqp_request->callback_fcn = nser_process_cqp_stats;
	status = nser_handle_cqp_op(rf, cqp_request);
	if (wait)
		nser_process_stats(pestat);
	nser_put_cqp_request(&rf->cqp, cqp_request);

	return status;
}

/**
 * nser_cqp_stats_inst_cmd - Allocate/free stats instance
 * @vsi: pointer to vsi structure
 * @cmd: command to allocate or free
 * @stats_info: pointer to allocate stats info
 */
int nser_cqp_stats_inst_cmd(struct nser_sc_vsi *vsi, u8 cmd,
			     struct nser_stats_inst_info *stats_info)
{
	struct nser_pci_f *rf = dev_to_rf(vsi->dev);
	struct nser_cqp *iwcqp = &rf->cqp;
	struct nser_cqp_request *cqp_request;
	struct cqp_cmds_info *cqp_info;
	int status;
	bool wait = false;

	if (cmd == NSER_OP_STATS_ALLOCATE)
		wait = true;
	cqp_request = nser_alloc_and_get_cqp_request(iwcqp, wait);
	if (!cqp_request)
		return -ENOMEM;

	cqp_info = &cqp_request->info;
	memset(cqp_info, 0, sizeof(*cqp_info));
	cqp_info->cqp_cmd = cmd;
	cqp_info->post_sq = 1;
	cqp_info->in.u.stats_manage.info = *stats_info;
	cqp_info->in.u.stats_manage.scratch = (uintptr_t)cqp_request;
	cqp_info->in.u.stats_manage.cqp = &rf->cqp.sc_cqp;
	status = nser_handle_cqp_op(rf, cqp_request);
	if (wait)
		stats_info->stats_idx = cqp_request->compl_info.op_ret_val;
	nser_put_cqp_request(iwcqp, cqp_request);

	return status;
}

/**
 * nser_cqp_ceq_cmd - Create/Destroy CEQ's after CEQ 0
 * @dev: pointer to device info
 * @sc_ceq: pointer to ceq structure
 * @op: Create or Destroy
 */
int nser_cqp_ceq_cmd(struct nser_sc_dev *dev, struct nser_sc_ceq *sc_ceq,
		      u8 op)
{
	struct nser_cqp_request *cqp_request;
	struct cqp_cmds_info *cqp_info;
	struct nser_pci_f *rf = dev_to_rf(dev);
	int status;

	cqp_request = nser_alloc_and_get_cqp_request(&rf->cqp, true);
	if (!cqp_request)
		return -ENOMEM;

	cqp_info = &cqp_request->info;
	cqp_info->post_sq = 1;
	cqp_info->cqp_cmd = op;
	cqp_info->in.u.ceq_create.ceq = sc_ceq;
	cqp_info->in.u.ceq_create.scratch = (uintptr_t)cqp_request;

	status = nser_handle_cqp_op(rf, cqp_request);
	nser_put_cqp_request(&rf->cqp, cqp_request);

	return status;
}

/**
 * nser_cqp_aeq_cmd - Create/Destroy AEQ
 * @dev: pointer to device info
 * @sc_aeq: pointer to aeq structure
 * @op: Create or Destroy
 */
int nser_cqp_aeq_cmd(struct nser_sc_dev *dev, struct nser_sc_aeq *sc_aeq,
		      u8 op)
{
	struct nser_cqp_request *cqp_request;
	struct cqp_cmds_info *cqp_info;
	struct nser_pci_f *rf = dev_to_rf(dev);
	int status;

	cqp_request = nser_alloc_and_get_cqp_request(&rf->cqp, true);
	if (!cqp_request)
		return -ENOMEM;

	cqp_info = &cqp_request->info;
	cqp_info->post_sq = 1;
	cqp_info->cqp_cmd = op;
	cqp_info->in.u.aeq_create.aeq = sc_aeq;
	cqp_info->in.u.aeq_create.scratch = (uintptr_t)cqp_request;

	status = nser_handle_cqp_op(rf, cqp_request);
	nser_put_cqp_request(&rf->cqp, cqp_request);

	return status;
}

/**
 * nser_cqp_ws_node_cmd - Add/modify/delete ws node
 * @dev: pointer to device structure
 * @cmd: Add, modify or delete
 * @node_info: pointer to ws node info
 */
int nser_cqp_ws_node_cmd(struct nser_sc_dev *dev, u8 cmd,
			  struct nser_ws_node_info *node_info)
{
	struct nser_pci_f *rf = dev_to_rf(dev);
	struct nser_cqp *iwcqp = &rf->cqp;
	struct nser_sc_cqp *cqp = &iwcqp->sc_cqp;
	struct nser_cqp_request *cqp_request;
	struct cqp_cmds_info *cqp_info;
	int status;
	bool poll;

	if (!rf->sc_dev.ceq_valid)
		poll = true;
	else
		poll = false;

	cqp_request = nser_alloc_and_get_cqp_request(iwcqp, !poll);
	if (!cqp_request)
		return -ENOMEM;

	cqp_info = &cqp_request->info;
	memset(cqp_info, 0, sizeof(*cqp_info));
	cqp_info->cqp_cmd = cmd;
	cqp_info->post_sq = 1;
	cqp_info->in.u.ws_node.info = *node_info;
	cqp_info->in.u.ws_node.cqp = cqp;
	cqp_info->in.u.ws_node.scratch = (uintptr_t)cqp_request;
	status = nser_handle_cqp_op(rf, cqp_request);
	if (status)
		goto exit;

	if (poll) {
		struct nser_ccq_cqe_info compl_info;

		status = nser_sc_poll_for_cqp_op_done(cqp, NSER_CQP_OP_WORK_SCHED_NODE,
						       &compl_info);
		node_info->qs_handle = compl_info.op_ret_val;
		nser_dbg(cqp->dev, "DCB: opcode=%d, compl_info.retval=%d\n",
			  compl_info.op_code, compl_info.op_ret_val);
	} else {
		node_info->qs_handle = cqp_request->compl_info.op_ret_val;
	}

exit:
	nser_put_cqp_request(&rf->cqp, cqp_request);

	return status;
}

/**
 * nser_cqp_up_map_cmd - Set the up-up mapping
 * @dev: pointer to device structure
 * @cmd: map command
 * @map_info: pointer to up map info
 */
int nser_cqp_up_map_cmd(struct nser_sc_dev *dev, u8 cmd,
			 struct nser_up_info *map_info)
{
	struct nser_pci_f *rf = dev_to_rf(dev);
	struct nser_cqp *iwcqp = &rf->cqp;
	struct nser_sc_cqp *cqp = &iwcqp->sc_cqp;
	struct nser_cqp_request *cqp_request;
	struct cqp_cmds_info *cqp_info;
	int status;

	cqp_request = nser_alloc_and_get_cqp_request(iwcqp, false);
	if (!cqp_request)
		return -ENOMEM;

	cqp_info = &cqp_request->info;
	memset(cqp_info, 0, sizeof(*cqp_info));
	cqp_info->cqp_cmd = cmd;
	cqp_info->post_sq = 1;
	cqp_info->in.u.up_map.info = *map_info;
	cqp_info->in.u.up_map.cqp = cqp;
	cqp_info->in.u.up_map.scratch = (uintptr_t)cqp_request;

	status = nser_handle_cqp_op(rf, cqp_request);
	nser_put_cqp_request(&rf->cqp, cqp_request);

	return status;
}

/**
 * nser_cqp_cnp_cmd - Set the cnp dscp priority value ipv4 or 802p prio value ipv6
 * @dev: pointer to device structure
 * @cmd: cnp command
 * @cnp_info: pointer to cnp info
 */
int nser_cqp_cnp_cmd(struct nser_sc_dev *dev, u8 cmd,
			 struct nser_cnp_info *cnp_info)
{
	struct nser_pci_f *rf = dev_to_rf(dev);
	struct nser_cqp *iwcqp = &rf->cqp;
	struct nser_sc_cqp *cqp = &iwcqp->sc_cqp;
	struct nser_cqp_request *cqp_request;
	struct cqp_cmds_info *cqp_info;
	int status;

	cqp_request = nser_alloc_and_get_cqp_request(iwcqp, false);
	if (!cqp_request)
		return -ENOMEM;

	cqp_info = &cqp_request->info;
	memset(cqp_info, 0, sizeof(*cqp_info));
	cqp_info->cqp_cmd = cmd;
	cqp_info->post_sq = 1;
	cqp_info->in.u.cnp.info = *cnp_info;
	cqp_info->in.u.cnp.cqp = cqp;
	cqp_info->in.u.cnp.scratch = (uintptr_t)cqp_request;

	status = nser_handle_cqp_op(rf, cqp_request);
	nser_put_cqp_request(&rf->cqp, cqp_request);

	return status;
}


/**
 * nser_ah_cqp_op - perform an AH cqp operation
 * @rf: RDMA PCI function
 * @sc_ah: address handle
 * @cmd: AH operation
 * @wait: wait if true
 * @callback_fcn: Callback function on CQP op completion
 * @cb_param: parameter for callback function
 *
 * returns errno
 */
int nser_ah_cqp_op(struct nser_pci_f *rf, struct nser_sc_ah *sc_ah, u8 cmd,
		    bool wait,
		    void (*callback_fcn)(struct nser_cqp_request *),
		    void *cb_param)
{
	struct nser_cqp_request *cqp_request;
	struct cqp_cmds_info *cqp_info;
	int status;

	if (cmd != NSER_OP_AH_CREATE && cmd != NSER_OP_AH_DESTROY)
		return -EINVAL;

	cqp_request = nser_alloc_and_get_cqp_request(&rf->cqp, wait);
	if (!cqp_request)
		return -ENOMEM;

	cqp_info = &cqp_request->info;
	cqp_info->cqp_cmd = cmd;
	cqp_info->post_sq = 1;
	if (cmd == NSER_OP_AH_CREATE) {
		cqp_info->in.u.ah_create.info = sc_ah->ah_info;
		cqp_info->in.u.ah_create.scratch = (uintptr_t)cqp_request;
		cqp_info->in.u.ah_create.cqp = &rf->cqp.sc_cqp;
	} else if (cmd == NSER_OP_AH_DESTROY) {
		cqp_info->in.u.ah_destroy.info = sc_ah->ah_info;
		cqp_info->in.u.ah_destroy.scratch = (uintptr_t)cqp_request;
		cqp_info->in.u.ah_destroy.cqp = &rf->cqp.sc_cqp;
	}

	if (!wait) {
		sc_ah->req = cqp_request;
		cqp_request->callback_fcn = callback_fcn;
		cqp_request->param = cb_param;
	}
	status = nser_handle_cqp_op(rf, cqp_request);
	nser_put_cqp_request(&rf->cqp, cqp_request);

	if (status)
		return -ENOMEM;

	if (wait)
		sc_ah->ah_info.ah_valid = (cmd == NSER_OP_AH_CREATE);

	return 0;
}

/**
 * nser_gsi_ud_qp_ah_cb - callback after creation of AH for GSI/ID QP
 * @cqp_request: pointer to cqp_request of create AH
 */
void nser_gsi_ud_qp_ah_cb(struct nser_cqp_request *cqp_request)
{
	struct nser_sc_ah *sc_ah = cqp_request->param;

	if (sc_ah == NULL)
		return;

	if (!cqp_request->compl_info.op_ret_val)
		sc_ah->ah_info.ah_valid = true;
	else
		sc_ah->ah_info.ah_valid = false;
}

/**
 * nser_prm_add_pble_mem - add memory to pble resources
 * @pprm: pble resource manager
 * @pchunk: chunk of memory to add
 */
int nser_prm_add_pble_mem(struct nser_pble_prm *pprm,
			   struct nser_chunk *pchunk)
{
	u64 sizeofbitmap;

	if (pchunk->size & 0xfff)
		return -EINVAL;

	sizeofbitmap = (u64)pchunk->size >> pprm->pble_shift;

	pchunk->bitmapmem.size = sizeofbitmap >> 3;
	pchunk->bitmapmem.va = kzalloc(pchunk->bitmapmem.size, GFP_KERNEL);

	if (!pchunk->bitmapmem.va)
		return -ENOMEM;

	pchunk->bitmapbuf = pchunk->bitmapmem.va;
	bitmap_zero(pchunk->bitmapbuf, sizeofbitmap);

	pchunk->sizeofbitmap = sizeofbitmap;
	/* each pble is 8 bytes hence shift by 3 */
	pprm->total_pble_alloc += pchunk->size >> 3;
	pprm->free_pble_cnt += pchunk->size >> 3;

	return 0;
}

/**
 * nser_prm_get_pbles - get pble's from prm
 * @pprm: pble resource manager
 * @chunkinfo: nformation about chunk where pble's were acquired
 * @mem_size: size of pble memory needed
 * @vaddr: returns virtual address of pble memory
 * @fpm_addr: returns fpm address of pble memory
 */
int nser_prm_get_pbles(struct nser_pble_prm *pprm,
			struct nser_pble_chunkinfo *chunkinfo, u64 mem_size,
			u64 **vaddr, u64 *fpm_addr)
{
	u64 bits_needed;
	u64 bit_idx = PBLE_INVALID_IDX;
	struct nser_chunk *pchunk = NULL;
	struct list_head *chunk_entry = pprm->clist.next;
	u32 offset;
	unsigned long flags;
	*vaddr = NULL;
	*fpm_addr = 0;

	bits_needed = DIV_ROUND_UP_ULL(mem_size, BIT_ULL(pprm->pble_shift));

	spin_lock_irqsave(&pprm->prm_lock, flags);
	while (chunk_entry != &pprm->clist) {
		pchunk = (struct nser_chunk *)chunk_entry;
		bit_idx = bitmap_find_next_zero_area(pchunk->bitmapbuf,
						     pchunk->sizeofbitmap, 0,
						     bits_needed, 0);
		if (bit_idx < pchunk->sizeofbitmap)
			break;

		/* list.next used macro */
		chunk_entry = pchunk->list.next;
	}

	if (!pchunk || bit_idx >= pchunk->sizeofbitmap) {
		spin_unlock_irqrestore(&pprm->prm_lock, flags);
		return -ENOMEM;
	}

	bitmap_set(pchunk->bitmapbuf, bit_idx, bits_needed);
	offset = bit_idx << pprm->pble_shift;
	*vaddr = pchunk->vaddr + offset;
	*fpm_addr = pchunk->fpm_addr + offset;

	chunkinfo->pchunk = pchunk;
	chunkinfo->bit_idx = bit_idx;
	chunkinfo->bits_used = bits_needed;
	/* 3 is sizeof pble divide */
	pprm->free_pble_cnt -= chunkinfo->bits_used << (pprm->pble_shift - 3);
	spin_unlock_irqrestore(&pprm->prm_lock, flags);

	return 0;
}

/**
 * nser_prm_return_pbles - return pbles back to prm
 * @pprm: pble resource manager
 * @chunkinfo: chunk where pble's were acquired and to be freed
 */
void nser_prm_return_pbles(struct nser_pble_prm *pprm,
			    struct nser_pble_chunkinfo *chunkinfo)
{
	unsigned long flags;

	spin_lock_irqsave(&pprm->prm_lock, flags);
	pprm->free_pble_cnt += chunkinfo->bits_used << (pprm->pble_shift - 3);
	bitmap_clear(chunkinfo->pchunk->bitmapbuf, chunkinfo->bit_idx,
		     chunkinfo->bits_used);
	spin_unlock_irqrestore(&pprm->prm_lock, flags);
}

int nser_map_vm_page_list(struct nser_hw *hw, void *va, dma_addr_t *pg_dma,
			   u32 pg_cnt)
{
	struct page *vm_page;
	int i;
	u8 *addr;

	addr = (u8 *)(uintptr_t)va;
	for (i = 0; i < pg_cnt; i++) {
		vm_page = vmalloc_to_page(addr);
		if (!vm_page)
			goto err;

		pg_dma[i] = dma_map_page(hw->device, vm_page, 0, PAGE_SIZE, DMA_BIDIRECTIONAL);
		if (dma_mapping_error(hw->device, pg_dma[i]))
			goto err;

		addr += PAGE_SIZE;
	}

	return 0;

err:
	nser_unmap_vm_page_list(hw, pg_dma, i);
	return -ENOMEM;
}

void nser_unmap_vm_page_list(struct nser_hw *hw, dma_addr_t *pg_dma, u32 pg_cnt)
{
	int i;

	for (i = 0; i < pg_cnt; i++)
		dma_unmap_page(hw->device, pg_dma[i], PAGE_SIZE, DMA_BIDIRECTIONAL);
}

/**
 * nser_pble_free_paged_mem - free virtual paged memory
 * @chunk: chunk to free with paged memory
 */
void nser_pble_free_paged_mem(struct nser_chunk *chunk)
{
	if (!chunk->pg_cnt)
		goto done;

	nser_unmap_vm_page_list(chunk->dev->hw, chunk->dmainfo.dmaaddrs,
				 chunk->pg_cnt);

done:
	kfree(chunk->dmainfo.dmaaddrs);
	chunk->dmainfo.dmaaddrs = NULL;
	vfree(chunk->vaddr);
	chunk->vaddr = NULL;
	chunk->type = 0;
}

/**
 * nser_pble_get_paged_mem -allocate paged memory for pbles
 * @chunk: chunk to add for paged memory
 * @pg_cnt: number of pages needed
 */
int nser_pble_get_paged_mem(struct nser_chunk *chunk, u32 pg_cnt)
{
	u32 size;
	void *va;

	chunk->dmainfo.dmaaddrs = kzalloc(pg_cnt << 3, GFP_KERNEL);
	if (!chunk->dmainfo.dmaaddrs)
		return -ENOMEM;

	size = PAGE_SIZE * pg_cnt;
	va = vmalloc(size);
	if (!va)
		goto err;

	if (nser_map_vm_page_list(chunk->dev->hw, va, chunk->dmainfo.dmaaddrs,
				   pg_cnt)) {
		vfree(va);
		goto err;
	}
	chunk->vaddr = va;
	chunk->size = size;
	chunk->pg_cnt = pg_cnt;
	chunk->type = PBLE_SD_PAGED;

	return 0;
err:
	kfree(chunk->dmainfo.dmaaddrs);
	chunk->dmainfo.dmaaddrs = NULL;

	return -ENOMEM;
}

void nser_update_vf_vlan_cfg(struct nser_sc_dev *dev,
			      struct nser_vfdev *vf_dev)
{
	struct iidc_core_dev_info *cdev_info = dev_to_rf(dev)->cdev;
	struct iidc_vf_port_info port_info = {};

	if (cdev_info->ops->get_vf_info(cdev_info, vf_dev->vf_id, &port_info))
		return;

	vf_dev->port_vlan_en = port_info.port_vlan_id ? true : false;
}

struct nser_sc_vsi *nser_update_vsi_ctx(struct nser_sc_dev *dev,
					  struct nser_vfdev *vf_dev,
					  bool enable)
{
	/* TBD: Add stats */
	struct nser_vsi_init_info vsi_info = {};
	struct nser_l2params l2params = {};
	struct nser_pci_f *rf = dev_to_rf(dev);
	struct nser_sc_vsi *vf_vsi;
	struct iidc_core_dev_info *cdev_info = dev_to_rf(dev)->cdev;

	vf_vsi = vf_dev->vf_vsi;
	if (!vf_vsi && enable) {
		struct iidc_vf_port_info port_info = {};
		struct nser_device *iwdev = rf->iwdev;

		if (cdev_info->ops->get_vf_info(cdev_info, vf_dev->vf_id, &port_info))
			return NULL;

		vf_vsi = kzalloc(sizeof(*vf_vsi), GFP_KERNEL);
		if (!vf_vsi)
			return NULL;

		vf_dev->port_vlan_en = port_info.port_vlan_id ? true : false;
		l2params.up2tc[0] = iwdev->vsi.qos[0].traffic_class;
		l2params.mtu = iwdev->vsi.mtu;
		l2params.num_tc = 1;
		l2params.vsi_rel_bw = iwdev->vsi.qos[0].rel_bw;
		l2params.vsi_prio_type = iwdev->vsi.qos[0].prio_type;

		vsi_info.vm_vf_type = NSER_PF_TYPE;
		vsi_info.dev = dev;
		vsi_info.back_vsi = iwdev;
		vsi_info.params = &l2params;
		vsi_info.pf_data_vsi_num = port_info.vsi_abs_id;
		vsi_info.register_qset = rf->gen_ops.register_qset;
		vsi_info.unregister_qset = rf->gen_ops.unregister_qset;
		nser_sc_vsi_init(vf_vsi, &vsi_info);
	}
	if (!vf_vsi)
		return NULL;
	if (!enable) {
		cdev_info->ops->update_vport_filter(cdev_info, vf_vsi->vsi_idx, false);
		kfree(vf_vsi);
		vf_vsi = NULL;
		vf_dev->vf_vsi = NULL;
	} else {
		cdev_info->ops->update_vport_filter(cdev_info, vf_vsi->vsi_idx, true);
	}

	return vf_vsi;
}

/**
 * nser_alloc_ws_node_id - Allocate a tx scheduler node ID
 * @dev: device pointer
 */
u16 nser_alloc_ws_node_id(struct nser_sc_dev *dev)
{
	struct nser_pci_f *rf = dev_to_rf(dev);
	u32 next = 1;
	u32 node_id;

	if (nser_alloc_rsrc(rf, rf->allocated_ws_nodes, rf->max_ws_node_id,
			     &node_id, &next))
		return NSER_WS_NODE_INVALID;

	return (u16)node_id;
}

/**
 * nser_free_ws_node_id - Free a tx scheduler node ID
 * @dev: device pointer
 * @node_id: Work scheduler node ID
 */
void nser_free_ws_node_id(struct nser_sc_dev *dev, u16 node_id)
{
	struct nser_pci_f *rf = dev_to_rf(dev);

	nser_free_rsrc(rf, rf->allocated_ws_nodes, (u32)node_id);
}

/**
 * nser_modify_qp_to_err - Modify a QP to error
 * @sc_qp: qp structure
 */
void nser_modify_qp_to_err(struct nser_sc_qp *sc_qp)
{
	struct nser_qp *qp = sc_qp->qp_uk.back_qp;
	struct ib_qp_attr attr;

	if (qp->iwdev->rf->reset)
		return;
	attr.qp_state = IB_QPS_ERR;

	nser_modify_qp_roce(&qp->ibqp, &attr, IB_QP_STATE, NULL);
}

void nser_ib_qp_event(struct nser_qp *iwqp, enum nser_qp_event_type event)
{
	struct ib_event ibevent;

	if (!iwqp->ibqp.event_handler)
		return;

	switch (event) {
	case NSER_QP_EVENT_CATASTROPHIC:
		ibevent.event = IB_EVENT_QP_FATAL;
		break;
	case NSER_QP_EVENT_ACCESS_ERR:
		ibevent.event = IB_EVENT_QP_ACCESS_ERR;
		break;
	case NSER_QP_EVENT_REQ_ERR:
		ibevent.event = IB_EVENT_QP_REQ_ERR;
		break;
	}
	ibevent.device = iwqp->ibqp.device;
	ibevent.element.qp = &iwqp->ibqp;
	iwqp->ibqp.event_handler(&ibevent, iwqp->ibqp.qp_context);
}

static void clear_qp_ctx_addr(__le64 *ctx)
{
	u64 tmp;

	get_64bit_val(ctx, 272, &tmp);
	tmp &= GENMASK_ULL(63, 58);
	set_64bit_val(ctx, 272, tmp);

	get_64bit_val(ctx, 296, &tmp);
	tmp &= GENMASK_ULL(7, 0);
	set_64bit_val(ctx, 296, tmp);

	get_64bit_val(ctx, 312, &tmp);
	tmp &= GENMASK_ULL(7, 0);
	set_64bit_val(ctx, 312, tmp);

	set_64bit_val(ctx, 368, 0);
}

/**
 * nser_upload_qp_context - upload raw QP context
 * @iwqp: QP pointer
 * @freeze: freeze QP
 * @raw: raw context flag
 */
int nser_upload_qp_context(struct nser_qp *iwqp, bool freeze, bool raw)
{
	struct nser_dma_mem dma_mem;
	struct nser_sc_dev *dev;
	struct nser_sc_qp *qp;
	struct nser_cqp *iwcqp;
	struct nser_cqp_request *cqp_request;
	struct cqp_cmds_info *cqp_info;
	struct nser_upload_context_info *info;
	struct nser_pci_f *rf;
	int ret;
	u32 *ctx;

	rf = iwqp->iwdev->rf;
	if (!rf)
		return -EINVAL;

	qp = &iwqp->sc_qp;
	dev = &rf->sc_dev;
	iwcqp = &rf->cqp;

	cqp_request = nser_alloc_and_get_cqp_request(iwcqp, true);
	if (!cqp_request)
		return -EINVAL;

	cqp_info = &cqp_request->info;
	info = &cqp_info->in.u.qp_upload_context.info;
	memset(info, 0, sizeof(struct nser_upload_context_info));
	cqp_info->cqp_cmd = NSER_OP_QP_UPLOAD_CONTEXT;
	cqp_info->post_sq = 1;
	cqp_info->in.u.qp_upload_context.dev = dev;
	cqp_info->in.u.qp_upload_context.scratch = (uintptr_t)cqp_request;

	dma_mem.size = ALIGN(PAGE_SIZE, PAGE_SIZE);
	dma_mem.va = dma_alloc_coherent(dev->hw->device, dma_mem.size,
					&dma_mem.pa, GFP_KERNEL);
	if (!dma_mem.va) {
		nser_put_cqp_request(&rf->cqp, cqp_request);
		return -ENOMEM;
	}

	ctx = dma_mem.va;
	info->buf_pa = dma_mem.pa;
	info->raw_format = raw;
	info->freeze_qp = freeze;
	info->qp_type = qp->qp_uk.qp_type;	/* 1 is iWARP and 2 UDA */
	info->qp_id = qp->qp_uk.qp_id;
	ret = nser_handle_cqp_op(rf, cqp_request);
	if (ret)
		goto error;

	nser_dbg(dev, "QP: PRINT CONTXT QP [%d]\n", info->qp_id);
	{
		u32 i, j;

		clear_qp_ctx_addr(dma_mem.va);
		for (i = 0, j = 0; i < 32; i++, j += 4)
			nser_dbg(dev, "QP: %d:\t [%08X %08x %08X %08X]\n",
				  (j * 4), ctx[j], ctx[j + 1], ctx[j + 2],
				  ctx[j + 3]);
	}
error:
	nser_put_cqp_request(iwcqp, cqp_request);
	dma_free_coherent(dev->hw->device, dma_mem.size, dma_mem.va,
			  dma_mem.pa);
	dma_mem.va = NULL;

	return ret;
}

bool nser_cq_empty(struct nser_cq *iwcq)
{
	struct nser_cq_uk *ukcq;
	u64 qword3;
	__le64 *cqe;
	u8 polarity;

	ukcq  = &iwcq->sc_cq.cq_uk;
	cqe = NSER_GET_CURRENT_CQ_ELEM(ukcq);
	get_64bit_val(cqe, 24, &qword3);
	polarity = (u8)FIELD_GET(NSER_CQ_VALID, qword3);

	return polarity != ukcq->polarity;
}

void nser_remove_cmpls_list(struct nser_cq *iwcq)
{
	struct nser_cmpl_gen *cmpl_node;
	struct list_head *tmp_node, *list_node;

	list_for_each_safe(list_node, tmp_node, &iwcq->cmpl_generated) {
		cmpl_node = list_entry(list_node, struct nser_cmpl_gen, list);
		list_del(&cmpl_node->list);
		kfree(cmpl_node);
	}
}

int nser_generated_cmpls(struct nser_cq *iwcq, struct nser_cq_poll_info *cq_poll_info)
{
	struct nser_cmpl_gen *cmpl;

	if (list_empty(&iwcq->cmpl_generated))
		return -ENOENT;
	cmpl = list_first_entry_or_null(&iwcq->cmpl_generated, struct nser_cmpl_gen, list);
	list_del(&cmpl->list);
	memcpy(cq_poll_info, &cmpl->cpi, sizeof(*cq_poll_info));
	kfree(cmpl);

	nser_dbg(iwcq->sc_cq.dev,
		  "VERBS: %s: Poll artificially generated completion for QP 0x%X, op %u, wr_id=0x%llx\n",
		  __func__, cq_poll_info->qp_id, cq_poll_info->op_type,
		  cq_poll_info->wr_id);

	return 0;
}

/**
 * nser_set_cpi_common_values - fill in values for polling info struct
 * @cpi: resulting structure of cq_poll_info type
 * @qp: QPair
 * @qp_num: id of the QP
 */
static void nser_set_cpi_common_values(struct nser_cq_poll_info *cpi,
					struct nser_qp_uk *qp, u32 qp_num)
{
	cpi->comp_status = NSER_COMPL_STATUS_FLUSHED;
	cpi->error = 1;
	cpi->major_err = NSER_FLUSH_MAJOR_ERR;
	cpi->minor_err = FLUSH_GENERAL_ERR;
	cpi->qp_handle = (nser_qp_handle)(uintptr_t)qp;
	cpi->qp_id = qp_num;
}

static inline void nser_comp_handler(struct nser_cq *cq)
{
	if (!cq->ibcq.comp_handler)
		return;

	if (atomic_cmpxchg(&cq->armed, 1, 0))
		cq->ibcq.comp_handler(&cq->ibcq, cq->ibcq.cq_context);
}

static bool qp_has_unpolled_cqes(struct nser_qp *iwqp, struct nser_cq *iwcq)
{
	struct nser_cq_uk *cq = &iwcq->sc_cq.cq_uk;
	struct nser_qp_uk *qp = &iwqp->sc_qp.qp_uk;
	u32 cq_head = NSER_RING_CURRENT_HEAD(cq->cq_ring);
	u64 qword3, comp_ctx;
	__le64 *cqe;
	u8 polarity, cq_polarity;

	cq_polarity = cq->polarity;
	do {
		if (cq->avoid_mem_cflct)
			cqe = ((struct nser_extended_cqe *)(cq->cq_base))[cq_head].buf;
		else
			cqe = cq->cq_base[cq_head].buf;
		get_64bit_val(cqe, 24, &qword3);
		polarity = (u8)FIELD_GET(NSER_CQ_VALID, qword3);

		if (polarity != cq_polarity)
			break;

		/* Ensure CQE contents are read after valid bit is checked */
		dma_rmb();

		get_64bit_val(cqe, 8, &comp_ctx);
		if ((struct nser_qp_uk *)(unsigned long)comp_ctx == qp)
			return true;

		cq_head = (cq_head + 1) % cq->cq_ring.size;
		if (!cq_head)
			cq_polarity ^= 1;
	} while (true);

	return false;
}

/**
 * nser_generate_flush_completions - generate completion from WRs
 * @iwqp: pointer to QP
 */
void nser_generate_flush_completions(struct nser_qp *iwqp)
{
	struct nser_qp_uk *qp = &iwqp->sc_qp.qp_uk;
	struct nser_ring *sq_ring = &qp->sq_ring;
	struct nser_ring *rq_ring = &qp->rq_ring;
	struct nser_cmpl_gen *cmpl;
	__le64 *sw_wqe;
	u64 wqe_qword;
	u32 wqe_idx;
	u8 compl_generated = 0;
	unsigned long flags;

#define SQ_COMPL_GENERATED (0x01)
#define RQ_COMPL_GENERATED (0x02)

	spin_lock_irqsave(&iwqp->iwscq->lock, flags);
	if (!qp_has_unpolled_cqes(iwqp, iwqp->iwscq)) {
		unsigned long flags2;

		spin_lock_irqsave(&iwqp->lock, flags2);
		while (NSER_RING_MORE_WORK(*sq_ring)) {
			cmpl = kzalloc(sizeof(*cmpl), GFP_ATOMIC);
			if (!cmpl) {
				spin_unlock_irqrestore(&iwqp->lock, flags2);
				spin_unlock_irqrestore(&iwqp->iwscq->lock, flags);
				return;
			}

			wqe_idx = sq_ring->tail;
			nser_set_cpi_common_values(&cmpl->cpi, qp, qp->qp_id);

			cmpl->cpi.wr_id = qp->sq_wrtrk_array[wqe_idx].wrid;
			sw_wqe = qp->sq_base[wqe_idx].elem;
			get_64bit_val(sw_wqe, 24, &wqe_qword);
			cmpl->cpi.op_type = (u8)FIELD_GET(NSERQPSQ_OPCODE, wqe_qword);
			cmpl->cpi.q_type = NSER_CQE_QTYPE_SQ;
			/* remove the SQ WR by moving SQ tail*/
			NSER_RING_SET_TAIL(*sq_ring, sq_ring->tail +
							qp->sq_wrtrk_array[sq_ring->tail].quanta);
			if (cmpl->cpi.op_type == NSERQP_OP_NOP) {
				kfree(cmpl);
				continue;
			}
			nser_dbg(iwqp->sc_qp.dev,
				  "DEV: %s: adding wr_id = 0x%llx SQ Completion to list qp_id=%d\n",
				  __func__, cmpl->cpi.wr_id, qp->qp_id);
			list_add_tail(&cmpl->list, &iwqp->iwscq->cmpl_generated);
			compl_generated |= SQ_COMPL_GENERATED;
		}
		spin_unlock_irqrestore(&iwqp->lock, flags2);
		spin_unlock_irqrestore(&iwqp->iwscq->lock, flags);
	} else {
		spin_unlock_irqrestore(&iwqp->iwscq->lock, flags);
		nser_sched_qp_flush_work(iwqp);
	}

	spin_lock_irqsave(&iwqp->iwrcq->lock, flags);
	if (!qp_has_unpolled_cqes(iwqp, iwqp->iwrcq)) {
		unsigned long flags2;

		spin_lock_irqsave(&iwqp->lock, flags2);
		while (NSER_RING_MORE_WORK(*rq_ring)) {
			cmpl = kzalloc(sizeof(*cmpl), GFP_ATOMIC);
			if (!cmpl) {
				spin_unlock_irqrestore(&iwqp->lock, flags2);
				spin_unlock_irqrestore(&iwqp->iwrcq->lock, flags);
				return;
			}

			wqe_idx = rq_ring->tail;
			nser_set_cpi_common_values(&cmpl->cpi, qp, qp->qp_id);

			cmpl->cpi.wr_id = qp->rq_wrid_array[wqe_idx];
			cmpl->cpi.op_type = NSER_OP_TYPE_REC;
			cmpl->cpi.q_type = NSER_CQE_QTYPE_RQ;
			/* remove the RQ WR by moving RQ tail */
			NSER_RING_SET_TAIL(*rq_ring, rq_ring->tail + 1);
			nser_dbg(iwqp->sc_qp.dev,
				  "DEV: %s: adding wr_id = 0x%llx RQ Completion to list qp_id=%d, wqe_idx=%d\n",
				  __func__, cmpl->cpi.wr_id, qp->qp_id,
				  wqe_idx);
			list_add_tail(&cmpl->list, &iwqp->iwrcq->cmpl_generated);

			compl_generated |= RQ_COMPL_GENERATED;
		}
		spin_unlock_irqrestore(&iwqp->lock, flags2);
		spin_unlock_irqrestore(&iwqp->iwrcq->lock, flags);
	} else {
		spin_unlock_irqrestore(&iwqp->iwrcq->lock, flags);
		nser_sched_qp_flush_work(iwqp);
	}

	if (!compl_generated)
		return;
	if (iwqp->iwscq == iwqp->iwrcq) {
		nser_comp_handler(iwqp->iwscq);
	} else {
		if (compl_generated & SQ_COMPL_GENERATED)
			nser_comp_handler(iwqp->iwscq);
		if (compl_generated & RQ_COMPL_GENERATED)
			nser_comp_handler(iwqp->iwrcq);
	}
	nser_dbg(iwqp->sc_qp.dev,
		  "VERBS: 0x%X (SQ 0x1, RQ 0x2, both 0x3) completions generated for QP %d\n",
		  compl_generated, iwqp->ibqp.qp_num);
}

/**
 * nser_copy_ip_ntohl - copy IP address from  network to host
 * @dst: IP address in host order
 * @src: IP address in network order (big endian)
 */
void nser_copy_ip_ntohl(u32 *dst, __be32 *src)
{
	*dst++ = ntohl(*src++);
	*dst++ = ntohl(*src++);
	*dst++ = ntohl(*src++);
	*dst = ntohl(*src);
}

/**
 * nser_copy_ip_htonl - copy IP address from host to network order
 * @dst: IP address in network order (big endian)
 * @src: IP address in host order
 */
void nser_copy_ip_htonl(__be32 *dst, u32 *src)
{
	*dst++ = htonl(*src++);
	*dst++ = htonl(*src++);
	*dst++ = htonl(*src++);
	*dst = htonl(*src);
}

/**
 * nser_ipv4_is_lpb - check if loopback
 * @loc_addr: local addr to compare
 * @rem_addr: remote address
 */
bool nser_ipv4_is_lpb(u32 loc_addr, u32 rem_addr)
{
	return ipv4_is_loopback(htonl(rem_addr)) || (loc_addr == rem_addr);
}

/**
 * nser_ipv6_is_lpb - check if loopback
 * @loc_addr: local addr to compare
 * @rem_addr: remote address
 */
bool nser_ipv6_is_lpb(u32 *loc_addr, u32 *rem_addr)
{
	struct in6_addr raddr6;

	nser_copy_ip_htonl(raddr6.in6_u.u6_addr32, rem_addr);

	return !memcmp(loc_addr, rem_addr, 16) || ipv6_addr_loopback(&raddr6);
}

/**
 * nser_netdev_vlan_ipv6 - Gets the netdev and mac
 * @addr: local IPv6 address
 * @vlan_id: vlan id for the given IPv6 address
 * @mac: mac address for the given IPv6 address
 *
 * Returns the net_device of the IPv6 address and also sets the
 * vlan id and mac for that address.
 */
struct net_device *nser_netdev_vlan_ipv6(u32 *addr, u16 *vlan_id, u8 *mac)
{
	struct net_device *ip_dev = NULL;
	struct in6_addr laddr6;

	if (!IS_ENABLED(CONFIG_IPV6))
		return NULL;

	nser_copy_ip_htonl(laddr6.in6_u.u6_addr32, addr);
	if (vlan_id)
		*vlan_id = 0xFFFF;	/* Match rdma_vlan_dev_vlan_id() */
	if (mac)
		eth_zero_addr(mac);

	rcu_read_lock();
	for_each_netdev_rcu(&init_net, ip_dev) {
		if (ipv6_chk_addr(&init_net, &laddr6, ip_dev, 1)) {
			if (vlan_id)
				*vlan_id = rdma_vlan_dev_vlan_id(ip_dev);
			if (ip_dev->dev_addr && mac)
				ether_addr_copy(mac, ip_dev->dev_addr);
			break;
		}
	}
	rcu_read_unlock();

	return ip_dev;
}

/**
 * nser_get_vlan_ipv4 - Returns the vlan_id for IPv4 address
 * @addr: local IPv4 address
 */
u16 nser_get_vlan_ipv4(u32 *addr)
{
	struct net_device *netdev;
	u16 vlan_id = 0xFFFF;

	netdev = ip_dev_find(&init_net, htonl(addr[0]));
	if (netdev) {
		vlan_id = rdma_vlan_dev_vlan_id(netdev);
		dev_put(netdev);
	}

	return vlan_id;
}
