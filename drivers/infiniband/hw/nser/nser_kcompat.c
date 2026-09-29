// SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB
/* Copyright (c) 2018 - 2022 WangXun Corporation */
#include "main.h"

#define NSER_ROCE_UDP_ENCAP_VALID_PORT_MIN (0xC000)

#define NSERDMA_PF_DB_ADDR_OFFSET	(1024 * 1024)
#define NSERDMA_VF_DB_ADDR_OFFSET	(12  * 1024)


static u16 kc_rdma_flow_label_to_udp_sport(u32 fl)
{
	u32 fl_low = fl & 0x03FFF;
	u32 fl_high = fl & 0xFC000;

	fl_low ^= fl_high >> 14;

	return (u16)(fl_low | NSER_ROCE_UDP_ENCAP_VALID_PORT_MIN);
}

#define NSER_GRH_FLOWLABEL_MASK (0x000FFFFF)

static u32 kc_rdma_calc_flow_label(u32 lqpn, u32 rqpn)
{
	u64 fl = (u64)lqpn * rqpn;

	fl ^= fl >> 20;
	fl ^= fl >> 40;

	return (u32)(fl & NSER_GRH_FLOWLABEL_MASK);
}

u16 kc_rdma_get_udp_sport(u32 fl, u32 lqpn, u32 rqpn)
{
	if (!fl)
		fl = kc_rdma_calc_flow_label(lqpn, rqpn);
	return kc_rdma_flow_label_to_udp_sport(fl);
}

struct dst_entry *nser_get_fl6_dst(struct sockaddr_in6 *src_addr,
				    struct sockaddr_in6 *dst_addr)
{
	struct dst_entry *dst = NULL;
	struct flowi6 fl6 = {};

	fl6.daddr = dst_addr->sin6_addr;
	fl6.saddr = src_addr->sin6_addr;
	if (ipv6_addr_type(&fl6.daddr) & IPV6_ADDR_LINKLOCAL)
		fl6.flowi6_oif = dst_addr->sin6_scope_id;

	dst = ip6_route_output(&init_net, NULL, &fl6);

	return dst;
}

struct neighbour *nser_get_neigh_ipv6(struct dst_entry *dst,
				       struct sockaddr_in6 *dst_ipaddr)
{
	struct neighbour *neigh = NULL;

	neigh = dst_neigh_lookup(dst, dst_ipaddr);
	return neigh;
}

struct neighbour *nser_get_neigh_ipv4(struct rtable *rt, __be32 *dst_ipaddr)
{
	struct neighbour *neigh = NULL;

	neigh = dst_neigh_lookup(&rt->dst, dst_ipaddr);
	return neigh;
}

void nser_get_dev_fw_str(struct ib_device *dev,
			  char *str)
{
	struct nser_device *iwdev = to_iwdev(dev);

	snprintf(str, IB_FW_VERSION_NAME_MAX, "0x%x",
		 nser_fw_ver(&iwdev->rf->sc_dev));
}

/**
 * nser_alloc_mr - register stag for fast memory registration
 * @pd: ibpd pointer
 * @mr_type: memory for stag registrion
 * @max_num_sg: man number of pages
 */
struct ib_mr *nser_alloc_mr(struct ib_pd *pd, enum ib_mr_type mr_type,
			     u32 max_num_sg)
{
	struct nser_device *iwdev = to_iwdev(pd->device);
	struct nser_pble_alloc *palloc;
	struct nser_pbl *iwpbl;
	struct nser_mr *iwmr;
	int status;
	u32 stag;
	int err_code = -ENOMEM;

	iwmr = kzalloc(sizeof(*iwmr), GFP_KERNEL);
	if (!iwmr)
		return ERR_PTR(-ENOMEM);

	stag = nser_create_stag(iwdev);
	if (!stag) {
		err_code = -ENOMEM;
		goto err;
	}

	iwmr->stag = stag;
	iwmr->ibmr.rkey = stag;
	iwmr->ibmr.lkey = stag;
	iwmr->ibmr.pd = pd;
	iwmr->ibmr.device = pd->device;
	iwpbl = &iwmr->iwpbl;
	iwpbl->iwmr = iwmr;
	iwmr->type = NSER_MEMREG_TYPE_MEM;
	palloc = &iwpbl->pble_alloc;
	iwmr->page_cnt = max_num_sg;
	/* Assume system PAGE_SIZE as the sg page sizes are unknown. */
	iwmr->len = max_num_sg * PAGE_SIZE;
	iwmr->page_cnt = round_up(iwmr->len, NSER_HW_PAGE_SIZE)/NSER_HW_PAGE_SIZE;
	status = nser_get_pble(iwdev->rf->pble_rsrc, palloc, iwmr->page_cnt,
				false);
	if (status)
		goto err_get_pble;

	err_code = nser_hw_alloc_stag(iwdev, iwmr);
	if (err_code)
		goto err_alloc_stag;

	iwpbl->pbl_allocated = true;

	return &iwmr->ibmr;
err_alloc_stag:
	nser_free_pble(iwdev->rf->pble_rsrc, palloc);
err_get_pble:
	nser_free_stag(iwdev, stag);
err:
	kfree(iwmr);

	return ERR_PTR(err_code);
}

/**
 * nser_alloc_ucontext - Allocate the user context data structure
 * @uctx: context
 * @udata: user data
 *
 * This keeps track of all objects associated with a particular
 * user-mode client.
 */
int nser_alloc_ucontext(struct ib_ucontext *uctx, struct ib_udata *udata)
{
	struct ib_device *ibdev = uctx->device;
	struct nser_device *iwdev = to_iwdev(ibdev);
	struct nser_alloc_ucontext_req req;
	struct nser_alloc_ucontext_resp uresp = {};
	struct nser_ucontext *ucontext = to_ucontext(uctx);
	struct nser_uk_attrs *uk_attrs;
	u64 bar_off;

	if (ib_copy_from_udata(&req, udata, min(sizeof(req), udata->inlen)))
		return -EINVAL;

	if (req.userspace_ver < 4 || req.userspace_ver > NSER_ABI_VER)
		goto ver_error;

	ucontext->iwdev = iwdev;
	ucontext->abi_ver = req.userspace_ver;

	uk_attrs = &iwdev->rf->sc_dev.hw_attrs.uk_attrs;
	bar_off =
		   (uintptr_t)iwdev->rf->sc_dev.hw_regs[NSER_DB_ADDR_OFFSET];
	ucontext->db_mmap_entry =
		nser_user_mmap_entry_insert(ucontext, bar_off,
						    NSER_MMAP_IO_NC,
						    &uresp.db_mmap_key);
	if (!ucontext->db_mmap_entry)
		return -ENOMEM;

	uresp.kernel_ver = NSER_ABI_VER;
	uresp.feature_flags = uk_attrs->feature_flags;
	uresp.max_hw_wq_frags = uk_attrs->max_hw_wq_frags;
	uresp.max_hw_read_sges = uk_attrs->max_hw_read_sges;
	uresp.max_hw_inline = uk_attrs->max_hw_inline;
	uresp.max_hw_rq_quanta = uk_attrs->max_hw_rq_quanta;
	uresp.max_hw_wq_quanta = uk_attrs->max_hw_wq_quanta;
	uresp.max_hw_sq_chunk = uk_attrs->max_hw_sq_chunk;
	uresp.max_hw_cq_size = uk_attrs->max_hw_cq_size;
	uresp.min_hw_cq_size = uk_attrs->min_hw_cq_size;
	uresp.hw_rev = uk_attrs->hw_rev;

	uresp.timely_ena = iwdev->roce_timely_en;
	if (iwdev->rf->sc_dev.privileged)
		uresp.db_offset = NSERDMA_PF_DB_ADDR_OFFSET % PAGE_SIZE;
	else
		uresp.db_offset = NSERDMA_VF_DB_ADDR_OFFSET % PAGE_SIZE;
	if (ib_copy_to_udata(udata, &uresp,
				    min(sizeof(uresp), udata->outlen))) {
		rdma_user_mmap_entry_remove(ucontext->db_mmap_entry);
		return -EFAULT;
	}

	INIT_LIST_HEAD(&ucontext->cq_reg_mem_list);
	spin_lock_init(&ucontext->cq_reg_mem_list_lock);
	INIT_LIST_HEAD(&ucontext->qp_reg_mem_list);
	spin_lock_init(&ucontext->qp_reg_mem_list_lock);

#ifdef CONFIG_DEBUG_FS
	nser_dbg_save_ucontext(iwdev, ucontext);
#endif
	return 0;

ver_error:
	dev_err(idev_to_dev(&iwdev->rf->sc_dev),
		"Invalid userspace driver version detected. Detected version %d, should be %d\n",
		req.userspace_ver, NSER_ABI_VER);
	return -EINVAL;
}

/**
 * nser_dealloc_ucontext - deallocate the user context data structure
 * @context: user context created during alloc
 */
void nser_dealloc_ucontext(struct ib_ucontext *context)
{
	struct nser_ucontext *ucontext = to_ucontext(context);

	rdma_user_mmap_entry_remove(ucontext->db_mmap_entry);
#ifdef CONFIG_DEBUG_FS
	nser_dbg_free_ucontext(ucontext);
#endif
}

/**
 * nser_alloc_pd - allocate protection domain
 * @pd: protection domain
 * @udata: user data
 */
int nser_alloc_pd(struct ib_pd *pd, struct ib_udata *udata)
{
	struct nser_pd *iwpd = to_iwpd(pd);
	struct nser_device *iwdev = to_iwdev(pd->device);
	struct nser_sc_dev *dev = &iwdev->rf->sc_dev;
	struct nser_pci_f *rf = iwdev->rf;
	struct nser_alloc_pd_resp uresp = {};
	struct nser_sc_pd *sc_pd;
	u32 pd_id = 0;
	int err;

	err = nser_alloc_rsrc(rf, rf->allocated_pds, rf->max_pd, &pd_id, &rf->next_pd);
	if (err)
		return err;

	sc_pd = &iwpd->sc_pd;
	if (udata) {
		struct nser_ucontext *ucontext =
			rdma_udata_to_drv_context(udata, struct nser_ucontext,
						  ibucontext);

		nser_sc_pd_init(dev, sc_pd, pd_id, ucontext->abi_ver);
		uresp.pd_id = pd_id;
		if (ib_copy_to_udata(udata, &uresp,
				     min(sizeof(uresp), udata->outlen))) {
			err = -EFAULT;
			goto error;
		}
	} else {
		nser_sc_pd_init(dev, sc_pd, pd_id, NSER_ABI_VER);
	}

		return 0;

error:

	nser_free_rsrc(rf, rf->allocated_pds, pd_id);

	return err;
}

int nser_dealloc_pd(struct ib_pd *ibpd, struct ib_udata *udata)
{
	struct nser_pd *iwpd = to_iwpd(ibpd);
	struct nser_device *iwdev = to_iwdev(ibpd->device);

	nser_free_rsrc(iwdev->rf, iwdev->rf->allocated_pds, iwpd->sc_pd.pd_id);
	return 0;
}

static void nser_fill_ah_info(struct nser_ah_info *ah_info,
			       const struct ib_gid_attr *sgid_attr,
			       struct sockaddr *sgid_addr, struct sockaddr *dgid_addr,
			       u8 *dmac, u8 net_type)
{
	if (net_type == RDMA_NETWORK_IPV4) {
		ah_info->ipv4_valid = true;
		ah_info->dest_ip_addr[0] =
				ntohl(((struct sockaddr_in *)dgid_addr)->sin_addr.s_addr);
		ah_info->src_ip_addr[0] =
				ntohl(((struct sockaddr_in *)sgid_addr)->sin_addr.s_addr);
		ah_info->do_lpbk = nser_ipv4_is_lpb(ah_info->src_ip_addr[0],
						     ah_info->dest_ip_addr[0]);
		if (ipv4_is_multicast(((struct sockaddr_in *)dgid_addr)->sin_addr.s_addr))
			nser_mcast_mac_v4(ah_info->dest_ip_addr, dmac);
	} else {
		nser_copy_ip_ntohl(ah_info->dest_ip_addr,
				    ((struct sockaddr_in6 *)dgid_addr)->sin6_addr.in6_u.u6_addr32);
		nser_copy_ip_ntohl(ah_info->src_ip_addr,
				    ((struct sockaddr_in6 *)sgid_addr)->sin6_addr.in6_u.u6_addr32);
		ah_info->do_lpbk = nser_ipv6_is_lpb(ah_info->src_ip_addr,
						     ah_info->dest_ip_addr);
		if (rdma_is_multicast_addr(&((struct sockaddr_in6 *)dgid_addr)->sin6_addr))
			nser_mcast_mac_v6(ah_info->dest_ip_addr, dmac);
	}
}

static int nser_create_ah_vlan_tag(struct nser_device *iwdev,
				    struct nser_ah_info *ah_info,
				    const struct ib_gid_attr *sgid_attr,
				    u8 *dmac)
{
	ah_info->dst_arpindex = nser_add_arp(iwdev->rf, ah_info->dest_ip_addr, dmac);

	if (ah_info->dst_arpindex == -1)
		return -EINVAL;

	if (ah_info->vlan_tag >= VLAN_N_VID && iwdev->dcb_vlan_mode)
		ah_info->vlan_tag = 0;

	if (ah_info->vlan_tag < VLAN_N_VID) {
		ah_info->insert_vlan_tag = true;
		ah_info->vlan_tag |=
				rt_tos2priority(ah_info->tc_tos) << VLAN_PRIO_SHIFT;
	}

	if (iwdev->roce_dcqcn_en) {
		ah_info->tc_tos &= ~ECN_CODE_PT_MASK;
		ah_info->tc_tos |= ECN_CODE_PT_VAL;
	}

	return 0;
}

static int nser_create_ah_wait(struct nser_pci_f *rf,
				struct nser_sc_ah *sc_ah, bool sleep)
{
	if (!sleep) {
		int cnt = rf->sc_dev.hw_attrs.max_cqp_compl_wait_time_ms *
			  CQP_TIMEOUT_THRESHOLD;
		if (rf->reset) {
			sc_ah->req->param = NULL;
			return -ETIMEDOUT;
		}

		do {
			nser_cqp_ce_handler(rf, &rf->ccq.sc_cq);
			mdelay(1);
		} while (!sc_ah->ah_info.ah_valid && --cnt);

		if (!cnt) {
			sc_ah->req->param = NULL;
			return -ETIMEDOUT;
		}
	}
	return 0;
}

static bool nser_ah_exists(struct nser_device *iwdev,
			    struct nser_ah *new_ah)
{
	struct nser_ah *ah;
	u32 save_ah_id = new_ah->sc_ah.ah_info.ah_idx;
	u32 key = new_ah->sc_ah.ah_info.dest_ip_addr[0] ^
		  new_ah->sc_ah.ah_info.dest_ip_addr[1] ^
		  new_ah->sc_ah.ah_info.dest_ip_addr[2] ^
		  new_ah->sc_ah.ah_info.dest_ip_addr[3];

	hash_for_each_possible(iwdev->ah_hash_tbl, ah, list, key) {
		/* Set ah_id the same so memcp can work */
		new_ah->sc_ah.ah_info.ah_idx = ah->sc_ah.ah_info.ah_idx;
		if (!memcmp(&ah->sc_ah.ah_info, &new_ah->sc_ah.ah_info,
			    sizeof(ah->sc_ah.ah_info))) {
			refcount_inc(&ah->refcnt);
			new_ah->parent_ah = ah;
			return true;
		}
	}
	new_ah->sc_ah.ah_info.ah_idx = save_ah_id;
	/* Add new AH to list */
	ah = kmemdup(new_ah, sizeof(*new_ah), GFP_KERNEL);
	if (!ah)
		return false;
	new_ah->parent_ah = ah;
	hash_add(iwdev->ah_hash_tbl, &ah->list, key);

	iwdev->ah_list_cnt++;
	if (iwdev->ah_list_cnt > iwdev->ah_list_hwm)
		iwdev->ah_list_hwm = iwdev->ah_list_cnt;
	refcount_set(&ah->refcnt, 1);

	return false;
}

int nser_create_ah_v2(struct ib_ah *ib_ah,
		       struct rdma_ah_attr *attr, u32 flags,
		       struct ib_udata *udata)
{
	struct nser_pd *pd = to_iwpd(ib_ah->pd);
	struct nser_ah *ah = container_of(ib_ah, struct nser_ah, ibah);
	struct nser_device *iwdev = to_iwdev(ib_ah->pd->device);
	const struct ib_gid_attr *sgid_attr;
	struct nser_pci_f *rf = iwdev->rf;
	struct nser_sc_ah *sc_ah;
	u32 ah_id = 0;
	struct nser_ah_info *ah_info;
	struct nser_create_ah_resp uresp;
	union {
		struct sockaddr saddr;
		struct sockaddr_in saddr_in;
		struct sockaddr_in6 saddr_in6;
	} sgid_addr, dgid_addr;
	int err;
	u8 dmac[ETH_ALEN];
	bool sleep = (flags & RDMA_CREATE_AH_SLEEPABLE) != 0;

	err = nser_alloc_rsrc(rf, rf->allocated_ahs,
			       rf->max_ah, &ah_id, &rf->next_ah);

	if (err)
		return err;

	ah->pd = pd;
	sc_ah = &ah->sc_ah;
	sc_ah->ah_info.ah_idx = ah_id;
	sc_ah->ah_info.vsi = &iwdev->vsi;
	nser_sc_init_ah(&rf->sc_dev, sc_ah);
	ah->sgid_index = attr->grh.sgid_index;
	memcpy(&ah->dgid, &attr->grh.dgid, sizeof(ah->dgid));
	sgid_attr = attr->grh.sgid_attr;

	rdma_gid2ip((struct sockaddr *)&sgid_addr, &sgid_attr->gid);
	rdma_gid2ip((struct sockaddr *)&dgid_addr, &attr->grh.dgid);
	ah->av.attrs = *attr;
	ah->av.net_type = kc_rdma_gid_attr_network_type(sgid_attr,
							sgid_attr.gid_type,
							&sgid);

	ah->av.sgid_addr.saddr = sgid_addr.saddr;
	ah->av.dgid_addr.saddr = dgid_addr.saddr;
	ah_info = &sc_ah->ah_info;
	ah_info->ah_idx = ah_id;
	ah_info->pd_idx = pd->sc_pd.pd_id;
	err = rdma_read_gid_l2_fields(sgid_attr, &ah_info->vlan_tag,
				      ah_info->mac_addr);

	if (err)
		goto err_gid_l2;

	if (attr->ah_flags & IB_AH_GRH) {
		ah_info->flow_label = attr->grh.flow_label;
		ah_info->hop_ttl = attr->grh.hop_limit;
		ah_info->tc_tos = attr->grh.traffic_class;
	}

	ether_addr_copy(dmac, attr->roce.dmac);

	nser_fill_ah_info(ah_info, sgid_attr, &sgid_addr.saddr, &dgid_addr.saddr,
			   dmac, ah->av.net_type);

	err = nser_create_ah_vlan_tag(iwdev, ah_info, sgid_attr, dmac);
	if (err)
		goto err_gid_l2;

	if (sleep) {
		mutex_lock(&iwdev->ah_list_lock);
		if (nser_ah_exists(iwdev, ah)) {
			nser_free_rsrc(iwdev->rf, iwdev->rf->allocated_ahs, ah_id);
			ah_id = 0;
#ifdef CONFIG_DEBUG_FS
			iwdev->ah_reused++;
#endif
			goto exit;
		}
	}

	err = nser_ah_cqp_op(iwdev->rf, sc_ah, NSER_OP_AH_CREATE,
			      sleep, nser_gsi_ud_qp_ah_cb, sc_ah);
	if (err) {
		nser_dbg(iwdev_to_idev(iwdev),
			  "VERBS: CQP-OP Create AH fail");
		goto err_ah_create;
	}

	err = nser_create_ah_wait(rf, sc_ah, sleep);
	if (err) {
		nser_dbg(iwdev_to_idev(iwdev),
			  "VERBS: CQP create AH timed out");
		goto err_gid_l2;
	}

exit:
	if (udata) {
		uresp.ah_id = ah->sc_ah.ah_info.ah_idx;
		err = ib_copy_to_udata(udata, &uresp, sizeof(uresp));
		if (err) {
			if (!ah->parent_ah ||
			    (ah->parent_ah && refcount_dec_and_test(&ah->parent_ah->refcnt))) {
				nser_ah_cqp_op(iwdev->rf, &ah->sc_ah,
						NSER_OP_AH_DESTROY, false, NULL, ah);
				ah_id = ah->sc_ah.ah_info.ah_idx;
				goto err_ah_create;
			}
			goto err_unlock;
		}
	}
	if (sleep)
		mutex_unlock(&iwdev->ah_list_lock);
	return 0;
err_ah_create:
	if (ah->parent_ah) {
		hash_del(&ah->parent_ah->list);
		kfree(ah->parent_ah);
		iwdev->ah_list_cnt--;
	}
err_unlock:
	if (sleep)
		mutex_unlock(&iwdev->ah_list_lock);
err_gid_l2:
	if (ah_id)
		nser_free_rsrc(iwdev->rf, iwdev->rf->allocated_ahs, ah_id);

	return err;
}

/**
 * nser_create_ah - create address handle
 * @ibah: ptr to AH
 * @init_attr: address handle attributes
 * @udata: user data
 *
 * returns a pointer to an address handle
 */
int nser_create_ah(struct ib_ah *ibah,
		    struct rdma_ah_init_attr *init_attr,
		    struct ib_udata *udata)
{
	return nser_create_ah_v2(ibah, init_attr->ah_attr, init_attr->flags, udata);
}

/**
 * nser_free_qp_rsrc - free up memory resources for qp
 * @iwqp: qp ptr (user or kernel)
 */
void nser_free_qp_rsrc(struct nser_qp *iwqp)
{
	struct nser_device *iwdev = iwqp->iwdev;
	struct nser_pci_f *rf = iwdev->rf;
	u32 qp_num = iwqp->ibqp.qp_num;

	if (iwqp->sc_qp.vsi) {
		nser_qp_rem_qos(&iwqp->sc_qp);
		iwqp->sc_qp.dev->ws_remove(iwqp->sc_qp.vsi,
					   iwqp->sc_qp.user_pri);
	}

	if (qp_num > 2) {
		if (rf->sc_dev.hw_attrs.uk_attrs.hw_rev == IIDC_RDMA_GEN_AMBER)
			put_qp_id_group(rf, qp_num);
		nser_free_rsrc_with_ts(rf, rf->allocated_qps, qp_num, rf->allocated_qps_ts);
		rf->used_qps -= 1;
	}

	dma_free_coherent(rf->sc_dev.hw->device, iwqp->qp_ctx_mem.size,
			  iwqp->qp_ctx_mem.va, iwqp->qp_ctx_mem.pa);
	iwqp->qp_ctx_mem.va = NULL;
	dma_free_coherent(rf->sc_dev.hw->device, iwqp->kqp.dma_mem.size,
			  iwqp->kqp.dma_mem.va, iwqp->kqp.dma_mem.pa);
	iwqp->kqp.dma_mem.va = NULL;
	kfree(iwqp->kqp.sq_wrid_mem);
	kfree(iwqp->kqp.rq_wrid_mem);
	kfree(iwqp->sg_list);
}

/**
 * nser_create_qp - create qp
 * @ibqp: ptr of qp
 * @init_attr: attributes for qp
 * @udata: user data for create qp
 */
int nser_create_qp(struct ib_qp *ibqp,
		    struct ib_qp_init_attr *init_attr,
		    struct ib_udata *udata)
{
	struct ib_pd *ibpd = ibqp->pd;
	struct nser_pd *iwpd = to_iwpd(ibpd);
	struct nser_device *iwdev = to_iwdev(ibpd->device);
	struct nser_pci_f *rf = iwdev->rf;
	struct nser_qp *iwqp = to_iwqp(ibqp);
	struct nser_create_qp_resp uresp = {};
	u32 qp_num = 0;
	int ret;
	int err_code;
	int sq_size;
	int rq_size;
	struct nser_sc_qp *qp;
	struct nser_sc_dev *dev = &rf->sc_dev;
	struct nser_uk_attrs *uk_attrs = &dev->hw_attrs.uk_attrs;
	struct nser_qp_init_info init_info = {};
	struct nser_qp_host_ctx_info *ctx_info;
	u32 next_qp = 0;
	u32 qp_id_cnt = rf->max_qp;

	err_code = nser_validate_qp_attrs(init_attr, iwdev);
	if (err_code)
		return err_code;

	sq_size = init_attr->cap.max_send_wr;
	rq_size = init_attr->cap.max_recv_wr;

	init_info.vsi = &iwdev->vsi;
	init_info.qp_uk_init_info.uk_attrs = uk_attrs;
	init_info.qp_uk_init_info.sq_size = sq_size;
	init_info.qp_uk_init_info.rq_size = rq_size;
	init_info.qp_uk_init_info.max_sq_frag_cnt = init_attr->cap.max_send_sge;
	init_info.qp_uk_init_info.max_rq_frag_cnt = init_attr->cap.max_recv_sge;
	init_info.qp_uk_init_info.max_inline_data = init_attr->cap.max_inline_data;

	iwqp->sg_list = kcalloc(uk_attrs->max_hw_wq_frags, sizeof(*iwqp->sg_list),
				GFP_KERNEL);
	if (!iwqp->sg_list)
		return -ENOMEM;

	qp = &iwqp->sc_qp;
	qp->qp_uk.back_qp = iwqp;
	qp->qp_uk.lock = &iwqp->lock;

	iwqp->iwdev = iwdev;
	iwqp->qp_ctx_mem.size = ALIGN(NSER_QP_CTX_SIZE,
				      256);
	iwqp->qp_ctx_mem.va = dma_alloc_coherent(dev->hw->device,
						 iwqp->qp_ctx_mem.size,
						 &iwqp->qp_ctx_mem.pa,
						 GFP_KERNEL);
	if (!iwqp->qp_ctx_mem.va) {
		kfree(iwqp->sg_list);
		return -ENOMEM;
	}

	init_info.host_ctx = iwqp->qp_ctx_mem.va;
	init_info.host_ctx_pa = iwqp->qp_ctx_mem.pa;

	if (init_attr->qp_type == IB_QPT_GSI)
		qp_num = 1;
	else {
		if (rf->sc_dev.hw_attrs.uk_attrs.hw_rev == IIDC_RDMA_GEN_AMBER)
			err_code = get_qp_id_group(rf, &next_qp, &qp_id_cnt);

		if (!err_code)
			err_code = nser_alloc_rsrc_with_ts(rf, rf->allocated_qps, qp_id_cnt,
							&qp_num, &next_qp, rf->allocated_qps_ts);
		if (!err_code)
			rf->used_qps += 1;
	}

	if (err_code)
		goto error;

	iwqp->iwpd = iwpd;
	iwqp->ibqp.qp_num = qp_num;
	qp = &iwqp->sc_qp;
	iwqp->iwscq = to_iwcq(init_attr->send_cq);
	iwqp->iwrcq = to_iwcq(init_attr->recv_cq);
	iwqp->host_ctx.va = init_info.host_ctx;
	iwqp->host_ctx.pa = init_info.host_ctx_pa;
	iwqp->host_ctx.size = NSER_QP_CTX_SIZE;

	init_info.pd = &iwpd->sc_pd;
	init_info.qp_uk_init_info.qp_id = iwqp->ibqp.qp_num;
	if (!rdma_protocol_roce(&iwdev->ibdev, 1))
		init_info.qp_uk_init_info.first_sq_wq = 1;
	iwqp->ctx_info.qp_compl_ctx = (uintptr_t)qp;
	init_waitqueue_head(&iwqp->waitq);
	init_waitqueue_head(&iwqp->mod_qp_waitq);

	if (udata) {
		init_info.qp_uk_init_info.abi_ver = iwpd->sc_pd.abi_ver;
		err_code = nser_setup_umode_qp(udata, iwdev, iwqp, &init_info);
	} else {
		INIT_DELAYED_WORK(&iwqp->dwork_flush, nser_flush_worker);
		init_info.qp_uk_init_info.abi_ver = NSER_ABI_VER;
		err_code = nser_setup_kmode_qp(iwdev, iwqp, &init_info, init_attr);
	}

	if (err_code) {
		nser_dbg(iwdev_to_idev(iwdev), "VERBS: setup qp failed\n");
		goto error;
	}

	if (init_attr->qp_type == IB_QPT_RC) {
		init_info.qp_uk_init_info.type = NSER_QP_TYPE_ROCE_RC;
		init_info.qp_uk_init_info.qp_caps = NSER_SEND_WITH_IMM |
							  NSER_WRITE_WITH_IMM |
							  NSER_ROCE;
	} else {
		init_info.qp_uk_init_info.type = NSER_QP_TYPE_ROCE_UD;
		init_info.qp_uk_init_info.qp_caps = NSER_SEND_WITH_IMM |
							    NSER_ROCE;
	}


	ret = nser_sc_qp_init(qp, &init_info);
	if (ret) {
		err_code = -EPROTO;
		nser_dbg(iwdev_to_idev(iwdev), "VERBS: qp_init fail\n");
		goto error;
	}

	ctx_info = &iwqp->ctx_info;
	ctx_info->send_cq_num = iwqp->iwscq->sc_cq.cq_uk.cq_id;
	ctx_info->rcv_cq_num = iwqp->iwrcq->sc_cq.cq_uk.cq_id;

	nser_roce_fill_and_set_qpctx_info(iwqp, ctx_info);
	err_code = nser_cqp_create_qp_cmd(iwqp);
	if (err_code)
		goto error;

	refcount_set(&iwqp->refcnt, 1);
	spin_lock_init(&iwqp->lock);
	iwqp->sig_all = (init_attr->sq_sig_type == IB_SIGNAL_ALL_WR) ? 1 : 0;
	rf->qp_table[qp_num] = iwqp;
	iwqp->max_send_wr = sq_size;
	iwqp->max_recv_wr = rq_size;
	init_completion(&iwqp->free_qp);

	if (dev->ws_add(&iwdev->vsi, 0)) {
		nser_cqp_qp_destroy_cmd(&rf->sc_dev, &iwqp->sc_qp);
		err_code = -EINVAL;
		goto error;
	}
	nser_qp_add_qos(&iwqp->sc_qp);

	if (udata) {
		uresp.actual_sq_size = sq_size;
		uresp.actual_rq_size = rq_size;
		uresp.qp_id = qp_num;
		uresp.qp_caps = qp->qp_uk.qp_caps;

		err_code = ib_copy_to_udata(udata, &uresp,
					    min(sizeof(uresp), udata->outlen));
		if (err_code) {
			nser_dbg(iwdev_to_idev(iwdev),
				  "VERBS: copy_to_udata failed\n");
			kc_nser_destroy_qp(&iwqp->ibqp, udata);
			return err_code;
		}
	}

	return 0;

error:
	nser_free_qp_rsrc(iwqp);

	return err_code;
}

/**
 * nser_destroy_qp - destroy qp
 * @ibqp: qp's ib pointer also to get to device's qp address
 * @udata: user data
 */
int nser_destroy_qp(struct ib_qp *ibqp, struct ib_udata *udata)
{
	struct nser_qp *iwqp = to_iwqp(ibqp);
	struct nser_device *iwdev = iwqp->iwdev;

	if (iwqp->sc_qp.qp_uk.destroy_pending)
		goto free_rsrc;
	iwqp->sc_qp.qp_uk.destroy_pending = true;

	if (iwqp->rdma_state >= NSER_QP_STATE_IDLE)
		nser_modify_qp_to_err(&iwqp->sc_qp);

	if (!iwqp->user_mode) {
		if (iwqp->iwscq) {
			nser_clean_cqes(iwqp, iwqp->iwscq);
			if (iwqp->iwrcq != iwqp->iwscq)
				nser_clean_cqes(iwqp, iwqp->iwrcq);
		}
	}

	nser_qp_rem_ref(&iwqp->ibqp);
	wait_for_completion(&iwqp->free_qp);
	if (!iwdev->rf->reset && nser_cqp_qp_destroy_cmd(&iwdev->rf->sc_dev, &iwqp->sc_qp))
		return iwqp->user_mode ? -ENOTRECOVERABLE : 0;
free_rsrc:
	nser_free_qp_rsrc(iwqp);

	return 0;
}


int nser_create_cq(struct ib_cq *ibcq,
		    const struct ib_cq_init_attr *attr,
		    struct ib_udata *udata)
{
#define NSER_CREATE_CQ_MIN_REQ_LEN offsetofend(struct nser_create_cq_req, user_cq_buf)
#define NSER_CREATE_CQ_MIN_RESP_LEN offsetofend(struct nser_create_cq_resp, cq_size)
	struct ib_device *ibdev = ibcq->device;
	struct nser_device *iwdev = to_iwdev(ibdev);
	struct nser_pci_f *rf = iwdev->rf;
	struct nser_cq *iwcq = to_iwcq(ibcq);
	u32 cq_num = 0;
	struct nser_sc_cq *cq;
	struct nser_sc_dev *dev = &rf->sc_dev;
	struct nser_cq_init_info info = {};
	int status;
	struct nser_cqp_request *cqp_request;
	struct cqp_cmds_info *cqp_info;
	struct nser_cq_uk_init_info *ukinfo = &info.cq_uk_init_info;
	unsigned long flags;
	int err_code;
	int entries = attr->cqe;
	bool cqe_64byte_ena;

	err_code = cq_validate_flags(attr->flags);
	if (err_code)
		return err_code;

	if (udata && (udata->inlen < NSER_CREATE_CQ_MIN_REQ_LEN ||
		      udata->outlen < NSER_CREATE_CQ_MIN_RESP_LEN))
		return -EINVAL;

	err_code = nser_alloc_rsrc_with_ts(rf, rf->allocated_cqs, rf->max_cq, &cq_num,
				    &rf->next_cq, rf->allocated_cqs_ts);
	if (!err_code)
		rf->used_cqs += 1;
	if (err_code)
		return err_code;

	cq = &iwcq->sc_cq;
	cq->back_cq = iwcq;
	refcount_set(&iwcq->refcnt, 1);
	spin_lock_init(&iwcq->lock);
	INIT_LIST_HEAD(&iwcq->resize_list);
	INIT_LIST_HEAD(&iwcq->cmpl_generated);
	info.dev = dev;
	ukinfo->cq_size = max(entries, 4);
	ukinfo->cq_id = cq_num;
	cqe_64byte_ena = (dev->hw_attrs.uk_attrs.feature_flags & NSER_FEATURE_64_BYTE_CQE) ?
					true : false;
	ukinfo->avoid_mem_cflct = cqe_64byte_ena;
	iwcq->ibcq.cqe = info.cq_uk_init_info.cq_size;
	//cq0 occupy comp_vector 0, others cqs occupy non-0 comp_vector
	info.ceq_id = (attr->comp_vector % rf->ceqs_count) == 0 && rf->ceqs_count > 1
					? 1 : rf->ceqs_count == 1 ?
					attr->comp_vector : (attr->comp_vector % rf->ceqs_count);

	info.ceq_id_valid = false;
	info.ceqe_mask = 1;
	info.type = NSER_CQ_TYPE_RDMA;
	info.vsi = &iwdev->vsi;

	if (udata) {
		struct nser_ucontext *ucontext;
		struct nser_create_cq_req req = {};
		struct nser_cq_mr *cqmr;
		struct nser_pbl *iwpbl;
		struct nser_pbl *iwpbl_shadow;
		struct nser_cq_mr *cqmr_shadow;

		iwcq->user_mode = true;
		ucontext = kc_get_ucontext(udata);
		if (ib_copy_from_udata(&req, udata,
				       min(sizeof(req), udata->inlen))) {
			err_code = -EFAULT;
			goto cq_free_rsrc;
		}

		spin_lock_irqsave(&ucontext->cq_reg_mem_list_lock, flags);
		iwpbl = nser_get_pbl((unsigned long)req.user_cq_buf,
				      &ucontext->cq_reg_mem_list);
		spin_unlock_irqrestore(&ucontext->cq_reg_mem_list_lock, flags);
		if (!iwpbl) {
			err_code = -EPROTO;
			goto cq_free_rsrc;
		}
		iwcq->iwpbl = iwpbl;
		iwcq->cq_mem_size = 0;
		cqmr = &iwpbl->cq_mr;

		if (rf->sc_dev.hw_attrs.uk_attrs.feature_flags & NSER_FEATURE_CQ_RESIZE) {
			spin_lock_irqsave(&ucontext->cq_reg_mem_list_lock, flags);
			iwpbl_shadow = nser_get_pbl((unsigned long)req.user_shadow_area,
						     &ucontext->cq_reg_mem_list);
			spin_unlock_irqrestore(&ucontext->cq_reg_mem_list_lock, flags);

			if (!iwpbl_shadow) {
				err_code = -EPROTO;
				goto cq_free_rsrc;
			}
			iwcq->iwpbl_shadow = iwpbl_shadow;
			cqmr_shadow = &iwpbl_shadow->cq_mr;
			info.shadow_area_pa = cqmr_shadow->cq_pbl.addr;
			cqmr->split = true;
		} else {
			info.shadow_area_pa = cqmr->shadow;
		}
		if (iwpbl->pbl_allocated) {
			info.virtual_map = true;
			info.pbl_chunk_size = 1;
			info.first_pm_pbl_idx = cqmr->cq_pbl.idx;
		} else {
			info.cq_base_pa = cqmr->cq_pbl.addr;
		}
	} else {
		/* Kmode allocations */
		int rsize;

		if (entries < 1 || entries > rf->max_cqe) {
			err_code = -EINVAL;
			goto cq_free_rsrc;
		}

		entries++;
		if (!cqe_64byte_ena)
			entries *= 2;
		if (entries & 1)
			entries += 1; /* cq size must be an even number */
		ukinfo->cq_size = entries;

		if (cqe_64byte_ena)
			rsize = info.cq_uk_init_info.cq_size * sizeof(struct nser_extended_cqe);
		else
			rsize = info.cq_uk_init_info.cq_size * sizeof(struct nser_cqe);
		iwcq->kmem.size = ALIGN(round_up(rsize, NSER_HW_PAGE_SIZE),
					NSER_HW_PAGE_SIZE);
		iwcq->kmem.va = dma_alloc_coherent(dev->hw->device,
						   iwcq->kmem.size,
						   &iwcq->kmem.pa, GFP_KERNEL);
		if (!iwcq->kmem.va) {
			err_code = -ENOMEM;
			goto cq_free_rsrc;
		}

		iwcq->kmem_shadow.size = ALIGN(NSER_SHADOW_AREA_SIZE << 3,
					       64);
		iwcq->kmem_shadow.va = dma_alloc_coherent(dev->hw->device,
							  iwcq->kmem_shadow.size,
							  &iwcq->kmem_shadow.pa,
							  GFP_KERNEL);

		if (!iwcq->kmem_shadow.va) {
			err_code = -ENOMEM;
			goto cq_free_rsrc;
		}
		info.shadow_area_pa = iwcq->kmem_shadow.pa;
		ukinfo->shadow_area = iwcq->kmem_shadow.va;
		ukinfo->cq_base = iwcq->kmem.va;
		info.cq_base_pa = iwcq->kmem.pa;
	}

	info.shadow_read_threshold = min(info.cq_uk_init_info.cq_size / 2,
						 (u32)NSER_MAX_CQ_READ_THRESH);
	if (nser_sc_cq_init(cq, &info)) {
		nser_dbg(iwdev_to_idev(iwdev), "VERBS: init cq fail\n");
		err_code = -EPROTO;
		goto cq_free_rsrc;
	}

	cqp_request = nser_alloc_and_get_cqp_request(&rf->cqp, true);
	if (!cqp_request) {
		err_code = -ENOMEM;
		goto cq_free_rsrc;
	}
	cqp_info = &cqp_request->info;
	cqp_info->cqp_cmd = NSER_OP_CQ_CREATE;
	cqp_info->post_sq = 1;
	cqp_info->in.u.cq_create.cq = cq;
	cqp_info->in.u.cq_create.check_overflow = true;
	cqp_info->in.u.cq_create.scratch = (uintptr_t)cqp_request;
	status = nser_handle_cqp_op(rf, cqp_request);
	nser_put_cqp_request(&rf->cqp, cqp_request);
	if (status) {
		err_code = -ENOMEM;
		goto cq_free_rsrc;
	}

	if (udata) {
		struct nser_create_cq_resp resp = {};

		resp.cq_id = info.cq_uk_init_info.cq_id;
		resp.cq_size = info.cq_uk_init_info.cq_size;
		if (ib_copy_to_udata(udata, &resp,
				     min(sizeof(resp), udata->outlen))) {
			nser_dbg(iwdev_to_idev(iwdev),
				  "VERBS: copy to user data\n");
			err_code = -EPROTO;
			goto cq_destroy;
		}
	}

	iwcq->ceq_id_valid_flag = false;
	rf->cq_table[cq_num] = iwcq;
	init_completion(&iwcq->free_cq);

	return 0;

cq_destroy:
	nser_cq_wq_destroy(rf, cq);
cq_free_rsrc:
	nser_cq_free_rsrc(rf, iwcq);
	return err_code;
}

/**
 * nser_destroy_ah - Destroy address handle
 * @ibah: pointer to address handle
 * @ah_flags: destroy flags
 */
int nser_destroy_ah(struct ib_ah *ibah, u32 ah_flags)
{
	struct nser_device *iwdev = to_iwdev(ibah->device);
	struct nser_ah *ah = to_iwah(ibah);

	if (ah->parent_ah) {
		mutex_lock(&iwdev->ah_list_lock);
		if (!refcount_dec_and_test(&ah->parent_ah->refcnt)) {
			mutex_unlock(&iwdev->ah_list_lock);
			return 0;
		}
		hash_del(&ah->parent_ah->list);
		kfree(ah->parent_ah);
		iwdev->ah_list_cnt--;
		mutex_unlock(&iwdev->ah_list_lock);
	}
	nser_ah_cqp_op(iwdev->rf, &ah->sc_ah, NSER_OP_AH_DESTROY,
			false, NULL, ah);

	nser_free_rsrc(iwdev->rf, iwdev->rf->allocated_ahs,
			ah->sc_ah.ah_info.ah_idx);

	return 0;
}

int nser_dereg_mr(struct ib_mr *ib_mr, struct ib_udata *udata)
{
	struct nser_mr *iwmr = to_iwmr(ib_mr);
	struct nser_device *iwdev = to_iwdev(ib_mr->device);
	struct nser_pbl *iwpbl = &iwmr->iwpbl;
	int ret;

	if (iwmr->type != NSER_MEMREG_TYPE_MEM) {
		if (iwmr->region) {
			struct nser_ucontext *ucontext;

			ucontext = rdma_udata_to_drv_context(udata,
							     struct nser_ucontext,
							     ibucontext);
			nser_del_memlist(iwmr, ucontext);
		}
		goto done;
	}

	ret = nser_hwdereg_mr(ib_mr);
	if (ret)
		return ret;

	nser_free_stag(iwdev, iwmr->stag);
done:
	if (iwpbl->pbl_allocated)
		nser_free_pble(iwdev->rf->pble_rsrc, &iwpbl->pble_alloc);

	if (iwmr->region)
		ib_umem_release(iwmr->region);

	kfree(iwmr);

	return 0;
}

/*
 *  nser_rereg_user_mr - Re-Register a user memory region
 *  @ibmr: ib mem to access iwarp mr pointer
 *  @flags: bit mask to indicate which of the attr's of MR modified
 *  @start: virtual start address
 *  @len: length of mr
 *  @virt: virtual address
 *  @new access flags: bit mask of access flags
 *  @new_pd: ptr of pd
 *  @udata: user data
 *
 *  Return:
 *  NULL - Success, existing MR updated
 *  ERR_PTR - error occurred
 */
struct ib_mr *nser_rereg_user_mr(struct ib_mr *ib_mr, int flags, u64 start,
				  u64 len, u64 virt, int new_access,
				  struct ib_pd *new_pd,
				  struct ib_udata *udata)
{
	struct nser_device *iwdev = to_iwdev(ib_mr->device);
	struct nser_mr *iwmr = to_iwmr(ib_mr);
	struct nser_pbl *iwpbl = &iwmr->iwpbl;
	int ret;

	if (len > iwdev->rf->sc_dev.hw_attrs.max_mr_size)
		return ERR_PTR(-EINVAL);

	if (flags & ~(IB_MR_REREG_TRANS | IB_MR_REREG_PD | IB_MR_REREG_ACCESS))
		return ERR_PTR(-EOPNOTSUPP);

	ret = nser_hwdereg_mr(ib_mr);
	if (ret)
		return ERR_PTR(ret);

	if (flags & IB_MR_REREG_ACCESS)
		iwmr->access = new_access;

	if (flags & IB_MR_REREG_PD) {
		iwmr->ibmr.pd = new_pd;
		iwmr->ibmr.device = new_pd->device;
	}

	if (flags & IB_MR_REREG_TRANS) {
		if (iwpbl->pbl_allocated) {
			nser_free_pble(iwdev->rf->pble_rsrc,
					&iwpbl->pble_alloc);
			iwpbl->pbl_allocated = false;
		}
		if (iwmr->region) {
			ib_umem_release(iwmr->region);
			iwmr->region = NULL;
		}

		ib_mr = nser_rereg_mr_trans(iwmr, start, len, virt, udata);
		if (IS_ERR(ib_mr))
			return ib_mr;
	} else {
		ret = nser_hwreg_mr(iwdev, iwmr, iwmr->access);
		if (ret)
			return ERR_PTR(ret);
	}

	return NULL;
}

/**
 * nser_reg_user_mr_dmabuf - register dma-buf based memory region
 * @pd: ibpd pointer
 * @start: offset
 * @len: size of memory to register
 * @virt: virtual address of memory to register
 * @fd: fd associated with dma_buf
 * @access: access rights
 * @udata: user data
 */
struct ib_mr *nser_reg_user_mr_dmabuf(struct ib_pd *pd, u64 start, u64 len,
				       u64 virt, int fd, int access,
				       struct ib_udata *udata)
{
	struct nser_device *iwdev = to_iwdev(pd->device);
	struct ib_umem_dmabuf *umem_dmabuf;
	struct nser_mr *iwmr;
	int err;

	if (len > iwdev->rf->sc_dev.hw_attrs.max_mr_size)
		return ERR_PTR(-EINVAL);

	umem_dmabuf = ib_umem_dmabuf_get_pinned(pd->device, start, len, fd, access);
	if (IS_ERR(umem_dmabuf)) {
		err = PTR_ERR(umem_dmabuf);
		ibdev_dbg(&iwdev->ibdev, "Failed to get dmabuf umem[%d]\n", err);
		return ERR_PTR(err);
	}

	iwmr = nser_alloc_iwmr(&umem_dmabuf->umem, pd, virt, NSER_MEMREG_TYPE_MEM);
	if (IS_ERR(iwmr)) {
		err = PTR_ERR(iwmr);
		goto err_release;
	}

	err = nser_reg_user_mr_type_mem(iwmr, access, true);
	if (err)
		goto err_iwmr;

	return &iwmr->ibmr;

err_iwmr:
	nser_free_iwmr(iwmr);

err_release:
	ib_umem_release(&umem_dmabuf->umem);

	return ERR_PTR(err);
}

int kc_nser_set_roce_cm_info(struct nser_qp *iwqp, struct ib_qp_attr *attr,
			      u16 *vlan_id)
{
	const struct ib_gid_attr *sgid_attr;
	int ret;
	struct nser_av *av = &iwqp->roce_ah.av;

	sgid_attr = attr->ah_attr.grh.sgid_attr;
	if (kc_deref_sgid_attr(sgid_attr)) {
		ret = rdma_read_gid_l2_fields(sgid_attr, vlan_id,
					      iwqp->ctx_info.roce_info->mac_addr);
		if (ret)
			return ret;
	}

	av->net_type = kc_rdma_gid_attr_network_type(sgid_attr,
						     sgid_attr->gid_type,
						     &sgid);

	rdma_gid2ip((struct sockaddr *)&av->sgid_addr, &sgid_attr->gid);
	return 0;
}

/**
 * nser_destroy_cq - destroy cq
 * @ib_cq: cq pointer
 * @udata: user data
 */
int nser_destroy_cq(struct ib_cq *ib_cq, struct ib_udata *udata)
{
	struct nser_device *iwdev = to_iwdev(ib_cq->device);
	struct nser_cq *iwcq = to_iwcq(ib_cq);
	struct nser_sc_cq *cq = &iwcq->sc_cq;
	struct nser_sc_dev *dev = cq->dev;
	struct nser_sc_ceq *ceq = dev->ceq[cq->ceq_id];
	struct nser_ceq *iwceq = container_of(ceq, struct nser_ceq, sc_ceq);
	unsigned long flags;

	spin_lock_irqsave(&iwcq->lock, flags);
	if (!list_empty(&iwcq->cmpl_generated))
		nser_remove_cmpls_list(iwcq);
	if (!list_empty(&iwcq->resize_list))
		nser_process_resize_list(iwcq, iwdev, NULL);
	spin_unlock_irqrestore(&iwcq->lock, flags);

	nser_cq_rem_ref(ib_cq);
	wait_for_completion(&iwcq->free_cq);

	nser_cq_wq_destroy(iwdev->rf, cq);

	spin_lock_irqsave(&iwceq->ce_lock, flags);
	nser_sc_cleanup_ceqes(cq, ceq);
	spin_unlock_irqrestore(&iwceq->ce_lock, flags);
	nser_cq_free_rsrc(iwdev->rf, iwcq);

	return 0;
}

/**
 * nser_alloc_mw - Allocate memory window
 * @ibmw: Memory Window
 * @udata: user data pointer
 */
int nser_alloc_mw(struct ib_mw *ibmw, struct ib_udata *udata)
{
	struct nser_device *iwdev = to_iwdev(ibmw->device);
	struct nser_mr *iwmr = to_iwmw(ibmw);
	int err_code;
	u32 stag;

	/* This is required for Linux kernels < 5.1, where MW type
	 * is not validated in ib_uverbs_alloc_mw function.
	 */
	if (ibmw->type != IB_MW_TYPE_1 && ibmw->type != IB_MW_TYPE_2)
		return -EINVAL;

	stag = nser_create_stag(iwdev);
	if (!stag)
		return -ENOMEM;

	iwmr->stag = stag;
	ibmw->rkey = stag;

	err_code = nser_hw_alloc_mw(iwdev, iwmr);
	if (err_code) {
		nser_free_stag(iwdev, stag);
		return err_code;
	}

	return 0;
}

/**
 * nser_disassociate_ucontext - Disassociate user context
 * @context: ib user context
 */
void nser_disassociate_ucontext(struct ib_ucontext *context)
{
}

/**
 * nser_query_gid_roce - Query port GID for Roce
 * @ibdev: device pointer from stack
 * @port: port number
 * @index: Entry index
 * @gid: Global ID
 */
int nser_query_gid_roce(struct ib_device *ibdev, u32 port, int index,
				union ib_gid *gid)
{
	int ret;

	ret = rdma_query_gid(ibdev, port, index, gid);
	if (ret == -EAGAIN) {
		memcpy(gid, &zgid, sizeof(*gid));
		return 0;
	}

	return ret;
}

/**
 * nser_modify_port - modify port attributes
 * @ibdev: device pointer from stack
 * @port: port number for query
 * @mask: Property mask
 * @props: returning device attributes
 */
int nser_modify_port(struct ib_device *ibdev, u32 port, int mask,
		      struct ib_port_modify *props)
{
	if (port > 1)
		return -EINVAL;

	return 0;
}

/**
 * nser_query_pkey - Query partition key
 * @ibdev: device pointer from stack
 * @port: port number
 * @index: index of pkey
 * @pkey: pointer to store the pkey
 */
int nser_query_pkey(struct ib_device *ibdev, u32 port, u16 index,
		     u16 *pkey)
{
	if (index >= NSER_PKEY_TBL_SZ)
		return -EINVAL;

	*pkey = NSER_DEFAULT_PKEY;
	return 0;
}

int nser_roce_port_immutable(struct ib_device *ibdev, u32 port_num,
			      struct ib_port_immutable *immutable)
{
	struct ib_port_attr attr;
	int err;

	immutable->core_cap_flags = RDMA_CORE_PORT_IBA_ROCE_UDP_ENCAP;
	err = ib_query_port(ibdev, port_num, &attr);
	if (err)
		return err;

	immutable->max_mad_size = IB_MGMT_MAD_SIZE;
	immutable->pkey_tbl_len = attr.pkey_tbl_len;
	immutable->gid_tbl_len = attr.gid_tbl_len;

	return 0;
}

/**
 * nser_query_port - get port attributes
 * @ibdev: device pointer from stack
 * @port: port number for query
 * @props: returning device attributes
 */
int nser_query_port(struct ib_device *ibdev, u32 port,
		     struct ib_port_attr *props)
{
	struct nser_device *iwdev = to_iwdev(ibdev);
	struct net_device *netdev = iwdev->netdev;

	/* no need to zero out pros here. done by caller */

	props->max_mtu = IB_MTU_4096;
	props->active_mtu = ib_mtu_int_to_enum(netdev->mtu);
	props->lid = 1;
	props->lmc = 0;
	props->sm_lid = 0;
	props->sm_sl = 0;
	if (netif_carrier_ok(netdev) && netif_running(netdev)) {
		props->state = IB_PORT_ACTIVE;
		props->phys_state = IB_PORT_PHYS_STATE_LINK_UP;
	} else {
		props->state = IB_PORT_DOWN;
		props->phys_state = IB_PORT_PHYS_STATE_DISABLED;
	}
	ib_get_eth_speed(ibdev, port, &props->active_speed, &props->active_width);

	props->gid_tbl_len = 32;
	kc_set_props_ip_gid_caps(props);
	props->pkey_tbl_len = NSER_PKEY_TBL_SZ;

	props->qkey_viol_cntr = 0;
	props->port_cap_flags |= IB_PORT_CM_SUP | IB_PORT_REINIT_SUP;
	props->max_msg_sz = iwdev->rf->sc_dev.hw_attrs.max_hw_outbound_msg_size;

	return 0;
}

extern const struct rdma_stat_desc nser_hw_stat_descs[];

/**
 * nser_alloc_hw_port_stats - Allocate a hw stats structure
 * @ibdev: device pointer from stack
 * @port_num: port number
 */
struct rdma_hw_stats *nser_alloc_hw_port_stats(struct ib_device *ibdev,
						u32 port_num)
{
	struct nser_device *iwdev = to_iwdev(ibdev);
	struct nser_sc_dev *dev = &iwdev->rf->sc_dev;

	int num_counters = dev->hw_attrs.max_stat_idx;
	unsigned long lifespan = RDMA_HW_STATS_DEFAULT_LIFESPAN;

	/*
	 * PFs get the default update lifespan, but VFs only update once
	 * per second
	 */
	if (!dev->privileged)
		lifespan = 1000;

	return rdma_alloc_hw_stats_struct(nser_hw_stat_descs, num_counters,
					  lifespan);
}

/**
 * nser_get_hw_stats - Populates the rdma_hw_stats structure
 * @ibdev: device pointer from stack
 * @stats: stats pointer from stack
 * @port_num: port number
 * @index: which hw counter the stack is requesting we update
 */
int nser_get_hw_stats(struct ib_device *ibdev,
		       struct rdma_hw_stats *stats, u32 port_num,
		       int index)
{
	struct nser_device *iwdev = to_iwdev(ibdev);
	struct nser_dev_hw_stats *hw_stats = &iwdev->vsi.pestat->hw_stats;

	nser_cqp_gather_stats_cmd(&iwdev->rf->sc_dev, iwdev->vsi.pestat, true);

	memcpy(&stats->value[0], hw_stats, sizeof(u64) * stats->num_counters);

	return stats->num_counters;
}

/**
 * nser_query_gid - Query port GID
 * @ibdev: device pointer from stack
 * @port: port number
 * @index: Entry index
 * @gid: Global ID
 */
int nser_query_gid(struct ib_device *ibdev, u32 port, int index,
		    union ib_gid *gid)
{
	struct nser_device *iwdev = to_iwdev(ibdev);

	memset(gid->raw, 0, sizeof(gid->raw));
	ether_addr_copy(gid->raw, iwdev->netdev->dev_addr);

	return 0;
}

enum rdma_link_layer nser_get_link_layer(struct ib_device *ibdev,
					  u32 port_num)
{
	return IB_LINK_LAYER_ETHERNET;
}

void nser_release_ib_devname(struct nser_device *iwdev)
{
}

char *nser_set_ib_devname(struct nser_device *iwdev)
{
	const char *name = iwdev->is_lag ? "nser_bond%d" : "nser%d";

	strscpy(iwdev->ib_devname, name, sizeof(iwdev->ib_devname));

	return iwdev->ib_devname;
}
