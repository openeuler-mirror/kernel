// SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB
/* Copyright (c) 2015 - 2022 WangXun Corporation */
#include "main.h"

/**
 * nser_query_device - get device attributes
 * @ibdev: device pointer from stack
 * @props: returning device attributes
 * @udata: user data
 */
static int nser_query_device(struct ib_device *ibdev,
			      struct ib_device_attr *props,
			      struct ib_udata *udata)
{
	struct nser_device *iwdev = to_iwdev(ibdev);
	struct nser_pci_f *rf = iwdev->rf;
	struct pci_dev *pcidev = iwdev->rf->pcidev;
	struct nser_hw_attrs *hw_attrs = &rf->sc_dev.hw_attrs;

	if (udata->inlen || udata->outlen)
		return -EINVAL;

	memset(props, 0, sizeof(*props));
	addrconf_addr_eui48((u8 *)&props->sys_image_guid,
			    iwdev->netdev->dev_addr);
	props->fw_ver = (u64)nser_fw_ver(&rf->sc_dev);
	props->device_cap_flags = iwdev->device_cap_flags;
	props->vendor_id = pcidev->vendor;
	props->vendor_part_id = pcidev->device;
	props->hw_ver = pcidev->revision;
	props->page_size_cap = hw_attrs->page_size_cap;
	props->max_mr_size = hw_attrs->max_mr_size;
	props->max_qp = rf->max_qp - rf->used_qps;
	props->max_qp_wr = hw_attrs->max_qp_wr;
	set_max_sge(props, rf);
	props->max_cq = rf->max_cq - rf->used_cqs;
	props->max_cqe = rf->max_cqe - 1;
	props->max_mr = rf->max_mr - rf->used_mrs;
	props->max_mw = props->max_mr;
	props->max_pd = rf->max_pd - rf->used_pds;
	props->max_sge_rd = hw_attrs->uk_attrs.max_hw_read_sges;
	props->max_qp_rd_atom = hw_attrs->max_hw_ird;
	props->max_qp_init_rd_atom = hw_attrs->max_hw_ord;
	props->max_pkeys = NSER_PKEY_TBL_SZ;
	props->max_ah = rf->max_ah;
	props->max_mcast_grp = rf->max_mcg;
	props->max_mcast_qp_attach = NSER_MAX_MGS_PER_CTX;
	props->max_total_mcast_qp_attach = rf->max_mcg * NSER_MAX_MGS_PER_CTX;
	props->max_fast_reg_page_list_len = NSER_MAX_PAGES_PER_FMR;

	if (hw_attrs->uk_attrs.feature_flags & NSER_FEATURE_ATOMIC_OPS)
		props->atomic_cap = IB_ATOMIC_HCA;
	else
		props->atomic_cap = IB_ATOMIC_NONE;
	props->masked_atomic_cap = props->atomic_cap;

	return 0;
}

static void nser_mmap_free(struct rdma_user_mmap_entry *rdma_entry)
{
	struct nser_user_mmap_entry *entry = to_nser_mmap_entry(rdma_entry);

	kfree(entry);
}

struct rdma_user_mmap_entry*
nser_user_mmap_entry_insert(struct nser_ucontext *ucontext, u64 bar_offset,
			     enum nser_mmap_flag mmap_flag, u64 *mmap_offset)
{
	struct nser_user_mmap_entry *entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	int ret;

	if (!entry)
		return NULL;

	entry->bar_offset = bar_offset;
	entry->mmap_flag = mmap_flag;

	ret = rdma_user_mmap_entry_insert(&ucontext->ibucontext,
					  &entry->rdma_entry, PAGE_SIZE);
	if (ret) {
		kfree(entry);
		return NULL;
	}
	*mmap_offset = rdma_user_mmap_get_offset(&entry->rdma_entry);

	return &entry->rdma_entry;
}


/**
 * nser_mmap - user memory map
 * @context: context created during alloc
 * @vma: kernel info for user memory map
 */
static int nser_mmap(struct ib_ucontext *context, struct vm_area_struct *vma)
{
	struct rdma_user_mmap_entry *rdma_entry;
	struct nser_user_mmap_entry *entry;
	struct nser_ucontext *ucontext;
	u64 pfn;
	int ret;

	ucontext = to_ucontext(context);

	rdma_entry = rdma_user_mmap_entry_get(&ucontext->ibucontext, vma);
	if (!rdma_entry) {
		nser_dbg(iwdev_to_idev(ucontext->iwdev),
			  "VERBS: pgoff[0x%lx] does not have valid entry\n",
			  vma->vm_pgoff);
		return -EINVAL;
	}
	entry = to_nser_mmap_entry(rdma_entry);

	nser_dbg(iwdev_to_idev(ucontext->iwdev),
		  "VERBS: bar_offset [0x%llx] mmap_flag [%d]\n",
		  entry->bar_offset, entry->mmap_flag);

	pfn = (entry->bar_offset +
	      pci_resource_start(ucontext->iwdev->rf->pcidev, 0)) >> PAGE_SHIFT;

	switch (entry->mmap_flag) {
	case NSER_MMAP_IO_NC:
		ret = rdma_user_mmap_io(context, vma, pfn, PAGE_SIZE,
					pgprot_noncached(vma->vm_page_prot),
					rdma_entry);
		break;
	case NSER_MMAP_IO_WC:
		ret = rdma_user_mmap_io(context, vma, pfn, PAGE_SIZE,
					pgprot_writecombine(vma->vm_page_prot),
					rdma_entry);
		break;
	default:
		ret = -EINVAL;
	}

	if (ret)
		nser_dbg(iwdev_to_idev(ucontext->iwdev),
			  "VERBS: bar_offset [0x%llx] mmap_flag[%d] err[%d]\n",
			  entry->bar_offset, entry->mmap_flag, ret);
	rdma_user_mmap_entry_put(rdma_entry);

	return ret;
}

/**
 * nser_get_pbl - Retrieve pbl from a list given a virtual
 * address
 * @va: user virtual address
 * @pbl_list: pbl list to search in (QP's or CQ's)
 */
struct nser_pbl *nser_get_pbl(unsigned long va,
				struct list_head *pbl_list)
{
	struct nser_pbl *iwpbl;

	list_for_each_entry(iwpbl, pbl_list, list) {
		if (iwpbl->user_base == va) {
			list_del(&iwpbl->list);
			iwpbl->on_list = false;
			return iwpbl;
		}
	}

	return NULL;
}

/**
 * nser_clean_cqes - clean cq entries for qp
 * @iwqp: qp ptr (user or kernel)
 * @iwcq: cq ptr
 */
void nser_clean_cqes(struct nser_qp *iwqp, struct nser_cq *iwcq)
{
	struct nser_cq_uk *ukcq = &iwcq->sc_cq.cq_uk;
	unsigned long flags;
	struct nser_cmpl_gen *cmpl_node;
	struct list_head *tmp_node, *list_node;

	spin_lock_irqsave(&iwcq->lock, flags);
	nser_uk_clean_cq(&iwqp->sc_qp.qp_uk, ukcq);

	list_for_each_safe(list_node, tmp_node, &iwcq->cmpl_generated) {
		cmpl_node = list_entry(list_node, struct nser_cmpl_gen, list);
		if (cmpl_node->cpi.qp_id == iwqp->ibqp.qp_num) {
			list_del(&cmpl_node->list);
			kfree(cmpl_node);
		}
	}

	spin_unlock_irqrestore(&iwcq->lock, flags);
}

/**
 * nser_setup_virt_qp - setup for allocation of virtual qp
 * @iwdev: nser device
 * @iwqp: qp ptr
 * @init_info: initialize info to return
 */
void nser_setup_virt_qp(struct nser_device *iwdev,
			 struct nser_qp *iwqp,
			 struct nser_qp_init_info *init_info)
{
	struct nser_pbl *iwpbl = iwqp->iwpbl;
	struct nser_qp_mr *qpmr = &iwpbl->qp_mr;

	iwqp->page = qpmr->sq_page;
	init_info->shadow_area_pa = qpmr->shadow;
	if (iwpbl->pbl_allocated) {
		init_info->virtual_map = true;
		init_info->sq_pa = qpmr->sq_pbl.idx;
		init_info->rq_pa = qpmr->rq_pbl.idx;
	} else {
		init_info->sq_pa = qpmr->sq_pbl.addr;
		init_info->rq_pa = qpmr->rq_pbl.addr;
	}
}

/**
 * nser_setup_umode_qp - setup sq and rq size in user mode qp
 * @udata: user data
 * @iwdev: iwarp device
 * @iwqp: qp ptr (user or kernel)
 * @info: initialize info to return
 */
int nser_setup_umode_qp(struct ib_udata *udata,
			 struct nser_device *iwdev,
			 struct nser_qp *iwqp,
			 struct nser_qp_init_info *info)
{
	struct nser_ucontext *ucontext = kc_rdma_udata_to_drv_context(&iwqp->iwpd->ibpd, udata);
	struct nser_create_qp_req req = {};
	unsigned long flags;
	int ret;

	ret = ib_copy_from_udata(&req, udata,
					      min(sizeof(req), udata->inlen));
	if (ret) {
		nser_dbg(iwdev_to_idev(iwdev), "VERBS: ib_copy_from_data fail\n");
		return ret;
	}

	iwqp->ctx_info.qp_compl_ctx = req.user_compl_ctx;
	iwqp->user_mode = 1;
	if (req.user_wqe_bufs) {
		spin_lock_irqsave(&ucontext->qp_reg_mem_list_lock, flags);
		iwqp->iwpbl = nser_get_pbl((unsigned long)req.user_wqe_bufs,
						&ucontext->qp_reg_mem_list);
		spin_unlock_irqrestore(&ucontext->qp_reg_mem_list_lock, flags);

		if (!iwqp->iwpbl) {
			ret = -ENODATA;
			nser_dbg(iwdev_to_idev(iwdev), "VERBS: no pbl info\n");
			return ret;
		}
	}
	nser_setup_virt_qp(iwdev, iwqp, info);

	return 0;
}

/**
 * nser_setup_kmode_qp - setup initialization for kernel mode qp
 * @iwdev: iwarp device
 * @iwqp: qp ptr (user or kernel)
 * @info: initialize info to return
 * @init_attr: Initial QP create attributes
 */
int nser_setup_kmode_qp(struct nser_device *iwdev,
			 struct nser_qp *iwqp,
			 struct nser_qp_init_info *info,
			 struct ib_qp_init_attr *init_attr)
{
	struct nser_dma_mem *mem = &iwqp->kqp.dma_mem;
	u32 sqdepth, rqdepth;
	u8 sqshift, rqshift;
	u32 size;
	int status;
	struct nser_qp_uk_init_info *ukinfo = &info->qp_uk_init_info;
	struct nser_uk_attrs *uk_attrs = &iwdev->rf->sc_dev.hw_attrs.uk_attrs;

	nser_get_wqe_shift(uk_attrs,
		ukinfo->max_sq_frag_cnt + 1,
		ukinfo->max_inline_data, &sqshift);
	status = nser_get_sqdepth(uk_attrs, ukinfo->sq_size, sqshift, &sqdepth);
	if (status)
		return status;

	nser_get_wqe_shift(uk_attrs, ukinfo->max_rq_frag_cnt, 0,
				    &rqshift);

	status = nser_get_rqdepth(uk_attrs, ukinfo->rq_size, rqshift, &rqdepth);
	if (status)
		return status;

	iwqp->kqp.sq_wrid_mem =
		kcalloc(sqdepth, sizeof(*iwqp->kqp.sq_wrid_mem), GFP_KERNEL);
	if (!iwqp->kqp.sq_wrid_mem)
		return -ENOMEM;

	iwqp->kqp.rq_wrid_mem =
		kcalloc(rqdepth, sizeof(*iwqp->kqp.rq_wrid_mem), GFP_KERNEL);
	if (!iwqp->kqp.rq_wrid_mem) {
		kfree(iwqp->kqp.sq_wrid_mem);
		iwqp->kqp.sq_wrid_mem = NULL;
		return -ENOMEM;
	}

	ukinfo->sq_wrtrk_array = iwqp->kqp.sq_wrid_mem;
	ukinfo->rq_wrid_array = iwqp->kqp.rq_wrid_mem;

	size = (sqdepth + rqdepth) * NSER_QP_WQE_MIN_SIZE;
	size += (NSER_QP_SHADOW_AREA_SIZE << 3);

	mem->size = ALIGN(size, 256);
	mem->va = dma_alloc_coherent(iwdev->rf->hw.device, mem->size,
				     &mem->pa, GFP_KERNEL);
	if (!mem->va) {
		kfree(iwqp->kqp.sq_wrid_mem);
		iwqp->kqp.sq_wrid_mem = NULL;
		kfree(iwqp->kqp.rq_wrid_mem);
		iwqp->kqp.rq_wrid_mem = NULL;
		return -ENOMEM;
	}

	ukinfo->sq = mem->va;
	info->sq_pa = mem->pa;
	ukinfo->rq = &ukinfo->sq[sqdepth];
	info->rq_pa = info->sq_pa + (sqdepth * NSER_QP_WQE_MIN_SIZE);
	ukinfo->shadow_area = ukinfo->rq[rqdepth].elem;
	info->shadow_area_pa = info->rq_pa + (rqdepth * NSER_QP_WQE_MIN_SIZE);
	ukinfo->sq_size = sqdepth >> sqshift;
	ukinfo->rq_size = rqdepth >> rqshift;
	ukinfo->qp_id = iwqp->ibqp.qp_num;

	init_attr->cap.max_send_wr = (sqdepth - NSER_SQ_RSVD) >> sqshift;
	init_attr->cap.max_recv_wr = (rqdepth - NSER_RQ_RSVD) >> rqshift;

	return 0;
}

int nser_cqp_create_qp_cmd(struct nser_qp *iwqp)
{
	struct nser_pci_f *rf = iwqp->iwdev->rf;
	struct nser_cqp_request *cqp_request;
	struct cqp_cmds_info *cqp_info;
	struct nser_create_qp_info *qp_info;
	int status;

	cqp_request = nser_alloc_and_get_cqp_request(&rf->cqp, true);
	if (!cqp_request)
		return -ENOMEM;

	cqp_info = &cqp_request->info;
	qp_info = &cqp_request->info.in.u.qp_create.info;
	memset(qp_info, 0, sizeof(*qp_info));
	qp_info->mac_valid = true;
	qp_info->cq_num_valid = true;
	qp_info->next_rdma_state = NSER_QP_STATE_IDLE;

	cqp_info->cqp_cmd = NSER_OP_QP_CREATE;
	cqp_info->post_sq = 1;
	cqp_info->in.u.qp_create.qp = &iwqp->sc_qp;
	cqp_info->in.u.qp_create.scratch = (uintptr_t)cqp_request;
	status = nser_handle_cqp_op(rf, cqp_request);
	nser_put_cqp_request(&rf->cqp, cqp_request);

	return status;
}

void nser_roce_fill_and_set_qpctx_info(struct nser_qp *iwqp,
					struct nser_qp_host_ctx_info *ctx_info)
{
	struct nser_device *iwdev = iwqp->iwdev;
	struct nser_sc_dev *dev = &iwdev->rf->sc_dev;
	struct nser_roce_offload_info *roce_info;
	struct nser_udp_offload_info *udp_info;

	udp_info = &iwqp->udp_info;
	udp_info->snd_mss = ib_mtu_enum_to_int(ib_mtu_int_to_enum(iwdev->vsi.mtu));
	udp_info->cwnd = iwdev->roce_cwnd;
	udp_info->rexmit_thresh = 2;
	udp_info->rnr_nak_thresh = 2;
	udp_info->src_port = 0xc000;
	udp_info->dst_port = ROCE_V2_UDP_DPORT;
	roce_info = &iwqp->roce_info;
	ether_addr_copy(roce_info->mac_addr, iwdev->netdev->dev_addr);

	roce_info->rd_en = true;
	roce_info->wr_rdresp_en = true;
	roce_info->bind_en = true;
	roce_info->rtomin = 14;

#if IS_ENABLED(CONFIG_CONFIGFS_FS)
	roce_info->ecn_en = iwdev->roce_ecn_en;
	roce_info->rcv_no_icrc = iwdev->roce_no_icrc_en;
#endif
	roce_info->dcqcn_en = iwdev->roce_dcqcn_en;
	roce_info->timely_en = iwdev->roce_timely_en;
	if (roce_info->timely_en) {
		roce_info->t_high = iwdev->rf->cc_params.timely_params.timely_thigh;
		roce_info->t_low = iwdev->rf->cc_params.timely_params.timely_tlow;
		roce_info->timely_min_rtt = iwdev->rf->cc_params.timely_params.timely_min_rtt;
	}

	if (roce_info->dcqcn_en) {
		roce_info->dcqcn_alpha = iwdev->rf->cc_params.dcqcn_params.dcqcn_alpha;
		roce_info->dcqcn_recovery_bcnt_period =
			iwdev->rf->cc_params.dcqcn_params.dcqcn_recovery_bcnt_period;
		roce_info->dcqcn_g = iwdev->rf->cc_params.dcqcn_params.dcqcn_g;
		roce_info->dcqcn_rpg_gd = iwdev->rf->cc_params.dcqcn_params.dcqcn_rpg_gd;
		roce_info->dcqcn_clamp_tar_rate =
			iwdev->rf->cc_params.dcqcn_params.dcqcn_clamp_tar_rate;
		roce_info->dcqcn_alpha_period =
			iwdev->rf->cc_params.dcqcn_params.dcqcn_alpha_period;
		roce_info->dcqcn_recovery_time_period =
			iwdev->rf->cc_params.dcqcn_params.dcqcn_recovery_time_period;
		roce_info->dcqcn_tar_work_rate =
			iwdev->rf->cc_params.dcqcn_params.dcqcn_tar_work_rate;
	}

	if (roce_info->timely_en || roce_info->dcqcn_en) {
		roce_info->cc_working_rate = iwdev->rf->cc_params.cc_working_rate;
		roce_info->cc_max_work_rate = iwdev->rf->cc_params.cc_max_work_rate;
		roce_info->cc_min_work_rate = iwdev->rf->cc_params.cc_min_work_rate;
	}

	roce_info->ack_credits = iwdev->roce_ackcreds;
	roce_info->ird_size = dev->hw_attrs.max_hw_ird;
	roce_info->ord_size = dev->hw_attrs.max_hw_ord;

	if (!iwqp->user_mode) {
		roce_info->priv_mode_en = true;
		roce_info->fast_reg_en = true;
		roce_info->udprivcq_en = true;
	}
	roce_info->roce_tver = 0;

	ctx_info->roce_info = &iwqp->roce_info;
	ctx_info->udp_info = &iwqp->udp_info;
	nser_sc_qp_setctx_roce(&iwqp->sc_qp, iwqp->host_ctx.va, ctx_info);
}

int nser_validate_qp_attrs(struct ib_qp_init_attr *init_attr,
			    struct nser_device *iwdev)
{
	struct nser_sc_dev *dev = &iwdev->rf->sc_dev;
	struct nser_uk_attrs *uk_attrs = &dev->hw_attrs.uk_attrs;

	if (init_attr->create_flags)
		return -EOPNOTSUPP;

	if (init_attr->cap.max_inline_data > uk_attrs->max_hw_inline ||
	    init_attr->cap.max_send_wr > uk_attrs->max_hw_wq_quanta ||
	    init_attr->cap.max_recv_wr > uk_attrs->max_hw_rq_quanta ||
	    init_attr->cap.max_send_sge > uk_attrs->max_hw_wq_frags ||
	    init_attr->cap.max_recv_sge > uk_attrs->max_hw_wq_frags)
		return -EINVAL;

	if (rdma_protocol_roce(&iwdev->ibdev, 1)) {
		if (init_attr->qp_type != IB_QPT_RC &&
		    init_attr->qp_type != IB_QPT_UD &&
		    init_attr->qp_type != IB_QPT_GSI)
			return -EOPNOTSUPP;
	} else {
		if (init_attr->qp_type != IB_QPT_RC)
			return -EOPNOTSUPP;
	}

	return 0;
}

void nser_sched_qp_flush_work(struct nser_qp *iwqp)
{
	if (iwqp->sc_qp.qp_uk.destroy_pending)
		return;
	nser_qp_add_ref(&iwqp->ibqp);
	if (mod_delayed_work(iwqp->iwdev->cleanup_wq, &iwqp->dwork_flush,
			     msecs_to_jiffies(NSER_FLUSH_DELAY_MS)))
		nser_qp_rem_ref(&iwqp->ibqp);
}

void nser_flush_worker(struct work_struct *work)
{
	struct delayed_work *dwork = to_delayed_work(work);
	struct nser_qp *iwqp = container_of(dwork, struct nser_qp, dwork_flush);

	nser_generate_flush_completions(iwqp);
	/* For the add in nser_sched_qp_flush_work */
	nser_qp_rem_ref(&iwqp->ibqp);
}

static int nser_get_ib_acc_flags(struct nser_qp *iwqp)
{
	int acc_flags = 0;

	if (iwqp->roce_info.wr_rdresp_en) {
		acc_flags |= IB_ACCESS_LOCAL_WRITE;
		acc_flags |= IB_ACCESS_REMOTE_WRITE;
	}

	if (iwqp->roce_info.rd_en)
		acc_flags |= IB_ACCESS_REMOTE_READ;

	if (iwqp->roce_info.bind_en)
		acc_flags |= IB_ACCESS_MW_BIND;

	return acc_flags;
}

/**
 * nser_query_qp - query qp attributes
 * @ibqp: qp pointer
 * @attr: attributes pointer
 * @attr_mask: Not used
 * @init_attr: qp attributes to return
 */
static int nser_query_qp(struct ib_qp *ibqp, struct ib_qp_attr *attr,
			  int attr_mask, struct ib_qp_init_attr *init_attr)
{
	struct nser_qp *iwqp = to_iwqp(ibqp);
	struct nser_sc_qp *qp = &iwqp->sc_qp;

	memset(attr, 0, sizeof(*attr));
	memset(init_attr, 0, sizeof(*init_attr));

	attr->qp_state = iwqp->ibqp_state;
	attr->cur_qp_state = iwqp->ibqp_state;
	attr->cap.max_send_wr = iwqp->max_send_wr;
	attr->cap.max_recv_wr = iwqp->max_recv_wr;
	attr->cap.max_inline_data = qp->qp_uk.max_inline_data;
	attr->cap.max_send_sge = qp->qp_uk.max_sq_frag_cnt;
	attr->cap.max_recv_sge = qp->qp_uk.max_rq_frag_cnt;
	attr->qp_access_flags = nser_get_ib_acc_flags(iwqp);
	attr->port_num = 1;
	if (rdma_protocol_roce(ibqp->device, 1)) {
		attr->path_mtu = ib_mtu_int_to_enum(iwqp->udp_info.snd_mss);
		attr->qkey = iwqp->roce_info.qkey;
		attr->rq_psn = iwqp->udp_info.epsn;
		attr->sq_psn = iwqp->udp_info.psn_nxt;
		attr->dest_qp_num = iwqp->roce_info.dest_qp;
		attr->pkey_index = iwqp->roce_info.p_key;
		attr->retry_cnt = iwqp->udp_info.rexmit_thresh;
		attr->rnr_retry = iwqp->udp_info.rnr_nak_thresh;
		attr->max_rd_atomic = iwqp->roce_info.ord_size;
		attr->max_dest_rd_atomic = iwqp->roce_info.ird_size;
	}

	init_attr->event_handler = iwqp->ibqp.event_handler;
	init_attr->qp_context = iwqp->ibqp.qp_context;
	init_attr->send_cq = iwqp->ibqp.send_cq;
	init_attr->recv_cq = iwqp->ibqp.recv_cq;
	init_attr->cap = attr->cap;

	return 0;
}

/**
 * nser_modify_qp_roce - modify qp request
 * @ibqp: qp's pointer for modify
 * @attr: access attributes
 * @attr_mask: state mask
 * @udata: user data
 */
int nser_modify_qp_roce(struct ib_qp *ibqp, struct ib_qp_attr *attr,
			 int attr_mask, struct ib_udata *udata)
{
	struct nser_pd *iwpd = to_iwpd(ibqp->pd);
	struct nser_qp *iwqp = to_iwqp(ibqp);
	struct nser_device *iwdev = iwqp->iwdev;
	struct nser_sc_dev *dev;
	struct nser_qp_host_ctx_info *ctx_info;
	struct nser_roce_offload_info *roce_info;
	struct nser_udp_offload_info *udp_info;
	struct nser_modify_qp_info info = {};
	struct nser_modify_qp_resp uresp = {};
	struct nser_modify_qp_req ureq = {};
	unsigned long flags;
	u8 issue_modify_qp = 0;
	int ret = 0;

	dev = &iwdev->rf->sc_dev;

	ctx_info = &iwqp->ctx_info;
	roce_info = &iwqp->roce_info;
	udp_info = &iwqp->udp_info;

	if (attr_mask & ~IB_QP_ATTR_STANDARD_BITS)
		return -EOPNOTSUPP;

	if (attr_mask & IB_QP_DEST_QPN)
		roce_info->dest_qp = attr->dest_qp_num;

	if (attr_mask & IB_QP_PKEY_INDEX) {
		ret = nser_query_pkey(ibqp->device, 0, attr->pkey_index,
				       &roce_info->p_key);
		if (ret)
			return ret;
	}

	if (attr_mask & IB_QP_QKEY)
		roce_info->qkey = attr->qkey;

	if (attr_mask & IB_QP_PATH_MTU)
		udp_info->snd_mss = ib_mtu_enum_to_int(attr->path_mtu);

	if (attr_mask & IB_QP_SQ_PSN) {
		udp_info->psn_nxt = attr->sq_psn;
		udp_info->lsn =  0xffff;
		udp_info->psn_una = attr->sq_psn;
		udp_info->psn_max = attr->sq_psn;
	}

	if (attr_mask & IB_QP_RQ_PSN)
		udp_info->epsn = attr->rq_psn;

	if (attr_mask & IB_QP_RNR_RETRY)
		udp_info->rnr_nak_thresh = attr->rnr_retry;

	if (attr_mask & IB_QP_RETRY_CNT)
		udp_info->rexmit_thresh = attr->retry_cnt;

	if (attr_mask & IB_QP_TIMEOUT)
		roce_info->rtomin = attr->timeout;

	if (attr_mask & IB_QP_MIN_RNR_TIMER)
		udp_info->min_rnr_timer = attr->min_rnr_timer;

	ctx_info->roce_info->pd_id = iwpd->sc_pd.pd_id;

	if (attr_mask & IB_QP_AV) {
		struct nser_av *av = &iwqp->roce_ah.av;
		u16 vlan_id = VLAN_N_VID;
		u32 local_ip[4] = {};

		memset(&iwqp->roce_ah, 0, sizeof(iwqp->roce_ah));
		if (attr->ah_attr.ah_flags & IB_AH_GRH) {
			udp_info->ttl = attr->ah_attr.grh.hop_limit;
			udp_info->flow_label = attr->ah_attr.grh.flow_label;
			udp_info->tos = attr->ah_attr.grh.traffic_class;

			udp_info->src_port = kc_rdma_get_udp_sport(udp_info->flow_label,
								   ibqp->qp_num,
								   roce_info->dest_qp);

			nser_qp_rem_qos(&iwqp->sc_qp);
			dev->ws_remove(iwqp->sc_qp.vsi, ctx_info->user_pri);
			if (iwqp->sc_qp.vsi->dscp_mode)
				ctx_info->user_pri =
					iwqp->sc_qp.vsi->dscp_map[nser_tos2dscp(udp_info->tos)];
			else
				ctx_info->user_pri = rt_tos2priority(udp_info->tos);
			iwqp->sc_qp.user_pri = ctx_info->user_pri;
			if (dev->ws_add(iwqp->sc_qp.vsi, ctx_info->user_pri))
				return -ENOMEM;
			nser_qp_add_qos(&iwqp->sc_qp);
		}
		ret = kc_nser_set_roce_cm_info(iwqp, attr, &vlan_id);
		if (ret)
			return ret;

		if (vlan_id >= VLAN_N_VID && iwdev->dcb_vlan_mode)
			vlan_id = 0;
		if (vlan_id < VLAN_N_VID) {
			udp_info->insert_vlan_tag = true;
			udp_info->vlan_tag = vlan_id |
				ctx_info->user_pri << VLAN_PRIO_SHIFT;
		} else {
			udp_info->insert_vlan_tag = false;
		}

		av->attrs = attr->ah_attr;
		rdma_gid2ip((struct sockaddr *)&av->dgid_addr, &attr->ah_attr.grh.dgid);
		if (av->net_type == RDMA_NETWORK_IPV6) {
			__be32 *daddr =
				av->dgid_addr.saddr_in6.sin6_addr.in6_u.u6_addr32;
			__be32 *saddr =
				av->sgid_addr.saddr_in6.sin6_addr.in6_u.u6_addr32;

			nser_copy_ip_ntohl(&udp_info->dest_ip_addr[0], daddr);
			nser_copy_ip_ntohl(&udp_info->local_ipaddr[0], saddr);

			udp_info->ipv4 = false;
			nser_copy_ip_ntohl(local_ip, daddr);

			udp_info->arp_idx = nser_arp_table(iwdev->rf, local_ip,
							    NULL, NSER_ARP_RESOLVE);
		} else if (av->net_type == RDMA_NETWORK_IPV4) {
			__be32 saddr = av->sgid_addr.saddr_in.sin_addr.s_addr;
			__be32 daddr = av->dgid_addr.saddr_in.sin_addr.s_addr;

			local_ip[0] = ntohl(daddr);

			udp_info->ipv4 = true;
			udp_info->dest_ip_addr[0] = 0;
			udp_info->dest_ip_addr[1] = 0;
			udp_info->dest_ip_addr[2] = 0;
			udp_info->dest_ip_addr[3] = local_ip[0];

			udp_info->local_ipaddr[0] = 0;
			udp_info->local_ipaddr[1] = 0;
			udp_info->local_ipaddr[2] = 0;
			udp_info->local_ipaddr[3] = ntohl(saddr);
		} else {
			return -EINVAL;
		}
		udp_info->arp_idx =
			nser_add_arp(iwdev->rf, local_ip,
				      ah_attr_to_dmac(attr->ah_attr));
	}

	if (attr_mask & IB_QP_MAX_QP_RD_ATOMIC) {
		if (attr->max_rd_atomic > dev->hw_attrs.max_hw_ord) {
			ibdev_err(&iwdev->ibdev,
				  "rd_atomic = %d, above max_hw_ord=%d\n",
				  attr->max_rd_atomic,
				  dev->hw_attrs.max_hw_ord);
			return -EINVAL;
		}
		if (attr->max_rd_atomic)
			roce_info->ord_size = attr->max_rd_atomic;
		info.ord_valid = true;
	}

	if (attr_mask & IB_QP_MAX_DEST_RD_ATOMIC) {
		if (attr->max_dest_rd_atomic > dev->hw_attrs.max_hw_ird) {
			ibdev_err(&iwdev->ibdev,
				  "rd_atomic = %d, above max_hw_ird=%d\n",
				  attr->max_rd_atomic,
				  dev->hw_attrs.max_hw_ird);
			return -EINVAL;
		}
		if (attr->max_dest_rd_atomic)
			roce_info->ird_size = attr->max_dest_rd_atomic;
	}

	if (attr_mask & IB_QP_ACCESS_FLAGS) {
		if (attr->qp_access_flags & IB_ACCESS_LOCAL_WRITE)
			roce_info->wr_rdresp_en = true;
		if (attr->qp_access_flags & IB_ACCESS_REMOTE_WRITE)
			roce_info->wr_rdresp_en = true;
		if (attr->qp_access_flags & IB_ACCESS_REMOTE_READ)
			roce_info->rd_en = true;
		if (dev->hw_attrs.uk_attrs.feature_flags & NSER_FEATURE_ATOMIC_OPS)
			if (attr->qp_access_flags & IB_ACCESS_REMOTE_ATOMIC)
				ctx_info->remote_atomics_en = true;
	}

	wait_event(iwqp->mod_qp_waitq, !atomic_read(&iwqp->hw_mod_qp_pend));

	nser_dbg(dev,
		  "VERBS: caller: %pS qp_id=%d to_ibqpstate=%d ibqpstate=%d nser_qpstate=%d attr_mask=0x%x\n",
		  __builtin_return_address(0), ibqp->qp_num, attr->qp_state,
		  iwqp->ibqp_state, iwqp->rdma_state, attr_mask);
	info.attr_mask = attr_mask;

	spin_lock_irqsave(&iwqp->lock, flags);
	if (attr_mask & IB_QP_STATE) {
		if (!kc_ib_modify_qp_is_ok(iwqp->ibqp_state, attr->qp_state,
					   iwqp->ibqp.qp_type, attr_mask,
					   IB_LINK_LAYER_ETHERNET)) {
			ibdev_warn(&iwdev->ibdev, "modify_qp invalid for qp_id=%d, old_state=0x%x, new_state=0x%x\n",
				   iwqp->ibqp.qp_num, iwqp->ibqp_state,
				   attr->qp_state);
			ret = -EINVAL;
			goto exit;
		}
		info.curr_rdma_state = iwqp->rdma_state;

		switch (attr->qp_state) {
		case IB_QPS_INIT:
			if (iwqp->rdma_state > NSER_QP_STATE_IDLE) {
				ret = -EINVAL;
				goto exit;
			}

			if (iwqp->rdma_state == NSER_QP_STATE_INVALID) {
				info.next_rdma_state = NSER_QP_STATE_IDLE;
				issue_modify_qp = 1;
			}
			break;
		case IB_QPS_RTR:
			if (iwqp->rdma_state > NSER_QP_STATE_IDLE) {
				ret = -EINVAL;
				goto exit;
			}
			info.arp_cache_idx_valid = true;
			info.cq_num_valid = true;
			info.next_rdma_state = NSER_QP_STATE_RTR;
			issue_modify_qp = 1;
			break;
		case IB_QPS_RTS:
			if (iwqp->ibqp_state < IB_QPS_RTR ||
			    iwqp->ibqp_state == IB_QPS_ERR) {
				ret = -EINVAL;
				goto exit;
			}

			info.arp_cache_idx_valid = true;
			info.cq_num_valid = true;
			info.ord_valid = true;
			info.next_rdma_state = NSER_QP_STATE_RTS;
			issue_modify_qp = 1;
			udp_info->cwnd = iwdev->roce_cwnd;
			roce_info->ack_credits = iwdev->roce_ackcreds;
			break;
		case IB_QPS_SQD:
			if (iwqp->rdma_state == NSER_QP_STATE_SQD)
				goto exit;

			if (iwqp->rdma_state != NSER_QP_STATE_RTS) {
				ret = -EINVAL;
				goto exit;
			}

			info.next_rdma_state = NSER_QP_STATE_SQD;
			issue_modify_qp = 1;
			break;
		case IB_QPS_SQE:
		case IB_QPS_ERR:
		case IB_QPS_RESET:
			if (iwqp->rdma_state == NSER_QP_STATE_RTS) {
				nser_cqp_qp_suspend_resume(&iwqp->sc_qp, NSER_OP_SUSPEND);
				spin_unlock_irqrestore(&iwqp->lock, flags);
				info.next_rdma_state = NSER_QP_STATE_SQD;
				nser_hw_modify_qp(iwdev, iwqp, &info, true);
				spin_lock_irqsave(&iwqp->lock, flags);
			}

			if (iwqp->rdma_state == NSER_QP_STATE_ERROR) {
				spin_unlock_irqrestore(&iwqp->lock, flags);
				if (udata) {
					if (ib_copy_from_udata(&ureq, udata,
					    min(sizeof(ureq), udata->inlen)))
						return -EINVAL;

					nser_flush_wqes(iwqp,
					    (ureq.sq_flush ? NSER_FLUSH_SQ : 0) |
					    (ureq.rq_flush ? NSER_FLUSH_RQ : 0) |
					    NSER_REFLUSH);
				}
				return 0;
			}

			info.next_rdma_state = NSER_QP_STATE_ERROR;
			issue_modify_qp = 1;
			break;
		default:
			ret = -EINVAL;
			goto exit;
		}

		iwqp->ibqp_state = attr->qp_state;
	}

	ctx_info->send_cq_num = iwqp->iwscq->sc_cq.cq_uk.cq_id;
	ctx_info->rcv_cq_num = iwqp->iwrcq->sc_cq.cq_uk.cq_id;
	nser_sc_qp_setctx_roce(&iwqp->sc_qp, iwqp->host_ctx.va, ctx_info);
	spin_unlock_irqrestore(&iwqp->lock, flags);

	if (attr_mask & IB_QP_STATE) {
		if (issue_modify_qp) {
			ctx_info->rem_endpoint_idx = udp_info->arp_idx;
			if (nser_hw_modify_qp(iwdev, iwqp, &info, true))
				return -EINVAL;
			spin_lock_irqsave(&iwqp->lock, flags);
			if (iwqp->rdma_state == info.curr_rdma_state) {
				iwqp->rdma_state = info.next_rdma_state;
				iwqp->ibqp_state = attr->qp_state;
			}
			if (iwqp->ibqp_state > IB_QPS_RTS &&
			    !iwqp->flush_issued) {
				spin_unlock_irqrestore(&iwqp->lock, flags);

				nser_flush_wqes(iwqp,
					    (ureq.sq_flush ? NSER_FLUSH_SQ : 0) |
					    (ureq.rq_flush ? NSER_FLUSH_RQ : 0) |
					    NSER_REFLUSH);

				iwqp->flush_issued = 1;

			} else {
				spin_unlock_irqrestore(&iwqp->lock, flags);
			}
		} else {
			iwqp->ibqp_state = attr->qp_state;
		}
		if (udata) {
			uresp.rd_fence_rate = iwdev->rd_fence_rate;
			uresp.qs_handle = iwqp->sc_qp.qs_handle;
			ret = ib_copy_to_udata(udata, &uresp, min(sizeof(uresp),
					       udata->outlen));
			if (ret) {
				nser_dbg(iwdev_to_idev(iwdev),
					  "VERBS: copy_to_udata failed\n");
				return ret;
			}
		}
	}
	return 0;
exit:
	spin_unlock_irqrestore(&iwqp->lock, flags);

	return ret;
}

/**
 * nser_cq_free_rsrc - free up resources for cq
 * @rf: RDMA PCI function
 * @iwcq: cq ptr
 */
void nser_cq_free_rsrc(struct nser_pci_f *rf, struct nser_cq *iwcq)
{
	struct nser_sc_cq *cq = &iwcq->sc_cq;

	if (!iwcq->user_mode) {
		dma_free_coherent(rf->sc_dev.hw->device, iwcq->kmem.size,
				  iwcq->kmem.va, iwcq->kmem.pa);
		iwcq->kmem.va = NULL;
		dma_free_coherent(rf->sc_dev.hw->device,
				  iwcq->kmem_shadow.size,
				  iwcq->kmem_shadow.va, iwcq->kmem_shadow.pa);
		iwcq->kmem_shadow.va = NULL;
	}

	nser_free_rsrc_with_ts(rf, rf->allocated_cqs, cq->cq_uk.cq_id, rf->allocated_cqs_ts);
	rf->used_cqs -= 1;
}

/**
 * nser_free_cqbuf - worker to free a cq buffer
 * @work: provides access to the cq buffer to free
 */
static void nser_free_cqbuf(struct work_struct *work)
{
	struct nser_cq_buf *cq_buf = container_of(work, struct nser_cq_buf, work);

	dma_free_coherent(cq_buf->hw->device, cq_buf->kmem_buf.size,
			  cq_buf->kmem_buf.va, cq_buf->kmem_buf.pa);
	cq_buf->kmem_buf.va = NULL;
	kfree(cq_buf);
}

/**
 * nser_process_resize_list - remove resized cq buffers from the resize_list
 * @iwcq: cq which owns the resize_list
 * @iwdev: nser device
 * @lcqe_buf: the buffer where the last cqe is received
 */
int nser_process_resize_list(struct nser_cq *iwcq,
			      struct nser_device *iwdev,
			      struct nser_cq_buf *lcqe_buf)
{
	struct list_head *tmp_node, *list_node;
	struct nser_cq_buf *cq_buf;
	int cnt = 0;

	list_for_each_safe(list_node, tmp_node, &iwcq->resize_list) {
		cq_buf = list_entry(list_node, struct nser_cq_buf, list);
		if (cq_buf == lcqe_buf)
			return cnt;

		list_del(&cq_buf->list);
		queue_work(iwdev->cleanup_wq, &cq_buf->work);
		cnt++;
	}

	return cnt;
}

/**
 * nser_resize_cq - resize cq
 * @ibcq: cq to be resized
 * @entries: desired cq size
 * @udata: user data
 */
static int nser_resize_cq(struct ib_cq *ibcq, int entries,
			   struct ib_udata *udata)
{
	struct nser_cq *iwcq = to_iwcq(ibcq);
	struct nser_sc_dev *dev = iwcq->sc_cq.dev;
	struct nser_cqp_request *cqp_request;
	struct cqp_cmds_info *cqp_info;
	struct nser_modify_cq_info *m_info;
	struct nser_modify_cq_info info = {};
	struct nser_dma_mem kmem_buf;
	struct nser_cq_mr *cqmr_buf;
	struct nser_pbl *iwpbl_buf;
	struct nser_device *iwdev;
	struct nser_pci_f *rf;
	struct nser_cq_buf *cq_buf = NULL;
	unsigned long flags;
	int ret;
	bool modify_cq_for_ceq_val = false;

	iwdev = to_iwdev(ibcq->device);
	rf = iwdev->rf;

	if (!(rf->sc_dev.hw_attrs.uk_attrs.feature_flags &
	    NSER_FEATURE_CQ_RESIZE))
		return -EOPNOTSUPP;

	if (entries > rf->max_cqe)
		return -EINVAL;

	if (entries == iwcq->sc_cq.cq_uk.cq_size) {
		modify_cq_for_ceq_val = true;
		iwcq->sc_cq.ceq_id_valid = true;
	}

	if (!iwcq->user_mode) {
		entries++;
		if (!iwcq->sc_cq.cq_uk.avoid_mem_cflct)
			entries *= 2;

		if (entries & 1)
			entries += 1; /* cq size must be an even number */
	}

	info.cq_size = max(entries, 4);

	if (udata) {
		struct nser_resize_cq_req req = {};
		struct nser_ucontext *ucontext =
			kc_rdma_udata_to_drv_context(ibcq, udata);

		if (ib_copy_from_udata(&req, udata,
				       min(sizeof(req), udata->inlen)))
			return -EINVAL;
		if (!modify_cq_for_ceq_val) {
			spin_lock_irqsave(&ucontext->cq_reg_mem_list_lock, flags);
			iwpbl_buf = nser_get_pbl((unsigned long)req.user_cq_buffer,
					  &ucontext->cq_reg_mem_list);
			spin_unlock_irqrestore(&ucontext->cq_reg_mem_list_lock, flags);

			if (!iwpbl_buf)
				return -ENOMEM;

			cqmr_buf = &iwpbl_buf->cq_mr;
			if (iwpbl_buf->pbl_allocated) {
				info.virtual_map = true;
				info.pbl_chunk_size = 1;
				info.first_pm_pbl_idx = cqmr_buf->cq_pbl.idx;
			} else {
				info.cq_pa = cqmr_buf->cq_pbl.addr;
			}
		}
	} else {
		if (!modify_cq_for_ceq_val) {
			/* Kmode CQ resize */
			int rsize;

			rsize = info.cq_size * sizeof(struct nser_cqe);
			kmem_buf.size = ALIGN(round_up(rsize, 256), 256);
			kmem_buf.va = dma_alloc_coherent(dev->hw->device,
						 kmem_buf.size, &kmem_buf.pa,
						 GFP_KERNEL);
			if (!kmem_buf.va)
				return -ENOMEM;

			info.cq_base = kmem_buf.va;
			info.cq_pa = kmem_buf.pa;
			cq_buf = kzalloc(sizeof(*cq_buf), GFP_KERNEL);
			if (!cq_buf) {
				ret = -ENOMEM;
				goto error;
			}
		}
	}

	cqp_request = nser_alloc_and_get_cqp_request(&rf->cqp, true);
	if (!cqp_request) {
		ret = -ENOMEM;
		goto error;
	}

	info.shadow_read_threshold = iwcq->sc_cq.shadow_read_threshold;
	if (modify_cq_for_ceq_val)
		info.cq_resize = false;
	else
		info.cq_resize = true;

	cqp_info = &cqp_request->info;
	m_info = &cqp_info->in.u.cq_modify.info;
	memcpy(m_info, &info, sizeof(*m_info));

	cqp_info->cqp_cmd = NSER_OP_CQ_MODIFY;
	cqp_info->in.u.cq_modify.cq = &iwcq->sc_cq;
	cqp_info->in.u.cq_modify.scratch = (uintptr_t)cqp_request;
	cqp_info->post_sq = 1;
	ret = nser_handle_cqp_op(rf, cqp_request);
	nser_put_cqp_request(&rf->cqp, cqp_request);
	if (ret)
		goto error;

	spin_lock_irqsave(&iwcq->lock, flags);
	if (!modify_cq_for_ceq_val) {
		if (cq_buf) {
			cq_buf->kmem_buf = iwcq->kmem;
			cq_buf->hw = dev->hw;
			memcpy(&cq_buf->cq_uk, &iwcq->sc_cq.cq_uk, sizeof(cq_buf->cq_uk));
			INIT_WORK(&cq_buf->work, nser_free_cqbuf);
			list_add_tail(&cq_buf->list, &iwcq->resize_list);
			iwcq->kmem = kmem_buf;
		}

		nser_sc_cq_resize(&iwcq->sc_cq, &info);
		ibcq->cqe = info.cq_size - 1;
	}
	spin_unlock_irqrestore(&iwcq->lock, flags);

	return 0;
error:
	if (!modify_cq_for_ceq_val) {
		if (!udata) {
			dma_free_coherent(dev->hw->device, kmem_buf.size, kmem_buf.va,
				  kmem_buf.pa);
			kmem_buf.va = NULL;
		}
		kfree(cq_buf);
	}

	return ret;
}

/**
 * nser_get_mr_access - get hw MR access permissions from IB access flags
 * @access: IB access flags
 */
static inline u16 nser_get_mr_access(int access)
{
	u16 hw_access = 0;

	hw_access |= (access & IB_ACCESS_LOCAL_WRITE) ?
		     NSER_ACCESS_FLAGS_LOCALWRITE : 0;
	hw_access |= (access & IB_ACCESS_REMOTE_WRITE) ?
		     NSER_ACCESS_FLAGS_REMOTEWRITE : 0;
	hw_access |= (access & IB_ACCESS_REMOTE_READ) ?
		     NSER_ACCESS_FLAGS_REMOTEREAD : 0;
	hw_access |= (access & IB_ACCESS_MW_BIND) ?
		     NSER_ACCESS_FLAGS_BIND_WINDOW : 0;
	hw_access |= (access & IB_ZERO_BASED) ?
		     NSER_ACCESS_FLAGS_ZERO_BASED : 0;
	hw_access |= NSER_ACCESS_FLAGS_LOCALREAD;

	return hw_access;
}

/**
 * nser_free_stag - free stag resource
 * @iwdev: nser device
 * @stag: stag to free
 */
void nser_free_stag(struct nser_device *iwdev, u32 stag)
{
	u32 stag_idx;

	stag_idx = (stag & iwdev->rf->mr_stagmask) >> NSER_CQPSQ_STAG_IDX_S;
	nser_free_rsrc_with_ts(iwdev->rf, iwdev->rf->allocated_mrs,
						  stag_idx, iwdev->rf->allocated_mrs_ts);
	iwdev->rf->used_mrs -= 1;
}

/**
 * nser_create_stag - create random stag
 * @iwdev: nser device
 */
u32 nser_create_stag(struct nser_device *iwdev)
{
	u32 stag = 0;
	u32 stag_index = 0;
	u32 next_stag_index;
	u32 driver_key;
	u32 random;
	u8 consumer_key;
	int ret;

	get_random_bytes(&random, sizeof(random));
	consumer_key = (u8)random;

	driver_key = random & ~iwdev->rf->mr_stagmask;
	next_stag_index = (random & iwdev->rf->mr_stagmask) >> 8;
	next_stag_index %= iwdev->rf->max_mr;

	ret = nser_alloc_rsrc_with_ts(iwdev->rf, iwdev->rf->allocated_mrs,
			       iwdev->rf->max_mr, &stag_index,
			       &next_stag_index, iwdev->rf->allocated_mrs_ts);
	if (!ret)
		iwdev->rf->used_mrs += 1;
	if (ret)
		return 0;
	stag = stag_index << NSER_CQPSQ_STAG_IDX_S;
	stag |= driver_key;
	stag += (u32)consumer_key;

	return stag;
}

/**
 * nser_next_pbl_addr - Get next pbl address
 * @pbl: pointer to a pble
 * @pinfo: info pointer
 * @idx: index
 */
static inline u64 *nser_next_pbl_addr(u64 *pbl, struct nser_pble_info **pinfo,
				       u32 *idx)
{
	*idx += 1;
	if (!(*pinfo) || *idx != (*pinfo)->cnt)
		return ++pbl;
	*idx = 0;
	(*pinfo)++;

	return (*pinfo)->addr;
}

/**
 * nser_copy_user_pgaddrs - copy user page address to pble's os locally
 * @iwmr: iwmr for IB's user page addresses
 * @pbl: ple pointer to save 1 level or 0 level pble
 * @level: indicated level 0, 1 or 2
 */
static void nser_copy_user_pgaddrs(struct nser_mr *iwmr, u64 *pbl,
			     enum nser_pble_level level)
{
	struct ib_umem *region = iwmr->region;
	struct nser_pbl *iwpbl = &iwmr->iwpbl;
	struct ib_block_iter biter;
	struct nser_pble_alloc *palloc = &iwpbl->pble_alloc;
	struct nser_pble_info *pinfo;
	u32 idx = 0;
	u32 pbl_cnt = 0;
	u32 page_mask = 0;
	u64 pble;
	u32 i;

	pinfo = (level == PBLE_LEVEL_1) ? NULL : palloc->level2.leaf;

	if (iwmr->type == NSER_MEMREG_TYPE_QP)
		iwpbl->qp_mr.sq_page = sg_page(region->sgt_append.sgt.sgl);

	page_mask = GENMASK(ffs((u32)PAGE_MASK)-2, 12) & region->address;

	pr_debug("PAGE_SIZE: 0x%lx, ib_umem_page_size:0x%llx, page_size:0x%llx\n",
			PAGE_SIZE, iwmr->ib_umem_page_size, iwmr->page_size);
	rdma_umem_for_each_dma_block(region, &biter, iwmr->ib_umem_page_size) {
		pble = rdma_block_iter_dma_address(&biter);
		for (i = 0; i * iwmr->page_size < iwmr->ib_umem_page_size; i++) {
			*pbl = pble + page_mask + i * iwmr->page_size;
			if (++pbl_cnt == palloc->total_cnt) {
				*pbl = 0;
				while (*pbl != 0)
					fsleep(10000);
				*pbl = pble + page_mask + i * iwmr->page_size;
				while (*pbl != pble + page_mask + i * iwmr->page_size)
					fsleep(10000);
				return;
			}
			pbl = nser_next_pbl_addr(pbl, &pinfo, &idx);
		}
	}
}

/**
 * nser_check_mem_contiguous - check if pbls stored in arr are contiguous
 * @arr: lvl1 pbl array
 * @npages: page count
 * @pg_size: page size
 *
 */
static bool nser_check_mem_contiguous(u64 *arr, u32 npages, u32 pg_size)
{
	u32 pg_idx;

	for (pg_idx = 0; pg_idx < npages; pg_idx++) {
		if ((*arr + ((u64)pg_size * pg_idx)) != arr[pg_idx])
			return false;
	}

	return true;
}

/**
 * nser_check_mr_contiguous - check if MR is physically contiguous
 * @palloc: pbl allocation struct
 * @pg_size: page size
 */
static bool nser_check_mr_contiguous(struct nser_pble_alloc *palloc,
				      u32 pg_size)
{
	struct nser_pble_level2 *lvl2 = &palloc->level2;
	struct nser_pble_info *leaf = lvl2->leaf;
	u64 *arr = NULL;
	u64 *start_addr = NULL;
	int i;
	bool ret;

	if (palloc->level == PBLE_LEVEL_1) {
		arr = palloc->level1.addr;
		ret = nser_check_mem_contiguous(arr, palloc->total_cnt,
						 pg_size);
		return ret;
	}

	start_addr = leaf->addr;

	for (i = 0; i < lvl2->leaf_cnt; i++, leaf++) {
		arr = leaf->addr;
		if ((*start_addr + (i * pg_size * PBLE_PER_PAGE)) != *arr)
			return false;
		ret = nser_check_mem_contiguous(arr, leaf->cnt, pg_size);
		if (!ret)
			return false;
	}

	return true;
}

/**
 * nser_setup_pbles - copy user pg address to pble's
 * @rf: RDMA PCI function
 * @iwmr: mr pointer for this memory registration
 * @lvl: requested pble levels
 */
static int nser_setup_pbles(struct nser_pci_f *rf, struct nser_mr *iwmr, u8 lvl)
{
	struct nser_pbl *iwpbl = &iwmr->iwpbl;
	struct nser_pble_alloc *palloc = &iwpbl->pble_alloc;
	struct nser_pble_info *pinfo;
	u64 *pbl;
	int status;
	enum nser_pble_level level = PBLE_LEVEL_1;

	if (lvl) {
		status = nser_get_pble(rf->pble_rsrc, palloc, iwmr->page_cnt,
					lvl);
		if (status)
			return status;

		iwpbl->pbl_allocated = true;
		level = palloc->level;
		pinfo = (level == PBLE_LEVEL_1) ? &palloc->level1 :
						  palloc->level2.leaf;
		pbl = pinfo->addr;
	} else {
		palloc->total_cnt = iwmr->page_cnt;
		pbl = iwmr->pgaddrmem;
	}

	nser_copy_user_pgaddrs(iwmr, pbl, level);

	if (lvl)
		iwmr->pgaddrmem[0] = *pbl;

	return 0;
}

/**
 * nser_handle_q_mem - handle memory for qp and cq
 * @iwdev: nser device
 * @req: information for q memory management
 * @iwpbl: pble struct
 * @lvl: pble level mask
 */
static int nser_handle_q_mem(struct nser_device *iwdev,
			      struct nser_mem_reg_req *req,
			      struct nser_pbl *iwpbl, u8 lvl)
{
	struct nser_pble_alloc *palloc = &iwpbl->pble_alloc;
	struct nser_mr *iwmr = iwpbl->iwmr;
	struct nser_qp_mr *qpmr = &iwpbl->qp_mr;
	struct nser_cq_mr *cqmr = &iwpbl->cq_mr;
	struct nser_hmc_pble *hmc_p;
	u64 *arr = iwmr->pgaddrmem;
	u32 pg_size, total;
	int err = 0;
	bool ret = true;

	pg_size = iwmr->page_size;
	err = nser_setup_pbles(iwdev->rf, iwmr, lvl);
	if (err)
		return err;

	if (lvl)
		arr = palloc->level1.addr;

	switch (iwmr->type) {
	case NSER_MEMREG_TYPE_QP:
		total = req->sq_pages + req->rq_pages;
		hmc_p = &qpmr->sq_pbl;
		qpmr->shadow = (dma_addr_t)arr[total];
		if (lvl) {
			ret = nser_check_mem_contiguous(arr, req->sq_pages,
							 pg_size);
			if (ret)
				ret = nser_check_mem_contiguous(&arr[req->sq_pages],
								 req->rq_pages,
								 pg_size);
		}

		if (!ret) {
			hmc_p->idx = palloc->level1.idx;
			hmc_p = &qpmr->rq_pbl;
			hmc_p->idx = palloc->level1.idx + req->sq_pages;
		} else {
			hmc_p->addr = arr[0];
			hmc_p = &qpmr->rq_pbl;
			hmc_p->addr = arr[req->sq_pages];
		}
		break;
	case NSER_MEMREG_TYPE_CQ:
		hmc_p = &cqmr->cq_pbl;

		if (!cqmr->split)
			cqmr->shadow = (dma_addr_t)arr[req->cq_pages];

		if (lvl)
			ret = nser_check_mem_contiguous(arr, req->cq_pages,
							 pg_size);

		if (!ret)
			hmc_p->idx = palloc->level1.idx;
		else
			hmc_p->addr = arr[0];
	break;
	default:
		nser_dbg(iwdev_to_idev(iwdev), "VERBS: MR type error\n");
		err = -EINVAL;
	}

	if (lvl && ret) {
		nser_free_pble(iwdev->rf->pble_rsrc, palloc);
		iwpbl->pbl_allocated = false;
	}

	return err;
}

/**
 * nser_hw_alloc_mw - create the hw memory window
 * @iwdev: nser device
 * @iwmr: pointer to memory window info
 */
int nser_hw_alloc_mw(struct nser_device *iwdev, struct nser_mr *iwmr)
{
	struct nser_mw_alloc_info *info;
	struct nser_pd *iwpd = to_iwpd(iwmr->ibmr.pd);
	struct nser_cqp_request *cqp_request;
	struct cqp_cmds_info *cqp_info;
	int status;

	cqp_request = nser_alloc_and_get_cqp_request(&iwdev->rf->cqp, true);
	if (!cqp_request)
		return -ENOMEM;

	cqp_info = &cqp_request->info;
	info = &cqp_info->in.u.mw_alloc.info;
	memset(info, 0, sizeof(*info));
	if (iwmr->ibmw.type == IB_MW_TYPE_1)
		info->mw_wide = true;

	info->page_size = PAGE_SIZE;
	info->mw_stag_index = iwmr->stag >> NSER_CQPSQ_STAG_IDX_S;
	info->pd_id = iwpd->sc_pd.pd_id;
	info->remote_access = true;
	cqp_info->cqp_cmd = NSER_OP_MW_ALLOC;
	cqp_info->post_sq = 1;
	cqp_info->in.u.mw_alloc.dev = &iwdev->rf->sc_dev;
	cqp_info->in.u.mw_alloc.scratch = (uintptr_t)cqp_request;
	status = nser_handle_cqp_op(iwdev->rf, cqp_request);
	nser_put_cqp_request(&iwdev->rf->cqp, cqp_request);

	return status;
}

/**
 * nser_dealloc_mw - Dealloc memory window
 * @ibmw: memory window structure.
 */
static int nser_dealloc_mw(struct ib_mw *ibmw)
{
	struct ib_pd *ibpd = ibmw->pd;
	struct nser_pd *iwpd = to_iwpd(ibpd);
	struct nser_mr *iwmr = to_iwmr((struct ib_mr *)ibmw);
	struct nser_device *iwdev = to_iwdev(ibmw->device);
	struct nser_cqp_request *cqp_request;
	struct cqp_cmds_info *cqp_info;
	struct nser_dealloc_stag_info *info;

	cqp_request = nser_alloc_and_get_cqp_request(&iwdev->rf->cqp, true);
	if (!cqp_request)
		return -ENOMEM;

	cqp_info = &cqp_request->info;
	info = &cqp_info->in.u.dealloc_stag.info;
	memset(info, 0, sizeof(*info));
	info->pd_id = iwpd->sc_pd.pd_id;
	info->stag_idx = RS_64_1(ibmw->rkey, NSER_CQPSQ_STAG_IDX_S);
	info->mr = false;
	cqp_info->cqp_cmd = NSER_OP_DEALLOC_STAG;
	cqp_info->post_sq = 1;
	cqp_info->in.u.dealloc_stag.dev = &iwdev->rf->sc_dev;
	cqp_info->in.u.dealloc_stag.scratch = (uintptr_t)cqp_request;
	nser_handle_cqp_op(iwdev->rf, cqp_request);
	nser_put_cqp_request(&iwdev->rf->cqp, cqp_request);
	nser_free_stag(iwdev, iwmr->stag);

	return 0;
}

static int cal_best_pble_page_size(int page_size)
{
	enum nser_hw_pble_page_size hw_page_size[] = {
		NSER_HW_PBLE_4K,
		NSER_HW_PBLE_2M,
	};
	int best_page_size = 0;
	int hw_pble_size_cnt = ARRAY_SIZE(hw_page_size);
	int i;

	for (i = 0; i < hw_pble_size_cnt; ++i) {
		if (page_size == hw_page_size[i]) {
			best_page_size = hw_page_size[i];
			break;
		} else if (!(page_size % hw_page_size[i])) {
			best_page_size = hw_page_size[i];
		}
	}
	pr_debug("find best page size: 0x%x\n", best_page_size);

	return best_page_size;
}

/**
 * nser_hw_alloc_stag - cqp command to allocate stag
 * @iwdev: nser device
 * @iwmr: nser mr pointer
 */
int nser_hw_alloc_stag(struct nser_device *iwdev,
			struct nser_mr *iwmr)
{
	struct nser_allocate_stag_info *info;
	struct ib_pd *pd = iwmr->ibmr.pd;
	struct nser_pd *iwpd = to_iwpd(pd);
	struct nser_cqp_request *cqp_request;
	struct cqp_cmds_info *cqp_info;
	int status;

	cqp_request = nser_alloc_and_get_cqp_request(&iwdev->rf->cqp, true);
	if (!cqp_request)
		return -ENOMEM;

	cqp_info = &cqp_request->info;
	info = &cqp_info->in.u.alloc_stag.info;
	memset(info, 0, sizeof(*info));
	info->page_size = cal_best_pble_page_size(PAGE_SIZE);
	info->stag_idx = iwmr->stag >> NSER_CQPSQ_STAG_IDX_S;
	info->pd_id = iwpd->sc_pd.pd_id;
	info->total_len = iwmr->len;
	info->all_memory = (pd->flags & IB_PD_UNSAFE_GLOBAL_RKEY) ? true : false;
	info->remote_access = true;
	cqp_info->cqp_cmd = NSER_OP_ALLOC_STAG;
	cqp_info->post_sq = 1;
	cqp_info->in.u.alloc_stag.dev = &iwdev->rf->sc_dev;
	cqp_info->in.u.alloc_stag.scratch = (uintptr_t)cqp_request;
	status = nser_handle_cqp_op(iwdev->rf, cqp_request);
	nser_put_cqp_request(&iwdev->rf->cqp, cqp_request);
	if (!status)
		iwmr->is_hwreg = 1;

	return status;
}

/**
 * nser_set_page - populate pbl list for fmr
 * @ibmr: ib mem to access iwarp mr pointer
 * @addr: page dma address fro pbl list
 */
static int nser_set_page(struct ib_mr *ibmr, u64 addr)
{
	struct nser_mr *iwmr = to_iwmr(ibmr);
	struct nser_pbl *iwpbl = &iwmr->iwpbl;
	struct nser_pble_alloc *palloc = &iwpbl->pble_alloc;
	u64 *pbl;

	if (unlikely(iwmr->npages == iwmr->page_cnt))
		return -ENOMEM;

	if (palloc->level == PBLE_LEVEL_2) {
		struct nser_pble_info *palloc_info =
			palloc->level2.leaf + (iwmr->npages >> PBLE_512_SHIFT);

		palloc_info->addr[iwmr->npages & (PBLE_PER_PAGE - 1)] = addr;

		while (palloc_info->addr[iwmr->npages & (PBLE_PER_PAGE - 1)] != addr)
			fsleep(3000);
	} else {
		pbl = palloc->level1.addr;
		pbl[iwmr->npages] = addr;

		while (pbl[iwmr->npages] != addr)
			fsleep(3000);
	}

	iwmr->npages++;
	return 0;
}

/**
 * nser_map_mr_sg - map of sg list for fmr
 * @ibmr: ib mem to access iwarp mr pointer
 * @sg: scatter gather list
 * @sg_nents: number of sg pages
 * @sg_offset: scatter gather list for fmr
 */
static int nser_map_mr_sg(struct ib_mr *ibmr, struct scatterlist *sg,
			   int sg_nents, unsigned int *sg_offset)
{
	struct nser_mr *iwmr = to_iwmr(ibmr);

	iwmr->npages = 0;

	return ib_sg_to_pages(ibmr, sg, sg_nents, sg_offset, nser_set_page);
}

/**
 * nser_hwreg_mr - send cqp command for memory registration
 * @iwdev: nser device
 * @iwmr: nser mr pointer
 * @access: access for MR
 */
int nser_hwreg_mr(struct nser_device *iwdev, struct nser_mr *iwmr,
		   u16 access)
{
	struct nser_pbl *iwpbl = &iwmr->iwpbl;
	struct nser_reg_ns_stag_info *stag_info;
	struct ib_pd *pd = iwmr->ibmr.pd;
	struct nser_pd *iwpd = to_iwpd(iwmr->ibmr.pd);
	struct nser_pble_alloc *palloc = &iwpbl->pble_alloc;
	struct nser_cqp_request *cqp_request;
	struct cqp_cmds_info *cqp_info;
	int ret;

	cqp_request = nser_alloc_and_get_cqp_request(&iwdev->rf->cqp, true);
	if (!cqp_request)
		return -ENOMEM;

	cqp_info = &cqp_request->info;
	stag_info = &cqp_info->in.u.mr_reg_non_shared.info;
	memset(stag_info, 0, sizeof(*stag_info));
	stag_info->va = iwpbl->user_base;
	stag_info->stag_idx = iwmr->stag >> NSER_CQPSQ_STAG_IDX_S;
	stag_info->stag_key = (u8)iwmr->stag;
	stag_info->total_len = iwmr->len;
	stag_info->all_memory = (pd->flags & IB_PD_UNSAFE_GLOBAL_RKEY) ? true : false;
	stag_info->access_rights = nser_get_mr_access(access);
	if (iwdev->rf->sc_dev.hw_attrs.uk_attrs.feature_flags & NSER_FEATURE_ATOMIC_OPS)
		stag_info->remote_atomics_en = (access & IB_ACCESS_REMOTE_ATOMIC) ? 1 : 0;
	stag_info->pd_id = iwpd->sc_pd.pd_id;
	if (stag_info->access_rights & NSER_ACCESS_FLAGS_ZERO_BASED)
		stag_info->addr_type = NSER_ADDR_TYPE_ZERO_BASED;
	else
		stag_info->addr_type = NSER_ADDR_TYPE_VA_BASED;
	stag_info->page_size = iwmr->page_size;

	if (iwpbl->pbl_allocated) {
		if (palloc->level == PBLE_LEVEL_1) {
			stag_info->first_pm_pbl_index = palloc->level1.idx;
			stag_info->chunk_size = 1;
		} else {
			stag_info->first_pm_pbl_index = palloc->level2.root.idx;
			stag_info->chunk_size = 3;
		}
	} else {
		stag_info->reg_addr_pa = iwmr->pgaddrmem[0];
#ifdef CONFIG_DEBUG_FS
		iwmr->level0_pa = iwmr->pgaddrmem[0];
#endif
	}

	cqp_info->cqp_cmd = NSER_OP_MR_REG_NON_SHARED;
	cqp_info->post_sq = 1;
	cqp_info->in.u.mr_reg_non_shared.dev = &iwdev->rf->sc_dev;
	cqp_info->in.u.mr_reg_non_shared.scratch = (uintptr_t)cqp_request;
	ret = nser_handle_cqp_op(iwdev->rf, cqp_request);
	nser_put_cqp_request(&iwdev->rf->cqp, cqp_request);

	if (!ret)
		iwmr->is_hwreg = 1;

	return ret;
}

/*
 * nser_alloc_iwmr - Allocate iwmr
 * @region - memory region
 * @pd - protection domain
 * @virt - virtual address
 * @reg_type - registration type
 */
struct nser_mr *nser_alloc_iwmr(struct ib_umem *region,
				  struct ib_pd *pd, u64 virt,
				  enum nser_memreg_type reg_type)
{
	struct nser_device *iwdev = to_iwdev(pd->device);
	struct nser_pbl *iwpbl;
	struct nser_mr *iwmr;
	unsigned long pgsz_bitmap;

	iwmr = kzalloc(sizeof(*iwmr), GFP_KERNEL);
	if (!iwmr)
		return ERR_PTR(-ENOMEM);

	iwpbl = &iwmr->iwpbl;
	iwpbl->iwmr = iwmr;
	iwmr->region = region;
	iwmr->ibmr.pd = pd;
	iwmr->ibmr.device = pd->device;
	iwmr->ibmr.iova = virt;
	iwmr->type = reg_type;

	pgsz_bitmap = (reg_type == NSER_MEMREG_TYPE_MEM) ?
				iwdev->rf->sc_dev.hw_attrs.page_size_cap | PAGE_SIZE
				: SZ_4K | PAGE_SIZE;

	iwmr->ib_umem_page_size = ib_umem_find_best_pgsz(region, pgsz_bitmap, virt);

	if (unlikely(!iwmr->ib_umem_page_size))
		iwmr->ib_umem_page_size = PAGE_SIZE;

	iwmr->page_size = cal_best_pble_page_size(iwmr->ib_umem_page_size);
	if (unlikely(!iwmr->page_size)) {
		kfree(iwmr);
		return ERR_PTR(-EOPNOTSUPP);
	}

	iwmr->len = region->length;
	iwpbl->user_base = virt;
	iwmr->page_cnt = ib_umem_num_dma_blocks(region, iwmr->page_size);

	return iwmr;
}

void nser_free_iwmr(struct nser_mr *iwmr)
{
	kfree(iwmr);
}

/*
 * nser_reg_user_mr_type_qp - Handle QP memory registration
 * @req - memory reg req
 * @udata - user info
 * @iwmr - nser mr
 */
static int nser_reg_user_mr_type_qp(struct nser_mem_reg_req req,
				     struct ib_udata *udata,
				     struct nser_mr *iwmr)
{
	struct nser_device *iwdev = to_iwdev(iwmr->ibmr.device);
	struct nser_pbl *iwpbl = &iwmr->iwpbl;
	struct nser_ucontext *ucontext;
	unsigned long flags;
	u32 total;
	int err;
	u8 lvl;

	total = req.sq_pages + req.rq_pages + NSER_SHADOW_PGCNT;
	if (total > iwmr->page_cnt)
		return -EINVAL;

	total = req.sq_pages + req.rq_pages;
	lvl = total > 2 ? PBLE_LEVEL_1 : PBLE_LEVEL_0;
	err = nser_handle_q_mem(iwdev, &req, iwpbl, lvl);
	if (err)
		return err;

	ucontext = kc_rdma_udata_to_drv_context(iwmr->ibmr.pd, udata);
	spin_lock_irqsave(&ucontext->qp_reg_mem_list_lock, flags);
	list_add_tail(&iwpbl->list, &ucontext->qp_reg_mem_list);
	iwpbl->on_list = true;
	spin_unlock_irqrestore(&ucontext->qp_reg_mem_list_lock, flags);

	return 0;
}

/*
 * nser_reg_user_mr_type_cq - Handle CQ memory registration
 * @req - memory reg req
 * @udata - user info
 * @iwmr - nser mr
 */
static int nser_reg_user_mr_type_cq(struct nser_mem_reg_req req,
				     struct ib_udata *udata,
				     struct nser_mr *iwmr)
{
	struct nser_device *iwdev = to_iwdev(iwmr->ibmr.device);
	struct nser_pbl *iwpbl = &iwmr->iwpbl;
	struct nser_ucontext *ucontext;
	unsigned long flags;
	u32 total;
	int err;
	u8 lvl;

	total = req.cq_pages +
		((iwdev->rf->sc_dev.hw_attrs.uk_attrs.feature_flags &
		NSER_FEATURE_CQ_RESIZE) ? 0 : NSER_SHADOW_PGCNT);
	if (total > iwmr->page_cnt)
		return -EINVAL;

	lvl = req.cq_pages > 1 ? PBLE_LEVEL_1 : PBLE_LEVEL_0;
	err = nser_handle_q_mem(iwdev, &req, iwpbl, lvl);
	if (err)
		return err;

	ucontext = kc_rdma_udata_to_drv_context(iwmr->ibmr.pd, udata);
	spin_lock_irqsave(&ucontext->cq_reg_mem_list_lock, flags);
	list_add_tail(&iwpbl->list, &ucontext->cq_reg_mem_list);
	iwpbl->on_list = true;
	spin_unlock_irqrestore(&ucontext->cq_reg_mem_list_lock, flags);

	return 0;
}

/*
 * nser_reg_user_mr_type_mem - Handle memory registration
 * @iwmr - nser mr
 * @access - access rights
 * @create_stag - flag to create stag or not
 */
int nser_reg_user_mr_type_mem(struct nser_mr *iwmr, int access,
			       bool create_stag)
{
	struct nser_device *iwdev = to_iwdev(iwmr->ibmr.device);
	struct nser_pbl *iwpbl = &iwmr->iwpbl;
	u32 stag = 0;
	int err;
	u8 lvl;

	lvl = iwmr->page_cnt != 1 ? PBLE_LEVEL_1 | PBLE_LEVEL_2 : PBLE_LEVEL_0;

	err = nser_setup_pbles(iwdev->rf, iwmr, lvl);
	if (err)
		return err;

	if (lvl) {
		err = nser_check_mr_contiguous(&iwpbl->pble_alloc,
						iwmr->page_size);
		if (err) {
			nser_free_pble(iwdev->rf->pble_rsrc, &iwpbl->pble_alloc);
			iwpbl->pbl_allocated = false;
		}
	}

	if (create_stag) {
		stag = nser_create_stag(iwdev);
		if (!stag) {
			err = -ENOMEM;
			goto free_pble;
		}

		iwmr->stag = stag;
		iwmr->ibmr.rkey = stag;
		iwmr->ibmr.lkey = stag;
	}
	iwmr->access = access;
	err = nser_hwreg_mr(iwdev, iwmr, access);
	if (err)
		goto err_hwreg;

	return 0;

err_hwreg:
	if (stag)
		nser_free_stag(iwdev, stag);

free_pble:
	if (iwpbl->pble_alloc.level != PBLE_LEVEL_0 && iwpbl->pbl_allocated)
		nser_free_pble(iwdev->rf->pble_rsrc, &iwpbl->pble_alloc);

	return err;
}

/**
 * nser_reg_user_mr - Register a user memory region
 * @pd: ptr of pd
 * @start: virtual start address
 * @len: length of mr
 * @virt: virtual address
 * @access: access of mr
 * @udata: user data
 */
static struct ib_mr *nser_reg_user_mr(struct ib_pd *pd, u64 start, u64 len,
			      u64 virt, int access,
			      struct ib_udata *udata)
{
	struct nser_device *iwdev = to_iwdev(pd->device);
	struct nser_mr *iwmr;
	struct ib_umem *region;
	struct nser_mem_reg_req req = {};
	int err = -EINVAL;

	if (len > iwdev->rf->sc_dev.hw_attrs.max_mr_size)
		return ERR_PTR(-EINVAL);

	region = ib_umem_get(pd->device, start, len, access);

	if (IS_ERR(region)) {
		nser_dbg(iwdev_to_idev(iwdev),
			  "VERBS: Failed to create ib_umem region\n");
		return (struct ib_mr *)region;
	}

	if (ib_copy_from_udata(&req, udata, min(sizeof(req), udata->inlen))) {
		ib_umem_release(region);
		return ERR_PTR(-EFAULT);
	}

	iwmr = nser_alloc_iwmr(region, pd, virt, req.reg_type);
	if (IS_ERR(iwmr)) {
		ib_umem_release(region);
		return (struct ib_mr *)iwmr;
	}

	switch (req.reg_type) {
	case NSER_MEMREG_TYPE_QP:
		err = nser_reg_user_mr_type_qp(req, udata, iwmr);
		if (err)
			goto error;

		break;
	case NSER_MEMREG_TYPE_CQ:
		err = nser_reg_user_mr_type_cq(req, udata, iwmr);
		if (err)
			goto error;

		break;
	case NSER_MEMREG_TYPE_MEM:
		err = nser_reg_user_mr_type_mem(iwmr, access, true);
		if (err)
			goto error;
		break;
	default:
		err = -EINVAL;
		goto error;
	}

	return &iwmr->ibmr;

error:
	ib_umem_release(region);
	kfree(iwmr);

	return ERR_PTR(err);
}

int nser_hwdereg_mr(struct ib_mr *ib_mr)
{
	struct nser_device *iwdev = to_iwdev(ib_mr->device);
	struct nser_mr *iwmr = to_iwmr(ib_mr);
	struct nser_pd *iwpd = to_iwpd(ib_mr->pd);
	struct nser_dealloc_stag_info *info;
	struct nser_pbl *iwpbl = &iwmr->iwpbl;
	struct nser_cqp_request *cqp_request;
	struct cqp_cmds_info *cqp_info;
	int status;

	/* Skip HW MR de-register when it is already de-registered
	 * during an MR re-reregister and the re-registration fails
	 */
	if (!iwmr->is_hwreg)
		return 0;

	cqp_request = nser_alloc_and_get_cqp_request(&iwdev->rf->cqp, true);
	if (!cqp_request)
		return -ENOMEM;

	cqp_info = &cqp_request->info;
	info = &cqp_info->in.u.dealloc_stag.info;
	memset(info, 0, sizeof(*info));
	info->pd_id = iwpd->sc_pd.pd_id;
	info->stag_idx = RS_64_1(ib_mr->rkey, NSER_CQPSQ_STAG_IDX_S);
	info->mr = true;
	if (iwpbl->pbl_allocated)
		info->dealloc_pbl = true;

	cqp_info->cqp_cmd = NSER_OP_DEALLOC_STAG;
	cqp_info->post_sq = 1;
	cqp_info->in.u.dealloc_stag.dev = &iwdev->rf->sc_dev;
	cqp_info->in.u.dealloc_stag.scratch = (uintptr_t)cqp_request;
	status = nser_handle_cqp_op(iwdev->rf, cqp_request);
	nser_put_cqp_request(&iwdev->rf->cqp, cqp_request);

	if (!status)
		iwmr->is_hwreg = 0;

	return status;
}

/*
 * nser_rereg_mr_trans - Re-register a user MR for a change translation.
 * @iwmr: ptr of iwmr
 * @start: virtual start address
 * @len: length of mr
 * @virt: virtual address
 *
 * Re-register a user memory region when a change translation is requested.
 * Re-register a new region while reusing the stag from the original registration.
 */
struct ib_mr *nser_rereg_mr_trans(struct nser_mr *iwmr, u64 start, u64 len,
				   u64 virt, struct ib_udata *udata)
{
	struct nser_device *iwdev = to_iwdev(iwmr->ibmr.device);
	struct nser_pbl *iwpbl = &iwmr->iwpbl;
	struct ib_pd *pd = iwmr->ibmr.pd;
	struct ib_umem *region;
	int err;

	region = ib_umem_get(pd->device, start, len, iwmr->access);

	if (IS_ERR(region)) {
		nser_dbg(iwdev_to_idev(iwdev),
			  "VERBS: Failed to create ib_umem region\n");
		return (struct ib_mr *)region;
	}

	iwmr->region = region;
	iwmr->ibmr.iova = virt;
	iwmr->ibmr.pd = pd;

	iwmr->ib_umem_page_size = ib_umem_find_best_pgsz(region,
					iwdev->rf->sc_dev.hw_attrs.page_size_cap | PAGE_SIZE,
					virt);

	if (unlikely(!iwmr->ib_umem_page_size))
		iwmr->ib_umem_page_size = PAGE_SIZE;

	iwmr->page_size = cal_best_pble_page_size(iwmr->ib_umem_page_size);
	if (unlikely(!iwmr->page_size)) {
		err = -EOPNOTSUPP;
		goto error;
	}

	iwmr->len = region->length;
	iwpbl->user_base = virt;
	iwmr->page_cnt = ib_umem_num_dma_blocks(region, iwmr->page_size);

	err = nser_reg_user_mr_type_mem(iwmr, iwmr->access, false);
	if (err)
		goto error;

	return &iwmr->ibmr;

error:
	ib_umem_release(region);
	iwmr->region = NULL;
	return ERR_PTR(err);
}

/**
 * nser_reg_phys_mr - register kernel physical memory
 * @pd: ibpd pointer
 * @addr: physical address of memory to register
 * @size: size of memory to register
 * @access: Access rights
 * @iova_start: start of virtual address for physical buffers
 */
struct ib_mr *nser_reg_phys_mr(struct ib_pd *pd, u64 addr, u64 size, int access,
				u64 *iova_start)
{
	struct nser_device *iwdev = to_iwdev(pd->device);
	struct nser_pbl *iwpbl;
	struct nser_mr *iwmr;
	u32 stag;
	int ret;

	iwmr = kzalloc(sizeof(*iwmr), GFP_KERNEL);
	if (!iwmr)
		return ERR_PTR(-ENOMEM);

	iwmr->ibmr.pd = pd;
	iwmr->ibmr.device = pd->device;
	if (size == 0)
		return &iwmr->ibmr;
	iwpbl = &iwmr->iwpbl;
	iwpbl->iwmr = iwmr;
	iwmr->type = NSER_MEMREG_TYPE_MEM;
	iwpbl->user_base = *iova_start;
	stag = nser_create_stag(iwdev);
	if (!stag) {
		ret = -ENOMEM;
		goto err;
	}

	iwmr->stag = stag;
	iwmr->ibmr.iova = *iova_start;
	iwmr->ibmr.rkey = stag;
	iwmr->ibmr.lkey = stag;
	iwmr->page_cnt = 1;
	iwmr->pgaddrmem[0] = addr;
	iwmr->len = size;
	iwmr->page_size = SZ_4K;
	ret = nser_hwreg_mr(iwdev, iwmr, access);
	if (ret) {
		nser_free_stag(iwdev, stag);
		goto err;
	}

	return &iwmr->ibmr;

err:
	kfree(iwmr);

	return ERR_PTR(ret);
}

/**
 * nser_get_dma_mr - register physical mem
 * @pd: ptr of pd
 * @acc: access for memory
 */
static struct ib_mr *nser_get_dma_mr(struct ib_pd *pd, int acc)
{
	u64 kva = 0;

	return nser_reg_phys_mr(pd, 0, 0, acc, &kva);
}

/**
 * nser_del_memlist - Deleting pbl list entries for CQ/QP
 * @iwmr: iwmr for IB's user page addresses
 * @ucontext: ptr to user context
 */
void nser_del_memlist(struct nser_mr *iwmr,
		       struct nser_ucontext *ucontext)
{
	struct nser_pbl *iwpbl = &iwmr->iwpbl;
	unsigned long flags;

	switch (iwmr->type) {
	case NSER_MEMREG_TYPE_CQ:
		spin_lock_irqsave(&ucontext->cq_reg_mem_list_lock, flags);
		if (iwpbl->on_list) {
			iwpbl->on_list = false;
			list_del(&iwpbl->list);
		}
		spin_unlock_irqrestore(&ucontext->cq_reg_mem_list_lock, flags);
		break;
	case NSER_MEMREG_TYPE_QP:
		spin_lock_irqsave(&ucontext->qp_reg_mem_list_lock, flags);
		if (iwpbl->on_list) {
			iwpbl->on_list = false;
			list_del(&iwpbl->list);
		}
		spin_unlock_irqrestore(&ucontext->qp_reg_mem_list_lock, flags);
		break;
	default:
		break;
	}
}

/**
 * nser_copy_sg_list - copy sg list for qp
 * @sg_list: copied into sg_list
 * @sgl: copy from sgl
 * @num_sges: count of sg entries
 */
static void nser_copy_sg_list(struct nser_sge *sg_list, struct ib_sge *sgl,
			       int num_sges)
{
	unsigned int i;

	for (i = 0; i < num_sges; i++) {
		sg_list[i].tag_off = sgl[i].addr;
		sg_list[i].len = sgl[i].length;
		sg_list[i].stag = sgl[i].lkey;
	}
}

/**
 * nser_post_send -  kernel application wr
 * @ibqp: qp ptr for wr
 * @ib_wr: work request ptr
 * @bad_wr: return of bad wr if err
 */
static int nser_post_send(struct ib_qp *ibqp,
			   const struct ib_send_wr *ib_wr,
			   const struct ib_send_wr **bad_wr)
{
	struct nser_qp *iwqp;
	struct nser_qp_uk *ukqp;
	struct nser_sc_dev *dev;
	struct nser_post_sq_info info;
	int err = 0;
	unsigned long flags;
	bool inv_stag;
	struct nser_ah *ah;

	iwqp = to_iwqp(ibqp);
	ukqp = &iwqp->sc_qp.qp_uk;
	dev = &iwqp->iwdev->rf->sc_dev;

	if (iwqp->iwdev->rf->reset && ibqp->qp_num == 1 && ibqp->qp_type == IB_QPT_GSI)
		return -EBUSY;

	spin_lock_irqsave(&iwqp->lock, flags);
	while (ib_wr) {
		memset(&info, 0, sizeof(info));
		inv_stag = false;
		info.wr_id = (ib_wr->wr_id);
		if ((ib_wr->send_flags & IB_SEND_SIGNALED) || iwqp->sig_all)
			info.signaled = true;
		if (ib_wr->send_flags & IB_SEND_FENCE)
			info.read_fence = true;
		switch (ib_wr->opcode) {
		case IB_WR_ATOMIC_CMP_AND_SWP:
			if (unlikely(!(dev->hw_attrs.uk_attrs.feature_flags &
				       NSER_FEATURE_ATOMIC_OPS))) {
				err = EINVAL;
				break;
			}
			info.op_type = NSER_OP_TYPE_ATOMIC_COMPARE_AND_SWAP;
			info.op.atomic_compare_swap.tagged_offset = ib_wr->sg_list[0].addr;
			info.op.atomic_compare_swap.remote_tagged_offset =
				atomic_wr(ib_wr)->remote_addr;
			info.op.atomic_compare_swap.swap_data_bytes = atomic_wr(ib_wr)->swap;
			info.op.atomic_compare_swap.compare_data_bytes =
				atomic_wr(ib_wr)->compare_add;
			info.op.atomic_compare_swap.stag = ib_wr->sg_list[0].lkey;
			info.op.atomic_compare_swap.remote_stag = atomic_wr(ib_wr)->rkey;
			err = nser_uk_atomic_compare_swap(ukqp, &info, false);
			break;
		case IB_WR_ATOMIC_FETCH_AND_ADD:
			if (unlikely(!(dev->hw_attrs.uk_attrs.feature_flags &
				       NSER_FEATURE_ATOMIC_OPS))) {
				err = EINVAL;
				break;
			}
			info.op_type = NSER_OP_TYPE_ATOMIC_FETCH_AND_ADD;
			info.op.atomic_fetch_add.tagged_offset = ib_wr->sg_list[0].addr;
			info.op.atomic_fetch_add.remote_tagged_offset =
				atomic_wr(ib_wr)->remote_addr;
			info.op.atomic_fetch_add.fetch_add_data_bytes =
				atomic_wr(ib_wr)->compare_add;
			info.op.atomic_fetch_add.stag = ib_wr->sg_list[0].lkey;
			info.op.atomic_fetch_add.remote_stag = atomic_wr(ib_wr)->rkey;
			err = nser_uk_atomic_fetch_add(ukqp, &info, false);
			break;
		case IB_WR_SEND_WITH_IMM:
			if (ukqp->qp_caps & NSER_SEND_WITH_IMM) {
				info.imm_data_valid = true;
				info.imm_data = ntohl(ib_wr->ex.imm_data);
			} else {
				err = -EINVAL;
				break;
			}
			fallthrough;
		case IB_WR_SEND:
		case IB_WR_SEND_WITH_INV:
			if (ib_wr->opcode == IB_WR_SEND ||
			    ib_wr->opcode == IB_WR_SEND_WITH_IMM) {
				if (ib_wr->send_flags & IB_SEND_SOLICITED)
					info.op_type = NSER_OP_TYPE_SEND_SOL;
				else
					info.op_type = NSER_OP_TYPE_SEND;
			} else {
				if (ib_wr->send_flags & IB_SEND_SOLICITED)
					info.op_type = NSER_OP_TYPE_SEND_SOL_INV;
				else
					info.op_type = NSER_OP_TYPE_SEND_INV;
				info.stag_to_inv = ib_wr->ex.invalidate_rkey;
			}

			info.op.send.num_sges = ib_wr->num_sge;
			info.op.send.sg_list = (struct nser_sge *)ib_wr->sg_list;
			if (iwqp->ibqp.qp_type == IB_QPT_UD ||
			    iwqp->ibqp.qp_type == IB_QPT_GSI) {
				ah = to_iwah(ud_wr(ib_wr)->ah);
				info.op.send.ah_id = ah->sc_ah.ah_info.ah_idx;
				info.op.send.qkey = ud_wr(ib_wr)->remote_qkey;
				info.op.send.dest_qp = ud_wr(ib_wr)->remote_qpn;
			}
			if (iwqp->iwdev->roce_timely_en)
				info.report_rtt = 1;
			if (ib_wr->send_flags & IB_SEND_INLINE)
				err = nser_uk_inline_send(ukqp, &info, false);
			else
				err = nser_uk_send(ukqp, &info, false);
			break;
		case IB_WR_RDMA_WRITE_WITH_IMM:
			if (ukqp->qp_caps & NSER_WRITE_WITH_IMM) {
				info.imm_data_valid = true;
				info.imm_data = ntohl(ib_wr->ex.imm_data);
			} else {
				err = -EINVAL;
				break;
			}
			fallthrough;
		case IB_WR_RDMA_WRITE:
			if (ib_wr->send_flags & IB_SEND_SOLICITED)
				info.op_type = NSER_OP_TYPE_RDMA_WRITE_SOL;
			else
				info.op_type = NSER_OP_TYPE_RDMA_WRITE;

			info.op.rdma_write.num_lo_sges = ib_wr->num_sge;
			info.op.rdma_write.lo_sg_list = (void *)ib_wr->sg_list;
			info.op.rdma_write.rem_addr.tag_off = rdma_wr(ib_wr)->remote_addr;
			info.op.rdma_write.rem_addr.stag = rdma_wr(ib_wr)->rkey;
			if (iwqp->iwdev->roce_timely_en)
				info.report_rtt = 1;
			if (ib_wr->send_flags & IB_SEND_INLINE)
				err = nser_uk_inline_rdma_write(ukqp, &info, false);
			else
				err = nser_uk_rdma_write(ukqp, &info, false);
			break;
		case IB_WR_RDMA_READ_WITH_INV:
			inv_stag = true;
			fallthrough;
		case IB_WR_RDMA_READ:
			if (ib_wr->num_sge >
			    dev->hw_attrs.uk_attrs.max_hw_read_sges) {
				err = -EINVAL;
				break;
			}
			info.op_type = NSER_OP_TYPE_RDMA_READ;
			info.op.rdma_read.rem_addr.tag_off = rdma_wr(ib_wr)->remote_addr;
			info.op.rdma_read.rem_addr.stag = rdma_wr(ib_wr)->rkey;
			info.op.rdma_read.lo_sg_list = (void *)ib_wr->sg_list;
			info.op.rdma_read.num_lo_sges = ib_wr->num_sge;
			if (iwqp->iwdev->roce_timely_en)
				info.report_rtt = 1;
			err = nser_uk_rdma_read(ukqp, &info, inv_stag, false);
			break;
		case IB_WR_LOCAL_INV:
			info.op_type = NSER_OP_TYPE_INV_STAG;
			info.op.inv_local_stag.target_stag = ib_wr->ex.invalidate_rkey;
			err = nser_uk_stag_local_invalidate(ukqp, &info, true);
			break;
		case IB_WR_REG_MR: {
			struct nser_mr *iwmr = to_iwmr(reg_wr(ib_wr)->mr);
			struct nser_pble_alloc *palloc = &iwmr->iwpbl.pble_alloc;
			struct nser_fast_reg_stag_info stag_info = {};

			stag_info.signaled = info.signaled;
			stag_info.read_fence = info.read_fence;
			stag_info.access_rights = nser_get_mr_access(reg_wr(ib_wr)->access);
			stag_info.stag_key = reg_wr(ib_wr)->key & 0xff;
			stag_info.stag_idx = reg_wr(ib_wr)->key >> 8;
			stag_info.page_size = cal_best_pble_page_size(reg_wr(ib_wr)->mr->page_size);
			stag_info.wr_id = ib_wr->wr_id;
			stag_info.addr_type = NSER_ADDR_TYPE_VA_BASED;
			stag_info.va = (void *)(uintptr_t)iwmr->ibmr.iova;
			stag_info.total_len = iwmr->ibmr.length;
			if (palloc->level == PBLE_LEVEL_2) {
				stag_info.chunk_size = 3;
				stag_info.first_pm_pbl_index = palloc->level2.root.idx;
			} else {
				stag_info.chunk_size = 1;
				stag_info.first_pm_pbl_index = palloc->level1.idx;
			}
			stag_info.local_fence = ib_wr->send_flags & IB_SEND_FENCE;
			err = nser_sc_mr_fast_register(&iwqp->sc_qp, &stag_info,
							true);
			break;
		}
		default:
			err = -EINVAL;
			nser_dbg(iwdev_to_idev(iwqp->iwdev),
				  "VERBS: upost_send bad opcode = 0x%x\n",
				  ib_wr->opcode);
			break;
		}

		if (err)
			break;
		ib_wr = ib_wr->next;
	}

	if (!iwqp->flush_issued) {
		if (iwqp->hw_rdma_state <= NSER_QP_STATE_RTS)
			nser_uk_qp_post_wr(ukqp);
		spin_unlock_irqrestore(&iwqp->lock, flags);
	} else {
		spin_unlock_irqrestore(&iwqp->lock, flags);
		nser_sched_qp_flush_work(iwqp);
	}

	if (err)
		*bad_wr = ib_wr;

	return err;
}

/**
 * nser_post_recv - post receive wr for kernel application
 * @ibqp: ib qp pointer
 * @ib_wr: work request for receive
 * @bad_wr: bad wr caused an error
 */
static int nser_post_recv(struct ib_qp *ibqp,
			   const struct ib_recv_wr *ib_wr,
			   const struct ib_recv_wr **bad_wr)
{
	struct nser_qp *iwqp = to_iwqp(ibqp);
	struct nser_qp_uk *ukqp = &iwqp->sc_qp.qp_uk;
	struct nser_post_rq_info post_recv = {};
	struct nser_sge *sg_list = iwqp->sg_list;
	unsigned long flags;
	int err = 0;

	spin_lock_irqsave(&iwqp->lock, flags);

	while (ib_wr) {
		if (ib_wr->num_sge > ukqp->max_rq_frag_cnt) {
			err = -EINVAL;
			goto out;
		}
		post_recv.num_sges = ib_wr->num_sge;
		post_recv.wr_id = ib_wr->wr_id;
		nser_copy_sg_list(sg_list, ib_wr->sg_list, ib_wr->num_sge);
		post_recv.sg_list = sg_list;
		err = nser_uk_post_receive(ukqp, &post_recv);
		if (err) {
			nser_dbg(iwdev_to_idev(iwqp->iwdev),
				  "VERBS: post_recv err %d\n", err);
			goto out;
		}

		ib_wr = ib_wr->next;
	}

out:
	spin_unlock_irqrestore(&iwqp->lock, flags);
	if (iwqp->flush_issued)
		nser_sched_qp_flush_work(iwqp);
	if (err)
		*bad_wr = ib_wr;

	return err;
}

/**
 * nser_flush_err_to_ib_wc_status - return change flush error code to IB status
 * @flush_opcode: flush code
 * @q_type: qp type, SQ or RQ
 * @opcode: qp op code
 */
static enum ib_wc_status nser_flush_err_to_ib_wc_status(u16 flush_opcode, u8 q_type, u8 opcode)
{
	switch (flush_opcode) {
	case EC_IB_REMOTE_OP_ERROR:
		return IB_WC_REM_OP_ERR;
	case EC_IB_REMOTE_ACCESS_ERR:
		return IB_WC_REM_ACCESS_ERR;
	case EC_INVALID_AH_ENTRY:
	case EC_AH_PD_MISMATCH:
	case AE_INVALID_ARP_ENTRY:
		return IB_WC_LOC_QP_OP_ERR;
	case EC_IBSEND_EXCEED_RQE:
		return IB_WC_LOC_LEN_ERR;
	case EC_WQE_FLUSHED:
		return IB_WC_WR_FLUSH_ERR;
	case EC_ERR_RETRY_EXCEED:
		return IB_WC_RETRY_EXC_ERR;
	case EC_RNR_RETRY_EXCEED:
		return IB_WC_RNR_RETRY_EXC_ERR;
	case EC_RDMA_READ_WHILE_ORD_ZERO:
	case EC_IBREQ_UNSUPORT_OPCODE:
	case EC_IBREQ_BAD_PADCNT:
	case EC_IBREQ_PYLD_PMTU_ERR:
	case EC_IBREAD_PYLD_NONEZERO:
	case EC_IBWRITE_DMALEN_ERR:
	case EC_IBREAD_DMALEN_ERR:
	case EC_IBWRITE_DMALEN_PYLD_MISMATCH:
	case EC_IBREQ_OPCODE_SEQ_ERR:
	case EC_RDRSP_DMALEN_PYLD_MISMATCH:
	case EC_RDRSP_BAD_PADCNT:
	case EC_RDRSP_PYLD_PMTU_ERR:
		return IB_WC_GENERAL_ERR;
	case EC_REQ_BAD_RESP:
		return IB_WC_BAD_RESP_ERR;
	case EC_AMP_UNALLOCATED_STAG:
	case EC_AMP_INVALID_STAG:
	case EC_AMP_BAD_QP:
	case EC_AMP_BAD_PD:
	case EC_AMP_BAD_STAG_KEY:
	case EC_AMP_BAD_STAG_INDEX:
	case EC_AMP_BOUNDS_VIOLATION:
	case EC_AMP_RIGHTS_VIOLATION:
	case EC_AMP_TO_WRAP:
	case EC_PRIV_OP_DENIED:
	case EC_STAG_ZERO_INVALID:
		if (q_type == NSER_CQE_QTYPE_SQ) {
			switch (opcode)
			case NSER_OP_TYPE_SEND_SOL:
			case NSER_OP_TYPE_SEND_SOL_INV:
			case NSER_OP_TYPE_SEND_INV:
			case NSER_OP_TYPE_SEND:
			case NSER_OP_TYPE_RDMA_WRITE:
			case NSER_OP_TYPE_RDMA_WRITE_SOL:
			case NSER_OP_TYPE_RDMA_READ_INV_STAG:
			case NSER_OP_TYPE_RDMA_READ:
				return IB_WC_LOC_PROT_ERR;
		} else if (q_type == NSER_CQE_QTYPE_RQ) {
			switch (opcode)
			case NSER_OP_TYPE_RDMA_WRITE:
			case NSER_OP_TYPE_RDMA_WRITE_SOL:
				return IB_WC_LOC_ACCESS_ERR;
		}
		return IB_WC_FATAL_ERR;
	default:
		return IB_WC_FATAL_ERR;
	}
}

static inline void set_ib_wc_op_sq(struct nser_cq_poll_info *cq_poll_info,
				   struct ib_wc *entry)
{
	struct nser_sc_qp *qp;

	switch (cq_poll_info->op_type) {
	case NSER_OP_TYPE_RDMA_WRITE:
	case NSER_OP_TYPE_RDMA_WRITE_SOL:
		entry->opcode = IB_WC_RDMA_WRITE;
		break;
	case NSER_OP_TYPE_RDMA_READ_INV_STAG:
	case NSER_OP_TYPE_RDMA_READ:
		entry->opcode = IB_WC_RDMA_READ;
		break;
	case NSER_OP_TYPE_SEND_SOL:
	case NSER_OP_TYPE_SEND_SOL_INV:
	case NSER_OP_TYPE_SEND_INV:
	case NSER_OP_TYPE_SEND:
		entry->opcode = IB_WC_SEND;
		break;
	case NSER_OP_TYPE_FAST_REG_NSMR:
		entry->opcode = IB_WC_REG_MR;
		break;
	case NSER_OP_TYPE_INV_STAG:
		entry->opcode = IB_WC_LOCAL_INV;
		break;
	default:
		qp = cq_poll_info->qp_handle;
		ibdev_err(nser_get_ibdev(qp->dev), "Invalid opcode = %d in CQE\n",
			  cq_poll_info->op_type);
		entry->status = IB_WC_GENERAL_ERR;
	}
}

static inline void set_ib_wc_op_rq(struct nser_cq_poll_info *cq_poll_info,
				   struct ib_wc *entry, bool send_imm_support)
{
	struct nser_qp_uk *qp = cq_poll_info->qp_handle;

	if (qp->uk_attrs->hw_rev >= 3) {
#define CQ_OP_RECV_SEND			0
#define CQ_OP_RECV_RDMA_WITH_IMM	1
		switch (cq_poll_info->op_type) {
		case CQ_OP_RECV_SEND:
			entry->opcode = IB_WC_RECV;
			break;
		case CQ_OP_RECV_RDMA_WITH_IMM:
			entry->opcode = IB_WC_RECV_RDMA_WITH_IMM;
			break;
		default:
			entry->opcode = IB_WC_RECV;
		}
	} else {
		if (cq_poll_info->imm_valid && cq_poll_info->stag_invalid_set) {
			entry->opcode = IB_WC_RECV_RDMA_WITH_IMM;
			cq_poll_info->stag_invalid_set = false;
		} else {
			entry->opcode = IB_WC_RECV;
		}
	}
}

/**
 * nser_process_cqe - process cqe info
 * @entry: processed cqe
 * @cq_poll_info: cqe info
 */
static void nser_process_cqe(struct ib_wc *entry,
			      struct nser_cq_poll_info *cq_poll_info)
{
	struct nser_sc_qp *qp;

	entry->wc_flags = 0;
	entry->pkey_index = 0;
	entry->wr_id = cq_poll_info->wr_id;

	qp = cq_poll_info->qp_handle;
	entry->qp = qp->qp_uk.back_qp;

	if (cq_poll_info->error) {
		entry->status = (cq_poll_info->comp_status == NSER_COMPL_STATUS_FLUSHED) ?
				nser_flush_err_to_ib_wc_status(cq_poll_info->minor_err,
					cq_poll_info->q_type, cq_poll_info->op_type)
					: IB_WC_GENERAL_ERR;

		entry->vendor_err = cq_poll_info->major_err << 16 |
				    cq_poll_info->minor_err;
	} else {
		entry->status = IB_WC_SUCCESS;
		if (cq_poll_info->imm_valid) {
			entry->ex.imm_data = htonl(cq_poll_info->imm_data);
			entry->wc_flags |= IB_WC_WITH_IMM;
		}
		if (cq_poll_info->ud_smac_valid) {
			ether_addr_copy(entry->smac, cq_poll_info->ud_smac);
			entry->wc_flags |= IB_WC_WITH_SMAC;
		}

		if (cq_poll_info->ud_vlan_valid && (dev_to_rf(qp->dev))->vlan_parse_en) {
			u16 vlan = cq_poll_info->ud_vlan & VLAN_VID_MASK;

			entry->sl = cq_poll_info->ud_vlan >> VLAN_PRIO_SHIFT;
			if (vlan) {
				entry->vlan_id = vlan;
				entry->wc_flags |= IB_WC_WITH_VLAN;
			}
		} else {
			entry->sl = 0;
		}
	}

	if (cq_poll_info->q_type == NSER_CQE_QTYPE_SQ) {
		set_ib_wc_op_sq(cq_poll_info, entry);
	} else {
		set_ib_wc_op_rq(cq_poll_info, entry,
				qp->qp_uk.qp_caps & NSER_SEND_WITH_IMM ?
				true : false);
		if (qp->qp_uk.qp_type != NSER_QP_TYPE_ROCE_UD &&
		    cq_poll_info->stag_invalid_set) {
			entry->ex.invalidate_rkey = cq_poll_info->inv_stag;
			entry->wc_flags |= IB_WC_WITH_INVALIDATE;
		}
	}

	if (qp->qp_uk.qp_type == NSER_QP_TYPE_ROCE_UD) {
		entry->src_qp = cq_poll_info->ud_src_qpn;
		entry->slid = 0;
		entry->wc_flags |=
			(IB_WC_GRH | IB_WC_WITH_NETWORK_HDR_TYPE);
		entry->network_hdr_type = cq_poll_info->ipv4 ?
						  RDMA_NETWORK_IPV4 :
						  RDMA_NETWORK_IPV6;
	} else {
		entry->src_qp = cq_poll_info->qp_id;
	}

	entry->byte_len = cq_poll_info->bytes_xfered;
}

/**
 * nser_poll_one - poll one entry of the CQ
 * @ukcq: ukcq to poll
 * @cur_cqe: current CQE info to be filled in
 * @entry: ibv_wc object to be filled for non-extended CQ or NULL for extended CQ
 *
 * Returns the internal nser device error code or 0 on success
 */
static inline int nser_poll_one(struct nser_cq_uk *ukcq,
				 struct nser_cq_poll_info *cur_cqe,
				 struct ib_wc *entry)
{
	int ret = nser_uk_cq_poll_cmpl(ukcq, cur_cqe);

	if (ret)
		return ret;

	nser_process_cqe(entry, cur_cqe);

	return 0;
}

/**
 * __nser_poll_cq - poll cq for completion (kernel apps)
 * @iwcq: cq to poll
 * @num_entries: number of entries to poll
 * @entry: wr of a completed entry
 */
static int __nser_poll_cq(struct nser_cq *iwcq, int num_entries, struct ib_wc *entry)
{
	struct list_head *tmp_node, *list_node;
	struct nser_cq_buf *last_buf = NULL;
	struct nser_cq_poll_info *cur_cqe = &iwcq->cur_cqe;
	struct nser_cq_buf *cq_buf;
	int ret;
	struct nser_device *iwdev;
	struct nser_cq_uk *ukcq;
	bool cq_new_cqe = false;
	int resized_bufs = 0;
	int npolled = 0;

	iwdev = to_iwdev(iwcq->ibcq.device);
	ukcq = &iwcq->sc_cq.cq_uk;

	/* go through the list of previously resized CQ buffers */
	list_for_each_safe(list_node, tmp_node, &iwcq->resize_list) {
		cq_buf = container_of(list_node, struct nser_cq_buf, list);
		while (npolled < num_entries) {
			ret = nser_poll_one(&cq_buf->cq_uk, cur_cqe, entry + npolled);
			if (!ret) {
				++npolled;
				cq_new_cqe = true;
				continue;
			}
			if (ret == -ENOENT)
				break;
			 /* QP using the CQ is destroyed. Skip reporting this CQE */
			if (ret == -EFAULT) {
				cq_new_cqe = true;
				continue;
			}
			goto error;
		}

		/* save the resized CQ buffer which received the last cqe */
		if (cq_new_cqe)
			last_buf = cq_buf;
		cq_new_cqe = false;
	}

	/* check the current CQ for new cqes */
	while (npolled < num_entries) {
		ret = nser_poll_one(ukcq, cur_cqe, entry + npolled);
		if (ret == -ENOENT) {
			ret = nser_generated_cmpls(iwcq, cur_cqe);
			if (!ret)
				nser_process_cqe(entry + npolled, cur_cqe);
		}
		if (!ret) {
			++npolled;
			cq_new_cqe = true;
			continue;
		}

		if (ret == -ENOENT)
			break;
		/* QP using the CQ is destroyed. Skip reporting this CQE */
		if (ret == -EFAULT) {
			cq_new_cqe = true;
			continue;
		}
		goto error;
	}

	if (cq_new_cqe)
		/* all previous CQ resizes are complete */
		resized_bufs = nser_process_resize_list(iwcq, iwdev, NULL);
	else if (last_buf)
		/* only CQ resizes up to the last_buf are complete */
		resized_bufs = nser_process_resize_list(iwcq, iwdev, last_buf);
	if (resized_bufs)
		/* report to the HW the number of complete CQ resizes */
		nser_uk_cq_set_resized_cnt(ukcq, resized_bufs);

	return npolled;
error:
	nser_dbg(iwdev_to_idev(iwdev),
		  "VERBS: %s: Error polling CQ, nser_err: %d\n", __func__,
		  ret);

	return ret;
}

/**
 * nser_poll_cq - poll cq for completion (kernel apps)
 * @ibcq: cq to poll
 * @num_entries: number of entries to poll
 * @entry: wr of a completed entry
 */
static int nser_poll_cq(struct ib_cq *ibcq, int num_entries,
			 struct ib_wc *entry)
{
	struct nser_cq *iwcq;
	unsigned long flags;
	int ret;

	iwcq = to_iwcq(ibcq);

	spin_lock_irqsave(&iwcq->lock, flags);
	ret = __nser_poll_cq(iwcq, num_entries, entry);
	spin_unlock_irqrestore(&iwcq->lock, flags);

	return ret;
}

/**
 * nser_req_notify_cq - arm cq kernel application
 * @ibcq: cq to arm
 * @notify_flags: notofication flags
 */
static int nser_req_notify_cq(struct ib_cq *ibcq,
			       enum ib_cq_notify_flags notify_flags)
{
	struct nser_cq *iwcq;
	struct nser_cq_uk *ukcq;
	unsigned long flags;
	enum nser_cmpl_notify cq_notify = NSER_CQ_COMPL_EVENT;
	bool promo_event = false;
	int ret = 0;

	iwcq = to_iwcq(ibcq);
	ukcq = &iwcq->sc_cq.cq_uk;

	if (!iwcq->ceq_id_valid_flag) {
		ret = nser_resize_cq(ibcq, iwcq->sc_cq.cq_uk.cq_size, NULL);
		if (ret)
			return ret;
		iwcq->ceq_id_valid_flag = true;
	}

	spin_lock_irqsave(&iwcq->lock, flags);
	if (notify_flags == IB_CQ_SOLICITED) {
		cq_notify = NSER_CQ_COMPL_SOLICITED;
	} else {
		if (iwcq->last_notify == NSER_CQ_COMPL_SOLICITED)
			promo_event = true;
	}

	if (!atomic_cmpxchg(&iwcq->armed, 0, 1) || promo_event) {
		iwcq->last_notify = cq_notify;
		nser_uk_cq_request_notification(ukcq, cq_notify);
	}

	if ((notify_flags & IB_CQ_REPORT_MISSED_EVENTS) &&
	    (!nser_cq_empty(iwcq) || !list_empty(&iwcq->cmpl_generated)))
		ret = 1;
	spin_unlock_irqrestore(&iwcq->lock, flags);

	return ret;
}

const struct rdma_stat_desc nser_hw_stat_descs[] = {
	[NSER_HW_STAT_INDEX_RX_VLAN_ERR].name		= "rxVlanErrors",

	[NSER_HW_STAT_INDEX_IPV4_RX_OCTS].name		= "ip4InOctets",
	[NSER_HW_STAT_INDEX_IPV4_RX_PKTS].name		= "ip4InPkts",
	[NSER_HW_STAT_INDEX_IPV4_RX_DISCARD].name	= "ip4InDiscards",
	[NSER_HW_STAT_INDEX_IPV4_RX_MCOCTS].name	= "ip4InMcastOctets",
	[NSER_HW_STAT_INDEX_IPV4_RX_MCPKTS].name	= "ip4InMcastPkts",

	[NSER_HW_STAT_INDEX_IPV6_RX_OCTS].name		= "ip6InOctets",
	[NSER_HW_STAT_INDEX_IPV6_RX_PKTS].name		= "ip6InPkts",
	[NSER_HW_STAT_INDEX_IPV6_RX_DISCARD].name	= "ip6InDiscards",
	[NSER_HW_STAT_INDEX_IPV6_RX_MCOCTS].name	= "ip6InMcastOctets",
	[NSER_HW_STAT_INDEX_IPV6_RX_MCPKTS].name	= "ip6InMcastPkts",

	[NSER_HW_STAT_INDEX_IPV4_TX_OCTS].name		= "ip4OutOctets",
	[NSER_HW_STAT_INDEX_IPV4_TX_PKTS].name		= "ip4OutPkts",
	[NSER_HW_STAT_INDEX_IPV4_TX_MCOTS].name		= "ip4OutMcastOctets",
	[NSER_HW_STAT_INDEX_IPV4_TX_MCPKTS].name	= "ip4OutMcastPkts",

	[NSER_HW_STAT_INDEX_IPV6_TX_OCTS].name		= "ip6OutOctets",
	[NSER_HW_STAT_INDEX_IPV6_TX_PKTS].name		= "ip6OutPkts",
	[NSER_HW_STAT_INDEX_IPV6_TX_MCOTS].name		= "ip6OutMcastOctets",
	[NSER_HW_STAT_INDEX_IPV6_TX_MCPKTS].name	= "ip6OutMcastPkts",

	[NSER_HW_STAT_INDEX_RDMA_RX_WRS].name		= "InRdmaWrites",
	[NSER_HW_STAT_INDEX_RDMA_RX_RDS].name		= "InRdmaReads",
	[NSER_HW_STAT_INDEX_RDMA_RX_SNDS].name		= "InRdmaSends",

	[NSER_HW_STAT_INDEX_RDMA_TX_WRS].name		= "OutRdmaWrites",
	[NSER_HW_STAT_INDEX_RDMA_TX_RDS].name		= "OutRdmaReads",
	[NSER_HW_STAT_INDEX_RDMA_TX_SNDS].name		= "OutRdmaSends",

	[NSER_HW_STAT_INDEX_RX_ECN_MARKED_PKTS].name	= "RxECNMrkd",
	[NSER_HW_STAT_INDEX_TX_REPKTS].name				= "OutRetransPackets",

	[NSER_HW_STAT_INDEX_RDMA_RX_ACK_PKT].name	= "RdmaInAckPkts",
	[NSER_HW_STAT_INDEX_RDMA_RX_NAK_PKT].name	= "RdmaInNakPkts",
	[NSER_HW_STAT_INDEX_RDMA_RX_RNR_PKT].name	= "RdmaInRnrPkts",
	[NSER_HW_STAT_INDEX_RDMA_RX_DUP_PKT].name	= "RdmaInDupPkts",
	[NSER_HW_STAT_INDEX_RDMA_RX_INV_PKT].name	= "RdmaInInvPkts",

	[NSER_HW_STAT_INDEX_RDMA_TX_ACK_PKT].name	= "RdmaOutAckPkts",
	[NSER_HW_STAT_INDEX_RDMA_TX_NAK_PKT].name = "RdmaOutNakPkts",
	[NSER_HW_STAT_INDEX_RDMA_TX_RNR_PKT].name = "RdmaOutRnrPkts",

	[NSER_HW_STAT_INDEX_RDMA_RX_UDDROP].name	= "RxUdDrop",
	[NSER_HW_STAT_INDEX_RX_CNP_IGNORED].name	= "cnpIgnored",

	[NSER_HW_STAT_INDEX_RX_CNP_HANDLED].name = "cnpHandled",
	[NSER_HW_STAT_INDEX_TX_CNPSENT].name = "cnpSent",

	[NSER_HW_STAT_INDEX_VBND].name	= "RdmaBnd",
	[NSER_HW_STAT_INDEX_VINV].name	= "RdmaInv",
	[NSER_HW_STAT_INDEX_FRM].name	= "FastRegPhyMem",
};

/**
 * mcast_list_add -  Add a new mcast item to list
 * @rf: RDMA PCI function
 * @new_elem: pointer to element to add
 */
static void mcast_list_add(struct nser_pci_f *rf,
			   struct mc_table_list *new_elem)
{
	list_add(&new_elem->list, &rf->mc_qht_list.list);
}

/**
 * mcast_list_del - Remove an mcast item from list
 * @mc_qht_elem: pointer to mcast table list element
 */
static void mcast_list_del(struct mc_table_list *mc_qht_elem)
{
	if (mc_qht_elem)
		list_del(&mc_qht_elem->list);
}

/**
 * mcast_list_lookup_ip - Search mcast list for address
 * @rf: RDMA PCI function
 * @ip_mcast: pointer to mcast IP address
 */
static struct mc_table_list *mcast_list_lookup_ip(struct nser_pci_f *rf,
						  u32 *ip_mcast)
{
	struct mc_table_list *mc_qht_el;
	struct list_head *pos, *q;

	list_for_each_safe(pos, q, &rf->mc_qht_list.list) {
		mc_qht_el = list_entry(pos, struct mc_table_list, list);
		if (!memcmp(mc_qht_el->mc_info.dest_ip, ip_mcast,
			    sizeof(mc_qht_el->mc_info.dest_ip)))
			return mc_qht_el;
	}

	return NULL;
}

/**
 * nser_mcast_cqp_op - perform a mcast cqp operation
 * @iwdev: nser device
 * @mc_grp_ctx: mcast group info
 * @op: operation
 *
 * returns error status
 */
static int nser_mcast_cqp_op(struct nser_device *iwdev,
			      struct nser_mcast_grp_info *mc_grp_ctx, u8 op)
{
	struct cqp_cmds_info *cqp_info;
	struct nser_cqp_request *cqp_request;
	int status;

	cqp_request = nser_alloc_and_get_cqp_request(&iwdev->rf->cqp, true);
	if (!cqp_request)
		return -ENOMEM;

	cqp_request->info.in.u.mc_create.info = *mc_grp_ctx;
	cqp_info = &cqp_request->info;
	cqp_info->cqp_cmd = op;
	cqp_info->post_sq = 1;
	cqp_info->in.u.mc_create.scratch = (uintptr_t)cqp_request;
	cqp_info->in.u.mc_create.cqp = &iwdev->rf->cqp.sc_cqp;
	status = nser_handle_cqp_op(iwdev->rf, cqp_request);
	nser_put_cqp_request(&iwdev->rf->cqp, cqp_request);

	return status;
}

/**
 * nser_attach_mcast - attach a qp to a multicast group
 * @ibqp: ptr to qp
 * @ibgid: pointer to global ID
 * @lid: local ID
 *
 * returns error status
 */
static int nser_attach_mcast(struct ib_qp *ibqp, union ib_gid *ibgid, u16 lid)
{
	struct nser_qp *iwqp = to_iwqp(ibqp);
	struct nser_device *iwdev = iwqp->iwdev;
	struct nser_pci_f *rf = iwdev->rf;
	struct mc_table_list *mc_qht_elem;
	struct nser_mcast_grp_ctx_entry_info mcg_info = {};
	unsigned long flags;
	u32 ip_addr[4] = {};
	u32 mgn;
	u32 no_mgs;
	int ret = 0;
	bool ipv4;
	u16 vlan_id;
	union {
		struct sockaddr saddr;
		struct sockaddr_in saddr_in;
		struct sockaddr_in6 saddr_in6;
	} sgid_addr;
	unsigned char dmac[ETH_ALEN];

	rdma_gid2ip((struct sockaddr *)&sgid_addr, ibgid);

	if (!ipv6_addr_v4mapped((struct in6_addr *)ibgid)) {
		nser_copy_ip_ntohl(ip_addr,
				    sgid_addr.saddr_in6.sin6_addr.in6_u.u6_addr32);
		nser_netdev_vlan_ipv6(ip_addr, &vlan_id, NULL);
		ipv4 = false;
		nser_dbg(iwdev_to_idev(iwdev),
			  "VERBS: qp_id=%d, IP6address=%pI6\n", ibqp->qp_num,
			  ip_addr);
		nser_mcast_mac_v6(ip_addr, dmac);
	} else {
		ip_addr[0] = ntohl(sgid_addr.saddr_in.sin_addr.s_addr);
		ipv4 = true;
		vlan_id = nser_get_vlan_ipv4(ip_addr);
		nser_mcast_mac_v4(ip_addr, dmac);
		nser_dbg(iwdev_to_idev(iwdev),
			  "VERBS: qp_id=%d, IP4address=%pI4, MAC=%pM\n",
			  ibqp->qp_num, ip_addr, dmac);
	}

	spin_lock_irqsave(&rf->qh_list_lock, flags);
	mc_qht_elem = mcast_list_lookup_ip(rf, ip_addr);
	if (!mc_qht_elem) {
		struct nser_dma_mem *dma_mem_mc;

		spin_unlock_irqrestore(&rf->qh_list_lock, flags);
		mc_qht_elem = kzalloc(sizeof(*mc_qht_elem), GFP_KERNEL);
		if (!mc_qht_elem)
			return -ENOMEM;

		mc_qht_elem->mc_info.ipv4_valid = ipv4;
		memcpy(mc_qht_elem->mc_info.dest_ip, ip_addr,
		       sizeof(mc_qht_elem->mc_info.dest_ip));
		ret = nser_alloc_rsrc(rf, rf->allocated_mcgs, rf->max_mcg,
				       &mgn, &rf->next_mcg);
		if (ret) {
			kfree(mc_qht_elem);
			return -ENOMEM;
		}

		mc_qht_elem->mc_info.mgn = mgn;
		dma_mem_mc = &mc_qht_elem->mc_grp_ctx.dma_mem_mc;
		dma_mem_mc->size = ALIGN(sizeof(u64) * NSER_MAX_MGS_PER_CTX,
					 NSER_HW_PAGE_SIZE);
		dma_mem_mc->va = dma_alloc_coherent(rf->hw.device,
						    dma_mem_mc->size,
						    &dma_mem_mc->pa,
						    GFP_KERNEL);
		if (!dma_mem_mc->va) {
			nser_free_rsrc(rf, rf->allocated_mcgs, mgn);
			kfree(mc_qht_elem);
			return -ENOMEM;
		}

		mc_qht_elem->mc_grp_ctx.mg_id = (u16)mgn;
		memcpy(mc_qht_elem->mc_grp_ctx.dest_ip_addr, ip_addr,
		       sizeof(mc_qht_elem->mc_grp_ctx.dest_ip_addr));
		mc_qht_elem->mc_grp_ctx.ipv4_valid = ipv4;
		mc_qht_elem->mc_grp_ctx.vlan_id = vlan_id;
		if (vlan_id < VLAN_N_VID)
			mc_qht_elem->mc_grp_ctx.vlan_valid = true;
		mc_qht_elem->mc_grp_ctx.hmc_fcn_id = iwdev->rf->sc_dev.hmc_fn_id;
		mc_qht_elem->mc_grp_ctx.qs_handle =
			iwqp->sc_qp.vsi->qos[iwqp->sc_qp.user_pri].qs_handle;
		ether_addr_copy(mc_qht_elem->mc_grp_ctx.dest_mac_addr, dmac);

		spin_lock_irqsave(&rf->qh_list_lock, flags);
		mcast_list_add(rf, mc_qht_elem);
	} else {
		if (mc_qht_elem->mc_grp_ctx.no_of_mgs ==
		    NSER_MAX_MGS_PER_CTX) {
			spin_unlock_irqrestore(&rf->qh_list_lock, flags);
			return -ENOMEM;
		}
	}

	mcg_info.qp_id = iwqp->ibqp.qp_num;
	no_mgs = mc_qht_elem->mc_grp_ctx.no_of_mgs;
	nser_sc_add_mcast_grp(&mc_qht_elem->mc_grp_ctx, &mcg_info);
	spin_unlock_irqrestore(&rf->qh_list_lock, flags);

	/* Only if there is a change do we need to modify or create */
	if (!no_mgs) {
		ret = nser_mcast_cqp_op(iwdev, &mc_qht_elem->mc_grp_ctx,
					 NSER_OP_MC_CREATE);
	} else if (no_mgs != mc_qht_elem->mc_grp_ctx.no_of_mgs) {
		ret = nser_mcast_cqp_op(iwdev, &mc_qht_elem->mc_grp_ctx,
					 NSER_OP_MC_MODIFY);
	} else {
		return 0;
	}

	if (ret)
		goto error;

	return 0;

error:
	nser_sc_del_mcast_grp(&mc_qht_elem->mc_grp_ctx, &mcg_info);
	if (!mc_qht_elem->mc_grp_ctx.no_of_mgs) {
		mcast_list_del(mc_qht_elem);
		dma_free_coherent(rf->hw.device,
				  mc_qht_elem->mc_grp_ctx.dma_mem_mc.size,
				  mc_qht_elem->mc_grp_ctx.dma_mem_mc.va,
				  mc_qht_elem->mc_grp_ctx.dma_mem_mc.pa);
		mc_qht_elem->mc_grp_ctx.dma_mem_mc.va = NULL;
		nser_free_rsrc(rf, rf->allocated_mcgs,
				mc_qht_elem->mc_grp_ctx.mg_id);
		kfree(mc_qht_elem);
	}

	return ret;
}

/**
 * nser_detach_mcast - detach a qp from a multicast group
 * @ibqp: ptr to qp
 * @ibgid: pointer to global ID
 * @lid: local ID
 *
 * returns error status
 */
static int nser_detach_mcast(struct ib_qp *ibqp, union ib_gid *ibgid, u16 lid)
{
	struct nser_qp *iwqp = to_iwqp(ibqp);
	struct nser_device *iwdev = iwqp->iwdev;
	struct nser_pci_f *rf = iwdev->rf;
	u32 ip_addr[4] = {};
	struct mc_table_list *mc_qht_elem;
	struct nser_mcast_grp_ctx_entry_info mcg_info = {};
	int ret;
	unsigned long flags;
	union {
		struct sockaddr saddr;
		struct sockaddr_in saddr_in;
		struct sockaddr_in6 saddr_in6;
	} sgid_addr;

	rdma_gid2ip((struct sockaddr *)&sgid_addr, ibgid);
	if (!ipv6_addr_v4mapped((struct in6_addr *)ibgid))
		nser_copy_ip_ntohl(ip_addr,
				    sgid_addr.saddr_in6.sin6_addr.in6_u.u6_addr32);
	else
		ip_addr[0] = ntohl(sgid_addr.saddr_in.sin_addr.s_addr);

	spin_lock_irqsave(&rf->qh_list_lock, flags);
	mc_qht_elem = mcast_list_lookup_ip(rf, ip_addr);
	if (!mc_qht_elem) {
		spin_unlock_irqrestore(&rf->qh_list_lock, flags);
		nser_dbg(iwdev_to_idev(iwdev),
			  "VERBS: address not found MCG\n");
		return 0;
	}

	mcg_info.qp_id = iwqp->ibqp.qp_num;
	nser_sc_del_mcast_grp(&mc_qht_elem->mc_grp_ctx, &mcg_info);
	if (!mc_qht_elem->mc_grp_ctx.no_of_mgs) {
		mcast_list_del(mc_qht_elem);
		spin_unlock_irqrestore(&rf->qh_list_lock, flags);
		ret = nser_mcast_cqp_op(iwdev, &mc_qht_elem->mc_grp_ctx,
					 NSER_OP_MC_DESTROY);
		if (ret) {
			nser_dbg(iwdev_to_idev(iwdev),
				  "VERBS: failed MC_DESTROY MCG\n");
			spin_lock_irqsave(&rf->qh_list_lock, flags);
			mcast_list_add(rf, mc_qht_elem);
			spin_unlock_irqrestore(&rf->qh_list_lock, flags);
			return -EAGAIN;
		}

		dma_free_coherent(rf->hw.device,
				  mc_qht_elem->mc_grp_ctx.dma_mem_mc.size,
				  mc_qht_elem->mc_grp_ctx.dma_mem_mc.va,
				  mc_qht_elem->mc_grp_ctx.dma_mem_mc.pa);
		mc_qht_elem->mc_grp_ctx.dma_mem_mc.va = NULL;
		nser_free_rsrc(rf, rf->allocated_mcgs,
				mc_qht_elem->mc_grp_ctx.mg_id);
		kfree(mc_qht_elem);
	} else {
		spin_unlock_irqrestore(&rf->qh_list_lock, flags);
		ret = nser_mcast_cqp_op(iwdev, &mc_qht_elem->mc_grp_ctx,
					 NSER_OP_MC_MODIFY);
		if (ret) {
			nser_dbg(iwdev_to_idev(iwdev),
				  "VERBS: failed Modify MCG\n");
			return ret;
		}
	}

	return 0;
}

/**
 * nser_query_ah - Query address handle
 * @ibah: pointer to address handle
 * @ah_attr: address handle attributes
 */
static int nser_query_ah(struct ib_ah *ibah, struct rdma_ah_attr *ah_attr)
{
	struct nser_ah *ah = to_iwah(ibah);

	memset(ah_attr, 0, sizeof(*ah_attr));
	if (ah->av.attrs.ah_flags & IB_AH_GRH) {
		ah_attr->ah_flags = IB_AH_GRH;
		ah_attr->grh.flow_label = ah->sc_ah.ah_info.flow_label;
		ah_attr->grh.traffic_class = ah->sc_ah.ah_info.tc_tos;
		ah_attr->grh.hop_limit = ah->sc_ah.ah_info.hop_ttl;
		ah_attr->grh.sgid_index = ah->sgid_index;
		ah_attr->grh.sgid_index = ah->sgid_index;
		memcpy(&ah_attr->grh.dgid, &ah->dgid,
		       sizeof(ah_attr->grh.dgid));
	}

	return 0;
}

static __be64 nser_mac_to_guid(struct net_device *ndev)
{
	const unsigned char *mac = ndev->dev_addr;
	__be64 guid;
	unsigned char *dst = (unsigned char *)&guid;

	dst[0] = mac[0] ^ 2;
	dst[1] = mac[1];
	dst[2] = mac[2];
	dst[3] = 0xff;
	dst[4] = 0xfe;
	dst[5] = mac[3];
	dst[6] = mac[4];
	dst[7] = mac[5];

	return guid;
}

static const struct ib_device_ops nser_roce_dev_ops = {
	.create_ah = nser_create_ah,
	.create_user_ah = nser_create_ah,
	.destroy_ah = nser_destroy_ah,
	.get_link_layer = nser_get_link_layer,
	.get_port_immutable = nser_roce_port_immutable,
	.modify_qp = nser_modify_qp_roce,
	.query_ah = nser_query_ah,
	.query_gid = nser_query_gid_roce,
	.query_pkey = nser_query_pkey,
};

static const struct ib_device_ops nser_mcast_ops = {
	.attach_mcast = nser_attach_mcast,
	.detach_mcast = nser_detach_mcast,
};

static const struct ib_device_ops nser_dev_ops = {
	.owner = THIS_MODULE,
	.driver_id = RDMA_DRIVER_NSER,
	.uverbs_abi_ver = NSER_ABI_VER,
	.alloc_hw_port_stats = nser_alloc_hw_port_stats,
	.alloc_mr = nser_alloc_mr,
	.alloc_mw = nser_alloc_mw,
	.alloc_pd = nser_alloc_pd,
	.alloc_ucontext = nser_alloc_ucontext,
	.create_cq = nser_create_cq,
	.create_qp = nser_create_qp,
	.dealloc_driver = nser_ib_dealloc_device,
	.dealloc_mw = nser_dealloc_mw,
	.dealloc_pd = nser_dealloc_pd,
	.dealloc_ucontext = nser_dealloc_ucontext,
	.dereg_mr = nser_dereg_mr,
	.destroy_cq = nser_destroy_cq,
	.destroy_qp = nser_destroy_qp,
	.disassociate_ucontext = nser_disassociate_ucontext,
	.get_dev_fw_str = nser_get_dev_fw_str,
	.get_dma_mr = nser_get_dma_mr,
	.get_hw_stats = nser_get_hw_stats,
	.map_mr_sg = nser_map_mr_sg,
	.mmap = nser_mmap,
	.mmap_free = nser_mmap_free,
	.poll_cq = nser_poll_cq,
	.post_recv = nser_post_recv,
	.post_send = nser_post_send,
	.query_device = nser_query_device,
	.query_port = nser_query_port,
	.modify_port = nser_modify_port,
	.query_qp = nser_query_qp,
	.reg_user_mr_dmabuf = nser_reg_user_mr_dmabuf,
	.reg_user_mr = nser_reg_user_mr,
	.rereg_user_mr = nser_rereg_user_mr,
	.req_notify_cq = nser_req_notify_cq,
	.resize_cq = nser_resize_cq,
	INIT_RDMA_OBJ_SIZE(ib_pd, nser_pd, ibpd),
	INIT_RDMA_OBJ_SIZE(ib_ucontext, nser_ucontext, ibucontext),
	INIT_RDMA_OBJ_SIZE(ib_ah, nser_ah, ibah),
	INIT_RDMA_OBJ_SIZE(ib_cq, nser_cq, ibcq),
	INIT_RDMA_OBJ_SIZE(ib_mw, nser_mr, ibmw),
	INIT_RDMA_OBJ_SIZE(ib_qp, nser_qp, ibqp),
};

static void nser_set_device_mcast_ops(struct ib_device *ibdev)
{
	ib_set_device_ops(ibdev, &nser_mcast_ops);
}

static void nser_set_device_roce_ops(struct ib_device *ibdev)
{
	ib_set_device_ops(ibdev, &nser_roce_dev_ops);
}

/**
 * nser_init_roce_device - initialization of roce rdma device
 * @iwdev: nser device
 */
static void nser_init_roce_device(struct nser_device *iwdev)
{
	iwdev->ibdev.node_type = RDMA_NODE_IB_CA;
	iwdev->ibdev.node_guid = nser_mac_to_guid(iwdev->netdev);
	nser_set_device_roce_ops(&iwdev->ibdev);
	nser_set_device_mcast_ops(&iwdev->ibdev);
}

/**
 * nser_init_rdma_device - initialization of rdma device
 * @iwdev: nser device
 */
static int nser_init_rdma_device(struct nser_device *iwdev)
{
	struct pci_dev *pcidev = iwdev->rf->pcidev;

	nser_init_roce_device(iwdev);

	iwdev->ibdev.phys_port_cnt = 1;
	iwdev->ibdev.num_comp_vectors = iwdev->rf->ceqs_count;
	iwdev->ibdev.dev.parent = &pcidev->dev;
	ib_set_device_ops(&iwdev->ibdev, &nser_dev_ops);

	return 0;
}

/**
 * nser_port_ibevent - indicate port event
 * @iwdev: nser device
 */
void nser_port_ibevent(struct nser_device *iwdev)
{
	struct ib_event event;

	event.device = &iwdev->ibdev;
	event.element.port_num = 1;
	event.event =
		iwdev->iw_status ? IB_EVENT_PORT_ACTIVE : IB_EVENT_PORT_ERR;
	ib_dispatch_event(&event);
}

static void nser_unregister_notifiers(struct nser_device *iwdev)
{
	unregister_netdevice_notifier(&iwdev->nb_netdevice_event);
	unregister_netevent_notifier(&iwdev->nb_net_event);
	unregister_inet6addr_notifier(&iwdev->nb_inet6addr_event);
	unregister_inetaddr_notifier(&iwdev->nb_inetaddr_event);
}

/**
 * nser_ib_unregister_device - unregister rdma device from IB
 * core
 * @iwdev: nser device
 */
void nser_ib_unregister_device(struct nser_device *iwdev)
{
	nser_unregister_notifiers(iwdev);
	iwdev->iw_status = 0;
	nser_port_ibevent(iwdev);
	ib_unregister_device(&iwdev->ibdev);
	nser_release_ib_devname(iwdev);
}

int nser_register_notifiers(struct nser_device *iwdev)
{
	int ret;

	iwdev->nb_netdevice_event.notifier_call = nser_netdevice_event;
	ret = register_netdevice_notifier(&iwdev->nb_netdevice_event);
	if (ret) {
		ibdev_err(&iwdev->ibdev, "register_netdevice_notifier failed\n");
		return ret;
	}

	iwdev->nb_net_event.notifier_call = nser_net_event;
	ret = register_netevent_notifier(&iwdev->nb_net_event);
	if (ret) {
		ibdev_err(&iwdev->ibdev, "register_netevent_notifier failed\n");
		goto netevent_error;
	}

	iwdev->nb_inet6addr_event.notifier_call = nser_inet6addr_event;
	ret = register_inet6addr_notifier(&iwdev->nb_inet6addr_event);
	if (ret) {
		ibdev_err(&iwdev->ibdev, "register_inet6addr_notifier failed\n");
		goto inet6addr_error;
	}

	iwdev->nb_inetaddr_event.notifier_call = nser_inetaddr_event;
	ret = register_inetaddr_notifier(&iwdev->nb_inetaddr_event);
	if (ret) {
		ibdev_err(&iwdev->ibdev, "register_inetaddr_notifier failed\n");
		goto inetaddr_error;
	}

	return 0;

inetaddr_error:
	unregister_inet6addr_notifier(&iwdev->nb_inet6addr_event);
inet6addr_error:
	unregister_netevent_notifier(&iwdev->nb_net_event);
netevent_error:
	unregister_netdevice_notifier(&iwdev->nb_netdevice_event);
	return ret;
}

/**
 * nser_ib_register_device - register nser device to IB core
 * @iwdev: nser device
 */
int nser_ib_register_device(struct nser_device *iwdev)
{
	const char *name = nser_set_ib_devname(iwdev);
	int ret;

	ret = nser_init_rdma_device(iwdev);
	if (ret)
		return ret;

	kc_set_driver_id(iwdev->ibdev);
	ret = ib_device_set_netdev(&iwdev->ibdev, iwdev->netdev, 1);
	if (ret)
		goto error;
	dma_set_max_seg_size(iwdev->rf->hw.device, SZ_2G);

	ret = kc_ib_register_device(&iwdev->ibdev, name, iwdev->rf->hw.device);
	if (ret)
		goto error;

	iwdev->iw_status = 1;
	nser_port_ibevent(iwdev);

	return 0;

error:
	nser_dbg(&iwdev->rf->sc_dev, "VERBS: Register RDMA device fail\n");

	return ret;
}

/**
 * nser_ib_dealloc_device
 * @ibdev: ib device
 *
 * callback from ibdev dealloc_driver to deallocate resources
 * unber nser device
 */
void nser_ib_dealloc_device(struct ib_device *ibdev)
{
	struct nser_device *iwdev = to_iwdev(ibdev);

	nser_cleanup_dead_qps(&iwdev->vsi);
#ifdef CONFIG_DEBUG_FS
	nser_dbg_pf_exit(iwdev->hdl);
#endif
	nser_rt_deinit_hw(iwdev);
	nser_ctrl_deinit_hw(iwdev->rf);
	nser_del_handler(iwdev->hdl);
	kfree(iwdev->hdl);
	kfree(iwdev->rf);
}
