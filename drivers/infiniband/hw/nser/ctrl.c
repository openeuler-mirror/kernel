// SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB
/* Copyright (c) 2015 - 2022 WangXun Corporation */
#include "osdep.h"
#include "hmc.h"
#include "defs.h"
#include "type.h"
#include "ws.h"
#include "protos.h"
#include "vf.h"
#include "virtchnl.h"
#include "main.h"

/**
 * nser_get_qp_from_list - get next qp from a list
 * @head: Listhead of qp's
 * @qp: current qp
 */
struct nser_sc_qp *nser_get_qp_from_list(struct list_head *head,
					 struct nser_sc_qp *qp)
{
	struct list_head *lastentry;
	struct list_head *entry = NULL;

	if (list_empty(head))
		return NULL;

	if (!qp) {
		entry = head->next;
	} else {
		lastentry = &qp->list;
		entry = lastentry->next;
		if (entry == head)
			return NULL;
	}

	return container_of(entry, struct nser_sc_qp, list);
}

/**
 * nser_sc_suspend_resume_qps - suspend/resume all qp's on VSI
 * @vsi: the VSI struct pointer
 * @op: Set to NSER_OP_RESUME or NSER_OP_SUSPEND
 */
void nser_sc_suspend_resume_qps(struct nser_sc_vsi *vsi, u8 op)
{
	struct nser_sc_qp *qp = NULL;
	u8 i;

	for (i = 0; i < NSER_MAX_USER_PRIORITY; i++) {
		mutex_lock(&vsi->qos[i].qos_mutex);
		qp = nser_get_qp_from_list(&vsi->qos[i].qplist, qp);
		while (qp) {
			if (op == NSER_OP_RESUME) {
				if (!qp->dev->ws_add(vsi, i)) {
					qp->qs_handle =
						vsi->qos[qp->user_pri].qs_handle;
					qp->qp_uk.qs_handle =
						vsi->qos[qp->user_pri].qs_handle;
					nser_cqp_qp_suspend_resume(qp, op);
				} else {
					nser_cqp_qp_suspend_resume(qp, op);
					nser_modify_qp_to_err(qp);
				}
			} else if (op == NSER_OP_SUSPEND) {
				/* issue cqp suspend command */
				if (!nser_cqp_qp_suspend_resume(qp, op))
					atomic_inc(&vsi->qp_suspend_reqs);
			}
			qp = nser_get_qp_from_list(&vsi->qos[i].qplist, qp);
		}
		mutex_unlock(&vsi->qos[i].qos_mutex);
	}
}

static void nser_set_qos_info(struct nser_sc_vsi  *vsi, struct nser_l2params *l2p)
{
	u8 i;

	vsi->qos_rel_bw = l2p->vsi_rel_bw;
	vsi->qos_prio_type = l2p->vsi_prio_type;
	vsi->dscp_mode = l2p->dscp_mode;
	if (l2p->dscp_mode) {
		memcpy(vsi->dscp_map, l2p->dscp_map, sizeof(vsi->dscp_map));
		for (i = 0; i < NSER_MAX_USER_PRIORITY; i++)
			l2p->up2tc[i] = i;
	}
	for (i = 0; i < IEEE_8021QAZ_MAX_TCS; i++)
		vsi->tc_print_warning[i] = true;
	for (i = 0; i < NSER_MAX_USER_PRIORITY; i++) {
		nser_init_config_check(&vsi->cfg_check[i],
				       l2p->up2tc[i],
					l2p->qs_handle_list[i]);
		vsi->qos[i].traffic_class = l2p->up2tc[i];
		vsi->qos[i].rel_bw =
			l2p->tc_info[vsi->qos[i].traffic_class].rel_bw;
		vsi->qos[i].prio_type =
			l2p->tc_info[vsi->qos[i].traffic_class].prio_type;
		vsi->qos[i].valid = false;
	}
}

/**
 * nser_change_l2params - given the new l2 parameters, change all qp
 * @vsi: RDMA VSI pointer
 * @l2params: New parameters from l2
 */
void nser_change_l2params(struct nser_sc_vsi *vsi,
			  struct nser_l2params *l2params)
{
	if (l2params->tc_changed) {
		vsi->tc_change_pending = false;
		nser_set_qos_info(vsi, l2params);
		nser_sc_suspend_resume_qps(vsi, NSER_OP_RESUME);
	}

	if (l2params->mtu_changed)
		vsi->mtu = l2params->mtu;
}

/**
 * nser_qp_rem_qos - remove qp from qos lists during destroy qp
 * @qp: qp to be removed from qos
 */
void nser_qp_rem_qos(struct nser_sc_qp *qp)
{
	struct nser_sc_vsi *vsi = qp->vsi;

	nser_dbg(qp->dev,
		 "DCB: DCB: Remove qp[%d] UP[%d] qset[%d] on_qoslist[%d]\n",
		  qp->qp_uk.qp_id, qp->user_pri, qp->qs_handle,
		  qp->on_qoslist);
	mutex_lock(&vsi->qos[qp->user_pri].qos_mutex);
	if (qp->on_qoslist) {
		qp->on_qoslist = false;
		list_del(&qp->list);
	}
	mutex_unlock(&vsi->qos[qp->user_pri].qos_mutex);
}

/**
 * nser_qp_add_qos - called during setctx for qp to be added to qos
 * @qp: qp to be added to qos
 */
void nser_qp_add_qos(struct nser_sc_qp *qp)
{
	struct nser_sc_vsi *vsi = qp->vsi;

	nser_dbg(qp->dev,
		 "DCB: DCB: Add qp[%d] UP[%d] qset[%d] on_qoslist[%d]\n",
		  qp->qp_uk.qp_id, qp->user_pri, qp->qs_handle,
		  qp->on_qoslist);
	mutex_lock(&vsi->qos[qp->user_pri].qos_mutex);
	if (!qp->on_qoslist) {
		list_add(&qp->list, &vsi->qos[qp->user_pri].qplist);
		qp->on_qoslist = true;
		qp->qs_handle = vsi->qos[qp->user_pri].qs_handle;
		qp->qp_uk.qs_handle = vsi->qos[qp->user_pri].qs_handle;
	}
	mutex_unlock(&vsi->qos[qp->user_pri].qos_mutex);
}

/**
 * nser_sc_pd_init - initialize sc pd struct
 * @dev: sc device struct
 * @pd: sc pd ptr
 * @pd_id: pd_id for allocated pd
 * @abi_ver: User/Kernel ABI version
 */
void nser_sc_pd_init(struct nser_sc_dev *dev, struct nser_sc_pd *pd, u32 pd_id,
		     int abi_ver)
{
	pd->pd_id = pd_id;
	pd->abi_ver = abi_ver;
	pd->dev = dev;
}

/**
 * nser_sc_add_arp_cache_entry - cqp wqe add arp cache entry
 * @cqp: struct for cqp hw
 * @info: arp entry information
 * @scratch: u64 saved to be used during cqp completion
 * @post_sq: flag for cqp db to ring
 */
static int
nser_sc_add_arp_cache_entry(struct nser_sc_cqp *cqp,
			    struct nser_add_arp_cache_entry_info *info,
			     u64 scratch, bool post_sq)
{
	__le64 *wqe;
	u64 hdr;

	wqe = nser_sc_cqp_get_next_send_wqe(cqp, scratch);
	if (!wqe)
		return -ENOMEM;
	set_64bit_val(wqe, 8, info->reach_max);

	set_64bit_val(wqe, 16, ether_addr_to_u64(info->mac_addr));

	hdr = info->arp_index |
	      FIELD_PREP(NSER_CQPSQ_OPCODE, NSER_CQP_OP_MANAGE_ARP) |
	      FIELD_PREP(NSER_CQPSQ_MAT_PERMANENT, info->permanent) |
	      FIELD_PREP(NSER_CQPSQ_MAT_ENTRYVALID, true) |
	      FIELD_PREP(NSER_CQPSQ_WQEVALID, cqp->polarity);
	dma_wmb(); /* make sure WQE is written before valid bit is set */

	set_64bit_val(wqe, 24, hdr);

	print_hex_dump_debug("WQE: ARP_CACHE_ENTRY WQE", DUMP_PREFIX_OFFSET,
			     16, 8, wqe, NSER_CQP_WQE_SIZE * 8, false);
	if (post_sq)
		nser_sc_cqp_post_sq(cqp);

	return 0;
}

/**
 * nser_sc_del_arp_cache_entry - dele arp cache entry
 * @cqp: struct for cqp hw
 * @scratch: u64 saved to be used during cqp completion
 * @arp_index: arp index to delete arp entry
 * @post_sq: flag for cqp db to ring
 */
static int nser_sc_del_arp_cache_entry(struct nser_sc_cqp *cqp, u64 scratch,
				       u16 arp_index, bool post_sq)
{
	__le64 *wqe;
	u64 hdr;

	wqe = nser_sc_cqp_get_next_send_wqe(cqp, scratch);
	if (!wqe)
		return -ENOMEM;

	hdr = arp_index |
	      FIELD_PREP(NSER_CQPSQ_OPCODE, NSER_CQP_OP_MANAGE_ARP) |
	      FIELD_PREP(NSER_CQPSQ_WQEVALID, cqp->polarity);
	dma_wmb(); /* make sure WQE is written before valid bit is set */

	set_64bit_val(wqe, 24, hdr);

	print_hex_dump_debug("WQE: ARP_CACHE_DEL_ENTRY WQE",
			     DUMP_PREFIX_OFFSET, 16, 8, wqe,
			     NSER_CQP_WQE_SIZE * 8, false);
	if (post_sq)
		nser_sc_cqp_post_sq(cqp);

	return 0;
}

/**
 * nser_sc_qp_init - initialize qp
 * @qp: sc qp
 * @info: initialization qp info
 */
int nser_sc_qp_init(struct nser_sc_qp *qp, struct nser_qp_init_info *info)
{
	int ret_code;
	u32 pble_obj_cnt;
	u16 wqe_size;

	if (info->qp_uk_init_info.max_sq_frag_cnt >
	    info->pd->dev->hw_attrs.uk_attrs.max_hw_wq_frags ||
	    info->qp_uk_init_info.max_rq_frag_cnt >
	    info->pd->dev->hw_attrs.uk_attrs.max_hw_wq_frags)
		return -EINVAL;

	qp->dev = info->pd->dev;
	qp->vsi = info->vsi;
	qp->sq_pa = info->sq_pa;
	qp->rq_pa = info->rq_pa;
	qp->hw_host_ctx_pa = info->host_ctx_pa;
	qp->shadow_area_pa = info->shadow_area_pa;
	qp->pd = info->pd;
	qp->hw_host_ctx = info->host_ctx;
	info->qp_uk_init_info.wqe_alloc_db = qp->pd->dev->wqe_alloc_db;
	ret_code = nser_uk_qp_init(&qp->qp_uk, &info->qp_uk_init_info);
	if (ret_code)
		return ret_code;

	qp->virtual_map = info->virtual_map;
	pble_obj_cnt = info->pd->dev->hmc_info->hmc_obj[NSER_HMC_IW_PBLE].cnt;

	if ((info->virtual_map && info->sq_pa >= pble_obj_cnt) ||
	    (info->virtual_map && info->rq_pa >= pble_obj_cnt))
		return -EINVAL;

	qp->hw_sq_size = nser_get_encoded_wqe_size(qp->qp_uk.sq_ring.size,
						   NSER_QUEUE_TYPE_SQ_RQ);
	nser_dbg(qp->dev, "WQE: hw_sq_size[%04d] sq_ring.size[%04d]\n",
		 qp->hw_sq_size, qp->qp_uk.sq_ring.size);
	ret_code = nser_fragcnt_to_wqesize_rq(qp->qp_uk.max_rq_frag_cnt,
					      &wqe_size);
	if (ret_code)
		return ret_code;

	qp->hw_rq_size =
		nser_get_encoded_wqe_size(qp->qp_uk.rq_size *
					   (wqe_size / NSER_QP_WQE_MIN_SIZE),
					   NSER_QUEUE_TYPE_SQ_RQ);
	nser_dbg(qp->dev,
		 "WQE: hw_rq_size[%04d] qp_uk.rq_size[%04d] wqe_size[%04d]\n",
		  qp->hw_rq_size, qp->qp_uk.rq_size, wqe_size);

	qp->sq_tph_val = info->sq_tph_val;
	qp->rq_tph_val = info->rq_tph_val;
	qp->sq_tph_en = info->sq_tph_en;
	qp->rq_tph_en = info->rq_tph_en;
	qp->rcv_tph_en = info->rcv_tph_en;
	qp->xmit_tph_en = info->xmit_tph_en;
	qp->qp_uk.first_sq_wq = info->qp_uk_init_info.first_sq_wq;
	qp->qs_handle = qp->vsi->qos[qp->user_pri].qs_handle;
	qp->qp_uk.qs_handle = qp->vsi->qos[qp->user_pri].qs_handle;

	return 0;
}

/**
 * nser_sc_qp_create - create qp
 * @qp: sc qp
 * @info: qp create info
 * @scratch: u64 saved to be used during cqp completion
 * @post_sq: flag for cqp db to ring
 */
int nser_sc_qp_create(struct nser_sc_qp *qp, struct nser_create_qp_info *info,
		      u64 scratch, bool post_sq)
{
	struct nser_sc_cqp *cqp;
	__le64 *wqe;
	u64 hdr;

	cqp = qp->dev->cqp;
	if (qp->qp_uk.qp_id < cqp->dev->hw_attrs.min_hw_qp_id ||
	    qp->qp_uk.qp_id > (cqp->dev->hmc_info->hmc_obj[NSER_HMC_IW_QP].max_cnt - 1))
		return -EINVAL;

	wqe = nser_sc_cqp_get_next_send_wqe(cqp, scratch);
	if (!wqe)
		return -ENOMEM;

	set_64bit_val(wqe, 16, qp->hw_host_ctx_pa);
	set_64bit_val(wqe, 40, qp->shadow_area_pa);

	hdr = qp->qp_uk.qp_id |
	      FIELD_PREP(NSER_CQPSQ_OPCODE, NSER_CQP_OP_CREATE_QP) |
	      FIELD_PREP(NSER_CQPSQ_QP_ORDVALID, info->ord_valid) |
	      FIELD_PREP(NSER_CQPSQ_QP_MACVALID, info->mac_valid) |
	      FIELD_PREP(NSER_CQPSQ_QP_QPTYPE, qp->qp_uk.qp_type) |
	      FIELD_PREP(NSER_CQPSQ_QP_VQ, qp->virtual_map) |
	      FIELD_PREP(NSER_CQPSQ_QP_FORCELOOPBACK, info->force_lpb) |
	      FIELD_PREP(NSER_CQPSQ_QP_CQNUMVALID, info->cq_num_valid) |
	      FIELD_PREP(NSER_CQPSQ_QP_ARPTABIDXVALID,
			 info->arp_cache_idx_valid) |
	      FIELD_PREP(NSER_CQPSQ_QP_NEXTIWSTATE, info->next_rdma_state) |
	      FIELD_PREP(NSER_CQPSQ_WQEVALID, cqp->polarity);

	dma_wmb(); /* make sure WQE is written before valid bit is set */

	set_64bit_val(wqe, 24, hdr);

	print_hex_dump_debug("WQE: QP_CREATE WQE", DUMP_PREFIX_OFFSET, 16, 8,
			     wqe, NSER_CQP_WQE_SIZE * 8, false);
	if (post_sq)
		nser_sc_cqp_post_sq(cqp);

	return 0;
}

/**
 * nser_sc_qp_modify - modify qp cqp wqe
 * @qp: sc qp
 * @info: modify qp info
 * @scratch: u64 saved to be used during cqp completion
 * @post_sq: flag for cqp db to ring
 */
int nser_sc_qp_modify(struct nser_sc_qp *qp, struct nser_modify_qp_info *info,
		      u64 scratch, bool post_sq)
{
	__le64 *wqe;
	struct nser_sc_cqp *cqp;
	u64 hdr;

	cqp = qp->dev->cqp;
	wqe = nser_sc_cqp_get_next_send_wqe(cqp, scratch);
	if (!wqe)
		return -ENOMEM;

	set_64bit_val(wqe, 16, qp->hw_host_ctx_pa);
	set_64bit_val(wqe, 40, qp->shadow_area_pa);
	set_64bit_val(wqe, 32, info->attr_mask);

	hdr = qp->qp_uk.qp_id |
	      FIELD_PREP(NSER_CQPSQ_OPCODE, NSER_CQP_OP_MODIFY_QP) |
	      FIELD_PREP(NSER_CQPSQ_QP_ORDVALID, info->ord_valid) |
	      FIELD_PREP(NSER_CQPSQ_QP_CACHEDVARVALID,
			 info->cached_var_valid) |
	      FIELD_PREP(NSER_CQPSQ_QP_VQ, qp->virtual_map) |
	      FIELD_PREP(NSER_CQPSQ_QP_CQNUMVALID, info->cq_num_valid) |
	      FIELD_PREP(NSER_CQPSQ_QP_MACVALID, info->mac_valid) |
	      FIELD_PREP(NSER_CQPSQ_QP_QPTYPE, qp->qp_uk.qp_type) |
	      FIELD_PREP(NSER_CQPSQ_QP_REMOVEHASHENTRY,
			 info->remove_hash_idx) |
	      FIELD_PREP(NSER_CQPSQ_QP_ARPTABIDXVALID,
			 info->arp_cache_idx_valid) |
	      FIELD_PREP(NSER_CQPSQ_QP_NEXTIWSTATE, info->next_rdma_state) |
	      FIELD_PREP(NSER_CQPSQ_WQEVALID, cqp->polarity);

	dma_wmb(); /* make sure WQE is written before valid bit is set */

	set_64bit_val(wqe, 24, hdr);

	print_hex_dump_debug("WQE: QP_MODIFY WQE", DUMP_PREFIX_OFFSET, 16, 8,
			     wqe, NSER_CQP_WQE_SIZE * 8, false);
	if (post_sq)
		nser_sc_cqp_post_sq(cqp);

	return 0;
}

/**
 * nser_sc_qp_destroy - cqp destroy qp
 * @qp: sc qp
 * @scratch: u64 saved to be used during cqp completion
 * @remove_hash_idx: flag if to remove hash idx
 * @ignore_mw_bnd: memory window bind flag
 * @post_sq: flag for cqp db to ring
 */
int nser_sc_qp_destroy(struct nser_sc_qp *qp, u64 scratch,
		       bool remove_hash_idx, bool ignore_mw_bnd, bool post_sq)
{
	__le64 *wqe;
	struct nser_sc_cqp *cqp;
	u64 hdr;

	cqp = qp->dev->cqp;
	wqe = nser_sc_cqp_get_next_send_wqe(cqp, scratch);
	if (!wqe)
		return -ENOSPC;

	set_64bit_val(wqe, 16, qp->hw_host_ctx_pa);
	set_64bit_val(wqe, 40, qp->shadow_area_pa);

	hdr = qp->qp_uk.qp_id |
	      FIELD_PREP(NSER_CQPSQ_OPCODE, NSER_CQP_OP_DESTROY_QP) |
	      FIELD_PREP(NSER_CQPSQ_QP_QPTYPE, qp->qp_uk.qp_type) |
	      FIELD_PREP(NSER_CQPSQ_QP_IGNOREMWBOUND, ignore_mw_bnd) |
	      FIELD_PREP(NSER_CQPSQ_QP_REMOVEHASHENTRY, remove_hash_idx) |
	      FIELD_PREP(NSER_CQPSQ_WQEVALID, cqp->polarity);
	dma_wmb(); /* make sure WQE is written before valid bit is set */

	set_64bit_val(wqe, 24, hdr);

	print_hex_dump_debug("WQE: QP_DESTROY WQE", DUMP_PREFIX_OFFSET, 16, 8,
			     wqe, NSER_CQP_WQE_SIZE * 8, false);
	if (post_sq)
		nser_sc_cqp_post_sq(cqp);

	return 0;
}

/**
 * nser_sc_get_encoded_ird_size -
 * @ird_size: IRD size
 * The ird from the connection is rounded to a supported HW setting and then encoded
 * for ird_size field of qp_ctx. Consumers are expected to provide valid ird size based
 * on hardware attributes. IRD size defaults to a value of 4 in case of invalid input
 */
static u8 nser_sc_get_encoded_ird_size(u16 ird_size)
{
	switch (ird_size ?
		roundup_pow_of_two(2 * ird_size) : 4) {
	case 256:
		return NSER_IRD_HW_SIZE_256;
	case 128:
		return NSER_IRD_HW_SIZE_128;
	case 64:
	case 32:
		return NSER_IRD_HW_SIZE_64;
	case 16:
	case 8:
		return NSER_IRD_HW_SIZE_16;
	case 4:
	default:
		break;
	}

	return NSER_IRD_HW_SIZE_4;
}

/**
 * nser_sc_qp_setctx_roce - set qp's context
 * @qp: sc qp
 * @qp_ctx: context ptr
 * @info: ctx info
 */
void nser_sc_qp_setctx_roce(struct nser_sc_qp *qp, __le64 *qp_ctx,
			    struct nser_qp_host_ctx_info *info)
{
	struct nser_roce_offload_info *roce_info;
	struct nser_udp_offload_info *udp;

	roce_info = info->roce_info;
	udp = info->udp_info;

	qp->user_pri = info->user_pri;
	set_64bit_val(qp_ctx, 0,
		      FIELD_PREP(NSERQPC_RQWQESIZE, qp->qp_uk.rq_wqe_size) |
		      FIELD_PREP(NSERQPC_RCVTPHEN, qp->rcv_tph_en) |
		      FIELD_PREP(NSERQPC_XMITTPHEN, qp->xmit_tph_en) |
		      FIELD_PREP(NSERQPC_RQTPHEN, qp->rq_tph_en) |
		      FIELD_PREP(NSERQPC_SQTPHEN, qp->sq_tph_en) |
		      FIELD_PREP(NSERQPC_PDIDXHI, roce_info->pd_id >> 16) |
		      FIELD_PREP(NSERQPC_ECN_EN, roce_info->ecn_en) |
		      FIELD_PREP(NSERQPC_ERR_RQ_IDX_VALID, roce_info->err_rq_idx_valid) |
		      FIELD_PREP(NSERQPC_ROCE_TVER, roce_info->roce_tver) |
		      FIELD_PREP(NSERQPC_IPV4, udp->ipv4) |
		      FIELD_PREP(NSERQPC_INSERTVLANTAG, udp->insert_vlan_tag));
	set_64bit_val(qp_ctx, 8, qp->sq_pa);
	set_64bit_val(qp_ctx, 16, qp->rq_pa);

	udp->tos &= ~ECN_CODE_PT_MASK;
	if (roce_info->dcqcn_en || roce_info->ecn_en)
		udp->tos |= ECN_CODE_PT_VAL;

	set_64bit_val(qp_ctx, 24,
		      FIELD_PREP(NSERQPC_RQSIZE, qp->hw_rq_size) |
		      FIELD_PREP(NSERQPC_SQSIZE, qp->hw_sq_size) |
		      FIELD_PREP(NSERQPC_TTL, udp->ttl) | FIELD_PREP(NSERQPC_TOS, udp->tos) |
		      FIELD_PREP(NSERQPC_SRCPORTNUM, udp->src_port) |
		      FIELD_PREP(NSERQPC_DESTPORTNUM, udp->dst_port));
	set_64bit_val(qp_ctx, 32,
		      FIELD_PREP(NSERQPC_DESTIPADDR2, udp->dest_ip_addr[2]) |
		      FIELD_PREP(NSERQPC_DESTIPADDR3, udp->dest_ip_addr[3]));
	set_64bit_val(qp_ctx, 40,
		      FIELD_PREP(NSERQPC_DESTIPADDR0, udp->dest_ip_addr[0]) |
		      FIELD_PREP(NSERQPC_DESTIPADDR1, udp->dest_ip_addr[1]));
	set_64bit_val(qp_ctx, 48,
		      FIELD_PREP(NSERQPC_SNDMSS, udp->snd_mss) |
		      FIELD_PREP(NSERQPC_VLANTAG, udp->vlan_tag) |
		      FIELD_PREP(NSERQPC_ARPIDX, udp->arp_idx));
	set_64bit_val(qp_ctx, 56,
		      FIELD_PREP(NSERQPC_PKEY, roce_info->p_key) |
		      FIELD_PREP(NSERQPC_PDIDX, roce_info->pd_id) |
		      FIELD_PREP(NSERQPC_ACKCREDITS, roce_info->ack_credits) |
		      FIELD_PREP(NSERQPC_FLOWLABEL, udp->flow_label));
	set_64bit_val(qp_ctx, 64,
		      FIELD_PREP(NSERQPC_QKEY, roce_info->qkey) |
		      FIELD_PREP(NSERQPC_DESTQP, roce_info->dest_qp));
	set_64bit_val(qp_ctx, 80,
		      FIELD_PREP(NSERQPC_PSNNXT, udp->psn_nxt) |
		      FIELD_PREP(NSERQPC_LSN, udp->lsn));
	set_64bit_val(qp_ctx, 88,
		      FIELD_PREP(NSERQPC_EPSN, udp->epsn));
	set_64bit_val(qp_ctx, 96,
		      FIELD_PREP(NSERQPC_PSNMAX, udp->psn_max) |
		      FIELD_PREP(NSERQPC_PSNUNA, udp->psn_una));
	set_64bit_val(qp_ctx, 112,
		      FIELD_PREP(NSERQPC_CWNDROCE, udp->cwnd));
	set_64bit_val(qp_ctx, 128,
		      FIELD_PREP(NSERQPC_MINRNR_TIMER, udp->min_rnr_timer) |
		      FIELD_PREP(NSERQPC_ERR_RQ_IDX, roce_info->err_rq_idx) |
		      FIELD_PREP(NSERQPC_RNRNAK_THRESH, udp->rnr_nak_thresh) |
		      FIELD_PREP(NSERQPC_REXMIT_THRESH, udp->rexmit_thresh) |
		      FIELD_PREP(NSERQPC_RTOMIN, roce_info->rtomin));
	set_64bit_val(qp_ctx, 136,
		      FIELD_PREP(NSERQPC_TXCQNUM, info->send_cq_num) |
		      FIELD_PREP(NSERQPC_RXCQNUM, info->rcv_cq_num));
	set_64bit_val(qp_ctx, 144,
		      FIELD_PREP(NSERQPC_STAT_INDEX, info->stats_idx));
	set_64bit_val(qp_ctx, 152,
		      FIELD_PREP(NSERQPC_MACADDRESS,
				 ether_addr_to_u64(roce_info->mac_addr)));
	set_64bit_val(qp_ctx, 160,
		      FIELD_PREP(NSERQPC_ORDSIZE, roce_info->ord_size) |
		      FIELD_PREP(NSERQPC_IRDSIZE,
						nser_sc_get_encoded_ird_size(roce_info->ird_size)) |
		      FIELD_PREP(NSERQPC_WRRDRSPOK, roce_info->wr_rdresp_en) |
		      FIELD_PREP(NSERQPC_RDOK, roce_info->rd_en) |
		      FIELD_PREP(NSERQPC_USESTATSINSTANCE, info->stats_idx_valid) |
		      FIELD_PREP(NSERQPC_BINDEN, roce_info->bind_en) |
		      FIELD_PREP(NSERQPC_FASTREGEN, roce_info->fast_reg_en) |
		      FIELD_PREP(NSERQPC_DCQCNENABLE, roce_info->dcqcn_en) |
		      FIELD_PREP(NSERQPC_RCVNOICRC, roce_info->rcv_no_icrc) |
		      FIELD_PREP(NSERQPC_FW_CC_ENABLE, roce_info->fw_cc_enable) |
		      FIELD_PREP(NSERQPC_UDPRIVCQENABLE, roce_info->udprivcq_en) |
		      FIELD_PREP(NSERQPC_PRIVEN, roce_info->priv_mode_en) |
		      FIELD_PREP(NSERQPC_TIMELYENABLE, roce_info->timely_en));
	set_64bit_val(qp_ctx, 168,
		      FIELD_PREP(NSERQPC_QPCOMPCTX, info->qp_compl_ctx));
	set_64bit_val(qp_ctx, 176,
		      FIELD_PREP(NSERQPC_SQTPHVAL, qp->sq_tph_val) |
		      FIELD_PREP(NSERQPC_RQTPHVAL, qp->rq_tph_val) |
		      FIELD_PREP(NSERQPC_QSHANDLE, qp->qs_handle));
	set_64bit_val(qp_ctx, 184,
		      FIELD_PREP(NSERQPC_LOCAL_IPADDR3, udp->local_ipaddr[3]) |
		      FIELD_PREP(NSERQPC_LOCAL_IPADDR2, udp->local_ipaddr[2]));
	set_64bit_val(qp_ctx, 192,
		      FIELD_PREP(NSERQPC_LOCAL_IPADDR1, udp->local_ipaddr[1]) |
		      FIELD_PREP(NSERQPC_LOCAL_IPADDR0, udp->local_ipaddr[0]));
	set_64bit_val(qp_ctx, 200,
		      FIELD_PREP(NSERQPC_THIGH, roce_info->t_high) |
		      FIELD_PREP(NSERQPC_TLOW, roce_info->t_low));
	set_64bit_val(qp_ctx, 208,
		      FIELD_PREP(NSERQPC_TIMELY_MIN_RTT, roce_info->timely_min_rtt) |
		      FIELD_PREP(NSERQPC_CC_WORKING_RATE, roce_info->cc_working_rate) |
		      FIELD_PREP(NSERQPC_DCQCN_APLPHA, roce_info->dcqcn_alpha));
	set_64bit_val(qp_ctx, 216,
		      FIELD_PREP(NSERQPC_CC_MAX_WORK_RATE, roce_info->cc_max_work_rate) |
		      FIELD_PREP(NSERQPC_CC_MIN_WORK_RATE, roce_info->cc_min_work_rate) |
		      FIELD_PREP(NSERQPC_DCQCN_RECOVERY_BCNT_PERIOD,
						roce_info->dcqcn_recovery_bcnt_period) |
		      FIELD_PREP(NSERQPC_DCQCN_G, roce_info->dcqcn_g) |
		      FIELD_PREP(NSERQPC_DCQCN_RPG_GD, roce_info->dcqcn_rpg_gd));
	set_64bit_val(qp_ctx, 224,
		      FIELD_PREP(NSERQPC_DCQCN_CLAMP_TAR_RATE, roce_info->dcqcn_clamp_tar_rate) |
		      FIELD_PREP(NSERQPC_DCQCN_ALPHA_PERIOD, roce_info->dcqcn_alpha_period) |
		      FIELD_PREP(NSERQPC_DCQCN_RECOVERY_TIME_PERIOD,
						roce_info->dcqcn_recovery_time_period));
	set_64bit_val(qp_ctx, 232,
		      FIELD_PREP(NSERQPC_DCQCN_TAR_WORK_RATE, roce_info->dcqcn_tar_work_rate));

	print_hex_dump_debug("WQE: QP_HOST CTX WQE", DUMP_PREFIX_OFFSET, 16,
			     8, qp_ctx, NSER_QP_CTX_SIZE, false);
}

/**
 * nser_sc_alloc_stag - mr stag alloc
 * @dev: sc device struct
 * @info: stag info
 * @scratch: u64 saved to be used during cqp completion
 * @post_sq: flag for cqp db to ring
 */
static int nser_sc_alloc_stag(struct nser_sc_dev *dev,
			      struct nser_allocate_stag_info *info,
			      u64 scratch, bool post_sq)
{
	__le64 *wqe;
	struct nser_sc_cqp *cqp;
	u64 hdr;
	enum nser_page_size page_size;

	if (!info->total_len && !info->all_memory)
		return -EINVAL;

	if (info->page_size == 0x40000000)
		page_size = NSER_PAGE_SIZE_1G;
	else if (info->page_size == 0x200000)
		page_size = NSER_PAGE_SIZE_2M;
	else
		page_size = NSER_PAGE_SIZE_4K;

	cqp = dev->cqp;
	wqe = nser_sc_cqp_get_next_send_wqe(cqp, scratch);
	if (!wqe)
		return -ENOMEM;

	set_64bit_val(wqe, 8,
		      FLD_LS_64(dev, info->pd_id, NSER_CQPSQ_STAG_PDID) |
		      FIELD_PREP(NSER_CQPSQ_STAG_STAGLEN, info->total_len));
	set_64bit_val(wqe, 16,
		      FIELD_PREP(NSER_CQPSQ_STAG_IDX, info->stag_idx));
	set_64bit_val(wqe, 40,
		      FIELD_PREP(NSER_CQPSQ_STAG_HMCFNIDX, info->hmc_fcn_index));

	if (info->chunk_size)
		set_64bit_val(wqe, 48,
			      FIELD_PREP(NSER_CQPSQ_STAG_FIRSTPMPBLIDX, info->first_pm_pbl_idx));

	hdr = FIELD_PREP(NSER_CQPSQ_OPCODE, NSER_CQP_OP_ALLOC_STAG) |
	      FIELD_PREP(NSER_CQPSQ_STAG_MR, 1) |
	      FIELD_PREP(NSER_CQPSQ_STAG_ARIGHTS, info->access_rights) |
	      FIELD_PREP(NSER_CQPSQ_STAG_LPBLSIZE, info->chunk_size) |
	      FIELD_PREP(NSER_CQPSQ_STAG_HPAGESIZE, page_size) |
	      FIELD_PREP(NSER_CQPSQ_STAG_REMACCENABLED, info->remote_access) |
	      FIELD_PREP(NSER_CQPSQ_STAG_USEHMCFNIDX, info->use_hmc_fcn_index) |
	      FIELD_PREP(NSER_CQPSQ_STAG_USEPFRID, info->use_pf_rid) |
	      FIELD_PREP(NSER_CQPSQ_WQEVALID, cqp->polarity);
	dma_wmb(); /* make sure WQE is written before valid bit is set */

	set_64bit_val(wqe, 24, hdr);

	print_hex_dump_debug("WQE: ALLOC_STAG WQE", DUMP_PREFIX_OFFSET, 16, 8,
			     wqe, NSER_CQP_WQE_SIZE * 8, false);
	if (post_sq)
		nser_sc_cqp_post_sq(cqp);

	return 0;
}

/**
 * nser_sc_mr_reg_non_shared - non-shared mr registration
 * @dev: sc device struct
 * @info: mr info
 * @scratch: u64 saved to be used during cqp completion
 * @post_sq: flag for cqp db to ring
 */
static int nser_sc_mr_reg_non_shared(struct nser_sc_dev *dev,
				     struct nser_reg_ns_stag_info *info,
				      u64 scratch, bool post_sq)
{
	__le64 *wqe;
	u64 fbo;
	struct nser_sc_cqp *cqp;
	u64 hdr;
	u32 pble_obj_cnt;
	bool remote_access;
	u8 addr_type;
	enum nser_page_size page_size;

	if (!info->total_len && !info->all_memory)
		return -EINVAL;

	if (info->page_size == 0x40000000)
		page_size = NSER_PAGE_SIZE_1G;
	else if (info->page_size == 0x200000)
		page_size = NSER_PAGE_SIZE_2M;
	else if (info->page_size == 0x1000)
		page_size = NSER_PAGE_SIZE_4K;
	else
		return -EINVAL;

	if (info->access_rights & (NSER_ACCESS_FLAGS_REMOTEREAD_ONLY |
				   NSER_ACCESS_FLAGS_REMOTEWRITE_ONLY))
		remote_access = true;
	else
		remote_access = false;

	pble_obj_cnt = dev->hmc_info->hmc_obj[NSER_HMC_IW_PBLE].cnt;
	if (info->chunk_size && info->first_pm_pbl_index >= pble_obj_cnt)
		return -EINVAL;

	cqp = dev->cqp;
	wqe = nser_sc_cqp_get_next_send_wqe(cqp, scratch);
	if (!wqe)
		return -ENOMEM;
	fbo = info->va & (info->page_size - 1);

	set_64bit_val(wqe, 0,
		      (info->addr_type == NSER_ADDR_TYPE_VA_BASED ?
		      info->va : fbo));
	set_64bit_val(wqe, 8,
		      FIELD_PREP(NSER_CQPSQ_STAG_STAGLEN, info->total_len) |
		      FLD_LS_64(dev, info->pd_id, NSER_CQPSQ_STAG_PDID));
	set_64bit_val(wqe, 16,
		      FIELD_PREP(NSER_CQPSQ_STAG_KEY, info->stag_key) |
		      FIELD_PREP(NSER_CQPSQ_STAG_IDX, info->stag_idx));
	if (!info->chunk_size)
		set_64bit_val(wqe, 32, info->reg_addr_pa);
	else
		set_64bit_val(wqe, 48,
			      FIELD_PREP(NSER_CQPSQ_STAG_FIRSTPMPBLIDX, info->first_pm_pbl_index));

	set_64bit_val(wqe, 40, info->hmc_fcn_index);

	addr_type = (info->addr_type == NSER_ADDR_TYPE_VA_BASED) ? 1 : 0;
	hdr = FIELD_PREP(NSER_CQPSQ_OPCODE, NSER_CQP_OP_REG_MR) |
	      FIELD_PREP(NSER_CQPSQ_STAG_MR, 1) |
	      FIELD_PREP(NSER_CQPSQ_STAG_LPBLSIZE, info->chunk_size) |
	      FIELD_PREP(NSER_CQPSQ_STAG_HPAGESIZE, page_size) |
	      FIELD_PREP(NSER_CQPSQ_STAG_ARIGHTS, info->access_rights) |
	      FIELD_PREP(NSER_CQPSQ_STAG_REMACCENABLED, remote_access) |
	      FIELD_PREP(NSER_CQPSQ_STAG_VABASEDTO, addr_type) |
	      FIELD_PREP(NSER_CQPSQ_STAG_USEHMCFNIDX, info->use_hmc_fcn_index) |
	      FIELD_PREP(NSER_CQPSQ_STAG_USEPFRID, info->use_pf_rid) |
	      FIELD_PREP(NSER_CQPSQ_WQEVALID, cqp->polarity);
	dma_wmb(); /* make sure WQE is written before valid bit is set */

	set_64bit_val(wqe, 24, hdr);

	print_hex_dump_debug("WQE: MR_REG_NS WQE", DUMP_PREFIX_OFFSET, 16, 8,
			     wqe, NSER_CQP_WQE_SIZE * 8, false);
	if (post_sq)
		nser_sc_cqp_post_sq(cqp);

	return 0;
}

/**
 * nser_sc_dealloc_stag - deallocate stag
 * @dev: sc device struct
 * @info: dealloc stag info
 * @scratch: u64 saved to be used during cqp completion
 * @post_sq: flag for cqp db to ring
 */
static int nser_sc_dealloc_stag(struct nser_sc_dev *dev,
				struct nser_dealloc_stag_info *info,
				 u64 scratch, bool post_sq)
{
	u64 hdr;
	__le64 *wqe;
	struct nser_sc_cqp *cqp;

	cqp = dev->cqp;
	wqe = nser_sc_cqp_get_next_send_wqe(cqp, scratch);
	if (!wqe)
		return -ENOMEM;

	set_64bit_val(wqe, 8,
		      FLD_LS_64(dev, info->pd_id, NSER_CQPSQ_STAG_PDID));
	set_64bit_val(wqe, 16,
		      FIELD_PREP(NSER_CQPSQ_STAG_IDX, info->stag_idx));

	hdr = FIELD_PREP(NSER_CQPSQ_OPCODE, NSER_CQP_OP_DEALLOC_STAG) |
	      FIELD_PREP(NSER_CQPSQ_STAG_MR, info->mr) |
	      FIELD_PREP(NSER_CQPSQ_WQEVALID, cqp->polarity);
	dma_wmb(); /* make sure WQE is written before valid bit is set */

	set_64bit_val(wqe, 24, hdr);

	print_hex_dump_debug("WQE: DEALLOC_STAG WQE", DUMP_PREFIX_OFFSET, 16,
			     8, wqe, NSER_CQP_WQE_SIZE * 8, false);
	if (post_sq)
		nser_sc_cqp_post_sq(cqp);

	return 0;
}

/**
 * nser_sc_mw_alloc - mw allocate
 * @dev: sc device struct
 * @info: memory window allocation information
 * @scratch: u64 saved to be used during cqp completion
 * @post_sq: flag for cqp db to ring
 */
static int nser_sc_mw_alloc(struct nser_sc_dev *dev,
			    struct nser_mw_alloc_info *info, u64 scratch,
			     bool post_sq)
{
	u64 hdr;
	struct nser_sc_cqp *cqp;
	__le64 *wqe;

	cqp = dev->cqp;
	wqe = nser_sc_cqp_get_next_send_wqe(cqp, scratch);
	if (!wqe)
		return -ENOMEM;

	set_64bit_val(wqe, 8,
		      FLD_LS_64(dev, info->pd_id, NSER_CQPSQ_STAG_PDID));
	set_64bit_val(wqe, 16,
		      FIELD_PREP(NSER_CQPSQ_STAG_IDX, info->mw_stag_index));

	hdr = FIELD_PREP(NSER_CQPSQ_OPCODE, NSER_CQP_OP_ALLOC_STAG) |
	      FIELD_PREP(NSER_CQPSQ_STAG_MWTYPE, info->mw_wide) |
	      FIELD_PREP(NSER_CQPSQ_STAG_MW1_BIND_DONT_VLDT_KEY,
			 info->mw1_bind_dont_vldt_key) |
	      FIELD_PREP(NSER_CQPSQ_WQEVALID, cqp->polarity);
	dma_wmb(); /* make sure WQE is written before valid bit is set */

	set_64bit_val(wqe, 24, hdr);

	print_hex_dump_debug("WQE: MW_ALLOC WQE", DUMP_PREFIX_OFFSET, 16, 8,
			     wqe, NSER_CQP_WQE_SIZE * 8, false);
	if (post_sq)
		nser_sc_cqp_post_sq(cqp);

	return 0;
}

/**
 * nser_sc_mr_fast_register - Posts RDMA fast register mr WR to rdma qp
 * @qp: sc qp struct
 * @info: fast mr info
 * @post_sq: flag for cqp db to ring
 */
int nser_sc_mr_fast_register(struct nser_sc_qp *qp,
			     struct nser_fast_reg_stag_info *info,
			      bool post_sq)
{
	u64 temp, hdr;
	__le64 *wqe;
	u32 wqe_idx;
	u16 quanta = NSER_QP_WQE_MIN_QUANTA;
	enum nser_page_size page_size;
	struct nser_post_sq_info sq_info = {};

	if (info->page_size == 0x40000000)
		page_size = NSER_PAGE_SIZE_1G;
	else if (info->page_size == 0x200000)
		page_size = NSER_PAGE_SIZE_2M;
	else
		page_size = NSER_PAGE_SIZE_4K;

	sq_info.wr_id = info->wr_id;
	sq_info.signaled = info->signaled;

	wqe = nser_qp_get_next_send_wqe(&qp->qp_uk, &wqe_idx,
					&quanta, 0, &sq_info);
	if (!wqe)
		return -ENOMEM;

	nser_dbg(qp->dev, "MR: wr_id[%llxh] wqe_idx[%04d] location[%p]\n",
		 info->wr_id, wqe_idx,
		  &qp->qp_uk.sq_wrtrk_array[wqe_idx].wrid);

	temp = (info->addr_type == NSER_ADDR_TYPE_VA_BASED) ?
		(uintptr_t)info->va : info->fbo;
	set_64bit_val(wqe, 0, temp);

	temp = FIELD_GET(NSERQPSQ_FIRSTPMPBLIDXHI,
			 info->first_pm_pbl_index >> 16);
	set_64bit_val(wqe, 8,
		      FIELD_PREP(NSERQPSQ_FIRSTPMPBLIDXHI, temp) |
		      FIELD_PREP(NSERQPSQ_PBLADDR, info->reg_addr_pa >> NSER_HW_PAGE_SHIFT));
	set_64bit_val(wqe, 16,
		      info->total_len |
		      FIELD_PREP(NSERQPSQ_FIRSTPMPBLIDXLO, info->first_pm_pbl_index));

	hdr = FIELD_PREP(NSERQPSQ_STAGKEY, info->stag_key) |
	      FIELD_PREP(NSERQPSQ_STAGINDEX, info->stag_idx) |
	      FIELD_PREP(NSERQPSQ_OPCODE, NSERQP_OP_FAST_REGISTER) |
	      FIELD_PREP(NSERQPSQ_LPBLSIZE, info->chunk_size) |
	      FIELD_PREP(NSERQPSQ_HPAGESIZE, page_size) |
	      FIELD_PREP(NSERQPSQ_STAGRIGHTS, info->access_rights) |
	      FIELD_PREP(NSERQPSQ_VABASEDTO, info->addr_type) |
	      FIELD_PREP(NSERQPSQ_READFENCE, info->read_fence) |
	      FIELD_PREP(NSERQPSQ_LOCALFENCE, info->local_fence) |
	      FIELD_PREP(NSERQPSQ_SIGCOMPL, info->signaled) |
	      FIELD_PREP(NSERQPSQ_VALID, qp->qp_uk.swqe_polarity);
	dma_wmb(); /* make sure WQE is written before valid bit is set */

	set_64bit_val(wqe, 24, hdr);

	print_hex_dump_debug("WQE: FAST_REG WQE", DUMP_PREFIX_OFFSET, 16, 8,
			     wqe, NSER_QP_WQE_MIN_SIZE, false);

	if (post_sq)
		nser_uk_qp_post_wr(&qp->qp_uk);

	return 0;
}

static int nser_null_ws_add(struct nser_sc_vsi *vsi, u8 user_pri)
{
	return 0;
}

static void nser_null_ws_remove(struct nser_sc_vsi *vsi, u8 user_pri)
{
	/* do nothing */
}

static void nser_null_ws_reset(struct nser_sc_vsi *vsi)
{
	/* do nothing */
}

/**
 * nser_sc_vsi_init - Init the vsi structure
 * @vsi: pointer to vsi structure to initialize
 * @info: the info used to initialize the vsi struct
 */
void nser_sc_vsi_init(struct nser_sc_vsi  *vsi,
		      struct nser_vsi_init_info *info)
{
	u8 i;

	vsi->dev = info->dev;
	vsi->back_vsi = info->back_vsi;
	vsi->register_qset = info->register_qset;
	vsi->unregister_qset = info->unregister_qset;
	vsi->mtu = info->params->mtu;
	vsi->vsi_idx = info->pf_data_vsi_num;
	vsi->vm_vf_type = info->vm_vf_type;

	nser_set_qos_info(vsi, info->params);
	for (i = 0; i < NSER_MAX_USER_PRIORITY; i++) {
		mutex_init(&vsi->qos[i].qos_mutex);
		INIT_LIST_HEAD(&vsi->qos[i].qplist);
	}
	if (vsi->register_qset || !vsi->dev->privileged) {
		vsi->dev->ws_add = nser_ws_add;
		vsi->dev->ws_remove = nser_ws_remove;
		vsi->dev->ws_reset = nser_ws_reset;
	} else {
		vsi->dev->ws_add = nser_null_ws_add;
		vsi->dev->ws_remove = nser_null_ws_remove;
		vsi->dev->ws_reset = nser_null_ws_reset;
	}
}

/**
 * nser_get_stats_idx - Return stats index
 * @vsi: pointer to the vsi
 */
static u8 nser_get_stats_idx(struct nser_sc_vsi *vsi)
{
	struct nser_stats_inst_info stats_info = {};
	struct nser_sc_dev *dev = vsi->dev;
	u8 i;

	if (!nser_cqp_stats_inst_cmd(vsi, NSER_OP_STATS_ALLOCATE,
				     &stats_info))
		return stats_info.stats_idx;

	for (i = 0; i < NSER_MAX_STATS_COUNT_GEN1; i++) {
		if (!dev->stats_idx_array[i]) {
			dev->stats_idx_array[i] = true;
			return i;
		}
	}

	return NSER_INVALID_STATS_IDX;
}

/**
 * nser_vsi_stats_init - Initialize the vsi statistics
 * @vsi: pointer to the vsi structure
 * @info: The info structure used for initialization
 */
int nser_vsi_stats_init(struct nser_sc_vsi *vsi,
			struct nser_vsi_stats_info *info)
{
	struct nser_dma_mem *stats_buff_mem;

	vsi->pestat = info->pestat;
	vsi->pestat->hw = vsi->dev->hw;
	vsi->pestat->vsi = vsi;

	stats_buff_mem = &vsi->pestat->gather_info.stats_buff_mem;
	stats_buff_mem->size = ALIGN(NSER_GATHER_STATS_BUF_SIZE * 2, 1);
	stats_buff_mem->va = dma_alloc_coherent(vsi->pestat->hw->device,
						stats_buff_mem->size,
						&stats_buff_mem->pa,
						GFP_KERNEL);
	if (!stats_buff_mem->va)
		return -ENOMEM;

	vsi->pestat->gather_info.gather_stats_va = stats_buff_mem->va;
	vsi->pestat->gather_info.last_gather_stats_va =
		(void *)((uintptr_t)stats_buff_mem->va +
			 NSER_GATHER_STATS_BUF_SIZE);

	nser_hw_stats_start_timer(vsi);
	/* when stat allocation is not required default to fcn_id. */
	vsi->stats_idx = info->fcn_id;
	if (info->alloc_stats_inst) {
		u8 stats_idx = nser_get_stats_idx(vsi);

		if (stats_idx != NSER_INVALID_STATS_IDX) {
			vsi->stats_inst_alloc = true;
			vsi->stats_idx = stats_idx;
			vsi->pestat->gather_info.use_stats_inst = true;
			vsi->pestat->gather_info.stats_inst_index = stats_idx;
		}
	}

	return 0;
}

/**
 * nser_vsi_stats_free - Free the vsi stats
 * @vsi: pointer to the vsi structure
 */
void nser_vsi_stats_free(struct nser_sc_vsi *vsi)
{
	struct nser_stats_inst_info stats_info = {};

	if (vsi->stats_inst_alloc) {
		stats_info.stats_idx = vsi->stats_idx;
		nser_cqp_stats_inst_cmd(vsi, NSER_OP_STATS_FREE,
					&stats_info);
	}

	if (!vsi->pestat)
		return;

	nser_hw_stats_stop_timer(vsi);
	dma_free_coherent(vsi->pestat->hw->device,
			  vsi->pestat->gather_info.stats_buff_mem.size,
			  vsi->pestat->gather_info.stats_buff_mem.va,
			  vsi->pestat->gather_info.stats_buff_mem.pa);
	vsi->pestat->gather_info.stats_buff_mem.va = NULL;
}

/**
 * nser_get_encoded_wqe_size - given wq size, returns hardware encoded size
 * @wqsize: size of the wq (sq, rq) to encoded_size
 * @queue_type: queue type selected for the calculation algorithm
 */
u8 nser_get_encoded_wqe_size(u32 wqsize, enum nser_queue_type queue_type)
{
	u8 encoded_size = 0;

	/* cqp sq's hw coded value starts from 1 for size of 4
	 * while it starts from 0 for qp' wq's.
	 */
	if (queue_type == NSER_QUEUE_TYPE_CQP)
		encoded_size = 1;
	wqsize >>= 2;
	while (wqsize >>= 1)
		encoded_size++;

	return encoded_size;
}

/**
 * nser_sc_gather_stats - collect the statistics
 * @cqp: struct for cqp hw
 * @info: gather stats info structure
 * @scratch: u64 saved to be used during cqp completion
 */
static int nser_sc_gather_stats(struct nser_sc_cqp *cqp,
				struct nser_stats_gather_info *info,
				 u64 scratch)
{
	__le64 *wqe;
	u64 temp;

	if (info->stats_buff_mem.size < NSER_GATHER_STATS_BUF_SIZE)
		return -ENOMEM;

	wqe = nser_sc_cqp_get_next_send_wqe(cqp, scratch);
	if (!wqe)
		return -ENOMEM;

	set_64bit_val(wqe, 40,
		      FIELD_PREP(NSER_CQPSQ_STATS_HMC_FCN_INDEX, info->hmc_fcn_index));
	set_64bit_val(wqe, 32, info->stats_buff_mem.pa);

	temp = FIELD_PREP(NSER_CQPSQ_STATS_WQEVALID, cqp->polarity) |
	       FIELD_PREP(NSER_CQPSQ_STATS_USE_INST, info->use_stats_inst) |
	       FIELD_PREP(NSER_CQPSQ_STATS_INST_INDEX,
			  info->stats_inst_index) |
	       FIELD_PREP(NSER_CQPSQ_STATS_USE_HMC_FCN_INDEX,
			  info->use_hmc_fcn_index) |
	       FIELD_PREP(NSER_CQPSQ_STATS_OP, NSER_CQP_OP_GATHER_STATS);
	dma_wmb(); /* make sure WQE is written before valid bit is set */

	set_64bit_val(wqe, 24, temp);

	print_hex_dump_debug("STATS: GATHER_STATS WQE", DUMP_PREFIX_OFFSET,
			     16, 8, wqe, NSER_CQP_WQE_SIZE * 8, false);

	nser_sc_cqp_post_sq(cqp);
	nser_dbg(cqp->dev, "STATS: CQP SQ head 0x%x tail 0x%x size 0x%x\n",
		 cqp->sq_ring.head, cqp->sq_ring.tail, cqp->sq_ring.size);

	return 0;
}

/**
 * nser_sc_manage_stats_inst - allocate or free stats instance
 * @cqp: struct for cqp hw
 * @info: stats info structure
 * @alloc: alloc vs. delete flag
 * @scratch: u64 saved to be used during cqp completion
 */
static int nser_sc_manage_stats_inst(struct nser_sc_cqp *cqp,
				     struct nser_stats_inst_info *info,
				      bool alloc, u64 scratch)
{
	__le64 *wqe;
	u64 temp;

	wqe = nser_sc_cqp_get_next_send_wqe(cqp, scratch);
	if (!wqe)
		return -ENOMEM;

	set_64bit_val(wqe, 40,
		      FIELD_PREP(NSER_CQPSQ_STATS_HMC_FCN_INDEX, info->hmc_fn_id));
	temp = FIELD_PREP(NSER_CQPSQ_STATS_WQEVALID, cqp->polarity) |
	       FIELD_PREP(NSER_CQPSQ_STATS_ALLOC_INST, alloc) |
	       FIELD_PREP(NSER_CQPSQ_STATS_USE_HMC_FCN_INDEX,
			  info->use_hmc_fcn_index) |
	       FIELD_PREP(NSER_CQPSQ_STATS_INST_INDEX, info->stats_idx) |
	       FIELD_PREP(NSER_CQPSQ_STATS_OP, NSER_CQP_OP_MANAGE_STATS);

	dma_wmb(); /* make sure WQE is written before valid bit is set */

	set_64bit_val(wqe, 24, temp);

	print_hex_dump_debug("WQE: MANAGE_STATS WQE", DUMP_PREFIX_OFFSET, 16,
			     8, wqe, NSER_CQP_WQE_SIZE * 8, false);

	nser_sc_cqp_post_sq(cqp);
	return 0;
}

/**
 * nser_sc_set_up_map - set the up map table
 * @cqp: struct for cqp hw
 * @info: User priority map info
 * @scratch: u64 saved to be used during cqp completion
 */
static int nser_sc_set_up_map(struct nser_sc_cqp *cqp,
			      struct nser_up_info *info, u64 scratch)
{
	__le64 *wqe;
	u64 temp;

	wqe = nser_sc_cqp_get_next_send_wqe(cqp, scratch);
	if (!wqe)
		return -ENOMEM;

	temp = info->map[0] | LS_64_1(info->map[1], 8) |
	       LS_64_1(info->map[2], 16) | LS_64_1(info->map[3], 24) |
	       LS_64_1(info->map[4], 32) | LS_64_1(info->map[5], 40) |
	       LS_64_1(info->map[6], 48) | LS_64_1(info->map[7], 56);

	set_64bit_val(wqe, 0, temp);
	set_64bit_val(wqe, 40,
		      FIELD_PREP(NSER_CQPSQ_UP_CNPOVERRIDE, info->cnp_up_override) |
		      FIELD_PREP(NSER_CQPSQ_UP_HMCFCNIDX, info->hmc_fcn_idx));

	temp = FIELD_PREP(NSER_CQPSQ_UP_WQEVALID, cqp->polarity) |
	       FIELD_PREP(NSER_CQPSQ_UP_USEVLAN, info->use_vlan) |
	       FIELD_PREP(NSER_CQPSQ_UP_USEOVERRIDE,
			  info->use_cnp_up_override) |
	       FIELD_PREP(NSER_CQPSQ_UP_OP, NSER_CQP_OP_UP_MAP);
	dma_wmb(); /* make sure WQE is written before valid bit is set */

	set_64bit_val(wqe, 24, temp);

	print_hex_dump_debug("WQE: UPMAP WQE", DUMP_PREFIX_OFFSET, 16, 8, wqe,
			     NSER_CQP_WQE_SIZE * 8, false);
	nser_sc_cqp_post_sq(cqp);

	return 0;
}

/**
 * nser_sc_set_cnp - set the cnp prio
 * @cqp: struct for cqp hw
 * @info: cnp prio info
 * @scratch: u64 saved to be used during cqp completion
 */
static int nser_sc_set_cnp(struct nser_sc_cqp *cqp,
			   struct nser_cnp_info *info, u64 scratch)
{
	__le64 *wqe;
	u64 temp;

	wqe = nser_sc_cqp_get_next_send_wqe(cqp, scratch);
	if (!wqe)
		return -ENOMEM;

	set_64bit_val(wqe, 0, 0);
	set_64bit_val(wqe, 40, 0);
	set_64bit_val(wqe, 16, 0);

	temp = FIELD_PREP(NSER_CQPSQ_UP_WQEVALID, cqp->polarity) |
	       FIELD_PREP(NSERQPC_CNP_DSCP, info->cnp_dscp) |
	       FIELD_PREP(NSERQPC_CNP_802P_PRIO,
			  info->cnp_802p_prio) |
	       FIELD_PREP(NSER_CQPSQ_UP_OP, NSER_CQP_OP_CNP_DSCP_PRIO);
	dma_wmb(); /* make sure WQE is written before valid bit is set */

	set_64bit_val(wqe, 24, temp);

	print_hex_dump_debug("WQE: CNP PRIO WQE", DUMP_PREFIX_OFFSET, 16, 8, wqe,
			     NSER_CQP_WQE_SIZE * 8, false);
	nser_sc_cqp_post_sq(cqp);

	return 0;
}

/**
 * nser_sc_manage_ws_node - create/modify/destroy WS node
 * @cqp: struct for cqp hw
 * @info: node info structure
 * @node_op: 0 for add 1 for modify, 2 for delete
 * @scratch: u64 saved to be used during cqp completion
 */
static int nser_sc_manage_ws_node(struct nser_sc_cqp *cqp,
				  struct nser_ws_node_info *info,
				   enum nser_ws_node_op node_op, u64 scratch)
{
	__le64 *wqe;
	u64 temp = 0;

	wqe = nser_sc_cqp_get_next_send_wqe(cqp, scratch);
	if (!wqe)
		return -ENOMEM;

	set_64bit_val(wqe, 32,
		      FIELD_PREP(NSER_CQPSQ_WS_VSI, info->vsi) |
		      FIELD_PREP(NSER_CQPSQ_WS_WEIGHT, info->weight));

	temp = FIELD_PREP(NSER_CQPSQ_WS_WQEVALID, cqp->polarity) |
	       FIELD_PREP(NSER_CQPSQ_WS_NODEOP, node_op) |
	       FIELD_PREP(NSER_CQPSQ_WS_ENABLENODE, info->enable) |
	       FIELD_PREP(NSER_CQPSQ_WS_NODETYPE, info->type_leaf) |
	       FIELD_PREP(NSER_CQPSQ_WS_PRIOTYPE, info->prio_type) |
	       FIELD_PREP(NSER_CQPSQ_WS_TC, info->tc) |
	       FIELD_PREP(NSER_CQPSQ_WS_OP, NSER_CQP_OP_WORK_SCHED_NODE) |
	       FIELD_PREP(NSER_CQPSQ_WS_PARENTID, info->parent_id) |
	       FIELD_PREP(NSER_CQPSQ_WS_NODEID, info->id);
	dma_wmb(); /* make sure WQE is written before valid bit is set */

	set_64bit_val(wqe, 24, temp);

	print_hex_dump_debug("WQE: MANAGE_WS WQE", DUMP_PREFIX_OFFSET, 16, 8,
			     wqe, NSER_CQP_WQE_SIZE * 8, false);
	nser_sc_cqp_post_sq(cqp);

	return 0;
}

/**
 * nser_sc_qp_flush_wqes - flush qp's wqe
 * @qp: sc qp
 * @info: dlush information
 * @scratch: u64 saved to be used during cqp completion
 * @post_sq: flag for cqp db to ring
 */
int nser_sc_qp_flush_wqes(struct nser_sc_qp *qp,
			  struct nser_qp_flush_info *info, u64 scratch,
			   bool post_sq)
{
	u64 temp = 0;
	__le64 *wqe;
	struct nser_sc_cqp *cqp;
	u64 hdr;
	bool flush_sq = false, flush_rq = false;

	if (info->rq && !qp->flush_rq)
		flush_rq = true;
	if (info->sq && !qp->flush_sq)
		flush_sq = true;
	qp->flush_sq |= flush_sq;
	qp->flush_rq |= flush_rq;

	if (!flush_sq && !flush_rq) {
		nser_dbg(qp->dev,
			 "CQP: Additional flush request ignored for qp %x\n",
			  qp->qp_uk.qp_id);
		return -EALREADY;
	}

	cqp = qp->pd->dev->cqp;
	wqe = nser_sc_cqp_get_next_send_wqe(cqp, scratch);
	if (!wqe)
		return -ENOMEM;

	if (info->userflushcode) {
		if (flush_rq)
			temp |= FIELD_PREP(NSER_CQPSQ_FWQE_RQMNERR,
					   info->rq_minor_code) |
				FIELD_PREP(NSER_CQPSQ_FWQE_RQMJERR,
					   info->rq_major_code);
		if (flush_sq)
			temp |= FIELD_PREP(NSER_CQPSQ_FWQE_SQMNERR,
					   info->sq_minor_code) |
				FIELD_PREP(NSER_CQPSQ_FWQE_SQMJERR,
					   info->sq_major_code);
	}
	set_64bit_val(wqe, 16, temp);

	temp = (info->generate_ae) ?
		info->ae_code | FIELD_PREP(NSER_CQPSQ_FWQE_AESOURCE,
					   info->ae_src) : 0;
	set_64bit_val(wqe, 8, temp);

	hdr = qp->qp_uk.qp_id |
	      FIELD_PREP(NSER_CQPSQ_OPCODE, NSER_CQP_OP_FLUSH_WQES) |
	      FIELD_PREP(NSER_CQPSQ_FWQE_GENERATE_AE, info->generate_ae) |
	      FIELD_PREP(NSER_CQPSQ_FWQE_USERFLCODE, info->userflushcode) |
	      FIELD_PREP(NSER_CQPSQ_FWQE_FLUSHSQ, flush_sq) |
	      FIELD_PREP(NSER_CQPSQ_FWQE_FLUSHRQ, flush_rq) |
	      FIELD_PREP(NSER_CQPSQ_WQEVALID, cqp->polarity);
	dma_wmb(); /* make sure WQE is written before valid bit is set */

	set_64bit_val(wqe, 24, hdr);

	print_hex_dump_debug("WQE: QP_FLUSH WQE", DUMP_PREFIX_OFFSET, 16, 8,
			     wqe, NSER_CQP_WQE_SIZE * 8, false);
	if (post_sq)
		nser_sc_cqp_post_sq(cqp);

	return 0;
}

/*** nser_sc_qp_upload_context - upload qp's context
 * @dev: sc device struct
 * @info: upload context info ptr for return
 * @scratch: u64 saved to be used during cqp completion
 * @post_sq: flag for cqp db to ring
 */
static int nser_sc_qp_upload_context(struct nser_sc_dev *dev,
				     struct nser_upload_context_info *info,
				      u64 scratch, bool post_sq)
{
	__le64 *wqe;
	struct nser_sc_cqp *cqp;
	u64 hdr;

	cqp = dev->cqp;
	wqe = nser_sc_cqp_get_next_send_wqe(cqp, scratch);
	if (!wqe)
		return -ENOMEM;

	set_64bit_val(wqe, 16, info->buf_pa);

	hdr = FIELD_PREP(NSER_CQPSQ_UCTX_QPID, info->qp_id) |
	      FIELD_PREP(NSER_CQPSQ_OPCODE, NSER_CQP_OP_UPLOAD_CONTEXT) |
	      FIELD_PREP(NSER_CQPSQ_UCTX_QPTYPE, info->qp_type) |
	      FIELD_PREP(NSER_CQPSQ_UCTX_RAWFORMAT, info->raw_format) |
	      FIELD_PREP(NSER_CQPSQ_UCTX_FREEZEQP, info->freeze_qp) |
	      FIELD_PREP(NSER_CQPSQ_WQEVALID, cqp->polarity);
	dma_wmb(); /* make sure WQE is written before valid bit is set */

	set_64bit_val(wqe, 24, hdr);

	print_hex_dump_debug("WQE: QP_UPLOAD_CTX WQE", DUMP_PREFIX_OFFSET, 16,
			     8, wqe, NSER_CQP_WQE_SIZE * 8, false);
	if (post_sq)
		nser_sc_cqp_post_sq(cqp);

	return 0;
}

/**
 * nser_sc_suspend_qp - suspend qp for param change
 * @cqp: struct for cqp hw
 * @qp: sc qp struct
 * @scratch: u64 saved to be used during cqp completion
 */
static int nser_sc_suspend_qp(struct nser_sc_cqp *cqp, struct nser_sc_qp *qp,
			      u64 scratch)
{
	u64 hdr;
	__le64 *wqe;

	wqe = nser_sc_cqp_get_next_send_wqe(cqp, scratch);
	if (!wqe)
		return -ENOMEM;

	hdr = FIELD_PREP(NSER_CQPSQ_SUSPENDQP_QPID, qp->qp_uk.qp_id) |
	      FIELD_PREP(NSER_CQPSQ_OPCODE, NSER_CQP_OP_SUSPEND_QP) |
	      FIELD_PREP(NSER_CQPSQ_WQEVALID, cqp->polarity);
	dma_wmb(); /* make sure WQE is written before valid bit is set */

	set_64bit_val(wqe, 24, hdr);

	print_hex_dump_debug("WQE: SUSPEND_QP WQE", DUMP_PREFIX_OFFSET, 16, 8,
			     wqe, NSER_CQP_WQE_SIZE * 8, false);
	nser_sc_cqp_post_sq(cqp);

	return 0;
}

/**
 * nser_sc_resume_qp - resume qp after suspend
 * @cqp: struct for cqp hw
 * @qp: sc qp struct
 * @scratch: u64 saved to be used during cqp completion
 */
static int nser_sc_resume_qp(struct nser_sc_cqp *cqp, struct nser_sc_qp *qp,
			     u64 scratch)
{
	u64 hdr;
	__le64 *wqe;

	wqe = nser_sc_cqp_get_next_send_wqe(cqp, scratch);
	if (!wqe)
		return -ENOMEM;

	set_64bit_val(wqe, 16,
		      FIELD_PREP(NSER_CQPSQ_RESUMEQP_QSHANDLE, qp->qs_handle));

	hdr = FIELD_PREP(NSER_CQPSQ_RESUMEQP_QPID, qp->qp_uk.qp_id) |
	      FIELD_PREP(NSER_CQPSQ_OPCODE, NSER_CQP_OP_RESUME_QP) |
	      FIELD_PREP(NSER_CQPSQ_WQEVALID, cqp->polarity);
	dma_wmb(); /* make sure WQE is written before valid bit is set */

	set_64bit_val(wqe, 24, hdr);

	print_hex_dump_debug("WQE: RESUME_QP WQE", DUMP_PREFIX_OFFSET, 16, 8,
			     wqe, NSER_CQP_WQE_SIZE * 8, false);
	nser_sc_cqp_post_sq(cqp);

	return 0;
}

/**
 * nser_sc_cq_ack - acknowledge completion q
 * @cq: cq struct
 */
static inline void nser_sc_cq_ack(struct nser_sc_cq *cq)
{
	writel(cq->cq_uk.cq_id, cq->cq_uk.cq_ack_db);
}

/**
 * nser_sc_cq_init - initialize completion q
 * @cq: cq struct
 * @info: cq initialization info
 */
int nser_sc_cq_init(struct nser_sc_cq *cq, struct nser_cq_init_info *info)
{
	int ret_code;
	u32 pble_obj_cnt;

	pble_obj_cnt = info->dev->hmc_info->hmc_obj[NSER_HMC_IW_PBLE].cnt;
	if (info->virtual_map && info->first_pm_pbl_idx >= pble_obj_cnt)
		return -EINVAL;

	cq->cq_pa = info->cq_base_pa;
	cq->dev = info->dev;
	cq->ceq_id = info->ceq_id;
	info->cq_uk_init_info.cqe_alloc_db = cq->dev->cq_arm_db;
	info->cq_uk_init_info.cq_ack_db = cq->dev->cq_ack_db;
	ret_code = nser_uk_cq_init(&cq->cq_uk, &info->cq_uk_init_info);
	if (ret_code)
		return ret_code;

	cq->virtual_map = info->virtual_map;
	cq->pbl_chunk_size = info->pbl_chunk_size;
	cq->ceqe_mask = info->ceqe_mask;
	cq->cq_type = (info->type) ? info->type : NSER_CQ_TYPE_RDMA;
	cq->shadow_area_pa = info->shadow_area_pa;
	cq->shadow_read_threshold = info->shadow_read_threshold;
	cq->ceq_id_valid = info->ceq_id_valid;
	cq->tph_en = info->tph_en;
	cq->tph_val = info->tph_val;
	cq->first_pm_pbl_idx = info->first_pm_pbl_idx;
	cq->vsi = info->vsi;

	return 0;
}

/**
 * nser_sc_cq_create - create completion q
 * @cq: cq struct
 * @scratch: u64 saved to be used during cqp completion
 * @check_overflow: flag for overflow check
 * @post_sq: flag for cqp db to ring
 */
static int nser_sc_cq_create(struct nser_sc_cq *cq, u64 scratch,
			     bool check_overflow, bool post_sq)
{
	__le64 *wqe;
	struct nser_sc_cqp *cqp;
	u64 hdr;
	struct nser_sc_ceq *ceq;
	int ret_code = 0;

	cqp = cq->dev->cqp;
	if (cq->cq_uk.cq_id > (cqp->dev->hmc_info->hmc_obj[NSER_HMC_IW_CQ].max_cnt - 1))
		return -EINVAL;

	if (cq->ceq_id > (cq->dev->hmc_fpm_misc.max_ceqs - 1))
		return -EINVAL;

	ceq = cq->dev->ceq[cq->ceq_id];
	if (ceq && ceq->reg_cq)
		ret_code = nser_sc_add_cq_ctx(ceq, cq);

	if (ret_code)
		return ret_code;

	wqe = nser_sc_cqp_get_next_send_wqe(cqp, scratch);
	if (!wqe) {
		if (ceq && ceq->reg_cq)
			nser_sc_remove_cq_ctx(ceq, cq);
		return -ENOMEM;
	}

	set_64bit_val(wqe, 0, cq->cq_uk.cq_size);
	set_64bit_val(wqe, 8, RS_64_1(cq, 1));
	set_64bit_val(wqe, 16,
		      FIELD_PREP(NSER_CQPSQ_CQ_SHADOW_READ_THRESHOLD, cq->shadow_read_threshold));
	set_64bit_val(wqe, 32, (cq->virtual_map ? 0 : cq->cq_pa));
	set_64bit_val(wqe, 40, cq->shadow_area_pa);
	set_64bit_val(wqe, 48,
		      FIELD_PREP(NSER_CQPSQ_CQ_FIRSTPMPBLIDX,
				 (cq->virtual_map ? cq->first_pm_pbl_idx : 0)));
	set_64bit_val(wqe, 56,
		      FIELD_PREP(NSER_CQPSQ_TPHVAL, cq->tph_val) |
		      FIELD_PREP(NSER_CQPSQ_VSIIDX, cq->vsi->vsi_idx));

	hdr = FLD_LS_64(cq->dev, cq->cq_uk.cq_id, NSER_CQPSQ_CQ_CQID) |
	      FLD_LS_64(cq->dev, (cq->ceq_id_valid ? cq->ceq_id : 0),
			NSER_CQPSQ_CQ_CEQID) |
	      FIELD_PREP(NSER_CQPSQ_OPCODE, NSER_CQP_OP_CREATE_CQ) |
	      FIELD_PREP(NSER_CQPSQ_CQ_LPBLSIZE, cq->pbl_chunk_size) |
	      FIELD_PREP(NSER_CQPSQ_CQ_CHKOVERFLOW, check_overflow) |
	      FIELD_PREP(NSER_CQPSQ_CQ_VIRTMAP, cq->virtual_map) |
	      FIELD_PREP(NSER_CQPSQ_CQ_ENCEQEMASK, cq->ceqe_mask) |
	      FIELD_PREP(NSER_CQPSQ_CQ_CEQIDVALID, cq->ceq_id_valid) |
	      FIELD_PREP(NSER_CQPSQ_TPHEN, cq->tph_en) |
	      FIELD_PREP(NSER_CQPSQ_CQ_AVOIDMEMCNFLCT,
			 cq->cq_uk.avoid_mem_cflct) |
	      FIELD_PREP(NSER_CQPSQ_WQEVALID, cqp->polarity);

	dma_wmb(); /* make sure WQE is written before valid bit is set */

	set_64bit_val(wqe, 24, hdr);

	print_hex_dump_debug("WQE: CQ_CREATE WQE", DUMP_PREFIX_OFFSET, 16, 8,
			     wqe, NSER_CQP_WQE_SIZE * 8, false);
	if (post_sq)
		nser_sc_cqp_post_sq(cqp);

	return 0;
}

/**
 * nser_sc_cq_destroy - destroy completion q
 * @cq: cq struct
 * @scratch: u64 saved to be used during cqp completion
 * @post_sq: flag for cqp db to ring
 */
int nser_sc_cq_destroy(struct nser_sc_cq *cq, u64 scratch, bool post_sq)
{
	struct nser_sc_cqp *cqp;
	__le64 *wqe;
	u64 hdr;
	struct nser_sc_ceq *ceq;

	cqp = cq->dev->cqp;
	wqe = nser_sc_cqp_get_next_send_wqe(cqp, scratch);
	if (!wqe)
		return -ENOMEM;

	ceq = cq->dev->ceq[cq->ceq_id];
	if (ceq && ceq->reg_cq)
		nser_sc_remove_cq_ctx(ceq, cq);

	set_64bit_val(wqe, 0, cq->cq_uk.cq_size);
	set_64bit_val(wqe, 8, RS_64_1(cq, 1));
	set_64bit_val(wqe, 40, cq->shadow_area_pa);
	set_64bit_val(wqe, 48,
		      (cq->virtual_map ? cq->first_pm_pbl_idx : 0));

	hdr = cq->cq_uk.cq_id |
	      FLD_LS_64(cq->dev, (cq->ceq_id_valid ? cq->ceq_id : 0),
			NSER_CQPSQ_CQ_CEQID) |
	      FIELD_PREP(NSER_CQPSQ_OPCODE, NSER_CQP_OP_DESTROY_CQ) |
	      FIELD_PREP(NSER_CQPSQ_CQ_LPBLSIZE, cq->pbl_chunk_size) |
	      FIELD_PREP(NSER_CQPSQ_CQ_VIRTMAP, cq->virtual_map) |
	      FIELD_PREP(NSER_CQPSQ_CQ_ENCEQEMASK, cq->ceqe_mask) |
	      FIELD_PREP(NSER_CQPSQ_CQ_CEQIDVALID, cq->ceq_id_valid) |
	      FIELD_PREP(NSER_CQPSQ_TPHEN, cq->tph_en) |
	      FIELD_PREP(NSER_CQPSQ_CQ_AVOIDMEMCNFLCT, cq->cq_uk.avoid_mem_cflct) |
	      FIELD_PREP(NSER_CQPSQ_WQEVALID, cqp->polarity);
	dma_wmb(); /* make sure WQE is written before valid bit is set */

	set_64bit_val(wqe, 24, hdr);

	print_hex_dump_debug("WQE: CQ_DESTROY WQE", DUMP_PREFIX_OFFSET, 16, 8,
			     wqe, NSER_CQP_WQE_SIZE * 8, false);
	if (post_sq)
		nser_sc_cqp_post_sq(cqp);

	return 0;
}

/**
 * nser_sc_cq_resize - set resized cq buffer info
 * @cq: resized cq
 * @info: resized cq buffer info
 */
void nser_sc_cq_resize(struct nser_sc_cq *cq, struct nser_modify_cq_info *info)
{
	cq->virtual_map = info->virtual_map;
	cq->cq_pa = info->cq_pa;
	cq->first_pm_pbl_idx = info->first_pm_pbl_idx;
	cq->pbl_chunk_size = info->pbl_chunk_size;
	nser_uk_cq_resize(&cq->cq_uk, info->cq_base, info->cq_size);
}

/**
 * nser_sc_cq_modify - modify a Completion Queue
 * @cq: cq struct
 * @info: modification info struct
 * @scratch: u64 saved to be used during cqp completion
 * @post_sq: flag to post to sq
 */
static int nser_sc_cq_modify(struct nser_sc_cq *cq,
			     struct nser_modify_cq_info *info, u64 scratch,
			      bool post_sq)
{
	struct nser_sc_cqp *cqp;
	__le64 *wqe;
	u64 hdr;
	u32 pble_obj_cnt;

	pble_obj_cnt = cq->dev->hmc_info->hmc_obj[NSER_HMC_IW_PBLE].cnt;
	if (info->cq_resize && info->virtual_map &&
	    info->first_pm_pbl_idx >= pble_obj_cnt)
		return -EINVAL;

	cqp = cq->dev->cqp;
	wqe = nser_sc_cqp_get_next_send_wqe(cqp, scratch);
	if (!wqe)
		return -ENOMEM;

	set_64bit_val(wqe, 0, info->cq_size);
	set_64bit_val(wqe, 8, RS_64_1(cq, 1));
	set_64bit_val(wqe, 16,
		      FIELD_PREP(NSER_CQPSQ_CQ_SHADOW_READ_THRESHOLD, info->shadow_read_threshold));
	set_64bit_val(wqe, 32, info->cq_pa);
	set_64bit_val(wqe, 40, cq->shadow_area_pa);
	set_64bit_val(wqe, 48, info->first_pm_pbl_idx);
	set_64bit_val(wqe, 56,
		      FIELD_PREP(NSER_CQPSQ_TPHVAL, cq->tph_val) |
		      FIELD_PREP(NSER_CQPSQ_VSIIDX, cq->vsi->vsi_idx));

	hdr = cq->cq_uk.cq_id |
	      FLD_LS_64(cq->dev, (cq->ceq_id_valid ? cq->ceq_id : 0),
			NSER_CQPSQ_CQ_CEQID) |
	      FIELD_PREP(NSER_CQPSQ_OPCODE, NSER_CQP_OP_MODIFY_CQ) |
	      FIELD_PREP(NSER_CQPSQ_CQ_CQRESIZE, info->cq_resize) |
	      FIELD_PREP(NSER_CQPSQ_CQ_LPBLSIZE, info->pbl_chunk_size) |
	      FIELD_PREP(NSER_CQPSQ_CQ_CHKOVERFLOW, info->check_overflow) |
	      FIELD_PREP(NSER_CQPSQ_CQ_VIRTMAP, info->virtual_map) |
	      FIELD_PREP(NSER_CQPSQ_CQ_ENCEQEMASK, cq->ceqe_mask) |
	      FIELD_PREP(NSER_CQPSQ_CQ_CEQIDVALID, cq->ceq_id_valid) |
	      FIELD_PREP(NSER_CQPSQ_TPHEN, cq->tph_en) |
	      FIELD_PREP(NSER_CQPSQ_CQ_AVOIDMEMCNFLCT,
			 cq->cq_uk.avoid_mem_cflct) |
	      FIELD_PREP(NSER_CQPSQ_WQEVALID, cqp->polarity);
	dma_wmb(); /* make sure WQE is written before valid bit is set */

	set_64bit_val(wqe, 24, hdr);

	print_hex_dump_debug("WQE: CQ_MODIFY WQE", DUMP_PREFIX_OFFSET, 16, 8,
			     wqe, NSER_CQP_WQE_SIZE * 8, false);
	if (post_sq)
		nser_sc_cqp_post_sq(cqp);

	return 0;
}

/**
 * nser_check_cqp_progress - check cqp processing progress
 * @timeout: timeout info struct
 * @dev: sc device struct
 */
void nser_check_cqp_progress(struct nser_cqp_timeout *timeout, struct nser_sc_dev *dev)
{
	if (timeout->compl_cqp_cmds != dev->cqp_cmd_stats[NSER_OP_CMPL_CMDS]) {
		timeout->compl_cqp_cmds = dev->cqp_cmd_stats[NSER_OP_CMPL_CMDS];
		timeout->count = 0;
	} else {
		if (dev->cqp_cmd_stats[NSER_OP_REQ_CMDS] !=
		    timeout->compl_cqp_cmds)
			timeout->count++;
	}
}

/**
 * nser_get_cqp_reg_info - get head and tail for cqp using registers
 * @cqp: struct for cqp hw
 * @val: cqp tail register value
 * @tail: wqtail register value
 * @error: cqp processing err
 */
static inline void nser_get_cqp_reg_info(struct nser_sc_cqp *cqp, u32 *val,
					 u32 *tail, u32 *error)
{
	*val = readl(cqp->dev->hw_regs[NSER_CQPTAIL]);
	*tail = FIELD_GET(NSER_CQPTAIL_WQTAIL, *val);
	*error = FIELD_GET(NSER_CQPTAIL_CQP_OP_ERR, *val);
}

/**
 * nser_cqp_poll_registers - poll cqp registers
 * @cqp: struct for cqp hw
 * @tail: wqtail register value
 * @count: how many times to try for completion
 */
static int nser_cqp_poll_registers(struct nser_sc_cqp *cqp, u32 tail,
				   u32 count)
{
	u32 i = 0;
	u32 newtail, error, val;

	while (i++ < count) {
		nser_get_cqp_reg_info(cqp, &val, &newtail, &error);
		if (error) {
			error = readl(cqp->dev->hw_regs[NSER_CQPERRCODES]);
			nser_dbg(cqp->dev,
				 "CQP: CQPERRCODES error_code[x%08X]\n",
				  error);
			return -EIO;
		}
		if (newtail != tail) {
			/* SUCCESS */
			NSER_RING_MOVE_TAIL(cqp->sq_ring);
			cqp->dev->cqp_cmd_stats[NSER_OP_CMPL_CMDS]++;
			return 0;
		}
		udelay(cqp->dev->hw_attrs.max_sleep_count);
	}

	return -ETIMEDOUT;
}

/**
 * nser_sc_decode_fpm_commit - decode a 64 bit value into count and base
 * @dev: sc device struct
 * @buf: pointer to commit buffer
 * @buf_idx: buffer index
 * @obj_info: object info pointer
 * @rsrc_idx: indexs of memory resource
 */
static u64 nser_sc_decode_fpm_commit(struct nser_sc_dev *dev, __le64 *buf,
				     u32 buf_idx, struct nser_hmc_obj_info *obj_info,
				      u32 rsrc_idx)
{
	u64 temp;

	get_64bit_val(buf, buf_idx, &temp);

	switch (rsrc_idx) {
	case NSER_HMC_IW_QP:
		obj_info[rsrc_idx].cnt = (u32)FIELD_GET(NSER_COMMIT_FPM_QPCNT, temp);
		break;
	case NSER_HMC_IW_CQ:
		obj_info[rsrc_idx].cnt = (u32)FLD_RS_64(dev, temp, NSER_COMMIT_FPM_CQCNT);
		break;
	default:
		obj_info[rsrc_idx].cnt = (u32)temp;
		break;
	}

	obj_info[rsrc_idx].base = (u64)RS_64_1(temp, NSER_COMMIT_FPM_BASE_S) * 512;

	return temp;
}

/**
 * nser_sc_parse_fpm_commit_buf - parse fpm commit buffer
 * @dev: pointer to dev struct
 * @buf: ptr to fpm commit buffer
 * @info: ptr to nser_hmc_obj_info struct
 * @sd: number of SDs for HMC objects
 *
 * parses fpm commit info and copy base value
 * of hmc objects in hmc_info
 */
static int nser_sc_parse_fpm_commit_buf(struct nser_sc_dev *dev, __le64 *buf,
					struct nser_hmc_obj_info *info,
					 u32 *sd)
{
	u64 size;
	u32 i;
	u64 max_base = 0;
	u32 last_hmc_obj = 0;

	nser_sc_decode_fpm_commit(dev, buf, 0, info, NSER_HMC_IW_IRRQ_LITE);
	nser_sc_decode_fpm_commit(dev, buf, 8, info, NSER_HMC_IW_IRRQ);
	nser_sc_decode_fpm_commit(dev, buf, 16, info, NSER_HMC_IW_ORRQ);
	nser_sc_decode_fpm_commit(dev, buf, 24, info, NSER_HMC_IW_XF);
	nser_sc_decode_fpm_commit(dev, buf, 32, info, NSER_HMC_IW_SQCQE);
	nser_sc_decode_fpm_commit(dev, buf, 40, info, NSER_HMC_IW_RQCQE);
	nser_sc_decode_fpm_commit(dev, buf, 48, info, NSER_HMC_IW_CQP);
	nser_sc_decode_fpm_commit(dev, buf, 56, info, NSER_HMC_IW_AEQ);
	nser_sc_decode_fpm_commit(dev, buf, 64, info, NSER_HMC_IW_QP);
	nser_sc_decode_fpm_commit(dev, buf, 72, info, NSER_HMC_IW_CQ);
	nser_sc_decode_fpm_commit(dev, buf, 80, info, NSER_HMC_IW_CEQ);
	nser_sc_decode_fpm_commit(dev, buf, 88, info, NSER_HMC_IW_MR);
	nser_sc_decode_fpm_commit(dev, buf, 96, info, NSER_HMC_IW_MG);
	nser_sc_decode_fpm_commit(dev, buf, 104, info, NSER_HMC_IW_MG_ID);
	nser_sc_decode_fpm_commit(dev, buf, 112, info, NSER_HMC_IW_AH);
	nser_sc_decode_fpm_commit(dev, buf, 120, info, NSER_HMC_IW_ARP);
	nser_sc_decode_fpm_commit(dev, buf, 128, info, NSER_HMC_IW_DUP_IRRQ);
	nser_sc_decode_fpm_commit(dev, buf, 136, info, NSER_HMC_IW_PBLE);
	nser_sc_decode_fpm_commit(dev, buf, 144, info, NSER_HMC_IW_FW);
	nser_sc_decode_fpm_commit(dev, buf, 152, info, NSER_HMC_IW_SQCQEFL);
	nser_sc_decode_fpm_commit(dev, buf, 160, info, NSER_HMC_IW_RQCQEFL);
	nser_sc_decode_fpm_commit(dev, buf, 168, info, NSER_HMC_IW_XFFL);
	nser_sc_decode_fpm_commit(dev, buf, 176, info, NSER_HMC_IW_IRRQ_LITE_FL);
	nser_sc_decode_fpm_commit(dev, buf, 184, info, NSER_HMC_IW_ORRQFL);

	/* searching for the last object in HMC to find the size of the HMC area. */
	for (i = NSER_HMC_IW_IRRQ_LITE; i < NSER_HMC_IW_MAX; i++) {
		if (info[i].base > max_base) {
			max_base = info[i].base;
			last_hmc_obj = i;
		}
	}

	size = info[last_hmc_obj].cnt * info[last_hmc_obj].size +
	       info[last_hmc_obj].base;

	if (size & 0x1FFFFF)
		*sd = (u32)((size >> 21) + 1); /* add 1 for remainder */
	else
		*sd = (u32)(size >> 21);

	return 0;
}

/**
 * nser_sc_decode_fpm_query() - Decode a 64 bit value into max count and size
 * @buf: ptr to fpm query buffer
 * @buf_idx: index into buf
 * @obj_info: ptr to nser_hmc_obj_info struct
 * @rsrc_idx: resource index into info
 *
 * Decode a 64 bit value from fpm query buffer into max count and size
 */
static u64 nser_sc_decode_fpm_query(__le64 *buf, u32 buf_idx,
				    struct nser_hmc_obj_info *obj_info,
				     u32 rsrc_idx)
{
	u64 temp;
	u32 size;

	get_64bit_val(buf, buf_idx, &temp);
	obj_info[rsrc_idx].max_cnt = (u32)temp;
	size = (u32)RS_64_1(temp, 32);
	obj_info[rsrc_idx].size = size;

	return temp;
}

/**
 * nser_sc_parse_fpm_query_buf() - parses fpm query buffer
 * @dev: ptr to shared code device
 * @buf: ptr to fpm query buffer
 * @hmc_info: ptr to nser_hmc_obj_info struct
 * @hmc_fpm_misc: ptr to fpm data
 *
 * parses fpm query buffer and copy max_cnt and
 * size value of hmc objects in hmc_info
 */
static int nser_sc_parse_fpm_query_buf(struct nser_sc_dev *dev, __le64 *buf,
				       struct nser_hmc_info *hmc_info,
					struct nser_hmc_fpm_misc *hmc_fpm_misc)
{
	struct nser_hmc_obj_info *obj_info;
	u64 temp;
	u16 max_pe_sds;

	obj_info = hmc_info->hmc_obj;

	get_64bit_val(buf, 0, &temp);
	hmc_info->first_sd_index = (u16)FIELD_GET(NSER_QUERY_FPM_FIRST_PE_SD_INDEX, temp);
	max_pe_sds = (u16)FIELD_GET(NSER_QUERY_FPM_MAX_PE_SDS, temp);

	hmc_fpm_misc->max_sds = max_pe_sds;
	hmc_info->sd_table.sd_cnt = max_pe_sds + hmc_info->first_sd_index;

	nser_sc_decode_fpm_query(buf, 8, obj_info, NSER_HMC_IW_IRRQ_LITE);
	nser_sc_decode_fpm_query(buf, 16, obj_info, NSER_HMC_IW_IRRQ);

	nser_sc_decode_fpm_query(buf, 24, obj_info, NSER_HMC_IW_ORRQ);
	nser_sc_decode_fpm_query(buf, 32, obj_info, NSER_HMC_IW_XF);
	nser_sc_decode_fpm_query(buf, 40, obj_info, NSER_HMC_IW_SQCQE);

	nser_sc_decode_fpm_query(buf, 48, obj_info, NSER_HMC_IW_RQCQE);
	nser_sc_decode_fpm_query(buf, 56, obj_info, NSER_HMC_IW_CQP);
	nser_sc_decode_fpm_query(buf, 64, obj_info, NSER_HMC_IW_AEQ);

	nser_sc_decode_fpm_query(buf, 72, obj_info, NSER_HMC_IW_QP);
	nser_sc_decode_fpm_query(buf, 80, obj_info, NSER_HMC_IW_CQ);
	nser_sc_decode_fpm_query(buf, 88, obj_info, NSER_HMC_IW_CEQ);
	hmc_fpm_misc->max_ceqs = obj_info[10].max_cnt;

	nser_sc_decode_fpm_query(buf, 96, obj_info, NSER_HMC_IW_MR);

	nser_sc_decode_fpm_query(buf, 104, obj_info, NSER_HMC_IW_MG);
	nser_sc_decode_fpm_query(buf, 112, obj_info, NSER_HMC_IW_MG_ID);
	nser_sc_decode_fpm_query(buf, 120, obj_info, NSER_HMC_IW_AH);
	nser_sc_decode_fpm_query(buf, 128, obj_info, NSER_HMC_IW_ARP);
	nser_sc_decode_fpm_query(buf, 136, obj_info, NSER_HMC_IW_DUP_IRRQ);
	nser_sc_decode_fpm_query(buf, 144, obj_info, NSER_HMC_IW_PBLE);
	nser_sc_decode_fpm_query(buf, 152, obj_info, NSER_HMC_IW_FW);
	nser_sc_decode_fpm_query(buf, 160, obj_info, NSER_HMC_IW_SQCQEFL);
	nser_sc_decode_fpm_query(buf, 168, obj_info, NSER_HMC_IW_RQCQEFL);
	nser_sc_decode_fpm_query(buf, 176, obj_info, NSER_HMC_IW_XFFL);
	nser_sc_decode_fpm_query(buf, 184, obj_info, NSER_HMC_IW_IRRQ_LITE_FL);
	nser_sc_decode_fpm_query(buf, 192, obj_info, NSER_HMC_IW_ORRQFL);
	nser_sc_decode_fpm_query(buf, 200, obj_info, NSER_HMC_IW_IRDSZ);

	return 0;
}

/**
 * nser_sc_find_reg_cq - find cq ctx index
 * @ceq: ceq sc structure
 * @cq: cq sc structure
 */
static u32 nser_sc_find_reg_cq(struct nser_sc_ceq *ceq,
			       struct nser_sc_cq *cq)
{
	u32 i;

	for (i = 0; i < ceq->reg_cq_size; i++) {
		if (cq == ceq->reg_cq[i])
			return i;
	}

	return NSER_INVALID_CQ_IDX;
}

/**
 * nser_sc_add_cq_ctx - add cq ctx tracking for ceq
 * @ceq: ceq sc structure
 * @cq: cq sc structure
 */
int nser_sc_add_cq_ctx(struct nser_sc_ceq *ceq, struct nser_sc_cq *cq)
{
	unsigned long flags;

	spin_lock_irqsave(&ceq->req_cq_lock, flags);

	if (ceq->reg_cq_size == ceq->elem_cnt) {
		spin_unlock_irqrestore(&ceq->req_cq_lock, flags);
		return -ENOMEM;
	}

	ceq->reg_cq[ceq->reg_cq_size++] = cq;

	spin_unlock_irqrestore(&ceq->req_cq_lock, flags);

	return 0;
}

/**
 * nser_sc_remove_cq_ctx - remove cq ctx tracking for ceq
 * @ceq: ceq sc structure
 * @cq: cq sc structure
 */
void nser_sc_remove_cq_ctx(struct nser_sc_ceq *ceq, struct nser_sc_cq *cq)
{
	unsigned long flags;
	u32 cq_ctx_idx;

	spin_lock_irqsave(&ceq->req_cq_lock, flags);
	cq_ctx_idx = nser_sc_find_reg_cq(ceq, cq);
	if (cq_ctx_idx == NSER_INVALID_CQ_IDX)
		goto exit;

	ceq->reg_cq_size--;
	if (cq_ctx_idx != ceq->reg_cq_size)
		ceq->reg_cq[cq_ctx_idx] = ceq->reg_cq[ceq->reg_cq_size];
	ceq->reg_cq[ceq->reg_cq_size] = NULL;

exit:
	spin_unlock_irqrestore(&ceq->req_cq_lock, flags);
}

/**
 * nser_sc_cqp_init - Initialize buffers for a control Queue Pair
 * @cqp: rdma control queue pair pointer
 * @info: rdma control queue pair init info pointer
 *
 * Initializes the object and context buffers for a control Queue Pair.
 */
int nser_sc_cqp_init(struct nser_sc_cqp *cqp,
		     struct nser_cqp_init_info *info)
{
	u8 hw_sq_size;

	if (info->sq_size > NSER_CQP_SW_SQSIZE_2048 ||
	    info->sq_size < NSER_CQP_SW_SQSIZE_4 ||
	    ((info->sq_size & (info->sq_size - 1))))
		return -EINVAL;

	hw_sq_size = nser_get_encoded_wqe_size(info->sq_size,
					       NSER_QUEUE_TYPE_CQP);
	cqp->size = sizeof(*cqp);
	cqp->sq_size = info->sq_size;
	cqp->hw_sq_size = hw_sq_size;
	cqp->sq_base = info->sq;
	cqp->host_ctx = info->host_ctx;
	cqp->sq_pa = info->sq_pa;
	cqp->host_ctx_pa = info->host_ctx_pa;
	cqp->dev = info->dev;
	cqp->struct_ver = info->struct_ver;
	cqp->hw_maj_ver = info->hw_maj_ver;
	cqp->hw_min_ver = info->hw_min_ver;
	cqp->scratch_array = info->scratch_array;
	cqp->polarity = 0;
	cqp->en_datacenter_tcp = info->en_datacenter_tcp;
	cqp->ena_vf_count = info->ena_vf_count;
	cqp->hmc_profile = info->hmc_profile;
	cqp->ceqs_per_vf = info->ceqs_per_vf;
	cqp->disable_packed = info->disable_packed;
	cqp->rocev2_rto_policy = info->rocev2_rto_policy;
	memcpy(&cqp->cc_params, &info->cc_params, sizeof(cqp->cc_params));

	cqp->timely_ena = info->timely_ena;
	cqp->dcqcn_ena = info->dcqcn_ena;
	cqp->hmc_on_chip = info->hmc_on_chip;
	cqp->mirror_ena = info->mirror_ena;

	info->dev->cqp = cqp;

	NSER_RING_INIT(cqp->sq_ring, cqp->sq_size);
	cqp->dev->cqp_cmd_stats[NSER_OP_REQ_CMDS] = 0;
	cqp->dev->cqp_cmd_stats[NSER_OP_CMPL_CMDS] = 0;
	/* for the cqp commands backlog. */
	INIT_LIST_HEAD(&cqp->dev->cqp_cmd_head);

	writel(0, cqp->dev->hw_regs[NSER_CQPTAIL]);
	writel(0, cqp->dev->hw_regs[NSER_CQPDB]);
	writel(0, cqp->dev->hw_regs[NSER_CCQPSTATUS]);

	nser_dbg(cqp->dev,
		 "WQE: sq_size[%04d] hw_sq_size[%04d] sq_base[%p] sq_pa[%pK] cqp[%p] polarity[x%04x]\n",
		  cqp->sq_size, cqp->hw_sq_size, cqp->sq_base,
		  (u64 *)(uintptr_t)cqp->sq_pa, cqp, cqp->polarity);
	return 0;
}

/**
 * nser_sc_cqp_create - create cqp during bringup
 * @cqp: struct for cqp hw
 * @maj_err: If error, major err number
 * @min_err: If error, minor err number
 */
int nser_sc_cqp_create(struct nser_sc_cqp *cqp, u16 *maj_err, u16 *min_err)
{
	u64 temp;
	u32 cnt = 0, p1, p2, val = 0, err_code;
	int ret_code;

	cqp->sdbuf.size = ALIGN(NSER_UPDATE_SD_BUFF_SIZE * cqp->sq_size,
				NSER_SD_BUF_ALIGNMENT);
	cqp->sdbuf.va = dma_alloc_coherent(cqp->dev->hw->device,
					   cqp->sdbuf.size, &cqp->sdbuf.pa,
					   GFP_KERNEL);
	if (!cqp->sdbuf.va)
		return -ENOMEM;

	spin_lock_init(&cqp->dev->cqp_lock);

	temp = FIELD_PREP(NSER_CQPHC_SQSIZE, cqp->hw_sq_size) |
	       FIELD_PREP(NSER_CQPHC_SVER, cqp->struct_ver) |
	       FIELD_PREP(NSER_CQPHC_DISABLE_PFPDUS, cqp->disable_packed) |
	       FIELD_PREP(NSER_CQPHC_CEQPERVF, cqp->ceqs_per_vf);

	temp |= FIELD_PREP(NSER_CQPHC_ROCEV2_RTO_POLICY,
				 cqp->rocev2_rto_policy);

	set_64bit_val(cqp->host_ctx, 0, temp);

	temp = cqp->sq_pa;
	temp |= FIELD_PREP(NSER_CQPHC_HMC_ON_CHIP, cqp->hmc_on_chip) |
		FIELD_PREP(NSER_CQPHC_MIRROR_ENA, cqp->mirror_ena);

	set_64bit_val(cqp->host_ctx, 8, temp);

	temp = FIELD_PREP(NSER_CQPHC_ENABLED_VFS, cqp->ena_vf_count) |
	       FIELD_PREP(NSER_CQPHC_HMC_PROFILE, cqp->hmc_profile);
	if (cqp->dcqcn_ena)
		temp |= FIELD_PREP(NSER_CQPHC_CC_TYPE, 0x1);
	else if (cqp->timely_ena)
		temp |= FIELD_PREP(NSER_CQPHC_CC_TYPE, 0x2);
	set_64bit_val(cqp->host_ctx, 16, temp);
	set_64bit_val(cqp->host_ctx, 24, (uintptr_t)cqp);
	temp = FIELD_PREP(NSER_CQPHC_HW_MAJVER, cqp->hw_maj_ver) |
	       FIELD_PREP(NSER_CQPHC_HW_MINVER, cqp->hw_min_ver);

	if (cqp->timely_ena || cqp->dcqcn_ena)
		temp |= FIELD_PREP(NSER_CQPHC_CC_F, cqp->cc_params.cc_f) |
			FIELD_PREP(NSER_CQPHC_CC_MIN_DEC, cqp->cc_params.cc_min_dec);
	set_64bit_val(cqp->host_ctx, 32, temp);

	temp = 0;
	if (cqp->timely_ena || cqp->dcqcn_ena)
		temp |= FIELD_PREP(NSER_CQPHC_CC_MAX_DEC, cqp->cc_params.cc_max_dec);
	if (cqp->dcqcn_ena)
		temp |= FIELD_PREP(NSER_CQPHC_DCQCN_ALPHA_MIN,
				cqp->cc_params.dcqcn_params.dcqcn_alpha_min) |
				FIELD_PREP(NSER_CQPHC_DCQCN_ALPHA_INIT_VALUE,
				cqp->cc_params.dcqcn_params.dcqcn_alpha_init_value);
	if (cqp->timely_ena)
		temp |= FIELD_PREP(NSER_CQPHC_TIMELY_ALPHA,
				cqp->cc_params.timely_params.timely_alpha) |
				FIELD_PREP(NSER_CQPHC_TIMELY_BETA,
				cqp->cc_params.timely_params.timely_beta);
	set_64bit_val(cqp->host_ctx, 40, temp);

	temp = 0;
	if (cqp->dcqcn_ena)
		temp |= FIELD_PREP(NSER_CQPHC_DCQCN_T, cqp->cc_params.dcqcn_params.dcqcn_t);
	if (cqp->timely_ena || cqp->dcqcn_ena)
		temp |= FIELD_PREP(NSER_CQPHC_RAI_FACTOR, cqp->cc_params.rai_factor) |
				FIELD_PREP(NSER_CQPHC_HAI_FACTOR, cqp->cc_params.hai_factor);
	set_64bit_val(cqp->host_ctx, 48, temp);

	temp = 0;
	if (cqp->dcqcn_ena)
		temp |= FIELD_PREP(NSER_CQPHC_DCQCN_B,
				cqp->cc_params.dcqcn_params.dcqcn_b) |
				FIELD_PREP(NSER_CQPHC_DCQCN_F,
				cqp->cc_params.dcqcn_params.dcqcn_f) |
				FIELD_PREP(NSER_CQPHC_CC_CFG_VALID,
				cqp->cc_params.dcqcn_params.cc_cfg_valid) |
				FIELD_PREP(NSER_CQPHC_RREDUCE_MPERIOD,
				cqp->cc_params.dcqcn_params.rreduce_mperiod);
	if (cqp->timely_ena)
		temp |= FIELD_PREP(NSER_CQPHC_CC_CFG_VALID,
				cqp->cc_params.timely_params.cc_cfg_valid);
	set_64bit_val(cqp->host_ctx, 56, temp);

	print_hex_dump_debug("WQE: CQP_HOST_CTX WQE", DUMP_PREFIX_OFFSET, 16,
			     8, cqp->host_ctx, NSER_CQP_CTX_SIZE * 8, false);
	p1 = RS_32_1(cqp->host_ctx_pa, 32);
	p2 = (u32)cqp->host_ctx_pa;

	writel(p1, cqp->dev->hw_regs[NSER_CCQPHIGH]);
	writel(p2, cqp->dev->hw_regs[NSER_CCQPLOW]);

	do {
		if (cnt++ > cqp->dev->hw_attrs.max_done_count) {
			ret_code = -ETIMEDOUT;
			goto err;
		}
		udelay(cqp->dev->hw_attrs.max_sleep_count);
		val = readl(cqp->dev->hw_regs[NSER_CCQPSTATUS]);
	} while (!val);

	if (FLD_RS_32(cqp->dev, val, NSER_CCQPSTATUS_CCQP_ERR)) {
		ret_code = -EOPNOTSUPP;
		goto err;
	}

	cqp->process_cqp_sds = nser_update_sds_noccq;
	return 0;

err:
	dma_free_coherent(cqp->dev->hw->device, cqp->sdbuf.size,
			  cqp->sdbuf.va, cqp->sdbuf.pa);
	cqp->sdbuf.va = NULL;
	err_code = readl(cqp->dev->hw_regs[NSER_CQPERRCODES]);
	*min_err = FIELD_GET(NSER_CQPERRCODES_CQP_MINOR_CODE, err_code);
	*maj_err = FIELD_GET(NSER_CQPERRCODES_CQP_MAJOR_CODE, err_code);
	return ret_code;
}

/**
 * nser_sc_cqp_post_sq - post of cqp's sq
 * @cqp: struct for cqp hw
 */
void nser_sc_cqp_post_sq(struct nser_sc_cqp *cqp)
{
	writel(NSER_RING_CURRENT_HEAD(cqp->sq_ring), cqp->dev->cqp_db);

	nser_dbg(cqp->dev, "WQE: CQP SQ head 0x%x tail 0x%x size 0x%x\n",
		 cqp->sq_ring.head, cqp->sq_ring.tail, cqp->sq_ring.size);
}

/**
 * nser_sc_cqp_get_next_send_wqe_idx - get next wqe on cqp sq
 * and pass back index
 * @cqp: CQP HW structure
 * @scratch: private data for CQP WQE
 * @wqe_idx: WQE index of CQP SQ
 */
__le64 *nser_sc_cqp_get_next_send_wqe_idx(struct nser_sc_cqp *cqp, u64 scratch,
					  u32 *wqe_idx)
{
	__le64 *wqe = NULL;
	int ret_code;

	if (NSER_RING_FULL_ERR(cqp->sq_ring)) {
		nser_dbg(cqp->dev,
			 "WQE: CQP SQ is full, head 0x%x tail 0x%x size 0x%x\n",
			  cqp->sq_ring.head, cqp->sq_ring.tail,
			  cqp->sq_ring.size);
		return NULL;
	}
	NSER_ATOMIC_RING_MOVE_HEAD(cqp->sq_ring, *wqe_idx, ret_code);
	if (ret_code)
		return NULL;

	cqp->dev->cqp_cmd_stats[NSER_OP_REQ_CMDS]++;
	if (!*wqe_idx)
		cqp->polarity = !cqp->polarity;
	wqe = cqp->sq_base[*wqe_idx].elem;
	cqp->scratch_array[*wqe_idx] = scratch;

	memset(&wqe[0], 0, 24);
	memset(&wqe[4], 0, 32);

	return wqe;
}

/**
 * nser_sc_cqp_destroy - destroy cqp during close
 * @cqp: struct for cqp hw
 * @free_hwcqp: true for regular cqp destroy; false for reset path
 */
int nser_sc_cqp_destroy(struct nser_sc_cqp *cqp, bool free_hwcqp)
{
	u32 cnt = 0, val;
	int ret_code = 0;

	if (free_hwcqp) {
		writel(0, cqp->dev->hw_regs[NSER_CCQPHIGH]);
		writel(0, cqp->dev->hw_regs[NSER_CCQPLOW]);
		do {
			if (cnt++ > cqp->dev->hw_attrs.max_done_count) {
				ret_code = -ETIMEDOUT;
				break;
			}
			udelay(cqp->dev->hw_attrs.max_sleep_count);
			val = readl(cqp->dev->hw_regs[NSER_CCQPSTATUS]);
		} while (FLD_RS_32(cqp->dev, val, NSER_CCQPSTATUS_CCQP_DONE));
	}
	dma_free_coherent(cqp->dev->hw->device, cqp->sdbuf.size,
			  cqp->sdbuf.va, cqp->sdbuf.pa);
	cqp->sdbuf.va = NULL;
	return ret_code;
}

/**
 * nser_sc_ccq_arm - enable intr for control cq
 * @ccq: ccq sc struct
 */
void nser_sc_ccq_arm(struct nser_sc_cq *ccq)
{
	writel(ccq->cq_uk.cq_id, ccq->dev->cq_arm_db);
}

/**
 * nser_sc_ccq_get_cqe_info - get ccq's cq entry
 * @ccq: ccq sc struct
 * @info: completion q entry to return
 */
int nser_sc_ccq_get_cqe_info(struct nser_sc_cq *ccq,
			     struct nser_ccq_cqe_info *info)
{
	u64 qp_ctx, temp, temp1;
	__le64 *cqe;
	struct nser_sc_cqp *cqp;
	u32 wqe_idx;
	u32 error;
	u8 polarity;
	int ret_code = 0;

	if (ccq->cq_uk.avoid_mem_cflct)
		cqe = NSER_GET_CURRENT_EXTENDED_CQ_ELEM(&ccq->cq_uk);
	else
		cqe = NSER_GET_CURRENT_CQ_ELEM(&ccq->cq_uk);

	get_64bit_val(cqe, 24, &temp);
	polarity = (u8)FIELD_GET(NSER_CQ_VALID, temp);
	if (polarity != ccq->cq_uk.polarity)
		return -ENOENT;

	get_64bit_val(cqe, 8, &qp_ctx);
	cqp = (struct nser_sc_cqp *)(unsigned long)qp_ctx;
	info->error = (bool)FIELD_GET(NSER_CQ_ERROR, temp);
	info->maj_err_code = NSER_CQPSQ_MAJ_NO_ERROR;
	info->min_err_code = (u16)FIELD_GET(NSER_CQ_MINERR, temp);
	if (info->error) {
		info->maj_err_code = (u16)FIELD_GET(NSER_CQ_MAJERR, temp);
		error = readl(cqp->dev->hw_regs[NSER_CQPERRCODES]);
		nser_dbg(cqp->dev, "CQP: CQPERRCODES error_code[x%08X]\n",
			 error);
	}

	wqe_idx = (u32)FIELD_GET(NSER_CQ_WQEIDX, temp);
	WARN(wqe_idx > 2047, "cqp wqe_idex:%d out of range [0,2047]\n", wqe_idx);
	info->scratch = cqp->scratch_array[wqe_idx];
	/*
	 * for we iterate through entire scratch_array in nser_free_pending_cqp_request,
	 * we should set the array item correspongding to the completed WQE to NULL,
	 * to prevent use dynamically allocated cqp_request space that has already been freed
	 */
	cqp->scratch_array[wqe_idx] = 0;

	get_64bit_val(cqe, 16, &temp1);
	info->op_ret_val = (u32)FIELD_GET(NSER_CCQ_OPRETVAL, temp1);
	get_64bit_val(cqp->sq_base[wqe_idx].elem, 24, &temp1);
	info->op_code = (u8)FIELD_GET(NSER_CQPSQ_OPCODE, temp1);
	info->cqp = cqp;

	/*  move the head for cq */
	NSER_RING_MOVE_HEAD(ccq->cq_uk.cq_ring, ret_code);
	if (!NSER_RING_CURRENT_HEAD(ccq->cq_uk.cq_ring))
		ccq->cq_uk.polarity ^= 1;

	/* update cq tail in cq shadow memory also */
	NSER_RING_MOVE_TAIL(ccq->cq_uk.cq_ring);
	set_64bit_val(ccq->cq_uk.shadow_area, 0,
		      NSER_RING_CURRENT_HEAD(ccq->cq_uk.cq_ring));

	dma_wmb(); /* make sure shadow area is updated before moving tail */
	NSER_RING_MOVE_TAIL(cqp->sq_ring);
	ccq->dev->cqp_cmd_stats[NSER_OP_CMPL_CMDS]++;
	nser_dbg(cqp->dev, "%s: complete wqe_idx(0x%x) op_code(0x%x) vsi_num(%d) scratch(0x%llx)\n",
			__func__, wqe_idx, info->op_code, ccq->vsi->vsi_idx, info->scratch);
	return ret_code;
}

/**
 * nser_sc_poll_for_cqp_op_done - Waits for last write to complete in CQP SQ
 * @cqp: struct for cqp hw
 * @op_code: cqp opcode for completion
 * @compl_info: completion q entry to return
 */
int nser_sc_poll_for_cqp_op_done(struct nser_sc_cqp *cqp, u8 op_code,
				 struct nser_ccq_cqe_info *compl_info)
{
	struct nser_ccq_cqe_info info = {};
	struct nser_sc_cq *ccq;
	int ret_code = 0;
	u32 cnt = 0;

	ccq = cqp->dev->ccq;
	while (1) {
		if (cnt++ > 100 * cqp->dev->hw_attrs.max_done_count)
			return -ETIMEDOUT;

		if (nser_sc_ccq_get_cqe_info(ccq, &info)) {
			udelay(cqp->dev->hw_attrs.max_sleep_count);
			continue;
		}
		if (info.error && info.op_code != NSER_CQP_OP_QUERY_STAG) {
			ret_code = -EIO;
			break;
		}
		/* make sure op code matches*/
		if (op_code == info.op_code)
			break;
		nser_dbg(cqp->dev,
			 "WQE: opcode mismatch for my op code 0x%x, returned opcode %x\n",
			  op_code, info.op_code);
	}

	if (compl_info)
		memcpy(compl_info, &info, sizeof(*compl_info));

	return ret_code;
}

/**
 * nser_sc_manage_hmc_pm_func_table - manage of function table
 * @cqp: struct for cqp hw
 * @scratch: u64 saved to be used during cqp completion
 * @info: info for the manage function table operation
 * @post_sq: flag for cqp db to ring
 */
static int nser_sc_manage_hmc_pm_func_table(struct nser_sc_cqp *cqp,
					    struct nser_hmc_fcn_info *info,
					     u64 scratch, bool post_sq)
{
	__le64 *wqe;
	u64 hdr;

	wqe = nser_sc_cqp_get_next_send_wqe(cqp, scratch);
	if (!wqe)
		return -ENOMEM;

	hdr = FIELD_PREP(NSER_CQPSQ_MHMC_VFIDX, info->vf_id) |
	      FIELD_PREP(NSER_CQPSQ_OPCODE,
			 NSER_CQP_OP_MANAGE_HMC_PM_FUNC_TABLE) |
	      FIELD_PREP(NSER_CQPSQ_MHMC_FREEPMFN, info->free_fcn) |
	      FIELD_PREP(NSER_CQPSQ_WQEVALID, cqp->polarity);
	dma_wmb(); /* make sure WQE is written before valid bit is set */

	set_64bit_val(wqe, 24, hdr);

	print_hex_dump_debug("WQE: MANAGE_HMC_PM_FUNC_TABLE WQE",
			     DUMP_PREFIX_OFFSET, 16, 8, wqe,
			     NSER_CQP_WQE_SIZE * 8, false);
	if (post_sq)
		nser_sc_cqp_post_sq(cqp);

	return 0;
}

/**
 * nser_sc_commit_fpm_val_done - wait for cqp eqe completion
 * for fpm commit
 * @cqp: struct for cqp hw
 */
static int nser_sc_commit_fpm_val_done(struct nser_sc_cqp *cqp)
{
	return nser_sc_poll_for_cqp_op_done(cqp, NSER_CQP_OP_COMMIT_FPM_VAL,
					     NULL);
}

/**
 * nser_sc_commit_fpm_val - cqp wqe for commit fpm values
 * @cqp: struct for cqp hw
 * @scratch: u64 saved to be used during cqp completion
 * @hmc_fn_id: hmc function id
 * @commit_fpm_mem: Memory for fpm values
 * @post_sq: flag for cqp db to ring
 * @wait_type: poll ccq or cqp registers for cqp completion
 */
static int nser_sc_commit_fpm_val(struct nser_sc_cqp *cqp, u64 scratch,
				  u8 hmc_fn_id,
				   struct nser_dma_mem *commit_fpm_mem,
				   bool post_sq, u8 wait_type)
{
	__le64 *wqe;
	u64 hdr;
	u32 tail, val, error;
	int ret_code = 0;

	wqe = nser_sc_cqp_get_next_send_wqe(cqp, scratch);
	if (!wqe)
		return -ENOMEM;

	set_64bit_val(wqe, 16, hmc_fn_id);
	set_64bit_val(wqe, 32, commit_fpm_mem->pa);

	hdr = FIELD_PREP(NSER_CQPSQ_BUFSIZE, NSER_COMMIT_FPM_BUF_SIZE) |
	      FIELD_PREP(NSER_CQPSQ_OPCODE, NSER_CQP_OP_COMMIT_FPM_VAL) |
	      FIELD_PREP(NSER_CQPSQ_WQEVALID, cqp->polarity);

	dma_wmb(); /* make sure WQE is written before valid bit is set */

	set_64bit_val(wqe, 24, hdr);

	print_hex_dump_debug("WQE: COMMIT_FPM_VAL WQE", DUMP_PREFIX_OFFSET,
			     16, 8, wqe, NSER_CQP_WQE_SIZE * 8, false);
	nser_get_cqp_reg_info(cqp, &val, &tail, &error);

	if (post_sq) {
		nser_sc_cqp_post_sq(cqp);
		if (wait_type == NSER_CQP_WAIT_POLL_REGS)
			ret_code = nser_cqp_poll_registers(cqp, tail,
							   cqp->dev->hw_attrs.max_done_count);
		else if (wait_type == NSER_CQP_WAIT_POLL_CQ)
			ret_code = nser_sc_commit_fpm_val_done(cqp);
	}

	return ret_code;
}

/**
 * nser_sc_query_fpm_val_done - poll for cqp wqe completion for
 * query fpm
 * @cqp: struct for cqp hw
 */
static int nser_sc_query_fpm_val_done(struct nser_sc_cqp *cqp)
{
	return nser_sc_poll_for_cqp_op_done(cqp, NSER_CQP_OP_QUERY_FPM_VAL,
					     NULL);
}

/**
 * nser_sc_query_fpm_val - cqp wqe query fpm values
 * @cqp: struct for cqp hw
 * @scratch: u64 saved to be used during cqp completion
 * @hmc_fn_id: hmc function id
 * @query_fpm_mem: memory for return fpm values
 * @post_sq: flag for cqp db to ring
 * @wait_type: poll ccq or cqp registers for cqp completion
 */
static int nser_sc_query_fpm_val(struct nser_sc_cqp *cqp, u64 scratch,
				 u8 hmc_fn_id,
				  struct nser_dma_mem *query_fpm_mem,
				  bool post_sq, u8 wait_type)
{
	__le64 *wqe;
	u64 hdr;
	u32 tail, val, error;
	int ret_code = 0;

	wqe = nser_sc_cqp_get_next_send_wqe(cqp, scratch);
	if (!wqe)
		return -ENOMEM;

	set_64bit_val(wqe, 16, hmc_fn_id);
	set_64bit_val(wqe, 32, query_fpm_mem->pa);

	hdr = FIELD_PREP(NSER_CQPSQ_OPCODE, NSER_CQP_OP_QUERY_FPM_VAL) |
	      FIELD_PREP(NSER_CQPSQ_WQEVALID, cqp->polarity);
	dma_wmb(); /* make sure WQE is written before valid bit is set */

	set_64bit_val(wqe, 24, hdr);

	print_hex_dump_debug("WQE: QUERY_FPM WQE", DUMP_PREFIX_OFFSET, 16, 8,
			     wqe, NSER_CQP_WQE_SIZE * 8, false);
	nser_get_cqp_reg_info(cqp, &val, &tail, &error);

	if (post_sq) {
		nser_sc_cqp_post_sq(cqp);
		if (wait_type == NSER_CQP_WAIT_POLL_REGS)
			ret_code = nser_cqp_poll_registers(cqp, tail,
							   cqp->dev->hw_attrs.max_done_count);
		else if (wait_type == NSER_CQP_WAIT_POLL_CQ)
			ret_code = nser_sc_query_fpm_val_done(cqp);
	}

	return ret_code;
}

/**
 * nser_sc_ceq_init - initialize ceq
 * @ceq: ceq sc structure
 * @info: ceq initialization info
 */
int nser_sc_ceq_init(struct nser_sc_ceq *ceq,
		     struct nser_ceq_init_info *info)
{
	u32 pble_obj_cnt;

	if (info->elem_cnt < info->dev->hw_attrs.min_hw_ceq_size ||
	    info->elem_cnt > info->dev->hw_attrs.max_hw_ceq_size)
		return -EINVAL;

	if (info->ceq_id > (info->dev->hmc_fpm_misc.max_ceqs - 1))
		return -EINVAL;
	pble_obj_cnt = info->dev->hmc_info->hmc_obj[NSER_HMC_IW_PBLE].cnt;

	if (info->virtual_map && info->first_pm_pbl_idx >= pble_obj_cnt)
		return -EINVAL;

	ceq->size = sizeof(*ceq);
	ceq->ceqe_base = (struct nser_ceqe *)info->ceqe_base;
	ceq->ceq_id = info->ceq_id;
	ceq->dev = info->dev;
	ceq->elem_cnt = info->elem_cnt;
	ceq->ceq_elem_pa = info->ceqe_pa;
	ceq->virtual_map = info->virtual_map;
	ceq->itr_no_expire = info->itr_no_expire;
	ceq->reg_cq = info->reg_cq;
	ceq->reg_cq_size = 0;
	spin_lock_init(&ceq->req_cq_lock);
	ceq->pbl_chunk_size = (ceq->virtual_map ? info->pbl_chunk_size : 0);
	ceq->first_pm_pbl_idx = (ceq->virtual_map ? info->first_pm_pbl_idx : 0);
	ceq->pbl_list = (ceq->virtual_map ? info->pbl_list : NULL);
	ceq->tph_en = info->tph_en;
	ceq->tph_val = info->tph_val;
	ceq->vsi = info->vsi;
	ceq->polarity = 1;
	NSER_RING_INIT(ceq->ceq_ring, ceq->elem_cnt);
	ceq->dev->ceq[info->ceq_id] = ceq;
	ceq->int_en = info->int_en;
	ceq->msix_idx = info->msix_idx;

	return 0;
}

/**
 * nser_sc_ceq_create - create ceq wqe
 * @ceq: ceq sc structure
 * @scratch: u64 saved to be used during cqp completion
 * @post_sq: flag for cqp db to ring
 */
static int nser_sc_ceq_create(struct nser_sc_ceq *ceq, u64 scratch,
			      bool post_sq)
{
	struct nser_sc_cqp *cqp;
	__le64 *wqe;
	u64 hdr;

	cqp = ceq->dev->cqp;
	wqe = nser_sc_cqp_get_next_send_wqe(cqp, scratch);
	if (!wqe)
		return -ENOMEM;
	set_64bit_val(wqe, 16, ceq->elem_cnt);
	set_64bit_val(wqe, 32,
		      (ceq->virtual_map ? 0 : ceq->ceq_elem_pa));
	set_64bit_val(wqe, 48,
		      (ceq->virtual_map ? ceq->first_pm_pbl_idx : 0));
	set_64bit_val(wqe, 56,
		      FIELD_PREP(NSER_CQPSQ_TPHVAL, ceq->tph_val) |
		      FIELD_PREP(NSER_CQPSQ_VSIIDX, ceq->vsi->vsi_idx));
	hdr = FIELD_PREP(NSER_CQPSQ_CEQ_CEQID, ceq->ceq_id) |
	      FIELD_PREP(NSER_CQPSQ_OPCODE, NSER_CQP_OP_CREATE_CEQ) |
	      FIELD_PREP(NSER_CQPSQ_CEQ_LPBLSIZE, ceq->pbl_chunk_size) |
	      FIELD_PREP(NSER_CQPSQ_CEQ_VMAP, ceq->virtual_map) |
	      FIELD_PREP(NSER_CQPSQ_CEQ_ITRNOEXPIRE, ceq->itr_no_expire) |
	      FIELD_PREP(NSER_CQPSQ_TPHEN, ceq->tph_en) |
	      FIELD_PREP(NSER_CQPSQ_WQEVALID, cqp->polarity) |
	      FIELD_PREP(NSER_CQPSQ_CEQ_INT, ceq->int_en) |
	      FIELD_PREP(NSER_CQPSQ_CEQ_MSIX_VEC, ceq->msix_idx);
	dma_wmb(); /* make sure WQE is written before valid bit is set */

	set_64bit_val(wqe, 24, hdr);

	print_hex_dump_debug("WQE: CEQ_CREATE WQE", DUMP_PREFIX_OFFSET, 16, 8,
			     wqe, NSER_CQP_WQE_SIZE * 8, false);
	if (post_sq)
		nser_sc_cqp_post_sq(cqp);

	return 0;
}

/**
 * nser_sc_cceq_create_done - poll for control ceq wqe to complete
 * @ceq: ceq sc structure
 */
static int nser_sc_cceq_create_done(struct nser_sc_ceq *ceq)
{
	struct nser_sc_cqp *cqp;

	cqp = ceq->dev->cqp;
	return nser_sc_poll_for_cqp_op_done(cqp, NSER_CQP_OP_CREATE_CEQ,
					     NULL);
}

/**
 * nser_sc_cceq_destroy_done - poll for destroy cceq to complete
 * @ceq: ceq sc structure
 */
int nser_sc_cceq_destroy_done(struct nser_sc_ceq *ceq)
{
	struct nser_sc_cqp *cqp;

	if (ceq->reg_cq)
		nser_sc_remove_cq_ctx(ceq, ceq->dev->ccq);

	cqp = ceq->dev->cqp;
	cqp->process_cqp_sds = nser_update_sds_noccq;

	return nser_sc_poll_for_cqp_op_done(cqp, NSER_CQP_OP_DESTROY_CEQ,
					     NULL);
}

/**
 * nser_sc_cceq_create - create cceq
 * @ceq: ceq sc structure
 */
int nser_sc_cceq_create(struct nser_sc_ceq *ceq)
{
	int ret_code;
	struct nser_sc_dev *dev = ceq->dev;

	dev->ccq->vsi = ceq->vsi;
	if (ceq->reg_cq) {
		ret_code = nser_sc_add_cq_ctx(ceq, ceq->dev->ccq);
		if (ret_code)
			return ret_code;
	}

	ret_code = nser_sc_ceq_create(ceq, 0, true);
	if (!ret_code)
		return nser_sc_cceq_create_done(ceq);

	return ret_code;
}

/**
 * nser_sc_ceq_destroy - destroy ceq
 * @ceq: ceq sc structure
 * @scratch: u64 saved to be used during cqp completion
 * @post_sq: flag for cqp db to ring
 */
int nser_sc_ceq_destroy(struct nser_sc_ceq *ceq, u64 scratch, bool post_sq)
{
	struct nser_sc_cqp *cqp;
	__le64 *wqe;
	u64 hdr;

	cqp = ceq->dev->cqp;
	wqe = nser_sc_cqp_get_next_send_wqe(cqp, scratch);
	if (!wqe)
		return -ENOMEM;

	set_64bit_val(wqe, 16, ceq->elem_cnt);
	set_64bit_val(wqe, 48, ceq->first_pm_pbl_idx);
	hdr = ceq->ceq_id |
	      FIELD_PREP(NSER_CQPSQ_OPCODE, NSER_CQP_OP_DESTROY_CEQ) |
	      FIELD_PREP(NSER_CQPSQ_CEQ_LPBLSIZE, ceq->pbl_chunk_size) |
	      FIELD_PREP(NSER_CQPSQ_CEQ_VMAP, ceq->virtual_map) |
	      FIELD_PREP(NSER_CQPSQ_TPHEN, ceq->tph_en) |
	      FIELD_PREP(NSER_CQPSQ_WQEVALID, cqp->polarity) |
	      FIELD_PREP(NSER_CQPSQ_CEQ_INT, 0);
	dma_wmb(); /* make sure WQE is written before valid bit is set */

	set_64bit_val(wqe, 24, hdr);

	print_hex_dump_debug("WQE: CEQ_DESTROY WQE", DUMP_PREFIX_OFFSET, 16,
			     8, wqe, NSER_CQP_WQE_SIZE * 8, false);
	if (post_sq)
		nser_sc_cqp_post_sq(cqp);

	return 0;
}

/**
 * nser_sc_process_ceq - process ceq
 * @dev: sc device struct
 * @ceq: ceq sc structure
 *
 * It is expected caller serializes this function with cleanup_ceqes()
 * because these functions manipulate the same ceq
 */
void *nser_sc_process_ceq(struct nser_sc_dev *dev, struct nser_sc_ceq *ceq)
{
	u64 temp;
	__le64 *ceqe;
	struct nser_sc_cq *cq = NULL;
	struct nser_sc_cq *temp_cq;
	u8 polarity;
	u32 cq_idx;
	unsigned long flags;

	do {
		cq_idx = 0;
		ceqe = NSER_GET_CURRENT_CEQ_ELEM(ceq);
		get_64bit_val(ceqe, 0, &temp);
		polarity = (u8)FIELD_GET(NSER_CEQE_VALID, temp);
		if (polarity != ceq->polarity)
			return NULL;

		temp_cq = (struct nser_sc_cq *)(unsigned long)LS_64_1(temp, 1);
		if (!temp_cq) {
			cq_idx = NSER_INVALID_CQ_IDX;
			NSER_RING_MOVE_TAIL(ceq->ceq_ring);

			if (!NSER_RING_CURRENT_TAIL(ceq->ceq_ring))
				ceq->polarity ^= 1;
			continue;
		}

		cq = temp_cq;
		if (ceq->reg_cq) {
			spin_lock_irqsave(&ceq->req_cq_lock, flags);
			cq_idx = nser_sc_find_reg_cq(ceq, cq);
			spin_unlock_irqrestore(&ceq->req_cq_lock, flags);
		}

		NSER_RING_MOVE_TAIL(ceq->ceq_ring);
		if (!NSER_RING_CURRENT_TAIL(ceq->ceq_ring))
			ceq->polarity ^= 1;
	} while (cq_idx == NSER_INVALID_CQ_IDX);

	if (cq) {
		cq->cq_uk.armed = false;
		nser_sc_cq_ack(cq);
	}
	return cq;
}

/**
 * nser_sc_cleanup_ceqes - clear the valid ceqes ctx matching the cq
 * @cq: cq for which the ceqes need to be cleaned up
 * @ceq: ceq ptr
 *
 * The function is called after the cq is destroyed to cleanup
 * its pending ceqe entries. It is expected caller serializes this
 * function with process_ceq() in interrupt context.
 */
void nser_sc_cleanup_ceqes(struct nser_sc_cq *cq, struct nser_sc_ceq *ceq)
{
	struct nser_sc_cq *next_cq;
	u8 ceq_polarity = ceq->polarity;
	__le64 *ceqe;
	u8 polarity;
	u64 temp;
	int next;
	u32 i;

	next = NSER_RING_GET_NEXT_TAIL(ceq->ceq_ring, 0);

	for (i = 1; i <= NSER_RING_SIZE(*ceq); i++) {
		ceqe = NSER_GET_CEQ_ELEM_AT_POS(ceq, next);

		get_64bit_val(ceqe, 0, &temp);
		polarity = (u8)FIELD_GET(NSER_CEQE_VALID, temp);
		if (polarity != ceq_polarity)
			return;

		next_cq = (struct nser_sc_cq *)(unsigned long)LS_64_1(temp, 1);
		if (cq == next_cq)
			set_64bit_val(ceqe, 0, temp & NSER_CEQE_VALID);

		next = NSER_RING_GET_NEXT_TAIL(ceq->ceq_ring, i);
		if (!next)
			ceq_polarity ^= 1;
	}
}

/**
 * nser_sc_aeq_init - initialize aeq
 * @aeq: aeq structure ptr
 * @info: aeq initialization info
 */
int nser_sc_aeq_init(struct nser_sc_aeq *aeq,
		     struct nser_aeq_init_info *info)
{
	u32 pble_obj_cnt;

	if (info->elem_cnt < info->dev->hw_attrs.min_hw_aeq_size ||
	    info->elem_cnt > info->dev->hw_attrs.max_hw_aeq_size)
		return -EINVAL;

	pble_obj_cnt = info->dev->hmc_info->hmc_obj[NSER_HMC_IW_PBLE].cnt;

	if (info->virtual_map && info->first_pm_pbl_idx >= pble_obj_cnt)
		return -EINVAL;

	aeq->polarity = 1;
	aeq->aeqe_base = (struct nser_sc_aeqe *)info->aeqe_base;
	aeq->dev = info->dev;
	aeq->elem_cnt = info->elem_cnt;
	aeq->aeq_elem_pa = info->aeq_elem_pa;
	NSER_RING_INIT(aeq->aeq_ring, aeq->elem_cnt);
	aeq->virtual_map = info->virtual_map;
	aeq->pbl_list = (aeq->virtual_map ? info->pbl_list : NULL);
	aeq->pbl_chunk_size = (aeq->virtual_map ? info->pbl_chunk_size : 0);
	aeq->first_pm_pbl_idx = (aeq->virtual_map ? info->first_pm_pbl_idx : 0);
	aeq->msix_idx = info->msix_idx;
	/* make sure aeqe_base setted before size */
	mb();
	aeq->size = sizeof(*aeq);
	info->dev->aeq = aeq;

	return 0;
}

/**
 * nser_sc_aeq_create - create aeq
 * @aeq: aeq structure ptr
 * @scratch: u64 saved to be used during cqp completion
 * @post_sq: flag for cqp db to ring
 */
static int nser_sc_aeq_create(struct nser_sc_aeq *aeq, u64 scratch,
			      bool post_sq)
{
	__le64 *wqe;
	struct nser_sc_cqp *cqp;
	u64 hdr;

	cqp = aeq->dev->cqp;
	wqe = nser_sc_cqp_get_next_send_wqe(cqp, scratch);
	if (!wqe)
		return -ENOMEM;
	set_64bit_val(wqe, 16, aeq->elem_cnt);
	set_64bit_val(wqe, 32,
		      (aeq->virtual_map ? 0 : aeq->aeq_elem_pa));
	set_64bit_val(wqe, 48,
		      (aeq->virtual_map ? aeq->first_pm_pbl_idx : 0));

	hdr = FIELD_PREP(NSER_CQPSQ_OPCODE, NSER_CQP_OP_CREATE_AEQ) |
	      FIELD_PREP(NSER_CQPSQ_AEQ_LPBLSIZE, aeq->pbl_chunk_size) |
	      FIELD_PREP(NSER_CQPSQ_AEQ_VMAP, aeq->virtual_map) |
	      FIELD_PREP(NSER_CQPSQ_WQEVALID, cqp->polarity) |
	      FIELD_PREP(NSER_CQPSQ_AEQ_INT, 1) |
	      FIELD_PREP(NSER_CQPSQ_AEQ_MSIX_VEC, aeq->msix_idx);
	dma_wmb(); /* make sure WQE is written before valid bit is set */

	set_64bit_val(wqe, 24, hdr);

	print_hex_dump_debug("WQE: AEQ_CREATE WQE", DUMP_PREFIX_OFFSET, 16, 8,
			     wqe, NSER_CQP_WQE_SIZE * 8, false);
	if (post_sq)
		nser_sc_cqp_post_sq(cqp);

	return 0;
}

/**
 * nser_sc_aeq_destroy - destroy aeq during close
 * @aeq: aeq structure ptr
 * @scratch: u64 saved to be used during cqp completion
 * @post_sq: flag for cqp db to ring
 */
int nser_sc_aeq_destroy(struct nser_sc_aeq *aeq, u64 scratch, bool post_sq)
{
	__le64 *wqe;
	struct nser_sc_cqp *cqp;
	struct nser_sc_dev *dev;
	u64 hdr;

	dev = aeq->dev;
	cqp = dev->cqp;
	wqe = nser_sc_cqp_get_next_send_wqe(cqp, scratch);
	if (!wqe)
		return -ENOMEM;
	set_64bit_val(wqe, 16, aeq->elem_cnt);
	set_64bit_val(wqe, 48, aeq->first_pm_pbl_idx);
	hdr = FIELD_PREP(NSER_CQPSQ_OPCODE, NSER_CQP_OP_DESTROY_AEQ) |
	      FIELD_PREP(NSER_CQPSQ_AEQ_LPBLSIZE, aeq->pbl_chunk_size) |
	      FIELD_PREP(NSER_CQPSQ_AEQ_VMAP, aeq->virtual_map) |
	      FIELD_PREP(NSER_CQPSQ_WQEVALID, cqp->polarity) |
	      FIELD_PREP(NSER_CQPSQ_AEQ_INT, 0) |
	      FIELD_PREP(NSER_CQPSQ_AEQ_MSIX_VEC, 0);
	dma_wmb(); /* make sure WQE is written before valid bit is set */

	set_64bit_val(wqe, 24, hdr);

	print_hex_dump_debug("WQE: AEQ_DESTROY WQE", DUMP_PREFIX_OFFSET, 16,
			     8, wqe, NSER_CQP_WQE_SIZE * 8, false);
	if (post_sq)
		nser_sc_cqp_post_sq(cqp);
	return 0;
}

/**
 * nser_sc_get_next_aeqe - get next aeq entry
 * @aeq: aeq structure ptr
 * @info: aeqe info to be returned
 */
int nser_sc_get_next_aeqe(struct nser_sc_aeq *aeq,
			  struct nser_aeqe_info *info)
{
	u64 temp, compl_ctx;
	__le64 *aeqe;
	u8 ae_src;
	u8 polarity;

	aeqe = NSER_GET_CURRENT_AEQ_ELEM(aeq);
	get_64bit_val(aeqe, 0, &compl_ctx);
	get_64bit_val(aeqe, 8, &temp);
	polarity = (u8)FIELD_GET(NSER_AEQE_VALID, temp);

	if (aeq->polarity != polarity)
		return -ENOENT;

	print_hex_dump_debug("WQE: AEQ_ENTRY WQE", DUMP_PREFIX_OFFSET, 16, 8,
			     aeqe, 16, false);

	ae_src = (u8)FIELD_GET(NSER_AEQE_AESRC, temp);
	info->wqe_idx = (u16)FIELD_GET(NSER_AEQE_WQDESCIDX, temp);
	info->qp_cq_id = (u32)FIELD_GET(NSER_AEQE_QPCQID_LOW, temp) |
			 ((u32)FIELD_GET(NSER_AEQE_QPCQID_HI, temp) << 18);
	info->ae_id = (u16)FIELD_GET(NSER_AEQE_AECODE, temp);
	info->rdma_state = (u8)FIELD_GET(NSER_AEQE_RDMASTATE, temp);
	info->aeqe_overflow = (bool)FIELD_GET(NSER_AEQE_OVERFLOW, temp);

	info->ae_src = ae_src;
	switch (info->ae_id) {
	case NSER_AE_PRIV_OPERATION_DENIED:
	case NSER_AE_AMP_INVALIDATE_TYPE1_MW:
	case NSER_AE_AMP_MWBIND_ZERO_BASED_TYPE1_MW:
	case NSER_AE_AMP_FASTREG_INVALID_PBL_HPS_CFG:
	case NSER_AE_AMP_FASTREG_PBLE_MISMATCH:
	case NSER_AE_UDA_XMIT_DGRAM_TOO_LONG:
	case NSER_AE_UDA_XMIT_BAD_PD:
	case NSER_AE_UDA_XMIT_DGRAM_TOO_SHORT:
	case NSER_AE_RDMA_READ_WHILE_ORD_ZERO:
	case NSER_AE_STAG_ZERO_INVALID:
	case NSER_AE_IB_RREQ_AND_Q1_FULL:
	case NSER_AE_IB_INVALID_REQUEST:
	case NSER_AE_WQE_UNEXPECTED_OPCODE:
	case NSER_AE_IB_REMOTE_ACCESS_ERROR:
	case NSER_AE_IB_REMOTE_OP_ERROR:
	case NSER_AE_RDMAP_ROE_UNEXPECTED_OPCODE:
	case NSER_AE_ROE_INVALID_RDMA_READ_REQUEST:
	case NSER_AE_ROE_INVALID_RDMA_WRITE_OR_READ_RESP:
	case NSER_AE_ROCE_RSP_LENGTH_ERROR:
	case NSER_AE_INVALID_ARP_ENTRY:
	case NSER_AE_STALE_ARP_ENTRY:
	case NSER_AE_INVALID_AH_ENTRY:
	case NSER_AE_LLP_RECEIVED_MPA_CRC_ERROR:
	case NSER_AE_LLP_TOO_MANY_RETRIES:
	case NSER_AE_LLP_DOUBT_REACHABILITY:
	case NSER_AE_LCE_QP_CATASTROPHIC:
	case NSER_AE_QP_SUSPEND_COMPLETE:
	case NSER_AE_UDA_L4LEN_INVALID:
		info->qp = true;
		info->compl_ctx = compl_ctx;
		break;
	case NSER_AE_LCE_CQ_CATASTROPHIC:
		info->cq = true;
		info->compl_ctx = LS_64_1(compl_ctx, 1);
		ae_src = NSER_AE_SOURCE_RSVD;
		break;
	case NSER_AE_ROCE_EMPTY_MCG:
	case NSER_AE_ROCE_BAD_MC_IP_ADDR:
	case NSER_AE_ROCE_BAD_MC_QPID:
	case NSER_AE_MCG_QP_PROTOCOL_MISMATCH:
		ae_src = NSER_AE_SOURCE_RSVD;
		info->qp = true;
		info->compl_ctx = compl_ctx;
		break;
	default:
		break;
	}

	switch (ae_src) {
	case NSER_AE_SOURCE_RQ:
	case NSER_AE_SOURCE_RQ_0011:
		info->qp = true;
		info->rq = true;
		info->compl_ctx = compl_ctx;
		break;
	case NSER_AE_SOURCE_CQ:
	case NSER_AE_SOURCE_CQ_0110:
	case NSER_AE_SOURCE_CQ_1010:
	case NSER_AE_SOURCE_CQ_1110:
		info->cq = true;
		info->compl_ctx = LS_64_1(compl_ctx, 1);
		break;
	case NSER_AE_SOURCE_SQ:
	case NSER_AE_SOURCE_SQ_0111:
		info->qp = true;
		info->sq = true;
		info->compl_ctx = compl_ctx;
		break;
	case NSER_AE_SOURCE_IN_WR:
	case NSER_AE_SOURCE_IN_RR:
		info->qp = true;
		info->compl_ctx = compl_ctx;
		info->in_rdrsp_wr = true;
		break;
	case NSER_AE_SOURCE_OUT_RR:
	case NSER_AE_SOURCE_OUT_RR_1111:
		info->qp = true;
		info->compl_ctx = compl_ctx;
		info->out_rdrsp = true;
		break;
	case NSER_AE_SOURCE_RSVD:
	default:
		break;
	}

	NSER_RING_MOVE_TAIL(aeq->aeq_ring);
	if (!NSER_RING_CURRENT_TAIL(aeq->aeq_ring))
		aeq->polarity ^= 1;

	return 0;
}

/**
 * nser_sc_repost_aeq_entries - repost completed aeq entries
 * @dev: sc device struct
 * @count: allocate count
 */
int nser_sc_repost_aeq_entries(struct nser_sc_dev *dev, u32 count)
{
	writel(count, dev->hw_regs[NSER_AEQALLOC]);

	return 0;
}

/**
 * nser_sc_ccq_init - initialize control cq
 * @cq: sc's cq ctruct
 * @info: info for control cq initialization
 */
int nser_sc_ccq_init(struct nser_sc_cq *cq, struct nser_ccq_init_info *info)
{
	u32 pble_obj_cnt;

	if (info->num_elem < info->dev->hw_attrs.uk_attrs.min_hw_cq_size ||
	    info->num_elem > info->dev->hw_attrs.uk_attrs.max_hw_cq_size)
		return -EINVAL;

	if (info->ceq_id > (info->dev->hmc_fpm_misc.max_ceqs - 1))
		return -EINVAL;

	pble_obj_cnt = info->dev->hmc_info->hmc_obj[NSER_HMC_IW_PBLE].cnt;

	if (info->virtual_map && info->first_pm_pbl_idx >= pble_obj_cnt)
		return -EINVAL;

	cq->cq_pa = info->cq_pa;
	cq->cq_uk.cq_base = info->cq_base;
	cq->shadow_area_pa = info->shadow_area_pa;
	cq->cq_uk.shadow_area = info->shadow_area;
	cq->shadow_read_threshold = info->shadow_read_threshold;
	cq->dev = info->dev;
	cq->ceq_id = info->ceq_id;
	cq->cq_uk.cq_size = info->num_elem;
	cq->cq_type = NSER_CQ_TYPE_CQP;
	cq->ceqe_mask = info->ceqe_mask;
	NSER_RING_INIT(cq->cq_uk.cq_ring, info->num_elem);
	cq->cq_uk.cq_id = 0; /* control cq is id 0 always */
	cq->ceq_id_valid = info->ceq_id_valid;
	cq->tph_en = info->tph_en;
	cq->tph_val = info->tph_val;
	cq->cq_uk.avoid_mem_cflct = info->avoid_mem_cflct;
	cq->pbl_list = info->pbl_list;
	cq->virtual_map = info->virtual_map;
	cq->pbl_chunk_size = info->pbl_chunk_size;
	cq->first_pm_pbl_idx = info->first_pm_pbl_idx;
	cq->cq_uk.polarity = true;
	cq->vsi = info->vsi;
	cq->cq_uk.cq_ack_db = cq->dev->cq_ack_db;

	/* Only applicable to CQs other than CCQ so initialize to zero */
	cq->cq_uk.cqe_alloc_db = NULL;

	info->dev->ccq = cq;
	return 0;
}

/**
 * nser_sc_ccq_create_done - poll cqp for ccq create
 * @ccq: ccq sc struct
 */
static inline int nser_sc_ccq_create_done(struct nser_sc_cq *ccq)
{
	struct nser_sc_cqp *cqp;

	cqp = ccq->dev->cqp;

	return nser_sc_poll_for_cqp_op_done(cqp, NSER_CQP_OP_CREATE_CQ, NULL);
}

/**
 * nser_sc_ccq_create - create control cq
 * @ccq: ccq sc struct
 * @scratch: u64 saved to be used during cqp completion
 * @check_overflow: overlow flag for ccq
 * @post_sq: flag for cqp db to ring
 */
int nser_sc_ccq_create(struct nser_sc_cq *ccq, u64 scratch,
		       bool check_overflow, bool post_sq)
{
	int ret_code;

	ret_code = nser_sc_cq_create(ccq, scratch, check_overflow, post_sq);
	if (ret_code)
		return ret_code;

	if (post_sq) {
		ret_code = nser_sc_ccq_create_done(ccq);
		if (ret_code)
			return ret_code;
	}
	ccq->dev->cqp->process_cqp_sds = nser_cqp_sds_cmd;

	return 0;
}

/**
 * nser_sc_ccq_destroy - destroy ccq during close
 * @ccq: ccq sc struct
 * @scratch: u64 saved to be used during cqp completion
 * @post_sq: flag for cqp db to ring
 */
int nser_sc_ccq_destroy(struct nser_sc_cq *ccq, u64 scratch, bool post_sq)
{
	struct nser_sc_cqp *cqp;
	__le64 *wqe;
	u64 hdr;
	int ret_code = 0;
	u32 tail, val, error;

	cqp = ccq->dev->cqp;
	wqe = nser_sc_cqp_get_next_send_wqe(cqp, scratch);
	if (!wqe)
		return -ENOMEM;

	set_64bit_val(wqe, 0, ccq->cq_uk.cq_size);
	set_64bit_val(wqe, 8, RS_64_1(ccq, 1));
	set_64bit_val(wqe, 40, ccq->shadow_area_pa);

	hdr = ccq->cq_uk.cq_id |
	      FLD_LS_64(ccq->dev, (ccq->ceq_id_valid ? ccq->ceq_id : 0),
			NSER_CQPSQ_CQ_CEQID) |
	      FIELD_PREP(NSER_CQPSQ_OPCODE, NSER_CQP_OP_DESTROY_CQ) |
	      FIELD_PREP(NSER_CQPSQ_CQ_ENCEQEMASK, ccq->ceqe_mask) |
	      FIELD_PREP(NSER_CQPSQ_CQ_CEQIDVALID, ccq->ceq_id_valid) |
	      FIELD_PREP(NSER_CQPSQ_TPHEN, ccq->tph_en) |
	      FIELD_PREP(NSER_CQPSQ_CQ_AVOIDMEMCNFLCT, ccq->cq_uk.avoid_mem_cflct) |
	      FIELD_PREP(NSER_CQPSQ_WQEVALID, cqp->polarity);
	dma_wmb(); /* make sure WQE is written before valid bit is set */

	set_64bit_val(wqe, 24, hdr);

	print_hex_dump_debug("WQE: CCQ_DESTROY WQE", DUMP_PREFIX_OFFSET, 16,
			     8, wqe, NSER_CQP_WQE_SIZE * 8, false);
	nser_get_cqp_reg_info(cqp, &val, &tail, &error);

	if (post_sq) {
		nser_sc_cqp_post_sq(cqp);
		ret_code = nser_cqp_poll_registers(cqp, tail,
						   cqp->dev->hw_attrs.max_done_count);
	}

	cqp->process_cqp_sds = nser_update_sds_noccq;

	return ret_code;
}

int nser_sc_vsi_reset(struct nser_sc_dev *dev, u64 scratch, bool post_sq)
{
	struct nser_sc_cqp *cqp;
	__le64 *wqe;
	u64 hdr;
	int ret_code = 0;
	u32 tail, val, error;

	cqp = dev->cqp;
	wqe = nser_sc_cqp_get_next_send_wqe(cqp, scratch);
	if (!wqe)
		return -ENOMEM;

	hdr = FIELD_PREP(NSER_CQPSQ_OPCODE, NSER_CQP_OP_VSI_RESET) |
	      FIELD_PREP(NSER_CQPSQ_WQEVALID, cqp->polarity);

	dma_wmb(); /* make sure WQE is written before valid bit is set */

	set_64bit_val(wqe, 24, hdr);

	print_hex_dump_debug("WQE: VSI_RESET WQE", DUMP_PREFIX_OFFSET, 16,
			     8, wqe, NSER_CQP_WQE_SIZE * 8, false);
	nser_get_cqp_reg_info(cqp, &val, &tail, &error);

	if (post_sq) {
		nser_sc_cqp_post_sq(cqp);
		ret_code = nser_cqp_poll_registers(cqp, tail,
						   cqp->dev->hw_attrs.max_done_count);
	}

	cqp->process_cqp_sds = nser_update_sds_noccq;

	return ret_code;
}

/**
 * nser_sc_init_iw_hmc() - queries fpm values using cqp and populates hmc_info
 * @dev : ptr to nser_dev struct
 * @hmc_fn_id: hmc function id
 */
int nser_sc_init_iw_hmc(struct nser_sc_dev *dev, u8 hmc_fn_id)
{
	struct nser_hmc_info *hmc_info;
	struct nser_hmc_fpm_misc *hmc_fpm_misc;
	struct nser_dma_mem query_fpm_mem;
	struct nser_virt_mem virt_mem;
	struct nser_vfdev *vf_dev = NULL;
	u32 mem_size;
	bool poll_registers = true;
	int ret_code = 0;
	u16 iw_vf_idx;
	u8 wait_type, i;

	nser_dbg(dev, "HMC: hmc_fn_id %u, dev->hmc_fn_id %u\n", hmc_fn_id,
		 dev->hmc_fn_id);
	if (hmc_fn_id == dev->hmc_fn_id) {
		hmc_info = dev->hmc_info;
		hmc_fpm_misc = &dev->hmc_fpm_misc;
		query_fpm_mem.pa = dev->fpm_query_buf_pa;
		query_fpm_mem.va = dev->fpm_query_buf;
	} else {
		vf_dev = nser_vfdev_from_fpm(dev, hmc_fn_id);
		if (!vf_dev)
			return -EINVAL;

		hmc_info = &vf_dev->hmc_info;
		hmc_fpm_misc = &vf_dev->hmc_fpm_misc;
		iw_vf_idx = vf_dev->iw_vf_idx;
		nser_dbg(dev, "HMC: vf_dev %p, hmc_info %p, hmc_obj %p\n",
			 vf_dev, hmc_info, hmc_info->hmc_obj);
		if (!vf_dev->fpm_query_buf) {
			if (!dev->vf_fpm_query_buf[iw_vf_idx].va) {
				ret_code = nser_alloc_query_fpm_buf(dev,
							&dev->vf_fpm_query_buf[iw_vf_idx]);
				if (ret_code)
					return ret_code;
			}
			vf_dev->fpm_query_buf = dev->vf_fpm_query_buf[iw_vf_idx].va;
			vf_dev->fpm_query_buf_pa = dev->vf_fpm_query_buf[iw_vf_idx].pa;
		}
		query_fpm_mem.pa = vf_dev->fpm_query_buf_pa;
		query_fpm_mem.va = vf_dev->fpm_query_buf;
		poll_registers = false;
	}
	hmc_info->hmc_fn_id = hmc_fn_id;

	hmc_info->hmc_va = dev->hmc_va;
	hmc_info->mem_type = NSER_HOST_MEM;
	if (dev->hw_attrs.uk_attrs.hw_rev == IIDC_RDMA_GEN_MOONSTONE) {
		if (hmc_info->hmc_va && dev->privileged &&
			hmc_fn_id == dev->hmc_fn_id && nser_hmc_on_chip)
			hmc_info->mem_type = NSER_CHIP_MEM;
	}

	if (hmc_fn_id != dev->hmc_fn_id) {
		ret_code = nser_cqp_query_fpm_val_cmd(dev, &query_fpm_mem,
						      hmc_fn_id);
	} else {
		wait_type = poll_registers ? (u8)NSER_CQP_WAIT_POLL_REGS :
					     (u8)NSER_CQP_WAIT_POLL_CQ;

		ret_code = nser_sc_query_fpm_val(dev->cqp, 0,
						 hmc_info->hmc_fn_id,
						  &query_fpm_mem, true,
						  wait_type);
	}
	if (ret_code)
		return ret_code;

	/* parse the fpm_query_buf and fill hmc obj info */
	ret_code = nser_sc_parse_fpm_query_buf(dev, query_fpm_mem.va, hmc_info,
					       hmc_fpm_misc);

	print_hex_dump_debug("HMC: QUERY FPM BUFFER", DUMP_PREFIX_OFFSET, 16,
			     8, query_fpm_mem.va, NSER_QUERY_FPM_BUF_SIZE,
			     false);

	if (ret_code)
		return ret_code;

	if (hmc_fn_id != dev->hmc_fn_id) {
		struct nser_hmc_obj_info *obj_info;
		__le64 *buf;

		obj_info = hmc_info->hmc_obj;
		buf = query_fpm_mem.va;
		for (i = NSER_HMC_IW_IRRQ_LITE; i < NSER_HMC_IW_MAX; i++)
			hmc_info->hmc_obj[i].cnt = hmc_info->hmc_obj[i].max_cnt;
		set_64bit_val(buf, 0, (u64)obj_info[NSER_HMC_IW_IRRQ_LITE].cnt);
		set_64bit_val(buf, 8, (u64)obj_info[NSER_HMC_IW_IRRQ].cnt);
		set_64bit_val(buf, 16, (u64)obj_info[NSER_HMC_IW_ORRQ].cnt);
		set_64bit_val(buf, 24, (u64)obj_info[NSER_HMC_IW_XF].cnt);
		set_64bit_val(buf, 32, (u64)obj_info[NSER_HMC_IW_SQCQE].cnt);
		set_64bit_val(buf, 40, (u64)obj_info[NSER_HMC_IW_RQCQE].cnt);
		set_64bit_val(buf, 48, (u64)obj_info[NSER_HMC_IW_CQP].cnt);
		set_64bit_val(buf, 56, (u64)obj_info[NSER_HMC_IW_AEQ].cnt);
		set_64bit_val(buf, 64, (u64)obj_info[NSER_HMC_IW_QP].cnt);
		set_64bit_val(buf, 72, (u64)obj_info[NSER_HMC_IW_CQ].cnt);
		set_64bit_val(buf, 80, (u64)obj_info[NSER_HMC_IW_CEQ].cnt);
		set_64bit_val(buf, 88, (u64)obj_info[NSER_HMC_IW_MR].cnt);
		set_64bit_val(buf, 96, (u64)obj_info[NSER_HMC_IW_MG].cnt);
		set_64bit_val(buf, 104, (u64)obj_info[NSER_HMC_IW_MG_ID].cnt);
		set_64bit_val(buf, 112, (u64)obj_info[NSER_HMC_IW_AH].cnt);
		set_64bit_val(buf, 120, (u64)obj_info[NSER_HMC_IW_ARP].cnt);
		set_64bit_val(buf, 128, (u64)obj_info[NSER_HMC_IW_DUP_IRRQ].cnt);
		set_64bit_val(buf, 136, (u64)obj_info[NSER_HMC_IW_PBLE].cnt);
		set_64bit_val(buf, 144, (u64)obj_info[NSER_HMC_IW_FW].cnt);
		set_64bit_val(buf, 152, (u64)obj_info[NSER_HMC_IW_SQCQEFL].cnt);
		set_64bit_val(buf, 160, (u64)obj_info[NSER_HMC_IW_RQCQEFL].cnt);
		set_64bit_val(buf, 168, (u64)obj_info[NSER_HMC_IW_XFFL].cnt);
		set_64bit_val(buf, 176, (u64)obj_info[NSER_HMC_IW_IRRQ_LITE_FL].cnt);
		set_64bit_val(buf, 184, (u64)obj_info[NSER_HMC_IW_ORRQFL].cnt);

		nser_cqp_commit_fpm_val_cmd(dev, &query_fpm_mem, hmc_fn_id);
		/* parse the fpm_commit_buf and fill hmc obj info */
		nser_sc_parse_fpm_commit_buf(dev, query_fpm_mem.va,
					     hmc_info->hmc_obj,
					      &hmc_info->sd_table.sd_cnt);

		print_hex_dump_debug("HMC: COMMIT FPM BUFFER",
				     DUMP_PREFIX_OFFSET, 16, 8,
				     query_fpm_mem.va,
				     NSER_COMMIT_FPM_BUF_SIZE, false);
		mem_size =
			sizeof(struct nser_hmc_sd_entry) *
			(hmc_info->sd_table.sd_cnt + hmc_info->first_sd_index);
		virt_mem.size = mem_size;
		virt_mem.va = kzalloc(virt_mem.size, GFP_KERNEL);
		if (!virt_mem.va)
			return -ENOMEM;

		hmc_info->sd_table.sd_entry = virt_mem.va;
	}
	return ret_code;
}

/**
 * nser_sc_cfg_iw_fpm() - commits hmc obj cnt values using cqp
 * command and populates fpm base address in hmc_info
 * @dev : ptr to nser_dev struct
 * @hmc_fn_id: hmc function id
 */
static int nser_sc_cfg_iw_fpm(struct nser_sc_dev *dev, u8 hmc_fn_id)
{
	struct nser_hmc_obj_info *obj_info;
	__le64 *buf;
	struct nser_hmc_info *hmc_info;
	struct nser_dma_mem commit_fpm_mem;
	int ret_code = 0;
	bool poll_registers = true;
	u8 wait_type;

	if (hmc_fn_id == dev->hmc_fn_id) {
		hmc_info = dev->hmc_info;
	} else {
		hmc_info = nser_vf_hmcinfo_from_fpm(dev, hmc_fn_id);
		poll_registers = false;
	}
	if (!hmc_info)
		return -EFAULT;
	obj_info = hmc_info->hmc_obj;
	buf = dev->fpm_commit_buf;

	set_64bit_val(buf, 0, (u64)obj_info[NSER_HMC_IW_IRRQ_LITE].cnt);
	set_64bit_val(buf, 8, (u64)obj_info[NSER_HMC_IW_IRRQ].cnt);
	set_64bit_val(buf, 16, (u64)obj_info[NSER_HMC_IW_ORRQ].cnt);
	set_64bit_val(buf, 24, (u64)obj_info[NSER_HMC_IW_XF].cnt);
	set_64bit_val(buf, 32, (u64)obj_info[NSER_HMC_IW_SQCQE].cnt);
	set_64bit_val(buf, 40, (u64)obj_info[NSER_HMC_IW_RQCQE].cnt);
	set_64bit_val(buf, 48, (u64)obj_info[NSER_HMC_IW_CQP].cnt);
	set_64bit_val(buf, 56, (u64)obj_info[NSER_HMC_IW_AEQ].cnt);
	set_64bit_val(buf, 64, (u64)obj_info[NSER_HMC_IW_QP].cnt);
	set_64bit_val(buf, 72, (u64)obj_info[NSER_HMC_IW_CQ].cnt);
	set_64bit_val(buf, 80, (u64)obj_info[NSER_HMC_IW_CEQ].cnt);
	set_64bit_val(buf, 88, (u64)obj_info[NSER_HMC_IW_MR].cnt);
	set_64bit_val(buf, 96, (u64)obj_info[NSER_HMC_IW_MG].cnt);
	set_64bit_val(buf, 104, (u64)obj_info[NSER_HMC_IW_MG_ID].cnt);
	set_64bit_val(buf, 112, (u64)obj_info[NSER_HMC_IW_AH].cnt);
	set_64bit_val(buf, 120, (u64)obj_info[NSER_HMC_IW_ARP].cnt);
	set_64bit_val(buf, 128, (u64)obj_info[NSER_HMC_IW_DUP_IRRQ].cnt);
	set_64bit_val(buf, 136, (u64)obj_info[NSER_HMC_IW_PBLE].cnt);
	set_64bit_val(buf, 144, (u64)obj_info[NSER_HMC_IW_FW].cnt);
	set_64bit_val(buf, 152, (u64)obj_info[NSER_HMC_IW_SQCQEFL].cnt);
	set_64bit_val(buf, 160, (u64)obj_info[NSER_HMC_IW_RQCQEFL].cnt);
	set_64bit_val(buf, 168, (u64)obj_info[NSER_HMC_IW_XFFL].cnt);
	set_64bit_val(buf, 176, (u64)obj_info[NSER_HMC_IW_IRRQ_LITE_FL].cnt);
	set_64bit_val(buf, 184, (u64)obj_info[NSER_HMC_IW_ORRQFL].cnt);

	commit_fpm_mem.pa = dev->fpm_commit_buf_pa;
	commit_fpm_mem.va = dev->fpm_commit_buf;

	wait_type = poll_registers ? (u8)NSER_CQP_WAIT_POLL_REGS :
				     (u8)NSER_CQP_WAIT_POLL_CQ;
	print_hex_dump_debug("HMC: COMMIT FPM BUFFER", DUMP_PREFIX_OFFSET, 16,
			     8, commit_fpm_mem.va, NSER_COMMIT_FPM_BUF_SIZE,
			     false);
	ret_code = nser_sc_commit_fpm_val(dev->cqp, 0, hmc_info->hmc_fn_id,
					  &commit_fpm_mem, true, wait_type);
	if (!ret_code)
		ret_code = nser_sc_parse_fpm_commit_buf(dev, dev->fpm_commit_buf,
							hmc_info->hmc_obj,
							 &hmc_info->sd_table.sd_cnt);
	print_hex_dump_debug("HMC: COMMIT FPM BUFFER", DUMP_PREFIX_OFFSET, 16,
			     8, commit_fpm_mem.va, NSER_COMMIT_FPM_BUF_SIZE,
			     false);

	return ret_code;
}

/**
 * cqp_sds_wqe_fill - fill cqp wqe doe sd
 * @cqp: struct for cqp hw
 * @info: sd info for wqe
 * @scratch: u64 saved to be used during cqp completion
 */
static int cqp_sds_wqe_fill(struct nser_sc_cqp *cqp,
			    struct nser_update_sds_info *info, u64 scratch)
{
	u64 data;
	u64 hdr;
	__le64 *wqe;
	int mem_entries, wqe_entries;
	struct nser_dma_mem *sdbuf = &cqp->sdbuf;
	u64 offset = 0;
	u32 wqe_idx;

	wqe = nser_sc_cqp_get_next_send_wqe_idx(cqp, scratch, &wqe_idx);
	if (!wqe)
		return -ENOMEM;

	wqe_entries = (info->cnt > 3) ? 3 : info->cnt;
	mem_entries = info->cnt - wqe_entries;

	if (mem_entries) {
		offset = wqe_idx * NSER_UPDATE_SD_BUFF_SIZE;
		memcpy(((char *)sdbuf->va + offset), &info->entry[3], mem_entries << 4);

		data = (u64)sdbuf->pa + offset;
	} else {
		data = 0;
	}
	data |= FLD_LS_64(cqp->dev, info->hmc_fn_id, NSER_CQPSQ_UPESD_HMCFNID);
	set_64bit_val(wqe, 16, data);

	switch (wqe_entries) {
	case 3:
		set_64bit_val(wqe, 48,
			      (FIELD_PREP(NSER_CQPSQ_UPESD_SDCMD, info->entry[2].cmd) |
			       FIELD_PREP(NSER_CQPSQ_UPESD_ENTRY_VALID, 1)));

		set_64bit_val(wqe, 56, info->entry[2].data);
		fallthrough;
	case 2:
		set_64bit_val(wqe, 32,
			      (FIELD_PREP(NSER_CQPSQ_UPESD_SDCMD, info->entry[1].cmd) |
			       FIELD_PREP(NSER_CQPSQ_UPESD_ENTRY_VALID, 1)));

		set_64bit_val(wqe, 40, info->entry[1].data);
		fallthrough;
	case 1:
		set_64bit_val(wqe, 0,
			      FIELD_PREP(NSER_CQPSQ_UPESD_SDCMD, info->entry[0].cmd));

		set_64bit_val(wqe, 8, info->entry[0].data);
		break;
	default:
		break;
	}

	hdr = FIELD_PREP(NSER_CQPSQ_OPCODE, NSER_CQP_OP_UPDATE_PE_SDS) |
	      FIELD_PREP(NSER_CQPSQ_WQEVALID, cqp->polarity) |
	      FIELD_PREP(NSER_CQPSQ_UPESD_ENTRY_COUNT, mem_entries);
	dma_wmb(); /* make sure WQE is written before valid bit is set */

	set_64bit_val(wqe, 24, hdr);

	if (mem_entries)
		print_hex_dump_debug("WQE: UPDATE_PE_SDS WQE Buffer",
				     DUMP_PREFIX_OFFSET, 16, 8,
				     (char *)sdbuf->va + offset,
				     mem_entries << 4, false);

	print_hex_dump_debug("WQE: UPDATE_PE_SDS WQE", DUMP_PREFIX_OFFSET, 16,
			     8, wqe, NSER_CQP_WQE_SIZE * 8, false);

	return 0;
}

/**
 * nser_update_pe_sds - cqp wqe for sd
 * @dev: ptr to nser_dev struct
 * @info: sd info for sd's
 * @scratch: u64 saved to be used during cqp completion
 */
static int nser_update_pe_sds(struct nser_sc_dev *dev,
			      struct nser_update_sds_info *info, u64 scratch)
{
	struct nser_sc_cqp *cqp = dev->cqp;
	int ret_code;

	ret_code = cqp_sds_wqe_fill(cqp, info, scratch);
	if (!ret_code)
		nser_sc_cqp_post_sq(cqp);

	return ret_code;
}

/**
 * nser_update_sds_noccq - update sd before ccq created
 * @dev: sc device struct
 * @info: sd info for sd's
 */
int nser_update_sds_noccq(struct nser_sc_dev *dev,
			  struct nser_update_sds_info *info)
{
	u32 error, val, tail;
	struct nser_sc_cqp *cqp = dev->cqp;
	int ret_code;

	ret_code = cqp_sds_wqe_fill(cqp, info, 0);
	if (ret_code)
		return ret_code;

	nser_get_cqp_reg_info(cqp, &val, &tail, &error);

	nser_sc_cqp_post_sq(cqp);
	return nser_cqp_poll_registers(cqp, tail,
					cqp->dev->hw_attrs.max_done_count);
}

/**
 * nser_sc_static_hmc_pages_allocated - cqp wqe to allocate hmc pages
 * @cqp: struct for cqp hw
 * @scratch: u64 saved to be used during cqp completion
 * @hmc_fn_id: hmc function id
 * @post_sq: flag for cqp db to ring
 * @poll_registers: flag to poll register for cqp completion
 */
int nser_sc_static_hmc_pages_allocated(struct nser_sc_cqp *cqp, u64 scratch,
				       u8 hmc_fn_id, bool post_sq,
					bool poll_registers)
{
	u64 hdr;
	__le64 *wqe;
	u32 tail, val, error;

	wqe = nser_sc_cqp_get_next_send_wqe(cqp, scratch);
	if (!wqe)
		return -ENOMEM;

	set_64bit_val(wqe, 16,
		      FIELD_PREP(NSER_SHMC_PAGE_ALLOCATED_HMC_FN_ID, hmc_fn_id));

	hdr = FIELD_PREP(NSER_CQPSQ_OPCODE,
			 NSER_CQP_OP_SHMC_PAGES_ALLOCATED) |
	      FIELD_PREP(NSER_CQPSQ_WQEVALID, cqp->polarity);
	dma_wmb(); /* make sure WQE is written before valid bit is set */

	set_64bit_val(wqe, 24, hdr);

	print_hex_dump_debug("WQE: SHMC_PAGES_ALLOCATED WQE",
			     DUMP_PREFIX_OFFSET, 16, 8, wqe,
			     NSER_CQP_WQE_SIZE * 8, false);
	nser_get_cqp_reg_info(cqp, &val, &tail, &error);

	if (post_sq) {
		nser_sc_cqp_post_sq(cqp);
		if (poll_registers)
			/* check for cqp sq tail update */
			return nser_cqp_poll_registers(cqp, tail,
							cqp->dev->hw_attrs.max_done_count);
		else
			return nser_sc_poll_for_cqp_op_done(cqp,
							     NSER_CQP_OP_SHMC_PAGES_ALLOCATED,
							     NULL);
	}

	return 0;
}

/**
 * nser_cqp_ring_full - check if cqp ring is full
 * @cqp: struct for cqp hw
 */
static bool nser_cqp_ring_full(struct nser_sc_cqp *cqp)
{
	return NSER_RING_FULL_ERR(cqp->sq_ring);
}

/**
 * nser_est_sd - returns approximate number of SDs for HMC
 * @dev: sc device struct
 * @hmc_info: hmc structure, size and count for HMC objects
 */
static u32 nser_est_sd(struct nser_sc_dev *dev,
		       struct nser_hmc_info *hmc_info)
{
	struct nser_hmc_obj_info *pble_info;
	int i;
	u64 size = 0;
	u64 sd;

	for (i = NSER_HMC_IW_IRRQ_LITE; i < NSER_HMC_IW_MAX; i++)
		if (i != NSER_HMC_IW_PBLE)
			size += round_up(hmc_info->hmc_obj[i].cnt *
					 hmc_info->hmc_obj[i].size, 512);

	pble_info = &hmc_info->hmc_obj[NSER_HMC_IW_PBLE];
	if (dev->privileged)
		size += round_up(pble_info->cnt * pble_info->size, 512);
	if (size & 0x1FFFFF)
		sd = (size >> 21) + 1; /* add 1 for remainder */
	else
		sd = size >> 21;

	if (!dev->privileged) {
		/* 2MB alignment for VF PBLE HMC */
		size = pble_info->cnt * pble_info->size;
		if (size & 0x1FFFFF)
			sd += (size >> 21) + 1; /* add 1 for remainder */
		else
			sd += size >> 21;
	}

	if (sd > 0xFFFFFFFF) {
		nser_dbg(dev, "HMC: sd overflow[%lld]\n", sd);
		sd = 0xFFFFFFFF - 1;
	}

	return (u32)sd;
}

/**
 * nser_sc_query_rdma_features - query RDMA features and FW ver
 * @cqp: struct for cqp hw
 * @buf: buffer to hold query info
 * @scratch: u64 saved to be used during cqp completion
 */
static int nser_sc_query_rdma_features(struct nser_sc_cqp *cqp,
				       struct nser_dma_mem *buf, u64 scratch)
{
	__le64 *wqe;
	u64 temp;
	u32 tail, val, error;
	int status;

	wqe = nser_sc_cqp_get_next_send_wqe(cqp, scratch);
	if (!wqe)
		return -ENOMEM;

	temp = buf->pa;
	set_64bit_val(wqe, 32, temp);

	temp = FIELD_PREP(NSER_CQPSQ_QUERY_RDMA_FEATURES_WQEVALID,
			  cqp->polarity) |
	       FIELD_PREP(NSER_CQPSQ_QUERY_RDMA_FEATURES_BUF_LEN, buf->size) |
	       FIELD_PREP(NSER_CQPSQ_UP_OP, NSER_CQP_OP_QUERY_RDMA_FEATURES);
	dma_wmb(); /* make sure WQE is written before valid bit is set */

	set_64bit_val(wqe, 24, temp);

	print_hex_dump_debug("WQE: QUERY RDMA FEATURES", DUMP_PREFIX_OFFSET,
			     16, 8, wqe, NSER_CQP_WQE_SIZE * 8, false);
	nser_get_cqp_reg_info(cqp, &val, &tail, &error);

	nser_sc_cqp_post_sq(cqp);
	status = nser_cqp_poll_registers(cqp, tail,
					 cqp->dev->hw_attrs.max_done_count);
	if (error || status)
		status = -EIO;

	return status;
}

/**
 * nser_get_rdma_features - get RDMA features
 * @dev: sc device struct
 */
int nser_get_rdma_features(struct nser_sc_dev *dev)
{
	int ret_code;
	struct nser_dma_mem feat_buf;
	u64 temp;
	u16 byte_idx, feat_type, feat_cnt, feat_idx;

	feat_buf.size = ALIGN(NSER_FEATURE_BUF_SIZE,
			      NSER_FEATURE_BUF_ALIGNMENT);
	feat_buf.va = dma_alloc_coherent(dev->hw->device, feat_buf.size,
					 &feat_buf.pa, GFP_KERNEL);
	if (!feat_buf.va)
		return -ENOMEM;

	ret_code = nser_sc_query_rdma_features(dev->cqp, &feat_buf, 0);
	if (ret_code)
		goto exit;

	get_64bit_val(feat_buf.va, 0, &temp);
	feat_cnt = (u16)FIELD_GET(NSER_FEATURE_CNT, temp);
	if (feat_cnt < NSER_MIN_FEATURES) {
		ret_code = -EINVAL;
		goto exit;
	} else if (feat_cnt > NSER_MAX_FEATURES) {
		nser_dbg(dev,
			 "DEV: feature buf size insufficient, retrying with larger buffer\n");
		dma_free_coherent(dev->hw->device, feat_buf.size, feat_buf.va,
				  feat_buf.pa);
		feat_buf.va = NULL;
		feat_buf.size = ALIGN(8 * feat_cnt,
				      NSER_FEATURE_BUF_ALIGNMENT);
		feat_buf.va = dma_alloc_coherent(dev->hw->device,
						 feat_buf.size, &feat_buf.pa,
						 GFP_KERNEL);
		if (!feat_buf.va)
			return -ENOMEM;

		ret_code = nser_sc_query_rdma_features(dev->cqp, &feat_buf, 0);
		if (ret_code)
			goto exit;

		get_64bit_val(feat_buf.va, 0, &temp);
		feat_cnt = (u16)FIELD_GET(NSER_FEATURE_CNT, temp);
		if (feat_cnt < NSER_MIN_FEATURES) {
			ret_code = -EINVAL;
			goto exit;
		}
	}

	print_hex_dump_debug("WQE: QUERY RDMA FEATURES", DUMP_PREFIX_OFFSET,
			     16, 8, feat_buf.va, feat_cnt * 8, false);

	for (byte_idx = 0, feat_idx = 0; feat_idx < min_t(u16, feat_cnt, (u16)NSER_MAX_FEATURES);
	     feat_idx++, byte_idx += 8) {
		get_64bit_val(feat_buf.va, byte_idx, &temp);
		feat_type = FIELD_GET(NSER_FEATURE_TYPE, temp);
		dev->feature_info[feat_type] = temp;
	}
exit:
	dma_free_coherent(dev->hw->device, feat_buf.size, feat_buf.va,
					feat_buf.pa);
	feat_buf.va = NULL;
	return ret_code;
}

/**
 * nser_cfg_sd_mem - allocate sd memory
 * @dev: sc device struct
 * @hmc_info: ptr to nser_hmc_info struct
 */
static int nser_cfg_sd_mem(struct nser_sc_dev *dev,
			   struct nser_hmc_info *hmc_info)
{
	struct nser_virt_mem virt_mem;
	u32 mem_size;

	mem_size = sizeof(struct nser_hmc_sd_entry) * hmc_info->sd_table.sd_cnt;
	virt_mem.size = mem_size;
	virt_mem.va = kzalloc(virt_mem.size, GFP_KERNEL);
	if (!virt_mem.va)
		return -ENOMEM;
	hmc_info->sd_table.sd_entry = virt_mem.va;

	return 0;
}

/**
 * cfg_fpm_value_on_chip - configure fpm when all hmc objects on chip memory for pf
 * @dev: sc device struct
 * @hmc_info: ptr to nser_hmc_obj_info struct
 */
static int cfg_fpm_value_on_chip(struct nser_sc_dev *dev,
				 struct nser_hmc_info *hmc_info)
{
	int ret_code, i;

	for (i = NSER_HMC_IW_IRRQ_LITE; i < NSER_HMC_IW_MAX; i++)
		hmc_info->hmc_obj[i].cnt = hmc_info->hmc_obj[i].max_cnt;

	// hmc objects configured by firmware， nser not adjust them
	ret_code = nser_sc_cfg_iw_fpm(dev, dev->hmc_fn_id);
	if (ret_code) {
		nser_dbg(dev, "HMC: cfg_iw_fpm returned error_code[x%08X]\n",
			 readl(dev->hw_regs[NSER_CQPERRCODES]));
		return ret_code;
	}

	dev->pble_start_va = dev->hmc_va + hmc_info->hmc_obj[NSER_HMC_IW_PBLE].base;
	dev->hw_attrs.max_hw_ird = hmc_info->hmc_obj[NSER_HMC_IW_IRDSZ].size;

	/* No need to set and sync sd entries because firmware should know backing pages already */
	return ret_code;
}

/**
 * nser_cfg_fpm_val - configure HMC objects
 * @dev: sc device struct
 */
int nser_cfg_fpm_val(struct nser_sc_dev *dev)
{
	u32 i;
	u32 qpwanted, mrwanted, pblewanted;

	u32 sd_needed;
	u32 sd_diff;
	u32 loop_count = 0;
	struct nser_hmc_info *hmc_info;
	struct nser_hmc_fpm_misc *hmc_fpm_misc;
	int ret_code = 0;
	u32 max_sds;

	hmc_info = dev->hmc_info;
	hmc_fpm_misc = &dev->hmc_fpm_misc;
	ret_code = nser_sc_init_iw_hmc(dev, dev->hmc_fn_id);
	if (ret_code) {
		nser_dbg(dev,
			 "HMC: nser_sc_init_iw_hmc returned error_code = %d\n",
			  ret_code);
		return ret_code;
	}

	max_sds = hmc_fpm_misc->max_sds;

	if (hmc_info->mem_type == NSER_CHIP_MEM)
		return cfg_fpm_value_on_chip(dev, hmc_info);

	for (i = NSER_HMC_IW_IRRQ_LITE; i < NSER_HMC_IW_MAX; i++)
		hmc_info->hmc_obj[i].cnt = hmc_info->hmc_obj[i].max_cnt;

	sd_needed = nser_est_sd(dev, hmc_info);
	nser_dbg(dev, "HMC: sd count %d where max sd is %d\n",
		 hmc_info->sd_table.sd_cnt, max_sds);

	//pr_info("HMC: sd count %d where max sd is %d\n",hmc_info->sd_table.sd_cnt, max_sds);
	qpwanted = dev->hmc_info->hmc_obj[NSER_HMC_IW_QP].max_cnt;

	mrwanted = hmc_info->hmc_obj[NSER_HMC_IW_MR].max_cnt;
	pblewanted = hmc_info->hmc_obj[NSER_HMC_IW_PBLE].max_cnt;

	pr_info(
		  "HMC: req_qp=%d max_sd=%d, max_qp = %d, max_cq=%d, max_mr=%d, max_pble=%d, irrq=%d, orrq=%d\n",
		  qpwanted, max_sds,
		  hmc_info->hmc_obj[NSER_HMC_IW_QP].max_cnt,
		  hmc_info->hmc_obj[NSER_HMC_IW_CQ].max_cnt,
		  hmc_info->hmc_obj[NSER_HMC_IW_MR].max_cnt,
		  hmc_info->hmc_obj[NSER_HMC_IW_PBLE].max_cnt,
		  hmc_info->hmc_obj[NSER_HMC_IW_IRRQ].max_cnt,
		  hmc_info->hmc_obj[NSER_HMC_IW_ORRQ].max_cnt);
	hmc_info->hmc_obj[NSER_HMC_IW_IRRQ].cnt =
		hmc_info->hmc_obj[NSER_HMC_IW_IRRQ].max_cnt;
	hmc_info->hmc_obj[NSER_HMC_IW_ORRQ].cnt =
		hmc_info->hmc_obj[NSER_HMC_IW_ORRQ].max_cnt;
	hmc_info->hmc_obj[NSER_HMC_IW_ARP].cnt =
		hmc_info->hmc_obj[NSER_HMC_IW_ARP].max_cnt;

	do {
		++loop_count;
		hmc_info->hmc_obj[NSER_HMC_IW_QP].cnt = qpwanted;
		hmc_info->hmc_obj[NSER_HMC_IW_CQ].cnt =
			min(2 * qpwanted, hmc_info->hmc_obj[NSER_HMC_IW_CQ].cnt);
		hmc_info->hmc_obj[NSER_HMC_IW_MR].cnt = mrwanted;

		hmc_info->hmc_obj[NSER_HMC_IW_XF].cnt = hmc_info->hmc_obj[NSER_HMC_IW_XF].max_cnt;
		hmc_info->hmc_obj[NSER_HMC_IW_IRRQ].cnt =
				hmc_info->hmc_obj[NSER_HMC_IW_IRRQ].max_cnt;
		hmc_info->hmc_obj[NSER_HMC_IW_XFFL].cnt =
				hmc_info->hmc_obj[NSER_HMC_IW_XFFL].max_cnt;

		hmc_info->hmc_obj[NSER_HMC_IW_PBLE].cnt = pblewanted;
		sd_needed = nser_est_sd(dev, hmc_info);
		nser_dbg(dev,
			 "HMC: sd_needed = %d, max_sds=%d, mrwanted=%d, pblewanted=%d qpwanted=%d\n",
			  sd_needed, max_sds, mrwanted, pblewanted, qpwanted);

		/* Do not reduce resources further. All objects fit with max SDs */
		if (sd_needed <= max_sds)
			break;

		sd_diff = sd_needed - max_sds;
		if (sd_diff > 128) {
			if (!(loop_count % 2) && qpwanted > 128) {
				qpwanted /= 2;
			} else {
				mrwanted /= 2;
				pblewanted /= 2;
			}
			continue;
		}

		if ((dev->cqp->hmc_profile != NSER_HMC_PROFILE_2 &&
			dev->cqp->hmc_profile != NSER_HMC_PROFILE_4 &&
			dev->cqp->hmc_profile != NSER_HMC_PROFILE_7) &&
			pblewanted > (512 * FPM_MULTIPLIER * sd_diff)) {
			pblewanted -= 256 * FPM_MULTIPLIER * sd_diff;
			continue;
		} else if (pblewanted > 100 * FPM_MULTIPLIER) {
			pblewanted -= 10 * FPM_MULTIPLIER;
		} else if (pblewanted > 16 * FPM_MULTIPLIER) {
			pblewanted -= FPM_MULTIPLIER;
		}
		if (mrwanted > FPM_MULTIPLIER)
			mrwanted -= FPM_MULTIPLIER;
		if (!(loop_count % 10) && qpwanted > 128)
			qpwanted /= 2;
	} while (loop_count < 2000);

	if (sd_needed > max_sds) {
		nser_dbg(dev,
			 "HMC: cfg_fpm failed loop_cnt=%d, sd_needed=%d, max sd count %d\n",
			  loop_count, sd_needed, hmc_info->sd_table.sd_cnt);
		return -EINVAL;
	}

	if (loop_count > 1 && sd_needed < max_sds) {
		pblewanted += (max_sds - sd_needed) * 256 * FPM_MULTIPLIER;
		hmc_info->hmc_obj[NSER_HMC_IW_PBLE].cnt = pblewanted;
		sd_needed = nser_est_sd(dev, hmc_info);
	}

	nser_dbg(dev,
		 "HMC: loop_cnt=%d, sd_needed=%d, qpcnt = %d, cqcnt=%d, mrcnt=%d, pblecnt=%d, irrq=%d, orrq=%d, max sd count %d, first sd index %d\n",
		  loop_count, sd_needed,
		  hmc_info->hmc_obj[NSER_HMC_IW_QP].cnt,
		  hmc_info->hmc_obj[NSER_HMC_IW_CQ].cnt,
		  hmc_info->hmc_obj[NSER_HMC_IW_MR].cnt,
		  hmc_info->hmc_obj[NSER_HMC_IW_PBLE].cnt,
		  hmc_info->hmc_obj[NSER_HMC_IW_IRRQ].cnt,
		  hmc_info->hmc_obj[NSER_HMC_IW_ORRQ].cnt,
		  hmc_info->sd_table.sd_cnt, hmc_info->first_sd_index);

	ret_code = nser_sc_cfg_iw_fpm(dev, dev->hmc_fn_id);
	if (ret_code) {
		nser_dbg(dev, "HMC: cfg_iw_fpm returned error_code[x%08X]\n",
			 readl(dev->hw_regs[NSER_CQPERRCODES]));
		return ret_code;
	}

	dev->hw_attrs.max_hw_ird = hmc_info->hmc_obj[NSER_HMC_IW_IRDSZ].size;

	return nser_cfg_sd_mem(dev, hmc_info);
}

/**
 * nser_exec_cqp_cmd - execute cqp cmd when wqe are available
 * @dev: rdma device
 * @pcmdinfo: cqp command info
 */
static int nser_exec_cqp_cmd(struct nser_sc_dev *dev,
			     struct cqp_cmds_info *pcmdinfo)
{
	int status;
	struct nser_dma_mem val_mem;
	bool alloc = false;

	dev->cqp_cmd_stats[pcmdinfo->cqp_cmd]++;
	switch (pcmdinfo->cqp_cmd) {
	case NSER_OP_CEQ_DESTROY:
		status = nser_sc_ceq_destroy(pcmdinfo->in.u.ceq_destroy.ceq,
					     pcmdinfo->in.u.ceq_destroy.scratch,
					      pcmdinfo->post_sq);
		break;
	case NSER_OP_AEQ_DESTROY:
		status = nser_sc_aeq_destroy(pcmdinfo->in.u.aeq_destroy.aeq,
					     pcmdinfo->in.u.aeq_destroy.scratch,
					      pcmdinfo->post_sq);
		break;
	case NSER_OP_CEQ_CREATE:
		status = nser_sc_ceq_create(pcmdinfo->in.u.ceq_create.ceq,
					    pcmdinfo->in.u.ceq_create.scratch,
					     pcmdinfo->post_sq);
		break;
	case NSER_OP_AEQ_CREATE:
		status = nser_sc_aeq_create(pcmdinfo->in.u.aeq_create.aeq,
					    pcmdinfo->in.u.aeq_create.scratch,
					     pcmdinfo->post_sq);
		break;
	case NSER_OP_QP_UPLOAD_CONTEXT:
		status = nser_sc_qp_upload_context(pcmdinfo->in.u.qp_upload_context.dev,
						   &pcmdinfo->in.u.qp_upload_context.info,
						    pcmdinfo->in.u.qp_upload_context.scratch,
						    pcmdinfo->post_sq);
		break;
	case NSER_OP_CQ_CREATE:
		status = nser_sc_cq_create(pcmdinfo->in.u.cq_create.cq,
					   pcmdinfo->in.u.cq_create.scratch,
					    pcmdinfo->in.u.cq_create.check_overflow,
					    pcmdinfo->post_sq);
		break;
	case NSER_OP_CQ_MODIFY:
		status = nser_sc_cq_modify(pcmdinfo->in.u.cq_modify.cq,
					   &pcmdinfo->in.u.cq_modify.info,
					    pcmdinfo->in.u.cq_modify.scratch,
					    pcmdinfo->post_sq);
		break;
	case NSER_OP_CQ_DESTROY:
		status = nser_sc_cq_destroy(pcmdinfo->in.u.cq_destroy.cq,
					    pcmdinfo->in.u.cq_destroy.scratch,
					     pcmdinfo->post_sq);
		break;
	case NSER_OP_QP_FLUSH_WQES:
		status = nser_sc_qp_flush_wqes(pcmdinfo->in.u.qp_flush_wqes.qp,
					       &pcmdinfo->in.u.qp_flush_wqes.info,
						pcmdinfo->in.u.qp_flush_wqes.scratch,
						pcmdinfo->post_sq);
		break;
	case NSER_OP_UPDATE_PE_SDS:
		status = nser_update_pe_sds(pcmdinfo->in.u.update_pe_sds.dev,
					    &pcmdinfo->in.u.update_pe_sds.info,
					     pcmdinfo->in.u.update_pe_sds.scratch);
		break;
	case NSER_OP_MANAGE_HMC_PM_FUNC_TABLE:
		/* switch to calling through the call table */
		status =
			nser_sc_manage_hmc_pm_func_table(pcmdinfo->in.u.manage_hmc_pm.dev->cqp,
							 &pcmdinfo->in.u.manage_hmc_pm.info,
							  pcmdinfo->in.u.manage_hmc_pm.scratch,
							  true);
		break;
	case NSER_OP_SUSPEND:
		status = nser_sc_suspend_qp(pcmdinfo->in.u.suspend_resume.cqp,
					    pcmdinfo->in.u.suspend_resume.qp,
					     pcmdinfo->in.u.suspend_resume.scratch);
		break;
	case NSER_OP_RESUME:
		status = nser_sc_resume_qp(pcmdinfo->in.u.suspend_resume.cqp,
					   pcmdinfo->in.u.suspend_resume.qp,
					    pcmdinfo->in.u.suspend_resume.scratch);
		break;
	case NSER_OP_MANAGE_VF_PBLE_BP:
		status = nser_manage_vf_pble_bp(pcmdinfo->in.u.manage_vf_pble_bp.cqp,
						&pcmdinfo->in.u.manage_vf_pble_bp.info,
						 pcmdinfo->in.u.manage_vf_pble_bp.scratch, true);
		break;
	case NSER_OP_QUERY_FPM_VAL:
		val_mem.pa = pcmdinfo->in.u.query_fpm_val.fpm_val_pa;
		val_mem.va = pcmdinfo->in.u.query_fpm_val.fpm_val_va;
		status = nser_sc_query_fpm_val(pcmdinfo->in.u.query_fpm_val.cqp,
					       pcmdinfo->in.u.query_fpm_val.scratch,
						pcmdinfo->in.u.query_fpm_val.hmc_fn_id,
						&val_mem, true, NSER_CQP_WAIT_EVENT);
		break;
	case NSER_OP_COMMIT_FPM_VAL:
		val_mem.pa = pcmdinfo->in.u.commit_fpm_val.fpm_val_pa;
		val_mem.va = pcmdinfo->in.u.commit_fpm_val.fpm_val_va;
		status = nser_sc_commit_fpm_val(pcmdinfo->in.u.commit_fpm_val.cqp,
						pcmdinfo->in.u.commit_fpm_val.scratch,
						 pcmdinfo->in.u.commit_fpm_val.hmc_fn_id,
						 &val_mem,
						 true,
						 NSER_CQP_WAIT_EVENT);
		break;
	case NSER_OP_STATS_ALLOCATE:
		alloc = true;
		fallthrough;
	case NSER_OP_STATS_FREE:
		status = nser_sc_manage_stats_inst(pcmdinfo->in.u.stats_manage.cqp,
						   &pcmdinfo->in.u.stats_manage.info,
						    alloc,
						    pcmdinfo->in.u.stats_manage.scratch);
		break;
	case NSER_OP_STATS_GATHER:
		status = nser_sc_gather_stats(pcmdinfo->in.u.stats_gather.cqp,
					      &pcmdinfo->in.u.stats_gather.info,
					       pcmdinfo->in.u.stats_gather.scratch);
		break;
	case NSER_OP_WS_MODIFY_NODE:
		status = nser_sc_manage_ws_node(pcmdinfo->in.u.ws_node.cqp,
						&pcmdinfo->in.u.ws_node.info,
						 NSER_MODIFY_NODE,
						 pcmdinfo->in.u.ws_node.scratch);
		break;
	case NSER_OP_WS_DELETE_NODE:
		status = nser_sc_manage_ws_node(pcmdinfo->in.u.ws_node.cqp,
						&pcmdinfo->in.u.ws_node.info,
						 NSER_DEL_NODE,
						 pcmdinfo->in.u.ws_node.scratch);
		break;
	case NSER_OP_WS_ADD_NODE:
		status = nser_sc_manage_ws_node(pcmdinfo->in.u.ws_node.cqp,
						&pcmdinfo->in.u.ws_node.info,
						 NSER_ADD_NODE,
						 pcmdinfo->in.u.ws_node.scratch);
		break;
	case NSER_OP_SET_UP_MAP:
		status = nser_sc_set_up_map(pcmdinfo->in.u.up_map.cqp,
					    &pcmdinfo->in.u.up_map.info,
					     pcmdinfo->in.u.up_map.scratch);
		break;
	case NSER_OP_SET_CNP:
		status = nser_sc_set_cnp(pcmdinfo->in.u.cnp.cqp,
					 &pcmdinfo->in.u.cnp.info,
						pcmdinfo->in.u.cnp.scratch);
		break;

	case NSER_OP_QUERY_RDMA_FEATURES:
		status = nser_sc_query_rdma_features(pcmdinfo->in.u.query_rdma.cqp,
						     &pcmdinfo->in.u.query_rdma.query_buff_mem,
						      pcmdinfo->in.u.query_rdma.scratch);
		break;
	case NSER_OP_DELETE_ARP_CACHE_ENTRY:
		status = nser_sc_del_arp_cache_entry(pcmdinfo->in.u.del_arp_cache_entry.cqp,
						     pcmdinfo->in.u.del_arp_cache_entry.scratch,
						      pcmdinfo->in.u.del_arp_cache_entry.arp_index,
						      pcmdinfo->post_sq);
		break;
	case NSER_OP_QP_MODIFY:
		status = nser_sc_qp_modify(pcmdinfo->in.u.qp_modify.qp,
					   &pcmdinfo->in.u.qp_modify.info,
					    pcmdinfo->in.u.qp_modify.scratch,
					    pcmdinfo->post_sq);
		break;
	case NSER_OP_QP_CREATE:
		status = nser_sc_qp_create(pcmdinfo->in.u.qp_create.qp,
					   &pcmdinfo->in.u.qp_create.info,
					    pcmdinfo->in.u.qp_create.scratch,
					    pcmdinfo->post_sq);
		break;
	case NSER_OP_QP_DESTROY:
		status = nser_sc_qp_destroy(pcmdinfo->in.u.qp_destroy.qp,
					    pcmdinfo->in.u.qp_destroy.scratch,
					     pcmdinfo->in.u.qp_destroy.remove_hash_idx,
					     pcmdinfo->in.u.qp_destroy.ignore_mw_bnd,
					     pcmdinfo->post_sq);
		break;
	case NSER_OP_ALLOC_STAG:
		status = nser_sc_alloc_stag(pcmdinfo->in.u.alloc_stag.dev,
					    &pcmdinfo->in.u.alloc_stag.info,
					     pcmdinfo->in.u.alloc_stag.scratch,
					     pcmdinfo->post_sq);
		break;
	case NSER_OP_MR_REG_NON_SHARED:
		status = nser_sc_mr_reg_non_shared(pcmdinfo->in.u.mr_reg_non_shared.dev,
						   &pcmdinfo->in.u.mr_reg_non_shared.info,
						    pcmdinfo->in.u.mr_reg_non_shared.scratch,
						    pcmdinfo->post_sq);
		break;
	case NSER_OP_DEALLOC_STAG:
		status = nser_sc_dealloc_stag(pcmdinfo->in.u.dealloc_stag.dev,
					      &pcmdinfo->in.u.dealloc_stag.info,
					       pcmdinfo->in.u.dealloc_stag.scratch,
					       pcmdinfo->post_sq);
		break;
	case NSER_OP_MW_ALLOC:
		status = nser_sc_mw_alloc(pcmdinfo->in.u.mw_alloc.dev,
					  &pcmdinfo->in.u.mw_alloc.info,
					   pcmdinfo->in.u.mw_alloc.scratch,
					   pcmdinfo->post_sq);
		break;
	case NSER_OP_ADD_ARP_CACHE_ENTRY:
		status = nser_sc_add_arp_cache_entry(pcmdinfo->in.u.add_arp_cache_entry.cqp,
						     &pcmdinfo->in.u.add_arp_cache_entry.info,
						      pcmdinfo->in.u.add_arp_cache_entry.scratch,
						      pcmdinfo->post_sq);
		break;
	case NSER_OP_AH_CREATE:
		status = nser_sc_create_ah(pcmdinfo->in.u.ah_create.cqp,
					   &pcmdinfo->in.u.ah_create.info,
					    pcmdinfo->in.u.ah_create.scratch);
		break;
	case NSER_OP_AH_DESTROY:
		status = nser_sc_destroy_ah(pcmdinfo->in.u.ah_destroy.cqp,
					    &pcmdinfo->in.u.ah_destroy.info,
					     pcmdinfo->in.u.ah_destroy.scratch);
		break;
	case NSER_OP_MC_CREATE:
		status = nser_sc_create_mcast_grp(pcmdinfo->in.u.mc_create.cqp,
						  &pcmdinfo->in.u.mc_create.info,
						   pcmdinfo->in.u.mc_create.scratch);
		break;
	case NSER_OP_MC_DESTROY:
		status = nser_sc_destroy_mcast_grp(pcmdinfo->in.u.mc_destroy.cqp,
						   &pcmdinfo->in.u.mc_destroy.info,
						    pcmdinfo->in.u.mc_destroy.scratch);
		break;
	case NSER_OP_MC_MODIFY:
		status = nser_sc_modify_mcast_grp(pcmdinfo->in.u.mc_modify.cqp,
						  &pcmdinfo->in.u.mc_modify.info,
						   pcmdinfo->in.u.mc_modify.scratch);
		break;
	default:
		status = -EOPNOTSUPP;
		break;
	}

	return status;
}

/**
 * nser_process_cqp_cmd - process all cqp commands
 * @dev: sc device struct
 * @pcmdinfo: cqp command info
 */
int nser_process_cqp_cmd(struct nser_sc_dev *dev,
			 struct cqp_cmds_info *pcmdinfo)
{
	int status = 0;
	unsigned long flags;

	spin_lock_irqsave(&dev->cqp_lock, flags);
	if (list_empty(&dev->cqp_cmd_head) && !nser_cqp_ring_full(dev->cqp))
		status = nser_exec_cqp_cmd(dev, pcmdinfo);
	else
		list_add_tail(&pcmdinfo->cqp_cmd_entry, &dev->cqp_cmd_head);
	spin_unlock_irqrestore(&dev->cqp_lock, flags);
	return status;
}

/**
 * nser_process_bh - called from tasklet for cqp list
 * @dev: sc device struct
 */
int nser_process_bh(struct nser_sc_dev *dev)
{
	int status = 0;
	struct cqp_cmds_info *pcmdinfo;
	unsigned long flags;

	spin_lock_irqsave(&dev->cqp_lock, flags);
	while (!list_empty(&dev->cqp_cmd_head) &&
	       !nser_cqp_ring_full(dev->cqp)) {
		pcmdinfo = (struct cqp_cmds_info *)nser_remove_cqp_head(dev);
		status = nser_exec_cqp_cmd(dev, pcmdinfo);
		if (status)
			break;
	}
	spin_unlock_irqrestore(&dev->cqp_lock, flags);
	return status;
}

/**
 * sc_vsi_update_stats - Update statistics
 * @vsi: sc_vsi instance to update
 */
void sc_vsi_update_stats(struct nser_sc_vsi *vsi)
{
	struct nser_gather_stats *gather_stats;
	struct nser_gather_stats *last_gather_stats;

	gather_stats = vsi->pestat->gather_info.gather_stats_va;
	last_gather_stats = vsi->pestat->gather_info.last_gather_stats_va;
	nser_update_stats(&vsi->pestat->hw_stats, gather_stats,
			  last_gather_stats, vsi->dev->hw_stats_map,
			   vsi->dev->hw_attrs.max_stat_idx);
}

/**
 * nser_wait_pe_ready - Check if firmware is ready
 * @dev: provides access to registers
 */
static int nser_wait_pe_ready(struct nser_sc_dev *dev)
{
	u32 statuspec;
	u32 retrycount = 0;

	do {
		statuspec = readl(dev->hw_regs[NSER_GLPE_PECSTATUS]);
		if (statuspec)
			return 0;
		mdelay(1000);
	} while (retrycount++ < dev->hw_attrs.max_pe_ready_count);
	return -1;
}

/**
 * nser_set_attr_from_fragcnt
 * @dev: Device pointer
 * @max_fragcnt: maximum fragment count
 *
 * configure device attributes given a fragment count limit
 */
int nser_set_attr_from_fragcnt(struct nser_sc_dev *dev, u8 max_fragcnt)
{
	int ret;
	u32 max_inline;
	u16 max_wqesz, max_quanta_per_wr;

	/* Compute the max wqe block size applicable to both queues */
	ret = nser_fragcnt_to_wqesize_rq(max_fragcnt + 1, &max_wqesz);
	if (ret)
		return ret;

	/* auto-correct max inline we support to fit in the computed max wqe block */
	max_inline = dev->hw_attrs.uk_attrs.max_hw_inline;
	switch (max_wqesz) {
	case 32:
		if (max_inline > 8)
			max_inline = 8;
		break;
	case 64:
		if (max_inline > 39)
			max_inline = 39;
		break;
	case 128:
		if (max_inline > 101)
			max_inline = 101;
		break;
	case 224:
	case 256:
		max_inline = 224;
		break;
	default:
		break;
	}

	max_quanta_per_wr = max_wqesz / NSER_QP_WQE_MIN_SIZE;
	dev->hw_attrs.uk_attrs.max_hw_wq_frags = max_fragcnt;
	dev->hw_attrs.uk_attrs.max_hw_read_sges = max_fragcnt;
	dev->hw_attrs.uk_attrs.max_hw_inline = max_inline;
	dev->hw_attrs.max_qp_wr = NSER_MAX_QP_WRS(max_quanta_per_wr);

	return 0;
}

static inline void nser_sc_init_hw(struct nser_sc_dev *dev)
{
	nserdma_init_hw(dev);
}

/**
 * nser_sc_dev_init - Initialize control part of device
 * @dev: Device pointer
 * @info: Device init info
 */
int nser_sc_dev_init(struct nser_sc_dev *dev, struct nser_device_init_info *info)
{
	u32 vchnl_ver = 0;
	int ret_code = 0;

	INIT_LIST_HEAD(&dev->cqp_cmd_head); /* for CQP command backlog */
	mutex_init(&dev->ws_mutex);
	dev->hmc_fn_id = info->hmc_fn_id;
	dev->vsi_num = info->vsi_num;
	dev->privileged = info->privileged;
	dev->num_vfs = info->max_vfs;
	dev->fpm_query_buf_pa = info->fpm_query_buf_pa;
	dev->fpm_query_buf = info->fpm_query_buf;
	dev->fpm_commit_buf_pa = info->fpm_commit_buf_pa;
	dev->fpm_commit_buf = info->fpm_commit_buf;
	dev->hw = info->hw;
	dev->hw->hw_addr = info->bar0;
	dev->hmc_va = info->hmc_va;

	/* Setup the hardware limits, hmc may limit further */
	dev->hw_attrs.min_hw_qp_id = NSER_MIN_IW_QP_ID;
	dev->hw_attrs.min_hw_aeq_size = NSER_MIN_AEQ_ENTRIES;
	dev->hw_attrs.max_hw_aeq_size = NSER_MAX_AEQ_ENTRIES;
	dev->hw_attrs.min_hw_ceq_size = NSER_MIN_CEQ_ENTRIES;
	dev->hw_attrs.max_hw_ceq_size = NSER_MAX_CEQ_ENTRIES;
	dev->hw_attrs.uk_attrs.min_hw_cq_size = NSER_MIN_CQ_SIZE;
	dev->hw_attrs.uk_attrs.max_hw_cq_size = NSER_MAX_CQ_SIZE;
	dev->hw_attrs.max_hw_outbound_msg_size = NSER_MAX_OUTBOUND_MSG_SIZE;
	dev->hw_attrs.max_mr_size = NSER_MAX_MR_SIZE;
	dev->hw_attrs.max_hw_inbound_msg_size = NSER_MAX_INBOUND_MSG_SIZE;
	dev->hw_attrs.uk_attrs.max_hw_inline = NSER_MAX_INLINE_DATA_SIZE;
	dev->hw_attrs.max_hw_wqes = NSER_MAX_WQ_ENTRIES;
	dev->hw_attrs.max_qp_wr = NSER_MAX_QP_WRS(NSER_MAX_QUANTA_PER_WR);

	dev->hw_attrs.uk_attrs.max_hw_rq_quanta = NSER_QP_SW_MAX_RQ_QUANTA;
	dev->hw_attrs.uk_attrs.max_hw_wq_quanta = NSER_QP_SW_MAX_WQ_QUANTA;
	dev->hw_attrs.max_hw_pds = NSER_MAX_PDS;
	dev->hw_attrs.max_hw_ena_vf_count = NSER_MAX_PE_ENA_VF_COUNT;

	dev->hw_attrs.max_pe_ready_count = 14;
	dev->hw_attrs.max_done_count = NSER_DONE_COUNT;
	dev->hw_attrs.max_sleep_count = NSER_SLEEP_COUNT;
	dev->hw_attrs.max_cqp_compl_wait_time_ms = CQP_COMPL_WAIT_TIME_MS;

	if (dev->vchnl_if)
		dev->vchnl_up = true;
	else
		dev->vchnl_up = false;
	if (!dev->privileged) {
		ret_code = nser_vchnl_vf_get_ver(dev, &vchnl_ver);
		if (!ret_code) {
			nser_dbg(dev,
				 "DEV: Get Channel version rc = 0x%0x, version is %u\n",
				  ret_code, vchnl_ver);
			ret_code = nser_vchnl_vf_get_hmc_fcn(dev);
			if (!ret_code) {
				nser_dbg(dev,
					 "DEV: Get HMC function rc = 0x%0x\n",
					  ret_code);
				// TBD: Should not be continuing here
			}
		}
	} else {
		dev->vchnl_wq = info->vchnl_wq;
	}

	spin_lock_init(&dev->vf_dev_lock);
	nser_sc_init_hw(dev);

	if (dev->privileged) {
		if (nser_wait_pe_ready(dev))
			return -ETIMEDOUT;
	}
	dev->db_addr = dev->hw->hw_addr + (uintptr_t)dev->hw_regs[NSER_DB_ADDR_OFFSET];

	return ret_code;
}

/**
 * nser_stat_val - Extract HW counter value from statistics buffer
 * @stats_val: pointer to statistics buffer
 * @byteoff: byte offset of counter value in the buffer (8B-aligned)
 * @bitoff: bit offset of counter value within 8B entry
 * @bitmask: maximum counter value (e.g. 0xffffff for 24-bit counter)
 */
static inline u64 nser_stat_val(const u64 *stats_val, u16 byteoff,
				u8 bitoff, u64 bitmask)
{
	u16 idx = byteoff / sizeof(*stats_val);

	return (stats_val[idx] >> bitoff) & bitmask;
}

/**
 * nser_stat_delta - Calculate counter delta
 * @new_val: updated counter value
 * @old_val: last counter value
 * @max_val: maximum counter value (e.g. 0xffffff for 24-bit counter)
 */
static inline u64 nser_stat_delta(u64 new_val, u64 old_val, u64 max_val)
{
	if (new_val >= old_val)
		return new_val - old_val;

	if (old_val - new_val > (max_val + 1) >> 1)
		return max_val - old_val + new_val + 1;

	return 0;
}

/**
 * nser_overwrite_val - Extract HW counter value from statistics buffer
 * @new_stats_val: pointer to new statistics buffer
 * @old_stats_val: pointer to last statistics buffer
 * @byteoff: byte offset of counter value in the buffer (8B-aligned)
 * @bitoff: bit offset of counter value within 8B entry
 * @bitmask: maximum counter value (e.g. 0xffffff for 24-bit counter)
 */
static void nser_overwrite_val(u64 *new_stats_val, u64 *old_stats_val,
								u16 byteoff, u8 bitoff, u64 bitmask)
{
	u16 idx = byteoff / sizeof(*new_stats_val);

	new_stats_val[idx] = old_stats_val[idx];
}

/**
 * nser_update_stats - Update statistics
 * @hw_stats: hw_stats instance to update
 * @gather_stats: updated stat counters
 * @last_gather_stats: last stat counters
 * @map: HW stat map (hw_stats => gather_stats)
 * @max_stat_idx: number of HW stats
 */
void nser_update_stats(struct nser_dev_hw_stats *hw_stats,
		       struct nser_gather_stats *gather_stats,
			struct nser_gather_stats *last_gather_stats,
			const struct nser_hw_stat_map *map,
			u16 max_stat_idx)
{
	u64 *stats_val = hw_stats->stats_val;
	u16 i;

	for (i = 0; i < max_stat_idx; i++) {
		u64 new_val = nser_stat_val(gather_stats->val,
							map[i].byteoff, map[i].bitoff,
							map[i].bitmask);
		u64 last_val = nser_stat_val(last_gather_stats->val,
							map[i].byteoff, map[i].bitoff,
							map[i].bitmask);
		u64 gap = nser_stat_delta(new_val, last_val,
							map[i].bitmask);

		if (!gap)
			nser_overwrite_val(gather_stats->val,
							last_gather_stats->val,
							map[i].byteoff, map[i].bitoff,
							map[i].bitmask);
		else
			stats_val[i] += gap;
	}

	memcpy(last_gather_stats, gather_stats,
	       sizeof(*last_gather_stats));
}
