// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#include "common/res_obj.h"
#include "common/xsc_ioctl.h"
#include "common/xsc_hsi.h"
#include "common/xsc_cmd.h"
#include "common/qp.h"
#include "common/driver.h"

static int xsc_alloc_obj(struct xsc_res_obj *obj, struct xsc_bdf_file *file,
			 void (*release_func)(void *), unsigned long key,
			 char *data, unsigned int datalen)
{
	obj->release_method = release_func;
	obj->file = file;
	obj->datalen = datalen;
	if (datalen) {
		obj->data = kmalloc(datalen, GFP_KERNEL);
		if (!obj->data)
			return -ENOMEM;
		memcpy(obj->data, data, datalen);
	}

	radix_tree_preload(GFP_KERNEL);
	spin_lock(&file->obj_lock);
	radix_tree_insert(&file->obj_tree, key, (void *)obj);
	spin_unlock(&file->obj_lock);
	radix_tree_preload_end();

	return 0;
}

static inline void xsc_free_obj(struct xsc_bdf_file *file, unsigned long key,
				struct xsc_res_obj **obj)
{
	*obj = radix_tree_delete(&file->obj_tree, key);
	if (!*obj)
		return;
	if ((*obj)->datalen)
		kfree((*obj)->data);
}

static void xsc_send_cmd_dealloc_pd(struct xsc_core_device *xdev, unsigned int pdn)
{
	struct xsc_dealloc_pd_mbox_in in;
	struct xsc_dealloc_pd_mbox_out out;
	int ret;

	in.hdr.opcode = cpu_to_be16(XSC_CMD_OP_DEALLOC_PD);
	in.pdn = cpu_to_be32(pdn);
	ret = xsc_cmd_exec(xdev, &in, sizeof(in), &out, sizeof(out));
	if (ret || out.hdr.status != 0)
		xsc_core_err(xdev, "failed to dealloc pd %d\n", pdn);
}

static void xsc_free_pd_obj(void *obj)
{
	struct xsc_pd_obj *pd_obj = container_of(obj, struct xsc_pd_obj, obj);
	struct xsc_bdf_file *file = pd_obj->obj.file;
	unsigned long key;
	struct xsc_res_obj *_obj;

	xsc_send_cmd_dealloc_pd(file->xdev, pd_obj->pdn);
	key = xsc_idx_to_key(RES_OBJ_PD, pd_obj->pdn);
	xsc_free_obj(file, key, &_obj);
	xsc_core_warn(pd_obj->obj.file->xdev, "free pd obj: %d\n", pd_obj->pdn);
	kfree(pd_obj);
}

int xsc_alloc_pd_obj(struct xsc_bdf_file *file,
		     unsigned int pdn, char *data, unsigned int datalen)
{
	struct xsc_pd_obj *pd_obj;
	unsigned long key;
	int ret;

	pd_obj = kzalloc(sizeof(*pd_obj), GFP_KERNEL);
	if (!pd_obj)
		return -ENOMEM;

	pd_obj->pdn = pdn;
	key = xsc_idx_to_key(RES_OBJ_PD, pdn);
	ret = xsc_alloc_obj(&pd_obj->obj, file, xsc_free_pd_obj, key, data, datalen);
	if (ret) {
		kfree(pd_obj);
		return ret;
	}
	xsc_core_dbg(file->xdev, "alloc pd %d obj\n", pdn);

	return 0;
}
EXPORT_SYMBOL_GPL(xsc_alloc_pd_obj);

void xsc_destroy_pd_obj(struct xsc_bdf_file *file, unsigned int pdn)
{
	struct xsc_pd_obj *pd_obj;
	struct xsc_res_obj *obj;
	unsigned long key = xsc_idx_to_key(RES_OBJ_PD, pdn);

	spin_lock(&file->obj_lock);
	xsc_free_obj(file, key, &obj);
	spin_unlock(&file->obj_lock);
	pd_obj = container_of(obj, struct xsc_pd_obj, obj);
	kfree(pd_obj);
	xsc_core_dbg(file->xdev, "destroy pd %d obj\n", pdn);
}
EXPORT_SYMBOL_GPL(xsc_destroy_pd_obj);

static void xsc_send_cmd_destroy_mkey(struct xsc_core_device *xdev, unsigned int mkey)
{
	struct xsc_destroy_mkey_mbox_in in;
	struct xsc_destroy_mkey_mbox_out out;
	int ret;

	in.hdr.opcode = cpu_to_be16(XSC_CMD_OP_DESTROY_MKEY);
	in.mkey = cpu_to_be32(mkey);
#ifdef REG_MR_VIA_CMDQ
	ret = xsc_cmd_exec(xdev, &in, sizeof(in), &out, sizeof(out));
#else
	ret = xsc_destroy_mkey(xdev, &in, &out);
#endif
	if (ret || out.hdr.status != 0)
		xsc_core_err(xdev, "failed to destroy mkey %d\n", mkey);
}

static void xsc_send_cmd_dereg_mr(struct xsc_core_device *xdev, unsigned int mkey)
{
	struct xsc_unregister_mr_mbox_in in;
	struct xsc_unregister_mr_mbox_out out;
	int ret;

	in.hdr.opcode = cpu_to_be16(XSC_CMD_OP_DEREG_MR);
	in.mkey = cpu_to_be32(mkey);
#ifdef REG_MR_VIA_CMDQ
	ret = xsc_cmd_exec(xdev, &in, sizeof(in), &out, sizeof(out));
#else
	ret = xsc_dereg_mr(xdev, &in, &out);
#endif
	if (ret || out.hdr.status != 0)
		xsc_core_err(xdev, "failed to dereg mr %d\n", mkey);
}

static void xsc_free_mr_obj(void *obj)
{
	struct xsc_mr_obj *mr_obj = container_of(obj, struct xsc_mr_obj, obj);
	struct xsc_bdf_file *file = mr_obj->obj.file;
	unsigned long key = xsc_idx_to_key(RES_OBJ_MR, mr_obj->mkey);
	struct xsc_res_obj *_obj;

	xsc_send_cmd_destroy_mkey(file->xdev, mr_obj->mkey);
	xsc_send_cmd_dereg_mr(file->xdev, mr_obj->mkey);

	xsc_free_obj(file, key, &_obj);
	xsc_core_warn(file->xdev, "free mr obj: %d\n", mr_obj->mkey);
	kfree(mr_obj);
}

int xsc_alloc_mr_obj(struct xsc_bdf_file *file,
		     unsigned int mkey, char *data, unsigned int datalen)
{
	struct xsc_mr_obj *mr_obj;
	unsigned long key = xsc_idx_to_key(RES_OBJ_MR, mkey);
	int ret;

	mr_obj = kzalloc(sizeof(*mr_obj), GFP_KERNEL);
	if (!mr_obj)
		return -ENOMEM;

	mr_obj->mkey = mkey;
	ret = xsc_alloc_obj(&mr_obj->obj, file, xsc_free_mr_obj, key, data, datalen);
	if (ret) {
		kfree(mr_obj);
		return ret;
	}

	xsc_core_dbg(file->xdev, "alloc mr %d obj\n", mkey);
	return 0;
}
EXPORT_SYMBOL_GPL(xsc_alloc_mr_obj);

void xsc_destroy_mr_obj(struct xsc_bdf_file *file, unsigned int mkey)
{
	struct xsc_mr_obj *mr_obj;
	struct xsc_res_obj *obj;
	unsigned long key = xsc_idx_to_key(RES_OBJ_MR, mkey);

	spin_lock(&file->obj_lock);
	xsc_free_obj(file, key, &obj);
	spin_unlock(&file->obj_lock);
	mr_obj = container_of(obj, struct xsc_mr_obj, obj);
	kfree(mr_obj);
	xsc_core_dbg(file->xdev, "destroy mr %d obj\n", mkey);
}
EXPORT_SYMBOL_GPL(xsc_destroy_mr_obj);

static void xsc_send_cmd_destroy_cq(struct xsc_core_device *xdev, unsigned int cqn)
{
	struct xsc_destroy_cq_mbox_in in;
	struct xsc_destroy_cq_mbox_out out;
	int ret;

	in.hdr.opcode = cpu_to_be16(XSC_CMD_OP_DESTROY_CQ);
	in.cqn = cpu_to_be32(cqn);
	ret = xsc_cmd_exec(xdev, &in, sizeof(in), &out, sizeof(out));
	if (ret || out.hdr.status != 0)
		xsc_core_err(xdev, "failed to destroy cq %d\n", cqn);
}

static void xsc_free_cq_obj(void *obj)
{
	struct xsc_cq_obj *cq_obj = container_of(obj, struct xsc_cq_obj, obj);
	struct xsc_bdf_file *file = cq_obj->obj.file;
	unsigned long key = xsc_idx_to_key(RES_OBJ_CQ, cq_obj->cqn);
	struct xsc_res_obj *_obj;

	xsc_send_cmd_destroy_cq(file->xdev, cq_obj->cqn);
	xsc_free_obj(file, key, &_obj);
	xsc_core_warn(file->xdev, "free cq obj: %d\n", cq_obj->cqn);
	kfree(cq_obj);
}

int xsc_alloc_cq_obj(struct xsc_bdf_file *file, unsigned int cqn,
		     char *data, unsigned int datalen)
{
	struct xsc_cq_obj *cq_obj;
	unsigned long key = xsc_idx_to_key(RES_OBJ_CQ, cqn);
	int ret;

	cq_obj = kzalloc(sizeof(*cq_obj), GFP_KERNEL);
	if (!cq_obj)
		return -ENOMEM;

	cq_obj->cqn = cqn;
	ret = xsc_alloc_obj(&cq_obj->obj, file, xsc_free_cq_obj, key, data, datalen);
	if (ret) {
		kfree(cq_obj);
		return ret;
	}
	xsc_core_dbg(file->xdev, "alloc cq %d obj\n", cqn);

	return 0;
}
EXPORT_SYMBOL_GPL(xsc_alloc_cq_obj);

void xsc_destroy_cq_obj(struct xsc_bdf_file *file, unsigned int cqn)
{
	struct xsc_cq_obj *cq_obj;
	struct xsc_res_obj *obj;
	unsigned long key = xsc_idx_to_key(RES_OBJ_CQ, cqn);

	spin_lock(&file->obj_lock);
	xsc_free_obj(file, key, &obj);
	spin_unlock(&file->obj_lock);
	cq_obj = container_of(obj, struct xsc_cq_obj, obj);
	kfree(cq_obj);
	xsc_core_dbg(file->xdev, "destroy cq %d obj\n", cqn);
}
EXPORT_SYMBOL_GPL(xsc_destroy_cq_obj);

static void xsc_send_cmd_2rst_qp(struct xsc_core_device *xdev, unsigned int qpn)
{
	struct xsc_modify_qp_mbox_in in;
	struct xsc_modify_qp_mbox_out out;
	int ret;

	ret = xsc_modify_qp(xdev, &in, &out, qpn, XSC_CMD_OP_2RST_QP);
	if (ret)
		xsc_core_err(xdev, "failed to reset qp %u\n", qpn);
}

static void xsc_send_cmd_destroy_qp(struct xsc_core_device *xdev, unsigned int qpn)
{
	struct xsc_destroy_qp_mbox_in in;
	struct xsc_destroy_qp_mbox_out out;
	int ret;

	in.hdr.opcode = cpu_to_be16(XSC_CMD_OP_DESTROY_QP);
	in.qpn = cpu_to_be32(qpn);
	ret = xsc_cmd_exec(xdev, &in, sizeof(in), &out, sizeof(out));
	if (ret || out.hdr.status != 0)
		xsc_core_err(xdev, "failed to destroy qp %d\n", qpn);
}

static void xsc_free_qp_obj(void *obj)
{
	struct xsc_qp_obj *qp_obj = container_of(obj, struct xsc_qp_obj, obj);
	struct xsc_bdf_file *file = qp_obj->obj.file;
	unsigned long key;
	struct xsc_res_obj *_obj;

	xsc_send_cmd_2rst_qp(file->xdev, qp_obj->qpn);
	xsc_send_cmd_destroy_qp(file->xdev, qp_obj->qpn);

	key = xsc_idx_to_key(RES_OBJ_QP, qp_obj->qpn);
	xsc_free_obj(file, key, &_obj);
	xsc_core_warn(file->xdev, "free qp obj: %d\n", qp_obj->qpn);
	kfree(qp_obj);
}

int xsc_alloc_qp_obj(struct xsc_bdf_file *file, unsigned int qpn,
		     char *data, unsigned int datalen)
{
	struct xsc_qp_obj *qp_obj;
	unsigned long key;
	int ret;

	qp_obj = kzalloc(sizeof(*qp_obj), GFP_KERNEL);
	if (!qp_obj)
		return -ENOMEM;

	qp_obj->qpn = qpn;
	key = xsc_idx_to_key(RES_OBJ_QP, qpn);
	ret = xsc_alloc_obj(&qp_obj->obj, file, xsc_free_qp_obj, key, data, datalen);
	if (ret) {
		kfree(qp_obj);
		return ret;
	}
	xsc_core_dbg(file->xdev, "alloc qp %d obj\n", qpn);

	return 0;
}
EXPORT_SYMBOL_GPL(xsc_alloc_qp_obj);

void xsc_destroy_qp_obj(struct xsc_bdf_file *file, unsigned int qpn)
{
	struct xsc_qp_obj *qp_obj;
	struct xsc_res_obj *obj;
	unsigned long key = xsc_idx_to_key(RES_OBJ_QP, qpn);

	spin_lock(&file->obj_lock);
	xsc_free_obj(file, key, &obj);
	spin_unlock(&file->obj_lock);
	qp_obj = container_of(obj, struct xsc_qp_obj, obj);
	kfree(qp_obj);
	xsc_core_dbg(file->xdev, "destroy qp %d obj\n", qpn);
}
EXPORT_SYMBOL_GPL(xsc_destroy_qp_obj);

static void xsc_send_cmd_del_pct(struct xsc_core_device *xdev,
				 unsigned int priority)
{
	struct xsc_ioctl_mbox_in *in;
	struct xsc_ioctl_mbox_out *out;
	struct xsc_ioctl_data_tl *tl;
	struct xsc_flow_pct_v4_del *pct_v4;
	unsigned int inlen;
	unsigned int outlen;
	int ret;

	inlen = sizeof(struct xsc_ioctl_mbox_in) + sizeof(struct xsc_ioctl_data_tl)
		+ sizeof(struct xsc_flow_pct_v4_del);
	in = kzalloc(inlen, GFP_KERNEL);
	if (!in)
		return;

	outlen = sizeof(struct xsc_ioctl_mbox_out) + sizeof(struct xsc_ioctl_data_tl)
		+ sizeof(struct xsc_flow_pct_v4_del);
	out = kzalloc(outlen, GFP_KERNEL);
	if (!out) {
		kfree(in);
		return;
	}

	in->hdr.opcode = cpu_to_be16(XSC_CMD_OP_IOCTL_FLOW);
	in->len = sizeof(struct xsc_ioctl_data_tl) + sizeof(struct xsc_flow_pct_v4_del);
	in->len = cpu_to_be16(in->len);
	tl = (struct xsc_ioctl_data_tl *)in->data;
	tl->opmod = XSC_IOCTL_OP_DEL;
	tl->table = XSC_FLOW_TBL_PCT_V4;
	tl->length = sizeof(struct xsc_flow_pct_v4_del);
	pct_v4 = (struct xsc_flow_pct_v4_del *)(tl + 1);
	pct_v4->priority = priority;
	out->len = in->len;
	ret = xsc_cmd_exec(xdev, in, inlen, out, outlen);
	if (ret || out->hdr.status != 0)
		xsc_core_err(xdev, "failed to del pct %d\n", priority);

	kfree(in);
	kfree(out);
}

static void xsc_free_pct_obj(void *obj)
{
	struct xsc_pct_obj *pct_obj = container_of(obj, struct xsc_pct_obj, obj);
	struct xsc_bdf_file *file = pct_obj->obj.file;
	struct xsc_res_obj *_obj;
	unsigned long key = xsc_idx_to_key(RES_OBJ_PCT, pct_obj->pct_idx);

	xsc_send_cmd_del_pct(file->xdev, pct_obj->pct_idx);
	xsc_free_obj(file, key, &_obj);
	xsc_core_warn(file->xdev, "free pct obj, priority:%d\n", pct_obj->pct_idx);
	kfree(pct_obj);
}

/* both pct4 and pct6 are allocated in the same tcam table, so we can delete pct6
 * by pct4 method
 */
int xsc_alloc_pct_obj(struct xsc_bdf_file *file, unsigned int priority,
		      char *data, unsigned int datalen)
{
	struct xsc_pct_obj *pct_obj;
	int ret;
	unsigned long key = xsc_idx_to_key(RES_OBJ_PCT, priority);

	pct_obj = kzalloc(sizeof(*pct_obj), GFP_KERNEL);
	if (!pct_obj)
		return -ENOMEM;

	pct_obj->pct_idx = priority;
	ret = xsc_alloc_obj(&pct_obj->obj, file, xsc_free_pct_obj, key, data, datalen);
	if (ret)
		kfree(pct_obj);
	xsc_core_dbg(file->xdev, "alloc pct %d obj\n", priority);
	return ret;
}
EXPORT_SYMBOL_GPL(xsc_alloc_pct_obj);

void xsc_destroy_pct_obj(struct xsc_bdf_file *file, unsigned int priority)
{
	struct xsc_pct_obj *pct_obj;
	struct xsc_res_obj *obj;
	unsigned long key = xsc_idx_to_key(RES_OBJ_PCT, priority);

	spin_lock(&file->obj_lock);
	xsc_free_obj(file, key, &obj);
	spin_unlock(&file->obj_lock);
	pct_obj = container_of(obj, struct xsc_pct_obj, obj);
	kfree(pct_obj);
	xsc_core_dbg(file->xdev, "destroy pct %d obj\n", priority);
}
EXPORT_SYMBOL_GPL(xsc_destroy_pct_obj);

void xsc_close_bdf_file(struct xsc_bdf_file *file)
{
	struct radix_tree_iter iter;
	void **slot;
	struct xsc_res_obj *obj;

	xsc_core_warn(file->xdev, "release bdf file:%lx\n", file->key);
	spin_lock(&file->obj_lock);
	radix_tree_for_each_slot(slot, &file->obj_tree, &iter, 0) {
		obj = (struct xsc_res_obj *)(*slot);
		obj->release_method(obj);
	}
	spin_unlock(&file->obj_lock);
}
EXPORT_SYMBOL_GPL(xsc_close_bdf_file);
