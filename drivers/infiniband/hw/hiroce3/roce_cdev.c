// SPDX-License-Identifier: GPL-2.0
// Copyright(c) 2024 Huawei Technologies Co., Ltd

#include <linux/io.h>
#include <linux/sched.h>
#include <linux/uaccess.h>
#include <linux/atomic.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/fs.h>
#include <linux/errno.h>
#include <linux/mm.h>
#include <linux/init.h>
#include <linux/cdev.h>
#include <linux/timer.h>
#include <linux/slab.h>
#include <linux/device.h>
#include <linux/if_ether.h>

#include "hinic3_hw.h"
#include "hinic3_srv_nic.h"

#include "roce.h"
#include "roce_compat.h"
#include "roce_mix.h"
#include "roce_netdev.h"
#include "roce_k_ioctl.h"
#include "roce_cqm_cmd.h"
#include "roce_pub_cmd.h"
#include "roce_cdev_extension.h"
#include "roce_verbs_cmd.h"
#include "roce_cmd.h"
#include "roce_srq.h"
#include "roce_qp.h"

#ifdef ROCE_BONDING_EN
#include "roce_bond.h"
#endif

#ifdef ROCE_EXTEND
#include "roce_qp_extension.h"
#endif

#define P2PCOS_MAX_VALUE 2
#define MAX_COS_NUM 0x7

static long roce3_cdev_create_ah(struct roce3_device *rdev, void *buf)
{
	long ret;
	struct rdma_ah_attr attr;
	union roce3_create_ah_buf ah_buf;
	struct ib_udata udata;

	ret = (long)copy_from_user(&ah_buf, buf, sizeof(ah_buf));
	if (ret != 0) {
		pr_err("[ROCE, ERR] %s: Failed to copy data from user\n", __func__);
		return ret;
	}

	attr.sl = ah_buf.cmd.attr.sl;
	attr.static_rate = ah_buf.cmd.attr.static_rate;
	attr.ah_flags = (ah_buf.cmd.attr.is_global != 0) ? IB_AH_GRH : 0;
	attr.port_num = ah_buf.cmd.attr.port_num;
	attr.grh.flow_label = ah_buf.cmd.attr.grh.flow_label;
	attr.grh.sgid_index = ah_buf.cmd.attr.grh.sgid_index;
	attr.grh.hop_limit = ah_buf.cmd.attr.grh.hop_limit;
	attr.grh.traffic_class = ah_buf.cmd.attr.grh.traffic_class;
	memset(attr.roce.dmac, 0, sizeof(attr.roce.dmac));
	memcpy(attr.grh.dgid.raw, ah_buf.cmd.attr.grh.dgid, ROCE_GID_LEN);

	memset(&udata, 0, sizeof(struct ib_udata));
	if (roce3_resolve_grh(rdev, &attr, &ah_buf.resp.vlan_id, &udata) != 0) {
		pr_err("[ROCE, ERR] %s: Failed to resolve grh\n", __func__);
		return -EINVAL;
	}

	memcpy(ah_buf.resp.dmac, attr.roce.dmac, ETH_ALEN);

	ret = (long)copy_to_user((void __user *)buf, &ah_buf, sizeof(ah_buf));
	if (ret != 0) {
		pr_err("[ROCE, ERR] %s: Failed to copy data to user\n", __func__);
		return ret;
	}

	return 0;
}

#ifdef ROCE_BONDING_EN

struct roce3_get_rx_port {
	__be32 rx_port;
};

struct roce3_get_func_table {
	__be32 func_table_val;
};

struct roce3_get_udp_src_port {
	__be32 udp_src_port;
};

static struct roce3_qp *roce3_cdev_lookup_rqp(struct roce3_device *rdev, u32 qpn)
{
	struct tag_cqm_object *cqm_obj_qp = NULL;
	struct roce3_qp *rqp = NULL;

	cqm_obj_qp = cqm_object_get(rdev->hwdev, CQM_OBJECT_SERVICE_CTX, qpn, false);
	if (cqm_obj_qp == NULL) {
		dev_err(rdev->hwdev_hdl,
			"[ROCE, ERR] %s: Can't find rqp according to qpn(0x%x), func_id(%d)\n",
			__func__, qpn, rdev->glb_func_id);
		return NULL;
	}

	rqp = cqmobj_to_roce_qp(cqm_obj_qp);
	hiudk_cqm_object_put(rdev->hwdev, cqm_obj_qp);

	return rqp;
}

static int roce3_get_qp_func_table(struct roce3_device *rdev, u32 qpn, u32 *func_table_val)
{
	int ret;
	struct tag_cqm_cmd_buf *cqm_cmd_inbuf = NULL;
	struct tag_cqm_cmd_buf *cqm_cmd_outbuf = NULL;
	struct tag_roce_get_qp_func_table *get_func_tbl_inbuf = NULL;
	struct roce3_get_func_table *get_func_tbl_outbuf = NULL;

	ret = roce3_cqm_cmd_zalloc_inoutbuf(rdev->hwdev,
		&cqm_cmd_inbuf, (u16)sizeof(struct tag_roce_get_qp_func_table),
		&cqm_cmd_outbuf, (u16)sizeof(struct tag_roce_get_qp_func_table));
	if (ret != 0) {
		dev_err(rdev->hwdev_hdl,
			"[ROCE, ERR] %s: Failed to alloc cqm_cmd_inoutbuf, func_id(%d), ret(%d)\n",
			__func__, rdev->glb_func_id, ret);
		return -ENOMEM;
	}

	get_func_tbl_inbuf = (struct tag_roce_get_qp_func_table *)cqm_cmd_inbuf->buf;
	get_func_tbl_inbuf->com.index = cpu_to_be32(qpn);
	get_func_tbl_inbuf->com.dw0.bs.cmd_bitmask = cpu_to_be16(VERBS_CMD_TYPE_QP_BITMASK);
	ret = roce3_send_qp_lb_cmd(qpn, rdev, ROCE_CMD_GET_QP_FUNC_TABLE,
		cqm_cmd_inbuf, cqm_cmd_outbuf, ROCE_CMD_TIME_CLASS_A);
	if (ret != 0) {
		dev_err(rdev->hwdev_hdl, "[ROCE, ERR] %s: Failed to send ROCE_CMD_GET_QP_FUNC_TABLE command, func_id(%d)\n",
			__func__, rdev->glb_func_id);
		roce3_cqm_cmd_free_inoutbuf(rdev->hwdev, cqm_cmd_inbuf, cqm_cmd_outbuf);
		return -1;
	}
	get_func_tbl_outbuf = (struct roce3_get_func_table *)cqm_cmd_outbuf->buf;
	*func_table_val = be32_to_cpu(get_func_tbl_outbuf->func_table_val);

	roce3_cqm_cmd_free_inoutbuf(rdev->hwdev, cqm_cmd_inbuf, cqm_cmd_outbuf);
	return 0;
}

static long roce3_cdev_query_qp_tx_port(struct roce3_device *rdev, void *buf)
{
	long ret;
	u32 slave_cnt;
	struct roce3_qp *rqp = NULL;
	struct roce3_qp_port_buf qp_port_buf;
	u32 func_tbl_value = 0;

	memset(&qp_port_buf, 0, sizeof(qp_port_buf));
	ret = (long)copy_from_user(&qp_port_buf, buf, sizeof(qp_port_buf));
	if (ret != 0) {
		pr_err("[ROCE, ERR] %s: Failed to copy data from user\n", __func__);
		return ret;
	}

	rqp = roce3_cdev_lookup_rqp(rdev, qp_port_buf.qpn);
	if (rqp == NULL) {
		pr_err("[ROCE, ERR] %s: Failed to look up rqp\n", __func__);
		return -EINVAL;
	}

	if (!roce3_bond_is_active(rdev)) {
		qp_port_buf.port = 0;

		ret = (long)copy_to_user((void __user *)buf, &qp_port_buf, sizeof(qp_port_buf));
		if (ret != 0) {
			pr_err("[ROCE, ERR] %s: Failed to copy data to user\n", __func__);
			return ret;
		}

		return 0;
	}

	ret = (long)roce3_get_qp_func_table(rdev, qp_port_buf.qpn, &func_tbl_value);
	if (ret != 0) {
		dev_err(rdev->hwdev_hdl,
			"[ROCE, ERR] %s: Failed to get func_tbl, func_id(%d)\n",
			__func__, rdev->glb_func_id);
		return ret;
	}

	slave_cnt = func_tbl_value & 0xf;
	if (slave_cnt == 0) {
		pr_err("[ROCE, ERR] %s: slave_cnt is 0\n", __func__);
		return -EINVAL;
	}

	qp_port_buf.port = (func_tbl_value >>
		(ROCE_BOND_FWD_ID_TBL_ALL_BITS - ((rqp->tx_hash_value % slave_cnt + 1) *
		ROCE_BOND_FWD_ID_TBL_PER_BITS))) & ROCE_BOND_FWD_ID_TBL_PER_BITS_MASK;

	ret = (long)copy_to_user((void __user *)buf, &qp_port_buf, sizeof(qp_port_buf));
	if (ret != 0) {
		pr_err("[ROCE, ERR] %s: Failed to copy data to user\n", __func__);
		return ret;
	}

	return 0;
}

static int roce3_modify_bond_hash_value(struct roce3_device *rdev, u32 qpn, u32 new_hash_value)
{
	int ret;
	struct tag_cqm_cmd_buf *cqm_cmd_inbuf = NULL;
	struct tag_roce_modify_hash_value *modify_hash_value = NULL;

	ret = roce3_cqm_cmd_zalloc_inoutbuf(rdev->hwdev, &cqm_cmd_inbuf,
		(u16)sizeof(struct tag_roce_modify_hash_value), NULL, 0);
	if (ret != 0) {
		dev_err(rdev->hwdev_hdl,
			"[ROCE, ERR] %s: Failed to alloc cqm_cmd_inoutbuf, func_id(%d), ret(%d)\n",
			__func__, rdev->glb_func_id, ret);
		return -ENOMEM;
	}

	modify_hash_value = (struct tag_roce_modify_hash_value *)cqm_cmd_inbuf->buf;

	modify_hash_value->com.index = cpu_to_be32(qpn);
	modify_hash_value->com.dw0.bs.cmd_bitmask = cpu_to_be16(VERBS_CMD_TYPE_QP_BITMASK);
	modify_hash_value->hash_value = cpu_to_be32(new_hash_value);

	ret = roce3_send_qp_lb_cmd(qpn, rdev, ROCE_CMD_MODIFY_HASH_VALUE_QP,
		cqm_cmd_inbuf, NULL, ROCE_CMD_TIME_CLASS_A);
	if (ret != 0) {
		dev_err(rdev->hwdev_hdl,
			"[ROCE, ERR] %s: Failed to send MODIFY_HASH_VALUE_QP command, func_id(%d)\n",
			__func__, rdev->glb_func_id);
		roce3_cqm_cmd_free_inoutbuf(rdev->hwdev, cqm_cmd_inbuf, NULL);
		return -1;
	}

	roce3_cqm_cmd_free_inoutbuf(rdev->hwdev, cqm_cmd_inbuf, NULL);

	return 0;
}

static long roce3_cdev_set_qp_tx_port(struct roce3_device *rdev, const void *buf)
{
	long ret;
	u32 new_tx_hash_value;
	u32 slave_cnt;
	u32 target_hash_port;
	u32 old_hash_port;
	struct roce3_qp *rqp = NULL;
	struct roce3_qp_port_buf qp_port_buf;
	u32 func_tbl_value = 0;

	ret = (long)copy_from_user(&qp_port_buf, buf, sizeof(qp_port_buf));
	if (ret != 0) {
		pr_err("[ROCE, ERR] %s: Failed to copy data from user\n", __func__);
		return ret;
	}

	/* check qp exist */
	rqp = roce3_cdev_lookup_rqp(rdev, qp_port_buf.qpn);
	if (rqp == NULL) {
		pr_err("[ROCE, ERR] %s: Failed to look up rqp\n", __func__);
		return -EINVAL;
	}

	if (!roce3_bond_is_active(rdev))
		return 0;

	ret = (long)roce3_get_qp_func_table(rdev, qp_port_buf.qpn, &func_tbl_value);
	if (ret != 0) {
		dev_err(rdev->hwdev_hdl,
			"[ROCE, ERR] %s: Failed to get func_tbl, func_id(%d)\n",
			__func__, rdev->glb_func_id);
		return ret;
	}

	slave_cnt = func_tbl_value & 0xf;
	if (slave_cnt == 0) {
		pr_err("[ROCE, ERR] %s: slave_cnt is 0\n", __func__);
		return -EINVAL;
	}
	target_hash_port = qp_port_buf.port & ROCE_BOND_FWD_ID_TBL_PER_BITS_MASK;

	old_hash_port = (func_tbl_value >>
		(ROCE_BOND_FWD_ID_TBL_ALL_BITS - ((rqp->tx_hash_value % slave_cnt + 1) *
		ROCE_BOND_FWD_ID_TBL_PER_BITS))) & ROCE_BOND_FWD_ID_TBL_PER_BITS_MASK;

	if (target_hash_port == old_hash_port)
		return 0;

	new_tx_hash_value = rqp->tx_hash_value + (((slave_cnt - old_hash_port) +
		target_hash_port) % slave_cnt);

	ret = (long)roce3_modify_bond_hash_value(rdev, rqp->qpn, new_tx_hash_value);
	if (ret != 0) {
		dev_err(rdev->hwdev_hdl, "[ROCE, ERR] %s: Failed to modify QP(0x%06x) hash value, func_id(%d)\n",
			__func__, rqp->qpn, rdev->glb_func_id);
		return -EIO;
	}

	rqp->tx_hash_value = new_tx_hash_value;

	return 0;
}

static int roce3_get_qp_rx_port(struct roce3_device *rdev, u32 qpn, u32 *rx_port)
{
	int ret;
	struct tag_cqm_cmd_buf *cqm_cmd_inbuf = NULL;
	struct tag_cqm_cmd_buf *cqm_cmd_outbuf = NULL;
	struct tag_roce_get_qp_rx_port *get_rx_port_inbuf = NULL;
	struct roce3_get_rx_port *get_rx_port_outbuf = NULL;

	ret = roce3_cqm_cmd_zalloc_inoutbuf(rdev->hwdev,
		&cqm_cmd_inbuf, (u16)sizeof(struct tag_roce_get_qp_rx_port),
		&cqm_cmd_outbuf, (u16)sizeof(struct tag_roce_get_qp_rx_port));
	if (ret != 0) {
		dev_err(rdev->hwdev_hdl,
			"[ROCE, ERR] %s: Failed to alloc cqm_cmd_inoutbuf, func_id(%d), ret(%d)\n",
			__func__, rdev->glb_func_id, ret);
		return -ENOMEM;
	}

	get_rx_port_inbuf = (struct tag_roce_get_qp_rx_port *)cqm_cmd_inbuf->buf;
	get_rx_port_inbuf->com.index = cpu_to_be32(qpn);
	get_rx_port_inbuf->com.dw0.bs.cmd_bitmask = cpu_to_be16(VERBS_CMD_TYPE_QP_BITMASK);
	ret = roce3_send_qp_lb_cmd(qpn, rdev, ROCE_CMD_GET_QP_RX_PORT,
		cqm_cmd_inbuf, cqm_cmd_outbuf, ROCE_CMD_TIME_CLASS_A);
	if (ret != 0) {
		dev_err(rdev->hwdev_hdl, "[ROCE, ERR] %s: Failed to send ROCE_CMD_GET_QP_RX_PORT command, func_id(%d)\n",
			__func__, rdev->glb_func_id);
		roce3_cqm_cmd_free_inoutbuf(rdev->hwdev, cqm_cmd_inbuf, cqm_cmd_outbuf);
		return -1;
	}
	get_rx_port_outbuf = (struct roce3_get_rx_port *)cqm_cmd_outbuf->buf;
	*rx_port = be32_to_cpu(get_rx_port_outbuf->rx_port);

	roce3_cqm_cmd_free_inoutbuf(rdev->hwdev, cqm_cmd_inbuf, cqm_cmd_outbuf);

	return 0;
}

static long roce3_cdev_query_qp_rx_port(struct roce3_device *rdev, void *buf)
{
	long ret;
	u32 rx_port = 0;
	struct roce3_qp *rqp = NULL;
	struct roce3_qp_port_buf qp_port_buf;

	memset(&qp_port_buf, 0, sizeof(qp_port_buf));
	ret = (long)copy_from_user(&qp_port_buf, buf, sizeof(qp_port_buf));
	if (ret != 0) {
		pr_err("[ROCE, ERR] %s: Failed to copy data from user\n", __func__);
		return ret;
	}

	rqp = roce3_cdev_lookup_rqp(rdev, qp_port_buf.qpn);
	if (rqp == NULL) {
		pr_err("[ROCE, ERR] %s: Failed to look up rqp\n", __func__);
		return -EINVAL;
	}

	if (rqp->qp_type != IB_QPT_RC) {
		pr_err("[ROCE, ERR] %s: not support qp type(%d), only support RC.\n",
			__func__, rqp->qp_type);
		return -EINVAL;
	}

	if (!roce3_bond_is_active(rdev)) {
		qp_port_buf.port = 0;

		ret = (long)copy_to_user((void __user *)buf, &qp_port_buf, sizeof(qp_port_buf));
		if (ret != 0) {
			pr_err("[ROCE, ERR] %s: Failed to copy data to user\n", __func__);
			return ret;
		}

		return 0;
	}

	ret = (long)roce3_get_qp_rx_port(rdev, qp_port_buf.qpn, &rx_port);
	if (ret != 0) {
		pr_err("[ROCE, ERR] %s: Failed to get QP(0x%06x) rx port\n",
			__func__, qp_port_buf.qpn);
		return ret;
	}

	qp_port_buf.port = rx_port;

	ret = (long)copy_to_user((void __user *)buf, &qp_port_buf, sizeof(qp_port_buf));
	if (ret != 0) {
		pr_err("[ROCE, ERR] %s: Failed to copy data to user\n", __func__);
		return ret;
	}

	return 0;
}

static long roce3_cdev_query_next_wqe_idx(struct roce3_device *rdev, void *buf)
{
	long ret;
	int ret_adm;
	struct roce3_dfx_query_inbuf dfx_query_inbuf = {0};
	u32 out_size = (u32)sizeof(union roce3_dfx_query_outbuf);
	union roce3_dfx_query_outbuf dfx_query_outbuf;
	int next_wqe_idx;

	ret = (long)copy_from_user(&dfx_query_inbuf, buf, sizeof(dfx_query_inbuf));
	if (ret != 0) {
		(void)pr_err("[ROCE] %s: Failed to copy data from user, ret(%lux)\n",
			__func__, ret);
		return ret;
	}

	dfx_query_inbuf.cmd_type = ROCE_CMD_GET_SRQC_FROM_CACHE;
	ret_adm = roce3_adm_dfx_query(rdev, &dfx_query_inbuf, sizeof(dfx_query_inbuf),
		&dfx_query_outbuf, &out_size);
	if (ret_adm != 0) {
		(void)pr_err("[ROCE] %s: Failed to do roce_adm_dfx_query, ret(%d)\n",
			__func__, ret_adm);
		return -EINVAL;
	}

	dfx_query_outbuf.srq_ctx.dw2.value = be32_to_cpu(dfx_query_outbuf.srq_ctx.dw2.value);
	dfx_query_outbuf.srq_ctx.dw3.value = be32_to_cpu(dfx_query_outbuf.srq_ctx.dw3.value);
	dfx_query_outbuf.srq_ctx.dw5.value = be32_to_cpu(dfx_query_outbuf.srq_ctx.dw5.value);

	if (dfx_query_outbuf.srq_ctx.dw2.bs.container_en == 0) {
		next_wqe_idx = (int)(dfx_query_outbuf.srq_ctx.dw5.bs.next_wqe_idx);
	} else {
		u32 container_mode = MAX_SUPPORT_CONTAINER_MODE -
			dfx_query_outbuf.srq_ctx.dw2.bs_c.container_size;
		u32 container_size = roce3_get_container_sz(container_mode);

		next_wqe_idx = (int)(container_size *
			dfx_query_outbuf.srq_ctx.dw3.bs_c.head_index);
	}
	ret = (long)copy_to_user((void __user *)buf, &next_wqe_idx, sizeof(int));
	if (ret != 0) {
		(void)pr_err(
			"[ROCE] %s: Failed to copy next_wqe_idx to user, ret(0x%lx)\n",
			__func__, ret);
		return ret;
	}

	return 0;
}

static void roce3_cdev_set_bond_port_info(struct roce3_bond_device *bond_dev,
	u32 func_tbl_value, struct roce3_bond_port_info_buf *bond_port_info_buf)
{
	u32 i;

	bond_port_info_buf->original_port_num = bond_dev->slave_cnt;
	mutex_lock(&bond_dev->slave_lock);
	for (i = 0; i < bond_dev->slave_cnt; i++)
		bond_port_info_buf->original_port[i] = bond_dev->slaves[i].func_id;

	mutex_unlock(&bond_dev->slave_lock);

	bond_port_info_buf->alive_port_num = func_tbl_value & 0xf;
	for (i = 0; i < bond_port_info_buf->alive_port_num; i++) {
		bond_port_info_buf->alive_port[i] =
			(func_tbl_value >> (ROCE_BOND_FWD_ID_TBL_ALL_BITS - ((i + 1) *
			ROCE_BOND_FWD_ID_TBL_PER_BITS))) & ROCE_BOND_FWD_ID_TBL_PER_BITS_MASK;
	}
}

static long roce3_cdev_query_bond_port_info(struct roce3_device *rdev, void *buf)
{
	long ret;
	struct roce3_bond_device *bond_dev = NULL;
	struct roce3_bond_port_info_buf bond_port_info_buf;
	u32 func_tbl_value = 0;

	memset(&bond_port_info_buf, 0, sizeof(bond_port_info_buf));

	if (!roce3_bond_is_active(rdev)) {
		ret = (long)copy_to_user((void __user *)buf, &bond_port_info_buf,
			sizeof(bond_port_info_buf));
		if (ret != 0) {
			pr_err("[ROCE, ERR] %s: Failed to copy data to user\n", __func__);
			return ret;
		}

		return 0;
	}

	bond_dev = rdev->bond_dev;
	if (bond_dev == NULL) {
		dev_err(rdev->hwdev_hdl,
			"[ROCE, ERR] %s: Can't find bond_dev, func_id(%d)\n",
			__func__, rdev->glb_func_id);
		return -EINVAL;
	}

	ret = roce3_get_func_table(rdev->hwdev, rdev->glb_func_id, &func_tbl_value);
	if (ret != 0) {
		dev_err(rdev->hwdev_hdl,
			"[ROCE, ERR] %s: Failed to get func_tbl, func_id(%d)\n",
			__func__, rdev->glb_func_id);
		return ret;
	}

	roce3_cdev_set_bond_port_info(bond_dev, func_tbl_value, &bond_port_info_buf);

	ret = (long)copy_to_user((void __user *)buf, &bond_port_info_buf,
		sizeof(bond_port_info_buf));
	if (ret != 0) {
		pr_err("[ROCE, ERR] %s: Failed to copy data to user\n", __func__);
		return ret;
	}

	return 0;
}

static int roce3_modify_udp_src_port(struct roce3_device *rdev, u32 qpn, u32 new_udp_src_port)
{
	int ret;
	struct tag_cqm_cmd_buf *cqm_cmd_inbuf = NULL;
	struct tag_roce_modify_udp_src_port *modify_udp_src_port = NULL;

	ret = roce3_cqm_cmd_zalloc_inoutbuf(rdev->hwdev, &cqm_cmd_inbuf,
		(u16)sizeof(struct tag_roce_modify_udp_src_port),
		NULL, 0);
	if (ret != 0) {
		dev_err(rdev->hwdev_hdl,
			"[ROCE, ERR] %s: Failed to alloc cqm_cmd_inoutbuf, func_id(%d), ret(%d)\n",
			__func__, rdev->glb_func_id, ret);
		return -ENOMEM;
	}

	modify_udp_src_port = (struct tag_roce_modify_udp_src_port *)cqm_cmd_inbuf->buf;
	modify_udp_src_port->com.index = cpu_to_be32(qpn);
	modify_udp_src_port->com.dw0.bs.cmd_bitmask = cpu_to_be16(VERBS_CMD_TYPE_QP_BITMASK);
	modify_udp_src_port->udp_src_port = cpu_to_be32(new_udp_src_port);

	ret = roce3_send_qp_lb_cmd(qpn, rdev, ROCE_CMD_MODIFY_UDP_SRC_PORT_QP,
		cqm_cmd_inbuf, NULL, ROCE_CMD_TIME_CLASS_A);
	if (ret != 0) {
		dev_err(rdev->hwdev_hdl,
			"[ROCE, ERR] %s: Failed to send MODIFY_HASH_VALUE_QP command, func_id(%d)\n",
			__func__, rdev->glb_func_id);
		roce3_cqm_cmd_free_inoutbuf(rdev->hwdev, cqm_cmd_inbuf, NULL);
		return -1;
	}

	roce3_cqm_cmd_free_inoutbuf(rdev->hwdev, cqm_cmd_inbuf, NULL);

	return 0;
}

static long roce3_cdev_set_qp_udp_src_port(struct roce3_device *rdev, const void *buf)
{
	long ret;
	struct roce3_qp *rqp = NULL;
	struct roce3_qp_udp_src_port_buf qp_udp_src_port_buf;

	ret = (long)copy_from_user(&qp_udp_src_port_buf, buf, sizeof(qp_udp_src_port_buf));
	if (ret != 0) {
		pr_err("[ROCE, ERR] %s: Failed to copy data from user\n", __func__);
		return ret;
	}

	/* check qp exist */
	rqp = roce3_cdev_lookup_rqp(rdev, qp_udp_src_port_buf.qpn);
	if (rqp == NULL) {
		pr_err("[ROCE, ERR] %s: Failed to look up rqp\n", __func__);
		return -EINVAL;
	}

	ret = (long)roce3_modify_udp_src_port(rdev, rqp->qpn, qp_udp_src_port_buf.udp_src_port);
	if (ret != 0) {
		dev_err(rdev->hwdev_hdl,
			"[ROCE, ERR] %s: Failed to modify QP(0x%06x) hash value, func_id(%d)\n",
			__func__, rqp->qpn, rdev->glb_func_id);
		return -EIO;
	}

	return 0;
}

static int roce3_get_qp_udp_src_port(struct roce3_device *rdev, u32 qpn, u32 *udp_src_port)
{
	int ret;
	struct tag_cqm_cmd_buf *cqm_cmd_inbuf = NULL;
	struct tag_cqm_cmd_buf *cqm_cmd_outbuf = NULL;
	struct roce_get_qp_udp_src_port *get_udp_src_port = NULL;
	struct roce3_get_udp_src_port *get_udp_src_port_outbuf = NULL;

	ret = roce3_cqm_cmd_zalloc_inoutbuf(rdev->hwdev,
		&cqm_cmd_inbuf, (u16)sizeof(struct roce_get_qp_udp_src_port),
		&cqm_cmd_outbuf, (u16)sizeof(struct roce_get_qp_udp_src_port));
	if (ret != 0) {
		dev_err(rdev->hwdev_hdl,
			"[ROCE, ERR] %s: Failed to alloc cqm_cmd_inoutbuf, func_id(%d), ret(%d)\n",
			__func__, rdev->glb_func_id, ret);
		return -ENOMEM;
	}

	get_udp_src_port = (struct roce_get_qp_udp_src_port *)cqm_cmd_inbuf->buf;
	get_udp_src_port->com.index = cpu_to_be32(qpn);
	get_udp_src_port->com.dw0.bs.cmd_bitmask = cpu_to_be16(VERBS_CMD_TYPE_QP_BITMASK);

	ret = roce3_send_qp_lb_cmd(qpn, rdev, ROCE_CMD_GET_UDP_SRC_PORT_QP,
		cqm_cmd_inbuf, cqm_cmd_outbuf, ROCE_CMD_TIME_CLASS_A);
	if (ret != 0) {
		dev_err(rdev->hwdev_hdl,
			"[ROCE, ERR] %s: Failed to send ROCE_CMD_GET_QP_RX_PORT command, func_id(%d)\n",
			__func__, rdev->glb_func_id);
		roce3_cqm_cmd_free_inoutbuf(rdev->hwdev, cqm_cmd_inbuf, cqm_cmd_outbuf);
		return -1;
	}

	get_udp_src_port_outbuf = (struct roce3_get_udp_src_port *)cqm_cmd_outbuf->buf;
	*udp_src_port = be32_to_cpu(get_udp_src_port_outbuf->udp_src_port);

	roce3_cqm_cmd_free_inoutbuf(rdev->hwdev, cqm_cmd_inbuf, cqm_cmd_outbuf);

	return 0;
}

static long roce3_cdev_query_qp_udp_src_port(struct roce3_device *rdev, void *buf)
{
	long ret;
	u32 udp_src_port = 0;
	struct roce3_qp_udp_src_port_buf qp_udp_src_port_buf;

	memset(&qp_udp_src_port_buf, 0, sizeof(qp_udp_src_port_buf));
	ret = (long)copy_from_user(&qp_udp_src_port_buf, buf, sizeof(qp_udp_src_port_buf));
	if (ret != 0) {
		pr_err("[ROCE, ERR] %s: Failed to copy data from user\n", __func__);
		return ret;
	}

	ret = (long)roce3_get_qp_udp_src_port(rdev, qp_udp_src_port_buf.qpn, &udp_src_port);
	if (ret != 0) {
		pr_err("[ROCE, ERR] %s: Failed to get QP(0x%06x) udp src port\n",
			__func__, qp_udp_src_port_buf.qpn);
		return ret;
	}

	qp_udp_src_port_buf.udp_src_port = udp_src_port;

	ret = (long)copy_to_user((void __user *)buf,
		&qp_udp_src_port_buf, sizeof(qp_udp_src_port_buf));
	if (ret != 0) {
		pr_err("[ROCE, ERR] %s: Failed to copy data to user\n", __func__);
		return ret;
	}

	return 0;
}

#endif

static int roce3_cdev_open(struct inode *inode, struct file *filp)
{
	struct roce3_cdev *dev = NULL;
	struct roce3_cdev_file *file = NULL;

	file = kzalloc(sizeof(*file), GFP_KERNEL);
	if (file == NULL)
		return -ENOMEM;

	dev = container_of(inode->i_cdev, struct roce3_cdev, cdev);
	file->cdev = dev;
	filp->private_data = file;

	return 0;
}

static int roce3_cdev_close(struct inode *inode, struct file *filp)
{
	struct roce3_cdev_file *file = filp->private_data;

	kfree(file);

	return 0;
}

static ssize_t roce3_cdev_read(struct file *fp, char __user *buf, size_t size, loff_t *pos)
{
	(void)(fp);
	(void)(buf);
	(void)(size);
	(void)(pos);
	return -EOPNOTSUPP;
}

static ssize_t roce3_cdev_write(struct file *fp, const char __user *buf, size_t size, loff_t *pos)
{
	(void)(fp);
	(void)(buf);
	(void)(size);
	(void)(pos);
	return -EOPNOTSUPP;
}

#ifdef ROCE_BONDING_EN
static long roce3_cdev_bonding_ioctl_part_1(unsigned int cmd,
	unsigned long arg, struct roce3_device *rdev)
{
	long ret = 0;

	switch (cmd) {
	case ROCE_CMD_QUERY_QP_TX_PORT:
		ret = roce3_cdev_query_qp_tx_port(rdev, (void *)(uintptr_t)arg);
		if (ret != 0) {
			pr_err("[ROCE, ERR] %s: roce3_cdev_query_qp_tx_port failed.\n", __func__);
			return ret;
		}
		break;

	case ROCE_CMD_SET_QP_TX_PORT:
		ret = roce3_cdev_set_qp_tx_port(rdev, (void *)(uintptr_t)arg);
		if (ret != 0) {
			pr_err("[ROCE, ERR] %s: roce3_cdev_set_qp_tx_port failed.\n", __func__);
			return ret;
		}
		break;
	case ROCE_CMD_QUERY_QP_RX_PORT:
		ret = roce3_cdev_query_qp_rx_port(rdev, (void *)(uintptr_t)arg);
		if (ret != 0) {
			pr_err("[ROCE, ERR] %s: roce3_cdev_query_qp_rx_port failed.\n", __func__);
			return ret;
		}
		break;
	default:
		pr_err("[ROCE, ERR] %s: Not supported cmd(%d).\n", __func__, cmd);
		ret = -1;
		return ret;
	}

	return ret;
}

static long roce3_cdev_bonding_ioctl_part_2(unsigned int cmd,
	unsigned long arg, struct roce3_device *rdev)
{
	long ret = 0;

	switch (cmd) {
	case ROCE_CMD_QUERY_BOND_PORT_INFO:
		ret = roce3_cdev_query_bond_port_info(rdev, (void *)(uintptr_t)arg);
		if (ret != 0) {
			pr_err("[ROCE, ERR] %s: roce3_cdev_query_qp_tx_port failed.\n", __func__);
			return ret;
		}
		break;

	case ROCE_CMD_SET_QP_UDP_SRC_PORT:
		ret = roce3_cdev_set_qp_udp_src_port(rdev, (void *)(uintptr_t)arg);
		if (ret != 0) {
			pr_err("[ROCE, ERR] %s: roce3_cdev_set_qp_tx_port failed.\n", __func__);
			return ret;
		}
		break;
	case ROCE_CMD_QUERY_QP_UDP_SRC_PORT:
		ret = roce3_cdev_query_qp_udp_src_port(rdev, (void *)(uintptr_t)arg);
		if (ret != 0) {
			pr_err("[ROCE, ERR] %s: roce3_cdev_query_qp_rx_port failed.\n", __func__);
			return ret;
		}
		break;

	case ROCE_CMD_QUERY_NEXT_WQE_IDX:
		ret = roce3_cdev_query_next_wqe_idx(rdev, (void *)(uintptr_t)arg);
		if (ret != 0) {
			pr_err("[ROCE, ERR] %s: roce3_cdev_query_next_wqe_idx failed.\n", __func__);
			return ret;
		}
		break;

	default:
		pr_err("[ROCE, ERR] %s: Not supported cmd(%d).\n", __func__, cmd);
		ret = -1;
		return ret;
	}

	return ret;
}
static long roce3_cdev_ioctl_bonding(unsigned int cmd, unsigned long arg, struct roce3_device *rdev)
{
	long ret = 0;

	if (cmd < ROCE_CMD_QUERY_BOND_PORT_INFO) {
		ret = roce3_cdev_bonding_ioctl_part_1(cmd, arg, rdev);
		if (ret != 0)
			return ret;
	} else {
		ret = roce3_cdev_bonding_ioctl_part_2(cmd, arg, rdev);
		if (ret != 0)
			return ret;
	}

	return ret;
}

static int roce3_bond_get_dcb_info_from_buddy(struct roce3_device *rdev,
	struct roce3_bond_device *bond_dev)
{
	int i;
	int ret;
	struct roce3_bond_slave *slave = NULL;
	struct hinic3_lld_dev *lld_dev = NULL;
	struct hinic3_dcb_state dcb_info, buddy_dcb_info;

	mutex_lock(&bond_dev->slave_lock);
	for (i = 0; i < bond_dev->slave_cnt; i++) {
		slave = &bond_dev->slaves[i];
		if (slave->func_id == rdev->glb_func_id)
			continue;

		if ((bond_dev->attr.active_slaves & (1U << slave->func_id)) == 0)
			continue;

		memset(&buddy_dcb_info, 0, sizeof(buddy_dcb_info));

		lld_dev = hinic3_get_lld_dev_by_netdev(slave->netdev);
		if (!lld_dev) {
			mutex_unlock(&bond_dev->slave_lock);
			return -ENODEV;
		}
		ret = hinic3_get_dcb_state(lld_dev->hwdev, &buddy_dcb_info);
		if (ret != 0) {
			mutex_unlock(&bond_dev->slave_lock);
			pr_err("[ROCE, ERR] %s: Failed to get dcb state, ret(%d)\n",
			       __func__, ret);
			return ret;
		}

		memset(&dcb_info, 0, sizeof(dcb_info));

		ret = hinic3_get_dcb_state(rdev->hwdev, &dcb_info);
		if (ret != 0) {
			mutex_unlock(&bond_dev->slave_lock);
			pr_err("[ROCE, ERR] %s: Failed to get dcb state, ret(%d)\n",
			       __func__, ret);
			return ret;
		}

		buddy_dcb_info.default_cos = dcb_info.default_cos;
		for (i = 0; i < NIC_DCB_UP_MAX; i++) {
			if (buddy_dcb_info.pcp2cos[i] > P2PCOS_MAX_VALUE)
				buddy_dcb_info.pcp2cos[i] = dcb_info.default_cos;
		}

		memcpy(&rdev->dcb_info, &buddy_dcb_info, sizeof(buddy_dcb_info));

		mutex_unlock(&bond_dev->slave_lock);
		return ret;
	}

	mutex_unlock(&bond_dev->slave_lock);
	return 0;
}

int roce3_bond_get_dcb_info(struct roce3_device *rdev)
{
	bool bond_dev_up;
	int ret;
	struct roce3_bond_device *bond_dev = rdev->bond_dev;

	if (!roce3_bond_is_active(rdev))
		return 0;

	bond_dev_up = (bond_dev->attr.active_slaves & (1U << rdev->glb_func_id)) != 0;
	if (!bond_dev_up) {
		ret = hinic3_get_dcb_state(rdev->hwdev, &rdev->dcb_info);
		if (ret != 0) {
			pr_err("[ROCE, ERR] %s: Failed to get dcb state, ret(%d)\n",
			       __func__, ret);
			return ret;
		}
	} else {
		ret = roce3_bond_get_dcb_info_from_buddy(rdev, bond_dev);
		if (ret != 0) {
			pr_err("[ROCE, ERR] %s: Failed to get dcb state from buddy, ret(%d)\n",
				__func__, ret);
			return ret;
		}
	}

	return 0;
}
#endif

static long roce3_cdev_query_dcb(struct roce3_device *rdev, void *buf)
{
	union roce3_query_dcb_buf dcb_buf;
	long ret;
	int get_group_id;
	struct roce_group_id group_id = {0};
	u8 cos;

	ret = (long)copy_from_user(&dcb_buf, buf, sizeof(dcb_buf));
	if (ret != 0) {
		pr_err("[ROCE, ERR] %s: Failed to copy data from user\n", __func__);
		return ret;
	}

#ifdef ROCE_BONDING_EN
	if (roce3_bond_get_dcb_info(rdev) != 0) {
		pr_err("[ROCE, ERR] %s: Failed to get dcb info, ret(%lu)\n", __func__, ret);
		return (-EINVAL);
	}
#endif

	ret = (long)roce3_get_dcb_cfg_cos(rdev,
		(struct roce3_get_cos_inbuf *)(void *)(&dcb_buf), &cos);
	if (ret != 0) {
		pr_err("[ROCE, ERR] %s: Failed to get cos from dcb info, ret:%ld\n",
		       __func__, ret);
		return ret;
	}

	dcb_buf.resp.cos = cos;

	if (rdev->is_vroce) {
		get_group_id = roce3_get_group_id(rdev->glb_func_id, rdev->hwdev, &group_id);
		if (get_group_id != 0) {
			pr_warn("Failed to get group id, ret(%d)", get_group_id);
		} else {
			rdev->group_rc_cos = group_id.group_rc_cos;
			rdev->group_ud_cos = group_id.group_ud_cos;
			rdev->group_xrc_cos = group_id.group_xrc_cos;
		}
		if (dcb_buf.cmd.dscp_type == (u8)IB_QPT_RC)
			dcb_buf.resp.cos = rdev->group_rc_cos & MAX_COS_NUM;
		else if (dcb_buf.cmd.dscp_type == (u8)IB_QPT_UD)
			dcb_buf.resp.cos = rdev->group_ud_cos & MAX_COS_NUM;
		else
			dcb_buf.resp.cos = rdev->group_xrc_cos & MAX_COS_NUM;
	}

	ret = (long)copy_to_user((void __user *)buf, &dcb_buf, sizeof(dcb_buf));
	if (ret != 0) {
		pr_err("[ROCE, ERR] %s: Failed to copy data to user\n", __func__);
		return ret;
	}
	return 0;
}

static long roce3_cdev_ioctl_non_bonding(unsigned int cmd,
	struct roce3_device *rdev, unsigned long arg)
{
	long ret = 0;

	switch (cmd) {
	case ROCE_CMD_QUERY_DCB:
		ret = roce3_cdev_query_dcb(rdev, (void *)(uintptr_t)arg);
		if (ret != 0) {
			pr_err("[ROCE, ERR] %s: roce3_cdev_query_dcb failed.\n", __func__);
			return ret;
		}
		break;

	case ROCE_CMD_CREATE_AH:
		ret = roce3_cdev_create_ah(rdev, (void *)(uintptr_t)arg);
		if (ret != 0) {
			pr_err("[ROCE, ERR] %s: roce3_cdev_create_ah failed.\n", __func__);
			return ret;
		}
		break;

	default:
		ret = ioctl_non_bonding_extend(cmd, rdev, arg);
		if (ret != NOT_SUPOORT_TYPE)
			return ret;

		pr_err("[ROCE, ERR] %s: Not supported cmd(%d).\n", __func__, cmd);
		ret = -1;
		return ret;
	}

	return ret;
}

static long roce3_ioctrl_version(struct roce3_device *rdev, void *buf);
static long roce3_ioctrl_reserved_1(struct roce3_device *rdev, void *buf);
static long roce3_ioctrl_reserved_2(struct roce3_device *rdev, void *buf);
static long roce3_ioctrl_reserved_3(struct roce3_device *rdev, void *buf);
static long roce3_ioctrl_reserved_4(struct roce3_device *rdev, void *buf);
static long roce3_ioctrl_reserved_5(struct roce3_device *rdev, void *buf);
static long roce3_ioctrl_reserved_6(struct roce3_device *rdev, void *buf);

struct tag_HW_ROCE_IOCTL_ACTION {
	unsigned int cmd;
	long (*action_func)(struct roce3_device *rdev, void *buf);
};

static struct tag_HW_ROCE_IOCTL_ACTION ioctl_reserved_tbl[] = {
	{HW_ROCE_CMD_VERSION,		roce3_ioctrl_version},
	{HW_ROCE_CMD_RESERVED_1,	roce3_ioctrl_reserved_1},
	{HW_ROCE_CMD_RESERVED_2,	roce3_ioctrl_reserved_2},
	{HW_ROCE_CMD_RESERVED_3,	roce3_ioctrl_reserved_3},
	{HW_ROCE_CMD_RESERVED_4,	roce3_ioctrl_reserved_4},
	{HW_ROCE_CMD_RESERVED_5,	roce3_ioctrl_reserved_5},
	{HW_ROCE_CMD_RESERVED_6,	roce3_ioctrl_reserved_6},
};

static long roce3_cdev_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	long ret = 0;
	struct roce3_device *rdev = NULL;
	struct roce3_cdev_file *cdev_file = NULL;
	unsigned int idx = 0;

	if (_IOC_TYPE(cmd) != ROCE_IOCTL_MAGIC) {
		pr_err("[ROCE, ERR] %s: ROCE_IOCTL_MAGIC check failed.\n", __func__);
		return -EINVAL;
	}

	cdev_file = filp->private_data;
	rdev = container_of(cdev_file->cdev, struct roce3_device, cdev);

	if (cmd < ROCE_CMD_QUERY_QP_TX_PORT) {
		ret = roce3_cdev_ioctl_non_bonding(cmd, rdev, arg);
		return ret;
	}
#ifdef ROCE_BONDING_EN
	else if (cmd < ROCE_CMD_MAX) {
		ret = roce3_cdev_ioctl_bonding(cmd, arg, rdev);
		return ret;
	}
#endif
#ifdef ROCE_EXTEND
	else if (cmd == HW_ROCE_EXT_CMD_SET_QP_ATTR) {
		ret = (long)roce3_set_qp_ext_attr(rdev, (void *)(uintptr_t)arg);
		if (ret != 0)
			pr_err("[ROCE, ERR] %s: roce3_set_qp_ext_attr failed.\n", __func__);

		return ret;
	} else if (cmd == HW_ROCE_EXT_CMD_CREATE_SQPC) {
		ret = (long)roce3_vbs_create_sqpc(rdev, (void *)(uintptr_t)arg);
		if (ret != 0)
			pr_err("[ROCE, ERR] %s: roce3_vbs_create_sqpc failed.\n", __func__);

		return ret;
	}
#endif

	for (idx = 0; idx < sizeof(ioctl_reserved_tbl) / sizeof((ioctl_reserved_tbl)[0]); idx++) {
		if (cmd == ioctl_reserved_tbl[idx].cmd &&
			ioctl_reserved_tbl[idx].action_func != NULL) {
			ret = ioctl_reserved_tbl[idx].action_func(rdev, (void *)(uintptr_t)arg);
			if (ret != 0) {
				pr_err("[ROCE, ERR] %s: cmd 0x%x ioctl action failed ret %ld.\n",
					__func__, cmd, ret);
			}
			return ret;	// cmd excute end
		}
	}
	// unsupport cmd
	pr_err("[ROCE, ERR] %s: Not supported cmd(%d).\n", __func__, cmd);
	return -EOPNOTSUPP;
}

static const struct file_operations roce3_cdev_fops = {
	.owner = THIS_MODULE,
	.open = roce3_cdev_open,
	.release = roce3_cdev_close,
	.read = roce3_cdev_read,
	.write = roce3_cdev_write,
	.unlocked_ioctl = roce3_cdev_ioctl,
};

#define ROCE_BASE_CDEV_MAJOR 232
#define ROCE_BASE_CDEV_MINOR 256
#define ROCE_MAX_DEVICES 256

/*lint -e708*/
static DEFINE_SPINLOCK(map_lock);
/*lint +e708*/
static DECLARE_BITMAP(dev_map, ROCE_MAX_DEVICES);

static char *roce3_devnode(const struct device *dev, umode_t *mode)
{
	if (mode)
		*mode = DEFAULT_ROCE_DEV_NODE_PRI;

	return kasprintf(GFP_KERNEL, "%s", dev_name(dev));
}

static int roce3_init_cdev_info(struct roce3_device *rdev)
{
	int ret;

	cdev_init(&rdev->cdev.cdev, &roce3_cdev_fops);
	rdev->cdev.cdev.owner = THIS_MODULE;
	rdev->cdev.cdev.ops = &roce3_cdev_fops;

	ret = cdev_add(&rdev->cdev.cdev, rdev->cdev.dev_major, 1);
	if (ret != 0) {
		dev_err(rdev->hwdev_hdl,
			"[ROCE, ERR] %s: Add cdev failed, func_id(%d)\n",
			__func__, rdev->glb_func_id);
		goto err_add_cdev;
	}

	/*lint -e160*/
	rdev->cdev.cdev_class = class_create(rdev->ib_dev.name);
	/*lint +e160*/
	if (IS_ERR(rdev->cdev.cdev_class)) {
		ret = (int)PTR_ERR(rdev->cdev.cdev_class);
		dev_err(rdev->hwdev_hdl,
			"[ROCE, ERR] %s: Create class failed, func_id(%d)\n",
			__func__, rdev->glb_func_id);
		goto err_create_class;
	}

	/*lint -e10 -e40 -e63*/
	rdev->cdev.cdev_class->devnode = roce3_devnode;
	/*lint +e10 +e40 +e63*/

	rdev->cdev.dev = device_create(rdev->cdev.cdev_class, NULL,
		rdev->cdev.dev_major, NULL, "%s", rdev->ib_dev.name);
	if (IS_ERR(rdev->cdev.dev)) {
		ret = (int)PTR_ERR(rdev->cdev.dev);
		dev_err(rdev->hwdev_hdl,
			"[ROCE, ERR] %s: Create device failed, func_id(%d)\n",
			__func__, rdev->glb_func_id);
		goto err_create_device;
	}

	return 0;

err_create_device:
	class_destroy(rdev->cdev.cdev_class);

err_create_class:
	cdev_del(&rdev->cdev.cdev);

err_add_cdev:
	return ret;
}

int roce3_init_cdev(struct roce3_device *rdev)
{
	int ret;

	spin_lock(&map_lock);
	rdev->cdev.dev_num = (int)find_first_zero_bit(dev_map, ROCE_MAX_DEVICES);
	if (rdev->cdev.dev_num >= ROCE_MAX_DEVICES) {
		spin_unlock(&map_lock);
		return -ENOMEM;
	}

	rdev->cdev.dev_major = MKDEV(ROCE_BASE_CDEV_MAJOR,
		(u32)rdev->cdev.dev_num + ROCE_BASE_CDEV_MINOR);
	set_bit((u32)rdev->cdev.dev_num, dev_map);
	spin_unlock(&map_lock);

	ret = register_chrdev_region(rdev->cdev.dev_major, 1, rdev->ib_dev.name);
	if (ret == -EBUSY) {
		/* alloc dynamic cdev by OS */
		ret = alloc_chrdev_region(&(rdev->cdev.dev_major),
			ROCE_BASE_CDEV_MINOR, 1, rdev->ib_dev.name);
		dev_err(rdev->hwdev_hdl, "[ROCE, ERR] %s: alloc cdev region, major(%d), minor(%d), func_id(%d), ret(%d)\n",
			__func__, MAJOR(rdev->cdev.dev_major),
			MINOR(rdev->cdev.dev_major), rdev->glb_func_id, ret);
	}

	if (ret != 0) {
		dev_err(rdev->hwdev_hdl,
			"[ROCE, ERR] %s: Register region failed, func_id(%d), ret(%d)\n",
			__func__, rdev->glb_func_id, ret);
		goto err_register_region;
	}

	ret = roce3_init_cdev_info(rdev);
	if (ret != 0)
		goto err_init_cdev_info;

	return 0;

err_init_cdev_info:
	unregister_chrdev_region(rdev->cdev.dev_major, 1);

err_register_region:
	clear_bit(rdev->cdev.dev_num, dev_map);

	return ret;
}

void roce3_remove_cdev(struct roce3_device *rdev)
{
	device_destroy(rdev->cdev.cdev_class, rdev->cdev.dev_major);

	class_destroy(rdev->cdev.cdev_class);

	cdev_del(&rdev->cdev.cdev);

	unregister_chrdev_region(rdev->cdev.dev_major, 1);

	clear_bit(rdev->cdev.dev_num, dev_map);
}

// get version
static long roce3_ioctrl_version(struct roce3_device *rdev, void *buf)
{
	char ver[VERSION_LEN] = "1.01";
	long ret = copy_to_user(buf, ver, VERSION_LEN);
	return ret;
}

static long roce3_ioctrl_reserved_1(struct roce3_device *rdev, void *buf)
{
	(void)(rdev);
	(void)(buf);
	return NOT_SUPOORT_TYPE;
}

static long roce3_ioctrl_reserved_2(struct roce3_device *rdev, void *buf)
{
	(void)(rdev);
	(void)(buf);
	return NOT_SUPOORT_TYPE;
}

static long roce3_ioctrl_reserved_3(struct roce3_device *rdev, void *buf)
{
	(void)(rdev);
	(void)(buf);
	return NOT_SUPOORT_TYPE;
}

static long roce3_ioctrl_reserved_4(struct roce3_device *rdev, void *buf)
{
	(void)(rdev);
	(void)(buf);
	return NOT_SUPOORT_TYPE;
}

static long roce3_ioctrl_reserved_5(struct roce3_device *rdev, void *buf)
{
	(void)(rdev);
	(void)(buf);
	return NOT_SUPOORT_TYPE;
}

static long roce3_ioctrl_reserved_6(struct roce3_device *rdev, void *buf)
{
	(void)(rdev);
	(void)(buf);
	return NOT_SUPOORT_TYPE;
}

