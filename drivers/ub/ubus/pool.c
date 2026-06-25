// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) HiSilicon Technologies Co., Ltd. 2025. All rights reserved.
 */

#define pr_fmt(fmt)	"ubus pool: " fmt

#include "ubus.h"
#include "ubus_controller.h"
#include "ubus_entity.h"
#include "resource.h"
#include "msg.h"
#include "enum.h"
#include "port.h"
#include "reset.h"
#include "instance.h"
#include "ubus_inner.h"
#include "task.h"
#include "pool.h"

struct cfg_cpl_notify_pld {
	u32 flag : 1;
	u32 rsvd : 31;
	u32 guid[UB_GUID_DW_NUM];
	u32 eid[4];
};
#define CFG_CPL_NOTIFY_PLD_SIZE 36

struct bi_create_pld {
	u32 guid[UB_GUID_DW_NUM];
	u32 eid[4];
	u32 upi : 15;
	u32 rsvd1 : 17;
};
#define BI_CREATE_PLD_SIZE 36

struct bi_destroy_pld {
	u32 guid[UB_GUID_DW_NUM];
};
#define BI_DESTROY_PLD_SIZE 16

struct pool_msg_pkt {
	struct msg_pkt_header header;
	union {
		struct entity_reg_msg_pld reg;
		struct entity_rls_msg_pld rls;
		struct cfg_cpl_notify_pld notify;
		struct bi_create_pld create;
		struct bi_destroy_pld destroy;
		struct port_reset_notify_pld port_reset;
	};
};

#define MSG_ENTITY_REG_SIZE (MSG_PKT_HEADER_SIZE + ENTITY_REG_PLD_SIZE)
#define MSG_ENTITY_RLS_SIZE (MSG_PKT_HEADER_SIZE + ENTITY_RLS_PLD_SIZE)
#define MSG_BI_CREATE_SIZE (MSG_PKT_HEADER_SIZE + BI_CREATE_PLD_SIZE)
#define MSG_BI_DESTROY_SIZE (MSG_PKT_HEADER_SIZE + BI_DESTROY_PLD_SIZE)
#define MSG_CFG_CPL_NOTIFY_SIZE (MSG_PKT_HEADER_SIZE + CFG_CPL_NOTIFY_PLD_SIZE)
#define MSG_PORT_RESET_SIZE (MSG_PKT_HEADER_SIZE + PORT_RESET_NOTIFY_PLD_SIZE)

static int ub_pool_res_init(struct entity_reg_msg_pld *pld,
			    struct ub_entity *uent, bool ers_valid)
{
	u32 source_support_map[MAX_UB_RES_NUM] = { UB_ERS0S_SUPPORT,
						   UB_ERS1S_SUPPORT,
						   UB_ERS2S_SUPPORT };
	u32 support_feature = 0;
	size_t pg_size;
	u8 sys_pg = 0;
	int ret, i;

	if (!ers_valid)
		return 0;

	ret = ub_cfg_read_byte(uent, UB_SYS_PGS, &sys_pg);
	if (ret) {
		ub_err(uent, "entity reg read UB_SYS_PGS failed, ret=%d\n", ret);
		return ret;
	}
	pg_size = (sys_pg & UB_SYS_PGS_SIZE) ? SZ_64K : SZ_4K;

	ret = ub_cfg_read_dword(uent, UB_CFG1_SUPPORT_FEATURE_L, &support_feature);
	if (ret) {
		ub_err(uent, "read cfg1 feature_l failed, ret=%d\n", ret);
		return ret;
	}

	for (i = 0; i < MAX_UB_RES_NUM; i++) {
		if (!(support_feature & source_support_map[i]))
			continue;

		uent->zone[i].res.start = ubba_gen(pld->ers[i].sa_h,
						   pld->ers[i].sa_l);
		uent->zone[i].res.end = uent->zone[i].res.start +
					((u64)pld->ers[i].ss * pg_size - 1);
		uent->zone[i].res.flags = IORESOURCE_MEM;
		uent->zone[i].res.name = ub_name(uent);
		uent->zone[i].sa_used = 1;
		uent->zone[i].ubba_used = 0;
		ub_info(uent, "mmio_idx=%d, res=%pR\n", i, &uent->zone[i].res);

		ret = ub_insert_resource(uent, i);
		if (ret) {
			ub_err(uent, "mmio[%d] insert res failed, ret=%d\n", i,
			       ret);
			goto fail;
		}

		ub_info(uent, "MMIO[%d]: ubba=0x0, size=%#llx, hpa=%#llx, wr_attr=0, prefetchable=0, order_type=0\n",
			i, ub_resource_len(uent, i), uent->zone[i].res.start);
		uent->zone[i].init_succ = 1;
	}

	return 0;

fail:
	for (i -= 1; i >= 0; i--)
		if (uent->zone[i].init_succ)
			ub_entity_free_mmio_idx(uent, i);
	return ret;
}

static void ub_pool_uent_init(struct entity_reg_msg_pld *pld,
			      struct ub_entity *uent)
{
	struct ub_guid *guid = (struct ub_guid *)pld->base.guid;
	char buf[SZ_64] = {};

	(void)ub_show_guid(guid, buf);

	uent->pool = true;
	uent->eid = pld->base.eid[0];
	uent->user_eid = pld->base.ueid[0];
	uent->cna = pld->base.cna;
	uent->upi = pld->base.upi;
	uent->entity_idx = pld->base.entity_idx;
	memcpy(uent->guid.dw, pld->base.guid, UB_GUID_SIZE);
	uent->pue = uent;
	uent->is_mue = 1;

	dev_info(&uent->ubc->dev,
		 "pool_add_idx=%u, eid=%#x, cna=%#x, upi=%#x, u_eid=%#05x, guid=%s\n",
		 pld->base.entity_idx, pld->base.eid[0], pld->base.cna,
		 pld->base.upi, pld->base.ueid[0], buf);
}

static int ub_pool_attach(struct ub_entity *uent,
			  struct entity_reg_msg_pld *pld, bool ers_valid)
{
	int ret;

	ret = ub_setup_ent(uent);
	if (ret)
		return ret;

	ret = ub_pool_res_init(pld, uent, ers_valid);
	WARN_ON(ret);

	ub_entity_assign_task_src(uent, TASK_SRC_POOL, true);
	ub_entity_add(uent, uent->ubc);
	atomic_set(&uent->ent_mgmt_state, MGMT_STATE_REGISTERING);

	return 0;
}

bool ub_rsp_msg_init(struct msg_pkt_header *header, u8 status, u32 plen)
{
	struct compact_network_header *cnth = &header->nth;
	u32 seid = header->deid;
	u32 deid = eid_gen(header->seid_h, header->seid_l);
	u16 dcna = cnth->scna;
	u16 scna = cnth->dcna;

	cnth->scna = scna;
	cnth->dcna = dcna;

	header->seid_h = seid_high(seid);
	header->seid_l = seid_low(seid);
	header->deid = deid;

	header->msgetah.plen = plen;
	header->msgetah.rsp_status = status;
	header->msgetah.type = MSG_RSP;

	return (scna == dcna);
}
EXPORT_SYMBOL_GPL(ub_rsp_msg_init);

static int ub_entity_reg_check(struct ub_bus_controller *ubc,
			       struct entity_reg_msg_pld *pld, bool ers_valid)
{
	struct ub_guid *guid = (struct ub_guid *)pld->base.guid;
	struct entity_rs_info *ers;
	int i;

	if (pld->base.eid[0] == 0 || pld->base.ueid[0] == 0) {
		dev_err(&ubc->dev, "entity reg eid=%#x u_eid=%#x is invalid\n",
			pld->base.eid[0], pld->base.ueid[0]);
		return -EINVAL;
	}

	if (!ub_bus_instance_exist(pld->base.ueid[0])) {
		dev_err(&ubc->dev, "entity reg u_eid=%#x not exist\n",
			pld->base.ueid[0]);
		return -EINVAL;
	}

	if (guid->bits.type != UB_TYPE_CONTROLLER) {
		dev_err(&ubc->dev, "entity reg guid type %u is invalid\n",
			guid->bits.type);
		return -EINVAL;
	}

	if (!ers_valid)
		return 0;

	ers = (struct entity_rs_info *)pld->ers;
	for (i = 0; i < MAX_UB_RES_NUM; i++) {
		if (ers[i].ss == 0) {
			dev_err(&ubc->dev, "entity reg ers[%d] size is 0\n", i);
			return -EINVAL;
		}
	}

	return 0;
}

static u8 ub_entity_reg_handle(struct ub_bus_controller *ubc,
			       struct pool_msg_pkt *pkt, bool ers_valid)
{
	struct entity_reg_msg_pld *pld = &pkt->reg;
	struct workqueue_struct *delay_task_wq;
	struct ub_delay_task *ub_task;
	struct ub_entity *uent;
	int ret;

	ret = ub_entity_reg_check(ubc, pld, ers_valid);
	if (ret)
		return UB_MSG_RSP_EXEC_EINVAL;

	uent = ub_alloc_ent();
	if (!uent) {
		dev_err(&ubc->dev, "Failed to allocate entity\n");
		return UB_MSG_RSP_EXEC_ENOMEM;
	}

	uent->ubc = ub_ubc_get(ubc);
	uent->dev.parent = &ubc->uent->dev;
	ub_pool_uent_init(pld, uent);

	ub_task = ub_delay_task_alloc_and_init(uent, NULL, TASK_TYPE_START);
	if (IS_ERR(ub_task)) {
		dev_err(&ubc->dev, "ub_delay_task alloc failed\n");
		ret = PTR_ERR(ub_task);
		goto free_uent;
	}

	delay_task_wq = ub_get_delay_task_wq();
	if (!delay_task_wq) {
		dev_err(&ubc->dev, "delay_task_wq get failed\n");
		ret = -EINVAL;
		goto free_task;
	}

	ret = ub_pool_attach(uent, pld, ers_valid);
	if (ret) {
		dev_err(&ubc->dev, "pool idx[%u] add failed\n",
			pld->base.entity_idx);
		goto free_task;
	}

	queue_work(delay_task_wq, &ub_task->work);

	return UB_MSG_RSP_SUCCESS;

free_task:
	ub_delay_task_free(ub_task);
free_uent:
	ub_ubc_put(uent->ubc);
	kfree(uent);
	return err_to_msg_rsp(ret);
}

static void
ub_entity_rls_msg_handler(struct ub_bus_controller *ubc, void *msg, u16 p_len)
{
	struct pool_msg_pkt *pkt = (struct pool_msg_pkt *)msg;
	struct msg_pkt_header *header = &pkt->header;
	struct entity_rls_msg_pld *pld = &pkt->rls;
	struct msg_info info = {};
	struct ub_entity *uent;
	bool local;
	u8 status;
	int ret;

	if (p_len != MSG_ENTITY_RLS_SIZE) {
		dev_err(&ubc->dev, "entity rls msg len is wrong, len=%#x\n",
			p_len);
		status = UB_MSG_RSP_CMD_LEN_ERR;
		goto rsp;
	}

	uent = ub_get_ent_by_eid(pld->eid[0]);
	if (!uent) {
		dev_err(&ubc->dev, "can not find ub entity by eid=%#05x\n",
			pld->eid[0]);
		status = UB_MSG_RSP_EXEC_ENODEV;
		goto rsp;
	}

	if (!is_p_device(uent)) {
		dev_err(&ubc->dev, "ub entity is not a pooled device\n");
		status = UB_MSG_RSP_EXEC_EINVAL;
		ub_entity_put(uent);
		goto rsp;
	}

	ret = ub_destroy_existed_entity_handler(uent);
	status = err_to_msg_rsp(ret);
	ub_entity_put(uent);

rsp:
	local = ub_rsp_msg_init(header, status, 0);
	message_info_init(&info, local ? ubc->uent : NULL, pkt, NULL,
			  (MSG_PKT_HEADER_SIZE << MSG_REQ_SIZE_OFFSET));

	ret = message_response(ubc->mdev, &info, header->msgetah.code);
	if (ret)
		dev_err(&ubc->dev, "send entity rls rsp, ret=%d\n", ret);
}

static void
ub_entity_reg_msg_handler(struct ub_bus_controller *ubc, void *msg, u16 p_len)
{
	struct pool_msg_pkt *pkt = (struct pool_msg_pkt *)msg;
	struct msg_pkt_header *header = &pkt->header;
	struct entity_reg_msg_pld *pld = &pkt->reg;
	struct msg_info info = {};
	struct ub_entity *uent;
	bool local, flag;
	u32 feature = 0;
	u8 status;
	int ret;

	if (p_len != MSG_ENTITY_REG_SIZE) {
		dev_err(&ubc->dev, "entity reg len err, len=%#x\n", p_len);
		status = UB_MSG_RSP_CMD_LEN_ERR;
		goto rsp;
	}

	ret = ub_cfg_read_dword(ubc->uent, UB_CFG1_SUPPORT_FEATURE_L, &feature);
	if (ret) {
		dev_err(&ubc->dev, "entity reg feature read failed, ret=%d\n",
			ret);
		status = UB_MSG_RSP_EXEC_ENOEXEC;
		goto rsp;
	}

	uent = ub_get_ent_by_eid(pld->base.eid[0]);
	if (uent) {
		if (!is_p_device(uent)) {
			dev_err(&ubc->dev,
				"Entity with eid=%#05x is not a pool device\n",
				pld->base.eid[0]);
			status = UB_MSG_RSP_EXEC_EINVAL;
			ub_entity_put(uent);
			goto rsp;
		}
		ret = ub_create_existed_entity_handler(uent);
		status = err_to_msg_rsp(ret);
		ub_entity_put(uent);
		goto rsp;
	}

	flag = !!(feature & UB_DECODER_JURIS);
	status = ub_entity_reg_handle(ubc, pkt, flag);

rsp:
	local = ub_rsp_msg_init(header, status, 0);
	message_info_init(&info, local ? ubc->uent : NULL, pkt, NULL,
			  (MSG_PKT_HEADER_SIZE << MSG_REQ_SIZE_OFFSET));

	ret = message_response(ubc->mdev, &info, header->msgetah.code);
	if (ret)
		dev_err(&ubc->dev, "send pool rsp msg, ret=%d\n", ret);
}

static void ub_cfg_cpl_notify_msg_rsp(struct ub_bus_controller *ubc,
				 struct msg_pkt_header *header)
{
	struct msg_info info = {};
	u32 tmp_eid, tmp_cna;
	bool local;
	int ret;

	tmp_eid = header->deid;
	header->deid = eid_gen(header->seid_h, header->seid_l);
	header->seid_h = seid_high(tmp_eid);
	header->seid_l = seid_low(tmp_eid);

	tmp_cna = header->nth.scna;
	header->nth.scna = header->nth.dcna;
	header->nth.dcna = tmp_cna;
	header->msgetah.type = MSG_RSP;
	header->msgetah.plen = 0;

	local = (header->nth.scna == header->nth.dcna);
	message_info_init(&info, local ? ubc->uent : NULL, header, NULL,
			  (MSG_PKT_HEADER_SIZE << MSG_REQ_SIZE_OFFSET));

	ret = message_response(ubc->mdev, &info, header->msgetah.code);
	if (ret)
		dev_err(&ubc->dev, "send notify rsp failed, ret=%d\n", ret);
}

static int ub_fm_flush_ubc_info(struct ub_bus_controller *ubc)
{
	struct device *dev = &ubc->dev;
	int ret = -ENOMEM;
	u32 eid, fm_cna;
	char *buf;
	u16 upi;

	buf = kzalloc(SZ_4K, GFP_KERNEL);
	if (!buf)
		goto out;

	ret = ub_query_ent_na(ubc->uent, buf);
	if (ret) {
		dev_err(dev, "update cluster ubc cna failed, ret=%d\n", ret);
		goto free_buf;
	}

	ret = ub_query_port_na(ubc->uent, buf);
	if (ret) {
		dev_err(dev, "update cluster ubc port cna failed, ret=%d\n", ret);
		goto free_buf;
	}

	ret = ub_cfg_read_word(ubc->uent, UB_UPI, &upi);
	if (ret) {
		dev_err(dev, "update cluster upi failed, ret=%d\n", ret);
		goto free_buf;
	}

	ubc->uent->upi = upi & UB_UPI_MASK;
	dev_info(dev, "update cluster ubc upi to %#x\n", ubc->uent->upi);

	ret = ub_cfg_read_dword(ubc->uent, UB_EID_0, &eid);
	if (ret) {
		dev_err(dev, "update cluster ubc eid failed, ret=%d\n", ret);
		goto free_buf;
	}

	if (eid <= ubc_eid_end) {
		dev_err(dev, "update cluster ubc wrong, eid=%#x\n", eid);
		ret = -EINVAL;
		goto free_buf;
	}

	ubc->uent->eid = eid & UB_COMPACT_EID_MASK;
	dev_info(dev, "update cluster ubc eid to %#x\n", ubc->uent->eid);

	ret = ub_cfg_read_dword(ubc->uent, UB_FM_CNA, &fm_cna);
	if (ret) {
		dev_err(dev, "read fm cna failed, ret=%d\n", ret);
		goto free_buf;
	}

	ubc->uent->fm_cna = fm_cna & UB_FM_CNA_MASK;
	dev_info(dev, "update cluster ubc fm cna to %#x\n", ubc->uent->fm_cna);

free_buf:
	kfree(buf);
out:
	return ret;
}

static void ub_cfg_cpl_notify_handler(struct ub_bus_controller *ubc, void *msg,
				      u16 p_len)
{
	struct pool_msg_pkt *pkt = (struct pool_msg_pkt *)msg;
	struct cfg_cpl_notify_pld *notify = &pkt->notify;
	struct msg_pkt_header *header = &pkt->header;
	u8 rsp_status = UB_MSG_RSP_SUCCESS;
	int ret;

	if (p_len != MSG_CFG_CPL_NOTIFY_SIZE) {
		dev_err(&ubc->dev, "notify msg len is wrong, len=%#x\n", p_len);
		rsp_status = UB_MSG_RSP_CMD_LEN_ERR;
		goto rsp;
	}

	ret = ub_fm_flush_ubc_info(ubc);
	if (ret) {
		rsp_status = err_to_msg_rsp(ret);
		goto rsp;
	}

	ret = ub_notify_bus_instance_handle(ubc, notify->flag, notify->guid,
					    notify->eid[0], ubc->uent->upi);
	if (ret) {
		dev_err(&ubc->dev, "handle notify bi failed, ret=%d\n", ret);
		rsp_status = err_to_msg_rsp(ret);
		goto rsp;
	}

	if (!ub_entity_test_priv_flag(ubc->uent, UB_ENTITY_START)) {
		ubc->uent->user_eid = notify->eid[0];
		ub_start_ent(ubc->uent);
	}

rsp:
	header->msgetah.rsp_status = rsp_status;
	ub_cfg_cpl_notify_msg_rsp(ubc, header);
}

static void ub_pool_bi_handler(struct ub_bus_controller *ubc,
			       void *msg, u16 p_len)
{
	struct pool_msg_pkt *pkt = (struct pool_msg_pkt *)msg;
	u32 size = MSG_PKT_HEADER_SIZE << MSG_REQ_SIZE_OFFSET;
	struct msg_pkt_header *header = &pkt->header;
	struct bi_create_pld *pld = &pkt->create;
	u8 status = UB_MSG_RSP_SUCCESS;
	struct device *dev = &ubc->dev;
	struct msg_info info = {};
	bool local;
	int ret;

	if (header->msgetah.sub_msg_code == UB_BI_CREATE) {
		if (p_len != MSG_BI_CREATE_SIZE) {
			dev_err(dev, "bi create msg len is wrong, len=%#x\n",
				p_len);
			status = UB_MSG_RSP_CMD_LEN_ERR;
			goto rsp;
		}

		ret = ub_msg_bus_instance_create(ubc, pld->guid, pld->eid[0],
						 pld->upi, EID_NONE);
	} else {
		if (p_len != MSG_BI_DESTROY_SIZE) {
			dev_err(dev, "bi destroy msg len is wrong, len=%#x\n",
				p_len);
			status = UB_MSG_RSP_CMD_LEN_ERR;
			goto rsp;
		}
		ret = ub_msg_bus_instance_destroy(ubc, pld->guid);
	}

	if (ret)
		status = UB_MSG_RSP_EXEC_ENOEXEC;

rsp:
	local = ub_rsp_msg_init(header, status, 0);
	message_info_init(&info, local ? ubc->uent : NULL, pkt, pkt, size);

	ret = message_response(ubc->mdev, &info, header->msgetah.code);
	if (ret)
		dev_err(dev, "send bi rsp msg, ret=%d\n", ret);
}

static void ub_port_reset_notify_handler(struct ub_bus_controller *ubc,
					 void *msg, u16 p_len)
{
	u32 size = MSG_PKT_HEADER_SIZE << MSG_REQ_SIZE_OFFSET;
	struct pool_msg_pkt *pkt = (struct pool_msg_pkt *)msg;
	struct msg_pkt_header *header = &pkt->header;
	struct port_reset_notify_pld *pld;
	u8 status = UB_MSG_RSP_SUCCESS;
	struct msg_info info = {};
	struct ub_port *port = NULL;
	bool local;
	int ret;

	pld = &pkt->port_reset;
	if (p_len != MSG_PORT_RESET_SIZE) {
		dev_err(&ubc->dev,
			"ub fm port reset notify msg len is wrong, len=%#x\n",
			p_len);
		status = UB_MSG_RSP_CMD_LEN_ERR;
		goto rsp;
	}

	if (ub_port_reset_check(ubc->uent, pld->port_index)) {
		status = UB_MSG_RSP_EXEC_ENOEXEC;
		goto rsp;
	}

	port = ubc->uent->ports + pld->port_index;
	if (port->shareable && port->domain_boundary) {
		if (pld->type == RESET_PREPARE)
			ub_notify_share_port(port, UB_PORT_EVENT_RESET_PREPARE);
		else if (pld->type == RESET_DONE)
			ub_notify_share_port(port, UB_PORT_EVENT_RESET_DONE);
	}

rsp:
	local = ub_rsp_msg_init(header, status, 0);
	message_info_init(&info, local ? ubc->uent : NULL, header, NULL, size);
	ret = message_response(ubc->mdev, &info, header->msgetah.code);
	if (ret)
		dev_err(&ubc->dev,
			"send ub fm port reset notify error, ret=%d\n", ret);
}

static rx_msg_handler_t pool_rx_msg_handler[UB_SUB_MSG_CODE_NUM] = {
	ub_entity_reg_msg_handler,
	ub_entity_rls_msg_handler,
	ub_pool_bi_handler,
	ub_pool_bi_handler,
	ub_cfg_cpl_notify_handler,
	ub_port_reset_notify_handler,
};

void ub_pool_rx_msg_handler(struct ub_bus_controller *ubc, void *pkt, u16 len)
{
	struct msg_pkt_header *header = (struct msg_pkt_header *)pkt;
	u8 sub_msg_code = header->msgetah.sub_msg_code;
	rx_msg_handler_t handler;

	handler = pool_rx_msg_handler[sub_msg_code];
	if (handler)
		handler(ubc, pkt, len);
	else
		dev_err(&ubc->dev, "pool sub msg code not support, code=%#x\n",
			sub_msg_code);
}
