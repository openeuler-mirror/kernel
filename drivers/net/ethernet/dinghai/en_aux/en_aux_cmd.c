// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#include <linux/dinghai/zxdh_compat.h>
#include <linux/dinghai/driver.h>
#include <linux/netdevice.h>
#include <linux/scatterlist.h>
#include <linux/interrupt.h>
#include <linux/device.h>
#include <linux/pci.h>
#include <xen/xen.h>
#include "../slib.h"
#include <linux/dinghai/dh_cmd.h>
#include "../en_aux.h"
#include "../en_np/table/include/dpp_tbl_api.h"
#include "../msg_common.h"
#include "en_aux_cmd.h"

#define UINT64_MAX (0xFFFFFFFFFFFFFFFF)

static s32 write_queue_index_to_message(struct zxdh_en_device *en_dev, u32 queue_nums, u32 field,
					u16 *bytes, u16 *data, union zxdh_msg *old_msg)
{
	u32 ix = 0;
	u16 old_queue_nums = 0;

	if (field == OP_CODE_DATA_CHAN) {
		*bytes = (u16)((queue_nums + 1) * ZXDH_QS_PAIRS);
		data[0] = (u16)queue_nums;

		for (ix = 0; ix < queue_nums; ix = ix + ZXDH_QS_PAIRS) {
			data[ix + 1] = en_dev->phy_index[ix];
			data[ix + 2] = en_dev->phy_index[ix + 1];
		}

		if (old_msg) {
			LOG_DEBUG("old_msg->reps.cmn_vq_msg.queue_nums: %u; queue_nums: %u",
				  old_msg->reps.cmn_vq_msg.queue_nums, queue_nums);
			if (old_msg->reps.cmn_vq_msg.queue_nums > 0) {
				old_queue_nums = old_msg->reps.cmn_vq_msg.queue_nums;
				if ((old_queue_nums + queue_nums) > 256) {
					LOG_ERR("Exceede max queues, old_queue(%d)+queue(%d)\n",
						old_queue_nums, queue_nums);
					return -1;
				}

				*bytes = (u16)((queue_nums + old_queue_nums + 1) * ZXDH_QS_PAIRS);
				data[0] = (u16)(queue_nums + old_queue_nums);
				memcpy(data + queue_nums + 1, old_msg->reps.cmn_vq_msg.phy_qidx,
				       old_queue_nums * ZXDH_QS_PAIRS);

				for (ix = 1; ix <= (queue_nums + old_queue_nums); ix++)
					LOG_DEBUG("vq phy_qid: %d ", data[ix]);
			}
		}
	}
#ifdef ZXDH_MSGQ
	else if (field == OP_CODE_MSGQ_CHAN) {
		if (en_dev->curr_queue_pairs * 2 > (ZXDH_MAX_QUEUES_NUM - 1)) {
			LOG_ERR("curr_queue_pairs out range!\n");
			return -1;
		}
		*bytes = (u16)(queue_nums * ZXDH_QS_PAIRS);
		data[0] =
			en_dev->phy_index[en_dev->curr_queue_pairs *
					  2]; //en_dev->rq[en_dev->curr_queue_pairs].vq->phy_index;
		data[1] =
			en_dev->phy_index[en_dev->curr_queue_pairs * 2 +
					  1]; //en_dev->sq[en_dev->curr_queue_pairs].vq->phy_index;
	}
#endif

	return 0;
}

static s32 cmd_tbl_messgae_to_riscv_send(struct zxdh_en_device *en_dev, void *payload, u32 pld_len)
{
	s32 ret = 0;
	struct cmd_hdr_recv *hdr_recv;
	struct cmd_tbl_ack cmd_tbl_ack = { 0 };
	struct zxdh_bar_extra_para para = { 0 };

	para.is_sync = true;
	para.retrycnt = BAR_MSG_RETRY_CNT_MAX;

	ret = en_dev->ops->msg_send_cmd(en_dev->parent, MODULE_TBL, payload, &cmd_tbl_ack, &para);
	if (ret != 0) {
		LOG_ERR("en_dev->ops->msg_send_cmd failed\n");
		goto out;
	}

	hdr_recv = (struct cmd_hdr_recv *)&cmd_tbl_ack;
	if (hdr_recv->check != OP_CODE_TBL_STAT) {
		LOG_ERR("tbl init message recv check failed\n");
		ret = -1;
	}
out:
	return ret;
}

static s32 cmd_common_tbl_init(struct zxdh_en_device *en_dev, u32 queue_nums, u32 field,
			       union zxdh_msg *old_msg)
{
	s32 ret = 0;
	union zxdh_msg *msg = NULL;

	msg = kzalloc(sizeof(union zxdh_msg), GFP_KERNEL);
	if (!msg) {
		LOG_ERR("kzalloc(%lu, GFP_KERNEL) failed !", sizeof(union zxdh_msg));
		return -1;
	}

	if ((2 * ZXDH_MAX_PAIRS_NUM) < queue_nums) {
		LOG_ERR("queue pairs %u out of range\n", queue_nums);
		kfree(msg);
		return -ENOMEM;
	}

	msg->payload.hdr_to_cmn.field = field;
	msg->payload.hdr_to_cmn.type = OP_CODE_WRITE;
	msg->payload.hdr_to_cmn.pcie_id = en_dev->pcie_id;
	ret = write_queue_index_to_message(en_dev, queue_nums, field,
					   &msg->payload.hdr_to_cmn.write_bytes,
					   msg->payload.cmn_tbl_msg, old_msg);
	if (ret != 0) {
		LOG_ERR("write_queue_index_to_message failed, ret: %d\n", ret);
		kfree(msg);
		return ret;
	}

	ret = cmd_tbl_messgae_to_riscv_send(
		en_dev, msg, MSG_STRUCT_HD_LEN + msg->payload.hdr_to_cmn.write_bytes);
	if (ret != 0)
		LOG_ERR("zxdh_bar_chan_sync_msg_send failed, ret: %d\n", ret);

	kfree(msg);

	return ret;
}

s32 zxdh_common_tbl_init(struct net_device *netdev, union zxdh_msg *old_msg)
{
	struct zxdh_en_priv *en_priv = netdev_priv(netdev);
	struct zxdh_en_device *en_dev = &en_priv->edev;
	s32 ret = 0;

#ifdef ZXDH_MSGQ
	if (NEED_MSGQ(en_dev)) {
		ret = cmd_common_tbl_init(en_dev, ZXDH_QS_PAIRS, OP_CODE_MSGQ_CHAN, old_msg);
		if (ret != 0) {
			LOG_ERR("field msgq message failed\n");
			return -1;
		}
	}
#endif

	ret = cmd_common_tbl_init(en_dev, en_dev->curr_queue_pairs * ZXDH_QS_PAIRS,
				  OP_CODE_DATA_CHAN, old_msg);
	if (ret != 0) {
		LOG_ERR("field data message failed\n");
		return -1;
	}

	return 0;
}

s32 get_common_table_msg(struct zxdh_en_device *en_dev, u16 pcie_id, u8 field, void *ack)
{
	s32 ret = 0;
	union zxdh_msg *msg = NULL;
	struct zxdh_bar_extra_para para = { 0 };

	para.is_sync = true;
	para.retrycnt = BAR_MSG_RETRY_CNT_MAX;

	msg = kzalloc(sizeof(union zxdh_msg), GFP_KERNEL);
	if (!msg) {
		LOG_ERR("kzalloc(%lu, GFP_KERNEL) failed !", sizeof(union zxdh_msg));
		return -1;
	}

	msg->payload.hdr_to_cmn.type = RISC_TYPE_READ;
	msg->payload.hdr_to_cmn.field = field;
	msg->payload.hdr_to_cmn.pcie_id = pcie_id;
	msg->payload.hdr_to_cmn.write_bytes = 0;

	ret = en_dev->ops->msg_send_cmd(en_dev->parent, MODULE_TBL, msg, ack, &para);

	kfree(msg);

	return ret;
}

s32 zxdh_hash_id_get(struct zxdh_en_device *en_dev)
{
	s32 ret = 0;
	union zxdh_msg *msg = NULL;

	msg = kzalloc(sizeof(union zxdh_msg), GFP_KERNEL);
	if (!msg) {
		LOG_ERR("kzalloc(%lu, GFP_KERNEL) failed !", sizeof(union zxdh_msg));
		return -1;
	}

	ret = get_common_table_msg(en_dev, en_dev->pcie_id, RISC_FIELD_HASHID_CHANNEL, msg);
	if (ret != 0) {
		LOG_ERR("get own hash_id failed: %d\n", ret);
		kfree(msg);
		return ret;
	}

	en_dev->hash_search_idx = msg->reps.cmn_recv_msg.value;
	LOG_DEBUG("hash_id: %u\n", en_dev->hash_search_idx);
	if (en_dev->hash_search_idx > ZXDH_MAX_HASH_INDEX) {
		LOG_ERR("hash_id is invalid value: %u\n", en_dev->hash_search_idx);
		kfree(msg);
		return -EINVAL;
	}
	if (en_dev->hash_search_idx == ZXDH_MAX_HASH_INDEX)
		en_dev->hash_search_idx = 1;

	kfree(msg);

	return ret;
}

s32 zxdh_phyport_get(struct zxdh_en_device *en_dev)
{
	s32 ret = 0;
	union zxdh_msg *msg = NULL;

	msg = kzalloc(sizeof(union zxdh_msg), GFP_KERNEL);
	if (!msg) {
		LOG_ERR("kzalloc(%lu, GFP_KERNEL) failed !", sizeof(union zxdh_msg));
		return -1;
	}

	ret = get_common_table_msg(en_dev, en_dev->pcie_id, RISC_FIELD_PHYPORT_CHANNEL, msg);
	if (ret != 0) {
		LOG_ERR("get own phyport failed: %d\n", ret);
		kfree(msg);
		return ret;
	}

	en_dev->phy_port = msg->reps.cmn_recv_msg.value;
	if (en_dev->phy_port == INVALID_PHY_PORT) {
		LOG_ERR("get phy_port failed\n");
		kfree(msg);
		return -EINVAL;
	}
	en_dev->ops->set_pf_phy_port(en_dev->parent, en_dev->phy_port);
	LOG_DEBUG("0x%x phy_port: %u\n", en_dev->ep_bdf, en_dev->phy_port);

	kfree(msg);

	return ret;
}

s32 zxdh_panel_id_init(struct zxdh_en_device *en_dev)
{
	s32 ret = 0;
	union zxdh_msg *msg = NULL;

	if (!zxdh_en_is_panel_port(en_dev) || en_dev->ops->is_bond(en_dev->parent))
		return ret;

	msg = kzalloc(sizeof(union zxdh_msg), GFP_KERNEL);
	if (!msg) {
		LOG_ERR("kzalloc(%lu, GFP_KERNEL) failed !", sizeof(union zxdh_msg));
		return -1;
	}

	ret = get_common_table_msg(en_dev, en_dev->pcie_id, RISC_FIELD_PANEL_ID, msg);
	if (ret != 0) {
		LOG_ERR("get own phyport failed: %d\n", ret);
		kfree(msg);
		return ret;
	}

	en_dev->panel_id = msg->reps.cmn_recv_msg.value;
	if (en_dev->panel_id > MAX_PANEL_ID) {
		LOG_ERR("get panel_id failed, panel_id: %u\n", en_dev->panel_id);
		kfree(msg);
		return -EINVAL;
	}
	LOG_DEBUG("panel_id: %u\n", en_dev->panel_id);

	kfree(msg);

	return ret;
}

s32 zxdh_pf_macpcs_num_get(struct zxdh_en_device *en_dev)
{
	s32 phy_port = 0;
	s32 mac_num = 0; //0-2

	phy_port = en_dev->phy_port;

	if (phy_port < 4) {
		mac_num = 0;
	} else if (phy_port < 8) {
		mac_num = 1;
	} else if (phy_port < 10) {
		mac_num = 2;
	} else {
		LOG_ERR("phy_port(%d) err, not in 0-9!!\n", phy_port);
		mac_num = -1;
		return mac_num;
	}

	LOG_DEBUG("mac_num: %d\n", mac_num);
	return mac_num;
}

s32 zxdh_lldp_enable_set(struct zxdh_en_device *en_dev, bool lldp_enable)
{
	union zxdh_msg *msg = NULL;
	s32 err = 0;
	struct zxdh_bar_extra_para para = { 0 };

	para.is_sync = true;
	para.retrycnt = BAR_MSG_RETRY_CNT_MAX;

	msg = kzalloc(sizeof(union zxdh_msg), GFP_KERNEL);
	if (!msg) {
		LOG_ERR("kzalloc(%lu, GFP_KERNEL) failed !", sizeof(union zxdh_msg));
		return -ENOMEM;
	}
	msg->payload.hdr_to_agt.op_code = AGENT_DEBUG_LLDP_ENABLE_SET;
	msg->payload.hdr_to_agt.port_id = en_dev->panel_id;

	if (en_dev->ops->is_bond(en_dev->parent))
		msg->payload.hdr_to_agt.port_id = en_dev->pannel_id;
	msg->payload.lldp_msg.lldp_enable = lldp_enable;

	err = en_dev->ops->msg_send_cmd(en_dev->parent, MODULE_DEBUG, msg, msg, &para);
	kfree(msg);
	return err;
}

static s32 zxdh_vf_dualtor_label_get(struct zxdh_en_device *en_dev, u32 *dual_tor)
{
	u64 dula_label_addr = 0;

	if (!en_dev) {
		LOG_ERR("en_dev is null.\n");
		return -1;
	}

	dula_label_addr =
		en_dev->ops->get_bar_virt_addr(en_dev->parent, 0) + ZXDH_DUALTOR_LABEL_OFFSET;
	*dual_tor = !!((ZXDH_BAR_DUALTOR_LABEL_ON == *(u32 *)dula_label_addr));
	return 0;
}

s32 zxdh_dual_tor_switch(struct zxdh_en_device *en_dev, bool state)
{
	int ret = 0;
	struct dpp_pf_info_t pf_info = { 0 };
	u64 dula_label_addr = 0;

	pf_info.slot = en_dev->slot_id;
	pf_info.vport = en_dev->vport;

	if (en_dev->ops->get_coredev_type(en_dev->parent) == DH_COREDEV_VF) { /* VF */
		LOG_ERR("vfs do not support dual switch.\n");
		return 0;
	}

	ret = dpp_pktrx_mcode_glb_cfg_write(&pf_info, ZXDH_NP_GLOBAL_PSN_ENABLE_BIT,
					    ZXDH_NP_GLOBAL_PSN_ENABLE_BIT, state);
	if (ret != 0) {
		LOG_ERR("switch dual tor to state: %u failed.\n", state);
		return -1;
	}

	dula_label_addr =
		en_dev->ops->get_bar_virt_addr(en_dev->parent, 0) + ZXDH_DUALTOR_LABEL_OFFSET;
	*(u32 *)dula_label_addr = state ? ZXDH_BAR_DUALTOR_LABEL_ON : 0;

	ret = dpp_l2d_psn_cfg_set(&pf_info, state);
	if (ret != 0) {
		LOG_ERR("dpp_l2d_psn_cfg_set failed.\n");
		return -1;
	}

	LOG_INFO("switch dual tor to state: %u success.\n", state);
	return 0;
}

s32 zxdh_dual_tor_label_get(struct zxdh_en_device *en_dev)
{
	int ret = 0;
	struct dpp_pf_info_t pf_info = { 0 };
	u32 global_value = 0;
	u32 psn_cfg = 0;
	u32 dula_tor = 0;

	if (en_dev->ops->get_coredev_type(en_dev->parent) == DH_COREDEV_VF) { /* VF */
		ret = zxdh_vf_dualtor_label_get(en_dev, &dula_tor);
		if (ret != 0)
			return -1;
		goto succ;
	}

	pf_info.slot = en_dev->slot_id;
	pf_info.vport = en_dev->vport;

	ret = dpp_l2d_psn_cfg_get(&pf_info, &psn_cfg);
	if (ret != 0) {
		LOG_ERR("dpp_l2d_psn_cfg_get failed.\n");
		return -1;
	}

	if (psn_cfg != 0)
		return psn_cfg;

	ret = dpp_glb_cfg_get_1(&pf_info, &global_value);
	if (ret != 0) {
		LOG_ERR("dpp_glb_cfg_get_1 failed.\n");
		return -1;
	}
	dula_tor = !!(global_value & ((u32)1 << ZXDH_NP_GLOBAL_PSN_ENABLE_BIT));
succ:

	return dula_tor;
}

s32 zxdh_sshd_enable_set(struct zxdh_en_device *en_dev, bool sshd_enable)
{
	union zxdh_msg *msg = NULL;
	s32 err = 0;
	struct zxdh_bar_extra_para para = { 0 };

	para.is_sync = true;
	para.retrycnt = BAR_MSG_RETRY_CNT_MAX;

	msg = kzalloc(sizeof(union zxdh_msg), GFP_KERNEL);
	if (!msg) {
		LOG_ERR("kzalloc(%lu, GFP_KERNEL) failed !", sizeof(union zxdh_msg));
		return -ENOMEM;
	}
	if (sshd_enable)
		msg->payload.hdr_to_agt.op_code = AGENT_SSHD_START;
	else
		msg->payload.hdr_to_agt.op_code = AGENT_SSHD_STOP;

	err = en_dev->ops->msg_send_cmd(en_dev->parent, MODULE_LOGIN_CTRL, msg, msg, &para);
	kfree(msg);
	return err;
}

s32 zxdh_lldp_enable_get(struct zxdh_en_device *en_dev, u32 *lldp_enable)
{
	s32 ret = 0;
	union zxdh_msg *msg = NULL;
	struct zxdh_bar_extra_para para = { 0 };

	para.is_sync = true;
	para.retrycnt = BAR_MSG_RETRY_CNT_MAX;

	msg = kzalloc(sizeof(union zxdh_msg), GFP_KERNEL);
	if (!msg) {
		LOG_ERR("kzalloc(%lu, GFP_KERNEL) failed !", sizeof(union zxdh_msg));
		return -ENOMEM;
	}
	msg->payload.hdr_to_agt.op_code = AGENT_DEBUG_LLDP_ENABLE_GET;
	msg->payload.hdr_to_agt.port_id = en_dev->panel_id;

	if (en_dev->ops->is_bond(en_dev->parent))
		msg->payload.hdr_to_agt.port_id = en_dev->pannel_id;

	ret = en_dev->ops->msg_send_cmd(en_dev->parent, MODULE_DEBUG, msg, msg, &para);
	if (ret != 0) {
		LOG_ERR("zxdh lldp enable get failed: %d\n", ret);
		kfree(msg);
		return ret;
	}

	*lldp_enable = (u32)(msg->reps.debug_lldp_msg.lldp_status);
	kfree(msg);
	return ret;
}

s32 zxdh_slot_info_send(struct zxdh_en_device *en_dev, u8 *slot_info)
{
	s32 ret = 0;
	union zxdh_msg *msg = NULL;
	struct zxdh_bar_extra_para para = { 0 };

	para.is_sync = true;
	para.retrycnt = BAR_MSG_RETRY_CNT_MAX;

	msg = kzalloc(sizeof(union zxdh_msg), GFP_KERNEL);
	if (!msg) {
		LOG_ERR("kzalloc(%lu, GFP_KERNEL) failed !", sizeof(union zxdh_msg));
		return -ENOMEM;
	}

	msg->payload.hdr_to_agt.op_code = AGENT_SLOT_INFO_SEND;
	msg->payload.debug_ip_send.slot_info = *slot_info;

	ret = en_dev->ops->msg_send_cmd(en_dev->parent, MODULE_LOGIN_CTRL, msg, msg, &para);
	if (ret != 0) {
		LOG_ERR("send slot info to riscv failed: %d\n", ret);
		kfree(msg);
		return ret;
	}
	kfree(msg);
	return ret;
}

int8_t zxdh_debug_ip_get(struct zxdh_en_device *en_dev, int8_t *ip)
{
	s32 ret = 0;
	u8 slot_info = 0;
	char ip_address[20] = { 0 };

	slot_info = (u8)((en_dev->slot_id) & 0xff);
	slot_info++;
	scnprintf(ip_address, sizeof(ip_address), "26.20.5.%d", slot_info);
	strscpy(ip, ip_address, sizeof(ip));

	ret = zxdh_slot_info_send(en_dev, &slot_info);
	if (ret != 0) {
		LOG_ERR("zxdh_slot_info_send failed: %d\n", ret);
		return ret;
	}

	LOG_DEBUG("DEBUG IP is: %s\n", ip_address);

	return ret;
}

s32 zxdh_spm_port_enable_cfg(struct zxdh_en_device *en_dev, u32 enable)
{
	s32 ret = 0;
	union zxdh_msg *msg = NULL;
	struct zxdh_bar_extra_para para = { 0 };

	para.is_sync = true;
	para.retrycnt = BAR_MSG_RETRY_CNT_MAX;

	if (!zxdh_en_is_panel_port(en_dev))
		return ret;

	msg = kzalloc(sizeof(union zxdh_msg), GFP_KERNEL);
	if (!msg) {
		LOG_ERR("kzalloc(%lu, GFP_KERNEL) failed !", sizeof(union zxdh_msg));
		return -ENOMEM;
	}
	msg->payload.hdr_to_agt.op_code = AGENT_SPM_PORT_ENABLE_SET;
	msg->payload.hdr_to_agt.phyport = en_dev->phy_port;
	msg->payload.spm_port_enable_set.enable = enable;

	ret = en_dev->ops->msg_send_cmd(en_dev->parent, MODULE_MAC, msg, msg, &para);
	if (ret != 0)
		LOG_ERR("set spm port enable failed: %d\n", ret);

	kfree(msg);
	return ret;
}

#define FLASH_OPEN_FW
s32 zxdh_en_firmware_version_get(struct zxdh_en_device *en_dev, u8 *fw_version, u8 *fw_version_len)
{
#ifdef FLASH_OPEN_FW
	s32 ret = 0;
	union zxdh_msg *msg = NULL;
	struct zxdh_bar_extra_para para = { 0 };

	para.is_sync = true;
	para.retrycnt = BAR_MSG_RETRY_CNT_MAX;

	msg = kzalloc(sizeof(union zxdh_msg), GFP_KERNEL);
	if (!msg) {
		LOG_ERR("kzalloc(%lu, GFP_KERNEL) failed !", sizeof(union zxdh_msg));
		return -ENOMEM;
	}
	msg->payload.hdr_to_agt.op_code = AGENT_FLASH_FIR_VERSION_GET;

	ret = en_dev->ops->msg_send_cmd(en_dev->parent, MODULE_FLASH, msg, msg, &para);
	if (ret != 0) {
		LOG_ERR("en_dev->ops->msg_send_cmd failed: %d\n", ret);
		goto free_msg;
	}

	memcpy(fw_version, msg->reps.flash_msg.firmware_version, FW_VERSION_LEN);
	*fw_version_len = FW_VERSION_LEN;
#else
	u8 fw_version_test[] = "V2.24.10.01B4";

	memcpy(fw_version, fw_version_test, sizeof(fw_version_test));
	*fw_version_len = sizeof(fw_version_test);
#endif

free_msg:
	kfree(msg);
	return ret;
}

void do_get_np_ext_stats(struct zxdh_en_device *en_dev, struct zxdh_en_vport_stats *vport_stats)
{
	struct zxdh_np_ext_stats *ext_stats = NULL;

	if (!en_dev->ops->if_suport_np_ext_stats(en_dev->parent))
		return;

	ext_stats = en_dev->ops->get_np_ext_stats(en_dev->parent, en_dev->phy_port);

	vport_stats->np_stats.rx_vport_idma_drop_packets = ext_stats->rx_vport2np_packets;
}

s32 do_get_vport_stats(struct zxdh_en_device *en_dev, u8 np_mode,
		       struct zxdh_en_vport_stats *vport_stats, bool is_init_get)
{
	union zxdh_msg *msg = NULL;
	u32 vf_id = GET_VFID(en_dev->vport);
	u32 pf_id_offst = 0;
	s32 err = 0;
	struct dpp_pf_info_t pf_info = { 0 };
	struct zxdh_bar_extra_para para = { 0 };

	para.is_sync = true;
	para.retrycnt = 0;

	pf_info.slot = en_dev->slot_id;
	pf_info.vport = en_dev->vport;

	msg = kzalloc(sizeof(union zxdh_msg), GFP_KERNEL);
	if (!msg) {
		LOG_ERR("kzalloc(%lu, GFP_KERNEL) failed !", sizeof(union zxdh_msg));
		return -ENOMEM;
	}

	msg->payload.hdr_to_agt.op_code = AGENT_VQM_DEVICE_STATS_GET;
	msg->payload.hdr_to_agt.vf_id = vf_id;
	msg->payload.hdr_to_agt.pcie_id = en_dev->pcie_id;
	err = en_dev->ops->msg_send_cmd(en_dev->parent, MODULE_VQM, msg, msg, &para);
	if (err != 0) {
		LOG_ERR("zxdh_vport_stats_get failed, err: %d\n", err);
		goto free_msg;
	}
	vport_stats->vqm_stats.rx_vport_packets = msg->reps.stats_msg.rx_total;
	vport_stats->vqm_stats.tx_vport_packets = msg->reps.stats_msg.tx_total;
	vport_stats->vqm_stats.rx_vport_bytes = msg->reps.stats_msg.rx_total_bytes;
	vport_stats->vqm_stats.tx_vport_bytes = msg->reps.stats_msg.tx_total_bytes;
	vport_stats->vqm_stats.rx_vport_dropped = msg->reps.stats_msg.rx_drop;

	memset(msg, 0, sizeof(union zxdh_msg));
	msg->payload.hdr_to_agt.op_code = AGENT_DTP_STATS_GET;
	msg->payload.hdr_to_agt.vf_id = vf_id;
	msg->payload.hdr_to_agt.pcie_id = en_dev->pcie_id;
	err = en_dev->ops->msg_send_cmd(en_dev->parent, MODULE_DTP, msg, msg, &para);
	if (err != 0) {
		LOG_ERR("zxdh_dtp_stats_get failed, err: %d\n", err);
		goto free_msg;
	}
	vport_stats->dtp_stats.rx_lro_packets = msg->reps.stats_msg.rx_total;
	vport_stats->dtp_stats.rx_udp_csum_fail_packets = msg->reps.stats_msg.tx_total;
	vport_stats->dtp_stats.tx_udp_csum_fail_packets = msg->reps.stats_msg.rx_total_bytes;
	vport_stats->dtp_stats.rx_tcp_csum_fail_packets = msg->reps.stats_msg.tx_total_bytes;
	vport_stats->dtp_stats.tx_tcp_csum_fail_packets = msg->reps.stats_msg.rx_good_bytes;
	vport_stats->dtp_stats.rx_ipv4_csum_fail_packets = msg->reps.stats_msg.tx_good_bytes;
	vport_stats->dtp_stats.tx_ipv4_csum_fail_packets = msg->reps.stats_msg.rx_error;

	memset(msg, 0, sizeof(union zxdh_msg));
	if (en_dev->ops->get_coredev_type(en_dev->parent) == DH_COREDEV_VF) {
		msg->payload.hdr.op_code = ZXDH_GET_NP_STATS;
		msg->payload.hdr.vport = en_dev->vport;
		msg->payload.hdr.vf_id = vf_id;
		msg->payload.hdr.pcie_id = en_dev->pcie_id;
		msg->payload.np_stats_get_msg.clear_mode = np_mode;
		msg->payload.np_stats_get_msg.is_init_get = is_init_get;
		err = en_dev->ops->msg_send_cmd(en_dev->parent, MODULE_VF_BAR_MSG_TO_PF, msg, msg,
						&para);
		if (err != 0) {
			LOG_ERR("zxdh_send_command_to_pf failed: %d\n", err);
			goto free_msg;
		}
		memcpy(&(vport_stats->np_stats), &(msg->reps.np_stats_msg),
		       sizeof(vport_stats->np_stats));
	} else {
		dpp_stat_port_uc_packet_rx_cnt_get(
			&pf_info, vf_id, np_mode, &(vport_stats->np_stats.rx_vport_unicast_bytes),
			&(vport_stats->np_stats.rx_vport_unicast_packets));
		dpp_stat_port_uc_packet_tx_cnt_get(
			&pf_info, vf_id, np_mode, &(vport_stats->np_stats.tx_vport_unicast_bytes),
			&(vport_stats->np_stats.tx_vport_unicast_packets));
		dpp_stat_port_mc_packet_rx_cnt_get(
			&pf_info, vf_id, np_mode, &(vport_stats->np_stats.rx_vport_multicast_bytes),
			&(vport_stats->np_stats.rx_vport_multicast_packets));
		dpp_stat_port_mc_packet_tx_cnt_get(
			&pf_info, vf_id, np_mode, &(vport_stats->np_stats.tx_vport_multicast_bytes),
			&(vport_stats->np_stats.tx_vport_multicast_packets));
		dpp_stat_port_bc_packet_rx_cnt_get(
			&pf_info, vf_id, np_mode, &(vport_stats->np_stats.rx_vport_broadcast_bytes),
			&(vport_stats->np_stats.rx_vport_broadcast_packets));
		dpp_stat_port_bc_packet_tx_cnt_get(
			&pf_info, vf_id, np_mode, &(vport_stats->np_stats.tx_vport_broadcast_bytes),
			&(vport_stats->np_stats.tx_vport_broadcast_packets));
		dpp_stat_MTU_packet_msg_rx_cnt_get(
			&pf_info, vf_id, np_mode, &(vport_stats->np_stats.rx_vport_mtu_drop_bytes),
			&(vport_stats->np_stats.rx_vport_mtu_drop_packets));
		dpp_stat_MTU_packet_msg_tx_cnt_get(
			&pf_info, vf_id, np_mode, &(vport_stats->np_stats.tx_vport_mtu_drop_bytes),
			&(vport_stats->np_stats.tx_vport_mtu_drop_packets));
		dpp_stat_plcr_packet_drop_rx_cnt_get(
			&pf_info, vf_id, np_mode, &(vport_stats->np_stats.rx_vport_plcr_drop_bytes),
			&(vport_stats->np_stats.rx_vport_plcr_drop_packets));
		dpp_stat_plcr_packet_drop_tx_cnt_get(
			&pf_info, vf_id, np_mode, &(vport_stats->np_stats.tx_vport_plcr_drop_bytes),
			&(vport_stats->np_stats.tx_vport_plcr_drop_packets));
		pf_id_offst = DH_AUX_PF_ID_OFFSET(en_dev->vport);
		dpp_stat_spoof_packet_drop_cnt_get(&pf_info, pf_id_offst, np_mode,
						   &(vport_stats->np_stats.tx_vport_ssvpc_packets));
		do_get_np_ext_stats(en_dev, vport_stats);
	}

free_msg:
	kfree(msg);
	return err;
}

s32 zxdh_en_vport_pre_stats_get(struct zxdh_en_device *en_dev)
{
	s32 err = 0;
	struct zxdh_en_vport_stats *vport_stats = &en_dev->pre_stats;

	err = do_get_vport_stats(en_dev, NP_GET_PKT_CNT, vport_stats, TRUE);
	if (err != 0)
		LOG_ERR("zxdh_en_vport_pre_stat_get failed\n");
	en_dev->last_tx_vport_ssvpc_packets = en_dev->pre_stats.np_stats.tx_vport_ssvpc_packets;
	return err;
}

s32 zxdh_en_udp_pkt_stats_get(struct zxdh_en_device *en_dev)
{
	union zxdh_msg *msg = NULL;
	u32 vf_id = GET_VFID(en_dev->vport);
	struct dpp_pf_info_t pf_info = { 0 };
	s32 err = 0;
	struct zxdh_bar_extra_para para = { 0 };

	para.is_sync = true;
	para.retrycnt = BAR_MSG_RETRY_CNT_MAX;

	pf_info.slot = en_dev->slot_id;
	pf_info.vport = en_dev->vport;

	if (!zxdh_en_is_panel_port(en_dev))
		return 0;

	if (en_dev->ops->get_coredev_type(en_dev->parent) != DH_COREDEV_PF) {
		msg = kzalloc(sizeof(union zxdh_msg), GFP_KERNEL);
		if (!msg) {
			LOG_ERR("kzalloc(%lu, GFP_KERNEL) failed !", sizeof(union zxdh_msg));
			return -ENOMEM;
		}

		msg->payload.hdr.op_code = ZXDH_VF_GET_UDP_STATS;
		msg->payload.hdr.vport = en_dev->vport;
		msg->payload.hdr.vf_id = vf_id;
		msg->payload.hdr.pcie_id = en_dev->pcie_id;
		err = en_dev->ops->msg_send_cmd(en_dev->parent, MODULE_VF_BAR_MSG_TO_PF, msg, msg,
						&para);
		if (err != 0) {
			LOG_ERR("zxdh_send_command_to_pf failed: %d\n", err);
			kfree(msg);
			return err;
		}
		zte_memcpy_s(&en_dev->hw_stats.udp_stats, &msg->reps.udp_phy_stats_msg,
			     sizeof(struct udp_phy_stats));
		kfree(msg);
		return 0;
	}

	err = dpp_stat_asn_phyport_rx_pkt_cnt_get(&pf_info, en_dev->phy_port,
						  STAT_RD_CLR_MODE_UNCLR,
						  &en_dev->hw_stats.udp_stats.rx_arn_phy);
	if (err != 0) {
		LOG_ERR("dpp_stat_asn_phyport_rx_pkt_cnt_get failed: %d\n", err);
		return -1;
	}

	err = dpp_stat_psn_phyport_tx_pkt_cnt_get(&pf_info, en_dev->phy_port,
						  STAT_RD_CLR_MODE_UNCLR,
						  &en_dev->hw_stats.udp_stats.tx_psn_phy);
	if (err != 0) {
		LOG_ERR("dpp_stat_psn_phyport_tx_pkt_cnt_get failed: %d\n", err);
		return -1;
	}

	err = dpp_stat_psn_phyport_rx_pkt_cnt_get(&pf_info, en_dev->phy_port,
						  STAT_RD_CLR_MODE_UNCLR,
						  &en_dev->hw_stats.udp_stats.rx_psn_phy);
	if (err != 0) {
		LOG_ERR("dpp_stat_psn_phyport_rx_pkt_cnt_get failed: %d\n", err);
		return -1;
	}

	err = dpp_stat_psn_ack_phyport_tx_pkt_cnt_get(&pf_info, en_dev->phy_port,
						      STAT_RD_CLR_MODE_UNCLR,
						      &en_dev->hw_stats.udp_stats.tx_psn_ack_phy);
	if (err != 0) {
		LOG_ERR("dpp_stat_psn_ack_phyport_tx_pkt_cnt_get failed: %d\n", err);
		return -1;
	}

	err = dpp_stat_psn_ack_phyport_rx_pkt_cnt_get(&pf_info, en_dev->phy_port,
						      STAT_RD_CLR_MODE_UNCLR,
						      &en_dev->hw_stats.udp_stats.rx_psn_ack_phy);
	if (err != 0) {
		LOG_ERR("dpp_stat_psn_ack_phyport_rx_pkt_cnt_get failed: %d\n", err);
		return -1;
	}

	return err;
}

s32 zxdh_vport_stats_get(struct zxdh_en_device *en_dev)
{
	s32 err = 0;
	struct zxdh_en_vport_stats *vport_stats = &en_dev->hw_stats.vport_stats;

	if (en_dev->device_state == ZXDH_DEVICE_STATE_INTERNAL_ERROR)
		return -ENXIO;
	err = do_get_vport_stats(en_dev, NP_GET_PKT_CNT, vport_stats, FALSE);
	if (err != 0) {
		LOG_ERR("zxdh vport stats get failed\n");
		return err;
	}

	vport_stats->vqm_stats.rx_vport_packets -= en_dev->pre_stats.vqm_stats.rx_vport_packets;
	vport_stats->vqm_stats.tx_vport_packets -= en_dev->pre_stats.vqm_stats.tx_vport_packets;
	vport_stats->vqm_stats.rx_vport_bytes -= en_dev->pre_stats.vqm_stats.rx_vport_bytes;
	vport_stats->vqm_stats.tx_vport_bytes -= en_dev->pre_stats.vqm_stats.tx_vport_bytes;
	vport_stats->vqm_stats.rx_vport_dropped -= en_dev->pre_stats.vqm_stats.rx_vport_dropped;

	vport_stats->dtp_stats.rx_lro_packets -= en_dev->pre_stats.dtp_stats.rx_lro_packets;
	vport_stats->dtp_stats.rx_udp_csum_fail_packets -=
		en_dev->pre_stats.dtp_stats.rx_udp_csum_fail_packets;
	vport_stats->dtp_stats.tx_udp_csum_fail_packets -=
		en_dev->pre_stats.dtp_stats.tx_udp_csum_fail_packets;
	vport_stats->dtp_stats.rx_tcp_csum_fail_packets -=
		en_dev->pre_stats.dtp_stats.rx_tcp_csum_fail_packets;
	vport_stats->dtp_stats.tx_tcp_csum_fail_packets -=
		en_dev->pre_stats.dtp_stats.tx_tcp_csum_fail_packets;
	vport_stats->dtp_stats.rx_ipv4_csum_fail_packets -=
		en_dev->pre_stats.dtp_stats.rx_ipv4_csum_fail_packets;
	vport_stats->dtp_stats.tx_ipv4_csum_fail_packets -=
		en_dev->pre_stats.dtp_stats.tx_ipv4_csum_fail_packets;

	vport_stats->np_stats.rx_vport_unicast_packets -=
		en_dev->pre_stats.np_stats.rx_vport_unicast_packets;
	vport_stats->np_stats.tx_vport_unicast_packets -=
		en_dev->pre_stats.np_stats.tx_vport_unicast_packets;
	vport_stats->np_stats.rx_vport_unicast_bytes -=
		en_dev->pre_stats.np_stats.rx_vport_unicast_bytes;
	vport_stats->np_stats.tx_vport_unicast_bytes -=
		en_dev->pre_stats.np_stats.tx_vport_unicast_bytes;
	vport_stats->np_stats.rx_vport_multicast_packets -=
		en_dev->pre_stats.np_stats.rx_vport_multicast_packets;
	vport_stats->np_stats.tx_vport_multicast_packets -=
		en_dev->pre_stats.np_stats.tx_vport_multicast_packets;
	vport_stats->np_stats.rx_vport_multicast_bytes -=
		en_dev->pre_stats.np_stats.rx_vport_multicast_bytes;
	vport_stats->np_stats.tx_vport_multicast_bytes -=
		en_dev->pre_stats.np_stats.tx_vport_multicast_bytes;
	vport_stats->np_stats.rx_vport_broadcast_packets -=
		en_dev->pre_stats.np_stats.rx_vport_broadcast_packets;
	vport_stats->np_stats.tx_vport_broadcast_packets -=
		en_dev->pre_stats.np_stats.tx_vport_broadcast_packets;
	vport_stats->np_stats.rx_vport_broadcast_bytes -=
		en_dev->pre_stats.np_stats.rx_vport_broadcast_bytes;
	vport_stats->np_stats.tx_vport_broadcast_bytes -=
		en_dev->pre_stats.np_stats.tx_vport_broadcast_bytes;
	vport_stats->np_stats.rx_vport_mtu_drop_packets -=
		en_dev->pre_stats.np_stats.rx_vport_mtu_drop_packets;
	vport_stats->np_stats.tx_vport_mtu_drop_packets -=
		en_dev->pre_stats.np_stats.tx_vport_mtu_drop_packets;
	vport_stats->np_stats.rx_vport_mtu_drop_bytes -=
		en_dev->pre_stats.np_stats.rx_vport_mtu_drop_bytes;
	vport_stats->np_stats.tx_vport_mtu_drop_bytes -=
		en_dev->pre_stats.np_stats.tx_vport_mtu_drop_bytes;
	vport_stats->np_stats.rx_vport_plcr_drop_packets -=
		en_dev->pre_stats.np_stats.rx_vport_plcr_drop_packets;
	vport_stats->np_stats.tx_vport_plcr_drop_packets -=
		en_dev->pre_stats.np_stats.tx_vport_plcr_drop_packets;
	vport_stats->np_stats.rx_vport_plcr_drop_bytes -=
		en_dev->pre_stats.np_stats.rx_vport_plcr_drop_bytes;
	vport_stats->np_stats.tx_vport_plcr_drop_bytes -=
		en_dev->pre_stats.np_stats.tx_vport_plcr_drop_bytes;
	vport_stats->np_stats.tx_vport_ssvpc_packets -=
		en_dev->pre_stats.np_stats.tx_vport_ssvpc_packets;
	vport_stats->np_stats.rx_vport_idma_drop_packets -=
		en_dev->pre_stats.np_stats.rx_vport_idma_drop_packets;
	return err;
}

static inline bool is_zf_dev(struct zxdh_en_device *en_dev)
{
	/* bit[12:14]-ep_id(0~4) */
	if ((en_dev->pcie_id & BIT(14)) != 0)
		return true;
	else
		return false;
}

bool zxdh_en_is_panel_port(struct zxdh_en_device *en_dev)
{
	if ((en_dev->ops->get_dev_type(en_dev->parent) == ZXDH_DEV_UPF) ||
	    (en_dev->ops->get_dev_type(en_dev->parent) == ZXDH_DEV_NE0) ||
	    (en_dev->ops->get_dev_type(en_dev->parent) == ZXDH_DEV_NE1)) {
		return false;
	}

	return true;
}

s32 zxdh_mac_stats_get(struct zxdh_en_device *en_dev)
{
	u64 virt_addr = 0;
	u64 stats_addr = 0;
	u64 bytes_addr = 0;
	struct zxdh_en_spm_stats spm_stats;
	struct zxdh_en_spm_bytes spm_bytes;
	struct zxdh_en_phy_stats *phy_stats = &en_dev->hw_stats.phy_stats;

	if ((en_dev->ops->get_coredev_type(en_dev->parent) == DH_COREDEV_VF) ||
	    (en_dev->phy_port > ZXDH_PHY_PORT_MAX))
		return 0;

	switch (en_dev->curr_speed_modes) {
	case BIT(SPM_SPEED_1X_1G):
	case BIT(SPM_SPEED_1X_10G):
	case BIT(SPM_SPEED_1X_25G):
	case BIT(SPM_SPEED_1X_50G): {
		stats_addr = ZXDH_SPM_STATS_OFFSET +
			     (en_dev->phy_port % 4) * sizeof(struct zxdh_en_spm_stats);
		bytes_addr = ZXDH_SPM_BYTES_OFFSET +
			     (en_dev->phy_port % 4) * sizeof(struct zxdh_en_spm_bytes);
		break;
	}
	case BIT(SPM_SPEED_2X_100G): {
		stats_addr = ZXDH_SPM_STATS_OFFSET +
			     (4 + (en_dev->phy_port % 4) / 2) * sizeof(struct zxdh_en_spm_stats);
		bytes_addr = ZXDH_SPM_BYTES_OFFSET +
			     (4 + (en_dev->phy_port % 4) / 2) * sizeof(struct zxdh_en_spm_bytes);
		break;
	}
	case BIT(SPM_SPEED_4X_40G):
	case BIT(SPM_SPEED_4X_100G):
	case BIT(SPM_SPEED_4X_200G): {
		stats_addr = ZXDH_SPM_STATS_OFFSET + 4 * sizeof(struct zxdh_en_spm_stats);
		bytes_addr = ZXDH_SPM_BYTES_OFFSET + 4 * sizeof(struct zxdh_en_spm_bytes);
		break;
	}
	default: {
		return 0;
	}
	}

	if (is_zf_dev(en_dev)) {
		stats_addr = TO_ZF_ADDR(stats_addr);
		bytes_addr = TO_ZF_ADDR(bytes_addr);
	}

	virt_addr = en_dev->ops->get_bar_virt_addr(en_dev->parent, 0);
	memcpy(&spm_stats, (void *)(virt_addr + stats_addr), sizeof(struct zxdh_en_spm_stats));
	memcpy(&spm_bytes, (void *)(virt_addr + bytes_addr), sizeof(struct zxdh_en_spm_bytes));

	if ((spm_stats.rx_error == UINT64_MAX) || (spm_stats.tx_error == UINT64_MAX))
		return 0;

	phy_stats->rx_packets_phy = spm_stats.rx_total;
	phy_stats->tx_packets_phy = spm_stats.tx_total;
	phy_stats->rx_bytes_phy = spm_bytes.rx_total_bytes;
	phy_stats->tx_bytes_phy = spm_bytes.tx_total_bytes;
	phy_stats->rx_error_phy = spm_stats.rx_error;
	phy_stats->tx_error_phy = spm_stats.tx_error;
	phy_stats->rx_drop_phy = spm_stats.rx_drop;
	phy_stats->tx_drop_phy = spm_stats.tx_drop;
	phy_stats->rx_good_bytes_phy = spm_bytes.rx_good_bytes;
	phy_stats->tx_good_bytes_phy = spm_bytes.tx_good_bytes;
	phy_stats->rx_unicast_phy = spm_stats.rx_unicast;
	phy_stats->tx_unicast_phy = spm_stats.tx_unicast;
	phy_stats->rx_multicast_phy = spm_stats.rx_multicast;
	phy_stats->tx_multicast_phy = spm_stats.tx_multicast;
	phy_stats->rx_broadcast_phy = spm_stats.rx_broadcast;
	phy_stats->tx_broadcast_phy = spm_stats.tx_broadcast;
	phy_stats->rx_under64_drop = spm_stats.rx_undersize;
	phy_stats->rx_undersize_phy = spm_stats.rx_undersize;
	phy_stats->rx_size_64_phy = spm_stats.rx_size_64;
	phy_stats->rx_size_65_127 = spm_stats.rx_size_65_127;
	phy_stats->rx_size_128_255 = spm_stats.rx_size_128_255;
	phy_stats->rx_size_256_511 = spm_stats.rx_size_256_511;
	phy_stats->rx_size_512_1023 = spm_stats.rx_size_512_1023;
	phy_stats->rx_size_1024_1518 = spm_stats.rx_size_1024_1518;
	phy_stats->rx_size_1519_mru = spm_stats.rx_size_1519_mru;
	phy_stats->rx_oversize_phy = spm_stats.rx_oversize;
	phy_stats->tx_undersize_phy = spm_stats.tx_undersize;
	phy_stats->tx_size_64_phy = spm_stats.tx_size_64;
	phy_stats->tx_size_65_127 = spm_stats.tx_size_65_127;
	phy_stats->tx_size_128_255 = spm_stats.tx_size_128_255;
	phy_stats->tx_size_256_511 = spm_stats.tx_size_256_511;
	phy_stats->tx_size_512_1023 = spm_stats.tx_size_512_1023;
	phy_stats->tx_size_1024_1518 = spm_stats.tx_size_1024_1518;
	phy_stats->tx_size_1519_mtu = spm_stats.tx_size_1519_mtu;
	phy_stats->tx_oversize_phy = spm_stats.tx_oversize;
	phy_stats->rx_pause_phy = spm_stats.rx_pause;
	phy_stats->tx_pause_phy = spm_stats.tx_pause;
	phy_stats->rx_crc_errors = spm_stats.rx_fcs_error;
	phy_stats->tx_crc_errors = spm_stats.tx_fcs_error;
	phy_stats->rx_mac_control_phy = spm_stats.rx_control;
	phy_stats->tx_mac_control_phy = spm_stats.tx_control;
	phy_stats->rx_fragment_phy = spm_stats.rx_fragment;
	phy_stats->tx_fragment_phy = spm_stats.tx_fragment;
	phy_stats->rx_jabber_phy = spm_stats.rx_jabber;
	phy_stats->tx_jabber_phy = spm_stats.tx_jabber;
	phy_stats->rx_vlan_phy = spm_stats.rx_vlan;
	phy_stats->tx_vlan_phy = spm_stats.tx_vlan;
	phy_stats->rx_eee_phy = spm_stats.rx_eee;
	phy_stats->tx_eee_phy = spm_stats.tx_eee;

	return 0;
}

s32 zxdh_mac_stats_clear(struct zxdh_en_device *en_dev)
{
	union zxdh_msg *msg = NULL;
	s32 err = 0;
	struct zxdh_bar_extra_para para = { 0 };

	para.is_sync = true;
	para.retrycnt = BAR_MSG_RETRY_CNT_MAX;

	if (!zxdh_en_is_panel_port(en_dev))
		return err;

	msg = kzalloc(sizeof(union zxdh_msg), GFP_KERNEL);
	if (unlikely(!msg)) {
		LOG_ERR("failed to kzalloc\n");
		return -ENOMEM;
	}

	msg->payload.hdr_to_agt.op_code = AGENT_MAC_STATS_CLEAR;
	msg->payload.hdr_to_agt.phyport = en_dev->phy_port;
	err = en_dev->ops->msg_send_cmd(en_dev->parent, MODULE_MAC, msg, msg, &para);
	if (err != 0) {
		LOG_ERR("zxdh mac stats clear failed, err: %d\n", err);
		kfree(msg);
		return err;
	}
	kfree(msg);
	return err;
}

s32 zxdh_en_phyport_init(struct zxdh_en_device *en_dev)
{
	union zxdh_msg *msg = NULL;
	s32 err = 0;
	struct link_info_struct link_info_val = { 0 };
	struct zxdh_bar_extra_para para = { 0 };

	para.is_sync = true;
	para.retrycnt = BAR_MSG_RETRY_CNT_MAX;

	msg = kzalloc(sizeof(union zxdh_msg), GFP_KERNEL);
	if (unlikely(!msg)) {
		LOG_ERR("failed to kzalloc\n");
		return -ENOMEM;
	}

	msg->payload.hdr_to_agt.op_code = AGENT_MAC_PHYPORT_INIT;
	msg->payload.hdr_to_agt.phyport = en_dev->phy_port;
	if (en_dev->ops->is_upf(en_dev->parent)) {
		msg->payload.hdr_to_agt.phyport = 0;
		msg->payload.hdr_to_agt.is_upf = 1;
		en_dev->link_up = FALSE;
		en_dev->speed = SPEED_UNKNOWN;
		en_dev->ops->set_pf_link_up(en_dev->parent, en_dev->link_up);
		netif_carrier_off(en_dev->netdev);
		LOG_INFO("upf link down init\n");
		kfree(msg);
		return err;
	} else if ((en_dev->ops->get_dev_type(en_dev->parent) == ZXDH_DEV_NE0) ||
		   (en_dev->ops->get_dev_type(en_dev->parent) == ZXDH_DEV_NE1)) {
		msg->payload.hdr_to_agt.phyport = 0;
		msg->payload.hdr_to_agt.is_upf = 1;

		en_dev->link_up = true;
		en_dev->speed = SPEED_100000;
		en_dev->ops->set_pf_link_up(en_dev->parent, en_dev->link_up);
		netif_carrier_on(en_dev->netdev);
	}

	err = en_dev->ops->msg_send_cmd(en_dev->parent, MODULE_MAC, msg, msg, &para);
	if (err != 0) {
		LOG_ERR("zxdh_send_command_to_riscv_mac failed, err: %d\n", err);
		kfree(msg);
		return err;
	}

	en_dev->supported_speed_modes = msg->reps.mac_set_msg.speed_modes;
	en_dev->advertising_speed_modes = msg->reps.mac_set_msg.speed_modes;

	link_info_val.speed = en_dev->speed;
	link_info_val.autoneg_enable = en_dev->autoneg_enable;
	link_info_val.supported_speed_modes = en_dev->supported_speed_modes;
	link_info_val.advertising_speed_modes = en_dev->advertising_speed_modes;
	link_info_val.duplex = en_dev->duplex;
	en_dev->ops->update_pf_link_info(en_dev->parent, &link_info_val);

	kfree(msg);
	return err;
}

s32 zxdh_en_autoneg_set(struct zxdh_en_device *en_dev, u8 enable, u32 speed_modes)
{
	s32 err = 0;
	union zxdh_msg *msg = NULL;
	struct zxdh_bar_extra_para para = { 0 };

	para.is_sync = true;
	para.retrycnt = BAR_MSG_RETRY_CNT_MAX;

	if (!zxdh_en_is_panel_port(en_dev))
		return err;

	msg = kzalloc(sizeof(union zxdh_msg), GFP_KERNEL);
	if (unlikely(!msg)) {
		LOG_ERR("failed to kzalloc\n");
		return -ENOMEM;
	}

	msg->payload.hdr_to_agt.op_code = AGENT_MAC_AUTONEG_SET;
	msg->payload.hdr_to_agt.phyport = en_dev->phy_port;
	msg->payload.mac_set_msg.autoneg = enable;
	msg->payload.mac_set_msg.speed_modes = speed_modes;

	err = en_dev->ops->msg_send_cmd(en_dev->parent, MODULE_MAC, msg, msg, &para);
	if (err != 0)
		LOG_ERR("zxdh_send_command_to_riscv_mac failed, err: %d\n", err);

	kfree(msg);
	return err;
}

s32 zxdh_en_fec_mode_set(struct zxdh_en_device *en_dev, u32 fec_cfg)
{
	union zxdh_msg *msg = NULL;
	s32 ret = 0;
	struct zxdh_bar_extra_para para = { 0 };

	para.is_sync = true;
	para.retrycnt = BAR_MSG_RETRY_CNT_MAX;

	if (!zxdh_en_is_panel_port(en_dev))
		return ret;

	msg = kzalloc(sizeof(union zxdh_msg), GFP_KERNEL);
	if (!msg) {
		LOG_ERR("kzalloc(%lu, GFP_KERNEL) failed !", sizeof(union zxdh_msg));
		return -ENOMEM;
	}

	msg->payload.hdr_to_agt.op_code = AGENT_MAC_FEC_MODE_SET;
	msg->payload.hdr_to_agt.phyport = en_dev->phy_port;
	msg->payload.mac_fec_mode_msg.fec_cfg = fec_cfg;

	ret = en_dev->ops->msg_send_cmd(en_dev->parent, MODULE_MAC, msg, msg, &para);
	kfree(msg);
	return ret;
}

s32 zxdh_en_fec_mode_get(struct zxdh_en_device *en_dev, u32 *fec_cap, u32 *fec_cfg, u32 *fec_active)
{
	union zxdh_msg *msg = NULL;
	s32 err = 0;
	struct zxdh_bar_extra_para para = { 0 };

	para.is_sync = true;
	para.retrycnt = 0;

	if (!zxdh_en_is_panel_port(en_dev))
		return err;

	msg = kzalloc(sizeof(union zxdh_msg), GFP_KERNEL);
	if (!msg) {
		LOG_ERR("kzalloc(%lu, GFP_KERNEL) failed !", sizeof(union zxdh_msg));
		return -ENOMEM;
	}

	msg->payload.hdr_to_agt.op_code = AGENT_MAC_FEC_MODE_GET;
	msg->payload.hdr_to_agt.phyport = en_dev->phy_port;

	err = en_dev->ops->msg_send_cmd(en_dev->parent, MODULE_MAC, msg, msg, &para);
	if (err != 0) {
		LOG_ERR("zxdh_send_command_to_riscv_mac failed, err: %d\n", err);
		kfree(msg);
		return err;
	}

	if (fec_cap)
		*fec_cap = msg->reps.mac_fec_mode_msg.fec_cap;
	if (fec_cfg)
		*fec_cfg = msg->reps.mac_fec_mode_msg.fec_cfg;
	if (fec_active)
		*fec_active = msg->reps.mac_fec_mode_msg.fec_link;

	kfree(msg);
	return err;
}

s32 zxdh_en_fc_mode_set(struct zxdh_en_device *en_dev, u32 fc_mode)
{
	union zxdh_msg *msg = NULL;
	s32 ret = 0;
	struct zxdh_bar_extra_para para = { 0 };

	para.is_sync = true;
	para.retrycnt = BAR_MSG_RETRY_CNT_MAX;

	if (!zxdh_en_is_panel_port(en_dev))
		return ret;

	msg = kzalloc(sizeof(union zxdh_msg), GFP_KERNEL);
	if (!msg) {
		LOG_ERR("kzalloc(%lu, GFP_KERNEL) failed !", sizeof(union zxdh_msg));
		return -ENOMEM;
	}

	msg->payload.hdr_to_agt.op_code = AGENT_MAC_FC_MODE_SET;
	msg->payload.hdr_to_agt.phyport = en_dev->phy_port;
	msg->payload.mac_fc_mode_msg.fc_mode = fc_mode;

	ret = en_dev->ops->msg_send_cmd(en_dev->parent, MODULE_MAC, msg, msg, &para);
	kfree(msg);
	return ret;
}

s32 zxdh_en_fc_mode_get(struct zxdh_en_device *en_dev, u32 *fc_mode)
{
	union zxdh_msg *msg = NULL;
	s32 err = 0;
	struct zxdh_bar_extra_para para = { 0 };

	para.is_sync = true;
	para.retrycnt = BAR_MSG_RETRY_CNT_MAX;

	if (!zxdh_en_is_panel_port(en_dev))
		return err;

	msg = kzalloc(sizeof(union zxdh_msg), GFP_KERNEL);
	if (!msg) {
		LOG_ERR("kzalloc(%lu, GFP_KERNEL) failed !", sizeof(union zxdh_msg));
		return -ENOMEM;
	}

	msg->payload.hdr_to_agt.op_code = AGENT_MAC_FC_MODE_GET;
	msg->payload.hdr_to_agt.phyport = en_dev->phy_port;

	err = en_dev->ops->msg_send_cmd(en_dev->parent, MODULE_MAC, msg, msg, &para);
	if (err != 0) {
		LOG_ERR("zxdh_send_command_to_riscv_mac failed, err: %d\n", err);
		kfree(msg);
		return err;
	}

	if (fc_mode)
		*fc_mode = msg->reps.mac_fc_mode_msg.fc_mode;

	kfree(msg);
	return err;
}

u32 zxdh_en_module_eeprom_read(struct zxdh_en_device *en_dev,
			       struct zxdh_en_module_eeprom_param *query, u8 *data)
{
	union zxdh_msg *msg = NULL;
	u8 length = 0;
	s32 err = 0;
	struct zxdh_bar_extra_para para = { 0 };

	para.is_sync = true;
	para.retrycnt = BAR_MSG_RETRY_CNT_MAX;

	if (!zxdh_en_is_panel_port(en_dev))
		return err;

	msg = kzalloc(sizeof(union zxdh_msg), GFP_KERNEL);
	if (!msg) {
		LOG_ERR("kzalloc(%lu, GFP_KERNEL) failed !", sizeof(union zxdh_msg));
		return -ENOMEM;
	}

	msg->payload.hdr_to_agt.op_code = AGENT_MAC_MODULE_EEPROM_READ;
	msg->payload.hdr_to_agt.phyport = en_dev->phy_port;
	msg->payload.module_eeprom_msg.i2c_addr = query->i2c_addr;
	msg->payload.module_eeprom_msg.bank = query->bank;
	msg->payload.module_eeprom_msg.page = query->page;
	msg->payload.module_eeprom_msg.offset = query->offset;
	msg->payload.module_eeprom_msg.length = query->length;

	err = en_dev->ops->msg_send_cmd(en_dev->parent, MODULE_MAC, msg, msg, &para);
	if (err != 0) {
		LOG_ERR("zxdh_send_command_to_riscv_mac failed, err: %d\n", err);
		kfree(msg);
		return 0;
	}

	if (data)
		memcpy(data, msg->reps.module_eeprom_msg.data, msg->reps.module_eeprom_msg.length);

	length = msg->reps.module_eeprom_msg.length;
	kfree(msg);
	return length;
}

s32 zxdh_vf_1588_call_np_interface(struct zxdh_en_device *en_dev)
{
	union zxdh_msg *msg = NULL;
	s32 ret = 0;
	struct zxdh_bar_extra_para para = { 0 };

	para.is_sync = true;
	para.retrycnt = BAR_MSG_RETRY_CNT_MAX;

	msg = kzalloc(sizeof(union zxdh_msg), GFP_KERNEL);
	if (!msg) {
		LOG_ERR("kzalloc(%lu, GFP_KERNEL) failed !", sizeof(union zxdh_msg));
		return -ENOMEM;
	}

	msg->payload.hdr.op_code = ZXDH_VF_1588_CALL_NP;
	msg->payload.hdr.vport = en_dev->vport;
	msg->payload.hdr.pcie_id = en_dev->pcie_id;
	msg->payload.vf_1588_call_np.vfid = VQM_VFID(msg->payload.hdr.vport);
	msg->payload.vf_1588_call_np.call_np_interface_num = en_dev->vf_1588_call_np_num;
	msg->payload.vf_1588_call_np.ptp_tc_enable_opt = en_dev->ptp_tc_enable_opt;
	ret = en_dev->ops->msg_send_cmd(en_dev->parent, MODULE_VF_BAR_MSG_TO_PF, msg, msg, &para);
	if (ret != 0) {
		LOG_ERR("zxdh_send_command_to_pf failed: %d\n", ret);
		kfree(msg);
		return ret;
	}

	kfree(msg);
	return ret;
}

s32 zxdh_vf_port_create(struct zxdh_en_device *en_dev)
{
	s32 ret = 0;
	union zxdh_msg *msg = NULL;
	u8 link_up = 0;
	bool is_upf = false;
	struct zxdh_bar_extra_para para = { 0 };

	para.is_sync = true;
	para.retrycnt = BAR_MSG_RETRY_CNT_MAX;

	msg = kzalloc(sizeof(union zxdh_msg), GFP_KERNEL);
	if (!msg) {
		LOG_ERR("kzalloc(%lu, GFP_KERNEL) failed !", sizeof(union zxdh_msg));
		return -ENOMEM;
	}

	if (!zxdh_en_is_panel_port(en_dev))
		is_upf = true;

	msg->payload.hdr.op_code = ZXDH_VF_PORT_INIT;
	msg->payload.hdr.vport = en_dev->vport;
	msg->payload.hdr.pcie_id = en_dev->pcie_id;
	msg->payload.vf_init_msg.base_qid = en_dev->phy_index[0];
	msg->payload.vf_init_msg.hash_search_idx = en_dev->hash_search_idx;
	msg->payload.vf_init_msg.rss_enable = 1;
	msg->payload.vf_init_msg.is_upf = is_upf;

	ret = en_dev->ops->msg_send_cmd(en_dev->parent, MODULE_VF_BAR_MSG_TO_PF, msg, msg, &para);
	if (ret != 0) {
		LOG_ERR("zxdh_send_command_to_pf failed: %d\n", ret);
		kfree(msg);
		return ret;
	}

	if (is_upf) {
		en_dev->link_up = msg->reps.vf_init_msg.link_up;
	} else {
		en_dev->ops->get_link_info_from_vqm(en_dev->parent, &link_up);
		en_dev->link_up = link_up;
		LOG_DEBUG("vf read link_up: %d from vqm\n", link_up);
	}

	zxdh_netdev_addr_set(en_dev->netdev, msg->reps.vf_init_msg.mac_addr);
	ether_addr_copy(en_dev->last_np_mac_addr.sa_data, en_dev->netdev->dev_addr);
	en_dev->netdev->addr_assign_type = msg->reps.vf_init_msg.addr_assign_type;
	en_dev->speed = msg->reps.vf_init_msg.speed;
	en_dev->autoneg_enable = msg->reps.vf_init_msg.autoneg_enable;
	en_dev->supported_speed_modes = msg->reps.vf_init_msg.sup_link_modes;
	en_dev->advertising_speed_modes = msg->reps.vf_init_msg.adv_link_modes;
	en_dev->duplex = msg->reps.vf_init_msg.duplex;
	en_dev->vlan_dev.vlan_id = msg->reps.vf_init_msg.vlan_id;
	en_dev->vlan_dev.qos = msg->reps.vf_init_msg.vlan_qos;

	if (!is_upf) {
		en_dev->phy_port = msg->reps.vf_init_msg.phy_port;
		en_dev->ops->set_pf_phy_port(en_dev->parent, en_dev->phy_port);
	}

	if (en_dev->link_up) {
		en_dev->ops->set_pf_link_up(en_dev->parent, TRUE);
		netif_carrier_on(en_dev->netdev);
	} else {
		en_dev->ops->set_pf_link_up(en_dev->parent, FALSE);
		netif_carrier_off(en_dev->netdev);
	}

	kfree(msg);
	return ret;
}

s32 zxdh_vf_port_delete(struct zxdh_en_device *en_dev)
{
	union zxdh_msg *msg = NULL;
	s32 ret = 0;
	struct zxdh_bar_extra_para para = { 0 };

	para.is_sync = true;
	para.retrycnt = BAR_MSG_RETRY_CNT_MAX;

	msg = kzalloc(sizeof(union zxdh_msg), GFP_KERNEL);
	if (!msg) {
		LOG_ERR("kzalloc(%lu, GFP_KERNEL) failed !", sizeof(union zxdh_msg));
		return -ENOMEM;
	}

	//dpp_np_uninit
	msg->payload.hdr.op_code = ZXDH_VF_PORT_UNINIT;
	msg->payload.hdr.vport = en_dev->vport;
	msg->payload.hdr.pcie_id = en_dev->pcie_id;
	ret = en_dev->ops->msg_send_cmd(en_dev->parent, MODULE_VF_BAR_MSG_TO_PF, msg, msg, &para);
	kfree(msg);
	return ret;
}

#ifdef VF_STATS_UPDATE
s32 zxdh_vf_item_init_stats_update(struct zxdh_en_device *en_dev)
{
	union zxdh_msg *msg = NULL;
	s32 ret = 0;
	u32 vf_id = GET_VFID(en_dev->vport);
	struct zxdh_bar_extra_para para = { 0 };

	para.is_sync = true;
	para.retrycnt = 0;

	msg = kzalloc(sizeof(union zxdh_msg), GFP_KERNEL);
	if (!msg) {
		LOG_ERR("kzalloc(%lu, GFP_KERNEL) failed !", sizeof(union zxdh_msg));
		return -ENOMEM;
	}

	msg->payload.hdr.op_code = ZXDH_GET_NP_STATS;
	msg->payload.hdr.vport = en_dev->vport;
	msg->payload.hdr.vf_id = vf_id;
	msg->payload.hdr.pcie_id = en_dev->pcie_id;
	msg->payload.np_stats_get_msg.clear_mode = NP_GET_PKT_CNT;
	msg->payload.np_stats_get_msg.is_init_get = true;
	ret = en_dev->ops->msg_send_cmd(en_dev->parent, MODULE_VF_BAR_MSG_TO_PF, msg, msg, &para);
	if (ret != 0)
		LOG_ERR("zxdh_send_command_to_pf failed: %d\n", ret);

	kfree(msg);
	return ret;
}
#endif

s32 zxdh_vf_dpp_add_mac(struct zxdh_en_device *en_dev, const u8 *dev_addr, u8 filter_flag)
{
	union zxdh_msg *msg = NULL;
	s32 ret = 0;
	struct zxdh_bar_extra_para para = { 0 };

	para.is_sync = true;
	para.retrycnt = BAR_MSG_RETRY_CNT_MAX;

	msg = kzalloc(sizeof(union zxdh_msg), GFP_KERNEL);
	if (!msg) {
		LOG_ERR("kzalloc(%lu, GFP_KERNEL) failed !", sizeof(union zxdh_msg));
		return -ENOMEM;
	}

	msg->payload.hdr.op_code = ZXDH_MAC_ADD;
	msg->payload.hdr.vport = en_dev->vport;
	msg->payload.hdr.pcie_id = en_dev->pcie_id;
	msg->payload.mac_addr_set_msg.filter_flag = filter_flag;
	memcpy(msg->payload.mac_addr_set_msg.mac_addr, dev_addr, en_dev->netdev->addr_len);

	ret = en_dev->ops->msg_send_cmd(en_dev->parent, MODULE_VF_BAR_MSG_TO_PF, msg, msg, &para);
	if (ret != 0) {
		if (msg->reps.vf_mac_set_msg.mac_err_flag == ZXDH_REPS_BEYOND_MAC) {
			kfree(msg);
			return ZXDH_REPS_BEYOND_MAC;
		} else if (msg->reps.vf_mac_set_msg.mac_err_flag == ZXDH_REPS_EXIST_MAC) {
			kfree(msg);
			return ZXDH_REPS_EXIST_MAC;
		}
	}
	kfree(msg);
	return ret;
}

s32 zxdh_vf_dpp_dump_mac(struct zxdh_en_device *en_dev, const u8 *dev_addr)
{
	union zxdh_msg *msg = NULL;
	s32 ret = 0;
	struct zxdh_bar_extra_para para = { 0 };

	para.is_sync = true;
	para.retrycnt = BAR_MSG_RETRY_CNT_MAX;

	msg = kzalloc(sizeof(union zxdh_msg), GFP_KERNEL);
	if (unlikely(!msg)) {
		LOG_ERR("failed to kzalloc\n");
		return -ENOMEM;
	}

	msg->payload.hdr.op_code = ZXDH_MAC_DUMP;
	msg->payload.hdr.vport = en_dev->vport;
	msg->payload.hdr.pcie_id = en_dev->pcie_id;
	memcpy(msg->payload.mac_addr_set_msg.mac_addr, dev_addr, en_dev->netdev->addr_len);

	ret = en_dev->ops->msg_send_cmd(en_dev->parent, MODULE_VF_BAR_MSG_TO_PF, msg, msg, &para);
	if (ret != 0) {
		LOG_ERR("en_dev->ops->msg_send_cmd failed, ret = %d\n", ret);
		kfree(msg);
		return ZXDH_REPS_EXIST_MAC;
	}

	kfree(msg);
	return ret;
}

s32 zxdh_vf_dpp_del_mac(struct zxdh_en_device *en_dev, const u8 *dev_addr, u8 filter_flag,
			bool mac_flag)
{
	union zxdh_msg *msg = NULL;
	s32 ret = 0;
	struct zxdh_bar_extra_para para = { 0 };

	para.is_sync = true;
	para.retrycnt = BAR_MSG_RETRY_CNT_MAX;

	msg = kzalloc(sizeof(union zxdh_msg), GFP_KERNEL);
	if (unlikely(!msg)) {
		LOG_ERR("failed to kzalloc\n");
		return -ENOMEM;
	}

	msg->payload.hdr.op_code = ZXDH_MAC_DEL;
	msg->payload.hdr.vport = en_dev->vport;
	msg->payload.hdr.pcie_id = en_dev->pcie_id;
	msg->payload.mac_addr_set_msg.filter_flag = filter_flag;
	msg->payload.mac_addr_set_msg.mac_flag = mac_flag;
	memcpy(msg->payload.mac_addr_set_msg.mac_addr, dev_addr, en_dev->netdev->addr_len);

	ret = en_dev->ops->msg_send_cmd(en_dev->parent, MODULE_VF_BAR_MSG_TO_PF, msg, msg, &para);
	if (ret != 0)
		LOG_ERR("en_dev->ops->msg_send_cmd failed, ret = %d\n", ret);
	kfree(msg);

	return ret;
}

s32 zxdh_vf_rss_en_set(struct zxdh_en_device *en_dev, u32 enable)
{
	union zxdh_msg *msg = NULL;
	s32 ret = 0;
	struct zxdh_bar_extra_para para = { 0 };

	para.is_sync = true;
	para.retrycnt = BAR_MSG_RETRY_CNT_MAX;

	msg = kzalloc(sizeof(union zxdh_msg), GFP_KERNEL);
	if (unlikely(!msg)) {
		LOG_ERR("failed to kzalloc\n");
		return -ENOMEM;
	}

	msg->payload.hdr.op_code = ZXDH_RSS_EN_SET;
	msg->payload.hdr.vport = en_dev->vport;
	msg->payload.hdr.pcie_id = en_dev->pcie_id;
	msg->payload.rss_enable_msg.rss_enable = enable;

	ret = en_dev->ops->msg_send_cmd(en_dev->parent, MODULE_VF_BAR_MSG_TO_PF, msg, msg, &para);
	if (ret != 0)
		LOG_ERR("en_dev->ops->msg_send_cmd failed, ret = %d\n", ret);
	kfree(msg);

	return ret;
}

s32 zxdh_vf_dpp_add_ipv6_mac(struct zxdh_en_device *en_dev, const u8 *mac_addr)
{
	union zxdh_msg *msg = NULL;
	s32 err = 0;
	struct zxdh_bar_extra_para para = { 0 };

	para.is_sync = true;
	para.retrycnt = BAR_MSG_RETRY_CNT_MAX;

	msg = kzalloc(sizeof(union zxdh_msg), GFP_KERNEL);
	if (unlikely(!msg)) {
		LOG_ERR("failed to kzalloc\n");
		return -ENOMEM;
	}

	msg->payload.hdr.op_code = ZXDH_IPV6_MAC_ADD;
	msg->payload.hdr.vport = en_dev->vport;
	msg->payload.hdr.pcie_id = en_dev->pcie_id;
	memcpy(msg->payload.mac_addr_set_msg.mac_addr, mac_addr, en_dev->netdev->addr_len);
	err = en_dev->ops->msg_send_cmd(en_dev->parent, MODULE_VF_BAR_MSG_TO_PF, msg, msg, &para);
	if ((err != 0) && (msg->reps.vf_mac_set_msg.mac_err_flag == ZXDH_REPS_BEYOND_MAC)) {
		LOG_ERR("Add Multi mac addr(%pM) Failed\n",
			mac_addr);
	}
	kfree(msg);

	return err;
}

s32 zxdh_vf_dpp_del_ipv6_mac(struct zxdh_en_device *en_dev, const u8 *mac_addr)
{
	union zxdh_msg *msg = NULL;
	s32 ret = 0;
	struct zxdh_bar_extra_para para = { 0 };

	para.is_sync = true;
	para.retrycnt = BAR_MSG_RETRY_CNT_MAX;

	msg = kzalloc(sizeof(union zxdh_msg), GFP_KERNEL);
	if (unlikely(!msg)) {
		LOG_ERR("failed to kzalloc\n");
		return -ENOMEM;
	}

	msg->payload.hdr.op_code = ZXDH_IPV6_MAC_DEL;
	msg->payload.hdr.vport = en_dev->vport;
	msg->payload.hdr.pcie_id = en_dev->pcie_id;
	memcpy(msg->payload.mac_addr_set_msg.mac_addr, mac_addr, en_dev->netdev->addr_len);

	ret = en_dev->ops->msg_send_cmd(en_dev->parent, MODULE_VF_BAR_MSG_TO_PF, msg, msg, &para);
	if (ret != 0)
		LOG_ERR("en_dev->ops->msg_send_cmd failed, ret = %d\n", ret);
	kfree(msg);

	return ret;
}

s32 zxdh_vf_dpp_add_lacp_mac(struct zxdh_en_device *en_dev, const u8 *mac_addr)
{
	union zxdh_msg *msg = NULL;
	s32 err = 0;
	struct zxdh_bar_extra_para para = { 0 };

	para.is_sync = true;
	para.retrycnt = BAR_MSG_RETRY_CNT_MAX;

	msg = kzalloc(sizeof(union zxdh_msg), GFP_KERNEL);
	if (unlikely(!msg)) {
		LOG_ERR("failed to kzalloc\n");
		return -ENOMEM;
	}

	msg->payload.hdr.op_code = ZXDH_LACP_MAC_ADD;
	msg->payload.hdr.vport = en_dev->vport;
	msg->payload.hdr.pcie_id = en_dev->pcie_id;
	memcpy(msg->payload.mac_addr_set_msg.mac_addr, mac_addr, en_dev->netdev->addr_len);
	err = en_dev->ops->msg_send_cmd(en_dev->parent, MODULE_VF_BAR_MSG_TO_PF, msg, msg, &para);
	if (err != 0)
		LOG_ERR("Add LACP Multicast MAC Address(%pM) Failed\n", mac_addr);

	kfree(msg);

	return err;
}

s32 zxdh_vf_dpp_del_lacp_mac(struct zxdh_en_device *en_dev, const u8 *mac_addr)
{
	union zxdh_msg *msg = NULL;
	s32 ret = 0;
	struct zxdh_bar_extra_para para = { 0 };

	para.is_sync = true;
	para.retrycnt = BAR_MSG_RETRY_CNT_MAX;

	msg = kzalloc(sizeof(union zxdh_msg), GFP_KERNEL);
	if (unlikely(!msg)) {
		LOG_ERR("failed to kzalloc\n");
		return -ENOMEM;
	}

	msg->payload.hdr.op_code = ZXDH_LACP_MAC_DEL;
	msg->payload.hdr.vport = en_dev->vport;
	msg->payload.hdr.pcie_id = en_dev->pcie_id;
	memcpy(msg->payload.mac_addr_set_msg.mac_addr, mac_addr, en_dev->netdev->addr_len);

	ret = en_dev->ops->msg_send_cmd(en_dev->parent, MODULE_VF_BAR_MSG_TO_PF, msg, msg, &para);
	if (ret != 0)
		LOG_ERR("DEL LACP Multicast MAC Address(%pM) Failed\n", mac_addr);

	kfree(msg);

	return ret;
}

s32 zxdh_vf_egr_port_attr_set(struct zxdh_en_device *en_dev, u32 mode, u32 value, u8 fow)
{
	union zxdh_msg *msg = NULL;
	s32 ret = 0;
	struct zxdh_bar_extra_para para = { 0 };

	para.is_sync = true;
	para.retrycnt = BAR_MSG_RETRY_CNT_MAX;

	msg = kzalloc(sizeof(union zxdh_msg), GFP_KERNEL);
	if (unlikely(!msg)) {
		LOG_ERR("failed to kzalloc\n");
		return -ENOMEM;
	}

	msg->payload.hdr.op_code = ZXDH_PORT_ATTRS_SET;
	msg->payload.hdr.vport = en_dev->vport;
	msg->payload.hdr.pcie_id = en_dev->pcie_id;
	msg->payload.port_attr_set_msg.mode = mode;
	msg->payload.port_attr_set_msg.value = value;
	msg->payload.port_attr_set_msg.allmulti_follow = fow;

	ret = en_dev->ops->msg_send_cmd(en_dev->parent, MODULE_VF_BAR_MSG_TO_PF, msg, msg, &para);
	if (ret != 0)
		LOG_ERR("en_dev->ops->msg_send_cmd failed, ret = %d\n", ret);
	kfree(msg);

	return ret;
}

s32 zxdh_vf_egr_port_attr_get(struct zxdh_en_device *en_dev,
			      struct zxdh_sriov_vport_t *port_attr_entry)
{
	union zxdh_msg *msg = NULL;
	s32 ret = 0;
	struct zxdh_bar_extra_para para = { 0 };

	para.is_sync = true;
	para.retrycnt = BAR_MSG_RETRY_CNT_MAX;

	msg = kzalloc(sizeof(union zxdh_msg), GFP_KERNEL);
	if (unlikely(!msg)) {
		LOG_ERR("failed to kzalloc\n");
		return -ENOMEM;
	}

	msg->payload.hdr.op_code = ZXDH_PORT_ATTRS_GET;
	msg->payload.hdr.vport = en_dev->vport;
	msg->payload.hdr.pcie_id = en_dev->pcie_id;
	ret = en_dev->ops->msg_send_cmd(en_dev->parent, MODULE_VF_BAR_MSG_TO_PF, msg, msg, &para);
	if (ret != 0) {
		LOG_ERR("en_dev->ops->msg_send_cmd failed, ret = %d\n", ret);
		kfree(msg);
		return ret;
	}

	memcpy(port_attr_entry, &msg->reps.port_attr_get_msg.port_attr_entry,
	       sizeof(struct zxdh_sriov_vport_t));
	kfree(msg);

	return ret;
}

s32 zxdh_vf_port_promisc_set(struct zxdh_en_device *en_dev, u8 mode, u8 value, u8 fow)
{
	union zxdh_msg *msg = NULL;
	s32 ret = 0;
	struct zxdh_bar_extra_para para = { 0 };

	para.is_sync = true;
	para.retrycnt = BAR_MSG_RETRY_CNT_MAX;

	msg = kzalloc(sizeof(union zxdh_msg), GFP_KERNEL);
	if (unlikely(!msg)) {
		LOG_ERR("failed to kzalloc\n");
		return -ENOMEM;
	}

	msg->payload.hdr.op_code = ZXDH_PROMISC_SET;
	msg->payload.hdr.vport = en_dev->vport;
	msg->payload.hdr.pcie_id = en_dev->pcie_id;
	msg->payload.promisc_set_msg.mode = mode;
	msg->payload.promisc_set_msg.value = value;
	msg->payload.promisc_set_msg.mc_follow = fow;

	ret = en_dev->ops->msg_send_cmd(en_dev->parent, MODULE_VF_BAR_MSG_TO_PF, msg, msg, &para);
	if (ret != 0)
		LOG_ERR("en_dev->ops->msg_send_cmd failed, ret = %d\n", ret);

	kfree(msg);

	return ret;
}

s32 zxdh_get_vf_err_stats(struct zxdh_en_device *en_dev, struct zxdh_get_sw_stats *payload,
			  struct zxdh_sw_stats_reply *reply)
{
	union zxdh_msg *msg = NULL;
	s32 err = 0;
	struct zxdh_bar_extra_para para = { 0 };

	para.is_sync = true;
	para.retrycnt = 0;

	if (!en_dev->ops->get_vf_is_probe(en_dev->parent, payload->vf_idx)) {
		LOG_ERR("vf(%u) is not probed\n", payload->vf_idx);
		return VF_ERR;
	}

	msg = kzalloc(sizeof(union zxdh_msg), GFP_KERNEL);
	if (!msg) {
		LOG_ERR("kzalloc(%lu, GFP_KERNEL) failed !", sizeof(union zxdh_msg));
		return GET_STAT_FAILED;
	}

	msg->payload.hdr_vf.op_code = ZXDH_GET_SW_STATS;
	msg->payload.hdr_vf.dst_pcie_id = FIND_VF_PCIE_ID(en_dev->pcie_id, payload->vf_idx);
	memcpy(&msg->payload.vf_sw_stats, payload, sizeof(struct zxdh_get_sw_stats));

	err = en_dev->ops->msg_send_cmd(en_dev->parent, MODULE_PF_BAR_MSG_TO_VF, msg, msg, &para);
	if (err != 0) {
		if (err == ZXDH_INVALID_OP_CODE) {
			LOG_ERR("vf is used by kernel driver, action is not supported!!!\n");
			kfree(msg);
			return ACTION_IS_NOT_SUPPORTED;
		}
		LOG_ERR("failed to get VF[%d] err stats:%d\n", payload->vf_idx, err);
		kfree(msg);
		return GET_STAT_FAILED;
	}
	memcpy(reply, &msg->reps.vf_sw_stats_rsp, sizeof(struct zxdh_sw_stats_reply));
	kfree(msg);
	return GET_STAT_SUCCESS;
}
EXPORT_SYMBOL(zxdh_get_vf_err_stats);

s32 zxdh_cfg_misx_mode(struct zxdh_en_device *en_dev, u16 rx_msix_mode, u16 tx_msix_mode)
{
	union zxdh_msg *msg = NULL;
	s32 err = 0;
	struct zxdh_bar_extra_para para = { 0 };

	para.is_sync = true;
	para.retrycnt = BAR_MSG_RETRY_CNT_MAX;

	msg = kzalloc(sizeof(union zxdh_msg), GFP_KERNEL);
	if (!msg) {
		LOG_ERR("kzalloc(%lu, GFP_KERNEL) failed !", sizeof(union zxdh_msg));
		return -ENOMEM;
	}

	msg->vqm_msg.opcode = MSIX_MODE_SET;
	msg->vqm_msg.cmd = MSIX_MODE_CMD;
	msg->vqm_msg.msix_mode_sel.rx_msix_mode = rx_msix_mode;
	msg->vqm_msg.msix_mode_sel.tx_msix_mode = tx_msix_mode;
	err = en_dev->ops->msg_send_cmd(en_dev->parent, MODULE_CFG_VQM, msg, msg, &para);
	if (err != 0)
		LOG_ERR("send cfg msix mode msg to riscv failed\n");
	kfree(msg);
	return err;
}

s32 zxdh_get_misx_mode(struct zxdh_en_device *en_dev, u16 *rx_msix_mode, u16 *tx_msix_mode)
{
	union zxdh_msg *msg = NULL;
	s32 err = 0;
	struct zxdh_bar_extra_para para = { 0 };

	para.is_sync = true;
	para.retrycnt = BAR_MSG_RETRY_CNT_MAX;

	msg = kzalloc(sizeof(union zxdh_msg), GFP_KERNEL);
	if (!msg) {
		LOG_ERR("kzalloc(%lu, GFP_KERNEL) failed !", sizeof(union zxdh_msg));
		return -ENOMEM;
	}

	msg->vqm_msg.opcode = MSIX_MODE_GET;
	msg->vqm_msg.cmd = MSIX_MODE_CMD;
	err = en_dev->ops->msg_send_cmd(en_dev->parent, MODULE_CFG_VQM, msg, msg, &para);
	if (err != 0) {
		LOG_ERR("send cfg msix mode msg to riscv failed\n");
		kfree(msg);
		return 1;
	}

	*rx_msix_mode = msg->vqm_reps.msix_mode_sel.rx_msix_mode;
	*tx_msix_mode = msg->vqm_reps.msix_mode_sel.tx_msix_mode;
	kfree(msg);
	return 0;
}

s32 zxdh_cfg_coalesce_usecs(struct zxdh_en_device *en_dev, u32 rx_coalesce_usecs,
			    u32 tx_coalesce_usecs)
{
	union zxdh_msg *msg = NULL;
	s32 err = 0;
	struct zxdh_bar_extra_para para = { 0 };

	para.is_sync = true;
	para.retrycnt = BAR_MSG_RETRY_CNT_MAX;

	msg = kzalloc(sizeof(union zxdh_msg), GFP_KERNEL);
	if (!msg) {
		LOG_ERR("kzalloc(%lu, GFP_KERNEL) failed !", sizeof(union zxdh_msg));
		return -ENOMEM;
	}

	msg->vqm_msg.opcode = MSIX_MODE_SET;
	msg->vqm_msg.cmd = COALESCE_USECS_CMD;
	msg->vqm_msg.wr_used_t.rx_used_ring_t = rx_coalesce_usecs;
	msg->vqm_msg.wr_used_t.tx_used_ring_t = tx_coalesce_usecs;
	err = en_dev->ops->msg_send_cmd(en_dev->parent, MODULE_CFG_VQM, msg, msg, &para);
	if (err != 0)
		LOG_ERR("send cfg msix mode msg to riscv failed\n");
	kfree(msg);
	return err;
}

s32 zxdh_get_coalesce_usecs(struct zxdh_en_device *en_dev, u32 *rx_coalesce_usecs,
			    u32 *tx_coalesce_usecs)
{
	union zxdh_msg *msg = NULL;
	s32 err = 0;
	struct zxdh_bar_extra_para para = { 0 };

	para.is_sync = true;
	para.retrycnt = BAR_MSG_RETRY_CNT_MAX;

	msg = kzalloc(sizeof(union zxdh_msg), GFP_KERNEL);
	if (!msg) {
		LOG_ERR("kzalloc(%lu, GFP_KERNEL) failed !", sizeof(union zxdh_msg));
		return -ENOMEM;
	}

	msg->vqm_msg.opcode = MSIX_MODE_GET;
	msg->vqm_msg.cmd = COALESCE_USECS_CMD;
	err = en_dev->ops->msg_send_cmd(en_dev->parent, MODULE_CFG_VQM, msg, msg, &para);
	if (err != 0) {
		LOG_ERR("send get_coalesce_usecs msg to riscv failed\n");
		kfree(msg);
		return 1;
	}

	*rx_coalesce_usecs = msg->vqm_reps.wr_used_t.rx_used_ring_t;
	*tx_coalesce_usecs = msg->vqm_reps.wr_used_t.tx_used_ring_t;
	kfree(msg);
	return 0;
}

s32 zxdh_en_vport_create(struct zxdh_en_device *en_dev)
{
	struct dpp_pf_info_t pf_info = { 0 };

	pf_info.slot = en_dev->slot_id;
	pf_info.vport = en_dev->vport;
	if (!en_dev->ops->if_init(en_dev->parent))
		return 0;

	return dpp_vport_create(&pf_info);
}

s32 zxdh_en_vport_delete(struct zxdh_en_device *en_dev)
{
	struct dpp_pf_info_t pf_info = { 0 };

	pf_info.slot = en_dev->slot_id;
	pf_info.vport = en_dev->vport;
	if (!en_dev->ops->if_init(en_dev->parent))
		return 0;

	return dpp_vport_delete(&pf_info);
}

s32 zxdh_pf_vport_create(struct zxdh_en_device *en_dev)
{
	s32 ret = 0;
	struct dpp_pf_info_t pf_info = { 0 };
	u32 lag_id = 0;

	pf_info.slot = en_dev->slot_id;
	pf_info.vport = en_dev->vport;

	ret = zxdh_en_vport_create(en_dev);
	if (ret != 0) {
		LOG_ERR("zxdh_en_vport_create failed: %d\n", ret);
		return ret;
	}

	ret = dpp_vport_bond_pf(&pf_info);
	if (ret != 0) {
		LOG_ERR("dpp_vport_bond_pf failed: %d\n", ret);
		goto err_vport;
	}

	if (!zxdh_en_is_panel_port(en_dev)) {
		if (en_dev->ops->get_dev_type(en_dev->parent) == ZXDH_DEV_NE1)
			lag_id = 1;

		ret = dpp_vport_attr_set(&pf_info, SRIOV_VPORT_LAG_ID, lag_id);
		if (ret != 0) {
			LOG_ERR("dpp_vport_attr_set lag_id 0 failed: %d\n", ret);
			goto err_vport;
		}

		ret = dpp_vport_attr_set(&pf_info, SRIOV_VPORT_LAG_EN_OFF, 1);
		if (ret != 0) {
			LOG_ERR("dpp_vport_attr_set bond_en 1 failed: %d\n", ret);
			goto err_vport;
		}
	} else {
		ret = dpp_uplink_phy_bond_vport(&pf_info, en_dev->phy_port);
		if (ret != 0) {
			LOG_ERR("dpp_uplink_phy_bond_vport failed: %d\n", ret);
			goto err_vport;
		}
	}

	return ret;

err_vport:
	zxdh_en_vport_delete(en_dev);
	return ret;
}

s32 zxdh_rxfh_set(struct zxdh_en_device *en_dev, u32 *queue_map)
{
	union zxdh_msg *msg = NULL;
	s32 err = 0;
	struct dpp_pf_info_t pf_info = { 0 };
	struct zxdh_bar_extra_para para = { 0 };

	para.is_sync = true;
	para.retrycnt = BAR_MSG_RETRY_CNT_MAX;

	msg = kzalloc(sizeof(union zxdh_msg), GFP_KERNEL);
	if (!msg) {
		LOG_ERR("kzalloc(%lu, GFP_KERNEL) failed !", sizeof(union zxdh_msg));
		return -1;
	}

	pf_info.slot = en_dev->slot_id;
	pf_info.vport = en_dev->vport;

	if (!queue_map) {
		kfree(msg);
		return -1;
	}

	if (en_dev->ops->get_coredev_type(en_dev->parent) == DH_COREDEV_PF) {
		err = dpp_rxfh_set(&pf_info, queue_map, ZXDH_INDIR_RQT_SIZE);
		if (err != 0)
			LOG_ERR("dpp_rxfh_set failed: %d\n", err);
	} else {
		msg->payload.hdr.op_code = ZXDH_RXFH_SET;
		msg->payload.hdr.vport = en_dev->vport;
		msg->payload.hdr.pcie_id = en_dev->pcie_id;
		memcpy(msg->payload.rxfh_set_msg.queue_map, queue_map,
		       ZXDH_INDIR_RQT_SIZE * sizeof(u32));
		err = en_dev->ops->msg_send_cmd(en_dev->parent, MODULE_VF_BAR_MSG_TO_PF, msg, msg,
						&para);
		if (err != 0)
			LOG_ERR("zxdh_send_command_to_pf_np failed: %d\n", err);
	}

	kfree(msg);
	return err;
}

void zxdh_rxfh_del(struct zxdh_en_device *en_dev)
{
	union zxdh_msg *msg = NULL;
	s32 err = 0;
	struct dpp_pf_info_t pf_info = { 0 };
	struct zxdh_bar_extra_para para = { 0 };

	pf_info.slot = en_dev->slot_id;
	pf_info.vport = en_dev->vport;
	para.is_sync = true;
	para.retrycnt = BAR_MSG_RETRY_CNT_MAX;

	if (en_dev->quick_remove)
		return;

	msg = kzalloc(sizeof(union zxdh_msg), GFP_KERNEL);
	if (!msg) {
		LOG_ERR("kzalloc(%lu, GFP_KERNEL) failed !", sizeof(union zxdh_msg));
		return;
	}

	if (en_dev->ops->is_bond(en_dev->parent)) {
		kfree(msg);
		return;
	}

	if (en_dev->ops->get_coredev_type(en_dev->parent) == DH_COREDEV_PF) {
		dpp_rxfh_del(&pf_info);
	} else {
		msg->payload.hdr.op_code = ZXDH_RXFH_DEL;
		msg->payload.hdr.vport = en_dev->vport;
		msg->payload.hdr.pcie_id = en_dev->pcie_id;
		err = en_dev->ops->msg_send_cmd(en_dev->parent, MODULE_VF_BAR_MSG_TO_PF, msg, msg,
						&para);
		if (err != 0)
			LOG_ERR("zxdh_send_command_to_pf_np failed: %d\n", err);
	}
	kfree(msg);
}

s32 zxdh_ethtool_init(struct zxdh_en_device *en_dev)
{
	s32 ret = 0;
	struct dpp_pf_info_t pf_info = { 0 };

	pf_info.slot = en_dev->slot_id;
	pf_info.vport = en_dev->vport;

	ret = dpp_vport_hash_funcs_set(&pf_info, en_dev->eth_config.hash_func);
	if (ret != 0) {
		LOG_ERR("dpp_vport_hash_funcs_set failed: %d\n", ret);
		return ret;
	}

	ret = dpp_vport_rx_flow_hash_set(&pf_info, en_dev->eth_config.hash_mode);
	if (ret != 0) {
		LOG_ERR("zxdh_rx_flow_hash_set failed: %d\n", ret);
		return ret;
	}

	ret = dpp_vport_attr_set(&pf_info, SRIOV_VPORT_PORT_BASE_QID, (u16)en_dev->phy_index[0]);
	if (ret != 0) {
		LOG_ERR("dpp_vport_attr_set %d failed: %d\n", en_dev->phy_index[0], ret);
		return ret;
	}

	ret = dpp_vqm_vfid_vlan_init(&pf_info);
	if (ret != 0) {
		LOG_ERR("dpp_vqm_vfid_vlan_init failed: %d\n", ret);
		return ret;
	}

	ret = dpp_vlan_filter_init(&pf_info);
	if (ret != 0) {
		LOG_ERR("dpp_vlan_filter_init failed: %d\n", ret);
		return ret;
	}

	ret = dpp_add_vlan_filter(&pf_info, 0);
	if (ret != 0) {
		LOG_ERR("dpp_add_vlan_filter 0 failed: %d\n", ret);
		return ret;
	}

	return ret;
}

s32 zxdh_pf_flush_mac(struct zxdh_en_device *en_dev)
{
	s32 err = 0;
	struct dpp_pf_info_t pf_info = { 0 };

	pf_info.slot = en_dev->slot_id;
	pf_info.vport = en_dev->vport;

	err = dpp_unicast_all_mac_delete(&pf_info);
	if (err != 0) {
		LOG_ERR("dpp_unicast_all_mac_delete failed\n");
		return err;
	}
	LOG_DEBUG("dpp_unicast_all_mac_delete succeed\n");

	err = dpp_multicast_all_mac_delete(&pf_info);
	if (err != 0) {
		LOG_ERR("dpp_multicast_all_mac_delete failed\n");
		return err;
	}
	LOG_DEBUG("dpp_multicast_all_mac_delete succeed\n");

	return err;
}

s32 zxdh_pf_flush_mac_online(struct zxdh_en_device *en_dev)
{
	s32 err = 0;
	struct dpp_pf_info_t pf_info = { 0 };

	pf_info.slot = en_dev->slot_id;
	pf_info.vport = en_dev->vport;

	err = dpp_unicast_all_mac_online_delete(&pf_info);
	if (err != 0) {
		LOG_ERR("dpp_unicast_all_mac_online_delete failed:%d\n", err);
		return err;
	}

	err = dpp_multicast_all_mac_online_delete(&pf_info);
	if (err != 0) {
		LOG_ERR("dpp_multicast_all_mac_online_delete failed:%d\n", err);
		return err;
	}

	return err;
}

s32 zxdh_pf_port_delete(struct net_device *netdev)
{
	struct zxdh_en_priv *en_priv = netdev_priv(netdev);
	struct zxdh_en_device *en_dev = &en_priv->edev;
	s32 ret = 0;
	struct dpp_pf_info_t pf_info = { 0 };

	if (!en_dev)
		return -1;

	pf_info.slot = en_dev->slot_id;
	pf_info.vport = en_dev->vport;
	dpp_vport_uc_promisc_set(&pf_info, 0);
	dpp_vport_mc_promisc_set(&pf_info, 0);

	if (!en_dev->ops->is_bond(en_dev->parent)) {
		ret = zxdh_pf_flush_mac_online(en_dev);
		if (ret != 0) {
			LOG_ERR("zxdh_pf_flush_mac_online failed: %d\n", ret);
			return ret;
		}
	}
	ret = dpp_fd_acl_all_delete(&pf_info);
	if (ret != 0) {
		LOG_ERR("dpp_fd_acl_all_delete failed: %d\n", ret);
		return ret;
	}
	ret = zxdh_en_vport_delete(en_dev);
	if (ret != 0) {
		LOG_ERR("dpp_vport_delete failed: %d\n", ret);
		return ret;
	}

	return ret;
}

s32 zxdh_aux_alloc_pannel(struct zxdh_en_device *en_dev)
{
	s32 ret = 0;
	struct zxdh_pannle_port port;

	ret = en_dev->ops->request_port(en_dev->parent, &port);
	if (ret != 0) {
		LOG_ERR("zxdh aux alloc pannel failed\n");
		goto out;
	}

	en_dev->phy_port = port.phyport;
	en_dev->pannel_id = port.pannel_id;
	en_dev->link_check_bit = port.link_check_bit;

	LOG_DEBUG("bond pf: pannel %u, phyport %u check bit %u\n", en_dev->pannel_id,
		  en_dev->phy_port, en_dev->link_check_bit);

out:
	return ret;
}

s32 zxdh_vf_fd_en_set(struct zxdh_en_device *en_dev, u32 enable)
{
	union zxdh_msg *msg = NULL;
	s32 err = 0;
	struct zxdh_bar_extra_para para = { 0 };

	para.is_sync = true;
	para.retrycnt = BAR_MSG_RETRY_CNT_MAX;

	msg = kzalloc(sizeof(union zxdh_msg), GFP_KERNEL);
	if (!msg) {
		LOG_ERR("kzalloc(%lu, GFP_KERNEL) failed !", sizeof(union zxdh_msg));
		return -ENOMEM;
	}

	msg->payload.hdr.op_code = ZXDH_FD_EN_SET;
	msg->payload.hdr.vport = en_dev->vport;
	msg->payload.hdr.pcie_id = en_dev->pcie_id;
	msg->payload.vf_fd_enable_msg.fd_enable = enable;

	err = en_dev->ops->msg_send_cmd(en_dev->parent, MODULE_VF_BAR_MSG_TO_PF, msg, msg, &para);
	if (err != 0)
		LOG_ERR("Fd_set:zxdh_send_command_to_pf_np to set fd failed: %d\n", err);

	kfree(msg);
	return err;
}

s32 zxdh_vf_add_fd(struct zxdh_en_device *en_dev, struct ethtool_rx_flow_spec *fs, u32 *index)
{
	union zxdh_msg *msg = NULL;
	s32 err = 0;
	struct zxdh_bar_extra_para para = { 0 };

	para.is_sync = true;
	para.retrycnt = BAR_MSG_RETRY_CNT_MAX;

	msg = kzalloc(sizeof(union zxdh_msg), GFP_KERNEL);
	if (!msg) {
		LOG_ERR("kzalloc(%lu, GFP_KERNEL) failed !", sizeof(union zxdh_msg));
		return -1;
	}
	msg->payload.hdr.op_code = ZXDH_FD_ADD;
	msg->payload.hdr.vport = en_dev->vport;
	msg->payload.hdr.pcie_id = en_dev->pcie_id;
	zte_memcpy_s(&msg->payload.vf_fd_cfg_msg.fs, fs, sizeof(*fs));

	msg->payload.vf_fd_cfg_msg.index = DEFAULT_ADD_INDEX;
	if (en_dev->fs.ethtool_fs[fs->location].is_used)
		msg->payload.vf_fd_cfg_msg.index = en_dev->fs.ethtool_fs[fs->location].index;

	err = en_dev->ops->msg_send_cmd(en_dev->parent, MODULE_VF_BAR_MSG_TO_PF, msg, msg, &para);
	if (err != 0) {
		LOG_ERR("Add_fd:zxdh_send_command_to_pf_np failed: %d\n", err);
		kfree(msg);
		return err;
	}

	*index = msg->reps.fd_cfg_resp.index;
	kfree(msg);
	return err;
}

s32 zxdh_vf_get_fd(struct zxdh_en_device *en_dev, u32 index)
{
	union zxdh_msg *msg = NULL;
	s32 err = 0;
	struct zxdh_bar_extra_para para = { 0 };

	para.is_sync = true;
	para.retrycnt = BAR_MSG_RETRY_CNT_MAX;

	msg = kzalloc(sizeof(union zxdh_msg), GFP_KERNEL);
	if (!msg) {
		LOG_ERR("kzalloc(%lu, GFP_KERNEL) failed !", sizeof(union zxdh_msg));
		return -1;
	}
	msg->payload.hdr.op_code = ZXDH_FD_GET;
	msg->payload.hdr.vport = en_dev->vport;
	msg->payload.hdr.pcie_id = en_dev->pcie_id;

	msg->payload.vf_fd_cfg_msg.index = index;

	err = en_dev->ops->msg_send_cmd(en_dev->parent, MODULE_VF_BAR_MSG_TO_PF, msg, msg, &para);
	if (err != 0)
		LOG_ERR("Get_fd:zxdh_send_command_to_pf_np failed: %d\n", err);
	kfree(msg);
	return err;
}

s32 zxdh_vf_del_fd(struct zxdh_en_device *en_dev, u32 index)
{
	union zxdh_msg *msg = NULL;
	s32 err = 0;
	struct zxdh_bar_extra_para para = { 0 };

	para.is_sync = true;
	para.retrycnt = BAR_MSG_RETRY_CNT_MAX;

	msg = kzalloc(sizeof(union zxdh_msg), GFP_KERNEL);
	if (!msg) {
		LOG_ERR("kzalloc(%lu, GFP_KERNEL) failed !", sizeof(union zxdh_msg));
		return -1;
	}

	msg->payload.hdr.op_code = ZXDH_FD_DEL;
	msg->payload.hdr.vport = en_dev->vport;
	msg->payload.hdr.pcie_id = en_dev->pcie_id;
	msg->payload.vf_fd_cfg_msg.index = index;
	err = en_dev->ops->msg_send_cmd(en_dev->parent, MODULE_VF_BAR_MSG_TO_PF, msg, msg, &para);
	if (err != 0)
		LOG_ERR("Del_fd:zxdh_send_command_to_pf_np failed: %d\n", err);

	kfree(msg);
	return err;
}

static void pf_recover_mac_get(struct zxdh_en_device *en_dev)
{
	struct netdev_hw_addr *ha = NULL;
	u32 i = 0;
	u32 j = 0;

	netif_addr_lock_bh(en_dev->netdev);

	list_for_each_entry(ha, &en_dev->netdev->uc.list, list) {
		if (i >= VF_MAX_UNICAST_MAC) {
			LOG_ERR("umac_num: %d exceed the max num: %d\n", i, VF_MAX_UNICAST_MAC);
			break;
		}
		zte_memcpy_s(en_dev->eth_config.pf_recover_mac.umac[i].mac_addr, ha->addr,
			     ETH_ALEN);
		i++;
	}

	list_for_each_entry(ha, &en_dev->netdev->mc.list, list) {
		if (j >= VF_MAX_MULTICAST_MAC) {
			LOG_ERR("mmac_num: %d exceed the max num: %d", j, VF_MAX_MULTICAST_MAC);
			break;
		}
		zte_memcpy_s(en_dev->eth_config.pf_recover_mac.mmac[j].mac_addr, ha->addr,
			     ETH_ALEN);
		j++;
	}

	netif_addr_unlock_bh(en_dev->netdev);
	en_dev->eth_config.pf_recover_mac.umac_num = i;
	en_dev->eth_config.pf_recover_mac.mmac_num = j;
}

static s32 eth_pf_mac_addr_recover(struct zxdh_en_device *en_dev)
{
	struct dpp_pf_info_t pf_info = { 0 };
	u32 i = 0;
	s32 ret = 0;

	pf_info.slot = en_dev->slot_id;
	pf_info.vport = en_dev->vport;

	ret = dpp_add_mac(&pf_info, en_dev->netdev->dev_addr, 0, 0);
	if (ret != 0) {
		LOG_ERR("pf add mac failed in recover local mac: %d\n", ret);
		return ret;
	}

	pf_recover_mac_get(en_dev);

	for (i = 0; i < en_dev->eth_config.pf_recover_mac.umac_num; i++) {
		ret = dpp_add_mac(&pf_info, en_dev->eth_config.pf_recover_mac.umac[i].mac_addr, 0,
				  0);
		if (ret != 0) {
			LOG_ERR("pf add mac failed in recover uc list: %d\n", ret);
			return ret;
		}
	}

	for (i = 0; i < en_dev->eth_config.pf_recover_mac.mmac_num; i++) {
		ret = dpp_multi_mac_add_member(&pf_info,
					       en_dev->eth_config.pf_recover_mac.mmac[i].mac_addr);
		if (ret != 0) {
			LOG_ERR("pf add mac failed in recover mc list: %d\n", ret);
			return ret;
		}
	}
	return 0;
}

static s32 zxdh_recover_fd_cfg(struct zxdh_en_device *en_dev)
{
	u32 orig_index = 0;
	u32 new_index = 0;
	u32 flow_num = 0;
	u32 location = 0;
	s32 err = 0;

	struct zxdh_fd_cfg_t p_fd_cfg = { 0 };
	struct dpp_pf_info_t pf_info = { 0 };

	pf_info.slot = en_dev->slot_id;
	pf_info.vport = en_dev->vport;

	LOG_INFO("recover_flow_table: total flow_num is %d", en_dev->fs.tot_num_rules);
	while (flow_num < en_dev->fs.tot_num_rules && location < ETHTOOL_FD_MAX_NUM) {
		if (en_dev->fs.ethtool_fs[location].is_used) {
			orig_index = en_dev->fs.ethtool_fs[location].index;
			if (en_dev->ops->get_coredev_type(en_dev->parent) == DH_COREDEV_VF) {
				en_dev->fs.ethtool_fs[location].is_used = false;
				err = zxdh_vf_add_fd(en_dev, &en_dev->fs.ethtool_fs[location].rfs,
						     &new_index);
				if (err) {
					LOG_ERR("zxdh_vf_recover_fd failed, location %d\n",
						location);
					return -1;
				}
				en_dev->fs.ethtool_fs[location].is_used = true;
			} else {
				zxdh_flow_table_add(&en_dev->fs.ethtool_fs[location].rfs, &p_fd_cfg,
						    &pf_info);
				err = zxdh_flow_table_pf_action_add(
					en_dev, &en_dev->fs.ethtool_fs[location].rfs, &p_fd_cfg);
				if (err) {
					LOG_ERR("zxdh_cfg_fd_add_action failed, location %d",
						location);
					return -EINVAL;
				}
				err = dpp_fd_acl_index_request(&pf_info, &new_index);
				if (err != 0) {
					LOG_ERR("zxdh_cfg_np_fd_acl_request failed, location %d\n",
						location);
					return -1;
				}
				err = dpp_tbl_fd_cfg_add(&pf_info, ZXDH_SDT_FD_CFG_TABLE, new_index,
							 &p_fd_cfg);
				if (err != 0) {
					LOG_ERR("zxdh_cfg_np_fd_recover failed, location %d\n",
						location);
					return -1;
				}
			}
			en_dev->fs.ethtool_fs[location].index = new_index;
			flow_num++;
			LOG_INFO(
				"recover_flow_table: location is %u, orig_index is %u, new_index is %u",
				location, orig_index, new_index);
		}
		location++;
	}
	return 0;
}

s32 zxdh_pf_port_init(struct zxdh_en_device *en_dev, bool boot)
{
	bool vepa = false;
	s32 ret = 0;
	struct dpp_pf_info_t pf_info = { 0 };

	if (!en_dev)
		return -1;

	pf_info.slot = en_dev->slot_id;
	pf_info.vport = en_dev->vport;

	ret = zxdh_pf_vport_create(en_dev);
	ZXDH_CHECK_RET_RETURN(ret, "zxdh_pf_vport_create failed: %d\n", ret);

	if (zxdh_en_is_panel_port(en_dev))
		dpp_uplink_phy_attr_set(&pf_info, en_dev->phy_port,
					UPLINK_PHY_PORT_MAGIC_PACKET_ENABLE,
					(en_dev->wolopts == WAKE_MAGIC));

	zxdh_mac_stats_clear(en_dev);

	if (en_dev->ops->is_bond(en_dev->parent)) {
		if (!en_dev->ops->if_init(en_dev->parent)) {
			LOG_INFO("First net-device is init\n");
			return 0;
		}

		ret = dpp_vport_attr_set(&pf_info, SRIOV_VPORT_PORT_BASE_QID,
					 (u16)en_dev->phy_index[0]);
		ZXDH_CHECK_RET_GOTO_ERR(ret, err_vport, "set qid: %d failed: %d\n",
					(u16)en_dev->phy_index[0], ret);
		return 0;
	}

	vepa = en_dev->ops->get_vepa(en_dev->parent);
	ret = dpp_vport_attr_set(&pf_info, SRIOV_VPORT_VEPA_EN_OFF, (u32)vepa);
	ZXDH_CHECK_RET_GOTO_ERR(ret, err_vport,
				"dpp_vport_attr_set SRIOV_VPORT_VEPA_EN_OFF failed: %d\n", ret);
	LOG_INFO("init vport(0x%x) to %s mode\n", en_dev->vport, vepa ? "vepa" : "veb");

	ret = dpp_vport_attr_set(&pf_info, SRIOV_VPORT_HASH_SEARCH_INDEX, en_dev->hash_search_idx);
	ZXDH_CHECK_RET_GOTO_ERR(ret, err_vport, "set hash_search_index %u failed: %d\n",
				en_dev->hash_search_idx, ret);

	ret = zxdh_ethtool_init(en_dev);
	ZXDH_CHECK_RET_GOTO_ERR(ret, err_vport, "zxdh_ethtool_init failed: %d\n", ret);

	if (boot) {
		ret = zxdh_pf_flush_mac(en_dev);
		ZXDH_CHECK_RET_GOTO_ERR(ret, err_vport, "zxdh_pf_flush_mac failed: %d\n", ret);

		ret = dpp_add_mac(&pf_info, en_dev->netdev->dev_addr, 0, 0);
		ZXDH_CHECK_RET_GOTO_ERR(ret, err_vport, "dpp_add_mac failed: %d\n", ret);
	} else {
		ret = eth_pf_mac_addr_recover(en_dev);
		ZXDH_CHECK_RET_GOTO_ERR(ret, err_vport, "eth_pf_mac_addr_recover failed: %d\n",
					ret);
	}

	if (!boot) {
		ret = zxdh_vlan_trunk_recover(&pf_info, en_dev->eth_config.vlan_trunk_bitmap);
		ZXDH_CHECK_RET_GOTO_ERR(ret, err_vport, "zxdh_vlan_trunk_recover failed: %d\n",
					ret);
	}

	ether_addr_copy(en_dev->last_np_mac_addr.sa_data, en_dev->netdev->dev_addr);
	if (en_dev->promisc_enabled) {
		dpp_vport_uc_promisc_set(&pf_info, 1);
		dpp_vport_mc_promisc_set(&pf_info, 1);
		dpp_vport_promisc_en_set(&pf_info, 1);
	} else if (en_dev->allmulti_enabled) {
		dpp_vport_mc_promisc_set(&pf_info, 1);
	} else {
		dpp_vport_uc_promisc_set(&pf_info, 0);
		dpp_vport_mc_promisc_set(&pf_info, 0);
	}

	if (!boot) {
		ret = dpp_fd_acl_all_delete(&pf_info);
		ZXDH_CHECK_RET_GOTO_ERR(ret, err_vport, "dpp_fd_acl_all_delete failed: %d\n", ret);
		ret = zxdh_recover_fd_cfg(en_dev);
		ZXDH_CHECK_RET_GOTO_ERR(ret, err_vport, "dpp_fd_acl_all_recover failed: %d\n", ret);
	}

	if ((!zxdh_en_is_panel_port(en_dev)) || (!boot))
		return 0;

	ret = dpp_stat_asn_phyport_rx_pkt_cnt_get(&pf_info, en_dev->phy_port, STAT_RD_CLR_MODE_CLR,
						  &en_dev->hw_stats.udp_stats.rx_arn_phy);
	ZXDH_CHECK_RET_GOTO_ERR(ret, err_vport, "dpp_stat_asn_phyport_rx_pkt_cnt_get failed: %d\n",
				ret);

	ret = dpp_stat_psn_phyport_tx_pkt_cnt_get(&pf_info, en_dev->phy_port, STAT_RD_CLR_MODE_CLR,
						  &en_dev->hw_stats.udp_stats.tx_psn_phy);
	ZXDH_CHECK_RET_GOTO_ERR(ret, err_vport, "dpp_stat_psn_phyport_tx_pkt_cnt_get failed: %d\n",
				ret);

	ret = dpp_stat_psn_phyport_rx_pkt_cnt_get(&pf_info, en_dev->phy_port, STAT_RD_CLR_MODE_CLR,
						  &en_dev->hw_stats.udp_stats.rx_psn_phy);
	ZXDH_CHECK_RET_GOTO_ERR(ret, err_vport, "dpp_stat_psn_phyport_rx_pkt_cnt_get failed: %d\n",
				ret);

	ret = dpp_stat_psn_ack_phyport_tx_pkt_cnt_get(&pf_info, en_dev->phy_port,
						      STAT_RD_CLR_MODE_CLR,
						      &en_dev->hw_stats.udp_stats.tx_psn_ack_phy);
	ZXDH_CHECK_RET_GOTO_ERR(ret, err_vport,
				"dpp_stat_psn_ack_phyport_tx_pkt_cnt_get failed: %d\n", ret);

	ret = dpp_stat_psn_ack_phyport_rx_pkt_cnt_get(&pf_info, en_dev->phy_port,
						      STAT_RD_CLR_MODE_CLR,
						      &en_dev->hw_stats.udp_stats.rx_psn_ack_phy);
	ZXDH_CHECK_RET_GOTO_ERR(ret, err_vport,
				"dpp_stat_psn_ack_phyport_rx_pkt_cnt_get failed: %d\n", ret);

	return 0;

err_vport:
	zxdh_en_vport_delete(en_dev);
	return ret;
}

s32 zxdh_vf_dpp_port_init(struct zxdh_en_device *en_dev)
{
	s32 ret = 0;

	ret = zxdh_vf_port_create(en_dev);
	if (ret != 0)
		LOG_ERR("zxdh_vf_port_create failed: %d\n", ret);

	return ret;
}

s32 zxdh_port_reload(struct zxdh_en_device *en_dev)
{
	union zxdh_msg *msg = NULL;
	s32 ret = 0;
	bool is_upf = false;
	u8 link_up = 0;
	struct zxdh_bar_extra_para para = { 0 };

	para.is_sync = true;
	para.retrycnt = BAR_MSG_RETRY_CNT_MAX;

	msg = kzalloc(sizeof(union zxdh_msg), GFP_KERNEL);
	if (!msg) {
		LOG_ERR("kzalloc(%lu, GFP_KERNEL) failed !", sizeof(union zxdh_msg));
		return -ENOMEM;
	}

	msg->payload.hdr.op_code = ZXDH_VF_PORT_RELOAD;
	msg->payload.hdr.vport = en_dev->vport;
	msg->payload.hdr.pcie_id = en_dev->pcie_id;

	msg->payload.vf_reload_msg.base_qid = en_dev->phy_index[0];
	is_upf = !(zxdh_en_is_panel_port(en_dev));
	msg->payload.vf_reload_msg.is_upf = is_upf;
	msg->payload.vf_reload_msg.hash_search_idx = en_dev->hash_search_idx;
	zte_memcpy_s(msg->payload.vf_reload_msg.queue_map, en_dev->eth_config.queue_map,
		     ZXDH_INDIR_RQT_SIZE * sizeof(u32));

	msg->payload.vf_reload_msg.hash_mode = en_dev->eth_config.hash_mode;
	msg->payload.vf_reload_msg.hash_func = en_dev->eth_config.hash_func;

	zte_memcpy_s(msg->payload.vf_reload_msg.vlan_trunk_bitmap,
		     en_dev->eth_config.vlan_trunk_bitmap,
		     sizeof(en_dev->eth_config.vlan_trunk_bitmap));

	if (en_dev->promisc_enabled) {
		msg->payload.vf_reload_msg.uc_promisc = true;
		msg->payload.vf_reload_msg.mc_promisc = true;
	} else if (en_dev->allmulti_enabled) {
		msg->payload.vf_reload_msg.mc_promisc = true;
	}

	ret = en_dev->ops->msg_send_cmd(en_dev->parent, MODULE_VF_BAR_MSG_TO_PF, msg, msg, &para);
	if (ret != 0) {
		LOG_ERR("zxdh_send_command_to_pf failed: %d\n", ret);
		kfree(msg);
		return ret;
	}

	if (is_upf) {
		en_dev->link_up = msg->reps.vf_reload_msg.link_up;
	} else {
		en_dev->ops->get_link_info_from_vqm(en_dev->parent, &link_up);
		en_dev->link_up = link_up;
		LOG_DEBUG("vf read link_up: %d from vqm\n", link_up);
	}

	en_dev->speed = msg->reps.vf_reload_msg.speed;
	en_dev->duplex = msg->reps.vf_reload_msg.duplex;
	en_dev->vlan_dev.qos = msg->reps.vf_reload_msg.vlan_qos;

	netif_tx_wake_all_queues(en_dev->netdev);
	if (en_dev->link_up) {
		en_dev->ops->set_pf_link_up(en_dev->parent, TRUE);
		netif_carrier_on(en_dev->netdev);
	} else {
		en_dev->ops->set_pf_link_up(en_dev->parent, FALSE);
		netif_carrier_off(en_dev->netdev);
	}

	kfree(msg);
	return ret;
}

s32 zxdh_port_init(struct net_device *netdev)
{
	struct zxdh_en_priv *en_priv = netdev_priv(netdev);
	struct zxdh_en_device *en_dev = &en_priv->edev;
	s32 err = 0;

	err = zxdh_indir_to_queue_map(en_dev, en_dev->indir_rqt);
	ZXDH_CHECK_RET_RETURN(err, "zxdh_indir_to_queue_map failed: %d\n", err);

	if (en_dev->ops->get_coredev_type(en_dev->parent) == DH_COREDEV_PF) {
		err = zxdh_pf_port_init(en_dev, false);
		ZXDH_CHECK_RET_RETURN(err, "zxdh port init failed: %d\n", err);
		err = zxdh_en_hash_key_recover(en_dev);
		ZXDH_CHECK_RET_GOTO_ERR(err, port_uninit, "zxdh_en_hash_key_recover failed: %d\n",
					err);
		if (!en_dev->ops->is_bond(en_dev->parent)) {
			err = zxdh_rxfh_set(en_dev, en_dev->eth_config.queue_map);
			ZXDH_CHECK_RET_GOTO_ERR(err, port_uninit, "zxdh_rxfh_set failed: %d\n",
						err);
		}
	} else {
		err = zxdh_port_reload(en_dev);
		ZXDH_CHECK_RET_RETURN(err, "zxdh_port_reload failed: %d\n", err);
		err = zxdh_recover_fd_cfg(en_dev);
		ZXDH_CHECK_RET_RETURN(err, "zxdh_port_recover_fd failed: %d\n", err);
	}

	err = zxdh_en_config_mtu_to_np(netdev, netdev->mtu);
	ZXDH_CHECK_RET_GOTO_ERR(err, port_uninit, "zxdh_en_mtu_init failed: %d\n", err);

	if (!en_dev->ops->is_bond(en_dev->parent)) {
		err = zxdh_en_sync_features(en_dev, netdev->features);
		ZXDH_CHECK_RET_GOTO_ERR(err, port_uninit, "zxdh_en_sync_features failed: %d\n",
					err);
	}

	return 0;
port_uninit:
	zxdh_vport_uninit(netdev);
	return err;
}

void zxdh_vport_uninit(struct net_device *netdev)
{
	struct zxdh_en_priv *en_priv = netdev_priv(netdev);
	struct zxdh_en_device *en_dev = &en_priv->edev;
	s32 ret = 0;

	if (en_dev->quick_remove)
		return;

	if (en_dev->device_state == ZXDH_DEVICE_STATE_INTERNAL_ERROR)
		return;

	if (en_dev->ops->get_coredev_type(en_dev->parent) == DH_COREDEV_PF) {
		ret = zxdh_pf_port_delete(netdev);
		if (ret != 0)
			LOG_ERR("zxdh_pf_port_delete failed: %d\n", ret);
	} else {
#ifdef VF_STATS_UPDATE
		ret = zxdh_vf_item_init_stats_update(en_dev);
		if (ret != 0)
			LOG_ERR("zxdh_vf_item_init_stats_update failed: %d\n", ret);
#endif
		ret = zxdh_vf_port_delete(en_dev);
		if (ret != 0)
			LOG_ERR("zxdh_vf_port_delete failed: %d\n", ret);
	}
}

u32 zxdh_uplink_phy_attr_set(struct dpp_pf_info_t *pf_info, u8 phy_port, u32 attr, u32 value)
{
	if (phy_port == INVALID_PHY_PORT)
		return 0;

	return dpp_uplink_phy_attr_set(pf_info, phy_port, attr, value);
}
