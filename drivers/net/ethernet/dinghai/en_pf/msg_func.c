// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#include <linux/dinghai/driver.h>
#include <linux/dinghai/dh_cmd.h>
#include "../msg_common.h"
#include "../en_pf.h"
#include "../en_aux/en_aux_cmd.h"
#include "../en_aux.h"
#include "../en_np/init/include/dpp_np_init.h"
#include "en_pf_eq.h"
#include "msg_func.h"
#include "../plcr.h"
#include "../en_np/driver/include/dpp_drv_sdt.h"
#include "../slib.h"

#define FUNC_NAME_SIZE_MAX 32
#define ZXDH_MAX_VF 256
#define PF_HAS_MAX_ENCAP1_NUM 256

#define ETH_PKT_IPV4 0x0800
#define ETH_PKT_IPV6 0x86dd

typedef u32 (*zxdh_vf_msg_func)(struct zxdh_msg_info *msg, struct zxdh_reps_info *reps,
				struct dpp_pf_info_t *pf_info, struct zxdh_vf_item *vf_item,
				struct zxdh_pf_device *pf_dev);

struct zxdh_vf_msg_proc {
	enum zxdh_msg_op_code op_code;
	u8 proc_name[FUNC_NAME_SIZE_MAX];
	zxdh_vf_msg_func msg_proc;
};

__weak int debug_print;
void zxdh_u32_array_print(u32 *array, u16 size)
{
	u16 i;

	if (debug_print == 0)
		return;

	for (i = 0; i < size; ++i) {
		pr_info("%u    ", array[i]);
		if ((i + 1) % 8 == 0)
			pr_info("\n");
	}
}
EXPORT_SYMBOL(zxdh_u32_array_print);

static void zxdh_vf_link_state_get_proc(struct zxdh_pf_device *pf_dev, struct zxdh_vf_item *vf_item,
					u16 vf_idx)
{
	u32 dev_link_up_reg = 0;
	u8 vf_link_up = 0;

	if (vf_item->link_forced)
		vf_link_up = vf_item->link_up ? 1 : 0;
	else
		vf_link_up = pf_dev->link_up ? 1 : 0;

	if (pf_dev->pf_sriov_cap_base) {
		dev_link_up_reg = ioread32((void __iomem *)(pf_dev->pf_sriov_cap_base +
							    (pf_dev->sriov_bar_size) * vf_idx +
							    pf_dev->dev_cfg_bar_off +
							    ZXDH_DEV_MAC_HIGH_OFFSET));
		dev_link_up_reg = (dev_link_up_reg & ~(0xFF << 16)) | ((u32)(vf_link_up) << 16);
		iowrite32(dev_link_up_reg,
			  (void __iomem *)(pf_dev->pf_sriov_cap_base +
					   (pf_dev->sriov_bar_size) * vf_idx +
					   pf_dev->dev_cfg_bar_off + ZXDH_DEV_MAC_HIGH_OFFSET));
	}
	LOG_INFO("vf[%d] link_forced is [%s], link state[%s] update ok.\n", vf_idx,
		 vf_item->link_forced ? "TRUE" : "FALSE", (vf_link_up == 1) ? "UP" : "DOWN");
}

s32 zxdh_vf_flush_mac(struct dpp_pf_info_t *pf_info, struct zxdh_vf_item *vf_item)
{
	s32 err = 0;
	u8 i = 0;
	u8 *addr = NULL;
	u16 sriov_vlan_tpid = 0;
	u16 sriov_vlan_id = 0;

	mutex_lock(&vf_item->lock);

	sriov_vlan_tpid = vf_item->vlan_proto;
	sriov_vlan_id = ZXDH_VLAN_TCI_GEN(vf_item->vlan, vf_item->qos);

	for (i = 0; i < DEV_UNICAST_MAX_NUM; ++i) {
		addr = vf_item->vf_mac_info.unicast_mac[i].mac_addr;

		if (!is_zero_ether_addr(addr)) {
			LOG_DEBUG("the deleted unicast mac is %pM\n", addr);
			err = dpp_del_mac(pf_info, addr, sriov_vlan_tpid, sriov_vlan_id);
			if (err != 0) {
				LOG_ERR("dpp_del_mac failed\n");
				mutex_unlock(&vf_item->lock);
				return err;
			}
		}
	}

	for (i = 0; i < DEV_MULTICAST_MAX_NUM; ++i) {
		addr = vf_item->vf_mac_info.multicast_mac[i].mac_addr;

		if (!is_zero_ether_addr(addr)) {
			LOG_DEBUG("the deleted multicasat mac is %pM\n", addr);
			err = dpp_multi_mac_del_member(pf_info, addr);
			if (err != 0) {
				LOG_ERR("dpp_multi_mac_del_member failed\n");
				mutex_unlock(&vf_item->lock);
				return err;
			}
		}
	}

	memset(&vf_item->vf_mac_info, 0, sizeof(vf_item->vf_mac_info));

	mutex_unlock(&vf_item->lock);
	return err;
}

static int zxdh_vf_enable_sriov_vlan_tbl(struct dpp_pf_info_t *pf_info, u16 vlan_tci,
					 u16 vlan_proto)
{
	int ret = 0;

	ret = dpp_vport_vlan_offload_en_set(pf_info, 1);
	if (ret != 0)
		goto err;

	ret = dpp_vqm_vfid_vlan_set(pf_info, VLAN_SRIOV_VLAN_TCI, vlan_tci);
	if (ret != 0)
		goto err;

	ret = dpp_vqm_vfid_vlan_set(pf_info, VLAN_SRIOV_VLAN_TPID, vlan_proto);
	if (ret != 0)
		goto err;

err:
	return ret;
}

static int zxdh_vf_init_vlan_recfg(struct zxdh_vf_item *vf_item, struct dpp_pf_info_t *pf_info)
{
	int ret = 0;
	u16 vlan_tci = 0;

	ret = dpp_vqm_vfid_vlan_init(pf_info);
	if (ret != 0) {
		LOG_ERR("dpp_vqm_vfid_vlan_init, ret: %d\n", ret);
		goto out;
	}

	ret = dpp_vlan_filter_init(pf_info);
	if (ret != 0) {
		LOG_ERR("dpp_vlan_filter_init failed: %d\n", ret);
		goto out;
	}

	ret = dpp_add_vlan_filter(pf_info, 0);
	if (ret != 0) {
		LOG_ERR("dpp_add_vlan_filter 0 failed: %d\n", ret);
		goto out;
	}

	if (vf_item->vlan != 0) {
		vlan_tci = ZXDH_VLAN_TCI_GEN(vf_item->vlan, vf_item->qos);
		ret = zxdh_vf_enable_sriov_vlan_tbl(pf_info, vlan_tci, vf_item->vlan_proto);
		if (ret != 0) {
			LOG_ERR("zxdh_enable_sriov_vlan_tbl failed, ret: %d\n", ret);
			return ret;
		}

		LOG_DEBUG("recover vf vlan: %d.\n", vf_item->vlan);
	}

out:
	return ret;
}

static u32 zxdh_vf_port_init(struct zxdh_msg_info *msg, struct zxdh_reps_info *reps,
			     struct dpp_pf_info_t *pf_info, struct zxdh_vf_item *vf_item,
			     struct zxdh_pf_device *pf_dev)
{
	u32 ret = 0;
	u8 mac[6] = { 0 };
	s32 vf_idx = msg->hdr.pcie_id & (0xff);
	u8 addr_type = NET_ADDR_PERM;
	u16 sriov_vlan_tpid = vf_item->vlan_proto;
	u16 sriov_vlan_id = ZXDH_VLAN_TCI_GEN(vf_item->vlan, vf_item->qos);

	LOG_INFO("%s, vfindex%d\n", __func__, vf_idx);
	ret = dpp_vport_create(pf_info);
	if (ret != 0) {
		LOG_ERR("dpp_vport_create failed, ret: %d\n", ret);
		return ret;
	}

	if (msg->vf_init_msg.is_upf) {
		ret = dpp_vport_attr_set(pf_info, SRIOV_VPORT_LAG_ID, 0);
		if (ret != 0) {
			LOG_ERR("dpp_vport_attr_set panel_id %d failed: %d\n", pf_dev->phy_port,
				ret);
			goto err_init;
		}

		ret = dpp_vport_attr_set(pf_info, SRIOV_VPORT_LAG_EN_OFF, 1);
		if (ret != 0) {
			LOG_ERR("dpp_vport_attr_set hash_search_idx %u failed: %d\n",
				msg->vf_init_msg.hash_search_idx, ret);
			goto err_init;
		}
	} else {
		ret = dpp_vport_attr_set(pf_info, SRIOV_VPORT_UPLINK_PHY_PORT_ID, pf_dev->phy_port);
		if (ret != 0) {
			LOG_ERR("dpp_vport_attr_set panel_id %d failed: %d\n", pf_dev->phy_port,
				ret);
			goto err_init;
		}
	}

	ret = dpp_vport_attr_set(pf_info, SRIOV_VPORT_HASH_SEARCH_INDEX,
				 msg->vf_init_msg.hash_search_idx);
	if (ret != 0) {
		LOG_ERR("dpp_vport_attr_set hash_search_idx %u failed: %d\n",
			msg->vf_init_msg.hash_search_idx, ret);
		goto err_init;
	}

	ret = dpp_vport_bond_pf(pf_info);
	if (ret != 0) {
		LOG_ERR("dpp_vport_bond_pf failed, ret: %d\n", ret);
		goto err_init;
	}

	ret = dpp_vport_rss_en_set(pf_info, msg->vf_init_msg.rss_enable);
	if (ret != 0) {
		LOG_ERR("dpp_vport_rss_en_set failed, ret: %d\n", ret);
		goto err_init;
	}

	ret = dpp_vport_hash_funcs_set(pf_info, ZXDH_FUNC_CRC32);
	if (ret != 0) {
		LOG_ERR("dpp_vport_hash_funcs_set failed, ret: %d\n", ret);
		goto err_init;
	}

	ret = dpp_vport_rx_flow_hash_set(pf_info, ZXDH_NET_RX_FLOW_HASH_SDFNT);
	if (ret != 0) {
		LOG_ERR("dpp_vport_rx_flow_hash_set failed, ret: %d\n", ret);
		goto err_init;
	}

	ret = dpp_vport_attr_set(pf_info, SRIOV_VPORT_VEPA_EN_OFF, (u32)pf_dev->vepa);
	if (ret != 0) {
		LOG_ERR("dpp_vport_attr_set vport(0x%x) %s mode failed: %d\n", msg->hdr.vport,
			pf_dev->vepa ? "vepa" : "veb", ret);
		goto err_init;
	}
	LOG_INFO("Initialize vport(0x%x) to %s mode\n", msg->hdr.vport,
		 pf_dev->vepa ? "vepa" : "veb");

	ret = dpp_vport_attr_set(pf_info, SRIOV_VPORT_PORT_BASE_QID, msg->vf_init_msg.base_qid);
	if (ret) {
		LOG_ERR("set_base_qid %d failed: %d\n", msg->vf_init_msg.base_qid, ret);
		goto err_init;
	}

	ret = dpp_vport_attr_set(pf_info, SRIOV_VPORT_SPOOFCHK_EN_OFF, vf_item->spoofchk);
	if (ret) {
		LOG_ERR("dpp_vport_attr_set spookchk %s failed: %d\n",
			vf_item->spoofchk ? "on" : "off", ret);
		goto err_init;
	}

	ret = zxdh_vf_init_vlan_recfg(vf_item, pf_info);
	if (ret) {
		LOG_ERR("zxdh_vf_init_vlan_recfg  %d\n", ret);
		goto err_init;
	}

	ret = zxdh_vf_flush_mac(pf_info, vf_item);
	if (ret)
		goto err_init;

	ret = dpp_fd_acl_all_delete(pf_info);
	if (ret) {
		LOG_ERR("dpp_fd_acl_all_delete failed! %d\n", ret);
		goto err_init;
	}

	ret = dpp_vport_attr_set(pf_info, SRIOV_VPORT_FD_VXLAN_OFFLOAD_EN, 0);
	if (ret) {
		LOG_ERR("dpp_vport_attr_set vxlan offload ip checksum failed: %d\n", ret);
		goto err_init;
	}

	ether_addr_copy(mac, vf_item->mac);
	if (is_zero_ether_addr(mac)) {
		get_random_bytes(mac, 6);
		mac[0] &= 0xfe;
		addr_type = NET_ADDR_RANDOM;
		LOG_INFO("vf set random mac %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n", mac[0], mac[1],
			 mac[2], mac[3], mac[4], mac[5]);
	}
	LOG_INFO("%s mac %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n", __func__, mac[0], mac[1], mac[2], mac[3],
		 mac[4], mac[5]);
	ret = dpp_add_mac(pf_info, mac, sriov_vlan_tpid, sriov_vlan_id);
	if (ret != 0) {
		LOG_ERR("dpp_add_mac failed, ret: %d\n", ret);
		goto err_init;
	}
	vf_item->vf_mac_info.current_unicast_num = 1;
	zxdh_pf_set_vf_mac_reg(pf_dev, mac, vf_idx);
	dpp_vport_uc_promisc_set(pf_info, 0);
	dpp_vport_mc_promisc_set(pf_info, 0);

	ether_addr_copy(vf_item->vf_mac_info.unicast_mac[0].mac_addr, mac);
	ether_addr_copy(reps->vf_init_msg.mac_addr, mac);
	reps->vf_init_msg.addr_assign_type = addr_type;
	reps->vf_init_msg.phy_port = pf_dev->phy_port;
	reps->vf_init_msg.link_up = pf_dev->link_up;
	reps->vf_init_msg.speed = pf_dev->speed;
	reps->vf_init_msg.duplex = pf_dev->duplex;
	reps->vf_init_msg.autoneg_enable = pf_dev->autoneg_enable;
	reps->vf_init_msg.sup_link_modes = pf_dev->supported_speed_modes;
	reps->vf_init_msg.adv_link_modes = pf_dev->advertising_speed_modes;
	reps->vf_init_msg.vlan_id = vf_item->vlan;
	reps->vf_init_msg.vlan_qos = vf_item->qos;

	LOG_INFO("%s plcr %u\n", __func__, vf_item->max_tx_rate);
	zxdh_plcr_recover_cfg(vf_item, pf_dev, vf_idx);

	zxdh_vf_link_state_get_proc(pf_dev, vf_item, vf_idx);

	vf_item->is_probed = true;
	return 0;

err_init:
	dpp_vport_delete(pf_info);
	return ret;
}

static s32 zxdh_vf_rate_clear(u16 vf_idx, struct zxdh_vf_item *vf_item,
			      struct zxdh_pf_device *pf_dev)
{
	struct zxdh_plcr_rate_limit_paras rate_limit_paras = { 0 };
	s32 rtn = 0;

	rate_limit_paras.req_type = E_RATE_LIMIT_REQ_VF_BYTE;
	rate_limit_paras.direction = E_RATE_LIMIT_TX;
	rate_limit_paras.mode = E_RATE_LIMIT_BYTE;
	rate_limit_paras.max_rate = 0;
	rate_limit_paras.min_rate = 0;
	rate_limit_paras.queue_id = PLCR_INVALID_PARAM;
	rate_limit_paras.vf_idx = vf_idx;
	rate_limit_paras.vfid = PLCR_INVALID_PARAM;
	rate_limit_paras.group_id = PLCR_INVALID_PARAM;

	rtn = zxdh_plcr_unified_set_rate_limit(pf_dev, &rate_limit_paras);
	if (PLCR_REMOVE_RATE_LIMIT == rtn || PLCR_DUPLICATE_RATE == rtn)
		return 0;

	return rtn;
}

static s32 zxdh_vf_rate_limit_health_set(u16 vf_idx, struct zxdh_vf_item *vf_item,
					 struct zxdh_pf_device *pf_dev)
{
	struct zxdh_plcr_rate_limit_paras rate_limit_paras = { 0 };
	s32 rtn = 0;

	PLCR_FUNC_DBG_ENTER();

	rate_limit_paras.req_type = E_RATE_LIMIT_REQ_VF_BYTE;
	rate_limit_paras.direction = E_RATE_LIMIT_TX;
	rate_limit_paras.mode = E_RATE_LIMIT_BYTE;
	rate_limit_paras.max_rate = vf_item->max_tx_rate;
	rate_limit_paras.min_rate = vf_item->min_tx_rate;
	rate_limit_paras.queue_id = PLCR_INVALID_PARAM;
	rate_limit_paras.vf_idx = vf_idx;
	rate_limit_paras.vfid = PLCR_INVALID_PARAM;
	rate_limit_paras.group_id = PLCR_INVALID_PARAM;

	rtn = zxdh_plcr_unified_set_rate_limit(pf_dev, &rate_limit_paras);
	if (PLCR_REMOVE_RATE_LIMIT == rtn || PLCR_DUPLICATE_RATE == rtn)
		return 0;

	return rtn;
}

static u32 zxdh_vf_mac_recover(struct dpp_pf_info_t *pf_info, struct zxdh_vf_item *vf_item)
{
	u16 sriov_vlan_id = ZXDH_VLAN_TCI_GEN(vf_item->vlan, vf_item->qos);
	u16 sriov_vlan_tpid = vf_item->vlan_proto;
	u32 i = 0;
	u32 err = 0;

	for (i = 0; i < DEV_UNICAST_MAX_NUM; ++i) {
		if (!is_zero_ether_addr(vf_item->vf_mac_info.unicast_mac[i].mac_addr)) {
			err = dpp_add_mac(pf_info, vf_item->vf_mac_info.unicast_mac[i].mac_addr,
					  sriov_vlan_tpid, sriov_vlan_id);
			ZXDH_CHECK_RET_RETURN(err, "dpp_add_unicast_mac[%d] failed: %d\n", i, err);
		}
	}

	for (i = 0; i < DEV_MULTICAST_MAX_NUM; ++i) {
		if (!is_zero_ether_addr(vf_item->vf_mac_info.multicast_mac[i].mac_addr)) {
			err = dpp_multi_mac_add_member(
				pf_info, vf_item->vf_mac_info.multicast_mac[i].mac_addr);
			ZXDH_CHECK_RET_RETURN(err, "dpp_add_multicast_mac[%d] failed: %d\n", i,
					      err);
		}
	}

	return 0;
}

static u32 zxdh_vf_item_reload(struct zxdh_pf_device *pf_dev, struct dpp_pf_info_t *pf_info,
			       struct zxdh_vf_item *vf_item, u16 vf_idx)
{
	u32 ret = 0;

	ret = zxdh_vf_mac_recover(pf_info, vf_item);
	ZXDH_CHECK_RET_RETURN(ret, "zxdh_vf_mac_recover failed! %d\n", ret);

	ret = dpp_vport_attr_set(pf_info, SRIOV_VPORT_SPOOFCHK_EN_OFF, vf_item->spoofchk);
	ZXDH_CHECK_RET_RETURN(ret, "spookchk %s failed: %d\n", vf_item->spoofchk ? "on" : "off",
			      ret);

	ret = zxdh_vf_init_vlan_recfg(vf_item, pf_info);
	ZXDH_CHECK_RET_RETURN(ret, "zxdh_vf_init_vlan_recfg  %d\n", ret);

	vf_item->is_probed = true;
	zxdh_vf_link_state_get_proc(pf_dev, vf_item, vf_idx);

	return ret;
}

s32 zxdh_vlan_trunk_recover(struct dpp_pf_info_t *pf_info, u8 *vlan_trunk_bitmap)
{
	int ret = 0;
	u16 vlan_idx = 0;
	u16 byte_index = 0;
	u8 bit_idx = 0;

	for (vlan_idx = 0; vlan_idx < 4096; vlan_idx++) {
		byte_index = vlan_idx / 8;
		bit_idx = vlan_idx % 8;
		if (vlan_trunk_bitmap[byte_index] & (1 << bit_idx)) {
			ret = dpp_add_vlan_filter(pf_info, vlan_idx);
			if (ret) {
				LOG_ERR("failed to recover vlan bit %d\n", vlan_idx);
				return -1;
			}
			LOG_DEBUG("dev-0x%x recover vlan-%d.\n", pf_info->vport, vlan_idx);
		}
	}
	return ret;
}
EXPORT_SYMBOL(zxdh_vlan_trunk_recover);

static u32 zxdh_vf_port_reload(struct zxdh_msg_info *msg, struct zxdh_reps_info *reps,
			       struct dpp_pf_info_t *pf_info, struct zxdh_vf_item *vf_item,
			       struct zxdh_pf_device *pf_dev)
{
	u16 vf_idx = msg->hdr.pcie_id & (0xff);
	struct zxdh_vf_reload_msg *eth_config = &msg->vf_reload_msg;
	u32 ret = 0;

	LOG_INFO("%s, vfindex%d\n", __func__, vf_idx);
	ret = dpp_vport_create(pf_info);
	ZXDH_CHECK_RET_RETURN(ret, "dpp_vport_create failed, ret: %d\n", ret);

	if (msg->vf_init_msg.is_upf) {
		ret = dpp_vport_attr_set(pf_info, SRIOV_VPORT_LAG_ID, 0);
		ZXDH_CHECK_RET_GOTO_ERR(ret, err_init,
					"dpp_vport_attr_set panel_id %d failed: %d\n",
					pf_dev->phy_port, ret);

		ret = dpp_vport_attr_set(pf_info, SRIOV_VPORT_LAG_EN_OFF, 1);
		ZXDH_CHECK_RET_GOTO_ERR(ret, err_init,
					"dpp_vport_attr_set SRIOV_VPORT_LAG_EN_OFF failed: %d\n",
					ret);
	} else {
		ret = dpp_vport_attr_set(pf_info, SRIOV_VPORT_UPLINK_PHY_PORT_ID, pf_dev->phy_port);
		ZXDH_CHECK_RET_GOTO_ERR(ret, err_init,
					"dpp_vport_attr_set panel_id %d failed: %d\n",
					pf_dev->phy_port, ret);
	}

	ret = dpp_vport_attr_set(pf_info, SRIOV_VPORT_HASH_SEARCH_INDEX,
				 eth_config->hash_search_idx);
	ZXDH_CHECK_RET_GOTO_ERR(ret, err_init, "dpp_vport_attr_set hash_search_idx %u failed: %d\n",
				eth_config->hash_search_idx, ret);

	ret = dpp_vport_bond_pf(pf_info);
	ZXDH_CHECK_RET_GOTO_ERR(ret, err_init, "dpp_vport_bond_pf failed, ret: %d\n", ret);

	ret = dpp_vport_hash_funcs_set(pf_info, eth_config->hash_func);
	ZXDH_CHECK_RET_GOTO_ERR(ret, err_init, "dpp_vport_hash_funcs_set failed, ret: %d\n", ret);

	ret = dpp_vport_rx_flow_hash_set(pf_info, eth_config->hash_mode);
	ZXDH_CHECK_RET_GOTO_ERR(ret, err_init, "dpp_vport_rx_flow_hash_set failed, ret: %d\n", ret);

	ret = dpp_vport_attr_set(pf_info, SRIOV_VPORT_VEPA_EN_OFF, (u32)pf_dev->vepa);
	ZXDH_CHECK_RET_GOTO_ERR(ret, err_init,
				"dpp_vport_attr_set vport(0x%x) %s mode failed: %d\n",
				msg->hdr.vport, pf_dev->vepa ? "vepa" : "veb", ret);
	LOG_INFO("Initialize vport(0x%x) to %s mode\n", msg->hdr.vport,
		 pf_dev->vepa ? "vepa" : "veb");

	ret = dpp_vport_attr_set(pf_info, SRIOV_VPORT_PORT_BASE_QID, eth_config->base_qid);
	ZXDH_CHECK_RET_GOTO_ERR(ret, err_init, "set_base_qid %d failed: %d\n", eth_config->base_qid,
				ret);

	ret = dpp_rxfh_set(pf_info, eth_config->queue_map, ZXDH_INDIR_RQT_SIZE);
	ZXDH_CHECK_RET_GOTO_ERR(ret, err_init, "dpp_rxfh_set failed: %d\n", ret);

	ret = dpp_fd_acl_all_delete(pf_info);
	ZXDH_CHECK_RET_GOTO_ERR(ret, err_init, "dpp_fd_acl_all_delete failed: %d\n", ret);

	if (vf_item->trusted) {
		dpp_vport_uc_promisc_set(pf_info, eth_config->uc_promisc);
		dpp_vport_mc_promisc_set(pf_info, eth_config->mc_promisc);
		if (eth_config->uc_promisc)
			dpp_vport_promisc_en_set(pf_info, 1);
	}

	//SRIOV_CONFIG
	ret = zxdh_vf_item_reload(pf_dev, pf_info, vf_item, vf_idx);
	ZXDH_CHECK_RET_GOTO_ERR(ret, err_init, "sriov_config_recover failed! %d\n", ret);

	ret = zxdh_vlan_trunk_recover(pf_info, eth_config->vlan_trunk_bitmap);
	ZXDH_CHECK_RET_GOTO_ERR(ret, err_init, "vlan_trunk_tbl_recover failed! %d\n", ret);

	ret = zxdh_vf_rate_clear(vf_idx, vf_item, pf_dev);
	ZXDH_CHECK_RET_RETURN(ret, "zxdh_vf_rate_clear failed: %d\n", ret);

	ret = zxdh_vf_rate_limit_health_set(vf_idx, vf_item, pf_dev);
	ZXDH_CHECK_RET_RETURN(ret, "zxdh_vf_rate_limit_health_set failed: %d\n", ret);

	return 0;

err_init:
	dpp_vport_delete(pf_info);
	return ret;
}

static u32 zxdh_vf_port_uninit(struct zxdh_msg_info *msg, struct zxdh_reps_info *reps,
			       struct dpp_pf_info_t *pf_info, struct zxdh_vf_item *vf_item,
			       struct zxdh_pf_device *pf_dev)
{
	s32 ret = 0;

	dpp_vport_uc_promisc_set(pf_info, 0);
	dpp_vport_mc_promisc_set(pf_info, 0);

	ret = dpp_fd_acl_all_delete(pf_info);
	if (ret != 0) {
		LOG_ERR("dpp_fd_acl_all_delete failed! %d\n", ret);
		return ret;
	}

	ret = dpp_vqm_vfid_vlan_delete(pf_info);
	if (ret != 0) {
		LOG_ERR("dpp_vport_vlan_filter_en_set failed, ret: %d\n", ret);
		return ret;
	}

	ret = dpp_vlan_filter_init(pf_info);
	if (ret != 0) {
		LOG_ERR("dpp_vlan_filter_init failed: %d\n", ret);
		return ret;
	}

	ret = zxdh_vf_flush_mac(pf_info, vf_item);
	if (ret != 0) {
		LOG_ERR("zxdh_vf_flush_macf failed, ret: %d\n", ret);
		return ret;
	}

	ret = dpp_vport_unbond_pf(pf_info);
	if (ret != 0) {
		LOG_ERR("dpp_vport_unbond_pf failed, ret: %d\n", ret);
		return ret;
	}

	ret = dpp_vport_delete(pf_info);
	if (ret != 0) {
		LOG_ERR("dpp_vport_delete failed, ret: %d\n", ret);
		return ret;
	}

	ret = dpp_vport_unregister(pf_info);
	if (ret != 0) {
		LOG_ERR("dpp_vport_unregister failed, ret: %d\n", ret);
		return ret;
	}

	vf_item->is_probed = false;
	return ret;
}

void zxdh_vf_item_mac_add(struct zxdh_vf_item *vf_item, u8 *mac_addr, u8 dhtool_mac_set_flag)
{
	u8 *addr = NULL;
	u8 i = 0;

	if (is_unicast_ether_addr(mac_addr)) {
		for (i = 0; i < DEV_UNICAST_MAX_NUM; ++i) {
			if (ether_addr_equal(mac_addr,
					     vf_item->vf_mac_info.unicast_mac[i].mac_addr)) {
				vf_item->vf_mac_info.unicast_mac[i].dhtool_mac_set_flag =
					dhtool_mac_set_flag;
				return;
			}
		}
		for (i = 1; i < DEV_UNICAST_MAX_NUM; ++i) {
			addr = vf_item->vf_mac_info.unicast_mac[i].mac_addr;
			if (is_zero_ether_addr(addr)) {
				memcpy(addr, mac_addr, ETH_ALEN);
				vf_item->vf_mac_info.unicast_mac[i].dhtool_mac_set_flag =
					dhtool_mac_set_flag;
				vf_item->vf_mac_info.current_unicast_num++;
				break;
			}
		}
	} else {
		for (i = 0; i < DEV_MULTICAST_MAX_NUM; ++i) {
			if (ether_addr_equal(mac_addr,
					     vf_item->vf_mac_info.multicast_mac[i].mac_addr)) {
				vf_item->vf_mac_info.multicast_mac[i].dhtool_mac_set_flag =
					dhtool_mac_set_flag;
				return;
			}
		}
		for (i = 0; i < DEV_MULTICAST_MAX_NUM; ++i) {
			addr = vf_item->vf_mac_info.multicast_mac[i].mac_addr;
			if (is_zero_ether_addr(addr)) {
				memcpy(addr, mac_addr, ETH_ALEN);
				vf_item->vf_mac_info.multicast_mac[i].dhtool_mac_set_flag =
					dhtool_mac_set_flag;
				vf_item->vf_mac_info.current_multicast_num++;
				break;
			}
		}
	}
}
EXPORT_SYMBOL(zxdh_vf_item_mac_add);

void zxdh_vf_item_mac_del(struct zxdh_vf_item *vf_item, u8 *mac_addr)
{
	u8 i = 0;
	u8 *addr = NULL;

	if (is_unicast_ether_addr(mac_addr)) {
		for (i = 1; i < DEV_UNICAST_MAX_NUM; ++i) {
			addr = vf_item->vf_mac_info.unicast_mac[i].mac_addr;

			if (ether_addr_equal(addr, mac_addr)) {
				LOG_DEBUG("the mac is %pM\n", addr);

				memset(&vf_item->vf_mac_info.unicast_mac[i], 0, ETH_ALEN);
				vf_item->vf_mac_info.current_unicast_num--;
				break;
			}
		}
	} else {
		for (i = 0; i < DEV_MULTICAST_MAX_NUM; ++i) {
			addr = vf_item->vf_mac_info.multicast_mac[i].mac_addr;

			if (ether_addr_equal(addr, mac_addr)) {
				LOG_DEBUG("the mac is %pM\n", addr);

				memset(&vf_item->vf_mac_info.multicast_mac[i], 0, ETH_ALEN);
				vf_item->vf_mac_info.current_multicast_num--;
				break;
			}
		}
	}
}
EXPORT_SYMBOL(zxdh_vf_item_mac_del);

static u32 zxdh_vf_mac_add(struct zxdh_msg_info *msg, struct zxdh_reps_info *reps,
			   struct dpp_pf_info_t *pf_info, struct zxdh_vf_item *vf_item,
			   struct zxdh_pf_device *pf_dev)
{
	s32 ret = 0;
	u16 sriov_vlan_tpid = vf_item->vlan_proto;
	u16 sriov_vlan_id = ZXDH_VLAN_TCI_GEN(vf_item->vlan, vf_item->qos);

	ether_addr_copy(vf_item->vf_mac_info.unicast_mac[0].mac_addr,
			msg->mac_addr_set_msg.mac_addr);
	ret = dpp_add_mac(pf_info, msg->mac_addr_set_msg.mac_addr, sriov_vlan_tpid, sriov_vlan_id);
	if (ret != 0)
		LOG_ERR("dpp_add_mac failed, ret: %d\n", ret);

	return ret;
}

static u32 zxdh_vf_mac_del(struct zxdh_msg_info *msg, struct zxdh_reps_info *reps,
			   struct dpp_pf_info_t *pf_info, struct zxdh_vf_item *vf_item,
			   struct zxdh_pf_device *pf_dev)
{
	s32 ret = 0;
	u8 i = 0;
	u8 *addr = NULL;
	u16 sriov_vlan_tpid = vf_item->vlan_proto;
	u16 sriov_vlan_id = ZXDH_VLAN_TCI_GEN(vf_item->vlan, vf_item->qos);

	if (msg->mac_addr_set_msg.mac_flag) {
		ret = dpp_del_mac(pf_info, msg->mac_addr_set_msg.mac_addr, sriov_vlan_tpid,
				  sriov_vlan_id);
		if (ret != 0) {
			LOG_ERR("dpp_del_mac failed, ret: %d\n", ret);
			return ret;
		}
	} else if (msg->mac_addr_set_msg.mac_addr == vf_item->vf_mac_info.unicast_mac[0].mac_addr) {
		for (i = 1; i < DEV_UNICAST_MAX_NUM; ++i) {
			addr = vf_item->vf_mac_info.unicast_mac[i].mac_addr;
			if (is_zero_ether_addr(addr)) {
				memcpy(addr, vf_item->vf_mac_info.unicast_mac[0].mac_addr,
				       ETH_ALEN);
				break;
			}
		}
	}

	return ret;
}

static u32 zxdh_vf_filter_mac_add(struct zxdh_msg_info *msg, struct zxdh_reps_info *reps,
				  struct dpp_pf_info_t *pf_info, struct zxdh_vf_item *vf_item,
				  struct zxdh_pf_device *pf_dev)
{
	u32 err = 0;
	u16 sriov_vlan_tpid = vf_item->vlan_proto;
	u16 sriov_vlan_id = ZXDH_VLAN_TCI_GEN(vf_item->vlan, vf_item->qos);

	LOG_DEBUG("msg->mac_addr_set_msg.mac_addr is %pM\n", msg->mac_addr_set_msg.mac_addr);

	err = dpp_add_mac(pf_info, msg->mac_addr_set_msg.mac_addr, sriov_vlan_tpid, sriov_vlan_id);
	if (err != 0) {
		LOG_ERR("dpp_add_mac failed\n");
		return err;
	}

	zxdh_vf_item_mac_add(vf_item, msg->mac_addr_set_msg.mac_addr, 0);

	return err;
}

static u32 zxdh_vf_filter_mac_del(struct zxdh_msg_info *msg, struct zxdh_reps_info *reps,
				  struct dpp_pf_info_t *pf_info, struct zxdh_vf_item *vf_item,
				  struct zxdh_pf_device *pf_dev)
{
	u32 err = 0;
	u16 sriov_vlan_tpid = vf_item->vlan_proto;
	u16 sriov_vlan_id = ZXDH_VLAN_TCI_GEN(vf_item->vlan, vf_item->qos);

	LOG_DEBUG("msg->mac_addr_set_msg.mac_addr is %pM\n", msg->mac_addr_set_msg.mac_addr);

	err = dpp_del_mac(pf_info, msg->mac_addr_set_msg.mac_addr, sriov_vlan_tpid, sriov_vlan_id);
	if (err != 0) {
		LOG_ERR("dpp_mac_del failed\n");
		return err;
	}

	zxdh_vf_item_mac_del(vf_item, msg->mac_addr_set_msg.mac_addr);

	return err;
}

static u32 zxdh_vf_multi_mac_add(struct zxdh_msg_info *msg, struct zxdh_reps_info *reps,
				 struct dpp_pf_info_t *pf_info, struct zxdh_vf_item *vf_item,
				 struct zxdh_pf_device *pf_dev)
{
	u32 err = 0;

	LOG_DEBUG("msg->mac_addr_set_msg.mac_addr is %pM\n", msg->mac_addr_set_msg.mac_addr);

	if (vf_item->vf_mac_info.current_multicast_num >= VF_MAX_MULTICAST_MAC) {
		LOG_ERR("vf multicast mac num:%u beyond 32",
			vf_item->vf_mac_info.current_multicast_num);
		return ZXDH_REPS_BEYOND_MAC;
	}

	err = dpp_multi_mac_add_member(pf_info, msg->mac_addr_set_msg.mac_addr);
	if (err != 0) {
		if (err == DPP_RC_TBL_IS_FULL) {
			LOG_ERR("multicast mac is beyond whole transfer num\n");
			return ZXDH_REPS_BEYOND_MAC;
		}
		LOG_ERR("dpp_multi_mac_add_member failed %d\n", err);
		return err;
	}

	zxdh_vf_item_mac_add(vf_item, msg->mac_addr_set_msg.mac_addr, 0);

	return err;
}

static u32 zxdh_vf_multi_mac_del(struct zxdh_msg_info *msg, struct zxdh_reps_info *reps,
				 struct dpp_pf_info_t *pf_info, struct zxdh_vf_item *vf_item,
				 struct zxdh_pf_device *pf_dev)
{
	u32 err = 0;

	LOG_DEBUG("msg->mac_addr_set_msg.mac_addr is %pM\n", msg->mac_addr_set_msg.mac_addr);

	err = dpp_multi_mac_del_member(pf_info, msg->mac_addr_set_msg.mac_addr);
	if (err != 0) {
		LOG_INFO("dpp_multi_mac_del_member failed %d\n", err);
		return err;
	}

	zxdh_vf_item_mac_del(vf_item, msg->mac_addr_set_msg.mac_addr);

	return err;
}

static bool zxdh_check_item_mac_exists(struct dpp_pf_info_t *pf_info, struct zxdh_pf_device *pf_dev,
				       u16 vf_idx, struct zxdh_vf_item *vf_item,
				       const unsigned char *target_mac)
{
	u32 i = 0;
	struct zxdh_vf_item *cur_vf_item = NULL;
	u16 sriov_vlan_id = 0;
	u16 sriov_vlan_tpid = 0;
	struct dh_core_dev *dh_dev = container_of((void *)(pf_dev), struct dh_core_dev, priv);
	struct pci_dev *pdev = dh_dev->pdev;
	int num_vfs = pci_num_vf(pdev);

	sriov_vlan_id = ZXDH_VLAN_TCI_GEN(vf_item->vlan, vf_item->qos);
	sriov_vlan_tpid = vf_item->vlan_proto;
	for (i = 0; i < num_vfs; i++) {
		if (i == vf_idx)
			continue;

		cur_vf_item = &pf_dev->vf_item[i];
		if (ether_addr_equal(cur_vf_item->mac, target_mac) &&
		    ((ZXDH_VLAN_TCI_GEN(cur_vf_item->vlan, cur_vf_item->qos) == sriov_vlan_id) &&
		     (cur_vf_item->vlan_proto == sriov_vlan_tpid))) {
			LOG_INFO("Mac already exists vf %d\n", i);
			return true;
		}
	}

	return false;
}

static u32 zxdh_vf_all_mac_dump(struct zxdh_msg_info *msg, struct zxdh_reps_info *reps,
				struct dpp_pf_info_t *pf_info, struct zxdh_vf_item *vf_item,
				struct zxdh_pf_device *pf_dev)
{
	u32 err = 0;
	u16 current_vport = 0;
	u16 vport = vf_item->vport;
	u16 sriov_vlan_id = ZXDH_VLAN_TCI_GEN(vf_item->vlan, vf_item->qos);
	u16 sriov_vlan_tpid = vf_item->vlan_proto;
	u16 vf_idx = msg->hdr.pcie_id & (0xff);

	err = dpp_unicast_mac_search(pf_info, msg->mac_addr_set_msg.mac_addr, sriov_vlan_tpid,
				     sriov_vlan_id, &current_vport);
	if ((err == 0) && (vport == current_vport)) {
		return 0;
	} else if ((err == 0) && (vport != current_vport)) {
		LOG_ERR("Mac already exists\n");
		return ZXDH_REPS_EXIST_MAC;
	} else if ((err != 0) && (err != DPP_HASH_RC_SRH_FAIL)) {
		LOG_ERR("dpp_unicast_mac_search failed, ret:%d\n", err);
		return 1;
	}

	if (zxdh_check_item_mac_exists(pf_info, pf_dev, vf_idx, vf_item,
				       msg->mac_addr_set_msg.mac_addr)) {
		LOG_ERR("Mac already exists\n");
		return ZXDH_REPS_EXIST_MAC;
	}

	return 0;
}

static u32 zxdh_vf_all_mac_add(struct zxdh_msg_info *msg, struct zxdh_reps_info *reps,
			       struct dpp_pf_info_t *pf_info, struct zxdh_vf_item *vf_item,
			       struct zxdh_pf_device *pf_dev)
{
	u32 err = 0;
	struct MAC_VPORT_INFO *p_mac_arr = NULL;
	u32 p_mac_num = 0;
	u16 current_vport = 0;
	u16 vport = vf_item->vport;
	u16 sriov_vlan_id = 0;
	u16 sriov_vlan_tpid = 0;
	u32 max_unicast_num = 0;
	u16 vf_idx = msg->hdr.pcie_id & (0xff);

	if (!is_unicast_ether_addr(msg->mac_addr_set_msg.mac_addr) &&
	    !is_link_local_ether_addr(msg->mac_addr_set_msg.mac_addr)) {
		return zxdh_vf_multi_mac_add(msg, reps, pf_info, vf_item, pf_dev);
	}

	mutex_lock(&vf_item->lock);
	sriov_vlan_id = ZXDH_VLAN_TCI_GEN(vf_item->vlan, vf_item->qos);
	sriov_vlan_tpid = vf_item->vlan_proto;

	err = dpp_unicast_mac_search(pf_info, msg->mac_addr_set_msg.mac_addr, sriov_vlan_tpid,
				     sriov_vlan_id, &current_vport);
	if ((err == 0) && (vport == current_vport)) {
		mutex_unlock(&vf_item->lock);
		return 0;
	} else if ((err == 0) && (vport != current_vport)) {
		LOG_ERR("Mac already exists\n");
		mutex_unlock(&vf_item->lock);
		return ZXDH_REPS_EXIST_MAC;
	} else if ((err != 0) && (err != DPP_HASH_RC_SRH_FAIL)) {
		LOG_ERR("dpp_unicast_mac_search failed, ret:%d\n", err);
		mutex_unlock(&vf_item->lock);
		return 1;
	}

	if (zxdh_check_item_mac_exists(pf_info, pf_dev, vf_idx, vf_item,
				       msg->mac_addr_set_msg.mac_addr)) {
		LOG_ERR("Mac already exists\n");
		mutex_unlock(&vf_item->lock);
		return ZXDH_REPS_EXIST_MAC;
	}

	if (msg->mac_addr_set_msg.filter_flag == UNFILTER_MAC) {
		err = zxdh_vf_mac_add(msg, reps, pf_info, vf_item, pf_dev);
		if (err != 0)
			LOG_ERR("zxdh_vf_mac_add failed\n");
		mutex_unlock(&vf_item->lock);
		return err;
	}

	if (vf_item->vf_mac_info.current_unicast_num >= VF_MAX_UNICAST_MAC) {
		LOG_ERR("vf unicast mac num:%u beyond 128",
			vf_item->vf_mac_info.current_unicast_num);
		mutex_unlock(&vf_item->lock);
		return ZXDH_REPS_BEYOND_MAC;
	}

	err = dpp_unicast_mac_dump(pf_info, p_mac_arr, &p_mac_num);
	if (err != 0) {
		LOG_ERR("dpp_unicast_mac_dump failed, ret:%d\n", err);
		mutex_unlock(&vf_item->lock);
		return err;
	}
	LOG_INFO("p_mac_num is %d\n", p_mac_num);

	err = dpp_unicast_mac_max_get(pf_info, &max_unicast_num);
	if (err != 0) {
		LOG_ERR("dpp_unicast_mac_max_get failed %u\n", max_unicast_num);
		mutex_unlock(&vf_item->lock);
		return err;
	}

	if (p_mac_num >= max_unicast_num) {
		LOG_ERR("curr_all_unicast_num is beyond maximum\n");
		mutex_unlock(&vf_item->lock);
		return ZXDH_REPS_BEYOND_MAC;
	}

	err = zxdh_vf_filter_mac_add(msg, reps, pf_info, vf_item, pf_dev);
	if (err != 0)
		LOG_ERR("dpp_unicast_mac_dump failed\n");
	mutex_unlock(&vf_item->lock);
	return err;
}
static u32 zxdh_vf_all_mac_del(struct zxdh_msg_info *msg, struct zxdh_reps_info *reps,
			       struct dpp_pf_info_t *pf_info, struct zxdh_vf_item *vf_item,
			       struct zxdh_pf_device *pf_dev)
{
	u32 err = 0;

	if (!is_unicast_ether_addr(msg->mac_addr_set_msg.mac_addr) &&
	    !is_link_local_ether_addr(msg->mac_addr_set_msg.mac_addr)) {
		return zxdh_vf_multi_mac_del(msg, reps, pf_info, vf_item, pf_dev);
	}

	mutex_lock(&vf_item->lock);

	if (msg->mac_addr_set_msg.filter_flag == UNFILTER_MAC) {
		err = zxdh_vf_mac_del(msg, reps, pf_info, vf_item, pf_dev);
		if (err != 0)
			LOG_ERR("zxdh_vf_mac_del failed\n");
		mutex_unlock(&vf_item->lock);
		return err;
	}

	err = zxdh_vf_filter_mac_del(msg, reps, pf_info, vf_item, pf_dev);
	if (err != 0)
		LOG_ERR("zxdh_vf_filter_mac_del failed\n");

	mutex_unlock(&vf_item->lock);
	return err;
}

static u32 zxdh_vf_ipv6_mac_add(struct zxdh_msg_info *msg, struct zxdh_reps_info *reps,
				struct dpp_pf_info_t *pf_info, struct zxdh_vf_item *vf_item,
				struct zxdh_pf_device *pf_dev)
{
	u32 err = 0;

	mutex_lock(&pf_dev->ip6mac_tbl->mlock);

	err = zxdh_vf_multi_mac_add(msg, reps, pf_info, vf_item, pf_dev);
	if (err != 0)
		LOG_ERR("zxdh_vf_multi_mac_add failed\n");

	mutex_unlock(&pf_dev->ip6mac_tbl->mlock);

	return err;
}

static u32 zxdh_vf_ipv6_mac_del(struct zxdh_msg_info *msg, struct zxdh_reps_info *reps,
				struct dpp_pf_info_t *pf_info, struct zxdh_vf_item *vf_item,
				struct zxdh_pf_device *pf_dev)
{
	u32 err = 0;

	mutex_lock(&pf_dev->ip6mac_tbl->mlock);

	err = zxdh_vf_multi_mac_del(msg, reps, pf_info, vf_item, pf_dev);
	if (err != 0)
		LOG_ERR("zxdh_vf_multi_mac_del failed\n");

	mutex_unlock(&pf_dev->ip6mac_tbl->mlock);

	return err;
}

static u32 zxdh_vf_lacp_mac_add(struct zxdh_msg_info *msg, struct zxdh_reps_info *reps,
				struct dpp_pf_info_t *pf_info, struct zxdh_vf_item *vf_item,
				struct zxdh_pf_device *pf_dev)
{
	u32 err = 0;

	err = zxdh_vf_multi_mac_add(msg, reps, pf_info, vf_item, pf_dev);
	if (err != 0)
		LOG_ERR("zxdh_vf_multi_mac_add failed\n");

	return err;
}

static u32 zxdh_vf_lacp_mac_del(struct zxdh_msg_info *msg, struct zxdh_reps_info *reps,
				struct dpp_pf_info_t *pf_info, struct zxdh_vf_item *vf_item,
				struct zxdh_pf_device *pf_dev)
{
	u32 err = 0;

	err = zxdh_vf_multi_mac_del(msg, reps, pf_info, vf_item, pf_dev);
	if (err != 0)
		LOG_ERR("zxdh_vf_multi_mac_del failed\n");

	return err;
}

static u32 zxdh_vf_mac_get(struct zxdh_msg_info *msg, struct zxdh_reps_info *reps,
			   struct dpp_pf_info_t *pf_info, struct zxdh_vf_item *vf_item,
			   struct zxdh_pf_device *pf_dev)
{
	ether_addr_copy(reps->vf_mac_addr_get_msg.mac_addr, vf_item->mac);
	return 0;
}

static u32 zxdh_vf_rss_state_set(struct zxdh_msg_info *msg, struct zxdh_reps_info *reps,
				 struct dpp_pf_info_t *pf_info, struct zxdh_vf_item *vf_item,
				 struct zxdh_pf_device *pf_dev)
{
	return dpp_vport_rss_en_set(pf_info, msg->rss_enable_msg.rss_enable);
}

static u32 zxdh_vf_fd_state_set(struct zxdh_msg_info *msg, struct zxdh_reps_info *reps,
				struct dpp_pf_info_t *pf_info, struct zxdh_vf_item *vf_item,
				struct zxdh_pf_device *pf_dev)
{
	return dpp_vport_fd_en_set(pf_info, msg->vf_fd_enable_msg.fd_enable);
}

static u32 zxdh_vf_rxfh_set(struct zxdh_msg_info *msg, struct zxdh_reps_info *reps,
			    struct dpp_pf_info_t *pf_info, struct zxdh_vf_item *vf_item,
			    struct zxdh_pf_device *pf_dev)
{
	return dpp_rxfh_set(pf_info, msg->rxfh_set_msg.queue_map, ZXDH_INDIR_RQT_SIZE);
}

static u32 zxdh_vf_rxfh_get(struct zxdh_msg_info *msg, struct zxdh_reps_info *reps,
			    struct dpp_pf_info_t *pf_info, struct zxdh_vf_item *vf_item,
			    struct zxdh_pf_device *pf_dev)
{
	u32 err = 0;

	err = dpp_rxfh_get(pf_info, reps->rxfh_get_msg.queue_map, ZXDH_INDIR_RQT_SIZE);
	if (err != 0) {
		LOG_ERR("dpp_rxfh_get failed: %d\n", err);
		return err;
	}

	return 0;
}

static u32 zxdh_vf_rxfh_del(struct zxdh_msg_info *msg, struct zxdh_reps_info *reps,
			    struct dpp_pf_info_t *pf_info, struct zxdh_vf_item *vf_item,
			    struct zxdh_pf_device *pf_dev)
{
	return dpp_rxfh_del(pf_info);
}

static u32 zxdh_vf_thash_key_set(struct zxdh_msg_info *msg, struct zxdh_reps_info *reps,
				 struct dpp_pf_info_t *pf_info, struct zxdh_vf_item *vf_item,
				 struct zxdh_pf_device *pf_dev)
{
	return dpp_thash_key_set(pf_info, msg->thash_key_set_msg.key_map, ZXDH_NET_HASH_KEY_SIZE);
}

static u32 zxdh_vf_thash_key_get(struct zxdh_msg_info *msg, struct zxdh_reps_info *reps,
				 struct dpp_pf_info_t *pf_info, struct zxdh_vf_item *vf_item,
				 struct zxdh_pf_device *pf_dev)
{
	return dpp_thash_key_get(pf_info, reps->thash_key_set_msg.key_map, ZXDH_NET_HASH_KEY_SIZE);
}

static u32 zxdh_vf_hash_funcs_set(struct zxdh_msg_info *msg, struct zxdh_reps_info *reps,
				  struct dpp_pf_info_t *pf_info, struct zxdh_vf_item *vf_item,
				  struct zxdh_pf_device *pf_dev)
{
	return dpp_vport_hash_funcs_set(pf_info, msg->hfunc_set_msg.func);
}

static u32 zxdh_vf_rx_flow_hash_set(struct zxdh_msg_info *msg, struct zxdh_reps_info *reps,
				    struct dpp_pf_info_t *pf_info, struct zxdh_vf_item *vf_item,
				    struct zxdh_pf_device *pf_dev)
{
	return dpp_vport_rx_flow_hash_set(pf_info, msg->rx_flow_hash_set_msg.hash_mode);
}

int zxdh_vf_switch_business_vlan(struct dpp_pf_info_t *pf_info, u8 type, u32 wanted_feature)
{
	int ret = 0;
	struct zxdh_vqm_vfid_vlan_t vf_vlan_attr = { 0 };
	bool old_vport_bit = 0;
	bool wanted_vport_bit = 0;
	u32 *changed_vlan_attr = NULL;

	if (type >= sizeof(vf_vlan_attr) / sizeof(vf_vlan_attr.rsv)) {
		LOG_ERR("%s para type err: %u.\n", __func__, type);
		return -1;
	}
	changed_vlan_attr = (u32 *)&vf_vlan_attr + type;
	ret = dpp_vqm_vfid_vlan_get(pf_info, &vf_vlan_attr);
	if (ret != 0) {
		LOG_ERR("dpp_vqm_vfid_vlan_get failed: %d.\n", ret);
		return -1;
	}
	old_vport_bit = vf_vlan_attr.sriov_business_qinq_vlan_strip_offload |
			vf_vlan_attr.sriov_business_vlan_filter |
			vf_vlan_attr.sriov_business_vlan_strip_offload;
	*changed_vlan_attr = wanted_feature;
	wanted_vport_bit = vf_vlan_attr.sriov_business_qinq_vlan_strip_offload |
			   vf_vlan_attr.sriov_business_vlan_filter |
			   vf_vlan_attr.sriov_business_vlan_strip_offload;

	ret = dpp_vqm_vfid_vlan_set(pf_info, type, wanted_feature);
	if (ret != 0) {
		LOG_ERR("dpp_vqm_vfid_vlan_set, ret: %d\n", ret);
		return -1;
	}

	if (!(old_vport_bit ^ wanted_vport_bit))
		return 0;

	ret = dpp_vport_business_vlan_offload_en_set(pf_info, wanted_vport_bit);
	if (ret != 0) {
		LOG_ERR("dpp_vport_business_vlan_offload_en_set, ret: %d\n", ret);
		return -1;
	}

	return 0;
}

static u32 zxdh_vf_vlan_strip_set(struct zxdh_msg_info *msg, struct zxdh_reps_info *reps,
				  struct dpp_pf_info_t *pf_info, struct zxdh_vf_item *vf_item,
				  struct zxdh_pf_device *pf_dev)
{
	if (msg->vlan_strip_msg.flag == VLAN_STRIP_MSG_TYPE) {
		return zxdh_vf_switch_business_vlan(pf_info, VLAN_SRIOV_BUSINESS_VLAN_STRIP_OFFLIAD,
						    msg->vlan_strip_msg.enable);
	} else {
		return zxdh_vf_switch_business_vlan(pf_info,
						    VLAN_SRIOV_BUSINESS_QINQ_VLAN_STRIP_OFFLOAD,
						    msg->vlan_strip_msg.enable);
	}
}

static u32 zxdh_vf_vxlan_offload_add(struct zxdh_msg_info *msg, struct zxdh_reps_info *reps,
				     struct dpp_pf_info_t *pf_info, struct zxdh_vf_item *vf_item,
				     struct zxdh_pf_device *pf_dev)
{
	u32 mcode_glb_cfg = 0;
	u32 ret = 0;

	ret = dpp_glb_cfg_get_0(pf_info, &mcode_glb_cfg);
	if (ret != 0) {
		LOG_ERR("dpp_pktrx_mcode_glb_cfg_get_0 failed: %d\n", ret);
		return -1;
	}

	mcode_glb_cfg = (mcode_glb_cfg & 0xFFFF0000) | msg->vf_vxlan_port.port;
	ret = dpp_glb_cfg_set_0(pf_info, mcode_glb_cfg);
	if (ret != 0) {
		LOG_ERR("dpp_pktrx_mcode_glb_cfg_set_0 failed: %d\n", ret);
		return -1;
	}

	return 0;
}

static u32 zxdh_vf_vxlan_offload_del(struct zxdh_msg_info *msg, struct zxdh_reps_info *reps,
				     struct dpp_pf_info_t *pf_info, struct zxdh_vf_item *vf_item,
				     struct zxdh_pf_device *pf_dev)
{
	u32 mcode_glb_cfg = 0;
	u16 vxlan_port_cfg = 0;
	u32 ret = 0;

	ret = dpp_glb_cfg_get_0(pf_info, &mcode_glb_cfg);
	if (ret != 0) {
		LOG_ERR("dpp_pktrx_mcode_glb_cfg_get_0 failed: %d\n", ret);
		return -1;
	}

	vxlan_port_cfg = mcode_glb_cfg & 0x0000FFFF;
	if (vxlan_port_cfg != msg->vf_vxlan_port.port) {
		LOG_ERR("del vxlan offload failed,port[%d] no equals to del_port[%d]\n",
			vxlan_port_cfg, msg->vf_vxlan_port.port);
		return -1;
	}

	mcode_glb_cfg = mcode_glb_cfg & 0xFFFF0000;
	ret = dpp_glb_cfg_set_0(pf_info, mcode_glb_cfg);
	if (ret != 0) {
		LOG_ERR("dpp_pktrx_mcode_glb_cfg_set_0 failed: %d\n", ret);
		return -1;
	}

	return 0;
}

static u32 zxdh_vf_qinq_tpid_cfg(struct zxdh_msg_info *msg, struct zxdh_reps_info *reps,
				 struct dpp_pf_info_t *pf_info, struct zxdh_vf_item *vf_item,
				 struct zxdh_pf_device *pf_dev)
{
	return dpp_vqm_vfid_vlan_set(pf_info, VLAN_SRIOV_BUSINESS_VLAN_TPID,
				     msg->tpid_cfg_msg.tpid);
}

static u32 zxdh_vf_rx_flow_hash_get(struct zxdh_msg_info *msg, struct zxdh_reps_info *reps,
				    struct dpp_pf_info_t *pf_info, struct zxdh_vf_item *vf_item,
				    struct zxdh_pf_device *pf_dev)
{
	return dpp_vport_rx_flow_hash_get(pf_info, &reps->rx_flow_hash_set_msg.hash_mode);
}

static u32 zxdh_vf_port_attrs_set(struct zxdh_msg_info *msg, struct zxdh_reps_info *reps,
				  struct dpp_pf_info_t *pf_info, struct zxdh_vf_item *vf_item,
				  struct zxdh_pf_device *pf_dev)
{
	u32 err = 0;

	if (msg->port_attr_set_msg.mode == SRIOV_VPORT_TCP_UDP_CHKSUM) {
		err = dpp_vport_attr_set(pf_info, SRIOV_VPORT_IP_CHKSUM,
					 msg->port_attr_set_msg.value);
		if (err != 0) {
			LOG_ERR("dpp_vport_ip_checksum_set failed: %u\n", err);
			return err;
		}
	}

	return dpp_vport_attr_set(pf_info, msg->port_attr_set_msg.mode,
				  msg->port_attr_set_msg.value);
}

static u32 zxdh_vf_port_attrs_get(struct zxdh_msg_info *msg, struct zxdh_reps_info *reps,
				  struct dpp_pf_info_t *pf_info, struct zxdh_vf_item *vf_item,
				  struct zxdh_pf_device *pf_dev)
{
	return dpp_vport_attr_get(pf_info, &reps->port_attr_get_msg.port_attr_entry);
}

static u32 zxdh_vf_promisc_set(struct zxdh_msg_info *msg, struct zxdh_reps_info *reps,
			       struct dpp_pf_info_t *pf_info, struct zxdh_vf_item *vf_item,
			       struct zxdh_pf_device *pf_dev)
{
	u32 err = 0;

	if (!vf_item->trusted) {
		LOG_ERR("vf untrusted!\n");
		return 0;
	}

	if (msg->promisc_set_msg.mode == ZXDH_PROMISC_MODE) {
		LOG_INFO("PROMISC_EN_SET: %d", msg->promisc_set_msg.value);
		err = dpp_vport_uc_promisc_set(pf_info, msg->promisc_set_msg.value);
		if (err != 0) {
			LOG_ERR("dpp_vport_uc_promisc_set failed: %d\n", err);
			return err;
		}
		err = dpp_vport_promisc_en_set(pf_info, msg->promisc_set_msg.value);
		if (err != 0) {
			LOG_ERR("dpp_vport_promisc_en_set failed: %d\n", err);
			return err;
		}
		if (msg->promisc_set_msg.mc_follow != 0) {
			LOG_DEBUG("allmulti_follow\n");
			err = dpp_vport_mc_promisc_set(pf_info, msg->promisc_set_msg.value);
			if (err != 0) {
				LOG_ERR("dpp_vport_mc_promisc_set failed: %d\n", err);
				return err;
			}
		}
		vf_item->promisc = msg->promisc_set_msg.value;
	} else if (msg->promisc_set_msg.mode == ZXDH_ALLMULTI_MODE) {
		LOG_INFO("ALLMULTI_EN_SET: %d", msg->promisc_set_msg.value);
		err = dpp_vport_mc_promisc_set(pf_info, msg->promisc_set_msg.value);
		if (err != 0) {
			LOG_ERR("dpp_vport_mc_promisc_set failed: %d\n", err);
			return err;
		}
		vf_item->mc_promisc = msg->promisc_set_msg.value;
	} else {
		LOG_ERR("promisc_set_msg.mode[%d] error\n", msg->promisc_set_msg.mode);
		return 1;
	}

	return err;
}

static u32 zxdh_vf_vlan_filter_set(struct zxdh_msg_info *msg, struct zxdh_reps_info *reps,
				   struct dpp_pf_info_t *pf_info, struct zxdh_vf_item *vf_item,
				   struct zxdh_pf_device *pf_dev)
{
	bool vf_vlan_filter_enable = msg->vlan_filter_set_msg.enable;

	return zxdh_vf_switch_business_vlan(pf_info, VLAN_SRIOV_BUSINESS_VLAN_FILTER,
					    vf_vlan_filter_enable);
}

static u32 zxdh_vf_rx_vid_add(struct zxdh_msg_info *msg, struct zxdh_reps_info *reps,
			      struct dpp_pf_info_t *pf_info, struct zxdh_vf_item *vf_item,
			      struct zxdh_pf_device *pf_dev)
{
	u16 vid = msg->rx_vid_add_msg.vlan_id;

	return dpp_add_vlan_filter(pf_info, vid);
}

static u32 zxdh_vf_rx_vid_del(struct zxdh_msg_info *msg, struct zxdh_reps_info *reps,
			      struct dpp_pf_info_t *pf_info, struct zxdh_vf_item *vf_item,
			      struct zxdh_pf_device *pf_dev)
{
	u16 vid = msg->rx_vid_del_msg.vlan_id;

	return dpp_del_vlan_filter(pf_info, vid);
}

static u32 zxdh_vf_np_stats_get(struct zxdh_msg_info *msg, struct zxdh_reps_info *reps,
				struct dpp_pf_info_t *pf_info, struct zxdh_vf_item *vf_item,
				struct zxdh_pf_device *pf_dev)
{
	u32 vf_id = msg->hdr.vf_id;

	dpp_stat_port_uc_packet_rx_cnt_get(pf_info, vf_id, msg->np_stats_get_msg.clear_mode,
					   &(reps->np_stats_msg.np_rx_vport_unicast_bytes),
					   &(reps->np_stats_msg.np_rx_vport_unicast_packets));
	dpp_stat_port_uc_packet_tx_cnt_get(pf_info, vf_id, msg->np_stats_get_msg.clear_mode,
					   &(reps->np_stats_msg.np_tx_vport_unicast_bytes),
					   &(reps->np_stats_msg.np_tx_vport_unicast_packets));
	dpp_stat_port_mc_packet_rx_cnt_get(pf_info, vf_id, msg->np_stats_get_msg.clear_mode,
					   &(reps->np_stats_msg.np_rx_vport_multicast_bytes),
					   &(reps->np_stats_msg.np_rx_vport_multicast_packets));
	dpp_stat_port_mc_packet_tx_cnt_get(pf_info, vf_id, msg->np_stats_get_msg.clear_mode,
					   &(reps->np_stats_msg.np_tx_vport_multicast_bytes),
					   &(reps->np_stats_msg.np_tx_vport_multicast_packets));
	dpp_stat_port_bc_packet_rx_cnt_get(pf_info, vf_id, msg->np_stats_get_msg.clear_mode,
					   &(reps->np_stats_msg.np_rx_vport_broadcast_bytes),
					   &(reps->np_stats_msg.np_rx_vport_broadcast_packets));
	dpp_stat_port_bc_packet_tx_cnt_get(pf_info, vf_id, msg->np_stats_get_msg.clear_mode,
					   &(reps->np_stats_msg.np_tx_vport_broadcast_bytes),
					   &(reps->np_stats_msg.np_tx_vport_broadcast_packets));
	dpp_stat_MTU_packet_msg_rx_cnt_get(pf_info, vf_id, msg->np_stats_get_msg.clear_mode,
					   &(reps->np_stats_msg.np_rx_vport_mtu_drop_bytes),
					   &(reps->np_stats_msg.np_rx_vport_mtu_drop_packets));
	dpp_stat_MTU_packet_msg_tx_cnt_get(pf_info, vf_id, msg->np_stats_get_msg.clear_mode,
					   &(reps->np_stats_msg.np_tx_vport_mtu_drop_bytes),
					   &(reps->np_stats_msg.np_tx_vport_mtu_drop_packets));
	dpp_stat_plcr_packet_drop_rx_cnt_get(pf_info, vf_id, msg->np_stats_get_msg.clear_mode,
					     &(reps->np_stats_msg.np_rx_vport_plcr_drop_bytes),
					     &(reps->np_stats_msg.np_rx_vport_plcr_drop_packets));
	dpp_stat_plcr_packet_drop_tx_cnt_get(pf_info, vf_id, msg->np_stats_get_msg.clear_mode,
					     &(reps->np_stats_msg.np_tx_vport_plcr_drop_bytes),
					     &(reps->np_stats_msg.np_tx_vport_plcr_drop_packets));
	reps->np_stats_msg.np_tx_vport_ssvpc_packets = 0;
	reps->np_stats_msg.rx_vport_idma_drop_packets = 0;
	if (msg->np_stats_get_msg.is_init_get) {
		memcpy(vf_item->init_np_stats, &reps->np_stats_msg,
		       sizeof(struct zxdh_en_vport_np_stats));
	}

	return 0;
}

static u32 zxdh_vf_rate_limit_set(struct zxdh_msg_info *msg, struct zxdh_reps_info *reps,
				  struct dpp_pf_info_t *pf_info, struct zxdh_vf_item *vf_item,
				  struct zxdh_pf_device *pf_dev)
{
	s32 rtn;
	u16 vport = msg->hdr.vport;
	u32 flowid = msg->rate_limit_set_msg.flowid;
	u32 car_type = msg->rate_limit_set_msg.car_type;
	u32 max_rate = msg->rate_limit_set_msg.max_rate;
	u32 min_rate = msg->rate_limit_set_msg.min_rate;
	u32 is_packet = msg->rate_limit_set_msg.is_packet;

	PLCR_FUNC_DBG_ENTER();

	rtn = zxdh_plcr_set_rate_limit(pf_dev, is_packet, car_type, vport, flowid, max_rate,
				       min_rate);
	reps->rate_limit_set_rsp.err_code = rtn;

	if (PLCR_REMOVE_RATE_LIMIT == rtn || PLCR_DUPLICATE_RATE == rtn)
		return 0;
	else
		return rtn;
}

static u32 zxdh_vf_plcr_uninit(struct zxdh_msg_info *msg, struct zxdh_reps_info *reps,
			       struct dpp_pf_info_t *pf_info, struct zxdh_vf_item *vf_item,
			       struct zxdh_pf_device *pf_dev)
{
	u16 vport;
	unsigned long flow_id;
	enum E_PLCR_CAR_TYPE car_index;
	struct xarray *xarray_flow;
	struct zxdh_plcr_flow *flow = NULL;

	PLCR_FUNC_DBG_ENTER();

	vport = msg->hdr.vport;

	//deal with car A's flowid
	for (car_index = E_PLCR_CAR_A; car_index <= E_PLCR_CAR_B; car_index++) {
		xarray_flow = &(pf_dev->plcr_table.plcr_flows[car_index]);
		xa_for_each_range(xarray_flow, flow_id, flow, 0, gaudplcrcarxflowidnum[car_index]) {
			if (flow->vport == vport) {
				zxdh_plcr_remove_rate_limit(pf_dev, car_index, (u32)flow_id, 0);

				//clear vport mappings between car B and car C.
				if (car_index == E_PLCR_CAR_B)
					zxdh_plcr_clear_map(pf_dev, car_index, flow_id);
			}
		}
	}

	zxdh_plcr_count_profiles(pf_dev);

	return 0;
}

static u32 zxdh_vf_plcr_flowid_map(struct zxdh_msg_info *msg, struct zxdh_reps_info *reps,
				   struct dpp_pf_info_t *pf_info, struct zxdh_vf_item *vf_item,
				   struct zxdh_pf_device *pf_dev)
{
	s32 rtn = 0;
	u32 car_type = 0;
	u32 flowid = 0;
	u32 map_flowid = 0;
	u32 map_sp = 0;

	car_type = msg->plcr_flowid_map_msg.car_type;
	flowid = msg->plcr_flowid_map_msg.flowid;
	map_flowid = msg->plcr_flowid_map_msg.map_flowid;
	map_sp = msg->plcr_flowid_map_msg.sp;

	PLCR_LOG_INFO(
		"dpp_car_queue_map_set: pf_info->vport = 0x%x, car_type = %d, flowid = %d, map_flowid = %d\n",
		pf_info->vport, car_type, flowid, map_flowid);
	rtn = dpp_car_queue_map_set(pf_info, car_type, flowid, map_flowid, map_sp);
	if (rtn) {
		PLCR_LOG_ERR("failed and rtn=%d\n", rtn);
		return rtn;
	}

	zxdh_plcr_stroe_map(pf_dev, car_type, flowid, map_flowid);

	return 0;
}

static u32 zxdh_vf_plcr_get_mode(struct zxdh_msg_info *msg, struct zxdh_reps_info *reps,
				 struct dpp_pf_info_t *pf_info, struct zxdh_vf_item *vf_item,
				 struct zxdh_pf_device *pf_dev)
{
	s32 rtn = 0;
	u16 vport = 0;
	enum E_RATE_LIMIT_MODE mode = 0;

	vport = msg->plcr_work_mode_msg.vport;

	rtn = zxdh_pf_plcr_get_mode(pf_dev, vport, &mode);
	if (rtn) {
		PLCR_LOG_ERR("failed and rtn=%d\n", rtn);
		return rtn;
	}

	reps->plcr_work_mode_rsp.mode = mode;

	return rtn;
}

static u32 zxdh_vf_plcr_set_mode(struct zxdh_msg_info *msg, struct zxdh_reps_info *reps,
				 struct dpp_pf_info_t *pf_info, struct zxdh_vf_item *vf_item,
				 struct zxdh_pf_device *pf_dev)
{
	s32 rtn = 0;
	u16 vport = 0;
	enum E_RATE_LIMIT_MODE mode = 0;

	vport = msg->plcr_work_mode_msg.vport;
	mode = msg->plcr_work_mode_msg.mode;

	rtn = zxdh_pf_plcr_set_mode(pf_dev, vport, mode);
	if (rtn) {
		PLCR_LOG_ERR("failed and rtn=%d\n", rtn);
		return rtn;
	}

	return rtn;
}

static u32 zxdh_vf_plcr_flow_init(struct zxdh_msg_info *msg, struct zxdh_reps_info *reps,
				  struct dpp_pf_info_t *pf_info, struct zxdh_vf_item *vf_item,
				  struct zxdh_pf_device *pf_dev)
{
	int rtn = 0;
	u32 car_type;
	u32 flowid;

	car_type = msg->plcr_flow_init_msg.car_type;
	flowid = msg->plcr_flow_init_msg.flowid;
	pf_info->slot = pf_dev->slot_id;
	pf_info->vport = pf_dev->vport;

	PLCR_LOG_INFO(
		"dpp_car_queue_cfg_set: vport = 0x%x, car_type = %d, flowid = %d, plcr_en = 0\n",
		pf_dev->vport, car_type, flowid);
	rtn = dpp_car_queue_cfg_set(pf_info, (u32)car_type, flowid, DROP_DISABLE, PLCR_DISABLE, 0);
	if (rtn)
		PLCR_LOG_ERR("failed to call dpp_car_queue_cfg_set()\n");

	return rtn;
}

static u32 zxdh_vf_plcr_profile_id_add(struct zxdh_msg_info *msg, struct zxdh_reps_info *reps,
				       struct dpp_pf_info_t *pf_info, struct zxdh_vf_item *vf_item,
				       struct zxdh_pf_device *pf_dev)
{
	s32 rtn = 0;
	u32 car_type = 0;
	u16 profile_id = 0;

	LOG_INFO("%s-%d:enter\n", __func__, __LINE__);

	car_type = msg->vf_plcr_profile_id_add_msg.car_type;

	rtn = zxdh_plcr_req_profile(pf_dev, car_type, &profile_id);
	if (rtn) {
		LOG_ERR("%s-%d : failed !\n", __func__, __LINE__);
		return rtn;
	}

	reps->vf_plcr_profile_id_add_rsp.profile_id = profile_id;

	return 0;
}

static u32 zxdh_vf_plcr_profile_id_delete(struct zxdh_msg_info *msg, struct zxdh_reps_info *reps,
					  struct dpp_pf_info_t *pf_info,
					  struct zxdh_vf_item *vf_item,
					  struct zxdh_pf_device *pf_dev)
{
	s32 rtn = 0;
	u32 car_type = 0;
	u16 profile_id = 0;

	LOG_INFO("%s-%d:enter\n", __func__, __LINE__);

	car_type = msg->vf_plcr_profile_id_delete_msg.car_type;
	profile_id = msg->vf_plcr_profile_id_delete_msg.profile_id;

	rtn = zxdh_plcr_release_profile(pf_dev, car_type, profile_id, 0);
	if (rtn) {
		LOG_ERR("%s-%d : failed !\n", __func__, __LINE__);
		return rtn;
	}

	return rtn;
}

static u32 zxdh_vf_plcr_profile_cfg_set(struct zxdh_msg_info *msg, struct zxdh_reps_info *reps,
					struct dpp_pf_info_t *pf_info, struct zxdh_vf_item *vf_item,
					struct zxdh_pf_device *pf_dev)
{
	s32 rtn = 0;
	u32 car_type = 0;
	u32 pkt_mode = 0;
	u16 profile_id = 0;
	u32 max_rate = 0;
	u32 min_rate = 0;
	struct xarray *xarray_profile = NULL;
	struct zxdh_plcr_profile *plcr_profile = NULL;
	union zxdh_plcr_profile_cfg profile_cfg;

	LOG_INFO("%s-%d:enter\n", __func__, __LINE__);

	car_type = msg->vf_plcr_profile_cfg_set_msg.car_type;
	pkt_mode = msg->vf_plcr_profile_cfg_set_msg.pkt_mode;
	profile_id = msg->vf_plcr_profile_cfg_set_msg.profile_id;

	if (profile_id !=
	    msg->vf_plcr_profile_cfg_set_msg.profile_cfg.byte_profile_cfg.profile_id) {
		LOG_ERR("%s-%d : failed\n", __func__, __LINE__);
		return -EINVAL;
	}

	if (pkt_mode != msg->vf_plcr_profile_cfg_set_msg.profile_cfg.byte_profile_cfg.pkt_sign) {
		LOG_ERR("%s-%d : failed\n", __func__, __LINE__);
		return -EINVAL;
	}

	xarray_profile = &(pf_dev->plcr_table.plcr_profiles[car_type]);
	plcr_profile = xa_load(xarray_profile, profile_id);

	if (pkt_mode == 1) {
		profile_cfg.pkt_profile_cfg =
			msg->vf_plcr_profile_cfg_set_msg.profile_cfg.pkt_profile_cfg;

		max_rate = profile_cfg.pkt_profile_cfg.cir;
		min_rate = profile_cfg.pkt_profile_cfg.cir;

		rtn = zxdh_plcr_cfg_profile(pf_dev, car_type, &profile_cfg.byte_profile_cfg);
		if (rtn) {
			LOG_ERR("%s-%d : failed\n", __func__, __LINE__);
			return -EINVAL;
		}
	} else {
		profile_cfg.byte_profile_cfg =
			msg->vf_plcr_profile_cfg_set_msg.profile_cfg.byte_profile_cfg;

		max_rate = zxdh_plcr_reg_maxrate_user(profile_cfg.byte_profile_cfg.eir);
		min_rate = zxdh_plcr_reg_maxrate_user(profile_cfg.byte_profile_cfg.cir);

		rtn = zxdh_plcr_cfg_profile(pf_dev, car_type, &profile_cfg.byte_profile_cfg);
		if (rtn) {
			LOG_ERR("%s-%d : failed\n", __func__, __LINE__);
			return -EINVAL;
		}
	}

	rtn = zxdh_plcr_store_profile(pf_dev, car_type, max_rate, min_rate,
				      &profile_cfg.byte_profile_cfg);
	if (rtn) {
		LOG_ERR("%s-%d : failed\n", __func__, __LINE__);
		return -EINVAL;
	}

	return 0;
}

static u32 zxdh_vf_plcr_profile_cfg_get(struct zxdh_msg_info *msg, struct zxdh_reps_info *reps,
					struct dpp_pf_info_t *pf_info, struct zxdh_vf_item *vf_item,
					struct zxdh_pf_device *pf_dev)
{
	s32 rtn = 0;
	u32 car_type = 0;
	u32 pkt_mode = 0;
	u16 profile_id = 0;

	LOG_INFO("%s-%d:enter\n", __func__, __LINE__);

	car_type = msg->vf_plcr_profile_cfg_get_msg.car_type;
	pkt_mode = msg->vf_plcr_profile_cfg_get_msg.pkt_mode;
	profile_id = msg->vf_plcr_profile_cfg_get_msg.profile_id;

	rtn = zxdh_plcr_get_profile(
		pf_dev, car_type, pkt_mode, profile_id,
		&reps->vf_plcr_profile_cfg_get_rsp.profile_cfg.byte_profile_cfg);
	if (rtn) {
		LOG_ERR("%s-%d : failed to call zxdh_plcr_cfg_profile()\n", __func__, __LINE__);
		return rtn;
	}

	return 0;
}

static u32 zxdh_vf_plcr_queue_cfg_set(struct zxdh_msg_info *msg, struct zxdh_reps_info *reps,
				      struct dpp_pf_info_t *pf_info, struct zxdh_vf_item *vf_item,
				      struct zxdh_pf_device *pf_dev)
{
	s32 rtn = 0;
	u32 car_type = 0;
	u32 drop_flag = 0;
	u32 plcr_en = 0;
	u32 flow_id = 0;
	u32 profile_id = 0;
	u16 vport = msg->hdr.vport;
	struct xarray *xarray_profile = NULL;
	struct zxdh_plcr_flow *plcr_flow = NULL;
	struct zxdh_plcr_profile *plcr_profile = NULL;

	LOG_INFO("%s-%d:enter\n", __func__, __LINE__);
	LOG_INFO("%s-%d:vport = 0x%x\n", __func__, __LINE__, vport);

	car_type = msg->vf_plcr_queue_cfg_set_msg.car_type;
	drop_flag = msg->vf_plcr_queue_cfg_set_msg.drop_flag;
	plcr_en = msg->vf_plcr_queue_cfg_set_msg.plcr_en;
	flow_id = msg->vf_plcr_queue_cfg_set_msg.flow_id;
	profile_id = msg->vf_plcr_queue_cfg_set_msg.profile_id;

	xarray_profile = &(pf_dev->plcr_table.plcr_profiles[car_type]);
	plcr_profile = xa_load(xarray_profile, profile_id);
	if (!plcr_profile) {
		LOG_ERR("%s-%d : failed\n", __func__, __LINE__);
		return -EINVAL;
	}

	if (plcr_en == PLCR_ENABLE) {
		rtn = zxdh_plcr_req_flow(pf_dev, car_type, flow_id, &plcr_flow);
		if (rtn) {
			LOG_ERR("%s-%d : kzalloc failed\n", __func__, __LINE__);
			return -EINVAL;
		}

		zxdh_plcr_update_flow(plcr_flow, vport, plcr_profile->max_rate,
				      plcr_profile->min_rate);

		plcr_flow->profile_id = profile_id;

		rtn = dpp_car_queue_cfg_set(pf_info, car_type, flow_id, drop_flag, plcr_en,
					    profile_id);
		if (rtn) {
			LOG_ERR("%s-%d : failed to call dpp_car_queue_cfg_set()\n", __func__,
				__LINE__);

			zxdh_plcr_release_flow(pf_dev, car_type, flow_id);
			return -EINVAL;
		}

		zxdh_plcr_count_up_profile(pf_dev, car_type, profile_id);
	} else {
		rtn = dpp_car_queue_cfg_set(pf_info, car_type, flow_id, drop_flag, plcr_en,
					    profile_id);
		if (rtn) {
			LOG_ERR("%s-%d : failed to call dpp_car_queue_cfg_set()\n", __func__,
				__LINE__);
			return -EINVAL;
		}

		zxdh_plcr_release_flow(pf_dev, car_type, flow_id);

		zxdh_plcr_count_down_profile(pf_dev, car_type, profile_id);
	}

	return 0;
}

static u32 zxdh_vf_plcr_port_meter_stat_clr(struct zxdh_msg_info *msg, struct zxdh_reps_info *reps,
					    struct dpp_pf_info_t *pf_info,
					    struct zxdh_vf_item *vf_item,
					    struct zxdh_pf_device *pf_dev)
{
	s32 rtn = 0;
	u64 pkb_cnt = 0;
	u64 pk_cnt = 0;

	LOG_INFO("%s-%d:enter\n", __func__, __LINE__);

	dpp_stat_plcr_packet_drop_tx_cnt_get(pf_info, msg->hdr.vf_id, 1, &pkb_cnt, &pk_cnt);
	dpp_stat_plcr_packet_drop_rx_cnt_get(pf_info, msg->hdr.vf_id, 1, &pkb_cnt, &pk_cnt);

	return rtn;
}

static u32 zxdh_vf_plcr_port_meter_stat_get(struct zxdh_msg_info *msg, struct zxdh_reps_info *reps,
					    struct dpp_pf_info_t *pf_info,
					    struct zxdh_vf_item *vf_item,
					    struct zxdh_pf_device *pf_dev)
{
	s32 rtn = 0;
	u32 direction = 0;
	u32 is_clr = 0;
	u64 *p_pkb_cnt = NULL;
	u64 *p_pk_cnt = NULL;

	LOG_INFO("%s-%d:enter\n", __func__, __LINE__);

	direction = msg->vf_plcr_port_meter_stat_get_msg.direction;
	is_clr = msg->vf_plcr_port_meter_stat_get_msg.is_clr;

	p_pkb_cnt = &(reps->vf_plcr_port_meter_stat_get_rsp.drop_pkb_cnt);
	p_pk_cnt = &(reps->vf_plcr_port_meter_stat_get_rsp.drop_pk_cnt);

	if (direction == 1) {
		dpp_stat_plcr_packet_drop_tx_cnt_get(pf_info, msg->hdr.vf_id, is_clr, p_pkb_cnt,
						     p_pk_cnt);
	} else {
		dpp_stat_plcr_packet_drop_rx_cnt_get(pf_info, msg->hdr.vf_id, is_clr, p_pkb_cnt,
						     p_pk_cnt);
	}

	return rtn;
}

static u32 zxdh_vf_call_np_1588(struct zxdh_msg_info *msg, struct zxdh_reps_info *reps,
				struct dpp_pf_info_t *pf_info, struct zxdh_vf_item *vf_item,
				struct zxdh_pf_device *pf_dev)
{
	u32 vfid = msg->vf_1588_call_np.vfid;
	u32 interface_num = msg->vf_1588_call_np.call_np_interface_num;
	u32 opt = msg->vf_1588_call_np.ptp_tc_enable_opt;

	switch (interface_num) {
	case PTP_PORT_VFID_SET: {
		LOG_INFO("call dpp_ptp_port_vfid_set\n");
		dpp_ptp_port_vfid_set(pf_info, vfid);
		break;
	}
	case PTP_TC_ENABLE_SET: {
		LOG_INFO("call dpp_ptp_tc_enable_set\n");
		dpp_ptp_tc_enable_set(pf_info, opt);
		break;
	}
	default: {
		LOG_ERR("cannot found the interface_num %u\n", interface_num);
		return -1;
	}
	}

	return 0;
}

static u32 zxdh_vf_slot_id_get(struct zxdh_msg_info *msg, struct zxdh_reps_info *reps,
			       struct dpp_pf_info_t *pf_info, struct zxdh_vf_item *vf_item,
			       struct zxdh_pf_device *pf_dev)
{
	reps->slot_info.slot_id = pf_dev->slot_id;
	return 0;
}

static u32 zxdh_vf_mcode_feature_get(struct zxdh_msg_info *msg, struct zxdh_reps_info *reps,
				     struct dpp_pf_info_t *pf_info, struct zxdh_vf_item *vf_item,
				     struct zxdh_pf_device *pf_dev)
{
	reps->mcode_feature_rsp.len = sizeof(reps->mcode_feature_rsp.feature);
	reps->mcode_feature_rsp.feature = pf_dev->mcode_feature;
	return 0;
}

static u32 zxdh_vf_k_cmpat_get(struct zxdh_msg_info *msg, struct zxdh_reps_info *reps,
			       struct dpp_pf_info_t *pf_info, struct zxdh_vf_item *vf_item,
			       struct zxdh_pf_device *pf_dev)
{
	reps->kernel_cmpat_rsp.k_msg_idmax = ZXDH_MSG_TYPE_CNT_MAX;
	return 0;
}

static u32 zxdh_vf_1588_enable_proc(struct zxdh_msg_info *msg, struct zxdh_reps_info *reps,
				    struct dpp_pf_info_t *pf_info, struct zxdh_vf_item *vf_item,
				    struct zxdh_pf_device *pf_dev)
{
	u32 proc_cmd = 0;
	u32 enable = 0;
	u32 ret = 0;
	struct zxdh_sriov_vport_t port_attr_entry = { 0 };

	proc_cmd = msg->vf_1588_enable.proc_cmd;
	switch (proc_cmd) {
	case ZXDH_VF_1588_ENABLE_SET: {
		enable = msg->vf_1588_enable.enable_1588_vf;
		pf_info->vport = msg->hdr.vport;
		ret = dpp_vport_attr_set(pf_info, SRIOV_VPORT_1588_EN, (u32)enable);
		if (ret != 0) {
			LOG_ERR("dpp_vport_attr_set SRIOV_VPORT_1588_EN failed, ret:%d\n", ret);
			return ret;
		}
		break;
	}
	case ZXDH_VF_1588_ENABLE_GET: {
		pf_info->vport = msg->hdr.vport;
		ret = dpp_vport_attr_get(pf_info, &port_attr_entry);
		if (ret != 0) {
			LOG_ERR("dpp_vport_attr_get SRIOV_VPORT_1588_EN failed, ret:%d\n", ret);
			return ret;
		}
		reps->vf_1588_enable_rsp.enable_1588_vf_rsp = port_attr_entry.flag_1588_enable;
		break;
	}
	default: {
		LOG_ERR("cannot found proc_cmd %u\n", proc_cmd);
		break;
	}
	}
	return 0;
}

static u32 zxdh_vf_flow_hw_add(struct zxdh_msg_info *msg, struct zxdh_reps_info *reps,
			       struct dpp_pf_info_t *pf_info, struct zxdh_vf_item *vf_item,
			       struct zxdh_pf_device *pf_dev)
{
	s32 err = 0;
	u32 handle = 0;
	u8 *key = NULL;
	u8 *key_mask = NULL;
	u8 *result = NULL;
	s32 vf_idx = 0;
	u8 eth_type_bit = 0;
	u16 sriov_tunnel_encap0_index = 0;
	u16 sriov_tunnel_encap1_index = 0;
	struct zxdh_flow_op_msg *f_msg = &msg->flow_msg;
	struct zxdh_flow_op_rsp *f_rsp = &reps->flow_rsp;

	vf_idx = msg->hdr.pcie_id & (0xff);

	err = dpp_fd_acl_index_request(pf_info, &handle);
	if (err) {
		LOG_ERR("failed to request index!!!\n");
		zte_strncpy_s(f_rsp->error.reason, "failed to request index!!!",
			      sizeof(f_rsp->error.reason) - 1);
		f_rsp->error.reason[sizeof(f_rsp->error.reason) - 1] = '\0';
		return -EINVAL;
	}

	key = (u8 *)&f_msg->dh_flow.flowentry.fd_flow.key;
	key_mask = (u8 *)&f_msg->dh_flow.flowentry.fd_flow.key_mask;
	if ((f_msg->dh_flow.flowentry.fd_flow.result.action_idx & (1 << FD_ACTION_COUNT_BIT)) !=
	    0) {
		f_msg->dh_flow.flowentry.fd_flow.result.countid = handle;
	}
	result = (u8 *)&f_msg->dh_flow.flowentry.fd_flow.result;

	if ((f_msg->dh_flow.flowentry.fd_flow.result.action_idx & (1 << FD_ACTION_VXLAN_ENCAP)) !=
	    0) {
		f_msg->dh_flow.flowentry.fd_flow.result.sriov_tunnel_encap0_index = handle;
		sriov_tunnel_encap0_index = handle;

		if (vf_idx < (ZXDH_MAX_VF - 1)) {
			f_msg->dh_flow.flowentry.fd_flow.result.sriov_tunnel_encap1_index =
				f_msg->dh_flow.hash_search_idx * PF_HAS_MAX_ENCAP1_NUM + vf_idx + 1;
		} else {
			LOG_ERR("encap1 vf_index is too big:%d\n", vf_idx);
			zte_strncpy_s(f_rsp->error.reason, "encap1 vf_index is too big!!!",
				      sizeof(f_rsp->error.reason) - 1);
			f_rsp->error.reason[sizeof(f_rsp->error.reason) - 1] = '\0';
			return -EINVAL;
		}

		sriov_tunnel_encap1_index =
			f_msg->dh_flow.flowentry.fd_flow.result.sriov_tunnel_encap1_index;
		eth_type_bit = f_msg->encap0.eth_type;
		err = dpp_eram_entry_insert(pf_info, ZXDH_SDT_TUNNEL_ENCAP0_TABLE,
					    sriov_tunnel_encap0_index * 2, (u8 *)&(f_msg->encap0));
		if (err) {
			LOG_ERR("dpp_eram_entry_insert encap0 table failed\n");
			zte_strncpy_s(f_rsp->error.reason,
				      "dpp_eram_entry_insert encap0 table failed",
				      sizeof(f_rsp->error.reason) - 1);
			f_rsp->error.reason[sizeof(f_rsp->error.reason) - 1] = '\0';
			return -EINVAL;
		}

		err = dpp_eram_entry_insert(pf_info, ZXDH_SDT_TUNNEL_ENCAP0_TABLE,
					    sriov_tunnel_encap0_index * 2 + 1,
					    (u8 *)&(f_msg->encap0.dip));
		if (err) {
			LOG_ERR("dpp_eram_entry_insert encap0 dip table failed\n");
			zte_strncpy_s(f_rsp->error.reason,
				      "dpp_eram_entry_insert encap0 dip table failed",
				      sizeof(f_rsp->error.reason) - 1);
			f_rsp->error.reason[sizeof(f_rsp->error.reason) - 1] = '\0';
			return -EINVAL;
		}

		if (eth_type_bit == 0) {
			err = dpp_eram_entry_insert(pf_info, ZXDH_SDT_TUNNEL_ENCAP1_TABLE,
						    sriov_tunnel_encap1_index * 4,
						    (u8 *)&(f_msg->encap1));
			if (err) {
				LOG_ERR("dpp_eram_entry_insert ipv4 encap1 table failed\n");
				zte_strncpy_s(f_rsp->error.reason,
					      "dpp_eram_entry_insert ipv4 encap1 table failed",
					      sizeof(f_rsp->error.reason) - 1);
				f_rsp->error.reason[sizeof(f_rsp->error.reason) - 1] = '\0';
				return -EINVAL;
			}

			err = dpp_eram_entry_insert(pf_info, ZXDH_SDT_TUNNEL_ENCAP1_TABLE,
						    sriov_tunnel_encap1_index * 4 + 2,
						    (u8 *)&(f_msg->encap1.sip));
			if (err) {
				LOG_ERR("dpp_eram_entry_insert ipv4 encap1 sip table failed\n");
				zte_strncpy_s(f_rsp->error.reason,
					      "dpp_eram_entry_insert ipv4 encap1 sip table failed",
					      sizeof(f_rsp->error.reason) - 1);
				f_rsp->error.reason[sizeof(f_rsp->error.reason) - 1] = '\0';
				return -EINVAL;
			}
		} else {
			err = dpp_eram_entry_insert(pf_info, ZXDH_SDT_TUNNEL_ENCAP1_TABLE,
						    sriov_tunnel_encap1_index * 4 + 1,
						    (u8 *)&(f_msg->encap1));
			if (err) {
				LOG_ERR("dpp_eram_entry_insert ipv6 encap1 table failed\n");
				zte_strncpy_s(f_rsp->error.reason,
					      "dpp_eram_entry_insert ipv6 encap1 table failed",
					      sizeof(f_rsp->error.reason) - 1);
				f_rsp->error.reason[sizeof(f_rsp->error.reason) - 1] = '\0';
				return -EINVAL;
			}

			err = dpp_eram_entry_insert(pf_info, ZXDH_SDT_TUNNEL_ENCAP1_TABLE,
						    sriov_tunnel_encap1_index * 4 + 3,
						    (u8 *)&(f_msg->encap1.sip));
			if (err) {
				LOG_ERR("dpp_eram_entry_insert ipv6 encap1 sip table failed\n");
				zte_strncpy_s(f_rsp->error.reason,
					      "dpp_eram_entry_insert ipv6 encap1 sip table failed",
					      sizeof(f_rsp->error.reason) - 1);
				f_rsp->error.reason[sizeof(f_rsp->error.reason) - 1] = '\0';
				return -EINVAL;
			}
		}
	}

	err = dpp_fd_acl_entry_add(pf_info, handle, key, key_mask, result);
	if (err) {
		LOG_ERR("failed to call dpp_fd_acl_entry_add()\n");
		zte_strncpy_s(f_rsp->error.reason, "failed to call dpp_fd_acl_entry_add()",
			      sizeof(f_rsp->error.reason) - 1);
		f_rsp->error.reason[sizeof(f_rsp->error.reason) - 1] = '\0';
		return -EINVAL;
	}

	err = dpp_stat_fd_stat_cnt_get(pf_info, handle, RD_CLR_MODE_CLR, &f_rsp->count.bytes,
				       &f_rsp->count.hits);
	if (err) {
		LOG_ERR("failed to clear fd cnt!!!\n");
		zte_strncpy_s(f_rsp->error.reason, "failed to clear fd cnt!!!",
			      sizeof(f_rsp->error.reason) - 1);
		f_rsp->error.reason[sizeof(f_rsp->error.reason) - 1] = '\0';
		return -EINVAL;
	}

	f_rsp->dh_flow.flowentry.hw_idx = handle;

	return 0;
}

static u32 zxdh_vf_flow_hw_del(struct zxdh_msg_info *msg, struct zxdh_reps_info *reps,
			       struct dpp_pf_info_t *pf_info, struct zxdh_vf_item *vf_item,
			       struct zxdh_pf_device *pf_dev)
{
	s32 err = 0;
	u32 handle = 0;
	struct zxdh_flow_op_msg *f_msg = &msg->flow_msg;
	struct zxdh_flow_op_rsp *f_rsp = &reps->flow_rsp;

	handle = f_msg->dh_flow.flowentry.hw_idx;

	err = dpp_fd_acl_entry_del(pf_info, handle);
	if (err) {
		LOG_ERR("failed to call dpp_fd_acl_entry_del()\n");
		zte_strncpy_s(f_rsp->error.reason, "failed to call dpp_fd_acl_entry_del()",
			      sizeof(f_rsp->error.reason) - 1);
		f_rsp->error.reason[sizeof(f_rsp->error.reason) - 1] = '\0';
		return -EINVAL;
	}

	err = dpp_stat_fd_stat_cnt_get(pf_info, handle, RD_CLR_MODE_CLR, &f_rsp->count.bytes,
				       &f_rsp->count.hits);
	if (err) {
		LOG_ERR("failed to clear fd cnt!!!\n");
		zte_strncpy_s(f_rsp->error.reason, "failed to clear fd cnt!!!",
			      sizeof(f_rsp->error.reason) - 1);
		f_rsp->error.reason[sizeof(f_rsp->error.reason) - 1] = '\0';
		return -EINVAL;
	}

	err = dpp_fd_acl_index_release(pf_info, handle);
	if (err) {
		LOG_ERR("failed to release index!!!\n");
		zte_strncpy_s(f_rsp->error.reason, "failed to release index!!!",
			      sizeof(f_rsp->error.reason) - 1);
		f_rsp->error.reason[sizeof(f_rsp->error.reason) - 1] = '\0';
		return -EINVAL;
	}

	f_rsp->dh_flow.flowentry.fd_flow.result = f_msg->dh_flow.flowentry.fd_flow.result;

	return 0;
}

static u32 zxdh_vf_flow_hw_get(struct zxdh_msg_info *msg, struct zxdh_reps_info *reps,
			       struct dpp_pf_info_t *pf_info, struct zxdh_vf_item *vf_item,
			       struct zxdh_pf_device *pf_dev)
{
	s32 err = 0;
	u32 handle = 0;
	u8 *key = NULL;
	u8 *key_mask = NULL;
	u8 *result = NULL;
	struct zxdh_flow_op_msg *f_msg = &msg->flow_msg;
	struct zxdh_flow_op_rsp *f_rsp = &reps->flow_rsp;

	handle = f_msg->dh_flow.flowentry.hw_idx;

	key = (u8 *)&f_rsp->dh_flow.flowentry.fd_flow.key;
	key_mask = (u8 *)&f_rsp->dh_flow.flowentry.fd_flow.key_mask;
	result = (u8 *)&f_rsp->dh_flow.flowentry.fd_flow.result;

	err = dpp_fd_acl_entry_get(pf_info, handle, key, key_mask, result);
	if (err) {
		LOG_ERR("failed to get fd rule!!!\n");
		zte_strncpy_s(f_rsp->error.reason, "failed to get fd rule!!!",
			      sizeof(f_rsp->error.reason) - 1);
		f_rsp->error.reason[sizeof(f_rsp->error.reason) - 1] = '\0';
		return -EINVAL;
	}

	f_rsp->count.bytes = 0;
	f_rsp->count.hits = 0;
	err = dpp_stat_fd_stat_cnt_get(pf_info, handle, RD_CLR_MODE_UNCLR, &f_rsp->count.bytes,
				       &f_rsp->count.hits);
	if (err) {
		LOG_ERR("failed to get fd cnt!!!\n");
		zte_strncpy_s(f_rsp->error.reason, "failed to get fd cnt!!!",
			      sizeof(f_rsp->error.reason) - 1);
		f_rsp->error.reason[sizeof(f_rsp->error.reason) - 1] = '\0';
		return -EINVAL;
	}

	return 0;
}

static u32 zxdh_vf_flow_hw_flush(struct zxdh_msg_info *msg, struct zxdh_reps_info *reps,
				 struct dpp_pf_info_t *pf_info, struct zxdh_vf_item *vf_item,
				 struct zxdh_pf_device *pf_dev)
{
	s32 err = 0;
	struct zxdh_flow_op_rsp *f_rsp = &reps->flow_rsp;

	err = dpp_fd_acl_all_delete(pf_info);
	if (err) {
		LOG_ERR("failed to detele all fd!!!\n");
		zte_strncpy_s(f_rsp->error.reason, "failed to detele all fd!!!",
			      sizeof(f_rsp->error.reason) - 1);
		f_rsp->error.reason[sizeof(f_rsp->error.reason) - 1] = '\0';
		return -EINVAL;
	}

	err = dpp_fd_acl_stat_clear(pf_info);
	if (err) {
		LOG_ERR("failed to clear fd stat!!!\n");
		zte_strncpy_s(f_rsp->error.reason, "failed to gclear fd stat!!!",
			      sizeof(f_rsp->error.reason) - 1);
		f_rsp->error.reason[sizeof(f_rsp->error.reason) - 1] = '\0';
		return -EINVAL;
	}

	return 0;
}

static s32 zxdh_flow_table_vf_action_add(struct ethtool_rx_flow_spec *fs,
					 struct zxdh_fd_cfg_t *p_fd_cfg,
					 struct dpp_pf_info_t *pf_info)
{
	u8 vf_id = 0;
	u32 queue_id = 0;
	u32 base_qid = 0;
	s32 ret = 0;

	if (fs->ring_cookie == RX_CLS_FLOW_DISC) {
		p_fd_cfg->as_rlt.action_index |= ACTION_TYPE_DROP;
		return 0;
	}

	vf_id = ethtool_get_flow_spec_ring_vf(fs->ring_cookie);
	queue_id = ethtool_get_flow_spec_ring(fs->ring_cookie);

	if (vf_id > 0) {
		LOG_ERR("vf fd action do not support specific vf");
		return -EINVAL;
	}

	if (queue_id == QUEUE_RSS) {
		p_fd_cfg->as_rlt.action_index |= ACTION_TYPE_RSS;
		return 0;
	}

	ret = dpp_vport_base_qid_get(pf_info, &base_qid);
	if (ret) {
		LOG_ERR("zxdh_cfg_fd_add: get vf base qid failed");
		return ret;
	}

	p_fd_cfg->as_rlt.action_index |= ACTION_TYPE_QUEUE;
	p_fd_cfg->as_rlt.v_qid = queue_id * 2 + base_qid;
	LOG_INFO("zxdh_cfg_vf_fd_add, phy queue id is %u", p_fd_cfg->as_rlt.v_qid);
	return 0;
}

void zxdh_flow_table_add(struct ethtool_rx_flow_spec *fs, struct zxdh_fd_cfg_t *p_fd_cfg,
			 struct dpp_pf_info_t *pf_info)
{
	zte_memset_s(&p_fd_cfg->mask, 0xff, sizeof(struct zxdh_fd_cfg_key));

	p_fd_cfg->key.vqm_vfid = VQM_VFID(pf_info->vport);
	p_fd_cfg->mask.vqm_vfid = ETHTOOL_TRUE_MASK;

	switch (fs->flow_type & ~(FLOW_EXT | FLOW_MAC_EXT)) {
	case ETHER_FLOW:
		if (!is_zero_ether_addr(fs->m_u.ether_spec.h_dest)) {
			zte_memcpy_s(p_fd_cfg->key.dmac, fs->h_u.ether_spec.h_dest, ETH_ALEN);
			zte_memset_s(p_fd_cfg->mask.dmac, ETHTOOL_TRUE_MASK, ETH_ALEN);
			LOG_INFO("dmac is %pM\n", p_fd_cfg->key.dmac);
		}
		if (!is_zero_ether_addr(fs->m_u.ether_spec.h_source)) {
			zte_memcpy_s(p_fd_cfg->key.smac, fs->h_u.ether_spec.h_source, ETH_ALEN);
			zte_memset_s(p_fd_cfg->mask.smac, ETHTOOL_TRUE_MASK, ETH_ALEN);
			LOG_INFO("smac is %pM\n", p_fd_cfg->key.smac);
		}
		if (fs->m_u.ether_spec.h_proto) {
			p_fd_cfg->key.ethtype = ntohs(fs->h_u.ether_spec.h_proto);
			p_fd_cfg->mask.ethtype = ETHTOOL_TRUE_MASK;
			LOG_INFO("ethertype is 0x%x\n", p_fd_cfg->key.ethtype);
		}
		break;
	case IPV4_USER_FLOW:
		if (fs->m_u.usr_ip4_spec.ip4src) {
			zte_memcpy_s((u8 *)p_fd_cfg->key.sip + 12, &fs->h_u.usr_ip4_spec.ip4src,
				     ETHTOOL_IP4_LEN);
			zte_memset_s((u8 *)p_fd_cfg->mask.sip + 12, ETHTOOL_TRUE_MASK,
				     ETHTOOL_IP4_LEN);
			LOG_INFO("sip: %d.%d.%d.%d\n", p_fd_cfg->key.sip[12], p_fd_cfg->key.sip[13],
				 p_fd_cfg->key.sip[14], p_fd_cfg->key.sip[15]);
		}
		if (fs->m_u.usr_ip4_spec.ip4dst) {
			zte_memcpy_s((u8 *)p_fd_cfg->key.dip + 12, &fs->h_u.usr_ip4_spec.ip4dst,
				     ETHTOOL_IP4_LEN);
			zte_memset_s((u8 *)p_fd_cfg->mask.dip + 12, ETHTOOL_TRUE_MASK,
				     ETHTOOL_IP4_LEN);
			LOG_INFO("dip: %d.%d.%d.%d\n", p_fd_cfg->key.dip[12], p_fd_cfg->key.dip[13],
				 p_fd_cfg->key.dip[14], p_fd_cfg->key.dip[15]);
		}
		if (fs->m_u.usr_ip4_spec.proto) {
			p_fd_cfg->key.proto = fs->h_u.usr_ip4_spec.proto;
			p_fd_cfg->mask.proto = ETHTOOL_TRUE_MASK;
			LOG_INFO("proto: %d\n", p_fd_cfg->key.proto);
		}
		p_fd_cfg->key.ethtype = ETH_PKT_IPV4;
		p_fd_cfg->mask.ethtype = ETHTOOL_TRUE_MASK;
		LOG_INFO("ethertype is 0x%x\n", p_fd_cfg->key.ethtype);
		break;
	case TCP_V4_FLOW:
		if (fs->m_u.tcp_ip4_spec.ip4src) {
			zte_memcpy_s((u8 *)p_fd_cfg->key.sip + 12, &fs->h_u.tcp_ip4_spec.ip4src,
				     ETHTOOL_IP4_LEN);
			zte_memset_s((u8 *)p_fd_cfg->mask.sip + 12, ETHTOOL_TRUE_MASK,
				     ETHTOOL_IP4_LEN);
			LOG_INFO("sip: %d.%d.%d.%d\n", p_fd_cfg->key.sip[12], p_fd_cfg->key.sip[13],
				 p_fd_cfg->key.sip[14], p_fd_cfg->key.sip[15]);
		}
		if (fs->m_u.tcp_ip4_spec.ip4dst) {
			zte_memcpy_s((u8 *)p_fd_cfg->key.dip + 12, &fs->h_u.tcp_ip4_spec.ip4dst,
				     ETHTOOL_IP4_LEN);
			zte_memset_s((u8 *)p_fd_cfg->mask.dip + 12, ETHTOOL_TRUE_MASK,
				     ETHTOOL_IP4_LEN);
			LOG_INFO("dip: %d.%d.%d.%d\n", p_fd_cfg->key.dip[12], p_fd_cfg->key.dip[13],
				 p_fd_cfg->key.dip[14], p_fd_cfg->key.dip[15]);
		}
		if (fs->m_u.tcp_ip4_spec.psrc) {
			p_fd_cfg->key.sport = ntohs(fs->h_u.tcp_ip4_spec.psrc);
			p_fd_cfg->mask.sport = ETHTOOL_TRUE_MASK;
			LOG_INFO("sport is %d\n", p_fd_cfg->key.sport);
		}
		if (fs->m_u.tcp_ip4_spec.pdst) {
			p_fd_cfg->key.dport = ntohs(fs->h_u.tcp_ip4_spec.pdst);
			p_fd_cfg->mask.dport = ETHTOOL_TRUE_MASK;
			LOG_INFO("dport is %d\n", p_fd_cfg->key.dport);
		}
		p_fd_cfg->key.ethtype = ETH_PKT_IPV4;
		p_fd_cfg->mask.ethtype = ETHTOOL_TRUE_MASK;
		LOG_INFO("ethertype is 0x%x\n", p_fd_cfg->key.ethtype);
		p_fd_cfg->key.proto = IPPROTO_TCP;
		p_fd_cfg->mask.proto = ETHTOOL_TRUE_MASK;
		LOG_INFO("proto is %d\n", p_fd_cfg->key.proto);
		break;
	case UDP_V4_FLOW:
		if (fs->m_u.udp_ip4_spec.ip4src) {
			zte_memcpy_s((u8 *)p_fd_cfg->key.sip + 12, &fs->h_u.udp_ip4_spec.ip4src,
				     ETHTOOL_IP4_LEN);
			zte_memset_s((u8 *)p_fd_cfg->mask.sip + 12, ETHTOOL_TRUE_MASK,
				     ETHTOOL_IP4_LEN);
			LOG_INFO("sip: %d.%d.%d.%d\n", p_fd_cfg->key.sip[12], p_fd_cfg->key.sip[13],
				 p_fd_cfg->key.sip[14], p_fd_cfg->key.sip[15]);
		}
		if (fs->m_u.udp_ip4_spec.ip4dst) {
			zte_memcpy_s((u8 *)p_fd_cfg->key.dip + 12, &fs->h_u.udp_ip4_spec.ip4dst,
				     ETHTOOL_IP4_LEN);
			zte_memset_s((u8 *)p_fd_cfg->mask.dip + 12, ETHTOOL_TRUE_MASK,
				     ETHTOOL_IP4_LEN);
			LOG_INFO("dip: %d.%d.%d.%d\n", p_fd_cfg->key.dip[12], p_fd_cfg->key.dip[13],
				 p_fd_cfg->key.dip[14], p_fd_cfg->key.dip[15]);
		}
		if (fs->m_u.udp_ip4_spec.psrc) {
			p_fd_cfg->key.sport = ntohs(fs->h_u.udp_ip4_spec.psrc);
			p_fd_cfg->mask.sport = ETHTOOL_TRUE_MASK;
			LOG_INFO("sport is %d\n", p_fd_cfg->key.sport);
		}
		if (fs->m_u.udp_ip4_spec.pdst) {
			p_fd_cfg->key.dport = ntohs(fs->h_u.udp_ip4_spec.pdst);
			p_fd_cfg->mask.dport = ETHTOOL_TRUE_MASK;
			LOG_INFO("dport is %d\n", p_fd_cfg->key.dport);
		}
		p_fd_cfg->key.ethtype = ETH_PKT_IPV4;
		p_fd_cfg->mask.ethtype = ETHTOOL_TRUE_MASK;
		LOG_INFO("ethertype is 0x%x\n", p_fd_cfg->key.ethtype);
		p_fd_cfg->key.proto = IPPROTO_UDP;
		p_fd_cfg->mask.proto = ETHTOOL_TRUE_MASK;
		LOG_INFO("proto is %d\n", p_fd_cfg->key.proto);
		break;
	case IPV6_USER_FLOW:
		if (!ipv6_addr_any((struct in6_addr *)fs->m_u.usr_ip6_spec.ip6src)) {
			zte_memcpy_s(p_fd_cfg->key.sip, &fs->h_u.usr_ip6_spec.ip6src,
				     ETHTOOL_IP6_LEN);
			zte_memset_s(p_fd_cfg->mask.sip, ETHTOOL_TRUE_MASK, ETHTOOL_IP6_LEN);
			LOG_INFO(
				"SIP: %02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x\n",
				p_fd_cfg->key.sip[0], p_fd_cfg->key.sip[1], p_fd_cfg->key.sip[2],
				p_fd_cfg->key.sip[3], p_fd_cfg->key.sip[4], p_fd_cfg->key.sip[5],
				p_fd_cfg->key.sip[6], p_fd_cfg->key.sip[7], p_fd_cfg->key.sip[8],
				p_fd_cfg->key.sip[9], p_fd_cfg->key.sip[10], p_fd_cfg->key.sip[11],
				p_fd_cfg->key.sip[12], p_fd_cfg->key.sip[13], p_fd_cfg->key.sip[14],
				p_fd_cfg->key.sip[15]);
		}
		if (!ipv6_addr_any((struct in6_addr *)fs->m_u.usr_ip6_spec.ip6dst)) {
			zte_memcpy_s(p_fd_cfg->key.dip, &fs->h_u.usr_ip6_spec.ip6dst,
				     ETHTOOL_IP6_LEN);
			zte_memset_s(p_fd_cfg->mask.dip, ETHTOOL_TRUE_MASK, ETHTOOL_IP6_LEN);
			LOG_INFO(
				"DIP: %02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x\n",
				p_fd_cfg->key.dip[0], p_fd_cfg->key.dip[1], p_fd_cfg->key.dip[2],
				p_fd_cfg->key.dip[3], p_fd_cfg->key.dip[4], p_fd_cfg->key.dip[5],
				p_fd_cfg->key.dip[6], p_fd_cfg->key.dip[7], p_fd_cfg->key.dip[8],
				p_fd_cfg->key.dip[9], p_fd_cfg->key.dip[10], p_fd_cfg->key.dip[11],
				p_fd_cfg->key.dip[12], p_fd_cfg->key.dip[13], p_fd_cfg->key.dip[14],
				p_fd_cfg->key.dip[15]);
		}
		if (fs->m_u.usr_ip6_spec.l4_proto) {
			p_fd_cfg->key.proto = fs->h_u.usr_ip6_spec.l4_proto;
			p_fd_cfg->mask.proto = ETHTOOL_TRUE_MASK;
			LOG_INFO("proto: %d\n", p_fd_cfg->key.proto);
		}
		p_fd_cfg->key.ethtype = ETH_PKT_IPV6;
		p_fd_cfg->mask.ethtype = ETHTOOL_TRUE_MASK;
		LOG_INFO("ethertype is 0x%x\n", p_fd_cfg->key.ethtype);
		break;
	case TCP_V6_FLOW:
		if (!ipv6_addr_any((struct in6_addr *)fs->m_u.tcp_ip6_spec.ip6src)) {
			zte_memcpy_s(p_fd_cfg->key.sip, &fs->h_u.tcp_ip6_spec.ip6src,
				     ETHTOOL_IP6_LEN);
			zte_memset_s(p_fd_cfg->mask.sip, ETHTOOL_TRUE_MASK, ETHTOOL_IP6_LEN);
			LOG_INFO(
				"SIP: %02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x\n",
				p_fd_cfg->key.sip[0], p_fd_cfg->key.sip[1], p_fd_cfg->key.sip[2],
				p_fd_cfg->key.sip[3], p_fd_cfg->key.sip[4], p_fd_cfg->key.sip[5],
				p_fd_cfg->key.sip[6], p_fd_cfg->key.sip[7], p_fd_cfg->key.sip[8],
				p_fd_cfg->key.sip[9], p_fd_cfg->key.sip[10], p_fd_cfg->key.sip[11],
				p_fd_cfg->key.sip[12], p_fd_cfg->key.sip[13], p_fd_cfg->key.sip[14],
				p_fd_cfg->key.sip[15]);
		}
		if (!ipv6_addr_any((struct in6_addr *)fs->m_u.tcp_ip6_spec.ip6dst)) {
			zte_memcpy_s(p_fd_cfg->key.dip, &fs->h_u.tcp_ip6_spec.ip6dst,
				     ETHTOOL_IP6_LEN);
			zte_memset_s(p_fd_cfg->mask.dip, ETHTOOL_TRUE_MASK, ETHTOOL_IP6_LEN);
			LOG_INFO(
				"DIP: %02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x\n",
				p_fd_cfg->key.dip[0], p_fd_cfg->key.dip[1], p_fd_cfg->key.dip[2],
				p_fd_cfg->key.dip[3], p_fd_cfg->key.dip[4], p_fd_cfg->key.dip[5],
				p_fd_cfg->key.dip[6], p_fd_cfg->key.dip[7], p_fd_cfg->key.dip[8],
				p_fd_cfg->key.dip[9], p_fd_cfg->key.dip[10], p_fd_cfg->key.dip[11],
				p_fd_cfg->key.dip[12], p_fd_cfg->key.dip[13], p_fd_cfg->key.dip[14],
				p_fd_cfg->key.dip[15]);
		}
		if (fs->m_u.tcp_ip6_spec.psrc) {
			p_fd_cfg->key.sport = ntohs(fs->h_u.tcp_ip6_spec.psrc);
			p_fd_cfg->mask.sport = ETHTOOL_TRUE_MASK;
			LOG_INFO("sport is %d\n", p_fd_cfg->key.sport);
		}
		if (fs->m_u.tcp_ip6_spec.pdst) {
			p_fd_cfg->key.dport = ntohs(fs->h_u.tcp_ip6_spec.pdst);
			p_fd_cfg->mask.dport = ETHTOOL_TRUE_MASK;
			LOG_INFO("dport is %d\n", p_fd_cfg->key.dport);
		}
		p_fd_cfg->key.ethtype = ETH_PKT_IPV6;
		p_fd_cfg->mask.ethtype = ETHTOOL_TRUE_MASK;
		LOG_INFO("ethertype is 0x%x\n", p_fd_cfg->key.ethtype);
		p_fd_cfg->key.proto = IPPROTO_TCP;
		p_fd_cfg->mask.proto = ETHTOOL_TRUE_MASK;
		LOG_INFO("proto is %d\n", p_fd_cfg->key.proto);
		break;
	case UDP_V6_FLOW:
		if (!ipv6_addr_any((struct in6_addr *)fs->m_u.udp_ip6_spec.ip6src)) {
			zte_memcpy_s(p_fd_cfg->key.sip, &fs->h_u.udp_ip6_spec.ip6src,
				     ETHTOOL_IP6_LEN);
			zte_memset_s(p_fd_cfg->mask.sip, ETHTOOL_TRUE_MASK, ETHTOOL_IP6_LEN);
			LOG_INFO(
				"SIP: %02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x\n",
				p_fd_cfg->key.sip[0], p_fd_cfg->key.sip[1], p_fd_cfg->key.sip[2],
				p_fd_cfg->key.sip[3], p_fd_cfg->key.sip[4], p_fd_cfg->key.sip[5],
				p_fd_cfg->key.sip[6], p_fd_cfg->key.sip[7], p_fd_cfg->key.sip[8],
				p_fd_cfg->key.sip[9], p_fd_cfg->key.sip[10], p_fd_cfg->key.sip[11],
				p_fd_cfg->key.sip[12], p_fd_cfg->key.sip[13], p_fd_cfg->key.sip[14],
				p_fd_cfg->key.sip[15]);
		}
		if (!ipv6_addr_any((struct in6_addr *)fs->m_u.udp_ip6_spec.ip6dst)) {
			zte_memcpy_s(p_fd_cfg->key.dip, &fs->h_u.udp_ip6_spec.ip6dst,
				     ETHTOOL_IP6_LEN);
			zte_memset_s(p_fd_cfg->mask.dip, ETHTOOL_TRUE_MASK, ETHTOOL_IP6_LEN);
			LOG_INFO(
				"DIP: %02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x\n",
				p_fd_cfg->key.dip[0], p_fd_cfg->key.dip[1], p_fd_cfg->key.dip[2],
				p_fd_cfg->key.dip[3], p_fd_cfg->key.dip[4], p_fd_cfg->key.dip[5],
				p_fd_cfg->key.dip[6], p_fd_cfg->key.dip[7], p_fd_cfg->key.dip[8],
				p_fd_cfg->key.dip[9], p_fd_cfg->key.dip[10], p_fd_cfg->key.dip[11],
				p_fd_cfg->key.dip[12], p_fd_cfg->key.dip[13], p_fd_cfg->key.dip[14],
				p_fd_cfg->key.dip[15]);
		}
		if (fs->m_u.udp_ip6_spec.psrc) {
			p_fd_cfg->key.sport = ntohs(fs->h_u.udp_ip6_spec.psrc);
			p_fd_cfg->mask.sport = ETHTOOL_TRUE_MASK;
			LOG_INFO("sport is %d\n", p_fd_cfg->key.dport);
		}
		if (fs->m_u.udp_ip6_spec.pdst) {
			p_fd_cfg->key.dport = ntohs(fs->h_u.udp_ip6_spec.pdst);
			p_fd_cfg->mask.dport = ETHTOOL_TRUE_MASK;
			LOG_INFO("dport is %d\n", p_fd_cfg->key.dport);
		}
		p_fd_cfg->key.ethtype = ETH_PKT_IPV6;
		p_fd_cfg->mask.ethtype = ETHTOOL_TRUE_MASK;
		LOG_INFO("ethertype is 0x%x\n", p_fd_cfg->key.ethtype);
		p_fd_cfg->key.proto = IPPROTO_UDP;
		p_fd_cfg->mask.proto = ETHTOOL_TRUE_MASK;
		LOG_INFO("proto is %d\n", p_fd_cfg->key.proto);
		break;
	default:
		break;
	}

	if ((fs->flow_type & FLOW_EXT)) {
		LOG_INFO("fs->h_ext.vlan_tci is %d\n", ntohs(fs->h_ext.vlan_tci));
		if (fs->m_ext.vlan_tci) {
			p_fd_cfg->key.cvlan_pri = (ntohs(fs->h_ext.vlan_tci) & VLAN_PCP_MASK) >>
						  VLAN_PCP_SHIFT;
			p_fd_cfg->mask.cvlan_pri = ETHTOOL_TRUE_MASK;
			p_fd_cfg->key.cvlanid = ntohs(fs->h_ext.vlan_tci) & VLAN_VID_MASK;
			p_fd_cfg->mask.cvlanid = ETHTOOL_TRUE_MASK;
			LOG_INFO("VLAN TCI: PRI=%u, VID=%u\n", p_fd_cfg->key.cvlan_pri,
				 p_fd_cfg->key.cvlanid);
		}
	}

	if ((fs->flow_type & FLOW_MAC_EXT) && (!is_zero_ether_addr(fs->m_ext.h_dest))) {
		zte_memcpy_s(p_fd_cfg->key.dmac, fs->h_ext.h_dest, ETH_ALEN);
		zte_memset_s(p_fd_cfg->mask.dmac, ETHTOOL_TRUE_MASK, ETH_ALEN);
		LOG_INFO("dmac is %pM\n", p_fd_cfg->key.dmac);
	}
}
EXPORT_SYMBOL(zxdh_flow_table_add);

static u32 zxdh_vf_fd_add(struct zxdh_msg_info *msg, struct zxdh_reps_info *reps,
			  struct dpp_pf_info_t *pf_info, struct zxdh_vf_item *vf_item,
			  struct zxdh_pf_device *pf_dev)
{
	struct zxdh_fd_cfg_t p_fd_cfg = { 0 };
	u32 handle = 0;
	u32 err = 0;

	zxdh_flow_table_add(&msg->vf_fd_cfg_msg.fs, &p_fd_cfg, pf_info);
	err = zxdh_flow_table_vf_action_add(&msg->vf_fd_cfg_msg.fs, &p_fd_cfg, pf_info);
	if (err != 0) {
		LOG_ERR("failed to add vf_action!\n");
		return 1;
	}

	if (msg->vf_fd_cfg_msg.index == DEFAULT_ADD_INDEX) {
		err = dpp_fd_acl_index_request(pf_info, &handle);
		if (err != 0) {
			LOG_ERR("failed to request index!\n");
			return 1;
		}
	} else {
		handle = msg->vf_fd_cfg_msg.index;
	}
	reps->fd_cfg_resp.index = handle;

	err = dpp_tbl_fd_cfg_add(pf_info, ZXDH_SDT_FD_CFG_TABLE, handle, &p_fd_cfg);
	if (err != 0) {
		LOG_ERR("failed to add fd in np!\n");
		return 1;
	}

	return 0;
}

static u32 zxdh_vf_fd_get(struct zxdh_msg_info *msg, struct zxdh_reps_info *reps,
			  struct dpp_pf_info_t *pf_info, struct zxdh_vf_item *vf_item,
			  struct zxdh_pf_device *pf_dev)
{
	struct zxdh_fd_cfg_t p_fd_cfg = { 0 };
	u32 err = 0;

	err = dpp_tbl_fd_cfg_get(pf_info, ZXDH_SDT_FD_CFG_TABLE, msg->vf_fd_cfg_msg.index,
				 &p_fd_cfg);
	if (err != 0) {
		LOG_ERR("failed to get fd in np!\n");
		return 1;
	}
	return 0;
}

static u32 zxdh_vf_fd_del(struct zxdh_msg_info *msg, struct zxdh_reps_info *reps,
			  struct dpp_pf_info_t *pf_info, struct zxdh_vf_item *vf_item,
			  struct zxdh_pf_device *pf_dev)
{
	u32 index = 0;
	u32 err = 0;

	index = msg->vf_fd_cfg_msg.index;
	if (index >= ETHTOOL_FD_MAX_NUM) {
		LOG_ERR("the index is invlaid: %d\n", index);
		return 1;
	}

	err = dpp_tbl_fd_cfg_del(pf_info, ZXDH_SDT_FD_CFG_TABLE, index);
	if (err != 0) {
		LOG_ERR("failed to del fd in np!\n");
		return 1;
	}

	err = dpp_fd_acl_index_release(pf_info, index);
	if (err) {
		LOG_ERR("failed to release index!\n");
		return -EINVAL;
	}

	return 0;
}

static u32 zxdh_vf_udp_stats_get(struct zxdh_msg_info *msg, struct zxdh_reps_info *reps,
				 struct dpp_pf_info_t *pf_info, struct zxdh_vf_item *vf_item,
				 struct zxdh_pf_device *pf_dev)
{
	s32 err = 0;

	err = dpp_stat_asn_phyport_rx_pkt_cnt_get(pf_info, pf_dev->phy_port, STAT_RD_CLR_MODE_UNCLR,
						  &reps->udp_phy_stats_msg.rx_arn_phy);
	if (err != 0) {
		LOG_ERR("dpp_stat_asn_phyport_rx_pkt_cnt_get failed: %d\n", err);
		return err;
	}

	err = dpp_stat_psn_phyport_tx_pkt_cnt_get(pf_info, pf_dev->phy_port, STAT_RD_CLR_MODE_UNCLR,
						  &reps->udp_phy_stats_msg.tx_psn_phy);
	if (err != 0) {
		LOG_ERR("dpp_stat_psn_phyport_tx_pkt_cnt_get failed: %d\n", err);
		return err;
	}

	err = dpp_stat_psn_phyport_rx_pkt_cnt_get(pf_info, pf_dev->phy_port, STAT_RD_CLR_MODE_UNCLR,
						  &reps->udp_phy_stats_msg.rx_psn_phy);
	if (err != 0) {
		LOG_ERR("dpp_stat_psn_phyport_rx_pkt_cnt_get failed: %d\n", err);
		return err;
	}

	err = dpp_stat_psn_ack_phyport_tx_pkt_cnt_get(pf_info, pf_dev->phy_port,
						      STAT_RD_CLR_MODE_UNCLR,
						      &reps->udp_phy_stats_msg.tx_psn_ack_phy);
	if (err != 0) {
		LOG_ERR("dpp_stat_psn_ack_phyport_tx_pkt_cnt_get failed: %d\n", err);
		return err;
	}

	err = dpp_stat_psn_ack_phyport_rx_pkt_cnt_get(pf_info, pf_dev->phy_port,
						      STAT_RD_CLR_MODE_UNCLR,
						      &reps->udp_phy_stats_msg.rx_psn_ack_phy);
	if (err != 0) {
		LOG_ERR("dpp_stat_psn_ack_phyport_rx_pkt_cnt_get failed: %d\n", err);
		return err;
	}

	return 0;
}

struct zxdh_vf_msg_proc vf_msg_proc[] = {
	{ ZXDH_VF_PORT_INIT, "vf_port_init", zxdh_vf_port_init },
	{ ZXDH_VF_PORT_UNINIT, "vf_port_uninit", zxdh_vf_port_uninit },
	{ ZXDH_VF_PORT_RELOAD, "vf_port_reload", zxdh_vf_port_reload },
	{ ZXDH_MAC_ADD, "vf_all_mac_add", zxdh_vf_all_mac_add },
	{ ZXDH_MAC_DEL, "vf_all_mac_del", zxdh_vf_all_mac_del },
	{ ZXDH_MAC_DUMP, "vf_all_mac_dump", zxdh_vf_all_mac_dump },
	{ ZXDH_IPV6_MAC_ADD, "vf_ipv6_mac_add", zxdh_vf_ipv6_mac_add },
	{ ZXDH_IPV6_MAC_DEL, "vf_ipv6_mac_del", zxdh_vf_ipv6_mac_del },
	{ ZXDH_LACP_MAC_ADD, "vf_lacp_mac_add", zxdh_vf_lacp_mac_add },
	{ ZXDH_LACP_MAC_DEL, "vf_lacp_mac_del", zxdh_vf_lacp_mac_del },
	{ ZXDH_MAC_GET, "vf_mac_get", zxdh_vf_mac_get },
	{ ZXDH_RSS_EN_SET, "vf_rss_state_set", zxdh_vf_rss_state_set },
	{ ZXDH_RXFH_SET, "vf_rxfh_set", zxdh_vf_rxfh_set },
	{ ZXDH_RXFH_GET, "vf_rxfh_get", zxdh_vf_rxfh_get },
	{ ZXDH_RXFH_DEL, "vf_rxfh_del", zxdh_vf_rxfh_del },
	{ ZXDH_THASH_KEY_SET, "vf_thash_key_set", zxdh_vf_thash_key_set },
	{ ZXDH_THASH_KEY_GET, "vf_thash_key_get", zxdh_vf_thash_key_get },
	{ ZXDH_HASH_FUNC_SET, "vf_hash_funcs_set", zxdh_vf_hash_funcs_set },
	{ ZXDH_RX_FLOW_HASH_SET, "vf_rx_flow_hash_set", zxdh_vf_rx_flow_hash_set },
	{ ZXDH_RX_FLOW_HASH_GET, "vf_rx_flow_hash_get", zxdh_vf_rx_flow_hash_get },
	{ ZXDH_PORT_ATTRS_SET, "vf_port_attrs_set", zxdh_vf_port_attrs_set },
	{ ZXDH_PORT_ATTRS_GET, "vf_port_attrs_get", zxdh_vf_port_attrs_get },
	{ ZXDH_PROMISC_SET, "vf_promisc_set", zxdh_vf_promisc_set },
	{ ZXDH_VLAN_FILTER_SET, "vf_vlan_filter_set", zxdh_vf_vlan_filter_set },
	{ ZXDH_VLAN_FILTER_ADD, "vf_rx_vid_add", zxdh_vf_rx_vid_add },
	{ ZXDH_VLAN_FILTER_DEL, "vf_rx_vid_del", zxdh_vf_rx_vid_del },
	{ ZXDH_GET_NP_STATS, "vf_np_stats_get", zxdh_vf_np_stats_get },
	{ ZXDH_VF_GET_UDP_STATS, "vf_udp_stats_get", zxdh_vf_udp_stats_get },
	{ ZXDH_VF_RATE_LIMIT_SET, "vf_rate_limit_set", zxdh_vf_rate_limit_set },
	{ ZXDH_PLCR_UNINIT, "vf_plcr_uninit", zxdh_vf_plcr_uninit },
	{ ZXDH_MAP_PLCR_FLOWID, "vf_map_plcr_flowid", zxdh_vf_plcr_flowid_map },
	{ ZXDH_PLCR_FLOW_INIT, "vf_plcr_flow_init", zxdh_vf_plcr_flow_init },
	{ ZXDH_PLCR_GET_MODE, "vf_plcr_get_mode", zxdh_vf_plcr_get_mode },
	{ ZXDH_PLCR_SET_MODE, "vf_plcr_set_mode", zxdh_vf_plcr_set_mode },
	{ ZXDH_FLOW_HW_ADD, "vf_flow_hw_add", zxdh_vf_flow_hw_add },
	{ ZXDH_FLOW_HW_DEL, "vf_flow_hw_del", zxdh_vf_flow_hw_del },
	{ ZXDH_FLOW_HW_GET, "vf_flow_hw_get", zxdh_vf_flow_hw_get },
	{ ZXDH_FLOW_HW_FLUSH, "vf_flow_hw_flush", zxdh_vf_flow_hw_flush },
	{ ZXDH_VLAN_OFFLOAD_SET, "vf_vlan_strip_set", zxdh_vf_vlan_strip_set },
	{ ZXDH_VXLAN_OFFLOAD_ADD, "vf_vxlan_offload_add", zxdh_vf_vxlan_offload_add },
	{ ZXDH_VXLAN_OFFLOAD_DEL, "vf_vxlan_offload_del", zxdh_vf_vxlan_offload_del },
	{ ZXDH_SET_TPID, "vf_qinq_tpid_cfg", zxdh_vf_qinq_tpid_cfg },
	{ ZXDH_FD_ADD, "vf_fd_add", zxdh_vf_fd_add },
	{ ZXDH_FD_GET, "vf_fd_get", zxdh_vf_fd_get },
	{ ZXDH_FD_DEL, "vf_fd_del", zxdh_vf_fd_del },
	{ ZXDH_FD_EN_SET, "vf_fd_state_set", zxdh_vf_fd_state_set },

	{ ZXDH_PLCR_CAR_PROFILE_ID_ADD, "vf_plcr_profile_id_add", zxdh_vf_plcr_profile_id_add },
	{ ZXDH_PLCR_CAR_PROFILE_ID_DELETE, "vf_plcr_profile_id_detele",
	  zxdh_vf_plcr_profile_id_delete },
	{ ZXDH_PLCR_CAR_PROFILE_CFG_SET, "vf_plcr_profile_cfg_set", zxdh_vf_plcr_profile_cfg_set },
	{ ZXDH_PLCR_CAR_PROFILE_CFG_GET, "vf_plcr_profile_cfg_get", zxdh_vf_plcr_profile_cfg_get },
	{ ZXDH_PLCR_CAR_QUEUE_CFG_SET, "vf_plcr_queue_cfg_set", zxdh_vf_plcr_queue_cfg_set },
	{ ZXDH_PORT_METER_STAT_CLR, "vf_plcr_port_meter_stat_clr",
	  zxdh_vf_plcr_port_meter_stat_clr },
	{ ZXDH_PORT_METER_STAT_GET, "vf_plcr_port_meter_stat_get",
	  zxdh_vf_plcr_port_meter_stat_get },
	{ ZXDH_VF_1588_CALL_NP, "vf_1588_call_np", zxdh_vf_call_np_1588 },
	{ ZXDH_VF_SLOT_ID_GET, "vf_slot_id_get", zxdh_vf_slot_id_get },
	{ ZXDH_MC_CMPAT_VERINFO, "vf_mcode_feature_get", zxdh_vf_mcode_feature_get },
	{ ZXDH_GET_K_CMPAT_VERINFO, "vf_k_cmpat_get", zxdh_vf_k_cmpat_get },
	{ ZXDH_VF_1588_ENABLE, "vf_1588_enable_proc", zxdh_vf_1588_enable_proc },
};

s32 dh_pf_msg_recv_func(void *pay_load, u16 len, void *reps_buffer, u16 *reps_len, void *dev)
{
	struct zxdh_msg_info *msg = (struct zxdh_msg_info *)pay_load;
	struct zxdh_reps_info *reps = (struct zxdh_reps_info *)reps_buffer;
	struct zxdh_pf_device *pf_dev = (struct zxdh_pf_device *)dev;
	struct zxdh_vf_item *vf_item = NULL;
	u32 ret = 0;
	s32 i = 0;
	s32 num = 0;
	struct dpp_pf_info_t pf_info = { 0 };

	if (!pf_dev) {
		LOG_ERR("dev is NULL\n");
		return -1;
	}

	LOG_DEBUG("vport: 0x%x vfitem indx %d\n", msg->hdr.vport, (msg->hdr.pcie_id & (0xff)));
	pf_info.slot = pf_dev->slot_id;
	pf_info.vport = msg->hdr.vport;
	num = sizeof(vf_msg_proc) / sizeof(struct zxdh_vf_msg_proc);
	vf_item = &pf_dev->vf_item[(msg->hdr.pcie_id & (0xff))];
	for (i = 0; i < num; i++) {
		*reps_len = sizeof(union zxdh_msg);
		if (msg->hdr.op_code < ZXDH_GET_SW_STATS)
			*reps_len = ZXDH_REPS_MAX_SIZE_BEFORE57;

		if (vf_msg_proc[i].op_code == msg->hdr.op_code) {
			ret = vf_msg_proc[i].msg_proc(msg, reps, &pf_info, vf_item, pf_dev);
			if (ret != 0) {
				if ((msg->hdr.op_code == ZXDH_MAC_ADD) ||
				    (msg->hdr.op_code == ZXDH_IPV6_MAC_ADD) ||
				    (msg->hdr.op_code == ZXDH_MAC_DUMP) ||
				    (msg->hdr.op_code == ZXDH_LACP_MAC_ADD)) {
					if (ret == ZXDH_REPS_BEYOND_MAC) {
						reps->vf_mac_set_msg.mac_err_flag =
							ZXDH_REPS_BEYOND_MAC;
					} else if (ret == ZXDH_REPS_EXIST_MAC) {
						reps->vf_mac_set_msg.mac_err_flag =
							ZXDH_REPS_EXIST_MAC;
					}
				}
				reps->flag = ZXDH_REPS_FAIL;
				LOG_ERR("%s failed, ret: %d\n", vf_msg_proc[i].proc_name, ret);
				return -1;
			}

			reps->flag = ZXDH_REPS_SUCC;
			return 0;
		}
	}

	LOG_ERR("invalid op_code: [%u]\n", msg->hdr.op_code);
	return -2;
}

s32 dh_pf_msg_recv_func_register(void)
{
	s32 ret = 0;

	ret = zxdh_bar_chan_msg_recv_register(MODULE_VF_BAR_MSG_TO_PF, dh_pf_msg_recv_func);
	if (ret != 0) {
		LOG_ERR("event_id[%d] register failed: %d\n", MODULE_VF_BAR_MSG_TO_PF, ret);
		return ret;
	}

	return ret;
}

void dh_pf_msg_recv_func_unregister(void)
{
	zxdh_bar_chan_msg_recv_unregister(MODULE_VF_BAR_MSG_TO_PF);
}
