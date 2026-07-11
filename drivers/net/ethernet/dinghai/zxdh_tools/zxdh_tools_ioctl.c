// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#include <linux/dinghai/dh_cmd.h>
#include <linux/dinghai/driver.h>
#include "../en_aux.h"
#include "../cmd/msg_chan_priv.h"
#include "../en_aux/priv_queue.h"
#include "zxdh_tools_ioctl.h"
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/rtc.h>

u8 pkt_event_init(struct zxdh_en_device *en_dev)
{
	if (!en_dev->pkt_wq) {
		en_dev->pkt_wq = create_singlethread_workqueue("dh_aux_pkt_events");
		if (!en_dev->pkt_wq) {
			LOG_ERR("events->pkt_wq create_singlethread_workqueue failed: %p\n",
				en_dev->pkt_wq);
			return DHTOOL_ERROR;
		}
	}

	INIT_WORK(&en_dev->capture_save_file_work, capture_save_file_work_handler);
	return 0;
}

void pkt_event_uninit(struct zxdh_en_device *en_dev)
{
	if (en_dev->pkt_wq) {
		destroy_workqueue(en_dev->pkt_wq);
		en_dev->pkt_wq = NULL;
	}
}

u8 pkt_packet_process(struct zxdh_en_device *en_dev, void *buf, u32 len, u8 pkt_flag)
{
	u8 flag = 0;

	if (en_dev->ops->get_coredev_type(en_dev->parent) != DH_COREDEV_PF)
		return 0;

	if (pkt_flag == 0)
		return 0;

	if (len <= ZXDH_PKT_HEDER_LENGTH) {
		LOG_ERR("pkt error, packet len less than pkt_header_length\n");
		return 0;
	}

	if (en_dev->pkt_cap_switch == 1)
		flag = 1;

	if ((en_dev->pkt_save_file.enable_pkt_num_mode == 1 &&
	     (en_dev->pkt_save_file.pkt_cur_num < en_dev->pkt_save_file.pkt_set_count)) ||
	    (en_dev->pkt_save_file.enable_pkt_num_mode == 0 &&
	     (en_dev->pkt_save_file.pkt_file_size > 0))) {
		pkt_packet_to_file(en_dev, (const char *)buf + ZXDH_PKT_HEDER_LENGTH,
				   len - ZXDH_PKT_HEDER_LENGTH);
		flag = 1;
	}

	return flag;
}

u8 pkt_skb_packet_process(struct zxdh_en_device *en_dev, struct sk_buff *skb, u8 pkt_flag)
{
	u8 flag = 0;
	u8 ret = 0;
	void *buffer = NULL;
	unsigned int total_len = skb->len;

	if (en_dev->ops->get_coredev_type(en_dev->parent) != DH_COREDEV_PF)
		return 0;

	if (pkt_flag == 0)
		return 0;

	if (en_dev->pkt_cap_switch == 1)
		flag = 1;

	if ((en_dev->pkt_save_file.enable_pkt_num_mode == 1 &&
	     (en_dev->pkt_save_file.pkt_cur_num < en_dev->pkt_save_file.pkt_set_count)) ||
	    (en_dev->pkt_save_file.enable_pkt_num_mode == 0 &&
	     (en_dev->pkt_save_file.pkt_file_size > 0))) {
		buffer = kmalloc(total_len, GFP_ATOMIC);
		if (!buffer) {
			LOG_ERR("pkt error, kmalloc failed\n");
			return 0;
		}

		ret = skb_copy_bits(skb, 0, buffer, total_len);
		if (ret) {
			kfree(buffer);
			LOG_ERR("pkt error, failed to copy skb data\n");
			return 0;
		}

		pkt_packet_to_file(en_dev, buffer, total_len);
		kfree(buffer);
		flag = 1;
	}

	return flag;
}

u8 zxdh_get_status_flag(struct dpp_pf_info_t *pf_info)
{
	u32 ret = 0;
	struct zxdh_pkt_cap_enable_status cap_status = { 0 };

	ret = dpp_pkt_capture_enable_status_get(pf_info, &cap_status);
	if (ret != 0) {
		DHTOOLS_LOG_ERR("dpp_pkt_capture_enable_status_get failed, ret:%d!!!\n", ret);
		return DHTOOL_ERROR;
	}

	if (cap_status.panel_rx_enable_status == 1 || cap_status.panel_tx_enable_status == 1 ||
	    cap_status.vqm_rx_enable_status == 1 || cap_status.vqm_tx_enable_status == 1 ||
	    cap_status.rdma_rx_enable_status == 1 || cap_status.rdma_tx_enable_status == 1) {
		return zxdh_cap_enable;
	}

	return ret;
}

u8 zxdh_get_rule_flag(struct dpp_pf_info_t *pf_info)
{
	u32 ret = 0;
	struct zxdh_pkt_cap_rule *pkt_rule = NULL;
	u32 entry_num = max_entry_num;

	pkt_rule = kcalloc(entry_num, sizeof(*pkt_rule), GFP_KERNEL);
	if (!pkt_rule)
		return DHTOOL_ERROR;

	ret = dpp_pkt_capture_table_dump(pf_info, pkt_rule, &entry_num);
	if (ret != 0) {
		SAFE_KFREE(pkt_rule);
		DHTOOLS_LOG_ERR("dpp_pkt_capture_table_dump failed, ret:%d!!!\n", ret);
		return DHTOOL_ERROR;
	}

	if (entry_num != 0) {
		SAFE_KFREE(pkt_rule);
		return zxdh_cap_enable;
	}

	SAFE_KFREE(pkt_rule);
	return ret;
}

u32 zxdh_pkt_capture_enable(struct net_device *netdev, struct zxdh_tools_msg *tool_msg,
			    struct zxdh_pkt_capture_msg *pkt_msg, struct dpp_pf_info_t *pf_info)
{
	u32 ret = 0;
	u8 zxdh_config_flag = 0;
	u8 zxdh_rule_flag = 0;
	u8 zxdh_pkt_cap_point = 0;
	struct zxdh_en_device *en_dev = NULL;
	struct zxdh_en_priv *en_priv = NULL;

	en_priv = netdev_priv(netdev);
	en_dev = &en_priv->edev;
	if (en_dev->ops->get_coredev_type(en_dev->parent) != DH_COREDEV_PF)
		return DHTOOL_ERROR;

	zxdh_pkt_cap_point = pkt_msg->payload[0];
	if (zxdh_pkt_cap_point > DH_PKT_CAP_POINT_MAX)
		return DHTOOL_ERROR;

	zxdh_config_flag = zxdh_get_status_flag(pf_info);
	zxdh_rule_flag = zxdh_get_rule_flag(pf_info);
	if (zxdh_config_flag == 0 && zxdh_rule_flag == 0 && en_dev->pkt_save_file_flag == 0) {
		en_dev->pkt_dev_flag = 1;
		goto capture_enale;
	} else if (zxdh_config_flag == 1 || zxdh_rule_flag == 1 ||
		   en_dev->pkt_save_file_flag == 1) {
		if (en_dev->pkt_dev_flag == 0)
			return MSG_RECV_PKT_CAP_PF_LOCK;

		goto capture_enale;
	} else {
		return DHTOOL_ERROR;
	}

capture_enale:
	ret = dpp_pkt_capture_enable(pf_info, zxdh_pkt_cap_point);
	if (ret != 0) {
		DHTOOLS_LOG_ERR("dpp_pkt_capture_enable failed!!!\n");
		return DHTOOL_ERROR;
	}
	en_dev->pkt_cap_switch = 0;
	return ret;
}

u32 zxdh_pkt_capture_disable(struct net_device *netdev, struct zxdh_tools_msg *tool_msg,
			     struct zxdh_pkt_capture_msg *pkt_msg, struct dpp_pf_info_t *pf_info)
{
	u32 ret = 0;
	u8 zxdh_config_flag = 0;
	u8 zxdh_rule_flag = 0;
	u8 zxdh_pkt_cap_point = 0;
	struct zxdh_en_device *en_dev = NULL;
	struct zxdh_en_priv *en_priv = NULL;

	en_priv = netdev_priv(netdev);
	en_dev = &en_priv->edev;
	if (en_dev->ops->get_coredev_type(en_dev->parent) != DH_COREDEV_PF)
		return DHTOOL_ERROR;

	zxdh_pkt_cap_point = pkt_msg->payload[0];
	if (zxdh_pkt_cap_point > DH_PKT_CAP_POINT_MAX)
		return DHTOOL_ERROR;

	zxdh_config_flag = zxdh_get_status_flag(pf_info);
	zxdh_rule_flag = zxdh_get_rule_flag(pf_info);
	if (zxdh_config_flag == 0 && zxdh_rule_flag == 0 && en_dev->pkt_save_file_flag == 0) {
		goto capture_disable;
	} else if (zxdh_config_flag == 1 || zxdh_rule_flag == 1 ||
		   en_dev->pkt_save_file_flag == 1) {
		if (en_dev->pkt_dev_flag == 0)
			return MSG_RECV_PKT_CAP_PF_LOCK;

		goto capture_disable;
	} else {
		return DHTOOL_ERROR;
	}
capture_disable:
	ret = dpp_pkt_capture_disable(pf_info, zxdh_pkt_cap_point);
	if (ret != 0) {
		DHTOOLS_LOG_ERR("%s failed!!!\n", __func__);
		return DHTOOL_ERROR;
	}

	zxdh_config_flag = zxdh_get_status_flag(pf_info);
	zxdh_rule_flag = zxdh_get_rule_flag(pf_info);
	if (zxdh_config_flag == 0 && zxdh_rule_flag == 0 && en_dev->pkt_save_file_flag == 0) {
		en_dev->pkt_dev_flag = 0;
		ret = dpp_pkt_capture_speed_set(pf_info, ZXDH_PKT_INIT_SPEED);
		if (ret != 0) {
			DHTOOLS_LOG_ERR("dpp_pkt_capture_speed_set failed, ret:%d!!!\n", ret);
			return DHTOOL_ERROR;
		}
		en_dev->pkt_dev_speed = ZXDH_PKT_INIT_SPEED;
	}
	return ret;
}

u32 zxdh_pkt_capture_disable_all(struct net_device *netdev, struct zxdh_tools_msg *tool_msg,
				 struct zxdh_pkt_capture_msg *pkt_msg,
				 struct dpp_pf_info_t *pf_info)
{
	u32 ret = 0;
	u8 zxdh_config_flag = 0;
	u8 zxdh_rule_flag = 0;
	struct zxdh_en_device *en_dev = NULL;
	struct zxdh_en_priv *en_priv = NULL;

	en_priv = netdev_priv(netdev);
	en_dev = &en_priv->edev;
	if (en_dev->ops->get_coredev_type(en_dev->parent) != DH_COREDEV_PF)
		return DHTOOL_ERROR;

	zxdh_config_flag = zxdh_get_status_flag(pf_info);
	zxdh_rule_flag = zxdh_get_rule_flag(pf_info);
	if (zxdh_config_flag == 0 && zxdh_rule_flag == 0 && en_dev->pkt_save_file_flag == 0) {
		goto capture_disable_all;
	} else if (zxdh_config_flag == 1 || zxdh_rule_flag == 1 ||
		   en_dev->pkt_save_file_flag == 1) {
		if (en_dev->pkt_dev_flag == 0)
			return MSG_RECV_PKT_CAP_PF_LOCK;
		goto capture_disable_all;

	} else {
		return DHTOOL_ERROR;
	}

capture_disable_all:
	ret = dpp_pkt_capture_disable_all(pf_info);
	if (ret != 0) {
		DHTOOLS_LOG_ERR("dpp_pkt_capture_disable_all failed, ret:%d!!!\n", ret);
		return DHTOOL_ERROR;
	}

	zxdh_config_flag = zxdh_get_status_flag(pf_info);
	zxdh_rule_flag = zxdh_get_rule_flag(pf_info);
	if (zxdh_config_flag == 0 && zxdh_rule_flag == 0 && en_dev->pkt_save_file_flag == 0) {
		en_dev->pkt_dev_flag = 0;
		ret = dpp_pkt_capture_speed_set(pf_info, ZXDH_PKT_INIT_SPEED);
		if (ret != 0) {
			DHTOOLS_LOG_ERR("dpp_pkt_capture_speed_set failed, ret:%d!!!\n", ret);
			return DHTOOL_ERROR;
		}
		en_dev->pkt_dev_speed = ZXDH_PKT_INIT_SPEED;
	}
	en_dev->pkt_cap_switch = 1;
	return ret;
}

u32 zxdh_pkt_capture_rule_insert(struct net_device *netdev, struct zxdh_tools_msg *tool_msg,
				 struct zxdh_pkt_capture_msg *pkt_msg,
				 struct dpp_pf_info_t *pf_info)
{
	u32 ret = 0;
	u32 tcam_index = 0;
	u8 zxdh_config_flag = 0;
	u8 zxdh_rule_flag = 0;
	struct zxdh_pkt_cap_rule_rule_insert *zxdh_pkt_insert_rule = NULL;
	struct zxdh_pkt_cap_rule *pkt_rule = NULL;
	struct zxdh_en_device *en_dev = NULL;
	struct zxdh_en_priv *en_priv = NULL;

	en_priv = netdev_priv(netdev);
	en_dev = &en_priv->edev;
	if (en_dev->ops->get_coredev_type(en_dev->parent) != DH_COREDEV_PF)
		return DHTOOL_ERROR;

	zxdh_config_flag = zxdh_get_status_flag(pf_info);
	zxdh_rule_flag = zxdh_get_rule_flag(pf_info);
	if (zxdh_config_flag == 0 && zxdh_rule_flag == 0 && en_dev->pkt_save_file_flag == 0) {
		en_dev->pkt_dev_flag = 1;
		goto rule_insert;
	} else if (zxdh_config_flag == 1 || zxdh_rule_flag == 1 ||
		   en_dev->pkt_save_file_flag == 1) {
		if (en_dev->pkt_dev_flag == 0)
			return MSG_RECV_PKT_CAP_PF_LOCK;
		goto rule_insert;
	} else {
		return DHTOOL_ERROR;
	}

rule_insert:
	zxdh_pkt_insert_rule = kzalloc(sizeof(*zxdh_pkt_insert_rule), GFP_KERNEL);
	if (!zxdh_pkt_insert_rule)
		return DHTOOL_ERROR;

	pkt_rule = kzalloc(sizeof(*pkt_rule), GFP_KERNEL);
	if (!pkt_rule) {
		SAFE_KFREE(zxdh_pkt_insert_rule);
		return DHTOOL_ERROR;
	}

	memcpy(zxdh_pkt_insert_rule, pkt_msg->payload,
	       sizeof(struct zxdh_pkt_cap_rule_rule_insert));

	DHTOOLS_LOG_INFO("rule_index %d\n", zxdh_pkt_insert_rule->rule_index);

	ret = dpp_pkt_capture_rule_index_to_tcam_index(zxdh_pkt_insert_rule->rule_index,
						       zxdh_pkt_insert_rule->cap_mode,
						       zxdh_pkt_insert_rule->cap_point,
						       &tcam_index);
	if (ret != 0) {
		DHTOOLS_LOG_ERR("dpp_pkt_capture_rule_index_to_tcam_index failed, ret:%d!!!\n",
				ret);
		SAFE_KFREE(zxdh_pkt_insert_rule);
		SAFE_KFREE(pkt_rule);
		return DHTOOL_ERROR;
	}

	DHTOOLS_LOG_INFO("tcam_index %d\n", tcam_index);

	pkt_rule->rule_config = zxdh_pkt_insert_rule->rule_config;
	pkt_rule->pkt_cap_key = zxdh_pkt_insert_rule->pkt_cap_key;
	pkt_rule->tcam_index = tcam_index;
	pkt_rule->dst_vqm_vfid = VQM_VFID(pf_info->vport);
	ret = dpp_pkt_capture_item_insert(pf_info, pkt_rule);
	if (ret != 0)
		DHTOOLS_LOG_ERR("dpp_pkt_capture_item_insert failed, ret:%d!!!\n", ret);

	SAFE_KFREE(zxdh_pkt_insert_rule);
	SAFE_KFREE(pkt_rule);
	return ret;
}

u32 zxdh_pkt_capture_rule_delete(struct net_device *netdev, struct zxdh_tools_msg *tool_msg,
				 struct zxdh_pkt_capture_msg *pkt_msg,
				 struct dpp_pf_info_t *pf_info)
{
	u32 ret = 0;
	u32 tcam_index = 0;
	u32 i = 0;
	u8 zxdh_config_flag = 0;
	u8 zxdh_rule_flag = 0;
	struct zxdh_pkt_cap_rule_rule_delete *zxdh_pkt_delete_rule = NULL;
	struct zxdh_en_device *en_dev = NULL;
	struct zxdh_en_priv *en_priv = NULL;

	en_priv = netdev_priv(netdev);
	en_dev = &en_priv->edev;
	if (en_dev->ops->get_coredev_type(en_dev->parent) != DH_COREDEV_PF)
		return DHTOOL_ERROR;

	zxdh_config_flag = zxdh_get_status_flag(pf_info);
	zxdh_rule_flag = zxdh_get_rule_flag(pf_info);
	if (zxdh_config_flag == 0 && zxdh_rule_flag == 0 && en_dev->pkt_save_file_flag == 0) {
		goto del_rule;
	} else if (zxdh_config_flag == 1 || zxdh_rule_flag == 1 ||
		   en_dev->pkt_save_file_flag == 1) {
		if (en_dev->pkt_dev_flag == 0)
			return MSG_RECV_PKT_CAP_PF_LOCK;

		goto del_rule;
	} else {
		return DHTOOL_ERROR;
	}

del_rule:
	zxdh_pkt_delete_rule = kzalloc(sizeof(*zxdh_pkt_delete_rule), GFP_KERNEL);
	if (!zxdh_pkt_delete_rule)
		return DHTOOL_ERROR;

	memcpy(zxdh_pkt_delete_rule, pkt_msg->payload,
	       sizeof(struct zxdh_pkt_cap_rule_rule_delete));
	DHTOOLS_LOG_INFO("rule_index %d, is_mode_all%d,is_all%d\n",
			 zxdh_pkt_delete_rule->rule_index, zxdh_pkt_delete_rule->is_mode_all,
			 zxdh_pkt_delete_rule->is_all);

	if ((zxdh_pkt_delete_rule->is_mode_all == 0) && (zxdh_pkt_delete_rule->is_all == 1)) {
		ret = dpp_pkt_capture_table_flush(pf_info);
		if (ret != 0) {
			SAFE_KFREE(zxdh_pkt_delete_rule);
			DHTOOLS_LOG_ERR("dpp_pkt_capture_table_flush failed, ret:%d!!!\n", ret);
			return DHTOOL_ERROR;
		}
	} else if ((zxdh_pkt_delete_rule->is_mode_all == 1) &&
		   (zxdh_pkt_delete_rule->is_all == 1)) {
		if (zxdh_pkt_delete_rule->cap_mode == DH_PKT_CAP_MODE_NORMAL) {
			for (i = 0; i < normal_tcam_index; i++) {
				ret = dpp_pkt_capture_item_delete(pf_info, i);
				if (ret != 0) {
					SAFE_KFREE(zxdh_pkt_delete_rule);
					DHTOOLS_LOG_ERR(
						"dpp_pkt_capture_item_delete failed, ret:%d!!!\n",
						ret);
					return DHTOOL_ERROR;
				}
			}
		}

		if (zxdh_pkt_delete_rule->cap_mode == DH_PKT_CAP_MODE_KEY_WORD) {
			for (i = 60; i < key_tcam_index; i++) {
				ret = dpp_pkt_capture_item_delete(pf_info, i);
				if (ret != 0) {
					SAFE_KFREE(zxdh_pkt_delete_rule);
					DHTOOLS_LOG_ERR(
						"dpp_pkt_capture_item_delete failed, ret:%d!!!\n",
						ret);
					return DHTOOL_ERROR;
				}
			}
		}
	} else {
		ret = dpp_pkt_capture_rule_index_to_tcam_index(zxdh_pkt_delete_rule->rule_index,
							       zxdh_pkt_delete_rule->cap_mode,
							       zxdh_pkt_delete_rule->cap_point,
							       &tcam_index);
		if (ret != 0) {
			SAFE_KFREE(zxdh_pkt_delete_rule);
			DHTOOLS_LOG_ERR(
				"dpp_pkt_capture_rule_index_to_tcam_index failed, ret:%d!!!\n",
				ret);
			return DHTOOL_ERROR;
		}

		DHTOOLS_LOG_INFO("tcam_index %d\n", tcam_index);
		ret = dpp_pkt_capture_item_delete(pf_info, tcam_index);
		if (ret != 0) {
			SAFE_KFREE(zxdh_pkt_delete_rule);
			DHTOOLS_LOG_ERR("dpp_pkt_capture_item_delete failed, ret:%d!!!\n", ret);
			return DHTOOL_ERROR;
		}
	}

	zxdh_config_flag = zxdh_get_status_flag(pf_info);
	zxdh_rule_flag = zxdh_get_rule_flag(pf_info);
	if (zxdh_config_flag == 0 && zxdh_rule_flag == 0 && en_dev->pkt_save_file_flag == 0)
		en_dev->pkt_dev_flag = 0;

	SAFE_KFREE(zxdh_pkt_delete_rule);
	return ret;
}

u32 zxdh_pkt_capture_cmd_show(struct net_device *netdev, struct zxdh_tools_msg *tool_msg,
			      struct zxdh_pkt_capture_msg *pkt_msg, struct dpp_pf_info_t *pf_info)
{
	u32 ret = 0;
	u32 i = 0;
	enum zxdh_pkt_cap_mode cap_mode = 0;
	u32 rule_index = 0;
	u32 entry_num = max_entry_num;
	u8 zxdh_config_flag = 0;
	u8 zxdh_rule_flag = 0;
	struct zxdh_pkt_cap_cmd_show *rule_show_info = NULL;
	struct zxdh_pkt_cap_rule *pkt_rule = NULL;
	struct zxdh_pkt_cap_enable_status cap_status = { 0 };
	struct zxdh_en_device *en_dev = NULL;
	struct zxdh_en_priv *en_priv = NULL;

	en_priv = netdev_priv(netdev);
	en_dev = &en_priv->edev;
	if (en_dev->ops->get_coredev_type(en_dev->parent) != DH_COREDEV_PF)
		return DHTOOL_ERROR;

	zxdh_config_flag = zxdh_get_status_flag(pf_info);
	zxdh_rule_flag = zxdh_get_rule_flag(pf_info);
	if (zxdh_config_flag == 0 && zxdh_rule_flag == 0 && en_dev->pkt_save_file_flag == 0) {
		goto rule_show;
	} else if (zxdh_config_flag == 1 || zxdh_rule_flag == 1 ||
		   en_dev->pkt_save_file_flag == 1) {
		if (en_dev->pkt_dev_flag == 0)
			return MSG_RECV_PKT_CAP_PF_LOCK;

		goto rule_show;
	} else {
		return DHTOOL_ERROR;
	}

rule_show:
	rule_show_info = kzalloc(sizeof(*rule_show_info), GFP_KERNEL);
	if (!rule_show_info)
		return DHTOOL_ERROR;

	pkt_rule = kcalloc(entry_num, sizeof(*pkt_rule), GFP_KERNEL);
	if (!pkt_rule) {
		SAFE_KFREE(rule_show_info);
		return DHTOOL_ERROR;
	}

	ret = dpp_pkt_capture_enable_status_get(pf_info, &cap_status);
	if (ret != 0) {
		DHTOOLS_LOG_ERR("dpp_pkt_capture_enable_status_get failed, ret:%d!!!\n", ret);
		SAFE_KFREE(pkt_rule);
		SAFE_KFREE(rule_show_info);
		return DHTOOL_ERROR;
	}

	ret = dpp_pkt_capture_table_dump(pf_info, pkt_rule, &entry_num);
	if (ret != 0) {
		SAFE_KFREE(pkt_rule);
		SAFE_KFREE(rule_show_info);
		DHTOOLS_LOG_ERR("dpp_pkt_capture_table_dump failed, ret:%d!!!\n", ret);
		return DHTOOL_ERROR;
	}

	DHTOOLS_LOG_INFO("entry_num %d\n", entry_num);
	for (i = 0; i < entry_num; i++) {
		dpp_pkt_capture_tcam_index_to_rule_index(pkt_rule[i].tcam_index, &cap_mode,
							 &rule_index);
		rule_show_info->entry_array[i].cap_mode = cap_mode;
		rule_show_info->entry_array[i].rule_index = rule_index;
		rule_show_info->entry_array[i].cap_point = pkt_rule[i].pkt_cap_key.capture_pkt_flag;
		rule_show_info->entry_array[i].pkt_cap_key = pkt_rule[i].pkt_cap_key;
		rule_show_info->entry_array[i].rule_config = pkt_rule[i].rule_config;

		memcpy(rule_show_info->entry_array[i].dev_name, netdev->name, IFNAMSIZ);
	}

	rule_show_info->speed = en_dev->pkt_dev_speed;
	rule_show_info->entry_num = entry_num;
	rule_show_info->enable_status = cap_status;
	if (en_dev->pkt_save_file.pkt_file_size != 0)
		rule_show_info->is_save_to_file = 1;

	memcpy(rule_show_info->file_path, en_dev->pkt_save_file.file_path,
	       sizeof(en_dev->pkt_save_file.file_path));
	rule_show_info->file_size = en_dev->pkt_save_file.pkt_file_size;
	rule_show_info->pkt_count = en_dev->pkt_save_file.pkt_set_count;

	if (unlikely(copy_to_user((void __user *)tool_msg->msg_reps, rule_show_info,
				  sizeof(struct zxdh_pkt_cap_cmd_show)))) {
		DHTOOLS_LOG_ERR("copy_to_user failed!!!\n");
		SAFE_KFREE(pkt_rule);
		SAFE_KFREE(rule_show_info);
		return DHTOOL_ERROR;
	}

	SAFE_KFREE(pkt_rule);
	SAFE_KFREE(rule_show_info);
	return ret;
}

struct file *open_log_file(const char *path)
{
	struct file *filp = filp_open(path, O_CREAT | O_WRONLY, 0644);

	if (IS_ERR(filp)) {
		DHTOOLS_LOG_ERR("Failed to open log file: %ld\n", PTR_ERR(filp));
		return NULL;
	}
	return filp;
}

void close_log_file(struct file *filp)
{
	if (filp)
		filp_close(filp, NULL);
}

void zxdh_pkt_clear_date(struct zxdh_en_device *en_dev)
{
	en_dev->pkt_save_file.pkt_rbuf_idx = 0;
	en_dev->pkt_save_file.ubuf_idx = 0;
	en_dev->pkt_save_file.pkt_file_size = 0;
	en_dev->pkt_save_file.pkt_cur_num = 0;
	en_dev->pkt_save_file.pkt_set_count = 0;
	en_dev->pkt_save_file.total_written_bytes = 0;
	en_dev->pkt_save_file.pkt_file_size = 0;
	en_dev->pkt_save_file.pkt_set_count = 0;
	en_dev->pkt_addr_marked = 0;
	memset(en_dev->pkt_save_file.file_path, 0, sizeof(en_dev->pkt_save_file.file_path));
	if (en_dev->pkt_file_info)
		SAFE_KFREE(en_dev->pkt_file_info);
	if (en_dev->pkt_save_file.log_file) {
		close_log_file(en_dev->pkt_save_file.log_file);
		en_dev->pkt_save_file.log_file = NULL;
	}
}

void capture_save_file_work_handler(struct work_struct *work)
{
	struct timespec64 ts;
	struct tm tm_info;
	long usec = 0;
	size_t buffer_size = 0;
	s32 write_size = 0;
	ssize_t ret;
	size_t i = 0;
	ssize_t filesize = 0;
	u32 data_len = 0;
	char *buf_ptr = NULL;
	char *buffer = NULL;
	u8 *pkt_buf_addr = NULL;
	struct dpp_pf_info_t pf_info = { 0 };
	struct zxdh_en_device *en_dev =
		container_of(work, struct zxdh_en_device, capture_save_file_work);

	if (!en_dev->pkt_file_info) {
		DHTOOLS_LOG_ERR("pkt_work_handler pkt addr error, buf_idx:%d\n",
				en_dev->pkt_save_file.ubuf_idx);
		return;
	}

	pkt_buf_addr = en_dev->pkt_file_info[en_dev->pkt_save_file.ubuf_idx].pkt_addr_array;
	if (!pkt_buf_addr) {
		DHTOOLS_LOG_ERR("pkt_work_handler buffer addr error, buf_idx:%d\n",
				en_dev->pkt_save_file.ubuf_idx);
		return;
	}

	data_len = en_dev->pkt_file_info[en_dev->pkt_save_file.ubuf_idx].pkt_buf_len;
	buffer_size = data_len * 4;
	pf_info.slot = en_dev->slot_id;
	pf_info.vport = en_dev->vport;

	buffer = kzalloc(buffer_size, GFP_KERNEL);
	if (!buffer) {
		DHTOOLS_LOG_ERR("Failed to allocate buffer\n");
		SAFE_KFREE(
			en_dev->pkt_file_info[en_dev->pkt_save_file.ubuf_idx].pkt_addr_array);
		zxdh_pkt_clear_date(en_dev);
		en_dev->pkt_file_num = 0;
		dpp_pkt_capture_disable_all(&pf_info);
		en_dev->pkt_cap_switch = 1;
		return;
	}

	buf_ptr = buffer;
	ktime_get_real_ts64(&ts);
	ts.tv_sec += EIGHT_HOURS_SECONDS;
	time64_to_tm(ts.tv_sec, 0, &tm_info);
	usec = ts.tv_nsec / 1000;

	write_size = snprintf(buf_ptr, buffer_size,
			      "%04ld-%02d-%02d %02d:%02d:%02d.%06lu 00000000 ",
			      tm_info.tm_year + 1900, tm_info.tm_mon + 1, tm_info.tm_mday,
			      tm_info.tm_hour, tm_info.tm_min, tm_info.tm_sec, usec);

	if (write_size < 0) {
		DHTOOLS_LOG_ERR("snprintf error\n");
		SAFE_KFREE(
			en_dev->pkt_file_info[en_dev->pkt_save_file.ubuf_idx].pkt_addr_array);
		zxdh_pkt_clear_date(en_dev);
		en_dev->pkt_file_num = 0;
		dpp_pkt_capture_disable_all(&pf_info);
		en_dev->pkt_cap_switch = 1;
		goto out_free;
	}

	buf_ptr += write_size;
	for (i = 0; i < data_len; i++)
		buf_ptr += snprintf(buf_ptr, 4, "%02x ", (unsigned char)pkt_buf_addr[i]);

	*buf_ptr++ = '\n';
	SAFE_KFREE(en_dev->pkt_file_info[en_dev->pkt_save_file.ubuf_idx].pkt_addr_array);
	if (en_dev->pkt_save_file.log_file) {
		filesize = i_size_read(file_inode(en_dev->pkt_save_file.log_file));
		filesize = filesize + (buf_ptr - buffer);
		if (filesize > (en_dev->pkt_save_file.pkt_file_size * 1024 * 1024)) {
			if (en_dev->pkt_save_file.enable_pkt_num_mode == 1) {
				dpp_pkt_capture_disable_all(&pf_info);
				en_dev->pkt_cap_switch = 1;
				en_dev->pkt_file_num = 0;
				en_dev->pkt_save_file_flag = 0;
				while (en_dev->pkt_save_file.ubuf_idx !=
				       en_dev->pkt_save_file.pkt_rbuf_idx) {
					if (en_dev->pkt_file_info[en_dev->pkt_save_file.ubuf_idx]
						.pkt_addr_array) {
						SAFE_KFREE(
							en_dev->pkt_file_info[en_dev->pkt_save_file
										      .ubuf_idx]
								.pkt_addr_array);
					}
					en_dev->pkt_save_file.ubuf_idx++;
					if (en_dev->pkt_save_file.ubuf_idx >=
					    (ZXDH_MQ_PAIRS_NUM * ZXDH_PF_MAX_DESC_NUM(en_dev))) {
						en_dev->pkt_save_file.ubuf_idx = 0;
					}
				}

				if (en_dev->pkt_file_info[en_dev->pkt_save_file.pkt_rbuf_idx]
					    .pkt_addr_array) {
					SAFE_KFREE(en_dev->pkt_file_info[en_dev->pkt_save_file
										 .pkt_rbuf_idx]
							   .pkt_addr_array);
				}
				zxdh_pkt_clear_date(en_dev);
				DHTOOLS_LOG_INFO("pkt size is reach, close file\n");
				goto out_free;
			}
			en_dev->pkt_save_file.total_written_bytes = 0;
			en_dev->pkt_save_file.file_pos = 0;
			en_dev->pkt_save_file.log_file->f_pos = 0;
		}
	}

	if (en_dev->pkt_save_file.log_file) {
		ret = kernel_write(en_dev->pkt_save_file.log_file, buffer, buf_ptr - buffer,
				   &en_dev->pkt_save_file.file_pos);
		if (ret < 0) {
			DHTOOLS_LOG_ERR("Failed to write to log file: %zd\n", ret);
			en_dev->pkt_file_num = 0;
			zxdh_pkt_clear_date(en_dev);
			dpp_pkt_capture_disable_all(&pf_info);
			en_dev->pkt_cap_switch = 1;
			goto out_free;
		}
	} else {
		zxdh_pkt_clear_date(en_dev);
		en_dev->pkt_file_num = 0;
		dpp_pkt_capture_disable_all(&pf_info);
		en_dev->pkt_cap_switch = 1;
		goto out_free;
	}

	en_dev->pkt_save_file.ubuf_idx++;
	if (en_dev->pkt_save_file.ubuf_idx >=
	    (ZXDH_MQ_PAIRS_NUM * ZXDH_PF_MAX_DESC_NUM(en_dev))) {
		en_dev->pkt_save_file.ubuf_idx = 0;
	}

	en_dev->pkt_save_file.total_written_bytes += ret;

	if (en_dev->pkt_save_file.enable_pkt_num_mode == 1) {
		en_dev->pkt_save_file.pkt_cur_num++;
		if (en_dev->pkt_save_file.pkt_cur_num == en_dev->pkt_save_file.pkt_set_count) {
			dpp_pkt_capture_disable_all(&pf_info);
			en_dev->pkt_cap_switch = 1;
			en_dev->pkt_save_file_flag = 0;
			en_dev->pkt_file_num = 0;
			while (en_dev->pkt_save_file.ubuf_idx !=
			       en_dev->pkt_save_file.pkt_rbuf_idx) {
				if (en_dev->pkt_file_info[en_dev->pkt_save_file
						.ubuf_idx].pkt_addr_array) {
					SAFE_KFREE(en_dev->pkt_file_info[en_dev->pkt_save_file
										 .ubuf_idx]
							   .pkt_addr_array);
				}
				en_dev->pkt_save_file.ubuf_idx++;
				if (en_dev->pkt_save_file.ubuf_idx >=
				    (ZXDH_MQ_PAIRS_NUM * ZXDH_PF_MAX_DESC_NUM(en_dev))) {
					en_dev->pkt_save_file.ubuf_idx = 0;
				}
			}

			if (en_dev->pkt_file_info[en_dev->pkt_save_file.pkt_rbuf_idx]
				    .pkt_addr_array) {
				SAFE_KFREE(en_dev->pkt_file_info[en_dev->pkt_save_file.pkt_rbuf_idx]
						   .pkt_addr_array);
			}

			en_dev->pkt_save_file.file_pos = 0;
			en_dev->pkt_save_file.log_file->f_pos = 0;
			zxdh_pkt_clear_date(en_dev);
			DHTOOLS_LOG_INFO("pkt count is reach, close file\n");
			goto out_free;
		}
	}
out_free:
	SAFE_KFREE(buffer);
}

ssize_t pkt_packet_to_file(struct zxdh_en_device *en_dev, const char *data, size_t len)
{
	struct zxdh_en_priv *en_priv = netdev_priv(en_dev->netdev);

	if (!en_dev->pkt_file_info) {
		DHTOOLS_LOG_ERR("dev not alloc memory\n");
		return 0;
	}

	if (en_dev->pkt_file_info[en_dev->pkt_save_file.pkt_rbuf_idx].pkt_addr_array) {
		if (!en_dev->pkt_addr_marked) {
			DHTOOLS_LOG_ERR("pkt cap buffer drop\n");
			en_dev->pkt_addr_marked = 1;
		}
		return 0;
	}
	en_dev->pkt_addr_marked = 0;

	en_dev->pkt_file_info[en_dev->pkt_save_file.pkt_rbuf_idx].pkt_addr_array =
		kzalloc(len, GFP_ATOMIC);
	if (!en_dev->pkt_file_info[en_dev->pkt_save_file.pkt_rbuf_idx].pkt_addr_array) {
		DHTOOLS_LOG_ERR("kzalloc pkt buffer error, buf len:%zu\n", len);
		return 0;
	}

	memcpy(en_dev->pkt_file_info[en_dev->pkt_save_file.pkt_rbuf_idx].pkt_addr_array, data, len);
	en_dev->pkt_file_info[en_dev->pkt_save_file.pkt_rbuf_idx].pkt_buf_len = len;

	if (en_dev->pkt_wq) {
		queue_work(en_dev->pkt_wq, &en_priv->edev.capture_save_file_work);
		en_dev->pkt_save_file.pkt_rbuf_idx++;
		if (en_dev->pkt_save_file.pkt_rbuf_idx >=
		    (ZXDH_MQ_PAIRS_NUM * ZXDH_PF_MAX_DESC_NUM(en_dev))) {
			en_dev->pkt_save_file.pkt_rbuf_idx = 0;
		}
	}
	return 0;
}

u32 zxdh_pkt_capture_save_to_file(struct net_device *netdev, struct zxdh_tools_msg *tool_msg,
				  struct zxdh_pkt_capture_msg *pkt_msg,
				  struct dpp_pf_info_t *pf_info)
{
	u32 ret = 0;
	struct zxdh_pkt_cap_cmd_save_to_file *pkt_save_file = NULL;
	struct file *filp = NULL;
	struct zxdh_en_priv *en_priv = NULL;
	struct zxdh_en_device *en_dev = NULL;
	u32 malloc_length = 0;
	u8 zxdh_config_flag = 0;
	u8 zxdh_rule_flag = 0;

	en_priv = netdev_priv(netdev);
	en_dev = &en_priv->edev;
	if (en_dev->ops->get_coredev_type(en_dev->parent) != DH_COREDEV_PF)
		return DHTOOL_ERROR;

	zxdh_config_flag = zxdh_get_status_flag(pf_info);
	zxdh_rule_flag = zxdh_get_rule_flag(pf_info);
	if (zxdh_config_flag == 0 && zxdh_rule_flag == 0) {
		en_dev->pkt_dev_flag = 1;
		goto save_file;
	} else if (zxdh_config_flag == 1 || zxdh_rule_flag == 1) {
		if (en_dev->pkt_dev_flag == 0)
			return MSG_RECV_PKT_CAP_PF_LOCK;

		goto save_file;
	} else {
		return DHTOOL_ERROR;
	}
save_file:
	pkt_save_file = kzalloc(sizeof(*pkt_save_file), GFP_KERNEL);
	if (!pkt_save_file)
		return DHTOOL_ERROR;

	memcpy(pkt_save_file, pkt_msg->payload, sizeof(struct zxdh_pkt_cap_cmd_save_to_file));
	DHTOOLS_LOG_INFO("file_path:%s, size:%d,count:%d, is_stop:%d\n", pkt_save_file->file_path,
			 pkt_save_file->file_size, pkt_save_file->pkt_count,
			 pkt_save_file->is_stop);

	if (pkt_save_file->is_stop == 0) {
		en_dev->pkt_file_num++;
		if (en_dev->pkt_file_num < 2) {
			filp = filp_open(pkt_save_file->file_path, O_RDONLY, 0);
			if (!IS_ERR(filp)) {
				en_dev->pkt_file_num = 0;
				filp_close(filp, NULL);
				DHTOOLS_LOG_ERR("File already exists: %s\n",
						pkt_save_file->file_path);
				SAFE_KFREE(pkt_save_file);
				return MSG_RECV_PKT_FILE_EXIST_ERR;
			}

			malloc_length = ZXDH_MQ_PAIRS_NUM * ZXDH_PF_MAX_DESC_NUM(en_dev) *
					sizeof(struct zxdh_pkt_file_info);
			en_dev->pkt_file_info = kzalloc(malloc_length, GFP_KERNEL);
			if (!en_dev->pkt_file_info) {
				DHTOOLS_LOG_ERR("kzalloc failed, szie:%d!!!\n", malloc_length);
				en_dev->pkt_file_num = 0;
				filp_close(filp, NULL);
				SAFE_KFREE(pkt_save_file);
				return DHTOOL_ERROR;
			}

			ret = pkt_event_init(en_dev);
			if (ret != 0) {
				DHTOOLS_LOG_ERR("pkt event init failed\n");
				SAFE_KFREE(pkt_save_file);
				SAFE_KFREE(en_dev->pkt_file_info);
				return -EINVAL;
			}

			if (pkt_save_file->pkt_count) {
				en_dev->pkt_save_file.enable_pkt_num_mode = 1;
				en_dev->pkt_save_file.pkt_cur_num = 0;
			} else {
				en_dev->pkt_save_file.enable_pkt_num_mode = 0;
				en_dev->pkt_save_file.pkt_cur_num = 0;
			}

			en_dev->pkt_cap_switch = 0;
			en_dev->pkt_save_file_flag = 1;
			memcpy(en_dev->pkt_save_file.file_path, pkt_save_file->file_path,
			       sizeof(pkt_save_file->file_path));

			en_dev->pkt_save_file.log_file =
				open_log_file(en_dev->pkt_save_file.file_path);
			if (!en_dev->pkt_save_file.log_file) {
				DHTOOLS_LOG_ERR("cmd open pkt file fialed\n");
				en_dev->pkt_cap_switch = 1;
				en_dev->pkt_save_file_flag = 0;
				en_dev->pkt_file_num = 0;
				en_dev->pkt_save_file.pkt_file_size = 0;
				en_dev->pkt_save_file.pkt_set_count = 0;
				memset(en_dev->pkt_save_file.file_path, 0,
				       sizeof(en_dev->pkt_save_file.file_path));
				SAFE_KFREE(pkt_save_file);
				SAFE_KFREE(en_dev->pkt_file_info);
				return MSG_RECV_PKT_FILE_PATH_ERR;
			}

			en_dev->pkt_save_file.pkt_file_size = pkt_save_file->file_size;
			en_dev->pkt_save_file.pkt_set_count = pkt_save_file->pkt_count;
		} else {
			DHTOOLS_LOG_ERR("another pkt file not close, please stop\n");
			SAFE_KFREE(pkt_save_file);
			return MSG_RECV_PKT_FILE_IN_PROGRESS_ERR;
		}
	} else {
		dpp_pkt_capture_disable_all(pf_info);
		en_dev->pkt_cap_switch = 1;
		en_dev->pkt_save_file_flag = 0;
		en_dev->pkt_file_num = 0;
		en_dev->pkt_save_file.pkt_file_size = 0;
		en_dev->pkt_save_file.pkt_set_count = 0;
		en_dev->pkt_save_file.total_written_bytes = 0;
		en_dev->pkt_save_file.pkt_cur_num = 0;
		en_dev->pkt_addr_marked = 0;
		memset(en_dev->pkt_save_file.file_path, 0, sizeof(en_dev->pkt_save_file.file_path));
		pkt_event_uninit(en_dev);

		while (en_dev->pkt_save_file.ubuf_idx != en_dev->pkt_save_file.pkt_rbuf_idx) {
			if (en_dev->pkt_file_info &&
			    en_dev->pkt_file_info[en_dev->pkt_save_file.ubuf_idx]
				    .pkt_addr_array) {
				SAFE_KFREE(en_dev->pkt_file_info[en_dev->pkt_save_file.ubuf_idx]
						   .pkt_addr_array);
			}
			en_dev->pkt_save_file.ubuf_idx++;
			if (en_dev->pkt_save_file.ubuf_idx >=
			    (ZXDH_MQ_PAIRS_NUM * ZXDH_PF_MAX_DESC_NUM(en_dev))) {
				en_dev->pkt_save_file.ubuf_idx = 0;
			}
		}

		if (en_dev->pkt_file_info &&
		    en_dev->pkt_file_info[en_dev->pkt_save_file.pkt_rbuf_idx].pkt_addr_array) {
			SAFE_KFREE(en_dev->pkt_file_info[en_dev->pkt_save_file.pkt_rbuf_idx]
					   .pkt_addr_array);
		}

		if (en_dev->pkt_save_file.log_file) {
			close_log_file(en_dev->pkt_save_file.log_file);
			en_dev->pkt_save_file.log_file = NULL;
			en_dev->pkt_save_file.file_pos = 0;
			DHTOOLS_LOG_INFO("pkt file is close\n");
		}

		if (en_dev->pkt_file_info)
			SAFE_KFREE(en_dev->pkt_file_info);

		en_dev->pkt_save_file.ubuf_idx = 0;
		en_dev->pkt_save_file.pkt_rbuf_idx = 0;
		zxdh_config_flag = zxdh_get_status_flag(pf_info);
		zxdh_rule_flag = zxdh_get_rule_flag(pf_info);
		if (zxdh_config_flag == 0 && zxdh_rule_flag == 0) {
			en_dev->pkt_dev_flag = 0;
			ret = dpp_pkt_capture_speed_set(pf_info, ZXDH_PKT_INIT_SPEED);
			if (ret != 0) {
				DHTOOLS_LOG_ERR("dpp_pkt_capture_speed_set failed, ret:%d!!!\n",
						ret);
				SAFE_KFREE(pkt_save_file);
				return DHTOOL_ERROR;
			}
			en_dev->pkt_dev_speed = ZXDH_PKT_INIT_SPEED;
		}
	}

	SAFE_KFREE(pkt_save_file);
	return ret;
}

u32 zxdh_pkt_capture_set_speed(struct net_device *netdev, struct zxdh_tools_msg *tool_msg,
			       struct zxdh_pkt_capture_msg *pkt_msg, struct dpp_pf_info_t *pf_info)
{
	u32 ret = 0;
	u32 *speed_date = NULL;
	struct zxdh_en_device *en_dev = NULL;
	struct zxdh_en_priv *en_priv = NULL;
	u8 zxdh_config_flag = 0;
	u8 zxdh_rule_flag = 0;

	if (!pkt_msg) {
		DHTOOLS_LOG_ERR("Payload is NULL\n");
		return DHTOOL_ERROR;
	}

	en_priv = netdev_priv(netdev);
	en_dev = &en_priv->edev;
	zxdh_config_flag = zxdh_get_status_flag(pf_info);
	zxdh_rule_flag = zxdh_get_rule_flag(pf_info);
	if (zxdh_config_flag == 0 && zxdh_rule_flag == 0) {
		goto set_speed;
	} else if (zxdh_config_flag == 1 || zxdh_rule_flag == 1) {
		if (en_dev->pkt_dev_flag == 0)
			return MSG_RECV_PKT_CAP_PF_LOCK;

		goto set_speed;
	} else {
		return DHTOOL_ERROR;
	}

set_speed:
	speed_date = (u32 *)pkt_msg->payload;
	ret = dpp_pkt_capture_speed_set(pf_info, *speed_date);
	if (ret)
		DHTOOLS_LOG_ERR("dpp_pkt_capture_speed_set failed, ret:%d!!!\n", ret);

	en_dev->pkt_dev_speed = *speed_date;
	return ret;
}

struct zxdh_pkt_capture_callback_entry_t callback_table[] = {
	{ DHTOOL_PKT_CAPTURE_CMD_ENABLE, zxdh_pkt_capture_enable },
	{ DHTOOL_PKT_CAPTURE_CMD_DISABLE, zxdh_pkt_capture_disable },
	{ DHTOOL_PKT_CAPTURE_CMD_DISABLE_ALL, zxdh_pkt_capture_disable_all },
	{ DHTOOL_PKT_CAPTURE_CMD_RULE_INSERT, zxdh_pkt_capture_rule_insert },
	{ DHTOOL_PKT_CAPTURE_CMD_RULE_DELETE, zxdh_pkt_capture_rule_delete },
	{ DHTOOL_PKT_CAPTURE_CMD_SHOW, zxdh_pkt_capture_cmd_show },
	{ DHTOOL_PKT_CAPTURE_CMD_SAVE_TO_FILE, zxdh_pkt_capture_save_to_file },
	{ DHTOOL_PKT_CAPTURE_CMD_SET_SPEED, zxdh_pkt_capture_set_speed }
};

u32 zxdh_pkt_capture_process_message(struct net_device *netdev, struct zxdh_tools_msg *tool_msg,
				     struct zxdh_pkt_capture_msg *pkt_msg,
				     struct dpp_pf_info_t *pf_info)
{
	u32 i = 0;
	u32 ret = 1;

	for (i = 0; i < (sizeof(callback_table) / sizeof(struct zxdh_pkt_capture_callback_entry_t));
	     i++) {
		if (callback_table[i].op_code == pkt_msg->op_code) {
			ret = callback_table[i].callback(netdev, tool_msg, pkt_msg, pf_info);
			break;
		}
	}

	return ret;
}

struct dhtool_eventpid_devbdf_array eventpid_devbdf_array[MAX_DHTOOL_PID_NUMS] = { 0 };

void dhtool_eventpid_exited_set_invalid(u32 event_pid)
{
	int i = 0;
	struct task_struct *task = NULL;

	for (i = 0; i < ARRAY_SIZE(eventpid_devbdf_array); i++) {
		if (eventpid_devbdf_array[i].is_valid == false)
			continue;
		task = pid_task(find_vpid(eventpid_devbdf_array[i].event_pid), PIDTYPE_PID);
		if (!task || (event_pid == eventpid_devbdf_array[i].event_pid))
			eventpid_devbdf_array[i].is_valid = false;
	}
}

int dhtool_eventpid_and_devbdf_register(u16 dev_pcieid, u32 dev_bdf, u32 event_pid)
{
	int i = 0;

	for (i = 0; i < ARRAY_SIZE(eventpid_devbdf_array); i++) {
		if (eventpid_devbdf_array[i].is_valid) {
			if (eventpid_devbdf_array[i].dev_bdf == dev_bdf) {
				eventpid_devbdf_array[i].is_valid = false;
				break;
			}
		}
	}

	for (i = 0; i < ARRAY_SIZE(eventpid_devbdf_array); i++) {
		if (!eventpid_devbdf_array[i].is_valid) {
			eventpid_devbdf_array[i].dev_pcieid = dev_pcieid;
			eventpid_devbdf_array[i].dev_bdf = dev_bdf;
			eventpid_devbdf_array[i].event_pid = event_pid;
			eventpid_devbdf_array[i].is_valid = true;
			return 0;
		}
	}

	DHTOOLS_LOG_ERR(
		" dhtool eventpid_devbdf_array (%d) is full(all running), waiting a moment!\n",
		MAX_DHTOOL_PID_NUMS);
	return -1;
}

int dhtool_eventpid_devbdf_list_process(u16 dev_pcieid, u32 dev_bdf, u32 event_pid)
{
	int ret = 0;

	dhtool_eventpid_exited_set_invalid(event_pid);
	ret = dhtool_eventpid_and_devbdf_register(dev_pcieid, dev_bdf, event_pid);
	return ret;
}

s32 zxdh_tools_mark_event_info(struct net_device *netdev, struct ifreq *ifr)
{
	int ret = 0;
	struct zxdh_en_priv *en_priv = netdev_priv(netdev);
	struct zxdh_en_device *en_dev = &en_priv->edev;
	struct zxdh_tools_msg *msg = NULL;
	struct zxdh_tools_reps tools_reps = { 0 };
	struct dhtool_dev_pcieid_get dev_pcieid_get = { 0 };
	struct pci_dev *pdev = NULL;
	u32 domain_no = 0;
	u32 bus_no = 0;
	u32 device_no = 0;
	u32 func_no = 0;
	u32 dev_bdf = 0;

	msg = kzalloc(sizeof(*msg), GFP_KERNEL);
	if (!msg)
		return -1;

	if (copy_from_user(msg, ifr->ifr_ifru.ifru_data, sizeof(struct zxdh_tools_msg))) {
		DHTOOLS_LOG_ERR("copy_from_user failed!!!\n");
		kfree(msg);
		return -EFAULT;
	}

	tools_reps.status = MSG_RECV_OK;

	DHTOOLS_LOG_INFO("en_dev->pcie_id=0x%x\n", en_dev->pcie_id);
	DHTOOLS_LOG_INFO("msg->event_pid=%d\n", msg->event_pid);
	dev_pcieid_get.dev_pcieid = en_dev->pcie_id;

	pdev = en_dev->ops->get_pdev(en_dev->parent);
	if (!pdev) {
		DHTOOLS_LOG_ERR("pdev is NULL\n");
		kfree(msg);
		return -EINVAL;
	}
	ret = sscanf(pci_name(pdev), "%x:%x:%x.%u", &domain_no, &bus_no, &device_no, &func_no);
	if (ret != 4) {
		DHTOOLS_LOG_ERR(
			"could not get dev domain_no、bus_no、device_no、func_no from pci_name(pdev)\n");
		kfree(msg);
		return -1;
	}
	dev_bdf = DBDF_ECAM(domain_no, bus_no, device_no, func_no);
	DHTOOLS_LOG_INFO("dev_bdf=%d\n", dev_bdf);

	ret = dhtool_eventpid_devbdf_list_process(en_dev->pcie_id, dev_bdf, msg->event_pid);
	if (ret != 0) {
		kfree(msg);
		return -1;
	}

	if (unlikely(copy_to_user((void __user *)msg->msg_reps, &dev_pcieid_get,
				  sizeof(struct dhtool_dev_pcieid_get)))) {
		DHTOOLS_LOG_ERR("copy_to_user failed!!!\n");
		kfree(msg);
		return -EFAULT;
	}

	if (unlikely(copy_to_user((void __user *)msg->tools_reps, &tools_reps,
				  sizeof(struct zxdh_tools_reps)))) {
		DHTOOLS_LOG_ERR("copy_to_user failed!!!\n");
		kfree(msg);
		return -EFAULT;
	}
	kfree(msg);
	return 0;
}

s32 zxdh_tools_ioctl_barchan_send(struct net_device *netdev, struct ifreq *ifr)
{
	struct zxdh_en_priv *en_priv = netdev_priv(netdev);
	struct zxdh_en_device *en_dev = &en_priv->edev;
	struct zxdh_tools_msg *msg = NULL;
	u8 *payload_addr = NULL;
	u8 *msg_reps = NULL;
	u16 msg_reps_len = 0;
	struct zxdh_tools_reps tools_reps = { 0 };
	struct zxdh_pci_bar_msg in = { 0 };
	struct zxdh_msg_recviver_mem result = { 0 };
	s32 ret = 0;

	msg = kzalloc(sizeof(*msg), GFP_KERNEL);
	if (!msg)
		return -1;

	if (copy_from_user(msg, ifr->ifr_ifru.ifru_data, sizeof(struct zxdh_tools_msg))) {
		DHTOOLS_LOG_ERR("copy_from_user failed!!!\n");
		kfree(msg);
		return -EFAULT;
	}

	if (msg->payload_len == 0 || msg->payload_len > BAR_MSG_PAYLOAD_MAX_LEN) {
		DHTOOLS_LOG_ERR("send para ERR: invalid payload len: %d!\n", msg->payload_len);
		kfree(msg);
		return -1;
	}

	payload_addr = vmalloc(msg->payload_len);
	if (!payload_addr) {
		DHTOOLS_LOG_ERR("vmalloc payload_addr failed!!!\n");
		kfree(msg);
		return -1;
	}

	if (copy_from_user(payload_addr, ifr->ifr_ifru.ifru_data + sizeof(struct zxdh_tools_msg),
			   msg->payload_len)) {
		DHTOOLS_LOG_ERR("copy_from_user failed!!!\n");
		vfree(payload_addr);
		kfree(msg);
		return -EFAULT;
	}

	in.virt_addr =
		(u64)ZXDH_BAR_MSG_BASE(en_dev->ops->get_bar_virt_addr(en_dev->parent, 0));
	in.payload_addr = payload_addr;
	in.payload_len = msg->payload_len;
	in.src = MSG_CHAN_END_PF;
	in.dst = msg->dst;
	in.event_id = msg->event_id;
	in.src_pcieid = en_dev->pcie_id;
	in.dst_pcieid = msg->dst_pcieid;

	if (msg->msg_reps_len == 0 || msg->msg_reps_len > BAR_MSG_PAYLOAD_MAX_LEN) {
		DHTOOLS_LOG_ERR("send para ERR: invalid msg_reps_len: %d!\n", msg->msg_reps_len);
		vfree(payload_addr);
		kfree(msg);
		return -1;
	}
	result.buffer_len = msg->msg_reps_len + REPS_HEADER_PAYLOAD_OFFSET;
	result.recv_buffer = vmalloc(result.buffer_len);
	if (!result.recv_buffer) {
		DHTOOLS_LOG_ERR("vmalloc result.recv_buffer failed!!!\n");
		vfree(payload_addr);
		kfree(msg);
		return -1;
	}
	msg_reps = (u8 *)result.recv_buffer + REPS_HEADER_PAYLOAD_OFFSET;
	msg_reps_len = msg->msg_reps_len;

	ret = zxdh_bar_chan_sync_msg_send(&in, &result);
	if (ret != BAR_MSG_OK)
		DHTOOLS_LOG_ERR("zxdh_bar_chan_sync_msg_send failed, ret=%d!!!\n", ret);

	tools_reps.bar_or_vq_chan_ret = ret;
	tools_reps.status = MSG_RECV_OK;

	//DHTOOLS_LOG_INFO("result.recv_buffer 8 bytes: 0x%llx\n", *(u64 *)result.recv_buffer);

	if (unlikely(copy_to_user((void __user *)msg->msg_reps, msg_reps, msg_reps_len))) {
		DHTOOLS_LOG_ERR("copy_to_user failed!!!\n");
		vfree(result.recv_buffer);
		vfree(payload_addr);
		kfree(msg);
		return -EFAULT;
	}

	if (unlikely(copy_to_user((void __user *)msg->tools_reps, &tools_reps,
				  sizeof(struct zxdh_tools_reps)))) {
		DHTOOLS_LOG_ERR("copy_to_user failed!!!\n");
		vfree(result.recv_buffer);
		vfree(payload_addr);
		kfree(msg);
		return -EFAULT;
	}

	vfree(result.recv_buffer);
	vfree(payload_addr);
	kfree(msg);
	return 0;
}

#ifdef ZXDH_MSGQ
s32 zxdh_tools_ioctl_msgq_send(struct net_device *netdev, struct ifreq *ifr)
{
	struct zxdh_en_device *en_dev = NULL;
	struct msgq_dev *msgq_dev = NULL;
	struct msgq_pkt_info pkt_info = { 0 };
	struct zxdh_tools_msg *msg = NULL;
	u8 *payload_addr = NULL;
	struct zxdh_tools_reps tools_reps = { 0 };
	struct reps_info msg_reps = { 0 };
	s32 ret = 0;

	CHECK_EQUAL_ERR(ifr, NULL, -EADDRNOTAVAIL, "ifr is null!\n");
	CHECK_EQUAL_ERR(netdev, NULL, -EADDRNOTAVAIL, "netdev is null!\n");

	en_dev = netdev_priv(netdev);
	if (!en_dev) {
		LOG_ERR("en_dev is null!\n");
		return -1;
	}
	msgq_dev = (struct msgq_dev *)en_dev->msgq_dev;
	if (!msgq_dev) {
		LOG_ERR("msgq_dev null!\n");
		return -1;
	}

	DHTOOLS_LOG_INFO("is called!\n");
	//DHTOOLS_LOG_INFO("en_dev->pcie_id=0x%x\n", en_dev->pcie_id);

	msg = kzalloc(sizeof(*msg), GFP_KERNEL);
	if (!msg) {
		DHTOOLS_LOG_ERR("kzalloc msg failed!!!\n");
		return -1;
	}

	if (copy_from_user(msg, ifr->ifr_ifru.ifru_data, sizeof(struct zxdh_tools_msg))) {
		DHTOOLS_LOG_ERR("copy_from_user failed!!!\n");
		kfree(msg);
		return -1;
	}

	if (msg->payload_len == 0 || msg->payload_len > MAX_PACKET_LEN) {
		DHTOOLS_LOG_ERR("send para ERR: invalid payload len: %d!\n", msg->payload_len);
		kfree(msg);
		return -1;
	}

	payload_addr = kzalloc(msg->payload_len + PRIV_HEADER_LEN, GFP_KERNEL);
	if (!payload_addr) {
		DHTOOLS_LOG_ERR("vmalloc payload_addr failed!!!\n");
		kfree(msg);
		return -1;
	}

	if (copy_from_user(payload_addr + PRIV_HEADER_LEN,
			   ifr->ifr_ifru.ifru_data + sizeof(struct zxdh_tools_msg),
			   msg->payload_len)) {
		DHTOOLS_LOG_ERR("copy_from_user failed!!!\n");
		kfree(payload_addr);
		kfree(msg);
		return -1;
	}

	pkt_info.event_id = msg->event_id;
	pkt_info.timeout_us = 400000;
	pkt_info.is_async = msg->sync_or_async;
	pkt_info.len = msg->payload_len + PRIV_HEADER_LEN;
	pkt_info.addr = payload_addr;
	//DHTOOLS_LOG_INFO("data_len: %d\n", pkt_info.len);

	if (msg->msg_reps_len == 0 || msg->msg_reps_len > MAX_PACKET_LEN) {
		DHTOOLS_LOG_ERR("send para ERR: invalid msg_reps_len: %d!\n", msg->msg_reps_len);
		kfree(payload_addr);
		kfree(msg);
		return -1;
	}
	msg_reps.len = msg->msg_reps_len;
	msg_reps.addr = vmalloc(msg_reps.len);
	if (!msg_reps.addr) {
		DHTOOLS_LOG_ERR("vmalloc msg_reps.addr failed!!!\n");
		kfree(payload_addr);
		kfree(msg);
		return -1;
	}

	ret = zxdh_msgq_send_cmd(msgq_dev, &pkt_info, &msg_reps);
	if (ret != MSGQ_RET_OK)
		DHTOOLS_LOG_ERR("zxdh_msgq_send_cmd failed: %d\n", ret);

	tools_reps.bar_or_vq_chan_ret = ret;
	tools_reps.status = MSG_RECV_OK;

	if (unlikely(copy_to_user((void __user *)msg->msg_reps, msg_reps.addr, msg_reps.len))) {
		DHTOOLS_LOG_ERR("copy_to_user failed!!!\n");
		goto err_ret;
	}

	if (unlikely(copy_to_user((void __user *)msg->tools_reps, &tools_reps,
				  sizeof(struct zxdh_tools_reps)))) {
		DHTOOLS_LOG_ERR("copy_to_user failed!!!\n");
		goto err_ret;
	}

	vfree(msg_reps.addr);
	kfree(msg);
	return 0;

err_ret:
	vfree(msg_reps.addr);
	kfree(msg);
	return -1;
}
#endif

s32 dhtool_device_info_get(struct net_device *netdev, struct ifreq *ifr)
{
	struct zxdh_en_priv *en_priv = netdev_priv(netdev);
	struct zxdh_en_device *en_dev = &en_priv->edev;
	struct pci_dev *pdev = NULL;
	struct pci_dev *swdsp_pdev = NULL;
	struct pci_dev *swusp_pdev = NULL;
	struct pci_dev *rp_pdev = NULL;
	struct zxdh_tools_msg *msg = NULL;
	struct zxdh_tools_reps tools_reps = { 0 };
	struct dhtool_dev_info_get_reps dev_info_get = { 0 };
	int sscanf_ret = 0;

	//DHTOOLS_LOG_INFO("is called!\n");
	msg = kzalloc(sizeof(*msg), GFP_KERNEL);
	if (!msg)
		return -1;

	if (copy_from_user(msg, ifr->ifr_ifru.ifru_data, sizeof(struct zxdh_tools_msg))) {
		DHTOOLS_LOG_ERR("copy_from_user failed!!!\n");
		kfree(msg);
		return -EFAULT;
	}

	tools_reps.status = MSG_RECV_OK;

	pdev = en_dev->ops->get_pdev(en_dev->parent);
	if (!pdev) {
		DHTOOLS_LOG_ERR("pdev is NULL\n");
		kfree(msg);
		return -EINVAL;
	}

	sscanf_ret = sscanf(pci_name(pdev), "%x:%x:%x.%u", &dev_info_get.dev_info.domain_no,
			    &dev_info_get.dev_info.bus_no, &dev_info_get.dev_info.device_no,
			    &dev_info_get.dev_info.func_no);
	if (sscanf_ret != 4) {
		DHTOOLS_LOG_ERR(
			"could not get dev domain_no、bus_no、device_no、func_no from pci_name(pdev)\n");
		kfree(msg);
		return -1;
	}
	DHTOOLS_LOG_INFO("dev_info, domain:bus:device.func = %04x:%02x:%02x.%x\n",
			 dev_info_get.dev_info.domain_no, dev_info_get.dev_info.bus_no,
			 dev_info_get.dev_info.device_no, dev_info_get.dev_info.func_no);

	swdsp_pdev = pci_upstream_bridge(pdev);
	if (!swdsp_pdev) {
		DHTOOLS_LOG_ERR("swdsp_pdev is NULL\n");
		kfree(msg);
		return -EINVAL;
	}

	if (swdsp_pdev->device == DH_SWITCH_DEVICE_ID &&
	    swdsp_pdev->vendor == DH_SWITCH_VENDOR_ID) {
		swusp_pdev = pci_upstream_bridge(swdsp_pdev);
		if (!swusp_pdev) {
			DHTOOLS_LOG_ERR("swusp_pdev is NULL\n");
			kfree(msg);
			return -EINVAL;
		}

		rp_pdev = pci_upstream_bridge(swusp_pdev);
		if (!rp_pdev) {
			DHTOOLS_LOG_ERR("rp_pdev is NULL\n");
			kfree(msg);
			return -EINVAL;
		}
		dev_info_get.switch_or_noswitch = SWITCH;
		sscanf_ret = sscanf(pci_name(rp_pdev), "%x:%x:%x.%u",
				    &dev_info_get.rp_info.domain_no, &dev_info_get.rp_info.bus_no,
				    &dev_info_get.rp_info.device_no, &dev_info_get.rp_info.func_no);
		if (sscanf_ret != 4) {
			DHTOOLS_LOG_ERR(
				"could not get rp domain_no、bus_no、device_no、func_no from pci_name(rp_pdev)\n");
			kfree(msg);
			return -1;
		}
		sscanf_ret = sscanf(pci_name(swusp_pdev), "%x:%x:%x.%u",
				    &dev_info_get.swusp_info.domain_no,
				    &dev_info_get.swusp_info.bus_no,
				    &dev_info_get.swusp_info.device_no,
				    &dev_info_get.swusp_info.func_no);
		if (sscanf_ret != 4) {
			DHTOOLS_LOG_ERR(
				"could not get swusp domain_no、bus_no、device_no、func_no from pci_name(swusp_pdev)\n");
			kfree(msg);
			return -1;
		}
	} else {
		dev_info_get.switch_or_noswitch = NO_SWITCH;
		sscanf_ret = sscanf(pci_name(swdsp_pdev), "%x:%x:%x.%u",
				    &dev_info_get.rp_info.domain_no, &dev_info_get.rp_info.bus_no,
				    &dev_info_get.rp_info.device_no, &dev_info_get.rp_info.func_no);
		if (sscanf_ret != 4) {
			DHTOOLS_LOG_ERR(
				"could not get rp domain_no、bus_no、device_no、func_no from pci_name(swdsp_pdev)\n");
			kfree(msg);
			return -1;
		}
	}
	DHTOOLS_LOG_INFO("rp_info, domain:bus:device.func = %04x:%02x:%02x.%x\n",
			 dev_info_get.rp_info.domain_no, dev_info_get.rp_info.bus_no,
			 dev_info_get.rp_info.device_no, dev_info_get.rp_info.func_no);

	if (unlikely(copy_to_user((void __user *)msg->msg_reps, &dev_info_get,
				  sizeof(struct dhtool_dev_info_get_reps)))) {
		DHTOOLS_LOG_ERR("copy_to_user failed!!!\n");
		kfree(msg);
		return -EFAULT;
	}

	if (unlikely(copy_to_user((void __user *)msg->tools_reps, &tools_reps,
				  sizeof(struct zxdh_tools_reps)))) {
		DHTOOLS_LOG_ERR("copy_to_user failed!!!\n");
		kfree(msg);
		return -EFAULT;
	}
	kfree(msg);
	return 0;
}

s32 zxdh_set_vf_status(struct zxdh_en_device *en_dev, int start_vf_idx,
		       enum VF_SET_STATUS vf_status)
{
	int num_vfs = 0;
	bool pf_link_up = en_dev->ops->get_pf_link_up(en_dev->parent);
	union zxdh_msg *msg = NULL;
	struct zxdh_vf_item *vf_item = NULL;
	struct pci_dev *pdev = NULL;
	s32 err = 0;
	u16 vf_idx = 0;
	u16 func_no = 0;
	u16 pf_no = FIND_PF_ID(en_dev->pcie_id);
	struct zxdh_bar_extra_para para = { 0 };

	LOG_INFO("is called\n");
	para.is_sync = true;
	para.retrycnt = BAR_MSG_RETRY_CNT_MAX;
	msg = kzalloc(sizeof(union zxdh_msg), GFP_KERNEL);
	if (!msg) {
		LOG_ERR("kzalloc(%lu, GFP_KERNEL) failed !", sizeof(union zxdh_msg));
		return -ENOMEM;
	}
	msg->payload.hdr_to_agt.op_code = AGENT_DEV_STATUS_NOTIFY;
	msg->payload.hdr_to_agt.pcie_id = en_dev->pcie_id;
	pdev = en_dev->ops->get_pdev(en_dev->parent);
	num_vfs = pci_num_vf(pdev);
	for (vf_idx = start_vf_idx; vf_idx < num_vfs; vf_idx++) {
		vf_item = en_dev->ops->get_vf_item(en_dev->parent, vf_idx);
		switch (vf_status) {
		case VF_STATUS_AUTO:
			vf_item->link_forced = FALSE;
			vf_item->link_up = pf_link_up;
			break;
		case VF_STATUS_ENABLE:
			vf_item->link_forced = TRUE;
			vf_item->link_up = TRUE;
			break;
		case VF_STATUS_DISABLE:
			vf_item->link_forced = TRUE;
			vf_item->link_up = FALSE;
			break;
		default:
			err = -EINVAL;
			goto free_msg;
		}
		if (en_dev->ops->get_vf_is_probe(en_dev->parent, vf_idx)) {
			func_no = GET_FUNC_NO(pf_no, vf_idx);
			LOG_INFO(
				"start set vf[%d], link_forced[%d], link_up[%d], probe[%d], func_no=0x%x\n",
				vf_idx, vf_item->link_forced ? 1 : 0, vf_item->link_up ? 1 : 0,
				vf_item->is_probed ? 1 : 0, func_no);
			msg->payload.pcie_msix_msg.func_no[msg->payload.pcie_msix_msg.num++] =
				func_no;
			en_dev->ops->set_vf_link_info(en_dev->parent, vf_idx,
						      vf_item->link_up ? 1 : 0);
		}
	}
	if (msg->payload.pcie_msix_msg.num > 0) {
		err = en_dev->ops->msg_send_cmd(en_dev->parent, MODULE_MAC, msg, msg, &para);
		if (err != 0) {
			LOG_ERR("failed to update VF link info, en_dev->ops->msg_send_cmd err:%d\n",
				err);
		}
	}

free_msg:
	kfree(msg);
	return err;
}

s32 zxdh_set_vf_mac(struct zxdh_en_device *en_dev, struct dhtool_set_vf_mac_msg *msg)
{
	s32 ret = 0;

	DHTOOLS_LOG_INFO("is called\n");

	if (msg->action == MAC_ADD) {
		if (msg->mac_config.unicast_add_count != 0) {
			ret = zxdh_pf_add_vf_unicast_mac(en_dev, msg);
			if (ret != 0) {
				DHTOOLS_LOG_ERR("zxdh_pf_add_vf_unicast_mac failed, ret:%d\n", ret);
				return ret;
			}
		}

		if (msg->mac_config.multicast_add_count != 0) {
			ret = zxdh_pf_add_vf_multicast_mac(en_dev, msg);
			if (ret != 0) {
				DHTOOLS_LOG_ERR("zxdh_pf_add_vf_multicast_mac failed\n");
				return ret;
			}
		}
	} else if (msg->action == MAC_DEL) {
		if (msg->mac_config.unicast_del_count != 0) {
			ret = zxdh_pf_del_vf_unicast_mac(en_dev, msg);
			if (ret != 0) {
				DHTOOLS_LOG_ERR("zxdh_pf_del_vf_unicast_mac failed\n");
				return ret;
			}
		}

		if (msg->mac_config.multicast_del_count != 0) {
			ret = zxdh_pf_del_vf_multicast_mac(en_dev, msg);
			if (ret != 0) {
				DHTOOLS_LOG_ERR("zxdh_pf_del_vf_multicast_mac failed\n");
				return ret;
			}
		}
	} else if (msg->action == MAC_TRANSFER) {
		ret = zxdh_pf_transfer_vf_mac(en_dev, msg->mac_transfer.src_vf,
					      msg->mac_transfer.dst_vf);
		if (ret != 0) {
			DHTOOLS_LOG_ERR("zxdh_pf_transfer_vf_mac failed\n");
			return ret;
		}
	} else {
		DHTOOLS_LOG_ERR("unknown atcion:%d", msg->action);
		return MAC_CONFIG_FAILED;
	}

	return MAC_CONFIG_SUCCESS;
}

s32 zxdh_tools_set_vf_mac(struct net_device *netdev, struct ifreq *ifr)
{
	struct zxdh_en_priv *en_priv = netdev_priv(netdev);
	struct zxdh_en_device *en_dev = &en_priv->edev;
	struct dhtool_set_vf_mac_msg *payload = NULL;
	struct zxdh_tools_msg *tools_msg = NULL;
	struct zxdh_tools_reps tools_reps = { 0 };
	s32 res = 0;

	DHTOOLS_LOG_INFO("is called!\n");

	tools_reps.status = MAC_CONFIG_SUCCESS;
	if (en_dev->ops->is_bond(en_dev->parent)) {
		tools_reps.status = MAC_CONFIG_FAILED;
		DHTOOLS_LOG_ERR("%s can't be used in bond_pf!\n", __func__);
		return -EINVAL;
	}

	tools_msg = kzalloc(sizeof(*tools_msg), GFP_KERNEL);
	if (!tools_msg)
		return -ENOMEM;

	if (copy_from_user(tools_msg, ifr->ifr_ifru.ifru_data, sizeof(struct zxdh_tools_msg))) {
		DHTOOLS_LOG_ERR("copy_from_user failed!!!\n");
		kfree(tools_msg);
		return -EFAULT;
	}

	if (tools_msg->payload_len == 0 || tools_msg->payload_len > BAR_MSG_PAYLOAD_MAX_LEN) {
		DHTOOLS_LOG_ERR("send para ERR: invalid payload len: %d!\n",
				tools_msg->payload_len);
		kfree(tools_msg);
		return -EINVAL;
	}

	payload = kzalloc(sizeof(*payload), GFP_KERNEL);
	if (!payload) {
		kfree(tools_msg);
		return -ENOMEM;
	}

	if (copy_from_user(payload, ifr->ifr_ifru.ifru_data + sizeof(struct zxdh_tools_msg),
			   sizeof(struct dhtool_set_vf_mac_msg))) {
		DHTOOLS_LOG_ERR("copy_from_user failed!!!\n");
		kfree(payload);
		kfree(tools_msg);
		return -EFAULT;
	}

	res = zxdh_set_vf_mac(en_dev, payload);
	if (res != 0) {
		DHTOOLS_LOG_ERR("zxdh_set_vf_mac failed, err %d\n", res);
		tools_reps.status = res;
	}

	if (unlikely(copy_to_user((void __user *)tools_msg->tools_reps, &tools_reps,
				  sizeof(struct zxdh_tools_reps)))) {
		DHTOOLS_LOG_ERR("copy_to_user failed!!!\n");
		res = -EFAULT;
	}
	kfree(payload);
	kfree(tools_msg);
	return 0;
}

s32 zxdh_tools_get_sw_stat(struct net_device *netdev, struct ifreq *ifr)
{
	struct zxdh_en_priv *en_priv = netdev_priv(netdev);
	struct zxdh_en_device *en_dev = &en_priv->edev;
	struct zxdh_tools_msg *tools_msg = NULL;
	struct zxdh_tools_reps tools_reps = { 0 };
	struct zxdh_sw_stats_reply *reply = NULL;
	struct zxdh_get_sw_stats *payload = NULL;
	s32 res = 0;

	DHTOOLS_LOG_INFO("is called!\n");

	tools_reps.status = GET_STAT_SUCCESS;

	tools_msg = kzalloc(sizeof(*tools_msg), GFP_KERNEL);
	if (!tools_msg)
		return -ENOMEM;

	if (copy_from_user(tools_msg, ifr->ifr_ifru.ifru_data, sizeof(struct zxdh_tools_msg))) {
		DHTOOLS_LOG_ERR("copy_from_user failed!!!\n");
		res = -EFAULT;
		goto err_tools_msg;
	}

	if (tools_msg->payload_len == 0 || tools_msg->payload_len > BAR_MSG_PAYLOAD_MAX_LEN) {
		DHTOOLS_LOG_ERR("send para ERR: invalid payload len: %d!\n",
				tools_msg->payload_len);
		res = -EINVAL;
		goto err_tools_msg;
	}

	payload = kzalloc(sizeof(*payload), GFP_KERNEL);
	if (!payload) {
		res = -ENOMEM;
		goto err_tools_msg;
	}

	if (copy_from_user(payload, ifr->ifr_ifru.ifru_data + sizeof(struct zxdh_tools_msg),
			   sizeof(struct zxdh_get_sw_stats))) {
		DHTOOLS_LOG_ERR("copy_from_user failed!!!\n");
		res = -EFAULT;
		goto err_payload;
	}

	reply = kzalloc(sizeof(*reply), GFP_KERNEL);
	if (!reply) {
		res = -ENOMEM;
		goto err_payload;
	}

	if (payload->vf_idx > ZXDH_VF_NUM_MAX) {
		DHTOOLS_LOG_ERR("payload->vf_idx > 256\n");
		res = -EFAULT;
		goto err_reply;
	}

	res = zxdh_get_vf_err_stats(en_dev, payload, reply);
	if (res != 0) {
		DHTOOLS_LOG_ERR("zxdh_get_vf_err_stats failed, err %d\n", res);
		tools_reps.status = res;
	}

	if (unlikely(copy_to_user((void __user *)tools_msg->tools_reps, &tools_reps,
				  sizeof(struct zxdh_tools_reps)))) {
		DHTOOLS_LOG_ERR("copy tools_reps to user failed!!!\n");
		res = -EFAULT;
		goto err_reply;
	}

	if (unlikely(copy_to_user((void __user *)tools_msg->msg_reps, reply,
				  sizeof(struct zxdh_sw_stats_reply)))) {
		DHTOOLS_LOG_ERR("copy reply to user failed!!!\n");
		res = -EFAULT;
		goto err_reply;
	}

err_reply:
	kfree(reply);
err_payload:
	kfree(payload);
err_tools_msg:
	kfree(tools_msg);
	return res;
}

s32 zxdh_tools_set_vf_status(struct net_device *netdev, struct ifreq *ifr)
{
	struct zxdh_en_priv *en_priv = netdev_priv(netdev);
	struct zxdh_en_device *en_dev = &en_priv->edev;
	struct dhtool_set_vf_status_msg *payload = NULL;
	struct zxdh_tools_msg *tools_msg = NULL;
	struct zxdh_tools_reps tools_reps = { 0 };
	struct pci_dev *pdev = en_dev->ops->get_pdev(en_dev->parent);
	int num_vfs = pci_num_vf(pdev);
	s32 res = 0;

	DHTOOLS_LOG_INFO("is called!\n");

	tools_reps.status = MSG_RECV_OK;
	if (en_dev->ops->is_bond(en_dev->parent)) {
		tools_reps.status = MSG_RECV_FAILED;
		DHTOOLS_LOG_ERR("%s can't be used in bond_pf!\n", __func__);
		return -EINVAL;
	}

	tools_msg = kzalloc(sizeof(*tools_msg), GFP_KERNEL);
	if (!tools_msg)
		return -ENOMEM;

	if (copy_from_user(tools_msg, ifr->ifr_ifru.ifru_data, sizeof(struct zxdh_tools_msg))) {
		DHTOOLS_LOG_ERR("copy_from_user failed!!!\n");
		kfree(tools_msg);
		return -EFAULT;
	}

	if (tools_msg->payload_len == 0 || tools_msg->payload_len > BAR_MSG_PAYLOAD_MAX_LEN) {
		DHTOOLS_LOG_ERR("send para ERR: invalid payload len: %d!\n",
				tools_msg->payload_len);
		kfree(tools_msg);
		return -EINVAL;
	}

	payload = kzalloc(sizeof(*payload), GFP_KERNEL);
	if (!payload) {
		kfree(tools_msg);
		return -ENOMEM;
	}

	if (copy_from_user(payload, ifr->ifr_ifru.ifru_data + sizeof(struct zxdh_tools_msg),
			   sizeof(struct dhtool_set_vf_status_msg))) {
		DHTOOLS_LOG_ERR("copy_from_user failed!!!\n");
		kfree(payload);
		kfree(tools_msg);
		return -EFAULT;
	}

	DHTOOLS_LOG_INFO("payload->mode %d, payload->vf_status %d\n", payload->mode,
			 payload->vf_status);

	if (num_vfs <= 0) {
		DHTOOLS_LOG_ERR("When the VF is %d, the set vf status function cannot be used.\n",
				num_vfs);
		tools_reps.status = MSG_RECV_FAILED;
		goto out;
	}

	if (payload->mode == VF3_MAX && num_vfs <= 2) {
		DHTOOLS_LOG_ERR("VF3_MAX mode can't use when num_vfs %d ≤ 2\n", num_vfs);
		tools_reps.status = MSG_RECV_FAILED;
		goto out;
	}
	res = zxdh_set_vf_status(en_dev, payload->mode == VF3_MAX ? 2 : 0, payload->vf_status);
	if (res != 0) {
		DHTOOLS_LOG_ERR("zxdh_set_vf_status failed, err %d\n", res);
		tools_reps.status = MSG_RECV_FAILED;
	}

out:
	if (unlikely(copy_to_user((void __user *)tools_msg->tools_reps, &tools_reps,
				  sizeof(struct zxdh_tools_reps)))) {
		DHTOOLS_LOG_ERR("copy_to_user failed!!!\n");
		res = -EFAULT;
	}
	kfree(payload);
	kfree(tools_msg);
	return res;
}

s32 dhtool_dev_phyport_get(struct net_device *netdev, struct ifreq *ifr)
{
	struct zxdh_en_priv *en_priv = netdev_priv(netdev);
	struct zxdh_en_device *en_dev = &en_priv->edev;
	struct zxdh_tools_msg *msg = NULL;
	struct zxdh_tools_reps tools_reps = { 0 };
	struct dhtool_dev_phyport_get dev_phyport_get = { 0 };

	tools_reps.status = MSG_RECV_OK;
	msg = kzalloc(sizeof(*msg), GFP_KERNEL);
	if (!msg) {
		DHTOOLS_LOG_ERR(" kzalloc msg failed!!!\n");
		return -1;
	}

	if (copy_from_user(msg, ifr->ifr_ifru.ifru_data, sizeof(struct zxdh_tools_msg))) {
		DHTOOLS_LOG_ERR("copy_from_user failed!!!\n");
		kfree(msg);
		return -EFAULT;
	}

	dev_phyport_get.phyport = en_dev->phy_port;
	DHTOOLS_LOG_INFO("dev_phyport_get.phyport %u\n", dev_phyport_get.phyport);

	if (unlikely(copy_to_user((void __user *)msg->msg_reps, &dev_phyport_get,
				  sizeof(struct dhtool_dev_phyport_get)))) {
		DHTOOLS_LOG_ERR("copy_to_user failed!!!\n");
		kfree(msg);
		return -EFAULT;
	}

	if (unlikely(copy_to_user((void __user *)msg->tools_reps, &tools_reps,
				  sizeof(struct zxdh_tools_reps)))) {
		DHTOOLS_LOG_ERR("copy_to_user failed!!!\n");
		kfree(msg);
		return -EFAULT;
	}
	kfree(msg);
	return 0;
}

s32 dhtool_pkt_capture(struct net_device *netdev, struct ifreq *ifr)
{
	struct zxdh_en_priv *en_priv = netdev_priv(netdev);
	struct zxdh_en_device *en_dev = &en_priv->edev;
	u16 fw_patch = en_dev->ops->get_fw_patch(en_dev->parent);
	struct pci_dev *pdev = NULL;
	u32 ret = 0;
	u32 i = 0;
	struct zxdh_tools_msg *msg = NULL;
	struct zxdh_tools_reps tools_reps = { 0 };
	struct zxdh_pkt_capture_msg *pkt_cap_msg = NULL;
	struct dpp_pf_info_t pf_info = { 0 };

	tools_reps.status = MSG_RECV_OK;

	pdev = en_dev->ops->get_pdev(en_dev->parent);
	if (!pdev) {
		DHTOOLS_LOG_ERR("pdev is NULL\n");
		return -EINVAL;
	}

	pf_info.slot = en_dev->slot_id;
	pf_info.vport = en_dev->vport;

	msg = kzalloc(sizeof(*msg), GFP_KERNEL);
	if (!msg)
		return -1;

	if (fw_patch < 2) {
		tools_reps.status = MSG_RECV_FAILED;
		if (unlikely(copy_to_user((void __user *)msg->tools_reps, &tools_reps,
					  sizeof(struct zxdh_tools_reps)))) {
			DHTOOLS_LOG_ERR("copy_to_user failed!!!\n");
		}

		kfree(msg);
		DHTOOLS_LOG_ERR("fw version not match pkt func!!!\n");
		return -EFAULT;
	}

	if (copy_from_user(msg, ifr->ifr_ifru.ifru_data, sizeof(struct zxdh_tools_msg))) {
		DHTOOLS_LOG_ERR("copy_from_user failed!!!\n");
		kfree(msg);
		return -EFAULT;
	}

	if (msg->payload_len == 0 || msg->payload_len > BAR_MSG_PAYLOAD_MAX_LEN) {
		DHTOOLS_LOG_ERR("send para ERR: invalid payload len: %d!\n", msg->payload_len);
		kfree(msg);
		return -EINVAL;
	}

	pkt_cap_msg = kzalloc(msg->payload_len, GFP_KERNEL);
	if (!pkt_cap_msg) {
		kfree(msg);
		return -ENOMEM;
	}

	if (copy_from_user(pkt_cap_msg, ifr->ifr_ifru.ifru_data + sizeof(struct zxdh_tools_msg),
			   msg->payload_len)) {
		DHTOOLS_LOG_ERR("copy_from_user failed!!!\n");
		kfree(pkt_cap_msg);
		kfree(msg);
		return -EFAULT;
	}

	if (pkt_cap_msg->payload_len > BAR_MSG_PAYLOAD_MAX_LEN) {
		DHTOOLS_LOG_ERR("send para ERR: invalid payload len: %d!\n",
				pkt_cap_msg->payload_len);
		kfree(pkt_cap_msg);
		kfree(msg);
		return -EINVAL;
	}

	for (i = 0; i < msg->payload_len; i++) {
		if (pkt_cap_msg->payload[i] > PKT_PAYLIAD_VALUE) {
			DHTOOLS_LOG_ERR("invalid payload value at index %u: %u\n", i,
					pkt_cap_msg->payload[i]);
			kfree(pkt_cap_msg);
			kfree(msg);
			return -EINVAL;
		}
	}

	ret = zxdh_pkt_capture_process_message(netdev, msg, pkt_cap_msg, &pf_info);
	if (ret != 0) {
		switch (ret) {
		case MSG_RECV_PKT_CAP_PF_LOCK:
		case MSG_RECV_PKT_FILE_PATH_ERR:
		case MSG_RECV_PKT_FILE_EXIST_ERR:
		case MSG_RECV_PKT_FILE_IN_PROGRESS_ERR:
			tools_reps.status = ret;
			break;
		default:
			tools_reps.status = MSG_RECV_FAILED;
			break;
		}

		DHTOOLS_LOG_ERR("zxdh_pkt_capture_process_message failed!!!\n");
	}

	if (unlikely(copy_to_user((void __user *)msg->tools_reps, &tools_reps,
				  sizeof(struct zxdh_tools_reps)))) {
		DHTOOLS_LOG_ERR("copy_to_user failed!!!\n");
		kfree(msg);
		kfree(pkt_cap_msg);
		return -EFAULT;
	}
	kfree(pkt_cap_msg);
	kfree(msg);
	return 0;
}

s32 dhtool_get_compat_infor(struct net_device *netdev, struct ifreq *ifr)
{
	struct zxdh_tools_msg *msg = NULL;
	struct zxdh_tools_reps tools_reps = { 0 };
	struct dhtool_compat_reg compat_reg = { 0 };
	struct dhtool_compat_reg tool_compat_reg = { 0 };

	tools_reps.status = MSG_RECV_OK;
	msg = kzalloc(sizeof(*msg), GFP_KERNEL);
	if (!msg)
		return -1;

	if (copy_from_user(msg, ifr->ifr_ifru.ifru_data, sizeof(struct zxdh_tools_msg))) {
		DHTOOLS_LOG_ERR("copy_from_user failed!!!\n");
		kfree(msg);
		return -EFAULT;
	}

	if (msg->payload_len != sizeof(struct dhtool_compat_reg)) {
		DHTOOLS_LOG_ERR("msg->payload_len error, msg->payload_len=%d!!!\n",
				msg->payload_len);
		kfree(msg);
		return -EFAULT;
	}

	if (copy_from_user(&tool_compat_reg,
			   ifr->ifr_ifru.ifru_data + sizeof(struct zxdh_tools_msg),
			   msg->payload_len)) {
		DHTOOLS_LOG_ERR("copy_from_user failed!!!\n");
		kfree(msg);
		return -EFAULT;
	}

	DHTOOLS_LOG_INFO("DHTOOL_COMPAT_ITM=%d\n", DHTOOL_COMPAT_ITM);
	DHTOOLS_LOG_INFO("DHTOOL_COMPAT_MAJOR=%d\n", DHTOOL_COMPAT_MAJOR);
	DHTOOLS_LOG_INFO("DHTOOL_COMPAT_TOOL_MINOR=%d\n", DHTOOL_COMPAT_TOOL_MINOR);
	DHTOOLS_LOG_INFO("DHTOOL_COMPAT_DRIV_MINOR=%d\n", DHTOOL_COMPAT_DRIV_MINOR);
	DHTOOLS_LOG_INFO("DHTOOL_COMPAT_PATCH=%d\n", DHTOOL_COMPAT_PATCH);

	compat_reg.version_compat_item = DHTOOL_COMPAT_ITM;
	compat_reg.major = DHTOOL_COMPAT_MAJOR;
	compat_reg.tool_minor = DHTOOL_COMPAT_TOOL_MINOR;
	compat_reg.drv_minor = DHTOOL_COMPAT_DRIV_MINOR;
	compat_reg.patch = DHTOOL_COMPAT_PATCH;
	if (unlikely(copy_to_user((void __user *)msg->msg_reps, &compat_reg,
				  sizeof(struct dhtool_compat_reg)))) {
		DHTOOLS_LOG_ERR("copy_to_user failed!!!\n");
		kfree(msg);
		return -EFAULT;
	}

	if (unlikely(copy_to_user((void __user *)msg->tools_reps, &tools_reps,
				  sizeof(struct zxdh_tools_reps)))) {
		DHTOOLS_LOG_ERR("copy_to_user failed!!!\n");
		kfree(msg);
		return -EFAULT;
	}
	kfree(msg);
	return 0;
}

struct zxdh_tools_ioctl_subcmd_info subcmd_table[] = {
	{ MSG_MARK_INFO, zxdh_tools_mark_event_info },
#ifdef ZXDH_TOOLS_MSGQ
	{ MSG_SEND_TO_RISCV, zxdh_tools_ioctl_msgq_send },
#else
	{ MSG_SEND_TO_RISCV, zxdh_tools_ioctl_barchan_send },
#endif
	{ MSG_DEVICE_INFO_GET, dhtool_device_info_get },
	{ MSG_SET_VF_STATUS, zxdh_tools_set_vf_status },
	{ MSG_DEVICE_PHYPORT_GET, dhtool_dev_phyport_get },
	{ MSG_PKT_CAPTURE, dhtool_pkt_capture },
	{ MSG_GET_DRV_VERSION, dhtool_get_compat_infor },
	{ MSG_SET_VF_MAC, zxdh_tools_set_vf_mac },
	{ MSG_GET_SW_STAT, zxdh_tools_get_sw_stat }
};

s32 zxdh_tools_ioctl_dispatcher(struct net_device *netdev, struct ifreq *ifr)
{
	struct zxdh_tools_msg *msg = NULL;
	s32 ret = 0;
	u32 i = 0;

	//DHTOOLS_LOG_INFO("is called!\n");
	msg = kzalloc(sizeof(*msg), GFP_KERNEL);
	if (!msg) {
		DHTOOLS_LOG_ERR("kzalloc msg failed!!!\n");
		return -1;
	}

	if (copy_from_user(msg, ifr->ifr_ifru.ifru_data, sizeof(struct zxdh_tools_msg))) {
		DHTOOLS_LOG_ERR("copy_from_user failed!!!\n");
		kfree(msg);
		return -EFAULT;
	}

	for (i = 0; i < ARRAY_SIZE(subcmd_table); i++) {
		if ((subcmd_table[i].subcmd == msg->subcmd) && (subcmd_table[i].subcmd_callback)) {
			ret = subcmd_table[i].subcmd_callback(netdev, ifr);
			break;
		}
	}

	if (i == ARRAY_SIZE(subcmd_table))
		DHTOOLS_LOG_ERR("No the callback of msg->subcmd %d!", msg->subcmd);

	kfree(msg);
	return ret;
}
