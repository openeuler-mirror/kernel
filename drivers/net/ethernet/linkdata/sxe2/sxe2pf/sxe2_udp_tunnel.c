// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2_udp_tunnel.c
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#include "sxe2.h"
#include "sxe2_hw.h"
#include "sxe2_log.h"
#include "sxe2_cmd.h"
#include "sxe2_drv_cmd.h"
#include "sxe2_vsi.h"
#include "sxe2_udp_tunnel.h"
#include "sxe2_com_ioctl.h"
#include "sxe2_netdev.h"

static s32 sxe2_fwc_udp_tunnel_port_add(struct sxe2_adapter *adapter,
					struct sxe2_udp_tunnel_cfg *tunnel_config)
{
	s32 ret = 0;
	struct sxe2_cmd_params cmd = {};
	struct sxe2_fwc_udp_tunnel_ref_add_req tunnel_cfg_fwc_req;

	tunnel_cfg_fwc_req.type = tunnel_config->protocol;
	tunnel_cfg_fwc_req.port = cpu_to_le16(tunnel_config->dev_port);

	sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_UDPTUNNEL_ADD, &tunnel_cfg_fwc_req,
				  sizeof(struct sxe2_fwc_udp_tunnel_ref_add_req), NULL,
				  0);

	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret != 0)
		LOG_ERROR("Failed to add func 0 tunnel port, ret=%d", ret);

	return ret;
}

static s32 sxe2_fwc_udp_tunnel_port_del(struct sxe2_adapter *adapter,
					struct sxe2_udp_tunnel_cfg *tunnel_config)
{
	s32 ret = 0;
	struct sxe2_cmd_params cmd = {};
	struct sxe2_fwc_udp_tunnel_ref_delete_req tunnel_cfg_fwc_req;

	tunnel_cfg_fwc_req.type = tunnel_config->protocol;

	sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_UDPTUNNEL_DEL, &tunnel_cfg_fwc_req,
				  sizeof(struct sxe2_fwc_udp_tunnel_ref_delete_req), NULL,
				  0);

	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret != 0)
		LOG_ERROR("Failed to delete func 0 tunnel port, ret=%d", ret);

	return ret;
}

static s32 sxe2_fwc_udp_tunnel_port_get(struct sxe2_adapter *adapter,
					struct sxe2_udp_tunnel_cfg *tunnel_config)
{
	s32 ret = 0;
	struct sxe2_cmd_params cmd = {};
	struct sxe2_fwc_udp_tunnel_ref_get_req tunnel_cfg_fwc_req;
	struct sxe2_fwc_udp_tunnel_ref_get_resp tunnel_cfg_fwc_resp;

	tunnel_cfg_fwc_req.type = tunnel_config->protocol;

	sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_UDPTUNNEL_GET, &tunnel_cfg_fwc_req,
				  sizeof(tunnel_cfg_fwc_req),
				  &tunnel_cfg_fwc_resp, sizeof(tunnel_cfg_fwc_resp));

	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret != 0) {
		LOG_ERROR("Failed to get func 0 tunnel port, ret=%d", ret);
		goto l_end;
	}

	tunnel_config->fw_port = le16_to_cpu(tunnel_cfg_fwc_resp.port);
	tunnel_config->fw_status = tunnel_cfg_fwc_resp.enable;
	tunnel_config->fw_dst_en = tunnel_cfg_fwc_resp.dst;
	tunnel_config->fw_src_en = tunnel_cfg_fwc_resp.src;
	tunnel_config->fw_used = tunnel_cfg_fwc_resp.used;

l_end:
	return ret;
}

static s32 sxe2_udp_tunnel_port_add_fw(struct sxe2_adapter *ad,
				       enum sxe2_udp_tunnel_protocol tunnel_proto,
				       u16 udp_port,
				       struct sxe2_udp_tunnel_cfg *tunnel_config)
{
	s32 ret = 0;

	tunnel_config->protocol = tunnel_proto;
	ret = sxe2_fwc_udp_tunnel_port_get(ad, tunnel_config);
	if (ret)
		goto l_end;

	if (tunnel_config->fw_used == SXE2_UDP_TUNNEL_ENABLE &&
	    tunnel_config->fw_port != udp_port) {
		LOG_ERROR("Hardware already configured with [type %d, udp_port %d]\n",
			  tunnel_proto, tunnel_config->fw_port);
		ret = -EINVAL;
		goto l_end;
	}

	tunnel_config->dev_port = udp_port;
	ret = sxe2_fwc_udp_tunnel_port_add(ad, tunnel_config);
	if (ret) {
		tunnel_config->dev_port = 0;
		goto l_end;
	}

l_end:
	return ret;
}

STATIC s32 sxe2_udp_tunnel_port_add_common(struct sxe2_vsi *vsi,
					   enum sxe2_udp_tunnel_protocol tunnel_proto,
					   u16 udp_port)
{
	struct sxe2_adapter *adapter = vsi->adapter;
	struct sxe2_udp_tunnel_cfg *tunnel_config = NULL, *tunnel_config_tmp = NULL;
	struct sxe2_vsi *rule_vsi = NULL;
	bool need_add_fw = true;
	s32 ret = 0;
	u32 pos = 0;

	mutex_lock(&adapter->udp_tunnel_ctxt.lock);
	tunnel_config = &vsi->udp_tunnel.cfgs[tunnel_proto];
	if (tunnel_config->dev_status == SXE2_UDP_TUNNEL_ENABLE) {
		if (udp_port == tunnel_config->dev_port &&
		    tunnel_config->dev_ref_cnt < 0xFFFFU) {
			need_add_fw = false;
		} else {
			LOG_ERROR_BDF("Udp port %u is invalid\n", udp_port);
			ret = -EINVAL;
			goto l_end;
		}
	} else {
		while (pos < SXE2_MAX_VSI_NUM) {
			pos = (u16)find_next_bit(adapter->udp_tunnel_ctxt.vsi_map,
						 SXE2_MAX_VSI_NUM, pos + 1);
			if (pos < SXE2_MAX_VSI_NUM && pos != vsi->id_in_pf) {
				rule_vsi = adapter->vsi_ctxt.vsi[pos];
				tunnel_config_tmp =
						&rule_vsi->udp_tunnel.cfgs[tunnel_proto];
				if (tunnel_config_tmp->dev_status ==
				    SXE2_UDP_TUNNEL_ENABLE) {
					need_add_fw = false;
					if (udp_port != tunnel_config_tmp->dev_port) {
						ret = -EINVAL;
						goto l_end;
					}
					break;
				}
			}
		}
	}

	if (need_add_fw) {
		ret = sxe2_udp_tunnel_port_add_fw(adapter, tunnel_proto, udp_port,
						  tunnel_config);
		if (ret) {
			LOG_ERROR("Add udp proto port %u to fw failed!\n", udp_port);
			goto l_end;
		}
	}

	tunnel_config->dev_status = SXE2_UDP_TUNNEL_ENABLE;
	tunnel_config->dev_port = udp_port;
	tunnel_config->dev_ref_cnt++;

l_end:
	mutex_unlock(&adapter->udp_tunnel_ctxt.lock);
	return ret;
}

STATIC s32 sxe2_udp_tunnel_port_del_common(struct sxe2_vsi *vsi,
					   enum sxe2_udp_tunnel_protocol tunnel_proto,
					   u16 udp_port, bool do_clear)
{
	struct sxe2_adapter *adapter = vsi->adapter;
	struct sxe2_udp_tunnel_cfg *tunnel_config, *tunnel_config_tmp;
	struct sxe2_vsi *rule_vsi = NULL;
	bool exist_in_cur_vsi = false;
	bool exist_in_other_vsi = false;
	bool need_rm_fw = false;
	s32 ret = 0;
	u16 pos = 0;

	tunnel_config = &vsi->udp_tunnel.cfgs[tunnel_proto];
	if (tunnel_config->dev_status == SXE2_UDP_TUNNEL_ENABLE &&
	    udp_port == tunnel_config->dev_port) {
		tunnel_config->dev_ref_cnt--;
		if (tunnel_config->dev_ref_cnt > 0) {
			exist_in_cur_vsi = true;
		} else {
			while (pos < SXE2_MAX_VSI_NUM) {
				pos = (u16)find_next_bit(adapter->udp_tunnel_ctxt.vsi_map,
							 SXE2_MAX_VSI_NUM, pos + 1);
				if (pos < SXE2_MAX_VSI_NUM && pos != vsi->id_in_pf) {
					rule_vsi = adapter->vsi_ctxt.vsi[pos];
					tunnel_config_tmp =
							&rule_vsi->udp_tunnel.cfgs
									 [tunnel_proto];
					if (tunnel_config_tmp->dev_status ==
							    SXE2_UDP_TUNNEL_ENABLE &&
					    udp_port == tunnel_config_tmp->dev_port) {
						exist_in_other_vsi = true;
						break;
					}
				}
			}
		}
	} else {
		ret = -EINVAL;
		goto l_end;
	}

	if ((!exist_in_other_vsi && (!exist_in_cur_vsi || do_clear)) ||
	    (do_clear && vsi == adapter->vsi_ctxt.main_vsi)) {
		need_rm_fw = true;
	}

	if (need_rm_fw) {
		tunnel_config->dev_port = udp_port;
		ret = sxe2_fwc_udp_tunnel_port_del(adapter, tunnel_config);
		if (ret)
			goto l_end;

		tunnel_config->dev_status = SXE2_UDP_TUNNEL_DISABLE;
		tunnel_config->dev_ref_cnt = 0;
	}

l_end:
	return ret;
}

#ifdef HAVE_UDP_TUNNEL_NIC_INFO

STATIC enum sxe2_udp_tunnel_protocol
sxe2_udp_tunnel_type_to_priv(enum udp_parsable_tunnel_type type)
{
	static enum sxe2_udp_tunnel_protocol sxe2_udp_proto_map[] = {
			[UDP_TUNNEL_TYPE_VXLAN] = SXE2_UDP_TUNNEL_PROTOCOL_VXLAN,
			[UDP_TUNNEL_TYPE_GENEVE] = SXE2_UDP_TUNNEL_PROTOCOL_GENEVE,
			[UDP_TUNNEL_TYPE_VXLAN_GPE] = SXE2_UDP_TUNNEL_PROTOCOL_VXLAN_GPE,
	};

	return sxe2_udp_proto_map[type];
}

s32 sxe2_udp_tunnel_set_port(struct net_device *netdev, u32 table_idx, u32 idx,
			     struct udp_tunnel_info *ti)
{
	s32 ret = 0;
	struct sxe2_netdev_priv *priv = netdev_priv(netdev);
	struct sxe2_adapter *adapter = priv->vsi->adapter;
	enum sxe2_udp_tunnel_protocol type = 0;
	u8 filter_index = 0;

	type = sxe2_udp_tunnel_type_to_priv(ti->type);
	ret = sxe2_udp_tunnel_port_add_common(adapter->vsi_ctxt.main_vsi, type, ti->port);
	if (ret != 0) {
		LOG_ERROR("Set 0 tunnel port failed [ret=%d]\n", ret);
		goto l_end;
	}

	udp_tunnel_nic_set_port_priv(netdev, table_idx, idx, filter_index);
l_end:
	return ret;
}

s32 sxe2_udp_tunnel_unset_port(struct net_device *netdev, u32 table_idx, u32 idx,
			       struct udp_tunnel_info *ti)
{
	s32 ret = 0;
	struct sxe2_netdev_priv *priv = netdev_priv(netdev);
	struct sxe2_adapter *adapter = priv->vsi->adapter;
	enum sxe2_udp_tunnel_protocol type = 0;

	type = sxe2_udp_tunnel_type_to_priv(ti->type);
	ret = sxe2_udp_tunnel_port_del_common(adapter->vsi_ctxt.main_vsi, type, ti->port,
					      false);
	if (ret != 0) {
		LOG_ERROR("Del 0 tunnel port failed [ret=%d]\n", ret);
		goto l_end;
	}

l_end:
	return ret;
}
#endif

s32 sxe2_com_udptunnel_handler(struct sxe2_adapter *adapter, struct sxe2_obj *obj,
			       struct sxe2_drv_cmd_params *cmd_buf)
{
	s32 ret = 0;
	struct sxe2_drv_udp_tunnel_req *req = NULL;
	struct sxe2_drv_udp_tunnel_resp resp = {};
	struct sxe2_udp_tunnel_cfg tunnel_config = {};
	struct sxe2_vsi *vsi = NULL;

	mutex_lock(&adapter->vsi_ctxt.lock);
	vsi = sxe2_vsi_get_by_idx(adapter, cmd_buf->vsi_id);
	if (!vsi) {
		LOG_ERROR_BDF("failed to get vsi[%u]\n", cmd_buf->vsi_id);
		ret = -EINVAL;
		mutex_unlock(&adapter->vsi_ctxt.lock);
		goto l_end;
	}
	mutex_unlock(&adapter->vsi_ctxt.lock);

	req = (struct sxe2_drv_udp_tunnel_req *)sxe2_com_req_data_copy_to_kernel(cmd_buf,
										 obj);
	if (!req) {
		LOG_ERROR_BDF("copy_from_user failed, len=%lu\n",
			      sizeof(struct sxe2_drv_udp_tunnel_req));
		ret = -EFAULT;
		goto l_end;
	}

	switch (cmd_buf->opcode) {
	case SXE2_DRV_CMD_UDPTUNNEL_ADD:
		ret = sxe2_udp_tunnel_port_add_common(vsi, req->type, req->port);
		if (ret) {
			LOG_ERROR_BDF("Udp tunnel port add failed, [ret=%d]\n", ret);
			goto l_end;
		}
		break;
	case SXE2_DRV_CMD_UDPTUNNEL_DEL:
		ret = sxe2_udp_tunnel_port_del_common(vsi, req->type, req->port, false);
		if (ret) {
			LOG_ERROR_BDF("Udp tunnel port del failed, [ret=%d]\n", ret);
			goto l_end;
		}
		break;
	case SXE2_DRV_CMD_UDPTUNNEL_GET:
		tunnel_config.protocol = req->type;
		ret = sxe2_fwc_udp_tunnel_port_get(adapter, &tunnel_config);
		if (ret) {
			LOG_ERROR_BDF("Udp tunnel port get failed, [ret=%d]\n", ret);
			goto l_end;
		}
		resp.type = tunnel_config.protocol;
		resp.port = tunnel_config.fw_port;
		resp.src = tunnel_config.fw_src_en;
		resp.dst = tunnel_config.fw_dst_en;
		resp.enable = tunnel_config.fw_status;
		resp.fw_used = tunnel_config.fw_used;

		if (sxe2_com_resp_copy_to_user(cmd_buf, &resp, sizeof(resp), obj) != 0) {
			LOG_ERROR_BDF("copy_to_user failed, len=%lu\n", sizeof(resp));
			ret = -EFAULT;
			goto l_end;
		}
		break;
	default:
		LOG_ERROR_BDF("Invalid opcode: %d\n", cmd_buf->opcode);
		ret = -EINVAL;
	}

l_end:
	kfree(req);
	return ret;
}

STATIC s32 sxe2_udp_tunnel_port_clear_by_vsi(struct sxe2_vsi *vsi)
{
	struct sxe2_udp_tunnel_cfg *tunnel_config = NULL;
	struct sxe2_adapter *adapter = vsi->adapter;
	u8 tunnel_proto = 0;
	s32 ret = 0;

	for (tunnel_proto = 0; tunnel_proto < SXE2_UDP_TUNNEL_MAX; tunnel_proto++) {
		tunnel_config = &vsi->udp_tunnel.cfgs[tunnel_proto];
		if (tunnel_config->dev_status != SXE2_UDP_TUNNEL_ENABLE)
			continue;

		ret = sxe2_udp_tunnel_port_del_common(vsi, tunnel_config->protocol,
						      tunnel_config->dev_port, true);
		if (ret != 0) {
			LOG_ERROR_BDF("Clear udp tunnel %d port %d failed, ret=%d\n",
				      tunnel_config->protocol, tunnel_config->dev_port,
				      ret);
		}
	}

	return ret;
}

void sxe2_udptunnel_vsi_init(struct sxe2_vsi *vsi)
{
	struct sxe2_adapter *adapter = vsi->adapter;
	struct sxe2_vsi_udp_tunnel *udp_tunnel = &vsi->udp_tunnel;

	memset(udp_tunnel, 0, sizeof(struct sxe2_vsi_udp_tunnel));
	set_bit(vsi->id_in_pf, adapter->udp_tunnel_ctxt.vsi_map);
}

void sxe2_udptunnel_vsi_deinit(struct sxe2_vsi *vsi)
{
	struct sxe2_adapter *adapter = vsi->adapter;
	struct sxe2_vsi_udp_tunnel *udp_tunnel = &vsi->udp_tunnel;

	(void)sxe2_udp_tunnel_port_clear_by_vsi(vsi);

	memset(udp_tunnel, 0, sizeof(struct sxe2_vsi_udp_tunnel));
	clear_bit(vsi->id_in_pf, adapter->udp_tunnel_ctxt.vsi_map);
}
