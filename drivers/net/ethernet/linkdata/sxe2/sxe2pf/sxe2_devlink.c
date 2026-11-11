// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2_devlink.c
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#include "sxe2_compat.h"
#include "sxe2.h"
#include "sxe2_log.h"
#include "sxe2_devlink.h"
#include "sxe2_udp_tunnel.h"

#ifdef HAVE_DEVLINK_PARAMS
enum sxe2_devlink_param_id {
	SXE2_DEVLINK_PARAM_ID_BASE = DEVLINK_PARAM_GENERIC_ID_MAX,
	SXE2_DEVLINK_PARAM_ID_UDP_TUNNEL_VXLAN_PORT,
	SXE2_DEVLINK_PARAM_ID_UDP_TUNNEL_VXLAN_GPE_PORT,
	SXE2_DEVLINK_PARAM_ID_UDP_TUNNEL_GENEVE_PORT,
	SXE2_DEVLINK_PARAM_ID_UDP_TUNNEL_GTP_C_PORT,
	SXE2_DEVLINK_PARAM_ID_UDP_TUNNEL_GTP_U_PORT,
	SXE2_DEVLINK_PARAM_ID_UDP_TUNNEL_PFCP_PORT,
	SXE2_DEVLINK_PARAM_ID_UDP_TUNNEL_ECPRI_PORT,
	SXE2_DEVLINK_PARAM_ID_UDP_TUNNEL_MPLS_PORT,
	SXE2_DEVLINK_PARAM_ID_UDP_TUNNEL_NVGRE_PORT,
	SXE2_DEVLINK_PARAM_ID_UDP_TUNNEL_L2TP_PORT,
	SXE2_DEVLINK_PARAM_ID_UDP_TUNNEL_TEREDO_PORT,
};

STATIC s32 sxe2_devlink_param_to_udp_proto(
	u32 id, enum sxe2_udp_tunnel_protocol *proto)
{
	switch (id) {
	case SXE2_DEVLINK_PARAM_ID_UDP_TUNNEL_VXLAN_PORT:
		*proto = SXE2_UDP_TUNNEL_PROTOCOL_VXLAN;
		return 0;
	case SXE2_DEVLINK_PARAM_ID_UDP_TUNNEL_VXLAN_GPE_PORT:
		*proto = SXE2_UDP_TUNNEL_PROTOCOL_VXLAN_GPE;
		return 0;
	case SXE2_DEVLINK_PARAM_ID_UDP_TUNNEL_GENEVE_PORT:
		*proto = SXE2_UDP_TUNNEL_PROTOCOL_GENEVE;
		return 0;
	case SXE2_DEVLINK_PARAM_ID_UDP_TUNNEL_GTP_C_PORT:
		*proto = SXE2_UDP_TUNNEL_PROTOCOL_GTP_C;
		return 0;
	case SXE2_DEVLINK_PARAM_ID_UDP_TUNNEL_GTP_U_PORT:
		*proto = SXE2_UDP_TUNNEL_PROTOCOL_GTP_U;
		return 0;
	case SXE2_DEVLINK_PARAM_ID_UDP_TUNNEL_PFCP_PORT:
		*proto = SXE2_UDP_TUNNEL_PROTOCOL_PFCP;
		return 0;
	case SXE2_DEVLINK_PARAM_ID_UDP_TUNNEL_ECPRI_PORT:
		*proto = SXE2_UDP_TUNNEL_PROTOCOL_ECPRI;
		return 0;
	case SXE2_DEVLINK_PARAM_ID_UDP_TUNNEL_MPLS_PORT:
		*proto = SXE2_UDP_TUNNEL_PROTOCOL_MPLS;
		return 0;
	case SXE2_DEVLINK_PARAM_ID_UDP_TUNNEL_NVGRE_PORT:
		*proto = SXE2_UDP_TUNNEL_PROTOCOL_NVGRE;
		return 0;
	case SXE2_DEVLINK_PARAM_ID_UDP_TUNNEL_L2TP_PORT:
		*proto = SXE2_UDP_TUNNEL_PROTOCOL_L2TP;
		return 0;
	case SXE2_DEVLINK_PARAM_ID_UDP_TUNNEL_TEREDO_PORT:
		*proto = SXE2_UDP_TUNNEL_PROTOCOL_TEREDO;
		return 0;
	default:
		return -EOPNOTSUPP;
	}
}

STATIC s32 sxe2_devlink_udp_tunnel_get(
	struct devlink *devlink, u32 id, struct devlink_param_gset_ctx *ctx)
{
	struct sxe2_adapter *adapter = devlink_priv(devlink);
	enum sxe2_udp_tunnel_protocol proto;
	u16 port;
	s32 ret;

	ret = sxe2_devlink_param_to_udp_proto(id, &proto);
	if (ret)
		return ret;

	ret = sxe2_udp_tunnel_main_vsi_get(adapter, proto, &port);
	if (!ret)
		ctx->val.vu32 = port;

	return ret;
}

#ifdef HAVE_DEVLINK_PARAMS_SET_EXTACK
STATIC s32 sxe2_devlink_udp_tunnel_set(
	struct devlink *devlink, u32 id, struct devlink_param_gset_ctx *ctx,
	struct netlink_ext_ack *extack)
#else
STATIC s32 sxe2_devlink_udp_tunnel_set(
	struct devlink *devlink, u32 id, struct devlink_param_gset_ctx *ctx)
#endif
{
	struct sxe2_adapter *adapter = devlink_priv(devlink);
	enum sxe2_udp_tunnel_protocol proto;
	s32 ret;

	ret = sxe2_devlink_param_to_udp_proto(id, &proto);
	if (ret)
		return ret;
	if (ctx->val.vu32 > U16_MAX) {
#ifdef HAVE_DEVLINK_PARAMS_SET_EXTACK
		NL_SET_ERR_MSG_MOD(extack,
				   "UDP tunnel port must be in range 0..65535");
#endif
		return -EINVAL;
	}

	ret = sxe2_udp_tunnel_main_vsi_set(adapter, proto,
					   (u16)ctx->val.vu32);
#ifdef HAVE_DEVLINK_PARAMS_SET_EXTACK
	if (ret == -EBUSY)
		NL_SET_ERR_MSG_MOD(extack,
				   "Another VSI owns a different port for this UDP tunnel protocol");
	else if (ret == -EIO)
		NL_SET_ERR_MSG_MOD(extack,
				   "UDP tunnel owner state is inconsistent");
#endif

	return ret;
}

STATIC s32 sxe2_devlink_udp_tunnel_validate(
	struct devlink *devlink, u32 id, union devlink_param_value val,
	struct netlink_ext_ack *extack)
{
	enum sxe2_udp_tunnel_protocol proto;
	s32 ret;

	(void)devlink;
	ret = sxe2_devlink_param_to_udp_proto(id, &proto);
	if (ret)
		return ret;
	if (val.vu32 > U16_MAX) {
		NL_SET_ERR_MSG_MOD(extack,
				   "UDP tunnel port must be in range 0..65535");
		return -EINVAL;
	}

	return 0;
}

#define SXE2_DEVLINK_UDP_TUNNEL_PARAM(_id, _name)                         \
	DEVLINK_PARAM_DRIVER((_id), (_name), DEVLINK_PARAM_TYPE_U32,       \
			     BIT(DEVLINK_PARAM_CMODE_RUNTIME),              \
			     sxe2_devlink_udp_tunnel_get,                    \
			     sxe2_devlink_udp_tunnel_set,                    \
			     sxe2_devlink_udp_tunnel_validate)

STATIC const struct devlink_param sxe2_udp_tunnel_params[] = {
	SXE2_DEVLINK_UDP_TUNNEL_PARAM(
		SXE2_DEVLINK_PARAM_ID_UDP_TUNNEL_VXLAN_PORT,
		"udp_tunnel_vxlan_port"),
	SXE2_DEVLINK_UDP_TUNNEL_PARAM(
		SXE2_DEVLINK_PARAM_ID_UDP_TUNNEL_VXLAN_GPE_PORT,
		"udp_tunnel_vxlan_gpe_port"),
	SXE2_DEVLINK_UDP_TUNNEL_PARAM(
		SXE2_DEVLINK_PARAM_ID_UDP_TUNNEL_GENEVE_PORT,
		"udp_tunnel_geneve_port"),
	SXE2_DEVLINK_UDP_TUNNEL_PARAM(
		SXE2_DEVLINK_PARAM_ID_UDP_TUNNEL_GTP_C_PORT,
		"udp_tunnel_gtp_c_port"),
	SXE2_DEVLINK_UDP_TUNNEL_PARAM(
		SXE2_DEVLINK_PARAM_ID_UDP_TUNNEL_GTP_U_PORT,
		"udp_tunnel_gtp_u_port"),
	SXE2_DEVLINK_UDP_TUNNEL_PARAM(
		SXE2_DEVLINK_PARAM_ID_UDP_TUNNEL_PFCP_PORT,
		"udp_tunnel_pfcp_port"),
	SXE2_DEVLINK_UDP_TUNNEL_PARAM(
		SXE2_DEVLINK_PARAM_ID_UDP_TUNNEL_ECPRI_PORT,
		"udp_tunnel_ecpri_port"),
	SXE2_DEVLINK_UDP_TUNNEL_PARAM(
		SXE2_DEVLINK_PARAM_ID_UDP_TUNNEL_MPLS_PORT,
		"udp_tunnel_mpls_port"),
	SXE2_DEVLINK_UDP_TUNNEL_PARAM(
		SXE2_DEVLINK_PARAM_ID_UDP_TUNNEL_NVGRE_PORT,
		"udp_tunnel_nvgre_port"),
	SXE2_DEVLINK_UDP_TUNNEL_PARAM(
		SXE2_DEVLINK_PARAM_ID_UDP_TUNNEL_L2TP_PORT,
		"udp_tunnel_l2tp_port"),
	SXE2_DEVLINK_UDP_TUNNEL_PARAM(
		SXE2_DEVLINK_PARAM_ID_UDP_TUNNEL_TEREDO_PORT,
		"udp_tunnel_teredo_port"),
};

s32 sxe2_devlink_udp_tunnel_params_register(struct sxe2_adapter *adapter)
{
	struct devlink *devlink = priv_to_devlink(adapter);
	s32 ret;

	ret = devlink_params_register(devlink, sxe2_udp_tunnel_params,
				      ARRAY_SIZE(sxe2_udp_tunnel_params));
	if (ret) {
		LOG_DEV_ERR("Register UDP tunnel Devlink parameters failed, ret=%d\n",
			    ret);
		return ret;
	}

#ifdef HAVE_DEVLINK_PARAMS_PUBLISH
	devlink_params_publish(devlink);
#endif
	return 0;
}

void sxe2_devlink_udp_tunnel_params_unregister(struct sxe2_adapter *adapter)
{
	struct devlink *devlink = priv_to_devlink(adapter);

#ifdef HAVE_DEVLINK_PARAMS_PUBLISH
	devlink_params_unpublish(devlink);
#endif
	devlink_params_unregister(devlink, sxe2_udp_tunnel_params,
				  ARRAY_SIZE(sxe2_udp_tunnel_params));
}
#else
s32 sxe2_devlink_udp_tunnel_params_register(struct sxe2_adapter *adapter)
{
	(void)adapter;
	return 0;
}

void sxe2_devlink_udp_tunnel_params_unregister(struct sxe2_adapter *adapter)
{
	(void)adapter;
}
#endif

#ifdef ESWITCH_MODE_SET_NEED_TWO_PRAMS
int sxe2_eswitch_mode_set(struct devlink *devlink, u16 mode)
#else
int sxe2_eswitch_mode_set(struct devlink *devlink, u16 mode,
			  struct netlink_ext_ack *extack)
#endif
{
#ifdef HAVE_METADATA_PORT_INFO
	s32 ret = 0;
	struct sxe2_adapter *adapter = devlink_priv(devlink);

	if (!test_bit(SXE2_FLAG_SWITCHDEV_CAPABLE, adapter->flags) &&
	    mode == DEVLINK_ESWITCH_MODE_SWITCHDEV) {
		ret = -EOPNOTSUPP;
		return ret;
	}

	if (sxe2_eswitch_mode_write_try_lock(adapter)) {
		LOG_DEV_INFO("PF %d get eswitchlock fail\n", adapter->pf_idx);
		ret = -EBUSY;
		goto l_end;
	}

	if (adapter->eswitch_ctxt.mode == mode)
		goto l_end;

	if (sxe2_vf_is_exist(adapter)) {
		LOG_DEV_INFO("changing eswitch mode is allowed only if there is no\t"
			     "VFs created.\n");
		ret = -EOPNOTSUPP;
		goto l_end;
	}

	switch (mode) {
	case DEVLINK_ESWITCH_MODE_LEGACY:
		LOG_DEV_INFO("PF %d changed eswitch mode to legacy.\n",
			     adapter->pf_idx);
		break;
	case DEVLINK_ESWITCH_MODE_SWITCHDEV:
		if (sxe2_macvlan_is_enabled(adapter)) {
			LOG_DEV_ERR("PF %d switchdev cannot be configured L2\t"
				    "Forwarding Offload is currently enabled.\n",
				    adapter->pf_idx);
			ret = -EOPNOTSUPP;
			goto l_end;
		}
		LOG_DEV_INFO("PF %d changed eswitch mode to switchdev.\n",
			     adapter->pf_idx);
		break;
	default:
#ifndef ESWITCH_MODE_SET_NEED_TWO_PRAMS
		NL_SET_ERR_MSG_MOD(extack, "Unknown eswitch mode");
#endif
		ret = -EINVAL;
		goto l_end;
	}

	adapter->eswitch_ctxt.mode = mode;

l_end:
	sxe2_eswitch_mode_write_unlock(adapter);
	return ret;
#else
	return -EOPNOTSUPP;
#endif
}

int sxe2_eswitch_mode_get(struct devlink *devlink, u16 *mode)
{
	struct sxe2_adapter *adapter = devlink_priv(devlink);

	*mode = adapter->eswitch_ctxt.mode;
	return 0;
}

static const struct devlink_ops sxe2_devlink_ops = {
		.eswitch_mode_get = sxe2_eswitch_mode_get,
		.eswitch_mode_set = sxe2_eswitch_mode_set,
};

void sxe2_devlink_register(struct sxe2_adapter *adapter)
{
	s32 ret = 0;
	struct devlink *devlink = priv_to_devlink(adapter);
#ifdef DEVLINK_REGISTER_NEED_2_PARAMS
	clear_bit(SXE2_FLAG_DEVLINK_REGISTERED, adapter->flags);
	ret = devlink_register(devlink, &adapter->pdev->dev);
	if (ret) {
		LOG_DEV_WARN("devlink_register failed, ret %d\n", ret);
		return;
	}

	ret = sxe2_devlink_udp_tunnel_params_register(adapter);
	if (ret) {
		LOG_DEV_WARN("sxe2_devlink_udp_tunnel_params_register failed, ret %d\n", ret);
		devlink_unregister(devlink);
		return;
	}

	set_bit(SXE2_FLAG_DEVLINK_REGISTERED, adapter->flags);
#else
	clear_bit(SXE2_FLAG_DEVLINK_REGISTERED, adapter->flags);
	ret = sxe2_devlink_udp_tunnel_params_register(adapter);
	if (ret) {
		LOG_DEV_WARN("sxe2_devlink_udp_tunnel_params_register failed, ret %d\n", ret);
		return;
	}

	devlink_register(devlink);
	set_bit(SXE2_FLAG_DEVLINK_REGISTERED, adapter->flags);
#endif
}

void sxe2_devlink_unregister(struct sxe2_adapter *adapter)
{
	if (!test_bit(SXE2_FLAG_DEVLINK_REGISTERED, adapter->flags))
		return;
#ifdef DEVLINK_REGISTER_NEED_2_PARAMS
	sxe2_devlink_udp_tunnel_params_unregister(adapter);
	devlink_unregister(priv_to_devlink(adapter));
#else
	devlink_unregister(priv_to_devlink(adapter));
	sxe2_devlink_udp_tunnel_params_unregister(adapter);
#endif
}

void sxe2_adapter_free(void *devlink_ptr)
{
	devlink_free((struct devlink *)devlink_ptr);
}

struct sxe2_adapter *sxe2_adapter_create(struct pci_dev *pdev)
{
	struct sxe2_adapter *adapter;
	struct device *dev = &pdev->dev;
	const char *device_name = dev_name(dev);
	struct devlink *devlink;
	u32 device_len;
	size_t copy_result;

	devlink = devlink_alloc(&sxe2_devlink_ops, sizeof(struct sxe2_adapter), dev);
	if (!devlink)
		return NULL;

	if (devm_add_action_or_reset(dev, sxe2_adapter_free, devlink))
		return NULL;

	adapter = devlink_priv(devlink);
	adapter->pdev = pdev;

	device_len = (u32)(strlen(device_name) + 1);
	copy_result = SXE2_STRCPY(adapter->dev_name, device_name,
				  min_t(u32, device_len, DEV_NAME_LEN));
	if (copy_result >= DEV_NAME_LEN) {
		LOG_INFO_BDF("adapter:%pK, pdev:%pK, device_len:%u\n", adapter, pdev,
			     device_len);
	}
	sxe2_eswitch_mode_rwlock_init(adapter);
	LOG_INFO_BDF("adapter:%pK, pdev:%pK\n", adapter, pdev);

	return adapter;
}
