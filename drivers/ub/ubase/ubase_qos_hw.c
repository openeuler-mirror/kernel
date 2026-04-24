// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved.
 *
 */

#include <ub/ubase/ubase_comm_qos.h>

#include "ubase_cmd.h"
#include "ubase_ctrlq.h"
#include "ubase_hw.h"

int ubase_query_sl_vl_map(struct ubase_dev *udev, u8 *sl_vl)
{
	struct ubase_query_sl_vl_cmd resp = {0};
	struct ubase_query_sl_vl_cmd req = {0};
	struct ubase_cmd_buf in, out;
	int ret;

	req.sl_num = UBASE_MAX_SL_NUM;
	__ubase_fill_inout_buf(&in, UBASE_OPC_QUERY_TA_SL_VL_MAP, true,
			       sizeof(req), &req);
	__ubase_fill_inout_buf(&out, UBASE_OPC_QUERY_TA_SL_VL_MAP, false,
			       sizeof(resp), &resp);

	ret = __ubase_cmd_send_inout(udev, &in, &out);
	if (ret) {
		ubase_err(udev, "failed to query sl_vl map, ret = %d.\n", ret);
		return ret;
	}

	memcpy(sl_vl, resp.sl_vl, UBASE_MAX_SL_NUM);
	return 0;
}

static inline unsigned long ubase_convert_sl_vl_bitmap(struct ubase_dev *udev,
						       unsigned long sl_bitmap)
{
	unsigned long vl_bitmap = 0;
	u8 i;

	for (i = 0; i < UBASE_MAX_SL_NUM; i++) {
		if (!test_bit(i, &sl_bitmap))
			continue;

		vl_bitmap |= 1 << udev->qos.adev_qos.ue_sl_vl[i];
	}

	return vl_bitmap;
}

static void ubase_get_vl_sche_info(struct ubase_dev *udev,
				   struct ubase_sl_priqos *sl_priqos,
				   unsigned long *vl_bitmap,
				   u8 *vl_bw, u8 *vl_tsa)
{
	unsigned long sl_bitmap = sl_priqos->sl_bitmap;
	u8 i;

	*vl_bitmap = ubase_convert_sl_vl_bitmap(udev, sl_bitmap);
	for (i = 0; i < UBASE_MAX_SL_NUM; i++) {
		if (!test_bit(i, &sl_bitmap))
			continue;

		vl_bw[udev->qos.adev_qos.ue_sl_vl[i]] = sl_priqos->weight[i];
		vl_tsa[udev->qos.adev_qos.ue_sl_vl[i]] = sl_priqos->sch_mode[i];
	}
}

static void ubase_prase_tm_vl_sch_resp(struct ubase_dev *udev,
				       struct ubase_sl_priqos *sl_priqos,
				       struct ubase_cfg_tm_vl_sch_cmd *resp)
{
	unsigned long tsa_bitmap = le16_to_cpu(resp->vl_tsa);
	unsigned long sl_bitmap = sl_priqos->sl_bitmap;
	u8 i;

	for (i = 0; i < UBASE_MAX_SL_NUM; i++) {
		if (!test_bit(i, &sl_bitmap))
			continue;

		sl_priqos->weight[i] = resp->vl_bw[udev->qos.adev_qos.ue_sl_vl[i]];
		sl_priqos->sch_mode[i] = test_bit(udev->qos.adev_qos.ue_sl_vl[i],
						  &tsa_bitmap) ?
					 UBASE_SL_DWRR : UBASE_SL_SP;
	}
}

static void ubase_prase_ets_vl_sch_resp(struct ubase_dev *udev,
					struct ubase_sl_priqos *sl_priqos,
					struct ubase_cfg_ets_vl_sch_cmd *resp)
{
	unsigned long sl_bitmap = sl_priqos->sl_bitmap;
	u8 i;

	for (i = 0; i < UBASE_MAX_SL_NUM; i++) {
		if (!test_bit(i, &sl_bitmap))
			continue;

		sl_priqos->weight[i] = resp->vl_bw[udev->qos.adev_qos.ue_sl_vl[i]];
		sl_priqos->sch_mode[i] = sl_priqos->weight[i] ?
					 UBASE_SL_DWRR : UBASE_SL_SP;
	}
}

static int ubase_check_sp_sch_param(struct ubase_dev *udev, u8 vl_bw,
				    u32 *bw_sum, u8 vl_idx, bool is_ets)
{
	if (is_ets) {
		if (vl_bw) {
			ubase_err(udev,
				  "vl(%u) vl_bw must be 0 in ets sp mode.\n",
				  vl_idx);
			return -EINVAL;
		}

		return 0;
	}

	if (!vl_bw) {
		ubase_err(udev, "vl(%u) vl_bw cannot be 0 in tm sp mode.\n",
			  vl_idx);
		return -EINVAL;
	}

	*bw_sum += vl_bw;

	return 0;
}

static int ubase_check_dwrr_sch_param(struct ubase_dev *udev, u8 vl_bw,
				      u32 *bw_sum, u8 vl_idx)
{
	if (!vl_bw) {
		ubase_err(udev, "vl(%u) bw cannot be 0 in dwrr mode.\n",
			  vl_idx);
		return -EINVAL;
	}

	*bw_sum += vl_bw;

	return 0;
}

static int __ubase_check_qos_sch_param(struct ubase_dev *udev,
				       unsigned long vl_bitmap,
				       u8 *vl_bw, u8 *vl_tsa, bool is_ets)
{
#define UBASE_BW_PERCENT	100

	u32 bw_sum = 0;
	int ret;
	u8 i;

	for (i = 0; i < UBASE_MAX_VL_NUM; i++) {
		if (!test_bit(i, &vl_bitmap))
			continue;

		switch (vl_tsa[i]) {
		case IEEE_8021QAZ_TSA_STRICT:
			ret = ubase_check_sp_sch_param(udev, vl_bw[i], &bw_sum,
						       i, is_ets);
			if (ret)
				return ret;
			break;
		case IEEE_8021QAZ_TSA_ETS:
			ret = ubase_check_dwrr_sch_param(udev, vl_bw[i],
							 &bw_sum, i);
			if (ret)
				return ret;
			break;
		default:
			ubase_err(udev, "not support tc%u tsa model: %u\n",
				  i, vl_tsa[i]);
			return -EINVAL;
		}
	}

	if (bw_sum && bw_sum != UBASE_BW_PERCENT) {
		ubase_err(udev,
			  "the vl_bw sum does not add up to 100 in %s mode.\n",
			  is_ets ? "ets dwrr" : "tm sp/dwrr");
		return -EINVAL;
	}

	return 0;
}

static int __ubase_config_tm_vl_sch(struct ubase_dev *udev, u16 vl_bitmap,
				    u8 *vl_bw, u8 *vl_tsa)
{
	struct ubase_cfg_tm_vl_sch_cmd req = {0};
	struct ubase_cmd_buf in;
	u16 tsa_bitmap = 0;
	int ret;
	u8 i;

	for (i = 0; i < UBASE_MAX_VL_NUM; i++)
		tsa_bitmap |= vl_tsa[i] ? 1 << i : 0;

	req.vl_bitmap = cpu_to_le16(vl_bitmap);
	req.vl_tsa = cpu_to_le16(tsa_bitmap);
	memcpy(req.vl_bw, vl_bw, UBASE_MAX_VL_NUM);

	ubase_fill_inout_buf(&in, UBASE_OPC_TA_VL_SCH_CONFIG, false,
			     sizeof(req), &req);

	ret = __ubase_cmd_send_in(udev, &in);
	if (ret && ret != -EPERM)
		ubase_err(udev, "failed to config tm vl sch, ret = %d", ret);

	return ret;
}

static int __ubase_config_ets_vl_sch(struct ubase_dev *udev, u16 vl_bitmap,
				     u8 *vl_bw, u32 port_bitmap)
{
	struct ubase_cfg_ets_vl_sch_cmd req = {0};
	struct ubase_cmd_buf in;
	int ret;

	req.port_bitmap = cpu_to_le32(port_bitmap);
	req.vl_bitmap = cpu_to_le16(vl_bitmap);
	memcpy(req.vl_bw, vl_bw, UBASE_MAX_VL_NUM);

	ubase_fill_inout_buf(&in, UBASE_OPC_CFG_ETS_TC_INFO, false, sizeof(req),
			     &req);

	ret = __ubase_cmd_send_in(udev, &in);
	if (ret && ret != -EPERM)
		ubase_err(udev, "failed to cfg ets vl sch, ret = %d.", ret);

	return ret;
}

static int ubase_set_tm_priqos(struct ubase_dev *udev,
			       struct ubase_sl_priqos *sl_priqos)
{
	u8 vl_tsa[UBASE_MAX_VL_NUM] = {0};
	u8 vl_bw[UBASE_MAX_VL_NUM] = {0};
	unsigned long vl_bitmap = 0;
	int ret;

	ubase_get_vl_sche_info(udev, sl_priqos, &vl_bitmap, vl_bw, vl_tsa);

	ret = __ubase_check_qos_sch_param(udev, vl_bitmap, vl_bw, vl_tsa, false);
	if (ret)
		return ret;

	return __ubase_config_tm_vl_sch(udev, vl_bitmap, vl_bw, vl_tsa);
}

static int ubase_get_tm_priqos(struct ubase_dev *udev,
			       struct ubase_sl_priqos *sl_priqos)
{
	struct ubase_cfg_tm_vl_sch_cmd resp = {0};
	struct ubase_cfg_tm_vl_sch_cmd req = {0};
	struct ubase_cmd_buf in, out;
	u16 vl_bitmap;
	int ret;

	vl_bitmap = ubase_convert_sl_vl_bitmap(udev, sl_priqos->sl_bitmap);
	req.vl_bitmap = cpu_to_le16(vl_bitmap);

	ubase_fill_inout_buf(&in, UBASE_OPC_TA_VL_SCH_CONFIG, true,
			     sizeof(req), &req);
	ubase_fill_inout_buf(&out, UBASE_OPC_TA_VL_SCH_CONFIG, false,
			     sizeof(resp), &resp);

	ret = __ubase_cmd_send_inout(udev, &in, &out);
	if (ret) {
		ubase_err(udev,
			  "failed to get tm vl sch mode and weight, ret = %d.\n",
			  ret);
		return ret;
	}

	ubase_prase_tm_vl_sch_resp(udev, sl_priqos, &resp);

	return 0;
}

static int ubase_set_ets_priqos(struct ubase_dev *udev,
				struct ubase_sl_priqos *sl_priqos)
{
	u8 vl_tsa[UBASE_MAX_VL_NUM] = {0};
	u8 vl_bw[UBASE_MAX_VL_NUM] = {0};
	unsigned long vl_bitmap = 0;
	int ret;

	ubase_get_vl_sche_info(udev, sl_priqos, &vl_bitmap, vl_bw, vl_tsa);

	ret = __ubase_check_qos_sch_param(udev, vl_bitmap, vl_bw, vl_tsa, true);
	if (ret)
		return ret;

	return __ubase_config_ets_vl_sch(udev, vl_bitmap, vl_bw,
					 sl_priqos->port_bitmap);
}

int ubase_query_ets_tc(struct ubase_dev *udev, u32 port_bitmap,
		       u16 vl_bitmap, struct ubase_cfg_ets_vl_sch_cmd *resp)
{
	struct ubase_cfg_ets_vl_sch_cmd req = {0};
	struct ubase_cmd_buf in, out;
	int ret;

	req.port_bitmap = cpu_to_le32(port_bitmap);
	req.vl_bitmap = cpu_to_le16(vl_bitmap);

	ubase_fill_inout_buf(&in, UBASE_OPC_CFG_ETS_TC_INFO, true,
			     sizeof(req), &req);
	ubase_fill_inout_buf(&out, UBASE_OPC_CFG_ETS_TC_INFO, false,
			     sizeof(*resp), resp);

	ret = __ubase_cmd_send_inout(udev, &in, &out);
	if (ret)
		ubase_err(udev,
			  "failed to query ets tc info, ret = %d.\n", ret);

	return ret;
}

static int ubase_get_ets_priqos(struct ubase_dev *udev,
				struct ubase_sl_priqos *sl_priqos)
{
	struct ubase_cfg_ets_vl_sch_cmd resp = {0};
	u32 port_bitmap;
	u16 vl_bitmap;
	int ret;

	vl_bitmap = ubase_convert_sl_vl_bitmap(udev, sl_priqos->sl_bitmap);
	port_bitmap = sl_priqos->port_bitmap;

	ret = ubase_query_ets_tc(udev, port_bitmap, vl_bitmap, &resp);
	if (ret)
		return ret;

	ubase_prase_ets_vl_sch_resp(udev, sl_priqos, &resp);

	return 0;
}

int ubase_query_ets_tcg(struct ubase_dev *udev,
			struct ubase_query_ets_tcg_cmd *resp)
{
	struct ubase_query_ets_tcg_cmd req = {0};
	struct ubase_cmd_buf in, out;
	int ret;

	ubase_fill_inout_buf(&in, UBASE_OPC_QUERY_ETS_TCG_INFO, true,
			     sizeof(req), &req);
	ubase_fill_inout_buf(&out, UBASE_OPC_QUERY_ETS_TCG_INFO, false,
			     sizeof(*resp), resp);

	ret = __ubase_cmd_send_inout(udev, &in, &out);
	if (ret)
		ubase_err(udev,
			  "failed to query ets tcg info, ret = %d.\n", ret);

	return ret;
}

int ubase_query_ets_port(struct ubase_dev *udev,
			 struct ubase_query_ets_port_cmd *resp)
{
	struct ubase_query_ets_port_cmd req = {0};
	struct ubase_cmd_buf in, out;
	int ret;

	ubase_fill_inout_buf(&in, UBASE_OPC_QUERY_ETS_PORT_INFO, true,
			     sizeof(req), &req);
	ubase_fill_inout_buf(&out, UBASE_OPC_QUERY_ETS_PORT_INFO, false,
			     sizeof(*resp), resp);

	ret = __ubase_cmd_send_inout(udev, &in, &out);
	if (ret)
		ubase_err(udev,
			  "failed to query ets port info, ret = %d.\n", ret);

	return ret;
}

int ubase_query_fst_fvt_rqmt(struct ubase_dev *udev,
			     struct ubase_query_fst_fvt_rqmt_cmd *resp,
			     u16 bus_ue_id)
{
	struct ubase_query_fst_fvt_rqmt_cmd req = {0};
	struct ubase_cmd_buf in, out;
	int ret;

	req.bus_ue_id = cpu_to_le16(bus_ue_id);

	ubase_fill_inout_buf(&in, UBASE_OPC_QUERY_FST_FVT_RQMT, true,
			     sizeof(req), &req);
	ubase_fill_inout_buf(&out, UBASE_OPC_QUERY_FST_FVT_RQMT, false,
			     sizeof(*resp), resp);

	ret = __ubase_cmd_send_inout(udev, &in, &out);
	if (ret == -EPERM)
		return -EOPNOTSUPP;
	if (ret)
		ubase_err(udev,
			  "failed to query fst fvt rqmt info, ret=%d.\n", ret);

	return ret;
}

static unsigned long ubase_get_sl_bitmap(struct ubase_dev *udev)
{
	struct ubase_adev_qos *qos = &udev->qos.adev_qos;
	unsigned long sl_bitmap = 0;
	u8 i;

	for (i = 0; i < qos->nic_sl_num; i++)
		sl_bitmap |= 1 << qos->nic_sl[i];

	for (i = 0; i < qos->tp_sl_num; i++)
		sl_bitmap |= 1 << qos->tp_sl[i];

	for (i = 0; i < qos->ctp_sl_num; i++)
		sl_bitmap |= 1 << qos->ctp_sl[i];

	return sl_bitmap;
}

static int ubase_check_sl_bitmap(struct ubase_dev *udev, unsigned long sl_bitmap)
{
	unsigned long sl_bitmap_cap;
	u8 i;

	sl_bitmap_cap = ubase_get_sl_bitmap(udev);
	for (i = 0; i < UBASE_MAX_SL_NUM; i++) {
		if (!test_bit(i, &sl_bitmap))
			continue;
		if (!test_bit(i, &sl_bitmap_cap))
			return -EINVAL;
	}

	return 0;
}

/**
 * ubase_check_qos_sch_param() - check qos schedule parameters
 * @adev: auxiliary device
 * @vl_bitmap: vl bitmap
 * @vl_bw: vl bandwidth weight
 * @vl_tsa: vl schedule mode
 * @is_ets: is ETS flow control mode
 *
 * The function is used to check qos schedule parameters
 * Obtain valid vls through 'vl_bitmap'. The vl scheduling mode 'vl_tsa' supports
 * two types: dwrr and sp. The sum of the vl scheduling weights 'vl_bw' must be
 * 100. When 'is_ets' is true, it indicates ETS flow control, and the scheduling
 * weight for vls with sp scheduling mode must be 0; when 'is_ets' is false, it
 * indicates TM flow control, and the scheduling weight for vls with sp
 * scheduling mode cannot be 0.
 *
 * Context: Process context. Takes and releases <lock>, BH-safe.
 * Return: 0 on success, negative error code otherwise
 */
int ubase_check_qos_sch_param(struct auxiliary_device *adev, u16 vl_bitmap,
			      u8 *vl_bw, u8 *vl_tsa, bool is_ets)
{
	struct ubase_dev *udev;

	if (!adev || !vl_tsa || !vl_bw)
		return -EINVAL;

	udev = __ubase_get_udev_by_adev(adev);

	return __ubase_check_qos_sch_param(udev, vl_bitmap, vl_bw, vl_tsa,
					   is_ets);
}
EXPORT_SYMBOL(ubase_check_qos_sch_param);

/**
 * ubase_config_tm_vl_sch() - configuring TM flow control scheduling
 * @adev: auxiliary device
 * @vl_bitmap: vl bitmap
 * @vl_bw: vl bandwidth weight
 * @vl_tsa: vl schedule mode
 *
 * The function is used to configure TM flow control scheduling.
 * Configure the scheduling weight 'vl_bw' and scheduling mode 'vl_tsa'
 * corresponding to the valid vl in 'vl_bitmap' to the TM flow control.
 *
 * Context: Process context. Takes and releases <lock>, BH-safe.
 * Return: 0 on success, negative error code otherwise
 */
int ubase_config_tm_vl_sch(struct auxiliary_device *adev, u16 vl_bitmap,
			   u8 *vl_bw, u8 *vl_tsa)
{
	struct ubase_dev *udev;

	if (!adev || !vl_bw  || !vl_tsa)
		return -EINVAL;

	udev = __ubase_get_udev_by_adev(adev);

	return __ubase_config_tm_vl_sch(udev, vl_bitmap, vl_bw, vl_tsa);
}
EXPORT_SYMBOL(ubase_config_tm_vl_sch);

/**
 * ubase_set_priqos_info() - set priority qos information
 * @dev: device
 * @sl_priqos: priority qos
 *
 * The function is used to set priority qos information.
 * Through 'sl_priqos->sl_bitmap', obtain the valid priority sl, use sl as an
 * index to get the corresponding bandwidth weight and scheduling mode from
 * 'sl_priqos->weight' and 'sl_priqos->ch_mode', and configure them to the hardware.
 * Specifically, when 'sl_priqos-> port_bitmap' is 0, it configures the TM flow
 * control; when 'port_bitmap' is not 0, it configures the ETS flow control for
 * the corresponding port.
 * The SP scheduling weight for TM flow control cannot be 0; multiple SP traffic
 * flows are scheduled according to their weights. For ETS flow control, the SP
 * scheduling weight must be 0.
 *
 * Context: Process context. Takes and releases <lock>, BH-safe.
 * Return: 0 on success, negative error code otherwise
 */
int ubase_set_priqos_info(struct device *dev, struct ubase_sl_priqos *sl_priqos)
{
	struct ubase_dev *udev;

	if (!dev || !sl_priqos || !sl_priqos->sl_bitmap)
		return -EINVAL;

	udev = dev_get_drvdata(dev);
	if (ubase_check_sl_bitmap(udev, sl_priqos->sl_bitmap))
		return -EINVAL;

	if (sl_priqos->port_bitmap)
		return ubase_set_ets_priqos(udev, sl_priqos);

	return ubase_set_tm_priqos(udev, sl_priqos);
}
EXPORT_SYMBOL(ubase_set_priqos_info);

/**
 * ubase_get_priqos_info() - get priority qos information
 * @dev: device
 * @sl_priqos: save the queried priority QoS information
 *
 * The function is used to get priority qos information.
 * Obtain the priority sl available for the device, as well as the corresponding
 * bandwidth weight and scheduling mode.
 * When port_bitmap is 0, the obtained values are the bandwidth weight and
 * scheduling mode for TM flow control; when port_bitmap is not 0, the obtained
 * values are the bandwidth weight and scheduling mode for ETS flow control.
 *
 * Context: Process context. Takes and releases <lock>, BH-safe.
 * Return: 0 on success, negative error code otherwise
 */
int ubase_get_priqos_info(struct device *dev, struct ubase_sl_priqos *sl_priqos)
{
	struct ubase_dev *udev;

	if (!dev || !sl_priqos)
		return -EINVAL;

	udev = dev_get_drvdata(dev);

	sl_priqos->sl_bitmap = ubase_get_sl_bitmap(udev);
	if (sl_priqos->port_bitmap)
		return ubase_get_ets_priqos(udev, sl_priqos);

	return ubase_get_tm_priqos(udev, sl_priqos);
}
EXPORT_SYMBOL(ubase_get_priqos_info);

static void ubase_get_sl_by_vl(struct ubase_dev *udev, u8 vl, u8 *sl,
			       u8 *sl_num)
{
	u8 i;

	for (i = 0; i < UBASE_MAX_SL_NUM; i++) {
		if (udev->qos.adev_qos.ue_sl_vl[i] == vl)
			sl[(*sl_num)++] = i;
	}
}

static void ubase_gather_udma_req_resp_vl(struct ubase_dev *udev, u8 *req_vl,
					  u8 req_vl_num, u8 resp_vl_off)
{
	struct ubase_caps *dev_caps = &udev->caps.dev_caps;
	struct ubase_adev_qos *qos = &udev->qos.adev_qos;
	u8 i, j;

	for (i = 0; i < req_vl_num; i++) {
		for (j = 0; j < qos->nic_vl_num; j++) {
			if (req_vl[i] == dev_caps->req_vl[j]) {
				dev_caps->resp_vl[j] = req_vl[i] + resp_vl_off;
				break;
			}
		}

		if (j < qos->nic_vl_num)
			continue;

		dev_caps->req_vl[dev_caps->vl_num] = req_vl[i];
		dev_caps->resp_vl[dev_caps->vl_num] = req_vl[i] + resp_vl_off;
		dev_caps->vl_num++;
	}
}

static void ubase_gather_urma_req_resp_vl(struct ubase_dev *udev)
{
	struct ubase_caps *dev_caps = &udev->caps.dev_caps;
	struct ubase_adev_qos *qos = &udev->qos.adev_qos;

	memcpy(dev_caps->req_vl, qos->nic_vl, qos->nic_vl_num);
	memcpy(dev_caps->resp_vl, qos->nic_vl, qos->nic_vl_num);
	dev_caps->vl_num = qos->nic_vl_num;

	/* Restriction: The unic vl can't be used as the dma resp vl. */
	ubase_gather_udma_req_resp_vl(udev, qos->tp_req_vl, qos->tp_vl_num,
				      qos->tp_resp_vl_offset);
	ubase_gather_udma_req_resp_vl(udev, qos->ctp_req_vl, qos->ctp_vl_num,
				      qos->ctp_resp_vl_offset);

	/* dev_caps->vl_num is used for DCB tool configuration. Therefore,
	 * dev_caps->vl_num cannot exceed IEEE_8021QAZ_MAX_TCS.
	 */
	dev_caps->vl_num = min(dev_caps->vl_num, IEEE_8021QAZ_MAX_TCS);
}

static inline void ubase_gather_cdma_req_resp_vl(struct ubase_dev *udev)
{
	struct ubase_adev_qos *qos = &udev->qos.adev_qos;

	ubase_gather_udma_req_resp_vl(udev, qos->ctp_req_vl,
				      qos->ctp_vl_num,
				      qos->ctp_resp_vl_offset);
}

static int ubase_query_ctp_vl_offset(struct ubase_dev *udev, u8 *ctp_vl_offset)
{
	struct ubase_query_ctp_vl_offset_cmd resp = {0};
	struct ubase_query_ctp_vl_offset_cmd req = {0};
	struct ubase_cmd_buf in, out;
	int ret;

	ubase_fill_inout_buf(&in, UBASE_OPC_QUERY_CTP_VL_OFFSET, true,
			     sizeof(req), &req);
	ubase_fill_inout_buf(&out, UBASE_OPC_QUERY_CTP_VL_OFFSET, false,
			     sizeof(resp), &resp);

	ret = __ubase_cmd_send_inout(udev, &in, &out);
	if (ret) {
		ubase_err(udev,
			  "failed to query ctp vl offset, ret = %d.\n", ret);
		return ret;
	}

	*ctp_vl_offset = resp.ctp_vl_offset;

	ubase_dbg(udev, "ctp_vl_offset:%u.\n", *ctp_vl_offset);

	return 0;
}

static int ubase_check_ctp_resp_vl(struct ubase_dev *udev, u8 ctp_vl_offset)
{
	struct ubase_adev_qos *qos = &udev->qos.adev_qos;
	u8 i, ctp_resp_vl_off;

	for (i = 0; i < qos->ctp_vl_num; i++) {
		ctp_resp_vl_off = qos->ctp_req_vl[i] + ctp_vl_offset;
		if (ctp_resp_vl_off >= UBASE_MAX_VL_NUM) {
			ubase_err(udev,
				  "the %uth ctp_resp_vl(%u) exceed max_vl_num(%u).\n",
				  i, ctp_resp_vl_off, UBASE_MAX_VL_NUM);
			return -EINVAL;
		}
	}

	return 0;
}

static int ubase_parse_ctp_resp_vl(struct ubase_dev *udev)
{
	struct ubase_adev_qos *qos = &udev->qos.adev_qos;
	u8 ctp_vl_offset;
	int ret;

	ret = ubase_query_ctp_vl_offset(udev, &ctp_vl_offset);
	if (ret)
		return ret;

	ret = ubase_check_ctp_resp_vl(udev, ctp_vl_offset);
	if (ret)
		return ret;

	qos->ctp_resp_vl_offset = ctp_vl_offset;

	return 0;
}

static inline int ubase_parse_udma_resp_vl(struct ubase_dev *udev)
{
	if (ubase_dev_ubl_supported(udev))
		return ubase_parse_ctp_resp_vl(udev);

	return 0;
}

static int ubase_get_vl_by_sl(struct ubase_dev *udev, u8 *urma_sl,
			      u8 urma_sl_num, u8 *urma_vl, u8 *urma_vl_num)
{
	u8 urma_vl_bitmap[UBASE_MAX_VL_NUM] = {0};
	u8 i, current_vl;
	int index = 0;

	for (i = 0; i < urma_sl_num; i++) {
		current_vl = udev->qos.adev_qos.ue_sl_vl[urma_sl[i]];
		if (current_vl >= UBASE_MAX_VL_NUM) {
			ubase_err(udev,
				  "urma vl(%u) exceeds the maximum(%u).\n",
				  current_vl, UBASE_MAX_VL_NUM);
			return -EINVAL;
		}

		if (urma_vl_bitmap[current_vl] == 0) {
			urma_vl[index++] = current_vl;
			urma_vl_bitmap[current_vl] = 1;
			(*urma_vl_num)++;
		}
	}

	return 0;
}

static int ubase_parse_nic_vl(struct ubase_dev *udev)
{
	struct ubase_adev_qos *adev_qos = &udev->qos.adev_qos;

	return ubase_get_vl_by_sl(udev, adev_qos->nic_sl, adev_qos->nic_sl_num,
				  adev_qos->nic_vl, &adev_qos->nic_vl_num);
}

static int ubase_parse_udma_req_vl(struct ubase_dev *udev)
{
	struct ubase_adev_qos *qos = &udev->qos.adev_qos;
	int ret;

	ret = ubase_get_vl_by_sl(udev, qos->tp_sl, qos->tp_sl_num,
				 qos->tp_req_vl, &qos->tp_vl_num);
	if (ret)
		return ret;

	if (ubase_dev_ubl_supported(udev))
		return ubase_get_vl_by_sl(udev, qos->ctp_sl, qos->ctp_sl_num,
					  qos->ctp_req_vl, &qos->ctp_vl_num);

	return 0;
}

static int ubase_parse_udma_vl(struct ubase_dev *udev)
{
	int ret;

	ret = ubase_parse_udma_req_vl(udev);
	if (ret)
		return ret;

	return ubase_parse_udma_resp_vl(udev);
}

static int ubase_parse_cdma_resp_vl(struct ubase_dev *udev)
{
	return ubase_parse_ctp_resp_vl(udev);
}

static int ubase_parse_cdma_req_vl(struct ubase_dev *udev)
{
	struct ubase_adev_qos *qos = &udev->qos.adev_qos;

	qos->ctp_vl_num = 0;
	memset(qos->ctp_req_vl, 0, sizeof(u8) * UBASE_MAX_VL_NUM);
	return ubase_get_vl_by_sl(udev, qos->ctp_sl, qos->ctp_sl_num,
				  qos->ctp_req_vl, &qos->ctp_vl_num);
}

static int ubase_parse_cdma_sl(struct ubase_dev *udev)
{
	struct ubase_adev_qos *qos = &udev->qos.adev_qos;
	u8 i;

	for (i = 0; i < qos->ctp_vl_num; i++)
		ubase_get_sl_by_vl(udev, qos->ctp_req_vl[i], qos->ctp_sl,
				   &qos->ctp_sl_num);

	if (!qos->ctp_sl_num) {
		ubase_err(udev, "cdma doesn't have any sl.\n");
		return -EINVAL;
	}

	return 0;
}

static int ubase_parse_cdma_sl_vl(struct ubase_dev *udev)
{
	int ret;

	ret = ubase_parse_cdma_sl(udev);
	if (ret)
		return ret;

	ret = ubase_parse_cdma_req_vl(udev);
	if (ret)
		return ret;

	ret = ubase_parse_cdma_resp_vl(udev);
	if (ret)
		return ret;

	ubase_gather_cdma_req_resp_vl(udev);
	return 0;
}

static int ubase_parse_urma_sl_vl(struct ubase_dev *udev)
{
	int ret;

	ret = ubase_parse_nic_vl(udev);
	if (ret)
		return ret;

	if (ubase_dev_udma_supported(udev)) {
		ret = ubase_parse_udma_vl(udev);
		if (ret)
			return ret;
	}

	ubase_gather_urma_req_resp_vl(udev);
	return 0;
}

static int ubase_parse_adev_sl_vl(struct ubase_dev *udev)
{
	if (ubase_dev_cdma_supported(udev))
		return ubase_parse_cdma_sl_vl(udev);

	if (ubase_dev_urma_supported(udev))
		return ubase_parse_urma_sl_vl(udev);

	return 0;
}

static void ubase_init_udma_dscp_vl(struct ubase_dev *udev)
{
	struct ubase_adev_qos *qos = &udev->qos.adev_qos;
	u8 i;

	for (i = 0; i < UBASE_MAX_DSCP; i++)
		qos->dscp_vl[i] = qos->tp_req_vl[0];
}

static void ubase_parse_max_vl(struct ubase_dev *udev)
{
	struct ubase_adev_qos *qos = &udev->qos.adev_qos;
	u8 i, ue_max_vl_id = 0;

	for (i = 0; i < qos->nic_vl_num; i++)
		ue_max_vl_id = max(qos->nic_vl[i], ue_max_vl_id);

	for (i = 0; i < qos->tp_vl_num; i++)
		ue_max_vl_id = max(qos->tp_req_vl[i] + qos->tp_resp_vl_offset,
				   ue_max_vl_id);

	for (i = 0; i < qos->ctp_vl_num; i++)
		ue_max_vl_id = max(qos->ctp_req_vl[i] + qos->ctp_resp_vl_offset,
				   ue_max_vl_id);

	qos->ue_max_vl_id = ue_max_vl_id;

	if (ubase_dev_urma_supported(udev) && !udev->use_fixed_rc_num)
		udev->caps.udma_caps.rc_max_cnt *= (ue_max_vl_id + 1);
}

static u8 ubase_get_nic_max_vl(struct ubase_dev *udev)
{
	struct ubase_adev_qos *qos = &udev->qos.adev_qos;
	u8 i, nic_max_vl = 0;

	for (i = 0; i < qos->nic_vl_num; i++)
		nic_max_vl = max(qos->nic_vl[i], nic_max_vl);

	return nic_max_vl;
}

static int ubase_parse_sl_vl(struct ubase_dev *udev)
{
	int ret;

	ret = ubase_query_sl_vl_map(udev, udev->qos.adev_qos.ue_sl_vl);
	if (ret)
		return ret;

	ret = ubase_parse_adev_sl_vl(udev);
	if (ret)
		return ret;

	if (ubase_dev_udma_supported(udev))
		ubase_init_udma_dscp_vl(udev);

	if (ubase_utp_supported(udev) && ubase_dev_urma_supported(udev))
		udev->caps.unic_caps.tpg.max_cnt = ubase_get_nic_max_vl(udev) + 1;

	ubase_parse_max_vl(udev);

	return 0;
}

static int ubase_ctrlq_query_vl(struct ubase_dev *udev)
{
	struct ubase_ctrlq_query_vl_resp resp = {0};
	struct ubase_ctrlq_query_vl_req req = {0};
	struct ubase_ctrlq_msg msg = {0};
	unsigned long vl_bitmap;
	u8 i, cdma_vl_cnt = 0;
	int ret;

	msg.service_ver = UBASE_CTRLQ_SER_VER_01;
	msg.service_type = UBASE_CTRLQ_SER_TYPE_QOS;
	msg.opcode = UBASE_CTRLQ_OPC_QUERY_VL;
	msg.need_resp = 1;
	msg.is_resp = 0;
	msg.in_size = sizeof(req);
	msg.in = &req;
	msg.out_size = sizeof(resp);
	msg.out = &resp;

	ret = __ubase_ctrlq_send(udev, &msg, true, NULL);
	if (ret) {
		ubase_err(udev,
			  "failed to send ctrlq msg when query vl, ret = %d.\n",
			  ret);
		return ret;
	}

	vl_bitmap = le16_to_cpu(resp.vl_bitmap);
	ubase_dbg(udev, "ctrlq query vl_bitmap = %lx.\n", vl_bitmap);

	/* NOTE: ctp_req_vl array temporarily saves both ctp req vl and ctp resp vl */
	for (i = 0; i < UBASE_MAX_VL_NUM; i++)
		if (test_bit(i, &vl_bitmap))
			udev->qos.adev_qos.ctp_req_vl[cdma_vl_cnt++] = i;

	if (!cdma_vl_cnt) {
		ubase_err(udev, "cdma doesn't have any vl.\n");
		return -EINVAL;
	}

	udev->qos.adev_qos.ctp_vl_num = cdma_vl_cnt;

	return 0;
}

static bool ubase_check_udma_sl_valid(struct ubase_dev *udev, u8 udma_tp_sl_cnt,
				     u8 udma_ctp_sl_cnt)
{
	if (!ubase_dev_udma_supported(udev))
		return true;

	if (ubase_dev_ubl_supported(udev) && !(udma_tp_sl_cnt + udma_ctp_sl_cnt))
		return false;

	if (!ubase_dev_ubl_supported(udev) && !udma_tp_sl_cnt)
		return false;

	return true;
}

static int ubase_ctrlq_query_sl(struct ubase_dev *udev)
{
	unsigned long unic_sl_bitmap, udma_tp_sl_bitmap, udma_ctp_sl_bitmap;
	u8 unic_sl_cnt = 0, udma_tp_sl_cnt = 0, udma_ctp_sl_cnt = 0;
	struct ubase_ctrlq_query_sl_resp resp = {0};
	struct ubase_ctrlq_query_sl_req req = {0};
	struct ubase_ctrlq_msg msg = {0};
	u16 rc_max_cnt;
	int ret;
	u8 i;

	msg.service_ver = UBASE_CTRLQ_SER_VER_01;
	msg.service_type = UBASE_CTRLQ_SER_TYPE_QOS;
	msg.opcode = UBASE_CTRLQ_OPC_QUERY_SL;
	msg.need_resp = 1;
	msg.is_resp = 0;
	msg.in_size = sizeof(req);
	msg.in = &req;
	msg.out_size = sizeof(resp);
	msg.out = &resp;

	ret = __ubase_ctrlq_send(udev, &msg, true, NULL);
	if (ret) {
		ubase_err(udev,
			  "failed to send ctrlq msg when query sl, ret = %d.\n", ret);
		return ret;
	}

	/* For compatibility, if the control plane returns 0,
	 * the value returned by the IMP is used by default.
	 */
	rc_max_cnt = le16_to_cpu(resp.rc_max_cnt);
	if (rc_max_cnt) {
		udev->use_fixed_rc_num = true;
		udev->caps.udma_caps.rc_max_cnt = rc_max_cnt;
	}

	if (!udev->caps.udma_caps.rc_max_cnt) {
		ubase_err(udev, "rc max cnt is zero.\n");
		return -EINVAL;
	}

	unic_sl_bitmap = le16_to_cpu(resp.unic_sl_bitmap);
	udma_tp_sl_bitmap = le16_to_cpu(resp.udma_tp_sl_bitmap);
	udma_ctp_sl_bitmap = le16_to_cpu(resp.udma_ctp_sl_bitmap);

	ubase_dbg(udev, "ctrlq query rc_max_cnt = %u, unic_sl_bitmap = 0x%lx\n",
		  rc_max_cnt, unic_sl_bitmap);
	ubase_dbg(udev, "udma_tp_sl_bitmap = 0x%lx, udma_ctp_sl_bitmap = 0x%lx.\n",
		  udma_tp_sl_bitmap, udma_ctp_sl_bitmap);

	for (i = 0; i < UBASE_MAX_SL_NUM; i++) {
		if (test_bit(i, &unic_sl_bitmap))
			udev->qos.adev_qos.nic_sl[unic_sl_cnt++] = i;
		if (test_bit(i, &udma_tp_sl_bitmap))
			udev->qos.adev_qos.tp_sl[udma_tp_sl_cnt++] = i;
		if (test_bit(i, &udma_ctp_sl_bitmap))
			udev->qos.adev_qos.ctp_sl[udma_ctp_sl_cnt++] = i;
	}

	if (!unic_sl_cnt) {
		ubase_err(udev, "nic doesn't have any sl.\n");
		return -EINVAL;
	}

	if (!ubase_check_udma_sl_valid(udev, udma_tp_sl_cnt, udma_ctp_sl_cnt)) {
		ubase_err(udev, "udma doesn't have any sl.\n");
		return -EINVAL;
	}

	udev->qos.adev_qos.nic_sl_num = unic_sl_cnt;
	udev->qos.adev_qos.tp_sl_num = udma_tp_sl_cnt;
	udev->qos.adev_qos.ctp_sl_num = udma_ctp_sl_cnt;

	return 0;
}

static int
ubase_check_tm_queue_qset_configuration(struct ubase_dev *udev,
					struct ubase_query_tm_qset_cmd *tm_qset,
					struct ubase_query_tm_queue_cmd *tm_queue)
{
	u8 i;

	if (tm_qset->qset_num != tm_queue->queue_num) {
		ubase_err(udev,
			  "the number of tm_queue(%u) and tm_qsets(%u) are different.\n",
			  tm_queue->queue_num, tm_qset->qset_num);
		return -EINVAL;
	}

	for (i = 0; i < tm_qset->qset_num; i++) {
		if (tm_qset->qset_id[i] != tm_queue->queue_id[i] ||
		    tm_queue->queue_id[i] != tm_queue->qset_id[i]) {
			ubase_err(udev,
				  "tm_qset id(%u, %u) and tm_queue id(%u) are not equal.\n",
				  tm_qset->qset_id[i], tm_queue->qset_id[i],
				  tm_queue->queue_id[i]);
			return -EINVAL;
		}

		if (tm_queue->queue_vl[i] >= UBASE_MAX_VL_NUM) {
			ubase_err(udev,
				  "vl(%u) corresponding to tm_queue(%u) exceeds the maximum value of vl (%u).\n",
				  tm_queue->queue_vl[i], tm_queue->queue_id[i],
				  UBASE_MAX_VL_NUM);
			return -EINVAL;
		}
	}

	return 0;
}

static int ubase_save_initial_qos_configuration(struct ubase_dev *udev)
{
	struct ubase_initial_qset_qos *initial_qos = &udev->qos.initial_qos;
	struct ubase_query_tm_queue_cmd tm_queue = {0};
	struct ubase_query_tm_qset_cmd tm_qset = {0};
	int ret;
	u8 i;

	ret = ubase_query_tm_qset(udev, 0, &tm_qset);
	if (ret)
		return ret == -EOPNOTSUPP ? 0 : ret;

	ret = ubase_query_tm_queue(udev, 0, &tm_queue);
	if (ret)
		return ret == -EOPNOTSUPP ? 0 : ret;

	ret = ubase_check_tm_queue_qset_configuration(udev, &tm_qset, &tm_queue);
	if (ret)
		return ret;

	initial_qos->num = tm_qset.qset_num;
	for (i = 0; i < tm_qset.qset_num; i++) {
		initial_qos->qset_id[i] = tm_qset.qset_id[i];
		initial_qos->qset_weight[i] = tm_qset.qset_weight[i];
		initial_qos->rate[i] = le32_to_cpu(tm_qset.rate[i]);
		initial_qos->vl[i] = tm_queue.queue_vl[i];
	}

	return 0;
}

static int __ubase_config_tm_vl_rate_limit(struct ubase_dev *udev, u16 vl_bitmap,
					   u32 *vl_maxrate)
{
	struct ubase_config_vl_speed_cmd req = {0};
	struct ubase_cmd_buf in;
	int ret;
	u8 i;

	req.vl_bitmap = cpu_to_le16(vl_bitmap);
	for (i = 0; i < UBASE_MAX_VL_NUM; i++)
		req.max_speed[i] = cpu_to_le32(vl_maxrate[i]);

	ubase_fill_inout_buf(&in, UBASE_OPC_VL_RATE_LIMIT_CONFIG, false,
			     sizeof(req), &req);

	ret = __ubase_cmd_send_in(udev, &in);
	if (ret && ret != -EPERM)
		ubase_err(udev,
			  "failed to config tm vl rate limit, ret = %d.\n", ret);

	return ret;
}

/**
 * ubase_config_tm_vl_rate_limit() - config tm vl rate limit
 * @adev: auxiliary device
 * @vl_bitmap: vl bitmap
 * @vl_maxrate: vl max rate
 *
 * The function is used to config tm vl rate limit. Configure the vl max rate
 * 'vl_maxrate' corresponding to the valid vl in 'vl_bitmap'.
 *
 * Context: Process context. Takes and releases <lock>, BH-safe. Sleep.
 * Return: 0 on success, negative error code otherwise
 */
int ubase_config_tm_vl_rate_limit(struct auxiliary_device *adev, u16 vl_bitmap,
				  u32 *vl_maxrate)
{
	struct ubase_dev *udev;

	if (!adev || !vl_maxrate)
		return -EINVAL;

	udev = __ubase_get_udev_by_adev(adev);
	return __ubase_config_tm_vl_rate_limit(udev, vl_bitmap, vl_maxrate);
}
EXPORT_SYMBOL(ubase_config_tm_vl_rate_limit);

static int __ubase_restore_initial_qset_qos(struct ubase_dev *udev)
{
	struct ubase_initial_qset_qos *initial_qos = &udev->qos.initial_qos;
	u32 vl_maxrate[UBASE_MAX_VL_NUM] = {0};
	u8 vl_tsa[UBASE_MAX_VL_NUM] = {0};
	u8 vl_bw[UBASE_MAX_VL_NUM] = {0};
	unsigned long vl_bitmap = 0;
	int ret;
	u8 i;

	if (!initial_qos->num)
		return 0;

	for (i = 0; i < initial_qos->num; i++) {
		set_bit(initial_qos->vl[i], &vl_bitmap);
		vl_bw[i] = initial_qos->qset_weight[i];
		vl_tsa[i] = vl_bw[i] ? UBASE_SL_DWRR : UBASE_SL_SP;
		vl_maxrate[i] = initial_qos->rate[i];
	}

	ret = __ubase_config_tm_vl_sch(udev, vl_bitmap, vl_bw, vl_tsa);
	if (ret)
		return ret;

	return __ubase_config_tm_vl_rate_limit(udev, vl_bitmap, vl_maxrate);
}

int ubase_qos_init(struct ubase_dev *udev)
{
	int ret = 0;

	if (ubase_dev_urma_supported(udev))
		ret = ubase_ctrlq_query_sl(udev);
	else if (ubase_dev_cdma_supported(udev))
		ret = ubase_ctrlq_query_vl(udev);

	if (ret)
		return ret;

	ret = ubase_parse_sl_vl(udev);
	if (ret)
		return ret;

	return ubase_save_initial_qos_configuration(udev);
}

void ubase_qos_uninit(struct ubase_dev *udev)
{
	__ubase_restore_initial_qset_qos(udev);
}

static bool ubase_is_udma_tp_vl(struct ubase_adev_qos *qos, u8 vl)
{
	u8 i;

	for (i = 0; i < qos->tp_vl_num; i++) {
		if (qos->tp_req_vl[i] == vl)
			return true;
	}

	return false;
}

/**
 * ubase_update_udma_dscp_vl() - update udma's dscp to vl mapping
 * @adev: auxiliary device
 * @dscp_vl: dscp to vl mapping
 * @dscp_num: dscp number
 *
 * The function updates the dscp to vl mapping based on 'dscp_vl' and saves it
 * to 'udma_dscp_vl' in 'struct ubase_adev_qos'.
 *
 * Context: Any context.
 */
void ubase_update_udma_dscp_vl(struct auxiliary_device *adev, u8 *dscp_vl,
			       u8 dscp_num)
{
	struct ubase_adev_qos *qos;
	u8 i, arr_len;

	if (!adev || !dscp_vl)
		return;

	qos = ubase_get_adev_qos(adev);
	arr_len = min(UBASE_MAX_DSCP, dscp_num);

	for (i = 0; i < arr_len; i++)
		qos->dscp_vl[i] = ubase_is_udma_tp_vl(qos, dscp_vl[i]) ?
				  dscp_vl[i] : qos->tp_req_vl[0];
}
EXPORT_SYMBOL(ubase_update_udma_dscp_vl);

int ubase_query_tm_queue(struct ubase_dev *udev, u16 bus_ue_id,
			 struct ubase_query_tm_queue_cmd *resp)
{
	struct ubase_query_tm_queue_cmd req = {0};
	struct ubase_cmd_buf in, out;
	int ret;

	req.bus_ue_id = cpu_to_le16(bus_ue_id);

	ubase_fill_inout_buf(&in, UBASE_OPC_QUERY_TM_Q_INFO, true,
			     sizeof(req), &req);
	ubase_fill_inout_buf(&out, UBASE_OPC_QUERY_TM_Q_INFO, false,
			     sizeof(*resp), resp);

	ret = __ubase_cmd_send_inout(udev, &in, &out);
	if (ret == -EPERM)
		return -EOPNOTSUPP;
	if (ret)
		ubase_err(udev,
			  "failed to query tm queue info, bus_ue_id=%u, ret=%d.\n",
			  bus_ue_id, ret);
	return ret;
}

int ubase_query_tm_qset(struct ubase_dev *udev, u16 bus_ue_id,
			struct ubase_query_tm_qset_cmd *resp)
{
	struct ubase_query_tm_qset_cmd req = {0};
	struct ubase_cmd_buf in, out;
	int ret;

	req.bus_ue_id = cpu_to_le16(bus_ue_id);

	ubase_fill_inout_buf(&in, UBASE_OPC_QUERY_TM_QS_INFO, true,
			     sizeof(req), &req);
	ubase_fill_inout_buf(&out, UBASE_OPC_QUERY_TM_QS_INFO, false,
			     sizeof(*resp), resp);

	ret = __ubase_cmd_send_inout(udev, &in, &out);
	if (ret == -EPERM)
		return -EOPNOTSUPP;
	if (ret)
		ubase_err(udev,
			  "failed to query tm qset info, bus_ue_id = %u, ret = %d.\n",
			  bus_ue_id, ret);
	return ret;
}

int ubase_query_tm_pri(struct ubase_dev *udev, u16 bus_ue_id,
		       struct ubase_query_tm_pri_cmd *resp)
{
	struct ubase_query_tm_pri_cmd req = {0};
	struct ubase_cmd_buf in, out;
	int ret;

	req.bus_ue_id = cpu_to_le16(bus_ue_id);

	ubase_fill_inout_buf(&in, UBASE_OPC_QUERY_TM_PRI_INFO, true,
			     sizeof(req), &req);
	ubase_fill_inout_buf(&out, UBASE_OPC_QUERY_TM_PRI_INFO, false,
			     sizeof(*resp), resp);

	ret = __ubase_cmd_send_inout(udev, &in, &out);
	if (ret == -EPERM)
		return -EOPNOTSUPP;
	if (ret)
		ubase_err(udev,
			  "failed to query tm pri info, bus_ue_id = %u, ret = %d.\n",
			  bus_ue_id, ret);
	return ret;
}

int ubase_query_tm_pg(struct ubase_dev *udev, u16 bus_ue_id,
		      struct ubase_query_tm_pg_cmd *resp)
{
	struct ubase_query_tm_pg_cmd req = {0};
	struct ubase_cmd_buf in, out;
	int ret;

	req.bus_ue_id = cpu_to_le16(bus_ue_id);

	ubase_fill_inout_buf(&in, UBASE_OPC_QUERY_TM_PG_INFO, true,
			     sizeof(req), &req);
	ubase_fill_inout_buf(&out, UBASE_OPC_QUERY_TM_PG_INFO, false,
			     sizeof(*resp), resp);

	ret = __ubase_cmd_send_inout(udev, &in, &out);
	if (ret == -EPERM)
		return -EOPNOTSUPP;
	if (ret)
		ubase_err(udev,
			  "failed to query tm pg info, bus_ue_id = %u, ret = %d.\n",
			  bus_ue_id, ret);
	return ret;
}

int ubase_query_tm_port(struct ubase_dev *udev,
			struct ubase_query_tm_port_cmd *resp)
{
	struct ubase_query_tm_port_cmd req = {0};
	struct ubase_cmd_buf in, out;
	int ret;

	ubase_fill_inout_buf(&in, UBASE_OPC_QUERY_TM_PORT_INFO, true,
			     sizeof(req), &req);
	ubase_fill_inout_buf(&out, UBASE_OPC_QUERY_TM_PORT_INFO, false,
			     sizeof(*resp), resp);

	ret = __ubase_cmd_send_inout(udev, &in, &out);
	if (ret == -EPERM)
		return -EOPNOTSUPP;
	if (ret)
		ubase_err(udev, "failed to query tm port info, ret = %d.\n", ret);
	return ret;
}

/**
 * ubase_restore_initial_qset_qos() - restore initial tm qset configuration
 * @adev: auxiliary device
 *
 * This function is called to restore the initial configuration of the
 * corresponding module driver to prevent residual user configurations.
 *
 * Context: Process context. Takes and releases <lock>, BH-safe. Sleep.
 * Return: 0 on success, negative error code otherwise
 */
int ubase_restore_initial_qset_qos(struct auxiliary_device *adev)
{
	struct ubase_dev *udev;

	if (!adev)
		return -EINVAL;

	udev = __ubase_get_udev_by_adev(adev);
	return __ubase_restore_initial_qset_qos(udev);
}
EXPORT_SYMBOL(ubase_restore_initial_qset_qos);

/**
 * ubase_get_initial_qset_qos() - get initial tm qset configuration
 * @adev: auxiliary device
 *
 * The function is used to get initial tm qset configuration.
 *
 * Context: Any context.
 * Return: NULL if the adev is empty, otherwise the pointer to struct ubase_initial_qset_qos
 */
struct ubase_initial_qset_qos *
ubase_get_initial_qset_qos(struct auxiliary_device *adev)
{
	struct ubase_dev *udev;

	if (!adev)
		return NULL;

	udev = __ubase_get_udev_by_adev(adev);
	return &udev->qos.initial_qos;
}
EXPORT_SYMBOL(ubase_get_initial_qset_qos);
