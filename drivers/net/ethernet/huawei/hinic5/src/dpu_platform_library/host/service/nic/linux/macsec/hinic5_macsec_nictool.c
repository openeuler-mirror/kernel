/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hinic5_macsec_nictool.c
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   : macsec nictool interface
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": [MACsec]" fmt

#include <linux/semaphore.h>

#include "hinic5_lld.h"
#include "hinic5_mt.h"

#include "macsec_pub_cmd.h"
#include "nic_pub_cmd.h"
#include "hinic5_macsec_common.h"
#include "hinic5_macsec_dfx.h"

static int himacsec_cmd_check_param_buf(const void *buf, u32 buf_size, u32 exp_buf_size)
{
	if (!buf || buf_size != exp_buf_size) {
		pr_err("Buffer in or out can not be NULL when exec macsec cmd, buf size=%d, exp size=%d",
		       buf_size, exp_buf_size);
		return -EINVAL;
	}
	return 0;
}

int himacsec_fill_enc_sa(struct hinic5_nic_dev *nic_dev, struct himacsec_sc *enc_sc,
			 struct himacsec_sa *tar_sa, u8 *sa_cnt, u32 cmd_type)
{
	struct himacsec_sa enc_sa = {0};
	u8 sa_index = 0;
	u8 an = 0; // There is no an in the sa table, it needs to be rewritten back
	int index;
	int ret = 0;

	for (index = 0; index < nic_dev->macsec_res->spec.max_sa; index++) {
		enc_sa = enc_sc->sa[index];
		an = enc_sa.info.an;
		if (MACSEC_SA_STATUS_VALID(enc_sa.status.status.sa) == 0)
			continue;
		if (cmd_type == MACSEC_TOOL_OP_DUMP) {
			ret = himacsec_cmd_exec_sa_op(nic_dev->lld_dev,
						      &enc_sa.info,
						      MACSEC_CMD_ENC_SA_GET_INFO);
			if (ret != 0) {
				macsec_err(nic_dev->lld_dev->dev, "%s: Exec cmd dump encryption sa config failed, ret=%d",
					   nic_dev->netdev->name, ret);
				return ret;
			}
			enc_sa.info.an = an;
		}
		tar_sa[sa_index++] = enc_sa;
	}
	*sa_cnt = sa_index;
	return ret;
}

int himacsec_fill_dec_sa(struct hinic5_nic_dev *nic_dev, struct himacsec_sc *dec_sc,
			 struct himacsec_sa *tar_sa, u8 *sa_cnt, u32 cmd_type)
{
	struct himacsec_sa dec_sa = {0};
	u8 an = 0; // There is no an in the sa table, it needs to be rewritten back
	u8 sa_index = 0;
	int index;
	int ret = 0;

	for (index = 0; index < nic_dev->macsec_res->spec.max_sa; index++) {
		dec_sa = dec_sc->sa[index];
		an = dec_sa.info.an;
		if (MACSEC_SA_STATUS_VALID(dec_sa.status.status.sa) == 0)
			continue;
		if (cmd_type == MACSEC_TOOL_OP_DUMP) {
			ret = himacsec_cmd_exec_sa_op(nic_dev->lld_dev,
						      &dec_sa.info,
						      MACSEC_CMD_DEC_SA_GET_INFO);
			if (ret != 0) {
				macsec_err(nic_dev->lld_dev->dev, "%s: Exec cmd dump decryption sa config failed, ret=%d",
					   nic_dev->netdev->name, ret);
				return ret;
			}
			dec_sa.info.an = an;
		}
		tar_sa[sa_index++] = dec_sa;
	}
	*sa_cnt = sa_index;
	return ret;
}

int macsec_get_enc_sc_info(struct hinic5_nic_dev *nic_dev, struct himacsec_sc *temp_sc,
			   struct himacsec_cmd_list_sc_buf *cur_sc_buf, u32 cmd_type)
{
	int ret = 0;

	if (cmd_type == MACSEC_TOOL_OP_DUMP) {
		ret = himacsec_cmd_exec_sc_op(nic_dev->lld_dev, &temp_sc->info,
					      MACSEC_CMD_ENC_SC_GET_INFO);
		if (ret != 0) {
			macsec_err(nic_dev->lld_dev->dev, "Dump cmd failed ret=%d, fetch tx sc info fail.",
				   ret);
			return ret;
		}
	}
	ret = himacsec_fill_enc_sa(nic_dev, temp_sc, cur_sc_buf->sc.sa,
				   &cur_sc_buf->sa_cnt, cmd_type);
	if (ret != 0) {
		macsec_err(nic_dev->lld_dev->dev, "Dump cmd failed ret=%d, fetch tx sa info fail.",
			   ret);
		return ret;
	}
	cur_sc_buf->sc.info = temp_sc->info;

	return 0;
}

int macsec_get_dec_sc_info(struct hinic5_nic_dev *nic_dev, struct himacsec_sc *temp_sc,
			   struct himacsec_cmd_list_sc_buf *cur_sc_buf, u32 cmd_type)
{
	int ret = 0;

	if (cmd_type == MACSEC_TOOL_OP_DUMP) {
		ret = himacsec_cmd_exec_sc_op(nic_dev->lld_dev, &temp_sc->info,
					      MACSEC_CMD_DEC_SC_GET_INFO);
		if (ret != 0) {
			macsec_err(nic_dev->lld_dev->dev, "Dump cmd failed ret=%d, fetch rx sc info fail.",
				   ret);
			return ret;
		}
	}
	ret = himacsec_fill_dec_sa(nic_dev, temp_sc, cur_sc_buf->sc.sa,
				   &cur_sc_buf->sa_cnt, cmd_type);
	if (ret != 0) {
		macsec_err(nic_dev->lld_dev->dev, "Dump cmd failed ret=%d, fetch rx sa info fail.",
			   ret);
		return ret;
	}
	cur_sc_buf->sc.info = temp_sc->info;

	return 0;
}

int himacsec_fill_config(struct hinic5_nic_dev *nic_dev, struct himacsec_cmd_list_out *cmd_out,
			 u32 cmd_type)
{
	struct himacsec_cmd_list_sc_buf *enc_sc_buf =
					(struct himacsec_cmd_list_sc_buf *)cmd_out->enc_sc_buf;
	struct himacsec_cmd_list_sc_buf *dec_sc_buf =
					(struct himacsec_cmd_list_sc_buf *)cmd_out->dec_sc_buf;
	struct himacsec_cmd_list_sc_buf *cur_sc_buf = NULL;
	struct himacsec_sc *temp_sc = NULL;
	u32 enc_sc_cnt = 0;
	u32 dec_sc_cnt = 0;
	u32 index;
	u32 port_id = nic_dev->macsec_res->function_port;
	int ret = 0;

	for (index = 0; index < nic_dev->macsec_res->spec.max_port_sc; index++) {
		// Get encryption direction macsec config
		temp_sc = get_g_macsec_port_res(MACSEC_OUTBOUND, port_id);
		if (!temp_sc && (MACSEC_SC_STATUS_VALID(temp_sc->status.status.sc) != 0)) {
			/* Calculate the next address to receive sc parameters */
			cur_sc_buf = enc_sc_buf + enc_sc_cnt;
			ret = macsec_get_enc_sc_info(nic_dev, temp_sc, cur_sc_buf, cmd_type);
			if (ret != 0) {
				macsec_err(nic_dev->lld_dev->dev, "Dump cmd failed ret=%d, get tx macsec info fail.",
					   ret);
				return ret;
			}
			enc_sc_cnt++;
		}

		// Get decryption direction macsec config
		temp_sc = get_g_macsec_port_res(MACSEC_INBOUND, port_id);
		if (temp_sc && (MACSEC_SC_STATUS_VALID(temp_sc->status.status.sc) != 0)) {
			/* Calculate the next address to receive sc parameters */
			cur_sc_buf = dec_sc_buf + dec_sc_cnt;
			ret = macsec_get_dec_sc_info(nic_dev, temp_sc, cur_sc_buf, cmd_type);
			if (ret != 0) {
				macsec_err(nic_dev->lld_dev->dev, "Dump cmd failed ret=%d, get rx macsec info fail.",
					   ret);
				return ret;
			}
			dec_sc_cnt++;
		}
	}

	cmd_out->enc_sc_cnt = enc_sc_cnt;
	cmd_out->dec_sc_cnt = dec_sc_cnt;
	return 0;
}

int himacsec_fill_mib_sc(struct hinic5_nic_dev *nic_dev, struct himacsec_cmd_mib_out *cmd_out,
			 u64 sci)
{
	struct himacsec_sc *enc_sc = NULL;
	struct himacsec_sc *dec_sc = NULL;
	int ret;

	// 1. Parameter validation
	enc_sc = himacsec_get_valid_dev_sc(nic_dev, sci, MACSEC_OUTBOUND);
	dec_sc = himacsec_get_valid_dev_sc(nic_dev, sci, MACSEC_INBOUND);
	if (!enc_sc && !dec_sc) { // SCI does not exist
		macsec_err(nic_dev->lld_dev->dev, "%s: Exec cmd querying sc mib failed, sci=%llx not found",
			   nic_dev->netdev->name, sci);
		return -EINVAL;
	}

	// 2. Send query request
	ret = himacsec_cmd_exec_mib_sc(nic_dev->lld_dev, cmd_out, sci);
	if (ret != 0) {
		macsec_err(nic_dev->lld_dev->dev, "%s: Exec cmd querying sc mib failed, sci=%llx, ret=%d",
			   nic_dev->netdev->name, sci, ret);
		return ret;
	}

	return ret;
}

int himacsec_fill_mib_port(struct hinic5_nic_dev *nic_dev, struct himacsec_cmd_mib_out *cmd_out)
{
	int ret;

	ret = himacsec_cmd_exec_mib_port(nic_dev->lld_dev, cmd_out);
	if (ret != 0)
		macsec_err(nic_dev->lld_dev->dev, "%s: Exec cmd query port mib failed, ret=%d",
			   nic_dev->netdev->name, ret);

	return ret;
}

/* hinicadmdfx5 macsec -o list -i enp133s0f1
 * Query all macsec configuration information for the current port in memory
 */
int macsec_cmd_list(struct hinic5_nic_dev *nic_dev, const void *buf_in,
		    u32 in_size, void *buf_out, u32 *out_size)
{
	int ret = -EINVAL;
	struct himacsec_cmd_in *cmd_in = (struct himacsec_cmd_in *)buf_in;
	struct himacsec_cmd_list_out *cmd_out = (struct himacsec_cmd_list_out *)buf_out;

	// 1. Parameter validation
	if (!nic_dev->macsec_res) {
		macsec_err(nic_dev->lld_dev->dev, "Macsec resource is NULL");
		return -EINVAL;
	}

	if ((himacsec_cmd_check_param_buf(buf_in, in_size, sizeof(struct himacsec_cmd_hdr)) != 0) ||
	    (himacsec_cmd_check_param_buf(buf_out, *out_size,
					  sizeof(struct himacsec_cmd_list_out)) != 0)) {
		return -EINVAL;
	}

	// 2. Parameter assignment
	ret = himacsec_fill_config(nic_dev, cmd_out, cmd_in->hdr.cmd_type);
	if (ret != 0)
		macsec_err(nic_dev->lld_dev->dev,
			   "Cmd list/dump macsec config exec failed, ret=%d", ret);

	return ret;
}

/* hinicadmdfx5 macsec -o mib -i enp133s0f1 -t [sc -s <sci> | port]
 * Query all macsec mib information
 */
int macsec_cmd_mib(struct hinic5_nic_dev *nic_dev, const void *buf_in,
		   u32 in_size, void *buf_out, u32 *out_size)
{
	int ret = -EINVAL;
	struct himacsec_cmd_in *cmd_in = (struct himacsec_cmd_in *)buf_in;
	struct himacsec_cmd_mib_in *mib_in = NULL;
	struct himacsec_cmd_mib_out *cmd_out = (struct himacsec_cmd_mib_out *)buf_out;
	u32 exp_in_size = sizeof(struct himacsec_cmd_hdr) + sizeof(struct himacsec_cmd_mib_in);

	// 1. Parameter validation
	if (!nic_dev->macsec_res) {
		macsec_err(nic_dev->lld_dev->dev, "Macsec resource is NULL");
		return -EINVAL;
	}

	if ((himacsec_cmd_check_param_buf(buf_in, in_size, exp_in_size) != 0) ||
	    (himacsec_cmd_check_param_buf(buf_out, *out_size,
					  sizeof(struct himacsec_cmd_mib_out)) != 0)) {
		return -EINVAL;
	}

	// 2. Parse input parameters
	mib_in = (struct himacsec_cmd_mib_in *)cmd_in->buf;
	if (mib_in->mib_type == HIMACSEC_TOOL_MIB_TYPE_PORT) {
		ret = himacsec_fill_mib_port(nic_dev, cmd_out);
	} else if (mib_in->mib_type == HIMACSEC_TOOL_MIB_TYPE_SC) {
		ret = himacsec_fill_mib_sc(nic_dev, cmd_out, mib_in->sci);
	} else {
		macsec_err(nic_dev->lld_dev->dev, "Unknown mib type %d", mib_in->mib_type);
		return -EINVAL;
	}

	if (ret != 0)
		macsec_err(nic_dev->lld_dev->dev, "Cmd querying macsec mib failed, ret=%d", ret);
	return ret;
}

int macsec_cmd_flush(struct hinic5_nic_dev *nic_dev, const void *buf_in,
		     u32 in_size, void *buf_out, u32 *out_size)
{
	int ret, index;
	struct himacsec_cmd_in *cmd_in = (struct himacsec_cmd_in *)buf_in;
	tag_macsec_flush_cmd_s flush_cmd = {0};
	struct macsec_resource *macsec_res = nic_dev->macsec_res;
	struct himacsec_sc *enc_sc = NULL;
	struct himacsec_sc *dec_sc = NULL;

	if (!macsec_res) {
		macsec_err(nic_dev->lld_dev->dev, "%s: MACsec resource is NULL",
			   nic_dev->netdev->name);
		return -EINVAL;
	}

	// 1. Parameter validation
	if (himacsec_cmd_check_param_buf(buf_in, in_size, sizeof(struct himacsec_cmd_hdr)) != 0)
		return -EINVAL;

	macsec_info(nic_dev->lld_dev->dev, "MACsec flush process, obj_type=0x%x",
		    cmd_in->hdr.obj_type);

	flush_cmd.op_code = MACSEC_CMD_FLUSH_SC_OP;
	ret = himacsec_cmd_exec_flush(nic_dev->lld_dev, &flush_cmd);
	if (ret != 0)
		macsec_err(nic_dev->lld_dev->dev, "MACsec flush failed, ret=0x%x", ret);

	enc_sc = himacsec_get_dev_sc(nic_dev, MACSEC_OUTBOUND);
	dec_sc = himacsec_get_dev_sc(nic_dev, MACSEC_INBOUND);
	/* Clear driver internal data */
	for (index = 0; index < macsec_res->spec.max_port_sc; index++) {
		memset(enc_sc, 0, sizeof(struct himacsec_sc));
		memset(dec_sc, 0, sizeof(struct himacsec_sc));
	}
	return ret;
}

int himacsec_nictool_add_sc(struct hinic5_nic_dev *nic_dev, const struct himacsec_cmd_in *cmd_in,
			    u32 in_size, crypt_direction_e direct)
{
	int ret = 0;
	macsec_sc_info_s *sc = (macsec_sc_info_s *)cmd_in->buf;
	u32 exp_in_size = sizeof(struct himacsec_cmd_hdr) + sizeof(macsec_sc_info_s);

	if (in_size != exp_in_size) {
		macsec_err(nic_dev->lld_dev->dev, "Add encryption cmd buffer invalid, in size=0x%x, exp_size=0x%x",
			   in_size, exp_in_size);
		return -EINVAL;
	}

	ret = himacsec_create_sc(nic_dev, sc, direct);
	if (ret != 0)
		macsec_err(nic_dev->lld_dev->dev, "Add encryption cmd fail, ret=%d", ret);

	return ret;
}

int himacsec_nictool_add_sa(struct hinic5_nic_dev *nic_dev, const struct himacsec_cmd_in *cmd_in,
			    u32 in_size, crypt_direction_e direct)
{
	macsec_sa_info_s *sa = (macsec_sa_info_s *)cmd_in->buf;
	u32 exp_in_size = sizeof(struct himacsec_cmd_hdr) + sizeof(macsec_sa_info_s);
	struct macsec_resource *macsec_res = nic_dev->macsec_res;

	if (in_size != exp_in_size) {
		macsec_err(nic_dev->lld_dev->dev, "Add sa failed, size error, in size=0x%x, exp_size=0x%x",
			   in_size, exp_in_size);
		return -EINVAL;
	}

	// SM4 algorithm needs to validate whether feature negotiation result is supported
	if (sa->current_crypto_algo == HIMACSEC_CRYPTO_ALGO_SM4 &&
	    (macsec_res->himacsec_feature[0] & (u64)MACSEC_F_SUPPORT_SM4) == 0) {
		macsec_err(nic_dev->lld_dev->dev, "Add sa failed, unsupported algorithm(0x%x)",
			   sa->current_crypto_algo);
		return -EINVAL;
	}

	// Need to display configuration of RX side next_pn table
	if (sa->next_pn < sa->replay_window) {
		macsec_err(nic_dev->lld_dev->dev, "Add sa failed, replay window(0x%x) is over next pn(0x%llx)",
			   sa->replay_window, sa->next_pn);
		return -EINVAL;
	}
	sa->lowest_pn = sa->next_pn - sa->replay_window;

	return himacsec_create_sa(nic_dev, sa, direct);
}

int macsec_cmd_add(struct hinic5_nic_dev *nic_dev, const void *buf_in, u32 in_size,
		   void *buf_out, u32 *out_size)
{
	struct himacsec_cmd_in *cmd_in = (struct himacsec_cmd_in *)buf_in;
	himacsec_tool_obj_e obj = HIMACSEC_TOOL_OBJ_MAX;
	int ret;

	// 1. Parameter validation
	if (!nic_dev->macsec_res) {
		macsec_err(nic_dev->lld_dev->dev, "Macsec resource is NULL");
		return -EINVAL;
	}

	if (!buf_in) {
		macsec_err(nic_dev->lld_dev->dev, "Buffer in can not be NULL when exec macsec add cmd");
		return -EINVAL;
	}

	obj = cmd_in->hdr.obj_type; // Type to be added
	switch (obj) {
	case HIMACSEC_TOOL_OBJ_ENC_SC:
		ret = himacsec_nictool_add_sc(nic_dev, cmd_in, in_size, MACSEC_OUTBOUND);
		break;
	case HIMACSEC_TOOL_OBJ_DEC_SC:
		ret = himacsec_nictool_add_sc(nic_dev, cmd_in, in_size, MACSEC_INBOUND);
		break;
	case HIMACSEC_TOOL_OBJ_ENC_SA:
		ret = himacsec_nictool_add_sa(nic_dev, cmd_in, in_size, MACSEC_OUTBOUND);
		break;
	case HIMACSEC_TOOL_OBJ_DEC_SA:
		ret = himacsec_nictool_add_sa(nic_dev, cmd_in, in_size, MACSEC_INBOUND);
		break;
	default:
		macsec_err(nic_dev->lld_dev->dev, "Unknown macsec object type:%d ", obj);
		ret = -EINVAL;
		break;
	}
	return ret;
}

int macsec_cmd_del(struct hinic5_nic_dev *nic_dev, const void *buf_in, u32 in_size,
		   void *buf_out, u32 *out_size)
{
	struct himacsec_cmd_in *cmd_in = (struct himacsec_cmd_in *)buf_in;
	u32 exp_in_size = sizeof(struct himacsec_cmd_del_in) + sizeof(struct himacsec_cmd_hdr);
	himacsec_tool_obj_e obj = HIMACSEC_TOOL_OBJ_MAX;
	struct himacsec_cmd_del_in *param = NULL;
	int ret = 0;

	if (!buf_in || exp_in_size != in_size) {
		macsec_err(nic_dev->lld_dev->dev, "Buffer in invalid when exec macsec del cmd, in_size=%d, exp_size=%d",
			   in_size, exp_in_size);
		return -EINVAL;
	}

	param = (struct himacsec_cmd_del_in *)cmd_in->buf;
	obj = cmd_in->hdr.obj_type;

	switch (obj) {
	case HIMACSEC_TOOL_OBJ_ENC_SC:
		ret = himacsec_destroy_sc(nic_dev, param->sci, MACSEC_OUTBOUND);
		break;
	case HIMACSEC_TOOL_OBJ_DEC_SC:
		ret = himacsec_destroy_sc(nic_dev, param->sci, MACSEC_INBOUND);
		break;
	case HIMACSEC_TOOL_OBJ_ENC_SA:
		ret = himacsec_destroy_sa(nic_dev, param->sci, param->an, MACSEC_OUTBOUND);
		break;
	case HIMACSEC_TOOL_OBJ_DEC_SA:
		ret = himacsec_destroy_sa(nic_dev, param->sci, param->an, MACSEC_INBOUND);
		break;
	default:
		macsec_err(nic_dev->lld_dev->dev, "Unknown macsec object type:%d ", obj);
		ret = -EINVAL;
		break;
	}
	return ret;
}

int himacsec_cmd_set_enc_sc(struct hinic5_nic_dev *nic_dev, struct himacsec_cmd_in *cmd_in,
			    u32 in_size)
{
	struct himacsec_sc *priv_sc_ptr = NULL;
	struct himacsec_cmd_set_sc_in *param = NULL;
	u32 exp_in_size = sizeof(struct himacsec_cmd_set_sc_in) + sizeof(struct himacsec_cmd_hdr);
	macsec_sc_info_s enc_sc = {0};
	struct macsec_resource *macsec_res = nic_dev->macsec_res;

	if (!macsec_res) {
		macsec_err(nic_dev->lld_dev->dev, "%s: MACsec resource is NULL",
			   nic_dev->netdev->name);
		return -EINVAL;
	}

	param = (struct himacsec_cmd_set_sc_in *)cmd_in->buf;
	if (!param || exp_in_size != in_size) {
		macsec_err(nic_dev->lld_dev->dev, "Buffer in invalid when exec macsec set cmd, in_size=%d, exp_size=%d",
			   in_size, exp_in_size);
		return -EINVAL;
	}

	priv_sc_ptr = himacsec_get_valid_dev_sc(nic_dev, param->sci, MACSEC_OUTBOUND);
	if (!priv_sc_ptr) {
		macsec_err(nic_dev->lld_dev->dev, "%s: Set encryption sc failed, sc not found",
			   nic_dev->netdev->name);
		return -EINVAL;
	}

	memcpy(&enc_sc, &priv_sc_ptr->info, sizeof(macsec_sc_info_s));
	// Use sc copy data, driver internal data will be automatically updated after update
	if ((param->set_flag_bitmap & HIMACSEC_SET_SC_ENCODING_SA_BIT_VAL) != 0) {
		// sa validation
		if (!himacsec_get_valid_dev_sa(nic_dev, param->sci,
					       param->sc.encoding_sa, MACSEC_OUTBOUND)) {
			macsec_err(nic_dev->lld_dev->dev, "%s: Update encodingsa failed, sa '%d' invalid",
				   nic_dev->netdev->name, param->sc.encoding_sa);
			return -EINVAL;
		}
		// Convert an to sa_index
		enc_sc.encoding_sa = param->sc.encoding_sa % macsec_res->spec.max_sa;
	}

	if ((param->set_flag_bitmap & HIMACSEC_SET_SC_PROTECT_FRAMES_BIT_VAL) != 0)
		enc_sc.protect_frames = param->sc.protect_frames;

	if ((param->set_flag_bitmap & HIMACSEC_SET_SC_PROTECTION_MODE_BIT_VAL) != 0)
		enc_sc.protection_mode = param->sc.protection_mode;

	return himacsec_set_sc(nic_dev, &enc_sc, MACSEC_OUTBOUND);
}

int himacsec_cmd_set_dec_sc(struct hinic5_nic_dev *nic_dev, struct himacsec_cmd_in *cmd_in,
			    u32 in_size)
{
	struct himacsec_sc *priv_sc_ptr = NULL;
	struct himacsec_cmd_set_sc_in *param = NULL;
	u32 exp_in_size = sizeof(struct himacsec_cmd_set_sc_in) + sizeof(struct himacsec_cmd_hdr);
	macsec_sc_info_s dec_sc = {0};

	param = (struct himacsec_cmd_set_sc_in *)cmd_in->buf;
	if (!param || exp_in_size != in_size) {
		macsec_err(nic_dev->lld_dev->dev, "Buffer in invalid when exec macsec set cmd, in_size=%d, exp_size=%d",
			   in_size, exp_in_size);
		return -EINVAL;
	}

	priv_sc_ptr = himacsec_get_valid_dev_sc(nic_dev, param->sci, MACSEC_INBOUND);
	if (!priv_sc_ptr) {
		macsec_err(nic_dev->lld_dev->dev, "%s: Set decryption sc failed, sc not found",
			   nic_dev->netdev->name);
		return -EINVAL;
	}
	memcpy(&dec_sc, &priv_sc_ptr->info, sizeof(macsec_sc_info_s));

	if ((param->set_flag_bitmap & HIMACSEC_SET_SC_VALIDATE_FRAMES_BIT_VAL) != 0)
		dec_sc.validate_frames = param->sc.validate_frames;
	return himacsec_set_sc(nic_dev, &dec_sc, MACSEC_INBOUND);
}

int macsec_cmd_set(struct hinic5_nic_dev *nic_dev, const void *buf_in,
		   u32 in_size, void *buf_out, u32 *out_size)
{
	struct himacsec_cmd_in *cmd_in = (struct himacsec_cmd_in *)buf_in;
	himacsec_tool_obj_e obj = HIMACSEC_TOOL_OBJ_MAX;
	int ret;

	if (!buf_in) {
		macsec_err(nic_dev->lld_dev->dev, "Buffer in is NULL when exec macsec set cmd");
		return -EINVAL;
	}

	obj = cmd_in->hdr.obj_type;
	if (obj == HIMACSEC_TOOL_OBJ_ENC_SC) {
		ret = himacsec_cmd_set_enc_sc(nic_dev, cmd_in, in_size);
	} else if (obj == HIMACSEC_TOOL_OBJ_DEC_SC) {
		ret = himacsec_cmd_set_dec_sc(nic_dev, cmd_in, in_size);
	} else {
		macsec_err(nic_dev->lld_dev->dev, "Unknown macsec object type:%d ", obj);
		ret = -EINVAL;
	}

	return ret;
}
