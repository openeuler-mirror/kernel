/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hinic5_macsec_service.c
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   : macsec service code
 */
#define pr_fmt(fmt) KBUILD_MODNAME ": [MACsec]" fmt

#include "ossl_knl.h"

#include "hinic5_srv_nic.h"
#include "hinic5_nic_dev.h"

#include "macsec_mpu_cmd.h"
#include "hinic5_macsec_dfx.h"
#include "hinic5_macsec_common.h"
#include "hinic5_macsec_dev.h"

int himacsec_get_sci_port(u8 *port, u8 *cos, u64 sci, struct macsec_resource *macsec_res)
{
	himacsec_spec_s *spec = &macsec_res->spec;
	u8 port_cos = (u8)sci;

	*port = port_cos / (spec->max_port_sc);
	*cos = port_cos % (spec->max_port_sc);
	return 0;
}

/* Get sc corresponding to sci:
 * 1. Parse sci to get sc_index.
 * 2. Return corresponding address based on array subscript.
 */
struct himacsec_sc *himacsec_get_dev_sc(struct hinic5_nic_dev *nic_dev, crypt_direction_e direct)
{
	u32 port_id = 0;

	if (nic_dev->macsec_res)
		port_id = nic_dev->macsec_res->function_port;
	else
		macsec_err(nic_dev->lld_dev->dev, "%s: MACsec resource is NULL",
			   nic_dev->netdev->name);

	return get_g_macsec_port_res(direct, port_id);
}

/* Get sc corresponding to sci and verify it matches the parameter sci:
 * 1. Get sc content for the sci corresponding sc_index.
 * 2. Check if the sc is valid.
 */
struct himacsec_sc *himacsec_get_valid_dev_sc(struct hinic5_nic_dev *nic_dev,
					      u64 sci, crypt_direction_e direct)
{
	struct himacsec_sc *knl_sc = NULL;
	u64 priv_sci = 0; // The sci of target sc index'sc
	u32 sc_status = SC_STATUS_MAX;

	// 1. get sc
	knl_sc = himacsec_get_dev_sc(nic_dev, direct);
	if (!knl_sc)
		return NULL;

	sc_status = knl_sc->status.status.sc;
	priv_sci = knl_sc->info.sci;

	// 2. check sc
	if ((MACSEC_SC_STATUS_VALID(sc_status) == 0) || sci != priv_sci) {
		macsec_info(nic_dev->lld_dev->dev, "%s: Can not find kernel device sc, direct=0x%x, target sci=%llx, sc status=%d",
			    nic_dev->netdev->name, direct, priv_sci, sc_status);
		return NULL;
	}

	return knl_sc;
}

struct himacsec_sa *himacsec_get_dev_sa(struct hinic5_nic_dev *nic_dev, u64 sci,
					u8 an, crypt_direction_e direct)
{
	struct himacsec_sc *sc = NULL;
	u32 sa_index = 0;
	struct macsec_resource *macsec_res = nic_dev->macsec_res;

	if (!macsec_res) {
		macsec_err(nic_dev->lld_dev->dev, "%s: MACsec resource is NULL",
			   nic_dev->netdev->name);
		return NULL;
	}

	sc = himacsec_get_valid_dev_sc(nic_dev, sci, direct);
	if (!sc) {
		macsec_err(nic_dev->lld_dev->dev, "%s: Get kernel device sa failed, sc not found, direct=0x%x, sci=%llx, an=%d",
			   nic_dev->netdev->name, direct, sci, an);
		return NULL;
	}
	sa_index = an % macsec_res->spec.max_sa;
	return &sc->sa[sa_index];
}

struct himacsec_sa *himacsec_get_valid_dev_sa(struct hinic5_nic_dev *nic_dev,
					      u64 sci, u8 an, crypt_direction_e direct)
{
	struct himacsec_sa *sa = NULL;

	sa = himacsec_get_dev_sa(nic_dev, sci, an, direct);
	if (!sa)
		return NULL;

	if ((MACSEC_SA_STATUS_VALID(sa->status.status.sa) == 0) || an != sa->info.an) {
		macsec_info(nic_dev->lld_dev->dev, "%s: Get kernel device sa failed, direct=0x%x, sci=%llx, target an=%d, already exist an=%d",
			    nic_dev->netdev->name, direct, sci, an, sa->info.an);
		return NULL;
	}

	return sa;
}

int himacsec_del_sa(struct hinic5_nic_dev *nic_dev, u64 sci, u8 assoc_num, crypt_direction_e direct)
{
	macsec_sa_info_s sa_info = {0};
	struct net_device *netdev = nic_dev->netdev;
	struct himacsec_sa *priv_sa_ptr = NULL;
	macsec_mbox_sa_op_cmd_e sa_op = (direct == MACSEC_OUTBOUND)
					? MACSEC_CMD_ENC_SA_DELETE
					: MACSEC_CMD_DEC_SA_DELETE;
	int ret;

	priv_sa_ptr = himacsec_get_valid_dev_sa(nic_dev, sci, assoc_num, direct);
	if (!priv_sa_ptr) {
		macsec_err(nic_dev->lld_dev->dev, "%s: Delete sa failed, sa not found, direct=0x%x",
			   netdev->name, direct);
		return -ENOENT;
	}

	sa_info.sci = sci;
	sa_info.an = assoc_num;
	ret = himacsec_cmd_exec_sa_op(nic_dev->lld_dev, &sa_info, sa_op);
	if (ret != 0) {
		macsec_err(nic_dev->lld_dev->dev, "%s: Exec cmd sc delete failed, direct=0x%x, ret=%d",
			   netdev->name, direct, ret);
		return ret;
	}

	memset(priv_sa_ptr, 0, sizeof(struct himacsec_sa));
	macsec_info(nic_dev->lld_dev->dev, "%s: Delete sa success, direct=0x%x, sci=%llx, an=%d",
		    netdev->name, direct, sci, assoc_num);
	return ret;
}

int himacsec_add_sa(struct hinic5_nic_dev *nic_dev, macsec_sa_info_s *sa_info,
		    crypt_direction_e direct)
{
	struct net_device *netdev = nic_dev->netdev;
	struct himacsec_sa *priv_sa_ptr = NULL;
	macsec_mbox_sa_op_cmd_e sa_op = (direct == MACSEC_OUTBOUND)
					? MACSEC_CMD_ENC_SA_CREATE
					: MACSEC_CMD_DEC_SA_CREATE;
	int ret;

	priv_sa_ptr = himacsec_get_dev_sa(nic_dev, sa_info->sci, sa_info->an, direct);
	if (!priv_sa_ptr) {
		macsec_err(nic_dev->lld_dev->dev, "%s: Add sa failed, sc not found", netdev->name);
		return -EINVAL;
	}

	ret = himacsec_cmd_exec_sa_op(nic_dev->lld_dev, sa_info, sa_op);
	if (ret != 0) {
		macsec_err(nic_dev->lld_dev->dev, "%s: Exec cmd sa create failed, direct=0x%x, ret=%d",
			   netdev->name, direct, ret);
		return ret;
	}

	priv_sa_ptr->status.status.sa = SA_STATUS_CREATED;
	memcpy(&priv_sa_ptr->info, sa_info, sizeof(macsec_sa_info_s));
	macsec_info(nic_dev->lld_dev->dev, "%s: Add sa success, direct=0x%x, sci=%llx, an=%d",
		    netdev->name, direct, sa_info->sci, sa_info->an);
	himacsec_dfx_show_sa(nic_dev, sa_info, direct);
	return ret;
}

int himacsec_create_sc(struct hinic5_nic_dev *nic_dev, macsec_sc_info_s *sc_info,
		       crypt_direction_e direct)
{
	struct himacsec_sc *priv_sc_ptr = NULL;
	struct net_device *netdev = nic_dev->netdev;
	macsec_mbox_sc_op_cmd_e sc_op = (direct == MACSEC_OUTBOUND)
					? MACSEC_CMD_ENC_SC_CREATE
					: MACSEC_CMD_DEC_SC_CREATE;
	int ret;

	// 1. get target sc_index's data
	priv_sc_ptr = himacsec_get_dev_sc(nic_dev, direct);
	if (!priv_sc_ptr) {
		macsec_err(nic_dev->lld_dev->dev, "Add sc failed, priv_sc_ptr is NULL");
		return -EINVAL;
	}

	// 2. check target sc_idnex's has valid sc
	if (MACSEC_SC_STATUS_VALID(priv_sc_ptr->status.status.sc) != 0) {
		macsec_err(nic_dev->lld_dev->dev, "%s: Add sc failed, sc already exists, direct=0x%x",
			   netdev->name, direct);
		return -EEXIST;
	}

	// 3. create sc
	ret = himacsec_cmd_exec_sc_op(nic_dev->lld_dev, sc_info, sc_op);
	if (ret != 0) {
		macsec_err(nic_dev->lld_dev->dev, "%s: Exec cmd sc create failed, direct=0x%x, ret=%d",
			   netdev->name, direct, ret);
		return ret;
	}

	(void)memcpy(&priv_sc_ptr->info, sc_info, sizeof(macsec_sc_info_s));
	priv_sc_ptr->status.status.sc = SC_STATUS_CREATED;
	macsec_info(nic_dev->lld_dev->dev, "%s: Add encryption sc success, sci=%llx",
		    netdev->name, sc_info->sci);
	himacsec_dfx_show_sc(nic_dev, &priv_sc_ptr->info, direct);
	return ret;
}

int himacsec_destroy_sc(struct hinic5_nic_dev *nic_dev, u64 sci, crypt_direction_e direct)
{
	struct net_device *netdev = nic_dev->netdev;
	struct himacsec_sc *priv_sc_ptr = NULL;
	macsec_sc_info_s sc_info = {0};
	macsec_mbox_sc_op_cmd_e sc_op = (direct == MACSEC_OUTBOUND)
					? MACSEC_CMD_ENC_SC_DELETE
					: MACSEC_CMD_DEC_SC_DELETE;
	int ret;

	// 1. get and check SCI corresponding to scindex
	priv_sc_ptr = himacsec_get_valid_dev_sc(nic_dev, sci, direct);
	if (!priv_sc_ptr) {
		macsec_err(nic_dev->lld_dev->dev, "%s: Exec cmd sc delete failed, sc not found, direct=0x%x",
			   netdev->name, direct);
		return -EINVAL;
	}

	sc_info.sci = sci;
	ret = himacsec_cmd_exec_sc_op(nic_dev->lld_dev, &sc_info, sc_op);
	if (ret != 0) {
		macsec_err(nic_dev->lld_dev->dev, "%s: Exec cmd sc delete failed, direct=0x%x, ret=%d",
			   netdev->name, direct, ret);
		return ret;
	}

	memset(priv_sc_ptr, 0, sizeof(struct himacsec_sc));
	macsec_info(nic_dev->lld_dev->dev, "%s: Delete sc success, direct=0x%x, sci=%llx",
		    netdev->name, direct, sci);
	return 0;
}

int himacsec_set_sc(struct hinic5_nic_dev *nic_dev, macsec_sc_info_s *sc_info,
		    crypt_direction_e direct)
{
	struct himacsec_sc *priv_sc_ptr = NULL;
	struct net_device *netdev = nic_dev->netdev;
	macsec_mbox_sc_op_cmd_e sc_op = (direct == MACSEC_OUTBOUND)
					? MACSEC_CMD_ENC_SC_UPDATE
					: MACSEC_CMD_DEC_SC_UPDATE;
	int ret;

	// Retrieve the data from the drive for write-back preparation.
	priv_sc_ptr = himacsec_get_valid_dev_sc(nic_dev, sc_info->sci, direct);
	if (!priv_sc_ptr) {
		macsec_err(nic_dev->lld_dev->dev, "%s: Set sc failed, sc not found, direct=0x%x",
			   netdev->name, direct);
		return -EINVAL;
	}

	// execute command
	ret = himacsec_cmd_exec_sc_op(nic_dev->lld_dev, sc_info, sc_op);
	if (ret != 0) {
		macsec_err(nic_dev->lld_dev->dev, "%s: Exec cmd sc set failed, direct=0x%x, ret=%d",
			   netdev->name, direct, ret);
		return ret;
	}

	// Writing back data in the driver.
	memcpy(&priv_sc_ptr->info, sc_info, sizeof(macsec_sc_info_s));
	macsec_info(nic_dev->lld_dev->dev, "%s: Set sc success, direct=0x%x, sci=%llx",
		    netdev->name, direct, sc_info->sci);
	himacsec_dfx_show_sc(nic_dev, &priv_sc_ptr->info, direct);
	return ret;
}

int himacsec_update_sa_an(struct hinic5_nic_dev *nic_dev, struct himacsec_sc *sc,
			  u32 sa_index, u8 an, crypt_direction_e direct)
{
	struct himacsec_sc temp_sc = {0};
	int ret;

	memcpy(&temp_sc, sc, sizeof(struct himacsec_sc));
	temp_sc.info.sa_an[sa_index] = an;

	ret = himacsec_set_sc(nic_dev, &temp_sc.info, direct);
	if (ret != 0) {
		macsec_err(nic_dev->lld_dev->dev, "%s: Update sa_an failed, sci=0x%016llx, an=%d",
			   nic_dev->netdev->name, sc->info.sci, an);
	}
	return ret;
}

int himacsec_update_sc_in_sa_add(struct hinic5_nic_dev *nic_dev, u64 sci, u8 an,
				 crypt_direction_e direct)
{
	struct himacsec_sc *sc = NULL;
	u32 sa_index;
	int ret;
	struct macsec_resource *macsec_res = nic_dev->macsec_res;

	if (!macsec_res) {
		macsec_err(nic_dev->lld_dev->dev, "%s: MACsec resource is NULL",
			   nic_dev->netdev->name);
		return -EINVAL;
	}

	// sa_index ensure that the array does not exceed the boundary.
	sa_index = an % macsec_res->spec.max_sa;
	if (sa_index >= HIMACSEC_MAX_SA_IN_SC) {
		macsec_err(nic_dev->lld_dev->dev, "%s: Update sc info in sa operation failed, sa_index overflow, an=%d, max_sa=%d",
			   nic_dev->netdev->name, an, macsec_res->spec.max_sa);
		return -EINVAL;
	}

	sc = himacsec_get_valid_dev_sc(nic_dev, sci, direct);
	if (!sc) {
		macsec_err(nic_dev->lld_dev->dev, "%s: Update sc info in sa operation failed, sci=%llx not found",
			   nic_dev->netdev->name, sci);
		return -EINVAL;
	}

	// update sa_an
	ret = himacsec_update_sa_an(nic_dev, sc, sa_index, an, direct);
	if (ret != 0)
		return ret;
	sc->info.sa_an[sa_index] = an;
	return 0;
}

int himacsec_create_sa(struct hinic5_nic_dev *nic_dev, macsec_sa_info_s *sa,
		       crypt_direction_e direct)
{
	int ret;

	ret = himacsec_add_sa(nic_dev, sa, direct);
	if (ret != 0) {
		macsec_err(nic_dev->lld_dev->dev, "Create sa failed, ret=0x%x, direct=0x%x",
			   ret, direct);
		return ret;
	}

	ret = himacsec_update_sc_in_sa_add(nic_dev, sa->sci, sa->an, direct);
	if (ret != 0) {
		if (himacsec_del_sa(nic_dev, sa->sci, sa->an, direct) != 0) {
			macsec_err(nic_dev->lld_dev->dev, "%s: Fallback to delete sa data failed, direct=0x%x",
				   nic_dev->netdev->name, direct);
		}
	}
	return ret;
}

int himacsec_destroy_sa(struct hinic5_nic_dev *nic_dev, u64 sci, u8 assoc_num,
			crypt_direction_e direct)
{
	struct himacsec_sc *sc = NULL;
	u32 sa_index = 0;
	int ret;
	struct macsec_resource *macsec_res = nic_dev->macsec_res;

	if (!macsec_res) {
		macsec_err(nic_dev->lld_dev->dev, "%s: MACsec resource is NULL",
			   nic_dev->netdev->name);
		return -EINVAL;
	}

	ret = himacsec_del_sa(nic_dev, sci, assoc_num, direct);
	if (ret != 0)
		return ret;

	// 清理 sa_an
	sc = himacsec_get_valid_dev_sc(nic_dev, sci, direct);
	if (!sc) {
		macsec_err(nic_dev->lld_dev->dev, "%s: Del sa, update sc failed, direct=0x%x, sci=%llx not found",
			   nic_dev->netdev->name, direct, sci);
		return -EINVAL;
	}

	// sa_index ensure that the array does not exceed the boundary.
	sa_index = assoc_num % macsec_res->spec.max_sa;
	if (sa_index >= HIMACSEC_MAX_SA_IN_SC) {
		macsec_err(nic_dev->lld_dev->dev, "%s: sa_index overflow, direct=0x%x, an=%d, max_sa=%d",
			   nic_dev->netdev->name, direct, assoc_num, macsec_res->spec.max_sa);
		return -EINVAL;
	}

	ret = himacsec_update_sa_an(nic_dev, sc, sa_index, 0, direct);
	if (ret != 0)
		return ret;

	sc->info.sa_an[sa_index] = 0;
	return 0;
}
