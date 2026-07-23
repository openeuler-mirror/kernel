// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#include "zxic_common.h"

#include "dpp_reg.h"
#include "dpp_se_api.h"
#include "dpp_etcam.h"
#include "dpp_dev.h"
#include "dpp_stat4k_reg.h"

#define DPP_ETCAM_OPR_WR (1)
#define DPP_ETCAM_OPR_RD (2)
#define DPP_ETCAM_OPR_UNLOAD (3)
#define DPP_ETCAM_OPR_VBIT (4)

#define TBLID_CFG_SETP (8)
#define BADDR_CFG_SETP (4)

struct dpp_etcam_entry_vld_t g_etcam_vld_info[DPP_DEV_CHANNEL_MAX][DPP_ETCAM_BLOCK_NUM]
					     [DPP_ETCAM_RAM_DEPTH] = { { { { 0 } } } };
#define GET_ETCAM_VLD_INFO(dev_id, block_id, block_index) \
	(g_etcam_vld_info[dev_id][block_id] + block_index)

#if ZXIC_REAL("IN_FUNC")
DPP_STATUS dpp_etcam_dm_to_xy(struct dpp_etcam_entry_t *p_dm, struct dpp_etcam_entry_t *p_xy,
			      u32 len)
{
	u32 i = 0;

	ZXIC_COMM_CHECK_POINT(p_dm);
	ZXIC_COMM_CHECK_POINT(p_xy);
	ZXIC_COMM_CHECK_INDEX(len, 0, DPP_ETCAM_WIDTH_MAX / 8);
	ZXIC_COMM_ASSERT(p_dm->p_data && p_dm->p_mask && p_xy->p_data && p_xy->p_mask);

	for (i = 0; i < len; i++) {
		p_xy->p_data[i] = ZXIC_COMM_DM_TO_X(p_dm->p_data[i], p_dm->p_mask[i]);
		p_xy->p_mask[i] = ZXIC_COMM_DM_TO_Y(p_dm->p_data[i], p_dm->p_mask[i]);
	}

	return DPP_OK;
}
DPP_STATUS dpp_etcam_xy_to_dm(struct dpp_etcam_entry_t *p_dm, struct dpp_etcam_entry_t *p_xy,
			      u32 len)
{
	u32 i = 0;

	ZXIC_COMM_CHECK_POINT(p_dm);
	ZXIC_COMM_CHECK_POINT(p_xy);
	ZXIC_COMM_CHECK_INDEX(len, 0, DPP_ETCAM_WIDTH_MAX / 8);
	ZXIC_COMM_ASSERT(p_dm->p_data && p_dm->p_mask && p_xy->p_data && p_xy->p_mask);

	for (i = 0; i < len; i++) {
		p_dm->p_data[i] = ZXIC_COMM_XY_TO_DATA(
			p_xy->p_data[i], p_xy->p_mask[i]); /* valid only when mask is 0 */
		p_dm->p_mask[i] = ZXIC_COMM_XY_TO_MASK(p_xy->p_data[i], p_xy->p_mask[i]);
	}

	return DPP_OK;
}
u32 dpp_etcam_ind_data_reg_opr_mask_get(u32 mask)
{
	u32 i = 0;
	u32 reg_mask = 0;

	ZXIC_COMM_CHECK_INDEX(mask, 0, 0xff);

	for (i = 0; i < DPP_ETCAM_RAM_NUM; i++) {
		if ((mask >> i) & 0x1)
			reg_mask |= ((u32)0x7 << ((i / 2) * 5 + (i % 2) * 2));
	}

	return reg_mask;
}
DPP_STATUS dpp_etcam_ind_data_set(struct dpp_dev_t *dev, u32 wr_mask, u8 *p_data)
{
	DPP_STATUS rc = DPP_OK;
	u32 i = 0;
	u32 offset = 0;
	u32 reg_mask = 0;
	u8 *p_temp = NULL;
	u8 buff[DPP_ETCAM_WIDTH_MAX / 8] = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), wr_mask, 0, DPP_ETCAM_WR_MASK_MAX);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_data);

	p_temp = p_data;

	/* 160bit key: high 80bit in tcam_ram1, low 80bit in tcam_ram0, and so on. */
	for (i = 0; i < DPP_ETCAM_RAM_NUM; i++) {
		offset = i * ((u32)DPP_ETCAM_WIDTH_MIN / 8);

		if ((wr_mask >> ((DPP_ETCAM_RAM_NUM - 1 - i) % 32)) & 0x1) {
			ZXIC_COMM_MEMCPY(buff + offset, p_temp, DPP_ETCAM_WIDTH_MIN / 8);
			p_temp += DPP_ETCAM_WIDTH_MIN / 8;
		}
	}

	zxic_comm_swap(buff, DPP_ETCAM_WIDTH_MAX / 8);

	/* get ind data reg operate mask, 20bit */
	reg_mask = dpp_etcam_ind_data_reg_opr_mask_get(wr_mask);

	/* cpu_ind_wdat0 reg is for lowest 32bit data. */
	for (i = 0; i < (DPP_ETCAM_WIDTH_MAX / 32); i++) {
		if ((reg_mask >> (DPP_ETCAM_WIDTH_MAX / 32 - 1 - i)) & 0x1) {
			rc = dpp_reg_write(dev, STAT_ETCAM_CPU_IND_WDAT19r - i, 0, 0,
					   (buff + i * sizeof(u32)));
			ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_reg_write");
		}
	}

	return DPP_OK;
}
DPP_STATUS dpp_etcam_ind_cmd_set(struct dpp_dev_t *dev, u32 addr, u32 block_idx, u32 data_or_mask,
				 u32 wr_mask, u32 opr_type, u32 tacm_reg_flag, u32 row_mask_flag,
				 u32 vben, u32 vbit)
{
	DPP_STATUS rc = DPP_OK;
	struct dpp_stat_etcam_cpu_ind_ctrl_tmp0_t ind_cmd = { 0 };
	struct dpp_stat_etcam_cpu_ind_ctrl_tmp1_t ind_cmd_1 = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), addr, 0, DPP_ETCAM_RAM_DEPTH - 1);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), block_idx, 0, DPP_ETCAM_BLOCK_NUM - 1);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), data_or_mask, 0, 1);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), wr_mask, 0, DPP_ETCAM_WR_MASK_MAX);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), opr_type, 1, 4);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), tacm_reg_flag, 0, 1);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), row_mask_flag, 0, 1);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), vben, 0, 1);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), vbit, 0, 0xff);

	ind_cmd_1.row_or_col_msk = row_mask_flag;
	ind_cmd_1.vben = vben;
	ind_cmd_1.vbit = vbit;

	rc = dpp_reg_write(dev, STAT_ETCAM_CPU_IND_CTRL_TMP1r, 0, 0, &ind_cmd_1);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_reg_write");

	/* opr_type: 1-write, 2-read, 3-unload */
	switch (opr_type) {
	case DPP_ETCAM_OPR_RD: {
		ind_cmd.rd_wr = 1;
	} break;

	case DPP_ETCAM_OPR_WR: {
		ind_cmd.rd_wr = 0;
		ind_cmd.wr_mode = wr_mask;
	} break;

	case DPP_ETCAM_OPR_UNLOAD: {
		ind_cmd.flush = wr_mask;
	} break;

	case DPP_ETCAM_OPR_VBIT: {
		ind_cmd.rd_wr = 1;
		ind_cmd.wr_mode = wr_mask;
	} break;

	default: {
		ZXIC_COMM_TRACE_DEV_ERROR(DEV_ID(dev), "Invalid opr_type!\n");
		ZXIC_COMM_ASSERT(0);
		return DPP_ERR;
	}
	}

	ind_cmd.dat_or_mask = data_or_mask;
	ind_cmd.ram_sel = block_idx;
	ind_cmd.addr = addr;

	ZXIC_COMM_TRACE_DEBUG("data_or_mask:%d\n", ind_cmd.dat_or_mask);
	ZXIC_COMM_TRACE_DEBUG("block_idx:%d\n", ind_cmd.ram_sel);
	ZXIC_COMM_TRACE_DEBUG("addr:0x%08x\n", ind_cmd.addr);

	rc = dpp_reg_write(dev, STAT_ETCAM_CPU_IND_CTRL_TMP0r, 0, 0, &ind_cmd);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_reg_write");

	return DPP_OK;
}

#endif

#if ZXIC_REAL("EX_FUNC")
DPP_STATUS dpp_etcam_cpu_afull_get(struct dpp_dev_t *dev, u32 block_idx, u32 *p_cpu_afull)
{
	DPP_STATUS rc = DPP_OK;
	struct dpp_stat_etcam_etcam_cpu_fl_t cpu_fl = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), block_idx, 0, DPP_ETCAM_BLOCK_NUM - 1);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_cpu_afull);

	rc = dpp_reg_read(dev, STAT_ETCAM_ETCAM_CPU_FLr, 0, 0, &cpu_fl);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_reg_read");

	*p_cpu_afull = (cpu_fl.etcam_cpu_fl >> block_idx) & 0x1;

	return DPP_OK;
}
DPP_STATUS dpp_etcam_cpu_afull_check(struct dpp_dev_t *dev, u32 block_idx)
{
	u32 read_cnt = 0;
	u32 cpu_afull = 1;
	DPP_STATUS rc = DPP_OK;

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), block_idx, 0, DPP_ETCAM_BLOCK_NUM - 1);

	while (cpu_afull) {
		rc = dpp_etcam_cpu_afull_get(dev, block_idx, &cpu_afull);
		ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_etcam_cpu_afull_get");

		if (!cpu_afull)
			break;

		read_cnt++;

		if (read_cnt > DPP_RD_CNT_MAX * DPP_RD_CNT_MAX) {
			ZXIC_COMM_TRACE_ERROR("Error!!! dpp etcam_cpu_afull_check is overtime!\n");
			return DPP_ERR;
		}

		/* zxic_comm_usleep(100); */
	}

	return DPP_OK;
}
DPP_STATUS dpp_etcam_entry_add(struct dpp_dev_t *dev, u32 addr, u32 block_idx, u32 wr_mask,
			       u32 opr_type, struct dpp_etcam_entry_t *p_entry)
{
	DPP_STATUS rc = DPP_OK;
	// u32 i = 0;
	// u32 tbl_id = 0;
	// u32 handle_row = 0;
	// u32 handle = 0;
	// u32 basea_addr = 0;
	u8 temp_data[DPP_ETCAM_WIDTH_MAX / 8] = { 0 };
	u8 temp_mask[DPP_ETCAM_WIDTH_MAX / 8] = { 0 };
	struct zxic_mutex_t *p_etcam_mutex = NULL;
	struct dpp_etcam_entry_t entry_xy = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), addr, 0, DPP_ETCAM_RAM_DEPTH - 1);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), block_idx, 0, DPP_ETCAM_BLOCK_NUM - 1);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), wr_mask, 0, DPP_ETCAM_WR_MASK_MAX);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), opr_type, DPP_ETCAM_OPR_DM, DPP_ETCAM_OPR_XY);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_entry);

	rc = dpp_dev_opr_mutex_get(dev, DPP_DEV_MUTEX_T_ETCAM, &p_etcam_mutex);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_dev_opr_mutex_get");

	rc = zxic_comm_mutex_lock(p_etcam_mutex);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "zxic_comm_mutex_lock");

	/* check cpu fifo is afull */
	rc = dpp_etcam_cpu_afull_check(dev, block_idx);
	ZXIC_COMM_CHECK_DEV_RC_UNLOCK(DEV_ID(dev), rc, "dpp_etcam_cpu_afull_check", p_etcam_mutex);

	ZXIC_COMM_ASSERT(p_entry->p_data && p_entry->p_mask);

	entry_xy.p_data = temp_data;
	entry_xy.p_mask = temp_mask;

	if (opr_type == DPP_ETCAM_OPR_DM) {
		/* convert user D/M data to X/Y */
		rc = dpp_etcam_dm_to_xy(p_entry, &entry_xy,
					DPP_ETCAM_ENTRY_SIZE_GET(p_entry->mode));
		ZXIC_COMM_CHECK_DEV_RC_UNLOCK(DEV_ID(dev), rc, "dpp_etcam_dm_to_xy", p_etcam_mutex);
	} else {
		ZXIC_COMM_MEMCPY(entry_xy.p_data, p_entry->p_data,
				 DPP_ETCAM_ENTRY_SIZE_GET(p_entry->mode));
		ZXIC_COMM_MEMCPY(entry_xy.p_mask, p_entry->p_mask,
				 DPP_ETCAM_ENTRY_SIZE_GET(p_entry->mode));
	}

	/* write data X */
	rc = dpp_etcam_ind_data_set(dev, wr_mask, entry_xy.p_data);
	ZXIC_COMM_CHECK_DEV_RC_UNLOCK(DEV_ID(dev), rc, "dpp_etcam_ind_data_set", p_etcam_mutex);

	rc = dpp_etcam_ind_cmd_set(dev, addr, block_idx, DPP_ETCAM_DTYPE_DATA, wr_mask,
				   DPP_ETCAM_OPR_WR, 0, 0, 1, 0);
	ZXIC_COMM_CHECK_DEV_RC_UNLOCK(DEV_ID(dev), rc, "dpp_etcam_ind_cmd_set", p_etcam_mutex);

	/* write mask Y */
	rc = dpp_etcam_ind_data_set(dev, wr_mask, entry_xy.p_mask);
	ZXIC_COMM_CHECK_DEV_RC_UNLOCK(DEV_ID(dev), rc, "dpp_etcam_ind_data_set", p_etcam_mutex);

	rc = dpp_etcam_ind_cmd_set(dev, addr, block_idx, DPP_ETCAM_DTYPE_MASK, wr_mask,
				   DPP_ETCAM_OPR_WR, 0, 0, 1, 0xFF);
	ZXIC_COMM_CHECK_DEV_RC_UNLOCK(DEV_ID(dev), rc, "dpp_etcam_ind_cmd_set", p_etcam_mutex);

	rc = zxic_comm_mutex_unlock(p_etcam_mutex);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "zxic_comm_mutex_unlock");

	return DPP_OK;
}
DPP_STATUS dpp_etcam_entry_del(struct dpp_dev_t *dev, u32 addr, u32 block_idx, u32 wr_mask)
{
	DPP_STATUS rc = DPP_OK;
	// u32 i = 0;
	// u32 tbl_id = 0;
	// u32 handle_row = 0;
	// u32 handle = 0;
	// u32 basea_addr = 0;

	u8 temp_data[DPP_ETCAM_WIDTH_MAX / 8] = {
		0xff,
	};
	u8 temp_mask[DPP_ETCAM_WIDTH_MAX / 8] = {
		0,
	};
	struct zxic_mutex_t *p_etcam_mutex = NULL;
	struct dpp_etcam_entry_t entry_xy = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), addr, 0, DPP_ETCAM_RAM_DEPTH - 1);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), block_idx, 0, DPP_ETCAM_BLOCK_NUM - 1);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), wr_mask, 0, DPP_ETCAM_WR_MASK_MAX);

	ZXIC_COMM_MEMSET(temp_data, 0xff, DPP_ETCAM_WIDTH_MAX / 8);
	ZXIC_COMM_MEMSET(temp_mask, 0, DPP_ETCAM_WIDTH_MAX / 8);

	entry_xy.p_data = temp_data;
	entry_xy.p_mask = temp_mask;

	rc = dpp_dev_opr_mutex_get(dev, DPP_DEV_MUTEX_T_ETCAM, &p_etcam_mutex);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_dev_opr_mutex_get");

	rc = zxic_comm_mutex_lock(p_etcam_mutex);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "zxic_comm_mutex_lock");

	/* check cpu fifo is afull */
	rc = dpp_etcam_cpu_afull_check(dev, block_idx);
	ZXIC_COMM_CHECK_DEV_RC_UNLOCK(DEV_ID(dev), rc, "dpp_etcam_cpu_afull_check", p_etcam_mutex);

	/* write data X */
	rc = dpp_etcam_ind_data_set(dev, wr_mask, entry_xy.p_data);
	ZXIC_COMM_CHECK_DEV_RC_UNLOCK(DEV_ID(dev), rc, "dpp_etcam_ind_data_set", p_etcam_mutex);

	rc = dpp_etcam_ind_cmd_set(dev, addr, block_idx, DPP_ETCAM_DTYPE_DATA, wr_mask,
				   DPP_ETCAM_OPR_WR, 0, 0, 1, 0xFF);
	ZXIC_COMM_CHECK_DEV_RC_UNLOCK(DEV_ID(dev), rc, "dpp_etcam_ind_cmd_set", p_etcam_mutex);

	/* write mask Y */
	rc = dpp_etcam_ind_data_set(dev, wr_mask, entry_xy.p_mask);
	ZXIC_COMM_CHECK_DEV_RC_UNLOCK(DEV_ID(dev), rc, "dpp_etcam_ind_data_set", p_etcam_mutex);

	rc = dpp_etcam_ind_cmd_set(dev, addr, block_idx, DPP_ETCAM_DTYPE_MASK, wr_mask,
				   DPP_ETCAM_OPR_WR, 0, 0, 1, 0xFF);
	ZXIC_COMM_CHECK_DEV_RC_UNLOCK(DEV_ID(dev), rc, "dpp_etcam_ind_cmd_set", p_etcam_mutex);

	rc = zxic_comm_mutex_unlock(p_etcam_mutex);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "zxic_comm_mutex_unlock");

	return DPP_OK;
}
u32 dpp_etcam_entry_cmp(struct dpp_etcam_entry_t *p_entry_dm, struct dpp_etcam_entry_t *p_entry_xy)
{
	DPP_STATUS rc = 0;
	u32 data_len = 0;
	u8 temp_data[DPP_ETCAM_WIDTH_MAX / 8] = { 0 };
	u8 temp_mask[DPP_ETCAM_WIDTH_MAX / 8] = { 0 };
	struct dpp_etcam_entry_t entry_xy_temp = { 0 };

	ZXIC_COMM_CHECK_POINT(p_entry_dm);
	ZXIC_COMM_CHECK_POINT(p_entry_xy);

	entry_xy_temp.mode = p_entry_dm->mode;
	entry_xy_temp.p_data = temp_data;
	entry_xy_temp.p_mask = temp_mask;
	data_len = DPP_ETCAM_ENTRY_SIZE_GET(entry_xy_temp.mode);

	if (data_len > 80)
		return 1;

	ZXIC_COMM_CHECK_INDEX_SUB_OVERFLOW_NO_ASSERT(3U, entry_xy_temp.mode);
	rc = dpp_etcam_dm_to_xy(p_entry_dm, &entry_xy_temp, data_len);
	ZXIC_COMM_CHECK_RC(rc, "dpp_etcam_dm_to_xy");

	if ((ZXIC_COMM_MEMCMP(entry_xy_temp.p_data, p_entry_xy->p_data, data_len) != 0) ||
	    (ZXIC_COMM_MEMCMP(entry_xy_temp.p_mask, p_entry_xy->p_mask, data_len) != 0)) {
		return 1;
	}

	return 0;
}
DPP_STATUS dpp_etcam_block_tbl_id_set(struct dpp_dev_t *dev, u32 block_idx, u32 tbl_id)
{
	DPP_STATUS rc = DPP_OK;
	u32 reg_offset = 0;
	u32 bit_offset = 0;
	u32 *p_temp = 0;
	struct dpp_stat4k_etcam_block0_7_port_id_cfg_t block_tbl_id = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), block_idx, 0, DPP_ETCAM_BLOCK_NUM - 1);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), tbl_id, 0, DPP_ETCAM_TBLID_NUM - 1);

	reg_offset = block_idx / TBLID_CFG_SETP;

	bit_offset = block_idx % TBLID_CFG_SETP;

	rc = dpp_reg_read(dev, STAT4K_ETCAM_BLOCK0_7_PORT_ID_CFGr + reg_offset, 0, 0,
			  &block_tbl_id);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_reg_read");

	p_temp = (u32 *)(&block_tbl_id) + 7 - bit_offset;

	*p_temp = tbl_id;

	rc = dpp_reg_write(dev, STAT4K_ETCAM_BLOCK0_7_PORT_ID_CFGr + reg_offset, 0, 0,
			   &block_tbl_id);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_reg_write");

	return DPP_OK;
}
DPP_STATUS dpp_etcam_block_tbl_id_get(struct dpp_dev_t *dev, u32 block_idx, u32 *p_tbl_id)
{
	DPP_STATUS rc = DPP_OK;
	u32 reg_offset = 0;
	u32 bit_offset = 0;
	u32 *p_temp = 0;
	struct dpp_stat4k_etcam_block0_7_port_id_cfg_t block_tbl_id = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), block_idx, 0, DPP_ETCAM_BLOCK_NUM - 1);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_tbl_id);

	reg_offset = block_idx / TBLID_CFG_SETP;
	bit_offset = block_idx % TBLID_CFG_SETP;

	rc = dpp_reg_read(dev, STAT4K_ETCAM_BLOCK0_7_PORT_ID_CFGr + reg_offset, 0, 0,
			  &block_tbl_id);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_reg_read");

	p_temp = (u32 *)(&block_tbl_id) + TBLID_CFG_SETP - 1 - bit_offset;

	*p_tbl_id = *p_temp;

	return DPP_OK;
}

DPP_STATUS dpp_etcam_block_baddr_set(struct dpp_dev_t *dev, u32 block_idx, u32 base_addr)
{
	DPP_STATUS rc = DPP_OK;
	u32 reg_offset = 0;
	u32 bit_offset = 0;
	u32 *p_temp = 0;
	struct dpp_stat4k_etcam_block0_3_base_addr_cfg_t block_baddr = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), block_idx, 0, DPP_ETCAM_BLOCK_NUM - 1);

	reg_offset = block_idx / BADDR_CFG_SETP;
	bit_offset = block_idx % BADDR_CFG_SETP;

	rc = dpp_reg_read(dev, STAT4K_ETCAM_BLOCK0_3_BASE_ADDR_CFGr + reg_offset, 0, 0,
			  &block_baddr);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_reg_read");

	p_temp = (u32 *)(&block_baddr) + 3 - bit_offset;

	*p_temp = base_addr;

	rc = dpp_reg_write(dev, STAT4K_ETCAM_BLOCK0_3_BASE_ADDR_CFGr + reg_offset, 0, 0,
			   &block_baddr);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_reg_write");

	return DPP_OK;
}
DPP_STATUS dpp_etcam_block_baddr_get(struct dpp_dev_t *dev, u32 block_idx, u32 *p_base_addr)
{
	DPP_STATUS rc = DPP_OK;
	u32 reg_offset = 0;
	u32 bit_offset = 0;
	u32 *p_temp = 0;
	struct dpp_stat4k_etcam_block0_3_base_addr_cfg_t block_baddr = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), block_idx, 0, DPP_ETCAM_BLOCK_NUM - 1);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_base_addr);

	reg_offset = block_idx / BADDR_CFG_SETP;
	bit_offset = block_idx % BADDR_CFG_SETP;

	rc = dpp_reg_read(dev, STAT4K_ETCAM_BLOCK0_3_BASE_ADDR_CFGr + reg_offset, 0, 0,
			  &block_baddr);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_reg_read");

	p_temp = (u32 *)&block_baddr + BADDR_CFG_SETP - 1 - bit_offset;

	*p_base_addr = *p_temp;

	return DPP_OK;
}

#endif
