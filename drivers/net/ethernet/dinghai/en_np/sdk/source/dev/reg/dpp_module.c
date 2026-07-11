// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#include "zxic_common.h"
#include "dpp_type_api.h"
#include "dpp_module.h"
#include "dpp_dev.h"
#include "dpp_reg_struct.h"
#include "dpp_reg_api.h"
DPP_STATUS dpp_read(struct dpp_dev_t *dev, u32 addr, u32 *p_data)
{
	return dpp_dev_read_channel(dev, addr, 1, p_data);
}
DPP_STATUS dpp_write(struct dpp_dev_t *dev, u32 addr, u32 *p_data)
{
	return dpp_dev_write_channel(dev, addr, 1, p_data);
}

#if ZXIC_REAL("SE")
DPP_STATUS dpp_se_read(struct dpp_dev_t *dev, u32 addr, u32 *p_data)
{
	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_data);

	return dpp_read(dev, addr, p_data);
}
DPP_STATUS dpp_se_write(struct dpp_dev_t *dev, u32 addr, u32 *p_data)
{
	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_data);

	return dpp_write(dev, addr, p_data);
}
#endif

#if ZXIC_REAL("SE ALG")
DPP_STATUS dpp_se_alg_read(struct dpp_dev_t *dev, u32 addr, u32 *p_data)
{
	DPP_STATUS rtn = DPP_OK;

	u32 cpu_rd_rdy_addr = SYS_SE_BASE_ADDR + MODULE_SE_ALG_BASE_ADDR + 0x0048;
	u32 ind_data0_addr = SYS_SE_BASE_ADDR + MODULE_SE_ALG_BASE_ADDR + 0x004c;
	u32 ind_cmd_addr = SYS_SE_BASE_ADDR + MODULE_SE_ALG_BASE_ADDR + 0x0004;
	u32 cpu_rd_rdy_reg = 0;
	u32 ind_data0_reg = 0;
	u32 ind_cmd_reg = 0;
	u32 cmd_data = 0;
	u32 i = 0;
	u32 cpu_rdy = 0;
	u32 read_cnt = 0;
	u32 recheck_flag = 20;

	struct zxic_mutex_t *p_alg_mutex = NULL;

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_data);

	ind_data0_reg =
		dpp_reg_addr_convert(DEV_ID(dev), SE4K, DPP_REG_FLAG_DIRECT, ind_data0_addr);
	ind_cmd_reg = dpp_reg_addr_convert(DEV_ID(dev), SE4K, DPP_REG_FLAG_DIRECT, ind_cmd_addr);
	cpu_rd_rdy_reg =
		dpp_reg_addr_convert(DEV_ID(dev), SE4K, DPP_REG_FLAG_DIRECT, cpu_rd_rdy_addr);

	rtn = dpp_dev_opr_mutex_get(dev, DPP_DEV_MUTEX_T_REG, &p_alg_mutex);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rtn, "dpp_dev_opr_mutex_get");

	rtn = zxic_comm_mutex_lock(p_alg_mutex);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rtn, "zxic_comm_mutex_lock");

	/* dpp_module_get_se_alg_baseaddr(&base_addr); */

	cmd_data = ((u32)0x1 << 31) | ((u32)0xF << 17) | addr;
	rtn = dpp_dev_write_channel(dev, ind_cmd_reg, 1, &cmd_data);
	ZXIC_COMM_CHECK_DEV_RC_UNLOCK(DEV_ID(dev), rtn, "dpp_dev_write_channel", p_alg_mutex);

	while (!(cpu_rdy & 0x1)) {
		rtn = dpp_dev_read_channel(dev, cpu_rd_rdy_reg, 1, &cpu_rdy);
		ZXIC_COMM_CHECK_DEV_RC_UNLOCK(DEV_ID(dev), rtn, "dpp_dev_read_channel",
					      p_alg_mutex);

		read_cnt++;
		/* zxic_comm_sleep(10); */

		if (read_cnt > DPP_RD_CNT_MAX * DPP_RD_CNT_MAX) {
			if (recheck_flag > 0) {
				recheck_flag--;
				read_cnt = 0;
				rtn = dpp_dev_write_channel(dev, ind_cmd_reg, 1, &cmd_data);
				ZXIC_COMM_CHECK_DEV_RC_UNLOCK(DEV_ID(dev), rtn,
							      "dpp_dev_write_channel", p_alg_mutex);
			} else {
				ZXIC_COMM_PRINT(
					"Error!!! dpp se alg read get cpu_rd_rdone failed!!!\n");
				zxic_comm_mutex_unlock(p_alg_mutex);
				return DPP_ERR;
			}
		}

		/* ZXIC_COMM_CHECK_DEV_INDEX(dev_id, read_cnt, 0, DPP_RD_CNT_MAX); */
	}

	for (i = 0; i < 16; i++) {
		rtn = dpp_dev_read_channel(dev, ind_data0_reg + 4 * i, 1, p_data + 15 - i);
		ZXIC_COMM_CHECK_DEV_RC_UNLOCK(DEV_ID(dev), rtn, "dpp_dev_read_channel",
					      p_alg_mutex);
	}

	rtn = zxic_comm_mutex_unlock(p_alg_mutex);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rtn, "zxic_comm_mutex_unlock");

	return DPP_OK;
}
DPP_STATUS dpp_se_alg_write(struct dpp_dev_t *dev, u32 addr, u32 *p_data)
{
	DPP_STATUS rtn = DPP_OK;

	u32 ind_data0_addr = SYS_SE_BASE_ADDR + MODULE_SE_ALG_BASE_ADDR + 0x0008;
	u32 cmd_data = 0;
	u32 ind_cmd_addr = SYS_SE_BASE_ADDR + MODULE_SE_ALG_BASE_ADDR + 0x0004;
	u32 ind_data0_reg = 0;
	u32 ind_cmd_reg = 0;
	u32 i = 0;
	struct zxic_mutex_t *p_alg_mutex = NULL;

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_data);

	ind_data0_reg =
		dpp_reg_addr_convert(DEV_ID(dev), SE4K, DPP_REG_FLAG_DIRECT, ind_data0_addr);
	ind_cmd_reg = dpp_reg_addr_convert(DEV_ID(dev), SE4K, DPP_REG_FLAG_DIRECT, ind_cmd_addr);

	/* dpp_module_get_se_alg_baseaddr(&base_addr); */
	rtn = dpp_dev_opr_mutex_get(dev, DPP_DEV_MUTEX_T_REG, &p_alg_mutex);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rtn, "dpp_dev_opr_mutex_get");

	rtn = zxic_comm_mutex_lock(p_alg_mutex);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rtn, "zxic_comm_mutex_lock");

	/* write data */
	for (i = 0; i < 16; i++) {
		ZXIC_COMM_TRACE_DEV_DEBUG(DEV_ID(dev),
					  "dpp se_alg_write: addr=0x%08x, data=0x%08x.\n",
					  ind_data0_reg + 4 * i, *(p_data + 15 - i));
		rtn = dpp_dev_write_channel(dev, ind_data0_reg + 4 * i, 1, p_data + 15 - i);
		ZXIC_COMM_CHECK_DEV_RC_UNLOCK(DEV_ID(dev), rtn, "dpp_dev_write_channel",
					      p_alg_mutex);
	}

	/* write cmd */
	/* cmd_data = ((u32)0xF << 17) | addr; */
	cmd_data = addr & 0x1fffff; /* mod by tf */
	ZXIC_COMM_TRACE_DEV_DEBUG(DEV_ID(dev), "dpp se_alg_write: addr=0x%08x, data=0x%08x.\n",
				  ind_cmd_reg, cmd_data);
	rtn = dpp_dev_write_channel(dev, ind_cmd_reg, 1, &cmd_data);
	ZXIC_COMM_CHECK_DEV_RC_UNLOCK(DEV_ID(dev), rtn, "dpp_dev_write_channel", p_alg_mutex);

	rtn = zxic_comm_mutex_unlock(p_alg_mutex);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rtn, "zxic_comm_mutex_unlock");

	return DPP_OK;
}

#endif

#if ZXIC_REAL("PPU")
DPP_STATUS dpp_ppu_read(struct dpp_dev_t *dev, u32 addr, u32 *p_data)
{
	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_data);

	return dpp_read(dev, addr, p_data);
}
DPP_STATUS dpp_ppu_write(struct dpp_dev_t *dev, u32 addr, u32 *p_data)
{
	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_data);

	return dpp_write(dev, addr, p_data);
}
#endif
