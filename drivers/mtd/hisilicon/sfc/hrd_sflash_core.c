// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2019 Hisilicon Limited, All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#include <linux/clk.h>
#include <linux/delay.h>
#include <linux/gpio.h>
#include <linux/interrupt.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/of_gpio.h>
#include <linux/of_platform.h>
#include <linux/of_address.h>
#include <linux/platform_device.h>
#include <linux/resource.h>
#include <linux/signal.h>
#include <linux/types.h>
#include "hrd_common.h"
#include "hrd_sflash_spec.h"
#include "hrd_sflash_core.h"

u32 SFC_RegisterRead(u64 reg_addr)
{
	u32 ulResult;

	ulResult = *(__iomem u32 *) (reg_addr);

	return HRD_32BIT_LE(ulResult);
}

void SFC_RegisterWrite(u64 reg_addr, u32 ulValue)
{
	*(__iomem u32 *) (reg_addr) = HRD_32BIT_LE(ulValue);
}

/* Judging sfc whether something is wrong  */
bool SFC_IsOpErr(u64 reg_addr)
{
	u32 IntStatus;

	IntStatus = SFC_RegisterRead(reg_addr + (u32) INTRAWSTATUS);
	if ((IntStatus & SFC_OP_ERR_MASK) != 0) {
		pr_err("%s ERROR:  Int status=%x not cleared, clear\r\n", __func__, IntStatus);
		SFC_RegisterWrite(reg_addr + INTCLEAR, INT_MASK);
		return true;
	}

	return false;
}

s32 SFC_ClearInt(u64 reg_addr)
{
	u32 IntStatus;

	IntStatus = SFC_RegisterRead(reg_addr + (u32) INTRAWSTATUS);
	if ((IntStatus & INT_MASK) != 0) {
		pr_err("[SFC] [%s %d]: Int status=%x not cleared, clear\r\n",
			   __func__, __LINE__, IntStatus);
		SFC_RegisterWrite(reg_addr + INTCLEAR, INT_MASK);
	}

	return 0;
}

s32 SFC_WaitInt(u64 reg_addr)
{
	u32 ulRegValue;
	u32 ulCount = 0;

	ulRegValue = SFC_RegisterRead(reg_addr + (u32) INTRAWSTATUS);
	while (((ulRegValue & CMD_OP_END_INT_BIT) != CMD_OP_END_INT_BIT)
		   && (ulCount < SFC_INT_WAIT_CNT)) {
		udelay(1);
		ulRegValue = SFC_RegisterRead(reg_addr + INTRAWSTATUS);
		ulCount++;
	}

	if (ulCount >= SFC_INT_WAIT_CNT) {
		pr_err("[SFC] [%s %d]: wait int time out\n", __func__, __LINE__);
		return WAIT_TIME_OUT;
	}

	SFC_RegisterWrite(reg_addr + INTCLEAR, CMD_OP_END_INT_BIT);

	return HRD_OK;
}

s32 SFC_WriteEnable(struct SFC_SFLASH_INFO *sflash)
{
	u32 ulRegValue;

	(void)SFC_ClearInt(sflash->sfc_reg_base);
	SFC_RegisterWrite(sflash->sfc_reg_base + CMD_INS, sflash->sflash_dev_params.ucOpcodeWREN);

	ulRegValue = SFC_RegisterRead(sflash->sfc_reg_base + CMD_CONFIG);
	ulRegValue &= (~(1 << ADDR_EN)) & (~(1 << DATA_EN)) & (~(1 << SEL_CS));
	ulRegValue |= (0x1 << LOCK_FLASH) | (SFC_CHIP_CS << SEL_CS) | (0x1 << START);

	wmb();

	SFC_RegisterWrite(sflash->sfc_reg_base + CMD_CONFIG, ulRegValue);

	return SFC_WaitInt(sflash->sfc_reg_base);
}

void SFC_FlashUnlock(struct SFC_SFLASH_INFO *sflash)
{
	u32 ulRegValue;

	ulRegValue = SFC_RegisterRead(sflash->sfc_reg_base + CMD_CONFIG);
	ulRegValue &= (~(1 << LOCK_FLASH));
	wmb();
	SFC_RegisterWrite(sflash->sfc_reg_base + CMD_CONFIG, ulRegValue);
}

u32 SFC_ReadStatus(struct SFC_SFLASH_INFO *sflash)
{
	u32 ulRegValue;
	s32 ulRet;

	(void)SFC_ClearInt(sflash->sfc_reg_base);

	SFC_RegisterWrite(sflash->sfc_reg_base + CMD_INS,
					  sflash->sflash_dev_params.ucOpcodeRDSR);

	ulRegValue = SFC_RegisterRead(sflash->sfc_reg_base + CMD_CONFIG);
	ulRegValue &=
		(~(0xff << DATA_CNT)) & (~(0x1 << RW_DATA)) & (~(0x1 << SEL_CS));
	ulRegValue |= (0x3 << DATA_CNT) | (0x1 << RW_DATA) | (0x1 << DATA_EN)
		| (SFC_CHIP_CS << SEL_CS) | (0x1 << START);

	wmb();
	SFC_RegisterWrite(sflash->sfc_reg_base + CMD_CONFIG, ulRegValue);

	ulRet = SFC_WaitInt(sflash->sfc_reg_base);
	if (ulRet != HRD_OK)
		return WAIT_TIME_OUT;

	ulRegValue = SFC_RegisterRead(sflash->sfc_reg_base + DATABUFFER1);
	ulRegValue = ulRegValue & 0xff;

	return ulRegValue;
}

s32 SFC_CheckBusy(struct SFC_SFLASH_INFO *sflash, u32 ulTimeOut)
{
	u32 ulRegValue;
	u32 ulWaitCount = 0;

	ulRegValue = SFC_ReadStatus(sflash);
	if (ulRegValue == WAIT_TIME_OUT) {
		pr_err("[SFC] [%s %d]: SFC_ReadStatus time out\n", __func__, __LINE__);
		return HRD_ERR;
	}

	while (((ulRegValue & STATUS_REG_BUSY_BIT) == STATUS_REG_BUSY_BIT)
		   && (ulWaitCount < ulTimeOut)) {
		udelay((unsigned long)1);

		ulRegValue = SFC_ReadStatus(sflash);
		if (ulRegValue == WAIT_TIME_OUT) {
			pr_err("[SFC] [%s %d]: SFC_ReadStatus time out\n", __func__, __LINE__);
			return HRD_ERR;
		}

		if ((sflash->manufacturerId == HISI_SPANSION_MANF_ID)
			&& (ulRegValue & (STATUS_REG_P_ERR | STATUS_REG_E_ERR))) {
			pr_err("[SFC] [%s %d]: program err or erase err, status = %08x\n",
				__func__, __LINE__, ulRegValue);
			return HRD_ERR;
		}

		ulWaitCount++;
		if ((ulWaitCount > 0) && (ulWaitCount % 1000 == 0)) { /* Every cycle 1000 times, sleep 1 ms */
			msleep(1);
		}
	}

	if (ulWaitCount >= ulTimeOut) {
		pr_err("[SFC] [%s %d]: CheckBusy time out\n", __func__, __LINE__);
		return WAIT_TIME_OUT;
	}

	return HRD_OK;
}

s32 SFC_ClearStatus(struct SFC_SFLASH_INFO *sflash)
{
	u32 ulRegValue = 0;
	s32 ulRet = HRD_ERR;

	(void)SFC_ClearInt(sflash->sfc_reg_base);

	if (sflash->manufacturerId == HISI_SPANSION_MANF_ID) {
		/* 30 for spansion , clear status */
		SFC_RegisterWrite(sflash->sfc_reg_base + CMD_INS, 0x30);

		/* set configure reg and startup */
		ulRegValue = SFC_RegisterRead(sflash->sfc_reg_base + CMD_CONFIG);

		ulRegValue &= (~(1 << ADDR_EN)) & (~(1 << DATA_EN)) & (~(1 << SEL_CS));
		ulRegValue |= (SFC_CHIP_CS << SEL_CS) | (1 << START);

		wmb();

		SFC_RegisterWrite(sflash->sfc_reg_base + CMD_CONFIG, ulRegValue);

		/* wait operate end */
		ulRet = SFC_WaitInt(sflash->sfc_reg_base);
		if (ulRet != HRD_OK)
			return ulRet;
	}

	return HRD_OK;
}

void SFC_CheckErr(struct SFC_SFLASH_INFO *sflash)
{
	u32 ulRegValue = 0;
	unsigned long delay_us = 50; /* delay 50us */

	if (sflash->manufacturerId == HISI_SPANSION_MANF_ID) {
		ulRegValue = SFC_ReadStatus(sflash);
		if (ulRegValue == WAIT_TIME_OUT) {
			pr_err("[SFC] [%s %d]: SFC_ReadStatus time out\n",
				   __func__, __LINE__);
			return;
		}

		udelay(delay_us);

		if (ulRegValue & (STATUS_REG_P_ERR | STATUS_REG_E_ERR)) {
			pr_err("[SFC] [%s %d]: program err or erase err, status = %08x\n",
				   __func__, __LINE__, ulRegValue);

			if (SFC_ClearStatus(sflash) != HRD_OK) {
				pr_err("[SFC] [%s %d]: clear status failed\r\n",
					   __func__, __LINE__);
				return;
			}

			udelay(delay_us);
		}
	}
}

s32 SFC_CheckCmdExcStatus(struct SFC_SFLASH_INFO *sflash)
{
	u32 temp;
	u32 timeout = 1000;

	temp = SFC_RegisterRead(sflash->sfc_reg_base + CMD_CONFIG);
	while (temp & 1) {
		udelay(1);
		temp = SFC_RegisterRead(sflash->sfc_reg_base + CMD_CONFIG);
		timeout--;

		if (timeout == 0) {
			pr_err("[SFC] %s (%d):Check cmd execute status time out!\n", __func__, __LINE__);
			return HRD_ERR;
		}
	}

	return HRD_OK;
}

int SFC_WaitFlashIdle(struct SFC_SFLASH_INFO *sflash)
{
	union UN_SFC_CMD_CONFIG temp;
	u32 temp2 = 0;
	u32 timeout = 10000;
	int ret;

	temp.u32 = 0;

	(void)SFC_ClearInt(sflash->sfc_reg_base);

	SFC_RegisterWrite(sflash->sfc_reg_base + CMD_INS, SPI_CMD_RDSR);
	do {
		temp.bits.rw = SFC_CMD_CFG_READ;
		temp.bits.addr_en = false;
		temp.bits.data_en = true;
		temp.bits.data_cnt = SFC_CMD_DATA_CNT(1);
		temp.bits.sel_cs = SFC_CHIP_CS;
		temp.bits.start = true;
		SFC_RegisterWrite(sflash->sfc_reg_base + CMD_CONFIG, temp.u32);

		ret = SFC_CheckCmdExcStatus(sflash);
		if (ret != HRD_OK) {
			pr_err("[SFC] [%s %d]: cmd execute timeout\r\n", __func__, __LINE__);
			return ret;
		}

		udelay(80); /* Delay 80 subtleties */
		temp2 = SFC_RegisterRead(sflash->sfc_reg_base + DATABUFFER1);
		if (!(temp2 & SPI_CMD_SR_WIP)) {
			return HRD_OK;
		}

		udelay(20); /* Delay 20 subtleties */
	} while (timeout--);

	pr_err("[SFC] [%s %d]: Write in progress!\r\n", __func__, __LINE__);

	return HRD_ERR;
}

int SFC_GetDeviceId(struct SFC_SFLASH_INFO *sflash, u32 *id)
{
	int ret;
	union UN_SFC_CMD_CONFIG temp;

	temp.u32 = 0;

	(void)SFC_ClearInt(sflash->sfc_reg_base);

	SFC_RegisterWrite(sflash->sfc_reg_base + CMD_INS,
					  SFLASH_DEFAULT_RDID_OPCD);

	temp.bits.rw = SFC_CMD_CFG_READ;
	temp.bits.addr_en = false;
	temp.bits.data_en = true;
	temp.bits.data_cnt = SFC_CMD_DATA_CNT(1);
	temp.bits.sel_cs = SFC_CHIP_CS;
	temp.bits.start = true;

	wmb();
	SFC_RegisterWrite(sflash->sfc_reg_base + CMD_CONFIG, temp.u32);

	ret = SFC_CheckCmdExcStatus(sflash);
	if (ret != HRD_OK) {
		pr_err("[SFC] %s %d\n", __func__, __LINE__);
		return ret;
	}

	*id = SFC_RegisterRead(sflash->sfc_reg_base + DATABUFFER1);
	pr_info("[SFC] %s(%d):get_device_id: 0x%x !\n", __func__, __LINE__, *id);

	return ret;
}

s32 SFC_RegWordAlignRead(struct SFC_SFLASH_INFO *sflash,
	u32 ulOffsetAddr, u32 *pulData, u32 ulReadLen)
{
	u32 i;
	u32 ulDataCnt;
	u32 ulRegValue;
	s32 ulRet;

	if (!ulReadLen || ulReadLen > SFC_HARD_BUF_LEN || (ulReadLen & 0x3)) {
		pr_err("[SFC] [%s %d]: len=%u err\n", __func__, __LINE__, ulReadLen);
		return HRD_ERR;
	}

	ulDataCnt = ulReadLen >> 0x2;
	(void)SFC_ClearInt(sflash->sfc_reg_base);

	/* configure INS reg,send RDDATA operate */
	SFC_RegisterWrite(sflash->sfc_reg_base + CMD_INS,
					  sflash->sflash_dev_params.ucOpcodeREAD);
	SFC_RegisterWrite(sflash->sfc_reg_base + CMD_ADDR, ulOffsetAddr);

	/* set configure reg and startup */
	ulRegValue = SFC_RegisterRead(sflash->sfc_reg_base + CMD_CONFIG);
	ulRegValue &= (~(0xff << DATA_CNT) & (~(1 << SEL_CS)));
	ulRegValue |=
		((ulReadLen - 1) << DATA_CNT) | (1 << ADDR_EN) | (1 << DATA_EN) | (1 << RW_DATA)
		| (SFC_CHIP_CS << SEL_CS) | (0x1 << START);

	wmb();
	SFC_RegisterWrite(sflash->sfc_reg_base + CMD_CONFIG, ulRegValue);

	ulRet = SFC_WaitInt(sflash->sfc_reg_base);
	if (ulRet != HRD_OK) {
		pr_err("[SFC] [%s %d]: SFC_WaitInt fail\n", __func__, __LINE__);
		return ulRet;
	}

	if (SFC_IsOpErr(sflash->sfc_reg_base))
		return HRD_ERR;

	for (i = 0; i < ulDataCnt; i++)
		pulData[i] = SFC_RegisterRead(sflash->sfc_reg_base + DATABUFFER1 + (u32)(0x4 * i));

	return ulRet;
}

s32 SFC_RegByteRead(struct SFC_SFLASH_INFO *sflash,
	u32 ulOffsetAddr, u8 *pucData)
{
	u32 ulRegValue;
	s32 ulRet;

	(void)SFC_ClearInt(sflash->sfc_reg_base);

	/* configure INS reg,send RDDATA operate */
	SFC_RegisterWrite(sflash->sfc_reg_base + CMD_INS,
					  sflash->sflash_dev_params.ucOpcodeREAD);
	SFC_RegisterWrite(sflash->sfc_reg_base + CMD_ADDR, ulOffsetAddr);

	/* set configure reg and startup */
	ulRegValue = SFC_RegisterRead(sflash->sfc_reg_base + CMD_CONFIG);
	ulRegValue &= (~(0xff << DATA_CNT) & (~(1 << SEL_CS)));
	ulRegValue |=
		(0 << DATA_CNT) | (1 << ADDR_EN) | (1 << DATA_EN) | (1 << RW_DATA)
		| (SFC_CHIP_CS << SEL_CS) | (0x1 << START);

	wmb();
	SFC_RegisterWrite(sflash->sfc_reg_base + CMD_CONFIG, ulRegValue);

	ulRet = SFC_WaitInt(sflash->sfc_reg_base);
	if (ulRet != HRD_OK) {
		pr_err("[SFC] [%s %d]: SFC_WaitInt fail\n", __func__, __LINE__);
		return ulRet;
	}

	if (SFC_IsOpErr(sflash->sfc_reg_base))
		return HRD_ERR;

	*pucData = SFC_RegisterRead(sflash->sfc_reg_base + DATABUFFER1) & 0xff;

	return ulRet;
}

/* 4bytes align, ulDataLen <=256 */
s32 SFC_RegWordAlignWrite(struct SFC_SFLASH_INFO *sflash,
	const u32 *ulData, u32 ulOffsetAddr, u32 ulWriteLen)
{
	u32 i;
	u32 ulDataCnt;
	u32 ulRegValue;
	s32 ulRet;

	ulRet = SFC_WriteEnable(sflash);
	if ((!ulWriteLen) || (ulWriteLen > SFC_HARD_BUF_LEN) || (ulWriteLen & 0x3)) {
		pr_err("[SFC] [%s %d]: len=%u err\n", __func__, __LINE__, ulWriteLen);
		ulRet = HRD_ERR;
		goto rel;
	}

	if (ulRet != HRD_OK) {
		pr_err("[SFC] [%s %d]: SFC_WriteEnable fail\n", __func__, __LINE__);
		goto rel;
	}

	SFC_RegisterWrite(sflash->sfc_reg_base + CMD_INS, sflash->sflash_dev_params.ucOpcodePP);

	ulDataCnt = ulWriteLen >> 0x2;
	for (i = 0; i < ulDataCnt; i++) {
		SFC_RegisterWrite(sflash->sfc_reg_base + DATABUFFER1 + (u32)(0x4 * i), ulData[i]);
	}
	SFC_RegisterWrite(sflash->sfc_reg_base + CMD_ADDR, ulOffsetAddr);

	/* set configure reg and startup */
	ulRegValue = SFC_RegisterRead(sflash->sfc_reg_base + CMD_CONFIG);
	ulRegValue &=
		(~(0xff << DATA_CNT)) & (~(1 << RW_DATA) & (~(1 << SEL_CS)));
	ulRegValue |= ((ulWriteLen - 1) << DATA_CNT) | (1 << ADDR_EN) | (1 << DATA_EN)
		| (SFC_CHIP_CS << SEL_CS) | (0x1 << START);

	wmb();
	SFC_RegisterWrite(sflash->sfc_reg_base + CMD_CONFIG, ulRegValue);
	ulRet = SFC_WaitInt(sflash->sfc_reg_base);
	if (ulRet != HRD_OK) {
		pr_err("[SFC] [%s %d]: SFC_WaitInt fail\n", __func__, __LINE__);
		goto rel;
	}

	if (SFC_IsOpErr(sflash->sfc_reg_base)) {
		ulRet = HRD_ERR;
		goto rel;
	}

	SFC_RegisterWrite(sflash->sfc_reg_base + CMD_INS,
					  sflash->sflash_dev_params.ucOpcodeRDSR);
	ulRet = SFC_CheckBusy(sflash, FLASH_WRITE_BUSY_WAIT_CNT);

 rel:
	SFC_FlashUnlock(sflash);

	return ulRet;
}

s32 SFC_RegByteWrite(struct SFC_SFLASH_INFO *sflash,
	u8 ucData, u32 ulOffsetAddr)
{
	u32 ulRegValue;
	s32 ulRet;

	ulRet = SFC_WriteEnable(sflash);
	if (ulRet != HRD_OK) {
		pr_err("[SFC] [%s %d]: SFC_WriteEnable failed\r\n", __func__, __LINE__);
		goto rel;
	}

	SFC_RegisterWrite(sflash->sfc_reg_base + CMD_INS, sflash->sflash_dev_params.ucOpcodePP);
	SFC_RegisterWrite(sflash->sfc_reg_base + DATABUFFER1, ucData);
	SFC_RegisterWrite(sflash->sfc_reg_base + CMD_ADDR, ulOffsetAddr);

	/* set configure reg and startup */
	ulRegValue = SFC_RegisterRead(sflash->sfc_reg_base + CMD_CONFIG);
	ulRegValue &=
		(~(0xff << DATA_CNT)) & (~(1 << RW_DATA)) & (~(1 << SEL_CS));
	ulRegValue |= (0 << DATA_CNT) | (1 << ADDR_EN) | (1 << DATA_EN)
		| (SFC_CHIP_CS << SEL_CS) | (0x1 << START);

	wmb();
	SFC_RegisterWrite(sflash->sfc_reg_base + CMD_CONFIG, ulRegValue);
	ulRet = SFC_WaitInt(sflash->sfc_reg_base);
	if (ulRet != HRD_OK) {
		pr_err("[SFC] [%s %d]: wait int failed\r\n", __func__, __LINE__);
		goto rel;
	}

	if (SFC_IsOpErr(sflash->sfc_reg_base)) {
		ulRet = HRD_ERR;
		goto rel;
	}

	SFC_RegisterWrite(sflash->sfc_reg_base + CMD_INS, sflash->sflash_dev_params.ucOpcodeRDSR);
	ulRet = SFC_CheckBusy(sflash, FLASH_WRITE_BUSY_WAIT_CNT);

 rel:
	SFC_FlashUnlock(sflash);

	return ulRet;
}
