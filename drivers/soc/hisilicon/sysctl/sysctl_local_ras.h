/* SPDX-License-Identifier: GPL-2.0 */
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
#ifndef _SYSCTL_LOCAL_RAS_H_
#define _SYSCTL_LOCAL_RAS_H_

enum {
	OEM1_SUB_MODULE_USB0 = 0,
	OEM1_SUB_MODULE_USB1,
	OEM1_SUB_MODULE_USB2,
};

enum {
	OEM1_MODULE_PLL = 1,
	OEM1_MODULE_SLLC = 2,
	OEM1_MODULE_SIOE = 4,
	OEM1_MODULE_POE = 5,
	OEM1_MODULE_DISP = 8,
	OEM1_MODULE_TDH = 9,
	OEM1_MODULE_GIC = 13,
	OEM1_MODULE_RDE = 14,
	OEM1_MODULE_SAS = 15,
	OEM1_MODULE_SATA = 16,
	OEM1_MODULE_USB = 17,
};

enum {
	OEM2_MODULE_SMMU = 0,
	OEM2_MODULE_HHA = 1,
	OEM2_MODULE_PA = 2,
	OEM2_MODULE_HLLC = 3,
	OEM2_MODULE_DDRC = 4,
};

enum {
	PCIE_LOCAL_MODULE_AP = 0,
	PCIE_LOCAL_MODULE_TL = 1,
	PCIE_LOCAL_MODULE_MAC = 2,
	PCIE_LOCAL_MODULE_DL = 3,
	PCIE_LOCAL_MODULE_SDI = 4,
};

#define HISI_OEM_VALID_SOC_ID		BIT(0)
#define HISI_OEM_VALID_SOCKET_ID	BIT(1)
#define HISI_OEM_VALID_NIMBUS_ID	BIT(2)
#define HISI_OEM_VALID_MODULE_ID	BIT(3)
#define HISI_OEM_VALID_SUB_MODULE_ID	BIT(4)
#define HISI_OEM_VALID_ERR_SEVERITY	BIT(5)

#define HISI_OEM_TYPE2_VALID_ERR_FR	BIT(6)
#define HISI_OEM_TYPE2_VALID_ERR_CTRL	BIT(7)
#define HISI_OEM_TYPE2_VALID_ERR_STATUS	BIT(8)
#define HISI_OEM_TYPE2_VALID_ERR_ADDR	BIT(9)
#define HISI_OEM_TYPE2_VALID_ERR_MISC_0	BIT(10)
#define HISI_OEM_TYPE2_VALID_ERR_MISC_1	BIT(11)

#define HISI_PCIE_LOCAL_VALID_VERSION		BIT(0)
#define HISI_PCIE_LOCAL_VALID_SOC_ID		BIT(1)
#define HISI_PCIE_LOCAL_VALID_SOCKET_ID		BIT(2)
#define HISI_PCIE_LOCAL_VALID_NIMBUS_ID		BIT(3)
#define HISI_PCIE_LOCAL_VALID_SUB_MODULE_ID	BIT(4)
#define HISI_PCIE_LOCAL_VALID_CORE_ID		BIT(5)
#define HISI_PCIE_LOCAL_VALID_PORT_ID		BIT(6)
#define HISI_PCIE_LOCAL_VALID_ERR_TYPE		BIT(7)
#define HISI_PCIE_LOCAL_VALID_ERR_SEVERITY	BIT(8)
#define HISI_PCIE_LOCAL_VALID_ERR_MISC_0	BIT(9)
#define HISI_PCIE_LOCAL_VALID_ERR_MISC_1	BIT(10)
#define HISI_PCIE_LOCAL_VALID_ERR_MISC_2	BIT(11)
#define HISI_PCIE_LOCAL_VALID_ERR_MISC_3	BIT(12)
#define HISI_PCIE_LOCAL_VALID_ERR_MISC_4	BIT(13)
#define HISI_PCIE_LOCAL_VALID_ERR_MISC_5	BIT(14)
#define HISI_PCIE_LOCAL_VALID_ERR_MISC_6	BIT(15)
#define HISI_PCIE_LOCAL_VALID_ERR_MISC_7	BIT(16)
#define HISI_PCIE_LOCAL_VALID_ERR_MISC_8	BIT(17)
#define HISI_PCIE_LOCAL_VALID_ERR_MISC_9	BIT(18)
#define HISI_PCIE_LOCAL_VALID_ERR_MISC_10	BIT(19)
#define HISI_PCIE_LOCAL_VALID_ERR_MISC_11	BIT(20)
#define HISI_PCIE_LOCAL_VALID_ERR_MISC_12	BIT(21)
#define HISI_PCIE_LOCAL_VALID_ERR_MISC_13	BIT(22)
#define HISI_PCIE_LOCAL_VALID_ERR_MISC_14	BIT(23)
#define HISI_PCIE_LOCAL_VALID_ERR_MISC_15	BIT(24)
#define HISI_PCIE_LOCAL_VALID_ERR_MISC_16	BIT(25)
#define HISI_PCIE_LOCAL_VALID_ERR_MISC_17	BIT(26)
#define HISI_PCIE_LOCAL_VALID_ERR_MISC_18	BIT(27)
#define HISI_PCIE_LOCAL_VALID_ERR_MISC_19	BIT(28)
#define HISI_PCIE_LOCAL_VALID_ERR_MISC_20	BIT(29)
#define HISI_PCIE_LOCAL_VALID_ERR_MISC_21	BIT(30)
#define HISI_PCIE_LOCAL_VALID_ERR_MISC_22	BIT(31)
#define HISI_PCIE_LOCAL_VALID_ERR_MISC_23	BIT(32)
#define HISI_PCIE_LOCAL_VALID_ERR_MISC_24	BIT(33)
#define HISI_PCIE_LOCAL_VALID_ERR_MISC_25	BIT(34)
#define HISI_PCIE_LOCAL_VALID_ERR_MISC_26	BIT(35)
#define HISI_PCIE_LOCAL_VALID_ERR_MISC_27	BIT(36)
#define HISI_PCIE_LOCAL_VALID_ERR_MISC_28	BIT(37)
#define HISI_PCIE_LOCAL_VALID_ERR_MISC_29	BIT(38)
#define HISI_PCIE_LOCAL_VALID_ERR_MISC_30	BIT(39)
#define HISI_PCIE_LOCAL_VALID_ERR_MISC_31	BIT(40)
#define HISI_PCIE_LOCAL_VALID_ERR_MISC_32	BIT(41)

#define HISI_PCIE_VENDOR_ID 0x19e5

/* NET Device ID */
#define HISI_PCIE_DEV_ID_GE		   0xa220
#define HISI_PCIE_DEV_ID_25GE		 0xa221
#define HISI_PCIE_DEV_ID_25GE_RDMA	0xa222
#define HISI_PCIE_DEV_ID_50GE_RDMA	0xa224
#define HISI_PCIE_DEV_ID_100G_RDMA	0xa226
#define HISI_PCIE_DEV_ID_SDI		  0xa22a
#define HISI_PCIE_DEV_ID_100G_VF	  0xa22e
#define HISI_PCIE_DEV_ID_100G_RDMA_VF 0xa22f

/* HPRE Device ID */
#define HISI_PCIE_DEV_ID_ZIP  0xa250
#define HISI_PCIE_DEV_ID_SEC  0xa255
#define HISI_PCIE_DEV_ID_HPRE 0xa258

#define CPER_SEC_HISI_OEM_1 \
	GUID_INIT(0x1F8161E1, 0x55D6, 0x41E6, 0xBD, 0x10, 0x7A,\
		0xFD, 0x1D, 0xC5, 0xF7, 0xC5)

#define CPER_SEC_HISI_OEM_2 \
	GUID_INIT(0x45534EA6, 0xCE23, 0x4115, 0x85, 0x35, 0xE0, 0x7A, \
		0xB3, 0xAE, 0xF9, 0x1D)

#define CPER_SEC_HISI_PCIE_LOCAL \
	GUID_INIT(0xb2889fc9, 0xe7d7, 0x4f9d, 0xa8, 0x67, 0xaf, 0x42, \
		0xe9, 0x8b, 0xe7, 0x72)

struct oem1_validation_bits {
	u32 soc_id_vald : 1;
	u32 socket_id_vald : 1;
	u32 nimbus_id_vald : 1;
	u32 module_id_vald : 1;
	u32 submod_id_vald : 1;
	u32 err_sever_vald : 1;
	u32 err_misc0_vald : 1;
	u32 err_misc1_vald : 1;
	u32 err_misc2_vald : 1;
	u32 err_misc3_vald : 1;
	u32 err_misc4_vald : 1;
	u32 err_addr_vald : 1;
	u32 reserv : 20;
};

struct hisi_oem_type1_err_sec {
	struct oem1_validation_bits validation_bits;
	u8 version;
	u8 soc_id;
	u8 socket_id;
	u8 nimbus_id;
	u8 module_id;
	u8 sub_mod_id;
	u8 err_severity;
	u8 resv1;
	u32 err_misc0;
	u32 err_misc1;
	u32 err_misc2;
	u32 err_misc3;
	u32 err_misc4;
	u32 err_addrl;
	u32 err_addrh;
};

struct hisi_oem_type2_err_sec {
	u32 val_bits;
	u8 version;
	u8 soc_id;
	u8 socket_id;
	u8 nimbus_id;
	u8 module_id;
	u8 sub_module_id;
	u8 err_severity;
	u8 reserv;
	u32 err_fr_0;
	u32 err_fr_1;
	u32 err_ctrl_0;
	u32 err_ctrl_1;
	u32 err_status_0;
	u32 err_status_1;
	u32 err_addr_0;
	u32 err_addr_1;
	u32 err_misc0_0;
	u32 err_misc0_1;
	u32 err_misc1_0;
	u32 err_misc1_1;
};

struct hisi_pcie_local_err_sec {
	u64 val_bits;
	u8 version;
	u8 soc_id;
	u8 socket_id;
	u8 nimbus_id;
	u8 sub_module_id;
	u8 core_id;
	u8 port_id;
	u8 err_severity;
	u16 err_type;
	u8 reserv[2]; /* reserv 2 bytes */
	u32 err_misc_0;
	u32 err_misc_1;
	u32 err_misc_2;
	u32 err_misc_3;
	u32 err_misc_4;
	u32 err_misc_5;
	u32 err_misc_6;
	u32 err_misc_7;
	u32 err_misc_8;
	u32 err_misc_9;
	u32 err_misc_10;
	u32 err_misc_11;
	u32 err_misc_12;
	u32 err_misc_13;
	u32 err_misc_14;
	u32 err_misc_15;
	u32 err_misc_16;
	u32 err_misc_17;
	u32 err_misc_18;
	u32 err_misc_19;
	u32 err_misc_20;
	u32 err_misc_21;
	u32 err_misc_22;
	u32 err_misc_23;
	u32 err_misc_24;
	u32 err_misc_25;
	u32 err_misc_26;
	u32 err_misc_27;
	u32 err_misc_28;
	u32 err_misc_29;
	u32 err_misc_30;
	u32 err_misc_31;
	u32 err_misc_32;
};

int hip_sysctl_local_ras_init(void);
void hip_sysctl_local_ras_exit(void);

#endif
