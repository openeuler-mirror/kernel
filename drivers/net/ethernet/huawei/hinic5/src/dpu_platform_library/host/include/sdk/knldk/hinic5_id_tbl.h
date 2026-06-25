/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hinic5_id_tbl.h
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   :
 */

#ifndef HINIC5_ID_TBL_H
#define HINIC5_ID_TBL_H

#define HINIC5_VIRTIO_VNEDER_ID         0x1AF4

#ifdef CONFIG_SP_VID_DID
#define PCI_VENDOR_ID_SPNIC			0x1F3F
#define HINIC5_DEV_ID_STANDARD			0x9020
#define HINIC5_DEV_ID_SDI_5_1_PF		0x9032
#define HINIC5_DEV_ID_VF			0x9001
#define HINIC5_DEV_ID_VF_HV			0x9002
#define HINIC5_DEV_ID_SPU			0xAC00
#else
#define PCI_VENDOR_ID_HUAWEI			0x19e5
#define HINIC5_DEV_ID_STANDARD			0x0222
#define HINIC5_DEV_ID_SDI_5_1_PF		0x0226
#define HINIC5_DEV_ID_SDI_5_0_PF		0x0225
#define HINIC5_DEV_ID_DPU_STORGE_PF		0x0220
#define HINIC5_DEV_ID_SDI_6_0_PF		0x0225
#define HINIC5_DEV_ID_VF			0x375F
#define HINIC5_DEV_ID_VF_HV			0x379F
#define HINIC5_DEV_ID_SPU			0xAC00

#define HINIC5_DEV_ID_TEMP			0x1823
#define HINIC5_DEV_ID_1823_VF_TEMP		0x375E
#define HINIC5_DEV_ID_1823_VF_HV_TEMP		0x379E

/* Hi1872V100, SP233, SP235, SP235-O */
#define HINIC5_DEV_ID_72V1_PF			0x0229
#define HINIC5_DEV_ID_72V1_VF			0x022a
#endif /* CONFIG_SP_VID_DID */

/* Hi1825V100 2X200G standard card, 1X400G standard card, 2X400G UBX UB carrier board UB EXP custom card, 2X200G 4X200G Tianqu 2.0 on-board card */
#define HINIC5_DEV_ID_25V1_PF           0x0230
#define HINIC5_DEV_ID_25V1_VF           0x0231

#define HINIC5_IS_VF_DEV(dev_id)	(((dev_id) == HINIC5_DEV_ID_VF) || \
				 ((dev_id) == HINIC5_DEV_ID_72V1_VF) || \
				 ((dev_id) == HINIC5_DEV_ID_1823_VF_TEMP) || \
				 ((dev_id) == HINIC5_DEV_ID_25V1_VF))
#define HINIC5_IS_SPU_DEV(dev_id)	(((dev_id) == HINIC5_DEV_ID_SPU) || \
				 ((dev_id) == HINIC5_DEV_ID_SDI_5_0_PF))

#define HINIC5_UDEV_VENDOR_ID_HUAWEI            0xCC08
#define HINIC5_UDEV_VENDOR_ID_HUAWEI_E0FC       0xE0FC /* Old Vendor ID, to be deleted */

#define HINIC5_UDEV_DEVICE_ID_1825_PF           0x8200
#define HINIC5_UDEV_DEVICE_ID_1825_VF           0x8201
#define HINIC5_UDEV_DEVICE_ID_1825_TEMP         0x1825 /* For development */

#define HINIC5_UDEV_DEVICE_ID_1872_PF           0x8100
#define HINIC5_UDEV_DEVICE_ID_1872_VF           0x8101

#define HINIC5_UDEV_CLASS_CODE_1825             0x0102
#define HINIC5_UDEV_CLASS_CODE_1872             0x0102

#define HINIC5_UDEV_CLASS_CODE_MASK             0xFFFF

#endif /* HINIC5_ID_TBL_H */

