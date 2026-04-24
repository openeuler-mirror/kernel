/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved.
 *
 */

#ifndef __UBASE_UBUS_H__
#define __UBASE_UBUS_H__

#include <ub/ubus/ubus.h>

#define UBASE_UBUS_IO_RESOURCE	2
#define UBASE_UBUS_MEM_RESOURCE	1
#define UBASE_UBUS_RESOURCE_0	0

#define UBASE_VENDOR_ID			0xCC08

#define UBASE_DEV_ID_K_0_URMA_MUE	0xA001
#define UBASE_DEV_ID_K_0_URMA_UE	0xA002
#define UBASE_DEV_ID_K_0_CDMA_MUE	0xA003
#define UBASE_DEV_ID_K_0_CDMA_UE	0xA004
#define UBASE_DEV_ID_K_0_PMU_MUE	0xA005
#define UBASE_DEV_ID_K_0_PMU_UE		0xA006

#define UBASE_DEV_ID_K_V2_URMA_MUE	0xA00B
#define UBASE_DEV_ID_K_V2_URMA_UE	0xA00C
#define UBASE_DEV_ID_K_V2_CDMA_MUE	0xA00D
#define UBASE_DEV_ID_K_V2_CDMA_UE	0xA00E
#define UBASE_DEV_ID_K_V2_PMU_MUE	0xA00F
#define UBASE_DEV_ID_K_V2_PMU_UE	0xA010

#define UBASE_DEV_ID_A_0_URMA_MUE	0xD802
#define UBASE_DEV_ID_A_0_URMA_UE	0xD803
#define UBASE_DEV_ID_A_0_CDMA_MUE	0xD804
#define UBASE_DEV_ID_A_0_CDMA_UE	0xD805
#define UBASE_DEV_ID_A_0_PMU_MUE	0xD806
#define UBASE_DEV_ID_A_0_PMU_UE		0xD807
#define UBASE_DEV_ID_A_0_UBOE_MUE	0xD80B
#define UBASE_DEV_ID_A_0_UBOE_UE	0xD80C

#define UBASE_DEV_ID_A_V2_URMA_MUE	0xD812
#define UBASE_DEV_ID_A_V2_URMA_UE	0xD813
#define UBASE_DEV_ID_A_V2_CDMA_MUE	0xD814
#define UBASE_DEV_ID_A_V2_CDMA_UE	0xD815
#define UBASE_DEV_ID_A_V2_PMU_MUE	0xD816
#define UBASE_DEV_ID_A_V2_PMU_UE	0xD817
#define UBASE_DEV_ID_A_V2_UBOE_MUE	0xD81B
#define UBASE_DEV_ID_A_V2_UBOE_UE	0xD81C

#define UBASE_DEV_ID_S_0_URMA_MUE	0x8011
#define UBASE_DEV_ID_S_0_URMA_UE	0x8012
#define UBASE_DEV_ID_S_0_PMU_MUE	0x8013
#define UBASE_DEV_ID_S_0_CDMA_MUE	0x8015

struct ubase_bus_eid;

int ubase_ubus_register_driver(void);
void ubase_ubus_unregister_driver(void);

int ubase_ubus_irq_vectors_alloc(struct device *dev);
void ubase_ubus_irq_vectors_free(struct device *dev);
int ubase_ubus_irq_vector(struct device *dev, u32 idx);

int ubase_ubus_reset_entry(struct device *dev);
void ubase_ubus_reinit(struct device *dev);

void ubase_ubus_fault_log(struct ubase_dev *udev, u32 event_id, void *data);

#endif /* __UBASE_UBUS_H__ */
