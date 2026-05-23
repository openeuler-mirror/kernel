/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hinic5_ubus.h
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   :
 */

#ifndef HINIC5_UBUS_H
#define HINIC5_UBUS_H
#ifdef __UBUS_DRIVER__
#include <linux/types.h>
#ifdef UB_SUPPORT_ENTITY
#include <ub/ubus/ubus.h>
#include <ub/ubus/ubus_regs.h>
#else
#include <linux/ubus.h>
#include <linux/ubus_regs.h>
#endif
#include "hinic5_dev_mgmt.h"

enum ubus_device_type {
	UBUS_DEVICE_TYPE_1825,
	UBUS_DEVICE_TYPE_1872,
	UBUS_DEVICE_TYPE_INVALID
};

// TODO: UB B173 and later version interface differences, need to define UB_SUPPORT_ENTITY for 173 and later
#ifdef UB_SUPPORT_ENTITY
typedef struct ub_entity hinic_ub_dev;
#define HINIC_UB_UE_ENABLE(ubus_dev, enable)    ub_entity_enable(ubus_dev, enable)
#define HINIC_UB_UNSET_HOST_INFO(ubus_dev)      ub_unset_user_info(ubus_dev)
#define HINIC_UB_SET_HOST_INFO(ubus_dev)        ub_set_user_info(ubus_dev)
#define HINIC_UB_DISABLE_FUNC(ubus_dev)         ub_disable_entities(ubus_dev)
#define HINIC_UB_ENABLE_VDEV(ubus_dev, ue_idx)  ub_enable_ue(ubus_dev, ue_idx)
#define HINIC_UB_DISABLE_VDEV(ubus_dev, ue_idx) ub_disable_ue(ubus_dev, ue_idx)
#define HINIC_UB_GET_DEVICE_ID(udev)            uent_device(udev)
#define HINIC_UB_GET_CLASS_CODE(udev)           uent_class(udev)
#define HINIC_TO_UB_DEV(dev)                    to_ub_entity(dev)
#else
typedef struct ub_dev hinic_ub_dev;
#define HINIC_UB_UE_ENABLE(ubus_dev, enable)    ub_fe_enable(ubus_dev, enable)
#define HINIC_UB_UNSET_HOST_INFO(ubus_dev)      ub_unset_hostinfo(ubus_dev)
#define HINIC_UB_SET_HOST_INFO(ubus_dev)        ub_set_hostinfo(ubus_dev)
#define HINIC_UB_DISABLE_FUNC(ubus_dev)         ub_disable_funcs(ubus_dev)
#define HINIC_UB_ENABLE_VDEV(ubus_dev, ue_idx)  ub_enable_vdev(ubus_dev, ue_idx)
#define HINIC_UB_DISABLE_VDEV(ubus_dev, ue_idx) ub_disable_vdev(ubus_dev, ue_idx)
#define HINIC_UB_GET_DEVICE_ID(udev)            udev_device(udev)
#define HINIC_UB_GET_CLASS_CODE(udev)           udev_class(udev)
#define HINIC_TO_UB_DEV(dev)                    to_ub_dev(dev)
#endif

int hinic5_ubus_register_driver(void);
void hinic5_ubus_unregister_driver(void);
bool hinic5_ubus_is_virtfn(struct hinic5_adev *adev);
struct hinic5_adev *hinic5_ubus_get_pf_adev(struct hinic5_adev *adev);
int hinic5_ubus_set_func_en(struct hinic5_adev *dst_dev, bool en, u16 vf_func_id);
struct hinic5_adev *hinic5_ubus_get_vf_adev_by_pf(struct hinic5_adev *adev, u16 func_id);
int hinic5_ubus_get_vf_num(struct hinic5_adev *adev);
u16 hinic5_ubus_get_device_id(struct hinic5_adev *adev);
int hinic5_ubus_irq_vectors_alloc(struct hinic5_adev *adev,
				  void *entry, u32 irqs_min, u32 irqs_num);
void hinic5_ubus_irq_vectors_free(struct hinic5_adev *adev);
int hinic5_ubus_irq_vector(struct hinic5_adev *adev, u32 idx);
int hinic5_ub_init_device_info(struct hinic5_adev *adev);
int hinic5_ubus_virt_configure(hinic_ub_dev *ubus_dev, int ue_idx, bool is_en);
void hinic5_ubus_numvds_store_vds_process(struct hinic5_adev *adev, int nums);
void hinic5_ubus_probe_fault_process(struct hinic5_adev *adev);

#endif
#endif
