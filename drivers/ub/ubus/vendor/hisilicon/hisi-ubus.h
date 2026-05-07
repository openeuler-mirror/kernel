/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (c) HiSilicon Technologies Co., Ltd. 2025. All rights reserved.
 */

#ifndef __HISI_UBUS_H__
#define __HISI_UBUS_H__

#include <ub/ubus/ubus.h>

#define MEM_INFO_NUM			5
#define MB_SIZE_OFFSET			20
#define HI_UBC_PRIVATE_DATA_RESERVED	3
#define HI_UBC_PRIVATE_DATA_RESERVED2	111
#define UB_MEM_VERSION_INVALID 0xffffffff
#define UB_MEM_VERSION_0 0
#define UB_MEM_VERSION_1 1
#define UB_MEM_VERSION_2 2

struct hi_mem_pa_info {
	u64 decode_addr;
	u32 cc_base_addr;
	u32 cc_base_size;
	u32 nc_base_addr;
	u32 nc_base_size;
};

struct hi_ubc_private_data {
	u32 ub_mem_version;
	u8 max_addr_bits;
	u8 reserved[HI_UBC_PRIVATE_DATA_RESERVED];
	struct hi_mem_pa_info mem_pa_info[MEM_INFO_NUM];
	u64 io_decoder_cmdq;
	u64 io_decoder_evtq;
	u8 features;
	u8 reserved2[HI_UBC_PRIVATE_DATA_RESERVED2];
};

int hi_eu_table_init(struct ub_bus_controller *ubc);
void hi_eu_table_uninit(struct ub_bus_controller *ubc);
int hi_eu_cfg(struct ub_bus_controller *ubc, bool add, u32 eid, u16 upi);
int hi_mem_decoder_create(struct ub_bus_controller *ubc);
void hi_mem_decoder_remove(struct ub_bus_controller *ubc);
void hi_register_ubmem_irq(struct ub_bus_controller *ubc);
void hi_unregister_ubmem_irq(struct ub_bus_controller *ubc);
int hi_send_entity_enable_msg(struct ub_entity *uent, u8 enable);
int hi_send_port_reset_msg(struct ub_entity *uent, u16 port_idx);
int ub_bus_controller_probe(struct ub_bus_controller *ubc);
void ub_bus_controller_remove(struct ub_bus_controller *ubc);
unsigned long long hi_feature_get(void);

#endif /* __HISI_UBUS_H__ */
