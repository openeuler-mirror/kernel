/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2024 Huawei Technologies Co., Ltd */

#ifndef ROCE_CMD_H
#define ROCE_CMD_H

#include "roce.h"
#include "roce_dfx.h"
#include "roce_srq.h"

#define ROCE_VLAN_ID_MASK 0x7FFF
#define ROCE_VLAN_N_VID 4096
#define ROCE_VNI_N_VID 0xFFFFFF
#define ROCE_CMD_DEFAULT_SIZE 12

#define ERR_EXIST	   6
#define ERR_NOT_FOUND   13
struct roce_cmd_get_group_id {
	u8 status;
	u8 version;
	u8 rsvd0[6];

	u16 func_id;
	u8 group_rc_cos;
	u8 group_ud_cos;
	u8 group_xrc_cos;
};

struct roce_group_id {
	u8 group_rc_cos;
	u8 group_ud_cos;
	u8 group_xrc_cos;
	u8 rsvd;
};

#define roce3_msg_to_mgmt_sync(hwdev, cmd, buf_in, in_size, buf_out, out_size) \
	(hinic3_msg_to_mgmt_sync(hwdev, HINIC3_MOD_ROCE, cmd, buf_in, in_size, \
		buf_out, out_size, 0, HINIC3_CHANNEL_ROCE))

int roce3_cfg_func_tbl_er_fwd_id_compact(void *hwdev, u32 bond_tbl_val, u16 func_id);

int roce3_set_port_tbl_bond_state(void *hwdev, u8 bond_state, u16 func_id);

int roce3_add_mac_tbl_mac_entry(void *hwdev, u8 *mac_addr, u32 vlan_id, u16 er_fwd_id, u16 func_id);
int roce3_del_mac_tbl_mac_entry(void *hwdev, u8 *mac_addr, u32 vlan_id, u16 er_fwd_id, u16 func_id);
typedef int (*roce3_modify_mac_tbl)(void *hwdev, u8 *mac_addr, u32 vlan_id,
	u16 er_fwd_id, u16 func_id);
void roce3_add_ipsu_tbl_mac_entry(void *hwdev, u8 *mac_addr, u32 vlan_id, u16 func_id, u8 er_id);
void roce3_del_ipsu_tbl_mac_entry(void *hwdev, u8 *mac_addr, u32 vlan_id, u16 func_id, u8 er_id);
typedef void (*roce3_modify_ipsu_tbl_mac)(void *hwdev, u8 *mac_addr,
	u32 vlan_id, u16 func_id, u8 er_id);

int roce3_do_cache_out(void *hwdev, u8 cl_id, u16 func_id);

int roce3_set_cfg_ccf_param(void *hwdev, u16 func_id, u32 *ccf_param);
int roce3_set_cfg_ipqcn_param(void *hwdev, u16 func_id, u32 *ipqcn_param);
int roce3_set_cfg_ldcp_param(void *hwdev, u16 func_id, u32 *ldcp_param);
int roce3_set_cfg_dcqcn_param(void *hwdev, u16 func_id, u32 *dcqcn_param);
int roce3_set_bw_ctrl_state(struct roce3_device *rdev, u8 cmd, struct roce3_bw_ctrl_inbuf *inbuf);
int roce3_query_bw_ctrl_state(struct roce3_device *rdev, struct roce3_bw_ctrl_param *bw_ctrl_param);

int roce3_set_cap_cfg(void *hwdev, u16 index, u32 *cap_cfg);
int roce3_get_cap_cfg(void *hwdev, u16 index, u32 *cap_cfg);
int roce3_clear_cap_counter(void *hwdev, u16 index, u32 *value);
int roce3_read_cap_counter(void *hwdev, u16 index, u32 *value);

int roce3_set_func_tbl_func_state(struct roce3_device *rdev, u8 func_state);
int roce3_get_func_table(void *hwdev, u16 func_id, u32 *func_tbl_value);
int roce3_set_func_tbl_cpu_endian(void *hwdev, u8 cpu_endian, u16 func_id);
int roce3_init_cfg_info(struct roce3_device *rdev);
int roce3_del_func_res(struct roce3_device *rdev);
int roce3_get_group_id(u16 func_id, void *hwdev, struct roce_group_id *group_id);

#endif /* ROCE_CMD_H */
