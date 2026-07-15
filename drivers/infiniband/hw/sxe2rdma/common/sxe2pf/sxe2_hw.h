/* SPDX-License-Identifier: GPL-2.0 */
/**
 * Copyright (C), 2020, sxe2rdma Technologies Co., Ltd.
 *
 * @file: sxe2_hw.h
 * @author: sxe2rdma
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#ifndef __SXE2_HW_H__
#define __SXE2_HW_H__

#ifdef SXE2_DPDK_DRIVER
#include "sxe2_osal.h"

#ifndef IEEE_8021Q_MAX_PRIORITIES
#define IEEE_8021Q_MAX_PRIORITIES 8
#endif
#ifndef IEEE_8021QAZ_MAX_TCS
#define IEEE_8021QAZ_MAX_TCS 8
#endif

#else
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/bitfield.h>
#include "sxe2_cmd_channel.h"
#include "sxe2_mbx_public.h"
#endif

#include "sxe2_cmd.h"
#include "sxe2_host_regs.h"

#define SXE2_BAR_RDMA_WB_START 0x03F0000
#define SXE2_BAR_RDMA_WB_END 0x0BFFFFF

#define SXE2_REG_INVALID_VALUE 0xffffffffU
#define SXE2_REG_RETRY_CNT 5

#define SXE2_FW_STATE_MASK 0xF0000
#define SXE2_FW_STATE_FINISH 0x20000
#define SXE2_FW_STATE_ABNORMAL 0x30000

#define SXE2_REG_UNACCESS (2)
#define sxe2_flush(hw) ((void)sxe2_read_reg((hw), SXE2_STATUS))
#define SXE2_REG_READ(hw, addr) sxe2_read_reg(hw, addr)
#define SXE2_REG_WRITE(hw, reg, value) sxe2_write_reg(hw, reg, value)

struct sxe2_adapter;

enum sxe2_hw_err_code {
	SXE2_HW_ERR_SUCCESS = 0,
	SXE2_HW_ERR_FAULT,
	SXE2_HW_ERR_TIMEDOUT,
	SXE2_HW_ERR_IO,
	SXE2_HW_ERR_INVAL,
};

struct sxe2_hw_cfg {
	u16 itr_gran;
	u16 credit_interval_gran;
};

struct sxe2_mac_info {
	u8 perm_addr[ETH_ALEN];
};

struct sxe2_map_info {
	void __iomem *addr;
	resource_size_t start;
	resource_size_t end;
	u32 bar_idx;
};

struct sxe2_hw_map {
	u32 map_cnt;
	struct sxe2_map_info maps[];
};

struct sxe2_hw {
	u8 *hw_map;
	struct sxe2_hw_cfg hw_cfg;
	void *adapter;
	struct sxe2_mac_info mac_info;

	u8 *pkg_copy;
	u32 pkg_size;

#ifndef SXE2_DPDK_DRIVER
	u32 (*reg_read)(const __iomem void *reg);
	void (*reg_write)(u32 value, __iomem void *reg);
	struct sxe2_fw_ver_msg fw_ver;
#endif
	bool is_pop_type;
};

struct sxe2_hw_vf_irq {
	u16 first_in_pf;
	u16 last_in_pf;
	u16 first_in_dev;
	u16 last_in_dev;
	u16 vfid_in_pf;
	u16 vfid_in_dev;
	u16 pf_id;
};

struct sxe2_hw_vf_queue {
	u16 txq_first_in_pf;
	u16 txq_cnt;
	u16 rxq_first_in_pf;
	u16 rxq_cnt;
	u16 vfid_in_pf;
};

struct sxe2_pause_stats {
	__le64 prio_xoff_rx[IEEE_8021Q_MAX_PRIORITIES];
	__le64 prio_xon_rx[IEEE_8021Q_MAX_PRIORITIES];
	__le64 prio_xon_tx[IEEE_8021Q_MAX_PRIORITIES];
	__le64 prio_xoff_tx[IEEE_8021Q_MAX_PRIORITIES];
	__le64 prio_xon_2_xoff[IEEE_8021Q_MAX_PRIORITIES];
	__le64 rx_pause;
	__le64 tx_pause;
};

void sxe2_hw_pause_stats_update(struct sxe2_hw *hw,
				u8 port_idx, bool prev_loaded,
				struct sxe2_pause_stats *cur,
				struct sxe2_pause_stats *prev);

void __iomem *sxe2_reg_addr_get(struct sxe2_hw *hw, resource_size_t reg);

#ifndef SXE2_DPDK_DRIVER
static inline void sxe2_hw_reg_handle_init(struct sxe2_hw *hw, u32 (*read)(const __iomem void *),
					   void (*write)(u32, __iomem void *))
{
	hw->reg_read = read;
	hw->reg_write = write;
}
#endif
void sxe2_write_reg(struct sxe2_hw *hw, u32 reg, u32 value);

u32 sxe2_read_reg(struct sxe2_hw *hw, u32 reg);

u64 sxe2_read_reg64(struct sxe2_hw *hw, u32 reg);

bool sxe2_hw_is_fault(struct sxe2_hw *hw);

u32 sxe2_hw_read_pcie_sys_ready(struct sxe2_hw *hw);

u32 sxe2_hw_evt_irq_cause_get(struct sxe2_hw *hw);

void sxe2_hw_irq_enable(struct sxe2_hw *hw, u16 irq_idx);

void sxe2_hw_irq_disable(struct sxe2_hw *hw, u16 irq_idx);

void sxe2_hw_irq_trigger(struct sxe2_hw *hw, u16 irq_idx);

void sxe2_hw_irq_dyn_ctl(struct sxe2_hw *hw, u16 irq_idx, u32 value);

void sxe2_hw_irq_itr_set(struct sxe2_hw *hw, u16 irq_idx, u16 itr_idx, u16 interval);

void sxe2_hw_irq_rate_limit_set(struct sxe2_hw *hw, u16 irq_idx, u16 intrl);

u32 sxe2_hw_irq_gran_info_get(struct sxe2_hw *hw);

void sxe2_hw_txq_irq_cause_setup(struct sxe2_hw *hw, u16 txq_idx, u16 itr_idx, u16 irq_idx);

void sxe2_hw_txq_irq_cause_clear(struct sxe2_hw *hw, u16 txq_idx);

void sxe2_hw_txq_irq_cause_switch(struct sxe2_hw *hw, u16 txq_idx, bool enable);
void sxe2_hw_rxq_irq_cause_setup(struct sxe2_hw *hw, u16 rxq_idx, u16 itr_idx, u16 irq_idx);
void sxe2_hw_rxq_irq_idx_change(struct sxe2_hw *hw, u16 rxq_idx, u16 irq_idx);

void sxe2_hw_rxq_irq_idx_change(struct sxe2_hw *hw, u16 rxq_idx, u16 irq_idx);

void sxe2_hw_rxq_irq_cause_clear(struct sxe2_hw *hw, u16 rxq_idx);

void sxe2_hw_rxq_irq_cause_switch(struct sxe2_hw *hw, u16 rxq_idx, bool enable);

void sxe2_hw_evt_irq_cfg(struct sxe2_hw *hw, u32 value, u16 itr_idx, u16 irq_idx);

void sxe2_hw_fwq_irq_cfg(struct sxe2_hw *hw, u16 itr_idx, u16 irq_idx);

void sxe2_hw_mbxq_irq_cfg(struct sxe2_hw *hw, u16 itr_idx, u16 irq_idx);

void sxe2_hw_evt_irq_clear(struct sxe2_hw *hw);

u32 sxe2_hw_evt_irq_mask_get(struct sxe2_hw *hw);

void sxe2_hw_fwq_irq_clear(struct sxe2_hw *hw);

void sxe2_hw_mbxq_irq_clear(struct sxe2_hw *hw);

struct sxe2_hw_rxq_ctxt {
	u64 base_addr;
	u16 depth;

	u16 dbuff_len;
	u16 hbuff_len;
	u8 hsplit_type;
	u8 desc_type;
	u8 crc_strip;
	u8 l2tag1_show;
	u8 hsplit_0;
	u8 hsplit_1;
	u8 inner_vlan_strip;

	u8 lro_enable;
	u8 cpuid;
	u16 max_frame_size;
	u16 lro_desc_max;
	u8 relax_data;
	u8 relax_wb_desc;
	u8 relax_rd_desc;

	u8 tphrdesc_enable;
	u8 tphwdesc_enable;
	u8 tphdata_enable;
	u8 tphhead_enable;
	u8 low_desc_waterline;
	u16 vfid;
	u8 pfid;

	u8 vfen;
	u16 vsi_id;

	u8 pref_enable;
	u16 head;
};

s32 sxe2_hw_fw_tq_enable(struct sxe2_hw *hw, u16 depth, dma_addr_t addr);

void sxe2_hw_fw_tq_disable(struct sxe2_hw *hw);

s32 sxe2_hw_fw_tq_is_idle(struct sxe2_hw *hw);

void sxe2_hw_fw_tq_write_tail(struct sxe2_hw *hw, u32 value);

u32 sxe2_hw_fw_tq_read_head(struct sxe2_hw *hw);

u32 sxe2_hw_fw_tq_get_error(struct sxe2_hw *hw);

s32 sxe2_hw_fw_rq_enable(struct sxe2_hw *hw, u16 depth, dma_addr_t addr);

void sxe2_hw_fw_rq_disable(struct sxe2_hw *hw);

s32 sxe2_hw_fw_rq_is_idle(struct sxe2_hw *hw);

void sxe2_hw_fw_rq_write_tail(struct sxe2_hw *hw, u32 value);

u32 sxe2_hw_fw_rq_read_head(struct sxe2_hw *hw);

u32 sxe2_hw_fw_rq_get_error(struct sxe2_hw *hw);

s32 sxe2_hw_mbx_tq_enable(struct sxe2_hw *hw, u16 depth, dma_addr_t addr);

void sxe2_hw_mbx_tq_disable(struct sxe2_hw *hw);

void sxe2_hw_mbx_tq_write_tail(struct sxe2_hw *hw, u32 value);

u32 sxe2_hw_mbx_tq_read_head(struct sxe2_hw *hw);

u32 sxe2_hw_mbx_tq_get_error(struct sxe2_hw *hw);

s32 sxe2_hw_mbx_rq_enable(struct sxe2_hw *hw, u16 depth, dma_addr_t addr);

void sxe2_hw_mbx_rq_disable(struct sxe2_hw *hw);

void sxe2_hw_mbx_rq_write_tail(struct sxe2_hw *hw, u32 value);

u32 sxe2_hw_mbx_rq_read_head(struct sxe2_hw *hw);

u32 sxe2_hw_mbx_rq_get_error(struct sxe2_hw *hw);

void sxe2_hw_rxq_ctxt_cfg(struct sxe2_hw *hw, struct sxe2_hw_rxq_ctxt *rxq_ctxt, u16 rxq_idx);

s32 sxe2_hw_rxq_ctrl(struct sxe2_hw *hw, u16 reg_idx, bool enable, bool wait, bool cde);

s32 sxe2_hw_rxq_status_check(struct sxe2_hw *hw, u32 reg_idx, bool enable);

u32 sxe2_fw_state_get(struct sxe2_hw *hw);

u32 sxe2_fw_ver_get(struct sxe2_hw *hw);

u32 sxe2_fw_comp_ver_get(struct sxe2_hw *hw);

u32 sxe2_fw_mode_get(struct sxe2_hw *hw);
u32 sxe2_fw_pop_get(struct sxe2_hw *hw);

void sxe2_hw_l2tag_accept(struct sxe2_hw *hw, u16 vsi_hw_id);

s32 sxe2_hw_desc_vlan_param_check(bool pvlan_exist, bool is_strip, u16 tpid);

s32 sxe2_hw_desc_vlan_strip_switch(struct sxe2_hw *hw, u16 vsi_hw_id,
				   u16 tpid, bool pvlan_exist, bool en);

s32 sxe2_hw_desc_vlan_insert_switch(struct sxe2_hw *hw, u16 vsi_hw_id, u16 tpid,
				    bool pvlan_exist, bool en);

s32 sxe2_hw_port_vlan_setup(struct sxe2_hw *hw, u16 vsi_hw_id, u16 vlan_info, u16 tpid);

void sxe2_hw_rx_vlan_filter_switch(struct sxe2_hw *hw, u16 vsi_hw_id, bool en);

void sxe2_hw_vsi_loopback_switch(struct sxe2_hw *hw, u16 vsi_hw_id, bool en);

void sxe2_hw_vsi_mac_spoofchk_switch(struct sxe2_hw *hw, u16 vsi_hw_id, bool en);

void sxe2_hw_vsi_vlan_spoofchk_switch(struct sxe2_hw *hw, u16 vsi_hw_id, bool en);

u32 sxe2_hw_fw_irq_cause_get(struct sxe2_hw *hw);

s32 sxe2_hw_corer_irq_cause_get(struct sxe2_hw *hw);

void sxe2_hw_trigger_pfr(struct sxe2_hw *hw);

s32 sxe2_hw_pfr_done(struct sxe2_hw *hw);

void sxe2_hw_trigger_corer(struct sxe2_hw *hw);

s32 sxe2_hw_corer_done(struct sxe2_hw *hw);

void sxe2_hw_stop_drop(struct sxe2_hw *hw);

s32 sxe2_hw_stop_drop_done(struct sxe2_hw *hw);

u32 sxe2_hw_heartbeat_get(struct sxe2_hw *hw);

void sxe2_hw_trigger_vfr(struct sxe2_hw *hw, u16 vf_id);

u32 sxe2_hw_vfr_done(struct sxe2_hw *hw, u16 vf_id);

void sxe2_hw_vf_active(struct sxe2_hw *hw, u16 vf_id);

void sxe2_hw_vf_deactive(struct sxe2_hw *hw, u16 vf_id);

bool sxe2_hw_vflr_cause_get(struct sxe2_hw *hw, u16 vf_id_in_dev);

void sxe2_hw_vflr_cause_clear(struct sxe2_hw *hw, u16 vf_id_in_dev);

s32 sxe2_hw_desc_outer_vlan_insert_switch(struct sxe2_hw *hw, u16 vsi_hw_id,
					  u16 tpid, bool pvlan_exist, bool en);

s32 sxe2_hw_port_inner_vlan_acceptrule_setup(struct sxe2_hw *hw, u16 vsi_hw_id,
					     bool acceptedtagged,
					     bool accepteduntagged);

s32 sxe2_hw_port_outer_vlan_acceptrule_setup(struct sxe2_hw *hw, u16 vsi_hw_id,
					     u16 tpid, bool acceptedtagged,
					     bool accepteduntagged);

void sxe2_hw_vf_irq_cfg(struct sxe2_hw *hw, struct sxe2_hw_vf_irq *vf_irq);

void sxe2_hw_vf_queue_cfg(struct sxe2_hw *hw, struct sxe2_hw_vf_queue *vf_queue);

void sxe2_hw_ptp_main_enable(struct sxe2_hw *hw);

void sxe2_hw_ptp_main_disable(struct sxe2_hw *hw);

bool sxe2_hw_ptp_main_is_enabled(struct sxe2_hw *hw);
void sxe2_hw_ptp_init_incval(struct sxe2_hw *hw, u64 incval);

void sxe2_hw_ptp_tsyn_switch(struct sxe2_hw *hw, bool on);
void sxe2_hw_ptp_tsyn_event_switch(struct sxe2_hw *hw, bool on);
u64 sxe2_hw_ptp_get_event_second(struct sxe2_hw *hw, u32 index);
u64 sxe2_hw_ptp_get_event_nanosecond(struct sxe2_hw *hw, u32 index);
void sxe2_hw_ptp_aux_in_set(struct sxe2_hw *hw, u32 index, u32 value);

bool sxe2_hw_ptp_tx_tstamp_read(struct sxe2_hw *hw, u8 port_id, u32 index, u64 *timestamp);
bool sxe2_hw_ptp_mac_tx_tstamp_read(struct sxe2_hw *hw, u8 phy_id, u8 index, u64 *timestamp);
void sxe2_hw_ptp_tx_tstamp_discard(struct sxe2_hw *hw, u8 port_id, u32 index);
void sxe2_hw_ptp_mac_tx_tstamp_discard(struct sxe2_hw *hw, u8 phy_id, u32 index);

void sxe2_hw_ptp_mac_tx_tstamp_clear_all(struct sxe2_hw *hw, u8 phy_id, u32 reg_idx);
bool sxe2_hw_ptp_acquire_1588_lock(struct sxe2_hw *hw);
void sxe2_hw_ptp_release_1588_lock(struct sxe2_hw *hw);
void sxe2_hw_ptp_1588_timestamp_read(struct sxe2_hw *hw, u64 *second, u64 *nanosecond);
void sxe2_hw_ptp_1588_timestamp_write(struct sxe2_hw *hw, u64 second, u32 nanosecond);
void sxe2_hw_ptp_1588_clockout_write(struct sxe2_hw *hw, u32 index,
				     u64 period, u64 second, u64 nanosecond);
void sxe2_hw_ptp_1588_timestamp_adjust(struct sxe2_hw *hw, u32 nanosecond, bool neg);
void sxe2_hw_ptp_1588_timestamp_adjust_at_time(struct sxe2_hw *hw, u32 nanosecond);
u32 sxe2_hw_ptp_auxout_get(struct sxe2_hw *hw, u32 index);
void sxe2_hw_ptp_auxout_set(struct sxe2_hw *hw, u32 index, u32 value);

s32 sxe2_hw_ptp_stat_get(struct sxe2_hw *hw);

s32 sxe2_hw_ptp_stat_get(struct sxe2_hw *hw);

void sxe2_hw_vf_queue_decfg(struct sxe2_hw *hw, struct sxe2_hw_vf_queue *vf_queue);

void sxe2_hw_vf_irq_decfg(struct sxe2_hw *hw, struct sxe2_hw_vf_irq *vf_irq);

void sxe2_hw_ipsec_tcam_clear(struct sxe2_hw *hw, u32 sa_index);

#endif
