/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2021 Ramaxel Memory Technology, Ltd */

#ifndef SPNIC_NIC_H
#define SPNIC_NIC_H
#include <linux/types.h>
#include "sphw_common.h"
#include "spnic_nic_io.h"
#include "spnic_nic_cfg.h"
#include "spnic_mag_cmd.h"

#define MSG_TO_MGMT_SYNC_RETURN_ERR(err, status, out_size)	\
		((err) || (status) || !(out_size))

struct spnic_sq_attr {
	u8 dma_attr_off;
	u8 pending_limit;
	u8 coalescing_time;
	u8 intr_en;
	u16 intr_idx;
	u32 l2nic_sqn;
	u64 ci_dma_base;
};

struct vf_data_storage {
	u8 drv_mac_addr[ETH_ALEN];
	u8 user_mac_addr[ETH_ALEN];
	bool registered;
	bool use_specified_mac;
	u16 pf_vlan;
	u8 pf_qos;
	u32 max_rate;
	u32 min_rate;

	bool link_forced;
	bool link_up;		/* only valid if VF link is forced */
	bool spoofchk;
	bool trust;
	u16 num_qps;
};

struct spnic_port_routine_cmd {
	bool mpu_send_sfp_info;
	bool mpu_send_sfp_abs;

	struct mag_cmd_get_xsfp_info std_sfp_info;
	struct mag_cmd_get_xsfp_present abs;
};

struct spnic_nic_cfg {
	void				*hwdev;
	void				*pcidev_hdl;
	void				*dev_hdl;

	struct spnic_io_queue		*sq;
	struct spnic_io_queue		*rq;

	u16				rx_buff_len;

	u16				num_qps;
	u16				max_qps;

	void				*ci_vaddr_base;
	dma_addr_t			ci_dma_base;

	/* including rq and rx doorbell */
	u16				allocated_num_db;
	u8 __iomem			**db_addr;

	u8				link_status;

	u16				max_vfs;
	struct vf_data_storage		*vf_infos;
	struct spnic_dcb_state		dcb_state;

	u64				feature_cap;

	struct semaphore		cfg_lock;

	/* Valid when pfc is disable */
	bool				pause_set;
	struct nic_pause_config		nic_pause;

	u8				pfc_en;
	u8				pfc_bitmap;

	struct nic_port_info		port_info;

	/* percentage of pf link bandwidth */
	u32				pf_bw_limit;

	struct spnic_port_routine_cmd	rt_cmd;
	/* mutex used for copy sfp info */
	struct mutex			sfp_mutex;
};

struct vf_msg_handler {
	u16 cmd;
	int (*handler)(struct spnic_nic_cfg *nic_cfg, u16 vf, void *buf_in, u16 in_size,
		       void *buf_out, u16 *out_size);
};

struct nic_event_handler {
	u16 cmd;
	void (*handler)(void *hwdev, void *buf_in, u16 in_size, void *buf_out, u16 *out_size);
};

int spnic_set_ci_table(void *hwdev, struct spnic_sq_attr *attr);

int l2nic_msg_to_mgmt_sync(void *hwdev, u16 cmd, void *buf_in, u16 in_size,
			   void *buf_out, u16 *out_size);

int l2nic_msg_to_mgmt_sync_ch(void *hwdev, u16 cmd, void *buf_in, u16 in_size,
			      void *buf_out, u16 *out_size, u16 channel);

int spnic_cfg_vf_vlan(struct spnic_nic_cfg *nic_cfg, u8 opcode, u16 vid, u8 qos, int vf_id);

int spnic_vf_event_handler(void *hwdev, void *pri_handle, u16 cmd, void *buf_in, u16 in_size,
			   void *buf_out, u16 *out_size);

void spnic_pf_event_handler(void *hwdev, void *pri_handle, u16 cmd, void *buf_in, u16 in_size,
			    void *buf_out, u16 *out_size);

int spnic_pf_mbox_handler(void *hwdev, void *pri_handle, u16 vf_id, u16 cmd, void *buf_in,
			  u16 in_size, void *buf_out, u16 *out_size);

u8 spnic_nic_sw_aeqe_handler(void *hwdev, u8 event, u8 *data);

int spnic_vf_func_init(struct spnic_nic_cfg *nic_cfg);

void spnic_vf_func_free(struct spnic_nic_cfg *nic_cfg);

void spnic_notify_dcb_state_event(struct spnic_nic_cfg *nic_cfg, struct spnic_dcb_state *dcb_state);

int spnic_save_dcb_state(struct spnic_nic_cfg *nic_cfg, struct spnic_dcb_state *dcb_state);

void spnic_notify_vf_link_status(struct spnic_nic_cfg *nic_cfg, u16 vf_id, u8 link_status);

int spnic_vf_mag_event_handler(void *hwdev, void *pri_handle, u16 cmd,
			       void *buf_in, u16 in_size, void *buf_out, u16 *out_size);

void spnic_pf_mag_event_handler(void *hwdev, void *pri_handle, u16 cmd,
				void *buf_in, u16 in_size, void *buf_out, u16 *out_size);

int spnic_pf_mag_mbox_handler(void *hwdev, void *pri_handle, u16 vf_id,
			      u16 cmd, void *buf_in, u16 in_size, void *buf_out, u16 *out_size);

#endif
