/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2021 Ramaxel Memory Technology, Ltd */

#ifndef UNF_PORTMAN_H
#define UNF_PORTMAN_H

#include "unf_type.h"
#include "unf_lport.h"

#define UNF_LPORT_POLL_TIMER ((u32)(1 * 1000))
#define UNF_TX_CREDIT_REG_32_G 0x2289420
#define UNF_RX_CREDIT_REG_32_G 0x228950c
#define UNF_CREDIT_REG_16_G 0x2283418
#define UNF_PORT_OFFSET_BASE 0x10000
#define UNF_CREDIT_EMU_VALUE 0x20
#define UNF_CREDIT_VALUE_32_G 0x8
#define UNF_CREDIT_VALUE_16_G 0x8000000080008

struct unf_nportid_map {
	u32 sid;
	u32 did;
	void *rport[1024];
	void *lport;
};

struct unf_global_card_thread {
	struct list_head card_list_head;
	spinlock_t global_card_list_lock;
	u32 card_num;
};

/* Global L_Port MG,manage all L_Port */
struct unf_global_lport {
	struct list_head lport_list_head;

	/* Temporary list,used in hold list traverse */
	struct list_head intergrad_head;

	/* destroy list,used in card remove */
	struct list_head destroy_list_head;

	/* Dirty list,abnormal port */
	struct list_head dirty_list_head;
	spinlock_t global_lport_list_lock;
	u32 lport_sum;
	u8 dft_mode;
	bool start_work;
};

struct unf_port_action {
	u32 action;
	u32 (*unf_action)(struct unf_lport *lport, void *input);
};

struct unf_reset_port_argin {
	u32 port_id;
};

extern struct unf_global_lport global_lport_mgr;
extern struct unf_global_card_thread card_thread_mgr;
extern struct workqueue_struct *unf_wq;

struct unf_lport *unf_find_lport_by_port_id(u32 port_id);
struct unf_lport *unf_find_lport_by_scsi_hostid(u32 scsi_host_id);
void *
unf_lport_create_and_init(void *private_data,
			  struct unf_low_level_functioon_op *low_level_op);
u32 unf_fc_port_link_event(void *lport, u32 events, void *input);
u32 unf_release_local_port(void *lport);
void unf_lport_route_work(struct work_struct *work);
void unf_lport_update_topo(struct unf_lport *lport,
			   enum unf_act_topo active_topo);
void unf_lport_ref_dec(struct unf_lport *lport);
u32 unf_lport_ref_inc(struct unf_lport *lport);
void unf_lport_ref_dec_to_destroy(struct unf_lport *lport);
void unf_port_mgmt_deinit(void);
void unf_port_mgmt_init(void);
void unf_show_dirty_port(bool show_only, u32 *dirty_port_num);
void *unf_lookup_lport_by_nportid(void *lport, u32 nport_id);
u32 unf_is_lport_valid(struct unf_lport *lport);
int unf_lport_reset_port(struct unf_lport *lport, u32 flag);
int unf_cm_ops_handle(u32 type, void **arg_in);
u32 unf_register_scsi_host(struct unf_lport *lport);
void unf_unregister_scsi_host(struct unf_lport *lport);
void unf_destroy_scsi_id_table(struct unf_lport *lport);
u32 unf_lport_login(struct unf_lport *lport, enum unf_act_topo act_topo);
u32 unf_init_scsi_id_table(struct unf_lport *lport);
void unf_set_lport_removing(struct unf_lport *lport);
void unf_lport_release_lw_funop(struct unf_lport *lport);
void unf_show_all_rport(struct unf_lport *lport);
void unf_disc_state_ma(struct unf_lport *lport, enum unf_disc_event evnet);
int unf_get_link_lose_tmo(struct unf_lport *lport);
u32 unf_port_release_rport_index(struct unf_lport *lport, void *input);
int unf_cm_reset_port(u32 port_id);

#endif
