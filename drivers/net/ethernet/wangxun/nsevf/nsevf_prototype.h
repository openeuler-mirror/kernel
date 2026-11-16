/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (c) 2018 - 2021 Beijing WangXun Technology Co., Ltd. */

#ifndef _NSEVF_PROTOTYPE_H_
#define _NSEVF_PROTOTYPE_H_

#include "nsevf_type.h"
#include "nsevf_alloc.h"
#include "virtchnl.h"

struct work_struct;

/* Prototypes for shared code functions that are not in
 * the standard function pointer structures.  These are
 * mostly because they are needed even before the init
 * has happened and will assist in the early SW and FW
 * setup.
 */

/* adminq functions */
enum nsevf_status nsevf_init_mailboxq(struct nsevf_hw *hw);
enum nsevf_status nsevf_shutdown_mailboxq(struct nsevf_hw *hw);
enum nsevf_status nsevf_aq_shutdown_mailboxq(struct nsevf_hw *hw);

enum nsevf_status nsevf_fdir_init_utilq(struct nsevf_hw *hw);
void nsevf_fdir_shutdown_utilq(struct nsevf_hw *hw);

enum nsevf_status nsevf_clean_arq_element(struct nsevf_hw *hw,
					  struct nsevf_ctl_q_info *aq,
					  struct nsevf_arq_event_info *e,
					  u16 *pending);
enum nsevf_status
nsevf_asq_send_command(struct nsevf_hw *hw, struct nsevf_ctl_q_info *aq,
		       struct nsevf_aq_desc *desc, void *buff, /* can be NULL */
		       u16 buff_size,
		       struct nsevf_asq_cmd_details *cmd_details);
bool nsevf_asq_done(struct nsevf_hw *hw, struct nsevf_ctl_q_info *aq,
		    struct nsevf_aq_desc *desc_on_ring);

/* debug function for adminq */
void nsevf_debug_aq(struct nsevf_hw *hw, void *desc, void *buffer, u16 buf_len);

bool nsevf_check_asq_alive(struct nsevf_hw *hw, struct nsevf_ctl_q_info *aq);
bool nsevf_check_arq_alive(struct nsevf_hw *hw, struct nsevf_ctl_q_info *aq);

const char *nsevf_aq_str(struct nsevf_hw *hw, enum nse_aq_err aq_err);
const char *nsevf_stat_str(struct nsevf_hw *hw, enum nsevf_status stat_err);

enum nsevf_status nsevf_set_mac_type(struct nsevf_hw *hw);
void nsevf_aq_cmd_background_task(struct work_struct *work);
void nsevf_locate_final_l3_l4_hdr(struct sk_buff *skb, void **ret_l4_hdr,
				  void **ret_l3_hdr, void **ret_1st_vlan_hdr,
				  u16 *l3_proto, u8 *l4_proto);

/* prototype for functions used for SW spinlocks */
void nsevf_init_spinlock(struct nsevf_spinlock *sp);
void nsevf_acquire_spinlock(struct nsevf_spinlock *sp);
void nsevf_release_spinlock(struct nsevf_spinlock *sp);
void nsevf_destroy_spinlock(struct nsevf_spinlock *sp);

void nsevf_vf_parse_hw_config(struct nsevf_hw *hw,
			      struct virtchnl_vf_resource *msg);
enum nsevf_status nsevf_vf_reset(struct nsevf_hw *hw);
enum nsevf_status
nsevf_aq_send_msg_to_pf(struct nsevf_hw *hw, enum virtchnl_ops v_opcode,
			enum virtchnl_status_code v_retval, u8 *msg, u16 msglen,
			struct nsevf_asq_cmd_details *cmd_details);
enum nsevf_status
nsevf_aq_debug_dump(struct nsevf_hw *hw, u8 cluster_id, u8 table_id,
		    u32 start_index, u16 buff_size, void *buff,
		    u16 *ret_buff_size, u8 *ret_next_table, u32 *ret_next_index,
		    struct nsevf_asq_cmd_details *cmd_details);

void nsevf_stat_update64(u64 new_data, bool prev_stat_loaded, u64 *prev_stat,
			 u64 *cur_stat);

#endif /* _NSEVF_PROTOTYPE_H_ */
