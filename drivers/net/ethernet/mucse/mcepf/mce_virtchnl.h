/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2024-2026 Mucse Corporation. */

#ifndef _MCE_CONTROLQ_H_
#define _MCE_CONTROLQ_H_

#define FLAG_VF_NONE_PROMISC (0x00000000)
#define FLAG_VF_UNICAST_PROMISC (0x00000001)
#define FLAG_VF_MULTICAST_PROMISC (0x00000002)

enum PF2VF_OPCODE {
	SET_VF_VLAN = 1,
	SET_VF_DSCP,
};

void mce_mbx_vf_req_isr(struct mce_mbx_info *mbx, struct mbx_req *req);
void mce_mbx_vf_event_req_isr(struct mce_mbx_info *mbx, int event_id);

static inline struct mce_mbx_info *mce_get_vf_mbx(struct mce_hw *hw, int vfd)
{
	if (vfd >= MAX_VF_CNT)
		return NULL;
	return &hw->vf_mbx[vfd];
}

static inline int mce_mbx_send_event_to_vf(struct mce_hw *hw,
					   int vfd,
					   enum PF2VF_EVENT_ID event_id,
					   int timeout_us)
{
	struct mce_mbx_info *mbx = mce_get_vf_mbx(hw, vfd);
	struct vf_info *vfinfo = mbx->vfinfo;

	if (!mbx)
		return -EINVAL;
	if (!vfinfo->init_done)
		return 0;

	return mce_mbx_send_event(mbx, event_id, timeout_us);
}

int mce_broadcast_event_to_vf(struct mce_pf *pf, enum PF2VF_EVENT_ID event, int timeout_us);

int mce_mbx_send_reset_vf_cmd(struct mce_pf *pf, int vfd);
void mce_vf_notify_link_state(struct mce_pf *pf);
void mce_vf_notify_fcs_state(struct mce_pf *pf, bool on);
void mce_vf_notify_spoof_state(struct mce_pf *pf, int vfid, bool on);
void mce_vf_notify_trust_state(struct mce_pf *pf, int vfid, bool on);
void mce_vf_notify_dscp_state(struct mce_pf *pf, int vfid, bool on);

static inline int mce_mbx_send_cmd_to_vf(struct mce_hw *hw,
					 int vfd,
					 int opcode,
					 int *data,
					 int data_bytes,
					 struct mbx_resp *resp,
					 int timeout_us)
{
	struct mce_mbx_info *mbx = mce_get_vf_mbx(hw, vfd);

	if (!mbx)
		return -EINVAL;

	return mce_mbx_send_req(mbx, opcode, data, data_bytes, resp, timeout_us);
}

int mce_broadcast_cmd_to_vf(struct mce_pf *pf, enum PF2VF_OPCODE opcode,
			    int *data, int data_bytes, int timeout_us);

#endif /* _MCE_CONTROLQ_H_ */
