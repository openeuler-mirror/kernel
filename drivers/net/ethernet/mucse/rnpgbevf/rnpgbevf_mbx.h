/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2022 - 2024 Mucse Corporation. */

#ifndef _RNPGBEVF_MBX_H_
#define _RNPGBEVF_MBX_H_

#include "vf.h"

struct rnpgbevf_hw;

struct counter {
	union {
		struct {
			unsigned short pf_req;
			unsigned short pf_ack;
		};
		struct {
			unsigned short cpu_req;
			unsigned short cpu_ack;
		};
	};
	unsigned short vf_req;
	unsigned short vf_ack;
} __packed;

#define PF2VF_MBOX_VEC(mbx, vf) (mbx->pf2vf_mbox_vec_base + 4 * (vf))
#define CPU2VF_MBOX_VEC(mbx, vf) (mbx->cpu2vf_mbox_vec_base + 4 * (vf))
#define PF_VF_SHM(mbx, vf)                                                     \
	((mbx->pf_vf_shm_base) + (64 * (vf)))
	/* for PF1 rtl will remap 6000 to 0xb000 */
#define PF2VF_COUNTER(mbx, vf) (PF_VF_SHM(mbx, vf) + 0)
#define VF2PF_COUNTER(mbx, vf) (PF_VF_SHM(mbx, vf) + 4)
#define PF_VF_SHM_DATA(mbx, vf) (PF_VF_SHM(mbx, vf) + 8)
#define VF2PF_MBOX_CTRL(mbx, vf) ((mbx->vf2pf_mbox_ctrl_base) + (4 * (vf)))
#define CPU_VF_SHM(mbx, vf) (mbx->cpu_vf_shm_base + (64 * (vf)))
#define CPU2VF_COUNTER(mbx, vf) (CPU_VF_SHM(mbx, vf) + 0)
#define VF2CPU_COUNTER(mbx, vf) (CPU_VF_SHM(mbx, vf) + 4)
#define CPU_VF_SHM_DATA(mbx, vf) (CPU_VF_SHM(mbx, vf) + 8)
#define VF2CPU_MBOX_CTRL(mbx, vf) (mbx->vf2cpu_mbox_ctrl_base + 64 * (vf))
#define CPU_VF_MBOX_MASK_LO(mbx, vf) (mbx->cpu_vf_mbox_mask_lo_base + 64 * (vf))
#define CPU_VF_MBOX_MASK_HI(mbx, vf) (mbx->cpu_vf_mbox_mask_hi_base + 64 * (vf))
#define MBOX_CTRL_REQ (0x1 << 0)
#define MBOX_CTRL_VF_HOLD_SHM (0x1 << 2) /* VF:WR, PF:RO */
#define MBOX_IRQ_EN 0
#define MBOX_IRQ_DISABLE 1
#define RNPGBE_VFMAILBOX_SIZE 14 /* 16 32 bit words - 64 bytes */
#define RNPGBE_ERR_MBX -100

struct mbx_shm {
	u32 stat;
#define MBX_ST_PF_ACK (0x1 << 0)
#define MBX_ST_PF_STS (0x1 << 1)
#define MBX_ST_PF_RST (0x1 << 2)
#define MBX_ST_VF_ACK (0x1 << 3)
#define MBX_ST_VF_REQ (0x1 << 4)
#define MBX_ST_VF_RST (0x1 << 5)
#define MBX_ST_CPU_ACK (0x1 << 6)
#define MBX_ST_CPU_REQ (0x1 << 7)

	u32 data[RNPGBE_VFMAILBOX_SIZE];
} __aligned(4);

/* If it's a RNPGBE_VF_* msg then it originates in the VF and is sent to the
 * PF.  The reverse is true if it is RNPGBE_PF_*.
 * Message ACK's are the value or'd with 0xF0000000
 */
#define RNPGBE_VT_MSGTYPE_ACK 0x80000000
/* Messages below or'd with
 * this are the ACK
 */
#define RNPGBE_VT_MSGTYPE_NACK 0x40000000
/* Messages below or'd with
 * this are the NACK
 */
#define RNPGBE_VT_MSGTYPE_CTS 0x20000000
/* Indicates that VF is still
 * clear to send requests
 */
#define RNPGBE_VT_MSGINFO_SHIFT 14
/* bits 23:16 are used for exra info for certain messages */
#define RNPGBE_VT_MSGINFO_MASK (0xFF << RNPGBE_VT_MSGINFO_SHIFT)

/* mailbox API, legacy requests */
#define RNPGBE_VF_RESET 0x01 /* VF requests reset */
#define RNPGBE_VF_SET_MAC_ADDR 0x02 /* VF requests PF to set MAC addr */
#define RNPGBE_VF_SET_MULTICAST 0x03 /* VF requests PF to set MC addr */
#define RNPGBE_VF_SET_VLAN 0x04 /* VF requests PF to set VLAN */

/* mailbox API, version 1.0 VF requests */
#define RNPGBE_VF_SET_LPE 0x05 /* VF requests PF to set VMOLR.LPE */
#define RNPGBE_VF_SET_MACVLAN 0x06 /* VF requests PF for unicast filter */
#define RNPGBE_VF_GET_MACVLAN 0x07 /* VF requests mac */
#define RNPGBE_VF_API_NEGOTIATE 0x08 /* negotiate API version */

/* mailbox API, version 1.1 VF requests */
#define RNPGBE_VF_GET_QUEUE 0x09 /* get queue configuration */
#define RNPGBE_VF_SET_VLAN_STRIP 0x0a /* VF requests PF to set VLAN STRIP */
#define RNPGBE_VF_REG_RD 0x0b /* vf read reg */
#define RNPGBE_VF_GET_MTU 0x0c /* vf read reg */
#define RNPGBE_VF_SET_MTU 0x0d /* vf read reg */
#define RNPGBE_VF_GET_FW 0x0e /* vf read reg */
#define RNPGBE_VF_RESET_PF 0x13 /* vf read reg */

#define RNPGBE_PF_VFNUM_MASK (0x3f << 21)
#define RNPGBE_PF_SET_FCS 0x10 /* PF set fcs status */
#define RNPGBE_PF_SET_PAUSE 0x11 /* PF set pause status */
#define RNPGBE_PF_SET_FT_PADDING 0x12 /* PF set ft padding status */
#define RNPGBE_PF_SET_VLAN_FILTER 0x13
#define RNPGBE_PF_SET_VLAN 0x14
#define RNPGBE_PF_SET_LINK 0x15
#define RNPGBE_PF_SET_MTU 0x16
#define RNPGBE_PF_SET_RESET 0x17
#define RNPGBE_PF_LINK_UP (0x1 << 31)

#define RNPGBE_PF_REMOVE 0x0f
#define RNPGBE_PF_GET_LINK 0x10
/* GET_QUEUES return data indices within the mailbox */
#define RNPGBE_VF_TX_QUEUES 1 /* number of Tx queues supported */
#define RNPGBE_VF_RX_QUEUES 2 /* number of Rx queues supported */
#define RNPGBE_VF_TRANS_VLAN 3 /* Indication of port vlan */
#define RNPGBE_VF_DEF_QUEUE 4 /* Default queue offset */

/* length of permanent address message returned from PF */
#define RNPGBE_VF_PERMADDR_MSG_LEN 11
/* word in permanent address message with the current multicast type */
#define RNPGBE_VF_MC_TYPE_WORD 3
#define RNPGBE_VF_DMA_VERSION_WORD 4
#define RNPGBE_VF_VLAN_WORD 5
#define RNPGBE_VF_PHY_TYPE_WORD 6
#define RNPGBE_VF_FW_VERSION_WORD 7
#define RNPGBE_VF_LINK_STATUS_WORD 8
#define RNPGBE_VF_AXI_MHZ 9
#define RNPGBE_VF_FEATURE 10

#define RNPGBE_PF_CONTROL_PRING_MSG 0x0100 /* PF control message */

#define RNPGBE_VF_MBX_INIT_TIMEOUT 2000 /* number of retries on mailbox */
#define RNPGBE_VF_MBX_INIT_DELAY 500 /* microseconds between retries */

/* forward declaration of the HW struct */
struct rnpgbevf_hw;

enum MBX_ID {
	MBX_VF0 = 0,
	MBX_VF1,
	//...
	MBX_VF63,
	MBX_CM3CPU,
	MBX_VFCNT
};

#endif /* _RNPGBEVF_MBX_H_ */
