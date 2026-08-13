/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2024-2026 Mucse Corporation. */

#ifndef MCE_IOCTL_H
#define MCE_IOCTL_H

#include <linux/types.h>

#define MCE_IOCTL_BASE 0xdd
#define MCE_IOCTL_GETDCBINFO _IOR(MCE_IOCTL_BASE, 0, struct mce_ioctl_dcbinfo)
#define MCE_IOCTL_SETPFC _IOW(MCE_IOCTL_BASE, 1, struct ieee_pfc)
#define MCE_IOCTL_SETETS _IOW(MCE_IOCTL_BASE, 2, struct ieee_ets)
#define MCE_IOCTL_SETDSCP _IOW(MCE_IOCTL_BASE, 3, struct mce_dscp_setup)
#define MCE_IOCTL_SETRX _IOW(MCE_IOCTL_BASE, 4, struct rx_qos)
#define MCE_IOCTL_MBX_CMD _IOW(MCE_IOCTL_BASE, 5, struct mce_mbx_cmd)
#define MCE_IOCTL_GET_DEVINFO _IOW(MCE_IOCTL_BASE, 6, struct mce_ioctl_devinfo)
#define MCE_IOCTL_DMA_OP _IOW(MCE_IOCTL_BASE, 7, struct mce_dma_op)
#define MCE_IOCTL_REG_OP _IOW(MCE_IOCTL_BASE, 8, struct mce_reg_op)
#define MCE_IOCTL_SETVLAN_TO_Q _IOW(MCE_IOCTL_BASE, 9, struct mce_vlan_to_q_setup)
#define MCE_IOCTL_DMA_BUF_RW _IOW(MCE_IOCTL_BASE, 10, struct mce_dma_buf_rw)
#define MCE_IOCTL_SETDCB_STATE _IOW(MCE_IOCTL_BASE, 11, struct mce_dma_buf_rw)
#define MCE_IOCTL_SETPF_SPEED _IOW(MCE_IOCTL_BASE, 12, struct mce_pf_speed)
#define MCE_IOCTL_SETSP_TIMEOUT _IOW(MCE_IOCTL_BASE, 13, struct mce_pf_speed)
#define MCE_IOCTL_SET_RDMA_PRI _IOW(MCE_IOCTL_BASE, 14, struct mce_rdma_pri)
#define MCE_IOCTL_SETPRIV_EN _IOW(MCE_IOCTL_BASE, 15, struct mce_pri_en_setup)

/* Char device mmap offset encoding for PCI register space mapping.
 *
 * When the flag bit (31) is set in the mmap offset (byte offset),
 * the offset is interpreted as a register region mmap request
 * instead of the default coherent DMA buffer mapping.
 *
 * Encoding:
 *   bit 31     = mmap flag (must be set)
 *   bits 30-28 = register region index
 *   bits 27-0  = byte offset within the region
 *
 * Register regions:
 *   0 = MCE_MMAP_REG_ETH   - Ethernet register space (eth_bar)
 *   1 = MCE_MMAP_REG_RDMA  - RDMA register space (rdma_bar)
 *   2 = MCE_MMAP_REG_NPU   - NPU register space (npu_bar, if available)
 *
 * Example (userspace):
 *   Map eth_bar, offset 0x1000, size 4096
 *   unsigned long off = MCE_CDEV_MMAP(MCE_MMAP_REG_ETH, 0x1000);
 *   addr = mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_SHARED, fd, off);
 */
#define MCE_CDEV_MMAP_FLAG		BIT(31)
#define MCE_CDEV_MMAP_REGION(off)	(((off) >> 28) & 0x7)
#define MCE_CDEV_MMAP_OFF(off)		((off) & ((1UL << 28) - 1))
#define MCE_CDEV_MMAP(reg, off)		(MCE_CDEV_MMAP_FLAG | \
					 ((reg) << 28) | \
					 ((off) & ((1UL << 28) - 1)))

#define MCE_MMAP_REG_ETH	0
#define MCE_MMAP_REG_RDMA	1
#define MCE_MMAP_REG_NPU	2

struct mce_dscp_setup {
	int flag;
	u8 dscp;
	u8 prio;
};

enum {
	DSCP_EN,
};

struct mce_pri_en_setup {
	int priv;
	int flag;
};

struct mce_dcb_state {
	int flags;
};

struct mce_vlan_to_q_setup {
	int flag;
	u16 vlan;
	u8 queue;
};

struct rx_qos {
	int rx_prio2buffer[IEEE_8021QAZ_MAX_TCS];
	int rx_buffer[IEEE_8021QAZ_MAX_TCS];
};

struct mce_ioctl_dcbinfo {
	int dcb_en;
	struct ieee_ets ets;
	int ets_en;
	struct ieee_pfc pfc;
	int pfc_en;
	u8 prio2buf[IEEE_8021QAZ_MAX_TCS];
	int rx_buffer[IEEE_8021QAZ_MAX_TCS];
	u8 dscp_map[MCE_MAX_DSCP];
	int dscp_en;
	int vlan_to_q_en;
	u8 vlan_to_q[MCE_MAX_VLAN];
	int speed_limit;
	u16 nic_prio;
	u16 rdma_prio;
	int sp_timeout;
};

struct mce_ioctl_devinfo {
	u16 nr_pf;
	u16 bd_number;
	char pci_name[20];
	char adpt_name[20];
	u8 mac_addr[8];
	u16 device_id;
	u16 sub_device_id;
	u16 sub_vendor;
	u16 linkup;
	char eth_name[IFNAMSIZ];
};

struct mce_mbx_cmd {
	int opcode;
	int timeout_us;
	int flags;
	int data_bytes;
	int data[60];
};

enum REG_REGION {
	REG_BAR0 = 0,
	REG_BAR2,
	REG_BAR4,
	REG_RDMA,
	REG_NIC,
	REG_RPU,
	REG_PCS,
	REG_SOC,
};

struct mce_reg_op {
	int op;
#define REG_OP_RD 0
#define REG_OP_WR 1
	int region;

	int offset;
	int value;
};

struct mce_dma_op {
	int op;
#define DMA_OP_ALLOC 0
#define DMA_OP_FREE 1
#define DMA_OP_FREE 1
	int bytes;
	int dma_phy_lo;
	int dma_phy_hi;
};

struct mce_dma_buf_rw {
	int op;
#define DMA_BUF_RD 1
#define DMA_BUF_WR 2
	void *user_buf;
	int dma_offset;
	int bytes;
};

struct mce_pf_speed {
	int flag;
	int speed;
};

struct mce_sp_timeout {
	int flag;
	int timeout;
};

struct mce_rdma_pri {
	int flag;
	u8 rdma_pri;
};
#endif
