/* SPDX-License-Identifier: GPL-2.0*/
/*
 * Copyright (c) 2022 nebula-matrix Limited.
 * Author:
 */

#ifndef _NBL_DEV_USER_H_
#define _NBL_DEV_USER_H_

#define NBL_DEV_USER_TYPE	('n')

#define NBL_DEV_USER_PCI_OFFSET_SHIFT		40
#define NBL_DEV_USER_OFFSET_TO_INDEX(off)	((off) >> NBL_DEV_USER_PCI_OFFSET_SHIFT)
#define NBL_DEV_USER_INDEX_TO_OFFSET(index)	((u64)(index) << NBL_DEV_USER_PCI_OFFSET_SHIFT)
#define NBL_DEV_SHM_MSG_RING_INDEX		(6)

/* 8192 ioctl mailbox msg */
struct nbl_dev_user_channel_msg {
	u16 msg_type;
	u16 dst_id;
	u32 arg_len;
	u32 ack_err;
	u16 ack_length;
	u16 ack;
	u32 data[2044];
};

#define NBL_DEV_USER_CHANNEL		_IO(NBL_DEV_USER_TYPE, 0)

struct nbl_dev_user_dma_map {
	u32	argsz;
	u32	flags;
#define NBL_DEV_USER_DMA_MAP_FLAG_READ BIT(0)	/* readable from device */
#define NBL_DEV_USER_DMA_MAP_FLAG_WRITE BIT(1)	/* writable from device */
	u64	vaddr;				/* Process virtual address */
	u64	iova;				/* IO virtual address */
	u64	size;				/* Size of mapping (bytes) */
};

#define NBL_DEV_USER_MAP_DMA		_IO(NBL_DEV_USER_TYPE, 1)

struct nbl_dev_user_dma_unmap {
	u32	argsz;
	u32	flags;
	u64	vaddr;
	u64	iova;				/* IO virtual address */
	u64	size;				/* Size of mapping (bytes) */
};

#define NBL_DEV_USER_UNMAP_DMA		_IO(NBL_DEV_USER_TYPE, 2)

#define NBL_KERNEL_NETWORK			0
#define NBL_USER_NETWORK			1

#define NBL_DEV_USER_SWITCH_NETWORK	_IO(NBL_DEV_USER_TYPE, 3)

#define NBL_DEV_USER_GET_IFINDEX	_IO(NBL_DEV_USER_TYPE, 4)

#define NBL_DEV_USER_SET_EVENTFD	_IO(NBL_DEV_USER_TYPE, 5)

#define NBL_DEV_USER_CLEAR_EVENTFD	_IO(NBL_DEV_USER_TYPE, 6)

#define NBL_DEV_USER_SET_LISTENER	_IO(NBL_DEV_USER_TYPE, 7)

#define NBL_DEV_USER_GET_BAR_SIZE	_IO(NBL_DEV_USER_TYPE, 8)

void nbl_dev_start_user_dev(struct nbl_adapter *adapter);
void nbl_dev_stop_user_dev(struct nbl_adapter *adapter);

#endif
