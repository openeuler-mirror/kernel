/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved.
 *
 */

#ifndef _UB_UBASE_COMM_MBX_H_
#define _UB_UBASE_COMM_MBX_H_

#include <linux/auxiliary_bus.h>
#include <linux/types.h>

#define UBASE_AEQ_CTX_SIZE	64
#define UBASE_CEQ_CTX_SIZE	64
#define UBASE_JFS_CTX_SIZE	256
#define UBASE_JFR_CTX_SIZE	64
#define UBASE_JFC_CTX_SIZE	128
#define UBASE_TP_CTX_SIZE	256
#define UBASE_TPG_CTX_SIZE	64
#define UBASE_RC_CTX_SIZE	256
#define UBASE_JTG_CTX_SIZE	8

/**
 * struct ubase_cmd_mailbox - mailbox cmmand address
 * @buf: virtual address
 * @dma: dma address
 * @count: reference count
 */
struct ubase_cmd_mailbox {
	void *buf;
	dma_addr_t dma;
	KABI_USE(1, atomic_t count)
	KABI_RESERVE(2)
	KABI_RESERVE(3)
	KABI_RESERVE(4)
};

/**
 * struct ubase_mbx_attr - mailbox attribute
 * @tag: queue id
 * @rsv: reserved bits
 * @op: mailbox opcode
 * @mbx_ue_id: mailbox ub entity id
 */
struct ubase_mbx_attr {
	__le32 tag : 24;
	__le32 rsv : 8;
	u8 op;
	u8 mbx_ue_id;
	KABI_RESERVE(1)
	KABI_RESERVE(2)
	KABI_RESERVE(3)
	KABI_RESERVE(4)
};

enum ubase_mbox_opcode {
	/* write/destroy jfs/jetty ctx buf */
	UBASE_MB_WRITE_JFS_CONTEXT_VA = 0x0,
	UBASE_MB_CREATE_JFS_CONTEXT = 0x4,
	UBASE_MB_MODIFY_JFS_CONTEXT = 0x5,
	UBASE_MB_QUERY_JFS_CONTEXT = 0x6,
	UBASE_MB_DESTROY_JFS_CONTEXT = 0x7,

	/* write/destroy rc ctx buf */
	UBASE_MB_WRITE_RC_CONTEXT_VA = 0x10,
	UBASE_MB_CREATE_RC_CONTEXT = 0x14,
	UBASE_MB_MODIFY_RC_CONTEXT = 0x15,
	UBASE_MB_QUERY_RC_CONTEXT = 0x16,
	UBASE_MB_DESTROY_RC_CONTEXT = 0x17,

	/* write/destroy jfc ctx buf */
	UBASE_MB_WRITE_JFC_CONTEXT_VA = 0x20,
	UBASE_MB_CREATE_JFC_CONTEXT = 0x24,
	UBASE_MB_MODIFY_JFC_CONTEXT = 0x25,
	UBASE_MB_QUERY_JFC_CONTEXT = 0x26,
	UBASE_MB_DESTROY_JFC_CONTEXT = 0x27,

	/* create/destroy aeq ctx */
	UBASE_MB_CREATE_AEQ_CONTEXT = 0x34,
	UBASE_MB_QUERY_AEQ_CONTEXT = 0x36,
	UBASE_MB_DESTROY_AEQ_CONTEXT = 0x37,

	/* create/destroy ceq ctx */
	UBASE_MB_CREATE_CEQ_CONTEXT = 0x44,
	UBASE_MB_QUERY_CEQ_CONTEXT = 0x46,
	UBASE_MB_DESTROY_CEQ_CONTEXT = 0x47,

	/* write/destroy jfr ctx buf */
	UBASE_MB_WRITE_JFR_CONTEXT_VA = 0x50,
	UBASE_MB_CREATE_JFR_CONTEXT = 0x54,
	UBASE_MB_MODIFY_JFR_CONTEXT = 0x55,
	UBASE_MB_QUERY_JFR_CONTEXT = 0x56,
	UBASE_MB_DESTROY_JFR_CONTEXT = 0x57,

	/* write/destroy jetty group ctx buf */
	UBASE_MB_WRITE_JETTY_GROUP_CONTEXT_VA = 0x60,
	UBASE_MB_CREATE_JETTY_GROUP_CONTEXT = 0x64,
	UBASE_MB_MODIFY_JETTY_GROUP_CONTEXT = 0x65,
	UBASE_MB_QUERY_JETTY_GROUP_CONTEXT = 0x66,
	UBASE_MB_DESTROY_JETTY_GROUP_CONTEXT = 0x67,

	/* query tpg ctx buf */
	UBASE_MB_QUERY_TPG_CONTEXT = 0x76,

	/* query tp ctx buf */
	UBASE_MB_QUERY_TP_CONTEXT = 0x86,
};

struct ubase_cmd_mailbox *ubase_alloc_cmd_mailbox(struct auxiliary_device *aux_dev);
void ubase_free_cmd_mailbox(struct auxiliary_device *aux_dev,
			    struct ubase_cmd_mailbox *mailbox);
int ubase_hw_upgrade_ctx_ex(struct auxiliary_device *aux_dev,
			    struct ubase_mbx_attr *attr,
			    struct ubase_cmd_mailbox *mailbox);

/**
 * ubase_fill_mbx_attr() - fill mailbox attribute
 * @attr: mailbox attribute
 * @tag: queue id
 * @op: mailbox opcode
 * @mbx_ue_id: mailbox ub entity id
 *
 * The function is used to assign 'tag', 'op', and 'mbx_ue_id' to 'struct ubase_mbx_attr'.
 *
 * Context: Process context.
 */
static inline void ubase_fill_mbx_attr(struct ubase_mbx_attr *attr, u32 tag,
				       u8 op, u8 mbx_ue_id)
{
	attr->tag = tag;
	attr->op = op;
	attr->mbx_ue_id = mbx_ue_id;
}

#endif /* _UBASE_COMM_MBX_H_ */
