/* SPDX-License-Identifier: GPL-2.0 */
/* Huawei iBMA driver.
 * Copyright (c) 2017, Huawei Technologies Co., Ltd.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#ifndef _EDMA_HOST_H_
#define _EDMA_HOST_H_

#include "bma_include.h"
#include "../include/bma_ker_intf.h"

#define EDMA_TIMER

#ifndef IN
#define IN
#endif

#ifndef OUT
#define OUT
#endif

#ifndef UNUSED
#define UNUSED
#endif

/* vm_flags in vm_area_struct, see mm_types.h. */
#define VM_NONE		0x00000000

#define VM_READ		0x00000001	/* currently active flags */
#define VM_WRITE	0x00000002
#define VM_EXEC		0x00000004
#define VM_SHARED	0x00000008

#define VM_MAYREAD	0x00000010	/* limits for mprotect() etc */
#define VM_MAYWRITE	0x00000020
#define VM_MAYEXEC	0x00000040
#define VM_MAYSHARE	0x00000080

#define VM_GROWSDOWN	0x00000100	/* general info on the segment */
/* Page-ranges managed without "struct page", just pure PFN */
#define VM_PFNMAP	0x00000400
#define VM_DENYWRITE	0x00000800	/* ETXTBSY on write attempts.. */

#define VM_LOCKED	0x00002000
#define VM_IO           0x00004000	/* Memory mapped I/O or similar */

					/* Used by sys_madvise() */
#define VM_SEQ_READ	0x00008000	/* App will access data sequentially */
/* App will not benefit from clustered reads */
#define VM_RAND_READ	0x00010000

#define VM_DONTCOPY	0x00020000	/* Do not copy this vma on fork */
#define VM_DONTEXPAND	0x00040000	/* Cannot expand with mremap() */
#define VM_ACCOUNT	0x00100000	/* Is a VM accounted object */
#define VM_NORESERVE	0x00200000	/* should the VM suppress accounting */
#define VM_HUGETLB	0x00400000	/* Huge TLB Page VM */
#define VM_NONLINEAR	0x00800000	/* Is non-linear (remap_file_pages) */
#define VM_ARCH_1	0x01000000	/* Architecture-specific flag */
#define VM_DONTDUMP	0x04000000	/* Do not include in the core dump */
/* Can contain "struct page" and pure PFN pages */
#define VM_MIXEDMAP	0x10000000

#define VM_MERGEABLE	0x80000000	/* KSM may merge identical pages */

#if defined(CONFIG_X86)
/* PAT reserves whole VMA at once (x86) */
#define VM_PAT		VM_ARCH_1
#elif defined(CONFIG_PPC)
#define VM_SAO		VM_ARCH_1	/* Strong Access Ordering (powerpc) */
#elif defined(CONFIG_PARISC)
#define VM_GROWSUP	VM_ARCH_1
#elif defined(CONFIG_METAG)
#define VM_GROWSUP	VM_ARCH_1
#elif defined(CONFIG_IA64)
#define VM_GROWSUP	VM_ARCH_1
#elif !defined(CONFIG_MMU)
#define VM_MAPPED_COPY	VM_ARCH_1 /* T if mapped copy of data (nommu mmap) */
#endif

#ifndef VM_GROWSUP
#define VM_GROWSUP	VM_NONE
#endif

#ifndef VM_STACK_DEFAULT_FLAGS	/* arch can override this */
#define VM_STACK_DEFAULT_FLAGS VM_DATA_DEFAULT_FLAGS
#endif

#define VM_READHINTMASK			(VM_SEQ_READ | VM_RAND_READ)
#define VM_NORMAL_READ_HINT(v)		(!((v)->vm_flags & VM_READHINTMASK))
#define VM_SEQUENTIAL_READ_HINT(v)	((v)->vm_flags & VM_SEQ_READ)
#define VM_RANDOM_READ_HINT(v)		((v)->vm_flags & VM_RAND_READ)

#define REG_PCIE1_DMAREAD_ENABLE	0xa18
#define SHIFT_PCIE1_DMAREAD_ENABLE	0

#define REG_PCIE1_DMAWRITE_ENABLE	0x9c4
#define SHIFT_PCIE1_DMAWRITE_ENABLE	0

#define REG_PCIE1_DMAREAD_STATUS	0xa10
#define SHIFT_PCIE1_DMAREAD_STATUS	0
#define REG_PCIE1_DMAREADINT_CLEAR	0xa1c
#define SHIFT_PCIE1_DMAREADINT_CLEAR	0

#define REG_PCIE1_DMAWRITE_STATUS	0x9bc
#define SHIFT_PCIE1_DMAWRITE_STATUS	0
#define REG_PCIE1_DMAWRITEINT_CLEAR	0x9c8
#define SHIFT_PCIE1_DMAWRITEINT_CLEAR	0

#define REG_PCIE1_DMA_READ_ENGINE_ENABLE	(0x99c)
#define SHIFT_PCIE1_DMA_ENGINE_ENABLE		(0)
#define REG_PCIE1_DMA_WRITE_ENGINE_ENABLE	(0x97C)

#define HOSTRTC_INT_OFFSET		0x10

#define H2BSTATE_IDLE			0
#define H2BSTATE_WAITREADY		1
#define H2BSTATE_WAITDMA		2
#define H2BSTATE_WAITACK		3
#define H2BSTATE_ERROR			4

#define B2HSTATE_IDLE			0
#define B2HSTATE_WAITREADY		1
#define B2HSTATE_WAITRECV		2
#define B2HSTATE_WAITDMA		3
#define B2HSTATE_ERROR			4

#define PAGE_ORDER			8
#define EDMA_DMABUF_SIZE		(1 << (PAGE_SHIFT + PAGE_ORDER))

#define EDMA_DMA_TRANSFER_WAIT_TIMEOUT	(10 * HZ)
#define TIMEOUT_WAIT_NOSIGNAL		2

#define TIMER_INTERVAL_CHECK		(HZ / 10)
#define DMA_TIMER_INTERVAL_CHECK	50
#define HEARTBEAT_TIMER_INTERVAL_CHECK	HZ

#define EDMA_PCI_MSG_LEN		(56 * 1024)

#define HOST_DMA_FLAG_LEN		(64)

#define HOST_MAX_SEND_MBX_LEN		(40 * 1024)
#define BMC_MAX_RCV_MBX_LEN		HOST_MAX_SEND_MBX_LEN

#define HOST_MAX_RCV_MBX_LEN		(16 * 1024)
#define BMC_MAX_SEND_MBX_LEN		HOST_MAX_RCV_MBX_LEN
#define CDEV_MAX_WRITE_LEN		(4 * 1024)

#define HOST_MAX_MSG_LENGTH		272

#define EDMA_MMAP_H2B_DMABUF		0xf1000000

#define EDMA_MMAP_B2H_DMABUF		0xf2000000

#define EDMA_IOC_MAGIC			'e'

#define EDMA_H_REGISTER_TYPE		_IOW(EDMA_IOC_MAGIC, 100, unsigned long)

#define EDMA_H_UNREGISTER_TYPE		_IOW(EDMA_IOC_MAGIC, 101, unsigned long)

#define EDMA_H_DMA_START		_IOW(EDMA_IOC_MAGIC, 102, unsigned long)

#define EDMA_H_DMA_TRANSFER		_IOW(EDMA_IOC_MAGIC, 103, unsigned long)

#define EDMA_H_DMA_STOP			_IOW(EDMA_IOC_MAGIC, 104, unsigned long)

#define U64ADDR_H(addr)			((((u64)addr) >> 32) & 0xffffffff)
#define U64ADDR_L(addr)			((addr) & 0xffffffff)

struct bma_register_dev_type_s {
	u32 type;
	u32 sub_type;
};

struct edma_mbx_hdr_s {
	u16 mbxlen;
	u16 mbxoff;
	u8 reserve[28];
} __packed;

#define SIZE_OF_MBX_HDR (sizeof(struct edma_mbx_hdr_s))

struct edma_recv_msg_s {
	struct list_head link;
	u32 msg_len;
	unsigned char msg_data[];
};

struct edma_dma_addr_s {
	void *kvaddr;
	dma_addr_t dma_addr;
	u32 len;
};

struct edma_msg_hdr_s {
	u32 type;
	u32 sub_type;
	u8 user_id;
	u8 dma_flag;
	u8 reserve1[2];
	u32 datalen;
	u8 data[];
};

#define SIZE_OF_MSG_HDR (sizeof(struct edma_msg_hdr_s))

#pragma pack(1)

#define IS_EDMA_B2H_INT(flag)		((flag) & 0x02)
#define CLEAR_EDMA_B2H_INT(flag)	((flag) = (flag) & 0xfffffffd)
#define SET_EDMA_H2B_INT(flag)		((flag) = (flag) | 0x01)
#define EDMA_B2H_INT_FLAG                      0x02

struct notify_msg {
	unsigned int host_registered;
	unsigned int host_heartbeat;
	unsigned int bmc_registered;
	unsigned int bmc_heartbeat;
	unsigned int int_flag;

	unsigned int reservrd5;
	unsigned int h2b_addr;
	unsigned int h2b_size;
	unsigned int h2b_rsize;
	unsigned int b2h_addr;
	unsigned int b2h_size;
	unsigned int b2h_rsize;
};

#pragma pack()

struct edma_statistics_s {
	unsigned int remote_status;
	__kernel_time_t init_time;
	unsigned int h2b_int;
	unsigned int b2h_int;
	unsigned int recv_bytes;
	unsigned int send_bytes;
	unsigned int send_pkgs;
	unsigned int recv_pkgs;
	unsigned int failed_count;
	unsigned int drop_pkgs;
	unsigned int dma_count;
	unsigned int lost_count;
};

struct edma_host_s {
	struct pci_dev *pdev;

	struct tasklet_struct tasklet;

	void __iomem *hostrtc_viraddr;

	void __iomem *edma_flag;
	void __iomem *edma_send_addr;
	void __iomem *edma_recv_addr;
#ifdef USE_DMA
	struct timer_list dma_timer;
#endif

	struct timer_list heartbeat_timer;

#ifdef EDMA_TIMER
	struct timer_list timer;
#else
	struct completion msg_ready;	/* to sleep thread on      */
	struct task_struct *edma_thread;
#endif
	/* spinlock for send msg buf */
	spinlock_t send_msg_lock;
	unsigned char *msg_send_buf;
	unsigned int msg_send_write;

	/* DMA */
	wait_queue_head_t wq_dmah2b;
	wait_queue_head_t wq_dmab2h;

	/* spinlock for read pci register */
	spinlock_t reg_lock;
	int h2b_state;
	int b2h_state;
	struct edma_dma_addr_s h2b_addr;
	struct edma_dma_addr_s b2h_addr;

	struct proc_dir_entry *proc_edma_dir;

	struct edma_statistics_s statistics;
	unsigned char local_open_status[TYPE_MAX];
	unsigned char remote_open_status[TYPE_MAX];
};

struct edma_user_inft_s {
	/* register user */
	int (*user_register)(struct bma_priv_data_s *priv);

	/* unregister user */
	void (*user_unregister)(struct bma_priv_data_s *priv);

	/* add msg */
	int (*add_msg)(void *msg, size_t msg_len);
};

int is_edma_b2h_int(struct edma_host_s *edma_host);
void edma_int_to_bmc(struct edma_host_s *edma_host);
int edma_host_mmap(struct edma_host_s *edma_hos, struct file *filp,
		   struct vm_area_struct *vma);
int edma_host_copy_msg(struct edma_host_s *edma_host, void *msg,
		       size_t msg_len);
int edma_host_add_msg(struct edma_host_s *edma_host,
		      struct bma_priv_data_s *priv, void *msg, size_t msg_len);
int edma_host_recv_msg(struct edma_host_s *edma_host,
		       struct bma_priv_data_s *priv,
		       struct edma_recv_msg_s **msg);
void edma_host_isr_tasklet(unsigned long data);
int edma_host_check_dma_status(enum dma_direction_e dir);
int edma_host_dma_start(struct edma_host_s *edma_host,
			struct bma_priv_data_s *priv);
int edma_host_dma_transfer(struct edma_host_s *edma_host,
			   struct bma_priv_data_s *priv,
			   struct bma_dma_transfer_s *dma_transfer);
int edma_host_dma_stop(struct edma_host_s *edma_host,
		       struct bma_priv_data_s *priv);
irqreturn_t edma_host_irq_handle(struct edma_host_s *edma_host);
struct edma_user_inft_s *edma_host_get_user_inft(u32 type);
int edma_host_user_register(u32 type, struct edma_user_inft_s *func);
int edma_host_user_unregister(u32 type);
int edma_host_init(struct edma_host_s *edma_host);
void edma_host_cleanup(struct edma_host_s *edma_host);
int edma_host_send_driver_msg(const void *msg, size_t msg_len, int subtype);
void edma_host_reset_dma(struct edma_host_s *edma_host, int dir);
void clear_int_dmah2b(struct edma_host_s *edma_host);
void clear_int_dmab2h(struct edma_host_s *edma_host);

enum EDMA_STATUS {
	DEREGISTERED = 0,
	REGISTERED = 1,
	LOST,
};
#endif
