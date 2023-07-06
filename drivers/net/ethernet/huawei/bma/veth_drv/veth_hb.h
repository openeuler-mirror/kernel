/* SPDX-License-Identifier: GPL-2.0 */
/*Huawei iBMA driver.
 *Copyright (c) 2017, Huawei Technologies Co., Ltd.
 *
 *This program is free software; you can redistribute it and/or
 *modify it under the terms of the GNU General Public License
 *as published by the Free Software Foundation; either version 2
 *of the License, or (at your option) any later version.
 *
 *This program is distributed in the hope that it will be useful,
 *but WITHOUT ANY WARRANTY; without even the implied warranty of
 *MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *GNU General Public License for more details.
 *
 */

#ifndef _VETH_HB_H_
#define _VETH_HB_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <linux/interrupt.h>

#define DEP_BMA

#include "../edma_drv/bma_include.h"
#include "../include/bma_ker_intf.h"

#ifdef DRV_VERSION
#define VETH_VERSION	MICRO_TO_STR(DRV_VERSION)
#else
#define VETH_VERSION	"0.3.6"
#endif

#define MODULE_NAME	"veth"
#define BSP_VETH_T	u64

#define BSP_OK				(0)
#define BSP_ERR				(0xFFFFFFFF)
#define BSP_NETDEV_TX_BUSY		(1)
#define BSP_ERR_INIT_ERR		(BSP_NETDEV_TX_BUSY)
#define BSP_ETH_ERR_BASE		(0x0FFFF000)
#define BSP_ERR_OUT_OF_MEM		(BSP_ETH_ERR_BASE + 1)
#define BSP_ERR_NULL_POINTER		(BSP_ETH_ERR_BASE + 2)
#define BSP_ERR_INVALID_STR		(BSP_ETH_ERR_BASE + 3)
#define BSP_ERR_INVALID_PARAM		(BSP_ETH_ERR_BASE + 4)
#define BSP_ERR_INVALID_DATA		(BSP_ETH_ERR_BASE + 5)
#define BSP_ERR_OUT_OF_RANGE		(BSP_ETH_ERR_BASE + 6)
#define BSP_ERR_INVALID_CARD		(BSP_ETH_ERR_BASE + 7)
#define BSP_ERR_INVALID_GRP		(BSP_ETH_ERR_BASE + 8)
#define BSP_ERR_INVALID_ETH		(BSP_ETH_ERR_BASE + 9)
#define BSP_ERR_SEND_ERR		(BSP_ETH_ERR_BASE + 10)
#define BSP_ERR_DMA_ERR			(BSP_ETH_ERR_BASE + 11)
#define BSP_ERR_RECV_ERR		(BSP_ETH_ERR_BASE + 12)
#define BSP_ERR_SKB_ERR			(BSP_ETH_ERR_BASE + 13)
#define BSP_ERR_DMA_ADDR_ERR		(BSP_ETH_ERR_BASE + 14)
#define BSP_ERR_IOREMAP_ERR		(BSP_ETH_ERR_BASE + 15)
#define BSP_ERR_LEN_ERR			(BSP_ETH_ERR_BASE + 16)
#define BSP_ERR_STAT_ERR		(BSP_ETH_ERR_BASE + 17)
#define BSP_ERR_AGAIN			(BSP_ETH_ERR_BASE + 18)
#define BSP_ERR_NOT_TO_HANDLE		(BSP_ETH_ERR_BASE + 19)

#define VETH_H2B_IRQ_NO			(113)
#define SYSCTL_REG_BASE			(0x20000000)
#define SYSCTL_REG_SIZE			(0x1000)
#define PCIE1_REG_BASE			(0x29000000)
#define PCIE1_REG_SIZE			(0x1000)
#define VETH_SHAREPOOL_BASE_INBMC	(0x84820000)
#define VETH_SHAREPOOL_SIZE		(0xdf000)
#define VETH_SHAREPOOL_OFFSET		(0x10000)
#define MAX_SHAREQUEUE_SIZE		(0x20000)

#define BSPVETH_SHMBDBASE_OFFSET	(0x80)
#define SHMDMAL_OFFSET			(0x10000)
#define MAX_SHMDMAL_SIZE		(BSPVETH_DMABURST_MAX * 32)

#define BSPVETH_DMABURST_MAX		64
#define BSPVETH_SKBTIMER_INTERVAL	(1)
#define BSPVETH_DMATIMER_INTERVAL	(1)
#define BSPVETH_CTLTIMER_INTERVAL	(10)
#define BSPVETH_HDCMD_CHKTIMER_INTERVAL	(10)
#define BSP_DMA_64BIT_MASK		(0xffffffffffffffffULL)
#define BSP_DMA_32BIT_MASK		(0x00000000ffffffffULL)
#define HOSTRTC_REG_BASE		(0x2f000000)
#define HOSTRTC_REG_SIZE		(0x10000)
#define REG_SYSCTL_HOSTINT_CLEAR	(0x44)
#define SHIFT_SYSCTL_HOSTINT_CLEAR	(22)
#define REG_SYSCTL_HOSTINT		(0xf4)
#define SHIFT_SYSCTL_HOSTINT		(26)

#define NET_TYPE_LEN			(16)

#define MAX_QUEUE_NUM			(1)
#define MAX_QUEUE_BDNUM			(128)
#define BSPVETH_MAX_QUE_DEEP		(MAX_QUEUE_BDNUM)
#define BSPVETH_POINT_MASK		(MAX_QUEUE_BDNUM - 1)
#define BSPVETH_WORK_LIMIT		(64)
#define BSPVETH_CHECK_DMA_STATUS_TIMES	(120)

#define REG_PCIE1_DMAREAD_ENABLE	(0xa18)
#define SHIFT_PCIE1_DMAREAD_ENABLE	(0)
#define REG_PCIE1_DMAWRITE_ENABLE	(0x9c4)
#define SHIFT_PCIE1_DMAWRITE_ENABLE	(0)
#define REG_PCIE1_DMAREAD_STATUS	(0xa10)
#define SHIFT_PCIE1_DMAREAD_STATUS	(0)
#define REG_PCIE1_DMAREADINT_CLEAR	(0xa1c)
#define SHIFT_PCIE1_DMAREADINT_CLEAR	(0)
#define REG_PCIE1_DMAWRITE_STATUS	(0x9bc)
#define SHIFT_PCIE1_DMAWRITE_STATUS	(0)
#define REG_PCIE1_DMAWRITEINT_CLEAR	(0x9c8)
#define SHIFT_PCIE1_DMAWRITEINT_CLEAR	(0)

#define BSPVETH_DMA_OK			(1)
#define BSPVETH_DMA_BUSY		(0)
#define BSPVETH_RX			(2)
#define BSPVETH_TX			(3)
#define HOSTRTC_INT_OFFSET		(0x10)
#define BSPVETH_DEV_NAME		(MODULE_NAME)
#define NET_NAME_LEN			(64)

#ifdef PCI_VENDOR_ID_HUAWEI
#undef PCI_VENDOR_ID_HUAWEI
#endif
#define PCI_VENDOR_ID_HUAWEI		(0x19e5)

#define PCI_DEVICE_ID_KBOX		(0x1710)
#define BSPVETH_MTU_MAX			(1500)
#define BSPVETH_MTU_MIN			(64)
#define BSPVETH_SKB_SIZE		(1536)
#define BSPVETH_NET_TIMEOUT		(5 * HZ)
#define BSPVETH_QUEUE_TIMEOUT_10MS	(100)
#define BSPVETH_SHMQUEUE_INITOK		(0x12)
#define BSPVETH_LBK_TYPE		(0x800)

#ifndef VETH_BMC
#define BSPVETH_CACHELINE_SIZE		(64)
#else
#define BSPVETH_CACHELINE_SIZE		(32)
#endif
#define BSPVETH_HBCMD_WCMP		(0x44)
#define BSPVETH_HBCMD_CMP		(0x55)
#define BSPVETH_HBCMD_OK		(0x66)
#define BSPVETH_HEART_WACK		(0x99)
#define BSPVETH_HEART_ACK		(0xaa)

#define BSPVETH_HBCMD_TIMEOUT		(1000)

#define SIZE_OF_UNSIGNED_LONG 8
#define ADDR_H_SHIFT 32
#define REGION_HOST 1
#define REGION_BMC 2

enum veth_hb_cmd {
	VETH_HBCMD_UNKNOWN = 0x0,
	VETH_HBCMD_SETIP,

	VETH_HBCMD_MAX,
};

#define USE_TASKLET

#define BSPVETH_ETHTOOL_BASE		0x89F0
#define BSPVETH_ETHTOOL_TESTINT		(BSPVETH_ETHTOOL_BASE + 1)
#define BSPVETH_ETHTOOL_TESTSHAREMEM	(BSPVETH_ETHTOOL_BASE + 2)
#define BSPVETH_ETHTOOL_DUMPSHAREMEM	(BSPVETH_ETHTOOL_BASE + 3)
#define BSPVETH_ETHTOOL_TESTDMA		(BSPVETH_ETHTOOL_BASE + 4)
#define BSPVETH_ETHTOOL_RWPCIEREG	(BSPVETH_ETHTOOL_BASE + 5)
#define BSPVETH_ETHTOOL_TESTLBK		(BSPVETH_ETHTOOL_BASE + 6)
#define BSPVETH_ETHTOOL_INITSTATIS	(BSPVETH_ETHTOOL_BASE + 7)
#define BSPVETH_HBCMD			(BSPVETH_ETHTOOL_BASE + 8)

struct bspveth_test {
	u32 intdirect;	/*0--H2B,1--B2H*/
	u32 rwshmcheck;	/*0--w,1--r and check*/
	u32 dshmbase;
	u32 dshmlen;
	u32 testdma;	/*0--disable,1---enable*/
	u32 pcierw;	/*0--w,1---r*/
	u32 reg;
	u32 data;
	u32 testlbk;	/*0--disable,1---enable*/
};

struct bspveth_hdcmd {
	u32 cmd;
	u32 stat;
	u32 heart;
	u32 err;
	u32 sequence;
	u32 len;
	u8 data[256];
};

struct bspveth_rxtx_statis {
	u64 pkt;
	u64 pktbyte;
	u64 refill;
	u64 freetx;
	u64 dmapkt;
	u64 dmapktbyte;

	u32 dropped_pkt;
	u32 netifrx_err;
	u32 null_point;
	u32 retry_err;
	u32 dma_mapping_err;
	u32 allocskb_err;
	u32 q_full;
	u32 q_emp;
	u32 shm_full;
	u32 shm_emp;
	u32 dma_busy;
	u32 need_fill;
	u32 need_free;
	u32 dmacmp_err;
	u32 type_err;
	u32 shmqueue_noinit;
	u32 shmretry_err;
	u32 dma_earlyint;
	u32 clr_dma_earlyint;
	u32 clr_dma_int;
	u32 dmarx_shmaddr_unalign;
	u32 dmarx_hostaddr_unalign;
	u32 dmatx_shmaddr_unalign;
	u32 dmatx_hostaddr_unalign;
	u32 dma_need_offset;
	u32 lastdmadir_err;
	u32 dma_failed;
	u32 dma_burst;
	u32 lbk_cnt;
	u32 lbk_txerr;
};

struct bspveth_bd_info {
	struct sk_buff *pdma_v;
	u32 len;
	unsigned long time_stamp;
};

struct bspveth_dma_shmbd {
	u32 dma_p;
	u32 len;
	u32 off;
};

struct bspveth_shmq_hd {
	u32 count;
	u32 size;	/*count x sizeof(dmaBD)*/
	u32 next_to_fill;
	u32 next_to_free;
	u32 head;
	u32 tail;
	u16 init;	/*  1--ok,0--nok*/
};

struct bspveth_dma_bd {
	u64 dma_p;
	u32 len;
	u32 off;
};

struct bspveth_dmal {
	u32 chl;
	u32 len;
	u32 slow;
	u32 shi;
	u32 dlow;
	u32 dhi;
};

struct bspveth_rxtx_q {
#ifndef VETH_BMC
	struct bspveth_dma_bd *pbdbase_v;
	u8 *pbdbase_p;
#endif

	struct bspveth_bd_info *pbdinfobase_v;
	struct bspveth_shmq_hd *pshmqhd_v;
	u8 *pshmqhd_p;

	struct bspveth_dma_shmbd *pshmbdbase_v;
	u8 *pshmbdbase_p;

	struct bspveth_dmal *pdmalbase_v;
	u8 *pdmalbase_p;

	u32 dmal_cnt;
	u32 dmal_byte;

	u32 count;
	u32 size;
	u32 rx_buf_len;

	u32 next_to_fill;
	u32 next_to_free;
	u32 head;
	u32 tail;
	u16 start_dma;
	u16 dmacmperr;

	u16 dma_overtime;

	u32 work_limit;
	struct bspveth_rxtx_statis s;
};

struct bspveth_device {
	struct bspveth_rxtx_q *ptx_queue[MAX_QUEUE_NUM];
	struct bspveth_rxtx_q *prx_queue[MAX_QUEUE_NUM];
	struct net_device *pnetdev;
	char name[NET_NAME_LEN];

	struct pci_dev *ppcidev;
	u8 *phostrtc_p;
	u8 *phostrtc_v;

	u8 *psysctl_v;
	u8 *ppcie1_v;

	u8 *pshmpool_p;
	u8 *pshmpool_v;
	u32 shmpoolsize;

	u32 recv_int;
	u32 tobmc_int;
	u32 tohost_int;
	u32 run_dma_tx_task;
	u32 run_dma_rx_task;
	u32 run_skb_rx_task;
	u32 run_skb_fr_task;
	u32 shutdown_cnt;
	__kernel_time_t init_time;

	/* spinlock for register */
	spinlock_t reg_lock;
#ifndef USE_TASKLET
	struct timer_list skbtrtimer;
	struct timer_list dmatimer;
#else
	struct tasklet_struct skb_task;
	struct tasklet_struct dma_task;
#endif

	struct net_device_stats stats;
	struct work_struct shutdown_task;
#ifdef DEP_BMA
	struct bma_priv_data_s *bma_priv;
#else
	void *edma_priv;
#endif
};

struct tag_pcie_comm_priv {
	char net_type[NET_TYPE_LEN];
	struct net_device_stats stats;
	int status;
	int irq_enable;
	int pcie_comm_rx_flag;
	spinlock_t lock; /* spinlock for priv data */
};

#define QUEUE_MASK(p)		((p) & (BSPVETH_POINT_MASK))

#define CHECK_ADDR_ALIGN(addr, statis)\
do {                         \
	if ((addr) & 0x3) \
		statis;\
} while (0)

#define PROC_P_STATIS(name, statis)\
	PROC_DPRINTK("[%10s]:\t0x%llx", #name, statis)

#define  INC_STATIS_RXTX(queue, name, count, type) \
do {                 \
	if (type == BSPVETH_RX)\
		g_bspveth_dev.prx_queue[queue]->s.name += count;\
	else\
		g_bspveth_dev.ptx_queue[queue]->s.name += count;\
} while (0)

#define PROC_DPRINTK(fmt, args...) (len += sprintf(buf + len, fmt, ##args))

#define JUDGE_TX_QUEUE_SPACE(head, tail, len) \
	(((BSPVETH_MAX_QUE_DEEP + (tail) - (head) - 1) \
	    & BSPVETH_POINT_MASK) >= (len))

#define JUDGE_RX_QUEUE_SPACE(head, tail, len) \
	(((BSPVETH_MAX_QUE_DEEP + (tail) - (head)) \
	    & BSPVETH_POINT_MASK) > (len))

#ifndef VETH_BMC
#define BSPVETH_UNMAP_DMA(data, len) \
	dma_unmap_single(&g_bspveth_dev.ppcidev->dev, \
			 data, len, DMA_FROM_DEVICE)
#else
#define BSPVETH_UNMAP_DMA(data, len) \
	dma_unmap_single(NULL, data, len, DMA_FROM_DEVICE)
#endif

int veth_tx(struct sk_buff *pstr_skb, struct net_device *pstr_dev);
int veth_dma_task_H(u32 type);
s32 veth_skbtimer_close(void);
void veth_skbtimer_init(void);
s32 veth_dmatimer_close_H(void);
void veth_dmatimer_init_H(void);
int veth_skb_tr_task(void);

s32 __dma_rxtx_H(struct bspveth_rxtx_q *prxtx_queue, u32 queue, u32 type);
s32 veth_recv_pkt(struct bspveth_rxtx_q *prx_queue, int queue);
s32 veth_free_txskb(struct bspveth_rxtx_q *ptx_queue, int queue);

enum {
	QUEUE_TX_STATS,
	QUEUE_RX_STATS,
	VETH_STATS,
	SHMQ_TX_STATS,
	SHMQ_RX_STATS,
	NET_STATS,
};

struct veth_stats {
	char stat_string[ETH_GSTRING_LEN];
	int type;
	int sizeof_stat;
	int stat_offset;
};

#define VETH_STAT_SIZE(m)	sizeof(((struct bspveth_device *)0)->m)
#define VETH_STAT_OFFSET(m)	offsetof(struct bspveth_device, m)
#define QUEUE_TXRX_STAT_SIZE(m)	sizeof(((struct bspveth_rxtx_q *)0)->m)
#define QUEUE_TXRX_STAT_OFFSET(m)	offsetof(struct bspveth_rxtx_q, m)
#define SHMQ_TXRX_STAT_SIZE(m)	sizeof(((struct bspveth_shmq_hd *)0)->m)
#define SHMQ_TXRX_STAT_OFFSET(m)	offsetof(struct bspveth_shmq_hd, m)

#ifdef __cplusplus
}
#endif
#endif
