/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#ifndef XSC_DRIVER_H
#define XSC_DRIVER_H

#include <linux/kernel.h>
#include <linux/completion.h>
#include <linux/pci.h>
#include <linux/spinlock_types.h>
#include <linux/semaphore.h>
#include <linux/vmalloc.h>
#include <linux/radix-tree.h>
#include "common/device.h"
#include "common/doorbell.h"
#include "common/xsc_core.h"
#include "common/xsc_cmd.h"
#include "common/xsc_hsi.h"
#include "common/qpts.h"

#define LS_64(val, field) (((u64)(val) << field ## _SHIFT) & (field ## _MASK))
#define RS_64(val, field) ((u64)((val) & field ## _MASK) >> field ## _SHIFT)
#define LS_32(val, field) (((val) << field ## _SHIFT) & (field ## _MASK))
#define RS_32(val, field) (((val) & field ## _MASK) >> field ## _SHIFT)

enum {
	CMD_OWNER_SW		= 0x0,
	CMD_OWNER_HW		= 0x1,
	CMD_STATUS_SUCCESS	= 0,
};

enum {
	XSC_MAX_FW_PORTS	= 1,
};

enum {
	XSC_MAX_IRQ_NAME	= 32
};

enum {
	XSC_MAX_EQ_NAME	= 20
};

enum {
	XSC_REG_PCAP		 = 0x5001,
	XSC_REG_PMTU		 = 0x5003,
	XSC_REG_PTYS		 = 0x5004,
	XSC_REG_PAOS		 = 0x5006,
	XSC_REG_PMAOS		 = 0x5012,
	XSC_REG_PUDE		 = 0x5009,
	XSC_REG_PMPE		 = 0x5010,
	XSC_REG_PELC		 = 0x500e,
	XSC_REG_PMLP		 = 0, /* TBD */
	XSC_REG_NODE_DESC	 = 0x6001,
	XSC_REG_HOST_ENDIANNESS = 0x7004,
	XSC_REG_MCIA		 = 0x9014,
};

enum dbg_rsc_type {
	XSC_DBG_RSC_QP,
	XSC_DBG_RSC_EQ,
	XSC_DBG_RSC_CQ,
};

struct xsc_field_desc {
	struct dentry	       *dent;
	int			i;
};

struct xsc_rsc_debug {
	struct xsc_core_device *xdev;
	void		       *object;
	enum dbg_rsc_type	type;
	struct dentry	       *root;
	struct xsc_field_desc	fields[];
};

struct xsc_buf_list {
	void		       *buf;
	dma_addr_t		map;
};

struct xsc_buf {
	struct xsc_buf_list	direct;
	struct xsc_buf_list   *page_list;
	int			nbufs;
	int			npages;
	int			page_shift;
	int			size;
};

struct xsc_frag_buf {
	struct xsc_buf_list	*frags;
	int			npages;
	int			size;
	u8			page_shift;
};

struct xsc_frag_buf_ctrl {
	struct xsc_buf_list   *frags;
	u32			sz_m1;
	u16			frag_sz_m1;
	u16			strides_offset;
	u8			log_sz;
	u8			log_stride;
	u8			log_frag_strides;
};

struct xsc_cq_table {
	/* protect radix tree
	 */
	spinlock_t		lock;
	struct radix_tree_root	tree;
};

struct xsc_eq {
	struct xsc_core_device   *dev;
	struct xsc_cq_table	cq_table;
	u32			doorbell;//offset from bar0/2 space start
	u32			cons_index;
	struct xsc_buf		buf;
	int			size;
	unsigned int		irqn;
	u16			eqn;
	int			nent;
	cpumask_var_t		mask;
	char			name[XSC_MAX_EQ_NAME];
	struct list_head	list;
	int			index;
	struct xsc_rsc_debug	*dbg;
};

struct xsc_core_mr {
	u64			iova;
	u64			size;
	u32			key;
	u32			pd;
	u32			access;
};

struct xsc_eq_table {
	void __iomem	       *update_ci;
	void __iomem	       *update_arm_ci;
	struct list_head       comp_eqs_list;
	struct xsc_eq		pages_eq;
	struct xsc_eq		async_eq;
	struct xsc_eq		cmd_eq;
	int			num_comp_vectors;
	int			eq_vec_comp_base;
	/* protect EQs list
	 */
	spinlock_t		lock;
};

struct xsc_irq_info {
	cpumask_var_t mask;
	char name[XSC_MAX_IRQ_NAME];
};

struct xsc_qp_table {
	/* protect radix tree
	 */
	spinlock_t		lock;
	struct radix_tree_root	tree;
};

struct counter_name_map {
	int index;
	const char *reg_name;
};

struct counter_reg_map {
	int index;
	int reg_addr;
};

struct xsc_dev_resource {
	struct xsc_qp_table qp_table;
	struct xsc_cq_table cq_table;
	struct xsc_eq_table eq_table;
	struct xsc_irq_info *irq_info;
	spinlock_t mkey_lock;	/* protect mkey */
	u8 mkey_key;
	struct mutex alloc_mutex;	/* protect buffer alocation according to numa node */
	int numa_node;
	int fw_pages;
	int reg_pages;
	struct mutex pgdir_mutex;	/* protect pgdir_list */
	struct list_head pgdir_list;
	struct dentry *qp_debugfs;
	struct dentry *eq_debugfs;
	struct dentry *cq_debugfs;
	struct dentry *cmdif_debugfs;
	struct dentry *qptrace_debugfs;
	struct dentry *dbg_root;
};

struct xsc_db {
	__be32			*db;
	union {
		struct xsc_db_pgdir		*pgdir;
		struct xsc_ib_user_db_page	*user_page;
	}			u;
	dma_addr_t		dma;
	int			index;
};

enum {
	XSC_COMP_EQ_SIZE = 1024,
};

/*replace by struct define in ofed*/
struct xsc_db_pgdir {
	struct list_head	list;
	unsigned long	       *bitmap;
	__be32		       *db_page;
	dma_addr_t		db_dma;
};

static inline void *xsc_buf_offset(struct xsc_buf *buf, int offset)
{
	if (likely(BITS_PER_LONG == 64 || buf->nbufs == 1))
		return buf->direct.buf + offset;
	else
		return buf->page_list[offset >> PAGE_SHIFT].buf +
			(offset & (PAGE_SIZE - 1));
}

static inline struct xsc_core_device *pci2xdev(struct pci_dev *pdev)
{
	return pci_get_drvdata(pdev);
}

extern struct dentry *xsc_debugfs_root;

static inline void *xsc_vzalloc(unsigned long size)
{
	void *rtn;

	rtn = kzalloc(size, GFP_KERNEL | __GFP_NOWARN);
	if (!rtn)
		rtn = vzalloc(size);
	return rtn;
}

static inline void xsc_vfree(const void *addr)
{
	if (addr && is_vmalloc_addr(addr))
		vfree(addr);
	else
		kfree(addr);
}

int xsc_dev_init(struct xsc_core_device *xdev);
void xsc_dev_cleanup(struct xsc_core_device *xdev);
int xsc_cmd_init(struct xsc_core_device *xdev);
void xsc_cmd_cleanup(struct xsc_core_device *xdev);
void xsc_cmd_use_events(struct xsc_core_device *xdev);
void xsc_cmd_use_polling(struct xsc_core_device *xdev);
int xsc_cmd_err_handler(struct xsc_core_device *xdev);
void xsc_cmd_resp_handler(struct xsc_core_device *xdev);
int xsc_cmd_status_to_err(struct xsc_outbox_hdr *hdr);
int _xsc_cmd_exec(struct xsc_core_device *xdev, void *in, int in_size, void *out,
		  int out_size);
int xsc_buf_alloc(struct xsc_core_device *xdev, int size, int max_direct,
		  struct xsc_buf *buf);
void xsc_buf_free(struct xsc_core_device *dev, struct xsc_buf *buf);
int xsc_core_create_mkey(struct xsc_core_device *dev, struct xsc_core_mr *mr);
int xsc_core_destroy_mkey(struct xsc_core_device *dev, struct xsc_core_mr *mr);
int xsc_core_register_mr(struct xsc_core_device *dev, struct xsc_core_mr *mr,
			 struct xsc_register_mr_mbox_in *in, int inlen);
int xsc_core_dereg_mr(struct xsc_core_device *dev, struct xsc_core_mr *mr);
void xsc_reg_local_dma_mr(struct xsc_core_device *dev);
int xsc_core_alloc_pd(struct xsc_core_device *xdev, u32 *pdn);
int xsc_core_dealloc_pd(struct xsc_core_device *xdev, u32 pdn);
int xsc_core_mad_ifc(struct xsc_core_device *xdev, void *inb, void *outb,
		     u16 opmod, int port);
void xsc_register_debugfs(void);
void xsc_unregister_debugfs(void);
int xsc_eq_init(struct xsc_core_device *dev);
void xsc_eq_cleanup(struct xsc_core_device *dev);
void xsc_fill_page_array(struct xsc_buf *buf, __be64 *pas, int npages);
void xsc_fill_page_frag_array(struct xsc_frag_buf *buf, __be64 *pas, int npages);
void xsc_qp_event(struct xsc_core_device *xdev, u32 qpn, int event_type);
int xsc_vector2eqn(struct xsc_core_device *dev, int vector, int *eqn,
		   unsigned int *irqn);
void xsc_cq_event(struct xsc_core_device *xdev, u32 cqn, int event_type);
int xsc_create_map_eq(struct xsc_core_device *dev, struct xsc_eq *eq, u8 vecidx,
		      int nent, const char *name);
int xsc_destroy_unmap_eq(struct xsc_core_device *dev, struct xsc_eq *eq);
int xsc_start_eqs(struct xsc_core_device *dev);
void xsc_stop_eqs(struct xsc_core_device *dev);

int xsc_qp_debugfs_init(struct xsc_core_device *dev);
void xsc_qp_debugfs_cleanup(struct xsc_core_device *dev);
int xsc_core_access_reg(struct xsc_core_device *xdev, void *data_in,
			int size_in, void *data_out, int size_out,
			u16 reg_num, int arg, int write);
int xsc_set_port_caps(struct xsc_core_device *xdev, int port_num, u32 caps);

int xsc_debug_eq_add(struct xsc_core_device *xdev, struct xsc_eq *eq);
void xsc_debug_eq_remove(struct xsc_core_device *xdev, struct xsc_eq *eq);
int xsc_core_eq_query(struct xsc_core_device *dev, struct xsc_eq *eq,
		      struct xsc_query_eq_mbox_out *out, int outlen);
int xsc_eq_debugfs_init(struct xsc_core_device *dev);
void xsc_eq_debugfs_cleanup(struct xsc_core_device *dev);
int xsc_cq_debugfs_init(struct xsc_core_device *dev);
void xsc_cq_debugfs_cleanup(struct xsc_core_device *dev);

const char *xsc_command_str(int command);
int xsc_cmdif_debugfs_init(struct xsc_core_device *xdev);
void xsc_cmdif_debugfs_cleanup(struct xsc_core_device *xdev);

int xsc_qptrace_debugfs_init(struct xsc_core_device *dev);
void xsc_qptrace_debugfs_cleanup(struct xsc_core_device *dev);

int xsc_db_alloc_node(struct xsc_core_device *xdev, struct xsc_db *db, int node);
int xsc_frag_buf_alloc_node(struct xsc_core_device *xdev, int size,
			    struct xsc_frag_buf *buf, int node);
void xsc_db_free(struct xsc_core_device *xdev, struct xsc_db *db);
void xsc_frag_buf_free(struct xsc_core_device *xdev, struct xsc_frag_buf *buf);

static inline u32 xsc_mkey_to_idx(u32 mkey)
{
	return mkey >> ((MMC_MPT_TBL_MEM_DEPTH == 32768) ? 17 : 18);
}

static inline u32 xsc_idx_to_mkey(u32 mkey_idx)
{
	return mkey_idx << ((MMC_MPT_TBL_MEM_DEPTH == 32768) ? 17 : 18);
}

enum {
	XSC_PROF_MASK_QP_SIZE		= (u64)1 << 0,
	XSC_PROF_MASK_CMDIF_CSUM	= (u64)1 << 1,
	XSC_PROF_MASK_MR_CACHE		= (u64)1 << 2,
};

#endif /* XSC_DRIVER_H */
