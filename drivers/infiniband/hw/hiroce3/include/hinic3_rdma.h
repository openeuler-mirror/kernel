/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2024 Huawei Technologies Co., Ltd */

#ifndef HINIC_RDMA_H__
#define HINIC_RDMA_H__

#define RDMA_ROCE_ENABLE 1
#define RDMA_IWARP_ENABLE 1
#define RDMA_ROCE_DISABLE 0
#define RDMA_IWARP_DISABLE 0

#define RDMA_MPT_DISABLED 0 /* has no mpt entry */
#define RDMA_MPT_EN_SW 1	/* has mpt, state INVALID */
#define RDMA_MPT_EN_HW 2	/* has mpt, state FREE or VALID */

#define RDMA_MPT_FIX_BUG_LKEY 0

struct mutex;
struct tag_cqm_qpc_mpt;
struct tag_cqm_object;
struct net_device;
struct rdma_gid_entry;

#include "hinic3_cqm.h"

enum mtt_check_type_e {
	MTT_CHECK_TYPE_0 = 0,
	MTT_CHECK_TYPE_1
};

enum mtt_data_type_e {
	MTT_DMTT_TYPE = 0,
	MTT_CMTT_TYPE
};

enum rdma_ib_access {
	RDMA_IB_ACCESS_LOCAL_WRITE = 1,
	RDMA_IB_ACCESS_REMOTE_WRITE = (1 << 1),
	RDMA_IB_ACCESS_REMOTE_READ = (1 << 2),
	RDMA_IB_ACCESS_REMOTE_ATOMIC = (1 << 3),
	RDMA_IB_ACCESS_MW_BIND = (1 << 4),
	RDMA_IB_ACCESS_ZERO_BASED = (1 << 5),
	RDMA_IB_ACCESS_ON_DEMAND = (1 << 6),
};

struct rdma_gid_entry {
	union {
		u8 raw[16];
		struct {
			__be64 subnet_prefix;
			__be64 interface_id;
		} global;
	};
	union {
		struct {
			u32 rsvd : 7;
			u32 is_vroce : 1;
			u32 cvlan : 12; /* 内层vlan customer vlan */
			u32 svlan : 12; /* 外层vlan */
		} bs;
		u32 value;
	} dw4;

	union {
		u32 hdr_len_value;
	};

	union {
		struct {
			/* 0:没有vlan； 1：一层vlan； 2: 2层vlan； 3：stag */
			u16 tag : 2;
			u16 tunnel : 1; // rsvd for ppe, don't use. 'tunnel'
			u16 gid_type : 2;
			u16 ppe_rsvd1 : 1;
			u16 outer_tag : 2; // rsvd for ppe, don't use. 'outer_tag'
			u16 ppe_rsvd3 : 1; // rsvd for ppe, don't use. 'stag'
			u16 gid_update : 1;
			u16 rsvd : 6;
		} bs;
		u16 value;
	} dw6_h;

	u8 smac[6];
};

struct rdma_comp_resource {
	struct mutex mutex;				/* gid_entry使用的互斥量 */
	__be64 node_guid;				  /* 与ibdev中的node_guid一致 */
	struct rdma_gid_entry **gid_table; /* gid_entry在rdma组件初始化时分配内存 */
};

struct rdma_mpt {
	u32 mpt_index;	/* 封装cqm提供的mpt_index */
	void *vaddr;	  /* 封装cqm提供的mpt_entry的虚拟地址 */
	void *mpt_object; /* 封装的cqm提供的指针 */
};


struct rdma_mtt_seg {
	u32 offset;	   /* 分配连续索引的首个索引 */
	u32 order;		/* mtt索引个数为1<<order，每个索引对应一个mtt entry */
	void *vaddr;	  /* mtt_seg第一个MTT的起始虚拟地址 */
	dma_addr_t paddr; /* mtt_seg第一个MTT的起始物理地址 */
};

struct rdma_mtt {
	/* mtt的级数,该值为0时表示不使用mtt做地址转换 */
	u32 mtt_layers;
	u32 mtt_page_shift;			/* MTT的页大小 */
	u32 buf_page_shift;			/* buffer页大小 */
	dma_addr_t mtt_paddr;		  /* 写入context中的物理地址 */
	__be64 *mtt_vaddr;			 /* 写入context中的虚拟地址 */
	struct rdma_mtt_seg **mtt_seg; /* 指向多级mtt */
	enum mtt_data_type_e mtt_type;
};

enum rdma_mr_type {
	RDMA_DMA_MR = 0,
	RDMA_USER_MR = 1,
	RDMA_FRMR = 2,
	RDMA_FMR = 3,
	RDMA_PHYS_MR = 4,
	RDMA_RSVD_LKEY = 5,
	RDMA_SIG_MR = 6,
	RDMA_INDIRECT_MR = 8,
	RDMA_ODP_IMPLICIT_MR = 9,
	RDMA_ODP_EXPLICIT_MR = 10,
};

struct rdma_mr {
	struct rdma_mpt mpt;
	struct rdma_mtt mtt;
	u64 iova;	/* mr指向内存的起始地址(虚拟地址,ZBVA时为0) */
	u64 size;	/* mr指向内存的大小 */
	u32 key;	 /* mr对应的key */
	u32 pdn;	 /* mr绑定的pdn */
	u32 access;  /* mr的访问权限 */
	int enabled; /* mr的状态,DISABLE、EN_SW、EN_HW */
	int mr_type; /* mr类型 */
	u32 block_size;
};

enum rdma_mw_type {
	RDMA_MW_TYPE_1 = 1,
	RDMA_MW_TYPE_2 = 2
};

struct rdma_mw {
	struct rdma_mpt mpt;
	u32 key;				/* mw对应的key */
	u32 pdn;				/* mw绑定的pdn */
	enum rdma_mw_type type; /* mw的类型,type1,type2 */
	int enabled;			/* mw的状态 */
};

struct rdma_fmr {
	struct rdma_mr mr;
	u32 max_pages;  /* fmr的最大映射页个数 */
	u32 max_maps;   /* fmr的最大映射次数 */
	u32 maps;	   /* fmr的当前映射次数 */
	u32 page_shift; /* fmr指定的页偏移 */
};

struct rdma_rdmarc {
	u32 offset;	/* 分配连续索引的首个索引 */
	u32 order;	 /* 分配的rdmarc的order,代表了个数 */
	u32 ext_order; /* 包含rc表和扩展表的个数 */
	dma_addr_t dma_addr;
	void *vaddr;
};

int roce3_rdma_pd_alloc(void *hwdev, u32 *pdn);

void roce3_rdma_pd_free(void *hwdev, u32 pdn);

int roce3_rdma_enable_mw_mpt(void *hwdev, struct rdma_mw *mw, u32 service_type);

int roce3_rdma_disable_mw_mpt(void *hwdev, struct rdma_mw *mw, u32 service_type);

int roce3_rdma_map_phys_fmr(void *hwdev, struct rdma_fmr *fmr, u64 *page_list,
	int npages, u64 iova, u32 service_type);

int roce3_rdma_unmap_fmr(void *hwdev, struct rdma_fmr *fmr, u32 service_type);

int roce3_rdma_rdmarc_alloc(void *hwdev, u32 num, struct rdma_rdmarc *rdmarc);

void roce3_rdma_rdmarc_free(void *hwdev, struct rdma_rdmarc *rdmarc);

int roce3_rdma_update_gid_mac(void *hwdev, u32 port, struct rdma_gid_entry *gid_entry);
int roce3_rdma_update_gid(void *hwdev, u32 port, u32 update_index,
	struct rdma_gid_entry *gid_entry);
int roce3_rdma_reset_gid_table(void *hwdev, u32 port);

int roce3_rdma_get_gid(void *hwdev, u32 port, u32 gid_index, struct rdma_gid_entry *gid);

/* 该接口在pf初始化时调用 */
int roce3_rdma_init_resource(void *hwdev);

/* 该接口在pf卸载时调用 */
void roce3_rdma_cleanup_resource(void *hwdev);

#endif /* HINIC_RDMA_H__ */
