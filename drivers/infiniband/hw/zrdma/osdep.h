/* SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB) */
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#ifndef ZXDH_OSDEP_H
#define ZXDH_OSDEP_H

#include <linux/pci.h>
#include <linux/bitfield.h>
#include <crypto/hash.h>
#include <rdma/ib_verbs.h>
#include <linux/workqueue.h>
#include <linux/refcount.h>
#define STATS_TIMER_DELAY 60000

#if !defined(fallthrough) && !defined(__GCC4_has_attribute___noclone__) && defined(__has_attribute)
#define fallthrough __attribute__((__fallthrough__))
#endif
#ifndef fallthrough
#define fallthrough \
	do {        \
	} while (0)
#endif
#define idev_to_dev(ptr) (((ptr)->hw->device))
#ifndef ibdev_dbg
#define zxdh_dbg(idev, fmt, ...) dev_dbg(idev_to_dev(idev), fmt, ##__VA_ARGS__)
#define ibdev_err(ibdev, fmt, ...) dev_err(&((ibdev)->dev), fmt, ##__VA_ARGS__)
#define ibdev_warn(ibdev, fmt, ...) dev_warn(&((ibdev)->dev), fmt, ##__VA_ARGS__)
#define ibdev_info(ibdev, fmt, ...) dev_info(&((ibdev)->dev), fmt, ##__VA_ARGS__)
#define ibdev_notice(ibdev, fmt, ...) dev_notice(&((ibdev)->dev), fmt, ##__VA_ARGS__)
#else
#define zxdh_dbg(idev, fmt, ...)                                        \
	do {                                                            \
		struct ib_device *ibdev = zxdh_get_ibdev(idev);         \
		if (ibdev)                                              \
			ibdev_dbg(ibdev, fmt, ##__VA_ARGS__);           \
		else                                                    \
			dev_dbg(idev_to_dev(idev), fmt, ##__VA_ARGS__); \
	} while (0)
#endif

struct zxdh_dma_info {
	dma_addr_t *dmaaddrs;
};

struct zxdh_dma_mem {
	void *va;
	dma_addr_t pa;
	u32 size;
} __packed;

struct zxdh_virt_mem {
	void *va;
	u32 size;
} __packed;

struct zxdh_sc_vsi;
struct zxdh_sc_dev;
struct zxdh_sc_qp;
struct zxdh_puda_buf;
struct zxdh_puda_cmpl_info;
struct zxdh_update_sds_info;
struct zxdh_hmc_fcn_info;
struct zxdh_manage_vf_pble_info;
struct zxdh_hw;
struct zxdh_pci_f;
struct zxdh_virtchnl_req;

struct ib_device *zxdh_get_ibdev(struct zxdh_sc_dev *dev);
void *zxdh_remove_cqp_head(struct zxdh_sc_dev *dev);
void zxdh_terminate_del_timer(struct zxdh_sc_qp *qp);
void zxdh_hw_stats_start_timer(struct zxdh_sc_vsi *vsi);
void zxdh_hw_stats_stop_timer(struct zxdh_sc_vsi *vsi);
void wr32(struct zxdh_hw *hw, u32 reg, u32 val);
u32 rd32(struct zxdh_hw *hw, u32 reg);
u64 rd64(struct zxdh_hw *hw, u32 reg);
int zxdh_map_vm_page_list(struct zxdh_hw *hw, void *va, dma_addr_t *pg_dma, u32 pg_cnt);
void zxdh_unmap_vm_page_list(struct zxdh_hw *hw, dma_addr_t *pg_dma, u32 pg_cnt);
#endif /* ZXDH_OSDEP_H */
