/* SPDX-License-Identifier: GPL-2.0 */
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2_com_cdev.h
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#ifndef __SXE2_COM_CDEV_H__
#define __SXE2_COM_CDEV_H__

#include <linux/device.h>
#include <linux/pci.h>
#include <linux/cdev.h>

#include "sxe2_log.h"
#include "sxe2_cdev.h"
#include "sxe2_com_dma.h"
#include "sxe2_com_irq.h"
#include "sxe2_com_ver_compat.h"

#define SXE2_COM_DEV_MGR_DATA_SIZE (128)
#define SXE2_MAX_IOCTL_CMDS (1)
#define SXE2_COM_CHRDEV_NAME "sxe2-dpdk"
#define SXE2VF_COM_CHRDEV_NAME "sxe2vf-dpdk"
#define SXE2_MAX_DEVICES_NUM BIT(MINORBITS)
#define SXE2_COM_CMD_DFLT_TIMEOUT (30)
#define SXE2_COM_CMD_DFLT_TIMEOUT_MS (30000)
#define SXE2_COM_DEV_MGR_DATA_CNT (1)

#define SXE2_COM_DEV_NAME 16

struct com_log_param {
	char dev_name[SXE2_COM_DEV_NAME];
	struct pci_dev *pdev;
};

#define LOG_ERROR_BDF_COM(fmt, ...)                                                 \
	{                                                                               \
		struct com_log_param *adapter = &com_ctxt->com_log_param;                   \
		LOG_ERROR_BDF(fmt, ##__VA_ARGS__);                                          \
	}

#define LOG_WARN_BDF_COM(fmt, ...)                                                  \
	{                                                                               \
		struct com_log_param *adapter = &com_ctxt->com_log_param;                   \
		LOG_WARN_BDF(fmt, ##__VA_ARGS__);                                           \
	}

#define LOG_INFO_BDF_COM(fmt, ...)                                                  \
	{                                                                               \
		struct com_log_param *adapter = &com_ctxt->com_log_param;                   \
		LOG_INFO_BDF(fmt, ##__VA_ARGS__);                                           \
	}

#define LOG_DEBUG_BDF_COM(fmt, ...)                                                 \
	{                                                                               \
		struct com_log_param *adapter = &com_ctxt->com_log_param;                   \
		LOG_DEBUG_BDF(fmt, ##__VA_ARGS__);                                          \
	}

#define LOG_DEV_ERR_COM(fmt, ...)                                                   \
	{                                                                               \
		struct com_log_param *adapter = &com_ctxt->com_log_param;                   \
		LOG_DEV_ERR(fmt, ##__VA_ARGS__);                                            \
	}

#define LOG_DEV_WARN_COM(fmt, ...)                                                  \
	{                                                                               \
		struct com_log_param *adapter = &com_ctxt->com_log_param;                   \
		LOG_DEV_WARN(fmt, ##__VA_ARGS__);                                           \
	}

#define LOG_DEV_INFO_COM(fmt, ...)                                                  \
	{                                                                               \
		struct com_log_param *adapter = &com_ctxt->com_log_param;                   \
		LOG_DEV_INFO(fmt, ##__VA_ARGS__);                                           \
	}

#define LOG_DEV_DEBUG_COM(fmt, ...)                                                 \
	{                                                                               \
		struct com_log_param *adapter = &com_ctxt->com_log_param;                   \
		LOG_DEV_DEBUG(fmt, ##__VA_ARGS__);                                          \
	}

enum sxe2_com_dev_status {
	SXE2_COM_CDEV_STATUS_UNACCESS = 0,
	SXE2_COM_CDEV_STATUS_NORMAL,
};

enum sxe2_com_module {
	SXE2_COM_MODULE_KERNEL = 0,
	SXE2_COM_MODULE_DPDK,
	SXE2_COM_MODULE_MIXED,
	SXE2_COM_MODULE_RDMA,
	SXE2_COM_MODULE_UNDEFINED,
	SXE2_COM_MODULE_INVAL,
};

enum sxe2_func_type {
	SXE2_PF = 0,
	SXE2_VF,
};

enum sxe2_drv_type {
	SXE2_KERNEL_DRV = 0,
	SXE2_DPDK_DRV,
};

struct sxe2_obj {
	u32 func_type : 2;
	u32 resv : 2;
	u32 pf_id : 4;
	u32 vf_id : 12;
	u32 resv1 : 4;
	u32 drv_type : 2;
	u32 drv_id : 6;
};

struct sxe2_com_vma_mgr {
	/* in order to protect the data */
	struct mutex vma_lock;
	struct list_head vma_list;
	struct page *read_page;
	struct page *write_page;
	u8 reserved[3];
};

struct sxe2_com_ops {
	void (*com_ctxt_fill)(void *adapter);
	s32 (*cmd_exec)(void *adapter, struct sxe2_obj *obj, struct sxe2_drv_cmd_params *param);
	s32 (*get_irq_num)(void *adapter);
	s32 (*get_vector)(void *adapter, u16 irq_id_in_com);
	s32 (*release)(void *adapter, struct sxe2_obj *obj);
	s32 (*com_mode_get)(void *adapter);
};

struct sxe2_com_context {
	void *adapter;
	struct pci_dev *pdev;
	struct sxe2_com_ops *ops;
	struct com_log_param com_log_param;
	u8 dpdk_mode;
	atomic_t ref_count;
	struct list_head list;
	wait_queue_head_t waitq;
	enum sxe2_com_dev_status status;
	struct sxe2_cdev_info cdev_info;
	enum sxe2_func_type func_type;
	u16 pf_id;
	u16 vf_id;
	bool is_handshake;
	u32 dpdk_ver;
	struct sxe2_com_irqs_ctxt irqs;
	struct sxe2_com_vma_mgr vma;
	struct sxe2_com_dma_dev dma_dev;
	struct sxe2_obj obj;
	/* in order to protect the data */
	struct mutex com_lock;
};

struct sxe2_com_dev_mgr {
	/* in order to protect the data */
	struct mutex lock;
};

struct sxe2_com_vma_device {
	struct vm_area_struct *vma;
	struct list_head vma_next;
};

#define SXE2_DRV_MSG_INFO_SIZE (sizeof(struct drv_msg_info))
#define SXE2_COM_DRV_REQ_MSG_HDR(param) ((struct drv_msg_info *)(param)->req_buff)

#define SXE2_DRV_MSG_MAX_SIZE (8192)
#define SXE2_DRV_MSG_MAGIC_CODE (0x56781234)
#define SXE2_MOD_DRV (1)
#define SXE2_SUB_MOD_DEV (1)

#define MODULE_ID_SHIFT (24)
#define SUB_MODULE_ID_SHIFT (16)
#define ERROR_INDEX_MASK (0xFFFF0000)
#define SXE2_MAKE_ERR_CODE_INDEX(module, sub_module)                                         \
	((((u32)((module) << MODULE_ID_SHIFT)) | ((u32)((sub_module) << SUB_MODULE_ID_SHIFT))) & \
	 ERROR_INDEX_MASK)

#define SXE2_COM_MODE_NAME_SIZE    64
#define SXE2_COM_KERNEL_MODE_NAME  "kernel"
#define SXE2_COM_DPDK_MODE_NAME    "dpdk"
#define SXE2_COM_RDMA_MODE_NAME    "rdma"
#define SXE2_COM_MIXED_MODE_NAME   "mixed"
#define SXE2_COM_UNDEFINED_MODE_NAME   "undefined"

void sxe2_com_deinit(struct sxe2_com_context *com_ctxt);

s32 sxe2_com_init(struct sxe2_com_context *com_ctxt, void *adapter, struct sxe2_com_ops *ops);

s32 sxe2_com_adapter_register(enum sxe2_func_type func_type);

void sxe2_com_adapter_unregister(void);

s32 sxe2_com_mode_get(void *adapter);

void sxe2_com_disable(struct sxe2_com_context *com_ctxt);

void sxe2_com_enable(struct sxe2_com_context *com_ctxt);

void sxe2_com_info_print(struct sxe2_com_context *com_ctxt);

#endif
