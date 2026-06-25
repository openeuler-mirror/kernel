/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hinic5_hw.h
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   :
 */

#ifndef HINIC5_HW_H
#define HINIC5_HW_H

#include <linux/types.h>

#include "mpu_inband_cmd_defs.h"
#include "hinic5_crm.h"

#ifndef BIG_ENDIAN
#define BIG_ENDIAN 0x4321		/**< Big endian byte order */
#endif

#ifndef LITTLE_ENDIAN
#define LITTLE_ENDIAN 0x1234	/**< Little endian byte order */
#endif

#ifdef BYTE_ORDER
#undef BYTE_ORDER
#endif
/* X86 */
#define BYTE_ORDER LITTLE_ENDIAN
/* to use 0-level CLA, page size must be: SQ 16B(wqe) * 64k(max_q_depth) */
#define HINIC5_DEFAULT_WQ_PAGE_SIZE 0x100000	/**< Default work queue page size */
#define HINIC5_HW_WQ_PAGE_SIZE 0x1000			/**< Hardware send queue page size */
#define HINIC5_MAX_WQ_PAGE_SIZE_ORDER 8			/**< Maximum work queue page size order */
#define SPU_HOST_ID 4		/**< Host ID */

/**< NIC resource type indicator */
#define HINIC5_NIC_RES	BIT(RES_TYPE_NIC)

/**
 * @brief enum hinic5_channel_id - Channel type
 * @details Defines the enumeration type for Hinic5 channels
 */
enum hinic5_channel_id {
	HINIC5_CHANNEL_DEFAULT,
	HINIC5_CHANNEL_COMM,
	HINIC5_CHANNEL_NIC,
	HINIC5_CHANNEL_ROCE,
	HINIC5_CHANNEL_TOE,
	HINIC5_CHANNEL_FC,
	HINIC5_CHANNEL_OVS,
	HINIC5_CHANNEL_DSW,
	HINIC5_CHANNEL_MIG,
	HINIC5_CHANNEL_CRYPT,
	HINIC5_CHANNEL_UB,
	HINIC5_CHANNEL_JBOF,
	HINIC5_CHANNEL_MACSEC,
	HINIC5_CHANNEL_DMMU,
	HINIC5_CHANNEL_HIHTR,

	HINIC5_CHANNEL_MAX = 32,
};

/**
 * @brief struct hinic5_cmd_buf - dma buffer object
 * @details Defines a dma buffer structure
 */
struct hinic5_cmd_buf {
	void *buf;                    /**< va for buffer */
	dma_addr_t dma_addr;          /**< dma address for buffer */
	u16 size;                     /**< buffer size */
	atomic_t ref_cnt;             /**< buffer reference count */
};

/**
 * @brief struct hinic5_cmdq_cmd_param - cmdq request object
 * @details Stores cmdq request parameters
 */
struct hinic5_cmdq_cmd_param {
	u8 mod;   /**< mod id */
	u8 cmd;   /**< cmd opcode */
	struct hinic5_cmd_buf *buf_in;   /**< input buf, only support 32B/96B/160B for inline data mode */
	struct hinic5_cmd_buf *buf_out;   /**< output buf writed by chip to return data */
	u64 *out_param;  /**< output data, only support 8B */
};

/**
 * @brief enum hinic5_hwdev_init_state
 * @details Defines the enumeration type for hardware device initialization state
 */
enum hinic5_hwdev_init_state {
	HINIC5_HWDEV_NONE_INITED = 0,	/**< Device not initialized */
	HINIC5_HWDEV_MGMT_INITED,		/**< Device management module initialized */
	HINIC5_HWDEV_MBOX_INITED,		/**< Device mailbox module initialized */
	HINIC5_HWDEV_CMDQ_INITED,		/**< Device cmdq module initialized */
};

/**
 * @brief struct hinic5_ceq_info - CEQ configuration info description
 * @details NA
 */
struct hinic5_ceq_info {
	u32 q_len;  /**< ceq length */
	u32 page_size; /**< ceq page size */
	u16 elem_size; /**< ceq element size */
	u16 num_pages;  /**< number of ceq pages*/
	u32 num_elem_in_pg; /**< number of ceq element in one page */
};

/**
 * @brief enum hinic5_ceq_event - CEQE event type
 * @details Defines Hinic5 interrupt event types
 */
enum hinic5_ceq_event {
	HINIC5_NON_L2NIC_SCQ,		/**< Non-L2NIC SCQ interrupt event */
	HINIC5_NON_L2NIC_ECQ,		/**< Non-L2NIC ECQ interrupt event */
	HINIC5_NON_L2NIC_NO_CQ_EQ,	/**< Non-L2NIC no CQ interrupt event */
	HINIC5_CMDQ,		/**< Command queue interrupt event */
	HINIC5_L2NIC_SQ,	/**< L2NIC send queue interrupt event */
	HINIC5_L2NIC_RQ,	/**< L2NIC receive queue interrupt event */
	HINIC5_CEQ_EVENT_RSVD,		/**< Reserved interrupt event */
	HINIC5_FAST_MSG_RQ,			/**< Fast message receive queue interrupt event */
	HINIC5_MAX_CEQ_EVENTS,		/**< Number of CEQE types */
};

/**
 * @brief enum hinic5_mbox_seg_errcode
 * @details Mailbox error code enumeration type
 */
enum hinic5_mbox_seg_errcode {
	MBOX_ERRCODE_NO_ERRORS		= 0,
	MBOX_ERRCODE_VF_TO_WRONG_FUNC	= 0x100,	/**< VF sends mailbox data to wrong target device */
	MBOX_ERRCODE_PPF_TO_WRONG_FUNC	= 0x200,	/**< PPF sends mailbox data to wrong target device */
	MBOX_ERRCODE_PF_TO_WRONG_FUNC	= 0x300,	/**< PF sends mailbox data to wrong target device */
	MBOX_ERRCODE_ZERO_DATA_SIZE	= 0x400,		/**< Mailbox data size set to all zeros */
	MBOX_ERRCODE_UNKNOWN_SRC_FUNC	= 0x500,	/**< Unknown source device */
	MBOX_ERRCODE_UNKNOWN_DES_FUNC	= 0x600,	/**< Unknown destination device */
};

/**
 * @brief Callback type for handling CEQE events
 * @param pri_handle Callback private data
 * @param ceqe_data CEQE data
 *
 * @return NA
 */
typedef void (*hinic5_ceq_event_cb)(void *pri_handle, u32 ceqe_data);

/**
 * @brief Define function pointer type named hinic5_aeq_swe_cb
 * @param pri_handle Parameter is a void pointer representing private handle
 * @param event Parameter is a u8 type representing event
 * @param data Parameter is a u8 pointer representing data
 *
 * @return Return value is u8 type function pointer
 */
typedef u8 (*hinic5_aeq_swe_cb)(void *pri_handle, u8 event, u8 *data);

/**
 * @brief Define a function pointer type for handling virtual function mailbox callback
 * @param pri_handle Pointer to private handle
 * @param cmd Command
 * @param buf_in Input buffer
 * @param in_size Input buffer size
 * @param buf_out Output buffer
 * @param out_size Pointer to output buffer size
 *
 * @return Whether successful
 * 		@retval zero: success
 * 		@retval non-zero: failure
 */
typedef int (*hinic5_vf_mbox_cb)(void *pri_handle, u16 cmd,
	     void *buf_in, u16 in_size, void *buf_out, u16 *out_size);

/**
 * @brief Define a function pointer type for handling PF mailbox callback
 * @param pri_handle Master handle
 * @param vf_id Virtual function ID
 * @param cmd Command
 * @param buf_in Input buffer
 * @param in_size Input buffer size
 * @param buf_out Output buffer
 * @param out_size Output buffer size
 *
 * @return Whether successful
 * 		@retval zero: success
 * 		@retval non-zero: failure
 */
typedef int (*hinic5_pf_mbox_cb)(void *pri_handle, u16 vf_id, u16 cmd, void *buf_in,
	     u16 in_size, void *buf_out, u16 *out_size);

/**
 * @brief Define a function pointer type for handling PF to VF mailbox communication
 * @param pri_handle Device handle
 * @param pf_idx PF index
 * @param vf_id VF ID
 * @param cmd Command
 * @param buf_in Input buffer
 * @param in_size Input buffer size
 * @param buf_out Output buffer
 * @param out_size Output buffer size
 *
 * @return Whether successful
 * 		@retval zero: success
 * 		@retval non-zero: failure
 */
typedef int (*hinic5_ppf_mbox_cb)(void *pri_handle, u16 pf_idx, u16 vf_id, u16 cmd, void *buf_in,
	     u16 in_size, void *buf_out, u16 *out_size);

/**
 * @brief Define a function pointer type for receiving messages from PPF mailbox
 * @param pri_handle Private handle
 * @param cmd Command
 * @param buf_in Input buffer
 * @param in_size Input buffer size
 * @param buf_out Output buffer
 * @param out_size Output buffer size
 *
 * @return Return value
 */
typedef int (*hinic5_pf_recv_from_ppf_mbox_cb)(void *pri_handle, u16 cmd, void *buf_in,
	     u16 in_size, void *buf_out, u16 *out_size);

/**
 * @brief Define a function pointer type for handling management messages
 * @param pri_handle Private handle passed to callback function
 * @param cmd Command code representing the operation to be performed
 * @param buf_in Input buffer for passing input parameters
 * @param in_size Input buffer size for limiting input parameter length
 * @param buf_out Output buffer for passing output results
 * @param out_size Output buffer size for limiting output result length
 *
 * @return None
 */
typedef void (*hinic5_mgmt_msg_cb)(void *pri_handle, u16 cmd, void *buf_in, u16 in_size,
	      void *buf_out, u16 *out_size);

u8 hinic5_nic_sw_aeqe_stats(void *hwdev, u8 event, u8 *data);

/**
 * @brief Register handler for stateless aeqe generated by microcode
 *
 * @param hwdev Device object pointer (struct hinic5_hwdev *)
 * @param pri_handle Callback function private data
 * @param stateless_aeq_swe_cb Callback function
 *
 * @details NA
 *
 * @attention: NA
 *
 * @return: Function return value description.
 *     @retval 0 Registration success
 *     @retval non-zero Registration failure
 */
int hinic5_register_stateless_aeqs(void *hwdev, void *pri_handle, hinic5_aeq_swe_cb stateless_aeq_swe_cb);

/**
 * @brief Unregister handler for stateless aeqe generated by microcode
 *
 * @param hwdev Device object pointer (struct hinic5_hwdev *)
 *
 * @details NA
 *
 * @attention: NA
 *
 * @return: NA
 */
void hinic5_unregister_stateless_aeqs(void *hwdev);

/**
 * @brief hinic5_ceq_register_cb -  register ceq callback
 * @param hwdev: device pointer to hwdev
 * @param event: event type
 * @param callback: callback function
 *
 * @return
 * 		@retval zero: success
 * 		@retval non-zero: failure
 */
int hinic5_ceq_register_cb(void *hwdev, void *pri_handle, enum hinic5_ceq_event event,
			   hinic5_ceq_event_cb callback);
/**
 * @brief hinic5_ceq_unregister_cb - unregister ceq callback
 * @param hwdev: device pointer to hwdev
 * @param event: event type
 **/
void hinic5_ceq_unregister_cb(void *hwdev, enum hinic5_ceq_event event);

/**
 * @brief Register handler for PPF mailbox messages
 *
 * @param hwdev Device object pointer
 * @param mod Service module, value is HINIC5_MOD_XXX macro definition
 * @param pri_handle Callback private data
 * @param callback Callback function
 *
 * @details NA
 *
 * @attention: NA
 *
 * @return: Function return value description.
 *     @retval 0 Success
 *     @retval non-zero Failure
 */
int hinic5_register_ppf_mbox_cb(void *hwdev, u8 mod, void *pri_handle,
				hinic5_ppf_mbox_cb callback);

/**
 * @brief Register handler for PF mailbox messages
 *
 * @param hwdev Device object pointer
 * @param mod Service module, value is HINIC5_MOD_XXX macro definition
 * @param pri_handle Callback private data
 * @param callback Callback function
 *
 * @details NA
 *
 * @attention: NA
 *
 * @return: Function return value description.
 *     @retval 0 Success
 *     @retval non-zero Failure
 */
int hinic5_register_pf_mbox_cb(void *hwdev, u8 mod, void *pri_handle,
			       hinic5_pf_mbox_cb callback);

/**
 * @brief Register handler for VF mailbox messages
 *
 * @param hwdev Device object pointer
 * @param mod Service module, value is HINIC5_MOD_XXX macro definition
 * @param pri_handle Callback private data
 * @param callback Callback function
 *
 * @details NA
 *
 * @attention: NA
 *
 * @return: Function return value description.
 *     @retval 0 Success
 *     @retval non-zero Failure
 */
int hinic5_register_vf_mbox_cb(void *hwdev, u8 mod, void *pri_handle,
			       hinic5_vf_mbox_cb callback);

/**
 * @brief Unregister PPF mailbox callback
 *
 * @param hwdev Device object pointer
 * @param mod Service module, value is HINIC5_MOD_XXX macro definition
 *
 * @details NA
 *
 * @attention: NA
 *
 * @return: NA
 */
void hinic5_unregister_ppf_mbox_cb(void *hwdev, u8 mod);

/**
 * @brief Unregister PF mailbox callback
 *
 * @param hwdev Device object pointer
 * @param mod Service module, value is HINIC5_MOD_XXX macro definition
 *
 * @details NA
 *
 * @attention: NA
 *
 * @return: NA
 */
void hinic5_unregister_pf_mbox_cb(void *hwdev, u8 mod);

/**
 * @brief Unregister VF mailbox callback
 *
 * @param hwdev Device object pointer
 * @param mod Service module, value is HINIC5_MOD_XXX macro definition
 *
 * @details NA
 *
 * @attention: NA
 *
 * @return: NA
 */
void hinic5_unregister_vf_mbox_cb(void *hwdev, u8 mod);

/**
 * @brief Unregister PF mailbox callback
 *
 * @param hwdev Device object pointer
 * @param mod Service module, value is HINIC5_MOD_XXX macro definition
 *
 * @details source is PPF
 *
 * @attention: NA
 *
 * @return: NA
 */
void hinic5_unregister_ppf_to_pf_mbox_cb(void *hwdev, u8 mod);

/**
 * @brief Register handler for function mailbox messages
 *
 * @param hwdev Device object pointer
 * @param mod Service module, value is HINIC5_MOD_XXX macro definition
 * @param pri_handle Callback private data
 * @param callback Callback function
 *
 * @details source is MPU
 *
 * @attention: NA
 *
 * @return: Function return value description.
 *     @retval 0 Success
 *     @retval non-zero Failure
 */
int hinic5_register_mgmt_msg_cb(void *hwdev, u8 mod, void *pri_handle,
				hinic5_mgmt_msg_cb callback);

/**
 * @brief Unregister function mailbox callback
 *
 * @param hwdev Device object pointer
 * @param mod Service module, value is HINIC5_MOD_XXX macro definition
 *
 * @details source is MPU
 *
 * @attention: NA
 *
 * @return: NA
 */
void hinic5_unregister_mgmt_msg_cb(void *hwdev, u8 mod);

/**
 * @brief hinic5_register_service_adapter - register service adapter
 * @param hwdev: device pointer to hwdev
 * @param service_adapter: service adapter
 * @param type: service type
 *
 * @return
 * 		@retval zero: success
 * 		@retval non-zero: failure
 */
int hinic5_register_service_adapter(void *hwdev, void *service_adapter,
				    enum hinic5_service_type type);

/**
 * @brief hinic5_unregister_service_adapter - unregister service adapter
 * @param hwdev: device pointer to hwdev
 * @param type: service type
 **/
void hinic5_unregister_service_adapter(void *hwdev,
				       enum hinic5_service_type type);

/**
 * @brief hinic5_get_service_adapter - get service adapter
 * @param hwdev: device pointer to hwdev
 * @param type: service type
 *
 * @return
 * 		@retval non-zero: success
 * 		@retval null: failure
 */
void *hinic5_get_service_adapter(void *hwdev, enum hinic5_service_type type);

/**
 * @brief hinic5_alloc_db_phy_addr - alloc doorbell & direct wqe pyhsical addr
 * @param hwdev: device pointer to hwdev
 * @param db_base: pointer to alloc doorbell base address
 * @param dwqe_base: pointer to alloc direct base address
 *
 * @return
 * 		@retval zero: success
 * 		@retval non-zero: failure
 */
int hinic5_alloc_db_phy_addr(void *hwdev, u64 *db_base, u64 *dwqe_base);

/**
 * @brief hinic5_free_db_phy_addr - free doorbell & direct wqe physical address
 * @param hwdev: device pointer to hwdev
 * @param db_base: pointer to free doorbell base address
 * @param dwqe_base: pointer to free direct base address
 **/
void hinic5_free_db_phy_addr(void *hwdev, u64 db_base, u64 dwqe_base);

/**
 * @brief hinic5_alloc_db_addr - alloc doorbell & direct wqe
 * @param hwdev: device pointer to hwdev
 * @param db_base: pointer to alloc doorbell base address
 * @param dwqe_base: pointer to alloc direct base address
 *
 * @return
 * 		@retval zero: success
 * 		@retval non-zero: failure
 */
int hinic5_alloc_db_addr(void *hwdev, void __iomem **db_base,
			 void __iomem **dwqe_base);

/**
 * @brief hinic5_free_db_addr - free doorbell & direct wqe
 * @param hwdev: device pointer to hwdev
 * @param db_base: pointer to free doorbell base address
 * @param dwqe_base: pointer to free direct base address
 **/
void hinic5_free_db_addr(void *hwdev, const void __iomem *db_base,
			 void __iomem *dwqe_base);

/**
 * @brief hinic5_alloc_db_phy_addr - alloc physical doorbell & direct wqe
 * @param hwdev: device pointer to hwdev
 * @param db_base: pointer to alloc doorbell base address
 * @param dwqe_base: pointer to alloc direct base address
 *
 * @return
 * 		@retval zero: success
 * 		@retval non-zero: failure
 */
int hinic5_alloc_db_phy_addr(void *hwdev, u64 *db_base, u64 *dwqe_base);

/**
 * @brief hinic5_free_db_phy_addr - free physical doorbell & direct wqe
 * @param hwdev: device pointer to hwdev
 * @param db_base: free doorbell base address
 * @param dwqe_base: free direct base address
 **/

void hinic5_free_db_phy_addr(void *hwdev, u64 db_base, u64 dwqe_base);

/**
 * @brief hinic5_set_root_ctxt - set root context
 * @param hwdev: device pointer to hwdev
 * @param rq_depth: rq depth
 * @param sq_depth: sq depth
 * @param rx_buf_sz: rx buffer size
 * @param channel: channel id
 *
 * @return
 * 		@retval zero: success
 * 		@retval non-zero: failure
 */
int hinic5_set_root_ctxt(void *hwdev, u32 rq_depth, u32 sq_depth,
			 u16 rx_buf_sz, u16 channel);

/**
 * @brief hinic5_clean_root_ctxt - clean root context
 * @param hwdev: device pointer to hwdev
 * @param channel: channel id
 *
 * @return
 * 		@retval zero: success
 * 		@retval non-zero: failure
 */
int hinic5_clean_root_ctxt(void *hwdev, u16 channel);

/**
 * @brief hinic5_alloc_cmd_buf - alloc cmd buffer
 * @param hwdev: device pointer to hwdev
 *
 * @return
 * 		@retval non-zero: success
 * 		@retval null: failure
 * @note
 * 		Allocated memory does not support default zeroing, caller should zero according to needs
 */
struct hinic5_cmd_buf *hinic5_alloc_cmd_buf(void *hwdev);

/**
 * @brief hinic5_free_cmd_buf - free cmd buffer
 * @param hwdev: device pointer to hwdev
 * @param cmd_buf: cmd buffer to free
 **/
void hinic5_free_cmd_buf(void *hwdev, struct hinic5_cmd_buf *cmd_buf);

/**
 * @brief Read 16-bit counter value
 * @param hwdev Hardware device context
 * @param node Node number
 * @param instance Instance number
 * @param ctr_id Counter ID
 * @param value Pointer to store the read counter value
 *
 * @return 0 on success, other values indicate failure
 */
int hinic5_sm_ctr_rd16(void *hwdev, u8 node, u8 instance, u32 ctr_id, u16 *value);

/**
 * @brief hinic5_sm_ctr_rd32 - small single 32 counter read
 * @param hwdev: device pointer to hwdev
 * @param node: the node id
 * @param instance: instance id
 * @param ctr_id: counter id
 * @param value: read counter value ptr
 *
 * @return
 * 		@retval zero: success
 * 		@retval non-zero: failure
 */
int hinic5_sm_ctr_rd32(void *hwdev, u8 node, u8 instance, u32 ctr_id,
		       u32 *value);
/**
 * @brief hinic5_sm_ctr_rd32_clear - small single 32 counter read clear
 * @param hwdev: device pointer to hwdev
 * @param node: the node id
 * @param instance: instance id
 * @param ctr_id: counter id
 * @param value: read counter value ptr
 *
 * @return
 * 		@retval zero: success
 * 		@retval non-zero: failure
 */
int hinic5_sm_ctr_rd32_clear(void *hwdev, u8 node, u8 instance,
			     u32 ctr_id, u32 *value);

/**
 * @brief hinic5_sm_ctr_rd64_pair - big pair 128 counter read
 * @param hwdev: device pointer to hwdev
 * @param node: the node id
 * @param instance: instance id
 * @param ctr_id: counter id
 * @param value1: read counter value ptr
 * @param value2: read counter value ptr
 *
 * @return
 * 		@retval zero: success
 * 		@retval non-zero: failure
 */
int hinic5_sm_ctr_rd64_pair(void *hwdev, u8 node, u8 instance,
			    u32 ctr_id, u64 *value1, u64 *value2);

/**
 * @brief Read and clear 64-bit counter pair value
 * @param hwdev Hardware device context
 * @param node Node number
 * @param instance Instance number
 * @param ctr_id Counter ID
 * @param value1 Pointer to store the first value of the 64-bit counter pair
 * @param value2 Pointer to store the second value of the 64-bit counter pair
 *
 * @return 0 on success, other values indicate failure
 */
int hinic5_sm_ctr_rd64_pair_clear(void *hwdev, u8 node, u8 instance,
				  u32 ctr_id, u64 *value1, u64 *value2);

/**
 * @brief hinic5_sm_ctr_rd64 - big counter 64 read
 * @param hwdev: device pointer to hwdev
 * @param node: the node id
 * @param instance: instance id
 * @param ctr_id: counter id
 * @param value: read counter value ptr
 *
 * @return
 * 		@retval zero: success
 * 		@retval non-zero: failure
 */
int hinic5_sm_ctr_rd64(void *hwdev, u8 node, u8 instance, u32 ctr_id,
		       u64 *value);

/**
 * @brief Clear 64-bit counter value
 * @param hwdev Hardware device handle
 * @param node Node number
 * @param instance Instance number
 * @param ctr_id Counter ID
 * @param value Pointer to store the read counter value
 *
 * @return 0 on success, other values indicate failure
 */
int hinic5_sm_ctr_rd64_clear(void *hwdev, u8 node, u8 instance,
			     u32 ctr_id, u64 *value);

/**
 * @brief hinic5_api_csr_rd32 - read 32 byte csr
 * @param hwdev: device pointer to hwdev
 * @param dest: hardware node id
 * @param addr: reg address
 * @param val: reg value
 *
 * @return
 * 		@retval zero: success
 * 		@retval non-zero: failure
 */
int hinic5_api_csr_rd32(void *hwdev, u8 dest, u32 addr, u32 *val);

/**
 * @brief hinic5_api_csr_wr32 - write 32 byte csr
 * @param hwdev: device pointer to hwdev
 * @param dest: hardware node id
 * @param addr: reg address
 * @param val: reg value
 *
 * @return
 * 		@retval zero: success
 * 		@retval non-zero: failure
 */
int hinic5_api_csr_wr32(void *hwdev, u8 dest, u32 addr, u32 val);

/**
 * @brief hinic5_api_csr_rd64 - read 64 byte csr
 * @param hwdev: device pointer to hwdev
 * @param dest: hardware node id
 * @param addr: reg address
 * @param val: reg value
 *
 * @return
 * 		@retval zero: success
 * 		@retval non-zero: failure
 */
int hinic5_api_csr_rd64(void *hwdev, u8 dest, u32 addr, u64 *val);

/**
 * @brief hinic5_dbg_get_hw_stats - get hardware stats
 * @param hwdev: device pointer to hwdev
 * @param hw_stats: pointer to memory caller to alloc
 * @param out_size: out size
 *
 * @return
 * 		@retval zero: success
 * 		@retval non-zero: failure
 */
int hinic5_dbg_get_hw_stats(const void *hwdev, u8 *hw_stats, const u32 *out_size);

/**
 * @brief hinic5_dbg_clear_hw_stats - clear hardware stats
 * @param hwdev: device pointer to hwdev
 * @return clear hardware size
 */
u16 hinic5_dbg_clear_hw_stats(void *hwdev);

/**
 * @brief hinic5_get_chip_fault_stats - get chip fault stats
 * @param hwdev: device pointer to hwdev
 * @param chip_fault_stats: pointer to memory caller to alloc
 * @param offset: offset
 */
void hinic5_get_chip_fault_stats(const void *hwdev, u8 *chip_fault_stats,
				 u32 offset);

/**
 * @brief hinic5_msg_to_mgmt_sync - msg to management cpu
 * @param hwdev: device pointer to hwdev
 * @param mod: mod type
 * @param cmd: cmd
 * @param buf_in: message buffer in
 * @param in_size: in buffer size
 * @param buf_out: message buffer out
 * @param out_size: out buffer size
 * @param timeout: timeout
 * @param channel: channel id
 *
 * @return
 * 		@retval zero: success
 * 		@retval non-zero: failure
 */
int hinic5_msg_to_mgmt_sync(void *hwdev, u8 mod, u16 cmd, void *buf_in,
			    u16 in_size, void *buf_out, u16 *out_size,
			    u32 timeout, u16 channel);

/**
 * @brief hinic5_msg_to_mgmt_async - msg to management cpu async
 * @param hwdev: device pointer to hwdev
 * @param mod: mod type
 * @param cmd: cmd
 * @param buf_in: message buffer in
 * @param in_size: in buffer size
 * @param channel: channel id
 *
 * @details The function does not sleep inside, allowing use in irq context
 * @return
 * 		@retval zero: success
 * 		@retval non-zero: failure
 */
int hinic5_msg_to_mgmt_async(void *hwdev, u8 mod, u16 cmd, const void *buf_in,
			     u16 in_size, u16 channel);

/**
 * @brief hinic5_msg_to_mgmt_no_ack - msg to management cpu don't need no ack
 * @param hwdev: device pointer to hwdev
 * @param mod: mod type
 * @param cmd: cmd
 * @param buf_in: message buffer in
 * @param in_size: in buffer size
 * @param channel: channel id
 *
 * @details The function will sleep inside, and it is not allowed to be used in interrupt context
 * @return Whether send is successful
 * 		@retval zero: success
 * 		@retval non-zero: failure
 */
int hinic5_msg_to_mgmt_no_ack(void *hwdev, u8 mod, u16 cmd, void *buf_in,
			      u16 in_size, u16 channel);

/**
 * @brief Send async message to management processing chain
 * @param hwdev Hardware device context
 * @param mod Message module
 * @param cmd Message command
 * @param buf_in Input buffer
 * @param in_size Input buffer size
 *
 * @return Whether send is successful
 * 		@retval zero: success
 * 		@retval non-zero: failure
 */
int hinic5_msg_to_mgmt_api_chain_async(void *hwdev, u8 mod, u16 cmd,
				       const void *buf_in, u16 in_size);

int hinic5_msg_to_mgmt_api_chain_sync(void *hwdev, u8 mod, u16 cmd,
				      void *buf_in, u16 in_size, void *buf_out,
				      u16 *out_size, u32 timeout);

/**
 * @brief hinic5_mbox_to_pf - vf mbox message to pf
 * @param hwdev: device pointer to hwdev
 * @param mod: mod type
 * @param cmd: cmd
 * @param buf_in: message buffer in
 * @param in_size: in buffer size
 * @param buf_out: message buffer out
 * @param out_size: out buffer size
 * @param timeout: timeout
 * @param channel: channel id
 *
 * @return Whether successful
 * 		@retval zero: success
 * 		@retval non-zero: failure
 */
int hinic5_mbox_to_pf(void *hwdev, u8 mod, u16 cmd, void *buf_in,
		      u16 in_size, void *buf_out, u16 *out_size,
		      u32 timeout, u16 channel);

/**
 * @brief hinic5_mbox_to_vf - mbox message to vf
 * @param hwdev: device pointer to hwdev
 * @param vf_id: vf index
 * @param mod: mod type
 * @param cmd: cmd
 * @param buf_in: message buffer in
 * @param in_size: in buffer size
 * @param buf_out: message buffer out
 * @param out_size: out buffer size
 * @param timeout: timeout
 * @param channel: channel id
 *
 * @return Whether successful
 * 		@retval zero: success
 * 		@retval non-zero: failure
 */
int hinic5_mbox_to_vf(void *hwdev, u16 vf_id, u8 mod, u16 cmd, void *buf_in,
		      u16 in_size, void *buf_out, u16 *out_size, u32 timeout,
		      u16 channel);

/**
 * @brief hinic5_mbox_to_vf_without_ack - mbox message to vf without ack
 * @param hwdev: device pointer to hwdev
 * @param vf_id: vf index
 * @param mod: mod type
 * @param cmd: cmd
 * @param buf_in: message buffer in
 * @param in_size: in buffer size
 * @param channel: channel id
 *
 * @return Whether successful
 * 		@retval zero: success
 * 		@retval non-zero: failure
 */
int hinic5_mbox_to_vf_without_ack(void *hwdev, u16 vf_id, u8 mod, u16 cmd,
								  void *buf_in, u16 in_size,  u16 channel);

/**
 * @brief hinic5_mbox_to_vf_no_ack - mbox message to vf no ack
 * @param hwdev: device pointer to hwdev
 * @param vf_id: vf index
 * @param mod: mod type
 * @param cmd: cmd
 * @param buf_in: message buffer in
 * @param in_size: in buffer size
 * @param buf_out: message buffer out
 * @param out_size: out buffer size
 * @param channel: channel id
 *
 * @return Whether successful
 * 		@retval zero: success
 * 		@retval non-zero: failure
 */
int hinic5_mbox_to_vf_no_ack(void *hwdev, u16 vf_id, u8 mod, u16 cmd, void *buf_in,
			     u16 in_size, void *buf_out, u16 *out_size, u16 channel);

int hinic5_clp_to_mgmt(void *hwdev, u8 mod, u16 cmd, const void *buf_in,
		       u16 in_size, void *buf_out, u16 *out_size);
/**
 * @brief hinic5_cmdq_async - cmdq asynchronous message
 * @param hwdev: device pointer to hwdev
 * @param mod: mod type
 * @param cmd: cmd
 * @param buf_in: message buffer in
 * @param channel: channel id
 *
 * @return Whether successful
 * 		@retval zero: success
 * 		@retval non-zero: failure
 */
int hinic5_cmdq_async(void *hwdev, u8 mod, u8 cmd, struct hinic5_cmd_buf *buf_in, u16 channel);

/**
 * @brief hinic5_cmdq_direct_resp - cmdq direct message response
 * @param hwdev: device pointer to hwdev
 * @param mod: mod type
 * @param cmd: cmd
 * @param buf_in: message buffer in
 * @param out_param: message out
 * @param timeout: timeout
 * @param channel: channel id
 *
 * @return Whether successful
 * 		@retval zero: success
 * 		@retval non-zero: failure
 */
int hinic5_cmdq_direct_resp(void *hwdev, u8 mod, u8 cmd,
			    struct hinic5_cmd_buf *buf_in,
			    u64 *out_param, u32 timeout, u16 channel);

/**
 * @brief hinic5_cmdq_detail_resp - cmdq detail message response
 * @param hwdev: device pointer to hwdev
 * @param mod: mod type
 * @param cmd: cmd
 * @param buf_in: message buffer in
 * @param buf_out: message buffer out
 * @param out_param: inline output data
 * @param timeout: timeout
 * @param channel: channel id
 *
 * @return Whether successful
 * 		@retval zero: success
 * 		@retval non-zero: failure
 */
int hinic5_cmdq_detail_resp(void *hwdev, u8 mod, u8 cmd,
			    struct hinic5_cmd_buf *buf_in,
			    struct hinic5_cmd_buf *buf_out,
			    u64 *out_param, u32 timeout, u16 channel);

/**
 * @brief hinic5_cmdq_inline_data - cmdq with inline data
 * @param hwdev: device pointer to hwdev
 * @param cmd_param: cmd info, see struct hinic5_cmdq_cmd_param
 * @param timeout: timeout
 * @param channel: channel id
 *
 * @return Whether successful
 * 		@retval zero: success
 * 		@retval non-zero: failure
 */
int hinic5_cmdq_inline_data(void *hwdev, struct hinic5_cmdq_cmd_param *cmd_param,
			    u32 timeout, u16 channel);

/**
 * @brief hinic5_cos_id_detail_resp - cmdq detail message response
 * @param hwdev: device pointer to hwdev
 * @param mod: mod type
 * @param cmd: cmd
 * @param cos_id: cos id
 * @param buf_in: message buffer in
 * @param buf_out: message buffer out
 * @param out_param: inline output data
 * @param timeout: timeout
 * @param channel: channel id
 *
 * @return Whether successful
 * 		@retval zero: success
 * 		@retval non-zero: failure
 */
int hinic5_cos_id_detail_resp(void *hwdev, u8 mod, u8 cmd, u8 cos_id,
			      struct hinic5_cmd_buf *buf_in,
			      struct hinic5_cmd_buf *buf_out,
			      u64 *out_param, u32 timeout, u16 channel);

/**
 * @brief hinic5_ppf_tmr_start - start ppf timer
 * @param hwdev: device pointer to hwdev
 *
 * @return Whether successful
 * 		@retval zero: success
 * 		@retval non-zero: failure
 */
int hinic5_ppf_tmr_start(void *hwdev);

/**
 * @brief hinic5_ppf_tmr_stop - stop ppf timer
 * @param hwdev: device pointer to hwdev
 *
 * @return Whether successful
 * 		@retval zero: success
 * 		@retval non-zero: failure
 */
int hinic5_ppf_tmr_stop(void *hwdev);

/**
 * @brief hinic5_func_tmr_bitmap_set - set timer bitmap status
 * @param hwdev: device pointer to hwdev
 * @param func_id: global function index
 * @param enable: 0-disable, 1-enable
 *
 * @return Whether successful
 * 		@retval zero: success
 * 		@retval non-zero: failure
 */
int hinic5_func_tmr_bitmap_set(void *hwdev, u16 func_id, bool en);

/**
 * @brief hinic5_func_vio_en - set current function VIO to enabled/disabled
 * @param hwdev: device pointer to hwdev
 * @param en: 0-disable, 1-enable
 *
 * @return Whether successful
 * 		@retval zero: success
 * 		@retval non-zero: failure
 */
int hinic5_func_vio_en(void *hwdev, bool en);

/**
 * @brief hinic5_get_board_info - get board info
 * @param hwdev: device pointer to hwdev
 * @param info: board info
 * @param channel: channel id
 *
 * @return Whether successful
 * 		@retval zero: success
 * 		@retval non-zero: failure
 */
int hinic5_get_board_info(void *hwdev, struct hinic5_board_info *info,
			  u16 channel);

/**
 * @brief hinic5_set_wq_page_size - set work queue page size
 * @param hwdev: device pointer to hwdev
 * @param func_idx: function id
 * @param page_size: page size
 * @param channel: channel id
 *
 * @return Whether successful
 * 		@retval zero: success
 * 		@retval non-zero: failure
 */
int hinic5_set_wq_page_size(void *hwdev, u16 func_idx, u32 page_size,
			    u16 channel);

/**
 * @brief hinic5_event_callback - evnet callback to notify service driver
 * @param hwdev: device pointer to hwdev
 * @param event: event info to service driver
 */
void hinic5_event_callback(void *hwdev, struct hinic5_event_info *event);

/**
 * @brief hinic5_dbg_lt_rd_16byte - liner table read
 * @param hwdev: device pointer to hwdev
 * @param dest: destine id
 * @param instance: instance id
 * @param lt_index: liner table index id
 * @param data: data
 */
int hinic5_dbg_lt_rd_16byte(void *hwdev, u8 dest, u8 instance,
			    u32 lt_index, u8 *data);

/**
 * @brief hinic5_dbg_lt_wr_16byte_mask - liner table write
 * @param hwdev: device pointer to hwdev
 * @param dest: destine id
 * @param instance: instance id
 * @param lt_index: liner table index id
 * @param data: data
 * @param mask: mask
 */
int hinic5_dbg_lt_wr_16byte_mask(void *hwdev, u8 dest, u8 instance,
				 u32 lt_index, u8 *data, u16 mask);

/**
 * @brief hinic5_link_event_stats - link event stats
 * @param hwdev: device pointer to hwdev
 * @param link: link status
 */
void hinic5_link_event_stats(void *dev, u8 link);

/**
 * @brief hinic5_get_link_down_cnt - link event stats
 * @param hwdev: device pointer to hwdev
 * @param link: link status
 */
int hinic5_get_link_down_cnt(void *dev, int *link_down_cnt);

/**
 * @brief hinic5_get_hw_pf_infos - get pf infos
 * @param hwdev: device pointer to hwdev
 * @param infos: pf infos
 * @param channel: channel id
 */
int hinic5_get_hw_pf_infos(void *hwdev, struct hinic5_hw_pf_infos *infos,
			   u16 channel);

/**
 * @brief hinic5_func_reset - reset func
 * @param hwdev: device pointer to hwdev
 * @param func_id: global function index
 * @param reset_flag: reset flag
 * @param channel: channel id
 */
int hinic5_func_reset(void *dev, u16 func_id, u64 reset_flag, u16 channel);

/**
 * @brief Get PPF (Physical Function) timer configuration
 * @param hwdev Hardware device context
 *
 * @return Whether successful
 * 		@retval zero: success
 * 		@retval non-zero: failure
 */
int hinic5_get_ppf_timer_cfg(void *hwdev);

/**
 * @brief Set PCI device BDF (Bus, Device, Function) information
 * @param hwdev Hardware device context
 * @param bus PCI bus number
 * @param device PCI device number
 * @param function PCI function number
 *
 * @return Whether successful
 * 		@retval zero: success
 * 		@retval non-zero: failure
 */
int hinic5_set_bdf_ctxt(void *hwdev, u8 bus, u8 device, u8 function);

/**
 * @brief Initialize function mailbox message channel
 * @param hwdev Hardware device
 * @param num_func Number of functions
 *
 * @return Whether successful
 * 		@retval zero: success
 * 		@retval non-zero: failure
 */
int hinic5_init_func_mbox_msg_channel(void *hwdev, u16 num_func);

/**
 * @brief Get SML table information
 * @param hwdev Hardware device info
 * @param tbl_id Table ID
 * @param node_id Node ID
 * @param instance_id Instance ID
 *
 * @return Whether successful
 * 		@retval zero: success
 * 		@retval non-zero: failure
 */
int hinic5_get_sml_table_info(void *hwdev, u32 tbl_id, u8 *node_id, u8 *instance_id);

/**
 * @brief Send mailbox message from PPF to host
 * @param hwdev Hardware device
 * @param mod Message module
 * @param cmd Message command
 * @param host_id Host ID
 * @param buf_in Input buffer
 * @param in_size Input buffer size
 * @param buf_out Output buffer
 * @param out_size Output buffer size
 * @param timeout Timeout
 * @param channel Channel
 *
 * @return Whether successful
 * 		@retval zero: success
 * 		@retval non-zero: failure
 */
int hinic5_mbox_ppf_to_host(void *hwdev, u8 mod, u16 cmd, u8 host_id,
			    void *buf_in, u16 in_size, void *buf_out,
			    u16 *out_size, u32 timeout, u16 channel);

/**
 * @brief Force complete all operations
 * @param dev Device pointer
 *
 * @return None
 */
void hinic5_force_complete_all(void *dev);
/**
 * @brief Get CEQ page physical address
 * @param hwdev Hardware device context
 * @param q_id Queue ID
 * @param page_idx Page index
 * @param page_phy_addr Page physical address
 *
 * @return Whether successful
 * 		@retval zero: success
 * 		@retval non-zero: failure
 */
int hinic5_get_ceq_page_phy_addr(void *hwdev, u16 q_id,
				 u16 page_idx, u64 *page_phy_addr);
				 /**
 * @brief Disable interrupt request
 * @param hwdev Hardware device
 * @param q_id Queue ID
 *
 * @return Whether successful
 * 		@retval zero: success
 * 		@retval non-zero: failure
 */
int hinic5_set_ceq_irq_disable(void *hwdev, u16 q_id);
/**
 * @brief Get CEQ information
 * @param hwdev Hardware device info
 * @param q_id Queue ID
 * @param ceq_info CEQ information
 *
 * @return Whether successful
 * 		@retval zero: success
 * 		@retval non-zero: failure
 */
int hinic5_get_ceq_info(void *hwdev, u16 q_id, struct hinic5_ceq_info *ceq_info);

/**
 * @brief hinic5_init_single_ceq_status
 * @param hwdev: device pointer to hwdev
 * @param q_id: ceq id
 */
int hinic5_init_single_ceq_status(void *hwdev, u16 q_id);

/**
 * @brief Set API stop
 * @param hwdev Hardware device pointer
 *
 * @return None
 */
void hinic5_set_api_stop(void *hwdev);

/**
 * @brief Activate firmware
 * @param hwdev Hardware device
 * @param cfg_index Configuration index
 *
 * @return Whether successful
 * 		@retval zero: success
 * 		@retval non-zero: failure
 */
int hinic5_activate_firmware(void *hwdev, u8 cfg_index);
/**
 * @brief  hinic5_switch_config function main purpose is to switch firmware version
 * @param  hwdev Device handle
 * @param  cfg_index Configuration index
 *
 * @return Whether successful
 * 		@retval zero: success
 * 		@retval non-zero: failure
 */
int hinic5_switch_config(void *hwdev, u8 cfg_index);

enum hinic5_hw_type {
	HINIC5_HW_TYPE_FPGA = 0,
	HINIC5_HW_TYPE_ASIC = 1,
	HINIC5_HW_TYPE_EMU = 2,
	HINIC5_HW_TYPE_EDA = 3,
	HINIC5_HW_TYPE_INVALID = 0xff,
};

/**
 * @brief Get device hardware type
 *
 * @param hwdev Device object pointer
 *
 * @details NA
 *
 * @attention: NA
 *
 * @return: Function return value description.
 *     @retval HINIC5_HW_TYPE_FPGA fpga type
 *     @retval HINIC5_HW_TYPE_ASIC asic type
 *     @retval HINIC5_HW_TYPE_EMU emu type
 *     @retval HINIC5_HW_TYPE_EDA eda type
 *     @retval HINIC5_HW_TYPE_INVALID invalid type
 */
u8 hinic5_get_hw_type(void *hwdev);

#endif
