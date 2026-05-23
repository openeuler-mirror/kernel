/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hinic5_hwif_inner.h
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   :
 */

#ifndef HINIC5_HWIF_INNER_H
#define HINIC5_HWIF_INNER_H

#include "hinic5_hwdev.h"

#define HINIC5_BUS_LINK_DOWN		0xFFFFFFFF
#define MAKE_64BITS(hi, lo) ((((u64)(hi)) << 32) | ((u64)((u32)(lo))))

struct hinic5_free_db_area {
	unsigned long		*db_bitmap_array;
	u32			db_max_areas;
	/* spinlock for allocating doorbell area */
	spinlock_t		idx_lock;
};

struct hinic5_func_attr {
	u16			func_global_idx;
	u8			port_to_port_idx;
	u8			pci_intf_idx;
	u8			vf_in_pf;
	u8			rsvd1;
	u16			rsvd2;
	enum func_type		func_type;

	u8			mpf_idx;

	u8			ppf_idx;

	u16			num_irqs; /* max: 2 ^ 15 */
	u8			num_aeqs; /* max: 2 ^ 3 */
	u8			num_ceqs; /* max: 2 ^ 7 */

	u16			num_sq; /* max: 2 ^ 8 */
	u8			num_dma_attr; /* max: 2 ^ 6 */
	u8			msix_flex_en;

	u16			global_vf_id_of_pf;
	u8			hw_type;
};

struct hinic5_hwif {
	u8 __iomem *fers2_reg_base;
	u8 __iomem *cfg_regs_base;
	u8 __iomem *intr_regs_base;
	u8 __iomem *mgmt_regs_base; /* only for PPF/PF */
	u64 db_base_phy;
	u64 db_dwqe_len;
	u8 __iomem *db_base;

	struct hinic5_free_db_area free_db_area;

	struct hinic5_func_attr attr;

#ifdef __UEFI__
	void *bus_dev; /* In pcie scenario it represents pdev, in ub scenario it represents ub dev */
#endif
	void *hwdev;

	u64 rsvd;
};

enum outbound_flush_state {
	OUTBOUND_FLUSH_DISABLED = 0,
	OUTBOUND_FLUSH_ENABLED = 1,
};

enum doorbell_flush_state {
	DOORBELL_FLUSH_DISABLED = 0,
	DOORBELL_FLUSH_ENABLED = 1,
};

enum hinic5_wait_return check_outbound_enable_handler(struct hinic5_hwdev *hwdev);

enum hinic5_pf_status {
	HINIC5_PF_STATUS_INIT = 0X0,
	HINIC5_PF_STATUS_ACTIVE_FLAG = 0x11,
	HINIC5_PF_STATUS_FLR_START_FLAG = 0x12,
	HINIC5_PF_STATUS_FLR_FINISH_FLAG = 0x13,
};

#define HINIC5_HWIF_NUM_AEQS(hwif)		((hwif)->attr.num_aeqs)
#define HINIC5_HWIF_NUM_CEQS(hwif)		((hwif)->attr.num_ceqs)
#define HINIC5_HWIF_NUM_IRQS(hwif)		((hwif)->attr.num_irqs)
#define HINIC5_HWIF_GLOBAL_IDX(hwif)		((hwif)->attr.func_global_idx)
#define HINIC5_HWIF_GLOBAL_VF_OFFSET(hwif) ((hwif)->attr.global_vf_id_of_pf)
#define HINIC5_HWIF_PPF_IDX(hwif)		((hwif)->attr.ppf_idx)
#define HINIC5_PCI_INTF_IDX(hwif)		((hwif)->attr.pci_intf_idx)

#define HINIC5_FUNC_TYPE(dev)		((dev)->hwif->attr.func_type)
#define HINIC5_IS_PF(dev)		(HINIC5_FUNC_TYPE(dev) == TYPE_PF)
#define HINIC5_IS_VF(dev)		(HINIC5_FUNC_TYPE(dev) == TYPE_VF)
#define HINIC5_IS_PPF(dev)		(HINIC5_FUNC_TYPE(dev) == TYPE_PPF)

struct hinic5_health_status {
	u32 rsvd : 7;
	u32 fw_img_load_fail : 1;
	u32 smu_lastword : 1;
	u32 npu_lastword : 1;
	u32 mpu_wdog : 1;
	u32 mpu_lastword : 1;
	u32 wr_phy_timeout : 1;
	u32 wr_mem_timeout : 1;
	u32 wr_reg_timeout : 1;
	u32 sfp_high_temperature_port : 4;
	u32 chip_low_temperature : 1;
	u32 chip_high_temperature : 1;
	u32 logic_except : 1;
	u32 host_heart : 5;
	u32 mpu_init_done : 2;
	u32 mpu_boot_cause : 3;
};

struct hinic5_chip_base {
	u32 chip_type : 2;
	u32 chip_ver : 2;
	u32 spu_en : 1;
	u32 host_num : 3;
	u32 cfg_template_id : 4;
	u32 board_type : 8;
	u32 board_id : 4;
	u32 mpu_ver : 8;
};

struct hinic5_chip_info {
	union {
		struct hinic5_health_status health_status;
		struct hinic5_chip_base chip_base;
		u32 value;
	};
};

struct hinic5_logic_except {
	u32 err_type  : 16;
	u32 err_level : 8;
	u32 mode_id   : 8;
};

struct hinic5_temperature_alarm {
	u32 cur_temperature : 16;
	u32 limit_temperature : 16;
};

struct hinic5_mpu_exception {
	u32 abnormal_thread_id : 16;
	u32 abnormal_reason : 16;
};

struct hinic5_sfp_high_temperature_port {
	u32 front_actual_temperature : 8;
	u32 front_alarm_threshold_temperature : 8;
	u32 after_actual_temperature : 8;
	u32 after_alarm_threshold_temperature : 8;
};

struct hinic5_eco0_info {
	u32 stfqu_uncrt_err : 1;
	u32 pqm_uncrt_err : 1;
	u32 mqm_uncrt_err : 1;
	u32 stlqu_uncrt_err : 1;
	u32 smf_uncrt_err : 4;
	u32 sml_uncrt_err : 4;
	u32 stftile_uncrt_err : 4;
	u32 stltile_uncrt_err : 4;
	u32 mpu_uncrt_err : 1;
	u32 cpi_uncrt_err : 1;
	u32 lcam_uncrt_err : 1;
	u32 ipsutx_uncrt_err : 1;
	u32 perx_uncrt_err : 1;
	u32 ipsurx_uncrt_err : 1;
	u32 petx_uncrt_err : 1;
	u32 cpb_uncrt_err : 1;
	u32 ckd_err_int : 2;
	u32 pcie_uncrt_err : 1;
	u32 cryptorx_uncrt_err : 1;
};

struct hinic5_eco1_info {
	u32 cryptotx_uncrt_err : 1;
	u32 ts_uncrt_err : 1;
	u32 mag_uncrt_err : 1;
	u32 fc_uncrt_err : 1;
	u32 hva_uncrt_err : 1;
	u32 reserved : 27;
};

struct hinic5_eco2_info {
	union {
		struct hinic5_logic_except logic_except;
		struct hinic5_temperature_alarm temperature_alarm;
		struct hinic5_mpu_exception mpu_exception;
		u32 value;
		u16 short_value;
	};
};

struct hinic5_eco3_info {
	union {
		struct hinic5_sfp_high_temperature_port sfp_high_temperature_port;
		u32 value;
	};
};

struct hinic5_eco4_info {
	union {
		struct hinic5_sfp_high_temperature_port sfp_high_temperature_port;
		u32 value;
	};
};

u32 hinic5_hwif_read_reg(struct hinic5_hwif *hwif, u32 reg);

void hinic5_hwif_write_reg(struct hinic5_hwif *hwif, u32 reg, u32 val);

void hinic5_set_pf_status(struct hinic5_hwif *hwif,
			  enum hinic5_pf_status status);

enum hinic5_pf_status hinic5_get_pf_status(struct hinic5_hwif *hwif);

void hinic5_disable_doorbell(struct hinic5_hwif *hwif);

void hinic5_enable_doorbell(struct hinic5_hwif *hwif);

int hinic5_init_hwif(struct hinic5_hwdev *hwdev, void *fers2_reg_base, void *cfg_reg_base,
		     void *intr_reg_base, void *mgmt_regs_base, u64 db_base_phy,
		     void *db_base, u64 db_dwqe_len);

void hinic5_free_hwif(struct hinic5_hwdev *hwdev);

void hinic5_show_chip_err_info(struct hinic5_hwdev *hwdev);

u8 hinic5_host_ppf_idx(struct hinic5_hwdev *hwdev, u8 host_id);

bool hinic5_get_card_present_state(struct hinic5_hwdev *hwdev);

bool get_handshake_state(struct hinic5_hwdev *hwdev);

int hinic5_n_ptp_ts_up_en(struct hinic5_hwdev *hwdev, u32 flags);

int hinic5_read_n_ptp_ts_data(struct hinic5_hwdev *hwdev, u64 *time_ns);

/**
 * @brief enum hinic5_aeq_type - AEQ event types generated by CPI hardware
 * @details aeqe.sw attribute is 0 (aeqe generated by cpi hardware) supported event types
 */
enum hinic5_aeq_type {
	HINIC5_HW_INTER_INT = 0,		/**< Hardware interrupt event */
	HINIC5_MBX_FROM_FUNC = 1,		/**< Mailbox from function */
	HINIC5_MSG_FROM_MGMT_CPU = 2,	/**< Mailbox from MPU */
	HINIC5_API_RSP = 3,				/**< API response data */
	HINIC5_API_CHAIN_STS = 4,		/**< API chain status data */
	HINIC5_MBX_SEND_RSLT = 5,		/**< mailbox sending result */
	HINIC5_MAX_AEQ_EVENTS			/**< Number of supported event types */
};

/**
 * @brief enum hinic5_aeq_sw_type - AEQ event types generated by microcode (Tile)
 * @details aeqe.sw attribute is 1 (aeqe generated by microcode) supported event types
 */
enum hinic5_aeq_sw_type {
	HINIC5_STATELESS_EVENT = 0,		/**< Stateless event */
	HINIC5_STATEFUL_EVENT = 1,		/**< Stateful event */
	HINIC5_MAX_AEQ_SW_EVENTS		/**< Number of supported event types */
};

/**
 * @brief Define a function pointer type for handling AEQ interrupt
 * @param pri_handle Device handle
 * @param data Interrupt data
 * @param size Interrupt data size
 *
 * @return None
 */
typedef void (*hinic5_aeq_hwe_cb)(void *pri_handle, u8 *data, u8 size);

/**
 * @brief hinic5_aeq_register_hw_cb -  register aeq hardware callback
 * @param hwdev: device pointer to hwdev
 * @param event: event type
 * @param hwe_cb: callback function
 *
 * @return
 *		@retval zero: success
 *		@retval non-zero: failure
 */
int hinic5_aeq_register_hw_cb(void *hwdev, void *pri_handle,
			      enum hinic5_aeq_type event, hinic5_aeq_hwe_cb hwe_cb);

/**
 * @brief hinic5_aeq_unregister_hw_cb - unregister aeq hardware callback
 *
 * @return
 *		@param hwdev: device pointer to hwdev
 *		@param event: event type
 */
void hinic5_aeq_unregister_hw_cb(void *hwdev, enum hinic5_aeq_type event);

/**
 * @brief hinic5_aeq_register_swe_cb -  register aeq soft event callback
 * @param hwdev: device pointer to hwdev
 * @pri_handle: the pointer to private invoker device
 * @param event: event type
 * @param aeq_swe_cb: callback function
 *
 * @return
 *		@retval zero: success
 *		@retval non-zero: failure
 */
int hinic5_aeq_register_swe_cb(void *hwdev, void *pri_handle, enum hinic5_aeq_sw_type event,
			       hinic5_aeq_swe_cb aeq_swe_cb);

/**
 * @brief hinic5_aeq_unregister_swe_cb - unregister aeq soft event callback
 * @param hwdev: device pointer to hwdev
 * @param event: event type
 **/
void hinic5_aeq_unregister_swe_cb(void *hwdev, enum hinic5_aeq_sw_type event);

#endif
