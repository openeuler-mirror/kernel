/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hinic5_lld.h
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   :
 */

#ifndef HINIC5_LLD_H
#define HINIC5_LLD_H

#include <linux/pci.h>
#include "hinic5_crm.h"

/**
 * @brief function device bus type
 * @details NA
 */
enum hinic5_dev_type {
	HINIC5_DEVICE_T_PCI,   /**< Device connected via pci bus */
	HINIC5_DEVICE_T_UB,    /**< Device connected via ub bus */
	HINIC5_DEVICE_T_MAX,   /**< Number of supported bus types */
};

#define HINIC5_CARD_ID_OFFSET  16
#define HINIC5_CARD_ID_MASK    0xffffffffffff
#define HINIC5_GUID_LEN (16)
/**
 * @brief guid
 * @details NA
 */
struct hinic5_guid {
	u8 id[HINIC5_GUID_LEN];
};

/**
 * @brief Device information for each function
 * @details NA
 */
struct hinic5_device_info {
	u64 id;                        /* DPU unique identifier */

	struct hinic5_guid guid;
};

/**
 * @brief struct hinic5_lld_dev - Device object exposed to uld
 * @details Device object used by uld, contains device type and hardware device pointer
 */
struct hinic5_lld_dev {
	void *hwdev;                      /**< Hardware device pointer inside sdk driver */
	struct device *dev;               /**< Associated struct device */
	enum hinic5_dev_type dev_type;    /**< device bus type */
};

/**
 * @brief struct hinic5_uld_info
 * @details Defines a structure for storing user-level driver (uld) information
 */
struct hinic5_uld_info {
	/* When the function does not need to initialize the corresponding uld,
	 * @probe needs to return 0 and uld_dev is set to NULL;
	 * if uld_dev is NULL, @remove will not be called when uninstalling
	 */
	int (*probe)(struct hinic5_lld_dev *lld_dev, void **uld_dev, char *uld_dev_name);	/**< Initialize user-level driver function */
	void (*remove)(struct hinic5_lld_dev *lld_dev, void *uld_dev);	/**< Remove user-level driver function */
	int (*suspend)(struct hinic5_lld_dev *lld_dev, void *uld_dev, pm_message_t state);	/**< Suspend user-level driver function */
	int (*resume)(struct hinic5_lld_dev *lld_dev, void *uld_dev);	/**< Resume user-level driver function */
	void (*event)(struct hinic5_lld_dev *lld_dev, void *uld_dev,	/**< Event handling function */
		      struct hinic5_event_info *event);
	int (*ioctl)(void *uld_dev, u32 cmd, const void *buf_in, u32 in_size,		/**< Execute ioctl operation function */
		     void *buf_out, u32 *out_size);
};

/**
 * @brief hinic5_get_card_nic_uld_array - get nic uld array
 * @param lld_dev: device pointer to pcie
 * @param dev_cnt: uld cnt
 * @param array: uld array
 *
 * @return
 *      @retval zero: success
 *      @retval non-zero: failure
 */

int hinic5_get_card_nic_uld_array(struct hinic5_lld_dev *lld_dev, u32 *dev_cnt, void *array[]);

/**
 * @brief Register user-level driver
 * @param type Service type
 * @param uld_info User-level driver information
 *
 * @details This function is used to register user-level driver based on the provided service type and user-level driver information
 *
 * @return
 *      @retval zero: success
 *      @retval non-zero: failure
 */
int hinic5_register_uld(enum hinic5_service_type type, struct hinic5_uld_info *uld_info);

/**
 * @brief Unregister user-defined upper driver module
 * @param type Service type enumeration
 *
 * @details This function is used to unregister user-defined upper driver module
 *
 * @return None
 */
void hinic5_unregister_uld(enum hinic5_service_type type);

/**
 * @brief Wait for LLD device node change to complete
 *
 * @details Before calling this function, ensure no device node is being changed
 *
 * @return None
 */
void hinic5_lld_hold(void);
/**
 * @brief This function is used to release the global lock
 *
 * @details Decrements device reference count through atomic operation. If reference count is 0, it means no device is using the lock and can be released
 *
 * @return None
 */
void hinic5_lld_put(void);

/**
 * @brief hinic5_get_lld_dev_by_chip_name - get lld device by chip name
 * @param chip_name: chip name
 *
 * @details The value of lld_dev reference increases when lld_dev is obtained. The caller needs
 * 	    to release the reference by calling hinic5_lld_dev_put.
 *
 * @return lld device
 */
struct hinic5_lld_dev *hinic5_get_lld_dev_by_chip_name(const char *chip_name);

/**
 * @brief hinic5_lld_dev_hold - get reference to lld_dev
 * @param dev: lld device
 *
 * @details Hold reference to device to keep it from being freed
 */
void hinic5_lld_dev_hold(struct hinic5_lld_dev *dev);

/**
 * @brief hinic5_lld_dev_put - release reference to lld_dev
 * @param dev: lld device
 *
 * @details Release reference to device to allow it to be freed
 */
void hinic5_lld_dev_put(struct hinic5_lld_dev *dev);

/**
 * @brief hinic5_get_lld_dev_by_dev_name - get lld device by uld device name
 * @param dev_name: uld device name
 * @param type: uld service type, When the type is SERVICE_T_MAX, try to match all ULD names to get uld_dev
 *
 * @details The value of lld_dev reference increases when lld_dev is obtained. The caller needs
 * 	    to release the reference by calling hinic5_lld_dev_put.
 *
 * @return Returns LLD device on success, otherwise returns NULL
 */
struct hinic5_lld_dev *hinic5_get_lld_dev_by_dev_name(const char *dev_name,
						      enum hinic5_service_type type);

/**
 * @brief hinic5_get_lld_dev_by_dev_name_unsafe - get lld device by uld device name
 * @param dev_name: uld device name
 * @param type: uld service type, When the type is SERVICE_T_MAX, try to match all ULD names to get uld_dev
 *
 * @details hinic5_get_lld_dev_by_dev_name_unsafe() is completely analogous to
 * 			hinic5_get_lld_dev_by_dev_name(), The only difference is that the reference
 * 			of lld_dev is not increased when lld_dev is obtained.
 *			The caller must ensure that lld_dev will not be freed during the remove process
 * 			when using lld_dev.
 *
 * @return Returns LLD device on success, otherwise returns NULL
 */
struct hinic5_lld_dev *hinic5_get_lld_dev_by_dev_name_unsafe(const char *dev_name,
							     enum hinic5_service_type type);

/**
 * @brief hinic5_get_lld_dev_by_chip_and_port - get lld device by chip name and port id
 * @param chip_name: chip name
 * @param port_id: port id
 *
 * @return Returns LLD device on success, otherwise returns NULL
 */
struct hinic5_lld_dev *hinic5_get_lld_dev_by_chip_and_port(const char *chip_name, u8 port_id);

/**
 * @brief hinic5_get_lld_dev_with_l3i_enabled - get lld device which enables BAT L3I
 * @param chip_name: chip name
 *
 * @return Returns LLD device on success, otherwise returns NULL
 */
struct hinic5_lld_dev *hinic5_get_lld_dev_with_l3i_enabled(const char *chip_name);

/**
 * @brief hinic5_get_ppf_lld_dev - get ppf lld device by current function's lld device
 * @param lld_dev: current function's lld device
 *
 * @details The value of lld_dev reference increases when lld_dev is obtained. The caller needs
 * 			to release the reference by calling hinic5_lld_dev_put.
 *
 * @return Returns LLD device on success, otherwise returns NULL
 */
struct hinic5_lld_dev *hinic5_get_ppf_lld_dev(struct hinic5_lld_dev *lld_dev);

/**
 * @brief hinic5_get_ppf_lld_dev_unsafe - get ppf lld device by current function's lld device
 * @param lld_dev: current function's lld device
 *
 * @details hinic5_get_ppf_lld_dev_unsafe() is completely analogous to hinic5_get_ppf_lld_dev(),
 * 			The only difference is that the reference of lld_dev is not increased when lld_dev is obtained.
 *			The caller must ensure that ppf's lld_dev will not be freed during the remove process
 * 			when using ppf lld_dev.
 *
 * @return Returns LLD device on success, otherwise returns NULL
 */
struct hinic5_lld_dev *hinic5_get_ppf_lld_dev_unsafe(struct hinic5_lld_dev *lld_dev);

/**
 * @brief hinic5_get_ppf_hw_dev_unsafe - get any ppf hw device in current host by current function's hw device
 * @param hwdev: current function's hw device
 *
 * @details The caller must ensure that ppf's hw_dev will not be freed during the remove process
 * 			when using ppf hw_dev.
 */
void *hinic5_get_ppf_hw_dev_unsafe(void *hwdev);

/**
 * @brief hinic5_uld_dev_hold - get reference to uld_dev
 * @param lld_dev: lld device
 * @param type: uld service type
 *
 * @details Hold reference to uld device to keep it from being freed
 */
void hinic5_uld_dev_hold(struct hinic5_lld_dev *lld_dev, enum hinic5_service_type type);

/**
 * @brief hinic5_uld_dev_put - release reference to lld_dev
 * @param dev: lld device
 * @param type: uld service type
 *
 * @details Release reference to uld device to allow it to be freed
 */
void hinic5_uld_dev_put(struct hinic5_lld_dev *lld_dev, enum hinic5_service_type type);

/**
 * @brief hinic5_get_uld_dev - get uld device by lld device
 * @param lld_dev: lld device
 * @param type: uld service type
 *
 * @details The value of uld_dev reference increases when uld_dev is obtained. The caller needs
 * 			to release the reference by calling hinic5_uld_dev_put.
 */
void *hinic5_get_uld_dev(struct hinic5_lld_dev *lld_dev, enum hinic5_service_type type);

/**
 * @brief hinic5_get_uld_dev_unsafe - get uld device by lld device
 * @param lld_dev: lld device
 * @param type: uld service type
 *
 * @details hinic5_get_uld_dev_unsafe() is completely analogous to hinic5_get_uld_dev(),
 * 			The only difference is that the reference of uld_dev is not increased when uld_dev is obtained.
 *			The caller must ensure that uld_dev will not be freed during the remove process when using uld_dev.
 */
void *hinic5_get_uld_dev_unsafe(struct hinic5_lld_dev *lld_dev, enum hinic5_service_type type);

/**
 * @brief hinic5_get_chip_name - get chip name by lld device
 * @param lld_dev: lld device
 * @param chip_name: String for storing the chip name
 * @param max_len: Maximum number of characters to be copied for chip_name
 *
 * @return 0 on success, other values on failure
 */
int hinic5_get_chip_name(struct hinic5_lld_dev *lld_dev, char *chip_name, u16 max_len);

/**
 * @brief Get SDK hardware device
 * @param lld_dev Low-level driver device
 *
 * @return Returns SDK hardware device
 */
void *hinic5_get_sdk_hwdev_by_lld(struct hinic5_lld_dev *lld_dev);

/**
 * @brief Set VF service enable switch, only PF calls
 * @param lld_dev Device structure pointer
 * @param service Service type
 * @param vf_srv_load Whether to enable virtual function service load
 *
 * @return Returns 0 on success, otherwise returns error code
 */
int hinic5_set_vf_service_load(struct hinic5_lld_dev *lld_dev, u16 service,
			       bool vf_srv_load);

/**
 * @brief Set VF load enable flag for this service
 * @param lld_dev Physical device
 * @param vf_func_id Virtual function ID
 * @param service Service type
 * @param en Whether to enable
 *
 * @return Returns 0 on success, otherwise returns error code
 */
int hinic5_set_vf_service_state(struct hinic5_lld_dev *lld_dev, u16 vf_func_id,
				u16 service, bool en);

/**
 * @brief Set VF load enable flag
 * @param lld_dev Device structure pointer
 * @param vf_load_state Virtual function load state
 *
 * @return Returns 0 on success, otherwise returns error code
 */
int hinic5_set_vf_load_state(struct hinic5_lld_dev *lld_dev, bool vf_load_state);

/**
 * @brief Attach NIC device
 * @param lld_dev Low-level device structure pointer
 *
 * @return Returns 0 on success, otherwise returns error code
 */
int hinic5_attach_nic(struct hinic5_lld_dev *lld_dev);

/**
 * @brief  Detach NIC
 * @param  lld_dev Device low-level driver information
 *
 * @return None
 */
void hinic5_detach_nic(const struct hinic5_lld_dev *lld_dev);

/**
 * @brief  Attach specified service type to device
 * @param  lld_dev Device low-level driver information
 * @param  type Service type
 *
 * @return Returns 0 on success, otherwise returns error code
 */
int hinic5_attach_service(const struct hinic5_lld_dev *lld_dev, enum hinic5_service_type type);
/**
 * @brief  hinic5_detach_service function is used to detach service
 * @param  lld_dev Device low-level driver information
 * @param  type Service type
 *
 * @return None
 */
void hinic5_detach_service(const struct hinic5_lld_dev *lld_dev, enum hinic5_service_type type);

/**
 * @brief Called before unregistering uld, executes cleanup callback
 *
 * @param type ULD service type
 * @param cleanup Callback
 *
 * @details All functions with ULD loaded, call cleanup callback in order
 *
 * @attention: NA
 *
 * @return: NA
 */
void hinic5_uld_cleanup_before_unregister(enum hinic5_service_type type, void (*cleanup)(void *));

/**
 * @brief  hinic5_get_vf_num function is used to get the number of enabled VFs for pci/ub device
 * @param  lld_dev Device low-level driver information
 *
 * @return Number of enabled VFs
 */
int hinic5_get_vf_num(struct hinic5_lld_dev *lld_dev);

/**
 * @brief  hinic5_get_chip_node_id function is used to get the chip_node id to which pci/ub device belongs
 * @param  lld_dev Device low-level driver information
 *
 * @return chip_node id
 */
int hinic5_get_chip_node_id(struct hinic5_lld_dev *lld_dev, u64 *chip_node_id);

/**
 * @brief Get device information
 *
 * @param[in] lld_dev Device
 * @param[out] info Return device information
 *
 * @details NULL
 *
 * @attention: NULL
 *
 * @return: Describes function return value.
 *     @retval 0 Success
 *     @retval non-zero Error code
 */
int hinic5_get_device_info(struct hinic5_lld_dev *lld_dev, struct hinic5_device_info *info);
int hinic5_lld_init(void);
void hinic5_lld_exit(void);

#endif
