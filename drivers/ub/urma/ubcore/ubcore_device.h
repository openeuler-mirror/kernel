/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2025. All rights reserved.
 *
 * Description: ubcore device head file
 * Author: Yan Fangfang
 * Create: 2024-02-05
 * Note:
 * History: 2024-02-05: Create file
 */

#ifndef UBCORE_DEVICE_H
#define UBCORE_DEVICE_H

#include "ubcore_priv.h"

#define UBCORE_DEVNODE_MODE (0666)
#define UBAGG_DEV_PREFIX "bonding_dev"

int ubcore_register_pnet_ops(void);
void ubcore_unregister_pnet_ops(void);
int ubcore_class_register(void);
void ubcore_class_unregister(void);
int ubcore_cdev_register(void);
int ubcore_cdev_unregister(void);
int ubcore_set_ns_mode(bool shared);
int ubcore_set_dev_ns(char *device_name, uint32_t ns_fd);
int ubcore_expose_dev_ns(char *device_name, uint32_t ns_fd);
int ubcore_unexpose_dev_ns(char *device_name, uint32_t ns_fd);
int ubcore_set_dev_eid_ns(char *device_name, uint32_t eid_index, uint32_t ns_fd);
bool ubcore_dev_accessible(struct ubcore_device *dev, struct net *net);
int ubcore_get_max_mtu(struct ubcore_device *dev, enum ubcore_mtu *mtu);
struct ubcore_nlmsg *ubcore_new_mue_dev_msg(struct ubcore_device *dev);
/* Only valid for user space */
bool ubcore_eid_accessible(struct ubcore_device *dev, uint32_t eid_index);
/* Valid for both user space and kerner space */
bool ubcore_eid_valid(struct ubcore_device *dev, uint32_t eid_index,
		      struct ubcore_udata *udata);
int ubcore_config_rsvd_jetty(struct ubcore_device *dev, uint32_t min_jetty_id,
			     uint32_t max_jetty_id);

int ubcore_process_mue_update_eid_tbl_notify_msg(struct ubcore_device *dev,
						 struct ubcore_resp *resp);
void ubcore_clear_pattern1_eid(struct ubcore_device *dev,
			       union ubcore_eid *eid);
void ubcore_clear_pattern3_eid(struct ubcore_device *dev,
			       union ubcore_eid *eid);

static inline bool ubcore_check_ctrlplane(struct ubcore_device *dev)
{
	return dev && dev->ops && dev->ops->get_tp_list;
}

static inline bool ubcore_is_bonding_dev(struct ubcore_device *dev)
{
	return memcmp(dev->dev_name, UBAGG_DEV_PREFIX,
		      strlen(UBAGG_DEV_PREFIX)) == 0;
}

#endif // UBCORE_DEVICE_H
