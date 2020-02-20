/* SPDX-License-Identifier: GPL-2.0+ */
/* Copyright (c) 2016-2017 Hisilicon Limited. */

#ifndef __HCLGE_MAIN_IT_H
#define __HCLGE_MAIN_IT_H

extern struct hnae3_ae_algo ae_algo;
extern struct hnae3_ae_ops hclge_ops;

enum hnae3_event_type_custom {
	HNAE3_VF_RESET_CUSTOM,
	HNAE3_VF_FUNC_RESET_CUSTOM,
	HNAE3_VF_PF_FUNC_RESET_CUSTOM,
	HNAE3_VF_FULL_RESET_CUSTOM,
	HNAE3_FLR_RESET_CUSTOM,
	HNAE3_FUNC_RESET_CUSTOM,
	HNAE3_GLOBAL_RESET_CUSTOM,
	HNAE3_IMP_RESET_CUSTOM,
	HNAE3_UNKNOWN_RESET_CUSTOM,
	HNAE3_NONE_RESET_CUSTOM,
	HNAE3_PORT_FAULT,
	HNAE3_RESET_DONE_CUSTOM,
	HNAE3_FUNC_RESET_FAIL_CUSTOM,
	HNAE3_GLOBAL_RESET_FAIL_CUSTOM,
	HNAE3_IMP_RESET_FAIL_CUSTOM,
	HNAE3_PPU_POISON_CUSTOM,
	HNAE3_IMP_RD_POISON_CUSTOM,
};

/**
 * nic_event_fn_t - nic event handler prototype
 * @netdev:	net device
 * @hnae3_event_type_custom:	nic device event type
 */
typedef void (*nic_event_fn_t) (struct net_device *netdev,
				enum hnae3_event_type_custom);

/**
 * nic_register_event - register for nic event listening
 * @event_call:	nic event handler
 * return 0 - success , negative - fail
 */
int nic_register_event(nic_event_fn_t event_call);

/**
 * nic_unregister_event - quit nic event listening
 * return 0 - success , negative - fail
 */
int nic_unregister_event(void);

int hclge_init(void);
#endif
