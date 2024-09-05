/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2024. Huawei Technologies Co., Ltd. All rights reserved.
 */
#ifndef __VIRTCCA_CVM_HOST_H
#define __VIRTCCA_CVM_HOST_H

#ifdef CONFIG_HISI_VIRTCCA_HOST

bool is_virtcca_cvm_enable(void);

#else

static inline bool is_virtcca_cvm_enable(void)
{
	return false;
}

#endif /* CONFIG_HISI_VIRTCCA_GUEST */
#endif /* __VIRTCCA_CVM_GUEST_H */
