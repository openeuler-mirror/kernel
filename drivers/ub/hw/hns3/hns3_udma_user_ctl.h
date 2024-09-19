/* SPDX-License-Identifier: GPL-2.0 */
/* Huawei HNS3_UDMA Linux driver
 * Copyright (c) 2023-2023 Hisilicon Limited.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
 * for more details.
 *
 */

#ifndef _HNS3_UDMA_USER_CTL_H
#define _HNS3_UDMA_USER_CTL_H

int hns3_udma_user_ctl(struct ubcore_device *dev, struct ubcore_user_ctl *k_user_ctl);
int hns3_udma_user_ctl_config_poe(struct ubcore_ucontext *uctx,
				  struct ubcore_user_ctl_in *in,
				  struct ubcore_user_ctl_out *out,
				  struct ubcore_udrv_priv *udrv_data);
int hns3_udma_user_ctl_query_poe(struct ubcore_ucontext *uctx, struct ubcore_user_ctl_in *in,
				  struct ubcore_user_ctl_out *out,
				  struct ubcore_udrv_priv *udrv_data);
int hns3_udma_user_ctl_dca_shrink(struct ubcore_ucontext *uctx, struct ubcore_user_ctl_in *in,
				  struct ubcore_user_ctl_out *out,
				  struct ubcore_udrv_priv *udrv_data);
int hns3_udma_user_ctl_dca_attach(struct ubcore_ucontext *uctx, struct ubcore_user_ctl_in *in,
				  struct ubcore_user_ctl_out *out,
				  struct ubcore_udrv_priv  *udrv_data);
int hns3_udma_user_ctl_dca_detach(struct ubcore_ucontext *uctx, struct ubcore_user_ctl_in *in,
				  struct ubcore_user_ctl_out *out,
				  struct ubcore_udrv_priv *udrv_data);
int hns3_udma_user_ctl_dca_query(struct ubcore_ucontext *uctx, struct ubcore_user_ctl_in *in,
				 struct ubcore_user_ctl_out *out,
				 struct ubcore_udrv_priv *udrv_data);
int hns3_udma_user_ctl_flush_cqe(struct ubcore_ucontext *uctx, struct ubcore_user_ctl_in *in,
				 struct ubcore_user_ctl_out *out,
				 struct ubcore_udrv_priv *udrv_data);
int hns3_udma_user_ctl_dca_reg(struct ubcore_ucontext *uctx, struct ubcore_user_ctl_in *in,
			       struct ubcore_user_ctl_out *out,
			       struct ubcore_udrv_priv *udrv_data);
int hns3_udma_user_ctl_dca_dereg(struct ubcore_ucontext *uctx, struct ubcore_user_ctl_in *in,
				 struct ubcore_user_ctl_out *out,
				 struct ubcore_udrv_priv *udrv_data);
#endif /* _HNS3_UDMA_USER_CTL_H */
