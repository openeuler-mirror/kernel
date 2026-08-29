/* SPDX-License-Identifier: GPL-2.0+ */
/* Copyright(c) 2026 HiSilicon Technologies CO., Ltd. All rights reserved. */

#ifndef __UDMA_JETTY_GROUP_H__
#define __UDMA_JETTY_GROUP_H__

#include "udma_common.h"

static inline struct udma_jetty_grp *to_udma_jetty_grp(struct ubcore_jetty_group *jetty_grp)
{
	return container_of(jetty_grp, struct udma_jetty_grp, ubcore_jetty_grp);
}

int add_jetty_to_grp(struct udma_dev *udma_dev, struct ubcore_jetty_group *jetty_grp,
			    struct udma_jetty_queue *sq, uint32_t cfg_id);
void remove_jetty_from_grp(struct udma_dev *udma_dev, struct udma_jetty *jetty);
int udma_check_jetty_grp_info(struct ubcore_tjetty_cfg *cfg, struct udma_dev *dev);
struct ubcore_jetty_group *udma_create_jetty_grp(struct ubcore_device *dev,
						 struct ubcore_jetty_grp_cfg *cfg,
						 struct ubcore_udata *udata);
int udma_delete_jetty_grp(struct ubcore_jetty_group *jetty_grp);
int udma_update_hw_grp_ctx_valid_only(struct udma_dev *udma_dev, struct udma_jetty *jetty,
				      bool is_add);
#endif /* __UDMA_JETTY_GROUP_H__ */
