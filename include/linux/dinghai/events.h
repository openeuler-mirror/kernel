/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#ifndef __ZXDH_EVENTS_H__
#define __ZXDH_EVENTS_H__

#include <linux/dinghai/eq.h>
#include <linux/dinghai/driver.h>
#include <linux/notifier.h>

struct dh_event_nb {
	struct dh_nb nb;
	void *ctx;
};

struct dh_events {
	struct dh_core_dev *dev;
	struct workqueue_struct *wq;
	int32_t evt_num;
	struct dh_event_nb notifiers[];
};

void zxdh_events_work_enqueue(struct dh_core_dev *dev, struct work_struct *work);
void zxdh_events_cleanup(struct dh_core_dev *dev);

#define dh_nb_cof(ptr, type, member) \
	(container_of(container_of(ptr, struct dh_nb, nb), type, member))

#endif
