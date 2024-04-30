/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2024 Huawei Technologies Co., Ltd */

#ifndef ROCE_EVENT_EXTENSION_H
#define ROCE_EVENT_EXTENSION_H

#include "roce_event.h"

void roce3_event_report_extend(const struct roce3_device *rdev, int event_str_index);

int roce3_async_event_handle_extend(u8 event_type, u8 *val, struct roce3_device *rdev);

#endif /* ROCE_EVENT_EXTENSION_H */
