/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (c) 2026 HiSilicon Technologies Co., Ltd. All rights reserved.
 */

#ifndef __UBASEPROXY_EVENT_H__
#define __UBASEPROXY_EVENT_H__

#include "ubaseproxy_dev.h"

int ubaseproxy_register_event(struct ubaseproxy_dev *udev);
void ubaseproxy_unregister_event(struct ubaseproxy_dev *udev);

#endif /* __UBASEPROXY_EVENT_H__ */
