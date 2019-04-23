/* SPDX-License-Identifier: GPL-2.0+ */
/* Copyright (c) 2016-2017 Hisilicon Limited. */

#ifndef __HCLGE_TEST_H
#define __HCLGE_TEST_H

#include "../../hns3pf/hclge_cmd.h"
#include "../../hns3pf/hclge_main.h"

int hclge_send_cmdq(struct hnae3_handle *handle, void *data, int num);

#endif
