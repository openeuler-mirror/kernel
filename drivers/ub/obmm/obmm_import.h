/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2026. All rights reserved.
 */
#ifndef OBMM_IMPORT_H
#define OBMM_IMPORT_H

#include "obmm_core.h"

int obmm_import(struct obmm_cmd_import *cmd_import);
int obmm_unimport(const struct obmm_cmd_unimport *cmd_unimport);

#endif
