/* SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB) */
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#ifndef _PUB_RETURN_H_
#define _PUB_RETURN_H_
#include "pub_print.h"

#ifdef PUB_ERROR
#undef PUB_ERROR
#define PUB_ERROR (0xffffffff)
#else
#define PUB_ERROR (0xffffffff) /*0xffffffff*/
#endif

#endif /* _PUB_RETURN_H_ */
