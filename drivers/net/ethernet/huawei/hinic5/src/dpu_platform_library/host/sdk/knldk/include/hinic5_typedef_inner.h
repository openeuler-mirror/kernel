/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hinic5_typedef_inner.h
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   :
 */

#ifndef HINIC5_TYPESDEF_INNER_H
#define HINIC5_TYPESDEF_INNER_H

/* static methods testable */
#ifdef EXPORT_STATIC_SYMBOL
#define STATIC (__weak noinline)
#define INLINE (__weak noinline)
#else
#define STATIC static
#define INLINE inline
#endif

#ifndef GIT_COMMIT_ID
#define GIT_COMMIT_ID "unknown"
#endif

#endif /* HINIC5_TYPESDEF_INNER_H */
