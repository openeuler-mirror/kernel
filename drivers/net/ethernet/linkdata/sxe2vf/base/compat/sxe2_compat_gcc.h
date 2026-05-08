/* SPDX-License-Identifier: GPL-2.0 */
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2_compat_gcc.h
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */
#ifndef __SXE2_COMPAT_GCC_H__
#define __SXE2_COMPAT_GCC_H__

#ifndef SXE2_TEST
#ifdef __has_attribute
#if __has_attribute(__fallthrough__)
# define fallthrough __attribute__((__fallthrough__))
#else
# define fallthrough do {} while (0)
#endif
#else
# define fallthrough do {} while (0)
#endif
#endif

#endif
