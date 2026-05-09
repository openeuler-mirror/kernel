/* SPDX-License-Identifier: GPL-2.0 */
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2_version.h
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */
#ifndef __SXE2_VER_H__
#define __SXE2_VER_H__

#define SXE2_VERSION                "2.1.0.9"
#define SXE2_COMMIT_ID              "049b638"
#define SXE2_BRANCH                 "develop/rc/tucana-2.1.0_B009_OpenSource-01"
#define SXE2_BUILD_TIME             "2026-05-07 14:15:31"

#define SXE2_DRV_ARCH                   "x86_64"
#define SXE2_DRV_NAME                   "sxe2"
#define SXE2VF_DRV_NAME                 "sxe2vf"
#define SXE2_DRV_LICENSE                "GPL v2"
#define SXE2_DRV_AUTHOR                 "SXE2"
#define SXE2_DRV_DESCRIPTION            "SXE2 Linux Driver"
#define SXE2VF_DRV_DESCRIPTION          "SXE2 Virtual Function Linux Driver"

#define SXE2_FW_NAME                     "soc"
#define SXE2_FW_ARCH                     "arm32"

#ifndef SXE2_CFG_RELEASE
#define SXE2_FW_BUILD_MODE             "debug"
#else
#define SXE2_FW_BUILD_MODE             "release"
#endif

#define SXE2_FW_RUN_MODE                   6

#endif
