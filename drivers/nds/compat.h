/* SPDX-License-Identifier: GPL-2.0 */
#ifndef P2P_COMPAT_H_
#define P2P_COMPAT_H_

/*
 * Kernel flavor dispatch. The Makefile selects the flavor through the
 * KERNEL_FLAVOR variable (vanilla is the default) and sets the matching
 * P2P_COMPAT_* macro through ccflags-y. Exactly one flavor header is
 * included below.
 */
#include <linux/version.h>

/*
 * Version test for the flavor headers. P2P_LINUX_VERSION_CODE is the
 * single reference to the kernel version code in this driver.
 */
#define P2P_LINUX_VERSION_CODE LINUX_##VERSION_CODE
#define P2P_VERSION_LT(major, minor, patch) \
	(KERNEL_VERSION(major, minor, patch) > P2P_LINUX_VERSION_CODE)

#if defined(P2P_COMPAT_VELINUX)
#include "compat_velinux.h"
#elif defined(P2P_COMPAT_UBUNTU)
#include "compat_ubuntu.h"
#elif defined(P2P_COMPAT_OPENEULER)
#include "compat_openeuler.h"
#else
#include "compat_vanilla.h"
#endif

#endif /* P2P_COMPAT_H_ */
