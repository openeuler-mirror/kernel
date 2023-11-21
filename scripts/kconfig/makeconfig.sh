#!/bin/sh
# SPDX-License-Identifier: GPL-2.0

if [ ! -f .config ]; then
	echo ".config does not exist"
	exit 1
fi

sed -e '/CONFIG_CC_VERSION_TEXT/d' \
    -e '/CONFIG_CC_IS_GCC/d' \
    -e '/CONFIG_GCC_VERSION/d' \
    -e '/CONFIG_LD_VERSION/d' \
    -e '/CONFIG_LD_IS/d' \
    -e '/CONFIG_CLANG_VERSION/d' \
    -e '/CONFIG_LLD_VERSION/d' \
    -e '/CONFIG_CC_CAN/d' \
    -e '/CONFIG_CC_HAS/d' \
    -e '/CONFIG_AS_VERSION/d' \
    -e '/CONFIG_AS_HAS/d' \
    -e '/CONFIG_AS_IS/d' \
    -e '/CONFIG_PAHOLE_VERSION/d' \
    -i .config

cp .config arch/$1/configs/openeuler_defconfig
