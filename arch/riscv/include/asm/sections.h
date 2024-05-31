/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2020 Western Digital Corporation or its affiliates.
 */
#ifndef __ASM_SECTIONS_H
#define __ASM_SECTIONS_H

#include <asm-generic/sections.h>

extern char _start[];
extern char _start_kernel[];
extern char __exittext_begin[], __exittext_end[];

#endif /* __ASM_SECTIONS_H */
