/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2021. Huawei Technologies Co., Ltd. All rights reserved.
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 and
 * only version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 */

#ifndef EUFS_FLUSH_H
#define EUFS_FLUSH_H

#ifdef CONFIG_X86_64
static __always_inline bool arch_has_clwb(void)
{
	return static_cpu_has(X86_FEATURE_CLWB);
}

static __always_inline bool arch_has_clflushopt(void)
{
	return static_cpu_has(X86_FEATURE_CLFLUSHOPT);
}

static __always_inline bool arch_has_clflush(void)
{
	return static_cpu_has(X86_FEATURE_CLFLUSH);
}

static __always_inline bool arch_has_rtm(void)
{
	return static_cpu_has(X86_FEATURE_RTM);
}

static __always_inline void __sfence(void)
{
	asm volatile("sfence\n" : : : "memory");
}

static inline void _mm_clflush(const void *addr)
{
	asm volatile("clflush %0" : "+m"(*(volatile char *)(addr)));
}

static inline void _mm_clflushopt(const void *addr)
{
	asm volatile(".byte 0x66; clflush %0" : "+m"(*(volatile char *)(addr)));
}

static inline void _mm_clwb(const void *addr)
{
	asm volatile(".byte 0x66; xsaveopt %0" : "+m"(*(volatile char *)(addr)));
}

#else
static __always_inline bool arch_has_clwb(void)
{
	return false;
}

static __always_inline bool arch_has_clflushopt(void)
{
	return false;
}

static __always_inline bool arch_has_clflush(void)
{
	return false;
}

static __always_inline bool arch_has_rtm(void)
{
	return false;
}

static __always_inline void __sfence(void)
{
	/* arm64 doesn't support sfence */
	smp_mb();
}

#define _mm_clflush(addr) do {} while (0)
#define _mm_clflushopt(addr) do {} while (0)
#define _mm_clwb(addr) do {} while (0)
#endif

extern int support_rtm;
extern int support_clwb;
extern int support_clflushopt;
extern int support_clflush;
extern int clflush_delay;
extern int force_nocache_write;
extern int max_dirty_inodes;
extern int max_dep_nodes;

static __always_inline void eufs_sfence(void)
{
	__sfence();
}

static __always_inline void eufs_pbarrier(void)
{
	if (support_clwb || support_clflushopt)
		eufs_sfence();
}

static __always_inline void eufs_flush_cacheline(const void *ptr)
{
	if (support_clwb)
		_mm_clwb(ptr);
	else if (support_clflushopt)
		_mm_clflushopt(ptr);
	else if (support_clflush)
		_mm_clflush(ptr);
}

static __always_inline void eufs_flush_page(const void *ptr)
{
	uint32_t i;

	if (support_clwb) {
		for (i = 0; i < PAGE_SIZE; i += CACHELINE_SIZE)
			_mm_clwb(ptr + i);
	} else if (support_clflushopt) {
		for (i = 0; i < PAGE_SIZE; i += CACHELINE_SIZE)
			_mm_clflushopt(ptr + i);
	} else if (support_clflush) {
		for (i = 0; i < PAGE_SIZE; i += CACHELINE_SIZE)
			_mm_clflush(ptr + i);
	}
}

static __always_inline void eufs_flush_buffer(const void *buf, uint32_t len,
					       bool fence)
{
	uint32_t i;
	uint32_t aligned_len =
		len + ((unsigned long)(buf) & (CACHELINE_SIZE - 1));

	if (support_clwb) {
		for (i = 0; i < aligned_len; i += CACHELINE_SIZE)
			_mm_clwb(buf + i);
	} else if (support_clflushopt) {
		for (i = 0; i < aligned_len; i += CACHELINE_SIZE)
			_mm_clflushopt(buf + i);
	} else if (support_clflush) {
		for (i = 0; i < aligned_len; i += CACHELINE_SIZE) {
			/* flush the cache line that contains the address (buf + i) */
			_mm_clflush(buf + i);
		}
	}

	/*
	 * Do a fence only if asked. We often don't need to do a fence
	 * immediately after clflush because even if we get context switched
	 * between clflush and subsequent fence, the context switch operation
	 * provides implicit fence.
	 */
	if (fence)
		eufs_sfence();
}

static __always_inline void eufs_flush_range(const void *ptr, uint32_t len)
{
	eufs_flush_buffer(ptr, len, false);
}

#endif /* EUFS_FLUSH_H */
