// SPDX-License-Identifier: GPL-2.0
/*
 * csum_partial_copy - do IP checksumming and copy
 *
 * (C) Copyright 1996 Linus Torvalds
 *
 * Don't look at this too closely - you'll go mad. The things
 * we do for performance..
 */

#include <linux/types.h>
#include <linux/string.h>
#include <linux/uaccess.h>


#define ldl_u(x, y) \
	__asm__ __volatile__("ldl_u %0, %1":"=r" (x):"m" (*(const unsigned long *)(y)))

#define stl_u(x, y) \
	__asm__ __volatile__("stl_u %1, %0":"=m" (*(unsigned long *)(y)):"r" (x))

static inline void stll_u(unsigned long data, unsigned long *dst)
{
	int i = 0;
	unsigned long doff = (unsigned long)dst & 7;

	for (; doff < 8; i++, doff++)
		*((char *)dst + i) = *((char *)&data + i);
}

static inline void sthl_u(unsigned long data, unsigned long *dst)
{
	int i = 0;
	unsigned long doff = (unsigned long)dst & 7;

	for (; i < doff; i++)
		*((char *)dst + 8 - doff + i) = *((char *)&data + 8 - doff + i);
}

#define extll(x, y, z) \
	__asm__ __volatile__("extll %1, %2, %0":"=r" (z):"r" (x), "r" (y))

#define exthl(x, y, z) \
	__asm__ __volatile__("exthl %1, %2, %0":"=r" (z):"r" (x), "r" (y))

#define maskll(x, y, z) \
	__asm__ __volatile__("maskll %1, %2, %0":"=r" (z):"r" (x), "r" (y))

#define maskhl(x, y, z) \
	__asm__ __volatile__("maskhl %1, %2, %0":"=r" (z):"r" (x), "r" (y))

#define insll(x, y, z) \
	__asm__ __volatile__("insll %1, %2, %0":"=r" (z):"r" (x), "r" (y))

#define inshl(x, y, z) \
	__asm__ __volatile__("inshl %1, %2, %0":"=r" (z):"r" (x), "r" (y))


#define __get_word(insn, x, ptr)			\
({							\
	long __guu_err;					\
	__asm__ __volatile__(				\
	"1:	"#insn" %0,%2\n"			\
	"2:\n"						\
	".section __ex_table,\"a\"\n"			\
	"	.long 1b - .\n"				\
	"	ldi %0,2b-1b(%1)\n"			\
	".previous"					\
		: "=r"(x), "=r"(__guu_err)		\
		: "m"(__m(ptr)), "1"(0));		\
	__guu_err;					\
})

static inline unsigned short from64to16(unsigned long x)
{
	/* Using extract instructions is a bit more efficient
	 * than the original shift/bitmask version.
	 */

	union {
		unsigned long	ul;
		unsigned int	ui[2];
		unsigned short	us[4];
	} in_v, tmp_v, out_v;

	in_v.ul = x;
	tmp_v.ul = (unsigned long) in_v.ui[0] + (unsigned long) in_v.ui[1];

	/* Since the bits of tmp_v.sh[3] are going to always be zero,
	 * we don't have to bother to add that in.
	 */
	out_v.ul = (unsigned long) tmp_v.us[0] + (unsigned long) tmp_v.us[1]
			+ (unsigned long) tmp_v.us[2];

	/* Similarly, out_v.us[2] is always zero for the final add.  */
	return out_v.us[0] + out_v.us[1];
}

/*
 * Ok. This isn't fun, but this is the EASY case.
 */
static inline unsigned long
csum_partial_cfu_aligned(const unsigned long __user *src, unsigned long *dst,
		long len)
{
	unsigned long checksum = ~0U;
	unsigned long carry = 0;

	while (len >= 0) {
		unsigned long word;

		if (__get_word(ldl, word, src))
			return 0;
		checksum += carry;
		src++;
		checksum += word;
		len -= 8;
		carry = checksum < word;
		*dst = word;
		dst++;
	}
	len += 8;
	checksum += carry;
	if (len) {
		int i = 0;
		unsigned long word;

		if (__get_word(ldl, word, src))
			return 0;
		maskll(word, len, word);
		checksum += word;
		carry = checksum < word;
		for (; i < len; i++)
			*((char *)dst + i) = *((char *)&word + i);
		checksum += carry;
	}
	return checksum;
}

/*
 * This is even less fun, but this is still reasonably
 * easy.
 */
static inline unsigned long
csum_partial_cfu_dest_aligned(const unsigned long __user *src,
		unsigned long *dst, unsigned long soff, long len)
{
	unsigned long first;
	unsigned long word, carry;
	unsigned long lastsrc = 7+len+(unsigned long)src;
	unsigned long checksum = ~0U;

	if (__get_word(ldl_u, first, src))
		return 0;
	carry = 0;
	while (len >= 0) {
		unsigned long second;

		if (__get_word(ldl_u, second, src+1))
			return 0;
		extll(first, soff, word);
		len -= 8;
		src++;
		exthl(second, soff, first);
		checksum += carry;
		word |= first;
		first = second;
		checksum += word;
		*dst = word;
		dst++;
		carry = checksum < word;
	}
	len += 8;
	checksum += carry;
	if (len) {
		int i = 0;
		unsigned long second;

		if (__get_word(ldl_u, second, lastsrc))
			return 0;
		extll(first, soff, word);
		exthl(second, soff, first);
		word |= first;
		maskll(word, len, word);
		checksum += word;
		carry = checksum < word;
		for (; i < len; i++)
			*((char *)dst + i) = *((char *)&word + i);
		checksum += carry;
	}
	return checksum;
}

/*
 * This is slightly less fun than the above..
 */
static inline unsigned long
csum_partial_cfu_src_aligned(const unsigned long __user *src,
		unsigned long *dst, unsigned long doff,
		long len, unsigned long partial_dest)
{
	unsigned long carry = 0;
	unsigned long word;
	unsigned long second_dest;
	int i;
	unsigned long checksum = ~0U;

	if (len >= 0) {
		if (__get_word(ldl, word, src))
			return 0;
		checksum += carry;
		checksum += word;
		carry = checksum < word;
		stll_u(word, dst);
		len -= 8;
		src++;
		dst++;

		inshl(word, doff, partial_dest);
		while (len >= 0) {
			if (__get_word(ldl, word, src))
				return 0;
			len -= 8;
			insll(word, doff, second_dest);
			checksum += carry;
			stl_u(partial_dest | second_dest, dst);
			src++;
			checksum += word;
			inshl(word, doff, partial_dest);
			carry = checksum < word;
			dst++;
		}
		sthl_u(word, dst - 1);
	}
	len += 8;

	if (__get_word(ldl, word, src))
		return 0;
	maskll(word, len, word);
	checksum += carry;
	checksum += word;
	carry = checksum < word;
	for (i = 0; i < len; i++)
		*((char *)dst + i) = *((char *)&word + i);

	checksum += carry;
	return checksum;
}

/*
 * This is so totally un-fun that it's frightening. Don't
 * look at this too closely, you'll go blind.
 */
static inline unsigned long
csum_partial_cfu_unaligned(const unsigned long __user *src,
		unsigned long *dst, unsigned long soff, unsigned long doff,
		long len, unsigned long partial_dest)
{
	unsigned long carry = 0;
	unsigned long first;
	unsigned long second, word;
	unsigned long second_dest;
	int i;
	unsigned long checksum = ~0U;

	if (__get_word(ldl_u, first, src))
		return 0;
	if (len >= 0) {
		extll(first, soff, word);
		if (__get_word(ldl_u, second, src+1))
			return 0;
		exthl(second, soff, first);
		word |= first;
		checksum += carry;
		checksum += word;
		carry = checksum < word;
		stll_u(word, dst);
		sthl_u(word, dst);
		len -= 8;
		src++;
		dst++;

		if (__get_word(ldl_u, first, src))
			return 0;
		ldl_u(partial_dest, dst);
		maskll(partial_dest, doff, partial_dest);
		while (len >= 0) {
			if (__get_word(ldl_u, second, src+1))
				return 0;
			extll(first, soff, word);
			checksum += carry;
			len -= 8;
			exthl(second, soff, first);
			src++;
			word |= first;
			first = second;
			insll(word, doff, second_dest);
			checksum += word;
			stl_u(partial_dest | second_dest, dst);
			carry = checksum < word;
			inshl(word, doff, partial_dest);
			dst++;
		}
		sthl_u(word, dst - 1);
	}
	len += 8;

	checksum += carry;
	if (__get_word(ldl_u, second, src+1))
		return 0;
	extll(first, soff, word);
	exthl(second, soff, first);
	word |= first;
	maskll(word, len, word);
	checksum += word;
	carry = checksum < word;
	for (i = 0; i < len; i++)
		*((char *)dst + i) = *((char *)&word + i);

	checksum += carry;
	return checksum;
}

static __wsum __csum_and_copy(const void __user *src, void *dst, int len)
{
	unsigned long checksum;
	unsigned long soff = 7 & (unsigned long) src;
	unsigned long doff = 7 & (unsigned long) dst;

	if (!doff) {
		if (!soff)
			checksum = csum_partial_cfu_aligned(
				(const unsigned long __user *) src,
				(unsigned long *) dst, len-8);
		else
			checksum = csum_partial_cfu_dest_aligned(
				(const unsigned long __user *) src,
				(unsigned long *) dst,
				soff, len-8);
	} else {
		unsigned long partial_dest;

		ldl_u(partial_dest, dst);
		if (!soff)
			checksum = csum_partial_cfu_src_aligned(
				(const unsigned long __user *) src,
				(unsigned long *) dst,
				doff, len-8, partial_dest);
		else
			checksum = csum_partial_cfu_unaligned(
				(const unsigned long __user *) src,
				(unsigned long *) dst,
				soff, doff, len-8, partial_dest);
	}
	return (__force __wsum)from64to16(checksum);
}

__wsum
csum_and_copy_from_user(const void __user *src, void *dst, int len)
{
	if (!access_ok(src, len))
		return 0;
	return __csum_and_copy(src, dst, len);
}
EXPORT_SYMBOL(csum_and_copy_from_user);

__wsum
csum_partial_copy_nocheck(const void *src, void *dst, int len)
{
	return __csum_and_copy((__force const void __user *)src,
			dst, len);
}
EXPORT_SYMBOL(csum_partial_copy_nocheck);
