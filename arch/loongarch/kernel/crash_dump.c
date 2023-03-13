// SPDX-License-Identifier: GPL-2.0
#include <linux/crash_dump.h>
#include <linux/io.h>
#include <linux/uio.h>

ssize_t copy_oldmem_page(unsigned long pfn, char *buf,
			 size_t csize, unsigned long offset, int userbuf)
{
	void *vaddr;

	if (!csize)
		return 0;

	vaddr = memremap(__pfn_to_phys(pfn), PAGE_SIZE, MEMREMAP_WB);
	if (!vaddr)
		return -ENOMEM;

	if (!userbuf) {
		memcpy(buf, vaddr + offset, csize);
	} else {
		if (copy_to_user(buf, vaddr + offset, csize)) {
			memunmap(vaddr);
			csize = -EFAULT;
		}
	}

	memunmap(vaddr);

	return csize;
}
