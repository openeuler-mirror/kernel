.. SPDX-License-Identifier: GPL-2.0

====================
Kernel driver eeprom
====================


Description
-----------
the PAGEATTACH mechanism, a zero-copy data transfer solution optimized for
High Performance Computing workloads. It allows direct sharing of physical
memory pages between distinct processes by mapping source pages to a target
address space, eliminating redundant data copying and improving large data
transfer efficiency.


Key features
-----------
- Supports zero-copy communication between intra-node processes.
- Handles both PTE-level small pages and PMD-level huge pages.
- Preserves the read/write permissions of the source page in the target address space.


Important constraints and requirements
---------------------
1. Callers must ensure the source address is already mapped to physical pages,
while the destination address is unused (no existing mappings). If exists
old mappings, the return value is -EAGAIN. For this case, caller should free
the old dst_addr, and alloc a new one to try again.

2. No internal locking is implemented in the PageAttach interface; Callers
must manage memory mapping and release order to avoid race conditions.

3. Source and destination must be different processes (not threads of the same process).

4. Only user-space addresses are supported; kernel addresses cannot be mapped.

5. Both source and destination processes must remain alive during the mapping operation.

6. PUD-level huge pages are not supported in current implementation.

7. The start address and size of both source and destination must be PMD-size-aligned.

8. Callers are responsible for ensuring safe access to mapped pages after attachment,
as permissions are inherited from the source.


Use
---
Process a
  src_addr= aligned_alloc(ALIGN_SIZE_2M, size);
  memset(src_addr, 0, size);

Process b
  #define ALIGN_SIZE_2M 2097152
  int fd = open(SLS_DEVICE, O_RDWR);

  dst_addr= aligned_alloc(ALIGN_SIZE_2M, size);
  res = zcopy(fd, (void *)src_addr, dst_addr, src_pid, dst_pid, size);
  while(res.ret == -EAGAIN && retry--) {
      free(dst_addr);
      dst_addr= aligned_alloc(ALIGN_SIZE_2M, size);
      res = zcopy(fd, (void *)src_addr, dst_addr, src_pid, dst_pid, aligned_size);
  }
