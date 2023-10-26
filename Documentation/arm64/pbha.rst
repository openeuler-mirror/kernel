=======================================================
Page Based Hardware Attribute support for AArch64 Linux
=======================================================

Page Based Hardware Attributes (PBHA) allow the OS to trigger IMPLEMENTATION
DEFINED behaviour associated with a memory access. For example, this may be
taken as a hint to a System Cache whether it should cache the location that
has been accessed.

PBHA consists of four bits in the leaf page table entries for a virtual
address, that are sent with any memory access via that virtual address.

IMPLEMENTATION DEFINED behaviour is not specified by the arm-arm, meaning
it varies between SoCs. There may be unexpected side effects when PBHA
bits are used or combined.
For example, a PBHA bit may be taken as a hint to the Memory Controller that
it should encrypt/decrypt the memory in DRAM. If the CPU has multiple virtual
aliases of the address, accesses that are made without this PBHA bit set may
cause corruption.


Use by virtual machines using KVM
---------------------------------

KVM allows an OS in a virtual machine to configure its own page tables. A
virtual machine can also configure PBHA bits in its page tables. To prevent
side effects that could affect the hypervisor, KVM will only allow
combinations of PBHA bits that only affect performance. Values that cause
changes to the data are forbidden as the Hypervisor and VMM have aliases of
the guest memory, and may swap it to/from disk.

The list of bits to allow is built from the firmware list of PBHA bit
combinations that only affect performance. Because the guest can choose
not to set all the bits in a value, (e.g. allowing 5 implicitly allows 1
and 4), the values supported may differ between a host and guest.

PBHA is only supported for a guest if KVM supports the mechanism the CPU uses
to combine the values from stage1 and stage2 translation. The mechanism is not
advertised, so which mechanism each CPU uses must also be known by the kernel.


Use by device drivers
---------------------

Device drivers should discover the PBHA value to use for a mapping from the
device's firmware description as these will vary between SoCs. If the value
is also listed by firmware as only affecting performance, it can be added to
the pgprot with pgprot_pbha().

Values that require all other aliases to be removed are not supported.


Linux's expectations around PBHA
--------------------------------

'IMPLEMENTATION DEFINED' describes a huge range of possible behaviours.
Linux expects PBHA to behave in the same way as the read/write allocate hints
for a memory type. Below is an incomplete list of expectations:

 * PBHA values have the same meaning for all CPUs in the SoC.
 * Use of the PBHA value does not cause mismatched type, shareability or
   cacheability, it does not take precedence over the stage2 attributes, or
   HCR_EL2 controls.
 * If a PBHA value requires all other aliases to be removed, higher exception
   levels do not have a concurrent alias. (This includes Secure World).
 * Break before make is sufficient when changing the PBHA value.
 * PBHA values used by a page can be changed independently without further side
   effects.
 * Save/restoring the page contents via a PBHA=0 mapping does not corrupt the
   values once a non-zero PBHA mapping is re-created.
 * The hypervisor may clean+invalidate to the PoC via a PBHA=0 mapping prior to
   save/restore to cleanup mismatched attributes. This does not corrupt the
   values after save/restore once a non-zero PBHA mapping is re-created.
 * Cache maintenance via a PBHA=0 mapping to prevent stale data being visible
   when mismatched attributes occur is sufficient even if the subsequent
   mapping has a non-zero PBHA value.
 * The OS/hypervisor can clean-up a page by removing all non-zero PBHA mappings,
   then writing new data via PBHA=0 mapping of the same type, shareability and
   cacheability. After this, only the new data is visible for data accesses.
 * For instruction-fetch, the same maintenance as would be performed against a
   PBHA=0 page is sufficient. (which with DIC+IDC, may be none at all).
 * The behaviour enabled by PBHA should not depend on the size of the access, or
   whether other SoC hardware under the control of the OS is enabled and
   configured.
 * EL2 is able to at least force stage1 PBHA bits to zero.
