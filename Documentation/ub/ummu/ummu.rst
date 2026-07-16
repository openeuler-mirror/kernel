.. SPDX-License-Identifier: GPL-2.0+

===========
UMMU Driver
===========

UMMU Functionality
==================

The UMMU driver implements IOMMU functionality, enabling address
translation and access control for DMA transactions initiated by
peripheral devices.

UMMU plays a critical role in system virtualization, device isolation,
and secure DMA address translation.

In Shared Virtual Addressing (SVA) scenarios, UMMU enforces permission
checks to protect data within the shared address space, ensuring access
integrity and confidentiality.

UMMU performs address translation and permission checking using input
parameters derived from the UB Memory Descriptor (EID + TokenID + UBA).

For detailed information on the UB Memory Descriptor format and semantics,
refer to the `UB-Base-Specification-2.0`_.

.. _UB-Base-Specification-2.0: https://www.unifiedbus.com/

The functionality of UMMU is primarily organized into the following three
core components:

Configuration Table Lookup
--------------------------

The configuration data for address translation and permission checking in
UMMU is stored in memory and organized into two levels of configuration
tables: TECT (Target Entity Configuration Table) and TCT (Target Context
Table).

- **TECT (Target Entity Configuration Table)**:
  UMMU uses the DstEID to locate the corresponding TECT entry. This entry
  primarily contains local entity information and serves as a storage
  location for the entry points of the TCT and the Stage 2 address
  translation tables.

- **TCT (Target Context Table)**:
  UMMU uses the TokenID to locate the corresponding TCT entry. This entry
  describes the address space-level information, which may have a
  granularity equal to or finer than that of the process level. The TCT
  entry primarily stores the base addresses of the Stage 1 address
  translation table and the MAPT (Memory Address Permission Table) used for
  SVA mode permission checking.

Address Translation
-------------------

UMMU uses the EID and TokenID to locate the corresponding entries in the
TECT (Target Entity Configuration Table) and TCT (Target Context Table).
Based on the configuration table entries, it determines the base address
of the page table. It then uses the UBA and the page table base address to
perform the page table entry lookup and complete the address translation.

In DMA scenarios, UMMU uses separate Stage 1 and Stage 2 translation
tables to support multiple-stage address translation.

In user-space SVA scenarios, UMMU enables the device to directly access
the process's virtual address space. Similarly, kernel-space SVA allows
the device to access kernel-level virtual memory, enabling efficient data
sharing between the device and the kernel.

Permission Checking
-------------------

In SVA scenarios, UMMU performs permission checks to ensure the security
of the address space.

UMMU performs permission checking in parallel with address translation.
After retrieving the TECT and TCT entries, if permission checking is
enabled for the currently accessed TECT entity, UMMU can obtain the MAPT
(Memory Address Permission Table) entry from the TCT entry. UMMU then
retrieves the permission information for the target memory from the MAPT,
compares it with the permissions specified in the memory access request,
and determines whether the access passes the permission check.

The permission checking feature enables fine-grained control over memory
segment access, allowing the system to authorize or deauthorize specific
memory regions. It is recommended to enable the permission checking
feature to enforce security policies and protect the SVA address space
from unauthorized access.

iommu.passthrough Not Supported
===============================

The UB protocol does not support the IOMMU passthrough mode
(iommu.passthrough=1). UMMU must operate in DMA mode as defined by the
UB protocol specification.

When `iommu.passthrough=1` is configured, UMMU becomes unavailable and
UB device functionality will be abnormal. Do not enable the
`iommu.passthrough` option in systems that use UMMU.

UMMU Driver Initialization
==========================

When the UMMU driver detects an UMMU-capable platform device, it invokes
the probe function `ummu_device_probe()`. This function identifies the
device's hardware capabilities, allocates queues, configuration tables,
and interrupt handlers, and initializes the associated resources.

UMMU Device Registration
========================

After the UMMU device completes its initialization, it is registered with
the UMMU framework. The UB system supports multiple UMMU devices within a
single chip. The UMMU framework abstracts a Logic UMMU device to uniformly
manage multiple physical UMMU devices. Once wrapped by the framework, the
Logic UMMU is ultimately registered with the IOMMU framework.

In addition to calling the `struct iommu_ops` registered by individual UMMU
devices, the Logic UMMU leverages the extended operation set `struct
ummu_core_ops` provided by the UMMU framework to uniformly manage all
underlying UMMU device instances. This includes sharing configuration and
page table information across devices, and synchronizing invalidation
operations to ensure consistent table lookup results across the entire
device set.

.. code-block:: none

                       +-------------------+
                       |  IOMMU Framework  |
                       +-------------------+
                                  ^
                                  |
                              Register
                                  |
                       +--------------------+
                       | UMMU-CORE Framework|
                       +--------------------+
                                  ^
                                  |
                              Register
                                  |
    +----------------+   +----------------+     +----------------+
    | ummu device 0  |   | ummu device 1  | ... | ummu device x  |
    +----------------+   +----------------+     +----------------+
