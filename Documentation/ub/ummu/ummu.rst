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

Interaction with ``iommu.passthrough``
--------------------------------------

The generic ``iommu.passthrough=1`` parameter is intended for PCI/IOMMU
bypass and only affects the generic IOMMU framework path. UMMU does not
respond to passthrough and keeps working normally even when
``iommu.passthrough=1`` is configured for PCI devices on a system where
PCI and UB coexist.

UMMU Driver Initialization
==========================

When the UMMU driver detects an UMMU-capable platform device, it invokes
the probe function `ummu_device_probe()`. This function identifies the
device's hardware capabilities, allocates queues, configuration tables,
and interrupt handlers, and initializes the associated resources.

Interrupt Handling
==================

The UMMU driver requests two MSIs per UMMU device, both allocated from the
platform MSI domain referenced by the ``msi-parent`` property:

- **Event Queue (evtq) interrupt**:
  Reports events written by the UMMU into the event queue. It is registered
  as a threaded handler (``IRQF_ONESHOT``) serviced by
  ``ummu_evtq_thread()``.

- **Global Error (gerror) interrupt**:
  Reports global errors detected by the UMMU. It is registered as a normal
  hardirq handler serviced by ``ummu_gerror_handler()``.

Both interrupts are set up by ``ummu_setup_irqs()`` during probe, after the
event queue and the command queue have been initialized.

Interrupt Affinity
------------------

By default the UMMU interrupts are left to the generic IRQ balancer. On
device tree platforms, the UMMU and the UMMU-PMU nodes accept the
``interrupt-affinity`` property, which pins their MSIs to a fixed set of
CPUs::

    interrupt-affinity = <&cpu1>, <&cpu3>;

The property uses the same syntax as the ``interrupt-affinity`` property
defined by the ARM PMU binding: each entry is a single phandle pointing to a
CPU node, written as its own ``<...>`` group and carrying no additional
arguments.

The semantics are different, though. The ARM PMU binding matches the i-th
entry to the i-th interrupt, while UMMU does not match entries to individual
interrupts at all: all listed CPUs are collected into one CPU mask, which is
applied to both the evtq and the gerror interrupt with
``irq_set_affinity()`` right after the interrupts have been requested.

Behaviour details:

- If the property is absent or empty, the default interrupt placement is
  kept and no message is emitted.
- Phandles that cannot be parsed, or that do not resolve to a valid logical
  CPU, are reported with a warning and skipped. If no valid CPU remains, the
  affinity is left untouched.
- A failing ``irq_set_affinity()`` is reported with a warning; probe
  continues and the interrupt keeps its previous placement.
- The property is only evaluated on device tree systems. UMMU platform
  devices created from ACPI have no device node, so the property has no
  effect there.

Example which pins the UMMU interrupts to CPU1 and CPU3::

    ummu@0 {
            compatible = "ub,ummu";
            index = <0x0>;
            msi-parent = <&its>;
            interrupt-affinity = <&cpu1>, <&cpu3>;
    };

UMMU-PMU Interrupt Affinity
---------------------------

The UMMU-PMU owns a single overflow MSI, registered as a non-threaded shared
interrupt (``IRQF_NOBALANCING | IRQF_SHARED | IRQF_NO_THREAD``). It accepts
the same ``interrupt-affinity`` property, and the whole CPU mask is applied
to that single interrupt::

    ummu-pmu@0 {
            compatible = "ub,ummu_pmu";
            index = <0x0>;
            msi-parent = <&its>;
            interrupt-affinity = <&cpu1>;
    };

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

UMMU Module Parameters
=======================

The UMMU driver exposes the following module parameter that can be set at
driver load time.

ubm_granule
-----------

UB memory page table granule, specified as an unsigned long via the
``ubm_granule`` kernel module parameter.

Usage::

    insmod ummu.ko ubm_granule=<value>

The granule size determines the minimum mapping unit for on-chip memory
address translation:

    ``granule_size = 2^ubm_granule * 2 MB``

Default value is ``0``, corresponding to a granule size of 2 MB.

If an invalid value is supplied, the driver emits a warning and resets
``ubm_granule`` to 0:

Granule Size Mapping Table
^^^^^^^^^^^^^^^^^^^^^^^^^^

========= ==================
granule   granule_size
          (2^g × 2 MB)
========= ==================
0         2 MB
1         4 MB
2         8 MB
3         16 MB
4         32 MB
5         64 MB
6         128 MB
7         256 MB
8         512 MB
10        2 GB
12        8 GB
14        32 GB
========= ==================

Both the address and the total mapping size must be aligned to
the granule size.  Misaligned mappings are rejected by the driver.

Examples::

    # granule = 4 → 32 MB mapping granularity
    insmod ummu.ko ubm_granule=4

    # Invalid value: driver warns and resets to 0
    insmod ummu.ko ubm_granule=9
