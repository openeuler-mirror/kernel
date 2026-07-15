.. SPDX-License-Identifier: GPL-2.0+

Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved.

===============================================
UnifiedBus DIRECT MEMORY ACCESS DRIVER (UDMA)
===============================================

Overview
=========

This document describes the context and capabilities of the UDMA driver.

**UnifiedBus** is an interconnect protocol for SuperPoD,  It unifies IO,
memory access, and communication between various processing units under
a single interconnect technology framework.
The UnifiedBus specifications are open source and available on the official
website: `UB Specification Documents <https://www.unifiedbus.com/>`_.

**UDMA** (UnifiedBus Direct Memory Access), is a hardware I/O device that
provides direct memory access capabilities.

**URMA(Unified Remote Memory Access)** is a component within the UnifiedBus
protocol stack, designed to abstract and facilitate communication between
different hardware and software entities.

The UDMA driver integrates with the UnifiedBus protocol by implementing
the **URMA programming API**, through this API, the driver exposes the
UnifiedBus remote memory access programming model to application developers.


Device Driver Model
=====================

The UDMA device is a UnifiedBus auxiliary device attached to the auxiliary bus.
The UDMA driver is developed based on the UBASE driver framework and uses
the auxiliary bus to perform device-driver binding.

.. code-block:: none

     +---------------+   +-------+
     |   UDMA Driver |   | ...   |
     +-------+-------+   +-------+
             |
            \|/
     +-------+-------------------+
     |       auxiliary bus       |
     +-------+-------------------+
            /|\
             |
     +-------+-------+
     |   UDMA Device |
     +----+----------+
         /|\
          |  UBASE driver creates UDMA device
     +----+------------------+
     |       UBASE Driver    |
     +-----------+-----------+
                 |
                \|/
     +-----------+---------------+
     |           ubus            |
     +---------------------------+

The figure above illustrates the hierarchy between the UDMA driver and the
UBASE driver. The UBASE driver is responsible for creating the UDMA auxiliary device
and registering it with the auxiliary bus.


Context & Submodules
=======================

The UDMA driver depends on the ``Hardware programming interface``,
``UBASE driver``, and ``UMMU driver``.
It implements the URMA API and provides direct memory access capabilities.

Below figure describe the UDMA driver's context and submodules.

.. code-block:: none

                 +-------------+
                 | 5. URMA API |
                 +-----+-------+
                       ^
                       |
                       |
     +-----------------+-----------------------+
     |             UDMA Driver                 |
     |                                         |
     |                                         |
     | +--------------------+   +-----------+  |
     | |   udma_main        |   | udma_comon|  |
     | +--------------------+   +-----------+  |
     | +----------------++--------++--------+  |
     | | udma_context   ||udma_eid||udma_tid|  |
     | +----------------++--------++--------+  |
     | +-----------------+ +----------------+  |      +---------------+
     | |  udma_jetty     | |  udma_segment  |  +----->| 4. UMMU Driver|
     | +-----------------+ +----------------+  |      +---------------+
     | +------------++---------++-----------+  |
     | |   udma_jfs ||udma_jfr || udma_jfc  |  |
     | +------------++---------++-----------+  |
     | +---------++---------------++--------+  |
     | | udma_db || udma_ctrlq_tp ||udma_dfx|  |
     | +---------++---------------++--------+  |
     | +-----------+ +---------+ +----------+  |
     | | udma_cmd  | |udma_ctl | | udma_eq  |  |
     | +-----------+ +---------+ +----------+  |
     +-----------------------------+-----------+
                                   |                +---------------------+
                                   |                | 3. Management Module|
                                  \|/               +----------+----------+
                          +--------+----------+                |
                          |  2. UBASE Driver  +<---------------+
                          +---------+---------+
                                                    Software
     -------------------------------+-----------------------------------------
                                   \|/              Hardware
      +-----------------------------+----------+
      |    1. Hardware programming interface   |
      +----------------------------------------+

Context
---------

1. Hardware programming interface: The UDMA driver encapsulates the
   hardware programming interface, abstracting the hardware specifics.

2. UBASE: UBASE driver responsible for managing UDMA auxiliary devices.
   It also provides common management capabilities for auxiliary bus devices
   and interacts with the Management module.
   The UDMA device driver is built upon the UBASE driver and reuses its common utility functions.

3. Management module: responsible for device management and configuration.

4. UMMU: UnifiedBus Memory Management Unit, providing memory management
   functionality(address translation, access permission, etc.) for UnifiedBus devices.

5. URMA API: URMA programming interface, URMA API abstracts the memory operations,
   and the UDMA driver implements it, so application developers do not need to be
   aware of the details of the UDMA driver.


Submodules
------------

The UDMA driver submodules can be divided into 4 categories:
common utility and main functions, UDMA communication, device management and configuration,
UDMA device debugging.

**Common Utility and Main Functions**

* udma_main: Implements module_init/module_exit, and registers the UDMA driver
  to the auxiliary bus.

* udma_common: Provides common utility functions for UDMA driver.

**UDMA Communication**

Theses submodules handle UDMA communication setup and
processes(e.g read/write or send/recv operations).

* udma_context: Manages UDMA communication context (allocates context, frees context, etc.).
* udma_eid: Manages UDMA Entity IDs (adds, removes, and queries UDMA entities).
* udma_tid: Manages TIDs (Token IDs) (allocates, frees token IDs).
* udma_segment: Manages memory segments, including local memory segment
  registration and remote memory segment import.
* udma_jetty, udma_jfs, udma_jfr, udma_jfc: Manages UnifiedBus communication
  jetty-related resources, including jetty, jfs, jfr, and jfc.

**UDMA Device Management and Configuration**

These submodules handle the UDMA device management and UDMA communication configuration.

* udma_cmd: Encapsulates hardware configuration commands for UDMA communication,
  e.g., create jfs, create jfc, etc.
* udma_db: Encapsulates UDMA hardware doorbell operations.
* udma_ctrlq_tp: Encapsulates control queue (CtrlQ) operations for UDMA hardware
  configuration, e.g., get the transport channels.
* udma_ctl: Encapsulates UDMA hardware-specific configure operations, which are
  not defined in the URMA API. Application developers should include the header file ``include/ub/urma/udma/udma_ctl.h`` separately.
* udma_eq: Encapsulates hardware event queue operations, e.g., register
  CtrlQ event handle to receive CtrlQ events.

**UDMA Device Debugging**

* udma_dfx: Queries the UDMA hardware runtime configurations, e.g.,
  jetty state, transport mode, etc.


Supported Hardware
====================

UDMA driver supported hardware:

===========   =============
Vendor ID       Device ID
===========   =============
0xCC08         0xA001
0xCC08         0xA002
0xCC08         0xD802
0xCC08         0xD803
0xCC08         0xD80B
0xCC08         0xD80C
===========   =============

You can use the ``lsub`` command on your host OS to query UB devices. Below is an example output:

.. code-block:: shell

    UB network controller <0002>: Huawei Technologies Co., Ltd. URMA management ub entity <cc08>:<a001>
    UB network controller <0082>: Huawei Technologies Co., Ltd. URMA management ub entity <cc08>:<d802>
    UB network controller <0002>: Huawei Technologies Co., Ltd. URMA management ub entity <cc08>:<d80b>

The ``Vendor ID`` and ``Device ID`` are located at the end of each output line
with the format ``<VendorID>:<DeviceID>``, e.g., ``<cc08>:<a001>``.

Note the ``lsub`` command is from ubutils; make sure it is installed on your host.


Module Parameters
===================

UDMA driver supports 4 parameters: **cqe_mode**, **jfc_arm_mode**,
**jfr_sleep_time**, **dump_aux_info**.
The default value represents the best practices; however, you may need to change
the default value in certain cases.

cqe_mode
-----------

``cqe_mode`` controls the method of **Completion Queue Entry (CQE)** event generation.

In interrupt mode, UDMA provides two mechanisms for generating CQE events:
**Producer Index (PI)/Consumer Index (CI) difference comparison**
and **counter-based threshold**.

* PI/CI difference comparison: PI (Producer Index) and CI (Consumer Index)
  respectively point to the next CQE to be written and read in the Completion Queue.
  The device generates an interrupt to notify the upper layer when the
  difference (the number of pending CQEs) exceeds a certain threshold.
* Counter-based threshold: An interrupt is generated when the total number of
  CQEs written to the Completion Queue reaches a programmed threshold.

**Parameter values:**

* 0: Counter-based threshold
* 1: PI/CI difference comparison

**Default value**: 1


jfc_arm_mode
--------------

`jfc_arm_mode` controls the completion event interrupt mode.

**Parameter Values:**

* 0: Always ARM, interrupt always enabled
* 1: No ARM, interrupt is disabled and cannot be modified
* Other value (e.g., 2): Interrupt is disabled, but can be modified

**Default value:** 0


jfr_sleep_time
----------------

``jfr_sleep_time`` configures the maximum blocking wait time (in microseconds)
when deregistering a JFR (Jetty-related resource). The default value is 1000 us.
You can adjust this parameter value as needed.

The allowed range is: ``[0,UINT32_MAX]``

dump_aux_info
---------------

``dump_aux_info`` controls whether to dump auxiliary information
(the hardware register values) into the event body when reporting asynchronous
or completion events.


**Parameter Values:**

* false: Disables the dumping of auxiliary information.
* true: Enables the dumping of auxiliary information.

**Default value**: false


dev_name_style
---------------

``dev_name_style`` controls whether to set udma device name style

**Parameter Values:**

* false: Not set udma device name, driver name is named by adev id
* true: Use chip id, die id and ue id to set udma driver name

**Default value**: true


batch_flush_query_freq
----------------------

``batch_flush_query_freq`` Set ta flush query frequency for batch
when destroy jetty batch, udma driver could set batch_flush_query_freq
to control frequency time to query jetty context.

The allowed range is: ``[0,UINT32_MAX]``

**Default value**: 10

batch_flush_query_timeout
-------------------------

``batch_flush_query_timeout`` Set ta flush query timeout
when destroy jetty, udma driver could set query ta timeout.

The allowed range is: ``[0,UINT32_MAX]``

**Default value**: 64000


sq_reserved
-----------

``sq_reserved`` Set whether reserved sq
In sq reserverd function, user can use reserverd sq address
to create jfs/jetty.

**Parameter Values:**

* false: Not use reserverd sq address.
* true: Use reserved sq address.

**Default value**: false


dump_aux_info
-------------

``dump_aux_info`` Set whether dump aux info
In dump aux info function, user can dump register information
when hardware is abnormal.

**Parameter Values:**

* false: Not use dump aux info.
* true: Use dump aux info.

**Default value**: false


hugepage_enable
---------------

``hugepage_enable`` Set whether set huge page
In set hugepage function, user can enable hugepage

**Parameter Values:**

* false: Not use hugepage.
* true: Use hugepage.

**Default value**: true


jfc_share_enable
----------------

``jfc_share_enable`` Set whether set jfc share
In jfc share function, udma driver could bind jfc
to same resource.

**Parameter Values:**

* false: Not use share jfc.
* true: Use share jfc.

**Default value**: true


dfx_switch
----------

``dfx_switch`` Set whether to enable the udma dfx function
In dfx function, udma driver could store and delete
resource id.

**Parameter Values:**

* false: Not use dfx function.
* true: Use dfx function.

**Default value**: false


debug_switch
----------

``debug_switch`` Set whether to enable the udma debug print function

**Parameter Values:**

* false: Not use debug switch function.
* true: Use debug switch function.

**Default value**: false

Support
=======

If there is any issue or question, please email the specific information related
to the issue or question to <dev@openeuler.org> or vendor's support channel.
