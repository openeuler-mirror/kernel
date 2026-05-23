.. SPDX-License-Identifier: GPL-2.0

============================================================
Linux Kernel Driver for Huawei Intelligent NIC(HiNIC5) family
============================================================

Overview:
=========
HiNIC5 is a network interface card for the Data Center Area.

The driver supports a range of link-speed devices (10GbE, 25GbE, 40GbE, etc.).
The driver supports also a negotiated and extendable feature set.

Some HiNIC5 devices support SR-IOV. This driver is used for Physical Function
(PF).

HiNIC5 devices support MSI-X interrupt vector for each Tx/Rx queue and
adaptive interrupt moderation.

HiNIC5 devices support also various offload features such as checksum offload,
TCP Transmit Segmentation Offload(TSO), Receive-Side Scaling(RSS) and
LRO(Large Receive Offload).


Supported PCI vendor ID/device IDs:
===================================

19e5:1822 - HiNIC5 PF


Driver Architecture and Source Code:
====================================

hinic5_dev - Implement a Logical Network device that is independent from
specific HW details about HW data structure formats.
hinic5_hwdev
 - Implement the HW details of the device and include the components
for accessing the PCI NIC.

hinic5_hwdev contains the following components:
===============================================

HW Interface:
=============

The interface for accessing the pci device (DMA memory and PCI BARs).
(hinic5_hw_if.c, hinic5_hw_if.h)

Configuration Status Registers Area that describes the HW Registers on the
configuration and status BAR0. (hinic5_hw_csr.h)

MGMT components:
================

Asynchronous Event Queues(AEQs) - The event queues for receiving messages from
the MGMT modules on the cards. (hinic5_hw_eqs.c, hinic5_hw_eqs.h)

Application Programmable Interface commands(API CMD) - Interface for sending
MGMT commands to the card. (hinic5_hw_api_cmd.c, hinic5_hw_api_cmd.h)

Management (MGMT) - the PF to MGMT channel that uses API CMD for sending MGMT
commands to the card and receives notifications from the MGMT modules on the
card by AEQs. Also set the addresses of the IO CMDQs in HW.
(hinic5_hw_mgmt.c, hinic5_hw_mgmt.h)

IO components:
==============

Completion Event Queues(CEQs) - The completion Event Queues that describe IO
tasks that are finished. (hinic5_hw_eqs.c, hinic5_hw_eqs.h)

Work Queues(WQ) - Contain the memory and operations for use by CMD queues and
the Queue Pairs. The WQ is a Memory Block in a Page. The Block contains
pointers to Memory Areas that are the Memory for the Work Queue Elements(WQEs).
(hinic5_hw_wq.c, hinic5_hw_wq.h)

Command Queues(CMDQ) - The queues for sending commands for IO management and is
used to set the QPs addresses in HW. The commands completion events are
accumulated on the CEQ that is configured to receive the CMDQ completion events.
(hinic5_hw_cmdq.c, hinic5_hw_cmdq.h)

Queue Pairs(QPs) - The HW Receive and Send queues for Receiving and Transmitting
Data. (hinic5_hw_qp.c, hinic5_hw_qp.h, hinic5_hw_qp_ctxt.h)

IO - de/constructs all the IO components. (hinic5_hw_io.c, hinic5_hw_io.h)

CQM components:
==========

The CQM module organizes the memory in the large system in a format (CLA table)
and allocates the memory to the chip (BAT table). The chip can use the memory in
the large system to save context information and queue information (SCQ\SRQ).
(cqm_bat_cla.c, cqm_bat_cla.h, cqm_bitmap_table.c, cqm_bitmap_table.h)

When a packet is transmitted from the PCIe link, the chip parses the 5-tuple
such as sid, did, and hostid. Fill the parsed data in the queue
(in the form of scqe). In this way, the driver can directly obtain data from the
queue (through MPDK polling) and then process the data. In this way, the
uninstallation is implemented.
(cqm_main.c, cqm_main.h, cqm_db.c, cqm_db.h)

HW device:
==========

HW device - de/constructs the HW Interface, the MGMT components on the
initialization of the driver and the IO components on the case of Interface
UP/DOWN Events. (hinic5_hw_dev.c, hinic5_hw_dev.h)


hinic5_dev contains the following components:
===============================================

PCI ID table - Contains the supported PCI Vendor/Device IDs.
(hinic5_pci_tbl.h)

Port Commands - Send commands to the HW device for port management
(MAC, Vlan, MTU, ...). (hinic5_port.c, hinic5_port.h)

Tx Queues - Logical Tx Queues that use the HW Send Queues for transmit.
The Logical Tx queue is not dependent on the format of the HW Send Queue.
(hinic5_tx.c, hinic5_tx.h)

Rx Queues - Logical Rx Queues that use the HW Receive Queues for receive.
The Logical Rx queue is not dependent on the format of the HW Receive Queue.
(hinic5_rx.c, hinic5_rx.h)

hinic_dev - de/constructs the Logical Tx and Rx Queues.
(hinic5_main.c, hinic5_dev.h)


Miscellaneous:
=============

Common functions that are used by HW and Logical Device.
(hinic5_common.c, hinic5_common.h)


Support
=======

If an issue is identified with the released source code on the supported kernel
with a supported adapter, email the specific information related to the issue to
wulike1@huawei.com.
