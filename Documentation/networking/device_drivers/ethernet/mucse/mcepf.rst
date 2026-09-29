.. SPDX-License-Identifier: GPL-2.0-only

MUCSE MCEPF Ethernet driver
===========================

The ``mcepf`` driver supports the physical functions (PFs) of MUCSE N20 and
B850 PCI Express Ethernet adapters.  The supported device families provide
25GbE, 40GbE, and 100GbE ports.

The driver matches MUCSE PCI vendor ID ``0x8848`` and the following device
IDs:

* N20: ``0x8500`` (25GbE), ``0x8501`` (100GbE), and ``0x8502`` (40GbE).
* B850: ``0x8507`` (25GbE), ``0x8508`` (100GbE), and ``0x8509`` (40GbE).

The network interface is created by the PF driver and is normally named by
udev in the same way as other PCI Ethernet devices.

Configuration and build
-----------------------

Enable the driver with ``CONFIG_MCEPF`` under ``NET_VENDOR_MUCSE``.  The
driver can be built into the kernel or as the ``mcepf`` module.  A minimal
configuration fragment is:

.. code-block:: none

   CONFIG_NET_VENDOR_MUCSE=y
   CONFIG_MCEPF=m

To build only this driver after configuring the kernel, use:

.. code-block:: shell

   make M=drivers/net/ethernet/mucse/mcepf CONFIG_MCEPF=m

Load a modular build with:

.. code-block:: shell

   modprobe mcepf

The driver uses the kernel auxiliary bus to expose an optional
``mrdma_roce`` companion device on adapters that provide the required RDMA
resources.  Ethernet operation does not require a separate auxiliary driver.

Features
--------

The PF network interface provides the following hardware-assisted features
when the corresponding kernel and firmware support is available:

* multi-queue transmit and receive with RSS and receive hashing;
* scatter-gather DMA, receive and transmit checksum offload, and SCTP CRC
  offload;
* TSO/TSO6 and GSO, including the supported GRE and UDP tunnel modes;
* 802.1Q and 802.1ad VLAN insertion, stripping, and filtering;
* UDP tunnel port offload;
* ethtool ntuple/Flow Director filters and hardware ``tc flower`` offload;
* PTP hardware transmit and receive timestamping through the kernel PHC;
* DCB traffic classes, ETS, PFC, DSCP mapping, and queue-rate controls;
* SR-IOV virtual functions and PF controls for VF MAC, VLAN, rate, trust,
  spoof checking, and link state;
* devlink device information, firmware flash operations, eswitch mode, and
  the ``vf_max_ring`` device parameter.

The exact set of advertised features depends on the selected kernel options,
the adapter, and its firmware.  Check the interface after loading the driver:

.. code-block:: shell

   ethtool -i <netdev>
   ethtool -k <netdev>
   ethtool -T <netdev>
   devlink dev info pci/<domain>:<bus>:<slot>.<func>

Accelerated Receive Flow Steering (ARFS) is disabled by default.  Enable it
at module load time when ``CONFIG_RFS_ACCEL`` is enabled:

.. code-block:: shell

   modprobe mcepf arfs=1

ARFS uses the hardware Flow Director to steer learned flows to the CPU and
queue selected by the networking stack.

Module parameters
-----------------

The most commonly useful parameters are:

``arfs``
  Boolean; enable ARFS through the Flow Director.  The default is ``0``.

``rx_page_pool``
  Boolean; use page-pool based receive buffer management.  The default is
  ``0``.

``fdir_mode``
  Select the Flow Director matching mode.  Values ``0`` through ``3`` select
  the exact or signature mode with or without MACVLAN filtering, as described
  by the module parameter help.

``tun_inner``
  Parse tunnel packets using the inner layer when set to ``1``; the default
  is ``0`` (outer layer).

``pcie_irq_mode``
  Select MSI-X (``1``), MSI (``2``), or legacy (``3``) interrupts.  The
  default lets the driver select MSI-X and fall back when necessary.

Other platform-specific and diagnostic parameters are visible with
``modinfo mcepf``.  Change those parameters only with the adapter and
firmware documentation available.

Diagnostics and testing
-----------------------

Verify that the PCI device is bound to the driver and inspect the link with:

.. code-block:: shell

   lspci -nnk
   ethtool <netdev>
   ethtool -S <netdev>
   ethtool -t <netdev> online

For a basic packet-path test, configure an address on the MCEPF interface and
on a directly connected peer, then test both directions.  Jumbo frames can be
tested by setting the same MTU on both interfaces and using a DF ping or an
equivalent traffic generator.  VLAN, offload, Flow Director, and PTP tests
should be performed with the corresponding ``ethtool``, ``devlink``, and
``ptp`` tools.

SR-IOV, DCB, devlink firmware operations, and PTP depend on adapter firmware
and platform capabilities.  In particular, a virtual machine or nested PCI
environment may not expose SR-IOV even though the PF driver contains the
support code.

Limitations
-----------

XDP and AF_XDP are not part of the current MCEPF implementation.  They should
not be assumed to work based only on the presence of the normal TX/RX
offloads.

Report driver issues with the PCI ID, kernel version, firmware version,
``ethtool -i`` output, relevant ``dmesg`` messages, and the exact command that
reproduces the problem.
