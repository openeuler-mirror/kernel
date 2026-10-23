.. SPDX-License-Identifier: GPL-2.0

=====================================================
Linux Core Driver for Nebula-Matrix NBL NIC family
=====================================================

Overview
========

The nbl_core driver supports the Nebula-Matrix M18110, M18000 (Leonis) and
M18305 (Draco) series of network interface cards for the Data Center.

The devices support SR-IOV; this driver handles both Physical Function (PF)
and Virtual Function (VF).

The devices use MSI-X interrupt vectors for Tx/Rx queues and support
interrupt moderation.

Offload features include checksum offload, Receive-Side Scaling (RSS),
kernel TLS offload (with CONFIG_TLS_DEVICE), MACsec, and tc flower
offload. Firmware health (temperature, reboot traces) is reported through
devlink health reporters.

Supported PCI vendor ID/device IDs
==================================

Draco (M18305) family:

1f0f:3502 - M18305 PF
1f0f:3503 - M18305 LX PF
1f0f:3504 - M18305 BASE-T PF
1f0f:3505 - M18305 LX BASE-T PF
1f0f:3506 - M18305 OCP PF
1f0f:3507 - M18305 LX OCP PF
1f0f:3508 - M18305 BASE-T OCP PF
1f0f:3509 - M18305 LX BASE-T OCP PF
1f0f:350a - M18305 VF

Leonis internal test IDs:

1f0f:3401 - Leonis PF
1f0f:3402 - Leonis VF

Leonis M18110 family:

1f0f:3403 - M18110 PF
1f0f:3404 - M18110 LX PF
1f0f:3405 - M18110 BASE-T PF
1f0f:3406 - M18110 LX BASE-T PF
1f0f:3407 - M18110 OCP PF
1f0f:3408 - M18110 LX OCP PF
1f0f:3409 - M18110 BASE-T OCP PF
1f0f:340a - M18110 LX BASE-T OCP PF

Leonis M18000 family:

1f0f:340b - M18000 PF
1f0f:340c - M18000 LX PF
1f0f:340d - M18000 BASE-T PF
1f0f:340e - M18000 LX BASE-T PF
1f0f:340f - M18000 OCP PF
1f0f:3410 - M18000 LX OCP PF
1f0f:3411 - M18000 BASE-T OCP PF
1f0f:3412 - M18000 LX BASE-T OCP PF
1f0f:3413 - M18000 VF

ethtool support
================

Obtain basic information of the network card::

    ethtool -i enp130s0f0

Get network card ring parameters::

    ethtool -g enp130s0f0

Set the ring parameter::

    ethtool -G enp130s0f0 rx 1024 tx 1024

View statistics::

    ethtool -S enp130s0f0

View optical module information::

    ethtool -m enp130s0f0

Support
=======

For more information about Nebula-Matrix NICs, please visit the following
URL: https://www.nebula-matrix.com/

If an issue is identified with the released source code on a supported
kernel with a supported adapter, email the specific information related to
the issue to open@nebula-matrix.com.
