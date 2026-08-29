.. SPDX-License-Identifier: GPL-2.0

===========================================
UnifiedBus Bus Driver (UBUS Driver) Service
===========================================

The UnifiedBus (UB) specification describes RAS-related error handling and
notification-based hot-plug functionalities. The UBUS driver implements these
two types of functionalities as two independent services in software. This
article will separately introduce these two services.

UB Device Driver Error Service
==============================
The UB specification defines three categories of protocol errors: A, B, and C.
Among these, A and B category protocol errors are directly handled by the
UB device driver, and thus will not be further discussed in this document.
C category protocol errors are reported to the UBUS Driver via the APEI
mechanism. The UBUS Driver provides a set of mechanisms for handling C category
protocol errors, which work in conjunction with the UB device driver to
complete the error handling process.

The UBUS driver provides the ``struct ub_error_handlers`` structure, which
includes multiple callback functions related to error handling. The UB device
driver needs to implement these callback functions:

.. kernel-doc:: include/ub/ubus/ubus.h
   :functions: ub_error_handlers

Hot-Plug Service
================
The UB specification defines the hot-plug functionality for devices, which
requires coordination between software and hardware. The UBUS driver implements
the hot removal and hot insertion of external devices on a per-slot basis.
For detailed procedures, please refer to the UB specification document. The main
functional points implemented by the UBUS driver include:

  - Button event handling, completing the processing of hot-plug and
       hot-unplug button messages
  - Indicator control, switching between different indicator states based on the
       device status
  - Power control, performing power on/off operations for slots based on the
       device status
  - Providing a user-space sysfs interface to simulate button effects
       according to user commands
