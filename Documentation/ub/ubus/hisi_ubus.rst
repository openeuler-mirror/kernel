.. SPDX-License-Identifier: GPL-2.0

=====================
Hisilicon UBUS Driver
=====================

Hisilicon UBUS Driver (abbreviated as Hisi UBUS) is a UnifiedBus (UB)
specification management subsystem specifically implemented for Hisi chips. It
provides a subsystem operation interfaces implementation:

.. kernel-doc:: drivers/ub/ubus/ubus.h
   :functions: ub_manage_subsystem_ops

including probe/remove methods for the UB bus controller and UB RAS handler, as
well as the VDM delay work method and feature get method. Each specification
management subsystem has a unique vendor ID to identify the provider. This
vendor ID is set to the vendor field of ``ub_manage_subsystem_ops``
implementation. During UB bus controller probe, a ub_bus_controller_ops will be
set to the UB bus controller, message device and debug file system will be
initialized. During UB bus controller remove, ops will be unset, message device
will be removed and debug file system will be deinitialized.

During module init, hisi_ub_manage_subsystem_ops is registered to Ubus driver
via the ``register_ub_manage_subsystem_ops()`` method provided by Ubus driver::

	int register_ub_manage_subsystem_ops(const struct ub_manage_subsystem_ops *ops)

When module is being unloaded, Ubus driver's
``unregister_ub_manage_subsystem_ops()`` is called to unregister the subsystem
operation interfaces::

	void unregister_ub_manage_subsystem_ops(const struct ub_manage_subsystem_ops *ops)

Hisi UBUS Controller Driver
===========================
Hisi UBUS provides a ub bus controller operation interfaces implementation:

.. kernel-doc:: drivers/ub/ubus/ubus_controller.h
   :functions: ub_bus_controller_ops

including init/uninit methods for EID-UPI table, create/remove methods for UB
memory decoder, register/unregister methods for UB memory decoder interrupts,
init/uninit methods for decoder queue, create/free methods for decoder table,
decoder map/unmap methods, decoder event handling method, etc.

UB Message Core Driver
======================
Hisi UBUS implements a message device that provides a set of operations:

.. kernel-doc:: drivers/ub/ubus/msg.h
   :functions: message_ops

including synchronous message sending, synchronous enumeration message sending,
response message sending, vendor-defined message reception handling, etc. After
device creation, ``message_device_register()`` method of Ubus driver is called
to register the device to the Ubus driver message framework::

	int message_device_register(struct message_device *mdev)

This framework provides a unified interface for message transmission and
reception externally.

Hisi UBUS Local RAS Error Handler
=================================
Hisi UBUS provides a local RAS handling module to detect and process errors
reported on the UB bus. It offers error printing and registry dump, determines
whether recovery is needed based on error type and severity, and can reset ports
for port issues in cluster environment.

UB Vendor-Defined Messages Manager
==================================
Hisi UBUS defines several vendor-defined messages, implements messages'
transmission and processing. These private messages are mainly used for managing
the registration, release, and state control of physical and virtual devices.
