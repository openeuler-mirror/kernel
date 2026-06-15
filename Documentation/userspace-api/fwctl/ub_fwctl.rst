.. SPDX-License-Identifier: GPL-2.0

================
fwctl ub driver
================

Overview
========

The ub_fwctl tool is primarily designed to provide functions including querying
the configuration of UB common functions, the status and statistics of common modules,
and information at the Die level. Ub_fwctl is integrated with the open-source fwctl framework,
providing a custom user-mode command format for UB and supporting the common functionality of UB systems.

The implemented driver is ub_fwctl, which includes the user-mode command line
tool ubctl and kernel-mode driver ub_fwctl. After the ub_fwctl driver is loaded,
a file such as ubctl is displayed in the /dev directory of the OS through the
sysfs system. The user-mode program ubctl obtains file descriptors by calling
open (/dev/fwctl/fwctlNN), and then communicates with the driver by calling ioctl.

Function implementation scheme::

        1. Ub_fwctl registers itself with the fwctl framework.

        2. As an auxiliary device, ub_fwctl is connected to ubase through an
        auxiliary bus and uses pmu idev's CMDQ to call the software programming
        interface to read and write registers.

        3. Ubctl provides command-line commands for users to call. At startup,
        ubctl opens the ubctl device file, assembles the corresponding data
        structure based on input, and calls ioctl to enter kernel state. After
        receiving the ubctl command, ub_fwctl first checks the legality of the
        command, and then communicates with the software by calling the interface
        provided by ubase to access CMDQ. The software returns the result of accessing
        the register to ub_fwctl through CMDQ, and ub_fwctl then returns the
        data to user state. Finally, close the opened ubctl file.

ub_fwctl User API
==================

First step for the app is to issue the ioctl(UBCTL_IOCTL_CMDRPC). Each RPC
request includes the operation id, and in and out buffer lengths and pointers.
The driver verifies the operations, then checks the request scope against the
required scope of the operation.  The request is then put together with the
request data and sent through the software's message queue to the firmware, and the
results are returned to the caller.

The RPC endpoints, operations, and buffer contents are defined by the
particular firmware package in the device, which varies across the
available product configurations.  The details are available in the
specific product SDK documentation.
