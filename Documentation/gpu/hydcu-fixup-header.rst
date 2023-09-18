.. SPDX-License-Identifier: GPL-2.0-only

=========================
 drm/hygon/hydcu-fixup-header hydcu-fixup-header driver
=========================

The  drm/hygon/hydcu-fixup-header driver supports all HYGON DCUs.

General description
======================

The drm/hygon/hydcu-fixup-header driver adds flags NO_BUS_RESET to hydcu
device to disable vfio pci reset, as dcu is not support now.
