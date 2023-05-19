.. SPDX-License-Identifier: GPL-2.0

==========
SMC Sysctl
==========

/proc/sys/net/smc/* Variables
=============================

smcr_buf_type - INTEGER
        Controls which type of sndbufs and RMBs to use in later newly created
        SMC-R link group. Only for SMC-R.

        Default: 0 (physically contiguous sndbufs and RMBs)

        Possible values:

        - 0 - Use physically contiguous buffers
        - 1 - Use virtually contiguous buffers
        - 2 - Mixed use of the two types. Try physically contiguous buffers first.
          If not available, use virtually contiguous buffers then.
