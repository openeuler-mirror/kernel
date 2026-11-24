# SPDX-License-Identifier: GPL-2.0
#
# NDS / XDS NVMe peer-to-peer I/O

# This is an openEuler kernel (5.10 / 6.6): select the matching compat flavor.
ccflags-y			+= -DP2P_COMPAT_OPENEULER

obj-$(CONFIG_NDS_P2P_DEV)	+= p2p_dev.o
p2p_dev-y			:= dev.o topo.o debugfs.o mem.o
