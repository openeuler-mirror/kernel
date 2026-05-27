# SPDX-License-Identifier: GPL-2.0
#
# Makefile for the Linux kernel UB device drivers.
#
ccflags-y += -I$(src)

ubcore-objs := \
ubcore_workqueue.o \
ubcore_main.o \
ubcore_hash_table.o \
ubcore_tp.o \
ubcore_tp_table.o \
ubcore_cgroup.o \
net/ubcore_comm.o \
ubcore_cdev_file.o \
ubcore_connect_adapter.o \
ubcore_connect_bonding.o \
ubcore_log.o \
net/ubcore_cm.o \
ubcore_topo_info.o \
net/ubcore_session.o \
ubcore_jetty.o \
ubcore_device.o \
ubcore_uvs_cmd.o \
ubcore_cmd_tlv.o \
ubcore_genl.o \
ubcore_genl_admin.o \
ubcore_vtp.o \
ubcore_msg.o \
ubcore_netlink.o \
ubcore_dp.o \
ubcore_segment.o \
ubcm/ub_mad.o \
ubcm/ub_cm.o \
ubcm/ubmad_datapath.o \
ubcore_umem.o \
ubmgr/ubmgr.o \
ubmgr/ubmgr_ping.o \
ubmgr/ubmgr_topo.o \
ubcore_dmac.o \
ubcore_main_ue_eid.o

obj-$(CONFIG_UB_URMA) += ubcore.o
