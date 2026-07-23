subdir-ccflags-y += -I$(src)
subdir-ccflags-y += -I$(srctree)/include/linux/dinghai/

ccflags-y += -DZXDH_MSGQ

ifeq ($(CONFIG_DINGHAI_SEC),y)
ccflags-y += -DZXDH_SEC
endif

ifeq ($(CONFIG_DINGHAI_PTP),m)
ccflags-y += -DPTP_DRIVER_INTERFACE_EN
endif

ccflags-y += -DCONFIG_DINGHAI_EN_AUX
ccflags-y += -DCONFIG_ZXDH_SF
ccflags-y += -DDRIVER_VERSION_VAL=\"1.0-1\"
ccflags-y += -DCONFIG_DINGHAI_TSN

obj-$(CONFIG_DINGHAI_DH_CMD) += dinghai10e_cmd.o
dinghai10e_cmd-y := dh_cmd.o  cmd/msg_main.o cmd/msg_chan_lock.o cmd/msg_chan_test.o

obj-$(CONFIG_DINGHAI_PF) += dinghai10e.o
dinghai10e-y := events.o en_pf.o eq.o pci_irq.o en_pf/en_pf_irq.o en_pf/en_pf_eq.o devlink.o en_pf/en_pf_devlink.o en_pf/en_pf_events.o \
    en_pf/msg_func.o dh_procfs.o lag/lag.o lag/lag_procfs.o plcr.o sriov_sysfs.o health.o slib.o

dinghai10e-y += irq_affinity.o en_sf.o en_sf/en_sf_eq.o en_sf/en_sf_irq.o en_sf/en_sf_devlink.o

dinghai10e-y += en_aux.o eq.o pci_irq.o irq_affinity.o en_aux/queue.o en_aux/en_aux_cmd.o en_aux/en_aux_eq.o \
                 en_aux/en_aux_events.o en_ethtool/ethtool.o en_aux/en_aux_ioctl.o \
                 en_aux/dcbnl/en_dcbnl.o en_aux/dcbnl/en_dcbnl_api.o \
                 zxdh_tools/zxdh_tools_ioctl.o zxdh_tools/zxdh_tools_netlink.o \
                 en_aux/en_1588_pkt_proc.o en_aux/en_1588_pkt_proc_func.o en_aux/selq.o slib.o
dinghai10e-y += en_aux/drs_sec_dtb.o
dinghai10e-y += en_aux/priv_queue.o
dinghai10e-y += bonding/zxdh_lag.o bonding/rdma_ops.o

obj-$(CONFIG_DINGHAI_AUXILIARY) += dinghai10e_auxiliary.o
dinghai10e_auxiliary-y += en_auxiliary.o

obj-$(CONFIG_DINGHAI_PTP)  += dinghai10e_ptp.o
dinghai10e_ptp-y :=en_ptp/tod_driver.o en_ptp/tod_driver_stub.o en_ptp/zxdh_ptp.o

obj-$(CONFIG_DINGHAI_TSN_M)  += dinghai10e_tsn.o
dinghai10e_tsn-y :=en_tsn/zxdh_tsn.o en_tsn/zxdh_tsn_reg.o en_tsn/zxdh_tsn_ioctl.o

include $(src)/en_np/Makefile

