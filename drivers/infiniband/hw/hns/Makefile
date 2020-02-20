#
# Makefile for the Hisilicon RoCE drivers.
#

ccflags-y :=  -Idrivers/net/ethernet/hisilicon/hns3

PWD = $(srctree)/drivers/infiniband/hw/hns/
ccflags-y += -I$(PWD) \
	-I$(PWD)/roce-customer/
ifeq ($(CONFIG_INFINIBAND_HNS_DFX), m)
	ccflags-y += -DCONFIG_INFINIBAND_HNS_DFX
endif

obj-$(CONFIG_INFINIBAND_HNS) += hns-roce.o
hns-roce-objs := hns_roce_main.o hns_roce_cmd.o hns_roce_pd.o \
	hns_roce_ah.o hns_roce_hem.o hns_roce_mr.o hns_roce_qp.o \
	hns_roce_sysfs.o \
	hns_roce_cq.o hns_roce_alloc.o hns_roce_db.o hns_roce_srq.o hns_roce_restrack.o \
    roce-customer/rdfx_intf.o roce-customer/rdfx_entry.o
obj-$(CONFIG_INFINIBAND_HNS_HIP06) += hns-roce-hw-v1.o
hns-roce-hw-v1-objs := hns_roce_hw_v1.o
obj-$(CONFIG_INFINIBAND_HNS_HIP08) += hns-roce-hw-v2.o
hns-roce-hw-v2-objs := hns_roce_hw_v2.o hns_roce_hw_v2_dfx.o hns_roce_hw_sysfs_v2.o
obj-$(CONFIG_INFINIBAND_HNS_DFX) += hns-roce-cae.o
hns-roce-cae-$(CONFIG_INFINIBAND_HNS_DFX) := roce-customer/rdfx_sysfs.o roce-customer/rdfx_hw_v2.o roce-customer/rdfx_main.o
