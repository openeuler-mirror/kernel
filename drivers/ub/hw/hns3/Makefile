#
## Makefile for the Huawei UDMA Linux driver.
#
##

MODULE_NAME := hns3_udma
ccflags-y += -I$(srctree)/drivers/net/ethernet/hisilicon/hns3/ \
		-I$(srctree)/drivers/ub/urma/

$(MODULE_NAME)-objs := hns3_udma_hw.o hns3_udma_main.o hns3_udma_cmd.o \
			hns3_udma_hem.o hns3_udma_qp.o hns3_udma_eq.o \
			hns3_udma_db.o hns3_udma_jfc.o hns3_udma_jfr.o \
			hns3_udma_segment.o  hns3_udma_tp.o hns3_udma_jfs.o \
			hns3_udma_jetty.o hns3_udma_sysfs.o hns3_udma_dca.o \
			hns3_udma_dfx.o hns3_udma_eid.o hns3_udma_user_ctl.o \
			hns3_udma_debugfs.o

obj-$(CONFIG_UB_UDMA_HNS3) := hns3_udma.o
