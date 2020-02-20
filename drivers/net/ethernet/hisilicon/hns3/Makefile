# SPDX-License-Identifier: GPL-2.0+
#
# Makefile for the HISILICON network device drivers.
#

# Add security options
ccflags-y += -fstack-protector-strong
ccflags-y += -Wl,-z,relro,-z,now
ccflags-y += -Wl,-z,noexecstack
ccflags-y += -D_FORTIFY_SOURCE=2 -O2
ccflags-y += -fvisibility=hidden
ccflags-y += -Wformat=2 -Wfloat-equal
ccflags-y += -fsigned-char

ccflags-y += -DCONFIG_IT_VALIDATION
ccflags-y += -DCONFIG_HNS3_TEST

PWD = $(srctree)/drivers/net/ethernet/hisilicon/hns3
#add include path
ccflags-y += 	-I$(PWD) \
		-I$(PWD)/hns3pf \
		-I$(PWD)/hns-customer \
		-I$(PWD)/hns-customer/hns3pf \
		-I$(PWD)/hns3vf \
		-I$(PWD)/hns3_cae

#### compile hnae3.ko
obj-$(CONFIG_HNS3) += hnae3.o

#### compile hns3.ko
HNS3_OBJS	=	hns3_enet.o \
			hns3_ethtool.o \
			hns3_debugfs.o
HNS3_OBJS_IT	=	hns-customer/hns3_enet_it.o
obj-$(CONFIG_HNS3_ENET) += hns3.o
hns3-objs = $(HNS3_OBJS) $(HNS3_OBJS_IT)

hns3-$(CONFIG_HNS3_DCB) += hns3_dcbnl.o

#### compile hclge.ko
HCLGE_OBJ = 	hns3pf/hclge_main.o \
			hns3pf/hclge_cmd.o \
			hns3pf/hclge_mdio.o \
			hns3pf/hclge_debugfs.o \
			hns3pf/hclge_tm.o \
			hns3pf/hclge_mbx.o \
			hns3pf/hclge_err.o


HCLGE_OBJ_IT_MAIN	=	hns-customer/hns3pf/hclge_main_it.o
obj-$(CONFIG_HNS3_HCLGE) += hclge.o
hclge-objs := $(HCLGE_OBJ) $(HCLGE_OBJ_IT_MAIN)
hclge-$(CONFIG_HNS3_DCB) += hns3pf/hclge_dcb.o
#### compile hclgevf.ko
obj-$(CONFIG_HNS3_HCLGEVF) += hclgevf.o
hclgevf-objs := hns3vf/hclgevf_main.o hns3vf/hclgevf_cmd.o hns3vf/hclgevf_mbx.o

#### compile hns3_cae.ko
#add rally code
HNS3_CAE_OBJS_PRIM = 	hns3_cae/hns3_cae_init.o \
			hns3_cae/hns3_cae_lib.o \
			hns3_cae/hns3_cae_dcb.o \
			hns3_cae/hns3_cae_dcqcn.o \
			hns3_cae/hns3_cae_version.o \
			hns3_cae/hns3_cae_reset.o \
			hns3_cae/hns3_cae_pfc_storm.o \
			hns3_cae/hns3_cae_cmd.o
#add test code
HNS3_CAE_OBJS_EXT =	hns3_cae/hns3_cae_dfx.o \
			hns3_cae/hns3_cae_fd.o \
			hns3_cae/hns3_cae_hilink_param.o \
			hns3_cae/hns3_cae_checksum.o \
			hns3_cae/hns3_cae_irq.o \
			hns3_cae/hns3_cae_gro.o \
			hns3_cae/hns3_cae_mac.o \
			hns3_cae/hns3_cae_port.o \
			hns3_cae/hns3_cae_promisc.o \
			hns3_cae/hns3_cae_qinfo.o \
			hns3_cae/hns3_cae_qos.o \
			hns3_cae/hns3_cae_qres.o \
			hns3_cae/hns3_cae_rss.o \
			hns3_cae/hns3_cae_stat.o \
			hns3_cae/hns3_cae_tm.o \
			hns3_cae/hns3_cae_vlan.o \
			hns3_cae/hns3_cae_xsfp.o \
			hns3_cae/hns3_cae_led.o
obj-$(CONFIG_HNS3_CAE) += hns3_cae.o
hns3_cae-objs := $(HNS3_CAE_OBJS_PRIM) $(HNS3_CAE_OBJS_EXT)
