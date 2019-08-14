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
ccflags-y += -DCONFIG_EXT_TEST

PWD = $(srctree)/drivers/net/ethernet/hisilicon/hns3
#add include path
ccflags-y +=	-I$(PWD) \
				-I$(PWD)/hns3pf \
				-I$(PWD)/hns-customer \
				-I$(PWD)/hns-customer/hns3pf \
				-I$(PWD)/hns3vf \
				-I$(PWD)/hns3_cae

obj-$(CONFIG_HNS3_HCLGE) += hclge.o
hclge-objs =	hns3pf/hclge_main.o \
				hns3pf/hclge_cmd.o \
				hns3pf/hclge_mdio.o \
				hns3pf/hclge_debugfs.o \
				hns3pf/hclge_tm.o \
				hns3pf/hclge_mbx.o \
				hns3pf/hclge_err.o

hclge-objs +=	hns-customer/hns3pf/hclge_main_it.o \
				hns-customer/hns3pf/hclge_cmd_it.o \
				hns-customer/hns3pf/hclge_ext.o \
				hns-customer/hns3pf/hclge_test.o

hclge-$(CONFIG_HNS3_DCB) += hns3pf/hclge_dcb.o

#### compile hnae3.ko
obj-$(CONFIG_HNS3) += hnae3.o

obj-$(CONFIG_HNS3_ENET) += hns3.o
hns3-objs = hns3_enet.o hns3_ethtool.o hns3_debugfs.o
hns3-objs += hns-customer/hns3_enet_it.o hns-customer/hns3_ext.o

hns3-$(CONFIG_HNS3_DCB) += hns3_dcbnl.o

#### compile hclgevf.ko
obj-$(CONFIG_HNS3_HCLGEVF) += hclgevf.o
hclgevf-objs := hns3vf/hclgevf_main.o hns3vf/hclgevf_cmd.o hns3vf/hclgevf_mbx.o

#### compile hns3_cae.ko
#add rally code
HNS3_CAE_OBJS_PRIM =	hns3_cae/hns3_cae_init.o \
						hns3_cae/hns3_nictool.o \
						hns3_cae/hns3_priv_common_test.o \
						hns3_cae/hns3_priv_dcb.o \
						hns3_cae/hns3_priv_lamp.o \
						hns3_cae/hns3_priv_mactbl.o \
						hns3_cae/hns3_priv_m7_cmd.o
#add test code
HNS3_CAE_OBJS_EXT =		hns3_cae/hns3_priv_dfx.o \
						hns3_cae/hns3_priv_ext.o \
						hns3_cae/hns3_priv_fd.o \
						hns3_cae/hns3_priv_hilink_param.o \
						hns3_cae/hns3_priv_irq.o \
						hns3_cae/hns3_priv_mac.o \
						hns3_cae/hns3_priv_phy.o \
						hns3_cae/hns3_priv_pkt.o \
						hns3_cae/hns3_priv_port.o \
						hns3_cae/hns3_priv_promisc.o \
						hns3_cae/hns3_priv_qinfo.o \
						hns3_cae/hns3_priv_qos.o \
						hns3_cae/hns3_priv_qres.o \
						hns3_cae/hns3_priv_rss.o \
						hns3_cae/hns3_priv_stat.o \
						hns3_cae/hns3_priv_tm.o \
						hns3_cae/hns3_priv_vlan.o \
						hns3_cae/hns3_priv_xsfp.o
obj-$(CONFIG_HNS3_CAE) += hns3_cae.o
hns3_cae-objs := $(HNS3_CAE_OBJS_PRIM) $(HNS3_CAE_OBJS_EXT)
