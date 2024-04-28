EXPORT_SYMBOL := true

OFED_VERSION := OFED_MLNX_5_8
KBUILD_EXTRA_SYMBOLS += $(srctree)/drivers/net/ethernet/huawei/hinic3/Module.symvers

ccflags-y += -DHW_CONVERT_ENDIAN
ccflags-y += -DROCE_SERVICE
ccflags-y += -D__ROCE_DFX__
ccflags-y += -DROCE_CC_EN
ccflags-y += -D$(OFED_VERSION)
ccflags-y += -DROCE_COMPUTE
ccflags-y += -DROCE_BONDING_EN
ccflags-y += -DROCE_STANDARD
ccflags-y += -DOFED_MLNX_5_8

# Set CFLAGS from default file directories
ccflags-y += -I$(srctree)/include/linux
ccflags-y += -I$(srctree)/drivers/infiniband/hw/hiroce3
ccflags-y += -I$(srctree)/drivers/infiniband/hw/hiroce3/host/hmm
ccflags-y += -I$(srctree)/drivers/infiniband/hw/hiroce3/bond
ccflags-y += -I$(srctree)/drivers/infiniband/hw/hiroce3/cq
ccflags-y += -I$(srctree)/drivers/infiniband/hw/hiroce3/dfx
ccflags-y += -I$(srctree)/drivers/infiniband/hw/hiroce3/extension
ccflags-y += -I$(srctree)/drivers/infiniband/hw/hiroce3/include
ccflags-y += -I$(srctree)/drivers/infiniband/hw/hiroce3/include/nic
ccflags-y += -I$(srctree)/drivers/infiniband/hw/hiroce3/include/rdma
ccflags-y += -I$(srctree)/drivers/infiniband/hw/hiroce3/include/mag
ccflags-y += -I$(srctree)/drivers/infiniband/hw/hiroce3/mr
ccflags-y += -I$(srctree)/drivers/infiniband/hw/hiroce3/qp
ccflags-y += -I$(srctree)/drivers/infiniband/hw/hiroce3/rdma
ccflags-y += -I$(srctree)/drivers/infiniband/hw/hiroce3/srq
ccflags-y += -I$(srctree)/drivers/net/ethernet/huawei/hinic3
ccflags-y += -I$(srctree)/drivers/net/ethernet/huawei/hinic3/hw
ccflags-y += -I$(srctree)/drivers/net/ethernet/huawei/hinic3/bond
ccflags-y += -I$(srctree)/drivers/net/ethernet/huawei/hinic3/include
ccflags-y += -I$(srctree)/drivers/net/ethernet/huawei/hinic3/include/cfg_mgmt
ccflags-y += -I$(srctree)/drivers/net/ethernet/huawei/hinic3/include/mpu
ccflags-y += -I$(srctree)/drivers/net/ethernet/huawei/hinic3/include/bond
ccflags-y += -I$(srctree)/drivers/net/ethernet/huawei/hinic3/include/cqm

obj-$(CONFIG_HIROCE3) += hiroce3.o

hiroce3-y := cq/roce_cq_common.o \
            cq/roce_cq_cqe.o \
            cq/roce_cq_create.o \
            cq/roce_cq_ctrl.o \
            cq/roce_cq_destroy.o \
            extension/roce_event_extension.o \
            extension/roce_main_extension.o \
            extension/roce_mr_extension.o \
            extension/roce_netdev_extension.o \
            extension/roce_qp_extension.o \
            extension/roce_qp_post_send_extension.o \
            extension/roce_srq_extension.o \
            extension/roce_cdev_extension.o \
            roce_db.o \
            roce_main.o \
            roce_netlink.o \
            roce_event.o \
            roce_netdev.o \
            roce_mix.o \
            mr/roce_mr.o \
            roce_pd.o \
            qp/roce_qp_create.o \
            qp/roce_qp_destroy.o \
            qp/roce_qp_modify.o \
            qp/roce_qp_post_recv.o \
            qp/roce_qp_post_send.o \
            qp/roce_qp_query.o \
            roce_xrc.o \
            dfx/roce_dfx.o \
            dfx/roce_dfx_query.o \
            dfx/roce_dfx_cap.o \
            roce_cdev.o \
            roce_sysfs.o \
            roce_cmd.o \
            roce_cqm_cmd.o \
            bond/roce_bond_common.o \
            rdma/rdma_bitmap.o \
            rdma/rdma_comp.o \
            rdma/rdma_comp_res.o \
            rdma/rdma_comp_gid.o \
            rdma/rdma_comp_init.o \
            rdma/rdma_comp_pd.o \
            rdma/rdma_comp_mw_mr.o \
            srq/roce_srq_comm.o \
            srq/roce_srq_create.o \
            srq/roce_srq_ctrl.o \
            host/hmm/hmm_buddy.o \
            host/hmm/hmm_comp.o \
            host/hmm/hmm_comp_init.o \
            host/hmm/hmm_comp_mtt.o \
            host/hmm/hmm_comp_mw_mr.o \
            host/hmm/hmm_comp_res.o \
            host/hmm/hmm_em.o \
            host/hmm/hmm_mr.o \
            host/hmm/hmm_umem.o

