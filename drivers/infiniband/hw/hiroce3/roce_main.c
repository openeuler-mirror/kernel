// SPDX-License-Identifier: GPL-2.0
// Copyright(c) 2024 Huawei Technologies Co., Ltd

#include <net/ipv6.h>
#include <net/addrconf.h>
#include <net/bonding.h>
#include <rdma/ib_verbs.h>
#include <rdma/ib_addr.h>
#include <rdma/ib_user_verbs.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/errno.h>
#include <linux/inetdevice.h>
#include <linux/if_vlan.h>

#include "hinic3_crm.h"
#include "hinic3_hw.h"
#include "hinic3_hwdev.h"
#include "hinic3_srv_nic.h"
#include "hinic3_rdma.h"
#include "hinic3_bond.h"
#include "hinic3_pci_id_tbl.h"

#include "roce_event.h"
#include "roce_compat.h"
#include "roce_dfx.h"
#include "roce_mr.h"
#include "roce_main_extension.h"

#ifdef ROCE_NETLINK_EN
#include "roce_netlink.h"
#endif

#ifdef ROCE_BONDING_EN
#include "roce_bond.h"
#endif

#include "roce_pub_cmd.h"

MODULE_AUTHOR(HIROCE3_DRV_AUTHOR);
MODULE_DESCRIPTION(HIROCE3_DRV_DESC);
MODULE_VERSION(HIROCE3_DRV_VERSION);
MODULE_LICENSE("GPL");

static int g_loop_times = 50000;
module_param(g_loop_times, int, 0444); //lint !e806
MODULE_PARM_DESC(g_loop_times, "default: 50000");

static bool g_ppf_stateful_init;
static u8 g_vf_stateful_num;

#ifdef ROCE_BONDING_EN
static int g_want_bond_slave_cnt = ROCE_BOND_WANT_TWO_SLAVES;
module_param(g_want_bond_slave_cnt, int, 0444);
MODULE_PARM_DESC(g_want_bond_slave_cnt, "default: 2, 2: two slaves, 3: three slaves, 4: four slaves");

static int g_want_bond0_slave_bits = 0x3; /* 0011 */
module_param(g_want_bond0_slave_bits, int, 0444);
MODULE_PARM_DESC(g_want_bond0_slave_bits, "default: 0x3(PF0+PF1), 4bits");

static char *g_bond_name;
module_param(g_bond_name, charp, 0444);
MODULE_PARM_DESC(g_bond_name, "bond name for sdi");
#endif

struct roce3_func_info {
	u16 func_id;
	struct list_head node;
};

LIST_HEAD(g_roce_device_list);
static void roce3_remove_device_from_list(struct hinic3_lld_dev *lld_dev);
static int roce3_add_device_to_list(struct hinic3_lld_dev *lld_dev);
static void roce3_wait_probe(struct hinic3_lld_dev *lld_dev);
DECLARE_WAIT_QUEUE_HEAD(g_roce_probe_queue);

/*
 ****************************************************************************
 Prototype	: roce3_cq_completion
 Description  : RoCE's callback function for CQ's completion events on ARM CQs
 Input		: void *svc_hd
				u32 cqn
				void *cq_handler
 Output	   : None

  1.Date		 : 2015/5/27
	Modification : Created function

****************************************************************************
*/
void roce3_cq_completion(void *svc_hd, u32 cqn, void *cq_handler)
{
	struct roce3_cq *cq = NULL;
	struct ib_cq *ibcq = NULL;

	if (cq_handler == NULL) {
		pr_err("[ROCE, ERR] %s: Cq_handler is null\n", __func__);
		return;
	}

	cq = (struct roce3_cq *)cq_handler;

	++cq->arm_sn;
	cq->arm_flag = 0;

	ibcq = &cq->ibcq;

	ibcq->comp_handler(ibcq, ibcq->cq_context);
}

/*
 ****************************************************************************
 Prototype	: get_cpu_endian
 Description  : Acquire CPU's enianness
 Return Value : 0: little endian; 1: big endian

  1.Date		 : 2016/6/23
	Modification : Created function

****************************************************************************
*/
static int get_cpu_endian(void)
{
	int cpu_mode = 0;
	union {
		unsigned int i;
		unsigned char s[4];
	} c;
	c.i = 0x12345678;

	if (c.s[0] == 0x12) {
		pr_info("[ROCE] %s: CPU is be\n", __func__);
		cpu_mode = 1;
	} else {
		pr_info("[ROCE] %s: CPU is le\n", __func__);
		cpu_mode = 0;
	}

	return cpu_mode;
}

static int roce3_alloc_hw_resource(struct roce3_device *rdev)
{
	int ret;

	ret = roce3_rdma_init_rsvd_lkey(rdev->hwdev);
	if (ret != 0) {
		dev_err(rdev->hwdev_hdl,
			"[ROCE, ERR] %s: Failed to init rsvd lkey, func_id(%u)\n",
			__func__, rdev->glb_func_id);
		return ret;
	}

	ret = roce3_rdma_reset_gid_table(rdev->hwdev, 0);
	if (ret != 0) {
		dev_err(rdev->hwdev_hdl,
			"[ROCE, ERR]: Failed to reset gid_table, func_id(%u)\n",
			rdev->glb_func_id);
		goto err_gid_reset;
	}

	return 0;

err_gid_reset:
	roce3_rdma_free_rsvd_lkey(rdev->hwdev);

	return ret;
}

static void roce3_dealloc_hw_resource(struct roce3_device *rdev)
{
	roce3_rdma_free_rsvd_lkey(rdev->hwdev);
}

static struct roce3_device *roce3_rdev_alloc(struct hinic3_lld_dev *lld_dev, void **uld_dev,
	const struct rdma_service_cap *rdma_cap)
{
	struct roce3_device *rdev = NULL;

	rdev = (struct roce3_device *)roce3_rdev_alloc_ext();
	if (rdev == NULL) {
		pr_err("[ROCE, ERR] %s: Failed to alloc rdev\n", __func__);
		return NULL;
	}

	*uld_dev = (void *)rdev;
	rdev->lld_dev = lld_dev;
	rdev->hwdev = lld_dev->hwdev;
	rdev->pdev = lld_dev->pdev;
	mutex_init(&rdev->qp_cnt.cur_qps_mutex);

	rdev->hwdev_hdl = ((struct hinic3_hwdev *)(rdev->hwdev))->dev_hdl;
	memcpy((void *)&rdev->rdma_cap, (void *)rdma_cap, sizeof(*rdma_cap));

	rdev->ndev = hinic3_get_netdev_by_lld(rdev->lld_dev);
	if (rdev->ndev == NULL) {
		pr_err("[ROCE, ERR] %s roce add failed, netdev is null.\n", __func__);
		ib_dealloc_device(&rdev->ib_dev);
		return NULL;
	}

	roce3_rdev_set_ext(rdev);

	return rdev;
}

static int roce3_board_info_get(struct roce3_device *rdev)
{
	int ret = 0;

	ret = hinic3_get_board_info(rdev->hwdev, &rdev->board_info, HINIC3_CHANNEL_ROCE);
	if (ret != 0) {
		pr_err("[ROCE, ERR] %s: Failed to get board info\n", __func__);
		return ret;
	}

	pr_info("[ROCE] Get board info success, board_type:0x%x, port_num:0x%x, pf_num:0x%x, vf_total_num:0x%x, work_mode:0x%x, service_mode:0x%x, speed:0x%x.\n",
		rdev->board_info.board_type, rdev->board_info.port_num,
		rdev->board_info.pf_num, rdev->board_info.vf_total_num,
		rdev->board_info.work_mode, rdev->board_info.service_mode,
		rdev->board_info.port_speed);

#ifdef ROCE_BONDING_EN
	ret = roce3_bond_attach(rdev);
	if (ret != 0)
		return ret;
#endif

	ret = roce3_board_cfg_check(rdev);
	if (ret != 0) {
		pr_err("[ROCE, ERR] %s: Failed to check board cfg info\n", __func__);
		return ret;
	}

	return ret;
}

static int roce3_init_info_get(struct roce3_device *rdev)
{
	int ret = 0;

	ret = roce3_board_info_get(rdev);
	if (ret != 0) {
		pr_err("[ROCE, ERR] %s: Failed to get board info\n", __func__);
		return ret;
	}

	return ret;
}

static void roce3_fix_ibdev_name(struct roce3_device *rdev)
{
#ifdef ROCE_BONDING_EN
	if (roce3_bond_is_active(rdev)) {
		strscpy(rdev->ib_dev.name, "hrn3_bond_%d", sizeof("hrn3_bond_%d"));
		return;
	}
#endif
	{
		strscpy(rdev->ib_dev.name, (rdev->is_vroce ? "efi_%d" : "hrn3_%d"),
			(rdev->is_vroce ? sizeof("efi_%d") : sizeof("hrn3_%d")));
	}
}

static int roce3_register_template(struct roce3_device *rdev)
{
	struct tag_service_register_template svc_template;
	int ret;

	memset(&svc_template, 0, sizeof(svc_template));

	svc_template.service_type = SERVICE_T_ROCE;
	svc_template.scq_ctx_size = rdev->rdma_cap.cqc_entry_sz;
	svc_template.srq_ctx_size = rdev->rdma_cap.dev_rdma_cap.roce_own_cap.srqc_entry_sz;
	svc_template.service_handle = rdev;
	svc_template.embedded_cq_ceq_callback = NULL;
	svc_template.no_cq_ceq_callback = NULL;

	svc_template.shared_cq_ceq_callback = roce3_cq_completion;
	svc_template.aeq_level_callback = roce3_async_event_level;
	svc_template.aeq_callback = roce3_async_event;

	ret = cqm_service_register(rdev->hwdev, &svc_template);
	if (ret != 0) {
		dev_err(rdev->hwdev_hdl,
			"[ROCE, ERR] %s: Failed to register cqm_service, func(%u)\n",
			__func__, rdev->glb_func_id);
		return ret;
	}

	return 0;
}

int roce3_init_dev_file(struct roce3_device *rdev)
{
	int ret = 0;

	ret = roce3_init_sysfs(rdev);
	if (ret != 0) {
		dev_err(rdev->hwdev_hdl,
			"[ROCE, ERR] %s: Failed to init sysfs, func_id(%u) ret(%d)\n",
			__func__, rdev->glb_func_id, ret);
		return ret;
	}

	ret = roce3_init_cdev(rdev);
	if (ret != 0) {
		dev_err(rdev->hwdev_hdl,
			"[ROCE, ERR] %s: Failed to init cdev, func_id(%u)\n",
			__func__, rdev->glb_func_id);
		roce3_remove_sysfs(rdev);
	}

	return ret;
}

void roce3_remove_dev_file(struct roce3_device *rdev)
{
	roce3_remove_cdev(rdev);

	roce3_remove_sysfs(rdev);
}

/* Alloc CEQs and alloc CEQN */
static int roce3_alloc_ceq(struct roce3_device *rdev)
{
	int ret;

	ret = hinic3_alloc_ceqs(rdev->hwdev, SERVICE_T_ROCE, rdev->ib_dev.num_comp_vectors,
		rdev->ceqn, &rdev->ceq_num);
	if (ret < 0) {
		dev_err(rdev->hwdev_hdl,
			"[ROCE, ERR] %s: Failed to alloc cqes, num_comp_vectors(%d), func_id(%u)\n",
			__func__, rdev->ib_dev.num_comp_vectors, rdev->glb_func_id);
		return ret;
	}

	return 0;
}

static void roce3_free_ceq(struct roce3_device *rdev)
{
	int i;

	for (i = 0; i < rdev->ceq_num; ++i)
		hinic3_free_ceq(rdev->hwdev, SERVICE_T_ROCE, rdev->ceqn[i]);
}

static void roce3_init_hw_info(struct roce3_device *rdev)
{
	int ret;
	struct roce_group_id group_id = {0};

	rdev->hw_info.config_num_ports = (int)rdev->rdma_cap.num_ports;
	rdev->hw_info.ep_id = hinic3_ep_id(rdev->hwdev);
	rdev->hw_info.phy_port = 1;
	rdev->hw_info.is_vf = (hinic3_func_type(rdev->hwdev) == TYPE_VF);
	rdev->hw_info.cpu_endian = (u8)get_cpu_endian();

	if (!rdev->is_vroce)
		return;

	ret = roce3_get_group_id(rdev->glb_func_id, rdev->hwdev, &group_id);
	if (!!ret) {
		dev_info(rdev->hwdev_hdl, "[ROCE , INFO] Failed to get group id, ret(%d)", ret);
		return;
	}

	rdev->group_rc_cos = group_id.group_rc_cos;
	rdev->group_ud_cos = group_id.group_ud_cos;
	rdev->group_xrc_cos = group_id.group_xrc_cos;
	dev_info(rdev->hwdev_hdl, "[ROCE , INFO] group id rc(%u), ud(%u), xrc(%u)",
		group_id.group_rc_cos, group_id.group_ud_cos, group_id.group_xrc_cos);
}

static int roce3_init_dev_upper(struct roce3_device *rdev)
{
	int ret;

	/* Set function table to ENABLE */
	ret = roce3_set_func_tbl_func_state(rdev, ROCE_FUNC_ENABLE);
	if (ret != 0) {
		dev_err(rdev->hwdev_hdl,
			"[ROCE, ERR] %s: Failed to set func_tbl, func_id(%u)\n",
			__func__, rdev->glb_func_id);
		goto err_set_func_tbl;
	}
	return 0;

err_set_func_tbl:
	return ret;
}

static void roce3_deinit_dev_upper(struct roce3_device *rdev)
{
	(void)roce3_set_func_tbl_func_state(rdev, ROCE_FUNC_DISABLE);
}

static int roce3_init_dev_info(struct roce3_device *rdev)
{
	int ret;

	ret = roce3_set_func_tbl_cpu_endian(rdev->hwdev, rdev->hw_info.cpu_endian,
		rdev->glb_func_id);
	if (ret != 0) {
		dev_err(rdev->hwdev_hdl,
			"[ROCE, ERR]: Failed to set func_tbl cpu_endian, func_id(%u)\n",
			rdev->glb_func_id);
		goto err_init_endianness;
	}

	ret = roce3_init_dev_ext(rdev);
	if (ret != 0) {
		dev_err(rdev->hwdev_hdl,
			"[ROCE, ERR]: Failed to init extended service for func_id(%u)\n",
			rdev->glb_func_id);
		goto err_init_dev_ext;
	}

	ret = roce3_dfx_mem_alloc(rdev);
	if (ret != 0)
		goto err_init_dev_dfx;

	ret = roce3_init_dev_upper(rdev);
	if (ret != 0)
		goto err_init_dev_upper;

	return 0;

err_init_dev_upper:
	roce3_dfx_mem_free(rdev);
err_init_dev_dfx:
	roce3_remove_clean_res_ext(rdev);
err_init_dev_ext:
err_init_endianness:
	return ret;
}

static void roce3_deinit_dev_info(struct roce3_device *rdev)
{
	roce3_deinit_dev_upper(rdev);
	roce3_dfx_mem_free(rdev);
	roce3_remove_clean_res_ext(rdev);
}
#ifdef ROCE_BONDING_EN
static int roce3_ib_register_bond_device(struct roce3_device *rdev)
{
	return ib_register_device(&rdev->ib_dev, "hrn3_bond_%d", &rdev->pdev->dev);
}
#endif // ROCE_BONDING_EN

static int roce3_ib_register_unbond_device(struct roce3_device *rdev)
{
	return ib_register_device(&rdev->ib_dev, "hrn3_%d", &rdev->pdev->dev);
}

static int roce3_ib_register_device(struct roce3_device *rdev)
{
#ifdef ROCE_BONDING_EN
	if (roce3_bond_is_active(rdev))
		return roce3_ib_register_bond_device(rdev);
#endif
	return roce3_ib_register_unbond_device(rdev);
}

static int roce3_init_dev(struct roce3_device *rdev, char *uld_dev_name)
{
	int ret;

	ret = roce3_init_dev_info(rdev);
	if (ret != 0) {
		dev_err(rdev->hwdev_hdl,
			"[ROCE, ERR] %s: Failed to init dev info, func_id(%u)\n",
			__func__, rdev->glb_func_id);
		goto err_init_dev_info;
	}

	/* Clear gid table before register for a new IB device */
	ret = roce3_alloc_hw_resource(rdev);
	if (ret != 0) {
		dev_err(rdev->hwdev_hdl,
			"[ROCE, ERR] %s: Failed to alloc hw res, func_id(%u)\n",
			__func__, rdev->glb_func_id);
		goto err_alloc_hw_res;
	}

	roce3_wait_probe(rdev->lld_dev);

	ret = roce3_ib_register_device(rdev);
	if (ret != 0) {
		dev_err(rdev->hwdev_hdl,
			"[ROCE, ERR] %s: Failed to reg ibdev, func_id(%u)\n",
			__func__, rdev->glb_func_id);
		goto err_reg_dev;
	}

	roce3_remove_device_from_list(rdev->lld_dev);

	memcpy(uld_dev_name, rdev->ib_dev.name, ROCE_ULD_DEV_NAME_LEN);

	ret = roce3_register_netdev_event(rdev);
	if (ret != 0) {
		dev_err(rdev->hwdev_hdl,
			"[ROCE, ERR] %s: Failed to reg netdev, func_id(%u)\n",
			__func__, rdev->glb_func_id);
		goto err_memcpy_uld;
	}

	ret = roce3_init_dev_file(rdev);
	if (ret != 0) {
		dev_err(rdev->hwdev_hdl,
			"[ROCE, ERR] %s: Failed to init sysfs, func_id(%u)\n",
			__func__, rdev->glb_func_id);
		goto err_init_dev_file;
	}
	rdev->ib_active = true;
	dev_info(rdev->hwdev_hdl,
		"[ROCE] %s: RoCE add init all ok, func_id(%u), dev_name(%s)\n",
		__func__, rdev->glb_func_id, rdev->ib_dev.name);

	return 0;

err_init_dev_file:
	roce3_unregister_netdev_event(rdev);
err_memcpy_uld:
	ib_unregister_device(&rdev->ib_dev);
err_reg_dev:
	roce3_dealloc_hw_resource(rdev);
err_alloc_hw_res:
	roce3_deinit_dev_info(rdev);
err_init_dev_info:
	return ret;
}

static int roce3_add_rdev_init(struct roce3_device *rdev)
{
	int ret = 0;

	ret = roce3_init_info_get(rdev);
	if (ret != 0) {
		pr_err("[ROCE, ERR] %s: Failed to check\n", __func__);
		return ret;
	}

	rdev->gid_dev = kzalloc(rdev->rdma_cap.max_gid_per_port *
		sizeof(struct net_device *), GFP_KERNEL);
	if (rdev->gid_dev == NULL)
		return -ENOMEM;

	ret = roce3_rdma_init_resource(rdev->hwdev);
	if (ret != 0) {
		pr_err("[ROCE, ERR] %s: Failed to init rdma resources.\n", __func__);
		goto err_init_resource;
	}

	pr_info("[ROCE] %s: Initializing(%s)\n", __func__, pci_name(rdev->pdev));

	rdev->glb_func_id = hinic3_global_func_id(rdev->hwdev);

	rdev->is_vroce = false;

	roce3_init_hw_info(rdev);

	ret = roce3_init_cfg_info(rdev);
	if (ret != 0) {
		dev_err(rdev->hwdev_hdl, "[ROCE, ERR]%s: Failed to get roce cfg, func_id(%u)\n",
			__func__, rdev->glb_func_id);
		goto err_init_cfg;
	}

	return 0;

err_init_cfg:
	roce3_rdma_cleanup_resource(rdev->hwdev);

err_init_resource:
	if (rdev->gid_dev != NULL)
		kfree(rdev->gid_dev);
	return ret;
}

static void roce3_add_rdev_unit(struct roce3_device *rdev)
{
	roce3_rdma_cleanup_resource(rdev->hwdev);
	if (rdev->gid_dev != NULL)
		kfree(rdev->gid_dev);
}

static __be64 rdma_gen_node_guid(u8 *dev_mac)
{
	u8 guid[8];
	u8 mac_addr[6];
	__be64 node_guid = 0;

	if (dev_mac == NULL) {
		pr_err("[ROCE, ERR]%s: Dev_mac is null\n", __func__);
		return RDMA_INVALID_GUID;
	}

	memcpy((void *)&mac_addr[0], (void *)dev_mac, sizeof(mac_addr));
/*
 * 0 is mac & guid array idx
 * 1 is mac & guid array idx
 * 2 is mac & guid array idx
 * 3 is guid array idx
 * 4 is guid array idx
 * 5 is guid array idx, 3 is mac array idx
 * 6 is guid array idx, 4 is mac array idx
 * 7 is guid array idx, 5 is mac array idx
 */
	guid[0] = mac_addr[0] ^ DEV_ADDR_FIRST_BYTE_VAL_MASK;
	guid[1] = mac_addr[1];
	guid[2] = mac_addr[2];
	guid[3] = 0xff;
	guid[4] = 0xfe;
	guid[5] = mac_addr[3];
	guid[6] = mac_addr[4];
	guid[7] = mac_addr[5];

	/* node_guid is calculated by guid. */
	node_guid = ((u64)guid[0] << 56) | // 0 is guid array idx, 56 is guid offset
		((u64)guid[1] << 48) |		 // 1 is guid array idx, 48 is guid offset
		((u64)guid[2] << 40) |		 // 2 is guid array idx, 40 is guid offset
		((u64)guid[3] << 32) |		 // 3 is guid array idx, 32 is guid offset
		((u64)guid[4] << 24) |		 // 4 is guid array idx, 24 is guid offset
		((u64)guid[5] << 16) |		 // 5 is guid array idx, 16 is guid offset
		((u64)guid[6] << 8) |		  // 6 is guid array idx, 8 is guid offset
		(u64)guid[7];				  // 7 is guid array idx

	return (__be64)cpu_to_be64(node_guid);
}

static __be64 roce3_rdma_init_guid(void *hwdev, struct net_device *netdev)
{
	struct rdma_comp_priv *comp_priv = NULL;

	if ((hwdev == NULL) || (netdev == NULL)) {
		pr_err("[ROCE, ERR]%s: Hwdev or netdev is null\n", __func__);
		return ~0ULL;
	}

	comp_priv = get_rdma_comp_priv(hwdev);
	if (comp_priv == NULL) {
		pr_err("[ROCE, ERR]%s: Comp_priv is null\n", __func__);
		return ~0ULL;
	}

	comp_priv->rdma_comp_res.node_guid = rdma_gen_node_guid((u8 *)netdev->dev_addr);

	return comp_priv->rdma_comp_res.node_guid;
}

static const struct ib_device_ops dev_ops = {
	.owner = THIS_MODULE,
	.uverbs_abi_ver = ROCE_IB_UVERBS_ABI_VERSION,

	.create_qp = roce3_create_qp,
	.modify_qp = roce3_modify_qp,
	.query_qp = roce3_query_qp,
	.destroy_qp = roce3_destroy_qp,
	.post_send = roce3_post_send,
	.post_recv = roce3_post_recv,
	.create_cq	 = roce3_create_cq,
	.modify_cq	 = roce3_modify_cq,
	.resize_cq	 = roce3_resize_cq,
	.destroy_cq	= roce3_destroy_cq,
	.poll_cq	   = roce3_poll_cq,
	.req_notify_cq = roce3_arm_cq,
	.create_srq	= roce3_create_srq,
	.modify_srq	= roce3_modify_srq,
	.query_srq	 = roce3_query_srq,
	.destroy_srq   = roce3_destroy_srq,
	.post_srq_recv = roce3_post_srq_recv,
	.map_mr_sg	 = roce3_map_kernel_frmr_sg,
	.get_dma_mr	= roce3_get_dma_mr,
	.reg_user_mr   = roce3_reg_user_mr,
	.dereg_mr	  = roce3_dereg_mr,
	.alloc_mr	  = roce3_alloc_mr,
	.alloc_mw	  = roce3_alloc_mw,
	.dealloc_mw	= roce3_dealloc_mw,
	.query_device = roce3_query_device,
	.query_port = roce3_query_port,
	.get_link_layer = roce3_port_link_layer,
	.query_gid = roce3_query_gid,
	.add_gid = roce3_ib_add_gid,
	.del_gid = roce3_ib_del_gid,
	.query_pkey = roce3_query_pkey,
	.modify_device = roce3_modify_device,
	.modify_port = roce3_modify_port,
	.alloc_ucontext = roce3_alloc_ucontext,
	.dealloc_ucontext = roce3_dealloc_ucontext,
	.mmap = roce3_mmap,
	.alloc_pd = roce3_alloc_pd,
	.dealloc_pd = roce3_dealloc_pd,
	.create_ah = roce3_create_ah,
	.query_ah = roce3_query_ah,
	.destroy_ah = roce3_destroy_ah,
	.alloc_xrcd = roce3_alloc_xrcd,
	.dealloc_xrcd = roce3_dealloc_xrcd,
	.get_port_immutable = roce3_port_immutable,
	.get_netdev = roce3_ib_get_netdev,
	INIT_RDMA_OBJ_SIZE(ib_ah, roce3_ah, ibah),
	INIT_RDMA_OBJ_SIZE(ib_cq, roce3_cq, ibcq),
	INIT_RDMA_OBJ_SIZE(ib_pd, roce3_pd, ibpd),
	INIT_RDMA_OBJ_SIZE(ib_srq, roce3_srq, ibsrq),
	INIT_RDMA_OBJ_SIZE(ib_ucontext, roce3_ucontext, ibucontext),
	INIT_RDMA_OBJ_SIZE(ib_xrcd, roce3_xrcd, ibxrcd),
	INIT_RDMA_OBJ_SIZE(ib_mw, roce3_mw, ibmw),
};

static void roce3_add_init(struct roce3_device *rdev)
{
	struct ib_device *ib_dev = &rdev->ib_dev;

	ib_dev->local_dma_lkey = rdev->rdma_cap.reserved_lkey;
	ib_dev->phys_port_cnt = (u8)rdev->rdma_cap.num_ports;
	ib_dev->num_comp_vectors =
		(rdev->rdma_cap.num_comp_vectors <= MAX_CEQ_NEED) ?
		(int)rdev->rdma_cap.num_comp_vectors : MAX_CEQ_NEED;
	ib_dev->node_type = RDMA_NODE_IB_CA;
	ib_dev->node_guid = roce3_rdma_init_guid(rdev->hwdev, rdev->ndev);
	ib_dev->dma_device = &rdev->pdev->dev;
	ib_dev->dev.parent = ib_dev->dma_device;
	strscpy(ib_dev->node_desc, "hrn3", sizeof("hrn3"));

	rdev->ib_dev.uverbs_cmd_mask = ROCE_UVERBS_CMD_MASK;
	ib_set_device_ops(ib_dev, &dev_ops);
	roce3_init_dev_ext_handlers(rdev);
}

static void roce3_mod_param_parse(struct roce3_device *rdev)
{
	rdev->try_times = g_loop_times;

#ifdef ROCE_BONDING_EN
	if (g_bond_name != NULL) {
		rdev->want_bond_slave_cnt = SDI_BOND_SUPPORT_ROCE_FUNC_CNT;
		rdev->want_bond_slave_bits[0] = SDI_BOND_SUPPORT_ROCE_FUNC_BIT;
		rdev->want_bond_slave_bits[1] = 0;
		rdev->sdi_bond_name = g_bond_name;
		return;
	}
	rdev->want_bond_slave_cnt = g_want_bond_slave_cnt;
	rdev->want_bond_slave_bits[0] = g_want_bond0_slave_bits;
	rdev->want_bond_slave_bits[1] = 0;
	rdev->sdi_bond_name = NULL;
#endif

}

static void *roce3_get_ppf_lld_dev(struct roce3_device *rdev)
{
	struct hinic3_lld_dev *ppf_lld_dev = NULL;

	ppf_lld_dev = hinic3_get_ppf_lld_dev_unsafe(rdev->lld_dev);
	if (!ppf_lld_dev) {
		pr_err("[ROCE, ERR] %s: Failed to get ppf lld_dev\n", __func__);
		return ERR_PTR(-EINVAL);
	}

	return ppf_lld_dev->hwdev;
}

static int roce3_rdev_init(struct roce3_device *rdev)
{
	int ret;
	void *ppf_hwdev = NULL;

	if (!hinic3_is_vm_slave_host(rdev->hwdev)) {
		if ((hinic3_func_type(rdev->hwdev) == TYPE_VF) &&
			(g_ppf_stateful_init == false) && (g_vf_stateful_num == 0)) {
			ppf_hwdev = roce3_get_ppf_lld_dev(rdev);
			ret = hinic3_stateful_init(ppf_hwdev);
			if (ret != 0) {
				pr_err("[ROCE, ERR] %s: Failed to init ppf stateful resource\n",
					__func__);
				return ret;
			}
		}

		if (hinic3_func_type(rdev->hwdev) == TYPE_PPF)
			g_ppf_stateful_init = true;
	}

	// BM:When the device is PPF, stateful_init is performed only when g_vf_stateful_num is 0.
	if (hinic3_is_vm_slave_host(rdev->hwdev) ||
		(hinic3_func_type(rdev->hwdev) != TYPE_PPF) || !g_vf_stateful_num) {
		ret = hinic3_stateful_init(rdev->hwdev);
		if (ret != 0) {
			pr_err("[ROCE, ERR] %s: Failed to init stateful resource\n", __func__);
			goto err_stateful_init;
		}
	}

	ret = roce3_add_rdev_init(rdev);
	if (ret != 0)
		goto err_rdev_init;

	/*lint -e708*/
	spin_lock_init(&rdev->node_desc_lock);
	/*lint +e708*/

	mutex_init(&rdev->cap_mask_mutex);
	INIT_LIST_HEAD(&rdev->mac_vlan_list_head);
	mutex_init(&rdev->mac_vlan_mutex);
	/*lint -e708*/
	spin_lock_init(&rdev->reset_flow_resource_lock);
	/*lint +e708*/
	INIT_LIST_HEAD(&rdev->qp_list);
	roce3_mod_param_parse(rdev);

	roce3_fix_ibdev_name(rdev);

	if (hinic3_func_type(rdev->hwdev) == TYPE_VF)
		g_vf_stateful_num++;

	return 0;

err_rdev_init:
	hinic3_stateful_deinit(rdev->hwdev);
err_stateful_init:
	if ((g_vf_stateful_num == 0) && (g_ppf_stateful_init == false))
		hinic3_stateful_deinit(ppf_hwdev);
	return ret;
}

static void roce3_stateful_unit(struct roce3_device *rdev)
{
	void *ppf_hwdev = NULL;

	if (!hinic3_is_vm_slave_host(rdev->hwdev)) {
		if (hinic3_func_type(rdev->hwdev) == TYPE_VF) {
			hinic3_stateful_deinit(rdev->hwdev);
			g_vf_stateful_num--;
			// Delete the last VF when no PF is added
			if ((g_vf_stateful_num == 0) && (g_ppf_stateful_init == false)) {
				ppf_hwdev = roce3_get_ppf_lld_dev(rdev);
				hinic3_stateful_deinit(ppf_hwdev);
			}
		} else {
			if (g_vf_stateful_num == 0)
				hinic3_stateful_deinit(rdev->hwdev);
		}
	} else {
		hinic3_stateful_deinit(rdev->hwdev);
	}
}

#ifdef ROCE_NETLINK_EN
static void roce3_adapt_unit(struct roce3_device *rdev)
{
	struct hiroce_netlink_dev *adp_dev;
	int offset = 0;

	offset = get_instance_of_func_id(rdev->glb_func_id);
	if (offset >= MAX_FUNCTION_NUM) {
		pr_err("[ROCE, ERR] %s: offset is over size\n", __func__);
		return;
	}
	adp_dev = hiroce_get_adp();
	mutex_lock(&adp_dev->mutex_dev);
	adp_dev->used_dev_num--;

	if (adp_dev->used_dev_num <= 0 && adp_dev->netlink)
		kfree(adp_dev->netlink);
	mutex_unlock(&adp_dev->mutex_dev);
}
#endif

static void roce3_rdev_unit(struct roce3_device *rdev)
{
	/* FLR by MPU when hotplug, don't need deinit anymore */
	if (hinic3_func_type(rdev->hwdev) == TYPE_PPF)
		g_ppf_stateful_init = false;

	if (roce3_hca_is_present(rdev) != 0)
		roce3_stateful_unit(rdev);

#ifdef ROCE_NETLINK_EN
	roce3_netlink_unit();
	roce3_adapt_unit(rdev);
#endif
	roce3_add_rdev_unit(rdev);
}

#ifdef ROCE_NETLINK_EN
static int roce3_adapt_init(struct roce3_device *rdev)
{
	int offset = 0;
	struct hiroce_netlink_dev *adp_dev = NULL;

	offset = get_instance_of_func_id(rdev->glb_func_id);
	if (offset >= ROCE_MAX_FUNCTION) {
		dev_err(rdev->hwdev_hdl,
			"[ROCE, ERR] %s: Failed to get offset , func_id(%u)\n",
			__func__, rdev->glb_func_id);
		return -EINVAL;
	}

	adp_dev = hiroce_get_adp();
	mutex_lock(&adp_dev->mutex_dev);
	if (adp_dev->used_dev_num == 0 && adp_dev->netlink == NULL) {
		adp_dev->netlink = kzalloc(sizeof(struct netlink_devk_dev), GFP_KERNEL);
		if (adp_dev->netlink == NULL) {
			mutex_unlock(&adp_dev->mutex_dev);
			return -EINVAL;
		}
	}

	adp_dev->used_dev_num++;
	mutex_unlock(&adp_dev->mutex_dev);
	adp_dev->netlink->rdev[offset] = rdev;

	return 0;
}
#endif

static int roce3_add_do_init(struct roce3_device *rdev, char *uld_dev_name)
{
	int ret;

	ret = roce3_rdev_init(rdev);
	if (ret != 0)
		goto err_init_rdev;

	ret = roce3_register_template(rdev);
	if (ret != 0) {
		dev_err(rdev->hwdev_hdl,
			"[ROCE, ERR] %s: Failed to register cqm_service, func_id(%u) ret(%d)\n",
			__func__, rdev->glb_func_id, ret);
		goto err_cqm_register;
	}

	ret = hinic3_alloc_db_addr(rdev->hwdev, &rdev->kernel_db_map, &rdev->kernel_dwqe_map);
	if (ret != 0) {
		dev_err(rdev->hwdev_hdl,
			"[ROCE, ERR] %s: Failed to alloc db or dwqe, func_id(%u)\n",
			__func__, rdev->glb_func_id);
		goto err_alloc_db;
	}

	roce3_add_init(rdev);

	ret = roce3_alloc_ceq(rdev);
	if (ret < 0) {
		dev_err(rdev->hwdev_hdl, "[ROCE, ERR]: Failed to alloc ceqs, func_id(%u)\n",
		rdev->glb_func_id);
		goto err_alloc_ceq;
	}

	ret = roce3_init_dev(rdev, uld_dev_name);
	if (ret != 0)
		goto err_init_dev;

#ifdef ROCE_NETLINK_EN
	ret = roce3_adapt_init(rdev);
	if (ret != 0)
		goto err_init_adp;

	roce3_netlink_init();

	return 0;
err_init_adp:
	roce3_adapt_unit(rdev);
#else
	return 0;
#endif

err_init_dev:
	roce3_free_ceq(rdev);

err_alloc_ceq:
	hinic3_free_db_addr(rdev->hwdev, rdev->kernel_db_map, rdev->kernel_dwqe_map);

err_alloc_db:
	cqm_service_unregister(rdev->hwdev, SERVICE_T_ROCE);

err_cqm_register:
	roce3_rdev_unit(rdev);

err_init_rdev:
	roce3_remove_device_from_list(rdev->lld_dev);
	return ret;
}

static bool is_device_v100(const struct hinic3_lld_dev *lld_dev)
{
	struct pci_dev *pdev = lld_dev->pdev;
	unsigned short ssdid = pdev->subsystem_device;

	return (ssdid == HINIC3_DEV_SSID_2X25G) || (ssdid == HINIC3_DEV_SSID_4X25G) ||
		(ssdid == HINIC3_DEV_SSID_2X100G);
}

static int roce3_add_check(const struct hinic3_lld_dev *lld_dev)
{
	int ret = 0;
	u16 func_id;
	u8 enable_roce = false;
	bool is_slave_func = false;

	if (lld_dev == NULL) {
		pr_err("[ROCE, ERR] %s: Lld_dev is null\n", __func__);
		return (-EINVAL);
	}

	if (!is_device_v100(lld_dev)) {
		pr_err("[ROCE, ERR] %s: ssdid 0x%x is NOT standard Card\n",
			__func__, lld_dev->pdev->subsystem_device);
		return -ENXIO;
	}

	ret = hinic3_is_slave_func(lld_dev->hwdev, &is_slave_func);
	if (ret != 0)
		pr_err("[ROCE, ERR] %s: Failed to get slave_func.\n", __func__);
	if (!is_slave_func)
		return 0;

	func_id = hinic3_global_func_id(lld_dev->hwdev);
	ret = hinic3_get_func_vroce_enable(lld_dev->hwdev, func_id, &enable_roce);
	if (ret != 0) {
		pr_err("[ROCE, ERR] %s: Failed to get roce state.\n",  __func__);
		return ret;
	}
	if (!enable_roce) {
		pr_warn("[ROCE] %s: %s RoCE dev is not enable, func: %u\n", __func__,
			pci_name(lld_dev->pdev), func_id);
		return (-EPERM);
	}

	return 0;
}

static void roce3_remove_device_from_list(struct hinic3_lld_dev *lld_dev)
{
	struct roce3_func_info *info;
	struct roce3_func_info *tmp;

	if (list_empty(&g_roce_device_list))
		return;

	list_for_each_entry_safe(info, tmp, &g_roce_device_list, node) {
		if (info->func_id == hinic3_global_func_id(lld_dev->hwdev)) {
			list_del(&info->node);
			kfree(info);
		}
	}

	wake_up(&g_roce_probe_queue);
}

static int roce3_add_device_to_list(struct hinic3_lld_dev *lld_dev)
{
	struct roce3_func_info *info = kzalloc(
		sizeof(struct roce3_func_info), GFP_ATOMIC);

	if (info == NULL) {
		pr_err("[ROCE, ERR] %s: no memory\n", __func__);
		return -ENOMEM;
	}

	info->func_id = hinic3_global_func_id(lld_dev->hwdev);
	list_add_tail(&info->node, &g_roce_device_list);

	return 0;
}

static void roce3_wait_probe(struct hinic3_lld_dev *lld_dev)
{
	struct roce3_func_info *info = NULL;
	bool wait_flg = false;
	DECLARE_WAITQUEUE(wait_queue, current);

	add_wait_queue(&g_roce_probe_queue, &wait_queue);
	pr_info("[ROCE] %s func %u start to wait\n", __func__,
		hinic3_global_func_id(lld_dev->hwdev));

	do {
		might_sleep();
		info = list_first_entry(&g_roce_device_list, struct roce3_func_info, node);
		wait_flg = (info->func_id == hinic3_global_func_id(lld_dev->hwdev)) ? true : false;
		if (!wait_flg) {
			set_current_state(TASK_INTERRUPTIBLE);
			schedule();
			if (signal_pending(current)) { /* if alarmed by signal */
				goto out;
			}
		}
	} while (!wait_flg);

	set_current_state(TASK_RUNNING);
	remove_wait_queue(&g_roce_probe_queue, &wait_queue);

	pr_info("[ROCE] %s func %u wait finished\n",
		__func__, hinic3_global_func_id(lld_dev->hwdev));
	return;
out:
	pr_info("[ROCE] %s func %u wait fail\n", __func__, hinic3_global_func_id(lld_dev->hwdev));
	remove_wait_queue(&g_roce_probe_queue, &wait_queue);
	set_current_state(TASK_RUNNING);
}

/*
 ****************************************************************************
 Prototype	: roce3_add
 Description  : roce3_add
 Input		: struct hinic_lld_dev *lld_dev
				void **uld_dev
				char *uld_dev_name
 Output	   : None

  1.Date		 : 2015/5/27
	Modification : Created function

****************************************************************************
*/
static int roce3_add(struct hinic3_lld_dev *lld_dev, void **uld_dev, char *uld_dev_name)
{
	struct roce3_device *rdev = NULL;
	struct rdma_service_cap rdma_cap;
	int ret = 0;

	ret = roce3_add_check(lld_dev);
	if (ret != 0)
		goto err_check;

	pr_info("[ROCE] %s: Initializing pci(%s)\n", __func__, pci_name(lld_dev->pdev));

	/* return 0 if the rdev don't support ROCE, make sure it probe success */
	if (!hinic3_support_roce(lld_dev->hwdev, &rdma_cap)) {
		pr_err("[ROCE, ERR] %s: %s Not support RoCE, func: %u\n",
			__func__, pci_name(lld_dev->pdev), hinic3_global_func_id(lld_dev->hwdev));
		goto err_check;
	}

	/* make sure roce device probe in order */
	ret = roce3_add_device_to_list(lld_dev);
	if (ret != 0) {
		pr_err("[ROCE, ERR] %s: Failed to add device to list, ret: %d, func: %u\n",
			__func__, ret, hinic3_global_func_id(lld_dev->hwdev));
		return ret;
	}

	roce3_rdma_cap_ext(&rdma_cap);

	rdev = roce3_rdev_alloc(lld_dev, uld_dev, &rdma_cap);
	if (rdev == NULL) {
		roce3_remove_device_from_list(lld_dev);
		pr_err("[ROCE, ERR] %s: Failed to alloc rdev, func: %u\n",
			__func__, hinic3_global_func_id(lld_dev->hwdev));
		return -EINVAL;
	}

	ret = roce3_add_do_init(rdev, uld_dev_name);
	if (ret != 0)
		goto err_do_init;

	return 0;

err_do_init:
	ib_dealloc_device(&rdev->ib_dev);
err_check:
	*uld_dev = NULL;
	return ret;
}

static void roce3_do_remove(struct roce3_device *rdev, u16 glb_func_id, const char *dev_name)
{
	roce3_remove_dev_file(rdev);

	roce3_unregister_netdev_event(rdev);

	if (roce3_hca_is_present(rdev) == 0) {
		roce3_handle_hotplug_arm_cq(rdev);
		roce3_kernel_hotplug_event_trigger(rdev);
	}

	ib_unregister_device(&rdev->ib_dev);
	pr_info("[ROCE] %s: Unregister IB device ok, func_id(%u), name(%s), pci(%s)\n",
		__func__, glb_func_id, dev_name, pci_name(rdev->pdev));

	roce3_dealloc_hw_resource(rdev);

	roce3_deinit_dev_info(rdev);

#ifdef ROCE_BONDING_EN
	roce3_set_bond_ipsurx_en(true);
#endif

	roce3_clean_vlan_device_mac(rdev);
	roce3_clean_real_device_mac(rdev);

	roce3_free_ceq(rdev);

	hinic3_free_db_addr(rdev->hwdev, rdev->kernel_db_map, rdev->kernel_dwqe_map);

	cqm_service_unregister(rdev->hwdev, SERVICE_T_ROCE);

	roce3_del_func_res(rdev);
	pr_info("[ROCE] %s: Function level resource clear ok, func_id(%u), name(%s), pci(%s)\n",
		__func__, glb_func_id, dev_name, pci_name(rdev->pdev));

	roce3_do_cache_out(rdev->hwdev, ROCE_CL_TYPE_CQC_SRQC, rdev->glb_func_id);

	roce3_rdev_unit(rdev);
	pr_info("[ROCE] %s: RoCE rdev uninit ok, func_id(%u), name(%s)\n",
		__func__, glb_func_id, dev_name);

	ib_dealloc_device(&rdev->ib_dev);
}

static int roce3_remove_check(const struct hinic3_lld_dev *lld_dev, const void *uld_dev)
{
	if ((uld_dev == NULL) || (lld_dev == NULL)) {
		pr_err("[ROCE, ERR] %s: input param is null\n", __func__);
		return (-EINVAL);
	}

	return 0;
}

static void roce3_remove(struct hinic3_lld_dev *lld_dev, void *uld_dev)
{
	struct roce3_device *rdev = NULL;
	char *dev_name = NULL;
	u16 glb_func_id;
	int ret;

	ret = roce3_remove_check(lld_dev, uld_dev);
	if (ret != 0)
		return;

	rdev = (struct roce3_device *)uld_dev;
	rdev->ib_active = false;
	dev_name = rdev->ib_dev.name;
	glb_func_id = rdev->glb_func_id;

	if (!hinic3_support_roce(rdev->hwdev, NULL)) {
		pr_err("[ROCE, ERR] %s: Not support RoCE\n", __func__);
		return;
	}

	dev_info(rdev->hwdev_hdl,
		"[ROCE] %s: RoCE remove start, func_id(%u), name(%s), pci(%s)\n", __func__,
		rdev->glb_func_id, dev_name, pci_name(rdev->pdev));

	roce3_do_remove(rdev, glb_func_id, dev_name);

	pr_info("[ROCE] %s: RoCE remove end, func_id(%u), name(%s)\n",
		__func__, glb_func_id, dev_name);
}

static bool roce3_need_proc_link_event(void *hwdev)
{
	int ret = 0;
	u16 func_id;
	u8 roce_enable = false;
	bool is_slave_func = false;
	struct hinic3_hw_bond_infos hw_bond_infos = {0};

	ret = hinic3_is_slave_func(hwdev, &is_slave_func);
	if (ret != 0) {
		pr_err("[ROCE, ERR] %s: lld_dev is null\n", __func__);
		return true;
	}

	if (!is_slave_func)
		return true;

	func_id = hinic3_global_func_id(hwdev);
	ret = hinic3_get_func_vroce_enable(hwdev, func_id, &roce_enable);
	if (ret != 0) {
		pr_err("[ROCE, ERR] %s: Failed to get vroce info\n", __func__);
		return true;
	}
	if (!roce_enable)
		return true;

	hw_bond_infos.bond_id = HINIC_OVS_BOND_DEFAULT_ID;

	ret = hinic3_get_hw_bond_infos(hwdev, &hw_bond_infos, HINIC3_CHANNEL_COMM);
	if (ret != 0) {
		pr_err("[ROCE, ERR] Get chipf bond info failed (%d)\n", ret);
		return true;
	}

	if (!hw_bond_infos.valid)
		return true;

	return false;
}

static bool roce3_need_proc_bond_event(void *hwdev)
{
	return !roce3_need_proc_link_event(hwdev);
}

static int roce3_proc_bond_status_change(struct roce3_device *rdev,
	const struct hinic3_event_info *event)
{
	switch (event->type) {
	case EVENT_NIC_BOND_UP:
		if (!roce3_need_proc_bond_event(rdev->hwdev)) {
			dev_info(rdev->hwdev_hdl,
				"[ROCE, WARN] %s: RoCE don't need proc bond event\n",
				__func__);
			return -1;
		}
		if (test_and_set_bit(ROCE3_PORT_EVENT, &rdev->status) != 0)
			return -1;
		dev_info(rdev->hwdev_hdl,
			"[ROCE, WARN] %s: RoCE report NIC BOND_UP, func_id(%u)\n",
			__func__, rdev->glb_func_id);
		return IB_EVENT_PORT_ACTIVE;

	case EVENT_NIC_BOND_DOWN:
		if (!roce3_need_proc_bond_event(rdev->hwdev)) {
			dev_info(rdev->hwdev_hdl,
				"[ROCE, WARN] %s: RoCE don't need proc bond event\n",
				__func__);
			return -1;
		}

		if (test_and_clear_bit(ROCE3_PORT_EVENT, &rdev->status) == 0)
			return -1;
		dev_info(rdev->hwdev_hdl,
			"[ROCE, WARN] %s: RoCE report NIC BOND_DOWN, func_id(%u)\n",
			__func__, rdev->glb_func_id);
		return IB_EVENT_PORT_ERR;

	default:
		dev_err(rdev->hwdev_hdl,
			"[ROCE, ERR] %s: Nic event unsupported, func_id(%u), event(%hu)\n",
			__func__, rdev->glb_func_id, event->type);
		return -1;
	}
}

static int roce3_set_nic_event(struct roce3_device *rdev,
							   const struct hinic3_event_info *event)
{
	switch (event->type) {
	case EVENT_NIC_LINK_UP:
		if (test_and_set_bit(ROCE3_PORT_EVENT, &rdev->status) != 0)
			return -1;
		dev_info(rdev->hwdev_hdl,
			"[ROCE, WARN] %s: RoCE report NIC LINK_UP, func_id(%u)\n",
			__func__, rdev->glb_func_id);
		return IB_EVENT_PORT_ACTIVE;

	case EVENT_NIC_LINK_DOWN:
		if (!roce3_need_proc_link_event(rdev->hwdev)) {
			dev_info(rdev->hwdev_hdl,
			"[ROCE, WARN] %s: RoCE don't need proc link event\n", __func__);
			return -1;
		}

		if (test_and_clear_bit(ROCE3_PORT_EVENT, &rdev->status) == 0)
			return -1;
		dev_info(rdev->hwdev_hdl,
			"[ROCE, WARN] %s: RoCE report NIC LINK_DOWN, func_id(%u)\n",
			__func__, rdev->glb_func_id);
		return IB_EVENT_PORT_ERR;

	case EVENT_NIC_BOND_UP:
	case EVENT_NIC_BOND_DOWN:
		return roce3_proc_bond_status_change(rdev, event);

	case EVENT_NIC_DCB_STATE_CHANGE:
		dev_info(rdev->hwdev_hdl, "[ROCE]%s: DCB state change no longer requires RoCE involvement, func_id(%u)\n",
			__func__, rdev->glb_func_id);
		return -1;

	default:
		dev_err(rdev->hwdev_hdl,
			"[ROCE, ERR] %s: Nic event unsupported, func_id(%u), event(%hu)\n",
			__func__, rdev->glb_func_id, event->type);
		return -1;
	}
}

static int roce3_set_ib_event(struct roce3_device *rdev, const struct hinic3_event_info *event)
{
	switch (event->service) {
	case EVENT_SRV_NIC:
		return roce3_set_nic_event(rdev, event);

	case EVENT_SRV_COMM:
		return roce3_set_comm_event(rdev, event);

	default:
		dev_err(rdev->hwdev_hdl, "[ROCE, ERR] %s: func_id(%u) event from svc(%hu) is not supported, event(%hu)\n",
			__func__, rdev->glb_func_id, event->service, event->type);
		return -1;
	}
}

static void roce3_event(struct hinic3_lld_dev *lld_dev,
	void *uld_dev, struct hinic3_event_info *event)
{
	struct ib_event ibevent;
	struct roce3_device *rdev = NULL;
	int type;
	int ret = 0;

	roce3_lock_rdev();

	ret = roce3_get_rdev_by_uld(lld_dev, uld_dev, &rdev, event);
	if (ret != 0) {
		pr_err("[ROCE] %s: find rdev failed, ret(%d)\n", __func__, ret);
		goto err_unlock;
	}
#ifdef ROCE_BONDING_EN
	if (roce3_bond_is_active(rdev)) {
		roce3_handle_bonded_port_state_event(rdev);
		goto err_unlock;
	}
#endif
	type = roce3_set_ib_event(rdev, event);
	if (type == -1)
		goto err_unlock;

	ibevent.event = (enum ib_event_type)type;
	ibevent.device = &rdev->ib_dev;
	ibevent.element.port_num = ROCE_DEFAULT_PORT_NUM;

	if (rdev->ib_active)
		ib_dispatch_event(&ibevent);

err_unlock:
	roce3_unlock_rdev();
}

typedef int (*roce3_adm_func_t)(struct roce3_device *rdev, const void *buf_in,
	u32 in_size, void *buf_out, u32 *out_size);

/*lint -e26*/
static roce3_adm_func_t g_roce3_adm_funcs[COMMON_CMD_VM_COMPAT_TEST] = {
	[COMMON_CMD_GET_DRV_VERSION] = roce3_get_drv_version,

#ifdef __ROCE_DFX__
	[ROCE_CMD_GET_QPC_FROM_CACHE] = roce3_adm_dfx_query,
	[ROCE_CMD_GET_QPC_FROM_HOST] = roce3_adm_dfx_query,
	[ROCE_CMD_GET_CQC_FROM_CACHE] = roce3_adm_dfx_query,
	[ROCE_CMD_GET_CQC_FROM_HOST] = roce3_adm_dfx_query,
	[ROCE_CMD_GET_SRQC_FROM_CACHE] = roce3_adm_dfx_query,
	[ROCE_CMD_GET_SRQC_FROM_HOST] = roce3_adm_dfx_query,
	[ROCE_CMD_GET_MPT_FROM_CACHE] = roce3_adm_dfx_query,
	[ROCE_CMD_GET_MPT_FROM_HOST] = roce3_adm_dfx_query,
	[ROCE_CMD_GET_GID_FROM_CACHE] = roce3_adm_dfx_query,
	[ROCE_CMD_GET_QPC_CQC_PI_CI] = roce3_adm_dfx_query,
	[ROCE_CMD_GET_QP_COUNT] = roce3_adm_dfx_query,
	[ROCE_CMD_GET_DEV_ALGO] = roce3_adm_dfx_query,
#ifdef ROCE_PKT_CAP_EN
	[ROCE_CMD_START_CAP_PACKET] = roce3_adm_dfx_capture,
	[ROCE_CMD_STOP_CAP_PACKET] = roce3_adm_dfx_capture,
	[ROCE_CMD_QUERY_CAP_INFO] = roce3_adm_dfx_capture,
	[ROCE_CMD_ENABLE_QP_CAP_PACKET] = roce3_adm_dfx_capture,
	[ROCE_CMD_DISABLE_QP_CAP_PACKET] = roce3_adm_dfx_capture,
	[ROCE_CMD_QUERY_QP_CAP_INFO] = roce3_adm_dfx_capture,
#endif /* ROCE_PKT_CAP_EN */
#endif /* __ROCE_DFX__ */

	[ROCE_CMD_ENABLE_BW_CTRL] = roce3_adm_dfx_bw_ctrl,
	[ROCE_CMD_DISABLE_BW_CTRL] = roce3_adm_dfx_bw_ctrl,
	[ROCE_CMD_CHANGE_BW_CTRL_PARAM] = roce3_adm_dfx_bw_ctrl,
	[ROCE_CMD_QUERY_BW_CTRL_PARAM] = roce3_adm_dfx_bw_ctrl,
};
/*lint +e26*/

static int roce3_adm(void *uld_dev, u32 cmd, const void *buf_in, u32 in_size,
	void *buf_out, u32 *out_size)
{
	struct roce3_device *rdev = (struct roce3_device *)uld_dev;
	roce3_adm_func_t roce3_adm_func;

	if (uld_dev == NULL || buf_in == NULL || buf_out == NULL || out_size == NULL) {
		pr_err("[ROCE] %s: Input params is null\n", __func__);
		return -EINVAL;
	}

	if (!hinic3_support_roce(rdev->hwdev, NULL)) {
		pr_err("[ROCE, ERR] %s: %s Not support RoCE\n", __func__, pci_name(rdev->pdev));
		return -EINVAL;
	}

	rdev = (struct roce3_device *)uld_dev;
	if (roce3_hca_is_present(rdev) == 0) {
		dev_err(rdev->hwdev_hdl,
			"[ROCE] %s: HCA not present(return fail), func_id(%u)\n",
			__func__, rdev->glb_func_id);
		return -EPERM;
	}

	if (cmd >= COMMON_CMD_VM_COMPAT_TEST) {
		dev_err(rdev->hwdev_hdl, "Not support this type(%u)", cmd);
		return -EINVAL;
	}

	roce3_adm_func = g_roce3_adm_funcs[cmd];
	if (roce3_adm_func == NULL) {
		dev_err(rdev->hwdev_hdl, "Not support this type(%u)", cmd);
		return -EINVAL;
	}

	return roce3_adm_func(rdev, buf_in, in_size, buf_out, out_size);
}

struct hinic3_uld_info roce3_info = {
	.probe = roce3_add,
	.remove = roce3_remove,
	.suspend = NULL,
	.resume = NULL,
	.event = roce3_event,
	.ioctl = roce3_adm,
};

struct hinic3_uld_info *roce3_info_get(void)
{
	return &roce3_info;
}

/*
 ****************************************************************************
 Prototype	: roce3_service_init
 Description  :
 Input		: void
 Output	   : None
 Return Value :
 Calls		:
 Called By	:

  History		:
  1.Date		 : 2015/5/27
	Author	   :
	Modification : Created function

****************************************************************************
*/
static int __init roce3_service_init(void)
{
	int ret;

	INIT_LIST_HEAD(&g_roce_device_list);
	init_waitqueue_head(&g_roce_probe_queue);
	roce3_service_init_pre();
#ifdef ROCE_NETLINK_EN
	/* init mutex */
	mutex_init(&hiroce_get_adp()->mutex_dev);
#endif
	ret = hinic3_register_uld(SERVICE_T_ROCE, roce3_info_get());
	if (ret != 0) {
		pr_err("[ROCE, ERR] %s: Failed to register uld. ret(%d)\n", __func__, ret);
		return ret;
	}

	roce3_service_init_ext();
#ifdef ROCE_BONDING_EN
	ret = roce3_bond_init();
#endif
	pr_info("[ROCE] %s: Register roce service done, ret(%d).\n", __func__, ret);

	return ret;
}

/*
 ****************************************************************************
 Prototype	: roce3_service_exit
 Description  : roce service disable
 Input		: void
 Output	   : None
 Return Value :
 Calls		:
 Called By	:

  History		:
  1.Date		 : 2015/5/27
	Author	   :
	Modification : Created function

****************************************************************************
*/
static void __exit roce3_service_exit(void)
{
#ifdef ROCE_BONDING_EN
	roce3_bond_pre_exit();
#endif
	hinic3_unregister_uld(SERVICE_T_ROCE);

#ifdef ROCE_BONDING_EN
	pr_info("[ROCE] %s: Bond remove all.\n", __func__);
	roce3_bond_exit();
#endif

	pr_info("[ROCE] %s: Unregister roce service successful\n", __func__);
}

bool roce3_is_roceaa(u8 scence_id)
{
	if ((scence_id == SCENES_ID_STORAGE_ROCEAA_2x100) ||
		(scence_id == SCENES_ID_STORAGE_ROCEAA_4x25))
		return true;

	return false;
}

module_init(roce3_service_init);
module_exit(roce3_service_exit);
