// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024-2026 Mucse Corporation. */

#include <linux/mm.h>
#include <linux/dma-mapping.h>
#include <linux/slab.h>
#include <asm/cacheflush.h>
#include "mce.h"
#include "mce_dcbnl.h"
#include "mce_dcb.h"
#include "mce_lib.h"
#include "mce_fwchnl.h"
#include "ioctl.h"
#include "mce_base.h"
#include "mce_n20/mce_hw_n20.h"

static int mce_cdev_mmap_reg(struct mce_pf *pf, struct vm_area_struct *vma,
			     unsigned long offset)
{
	struct mce_hw *hw = &pf->hw;
	resource_size_t reg_phy;
	unsigned long reg_off;
	int reg_sz;
	long size;

	size = vma->vm_end - vma->vm_start;
	reg_off = offset & ((1UL << 28) - 1);

	switch ((offset >> 28) & 0x7) {
	case MCE_MMAP_REG_ETH:
		if (!hw->eth_bar_base)
			return -EINVAL;
		reg_phy = hw->bar_3th_phy;
		reg_sz = hw->bar_3th_sz;
		break;
	case MCE_MMAP_REG_RDMA:
		if (!hw->rdma_bar_base)
			return -EINVAL;
		reg_phy = hw->rdma_bar_phy;
		reg_sz = hw->bar_3th_sz - (1 * 1024 * 1024);
		break;
	case MCE_MMAP_REG_NPU:
		if (!hw->npu_bar_base)
			return -EINVAL;
		reg_phy = hw->bar_1th_phy;
		reg_sz = hw->bar_1th_sz;
		break;
	default:
		return -EINVAL;
	}

	if (reg_off + size > reg_sz)
		return -EINVAL;

	vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);

	if (io_remap_pfn_range(vma, vma->vm_start,
			       (reg_phy + reg_off) >> PAGE_SHIFT, size,
			       vma->vm_page_prot))
		return -EAGAIN;

	return 0;
}

static int mce_cdev_mmap(struct file *filp, struct vm_area_struct *vma)
{
	unsigned long offset = vma->vm_pgoff << PAGE_SHIFT;
	long size = vma->vm_end - vma->vm_start;
	struct mce_pf *pf = filp->private_data;
	int ret;

	logd(LOG_CDEV, "%s: pgoff:%lu offset:%lu sz:%lu\n", __func__,
	     vma->vm_pgoff, offset, size);

	mutex_lock(&pf->cdev_lock);
	if (test_bit(MCE_REMOVED, pf->state)) {
		ret = -ENODEV;
		goto unlock_cdev;
	}

	if (offset & MCE_CDEV_MMAP_FLAG) {
		ret = mce_cdev_mmap_reg(pf, vma, offset);
		goto unlock_cdev;
	}

	mutex_lock(&pf->cdev_dma_lock);
	if (!pf->cdev_dma_buf) {
		mutex_unlock(&pf->cdev_dma_lock);
		ret = -EINVAL;
		goto unlock_cdev;
	}
	/* check length */
	if ((offset + size > pf->cdev_dma_size)) {
		dev_err(&pf->pdev->dev, "invalid mmap offset:%lu,size=%lu\n",
			offset, size);
		mutex_unlock(&pf->cdev_dma_lock);
		ret = -EINVAL;
		goto unlock_cdev;
	}

	if (dma_mmap_coherent(&pf->pdev->dev, vma, pf->cdev_dma_buf + offset,
			      pf->cdev_dma_phy + offset, size)) {
		dev_err(&pf->pdev->dev, "Failed to mmap DMA memory\n");
		mutex_unlock(&pf->cdev_dma_lock);
		ret = -EAGAIN;
		goto unlock_cdev;
	}
	mutex_unlock(&pf->cdev_dma_lock);

	ret = 0;
unlock_cdev:
	mutex_unlock(&pf->cdev_lock);
	return ret;
}

static int mce_cdev_open(struct inode *inode, struct file *filp)
{
	struct mce_pf *pf = container_of(inode->i_cdev, struct mce_pf, cdev);
	struct filp_node *fnode;

	spin_lock(&pf->spinlock_cdev);
	if (pf->open_inhibit || test_bit(MCE_REMOVED, pf->state)) {
		spin_unlock(&pf->spinlock_cdev);
		return -ENODEV;
	}
	if (pf->open_exclusive) {
		spin_unlock(&pf->spinlock_cdev);
		return -EBUSY;
	}
	if (filp->f_flags & O_EXCL) {
		if (pf->open_count > 0) {
			spin_unlock(&pf->spinlock_cdev);
			return -EBUSY;
		}
		pf->open_exclusive = 1;
	}
	pf->open_count++;
	filp->private_data = pf;

	fnode = kmalloc(sizeof(*fnode), GFP_ATOMIC);
	if (!fnode) {
		pf->open_count--;
		if (filp->f_flags & O_EXCL)
			pf->open_exclusive = 0;
		filp->private_data = NULL;
		spin_unlock(&pf->spinlock_cdev);
		return -ENOMEM;
	}
	INIT_LIST_HEAD(&fnode->linkage);
	fnode->filp = filp;
	fnode->pid = get_task_pid(current, PIDTYPE_PID);
	list_add_tail(&fnode->linkage, &pf->filp_list);

	spin_unlock(&pf->spinlock_cdev);
	return 0;
}

static int mce_cdev_release(struct inode *inode, struct file *filp)
{
	struct mce_pf *pf = container_of(inode->i_cdev, struct mce_pf, cdev);
	struct filp_node *fnode;
	struct filp_node *tnode;

	spin_lock(&pf->spinlock_cdev);
	pf->open_count--;
	if (pf->open_exclusive)
		pf->open_exclusive = 0;

	list_for_each_entry_safe(fnode, tnode, &pf->filp_list, linkage) {
		if (fnode->filp == filp) {
			list_del(&fnode->linkage);
			put_pid(fnode->pid);
			kfree(fnode);
			break;
		}
	}

	spin_unlock(&pf->spinlock_cdev);
	wake_up(&pf->cdev_wait);
	return 0;
}

static long ioctl_get_devinfo(struct mce_pf *pf, void __user *target)
{
	struct net_device *netdev = pf->vsi[0]->netdev;
	struct mce_vsi *vsi = mce_get_main_vsi(pf);
	struct mce_ioctl_devinfo devinfo;
	struct mce_hw *hw = &pf->hw;

	memset(&devinfo, 0, sizeof(devinfo));
	devinfo.nr_pf = hw->pfvfnum.pf;

	(void)strscpy(devinfo.pci_name, pci_name(hw->pdev),
		      sizeof(devinfo.pci_name));
	devinfo.device_id = hw->device_id;
	devinfo.sub_vendor = hw->subsystem_vendor_id;
	devinfo.sub_device_id = hw->subsystem_device_id;
	devinfo.bd_number = pf->bd_number;

	hw->ops->update_pf_stat(hw);
	devinfo.linkup = hw->fw_stat.stat0.linkup;

	if (netdev) {
		(void)strscpy(devinfo.eth_name, netdev_name(netdev),
			      sizeof(devinfo.eth_name));
		memcpy(devinfo.mac_addr, vsi->port_info->addr, 6);
	} else {
		(void)strscpy(devinfo.eth_name, pf->name,
			      sizeof(devinfo.eth_name));
	}
	(void)strscpy(devinfo.adpt_name, pf->name,
		      sizeof(devinfo.adpt_name));

	if (copy_to_user(target, &devinfo, sizeof(devinfo)))
		return -EFAULT;
	return sizeof(devinfo);
}

static long ioctl_getdcbinfo(struct mce_pf *pf, void __user *target)
{
	struct iidc_core_dev_info *cdev_info = pf->cdev_infos;
	struct net_device *netdev = pf->vsi[0]->netdev;
	struct mce_vsi *vsi = mce_get_main_vsi(pf);
	struct mce_ioctl_dcbinfo *info;
	struct mce_dcb *dcb = pf->dcb;
	struct mce_pfc_cfg *pfccfg = &dcb->cur_pfccfg;
	struct mce_hw *hw = &pf->hw;

	info = kzalloc(sizeof(*info), GFP_KERNEL);
	if (!info)
		return -ENOMEM;
	/* copy info from pf */
	mce_dcbnl_getpfc(netdev, &info->pfc);
	if (test_bit(MCE_PFC_EN, dcb->flags))
		info->pfc_en = 1;
	mce_dcbnl_getets(netdev, &info->ets);
	if (test_bit(MCE_ETS_EN, dcb->flags))
		info->ets_en = 1;
	if (test_bit(MCE_DCB_EN, dcb->flags))
		info->dcb_en = 1;
	if (test_bit(MCE_DSCP_EN, dcb->flags))
		info->dscp_en = 1;
	if (test_bit(MCE_FLAG_PF_VLAN_Q_MAP, pf->flags))
		info->vlan_to_q_en = 1;
	/* add vlan to q */
	memcpy(info->prio2buf, pfccfg->rx_pri2buf, IEEE_8021QAZ_MAX_TCS);
	memcpy(info->rx_buffer, pfccfg->fifo_depth,
	       sizeof(int) * MCE_MAX_PRIORITY);
	memcpy(info->dscp_map, dcb->dscp_map, MCE_MAX_DSCP);
	memcpy(info->vlan_to_q, dcb->vlan_to_q, MCE_MAX_VLAN);
	info->speed_limit = hw->speed_limit;
	info->nic_prio = vsi->valid_prio;
	if (cdev_info)
		info->rdma_prio = cdev_info->valid_prio;
	else
		info->rdma_prio = 0;
	info->sp_timeout = hw->sp_timeout;

	if (copy_to_user(target, info, sizeof(struct mce_ioctl_dcbinfo))) {
		kfree(info);
		return -EFAULT;
	}
	kfree(info);
	return 0;
}

static int ioctl_setpfc(struct mce_pf *pf, void __user *pfc)
{
#ifdef CONFIG_DCB
	struct net_device __maybe_unused *netdev = pf->vsi[0]->netdev;
	const struct dcbnl_rtnl_ops *dcbnl_ops = netdev->dcbnl_ops;
	struct mce_dcb *dcb = pf->dcb;
	struct ieee_pfc pfc_new;
	u8 ret = 0;

	if (copy_from_user(&pfc_new, pfc, sizeof(struct ieee_pfc)))
		return -EFAULT;
	/* if mtu more than normal_mtu, no pfc */
	if (netdev->mtu > NORMAL_MTU) {
		netdev_err(netdev, "not support pfc mtu more than %d\n", NORMAL_MTU);
		return -EFAULT;
	}

	/* if not open dcb, open it */
	if (!test_bit(MCE_DCB_EN, dcb->flags)) {
		rtnl_lock();
		ret = dcbnl_ops->setstate(netdev, 1);
		rtnl_unlock();
	}

	if (ret == 255)
		return -EFAULT;
	if (!netif_running(netdev))
		return -EFAULT;
	/* temp close priv */
	if (test_bit(MCE_FLAG_DCB_TOOLS, dcb->flags))
		clear_bit(MCE_FLAG_DCB_TOOLS, dcb->flags);
	ret = dcbnl_ops->ieee_setpfc(netdev, &pfc_new);
	/* force setup tools control */
	set_bit(MCE_FLAG_DCB_TOOLS, dcb->flags);
	/* echo all vf, pfc changed */
	mce_reset_vf(netdev);
#endif
	return 0;
}

static int ioctl_setets(struct mce_pf *pf, void __user *ets)
{
#ifdef CONFIG_DCB
	struct net_device __maybe_unused *netdev = pf->vsi[0]->netdev;
	const struct dcbnl_rtnl_ops *dcbnl_ops = netdev->dcbnl_ops;
	struct mce_dcb *dcb = pf->dcb;
	struct ieee_ets ets_new;
	u8 ret = 0;

	if (copy_from_user(&ets_new, ets, sizeof(struct ieee_ets)))
		return -EFAULT;

	if (test_bit(MCE_FLAG_SRIOV_ENA, pf->flags))
		return -EFAULT;
	if (!netif_running(netdev))
		return -EFAULT;
	/* if not open dcb, open it */
	if (!test_bit(MCE_DCB_EN, dcb->flags)) {
		rtnl_lock();
		ret = dcbnl_ops->setstate(netdev, 1);
		rtnl_unlock();
	}

	if (ret == 255)
		return -EFAULT;

	/* temp close priv */
	if (test_bit(MCE_FLAG_DCB_TOOLS, dcb->flags))
		clear_bit(MCE_FLAG_DCB_TOOLS, dcb->flags);
	ret = dcbnl_ops->ieee_setets(netdev, &ets_new);
	/* force setup tools control */
	set_bit(MCE_FLAG_DCB_TOOLS, dcb->flags);
#endif
	return 0;
}

static int ioctl_setdcb(struct mce_pf *pf, void __user *state)
{
#ifdef CONFIG_DCB
	struct net_device __maybe_unused *netdev = pf->vsi[0]->netdev;
	const struct dcbnl_rtnl_ops *dcbnl_ops = netdev->dcbnl_ops;
	struct mce_dcb_state new_state;
	struct mce_dcb *dcb = pf->dcb;

	if (copy_from_user(&new_state, state, sizeof(struct mce_dcb_state)))
		return -EFAULT;
	/* if mrdma used, no support for off dcb */
	if (pf->m_status == MRDMA_INSMOD && !new_state.flags)
		return -EFAULT;

	if (new_state.flags) {
		if (!test_bit(MCE_DCB_EN, dcb->flags)) {
			rtnl_lock();
			(void)dcbnl_ops->setstate(netdev, 1);
			rtnl_unlock();
		}
	} else {
		if (test_bit(MCE_DCB_EN, dcb->flags)) {
			rtnl_lock();
			(void)dcbnl_ops->setstate(netdev, 0);
			rtnl_unlock();
		}
	}
#endif
	return 0;
}

static int ioctl_setdscp(struct mce_pf *pf, void __user *dscp)
{
#ifdef CONFIG_DCB
	struct net_device __maybe_unused *netdev = pf->vsi[0]->netdev;
	const struct dcbnl_rtnl_ops *dcbnl_ops = netdev->dcbnl_ops;
	struct mce_dscp_setup dscp_info;
	struct mce_dcb *dcb = pf->dcb;
	struct dcb_app app;

	if (copy_from_user(&dscp_info, dscp, sizeof(struct mce_dscp_setup)))
		return -EFAULT;

	if (!test_bit(MCE_FLAG_DSCP_ENA, pf->flags))
		return -EFAULT;

	if (!test_bit(MCE_DCB_EN, dcb->flags))
		return -EFAULT;

	app.selector = IEEE_8021QAZ_APP_SEL_DSCP;
	app.protocol = dscp_info.dscp;
	app.priority = dscp_info.prio;
	/* temp close priv */
	if (test_bit(MCE_FLAG_DCB_TOOLS, dcb->flags))
		clear_bit(MCE_FLAG_DCB_TOOLS, dcb->flags);
	if (dscp_info.flag)
		dcbnl_ops->ieee_setapp(netdev, &app);
	else
		dcbnl_ops->ieee_delapp(netdev, &app);
	set_bit(MCE_FLAG_DCB_TOOLS, dcb->flags);

	/* set to all vfs */
	mce_set_vf_dscp_prio(netdev, dscp_info.dscp, dcb->dscp_map[dscp_info.dscp]);
#endif
	return 0;
}

static int ioctl_setvlantoq(struct mce_pf *pf, void __user *vlan_info)
{
	struct mce_vlan_to_q_setup vlan_to_q_info;
	struct mce_dcb *dcb = pf->dcb;

	if (copy_from_user(&vlan_to_q_info, vlan_info, sizeof(struct mce_vlan_to_q_setup)))
		return -EFAULT;

	if (!test_bit(MCE_FLAG_PF_VLAN_Q_MAP, pf->flags))
		return -EFAULT;
	if (vlan_to_q_info.vlan >= MCE_MAX_VLAN)
		return -EINVAL;

	if (vlan_to_q_info.flag)
		dcb->vlan_to_q[vlan_to_q_info.vlan] = vlan_to_q_info.queue;
	else
		dcb->vlan_to_q[vlan_to_q_info.vlan] = 0xff;

	return 0;
}

static int ioctl_setrxbuffer(struct mce_pf *pf, void __user *qos)
{
	struct mce_dcb *dcb = pf->dcb;
	struct mce_pfc_cfg *pfccfg = &dcb->cur_pfccfg;
	struct mce_hw *hw = &pf->hw;
	struct rx_qos qos_info;
	int i, tmp = 0;

	if (copy_from_user(&qos_info, qos, sizeof(struct rx_qos)))
		return -EFAULT;
	if (!test_bit(MCE_DCB_EN, dcb->flags))
		return -EFAULT;

	for (i = 0; i < MCE_MAX_PRIORITY; i++) {
		pfccfg->fifo_head[i] = tmp;
		pfccfg->fifo_tail[i] = tmp + qos_info.rx_buffer[i] - 1;
		pfccfg->fifo_depth[i] = qos_info.rx_buffer[i];
		pfccfg->rx_pri2buf[i] = qos_info.rx_prio2buffer[i];
		tmp += qos_info.rx_buffer[i];
	}
	hw->ops->setup_rx_buffer(hw);

	return 0;
}

static int ioctl_setpfspeed(struct mce_pf *pf, void __user *speed)
{
	struct mce_pf_speed speed_info;
	struct mce_hw *hw = &pf->hw;
	int speed_now;

	if (copy_from_user(&speed_info, speed, sizeof(struct mce_pf_speed)))
		return -EFAULT;

	if (speed_info.flag)
		hw->speed_limit = speed_info.speed;
	else
		hw->speed_limit = 0;

	if (hw->fw_stat.stat0.linkup) {
		u32 val = 0;
		u32 tmp;

		/* setup pf limit again */
		speed_now = speed_unzip(hw->fw_stat.stat0.s_speed);
		if (hw->speed_limit)
			speed_now = min_t(int, speed_now, hw->speed_limit);

		/* update for dcb use */
		hw->qos.link_speed = speed_now;

		val |= F_PF_BW_EN;
		tmp = (((speed_now * 1000) >> 9)) * 500 / hw->axi_mhz;

		tmp = tmp * hw->qos.interal;
		val |= (tmp & (0x3fffffff));

		wr32(hw, N20_DMA_TC_TAL_BW, val);
	}

	return 0;
}

static int ioctl_setsptimeout(struct mce_pf *pf, void __user *sp_timeout)
{
	struct mce_hw *hw = &pf->hw;
	struct mce_sp_timeout sp_t;
	u32 val;

	if (copy_from_user(&sp_t, sp_timeout, sizeof(struct mce_sp_timeout)))
		return -EFAULT;
	hw->sp_timeout = sp_t.timeout;

	val = rd32(hw, N20_DMA_TC_TIMEOUT);
	MODIFY_BITFIELD(val, hw->sp_timeout, 16, 16);
	wr32(hw, N20_DMA_TC_TIMEOUT, val);

	return 0;
}

static int ioctl_setrdmapri(struct mce_pf *pf, void __user *rdma_pri)
{
	struct iidc_core_dev_info *cdev_info = pf->cdev_infos;
	struct mce_vsi *vsi = mce_get_main_vsi(pf);
	struct mce_rdma_pri r_pri;
	struct net_device *netdev;
	struct iidc_event *event;
	u16 valid;

	if (copy_from_user(&r_pri, rdma_pri, sizeof(struct mce_rdma_pri)))
		return -EFAULT;

	netdev = mce_get_main_net_dev(pf);
	valid = r_pri.rdma_pri;

	if (valid == 0xff || valid == 0x7f)
		return -EFAULT;
	if (!cdev_info)
		return -ENODEV;

	cdev_info->valid_prio = valid & 0xff;

	vsi->valid_prio = (~cdev_info->valid_prio);

	/* if mrdma insmod, should never use prio7 */
	if (pf->m_status == MRDMA_INSMOD)
		vsi->valid_prio &= 0x7f;

	mce_force_close_dcb(pf);
	event = kzalloc(sizeof(*event), GFP_KERNEL);

	set_bit(IIDC_EVENT_PRIO_CHNG, event->type);
	mce_send_event_to_auxs(pf, event);
	kfree(event);
	mce_recover_dcb(pf);
	mce_reset_vf(netdev);

	return 0;
}

static int ioctl_setpriv_en(struct mce_pf *pf, void __user *priv_en)
{
	struct mce_pri_en_setup priv_s;
	struct mce_hw *hw = &pf->hw;
	struct net_device *netdev;
	struct iidc_event *event;

	netdev = mce_get_main_net_dev(pf);

	if (copy_from_user(&priv_s, priv_en, sizeof(struct mce_pri_en_setup)))
		return -EFAULT;
	switch (priv_s.priv) {
	case DSCP_EN:
		if (priv_s.flag) {
			set_bit(MCE_DSCP_EN, pf->dcb->flags);
			mce_set_vf_dscp(netdev, true);
			set_bit(MCE_FLAG_DSCP_ENA, pf->flags);
		} else {
			clear_bit(MCE_DSCP_EN, pf->dcb->flags);
			mce_set_vf_dscp(netdev, false);
			clear_bit(MCE_FLAG_DSCP_ENA, pf->flags);
		}
		hw->ops->set_dscp(hw, pf->dcb);
		event = kzalloc(sizeof(*event), GFP_KERNEL);
		set_bit(IIDC_EVENT_PRIO_MODE_CHNG, event->type);
		mce_send_event_to_auxs(pf, event);
		kfree(event);

	break;
	}

	return 0;
}

static u8 __iomem *region_to_ptr(struct mce_pf *pf, enum REG_REGION region,
				 int offset)
{
	struct mce_hw *hw = &pf->hw;

	switch (region) {
	case REG_BAR0: {
		if (!hw->bar_1th)
			return NULL;
		return hw->bar_1th + offset;
	}
	case REG_BAR2: {
		if (!hw->bar_2th)
			return NULL;
		return hw->bar_2th + offset;
	}
	case REG_BAR4: {
		if (!hw->bar_3th)
			return NULL;
		return hw->bar_3th + offset;
	}
	case REG_RDMA: {
		if (hw->rdma_bar_base)
			return hw->rdma_bar_base + offset;
		return NULL;
	}
	case REG_RPU: {
		if (hw->npu_bar_base)
			return hw->npu_bar_base + offset;
		return NULL;
	}
	case REG_NIC: {
		if (hw->eth_bar_base)
			return hw->eth_bar_base + offset;
		return NULL;
	}
	default: {
		return NULL;
	}
	}
	return NULL;
}

static int ioctl_mbx_cmd(struct mce_pf *pf, void __user *uarg)
{
	struct mbx_resp *presp = NULL;
	struct mce_mbx_cmd req = {};
	struct mbx_resp resp = {};
	int  err;

	if (copy_from_user(&req, uarg, sizeof(req)))
		return -EFAULT;

	if (req.data_bytes > sizeof(req)) {
		dev_err(&pf->pdev->dev, "%s: %d > %d\n", __func__,
			req.data_bytes, (int)sizeof(req));
		return -EINVAL;
	}

	if (req.flags & 1) {
		/*has resp */
		presp = &resp;
	}

	err = mce_mbx_send_req(&pf->hw.fw_mbx, req.opcode, req.data,
			       req.data_bytes, presp, req.timeout_us);
	if (err)
		return -EIO;

	/*copy resp back to userspace*/
	if (presp) {
		memcpy(&req, &resp,
		       resp.cmd.arg_cnts * 4 + offsetof(struct mbx_resp, data));

		if (copy_to_user(uarg, &req, sizeof(req)))
			return -EFAULT;
	}

	return 0;
}

static int ioctl_dma_buf_op(struct mce_pf *pf, void __user *uarg)
{
	struct mce_dma_buf_rw dma_buf_op;

	if (copy_from_user(&dma_buf_op, uarg, sizeof(dma_buf_op)))
		return -EFAULT;

	mutex_lock(&pf->cdev_dma_lock);
	logd(LOG_CDEV, "%s: op:%d offset:%d sz:%d buf:%p, %p\n", __func__,
	     dma_buf_op.op, dma_buf_op.dma_offset, dma_buf_op.bytes,
	     dma_buf_op.user_buf, pf->cdev_dma_buf);

	if (!pf->cdev_dma_buf) {
		mutex_unlock(&pf->cdev_dma_lock);
		return -ENOMEM;
	}

	if (dma_buf_op.dma_offset >= pf->cdev_dma_size ||
	    (dma_buf_op.dma_offset + dma_buf_op.bytes) > pf->cdev_dma_size) {
		mutex_unlock(&pf->cdev_dma_lock);
		return -EINVAL;
	}
	if (dma_buf_op.op == DMA_BUF_WR) {
		if (copy_from_user(pf->cdev_dma_buf + dma_buf_op.dma_offset,
				   (void __user *)dma_buf_op.user_buf,
				   dma_buf_op.bytes)) {
			mutex_unlock(&pf->cdev_dma_lock);
			return -EFAULT;
		}
	} else if (dma_buf_op.op == DMA_BUF_RD) {
		if (copy_to_user((void __user *)dma_buf_op.user_buf,
				 pf->cdev_dma_buf +
					 dma_buf_op.dma_offset,
				 dma_buf_op.bytes)) {
			mutex_unlock(&pf->cdev_dma_lock);
			return -EFAULT;
		}
	} else {
		mutex_unlock(&pf->cdev_dma_lock);
		return -EINVAL;
	}
	mutex_unlock(&pf->cdev_dma_lock);

	return 0;
}

static int ioctl_dmaop(struct mce_pf *pf, void __user *uarg)
{
	struct mce_dma_op dmaop;

	if (copy_from_user(&dmaop, uarg, sizeof(dmaop)))
		return -EFAULT;

	mutex_lock(&pf->cdev_dma_lock);
	if (dmaop.op == DMA_OP_FREE) {
		if (pf->cdev_dma_buf) {
			dma_free_coherent(&pf->pdev->dev, pf->cdev_dma_size,
					  pf->cdev_dma_buf, pf->cdev_dma_phy);
			pf->cdev_dma_buf = NULL;
			pf->cdev_dma_size = 0;
		}
		mutex_unlock(&pf->cdev_dma_lock);
		return 0;
	}
	/* alloc dma */
	if (pf->cdev_dma_buf && dmaop.bytes > pf->cdev_dma_size) {
		/* requested dma > allocated before, free it */
		dma_free_coherent(&pf->pdev->dev, pf->cdev_dma_size,
				  pf->cdev_dma_buf, pf->cdev_dma_phy);
		pf->cdev_dma_buf = NULL;
		pf->cdev_dma_size = 0;
	}
	if (!pf->cdev_dma_buf) {
		pf->cdev_dma_size = dmaop.bytes;
		pf->cdev_dma_buf =
			dma_alloc_coherent(&pf->pdev->dev, dmaop.bytes,
					   &pf->cdev_dma_phy, GFP_KERNEL);
		if (!pf->cdev_dma_buf) {
			dev_err(&pf->pdev->dev,
				"%s: dma alloc memory failed:%d\n", __func__,
				dmaop.bytes);
			mutex_unlock(&pf->cdev_dma_lock);
			return -ENOMEM;
		}
	}

	dmaop.dma_phy_hi = (pf->cdev_dma_phy >> 32) & 0xffffffff;
	dmaop.dma_phy_lo = pf->cdev_dma_phy & 0xffffffff;
	dmaop.bytes = pf->cdev_dma_size;

	if (copy_to_user(uarg, &dmaop, sizeof(dmaop))) {
		mutex_unlock(&pf->cdev_dma_lock);
		return -EFAULT;
	}
	mutex_unlock(&pf->cdev_dma_lock);
	return 0;
}

static int ioctl_regop(struct mce_pf *pf, void __user *uarg)
{
	struct mce_hw *hw = &pf->hw;
	struct mce_reg_op regop;
	u8 __iomem *ptr;

	if (copy_from_user(&regop, uarg, sizeof(regop)))
		return -EFAULT;

	/* soc reg read/write */
	if (regop.region == REG_SOC) {
		if (regop.op == REG_OP_RD) {
			if (mce_soc_ioread32(hw, regop.offset, &regop.value))
				return -EIO;
			if (copy_to_user(uarg, &regop, sizeof(regop)))
				return -EFAULT;
			return 0;
		}
		if (mce_soc_iowrite32(hw, regop.offset, regop.value))
			return -EIO;
		return 0;
	}

	/* bar register */
	ptr = region_to_ptr(pf, regop.region, regop.offset);
	if (!ptr)
		return -EINVAL;

	if (regop.op == REG_OP_RD) {
		regop.value = raw_rd32(ptr);
		if (copy_to_user(uarg, &regop, sizeof(regop)))
			return -EFAULT;
		return 0;
	}
	raw_wr32(regop.value, ptr);

	return 0;
}

static long mce_cdev_ioctl(struct file *filp, unsigned int cmd,
			   unsigned long arg)
{
	struct mce_pf *pf = filp->private_data;
	struct net_device *netdev;
	int rv;

	mutex_lock(&pf->cdev_lock);
	if (test_bit(MCE_REMOVED, pf->state)) {
		rv = -ENODEV;
		goto unlock_cdev;
	}
	if (!pf->vsi || !pf->vsi[0] || !pf->vsi[0]->netdev) {
		rv = -ENODEV;
		goto unlock_cdev;
	}
	netdev = pf->vsi[0]->netdev;

	/* if net not open, return failed */
	if (!netif_running(netdev)) {
		netdev_err(netdev, "Should up port first\n");
		rv = -EOPNOTSUPP;
		goto unlock_cdev;
	}

	switch (cmd) {
	case MCE_IOCTL_GET_DEVINFO:
		rv = ioctl_get_devinfo(pf, (void __user *)arg);
		break;
	case MCE_IOCTL_GETDCBINFO:
		rv = ioctl_getdcbinfo(pf, (void __user *)arg);
		break;
	case MCE_IOCTL_SETPFC:
		rv = ioctl_setpfc(pf, (void __user *)arg);
		break;
	case MCE_IOCTL_SETETS:
		rv = ioctl_setets(pf, (void __user *)arg);
		break;
	case MCE_IOCTL_SETDCB_STATE:
		rv = ioctl_setdcb(pf, (void __user *)arg);
		break;
	case MCE_IOCTL_SETDSCP:
		rv = ioctl_setdscp(pf, (void __user *)arg);
		break;
	case MCE_IOCTL_SETVLAN_TO_Q:
		rv = ioctl_setvlantoq(pf, (void __user *)arg);
		break;
	case MCE_IOCTL_SETRX:
		rv = ioctl_setrxbuffer(pf, (void __user *)arg);
		break;
	case MCE_IOCTL_SETPF_SPEED:
		rv = ioctl_setpfspeed(pf, (void __user *)arg);
		break;
	case MCE_IOCTL_SETSP_TIMEOUT:
		rv = ioctl_setsptimeout(pf, (void __user *)arg);
		break;
	case MCE_IOCTL_SET_RDMA_PRI:
		rv = ioctl_setrdmapri(pf, (void __user *)arg);
		break;
	case MCE_IOCTL_SETPRIV_EN:
		rv = ioctl_setpriv_en(pf, (void __user *)arg);
		break;
	case MCE_IOCTL_MBX_CMD:
		rv = ioctl_mbx_cmd(pf, (void __user *)arg);
		break;
	case MCE_IOCTL_DMA_OP:
		rv = ioctl_dmaop(pf, (void __user *)arg);
		break;
	case MCE_IOCTL_DMA_BUF_RW:
		rv = ioctl_dma_buf_op(pf, (void __user *)arg);
		break;
	case MCE_IOCTL_REG_OP:
		rv = ioctl_regop(pf, (void __user *)arg);
		break;
	default:
		rv = -ENOTTY;
	}

unlock_cdev:
	mutex_unlock(&pf->cdev_lock);
	return rv;
}

const struct file_operations mce_fops = {
	.owner = THIS_MODULE,
	.open = mce_cdev_open,
	.release = mce_cdev_release,
	.mmap = mce_cdev_mmap,
	.unlocked_ioctl = mce_cdev_ioctl,
};
