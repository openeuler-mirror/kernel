// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#include <linux/dinghai/zxdh_compat.h>
#include <linux/netdevice.h>
#include <linux/scatterlist.h>
#include <linux/interrupt.h>
#include <linux/device.h>
#include <linux/kernel.h>
#include <linux/delay.h>
#include <linux/pci.h>
#include <net/xdp.h>
#include <linux/bpf.h>
#include <xen/xen.h>
#include "../en_aux.h"
#include "queue.h"
#include "en_1588_pkt_proc.h"
#include "../en_ethtool/ethtool.h"
#include "zxdh_tools/zxdh_tools_ioctl.h"

#ifdef ZXDH_MSGQ
#include "priv_queue.h"
#endif

#define RCV_1588_MSG_BIT 27

/* Amount of XDP headroom to prepend to packets for use by xdp_adjust_head */
#define ZXDH_XDP_HEADROOM 256

/* Separating two types of XDP xmit */
#define ZXDH_XDP_TX BIT(0)
#define ZXDH_XDP_REDIR BIT(1)
#define ZXDH_XDP_FLAG BIT(0)

static u32 features_table[] = { ZXDH_NET_F_MRG_RXBUF,	   ZXDH_NET_F_STATUS,
				ZXDH_NET_F_CTRL_VQ,	   ZXDH_NET_F_MQ,
				ZXDH_RING_F_INDIRECT_DESC, ZXDH_RING_F_EVENT_IDX,
				ZXDH_F_VERSION_1,	   ZXDH_F_RING_PACKED };

static bool is_xdp_frame(void *ptr)
{
	return (unsigned long)ptr & ZXDH_XDP_FLAG;
}

static void *xdp_to_ptr(struct xdp_frame *ptr)
{
	return (void *)((unsigned long)ptr | ZXDH_XDP_FLAG);
}

static struct xdp_frame *ptr_to_xdp(void *ptr)
{
	return (struct xdp_frame *)((unsigned long)ptr & ~ZXDH_XDP_FLAG);
}

static unsigned int zxdh_en_get_headroom(struct zxdh_en_device *en_dev)
{
	return en_dev->xdp_enabled ? ZXDH_XDP_HEADROOM : 0;
}

/* We copy the packet for XDP in the following cases:
 *
 * 1) Packet is scattered across multiple rx buffers.
 * 2) Headroom space is insufficient.
 *
 * This is inefficient but it's a temporary condition that
 * we hit right after XDP is enabled and until queue is refilled
 * with large buffers with sufficient headroom - so it should affect
 * at most queue size packets.
 * Afterwards, the conditions to enable
 * XDP should preclude the underlying device from sending packets
 * across multiple buffers (num_buf > 1), and we make sure buffers
 * have enough headroom.
 */
static struct page *xdp_linearize_page(struct receive_queue *rq, u16 *num_buf, struct page *p,
				       int offset, int page_off, unsigned int *len)
{
	struct page *page = alloc_page(GFP_ATOMIC);

	if (!page)
		return NULL;

	memcpy(page_address(page) + page_off, page_address(p) + offset, *len);
	page_off += *len;

	while (--*num_buf) {
		int tailroom = SKB_DATA_ALIGN(sizeof(struct skb_shared_info));
		unsigned int buflen;
		void *buf;
		int off;

		buf = zxdh_virtqueue_get_buf(rq->vq, &buflen);
		if (unlikely(!buf))
			goto err_buf;

		p = virt_to_head_page(buf);
		off = buf - page_address(p);

		/* guard against a misconfigured or uncooperative backend that
		 * is sending packet larger than the MTU.
		 */
		if ((page_off + buflen + tailroom) > PAGE_SIZE) {
			put_page(p);
			goto err_buf;
		}

		memcpy(page_address(page) + page_off, page_address(p) + off, buflen);
		page_off += buflen;
		put_page(p);
	}

	/* Headroom does not contribute to packet length */
	*len = page_off - ZXDH_XDP_HEADROOM;
	return page;
err_buf:
	__free_pages(page, 0);
	return NULL;
}

void zxdh_print_vring_info(struct virtqueue *vq, u32 desc_index, u32 desc_num)
{
	struct vring_virtqueue *vvq = to_vvq(vq);
	struct vring_packed_desc *desc = NULL;
	u32 i = 0;
	u32 j = 0;

	LOG_INFO("phy_index         : %d\n", vq->phy_index);
	LOG_INFO("num free          : %d\n", vq->num_free);
	LOG_INFO("vring address     : 0x%llx\n", (u64)&vvq->packed.vring);
	LOG_INFO("vring size        : %d\n", vvq->packed.vring.num);
	LOG_INFO("last_used_idx     : %d\n", vvq->last_used_idx);
	LOG_INFO("avail_wrap_counter: %d\n", vvq->packed.avail_wrap_counter);
	LOG_INFO("next_avail_idx    : %d\n", vvq->packed.next_avail_idx);
	LOG_INFO("free head         : %d\n", vvq->free_head);
	LOG_INFO("driver->flags     : 0x%x\n", vvq->packed.vring.driver->flags);
	LOG_INFO("driver->off_wrap  : %d\n", vvq->packed.vring.driver->off_wrap);
	LOG_INFO("device->flags     : 0x%x\n", vvq->packed.vring.device->flags);
	LOG_INFO("device->off_wrap  : %d\n", vvq->packed.vring.device->off_wrap);
	LOG_INFO("DESC[x]:\tDESC_ADDR\t[BUFFER_ADDR]\t\t[LEN]\t\t[ID]\t[FLAG]\n");

	for (i = 0; i < desc_num; i++) {
		j = (desc_index + i) % vvq->packed.vring.num;
		desc = &vvq->packed.vring.desc[j];
		LOG_INFO("DESC[%d] 0x%llx:\t0x%016llx\t0x%08x\t%8d\t0x%x\n", j, (u64)desc,
			 desc->addr, desc->len, desc->id, desc->flags);
	}
}

/* enable irq handlers */
void zxdh_vp_enable_cbs(struct net_device *netdev)
{
	struct zxdh_en_priv *en_priv = netdev_priv(netdev);
	struct zxdh_en_device *en_dev = &en_priv->edev;
	s32 i = 0;

	for (i = 0; i < en_dev->channels_num; i++)
		en_dev->ops->switch_vqs_channel(en_dev->parent, i, 1);
}

/* disable irq handlers */
void zxdh_vp_disable_cbs(struct net_device *netdev)
{
	struct zxdh_en_priv *en_priv = netdev_priv(netdev);
	struct zxdh_en_device *en_dev = &en_priv->edev;
	s32 i = 0;

	for (i = 0; i < en_dev->channels_num; i++)
		en_dev->ops->switch_vqs_channel(en_dev->parent, i, 0);
}

#define VP_RESET_MS_TIMEOUT_CNT (10000)
void zxdh_vp_reset(struct net_device *netdev)
{
	struct zxdh_en_priv *en_priv = netdev_priv(netdev);
	struct zxdh_en_device *en_dev = &en_priv->edev;
	u32 timeout_cnt = 0;

	/* 0 status means a reset. */
	en_dev->ops->set_status(en_dev->parent, 0);

	/* After writing 0 to device_status, the driver MUST wait for a read of
	 * device_status to return 0 before reinitializing the device.
	 * This will flush out the status write, and flush in device writes,
	 * including MSI-X interrupts, if any.
	 */
	LOG_INFO("get_status start\n");
	while (en_dev->ops->get_status(en_dev->parent) != 0) {
		usleep_range(1000, 2000);
		timeout_cnt++;
		if (timeout_cnt >= VP_RESET_MS_TIMEOUT_CNT) {
			LOG_ERR("vp reset time out!\n");
			break;
		}
	}
	LOG_INFO("get_status stop\n");
}

void zxdh_add_status(struct net_device *netdev, u32 status)
{
	struct zxdh_en_priv *en_priv = netdev_priv(netdev);
	struct zxdh_en_device *en_dev = &en_priv->edev;
	u8 dev_status = 0;

	might_sleep();

	dev_status = en_dev->ops->get_status(en_dev->parent);

	en_dev->ops->set_status(en_dev->parent, (dev_status | status));
}

bool zxdh_has_status(struct net_device *netdev, u32 sbit)
{
	struct zxdh_en_priv *en_priv = netdev_priv(netdev);
	struct zxdh_en_device *en_dev = &en_priv->edev;
	u8 dev_status = 0;

	dev_status = en_dev->ops->get_status(en_dev->parent);

	return (dev_status & sbit);
}

void zxdh_pf_features_init(struct net_device *netdev)
{
	struct zxdh_en_priv *en_priv = netdev_priv(netdev);
	struct zxdh_en_device *en_dev = &en_priv->edev;
	u32 i = 0;
	u64 features = 0;

	en_dev->device_feature = en_dev->ops->get_features(en_dev->parent);
	en_dev->device_feature |= BIT(34);
	en_dev->driver_feature = 0;

	for (i = 0; i < ARRAY_SIZE(features_table); i++) {
		features = features_table[i];
		en_dev->driver_feature |= (1ULL << features);
	}
	en_dev->guest_feature = en_dev->device_feature & 0xfffffff7dfffffff;
	LOG_INFO("device_feature: 0x%llx, guest_feature: 0x%llx\n", en_dev->device_feature,
		 en_dev->guest_feature);
	en_dev->ops->set_features(en_dev->parent, en_dev->guest_feature);
}

bool zxdh_has_feature(struct zxdh_en_device *en_dev, u32 fbit)
{
	return en_dev->guest_feature & BIT_ULL(fbit);
}

s32 vq2txq(struct virtqueue *vq)
{
	return (vq->index - 1) / 2;
}

s32 txq2vq(s32 txq)
{
	return txq * 2 + 1;
}
s32 vq2rxq(struct virtqueue *vq)
{
	return vq->index / 2;
}

s32 rxq2vq(s32 rxq)
{
	return rxq * 2;
}

inline void vqm_mb(bool weak_barriers)
{
	if (weak_barriers)
		/* 虚拟化环境使用较轻量级屏障 */
		virt_mb();
	else
		/* 完整内存屏障 */
		mb();
}

inline void vqm_rmb(bool weak_barriers)
{
	if (weak_barriers)
		/* 虚拟化环境使用较轻量级屏障 */
		virt_rmb();
	else
		dma_rmb();
}

inline void vqm_wmb(bool weak_barriers)
{
	if (weak_barriers)
		/* 虚拟化环境使用较轻量级屏障 */
		virt_wmb();
	else
		dma_wmb();
}

void zxdh_vring_del_virtqueue(struct virtqueue *_vq)
{
	struct zxdh_en_device *en_dev = _vq->en_dev;
	struct vring_virtqueue *vq = to_vvq(_vq);

	spin_lock(&en_dev->vqs_list_lock);
	list_del(&_vq->list);
	spin_unlock(&en_dev->vqs_list_lock);

	if (vq->we_own_ring) {
		vring_free_queue(vq->vq.en_dev, vq->packed.ring_size_in_bytes,
				 vq->packed.vring.desc, vq->packed.ring_dma_addr);

		vring_free_queue(vq->vq.en_dev, vq->packed.event_size_in_bytes,
				 vq->packed.vring.driver, vq->packed.driver_event_dma_addr);

		vring_free_queue(vq->vq.en_dev, vq->packed.event_size_in_bytes,
				 vq->packed.vring.device, vq->packed.device_event_dma_addr);

		kfree(vq->packed.desc_state);
		vq->packed.desc_state = NULL;
		kfree(vq->packed.desc_extra);
		vq->packed.desc_extra = NULL;
	}

	kfree(vq);
	vq = NULL;
}

void del_vq(struct zxdh_pci_vq_info *info)
{
	struct virtqueue *vq = info->vq;
	struct zxdh_en_device *en_dev = vq->en_dev;

	en_dev->ops->vq_unbind_channel(en_dev->parent, vq->phy_index);

	en_dev->ops->vp_modern_unmap_vq_notify(en_dev->parent, vq->priv);

	zxdh_vring_del_virtqueue(vq);
}

void vp_del_vq(struct virtqueue *vq)
{
	struct zxdh_en_device *en_dev = vq->en_dev;
	struct zxdh_pci_vq_info *info = en_dev->vqs[vq->index];
	unsigned long flags;

	spin_lock_irqsave(&en_dev->lock, flags);
	list_del(&info->node);
	spin_unlock_irqrestore(&en_dev->lock, flags);

	en_dev->vqs[vq->index] = NULL;
	del_vq(info);
	kfree(info);
}

void vp_detach_vqs(void *para)
{
	struct net_device *netdev = para;
	struct zxdh_en_priv *en_priv = netdev_priv(netdev);
	struct zxdh_en_device *en_dev = &en_priv->edev;
	struct virtqueue *vq;
	struct virtqueue *n;

	list_for_each_entry_safe(vq, n, &en_dev->vqs_list, list) {
		vp_del_vq(vq);
	}
}

void zxdh_vp_del_vqs(struct net_device *netdev)
{
	struct zxdh_en_priv *en_priv = netdev_priv(netdev);
	struct zxdh_en_device *en_dev = &en_priv->edev;

	vp_detach_vqs(netdev);

	kfree(en_dev->vqs);
	en_dev->vqs = NULL;
}

/**
 * zxdh_virtqueue_get_vring_size - return the size of the virtqueue's vring
 * @_vq: the struct virtqueue containing the vring of interest.
 *
 * Returns the size of the vring.  This is mainly used for boasting to
 * userspace.  Unlike other operations, this need not be serialized.
 */
u32 zxdh_virtqueue_get_vring_size(struct virtqueue *_vq)
{
	struct vring_virtqueue *vq = to_vvq(_vq);

	return vq->packed.vring.num;
}

dma_addr_t zxdh_virtqueue_get_desc_addr(struct virtqueue *_vq)
{
	struct vring_virtqueue *vq = to_vvq(_vq);

	if (WARN_ON(!vq->we_own_ring))
		return 0;

	return vq->packed.ring_dma_addr;
}

dma_addr_t zxdh_virtqueue_get_avail_addr(struct virtqueue *_vq)
{
	struct vring_virtqueue *vq = to_vvq(_vq);

	if (WARN_ON(!vq->we_own_ring))
		return 0;

	return vq->packed.driver_event_dma_addr;
}

dma_addr_t zxdh_virtqueue_get_used_addr(struct virtqueue *_vq)
{
	struct vring_virtqueue *vq = to_vvq(_vq);

	if (WARN_ON(!vq->we_own_ring))
		return 0;

	return vq->packed.device_event_dma_addr;
}

bool vqm_has_dma_quirk(struct zxdh_en_device *en_dev)
{
	/* Note the reverse polarity of the quirk feature (compared to most
	 * other features), this is for compatibility with legacy systems.
	 */
	return !zxdh_has_feature(en_dev, ZXDH_F_ACCESS_PLATFORM);
}

bool vring_use_dma_api(struct zxdh_en_device *en_dev)
{
	if (!vqm_has_dma_quirk(en_dev))
		return true;

	/* Otherwise, we are left to guess. */
	/* In theory, it's possible to have a buggy QEMU-supposed
	 * emulated Q35 IOMMU and Xen enabled at the same time.  On
	 * such a configuration, zxdh has never worked and will
	 * not work without an even larger kludge.  Instead, enable
	 * the DMA API if we're a Xen guest, which at least allows
	 * all of the sensible Xen configurations to work correctly.
	 */
	if (xen_domain())
		return true;

	return false;
}

void vring_free_queue(struct zxdh_en_device *en_dev, size_t size, void *queue,
		      dma_addr_t dma_handle)
{
	if (vring_use_dma_api(en_dev))
		dma_free_coherent(en_dev->dmadev, size, queue, dma_handle);
	else
		free_pages_exact(queue, PAGE_ALIGN(size));
}

void *vring_alloc_queue(struct zxdh_en_device *en_dev, size_t size, dma_addr_t *dma_handle,
			gfp_t flag)
{
	if (vring_use_dma_api(en_dev))
		return dma_alloc_coherent(en_dev->dmadev, size, dma_handle, flag);

	void *queue = alloc_pages_exact(PAGE_ALIGN(size), flag);

	if (queue) {
		phys_addr_t phys_addr = virt_to_phys(queue);
		*dma_handle = (dma_addr_t)phys_addr;

		/* Sanity check: make sure we dind't truncate
		 * the address.  The only arches I can find that
		 * have 64-bit phys_addr_t but 32-bit dma_addr_t
		 * are certain non-highmem MIPS and x86
		 * configurations, but these configurations
		 * should never allocate physical pages above 32
		 * bits, so this is fine.  Just in case, throw a
		 * warning and abort if we end up with an
		 * unrepresentable address.
		 */
		if (WARN_ON_ONCE(*dma_handle != phys_addr)) {
			free_pages_exact(queue, PAGE_ALIGN(size));
			return NULL;
		}
	}
	return queue;
}

struct vring_desc_extra *vring_alloc_desc_extra(struct vring_virtqueue *vq, u32 num)
{
	struct vring_desc_extra *desc_extra = NULL;
	u32 i = 0;

	desc_extra = kmalloc_array(num, sizeof(struct vring_desc_extra), GFP_KERNEL);
	if (unlikely(!desc_extra)) {
		LOG_ERR("desc_extra kmalloc_array failed\n");
		return NULL;
	}

	memset(desc_extra, 0, num * sizeof(struct vring_desc_extra));

	for (i = 0; i < num - 1; i++)
		desc_extra[i].next = i + 1;

	return desc_extra;
}

struct virtqueue *vring_create_virtqueue_packed(u32 index, u32 num, u32 vring_align,
						struct net_device *netdev, bool weak_barriers,
						bool may_reduce_num, bool context,
						bool (*notify)(struct virtqueue *),
						void (*callback)(struct virtqueue *),
						const char *name)
{
	struct zxdh_en_priv *en_priv = netdev_priv(netdev);
	struct zxdh_en_device *en_dev = &en_priv->edev;
	struct vring_virtqueue *vq = NULL;
	struct vring_packed_desc *ring = NULL;
	struct vring_packed_desc_event *driver = NULL;
	struct vring_packed_desc_event *device = NULL;
	dma_addr_t ring_dma_addr;
	dma_addr_t driver_event_dma_addr;
	dma_addr_t device_event_dma_addr;
	size_t ring_size_in_bytes;
	size_t event_size_in_bytes;

	ring_size_in_bytes = ZXDH_PF_MAX_DESC_NUM(en_dev) * sizeof(struct vring_packed_desc) +
			     ZXDH_DESC_EXTRA_SIZE;
	ring = vring_alloc_queue(en_dev, ring_size_in_bytes, &ring_dma_addr,
				 GFP_KERNEL | __GFP_NOWARN | __GFP_ZERO);
	if (unlikely(!ring)) {
		LOG_ERR("ring vring_alloc_queue failed\n");
		goto err_ring;
	}

	event_size_in_bytes = sizeof(struct vring_packed_desc_event);

	driver = vring_alloc_queue(en_dev, event_size_in_bytes, &driver_event_dma_addr,
				   GFP_KERNEL | __GFP_NOWARN | __GFP_ZERO);
	if (unlikely(!driver)) {
		LOG_ERR("driver vring_alloc_queue failed\n");
		goto err_driver;
	}

	device = vring_alloc_queue(en_dev, event_size_in_bytes, &device_event_dma_addr,
				   GFP_KERNEL | __GFP_NOWARN | __GFP_ZERO);
	if (unlikely(!device)) {
		LOG_ERR("device vring_alloc_queue failed\n");
		goto err_device;
	}

	vq = kmalloc(sizeof(*vq), GFP_KERNEL);
	if (unlikely(!vq)) {
		LOG_ERR("vq kmalloc failed\n");
		goto err_vq;
	}

	vq->vq.callback = callback;
	vq->vq.en_dev = en_dev;
	vq->vq.name = name;
	vq->vq.num_free = num;
	vq->vq.index = index;
	vq->we_own_ring = true;
	vq->notify = notify;
	vq->weak_barriers = weak_barriers;
	vq->broken = false;
	vq->last_used_idx = 0 | (1 << VRING_PACKED_EVENT_F_WRAP_CTR);
	vq->event_triggered = false;
	vq->num_added = 0;
	vq->packed_ring = true;
	vq->use_dma_api = vring_use_dma_api(en_dev);
#ifdef DEBUG
	vq->in_use = false;
	vq->last_add_time_valid = false;
#endif

	vq->indirect = zxdh_has_feature(en_dev, ZXDH_RING_F_INDIRECT_DESC) && !context;
	vq->event = zxdh_has_feature(en_dev, ZXDH_RING_F_EVENT_IDX);

	if (zxdh_has_feature(en_dev, ZXDH_F_ORDER_PLATFORM))
		vq->weak_barriers = false;

	vq->packed.ring_dma_addr = ring_dma_addr;
	vq->packed.driver_event_dma_addr = driver_event_dma_addr;
	vq->packed.device_event_dma_addr = device_event_dma_addr;

	vq->packed.ring_size_in_bytes = ring_size_in_bytes;
	vq->packed.event_size_in_bytes = event_size_in_bytes;

	vq->packed.vring.num = num;
	vq->packed.vring.desc = ring;
	vq->packed.vring.driver = driver;
	vq->packed.vring.device = device;

	vq->packed.next_avail_idx = 0;
	vq->packed.avail_wrap_counter = 1;
	vq->packed.event_flags_shadow = 0;
	vq->packed.avail_used_flags = 1 << VRING_PACKED_DESC_F_AVAIL;

	vq->packed.desc_state = kmalloc_array(ZXDH_PF_MAX_DESC_NUM(en_dev),
					      sizeof(struct vring_desc_state_packed), GFP_KERNEL);
	if (unlikely(!vq->packed.desc_state)) {
		LOG_ERR("vq->packed.desc_state kmalloc_array failed\n");
		goto err_desc_state;
	}

	memset(vq->packed.desc_state, 0, num * sizeof(struct vring_desc_state_packed));

	/* Put everything in free lists. */
	vq->free_head = 0;

	vq->packed.desc_extra = vring_alloc_desc_extra(vq, ZXDH_PF_MAX_DESC_NUM(en_dev));
	if (unlikely(!vq->packed.desc_extra)) {
		LOG_ERR("vq->packed.desc_extra vring_alloc_desc_extra failed\n");
		goto err_desc_extra;
	}

	/* No callback? Tell other side not to bother us. */
	if (!callback) {
		vq->packed.event_flags_shadow = VRING_PACKED_EVENT_FLAG_DISABLE;
		vq->packed.vring.driver->flags = cpu_to_le16(vq->packed.event_flags_shadow);
	}

	spin_lock(&en_dev->vqs_list_lock);
	list_add_tail(&vq->vq.list, &en_dev->vqs_list);
	spin_unlock(&en_dev->vqs_list_lock);

	return &vq->vq;

err_desc_extra:
	kfree(vq->packed.desc_state);
	vq->packed.desc_state = NULL;
err_desc_state:
	kfree(vq);
	vq = NULL;
err_vq:
	vring_free_queue(en_dev, event_size_in_bytes, device, device_event_dma_addr);
err_device:
	vring_free_queue(en_dev, event_size_in_bytes, driver, driver_event_dma_addr);
err_driver:
	vring_free_queue(en_dev, ring_size_in_bytes, ring, ring_dma_addr);
err_ring:
	return NULL;
}

void zxdh_en_xmit_pkts(struct virtqueue *tvq);
void zxdh_vvq_reset(struct zxdh_en_device *en_dev)
{
	struct virtqueue *vq = NULL;
	struct vring_virtqueue *vvq = NULL;
	u16 num;
	s32 i;
	s32 j;

	for (i = 0; i < 2 * en_dev->max_queue_pairs; ++i) {
		vq = en_dev->vqs[i]->vq;
		vvq = to_vvq(vq);

		if (i % 2 == 0) {
			num = en_dev->eth_config.rx_queue_size;
		} else {
			num = en_dev->eth_config.tx_queue_size;
			vq->callback = zxdh_en_xmit_pkts;
		}

		vq->num_free = num;
		vvq->last_used_idx = 0 | (1 << VRING_PACKED_EVENT_F_WRAP_CTR);
		vvq->num_added = 0;
		vvq->packed.vring.num = num;
		vvq->packed.next_avail_idx = 0;
		vvq->packed.avail_wrap_counter = 1;
		vvq->packed.avail_used_flags = 1 << VRING_PACKED_DESC_F_AVAIL;
		vvq->free_head = 0;

		memset(vvq->packed.desc_state, 0, num * sizeof(struct vring_desc_state_packed));
		memset(vvq->packed.vring.desc, 0,
		       num * sizeof(struct vring_packed_desc) + ZXDH_DESC_EXTRA_SIZE);
		memset(vvq->packed.desc_extra, 0, num * sizeof(struct vring_desc_extra));
		for (j = 0; j < num - 1; ++j)
			vvq->packed.desc_extra[j].next = j + 1;

		en_dev->ops->set_queue_size(en_dev->parent, en_dev->phy_index[i], num);
		en_dev->ops->set_queue_enable(en_dev->parent, en_dev->phy_index[i], true);
	}
}

/* the notify function used when creating a virt queue */
bool zxdh_vp_notify(struct virtqueue *vq)
{
	/* we write the queue's selector into the notification register to
	 * signal the other end
	 */
	iowrite16(vq->phy_index, (void __iomem *)vq->priv);

	return true;
}

struct virtqueue *vp_setup_vq(struct net_device *netdev, unsigned int index,
			      void (*callback)(struct virtqueue *vq), const char *name, bool ctx,
			      u16 channel_num)
{
	struct zxdh_en_priv *en_priv = netdev_priv(netdev);
	struct zxdh_en_device *en_dev = &en_priv->edev;
	struct zxdh_pci_vq_info *info = kmalloc(sizeof(*info), GFP_KERNEL);
	struct virtqueue *vq = NULL;
	struct virtqueue *n = NULL;
	unsigned long flags;
	u16 num = 0;
	u16 alloc_channel_num = 0;
	s32 err = 0;
	struct dh_vq_handler vq_handler;

	/* fill out our structure that represents an active queue */
	if (unlikely(!info)) {
		LOG_ERR("info kmalloc failed\n");
		return ERR_PTR(-ENOMEM);
	}

	if (index % 2 == 0)
		num = en_dev->eth_config.rx_queue_size;
	else
		num = en_dev->eth_config.tx_queue_size;

	/* create the vring */
	vq = vring_create_virtqueue_packed(index, num, SMP_CACHE_BYTES, en_dev->netdev, true, true,
					   ctx, zxdh_vp_notify, callback, name);
	if (!vq) {
		LOG_ERR("create the vring failed\n");
		err = -ENOMEM;
		goto out_info;
	}

	/* activate the queue */
	en_dev->ops->activate_phy_vq(en_dev->parent, en_dev->phy_index[index],
				     zxdh_virtqueue_get_vring_size(vq),
				     zxdh_virtqueue_get_desc_addr(vq),
				     zxdh_virtqueue_get_avail_addr(vq),
				     zxdh_virtqueue_get_used_addr(vq));

	vq->priv = (void __force *)en_dev->ops->vp_modern_map_vq_notify(
		en_dev->parent, en_dev->phy_index[index], NULL);
	if (!vq->priv) {
		LOG_ERR("vp_modern_map_vq_notify failed\n");
		err = -ENOMEM;
		goto err_map_notify;
	}

	vq->phy_index = en_dev->phy_index[index];
	vq->index = index;
	info->channel_num = channel_num;

	memset(&vq_handler, 0, sizeof(struct dh_vq_handler));
	vq_handler.callback = dh_eq_vqs_vring_int;
	alloc_channel_num = en_dev->ops->get_channels_num(en_dev->parent);
	if (channel_num < alloc_channel_num) {
		err = en_dev->ops->vqs_channel_bind_handler(en_dev->parent, channel_num,
							    &vq_handler);
		if (err < 0) {
			LOG_ERR("vqs_channel_bind_handler failed: %d\n", err);
			goto err_vqs_channel_bind_handler;
		}
	}

	if (channel_num >= alloc_channel_num) {
		if (alloc_channel_num == 0)
			channel_num = 0;
		else
			channel_num = (channel_num - alloc_channel_num) % alloc_channel_num;
	}
	err = en_dev->ops->vq_bind_channel(en_dev->parent, channel_num, en_dev->phy_index[index],
					   index);
	if (err < 0) {
		LOG_ERR("vq_bind_channel failed: %d\n", err);
		goto err_vq_bind_channel;
	}

	if (callback) {
		spin_lock_irqsave(&en_dev->lock, flags);
		err = en_dev->ops->vqs_bind_eqs(en_dev->parent, channel_num, &info->node);
		spin_unlock_irqrestore(&en_dev->lock, flags);
		if (err < 0) {
			LOG_ERR("vqs_bind_eqs failed: %d\n", err);
			goto err_vqs_bind_eqs;
		}
	} else {
		INIT_LIST_HEAD(&info->node);
	}

	info->vq = vq;
	en_dev->vqs[index] = info;
	return vq;

err_vqs_bind_eqs:
	list_for_each_entry_safe(vq, n, &en_dev->vqs_list, list) {
		en_dev->ops->vq_unbind_channel(en_dev->parent, vq->phy_index);
	}
err_vq_bind_channel:
	if (channel_num < alloc_channel_num)
		en_dev->ops->vqs_channel_unbind_handler(en_dev->parent, channel_num);
err_vqs_channel_bind_handler:
	en_dev->ops->vp_modern_unmap_vq_notify(en_dev->parent, (void __iomem __force *)vq->priv);
err_map_notify:
	zxdh_vring_del_virtqueue(vq);
out_info:
	kfree(info);
	en_dev->vqs[index] = NULL;
	return ERR_PTR(err);
}

u32 get_mergeable_buf_len(struct receive_queue *rq, struct ewma_pkt_len *avg_pkt_len, u32 room)
{
	struct zxdh_en_device *en_dev = rq->vq->en_dev;
	size_t hdr_len = 0;
	u32 len = 0;

	hdr_len = sizeof(struct zxdh_net_hdr_rx);
	if (en_dev->dtp_drs_offload == false)
		hdr_len = sizeof(struct zxdh_net_hdr_rx) - sizeof(struct pi_hdr);

	if (room)
		return PAGE_SIZE - room;

	len = hdr_len + DH_BUFF_LEN;

	return ALIGN(len, L1_CACHE_BYTES);
}

/* The DMA ops on various arches are rather gnarly right now, and
 * making all of the arch DMA ops work on the vring device itself
 * is a mess.  For now, we use the parent device for DMA ops.
 */
static inline struct device *vring_dma_dev(const struct vring_virtqueue *vq)
{
	return vq->vq.en_dev->dmadev;
}

/* Map one sg entry. */
dma_addr_t vring_map_one_sg(const struct vring_virtqueue *vq, struct scatterlist *sg,
			    enum dma_data_direction direction)
{
	if (!vq->use_dma_api)
		return (dma_addr_t)sg_phys(sg);

	/* We can't use dma_map_sg, because we don't use scatterlists in
	 * the way it expects (we don't guarantee that the scatterlist
	 * will exist for the lifetime of the mapping).
	 */
	return dma_map_page(vring_dma_dev(vq), sg_page(sg), sg->offset, sg->length, direction);
}

dma_addr_t vring_map_single(const struct vring_virtqueue *vq, void *cpu_addr, size_t size,
			    enum dma_data_direction direction)
{
	if (!vq->use_dma_api)
		return (dma_addr_t)virt_to_phys(cpu_addr);

	return dma_map_single(vring_dma_dev(vq), cpu_addr, size, direction);
}

s32 vring_mapping_error(const struct vring_virtqueue *vq, dma_addr_t addr)
{
	if (!vq->use_dma_api)
		return 0;

	return dma_mapping_error(vring_dma_dev(vq), addr);
}

/* Packed ring specific functions - *_packed(). */
void vring_unmap_state_packed(const struct vring_virtqueue *vq, struct vring_desc_extra *state)
{
	u16 flags = 0;

	if (!vq->use_dma_api)
		return;

	flags = state->flags;
	if (flags & VRING_DESC_F_INDIRECT) {
		dma_unmap_single(vring_dma_dev(vq), state->addr, state->len,
				 (flags & VRING_DESC_F_WRITE) ? DMA_FROM_DEVICE : DMA_TO_DEVICE);
	} else {
		dma_unmap_page(vring_dma_dev(vq), state->addr, state->len,
			       (flags & VRING_DESC_F_WRITE) ? DMA_FROM_DEVICE : DMA_TO_DEVICE);
	}
}

void vring_unmap_desc_packed(const struct vring_virtqueue *vq, struct vring_packed_desc *desc)
{
	u16 flags = 0;

	if (!vq->use_dma_api)
		return;

	flags = le16_to_cpu(desc->flags);

	if (flags & VRING_DESC_F_INDIRECT) {
		dma_unmap_single(vring_dma_dev(vq), le64_to_cpu(desc->addr), le32_to_cpu(desc->len),
				 (flags & VRING_DESC_F_WRITE) ? DMA_FROM_DEVICE : DMA_TO_DEVICE);
	} else {
		dma_unmap_page(vring_dma_dev(vq), le64_to_cpu(desc->addr), le32_to_cpu(desc->len),
			       (flags & VRING_DESC_F_WRITE) ? DMA_FROM_DEVICE : DMA_TO_DEVICE);
	}
}

void *mergeable_len_to_ctx(u32 truesize, u32 headroom)
{
	return (void *)(unsigned long)((headroom << MRG_CTX_HEADER_SHIFT) | truesize);
}

inline bool virtqueue_use_indirect(struct virtqueue *_vq, unsigned int total_sg)
{
	struct vring_virtqueue *vq = to_vvq(_vq);

	/* If the host supports indirect descriptor tables, and we have multiple
	 * buffers, then go indirect. FIXME: tune this threshold
	 */
	return (vq->indirect && total_sg > 1 && vq->vq.num_free);
}

struct vring_packed_desc *alloc_indirect_packed(unsigned int total_sg, gfp_t gfp)
{
	struct vring_packed_desc *desc = NULL;

	/* We require lowmem mappings for the descriptors because
	 * otherwise virt_to_phys will give us bogus addresses in the
	 * virtqueue.
	 */
	gfp &= ~__GFP_HIGHMEM;

	desc = kmalloc_array(total_sg, sizeof(struct vring_packed_desc), gfp);

	return desc;
}

int virtqueue_add_indirect_packed(struct vring_virtqueue *vq, struct scatterlist *sgs[],
				  unsigned int total_sg, unsigned int out_sgs, unsigned int in_sgs,
				  void *data, gfp_t gfp)
{
	struct vring_packed_desc *desc = NULL;
	struct scatterlist *sg = NULL;
	u32 i = 0;
	u32 n = 0;
	u32 err_idx = 0;
	u16 head = 0;
	u16 id = 0;
	dma_addr_t addr;

	head = vq->packed.next_avail_idx;
	desc = alloc_indirect_packed(total_sg, gfp);
	if (!desc) {
		LOG_ERR("desc alloc_indirect_packed failed\n");
		return -ENOMEM;
	}

	if (unlikely(vq->vq.num_free < 1)) {
		kfree(desc);
		END_USE(vq);
		return -ENOSPC;
	}

	i = 0;
	id = vq->free_head;
	if (WARN_ON(id == vq->packed.vring.num))
		return -ENOSPC;

	for (n = 0; n < out_sgs + in_sgs; n++) {
		for (sg = sgs[n]; sg; sg = sg_next(sg)) {
			addr = vring_map_one_sg(vq, sg,
						n < out_sgs ? DMA_TO_DEVICE : DMA_FROM_DEVICE);
			if (vring_mapping_error(vq, addr)) {
				LOG_ERR("vring_map_one_sg error\n");
				goto unmap_release;
			}

			desc[i].flags = cpu_to_le16(n < out_sgs ? 0 : VRING_DESC_F_WRITE);
			desc[i].addr = cpu_to_le64(addr);
			desc[i].len = cpu_to_le32(sg->length);
			i++;
		}
	}

	/* Now that the indirect table is filled in, map it. */
	addr = vring_map_single(vq, desc, total_sg * sizeof(struct vring_packed_desc),
				DMA_TO_DEVICE);
	if (vring_mapping_error(vq, addr)) {
		LOG_ERR("vring_map_single error\n");
		goto unmap_release;
	}

	vq->packed.vring.desc[head].addr = cpu_to_le64(addr);
	vq->packed.vring.desc[head].len = cpu_to_le32(total_sg * sizeof(struct vring_packed_desc));
	vq->packed.vring.desc[head].id = cpu_to_le16(id);

	if (vq->use_dma_api) {
		vq->packed.desc_extra[id].addr = addr;
		vq->packed.desc_extra[id].len = total_sg * sizeof(struct vring_packed_desc);
		vq->packed.desc_extra[id].flags = VRING_DESC_F_INDIRECT |
						  vq->packed.avail_used_flags;
	}

	/* A driver MUST NOT make the first descriptor in the list
	 * available before all subsequent descriptors comprising
	 * the list are made available.
	 */
	vqm_wmb(vq->weak_barriers);
	vq->packed.vring.desc[head].flags =
		cpu_to_le16(VRING_DESC_F_INDIRECT | vq->packed.avail_used_flags);

	/* We're using some buffers from the free list. */
	vq->vq.num_free -= 1;

	/* Update free pointer */
	n = head + 1;
	if (n >= vq->packed.vring.num) {
		n = 0;
		vq->packed.avail_wrap_counter ^= 1;
		vq->packed.avail_used_flags ^= 1 << VRING_PACKED_DESC_F_AVAIL |
					       1 << VRING_PACKED_DESC_F_USED;
	}
	vq->packed.next_avail_idx = n;
	vq->free_head = vq->packed.desc_extra[id].next;

	/* Store token and indirect buffer state. */
	vq->packed.desc_state[id].num = 1;
	vq->packed.desc_state[id].data = data;
	vq->packed.desc_state[id].indir_desc = desc;
	vq->packed.desc_state[id].last = id;

	vq->num_added += 1;

	//LOG_DEBUG("added buffer head %i to %p\n", head, vq);
	END_USE(vq);

	return 0;

unmap_release:
	err_idx = i;

	for (i = 0; i < err_idx; i++)
		vring_unmap_desc_packed(vq, &desc[i]);

	kfree(desc);

	END_USE(vq);
	return -ENOMEM;
}

s32 virtqueue_add_packed(struct virtqueue *_vq, struct scatterlist *sgs[], u32 total_sg,
			 u32 out_sgs, u32 in_sgs, void *data, void *ctx, gfp_t gfp)
{
	struct vring_virtqueue *vq = to_vvq(_vq);
	struct vring_packed_desc *desc = NULL;
	struct scatterlist *sg = NULL;
	u32 i = 0;
	u32 n = 0;
	u32 c = 0;
	u32 descs_used = 0;
	u32 err_idx = 0;
	__le16 head_flags = 0;
	__le16 flags = 0;
	u16 head = 0;
	u16 id = 0;
	u16 prev = 0;
	u16 curr = 0;
	u16 avail_used_flags = 0;
	s32 err = 0;

	START_USE(vq);

	if (WARN_ON(!data))
		return -EINVAL;

	if (WARN_ON(ctx && vq->indirect))
		return -EINVAL;

	if (unlikely(vq->broken)) {
		LOG_ERR("vq->broken\n");
		END_USE(vq);
		return -EIO;
	}

	LAST_ADD_TIME_UPDATE(vq);

	if (WARN_ON(total_sg == 0))
		return -EINVAL;

	if (virtqueue_use_indirect(_vq, total_sg)) {
		err = virtqueue_add_indirect_packed(vq, sgs, total_sg, out_sgs, in_sgs, data, gfp);
		if (err != -ENOMEM) {
			END_USE(vq);
			return err;
		}
		/* fall back on direct */
	}

	head = vq->packed.next_avail_idx;
	avail_used_flags = vq->packed.avail_used_flags;

	WARN_ON_ONCE(total_sg > vq->packed.vring.num && !vq->indirect);

	desc = vq->packed.vring.desc;
	i = head;
	descs_used = total_sg;

	if (unlikely(vq->vq.num_free < descs_used)) {
		END_USE(vq);
		return -ENOSPC;
	}

	id = vq->free_head;
	if (WARN_ON(id == vq->packed.vring.num))
		return -ENOSPC;

	curr = id;
	c = 0;
	for (n = 0; n < out_sgs + in_sgs; n++) {
		for (sg = sgs[n]; sg; sg = sg_next(sg)) {
			dma_addr_t addr = vring_map_one_sg(
				vq, sg, n < out_sgs ? DMA_TO_DEVICE : DMA_FROM_DEVICE);
			if (vring_mapping_error(vq, addr)) {
				LOG_ERR("vring_map_one_sg error\n");
				goto unmap_release;
			}

			flags = cpu_to_le16(vq->packed.avail_used_flags |
					    (++c == total_sg ? 0 : VRING_DESC_F_NEXT) |
					    (n < out_sgs ? 0 : VRING_DESC_F_WRITE));

			desc[i].addr = cpu_to_le64(addr);
			desc[i].len = cpu_to_le32(sg->length);
			desc[i].id = cpu_to_le16(id);

			if (i == head)
				head_flags = flags;
			else
				desc[i].flags = flags;

			if (unlikely(vq->use_dma_api)) {
				vq->packed.desc_extra[curr].addr = addr;
				vq->packed.desc_extra[curr].len = sg->length;
				vq->packed.desc_extra[curr].flags = le16_to_cpu(flags);
			}
			prev = curr;
			curr = vq->packed.desc_extra[curr].next;

			if ((unlikely(++i >= vq->packed.vring.num))) {
				i = 0;
				vq->packed.avail_used_flags ^= 1 << VRING_PACKED_DESC_F_AVAIL |
							       1 << VRING_PACKED_DESC_F_USED;
			}
		}
	}

	if (i < head)
		vq->packed.avail_wrap_counter ^= 1;

	/* We're using some buffers from the free list. */
	vq->vq.num_free -= descs_used;

	/* Update free pointer */
	vq->packed.next_avail_idx = i;
	vq->free_head = curr;

	/* Store token. */
	vq->packed.desc_state[id].num = descs_used;
	vq->packed.desc_state[id].data = data;
	vq->packed.desc_state[id].indir_desc = ctx;
	vq->packed.desc_state[id].last = prev;

	/* A driver MUST NOT make the first descriptor in the list
	 * available before all subsequent descriptors comprising
	 * the list are made available.
	 */
	vqm_wmb(vq->weak_barriers);
	vq->packed.vring.desc[head].flags = head_flags;
	vq->num_added += descs_used;

	//LOG_INFO("added buffer head %i to %p\n", head, vq);
	END_USE(vq);

	return 0;

unmap_release:
	err_idx = i;
	i = head;
	curr = vq->free_head;

	vq->packed.avail_used_flags = avail_used_flags;

	for (n = 0; n < total_sg; n++) {
		if (i == err_idx)
			break;

		vring_unmap_state_packed(vq, &vq->packed.desc_extra[curr]);
		curr = vq->packed.desc_extra[curr].next;
		i++;
		if (i >= vq->packed.vring.num)
			i = 0;
	}

	END_USE(vq);
	return -EIO;
}

/**
 * zxdh_virtqueue_add_inbuf_ctx - expose input buffers to other end
 * @vq: the struct virtqueue we're talking about.
 * @sg: scatterlist (must be well-formed and terminated!)
 * @num: the number of entries in @sg writable by other side
 * @data: the token identifying the buffer.
 * @ctx: extra context for the token
 * @gfp: how to do memory allocations (if necessary).
 *
 * Caller must ensure we don't call this with other virtqueue operations
 * at the same time (except where noted).
 *
 * Returns zero or a negative error (ie. ENOSPC, ENOMEM, EIO).
 */
s32 zxdh_virtqueue_add_inbuf_ctx(struct virtqueue *vq, struct scatterlist *sg, u32 num, void *data,
				 void *ctx, gfp_t gfp)
{
	return virtqueue_add_packed(vq, &sg, num, 0, 1, data, ctx, gfp);
}

bool is_used_desc_packed(struct vring_virtqueue *vq, u16 idx, bool used_wrap_counter)
{
	bool avail = false;
	bool used = false;
	u16 flags = 0;

	flags = le16_to_cpu(vq->packed.vring.desc[idx].flags);
	avail = !!(flags & (1 << VRING_PACKED_DESC_F_AVAIL));
	used = !!(flags & (1 << VRING_PACKED_DESC_F_USED));

	return avail == used && used == used_wrap_counter;
}

bool virtqueue_poll_packed(struct virtqueue *_vq, u16 off_wrap)
{
	struct vring_virtqueue *vq = to_vvq(_vq);
	bool wrap_counter = false;
	u16 used_idx = 0;

	wrap_counter = off_wrap >> VRING_PACKED_EVENT_F_WRAP_CTR;
	used_idx = off_wrap & ~(1 << VRING_PACKED_EVENT_F_WRAP_CTR);

	return is_used_desc_packed(vq, used_idx, wrap_counter);
}

/**
 * zxdh_virtqueue_poll - query pending used buffers
 * @_vq: the struct virtqueue we're talking about.
 * @last_used_idx: virtqueue state (from call to zxdh_virtqueue_enable_cb_prepare).
 *
 * Returns "true" if there are pending used buffers in the queue.
 *
 * This does not need to be serialized.
 */
bool zxdh_virtqueue_poll(struct virtqueue *_vq, unsigned int last_used_idx)
{
	struct vring_virtqueue *vq = to_vvq(_vq);

	if (unlikely(vq->broken)) {
		LOG_ERR("vq->broken\n");
		return false;
	}

	vqm_mb(vq->weak_barriers);
	return virtqueue_poll_packed(_vq, last_used_idx);
}

unsigned int virtqueue_enable_cb_prepare_packed(struct virtqueue *_vq)
{
	struct vring_virtqueue *vq = to_vvq(_vq);

	START_USE(vq);

	/* We optimistically turn back on interrupts, then check if there was
	 * more to do.
	 */
	if (vq->event) {
		vq->packed.vring.driver->off_wrap = cpu_to_le16(vq->last_used_idx);

		/* We need to update event offset and event wrap
		 * counter first before updating event flags.
		 */
		vqm_wmb(vq->weak_barriers);
	}

	if (vq->packed.event_flags_shadow == VRING_PACKED_EVENT_FLAG_DISABLE) {
		vq->packed.event_flags_shadow = vq->event ? VRING_PACKED_EVENT_FLAG_DESC :
								  VRING_PACKED_EVENT_FLAG_ENABLE;
		vq->packed.vring.driver->flags = cpu_to_le16(vq->packed.event_flags_shadow);
	}

	END_USE(vq);
	return vq->last_used_idx;
}

s32 zxdh_virtqueue_enable_cb_prepare(struct virtqueue *_vq)
{
	struct vring_virtqueue *vq = to_vvq(_vq);

	if (vq->event_triggered)
		vq->event_triggered = false;

	return virtqueue_enable_cb_prepare_packed(_vq);
}

bool packed_used_wrap_counter(u16 last_used_idx)
{
	return !!(last_used_idx & (1 << VRING_PACKED_EVENT_F_WRAP_CTR));
}

u16 packed_last_used(u16 last_used_idx)
{
	return last_used_idx & ~(-(1 << VRING_PACKED_EVENT_F_WRAP_CTR));
}

bool more_used_packed(struct vring_virtqueue *vq)
{
	u16 last_used = 0;
	u16 last_used_idx = 0;
	bool used_wrap_counter = false;

	last_used_idx = READ_ONCE(vq->last_used_idx);
	last_used = packed_last_used(last_used_idx);
	used_wrap_counter = packed_used_wrap_counter(last_used_idx);

	return is_used_desc_packed(vq, last_used, used_wrap_counter);
}

#define MIN_WAIT_COUNT 10
bool is_flow_stopped(struct zxdh_en_device *en_dev)
{
	struct virtqueue *vq = NULL;
	struct vring_virtqueue *vvq = NULL;
	s32 consecutive_false_count = 0;
	u16 last_used = 0;
	u16 last_used_idx = 0;
	s32 i = 0;
	s32 j = 0;

	for (i = 0; i < 2 * en_dev->max_queue_pairs; ++i) {
		vq = en_dev->vqs[i]->vq;
		vvq = to_vvq(vq);
		j = 0;
		consecutive_false_count = 0;

		for (j = 0; j < 2000; ++j) {
			if (i % 2 == 0) {
				if (more_used_packed(vvq)) {
					synchronize_net();
					consecutive_false_count = 0;
				} else {
					if (++consecutive_false_count >= MIN_WAIT_COUNT)
						break;
				}
			} else {
				vq->callback = NULL;
				return true;
			}
			usleep_range(5, 10);
		}

		if (consecutive_false_count < MIN_WAIT_COUNT) {
			last_used_idx = READ_ONCE(vvq->last_used_idx);
			last_used = packed_last_used(last_used_idx);
			zxdh_print_vring_info(vq, last_used - 10, 10);
			zxdh_print_vring_info(vq, last_used, 30);
			return false;
		}
	}

	return true;
}

void detach_buf_packed(struct vring_virtqueue *vq, u32 id, void **ctx)
{
	struct vring_desc_state_packed *state = NULL;
	struct vring_packed_desc *desc = NULL;
	u32 i = 0;
	u32 curr = 0;

	state = &vq->packed.desc_state[id];

	/* Clear data ptr. */
	state->data = NULL;

	vq->packed.desc_extra[state->last].next = vq->free_head;
	vq->free_head = id;
	vq->vq.num_free += state->num;

	if (unlikely(vq->use_dma_api)) {
		curr = id;
		for (i = 0; i < state->num; i++) {
			vring_unmap_state_packed(vq, &vq->packed.desc_extra[curr]);
			curr = vq->packed.desc_extra[curr].next;
		}
	}

	if (vq->indirect) {
		u32 len;

		/* Free the indirect table, if any, now that it's unmapped. */
		desc = state->indir_desc;
		if (!desc)
			return;

		if (vq->use_dma_api) {
			len = vq->packed.desc_extra[id].len;
			for (i = 0; i < len / sizeof(struct vring_packed_desc); i++)
				vring_unmap_desc_packed(vq, &desc[i]);
		}
		kfree(desc);
		state->indir_desc = NULL;
	} else if (ctx) {
		*ctx = state->indir_desc;
	}
}

void *virtqueue_get_buf_ctx_packed(struct virtqueue *_vq, u32 *len, void **ctx)
{
	struct vring_virtqueue *vq = to_vvq(_vq);
	u16 last_used = 0;
	u16 id = 0;
	u16 last_used_idx = 0;
	bool used_wrap_counter = false;
	void *ret = NULL;

	START_USE(vq);

	if (unlikely(vq->broken)) {
		END_USE(vq);
		return NULL;
	}

	if (!more_used_packed(vq)) {
		//LOG_ERR("no more buffers in queue\n");
		END_USE(vq);
		return NULL;
	}

	/* Only get used elements after they have been exposed by host. */
	vqm_rmb(vq->weak_barriers);

	last_used_idx = READ_ONCE(vq->last_used_idx);
	used_wrap_counter = packed_used_wrap_counter(last_used_idx);
	last_used = packed_last_used(last_used_idx);
	id = le16_to_cpu(vq->packed.vring.desc[last_used].id);
	*len = le32_to_cpu(vq->packed.vring.desc[last_used].len);

	if (unlikely(id >= vq->packed.vring.num)) {
		zxdh_print_vring_info(_vq, 0, vq->packed.vring.num);
		BAD_RING(vq, "id %u out of range\n", id);
		return NULL;
	}
	if (unlikely(!vq->packed.desc_state[id].data)) {
		zxdh_print_vring_info(_vq, last_used - 10, 10);
		zxdh_print_vring_info(_vq, last_used, 30);
		BAD_RING(vq, "id %u is not a head!\n", id);
		return NULL;
	}

	/* detach_buf_packed clears data, so grab it now. */
	ret = vq->packed.desc_state[id].data;
	detach_buf_packed(vq, id, ctx);

	last_used += vq->packed.desc_state[id].num;
	if (unlikely(last_used >= vq->packed.vring.num)) {
		last_used -= vq->packed.vring.num;
		used_wrap_counter ^= 1;
	}

	last_used = (last_used | (used_wrap_counter << VRING_PACKED_EVENT_F_WRAP_CTR));
	WRITE_ONCE(vq->last_used_idx, last_used);

	/* If we expect an interrupt for the next entry, tell host
	 * by writing event index and flush out the write before
	 * the read in the next get_buf call.
	 */
	if (vq->packed.event_flags_shadow == VRING_PACKED_EVENT_FLAG_DESC)
		vqm_store_mb(vq->weak_barriers, &vq->packed.vring.driver->off_wrap,
			     cpu_to_le16(vq->last_used_idx));

	LAST_ADD_TIME_INVALID(vq);

	END_USE(vq);
	return ret;
}

void *zxdh_virtqueue_get_buf(struct virtqueue *_vq, u32 *len)
{
	return virtqueue_get_buf_ctx_packed(_vq, len, NULL);
}

/* private is used to chain pages for big packets, put the whole
 * most recent used list in the beginning for reuse
 */
void give_pages(struct receive_queue *rq, struct page *page)
{
	struct page *end = NULL;

	/* Find end of list, sew whole thing into vi->rq.pages. */
	for (end = page; end->private; end = (struct page *)end->private)
		;
	end->private = (unsigned long)rq->pages;
	rq->pages = page;
}

void free_old_xmit_skbs(struct net_device *netdev, struct send_queue *sq, bool in_napi)
{
	u32 len = 0;
	u32 packets = 0;
	u32 bytes = 0;
	void *ptr = NULL;

	while ((ptr = zxdh_virtqueue_get_buf(sq->vq, &len)) != NULL) {
		if (likely(!is_xdp_frame(ptr))) {
			struct sk_buff *skb = ptr;

			bytes += skb->len;
			napi_consume_skb(skb, in_napi);
		} else {
			struct xdp_frame *frame = ptr_to_xdp(ptr);

			bytes += frame->len;
			xdp_return_frame(frame);
		}
		packets++;
	}

	/* Avoid overhead when no packets have been processed
	 * happens when called speculatively from start_xmit.
	 */
	if (!packets)
		return;

	u64_stats_update_begin(&sq->stats.syncp);
	sq->stats.bytes += bytes;
	sq->stats.packets += packets;
	u64_stats_update_end(&sq->stats.syncp);
}

void virtqueue_disable_cb_packed(struct virtqueue *_vq)
{
	struct vring_virtqueue *vq = to_vvq(_vq);

	if (vq->packed.event_flags_shadow != VRING_PACKED_EVENT_FLAG_DISABLE) {
		vq->packed.event_flags_shadow = VRING_PACKED_EVENT_FLAG_DISABLE;
		vq->packed.vring.driver->flags = cpu_to_le16(vq->packed.event_flags_shadow);
	}
}

/**
 * zxdh_virtqueue_disable_cb - disable callbacks
 * @_vq: the struct virtqueue we're talking about.
 *
 * Note that this is not necessarily synchronous, hence unreliable and only
 * useful as an optimization.
 *
 * Unlike other operations, this need not be serialized.
 */
void zxdh_virtqueue_disable_cb(struct virtqueue *_vq)
{
	struct vring_virtqueue *vq = to_vvq(_vq);

	/* If device triggered an event already it won't trigger one again:
	 * no need to disable.
	 */
	if (vq->event_triggered)
		return;

	virtqueue_disable_cb_packed(_vq);
}

void virtqueue_napi_schedule(struct napi_struct *napi, struct virtqueue *vq)
{
	if (napi_schedule_prep(napi)) {
		zxdh_virtqueue_disable_cb(vq);
		__napi_schedule(napi);
	}
}

void virtnet_napi_enable(struct virtqueue *vq, struct napi_struct *napi)
{
	napi_enable(napi);

	/* If all buffers were filled by other side before we napi_enabled, we
	 * won't get another interrupt, so process any outstanding packets now.
	 * Call local_bh_enable after to trigger softIRQ processing.
	 */
	local_bh_disable();
	virtqueue_napi_schedule(napi, vq);
	local_bh_enable();
}

void virtnet_napi_tx_enable(struct net_device *netdev, struct virtqueue *vq,
			    struct napi_struct *napi)
{
	if (!napi->weight)
		return;

	virtnet_napi_enable(vq, napi);
}

void virtnet_napi_tx_disable(struct napi_struct *napi)
{
	if (napi->weight)
		napi_disable(napi);
}

static bool is_xdp_raw_buffer_queue(struct zxdh_en_device *en_dev, int q)
{
	if (q < (en_dev->curr_queue_pairs - en_dev->xdp_queue_pairs))
		return false;
	else if (q < en_dev->curr_queue_pairs)
		return true;
	else
		return false;
}

int virtnet_poll_tx(struct napi_struct *napi, int budget)
{
	struct send_queue *sq = container_of(napi, struct send_queue, napi);
	struct zxdh_en_device *en_dev = sq->vq->en_dev;
	u32 index = vq2txq(sq->vq);
	struct netdev_queue *txq = NULL;
	s32 opaque = 0;
	bool done = false;

	if (unlikely(is_xdp_raw_buffer_queue(en_dev, index))) {
		/* We don't need to enable cb for XDP */
		napi_complete_done(napi, 0);
		return 0;
	}

	txq = netdev_get_tx_queue(en_dev->netdev, index);
	__netif_tx_lock(txq, raw_smp_processor_id());
	zxdh_virtqueue_disable_cb(sq->vq);
	free_old_xmit_skbs(en_dev->netdev, sq, true);

	if (sq->vq->num_free >= 2 + MAX_SKB_FRAGS)
		netif_tx_wake_queue(txq);

	opaque = zxdh_virtqueue_enable_cb_prepare(sq->vq);

	done = napi_complete_done(napi, 0);

	if (!done)
		zxdh_virtqueue_disable_cb(sq->vq);

	__netif_tx_unlock(txq);

	if (done) {
		if (unlikely(zxdh_virtqueue_poll(sq->vq, opaque))) {
			if (napi_schedule_prep(napi)) {
				__netif_tx_lock(txq, raw_smp_processor_id());
				zxdh_virtqueue_disable_cb(sq->vq);
				__netif_tx_unlock(txq);
				__napi_schedule(napi);
			}
		}
	}

	return 0;
}

bool virtqueue_enable_cb_delayed_packed(struct virtqueue *_vq)
{
	struct vring_virtqueue *vq = to_vvq(_vq);
	u16 used_idx = 0;
	u16 wrap_counter = 0;
	u16 last_used_idx = 0;
	u16 bufs = 0;

	START_USE(vq);

	/* We optimistically turn back on interrupts, then check if there was
	 * more to do.
	 */

	if (vq->event) {
		bufs = (vq->packed.vring.num - vq->vq.num_free) * 3 / 4;
		last_used_idx = READ_ONCE(vq->last_used_idx);
		wrap_counter = packed_used_wrap_counter(last_used_idx);

		used_idx = packed_last_used(last_used_idx) + bufs;
		if (used_idx >= vq->packed.vring.num) {
			used_idx -= vq->packed.vring.num;
			wrap_counter ^= 1;
		}

		vq->packed.vring.driver->off_wrap =
			cpu_to_le16(used_idx | (wrap_counter << VRING_PACKED_EVENT_F_WRAP_CTR));

		/* We need to update event offset and event wrap
		 * counter first before updating event flags.
		 */
		vqm_wmb(vq->weak_barriers);
	}

	if (vq->packed.event_flags_shadow == VRING_PACKED_EVENT_FLAG_DISABLE) {
		vq->packed.event_flags_shadow = vq->event ? VRING_PACKED_EVENT_FLAG_DESC :
								  VRING_PACKED_EVENT_FLAG_ENABLE;
		vq->packed.vring.driver->flags = cpu_to_le16(vq->packed.event_flags_shadow);
	}

	/* We need to update event suppression structure first
	 * before re-checking for more used buffers.
	 */
	vqm_mb(vq->weak_barriers);

	last_used_idx = READ_ONCE(vq->last_used_idx);
	wrap_counter = packed_used_wrap_counter(last_used_idx);
	used_idx = packed_last_used(last_used_idx);
	if (is_used_desc_packed(vq, used_idx, wrap_counter)) {
		END_USE(vq);
		return false;
	}

	END_USE(vq);
	return true;
}
u16 __vqm16_to_cpu(bool little_endian, __vqm16 val)
{
	if (little_endian)
		return le16_to_cpu((__force __le16)val);
	else
		return be16_to_cpu((__force __be16)val);
}

static inline bool zxdh_legacy_is_little_endian(void)
{
#ifdef __LITTLE_ENDIAN
	return true;
#else
	return false;
#endif
}

bool zxdh_is_little_endian(struct zxdh_en_device *en_dev)
{
	return zxdh_has_feature(en_dev, ZXDH_F_VERSION_1) || zxdh_legacy_is_little_endian();
}

/* Memory accessors */
u16 vqm16_to_cpu(struct zxdh_en_device *en_dev, __vqm16 val)
{
	return __vqm16_to_cpu(zxdh_is_little_endian(en_dev), val);
}

u32 mergeable_ctx_to_headroom(void *mrg_ctx)
{
	return (unsigned long)mrg_ctx >> MRG_CTX_HEADER_SHIFT;
}

u32 mergeable_ctx_to_truesize(void *mrg_ctx)
{
	return (unsigned long)mrg_ctx & ((1 << MRG_CTX_HEADER_SHIFT) - 1);
}

/**
 * zxdh_virtqueue_enable_cb_delayed - restart callbacks after disable_cb.
 * @_vq: the struct virtqueue we're talking about.
 *
 * This re-enables callbacks but hints to the other side to delay
 * interrupts until most of the available buffers have been processed;
 * it returns "false" if there are many pending buffers in the queue,
 * to detect a possible race between the driver checking for more work,
 * and enabling callbacks.
 *
 * Caller must ensure we don't call this with other virtqueue
 * operations at the same time (except where noted).
 */
bool zxdh_virtqueue_enable_cb_delayed(struct virtqueue *_vq)
{
	struct vring_virtqueue *vq = to_vvq(_vq);

	if (vq->event_triggered)
		vq->event_triggered = false;

	return virtqueue_enable_cb_delayed_packed(_vq);
}

void virtnet_poll_cleantx(struct receive_queue *rq)
{
	struct zxdh_en_device *en_dev = rq->vq->en_dev;
	u32 index = vq2rxq(rq->vq);
	struct send_queue *sq = &en_dev->sq[index];
	struct netdev_queue *txq = netdev_get_tx_queue(en_dev->netdev, index);

	if (!sq->napi.weight || is_xdp_raw_buffer_queue(en_dev, index))
		return;

	if (__netif_tx_trylock(txq)) {
		do {
			zxdh_virtqueue_disable_cb(sq->vq);
			free_old_xmit_skbs(en_dev->netdev, sq, true);
		} while (unlikely(!zxdh_virtqueue_enable_cb_delayed(sq->vq)));

		if (sq->vq->num_free >= 2 + MAX_SKB_FRAGS)
			netif_tx_wake_queue(txq);

		__netif_tx_unlock(txq);
	}
}

inline struct zxdh_net_hdr_rx *skb_vnet_hdr(struct sk_buff *skb)
{
	return (struct zxdh_net_hdr_rx *)skb->cb;
}

/* Called from bottom half context */
struct sk_buff *page_to_skb(struct zxdh_en_device *en_dev, struct receive_queue *rq,
			    struct page *page, u32 offset, u32 len, u32 truesize, u32 metasize,
			    u32 headroom)
{
	struct sk_buff *skb = NULL;
	u32 copy = 0;
	u32 hdr_len = 0;
	struct page *page_to_free = NULL;
	s32 tailroom = 0;
	s32 shinfo_size = 0;
	char *p = NULL;
	char *hdr_p = NULL;
	char *buf = NULL;

	p = page_address(page) + offset;
	hdr_p = p;

	hdr_len = (((struct zxdh_net_hdr_rx *)hdr_p)->pd_len) * HDR_2B_UNIT;

	/* If headroom is not 0, there is an offset between the beginning of the
	 * data and the allocated space, otherwise the data and the allocated
	 * space are aligned.
	 *
	 * Buffers with headroom use PAGE_SIZE as alloc size, see
	 * add_recvbuf_mergeable() + get_mergeable_buf_len()
	 */
	truesize = headroom ? PAGE_SIZE : truesize;
	tailroom = truesize - headroom;
	buf = p - headroom;

	len -= hdr_len;
	offset += hdr_len;
	p += hdr_len;
	tailroom -= hdr_len + len;

	shinfo_size = SKB_DATA_ALIGN(sizeof(struct skb_shared_info));

	/* copy small packet so we can reuse these pages */
	if (!NET_IP_ALIGN && len > GOOD_COPY_LEN && tailroom >= shinfo_size) {
		skb = build_skb(buf, truesize);
		if (unlikely(!skb)) {
			LOG_ERR("build_skb is null\n");
			return NULL;
		}

		skb_reserve(skb, p - buf);
		skb_put(skb, len);

		page = (struct page *)page->private;
		if (page)
			give_pages(rq, page);
		goto ok;
	}

	/* copy small packet so we can reuse these pages for small data */
	skb = napi_alloc_skb(&rq->napi, GOOD_COPY_LEN);
	if (unlikely(!skb)) {
		LOG_ERR("napi_alloc_skb is null\n");
		return NULL;
	}

	/* Copy all frame if it fits skb->head */
	if (len <= skb_tailroom(skb))
		copy = len;
	else
		copy = ETH_HLEN + metasize;

	skb_put_data(skb, p, copy);

	len -= copy;
	offset += copy;

	if (len)
		skb_add_rx_frag(skb, 0, page, offset, len, truesize);
	else
		page_to_free = page;

ok:
	if (page_to_free)
		put_page(page_to_free);

	if (metasize) {
		__skb_pull(skb, metasize);
		skb_metadata_set(skb, metasize);
	}

	return skb;
}

/**
 * zxdh_virtqueue_add_outbuf - expose output buffers to other end
 * @vq: the struct virtqueue we're talking about.
 * @sg: scatterlist (must be well-formed and terminated!)
 * @num: the number of entries in @sg readable by other side
 * @data: the token identifying the buffer.
 * @gfp: how to do memory allocations (if necessary).
 *
 * Caller must ensure we don't call this with other virtqueue operations
 * at the same time (except where noted).
 *
 * Returns zero or a negative error (ie. ENOSPC, ENOMEM, EIO).
 */
s32 zxdh_virtqueue_add_outbuf(struct virtqueue *vq, struct scatterlist *sg, u32 num, void *data,
			      gfp_t gfp)
{
	return virtqueue_add_packed(vq, &sg, num, 1, 0, data, NULL, gfp);
}

static int __zxdh_en_xdp_xmit_one(struct zxdh_en_device *en_dev, struct send_queue *sq,
				  struct xdp_frame *xdpf)
{
	struct zxdh_net_hdr_tx *hdr;
	int err;

	if (unlikely(xdpf->headroom < en_dev->hdr_len))
		return -EOVERFLOW;

	/* Make room for virtqueue hdr (also change xdpf->headroom?) */
	xdpf->data -= en_dev->hdr_len;
	/* Zero header and leave csum up to XDP layers */
	hdr = xdpf->data;
	memset(hdr, 0, en_dev->hdr_len);
	xdpf->len += en_dev->hdr_len;

	hdr->pd_len = en_dev->hdr_len / HDR_2B_UNIT;

	sg_init_one(sq->sg, xdpf->data, xdpf->len);

	err = zxdh_virtqueue_add_outbuf(sq->vq, sq->sg, 1, xdp_to_ptr(xdpf), GFP_ATOMIC);
	if (unlikely(err))
		return -ENOSPC; /* Caller handle free/refcnt */

	return 0;
}

/* when vi->curr_queue_pairs > nr_cpu_ids, the txq/sq is only used for xdp tx on
 * the current cpu, so it does not need to be locked.
 *
 * Here we use marco instead of inline functions because we have to deal with
 * three issues at the same time: 1. the choice of sq. 2. judge and execute the
 * lock/unlock of txq 3. make sparse happy. It is difficult for two inline
 * functions to perfectly solve these three problems at the same time.
 */
#define zxdh_en_xdp_get_sq(en_dev)	 \
	({								 \
		int cpu = smp_processor_id(); \
		struct netdev_queue *txq;	 \
		typeof(en_dev) v = (en_dev); \
		unsigned int qp;			 \
									 \
		if (v->curr_queue_pairs > nr_cpu_ids) {	\
			qp = v->curr_queue_pairs - v->xdp_queue_pairs; \
			qp += cpu;		\
			txq = netdev_get_tx_queue(v->netdev, qp); \
			__netif_tx_acquire(txq);			\
		} else {								\
			qp = cpu % v->curr_queue_pairs;		\
			txq = netdev_get_tx_queue(v->netdev, qp); \
			__netif_tx_lock(txq, cpu);				\
		}					\
		v->sq + qp;			\
	})

#define zxdh_en_xdp_put_sq(en_dev, q)	\
	{									\
		struct netdev_queue *txq;		\
		typeof(en_dev) v = (en_dev);	\
										\
		txq = netdev_get_tx_queue(v->netdev, (q)-v->sq); \
		if (v->curr_queue_pairs > nr_cpu_ids) \
			__netif_tx_release(txq);	\
		else							\
			__netif_tx_unlock(txq);		\
	}

int zxdh_en_xdp_xmit(struct net_device *dev, int n, struct xdp_frame **frames, u32 flags)
{
	struct zxdh_en_priv *en_priv = netdev_priv(dev);
	struct zxdh_en_device *en_dev = &en_priv->edev;
	struct receive_queue *rq = en_dev->rq;
	struct bpf_prog *xdp_prog;
	struct send_queue *sq;
	unsigned int len;
	int packets = 0;
	int bytes = 0;
	int nxmit = 0;
	int kicks = 0;
	void *ptr;
	int ret;
	int i;

	/* Only allow ndo_xdp_xmit if XDP is loaded on dev, as this
	 * indicate XDP resources have been successfully allocated.
	 */
	xdp_prog = rcu_access_pointer(rq->xdp_prog);
	if (!xdp_prog)
		return -ENXIO;

	sq = zxdh_en_xdp_get_sq(en_dev);

	if (unlikely(flags & ~XDP_XMIT_FLAGS_MASK)) {
		ret = -EINVAL;
		goto out;
	}

	/* Free up any pending old buffers before queueing new ones. */
	while ((ptr = zxdh_virtqueue_get_buf(sq->vq, &len)) != NULL) {
		if (likely(is_xdp_frame(ptr))) {
			struct xdp_frame *frame = ptr_to_xdp(ptr);

			bytes += frame->len;
			xdp_return_frame(frame);
		} else {
			struct sk_buff *skb = ptr;

			bytes += skb->len;
			napi_consume_skb(skb, false);
		}
		packets++;
	}

	for (i = 0; i < n; i++) {
		struct xdp_frame *xdpf = frames[i];

		if (__zxdh_en_xdp_xmit_one(en_dev, sq, xdpf))
			break;
		nxmit++;
	}
	ret = nxmit;

	if (flags & XDP_XMIT_FLUSH) {
		if (virtqueue_kick_prepare_packed(sq->vq) && zxdh_virtqueue_notify(sq->vq))
			kicks = 1;
	}
out:
	u64_stats_update_begin(&sq->stats.syncp);
	sq->stats.bytes += bytes;
	sq->stats.packets += packets;
	sq->stats.xdp_tx += n;
	sq->stats.xdp_tx_drops += n - nxmit;
	sq->stats.kicks += kicks;
	u64_stats_update_end(&sq->stats.syncp);

	zxdh_en_xdp_put_sq(en_dev, sq);
	return ret;
}

static __always_inline void zxdh_xdp_init_buff(struct xdp_buff *xdp, u32 frame_sz,
					       struct xdp_rxq_info *rxq)
{
	xdp->frame_sz = frame_sz;
	xdp->rxq = rxq;
}

static __always_inline void zxdh_xdp_prepare_buff(struct xdp_buff *xdp, unsigned char *hard_start,
						  int headroom, int data_len, const bool meta_valid)
{
	unsigned char *data = hard_start + headroom;

	xdp->data_hard_start = hard_start;
	xdp->data = data;
	xdp->data_end = data + data_len;
	xdp->data_meta = meta_valid ? data : data + 1;
}

struct sk_buff *receive_mergeable(struct net_device *netdev, struct zxdh_en_device *en_dev,
				  struct receive_queue *rq, void *buf, void *ctx, u32 len,
				  u32 *xdp_xmit, struct virtnet_rq_stats *stats)
{
	struct zxdh_net_hdr_rx *hdr = buf;
	u16 num_buf = vqm16_to_cpu(en_dev, hdr->num_buffers);
	u16 hdr_len = hdr->pd_len * HDR_2B_UNIT;
	struct page *page = virt_to_head_page(buf);
	s32 offset = buf - page_address(page);
	struct sk_buff *head_skb = NULL;
	struct sk_buff *curr_skb = NULL;
	struct bpf_prog *xdp_prog;
	u32 truesize = mergeable_ctx_to_truesize(ctx);
	u32 headroom = mergeable_ctx_to_headroom(ctx);
	u32 metasize = 0;
	u32 frame_sz = 0;
	s32 err;

	stats->bytes += (len - hdr_len);
	netdev->stats.rx_bytes += (len - hdr_len);

	if (unlikely(len > truesize)) {
		LOG_ERR("%s: rx error: len %u exceeds truesize %lu\n", netdev->name, len,
			(unsigned long)ctx);
		netdev->stats.rx_length_errors++;
		netdev->stats.rx_errors++;
		goto err_skb;
	}

	if (likely(!en_dev->xdp_enabled)) {
		xdp_prog = NULL;
		goto skip_xdp;
	}

	rcu_read_lock();
	xdp_prog = rcu_dereference(rq->xdp_prog);
	if (xdp_prog) {
		struct xdp_frame *xdpf;
		struct page *xdp_page;
		struct xdp_buff xdp;
		void *data;
		u32 act;

		frame_sz = headroom ? PAGE_SIZE : truesize;

		if (unlikely(num_buf > 1 || headroom < zxdh_en_get_headroom(en_dev))) {
			/* linearize data for XDP */
			xdp_page = xdp_linearize_page(rq, &num_buf, page, offset, ZXDH_XDP_HEADROOM,
						      &len);
			frame_sz = PAGE_SIZE;

			if (!xdp_page)
				goto err_xdp;
			offset = ZXDH_XDP_HEADROOM;
		} else {
			xdp_page = page;
		}

		/* Allow consuming headroom but reserve enough space to push
		 * the descriptor on if we get an XDP_TX return code.
		 */
		data = page_address(xdp_page) + offset;

		zxdh_xdp_init_buff(&xdp, frame_sz - hdr_len, &rq->xdp_rxq);
		zxdh_xdp_prepare_buff(&xdp, data - ZXDH_XDP_HEADROOM + hdr_len, ZXDH_XDP_HEADROOM,
				      len - hdr_len, true);

		act = bpf_prog_run_xdp(xdp_prog, &xdp);
		stats->xdp_packets++;

		switch (act) {
		case XDP_PASS:
			metasize = xdp.data - xdp.data_meta;

			/* recalculate offset to account for any header
			 * adjustments and minus the metasize to copy the
			 * metadata in page_to_skb(). Note other cases do not
			 * build an skb and avoid using offset
			 */
			offset = xdp.data - page_address(xdp_page) - hdr_len - metasize;

			/* recalculate len if xdp.data, xdp.data_end or
			 * xdp.data_meta were adjusted
			 */
			len = xdp.data_end - xdp.data + hdr_len + metasize;
			/* We can only create skb based on xdp_page. */
			if (unlikely(xdp_page != page)) {
				rcu_read_unlock();
				put_page(page);
				head_skb = page_to_skb(en_dev, rq, xdp_page, offset, len, PAGE_SIZE,
						       metasize, ZXDH_XDP_HEADROOM);
				return head_skb;
			}
			break;
		case XDP_TX:
			stats->xdp_tx++;
			xdpf = xdp_convert_buff_to_frame(&xdp);
			if (unlikely(!xdpf))
				goto err_xdp;
			err = zxdh_en_xdp_xmit(netdev, 1, &xdpf, 0);
			if (unlikely(!err)) {
				xdp_return_frame_rx_napi(xdpf);
			} else if (unlikely(err < 0)) {
				trace_xdp_exception(en_dev->netdev, xdp_prog, act);
				if (unlikely(xdp_page != page))
					put_page(xdp_page);
				goto err_xdp;
			}
			*xdp_xmit |= ZXDH_XDP_TX;
			if (unlikely(xdp_page != page))
				put_page(page);
			rcu_read_unlock();
			goto xdp_xmit;
		case XDP_REDIRECT:
			stats->xdp_redirects++;
			err = xdp_do_redirect(netdev, &xdp, xdp_prog);
			if (err) {
				if (unlikely(xdp_page != page))
					put_page(xdp_page);
				goto err_xdp;
			}
			*xdp_xmit |= ZXDH_XDP_REDIR;
			if (unlikely(xdp_page != page))
				put_page(page);
			rcu_read_unlock();
			goto xdp_xmit;
		default:
			bpf_warn_invalid_xdp_action(en_dev->netdev, xdp_prog, act);
			if (unlikely(xdp_page != page))
				__free_pages(xdp_page, 0);
			goto err_xdp;
		case XDP_ABORTED:
		case XDP_DROP:
			if (unlikely(xdp_page != page))
				__free_pages(xdp_page, 0);
			goto err_xdp;
		}
	}
	rcu_read_unlock();

skip_xdp:
	head_skb = page_to_skb(en_dev, rq, page, offset, len, truesize, metasize, headroom);
	curr_skb = head_skb;

	if (unlikely(!curr_skb)) {
		LOG_ERR("page_to_skb is null\n");
		goto err_skb;
	}
	while (--num_buf) {
		s32 num_skb_frags;

		buf = virtqueue_get_buf_ctx_packed(rq->vq, &len, &ctx);
		if (unlikely(!buf)) {
			LOG_ERR("%s: rx error: %d buffers out of %d missing\n", netdev->name,
				num_buf, vqm16_to_cpu(en_dev, hdr->num_buffers));
			netdev->stats.rx_length_errors++;
			netdev->stats.rx_errors++;
			goto err_buf;
		}

		stats->bytes += len;
		page = virt_to_head_page(buf);

		truesize = mergeable_ctx_to_truesize(ctx);
		if (unlikely(len > truesize)) {
			LOG_ERR("%s: rx error: len %u exceeds truesize %lu\n", netdev->name, len,
				(unsigned long)ctx);
			netdev->stats.rx_length_errors++;
			netdev->stats.rx_errors++;
			goto err_skb;
		}

		num_skb_frags = skb_shinfo(curr_skb)->nr_frags;
		if (unlikely(num_skb_frags == MAX_SKB_FRAGS)) {
			struct sk_buff *nskb = alloc_skb(0, GFP_ATOMIC);

			if (unlikely(!nskb)) {
				LOG_ERR("alloc_skb is null\n");
				goto err_skb;
			}
			if (curr_skb == head_skb)
				skb_shinfo(curr_skb)->frag_list = nskb;
			else
				curr_skb->next = nskb;
			curr_skb = nskb;
			head_skb->truesize += nskb->truesize;
			num_skb_frags = 0;
		}

		if (curr_skb != head_skb) {
			head_skb->data_len += len;
			head_skb->len += len;
			head_skb->truesize += truesize;
		}
		offset = buf - page_address(page);

		if (skb_can_coalesce(curr_skb, num_skb_frags, page, offset)) {
			put_page(page);
			skb_coalesce_rx_frag(curr_skb, num_skb_frags - 1, len, truesize);
		} else {
			skb_add_rx_frag(curr_skb, num_skb_frags, page, offset, len, truesize);
		}
	}

	ewma_pkt_len_add(&rq->mrg_avg_pkt_len, head_skb->len);
	return head_skb;

err_xdp:
	rcu_read_unlock();
	stats->xdp_drops++;
err_skb:
	put_page(page);
	while (num_buf-- > 1) {
		buf = zxdh_virtqueue_get_buf(rq->vq, &len);
		if (unlikely(!buf)) {
			LOG_ERR("%s: rx error: %d buffers missing\n", netdev->name, num_buf);
			netdev->stats.rx_length_errors++;
			netdev->stats.rx_errors++;
			break;
		}
		stats->bytes += len;
		page = virt_to_head_page(buf);
		put_page(page);
	}
err_buf:
	stats->drops++;
	dev_kfree_skb(head_skb);
xdp_xmit:
	return NULL;
}

void pipd_receive_handle(struct net_device *netdev, struct sk_buff *skb,
			 struct zxdh_net_hdr_rx *hdr_rcv, struct virtnet_rq_stats *stats)
{
	struct zxdh_en_priv *en_priv = netdev_priv(netdev);
	struct zxdh_en_device *en_dev = &en_priv->edev;
	u16 cvid = 0;
	u16 svid = 0;
	u16 vid = 0;
	bool vlan_striped = false;

	/* rx packet contain the strip label & open rxvlan offloading*/
	vlan_striped = hdr_rcv->pipd_hdr.pd_hdr.flags & RX_VLAN_STRIPED_MASK;
	if ((netdev->features & NETIF_F_HW_VLAN_CTAG_RX) && vlan_striped) {
		cvid = htons(hdr_rcv->pipd_hdr.pd_hdr.striped_ctci) & RX_TPID_VLAN_ID_MASK;
		svid = htons(hdr_rcv->pipd_hdr.pd_hdr.striped_stci) & RX_TPID_VLAN_ID_MASK;
		vid = (hdr_rcv->pipd_hdr.pd_hdr.flags & RX_IS_QINQ_PKT_MASK) ? svid : cvid;
		__vlan_hwaccel_put_tag(skb, htons(ETH_P_8021Q), vid);
		stats->rx_removed_vlan_packets++;
	}

	if (netdev->features & NETIF_F_RXCSUM) {
		if (!(hdr_rcv->pipd_hdr.pi_hdr.error_code[1]) &&
		    !(hdr_rcv->pipd_hdr.pi_hdr.error_code[0]) &&
		    !(hdr_rcv->pipd_hdr.pd_hdr.flags & OUTER_IP_CHKSUM_ERROR_CODE)) {
			skb->ip_summed = CHECKSUM_UNNECESSARY;
			stats->rx_csum_offload_good++;
		} else {
			skb->ip_summed = CHECKSUM_NONE;
			en_dev->hw_stats.netdev_stats.rx_csum_offload_error++;
		}
	}
}

void pd_receive_handle(struct net_device *netdev, struct sk_buff *skb,
		       struct zxdh_net_hdr_rx *hdr_rcv, struct virtnet_rq_stats *stats)
{
	u16 cvid = 0;
	u16 svid = 0;
	u16 vid = 0;
	bool vlan_striped = false;

	/* rx packet contain the strip label & open rxvlan offloading*/
	vlan_striped = hdr_rcv->pd_hdr.flags & RX_VLAN_STRIPED_MASK;
	if ((netdev->features & NETIF_F_HW_VLAN_CTAG_RX) && vlan_striped) {
		cvid = htons(hdr_rcv->pd_hdr.striped_ctci) & RX_TPID_VLAN_ID_MASK;
		svid = htons(hdr_rcv->pd_hdr.striped_stci) & RX_TPID_VLAN_ID_MASK;
		vid = (hdr_rcv->pd_hdr.flags & RX_IS_QINQ_PKT_MASK) ? svid : cvid;
		__vlan_hwaccel_put_tag(skb, htons(ETH_P_8021Q), vid);
		stats->rx_removed_vlan_packets++;
	}
}

void receive_buf(struct zxdh_en_device *en_dev, struct receive_queue *rq, void *buf, u32 len,
		 void **ctx, u32 *xdp_xmit, struct virtnet_rq_stats *stats)
{
	struct net_device *netdev = en_dev->netdev;
	struct sk_buff *skb = NULL;
	struct zxdh_net_hdr_rx *hdr_rcv = (struct zxdh_net_hdr_rx *)buf;
	s32 ret = 0;
	struct zxdh_net_1588_hdr_rcv *hdr_rcv_1588 = NULL;
	struct zxdh_net_1588_nopi_hdr_rcv *hdr_rcv_nopi_1588 = NULL;
	u8 pd_len = 0;
	u8 pkt_flag = 0;
	u8 packet_to_file = 0;
	// struct iphdr *iph = NULL;
	// struct udphdr *udph = NULL;
	// __sum16 skb_sum = 0;
	DEBUG_1588("receive buf:");
	DEBUG_1588_DATA((u8 *)buf, len);

	pd_len = hdr_rcv->pd_len * HDR_2B_UNIT;
	DEBUG_1588("pd_len:%hhu", pd_len);

	if ((hdr_rcv->pd_hdr.flags & 0xff) == ZXDH_PKT_FLAG)
		pkt_flag = 1;

	if (unlikely(len < (hdr_rcv->pd_len * HDR_2B_UNIT) + ETH_HLEN)) {
		LOG_ERR("%s: short packet %i\n", netdev->name, len);
		netdev->stats.rx_length_errors++;
		netdev->stats.rx_errors++;
		pkt_packet_process(en_dev, buf, len, pkt_flag);
		goto ret_out;
	}

	get_page(virt_to_head_page(buf));

	skb = receive_mergeable(netdev, en_dev, rq, buf, ctx, len, xdp_xmit, stats);

	if (unlikely(!skb)) {
		LOG_ERR("skb receive_mergeable null\n");
		pkt_packet_process(en_dev, buf, len, pkt_flag);
		goto ret_out;
	}

	if (hdr_rcv->pd_len > ZXDH_HAS_PI_FLAG)
		pipd_receive_handle(netdev, skb, hdr_rcv, stats);
	else if (hdr_rcv->pd_len != ZXDH_TYPE_FLAG_LEN)
		pd_receive_handle(netdev, skb, hdr_rcv, stats);

	if (en_dev->enable_1588 == true) {
		if (pd_len == sizeof(struct zxdh_net_1588_hdr_rcv) ||
		    pd_len == sizeof(struct zxdh_net_1588_nopi_hdr_rcv)) {
			if (en_dev->dtp_drs_offload == true) {
				hdr_rcv_1588 = (struct zxdh_net_1588_hdr_rcv *)hdr_rcv;
				ret = pkt_1588_proc_rcv(skb, &(hdr_rcv_1588->pd_1588),
							en_dev->clock_no, en_dev);

				DEBUG_1588("vport 0x%x rx 1588 hdr :", en_dev->vport);
				DEBUG_1588_DATA((u8 *)hdr_rcv_1588,
						sizeof(struct zxdh_net_1588_hdr_rcv));
			} else {
				hdr_rcv_nopi_1588 = (struct zxdh_net_1588_nopi_hdr_rcv *)hdr_rcv;
				ret = pkt_1588_proc_rcv(skb, &(hdr_rcv_nopi_1588->pd_1588),
							en_dev->clock_no, en_dev);

				DEBUG_1588("vport 0x%x rx 1588 hdr nopi :", en_dev->vport);
				DEBUG_1588_DATA((u8 *)hdr_rcv_nopi_1588,
						sizeof(struct zxdh_net_1588_nopi_hdr_rcv));
			}

			if ((ret != PTP_SUCCESS) && (ret != IS_NOT_PTP_MSG)) {
				DEBUG_1588("dev %s vport 0x%x pkt_1588_proc_rcv !!!\n",
					   en_dev->netdev->name, en_dev->vport);
			}

			if (skb->ip_summed == CHECKSUM_NONE)
				skb->ip_summed = CHECKSUM_UNNECESSARY;

			DEBUG_1588("rx skb->data:");
			DEBUG_1588_DATA((u8 *)skb->data, skb->len);
		}
	}

	skb_record_rx_queue(skb, vq2rxq(rq->vq));
	packet_to_file = pkt_skb_packet_process(en_dev, skb, pkt_flag);
	skb->protocol = eth_type_trans(skb, netdev);

	if (packet_to_file == 0)
		napi_gro_receive(&rq->napi, skb);

ret_out:

	put_page(virt_to_head_page(buf));
}

/**
 * zxdh_virtqueue_notify - second half of split virtqueue_kick call.
 * @_vq: the struct virtqueue
 *
 * This does not need to be serialized.
 *
 * Returns false if host notify failed or queue is broken, otherwise true.
 */
bool zxdh_virtqueue_notify(struct virtqueue *_vq)
{
	struct vring_virtqueue *vq = to_vvq(_vq);

	if (unlikely(vq->broken)) {
		LOG_ERR("vq->broken\n");
		return false;
	}

	/* Prod other side to tell it about changes. */
	if (!vq->notify(_vq)) {
		LOG_ERR("vq->notify(_vq) failed\n");
		vq->broken = true;
		return false;
	}

	return true;
}

bool dh_skb_page_frag_refill(unsigned int sz, struct page_frag *pfrag, gfp_t gfp)
{
	if (pfrag->page) {
		if (page_ref_count(pfrag->page) == 1) {
			pfrag->offset = 0;
			return true;
		}
		if (pfrag->offset + sz <= pfrag->size)
			return true;
		put_page(pfrag->page);
	}
	pfrag->offset = 0;
	if (1) {
		/* Avoid direct reclaim but allow kswapd to wake */
		pfrag->page = alloc_pages((gfp & ~__GFP_DIRECT_RECLAIM) | __GFP_COMP |
						  __GFP_NOWARN | __GFP_NORETRY,
					  DH_SKB_FRAG_PAGE_ORDER);
		if (likely(pfrag->page)) {
			pfrag->size = PAGE_SIZE << DH_SKB_FRAG_PAGE_ORDER;
			return true;
		}
	}
	pfrag->page = alloc_page(gfp);
	if (likely(pfrag->page)) {
		pfrag->size = PAGE_SIZE;
		return true;
	}
	return false;
}

s32 add_recvbuf_mergeable(struct receive_queue *rq, gfp_t gfp)
{
	struct page_frag *alloc_frag = &rq->alloc_frag;
	u32 headroom = 0;
	u32 tailroom = 0;
	u32 room = SKB_DATA_ALIGN(headroom + tailroom);
	char *buf = NULL;
	void *ctx = NULL;
	s32 err = 0;
	u32 len = 0;
	u32 hole = 0;

	/* Extra tailroom is needed to satisfy XDP's assumption. This
	 * means rx frags coalescing won't work, but consider we've
	 * disabled GSO for XDP, it won't be a big issue.
	 */
	len = get_mergeable_buf_len(rq, &rq->mrg_avg_pkt_len, room);
	if (unlikely(!dh_skb_page_frag_refill(len + room, alloc_frag, gfp))) {
		LOG_ERR("dh_skb_page_frag_refill failed\n");
		return -ENOMEM;
	}

	buf = (char *)page_address(alloc_frag->page) + alloc_frag->offset;
	buf += headroom; /* advance address leaving hole at front of pkt */
	get_page(alloc_frag->page);
	alloc_frag->offset += len + room;
	hole = alloc_frag->size - alloc_frag->offset;
	if (hole < len + room) {
		/* To avoid internal fragmentation, if there is very likely not
		 * enough space for another buffer, add the remaining space to
		 * the current buffer.
		 */
		len += hole;
		alloc_frag->offset += hole;
	}

	sg_init_one(rq->sg, buf, len);
	ctx = mergeable_len_to_ctx(len, headroom);
	err = zxdh_virtqueue_add_inbuf_ctx(rq->vq, rq->sg, 1, buf, ctx, gfp);
	if (err < 0)
		put_page(virt_to_head_page(buf));

	return err;
}

/* Assuming a given event_idx value from the other side, if
 * we have just incremented index from old to new_idx,
 * should we trigger an event?
 */
s32 vring_need_event(__u16 event_idx, __u16 new_idx, __u16 old)
{
	/* Note: Xen has similar logic for notification hold-off
	 * in include/xen/interface/io/ring.h with req_event and req_prod
	 * corresponding to event_idx + 1 and new_idx respectively.
	 * Note also that req_event and req_prod in Xen start at 1,
	 * event indexes in custom queue start at 0.
	 */
	return (__u16)(new_idx - event_idx - 1) < (__u16)(new_idx - old);
}

bool virtqueue_kick_prepare_packed(struct virtqueue *_vq)
{
	struct vring_virtqueue *vq = to_vvq(_vq);
	u16 new = 0;
	u16 old = 0;
	u16 off_wrap = 0;
	u16 flags = 0;
	u16 wrap_counter = 0;
	u16 event_idx = 0;
	bool needs_kick = false;
	union {
		struct {
			__le16 off_wrap;
			__le16 flags;
		};
		u32 u32;
	} snapshot;

	START_USE(vq);

	/* We need to expose the new flags value before checking notification
	 * suppressions.
	 */
	vqm_mb(vq->weak_barriers);

	old = vq->packed.next_avail_idx - vq->num_added;
	new = vq->packed.next_avail_idx;
	vq->num_added = 0;

	snapshot.u32 = *(u32 *)vq->packed.vring.device;
	flags = le16_to_cpu(snapshot.flags);

	LAST_ADD_TIME_CHECK(vq);
	LAST_ADD_TIME_INVALID(vq);

	if (flags != VRING_PACKED_EVENT_FLAG_DESC) {
		needs_kick = (flags != VRING_PACKED_EVENT_FLAG_DISABLE);
		goto out;
	}

	off_wrap = le16_to_cpu(snapshot.off_wrap);

	wrap_counter = off_wrap >> VRING_PACKED_EVENT_F_WRAP_CTR;
	event_idx = off_wrap & ~(1 << VRING_PACKED_EVENT_F_WRAP_CTR);
	if (wrap_counter != vq->packed.avail_wrap_counter)
		event_idx -= vq->packed.vring.num;

	needs_kick = vring_need_event(event_idx, new, old);
out:
	END_USE(vq);
	return needs_kick;
}

/* Returns false if we couldn't fill entirely (OOM).
 *
 * Normally run in the receive path, but can also be run from ndo_open
 * before we're receiving packets, or from refill_work which is
 * careful to disable receiving (using napi_disable).
 */
bool try_fill_recv(struct receive_queue *rq, gfp_t gfp)
{
	s32 err = 0;
	bool oom = 0;
	unsigned long flags = 0;

	do {
		err = add_recvbuf_mergeable(rq, gfp);
		oom = err == -ENOMEM;
		if (err)
			break;
	} while (rq->vq->num_free);

	if (virtqueue_kick_prepare_packed(rq->vq) && zxdh_virtqueue_notify(rq->vq)) {
		flags = u64_stats_update_begin_irqsave(&rq->stats.syncp);
		rq->stats.kicks++;
		u64_stats_update_end_irqrestore(&rq->stats.syncp, flags);
	}

	return !oom;
}

s32 virtnet_receive(struct receive_queue *rq, s32 budget, u32 *xdp_xmit)
{
	struct zxdh_en_device *en_dev = rq->vq->en_dev;
	struct virtnet_rq_stats stats = {};
	u32 len = 0;
	void *buf = NULL;
	s32 i = 0;
	void *ctx = NULL;

	while (stats.packets < budget && (buf = virtqueue_get_buf_ctx_packed(rq->vq, &len, &ctx))) {
		receive_buf(en_dev, rq, buf, len, ctx, xdp_xmit, &stats);
		stats.packets++;
	}

	if (rq->vq->num_free > min_t(u32, budget, zxdh_virtqueue_get_vring_size(rq->vq)) / 2) {
		if (!try_fill_recv(rq, GFP_ATOMIC))
			schedule_delayed_work(&en_dev->refill, 0);
	}

	u64_stats_update_begin(&rq->stats.syncp);
	for (i = 0; i < VIRTNET_RQ_STATS_LEN; i++) {
		size_t offset = virtnet_rq_stats_desc[i].offset;
		u64 *item;

		item = (u64 *)((u8 *)&rq->stats + offset);
		*item += *(u64 *)((u8 *)&stats + offset);
	}
	u64_stats_update_end(&rq->stats.syncp);

	return stats.packets;
}

void virtqueue_napi_complete(struct napi_struct *napi, struct virtqueue *vq, s32 processed)
{
	s32 opaque = 0;

	opaque = zxdh_virtqueue_enable_cb_prepare(vq);
	if (napi_complete_done(napi, processed)) {
		if (unlikely(zxdh_virtqueue_poll(vq, opaque)))
			virtqueue_napi_schedule(napi, vq);
	} else {
		zxdh_virtqueue_disable_cb(vq);
	}
}

int virtnet_poll(struct napi_struct *napi, int budget)
{
	struct receive_queue *rq = container_of(napi, struct receive_queue, napi);
	struct zxdh_en_device *en_dev = rq->vq->en_dev;
	struct send_queue *sq;
	u32 received = 0;
	u32 xdp_xmit = 0;

	virtnet_poll_cleantx(rq);

	received = virtnet_receive(rq, budget, &xdp_xmit);

	/* Out of packets? */
	if (received < budget)
		virtqueue_napi_complete(napi, rq->vq, received);

	if (xdp_xmit & ZXDH_XDP_REDIR)
		xdp_do_flush();

	if (xdp_xmit & ZXDH_XDP_TX) {
		sq = zxdh_en_xdp_get_sq(en_dev);
		if (virtqueue_kick_prepare_packed(sq->vq) && zxdh_virtqueue_notify(sq->vq)) {
			u64_stats_update_begin(&sq->stats.syncp);
			sq->stats.kicks++;
			u64_stats_update_end(&sq->stats.syncp);
		}
		zxdh_en_xdp_put_sq(en_dev, sq);
	}

	return received;
}

s32 virtnet_alloc_queues(struct zxdh_en_device *en_dev)
{
	s32 i = 0;

	en_dev->sq = kcalloc(en_dev->max_queue_pairs, sizeof(*en_dev->sq), GFP_KERNEL);
	if (unlikely(!en_dev->sq)) {
		LOG_ERR("en_dev->sq kcalloc failed\n");
		goto err_sq;
	}

	en_dev->rq = kcalloc(en_dev->max_queue_pairs, sizeof(*en_dev->rq), GFP_KERNEL);
	if (unlikely(!en_dev->rq)) {
		LOG_ERR("en_dev->rq kcalloc failed\n");
		goto err_rq;
	}

	INIT_DELAYED_WORK(&en_dev->refill, refill_work);

	for (i = 0; i < en_dev->curr_queue_pairs; i++) {
		en_dev->rq[i].pages = NULL;

		netif_napi_add(en_dev->netdev, &en_dev->rq[i].napi, virtnet_poll);
		netif_napi_add_tx_weight(en_dev->netdev, &en_dev->sq[i].napi, virtnet_poll_tx,
					 NAPI_POLL_WEIGHT);
		sg_init_table(en_dev->rq[i].sg, ARRAY_SIZE(en_dev->rq[i].sg));
		ewma_pkt_len_init(&en_dev->rq[i].mrg_avg_pkt_len);
		sg_init_table(en_dev->sq[i].sg, ARRAY_SIZE(en_dev->sq[i].sg));

		u64_stats_init(&en_dev->rq[i].stats.syncp);
		u64_stats_init(&en_dev->sq[i].stats.syncp);
	}

	return 0;

err_rq:
	kfree(en_dev->sq);
	en_dev->sq = NULL;
err_sq:
	return -ENOMEM;
}

/**
 * virtqueue_set_affinity - setting affinity for a virtqueue
 * @vq: the virtqueue
 * @cpu_mask: the cpu no.
 *
 * Pay attention the function are best-effort: the affinity hint may not be set
 * due to config support, irq type and sharing.
 *
 */
s32 virtqueue_set_affinity(struct virtqueue *vq, const struct cpumask *cpu_mask)
{
	if (!vq->callback) {
		LOG_ERR("vq->callback is null\n");
		return -EINVAL;
	}

	return 0;
}

void refill_work(struct work_struct *work)
{
	s32 i = 0;
	bool still_empty = false;
	struct zxdh_en_device *en_dev = container_of(work, struct zxdh_en_device, refill.work);

	for (i = 0; i < en_dev->curr_queue_pairs; i++) {
		struct receive_queue *rq = &en_dev->rq[i];

		napi_disable(&rq->napi);
		still_empty = !try_fill_recv(rq, GFP_KERNEL);
		virtnet_napi_enable(rq->vq, &rq->napi);

		/* In theory, this can happen: if we don't get any buffers in
		 * we will *never* try to fill again.
		 */
		if (still_empty)
			schedule_delayed_work(&en_dev->refill, HZ / 2);
	}
}

s32 dh_eq_vqs_vring_int(struct notifier_block *nb, unsigned long action, void *data)
{
	struct dh_eq_vq *eq_vq = container_of(nb, struct dh_eq_vq, irq_nb);
	struct dh_eq_vqs *eq_vqs = container_of(eq_vq, struct dh_eq_vqs, vq_s);
	struct list_head *item = NULL;
	struct zxdh_pci_vq_info *info = NULL;
	struct vring_virtqueue *vq = NULL;
	struct zxdh_en_device *en_dev = NULL;
	unsigned long flags;

	en_dev = (struct zxdh_en_device *)data;
	spin_lock_irqsave(&en_dev->lock, flags);

	list_for_each(item, &eq_vqs->vqs) {
		info = list_entry(item, struct zxdh_pci_vq_info, node);

		vq = to_vvq(info->vq);
		if (!more_used_packed(vq))
			continue;

		if (unlikely(vq->broken)) {
			LOG_ERR("vq:%d is broken\n", info->vq->phy_index);
			continue;
		}

		/* Just a hint for performance: so it's ok that this can be racy! */
		if (vq->event)
			vq->event_triggered = true;

		if (vq->vq.callback)
			vq->vq.callback(&vq->vq);
	}

	spin_unlock_irqrestore(&en_dev->lock, flags);

	return 0;
}

s32 vp_get_phy_vqs(struct net_device *netdev, u16 vq_cnt, u32 *phy_index, const char *type)
{
	struct zxdh_en_priv *en_priv = netdev_priv(netdev);
	struct zxdh_en_device *en_dev = &en_priv->edev;
	u16 fw_patch = en_dev->ops->get_fw_patch(en_dev->parent);
	s32 err = 0;
	union zxdh_msg *old_msg = NULL;
	u32 i = 0;
#ifdef ZXDH_MSGQ
	bool need_msgq = false;
#endif
	unsigned long flags = 0;

	if (vq_cnt > ZXDH_MAX_QUEUES_NUM) {
		LOG_ERR("Too many vqs: vq_cnt=%d out of rang:%d", vq_cnt, ZXDH_MAX_QUEUES_NUM);
		return -1;
	}

	if (fw_patch < DH_NEW_QUEEU_ALLOC_PATCH) {
		old_msg = kzalloc(sizeof(union zxdh_msg), GFP_KERNEL);
		if (!old_msg) {
			LOG_ERR("kzalloc(%lu, GFP_KERNEL) failed !", sizeof(union zxdh_msg));
			return -1;
		}

		/* if bond device, read queue already used */
		if (en_dev->ops->is_bond(en_dev->parent)) {
			LOG_DEBUG("Start get_common_table_msg!!!");
			err = get_common_table_msg(en_dev, en_dev->pcie_id, OP_CODE_DATA_CHAN,
						   old_msg);
			if (err != 0) {
				LOG_ERR("Failed to get bond device queue information: %d\n", err);
				kfree(old_msg);
				return -1;
			}

			LOG_DEBUG("old_msg->reps.cmn_vq_msg.queue_nums=%u",
				  old_msg->reps.cmn_vq_msg.queue_nums);
			for (i = 0; i < old_msg->reps.cmn_vq_msg.queue_nums; i++) {
				LOG_DEBUG("old_msg->reps.cmn_vq_msg.phy_qidx[%u]: %u", i,
					  old_msg->reps.cmn_vq_msg.phy_qidx[i]);
			}
		}
	}

	if (fw_patch >= DH_NEW_QUEEU_ALLOC_PATCH) {
		local_irq_save(flags);
		preempt_disable();
	}

	/* get phy vq lock */
	err = en_dev->ops->get_vq_lock(en_dev->parent);
	if (err < 0)
		goto err_get_lock;

	/* find valid vqs */
	err = en_dev->ops->find_valid_vqs(en_dev->parent, vq_cnt, phy_index);
	if (err < 0)
		goto err_find_valid_vqs;

	/* write common list */
	if (fw_patch < DH_NEW_QUEEU_ALLOC_PATCH) {
		err = zxdh_common_tbl_init(netdev, old_msg);
	} else {
#ifdef ZXDH_MSGQ
		if (NEED_MSGQ(en_dev))
			need_msgq = true;
#endif
		err = en_dev->ops->write_queue_tlb(en_dev->parent, vq_cnt, phy_index, need_msgq);
	}
	if (err != 0)
		goto err_find_valid_vqs;

	/* write vq list */
	en_dev->ops->write_vqs_bit(en_dev->parent, vq_cnt, phy_index);

err_find_valid_vqs:
	/* release phy vq lock */
	en_dev->ops->release_vq_lock(en_dev->parent);
err_get_lock:
	if (fw_patch < DH_NEW_QUEEU_ALLOC_PATCH)
		kfree(old_msg);

	if (fw_patch >= DH_NEW_QUEEU_ALLOC_PATCH) {
		preempt_enable();
		local_irq_restore(flags);
	}

	pr_info("[zxdh_pf][%s][%d] %s phy_index: ", __func__, __LINE__, type);
	for (i = 0; i < vq_cnt; i++)
		pr_info("%u ", phy_index[i]);
	pr_info("\n");

	return err;
}

s32 vp_find_vqs_msix(struct net_device *netdev, unsigned int nvqs, struct virtqueue *vqs[],
		     vq_callback_t *callbacks[], const char *const names[], const bool *ctx)
{
	struct zxdh_en_priv *en_priv = netdev_priv(netdev);
	struct zxdh_en_device *en_dev = &en_priv->edev;
	s32 err = 0;
	u16 qidx = 0;

	en_dev->vqs = kcalloc(nvqs, sizeof(*en_dev->vqs), GFP_KERNEL);
	if (unlikely(!en_dev->vqs)) {
		LOG_ERR("en_dev->vqs kcalloc failed\n");
		return -ENOMEM;
	}

	err = vp_get_phy_vqs(netdev, nvqs, en_dev->phy_index, "std");
	if (err < 0) {
		LOG_ERR("get vq phy lock failed!");
		goto err_find_vq;
	}

	for (qidx = 0; qidx < nvqs; ++qidx) {
		vqs[qidx] = vp_setup_vq(netdev, qidx, callbacks[qidx], names[qidx],
					ctx ? ctx[qidx] : false, qidx);
		if (IS_ERR_OR_NULL(vqs[qidx])) {
			err = PTR_ERR(vqs[qidx]);
			LOG_ERR("vp_setup_vq failed: %d\n", err);
			goto err_setup_vq;
		}

		en_dev->ops->set_queue_enable(en_dev->parent, en_dev->phy_index[qidx], true);
	}
	return 0;

err_setup_vq:
	zxdh_vp_reset(netdev);
err_find_vq:
	zxdh_vp_del_vqs(netdev);
	return err;
}

void zxdh_en_recv_pkts(struct virtqueue *rvq)
{
	struct zxdh_en_device *en_dev = rvq->en_dev;
	struct receive_queue *rq = &en_dev->rq[vq2rxq(rvq)];

	virtqueue_napi_schedule(&rq->napi, rvq);
}

void zxdh_en_xmit_pkts(struct virtqueue *tvq)
{
	struct zxdh_en_device *en_dev = tvq->en_dev;
	struct napi_struct *napi = &en_dev->sq[vq2txq(tvq)].napi;

	/* Suppress further interrupts. */
	zxdh_virtqueue_disable_cb(tvq);

	if (napi->weight) {
		virtqueue_napi_schedule(napi, tvq);
	} else {
		/* We were probably waiting for more output buffers. */
		netif_wake_subqueue(en_dev->netdev, vq2txq(tvq));
		en_dev->hw_stats.q_stats[vq2txq(tvq)].q_tx_wake++;
	}
}

void zxdh_free_hdr_buf(struct zxdh_en_device *en_dev)
{
	s32 i = 0;

	for (i = 0; i < en_dev->max_queue_pairs; i++)
		kfree(en_dev->sq[i].hdr_buf);
}

s32 zxdh_alloc_hdr_buf(struct zxdh_en_device *en_dev)
{
	s32 i = 0;

	for (i = 0; i < en_dev->max_queue_pairs; i++) {
		en_dev->sq[i].hdr_idx = 0;
		en_dev->sq[i].hdr_buf =
			kzalloc(ZXDH_PF_MAX_DESC_NUM(en_dev) * HDR_BUFFER_LEN, GFP_KERNEL);
		if (!en_dev->sq[i].hdr_buf) {
			LOG_ERR("en_dev->sq[%d].hdr_buf kzalloc failed\n", i);
			zxdh_free_hdr_buf(en_dev);
			return -1;
		}
	}

	return 0;
}

s32 virtnet_find_vqs(struct zxdh_en_device *en_dev)
{
	vq_callback_t **callbacks = NULL;
	struct virtqueue **vqs = NULL;
	s32 ret = -ENOMEM;
	s32 i = 0;
	s32 total_vqs = 0;
	const char **names = NULL;
	bool *ctx = NULL;

	total_vqs = en_dev->max_queue_pairs * 2;

	/* Allocate space for find_vqs parameters */
	vqs = kcalloc(total_vqs, sizeof(*vqs), GFP_KERNEL);
	if (unlikely(!vqs)) {
		LOG_ERR("vqs kcalloc failed\n");
		goto err_vq;
	}

	callbacks = kmalloc_array(total_vqs, sizeof(*callbacks), GFP_KERNEL);
	if (unlikely(!callbacks)) {
		LOG_ERR("callbacks kmalloc_array failed\n");
		goto err_callback;
	}

	names = kmalloc_array(total_vqs, sizeof(*names), GFP_KERNEL);
	if (unlikely(!names)) {
		LOG_ERR("names kmalloc_array failed\n");
		goto err_names;
	}

	ctx = kcalloc(total_vqs, sizeof(*ctx), GFP_KERNEL);
	if (unlikely(!ctx)) {
		LOG_ERR("ctx kmalloc failed\n");
		goto err_ctx;
	}

	/* Allocate/initialize parameters for services send/receive virtqueues */
	for (i = 0; i < en_dev->max_queue_pairs; i++) {
		callbacks[rxq2vq(i)] = zxdh_en_recv_pkts;
		callbacks[txq2vq(i)] = zxdh_en_xmit_pkts;
		scnprintf(en_dev->rq[i].name, sizeof(en_dev->rq[i].name), "input.%d", i);
		scnprintf(en_dev->sq[i].name, sizeof(en_dev->sq[i].name), "output.%d", i);
		names[rxq2vq(i)] = en_dev->rq[i].name;
		names[txq2vq(i)] = en_dev->sq[i].name;
		if (ctx)
			ctx[rxq2vq(i)] = true;
	}

#ifdef ZXDH_MSGQ
	if (NEED_MSGQ(en_dev))
		callbacks[txq2vq(en_dev->max_queue_pairs - 1)] = NULL;
#endif

	ret = vp_find_vqs_msix(en_dev->netdev, total_vqs, vqs, callbacks, names, ctx);
	if (ret) {
		LOG_ERR("vp_find_vqs_msix failed: %d\n", ret);
		goto err_find;
	}

	for (i = 0; i < en_dev->max_queue_pairs; i++) {
		en_dev->rq[i].vq = vqs[rxq2vq(i)];
		en_dev->sq[i].vq = vqs[txq2vq(i)];
	}

err_find:
	kfree(ctx);
	ctx = NULL;
err_ctx:
	kfree(names);
	names = NULL;
err_names:
	kfree(callbacks);
	callbacks = NULL;
err_callback:
	kfree(vqs);
	vqs = NULL;
err_vq:
	return ret;
}

void virtnet_free_queues(struct zxdh_en_device *en_dev)
{
	s32 i = 0;
	u16 qpairs = 0;

	qpairs = en_dev->max_queue_pairs;
#ifdef ZXDH_MSGQ
	if (NEED_MSGQ(en_dev))
		--qpairs;
#endif

	for (i = 0; i < qpairs; i++) {
		netif_napi_del(&en_dev->rq[i].napi);
		netif_napi_del(&en_dev->sq[i].napi);
	}

	/* We called __netif_napi_del(),
	 * we need to respect an RCU grace period before freeing zxdev->rq
	 */
	synchronize_net();

	kfree(en_dev->rq);
	kfree(en_dev->sq);
}

void *virtqueue_detach_unused_buf_packed(struct virtqueue *_vq)
{
	struct vring_virtqueue *vq = to_vvq(_vq);
	u32 i = 0;
	void *buf = NULL;

	START_USE(vq);

	for (i = 0; i < vq->packed.vring.num; i++) {
		if (!vq->packed.desc_state[i].data)
			continue;

		/* detach_buf clears data, so grab it now. */
		buf = vq->packed.desc_state[i].data;
		detach_buf_packed(vq, i, NULL);
		END_USE(vq);
		return buf;
	}

	/* That should have freed everything. */
	if (WARN_ON(vq->vq.num_free != vq->packed.vring.num))
		return NULL;

	END_USE(vq);
	return NULL;
}

void zxdh_free_unused_bufs(struct net_device *netdev)
{
	struct zxdh_en_priv *en_priv = netdev_priv(netdev);
	struct zxdh_en_device *en_dev = &en_priv->edev;
	struct virtqueue *vq = NULL;
	void *buf = NULL;
	s32 i = 0;

	for (i = 0; i < en_dev->max_queue_pairs; i++) {
		vq = en_dev->sq[i].vq;
		while ((buf = virtqueue_detach_unused_buf_packed(vq)) != NULL) {
#ifdef ZXDH_MSGQ
			if (i == (en_dev->max_queue_pairs - 1)) {
				if (NEED_MSGQ(en_dev)) {
					ZXDH_FREE_PTR(buf);
					continue;
				}
			}
#endif
			if (!is_xdp_frame(buf))
				dev_kfree_skb(buf);
			else
				xdp_return_frame(ptr_to_xdp(buf));
		}
	}

	for (i = 0; i < en_dev->max_queue_pairs; i++) {
		vq = en_dev->rq[i].vq;
		while ((buf = virtqueue_detach_unused_buf_packed(vq)) != NULL)
			put_page(virt_to_head_page(buf));
	}
}

struct page *get_a_page(struct receive_queue *rq, gfp_t gfp_mask)
{
	struct page *p = rq->pages;

	if (p) {
		rq->pages = (struct page *)p->private;
		/* clear private here, it is used to chain pages */
		p->private = 0;
	} else {
		p = alloc_page(gfp_mask);
	}
	return p;
}

void _free_receive_bufs(struct zxdh_en_device *en_dev)
{
	struct bpf_prog *old_prog = NULL;
	s32 i = 0;

	for (i = 0; i < en_dev->max_queue_pairs; i++) {
		while (en_dev->rq[i].pages) {
			__free_pages(get_a_page(&en_dev->rq[i], GFP_KERNEL), 0);

			old_prog = rtnl_dereference(en_dev->rq[i].xdp_prog);
			RCU_INIT_POINTER(en_dev->rq[i].xdp_prog, NULL);
			if (old_prog)
				bpf_prog_put(old_prog);
		}
	}
}

void zxdh_free_receive_bufs(struct net_device *netdev)
{
	struct zxdh_en_priv *en_priv = netdev_priv(netdev);
	struct zxdh_en_device *en_dev = &en_priv->edev;

	rtnl_lock();
	_free_receive_bufs(en_dev);
	rtnl_unlock();
}

void zxdh_free_receive_page_frags(struct net_device *netdev)
{
	struct zxdh_en_priv *en_priv = netdev_priv(netdev);
	struct zxdh_en_device *en_dev = &en_priv->edev;
	s32 i = 0;

	for (i = 0; i < en_dev->max_queue_pairs; i++) {
		if (en_dev->rq[i].alloc_frag.page)
			put_page(en_dev->rq[i].alloc_frag.page);
	}
}

void zxdh_virtnet_del_vqs(struct net_device *netdev)
{
	struct zxdh_en_priv *en_priv = netdev_priv(netdev);
	struct zxdh_en_device *en_dev = &en_priv->edev;

	zxdh_vp_del_vqs(netdev);
	en_dev->ops->vqs_unbind_eqs(en_dev->parent, (en_dev->max_queue_pairs * 2 - 1));
	en_dev->ops->vqs_channel_unbind_handler(en_dev->parent, (en_dev->max_queue_pairs * 2 - 1));
	virtnet_free_queues(en_dev);
}

void zxdh_sec_release_vqs(struct net_device *netdev, struct zxdh_sec_info *sec_info, u8 qidx)
{
	struct zxdh_en_priv *en_priv = netdev_priv(netdev);
	struct zxdh_en_device *en_dev = &en_priv->edev;

	en_dev->ops->vp_modern_unmap_vq_notify(
		en_dev->parent, (void __iomem __force *)sec_info[qidx].notify_phy_addr);
	dma_free_coherent(en_dev->dmadev, sec_info[qidx].event_size_in_bytes, sec_info[qidx].device,
			  sec_info[qidx].device_event_dma_addr);
	dma_free_coherent(en_dev->dmadev, sec_info[qidx].event_size_in_bytes, sec_info[qidx].driver,
			  sec_info[qidx].driver_event_dma_addr);
	dma_free_coherent(en_dev->dmadev, sec_info[qidx].ring_size_in_bytes, sec_info[qidx].desc,
			  sec_info[qidx].ring_dma_addr);
}

int8_t zxdh_sec_create_vqs(struct net_device *netdev, struct zxdh_sec_info *sec_info, u8 qidx)
{
	struct zxdh_en_priv *en_priv = netdev_priv(netdev);
	struct zxdh_en_device *en_dev = &en_priv->edev;
	struct vring_packed_desc *ring = NULL;
	struct vring_packed_desc_event *driver = NULL;
	struct vring_packed_desc_event *device = NULL;
	dma_addr_t ring_dma_addr;
	dma_addr_t driver_event_dma_addr;
	dma_addr_t device_event_dma_addr;
	size_t ring_size_in_bytes;
	size_t event_size_in_bytes;
	void *notify_addr = NULL;

	ring_size_in_bytes = ZXDH_SEC_MIN_DESC_NUM * sizeof(struct vring_packed_desc);
	ring = dma_alloc_coherent(en_dev->dmadev, ring_size_in_bytes, &ring_dma_addr,
				  GFP_KERNEL | __GFP_NOWARN | __GFP_ZERO);
	if (unlikely(!ring)) {
		LOG_ERR("ring dma_alloc_coherent failed\n");
		goto err_ring;
	}

	event_size_in_bytes = sizeof(struct vring_packed_desc_event);
	driver = dma_alloc_coherent(en_dev->dmadev, event_size_in_bytes, &driver_event_dma_addr,
				    GFP_KERNEL | __GFP_NOWARN | __GFP_ZERO);
	if (unlikely(!driver)) {
		LOG_ERR("driver dma_alloc_coherent failed\n");
		goto err_driver;
	}
	device = dma_alloc_coherent(en_dev->dmadev, event_size_in_bytes, &device_event_dma_addr,
				    GFP_KERNEL | __GFP_NOWARN | __GFP_ZERO);
	if (unlikely(!device)) {
		LOG_ERR("device dma_alloc_coherent failed\n");
		goto err_device;
	}

	en_dev->ops->activate_phy_vq(en_dev->parent, en_dev->sec_phy_index[qidx],
				     ZXDH_SEC_MIN_DESC_NUM, ring_dma_addr, driver_event_dma_addr,
				     device_event_dma_addr);
	notify_addr = (void __force *)en_dev->ops->vp_modern_map_vq_notify(
		en_dev->parent, en_dev->sec_phy_index[qidx], &en_dev->notify_phy_addr);
	if (unlikely(!notify_addr)) {
		LOG_ERR("vp_modern_map_vq_notify failed\n");
		goto err_map_notify;
	}
	en_dev->ops->vq_unbind_channel(en_dev->parent, en_dev->sec_phy_index[qidx]);
	en_dev->ops->set_queue_enable(en_dev->parent, en_dev->sec_phy_index[qidx], true);

	sec_info[qidx].ring_dma_addr = ring_dma_addr;
	sec_info[qidx].driver_event_dma_addr = driver_event_dma_addr;
	sec_info[qidx].device_event_dma_addr = device_event_dma_addr;

	sec_info[qidx].desc = ring;
	sec_info[qidx].driver = driver;
	sec_info[qidx].device = device;

	sec_info[qidx].ring_size_in_bytes = ring_size_in_bytes;
	sec_info[qidx].event_size_in_bytes = event_size_in_bytes;

	sec_info[qidx].desc_num = ZXDH_SEC_MIN_DESC_NUM;
	sec_info[qidx].queue_pairs = ZXDH_SEC_QUEUES_NUM(en_dev) / 2;
	sec_info[qidx].phy_index = en_dev->sec_phy_index[qidx];
	sec_info[qidx].notify_phy_addr = en_dev->notify_phy_addr;

	sec_info[qidx].bar0_phy_addr = en_dev->ops->get_bar_phy_addr(en_dev->parent, 0);
	sec_info[qidx].bar0_vir_addr = en_dev->ops->get_bar_virt_addr(en_dev->parent, 0);
	sec_info[qidx].bar0_size = en_dev->ops->get_bar_size(en_dev->parent, 0);
	sec_info[qidx].pcie_id = en_dev->ops->get_pcie_id(en_dev->parent);
	sec_info[qidx].pdev = en_dev->ops->get_pdev(en_dev->parent);

	return 0;

err_map_notify:
	dma_free_coherent(en_dev->dmadev, event_size_in_bytes, device, device_event_dma_addr);
err_device:
	dma_free_coherent(en_dev->dmadev, event_size_in_bytes, driver, driver_event_dma_addr);
err_driver:
	dma_free_coherent(en_dev->dmadev, ring_size_in_bytes, ring, ring_dma_addr);
err_ring:
	return -1;
}

void zxdh_sec_vqs_uninit(struct net_device *netdev, u8 qidx)
{
	struct zxdh_en_priv *en_priv = netdev_priv(netdev);
	struct zxdh_en_device *en_dev = &en_priv->edev;
	u8 i = 0;

	for (i = 0; i < qidx; i++)
		zxdh_sec_release_vqs(netdev, en_dev->sec_info, i);
}

s32 zxdh_sec_vqs_init(struct net_device *netdev)
{
	struct zxdh_en_priv *en_priv = netdev_priv(netdev);
	struct zxdh_en_device *en_dev = &en_priv->edev;
	u8 qidx = 0;
	s32 err = 0;

	en_dev->sec_info =
		kcalloc(ZXDH_SEC_QUEUES_NUM(en_dev), sizeof(struct zxdh_sec_info), GFP_KERNEL);
	if (unlikely(!en_dev->sec_info)) {
		LOG_ERR("sec_info kzalloc failed\n");
		return -1;
	}

	err = vp_get_phy_vqs(netdev, ZXDH_SEC_QUEUES_NUM(en_dev), en_dev->sec_phy_index, "sec");
	if (err < 0) {
		LOG_ERR("get vq phy lock failed!");
		goto err_find_vq;
	}

	for (qidx = 0; qidx < ZXDH_SEC_QUEUES_NUM(en_dev); qidx++) {
		err = zxdh_sec_create_vqs(netdev, en_dev->sec_info, qidx);
		if (err != 0) {
			LOG_ERR("zxdh_sec_create_vqs failed: %d\n", err);
			goto err_create_vqs;
		}
	}

	en_dev->ops->set_sec_info(en_dev->parent, en_dev->sec_info);

	return 0;

err_create_vqs:
	zxdh_sec_vqs_uninit(netdev, qidx);
err_find_vq:
	kfree(en_dev->sec_info);
	return -1;
}

void zxdh_vqs_uninit(struct net_device *netdev)
{
	struct zxdh_en_priv *en_priv = netdev_priv(netdev);
	struct zxdh_en_device *en_dev = &en_priv->edev;

	if (en_dev->device_state != ZXDH_DEVICE_STATE_INTERNAL_ERROR && !en_dev->quick_remove)
		zxdh_vp_reset(netdev);

	cancel_delayed_work_sync(&en_dev->refill);
	zxdh_free_unused_bufs(netdev);
	zxdh_free_receive_bufs(netdev);
	zxdh_free_receive_page_frags(netdev);
	zxdh_free_hdr_buf(en_dev);
	zxdh_virtnet_del_vqs(netdev);
}

void zxdh_set_default_xps_cpumasks(struct zxdh_en_device *en_dev)
{
	u16 queue_pairs = en_dev->curr_queue_pairs;
	cpumask_var_t xps_mask;
	int i;
	int numa = dev_to_node(en_dev->dmadev);

	if (queue_pairs == 0) {
		LOG_INFO("en_dev->curr_queue_pairs is 0\n");
		return;
	}

	if (!zalloc_cpumask_var(&xps_mask, GFP_KERNEL)) {
		LOG_ERR("zalloc_cpumask_var failed for xps_mask\n");
		return;
	}

	for (i = 0; i < queue_pairs; i++) {
		cpumask_set_cpu(cpumask_local_spread(i, numa), xps_mask);

		netif_set_xps_queue(en_dev->netdev, xps_mask, i);
		cpumask_clear(xps_mask);
	}

	free_cpumask_var(xps_mask);
}

s32 zxdh_vqs_init(struct net_device *netdev)
{
	struct zxdh_en_priv *en_priv = netdev_priv(netdev);
	struct zxdh_en_device *en_dev = &en_priv->edev;
	s32 ret = 0;

	zxdh_netdev_features_over_dtp(netdev);
	en_dev->hdr_len = sizeof(struct zxdh_net_hdr_tx);
	if (en_dev->dtp_drs_offload == false)
		en_dev->hdr_len = sizeof(struct zxdh_net_hdr_tx) - sizeof(struct pi_hdr);

	en_dev->any_header_sg = zxdh_has_feature(en_dev, ZXDH_F_ANY_LAYOUT);
	en_dev->mergeable_rx_bufs = zxdh_has_feature(en_dev, ZXDH_NET_F_MRG_RXBUF);
	en_dev->netdev->needed_headroom = sizeof(struct zxdh_net_hdr_rx);
	en_dev->max_queue_pairs = en_dev->max_vq_pairs;
	en_dev->curr_queue_pairs = en_dev->max_queue_pairs;
	memset(en_dev->phy_index, 0xFF, sizeof(en_dev->phy_index));

#ifdef ZXDH_MSGQ
	if (NEED_MSGQ(en_dev)) {
		en_dev->max_queue_pairs += ZXDH_PQ_PAIRS_NUM;
		LOG_INFO("Add msgq, update max_queue_pairs: %d\n", en_dev->max_queue_pairs);
	}
#endif

	INIT_LIST_HEAD(&en_dev->vqs_list);
	spin_lock_init(&en_dev->vqs_list_lock);

	INIT_LIST_HEAD(&en_dev->virtqueues);
	spin_lock_init(&en_dev->lock);

	/* Allocate services send & receive queues */
	ret = virtnet_alloc_queues(en_dev);
	if (ret) {
		LOG_ERR("virtnet_alloc_queues failed: %d\n", ret);
		return ret;
	}

	ret = zxdh_alloc_hdr_buf(en_dev);
	if (ret != 0) {
		LOG_ERR("zxdh_alloc_hdr_buf failed\n");
		goto err_alloc_hdr_buf;
	}

	ret = virtnet_find_vqs(en_dev);
	if (ret) {
		LOG_ERR("virtnet_find_vqs failed: %d\n", ret);
		goto err_find_vqs;
	}

	zxdh_set_default_xps_cpumasks(en_dev);

	rtnl_lock();
	netif_set_real_num_tx_queues(en_dev->netdev, en_dev->curr_queue_pairs);
	rtnl_unlock();
	rtnl_lock();
	netif_set_real_num_rx_queues(en_dev->netdev, en_dev->curr_queue_pairs);
	rtnl_unlock();

	return 0;

err_find_vqs:
	zxdh_free_hdr_buf(en_dev);
err_alloc_hdr_buf:
	virtnet_free_queues(en_dev);
	return ret;
}
