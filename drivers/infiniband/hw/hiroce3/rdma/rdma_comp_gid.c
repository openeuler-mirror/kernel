// SPDX-License-Identifier: GPL-2.0
// Copyright(c) 2024 Huawei Technologies Co., Ltd

#include <linux/module.h>
#include <linux/netdevice.h>

#include "hinic3_hw.h"
#include "rdma_comp.h"
#include "roce.h"
#include "roce_cqm_cmd.h"

static int rdma_update_gid(struct rdma_comp_priv *comp_priv,
	struct rdma_gid_entry *new_gid_entry, int port, int gid_index)
{
	struct tag_cqm_cmd_buf *cqm_cmd_inbuf = NULL;
	struct rdma_gid_update_inbuf *gid_update_inbuf = NULL;
	int ret;

	ret = roce3_cqm_cmd_zalloc_inoutbuf(comp_priv->hwdev, &cqm_cmd_inbuf,
		(u16)sizeof(struct rdma_gid_update_inbuf), NULL, 0);
	if (ret != 0) {
		pr_err("[ROCE, ERR] %s: Failed to alloc cqm_cmd_inoutbuf, ret(%d)\n",
			__func__, ret);
		return -ENOMEM;
	}

	gid_update_inbuf = (struct rdma_gid_update_inbuf *)cqm_cmd_inbuf->buf;
	gid_update_inbuf->port = cpu_to_be32((u32)port);
	gid_update_inbuf->com.index = cpu_to_be32((u32)gid_index);
	gid_update_inbuf->gid_entry.global.subnet_prefix = new_gid_entry->global.subnet_prefix;
	gid_update_inbuf->gid_entry.global.interface_id = new_gid_entry->global.interface_id;
	gid_update_inbuf->gid_entry.dw4.value = cpu_to_be32(new_gid_entry->dw4.value);
	gid_update_inbuf->gid_entry.dw6_h.value = cpu_to_be16(new_gid_entry->dw6_h.value);
	gid_update_inbuf->gid_entry.hdr_len_value = cpu_to_be32(new_gid_entry->hdr_len_value);
	gid_update_inbuf->com.dw0.bs.cmd_bitmask =
		cpu_to_be16(VERBS_CMD_TYPE_GID_BITMASK); //lint !e778

	memcpy(&gid_update_inbuf->gid_entry.smac[0], &new_gid_entry->smac[0], ETH_ALEN);

	pr_info("[ROCE] %s:gid_index:0x%x gid:0x%x %x %x %x %x %x %x %x\n",
		__func__, gid_update_inbuf->com.index,
		*((u32 *)(void *)new_gid_entry + 0),
		*((u32 *)(void *)new_gid_entry + 1), // 0 1 is gid array idx
		*((u32 *)(void *)new_gid_entry + 2),
		*((u32 *)(void *)new_gid_entry + 3), // 2 3 is gid array idx
		*((u32 *)(void *)new_gid_entry + 4),
		*((u32 *)(void *)new_gid_entry + 5), // 4 5 is gid array idx
		*((u32 *)(void *)new_gid_entry + 6),
		*((u32 *)(void *)new_gid_entry + 7)); // 6 7 is gid array idx
	ret = cqm_send_cmd_box(comp_priv->hwdev, HINIC3_MOD_ROCE,
		RDMA_ROCE_CMD_UPDATE_GID, cqm_cmd_inbuf, NULL, NULL,
		ROCE3_RDMA_CMD_TIME_OUT_A, HINIC3_CHANNEL_ROCE);
	if (ret != 0) {
		pr_err("%s: Send cmd update_gid failed, ret(%d)\n", __func__, ret);
		ret = -1;
	}

	roce3_cqm_cmd_free_inoutbuf(comp_priv->hwdev, cqm_cmd_inbuf, NULL);

	return ret;
}

int rdma_gid_entry_cmp(struct rdma_gid_entry *gid_tbl_entry, struct rdma_gid_entry *gid_entry)
{
	struct rdma_gid_entry entry1;
	struct rdma_gid_entry entry2;

	memcpy(&entry1, gid_tbl_entry, sizeof(struct rdma_gid_entry));
	memcpy(&entry2, gid_entry, sizeof(struct rdma_gid_entry));

	/* compare ip+vlan, compare after clear smac */
	memset((void *)entry1.smac, 0, sizeof(entry1.smac));
	memset((void *)entry2.smac, 0, sizeof(entry2.smac));
	return memcmp((void *)&entry1, (void *)&entry2, sizeof(struct rdma_gid_entry));
}

static int rdma_reset_gid(struct rdma_comp_priv *comp_priv, u32 port, u32 gid_num)
{
	int ret;
	struct tag_cqm_cmd_buf *cqm_cmd_inbuf = NULL;
	struct tag_roce_clear_gid *gid_clear_inbuf = NULL;

	ret = roce3_cqm_cmd_zalloc_inoutbuf(comp_priv->hwdev, &cqm_cmd_inbuf,
		(u16)sizeof(struct tag_roce_clear_gid), NULL, 0);
	if (ret != 0) {
		pr_err("[ROCE, ERR] %s: Failed to alloc cqm_cmd_inoutbuf, ret(%d)\n",
			__func__, ret);
		return -ENOMEM;
	}

	gid_clear_inbuf = (struct tag_roce_clear_gid *)cqm_cmd_inbuf->buf;
	gid_clear_inbuf->port = cpu_to_be32(port);
	gid_clear_inbuf->com.index = 0; // cpu_to_be32(gid_num);
	gid_clear_inbuf->com.dw0.bs.cmd_bitmask =
		cpu_to_be16(VERBS_CMD_TYPE_GID_BITMASK); //lint !e778

	ret = cqm_send_cmd_box(comp_priv->hwdev, HINIC3_MOD_ROCE,
		RDMA_ROCE_CMD_CLEAR_GID, cqm_cmd_inbuf, NULL, NULL,
		ROCE3_RDMA_CMD_TIME_OUT_A, HINIC3_CHANNEL_ROCE);
	if (ret != 0) {
		pr_err("%s: Send cmd clear_gid failed, ret(%d)\n", __func__, ret);
		ret = -1;
	}

	roce3_cqm_cmd_free_inoutbuf(comp_priv->hwdev, cqm_cmd_inbuf, NULL);

	return ret;
}

int roce3_rdma_update_gid_mac(void *hwdev, u32 port, struct rdma_gid_entry *gid_entry)
{
	struct rdma_comp_priv *comp_priv = NULL;
	struct rdma_gid_entry **gid_table = NULL;
	u32 gid_index = 0;
	int update_index = -1; /* -1 is initvalue, indicating no need to update */
	int ret = 0;

	if ((hwdev == NULL) || (gid_entry == NULL)) {
		pr_err("%s: Hwdev or gid_tbl is null\n", __func__);
		return -EINVAL;
	}
	comp_priv = get_rdma_comp_priv(hwdev);
	if (comp_priv == NULL) {
		pr_err("%s: Comp_priv is null\n", __func__);
		return -EINVAL;
	}
	/* port num index from zero */
	if (port >= comp_priv->rdma_cap.num_ports) {
		pr_err("%s: Input port(%d) is invalid\n", __func__, port);
		return -EINVAL;
	}
	/* invalid gid cause of with the head fe80:: of IPV6 */
	if (cpu_to_be64(gid_entry->global.subnet_prefix) == RDMA_DEFAULT_GID_SUBNET_PREFIX)
		return 0;

	gid_table = comp_priv->rdma_comp_res.gid_table;
	mutex_lock(&comp_priv->rdma_comp_res.mutex);
	/* loop all gid, ensure all gid cleared not exist */
	for (gid_index = 1; gid_index < comp_priv->rdma_cap.max_gid_per_port; gid_index++) {
		if (rdma_gid_entry_cmp(&gid_table[port][gid_index], gid_entry) == 0) {
			update_index = (int)gid_index;
			break;
		}
	}
	if (update_index > 0) {
		ret = rdma_update_gid(comp_priv, gid_entry, (int)port, update_index);
		if (ret != 0) {
			pr_err("%s: Update gid tbl failed, ret(%d)\n", __func__, ret);
			mutex_unlock(&comp_priv->rdma_comp_res.mutex);
			return ret;
		}
		/* update gid table after CMDQ */
		memcpy((void *)&gid_table[port][update_index], (void *)gid_entry,
			sizeof(*gid_entry));

		mutex_unlock(&comp_priv->rdma_comp_res.mutex);
		return 0;
	}
	mutex_unlock(&comp_priv->rdma_comp_res.mutex);
	return 0;
}

int roce3_rdma_update_gid(void *hwdev, u32 port, u32 update_index, struct rdma_gid_entry *gid_entry)
{
	int ret = 0;
	u32 port_num = 0;
	struct rdma_comp_priv *comp_priv = NULL;
	struct rdma_gid_entry **gid_table;

	if ((hwdev == NULL) || (gid_entry == NULL)) {
		pr_err("%s: Hwdev or gid_tbl is null\n", __func__);
		return -EINVAL;
	}

	comp_priv = get_rdma_comp_priv(hwdev);
	if (comp_priv == NULL) {
		pr_err("%s: Comp_priv is null\n", __func__);
		return -EINVAL;
	}

	gid_table = comp_priv->rdma_comp_res.gid_table;

	/* port start from zero */
	port_num = comp_priv->rdma_cap.num_ports;
	if (port >= port_num) {
		pr_err("%s: Input port(%d) is invalid\n", __func__, port);
		return -EINVAL;
	}

	mutex_lock(&comp_priv->rdma_comp_res.mutex);
	ret = rdma_update_gid(comp_priv, gid_entry, (int)port, (int)update_index);
	if (ret != 0) {
		pr_err("%s: Rdma_update_gid failed\n", __func__);
		mutex_unlock(&comp_priv->rdma_comp_res.mutex);
		return ret;
	}

	memcpy((void *)&gid_table[port][update_index], (void *)gid_entry, sizeof(*gid_entry));
	mutex_unlock(&comp_priv->rdma_comp_res.mutex);

	return 0;
}

int roce3_rdma_reset_gid_table(void *hwdev, u32 port)
{
	struct rdma_comp_priv *comp_priv = NULL;
	struct rdma_gid_entry **gid_table = NULL;
	int ret = 0;
	u32 gids_per_port = 0;

	if (hwdev == NULL) {
		pr_err("%s: Hwdev is null\n", __func__);
		return -EINVAL;
	}

	comp_priv = get_rdma_comp_priv(hwdev);
	if (comp_priv == NULL) {
		pr_err("%s: Comp_priv is null\n", __func__);
		return -EINVAL;
	}

	gid_table = comp_priv->rdma_comp_res.gid_table;
	if (gid_table == NULL) {
		pr_err("%s: Gid_table is null\n", __func__);
		return -EINVAL;
	}

	gids_per_port = comp_priv->rdma_cap.max_gid_per_port;
	if (gids_per_port == 0) {
		pr_err("%s: Gids_per_port(%d) is invalid\n", __func__, gids_per_port);
		return -EINVAL;
	}

	memset(&gid_table[port][0], 0,
		gids_per_port * sizeof(struct rdma_gid_entry));
	ret = rdma_reset_gid(comp_priv, port, gids_per_port);
	if (ret != 0) {
		pr_err("%s: Reset gid table failed, ret(%d)\n", __func__, ret);
		return ret;
	}

	return 0;
}

int roce3_rdma_get_gid(void *hwdev, u32 port, u32 gid_index, struct rdma_gid_entry *gid)
{
	struct rdma_service_cap *rdma_cap = NULL;
	struct rdma_comp_priv *comp_priv = NULL;

	if (hwdev == NULL) {
		pr_err("%s: Hwdev is null\n", __func__);
		return -EINVAL;
	}

	if (gid == NULL) {
		pr_err("%s: Gid is null\n", __func__);
		return -EINVAL;
	}

	comp_priv = get_rdma_comp_priv(hwdev);
	if (comp_priv == NULL) {
		pr_err("%s: Comp_priv is null\n", __func__);
		return -EINVAL;
	}

	rdma_cap = &comp_priv->rdma_cap;
	if (port < 1 || port > rdma_cap->num_ports) {
		pr_err("%s: Port(%d) invalid\n", __func__, port);
		return -EINVAL;
	}

	if (gid_index >= rdma_cap->max_gid_per_port) {
		pr_err("%s: gid_index(%d) invalid\n", __func__, gid_index);
		return -EINVAL;
	}

	memcpy((void *)gid, (void *)&comp_priv->rdma_comp_res.gid_table[port - 1][gid_index],
		sizeof(*gid));

	return 0;
}
