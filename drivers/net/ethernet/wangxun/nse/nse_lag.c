// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2018 - 2021 Beijing WangXun Technology Co., Ltd. */

/* Link Aggregation code */

#include "nse.h"
#include "nse_lib.h"
#include "nse_lag.h"
#include "nse_fltr.h"
#include <net/bonding.h>

static DEFINE_SPINLOCK(lag_lock);

/**
 * nse_aq_hw_lag - add/update/remove hw lag
 * @hw: pointer to the HW struct
 * @buf: pointer to the result buffer
 * @buf_size: length of the buffer available for response
 * @opc: hw lag population command type - pass in the command opcode
 * @cd: pointer to command details structure or NULL
 *
 */
enum nse_status
nse_aq_hw_lag(struct nse_hw *hw, void *buf, u16 buf_size,
		enum nse_adminq_opc_category_misc_subcodes opc,
		struct nse_sq_cd *cd)
{
	struct nse_aq_desc desc;
	enum nse_status status = NSE_SUCCESS;

	if (opc != NSE_AQ_OPC_ADD_HW_LAG &&
	    opc != NSE_AQ_OPC_UPDATE_HW_LAG &&
	    opc != NSE_AQ_OPC_REMOVE_HW_LAG &&
	    opc != NSE_AQ_OPC_HW_LAG_CFG_DROP &&
	    opc != NSE_AQ_OPC_GET_HW_LAG)
		return NSE_ERR_PARAM;

	nse_fill_dflt_direct_cmd_desc(&desc, NSE_AQ_OPC_CATEGORY_MISC, opc);

	status = nse_aq_send_cmd(hw, &desc, buf, buf_size, cd);
	if (opc != NSE_AQ_OPC_ADD_HW_LAG &&
	    hw->adminq.sq_last_status == NSE_AQ_RC_ENOENT)
		status = NSE_ERR_DOES_NOT_EXIST;

	return status;
}

/**
 * nse_lag_dev_get_netdev_idx - get idx pf in lag by netdev
 *
 * @ldev: nse lag struct for this chip
 * @ndev: netdev used to compare
 */
int nse_lag_dev_get_netdev_idx(struct nse_lag *ldev,
				struct net_device *ndev)
{
	int i;

	for (i = 0; i < ldev->ports; i++)
		if (ldev->lag_func[i].netdev == ndev)
			return i;

	return -ENOENT;
}

/**
 * nse_lag_is_ready - whether is lag active or not
 *		lag is woring in sriov or roce lag mode
 *
 * @ldev: nse lag struct for this chip
 */
bool
nse_lag_is_active(struct nse_lag *ldev)
{
	return ldev->mode != NSE_LAG_MODE_NONE;
}

/**
 * nse_lag_is_ready - whether is lag ready or not
 *		all pf and pf netdev in same chip are ready to bond
 *
 * @ldev: nse lag struct for this chip
 */
static bool
nse_lag_is_ready(struct nse_lag *ldev)
{
	return test_bit(NSE_LAG_FLAG_NDEVS_READY, &ldev->flags);
}

/**
 * nse_lag_get_first_pf - get first slave pf in lag
 *
 * @ldev: nse lag struct for this chip
 */
static struct nse_pf *
nse_lag_get_first_pf(struct nse_lag *ldev)
{
	unsigned long slave_bitmap = 0;
	struct nse_pf *first_pf = ldev->first_pf;
	u8 idx;

	/* when ldev->first_pf is non-NULL,
	 * means that hw lag has been activated.
	 * first_pf is initialed at hw lag active phase, so use it.
	 */
	if (first_pf)
		return first_pf;

	slave_bitmap = ldev->tracker.slave_bitmap;
	idx = (u8)find_first_bit(&slave_bitmap, NSE_LAG_MAX_PORT);
	first_pf = ldev->lag_func[idx].pf;

	return first_pf;
}
/**
 * nse_lag_check_prereq -
 *		two situations will return true:
 *			1.  all pf's sriov and switchdev both enabled. (for sriov lag)
 *			2.  all pf's sriov not enabled + legacy switch. (for roce lag)
 *
 * @ldev: nse lag struct for this chip
 * @roce_lag: return value that whether roce lag or sriov lag?
 */
static bool nse_lag_check_prereq(struct nse_lag *ldev,
		bool *roce_lag)
{
	unsigned long slave_bitmap = 0;
	struct nse_pf *first_pf = NULL;
	struct device *dev;
	u8 idx;

	first_pf = nse_lag_get_first_pf(ldev);
	if (!first_pf)
		return false;

	*roce_lag = false;
	dev = nse_pf_to_dev(first_pf);
	slave_bitmap = ldev->tracker.slave_bitmap;
	for_each_set_bit(idx, &slave_bitmap, NSE_LAG_MAX_PORT) {
		struct nse_pf *pf = ldev->lag_func[idx].pf;

		if (!ldev->lag_func[idx].netdev || !pf)
			return false;

		if ((nse_is_sriov_enabled(pf) && !nse_is_eswitch_mode_switchdev(pf)) ||
			(!nse_is_sriov_enabled(pf) && nse_is_eswitch_mode_switchdev(pf))) {
			dev_info(dev,
				"pf[%d] sriov is enabled but switchdev isn't enabled, or vice versa\n",
				pf->hw.pcore_pf_id);

			return false;
		}

		if (nse_is_sriov_enabled(first_pf) != nse_is_sriov_enabled(pf) ||
			first_pf->eswitch_mode != pf->eswitch_mode) {
			dev_info(dev,
				"pf[%d]'s sriov and eswitch mode is different with pf[%d]'s\n",
				pf->hw.pcore_pf_id, first_pf->hw.pcore_pf_id);

			dev_info(dev,
				"\tpf[%d]-sriov[%d]-eswitch[%d] VS pf[%d]-sriov[%d]-eswitch[%d]\n",
				pf->hw.pcore_pf_id, nse_is_sriov_enabled(pf), pf->eswitch_mode,
				first_pf->hw.pcore_pf_id, nse_is_sriov_enabled(first_pf),
				first_pf->eswitch_mode);

			return false;
		}
	}

	/*once enter here, which means that all pfs in lag are in below 2 situation:
	 *  situation 1: sriov and switchdev both disabled, for roce lag.
	 *  situation 2: sriov and switchdev both enabled, for sriov vf lag.
	 */
	if (!nse_is_sriov_enabled(first_pf) &&
		!nse_is_eswitch_mode_switchdev(first_pf)) {
		/* check further that roce en or not in situation 1*/
		*roce_lag = true;
		for_each_set_bit(idx, &slave_bitmap, NSE_LAG_MAX_PORT) {
			struct iidc_core_dev_info *cdev_info;
			struct nse_pf *pf = ldev->lag_func[idx].pf;

			cdev_info = nse_find_cdev_info_by_id(pf, IIDC_RDMA_ID);
			if (!cdev_info) {
				/*  when anyone of slave members disable roce, roce lag will be
				 * false
				 */
				*roce_lag = false;
				return false;
			}
		}
	}

	return true;
}

/**
 * nse_lag_fill_aqc_common -
 *		fill common information for both active-backup lag and hash lag
 *
 * @ldev: nse lag struct for this chip
 * @tracker: parsed bond inforation previously
 * @buf: aqc memory buf for hw lag command
 */
static void
nse_lag_fill_aqc_common(struct nse_lag *ldev,
			struct lag_tracker *tracker, struct nse_aqc_hw_lag_cfg *buf)
{
	u8 idx, i = 0;

	buf->lag_id = ldev->hw_lag_id;
	buf->lan_port_num = tracker->vld_ports;
	for_each_set_bit(idx, &tracker->slave_bitmap, NSE_LAG_MAX_PORT) {
		struct nse_pf *pf = ldev->lag_func[idx].pf;

		buf->lan_id[i++] = pf->hw.lan_id;
	}
}

/**
 * nse_lag_remap_port_mapping -
 *	 this is used for set remap port table for create/modify hw lag
 *	 hw lag mode is active backup
 * @ldev: nse lag struct for this chip
 * @tracker: parsed bond inforation previously
 * @remap_port: output for remap port
 */
static int
nse_lag_remap_port_mapping(struct nse_lag *ldev,
			struct lag_tracker *tracker, u8 *remap_port)
{
	struct nse_pf *first_pf = NULL;
	struct device *dev;
	unsigned long slave_bitmap = 0;
	u8 idx, i = 0;

	first_pf = nse_lag_get_first_pf(ldev);
	if (!first_pf)
		return -EIO;

	dev = nse_pf_to_dev(first_pf);
	slave_bitmap = tracker->slave_bitmap;
	for_each_set_bit(idx, &slave_bitmap, NSE_LAG_MAX_PORT) {
		struct nse_pf *pf = ldev->lag_func[idx].pf;
		bool port_en;

		port_en = tracker->netdev_state[idx].tx_enabled &&
			tracker->netdev_state[idx].link_up;
		if (port_en) {
			*remap_port = pf->hw.lan_id;
			break;
		}

		i++;
	}

	if (i >= tracker->vld_ports) {
		*remap_port = first_pf->hw.lan_id;
		dev_info(dev,
			"all ports of active-backup bond are tx disabled, 1st lan_id is used\n");
	}

	return 0;
}

/**
 * nse_lag_hash_port_mapping -
 *	 this is used for set hash port table for create/modify hw lag
 *	 hw lag mode is hash mode
 * @ldev: nse lag struct for this chip
 * @tracker: parsed bond inforation previously
 * @ports: output hash port array
 * @opc: create or modify operation
 */
static int
nse_lag_hash_port_mapping(struct nse_lag *ldev,
			struct lag_tracker *tracker, u8 *ports,
			enum nse_adminq_opc_category_misc_subcodes opc)
{
	struct nse_pf *first_pf = NULL;
	struct device *dev;
	unsigned long slave_bitmap = 0;
	int dis_port[NSE_LAG_MAX_PORT] = {};
	int en_port[NSE_LAG_MAX_PORT] = {};
	int total_port[NSE_LAG_MAX_PORT] = {};
	int total_port_num = 0;
	int dis_port_num = 0;
	int en_port_num = 0, i;
	u8 idx, j;

	first_pf = nse_lag_get_first_pf(ldev);
	if (!first_pf)
		return -EIO;
	dev = nse_pf_to_dev(first_pf);

	slave_bitmap = tracker->slave_bitmap;
	for_each_set_bit(idx, &slave_bitmap, NSE_LAG_MAX_PORT) {
		struct nse_pf *pf = ldev->lag_func[idx].pf;
		bool port_en;

		total_port[total_port_num++] = pf->hw.lan_id;
		port_en = tracker->netdev_state[idx].tx_enabled &&
			tracker->netdev_state[idx].link_up;
		if (port_en)
			en_port[en_port_num++] = pf->hw.lan_id;
		else
			dis_port[dis_port_num++] = pf->hw.lan_id;
	}

	if (total_port_num != tracker->vld_ports) {
		dev_err(dev,
			"it is err that total_port_num != tracker->vld_ports\n");
		return -EIO;
	}

	for (i = 0; i < tracker->vld_ports; i++)
		for (j = 0; j < tracker->buckets; j++) {
			idx = i * tracker->buckets + j;
			ports[idx] = total_port[i];
		}

	if (en_port_num == total_port_num ||
	    dis_port_num == total_port_num)
		return 0;

	for (i = 0; i < tracker->vld_ports; i++) {
		for (j = 0; j < tracker->buckets; j++) {
			int dis_idx;

			/* hash entry index*/
			idx = i * tracker->buckets + j;

			/*find out all hash entries which dest port is disabled*/
			for (dis_idx = 0; dis_idx < dis_port_num; dis_idx++) {
				if (dis_port[dis_idx] == ports[idx])
					break;
			}

			/*if find nothing , continue to next hash entry*/
			if (dis_idx == dis_port_num)
				continue;

			/*such entry 's dest port is replaced by enable port one by one*/
			ports[idx] = en_port[j % en_port_num];
		}
	}

	return 0;
}

/**
 * nse_aqc_remove_lag -
 *		this function is used to remove hw lag
 * @ldev: nse lag struct for this chip
 */
static int
nse_aqc_remove_lag(struct nse_lag *ldev)
{
	struct nse_pf *first_pf = NULL;
	struct device *dev;
	struct nse_hw *hw;
	struct nse_aqc_hw_lag_cfg *buf;
	int err = 0;
	enum nse_status status = NSE_SUCCESS;

	first_pf = nse_lag_get_first_pf(ldev);
	if (!first_pf)
		return -EIO;
	dev = nse_pf_to_dev(first_pf);

	hw = &first_pf->hw;
	buf = devm_kzalloc(nse_hw_to_dev(hw), sizeof(*buf), GFP_KERNEL);
	if (!buf) {
		dev_err(dev, "[%s, %d] Failed to devm_kzalloc for hw lag remove\n",
				__func__, __LINE__);
		return -ENOMEM;
	}

	buf->lag_id = ldev->hw_lag_id;

	dev_info(dev,
		"[%s, %d] Start to remove hw lag [hw_id = %d]:\n",
		__func__, __LINE__, buf->lag_id);

	status = nse_aq_hw_lag(hw, buf, sizeof(*buf), NSE_AQ_OPC_REMOVE_HW_LAG, NULL);
	if (status) {
		dev_err(dev, "Failed to remove hw lag\n");
		err = -EIO;
		goto nse_aqc_remove_lag_exit;
	}

nse_aqc_remove_lag_exit:
	devm_kfree(nse_hw_to_dev(hw), buf);
	return err;
}

/**
 * nse_opc_active_backup_lag -
 *		this function is used to creat/modify active backup hw lag
 *			for both roce and sriov mode lag.
 * @ldev: nse lag struct for this chip
 * @tracker: parsed bond inforation previously
 * @opc: create or modify operation
 */
static int nse_opc_active_backup_lag(struct nse_lag *ldev,
		      struct lag_tracker *tracker,
		      enum nse_adminq_opc_category_misc_subcodes opc)
{
	struct nse_pf *first_pf = NULL;
	struct device *dev;
	struct nse_hw *hw;
	struct nse_aqc_hw_lag_cfg *buf;
	u8 remap_port = 0;
	enum nse_status status = NSE_SUCCESS;
	int err = 0;

	first_pf = nse_lag_get_first_pf(ldev);
	if (!first_pf)
		return -EIO;
	dev = nse_pf_to_dev(first_pf);

	err = nse_lag_remap_port_mapping(ldev, tracker, &remap_port);
	if (err) {
		dev_warn(dev,
			"Failed to mapping remap port in active-bakcup mode, err = %d\n", err);
		return err;
	}

	if (opc == NSE_AQ_OPC_UPDATE_HW_LAG &&
		remap_port == ldev->v2p_map[0]) {
		dev_info(dev, "Active port(%d) is not changed when modify lag!\n", remap_port);
		return 0;
	}

	hw = &first_pf->hw;
	buf = devm_kzalloc(nse_hw_to_dev(hw), sizeof(*buf), GFP_KERNEL);
	if (!buf) {
		dev_err(dev, "[%s, %d] Failed to devm_kzalloc for hw lag aqc\n",
				__func__, __LINE__);
		return -ENOMEM;
	}

	nse_lag_fill_aqc_common(ldev, tracker, buf);
	buf->tx_type = NSE_AQC_LAG_TX_TYPE_ACT_BKUP;
	buf->tbl.remap.remap_port[0] = remap_port;
	buf->tbl.remap.remap_port[1] = remap_port;

	if (opc == NSE_AQ_OPC_ADD_HW_LAG)
		dev_info(dev,
			"[%s, %d] Start to add hw lag:\n", __func__, __LINE__);
	else
		dev_info(dev,
			"[%s, %d] Start to update hw lag:\n", __func__, __LINE__);

	dev_info(dev,
		"\t hw_lag_id = %d, port_num = %d, lan_id[%d,%d,%d,%d]\n",
		buf->lag_id, buf->lan_port_num,
		buf->lan_id[0], buf->lan_id[1], buf->lan_id[2], buf->lan_id[3]);

	dev_info(dev,
		"\t tx_type = %d, remap_port[%d,%d]\n",
		buf->tx_type, buf->tbl.remap.remap_port[0], buf->tbl.remap.remap_port[1]);

	status = nse_aq_hw_lag(hw, buf, sizeof(*buf), opc, NULL);
	if (status) {
		dev_err(dev, "Failed to operate active backup hw lag\n");
		err = -EIO;
		goto nse_opc_active_backup_lag_exit;
	}

	memcpy(ldev->v2p_map, &remap_port, sizeof(remap_port));
	dev_info(dev,
		"Success to mapping remap port[%d] in active-bakcup mode\n",
		ldev->v2p_map[0]);

nse_opc_active_backup_lag_exit:
	devm_kfree(nse_hw_to_dev(hw), buf);
	return err;
}

/**
 * nse_aqc_opc_lan_rx_drop - operate lan's rx drop enable.
 * @hw: pointer to the HW struct
 * @is_en: enable or disable rx drop
 *
 */
static int
nse_aqc_opc_lan_rx_drop(struct nse_hw *hw, bool is_en)
{
	struct nse_aqc_hw_lag_cfg_drop *buf;
	enum nse_status status = NSE_SUCCESS;
	int err = 0;

	buf = devm_kzalloc(nse_hw_to_dev(hw), sizeof(*buf), GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	buf->lan_id = cpu_to_le16(hw->lan_id);

	if (is_en)
		buf->drop_en = cpu_to_le16(1);
	else
		buf->drop_en = cpu_to_le16(0);

	dev_info(nse_hw_to_dev(hw),
		 "[%s, %d] Start to operate hw lag's rx drop, lan_id = %d, drop en = %d\n",
		 __func__, __LINE__, le16_to_cpu(buf->lan_id), le16_to_cpu(buf->drop_en));

	status = nse_aq_hw_lag(hw, buf, sizeof(*buf),
					NSE_AQ_OPC_HW_LAG_CFG_DROP, NULL);
	if (status) {
		dev_err(nse_hw_to_dev(hw),
			"[%s, %d] Failed to operate hw lag's rx drop\n",
			__func__, __LINE__);
		err = -EIO;
	}

	devm_kfree(nse_hw_to_dev(hw), buf);

	return err;
}

/**
 * nse_aqc_enable_lan_rx_drop -
 *		enable one pf's rx drop.
 * @pf: the related pf struct which lan port should be drop in rx.
 */
static int
nse_aqc_enable_lan_rx_drop(struct nse_pf *pf)
{
	int err = 0;

	if (!pf)
		return -EINVAL;

	err = nse_aqc_opc_lan_rx_drop(&pf->hw, true);
	if (err)
		dev_err(nse_pf_to_dev(pf),
			"Failed to enable lan rx drop!\n");

	return err;
}

/**
 * nse_aqc_disable_lan_rx_drop -
 *		disable one pf's rx drop.
 * @pf: the related pf struct which lan port should be drop in rx.
 */
static int
nse_aqc_disable_lan_rx_drop(struct nse_pf *pf)
{
	int err = 0;

	if (!pf)
		return -EINVAL;

	err = nse_aqc_opc_lan_rx_drop(&pf->hw, false);
	if (err)
		dev_err(nse_pf_to_dev(pf),
			"Failed to disable lan rx drop!\n");

	return err;
}

/**
 * nse_lag_get_hash_type -
 *		transfer OS hash type to HW hash type
 * @hash_type: OS hash type
 */
static u8
nse_lag_get_hash_type(enum netdev_lag_hash hash_type)
{
	u8 hw_hash = 0;

	switch (hash_type) {
	case NETDEV_LAG_HASH_L2:
		hw_hash = NSE_AQC_HW_LAG_HASH_L2_TYPE;
		break;

	case NETDEV_LAG_HASH_L23:
		hw_hash = NSE_AQC_HW_LAG_HASH_L23_TYPE;
		break;

	case NETDEV_LAG_HASH_L34:
		hw_hash = NSE_AQC_HW_LAG_HASH_L34_TYPE;
		break;

	case NETDEV_LAG_HASH_E23:
		hw_hash = NSE_AQC_HW_LAG_HASH_E23_TYPE;
		break;
	case NETDEV_LAG_HASH_E34:
		hw_hash = NSE_AQC_HW_LAG_HASH_E34_TYPE;
		break;
	default:
		break;
	}

	return hw_hash;
}

/**
 * nse_opc_hash_lag -
 *		this function is used to creat/modify hash hw lag
 *			for both roce and sriov mode lag.
 * @ldev: nse lag struct for this chip
 * @tracker: parsed bond inforation previously
 * @opc: create or modify operation
 */
static int nse_opc_hash_lag(struct nse_lag *ldev,
		      struct lag_tracker *tracker,
		      enum nse_adminq_opc_category_misc_subcodes opc)
{
	struct nse_pf *first_pf = NULL;
	struct device *dev;
	struct nse_hw *hw;
	struct nse_aqc_hw_lag_cfg *buf;
	u8 hash_port[NSE_LAG_HASH_MAX_ENTRY] = { 0 }, hash_type;
	enum nse_status status = NSE_SUCCESS;
	int err = 0, i;
	u16	vld_entry = 0;

	first_pf = nse_lag_get_first_pf(ldev);
	if (!first_pf)
		return -EIO;
	dev = nse_pf_to_dev(first_pf);

	err = nse_lag_hash_port_mapping(ldev, tracker, hash_port, opc);
	if (err) {
		dev_err(dev,
			"[%s, %d] Failed to mapping hash entry in hash mode, err = %d\n",
			__func__, __LINE__, err);
		return err;
	}

	hw = &first_pf->hw;
	buf = devm_kzalloc(nse_hw_to_dev(hw), sizeof(*buf), GFP_KERNEL);
	if (!buf) {
		dev_err(dev, "[%s, %d] Failed to devm_kzalloc for hw lag aqc\n",
				__func__, __LINE__);
		return -ENOMEM;
	}

	nse_lag_fill_aqc_common(ldev, tracker, buf);
	buf->tx_type = NSE_AQC_LAG_TX_TYPE_HASH;
	hash_type = nse_lag_get_hash_type(tracker->hash_type);
	if (!hash_type) {
		dev_err(dev, "Failed to parse OS hash type(%d)\n", tracker->hash_type);
		err = -EINVAL;
		goto nse_opc_hash_lag_exit;
	}
	buf->tbl.hash_tbl.hash_type = hash_type;

	for (i = 0; i < NSE_LAG_HASH_MAX_ENTRY; i++) {
		struct nse_aqc_hw_lag_hash_entry *entry;

		if (opc == NSE_AQ_OPC_UPDATE_HW_LAG &&
			ldev->v2p_map[i] == hash_port[i])
			continue;

		entry = &buf->tbl.hash_tbl.entry[vld_entry++];
		entry->entry_idx = i;
		entry->dst_port = hash_port[i];
	}

	if (vld_entry == 0 && hash_type == ldev->old_hash_type) {
		dev_info(dev,
			"[%s, %d] both hash port and hash type are not changed\n",
			__func__, __LINE__);
		return 0;
	}

	buf->tbl.hash_tbl.vld_entries = cpu_to_le16(vld_entry);

	if (opc == NSE_AQ_OPC_ADD_HW_LAG)
		dev_info(dev,
			"[%s, %d] Start to add hw lag:\n", __func__, __LINE__);
	else
		dev_info(dev,
			"[%s, %d] Start to update hw lag:\n", __func__, __LINE__);

	dev_info(dev,
		"\t hw_lag_id = %d, port_num = %d, lan_id[%d,%d,%d,%d]\n",
		buf->lag_id, buf->lan_port_num,
		buf->lan_id[0], buf->lan_id[1], buf->lan_id[2], buf->lan_id[3]);

	dev_info(dev,
		"\t tx_type = %d, hash_type = %d, hash_vld_entry = %d\n",
		buf->tx_type, buf->tbl.hash_tbl.hash_type, vld_entry);

	dev_info(dev, "Hash Entry(index-value):\n");
	for (i = 0; i < NSE_LAG_HASH_MAX_ENTRY; i = i+16) {
		dev_info(dev,
			"\t%d-%d, \t%d-%d, \t%d-%d, \t%d-%d, \t%d-%d, \t%d-%d, \t%d-%d, \t%d-%d, ",
			buf->tbl.hash_tbl.entry[i].entry_idx,
			buf->tbl.hash_tbl.entry[i].dst_port,
			buf->tbl.hash_tbl.entry[i+1].entry_idx,
			buf->tbl.hash_tbl.entry[i+1].dst_port,
			buf->tbl.hash_tbl.entry[i+2].entry_idx,
			buf->tbl.hash_tbl.entry[i+2].dst_port,
			buf->tbl.hash_tbl.entry[i+3].entry_idx,
			buf->tbl.hash_tbl.entry[i+3].dst_port,
			buf->tbl.hash_tbl.entry[i+4].entry_idx,
			buf->tbl.hash_tbl.entry[i+4].dst_port,
			buf->tbl.hash_tbl.entry[i+5].entry_idx,
			buf->tbl.hash_tbl.entry[i+5].dst_port,
			buf->tbl.hash_tbl.entry[i+6].entry_idx,
			buf->tbl.hash_tbl.entry[i+6].dst_port,
			buf->tbl.hash_tbl.entry[i+7].entry_idx,
			buf->tbl.hash_tbl.entry[i+7].dst_port);

		dev_info(dev,
			"\t%d-%d, \t%d-%d, \t%d-%d, \t%d-%d, \t%d-%d, \t%d-%d, \t%d-%d, \t%d-%d\n",
			buf->tbl.hash_tbl.entry[i+8].entry_idx,
			buf->tbl.hash_tbl.entry[i+8].dst_port,
			buf->tbl.hash_tbl.entry[i+9].entry_idx,
			buf->tbl.hash_tbl.entry[i+9].dst_port,
			buf->tbl.hash_tbl.entry[i+10].entry_idx,
			buf->tbl.hash_tbl.entry[i+10].dst_port,
			buf->tbl.hash_tbl.entry[i+11].entry_idx,
			buf->tbl.hash_tbl.entry[i+11].dst_port,
			buf->tbl.hash_tbl.entry[i+12].entry_idx,
			buf->tbl.hash_tbl.entry[i+12].dst_port,
			buf->tbl.hash_tbl.entry[i+13].entry_idx,
			buf->tbl.hash_tbl.entry[i+13].dst_port,
			buf->tbl.hash_tbl.entry[i+14].entry_idx,
			buf->tbl.hash_tbl.entry[i+14].dst_port,
			buf->tbl.hash_tbl.entry[i+15].entry_idx,
			buf->tbl.hash_tbl.entry[i+15].dst_port);
	}

	status = nse_aq_hw_lag(hw, buf, sizeof(*buf), opc, NULL);
	if (status) {
		dev_err(dev, "Failed to operate hash hw lag\n");
		err = -EIO;
		goto nse_opc_hash_lag_exit;
	}

	memcpy(ldev->v2p_map, hash_port, sizeof(hash_port));
	ldev->old_hash_type = hash_type;

nse_opc_hash_lag_exit:
	devm_kfree(nse_hw_to_dev(hw), buf);
	return err;
}

/**
 * nse_lag_set_hw_lag_id -
 *		calculate hw_lag_id, use minimum lan id in lag as hw_lag_id
 *
 * @ldev: nse lag struct for this chip
 * @tracker: parsed bond inforation previously
 */
static void
nse_lag_set_hw_lag_id(struct nse_lag *ldev,
			struct lag_tracker *tracker)
{
	unsigned long slave_bitmap = 0;
	u8 idx, hw_lag_id = 0;

	slave_bitmap = tracker->slave_bitmap;

	for_each_set_bit(idx, &slave_bitmap, NSE_LAG_MAX_PORT) {
		struct nse_pf *pf = ldev->lag_func[idx].pf;
		u8 lan_id = pf->hw.lan_id;

		hw_lag_id = max_t(u8, lan_id, hw_lag_id);
	}

	ldev->hw_lag_id = hw_lag_id;
}

/**
 * nse_lag_has_drop_rule -
 *		judge there is lan rx drop rule
 *
 * @ldev: nse lag struct for this chip
 */
static bool nse_lag_has_drop_rule(struct nse_lag *ldev)
{
	int i;

	for (i = 0; i < ldev->ports; i++)
		if (ldev->lag_func[i].has_drop)
			return true;

	return false;
}

/**
 * nse_lag_drop_rule_cleanup - cleanup all lan rx drop rules
 *
 *		we should loop based on ldev->ports,
 *		because tracker is changed sometime
 *
 * @ldev: nse lag struct for this chip
 */
static void nse_lag_drop_rule_cleanup(struct nse_lag *ldev)
{
	int idx, err = 0;

	/*when disable lag, tracker is not the existed info, so we check all ports*/
	for (idx = 0; idx < ldev->ports; idx++) {
		struct nse_pf *pf = ldev->lag_func[idx].pf;

		if (!ldev->lag_func[idx].has_drop)
			continue;

		err = nse_aqc_disable_lan_rx_drop(pf);
		if (err)
			dev_err(nse_pf_to_dev(pf),
				"[%s, %d] Failed to remove lan rx drop in hw, err = %d\n",
				__func__, __LINE__, err);

		ldev->lag_func[idx].has_drop = false;
	}
}

/**
 * nse_lag_drop_rule_setup -
 *		dynamic setup lan drop rule according to current lag status.
 *			first, cleanup existed drop rules
 *			second, create drop rules according to newest lag tracker
 *
 * @ldev: nse lag struct for this chip
 * @tracker: parsed bond inforation previously
 */
static void nse_lag_drop_rule_setup(struct nse_lag *ldev,
				     struct lag_tracker *tracker)
{
	unsigned long slave_bitmap = 0;
	u8 idx;
	int err = 0;

	nse_lag_drop_rule_cleanup(ldev);

	if (!ldev->tracker.has_inactive)
		return;

	slave_bitmap = tracker->slave_bitmap;
	for_each_set_bit(idx, &slave_bitmap, NSE_LAG_MAX_PORT) {
		struct nse_pf *pf = ldev->lag_func[idx].pf;
		bool port_en;

		port_en = tracker->netdev_state[idx].tx_enabled &&
			tracker->netdev_state[idx].link_up;

		if (!port_en) {
			err = nse_aqc_enable_lan_rx_drop(pf);
			if (!err)
				ldev->lag_func[idx].has_drop = true;
			else
				dev_err(nse_pf_to_dev(pf),
					"[%s, %d] Failed to create lan rx drop in hw, err = %d\n",
					__func__, __LINE__, err);
		}
	}
}

/**
 * nse_lag_has_unplug -
 *		judge there is has unplug flag
 *
 * @ldev: nse lag struct for this chip
 */
static bool nse_lag_has_unplug(struct nse_lag *ldev)
{
	int i;

	for (i = 0; i < ldev->ports; i++)
		if (ldev->lag_func[i].has_unplug)
			return true;

	return false;
}

/**
 * nse_lag_plug_main_aux_dev -  when active hw lag
 *			plug main aux device with hw lag en
 *
 * @pf: pointer of nse pf struct
 */
static int
nse_lag_plug_main_aux_dev(struct nse_pf *pf)
{
	struct iidc_core_dev_info *cdev_info = NULL;
	int err = 0;

	cdev_info = nse_find_cdev_info_by_id(pf, IIDC_RDMA_ID);
	if (!cdev_info) {
		dev_err(nse_pf_to_dev(pf),
			"[%s, %d] Failed to find cdev object of main pf[%d] of roce lag\n",
			__func__, __LINE__, pf->hw.pcore_pf_id);
		return -EINVAL;
	}

	cdev_info->is_lag = 1;

	dev_info(nse_pf_to_dev(pf),
		"[%s, %d] Start to plug pf[%d]'s aux device with lag enabled\n",
		__func__, __LINE__, pf->hw.pcore_pf_id);

	err = nse_plug_aux_dev(cdev_info, IIDC_RDMA_ROCE_NAME);
	if (err)
		dev_err(nse_pf_to_dev(pf),
			"[%s, %d] Failed to plug main pf[%d] of roce lag\n",
			__func__, __LINE__, pf->hw.pcore_pf_id);

	return err;
}

/**
 * nse_lag_plug_normal_aux_dev -  restore when disable hw lag
 *			plug normal aux device without hw lag en
 *
 * @pf: pointer of nse pf struct
 */
static int
nse_lag_plug_normal_aux_dev(struct nse_pf *pf)
{
	struct iidc_core_dev_info *cdev_info = NULL;
	int err = 0;

	cdev_info = nse_find_cdev_info_by_id(pf, IIDC_RDMA_ID);
	if (!cdev_info) {
		dev_err(nse_pf_to_dev(pf),
			"[%s, %d] Failed to find cdev object of pf[%d] of roce lag\n",
			__func__, __LINE__, pf->hw.pcore_pf_id);
		return -EINVAL;
	}

	cdev_info->is_lag = 0;

	dev_info(nse_pf_to_dev(pf),
		"[%s, %d] Start to plug pf[%d]'s aux device with lag disabled\n",
		__func__, __LINE__, pf->hw.pcore_pf_id);

	err = nse_plug_aux_dev(cdev_info, IIDC_RDMA_ROCE_NAME);
	if (err)
		dev_err(nse_pf_to_dev(pf),
			"[%s, %d] Failed to plug pf[%d]\n",
			__func__, __LINE__, pf->hw.pcore_pf_id);

	return err;
}

/**
 * nse_lag_remove_devices -
 *		unplug aux dev of slave pf member in hw_lag
 *
 * @ldev: nse lag struct for this chip
 */
static void
nse_lag_remove_devices(struct nse_lag *ldev)
{
	struct lag_tracker *tracker = &ldev->tracker;
	unsigned long slave_bitmap = 0;
	u8 idx;

	slave_bitmap = tracker->slave_bitmap;
	for_each_set_bit(idx, &slave_bitmap, NSE_LAG_MAX_PORT) {
		struct nse_pf *pf = ldev->lag_func[idx].pf;

		dev_info(nse_pf_to_dev(pf),
			"[%s, %d] Start to unplug pf[%d]'s aux device before active roce lag\n",
			__func__, __LINE__, pf->hw.pcore_pf_id);

		nse_unplug_aux_devs(pf, 0, 1);
		ldev->lag_func[idx].has_unplug = true;
	}
}

/**
 * nse_lag_add_devices -
 *		add normal aux dev, all slave pf members
 *
 * @ldev: nse lag struct for this chip
 */
static void
nse_lag_add_devices(struct nse_lag *ldev)
{
	struct lag_tracker *tracker = &ldev->tracker;
	unsigned long slave_bitmap = 0;
	u8 idx;

	slave_bitmap = tracker->slave_bitmap;
	for_each_set_bit(idx, &slave_bitmap, NSE_LAG_MAX_PORT) {
		struct nse_pf *pf = ldev->lag_func[idx].pf;

		dev_info(nse_pf_to_dev(pf),
			"[%s, %d] Start to plug pf[%d]'s aux device because fail to active roce lag\n",
			__func__, __LINE__, pf->hw.pcore_pf_id);

		nse_lag_plug_normal_aux_dev(pf);
		ldev->lag_func[idx].has_unplug = false;
	}
}

/**
 * nse_lag_set_roce_fltr -
 *		create a roce fltr on source pf's eswitch,
 *		forward source pf's dmac + roce packet to dest pf's main vsi
 *
 *
 * @pf: source pf struct, roce filter will be set on this pf's eswitch
 * @dst_pf: dest pf struct.
 */
static int
nse_lag_set_roce_fltr(struct nse_pf *pf, struct nse_pf *dst_pf)
{
	struct nse_vsi *vsi = NULL, *dst_vsi = NULL;
	enum nse_status status = NSE_SUCCESS;
	u8 mac_addr[ETH_ALEN] = { 0 };
	int err = 0;

	if (!pf || !dst_pf)
		return -EINVAL;

	vsi = nse_get_main_vsi(pf);
	if (!vsi) {
		dev_err(nse_pf_to_dev(pf),
				"[%s, %d] Couldn't get main vsi\n",
				__func__, __LINE__);
		err = -EIO;
		goto exit;
	}

	/*mac addr is masked now, keep it 0*/

	dst_vsi = nse_get_main_vsi(dst_pf);
	if (!dst_vsi) {
		dev_err(nse_pf_to_dev(dst_pf),
				"[%s, %d] Couldn't get main vsi\n",
				__func__, __LINE__);
		err = -EIO;
		goto exit;
	}

	status = nse_fltr_add_roce_mac(vsi, mac_addr, dst_vsi, NSE_FWD_TO_VSI);
	if (status) {
		dev_err(nse_pf_to_dev(pf),
				"[%s, %d] Failed to add roce mac fltr, src pf(%d), dst pf(%d).\n",
				__func__, __LINE__, pf->hw.pcore_pf_id, dst_pf->hw.pcore_pf_id);
		err = -EIO;
		goto exit;
	}

	dev_info(nse_pf_to_dev(pf),
			"[%s, %d] Success to add roce mac fltr, src pf(%d), dst pf(%d).\n",
			__func__, __LINE__, pf->hw.pcore_pf_id, dst_pf->hw.pcore_pf_id);

exit:
	return err;
}

/**
 * nse_lag_clear_roce_fltr -
 *		clear a roce fltr on source pf's eswitch,
 *		forward source pf's dmac + roce packet to dest pf's main vsi
 *
 *
 * @pf: source pf struct, roce filter will be clear on this pf's eswitch
 * @dst_pf: dest pf struct.
 */
static int
nse_lag_clear_roce_fltr(struct nse_pf *pf, struct nse_pf *dst_pf)
{
	struct nse_vsi *vsi = NULL, *dst_vsi = NULL;
	enum nse_status status = NSE_SUCCESS;
	u8 mac_addr[ETH_ALEN] = { 0 };
	int err = 0;

	if (!pf || !dst_pf)
		return -EINVAL;

	vsi = nse_get_main_vsi(pf);
	if (!vsi) {
		dev_err(nse_pf_to_dev(pf),
				"[%s, %d] Couldn't get main vsi\n",
				__func__, __LINE__);
		err = -EIO;
		goto exit;
	}

	/*mac addr is masked now, keep it 0*/

	dst_vsi = nse_get_main_vsi(dst_pf);
	if (!dst_vsi) {
		dev_err(nse_pf_to_dev(dst_pf),
				"[%s, %d] Couldn't get main vsi\n",
				__func__, __LINE__);
		err = -EIO;
		goto exit;
	}

	status = nse_fltr_remove_roce_mac(vsi, mac_addr, dst_vsi, NSE_FWD_TO_VSI);
	if (status) {
		dev_err(nse_pf_to_dev(pf),
				"[%s, %d] Failed to remove roce mac fltr, src pf(%d), dst pf(%d).\n",
				__func__, __LINE__, pf->hw.pcore_pf_id, dst_pf->hw.pcore_pf_id);
		err = -EIO;
		goto exit;
	}

	dev_info(nse_pf_to_dev(pf),
			"[%s, %d] Success to remove roce mac fltr, src pf(%d), dst pf(%d).\n",
			__func__, __LINE__, pf->hw.pcore_pf_id, dst_pf->hw.pcore_pf_id);

exit:
	return err;
}

/**
 * nse_lag_post_active_roce_lag - do following things after roce lag is activated successfully
 *		1. plug first pf's aux dev with lag enable
 *		2. setup roce fltr in other pf, forward roce packet to first pf main vsi
 *
 * @ldev: nse lag struct for this chip
 */
static int
nse_lag_post_active_roce_lag(struct nse_lag *ldev)
{
	struct nse_pf *first_pf = NULL;
	struct lag_tracker *tracker = &ldev->tracker;
	unsigned long slave_bitmap = 0;
	int err = 0;
	u8 idx;

	first_pf = nse_lag_get_first_pf(ldev);
	if (!first_pf)
		return -EINVAL;

	slave_bitmap = tracker->slave_bitmap;
	for_each_set_bit(idx, &slave_bitmap, NSE_LAG_MAX_PORT) {
		struct nse_pf *pf = ldev->lag_func[idx].pf;

		if (pf == first_pf) {
			err = nse_lag_plug_main_aux_dev(pf);
			if (err)
				dev_err(nse_pf_to_dev(pf),
					"[%s, %d] Failed to plug first pf[%d] of roce lag\n",
					__func__, __LINE__, pf->hw.pcore_pf_id);
		} else {
			err = nse_lag_set_roce_fltr(pf, first_pf);
			if (err)
				dev_err(nse_pf_to_dev(pf),
					"[%s, %d] Failed to set roce fltr in pf[%d] of roce lag\n",
					__func__, __LINE__, pf->hw.pcore_pf_id);
		}
	}

	return err;
}

/**
 * nse_lag_post_disable_roce_lag - do following things after disable roce lag
 *		1. unplug first pf's aux dev
 *		2. plug all pf's aux dev without roce enable
 *		3. clear roce fltr in other pf (non-first pf)
 *
 * @ldev: nse lag struct for this chip
 */
static void
nse_lag_post_disable_roce_lag(struct nse_lag *ldev)
{
	struct nse_pf *first_pf = NULL;
	int idx, err = 0;

	first_pf = nse_lag_get_first_pf(ldev);
	if (!first_pf)
		return;

	/*unplug lag main aux dev firstly*/
	dev_info(nse_pf_to_dev(first_pf),
		"[%s, %d] Start to unplug main pf[%d]'s aux device in roce lag\n",
		__func__, __LINE__, first_pf->hw.pcore_pf_id);
	nse_unplug_aux_devs(first_pf, 0, 1);

	/*when disable lag, tracker is not the existed info, so we check all ports*/
	for (idx = 0; idx < ldev->ports; idx++) {
		struct nse_pf *pf = ldev->lag_func[idx].pf;

		if (!ldev->lag_func[idx].has_unplug)
			continue;

		err = nse_lag_plug_normal_aux_dev(pf);
		if (err)
			dev_err(nse_pf_to_dev(pf),
				"[%s, %d] Failed to restore aux dev when disable hw lag, err = %d\n",
				__func__, __LINE__, err);

		ldev->lag_func[idx].has_unplug = false;

		if (pf != first_pf) {
			err = nse_lag_clear_roce_fltr(pf, first_pf);
			if (err)
				dev_err(nse_pf_to_dev(pf),
					"[%s, %d] Failed to clear roce fltr in pf[%d] of roce lag\n",
					__func__, __LINE__, pf->hw.pcore_pf_id);
		}
	}
}

/**
 * nse_activate_lag -
 *		active hw lag according to information in tracker
 *
 * @ldev: nse lag struct for this chip
 * @tracker: parsed bond inforation previously
 * @mode: roce lag or sriov lag
 */
static int
nse_activate_lag(struct nse_lag *ldev,
		      struct lag_tracker *tracker,
		      enum nse_lag_mode mode)
{
	enum netdev_lag_tx_type	tx_type = tracker->tx_type;
	struct nse_pf *first_pf = NULL;
	struct device *dev;
	int err = 0;

	first_pf = nse_lag_get_first_pf(ldev);
	if (!first_pf)
		return -EIO;
	dev = nse_pf_to_dev(first_pf);

	/*only initial first pf in active flow
	 * when in modify/disable flow, will keep this first pf same.
	 */
	ldev->first_pf = first_pf;
	nse_lag_set_hw_lag_id(ldev, tracker);

	switch (tx_type) {
	case NETDEV_LAG_TX_TYPE_ACTIVEBACKUP:
		err = nse_opc_active_backup_lag(ldev, tracker, NSE_AQ_OPC_ADD_HW_LAG);
		if (err) {
			dev_err(dev, "Failed to create active backup hw lag\n");
			err = -EIO;
			goto nse_activate_lag_exit;
		}
		break;

	case NETDEV_LAG_TX_TYPE_HASH:
		err = nse_opc_hash_lag(ldev,  tracker,  NSE_AQ_OPC_ADD_HW_LAG);
		if (err) {
			dev_err(dev, "Failed to create hash hw lag\n");
			err = -EIO;
			goto nse_activate_lag_exit;
		}
		break;

	default:
		dev_err(dev, "Failed to active lag due to tx_type(%d) not supported\n",
			tx_type);
		err = -EINVAL;
		goto nse_activate_lag_exit;
	}

	if (tracker->tx_type == NETDEV_LAG_TX_TYPE_ACTIVEBACKUP &&
	    !(mode == NSE_LAG_MODE_ROCE))
		nse_lag_drop_rule_setup(ldev, tracker);

	/*set hw lag state to active*/
	ldev->mode = mode;

nse_activate_lag_exit:

	return err;
}

/**
 * nse_modify_lag -
 *		failover hw lag according to information in tracker
 *
 * @ldev: nse lag struct for this chip
 * @tracker: parsed bond inforation previously
 */
int nse_modify_lag(struct nse_lag *ldev,
		      struct lag_tracker *tracker)
{
	enum netdev_lag_tx_type	tx_type = tracker->tx_type;
	struct nse_pf *first_pf = NULL;
	struct device *dev;
	int err = 0;

	first_pf = nse_lag_get_first_pf(ldev);
	if (!first_pf)
		return -EIO;
	dev = nse_pf_to_dev(first_pf);

	switch (tx_type) {
	case NETDEV_LAG_TX_TYPE_ACTIVEBACKUP:
		err = nse_opc_active_backup_lag(ldev, tracker, NSE_AQ_OPC_UPDATE_HW_LAG);
		if (err) {
			dev_warn(dev, "Failed to modify active backup hw lag\n");
			err = -EIO;
			goto nse_modify_lag_exit;
		}
		break;

	case NETDEV_LAG_TX_TYPE_HASH:
		err = nse_opc_hash_lag(ldev, tracker, NSE_AQ_OPC_UPDATE_HW_LAG);
		if (err) {
			dev_warn(dev, "Failed to modify hash hw lag\n");
			err = -EIO;
			goto nse_modify_lag_exit;
		}
		break;

	default:
		dev_err(dev, "Failed to modify lag due to tx_type(%d) not supported\n",
			tx_type);
		err = -EINVAL;
		goto nse_modify_lag_exit;
	}

	if (tracker->tx_type == NETDEV_LAG_TX_TYPE_ACTIVEBACKUP &&
		!(ldev->mode == NSE_LAG_MODE_ROCE))
		nse_lag_drop_rule_setup(ldev, tracker);

nse_modify_lag_exit:
	return 0;
}

/**
 * nse_disable_lag -
 *		disable hw lag
 *
 * @ldev: nse lag struct for this chip
 */
void nse_disable_lag(struct nse_lag *ldev)
{
	if (!ldev)
		return;

	nse_aqc_remove_lag(ldev);

	if (nse_lag_has_drop_rule(ldev))
		nse_lag_drop_rule_cleanup(ldev);

	if (nse_lag_has_unplug(ldev) &&
			(ldev->mode == NSE_LAG_MODE_ROCE))
		nse_lag_post_disable_roce_lag(ldev);

	/*set hw lag state to inactive*/
	ldev->mode = NSE_LAG_MODE_NONE;
}

/**
 * nse_do_bond -
 *		important function to handle hw lag.
 *
 * @ldev: nse lag struct for this chip
 */
static void
nse_do_bond(struct nse_lag *ldev)
{
	struct lag_tracker tracker = { };
	struct nse_pf *first_pf = NULL;
	struct device *dev;
	bool do_bond = false, roce_lag = false;
	int err = 0;

	spin_lock(&ldev->next_tracker_lock);
	ldev->tracker = ldev->next_tracker;
	spin_unlock(&ldev->next_tracker_lock);

	first_pf = nse_lag_get_first_pf(ldev);
	if (!first_pf)
		return;
	dev = nse_pf_to_dev(first_pf);

	if (!nse_lag_is_ready(ldev)) {
		do_bond = false;
	} else {
		tracker = ldev->tracker;
		do_bond = tracker.is_bonded && nse_lag_check_prereq(ldev, &roce_lag);
	}

	dev_info(dev,
		"Start to do bond process: do_bond = %d, is_lag_active = %d, roce_lag = %d\n",
		do_bond, nse_lag_is_active(ldev), roce_lag);

	if (do_bond && !nse_lag_is_active(ldev)) {
		if (roce_lag)
			nse_lag_remove_devices(ldev);

		err = nse_activate_lag(ldev, &tracker,
				roce_lag ? NSE_LAG_MODE_ROCE : NSE_LAG_MODE_SRIOV);
		if (err) {
			if (roce_lag)
				nse_lag_add_devices(ldev);

			dev_err(dev, "Failed to nse_activate_lag, err = %d\n", err);
			return;
		} else if (roce_lag) {
			err = nse_lag_post_active_roce_lag(ldev);
			if (err) {
				dev_err(dev,
					"Failed to post process after active roce lag, err = %d\n",
						err);
				nse_disable_lag(ldev);
				return;
			}
		}
	} else if (do_bond && nse_lag_is_active(ldev)) {
		nse_modify_lag(ldev, &tracker);
	} else if (!do_bond && nse_lag_is_active(ldev)) {
		nse_disable_lag(ldev);
	}
}

static void
nse_do_bond_work(struct work_struct *work)
{
	struct delayed_work *delayed_work = to_delayed_work(work);
	struct nse_lag *ldev = container_of(delayed_work, struct nse_lag,
						 bond_work);

	mutex_lock(&ldev->lock);
	nse_do_bond(ldev);
	mutex_unlock(&ldev->lock);
}

static void
nse_queue_bond_work(struct nse_lag *ldev, unsigned long delay)
{
	queue_delayed_work(ldev->wq, &ldev->bond_work, delay);
}

/**
 * nse_handle_changeupper_event -
 * callback function for handle bond change upper event
 * to bond slave netdev
 * @ldev: nse lag struct for this chip
 * @track: track of nse lag for storing current state of bond
 * @ptr: notifiter information
 */
static int nse_handle_changeupper_event(struct nse_lag *ldev,
					 struct lag_tracker *tracker,
					 struct netdev_notifier_changeupper_info *info)
{
	struct net_device *upper_ndev = info->upper_dev, *tmp_ndev;
	struct net_device *ndev =
		netdev_notifier_info_to_dev((struct netdev_notifier_info *)info);
	struct netdev_lag_upper_info *lag_upper_info = NULL;
	bool is_bonded, is_in_lag = false, mode_supported;
	bool has_other_slave = false;
	bool has_inactive = 0;
	struct slave *slave;
	unsigned long slave_bitmap = 0;
	int num_slaves = 0;
	int changed = 0;
	int idx;

	if (!netif_is_lag_master(upper_ndev))
		return 0;

	netdev_info(ndev,
		"%s receive a bond(%s) changeupper event\n",
		ndev->name, upper_ndev->name);

	if (info->linking)
		lag_upper_info = info->upper_info;

	rcu_read_lock();
	for_each_netdev_in_bond_rcu(upper_ndev, tmp_ndev) {
		idx = nse_lag_dev_get_netdev_idx(ldev, tmp_ndev);
		if (idx >= 0) {
			slave = bond_slave_get_rcu(tmp_ndev);
			slave_bitmap |= (1 << idx);
			if (slave)
				has_inactive |= bond_is_slave_inactive(slave);
		} else {
			netdev_info(ndev,
				"bond(%s) has other slave(%s)\n",
				upper_ndev->name, tmp_ndev->name);
			has_other_slave = true;
			break;
		}
		num_slaves++;
	}
	rcu_read_unlock();

	if (has_other_slave)
		return 0;

	/* All slave members are in same chip */
	if (!(slave_bitmap & GENMASK(ldev->ports - 1, 0)))
		return 0;

	if (lag_upper_info) {
		tracker->tx_type = lag_upper_info->tx_type;
		tracker->hash_type = lag_upper_info->hash_type;
	}

	tracker->has_inactive = has_inactive;
	tracker->slave_bitmap = slave_bitmap;
	tracker->vld_ports = num_slaves;

	/* Determine bonding status:
	 * A device is considered bonded if both its physical ports are slaves
	 * of the same lag master, and only them.
	 */
	is_in_lag = num_slaves == ldev->ports &&
		slave_bitmap == GENMASK(ldev->ports - 1, 0);

	mode_supported = tracker->tx_type == NETDEV_LAG_TX_TYPE_ACTIVEBACKUP ||
			 tracker->tx_type == NETDEV_LAG_TX_TYPE_HASH;

	if (tracker->tx_type == NETDEV_LAG_TX_TYPE_HASH)
		tracker->buckets = NSE_LAG_HASH_MAX_ENTRY / ldev->ports;

	is_bonded = is_in_lag && mode_supported;

	if (tracker->is_bonded != is_bonded) {
		tracker->is_bonded = is_bonded;
		changed = 1;
	}

	netdev_info(ndev,
		"tracker info after parsing changeupper event\n");

	netdev_info(ndev,
		"\t changed = %d, slave_bitmap = 0x%lx, vld_ports = %d\n",
		changed, tracker->slave_bitmap, tracker->vld_ports);

	netdev_info(ndev,
		"\t is_bonded = %d, tx_type = %d, hash_type = %d\n",
		tracker->is_bonded, tracker->tx_type, tracker->hash_type);

	return changed;
}

/**
 * nse_handle_changeupper_event -
 * callback function for handle bond changelowerstate
 * event to bond slave netdev
 *
 * @ldev: nse lag struct for this chip
 * @track: track of nse lag for storing current state of bond
 * @ndev: slave netdev which receive this event
 * @info: notifiter information
 */
static int nse_handle_changelowerstate_event(struct nse_lag *ldev,
					      struct lag_tracker *tracker,
					      struct net_device *ndev,
					      struct netdev_notifier_changelowerstate_info *info)
{
	struct netdev_lag_lower_state_info *lag_lower_info;
	int idx;

	if (!netif_is_lag_port(ndev))
		return 0;

	netdev_info(ndev,
		"%s receive a bond changelowerstate event\n",
		ndev->name);

	idx = nse_lag_dev_get_netdev_idx(ldev, ndev);
	if (idx < 0)
		return 0;

	lag_lower_info = info->lower_state_info;
	if (!lag_lower_info)
		return 0;

	tracker->netdev_state[idx] = *lag_lower_info;

	netdev_info(ndev,
		"tracker info after parsing changelowerstate event\n");

	netdev_info(ndev,
		"\t netdev = %s, idx = %d, link_up = %d, tx_enabled = %d\n",
		ndev->name, idx, tracker->netdev_state[idx].link_up,
		tracker->netdev_state[idx].tx_enabled);

	return 1;
}

/**
 * nse_handle_changeinfodata_event -
 *	callback function for handle bond changeinfodata event,
 *		handle has_inactive info, event to bond master netdev.
 *
 * @ldev: nse lag struct for this chip
 * @track: track of nse lag for storing current state of bond
 * @ndev: slave netdev which receive this event
 */
static int nse_handle_changeinfodata_event(struct nse_lag *ldev,
					    struct lag_tracker *tracker,
					    struct net_device *ndev)
{
	struct net_device *tmp_ndev;
	struct slave *slave;
	bool has_inactive = 0;
	int idx;

	if (!netif_is_lag_master(ndev))
		return 0;

	netdev_info(ndev,
		"%s receive a bond changeinfodata event\n",
		ndev->name);

	rcu_read_lock();
	for_each_netdev_in_bond_rcu(ndev, tmp_ndev) {
		idx = nse_lag_dev_get_netdev_idx(ldev, tmp_ndev);
		if (idx < 0)
			continue;

		slave = bond_slave_get_rcu(tmp_ndev);
		if (slave)
			has_inactive |= bond_is_slave_inactive(slave);
	}
	rcu_read_unlock();

	if (tracker->has_inactive == has_inactive)
		return 0;

	tracker->has_inactive = has_inactive;
	return 1;
}

/**
 * nse_lag_netdev_event -
 *	callback function for handle bond event
 *
 * @this: OS notifier block.
 * @event: type of bond event
 * @ptr: notifiter information
 */
static int
nse_lag_netdev_event(struct notifier_block *this,
				 unsigned long event, void *ptr)
{
	struct net_device *ndev = netdev_notifier_info_to_dev(ptr);
	struct lag_tracker tracker;
	struct nse_lag *ldev;
	int changed = 0;

	if (event != NETDEV_CHANGEUPPER &&
	    event != NETDEV_CHANGELOWERSTATE &&
	    event != NETDEV_CHANGEINFODATA)
		return NOTIFY_DONE;

	ldev = container_of(this, struct nse_lag, nb);
	spin_lock(&ldev->next_tracker_lock);
	tracker = ldev->next_tracker;
	spin_unlock(&ldev->next_tracker_lock);

	switch (event) {
	case NETDEV_CHANGEUPPER:
		changed = nse_handle_changeupper_event(ldev, &tracker, ptr);
		break;
	case NETDEV_CHANGELOWERSTATE:
		changed = nse_handle_changelowerstate_event(ldev, &tracker,
							     ndev, ptr);
		break;
	case NETDEV_CHANGEINFODATA:
		changed = nse_handle_changeinfodata_event(ldev, &tracker, ndev);
		break;
	}

	spin_lock(&ldev->next_tracker_lock);
	ldev->next_tracker = tracker;
	spin_unlock(&ldev->next_tracker_lock);

	if (changed)
		nse_queue_bond_work(ldev, 0);

	return NOTIFY_DONE;
}

/**
 * nse_lag_dev_alloc -
 *	allocate and create a unique lag dev, only one pf in same chip will allocate.
 *
 * @pf: PF struct
 */
struct nse_lag *
nse_lag_dev_alloc(struct nse_pf *pf)
{
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_lag *ldev = NULL;

	ldev = kzalloc(sizeof(*ldev), GFP_KERNEL);
	if (!ldev)
		return NULL;

	ldev->wq = create_singlethread_workqueue("nse_lag_wq");
	if (!ldev->wq) {
		kfree(ldev);
		return NULL;
	}

	kref_init(&ldev->ref);
	mutex_init(&ldev->lock);
	spin_lock_init(&ldev->next_tracker_lock);
	INIT_DELAYED_WORK(&ldev->bond_work, nse_do_bond_work);

	ldev->nb.notifier_call = nse_lag_netdev_event;

	if (register_netdevice_notifier_net(&init_net, &ldev->nb)) {
		ldev->nb.notifier_call = NULL;
		dev_err(dev, "Failed to register LAG netdev notifier\n");
	}

	ldev->mode = NSE_LAG_MODE_NONE;

	ldev->ports = bitmap_weight((unsigned long *)&pf->hw.cur_pcore_pf_bitmap, NSE_LAG_MAX_PORT);
	if (ldev->ports < NSE_LAG_MIN_PORT)
		ldev->ports = NSE_LAG_MIN_PORT;

	return ldev;
}

/**
 * nse_gen_pci_id -
 *
 *   get pf's pci domain, bus number, PCI_SLOT(device num)
 *					 don't care function num.
 *
 * @curr_pf: pf struct
 */
static u32
nse_gen_pci_id(struct nse_pf *pf)
{
	return (u32)((pci_domain_nr(pf->pdev->bus) << 16) |
		     (pf->pdev->bus->number << 8) |
		     PCI_SLOT(pf->pdev->devfn));
}

/**
 * _next_phys_dev -
 *
 *           sub match function which is  provided by driver.
 *		return 0 means (1). the iterated one is same as current one, skip it.
 *                                   (2). iterated one is nse driver,  but not in same chip.
 *		return 1 means we found the physical function in same chip.
 *
 * @other_pf: pf struct which is iterated on bus, will be changed one by one.
 * @curr_pf: pf struct which is current.
 */
static int
_next_phys_dev(struct nse_pf *other_pf,
			  struct nse_pf *curr_pf)
{
	if (other_pf == curr_pf)
		return 0;

	if (nse_gen_pci_id(other_pf) != nse_gen_pci_id(curr_pf))
		return 0;

	return 1;
}

/**
 * pci_get_other_drvdata -
 *
 *           sub match function which is  provided by driver.
 *		return NULL means it is not nse driver, skip it.
 *		return non-NULL means its nse driver, need check further.
 *
 * @this: device which is current.
 * @other: device which is iterated on bus, will be changed one by one.
 */
static void *
pci_get_other_drvdata(struct device *this, struct device *other)
{
	if (this->driver != other->driver)
		return NULL;

	return pci_get_drvdata(to_pci_dev(other));
}

/**
 * next_phys_dev_lag -
 *
 *           match function which is  provided by driver.
 *		return 0 means it is not we needed, skip the dev.
 *		return 1 means we found the physical function in same chip.
 * @dev: device which is iterated on bus, will be changed one by one.
 * @data: PF struct which is current.
 */
static int
next_phys_dev_lag(struct device *dev,
			const void *data)
{
	struct nse_pf *other_pf, *cur_pf = (struct nse_pf *)data;

	other_pf = pci_get_other_drvdata(&cur_pf->pdev->dev, dev);
	if (!other_pf)
		return 0;

	return _next_phys_dev(other_pf, cur_pf);
}

/**
 * nse_get_next_dev -
 *			get other physical function pf
 *
 *		according to OS bus_find_device, iterate the pci device on bus.
 *           match function(next_phys_dev_lag) is provided by driver.
 * @pf: PF struct
 */
static struct nse_pf *
nse_get_next_dev(struct nse_pf *pf,
					       int (*match)(struct device *dev, const void *data))
{
	struct device *next;

	next = bus_find_device(&pci_bus_type, NULL, pf, match);
	if (!next)
		return NULL;

	put_device(next);
	return pci_get_drvdata(to_pci_dev(next));
}

/**
 * nse_get_next_phys_dev_lag -
 *			get other physical function pf for hw lag
 *
 * @pf: PF struct
 */
static struct nse_pf *
nse_get_next_phys_dev_lag(struct nse_pf *pf)
{
	return nse_get_next_dev(pf, &next_phys_dev_lag);
}

/**
 * nse_lag_dev_free -
 *			once ref cnt == 0 will free per chip lag struct.
 * @ref: kernel ref struct
 */
static void
nse_lag_dev_free(struct kref *ref)
{
	struct nse_lag *ldev = container_of(ref, struct nse_lag, ref);

	if (ldev->nb.notifier_call)
		unregister_netdevice_notifier_net(&init_net, &ldev->nb);

	destroy_workqueue(ldev->wq);
	mutex_destroy(&ldev->lock);
	kfree(ldev);
}

/**
 * nse_lag_dev_put -
 *			ref cnt is decreased, once ref cnt == 0 will free lag.
 * @ldev: per chip lag struct
 */
static void
nse_lag_dev_put(struct nse_lag *ldev)
{
	kref_put(&ldev->ref, nse_lag_dev_free);
}

/**
 * nse_lag_dev_get -
 *			ref cnt is increased.
 * @ldev: per chip lag struct
 */
static void
nse_lag_dev_get(struct nse_lag *ldev)
{
	kref_get(&ldev->ref);
}

/**
 * nse_lag_dev_add_pf -
 *			add current pf to hw lag struct.
 * @ldev: per chip lag struct
 * @pf: PF struct
 */
static void
nse_lag_dev_add_pf(struct nse_lag *ldev,
			       struct nse_pf *pf)
{
	unsigned int fn;

	if (!ldev || !pf)
		return;

	fn = pf->hw.pcore_pf_id;
	if (fn >= ldev->ports) {
		dev_warn(nse_pf_to_dev(pf),
			"[%s, %d] it's wrong that function id(%d) bigger than max port num(%d)\n",
			__func__, __LINE__, fn, ldev->ports);
		return;
	}
	ldev->lag_func[fn].pf = pf;
	ldev->lag_func[fn].has_drop = false;
	ldev->lag_func[fn].has_unplug = false;
	pf->lag = ldev;
}

/**
 * nse_lag_dev_remove_pf -
 *			remove current pf from hw lag struct.
 * @ldev: per chip lag struct
 * @pf: PF struct
 */
static void
nse_lag_dev_remove_pf(struct nse_lag *ldev,
				  struct nse_pf *pf)
{
	int i;

	for (i = 0; i < ldev->ports; i++)
		if (ldev->lag_func[i].pf == pf)
			break;

	if (i == ldev->ports)
		return;

	ldev->lag_func[i].pf = NULL;
	pf->lag = NULL;
}

/**
 * nse_lag_dev_alloc_and_add_pf - alloc or find lag dev
 *							      and then add cur pf to it.
 *
 * @pf: PF struct
 */
static int
nse_lag_dev_alloc_and_add_pf(struct nse_pf *pf)
{
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_lag *ldev = NULL;
	struct nse_pf *tmp_pf;

	tmp_pf = nse_get_next_phys_dev_lag(pf);
	if (tmp_pf) {
		dev_info(dev, "Sibling PF[%d] has beend found, its lag address is %p\n",
			tmp_pf->hw.pcore_pf_id, tmp_pf->lag);
		ldev = tmp_pf->lag;
	}

	if (!ldev) {
		dev_info(dev, "PF[%d] start to alloc lag dev\n", pf->hw.pcore_pf_id);
		ldev = nse_lag_dev_alloc(pf);
		if (!ldev) {
			dev_err(dev, "Failed to alloc lag dev\n");
			return -EIO;
		}

		mutex_lock(&ldev->lock);
		/* ldev is allocated by self, ldev->ref has been init to 1
		 * so, nse_lag_dev_get(ldev) is unnecessary
		 */
		nse_lag_dev_add_pf(ldev, pf);
		mutex_unlock(&ldev->lock);
		return 0;
	}

	mutex_lock(&ldev->lock);
	nse_lag_dev_get(ldev);
	nse_lag_dev_add_pf(ldev, pf);
	mutex_unlock(&ldev->lock);
	return 0;
}

/**
 * nse_lag_dev_add_netdev - add cur pf main vsi netdev to lag
 * @pf: PF struct
 * @netdev: main vsi's netdev
 *
 *	add current pf main vsi's netdev to lag, its initail state is down
 *
 */
static int
nse_lag_dev_add_netdev(struct nse_pf *pf,
				 struct net_device *netdev)
{
	unsigned int fn = pf->hw.pcore_pf_id;
	struct nse_lag *ldev = pf->lag;
	unsigned long flags;

	if (!ldev)
		return -EIO;

	if (fn >= ldev->ports)
		return -EIO;

	spin_lock_irqsave(&lag_lock, flags);
	ldev->lag_func[fn].netdev = netdev;
	ldev->tracker.netdev_state[fn].link_up = 0;
	ldev->tracker.netdev_state[fn].tx_enabled = 0;
	spin_unlock_irqrestore(&lag_lock, flags);

	return 0;
}

/**
 * nse_lag_dev_remove_netdev -
 * @ldev: lag struct
 * @netdev: main vsi's netdev
 *
 *	 remove cur pf main vsi netdev from lag
 *
 */
static void
nse_lag_dev_remove_netdev(struct nse_lag *ldev,
				    struct net_device *netdev)
{
	unsigned long flags;
	int i;

	spin_lock_irqsave(&lag_lock, flags);
	for (i = 0; i < ldev->ports; i++) {
		if (ldev->lag_func[i].netdev == netdev) {
			ldev->lag_func[i].netdev = NULL;
			break;
		}
	}
	spin_unlock_irqrestore(&lag_lock, flags);
}

/**
 * nse_lag_add_netdev - add cur pf main vsi netdev to lag
 * @pf: PF struct
 * @netdev: main vsi's netdev
 *
 *    1. add current pf main vsi's netdev to lag
 *    2. judge whether all pf's netdev have added or not
 *
 */
static int
nse_lag_add_netdev(struct nse_pf *pf,
				 struct net_device *netdev)
{
	struct nse_lag *ldev = pf->lag;
	int i, err = 0;

	if (!ldev)
		return -EIO;

	mutex_lock(&ldev->lock);
	err = nse_lag_dev_add_netdev(pf, netdev);
	if (err) {
		mutex_unlock(&ldev->lock);
		return err;
	}

	for (i = 0; i < ldev->ports; i++)
		if (!ldev->lag_func[i].netdev)
			break;

	if (i >= ldev->ports)
		set_bit(NSE_LAG_FLAG_NDEVS_READY, &ldev->flags);

	mutex_unlock(&ldev->lock);
	return err;
}

/**
 * nse_lag_remove_netdev - remove cur pf main vsi netdev from lag
 * @pf: PF struct
 * @netdev: main vsi's netdev
 *
 *    1. remove current pf main vsi's netdev from lag
 *    2. disable hw lag from active to inactive
 *
 */
static void
nse_lag_remove_netdev(struct nse_pf *pf,
			    struct net_device *netdev)
{
	struct nse_lag *ldev = pf->lag;
	bool lag_is_active;

	if (!ldev)
		return;

	mutex_lock(&ldev->lock);
	nse_lag_dev_remove_netdev(ldev, netdev);
	clear_bit(NSE_LAG_FLAG_NDEVS_READY, &ldev->flags);

	lag_is_active = nse_lag_is_active(ldev);

	if (lag_is_active)
		nse_do_bond(ldev);

	mutex_unlock(&ldev->lock);
}

/**
 * nse_init_lag - initialize support for HW LAG
 * @pf: PF struct
 *
 * Per Chip HW LAG structs,
 *    1. when other pf of same chip don't alloc memory for LAG structs,
 *                    alloc hw lag struct and add current pf and main netdev to it.
 *    2. when other pf of same chip has alloced memory for LAG structs,
		       add current pf and main netdev to it.
 *
 */
int
nse_init_lag(struct nse_pf *pf)
{
#ifdef NSE_SUPPORT_HW_LAG
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_vsi *vsi;
	int err = 0;

	if (!nse_is_hw_static_fea_set(&pf->hw, NSE_HW_STATIC_FEA_MISC_SUPPORT_HW_LAG))
		return 0;

	err = nse_lag_dev_alloc_and_add_pf(pf);
	if (err) {
		dev_err(dev, "Failed to add pf to lag dev\n");
		goto lag_error;
	}

	vsi = nse_get_main_vsi(pf);
	if (!vsi || !vsi->netdev) {
		dev_err(dev, "Couldn't get main vsi, link aggregation init fail\n");
		err = -EIO;
		goto lag_error;
	}

	err = nse_lag_add_netdev(pf, vsi->netdev);
	if (err) {
		dev_err(dev, "Failed to add pf main netdev to lag dev\n");
		goto lag_error;
	}

lag_error:

	return err;
#else
	return 0;
#endif
}

/**
 * nse_deinit_lag - Clean up LAG
 * @pf: PF struct
 *
 * Clean up kernel LAG info and free memory
 * This function is meant to only be called on driver remove/shutdown
 */
void
nse_deinit_lag(struct nse_pf *pf)
{
#ifdef NSE_SUPPORT_HW_LAG
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_lag *ldev = pf->lag;
	struct nse_vsi *vsi = NULL;

	if (!nse_is_hw_static_fea_set(&pf->hw, NSE_HW_STATIC_FEA_MISC_SUPPORT_HW_LAG))
		return;

	if (!ldev)
		return;

	vsi = nse_get_main_vsi(pf);
	if (!vsi || !vsi->netdev) {
		dev_err(dev, "Couldn't get main vsi, link aggregation deinit fail\n");
		return;
	}

	nse_lag_remove_netdev(pf, vsi->netdev);

	mutex_lock(&ldev->lock);
	nse_lag_dev_remove_pf(ldev, pf);
	mutex_unlock(&ldev->lock);
	nse_lag_dev_put(ldev);
	return;
#else
	return;
#endif
}

/**
 * nse_is_pf_in_active_lag - check pf is in active hw lag or not
 * @pf: PF struct
 *
 */
bool
nse_is_pf_in_active_lag(struct nse_pf *pf)
{
#ifdef NSE_SUPPORT_HW_LAG
	struct nse_lag *ldev = pf->lag;
	struct lag_tracker	*tracker;
	unsigned long slave_bitmap = 0;
	bool pf_in_lag = false;
	u8 idx;

	if (!nse_is_hw_static_fea_set(&pf->hw, NSE_HW_STATIC_FEA_MISC_SUPPORT_HW_LAG))
		return false;

	if (!ldev)
		return pf_in_lag;

	tracker = &ldev->tracker;
	slave_bitmap = tracker->slave_bitmap;
	for_each_set_bit(idx, &slave_bitmap, NSE_LAG_MAX_PORT) {
		struct nse_pf *itr_pf = ldev->lag_func[idx].pf;

		if (itr_pf == pf && nse_lag_is_active(ldev)) {
			pf_in_lag = true;
			break;
		}
	}
	return pf_in_lag;
#else
	return false;
#endif
}

