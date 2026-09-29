// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2018 - 2021 Beijing WangXun Technology Co., Ltd. */
/* @zpzheng */
#include "nsevf.h"

#include "nsevf_adminq.h"
#include "nsevf_fdir.h"

/* some wellknown ptype */
#define NSEVF_PTYPE_MAC_IPV4_UDP_PAY4 35
#define NSEVF_PTYPE_MAC_IPV4_TCP_PAY4 36
#define NSEVF_PTYPE_MAC_IPV6_UDP_PAY4 43
#define NSEVF_PTYPE_MAC_IPV6_TCP_PAY4 44

/* cover all IPv4 ptypes in nse_ptype_lkup  */
#define NSEVF_PTYPE_MAC_IPV4_ALL 0x20 /* 0b' 0010 + Bit3:0 - with bit 3 = 0 */
#define NSEVF_PTYPE_MAC_IPV6_ALL 0x28 /* 0b' 0010 + Bit3:0 - with bit 3 = 1 */

#define NSEVF_PTYPE_MAC_IP_STREAM_MASK 0xF8 /* mask bit 7:4, and bit 3*/

static int nsevf_ntuple_flow_type_to_ptype(struct ethtool_rx_flow_spec *fsp,
					   u8 *ptype, u8 *stream_ptype_mask,
					   u32 *hw_ptype_mask)
{
	*stream_ptype_mask = 0xFF;
	*hw_ptype_mask = 0;

	switch (fsp->flow_type & ~FLOW_EXT) {
	case UDP_V4_FLOW:
		*ptype = NSEVF_PTYPE_MAC_IPV4_UDP_PAY4;
		break;
	case TCP_V4_FLOW:
		*ptype = NSEVF_PTYPE_MAC_IPV4_TCP_PAY4;
		break;
	case UDP_V6_FLOW:
		*ptype = NSEVF_PTYPE_MAC_IPV6_UDP_PAY4;
		break;
	case TCP_V6_FLOW:
		*ptype = NSEVF_PTYPE_MAC_IPV6_TCP_PAY4;
		break;

	case IP_USER_FLOW:
		switch (fsp->h_u.usr_ip4_spec.proto) {
		case IPPROTO_UDP:
			*ptype = NSEVF_PTYPE_MAC_IPV4_UDP_PAY4;
			break;
		case IPPROTO_TCP:
			*ptype = NSEVF_PTYPE_MAC_IPV4_TCP_PAY4;
			break;
		case 0:
			if (!fsp->m_u.usr_ip4_spec.proto) {
				*ptype = NSEVF_PTYPE_MAC_IPV4_ALL;
				*stream_ptype_mask =
					NSEVF_PTYPE_MAC_IP_STREAM_MASK;
				*hw_ptype_mask = NSEVF_FDIR_MASK_OTHER_L4P_M;
				break;
			}
			fallthrough;
		default:
			return 0;
		}
		break;

	case IPV6_USER_FLOW:
		switch (fsp->h_u.usr_ip6_spec.l4_proto) {
		case IPPROTO_UDP:
			*ptype = NSEVF_PTYPE_MAC_IPV6_UDP_PAY4;
			break;
		case IPPROTO_TCP:
			*ptype = NSEVF_PTYPE_MAC_IPV6_TCP_PAY4;
			break;
		case 0:
			if (!fsp->m_u.usr_ip6_spec.l4_proto) {
				*ptype = NSEVF_PTYPE_MAC_IPV6_ALL;
				*stream_ptype_mask =
					NSEVF_PTYPE_MAC_IP_STREAM_MASK;
				*hw_ptype_mask = NSEVF_FDIR_MASK_OTHER_L4P_M;
				break;
			}
			fallthrough;
		default:
			return 0;
		}
		break;

	default:
		return 0;
	}

	return 1;
}

static bool nsevf_is_mask_valid(u64 mask, u64 field)
{
	return (mask & field) == field;
}

static int nsevf_ntuple_parse_userdef(struct nsevf_adapter *adapter,
				      struct ethtool_rx_flow_spec *fsp,
				      u8 ptype,
				      struct nsevf_fdir_ntuple_userdef *data)
{
	struct device *dev = nsevf_adapter_to_dev(adapter);
	u64 value, mask;

	memset(data, 0, sizeof(*data));

	if (!(fsp->flow_type & FLOW_EXT))
		return 0;

	value = be64_to_cpu(*((__force __be64 *)fsp->h_ext.data));
	mask = be64_to_cpu(*((__force __be64 *)fsp->m_ext.data));
	if (!mask)
		return 0;

#define NSEVF_USERDEF_FLEX_WORD_M GENMASK_ULL(15, 0)
#define NSEVF_USERDEF_FLEX_OFFS_S 16
#define NSEVF_USERDEF_FLEX_OFFS_M GENMASK_ULL(31, NSEVF_USERDEF_FLEX_OFFS_S)
#define NSEVF_USERDEF_FLEX_FLTR_M GENMASK_ULL(31, 0)

	if (!nsevf_is_mask_valid(mask, NSEVF_USERDEF_FLEX_FLTR_M) ||
	    value > NSEVF_USERDEF_FLEX_FLTR_M)
		return -EINVAL;

	data->flex_word = value & NSEVF_USERDEF_FLEX_WORD_M;
	data->flex_offset = (value & NSEVF_USERDEF_FLEX_OFFS_M) >>
			    NSEVF_USERDEF_FLEX_OFFS_S;

	/* flex_offset given from ethtool in a byte unit */

	if (data->flex_offset & 0x1) { /* not in word unit */
		return -EINVAL;
	}

	data->flex_offset >>= 1; /* convert to word unit */

	/* 0x1F (word unit) is the maximum value for offsets stored in the internal
	 */
#define NSEVF_USERDEF_FLEX_MAX_OFFS_VAL 0x1F

	if (data->flex_offset > NSEVF_USERDEF_FLEX_MAX_OFFS_VAL)
		return -EINVAL;

	if (ptype == NSEVF_PTYPE_MAC_IPV4_UDP_PAY4 ||
	    ptype == NSEVF_PTYPE_MAC_IPV4_TCP_PAY4 ||
	    ptype == NSEVF_PTYPE_MAC_IPV6_UDP_PAY4 ||
	    ptype == NSEVF_PTYPE_MAC_IPV6_TCP_PAY4) {
		data->flex_base = NSEVF_FDIR_FLEX_CFG_BASE_L4_PAYLOAD;
	} else if (ptype == NSEVF_PTYPE_MAC_IPV4_ALL ||
		   ptype == NSEVF_PTYPE_MAC_IPV6_ALL) {
		data->flex_base = NSEVF_FDIR_FLEX_CFG_BASE_L4_HDR;
	} else {
		dev_err(dev, "can not determine flex_base for this ptype\n");
		return -EINVAL;
	}

	data->flex_fltr = 1; //TRUE

	return 0;
}

static u64 nsevf_get_u64_from_ext_s(struct nsevf_fdir_input_stream *stream,
				    unsigned int bit_idx)
{
	u64 ret = 0;
	u64 orig_val_u64 = 0;
	u16 orig_val_u16 = 0;
	unsigned int u64_idx = 0;
	unsigned int shift = 0;

	/* Ext_S[n] - S[14:0] | S[335:0] | S[335:321] // concatenated
	 */
	if (bit_idx >= 0 && bit_idx <= 14) {
		/* part of LSB bits in S[335:321] part
		 *
		 * part of MSB bits in S[335:0] part
		 */

		/* locate bits in S[335:321] --- which is in last 2 bytes of 42 bytes stream.
		 *
		 * save this 15 bits in u16, and do a shift.
		 */

		orig_val_u16 =
			*((u16 *)stream + 20); /* This is S[335:320] 16 bits */
		orig_val_u16 >>= 1; /* get S[335:321] 15 bits */
		ret = ((u64)orig_val_u16 >> bit_idx); /* shift */

		/* Locate remaining S[335:0] bits in the first u64.
		 *
		 * save first u64 in u64, and do a shift to get remain bits.
		 */
		orig_val_u64 = *((u64 *)stream);
		orig_val_u64 <<= (15 - bit_idx);

		/* concat 2 bits together */
		ret |= orig_val_u64;
	} else if (bit_idx >= 15 && bit_idx <= 287) {
		/* a FULL 64 bits in S[335:0] part, and fully in this part
		 *
		 * Note, *** fully in this part ***
		 *
		 *  287 = Ext_S 366 bits - S[14:0] 15 bits - 64 bits
		 */

		u64_idx = (bit_idx - 15) / 64;
		shift = (bit_idx - 15) % 64;
		orig_val_u64 = *((u64 *)stream + u64_idx);
		if (!shift) {
			/* happen in a 64 bit boundary, lucky */
			ret = orig_val_u64;
		} else {
			/* get LSB bits */
			ret = (orig_val_u64 >> shift);

			/* get MSB bits in next u64 */
			u64_idx++;

			orig_val_u64 = *((u64 *)stream + u64_idx);

			/* concat LSB + MSB bits */
			ret |= (orig_val_u64 << (64 - shift));
		}
	} else if (bit_idx >= 288 && bit_idx < 351) {
		/* Part of LSB bits in S[335:0] part.
		 *
		 *	   --- [*] Note, here a 64 bits may cross 2 u64 in S[335:0].
		 *
		 * sizeof(stream) is five u64 values plus two bytes.
		 *
		 * The value is in stream[4], or partially beyond stream[5].
		 *
		 * Part of MSB bits in S[14:0] part
		 */

		u64_idx = (bit_idx - 15) / 64;
		shift = (bit_idx - 15) % 64;

		if (u64_idx < (sizeof(struct nsevf_fdir_input_stream) / 8)) {
			/* LSB bits starts in (u64 *)stream[4]
			 */

			/* get LSB bits in: (u64 *)stream[4] */
			orig_val_u64 = *((u64 *)stream + u64_idx);
			ret = (orig_val_u64 >> shift);

			/* the whole remain 2 bytes of stream are LSB bits */

			orig_val_u16 = *((u16 *)stream + 20);

			ret |= ((u64)orig_val_u16 << (64 - shift));

			/* determine the shift of MSB bits */
			shift = (64 - shift + 16);
		} else {
			/* LSB bits starts in (u64 *)stream[5]
			 */

			orig_val_u16 = *((u16 *)stream + 20);

			ret = ((u64)orig_val_u16 >> shift);

			/* determine the shift of MSB bits */
			shift = (64 - shift);
		}

		/* MSB bits in S[14:0] */
		/* definitely some bits in (u64 *)stream[5] */

		orig_val_u16 = *((u16 *)stream); /* This is S[15:0] */
		orig_val_u16 &= ~BIT(15); /* get S[14:0] */
		ret |= ((u64)orig_val_u16 << shift);
	} else if (bit_idx >= 351 && bit_idx < 366) {
		/* Whole 64 bits in S[14:0] part
		 */

		orig_val_u16 = *((u16 *)stream); /* This is S[15:0] */
		orig_val_u16 &= ~BIT(15); /* get S[14:0] */
		shift = bit_idx - 351;
		ret = ((u64)orig_val_u16 >> shift);
	}

	return ret;
}

static void nsevf_fdir_compute_hash(struct nsevf_fdir_input_stream *stream,
				    u32 key, u16 *hash_p)
{
	unsigned int i, k_bit_idx, j;
	u64 ext_s_part = 0;
	u64 hash = 0;

	/* Tmp_K[11*32 - 1 : 0] is: 32 x 11 = 352 bits
	 *
	 * Ext_K[350 : 0] is Tmp_K[351 : 0]
	 */

	/* First, loop for:
	 *
	 *	   Ext_K [30 : 0] 31 bits	which is   Tmp_K [31 : 1]
	 *
	 *
	 * That is:
	 *
	 *	   for [i = 0 to 30] portion in datasheet loop: for [i = 0 to 350]
	 */
	ext_s_part = nsevf_get_u64_from_ext_s(stream,
					      0); /* u64 is enough to cover */

	for (k_bit_idx = 1, i = 0; k_bit_idx <= 31; k_bit_idx++, i++) {
		if (key & BIT(k_bit_idx))
			hash ^= (ext_s_part >> i);
	}

	/* previous, i = [30 : 0] 31 bits was already handled, remain:
	 *
	 *	   i = [31, 350] = 320 bits
	 *
	 *	   each 32 bits correspond to a full K [31 : 0]
	 *
	 *	   j is for this 10 loops
	 */
	for (j = 0; j < 10; j++) {
		/* each loop handle 32 bits, we prefetch 64 bits should be OK. */
		ext_s_part = nsevf_get_u64_from_ext_s(stream, i);

		for (k_bit_idx = 0; k_bit_idx < 32; k_bit_idx++, i++) {
			if (key & BIT(k_bit_idx))
				hash ^= (ext_s_part >> k_bit_idx);
		}
	}

	/* keep lowest 16 bits of u64 hash.
	 *
	 * this works on Little-Endian Machine.
	 *
	 * On Big-Endian Machine, this need change.
	 */
	*hash_p = (u16)hash;
}

static u16 nsevf_fdir_compute_bkt_hash(struct nsevf_adapter *adapter,
				       struct nsevf_fdir_input_stream *stream,
				       struct nsevf_fdir_input_stream *mask)
{
	struct nsevf_fdir_cb *cb = &adapter->fdir_cb;
	u16 hash;
	int i = 0;

	/* apply mask */
	stream->flex_bytes &= mask->flex_bytes;
	stream->dst_port &= mask->dst_port;
	stream->src_port &= mask->src_port;
	for (i = 0; i < 4; i++) {
		stream->dst_ip[i] &= mask->dst_ip[i];
		stream->src_ip[i] &= mask->src_ip[i];
	}
	stream->ptype &= mask->ptype;

	nsevf_fdir_compute_hash(stream, le32_to_cpu(cb->fdir_hkey), &hash);

	/* bkt_hash only use 15 bits */
	return hash & 0x7FFF;
}

static u16 nsevf_fdir_compute_sig_hash(struct nsevf_adapter *adapter,
				       struct nsevf_fdir_input_stream *stream,
				       struct nsevf_fdir_input_stream *mask)
{
	struct nsevf_fdir_cb *cb = &adapter->fdir_cb;
	u16 hash;
	int i = 0;

	/* apply mask */
	stream->flex_bytes &= mask->flex_bytes;
	stream->dst_port &= mask->dst_port;
	stream->src_port &= mask->src_port;
	for (i = 0; i < 4; i++) {
		stream->dst_ip[i] &= mask->dst_ip[i];
		stream->src_ip[i] &= mask->src_ip[i];
	}
	stream->ptype &= mask->ptype;

	nsevf_fdir_compute_hash(stream, le32_to_cpu(cb->fdir_skey), &hash);

	return hash & 0x1FFF;
}

static enum nsevf_status
nsevf_uq_conf_filter_by_utilq(struct nsevf_adapter *adapter,
			      struct nsevf_fdir_utilq_config_payload *payload)
{
	struct nsevf_hw *hw = &adapter->hw;
	struct nse_aq_desc desc;
	enum nsevf_status status = 0;

	if (!hw->utilq_initialized) {
		nsevf_debug(hw, NSEVF_DBG_RCF, "[%s] utilQ not ready\n",
			    __func__);
		status = NSEVF_ERR_NOT_READY;
		goto out;
	}

	nsevf_fill_default_direct_cmd_desc(&desc, NSEVF_AQ_OPC_CATEGORY_RCF,
					   NSEVF_AQ_OPC_FDIR_CONF_FILTER_BY_UTILQ);

	desc.mailbox_id = cpu_to_le16(NSEVF_AQ_MAILBOX_ID_UTILQ);

	/* always set RD and BUF flag, because always have indirect buffer	*/
	desc.flags |= cpu_to_le16(NSE_AQ_FLAG_RD);
	desc.flags |= cpu_to_le16(NSE_AQ_FLAG_BUF);

	status = nsevf_asq_send_command(hw, &hw->utilq, &desc, payload,
					sizeof(*payload), NULL);

out:
	return status;
}

static bool nsevf_match_existing_filter(struct nsevf_fdir_cb *cb,
					struct nsevf_fdir_filter *filter)
{
	struct hlist_node *node2;
	struct nsevf_fdir_filter *f = NULL;

	hlist_for_each_entry_safe(f, node2, &cb->filter_list, hnode) {
		if (f->bkt_hash == filter->bkt_hash &&
		    !memcmp(&f->input_stream, &filter->input_stream,
			    sizeof(f->input_stream))) {
			return true;
		}
	}

	return false;
}

static int nsevf_fdir_add_perfect_filter(struct nsevf_adapter *adapter,
					 struct nsevf_fdir_filter *filter)
{
	struct nsevf_fdir_input_stream *stream = &filter->input_stream;
	struct nsevf_fdir_utilq_config_payload *uq_cmd;
	u32 val;
	enum nsevf_status status;
	int ret;

	uq_cmd = kzalloc(sizeof(*uq_cmd), GFP_KERNEL);
	if (!uq_cmd) {
		ret = -ENOMEM;
		goto out;
	}

	uq_cmd->sa0 = stream->src_ip[0];
	uq_cmd->da = stream->dst_ip[0];

	val = (((u32)stream->src_port) << NSEVF_FDIR_PORT_SPORT_S) |
	      (((u32)stream->dst_port) << NSEVF_FDIR_PORT_DPORT_S);
	uq_cmd->port = cpu_to_le32(val);

	val = ((u32)stream->ptype) |
	      ((u32)stream->vsi << NSEVF_FDIR_FLEX_VSI_S) |
	      (((u32)stream->flex_bytes) << NSEVF_FDIR_FLEX_FLEX_DATA_S);
	uq_cmd->flex = cpu_to_le32(val);

	val = ((u32)filter->sw_idx << NSEVF_FDIR_HASH_SW_IDX_S) |
	      NSEVF_FDIR_HASH_VLD_M |
	      ((u32)filter->bkt_hash << NSEVF_FDIR_HASH_BUCKET_HASH_S);
	uq_cmd->hash = cpu_to_le32(val);

	val = (NSEVF_FDIR_CMD_OP_ADD << NSEVF_FDIR_CMD_OP_S) |
	      NSEVF_FDIR_CMD_UPDATE_M | NSEVF_FDIR_CMD_LAST_M |
	      NSEVF_FDIR_CMD_QUEUE_EN_M;

	if (filter->is_action_drop)
		val |= NSEVF_FDIR_CMD_DROP_M;

	val |= ((u32)filter->action_rxq_abs_id
		<< NSEVF_FDIR_CMD_QUEUE_ACTION_S);
	uq_cmd->cmd = cpu_to_le32(val);

	status = nsevf_uq_conf_filter_by_utilq(adapter, uq_cmd);
	if (status) {
		ret = -EIO;
		goto out;
	}

	ret = 0;
out:
	kfree(uq_cmd);

	return ret;
}

static int nsevf_fdir_del_perfect_filter(struct nsevf_adapter *adapter,
					 struct nsevf_fdir_filter *filter)
{
	struct nsevf_fdir_input_stream *stream = &filter->input_stream;
	struct nsevf_fdir_utilq_config_payload *uq_cmd;
	u32 val;
	enum nsevf_status status;
	int ret;

	uq_cmd = kzalloc(sizeof(*uq_cmd), GFP_KERNEL);
	if (!uq_cmd) {
		ret = -ENOMEM;
		goto out;
	}

	val = (u32)stream->vsi << NSEVF_FDIR_FLEX_VSI_S;
	uq_cmd->flex = cpu_to_le32(val);

	val = ((u32)filter->sw_idx << NSEVF_FDIR_HASH_SW_IDX_S) |
	      ((u32)filter->bkt_hash << NSEVF_FDIR_HASH_BUCKET_HASH_S);
	uq_cmd->hash = cpu_to_le32(val);

	val = (NSEVF_FDIR_CMD_OP_REMOVE << NSEVF_FDIR_CMD_OP_S);
	uq_cmd->cmd = cpu_to_le32(val);

	status = nsevf_uq_conf_filter_by_utilq(adapter, uq_cmd);

	if (status) {
		ret = -EIO;
		goto out;
	}

	ret = 0;
out:
	kfree(uq_cmd);

	return ret;
}

static int nsevf_fdir_add_sig_filter(struct nsevf_adapter *adapter,
				     struct nsevf_fdir_filter *filter)
{
	struct nsevf_fdir_utilq_config_payload *uq_cmd;
	u32 val;
	enum nsevf_status status;
	int ret;

	uq_cmd = kzalloc(sizeof(*uq_cmd), GFP_KERNEL);
	if (!uq_cmd) {
		ret = -ENOMEM;
		goto out;
	}

	val = ((u32)filter->sig_hash << NSEVF_FDIR_HASH_SIG_HASH_S) |
	      ((u32)adapter->vf_res->lan_channel_pf_id
	       << NSEVF_FDIR_HASH_SIG_PF_S) |
	      NSEVF_FDIR_HASH_VLD_M |
	      ((u32)filter->bkt_hash << NSEVF_FDIR_HASH_BUCKET_HASH_S);

	uq_cmd->hash = cpu_to_le32(val);

	val = (NSEVF_FDIR_CMD_OP_ADD << NSEVF_FDIR_CMD_OP_S) |
	      NSEVF_FDIR_CMD_UPDATE_M | NSEVF_FDIR_CMD_LAST_M |
	      NSEVF_FDIR_CMD_QUEUE_EN_M;
	val |= ((u32)filter->action_rxq_abs_id
		<< NSEVF_FDIR_CMD_QUEUE_ACTION_S);

	uq_cmd->cmd = cpu_to_le32(val);

	status = nsevf_uq_conf_filter_by_utilq(adapter, uq_cmd);

	if (status) {
		ret = -EIO;
		goto out;
	}

	ret = 0;

out:
	kfree(uq_cmd);

	return ret;
}

static int nsevf_fdir_del_sig_filter(struct nsevf_adapter *adapter,
				     struct nsevf_fdir_filter *filter)
{
	struct nsevf_fdir_utilq_config_payload *uq_cmd;
	u32 val;
	enum nsevf_status status;
	int ret;

	uq_cmd = kzalloc(sizeof(*uq_cmd), GFP_KERNEL);
	if (!uq_cmd) {
		ret = -ENOMEM;
		goto out;
	}

	val = ((u32)filter->sig_hash << NSEVF_FDIR_HASH_SW_IDX_S) |
	      ((u32)filter->bkt_hash << NSEVF_FDIR_HASH_BUCKET_HASH_S);
	uq_cmd->hash = cpu_to_le32(val);

	val = (NSEVF_FDIR_CMD_OP_REMOVE << NSEVF_FDIR_CMD_OP_S);
	uq_cmd->cmd = cpu_to_le32(val);

	status = nsevf_uq_conf_filter_by_utilq(adapter, uq_cmd);
	if (status) {
		ret = -EIO;
		goto out;
	}

	ret = 0;
out:
	kfree(uq_cmd);

	return ret;
}

static int nsevf_fdir_add_filter(struct nsevf_adapter *adapter,
				 struct nsevf_fdir_filter *filter)
{
	struct nsevf_fdir_cb *cb = &adapter->fdir_cb;

	if (cb->fdir_mode == NSEVF_FDIR_CTL_FILTER_MODE_PERFECT)
		return nsevf_fdir_add_perfect_filter(adapter, filter);
	else
		return nsevf_fdir_add_sig_filter(adapter, filter);
}

static int nsevf_fdir_del_filter(struct nsevf_adapter *adapter,
				 struct nsevf_fdir_filter *filter)
{
	struct nsevf_fdir_cb *cb = &adapter->fdir_cb;

	if (cb->fdir_mode == NSEVF_FDIR_CTL_FILTER_MODE_PERFECT)
		return nsevf_fdir_del_perfect_filter(adapter, filter);
	else
		return nsevf_fdir_del_sig_filter(adapter, filter);
}

static int nsevf_fdir_update_ethtool_entry(struct nsevf_adapter *adapter,
					   struct nsevf_fdir_filter *new_filter,
					   u16 sw_idx)
{
	struct nsevf_fdir_cb *cb = &adapter->fdir_cb;
	struct hlist_node *node2;
	struct nsevf_fdir_filter *f = NULL, *prev = NULL;
	bool deleted = false;
	int ret;

	hlist_for_each_entry_safe(f, node2, &cb->filter_list, hnode) {
		/* hash found, or no matching entry */
		if (f->sw_idx >= sw_idx)
			break;
		prev = f;
	}

	/* if there is an old rule occupying our place remove it */
	if (f && f->sw_idx == sw_idx) {
		if (!new_filter || new_filter->bkt_hash != f->bkt_hash) {
			ret = nsevf_fdir_del_filter(adapter, f);
			if (ret)
				return ret;
		}

		hlist_del(&f->hnode);
		kfree(f);
		cb->filter_count--;
		deleted = true;
	}

	/* If we weren't given an input, then this was a request to delete a
	 * filter. We should return -EINVAL if the filter wasn't found, but
	 * return 0 if the rule was successfully deleted.
	 */
	if (!new_filter)
		return deleted ? 0 : -EINVAL;

	/* initialize node and set software index */
	INIT_HLIST_NODE(&new_filter->hnode);

	/* add filter to the list */
	if (prev)
		hlist_add_behind(&new_filter->hnode, &prev->hnode);
	else
		hlist_add_head(&new_filter->hnode, &cb->filter_list);

	/* update counts */
	cb->filter_count++;

	return 0;
}

int nsevf_add_ethtool_ntuple(struct nsevf_adapter *adapter,
			     struct ethtool_rxnfc *cmd)
{
	struct nsevf_hw *hw = &adapter->hw;
	struct nsevf_fdir_cb *cb = &adapter->fdir_cb;
	struct device *dev = nsevf_adapter_to_dev(adapter);
	struct ethtool_rx_flow_spec *fsp =
		(struct ethtool_rx_flow_spec *)&cmd->fs;
	struct nsevf_fdir_filter *filter = NULL;
	struct nsevf_fdir_input_stream *mask = NULL;
	struct nsevf_fdir_ntuple_userdef userdef;
	u32 hw_ptype_mask = 0;
	u16 rxq_abs_id;
	int ret = 0;

	if (!(adapter->flags & NSEVF_FLAG_FDIR_CAPABLE)) {
		ret = -EOPNOTSUPP;
		goto err_out;
	}

	if (!hw->utilq_initialized) {
		ret = -EOPNOTSUPP;
		goto err_out;
	}

	/* Do not program filters during reset */
	if (nsevf_is_reset_in_progress(adapter)) {
		dev_err(dev,
			"Device is resetting - adding ntuple filters not supported during reset\n");
		ret = -EBUSY;
		goto err_out;
	}

	if (fsp->ring_cookie == RX_CLS_FLOW_DISC &&
	    cb->fdir_mode == NSEVF_FDIR_CTL_FILTER_MODE_SIGNATURE) {
		dev_err(dev, "fdir: signature mode does not support drop\n");
		ret = -EOPNOTSUPP;
		goto err_out;
	}

	if (fsp->ring_cookie == RX_CLS_FLOW_DISC) {
		rxq_abs_id = cb->fdir_drp_rxq_abs_id;
	} else {
		u32 ring_id = ethtool_get_flow_spec_ring(fsp->ring_cookie);

		if (ring_id >= adapter->num_active_queues) {
			dev_err(dev,
				"fdir: specified rxq out of enabled rxq range.\n");
			ret = -EINVAL;
			goto err_out;
		}

		rxq_abs_id = ring_id + hw->dev_caps.lan_rxq_base_abs_id;
	}

	/* Don't allow indexes to exist outside of available space */
	if ((cb->fdir_mode == NSEVF_FDIR_CTL_FILTER_MODE_PERFECT &&
	     fsp->location >= (cb->fdir_max_num_pfilter - 2)) ||
	    (cb->fdir_mode == NSEVF_FDIR_CTL_FILTER_MODE_SIGNATURE &&
	     fsp->location >= (cb->fdir_max_num_sfilter - 2))) {
		dev_err(dev, "fdir: ntuple filter location out of range\n");
		ret = -EINVAL;
		goto err_out;
	}

	filter = kzalloc(sizeof(*filter), GFP_ATOMIC);
	mask = kzalloc(sizeof(*mask), GFP_ATOMIC);
	if (!filter || !mask) {
		ret = -ENOMEM;
		goto err_out;
	}

	/* set SW index */
	filter->sw_idx = fsp->location;

	/* record ptype */
	if (!nsevf_ntuple_flow_type_to_ptype(fsp, &filter->input_stream.ptype,
					     &mask->ptype, &hw_ptype_mask)) {
		dev_err(dev, "fdir: Unrecognized flow type\n");
		ret = -EOPNOTSUPP;
		goto err_out;
	}

	if ((filter->input_stream.ptype & NSEVF_PTYPE_MAC_IP_STREAM_MASK) ==
	    NSEVF_PTYPE_MAC_IPV6_ALL) { /* ptype is IPv6 */

		if (fsp->m_u.tcp_ip6_spec.ip6src[0] ||
		    fsp->m_u.tcp_ip6_spec.ip6src[1] ||
		    fsp->m_u.tcp_ip6_spec.ip6src[2] ||
		    fsp->m_u.tcp_ip6_spec.ip6src[3] ||
		    fsp->m_u.tcp_ip6_spec.ip6dst[0] ||
		    fsp->m_u.tcp_ip6_spec.ip6dst[1] ||
		    fsp->m_u.tcp_ip6_spec.ip6dst[2] ||
		    fsp->m_u.tcp_ip6_spec.ip6dst[3]) {
			dev_err(dev,
				"fdir: Error not support IPv6 address fitlers\n");
			ret = -EOPNOTSUPP;
			goto err_out;
		}

		filter->input_stream.src_port =
			be16_to_le(fsp->h_u.tcp_ip6_spec.psrc);
		mask->src_port = be16_to_le(fsp->m_u.tcp_ip6_spec.psrc);

		filter->input_stream.dst_port =
			be16_to_le(fsp->h_u.tcp_ip6_spec.pdst);
		mask->dst_port = be16_to_le(fsp->m_u.tcp_ip6_spec.pdst);

	} else {
		/* Copy input into formatted structures */
		filter->input_stream.src_ip[0] =
			be32_to_le(fsp->h_u.tcp_ip4_spec.ip4src);
		mask->src_ip[0] = be32_to_le(fsp->m_u.tcp_ip4_spec.ip4src);

		filter->input_stream.dst_ip[0] =
			be32_to_le(fsp->h_u.tcp_ip4_spec.ip4dst);
		mask->dst_ip[0] = be32_to_le(fsp->m_u.tcp_ip4_spec.ip4dst);

		filter->input_stream.src_port =
			be16_to_le(fsp->h_u.tcp_ip4_spec.psrc);
		mask->src_port = be16_to_le(fsp->m_u.tcp_ip4_spec.psrc);

		filter->input_stream.dst_port =
			be16_to_le(fsp->h_u.tcp_ip4_spec.pdst);
		mask->dst_port = be16_to_le(fsp->m_u.tcp_ip4_spec.pdst);
	}

	memset(&userdef, 0, sizeof(userdef));

	if (fsp->flow_type & FLOW_EXT) {
		if (fsp->m_ext.vlan_etype || fsp->m_ext.vlan_tci) {
			dev_err(dev,
				"fdir: not support VLAN, etype, DMAC filtering\n");
			ret = -EOPNOTSUPP;
			goto err_out;
		}

		if (nsevf_ntuple_parse_userdef(adapter, fsp,
					       filter->input_stream.ptype,
					       &userdef)) {
			dev_err(dev, "fdir: BAD user-def\n");
			ret = -EOPNOTSUPP;
			goto err_out;
		}
	}

	/* determine if we need to drop or route the packet */
	if (fsp->ring_cookie == RX_CLS_FLOW_DISC)
		filter->is_action_drop = 1;
	else
		filter->is_action_drop = 0;

	filter->action_rxq_abs_id = rxq_abs_id;

	/* save something for quick GET */
	filter->fsp_ring_cookie = fsp->ring_cookie;
	filter->fsp_flow_type = fsp->flow_type;
	filter->fsp_h_ext_data[0] = fsp->h_ext.data[0];
	filter->fsp_h_ext_data[1] = fsp->h_ext.data[1];
	filter->fsp_m_ext_data[0] = fsp->m_ext.data[0];
	filter->fsp_m_ext_data[1] = fsp->m_ext.data[1];

	/* fill the missing part of filter stream and mask */
	filter->input_stream.vsi = adapter->vsi.vsi_abs_id;
	mask->vsi = 0xFF;

	if (userdef.flex_fltr) {
		filter->input_stream.flex_bytes =
			cpu_to_le16(userdef.flex_word);
		mask->flex_bytes = cpu_to_le16(0xFFFF);
	}

	filter->bkt_hash =
		nsevf_fdir_compute_bkt_hash(adapter, &filter->input_stream, mask);
	if (cb->fdir_mode == NSEVF_FDIR_CTL_FILTER_MODE_SIGNATURE)
		filter->sig_hash =
			nsevf_fdir_compute_sig_hash(adapter,
						    &filter->input_stream, mask);

	mutex_lock(&cb->lock);

	/* handle mask */
	if (hlist_empty(&cb->filter_list)) {
		/* save mask and program input mask into HW */
		memcpy(&cb->input_stream_mask, mask,
		       sizeof(cb->input_stream_mask));

		memcpy(&cb->flex_setting, &userdef, sizeof(cb->flex_setting));

		cb->hw_ptype_mask = hw_ptype_mask;

		/* apply mask and flex offset */
		nsevf_schedule_aq_request(adapter,
					  NSEVF_FLAG_AQ_SET_FDIR_INPUT_MASK);
	} else {
		if (memcmp(&cb->input_stream_mask, mask,
			   sizeof(cb->input_stream_mask))) {
			dev_err(dev,
				"fdir: Hardware only supports one mask per VSP. To change the mask you must first delete all the rules.\n");
			ret = -EIO;
			goto err_out_w_lock;
		}

		if (cb->flex_setting.flex_fltr != userdef.flex_fltr ||
		    cb->flex_setting.flex_offset != userdef.flex_offset) {
			dev_err(dev,
				"fdir: Hardware only supports one flex offset per VSP. To change the mask you must first delete all the rules.\n");
			ret = -EIO;
			goto err_out_w_lock;
		}
	}

	/* check if new entry does not exist on filter list */
	if (nsevf_match_existing_filter(cb, filter)) {
		dev_err(dev, "fdir: already exist this filter\n");
		ret = -EEXIST;
		goto err_out_w_lock;
	}

	ret = nsevf_fdir_add_filter(adapter, filter);
	if (ret) {
		dev_err(dev, "fdir: add filter to HW\n");
		goto err_out_w_lock;
	}

	(void)nsevf_fdir_update_ethtool_entry(adapter, filter, filter->sw_idx);
	mutex_unlock(&cb->lock);

	kfree(mask);

	return 0;

err_out_w_lock:
	mutex_unlock(&cb->lock);

err_out:
	kfree(filter);

	kfree(mask);

	return ret;
}

int nsevf_del_ethtool_ntuple(struct nsevf_adapter *adapter,
			     struct ethtool_rxnfc *cmd)
{
	struct nsevf_fdir_cb *cb = &adapter->fdir_cb;
	struct ethtool_rx_flow_spec *fsp =
		(struct ethtool_rx_flow_spec *)&cmd->fs;
	int ret;

	mutex_lock(&cb->lock);
	/* give filter = NULL, would delete HW filter internnally */
	ret = nsevf_fdir_update_ethtool_entry(adapter, NULL, fsp->location);
	mutex_unlock(&cb->lock);

	return ret;
}

int nsevf_get_ethtool_ntuple(struct nsevf_adapter *adapter,
			     struct ethtool_rxnfc *cmd)
{
	struct nsevf_fdir_cb *cb = &adapter->fdir_cb;
	struct ethtool_rx_flow_spec *fsp =
		(struct ethtool_rx_flow_spec *)&cmd->fs;
	struct hlist_node *node;
	struct nsevf_fdir_filter *f = NULL;
	struct nsevf_fdir_input_stream *stream, *stream_mask;
	int ret;

	/* report total rule count */
	cmd->data = (cb->fdir_mode == NSEVF_FDIR_CTL_FILTER_MODE_PERFECT) ?
			    (cb->fdir_max_num_pfilter - 2) :
			    (cb->fdir_max_num_sfilter - 2);

	mutex_lock(&cb->lock);

	hlist_for_each_entry_safe(f, node, &cb->filter_list, hnode) {
		if (fsp->location <= f->sw_idx)
			break;
	}

	if (!f || fsp->location != f->sw_idx) {
		ret = -EINVAL;
		goto out;
	}

	stream = &f->input_stream;
	stream_mask = &cb->input_stream_mask;

	fsp->flow_type = f->fsp_flow_type;
	if (fsp->flow_type == IP_USER_FLOW) {
		fsp->h_u.usr_ip4_spec.ip_ver = ETH_RX_NFC_IP4;
		fsp->h_u.usr_ip4_spec.proto = 0;
		fsp->m_u.usr_ip4_spec.proto = 0;
	}

	if ((stream->ptype & NSEVF_PTYPE_MAC_IP_STREAM_MASK) ==
	    NSEVF_PTYPE_MAC_IPV6_ALL) {
		fsp->h_u.tcp_ip6_spec.psrc = le16_to_be(stream->src_port);
		fsp->m_u.tcp_ip6_spec.psrc = le16_to_be(stream_mask->src_port);
		fsp->h_u.tcp_ip6_spec.pdst = le16_to_be(stream->dst_port);
		fsp->m_u.tcp_ip6_spec.pdst = le16_to_be(stream_mask->dst_port);
	} else {
		fsp->h_u.tcp_ip4_spec.psrc = le16_to_be(stream->src_port);
		fsp->m_u.tcp_ip4_spec.psrc = le16_to_be(stream_mask->src_port);
		fsp->h_u.tcp_ip4_spec.pdst = le16_to_be(stream->dst_port);
		fsp->m_u.tcp_ip4_spec.pdst = le16_to_be(stream_mask->dst_port);
		fsp->h_u.tcp_ip4_spec.ip4src = le32_to_be(stream->src_ip[0]);
		fsp->m_u.tcp_ip4_spec.ip4src =
			le32_to_be(stream_mask->src_ip[0]);
		fsp->h_u.tcp_ip4_spec.ip4dst = le32_to_be(stream->dst_ip[0]);
		fsp->m_u.tcp_ip4_spec.ip4dst =
			le32_to_be(stream_mask->dst_ip[0]);
	}
	if (cb->flex_setting.flex_fltr) {
		fsp->flow_type |= FLOW_EXT;
		fsp->h_ext.data[0] = f->fsp_h_ext_data[0];
		fsp->h_ext.data[1] = f->fsp_h_ext_data[1];
		fsp->m_ext.data[0] = f->fsp_m_ext_data[0];
		fsp->m_ext.data[1] = f->fsp_m_ext_data[1];
	}

	fsp->ring_cookie = f->fsp_ring_cookie;

	ret = 0;

out:
	mutex_unlock(&cb->lock);
	return ret;
}

int nsevf_get_ethtool_ntuple_ids(struct nsevf_adapter *adapter,
				 struct ethtool_rxnfc *cmd, u32 *rule_locs)
{
	struct nsevf_fdir_cb *cb = &adapter->fdir_cb;
	struct hlist_node *node;
	struct nsevf_fdir_filter *f;
	int cnt = 0;
	int ret;

	/* report total rule count */
	cmd->data = (cb->fdir_mode == NSEVF_FDIR_CTL_FILTER_MODE_PERFECT) ?
			    (cb->fdir_max_num_pfilter - 2) :
			    (cb->fdir_max_num_sfilter - 2);

	mutex_lock(&cb->lock);

	hlist_for_each_entry_safe(f, node, &cb->filter_list, hnode) {
		if (cnt == cmd->rule_cnt) {
			ret = -EMSGSIZE;
			goto out;
		}
		rule_locs[cnt] = f->sw_idx;
		cnt++;
	}

	ret = 0;
out:
	mutex_unlock(&cb->lock);

	return ret;
}

static int nsevf_fdir_flush_vsi_perfect_filter(struct nsevf_adapter *adapter)
{
	struct nsevf_fdir_utilq_config_payload *uq_cmd = NULL;
	u32 val;
	enum nsevf_status status;
	int ret;

	if (!adapter->vsi_res)
		return 0;

	uq_cmd = kzalloc(sizeof(*uq_cmd), GFP_KERNEL);
	if (!uq_cmd) {
		ret = -ENOMEM;
		goto out;
	}

	val = ((u32)adapter->vsi_res->vsi_abs_id << NSEVF_FDIR_FLEX_VSI_S);

	uq_cmd->flex = cpu_to_le32(val);

	val = NSEVF_FDIR_CMD_RM_VSI_ALL_M |
	      (NSEVF_FDIR_CMD_OP_REMOVE << NSEVF_FDIR_CMD_OP_S);

	uq_cmd->cmd = cpu_to_le32(val);

	status = nsevf_uq_conf_filter_by_utilq(adapter, uq_cmd);

	if (status) {
		ret = -EIO;
		goto out;
	}

	ret = 0;

out:
	kfree(uq_cmd);

	return ret;
}

void nsevf_del_ethool_ntuple_all(struct nsevf_adapter *adapter, bool in_reset)
{
	struct nsevf_fdir_cb *cb = &adapter->fdir_cb;
	struct hlist_node *node2;
	struct nsevf_fdir_filter *f = NULL;

	mutex_lock(&cb->lock);

	/* perfect mode support flush all filter of a VSI */
	if (cb->fdir_mode == NSEVF_FDIR_CTL_FILTER_MODE_PERFECT)
		(void)nsevf_fdir_flush_vsi_perfect_filter(adapter);

	hlist_for_each_entry_safe(f, node2, &cb->filter_list, hnode) {
		if (cb->fdir_mode == NSEVF_FDIR_CTL_FILTER_MODE_SIGNATURE)
			(void)nsevf_fdir_del_filter(adapter, f);

		if (in_reset) /* save in shadow table for later replay */
			continue;

		hlist_del(&f->hnode);
		kfree(f);

		cb->filter_count--;
	}

	mutex_unlock(&cb->lock);
}

void nsevf_fdir_dump_cb(struct nsevf_adapter *adapter)
{
	struct nsevf_hw *hw = &adapter->hw;
	struct nsevf_fdir_cb *cb = &adapter->fdir_cb;
	struct device *dev = nsevf_adapter_to_dev(adapter);

	if (!(adapter->flags & NSEVF_FLAG_FDIR_CAPABLE)) {
		dev_info(dev, "FDir not support on this VF\n");
		return;
	}

	dev_info(dev, "====== FDir CB content:\n");

	dev_info(dev, "filter_count=%d\n", cb->filter_count);

	dev_info(dev, "input_stream_mask:\n");
	dev_info(dev, "\t vsi=%X\n", cb->input_stream_mask.vsi);
	dev_info(dev, "\t flex_bytes=%X\n",
		 le16_to_cpu(cb->input_stream_mask.flex_bytes));
	dev_info(dev, "\t dst_port=%X\n",
		 le16_to_cpu(cb->input_stream_mask.dst_port));
	dev_info(dev, "\t src_port=%X\n",
		 le16_to_cpu(cb->input_stream_mask.src_port));
	dev_info(dev, "\t dst_ip[0]=%X\n",
		 le32_to_cpu(cb->input_stream_mask.dst_ip[0]));
	dev_info(dev, "\t src_ip[0]=%X\n",
		 le32_to_cpu(cb->input_stream_mask.src_ip[0]));
	dev_info(dev, "\t ptype[0]=%X\n", cb->input_stream_mask.ptype);

	dev_info(dev, "flex_setting:\n");
	dev_info(dev, "\t flex_fltr=%d\n", cb->flex_setting.flex_fltr);
	dev_info(dev, "\t flex_base=%d\n", cb->flex_setting.flex_base);
	dev_info(dev, "\t flex_offset=%d\n", cb->flex_setting.flex_offset);
	dev_info(dev, "\t flex_word=%d\n", cb->flex_setting.flex_word);

	dev_info(dev, "hw_ptype_mask=%X\n", cb->hw_ptype_mask);

	dev_info(dev, "utilq_initialized=%d\n", hw->utilq_initialized);
	if (hw->utilq_initialized) {
		dev_info(dev, "utilq:\n");
		dev_info(dev, "\t qtype=%d\n", hw->utilq.qtype);
		dev_info(dev, "\t num_sq_entries=%d\n",
			 hw->utilq.num_asq_entries);
		dev_info(dev, "\t asq_buf_size=%d\n", hw->utilq.asq_buf_size);
		dev_info(dev, "\t asq_last_status=%d\n",
			 hw->utilq.asq_last_status);

		dev_info(dev, "\t sq:\n");
		dev_info(dev, "\t\t next_to_use=%d\n",
			 hw->utilq.asq.next_to_use);
		dev_info(dev, "\t\t next_to_clean=%d\n",
			 hw->utilq.asq.next_to_clean);
		dev_info(dev, "\t\t bah(addr=%X)=%X\n", hw->utilq.asq.bah,
			 rd32(hw, hw->utilq.asq.bah));
		dev_info(dev, "\t\t bal(addr=%X)=%X\n", hw->utilq.asq.bal,
			 rd32(hw, hw->utilq.asq.bal));
		dev_info(dev, "\t\t len(addr=%X)=%X\n", hw->utilq.asq.len,
			 rd32(hw, hw->utilq.asq.len));
		dev_info(dev, "\t\t head(addr=%X)=%X\n", hw->utilq.asq.head,
			 rd32(hw, hw->utilq.asq.head));
		dev_info(dev, "\t\t tail(addr=%X)=%X\n", hw->utilq.asq.tail,
			 rd32(hw, hw->utilq.asq.tail));
	}

	dev_info(dev, "drp_rxq_abs_id=%d\n", cb->fdir_drp_rxq_abs_id);
	dev_info(dev, "VF lan_rxq_base_abs_id=%d\n",
		 hw->dev_caps.lan_rxq_base_abs_id);

	dev_info(dev, "fdir_hkey = %08X\n", le32_to_cpu(cb->fdir_hkey));
	dev_info(dev, "fdir_skey = %08X\n", le32_to_cpu(cb->fdir_skey));

	dev_info(dev, "mode=%d\n", cb->fdir_mode);

	dev_info(dev, "max_num_pfilter=%d\n", cb->fdir_max_num_pfilter);
	dev_info(dev, "max_num_sfilter=%d\n", cb->fdir_max_num_sfilter);
}

void nsevf_fdir_pre_init(struct nsevf_adapter *adapter)
{
	struct nsevf_fdir_cb *cb = &adapter->fdir_cb;

	memset(cb, 0, sizeof(*cb));

	mutex_init(&cb->lock);
	INIT_HLIST_HEAD(&cb->filter_list);
}

void nsevf_fdir_init(struct nsevf_adapter *adapter)
{
	struct nsevf_hw *hw = &adapter->hw;
	struct nsevf_fdir_cb *cb = &adapter->fdir_cb;

	if (!nsevf_fdir_ena) {
		adapter->flags &= ~NSEVF_FLAG_FDIR_CAPABLE;
		return;
	}

	/* VF not support FDIR due to lack of FDIR filters */
	if (!(adapter->vf_res->vf_cap_flags & VIRTCHNL_VF_CAP_FDIR)) {
		adapter->flags &= ~NSEVF_FLAG_FDIR_CAPABLE;
		return;
	}

	cb->fdir_mode = adapter->vf_res->fdir_mode;
	cb->fdir_drp_rxq_abs_id = adapter->vf_res->fdir_drp_rxq_abs_id;
	cb->fdir_hkey = adapter->vf_res->fdir_hkey;
	cb->fdir_skey = adapter->vf_res->fdir_skey;

	if (cb->fdir_mode == NSEVF_FDIR_CTL_FILTER_MODE_PERFECT) {
		cb->fdir_max_num_pfilter =
			adapter->vf_res->fdir_max_num_pfilter;
	} else if (cb->fdir_mode == NSEVF_FDIR_CTL_FILTER_MODE_SIGNATURE) {
		cb->fdir_max_num_sfilter =
			adapter->vf_res->fdir_max_num_sfilter;
	}

	adapter->flags |= NSEVF_FLAG_FDIR_CAPABLE;

	(void)nsevf_fdir_init_utilq(hw);
}

void nsevf_fdir_deinit(struct nsevf_adapter *adapter, bool in_reset)
{
	struct nsevf_hw *hw = &adapter->hw;

	if (!(adapter->flags & NSEVF_FLAG_FDIR_CAPABLE))
		return;

	nsevf_del_ethool_ntuple_all(adapter, in_reset);

	nsevf_fdir_shutdown_utilq(hw);
}

static void nsevf_fdir_replay_filters(struct nsevf_adapter *adapter)
{
	struct nsevf_fdir_cb *cb = &adapter->fdir_cb;
	struct nsevf_fdir_filter *f = NULL;

	if (!(adapter->flags & NSEVF_FLAG_FDIR_CAPABLE))
		return;

	hlist_for_each_entry(f, &cb->filter_list, hnode) {
		(void)nsevf_fdir_add_filter(adapter, f);
	}
}

void nsevf_fdir_rebuild(struct nsevf_adapter *adapter)
{
	if (!(adapter->flags & NSEVF_FLAG_FDIR_CAPABLE))
		return;

	nsevf_fdir_init(adapter);

	nsevf_fdir_replay_filters(adapter);
}
