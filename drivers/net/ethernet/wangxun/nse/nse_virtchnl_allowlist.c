// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2018 - 2021 Beijing WangXun Technology Co., Ltd. */

#include "nse_virtchnl_allowlist.h"

/* Purpose of this file is to share functionality to allowlist or denylist
 * opcodes used in PF <-> VF communication. Group of opcodes:
 * - default -> should be always allowed after creating VF,
 *   default_allowlist_opcodes
 * - opcodes needed by VF to work correctly, but not associated with caps ->
 *   should be allowed after successful VF resources allocation,
 *   working_allowlist_opcodes
 * - opcodes needed by VF when caps are activated
 *
 * Caps that don't use new opcodes (no opcodes should be allowed):
 * - VIRTCHNL_VF_OFFLOAD_RSS_AQ
 * - VIRTCHNL_VF_OFFLOAD_RSS_REG
 * - VIRTCHNL_VF_OFFLOAD_WB_ON_ITR
 * - VIRTCHNL_VF_OFFLOAD_CRC
 * - VIRTCHNL_VF_OFFLOAD_RX_POLLING
 * - VIRTCHNL_VF_OFFLOAD_RSS_PCTYPE_V2
 * - VIRTCHNL_VF_OFFLOAD_ENCAP
 * - VIRTCHNL_VF_OFFLOAD_ENCAP_CSUM
 * - VIRTCHNL_VF_OFFLOAD_RX_ENCAP_CSUM
 * - VIRTCHNL_VF_OFFLOAD_USO
 */

/* default opcodes to communicate with VF */
static const u32 default_allowlist_opcodes[] = {
	VIRTCHNL_OP_GET_VF_RESOURCES, VIRTCHNL_OP_VERSION,
		VIRTCHNL_OP_RESET_VF, VIRTCHNL_OP_RESET_VF_RDMA,
};

/* opcodes supported after successful VIRTCHNL_OP_GET_VF_RESOURCES */
static const u32 working_allowlist_opcodes[] = {
	VIRTCHNL_OP_CONFIG_VSI_QUEUES, VIRTCHNL_OP_CONFIG_IRQ_MAP,
	VIRTCHNL_OP_ENABLE_QUEUES, VIRTCHNL_OP_DISABLE_QUEUES,
	VIRTCHNL_OP_GET_STATS, VIRTCHNL_OP_EVENT,
	VIRTCHNL_OP_QUERY_QUEUE_INFO,
};

/* VIRTCHNL_VF_OFFLOAD_L2 */
static const u32 l2_allowlist_opcodes[] = {
	VIRTCHNL_OP_ADD_ETH_ADDR, VIRTCHNL_OP_DEL_ETH_ADDR,
	VIRTCHNL_OP_CONFIG_PROMISCUOUS_MODE,
};

/* VIRTCHNL_VF_CAP_RDMA */
static const u32 rdma_allowlist_opcodes[] = {
	VIRTCHNL_OP_RDMA, VIRTCHNL_OP_CONFIG_RDMA_IRQ_MAP,
	VIRTCHNL_OP_RELEASE_RDMA_IRQ_MAP,
};

/* VIRTCHNL_VF_OFFLOAD_VLAN_V2 */
static const u32 vlan_v2_allowlist_opcodes[] = {
	VIRTCHNL_OP_GET_OFFLOAD_VLAN_V2_CAPS, VIRTCHNL_OP_ADD_VLAN_V2,
	VIRTCHNL_OP_DEL_VLAN_V2, VIRTCHNL_OP_ENABLE_VLAN_STRIPPING_V2,
	VIRTCHNL_OP_DISABLE_VLAN_STRIPPING_V2,
	VIRTCHNL_OP_ENABLE_VLAN_INSERTION_V2,
	VIRTCHNL_OP_DISABLE_VLAN_INSERTION_V2,
};

/* VIRTCHNL_VF_OFFLOAD_RSS_PF */
static const u32 rss_pf_allowlist_opcodes[] = {
	VIRTCHNL_OP_CONFIG_RSS_KEY, VIRTCHNL_OP_CONFIG_RSS_LUT, VIRTCHNL_OP_CONFIG_RSS_ALG,
};

/* VIRTCHNL_VF_OFFLOAD_RX_FLEX_DESC */
static const u32 rx_flex_desc_allowlist_opcodes[] = {
	VIRTCHNL_OP_GET_SUPPORTED_RXDIDS,
};

/* VIRTCHNL_VF_OFFLOAD_QoS */
static const u32 tc_allowlist_opcodes[] = {
	VIRTCHNL_OP_GET_QOS_CAPS, VIRTCHNL_OP_CONFIG_QUEUE_TC_MAP,
	VIRTCHNL_OP_CONFIG_QUEUE_BW, VIRTCHNL_OP_CONFIG_QUANTA,
};

/* VIRTCHNL_VF_OFFLOAD_RX_FLEX_DESC */
static const u32 fdir_allowlist_opcodes[] = {
	VIRTCHNL_OP_SET_FDIR_INPUT_MASK,
};

static const u32 logall_allowlist_opcodes[] = {
	VIRTCHNL_OP_SET_LOGALL_BITMAP,
};

struct allowlist_opcode_info {
	const u32 *opcodes;
	size_t size;
};

#define BIT_INDEX(caps) (HWEIGHT((caps) - 1))
#define ALLOW_ITEM(caps, list) \
	[BIT_INDEX(caps)] = { \
		.opcodes = list, \
		.size = ARRAY_SIZE(list) \
	}
static const struct allowlist_opcode_info allowlist_opcodes[] = {
	ALLOW_ITEM(VIRTCHNL_VF_OFFLOAD_L2, l2_allowlist_opcodes),
	ALLOW_ITEM(VIRTCHNL_VF_CAP_RDMA, rdma_allowlist_opcodes),
	ALLOW_ITEM(VIRTCHNL_VF_OFFLOAD_RSS_PF, rss_pf_allowlist_opcodes),
	ALLOW_ITEM(VIRTCHNL_VF_OFFLOAD_RX_FLEX_DESC, rx_flex_desc_allowlist_opcodes),
	ALLOW_ITEM(VIRTCHNL_VF_OFFLOAD_QOS, tc_allowlist_opcodes),
	ALLOW_ITEM(VIRTCHNL_VF_OFFLOAD_VLAN_V2, vlan_v2_allowlist_opcodes),
	ALLOW_ITEM(VIRTCHNL_VF_CAP_FDIR, fdir_allowlist_opcodes),
	ALLOW_ITEM(VIRTCHNL_VF_CAP_LOGALL, logall_allowlist_opcodes),
};

/**
 * nse_vc_is_opcode_allowed - check if this opcode is allowed on this VF
 * @vf: pointer to VF structure
 * @opcode: virtchnl opcode
 *
 * Return true if message is allowed on this VF
 */
bool nse_vc_is_opcode_allowed(struct nse_vf *vf, u32 opcode)
{
	if (opcode >= VIRTCHNL_OP_MAX)
		return false;

	return test_bit(opcode, vf->opcodes_allowlist);
}

/**
 * nse_vc_allowlist_opcodes - allowlist selected opcodes
 * @vf: pointer to VF structure
 * @opcodes: array of opocodes to allowlist
 * @size: size of opcodes array
 *
 * Function should be called to allowlist opcodes on VF.
 */
static void
nse_vc_allowlist_opcodes(struct nse_vf *vf, const u32 *opcodes, size_t size)
{
	unsigned int i;

	for (i = 0; i < size; i++)
		set_bit(opcodes[i], vf->opcodes_allowlist);
}

/**
 * nse_vc_clear_allowlist - clear all allowlist opcodes
 * @vf: pointer to VF structure
 */
static void nse_vc_clear_allowlist(struct nse_vf *vf)
{
	bitmap_zero(vf->opcodes_allowlist, VIRTCHNL_OP_MAX);
}

/**
 * nse_vc_set_default_allowlist - allowlist default opcodes for VF
 * @vf: pointer to VF structure
 */
void nse_vc_set_default_allowlist(struct nse_vf *vf)
{
	nse_vc_clear_allowlist(vf);
	nse_vc_allowlist_opcodes(vf, default_allowlist_opcodes,
				 ARRAY_SIZE(default_allowlist_opcodes));
}

/**
 * nse_vc_set_working_allowlist - allowlist opcodes needed to by VF to work
 * @vf: pointer to VF structure
 *
 * Allowlist opcodes that aren't associated with specific caps, but
 * are needed by VF to work.
 */
void nse_vc_set_working_allowlist(struct nse_vf *vf)
{
	nse_vc_allowlist_opcodes(vf, working_allowlist_opcodes,
				 ARRAY_SIZE(working_allowlist_opcodes));
}

/**
 * nse_vc_set_caps_allowlist - allowlist VF opcodes according caps
 * @vf: pointer to VF structure
 */
void nse_vc_set_caps_allowlist(struct nse_vf *vf)
{
	unsigned long caps = vf->driver_caps;
	unsigned int i;

	for_each_set_bit(i, &caps, ARRAY_SIZE(allowlist_opcodes))
		nse_vc_allowlist_opcodes(vf, allowlist_opcodes[i].opcodes,
					 allowlist_opcodes[i].size);
}
