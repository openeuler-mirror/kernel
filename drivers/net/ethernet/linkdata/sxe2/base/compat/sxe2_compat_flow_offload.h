/* SPDX-License-Identifier: GPL-2.0 */
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2_compat_flow_offload.h
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */
#ifndef __SXE2_COMPAT_FLOW_OFFLOAD_H__
#define __SXE2_COMPAT_FLOW_OFFLOAD_H__

#ifdef NEED_FLOW_MATCH
#include <net/pkt_cls.h>
#include <net/flow_dissector.h>

struct flow_match {
	struct flow_dissector	*dissector;
	void			*mask;
	void			*key;
};

struct flow_match_basic {
	struct flow_dissector_key_basic *key, *mask;
};

struct flow_match_control {
	struct flow_dissector_key_control *key, *mask;
};

struct flow_match_eth_addrs {
	struct flow_dissector_key_eth_addrs *key, *mask;
};

#ifndef HAVE_TC_FLOWER_VLAN_IN_TAGS
struct flow_match_vlan {
	struct flow_dissector_key_vlan *key, *mask;
};
#endif

struct flow_match_ipv4_addrs {
	struct flow_dissector_key_ipv4_addrs *key, *mask;
};

struct flow_match_ipv6_addrs {
	struct flow_dissector_key_ipv6_addrs *key, *mask;
};

#ifdef HAVE_FLOW_DISSECTOR_KEY_IP
struct flow_match_ip {
	struct flow_dissector_key_ip *key, *mask;
};
#endif

struct flow_match_ports {
	struct flow_dissector_key_ports *key, *mask;
};

#ifdef HAVE_TC_FLOWER_ENC
struct flow_match_enc_keyid {
	struct flow_dissector_key_keyid *key, *mask;
};
#endif

struct flow_rule {
	struct flow_match	match;
};

static inline struct flow_rule *
tc_cls_flower_offload_flow_rule(struct tc_cls_flower_offload *tc_flow_cmd)
{
	return (struct flow_rule *)&tc_flow_cmd->dissector;
}

static inline bool flow_rule_match_key(const struct flow_rule *rule,
				       enum flow_dissector_key_id key)
{
	return dissector_uses_key(rule->match.dissector, key);
}

#define FLOW_DISSECTOR_MATCH(_rule, _type, _out) do { \
	typeof(_rule) _local_rule = (_rule); \
	typeof(_type) _local_type = (_type); \
	typeof(_out) _local_out = (_out); \
	const struct flow_dissector *_d = (_local_rule)->match; \
	struct flow_match _m = (_local_rule)->mask; \
	(_local_out)->key = skb_flow_dissector_target(_d, _local_type, (_m)->key); \
	(_local_out)->mask = skb_flow_dissector_target(_d, _local_type, (_m)->mask); \
} while (0)

static inline void
flow_rule_match_basic(const struct flow_rule *rule,
		      struct flow_match_basic *out)
{
	FLOW_DISSECTOR_MATCH(rule, FLOW_DISSECTOR_KEY_BASIC, out);
}

static inline void
flow_rule_match_control(const struct flow_rule *rule,
			struct flow_match_control *out)
{
	FLOW_DISSECTOR_MATCH(rule, FLOW_DISSECTOR_KEY_CONTROL, out);
}

static inline void
flow_rule_match_eth_addrs(const struct flow_rule *rule,
			  struct flow_match_eth_addrs *out)
{
	FLOW_DISSECTOR_MATCH(rule, FLOW_DISSECTOR_KEY_ETH_ADDRS, out);
}

#ifndef HAVE_TC_FLOWER_VLAN_IN_TAGS
static inline void
flow_rule_match_vlan(const struct flow_rule *rule, struct flow_match_vlan *out)
{
	FLOW_DISSECTOR_MATCH(rule, FLOW_DISSECTOR_KEY_VLAN, out);
}
#endif

static inline void
flow_rule_match_ipv4_addrs(const struct flow_rule *rule,
			   struct flow_match_ipv4_addrs *out)
{
	FLOW_DISSECTOR_MATCH(rule, FLOW_DISSECTOR_KEY_IPV4_ADDRS, out);
}

static inline void
flow_rule_match_ipv6_addrs(const struct flow_rule *rule,
			   struct flow_match_ipv6_addrs *out)
{
	FLOW_DISSECTOR_MATCH(rule, FLOW_DISSECTOR_KEY_IPV6_ADDRS, out);
}

#ifdef HAVE_FLOW_DISSECTOR_KEY_IP
static inline void
flow_rule_match_ip(const struct flow_rule *rule, struct flow_match_ip *out)
{
	FLOW_DISSECTOR_MATCH(rule, FLOW_DISSECTOR_KEY_IP, out);
}
#endif

static inline void
flow_rule_match_ports(const struct flow_rule *rule,
		      struct flow_match_ports *out)
{
	FLOW_DISSECTOR_MATCH(rule, FLOW_DISSECTOR_KEY_PORTS, out);
}

#ifdef HAVE_TC_FLOWER_ENC
static inline void
flow_rule_match_enc_control(const struct flow_rule *rule,
			    struct flow_match_control *out)
{
	FLOW_DISSECTOR_MATCH(rule, FLOW_DISSECTOR_KEY_ENC_CONTROL, out);
}

static inline void
flow_rule_match_enc_ipv4_addrs(const struct flow_rule *rule,
			       struct flow_match_ipv4_addrs *out)
{
	FLOW_DISSECTOR_MATCH(rule, FLOW_DISSECTOR_KEY_ENC_IPV4_ADDRS, out);
}

static inline void
flow_rule_match_enc_ipv6_addrs(const struct flow_rule *rule,
			       struct flow_match_ipv6_addrs *out)
{
	FLOW_DISSECTOR_MATCH(rule, FLOW_DISSECTOR_KEY_ENC_IPV6_ADDRS, out);
}

#ifdef HAVE_FLOW_DISSECTOR_KEY_IP
#ifdef HAVE_FLOW_DISSECTOR_KEY_ENC_IP
static inline void
flow_rule_match_enc_ip(const struct flow_rule *rule, struct flow_match_ip *out)
{
	FLOW_DISSECTOR_MATCH(rule, FLOW_DISSECTOR_KEY_ENC_IP, out);
}
#endif
#endif

static inline void
flow_rule_match_enc_ports(const struct flow_rule *rule,
			  struct flow_match_ports *out)
{
	FLOW_DISSECTOR_MATCH(rule, FLOW_DISSECTOR_KEY_ENC_PORTS, out);
}

static inline void
flow_rule_match_enc_keyid(const struct flow_rule *rule,
			  struct flow_match_enc_keyid *out)
{
	FLOW_DISSECTOR_MATCH(rule, FLOW_DISSECTOR_KEY_ENC_KEYID, out);
}
#endif

#ifdef COMPILER_HAS_GENERIC_BUILTIN_OVERFLOW
static inline bool __must_check __must_check_overflow(bool overflow)
{
	return unlikely(overflow);
}

#define check_add_overflow(a, b, d)		\
	__must_check_overflow(__builtin_add_overflow(a, b, d))

#define check_sub_overflow(a, b, d)		\
	__must_check_overflow(__builtin_sub_overflow(a, b, d))

#define check_mul_overflow(a, b, d)		\
	__must_check_overflow(__builtin_mul_overflow(a, b, d))
#endif

#endif
#endif
