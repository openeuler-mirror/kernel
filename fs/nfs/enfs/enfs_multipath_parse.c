// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 */
#include <linux/types.h>
#include <linux/nfs.h>
#include <linux/nfs4.h>
#include <linux/nfs_fs.h>
#include <linux/nfs_fs_sb.h>
#include <linux/kern_levels.h>
#include <linux/sunrpc/addr.h>
#include "enfs_multipath_parse.h"
#include "enfs_log.h"
#include "enfs_config.h"

#define NFSDBG_FACILITY NFSDBG_CLIENT
#define REMOTE_IP 0
#define REMOTE_DNS 1

void nfs_multipath_parse_ip_ipv6_add(struct sockaddr_in6 *sin6, int add_num)
{
	int i;

	enfs_log_info("before %08x%08x%08x%08x  add_num: %d\n",
		      ntohl(sin6->sin6_addr.in6_u.u6_addr32[0]),
		      ntohl(sin6->sin6_addr.in6_u.u6_addr32[1]),
		      ntohl(sin6->sin6_addr.in6_u.u6_addr32[2]),
		      ntohl(sin6->sin6_addr.in6_u.u6_addr32[3]), add_num);
	for (i = 0; i < add_num; i++) {
		sin6->sin6_addr.in6_u.u6_addr32[3] =
			htonl(ntohl(sin6->sin6_addr.in6_u.u6_addr32[3]) + 1);
		if (sin6->sin6_addr.in6_u.u6_addr32[3] != 0)
			continue;
		sin6->sin6_addr.in6_u.u6_addr32[2] =
			htonl(ntohl(sin6->sin6_addr.in6_u.u6_addr32[2]) + 1);
		if (sin6->sin6_addr.in6_u.u6_addr32[2] != 0)
			continue;
		sin6->sin6_addr.in6_u.u6_addr32[1] =
			htonl(ntohl(sin6->sin6_addr.in6_u.u6_addr32[1]) + 1);
		if (sin6->sin6_addr.in6_u.u6_addr32[1] != 0)
			continue;
		sin6->sin6_addr.in6_u.u6_addr32[0] =
			htonl(ntohl(sin6->sin6_addr.in6_u.u6_addr32[0]) + 1);
		if (sin6->sin6_addr.in6_u.u6_addr32[0] != 0)
			continue;
	}
}

static int enfs_parse_ip_range(struct net *net_ns, const char *cursor,
			       struct nfs_ip_list *ip_list,
			       enum nfsmultipathoptions type)
{
	struct sockaddr_storage addr;
	struct sockaddr_storage tmp_addr;
	int i;
	size_t len;
	int add_num = 1;
	bool duplicate_flag = false;
	bool is_complete = false;
	struct sockaddr_in *sin4;
	struct sockaddr_in6 *sin6;

	enfs_log_info("parsing nfs mount option '%s' type: %d\n", cursor, type);
	len = rpc_pton(net_ns, cursor, strlen(cursor), (struct sockaddr *)&addr,
		       sizeof(addr));
	if (!len)
		return -EINVAL;

	if (addr.ss_family != ip_list->address[ip_list->count - 1].ss_family) {
		enfs_log_info("parsing nfs mount option type: %d fail. both have ipv4 and ipv6 address\n",
			      type);
		return -EINVAL;
	}

	if (rpc_cmp_addr((const struct sockaddr *)&ip_list
				 ->address[ip_list->count - 1],
			 (const struct sockaddr *)&addr)) {
		enfs_log_info("range ip is same ip.\n");
		return 0;
	}

	while (true) {
		tmp_addr = ip_list->address[ip_list->count - 1];

		switch (addr.ss_family) {
		case AF_INET: {
			sin4 = (struct sockaddr_in *)&tmp_addr;
			sin4->sin_addr.s_addr =
				htonl(ntohl(sin4->sin_addr.s_addr) + add_num);
			enfs_log_info("parsing nfs mount option ip %08x type: %d ipcont %d\n",
				      ntohl(sin4->sin_addr.s_addr), type, ip_list->count);
			break;
		}
		case AF_INET6:
			sin6 = (struct sockaddr_in6 *)&tmp_addr;
			nfs_multipath_parse_ip_ipv6_add(sin6, add_num);
			enfs_log_info("parsing nfs mount option ip %08x%08x%08x%08x type: %d ipcont %d\n",
				      ntohl(sin6->sin6_addr.in6_u.u6_addr32[0]),
				      ntohl(sin6->sin6_addr.in6_u.u6_addr32[1]),
				      ntohl(sin6->sin6_addr.in6_u.u6_addr32[2]),
				      ntohl(sin6->sin6_addr.in6_u.u6_addr32[3]),
				      type, ip_list->count);
			break;
		default:
			return -EOPNOTSUPP;
		}

		if (rpc_cmp_addr((const struct sockaddr *)&tmp_addr,
				 (const struct sockaddr *)&addr)) {
			is_complete = true;
		}

		for (i = 0; i < ip_list->count; i++) {
			duplicate_flag = false;
			if (rpc_cmp_addr((const struct sockaddr *)&ip_list
						 ->address[i],
					 (const struct sockaddr *)&tmp_addr)) {
				enfs_log_info("parsing nfs mount option type: %d index %d,same as before %d, add_num %d\n",
					      type, ip_list->count, i, add_num);
				add_num++;
				duplicate_flag = true;
				break;
			}
		}

		if (duplicate_flag == false) {
			enfs_log_info("this ip not duplicate;");
			add_num = 1;

			if ((type == LOCALADDR &&
			     ip_list->count >= MAX_SUPPORTED_LOCAL_IP_COUNT) ||
			    (type == REMOTEADDR &&
			     ip_list->count >=
				     enfs_get_config_link_count_per_mount())) {
				enfs_log_info("iplist for type %d reached %d, more than supported limit %d\n",
					      type, ip_list->count,
					      type == LOCALADDR ?
						      MAX_SUPPORTED_LOCAL_IP_COUNT :
						      enfs_get_config_link_count_per_mount());
				ip_list->count = 0;
				return -ENOSPC;
			}
			ip_list->address[ip_list->count] = tmp_addr;
			ip_list->addrlen[ip_list->count] =
				ip_list->addrlen[ip_list->count - 1];
			ip_list->count += 1;
		}
		if (is_complete == true)
			break;
	}
	return 0;
}

int enfs_parse_ip_single(struct nfs_ip_list *ip_list, struct net *net_ns,
			 char *cursor, enum nfsmultipathoptions type)
{
	int i = 0;
	struct sockaddr_storage addr;
	struct sockaddr_storage swap;
	int len;

	len = rpc_pton(net_ns, cursor, strlen(cursor), (struct sockaddr *)&addr,
		       sizeof(addr));
	if (!len)
		return -EINVAL;

	// check same as exist ip
	for (i = 0; i < ip_list->count; i++) {
		if (rpc_cmp_addr((const struct sockaddr *)&ip_list->address[i],
				 (const struct sockaddr *)&addr)) {
			enfs_log_info("parsing nfs mount option '%s' type: %d index %d same as before index %d\n",
				      cursor, type, ip_list->count, i);

			swap = ip_list->address[i];
			ip_list->address[i] =
				ip_list->address[ip_list->count - 1];
			ip_list->address[ip_list->count - 1] = swap;
			return 0;
		}
	}

	if ((type == LOCALADDR &&
	     ip_list->count >= MAX_SUPPORTED_LOCAL_IP_COUNT) ||
	    (type == REMOTEADDR &&
	     ip_list->count >= enfs_get_config_link_count_per_mount())) {
		enfs_log_info("iplist for type %d reached %d, more than supported limit %d\n",
			      type, ip_list->count,
			      type == LOCALADDR ?
				      MAX_SUPPORTED_LOCAL_IP_COUNT :
				      enfs_get_config_link_count_per_mount());
		ip_list->count = 0;
		return -ENOSPC;
	}
	ip_list->address[ip_list->count] = addr;
	ip_list->addrlen[ip_list->count] = len;
	ip_list->count++;

	return 0;
}

char *nfs_multipath_parse_ip_list_get_cursor(char **buf_to_parse, bool *single)
{
	char *cursor = NULL;
	const char *single_sep = strchr(*buf_to_parse, '~');
	const char *range_sep = strchr(*buf_to_parse, '-');

	*single = true;
	if (range_sep) {
		if (range_sep > single_sep) { // A-B or A~B-C
			if (single_sep == NULL) { // A-B
				cursor = strsep(buf_to_parse, "-");
				if (cursor)
					*single = false;
			} else { // A~B-C
				cursor = strsep(buf_to_parse, "~");
			}
		} else { // A-B~C
			cursor = strsep(buf_to_parse, "-");
			if (cursor)
				*single = false;
		}
	} else { // A~B~C
		cursor = strsep(buf_to_parse, "~");
	}
	return cursor;
}

bool enfs_valid_ip(char *str, struct net *net)
{
	int len;
	struct sockaddr_storage addr;

	len = rpc_pton(net, str, strlen(str), (struct sockaddr *)&addr,
		       sizeof(addr));
	if (!len)
		return false;
	return true;
}

int nfs_multipath_parse_ip_list(char *buffer, struct net *net_ns,
				struct multipath_mount_options *options,
				enum nfsmultipathoptions type)
{
	char *ptr = NULL;
	bool prev_range = false;
	int ret = 0;
	char *cursor = NULL;
	bool single = true;
	struct nfs_ip_list *ip_list_tmp = NULL;

	if (type == LOCALADDR)
		ip_list_tmp = options->local_ip_list;
	else
		ip_list_tmp = options->remote_ip_list;
	ip_list_tmp->count = 0;

	enfs_log_info("NFS:   parsing nfs mount option '%s' type: %d\n", buffer, type);
	ptr = buffer;
	while (ptr != NULL) {
		cursor = nfs_multipath_parse_ip_list_get_cursor(&ptr, &single);
		if (!cursor)
			break;

		if (single == false && prev_range == true) {
			enfs_log_info(
			"parsing nfs mount option type: %d fail. Multiple Range.\n", type);
			ret = -EINVAL;
			goto out;
		}

		if (prev_range == false) {
			ret = enfs_parse_ip_single(ip_list_tmp, net_ns, cursor, type);
			if (ret)
				goto out;
			if (single == false)
				prev_range = true;
		} else {
			ret = enfs_parse_ip_range(net_ns, cursor, ip_list_tmp, type);
			if (ret != 0)
				goto out;
			prev_range = false;
		}
	}

out:
	if (ret)
		memset(ip_list_tmp, 0, sizeof(struct nfs_ip_list));

	return ret;
}

static bool dns_valid_char(char c)
{
	return isalnum(c) || c == '.' || c == '_' || c == '-';
}

static bool dns_valid_string(const char *str, int len)
{
	int i;

	for (i = 0; i < len; i++) {
		if (!dns_valid_char(str[i]))
			return false;
	}

	return true;
}

static bool enfs_valid_dns(const char *s)
{
	char *copy;
	char *tmp;
	char *token;
	int sublen;
	int len = strlen(s);

	// Total length of the domain name 1 - 255
	if (len < 1 || len > 255)
		return false;

	copy = kstrdup(s, GFP_KERNEL);
	if (!copy) {
		enfs_log_error("not enough memory.\n");
		return false;
	}
	tmp = copy;

	// Use (.) to separate character strings a.
	while ((token = strsep(&tmp, ".")) != NULL) {
		sublen = strlen(token);

		// The substring contains a maximum of 63 characters.
		if (sublen > 63 || sublen < 1) {
			kfree(copy);
			return false;
		}
		// The substring starts and ends with a digit or letter
		if (!isalnum(token[0]) || !isalnum(token[sublen - 1])) {
			kfree(copy);
			return false;
		}
		// The substring consists of only letters, numbers, (.), (_), or (-).
		if (!dns_valid_string(token, sublen)) {
			kfree(copy);
			return false;
		}
	}

	kfree(copy);
	return true;
}

bool isInvalidDns(char *cursor, struct net *net_ns)
{
	char *ptr = strchr(cursor, '-');

	if (ptr) {
		*ptr = '\0';
		// Check whether the split result is a valid IP address.
		if (enfs_valid_ip(cursor, net_ns))
			return true;
		*ptr = '-';
	}

	if (enfs_valid_ip(cursor, net_ns))
		return true;

	if (!enfs_valid_dns(cursor)) {
		enfs_log_error("invalid dns %s\n", cursor);
		return true;
	}

	if (strlen(cursor) > MAX_DNS_NAME_LEN)
		return true;

	return false;
}

int nfs_multipath_parse_dns_list(char *buffer, struct net *net_ns,
				 struct multipath_mount_options *options)
{
	struct enfs_route_dns_info *dns = NULL;
	char *cursor = NULL;
	char *ptr;

	// freed in nfs_free_parsed_mount_data
	dns = kmalloc(sizeof(struct enfs_route_dns_info), GFP_KERNEL);
	if (!dns)
		return -ENOMEM;

	dns->dnsNameCount = 0;
	ptr = buffer;
	while (ptr) {
		if (dns->dnsNameCount >= MAX_DNS_SUPPORTED) {
			enfs_log_error(
				"more than supported limit,support max dns:%d.\n",
				MAX_DNS_SUPPORTED);
			goto out;
		}
		cursor = strsep(&ptr, "~");
		if (!cursor)
			break;
		// Config of mixed IP addresses and domain names is not supported.
		if (isInvalidDns(cursor, net_ns))
			goto out;

		strscpy(dns->routeRemoteDnsList[dns->dnsNameCount].dnsname,
		       cursor, MAX_DNS_NAME_LEN);
		dns->dnsNameCount++;
	}

	if (dns->dnsNameCount == 0) {
		kfree(dns);
		return -EINVAL;
	}
	kfree(options->pRemoteDnsInfo);
	options->pRemoteDnsInfo = dns;
	return 0;
out:
	kfree(dns);
	return -ENOSPC;
}

int parse_remote_type(char *str, struct net *net)
{
	int ret;
	char *ptr = strchr(str, '-');

	if (ptr) {
		*ptr = '\0';
		ret = enfs_valid_ip(str, net) ? REMOTE_IP : REMOTE_DNS;
		*ptr = '-';
	} else {
		ret = enfs_valid_ip(str, net) ? REMOTE_IP : REMOTE_DNS;
	}

	if (ret == REMOTE_IP)
		return REMOTE_IP;

	ptr = strchr(str, '~');
	if (ptr) {
		*ptr = '\0';
		ret = enfs_valid_ip(str, net) ? REMOTE_IP : REMOTE_DNS;
		*ptr = '~';
	} else {
		ret = enfs_valid_ip(str, net) ? REMOTE_IP : REMOTE_DNS;
	}

	return ret;
}

static int enfs_parse_remoteaddrs(char *str, struct net *net,
				  struct multipath_mount_options *options)
{
	if (parse_remote_type(str, net) == REMOTE_IP) {
		options->pRemoteDnsInfo->dnsNameCount = 0;
		return nfs_multipath_parse_ip_list(str, net, options,
						   REMOTEADDR);
	}

	return nfs_multipath_parse_dns_list(str, net, options);
}

int nfs_multipath_parse_options_check_ipv4_valid(struct sockaddr_in *addr)
{
	if (addr->sin_addr.s_addr == 0 || addr->sin_addr.s_addr == 0xffffffff)
		return -EINVAL;
	return 0;
}

int nfs_multipath_parse_options_check_ipv6_valid(struct sockaddr_in6 *addr)
{
	if (addr->sin6_addr.in6_u.u6_addr32[0] == 0 &&
	    addr->sin6_addr.in6_u.u6_addr32[1] == 0 &&
	    addr->sin6_addr.in6_u.u6_addr32[2] == 0 &&
	    addr->sin6_addr.in6_u.u6_addr32[3] == 0)
		return -EINVAL;

	if (addr->sin6_addr.in6_u.u6_addr32[0] == 0xffffffff &&
	    addr->sin6_addr.in6_u.u6_addr32[1] == 0xffffffff &&
	    addr->sin6_addr.in6_u.u6_addr32[2] == 0xffffffff &&
	    addr->sin6_addr.in6_u.u6_addr32[3] == 0xffffffff)
		return -EINVAL;
	return 0;
}

int nfs_multipath_parse_options_check_ip_valid(struct sockaddr_storage *address)
{
	int rc = 0;

	if (address->ss_family == AF_INET) {
		rc = nfs_multipath_parse_options_check_ipv4_valid(
			(struct sockaddr_in *)address);
	} else if (address->ss_family == AF_INET6) {
		rc = nfs_multipath_parse_options_check_ipv6_valid(
			(struct sockaddr_in6 *)address);
	} else {
		rc = -EINVAL;
	}
	return rc;
}

int nfs_multipath_parse_options_check_valid(
	struct multipath_mount_options *options)
{
	int rc;
	int i;

	if (options == NULL)
		return 0;

	for (i = 0; i < options->local_ip_list->count; i++) {
		rc = nfs_multipath_parse_options_check_ip_valid(
			&options->local_ip_list->address[i]);
		if (rc != 0)
			return rc;
	}

	for (i = 0; i < options->remote_ip_list->count; i++) {
		rc = nfs_multipath_parse_options_check_ip_valid(
			&options->remote_ip_list->address[i]);
		if (rc != 0)
			return rc;
	}

	return 0;
}

int nfs_multipath_parse_options_check_duplicate(
	struct multipath_mount_options *options)
{
	int i, j;

	if (options == NULL || options->local_ip_list->count == 0 ||
	    options->remote_ip_list->count == 0) {
		return 0;
	}

	for (i = 0; i < options->local_ip_list->count; i++) {
		for (j = 0; j < options->remote_ip_list->count; j++) {
			if (rpc_cmp_addr((const struct sockaddr *)&options
						 ->local_ip_list->address[i],
					 (const struct sockaddr *)&options
						 ->remote_ip_list->address[j])) {
				enfs_log_info("local_addr index %d as same as remote_addr index %d\n.",
					      i, j);
				return -EOPNOTSUPP;
			}
		}
	}
	return 0;
}

int nfs_multipath_parse_options_check(struct multipath_mount_options *options)
{
	int rc = 0;

	rc = nfs_multipath_parse_options_check_valid(options);
	if (rc != 0) {
		enfs_log_error("has invalid ip.\n");
		return rc;
	}

	rc = nfs_multipath_parse_options_check_duplicate(options);
	if (rc != 0)
		return rc;
	return rc;
}

int nfs_multipath_alloc_options(void **enfs_option)
{
	struct multipath_mount_options *options = NULL;

	options = kzalloc(sizeof(struct multipath_mount_options), GFP_KERNEL);
	if (options == NULL)
		return -ENOMEM;

	options->local_ip_list =
		kzalloc(sizeof(struct nfs_ip_list), GFP_KERNEL);
	if (options->local_ip_list == NULL) {
		kfree(options);
		return -ENOMEM;
	}

	options->remote_ip_list =
		kzalloc(sizeof(struct nfs_ip_list), GFP_KERNEL);
	if (options->remote_ip_list == NULL) {
		kfree(options->local_ip_list);
		kfree(options);
		return -ENOMEM;
	}

	options->pRemoteDnsInfo =
		kzalloc(sizeof(struct enfs_route_dns_info), GFP_KERNEL);
	if (options->pRemoteDnsInfo == NULL) {
		kfree(options->remote_ip_list);
		kfree(options->local_ip_list);
		kfree(options);
		return -ENOMEM;
	}

	*enfs_option = options;
	return 0;
}

int nfs_multipath_parse_options(enum nfsmultipathoptions type, char *str,
				void **enfs_option, struct net *net_ns)
{
	int rc;
	struct multipath_mount_options *options = NULL;
	int link_count = enfs_link_count_num();
	int mount_count = enfs_mount_count();

	/* Native links and multipath links */
	if (link_count >= enfs_get_config_link_count_total() - 1 ||
	    mount_count >= ENFS_MAX_MOUNT_COUNT) {
		enfs_log_error(
			"link count:%d fs count:%d count2:%d exceeds the limit,can not create new multipath nfs.\n",
			link_count, mount_count,
			enfs_get_config_link_count_total());
		return -EINVAL;
	}
	if ((str == NULL) || (enfs_option == NULL) || (net_ns == NULL))
		return -EINVAL;

	if (*enfs_option == NULL) {
		rc = nfs_multipath_alloc_options(enfs_option);
		if (rc != 0) {
			enfs_log_error("alloc enfs_options failed! errno:%d\n",
				       rc);
			return rc;
		}
	}
	options = *enfs_option;

	if (type == LOCALADDR)
		rc = nfs_multipath_parse_ip_list(str, net_ns, options, type);
	else if (type == REMOTEADDR)
		/* alloc and release need to modify */
		rc = enfs_parse_remoteaddrs(str, net_ns, options);
	else
		rc = -EOPNOTSUPP;

	// if have some ip return err
	if (rc == 0)
		rc = nfs_multipath_parse_options_check_duplicate(options);

	if (rc == 0)
		rc = nfs_multipath_parse_options_check(options);

	return rc;
}

void nfs_multipath_free_options(void **enfs_option)
{
	struct multipath_mount_options *options;

	if (enfs_option == NULL || *enfs_option == NULL)
		return;

	options = (struct multipath_mount_options *)*enfs_option;

	if (options->remote_ip_list != NULL) {
		kfree(options->remote_ip_list);
		options->remote_ip_list = NULL;
	}

	if (options->local_ip_list != NULL) {
		kfree(options->local_ip_list);
		options->local_ip_list = NULL;
	}

	if (options->pRemoteDnsInfo != NULL) {
		kfree(options->pRemoteDnsInfo);
		options->pRemoteDnsInfo = NULL;
	}

	kfree(options);
	*enfs_option = NULL;
}

static bool is_valid_ip_address(const char *ip_str)
{
	struct in_addr addr4;
	struct in6_addr addr6;

	if (in4_pton(ip_str, -1, (u8 *)&addr4, '\0', NULL) == 1)
		return true;

	if (in6_pton(ip_str, -1, (u8 *)&addr6, '\0', NULL) == 1)
		return true;

	return false;
}

void enfs_set_mount_data(void **enfs_option, const char *hostname)
{
	int error;
	struct multipath_mount_options *opt;

	if (!enfs_get_config_dns_auto_multipath_resolution() ||
	    !enfs_valid_dns(hostname) || is_valid_ip_address(hostname) ||
	    *enfs_option) {
		return;
	}

	error = nfs_multipath_alloc_options(enfs_option);
	if (error) {
		enfs_log_error("alloca option err:%d\n", error);
		return;
	}

	opt = *enfs_option;
	opt->pRemoteDnsInfo->dnsNameCount = 1;
	strscpy(opt->pRemoteDnsInfo->routeRemoteDnsList[0].dnsname, hostname, MAX_DNS_NAME_LEN);
}
