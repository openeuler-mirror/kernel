// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2025. All rights reserved.
 *
 * Description: uburma cmd tlv parse implement
 * Author: Wang Hang
 * Create: 2024-08-27
 * Note:
 * History: 2024-08-27: Create file
 */

#include "uburma_log.h"
#include "uburma_cmd_tlv.h"

#define UBURMA_CMD_TLV_MAX_LEN \
	(sizeof(struct uburma_cmd_attr) * UBURMA_CMD_OUT_TYPE_INIT)

#define UBURMA_EVENT_SPEC_ATTR_SIZE 16
#define UBURMA_CMD_EVENT_TLV_MAX_LEN \
	(sizeof(struct uburma_cmd_attr) * UBURMA_EVENT_SPEC_ATTR_SIZE)

struct uburma_tlv_handler {
	void (*fill_spec_in)(void *arg, struct uburma_cmd_spec *s);
	size_t spec_in_len;
	void (*fill_spec_out)(void *arg, struct uburma_cmd_spec *s);
	size_t spec_out_len;
};

static inline void fill_spec(struct uburma_cmd_spec *spec,
			     uint16_t type, uint16_t field_size,
			     uint16_t el_num, uint16_t el_size,
			     uintptr_t data)
{
	*spec = (struct uburma_cmd_spec) {
		.type = type,
		.flag.bs = { .mandatory = 1 },
		.field_size = field_size,
		.attr_data.bs = { .el_num = el_num,
				  .el_size = el_size },
		.data = data,
	};
}

/**
 * Fill spec with a field, which is a value or an array taken as a whole.
 * @param v Full path of field, e.g. `arg->out.attr.dev_cap.feature`
 */
#define SPEC(spec, type, v) \
	fill_spec(spec, type, sizeof(v), 1, 0, (uintptr_t)(&(v)))

/**
 * Fill spec with a field, which belongs to an array of structs.
 * @param v1 Full path of struct array, e.g. `arg->out.attr.port_attr`
 * @param v2 Path relative to struct in array, e.g. `active_speed`
 */
#define SPEC_ARRAY(spec, type, v1, v2)                          \
	fill_spec(spec, type, sizeof((v1)->v2), ARRAY_SIZE(v1), \
		  sizeof((v1)[0]), (uintptr_t)(&((v1)->v2)))

static void
uburma_create_ctx_fill_spec_in(void *arg_addr,
			       struct uburma_cmd_spec *spec)
{
	struct uburma_cmd_create_ctx *arg = arg_addr;
	struct uburma_cmd_spec *s = spec;

	SPEC(s++, CREATE_CTX_IN_EID, arg->in.eid);
	SPEC(s++, CREATE_CTX_IN_EID_INDEX, arg->in.eid_index);
	SPEC(s++, CREATE_CTX_IN_UDATA, arg->udata);
}

static void
uburma_create_ctx_fill_spec_out(void *arg_addr,
				struct uburma_cmd_spec *spec)
{
	struct uburma_cmd_create_ctx *arg = arg_addr;
	struct uburma_cmd_spec *s = spec;

	SPEC(s++, CREATE_CTX_OUT_ASYNC_FD, arg->out.async_fd);
	SPEC(s++, CREATE_CTX_OUT_UDATA, arg->udata);
}

static void
uburma_alloc_token_id_fill_spec_in(void *arg_addr,
				   struct uburma_cmd_spec *spec)
{
	struct uburma_cmd_alloc_token_id *arg = arg_addr;
	struct uburma_cmd_spec *s = spec;

	SPEC(s++, ALLOC_TOKEN_ID_IN_FLAG, arg->flag);
	SPEC(s++, ALLOC_TOKEN_ID_IN_UDATA, arg->udata);
}

static void
uburma_alloc_token_id_fill_spec_out(void *arg_addr,
				    struct uburma_cmd_spec *spec)
{
	struct uburma_cmd_alloc_token_id *arg = arg_addr;
	struct uburma_cmd_spec *s = spec;

	SPEC(s++, ALLOC_TOKEN_ID_OUT_TOKEN_ID, arg->out.token_id);
	SPEC(s++, ALLOC_TOKEN_ID_OUT_HANDLE, arg->out.handle);
	SPEC(s++, ALLOC_TOKEN_ID_OUT_UDATA, arg->udata);
}

static void
uburma_free_token_id_fill_spec_in(void *arg_addr,
				  struct uburma_cmd_spec *spec)
{
	struct uburma_cmd_free_token_id *arg = arg_addr;
	struct uburma_cmd_spec *s = spec;

	SPEC(s++, FREE_TOKEN_ID_IN_HANDLE, arg->in.handle);
	SPEC(s++, FREE_TOKEN_ID_IN_TOKEN_ID, arg->in.token_id);
}

static void
uburma_register_seg_fill_spec_in(void *arg_addr,
				 struct uburma_cmd_spec *spec)
{
	struct uburma_cmd_register_seg *arg = arg_addr;
	struct uburma_cmd_spec *s = spec;

	SPEC(s++, REGISTER_SEG_IN_VA, arg->in.va);
	SPEC(s++, REGISTER_SEG_IN_LEN, arg->in.len);
	SPEC(s++, REGISTER_SEG_IN_TOKEN_ID, arg->in.token_id);
	SPEC(s++, REGISTER_SEG_IN_TOKEN_ID_HANDLE,
	     arg->in.token_id_handle);
	SPEC(s++, REGISTER_SEG_IN_TOKEN, arg->in.token);
	SPEC(s++, REGISTER_SEG_IN_FLAG, arg->in.flag);
	SPEC(s++, REGISTER_SEG_IN_UDATA, arg->udata);
}

static void
uburma_register_seg_fill_spec_out(void *arg_addr,
				  struct uburma_cmd_spec *spec)
{
	struct uburma_cmd_register_seg *arg = arg_addr;
	struct uburma_cmd_spec *s = spec;

	SPEC(s++, REGISTER_SEG_OUT_TOKEN_ID, arg->out.token_id);
	SPEC(s++, REGISTER_SEG_OUT_HANDLE, arg->out.handle);
	SPEC(s++, REGISTER_SEG_OUT_UDATA, arg->udata);
}

static void
uburma_unregister_seg_fill_spec_in(void *arg_addr,
				   struct uburma_cmd_spec *spec)
{
	struct uburma_cmd_unregister_seg *arg = arg_addr;
	struct uburma_cmd_spec *s = spec;

	SPEC(s++, UNREGISTER_SEG_IN_HANDLE, arg->in.handle);
}

static void
uburma_import_seg_fill_spec_in(void *arg_addr,
			       struct uburma_cmd_spec *spec)
{
	struct uburma_cmd_import_seg *arg = arg_addr;
	struct uburma_cmd_spec *s = spec;

	SPEC(s++, IMPORT_SEG_IN_EID, arg->in.eid);
	SPEC(s++, IMPORT_SEG_IN_VA, arg->in.va);
	SPEC(s++, IMPORT_SEG_IN_LEN, arg->in.len);
	SPEC(s++, IMPORT_SEG_IN_FLAG, arg->in.flag);
	SPEC(s++, IMPORT_SEG_IN_TOKEN, arg->in.token);
	SPEC(s++, IMPORT_SEG_IN_TOKEN_ID, arg->in.token_id);
	SPEC(s++, IMPORT_SEG_IN_MVA, arg->in.mva);
	SPEC(s++, IMPORT_SEG_IN_UDATA, arg->udata);
}

static void
uburma_import_seg_fill_spec_out(void *arg_addr,
				struct uburma_cmd_spec *spec)
{
	struct uburma_cmd_import_seg *arg = arg_addr;
	struct uburma_cmd_spec *s = spec;

	SPEC(s++, IMPORT_SEG_OUT_HANDLE, arg->out.handle);
	SPEC(s++, IMPORT_SEG_OUT_UDATA, arg->udata);
}

static void
uburma_unimport_seg_fill_spec_in(void *arg_addr,
				 struct uburma_cmd_spec *spec)
{
	struct uburma_cmd_unimport_seg *arg = arg_addr;
	struct uburma_cmd_spec *s = spec;

	SPEC(s++, UNIMPORT_SEG_IN_HANDLE, arg->in.handle);
}

static void
uburma_create_jfs_fill_spec_in(void *arg_addr,
			       struct uburma_cmd_spec *spec)
{
	struct uburma_cmd_create_jfs *arg = arg_addr;
	struct uburma_cmd_spec *s = spec;

	SPEC(s++, CREATE_JFS_IN_DEPTH, arg->in.depth);
	SPEC(s++, CREATE_JFS_IN_FLAG, arg->in.flag);
	SPEC(s++, CREATE_JFS_IN_TRANS_MODE, arg->in.trans_mode);
	SPEC(s++, CREATE_JFS_IN_PRIORITY, arg->in.priority);
	SPEC(s++, CREATE_JFS_IN_MAX_SGE, arg->in.max_sge);
	SPEC(s++, CREATE_JFS_IN_MAX_RSGE, arg->in.max_rsge);
	SPEC(s++, CREATE_JFS_IN_MAX_INLINE_DATA,
	     arg->in.max_inline_data);
	SPEC(s++, CREATE_JFS_IN_RETRY_CNT, arg->in.retry_cnt);
	SPEC(s++, CREATE_JFS_IN_RNR_RETRY, arg->in.rnr_retry);
	SPEC(s++, CREATE_JFS_IN_ERR_TIMEOUT, arg->in.err_timeout);
	SPEC(s++, CREATE_JFS_IN_JFC_ID, arg->in.jfc_id);
	SPEC(s++, CREATE_JFS_IN_JFC_HANDLE, arg->in.jfc_handle);
	SPEC(s++, CREATE_JFS_IN_URMA_JFS, arg->in.urma_jfs);
	SPEC(s++, CREATE_JFS_IN_UDATA, arg->udata);
}

static void
uburma_create_jfs_fill_spec_out(void *arg_addr,
				struct uburma_cmd_spec *spec)
{
	struct uburma_cmd_create_jfs *arg = arg_addr;
	struct uburma_cmd_spec *s = spec;

	SPEC(s++, CREATE_JFS_OUT_ID, arg->out.id);
	SPEC(s++, CREATE_JFS_OUT_DEPTH, arg->out.depth);
	SPEC(s++, CREATE_JFS_OUT_MAX_SGE, arg->out.max_sge);
	SPEC(s++, CREATE_JFS_OUT_MAX_RSGE, arg->out.max_rsge);
	SPEC(s++, CREATE_JFS_OUT_MAX_INLINE_DATA,
	     arg->out.max_inline_data);
	SPEC(s++, CREATE_JFS_OUT_HANDLE, arg->out.handle);
	SPEC(s++, CREATE_JFS_OUT_UDATA, arg->udata);
}

static void
uburma_modify_jfs_fill_spec_in(void *arg_addr,
			       struct uburma_cmd_spec *spec)
{
	struct uburma_cmd_modify_jfs *arg = arg_addr;
	struct uburma_cmd_spec *s = spec;

	SPEC(s++, MODIFY_JFS_IN_HANDLE, arg->in.handle);
	SPEC(s++, MODIFY_JFS_IN_MASK, arg->in.mask);
	SPEC(s++, MODIFY_JFS_IN_STATE, arg->in.state);
	SPEC(s++, MODIFY_JFS_IN_UDATA, arg->udata);
}

static void
uburma_modify_jfs_fill_spec_out(void *arg_addr,
				struct uburma_cmd_spec *spec)
{
	struct uburma_cmd_modify_jfs *arg = arg_addr;
	struct uburma_cmd_spec *s = spec;

	SPEC(s++, MODIFY_JFS_OUT_UDATA, arg->udata);
}

static void
uburma_query_jfs_fill_spec_in(void *arg_addr,
			      struct uburma_cmd_spec *spec)
{
	struct uburma_cmd_query_jfs *arg = arg_addr;
	struct uburma_cmd_spec *s = spec;

	SPEC(s++, QUERY_JFS_IN_HANDLE, arg->in.handle);
}

static void
uburma_query_jfs_fill_spec_out(void *arg_addr,
			       struct uburma_cmd_spec *spec)
{
	struct uburma_cmd_query_jfs *arg = arg_addr;
	struct uburma_cmd_spec *s = spec;

	SPEC(s++, QUERY_JFS_OUT_DEPTH, arg->out.depth);
	SPEC(s++, QUERY_JFS_OUT_FLAG, arg->out.flag);
	SPEC(s++, QUERY_JFS_OUT_TRANS_MODE, arg->out.trans_mode);
	SPEC(s++, QUERY_JFS_OUT_PRIORITY, arg->out.priority);
	SPEC(s++, QUERY_JFS_OUT_MAX_SGE, arg->out.max_sge);
	SPEC(s++, QUERY_JFS_OUT_MAX_RSGE, arg->out.max_rsge);
	SPEC(s++, QUERY_JFS_OUT_MAX_INLINE_DATA,
	     arg->out.max_inline_data);
	SPEC(s++, QUERY_JFS_OUT_RETRY_CNT, arg->out.retry_cnt);
	SPEC(s++, QUERY_JFS_OUT_RNR_RETRY, arg->out.rnr_retry);
	SPEC(s++, QUERY_JFS_OUT_ERR_TIMEOUT, arg->out.err_timeout);
	SPEC(s++, QUERY_JFS_OUT_STATE, arg->out.state);
}

static void
uburma_delete_jfs_fill_spec_in(void *arg_addr,
			       struct uburma_cmd_spec *spec)
{
	struct uburma_cmd_delete_jfs *arg = arg_addr;
	struct uburma_cmd_spec *s = spec;

	SPEC(s++, DELETE_JFS_IN_HANDLE, arg->in.handle);
}

static void
uburma_delete_jfs_fill_spec_out(void *arg_addr,
				struct uburma_cmd_spec *spec)
{
	struct uburma_cmd_delete_jfs *arg = arg_addr;
	struct uburma_cmd_spec *s = spec;

	SPEC(s++, DELETE_JFS_OUT_ASYNC_EVENTS_REPORTED,
	     arg->out.async_events_reported);
}

static void
uburma_delete_jfs_batch_fill_spec_in(void *arg_addr,
				     struct uburma_cmd_spec *spec)
{
	struct uburma_cmd_delete_jfs_batch *arg = arg_addr;
	struct uburma_cmd_spec *s = spec;

	SPEC(s++, DELETE_JFS_BATCH_IN_JFS_COUNT, arg->in.jfs_num);
	SPEC(s++, DELETE_JFS_BATCH_IN_JFS_PTR, arg->in.jfs_ptr);
}

static void
uburma_delete_jfs_batch_fill_spec_out(void *arg_addr,
				      struct uburma_cmd_spec *spec)
{
	struct uburma_cmd_delete_jfs_batch *arg = arg_addr;
	struct uburma_cmd_spec *s = spec;

	SPEC(s++, DELETE_JFS_BATCH_OUT_ASYNC_EVENTS_REPORTED,
	     arg->out.async_events_reported);
	SPEC(s++, DELETE_JFS_BATCH_OUT_BAD_JFS_INDEX,
	     arg->out.bad_jfs_index);
}

static void uburma_alloc_jfs_fill_spec_in(void *arg_addr, struct uburma_cmd_spec *spec)
{
	struct uburma_cmd_alloc_jfs *arg = arg_addr;
	struct uburma_cmd_spec *s = spec;

	SPEC(s++, ALLOC_JFS_IN_DEPTH, arg->in.depth);
	SPEC(s++, ALLOC_JFS_IN_FLAG, arg->in.flag);
	SPEC(s++, ALLOC_JFS_IN_TRANS_MODE, arg->in.trans_mode);
	SPEC(s++, ALLOC_JFS_IN_PRIORITY, arg->in.priority);
	SPEC(s++, ALLOC_JFS_IN_MAX_SGE, arg->in.max_sge);
	SPEC(s++, ALLOC_JFS_IN_MAX_RSGE, arg->in.max_rsge);
	SPEC(s++, ALLOC_JFS_IN_MAX_INLINE_DATA, arg->in.max_inline_data);
	SPEC(s++, ALLOC_JFS_IN_RNR_RETRY, arg->in.rnr_retry);
	SPEC(s++, ALLOC_JFS_IN_ERR_TIMEOUT, arg->in.err_timeout);
	SPEC(s++, ALLOC_JFS_IN_JFC_ID, arg->in.jfc_id);
	SPEC(s++, ALLOC_JFS_IN_JFC_HANDLE, arg->in.jfc_handle);
	SPEC(s++, ALLOC_JFS_IN_URMA_JFS, arg->in.urma_jfs);
	SPEC(s++, ALLOC_JFS_IN_UDATA, arg->udata);
}

static void uburma_alloc_jfs_fill_spec_out(void *arg_addr, struct uburma_cmd_spec *spec)
{
	struct uburma_cmd_alloc_jfs *arg = arg_addr;
	struct uburma_cmd_spec *s = spec;

	SPEC(s++, ALLOC_JFS_OUT_ID, arg->out.id);
	SPEC(s++, ALLOC_JFS_OUT_DEPTH, arg->out.depth);
	SPEC(s++, ALLOC_JFS_OUT_MAX_SGE, arg->out.max_sge);
	SPEC(s++, ALLOC_JFS_OUT_MAX_RSGE, arg->out.max_rsge);
	SPEC(s++, ALLOC_JFS_OUT_MAX_INLINE_DATA, arg->out.max_inline_data);
	SPEC(s++, ALLOC_JFS_OUT_HANDLE, arg->out.handle);
	SPEC(s++, ALLOC_JFS_OUT_UDATA, arg->udata);
}

static void uburma_free_jfs_fill_spec_in(void *arg_addr, struct uburma_cmd_spec *spec)
{
	struct uburma_cmd_free_jfs *arg = arg_addr;
	struct uburma_cmd_spec *s = spec;

	SPEC(s++, FREE_JFS_IN_HANDLE, arg->in.handle);
	SPEC(s++, FREE_JFS_IN_UDATA, arg->udata);
}

static void uburma_free_jfs_fill_spec_out(void *arg_addr, struct uburma_cmd_spec *spec)
{
	struct uburma_cmd_free_jfs *arg = arg_addr;
	struct uburma_cmd_spec *s = spec;

	SPEC(s++, FREE_JFS_OUT_ASYNC_EVENTS_REPORTED, arg->out.async_events_reported);
	SPEC(s++, FREE_JFS_OUT_UDATA, arg->udata);
}

static void uburma_set_jfs_opt_fill_spec_in(void *arg_addr, struct uburma_cmd_spec *spec)
{
	struct uburma_cmd_set_jfs_opt *arg = arg_addr;
	struct uburma_cmd_spec *s = spec;

	SPEC(s++, SET_JFS_OPT_IN_HANDLE, arg->in.handle);
	SPEC(s++, SET_JFS_OPT_IN_OPT, arg->in.opt);
	SPEC(s++, SET_JFS_OPT_IN_BUF, arg->in.buf);
	SPEC(s++, SET_JFS_OPT_IN_LEN, arg->in.len);
	SPEC(s++, SET_JFS_OPT_IN_UDATA, arg->udata);
}

static void uburma_set_jfs_opt_fill_spec_out(void *arg_addr, struct uburma_cmd_spec *spec)
{
	struct uburma_cmd_set_jfs_opt *arg = arg_addr;
	struct uburma_cmd_spec *s = spec;

	SPEC(s++, SET_JFS_OPT_OUT_UDATA, arg->udata);
}

static void uburma_get_jfs_opt_fill_spec_in(void *arg_addr, struct uburma_cmd_spec *spec)
{
	struct uburma_cmd_get_jfs_opt *arg = arg_addr;
	struct uburma_cmd_spec *s = spec;

	SPEC(s++, GET_JFS_OPT_IN_HANDLE, arg->in.handle);
	SPEC(s++, GET_JFS_OPT_IN_OPT, arg->in.opt);
	SPEC(s++, GET_JFS_OPT_IN_BUF, arg->in.buf);
	SPEC(s++, GET_JFS_OPT_IN_LEN, arg->in.len);
	SPEC(s++, GET_JFS_OPT_IN_UDATA, arg->udata);
}

static void uburma_get_jfs_opt_fill_spec_out(void *arg_addr, struct uburma_cmd_spec *spec)
{
	struct uburma_cmd_get_jfs_opt *arg = arg_addr;
	struct uburma_cmd_spec *s = spec;

	SPEC(s++, GET_JFS_OPT_OUT_BUF, arg->out.buf);
	SPEC(s++, GET_JFS_OPT_OUT_LEN, arg->out.len);
	SPEC(s++, GET_JFS_OPT_OUT_UDATA, arg->udata);
}

static void uburma_active_jfs_fill_spec_in(void *arg_addr, struct uburma_cmd_spec *spec)
{
	struct uburma_cmd_active_jfs *arg = arg_addr;
	struct uburma_cmd_spec *s = spec;

	SPEC(s++, ACTIVE_JFS_IN_HANDLE, arg->in.handle);
	SPEC(s++, ACTIVE_JFS_IN_DEPTH, arg->in.depth);
	SPEC(s++, ACTIVE_JFS_IN_FLAG, arg->in.flag);
	SPEC(s++, ACTIVE_JFS_IN_TRANS_MODE, arg->in.trans_mode);
	SPEC(s++, ACTIVE_JFS_IN_PRIORITY, arg->in.priority);
	SPEC(s++, ACTIVE_JFS_IN_MAX_SGE, arg->in.max_sge);
	SPEC(s++, ACTIVE_JFS_IN_MAX_RSGE, arg->in.max_rsge);
	SPEC(s++, ACTIVE_JFS_IN_MAX_INLINE_DATA, arg->in.max_inline_data);
	SPEC(s++, ACTIVE_JFS_IN_RNR_RETRY, arg->in.rnr_retry);
	SPEC(s++, ACTIVE_JFS_IN_ERR_TIMEOUT, arg->in.err_timeout);
	SPEC(s++, ACTIVE_JFS_IN_JFC_ID, arg->in.jfc_id);
	SPEC(s++, ACTIVE_JFS_IN_JFC_HANDLE, arg->in.jfc_handle);
	SPEC(s++, ACTIVE_JFS_IN_JFS_OPT, arg->in.jfs_opt);
	SPEC(s++, ACTIVE_JFS_IN_UDATA, arg->udata);
}

static void uburma_active_jfs_fill_spec_out(void *arg_addr, struct uburma_cmd_spec *spec)
{
	struct uburma_cmd_active_jfs *arg = arg_addr;
	struct uburma_cmd_spec *s = spec;

	SPEC(s++, ACTIVE_JFS_OUT_ID, arg->out.id);
	SPEC(s++, ACTIVE_JFS_OUT_DEPTH, arg->out.depth);
	SPEC(s++, ACTIVE_JFS_OUT_MAX_SGE, arg->out.max_sge);
	SPEC(s++, ACTIVE_JFS_OUT_MAX_RSGE, arg->out.max_rsge);
	SPEC(s++, ACTIVE_JFS_OUT_MAX_INLINE_DATA, arg->out.max_inline_data);
	SPEC(s++, ACTIVE_JFS_OUT_HANDLE, arg->out.handle);
	SPEC(s++, ACTIVE_JFS_OUT_UDATA, arg->udata);
}

static void uburma_deactive_jfs_fill_spec_in(void *arg_addr, struct uburma_cmd_spec *spec)
{
	struct uburma_cmd_deactive_jfs *arg = arg_addr;
	struct uburma_cmd_spec *s = spec;

	SPEC(s++, DEACTIVE_JFS_IN_HANDLE, arg->in.handle);
	SPEC(s++, DEACTIVE_JFS_IN_UDATA, arg->udata);
}

static void uburma_deactive_jfs_fill_spec_out(void *arg_addr, struct uburma_cmd_spec *spec)
{
	struct uburma_cmd_deactive_jfs *arg = arg_addr;
	struct uburma_cmd_spec *s = spec;

	SPEC(s++, DEACTIVE_JFS_OUT_UDATA, arg->udata);
}

static void uburma_create_jfr_fill_spec_in(void *arg_addr, struct uburma_cmd_spec *spec)
{
	struct uburma_cmd_create_jfr *arg = arg_addr;
	struct uburma_cmd_spec *s = spec;

	SPEC(s++, CREATE_JFR_IN_DEPTH, arg->in.depth);
	SPEC(s++, CREATE_JFR_IN_FLAG, arg->in.flag);
	SPEC(s++, CREATE_JFR_IN_TRANS_MODE, arg->in.trans_mode);
	SPEC(s++, CREATE_JFR_IN_MAX_SGE, arg->in.max_sge);
	SPEC(s++, CREATE_JFR_IN_MIN_RNR_TIMER, arg->in.min_rnr_timer);
	SPEC(s++, CREATE_JFR_IN_JFC_ID, arg->in.jfc_id);
	SPEC(s++, CREATE_JFR_IN_JFC_HANDLE, arg->in.jfc_handle);
	SPEC(s++, CREATE_JFR_IN_TOKEN, arg->in.token);
	SPEC(s++, CREATE_JFR_IN_ID, arg->in.id);
	SPEC(s++, CREATE_JFR_IN_URMA_JFR, arg->in.urma_jfr);
	SPEC(s++, CREATE_JFR_IN_UDATA, arg->udata);
}

static void
uburma_create_jfr_fill_spec_out(void *arg_addr,
				struct uburma_cmd_spec *spec)
{
	struct uburma_cmd_create_jfr *arg = arg_addr;
	struct uburma_cmd_spec *s = spec;

	SPEC(s++, CREATE_JFR_OUT_ID, arg->out.id);
	SPEC(s++, CREATE_JFR_OUT_DEPTH, arg->out.depth);
	SPEC(s++, CREATE_JFR_OUT_MAX_SGE, arg->out.max_sge);
	SPEC(s++, CREATE_JFR_OUT_HANDLE, arg->out.handle);
	SPEC(s++, CREATE_JFR_OUT_UDATA, arg->udata);
}

static void
uburma_modify_jfr_fill_spec_in(void *arg_addr,
			       struct uburma_cmd_spec *spec)
{
	struct uburma_cmd_modify_jfr *arg = arg_addr;
	struct uburma_cmd_spec *s = spec;

	SPEC(s++, MODIFY_JFR_IN_HANDLE, arg->in.handle);
	SPEC(s++, MODIFY_JFR_IN_MASK, arg->in.mask);
	SPEC(s++, MODIFY_JFR_IN_RX_THRESHOLD, arg->in.rx_threshold);
	SPEC(s++, MODIFY_JFR_IN_STATE, arg->in.state);
	SPEC(s++, MODIFY_JFR_IN_UDATA, arg->udata);
}

static void
uburma_modify_jfr_fill_spec_out(void *arg_addr,
				struct uburma_cmd_spec *spec)
{
	struct uburma_cmd_modify_jfr *arg = arg_addr;
	struct uburma_cmd_spec *s = spec;

	SPEC(s++, MODIFY_JFR_OUT_UDATA, arg->udata);
}

static void
uburma_cmd_query_jfr_fill_spec_in(void *arg_addr,
				  struct uburma_cmd_spec *spec)
{
	struct uburma_cmd_query_jfr *arg = arg_addr;
	struct uburma_cmd_spec *s = spec;

	SPEC(s++, QUERY_JFR_IN_HANDLE, arg->in.handle);
}

static void
uburma_cmd_query_jfr_fill_spec_out(void *arg_addr,
				   struct uburma_cmd_spec *spec)
{
	struct uburma_cmd_query_jfr *arg = arg_addr;
	struct uburma_cmd_spec *s = spec;

	SPEC(s++, QUERY_JFR_OUT_DEPTH, arg->out.depth);
	SPEC(s++, QUERY_JFR_OUT_FLAG, arg->out.flag);
	SPEC(s++, QUERY_JFR_OUT_TRANS_MODE, arg->out.trans_mode);
	SPEC(s++, QUERY_JFR_OUT_MAX_SGE, arg->out.max_sge);
	SPEC(s++, QUERY_JFR_OUT_MIN_RNR_TIMER,
	     arg->out.min_rnr_timer);
	SPEC(s++, QUERY_JFR_OUT_TOKEN, arg->out.token);
	SPEC(s++, QUERY_JFR_OUT_ID, arg->out.id);
	SPEC(s++, QUERY_JFR_OUT_RX_THRESHOLD, arg->out.rx_threshold);
	SPEC(s++, QUERY_JFR_OUT_STATE, arg->out.state);
}

static void
uburma_delete_jfr_fill_spec_in(void *arg_addr,
			       struct uburma_cmd_spec *spec)
{
	struct uburma_cmd_delete_jfr *arg = arg_addr;
	struct uburma_cmd_spec *s = spec;

	SPEC(s++, DELETE_JFR_IN_HANDLE, arg->in.handle);
}

static void
uburma_delete_jfr_fill_spec_out(void *arg_addr,
				struct uburma_cmd_spec *spec)
{
	struct uburma_cmd_delete_jfr *arg = arg_addr;
	struct uburma_cmd_spec *s = spec;

	SPEC(s++, DELETE_JFR_OUT_ASYNC_EVENTS_REPORTED,
	     arg->out.async_events_reported);
}

static void
uburma_delete_jfr_batch_fill_spec_in(void *arg_addr,
				     struct uburma_cmd_spec *spec)
{
	struct uburma_cmd_delete_jfr_batch *arg = arg_addr;
	struct uburma_cmd_spec *s = spec;

	SPEC(s++, DELETE_JFR_BATCH_IN_JFR_COUNT, arg->in.jfr_num);
	SPEC(s++, DELETE_JFR_BATCH_IN_JFR_PTR, arg->in.jfr_ptr);
}

static void
uburma_delete_jfr_batch_fill_spec_out(void *arg_addr,
				      struct uburma_cmd_spec *spec)
{
	struct uburma_cmd_delete_jfr_batch *arg = arg_addr;
	struct uburma_cmd_spec *s = spec;

	SPEC(s++, DELETE_JFR_BATCH_OUT_ASYNC_EVENTS_REPORTED,
	     arg->out.async_events_reported);
	SPEC(s++, DELETE_JFR_BATCH_OUT_BAD_JFR_INDEX,
	     arg->out.bad_jfr_index);
}

static void uburma_alloc_jfr_fill_spec_in(void *arg_addr, struct uburma_cmd_spec *spec)
{
	struct uburma_cmd_alloc_jfr *arg = arg_addr;
	struct uburma_cmd_spec *s = spec;

	SPEC(s++, ALLOC_JFR_IN_DEPTH, arg->in.depth);
	SPEC(s++, ALLOC_JFR_IN_FLAG, arg->in.flag);
	SPEC(s++, ALLOC_JFR_IN_TRANS_MODE, arg->in.trans_mode);
	SPEC(s++, ALLOC_JFR_IN_MAX_SGE, arg->in.max_sge);
	SPEC(s++, ALLOC_JFR_IN_MIN_RNR_TIMER, arg->in.min_rnr_timer);
	SPEC(s++, ALLOC_JFR_IN_JFC_ID, arg->in.jfc_id);
	SPEC(s++, ALLOC_JFR_IN_JFC_HANDLE, arg->in.jfc_handle);
	SPEC(s++, ALLOC_JFR_IN_TOKEN, arg->in.token);
	SPEC(s++, ALLOC_JFR_IN_ID, arg->in.id);
	SPEC(s++, ALLOC_JFR_IN_URMA_JFR, arg->in.urma_jfr);
	SPEC(s++, ALLOC_JFR_IN_UDATA, arg->udata);
}

static void uburma_alloc_jfr_fill_spec_out(void *arg_addr, struct uburma_cmd_spec *spec)
{
	struct uburma_cmd_alloc_jfr *arg = arg_addr;
	struct uburma_cmd_spec *s = spec;

	SPEC(s++, ALLOC_JFR_OUT_ID, arg->out.id);
	SPEC(s++, ALLOC_JFR_OUT_DEPTH, arg->out.depth);
	SPEC(s++, ALLOC_JFR_OUT_HANDLE, arg->out.handle);
	SPEC(s++, ALLOC_JFR_OUT_MAX_SGE, arg->out.max_sge);
	SPEC(s++, ALLOC_JFR_OUT_UDATA, arg->udata);
}

static void uburma_free_jfr_fill_spec_in(void *arg_addr, struct uburma_cmd_spec *spec)
{
	struct uburma_cmd_free_jfr *arg = arg_addr;
	struct uburma_cmd_spec *s = spec;

	SPEC(s++, FREE_JFR_IN_HANDLE, arg->in.handle);
	SPEC(s++, FREE_JFR_IN_UDATA, arg->udata);
}

static void uburma_free_jfr_fill_spec_out(void *arg_addr, struct uburma_cmd_spec *spec)
{
	struct uburma_cmd_free_jfr *arg = arg_addr;
	struct uburma_cmd_spec *s = spec;

	SPEC(s++, FREE_JFR_OUT_ASYNC_EVENTS_REPORTED, arg->out.async_events_reported);
	SPEC(s++, FREE_JFR_OUT_UDATA, arg->udata);
}

static void uburma_set_jfr_opt_fill_spec_in(void *arg_addr, struct uburma_cmd_spec *spec)
{
	struct uburma_cmd_set_jfr_opt *arg = arg_addr;
	struct uburma_cmd_spec *s = spec;

	SPEC(s++, SET_JFR_OPT_IN_HANDLE, arg->in.handle);
	SPEC(s++, SET_JFR_OPT_IN_OPT, arg->in.opt);
	SPEC(s++, SET_JFR_OPT_IN_BUF, arg->in.buf);
	SPEC(s++, SET_JFR_OPT_IN_LEN, arg->in.len);
	SPEC(s++, SET_JFR_OPT_IN_UDATA, arg->udata);
}

static void uburma_set_jfr_opt_fill_spec_out(void *arg_addr, struct uburma_cmd_spec *spec)
{
	struct uburma_cmd_set_jfr_opt *arg = arg_addr;
	struct uburma_cmd_spec *s = spec;

	SPEC(s++, SET_JFR_OPT_OUT_UDATA, arg->udata);
}

static void uburma_get_jfr_opt_fill_spec_in(void *arg_addr, struct uburma_cmd_spec *spec)
{
	struct uburma_cmd_get_jfr_opt *arg = arg_addr;
	struct uburma_cmd_spec *s = spec;

	SPEC(s++, GET_JFR_OPT_IN_HANDLE, arg->in.handle);
	SPEC(s++, GET_JFR_OPT_IN_OPT, arg->in.opt);
	SPEC(s++, GET_JFR_OPT_IN_BUF, arg->in.buf);
	SPEC(s++, GET_JFR_OPT_IN_LEN, arg->in.len);
	SPEC(s++, GET_JFR_OPT_IN_UDATA, arg->udata);
}

static void uburma_get_jfr_opt_fill_spec_out(void *arg_addr, struct uburma_cmd_spec *spec)
{
	struct uburma_cmd_get_jfr_opt *arg = arg_addr;
	struct uburma_cmd_spec *s = spec;

	SPEC(s++, GET_JFR_OPT_OUT_BUF, arg->out.buf);
	SPEC(s++, GET_JFR_OPT_OUT_LEN, arg->out.len);
	SPEC(s++, GET_JFR_OPT_OUT_UDATA, arg->udata);
}

static void uburma_active_jfr_fill_spec_in(void *arg_addr, struct uburma_cmd_spec *spec)
{
	struct uburma_cmd_active_jfr *arg = arg_addr;
	struct uburma_cmd_spec *s = spec;

	SPEC(s++, ACTIVE_JFR_IN_HANDLE, arg->in.handle);
	SPEC(s++, ACTIVE_JFR_IN_DEPTH, arg->in.depth);
	SPEC(s++, ACTIVE_JFR_IN_FLAG, arg->in.flag);
	SPEC(s++, ACTIVE_JFR_IN_TRANS_MODE, arg->in.trans_mode);
	SPEC(s++, ACTIVE_JFR_IN_MAX_SGE, arg->in.max_sge);
	SPEC(s++, ACTIVE_JFR_IN_MIN_RNR_TIMER, arg->in.min_rnr_timer);
	SPEC(s++, ACTIVE_JFR_IN_JFC_ID, arg->in.jfc_id);
	SPEC(s++, ACTIVE_JFR_IN_JFC_HANDLE, arg->in.jfc_handle);
	SPEC(s++, ACTIVE_JFR_IN_TOKEN, arg->in.token_value);
	SPEC(s++, ACTIVE_JFR_IN_JFR_OPT, arg->in.urma_jfr_opt);
	SPEC(s++, ACTIVE_JFR_IN_UDATA, arg->udata);
}

static void uburma_active_jfr_fill_spec_out(void *arg_addr, struct uburma_cmd_spec *spec)
{
	struct uburma_cmd_active_jfr *arg = arg_addr;
	struct uburma_cmd_spec *s = spec;

	SPEC(s++, ACTIVE_JFR_OUT_ID, arg->out.id);
	SPEC(s++, ACTIVE_JFR_OUT_DEPTH, arg->out.depth);
	SPEC(s++, ACTIVE_JFR_OUT_HANDLE, arg->out.handle);
	SPEC(s++, ACTIVE_JFR_OUT_MAX_SGE, arg->out.max_sge);
	SPEC(s++, ACTIVE_JFR_OUT_UDATA, arg->udata);
}

static void uburma_deactive_jfr_fill_spec_in(void *arg_addr, struct uburma_cmd_spec *spec)
{
	struct uburma_cmd_deactive_jfr *arg = arg_addr;
	struct uburma_cmd_spec *s = spec;

	SPEC(s++, DEACTIVE_JFR_IN_HANDLE, arg->in.handle);
	SPEC(s++, DEACTIVE_JFR_IN_UDATA, arg->udata);
}

static void uburma_deactive_jfr_fill_spec_out(void *arg_addr, struct uburma_cmd_spec *spec)
{
	struct uburma_cmd_deactive_jfr *arg = arg_addr;
	struct uburma_cmd_spec *s = spec;

	SPEC(s++, DEACTIVE_JFR_OUT_UDATA, arg->udata);
}

static void uburma_create_jfc_fill_spec_in(void *arg_addr, struct uburma_cmd_spec *spec)
{
	struct uburma_cmd_create_jfc *arg = arg_addr;
	struct uburma_cmd_spec *s = spec;

	SPEC(s++, CREATE_JFC_IN_DEPTH, arg->in.depth);
	SPEC(s++, CREATE_JFC_IN_FLAG, arg->in.flag);
	SPEC(s++, CREATE_JFC_IN_JFCE_FD, arg->in.jfce_fd);
	SPEC(s++, CREATE_JFC_IN_URMA_JFC, arg->in.urma_jfc);
	SPEC(s++, CREATE_JFC_IN_CEQN, arg->in.ceqn);
	SPEC(s++, CREATE_JFC_IN_UDATA, arg->udata);
}

static void
uburma_create_jfc_fill_spec_out(void *arg_addr,
				struct uburma_cmd_spec *spec)
{
	struct uburma_cmd_create_jfc *arg = arg_addr;
	struct uburma_cmd_spec *s = spec;

	SPEC(s++, CREATE_JFC_OUT_ID, arg->out.id);
	SPEC(s++, CREATE_JFC_OUT_DEPTH, arg->out.depth);
	SPEC(s++, CREATE_JFC_OUT_HANDLE, arg->out.handle);
	SPEC(s++, CREATE_JFC_OUT_UDATA, arg->udata);
}

static void
uburma_modify_jfc_fill_spec_in(void *arg_addr,
			       struct uburma_cmd_spec *spec)
{
	struct uburma_cmd_modify_jfc *arg = arg_addr;
	struct uburma_cmd_spec *s = spec;

	SPEC(s++, MODIFY_JFC_IN_HANDLE, arg->in.handle);
	SPEC(s++, MODIFY_JFC_IN_MASK, arg->in.mask);
	SPEC(s++, MODIFY_JFC_IN_MODERATE_COUNT,
	     arg->in.moderate_count);
	SPEC(s++, MODIFY_JFC_IN_MODERATE_PERIOD,
	     arg->in.moderate_period);
	SPEC(s++, MODIFY_JFC_IN_UDATA, arg->udata);
}

static void
uburma_modify_jfc_fill_spec_out(void *arg_addr,
				struct uburma_cmd_spec *spec)
{
	struct uburma_cmd_modify_jfc *arg = arg_addr;
	struct uburma_cmd_spec *s = spec;

	SPEC(s++, MODIFY_JFC_OUT_UDATA, arg->udata);
}

static void
uburma_delete_jfc_fill_spec_in(void *arg_addr,
			       struct uburma_cmd_spec *spec)
{
	struct uburma_cmd_delete_jfc *arg = arg_addr;
	struct uburma_cmd_spec *s = spec;

	SPEC(s++, DELETE_JFC_IN_HANDLE, arg->in.handle);
}

static void
uburma_delete_jfc_fill_spec_out(void *arg_addr,
				struct uburma_cmd_spec *spec)
{
	struct uburma_cmd_delete_jfc *arg = arg_addr;
	struct uburma_cmd_spec *s = spec;

	SPEC(s++, DELETE_JFC_OUT_COMP_EVENTS_REPORTED,
	     arg->out.comp_events_reported);
	SPEC(s++, DELETE_JFC_OUT_ASYNC_EVENTS_REPORTED,
	     arg->out.async_events_reported);
}

static void uburma_alloc_jfc_fill_spec_in(void *arg_addr, struct uburma_cmd_spec *spec)
{
	struct uburma_cmd_alloc_jfc *arg = arg_addr;
	struct uburma_cmd_spec *s = spec;

	SPEC(s++, ALLOC_JFC_IN_DEPTH, arg->in.depth);
	SPEC(s++, ALLOC_JFC_IN_FLAG, arg->in.flag);
	SPEC(s++, ALLOC_JFC_IN_JFCE_FD, arg->in.jfce_fd);
	SPEC(s++, ALLOC_JFC_IN_URMA_JFC, arg->in.urma_jfc);
	SPEC(s++, ALLOC_JFC_IN_CEQN, arg->in.ceqn);
	SPEC(s++, ALLOC_JFC_IN_UDATA, arg->udata);
}

static void uburma_alloc_jfc_fill_spec_out(void *arg_addr, struct uburma_cmd_spec *spec)
{
	struct uburma_cmd_alloc_jfc *arg = arg_addr;
	struct uburma_cmd_spec *s = spec;

	SPEC(s++, ALLOC_JFC_OUT_DEPTH, arg->out.depth);
	SPEC(s++, ALLOC_JFC_OUT_ID, arg->out.id);
	SPEC(s++, ALLOC_JFC_OUT_HANDLE, arg->out.handle);
	SPEC(s++, ALLOC_JFC_IN_UDATA, arg->udata);
}

static void uburma_free_jfc_fill_spec_in(void *arg_addr, struct uburma_cmd_spec *spec)
{
	struct uburma_cmd_free_jfc *arg = arg_addr;
	struct uburma_cmd_spec *s = spec;

	SPEC(s++, FREE_JFC_IN_HANDLE, arg->in.handle);
	SPEC(s++, FREE_JFC_IN_UDATA, arg->udata);
}

static void uburma_free_jfc_fill_spec_out(void *arg_addr, struct uburma_cmd_spec *spec)
{
	struct uburma_cmd_free_jfc *arg = arg_addr;
	struct uburma_cmd_spec *s = spec;

	SPEC(s++, FREE_JFC_OUT_COMP_EVENTS_REPORTED, arg->out.comp_events_reported);
	SPEC(s++, FREE_JFC_OUT_ASYNC_EVENTS_REPORTED, arg->out.async_events_reported);
	SPEC(s++, FREE_JFC_OUT_UDATA, arg->udata);
}
static void uburma_set_jfc_opt_fill_spec_in(void *arg_addr, struct uburma_cmd_spec *spec)
{
	struct uburma_cmd_set_jfc_opt *arg = arg_addr;
	struct uburma_cmd_spec *s = spec;

	SPEC(s++, SET_JFC_OPT_IN_HANDLE, arg->in.handle);
	SPEC(s++, SET_JFC_OPT_IN_OPT, arg->in.opt);
	SPEC(s++, SET_JFC_OPT_IN_BUF, arg->in.buf);
	SPEC(s++, SET_JFC_OPT_IN_LEN, arg->in.len);
	SPEC(s++, SET_JFC_OPT_IN_UDATA, arg->udata);
}

static void uburma_set_jfc_opt_fill_spec_out(void *arg_addr, struct uburma_cmd_spec *spec)
{
	struct uburma_cmd_set_jfc_opt *arg = arg_addr;
	struct uburma_cmd_spec *s = spec;

	SPEC(s++, SET_JFC_OPT_OUT_UDATA, arg->udata);
}

static void uburma_get_jfc_opt_fill_spec_in(void *arg_addr, struct uburma_cmd_spec *spec)
{
	struct uburma_cmd_get_jfc_opt *arg = arg_addr;
	struct uburma_cmd_spec *s = spec;

	SPEC(s++, GET_JFC_OPT_IN_HANDLE, arg->in.handle);
	SPEC(s++, GET_JFC_OPT_IN_OPT, arg->in.opt);
	SPEC(s++, GET_JFC_OPT_IN_BUF, arg->in.buf);
	SPEC(s++, GET_JFC_OPT_IN_LEN, arg->in.len);
	SPEC(s++, GET_JFC_OPT_IN_UDATA, arg->udata);
}

static void uburma_get_jfc_opt_fill_spec_out(void *arg_addr, struct uburma_cmd_spec *spec)
{
	struct uburma_cmd_get_jfc_opt *arg = arg_addr;
	struct uburma_cmd_spec *s = spec;

	SPEC(s++, GET_JFC_OPT_OUT_BUF, arg->out.buf);
	SPEC(s++, GET_JFC_OPT_OUT_LEN, arg->out.len);
	SPEC(s++, GET_JFC_OPT_OUT_UDATA, arg->udata);
}

static void uburma_delete_jfc_batch_fill_spec_in(void *arg_addr, struct uburma_cmd_spec *spec)
{
	struct uburma_cmd_delete_jfc_batch *arg = arg_addr;
	struct uburma_cmd_spec *s = spec;

	SPEC(s++, DELETE_JFC_BATCH_IN_JFC_COUNT, arg->in.jfc_num);
	SPEC(s++, DELETE_JFC_BATCH_IN_JFC_PTR, arg->in.jfc_ptr);
}

static void
uburma_delete_jfc_batch_fill_spec_out(void *arg_addr,
				      struct uburma_cmd_spec *spec)
{
	struct uburma_cmd_delete_jfc_batch *arg = arg_addr;
	struct uburma_cmd_spec *s = spec;

	SPEC(s++, DELETE_JFC_BATCH_OUT_COMP_EVENTS_REPORTED,
	     arg->out.comp_events_reported);
	SPEC(s++, DELETE_JFC_BATCH_OUT_ASYNC_EVENTS_REPORTED,
	     arg->out.async_events_reported);
	SPEC(s++, DELETE_JFC_BATCH_OUT_BAD_JFC_INDEX,
	     arg->out.bad_jfc_index);
}

static void uburma_active_jfc_fill_spec_in(void *arg_addr, struct uburma_cmd_spec *spec)
{
	struct uburma_cmd_active_jfc *arg = arg_addr;
	struct uburma_cmd_spec *s = spec;

	SPEC(s++, ACTIVE_JFC_IN_HANDLE, arg->in.handle);
	SPEC(s++, ACTIVE_JFC_IN_DEPTH, arg->in.depth);
	SPEC(s++, ACTIVE_JFC_IN_FLAG, arg->in.flag);
	SPEC(s++, ACTIVE_JFC_IN_CEQN, arg->in.ceqn);
	SPEC(s++, ACTIVE_JFC_IN_JFC_OPT, arg->in.urma_jfc_opt);
	SPEC(s++, ACTIVE_JFC_IN_UDATA, arg->udata);
}

static void uburma_active_jfc_fill_spec_out(void *arg_addr, struct uburma_cmd_spec *spec)
{
	struct uburma_cmd_active_jfc *arg = arg_addr;
	struct uburma_cmd_spec *s = spec;

	SPEC(s++, ACTIVE_JFC_OUT_ID, arg->out.id);
	SPEC(s++, ACTIVE_JFC_OUT_DEPTH, arg->out.depth);
	SPEC(s++, ACTIVE_JFC_OUT_HANDLE, arg->out.handle);
	SPEC(s++, ACTIVE_JFC_OUT_UDATA, arg->udata);
}

static void uburma_deactive_jfc_fill_spec_in(void *arg_addr, struct uburma_cmd_spec *spec)
{
	struct uburma_cmd_deactive_jfc *arg = arg_addr;
	struct uburma_cmd_spec *s = spec;

	SPEC(s++, DEACTIVE_JFC_IN_HANDLE, arg->in.handle);
	SPEC(s++, DEACTIVE_JFC_IN_UDATA, arg->udata);
}

static void uburma_deactive_jfc_fill_spec_out(void *arg_addr, struct uburma_cmd_spec *spec)
{
	struct uburma_cmd_deactive_jfc *arg = arg_addr;
	struct uburma_cmd_spec *s = spec;

	SPEC(s++, DEACTIVE_JFC_IN_UDATA, arg->udata);
}

static void uburma_create_jfce_fill_spec_out(void *arg_addr, struct uburma_cmd_spec *spec)
{
	struct uburma_cmd_create_jfce *arg = arg_addr;
	struct uburma_cmd_spec *s = spec;

	SPEC(s++, CREATE_JFCE_OUT_FD, arg->out.fd);
}

static void
uburma_import_jfr_fill_spec_in(void *arg_addr,
			       struct uburma_cmd_spec *spec)
{
	struct uburma_cmd_import_jfr *arg = arg_addr;
	struct uburma_cmd_spec *s = spec;

	SPEC(s++, IMPORT_JFR_IN_EID, arg->in.eid);
	SPEC(s++, IMPORT_JFR_IN_ID, arg->in.id);
	SPEC(s++, IMPORT_JFR_IN_FLAG, arg->in.flag);
	SPEC(s++, IMPORT_JFR_IN_TOKEN, arg->in.token);
	SPEC(s++, IMPORT_JFR_IN_TRANS_MODE, arg->in.trans_mode);
	SPEC(s++, IMPORT_JFR_IN_TP_TYPE, arg->in.tp_type);
	SPEC(s++, IMPORT_JFR_IN_UDATA, arg->udata);
}

static void
uburma_import_jfr_fill_spec_out(void *arg_addr,
				struct uburma_cmd_spec *spec)
{
	struct uburma_cmd_import_jfr *arg = arg_addr;
	struct uburma_cmd_spec *s = spec;

	SPEC(s++, IMPORT_JFR_OUT_TPN, arg->out.tpn);
	SPEC(s++, IMPORT_JFR_OUT_HANDLE, arg->out.handle);
	SPEC(s++, IMPORT_JFR_OUT_UDATA, arg->udata);
}

static void
uburma_unimport_jfr_fill_spec_in(void *arg_addr,
				 struct uburma_cmd_spec *spec)
{
	struct uburma_cmd_unimport_jfr *arg = arg_addr;
	struct uburma_cmd_spec *s = spec;

	SPEC(s++, UNIMPORT_JFR_IN_HANDLE, arg->in.handle);
}

static void
uburma_create_jetty_fill_spec_in(void *arg_addr,
				 struct uburma_cmd_spec *spec)
{
	struct uburma_cmd_create_jetty *arg = arg_addr;
	struct uburma_cmd_spec *s = spec;

	SPEC(s++, CREATE_JETTY_IN_ID, arg->in.id);
	SPEC(s++, CREATE_JETTY_IN_JETTY_FLAG, arg->in.jetty_flag);
	SPEC(s++, CREATE_JETTY_IN_JFS_DEPTH, arg->in.jfs_depth);
	SPEC(s++, CREATE_JETTY_IN_JFS_FLAG, arg->in.jfs_flag);
	SPEC(s++, CREATE_JETTY_IN_TRANS_MODE, arg->in.trans_mode);
	SPEC(s++, CREATE_JETTY_IN_PRIORITY, arg->in.priority);
	SPEC(s++, CREATE_JETTY_IN_MAX_SEND_SGE, arg->in.max_send_sge);
	SPEC(s++, CREATE_JETTY_IN_MAX_SEND_RSGE,
	     arg->in.max_send_rsge);
	SPEC(s++, CREATE_JETTY_IN_MAX_INLINE_DATA,
	     arg->in.max_inline_data);
	SPEC(s++, CREATE_JETTY_IN_RNR_RETRY, arg->in.rnr_retry);
	SPEC(s++, CREATE_JETTY_IN_ERR_TIMEOUT, arg->in.err_timeout);
	SPEC(s++, CREATE_JETTY_IN_SEND_JFC_ID, arg->in.send_jfc_id);
	SPEC(s++, CREATE_JETTY_IN_SEND_JFC_HANDLE,
	     arg->in.send_jfc_handle);
	SPEC(s++, CREATE_JETTY_IN_JFR_DEPTH, arg->in.jfr_depth);
	SPEC(s++, CREATE_JETTY_IN_JFR_FLAG, arg->in.jfr_flag);
	SPEC(s++, CREATE_JETTY_IN_MAX_RECV_SGE, arg->in.max_recv_sge);
	SPEC(s++, CREATE_JETTY_IN_MIN_RNR_TIMER,
	     arg->in.min_rnr_timer);
	SPEC(s++, CREATE_JETTY_IN_RECV_JFC_ID, arg->in.recv_jfc_id);
	SPEC(s++, CREATE_JETTY_IN_RECV_JFC_HANDLE,
	     arg->in.recv_jfc_handle);
	SPEC(s++, CREATE_JETTY_IN_TOKEN, arg->in.token);
	SPEC(s++, CREATE_JETTY_IN_JFR_ID, arg->in.jfr_id);
	SPEC(s++, CREATE_JETTY_IN_JFR_HANDLE, arg->in.jfr_handle);
	SPEC(s++, CREATE_JETTY_IN_JETTY_GRP_HANDLE,
	     arg->in.jetty_grp_handle);
	SPEC(s++, CREATE_JETTY_IN_IS_JETTY_GRP, arg->in.is_jetty_grp);
	SPEC(s++, CREATE_JETTY_IN_URMA_JETTY, arg->in.urma_jetty);
	SPEC(s++, CREATE_JETTY_IN_UDATA, arg->udata);
}

static void
uburma_create_jetty_fill_spec_out(void *arg_addr,
				  struct uburma_cmd_spec *spec)
{
	struct uburma_cmd_create_jetty *arg = arg_addr;
	struct uburma_cmd_spec *s = spec;

	SPEC(s++, CREATE_JETTY_OUT_ID, arg->out.id);
	SPEC(s++, CREATE_JETTY_OUT_HANDLE, arg->out.handle);
	SPEC(s++, CREATE_JETTY_OUT_JFS_DEPTH, arg->out.jfs_depth);
	SPEC(s++, CREATE_JETTY_OUT_JFR_DEPTH, arg->out.jfr_depth);
	SPEC(s++, CREATE_JETTY_OUT_MAX_SEND_SGE,
	     arg->out.max_send_sge);
	SPEC(s++, CREATE_JETTY_OUT_MAX_SEND_RSGE,
	     arg->out.max_send_rsge);
	SPEC(s++, CREATE_JETTY_OUT_MAX_RECV_SGE,
	     arg->out.max_recv_sge);
	SPEC(s++, CREATE_JETTY_OUT_MAX_INLINE_DATA,
	     arg->out.max_inline_data);
	SPEC(s++, CREATE_JETTY_OUT_UDATA, arg->udata);
}

static void
uburma_modify_jetty_fill_spec_in(void *arg_addr,
				 struct uburma_cmd_spec *spec)
{
	struct uburma_cmd_modify_jetty *arg = arg_addr;
	struct uburma_cmd_spec *s = spec;

	SPEC(s++, MODIFY_JETTY_IN_HANDLE, arg->in.handle);
	SPEC(s++, MODIFY_JETTY_IN_MASK, arg->in.mask);
	SPEC(s++, MODIFY_JETTY_IN_RX_THRESHOLD, arg->in.rx_threshold);
	SPEC(s++, MODIFY_JETTY_IN_STATE, arg->in.state);
	SPEC(s++, MODIFY_JETTY_IN_UDATA, arg->udata);
}

static void
uburma_modify_jetty_fill_spec_out(void *arg_addr,
				  struct uburma_cmd_spec *spec)
{
	struct uburma_cmd_modify_jetty *arg = arg_addr;
	struct uburma_cmd_spec *s = spec;

	SPEC(s++, MODIFY_JETTY_OUT_UDATA, arg->udata);
}

static void
uburma_query_jetty_fill_spec_in(void *arg_addr,
				struct uburma_cmd_spec *spec)
{
	struct uburma_cmd_query_jetty *arg = arg_addr;
	struct uburma_cmd_spec *s = spec;

	SPEC(s++, QUERY_JETTY_IN_HANDLE, arg->in.handle);
}

static void
uburma_query_jetty_fill_spec_out(void *arg_addr,
				 struct uburma_cmd_spec *spec)
{
	struct uburma_cmd_query_jetty *arg = arg_addr;
	struct uburma_cmd_spec *s = spec;

	SPEC(s++, QUERY_JETTY_OUT_ID, arg->out.id);
	SPEC(s++, QUERY_JETTY_OUT_JETTY_FLAG, arg->out.jetty_flag);
	SPEC(s++, QUERY_JETTY_OUT_JFS_DEPTH, arg->out.jfs_depth);
	SPEC(s++, QUERY_JETTY_OUT_JFR_DEPTH, arg->out.jfr_depth);
	SPEC(s++, QUERY_JETTY_OUT_JFS_FLAG, arg->out.jfs_flag);
	SPEC(s++, QUERY_JETTY_OUT_JFR_FLAG, arg->out.jfr_flag);
	SPEC(s++, QUERY_JETTY_OUT_TRANS_MODE, arg->out.trans_mode);
	SPEC(s++, QUERY_JETTY_OUT_MAX_SEND_SGE,
	     arg->out.max_send_sge);
	SPEC(s++, QUERY_JETTY_OUT_MAX_SEND_RSGE,
	     arg->out.max_send_rsge);
	SPEC(s++, QUERY_JETTY_OUT_MAX_RECV_SGE,
	     arg->out.max_recv_sge);
	SPEC(s++, QUERY_JETTY_OUT_MAX_INLINE_DATA,
	     arg->out.max_inline_data);
	SPEC(s++, QUERY_JETTY_OUT_PRIORITY, arg->out.priority);
	SPEC(s++, QUERY_JETTY_OUT_RETRY_CNT, arg->out.retry_cnt);
	SPEC(s++, QUERY_JETTY_OUT_RNR_RETRY, arg->out.rnr_retry);
	SPEC(s++, QUERY_JETTY_OUT_ERR_TIMEOUT, arg->out.err_timeout);
	SPEC(s++, QUERY_JETTY_OUT_MIN_RNR_TIMER,
	     arg->out.min_rnr_timer);
	SPEC(s++, QUERY_JETTY_OUT_JFR_ID, arg->out.jfr_id);
	SPEC(s++, QUERY_JETTY_OUT_TOKEN, arg->out.token);
	SPEC(s++, QUERY_JETTY_OUT_RX_THRESHOLD,
	     arg->out.rx_threshold);
	SPEC(s++, QUERY_JETTY_OUT_STATE, arg->out.state);
}

static void
uburma_delete_jetty_fill_spec_in(void *arg_addr,
				 struct uburma_cmd_spec *spec)
{
	struct uburma_cmd_delete_jetty *arg = arg_addr;
	struct uburma_cmd_spec *s = spec;

	SPEC(s++, DELETE_JETTY_IN_HANDLE, arg->in.handle);
}

static void
uburma_delete_jetty_fill_spec_out(void *arg_addr,
				  struct uburma_cmd_spec *spec)
{
	struct uburma_cmd_delete_jetty *arg = arg_addr;
	struct uburma_cmd_spec *s = spec;

	SPEC(s++, DELETE_JETTY_OUT_ASYNC_EVENTS_REPORTED,
	     arg->out.async_events_reported);
}

static void
uburma_delete_jetty_batch_fill_spec_in(void *arg_addr,
				       struct uburma_cmd_spec *spec)
{
	struct uburma_cmd_delete_jetty_batch *arg = arg_addr;
	struct uburma_cmd_spec *s = spec;

	SPEC(s++, DELETE_JETTY_BATCH_IN_JETTY_COUNT,
	     arg->in.jetty_num);
	SPEC(s++, DELETE_JETTY_BATCH_IN_JETTY_PTR, arg->in.jetty_ptr);
}

static void
uburma_delete_jetty_batch_fill_spec_out(void *arg_addr,
					struct uburma_cmd_spec *spec)
{
	struct uburma_cmd_delete_jetty_batch *arg = arg_addr;
	struct uburma_cmd_spec *s = spec;

	SPEC(s++, DELETE_JETTY_BATCH_OUT_ASYNC_EVENTS_REPORTED,
	     arg->out.async_events_reported);
	SPEC(s++, DELETE_JETTY_BATCH_OUT_BAD_JETTY_INDEX,
	     arg->out.bad_jetty_index);
}

static void
uburma_import_jetty_fill_spec_in(void *arg_addr,
				 struct uburma_cmd_spec *spec)
{
	struct uburma_cmd_import_jetty *arg = arg_addr;
	struct uburma_cmd_spec *s = spec;

	SPEC(s++, IMPORT_JETTY_IN_EID, arg->in.eid);
	SPEC(s++, IMPORT_JETTY_IN_ID, arg->in.id);
	SPEC(s++, IMPORT_JETTY_IN_FLAG, arg->in.flag);
	SPEC(s++, IMPORT_JETTY_IN_TOKEN, arg->in.token);
	SPEC(s++, IMPORT_JETTY_IN_TRANS_MODE, arg->in.trans_mode);
	SPEC(s++, IMPORT_JETTY_IN_POLICY, arg->in.policy);
	SPEC(s++, IMPORT_JETTY_IN_TYPE, arg->in.type);
	SPEC(s++, IMPORT_JETTY_IN_TP_TYPE, arg->in.tp_type);
	SPEC(s++, IMPORT_JETTY_IN_UDATA, arg->udata);
}

static void
uburma_import_jetty_fill_spec_out(void *arg_addr,
				  struct uburma_cmd_spec *spec)
{
	struct uburma_cmd_import_jetty *arg = arg_addr;
	struct uburma_cmd_spec *s = spec;

	SPEC(s++, IMPORT_JETTY_OUT_TPN, arg->out.tpn);
	SPEC(s++, IMPORT_JETTY_OUT_HANDLE, arg->out.handle);
	SPEC(s++, IMPORT_JETTY_OUT_UDATA, arg->udata);
}

static void
uburma_unimport_jetty_fill_spec_in(void *arg_addr,
				   struct uburma_cmd_spec *spec)
{
	struct uburma_cmd_unimport_jetty *arg = arg_addr;
	struct uburma_cmd_spec *s = spec;

	SPEC(s++, UNIMPORT_JETTY_IN_HANDLE, arg->in.handle);
}

static void
uburma_advise_jetty_fill_spec_in(void *arg_addr,
				 struct uburma_cmd_spec *spec)
{
	struct uburma_cmd_advise_jetty *arg = arg_addr;
	struct uburma_cmd_spec *s = spec;

	SPEC(s++, ADVISE_JETTY_IN_JETTY_HANDLE, arg->in.jetty_handle);
	SPEC(s++, ADVISE_JETTY_IN_TJETTY_HANDLE,
	     arg->in.tjetty_handle);
	SPEC(s++, ADVISE_JETTY_IN_UDATA, arg->udata);
}

static void
uburma_unadvise_jetty_fill_spec_in(void *arg_addr,
				   struct uburma_cmd_spec *spec)
{
	struct uburma_cmd_unadvise_jetty *arg = arg_addr;
	struct uburma_cmd_spec *s = spec;

	SPEC(s++, UNADVISE_JETTY_IN_JETTY_HANDLE,
	     arg->in.jetty_handle);
	SPEC(s++, UNADVISE_JETTY_IN_TJETTY_HANDLE,
	     arg->in.tjetty_handle);
}

static void
uburma_bind_jetty_fill_spec_in(void *arg_addr,
			       struct uburma_cmd_spec *spec)
{
	struct uburma_cmd_bind_jetty *arg = arg_addr;
	struct uburma_cmd_spec *s = spec;

	SPEC(s++, BIND_JETTY_IN_JETTY_HANDLE, arg->in.jetty_handle);
	SPEC(s++, BIND_JETTY_IN_TJETTY_HANDLE, arg->in.tjetty_handle);
	SPEC(s++, BIND_JETTY_IN_UDATA, arg->udata);
}

static void
uburma_bind_jetty_fill_spec_out(void *arg_addr,
				struct uburma_cmd_spec *spec)
{
	struct uburma_cmd_bind_jetty *arg = arg_addr;
	struct uburma_cmd_spec *s = spec;

	SPEC(s++, BIND_JETTY_OUT_TPN, arg->out.tpn);
	SPEC(s++, BIND_JETTY_OUT_UDATA, arg->udata);
}

static void
uburma_create_jetty_grp_fill_spec_in(void *arg_addr,
				     struct uburma_cmd_spec *spec)
{
	struct uburma_cmd_create_jetty_grp *arg = arg_addr;
	struct uburma_cmd_spec *s = spec;

	SPEC(s++, CREATE_JETTY_GRP_IN_NAME, arg->in.name);
	SPEC(s++, CREATE_JETTY_GRP_IN_TOKEN, arg->in.token);
	SPEC(s++, CREATE_JETTY_GRP_IN_ID, arg->in.id);
	SPEC(s++, CREATE_JETTY_GRP_IN_POLICY, arg->in.policy);
	SPEC(s++, CREATE_JETTY_GRP_IN_FLAG, arg->in.flag);
	SPEC(s++, CREATE_JETTY_GRP_IN_URMA_JETTY_GRP,
	     arg->in.urma_jetty_grp);
	SPEC(s++, CREATE_JETTY_GRP_IN_UDATA, arg->udata);
}

static void
uburma_create_jetty_grp_fill_spec_out(void *arg_addr,
				      struct uburma_cmd_spec *spec)
{
	struct uburma_cmd_create_jetty_grp *arg = arg_addr;
	struct uburma_cmd_spec *s = spec;

	SPEC(s++, CREATE_JETTY_GRP_OUT_ID, arg->out.id);
	SPEC(s++, CREATE_JETTY_GRP_OUT_HANDLE, arg->out.handle);
	SPEC(s++, CREATE_JETTY_GRP_OUT_UDATA, arg->udata);
}

static void
uburma_delete_jetty_grp_fill_spec_in(void *arg_addr,
				     struct uburma_cmd_spec *spec)
{
	struct uburma_cmd_delete_jetty_grp *arg = arg_addr;
	struct uburma_cmd_spec *s = spec;

	SPEC(s++, DELETE_JETTY_GRP_IN_HANDLE, arg->in.handle);
}

static void
uburma_delete_jetty_grp_fill_spec_out(void *arg_addr,
				      struct uburma_cmd_spec *spec)
{
	struct uburma_cmd_delete_jetty_grp *arg = arg_addr;
	struct uburma_cmd_spec *s = spec;

	SPEC(s++, DELETE_JETTY_GRP_OUT_ASYNC_EVENTS_REPORTED,
	     arg->out.async_events_reported);
}

static void uburma_user_ctl_fill_spec_in(void *arg_addr,
					 struct uburma_cmd_spec *spec)
{
	struct uburma_cmd_user_ctl *arg = arg_addr;
	struct uburma_cmd_spec *s = spec;

	SPEC(s++, USER_CTL_IN_IN_ADDR, arg->in.addr);
	SPEC(s++, USER_CTL_IN_IN_LEN, arg->in.len);
	SPEC(s++, USER_CTL_IN_OPCODE, arg->in.opcode);
	SPEC(s++, USER_CTL_IN_OUT_ADDR, arg->out.addr);
	SPEC(s++, USER_CTL_IN_OUT_LEN, arg->out.len);
	SPEC(s++, USER_CTL_IN_UDATA, arg->udrv);
}

static void
uburma_get_eid_list_fill_spec_in(void *arg_addr,
				 struct uburma_cmd_spec *spec)
{
	struct uburma_cmd_get_eid_list *arg = arg_addr;
	struct uburma_cmd_spec *s = spec;

	SPEC(s++, GET_EID_LIST_IN_MAX_EID_CNT, arg->in.max_eid_cnt);
}

static void
uburma_get_eid_list_fill_spec_out(void *arg_addr,
				  struct uburma_cmd_spec *spec)
{
	struct uburma_cmd_get_eid_list *arg = arg_addr;
	struct uburma_cmd_spec *s = spec;

	SPEC(s++, GET_EID_LIST_OUT_EID_CNT, arg->out.eid_cnt);
	SPEC(s++, GET_EID_LIST_OUT_EID_LIST, arg->out.eid_list);
}

static void
uburma_get_net_addr_list_fill_spec_in(void *arg_addr,
				      struct uburma_cmd_spec *spec)
{
	struct uburma_cmd_get_net_addr_list *arg = arg_addr;
	struct uburma_cmd_spec *s = spec;

	SPEC(s++, GET_NET_ADDR_LIST_IN_MAX_NETADDR_CNT,
	     arg->in.max_netaddr_cnt);
}

static void
uburma_get_net_addr_list_fill_spec_out(void *arg_addr,
				       struct uburma_cmd_spec *spec)
{
	struct uburma_cmd_get_net_addr_list *arg = arg_addr;
	struct uburma_cmd_spec *s = spec;
	uint64_t netaddr_size =
		sizeof(struct uburma_cmd_net_addr_info);

	SPEC(s++, GET_NET_ADDR_LIST_OUT_NETADDR_CNT,
	     arg->out.netaddr_cnt);
	fill_spec(s++, GET_NET_ADDR_LIST_OUT_NETADDR_LIST,
		  netaddr_size, arg->out.len / netaddr_size,
		  netaddr_size, arg->out.addr);
}

static void
uburma_modify_tp_fill_spec_in(void *arg_addr,
			      struct uburma_cmd_spec *spec)
{
	struct uburma_cmd_modify_tp *arg = arg_addr;
	struct uburma_cmd_spec *s = spec;

	SPEC(s++, MODIFY_TP_IN_TPN, arg->in.tpn);
	SPEC(s++, MODIFY_TP_IN_TP_CFG_FLAG, arg->in.tp_cfg.flag);
	SPEC(s++, MODIFY_TP_IN_TP_CFG_TRANS_MODE,
	     arg->in.tp_cfg.trans_mode);
	SPEC(s++, MODIFY_TP_IN_TP_CFG_RETRY_NUM,
	     arg->in.tp_cfg.retry_num);
	SPEC(s++, MODIFY_TP_IN_TP_CFG_RETRY_FACTOR,
	     arg->in.tp_cfg.retry_factor);
	SPEC(s++, MODIFY_TP_IN_TP_CFG_ACK_TIMEOUT,
	     arg->in.tp_cfg.ack_timeout);
	SPEC(s++, MODIFY_TP_IN_TP_CFG_DSCP, arg->in.tp_cfg.dscp);
	SPEC(s++, MODIFY_TP_IN_TP_CFG_OOR_CNT,
	     arg->in.tp_cfg.oor_cnt);
	SPEC(s++, MODIFY_TP_IN_ATTR_FLAG, arg->in.attr.flag);
	SPEC(s++, MODIFY_TP_IN_ATTR_PEER_TPN, arg->in.attr.peer_tpn);
	SPEC(s++, MODIFY_TP_IN_ATTR_STATE, arg->in.attr.state);
	SPEC(s++, MODIFY_TP_IN_ATTR_TX_PSN, arg->in.attr.tx_psn);
	SPEC(s++, MODIFY_TP_IN_ATTR_RX_PSN, arg->in.attr.rx_psn);
	SPEC(s++, MODIFY_TP_IN_ATTR_MTU, arg->in.attr.mtu);
	SPEC(s++, MODIFY_TP_IN_ATTR_CC_PATTERN_IDX,
	     arg->in.attr.cc_pattern_idx);
	SPEC(s++, MODIFY_TP_IN_ATTR_OOS_CNT, arg->in.attr.oos_cnt);
	SPEC(s++, MODIFY_TP_IN_ATTR_LOCAL_NET_ADDR_IDX,
	     arg->in.attr.local_net_addr_idx);
	SPEC(s++, MODIFY_TP_IN_ATTR_PEER_NET_ADDR,
	     arg->in.attr.peer_net_addr);
	SPEC(s++, MODIFY_TP_IN_ATTR_DATA_UDP_START,
	     arg->in.attr.data_udp_start);
	SPEC(s++, MODIFY_TP_IN_ATTR_ACK_UDP_START,
	     arg->in.attr.ack_udp_start);
	SPEC(s++, MODIFY_TP_IN_ATTR_UDP_RANGE,
	     arg->in.attr.udp_range);
	SPEC(s++, MODIFY_TP_IN_ATTR_HOP_LIMIT,
	     arg->in.attr.hop_limit);
	SPEC(s++, MODIFY_TP_IN_ATTR_FLOW_LABEL,
	     arg->in.attr.flow_label);
	SPEC(s++, MODIFY_TP_IN_ATTR_PORT_ID, arg->in.attr.port_id);
	SPEC(s++, MODIFY_TP_IN_ATTR_MN, arg->in.attr.mn);
	SPEC(s++, MODIFY_TP_IN_ATTR_PEER_TRANS_TYPE,
	     arg->in.attr.peer_trans_type);
	SPEC(s++, MODIFY_TP_IN_MASK, arg->in.mask);
}

static void
uburma_query_device_fill_spec_in(void *arg_addr,
				 struct uburma_cmd_spec *spec)
{
	struct uburma_cmd_query_device_attr *arg = arg_addr;
	struct uburma_cmd_spec *s = spec;

	SPEC(s++, QUERY_DEVICE_IN_DEV_NAME, arg->in.dev_name);
}

static void
uburma_query_device_fill_spec_out(void *arg_addr,
				  struct uburma_cmd_spec *spec)
{
	struct uburma_cmd_query_device_attr *arg = arg_addr;
	struct uburma_cmd_spec *s = spec;

	SPEC(s++, QUERY_DEVICE_OUT_GUID, arg->out.attr.guid);
	SPEC(s++, QUERY_DEVICE_OUT_DEV_CAP_FEATURE,
	     arg->out.attr.dev_cap.feature);
	SPEC(s++, QUERY_DEVICE_OUT_DEV_CAP_MAX_JFC,
	     arg->out.attr.dev_cap.max_jfc);
	SPEC(s++, QUERY_DEVICE_OUT_DEV_CAP_MAX_JFS,
	     arg->out.attr.dev_cap.max_jfs);
	SPEC(s++, QUERY_DEVICE_OUT_DEV_CAP_MAX_JFR,
	     arg->out.attr.dev_cap.max_jfr);
	SPEC(s++, QUERY_DEVICE_OUT_DEV_CAP_MAX_JETTY,
	     arg->out.attr.dev_cap.max_jetty);
	SPEC(s++, QUERY_DEVICE_OUT_DEV_CAP_MAX_JETTY_GRP,
	     arg->out.attr.dev_cap.max_jetty_grp);
	SPEC(s++, QUERY_DEVICE_OUT_DEV_CAP_MAX_JETTY_IN_JETTY_GRP,
	     arg->out.attr.dev_cap.max_jetty_in_jetty_grp);
	SPEC(s++, QUERY_DEVICE_OUT_DEV_CAP_MAX_JFC_DEPTH,
	     arg->out.attr.dev_cap.max_jfc_depth);
	SPEC(s++, QUERY_DEVICE_OUT_DEV_CAP_MAX_JFS_DEPTH,
	     arg->out.attr.dev_cap.max_jfs_depth);
	SPEC(s++, QUERY_DEVICE_OUT_DEV_CAP_MAX_JFR_DEPTH,
	     arg->out.attr.dev_cap.max_jfr_depth);
	SPEC(s++, QUERY_DEVICE_OUT_DEV_CAP_MAX_JFS_INLINE_LEN,
	     arg->out.attr.dev_cap.max_jfs_inline_len);
	SPEC(s++, QUERY_DEVICE_OUT_DEV_CAP_MAX_JFS_SGE,
	     arg->out.attr.dev_cap.max_jfs_sge);
	SPEC(s++, QUERY_DEVICE_OUT_DEV_CAP_MAX_JFS_RSGE,
	     arg->out.attr.dev_cap.max_jfs_rsge);
	SPEC(s++, QUERY_DEVICE_OUT_DEV_CAP_MAX_JFR_SGE,
	     arg->out.attr.dev_cap.max_jfr_sge);
	SPEC(s++, QUERY_DEVICE_OUT_DEV_CAP_MAX_MSG_SIZE,
	     arg->out.attr.dev_cap.max_msg_size);
	SPEC(s++, QUERY_DEVICE_OUT_DEV_CAP_MAX_READ_SIZE,
	     arg->out.attr.dev_cap.max_read_size);
	SPEC(s++, QUERY_DEVICE_OUT_DEV_CAP_MAX_WRITE_SIZE,
	     arg->out.attr.dev_cap.max_write_size);
	SPEC(s++, QUERY_DEVICE_OUT_DEV_CAP_MAX_CAS_SIZE,
	     arg->out.attr.dev_cap.max_cas_size);
	SPEC(s++, QUERY_DEVICE_OUT_DEV_CAP_MAX_SWAP_SIZE,
	     arg->out.attr.dev_cap.max_swap_size);
	SPEC(s++, QUERY_DEVICE_OUT_DEV_CAP_MAX_FETCH_AND_ADD_SIZE,
	     arg->out.attr.dev_cap.max_fetch_and_add_size);
	SPEC(s++, QUERY_DEVICE_OUT_DEV_CAP_MAX_FETCH_AND_SUB_SIZE,
	     arg->out.attr.dev_cap.max_fetch_and_sub_size);
	SPEC(s++, QUERY_DEVICE_OUT_DEV_CAP_MAX_FETCH_AND_AND_SIZE,
	     arg->out.attr.dev_cap.max_fetch_and_and_size);
	SPEC(s++, QUERY_DEVICE_OUT_DEV_CAP_MAX_FETCH_AND_OR_SIZE,
	     arg->out.attr.dev_cap.max_fetch_and_or_size);
	SPEC(s++, QUERY_DEVICE_OUT_DEV_CAP_MAX_FETCH_AND_XOR_SIZE,
	     arg->out.attr.dev_cap.max_fetch_and_xor_size);
	SPEC(s++, QUERY_DEVICE_OUT_DEV_CAP_ATOMIC_FEAT,
	     arg->out.attr.dev_cap.atomic_feat);
	SPEC(s++, QUERY_DEVICE_OUT_DEV_CAP_TRANS_MODE,
	     arg->out.attr.dev_cap.trans_mode);
	SPEC(s++, QUERY_DEVICE_OUT_DEV_CAP_CONGESTION_CTRL_ALG,
	     arg->out.attr.dev_cap.congestion_ctrl_alg);
	SPEC(s++, QUERY_DEVICE_OUT_DEV_CAP_CEQ_CNT,
	     arg->out.attr.dev_cap.ceq_cnt);
	SPEC(s++, QUERY_DEVICE_OUT_DEV_CAP_MAX_TP_IN_TPG,
	     arg->out.attr.dev_cap.max_tp_in_tpg);
	SPEC(s++, QUERY_DEVICE_OUT_DEV_CAP_MAX_EID_CNT,
	     arg->out.attr.dev_cap.max_eid_cnt);
	SPEC(s++, QUERY_DEVICE_OUT_DEV_CAP_PAGE_SIZE_CAP,
	     arg->out.attr.dev_cap.page_size_cap);
	SPEC(s++, QUERY_DEVICE_OUT_DEV_CAP_MAX_OOR_CNT,
	     arg->out.attr.dev_cap.max_oor_cnt);
	SPEC(s++, QUERY_DEVICE_OUT_DEV_CAP_MN,
	     arg->out.attr.dev_cap.mn);
	SPEC(s++, QUERY_DEVICE_OUT_DEV_CAP_MAX_NETADDR_CN,
	     arg->out.attr.dev_cap.max_netaddr_cnt);
	SPEC(s++, QUERY_DEVICE_OUT_PORT_CNT, arg->out.attr.port_cnt);
	SPEC(s++, QUERY_DEVICE_OUT_RESERVED_JETTY_ID_MIN,
	     arg->out.attr.reserved_jetty_id_min);
	SPEC(s++, QUERY_DEVICE_OUT_RESERVED_JETTY_ID_MAX,
	     arg->out.attr.reserved_jetty_id_max);

	SPEC_ARRAY(s++, QUERY_DEVICE_OUT_PORT_ATTR_MAX_MTU,
		   arg->out.attr.port_attr, max_mtu);
	SPEC_ARRAY(s++, QUERY_DEVICE_OUT_PORT_ATTR_STATE,
		   arg->out.attr.port_attr, state);
	SPEC_ARRAY(s++, QUERY_DEVICE_OUT_PORT_ATTR_ACTIVE_WIDTH,
		   arg->out.attr.port_attr, active_width);
	SPEC_ARRAY(s++, QUERY_DEVICE_OUT_PORT_ATTR_ACTIVE_SPEED,
		   arg->out.attr.port_attr, active_speed);
	SPEC_ARRAY(s++, QUERY_DEVICE_OUT_PORT_ATTR_ACTIVE_MTU,
		   arg->out.attr.port_attr, active_mtu);
	SPEC(s++, QUERY_DEVICE_OUT_DEV_CAP_RM_ORDER_CAP,
			arg->out.attr.dev_cap.rm_order_cap.value);
	SPEC(s++, QUERY_DEVICE_OUT_DEV_CAP_RC_ORDER_CAP,
			arg->out.attr.dev_cap.rc_order_cap.value);
	SPEC(s++, QUERY_DEVICE_OUT_DEV_CAP_RM_TP_CAP,
			arg->out.attr.dev_cap.rm_tp_cap.value);
	SPEC(s++, QUERY_DEVICE_OUT_DEV_CAP_RC_TP_CAP,
		arg->out.attr.dev_cap.rc_tp_cap.value);
	SPEC(s++, QUERY_DEVICE_OUT_DEV_CAP_UM_TP_CAP,
		arg->out.attr.dev_cap.um_tp_cap.value);
	SPEC(s++, QUERY_DEVICE_OUT_DEV_CAP_TP_FEATURE,
		arg->out.attr.dev_cap.tp_feature.value);
	SPEC(s++, QUERY_DEVICE_OUT_DEV_CAP_PRIORITY_INFO,
		arg->out.attr.dev_cap.priority_info);
}

static void
uburma_import_jetty_async_fill_spec_in(void *arg_addr,
				       struct uburma_cmd_spec *spec)
{
	struct uburma_cmd_import_jetty_async *arg = arg_addr;
	struct uburma_cmd_spec *s = spec;

	SPEC(s++, IMPORT_JETTY_ASYNC_IN_EID, arg->in.eid);
	SPEC(s++, IMPORT_JETTY_ASYNC_IN_ID, arg->in.id);
	SPEC(s++, IMPORT_JETTY_ASYNC_IN_FLAG, arg->in.flag);
	SPEC(s++, IMPORT_JETTY_ASYNC_IN_TOKEN, arg->in.token);
	SPEC(s++, IMPORT_JETTY_ASYNC_IN_TRANS_MODE,
	     arg->in.trans_mode);
	SPEC(s++, IMPORT_JETTY_ASYNC_IN_POLICY, arg->in.policy);
	SPEC(s++, IMPORT_JETTY_ASYNC_IN_TYPE, arg->in.type);
	SPEC(s++, IMPORT_JETTY_ASYNC_IN_URMA_TJETTY,
	     arg->in.urma_tjetty);
	SPEC(s++, IMPORT_JETTY_ASYNC_IN_USER_CTX, arg->in.user_ctx);
	SPEC(s++, IMPORT_JETTY_ASYNC_IN_FD, arg->in.fd);
	SPEC(s++, IMPORT_JETTY_ASYNC_IN_TIMEOUT, arg->in.timeout);
	SPEC(s++, IMPORT_JETTY_ASYNC_IN_UDATA, arg->udata);
}

static void
uburma_import_jetty_async_fill_spec_out(void *arg_addr,
					struct uburma_cmd_spec *spec)
{
	struct uburma_cmd_import_jetty_async *arg = arg_addr;
	struct uburma_cmd_spec *s = spec;

	SPEC(s++, IMPORT_JETTY_ASYNC_OUT_TPN, arg->out.tpn);
	SPEC(s++, IMPORT_JETTY_ASYNC_OUT_HANDLE, arg->out.handle);
	SPEC(s++, IMPORT_JETTY_ASYNC_OUT_UDATA, arg->udata);
}

static void
uburma_unimport_jetty_async_fill_spec_in(void *arg_addr,
					 struct uburma_cmd_spec *spec)
{
	struct uburma_cmd_unimport_jetty_async *arg = arg_addr;
	struct uburma_cmd_spec *s = spec;

	SPEC(s++, UNIMPORT_JETTY_ASYNC_IN_HANDLE, arg->in.handle);
}

static void
uburma_bind_jetty_async_fill_spec_in(void *arg_addr,
				     struct uburma_cmd_spec *spec)
{
	struct uburma_cmd_bind_jetty_async *arg = arg_addr;
	struct uburma_cmd_spec *s = spec;

	SPEC(s++, BIND_JETTY_ASYNC_IN_JETTY_HANDLE,
	     arg->in.jetty_handle);
	SPEC(s++, BIND_JETTY_ASYNC_IN_TJETTY_HANDLE,
	     arg->in.tjetty_handle);
	SPEC(s++, BIND_JETTY_ASYNC_IN_URMA_TJETTY,
	     arg->in.urma_tjetty);
	SPEC(s++, BIND_JETTY_ASYNC_IN_URMA_JETTY, arg->in.urma_jetty);
	SPEC(s++, BIND_JETTY_ASYNC_IN_FD, arg->in.fd);
	SPEC(s++, BIND_JETTY_ASYNC_IN_USER_CTX, arg->in.user_ctx);
	SPEC(s++, BIND_JETTY_ASYNC_IN_TIMEOUT, arg->in.timeout);
	SPEC(s++, BIND_JETTY_ASYNC_IN_UDATA, arg->udata);
}

static void
uburma_bind_jetty_async_fill_spec_out(void *arg_addr,
				      struct uburma_cmd_spec *spec)
{
	struct uburma_cmd_bind_jetty_async *arg = arg_addr;
	struct uburma_cmd_spec *s = spec;

	SPEC(s++, BIND_JETTY_ASYNC_OUT_TPN, arg->out.tpn);
	SPEC(s++, BIND_JETTY_ASYNC_OUT_UDATA, arg->udata);
}

static void
uburma_unbind_jetty_async_fill_spec_in(void *arg_addr,
				       struct uburma_cmd_spec *spec)
{
	struct uburma_cmd_unbind_jetty_async *arg = arg_addr;
	struct uburma_cmd_spec *s = spec;

	SPEC(s++, UNBIND_JETTY_ASYNC_IN_JETTY_HANDLE,
	     arg->in.jetty_handle);
	SPEC(s++, UNBIND_JETTY_ASYNC_IN_TJETTY_HANDLE,
	     arg->in.tjetty_handle);
}

static void
uburma_create_notifier_fill_spec_out(void *arg_addr,
				     struct uburma_cmd_spec *spec)
{
	struct uburma_cmd_create_notifier *arg = arg_addr;
	struct uburma_cmd_spec *s = spec;

	SPEC(s++, CREATE_NOTIFIER_OUT_FD, arg->out.fd);
}

static void
uburma_get_tp_list_fill_spec_in(void *arg_addr,
				struct uburma_cmd_spec *spec)
{
	struct uburma_cmd_get_tp_list *arg = arg_addr;
	struct uburma_cmd_spec *s = spec;

	SPEC(s++, GET_TP_LIST_IN_FLAG, arg->in.flag);
	SPEC(s++, GET_TP_LIST_IN_TRANS_MODE, arg->in.trans_mode);
	SPEC(s++, GET_TP_LIST_IN_LOCAL_EID, arg->in.local_eid);
	SPEC(s++, GET_TP_LIST_IN_PEER_EID, arg->in.peer_eid);
	SPEC(s++, GET_TP_LIST_IN_TP_CNT, arg->in.tp_cnt);
	SPEC(s++, GET_TP_LIST_IN_UDATA, arg->udata);
}

static void
uburma_get_tp_list_fill_spec_out(void *arg_addr,
				 struct uburma_cmd_spec *spec)
{
	struct uburma_cmd_get_tp_list *arg = arg_addr;
	struct uburma_cmd_spec *s = spec;

	SPEC(s++, GET_TP_LIST_OUT_TP_CNT, arg->out.tp_cnt);
	SPEC(s++, GET_TP_LIST_OUT_TP_HANDLE, arg->out.tp_handle);
	SPEC(s++, GET_TP_LIST_OUT_UDATA, arg->udata);
}

static void
uburma_import_jetty_ex_fill_spec_in(void *arg_addr,
				    struct uburma_cmd_spec *spec)
{
	struct uburma_cmd_import_jetty_ex *arg = arg_addr;
	struct uburma_cmd_spec *s = spec;

	SPEC(s++, IMPORT_JETTY_EX_IN_EID, arg->in.eid);
	SPEC(s++, IMPORT_JETTY_EX_IN_ID, arg->in.id);
	SPEC(s++, IMPORT_JETTY_EX_IN_FLAG, arg->in.flag);
	SPEC(s++, IMPORT_JETTY_EX_IN_TOKEN, arg->in.token);
	SPEC(s++, IMPORT_JETTY_EX_IN_TRANS_MODE, arg->in.trans_mode);
	SPEC(s++, IMPORT_JETTY_EX_IN_POLICY, arg->in.policy);
	SPEC(s++, IMPORT_JETTY_EX_IN_TYPE, arg->in.type);
	SPEC(s++, IMPORT_JETTY_EX_IN_TP_TYPE, arg->in.tp_type);
	SPEC(s++, IMPORT_JETTY_EX_IN_TP_HANDLE, arg->in.tp_handle);
	SPEC(s++, IMPORT_JETTY_EX_IN_PEER_TP_HANDLE,
	     arg->in.peer_tp_handle);
	SPEC(s++, IMPORT_JETTY_EX_IN_TAG, arg->in.tag);
	SPEC(s++, IMPORT_JETTY_EX_IN_TX_PSN, arg->in.tx_psn);
	SPEC(s++, IMPORT_JETTY_EX_IN_RX_PSN, arg->in.rx_psn);
	SPEC(s++, IMPORT_JETTY_EX_IN_UDATA, arg->udata);
}

static void
uburma_import_jetty_ex_fill_spec_out(void *arg_addr,
				     struct uburma_cmd_spec *spec)
{
	struct uburma_cmd_import_jetty_ex *arg = arg_addr;
	struct uburma_cmd_spec *s = spec;

	SPEC(s++, IMPORT_JETTY_EX_OUT_TPN, arg->out.tpn);
	SPEC(s++, IMPORT_JETTY_EX_OUT_HANDLE, arg->out.handle);
	SPEC(s++, IMPORT_JETTY_EX_OUT_UDATA, arg->udata);
}

static void
uburma_import_jfr_ex_fill_spec_in(void *arg_addr,
				  struct uburma_cmd_spec *spec)
{
	struct uburma_cmd_import_jfr_ex *arg = arg_addr;
	struct uburma_cmd_spec *s = spec;

	SPEC(s++, IMPORT_JFR_EX_IN_EID, arg->in.eid);
	SPEC(s++, IMPORT_JFR_EX_IN_ID, arg->in.id);
	SPEC(s++, IMPORT_JFR_EX_IN_FLAG, arg->in.flag);
	SPEC(s++, IMPORT_JFR_EX_IN_TOKEN, arg->in.token);
	SPEC(s++, IMPORT_JFR_EX_IN_TRANS_MODE, arg->in.trans_mode);
	SPEC(s++, IMPORT_JFR_EX_IN_TP_TYPE, arg->in.tp_type);
	SPEC(s++, IMPORT_JFR_EX_IN_TP_HANDLE, arg->in.tp_handle);
	SPEC(s++, IMPORT_JFR_EX_IN_PEER_TP_HANDLE,
	     arg->in.peer_tp_handle);
	SPEC(s++, IMPORT_JFR_EX_IN_TAG, arg->in.tag);
	SPEC(s++, IMPORT_JFR_EX_IN_TX_PSN, arg->in.tx_psn);
	SPEC(s++, IMPORT_JFR_EX_IN_RX_PSN, arg->in.rx_psn);
	SPEC(s++, IMPORT_JFR_EX_IN_UDATA, arg->udata);
}

static void
uburma_import_jfr_ex_fill_spec_out(void *arg_addr,
				   struct uburma_cmd_spec *spec)
{
	struct uburma_cmd_import_jfr_ex *arg = arg_addr;
	struct uburma_cmd_spec *s = spec;

	SPEC(s++, IMPORT_JFR_EX_OUT_TPN, arg->out.tpn);
	SPEC(s++, IMPORT_JFR_EX_OUT_HANDLE, arg->out.handle);
	SPEC(s++, IMPORT_JFR_EX_OUT_UDATA, arg->udata);
}

static void
uburma_bind_jetty_ex_fill_spec_in(void *arg_addr,
				  struct uburma_cmd_spec *spec)
{
	struct uburma_cmd_bind_jetty_ex *arg = arg_addr;
	struct uburma_cmd_spec *s = spec;

	SPEC(s++, BIND_JETTY_EX_IN_JETTY_HANDLE,
	     arg->in.jetty_handle);
	SPEC(s++, BIND_JETTY_EX_IN_TJETTY_HANDLE,
	     arg->in.tjetty_handle);
	SPEC(s++, BIND_JETTY_EX_IN_TP_HANDLE, arg->in.tp_handle);
	SPEC(s++, BIND_JETTY_EX_IN_PEER_TP_HANDLE,
	     arg->in.peer_tp_handle);
	SPEC(s++, BIND_JETTY_EX_IN_TAG, arg->in.tag);
	SPEC(s++, BIND_JETTY_EX_IN_TX_PSN, arg->in.tx_psn);
	SPEC(s++, BIND_JETTY_EX_IN_RX_PSN, arg->in.rx_psn);
	SPEC(s++, BIND_JETTY_EX_IN_UDATA, arg->udata);
}

static void
uburma_bind_jetty_ex_fill_spec_out(void *arg_addr,
				   struct uburma_cmd_spec *spec)
{
	struct uburma_cmd_bind_jetty_ex *arg = arg_addr;
	struct uburma_cmd_spec *s = spec;

	SPEC(s++, BIND_JETTY_EX_OUT_TPN, arg->out.tpn);
	SPEC(s++, BIND_JETTY_EX_OUT_UDATA, arg->udata);
}

static void
uburma_set_tp_attr_fill_spec_in(void *arg_addr,
				struct uburma_cmd_spec *spec)
{
	struct uburma_cmd_set_tp_attr *arg = arg_addr;
	struct uburma_cmd_spec *s = spec;

	SPEC(s++, SET_TP_ATTR_IN_TP_HANLDE, arg->in.tp_handle);
	SPEC(s++, SET_TP_ATTR_IN_TP_ATTR_CNT, arg->in.tp_attr_cnt);
	SPEC(s++, SET_TP_ATTR_IN_TP_ATTR_BITMAP,
	     arg->in.tp_attr_bitmap);
	SPEC(s++, SET_TP_ATTR_IN_TP_ATTR, arg->in.tp_attr);
	SPEC(s++, SET_TP_ATTR_IN_UDATA, arg->udata);
}

static void
uburma_set_tp_attr_fill_spec_out(void *arg_addr,
				 struct uburma_cmd_spec *spec)
{
	struct uburma_cmd_set_tp_attr *arg = arg_addr;
	struct uburma_cmd_spec *s = spec;

	SPEC(s++, SET_TP_ATTR_OUT_UDATA, arg->udata);
}

static void uburma_alloc_jetty_fill_spec_in(void *arg_addr, struct uburma_cmd_spec *spec)
{
	struct uburma_cmd_alloc_jetty *arg = arg_addr;
	struct uburma_cmd_spec *s = spec;

	SPEC(s++, ALLOC_JETTY_IN_CFG, arg->create_jetty);
}

static void uburma_alloc_jetty_fill_spec_out(void *arg_addr, struct uburma_cmd_spec *spec)
{
	struct uburma_cmd_alloc_jetty *arg = arg_addr;
	struct uburma_cmd_spec *s = spec;

	SPEC(s++, ALLOC_JETTY_OUT_CFG, arg->create_jetty);
}

static void uburma_free_jetty_fill_spec_in(void *arg_addr, struct uburma_cmd_spec *spec)
{
	struct uburma_cmd_free_jetty *arg = arg_addr;
	struct uburma_cmd_spec *s = spec;

	SPEC(s++, FREE_JETTY_IN_HANDLE, arg->in.handle);
	SPEC(s++, FREE_JETTY_IN_UDATA, arg->udata);
}

static void uburma_free_jetty_fill_spec_out(void *arg_addr, struct uburma_cmd_spec *spec)
{
	struct uburma_cmd_free_jetty *arg = arg_addr;
	struct uburma_cmd_spec *s = spec;

	SPEC(s++, FREE_JETTY_OUT_ASYNC_EVENTS_REPORTED, arg->out.async_events_reported);
	SPEC(s++, FREE_JETTY_OUT_UDATA, arg->udata);
}

static void uburma_set_jetty_opt_fill_spec_in(void *arg_addr, struct uburma_cmd_spec *spec)
{
	struct uburma_cmd_set_jetty_opt *arg = arg_addr;
	struct uburma_cmd_spec *s = spec;

	SPEC(s++, SET_JETTY_OPT_IN_HANDLE, arg->in.handle);
	SPEC(s++, SET_JETTY_OPT_IN_OPT, arg->in.opt);
	SPEC(s++, SET_JETTY_OPT_IN_BUF, arg->in.buf);
	SPEC(s++, SET_JETTY_OPT_IN_LEN, arg->in.len);
	SPEC(s++, SET_JETTY_OPT_IN_UDATA, arg->udata);
}

static void uburma_set_jetty_opt_fill_spec_out(void *arg_addr, struct uburma_cmd_spec *spec)
{
	struct uburma_cmd_set_jetty_opt *arg = arg_addr;
	struct uburma_cmd_spec *s = spec;

	SPEC(s++, SET_JETTY_OPT_OUT_UDATA, arg->udata);
}

static void uburma_get_jetty_opt_fill_spec_in(void *arg_addr, struct uburma_cmd_spec *spec)
{
	struct uburma_cmd_get_jetty_opt *arg = arg_addr;
	struct uburma_cmd_spec *s = spec;

	SPEC(s++, GET_JETTY_OPT_IN_HANDLE, arg->in.handle);
	SPEC(s++, GET_JETTY_OPT_IN_OPT, arg->in.opt);
	SPEC(s++, GET_JETTY_OPT_IN_BUF, arg->in.buf);
	SPEC(s++, GET_JETTY_OPT_IN_LEN, arg->in.len);
	SPEC(s++, GET_JETTY_OPT_IN_UDATA, arg->udata);
}

static void uburma_get_jetty_opt_fill_spec_out(void *arg_addr, struct uburma_cmd_spec *spec)
{
	struct uburma_cmd_get_jetty_opt *arg = arg_addr;
	struct uburma_cmd_spec *s = spec;

	SPEC(s++, GET_JETTY_OPT_OUT_BUF, arg->out.buf);
	SPEC(s++, GET_JETTY_OPT_OUT_LEN, arg->out.len);
	SPEC(s++, GET_JETTY_OPT_OUT_UDATA, arg->udata);
}

static void uburma_active_jetty_fill_spec_in(void *arg_addr, struct uburma_cmd_spec *spec)
{
	struct uburma_cmd_active_jetty *arg = arg_addr;
	struct uburma_cmd_spec *s = spec;

	SPEC(s++, ACTIVE_JETTY_IN_FLAG, arg->in.flag);
	SPEC(s++, ACTIVE_JETTY_IN_HANDLE, arg->in.handle);
	SPEC(s++, ACTIVE_JETTY_IN_SEND_JFC_HANDLE, arg->in.send_jfc_handle);
	SPEC(s++, ACTIVE_JETTY_IN_RECV_JFC_HANDLE, arg->in.recv_jfc_handle);
	SPEC(s++, ACTIVE_JETTY_IN_URMA_JETTY, arg->in.urma_jetty);
	SPEC(s++, ACTIVE_JETTY_IN_JETTY_OPT, arg->in.jetty_opt);
	SPEC(s++, ACTIVE_JETTY_IN_UDATA, arg->udata);
}

static void uburma_active_jetty_fill_spec_out(void *arg_addr, struct uburma_cmd_spec *spec)
{
	struct uburma_cmd_active_jetty *arg = arg_addr;
	struct uburma_cmd_spec *s = spec;

	SPEC(s++, ACTIVE_JETTY_OUT_JETTY_ID, arg->out.jetty_id);
	SPEC(s++, ACTIVE_JETTY_OUT_UDATA, arg->udata);
}

static void uburma_deactive_jetty_fill_spec_in(void *arg_addr, struct uburma_cmd_spec *spec)
{
	struct uburma_cmd_deactive_jetty *arg = arg_addr;
	struct uburma_cmd_spec *s = spec;

	SPEC(s++, DEACTIVE_JETTY_IN_HANDLE, arg->in.handle);
	SPEC(s++, DEACTIVE_JETTY_IN_UDATA, arg->udata);
}

static void uburma_deactive_jetty_fill_spec_out(void *arg_addr, struct uburma_cmd_spec *spec)
{
	struct uburma_cmd_deactive_jetty *arg = arg_addr;
	struct uburma_cmd_spec *s = spec;

	SPEC(s++, DEACTIVE_JETTY_OUT_UDATA, arg->udata);
}

static void uburma_get_tp_attr_fill_spec_in(void *arg_addr, struct uburma_cmd_spec *spec)
{
	struct uburma_cmd_get_tp_attr *arg = arg_addr;
	struct uburma_cmd_spec *s = spec;

	SPEC(s++, GET_TP_ATTR_IN_TP_HANDLE, arg->in.tp_handle);
	SPEC(s++, GET_TP_ATTR_IN_UDATA, arg->udata);
}

static void
uburma_get_tp_attr_fill_spec_out(void *arg_addr,
				 struct uburma_cmd_spec *spec)
{
	struct uburma_cmd_get_tp_attr *arg = arg_addr;
	struct uburma_cmd_spec *s = spec;

	SPEC(s++, GET_TP_ATTR_OUT_TP_ATTR_CNT, arg->out.tp_attr_cnt);
	SPEC(s++, GET_TP_ATTR_OUT_TP_ATTR_BITMAP,
	     arg->out.tp_attr_bitmap);
	SPEC(s++, GET_TP_ATTR_OUT_TP_ATTR, arg->out.tp_attr);
	SPEC(s++, GET_TP_ATTR_OUT_UDATA, arg->udata);
}

static void
uburma_exchange_tp_info_fill_spec_in(void *arg_addr,
				     struct uburma_cmd_spec *spec)
{
	struct uburma_cmd_exchange_tp_info *arg = arg_addr;
	struct uburma_cmd_spec *s = spec;

	SPEC(s++, EXCHANGE_TP_INFO_IN_FLAG, arg->in.get_tp_cfg.flag);
	SPEC(s++, EXCHANGE_TP_INFO_IN_TRANS_MODE,
	     arg->in.get_tp_cfg.trans_mode);
	SPEC(s++, EXCHANGE_TP_INFO_IN_LOCAL_EID,
	     arg->in.get_tp_cfg.local_eid);
	SPEC(s++, EXCHANGE_TP_INFO_IN_PEER_EID,
	     arg->in.get_tp_cfg.peer_eid);
	SPEC(s++, EXCHANGE_TP_INFO_IN_TP_HANDLE, arg->in.tp_handle);
	SPEC(s++, EXCHANGE_TP_INFO_IN_TX_PSN, arg->in.tx_psn);
}

static void
uburma_exchange_tp_info_fill_spec_out(void *arg_addr,
				      struct uburma_cmd_spec *spec)
{
	struct uburma_cmd_exchange_tp_info *arg = arg_addr;
	struct uburma_cmd_spec *s = spec;

	SPEC(s++, EXCHANGE_TP_INFO_OUT_PEER_TP_HANDLE,
	     arg->out.peer_tp_handle);
	SPEC(s++, EXCHANGE_TP_INFO_OUT_RX_PSN, arg->out.rx_psn);
}

static void
uburma_get_eid_by_ip_fill_spec_in(void *arg_addr,
					 struct uburma_cmd_spec *spec)
{
	struct uburma_cmd_get_eid_by_ip *arg = arg_addr;
	struct uburma_cmd_spec *s = spec;

	SPEC(s++, GET_EID_BY_IP_INFO_IN_NET_ADDR, arg->in.net_addr);
}

static void
uburma_get_eid_by_ip_fill_spec_out(void *arg_addr,
					 struct uburma_cmd_spec *spec)
{
	struct uburma_cmd_get_eid_by_ip *arg = arg_addr;
	struct uburma_cmd_spec *s = spec;

	SPEC(s++, GET_EID_BY_IP_INFO_OUT_EID, arg->out.eid);
}

static void
uburma_get_ip_by_eid_fill_spec_in(void *arg_addr,
					 struct uburma_cmd_spec *spec)
{
	struct uburma_cmd_get_ip_by_eid *arg = arg_addr;
	struct uburma_cmd_spec *s = spec;

	SPEC(s++, GET_IP_BY_EID_INFO_IN_EID, arg->in.eid);
}

static void
uburma_get_ip_by_eid_fill_spec_out(void *arg_addr,
					 struct uburma_cmd_spec *spec)
{
	struct uburma_cmd_get_ip_by_eid *arg = arg_addr;
	struct uburma_cmd_spec *s = spec;

	SPEC(s++, GET_IP_BY_EID_INFO_OUT_NET_ADDR, arg->out.net_addr);
}

static void
uburma_get_smac_fill_spec_out(void *arg_addr,
					 struct uburma_cmd_spec *spec)
{
	struct uburma_cmd_get_smac *arg = arg_addr;
	struct uburma_cmd_spec *s = spec;

	SPEC(s++, GET_SMAC_OUT_MAC, arg->out.mac);
}

static void
uburma_get_dmac_fill_spec_in(void *arg_addr,
					 struct uburma_cmd_spec *spec)
{
	struct uburma_cmd_get_dmac *arg = arg_addr;
	struct uburma_cmd_spec *s = spec;

	SPEC(s++, GET_DMAC_IN_NET_ADDR, arg->in.net_addr);
}

static void
uburma_get_dmac_fill_spec_out(void *arg_addr,
					 struct uburma_cmd_spec *spec)
{
	struct uburma_cmd_get_dmac *arg = arg_addr;
	struct uburma_cmd_spec *s = spec;

	SPEC(s++, GET_DMAC_OUT_MAC, arg->out.mac);
}

static struct uburma_tlv_handler g_tlv_handler[] = {
	[0] = {0},
	[UBURMA_CMD_CREATE_CTX] = {
		uburma_create_ctx_fill_spec_in, CREATE_CTX_IN_NUM,
		uburma_create_ctx_fill_spec_out, CREATE_CTX_OUT_NUM - UBURMA_CMD_OUT_TYPE_INIT,
	},
	[UBURMA_CMD_ALLOC_TOKEN_ID] = {
		uburma_alloc_token_id_fill_spec_in, ALLOC_TOKEN_ID_IN_NUM,
		uburma_alloc_token_id_fill_spec_out, ALLOC_TOKEN_ID_OUT_NUM -
		UBURMA_CMD_OUT_TYPE_INIT,
	},
	[UBURMA_CMD_FREE_TOKEN_ID] = {
		uburma_free_token_id_fill_spec_in, FREE_TOKEN_ID_IN_NUM,
		NULL, 0,
	},
	[UBURMA_CMD_REGISTER_SEG] = {
		uburma_register_seg_fill_spec_in, REGISTER_SEG_IN_NUM,
		uburma_register_seg_fill_spec_out, REGISTER_SEG_OUT_NUM - UBURMA_CMD_OUT_TYPE_INIT,
	},
	[UBURMA_CMD_UNREGISTER_SEG] = {
		uburma_unregister_seg_fill_spec_in, UNREGISTER_SEG_IN_NUM,
		NULL, 0,
	},
	[UBURMA_CMD_IMPORT_SEG] = {
		uburma_import_seg_fill_spec_in, IMPORT_SEG_IN_NUM,
		uburma_import_seg_fill_spec_out, IMPORT_SEG_OUT_NUM - UBURMA_CMD_OUT_TYPE_INIT,
	},
	[UBURMA_CMD_UNIMPORT_SEG] = {
		uburma_unimport_seg_fill_spec_in, UNIMPORT_SEG_IN_NUM,
		NULL, 0,
	},
	[UBURMA_CMD_CREATE_JFR] = {
		uburma_create_jfr_fill_spec_in, CREATE_JFR_IN_NUM,
		uburma_create_jfr_fill_spec_out, CREATE_JFR_OUT_NUM - UBURMA_CMD_OUT_TYPE_INIT,
	},
	[UBURMA_CMD_MODIFY_JFR] = {
		uburma_modify_jfr_fill_spec_in, MODIFY_JFR_IN_NUM,
		uburma_modify_jfr_fill_spec_out, MODIFY_JFR_OUT_NUM - UBURMA_CMD_OUT_TYPE_INIT,
	},
	[UBURMA_CMD_QUERY_JFR] = {
		uburma_cmd_query_jfr_fill_spec_in, QUERY_JFR_IN_NUM,
		uburma_cmd_query_jfr_fill_spec_out, QUERY_JFR_OUT_NUM - UBURMA_CMD_OUT_TYPE_INIT,
	},
	[UBURMA_CMD_DELETE_JFR] = {
		uburma_delete_jfr_fill_spec_in, DELETE_JFR_IN_NUM,
		uburma_delete_jfr_fill_spec_out, DELETE_JFR_OUT_NUM - UBURMA_CMD_OUT_TYPE_INIT,
	},
	[UBURMA_CMD_CREATE_JFS] = {
		uburma_create_jfs_fill_spec_in, CREATE_JFS_IN_NUM,
		uburma_create_jfs_fill_spec_out, CREATE_JFS_OUT_NUM - UBURMA_CMD_OUT_TYPE_INIT,
	},
	[UBURMA_CMD_MODIFY_JFS] = {
		uburma_modify_jfs_fill_spec_in, MODIFY_JFS_IN_NUM,
		uburma_modify_jfs_fill_spec_out, MODIFY_JFS_OUT_NUM - UBURMA_CMD_OUT_TYPE_INIT,
	},
	[UBURMA_CMD_QUERY_JFS] = {
		uburma_query_jfs_fill_spec_in, QUERY_JFS_IN_NUM,
		uburma_query_jfs_fill_spec_out, QUERY_JFS_OUT_NUM - UBURMA_CMD_OUT_TYPE_INIT,
	},
	[UBURMA_CMD_DELETE_JFS] = {
		uburma_delete_jfs_fill_spec_in, DELETE_JFS_IN_NUM,
		uburma_delete_jfs_fill_spec_out, DELETE_JFS_OUT_NUM - UBURMA_CMD_OUT_TYPE_INIT,
	},
	[UBURMA_CMD_CREATE_JFC] = {
		uburma_create_jfc_fill_spec_in, CREATE_JFC_IN_NUM,
		uburma_create_jfc_fill_spec_out, CREATE_JFC_OUT_NUM - UBURMA_CMD_OUT_TYPE_INIT,
	},
	[UBURMA_CMD_MODIFY_JFC] = {
		uburma_modify_jfc_fill_spec_in, MODIFY_JFC_IN_NUM,
		uburma_modify_jfc_fill_spec_out, MODIFY_JFC_OUT_NUM - UBURMA_CMD_OUT_TYPE_INIT,
	},
	[UBURMA_CMD_DELETE_JFC] = {
		uburma_delete_jfc_fill_spec_in, DELETE_JFC_IN_NUM,
		uburma_delete_jfc_fill_spec_out, DELETE_JFC_OUT_NUM - UBURMA_CMD_OUT_TYPE_INIT,
	},
	[UBURMA_CMD_CREATE_JFCE] = {
		NULL, 0,
		uburma_create_jfce_fill_spec_out, CREATE_JFCE_OUT_NUM - UBURMA_CMD_OUT_TYPE_INIT,
	},
	[UBURMA_CMD_IMPORT_JFR] = {
		uburma_import_jfr_fill_spec_in, IMPORT_JFR_IN_NUM,
		uburma_import_jfr_fill_spec_out, IMPORT_JFR_OUT_NUM - UBURMA_CMD_OUT_TYPE_INIT,
	},
	[UBURMA_CMD_UNIMPORT_JFR] = {
		uburma_unimport_jfr_fill_spec_in, UNIMPORT_JFR_IN_NUM,
		NULL, 0,
	},
	[UBURMA_CMD_CREATE_JETTY] = {
		uburma_create_jetty_fill_spec_in, CREATE_JETTY_IN_NUM,
		uburma_create_jetty_fill_spec_out, CREATE_JETTY_OUT_NUM - UBURMA_CMD_OUT_TYPE_INIT,
	},
	[UBURMA_CMD_MODIFY_JETTY] = {
		uburma_modify_jetty_fill_spec_in, MODIFY_JETTY_IN_NUM,
		uburma_modify_jetty_fill_spec_out, MODIFY_JETTY_OUT_NUM - UBURMA_CMD_OUT_TYPE_INIT,
	},
	[UBURMA_CMD_QUERY_JETTY] = {
		uburma_query_jetty_fill_spec_in, QUERY_JETTY_IN_NUM,
		uburma_query_jetty_fill_spec_out, QUERY_JETTY_OUT_NUM - UBURMA_CMD_OUT_TYPE_INIT,
	},
	[UBURMA_CMD_DELETE_JETTY] = {
		uburma_delete_jetty_fill_spec_in, DELETE_JETTY_IN_NUM,
		uburma_delete_jetty_fill_spec_out, DELETE_JETTY_OUT_NUM - UBURMA_CMD_OUT_TYPE_INIT,
	},
	[UBURMA_CMD_IMPORT_JETTY] = {
		uburma_import_jetty_fill_spec_in, IMPORT_JETTY_IN_NUM,
		uburma_import_jetty_fill_spec_out, IMPORT_JETTY_OUT_NUM - UBURMA_CMD_OUT_TYPE_INIT,
	},
	[UBURMA_CMD_UNIMPORT_JETTY] = {
		uburma_unimport_jetty_fill_spec_in, UNIMPORT_JETTY_IN_NUM,
		NULL, 0,
	},
	[UBURMA_CMD_ADVISE_JFR] = {
		uburma_advise_jetty_fill_spec_in, ADVISE_JETTY_IN_NUM,
		NULL, 0,
	},
	[UBURMA_CMD_UNADVISE_JFR] = {
		uburma_unadvise_jetty_fill_spec_in, UNADVISE_JETTY_IN_NUM,
		NULL, 0,
	},
	[UBURMA_CMD_ADVISE_JETTY] = {
		uburma_advise_jetty_fill_spec_in, ADVISE_JETTY_IN_NUM,
		NULL, 0,
	},
	[UBURMA_CMD_UNADVISE_JETTY] = {
		uburma_unadvise_jetty_fill_spec_in, UNADVISE_JETTY_IN_NUM,
		NULL, 0,
	},
	[UBURMA_CMD_BIND_JETTY] = {
		uburma_bind_jetty_fill_spec_in, BIND_JETTY_IN_NUM,
		uburma_bind_jetty_fill_spec_out, BIND_JETTY_OUT_NUM - UBURMA_CMD_OUT_TYPE_INIT,
	},
	[UBURMA_CMD_UNBIND_JETTY] = {
		uburma_unadvise_jetty_fill_spec_in, UNADVISE_JETTY_IN_NUM,
		NULL, 0,
	},
	[UBURMA_CMD_CREATE_JETTY_GRP] = {
		uburma_create_jetty_grp_fill_spec_in, CREATE_JETTY_GRP_IN_NUM,
		uburma_create_jetty_grp_fill_spec_out, CREATE_JETTY_GRP_OUT_NUM -
		UBURMA_CMD_OUT_TYPE_INIT,
	},
	[UBURMA_CMD_DESTROY_JETTY_GRP] = {
		uburma_delete_jetty_grp_fill_spec_in, DELETE_JETTY_GRP_IN_NUM,
		uburma_delete_jetty_grp_fill_spec_out, DELETE_JETTY_GRP_OUT_NUM -
		UBURMA_CMD_OUT_TYPE_INIT,
	},
	[UBURMA_CMD_USER_CTL] = {
		uburma_user_ctl_fill_spec_in, USER_CTL_IN_NUM,
		NULL, 0,
	},
	[UBURMA_CMD_GET_EID_LIST] = {
		uburma_get_eid_list_fill_spec_in, GET_EID_LIST_IN_NUM,
		uburma_get_eid_list_fill_spec_out, GET_EID_LIST_OUT_NUM -
		UBURMA_CMD_OUT_TYPE_INIT,
	},
	[UBURMA_CMD_GET_NETADDR_LIST] = {
		uburma_get_net_addr_list_fill_spec_in, GET_NET_ADDR_LIST_IN_NUM,
		uburma_get_net_addr_list_fill_spec_out, GET_NET_ADDR_LIST_OUT_NUM -
		UBURMA_CMD_OUT_TYPE_INIT,
	},
	[UBURMA_CMD_MODIFY_TP] = {
		uburma_modify_tp_fill_spec_in, MODIFY_TP_IN_NUM,
		NULL, 0,
	},
	[UBURMA_CMD_QUERY_DEV_ATTR] = {
		uburma_query_device_fill_spec_in, QUERY_DEVICE_IN_NUM,
		uburma_query_device_fill_spec_out, QUERY_DEVICE_OUT_NUM -
		UBURMA_CMD_OUT_TYPE_INIT,
	},
	[UBURMA_CMD_IMPORT_JETTY_ASYNC] = {
		uburma_import_jetty_async_fill_spec_in, IMPORT_JETTY_ASYNC_IN_NUM,
		uburma_import_jetty_async_fill_spec_out, IMPORT_JETTY_ASYNC_OUT_NUM -
		UBURMA_CMD_OUT_TYPE_INIT,
	},
	[UBURMA_CMD_UNIMPORT_JETTY_ASYNC] = {
		uburma_unimport_jetty_async_fill_spec_in, UNIMPORT_JETTY_ASYNC_IN_NUM,
		NULL, 0,
	},
	[UBURMA_CMD_BIND_JETTY_ASYNC] = {
		uburma_bind_jetty_async_fill_spec_in, BIND_JETTY_ASYNC_IN_NUM,
		uburma_bind_jetty_async_fill_spec_out, BIND_JETTY_ASYNC_OUT_NUM -
		UBURMA_CMD_OUT_TYPE_INIT,
	},
	[UBURMA_CMD_UNBIND_JETTY_ASYNC] = {
		uburma_unbind_jetty_async_fill_spec_in, UNBIND_JETTY_ASYNC_IN_NUM,
		NULL, 0,
	},
	[UBURMA_CMD_CREATE_NOTIFIER] = {
		NULL, 0,
		uburma_create_notifier_fill_spec_out, CREATE_NOTIFIER_OUT_NUM -
		UBURMA_CMD_OUT_TYPE_INIT,
	},
	[UBURMA_CMD_GET_TP_LIST] = {
		uburma_get_tp_list_fill_spec_in, GET_TP_LIST_IN_NUM,
		uburma_get_tp_list_fill_spec_out, GET_TP_LIST_OUT_NUM -
		UBURMA_CMD_OUT_TYPE_INIT,
	},
	[UBURMA_CMD_IMPORT_JETTY_EX] = {
		uburma_import_jetty_ex_fill_spec_in, IMPORT_JETTY_EX_IN_NUM,
		uburma_import_jetty_ex_fill_spec_out, IMPORT_JETTY_EX_OUT_NUM -
		UBURMA_CMD_OUT_TYPE_INIT,
	},
	[UBURMA_CMD_IMPORT_JFR_EX] = {
		uburma_import_jfr_ex_fill_spec_in, IMPORT_JFR_EX_IN_NUM,
		uburma_import_jfr_ex_fill_spec_out, IMPORT_JFR_EX_OUT_NUM -
		UBURMA_CMD_OUT_TYPE_INIT,
	},
	[UBURMA_CMD_BIND_JETTY_EX] = {
		uburma_bind_jetty_ex_fill_spec_in, BIND_JETTY_EX_IN_NUM,
		uburma_bind_jetty_ex_fill_spec_out, BIND_JETTY_EX_OUT_NUM -
		UBURMA_CMD_OUT_TYPE_INIT,
	},
	[UBURMA_CMD_DELETE_JFS_BATCH] = {
		uburma_delete_jfs_batch_fill_spec_in, DELETE_JFS_BATCH_IN_NUM,
		uburma_delete_jfs_batch_fill_spec_out, DELETE_JFS_BATCH_OUT_NUM -
		UBURMA_CMD_OUT_TYPE_INIT,
	},
	[UBURMA_CMD_DELETE_JFR_BATCH] = {
		uburma_delete_jfr_batch_fill_spec_in, DELETE_JFR_BATCH_IN_NUM,
		uburma_delete_jfr_batch_fill_spec_out, DELETE_JFR_BATCH_OUT_NUM -
		UBURMA_CMD_OUT_TYPE_INIT,
	},
	[UBURMA_CMD_DELETE_JFC_BATCH] = {
		uburma_delete_jfc_batch_fill_spec_in, DELETE_JFC_BATCH_IN_NUM,
		uburma_delete_jfc_batch_fill_spec_out, DELETE_JFC_BATCH_OUT_NUM -
		UBURMA_CMD_OUT_TYPE_INIT,
	},
	[UBURMA_CMD_DELETE_JETTY_BATCH] = {
		uburma_delete_jetty_batch_fill_spec_in, DELETE_JETTY_BATCH_IN_NUM,
		uburma_delete_jetty_batch_fill_spec_out, DELETE_JETTY_BATCH_OUT_NUM -
		UBURMA_CMD_OUT_TYPE_INIT,
	},
	[UBURMA_CMD_SET_TP_ATTR] = {
		uburma_set_tp_attr_fill_spec_in, SET_TP_ATTR_IN_NUM,
		uburma_set_tp_attr_fill_spec_out, SET_TP_ATTR_OUT_NUM - UBURMA_CMD_OUT_TYPE_INIT,
	},
	[UBURMA_CMD_GET_TP_ATTR] = {
		uburma_get_tp_attr_fill_spec_in, GET_TP_ATTR_IN_NUM,
		uburma_get_tp_attr_fill_spec_out, GET_TP_ATTR_OUT_NUM - UBURMA_CMD_OUT_TYPE_INIT,
	},
	[UBURMA_CMD_EXCHANGE_TP_INFO] = {
		uburma_exchange_tp_info_fill_spec_in, EXCHANGE_TP_INFO_IN_NUM,
		uburma_exchange_tp_info_fill_spec_out, EXCHANGE_TP_INFO_OUT_NUM -
		UBURMA_CMD_OUT_TYPE_INIT,
	},
	[UBURMA_CMD_GET_EID_BY_IP] = {
		uburma_get_eid_by_ip_fill_spec_in, GET_EID_BY_IP_INFO_IN_NUM,
		uburma_get_eid_by_ip_fill_spec_out, GET_EID_BY_IP_INFO_OUT_NUM -
		UBURMA_CMD_OUT_TYPE_INIT,
	},
	[UBURMA_CMD_GET_IP_BY_EID] = {
		uburma_get_ip_by_eid_fill_spec_in, GET_IP_BY_EID_INFO_IN_NUM,
		uburma_get_ip_by_eid_fill_spec_out, GET_IP_BY_EID_INFO_OUT_NUM -
		UBURMA_CMD_OUT_TYPE_INIT,
	},
	[UBURMA_CMD_GET_SMAC] = {
		NULL, 0,
		uburma_get_smac_fill_spec_out, GET_SMAC_OUT_NUM - UBURMA_CMD_OUT_TYPE_INIT,
	},
	[UBURMA_CMD_GET_DMAC] = {
		uburma_get_dmac_fill_spec_in, GET_DMAC_IN_NUM,
		uburma_get_dmac_fill_spec_out, GET_DMAC_OUT_NUM - UBURMA_CMD_OUT_TYPE_INIT,
	},
	[UBURMA_CMD_ALLOC_JFC] = {
		uburma_alloc_jfc_fill_spec_in, ALLOC_JFC_IN_NUM,
		uburma_alloc_jfc_fill_spec_out, ALLOC_JFC_OUT_NUM - UBURMA_CMD_OUT_TYPE_INIT,
	},
	[UBURMA_CMD_FREE_JFC] = {
		uburma_free_jfc_fill_spec_in, FREE_JFC_IN_NUM,
		uburma_free_jfc_fill_spec_out, FREE_JFC_OUT_NUM - UBURMA_CMD_OUT_TYPE_INIT,
	},
	[UBURMA_CMD_SET_JFC_OPT] = {
		uburma_set_jfc_opt_fill_spec_in, SET_JFC_OPT_IN_NUM,
		uburma_set_jfc_opt_fill_spec_out, SET_JFC_OPT_OUT_NUM - UBURMA_CMD_OUT_TYPE_INIT,
	},
	[UBURMA_CMD_GET_JFC_OPT] = {
		uburma_get_jfc_opt_fill_spec_in, GET_JFC_OPT_IN_NUM,
		uburma_get_jfc_opt_fill_spec_out, GET_JFC_OPT_OUT_NUM - UBURMA_CMD_OUT_TYPE_INIT,
	},
	[UBURMA_CMD_ACTIVE_JFC] = {
		uburma_active_jfc_fill_spec_in, ACTIVE_JFC_IN_NUM,
		uburma_active_jfc_fill_spec_out, ACTIVE_JFC_OUT_NUM - UBURMA_CMD_OUT_TYPE_INIT,
	},
	[UBURMA_CMD_DEACTIVE_JFC] = {
		uburma_deactive_jfc_fill_spec_in, DEACTIVE_JFC_IN_NUM,
		uburma_deactive_jfc_fill_spec_out, DEACTIVE_JFC_OUT_NUM - UBURMA_CMD_OUT_TYPE_INIT,
	},
	[UBURMA_CMD_ALLOC_JFR] = {
		uburma_alloc_jfr_fill_spec_in, ALLOC_JFR_IN_NUM,
		uburma_alloc_jfr_fill_spec_out, ALLOC_JFR_OUT_NUM - UBURMA_CMD_OUT_TYPE_INIT,
	},
	[UBURMA_CMD_FREE_JFR] = {
		uburma_free_jfr_fill_spec_in, FREE_JFR_IN_NUM,
		uburma_free_jfr_fill_spec_out, FREE_JFR_OUT_NUM - UBURMA_CMD_OUT_TYPE_INIT,
	},
	[UBURMA_CMD_SET_JFR_OPT] = {
		uburma_set_jfr_opt_fill_spec_in, SET_JFR_OPT_IN_NUM,
		uburma_set_jfr_opt_fill_spec_out, SET_JFR_OPT_OUT_NUM - UBURMA_CMD_OUT_TYPE_INIT,
	},
	[UBURMA_CMD_GET_JFR_OPT] = {
		uburma_get_jfr_opt_fill_spec_in, GET_JFR_OPT_IN_NUM,
		uburma_get_jfr_opt_fill_spec_out, GET_JFR_OPT_OUT_NUM - UBURMA_CMD_OUT_TYPE_INIT,
	},
	[UBURMA_CMD_ACTIVE_JFR] = {
		uburma_active_jfr_fill_spec_in, ACTIVE_JFR_IN_NUM,
		uburma_active_jfr_fill_spec_out, ACTIVE_JFR_OUT_NUM - UBURMA_CMD_OUT_TYPE_INIT,
	},
	[UBURMA_CMD_DEACTIVE_JFR] = {
		uburma_deactive_jfr_fill_spec_in, DEACTIVE_JFR_IN_NUM,
		uburma_deactive_jfr_fill_spec_out, DEACTIVE_JFR_OUT_NUM - UBURMA_CMD_OUT_TYPE_INIT,
	},
	[UBURMA_CMD_ALLOC_JFS] = {
		uburma_alloc_jfs_fill_spec_in, ALLOC_JFS_IN_NUM,
		uburma_alloc_jfs_fill_spec_out, ALLOC_JFS_OUT_NUM - UBURMA_CMD_OUT_TYPE_INIT,
	},
	[UBURMA_CMD_FREE_JFS] = {
		uburma_free_jfs_fill_spec_in, FREE_JFS_IN_NUM,
		uburma_free_jfs_fill_spec_out, FREE_JFS_OUT_NUM - UBURMA_CMD_OUT_TYPE_INIT,
	},
	[UBURMA_CMD_SET_JFS_OPT] = {
		uburma_set_jfs_opt_fill_spec_in, SET_JFS_OPT_IN_NUM,
		uburma_set_jfs_opt_fill_spec_out, SET_JFS_OPT_OUT_NUM - UBURMA_CMD_OUT_TYPE_INIT,
	},
	[UBURMA_CMD_GET_JFS_OPT] = {
		uburma_get_jfs_opt_fill_spec_in, GET_JFS_OPT_IN_NUM,
		uburma_get_jfs_opt_fill_spec_out, GET_JFS_OPT_OUT_NUM - UBURMA_CMD_OUT_TYPE_INIT,
	},
	[UBURMA_CMD_ACTIVE_JFS] = {
		uburma_active_jfs_fill_spec_in, ACTIVE_JFS_IN_NUM,
		uburma_active_jfs_fill_spec_out, ACTIVE_JFS_OUT_NUM - UBURMA_CMD_OUT_TYPE_INIT,
	},
	[UBURMA_CMD_DEACTIVE_JFS] = {
		uburma_deactive_jfs_fill_spec_in, DEACTIVE_JFS_IN_NUM,
		uburma_deactive_jfs_fill_spec_out, DEACTIVE_JFS_OUT_NUM - UBURMA_CMD_OUT_TYPE_INIT,
	},
	[UBURMA_CMD_ALLOC_JETTY] = {
		uburma_alloc_jetty_fill_spec_in, ALLOC_JETTY_IN_NUM,
		uburma_alloc_jetty_fill_spec_out, ALLOC_JETTY_OUT_NUM - UBURMA_CMD_OUT_TYPE_INIT,
	},
	[UBURMA_CMD_FREE_JETTY] = {
		uburma_free_jetty_fill_spec_in, FREE_JETTY_IN_NUM,
		uburma_free_jetty_fill_spec_out, FREE_JETTY_OUT_NUM - UBURMA_CMD_OUT_TYPE_INIT,
	},
	[UBURMA_CMD_SET_JETTY_OPT] = {
		uburma_set_jetty_opt_fill_spec_in, SET_JETTY_OPT_IN_NUM,
		uburma_set_jetty_opt_fill_spec_out,
		SET_JETTY_OPT_OUT_NUM - UBURMA_CMD_OUT_TYPE_INIT,
	},
	[UBURMA_CMD_GET_JETTY_OPT] = {
		uburma_get_jetty_opt_fill_spec_in, GET_JETTY_OPT_IN_NUM,
		uburma_get_jetty_opt_fill_spec_out,
		GET_JETTY_OPT_OUT_NUM - UBURMA_CMD_OUT_TYPE_INIT,
	},
	[UBURMA_CMD_ACTIVE_JETTY] = {
		uburma_active_jetty_fill_spec_in, ACTIVE_JETTY_IN_NUM,
		uburma_active_jetty_fill_spec_out, ACTIVE_JETTY_OUT_NUM - UBURMA_CMD_OUT_TYPE_INIT,
	},
	[UBURMA_CMD_DEACTIVE_JETTY] = {
		uburma_deactive_jetty_fill_spec_in, DEACTIVE_JETTY_IN_NUM,
		uburma_deactive_jetty_fill_spec_out,
		DEACTIVE_JETTY_OUT_NUM - UBURMA_CMD_OUT_TYPE_INIT,
	},
};

static struct uburma_cmd_attr *
uburma_create_tlv_attr(struct uburma_cmd_hdr *hdr,
		       uint32_t *attr_size)
{
	struct uburma_cmd_attr *attr;
	int ret;

	if (hdr->args_len % sizeof(struct uburma_cmd_attr) != 0 ||
	    hdr->args_len >= UBURMA_CMD_TLV_MAX_LEN) {
		uburma_log_err("Invalid args_len: %u.\n",
			       hdr->args_len);
		return NULL;
	}
	attr = kzalloc(hdr->args_len, GFP_KERNEL);
	if (!attr)
		return NULL;

	ret = uburma_copy_from_user(
		attr, (void __user *)(uintptr_t)hdr->args_addr,
		hdr->args_len);
	if (ret != 0) {
		kfree(attr);
		return NULL;
	}
	*attr_size = hdr->args_len / sizeof(struct uburma_cmd_attr);
	return attr;
}

static int uburma_cmd_tlv_parse_type(struct uburma_cmd_spec *spec,
				     struct uburma_cmd_attr *attr)
{
	uintptr_t ptr_src, ptr_dst;
	uint32_t i;
	int ret;

	/* length of uburma spec and from uvs should be strictly checked */
	/* as length of uvs ioctl attr should be strictly equal to length of uburma */
	if (spec->field_size != attr->field_size ||
	    spec->attr_data.bs.el_num != attr->attr_data.bs.el_num) {
		uburma_log_err(
			"Invalid attr, spec/attr, field_size: %u/%u, el_num: %u/%u, type: %u.\n",
			spec->field_size, attr->field_size,
			spec->attr_data.bs.el_num,
			attr->attr_data.bs.el_num, spec->type);
		return -EINVAL;
	}

	for (i = 0; i < spec->attr_data.bs.el_num; i++) {
		ptr_dst =
			(spec->data) + i * spec->attr_data.bs.el_size;
		ptr_src =
			(attr->data) + i * attr->attr_data.bs.el_size;
		ret = uburma_copy_from_user((void *)ptr_dst,
					    (void __user *)ptr_src,
					    spec->field_size);
		if (ret != 0)
			return ret;
	}

	return ret;
}

static int uburma_cmd_tlv_parse(struct uburma_cmd_spec *spec,
				uint32_t spec_size,
				struct uburma_cmd_attr *attr,
				uint32_t attr_size)
{
	uint32_t spec_idx, attr_idx;
	bool match;
	int ret;

	/* spec type of this range is only in type */
	for (spec_idx = 0; spec_idx < spec_size; spec_idx++) {
		match = false;
		for (attr_idx = 0; attr_idx < attr_size; attr_idx++) {
			if (spec[spec_idx].type ==
			    attr[attr_idx].type) {
				ret = uburma_cmd_tlv_parse_type(
					&spec[spec_idx],
					&attr[attr_idx]);
				if (ret != 0)
					return ret;
				match = true;
				break;
			}
		}
		if (!match &&
		    ((spec[spec_idx].flag.bs.mandatory) != 0)) {
			uburma_log_err(
				"Failed to match mandatory in type: %u.\n",
				spec[spec_idx].type);
			return -EINVAL;
		}
	}

	return 0;
}

static int uburma_cmd_tlv_append_type(struct uburma_cmd_spec *spec,
				      struct uburma_cmd_attr *attr)
{
	uintptr_t ptr_src, ptr_dst;
	uint32_t i;
	int ret;

	/* length of uburma spec and from uvs should be strictly checked */
	/* as length of uvs ioctl attr should be strictly equal to length of uburma */
	if (spec->field_size != attr->field_size ||
	    spec->attr_data.bs.el_num > attr->attr_data.bs.el_num) {
		uburma_log_err(
			"Invalid attr, spec/attr, field_size: %u/%u, array_size: %u/%u, type: %u.\n",
			spec->field_size, attr->field_size,
			spec->attr_data.bs.el_num,
			attr->attr_data.bs.el_num, spec->type);
		return -EINVAL;
	}

	for (i = 0; i < spec->attr_data.bs.el_num; i++) {
		ptr_src =
			(spec->data) + i * spec->attr_data.bs.el_size;
		ptr_dst =
			(attr->data) + i * attr->attr_data.bs.el_size;
		ret = uburma_copy_to_user((void __user *)ptr_dst,
					  (void *)ptr_src,
					  spec->field_size);
		if (ret != 0)
			return ret;
	}

	return ret;
}

static int uburma_cmd_tlv_append(struct uburma_cmd_spec *spec,
				 uint32_t spec_size,
				 struct uburma_cmd_attr *attr,
				 uint32_t attr_size)
{
	uint32_t spec_idx, attr_idx;
	bool match;
	int ret;

	for (spec_idx = 0; spec_idx < spec_size; spec_idx++) {
		match = false;
		for (attr_idx = 0; attr_idx < attr_size; attr_idx++) {
			if (spec[spec_idx].type ==
			    attr[attr_idx].type) {
				ret = uburma_cmd_tlv_append_type(
					&spec[spec_idx],
					&attr[attr_idx]);
				if (ret != 0)
					return ret;
				match = true;
				break;
			}
		}
		if (!match && spec[spec_idx].flag.bs.mandatory) {
			uburma_log_err(
				"Failed to match mandatory out type: %u.\n",
				spec[spec_idx].type);
			return -EINVAL;
		}
	}

	return 0;
}

int uburma_tlv_parse(struct uburma_cmd_hdr *hdr, void *arg)
{
	struct uburma_cmd_spec *spec = NULL;
	struct uburma_cmd_attr *attr = NULL;
	uint32_t attr_size, spec_size;
	int ret;

	/* Command of hdr is valid, no need to check it */
	if (!g_tlv_handler[hdr->command].fill_spec_in) {
		uburma_log_err("Invalid command: %u.\n",
			       hdr->command);
		return -EINVAL;
	}

	spec_size = g_tlv_handler[hdr->command].spec_in_len;
	spec = kcalloc(spec_size, sizeof(struct uburma_cmd_spec),
		       GFP_KERNEL);
	if (!spec)
		return -ENOMEM;

	g_tlv_handler[hdr->command].fill_spec_in(arg, spec);

	attr = uburma_create_tlv_attr(hdr, &attr_size);
	if (!attr) {
		ret = -ENOMEM;
		goto free_spec;
	}

	ret = uburma_cmd_tlv_parse(spec, spec_size, attr, attr_size);

	kfree(attr);
free_spec:
	kfree(spec);
	return ret;
}

int uburma_tlv_append(struct uburma_cmd_hdr *hdr, void *arg)
{
	struct uburma_cmd_spec *spec = NULL;
	struct uburma_cmd_attr *attr = NULL;
	uint32_t attr_size, spec_size;
	int ret;

	/* Command of hdr is valid, no need to check it */
	if (!g_tlv_handler[hdr->command].fill_spec_out) {
		uburma_log_err("Invalid command: %u.\n",
			       hdr->command);
		return -EINVAL;
	}

	spec_size = g_tlv_handler[hdr->command].spec_out_len;
	spec = kcalloc(spec_size, sizeof(struct uburma_cmd_spec),
		       GFP_KERNEL);
	if (!spec)
		return -ENOMEM;

	g_tlv_handler[hdr->command].fill_spec_out(arg, spec);

	attr = uburma_create_tlv_attr(hdr, &attr_size);
	if (!attr) {
		ret = -ENOMEM;
		goto free_spec;
	}

	ret = uburma_cmd_tlv_append(spec, spec_size, attr, attr_size);

	kfree(attr);
free_spec:
	kfree(spec);
	return ret;
}

static void
uburma_wait_jfce_fill_spec_in(void *arg_addr,
			      struct uburma_cmd_spec *spec)
{
	struct uburma_cmd_jfce_wait *arg = arg_addr;
	struct uburma_cmd_spec *s = spec;

	SPEC(s++, JFCE_WAIT_IN_MAX_EVENT_CNT, arg->in.max_event_cnt);
	SPEC(s++, JFCE_WAIT_IN_TIME_OUT, arg->in.time_out);
}

static void
uburma_wait_jfce_fill_spec_out(void *arg_addr,
			       struct uburma_cmd_spec *spec)
{
	struct uburma_cmd_jfce_wait *arg = arg_addr;
	struct uburma_cmd_spec *s = spec;

	SPEC(s++, JFCE_WAIT_OUT_EVENT_CNT, arg->out.event_cnt);
	SPEC(s++, JFCE_WAIT_OUT_EVENT_DATA, arg->out.event_data);
}

static void
uburma_get_async_event_fill_spec_out(void *arg_addr,
				     struct uburma_cmd_spec *spec)
{
	struct uburma_cmd_async_event *arg = arg_addr;
	struct uburma_cmd_spec *s = spec;

	SPEC(s++, GET_ASYNC_EVENT_OUT_EVENT_TYPE, arg->event_type);
	SPEC(s++, GET_ASYNC_EVENT_OUT_EVENT_DATA, arg->event_data);
}

static void
uburma_wait_notify_fill_spec_in(void *arg_addr,
				struct uburma_cmd_spec *spec)
{
	struct uburma_cmd_wait_notify *arg = arg_addr;
	struct uburma_cmd_spec *s = spec;

	SPEC(s++, WAIT_NOTIFY_IN_CNT, arg->in.cnt);
	SPEC(s++, WAIT_NOTIFY_IN_TIMEOUT, arg->in.timeout);
}

static void
uburma_wait_notify_fill_spec_out(void *arg_addr,
				 struct uburma_cmd_spec *spec)
{
	struct uburma_cmd_wait_notify *arg = arg_addr;
	struct uburma_cmd_spec *s = spec;

	SPEC(s++, WAIT_NOTIFY_OUT_CNT, arg->out.cnt);
	SPEC(s++, WAIT_NOTIFY_OUT_NOTIFY, arg->out.notify);
}

static struct uburma_tlv_handler g_event_tlv_handler[] = {
	[0] = {0},
	[UBURMA_EVENT_CMD_WAIT_JFCE] = {
		uburma_wait_jfce_fill_spec_in, JFCE_WAIT_IN_NUM,
		uburma_wait_jfce_fill_spec_out, JFCE_WAIT_OUT_NUM - UBURMA_CMD_OUT_TYPE_INIT,
	},
	[UBURMA_EVENT_CMD_GET_ASYNC_EVENT] = {
		NULL, 0,
		uburma_get_async_event_fill_spec_out,
		GET_ASYNC_EVENT_OUT_NUM - UBURMA_CMD_OUT_TYPE_INIT,
	},
	[UBURMA_EVENT_CMD_WAIT_NOTIFY] = {
		uburma_wait_notify_fill_spec_in, WAIT_NOTIFY_IN_NUM,
		uburma_wait_notify_fill_spec_out, WAIT_NOTIFY_OUT_NUM - UBURMA_CMD_OUT_TYPE_INIT,
	}
};

int uburma_event_tlv_parse(struct uburma_cmd_hdr *hdr, void *arg)
{
	struct uburma_cmd_spec spec[UBURMA_EVENT_SPEC_ATTR_SIZE] = {0};
	struct uburma_cmd_attr attr[UBURMA_EVENT_SPEC_ATTR_SIZE] = {0};
	uint32_t attr_size, spec_size;
	int ret;

	/* Command of hdr is valid, no need to check it */
	if (!g_event_tlv_handler[hdr->command].fill_spec_in) {
		uburma_log_err("Invalid command: %u.\n",
			       hdr->command);
		return -EINVAL;
	}

	spec_size = g_event_tlv_handler[hdr->command].spec_in_len;
	g_event_tlv_handler[hdr->command].fill_spec_in(arg, spec);

	if (hdr->args_len % sizeof(struct uburma_cmd_attr) != 0 ||
		hdr->args_len >= UBURMA_CMD_EVENT_TLV_MAX_LEN) {
		uburma_log_err("Invalid args_len: %u.\n", hdr->args_len);
		return -EINVAL;
	}

	ret = uburma_copy_from_user(attr, (void __user *)(uintptr_t)hdr->args_addr,
		hdr->args_len);
	if (ret != 0)
		return ret;
	attr_size = hdr->args_len / sizeof(struct uburma_cmd_attr);

	return uburma_cmd_tlv_parse(spec, spec_size, attr, attr_size);
}

int uburma_event_tlv_append(struct uburma_cmd_hdr *hdr, void *arg)
{
	struct uburma_cmd_spec spec[UBURMA_EVENT_SPEC_ATTR_SIZE] = {0};
	struct uburma_cmd_attr attr[UBURMA_EVENT_SPEC_ATTR_SIZE] = {0};
	uint32_t attr_size, spec_size;
	int ret;

	/* Command of hdr is valid, no need to check it */
	if (!g_event_tlv_handler[hdr->command].fill_spec_out) {
		uburma_log_err("Invalid command: %u.\n",
			       hdr->command);
		return -EINVAL;
	}

	spec_size = g_event_tlv_handler[hdr->command].spec_out_len;
	g_event_tlv_handler[hdr->command].fill_spec_out(arg, spec);

	if (hdr->args_len % sizeof(struct uburma_cmd_attr) != 0 ||
		hdr->args_len >= UBURMA_CMD_EVENT_TLV_MAX_LEN) {
		uburma_log_err("Invalid args_len: %u.\n", hdr->args_len);
		return -EINVAL;
	}
	ret = uburma_copy_from_user(attr, (void __user *)(uintptr_t)hdr->args_addr,
		hdr->args_len);
	if (ret != 0)
		return ret;
	attr_size = hdr->args_len / sizeof(struct uburma_cmd_attr);

	return uburma_cmd_tlv_append(spec, spec_size, attr, attr_size);
}
