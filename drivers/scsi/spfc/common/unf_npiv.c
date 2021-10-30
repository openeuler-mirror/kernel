// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2021 Ramaxel Memory Technology, Ltd */

#include "unf_npiv.h"
#include "unf_log.h"
#include "unf_rport.h"
#include "unf_exchg.h"
#include "unf_portman.h"
#include "unf_npiv_portman.h"

#define UNF_DELETE_VPORT_MAX_WAIT_TIME_MS 60000

u32 unf_init_vport_pool(struct unf_lport *lport)
{
	u32 ret = RETURN_OK;
	u32 i;
	u16 vport_cnt = 0;
	struct unf_lport *vport = NULL;
	struct unf_vport_pool *vport_pool = NULL;
	u32 vport_pool_size;
	ulong flags = 0;

	FC_CHECK_RETURN_VALUE(lport, RETURN_ERROR);

	UNF_TOU16_CHECK(vport_cnt, lport->low_level_func.support_max_npiv_num,
			return RETURN_ERROR);
	if (vport_cnt == 0) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_WARN,
			     "[warn]Port(0x%x) do not support NPIV",
			     lport->port_id);

		return RETURN_OK;
	}

	vport_pool_size = sizeof(struct unf_vport_pool) + sizeof(struct unf_lport *) * vport_cnt;
	lport->vport_pool = vmalloc(vport_pool_size);
	if (!lport->vport_pool) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_ERR,
			     "[err]Port(0x%x) cannot allocate vport pool",
			     lport->port_id);

		return RETURN_ERROR;
	}
	memset(lport->vport_pool, 0, vport_pool_size);
	vport_pool = lport->vport_pool;
	vport_pool->vport_pool_count = vport_cnt;
	vport_pool->vport_pool_completion = NULL;
	spin_lock_init(&vport_pool->vport_pool_lock);
	INIT_LIST_HEAD(&vport_pool->list_vport_pool);

	vport_pool->vport_pool_addr =
	    vmalloc((size_t)(vport_cnt * sizeof(struct unf_lport)));
	if (!vport_pool->vport_pool_addr) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_ERR,
			     "[err]Port(0x%x) cannot allocate vport pool address",
			     lport->port_id);
		vfree(lport->vport_pool);
		lport->vport_pool = NULL;

		return RETURN_ERROR;
	}

	memset(vport_pool->vport_pool_addr, 0,
	       vport_cnt * sizeof(struct unf_lport));
	vport = (struct unf_lport *)vport_pool->vport_pool_addr;

	spin_lock_irqsave(&vport_pool->vport_pool_lock, flags);
	for (i = 0; i < vport_cnt; i++) {
		list_add_tail(&vport->entry_vport, &vport_pool->list_vport_pool);
		vport++;
	}

	vport_pool->slab_next_index = 0;
	vport_pool->slab_total_sum = vport_cnt;
	spin_unlock_irqrestore(&vport_pool->vport_pool_lock, flags);

	return ret;
}

void unf_free_vport_pool(struct unf_lport *lport)
{
	struct unf_vport_pool *vport_pool = NULL;
	bool wait = false;
	ulong flag = 0;
	u32 remain = 0;
	struct completion vport_pool_completion;

	init_completion(&vport_pool_completion);
	FC_CHECK_RETURN_VOID(lport);
	FC_CHECK_RETURN_VOID(lport->vport_pool);
	vport_pool = lport->vport_pool;

	spin_lock_irqsave(&vport_pool->vport_pool_lock, flag);

	if (vport_pool->slab_total_sum != vport_pool->vport_pool_count) {
		vport_pool->vport_pool_completion = &vport_pool_completion;
		remain = vport_pool->slab_total_sum - vport_pool->vport_pool_count;
		wait = true;
	}
	spin_unlock_irqrestore(&vport_pool->vport_pool_lock, flag);

	if (wait) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_MAJOR,
			     "[info]Port(0x%x) begin to wait for vport pool completion remain(0x%x)",
			     lport->port_id, remain);

		wait_for_completion(vport_pool->vport_pool_completion);
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_MAJOR,
			     "[info]Port(0x%x) wait for vport pool completion end",
			     lport->port_id);
		spin_lock_irqsave(&vport_pool->vport_pool_lock, flag);
		vport_pool->vport_pool_completion = NULL;
		spin_unlock_irqrestore(&vport_pool->vport_pool_lock, flag);
	}

	if (lport->vport_pool->vport_pool_addr) {
		vfree(lport->vport_pool->vport_pool_addr);
		lport->vport_pool->vport_pool_addr = NULL;
	}

	vfree(lport->vport_pool);
	lport->vport_pool = NULL;
}

struct unf_lport *unf_get_vport_by_slab_index(struct unf_vport_pool *vport_pool,
					      u16 slab_index)
{
	FC_CHECK_RETURN_VALUE(vport_pool, NULL);

	return vport_pool->vport_slab[slab_index];
}

static inline void unf_vport_pool_slab_set(struct unf_vport_pool *vport_pool,
					   u16 slab_index,
					   struct unf_lport *vport)
{
	FC_CHECK_RETURN_VOID(vport_pool);

	vport_pool->vport_slab[slab_index] = vport;
}

u32 unf_alloc_vp_index(struct unf_vport_pool *vport_pool,
		       struct unf_lport *vport, u16 vpid)
{
	u16 slab_index;
	ulong flags = 0;

	FC_CHECK_RETURN_VALUE(vport_pool, RETURN_ERROR);
	FC_CHECK_RETURN_VALUE(vport, RETURN_ERROR);

	spin_lock_irqsave(&vport_pool->vport_pool_lock, flags);
	if (vpid == 0) {
		slab_index = vport_pool->slab_next_index;
		while (unf_get_vport_by_slab_index(vport_pool, slab_index)) {
			slab_index = (slab_index + 1) % vport_pool->slab_total_sum;

			if (vport_pool->slab_next_index == slab_index) {
				spin_unlock_irqrestore(&vport_pool->vport_pool_lock, flags);

				FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_WARN,
					     "[warn]VPort pool has no slab ");

				return RETURN_ERROR;
			}
		}
	} else {
		slab_index = vpid - 1;
		if (unf_get_vport_by_slab_index(vport_pool, slab_index)) {
			spin_unlock_irqrestore(&vport_pool->vport_pool_lock, flags);

			FC_DRV_PRINT(UNF_LOG_REG_ATT,
				     UNF_WARN,
				     "[warn]VPort Index(0x%x) is occupy", vpid);

			return RETURN_ERROR;
		}
	}

	unf_vport_pool_slab_set(vport_pool, slab_index, vport);

	vport_pool->slab_next_index = (slab_index + 1) % vport_pool->slab_total_sum;

	spin_unlock_irqrestore(&vport_pool->vport_pool_lock, flags);

	spin_lock_irqsave(&vport->lport_state_lock, flags);
	vport->vp_index = slab_index + 1;
	spin_unlock_irqrestore(&vport->lport_state_lock, flags);

	return RETURN_OK;
}

void unf_free_vp_index(struct unf_vport_pool *vport_pool,
		       struct unf_lport *vport)
{
	ulong flags = 0;

	FC_CHECK_RETURN_VOID(vport_pool);
	FC_CHECK_RETURN_VOID(vport);

	if (vport->vp_index == 0 ||
	    vport->vp_index > vport_pool->slab_total_sum) {
		FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_MAJOR,
			     "Input vpoot index(0x%x) is beyond the normal range, min(0x1), max(0x%x).",
			     vport->vp_index, vport_pool->slab_total_sum);
		return;
	}

	spin_lock_irqsave(&vport_pool->vport_pool_lock, flags);
	unf_vport_pool_slab_set(vport_pool, vport->vp_index - 1,
				NULL); /* SlabIndex=VpIndex-1 */
	spin_unlock_irqrestore(&vport_pool->vport_pool_lock, flags);

	spin_lock_irqsave(&vport->lport_state_lock, flags);
	vport->vp_index = INVALID_VALUE16;
	spin_unlock_irqrestore(&vport->lport_state_lock, flags);
}

struct unf_lport *unf_get_free_vport(struct unf_lport *lport)
{
	struct unf_lport *vport = NULL;
	struct list_head *list_head = NULL;
	struct unf_vport_pool *vport_pool = NULL;
	ulong flag = 0;

	FC_CHECK_RETURN_VALUE(lport, NULL);
	FC_CHECK_RETURN_VALUE(lport->vport_pool, NULL);

	vport_pool = lport->vport_pool;

	spin_lock_irqsave(&vport_pool->vport_pool_lock, flag);
	if (!list_empty(&vport_pool->list_vport_pool)) {
		list_head = UNF_OS_LIST_NEXT(&vport_pool->list_vport_pool);
		list_del(list_head);
		vport_pool->vport_pool_count--;
		list_add_tail(list_head, &lport->list_vports_head);
		vport = list_entry(list_head, struct unf_lport, entry_vport);
	} else {
		FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_WARN,
			     "[warn]LPort(0x%x)'s vport pool is empty", lport->port_id);
		spin_unlock_irqrestore(&vport_pool->vport_pool_lock, flag);

		return NULL;
	}
	spin_unlock_irqrestore(&vport_pool->vport_pool_lock, flag);

	return vport;
}

void unf_vport_back_to_pool(void *vport)
{
	struct unf_lport *unf_lport = NULL;
	struct unf_lport *unf_vport = NULL;
	struct list_head *list = NULL;
	ulong flag = 0;

	FC_CHECK_RETURN_VOID(vport);
	unf_vport = vport;
	unf_lport = (struct unf_lport *)(unf_vport->root_lport);
	FC_CHECK_RETURN_VOID(unf_lport);
	FC_CHECK_RETURN_VOID(unf_lport->vport_pool);

	unf_free_vp_index(unf_lport->vport_pool, unf_vport);

	spin_lock_irqsave(&unf_lport->vport_pool->vport_pool_lock, flag);

	list = &unf_vport->entry_vport;
	list_del(list);
	list_add_tail(list, &unf_lport->vport_pool->list_vport_pool);
	unf_lport->vport_pool->vport_pool_count++;

	spin_unlock_irqrestore(&unf_lport->vport_pool->vport_pool_lock, flag);
}

void unf_init_vport_from_lport(struct unf_lport *vport, struct unf_lport *lport)
{
	FC_CHECK_RETURN_VOID(vport);
	FC_CHECK_RETURN_VOID(lport);

	vport->port_type = lport->port_type;
	vport->fc_port = lport->fc_port;
	vport->act_topo = lport->act_topo;
	vport->root_lport = lport;
	vport->unf_qualify_rport = lport->unf_qualify_rport;
	vport->link_event_wq = lport->link_event_wq;
	vport->xchg_wq = lport->xchg_wq;

	memcpy(&vport->xchg_mgr_temp, &lport->xchg_mgr_temp,
	       sizeof(struct unf_cm_xchg_mgr_template));

	memcpy(&vport->event_mgr, &lport->event_mgr, sizeof(struct unf_event_mgr));

	memset(&vport->lport_mgr_temp, 0, sizeof(struct unf_cm_lport_template));

	memcpy(&vport->low_level_func, &lport->low_level_func,
	       sizeof(struct unf_low_level_functioon_op));
}

void unf_check_vport_pool_status(struct unf_lport *lport)
{
	struct unf_vport_pool *vport_pool = NULL;
	ulong flags = 0;

	FC_CHECK_RETURN_VOID(lport);
	vport_pool = lport->vport_pool;
	FC_CHECK_RETURN_VOID(vport_pool);

	spin_lock_irqsave(&vport_pool->vport_pool_lock, flags);

	if (vport_pool->vport_pool_completion &&
	    vport_pool->slab_total_sum == vport_pool->vport_pool_count) {
		complete(vport_pool->vport_pool_completion);
	}
	spin_unlock_irqrestore(&vport_pool->vport_pool_lock, flags);
}

void unf_vport_fabric_logo(struct unf_lport *vport)
{
	struct unf_rport *unf_rport = NULL;
	ulong flag = 0;

	unf_rport = unf_get_rport_by_nport_id(vport, UNF_FC_FID_FLOGI);
	FC_CHECK_RETURN_VOID(unf_rport);
	spin_lock_irqsave(&unf_rport->rport_state_lock, flag);
	unf_rport_state_ma(unf_rport, UNF_EVENT_RPORT_LOGO);
	spin_unlock_irqrestore(&unf_rport->rport_state_lock, flag);

	unf_rport_enter_logo(vport, unf_rport);
}

void unf_vport_deinit(void *vport)
{
	struct unf_lport *unf_vport = NULL;

	FC_CHECK_RETURN_VOID(vport);
	unf_vport = (struct unf_lport *)vport;

	unf_unregister_scsi_host(unf_vport);

	unf_disc_mgr_destroy(unf_vport);

	unf_release_xchg_mgr_temp(unf_vport);

	unf_release_vport_mgr_temp(unf_vport);

	unf_destroy_scsi_id_table(unf_vport);

	unf_lport_release_lw_funop(unf_vport);
	unf_vport->fc_port = NULL;
	unf_vport->vport = NULL;

	if (unf_vport->lport_free_completion) {
		complete(unf_vport->lport_free_completion);
	} else {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_ERR,
			     "[err]VPort(0x%x) point(0x%p) completion free function is NULL",
			     unf_vport->port_id, unf_vport);
		dump_stack();
	}
}

void unf_vport_ref_dec(struct unf_lport *vport)
{
	FC_CHECK_RETURN_VOID(vport);

	if (atomic_dec_and_test(&vport->port_ref_cnt)) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_MAJOR,
			     "[info]VPort(0x%x) point(0x%p) reference count is 0 and freevport",
			     vport->port_id, vport);

		unf_vport_deinit(vport);
	}
}

u32 unf_vport_init(void *vport)
{
	struct unf_lport *unf_vport = NULL;

	FC_CHECK_RETURN_VALUE(vport, RETURN_ERROR);
	unf_vport = (struct unf_lport *)vport;

	unf_vport->options = UNF_PORT_MODE_INI;
	unf_vport->nport_id = 0;

	if (unf_init_scsi_id_table(unf_vport) != RETURN_OK) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_ERR,
			     "[err]Vport(0x%x) can not initialize SCSI ID table",
			     unf_vport->port_id);

		return RETURN_ERROR;
	}

	if (unf_init_disc_mgr(unf_vport) != RETURN_OK) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_ERR,
			     "[err]Vport(0x%x) can not initialize discover manager",
			     unf_vport->port_id);
		unf_destroy_scsi_id_table(unf_vport);

		return RETURN_ERROR;
	}

	if (unf_register_scsi_host(unf_vport) != RETURN_OK) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_ERR,
			     "[err]Vport(0x%x) vport can not register SCSI host",
			     unf_vport->port_id);
		unf_disc_mgr_destroy(unf_vport);
		unf_destroy_scsi_id_table(unf_vport);

		return RETURN_ERROR;
	}

	FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_KEVENT,
		     "[event]Vport(0x%x) Create succeed with wwpn(0x%llx)",
		     unf_vport->port_id, unf_vport->port_name);

	return RETURN_OK;
}

void unf_vport_remove(void *vport)
{
	struct unf_lport *unf_vport = NULL;
	struct unf_lport *unf_lport = NULL;
	struct completion port_free_completion;

	init_completion(&port_free_completion);
	FC_CHECK_RETURN_VOID(vport);
	unf_vport = (struct unf_lport *)vport;
	unf_lport = (struct unf_lport *)(unf_vport->root_lport);
	unf_vport->lport_free_completion = &port_free_completion;

	unf_set_lport_removing(unf_vport);

	unf_vport_ref_dec(unf_vport);

	wait_for_completion(unf_vport->lport_free_completion);
	unf_vport_back_to_pool(unf_vport);

	unf_check_vport_pool_status(unf_lport);
}

u32 unf_npiv_conf(u32 port_id, u64 wwpn, enum unf_rport_qos_level qos_level)
{
#define VPORT_WWN_MASK 0xff00ffffffffffff
#define VPORT_WWN_SHIFT 48

	struct fc_vport_identifiers vid = {0};
	struct Scsi_Host *host = NULL;
	struct unf_lport *unf_lport = NULL;
	struct unf_lport *unf_vport = NULL;
	u16 vport_id = 0;

	unf_lport = unf_find_lport_by_port_id(port_id);
	if (!unf_lport) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_ERR,
			     "[err]Cannot find LPort by (0x%x).", port_id);

		return RETURN_ERROR;
	}

	unf_vport = unf_cm_lookup_vport_by_wwpn(unf_lport, wwpn);
	if (unf_vport) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_WARN,
			     "[err]Port(0x%x) has find vport with wwpn(0x%llx), can't create again",
			     unf_lport->port_id, wwpn);

		return RETURN_ERROR;
	}

	unf_vport = unf_get_free_vport(unf_lport);
	if (!unf_vport) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_WARN,
			     "[warn]Can not get free vport from pool");

		return RETURN_ERROR;
	}

	unf_init_port_parms(unf_vport);
	unf_init_vport_from_lport(unf_vport, unf_lport);

	if ((unf_lport->port_name & VPORT_WWN_MASK) == (wwpn & VPORT_WWN_MASK)) {
		vport_id = (wwpn & ~VPORT_WWN_MASK) >> VPORT_WWN_SHIFT;
		if (vport_id == 0)
			vport_id = (unf_lport->port_name & ~VPORT_WWN_MASK) >> VPORT_WWN_SHIFT;
	}

	if (unf_alloc_vp_index(unf_lport->vport_pool, unf_vport, vport_id) != RETURN_OK) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_WARN,
			     "[warn]Vport can not allocate vport index");
		unf_vport_back_to_pool(unf_vport);

		return RETURN_ERROR;
	}
	unf_vport->port_id = (((u32)unf_vport->vp_index) << PORTID_VPINDEX_SHIT) |
				unf_lport->port_id;

	vid.roles = FC_PORT_ROLE_FCP_INITIATOR;
	vid.vport_type = FC_PORTTYPE_NPIV;
	vid.disable = false;
	vid.node_name = unf_lport->node_name;

	if (wwpn) {
		vid.port_name = wwpn;
	} else {
		if ((unf_lport->port_name & ~VPORT_WWN_MASK) >> VPORT_WWN_SHIFT !=
		    unf_vport->vp_index) {
			vid.port_name = (unf_lport->port_name & VPORT_WWN_MASK) |
			    (((u64)unf_vport->vp_index) << VPORT_WWN_SHIFT);
		} else {
			vid.port_name = (unf_lport->port_name & VPORT_WWN_MASK);
		}
	}

	unf_vport->port_name = vid.port_name;

	host = unf_lport->host_info.host;

	if (!fc_vport_create(host, 0, &vid)) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_ERR,
			     "[err]Port(0x%x) Cannot Failed to create vport wwpn=%llx",
			     unf_lport->port_id, vid.port_name);

		unf_vport_back_to_pool(unf_vport);

		return RETURN_ERROR;
	}

	unf_vport->qos_level = qos_level;
	return RETURN_OK;
}

struct unf_lport *unf_creat_vport(struct unf_lport *lport,
				  struct vport_config *vport_config)
{
	u32 ret = RETURN_OK;
	struct unf_lport *unf_lport = NULL;
	struct unf_lport *vport = NULL;
	enum unf_act_topo lport_topo;
	enum unf_lport_login_state lport_state;
	ulong flag = 0;

	FC_CHECK_RETURN_VALUE(lport, NULL);
	FC_CHECK_RETURN_VALUE(vport_config, NULL);

	if (vport_config->port_mode != FC_PORT_ROLE_FCP_INITIATOR) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_ERR,
			     "[err]Only support INITIATOR port mode(0x%x)",
			     vport_config->port_mode);

		return NULL;
	}
	unf_lport = lport;

	if (unf_lport->root_lport != unf_lport) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_ERR,
			     "[err]Port(0x%x) not root port return",
			     unf_lport->port_id);

		return NULL;
	}

	vport = unf_cm_lookup_vport_by_wwpn(unf_lport, vport_config->port_name);
	if (!vport) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_WARN,
			     "[err]Port(0x%x) can not find vport with wwpn(0x%llx)",
			     unf_lport->port_id, vport_config->port_name);

		return NULL;
	}

	ret = unf_vport_init(vport);
	if (ret != RETURN_OK) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_WARN,
			     "[warn]VPort(0x%x) can not initialize vport",
			     vport->port_id);

		return NULL;
	}

	spin_lock_irqsave(&unf_lport->lport_state_lock, flag);
	lport_topo = unf_lport->act_topo;
	lport_state = unf_lport->states;

	vport_config->node_name = unf_lport->node_name;
	spin_unlock_irqrestore(&unf_lport->lport_state_lock, flag);

	vport->port_name = vport_config->port_name;
	vport->node_name = vport_config->node_name;

	if (lport_topo == UNF_ACT_TOP_P2P_FABRIC &&
	    lport_state >= UNF_LPORT_ST_PLOGI_WAIT &&
	    lport_state <= UNF_LPORT_ST_READY) {
		vport->link_up = unf_lport->link_up;
		(void)unf_lport_login(vport, lport_topo);
	}

	return vport;
}

u32 unf_drop_vport(struct unf_lport *vport)
{
	u32 ret = RETURN_ERROR;
	struct fc_vport *unf_vport = NULL;

	FC_CHECK_RETURN_VALUE(vport, RETURN_ERROR);

	unf_vport = vport->vport;
	if (!unf_vport) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_ERR,
			     "[err]VPort(0x%x) find vport in scsi is NULL",
			     vport->port_id);

		return ret;
	}

	ret = fc_vport_terminate(unf_vport);
	if (ret != RETURN_OK) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_ERR,
			     "[err]VPort(0x%x) terminate vport(%p) in scsi failed",
			     vport->port_id, unf_vport);

		return ret;
	}
	return ret;
}

u32 unf_delete_vport(u32 port_id, u32 vp_index)
{
	struct unf_lport *unf_lport = NULL;
	u16 unf_vp_index = 0;
	struct unf_lport *vport = NULL;

	unf_lport = unf_find_lport_by_port_id(port_id);
	if (!unf_lport) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_ERR,
			     "[err]Port(0x%x) can not be found by portid", port_id);

		return RETURN_ERROR;
	}

	if (atomic_read(&unf_lport->lport_no_operate_flag) == UNF_LPORT_NOP) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_MAJOR,
			     "[info]Port(0x%x) is in NOP, destroy all vports function will be called",
			     unf_lport->port_id);

		return RETURN_OK;
	}

	UNF_TOU16_CHECK(unf_vp_index, vp_index, return RETURN_ERROR);
	vport = unf_cm_lookup_vport_by_vp_index(unf_lport, unf_vp_index);
	if (!vport) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_WARN,
			     "[warn]Can not lookup VPort by VPort index(0x%x)",
			     unf_vp_index);

		return RETURN_ERROR;
	}

	return unf_drop_vport(vport);
}

void unf_vport_abort_all_sfs_exch(struct unf_lport *vport)
{
	struct unf_xchg_hot_pool *hot_pool = NULL;
	struct list_head *xchg_node = NULL;
	struct list_head *next_xchg_node = NULL;
	struct unf_xchg *exch = NULL;
	ulong pool_lock_flags = 0;
	ulong exch_lock_flags = 0;
	u32 i;

	FC_CHECK_RETURN_VOID(vport);
	for (i = 0; i < UNF_EXCHG_MGR_NUM; i++) {
		hot_pool = unf_get_hot_pool_by_lport((struct unf_lport *)(vport->root_lport), i);
		if (unlikely(!hot_pool)) {
			FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_WARN,
				     "[warn]Port(0x%x) hot pool is NULL",
				     ((struct unf_lport *)(vport->root_lport))->port_id);
			continue;
		}

		spin_lock_irqsave(&hot_pool->xchg_hotpool_lock, pool_lock_flags);
		list_for_each_safe(xchg_node, next_xchg_node, &hot_pool->sfs_busylist) {
			exch = list_entry(xchg_node, struct unf_xchg, list_xchg_entry);
			spin_lock_irqsave(&exch->xchg_state_lock, exch_lock_flags);
			if (vport == exch->lport && (atomic_read(&exch->ref_cnt) > 0)) {
				exch->io_state |= TGT_IO_STATE_ABORT;
				spin_unlock_irqrestore(&exch->xchg_state_lock, exch_lock_flags);
				unf_disc_ctrl_size_inc(vport, exch->cmnd_code);
				/* Transfer exch to destroy chain */
				list_del(xchg_node);
				list_add_tail(xchg_node, &hot_pool->list_destroy_xchg);
			} else {
				spin_unlock_irqrestore(&exch->xchg_state_lock, exch_lock_flags);
			}
		}
		spin_unlock_irqrestore(&hot_pool->xchg_hotpool_lock, pool_lock_flags);
	}
}

void unf_vport_abort_ini_io_exch(struct unf_lport *vport)
{
	struct unf_xchg_hot_pool *hot_pool = NULL;
	struct list_head *xchg_node = NULL;
	struct list_head *next_xchg_node = NULL;
	struct unf_xchg *exch = NULL;
	ulong pool_lock_flags = 0;
	ulong exch_lock_flags = 0;
	u32 i;

	FC_CHECK_RETURN_VOID(vport);
	for (i = 0; i < UNF_EXCHG_MGR_NUM; i++) {
		hot_pool = unf_get_hot_pool_by_lport((struct unf_lport *)(vport->root_lport), i);
		if (unlikely(!hot_pool)) {
			FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_WARN,
				     "[warn]Port(0x%x) MgrIdex %u hot pool is NULL",
				     ((struct unf_lport *)(vport->root_lport))->port_id, i);
			continue;
		}

		spin_lock_irqsave(&hot_pool->xchg_hotpool_lock, pool_lock_flags);
		list_for_each_safe(xchg_node, next_xchg_node, &hot_pool->ini_busylist) {
			exch = list_entry(xchg_node, struct unf_xchg, list_xchg_entry);

			if (vport == exch->lport && atomic_read(&exch->ref_cnt) > 0) {
				/* Transfer exch to destroy chain */
				list_del(xchg_node);
				list_add_tail(xchg_node, &hot_pool->list_destroy_xchg);

				spin_lock_irqsave(&exch->xchg_state_lock, exch_lock_flags);
				exch->io_state |= INI_IO_STATE_DRABORT;
				spin_unlock_irqrestore(&exch->xchg_state_lock, exch_lock_flags);
			}
		}

		spin_unlock_irqrestore(&hot_pool->xchg_hotpool_lock, pool_lock_flags);
	}
}

void unf_vport_abort_exch(struct unf_lport *vport)
{
	FC_CHECK_RETURN_VOID(vport);

	unf_vport_abort_all_sfs_exch(vport);

	unf_vport_abort_ini_io_exch(vport);
}

u32 unf_vport_wait_all_exch_removed(struct unf_lport *vport)
{
#define UNF_WAIT_EXCH_REMOVE_ONE_TIME_MS 1000
	struct unf_xchg_hot_pool *hot_pool = NULL;
	struct list_head *xchg_node = NULL;
	struct list_head *next_xchg_node = NULL;
	struct unf_xchg *exch = NULL;
	u32 vport_uses = 0;
	ulong flags = 0;
	u32 wait_timeout = 0;
	u32 i = 0;

	FC_CHECK_RETURN_VALUE(vport, RETURN_ERROR);

	while (1) {
		vport_uses = 0;

		for (i = 0; i < UNF_EXCHG_MGR_NUM; i++) {
			hot_pool =
			    unf_get_hot_pool_by_lport((struct unf_lport *)(vport->root_lport), i);
			if (unlikely(!hot_pool)) {
				FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_WARN,
					     "[warn]Port(0x%x) hot Pool is NULL",
					     ((struct unf_lport *)(vport->root_lport))->port_id);

				continue;
			}

			spin_lock_irqsave(&hot_pool->xchg_hotpool_lock, flags);
			list_for_each_safe(xchg_node, next_xchg_node,
					   &hot_pool->list_destroy_xchg) {
				exch = list_entry(xchg_node, struct unf_xchg, list_xchg_entry);

				if (exch->lport != vport)
					continue;
				vport_uses++;
				if (wait_timeout >=
				    UNF_DELETE_VPORT_MAX_WAIT_TIME_MS) {
					FC_DRV_PRINT(UNF_LOG_NORMAL, UNF_ERR,
						     "[error]VPort(0x%x) Abort Exch(0x%p) Type(0x%x) OxRxid(0x%x 0x%x),sid did(0x%x 0x%x) SeqId(0x%x) IOState(0x%x) Ref(0x%x)",
						     vport->port_id, exch,
						     (u32)exch->xchg_type,
						     (u32)exch->oxid,
						     (u32)exch->rxid, (u32)exch->sid,
						     (u32)exch->did, (u32)exch->seq_id,
						     (u32)exch->io_state,
						     atomic_read(&exch->ref_cnt));
				}
			}
			spin_unlock_irqrestore(&hot_pool->xchg_hotpool_lock, flags);
		}

		if (vport_uses == 0) {
			FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_MAJOR,
				     "[info]VPort(0x%x) has removed all exchanges it used",
				     vport->port_id);
			break;
		}

		if (wait_timeout >= UNF_DELETE_VPORT_MAX_WAIT_TIME_MS)
			return RETURN_ERROR;

		msleep(UNF_WAIT_EXCH_REMOVE_ONE_TIME_MS);
		wait_timeout += UNF_WAIT_EXCH_REMOVE_ONE_TIME_MS;
	}

	return RETURN_OK;
}

u32 unf_vport_wait_rports_removed(struct unf_lport *vport)
{
#define UNF_WAIT_RPORT_REMOVE_ONE_TIME_MS 5000

	struct unf_disc *disc = NULL;
	struct list_head *node = NULL;
	struct list_head *next_node = NULL;
	u32 vport_uses = 0;
	ulong flags = 0;
	u32 wait_timeout = 0;
	struct unf_rport *unf_rport = NULL;

	FC_CHECK_RETURN_VALUE(vport, RETURN_ERROR);
	disc = &vport->disc;

	while (1) {
		vport_uses = 0;
		spin_lock_irqsave(&disc->rport_busy_pool_lock, flags);
		list_for_each_safe(node, next_node, &disc->list_delete_rports) {
			unf_rport = list_entry(node, struct unf_rport, entry_rport);
			FC_DRV_PRINT(UNF_LOG_NORMAL, UNF_MAJOR,
				     "[info]Vport(0x%x) Rport(0x%x) point(%p) is in Delete",
				     vport->port_id, unf_rport->nport_id, unf_rport);
			vport_uses++;
		}

		list_for_each_safe(node, next_node, &disc->list_destroy_rports) {
			unf_rport = list_entry(node, struct unf_rport, entry_rport);
			FC_DRV_PRINT(UNF_LOG_NORMAL, UNF_MAJOR,
				     "[info]Vport(0x%x) Rport(0x%x) point(%p) is in Destroy",
				     vport->port_id, unf_rport->nport_id, unf_rport);
			vport_uses++;
		}
		spin_unlock_irqrestore(&disc->rport_busy_pool_lock, flags);

		if (vport_uses == 0) {
			FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_MAJOR,
				     "[info]VPort(0x%x) has removed all RPorts it used",
				     vport->port_id);
			break;
		}

		FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_WARN,
			     "[warn]Vport(0x%x) has %u RPorts not removed wait timeout(%u ms)",
			     vport->port_id, vport_uses, wait_timeout);

		if (wait_timeout >= UNF_DELETE_VPORT_MAX_WAIT_TIME_MS)
			return RETURN_ERROR;

		msleep(UNF_WAIT_RPORT_REMOVE_ONE_TIME_MS);
		wait_timeout += UNF_WAIT_RPORT_REMOVE_ONE_TIME_MS;
	}

	return RETURN_OK;
}

u32 unf_destroy_one_vport(struct unf_lport *vport)
{
	u32 ret;
	struct unf_lport *root_port = NULL;

	FC_CHECK_RETURN_VALUE(vport, RETURN_ERROR);

	root_port = (struct unf_lport *)vport->root_lport;

	unf_vport_fabric_logo(vport);

	/* 1 set NOP */
	atomic_set(&vport->lport_no_operate_flag, UNF_LPORT_NOP);
	vport->port_removing = true;

	/* 2 report linkdown to scsi and delele rpot */
	unf_linkdown_one_vport(vport);

	/* 3 set abort for exchange */
	unf_vport_abort_exch(vport);

	/* 4 wait exch return freepool */
	if (!root_port->port_dirt_exchange) {
		ret = unf_vport_wait_all_exch_removed(vport);
		if (ret != RETURN_OK) {
			if (!root_port->port_removing) {
				vport->port_removing = false;
				FC_DRV_PRINT(UNF_LOG_NORMAL, UNF_ERR,
					     "[err]VPort(0x%x) can not wait Exchange return freepool",
					     vport->port_id);

				return RETURN_ERROR;
			}

			FC_DRV_PRINT(UNF_LOG_NORMAL, UNF_WARN,
				     "[warn]Port(0x%x) is removing, there is dirty exchange, continue",
				     root_port->port_id);

			root_port->port_dirt_exchange = true;
		}
	}

	/* wait rport return rportpool */
	ret = unf_vport_wait_rports_removed(vport);
	if (ret != RETURN_OK) {
		vport->port_removing = false;
		FC_DRV_PRINT(UNF_LOG_NORMAL, UNF_ERR,
			     "[err]VPort(0x%x) can not wait Rport return freepool",
			     vport->port_id);

		return RETURN_ERROR;
	}

	unf_cm_vport_remove(vport);

	return RETURN_OK;
}

void unf_destroy_all_vports(struct unf_lport *lport)
{
	struct unf_vport_pool *vport_pool = NULL;
	struct unf_lport *unf_lport = NULL;
	struct unf_lport *vport = NULL;
	struct list_head *node = NULL;
	struct list_head *next_node = NULL;
	ulong flags = 0;

	unf_lport = lport;
	FC_CHECK_RETURN_VOID(unf_lport);

	vport_pool = unf_lport->vport_pool;
	if (unlikely(!vport_pool)) {
		FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_ERR,
			     "[err]Lport(0x%x) VPort pool is NULL", unf_lport->port_id);

		return;
	}

	/* Transfer to the transition chain */
	spin_lock_irqsave(&vport_pool->vport_pool_lock, flags);
	list_for_each_safe(node, next_node, &unf_lport->list_vports_head) {
		vport = list_entry(node, struct unf_lport, entry_vport);
		list_del_init(&vport->entry_vport);
		list_add_tail(&vport->entry_vport, &unf_lport->list_destroy_vports);
	}

	list_for_each_safe(node, next_node, &unf_lport->list_intergrad_vports) {
		vport = list_entry(node, struct unf_lport, entry_vport);
		list_del_init(&vport->entry_vport);
		list_add_tail(&vport->entry_vport, &unf_lport->list_destroy_vports);
		atomic_dec(&vport->port_ref_cnt);
	}
	spin_unlock_irqrestore(&vport_pool->vport_pool_lock, flags);

	spin_lock_irqsave(&vport_pool->vport_pool_lock, flags);
	while (!list_empty(&unf_lport->list_destroy_vports)) {
		node = UNF_OS_LIST_NEXT(&unf_lport->list_destroy_vports);
		vport = list_entry(node, struct unf_lport, entry_vport);

		list_del_init(&vport->entry_vport);
		list_add_tail(&vport->entry_vport, &unf_lport->list_vports_head);
		spin_unlock_irqrestore(&vport_pool->vport_pool_lock, flags);

		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_MAJOR,
			     "[info]VPort(0x%x) Destroy begin", vport->port_id);
		unf_drop_vport(vport);
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_KEVENT,
			     "[info]VPort(0x%x) Destroy end", vport->port_id);

		spin_lock_irqsave(&vport_pool->vport_pool_lock, flags);
	}
	spin_unlock_irqrestore(&vport_pool->vport_pool_lock, flags);
}

u32 unf_init_vport_mgr_temp(struct unf_lport *lport)
{
	FC_CHECK_RETURN_VALUE(lport, UNF_RETURN_ERROR);
	lport->lport_mgr_temp.unf_look_up_vport_by_index = unf_lookup_vport_by_index;
	lport->lport_mgr_temp.unf_look_up_vport_by_port_id = unf_lookup_vport_by_portid;
	lport->lport_mgr_temp.unf_look_up_vport_by_did = unf_lookup_vport_by_did;
	lport->lport_mgr_temp.unf_look_up_vport_by_wwpn = unf_lookup_vport_by_wwpn;
	lport->lport_mgr_temp.unf_vport_remove = unf_vport_remove;

	return RETURN_OK;
}

void unf_release_vport_mgr_temp(struct unf_lport *lport)
{
	FC_CHECK_RETURN_VOID(lport);

	memset(&lport->lport_mgr_temp, 0, sizeof(struct unf_cm_lport_template));

	lport->destroy_step = UNF_LPORT_DESTROY_STEP_9_DESTROY_LPORT_MG_TMP;
}
