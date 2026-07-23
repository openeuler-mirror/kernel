// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#include <linux/hrtimer.h>
#include "log.h"
#include "en_pf.h"
#include "en_aux.h"
#include "zxdh_tsn.h"
#include "zxdh_tsn_reg.h"
#include "zxdh_tsn_ioctl.h"
#include "zxdh_tsn_comm.h"
#ifndef HAVE_IOPOLL_OPS
#include <linux/iopoll.h>
#endif

static s32 zxdh_tsn_qbv_disable(struct zxdh_tsn_private *tsn)
{
	s32 ret = 0;

	ret = tsn_port_disable_set(tsn);
	if (ret) {
		DH_LOG_ERR(MODULE_TSN, "[ErrorCode: %d] !\n", ret);
		return ret;
	}

	memset(tsn->tsn_qbv_conf, 0x00, sizeof(tsn->tsn_qbv_conf));

	hrtimer_cancel(&tsn->tsn_qbv_change_timer);

	DH_LOG_INFO(MODULE_TSN, "tsn port id %u is disable.\n", tsn->tsn_port_id.port_id);

	return TSN_OK;
}

static s32 zxdh_tsn_port_id_set(struct zxdh_tsn_private *tsn, struct zxdh_tsn_msg *msg)
{
	s32 ret = 0;
	u64 reg_base_addr = 0;
	struct zxdh_tsn_port_id *tsn_port_id = NULL;

	if (msg->len != (u32)sizeof(struct zxdh_tsn_port_id)) {
		DH_LOG_ERR(MODULE_TSN, "[Error: VALUE %u INVALID] [EQUAL %u] !\n", msg->len,
			   (u32)sizeof(struct zxdh_tsn_port_id));
		return -EINVAL;
	}

	tsn_port_id = (struct zxdh_tsn_port_id *)msg->data;
	if (!tsn_port_id) {
		DH_LOG_ERR(MODULE_TSN, "[Error: POINT NULL] !\n");
		return -EINVAL;
	}

	if (tsn_port_id->port_id > TSN_PORT_PORT_ID_MAX) {
		DH_LOG_ERR(MODULE_TSN, "[Error: VALUE %u INVALID] [MAX %u] !\n",
			   tsn_port_id->port_id, TSN_PORT_PORT_ID_MAX);
		return -EINVAL;
	}

	if (!IS_ERR_OR_NULL((void *)tsn->tsn_reg_base_addr)) {
		ret = tsn_port_disable_set(tsn);
		if (ret) {
			DH_LOG_ERR(MODULE_TSN, "[ErrorCode: %d] !\n", ret);
			return ret;
		}

		ret = tsn_port_phy_port_set(tsn, TSN_PORT_PORT_ID_DEF);
		if (ret) {
			DH_LOG_ERR(MODULE_TSN, "[ErrorCode: %d] !\n", ret);
			return ret;
		}
	}

	reg_base_addr = tsn->pci_ioremap_addr + TSN_PORT_REG_BAR_OFFSET +
			(tsn_port_id->port_id * TSN_PORT_REG_BAR_SIZE);
	ret = tsn_write(reg_base_addr, TSN_PORT_PHY_PORT_SEL, tsn->phy_port_id);
	if (ret) {
		DH_LOG_ERR(MODULE_TSN, "[ErrorCode: %d] !\n", ret);
		return ret;
	}

	DH_LOG_INFO(MODULE_TSN, "tsn port id %u is bound to phy port id %u.\n",
		    tsn_port_id->port_id, tsn->phy_port_id);
	tsn->tsn_reg_base_addr = reg_base_addr;
	tsn->tsn_port_id.port_id = tsn_port_id->port_id;

	ret = zxdh_tsn_qbv_disable(tsn);
	if (ret) {
		DH_LOG_ERR(MODULE_TSN, "[ErrorCode: %d] !\n", ret);
		return ret;
	}

	return TSN_OK;
}

static s32 zxdh_tsn_port_id_get(struct zxdh_tsn_private *tsn, struct zxdh_tsn_msg *msg)
{
	struct zxdh_tsn_port_id tsn_port_id;

	if (msg->len != (u32)sizeof(struct zxdh_tsn_port_id)) {
		DH_LOG_ERR(MODULE_TSN, "[Error: VALUE %u INVALID] [EQUAL %u] !\n", msg->len,
			   (u32)sizeof(struct zxdh_tsn_port_id));
		return -EINVAL;
	}

	tsn_port_id.port_id = tsn->tsn_port_id.port_id;

	memcpy(msg->data, &tsn_port_id, sizeof(struct zxdh_tsn_port_id));

	return TSN_OK;
}

static s32 zxdh_tsn_timer_id_set(struct zxdh_tsn_private *tsn, struct zxdh_tsn_msg *msg)
{
	s32 ret = 0;
	struct zxdh_tsn_timer_id *tsn_timer_id = NULL;

	if (msg->len != (u32)sizeof(struct zxdh_tsn_timer_id)) {
		DH_LOG_ERR(MODULE_TSN, "[Error: VALUE %u INVALID] [EQUAL %u] !\n", msg->len,
			   (u32)sizeof(struct zxdh_tsn_timer_id));
		return -EINVAL;
	}

	tsn_timer_id = (struct zxdh_tsn_timer_id *)msg->data;
	if (!tsn_timer_id) {
		DH_LOG_ERR(MODULE_TSN, "[Error: POINT NULL] !\n");
		return -EINVAL;
	}

	if (tsn_timer_id->timer_id > TSN_PORT_TIMER_ID_MAX) {
		DH_LOG_ERR(MODULE_TSN, "[Error: VALUE %u INVALID] [MAX %u] !\n",
			   tsn_timer_id->timer_id, TSN_PORT_TIMER_ID_MAX);
		return -EINVAL;
	}

	ret = tsn_port_timer_id_set(tsn, tsn_timer_id->timer_id);
	if (ret) {
		DH_LOG_ERR(MODULE_TSN, "[ErrorCode: %d] !\n", ret);
		return ret;
	}

	DH_LOG_INFO(MODULE_TSN, "tsn port id %u is bound to timer id %u.\n",
		    tsn->tsn_port_id.port_id, tsn_timer_id->timer_id);

	return TSN_OK;
}

static s32 zxdh_tsn_timer_id_get(struct zxdh_tsn_private *tsn, struct zxdh_tsn_msg *msg)
{
	s32 ret = 0;
	struct zxdh_tsn_timer_id tsn_timer_id;

	if (msg->len != (u32)sizeof(struct zxdh_tsn_timer_id)) {
		DH_LOG_ERR(MODULE_TSN, "[Error: VALUE %u INVALID] [EQUAL %u] !\n", msg->len,
			   (u32)sizeof(struct zxdh_tsn_timer_id));
		return -EINVAL;
	}

	ret = tsn_port_timer_id_get(tsn, &tsn_timer_id.timer_id);
	if (ret) {
		DH_LOG_ERR(MODULE_TSN, "[ErrorCode: %d] !\n", ret);
		return ret;
	}

	memcpy(msg->data, &tsn_timer_id, sizeof(struct zxdh_tsn_timer_id));

	return TSN_OK;
}

static s32 zxdh_tsn_qbv_conf_check(struct zxdh_tsn_private *tsn,
				   struct zxdh_tsn_qbv_conf *tsn_qbv_conf)
{
	u32 index = 0;
	u64 time_interval_sum = 0;
	struct zxdh_tsn_qbv_basic *tsn_qbv_basic = &tsn_qbv_conf->admin;
	struct zxdh_tsn_qbv_entry *tsn_qbv_entry = tsn_qbv_conf->admin.control_list;

	if (tsn_qbv_conf->enable > TSN_PORT_GATE_ENABLE) {
		DH_LOG_ERR(MODULE_TSN, "[Error: VALUE %u INVALID] [MAX %u] !\n",
			   tsn_qbv_conf->enable, TSN_PORT_GATE_ENABLE);
		return -EINVAL;
	}

	if (tsn_qbv_basic->cycle_time < tsn->tsn_qbv_cap.ct_min ||
	    tsn_qbv_basic->cycle_time > tsn->tsn_qbv_cap.ct_max) {
		DH_LOG_ERR(MODULE_TSN, "[Error: VALUE %llu INVALID] [MIN %llu MAX %llu] !\n",
			   tsn_qbv_basic->cycle_time, tsn->tsn_qbv_cap.ct_min,
			   tsn->tsn_qbv_cap.ct_max);
		return -EINVAL;
	}

	if (tsn_qbv_basic->control_list_length < 1 ||
	    tsn_qbv_basic->control_list_length > tsn->tsn_qbv_cap.gcl_num) {
		DH_LOG_ERR(MODULE_TSN, "[Error: VALUE %u INVALID] [MIN %u MAX %u] !\n",
			   tsn_qbv_basic->control_list_length, 1, tsn->tsn_qbv_cap.gcl_num);
		return -EINVAL;
	}

	for (index = 0; index < tsn_qbv_basic->control_list_length; index++) {
		if (tsn_qbv_entry[index].time_interval < tsn->tsn_qbv_cap.it_min ||
		    tsn_qbv_entry[index].time_interval > tsn->tsn_qbv_cap.it_max) {
			DH_LOG_ERR(MODULE_TSN, "[Error: VALUE %u INVALID] [MIN %u MAX %u] !\n",
				   tsn_qbv_entry[index].time_interval, tsn->tsn_qbv_cap.it_min,
				   tsn->tsn_qbv_cap.it_max);
			return -EINVAL;
		}
		time_interval_sum += tsn_qbv_entry[index].time_interval;
	}

	if (tsn_qbv_basic->cycle_time != time_interval_sum) {
		DH_LOG_ERR(MODULE_TSN, "[Error: VALUE %llu INVALID] [EQUAL %llu] !\n",
			   tsn_qbv_basic->cycle_time, time_interval_sum);
		return -EINVAL;
	}

	return TSN_OK;
}

static s32 zxdh_tsn_qbv_base_time_cal(struct zxdh_tsn_private *tsn,
				      struct zxdh_tsn_qbv_conf *tsn_qbv_conf_oper,
				      struct zxdh_tsn_qbv_conf *tsn_qbv_conf_admin,
				      u64 real_tod_time, u32 status)
{
	u64 oper_base_time = 0;
	u64 oper_cycle_time = 0;
	u64 admin_base_time = 0;
	u64 admin_cycle_time = 0;
	u64 cycle_time_extension = 0;

	if (!tsn_qbv_conf_oper) {
		DH_LOG_ERR(MODULE_TSN, "[Error: POINT NULL] !\n");
		return -EINVAL;
	}
	if (!tsn_qbv_conf_admin) {
		DH_LOG_ERR(MODULE_TSN, "[Error: POINT NULL] !\n");
		return -EINVAL;
	}

	oper_base_time = tsn_qbv_conf_oper->admin.base_time;
	oper_cycle_time = tsn_qbv_conf_oper->admin.cycle_time;

	admin_base_time = tsn_qbv_conf_admin->admin.base_time;
	admin_cycle_time = tsn_qbv_conf_admin->admin.cycle_time;

	if (real_tod_time >= admin_base_time) {
		admin_base_time += admin_cycle_time *
				   (((real_tod_time - admin_base_time) / admin_cycle_time) + 1);
		if ((admin_base_time - real_tod_time) < TSN_SOFT_RESERVED_TIME)
			admin_base_time += TSN_RESERVED_TIME(admin_cycle_time);

		DH_LOG_INFO(
			MODULE_TSN,
			"tsn port id %u admin_base_time change to %llu real_tod_time %llu diff %llu.\n",
			tsn->tsn_port_id.port_id, admin_base_time, real_tod_time,
			admin_base_time - real_tod_time);
	} else if ((admin_base_time - real_tod_time) < TSN_SOFT_RESERVED_TIME) {
		admin_base_time += TSN_RESERVED_TIME(admin_cycle_time);
		DH_LOG_INFO(
			MODULE_TSN,
			"tsn port id %u admin_base_time change to %llu real_tod_time %llu diff %llu.\n",
			tsn->tsn_port_id.port_id, admin_base_time, real_tod_time,
			admin_base_time - real_tod_time);
	}

	if (status != TSN_PORT_GATE_IDLE) {
		if (real_tod_time >= oper_base_time) {
			cycle_time_extension = (admin_base_time - oper_base_time) % oper_cycle_time;
			if (cycle_time_extension < TSN_CYCLE_TIME_EXTENSION_MIN)
				cycle_time_extension += oper_cycle_time;

			DH_LOG_INFO(MODULE_TSN, "tsn port id %u cycle_time_extension %llu .\n",
				    tsn->tsn_port_id.port_id, cycle_time_extension);

			if (cycle_time_extension < oper_cycle_time) {
				oper_base_time +=
					oper_cycle_time *
					(((real_tod_time - oper_base_time) / oper_cycle_time) + 1);
				if ((oper_base_time - real_tod_time) < TSN_SOFT_RESERVED_TIME)
					oper_base_time += TSN_RESERVED_TIME(oper_cycle_time);

			} else {
				oper_base_time +=
					oper_cycle_time *
					(((real_tod_time - oper_base_time) / oper_cycle_time) + 2);
				if ((oper_base_time - oper_cycle_time - real_tod_time) <
				    TSN_SOFT_RESERVED_TIME) {
					oper_base_time += TSN_RESERVED_TIME(oper_cycle_time);
				}
			}
			DH_LOG_INFO(
				MODULE_TSN,
				"tsn port id %u oper_base_time change to %llu real_tod_time %llu diff %llu.\n",
				tsn->tsn_port_id.port_id, oper_base_time, real_tod_time,
				oper_base_time - real_tod_time);
		}

		if (oper_base_time > admin_base_time) {
			if (cycle_time_extension == oper_cycle_time) {
				admin_base_time +=
					admin_cycle_time *
					(((oper_base_time - admin_base_time) / admin_cycle_time));
			} else {
				admin_base_time +=
					admin_cycle_time *
					(((oper_base_time - admin_base_time) / admin_cycle_time) +
					 1);
			}
			DH_LOG_INFO(
				MODULE_TSN,
				"tsn port id %u admin_base_time change to %llu oper_base_time %llu diff %llu.\n",
				tsn->tsn_port_id.port_id, admin_base_time, oper_base_time,
				admin_base_time - oper_base_time);
		}
	}

	tsn_qbv_conf_admin->admin.base_time = admin_base_time;

	return TSN_OK;
}

static s32 zxdh_tsn_qbv_cycle_time_extension_cal(struct zxdh_tsn_private *tsn,
						 struct zxdh_tsn_qbv_conf *tsn_qbv_conf_oper,
						 struct zxdh_tsn_qbv_conf *tsn_qbv_conf_admin,
						 u64 *cycle_time_extension)
{
	u64 admin_base_time = 0;
	u64 oper_base_time = 0;
	u64 oper_cycle_time = 0;

	if (!tsn_qbv_conf_oper) {
		DH_LOG_ERR(MODULE_TSN, "[Error: POINT NULL] !\n");
		return -EINVAL;
	}
	if (!tsn_qbv_conf_admin) {
		DH_LOG_ERR(MODULE_TSN, "[Error: POINT NULL] !\n");
		return -EINVAL;
	}
	if (!cycle_time_extension) {
		DH_LOG_ERR(MODULE_TSN, "[Error: POINT NULL] !\n");
		return -EINVAL;
	}

	oper_base_time = tsn_qbv_conf_oper->admin.base_time;
	oper_cycle_time = tsn_qbv_conf_oper->admin.cycle_time;

	admin_base_time = tsn_qbv_conf_admin->admin.base_time;

	if ((admin_base_time > oper_base_time) && (oper_cycle_time != 0)) {
		oper_base_time +=
			oper_cycle_time * ((admin_base_time - oper_base_time) / oper_cycle_time);
		if (admin_base_time >= oper_base_time) {
			*cycle_time_extension = admin_base_time - oper_base_time;
			if (*cycle_time_extension < TSN_CYCLE_TIME_EXTENSION_MIN)
				*cycle_time_extension += oper_cycle_time;

			DH_LOG_INFO(MODULE_TSN, "tsn port id %u cycle_time_extension %llu.\n",
				    tsn->tsn_port_id.port_id, *cycle_time_extension);
			return TSN_OK;
		}
	}

	return -EINVAL;
}

static s32 zxdh_tsn_qbv_gate_status_get(struct zxdh_tsn_private *tsn, u32 *p_ram_n_idle,
					u32 *p_status)
{
	s32 ret = 0;
	u32 init_finish = 0;
	u32 change_en = 0;
	u32 ram_n = 0;
	u32 status = 0;
	u32 enable = 0;
	u64 admin_base_time = 0;
	u64 real_tod_time = 0;
	u64 cycle_time_extension = 0;

	ret = tsn_port_status_get(tsn, &ram_n, &status);
	if (ret) {
		DH_LOG_ERR(MODULE_TSN, "[ErrorCode: %d] !\n", ret);
		return ret;
	}

	ret = tsn_port_init_finish_get(tsn, &init_finish);
	if (ret) {
		DH_LOG_ERR(MODULE_TSN, "[ErrorCode: %d] !\n", ret);
		return ret;
	}

	ret = tsn_port_change_en_get(tsn, &change_en);
	if (ret) {
		DH_LOG_ERR(MODULE_TSN, "[ErrorCode: %d] !\n", ret);
		return ret;
	}

	ret = tsn_port_enable_get(tsn, &enable);
	if (ret) {
		DH_LOG_ERR(MODULE_TSN, "[ErrorCode: %d] !\n", ret);
		return ret;
	}

	*p_ram_n_idle = (ram_n == 0) ? 0 : ((ram_n == 1) ? 1 : ((ram_n == 2) ? 0 : 2));
	if (*p_ram_n_idle > TSN_PORT_RAM_MAX) {
		DH_LOG_ERR(MODULE_TSN, "[Error: VALUE %u INVALID] [MAX %u] !\n", *p_ram_n_idle,
			   TSN_PORT_RAM_MAX);
		return -EINVAL;
	}

	if ((status == 0) && (init_finish == 0) && (change_en == 0) &&
	    (enable == TSN_PORT_GATE_DISABLE)) {
		*p_status = TSN_PORT_GATE_IDLE;
		DH_LOG_INFO(
			MODULE_TSN,
			"tsn port id %u idle status %u init_finish %u change_en %u enable %u.\n",
			tsn->tsn_port_id.port_id, status, init_finish, change_en, enable);
		return TSN_OK;
	}

	if (((status >= 3) && (status <= 8)) && (init_finish == 0) && (change_en == 0) &&
	    (enable == TSN_PORT_GATE_ENABLE)) {
		*p_status = TSN_PORT_GATE_RUNNING;
		DH_LOG_INFO(
			MODULE_TSN,
			"tsn port id %u running status %u init_finish %u change_en %u enable %u.\n",
			tsn->tsn_port_id.port_id, status, init_finish, change_en, enable);
		return TSN_OK;
	}

	if (((status >= 3) && (status <= 8)) && (init_finish == 0) && (change_en == 1) &&
	    (enable == TSN_PORT_GATE_ENABLE)) {
		admin_base_time = tsn->tsn_qbv_conf[*p_ram_n_idle].admin.base_time;
		ret = zxdh_tsn_qbv_cycle_time_extension_cal(
			tsn, &tsn->tsn_qbv_conf[TSN_RAM_N_IN_SERVICE(*p_ram_n_idle)],
			&tsn->tsn_qbv_conf[*p_ram_n_idle], &cycle_time_extension);
		if (ret) {
			DH_LOG_ERR(MODULE_TSN, "[ErrorCode: %d] !\n", ret);
			return ret;
		}

		ret = tsn_port_real_tod_time_get(tsn, &real_tod_time);
		if (ret) {
			DH_LOG_ERR(MODULE_TSN, "[ErrorCode: %d] !\n", ret);
			return ret;
		}

		if ((admin_base_time - cycle_time_extension - TSN_SOFT_RESERVED_TIME) >
		    real_tod_time) {
			*p_status = TSN_PORT_GATE_CHANGING;
			DH_LOG_INFO(
				MODULE_TSN,
				"tsn port id %u changing status %u init_finish %u change_en %u enable %u.\n",
				tsn->tsn_port_id.port_id, status, init_finish, change_en, enable);
			return TSN_OK;
		}
	}

	*p_status = TSN_PORT_GATE_PENDING;
	DH_LOG_INFO(MODULE_TSN,
		    "tsn port id %u pending status %u init_finish %u change_en %u enable %u.\n",
		    tsn->tsn_port_id.port_id, status, init_finish, change_en, enable);
	return TSN_OK;
}

static s32 zxdh_tsn_qbv_basic_set(struct zxdh_tsn_private *tsn,
				  struct zxdh_tsn_qbv_conf *tsn_qbv_conf, u32 ram_n_idle)
{
	s32 ret = 0;
	u32 index = 0;

	ret = tsn_port_default_gate_set(tsn, 0x00);
	if (ret) {
		DH_LOG_ERR(MODULE_TSN, "[ErrorCode: %d] !\n", ret);
		return ret;
	}

	ret = tsn_port_change_gate_set(tsn, 0xFF);
	if (ret) {
		DH_LOG_ERR(MODULE_TSN, "[ErrorCode: %d] !\n", ret);
		return ret;
	}

	for (index = 0; index < TSN_PORT_QUEUE_NUM; index++) {
		ret = tsn_port_guard_band_time_set(tsn, index,
						   tsn_qbv_conf->admin.guard_band_time[index]);
		if (ret) {
			DH_LOG_ERR(MODULE_TSN, "[ErrorCode: %d] !\n", ret);
			return ret;
		}
	}

	ret = tsn_port_gcl_num_set(tsn, ram_n_idle, tsn_qbv_conf->admin.control_list_length);
	if (ret) {
		DH_LOG_ERR(MODULE_TSN, "[ErrorCode: %d] !\n", ret);
		return ret;
	}

	for (index = 0; index < tsn_qbv_conf->admin.control_list_length; index++) {
		ret = tsn_port_gcl_control_set(
			tsn, ram_n_idle, index, tsn_qbv_conf->admin.control_list[index].gate_state,
			tsn_qbv_conf->admin.control_list[index].time_interval);
		if (ret) {
			DH_LOG_ERR(MODULE_TSN, "[ErrorCode: %d] !\n", ret);
			return ret;
		}
	}

	ret = tsn_port_enable_set(tsn, TSN_PORT_GATE_ENABLE);
	if (ret) {
		DH_LOG_ERR(MODULE_TSN, "[ErrorCode: %d] !\n", ret);
		return ret;
	}

	ret = tsn_port_cycle_time_set(tsn, tsn_qbv_conf->admin.cycle_time);
	if (ret) {
		DH_LOG_ERR(MODULE_TSN, "[ErrorCode: %d] !\n", ret);
		return ret;
	}

	ret = tsn_port_base_time_set(tsn, tsn_qbv_conf->admin.base_time);
	if (ret) {
		DH_LOG_ERR(MODULE_TSN, "[ErrorCode: %d] !\n", ret);
		return ret;
	}

	return TSN_OK;
}

static s32 zxdh_tsn_qbv_change_set(struct zxdh_tsn_private *tsn,
				   struct zxdh_tsn_qbv_conf *tsn_qbv_conf, u32 ram_n_idle)
{
	s32 ret = 0;

	ret = tsn_port_change_en_set(tsn, TSN_PORT_CHANGE_DISABLE);
	if (ret) {
		DH_LOG_ERR(MODULE_TSN, "[ErrorCode: %d] !\n", ret);
		return ret;
	}

	ret = zxdh_tsn_qbv_basic_set(tsn, tsn_qbv_conf, ram_n_idle);
	if (ret) {
		DH_LOG_ERR(MODULE_TSN, "[ErrorCode: %d] !\n", ret);
		return ret;
	}

	ret = tsn_port_change_en_set(tsn, TSN_PORT_CHANGE_ENABLE);
	if (ret) {
		DH_LOG_ERR(MODULE_TSN, "[ErrorCode: %d] !\n", ret);
		return ret;
	}

	return TSN_OK;
}

static s32 zxdh_tsn_qbv_set(struct zxdh_tsn_private *tsn, struct zxdh_tsn_msg *msg)
{
	s32 ret = 0;
	u32 ram_n_idle = 0;
	u32 status = 0;
	u64 cycle_time_extension = 0;
	u64 real_tod_time = 0;
	u64 expires_in_nanosecond = 0;
	struct zxdh_tsn_qbv_conf *tsn_qbv_conf = NULL;

	if (msg->len != (u32)sizeof(struct zxdh_tsn_qbv_conf)) {
		DH_LOG_ERR(MODULE_TSN, "[Error: VALUE %u INVALID] [EQUAL %u] !\n", msg->len,
			   (u32)sizeof(struct zxdh_tsn_qbv_conf));
		return -EINVAL;
	}

	tsn_qbv_conf = (struct zxdh_tsn_qbv_conf *)msg->data;
	if (!tsn_qbv_conf) {
		DH_LOG_ERR(MODULE_TSN, "[Error: POINT NULL] !\n");
		return -EINVAL;
	}

	if (tsn_qbv_conf->enable == TSN_PORT_GATE_DISABLE) {
		ret = zxdh_tsn_qbv_disable(tsn);
		if (ret) {
			DH_LOG_ERR(MODULE_TSN, "[ErrorCode: %d] !\n", ret);
			return ret;
		}
		return TSN_OK;
	}

	ret = zxdh_tsn_qbv_conf_check(tsn, tsn_qbv_conf);
	if (ret) {
		DH_LOG_ERR(MODULE_TSN, "[ErrorCode: %d] !\n", ret);
		return ret;
	}

	ret = zxdh_tsn_qbv_gate_status_get(tsn, &ram_n_idle, &status);
	if (ret) {
		DH_LOG_ERR(MODULE_TSN, "[ErrorCode: %d] !\n", ret);
		return ret;
	}

	if (status == TSN_PORT_GATE_PENDING) {
		DH_LOG_ERR(MODULE_TSN, "tsn port id %u is pending.\n", tsn->tsn_port_id.port_id);
		return -EBUSY;
	}

	ret = tsn_port_real_tod_time_get(tsn, &real_tod_time);
	if (ret) {
		DH_LOG_ERR(MODULE_TSN, "[ErrorCode: %d] !\n", ret);
		return ret;
	}

	ret = zxdh_tsn_qbv_base_time_cal(tsn, &tsn->tsn_qbv_conf[TSN_RAM_N_IN_SERVICE(ram_n_idle)],
					 tsn_qbv_conf, real_tod_time, status);
	if (ret) {
		DH_LOG_ERR(MODULE_TSN, "[ErrorCode: %d] !\n", ret);
		return ret;
	}

	if (status == TSN_PORT_GATE_IDLE) {
		ret = zxdh_tsn_qbv_basic_set(tsn, tsn_qbv_conf, ram_n_idle);
		if (ret) {
			DH_LOG_ERR(MODULE_TSN, "[ErrorCode: %d] !\n", ret);
			return ret;
		}

		ret = tsn_port_init_finish_set(tsn, TSN_PORT_INIT_ENABLE);
		if (ret) {
			DH_LOG_ERR(MODULE_TSN, "[ErrorCode: %d] !\n", ret);
			return ret;
		}

		memcpy(&tsn->tsn_qbv_conf[ram_n_idle], tsn_qbv_conf,
		       sizeof(struct zxdh_tsn_qbv_conf));

		DH_LOG_INFO(MODULE_TSN, "tsn port id %u ram %u is enable.\n",
			    tsn->tsn_port_id.port_id, ram_n_idle);
	} else {
		ret = zxdh_tsn_qbv_cycle_time_extension_cal(
			tsn, &tsn->tsn_qbv_conf[TSN_RAM_N_IN_SERVICE(ram_n_idle)], tsn_qbv_conf,
			&cycle_time_extension);
		if (ret) {
			DH_LOG_ERR(MODULE_TSN, "[ErrorCode: %d] !\n", ret);
			return ret;
		}

		memcpy(&tsn->tsn_qbv_conf[ram_n_idle], tsn_qbv_conf,
		       sizeof(struct zxdh_tsn_qbv_conf));

		expires_in_nanosecond = tsn->tsn_qbv_conf[ram_n_idle].admin.base_time -
					cycle_time_extension - TSN_TIMER_RESERVED_TIME -
					real_tod_time;
		hrtimer_start(&tsn->tsn_qbv_change_timer, ns_to_ktime(expires_in_nanosecond),
			      HRTIMER_MODE_REL);

		DH_LOG_INFO(MODULE_TSN, "tsn port id %u timer wake up in %llu ns later.\n",
			    tsn->tsn_port_id.port_id, expires_in_nanosecond);
		// }
	}

	return TSN_OK;
}

static s32 zxdh_tsn_qbv_status_get(struct zxdh_tsn_private *tsn, struct zxdh_tsn_msg *msg)
{
	s32 ret = 0;
	u32 ram_n_idle = 0;
	struct zxdh_tsn_qbv_status *tsn_qbv_status;

	if (msg->len != (u32)sizeof(struct zxdh_tsn_qbv_status)) {
		DH_LOG_ERR(MODULE_TSN, "[Error: VALUE %u INVALID] [EQUAL %u] !\n", msg->len,
			   (u32)sizeof(struct zxdh_tsn_qbv_conf));
		return -EINVAL;
	}

	tsn_qbv_status = (struct zxdh_tsn_qbv_status *)msg->data;
	if (!tsn_qbv_status) {
		DH_LOG_ERR(MODULE_TSN, "[Error: POINT NULL] !\n");
		return -EINVAL;
	}

	ret = zxdh_tsn_qbv_gate_status_get(tsn, &ram_n_idle, &tsn_qbv_status->current_status);
	if (ret) {
		DH_LOG_ERR(MODULE_TSN, "[ErrorCode: %d] !\n", ret);
		return ret;
	}

	ret = tsn_port_real_tod_time_get(tsn, &tsn_qbv_status->current_time);
	if (ret) {
		DH_LOG_ERR(MODULE_TSN, "[ErrorCode: %d] !\n", ret);
		return ret;
	}

	memcpy(&tsn_qbv_status->oper, &tsn->tsn_qbv_conf[TSN_RAM_N_IN_SERVICE(ram_n_idle)].admin,
	       sizeof(struct zxdh_tsn_qbv_basic));

	return TSN_OK;
}

static s32 zxdh_tsn_qbv_cycle_time_extension_set(struct zxdh_tsn_private *tsn,
						 struct zxdh_tsn_qbv_conf *tsn_qbv_conf,
						 u64 cycle_time_extension, u32 ram_n_idle)
{
	s32 ret = 0;
	u32 index = 0;
	u32 gate_state = 0;
	u32 change_gate_status = 0;
	u32 time_interval = 0;
	u64 real_tod_time = 0;
	u64 cycle_time_reserved = 0;

	ret = tsn_port_real_tod_time_get(tsn, &real_tod_time);
	if (ret) {
		DH_LOG_ERR(MODULE_TSN, "[ErrorCode: %d] !\n", ret);
		return ret;
	}

	memcpy(tsn_qbv_conf, &tsn->tsn_qbv_conf[TSN_RAM_N_IN_SERVICE(ram_n_idle)],
	       sizeof(struct zxdh_tsn_qbv_conf));

	if (cycle_time_extension > tsn_qbv_conf->admin.cycle_time) {
		cycle_time_reserved = cycle_time_extension - tsn_qbv_conf->admin.cycle_time;

		for (index = 0; index < TSN_PORT_GCL_EXT_NUM; index++) {
			gate_state = tsn_qbv_conf->admin.control_list[index].gate_state;
			time_interval = tsn_qbv_conf->admin.control_list[index].time_interval;

			ret = tsn_port_gcl_control_set(
				tsn, ram_n_idle, tsn_qbv_conf->admin.control_list_length + index,
				gate_state, time_interval);
			if (ret) {
				DH_LOG_ERR(MODULE_TSN, "[ErrorCode: %d] !\n", ret);
				return ret;
			}

			if (cycle_time_reserved > time_interval) {
				cycle_time_reserved = cycle_time_reserved - time_interval;
				continue;
			}
			break;
		}
	}

	tsn_qbv_conf->admin.base_time = tsn->tsn_qbv_conf[ram_n_idle].admin.base_time -
					cycle_time_extension + TSN_HW_RESERVED_TIME;
	tsn_qbv_conf->admin.cycle_time = cycle_time_extension - (2 * TSN_HW_RESERVED_TIME);
	tsn_qbv_conf->admin.control_list[0].time_interval -= TSN_HW_RESERVED_TIME;

	ret = zxdh_tsn_qbv_change_set(tsn, tsn_qbv_conf, ram_n_idle);
	if (ret) {
		DH_LOG_ERR(MODULE_TSN, "[ErrorCode: %d] !\n", ret);
		return ret;
	}

	change_gate_status = tsn_qbv_conf->admin.control_list[0].gate_state;
	ret = tsn_port_change_gate_set(tsn, change_gate_status);
	if (ret) {
		DH_LOG_ERR(MODULE_TSN, "[ErrorCode: %d] !\n", ret);
		return ret;
	}

	ret = tsn_port_gcl_num_set(tsn, ram_n_idle,
				   tsn_qbv_conf->admin.control_list_length + index + 1);
	if (ret) {
		DH_LOG_ERR(MODULE_TSN, "[ErrorCode: %d] !\n", ret);
		return ret;
	}

	DH_LOG_INFO(MODULE_TSN,
		    "tsn port id %u admin_base_time %llu real_tod_time %llu diff %llu.\n",
		    tsn->tsn_port_id.port_id, tsn_qbv_conf->admin.base_time, real_tod_time,
		    tsn_qbv_conf->admin.base_time - real_tod_time);
	DH_LOG_INFO(MODULE_TSN, "tsn port id %u ram %u is going to change in timer.\n",
		    tsn->tsn_port_id.port_id, ram_n_idle);

	return TSN_OK;
}

enum hrtimer_restart zxdh_tsn_qbv_change_timer_callback(struct hrtimer *t)
{
	s32 ret = 0;
	u32 change_en = 0;
	u32 change_gate_status = 0;
	u32 ram_n_idle = 0;
	u32 status = 0;
	u64 real_tod_time = 0;
	u64 cycle_time_extension = 0;
	struct zxdh_tsn_private *tsn = NULL;
	struct zxdh_tsn_qbv_conf *tsn_qbv_conf = NULL;

	tsn = container_of(t, struct zxdh_tsn_private, tsn_qbv_change_timer);
	if (!tsn) {
		DH_LOG_ERR(MODULE_TSN, "[Error: POINT NULL] !\n");
		return HRTIMER_NORESTART;
	}

	spin_lock(&tsn->tsn_spin_lock);

	tsn_qbv_conf = kzalloc(sizeof(struct zxdh_tsn_qbv_conf), GFP_KERNEL);
	if (!tsn_qbv_conf) {
		DH_LOG_ERR(MODULE_TSN, "[Error: POINT NULL] !\n");
		spin_unlock(&tsn->tsn_spin_lock);
		return HRTIMER_NORESTART;
	}

	ret = zxdh_tsn_qbv_gate_status_get(tsn, &ram_n_idle, &status);
	if (ret) {
		DH_LOG_ERR(MODULE_TSN, "[ErrorCode: %d] !\n", ret);
		spin_unlock(&tsn->tsn_spin_lock);
		kfree(tsn_qbv_conf);
		return HRTIMER_NORESTART;
	}

	ret = zxdh_tsn_qbv_cycle_time_extension_cal(
		tsn, &tsn->tsn_qbv_conf[TSN_RAM_N_IN_SERVICE(ram_n_idle)],
		&tsn->tsn_qbv_conf[ram_n_idle], &cycle_time_extension);
	if (ret) {
		DH_LOG_ERR(MODULE_TSN, "[ErrorCode: %d] !\n", ret);
		spin_unlock(&tsn->tsn_spin_lock);
		kfree(tsn_qbv_conf);
		return HRTIMER_NORESTART;
	}

	ret = zxdh_tsn_qbv_cycle_time_extension_set(tsn, tsn_qbv_conf, cycle_time_extension,
						    ram_n_idle);
	if (ret) {
		DH_LOG_ERR(MODULE_TSN, "[ErrorCode: %d] !\n", ret);
		spin_unlock(&tsn->tsn_spin_lock);
		kfree(tsn_qbv_conf);
		return HRTIMER_NORESTART;
	}

	ret = readx_poll_timeout_atomic(readl,
					((void *)(tsn->tsn_reg_base_addr + TSN_PORT_CHANGE_EN)),
					change_en, (change_en == 0), 1,
					(TSN_TIMER_RESERVED_TIME * 2));
	if (ret) {
		DH_LOG_ERR(MODULE_TSN, "[ErrorCode: %d] !\n", ret);
		spin_unlock(&tsn->tsn_spin_lock);
		kfree(tsn_qbv_conf);
		return HRTIMER_NORESTART;
	}

	change_gate_status =
		tsn_qbv_conf->admin.control_list[tsn_qbv_conf->admin.control_list_length - 1]
			.gate_state;

	ret = tsn_port_real_tod_time_get(tsn, &real_tod_time);
	if (ret) {
		DH_LOG_ERR(MODULE_TSN, "[ErrorCode: %d] !\n", ret);
		spin_unlock(&tsn->tsn_spin_lock);
		kfree(tsn_qbv_conf);
		return HRTIMER_NORESTART;
	}

	memcpy(tsn_qbv_conf, &tsn->tsn_qbv_conf[ram_n_idle], sizeof(struct zxdh_tsn_qbv_conf));
	memcpy(&tsn->tsn_qbv_conf[ram_n_idle], &tsn->tsn_qbv_conf[TSN_RAM_N_IN_SERVICE(ram_n_idle)],
	       sizeof(struct zxdh_tsn_qbv_conf));

	ret = zxdh_tsn_qbv_gate_status_get(tsn, &ram_n_idle, &status);
	if (ret) {
		DH_LOG_ERR(MODULE_TSN, "[ErrorCode: %d] !\n", ret);
		spin_unlock(&tsn->tsn_spin_lock);
		kfree(tsn_qbv_conf);
		return HRTIMER_NORESTART;
	}

	ret = zxdh_tsn_qbv_change_set(tsn, tsn_qbv_conf, ram_n_idle);
	if (ret) {
		DH_LOG_ERR(MODULE_TSN, "[ErrorCode: %d] !\n", ret);
		spin_unlock(&tsn->tsn_spin_lock);
		kfree(tsn_qbv_conf);
		return HRTIMER_NORESTART;
	}

	ret = tsn_port_change_gate_set(tsn, change_gate_status);
	if (ret) {
		DH_LOG_ERR(MODULE_TSN, "[ErrorCode: %d] !\n", ret);
		spin_unlock(&tsn->tsn_spin_lock);
		kfree(tsn_qbv_conf);
		return HRTIMER_NORESTART;
	}

	memcpy(&tsn->tsn_qbv_conf[ram_n_idle], tsn_qbv_conf, sizeof(struct zxdh_tsn_qbv_conf));

	DH_LOG_INFO(MODULE_TSN,
		    "tsn port id %u admin_base_time %llu real_tod_time %llu diff %llu.\n",
		    tsn->tsn_port_id.port_id, tsn_qbv_conf->admin.base_time, real_tod_time,
		    tsn_qbv_conf->admin.base_time - real_tod_time);

	kfree(tsn_qbv_conf);

	spin_unlock(&tsn->tsn_spin_lock);

	DH_LOG_INFO(MODULE_TSN, "tsn port id %u ram %u is going to change in timer.\n",
		    tsn->tsn_port_id.port_id, ram_n_idle);

	return HRTIMER_NORESTART;
}

static struct zxdh_tsn_ioctl_table tsn_ioctl_table[] = {
	{ TSN_PORT_ID_SET, zxdh_tsn_port_id_set },
	{ TSN_PORT_ID_GET, zxdh_tsn_port_id_get },
	{ TSN_TIMER_ID_SET, zxdh_tsn_timer_id_set },
	{ TSN_TIMER_ID_GET, zxdh_tsn_timer_id_get },
	{ TSN_QBV_CONF_SET, zxdh_tsn_qbv_set },
	{ TSN_QBV_STATUS_GET, zxdh_tsn_qbv_status_get },
};

s32 zxdh_en_tsn_func(struct net_device *netdev, struct ifreq *ifr)
{
	s32 ret = 0;
	u32 index = 0;
	u32 table_size = 0;
	u64 start_time = 0;
	u64 end_time = 0;
	unsigned long flags = 0;
	struct zxdh_en_priv *en_priv = NULL;
	struct zxdh_en_device *en_dev = NULL;
	struct zxdh_pf_device *pf_dev = NULL;
	struct zxdh_tsn_private *tsn = NULL;
	struct zxdh_tsn_msg *msg = NULL;

	if (!netdev) {
		DH_LOG_ERR(MODULE_TSN, "[Error: POINT NULL] !\n");
		return -EINVAL;
	}
	if (!ifr) {
		DH_LOG_ERR(MODULE_TSN, "[Error: POINT NULL] !\n");
		return -EINVAL;
	}

	en_priv = netdev_priv(netdev);
	if (!en_priv) {
		DH_LOG_ERR(MODULE_TSN, "[Error: POINT NULL] !\n");
		return -EINVAL;
	}

	en_dev = &en_priv->edev;
	if (!en_dev) {
		DH_LOG_ERR(MODULE_TSN, "[Error: POINT NULL] !\n");
		return -EINVAL;
	}

	pf_dev = dh_core_priv(en_dev->parent->parent);
	if (!pf_dev) {
		DH_LOG_ERR(MODULE_TSN, "[Error: POINT NULL] !\n");
		return -EINVAL;
	}

	tsn = pf_dev->tsn;
	if (!tsn) {
		DH_LOG_ERR(MODULE_TSN, "[Error: POINT NULL] !\n");
		return -EINVAL;
	}

	msg = kzalloc(sizeof(struct zxdh_tsn_msg), GFP_KERNEL);
	if (!msg) {
		DH_LOG_ERR(MODULE_TSN, "[Error: POINT NULL] !\n");
		return -EINVAL;
	}

	ret = unlikely(copy_from_user(msg, ifr->ifr_ifru.ifru_data, sizeof(struct zxdh_tsn_msg)));
	if (ret) {
		DH_LOG_ERR(MODULE_TSN, "[ErrorCode: %d] !\n", ret);
		kfree(msg);
		return ret;
	}

	table_size = (u32)(sizeof(tsn_ioctl_table) / sizeof(struct zxdh_tsn_ioctl_table));

	for (index = 0; index < table_size; index++) {
		if ((msg->cmd == tsn_ioctl_table[index].cmd) && tsn_ioctl_table[index].func) {
			spin_lock_irqsave(&tsn->tsn_spin_lock, flags);

			start_time = ktime_get_ns();

			ret = tsn_ioctl_table[index].func(tsn, msg);
			if (ret) {
				DH_LOG_ERR(MODULE_TSN, "[ErrorCode: %d] !\n", ret);
				spin_unlock_irqrestore(&tsn->tsn_spin_lock, flags);
				kfree(msg);
				return ret;
			}

			end_time = ktime_get_ns();

			spin_unlock_irqrestore(&tsn->tsn_spin_lock, flags);

			DH_LOG_INFO(MODULE_TSN, "tsn port id %u cmd %u total take up %lld ns.\n",
				    tsn->tsn_port_id.port_id, msg->cmd, end_time - start_time);
			break;
		}
	}

	if (index > table_size - 1) {
		DH_LOG_ERR(MODULE_TSN, "[Error: VALUE %u INVALID] [MAX %u] !\n", index,
			   table_size - 1);
		kfree(msg);
		return -EINVAL;
	}

	ret = unlikely(copy_to_user(ifr->ifr_ifru.ifru_data, msg, sizeof(struct zxdh_tsn_msg)));
	if (ret) {
		DH_LOG_ERR(MODULE_TSN, "[ErrorCode: %d] !\n", ret);
		kfree(msg);
		return ret;
	}

	kfree(msg);

	return TSN_OK;
}
EXPORT_SYMBOL_GPL(zxdh_en_tsn_func);
