/* SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB */
/* Copyright (c) 2018 - 2025 Beijing WangXun Technology Co., Ltd. */
#ifndef NSER_PROTOS_H
#define NSER_PROTOS_H

#define PAUSE_TIMER_VAL		0xffff
#define REFRESH_THRESHOLD	0x7fff
#define HIGH_THRESHOLD		0x800
#define LOW_THRESHOLD		0x200
#define ALL_TC2PFC		0xff
#define CQP_COMPL_WAIT_TIME_MS	10
#define CQP_TIMEOUT_THRESHOLD	500

/* init operations */
int nser_sc_dev_init(struct nser_sc_dev *dev, struct nser_device_init_info *info);
void nser_sc_cqp_post_sq(struct nser_sc_cqp *cqp);
__le64 *nser_sc_cqp_get_next_send_wqe(struct nser_sc_cqp *cqp, u64 scratch);
int nser_sc_mr_fast_register(struct nser_sc_qp *qp,
			      struct nser_fast_reg_stag_info *info,
			      bool post_sq);
void nser_init_config_check(struct nser_config_check *cc,
			     u8 traffic_class,
			     u16 qs_handle);
/* HMC/FPM functions */
int nser_sc_init_iw_hmc(struct nser_sc_dev *dev, u8 hmc_fn_id);
int nser_pf_init_vfhmc(struct nser_sc_dev *dev, u8 vf_hmc_fn_id);
/* stats misc */
int nser_cqp_gather_stats_cmd(struct nser_sc_dev *dev,
			       struct nser_vsi_pestat *pestat, bool wait);
void nser_cqp_gather_stats_gen1(struct nser_sc_dev *dev,
				 struct nser_vsi_pestat *pestat);
void nser_hw_stats_read_all(struct nser_vsi_pestat *stats,
			     const u64 *hw_stats_regs);
int nser_cqp_ws_node_cmd(struct nser_sc_dev *dev, u8 cmd,
			  struct nser_ws_node_info *node_info);
int nser_cqp_up_map_cmd(struct nser_sc_dev *dev, u8 cmd,
			 struct nser_up_info *map_info);

int nser_cqp_cnp_cmd(struct nser_sc_dev *dev, u8 cmd,
			 struct nser_cnp_info *cnp_info);

int nser_cqp_ceq_cmd(struct nser_sc_dev *dev, struct nser_sc_ceq *sc_ceq,
		      u8 op);
int nser_cqp_aeq_cmd(struct nser_sc_dev *dev, struct nser_sc_aeq *sc_aeq,
		      u8 op);
int nser_cqp_stats_inst_cmd(struct nser_sc_vsi *vsi, u8 cmd,
			     struct nser_stats_inst_info *stats_info);
u16 nser_alloc_ws_node_id(struct nser_sc_dev *dev);
void nser_free_ws_node_id(struct nser_sc_dev *dev, u16 node_id);
void nser_update_stats(struct nser_dev_hw_stats *hw_stats,
			struct nser_gather_stats *gather_stats,
			struct nser_gather_stats *last_gather_stats,
			const struct nser_hw_stat_map *map,
			u16 max_stat_idx);
/* vsi functions */
int nser_vsi_stats_init(struct nser_sc_vsi *vsi,
			 struct nser_vsi_stats_info *info);
void nser_vsi_stats_free(struct nser_sc_vsi *vsi);
void nser_sc_vsi_init(struct nser_sc_vsi *vsi,
		       struct nser_vsi_init_info *info);
int nser_sc_add_cq_ctx(struct nser_sc_ceq *ceq, struct nser_sc_cq *cq);
void nser_sc_remove_cq_ctx(struct nser_sc_ceq *ceq, struct nser_sc_cq *cq);
/* misc L2 param change functions */
void nser_change_l2params(struct nser_sc_vsi *vsi,
			   struct nser_l2params *l2params);
void nser_sc_suspend_resume_qps(struct nser_sc_vsi *vsi, u8 suspend);
int nser_cqp_qp_suspend_resume(struct nser_sc_qp *qp, u8 cmd);
void nser_qp_add_qos(struct nser_sc_qp *qp);
void nser_qp_rem_qos(struct nser_sc_qp *qp);
struct nser_sc_qp *nser_get_qp_from_list(struct list_head *head,
					   struct nser_sc_qp *qp);
void nser_reinitialize_ieq(struct nser_sc_vsi *vsi);
u16 nser_alloc_ws_node_id(struct nser_sc_dev *dev);
void nser_free_ws_node_id(struct nser_sc_dev *dev, u16 node_id);
struct nser_sc_vsi *nser_update_vsi_ctx(struct nser_sc_dev *dev,
					  struct nser_vfdev *vf_dev,
					  bool enable);
void nser_update_vf_vlan_cfg(struct nser_sc_dev *dev,
			      struct nser_vfdev *vf_dev);
/* dynamic memory allocation */
/* misc */
u8 nser_get_encoded_wqe_size(u32 wqsize, enum nser_queue_type queue_type);
void nser_modify_qp_to_err(struct nser_sc_qp *sc_qp);
int nser_sc_static_hmc_pages_allocated(struct nser_sc_cqp *cqp, u64 scratch,
					u8 hmc_fn_id, bool post_sq,
					bool poll_registers);
int nser_cfg_fpm_val(struct nser_sc_dev *dev);
int nser_get_rdma_features(struct nser_sc_dev *dev);
void free_sd_mem(struct nser_sc_dev *dev);
int nser_process_cqp_cmd(struct nser_sc_dev *dev,
			  struct cqp_cmds_info *pcmdinfo);
int nser_process_bh(struct nser_sc_dev *dev);
extern void dump_ctx(struct nser_sc_dev *dev, u32 pf_num, u32 qp_num);
void dumpCSR(struct nser_sc_dev *dev);
void dumpCSRx(struct nser_sc_dev *dev);
void dumpcls(struct nser_sc_dev *dev);
int nser_cqp_sds_cmd(struct nser_sc_dev *dev,
		      struct nser_update_sds_info *info);
int nser_cqp_query_fpm_val_cmd(struct nser_sc_dev *dev,
				struct nser_dma_mem *val_mem, u8 hmc_fn_id);
int nser_cqp_commit_fpm_val_cmd(struct nser_sc_dev *dev,
				 struct nser_dma_mem *val_mem, u8 hmc_fn_id);
int nser_alloc_query_fpm_buf(struct nser_sc_dev *dev,
			      struct nser_dma_mem *mem);
int nser_cqp_manage_hmc_fcn_cmd(struct nser_sc_dev *dev,
				 struct nser_hmc_fcn_info *hmcfcninfo,
				 u16 *pmf_idx);
int nser_set_attr_from_fragcnt(struct nser_sc_dev *dev, u8 max_fragcnt);
void *nser_remove_cqp_head(struct nser_sc_dev *dev);
#endif /* NSER_PROTOS_H */
