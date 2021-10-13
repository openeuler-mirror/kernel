/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2021 Ramaxel Memory Technology, Ltd */

#ifndef SPHW_EQS_H
#define SPHW_EQS_H

#define SPHW_MAX_AEQS			4
#define SPHW_MAX_CEQS			32

#define SPHW_AEQ_MAX_PAGES		4
#define SPHW_CEQ_MAX_PAGES		8

#define SPHW_AEQE_SIZE		64
#define SPHW_CEQE_SIZE		4

#define SPHW_AEQE_DESC_SIZE		4
#define SPHW_AEQE_DATA_SIZE		\
			(SPHW_AEQE_SIZE - SPHW_AEQE_DESC_SIZE)

#define SPHW_DEFAULT_AEQ_LEN		4096
#define SPHW_DEFAULT_CEQ_LEN		8192

#define SPHW_MIN_EQ_PAGE_SIZE		0x1000   /* min eq page size 4K Bytes */
#define SPHW_MAX_EQ_PAGE_SIZE		0x400000 /* max eq page size 4M Bytes */

#define SPHW_MIN_AEQ_LEN		64
#define SPHW_MAX_AEQ_LEN		\
	((SPHW_MAX_EQ_PAGE_SIZE / SPHW_AEQE_SIZE) * SPHW_AEQ_MAX_PAGES)

#define SPHW_MIN_CEQ_LEN		64
#define SPHW_MAX_CEQ_LEN		\
	((SPHW_MAX_EQ_PAGE_SIZE / SPHW_CEQE_SIZE) * SPHW_CEQ_MAX_PAGES)
#define	SPHW_CEQ_ID_CMDQ		0

#define EQ_IRQ_NAME_LEN			64

#define EQ_USLEEP_LOW_BOUND		900
#define EQ_USLEEP_HIG_BOUND		1000

enum sphw_eq_type {
	SPHW_AEQ,
	SPHW_CEQ
};

enum sphw_eq_intr_mode {
	SPHW_INTR_MODE_ARMED,
	SPHW_INTR_MODE_ALWAYS,
};

enum sphw_eq_ci_arm_state {
	SPHW_EQ_NOT_ARMED,
	SPHW_EQ_ARMED,
};

struct sphw_eq_work {
	struct work_struct	work;
	void			*data;
};

struct sphw_ceq_tasklet_data {
	void	*data;
};

struct sphw_eq {
	struct sphw_hwdev		*hwdev;
	u16				q_id;
	enum sphw_eq_type		type;
	u32				page_size;
	u32				orig_page_size;
	u32				eq_len;

	u32				cons_idx;
	u16				wrapped;

	u16				elem_size;
	u16				num_pages;
	u32				num_elem_in_pg;

	struct irq_info			eq_irq;
	char				irq_name[EQ_IRQ_NAME_LEN];

	struct sphw_dma_addr_align	*eq_pages;

	struct sphw_eq_work		aeq_work;
	struct tasklet_struct		ceq_tasklet;
	struct sphw_ceq_tasklet_data	ceq_tasklet_data;

	u64				hard_intr_jif;
	u64				soft_intr_jif;
};

struct sphw_aeq_elem {
	u8	aeqe_data[SPHW_AEQE_DATA_SIZE];
	u32	desc;
};

enum sphw_aeq_cb_state {
	SPHW_AEQ_HW_CB_REG = 0,
	SPHW_AEQ_HW_CB_RUNNING,
	SPHW_AEQ_SW_CB_REG,
	SPHW_AEQ_SW_CB_RUNNING,
};

struct sphw_aeqs {
	struct sphw_hwdev	*hwdev;

	sphw_aeq_hwe_cb	aeq_hwe_cb[SPHW_MAX_AEQ_EVENTS];
	sphw_aeq_swe_cb	aeq_swe_cb[SPHW_MAX_AEQ_SW_EVENTS];
	unsigned long		aeq_hw_cb_state[SPHW_MAX_AEQ_EVENTS];
	unsigned long		aeq_sw_cb_state[SPHW_MAX_AEQ_SW_EVENTS];

	struct sphw_eq	aeq[SPHW_MAX_AEQS];
	u16			num_aeqs;
	struct workqueue_struct	*workq;
};

enum sphw_ceq_cb_state {
	SPHW_CEQ_CB_REG = 0,
	SPHW_CEQ_CB_RUNNING,
};

struct sphw_ceqs {
	struct sphw_hwdev	*hwdev;

	sphw_ceq_event_cb	ceq_cb[SPHW_MAX_CEQ_EVENTS];
	void			*ceq_data[SPHW_MAX_CEQ_EVENTS];
	unsigned long		ceq_cb_state[SPHW_MAX_CEQ_EVENTS];

	struct sphw_eq	ceq[SPHW_MAX_CEQS];
	u16			num_ceqs;
};

struct sphw_ceq_info {
	u32 q_len;
	u32 page_size;
	u16 elem_size;
	u16 num_pages;
	u32 num_elem_in_pg;
};

int sphw_aeqs_init(struct sphw_hwdev *hwdev, u16 num_aeqs, struct irq_info *msix_entries);

void sphw_aeqs_free(struct sphw_hwdev *hwdev);

int sphw_ceqs_init(struct sphw_hwdev *hwdev, u16 num_ceqs, struct irq_info *msix_entries);

void sphw_ceqs_free(struct sphw_hwdev *hwdev);

void sphw_get_ceq_irqs(struct sphw_hwdev *hwdev, struct irq_info *irqs, u16 *num_irqs);

void sphw_get_aeq_irqs(struct sphw_hwdev *hwdev, struct irq_info *irqs, u16 *num_irqs);

void sphw_dump_ceq_info(struct sphw_hwdev *hwdev);

void sphw_dump_aeq_info(struct sphw_hwdev *hwdev);

#endif
