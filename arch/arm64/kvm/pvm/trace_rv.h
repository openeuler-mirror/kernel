/* SPDX-License-Identifier: GPL-2.0 */
#if !defined(_TRACE_RV_ARM64_KVM_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_RV_ARM64_KVM_H

#include <kvm/arm_rv_timer.h>
#include <linux/tracepoint.h>

#undef TRACE_SYSTEM
#define TRACE_SYSTEM kvm

TRACE_EVENT(kvm_rv_timer_update_irq,
	TP_PROTO(unsigned long vcpu_id, __u32 irq, int level),
	TP_ARGS(vcpu_id, irq, level),

	TP_STRUCT__entry(
		__field(unsigned long, vcpu_id)
		__field(__u32, irq)
		__field(int, level)
	),

	TP_fast_assign(
		__entry->vcpu_id	= vcpu_id;
		__entry->irq		= irq;
		__entry->level		= level;
	),

	TP_printk("VCPU: %lu, IRQ %u, level %d",
		  __entry->vcpu_id, __entry->irq, __entry->level)
);

TRACE_EVENT(kvm_rv_timer_put_state,
	TP_PROTO(struct rv_timer_context *ctx),
	TP_ARGS(ctx),

	TP_STRUCT__entry(
		__field(unsigned long, ctl)
		__field(unsigned long long, cval)
		__field(int, timer_idx)
	),

	TP_fast_assign(
		__entry->ctl			= rv_timer_get_ctl(ctx);
		__entry->cval			= rv_timer_get_cval(ctx);
		__entry->timer_idx		= rv_timer_ctx_index(ctx);
	),

	TP_printk("   CTL: %#08lx CVAL: %#16llx rv_timer_ctx_index: %d",
		  __entry->ctl,
		  __entry->cval,
		  __entry->timer_idx)
);

TRACE_EVENT(kvm_rv_timer_load_state,
	TP_PROTO(struct rv_timer_context *ctx),
	TP_ARGS(ctx),

	TP_STRUCT__entry(
		__field(unsigned long, ctl)
		__field(unsigned long long, cval)
		__field(int, timer_idx)
	),

	TP_fast_assign(
		__entry->ctl			= rv_timer_get_ctl(ctx);
		__entry->cval			= rv_timer_get_cval(ctx);
		__entry->timer_idx		= rv_timer_ctx_index(ctx);
	),

	TP_printk("CTL: %#08lx CVAL: %#16llx rv_timer_ctx_index: %d",
		  __entry->ctl,
		  __entry->cval,
		  __entry->timer_idx)
);

TRACE_EVENT(kvm_rv_timer_hrtimer_expire,
	TP_PROTO(struct rv_timer_context *ctx),
	TP_ARGS(ctx),

	TP_STRUCT__entry(
		__field(int, timer_idx)
	),

	TP_fast_assign(
		__entry->timer_idx		= rv_timer_ctx_index(ctx);
	),

	TP_printk("rv_timer_ctx_index: %d", __entry->timer_idx)
);

TRACE_EVENT(kvm_rv_timer_emulate,
	TP_PROTO(struct rv_timer_context *ctx, bool should_fire),
	TP_ARGS(ctx, should_fire),

	TP_STRUCT__entry(
		__field(int, timer_idx)
		__field(bool, should_fire)
	),

	TP_fast_assign(
		__entry->timer_idx		= rv_timer_ctx_index(ctx);
		__entry->should_fire		= should_fire;
	),

	TP_printk("rv_timer_ctx_index: %d (should_fire: %d)",
		  __entry->timer_idx, __entry->should_fire)
);

#endif /* _TRACE_RV_ARM64_KVM_H */

#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH ./pvm
#undef TRACE_INCLUDE_FILE
#define TRACE_INCLUDE_FILE trace_rv

/* This part must be outside protection */
#include <trace/define_trace.h>
