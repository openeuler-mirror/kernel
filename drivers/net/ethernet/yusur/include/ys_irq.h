/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __YS_IRQ_H_
#define __YS_IRQ_H_

#include <linux/interrupt.h>
#include <linux/notifier.h>

enum ys_irq_states {
	YS_IRQ_STATE_UNREGISTERED,
	YS_IRQ_STATE_REGISTERED
};

enum ys_irq_types {
	YS_IRQ_TYPE_QUEUE,
	YS_IRQ_TYPE_HW_PRIVATE
};

enum ys_irq_bh_types {
	YS_IRQ_BH_NONE,
	YS_IRQ_BH_THREADED,
	YS_IRQ_BH_WORK
};

enum ys_irq_nb_types {
	YS_IRQ_NB_REGISTER_FIXED,
	YS_IRQ_NB_REGISTER_ANY,
	YS_IRQ_NB_UNREGISTER
};

/*  struct ys_irq_sub - variable irq information
 *  @irq_type: type define in ys_irq_types
 *  @ndev: which net_device does the irq belongs to
 *  @handler: the irq handler
 *  @bh_type: the irq bottom half processing type
 *  @bh: the irq bottom half information
 *  @devname: an ascii name for the claiming device
 */
struct ys_irq_sub {
	int irq_type;
	struct net_device *ndev;
	irq_handler_t handler;
	int bh_type;
	union {
		irq_handler_t thread_fn;
		struct {
			struct work_struct work;
			work_func_t work_handler;
		};
	} bh;
	char *devname;
};

struct ys_irq_nb {
	int index;
	struct pci_dev *pdev;
	struct ys_irq_sub sub;
};

#define YS_IRQ_SUB_INIT(_irq_type, _ndev, _handler, _bh_type, _devname) \
	{ \
		.irq_type = (_irq_type), .ndev = (_ndev), \
		.handler = (_handler), .bh_type = (_bh_type), \
		.devname = (_devname), \
	}

#define YS_IRQ_NB_INIT(_index, _pdev, _irq_type, _ndev, _handler, _devname) \
	{ \
		.index = (_index), .pdev = (_pdev), \
		.sub = YS_IRQ_SUB_INIT((_irq_type), (_ndev), (_handler), \
				       YS_IRQ_BH_NONE, _devname) \
	}

#define YS_REGISTER_IRQ(_nh, _mode, _index, _pdev, _sub) \
	({ \
		int ret; \
		do { \
			struct ys_irq_nb irq_nb; \
			irq_nb.index = _index; \
			irq_nb.pdev = _pdev; \
			irq_nb.sub = _sub; \
			ret = blocking_notifier_call_chain((_nh), (_mode), \
							   &irq_nb); \
		} while (0); \
		ret; \
	})

#define YS_REGISTER_NONE_IRQ(_nh, _mode, _index, _pdev, _irq_type, \
	_ndev, _handler, _devname) \
	({ \
		int ret; \
		do { \
			struct ys_irq_nb irq_nb = YS_IRQ_NB_INIT(_index, \
				_pdev, _irq_type, _ndev, _handler, _devname); \
			ret = blocking_notifier_call_chain((_nh), (_mode), \
				&irq_nb); \
		} while (0); \
		ret; \
	})

#define YS_REGISTER_THREADED_IRQ(_nh, _mode, _index, _pdev, _irq_type, \
	_ndev, _handler, _func, _devname) \
	({ \
		int ret; \
		do { \
			struct ys_irq_nb irq_nb = YS_IRQ_NB_INIT(_index, \
				_pdev, _irq_type, _ndev, _handler, _devname); \
			irq_nb.sub.bh_type = YS_IRQ_BH_THREADED; \
			irq_nb.sub.bh.thread_fn = _func; \
			ret = blocking_notifier_call_chain((_nh), (_mode), \
							   &irq_nb); \
		} while (0); \
		ret; \
	})

#define YS_REGISTER_WORK_IRQ(_nh, _mode, _index, _pdev, _irq_type, \
	_ndev, _handler, _func, _devname) \
	({ \
		int ret; \
		do { \
			struct ys_irq_nb irq_nb = YS_IRQ_NB_INIT(_index, \
				_pdev, _irq_type, _ndev, _handler, _devname); \
			irq_nb.sub.bh_type = YS_IRQ_BH_WORK; \
			irq_nb.sub.bh.work_handler = _func; \
			ret = blocking_notifier_call_chain((_nh), (_mode), \
							   &irq_nb); \
		} while (0); \
		ret; \
	})

#define YS_UNREGISTER_IRQ(_nh, _index, _pdev) ({ \
	int ret; \
	do { \
		struct ys_irq_nb irq_nb = \
			YS_IRQ_NB_INIT(_index, _pdev, 0, NULL, NULL, NULL); \
		ret = blocking_notifier_call_chain((_nh), \
			YS_IRQ_NB_UNREGISTER, &irq_nb); \
	} while (0); \
	ret; \
})

#endif /* __YS_IRQ_H_ */
