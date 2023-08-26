/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _VM_OBJECT_H
#define _VM_OBJECT_H

#ifdef CONFIG_GMEM

static inline int __init vm_object_init(void) { return 0; }
static inline struct gm_mapping *vm_object_lookup(vm_object_t *obj, gm_va_t va) { return NULL; }
static inline int vm_object_mapping_create(vm_object_t *obj, gm_va_t start) { return 0; }

#endif

#endif /* _VM_OBJECT_H */
