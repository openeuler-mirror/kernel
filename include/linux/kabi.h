/* SPDX-License-Identifier: GPL-2.0 */
/*
 * kabi.h - openEuler kABI abstraction header
 *
 * Copyright (c) 2014 Don Zickus
 * Copyright (c) 2015-2018 Jiri Benc
 * Copyright (c) 2015 Sabrina Dubroca, Hannes Frederic Sowa
 * Copyright (c) 2016-2018 Prarit Bhargava
 * Copyright (c) 2017 Paolo Abeni, Larry Woodman
 * Copyright (c) 2021 Xie XiuQi <xiexiuqi@huawei.com>
 *
 * This file is released under the GPLv2.
 * See the file COPYING for more details.
 *
 * These kabi macros hide the changes from the kabi checker and from the
 * process that computes the exported symbols' checksums.
 * They have 2 variants: one (defined under __GENKSYMS__) used when
 * generating the checksums, and the other used when building the kernel's
 * binaries.
 *
 * The use of these macros does not guarantee that the usage and modification
 * of code is correct.  As with all openEuler only changes, an engineer must
 * explain why the use of the macro is valid in the patch containing the
 * changes.
 *
 * The macro helpers are derived from RHEL "include/linux/rh_kabi.h"
 * Mostly debrand from RHEL.
 */

#ifndef _LINUX_KABI_H
#define _LINUX_KABI_H

#include <linux/compiler.h>
#include <linux/stringify.h>

/*
 * NOTE
 *   Unless indicated otherwise, don't use ';' after these macros as it
 *   messes up the kABI checker by changing what the resulting token string
 *   looks like.  Instead let the macros add the ';' so it can be properly
 *   hidden from the kABI checker (mainly for KABI_EXTEND, but applied to
 *   most macros for uniformity).
 *
 * KABI_CONST
 *   Adds a new const modifier to a function parameter preserving the old
 *   checksum.
 *
 * KABI_ADD_MODIFIER
 *   Adds a new modifier to a function parameter or a typedef, preserving
 *   the old checksum.  Useful e.g. for adding rcu annotations or changing
 *   int to unsigned.  Beware that this may change the semantics; if you're
 *   sure this is safe, always explain why binary compatibility with 3rd
 *   party modules is retained.
 *
 * KABI_DEPRECATE
 *   Marks the element as deprecated and make it unusable by modules while
 *   keeping a hole in its place to preserve binary compatibility.
 *
 * # define KABI_BROKEN_INSERT_ENUM(_new)	_new,
 * # define KABI_BROKEN_REMOVE_ENUM(_orig)
 * KABI_DEPRECATE_FN
 *   Marks the function pointer as deprecated and make it unusable by modules
 *   while keeping a hole in its place to preserve binary compatibility.
 *
 * KABI_EXTEND
 *   Adds a new field to a struct.  This must always be added to the end of
 *   the struct.  Before using this macro, make sure this is actually safe
 *   to do - there is a number of conditions under which it is *not* safe.
 *   In particular (but not limited to), this macro cannot be used:
 *   - if the struct in question is embedded in another struct, or
 *   - if the struct is allocated by drivers either statically or
 *     dynamically, or
 *   - if the struct is allocated together with driver data (an example of
 *     such behavior is struct net_device or struct request).
 *
 * KABI_EXTEND_WITH_SIZE
 *   Adds a new element (usually a struct) to a struct and reserves extra
 *   space for the new element.  The provided 'size' is the total space to
 *   be added in longs (i.e. it's 8 * 'size' bytes), including the size of
 *   the added element.  It is automatically checked that the new element
 *   does not overflow the reserved space, now nor in the future. However,
 *   no attempt is done to check the content of the added element (struct)
 *   for kABI conformance - kABI checking inside the added element is
 *   effectively switched off.
 *   For any struct being added by KABI_EXTEND_WITH_SIZE, it is
 *   recommended its content to be documented as not covered by kABI
 *   guarantee.
 *
 * KABI_FILL_HOLE
 *   Fills a hole in a struct.
 *
 *   Warning: only use if a hole exists for _all_ arches.  Use pahole to verify.
 *
 * KABI_RENAME
 *   Renames an element without changing its type.  This macro can be used in
 *   bitfields, for example.
 *
 *   NOTE: does not include the final ';'
 *
 * KABI_REPLACE
 *   Replaces the _orig field by the _new field.  The size of the occupied
 *   space is preserved, it's fine if the _new field is smaller than the
 *   _orig field.  If a _new field is larger or has a different alignment,
 *   compilation will abort.
 *
 *
 * KABI_HIDE_INCLUDE
 *   Hides the given include file from kABI checksum computations.  This is
 *   used when a newly added #include makes a previously opaque struct
 *   visible.
 *
 *   Example usage:
 *   #include KABI_HIDE_INCLUDE(<linux/poll.h>)
 *
 * KABI_FAKE_INCLUDE
 *   Pretends inclusion of the given file for kABI checksum computations.
 *   This is used when upstream removed a particular #include but that made
 *   some structures opaque that were previously visible and is causing kABI
 *   checker failures.
 *
 *   Example usage:
 *   #include KABI_FAKE_INCLUDE(<linux/rhashtable.h>)
 *
 * KABI_RESERVE
 *   Adds a reserved field to a struct.  This is done prior to kABI freeze
 *   for structs that cannot be expanded later using KABI_EXTEND (for
 *   example because they are embedded in another struct or because they are
 *   allocated by drivers or because they use unusual memory layout).  The
 *   size of the reserved field is 'unsigned long' and is assumed to be
 *   8 bytes.
 *
 *   The argument is a number unique for the given struct; usually, multiple
 *   KABI_RESERVE macros are added to a struct with numbers starting from
 *   one.
 *
 *   Example usage:
 *   struct foo {
 *           int a;
 *           KABI_RESERVE(1)
 *           KABI_RESERVE(2)
 *   };
 *
 * KABI_USE
 *   Simple wrappers to replace standard openEuler reserved elements.
 *
 * KABI_AUX_EMBED
 * KABI_AUX_PTR
 *   Adds an extenstion of a struct in the form of "auxiliary structure".
 *   This is done prior to kABI freeze for structs that cannot be expanded
 *   later using KABI_EXTEND.  See also KABI_RESERVED, these two
 *   approaches can (and often are) combined.
 *
 *   To use this for 'struct foo' (the "base structure"), define a new
 *   structure called 'struct foo_resvd'; this new struct is called "auxiliary
 *   structure".  Then add KABI_AUX_EMBED or KABI_AUX_PTR to the end
 *   of the base structure.  The argument is the name of the base structure,
 *   without the 'struct' keyword.
 *
 *   KABI_AUX_PTR stores a pointer to the aux structure in the base
 *   struct.  The lifecycle of the aux struct needs to be properly taken
 *   care of.
 *
 *   KABI_AUX_EMBED embeds the aux struct into the base struct.  This
 *   cannot be used when the base struct is itself embedded into another
 *   struct, allocated in an array, etc.
 *
 *   Both approaches (ptr and embed) work correctly even when the aux struct
 *   is allocated by modules.  To ensure this, the code responsible for
 *   allocation/assignment of the aux struct has to properly set the size of
 *   the aux struct; see the KABI_AUX_SET_SIZE and KABI_AUX_INIT_SIZE
 *   macros.
 *
 *   New fields can be later added to the auxiliary structure, always to its
 *   end.  Note the auxiliary structure cannot be shrunk in size later (i.e.,
 *   fields cannot be removed, only deprecated).  Any code accessing fields
 *   from the aux struct must guard the access using the KABI_AUX macro.
 *   The access itself is then done via a '_resvd' field in the base struct.
 *
 *   The auxiliary structure is not guaranteed for access by modules unless
 *   explicitly commented as such in the declaration of the aux struct
 *   itself or some of its elements.
 *
 *   Example:
 *
 *   struct foo_resvd {
 *           int newly_added;
 *   };
 *
 *   struct foo {
 *           bool big_hammer;
 *           KABI_AUX_PTR(foo)
 *   };
 *
 *   void use(struct foo *f)
 *   {
 *           if (KABI_AUX(f, foo, newly_added))
 *                   f->_resvd->newly_added = 123;
 *	     else
 *	             // the field 'newly_added' is not present in the passed
 *	             // struct, fall back to old behavior
 *	             f->big_hammer = true;
 *   }
 *
 *   static struct foo_resvd my_foo_resvd {
 *           .newly_added = 0;
 *   }
 *
 *   static struct foo my_foo = {
 *           .big_hammer = false,
 *           ._resvd = &my_foo_resvd,
 *           KABI_AUX_INIT_SIZE(foo)
 *   };
 *
 * KABI_USE_AUX_PTR
 *   Creates an auxiliary structure post kABI freeze.  This works by using
 *   two reserved fields (thus there has to be two reserved fields still
 *   available) and converting them to KABI_AUX_PTR.
 *
 *   Example:
 *
 *   struct foo_resvd {
 *   };
 *
 *   struct foo {
 *           int a;
 *           KABI_RESERVE(1)
 *           KABI_USE_AUX_PTR(2, 3, foo)
 *   };
 *
 * KABI_AUX_SET_SIZE
 * KABI_AUX_INIT_SIZE
 *   Calculates and stores the size of the auxiliary structure.
 *
 *   KABI_AUX_SET_SIZE is for dynamically allocated base structs,
 *   KABI_AUX_INIT_SIZE is for statically allocated case structs.
 *
 *   These macros must be called from the allocation (KABI_AUX_SET_SIZE)
 *   or declaration (KABI_AUX_INIT_SIZE) site, regardless of whether
 *   that happens in the kernel or in a module.  Without calling one of
 *   these macros, the aux struct will appear to have no fields to the
 *   kernel.
 *
 *   Note: since KABI_AUX_SET_SIZE is intended to be invoked outside of
 *   a struct definition, it does not add the semicolon and must be
 *   terminated by semicolon by the caller.
 *
 * KABI_AUX
 *   Verifies that the given field exists in the given auxiliary structure.
 *   This MUST be called prior to accessing that field; failing to do that
 *   may lead to invalid memory access.
 *
 *   The first argument is a pointer to the base struct, the second argument
 *   is the name of the base struct (without the 'struct' keyword), the
 *   third argument is the field name.
 *
 *   This macro works for structs extended by either of KABI_AUX_EMBED,
 *   KABI_AUX_PTR and KABI_USE_AUX_PTR.
 *
 * KABI_FORCE_CHANGE
 *   Force change of the symbol checksum.  The argument of the macro is a
 *   version for cases we need to do this more than once.
 *
 *   This macro does the opposite: it changes the symbol checksum without
 *   actually changing anything about the exported symbol.  It is useful for
 *   symbols that are not whitelisted, we're changing them in an
 *   incompatible way and want to prevent 3rd party modules to silently
 *   corrupt memory.  Instead, by changing the symbol checksum, such modules
 *   won't be loaded by the kernel.  This macro should only be used as a
 *   last resort when all other KABI workarounds have failed.
 *
 * KABI_EXCLUDE
 *   !!! WARNING: DANGEROUS, DO NOT USE unless you are aware of all the !!!
 *   !!! implications. This should be used ONLY EXCEPTIONALLY and only  !!!
 *   !!! under specific circumstances. Very likely, this macro does not !!!
 *   !!! do what you expect it to do. Note that any usage of this macro !!!
 *   !!! MUST be paired with a KABI_FORCE_CHANGE annotation of          !!!
 *   !!! a suitable symbol (or an equivalent safeguard) and the commit  !!!
 *   !!! log MUST explain why the chosen solution is appropriate.       !!!
 *
 *   Exclude the element from checksum generation.  Any such element is
 *   considered not to be part of the kABI whitelist and may be changed at
 *   will.  Note however that it's the responsibility of the developer
 *   changing the element to ensure 3rd party drivers using this element
 *   won't panic, for example by not allowing them to be loaded.  That can
 *   be achieved by changing another, non-whitelisted symbol they use,
 *   either by nature of the change or by using KABI_FORCE_CHANGE.
 *
 *   Also note that any change to the element must preserve its size. Change
 *   of the size is not allowed and would constitute a silent kABI breakage.
 *   Beware that the KABI_EXCLUDE macro does not do any size checks.
 *
 * KABI_BROKEN_INSERT
 * KABI_BROKEN_REMOVE
 *   Insert a field to the middle of a struct / delete a field from a struct.
 *   Note that this breaks kABI! It can be done only when it's certain that
 *   no 3rd party driver can validly reach into the struct.  A typical
 *   example is a struct that is:  both (a) referenced only through a long
 *   chain of pointers from another struct that is part of a whitelisted
 *   symbol and (b) kernel internal only, it should have never been visible
 *   to genksyms in the first place.
 *
 *   Another example are structs that are explicitly exempt from kABI
 *   guarantee but we did not have enough foresight to use KABI_EXCLUDE.
 *   In this case, the warning for KABI_EXCLUDE applies.
 *
 *   A detailed explanation of correctness of every KABI_BROKEN_* macro
 *   use is especially important.
 *
 * KABI_BROKEN_INSERT_BLOCK
 * KABI_BROKEN_REMOVE_BLOCK
 *   A version of KABI_BROKEN_INSERT / REMOVE that allows multiple fields
 *   to be inserted or removed together.  All fields need to be terminated
 *   by ';' inside(!) the macro parameter.  The macro itself must not be
 *   terminated by ';'.
 *
 * KABI_BROKEN_REPLACE
 *   Replace a field by a different one without doing any checking.  This
 *   allows replacing a field by another with a different size.  Similarly
 *   to other KABI_BROKEN macros, use of this indicates a kABI breakage.
 *
 * KABI_BROKEN_INSERT_ENUM
 * KABI_BROKEN_REMOVE_ENUM
 *   Insert a field to the middle of an enumaration type / delete a field from
 *   an enumaration type. Note that this can break kABI especially if the
 *   number of enum fields is used in an array within a structure. It can be
 *   done only when it is certain that no 3rd party driver will use the
 *   enumeration type or a structure that embeds an array with size determined
 *   by an enumeration type.
 *
 * KABI_EXTEND_ENUM
 *   Adds a new field to an enumeration type.  This must always be added to
 *   the end of the enum.  Before using this macro, make sure this is actually
 *   safe to do.
 */
#ifdef __GENKSYMS__

# define KABI_CONST
# define KABI_ADD_MODIFIER(_new)
# define KABI_EXTEND(_new)
# define KABI_FILL_HOLE(_new)
# define KABI_FORCE_CHANGE(ver)		__attribute__((kabi_change ## ver))
# define KABI_RENAME(_orig, _new)		_orig
# define KABI_HIDE_INCLUDE(_file)		<linux/kabi.h>
# define KABI_FAKE_INCLUDE(_file)		_file
# define KABI_BROKEN_INSERT(_new)
# define KABI_BROKEN_REMOVE(_orig)		_orig;
# define KABI_BROKEN_INSERT_BLOCK(_new)
# define KABI_BROKEN_REMOVE_BLOCK(_orig)	_orig
# define KABI_BROKEN_REPLACE(_orig, _new)	_orig;
# define KABI_BROKEN_INSERT_ENUM(_new)
# define KABI_BROKEN_REMOVE_ENUM(_orig)	_orig,
# define KABI_EXTEND_ENUM(_new)

# define _KABI_DEPRECATE(_type, _orig)	_type _orig
# define _KABI_DEPRECATE_FN(_type, _orig, _args...)	_type (*_orig)(_args)
# define _KABI_REPLACE(_orig, _new)		_orig
# define _KABI_EXCLUDE(_elem)

#else

# define KABI_ALIGN_WARNING ".  Disable CONFIG_KABI_SIZE_ALIGN_CHECKS if debugging."

# define KABI_CONST				const
# define KABI_ADD_MODIFIER(_new)		_new
# define KABI_EXTEND(_new)			_new;
# define KABI_FILL_HOLE(_new)		_new;
# define KABI_FORCE_CHANGE(ver)
# define KABI_RENAME(_orig, _new)		_new
# define KABI_HIDE_INCLUDE(_file)		_file
# define KABI_FAKE_INCLUDE(_file)		<linux/kabi.h>
# define KABI_BROKEN_INSERT(_new)		_new;
# define KABI_BROKEN_REMOVE(_orig)
# define KABI_BROKEN_INSERT_BLOCK(_new)	_new
# define KABI_BROKEN_REMOVE_BLOCK(_orig)
# define KABI_BROKEN_REPLACE(_orig, _new)	_new;
# define KABI_BROKEN_INSERT_ENUM(_new)	_new,
# define KABI_BROKEN_REMOVE_ENUM(_orig)
# define KABI_EXTEND_ENUM(_new)		_new,

#if IS_BUILTIN(CONFIG_KABI_SIZE_ALIGN_CHECKS)
# define __KABI_CHECK_SIZE_ALIGN(_orig, _new)			\
	union {								\
		_Static_assert(sizeof(struct{_new;}) <= sizeof(struct{_orig;}), \
			       __FILE__ ":" __stringify(__LINE__) ": "  __stringify(_new) " is larger than " __stringify(_orig) KABI_ALIGN_WARNING); \
		_Static_assert(__alignof__(struct{_new;}) <= __alignof__(struct{_orig;}), \
			       __FILE__ ":" __stringify(__LINE__) ": "  __stringify(_orig) " is not aligned the same as " __stringify(_new) KABI_ALIGN_WARNING); \
	}
# define __KABI_CHECK_SIZE(_item, _size)				\
	_Static_assert(sizeof(struct{_item;}) <= _size,			\
		       __FILE__ ":" __stringify(__LINE__) ": " __stringify(_item) " is larger than the reserved size (" __stringify(_size) " bytes)" KABI_ALIGN_WARNING)
#else
# define __KABI_CHECK_SIZE_ALIGN(_orig, _new)
# define __KABI_CHECK_SIZE(_item, _size)
#endif

#define KABI_UNIQUE_ID __PASTE(kabi_hidden_, __LINE__)

# define _KABI_DEPRECATE(_type, _orig)	_type kabi_reserved_##_orig
# define _KABI_DEPRECATE_FN(_type, _orig, _args...)  \
	_type (* kabi_reserved_##_orig)(_args)
#ifdef CONFIG_KABI_RESERVE
# define _KABI_REPLACE(_orig, _new)			  \
	union {						  \
		_new;					  \
		struct {				  \
			_orig;				  \
		} KABI_UNIQUE_ID;			  \
		__KABI_CHECK_SIZE_ALIGN(_orig, _new);  \
	}
#else
# define _KABI_REPLACE(_orig, _new)		KABI_BROKEN_REPLACE(_orig, _new)
#endif

# define _KABI_EXCLUDE(_elem)		_elem

#endif /* __GENKSYMS__ */

/* semicolon added wrappers for the KABI_REPLACE macros */
# define KABI_DEPRECATE(_type, _orig)	_KABI_DEPRECATE(_type, _orig);
# define KABI_DEPRECATE_FN(_type, _orig, _args...)  \
	_KABI_DEPRECATE_FN(_type, _orig, _args);
# define KABI_REPLACE(_orig, _new)		_KABI_REPLACE(_orig, _new);
/*
 * Macro for breaking up a random element into two smaller chunks using an
 * anonymous struct inside an anonymous union.
 */
# define KABI_REPLACE2(orig, _new1, _new2)	KABI_REPLACE(orig, struct{ _new1; _new2;})

/*
 * We tried to standardize on openEuler reserved names.  These wrappers
 * leverage those common names making it easier to read and find in the
 * code.
 */
#ifdef CONFIG_KABI_RESERVE
# define _KABI_RESERVE(n)		u64 kabi_reserved##n
#else
# define _KABI_RESERVE(n)
#endif
# define KABI_RESERVE(n)		_KABI_RESERVE(n);
/*
 * Simple wrappers to replace standard openEuler reserved elements.
 */
# define KABI_USE(n, _new)		KABI_REPLACE(_KABI_RESERVE(n), _new)
/*
 * Macros for breaking up a reserved element into two smaller chunks using
 * an anonymous struct inside an anonymous union.
 */
# define KABI_USE2(n, _new1, _new2)	KABI_REPLACE(_KABI_RESERVE(n), struct{ _new1; _new2; })

#define KABI_EXCLUDE(_elem)		_KABI_EXCLUDE(_elem);

#define KABI_EXTEND_WITH_SIZE(_new, _size)				\
	KABI_EXTEND(union {						\
		_new;							\
		unsigned long KABI_UNIQUE_ID[_size];			\
		__KABI_CHECK_SIZE(_new, 8 * (_size));		\
	})

#define _KABI_AUX_PTR(_struct)					\
	size_t _struct##_size_resvd;					\
	_KABI_EXCLUDE(struct _struct##_resvd *_resvd)
#define KABI_AUX_PTR(_struct)					\
	_KABI_AUX_PTR(_struct);

#define _KABI_AUX_EMBED(_struct)					\
	size_t _struct##_size_resvd;					\
	_KABI_EXCLUDE(struct _struct##_resvd _resvd)
#define KABI_AUX_EMBED(_struct)					\
	_KABI_AUX_EMBED(_struct);

#define KABI_USE_AUX_PTR(n1, n2, _struct)				\
	KABI_USE(n1, n2,						\
		     struct { KABI_AUX_PTR(_struct) })

/*
 * KABI_AUX_SET_SIZE calculates and sets the size of the extended struct and
 * stores it in the size_resvd field for structs that are dynamically allocated.
 * This macro MUST be called when expanding a base struct with
 * KABI_SIZE_AND_EXTEND, and it MUST be called from the allocation site
 * regardless of being allocated in the kernel or a module.
 * Note: since this macro is intended to be invoked outside of a struct,
 * a semicolon is necessary at the end of the line where it is invoked.
 */
#define KABI_AUX_SET_SIZE(_name, _struct) ({				\
	(_name)->_struct##_size_resvd = sizeof(struct _struct##_resvd);	\
})

/*
 * KABI_AUX_INIT_SIZE calculates and sets the size of the extended struct and
 * stores it in the size_resvd field for structs that are statically allocated.
 * This macro MUST be called when expanding a base struct with
 * KABI_SIZE_AND_EXTEND, and it MUST be called from the declaration site
 * regardless of being allocated in the kernel or a module.
 */
#define KABI_AUX_INIT_SIZE(_struct)					\
	._struct##_size_resvd = sizeof(struct _struct##_resvd),

/*
 * KABI_AUX verifies allocated memory exists.  This MUST be called to
 * verify that memory in the _resvd struct is valid, and can be called
 * regardless if KABI_SIZE_AND_EXTEND or KABI_SIZE_AND_EXTEND_PTR is
 * used.
 */
#define KABI_AUX(_ptr, _struct, _field) ({				\
	size_t __off = offsetof(struct _struct##_resvd, _field);		\
	(_ptr)->_struct##_size_resvd > __off ? true : false;		\
})

#endif /* _LINUX_KABI_H */
