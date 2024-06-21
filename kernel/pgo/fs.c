// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2019 Google, Inc.
 *
 * Author:
 *     Sami Tolvanen <samitolvanen@google.com>
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#define pr_fmt(fmt) "pgo: " fmt

#include <linux/kernel.h>
#include <linux/debugfs.h>
#include <linux/fs.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/elf.h>
#include "pgo.h"

#define NT_GNU_BUILD_ID 3

static struct dentry *directory;

struct prf_private_data {
	void *buffer;
	unsigned long size;
};

/*
 * Elf note section
 * The definition can be used in both 32-bit and 64-bit system,
 * because Elf32_Nhdr and Elf64_Nhdr are identical.
 */
extern Elf64_Nhdr __start_notes[];
extern Elf64_Nhdr __stop_notes[];

static u64 prf_binary_id_size(void);

/*
 * Raw profile data format:
 *
 *     - llvm_prf_header
 *     - binary_ids
 *     - __llvm_prf_data
 *     - __llvm_prf_cnts
 *     - __llvm_prf_names
 *     - zero padding to 8 bytes
 *     - for each llvm_prf_data in __llvm_prf_data:
 *             - llvm_prf_value_data
 *                     - llvm_prf_value_record + site count array
 *                             - llvm_prf_value_node_data
 *                             ...
 *                     ...
 *             ...
 */

static void prf_fill_header(void **buffer)
{
	struct llvm_prf_header *header = *(struct llvm_prf_header **)buffer;

#ifdef CONFIG_64BIT
	header->magic = LLVM_INSTR_PROF_RAW_MAGIC_64;
#else
	header->magic = LLVM_INSTR_PROF_RAW_MAGIC_32;
#endif
	header->version = LLVM_VARIANT_MASK_IR_PROF |
			  LLVM_INSTR_PROF_RAW_VERSION;
	header->binary_ids_size = prf_binary_id_size();
	header->data_size = prf_data_count();
	header->padding_bytes_before_counters = 0;
	header->counters_size = prf_cnts_count();
	header->padding_bytes_after_counters = 0;
	header->names_size = prf_names_count();
	header->counters_delta =
		(u64)__llvm_prf_cnts_start - (u64)__llvm_prf_data_start;
	header->names_delta = (u64)__llvm_prf_names_start;
	header->value_kind_last = LLVM_INSTR_PROF_IPVK_LAST;

	*buffer += sizeof(*header);
}

/*
 * Copy the source into the buffer, incrementing the pointer into buffer in the
 * process.
 */
static void prf_copy_to_buffer(void **buffer, const void *src,
			       unsigned long size)
{
	memcpy(*buffer, src, size);
	*buffer += size;
}

static u32 __prf_get_value_size(struct llvm_prf_data *p, u32 *value_kinds)
{
	struct llvm_prf_value_node **nodes =
		(struct llvm_prf_value_node **)p->values;
	u32 kinds = 0;
	u32 size = 0;
	unsigned int kind;
	unsigned int n;
	unsigned int s = 0;

	for (kind = 0; kind < ARRAY_SIZE(p->num_value_sites); kind++) {
		unsigned int sites = p->num_value_sites[kind];

		if (!sites)
			continue;

		/* Record + site count array */
		size += prf_get_value_record_size(sites);
		kinds++;

		if (!nodes)
			continue;

		for (n = 0; n < sites; n++) {
			u32 count = 0;
			struct llvm_prf_value_node *site = nodes[s + n];

			while (site && ++count <= U8_MAX)
				site = site->next;

			size += count * sizeof(struct llvm_prf_value_node_data);
		}

		s += sites;
	}

	if (size)
		size += sizeof(struct llvm_prf_value_data);

	if (value_kinds)
		*value_kinds = kinds;

	return size;
}

static u32 prf_get_value_size(void)
{
	u32 size = 0;
	struct llvm_prf_data *p;

	for (p = __llvm_prf_data_start; p < __llvm_prf_data_end; p++)
		size += __prf_get_value_size(p, NULL);

	return size;
}

/* Serialize the profiling's value. */
static void prf_serialize_value(struct llvm_prf_data *p, void **buffer)
{
	struct llvm_prf_value_data header;
	struct llvm_prf_value_node **nodes =
		(struct llvm_prf_value_node **)p->values;
	unsigned int kind;
	unsigned int n;
	unsigned int s = 0;

	header.total_size = __prf_get_value_size(p, &header.num_value_kinds);

	if (!header.num_value_kinds)
		/* Nothing to write. */
		return;

	prf_copy_to_buffer(buffer, &header, sizeof(header));

	for (kind = 0; kind < ARRAY_SIZE(p->num_value_sites); kind++) {
		struct llvm_prf_value_record *record;
		u8 *counts;
		unsigned int sites = p->num_value_sites[kind];

		if (!sites)
			continue;

		/* Profiling value record. */
		record = *(struct llvm_prf_value_record **)buffer;
		*buffer += prf_get_value_record_header_size();

		record->kind = kind;
		record->num_value_sites = sites;

		/* Site count array. */
		counts = *(u8 **)buffer;
		*buffer += prf_get_value_record_site_count_size(sites);

		/*
		  * If we don't have nodes, we can skip updating the site count
		  * array, because the buffer is zero filled.
		  */
		if (!nodes)
			continue;

		for (n = 0; n < sites; n++) {
			u32 count = 0;
			struct llvm_prf_value_node *site = nodes[s + n];

			while (site && ++count <= U8_MAX) {
				prf_copy_to_buffer(
					buffer, site,
					sizeof(struct llvm_prf_value_node_data));
				site = site->next;
			}

			counts[n] = (u8)count;
		}

		s += sites;
	}
}

static void prf_serialize_values(void **buffer)
{
	struct llvm_prf_data *p;

	for (p = __llvm_prf_data_start; p < __llvm_prf_data_end; p++)
		prf_serialize_value(p, buffer);
}

static inline unsigned long prf_get_padding(unsigned long size)
{
	return 7 & (sizeof(u64) - size % sizeof(u64));
}

#define foreach_build_id(process)                                             \
	Elf64_Nhdr *nhdr = __start_notes;                                     \
	while (nhdr < __stop_notes) {                                         \
		const char *note_name =                                       \
			(const char *)nhdr + sizeof(Elf64_Nhdr);              \
		if (nhdr->n_type == NT_GNU_BUILD_ID && nhdr->n_namesz == 4 && \
		    memcmp(note_name, "GNU\0", 4) == 0) {                     \
			process                                               \
		}                                                             \
		nhdr = (void *)nhdr + sizeof(Elf64_Nhdr) +                    \
		       roundup(nhdr->n_namesz, 4) +                           \
		       roundup(nhdr->n_descsz, 4);                            \
	}

static u64 prf_binary_id_size(void)
{
	u64 size = 0;

	foreach_build_id(size += sizeof(u64) + nhdr->n_descsz +
			prf_get_padding(nhdr->n_descsz);)
	return size;
}

static unsigned long prf_buffer_size(void)
{
	return sizeof(struct llvm_prf_header) +
			prf_binary_id_size() +
			prf_data_size() +
			prf_cnts_size() +
			prf_names_size() +
			prf_get_padding(prf_names_size()) +
			prf_get_value_size();
}

static void prf_fill_binary_id(void **buffer)
{
	foreach_build_id(
		u64 binary_id_len = nhdr->n_descsz;

		prf_copy_to_buffer(buffer, &binary_id_len, sizeof(u64));
		prf_copy_to_buffer(buffer,
				   note_name + roundup(nhdr->n_namesz, 4),
				   binary_id_len);
		*buffer += prf_get_padding(binary_id_len);
	)
}

/*
 * Serialize the profiling data into a format LLVM's tools can understand.
 * Note: caller *must* hold pgo_lock.
 */
static int prf_serialize(struct prf_private_data *p)
{
	int err = 0;
	void *buffer;

	p->size = prf_buffer_size();
	p->buffer = vzalloc(p->size);

	if (!p->buffer) {
		err = -ENOMEM;
		goto out;
	}

	buffer = p->buffer;

	prf_fill_header(&buffer);
	prf_fill_binary_id(&buffer);
	prf_copy_to_buffer(&buffer, __llvm_prf_data_start, prf_data_size());
	prf_copy_to_buffer(&buffer, __llvm_prf_cnts_start, prf_cnts_size());
	prf_copy_to_buffer(&buffer, __llvm_prf_names_start, prf_names_size());
	buffer += prf_get_padding(prf_names_size());

	prf_serialize_values(&buffer);

out:
	return err;
}

/* open() implementation for PGO. Creates a copy of the profiling data set. */
static int prf_open(struct inode *inode, struct file *file)
{
	struct prf_private_data *data;
	unsigned long flags;
	int err;

	data = kzalloc(sizeof(*data), GFP_KERNEL);
	if (!data) {
		err = -ENOMEM;
		goto out;
	}

	flags = prf_lock();

	err = prf_serialize(data);
	if (unlikely(err)) {
		kfree(data);
		goto out_unlock;
	}

	file->private_data = data;

out_unlock:
	prf_unlock(flags);
out:
	return err;
}

/* read() implementation for PGO. */
static ssize_t prf_read(struct file *file, char __user *buf, size_t count,
			loff_t *ppos)
{
	struct prf_private_data *data = file->private_data;

	BUG_ON(!data);

	return simple_read_from_buffer(buf, count, ppos, data->buffer,
				       data->size);
}

/* release() implementation for PGO. Release resources allocated by open(). */
static int prf_release(struct inode *inode, struct file *file)
{
	struct prf_private_data *data = file->private_data;

	if (data) {
		vfree(data->buffer);
		kfree(data);
	}

	return 0;
}

static const struct file_operations prf_fops = {
	.owner = THIS_MODULE,
	.open = prf_open,
	.read = prf_read,
	.llseek = default_llseek,
	.release = prf_release
};

/* write() implementation for resetting PGO's profile data. */
static ssize_t reset_write(struct file *file, const char __user *addr,
			   size_t len, loff_t *pos)
{
	struct llvm_prf_data *data;

	memset(__llvm_prf_cnts_start, 0, prf_cnts_size());

	for (data = __llvm_prf_data_start; data < __llvm_prf_data_end; data++) {
		struct llvm_prf_value_node **vnodes;
		u64 current_vsite_count;
		u32 i;

		if (!data->values)
			continue;

		current_vsite_count = 0;
		vnodes = (struct llvm_prf_value_node **)data->values;

		for (i = LLVM_INSTR_PROF_IPVK_FIRST;
		     i <= LLVM_INSTR_PROF_IPVK_LAST; i++)
			current_vsite_count += data->num_value_sites[i];

		for (i = 0; i < current_vsite_count; i++) {
			struct llvm_prf_value_node *current_vnode = vnodes[i];

			while (current_vnode) {
				current_vnode->count = 0;
				current_vnode = current_vnode->next;
			}
		}
	}

	return len;
}

static const struct file_operations prf_reset_fops = {
	.owner = THIS_MODULE,
	.write = reset_write,
	.llseek = noop_llseek,
};

/* Create debugfs entries. */
static int __init pgo_init(void)
{
	directory = debugfs_create_dir("pgo", NULL);
	if (!directory)
		goto err_remove;

	if (!debugfs_create_file("vmlinux.profraw", 0600, directory, NULL,
				 &prf_fops))
		goto err_remove;

	if (!debugfs_create_file("reset", 0200, directory, NULL,
				 &prf_reset_fops))
		goto err_remove;

	return 0;

err_remove:
	pr_err("initialization failed\n");
	return -EIO;
}

/* Remove debugfs entries. */
static void __exit pgo_exit(void)
{
	debugfs_remove_recursive(directory);
}

module_init(pgo_init);
module_exit(pgo_exit);
