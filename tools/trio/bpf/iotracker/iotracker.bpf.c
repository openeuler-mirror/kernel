// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2025 Huawei Technologies Co., Ltd
 */

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

enum {
	TAG_READ = 0,
	TAG_PRE_FAULT = 1,
	TAG_POST_FAULT = 2
};

extern void bpf_tracker_rio(unsigned long addr1, unsigned long addr2, int tag) __ksym;

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("kprobe/erofs_file_read_iter")
int BPF_KPROBE(erofs_file_read_iter_entry, struct kiocb *iocb,
	       struct iov_iter *to)
{
	struct kiocb *_iocb;
	struct iov_iter *_to;

	bpf_core_read(&_iocb, sizeof(struct kiocb *), &iocb);
	bpf_core_read(&_to, sizeof(struct iov_iter *), &to);

	bpf_tracker_rio((unsigned long)_iocb, (unsigned long)_to, TAG_READ);
	return 0;
}

SEC("kprobe/filemap_fault")
int BPF_KPROBE(filemap_fault_entry, struct vm_fault *vmf)
{
	struct vm_fault *_vmf;

	bpf_core_read(&_vmf, sizeof(struct vm_fault *), &vmf);
	bpf_tracker_rio((unsigned long)_vmf, 0, TAG_PRE_FAULT);
	return 0;
}

SEC("kprobe/finish_fault")
int BPF_KPROBE(finish_fault_entry, struct vm_fault *vmf)
{
	struct vm_fault *_vmf;

	bpf_core_read(&_vmf, sizeof(struct vm_fault *), &vmf);
	bpf_tracker_rio((unsigned long)_vmf, 0, TAG_POST_FAULT);
	return 0;
}
