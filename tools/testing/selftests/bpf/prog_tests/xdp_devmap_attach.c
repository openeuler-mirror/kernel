// SPDX-License-Identifier: GPL-2.0
#include <uapi/linux/bpf.h>
#include <linux/if_link.h>
#include <test_progs.h>

#include "test_xdp_devmap_helpers.skel.h"
#include "test_xdp_devmap_tailcall.skel.h"
#include "xdp_tailcall_devmap.skel.h"
#include "test_xdp_with_devmap_helpers.skel.h"

#define IFINDEX_LO 1

void test_xdp_with_devmap_helpers(void)
{
	struct test_xdp_with_devmap_helpers *skel;
	struct bpf_prog_info info = {};
	struct bpf_devmap_val val = {
		.ifindex = IFINDEX_LO,
	};
	__u32 len = sizeof(info);
	__u32 duration = 0, idx = 0;
	int err, dm_fd, map_fd;


	skel = test_xdp_with_devmap_helpers__open_and_load();
	if (CHECK_FAIL(!skel)) {
		perror("test_xdp_with_devmap_helpers__open_and_load");
		return;
	}

	/* can not attach program with DEVMAPs that allow programs
	 * as xdp generic
	 */
	dm_fd = bpf_program__fd(skel->progs.xdp_redir_prog);
	err = bpf_set_link_xdp_fd(IFINDEX_LO, dm_fd, XDP_FLAGS_SKB_MODE);
	CHECK(err == 0, "Generic attach of program with 8-byte devmap",
	      "should have failed\n");

	dm_fd = bpf_program__fd(skel->progs.xdp_dummy_dm);
	map_fd = bpf_map__fd(skel->maps.dm_ports);
	err = bpf_obj_get_info_by_fd(dm_fd, &info, &len);
	if (CHECK_FAIL(err))
		goto out_close;

	val.bpf_prog.fd = dm_fd;
	err = bpf_map_update_elem(map_fd, &idx, &val, 0);
	CHECK(err, "Add program to devmap entry",
	      "err %d errno %d\n", err, errno);

	err = bpf_map_lookup_elem(map_fd, &idx, &val);
	CHECK(err, "Read devmap entry", "err %d errno %d\n", err, errno);
	CHECK(info.id != val.bpf_prog.id, "Expected program id in devmap entry",
	      "expected %u read %u\n", info.id, val.bpf_prog.id);

	/* can not attach BPF_XDP_DEVMAP program to a device */
	err = bpf_set_link_xdp_fd(IFINDEX_LO, dm_fd, XDP_FLAGS_SKB_MODE);
	CHECK(err == 0, "Attach of BPF_XDP_DEVMAP program",
	      "should have failed\n");

	val.ifindex = 1;
	val.bpf_prog.fd = bpf_program__fd(skel->progs.xdp_dummy_prog);
	err = bpf_map_update_elem(map_fd, &idx, &val, 0);
	CHECK(err == 0, "Add non-BPF_XDP_DEVMAP program to devmap entry",
	      "should have failed\n");

out_close:
	test_xdp_with_devmap_helpers__destroy(skel);
}

void test_neg_xdp_devmap_helpers(void)
{
	struct test_xdp_devmap_helpers *skel;
	__u32 duration = 0;

	skel = test_xdp_devmap_helpers__open_and_load();
	if (CHECK(skel,
		  "Load of XDP program accessing egress ifindex without attach type",
		  "should have failed\n")) {
		test_xdp_devmap_helpers__destroy(skel);
	}
}

static void test_xdp_devmap_tailcall(enum bpf_attach_type prog_dev,
				     enum bpf_attach_type prog_tail,
				     bool expect_reject)
{
	struct test_xdp_devmap_tailcall *skel = NULL;
	struct xdp_tailcall_devmap *tailcall_skel = NULL;
	__u32 duration = 0, zero = 0;
	int err, map_fd, prog_fd;

	skel = test_xdp_devmap_tailcall__open();
	if (!ASSERT_OK_PTR(skel, "test_xdp_devmap_tailcall__open"))
		return;

	bpf_program__set_expected_attach_type(skel->progs.xdp_devmap, prog_dev);
	err = test_xdp_devmap_tailcall__load(skel);
	if (prog_dev == BPF_XDP_DEVMAP) {
		if (!ASSERT_OK(err, "test_xdp_devmap_tailcall__load"))
			goto out_close;
	} else {
		/*
		 * Will be rejected by verifier due to xdp_is_valid_access
		 * failure, because programs with expected_attach_type
		 * other than BPF_XDP_DEVMAP are not allowed to obtain
		 * ctx->egress_ifindex.
		 */
		ASSERT_ERR(err, "test_xdp_devmap_tailcall__load");
		goto out_close;
	}

	map_fd = bpf_map__fd(skel->maps.xdp_map);
	prog_fd = bpf_program__fd(skel->progs.xdp_devmap);
	err = bpf_map_update_elem(map_fd, &zero, &prog_fd, BPF_ANY);
	CHECK(err, "Add program to devmap entry",
	      "err %d errno %d\n", err, errno);

	tailcall_skel = xdp_tailcall_devmap__open();
	if (!ASSERT_OK_PTR(tailcall_skel, "xdp_tailcall_devmap__open"))
		goto out_close;

	bpf_map__reuse_fd(tailcall_skel->maps.xdp_map, map_fd);
	bpf_program__set_expected_attach_type(tailcall_skel->progs.xdp_entry,
					      prog_tail);

	err = xdp_tailcall_devmap__load(tailcall_skel);
	if (expect_reject)
		ASSERT_ERR(err, "xdp_tailcall_devmap__load");
	else
		ASSERT_OK(err, "xdp_tailcall_devmap__load");

out_close:
	test_xdp_devmap_tailcall__destroy(skel);
	xdp_tailcall_devmap__destroy(tailcall_skel);
}

void test_xdp_devmap_attach(void)
{
	if (test__start_subtest("DEVMAP with programs in entries"))
		test_xdp_with_devmap_helpers();

	if (test__start_subtest("Verifier check of DEVMAP programs")) {
		test_neg_xdp_devmap_helpers();
		test_xdp_devmap_tailcall(BPF_XDP_DEVMAP, BPF_XDP_DEVMAP, false);
		test_xdp_devmap_tailcall(0, 0, true);
		test_xdp_devmap_tailcall(BPF_XDP_DEVMAP, 0, true);
		test_xdp_devmap_tailcall(0, BPF_XDP_DEVMAP, true);
	}
}
