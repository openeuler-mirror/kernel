// SPDX-License-Identifier: GPL-2.0
#include <kunit/test.h>

#include "pm_ping.h"

static void enfs_unstable_state_test(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, true, enfs_test_reconnect_time());
}

static void enfs_fault_recovery_state_test(struct kunit *test)
{
	KUNIT_EXPECT_TRUE(test, enfs_test_fault_recovery_state());
}

static struct kunit_case enfs_test_cases[] = {
	KUNIT_CASE(enfs_unstable_state_test),
	KUNIT_CASE(enfs_fault_recovery_state_test),
	{}
};

static struct kunit_suite enfs_suite = {
	.name = "enfs",
	.test_cases = enfs_test_cases,
};

kunit_test_suite(enfs_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for ENFS");
