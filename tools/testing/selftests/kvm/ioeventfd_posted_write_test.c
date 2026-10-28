// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright Nutanix, 2026
 *
 * Author: Thanos Makatos <thanos.makatos@nutanix.com>
 */

#include <errno.h>
#include <poll.h>
#include <string.h>

#include "kvm_util.h"
#include "processor.h"
#include "ucall_common.h"

#define MMIO_GPA	(1UL << 30)
#define PIO_PORT	0xe000
#define TEST_VAL	0xDEADBEEFCAFEFEEDULL
#define MATCH_VAL	0x42U
#define NOMATCH_VAL	(MATCH_VAL + 1)
#define POISON_VAL	0xFFFFFFFFU

static void assert_ucall(struct kvm_vcpu *vcpu, uint64_t expected_cmd,
                         uint64_t expected_stage)
{
	struct ucall uc;

	TEST_ASSERT_KVM_EXIT_REASON(vcpu, KVM_EXIT_IO);

	switch (get_ucall(vcpu, &uc)) {
	case UCALL_ABORT:
		REPORT_GUEST_ASSERT(uc);
		break;
	case UCALL_SYNC:
		TEST_ASSERT(expected_cmd == UCALL_SYNC,
			    "got UCALL_SYNC, expected %lu",
			    expected_cmd);
		TEST_ASSERT(uc.args[1] == expected_stage,
			    "expected stage %lu, got %lu",
			    expected_stage, uc.args[1]);
		break;
	case UCALL_DONE:
		TEST_ASSERT(expected_cmd == UCALL_DONE,
			    "got UCALL_DONE, expected %lu",
			    expected_cmd);
		break;
	default:
		TEST_FAIL("unexpected ucall %lu", uc.cmd);
	}
}

/*
 * Verify that KVM_IOEVENTFD rejects invalid POST_WRITE configurations:
 *   - len=0: the kernel needs a non-zero length to know how many bytes to copy.
 *   - post_addr=NULL: there is no destination for the copy.
 *   - post_addr outside the process address space: access_ok() rejects it.
 *   - post_addr unaligned: IS_ALIGNED() rejects it
 * All three must fail with EINVAL.
 */
static void test_post_write_negative(void)
{
	struct kvm_ioeventfd ioeventfd;
	struct kvm_vm *vm;
	uint64_t dummy;
	int ret;
	int fd;

	vm = vm_create_barebones();
	fd = kvm_new_eventfd();

	/* length cannot be zero */
	ioeventfd = (struct kvm_ioeventfd) {
		.addr = MMIO_GPA,
		.len = 0,
		.fd = fd,
		.flags = KVM_IOEVENTFD_FLAG_POST_WRITE,
		.post_addr = (u64)&dummy,
	};
	ret = __vm_ioctl(vm, KVM_IOEVENTFD, &ioeventfd);
	TEST_ASSERT(ret && errno == EINVAL,
		    "len=0: expected EINVAL, got ret=%d errno=%d", ret, errno);

	/* post_addr cannot be NULL */
	ioeventfd.len = 4;
	ioeventfd.post_addr = 0ULL;
	ret = __vm_ioctl(vm, KVM_IOEVENTFD, &ioeventfd);
	TEST_ASSERT(ret && errno == EINVAL,
		    "NULL post_addr: expected EINVAL, got ret=%d errno=%d",
		    ret, errno);

	/* bogus post_addr */
	ioeventfd.post_addr = (u64)0xdeaddeaddeaddeadULL;
	ret = __vm_ioctl(vm, KVM_IOEVENTFD, &ioeventfd);
	TEST_ASSERT(ret && errno == EINVAL,
		    "bad post_addr: expected EINVAL, got ret=%d errno=%d",
		    ret, errno);

	/* unaligned post_addr */
	ioeventfd.post_addr = (uintptr_t)((char *)&dummy + 1);
	ioeventfd.len = sizeof dummy;
	ret = __vm_ioctl(vm, KVM_IOEVENTFD, &ioeventfd);
	TEST_ASSERT(ret && errno == EINVAL,
		    "bad post_addr: expected EINVAL, got ret=%d errno=%d",
		    ret, errno);

	close(fd);
	kvm_vm_free(vm);
}

#define DEFINE_GUEST_WRITE_FN(suffix, type)      \
static void guest_code_w##suffix(void) {         \
	*(volatile type *)MMIO_GPA = (type)TEST_VAL; \
	GUEST_DONE();                                \
}

DEFINE_GUEST_WRITE_FN(1, uint8_t)
DEFINE_GUEST_WRITE_FN(2, uint16_t)
DEFINE_GUEST_WRITE_FN(4, uint32_t)
DEFINE_GUEST_WRITE_FN(8, uint64_t)

/*
 * Verify that ioeventfd_write copies exactly @width bytes to post_addr for
 * each supported MMIO write width (1, 2, 4, 8).  The guest writes the low
 * @width bytes of TEST_VAL; the host checks that exactly those bytes land
 * at post_addr and the eventfd is signaled.
 */
static void test_post_write_width(int width, void (*guest_fn)(void))
{
	uint64_t actual, expected, count;
	struct kvm_ioeventfd ioeventfd;
	struct kvm_vcpu *vcpu;
	struct kvm_vm *vm;
	int fd, ret;

	/* need to initialize to 0 because the guest writes the low @width bytes */
	actual = 0;
	expected = 0;

	vm = vm_create_with_one_vcpu(&vcpu, guest_fn);
	virt_map(vm, MMIO_GPA, MMIO_GPA, 1);

	fd = kvm_new_eventfd();

	ioeventfd = (struct kvm_ioeventfd) {
		.addr = MMIO_GPA,
		.len = width,
		.fd = fd,
		.flags = KVM_IOEVENTFD_FLAG_POST_WRITE,
		.post_addr = (u64)&actual,
	};

	ret = __vm_ioctl(vm, KVM_IOEVENTFD, &ioeventfd);
	TEST_ASSERT(!ret, "KVM_IOEVENTFD failed: %s", strerror(errno));

	vcpu_run(vcpu);
	assert_ucall(vcpu, UCALL_DONE, 0);

	ret = read(fd, &count, sizeof(count));
	TEST_ASSERT(ret == sizeof(count),
		    "eventfd read failed: ret=%d errno=%d", ret, errno);

	memcpy(&expected, &(uint64_t){TEST_VAL}, width);
	TEST_ASSERT_EQ(actual, expected);

	close(fd);
	kvm_vm_free(vm);
}

static void guest_code_datamatch(void)
{
	*(volatile uint32_t *)MMIO_GPA = MATCH_VAL;
	GUEST_SYNC(1);
	*(volatile uint32_t *)MMIO_GPA = NOMATCH_VAL;
	GUEST_SYNC(2);
	GUEST_DONE();
}

/*
 * Test the interaction between DATAMATCH and POST_WRITE.  When both flags are
 * set, ioeventfd_write should only fire (signal eventfd + copy value) when the
 * written value matches datamatch.  A non-matching write must leave the eventfd
 * unsignaled and post_addr untouched, and fall through to KVM_EXIT_MMIO.
 */
static void test_post_write_datamatch(void)
{
	struct kvm_ioeventfd ioeventfd;
	struct kvm_vcpu *vcpu;
	struct kvm_run *run;
	struct kvm_vm *vm;
	struct pollfd pfd;
	uint64_t count;
	uint32_t actual;
	int fd, ret;

	actual = POISON_VAL;

	vm = vm_create_with_one_vcpu(&vcpu, guest_code_datamatch);
	virt_map(vm, MMIO_GPA, MMIO_GPA, 1);
	run = vcpu->run;

	fd = kvm_new_eventfd();
	pfd = (struct pollfd){ .fd = fd, .events = POLLIN };

	ioeventfd = (struct kvm_ioeventfd) {
		.datamatch = MATCH_VAL,
		.addr = MMIO_GPA,
		.len = 4,
		.fd = fd,
		.flags = KVM_IOEVENTFD_FLAG_POST_WRITE |
			 KVM_IOEVENTFD_FLAG_DATAMATCH,
		.post_addr = (u64)&actual,
	};

	ret = __vm_ioctl(vm, KVM_IOEVENTFD, &ioeventfd);
	TEST_ASSERT(!ret, "KVM_IOEVENTFD failed: %s", strerror(errno));

	/*
	 * Guest writes MATCH_VAL → ioeventfd fires (value copied, eventfd
	 * signaled), vCPU continues, then GUEST_SYNC(1).
	 */
	vcpu_run(vcpu);
	assert_ucall(vcpu, UCALL_SYNC, 1);
	TEST_ASSERT(read(fd, &count, sizeof(count)) == sizeof(count),
	            "eventfd read failed: errno=%d", errno);
	TEST_ASSERT_EQ(actual, MATCH_VAL);

	actual = POISON_VAL;

	/*
	 * Guest writes NOMATCH_VAL → ioeventfd_in_range() returns false, bus
	 * returns -EOPNOTSUPP → KVM_EXIT_MMIO to userspace.
	 */
	vcpu_run(vcpu);
	TEST_ASSERT_KVM_EXIT_REASON(vcpu, KVM_EXIT_MMIO);
	TEST_ASSERT(run->mmio.is_write, "expected MMIO write");
	TEST_ASSERT(run->mmio.phys_addr == MMIO_GPA,
	            "expected MMIO at 0x%lx, got 0x%llx",
	            MMIO_GPA, run->mmio.phys_addr);

	/* Re-enter: KVM completes the MMIO, guest runs to GUEST_SYNC(2). */
	vcpu_run(vcpu);
	assert_ucall(vcpu, UCALL_SYNC, 2);

	TEST_ASSERT(poll(&pfd, 1, 0) == 0,
	            "eventfd should not be signaled after non-matching write");
	TEST_ASSERT_EQ(actual, (uint32_t)POISON_VAL);

	vcpu_run(vcpu);
	assert_ucall(vcpu, UCALL_DONE, 0);

	close(fd);
	kvm_vm_free(vm);
}

static void guest_code_multi(void)
{
	*(volatile uint32_t *)MMIO_GPA = 0x11111111;
	GUEST_SYNC(1);
	*(volatile uint32_t *)MMIO_GPA = 0x22222222;
	GUEST_SYNC(2);
	*(volatile uint32_t *)MMIO_GPA = 0x33333333;
	GUEST_SYNC(3);
	GUEST_DONE();
}

/*
 * Verify that post_addr is updated on every MMIO write, not just the first.
 * The guest writes three distinct values in sequence; the host checks after
 * each one that post_addr holds the latest value and the eventfd is signaled
 * each time.
 */
static void test_post_write_multi(void)
{
	static const uint32_t expected[] = {
		0x11111111, 0x22222222, 0x33333333,
	};
	struct kvm_ioeventfd ioeventfd;
	struct kvm_vcpu *vcpu;
	struct kvm_vm *vm;
	uint64_t count;
	uint32_t actual;
	int fd, ret, i;

	actual = POISON_VAL;

	vm = vm_create_with_one_vcpu(&vcpu, guest_code_multi);
	virt_map(vm, MMIO_GPA, MMIO_GPA, 1);

	fd = kvm_new_eventfd();

	ioeventfd = (struct kvm_ioeventfd) {
		.addr = MMIO_GPA,
		.len = 4,
		.fd = fd,
		.flags = KVM_IOEVENTFD_FLAG_POST_WRITE,
		.post_addr = (u64)&actual,
	};

	ret = __vm_ioctl(vm, KVM_IOEVENTFD, &ioeventfd);
	TEST_ASSERT(!ret, "KVM_IOEVENTFD failed: %s", strerror(errno));

	for (i = 0; i < ARRAY_SIZE(expected); i++) {
		vcpu_run(vcpu);
		assert_ucall(vcpu, UCALL_SYNC, i + 1);
		TEST_ASSERT(read(fd, &count, sizeof(count)) == sizeof(count),
		            "eventfd read failed: errno=%d", errno);
		TEST_ASSERT_EQ(actual, expected[i]);
	}

	vcpu_run(vcpu);
	assert_ucall(vcpu, UCALL_DONE, 0);

	close(fd);
	kvm_vm_free(vm);
}

static void guest_code_multi_nosync(void)
{
	*(volatile uint32_t *)MMIO_GPA = 0x11111111;
	*(volatile uint32_t *)MMIO_GPA = 0x22222222;
	*(volatile uint32_t *)MMIO_GPA = 0x33333333;
	GUEST_DONE();
}

/*
 * Variant of the multi-write test where the guest performs three consecutive
 * MMIO writes with no GUEST_SYNC in between.  All three are handled in-kernel
 * by ioeventfd before the vCPU exits at GUEST_DONE.  Verify that:
 *   - post_addr reflects the last written value (0x33333333).
 *   - A single eventfd read() returns a counter of 3 (one signal per write).
 */
static void test_post_write_multi_nosync(void)
{
	struct kvm_ioeventfd ioeventfd;
	struct kvm_vcpu *vcpu;
	struct kvm_vm *vm;
	uint64_t count;
	uint32_t actual;
	int fd, ret;

	actual = POISON_VAL;

	vm = vm_create_with_one_vcpu(&vcpu, guest_code_multi_nosync);
	virt_map(vm, MMIO_GPA, MMIO_GPA, 1);

	fd = kvm_new_eventfd();

	ioeventfd = (struct kvm_ioeventfd) {
		.addr = MMIO_GPA,
		.len = 4,
		.fd = fd,
		.flags = KVM_IOEVENTFD_FLAG_POST_WRITE,
		.post_addr = (u64)&actual,
	};

	ret = __vm_ioctl(vm, KVM_IOEVENTFD, &ioeventfd);
	TEST_ASSERT(!ret, "KVM_IOEVENTFD failed: %s", strerror(errno));

	vcpu_run(vcpu);
	assert_ucall(vcpu, UCALL_DONE, 0);

	ret = read(fd, &count, sizeof(count));
	TEST_ASSERT(ret == sizeof(count),
		    "eventfd read failed: ret=%d errno=%d", ret, errno);
	TEST_ASSERT_EQ(count, (uint64_t)3);
	TEST_ASSERT_EQ(actual, (uint32_t)0x33333333);

	close(fd);
	kvm_vm_free(vm);
}

static void guest_code_deassign(void)
{
	*(volatile uint32_t *)MMIO_GPA = MATCH_VAL;
	GUEST_SYNC(1);
	*(volatile uint32_t *)MMIO_GPA = MATCH_VAL;
	GUEST_DONE();
}

/*
 * Verify that deassigning an ioeventfd with POST_WRITE fully removes it from
 * the I/O bus.
 */
static void test_post_write_deassign(void)
{
	struct kvm_ioeventfd ioeventfd;
	struct kvm_vcpu *vcpu;
	struct kvm_run *run;
	struct kvm_vm *vm;
	struct pollfd pfd;
	uint64_t count;
	uint32_t actual;
	int fd, ret;

	actual = POISON_VAL;

	vm = vm_create_with_one_vcpu(&vcpu, guest_code_deassign);
	virt_map(vm, MMIO_GPA, MMIO_GPA, 1);
	run = vcpu->run;

	fd = kvm_new_eventfd();
	pfd = (struct pollfd){ .fd = fd, .events = POLLIN };

	ioeventfd = (struct kvm_ioeventfd) {
		.addr = MMIO_GPA,
		.len = 4,
		.fd = fd,
		.flags = KVM_IOEVENTFD_FLAG_POST_WRITE,
		.post_addr = (u64)&actual,
	};

	ret = __vm_ioctl(vm, KVM_IOEVENTFD, &ioeventfd);
	TEST_ASSERT(!ret, "KVM_IOEVENTFD assign failed: %s", strerror(errno));

	/*
	 * Guest writes MATCH_VAL → ioeventfd fires, then GUEST_SYNC(1).
	 */
	vcpu_run(vcpu);
	assert_ucall(vcpu, UCALL_SYNC, 1);
	TEST_ASSERT(read(fd, &count, sizeof(count)) == sizeof(count),
	            "eventfd read failed: errno=%d", errno);
	TEST_ASSERT_EQ(actual, MATCH_VAL);

	/* Deassign the ioeventfd. */
	ioeventfd.flags |= KVM_IOEVENTFD_FLAG_DEASSIGN;
	ret = __vm_ioctl(vm, KVM_IOEVENTFD, &ioeventfd);
	TEST_ASSERT(!ret, "KVM_IOEVENTFD deassign failed: %s", strerror(errno));

	actual = POISON_VAL;

	/*
	 * Guest writes MATCH_VAL again → no handler on the bus →
	 * KVM_EXIT_MMIO to userspace.
	 */
	vcpu_run(vcpu);
	TEST_ASSERT_KVM_EXIT_REASON(vcpu, KVM_EXIT_MMIO);
	TEST_ASSERT(run->mmio.is_write, "expected MMIO write");
	TEST_ASSERT(run->mmio.phys_addr == MMIO_GPA,
	            "expected MMIO at 0x%lx, got 0x%llx",
	            MMIO_GPA, run->mmio.phys_addr);

	/* Re-enter: KVM completes MMIO, guest runs to GUEST_DONE. */
	vcpu_run(vcpu);
	assert_ucall(vcpu, UCALL_DONE, 0);

	TEST_ASSERT(poll(&pfd, 1, 0) == 0,
		    "eventfd should not be signaled after deassign");
	TEST_ASSERT_EQ(actual, (uint32_t)POISON_VAL);

	close(fd);
	kvm_vm_free(vm);
}

#ifdef __x86_64__
static void guest_code_pio(void)
{
	outl(PIO_PORT, (uint32_t)TEST_VAL);
	GUEST_DONE();
}

/*
 * Verify that POST_WRITE works on the PIO bus (KVM_PIO_BUS), not just MMIO.
 * The guest does an outl to PIO_PORT; the host checks that the written value
 * is copied to post_addr and the eventfd is signaled.
 */
static void test_post_write_pio(void)
{
	struct kvm_ioeventfd ioeventfd;
	struct kvm_vcpu *vcpu;
	struct kvm_vm *vm;
	uint64_t count;
	uint32_t actual;
	int fd, ret;

	actual = POISON_VAL;

	vm = vm_create_with_one_vcpu(&vcpu, guest_code_pio);

	fd = kvm_new_eventfd();

	ioeventfd = (struct kvm_ioeventfd) {
		.addr = PIO_PORT,
		.len = 4,
		.fd = fd,
		.flags = KVM_IOEVENTFD_FLAG_POST_WRITE |
			 KVM_IOEVENTFD_FLAG_PIO,
		.post_addr = (u64)&actual,
	};

	ret = __vm_ioctl(vm, KVM_IOEVENTFD, &ioeventfd);
	TEST_ASSERT(!ret, "KVM_IOEVENTFD failed: %s", strerror(errno));

	vcpu_run(vcpu);
	assert_ucall(vcpu, UCALL_DONE, 0);

	ret = read(fd, &count, sizeof(count));
	TEST_ASSERT(ret == sizeof(count),
	            "eventfd read failed: ret=%d errno=%d", ret, errno);

	TEST_ASSERT_EQ(actual, (uint32_t)TEST_VAL);

	close(fd);
	kvm_vm_free(vm);
}

static void guest_code_pio_datamatch(void)
{
	outl(PIO_PORT, MATCH_VAL);
	GUEST_SYNC(1);
	outl(PIO_PORT, NOMATCH_VAL);
	GUEST_SYNC(2);
	GUEST_DONE();
}

/*
 * Test POST_WRITE + PIO + DATAMATCH together.  When all three flags are set,
 * the ioeventfd should only fire when the outl value matches datamatch.
 * A non-matching outl must fall through to KVM_EXIT_IO (port I/O exit),
 * leaving the eventfd unsignaled and post_addr untouched.
 */
static void test_post_write_pio_datamatch(void)
{
	struct kvm_ioeventfd ioeventfd;
	struct kvm_vcpu *vcpu;
	struct kvm_run *run;
	struct kvm_vm *vm;
	struct pollfd pfd;
	uint64_t count;
	uint32_t actual;
	int fd, ret;

	actual = POISON_VAL;

	vm = vm_create_with_one_vcpu(&vcpu, guest_code_pio_datamatch);
	run = vcpu->run;

	fd = kvm_new_eventfd();
	pfd = (struct pollfd){ .fd = fd, .events = POLLIN };

	ioeventfd = (struct kvm_ioeventfd) {
		.datamatch = MATCH_VAL,
		.addr = PIO_PORT,
		.len = 4,
		.fd = fd,
		.flags = KVM_IOEVENTFD_FLAG_POST_WRITE |
		         KVM_IOEVENTFD_FLAG_PIO |
		         KVM_IOEVENTFD_FLAG_DATAMATCH,
		.post_addr = (u64)&actual,
	};

	ret = __vm_ioctl(vm, KVM_IOEVENTFD, &ioeventfd);
	TEST_ASSERT(!ret, "KVM_IOEVENTFD failed: %s", strerror(errno));

	/*
	 * Guest does outl MATCH_VAL → ioeventfd fires, then GUEST_SYNC(1).
	 */
	vcpu_run(vcpu);
	assert_ucall(vcpu, UCALL_SYNC, 1);
	TEST_ASSERT(read(fd, &count, sizeof(count)) == sizeof(count),
	            "eventfd read failed: errno=%d", errno);
	TEST_ASSERT_EQ(actual, MATCH_VAL);

	actual = POISON_VAL;

	/*
	 * Guest does outl NOMATCH_VAL → no match → KVM_EXIT_IO.
	 */
	vcpu_run(vcpu);
	TEST_ASSERT_KVM_EXIT_REASON(vcpu, KVM_EXIT_IO);
	TEST_ASSERT(run->io.direction == KVM_EXIT_IO_OUT,
	            "expected PIO write");
	TEST_ASSERT(run->io.port == PIO_PORT,
	            "expected PIO at 0x%x, got 0x%x",
	            PIO_PORT, run->io.port);

	/* Re-enter: guest continues to GUEST_SYNC(2). */
	vcpu_run(vcpu);
	assert_ucall(vcpu, UCALL_SYNC, 2);

	TEST_ASSERT(poll(&pfd, 1, 0) == 0,
		    "eventfd should not be signaled after non-matching PIO write");
	TEST_ASSERT_EQ(actual, (uint32_t)POISON_VAL);

	/* GUEST_DONE */
	vcpu_run(vcpu);
	assert_ucall(vcpu, UCALL_DONE, 0);

	close(fd);
	kvm_vm_free(vm);
}
#endif

int main(void)
{
	TEST_REQUIRE(kvm_check_cap(KVM_CAP_IOEVENTFD_POST_WRITE));

	test_post_write_negative();

	test_post_write_width(1, guest_code_w1);
	test_post_write_width(2, guest_code_w2);
	test_post_write_width(4, guest_code_w4);
	test_post_write_width(8, guest_code_w8);

	test_post_write_datamatch();

	test_post_write_multi();

	test_post_write_multi_nosync();

	test_post_write_deassign();

#ifdef __x86_64__
	test_post_write_pio();
	test_post_write_pio_datamatch();
#endif

	return 0;
}
