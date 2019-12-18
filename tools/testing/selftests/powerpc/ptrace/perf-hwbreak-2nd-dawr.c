#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/sysinfo.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <asm/ptrace.h>
#include <asm/unistd.h>
#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>
#include "utils.h"

#define EMISMATCH	0xffff

static volatile int a = 10;
static volatile int b = 10;
static volatile char c[512+8] __attribute__((aligned(512)));

int nprocs;

static void workload(void)
{
	a += 10;
	b += 10;
	c[512+1] += 'a';
}

/* This is just a test/target workload, not really a profiler. */
static int kernel_workload(void)
{
	struct perf_event_attr attr = {0};
	int fd;

	attr.type = PERF_TYPE_HARDWARE;
	attr.size = sizeof(struct perf_event_attr);
	attr.config = PERF_COUNT_HW_CPU_CYCLES;
	attr.disabled = 1;
	attr.exclude_kernel = 1;
	attr.exclude_hv = 1;
	attr.freq = 1;
	attr.sample_period = 0x1234;

	fd = syscall(__NR_perf_event_open, &attr, getpid(), -1, -1, 0);
	close(fd);
	return fd;
}

static void perf_user_event_attr_set(struct perf_event_attr *attr,
				__u32 type, __u64 addr, __u64 len)
{
	memset(attr, 0, sizeof(struct perf_event_attr));
	attr->type           = PERF_TYPE_BREAKPOINT;
	attr->size           = sizeof(struct perf_event_attr);
	attr->bp_type        = type;
	attr->bp_addr        = addr;
	attr->bp_len         = len;
	attr->exclude_kernel = 1;
	attr->exclude_hv     = 1;
	attr->exclude_guest  = 1;
}

static void perf_kernel_event_attr_set(struct perf_event_attr *attr,
				 __u32 type, __u64 addr, __u64 len)
{
	memset(attr, 0, sizeof(struct perf_event_attr));
	attr->type           = PERF_TYPE_BREAKPOINT;
	attr->size           = sizeof(struct perf_event_attr);
	attr->bp_type        = type;
	attr->bp_addr        = addr;
	attr->bp_len         = len;
	attr->exclude_user   = 1;
	attr->exclude_hv     = 1;
	attr->exclude_guest  = 1;
}

static int perf_thread_event_open(__u32 type, __u64 addr, __u64 len)
{
	struct perf_event_attr attr;

	perf_user_event_attr_set(&attr, type, addr, len);
	return syscall(__NR_perf_event_open, &attr, getpid(), -1, -1, 0);
}

static int perf_cpu_event_open(long cpu, __u32 type, __u64 addr, __u64 len)
{
	struct perf_event_attr attr;

	perf_user_event_attr_set(&attr, type, addr, len);
	return syscall(__NR_perf_event_open, &attr, -1, cpu, -1, 0);
}

static int perf_thread_kernel_event_open(__u32 type, __u64 addr, __u64 len)
{
	struct perf_event_attr attr;

	perf_kernel_event_attr_set(&attr, type, addr, len);
	return syscall(__NR_perf_event_open, &attr, getpid(), -1, -1, 0);
}

static int perf_cpu_kernel_event_open(long cpu, __u32 type, __u64 addr, __u64 len)
{
	struct perf_event_attr attr;

	perf_kernel_event_attr_set(&attr, type, addr, len);
	return syscall(__NR_perf_event_open, &attr, -1, cpu, -1, 0);
}

static void close_fds(int *fd, int n)
{
	int i;

	for (i = 0; i < n; i++)
		close(fd[i]);
}

static unsigned long read_fds(int *fd, int n)
{
	int i;
	unsigned long c = 0;
	unsigned long count = 0;

	for (i = 0; i < n; i++) {
		read(fd[i], &c, sizeof(c));
		count += c;
	}
	return count;
}

static int perf_systemwide_event_open(int *fd, __u32 type, __u64 addr, __u64 len)
{
	int i = 0;

	/* Assume online processors are 0 to nprocs for simplisity */
	for (i = 0; i < nprocs; i++) {
		fd[i] = perf_cpu_event_open(i, type, addr, len);
		if (fd[i] < 0) {
			close_fds(fd, i);
			return fd[i];
		}
	}
	return 0;
}

static int perf_systemwide_kernel_event_open(int *fd, __u32 type, __u64 addr,
					     __u64 len)
{
	int i = 0;

	/* Assume online processors are 0 to nprocs for simplisity */
	for (i = 0; i < nprocs; i++) {
		fd[i] = perf_cpu_kernel_event_open(i, type, addr, len);
		if (fd[i] < 0) {
			close_fds(fd, i);
			return fd[i];
		}
	}
	return 0;
}

static int test1(void)
{
	unsigned long count = 0;
	int fd;

	fd = perf_thread_event_open(HW_BREAKPOINT_RW, (__u64)&b, (__u64)sizeof(b));
	if (fd < 0)
		return fd;

	workload();
	read(fd, &count, sizeof(count));
	close(fd);

	if (count != 2)
		return -EMISMATCH;
	return 0;
}

static int test2(void)
{
	unsigned long count = 0;
	int fd;

	fd = perf_thread_event_open(HW_BREAKPOINT_R, (__u64)&a, (__u64)sizeof(a));
	if (fd < 0)
		return fd;

	workload();
	read(fd, &count, sizeof(count));
	close(fd);

	if (count != 1)
		return -EMISMATCH;
	return 0;
}

static int test3(void)
{
	unsigned long count = 0;
	int fd;

	fd = perf_thread_event_open(HW_BREAKPOINT_R, (__u64)&a, (__u64)sizeof(a));
	if (fd < 0)
		return fd;

	workload();
	read(fd, &count, sizeof(count));
	close(fd);

	if (count != 1)
		return -EMISMATCH;
	return 0;
}

static int test4(void)
{
	unsigned long count1 = 0, count2 = 0;
	int fd1, fd2;

	fd1 = perf_thread_event_open(HW_BREAKPOINT_RW, (__u64)&a, (__u64)sizeof(a));
	if (fd1 < 0)
		return fd1;

	fd2 = perf_thread_event_open(HW_BREAKPOINT_RW, (__u64)&b, (__u64)sizeof(b));
	if (fd2 < 0) {
		close(fd1);
		return fd2;
	}

	workload();

	read(fd1, &count1, sizeof(count1));
	read(fd2, &count2, sizeof(count2));

	close(fd1);
	close(fd2);

	if (count1 != 2 || count2 != 2)
		return -EMISMATCH;
	return 0;
}

static int test5(void)
{
	unsigned long count1 = 0, count2 = 0;
	int fd1, fd2;

	fd1 = perf_thread_event_open(HW_BREAKPOINT_RW, (__u64)&a, (__u64)sizeof(a));
	if (fd1 < 0)
		return fd1;

	fd2 = perf_thread_event_open(HW_BREAKPOINT_RW, (__u64)&a, (__u64)sizeof(a));
	if (fd2 < 0) {
		close(fd1);
		return fd2;
	}

	workload();

	read(fd1, &count1, sizeof(count1));
	read(fd2, &count2, sizeof(count2));

	close(fd1);
	close(fd2);

	if (count1 != 2 || count2 != 2)
		return -EMISMATCH;
	return 0;
}

static int test6(void)
{
	unsigned long count1 = 0, count2 = 0;
	int fd1, fd2;

	fd1 = perf_thread_event_open(HW_BREAKPOINT_W, (__u64)&a, (__u64)sizeof(a));
	if (fd1 < 0)
		return fd1;

	fd2 = perf_thread_event_open(HW_BREAKPOINT_R, (__u64)&b, (__u64)sizeof(b));
	if (fd2 < 0) {
		close(fd1);
		return fd2;
	}

	workload();

	read(fd1, &count1, sizeof(count1));
	read(fd2, &count2, sizeof(count2));

	close(fd1);
	close(fd2);

	if (count1 != 1 || count2 != 1)
		return -EMISMATCH;
	return 0;
}

static int test7(void)
{
	unsigned long count1 = 0, count2 = 0;
	int fd1, fd2;

	fd1 = perf_thread_event_open(HW_BREAKPOINT_R, (__u64)&a, (__u64)sizeof(a));
	if (fd1 < 0)
		return fd1;

	fd2 = perf_thread_event_open(HW_BREAKPOINT_W, (__u64)&a, (__u64)sizeof(a));
	if (fd2 < 0) {
		close(fd1);
		return fd2;
	}

	workload();

	read(fd1, &count1, sizeof(count1));
	read(fd2, &count2, sizeof(count2));

	close(fd1);
	close(fd2);

	if (count1 != 1 || count2 != 1)
		return -EMISMATCH;
	return 0;
}

static int test8(void)
{
	unsigned long count = 0;
	int *fd = malloc(nprocs * sizeof(int));
	int ret;

	ret = perf_systemwide_event_open(fd, HW_BREAKPOINT_RW, (__u64)&b,
					 (__u64)sizeof(b));
	if (ret)
		return ret;

	workload();
	count = read_fds(fd, nprocs);
	close_fds(fd, nprocs);
	free(fd);

	if (count != 2)
		return -EMISMATCH;
	return 0;
}

static int test9(void)
{
	unsigned long count = 0;
	int *fd = malloc(nprocs * sizeof(int));
	int ret;

	ret = perf_systemwide_event_open(fd, HW_BREAKPOINT_R, (__u64)&a,
					 (__u64)sizeof(a));
	if (ret)
		return ret;

	workload();
	count = read_fds(fd, nprocs);
	close_fds(fd, nprocs);
	free(fd);

	if (count != 1)
		return -EMISMATCH;
	return 0;
}

static int test10(void)
{
	unsigned long count = 0;
	int *fd = malloc(nprocs * sizeof(int));
	int ret;

	ret = perf_systemwide_event_open(fd, HW_BREAKPOINT_W, (__u64)&b,
					 (__u64)sizeof(b));
	if (ret)
		return ret;

	workload();
	count = read_fds(fd, nprocs);
	close_fds(fd, nprocs);
	free(fd);

	if (count != 1)
		return -EMISMATCH;
	return 0;
}

static int test11(void)
{
	unsigned long count1 = 0, count2 = 0;
	int *fd1 = malloc(nprocs * sizeof(int));
	int *fd2 = malloc(nprocs * sizeof(int));
	int ret;

	ret = perf_systemwide_event_open(fd1, HW_BREAKPOINT_RW, (__u64)&a,
					(__u64)sizeof(a));
	if (ret)
		return ret;

	ret = perf_systemwide_event_open(fd2, HW_BREAKPOINT_RW, (__u64)&b,
					(__u64)sizeof(b));
	if (ret) {
		close_fds(fd1, nprocs);
		return ret;
	}

	workload();

	count1 = read_fds(fd1, nprocs);
	count2 = read_fds(fd2, nprocs);

	close_fds(fd1, nprocs);
	close_fds(fd2, nprocs);

	free(fd1);
	free(fd2);

	if (count1 != 2 || count2 != 2)
		return -EMISMATCH;
	return 0;
}

static int test12(void)
{
	unsigned long count1 = 0, count2 = 0;
	int *fd1 = malloc(nprocs * sizeof(int));
	int *fd2 = malloc(nprocs * sizeof(int));
	int ret;

	ret = perf_systemwide_event_open(fd1, HW_BREAKPOINT_RW, (__u64)&a,
					(__u64)sizeof(a));
	if (ret)
		return ret;

	ret = perf_systemwide_event_open(fd2, HW_BREAKPOINT_RW, (__u64)&a,
					(__u64)sizeof(a));
	if (ret) {
		close_fds(fd1, nprocs);
		return ret;
	}

	workload();

	count1 = read_fds(fd1, nprocs);
	count2 = read_fds(fd2, nprocs);

	close_fds(fd1, nprocs);
	close_fds(fd2, nprocs);

	free(fd1);
	free(fd2);

	if (count1 != 2 || count2 != 2)
		return -EMISMATCH;
	return 0;
}

static int test13(void)
{
	unsigned long count1 = 0, count2 = 0;
	int *fd1 = malloc(nprocs * sizeof(int));
	int *fd2 = malloc(nprocs * sizeof(int));
	int ret;

	ret = perf_systemwide_event_open(fd1, HW_BREAKPOINT_W, (__u64)&a,
					(__u64)sizeof(a));
	if (ret)
		return ret;

	ret = perf_systemwide_event_open(fd2, HW_BREAKPOINT_R, (__u64)&b,
					(__u64)sizeof(b));
	if (ret) {
		close_fds(fd1, nprocs);
		return ret;
	}

	workload();

	count1 = read_fds(fd1, nprocs);
	count2 = read_fds(fd2, nprocs);

	close_fds(fd1, nprocs);
	close_fds(fd2, nprocs);

	free(fd1);
	free(fd2);

	if (count1 != 1 || count2 != 1)
		return -EMISMATCH;
	return 0;
}

static int test14(void)
{
	unsigned long count1 = 0, count2 = 0;
	int *fd1 = malloc(nprocs * sizeof(int));
	int *fd2 = malloc(nprocs * sizeof(int));
	int ret;

	ret = perf_systemwide_event_open(fd1, HW_BREAKPOINT_W, (__u64)&a,
					(__u64)sizeof(a));
	if (ret)
		return ret;

	ret = perf_systemwide_event_open(fd2, HW_BREAKPOINT_R, (__u64)&a,
					(__u64)sizeof(a));
	if (ret) {
		close_fds(fd1, nprocs);
		return ret;
	}

	workload();

	count1 = read_fds(fd1, nprocs);
	count2 = read_fds(fd2, nprocs);

	close_fds(fd1, nprocs);
	close_fds(fd2, nprocs);

	free(fd1);
	free(fd2);

	if (count1 != 1 || count2 != 1)
		return -EMISMATCH;
	return 0;
}

static __u64 get_kernel_var_addr(void)
{
	char line[256];
	FILE *fp = fopen("/proc/kallsyms", "r");
	__u64 addr = 0;

	if (!fp)
		return 0;

	while (fgets(line, sizeof(line), fp)) {
		if (strstr(line, "sysctl_perf_event_sample_rate")) {
			addr = strtoul(line, NULL, 16);
			break;
		}
	}

	fclose(fp);
	return addr;
}

static int test15(void)
{
	unsigned long count = 0;
	int fd;
	__u64 addr = get_kernel_var_addr();

	if (!addr)
		return -errno;

	fd = perf_thread_kernel_event_open(HW_BREAKPOINT_RW, addr,
					   (__u64)sizeof(int));
	if (fd < 0)
		return fd;

	kernel_workload();
	read(fd, &count, sizeof(count));
	close(fd);

	if (count != 1)
		return -EMISMATCH;
	return 0;
}

static int test16(void)
{
	unsigned long count = 0;
	int *fd = malloc(nprocs * sizeof(int));
	int ret;
	__u64 addr = get_kernel_var_addr();

	if (!addr)
		return -errno;

	ret = perf_systemwide_kernel_event_open(fd, HW_BREAKPOINT_RW, addr,
						(__u64)sizeof(int));
	if (ret)
		return ret;

	kernel_workload();
	count = read_fds(fd, nprocs);
	close_fds(fd, nprocs);
	free(fd);

	if (count < 1)
		return -EMISMATCH;
	return 0;
}

static int test17(void)
{
	unsigned long count = 0;
	int fd;
	__u64 addr = (__u64)&c + 8;

	fd = perf_thread_event_open(HW_BREAKPOINT_RW, addr, 512);
	if (fd < 0)
		return fd;

	workload();
	read(fd, &count, sizeof(count));
	close(fd);

	if (count != 2)
		return -EMISMATCH;
	return 0;
}

/* There is no perf api to find number of available watchpoints. Use ptrace. */
static int get_nr_wps(void)
{
	struct ppc_debug_info dbginfo;
	int child_pid;

	child_pid = fork();
	if (!child_pid) {
		int ret = ptrace(PTRACE_TRACEME, 0, NULL, 0);
		if (ret) {
			perror("PTRACE_TRACEME failed\n");
			exit(EXIT_FAILURE);
		}
		kill(getpid(), SIGUSR1);

		sleep(1);
		exit(EXIT_SUCCESS);
	}

	wait(NULL);
	if (ptrace(PPC_PTRACE_GETHWDBGINFO, child_pid, NULL, &dbginfo)) {
		perror("Can't get breakpoint info");
		exit(EXIT_FAILURE);
	}
	return dbginfo.num_data_bps;
}

#define TEST(msg, fun, ret) {						\
	int r;								\
	r = fun();							\
	if (r == -EMISMATCH)						\
		printf("%s: Error (Count mismatch)\n", msg);		\
	else if (r)							\
		printf("%s: Error (%s)\n", msg, strerror(errno));	\
	else								\
		printf("%s: Ok\n", msg);				\
	ret |= r;							\
}

static char *desc[17] = {
	"Process specific, single event",
	"Process specific, single RO event",
	"Process specific, single WO event",
	"Process specific, Two events with different addresses",
	"Process specific, Two events with same address",
	"Process specific, Two events, one is RO, other is WO",
	"Process specific, Two events with same address, one is RO, other is WO",
	"Systemwide, single event",
	"Systemwide, single RO event",
	"Systemwide, single WO event",
	"Systemwide, Two events with different addresses",
	"Systemwide, Two events with same address",
	"Systemwide, Two events, one is RO, other is WO",
	"Systemwide, Two events with same address, one is RO, other is WO",
	"Process specific, single kernel event",
	"Systemwide, single kernel event",
	"Process specific, 512 bytes, unaligned",
};

static int runtests(void)
{
	int ret = 0;
	int nr_wps = get_nr_wps();
	nprocs = get_nprocs();

	TEST(desc[0], test1, ret);
	TEST(desc[1], test2, ret);
	TEST(desc[2], test3, ret);
	if (nr_wps > 1) {
		TEST(desc[3], test4, ret);
		TEST(desc[4], test5, ret);
		TEST(desc[5], test6, ret);
		TEST(desc[6], test7, ret);
	}
	TEST(desc[7], test8, ret);
	TEST(desc[8], test9, ret);
	TEST(desc[9], test10, ret);
	if (nr_wps > 1) {
		TEST(desc[10], test11, ret);
		TEST(desc[11], test12, ret);
		TEST(desc[12], test13, ret);
		TEST(desc[13], test14, ret);
	}
	TEST(desc[14], test15, ret);
	TEST(desc[15], test16, ret);
	if (nr_wps > 1)
		TEST(desc[16], test17, ret);

	return ret;
}

int main(int argc, char *argv[], char **envp)
{
	return test_harness(runtests, "perf_hwbreak_2nd_dawr");
}
