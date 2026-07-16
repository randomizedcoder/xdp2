// SPDX-License-Identifier: GPL-2.0
/*
 * Targeted reproducer for the flow_dissector BPF static-key refcount change
 * (patch 0001: netns_bpf_flow_dissector_enabled inc/dec across attach/detach/
 * replace/netns-exit). Hammers those exact paths on the running kernel and
 * watches for a static_key underflow WARN (the detectable failure mode).
 *
 * Root + a kernel with BPF_PROG_TYPE_FLOW_DISSECTOR.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sched.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <linux/bpf.h>

static int sys_bpf(int cmd, union bpf_attr *attr)
{
	return syscall(__NR_bpf, cmd, attr, sizeof(*attr));
}

/* Minimal flow-dissector prog: r0 = 0 (BPF_OK/CONTINUE); exit. */
static int load_prog(void)
{
	struct bpf_insn insns[] = {
		{ .code = 0xb7, .dst_reg = 0, .imm = 0 }, /* mov r0, 0 */
		{ .code = 0x95 },                         /* exit      */
	};
	static char log[1 << 16];
	union bpf_attr a = {0};

	a.prog_type = BPF_PROG_TYPE_FLOW_DISSECTOR;
	a.insn_cnt = 2;
	a.insns = (unsigned long)insns;
	a.license = (unsigned long)"GPL";
	a.log_buf = (unsigned long)log;
	a.log_size = sizeof(log);
	a.log_level = 1;
	int fd = sys_bpf(BPF_PROG_LOAD, &a);
	if (fd < 0)
		fprintf(stderr, "PROG_LOAD failed: %s\n%s\n", strerror(errno), log);
	return fd;
}

static int attach(int prog_fd)
{
	union bpf_attr a = {0};
	a.attach_type = BPF_FLOW_DISSECTOR;
	a.attach_bpf_fd = prog_fd;
	a.target_fd = 0;              /* current netns */
	return sys_bpf(BPF_PROG_ATTACH, &a);
}

static int detach(int prog_fd)
{
	union bpf_attr a = {0};
	a.attach_type = BPF_FLOW_DISSECTOR;
	a.attach_bpf_fd = prog_fd;
	a.target_fd = 0;
	return sys_bpf(BPF_PROG_DETACH, &a);
}

/* number of flow-dissector progs attached to the current netns.
 * QUERY needs an explicit netns fd (unlike the legacy attach path, which
 * takes target_fd == 0 for the caller's netns).
 */
static int query_cnt(void)
{
	unsigned int ids[8] = {0};
	union bpf_attr a = {0};
	int ns = open("/proc/self/ns/net", O_RDONLY);
	if (ns < 0)
		return -1;
	a.query.target_fd = ns;
	a.query.attach_type = BPF_FLOW_DISSECTOR;
	a.query.prog_ids = (unsigned long)ids;
	a.query.prog_cnt = 8;
	int r = sys_bpf(BPF_PROG_QUERY, &a);
	close(ns);
	if (r < 0)
		return -1;
	return a.query.prog_cnt;
}

#define OK(cond, msg) do { if (!(cond)) { \
	fprintf(stderr, "FAIL: %s (errno=%s)\n", msg, strerror(errno)); \
	exit(1); } } while (0)

int main(void)
{
	int pf = load_prog();
	OK(pf >= 0, "load flow-dissector prog");

	/* 1. baseline: nothing attached */
	OK(query_cnt() == 0, "baseline query == 0");

	/* 2. attach/detach cycles: inc then dec, N times */
	const int N = 2000;
	for (int i = 0; i < N; i++) {
		OK(attach(pf) == 0, "attach");
		OK(query_cnt() == 1, "query == 1 after attach");
		OK(detach(pf) == 0, "detach");
		OK(query_cnt() == 0, "query == 0 after detach");
	}
	printf("  [1] %d attach/detach cycles: OK\n", N);

	/* 3. replace-in-place: attach pf, attach pf2 (replaces, no count change),
	 *    detach pf2. Exercises the 'attached != NULL -> no need()' branch.
	 */
	int pf2 = load_prog();
	OK(pf2 >= 0, "load 2nd prog");
	for (int i = 0; i < N; i++) {
		OK(attach(pf) == 0, "attach pf");
		OK(attach(pf2) == 0, "replace with pf2");
		OK(query_cnt() == 1, "still 1 after replace");
		OK(detach(pf2) == 0, "detach pf2");
		OK(query_cnt() == 0, "0 after detach");
	}
	printf("  [2] %d replace-in-place cycles: OK\n", N);

	/* 4. netns exit WITH a prog still attached (the pre_exit prog-path
	 *    unneed this patch adds). Child unshares a fresh netns, attaches,
	 *    and exits WITHOUT detaching -> netns teardown must release the ref.
	 */
	const int M = 500;
	for (int i = 0; i < M; i++) {
		pid_t p = fork();
		OK(p >= 0, "fork");
		if (p == 0) {
			if (unshare(CLONE_NEWNET) != 0)
				_exit(2);
			if (attach(pf) != 0)   /* attach in the fresh netns */
				_exit(3);
			_exit(0);              /* exit: netns dies with prog attached */
		}
		int st = 0;
		waitpid(p, &st, 0);
		OK(WIFEXITED(st) && WEXITSTATUS(st) == 0, "child unshare+attach");
	}
	printf("  [3] %d netns-exit-with-attached-prog cycles: OK\n", M);

	/* 5. final state clean in our (original) netns */
	OK(query_cnt() == 0, "final query == 0 in root netns");
	printf("ALL REPRODUCER CHECKS PASSED\n");
	return 0;
}
