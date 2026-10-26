#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/landlock.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

/* Trusted setup only. No target code runs until every kernel restriction succeeds.
 * Bubblewrap supplies a sparse filesystem and isolated PID/user/network namespaces.
 * Landlock additionally forbids execution from the writable grant. Seccomp denies
 * all socket creation (including pathname/abstract Unix), fd/process attacks and
 * io_uring, rather than treating a disconnected network namespace as deny-network.
 */
static void fail(const char *what) { perror(what); _exit(125); }
static void rule(int ruleset, const char *path, uint64_t access) {
    int fd = open(path, O_PATH | O_CLOEXEC);
    if (fd < 0) fail("landlock open");
    struct landlock_path_beneath_attr attr = { .allowed_access = access, .parent_fd = fd };
    if (syscall(SYS_landlock_add_rule, ruleset, LANDLOCK_RULE_PATH_BENEATH, &attr, 0)) fail("landlock rule");
    close(fd);
}
#define DENY(n) BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_##n, 0, 1), BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM)
int main(int argc, char **argv) {
    if (argc < 5) return 125;
    int libs = atoi(argv[3]);
    if (libs < 1 || argc < 5 + libs) return 125;
    int abi = (int)syscall(SYS_landlock_create_ruleset, NULL, 0, LANDLOCK_CREATE_RULESET_VERSION);
    if (abi < 3) { errno = ENOTSUP; fail("Landlock ABI >= 3 required"); }
    uint64_t all = (LANDLOCK_ACCESS_FS_REFER << 1) - 1;
    /* TRUNCATE is ABI3; avoid depending on the build host's newer headers. */
    all |= (1ULL << 14);
    struct landlock_ruleset_attr attr = { .handled_access_fs = all };
    int ruleset = (int)syscall(SYS_landlock_create_ruleset, &attr, sizeof attr, 0);
    if (ruleset < 0) fail("landlock create");
    rule(ruleset, argv[1], all & ~LANDLOCK_ACCESS_FS_EXECUTE);
    rule(ruleset, argv[2], LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_EXECUTE);
    for (int i = 0; i < libs; ++i)
        rule(ruleset, argv[4+i], LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_EXECUTE);
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) fail("no_new_privs");
    if (syscall(SYS_landlock_restrict_self, ruleset, 0)) fail("landlock restrict");
    close(ruleset);
    struct sock_filter filter[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
#if defined(__aarch64__)
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_AARCH64, 1, 0),
#elif defined(__x86_64__)
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
#else
#error Unsupported sandbox architecture
#endif
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
#if defined(__x86_64__)
        /* Reject x32, which shares AUDIT_ARCH_X86_64 but different syscall IDs. */
        BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, 0x40000000, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
#endif
        DENY(socket), DENY(socketpair), DENY(connect), DENY(bind),
        DENY(ptrace), DENY(process_vm_readv), DENY(process_vm_writev),
        DENY(pidfd_getfd), DENY(pidfd_send_signal),
        DENY(io_uring_setup), DENY(bpf), DENY(perf_event_open),
        DENY(open_by_handle_at), DENY(mount), DENY(umount2),
        DENY(pivot_root), DENY(setns), DENY(unshare),
        DENY(kill), DENY(tkill), DENY(tgkill),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)
    };
    struct sock_fprog program = { .len = sizeof filter / sizeof filter[0], .filter = filter };
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program)) fail("seccomp");
    /* No inherited host descriptors beyond stdio, even when the caller forgot CLOEXEC. */
    if (syscall(SYS_close_range, 3, ~0U, 0)) fail("close_range");
    if (write(STDOUT_FILENO, "SBOXv1!\n", 8) != 8) return 125;
    execv(argv[2], &argv[4+libs]);
    fail("sandbox exec");
}
