/*
 * agent/collectors/ebpf_tracer.c
 * ==============================
 * AEGIS Autonomous EDR - High-Performance Linux eBPF Kernel Tracepoint Hook
 * -------------------------------------------------------------------------
 * Captures process execution (sys_enter_execve), network connections (sys_enter_connect),
 * file operations (sys_enter_openat), signal/kill injections (sys_enter_kill), and
 * ptrace anti-analysis / injection (sys_enter_ptrace) at the kernel level with
 * negligible CPU overhead (< 1.5%).
 *
 * Emits structured event records to an eBPF ring buffer / perf output buffer
 * for zero-copy userspace consumption by AEGIS collectors.
 */

#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>

#define TASK_COMM_LEN 16
#define MAX_PATH_LEN 256
#define EVENT_TYPE_EXECVE   1
#define EVENT_TYPE_CONNECT  2
#define EVENT_TYPE_OPENAT   3
#define EVENT_TYPE_KILL     4
#define EVENT_TYPE_PTRACE   5

/* Structured Kernel Telemetry Event */
struct aegis_kernel_event_t {
    u64 timestamp_ns;
    u32 pid;
    u32 tgid;
    u32 uid;
    u32 event_type;
    s32 ret_val;
    char comm[TASK_COMM_LEN];
    char target_path[MAX_PATH_LEN];
    u32 dst_ip;
    u16 dst_port;
    u16 flags;
};

/* BPF Perf Buffer Output Map */
BPF_PERF_OUTPUT(aegis_kernel_events);

/* -------------------------------------------------------------------------
 * 1. Tracepoint: sys_enter_execve (Process Execution)
 * ------------------------------------------------------------------------- */
TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    struct aegis_kernel_event_t evt = {};

    evt.timestamp_ns = bpf_ktime_get_ns();
    u64 pid_tgid = bpf_get_current_pid_tgid();
    evt.pid = pid_tgid;
    evt.tgid = pid_tgid >> 32;
    evt.uid = bpf_get_current_uid_gid();
    evt.event_type = EVENT_TYPE_EXECVE;

    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));

    /* Read executable path from userspace argument */
    const char __user *filename = (const char __user *)args->filename;
    if (filename) {
        bpf_probe_read_user_str(&evt.target_path, sizeof(evt.target_path), filename);
    }

    aegis_kernel_events.perf_submit(args, &evt, sizeof(evt));
    return 0;
}

/* -------------------------------------------------------------------------
 * 2. Tracepoint: sys_enter_connect (Network Socket Connection)
 * ------------------------------------------------------------------------- */
TRACEPOINT_PROBE(syscalls, sys_enter_connect) {
    struct aegis_kernel_event_t evt = {};

    evt.timestamp_ns = bpf_ktime_get_ns();
    u64 pid_tgid = bpf_get_current_pid_tgid();
    evt.pid = pid_tgid;
    evt.tgid = pid_tgid >> 32;
    evt.uid = bpf_get_current_uid_gid();
    evt.event_type = EVENT_TYPE_CONNECT;

    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));

    /* Read sockaddr from userspace */
    struct sockaddr_in {
        unsigned short sin_family;
        unsigned short sin_port;
        struct { unsigned int s_addr; } sin_addr;
    } s_in = {};

    if (args->addrlen >= sizeof(s_in)) {
        bpf_probe_read_user(&s_in, sizeof(s_in), (void *)args->uservaddr);
        if (s_in.sin_family == 2) { /* AF_INET */
            evt.dst_ip = s_in.sin_addr.s_addr;
            evt.dst_port = ((s_in.sin_port & 0xFF) << 8) | ((s_in.sin_port >> 8) & 0xFF);
        }
    }

    aegis_kernel_events.perf_submit(args, &evt, sizeof(evt));
    return 0;
}

/* -------------------------------------------------------------------------
 * 3. Tracepoint: sys_enter_openat (File Access / Droppers)
 * ------------------------------------------------------------------------- */
TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
    struct aegis_kernel_event_t evt = {};

    evt.timestamp_ns = bpf_ktime_get_ns();
    u64 pid_tgid = bpf_get_current_pid_tgid();
    evt.pid = pid_tgid;
    evt.tgid = pid_tgid >> 32;
    evt.uid = bpf_get_current_uid_gid();
    evt.event_type = EVENT_TYPE_OPENAT;
    evt.flags = args->flags;

    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));

    const char __user *filename = (const char __user *)args->filename;
    if (filename) {
        bpf_probe_read_user_str(&evt.target_path, sizeof(evt.target_path), filename);
    }

    aegis_kernel_events.perf_submit(args, &evt, sizeof(evt));
    return 0;
}

/* -------------------------------------------------------------------------
 * 4. Tracepoint: sys_enter_kill (Inter-process Termination / Attack Signals)
 * ------------------------------------------------------------------------- */
TRACEPOINT_PROBE(syscalls, sys_enter_kill) {
    struct aegis_kernel_event_t evt = {};

    evt.timestamp_ns = bpf_ktime_get_ns();
    u64 pid_tgid = bpf_get_current_pid_tgid();
    evt.pid = pid_tgid;
    evt.tgid = pid_tgid >> 32;
    evt.uid = bpf_get_current_uid_gid();
    evt.event_type = EVENT_TYPE_KILL;
    evt.flags = args->sig;
    evt.dst_ip = args->pid; /* Target PID encoded in dst_ip slot */

    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));

    aegis_kernel_events.perf_submit(args, &evt, sizeof(evt));
    return 0;
}

/* -------------------------------------------------------------------------
 * 5. Tracepoint: sys_enter_ptrace (Process Injection / Debugger Attachment)
 * ------------------------------------------------------------------------- */
TRACEPOINT_PROBE(syscalls, sys_enter_ptrace) {
    struct aegis_kernel_event_t evt = {};

    evt.timestamp_ns = bpf_ktime_get_ns();
    u64 pid_tgid = bpf_get_current_pid_tgid();
    evt.pid = pid_tgid;
    evt.tgid = pid_tgid >> 32;
    evt.uid = bpf_get_current_uid_gid();
    evt.event_type = EVENT_TYPE_PTRACE;
    evt.flags = args->request;
    evt.dst_ip = args->pid; /* Target PID attached to */

    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));

    aegis_kernel_events.perf_submit(args, &evt, sizeof(evt));
    return 0;
}
