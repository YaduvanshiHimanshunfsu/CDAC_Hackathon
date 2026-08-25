#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "aegis_events.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} process_events SEC(".maps");

SEC("tracepoint/sched/sched_process_exec")
int observe_process_exec(void *ctx)
{
    struct aegis_process_event *event;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();

    event = bpf_ringbuf_reserve(&process_events, sizeof(*event), 0);
    if (!event)
        return 0;

    event->monotonic_ns = bpf_ktime_get_ns();
    event->process_start_ns = BPF_CORE_READ(task, start_boottime);
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->ppid = BPF_CORE_READ(task, real_parent, tgid);
    event->uid = bpf_get_current_uid_gid();
    event->event_type = AEGIS_PROCESS_EXEC;
    bpf_get_current_comm(event->comm, sizeof(event->comm));

    /* Extract binary dentry name from task memory descriptor using CO-RE */
    struct file *exe_file = BPF_CORE_READ(task, mm, exe_file);
    if (exe_file) {
        struct qstr d_name = BPF_CORE_READ(exe_file, f_path.dentry, d_name);
        bpf_probe_read_kernel_str(event->filename, sizeof(event->filename), d_name.name);
    } else {
        bpf_get_current_comm(event->filename, sizeof(event->filename));
    }

    bpf_ringbuf_submit(event, 0);
    return 0;
}
