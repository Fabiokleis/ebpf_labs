//go:build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <stddef.h>

// event struct - golang side as bpfEvent
struct tls_event {
    __u32 pid;
    __u32 uid;
    __u16 cipher_suite;
    char comm[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); // 256 KB
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u64);
    __type(value, const char *);
} active_reads SEC(".maps");

// /sys/kernel/tracing/events/syscalls/sys_enter_read/format
struct trace_event_raw_sys_enter_read {
    __u64 unused;
    long syscall_nr;
    unsigned long fd;
    const char *buf;
    size_t count;
};

//  /sys/kernel/tracing/events/syscalls/sys_exit_read/format
struct trace_event_raw_sys_exit_read {
    __u64 unused;
    long syscall_nr;
    long ret;
};

SEC("tracepoint/syscalls/sys_enter_read")
int handle_enter_read(struct trace_event_raw_sys_enter_read *ctx) {
    if (ctx->fd < 3) return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    const char *buf = ctx->buf;

    bpf_map_update_elem(&active_reads, &pid_tgid, &buf, BPF_ANY);

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_read")
int handle_exit_read(struct trace_event_raw_sys_exit_read *ctx) {

    __u64 pid_tgid = bpf_get_current_pid_tgid();

    const char **buf_ptr = bpf_map_lookup_elem(&active_reads, &pid_tgid);
    if (!buf_ptr) {
        return 0;
    }
    
    const char *user_buf = *buf_ptr;
    bpf_map_delete_elem(&active_reads, &pid_tgid);

    // syscall returned successfully
    if (ctx->ret <= 0) {
        return 0;
    }

    char buf[100];
    if (bpf_probe_read_user(&buf, sizeof(buf), user_buf) != 0) {
        return 0;
    }

    // 0x16 (Handshake TLS) 
    // 0x02 (ServerHello) Handshake
    if (buf[0] == 0x16 && buf[5] == 0x02) {
        __u8 sid_len = buf[43]; 
        
        if (44 + sid_len + 1 < sizeof(buf)) {
            __u16 cipher = (buf[44 + sid_len] << 8) | buf[44 + sid_len + 1];

            struct tls_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
            if (e) {
                e->pid = bpf_get_current_pid_tgid() >> 32;
                e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
                e->cipher_suite = cipher;
                bpf_get_current_comm(&e->comm, sizeof(e->comm));
                
                bpf_ringbuf_submit(e, 0);
            }
        }
    }
    return 0;
}

char _license[] SEC("license") = "GPL";
