//go:build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <stddef.h>

#define MAX_PAYLOAD 4096

// event struct - golang side as bpfWriteEvent
struct write_event {
    __u32 pid;
    __u32 fd;
    __u32 orig_len;
    __u32 captured_len;
    char comm[16];
    __u8 payload[MAX_PAYLOAD];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4 * 1024 * 1024); // 4 MB
} events SEC(".maps");

// /sys/kernel/tracing/events/syscalls/sys_enter_write/format
struct trace_event_raw_sys_enter_write {
    __u64 unused;
    long syscall_nr;
    unsigned long fd;
    const char *buf;
    size_t count;
};

SEC("tracepoint/syscalls/sys_enter_write")
int handle_enter_write(struct trace_event_raw_sys_enter_write *ctx) {
    if (ctx->fd < 3) {
        return 0;
    }

    char comm[16];
    bpf_get_current_comm(&comm, sizeof(comm));

    if (bpf_strncmp(comm, sizeof(comm), "openssl") != 0) {
        return 0;
    }
    
    if (ctx->count == 0 || !ctx->buf) {
        return 0;
    }

    // 0x16 (Handshake TLS)
    __u8 record_type = 0;
    if (bpf_probe_read_user(&record_type, sizeof(record_type), ctx->buf) != 0 || record_type != 0x16) {
        return 0;
    }

    struct write_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->fd = (__u32)ctx->fd;
    e->orig_len = (__u32)ctx->count;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));


    __u32 copy_len = (__u32)ctx->count;
    if (copy_len > MAX_PAYLOAD) {
        copy_len = MAX_PAYLOAD;
    }
    if (copy_len == 0) {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }
    
    if (bpf_probe_read_user(e->payload, copy_len, ctx->buf) != 0) {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }

    e->captured_len = copy_len;
    bpf_ringbuf_submit(e, 0);

    return 0;
}

char _license[] SEC("license") = "GPL";
