# ebpf lab

ebpf labs in golang + c

## sk_tracer
golang ebpf `sys_enter_connect` monitoring script
```c
SEC("tracepoint/syscalls/sys_enter_connect")
```

## tls_cipher_tracer

golang ebpf `sys_enter_read` and `sys_exit_read` monitoring script
```c
SEC("tracepoint/syscalls/sys_enter_read")
SEC("tracepoint/syscalls/sys_exit_read")
```

## runtime_cbom

golang ebpf `sys_enter_write` collector for runtime Cryptographic Bill of Materials (CycloneDX 1.7) generation across TLS 1.2 and TLS 1.3 handshakes
```c
SEC("tracepoint/syscalls/sys_enter_write")
```
### Runtime Capture Pipeline

> **Note:** This document describes how `runtime_cbom` captures, correlates, and parses TLS handshakes from kernel `write(2)` syscalls to structured observations.

### Architecture Overview

```text
[1. Kernel eBPF: sys_enter_write]
   Intercepts write() calls starting with 0x16 (TLS Handshake) and copies up to 4096 B.
   (Continuation writes > 4 KB or encrypted 0x17 records are filtered in kernel space.)
          │
          ▼
[2. Per-Socket Aggregator: (PID, FD)]
   - Opens a flight window ONLY on HS 0x02 (ServerHello).
   - Drops client messages (0x01, 0x10) and post-handshake tickets (0x04).
   - Groups consecutive write() syscalls from the same (PID, FD) until flight completion.
          │
          ▼
[3. TLS Parser: Records -> Handshake Messages]
   - TLS 1.3: 1 write() -> ServerHello (0x02) + key_share -> closes on 0x14/0x17.
   - TLS 1.2 (cert < 4 KB): 1 write() -> 0x02 + 0x0B + 0x0C -> closes on 0x0E.
   - TLS 1.2 (cert > 4 KB):
       - write #1 (4096 B): ServerHello (0x02) + Certificate (0x0B, TRUNCATED).
       - [intermediate Certificate writes without 0x16 header are dropped by eBPF]
       - write #2 (~314 B): ServerKeyExchange (0x0C) + ServerHelloDone (0x0E).
```

### Scenario
[openssl server & client](./runtime_cbom/SCENARIO.md)

## NixOS Setup
in root directory start a clean environment by running:
```shell
nix-shell
```

## Build
```shell
go generate
```

## Running
```shell
sudo -E go run .
```
