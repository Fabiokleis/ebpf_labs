# ebpf lab

ebpf labs in golang + c

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
### Scenario
[openssl server & client](./runtime_cbom/SCENARIO.md)

### Runtime Capture Pipeline

> **Note:** This document describes how `runtime_cbom` captures, correlates, and parses TLS handshakes from kernel `write(2)` syscalls to structured observations.

### Architecture Overview

```text
[1. Kernel eBPF: sys_enter_write]
   Intercepts write() calls starting with 0x16 (TLS Handshake) and copies up to 4096 B.
   (Writes without the 0x16 header, such as continuation writes or encrypted 0x17 records, are filtered in kernel space.)
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
       - [rest of the Certificate in a write without 0x16 header, dropped by eBPF]
       - next write (~314 B): ServerKeyExchange (0x0C) + ServerHelloDone (0x0E).
```

### Runtime CBOM Collector (`runtime_cbom`)

> **Note:** Build and run the collector from `runtime_cbom/`. By default, generated CycloneDX 1.7 JSON files are written to `artifacts/cbom/` at the repository root.

### CycloneDX json

Check json generated CBOM inventory JSON by using official 1.7 schema: 
```shell
check-jsonschema --schemafile https://raw.githubusercontent.com/CycloneDX/specification/master/schema/bom-1.7.schema.json artifacts/cbom/cbom_*
```

### Running

```shell
cd runtime_cbom
sudo -E CGO_ENABLED=0 go run . -out ../artifacts/cbom
```
