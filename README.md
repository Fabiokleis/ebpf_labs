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
### Scenario
(./runtime_cbom/SCENARIO.md)[openssl server & client]

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
