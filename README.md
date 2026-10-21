# ebpf lab

ebpf labs in golang + c

## sk_tracer
golang ebpf `sys_enter_connect` monitoring script

## NixOS Setup
```shell
nix-shell -p go clang llvmPackages.clang-unwrapped llvmPackages.llvm libbpf linuxHeaders
```

## Build
```shell
go generate
```

## Running
```shell
sudo -E go run .
```
