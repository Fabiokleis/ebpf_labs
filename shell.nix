{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
  buildInputs = with pkgs; [
    go
    llvmPackages.clang-unwrapped
    llvmPackages.llvm
    libbpf
    linuxHeaders
  ];

  shellHook = ''
    export CLANG="${pkgs.llvmPackages.clang-unwrapped}/bin/clang"
    export BPF_CLANG="${pkgs.llvmPackages.clang-unwrapped}/bin/clang"
    export CC="${pkgs.llvmPackages.clang-unwrapped}/bin/clang"
    
    export BPF_CFLAGS="-I${pkgs.linuxHeaders}/include -I${pkgs.libbpf}/include -O2 -g"
    export CFLAGS="-I${pkgs.linuxHeaders}/include -I${pkgs.libbpf}/include"
  '';
}
