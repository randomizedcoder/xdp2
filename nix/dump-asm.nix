# SPDX-License-Identifier: BSD-2-Clause-FreeBSD
#
# dump-asm — Phase A1 wrapper. Bundles dump-asm.sh with the
# binutils + llvm tooling it needs (objdump, llvm-objdump). bpftool
# is gated behind --with-bpf-jit and discovered at runtime; the
# dev-shell on hp5 already has it via systemPackages, but we don't
# bake it in here so the local build works without root.

{ pkgs, xdp2Rs, flowDissectorMatrix }:

let
  artifacts = flowDissectorMatrix.artifacts;
in

pkgs.writeShellApplication {
  name = "flow-dissector-dump-asm";

  runtimeInputs = [
    pkgs.coreutils
    pkgs.gnugrep
    pkgs.gawk
    pkgs.gnused
    pkgs.binutils      # objdump
    pkgs.llvm          # llvm-objdump (for BPF .o disassembly)
    xdp2Rs.build       # xdp2-bench
    artifacts          # benchmark + benchmark_bpf + .bpf.o files
  ];

  text = ''
    # Default --xdp2-rs / --artifacts paths point at the closure-bundled
    # builds. Caller can still override.
    exec ${./scripts/dump-asm.sh} \
        --xdp2-rs ${xdp2Rs.build} \
        --artifacts ${artifacts} \
        "$@"
  '';

  meta = {
    description = "Dump per-impl assembly for the 14 flow-dissector implementations";
    mainProgram = "flow-dissector-dump-asm";
  };
}
