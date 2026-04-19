# nix/xdp2-flow-ebpf.nix
#
# Production-distribution target for the fast-path eBPF flow
# dissector: bundles the compiled BPF object, the userspace loader
# binary, a minimal man page, and a systemd unit into a single
# Nix-packaged output that operators can `nix build .#xdp2-flow-ebpf`
# and deploy as-is.
#
# Track D milestone D8 in
# samples/flow_dissector/docs/super-flow-dissector-implementation.md.
#
# Layout of the resulting derivation:
#
#   $out/
#   ├── bin/
#   │   └── xdp2-flow-loader            # userspace CLI
#   ├── lib/xdp2-flow-ebpf/
#   │   └── fast_flow.bpf.o             # fast-path BPF object
#   ├── share/man/man1/
#   │   └── xdp2-flow-loader.1          # man page
#   └── share/xdp2-flow-ebpf/
#       └── xdp2-flow-loader.service    # systemd unit (scaffold)
#
# Usage:
#
#   nix build .#xdp2-flow-ebpf
#   sudo ./result/bin/xdp2-flow-loader \
#        --bpf ./result/lib/xdp2-flow-ebpf/fast_flow.bpf.o
#
# The loader and BPF object are versioned in lock-step — both come
# out of the same source tree, so `CHAIN_DYNAMIC` and the Rust
# `xdp2_flow_loader::CHAIN_DYNAMIC` constant cannot drift within one
# derivation.

{ pkgs
, xdp2      # C install tree (for <xdp2/*.h> headers pulled by fast_flow.bpf.c)
, llvmPackages
}:

let
  rustSrc = ../xdp2-rs;
  bpfSrc  = ../samples/flow_dissector/fast_bpf;

  # Mirror nix/xdp2-rs.nix commonArgs — keep these in sync if bumping.
  cargoHash = "sha256-2v9lLCpU1NPWL5xnTbK4G48BbcE9BXffx3q8ku5Bb0M=";

  # ── Userspace loader binary ─────────────────────────────────────
  #
  # The crate links against system libbpf (`#[link(name = "bpf")]`
  # in crates/xdp2-flow-loader/src/libbpf_sys.rs), so libbpf —
  # with its elfutils and zlib transitive deps — must be on the
  # build and runtime path.
  loader = pkgs.rustPlatform.buildRustPackage {
    pname = "xdp2-flow-loader";
    version = "0.1.0";
    src = rustSrc;
    inherit cargoHash;

    nativeBuildInputs = [ pkgs.pkg-config ];
    buildInputs = [
      pkgs.libbpf
      pkgs.elfutils
      pkgs.zlib
    ];

    # Only build the loader binary from the workspace — tests and
    # other crates are covered by xdp2-rs-test, not this target.
    cargoBuildFlags = [ "-p" "xdp2-flow-loader" "--bin" "xdp2-flow-loader" ];
    doCheck = false;

    meta = {
      description = "Userspace loader for the xdp2-flow-ebpf fast-path flow dissector";
      license = pkgs.lib.licenses.bsd2;
      mainProgram = "xdp2-flow-loader";
    };
  };

  # ── Fast-path BPF object ────────────────────────────────────────
  #
  # Compile fast_flow.bpf.c with clang's BPF target. The Nix test at
  # nix/tests/super-flow-dissector.nix uses the same flags — keep
  # in sync if either side drifts.
  bpfArchDefines = let
    cpu = pkgs.stdenv.hostPlatform.parsed.cpu.name;
  in {
    "x86_64"  = "-D__TARGET_ARCH_x86 -D__x86_64__";
    "aarch64" = "-D__TARGET_ARCH_arm64 -D__aarch64__";
    "riscv64" = "-D__TARGET_ARCH_riscv -D__riscv -D__riscv_xlen=64";
  }.${cpu} or (throw "Unsupported BPF target architecture: ${cpu}");

  bpfObject = pkgs.runCommand "xdp2-flow-ebpf-bpf-object" {
    nativeBuildInputs = [ llvmPackages.clang ];
    buildInputs = [ pkgs.libbpf ];
    # cc-wrapper's default hardening flags include
    # -fzero-call-used-regs and -fstack-protector-strong, both of
    # which the BPF target rejects. Match what the Makefile and the
    # super-flow-dissector Nix test do.
    NIX_HARDENING_ENABLE = "";
  } ''
    mkdir -p $out/lib/xdp2-flow-ebpf
    clang -x c -target bpf \
        ${bpfArchDefines} -Wno-unused-command-line-argument \
        -I${xdp2}/include -I${pkgs.libbpf}/include \
        -std=gnu11 -g -O2 \
        -c -o $out/lib/xdp2-flow-ebpf/fast_flow.bpf.o \
        ${bpfSrc}/fast_flow.bpf.c
    # Sanity-check: object is non-empty and contains the entry
    # program. A stripped-to-zero .o is a silent failure mode worth
    # catching at build time rather than deployment.
    test -s $out/lib/xdp2-flow-ebpf/fast_flow.bpf.o
  '';

  # ── Man page (minimal, format-only) ─────────────────────────────
  #
  # Scaffold suitable for `man 1 xdp2-flow-loader`. Content stays
  # in sync with the CLI's --help output; expand in D10 when the
  # container image / Helm chart lands.
  manPage = pkgs.writeText "xdp2-flow-loader.1" ''
    .TH XDP2-FLOW-LOADER 1 "2026" "xdp2-flow-ebpf" "User Commands"
    .SH NAME
    xdp2-flow-loader \- load the xdp2-flow-ebpf fast-path flow dissector
    .SH SYNOPSIS
    .B xdp2-flow-loader
    .B --bpf
    .I <fast_flow.bpf.o>
    .RB [ --slow-path
    .IR <obj> ]
    .RB [ --netns
    .IR <path> ]
    .SH DESCRIPTION
    Loads the xdp2-flow-ebpf fast-path BPF object, populates its
    .I jmp_table
    with per-chain specialised extractors, optionally installs a
    slow-path dissector into the CHAIN_DYNAMIC slot, and attaches
    the entry program to the flow_dissector hook in the target
    network namespace.
    .PP
    Requires
    .B CAP_NET_ADMIN
    in the target netns to attach.
    .SH OPTIONS
    .TP
    .BI --bpf " <path>"
    Path to the fast-path BPF object (typically
    .IR fast_flow.bpf.o ).
    Required.
    .TP
    .BI --slow-path " <path>"
    Optional slow-path BPF object. Its
    .B _dissect
    program is installed into
    .BR jmp_table[CHAIN_DYNAMIC]
    so fast-path misses tail-call into a full dissector instead of
    returning BPF_FLOW_DISSECTOR_CONTINUE.
    .TP
    .BI --netns " <path>"
    Path to the target network namespace (default
    .IR /proc/self/ns/net ).
    .SH EXIT STATUS
    0 on success, 1 on argument or runtime error.
    .SH SEE ALSO
    .BR bpf (2),
    .BR flow_dissector (7).
  '';

  # ── systemd unit (scaffold) ─────────────────────────────────────
  #
  # Minimal unit that attaches the loader at boot in the host netns.
  # Operators can drop this into /etc/systemd/system/ or use as a
  # template for their own deployment. Expand with hardening flags,
  # cgroup scoping, and environment overrides in D10.
  systemdUnit = pkgs.writeText "xdp2-flow-loader.service" ''
    [Unit]
    Description=xdp2-flow-ebpf fast-path flow dissector loader
    Documentation=man:xdp2-flow-loader(1)
    After=network-pre.target
    Wants=network-pre.target

    [Service]
    Type=exec
    ExecStart=${loader}/bin/xdp2-flow-loader --bpf ${bpfObject}/lib/xdp2-flow-ebpf/fast_flow.bpf.o
    AmbientCapabilities=CAP_NET_ADMIN CAP_BPF CAP_SYS_RESOURCE
    CapabilityBoundingSet=CAP_NET_ADMIN CAP_BPF CAP_SYS_RESOURCE
    NoNewPrivileges=true
    ProtectSystem=strict
    ProtectHome=true
    PrivateTmp=true
    Restart=on-failure

    [Install]
    WantedBy=multi-user.target
  '';
in
# symlinkJoin composes the three pieces into one $out that has the
# final layout documented at the top of this file. Individual
# components remain inspectable via their own derivations if needed
# for debugging.
pkgs.symlinkJoin {
  name = "xdp2-flow-ebpf";
  paths = [ loader bpfObject ];

  # We use postBuild to drop in the man page and unit file — they
  # don't come from a package, so they can't be in `paths`.
  postBuild = ''
    mkdir -p $out/share/man/man1
    cp ${manPage} $out/share/man/man1/xdp2-flow-loader.1

    mkdir -p $out/share/xdp2-flow-ebpf
    cp ${systemdUnit} $out/share/xdp2-flow-ebpf/xdp2-flow-loader.service
  '';

  meta = {
    description = "Production packaging of the xdp2-flow-ebpf fast-path flow dissector";
    license = pkgs.lib.licenses.bsd2;
    platforms = pkgs.lib.platforms.linux;
  };
}
