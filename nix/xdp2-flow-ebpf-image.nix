# nix/xdp2-flow-ebpf-image.nix
#
# OCI container image bundling the xdp2-flow-ebpf production deliverable
# (loader binary + fast-path BPF object) for Kubernetes DaemonSet
# deployment.
#
# Track D milestone D10 (first half) in
# samples/flow_dissector/docs/super-flow-dissector-implementation.md.
#
# The image is a bit-reproducible `pkgs.dockerTools.buildLayeredImage`
# layered in roughly this order (lowest/shared layers first):
#   1. libbpf + elfutils + zlib (shared libraries; largest, most stable)
#   2. xdp2-flow-ebpf derivation ($out from nix/xdp2-flow-ebpf.nix)
#
# Usage:
#
#   # Build
#   nix build .#xdp2-flow-ebpf-image
#
#   # Load into a local Docker daemon for testing
#   docker load < result
#
#   # Push to a registry (after `docker tag`)
#   docker push ghcr.io/<org>/xdp2-flow-ebpf:latest
#
# The container needs CAP_NET_ADMIN + CAP_BPF + CAP_SYS_RESOURCE and
# must run in the host network namespace to attach to the flow-dissector
# hook (see deploy/helm/xdp2-flow-ebpf/templates/daemonset.yaml for the
# k8s pod spec). Inside the container the entrypoint is
# /bin/xdp2-flow-loader; the bpf object lives at
# /lib/xdp2-flow-ebpf/fast_flow.bpf.o — both paths come from the
# symlinkJoin in nix/xdp2-flow-ebpf.nix.

{ pkgs
, xdp2-flow-ebpf  # the symlinkJoin derivation from nix/xdp2-flow-ebpf.nix
}:

pkgs.dockerTools.buildLayeredImage {
  name = "xdp2-flow-ebpf";
  tag = "latest";

  # Reproducible timestamp. `now` would bake in wall-clock time and
  # break image content-addressing across rebuilds.
  created = "1970-01-01T00:00:00Z";

  contents = [
    xdp2-flow-ebpf
    # coreutils isn't strictly required for the happy path, but having
    # ls/cat/sh in the image makes `kubectl exec` debugging possible
    # without rebuilding. Cost: ~2 MB on top of the ~20 MB loader +
    # libbpf layers. Worth it for operators.
    pkgs.coreutils
    pkgs.bashInteractive
  ];

  config = {
    Entrypoint = [ "/bin/xdp2-flow-loader" ];
    # Default args: attach using the packaged bpf object. Helm chart
    # overrides this via `args:` to pass --slow-path, --netns, etc.
    Cmd = [
      "--bpf"
      "/lib/xdp2-flow-ebpf/fast_flow.bpf.o"
    ];
    # No USER directive — the loader requires CAP_NET_ADMIN +
    # CAP_BPF + CAP_SYS_RESOURCE, which the k8s DaemonSet grants via
    # securityContext.capabilities, not uid. Pod still runs as root
    # inside the container; capabilities (not uid) are the gate.
    Labels = {
      "org.opencontainers.image.title" = "xdp2-flow-ebpf";
      "org.opencontainers.image.description" =
        "Fast-path eBPF flow dissector (xdp2-flow-ebpf) — production deliverable for Kubernetes / Cilium-style deployments";
      "org.opencontainers.image.licenses" = "BSD-2-Clause";
      "org.opencontainers.image.source" =
        "https://github.com/randomizedcoder/xdp2";
    };
  };
}
