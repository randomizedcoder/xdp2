# xdp2-flow-ebpf Helm chart

Deploys the [xdp2-flow-ebpf](../../../samples/flow_dissector/fast_bpf/)
fast-path eBPF flow dissector as a host-network DaemonSet that attaches
on every node.

## Prerequisites

- Kubernetes ≥ 1.22
- Linux kernel ≥ 5.1 on all nodes (for `BPF_FLOW_DISSECTOR_CONTINUE`)
- libbpf ≥ 0.7 inside the container image (baked in by
  `nix build .#xdp2-flow-ebpf-image`)
- Ability to run pods with `hostNetwork: true` plus `CAP_NET_ADMIN`,
  `CAP_BPF`, `CAP_SYS_RESOURCE`

## Install

```bash
helm install xdp2-flow-ebpf ./deploy/helm/xdp2-flow-ebpf \
     --namespace kube-system \
     --set image.tag=0.1.0
```

## Uninstall

```bash
helm uninstall xdp2-flow-ebpf -n kube-system
```

On uninstall the DaemonSet pods terminate, which triggers the loader's
`Drop` handler — it detaches from the flow-dissector hook and closes
the netns fd, so the kernel reverts to its built-in software dissector
immediately.

## Values

See [`values.yaml`](values.yaml) for the full list. Most operators only
need to override `image.repository` and `image.tag`.

## Image

The container image is produced by the Nix flake in this repository:

```bash
nix build .#xdp2-flow-ebpf-image
docker load < result
```

## Security

- Pods run `hostNetwork: true` because the flow-dissector hook is a
  netns-scoped resource — we must attach in the host netns to affect
  all pod traffic on the node.
- The container drops `ALL` capabilities and re-adds exactly the three
  required to call `bpf(BPF_PROG_ATTACH, ..., BPF_FLOW_DISSECTOR)`.
- `allowPrivilegeEscalation: false` prevents the loader process from
  gaining additional capabilities at runtime.
- `readOnlyRootFilesystem: true` — the loader is a short-lived
  attach-then-sleep process with no runtime writes.
