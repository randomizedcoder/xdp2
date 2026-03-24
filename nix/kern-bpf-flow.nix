# nix/kern-bpf-flow.nix
#
# Fetch kernel BPF flow dissector source from Linux selftests.
#
# Downloads bpf_flow.c from the Linux kernel repository at a pinned
# version so the vendored copy in samples/flow_dissector/kern_bpf/
# can be easily updated when the kernel changes.
#
# Usage:
#   # Fetch the source (updates hash automatically on first build)
#   nix build .#kern-bpf-flow-src
#
#   # Update the vendored copy
#   cp result/bpf_flow.c samples/flow_dissector/kern_bpf/bpf_flow.c
#
# To update to a new kernel version:
#   1. Change `rev` below to the new tag/commit
#   2. Set hash to pkgs.lib.fakeHash
#   3. Run `nix build .#kern-bpf-flow-src` — it will fail and print the real hash
#   4. Replace the hash with the real one
#   5. Run again to verify, then copy the file
#

{ pkgs }:

let
  # Linux kernel version to fetch from.
  # Change rev to a tag (e.g., "v6.13") or commit SHA to update.
  rev = "v6.12";
in
pkgs.fetchurl {
  url = "https://raw.githubusercontent.com/torvalds/linux/${rev}/tools/testing/selftests/bpf/progs/bpf_flow.c";
  name = "bpf_flow.c";
  # To get the correct hash:
  #   nix-prefetch-url --type sha256 \
  #     https://raw.githubusercontent.com/torvalds/linux/v6.12/tools/testing/selftests/bpf/progs/bpf_flow.c
  #
  # Or set to pkgs.lib.fakeHash and let nix tell you.
  hash = pkgs.lib.fakeHash;
}
