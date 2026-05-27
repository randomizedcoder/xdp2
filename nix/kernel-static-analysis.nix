# Kernel-source static analysis tools.
#
# These are the tools used to vet the kernel-patches/ series before
# posting to netdev. They run against an actual kernel source tree
# (e.g. /home/das/Downloads/net-next), NOT against the xdp2 codebase.
#
# Usage:
#   nix build .#sparse-master
#   ./result/bin/sparse --version
#
# Then from inside the kernel tree:
#   make x86_64_defconfig
#   make C=2 CHECK=$(nix path-info /path/to/result)/bin/sparse \
#        net/core/flow_dissector.o
#
# Or via the convenience runner:
#   nix run .#kernel-check -- /home/das/Downloads/net-next \
#                              net/core/flow_dissector.o

{ pkgs, lib }:

let
  # Sparse from upstream master. Pinned by commit (or refs/heads/master
  # for floating). The nixpkgs 0.6.4-unstable-2024-02-03 does not
  # understand newer kernel macros like __typeof_unqual__.
  sparseMaster = pkgs.sparse.overrideAttrs (old: {
    version = "0.6.4-master";
    src = pkgs.fetchgit {
      url = "https://git.kernel.org/pub/scm/devel/sparse/sparse.git";
      rev = "refs/heads/master";
      sha256 = "sha256-662n1ENn8ZsiBtSBx6Vr1MrRAwzvob0Y1ifnBVtfB5k=";
    };
  });

  # smatch is already current in nixpkgs (1.74 at time of writing).
  # We expose it under a stable attribute name for the same UX as
  # sparse-master.
  smatch = pkgs.smatch;

  # Wrapper: 'kernel-check <kernel-tree> <target.o>'. Runs both
  # sparse-master and smatch as the 'CHECK=' tool, prints findings
  # in our file only (filters out included-header noise).
  kernelCheck = pkgs.writeShellApplication {
    name = "kernel-check";
    runtimeInputs = with pkgs; [
      flex bison bc elfutils openssl pkg-config gcc gnumake
      sparseMaster smatch coreutils gnugrep
    ];
    text = ''
      tree="$1"
      target="$2"
      cd "$tree"
      if [[ ! -f .config ]]; then
        make x86_64_defconfig >/dev/null 2>&1
      fi

      # Make sure the file is rebuilt so CHECK runs.
      src_c="''${target%.o}.c"

      run_check() {
        local name="$1"
        local tool="$2"
        local out
        echo "=== $name CHECK $target ==="
        touch "$src_c"
        out="$(make C=2 CHECK="$tool" "$target" 2>&1 || true)"
        local findings
        findings="$(echo "$out" | grep -E "^''${src_c}:[0-9]+:" || true)"
        if [[ -z "$findings" ]]; then
          echo "  (clean: no findings)"
        else
          echo "$findings"
        fi
      }

      run_check sparse-master "$(command -v sparse)"
      echo ""
      run_check smatch "$(command -v smatch)"
    '';
  };
in {
  inherit sparseMaster smatch kernelCheck;
}
