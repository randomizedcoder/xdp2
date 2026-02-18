# nix/microvms/x86_64.nix
#
# DEPRECATED: This file is a compatibility wrapper.
# Use mkVm.nix directly with arch = "x86_64" instead.
#
# This wrapper maintains backwards compatibility with code that
# directly imports this file.
#
{ pkgs, lib, microvm, nixpkgs }:

import ./mkVm.nix {
  inherit pkgs lib microvm nixpkgs;
  arch = "x86_64";
}
