#
# Nix flake for xdp2
#
# To develop for xdp2 run:
# nix develop
#
{
  description = "XDP2 development environment";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};

        # nixDebug = false;

        # Package groups for clarity and maintainability
        compilers = with pkgs; [ gcc clang ];
        buildTools = with pkgs; [ gnumake pkg-config bison flex llvm.dev ];
        coreUtils = with pkgs; [ bash coreutils gnused gawk gnutar xz git ];
        runtimeLibs = with pkgs; [ boost boost.dev boost.out libpcap libelf libbpf python3 ];
        devTools = with pkgs; [ graphviz bpftools ];

        # Combined package list - include everything everywhere for simplicity
        allPackages = compilers ++ buildTools ++ coreUtils ++ runtimeLibs ++ devTools;

        xdp2-build = pkgs.stdenv.mkDerivation {
          name = "xdp2-build";
          src = ./.;

          nativeBuildInputs = allPackages;
          buildInputs = allPackages;

          patchPhase = ''
            cd src
            substituteInPlace configure_nix --replace-fail '#!/bin/bash' '#!${pkgs.bash}/bin/bash'
            substituteInPlace test/parser/run-tests.sh --replace-fail '#!/bin/bash' '#!${pkgs.bash}/bin/bash'
          '';

          configurePhase = ''
            export HOST_LLVM_CONFIG=${pkgs.llvm.dev}/bin/llvm-config
            export HOST_CXX=clang
            export NIX_BOOST_DEV=${pkgs.boost.dev}
            export NIX_BOOST_OUT=${pkgs.boost.out}
            export NIX_LLVM_CONFIG=${pkgs.llvm.dev}/bin/llvm-config
            export NIX_CLANG_INCLUDES="-I${pkgs.clang}/include"
            ./configure_nix --build-opt-parser --installdir $out
          '';

          buildPhase = ''
            make
          '';

          installPhase = ''
            make install
          '';

          XDP2_CLANG_VERSION = pkgs.lib.getVersion pkgs.clang;
          XDP2_CLANG_RESOURCE_PATH = "${pkgs.clang}/lib/clang/${pkgs.lib.getVersion pkgs.clang}";
          HOST_LLVM_CONFIG = "${pkgs.llvm}/bin/llvm-config";
          BUILD_OPT_PARSER = "y";
        };
      in
      {
        devShells.default = pkgs.mkShell {
          buildInputs = allPackages;

          shellHook = ''
            export XDP2DIR=${xdp2-build}
            export CC=gcc
            export CXX=g++
            export HOST_CC=gcc
            export HOST_CXX=clang
            export HOST_LLVM_CONFIG=${pkgs.llvm}/bin/llvm-config
            export XDP2_CLANG_VERSION=${pkgs.lib.getVersion pkgs.clang}
            export XDP2_CLANG_RESOURCE_PATH=${pkgs.clang}/lib/clang/${pkgs.lib.getVersion pkgs.clang}
            export BUILD_OPT_PARSER=y
            export PYTHON_VER=3
            export PKG_CONFIG_PATH=${pkgs.lib.makeSearchPath "lib/pkgconfig" allPackages}
            export LD_LIBRARY_PATH=${pkgs.lib.makeLibraryPath allPackages}
          '';
        };
      });
}

# end