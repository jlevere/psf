{
  description = "Pure-Rust reader for Microsoft Patch Storage Files (PSTREAM / express download payloads) and their Container Index (CIX)";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    fenix = {
      url = "github:nix-community/fenix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, flake-utils, fenix }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };
        toolchain = fenix.packages.${system}.stable.toolchain;
      in {
        devShells.default = pkgs.mkShell {
          name = "psf";
          packages = [
            toolchain
            pkgs.rust-analyzer
            pkgs.cargo-nextest
            pkgs.hexyl
            pkgs.file
          ];
          shellHook = ''
            echo "psf -- PSTREAM Patch Storage File + CIX reader"
            echo "Build: cargo build  |  cargo nextest run"
          '';
        };
      });
}
