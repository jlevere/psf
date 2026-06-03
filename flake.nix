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
        nightlyToolchain = fenix.packages.${system}.complete.toolchain;
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
            echo "Fuzz:  nix develop .#fuzz"
          '';
        };

        # Nightly toolchain + cargo-fuzz, isolated from the default stable
        # shell. Enter with `nix develop .#fuzz`.
        devShells.fuzz = pkgs.mkShell {
          name = "psf-fuzz";
          packages = [
            nightlyToolchain
            pkgs.cargo-fuzz
            pkgs.hexyl
          ];
          shellHook = ''
            echo "psf -- fuzzing shell (nightly + cargo-fuzz)"
            echo ""
            echo "Seed:  ./fuzz/seed_corpus.sh                          # valid artifacts -> corpora"
            echo "List:  cargo fuzz list"
            echo "Run:   cargo fuzz run fuzz_cix -- -dict=fuzz/cix.dict"
            echo "       cargo fuzz run fuzz_psf -- -dict=fuzz/psf.dict"
            echo "Repro: cargo fuzz run fuzz_cix fuzz/artifacts/fuzz_cix/<crash>"
          '';
        };
      });
}
