{ tir, system }:
let
  pkgs = import tir.inputs.nixpkgs {
    inherit system;
    overlays = [ (import tir.inputs.rust-overlay) ];
  };
  toolchain = pkgs.rust-bin.nightly.latest.default;
  craneLib = (tir.inputs.crane.mkLib pkgs).overrideToolchain toolchain;
  vendor = craneLib.vendorCargoDeps { cargoLock = "${tir}/Cargo.lock"; };
  # Resolve the bridge inside the fetched workspace using only the crate
  # versions already vendored from TIR's committed lockfile. No sibling checkout
  # or network access is needed by Cargo, including when producing this lockfile.
  source = pkgs.runCommand "focaccia-tir-oracle-source" {
    nativeBuildInputs = [ toolchain ];
  } ''
    mkdir -p "$out/focaccia-oracle" "$TMPDIR/cargo-home"
    cp ${tir}/Cargo.toml ${tir}/Cargo.lock "$out/"
    cp -r ${tir}/src ${tir}/crates "$out/"
    cp -r ${../rust/tir-oracle}/. "$out/focaccia-oracle/"
    chmod -R u+w "$out"
    substituteInPlace "$out/Cargo.toml" \
      --replace-fail '    "crates/tirrt-rt",' '    "crates/tirrt-rt", "focaccia-oracle",'
    export CARGO_HOME="$TMPDIR/cargo-home"
    cp ${vendor}/config.toml "$CARGO_HOME/config.toml"
    cd "$out"
    cargo generate-lockfile --offline
  '';
  args = {
    pname = "focaccia-tir-oracle";
    version = "0.1.0";
    src = source;
    cargoVendorDir = vendor;
    cargoExtraArgs = "--locked -p focaccia-tir-oracle";
    strictDeps = true;
    doCheck = false;
    nativeBuildInputs = [ pkgs.pkg-config pkgs.llvmPackages_18.llvm.dev ];
    buildInputs = [ pkgs.llvmPackages_18.libllvm pkgs.libffi pkgs.libxml2 pkgs.ncurses pkgs.zlib ];
    LLVM_CONFIG_PATH = "${pkgs.llvmPackages_18.llvm.dev}/bin/llvm-config";
    LLVM_SYS_181_PREFIX = "${pkgs.llvmPackages_18.llvm.dev}";
    RUSTFLAGS = "-C link-arg=-rdynamic";
    FOCACCIA_TIR_REVISION = tir.rev;
  };
  artifacts = craneLib.buildDepsOnly args;
  unwrapped = craneLib.buildPackage (args // { cargoArtifacts = artifacts; });
  prepared = pkgs.runCommand "focaccia-tir-prepared-specification" {
    nativeBuildInputs = [ unwrapped ];
    TIR_ASL_AST = "${tir.packages.${system}.asl-specification}/ast.json";
  } ''
    mkdir -p "$out"
    focaccia-tir-oracle --prepare "$out/module.bin"
  '';
in pkgs.symlinkJoin {
  name = "focaccia-tir-oracle-0.1.0";
  paths = [ unwrapped ];
  nativeBuildInputs = [ pkgs.makeWrapper ];
  postBuild = ''
    wrapProgram "$out/bin/focaccia-tir-oracle" \
      --set-default TIR_ASL_AST "${tir.packages.${system}.asl-specification}/ast.json" \
      --set FOCACCIA_TIR_MODULE "${prepared}/module.bin"
  '';
  passthru.preparedSpecification = prepared;
  meta.mainProgram = "focaccia-tir-oracle";
}
