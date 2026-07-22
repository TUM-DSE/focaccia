{
  description = "Focaccia: Translation Validator for CPU Emulators";

  inputs = {
    self.submodules = true;

    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

    flake-utils.url = "github:numtide/flake-utils";

    pyproject-nix = {
      url = "github:pyproject-nix/pyproject.nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    uv2nix = {
      url = "github:pyproject-nix/uv2nix";
      inputs.nixpkgs.follows = "nixpkgs";
      inputs.pyproject-nix.follows = "pyproject-nix";
    };

    pyproject-build-systems = {
      url = "github:pyproject-nix/build-system-pkgs";
      inputs.uv2nix.follows = "uv2nix";
      inputs.nixpkgs.follows = "nixpkgs";
      inputs.pyproject-nix.follows = "pyproject-nix";
    };

    qemu-submodule = {
      url = "path:qemu/";
      flake = true;
    };
  };

  outputs = {
    uv2nix,
    nixpkgs,
    flake-utils,
    pyproject-nix,
    pyproject-build-systems,
    qemu-submodule,
    ...
  }:
  flake-utils.lib.eachSystem [ "x86_64-linux" "aarch64-linux" ] (system:
  let
    pkgs = import nixpkgs { inherit system; };

    python = pkgs.python312;

    musl-pkgs = import nixpkgs {
      inherit system;
      crossSystem.config = "${system}-musl";
    };

    minimal-compile-flags =
      " -mno-xsave -mno-xsaveopt -mno-xsavec -mno-xsaves -mno-avx"
      + " -mno-avx2 -mno-avx512f -static";

    musl-minimal-pkgs = import nixpkgs {
      inherit system;
      crossSystem.config = "${system}-musl";
      overlays = [
        (_final: prev: {
          stdenv = prev.stdenv.override (old: {
            cc =
              if old.cc != null then
                old.cc.overrideAttrs (ccOld: {
                  env =
                    let
                      oldEnv = ccOld.env or {};
                      oldFlags = oldEnv.NIX_CFLAGS_COMPILE or "";
                    in
                    oldEnv // { NIX_CFLAGS_COMPILE = oldFlags + minimal-compile-flags; };
                })
              else
                null;
          });
        })
      ];
    };


    workspace = uv2nix.lib.workspace.loadWorkspace { workspaceRoot = ./.; };

    overlay = workspace.mkPyprojectOverlay { sourcePreference = "wheel"; };

    editableOverlay = workspace.mkEditablePyprojectOverlay {
      root = "$REPO_ROOT";
      members = [ "focaccia" "miasm" ];
    };


    zydis-shared-object = pkgs.zydis.overrideAttrs (old: {
      cmakeFlags = (old.cmakeFlags or []) ++ [ "-DZYDIS_BUILD_SHARED_LIB=ON" ];
    });

    box64-patched = pkgs.stdenv.mkDerivation {
      pname = "box64";
      version = "74d4db";

      src = pkgs.fetchFromGitHub {
        owner = "ptitSeb";
        repo = "box64";
        rev = "74d4db051b4c74aaab23b19fbb51e441448faf8e";
        sha256 = "sha256-G6tsqXsnTrs8I47YLnuivC79IFDGfbiLSm4J2Djc0kU=";
      };

      nativeBuildInputs = with pkgs; [ cmake python pkg-config zydis-shared-object ];
      cmakeFlags = [ "-DDYNAREC=ON" "-DHAVE_TRACE=ON" ];
      patches = [ ./fix-box64.patch ];

      installPhase = ''
        runHook preInstall
        mkdir -p $out/bin
        cp box64 $out/bin/
        runHook postInstall
      '';
    };


    lldbPostInstall = ''
      set -eu
      target="$out/${python.sitePackages}"
      src="$(${pkgs.lldb}/bin/lldb -P)"
      mkdir -p "$target"
      if [ -d "$src/lldb" ]; then
        ln -sTf "$src/lldb" "$target/lldb"
      fi
      if [ -f "$src/LLDB.py" ]; then
        cp -a "$src/LLDB.py" "$target/"
      fi
    '';

    lldbPostInstallEditable = ''
      set -eu
      target="$out/${python.sitePackages}"
      src="$(${pkgs.lldb}/bin/lldb -P)"
      mkdir -p "$target"
      if [ -h "$src/lldb" ]; then
        ln -sT "$src/lldb" "$target/lldb"
      fi
      if [ -f "$src/LLDB.py" ]; then
        cp -a "$src/LLDB.py" "$target/"
      fi
    '';

    pyprojectOverrides = self: super: {
      miasm = super.miasm.overrideAttrs (old: {
        nativeBuildInputs = (old.nativeBuildInputs or []) ++ [ self.setuptools ];
      });

      cpuid = super.cpuid.overrideAttrs (old: {
        nativeBuildInputs = (old.nativeBuildInputs or []) ++ [ self.setuptools ];
      });

      focaccia = super.focaccia.overrideAttrs (old: {
        buildInputs = (old.buildInputs or []) ++ [ pkgs.lldb ];
        postInstall = (old.postInstall or "") + lldbPostInstall;
      });
    };

    pyprojectOverridesEditable = self: super: {
      miasm = super.miasm.overrideAttrs (old: {
        nativeBuildInputs = (old.nativeBuildInputs or []) ++ [ self.setuptools ];
        src = pkgs.lib.fileset.toSource {
          root = old.src;
          fileset = pkgs.lib.fileset.unions [
            (old.src + "/pyproject.toml")
            (old.src + "/README.md")
            (old.src + "/src/miasm/__init__.py")
          ];
        };
      });

      cpuid = super.cpuid.overrideAttrs (old: {
        nativeBuildInputs = (old.nativeBuildInputs or []) ++ [ self.setuptools ];
      });

      focaccia = super.focaccia.overrideAttrs (old: {
        nativeBuildInputs = (old.nativeBuildInputs or []) ++
                            [ pkgs.lldb ] ++
                            self.resolveBuildSystem { editables = []; };
        src = pkgs.lib.fileset.toSource {
          root = old.src;
          fileset = pkgs.lib.fileset.unions [
            (old.src + "/pyproject.toml")
            (old.src + "/README.md")
            (old.src + "/src/focaccia/__init__.py")
          ];
        };
        postInstall = (old.postInstall or "") + lldbPostInstallEditable;
      });
    };

    pythonSet = (pkgs.callPackage pyproject-nix.build.packages { inherit python; }).overrideScope (
      pkgs.lib.composeManyExtensions [
        pyproject-build-systems.overlays.default
        overlay
        pyprojectOverrides
      ]
    );

    pythonSetEditable = pythonSet.overrideScope (
      pkgs.lib.composeManyExtensions [
        editableOverlay
        pyprojectOverridesEditable
      ]
    );

    pythonEnv = pythonSet.mkVirtualEnv "focaccia-env" workspace.deps.default;
    pythonDevEnv = pythonSetEditable.mkVirtualEnv "focaccia-dev-env" workspace.deps.all;
    pythonStaticUnitEnv = pythonSet.mkVirtualEnv "focaccia-static-unit-env" workspace.deps.all;

    devEnv = pythonDevEnv.overrideAttrs (old: {
      buildPhase = ''
        ${checkSubmodulesInitialized}
        ${old.buildPhase or ""}
      '';
      propagatedBuildInputs = (old.propagatedBuildInputs or []) ++ [
        pkgs.uv
        pkgs.lldb
        gdbInternal
        pkgs.nodejs
      ];
    });

    gdbInternal = pkgs.gdb.override { python3 = python; };

    rr = pkgs.rr.overrideAttrs (old: {
      pname = "focaccia-rr";
      version = "git";
      src = ./rr;
    });

    uvEnv = {
      UV_NO_SYNC = "1";
      UV_PYTHON = python.interpreter;
      UV_PYTHON_DOWNLOADS = "never";
    };

    uvShellHook = ''
      unset PYTHONPATH
      export REPO_ROOT=$(git rev-parse --show-toplevel)
    '';

    checkSubmodulesInitialized = ''
      if ! ${pkgs.git}/bin/git submodule status --recursive >/dev/null 2>&1; then
        printf 'Error: git submodules not initialized correctly, build cannot proceed\n'
        printf 'Run git submodule update --init --recursive and then rebuild\n'
        exit 2
      fi
    '';

    # Helper to create musl dev shells with shared boilerplate
    mkMuslShell = { name ? "focaccia-musl", extraPackages ? [], extraShellHook ? "" }:
      pkgs.mkShell {
        inherit name;
        packages = [
          devEnv
          musl-pkgs.gcc
          musl-pkgs.pkg-config
        ] ++ extraPackages;

        hardeningDisable = [ "pie" ];
        env = uvEnv;
        shellHook = uvShellHook + extraShellHook;
      };

    musl-minimal-redis = musl-minimal-pkgs.pkgsStatic.redis.overrideAttrs (_: { doCheck = false; });
    musl-minimal-sqlite = musl-minimal-pkgs.pkgsStatic.sqlite.overrideAttrs (_: { doCheck = false; });
    musl-minimal-memcached = musl-minimal-pkgs.pkgsStatic.memcached.overrideAttrs (_: { doCheck = false; });
    musl-minimal-curl = musl-minimal-pkgs.pkgsStatic.curl.overrideAttrs (old: {
      doCheck = false;
      configureFlags = (old.configureFlags or []) ++ [ "--disable-hyper" ];
    });

    staticUnitSource = pkgs.lib.fileset.toSource {
      root = ./.;
      fileset = pkgs.lib.fileset.unions [
        ./pyproject.toml
        ./src/focaccia
        ./tests
      ];
    };

    mkStaticUnitCheck = { name, ruffTargets, pytestTargets }:
      pkgs.stdenv.mkDerivation {
        inherit name;
        src = staticUnitSource;

        doCheck = true;
        dontBuild = true;
        nativeCheckInputs = [ pythonStaticUnitEnv pkgs.nodejs ];

        checkPhase = ''
          set -euo pipefail
          export REPO_ROOT="$PWD"

          ruff check ${pkgs.lib.escapeShellArgs ruffTargets}
          python -m pyright
          python -m pytest -q -m 'not integration' \
            ${pkgs.lib.escapeShellArgs pytestTargets}

          touch "$out"
        '';

        env = uvEnv;
      };

    staticUnitChecks = mkStaticUnitCheck {
      name = "static-unit-checks";
      ruffTargets = [
        "src/focaccia/__init__.py"
        "src/focaccia/arch/__init__.py"
        "src/focaccia/arch/arch.py"
        "src/focaccia/arch/aarch64.py"
        "src/focaccia/arch/x86.py"
        "src/focaccia/cli.py"
        "src/focaccia/compare.py"
        "src/focaccia/match.py"
        "src/focaccia/miasm_util.py"
        "src/focaccia/native/lldb_target.py"
        "src/focaccia/native/tracer.py"
        "src/focaccia/parser.py"
        "src/focaccia/persistence.py"
        "src/focaccia/qemu/_qemu_tool.py"
        "src/focaccia/qemu/deterministic.py"
        "src/focaccia/qemu/target.py"
        "src/focaccia/qemu/validation_server.py"
        "src/focaccia/reproducer.py"
        "src/focaccia/snapshot.py"
        "src/focaccia/symbolic.py"
        "src/focaccia/tools/capture_transforms.py"
        "src/focaccia/tools/validate_qemu.py"
        "src/focaccia/trace.py"
        "tests"
      ];
      pytestTargets = [ "tests" ];
    };

    registerApiMigrationCheck = mkStaticUnitCheck {
      name = "register-api-migration";
      ruffTargets = [
        "src/focaccia/parser.py"
        "src/focaccia/native/lldb_target.py"
        "src/focaccia/qemu/validation_server.py"
        "tests/test_api_migrations.py"
        "tests/test_snapshot.py"
      ];
      pytestTargets = [
        "tests/test_snapshot.py"
        "tests/test_api_migrations.py"
      ];
    };

    cliImportsCheck = mkStaticUnitCheck {
      name = "cli-imports";
      ruffTargets = [
        "src/focaccia/cli.py"
        "src/focaccia/reproducer.py"
        "tests/test_cli.py"
        "tests/test_core_imports.py"
      ];
      pytestTargets = [
        "tests/test_core_imports.py"
        "tests/test_cli.py"
      ];
    };

    nativeReadPcCheck = mkStaticUnitCheck {
      name = "native-read-pc";
      ruffTargets = [
        "src/focaccia/native/lldb_target.py"
        "src/focaccia/native/tracer.py"
        "tests/test_native_api.py"
      ];
      pytestTargets = [
        "tests/test_native_api.py"
        "-k"
        "read_pc or speculative"
      ];
    };

    localTargetSelectionCheck = mkStaticUnitCheck {
      name = "local-target-selection";
      ruffTargets = [
        "src/focaccia/cli.py"
        "src/focaccia/reproducer.py"
        "src/focaccia/native/tracer.py"
        "tests/test_cli.py"
        "tests/test_native_api.py"
      ];
      pytestTargets = [
        "tests/test_cli.py"
        "tests/test_native_api.py"
        "-k"
        "local_target"
      ];
    };

    disassemblyFallbackCheck = mkStaticUnitCheck {
      name = "disassembly-fallback";
      ruffTargets = [
        "src/focaccia/native/tracer.py"
        "tests/test_native_api.py"
      ];
      pytestTargets = [
        "tests/test_native_api.py"
        "-k"
        "disassembly_fallback"
      ];
    };

    remoteTargetSelectionCheck = mkStaticUnitCheck {
      name = "remote-target-selection";
      ruffTargets = [
        "src/focaccia/native/tracer.py"
        "src/focaccia/tools/capture_transforms.py"
        "tests/test_native_api.py"
      ];
      pytestTargets = [
        "tests/test_native_api.py"
        "-k"
        "remote_target or remote_default"
      ];
    };

    oracleProgramRoutingCheck = mkStaticUnitCheck {
      name = "oracle-program-routing";
      ruffTargets = [
        "src/focaccia/cli.py"
        "src/focaccia/native/tracer.py"
        "tests/test_cli.py"
        "tests/test_native_api.py"
      ];
      pytestTargets = [
        "tests/test_cli.py"
        "tests/test_native_api.py"
        "-k"
        "oracle_program or missing_deterministic_log"
      ];
    };

    fix028CrossValidateOptionCheck = mkStaticUnitCheck {
      name = "fix-028-cross-validate-option";
      ruffTargets = [
        "src/focaccia/tools/capture_transforms.py"
        "tests/test_native_tracing.py"
      ];
      pytestTargets = [
        "tests/test_native_tracing.py"
        "-k"
        "capture_options"
      ];
    };

    fix030NativeEventMatchingCheck = mkStaticUnitCheck {
      name = "fix-030-native-event-matching";
      ruffTargets = [
        "src/focaccia/native/tracer.py"
        "tests/test_native_tracing.py"
      ];
      pytestTargets = [
        "tests/test_native_tracing.py"
        "-k"
        "event_matching"
      ];
    };

    fix031SpeculativeSynchronizationCheck = mkStaticUnitCheck {
      name = "fix-031-speculative-synchronization";
      ruffTargets = [
        "src/focaccia/native/tracer.py"
        "tests/test_native_tracing.py"
      ];
      pytestTargets = [
        "tests/test_native_tracing.py"
        "-k"
        "speculation or branch_mismatch or predicted_exit or unknown_destination or memory_write or register_write"
      ];
    };

    nativeTargetErrorHandlingCheck = mkStaticUnitCheck {
      name = "native-target-error-handling";
      ruffTargets = [
        "src/focaccia/native/lldb_target.py"
        "tests/test_native_tracing.py"
      ];
      pytestTargets = [
        "tests/test_native_tracing.py"
        "-k"
        "lldb_target or run_until or breakpoint or lldb_scalar or lldb_memory_reads"
      ];
    };

    nativeGapErrorBoundariesCheck = mkStaticUnitCheck {
      name = "native-gap-error-boundaries";
      ruffTargets = [
        "src/focaccia/native/tracer.py"
        "src/focaccia/symbolic.py"
        "tests/test_native_api.py"
      ];
      pytestTargets = [
        "tests/test_native_api.py"
        "-k"
        "force_mode_records or symbolic_execution_not_implemented or disassembly_fallback_does_not_hide"
      ];
    };

    nativeVectorRegisterByteOrderCheck = mkStaticUnitCheck {
      name = "native-vector-register-byte-order";
      ruffTargets = [
        "src/focaccia/native/lldb_target.py"
        "tests/test_native_tracing.py"
      ];
      pytestTargets = [
        "tests/test_native_tracing.py"
        "-k"
        "vector_reads or 80_bit_register"
      ];
    };

    nativeScriptedTracingCheck = mkStaticUnitCheck {
      name = "native-scripted-tracing";
      ruffTargets = [
        "src/focaccia/native/lldb_target.py"
        "src/focaccia/native/tracer.py"
        "src/focaccia/tools/capture_transforms.py"
        "tests/test_native_api.py"
        "tests/test_native_tracing.py"
      ];
      pytestTargets = [
        "tests/test_native_api.py"
        "tests/test_native_tracing.py"
      ];
    };

    architectureIdentityCheck = mkStaticUnitCheck {
      name = "architecture-identity";
      ruffTargets = [
        "src/focaccia/arch"
        "src/focaccia/parser.py"
        "src/focaccia/symbolic.py"
        "tests/test_architecture.py"
        "tests/test_state_serialization.py"
      ];
      pytestTargets = [
        "tests/test_architecture.py"
        "tests/test_state_serialization.py"
        "-k"
        "identity or serialization"
      ];
    };

    sparseMemoryValidityCheck = mkStaticUnitCheck {
      name = "sparse-memory-validity";
      ruffTargets = [
        "src/focaccia/qemu/validation_server.py"
        "src/focaccia/snapshot.py"
        "tests/test_plugin_state_validity.py"
        "tests/test_sparse_memory.py"
        "tests/test_state_serialization.py"
      ];
      pytestTargets = [
        "tests/test_plugin_state_validity.py"
        "tests/test_sparse_memory.py"
        "tests/test_state_serialization.py"
      ];
    };

    registerValidityCheck = mkStaticUnitCheck {
      name = "register-validity";
      ruffTargets = [
        "src/focaccia/arch"
        "src/focaccia/qemu/validation_server.py"
        "src/focaccia/snapshot.py"
        "tests/test_plugin_state_validity.py"
        "tests/test_snapshot.py"
      ];
      pytestTargets = [
        "tests/test_plugin_state_validity.py"
        "tests/test_snapshot.py"
      ];
    };

    multibitFlagsCheck = mkStaticUnitCheck {
      name = "multibit-flags";
      ruffTargets = [
        "src/focaccia/arch/aarch64.py"
        "src/focaccia/arch/x86.py"
        "tests/test_architecture.py"
      ];
      pytestTargets = [
        "tests/test_architecture.py"
        "-k"
        "multibit"
      ];
    };

    aarch64RegisterSemanticsCheck = mkStaticUnitCheck {
      name = "aarch64-register-semantics";
      ruffTargets = [
        "src/focaccia/arch/aarch64.py"
        "src/focaccia/snapshot.py"
        "src/focaccia/symbolic.py"
        "tests/test_architecture.py"
      ];
      pytestTargets = [
        "tests/test_architecture.py"
        "-k"
        "aarch64_zero or aarch64_status or symbolic_writes_to_aarch64_zero"
      ];
    };

    memoryByteOrderCheck = mkStaticUnitCheck {
      name = "memory-byte-order";
      ruffTargets = [
        "src/focaccia/native/lldb_target.py"
        "src/focaccia/qemu/target.py"
        "tests/test_memory_byte_order.py"
      ];
      pytestTargets = [ "tests/test_memory_byte_order.py" ];
    };

    syscallModelBoundaryCheck = mkStaticUnitCheck {
      name = "syscall-model-boundary";
      ruffTargets = [
        "src/focaccia/arch"
        "src/focaccia/qemu/deterministic.py"
        "src/focaccia/qemu/target.py"
        "tests/test_architecture.py"
      ];
      pytestTargets = [
        "tests/test_architecture.py"
        "-k"
        "syscall_replay_policy"
      ];
    };

    explicitTraceKindsCheck = mkStaticUnitCheck {
      name = "explicit-trace-kinds";
      ruffTargets = [
        "src/focaccia/trace.py"
        "tests/test_api_migrations.py"
        "tests/test_trace.py"
      ];
      pytestTargets = [
        "tests/test_api_migrations.py"
        "tests/test_trace.py"
        "-k"
        "trace_contract_migration or trace_kinds_are_explicit or transform_stream or transition_trace"
      ];
    };

    repeatableMaterializedTracesCheck = mkStaticUnitCheck {
      name = "repeatable-materialized-traces";
      ruffTargets = [
        "src/focaccia/trace.py"
        "tests/test_state_serialization.py"
        "tests/test_trace.py"
      ];
      pytestTargets = [
        "tests/test_state_serialization.py"
        "tests/test_trace.py"
        "-k"
        "materialized_program_state or materialized_symbolic or empty_materialized_trace or snapshot_serialization"
      ];
    };

    explicitTraceAddressesCheck = mkStaticUnitCheck {
      name = "explicit-trace-addresses";
      ruffTargets = [
        "src/focaccia/parser.py"
        "src/focaccia/trace.py"
        "tests/test_state_serialization.py"
        "tests/test_trace.py"
      ];
      pytestTargets = [
        "tests/test_state_serialization.py"
        "tests/test_trace.py"
        "-k"
        "materialized_program_state or requires_explicit_matching_addresses or snapshot_serialization"
      ];
    };

    traceEnvironmentIdentityCheck = mkStaticUnitCheck {
      name = "trace-environment-identity";
      ruffTargets = [
        "src/focaccia/trace.py"
        "tests/test_trace.py"
      ];
      pytestTargets = [
        "tests/test_trace.py"
        "-k"
        "trace_environment"
      ];
    };

    unknownTraceEnvironmentCheck = mkStaticUnitCheck {
      name = "unknown-trace-environment";
      ruffTargets = [
        "src/focaccia/parser.py"
        "src/focaccia/trace.py"
        "tests/test_trace.py"
      ];
      pytestTargets = [
        "tests/test_trace.py"
        "-k"
        "legacy_log_parser_uses_typed_unknown_environment"
      ];
    };

    materializedSnapshotSerializationCheck = mkStaticUnitCheck {
      name = "materialized-snapshot-serialization";
      ruffTargets = [
        "src/focaccia/parser.py"
        "src/focaccia/trace.py"
        "tests/test_trace.py"
      ];
      pytestTargets = [
        "tests/test_trace.py"
        "-k"
        "empty_materialized_snapshot_serialization"
      ];
    };

    qemuSnapshotTraceConstructionCheck = mkStaticUnitCheck {
      name = "qemu-snapshot-trace-construction";
      ruffTargets = [
        "src/focaccia/qemu/_qemu_tool.py"
        "src/focaccia/qemu/validation_server.py"
        "src/focaccia/tools/validate_qemu.py"
        "tests/test_qemu_trace_output.py"
      ];
      pytestTargets = [ "tests/test_qemu_trace_output.py" ];
    };

    freshFileHashesCheck = mkStaticUnitCheck {
      name = "fresh-file-hashes";
      ruffTargets = [
        "src/focaccia/utils.py"
        "tests/test_file_hash.py"
      ];
      pytestTargets = [ "tests/test_file_hash.py" ];
    };

    traceSchemaV2Check = mkStaticUnitCheck {
      name = "trace-schema-v2";
      ruffTargets = [
        "src/focaccia/parser.py"
        "src/focaccia/persistence.py"
        "tests/test_persistence.py"
      ];
      pytestTargets = [
        "tests/test_persistence.py"
        "-k"
        "schema_v2 or share_logical_header or explicit_null_binary_hash or unknown_schema"
      ];
    };

    traceSchemaV3Check = mkStaticUnitCheck {
      name = "trace-schema-v3";
      ruffTargets = [
        "src/focaccia/parser.py"
        "src/focaccia/persistence.py"
        "src/focaccia/symbolic.py"
        "tests/test_persistence.py"
      ];
      pytestTargets = [
        "tests/test_persistence.py"
        "-k"
        "schema_v3 or ordered_memory_writes or trace_gaps or malformed_trace_gap"
      ];
    };

    jsonTraceRoundtripCheck = mkStaticUnitCheck {
      name = "json-trace-roundtrip";
      ruffTargets = [
        "src/focaccia/persistence.py"
        "tests/test_persistence.py"
        "tests/test_state_serialization.py"
      ];
      pytestTargets = [
        "tests/test_persistence.py"
        "tests/test_state_serialization.py"
        "-k"
        "json_transform_round_trip or aarch64_big_endian_state_round_trip or snapshot_serialization"
      ];
    };

    msgpackTraceRoundtripCheck = mkStaticUnitCheck {
      name = "msgpack-trace-roundtrip";
      ruffTargets = [
        "src/focaccia/persistence.py"
        "tests/test_persistence.py"
      ];
      pytestTargets = [
        "tests/test_persistence.py"
        "-k"
        "msgpack_transform_round_trip or truncated_and_trailing_msgpack"
      ];
    };

    legacyTraceReadersCheck = mkStaticUnitCheck {
      name = "legacy-trace-readers";
      ruffTargets = [
        "src/focaccia/persistence.py"
        "tests/test_persistence.py"
        "tests/test_trace.py"
      ];
      pytestTargets = [
        "tests/test_persistence.py"
        "tests/test_trace.py"
        "-k"
        "known_legacy or ambiguous_legacy or msgpack_transform_stream"
      ];
    };

    traceStructuralValidationCheck = mkStaticUnitCheck {
      name = "trace-structural-validation";
      ruffTargets = [
        "src/focaccia/persistence.py"
        "tests/test_persistence.py"
      ];
      pytestTargets = [
        "tests/test_persistence.py"
        "-k"
        "cardinality or memory_ranges or expression_widths or missing_versioned or top_level"
      ];
    };

    typedEmptyTracesCheck = mkStaticUnitCheck {
      name = "typed-empty-traces";
      ruffTargets = [
        "src/focaccia/persistence.py"
        "tests/test_persistence.py"
        "tests/test_trace.py"
      ];
      pytestTargets = [
        "tests/test_persistence.py"
        "tests/test_trace.py"
        "-k"
        "empty_state_trace or empty_transform_trace or empty_materialized_snapshot"
      ];
    };

    transitionBoundaryMatchingCheck = mkStaticUnitCheck {
      name = "transition-boundary-matching";
      ruffTargets = [
        "src/focaccia/match.py"
        "src/focaccia/trace.py"
        "tests/test_match.py"
        "tests/test_trace.py"
      ];
      pytestTargets = [
        "tests/test_match.py"
        "tests/test_trace.py"
        "-k"
        "linear_match or single_transform or unmatched_terminal or transition_trace"
      ];
    };

    terminalTransitionValidationCheck = mkStaticUnitCheck {
      name = "terminal-transition-validation";
      ruffTargets = [
        "src/focaccia/compare.py"
        "src/focaccia/match.py"
        "src/focaccia/qemu/validation_server.py"
        "tests/test_compare.py"
        "tests/test_qemu_matching.py"
      ];
      pytestTargets = [
        "tests/test_compare.py"
        "tests/test_qemu_matching.py"
        "-k"
        "final_transition or single_transition or destination_for_single or preserves_final or missing_terminal or gdb_collector"
      ];
    };

    adaptiveCutpointCompositionCheck = mkStaticUnitCheck {
      name = "adaptive-cutpoint-composition";
      ruffTargets = [
        "src/focaccia/match.py"
        "tests/test_match.py"
        "tests/test_qemu_matching.py"
      ];
      pytestTargets = [
        "tests/test_match.py"
        "tests/test_qemu_matching.py"
        "-k"
        "repeated_pc or skipped_symbolic or composed_cutpoint or one_shot or concrete_only or discontinuous or stop_address or composes_symbolic"
      ];
    };

    comparisonShapeDiagnosticsCheck = mkStaticUnitCheck {
      name = "comparison-shape-diagnostics";
      ruffTargets = [
        "src/focaccia/compare.py"
        "src/focaccia/utils.py"
        "tests/test_compare.py"
      ];
      pytestTargets = [
        "tests/test_compare.py"
        "-k"
        "empty or unequal or range_mismatch or unmatched_initial or zero_transition or renderer"
      ];
    };

    sharedTransitionMatcherCheck = mkStaticUnitCheck {
      name = "shared-transition-matcher";
      ruffTargets = [
        "src/focaccia/cli.py"
        "src/focaccia/match.py"
        "src/focaccia/qemu/_qemu_tool.py"
        "src/focaccia/qemu/validation_server.py"
        "tests/test_match.py"
        "tests/test_qemu_matching.py"
      ];
      pytestTargets = [
        "tests/test_match.py"
        "tests/test_qemu_matching.py"
      ];
    };

    fix046SymbolicCompositionCheck = mkStaticUnitCheck {
      name = "fix-046-symbolic-composition";
      ruffTargets = [
        "src/focaccia/arch"
        "src/focaccia/miasm_util.py"
        "src/focaccia/symbolic.py"
        "tests/test_symbolic_composition.py"
      ];
      pytestTargets = [ "tests/test_symbolic_composition.py" ];
    };

    fix045Fp32ToFp64Check = mkStaticUnitCheck {
      name = "fix-045-fp32-to-fp64";
      ruffTargets = [
        "src/focaccia/miasm_util.py"
        "tests/test_fp_semantics.py"
      ];
      pytestTargets = [ "tests/test_fp_semantics.py" ];
    };

    fix029ExplicitTraceGapsCheck = mkStaticUnitCheck {
      name = "fix-029-explicit-trace-gaps";
      ruffTargets = [
        "src/focaccia/compare.py"
        "src/focaccia/match.py"
        "src/focaccia/native/tracer.py"
        "src/focaccia/persistence.py"
        "src/focaccia/symbolic.py"
        "tests/test_native_api.py"
        "tests/test_persistence.py"
        "tests/test_trace_gaps.py"
      ];
      pytestTargets = [
        "tests/test_native_api.py"
        "tests/test_persistence.py"
        "tests/test_trace_gaps.py"
        "-k"
        "trace_gap or force_mode_records or gap_is_retained or gap_cannot or gap_preserves"
      ];
    };

    fix067X86ExtendedRegisterAliasesCheck = mkStaticUnitCheck {
      name = "fix-067-x86-extended-register-aliases";
      ruffTargets = [
        "src/focaccia/arch/x86.py"
        "src/focaccia/symbolic.py"
        "tests/test_symbolic_composition.py"
      ];
      pytestTargets = [
        "tests/test_symbolic_composition.py"
        "-k"
        "extended_register_aliases"
      ];
    };

    fix062TargetEnvironmentSymbolsCheck = mkStaticUnitCheck {
      name = "fix-062-target-environment-symbols";
      ruffTargets = [
        "src/focaccia/arch/aarch64.py"
        "src/focaccia/compare.py"
        "src/focaccia/miasm_util.py"
        "src/focaccia/native/lldb_target.py"
        "src/focaccia/symbolic.py"
        "tests/test_environment_symbols.py"
      ];
      pytestTargets = [ "tests/test_environment_symbols.py" ];
    };

  in rec {
    packages = rec {
      focaccia = pythonEnv.overrideAttrs (old: {
        buildPhase = ''
          ${checkSubmodulesInitialized}
          ${old.buildPhase or ""}
        '';
        propagatedBuildInputs = (old.propagatedBuildInputs or []) ++ [ pkgs.lldb ];
      });

      dev = devEnv;

      qemu-plugin = qemu-submodule.packages.${system}.default;

      default = focaccia;
    };

    apps = {
      default = {
        type = "app";
        program = "${packages.focaccia}/bin/focaccia";
      };

      convert-log = {
        type = "app";
        program = "${packages.focaccia}/bin/convert";
      };

      capture-transforms = {
        type = "app";
        program = "${packages.focaccia}/bin/capture-transforms";
      };

      validate-qemu = {
        type = "app";
        program = let
          wrapper = pkgs.writeShellScriptBin "validate-qemu" ''
            exec ${packages.focaccia}/bin/validate-qemu --gdb "${gdbInternal}/bin/gdb" "$@"
          '';
        in "${wrapper}/bin/validate-qemu";
      };

      uv-sync = {
        type = "app";
        program = "${pkgs.writeShellScriptBin "uv-sync" ''
          set -euo pipefail
          ${pkgs.uv}/bin/uv sync
          sed -i '/riscv/d' uv.lock
        ''}/bin/uv-sync";
      };
    };

    devShells = {
      default = pkgs.mkShell {
        packages = [ devEnv ];
        env = uvEnv;
        shellHook = uvShellHook;
      };

      glibc = pkgs.mkShell {
        packages = [
          packages.dev
          pkgs.gcc
          pkgs.glibc.all
        ];
        env = uvEnv;
        shellHook = uvShellHook;
      };

      musl = mkMuslShell {};

      musl-box64 = mkMuslShell {
        name = "focaccia-musl-box64";
        extraPackages = [ box64-patched ];
        extraShellHook = ''
          export BOX64_TRACE=1
          export BOX64_DYNAREC_TRACE=1
          export BOX64_DYNAREC_DF=0
          export LD_LIBRARY_PATH=''${LD_LIBRARY_PATH:+$LD_LIBRARY_PATH:}${zydis-shared-object}/lib
        '';
      };

      musl-extra = mkMuslShell {
        name = "focaccia-musl-extra";
        extraPackages = [ rr pkgs.capnproto ];
      };

      musl-all = mkMuslShell {
        name = "focaccia-musl-all";
        extraPackages = [
          rr
          pkgs.capnproto
          musl-pkgs.cmake
          musl-pkgs.stdenv
          musl-minimal-curl
          musl-minimal-redis
          musl-minimal-sqlite
          musl-minimal-memcached
          musl-minimal-pkgs.pkgsStatic.gzip
          musl-minimal-pkgs.pkgsStatic.file
          musl-minimal-pkgs.pkgsStatic.darkhttpd
          pkgs.memtier-benchmark
          pkgs.lua51Packages.luarocks
        ];
      };
    };


    checks = {
      static-unit-checks = staticUnitChecks;
      focaccia-tests = staticUnitChecks;
      register-api-migration = registerApiMigrationCheck;
      cli-imports = cliImportsCheck;
      native-read-pc = nativeReadPcCheck;
      local-target-selection = localTargetSelectionCheck;
      disassembly-fallback = disassemblyFallbackCheck;
      remote-target-selection = remoteTargetSelectionCheck;
      oracle-program-routing = oracleProgramRoutingCheck;
      fix-028-cross-validate-option = fix028CrossValidateOptionCheck;
      fix-030-native-event-matching = fix030NativeEventMatchingCheck;
      fix-031-speculative-synchronization = fix031SpeculativeSynchronizationCheck;
      native-target-error-handling = nativeTargetErrorHandlingCheck;
      native-gap-error-boundaries = nativeGapErrorBoundariesCheck;
      native-vector-register-byte-order = nativeVectorRegisterByteOrderCheck;
      native-scripted-tracing = nativeScriptedTracingCheck;
      architecture-identity = architectureIdentityCheck;
      sparse-memory-validity = sparseMemoryValidityCheck;
      register-validity = registerValidityCheck;
      multibit-flags = multibitFlagsCheck;
      aarch64-register-semantics = aarch64RegisterSemanticsCheck;
      memory-byte-order = memoryByteOrderCheck;
      syscall-model-boundary = syscallModelBoundaryCheck;
      explicit-trace-kinds = explicitTraceKindsCheck;
      repeatable-materialized-traces = repeatableMaterializedTracesCheck;
      explicit-trace-addresses = explicitTraceAddressesCheck;
      trace-environment-identity = traceEnvironmentIdentityCheck;
      unknown-trace-environment = unknownTraceEnvironmentCheck;
      materialized-snapshot-serialization = materializedSnapshotSerializationCheck;
      qemu-snapshot-trace-construction = qemuSnapshotTraceConstructionCheck;
      fresh-file-hashes = freshFileHashesCheck;
      trace-schema-v2 = traceSchemaV2Check;
      trace-schema-v3 = traceSchemaV3Check;
      json-trace-roundtrip = jsonTraceRoundtripCheck;
      msgpack-trace-roundtrip = msgpackTraceRoundtripCheck;
      legacy-trace-readers = legacyTraceReadersCheck;
      trace-structural-validation = traceStructuralValidationCheck;
      typed-empty-traces = typedEmptyTracesCheck;
      transition-boundary-matching = transitionBoundaryMatchingCheck;
      terminal-transition-validation = terminalTransitionValidationCheck;
      adaptive-cutpoint-composition = adaptiveCutpointCompositionCheck;
      comparison-shape-diagnostics = comparisonShapeDiagnosticsCheck;
      shared-transition-matcher = sharedTransitionMatcherCheck;
      fix-046-symbolic-composition = fix046SymbolicCompositionCheck;
      fix-045-fp32-to-fp64 = fix045Fp32ToFp64Check;
      fix-029-explicit-trace-gaps = fix029ExplicitTraceGapsCheck;
      fix-062-target-environment-symbols = fix062TargetEnvironmentSymbolsCheck;
      fix-067-x86-extended-register-aliases = fix067X86ExtendedRegisterAliasesCheck;
    };
  });
}
