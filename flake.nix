{
  description = "Focaccia: Translation Validator for CPU Emulators";

  inputs = {
    self.submodules = false;

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
      url = "git+https://github.com/TUM-DSE/focaccia-qemu.git?rev=3b2a0fb80eb9b6b5f216fa69069e66210466f5eb&submodules=1";
      flake = true;
    };

    rr-submodule = {
      url = "git+https://github.com/rr-debugger/rr.git?rev=f248913aa51ccf61932145a67e08a1e811953a2b";
      flake = false;
    };
  };

  outputs = {
    self,
    uv2nix,
    nixpkgs,
    flake-utils,
    pyproject-nix,
    pyproject-build-systems,
    qemu-submodule,
    rr-submodule,
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
      members = [ "focaccia" ];
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

    developmentDependencies = workspace.deps.default // {
      focaccia = [ "dev" ];
    };

    pythonEnv = pythonSet.mkVirtualEnv "focaccia-env" workspace.deps.default;
    pythonDevEnv = pythonSetEditable.mkVirtualEnv "focaccia-dev-env" developmentDependencies;
    pythonStaticUnitEnv = pythonSet.mkVirtualEnv "focaccia-static-unit-env" developmentDependencies;

    devEnv = pythonDevEnv.overrideAttrs (old: {
      buildPhase = old.buildPhase or "";
      propagatedBuildInputs = (old.propagatedBuildInputs or []) ++ [
        pkgs.uv
        pkgs.lldb
        gdbInternal
        pkgs.nodejs
      ];
    });

    gdbInternal = pkgs.gdb.override { python3 = python; };

    rrTool = pkgs.rr.overrideAttrs (old: {
      pname = "focaccia-rr";
      version = "5.8.0";
      src = rr-submodule;
    });

    validateQemuWrapper = pkgs.writeShellScriptBin "validate-qemu" ''
      exec ${pythonEnv}/bin/validate-qemu --gdb "${gdbInternal}/bin/gdb" "$@"
    '';

    x86FileReadFixture =
      if system == "x86_64-linux" then
        pkgs.stdenv.mkDerivation {
          pname = "focaccia-x86-file-read-fixture";
          version = "1";
          src = ./tests/fixtures/integration;

          dontConfigure = true;
          dontStrip = true;
          hardeningDisable = [ "all" ];
          nativeBuildInputs = [ pkgs.binutils ];

          buildPhase = ''
            set -euo pipefail
            $CC -nostdlib -static -no-pie -Wl,--build-id=none \
              -o file-read x86_64-file-read.S
            ${pkgs.binutils}/bin/readelf -h file-read | \
              ${pkgs.gnugrep}/bin/grep -F 'Type:' | \
              ${pkgs.gnugrep}/bin/grep -F 'EXEC'
            ${pkgs.binutils}/bin/readelf -h file-read | \
              ${pkgs.gnugrep}/bin/grep -F 'Advanced Micro Devices X86-64'
            if ${pkgs.binutils}/bin/readelf -l file-read | \
                ${pkgs.gnugrep}/bin/grep -Fq 'INTERP'; then
              echo 'Smoke fixture unexpectedly has an ELF interpreter' >&2
              exit 1
            fi
            ${pkgs.binutils}/bin/nm file-read | \
              ${pkgs.gnugrep}/bin/grep -F ' _focaccia_trace_start'
            ${pkgs.binutils}/bin/nm file-read | \
              ${pkgs.gnugrep}/bin/grep -F ' _focaccia_trace_stop'
          '';

          installPhase = ''
            mkdir -p "$out/bin" "$out/share/focaccia-smoke"
            cp file-read "$out/bin/file-read"
            cp input.txt "$out/share/focaccia-smoke/input.txt"
          '';
        }
      else
        null;

    uvEnv = {
      UV_NO_SYNC = "1";
      UV_PYTHON = python.interpreter;
      UV_PYTHON_DOWNLOADS = "never";
    };

    uvSyncWrapper = pkgs.writeShellScriptBin "uv-sync" ''
      set -euo pipefail
      exec ${pkgs.uv}/bin/uv sync --locked "$@"
    '';

    uvShellHook = ''
      unset PYTHONPATH
      export REPO_ROOT=$(git rev-parse --show-toplevel)
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

    mkStaticUnitCheck = {
      name,
      ruffTargets,
      pytestTargets,
      extraCheckPhase ? "",
    }:
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

          ${extraCheckPhase}
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
        "src/focaccia/deterministic.py"
        "src/focaccia/experimental/__init__.py"
        "src/focaccia/experimental/scheduler.py"
        "src/focaccia/match.py"
        "src/focaccia/miasm_util.py"
        "src/focaccia/native/lldb_target.py"
        "src/focaccia/native/tracer.py"
        "src/focaccia/parser.py"
        "src/focaccia/persistence.py"
        "src/focaccia/qemu/_qemu_tool.py"
        "src/focaccia/qemu/aarch64.py"
        "src/focaccia/qemu/concurrency.py"
        "src/focaccia/qemu/deterministic.py"
        "src/focaccia/qemu/integration.py"
        "src/focaccia/qemu/replay.py"
        "src/focaccia/qemu/report.py"
        "src/focaccia/qemu/snapshot.py"
        "src/focaccia/qemu/state.py"
        "src/focaccia/qemu/syscall.py"
        "src/focaccia/qemu/target.py"
        "src/focaccia/qemu/transport.py"
        "src/focaccia/qemu/validation_server.py"
        "src/focaccia/qemu/x86.py"
        "src/focaccia/reproducer.py"
        "src/focaccia/rr"
        "src/focaccia/snapshot.py"
        "src/focaccia/symbolic.py"
        "src/focaccia/tools/capture_transforms.py"
        "src/focaccia/tools/rr_qemu_smoke.py"
        "src/focaccia/tools/validate_qemu.py"
        "src/focaccia/trace.py"
        "tests"
      ];
      pytestTargets = [ "tests" ];
    };

    reproducerMemoryLayoutCheck = mkStaticUnitCheck {
      name = "reproducer-memory-layout";
      ruffTargets = [
        "src/focaccia/reproducer.py"
        "tests/test_reproducer.py"
      ];
      pytestTargets = [
        "tests/test_reproducer.py"
        "-k"
        "memory"
      ];
    };

    reproducerStateRestorationCheck = mkStaticUnitCheck {
      name = "reproducer-state-restoration";
      ruffTargets = [
        "src/focaccia/reproducer.py"
        "tests/test_reproducer.py"
      ];
      pytestTargets = [
        "tests/test_reproducer.py"
        "-k"
        "state_restore or state_restoration"
      ];
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

    fix077LldbRemoteStateEventCheck = mkStaticUnitCheck {
      name = "fix-077-lldb-remote-state-event";
      ruffTargets = [
        "src/focaccia/native/lldb_target.py"
        "tests/test_native_tracing.py"
      ];
      pytestTargets = [
        "tests/test_native_tracing.py"
        "-k"
        "lldb_remote_initialization_consumes_delayed_stopped_event"
      ];
    };

    fix078NativeEventPhaseCheck = mkStaticUnitCheck {
      name = "fix-078-native-event-phase";
      ruffTargets = [
        "src/focaccia/native/tracer.py"
        "tests/test_deterministic.py"
        "tests/test_native_api.py"
      ];
      pytestTargets = [
        "tests/test_deterministic.py"
        "tests/test_native_api.py"
        "-k"
        "initial_post_event"
      ];
    };

    fix079LldbRemoteX86FlagsWidthCheck = mkStaticUnitCheck {
      name = "fix-079-lldb-remote-x86-flags-width";
      ruffTargets = [
        "src/focaccia/native/lldb_target.py"
        "tests/test_native_tracing.py"
      ];
      pytestTargets = [
        "tests/test_native_tracing.py"
        "-k"
        "lldb_remote_x86_flags_width"
      ];
    };

    fix086LldbCanonicalRflagsObservationCheck = mkStaticUnitCheck {
      name = "fix-086-lldb-canonical-rflags-observation";
      ruffTargets = [
        "src/focaccia/native/lldb_target.py"
        "tests/test_native_tracing.py"
      ];
      pytestTargets = [
        "tests/test_native_tracing.py"
        "-k"
        "lldb_canonical_rflags_read"
      ];
    };

    fix080RepeatedPcMaterializationCheck = mkStaticUnitCheck {
      name = "fix-080-repeated-pc-materialization";
      ruffTargets = [
        "src/focaccia/native/tracer.py"
        "tests/test_native_tracing.py"
      ];
      pytestTargets = [
        "tests/test_native_tracing.py"
        "-k"
        "repeated_pc_materialization"
      ];
    };

    fix081RecordedSyscallControlOutputCheck = mkStaticUnitCheck {
      name = "fix-081-recorded-syscall-control-output";
      ruffTargets = [
        "src/focaccia/native/tracer.py"
        "tests/test_native_api.py"
      ];
      pytestTargets = [
        "tests/test_native_api.py"
        "-k"
        "recorded_syscall_control_output"
      ];
    };

    fix088ObservedDivisionControlCheck = mkStaticUnitCheck {
      name = "fix-088-observed-division-control";
      ruffTargets = [
        "src/focaccia/native/tracer.py"
        "tests/test_native_api.py"
      ];
      pytestTargets = [
        "tests/test_native_api.py"
        "-k"
        "observed_division"
      ];
    };

    fix082X86SyscallEntryMatchingCheck = mkStaticUnitCheck {
      name = "fix-082-x86-syscall-entry-matching";
      ruffTargets = [
        "src/focaccia/native/tracer.py"
        "tests/test_native_tracing.py"
      ];
      pytestTargets = [
        "tests/test_native_tracing.py"
        "-k"
        "x86_syscall_entry_matching"
      ];
    };

    fix083NativeTerminalSyscallCheck = mkStaticUnitCheck {
      name = "fix-083-native-terminal-syscall";
      ruffTargets = [
        "src/focaccia/deterministic.py"
        "src/focaccia/native/tracer.py"
        "tests/test_deterministic.py"
        "tests/test_native_api.py"
        "tests/test_native_tracing.py"
      ];
      pytestTargets = [
        "tests/test_deterministic.py"
        "tests/test_native_api.py"
        "tests/test_native_tracing.py"
        "-k"
        "terminal_syscall"
      ];
    };

    fix087RrLldbSyscallBoundaryCheck = mkStaticUnitCheck {
      name = "fix-087-rr-lldb-syscall-boundary";
      ruffTargets = [
        "src/focaccia/native/tracer.py"
        "tests/test_native_tracing.py"
      ];
      pytestTargets = [
        "tests/test_native_tracing.py"
        "-k"
        "recorded_syscall_materialization or recorded_syscall_gap"
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

    fix021PluginFramedTransportCheck = mkStaticUnitCheck {
      name = "fix-021-plugin-framed-transport";
      ruffTargets = [
        "src/focaccia/qemu/transport.py"
        "tests/test_qemu_transport.py"
      ];
      pytestTargets = [ "tests/test_qemu_transport.py" ];
    };

    fix022PluginRegisterCacheCheck = mkStaticUnitCheck {
      name = "fix-022-plugin-register-cache";
      ruffTargets = [
        "src/focaccia/qemu/state.py"
        "src/focaccia/qemu/target.py"
        "src/focaccia/qemu/validation_server.py"
        "tests/test_gdb_program_state.py"
        "tests/test_plugin_state_validity.py"
      ];
      pytestTargets = [
        "tests/test_gdb_program_state.py"
        "tests/test_plugin_state_validity.py"
        "-k"
        "alias or flag or status or base_register"
      ];
    };

    fix033PluginConnectionOwnershipCheck = mkStaticUnitCheck {
      name = "fix-033-plugin-connection-ownership";
      ruffTargets = [
        "src/focaccia/qemu/transport.py"
        "src/focaccia/qemu/validation_server.py"
        "tests/test_plugin_state_validity.py"
        "tests/test_qemu_transport.py"
      ];
      pytestTargets = [
        "tests/test_plugin_state_validity.py"
        "tests/test_qemu_transport.py"
        "-k"
        "module_global or own_independent or context_manager"
      ];
    };

    fix054GdbLaunchEncodingCheck = mkStaticUnitCheck {
      name = "fix-054-gdb-launch-encoding";
      ruffTargets = [
        "src/focaccia/qemu/_qemu_tool.py"
        "src/focaccia/tools/validate_qemu.py"
        "tests/test_qemu_launcher.py"
      ];
      pytestTargets = [ "tests/test_qemu_launcher.py" ];
    };

    fix058SharedSnapshotPlannerCheck = mkStaticUnitCheck {
      name = "fix-058-shared-snapshot-planner";
      ruffTargets = [
        "src/focaccia/qemu/_qemu_tool.py"
        "src/focaccia/qemu/snapshot.py"
        "src/focaccia/qemu/validation_server.py"
        "tests/test_qemu_matching.py"
        "tests/test_qemu_snapshot.py"
      ];
      pytestTargets = [
        "tests/test_qemu_matching.py"
        "tests/test_qemu_snapshot.py"
      ];
    };

    fix070GdbWideRegisterCheck = mkStaticUnitCheck {
      name = "fix-070-gdb-wide-registers";
      ruffTargets = [
        "src/focaccia/qemu/state.py"
        "src/focaccia/qemu/target.py"
        "tests/test_gdb_program_state.py"
      ];
      pytestTargets = [
        "tests/test_gdb_program_state.py"
        "-k"
        "80_bit_scalar"
      ];
    };

    fix084X86EflagsObservationCheck = mkStaticUnitCheck {
      name = "fix-084-x86-eflags-observation";
      ruffTargets = [
        "src/focaccia/arch/arch.py"
        "src/focaccia/arch/x86.py"
        "src/focaccia/qemu/state.py"
        "tests/test_gdb_program_state.py"
        "tests/test_plugin_state_validity.py"
      ];
      pytestTargets = [
        "tests/test_gdb_program_state.py"
        "tests/test_plugin_state_validity.py"
        "-k"
        "flag_aliases or flag_reads or incomplete_flags_observation"
      ];
    };

    fix085FlakeSourceBoundaryCheck =
      assert qemu-submodule.rev == "3b2a0fb80eb9b6b5f216fa69069e66210466f5eb";
      assert rr-submodule.rev == "f248913aa51ccf61932145a67e08a1e811953a2b";
      pkgs.runCommand "fix-085-flake-source-boundary" {
        nativeBuildInputs = [ pkgs.coreutils pkgs.gnugrep ];
      } ''
        test ! -e ${self}/miasm/src/miasm
        test ! -e ${self}/qemu/softmmu
        test ! -e ${self}/rr/src

        self_kib=$(du -sk ${self} | cut -f1)
        test "$self_kib" -lt 65536

        grep -F 'miasm = { git = "https://github.com/taugoust/miasm.git", rev = "083c88f096d1b654069eff874356df7b2ecd4606" }' \
          ${self}/pyproject.toml
        grep -F 'source = { git = "https://github.com/taugoust/miasm.git?rev=083c88f096d1b654069eff874356df7b2ecd4606#083c88f096d1b654069eff874356df7b2ecd4606" }' \
          ${self}/uv.lock

        mkdir -p "$out"
        printf 'self_kib=%s\nqemu_rev=%s\nrr_rev=%s\n' \
          "$self_kib" \
          '${qemu-submodule.rev}' \
          '${rr-submodule.rev}' \
          > "$out/source-boundary.txt"
      '';

    explicitEmptyEventLogCheck = mkStaticUnitCheck {
      name = "explicit-empty-event-log";
      ruffTargets = [
        "src/focaccia/deterministic.py"
        "src/focaccia/native/tracer.py"
        "src/focaccia/qemu/_qemu_tool.py"
        "src/focaccia/qemu/target.py"
        "src/focaccia/tools/capture_transforms.py"
        "tests/test_deterministic.py"
        "tests/test_gdb_program_state.py"
        "tests/test_native_api.py"
      ];
      pytestTargets = [
        "tests/test_deterministic.py"
        "tests/test_gdb_program_state.py"
        "tests/test_native_api.py"
        "-k"
        "none_selects_explicit_empty_log or missing_deterministic_log_provides_empty_events or qemu_iterator_accepts_explicit_empty_event_log"
      ];
    };

    deterministicImportBoundaryCheck = mkStaticUnitCheck {
      name = "deterministic-import-boundary";
      ruffTargets = [
        "src/focaccia/deterministic.py"
        "tests/test_deterministic.py"
      ];
      pytestTargets = [
        "tests/test_deterministic.py"
        "-k"
        "only_parser_dependencies or unrelated_adapter_import"
      ];
    };

    rrSchemaV85PackagingCheck = mkStaticUnitCheck {
      name = "rr-schema-v85-packaging";
      ruffTargets = [
        "src/focaccia/deterministic.py"
        "src/focaccia/rr"
        "tests/test_rr_adapter.py"
      ];
      pytestTargets = [
        "tests/test_rr_adapter.py"
        "-k"
        "packaged_schema or rr_version_mismatch"
      ];
      extraCheckPhase = ''
        fixture="$PWD/tests/fixtures/deterministic/empty-x86"
        workdir="$TMPDIR/rr-schema-check"
        mkdir -p "$workdir"
        cd "$workdir"
        ${pythonEnv}/bin/python - "$fixture" <<'PY'
        import importlib.resources
        import sys

        from focaccia.deterministic import DeterministicLog
        from focaccia.rr.adapter import (
            RR_SCHEMA,
            RR_SCHEMA_ID,
            RR_SCHEMA_VERSION,
            RR_TRACE_VERSION,
        )

        resources = importlib.resources.files("focaccia.rr.schemas")
        assert resources.joinpath("rr_trace_v85.capnp").is_file()
        assert resources.joinpath("RR-LICENSE").is_file()
        log = DeterministicLog(sys.argv[1])
        assert log.metadata is not None
        assert log.metadata.trace_version == RR_TRACE_VERSION == 85
        assert log.metadata.schema_version == RR_SCHEMA_VERSION == "rr-trace-v85"
        assert log.metadata.schema_id == RR_SCHEMA_ID == "0xcaa0b1486c12c629"
        assert f"{RR_SCHEMA.schema.node.id:#x}" == RR_SCHEMA_ID
        PY
      '';
    };

    rrRegisterLayoutsCheck = mkStaticUnitCheck {
      name = "rr-register-layouts";
      ruffTargets = [
        "src/focaccia/deterministic.py"
        "src/focaccia/rr/adapter.py"
        "tests/test_rr_adapter.py"
      ];
      pytestTargets = [
        "tests/test_rr_adapter.py"
        "-k"
        "register_layout or register_decoders or aarch64_fixture"
      ];
    };

    rrMemoryWriteRangesCheck = mkStaticUnitCheck {
      name = "rr-memory-write-ranges";
      ruffTargets = [
        "src/focaccia/deterministic.py"
        "src/focaccia/qemu/target.py"
        "src/focaccia/rr/adapter.py"
        "tests/test_deterministic.py"
        "tests/test_gdb_program_state.py"
        "tests/test_rr_adapter.py"
      ];
      pytestTargets = [
        "tests/test_deterministic.py"
        "tests/test_gdb_program_state.py"
        "tests/test_rr_adapter.py"
        "-k"
        "memory_write_ranges or fully_known_memory or x86_fixture_decodes or memory_write_parser or qemu_replay_rejects_unknown_holes"
      ];
    };

    rrCompressedStreamsCheck = mkStaticUnitCheck {
      name = "rr-compressed-streams";
      ruffTargets = [
        "src/focaccia/rr/adapter.py"
        "tests/test_rr_adapter.py"
      ];
      pytestTargets = [
        "tests/test_rr_adapter.py"
        "-k"
        "compressed_reader or x86_fixture_decodes"
      ];
    };

    rrTaskEventVariantsCheck = mkStaticUnitCheck {
      name = "rr-task-event-variants";
      ruffTargets = [
        "src/focaccia/deterministic.py"
        "src/focaccia/rr/adapter.py"
        "tests/test_rr_adapter.py"
      ];
      pytestTargets = [
        "tests/test_rr_adapter.py"
        "-k"
        "all_task_variants or unknown_task_and_event"
      ];
    };

    deterministicEventCursorCheck = mkStaticUnitCheck {
      name = "deterministic-event-cursor";
      ruffTargets = [
        "src/focaccia/deterministic.py"
        "src/focaccia/native/tracer.py"
        "src/focaccia/qemu/target.py"
        "tests/test_deterministic.py"
        "tests/test_gdb_program_state.py"
      ];
      pytestTargets = [
        "tests/test_deterministic.py"
        "tests/test_gdb_program_state.py"
        "-k"
        "cursor_has_explicit or cursor_unsynchronized or cursor_configured or cursor_rejects_malformed or cursor_validates_signal or cursor_rejects_missing or qemu_event_loop_fails"
      ];
    };

    deterministicMappingCursorCheck = mkStaticUnitCheck {
      name = "deterministic-mapping-cursor";
      ruffTargets = [
        "src/focaccia/deterministic.py"
        "tests/test_deterministic.py"
        "tests/test_rr_adapter.py"
      ];
      pytestTargets = [
        "tests/test_deterministic.py"
        "tests/test_rr_adapter.py"
        "-k"
        "mapping_cursor or mapping_gaps"
      ];
    };

    x86SyscallEffectPoliciesCheck = mkStaticUnitCheck {
      name = "x86-syscall-effect-policies";
      ruffTargets = [
        "src/focaccia/qemu/deterministic.py"
        "src/focaccia/qemu/replay.py"
        "src/focaccia/qemu/syscall.py"
        "src/focaccia/qemu/x86.py"
        "tests/test_x86_replay.py"
      ];
      pytestTargets = [
        "tests/test_x86_replay.py"
        "-k"
        "policy or nested_output or opened_descriptor or rr_extra_effects"
      ];
    };

    x86ReplayFailClosedCheck = mkStaticUnitCheck {
      name = "x86-replay-fail-closed";
      ruffTargets = [
        "src/focaccia/qemu/concurrency.py"
        "src/focaccia/qemu/replay.py"
        "src/focaccia/qemu/syscall.py"
        "src/focaccia/qemu/target.py"
        "src/focaccia/qemu/x86.py"
        "tests/test_gdb_program_state.py"
        "tests/test_x86_replay.py"
      ];
      pytestTargets = [
        "tests/test_gdb_program_state.py"
        "tests/test_x86_replay.py"
        "-k"
        "unknown_syscall or unsafe_ioctl or thread_creating or unknown_holes or file_backed_mmap or unclassified_rr_event or unexpected_recorded_writes or unwritable_complete_fp_state"
      ];
    };

    x86NestedOutputReplayCheck = mkStaticUnitCheck {
      name = "x86-nested-output-replay";
      ruffTargets = [
        "src/focaccia/qemu/replay.py"
        "src/focaccia/qemu/syscall.py"
        "src/focaccia/qemu/x86.py"
        "tests/test_x86_replay.py"
      ];
      pytestTargets = [
        "tests/test_x86_replay.py"
        "-k"
        "read_translates_output or readv_nested or iovec_result"
      ];
    };

    x86SignalFrameAbiCheck = mkStaticUnitCheck {
      name = "x86-signal-frame-abi";
      ruffTargets = [
        "src/focaccia/qemu/replay.py"
        "src/focaccia/qemu/syscall.py"
        "src/focaccia/qemu/x86.py"
        "tests/test_x86_signal_replay.py"
      ];
      pytestTargets = [
        "tests/test_x86_signal_replay.py"
        "-k"
        "uapi_offset or recorded_signal_frame or variable_xstate or signal_delivery or malformed_fpstate or frame_context or sigaction"
      ];
    };

    x86SignalReturnCheck = mkStaticUnitCheck {
      name = "x86-signal-return";
      ruffTargets = [
        "src/focaccia/qemu/replay.py"
        "src/focaccia/qemu/x86.py"
        "tests/test_x86_signal_replay.py"
      ];
      pytestTargets = [
        "tests/test_x86_signal_replay.py"
        "-k"
        "sigreturn"
      ];
    };

    replayEffectCoverageCheck = mkStaticUnitCheck {
      name = "replay-effect-coverage";
      ruffTargets = [
        "src/focaccia/qemu/replay.py"
        "src/focaccia/qemu/syscall.py"
        "src/focaccia/qemu/target.py"
        "tests/test_x86_replay.py"
      ];
      pytestTargets = [
        "tests/test_x86_replay.py"
        "-k"
        "coverage or safe_passthrough or terminal_exit"
      ];
    };

    qemuReplayStartSynchronizationCheck = mkStaticUnitCheck {
      name = "qemu-replay-start-synchronization";
      ruffTargets = [
        "src/focaccia/qemu/target.py"
        "tests/test_gdb_program_state.py"
      ];
      pytestTargets = [
        "tests/test_gdb_program_state.py"
        "-k"
        "start_before_first_rr_event or without_any_synchronization_pc or synchronizes_when_first_rr_event_is_reached or steps_safely or post_event_is_not or run_until_replays"
      ];
    };

    qemuStructuredReplayReportCheck = mkStaticUnitCheck {
      name = "qemu-structured-replay-report";
      ruffTargets = [
        "src/focaccia/qemu/_qemu_tool.py"
        "src/focaccia/qemu/report.py"
        "src/focaccia/tools/validate_qemu.py"
        "tests/test_qemu_launcher.py"
        "tests/test_qemu_report.py"
      ];
      pytestTargets = [
        "tests/test_qemu_launcher.py"
        "tests/test_qemu_report.py"
      ];
    };

    rrQemuRunManifestCheck = mkStaticUnitCheck {
      name = "rr-qemu-run-manifest";
      ruffTargets = [
        "src/focaccia/qemu/integration.py"
        "tests/test_qemu_integration.py"
      ];
      pytestTargets = [ "tests/test_qemu_integration.py" ];
    };

    rrQemuSmokeHarnessCheck = mkStaticUnitCheck {
      name = "rr-qemu-smoke-harness";
      ruffTargets = [
        "src/focaccia/tools/rr_qemu_smoke.py"
        "tests/test_rr_qemu_smoke.py"
      ];
      pytestTargets = [ "tests/test_rr_qemu_smoke.py" ];
    };

    schedulerQuarantineCheck = mkStaticUnitCheck {
      name = "scheduler-quarantine";
      ruffTargets = [
        "src/focaccia/experimental/__init__.py"
        "src/focaccia/experimental/scheduler.py"
        "src/focaccia/qemu/_qemu_tool.py"
        "src/focaccia/qemu/concurrency.py"
        "src/focaccia/qemu/target.py"
        "src/focaccia/tools/validate_qemu.py"
        "tests/test_gdb_program_state.py"
        "tests/test_scheduler_quarantine.py"
      ];
      pytestTargets = [
        "tests/test_gdb_program_state.py"
        "tests/test_scheduler_quarantine.py"
        "-k"
        "scheduler or concurrency or thread_creating"
      ];
      extraCheckPhase = ''
        python -c 'import importlib.util; assert importlib.util.find_spec("ptrace") is None'
        ${pythonEnv}/bin/python - <<'PY'
        import importlib.metadata
        import importlib.util

        assert importlib.util.find_spec("ptrace") is None
        assert importlib.util.find_spec("focaccia.experimental.scheduler") is not None
        requirements = importlib.metadata.requires("focaccia") or []
        ptrace = [item for item in requirements if item.startswith("python-ptrace")]
        assert len(ptrace) == 1
        assert "extra ==" in ptrace[0]
        assert "experimental-scheduler" in ptrace[0]
        PY
      '';
    };

    uvSyncLockIntegrityCheck = pkgs.runCommand "uv-sync-lock-integrity" {} ''
      wrapper=${uvSyncWrapper}/bin/uv-sync
      ${pkgs.gnugrep}/bin/grep -F -- "uv sync --locked" "$wrapper"
      if ${pkgs.gnugrep}/bin/grep -Fq "sed -i" "$wrapper" \
        || ${pkgs.gnugrep}/bin/grep -Fq "riscv" "$wrapper"; then
        echo "uv-sync must not text-filter the resolver lockfile" >&2
        exit 1
      fi
      touch "$out"
    '';

    qemuSparseMemoryCacheCheck = mkStaticUnitCheck {
      name = "qemu-sparse-memory-cache";
      ruffTargets = [
        "src/focaccia/qemu/state.py"
        "tests/test_gdb_program_state.py"
        "tests/test_plugin_state_validity.py"
      ];
      pytestTargets = [
        "tests/test_gdb_program_state.py"
        "tests/test_plugin_state_validity.py"
        "-k"
        "memory or full_range"
      ];
    };

    qemuScriptedStateCollectionCheck = mkStaticUnitCheck {
      name = "qemu-scripted-state-collection";
      ruffTargets = [
        "src/focaccia/qemu/_qemu_tool.py"
        "src/focaccia/qemu/snapshot.py"
        "src/focaccia/qemu/state.py"
        "src/focaccia/qemu/target.py"
        "src/focaccia/qemu/transport.py"
        "src/focaccia/qemu/validation_server.py"
        "src/focaccia/tools/validate_qemu.py"
        "tests/test_gdb_program_state.py"
        "tests/test_plugin_state_validity.py"
        "tests/test_qemu_launcher.py"
        "tests/test_qemu_matching.py"
        "tests/test_qemu_snapshot.py"
        "tests/test_qemu_trace_output.py"
        "tests/test_qemu_transport.py"
      ];
      pytestTargets = [
        "tests/test_gdb_program_state.py"
        "tests/test_plugin_state_validity.py"
        "tests/test_qemu_launcher.py"
        "tests/test_qemu_matching.py"
        "tests/test_qemu_snapshot.py"
        "tests/test_qemu_trace_output.py"
        "tests/test_qemu_transport.py"
      ];
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

    fix071SignalExtraRegistersCheck = mkStaticUnitCheck {
      name = "fix-071-signal-extra-registers";
      ruffTargets = [
        "src/focaccia/deterministic.py"
        "src/focaccia/rr/adapter.py"
        "src/focaccia/qemu/aarch64.py"
        "src/focaccia/qemu/replay.py"
        "src/focaccia/qemu/target.py"
        "tests/test_aarch64_signal_replay.py"
        "tests/test_rr_adapter.py"
        "tests/test_x86_signal_replay.py"
      ];
      pytestTargets = [
        "tests/test_aarch64_signal_replay.py"
        "tests/test_rr_adapter.py"
        "tests/test_x86_signal_replay.py"
      ];
    };

    fix027Aarch64DeterministicReplayCheck = mkStaticUnitCheck {
      name = "fix-027-aarch64-deterministic-replay";
      ruffTargets = [
        "src/focaccia/qemu/aarch64.py"
        "src/focaccia/qemu/deterministic.py"
        "src/focaccia/qemu/replay.py"
        "src/focaccia/qemu/target.py"
        "tests/test_aarch64_replay.py"
      ];
      pytestTargets = [ "tests/test_aarch64_replay.py" ];
    };

    aarch64NativeRrToolCheck = pkgs.runCommand "fix-027-aarch64-native-rr-tool" {
      nativeBuildInputs = [ rrTool pkgs.gnugrep ];
    } ''
      mkdir -p "$out"
      rr --version | tee "$out/version.txt"
      grep -F 'rr version' "$out/version.txt"
    '';

    fix076RrStandaloneLldbCompatibilityCheck =
      pkgs.runCommand "fix-076-rr-standalone-lldb-compatibility" {
        nativeBuildInputs = [ rrTool pkgs.gnugrep ];
      } ''
        mkdir -p "$out"
        rr --version 2>&1 | tee "$out/version.txt"
        grep -Ex 'rr version 5[.]8[.]0[[:space:]]*' "$out/version.txt"
        grep -F '#define TRACE_VERSION 85' ${rr-submodule}/src/TraceStream.cc \
          > "$out/trace-version.txt"
        grep -F '@0xcaa0b1486c12c629;' ${rr-submodule}/src/rr_trace.capnp \
          > "$out/schema-id.txt"
      '';

  in rec {
    packages = rec {
      focaccia = pythonEnv.overrideAttrs (old: {
        buildPhase = old.buildPhase or "";
        propagatedBuildInputs = (old.propagatedBuildInputs or []) ++ [ pkgs.lldb ];
      });

      dev = devEnv;

      qemu-plugin = qemu-submodule.packages.${system}.default;

      rr = rrTool;

      default = focaccia;
    } // pkgs.lib.optionalAttrs (system == "x86_64-linux") {
      x86-file-read-fixture = x86FileReadFixture;
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
        program = "${validateQemuWrapper}/bin/validate-qemu";
      };

      qemu-x86_64 = {
        type = "app";
        program = "${packages.qemu-plugin}/bin/qemu-x86_64";
      };

      rr = {
        type = "app";
        program = "${rrTool}/bin/rr";
      };

      uv-sync = {
        type = "app";
        program = "${uvSyncWrapper}/bin/uv-sync";
      };
    } // pkgs.lib.optionalAttrs (system == "x86_64-linux") {
      rr-qemu-smoke = {
        type = "app";
        program = let
          wrapper = pkgs.writeShellScriptBin "rr-qemu-smoke" ''
            export FOCACCIA_RR=${rrTool}/bin/rr
            export FOCACCIA_QEMU_X86_64=${packages.qemu-plugin}/bin/qemu-x86_64
            export FOCACCIA_CAPTURE_TRANSFORMS=${packages.focaccia}/bin/capture-transforms
            export FOCACCIA_VALIDATE_QEMU=${validateQemuWrapper}/bin/validate-qemu
            export FOCACCIA_NM=${pkgs.binutils}/bin/nm
            export FOCACCIA_SMOKE_BINARY=${x86FileReadFixture}/bin/file-read
            export FOCACCIA_SMOKE_INPUT=${x86FileReadFixture}/share/focaccia-smoke/input.txt
            exec ${packages.focaccia}/bin/rr-qemu-smoke "$@"
          '';
        in "${wrapper}/bin/rr-qemu-smoke";
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
        extraPackages = [ rrTool pkgs.capnproto ];
      };

      musl-all = mkMuslShell {
        name = "focaccia-musl-all";
        extraPackages = [
          rrTool
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
      reproducer-memory-layout = reproducerMemoryLayoutCheck;
      reproducer-state-restoration = reproducerStateRestorationCheck;
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
      fix-077-lldb-remote-state-event = fix077LldbRemoteStateEventCheck;
      fix-078-native-event-phase = fix078NativeEventPhaseCheck;
      fix-079-lldb-remote-x86-flags-width = fix079LldbRemoteX86FlagsWidthCheck;
      fix-086-lldb-canonical-rflags-observation = fix086LldbCanonicalRflagsObservationCheck;
      fix-080-repeated-pc-materialization = fix080RepeatedPcMaterializationCheck;
      fix-081-recorded-syscall-control-output = fix081RecordedSyscallControlOutputCheck;
      fix-088-observed-division-control = fix088ObservedDivisionControlCheck;
      fix-082-x86-syscall-entry-matching = fix082X86SyscallEntryMatchingCheck;
      fix-083-native-terminal-syscall = fix083NativeTerminalSyscallCheck;
      fix-087-rr-lldb-syscall-boundary = fix087RrLldbSyscallBoundaryCheck;
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
      fix-021-plugin-framed-transport = fix021PluginFramedTransportCheck;
      fix-022-plugin-register-cache = fix022PluginRegisterCacheCheck;
      fix-033-plugin-connection-ownership = fix033PluginConnectionOwnershipCheck;
      uv-sync-lock-integrity = uvSyncLockIntegrityCheck;
      fix-054-gdb-launch-encoding = fix054GdbLaunchEncodingCheck;
      explicit-empty-event-log = explicitEmptyEventLogCheck;
      deterministic-import-boundary = deterministicImportBoundaryCheck;
      rr-schema-v85-packaging = rrSchemaV85PackagingCheck;
      rr-register-layouts = rrRegisterLayoutsCheck;
      rr-memory-write-ranges = rrMemoryWriteRangesCheck;
      rr-compressed-streams = rrCompressedStreamsCheck;
      rr-task-event-variants = rrTaskEventVariantsCheck;
      deterministic-event-cursor = deterministicEventCursorCheck;
      deterministic-mapping-cursor = deterministicMappingCursorCheck;
      x86-syscall-effect-policies = x86SyscallEffectPoliciesCheck;
      x86-replay-fail-closed = x86ReplayFailClosedCheck;
      x86-nested-output-replay = x86NestedOutputReplayCheck;
      x86-signal-frame-abi = x86SignalFrameAbiCheck;
      x86-signal-return = x86SignalReturnCheck;
      replay-effect-coverage = replayEffectCoverageCheck;
      qemu-replay-start-synchronization = qemuReplayStartSynchronizationCheck;
      qemu-structured-replay-report = qemuStructuredReplayReportCheck;
      rr-qemu-run-manifest = rrQemuRunManifestCheck;
      rr-qemu-smoke-harness = rrQemuSmokeHarnessCheck;
      scheduler-quarantine = schedulerQuarantineCheck;
      fix-058-shared-snapshot-planner = fix058SharedSnapshotPlannerCheck;
      fix-070-gdb-wide-registers = fix070GdbWideRegisterCheck;
      fix-084-x86-eflags-observation = fix084X86EflagsObservationCheck;
      fix-085-flake-source-boundary = fix085FlakeSourceBoundaryCheck;
      qemu-sparse-memory-cache = qemuSparseMemoryCacheCheck;
      qemu-scripted-state-collection = qemuScriptedStateCollectionCheck;
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
      fix-027-aarch64-deterministic-replay = fix027Aarch64DeterministicReplayCheck;
      fix-071-signal-extra-registers = fix071SignalExtraRegistersCheck;
      fix-076-rr-standalone-lldb-compatibility =
        fix076RrStandaloneLldbCompatibilityCheck;
    } // pkgs.lib.optionalAttrs (system == "x86_64-linux") {
      rr-qemu-file-read-fixture = x86FileReadFixture;
    } // pkgs.lib.optionalAttrs (system == "aarch64-linux") {
      fix-027-aarch64-native-rr-tool = aarch64NativeRrToolCheck;
    };
  });
}
