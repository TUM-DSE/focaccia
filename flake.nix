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
      url = "git+https://github.com/TUM-DSE/focaccia-qemu.git?rev=83e4033ef58f5eb377807e6449115ec9d801d314&submodules=1";
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

    # Build only: these native fixtures are never executed by flake checks.
    nativeTerminalFixtures = pkgs.stdenv.mkDerivation {
      name = "native-terminal-observation-fixtures";
      src = ./tests/probes;
      dontConfigure = true;
      dontStrip = true;
      buildPhase = ''
        $CC -g -O0 -DEXIT_CODE=0 terminal_fixture.c -o exit0
        $CC -g -O0 -DEXIT_CODE=7 terminal_fixture.c -o exit7
        $CC -g -O0 -DFATAL_SIGNAL terminal_fixture.c -o fatal-signal
      '';
      installPhase = ''
        mkdir -p "$out/bin"
        cp exit0 exit7 fatal-signal "$out/bin/"
      '';
    };

    # Fake-only contract coverage: no debugger attachment, inferior, or RR.
    nativeTerminalOutcomeCheck = mkStaticUnitCheck {
      name = "native-terminal-outcome";
      ruffTargets = [
        "src/focaccia/execution.py"
        "src/focaccia/native/lldb_target.py"
        "tests/test_native_terminal_outcome.py"
      ];
      pytestTargets = [ "tests/test_native_terminal_outcome.py" ];
    };

    # Fake-only GDB process events; no debugger, inferior, sockets, or RR.
    qemuTerminalOutcomeCheck = mkStaticUnitCheck {
      name = "qemu-terminal-outcome";
      ruffTargets = [
        "src/focaccia/qemu/target.py"
        "tests/test_qemu_terminal_outcome.py"
      ];
      pytestTargets = [ "tests/test_qemu_terminal_outcome.py" ];
    };

    # Fake-only GDB signal delivery semantics: default-fatal, handler stop,
    # and genuine trap delivery. No debugger, inferior, sockets, or RR.
    qemuFatalSignalTerminationCheck = mkStaticUnitCheck {
      name = "qemu-fatal-signal-termination";
      ruffTargets = [
        "src/focaccia/qemu/_qemu_tool.py"
        "src/focaccia/qemu/report.py"
        "src/focaccia/qemu/target.py"
        "tests/test_qemu_terminal_outcome.py"
      ];
      pytestTargets = [
        "tests/test_qemu_terminal_outcome.py"
        "-k"
        "pending_guest_signal"
      ];
    };

    nativeTerminalObservationCheck = mkStaticUnitCheck {
      name = "native-terminal-observation-harness";
      ruffTargets = [
        "tests/probes/native_terminal_observation.py"
        "tests/test_native_terminal_observation.py"
      ];
      pytestTargets = [ "tests/test_native_terminal_observation.py" ];
    };

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

    coreBranchCoverageCheck = pkgs.stdenv.mkDerivation {
      name = "core-branch-coverage";
      src = staticUnitSource;

      doCheck = true;
      dontBuild = true;
      nativeCheckInputs = [ pythonDevEnv ];

      checkPhase = ''
        set -euo pipefail
        export REPO_ROOT="$PWD"
        mkdir -p "$out/html"

        python -m pytest -q -m 'not integration' tests \
          --cov=focaccia \
          --cov-branch \
          --cov-report=term-missing \
          --cov-report=json:"$out/coverage.json" \
          --cov-report=xml:"$out/coverage.xml" \
          --cov-report=html:"$out/html"

        python - "$out/coverage.json" "$out/summary.txt" <<'PY'
        import json
        import pathlib
        import sys
        import tomllib

        report_path = pathlib.Path(sys.argv[1])
        summary_path = pathlib.Path(sys.argv[2])
        document = json.loads(report_path.read_text())
        if document.get("meta", {}).get("branch_coverage") is not True:
            raise SystemExit("coverage report does not contain branch coverage")

        files = {
            pathlib.PurePath(name).as_posix(): data
            for name, data in document.get("files", {}).items()
        }
        policy_document = tomllib.loads(pathlib.Path("pyproject.toml").read_text())
        policy = policy_document["tool"]["focaccia"]["coverage"]
        core_modules = set(policy["core_modules"])
        integration_prefixes = tuple(policy["integration_prefixes"])
        experimental_prefixes = tuple(policy["experimental_prefixes"])
        ratchets = policy["ratchets"]

        if set(ratchets) != core_modules:
            missing_ratchets = sorted(core_modules - set(ratchets))
            extra_ratchets = sorted(set(ratchets) - core_modules)
            raise SystemExit(
                "coverage ratchets must exactly match core modules: "
                f"missing={missing_ratchets}, extra={extra_ratchets}"
            )

        package_files = {
            name for name in files if name.startswith("src/focaccia/")
        }
        categories: dict[str, str] = {}
        for name in sorted(package_files):
            matches = []
            if name in core_modules:
                matches.append("core")
            if name.startswith(integration_prefixes):
                matches.append("integration")
            if name.startswith(experimental_prefixes):
                matches.append("experimental")
            if len(matches) != 1:
                raise SystemExit(
                    f"coverage file {name} must have exactly one classification; "
                    f"found {matches}"
                )
            categories[name] = matches[0]

        missing_core = sorted(core_modules - package_files)
        if missing_core:
            raise SystemExit(f"coverage report is missing core modules: {missing_core}")

        failures = []
        ratchet_lines = [
            "Core coverage ratchets (integration and experimental code are report-only)",
        ]
        for name in sorted(core_modules):
            measured = files[name]["summary"]
            minimum = ratchets[name]
            statement_coverage = measured["percent_statements_covered"]
            branch_coverage = measured["percent_branches_covered"]
            ratchet_lines.append(
                f"{name}: statements {statement_coverage:.2f}% >= "
                f"{minimum['statements']:.2f}%; branches {branch_coverage:.2f}% >= "
                f"{minimum['branches']:.2f}%"
            )
            if statement_coverage + 1e-9 < minimum["statements"]:
                failures.append(
                    f"{name} statement coverage {statement_coverage:.2f}% is below "
                    f"{minimum['statements']:.2f}%"
                )
            if branch_coverage + 1e-9 < minimum["branches"]:
                failures.append(
                    f"{name} branch coverage {branch_coverage:.2f}% is below "
                    f"{minimum['branches']:.2f}%"
                )

        category_counts = {
            category: sum(value == category for value in categories.values())
            for category in ("core", "integration", "experimental")
        }
        output_dir = report_path.parent
        (output_dir / "core-ratchets.txt").write_text(
            "\n".join(ratchet_lines) + "\n"
        )
        (output_dir / "classification.json").write_text(
            json.dumps(categories, indent=2, sort_keys=True) + "\n"
        )

        totals = document.get("totals", {})
        if totals.get("num_statements", 0) <= 0 or totals.get("covered_lines", 0) <= 0:
            raise SystemExit("coverage report does not contain executed statements")

        summary_path.write_text(
            "Whole-package informational coverage (no global threshold)\n"
            f"statements: {totals['covered_lines']}/{totals['num_statements']}\n"
            f"branches: {totals['covered_branches']}/{totals['num_branches']}\n"
            f"coverage: {totals['percent_covered']:.2f}%\n"
            f"classified files: {category_counts}\n"
            f"core ratchets passed: {len(core_modules)}\n"
        )
        if failures:
            raise SystemExit("coverage ratchet failures:\n" + "\n".join(failures))
        PY
      '';

      env = uvEnv;
    };

    mutationCoreSmokeCheck = pkgs.stdenv.mkDerivation {
      name = "mutation-core-smoke";
      src = staticUnitSource;

      doCheck = true;
      dontBuild = true;
      nativeCheckInputs = [ pythonStaticUnitEnv ];

      checkPhase = ''
        set -euo pipefail
        export HOME="$TMPDIR"
        export REPO_ROOT="$PWD"

        ${pkgs.coreutils}/bin/timeout 180 mutmut run --max-children 4
        mutmut export-cicd-stats
        mutmut results > mutation-results.txt

        mkdir -p "$out"
        cp mutants/mutmut-cicd-stats.json "$out/stats.json"
        cp mutation-results.txt "$out/results.txt"

        python - "$out/stats.json" "$out/summary.txt" <<'PY'
        import json
        import pathlib
        import sys
        import tomllib

        stats_path = pathlib.Path(sys.argv[1])
        summary_path = pathlib.Path(sys.argv[2])
        stats = json.loads(stats_path.read_text())
        required = {
            "killed",
            "survived",
            "total",
            "no_tests",
            "skipped",
            "suspicious",
            "timeout",
            "check_was_interrupted_by_user",
            "segfault",
        }
        if set(stats) != required:
            raise SystemExit(
                f"unexpected mutmut statistics fields: {sorted(set(stats) ^ required)}"
            )
        if any(not isinstance(stats[name], int) or stats[name] < 0 for name in required):
            raise SystemExit("mutmut statistics must be non-negative integers")
        if stats["total"] <= 0:
            raise SystemExit("mutation smoke did not generate any mutants")

        classified = sum(stats[name] for name in required - {"total"})
        if classified != stats["total"]:
            raise SystemExit(
                f"mutation result count mismatch: total={stats['total']}, "
                f"classified={classified}"
            )

        infrastructure_failures = {
            name: stats[name]
            for name in (
                "suspicious",
                "timeout",
                "check_was_interrupted_by_user",
                "segfault",
            )
            if stats[name]
        }
        if infrastructure_failures:
            raise SystemExit(
                f"mutation smoke had infrastructure failures: {infrastructure_failures}"
            )

        assessed = stats["killed"] + stats["survived"]
        if assessed <= 0:
            raise SystemExit("mutation smoke did not assess any mutants")
        score = 100 * stats["killed"] / assessed
        policy_document = tomllib.loads(pathlib.Path("pyproject.toml").read_text())
        policy = policy_document["tool"]["focaccia"]["mutation"]
        minimum_score = policy["minimum_score"]
        maximum_no_tests = policy["maximum_no_tests"]
        maximum_skipped = policy["maximum_skipped"]
        if not isinstance(minimum_score, (int, float)) or not 0 <= minimum_score <= 100:
            raise SystemExit("mutation minimum_score must be between 0 and 100")
        if not isinstance(maximum_no_tests, int) or maximum_no_tests < 0:
            raise SystemExit("mutation maximum_no_tests must be a non-negative integer")
        if not isinstance(maximum_skipped, int) or maximum_skipped < 0:
            raise SystemExit("mutation maximum_skipped must be a non-negative integer")

        summary_path.write_text(
            "compare.py curated mutation ratchet\n"
            f"killed: {stats['killed']}\n"
            f"survived: {stats['survived']}\n"
            f"no tests: {stats['no_tests']} <= {maximum_no_tests}\n"
            f"skipped: {stats['skipped']} <= {maximum_skipped}\n"
            f"assessed mutation score: {score:.2f}% >= {minimum_score:.2f}%\n"
            f"total generated mutants: {stats['total']}\n"
        )
        if stats["no_tests"] > maximum_no_tests:
            raise SystemExit(
                f"mutation no-test count {stats['no_tests']} exceeds {maximum_no_tests}"
            )
        if stats["skipped"] > maximum_skipped:
            raise SystemExit(
                f"mutation skipped count {stats['skipped']} exceeds {maximum_skipped}"
            )
        if score + 1e-9 < minimum_score:
            raise SystemExit(
                f"mutation score {score:.2f}% is below {minimum_score:.2f}%"
            )
        PY
      '';

      env = uvEnv;
    };

    propertyCoreModelsCheck = mkStaticUnitCheck {
      name = "property-core-models";
      ruffTargets = [
        "src/focaccia/snapshot.py"
        "tests/test_register_properties.py"
        "tests/test_sparse_memory_properties.py"
        "tests/test_trace_properties.py"
      ];
      pytestTargets = [
        "tests/test_register_properties.py"
        "tests/test_sparse_memory_properties.py"
        "tests/test_trace_properties.py"
      ];
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

    reproducerNarrowGprRestorationCheck = mkStaticUnitCheck {
      name = "reproducer-narrow-gpr-restoration";
      ruffTargets = [
        "src/focaccia/reproducer.py"
        "tests/test_reproducer.py"
      ];
      pytestTargets = [
        "tests/test_reproducer.py::test_reproducer_state_restore_uses_known_32_bit_alias_without_inventing_upper_bits"
        "tests/test_reproducer.py::test_reproducer_state_restore_does_not_invent_unknown_base_register_bits"
      ];
    };

    reproducerObservedUpperContextCheck = mkStaticUnitCheck {
      name = "reproducer-observed-upper-context";
      ruffTargets = [
        "src/focaccia/reproducer.py"
        "tests/test_reproducer.py"
      ];
      pytestTargets = [
        "tests/test_reproducer.py::test_reproducer_narrow_input_preserves_observed_upper_context"
        "tests/test_reproducer.py::test_reproducer_state_restore_uses_known_32_bit_alias_without_inventing_upper_bits"
      ];
    };

    reproducerSimdMmxRestorationCheck = mkStaticUnitCheck {
      name = "reproducer-simd-mmx-restoration";
      ruffTargets = [
        "src/focaccia/reproducer.py"
        "tests/test_reproducer.py"
      ];
      pytestTargets = [
        "tests/test_reproducer.py::test_simd_mmx_restores_canonical_known_xmm_without_zeroing_upper_bits"
        "tests/test_reproducer.py::test_simd_mmx_restores_exact_mmx_with_valid_instruction"
        "tests/test_reproducer.py::test_simd_mmx_restore_values_are_validated"
        "tests/test_reproducer.py::test_simd_mmx_unknown_required_bits_fail_closed"
        "tests/test_reproducer.py::test_simd_mmx_observed_upper_context_fails_closed"
        "tests/test_reproducer.py::test_simd_mmx_unsupported_widths_do_not_zero_unknown_context"
      ];
    };

    reproducerAarch64BackendCheck = mkStaticUnitCheck {
      name = "reproducer-aarch64-backend";
      ruffTargets = [
        "src/focaccia/reproducer_aarch64.py"
        "tests/test_reproducer_aarch64.py"
      ];
      pytestTargets = [
        "tests/test_reproducer_aarch64.py"
      ];
    };

    aarch64ReproducerStopCaptureCheck = mkStaticUnitCheck {
      name = "aarch64-reproducer-stop-capture";
      ruffTargets = [
        "src/focaccia/reproducer_aarch64.py"
        "tests/test_reproducer_aarch64.py"
      ];
      pytestTargets = [
        "tests/test_reproducer_aarch64.py::test_destination_pc_has_unique_mapped_stop_landing_instruction"
      ];
    };

    reproducerFragmentFidelityCheck = mkStaticUnitCheck {
      name = "reproducer-fragment-fidelity";
      ruffTargets = [
        "src/focaccia/reproducer.py"
        "tests/test_reproducer.py"
      ];
      pytestTargets = [
        "tests/test_reproducer.py"
        "-k"
        "fragment or entry_prefix or single_transition or condition_code_seed"
      ];
    };

    # Pure action-policy fixtures; no native debugger, RR, or emulator execution.
    noReplaySyscallActionsCheck = mkStaticUnitCheck {
      name = "no-replay-syscall-actions";
      ruffTargets = [
        "src/focaccia/no_replay.py"
        "tests/test_no_replay.py"
      ];
      pytestTargets = [ "tests/test_no_replay.py" ];
    };

    noReplayAnonymousMmapCheck = mkStaticUnitCheck {
      name = "no-replay-anonymous-mmap";
      ruffTargets = [
        "src/focaccia/no_replay.py"
        "src/focaccia/qemu/_qemu_tool.py"
        "tests/test_no_replay.py"
        "tests/test_qemu_whole_program.py"
      ];
      pytestTargets = [
        "tests/test_no_replay.py"
        "tests/test_qemu_whole_program.py"
        "-k"
        "anonymous_mmap or interior_no_replay_action_kind"
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

    crossValidateOptionCheck = mkStaticUnitCheck {
      name = "cross-validate-option";
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

    nativeEventMatchingCheck = mkStaticUnitCheck {
      name = "native-event-matching";
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

    speculativeSynchronizationCheck = mkStaticUnitCheck {
      name = "speculative-synchronization";
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

    # Fake LLDB values only; no native debugger/ptrace capability required.
    lldbSegmentSelectorObservationCheck = mkStaticUnitCheck {
      name = "lldb-segment-selector-observation";
      ruffTargets = [
        "src/focaccia/native/lldb_target.py"
        "tests/test_native_tracing.py"
      ];
      pytestTargets = [
        "tests/test_native_tracing.py"
        "-k"
        "lldb_selector_container"
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

    lldbRemoteStateEventCheck = mkStaticUnitCheck {
      name = "lldb-remote-state-event";
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

    nativeEventPhaseCheck = mkStaticUnitCheck {
      name = "native-event-phase";
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

    lldbRemoteX86FlagsWidthCheck = mkStaticUnitCheck {
      name = "lldb-remote-x86-flags-width";
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

    lldbCanonicalRflagsObservationCheck = mkStaticUnitCheck {
      name = "lldb-canonical-rflags-observation";
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

    repeatedPcMaterializationCheck = mkStaticUnitCheck {
      name = "repeated-pc-materialization";
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

    recordedSyscallControlOutputCheck = mkStaticUnitCheck {
      name = "recorded-syscall-control-output";
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

    qemuValidationProfileComponentsCheck = mkStaticUnitCheck {
      name = "qemu-validation-profile-components";
      ruffTargets = [
        "src/focaccia/qemu/profiling.py"
        "src/focaccia/qemu/validation_server.py"
        "src/focaccia/qemu/_qemu_tool.py"
        "src/focaccia/tools/validate_qemu.py"
        "tests/test_qemu_trace_output.py"
      ];
      pytestTargets = [
        "tests/test_qemu_trace_output.py::test_plugin_validation_writes_component_profile"
      ];
    };

    qemuStopGenerationCacheCheck = mkStaticUnitCheck {
      name = "qemu-stop-generation-cache";
      # Fake GDB backend only: proves reads reuse one stopped-state validation
      # and that resume/write boundaries invalidate the state token.
      ruffTargets = [
        "src/focaccia/qemu/target.py"
        "tests/test_gdb_program_state.py"
      ];
      pytestTargets = [
        "tests/test_gdb_program_state.py"
        "-k"
        "stop_once_then_uses_generation_token or target_writes_invalidate_existing_state"
      ];
    };

    nativeComponentAccountingCheck = mkStaticUnitCheck {
      name = "native-component-accounting";
      # Deterministic fake-clock/backend checks; no debugger or RR capability.
      ruffTargets = [
        "src/focaccia/native/profiling.py"
        "src/focaccia/native/tracer.py"
        "tests/test_native_component_accounting.py"
        "tests/test_native_profiling.py"
      ];
      pytestTargets = [
        "tests/test_native_component_accounting.py"
        "tests/test_native_profiling.py"
        "tests/test_native_tracing.py"
        "tests/test_native_api.py"
      ];
    };

    persistenceTimingSeparationCheck = mkStaticUnitCheck {
      name = "persistence-timing-separation";
      ruffTargets = [
        "src/focaccia/native/profiling.py"
        "src/focaccia/tools/capture_transforms.py"
        "tests/test_native_profiling.py"
      ];
      pytestTargets = [
        "tests/test_native_profiling.py"
        "-k"
        "separates_trace_from_serialization or profile_report"
      ];
    };

    optInCaptureProfilingCheck = mkStaticUnitCheck {
      name = "opt-in-capture-profiling";
      ruffTargets = [
        "src/focaccia/native/profiling.py"
        "src/focaccia/native/lldb_target.py"
        "src/focaccia/native/tracer.py"
        "src/focaccia/qemu/_qemu_tool.py"
        "src/focaccia/qemu/target.py"
        "src/focaccia/tools/capture_transforms.py"
        "tests/test_gdb_program_state.py"
        "tests/test_native_api.py"
        "tests/test_native_profiling.py"
        "tests/test_native_tracing.py"
        "tests/test_qemu_matching.py"
        "tests/test_qemu_report.py"
      ];
      pytestTargets = [
        "tests/test_native_profiling.py"
        "tests/test_native_api.py::test_force_mode_records_unknown_symbolic_outputs_as_trace_gap"
        "tests/test_native_tracing.py::test_lldb_execution_is_profiled_only_with_explicit_collector"
        "tests/test_qemu_report.py::test_gdb_validation_avoids_timing_output_and_writes_report"
      ];
    };

    x86UcomisdConcreteResolutionCheck = mkStaticUnitCheck {
      name = "x86-ucomisd-concrete-resolution";
      ruffTargets = [ "tests/test_ucomisd_resolution.py" ];
      pytestTargets = [ "tests/test_ucomisd_resolution.py" ];
    };

    x86AvxLogicCheck = mkStaticUnitCheck {
      name = "x86-avx-logic-semantics";
      ruffTargets = [ "tests/test_x86_avx_logic.py" ];
      pytestTargets = [
        "tests/test_x86_avx_logic.py"
        "tests/test_x86_vmovdqa.py"
        "tests/test_native_api.py::test_aligned_vector_move_requires_exact_native_bytes"
      ];
    };

    partialWideVectorDependencyCheck = mkStaticUnitCheck {
      name = "partial-wide-vector-dependency";
      ruffTargets = [
        "src/focaccia/miasm_util.py"
        "src/focaccia/symbolic.py"
        "src/focaccia/qemu/target.py"
        "tests/test_compare.py"
        "tests/test_qemu_snapshot.py"
        "tests/test_symbolic_composition.py"
        "tests/test_no_replay_exit_only.py"
        "tests/test_qemu_matching.py"
        "tests/test_qemu_whole_program.py"
      ];
      pytestTargets = [
        "tests/test_compare.py::test_low_vector_alias_confirms_memory_while_unknown_upper_bits_stay_incomplete"
        "tests/test_compare.py::test_malformed_symbolic_register_width_rejects_narrow_alias_resolution"
        "tests/test_qemu_snapshot.py::test_low_vector_slice_planning_requests_observable_alias_not_full_base"
        "tests/test_symbolic_composition.py::test_aarch64_scalar_bit_slice_resolves_from_known_full_register"
        "tests/test_symbolic_composition.py::test_register_slice_evaluation_preserves_resolver_overrides"
        "tests/test_no_replay_exit_only.py::test_qemu_ordinary_prefix_cannot_cross_action"
        "tests/test_qemu_matching.py::test_gdb_collector_composes_to_declared_cutpoint"
      ];
    };

    adaptiveUnobservableOutputCompositionCheck = mkStaticUnitCheck {
      name = "adaptive-unobservable-output-composition";
      ruffTargets = [
        "src/focaccia/match.py"
        "src/focaccia/qemu/_qemu_tool.py"
        "src/focaccia/qemu/snapshot.py"
        "tests/test_qemu_matching.py"
      ];
      pytestTargets = [
        "tests/test_qemu_matching.py::test_gdb_collector_composes_unobservable_register_into_memory_effect"
      ];
    };

    nativeRemoteWideVectorObservationCheck = mkStaticUnitCheck {
      name = "native-remote-wide-vector-observation";
      ruffTargets = [ "src/focaccia/native/lldb_target.py" "tests/test_native_tracing.py" ];
      pytestTargets = [
        "tests/test_native_tracing.py"
        "-k"
        "gdb_target_xml_layout or remote_zmm"
      ];
    };

    nativeNarrowRegisterAliasCheck = mkStaticUnitCheck {
      name = "native-narrow-register-alias";
      ruffTargets = [ "src/focaccia/native/lldb_target.py" "tests/test_native_tracing.py" ];
      pytestTargets = [
        "tests/test_native_tracing.py::test_lldb_narrow_alias_falls_back_to_exact_hardware_parent_slice"
      ];
    };

    x86VectorPersistenceRoundtripCheck = mkStaticUnitCheck {
      name = "x86-vector-persistence-roundtrip";
      ruffTargets = [ "src/focaccia/symbolic.py" "tests/test_x86_avx_logic.py" ];
      pytestTargets = [
        "tests/test_x86_avx_logic.py"
        "-k"
        "project_avx_text"
      ];
    };

    x86AlignedVectorMovesCheck = mkStaticUnitCheck {
      name = "x86-aligned-vector-moves";
      ruffTargets = [ "tests/test_x86_vmovdqa.py" ];
      pytestTargets = [
        "tests/test_x86_vmovdqa.py"
        "tests/test_native_api.py::test_aligned_vector_move_requires_exact_native_bytes"
      ];
    };

    miasmVmovdquSupportCheck = mkStaticUnitCheck {
      name = "miasm-vmovdqu-support";
      ruffTargets = [ "tests/test_native_api.py" ];
      pytestTargets = [
        "tests/test_native_api.py"
        "-k"
        "vex_misdecode"
      ];
    };

    miasmSseSupportCheck = mkStaticUnitCheck {
      name = "miasm-sse-support";
      ruffTargets = [ "tests/test_native_api.py" ];
      pytestTargets = [
        "tests/test_native_api.py"
        "-k"
        "pinned_miasm_decodes"
      ];
    };

    nativeSignalActionCheck = mkStaticUnitCheck {
      name = "native-signal-action";
      ruffTargets = [
        "src/focaccia/native/tracer.py"
        "tests/test_native_api.py"
      ];
      pytestTargets = [
        "tests/test_native_api.py"
        "-k"
        "signal_action"
      ];
    };

    rexMmxMovqCheck = mkStaticUnitCheck {
      name = "rex-mmx-movq";
      ruffTargets = [
        "src/focaccia/native/tracer.py"
        "tests/test_native_api.py"
      ];
      pytestTargets = [
        "tests/test_native_api.py"
        "-k"
        "rex_mmx_movq"
      ];
    };

    lslEnvironmentSpecializationCheck = mkStaticUnitCheck {
      name = "lsl-environment-specialization";
      ruffTargets = [
        "src/focaccia/native/tracer.py"
        "tests/test_native_api.py"
      ];
      pytestTargets = [
        "tests/test_native_api.py"
        "-k"
        "lsl_environment_specialization"
      ];
    };

    lldbLockPrefixDisassemblyCheck = mkStaticUnitCheck {
      name = "lldb-lock-prefix-disassembly";
      ruffTargets = [
        "src/focaccia/native/tracer.py"
        "tests/test_native_api.py"
      ];
      pytestTargets = [
        "tests/test_native_api.py"
        "-k"
        "lldb_lock_prefix or prefixed_disassembly or empty_lldb_fallback"
      ];
    };

    nativeDisassemblyVerificationReuseCheck = mkStaticUnitCheck {
      name = "native-disassembly-verification-reuse";
      # Offline byte fixtures and fake backends only; no debugger/ptrace/RR.
      ruffTargets = [
        "src/focaccia/native/tracer.py"
        "tests/test_native_disassembly_cache.py"
      ];
      pytestTargets = [
        "tests/test_native_disassembly_cache.py"
        "tests/test_native_api.py"
        "-k"
        "verification_reuse or disassembly or vex_misdecode or rex_mmx_movq"
      ];
    };

    vexDisassemblyValidationCheck = mkStaticUnitCheck {
      name = "vex-disassembly-validation";
      ruffTargets = [
        "src/focaccia/native/tracer.py"
        "tests/test_native_api.py"
      ];
      pytestTargets = [
        "tests/test_native_api.py"
        "-k"
        "vex_misdecode or disassembly_validation"
      ];
    };

    emptyMiasmDisassemblyCheck = mkStaticUnitCheck {
      name = "empty-miasm-disassembly";
      ruffTargets = [
        "src/focaccia/symbolic.py"
        "tests/test_native_api.py"
      ];
      pytestTargets = [
        "tests/test_native_api.py"
        "-k"
        "empty_miasm_disassembly or pinned_miasm_decodes"
      ];
    };

    xmmCrossValidationCheck = mkStaticUnitCheck {
      name = "xmm-cross-validation";
      ruffTargets = [
        "src/focaccia/native/tracer.py"
        "src/focaccia/symbolic.py"
        "tests/test_native_tracing.py"
      ];
      pytestTargets = [
        "tests/test_native_tracing.py"
        "-k"
        "xmm_cross_validation"
      ];
    };

    definedFlagCrossValidationCheck = mkStaticUnitCheck {
      name = "defined-flag-cross-validation";
      ruffTargets = [
        "src/focaccia/native/tracer.py"
        "src/focaccia/symbolic.py"
        "tests/test_native_tracing.py"
      ];
      pytestTargets = [
        "tests/test_native_tracing.py"
        "-k"
        "native_cross_validation"
      ];
    };

    observedDivisionControlCheck = mkStaticUnitCheck {
      name = "observed-division-control";
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

    observedPopfControlCheck = mkStaticUnitCheck {
      name = "observed-popf-control";
      ruffTargets = [
        "src/focaccia/native/tracer.py"
        "tests/test_native_api.py"
      ];
      pytestTargets = [
        "tests/test_native_api.py"
        "-k"
        "observed_popfq or verified_exit_action"
      ];
    };

    x86SyscallEntryMatchingCheck = mkStaticUnitCheck {
      name = "x86-syscall-entry-matching";
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

    nativePostExitCrossValidationCheck = mkStaticUnitCheck {
      name = "native-post-exit-cross-validation";
      ruffTargets = [ "src/focaccia/native/tracer.py" "tests/test_native_api.py" ];
      pytestTargets = [ "tests/test_native_api.py::test_cross_validation_rejects_missing_post_exit_state" ];
    };

    noReplayExitOnlyCheck = mkStaticUnitCheck {
      name = "no-replay-exit-only-whole-program";
      ruffTargets = [
        "src/focaccia/no_replay.py"
        "src/focaccia/native/tracer.py"
        "src/focaccia/qemu/target.py"
        "src/focaccia/qemu/_qemu_tool.py"
        "src/focaccia/qemu/report.py"
        "src/focaccia/completion.py"
        "src/focaccia/persistence.py"
        "tests/test_no_replay.py"
      ];
      pytestTargets = [
        "tests/test_no_replay.py"
        "tests/test_native_whole_program.py"
        "tests/test_qemu_whole_program.py"
        "tests/test_trace_completion.py"
      ];
    };

    noReplaySetFsCheck = mkStaticUnitCheck {
      name = "no-replay-ordered-set-fs";
      ruffTargets = [
        "src/focaccia/no_replay.py" "src/focaccia/native/tracer.py"
        "src/focaccia/qemu/target.py" "src/focaccia/qemu/_qemu_tool.py"
        "src/focaccia/qemu/report.py" "src/focaccia/completion.py"
        "src/focaccia/persistence.py" "src/focaccia/match.py"
        "tests/test_no_replay.py" "tests/test_native_whole_program.py"
        "tests/test_qemu_whole_program.py" "tests/test_trace_completion.py"
      ];
      pytestTargets = [
        "tests/test_no_replay.py" "tests/test_native_whole_program.py"
        "tests/test_qemu_whole_program.py" "tests/test_trace_completion.py"
      ];
    };

    noReplaySetFsContinuedDiagnosticsCheck = mkStaticUnitCheck {
      name = "no-replay-set-fs-continued-diagnostics";
      ruffTargets = [
        "src/focaccia/no_replay.py" "src/focaccia/qemu/target.py"
        "tests/test_no_replay.py" "tests/test_qemu_whole_program.py"
      ];
      pytestTargets = [ "tests/test_no_replay.py" "tests/test_qemu_whole_program.py" ];
    };

    noReplaySyscallContinuedDiagnosticsCheck = mkStaticUnitCheck {
      name = "no-replay-syscall-continued-diagnostics";
      ruffTargets = [
        "src/focaccia/no_replay.py" "src/focaccia/qemu/target.py"
        "src/focaccia/qemu/_qemu_tool.py"
        "tests/test_no_replay.py" "tests/test_qemu_whole_program.py"
      ];
      pytestTargets = [ "tests/test_no_replay.py" "tests/test_qemu_whole_program.py" ];
    };

    noReplayContextTidCheck = mkStaticUnitCheck {
      name = "no-replay-context-relative-tid";
      ruffTargets = [
        "src/focaccia/no_replay.py" "src/focaccia/native/tracer.py"
        "src/focaccia/native/lldb_target.py" "src/focaccia/qemu/target.py"
        "src/focaccia/qemu/_qemu_tool.py" "src/focaccia/qemu/report.py"
        "src/focaccia/completion.py" "src/focaccia/persistence.py"
        "src/focaccia/snapshot.py" "src/focaccia/symbolic.py" "src/focaccia/qemu/snapshot.py"
        "tests/test_no_replay.py" "tests/test_native_whole_program.py"
        "tests/test_qemu_whole_program.py" "tests/test_persistence.py" "tests/test_whole_program_report.py"
      ];
      pytestTargets = [
        "tests/test_no_replay.py" "tests/test_native_whole_program.py"
        "tests/test_qemu_whole_program.py" "tests/test_persistence.py" "tests/test_whole_program_report.py"
      ];
    };

    # Fake-only checks run on either host ISA. Live acceptance requires native
    # AArch64 hardware + authorized LLDB ptrace, and a Linux-user QEMU GDB socket.
    # Fake native observation only. Live invocation requires authorized native
    # AArch64 LLDB tracing; never applied to emulator or RR/remote targets.
    aarch64SourceContextCheck = mkStaticUnitCheck {
      name = "aarch64-whole-program-source-context";
      ruffTargets = [ "src/focaccia/qemu/snapshot.py" "src/focaccia/qemu/_qemu_tool.py" "src/focaccia/match.py" "src/focaccia/symbolic.py" "tests/test_aarch64_source_context.py" ];
      pytestTargets = [ "tests/test_aarch64_source_context.py" "tests/test_qemu_trace_output.py" "tests/test_match.py" ];
    };

    orderedStoreSnapshotAddressCheck = mkStaticUnitCheck {
      name = "ordered-store-snapshot-addresses";
      ruffTargets = [ "src/focaccia/qemu/snapshot.py" "src/focaccia/symbolic.py" "tests/test_aarch64_source_context.py" ];
      pytestTargets = [ "tests/test_aarch64_source_context.py" ];
    };

    aarch64VectorObservationCheck = mkStaticUnitCheck {
      name = "aarch64-qemu-vector-observation";
      ruffTargets = [ "src/focaccia/qemu/target.py" "tests/test_aarch64_qemu_context.py" ];
      pytestTargets = [ "tests/test_aarch64_qemu_context.py" ];
    };

    aarch64QemuContextCheck = mkStaticUnitCheck {
      name = "aarch64-qemu-independent-cpu-context";
      ruffTargets = [
        "src/focaccia/qemu/target.py" "src/focaccia/qemu/_qemu_tool.py"
        "src/focaccia/tools/validate_qemu.py" "tests/test_aarch64_qemu_context.py"
      ];
      pytestTargets = [
        "tests/test_aarch64_qemu_context.py" "tests/test_aarch64_dczva.py"
        "tests/test_aarch64_no_replay.py" "tests/test_gdb_program_state.py"
      ];
    };

    aarch64SvcBoundaryCheck = mkStaticUnitCheck {
      name = "aarch64-svc-successor-boundary";
      ruffTargets = [ "src/focaccia/qemu/target.py" "tests/test_aarch64_no_replay.py" ];
      pytestTargets = [ "tests/test_aarch64_no_replay.py" "tests/test_qemu_whole_program.py" ];
    };

    aarch64BranchAliasesCheck = mkStaticUnitCheck {
      name = "aarch64-carry-branch-aliases";
      ruffTargets = [
        "src/focaccia/symbolic.py" "src/focaccia/native/tracer.py"
        "tests/test_aarch64_branch_aliases.py"
      ];
      pytestTargets = [
        "tests/test_aarch64_branch_aliases.py" "tests/test_native_api.py"
        "tests/test_native_disassembly_cache.py" "tests/test_aarch64_no_replay.py"
      ];
    };

    aarch64SyscallPstateCheck = mkStaticUnitCheck {
      name = "aarch64-syscall-pstate-observation";
      ruffTargets = [
        "src/focaccia/no_replay.py" "src/focaccia/native/tracer.py"
        "tests/test_aarch64_syscall_pstate.py" "tests/test_aarch64_no_replay.py"
      ];
      pytestTargets = [
        "tests/test_aarch64_syscall_pstate.py" "tests/test_aarch64_no_replay.py"
        "tests/test_no_replay.py" "tests/test_native_whole_program.py"
        "tests/test_qemu_whole_program.py"
      ];
    };

    nativeDczidObservationCheck = mkStaticUnitCheck {
      name = "aarch64-native-dczid-observation";
      ruffTargets = [ "src/focaccia/native/tracer.py" "tests/test_native_dczid_observation.py" ];
      pytestTargets = [
        "tests/test_native_dczid_observation.py" "tests/test_aarch64_dczva.py"
        "tests/test_aarch64_no_replay.py" "tests/test_native_tracing.py"
        "tests/test_native_api.py"
      ];
    };

    aarch64DczvaCheck = mkStaticUnitCheck {
      name = "aarch64-target-dczid-zeroing";
      ruffTargets = [
        "src/focaccia/arch/aarch64.py" "src/focaccia/symbolic.py"
        "src/focaccia/miasm_util.py" "src/focaccia/native/lldb_target.py"
        "src/focaccia/qemu/target.py" "tests/test_aarch64_dczva.py"
        "tests/test_environment_symbols.py"
      ];
      pytestTargets = [
        "tests/test_aarch64_dczva.py" "tests/test_aarch64_dup.py"
        "tests/test_aarch64_no_replay.py" "tests/test_memory_byte_order.py"
        "tests/test_environment_symbols.py"
      ];
    };

    aarch64DupGeneralCheck = mkStaticUnitCheck {
      name = "aarch64-dup-general-semantics";
      ruffTargets = [ "src/focaccia/symbolic.py" "tests/test_aarch64_dup.py" ];
      pytestTargets = [ "tests/test_aarch64_dup.py" "tests/test_aarch64_no_replay.py" ];
    };

    aarch64NoReplayCheck = mkStaticUnitCheck {
      name = "aarch64-no-replay-whole-program";
      ruffTargets = [
        "src/focaccia/no_replay.py" "src/focaccia/native/tracer.py"
        "src/focaccia/qemu/target.py" "tests/test_aarch64_no_replay.py"
      ];
      pytestTargets = [
        "tests/test_aarch64_no_replay.py" "tests/test_no_replay.py"
        "tests/test_native_whole_program.py" "tests/test_qemu_whole_program.py"
      ];
    };

    x86NoReplaySourceContextCheck = mkStaticUnitCheck {
      name = "x86-no-replay-source-context";
      ruffTargets = [
        "src/focaccia/trace.py" "src/focaccia/qemu/snapshot.py"
        "src/focaccia/qemu/_qemu_tool.py" "tests/test_trace_completion.py"
        "tests/test_qemu_matching.py" "tests/test_no_replay.py"
        "tests/test_qemu_whole_program.py"
      ];
      pytestTargets = [
        "tests/test_trace_completion.py"
        "tests/test_qemu_matching.py"
        "tests/test_qemu_whole_program.py::test_collector_executes_and_validates_ordered_set_fs"
      ];
    };

    nativeWholeProgramCaptureCheck = mkStaticUnitCheck {
      name = "native-whole-program-capture";
      ruffTargets = [ "src/focaccia/native/tracer.py" "tests/test_native_whole_program.py" ];
      pytestTargets = [ "tests/test_native_whole_program.py" ];
    };

    nativeTerminalSyscallCheck = mkStaticUnitCheck {
      name = "native-terminal-syscall";
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

    rrLldbSyscallBoundaryCheck = mkStaticUnitCheck {
      name = "rr-lldb-syscall-boundary";
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

    # Pure symbolic fixtures: no native ISA, debugger, RR, or memory-ordering claim.
    aarch64LdapurSemanticsCheck = mkStaticUnitCheck {
      name = "aarch64-ldapur-semantics";
      ruffTargets = [ "tests/test_aarch64_ldapur.py" ];
      pytestTargets = [ "tests/test_aarch64_ldapur.py" ];
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

    pluginFramedTransportCheck = mkStaticUnitCheck {
      name = "plugin-framed-transport";
      ruffTargets = [
        "src/focaccia/qemu/transport.py"
        "tests/test_qemu_transport.py"
      ];
      pytestTargets = [ "tests/test_qemu_transport.py" ];
    };

    pluginWholeProgramTerminalEvidenceCheck = mkStaticUnitCheck {
      name = "plugin-whole-program-terminal-evidence";
      ruffTargets = [
        "src/focaccia/qemu/validation_server.py"
        "src/focaccia/tools/validate_qemu.py"
        "tests/test_qemu_whole_program.py"
      ];
      pytestTargets = [
        "tests/test_qemu_whole_program.py"
        "-k"
        "plugin_terminal_evidence or plugin_whole_program_rejects_before_connecting"
      ];
    };

    pluginStructuredReportCheck = mkStaticUnitCheck {
      name = "plugin-structured-validation-report";
      ruffTargets = [
        "src/focaccia/qemu/report.py"
        "src/focaccia/qemu/validation_server.py"
        "src/focaccia/tools/validate_qemu.py"
        "tests/test_qemu_launcher.py"
        "tests/test_qemu_trace_output.py"
      ];
      pytestTargets = [
        "tests/test_qemu_launcher.py::test_plugin_report_is_supported_without_enabling_replay_options"
        "tests/test_qemu_trace_output.py::test_quiet_plugin_validation_still_writes_structured_report"
        "tests/test_qemu_trace_output.py::test_plugin_validation_rejects_incomplete_trace_before_finish"
        "tests/test_qemu_trace_output.py::test_plugin_validation_aborts_peer_on_collection_failure"
      ];
    };

    gdbSetFsSuccessorCheck = mkStaticUnitCheck {
      name = "gdb-set-fs-successor";
      ruffTargets = [
        "src/focaccia/qemu/target.py"
        "tests/test_gdb_program_state.py"
      ];
      pytestTargets = [
        "tests/test_gdb_program_state.py::test_gdb_set_fs_stops_at_immediate_syscall_successor"
      ];
    };

    gdbSegmentSelectorWidthCheck = mkStaticUnitCheck {
      name = "gdb-segment-selector-width";
      ruffTargets = [
        "src/focaccia/qemu/target.py"
        "tests/test_gdb_program_state.py"
      ];
      pytestTargets = [
        "tests/test_gdb_program_state.py"
        "-k"
        "segment_selector"
      ];
    };

    pluginRegisterCacheCheck = mkStaticUnitCheck {
      name = "plugin-register-cache";
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

    pluginConnectionOwnershipCheck = mkStaticUnitCheck {
      name = "plugin-connection-ownership";
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

    gdbLaunchEncodingCheck = mkStaticUnitCheck {
      name = "gdb-launch-encoding";
      ruffTargets = [
        "src/focaccia/qemu/_qemu_tool.py"
        "src/focaccia/tools/validate_qemu.py"
        "tests/test_qemu_launcher.py"
      ];
      pytestTargets = [ "tests/test_qemu_launcher.py" ];
    };

    sharedSnapshotPlannerCheck = mkStaticUnitCheck {
      name = "shared-snapshot-planner";
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

    adaptiveSuccessorSourcePlanningCheck = mkStaticUnitCheck {
      name = "adaptive-successor-source-planning";
      ruffTargets = [
        "src/focaccia/match.py"
        "src/focaccia/qemu/_qemu_tool.py"
        "src/focaccia/qemu/snapshot.py"
        "src/focaccia/qemu/validation_server.py"
        "tests/test_qemu_matching.py"
      ];
      pytestTargets = [
        "tests/test_qemu_matching.py::test_plugin_collector_captures_union_of_direct_successor_dependencies"
        "tests/test_qemu_matching.py::test_plugin_collector_captures_late_composed_source_dependencies"
      ];
    };

    declaredValidationCutpointsCheck = mkStaticUnitCheck {
      name = "declared-validation-cutpoints";
      ruffTargets = [
        "src/focaccia/qemu/_qemu_tool.py"
        "src/focaccia/tools/validate_qemu.py"
        "tests/test_qemu_matching.py"
      ];
      pytestTargets = [
        "tests/test_qemu_matching.py::test_gdb_collector_composes_to_declared_cutpoint"
      ];
    };

    narrowVectorObservationCheck = mkStaticUnitCheck {
      name = "narrow-vector-observation";
      ruffTargets = [
        "src/focaccia/qemu/snapshot.py"
        "src/focaccia/qemu/state.py"
        "src/focaccia/qemu/target.py"
        "src/focaccia/qemu/validation_server.py"
        "tests/test_gdb_program_state.py"
        "tests/test_qemu_snapshot.py"
      ];
      pytestTargets = [
        "tests/test_gdb_program_state.py::test_gdb_reads_narrow_vector_alias_without_requiring_zmm"
        "tests/test_qemu_snapshot.py"
      ];
    };

    narrowVectorDependencyPlanningCheck = mkStaticUnitCheck {
      name = "narrow-vector-dependency-planning";
      ruffTargets = [
        "src/focaccia/qemu/snapshot.py"
        "src/focaccia/symbolic.py"
        "tests/test_qemu_snapshot.py"
      ];
      pytestTargets = [
        "tests/test_qemu_snapshot.py::test_vector_source_planning_preserves_narrow_aliases"
      ];
    };

    narrowVectorValidationEvaluationCheck = mkStaticUnitCheck {
      name = "narrow-vector-validation-evaluation";
      ruffTargets = [
        "src/focaccia/symbolic.py"
        "tests/test_qemu_snapshot.py"
      ];
      pytestTargets = [
        "tests/test_qemu_snapshot.py::test_vector_validation_evaluation_preserves_narrow_aliases"
      ];
    };

    wideRegisterStateSerializationCheck = mkStaticUnitCheck {
      name = "wide-register-state-serialization";
      ruffTargets = [
        "src/focaccia/persistence.py"
        "tests/test_persistence.py"
        "tests/test_state_serialization.py"
      ];
      pytestTargets = [
        "tests/test_state_serialization.py::test_wide_x86_registers_serialize_without_integer_limits"
        "tests/test_state_serialization.py::test_snapshot_serialization_preserves_identity_and_partial_validity"
        "tests/test_persistence.py::test_schema_v2_state_documents_remain_readable"
      ];
    };

    undefinedShiftFlagSemanticsCheck = mkStaticUnitCheck {
      name = "undefined-shift-flag-semantics";
      ruffTargets = [
        "src/focaccia/persistence.py"
        "src/focaccia/symbolic.py"
        "tests/test_compare.py"
        "tests/test_persistence.py"
        "tests/test_symbolic_composition.py"
      ];
      pytestTargets = [
        "tests/test_compare.py::test_undefined_shift_rotate_overflow_is_not_compared"
        "tests/test_compare.py::test_shift_count_at_operand_width_makes_carry_unknown"
        "tests/test_compare.py::test_shift_overflow_remains_defined_for_effective_count_one"
        "tests/test_symbolic_composition.py::test_undefined_shift_flag_propagates_until_a_later_definition"
        "tests/test_persistence.py::test_undefined_shift_flag_metadata_round_trips"
      ];
    };

    qemuMmxObservationCheck = mkStaticUnitCheck {
      name = "qemu-mmx-observation";
      ruffTargets = [
        "src/focaccia/arch/x86.py"
        "src/focaccia/qemu/target.py"
        "src/focaccia/qemu/validation_server.py"
        "tests/test_architecture.py"
        "tests/test_compare.py"
        "tests/test_gdb_program_state.py"
        "tests/test_plugin_state_validity.py"
        "tests/test_qemu_snapshot.py"
      ];
      pytestTargets = [
        "tests/test_architecture.py::test_x86_mmx_registers_do_not_alias_simd_registers"
        "tests/test_architecture.py::test_mmx_stack_mapping_rejects_non_mmx_registers"
        "tests/test_architecture.py::test_mmx_stack_mapping_tracks_physical_slots"
        "tests/test_compare.py::test_mmx_source_detects_the_rex_movq_mismatch_without_zmm_state"
        "tests/test_gdb_program_state.py::test_gdb_reads_physical_mmx_value_from_logical_x87_stack"
        "tests/test_plugin_state_validity.py::test_plugin_reads_physical_mmx_value_from_logical_x87_stack"
        "tests/test_qemu_snapshot.py::test_mmx_source_planning_does_not_request_simd_state"
      ];
    };

    xmmReadTransportCheck = mkStaticUnitCheck {
      name = "qemu-xmm-read-transport";
      ruffTargets = [ "src/focaccia/qemu/transport_profile.py" "tests/test_xmm_transport_profile.py" ];
      pytestTargets = [ "tests/test_xmm_transport_profile.py" ];
    };

    wideVectorObservationCapabilityCheck = mkStaticUnitCheck {
      name = "wide-vector-observation-capability";
      ruffTargets = [ "src/focaccia/qemu/snapshot.py" "tests/test_qemu_snapshot.py" ];
      pytestTargets = [
        "tests/test_qemu_snapshot.py::test_wide_vector_observation_capability_rejects_unknown_upper_lanes"
      ];
    };

    gdbWideRegisterCheck = mkStaticUnitCheck {
      name = "gdb-wide-registers";
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

    x86EflagsObservationCheck = mkStaticUnitCheck {
      name = "x86-eflags-observation";
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

    codeNamingPolicyCheck = pkgs.runCommand "code-naming-policy" {
      nativeBuildInputs = [ pkgs.gnugrep ];
    } ''
      numbered_fix_pattern="fi""x([-_]?[0-9]{3}|[0-9]{3}[A-Z])"
      private_issue_pattern="is""sue[ #:-]*[0-9]{3}|docs/is""sues/[0-9]{3}"
      ! grep -R -n -E "$numbered_fix_pattern|$private_issue_pattern" \
        ${self}/flake.nix ${self}/pyproject.toml ${self}/src ${self}/tests
      touch "$out"
    '';

    flakeSourceBoundaryCheck =
      assert qemu-submodule.rev == "83e4033ef58f5eb377807e6449115ec9d801d314";
      assert rr-submodule.rev == "f248913aa51ccf61932145a67e08a1e811953a2b";
      pkgs.runCommand "flake-source-boundary" {
        nativeBuildInputs = [ pkgs.coreutils pkgs.gnugrep ];
      } ''
        test ! -e ${self}/miasm/src/miasm
        test ! -e ${self}/qemu/softmmu
        test ! -e ${self}/rr/src

        self_kib=$(du -sk ${self} | cut -f1)
        test "$self_kib" -lt 65536

        grep -F 'miasm = { git = "https://github.com/taugoust/miasm.git", rev = "b5e1de0d0a81ec34646d7c0b0b3cc476ef3b9c7f" }' \
          ${self}/pyproject.toml
        grep -F 'source = { git = "https://github.com/taugoust/miasm.git?rev=b5e1de0d0a81ec34646d7c0b0b3cc476ef3b9c7f#b5e1de0d0a81ec34646d7c0b0b3cc476ef3b9c7f" }' \
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

    recordedFcntlReplayCheck = mkStaticUnitCheck {
      name = "recorded-fcntl-replay";
      ruffTargets = [
        "src/focaccia/qemu/replay.py"
        "src/focaccia/qemu/syscall.py"
        "src/focaccia/qemu/x86.py"
        "tests/test_x86_replay.py"
      ];
      pytestTargets = [
        "tests/test_x86_replay.py"
        "-k"
        "supported_fcntl_commands or unknown_fcntl_command"
      ];
    };

    recordedTiocgwinszReplayCheck = mkStaticUnitCheck {
      name = "recorded-tiocgwinsz-replay";
      ruffTargets = [
        "src/focaccia/qemu/replay.py"
        "src/focaccia/qemu/syscall.py"
        "src/focaccia/qemu/x86.py"
        "tests/test_x86_replay.py"
      ];
      pytestTargets = [
        "tests/test_x86_replay.py"
        "-k"
        "tiocgwinsz_replays_recorded_output or classified_unsafe_ioctl"
      ];
    };

    qemuSyscallPostBoundaryCheck = mkStaticUnitCheck {
      name = "qemu-syscall-post-boundary";
      ruffTargets = [
        "src/focaccia/qemu/replay.py"
        "src/focaccia/qemu/target.py"
        "tests/test_x86_replay.py"
      ];
      pytestTargets = [
        "tests/test_x86_replay.py"
        "-k"
        "anonymous_mmap_executes_and_reconciles_exact_result"
      ];
    };

    fixedRecordedAnonymousMmapCheck = mkStaticUnitCheck {
      name = "fixed-recorded-anonymous-mmap";
      ruffTargets = [
        "src/focaccia/qemu/replay.py"
        "src/focaccia/qemu/x86.py"
        "tests/test_x86_replay.py"
      ];
      pytestTargets = [
        "tests/test_x86_replay.py"
        "-k"
        "anonymous_mmap_null"
      ];
    };

    translatedInitialBrkQueryCheck = mkStaticUnitCheck {
      name = "translated-initial-brk-query";
      ruffTargets = [
        "src/focaccia/qemu/replay.py"
        "src/focaccia/qemu/syscall.py"
        "src/focaccia/qemu/x86.py"
        "tests/test_x86_replay.py"
      ];
      pytestTargets = [
        "tests/test_x86_replay.py"
        "-k"
        "brk_zero_query_applies_recorded_address"
      ];
    };

    recordedSyscallClobberReplayCheck = mkStaticUnitCheck {
      name = "recorded-syscall-clobber-replay";
      ruffTargets = [
        "src/focaccia/qemu/replay.py"
        "tests/test_x86_replay.py"
      ];
      pytestTargets = [
        "tests/test_x86_replay.py"
        "-k"
        "executed_syscall_applies_recorded_rcx_and_r11_control_effects"
      ];
    };

    recordedArchPrctlReplayCheck = mkStaticUnitCheck {
      name = "recorded-arch-prctl-replay";
      ruffTargets = [
        "src/focaccia/qemu/replay.py"
        "src/focaccia/qemu/syscall.py"
        "src/focaccia/qemu/x86.py"
        "tests/test_x86_replay.py"
      ];
      pytestTargets = [
        "tests/test_x86_replay.py"
        "-k"
        "arch_prctl_replays_recorded_segment_bases"
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

    interruptedSyscallSignalFrameCheck = mkStaticUnitCheck {
      name = "interrupted-syscall-signal-frame";
      ruffTargets = [
        "src/focaccia/qemu/replay.py"
        "src/focaccia/qemu/x86.py"
        "tests/test_x86_signal_replay.py"
      ];
      pytestTargets = [
        "tests/test_x86_signal_replay.py"
        "-k"
        "interrupted_syscall"
      ];
    };

    relocatedX86SignalFrameCheck = mkStaticUnitCheck {
      name = "relocated-x86-signal-frame";
      ruffTargets = [
        "src/focaccia/qemu/replay.py"
        "src/focaccia/qemu/x86.py"
        "tests/test_x86_signal_replay.py"
      ];
      pytestTargets = [
        "tests/test_x86_signal_replay.py"
        "-k"
        "signal_delivery_relocates or signal_relocation_rejects or relocated_rt_sigreturn"
      ];
    };

    nonSiginfoSignalFrameCheck = mkStaticUnitCheck {
      name = "non-siginfo-signal-frame";
      ruffTargets = [
        "src/focaccia/qemu/replay.py"
        "src/focaccia/qemu/x86.py"
        "tests/test_x86_signal_replay.py"
      ];
      pytestTargets = [
        "tests/test_x86_signal_replay.py"
        "-k"
        "non_siginfo_signal or siginfo_signal_rejects"
      ];
    };

    partialX86SignalStateReplayCheck = mkStaticUnitCheck {
      name = "partial-x86-signal-state-replay";
      ruffTargets = [
        "src/focaccia/qemu/replay.py"
        "src/focaccia/qemu/target.py"
        "tests/test_gdb_program_state.py"
        "tests/test_x86_signal_replay.py"
      ];
      pytestTargets = [
        "tests/test_gdb_program_state.py"
        "tests/test_x86_signal_replay.py"
        "-k"
        "gdb_signal_replay or partial_signal_extra_transition"
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

    absentVdsoStartupReplayCheck = mkStaticUnitCheck {
      name = "x86-startup-without-vdso";
      ruffTargets = [
        "src/focaccia/qemu/replay.py"
        "src/focaccia/qemu/target.py"
        "tests/test_gdb_program_state.py"
        "tests/test_x86_replay.py"
      ];
      pytestTargets = [
        "tests/test_x86_replay.py::test_initial_exec_neutralizes_recorded_vdso_when_live_stack_has_none"
        "tests/test_gdb_program_state.py::test_startup_mmap_uses_static_executable_without_vdso"
      ];
    };

    protectedEntryStartupReplayCheck = mkStaticUnitCheck {
      name = "protected-entry-startup-replay";
      ruffTargets = [
        "src/focaccia/qemu/replay.py"
        "src/focaccia/qemu/target.py"
        "tests/test_gdb_program_state.py"
        "tests/test_x86_replay.py"
      ];
      pytestTargets = [
        "tests/test_gdb_program_state.py::test_startup_mmap_uses_existing_syscall_without_writing_rx_text"
        "tests/test_gdb_program_state.py::test_startup_mmap_rejects_image_without_syscall_before_mutation"
        "tests/test_x86_replay.py::test_initial_exec_establishes_recorded_stack_with_live_vdso"
      ];
    };

    recordedX86InitialStackCheck = mkStaticUnitCheck {
      name = "recorded-x86-initial-stack";
      ruffTargets = [
        "src/focaccia/qemu/replay.py"
        "src/focaccia/qemu/target.py"
        "tests/test_x86_replay.py"
        "tests/test_gdb_program_state.py"
      ];
      pytestTargets = [
        "tests/test_x86_replay.py"
        "tests/test_gdb_program_state.py"
        "-k"
        "initial_stack or initial_exec"
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

    nonDestructiveQemuReportingCheck = mkStaticUnitCheck {
      name = "non-destructive-qemu-reporting";
      ruffTargets = [
        "src/focaccia/qemu/_qemu_tool.py"
        "src/focaccia/qemu/report.py"
        "tests/test_qemu_report.py"
      ];
      pytestTargets = [
        "tests/test_qemu_report.py::test_gdb_validation_persists_artifacts_before_renderer_failure"
      ];
    };

    boundedDiagnosticRenderingCheck = mkStaticUnitCheck {
      name = "bounded-diagnostic-rendering";
      ruffTargets = [
        "src/focaccia/utils.py"
        "tests/test_compare.py"
      ];
      pytestTargets = [
        "tests/test_compare.py::test_result_renderer_bounds_entries_diagnostics_and_transform_text"
      ];
    };

    aarch64SignalReturnDispatchCheck = mkStaticUnitCheck {
      name = "aarch64-signal-return-dispatch";
      ruffTargets = [ "src/focaccia/qemu/replay.py" "tests/test_aarch64_signal_replay.py" ];
      pytestTargets = [ "tests/test_aarch64_signal_replay.py::test_aarch64_signal_frame_delivery_and_rt_sigreturn_round_trip" ];
    };

    currentDiagnosticStreamCheck = mkStaticUnitCheck {
      name = "current-diagnostic-stream";
      ruffTargets = [ "src/focaccia/utils.py" "tests/test_compare.py" ];
      pytestTargets = [ "tests/test_compare.py::test_separator_uses_current_output_stream" ];
    };

    memoryMismatchLocalizationCheck = mkStaticUnitCheck {
      name = "memory-mismatch-localization";
      ruffTargets = [
        "src/focaccia/compare.py"
        "tests/test_compare.py"
        "tests/test_qemu_report.py"
      ];
      pytestTargets = [
        "tests/test_compare.py::test_symbolic_memory_validation_classifies_missing_and_incorrect_destinations"
        "tests/test_compare.py::test_symbolic_memory_validation_checks_every_output_after_an_unavailable_range"
        "tests/test_compare.py::test_symbolic_memory_validation_fails_closed_on_unavailable_dependencies"
        "tests/test_qemu_report.py::test_structured_qemu_report_localizes_memory_mismatch"
      ];
    };

    qemuWholeProgramCollectionCheck = mkStaticUnitCheck {
      name = "qemu-whole-program-collection";
      ruffTargets = [
        "src/focaccia/match.py"
        "src/focaccia/qemu/validation_server.py"
        "src/focaccia/qemu/_qemu_tool.py"
        "src/focaccia/qemu/target.py"
        "src/focaccia/qemu/report.py"
        "tests/test_qemu_whole_program.py"
      ];
      pytestTargets = [ "tests/test_qemu_whole_program.py" ];
    };

    wholeProgramTerminalAcceptanceCheck = mkStaticUnitCheck {
      name = "whole-program-terminal-acceptance";
      ruffTargets = [
        "src/focaccia/qemu/report.py"
        "tests/test_whole_program_report.py"
      ];
      pytestTargets = [ "tests/test_whole_program_report.py" ];
    };

    terminalTraceReportingCheck = mkStaticUnitCheck {
      name = "terminal-trace-reporting";
      ruffTargets = [
        "src/focaccia/qemu/_qemu_tool.py"
        "src/focaccia/qemu/report.py"
        "tests/test_qemu_report.py"
      ];
      pytestTargets = [
        "tests/test_qemu_report.py::test_structured_qemu_report_records_terminal_trace_evidence"
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

    wholeProgramSmokeCheck = mkStaticUnitCheck {
      name = "whole-program-smoke";
      ruffTargets = [ "src/focaccia/tools/rr_qemu_smoke.py" "tests/test_rr_qemu_smoke.py" ];
      pytestTargets = [ "tests/test_rr_qemu_smoke.py" ];
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

    traceCompletionPersistenceCheck = mkStaticUnitCheck {
      name = "trace-completion-persistence";
      ruffTargets = [
        "src/focaccia/completion.py"
        "src/focaccia/trace.py"
        "src/focaccia/persistence.py"
        "tests/test_trace_completion.py"
      ];
      pytestTargets = [ "tests/test_trace_completion.py" ];
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

    box64AdjacentFlagsCheck = mkStaticUnitCheck {
      name = "box64-adjacent-flags";
      ruffTargets = [
        "src/focaccia/parser.py"
        "tests/test_trace.py"
      ];
      pytestTargets = [
        "tests/test_trace.py"
        "-k"
        "box64_parser_separates_adjacent_flags"
      ];
    };

    box64FlagObservationValidityCheck = mkStaticUnitCheck {
      name = "box64-flag-observation-validity";
      ruffTargets = [
        "src/focaccia/parser.py"
        "tests/test_trace.py"
      ];
      pytestTargets = [
        "tests/test_trace.py"
        "-k"
        "box64_parser_does_not_treat_stale_materialized_flags_as_observed or box64_parser_keeps_legacy_deferred_flags_unknown"
      ];
    };

    box64FusedPushCutpointCheck = mkStaticUnitCheck {
      name = "box64-fused-push-cutpoint";
      ruffTargets = [
        "src/focaccia/parser.py"
        "tests/test_trace.py"
      ];
      pytestTargets = [
        "tests/test_trace.py"
        "-k"
        "box64_parser_groups_proven_fused_pushes_without_fabricating_boundary or box64_parser_does_not_group_ordinary_cmpxchg_boundary"
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

    concretePcDiagnosticCheck = mkStaticUnitCheck {
      name = "concrete-pc-diagnostic";
      ruffTargets = [
        "src/focaccia/match.py"
        "tests/test_match.py"
      ];
      pytestTargets = [
        "tests/test_match.py"
        "-k"
        "no_matching_boundary_and_unavailable_pc"
      ];
    };

    matchingFailureDiagnosticsCheck = mkStaticUnitCheck {
      name = "matching-failure-diagnostics";
      ruffTargets = [
        "src/focaccia/match.py"
        "tests/test_match.py"
      ];
      pytestTargets = [ "tests/test_match.py" ];
    };

    repeatedTransformDecodingCheck = mkStaticUnitCheck {
      name = "repeated-transform-decoding";
      ruffTargets = [
        "src/focaccia/persistence.py"
        "tests/test_persistence.py"
      ];
      pytestTargets = [
        "tests/test_persistence.py"
        "-k"
        "repeated_msgpack_decode or msgpack_transform_round_trip or msgpack_stream_rejects"
      ];
    };

    transformSerializationValidationReuseCheck = mkStaticUnitCheck {
      name = "transform-serialization-validation-reuse";
      # Offline parsing/serialization fixtures; no native debugger or RR.
      ruffTargets = [
        "src/focaccia/persistence.py"
        "tests/test_transform_serialization_reuse.py"
      ];
      pytestTargets = [
        "tests/test_transform_serialization_reuse.py"
        "tests/test_persistence.py"
      ];
    };

    persistenceAdversarialInputsCheck = mkStaticUnitCheck {
      name = "persistence-adversarial-inputs";
      ruffTargets = [
        "src/focaccia/persistence.py"
        "tests/test_persistence.py"
      ];
      pytestTargets = [ "tests/test_persistence.py" ];
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

    indexedDestinationMatchingCheck = mkStaticUnitCheck {
      name = "indexed-destination-matching";
      ruffTargets = [
        "src/focaccia/match.py"
        "tests/test_match.py"
      ];
      pytestTargets = [
        "tests/test_match.py"
        "-k"
        "bounded_unmatched_destination or indexed_terminal_destination"
      ];
    };

    deferredMemoryAliasCheck = mkStaticUnitCheck {
      name = "deferred-memory-alias-resolution";
      ruffTargets = [
        "src/focaccia/miasm_util.py"
        "src/focaccia/symbolic.py"
        "tests/test_symbolic_composition.py"
      ];
      pytestTargets = [
        "tests/test_symbolic_composition.py"
        "-k"
        "deferred_memory_reads or store or memory_aliases or overlapping"
      ];
    };

    optInUnmatchedTransformSkippingCheck = mkStaticUnitCheck {
      name = "opt-in-unmatched-transform-skipping";
      ruffTargets = [
        "src/focaccia/match.py"
        "src/focaccia/symbolic.py"
        "src/focaccia/qemu/_qemu_tool.py"
        "src/focaccia/qemu/validation_server.py"
        "src/focaccia/tools/validate_qemu.py"
        "tests/test_match.py"
        "tests/test_qemu_launcher.py"
        "tests/test_qemu_matching.py"
      ];
      pytestTargets = [
        "tests/test_match.py"
        "tests/test_qemu_launcher.py"
        "tests/test_qemu_matching.py"
        "-k"
        "unmatched_skip or unmatched_skipping"
      ];
    };

    completeCutpointSourceSnapshotCheck = mkStaticUnitCheck {
      name = "complete-cutpoint-source-snapshot";
      ruffTargets = [
        "src/focaccia/match.py"
        "src/focaccia/qemu/_qemu_tool.py"
        "src/focaccia/qemu/snapshot.py"
        "src/focaccia/qemu/target.py"
        "src/focaccia/qemu/validation_server.py"
        "tests/test_qemu_matching.py"
      ];
      pytestTargets = [
        "tests/test_qemu_matching.py"
        "-k"
        "late_composed_source_dependencies or gdb_collector"
      ];
    };

    linearCutpointCompositionCheck = mkStaticUnitCheck {
      name = "linear-cutpoint-composition";
      ruffTargets = [
        "src/focaccia/match.py"
        "src/focaccia/symbolic.py"
        "tests/test_match.py"
        "tests/test_symbolic_composition.py"
      ];
      pytestTargets = [
        "tests/test_match.py"
        "tests/test_symbolic_composition.py"
        "-k"
        "large_terminal_cutpoint or symbolic_state_composition_is_associative or memory"
      ];
    };

    guestSignalLocalizationCheck = mkStaticUnitCheck {
      name = "guest-signal-localization";
      ruffTargets = [
        "src/focaccia/qemu/_qemu_tool.py"
        "src/focaccia/qemu/report.py"
        "src/focaccia/qemu/target.py"
        "tests/test_gdb_program_state.py"
        "tests/test_qemu_report.py"
      ];
      pytestTargets = [
        "tests/test_gdb_program_state.py::test_gdb_step_stops_at_first_guest_signal"
        "tests/test_qemu_report.py::test_gdb_validation_avoids_timing_output_and_writes_report"
        "tests/test_qemu_report.py::test_structured_qemu_report_records_guest_signal_and_fault_pc"
        "tests/test_qemu_report.py::test_pending_transition_requires_localized_signal_for_confirmed_mismatch"
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

    comparisonErrorClassificationCheck = mkStaticUnitCheck {
      name = "comparison-error-classification";
      ruffTargets = [
        "src/focaccia/compare.py"
        "tests/test_compare.py"
      ];
      pytestTargets = [ "tests/test_compare.py" ];
    };

    definedRegisterOutputValidationCheck = mkStaticUnitCheck {
      name = "defined-register-output-validation";
      ruffTargets = [
        "src/focaccia/compare.py"
        "tests/test_compare.py"
      ];
      pytestTargets = [
        "tests/test_compare.py"
        "-k"
        "defined_register_output_slices"
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

    canonicalRegisterOutputCacheCheck = mkStaticUnitCheck {
      name = "canonical-register-output-cache";
      ruffTargets = [
        "src/focaccia/arch/arch.py"
        "src/focaccia/symbolic.py"
        "tests/test_symbolic_composition.py"
      ];
      pytestTargets = [
        "tests/test_symbolic_composition.py::test_canonical_output_cache_preserves_alias_unknown_and_mutation_semantics"
      ];
    };

    symbolicCompositionCheck = mkStaticUnitCheck {
      name = "symbolic-composition";
      ruffTargets = [
        "src/focaccia/arch"
        "src/focaccia/miasm_util.py"
        "src/focaccia/symbolic.py"
        "tests/test_symbolic_composition.py"
      ];
      pytestTargets = [ "tests/test_symbolic_composition.py" ];
    };

    linearSuccessorPlanningCheck = mkStaticUnitCheck {
      name = "linear-successor-planning";
      ruffTargets = [
        "src/focaccia/match.py"
        "src/focaccia/symbolic.py"
        "src/focaccia/qemu/snapshot.py"
        "src/focaccia/qemu/_qemu_tool.py"
        "src/focaccia/qemu/validation_server.py"
        "tests/test_qemu_matching.py"
      ];
      pytestTargets = [
        "tests/test_qemu_matching.py"
        "-k"
        "successor_dependency_planning or successor_dependencies or skip_mode_does_not_compose_candidate_dependencies"
      ];
    };

    boundedNoSkipCollectorPlanningCheck = mkStaticUnitCheck {
      name = "bounded-no-skip-collector-planning";
      ruffTargets = [
        "src/focaccia/qemu/_qemu_tool.py"
        "src/focaccia/qemu/validation_server.py"
        "tests/test_qemu_matching.py"
      ];
      pytestTargets = [
        "tests/test_qemu_matching.py"
        "-k"
        "no_skip_collector_plans_declared_long_block_once"
      ];
    };

    boundedLongCutpointCompositionCheck = mkStaticUnitCheck {
      name = "bounded-long-cutpoint-composition";
      ruffTargets = [
        "src/focaccia/symbolic.py"
        "tests/test_symbolic_composition.py"
      ];
      pytestTargets = [
        "tests/test_symbolic_composition.py"
        "-k"
        "long_composition_does_not_rescan_accumulated_register_dags"
      ];
    };

    iterativeSymbolicDagProcessingCheck = mkStaticUnitCheck {
      name = "iterative-symbolic-dag-processing";
      ruffTargets = [
        "src/focaccia/miasm_util.py"
        "src/focaccia/symbolic.py"
        "tests/test_symbolic_composition.py"
      ];
      pytestTargets = [
        "tests/test_symbolic_composition.py::test_deep_expression_composition_evaluation_and_dependencies_are_iterative"
      ];
    };

    fp32ToFp64Check = mkStaticUnitCheck {
      name = "fp32-to-fp64";
      ruffTargets = [
        "src/focaccia/miasm_util.py"
        "tests/test_fp_semantics.py"
      ];
      pytestTargets = [ "tests/test_fp_semantics.py" ];
    };

    explicitTraceGapsCheck = mkStaticUnitCheck {
      name = "explicit-trace-gaps";
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

    x86ExtendedRegisterAliasesCheck = mkStaticUnitCheck {
      name = "x86-extended-register-aliases";
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

    targetEnvironmentSymbolsCheck = mkStaticUnitCheck {
      name = "target-environment-symbols";
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

    signalExtraRegistersCheck = mkStaticUnitCheck {
      name = "signal-extra-registers";
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

    aarch64DeterministicReplayCheck = mkStaticUnitCheck {
      name = "aarch64-deterministic-replay";
      ruffTargets = [
        "src/focaccia/qemu/aarch64.py"
        "src/focaccia/qemu/deterministic.py"
        "src/focaccia/qemu/replay.py"
        "src/focaccia/qemu/target.py"
        "tests/test_aarch64_replay.py"
      ];
      pytestTargets = [ "tests/test_aarch64_replay.py" ];
    };

    aarch64NativeRrToolCheck = pkgs.runCommand "aarch64-native-rr-tool" {
      nativeBuildInputs = [ rrTool pkgs.gnugrep ];
    } ''
      mkdir -p "$out"
      rr --version | tee "$out/version.txt"
      grep -F 'rr version' "$out/version.txt"
    '';

    rrStandaloneLldbCompatibilityCheck =
      pkgs.runCommand "rr-standalone-lldb-compatibility" {
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
      qemu-plugin-2248-injected =
        qemu-submodule.packages.${system}.with-focaccia-plugin-2248;
      qemu-plugin-source = qemu-submodule.packages.${system}.plugin-source;

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

      # Opt-in only: requires authorized same-ISA native ptrace/process-memory
      # access. No RR, sandbox relaxations, or production tracing semantics.
      native-terminal-observation = {
        type = "app";
        program = let
          wrapper = pkgs.writeShellScriptBin "native-terminal-observation" ''
            ulimit -c 0
            exec ${python.interpreter} ${./tests/probes}/native_terminal_observation.py \
              --lldb ${pkgs.lldb}/bin/lldb \
              --fixtures ${nativeTerminalFixtures}/bin "$@"
          '';
        in "${wrapper}/bin/native-terminal-observation";
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
      core-branch-coverage = coreBranchCoverageCheck;
      coverage-classification-ratchet = coreBranchCoverageCheck;
      mutation-core-smoke = mutationCoreSmokeCheck;
      property-core-models = propertyCoreModelsCheck;
      reproducer-memory-layout = reproducerMemoryLayoutCheck;
      reproducer-state-restoration = reproducerStateRestorationCheck;
      reproducer-ymm-restoration = mkStaticUnitCheck {
        name = "reproducer-ymm-restoration";
        ruffTargets = [ "src/focaccia/reproducer.py" "tests/test_reproducer.py" ];
        pytestTargets = [ "tests/test_reproducer.py" "-k" "ymm_restore" ];
      };
      reproducer-narrow-gpr-restoration = reproducerNarrowGprRestorationCheck;
      reproducer-observed-upper-context = reproducerObservedUpperContextCheck;
      reproducer-simd-mmx-restoration = reproducerSimdMmxRestorationCheck;
      reproducer-aarch64-backend = reproducerAarch64BackendCheck;
      aarch64-reproducer-stop-capture = aarch64ReproducerStopCaptureCheck;
      reproducer-fragment-fidelity = reproducerFragmentFidelityCheck;
      no-replay-syscall-actions = noReplaySyscallActionsCheck;
      no-replay-anonymous-mmap = noReplayAnonymousMmapCheck;
      register-api-migration = registerApiMigrationCheck;
      cli-imports = cliImportsCheck;
      native-read-pc = nativeReadPcCheck;
      local-target-selection = localTargetSelectionCheck;
      disassembly-fallback = disassemblyFallbackCheck;
      remote-target-selection = remoteTargetSelectionCheck;
      oracle-program-routing = oracleProgramRoutingCheck;
      cross-validate-option = crossValidateOptionCheck;
      native-event-matching = nativeEventMatchingCheck;
      speculative-synchronization = speculativeSynchronizationCheck;
      lldb-segment-selector-observation = lldbSegmentSelectorObservationCheck;
      native-target-error-handling = nativeTargetErrorHandlingCheck;
      lldb-remote-state-event = lldbRemoteStateEventCheck;
      native-event-phase = nativeEventPhaseCheck;
      lldb-remote-x86-flags-width = lldbRemoteX86FlagsWidthCheck;
      lldb-canonical-rflags-observation = lldbCanonicalRflagsObservationCheck;
      repeated-pc-materialization = repeatedPcMaterializationCheck;
      recorded-syscall-control-output = recordedSyscallControlOutputCheck;
      observed-division-control = observedDivisionControlCheck;
      observed-popf-control = observedPopfControlCheck;
      defined-flag-cross-validation = definedFlagCrossValidationCheck;
      xmm-cross-validation = xmmCrossValidationCheck;
      empty-miasm-disassembly = emptyMiasmDisassemblyCheck;
      vex-disassembly-validation = vexDisassemblyValidationCheck;
      native-disassembly-verification-reuse = nativeDisassemblyVerificationReuseCheck;
      lsl-environment-specialization = lslEnvironmentSpecializationCheck;
      rex-mmx-movq = rexMmxMovqCheck;
      native-signal-action = nativeSignalActionCheck;
      miasm-sse-support = miasmSseSupportCheck;
      x86-ucomisd-concrete-resolution = x86UcomisdConcreteResolutionCheck;
      x86-avx-logic-semantics = x86AvxLogicCheck;
      partial-wide-vector-dependency = partialWideVectorDependencyCheck;
      adaptive-unobservable-output-composition = adaptiveUnobservableOutputCompositionCheck;
      native-remote-wide-vector-observation = nativeRemoteWideVectorObservationCheck;
      native-narrow-register-alias = nativeNarrowRegisterAliasCheck;
      x86-vector-persistence-roundtrip = x86VectorPersistenceRoundtripCheck;
      x86-aligned-vector-moves = x86AlignedVectorMovesCheck;
      miasm-vmovdqu-support = miasmVmovdquSupportCheck;
      opt-in-capture-profiling = optInCaptureProfilingCheck;
      lldb-lock-prefix-disassembly = lldbLockPrefixDisassemblyCheck;
      native-component-accounting = nativeComponentAccountingCheck;
      persistence-timing-separation = persistenceTimingSeparationCheck;
      qemu-validation-profile-components = qemuValidationProfileComponentsCheck;
      qemu-stop-generation-cache = qemuStopGenerationCacheCheck;
      x86-syscall-entry-matching = x86SyscallEntryMatchingCheck;
      native-terminal-syscall = nativeTerminalSyscallCheck;
      native-whole-program-capture = nativeWholeProgramCaptureCheck;
      no-replay-exit-only-whole-program = noReplayExitOnlyCheck;
      no-replay-ordered-set-fs = noReplaySetFsCheck;
      no-replay-set-fs-continued-diagnostics = noReplaySetFsContinuedDiagnosticsCheck;
      no-replay-syscall-continued-diagnostics = noReplaySyscallContinuedDiagnosticsCheck;
      no-replay-context-relative-tid = noReplayContextTidCheck;
      aarch64-no-replay-whole-program = aarch64NoReplayCheck;
      x86-no-replay-source-context = x86NoReplaySourceContextCheck;
      aarch64-dup-general-semantics = aarch64DupGeneralCheck;
      aarch64-target-dczid-zeroing = aarch64DczvaCheck;
      aarch64-native-dczid-observation = nativeDczidObservationCheck;
      aarch64-syscall-pstate-observation = aarch64SyscallPstateCheck;
      aarch64-carry-branch-aliases = aarch64BranchAliasesCheck;
      aarch64-svc-successor-boundary = aarch64SvcBoundaryCheck;
      aarch64-qemu-independent-cpu-context = aarch64QemuContextCheck;
      aarch64-whole-program-source-context = aarch64SourceContextCheck;
      ordered-store-snapshot-addresses = orderedStoreSnapshotAddressCheck;
      aarch64-qemu-vector-observation = aarch64VectorObservationCheck;
      native-post-exit-cross-validation = nativePostExitCrossValidationCheck;
      rr-lldb-syscall-boundary = rrLldbSyscallBoundaryCheck;
      native-gap-error-boundaries = nativeGapErrorBoundariesCheck;
      native-vector-register-byte-order = nativeVectorRegisterByteOrderCheck;
      native-scripted-tracing = nativeScriptedTracingCheck;
      architecture-identity = architectureIdentityCheck;
      sparse-memory-validity = sparseMemoryValidityCheck;
      register-validity = registerValidityCheck;
      multibit-flags = multibitFlagsCheck;
      aarch64-register-semantics = aarch64RegisterSemanticsCheck;
      aarch64-ldapur-semantics = aarch64LdapurSemanticsCheck;
      memory-byte-order = memoryByteOrderCheck;
      syscall-model-boundary = syscallModelBoundaryCheck;
      explicit-trace-kinds = explicitTraceKindsCheck;
      repeatable-materialized-traces = repeatableMaterializedTracesCheck;
      explicit-trace-addresses = explicitTraceAddressesCheck;
      trace-environment-identity = traceEnvironmentIdentityCheck;
      unknown-trace-environment = unknownTraceEnvironmentCheck;
      materialized-snapshot-serialization = materializedSnapshotSerializationCheck;
      qemu-snapshot-trace-construction = qemuSnapshotTraceConstructionCheck;
      plugin-framed-transport = pluginFramedTransportCheck;
      plugin-whole-program-terminal-evidence = pluginWholeProgramTerminalEvidenceCheck;
      plugin-structured-validation-report = pluginStructuredReportCheck;
      gdb-set-fs-successor = gdbSetFsSuccessorCheck;
      gdb-segment-selector-width = gdbSegmentSelectorWidthCheck;
      plugin-register-cache = pluginRegisterCacheCheck;
      plugin-connection-ownership = pluginConnectionOwnershipCheck;
      uv-sync-lock-integrity = uvSyncLockIntegrityCheck;
      gdb-launch-encoding = gdbLaunchEncodingCheck;
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
      recorded-fcntl-replay = recordedFcntlReplayCheck;
      recorded-tiocgwinsz-replay = recordedTiocgwinszReplayCheck;
      qemu-syscall-post-boundary = qemuSyscallPostBoundaryCheck;
      fixed-recorded-anonymous-mmap = fixedRecordedAnonymousMmapCheck;
      translated-initial-brk-query = translatedInitialBrkQueryCheck;
      recorded-syscall-clobber-replay = recordedSyscallClobberReplayCheck;
      recorded-arch-prctl-replay = recordedArchPrctlReplayCheck;
      x86-replay-fail-closed = x86ReplayFailClosedCheck;
      x86-nested-output-replay = x86NestedOutputReplayCheck;
      x86-signal-frame-abi = x86SignalFrameAbiCheck;
      interrupted-syscall-signal-frame = interruptedSyscallSignalFrameCheck;
      relocated-x86-signal-frame = relocatedX86SignalFrameCheck;
      non-siginfo-signal-frame = nonSiginfoSignalFrameCheck;
      partial-x86-signal-state-replay = partialX86SignalStateReplayCheck;
      x86-signal-return = x86SignalReturnCheck;
      replay-effect-coverage = replayEffectCoverageCheck;
      qemu-replay-start-synchronization = qemuReplayStartSynchronizationCheck;
      x86-startup-without-vdso = absentVdsoStartupReplayCheck;
      protected-entry-startup-replay = protectedEntryStartupReplayCheck;
      recorded-x86-initial-stack = recordedX86InitialStackCheck;
      qemu-structured-replay-report = qemuStructuredReplayReportCheck;
      non-destructive-qemu-reporting = nonDestructiveQemuReportingCheck;
      bounded-diagnostic-rendering = boundedDiagnosticRenderingCheck;
      current-diagnostic-stream = currentDiagnosticStreamCheck;
      memory-mismatch-localization = memoryMismatchLocalizationCheck;
      qemu-whole-program-collection = qemuWholeProgramCollectionCheck;
      whole-program-terminal-acceptance = wholeProgramTerminalAcceptanceCheck;
      terminal-trace-reporting = terminalTraceReportingCheck;
      rr-qemu-run-manifest = rrQemuRunManifestCheck;
      rr-qemu-smoke-harness = rrQemuSmokeHarnessCheck;
      whole-program-smoke = wholeProgramSmokeCheck;
      native-terminal-outcome = nativeTerminalOutcomeCheck;
      qemu-terminal-outcome = qemuTerminalOutcomeCheck;
      qemu-fatal-signal-termination = qemuFatalSignalTerminationCheck;
      native-terminal-observation-harness = nativeTerminalObservationCheck;
      native-terminal-observation-fixtures = nativeTerminalFixtures;
      scheduler-quarantine = schedulerQuarantineCheck;
      shared-snapshot-planner = sharedSnapshotPlannerCheck;
      adaptive-successor-source-planning = adaptiveSuccessorSourcePlanningCheck;
      linear-successor-planning = linearSuccessorPlanningCheck;
      bounded-no-skip-collector-planning = boundedNoSkipCollectorPlanningCheck;
      qemu-xmm-read-transport = xmmReadTransportCheck;
      gdb-wide-registers = gdbWideRegisterCheck;
      wide-vector-observation-capability = wideVectorObservationCapabilityCheck;
      declared-validation-cutpoints = declaredValidationCutpointsCheck;
      narrow-vector-observation = narrowVectorObservationCheck;
      narrow-vector-dependency-planning = narrowVectorDependencyPlanningCheck;
      narrow-vector-validation-evaluation = narrowVectorValidationEvaluationCheck;
      qemu-mmx-observation = qemuMmxObservationCheck;
      undefined-shift-flag-semantics = undefinedShiftFlagSemanticsCheck;
      wide-register-state-serialization = wideRegisterStateSerializationCheck;
      x86-eflags-observation = x86EflagsObservationCheck;
      code-naming-policy = codeNamingPolicyCheck;
      flake-source-boundary = flakeSourceBoundaryCheck;
      qemu-sparse-memory-cache = qemuSparseMemoryCacheCheck;
      qemu-scripted-state-collection = qemuScriptedStateCollectionCheck;
      fresh-file-hashes = freshFileHashesCheck;
      trace-schema-v2 = traceSchemaV2Check;
      trace-schema-v3 = traceSchemaV3Check;
      json-trace-roundtrip = jsonTraceRoundtripCheck;
      msgpack-trace-roundtrip = msgpackTraceRoundtripCheck;
      legacy-trace-readers = legacyTraceReadersCheck;
      box64-adjacent-flags = box64AdjacentFlagsCheck;
      box64-flag-observation-validity = box64FlagObservationValidityCheck;
      box64-fused-push-cutpoint = box64FusedPushCutpointCheck;
      trace-structural-validation = traceStructuralValidationCheck;
      typed-empty-traces = typedEmptyTracesCheck;
      concrete-pc-diagnostic = concretePcDiagnosticCheck;
      matching-failure-diagnostics = matchingFailureDiagnosticsCheck;
      repeated-transform-decoding = repeatedTransformDecodingCheck;
      trace-completion-persistence = traceCompletionPersistenceCheck;
      transform-serialization-validation-reuse = transformSerializationValidationReuseCheck;
      persistence-adversarial-inputs = persistenceAdversarialInputsCheck;
      transition-boundary-matching = transitionBoundaryMatchingCheck;
      indexed-destination-matching = indexedDestinationMatchingCheck;
      deferred-memory-alias-resolution = deferredMemoryAliasCheck;
      opt-in-unmatched-transform-skipping = optInUnmatchedTransformSkippingCheck;
      complete-cutpoint-source-snapshot = completeCutpointSourceSnapshotCheck;
      linear-cutpoint-composition = linearCutpointCompositionCheck;
      guest-signal-localization = guestSignalLocalizationCheck;
      terminal-transition-validation = terminalTransitionValidationCheck;
      adaptive-cutpoint-composition = adaptiveCutpointCompositionCheck;
      comparison-shape-diagnostics = comparisonShapeDiagnosticsCheck;
      comparison-error-classification = comparisonErrorClassificationCheck;
      defined-register-output-validation = definedRegisterOutputValidationCheck;
      shared-transition-matcher = sharedTransitionMatcherCheck;
      canonical-register-output-cache = canonicalRegisterOutputCacheCheck;
      symbolic-composition = symbolicCompositionCheck;
      bounded-long-cutpoint-composition = boundedLongCutpointCompositionCheck;
      iterative-symbolic-dag-processing = iterativeSymbolicDagProcessingCheck;
      fp32-to-fp64 = fp32ToFp64Check;
      explicit-trace-gaps = explicitTraceGapsCheck;
      target-environment-symbols = targetEnvironmentSymbolsCheck;
      x86-extended-register-aliases = x86ExtendedRegisterAliasesCheck;
      aarch64-deterministic-replay = aarch64DeterministicReplayCheck;
      aarch64-signal-return-dispatch = aarch64SignalReturnDispatchCheck;
      signal-extra-registers = signalExtraRegistersCheck;
      rr-standalone-lldb-compatibility =
        rrStandaloneLldbCompatibilityCheck;
    } // pkgs.lib.optionalAttrs (system == "x86_64-linux") {
      rr-qemu-file-read-fixture = x86FileReadFixture;
    } // pkgs.lib.optionalAttrs (system == "aarch64-linux") {
      aarch64-native-rr-tool = aarch64NativeRrToolCheck;
    };
  });
}
