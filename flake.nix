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
        "src/focaccia/cli.py"
        "src/focaccia/compare.py"
        "src/focaccia/match.py"
        "src/focaccia/native/lldb_target.py"
        "src/focaccia/native/tracer.py"
        "src/focaccia/parser.py"
        "src/focaccia/qemu/validation_server.py"
        "src/focaccia/reproducer.py"
        "src/focaccia/snapshot.py"
        "src/focaccia/tools/capture_transforms.py"
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
    };
  });
}
