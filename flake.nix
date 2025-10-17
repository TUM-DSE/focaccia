{
	description = "Focaccia: A Symbolic Tester for QEMU";

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
		# Refine nixpkgs used in flake to system arch
		pkgs = import nixpkgs {
			inherit system;
		};

		musl-pkgs = import nixpkgs {
			inherit system;
			crossSystem = {
				config = "${system}-musl";
			};
		};

		# Pin Python version
		python = pkgs.python312;

		# Define workspace root and load uv workspace metadata
		workspace = uv2nix.lib.workspace.loadWorkspace { workspaceRoot = ./.; };

		# Create an overlay for Nix that includes extracted Python packages declared as dependencies
		# in uv
		overlay = workspace.mkPyprojectOverlay { sourcePreference = "wheel"; };

		editableOverlay = workspace.mkEditablePyprojectOverlay {
			# Use environment variable
			root = "$REPO_ROOT";

			members = [ "focaccia" "miasm" ];
		};

        # Box64
        zydis-shared-object = pkgs.zydis.overrideAttrs (oldAttrs: {
			cmakeFlags = (oldAttrs.cmakeFlags or []) ++ [
			  "-DZYDIS_BUILD_SHARED_LIB=ON"
			];
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

			nativeBuildInputs = with pkgs; [
				cmake
				python
				pkg-config
				zydis-shared-object
			];

			cmakeFlags = [
				"-DDYNAREC=ON"
				"-DHAVE_TRACE=ON"
			];

			patches = [ ./fix-box64.patch ];
			installPhase = ''
				runHook preInstall
				mkdir -p $out/bin
				cp box64 $out/bin/
				runHook postInstall
			'';
        };

		# Another overlay layer for flake-specific overloads
		# This might be needed because uv does not have sufficient metadata
		# Here, uv does include metadata about build systems used by each dependency
		# Ergo we need to add a nativeBuildInput to miasm because it depends on setuptools for its
		# installation
		pyprojectOverrides = self: super: {
			miasm = super.miasm.overrideAttrs (old: {
				nativeBuildInputs = (old.nativeBuildInputs or []) ++ [ self.setuptools ];
			});

			cpuid = super.cpuid.overrideAttrs (old: {
				nativeBuildInputs = (old.nativeBuildInputs or []) ++ [ self.setuptools ];
			});

			focaccia = super.focaccia.overrideAttrs (old: {
				buildInputs = (old.buildInputs or []) ++ [ pkgs.lldb ];

				postInstall = (old.postInstall or "") + ''
					set -eu

					target="$out/${python.sitePackages}" 
					src="$(${pkgs.lldb}/bin/lldb -P)"

					mkdir -p "$target"

					# Copy the lldb Python package (and the native extension)
					if [ -d "$src/lldb" ]; then
						ln -sTf "$src/lldb" "$target/lldb"
					fi

					# Optional: some builds ship a top-level helper
					if [ -f "$src/LLDB.py" ]; then
						cp -a "$src/LLDB.py" "$target/"
					fi
				'';
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

				postInstall = (old.postInstall or "") + ''
					set -eu

					target="$out/${python.sitePackages}" 
					src="$(${pkgs.lldb}/bin/lldb -P)"

					mkdir -p "$target"

					# Copy the lldb Python package (and the native extension)
					if [ -h "$src/lldb" ]; then
						ln -sT "$src/lldb" "$target/lldb"
					fi

					# Optional: some builds ship a top-level helper
					if [ -f "$src/LLDB.py" ]; then
						cp -a "$src/LLDB.py" "$target/"
					fi
				'';
			});
		};

		# Build a set of Python packages
		# The call to callPackage here uses the base package set from pyproject.nix
		# We inherit the Python version to ensure that the packages have the same version
		#
		# The overrideScope here customizes the Python package set with an overlay defined by the
		# composition of three overlay functions
		pythonSet = (pkgs.callPackage pyproject-nix.build.packages { inherit python; }).
					 overrideScope (pkgs.lib.composeManyExtensions [
						 pyproject-build-systems.overlays.default
						 overlay
						 pyprojectOverrides 
					 ]);

		pythonSetEditable = pythonSet.overrideScope (
			pkgs.lib.composeManyExtensions [
				editableOverlay
				pyprojectOverridesEditable
			]
		);

		 # Create a Python venv with the default dependency group
		 pythonEnv = pythonSet.mkVirtualEnv "focaccia-env" workspace.deps.default;

		 # Create a Python venv with the default dependency group
		 pythonDevEnv = pythonSetEditable.mkVirtualEnv "focaccia-env" workspace.deps.all;

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
			if ! ${pkgs.git} submodule status --recursive >/dev/null 2>&1; then
				printf 'Error: git submodules not initialized correctly, build cannot proceed\n'
				printf 'Run git submodule update --init --recursive and then rebuild\n'
				exit 2
			fi
		'';

		gdbInternal = pkgs.gdb.override { python3 = python; };
		rr = pkgs.rr.overrideAttrs (old: {
			pname = "focaccia-rr";
			version = "git";
			src = ./rr;
		});

		redis-flags = " -mno-xsave -mno-xsaveopt -mno-xsavec -mno-xsaves -mno-avx" +
					  " -mno-avx2 -mno-avx512f";
		musl-redis-nocheck = musl-pkgs.pkgsStatic.redis.overrideAttrs (old: rec {
			doCheck = false;
			env = (old.env or {}) // {
				NIX_CFLAGS_COMPILE = (old.env.NIX_CFLAGS_COMPILE or "") + redis-flags;
			};
			makeFlags = (old.makeFlags or []) ++ [ "CFLAGS=${env.NIX_CFLAGS_COMPILE}" ];
		});
	in rec {
		# Default package just builds Focaccia
		packages = rec {
			focaccia = pythonEnv.overrideAttrs (old: {
				buildPhase = ''
					${checkSubmodulesInitialized}
					${old.buildPhase or ""}
				'';
				propagatedBuildInputs = (old.propagatedBuildInputs or []) ++ [ pkgs.lldb ];
			});

			dev = pythonDevEnv.overrideAttrs (old: {
				buildPhase = ''
					${checkSubmodulesInitialized}
					${old.buildPhase or ""}
				'';
				propagatedBuildInputs = (old.propagatedBuildInputs or []) ++ [ 
					pkgs.uv
					pkgs.lldb 
					gdbInternal # TODO keep this internal somehow
				];
			});

			qemu-plugin = qemu-submodule.packages.${system}.default;

			default = focaccia;
		};

		# Default app is just Focaccia
		apps = {
			default = {
				type = "app";
				program = "${packages.focaccia}/bin/focaccia";
				meta = {
					description = "Translation validator for user-mode emulators";
				};
			};

			convert-log = {
				type = "app";
				program = "${packages.focaccia}/bin/convert";
				meta = {
					description = "Convert emulator debug logs to format accepted by Focaccia";
				};
			};

			capture-transforms = {
				type = "app";
				program = "${packages.focaccia}/bin/capture-transforms";
				meta = {
					description = "Capture symbolic equations describing program execution";
				};
			};

			validate-qemu = {
				type = "app";
				program = let
					wrapper = pkgs.writeShellScriptBin "validate-qemu" ''
						exec ${packages.focaccia}/bin/validate-qemu --gdb "${gdbInternal}/bin/gdb" "$@"
					'';
				in "${wrapper}/bin/validate-qemu";
				meta = {
					description = "Validate QEMU translations using symbolic equations";
				};
			};

			# Useful for synchronize the uv lockfile
			uv-sync = {
				type = "app";
				program = "${pkgs.writeShellScriptBin "uv-sync" ''
					set -euo pipefail
					${pkgs.uv}/bin/uv sync
					sed -i '/riscv/d' uv.lock
				''}/bin/uv-sync";
				meta = {
					description = "Sync uv python packages";
				};
			};
		};

		# Developer shell that includes Focaccia and QEMU
		devShells = {
			default = pkgs.mkShell {
				packages = [ packages.dev ];

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

			musl = pkgs.mkShell {
				packages = [
					packages.dev
					musl-pkgs.gcc
					musl-pkgs.pkg-config
				];

				hardeningDisable = [ "pie" ];

				env = uvEnv;
				shellHook = uvShellHook;
			};

			musl-box64 = pkgs.mkShell {
				packages = [
					packages.dev
					musl-pkgs.gcc
					musl-pkgs.pkg-config
                    box64-patched
				];

				hardeningDisable = [ "pie" ];

				env = uvEnv;
				shellHook = uvShellHook + ''
                  export BOX64_TRACE=1
                  export BOX64_DYNAREC_TRACE=1
                  export BOX64_DYNAREC_DF=0
                  export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:${zydis-shared-object}/lib
                '';
			};

			musl-extra = pkgs.mkShell {
				packages = [
					packages.dev
					rr
					pkgs.capnproto
					musl-pkgs.gcc
					musl-pkgs.pkg-config
				];

				hardeningDisable = [ "pie" ];

				env = uvEnv;
				shellHook = uvShellHook;
			};

			musl-all = pkgs.mkShell {
				packages = [
					packages.dev
					pkgs.rr
					pkgs.capnproto
					musl-pkgs.gcc
					musl-pkgs.pkg-config
					musl-redis-nocheck
				];

				hardeningDisable = [ "pie" ];

				env = uvEnv;
				shellHook = uvShellHook;
			};
		};

		checks = {
			focaccia-tests = pkgs.stdenv.mkDerivation {
				name = "focaccia-tests";
				src = ./.;

				doCheck = true;
				dontBuild = true;

				nativeCheckInputs = [ packages.dev pythonDevEnv ];

				checkPhase = ''
					set -euo pipefail
					export REPO_ROOT="$PWD"
					${packages.dev}/bin/python -m 'pytest' -q tests
					touch $out
				'';

				env = uvEnv;
				shellHook = uvShellHook;
			};
		};
	});
}

