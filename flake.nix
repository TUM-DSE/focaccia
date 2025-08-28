{
	description = "Focaccia: A Symbolic Tester for QEMU";

	inputs = {
		self.submodules = true;

		nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

		nixpkgs-qemu-60.url = "github:nixos/nixpkgs/f8f124009497b3f9908f395d2533a990feee1de8";

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
	};

	outputs = inputs@{
		self,
		uv2nix,
		nixpkgs,
		flake-utils,
		pyproject-nix,
		pyproject-build-systems,
		...
	}:
	flake-utils.lib.eachSystem [ "x86_64-linux" "aarch64-linux" ] (system:
	let
		qemu-60 = inputs.nixpkgs-qemu-60.qemu;

		# Refine nixpkgs used in flake to system arch
		pkgs = import nixpkgs {
			inherit system;
		};

		musl-pkgs = import nixpkgs {
			inherit system;
			crossSystem = {
				config = "x86_64-unknown-linux-musl";
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
						(old.src + "/miasm/__init__.py")
					];
				};
			});

			cpuid = super.cpuid.overrideAttrs (old: {
				nativeBuildInputs = (old.nativeBuildInputs or []) ++ [ self.setuptools ];
			});

			focaccia = super.focaccia.overrideAttrs (old: {
				nativeBuildInputs = (old.nativeBuildInputs or []) ++
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
	in rec {
		# Default package just builds Focaccia
		packages = rec {
			focaccia = pythonEnv;
			dev = pythonDevEnv;

			default = focaccia;
		};

		# Default app is just Focaccia
		apps = {
			default = {
				type = "app";
				program = "${packages.default}/bin/focaccia";
			};

			convert-log = {
				type = "app";
				program = "${packages.default}/bin/convert";
			};

			capture-transforms = {
				type = "app";
				program = "${packages.default}/bin/capture-transforms";
			};

			validate-qemu = {
				type = "app";
				program = "${packages.default}/bin/validate-qemu";
			};

			# Useful for synchronize the uv lockfile
			uv-sync = {
				type = "app";
				program = "${pkgs.writeShellScriptBin "uv-sync" ''
					set -euo pipefail
					exec ${pkgs.uv}/bin/uv sync
				''}/bin/uv-sync";
			};
		};

		# Developer shell that includes Focaccia and QEMU
		devShells = {
			default = pkgs.mkShell {
				packages = [
					packages.dev
					pkgs.uv
					pkgs.gdb
					pkgs.git
				];

				env = uvEnv;
				shellHook = uvShellHook;
			};

			glibc = pkgs.mkShell {
				packages = [
					packages.dev
					pkgs.uv
					pkgs.gdb
					pkgs.gcc
					pkgs.glibc.all
				];

				env = uvEnv;
				shellHook = uvShellHook;
			};

			musl = pkgs.mkShell {
				packages = [
					packages.dev
					pkgs.uv
					pkgs.gdb
					musl-pkgs.gcc
					musl-pkgs.pkg-config
				];

				env = uvEnv;
				shellHook = uvShellHook;
			};
		};
	});
}

