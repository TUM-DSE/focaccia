# Synthetic RR v85 fixtures

These are minimal parser fixtures generated directly from Focaccia's packaged
RR trace-version-85 Cap'n Proto schema. They are **not** RR recordings and no
program, debugger, emulator, or RR process is run to create them.

- `empty-x86/` contains a valid header and empty substreams.
- `x86-syscall/` contains a paired syscall, two memory writes with multiple
  holes, multiple compressed blocks, one register-less bookkeeping event, all
  four task variants (including detach), and mappings whose frame counts include
  a gap.
- `aarch64-syscall/` contains exact RR AArch64 register payloads for a paired
  syscall.

Regenerate through the flake only:

```sh
nix develop -c python tests/fixtures/deterministic/generate.py
```

The schema wire ID is `0xcaa0b1486c12c629`, and the compatible RR trace
version is 85.
