# SheBangs

## The Problem

XDP2 contains shell scripts with hardcoded shebang lines like `#!/bin/bash`. In Nix build environments, these paths don't exist because Nix uses isolated environments where `/bin/bash` is not available.

## Files with Hardcoded Shebangs

The following XDP2 files contain hardcoded `/bin/bash` shebangs:
- `./src/configure`
- `./src/test/parser/run-tests.sh`
- `./platforms/default/src/configure`

## The Solution: Fix at Build Time with substituteInPlace

We fixed the shebang issue by using Nix's `substituteInPlace` function in the `patchPhase` to replace hardcoded shebangs with Nix store paths.

**Implementation in flake.nix:**
```nix
patchPhase = ''
  cd src
  substituteInPlace configure --replace '#!/bin/bash' '#!${pkgs.bash}/bin/bash'
  substituteInPlace test/parser/run-tests.sh --replace '#! /bin/bash' '#!${pkgs.bash}/bin/bash'
'';
```

**Files Updated:**
- `./src/configure`: `#!/bin/bash` → `#!${pkgs.bash}/bin/bash`
- `./src/test/parser/run-tests.sh`: `#! /bin/bash` → `#!${pkgs.bash}/bin/bash`
- `./platforms/default/src/configure`: `#!/bin/bash` → `#!${pkgs.bash}/bin/bash`

## Why substituteInPlace Works

- **Build-time patching**: Fixes shebangs during the Nix build process
- **Nix store paths**: Uses actual Nix store paths for bash interpreter
- **Reliable**: Works consistently across different Nix environments
- **No source changes**: Keeps original source files unchanged
- **Automatic**: Handles the patching as part of the build process
