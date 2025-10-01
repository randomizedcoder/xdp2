# Improving ./src/configure script

The ./src/configure script is a bash script that is used to configure the build of the project.

Currently it does not check for the presence of python3 scapy.

Maybe configure could test of scapy by doing something like "python3 -c "import scapy.all; print('scapy OK')""

# Plan to add check_scapy function to ./src/configure script

## Analysis of existing check functions

The configure script already has several check functions that follow a consistent pattern:

1. **check_prog()** - Simple program availability check using `command -v`
2. **check_libpcap()** - C library check by compiling a test program
3. **check_boostwave()** - C++ library check by compiling a test program
4. **check_boostthread()** - C++ library check by compiling a test program
5. **check_boostsystem()** - C++ library check by compiling a test program
6. **check_boostfilesystem()** - C++ library check by compiling a test program
7. **check_clang_lib()** - C++ library check by compiling a test program
8. **check_python()** - Python C API check by compiling a test program

## Proposed check_scapy function

For scapy, we need to check if the Python scapy module is available and importable. Since scapy is a Python package (not a C/C++ library), we should use a Python-based approach rather than compiling C/C++ code.

### Implementation approach:

```bash
check_scapy()
{
    echo -n "Checking for scapy... "
    python3 -c "import scapy.all; print('scapy OK')" >/dev/null 2>&1
    case $? in
        0)  echo "yes"
            echo "HAVE_SCAPY:=y" >> $CONFIG
            ;;
        *)  echo "no"
            echo "ERROR: scapy is required but not found!" 1>&2
            echo "Please install scapy: ( pip3 install scapy | apt install python3-scapy )" 1>&2
            exit 1
            ;;
    esac
}
```

### Integration points:

1. **Add function definition** - Insert the `check_scapy()` function after the existing check functions (around line 196, after `check_python()`)

2. **Add function call** - Add `check_scapy` to the list of check functions called in the main execution flow (around line 456, after `check_python`)

3. **Makefile integration** - The `HAVE_SCAPY` variable will be available in the generated `config.mk` file for use in Makefiles

### Alternative approaches considered:

1. **Using check_prog()** - Not suitable since scapy is a Python module, not a standalone program
2. **C/C++ compilation test** - Not applicable since scapy is pure Python
3. **pkg-config approach** - Not available for Python packages like scapy

## Python version modernization

The script currently uses `PYTHON_VER=3` variable, which appears to be a legacy from iproute2's migration from Python 2 to Python 3. Since Python 2 is end-of-life and Python 3 is the only viable option today, we should modernize the script to assume Python 3.

### Changes needed to remove PYTHON_VER variable:

1. **Remove PYTHON_VER declaration** - Delete line 14: `PYTHON_VER=3`

2. **Update check_python() function** - Replace `python$PYTHON_VER` with `python3`:
   ```bash
   # Current (line 187):
   `$PKG_CONFIG --cflags --libs python$PYTHON_VER-embed`

   # Updated:
   `$PKG_CONFIG --cflags --libs python3-embed`
   ```

3. **Update config.mk generation** - Replace `python$PYTHON_VER` with `python3`:
   ```bash
   # Current (lines 331-334):
   echo -n 'CFLAGS_PYTHON=`$(PKG_CONFIG) $(PATH_ARG)' >> $CONFIG
   echo ' --cflags python$(PYTHON_VER)-embed`' >> $CONFIG
   echo -n 'LDFLAGS_PYTHON=`$(PKG_CONFIG) $(PATH_ARG) --libs' >> $CONFIG
   echo ' python$(PYTHON_VER)-embed`' >> $CONFIG

   # Updated:
   echo -n 'CFLAGS_PYTHON=`$(PKG_CONFIG) $(PATH_ARG)' >> $CONFIG
   echo ' --cflags python3-embed`' >> $CONFIG
   echo -n 'LDFLAGS_PYTHON=`$(PKG_CONFIG) $(PATH_ARG) --libs' >> $CONFIG
   echo ' python3-embed`' >> $CONFIG
   ```

4. **Update PYTHON variable** - Replace `python$PYTHON_VER` with `python3`:
   ```bash
   # Current (line 444):
   echo "PYTHON := python$PYTHON_VER" >> $CONFIG

   # Updated:
   echo "PYTHON := python3" >> $CONFIG
   ```

5. **Remove PYTHON_VER from config.mk** - Delete line 323:
   ```bash
   # Remove this line:
   echo "PYTHON_VER:=$PYTHON_VER" >> $CONFIG
   ```

6. **Update command line option** - Remove `--python-ver` option from usage and argument parsing:
   - Remove from usage() function (line 280)
   - Remove from argument parsing (lines 304-305)

### Benefits:

- Follows the existing pattern of dependency checking
- **Makes scapy a hard requirement** - configure fails with clear error message if scapy is missing
- Provides clear installation instructions when scapy is missing
- Removes legacy Python 2 compatibility code
- Simplifies the script by removing unnecessary version variables
- Uses modern Python 3 assumption throughout

### Usage in Makefiles:

After implementation, Makefiles can use:
```makefile
# Since scapy is now a hard requirement, HAVE_SCAPY will always be 'y'
# if configure succeeds, so this check is mainly for documentation/clarity
ifeq ($(HAVE_SCAPY),y)
    # Build scapy-dependent targets
    SCAPY_TARGETS = some_scapy_tool
else
    # This should never happen since configure fails without scapy
    $(error scapy is required but not available)
endif
```

## Summary of all changes needed:

1. **Add check_scapy() function** (after line 195)
2. **Call check_scapy()** (after line 456)
3. **Remove PYTHON_VER=3** (line 14)
4. **Update check_python()** (line 187)
5. **Update config.mk generation** (lines 331-334)
6. **Update PYTHON variable** (line 444)
7. **Remove PYTHON_VER from config.mk** (line 323)
8. **Remove --python-ver option** (lines 280, 304-305)

This modernization makes the script cleaner, removes legacy Python 2 support, and ensures scapy is available before proceeding with the build.

