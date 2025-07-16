# Avoiding Error Definition Duplication

This document explains how the Python binding avoids duplicating error definitions from the C library.

## Problem

Previously, error codes and messages were defined in two places:
1. C library: `src/core/lib/attestation_errors.h` and `src/core/lib/attestation_errors.c`
2. Python binding: `src/bindings/python/attestation/__init__.py`

This created maintenance overhead as changes to errors required updates in both places.

## Solution

The Python binding now automatically generates error constants from the C source files:

1. **Single Source of Truth**: Error codes and messages are defined only in the C library
2. **Auto-generation**: A script (`generate_error_constants.py`) parses the C header and source files
3. **Build Integration**: The build process automatically generates `_error_constants.py` during package build
4. **Import Strategy**: The Python module imports constants from the generated file

## Implementation Details

### Generator Script (`generate_error_constants.py`)
- Parses `attestation_errors.h` to extract `#define` constants
- Parses `attestation_errors.c` to extract error messages from the switch statement
- Generates a Python module with constants and error message dictionary

### Build Integration (`setup.py`)
- Custom build command runs the generator script before building the package
- Generated file is created at build time, not stored in version control

### Import Strategy (`__init__.py`)
- Uses `from ._error_constants import *` to import all constants
- Imports error message dictionary for use in `AttestationError` class
- Maintains full backward compatibility

## Benefits

1. **Single Maintenance Point**: Errors only need to be defined in C source files
2. **Automatic Sync**: Python constants are always in sync with C definitions
3. **Backward Compatibility**: Existing Python code continues to work unchanged
4. **Type Safety**: Python constants have the same values as C constants
5. **Human-Readable Messages**: Error messages are automatically extracted from C source

## Usage

The API remains unchanged for users:

```python
import attestation

# Constants are still available
if error_code == attestation.ATTESTATION_ERROR_REPORT_DATA_MISMATCH:
    print("Report data mismatch")

# Exception handling still works
try:
    attestation.verify_attestation_ccf(data, raise_on_error=True)
except attestation.AttestationError as e:
    print(f"Error {e.error_code}: {e.message}")
```

## Files Modified

- `setup.py`: Added error constant generation to build process
- `__init__.py`: Changed to import from generated constants file
- `.gitignore`: Added generated file to ignore list
- `generate_error_constants.py`: New script to generate constants from C source

## Files Generated (Not in Git)

- `_error_constants.py`: Auto-generated Python constants and messages