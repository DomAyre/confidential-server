"""
attestation
-----------

Python bindings for the SNP attestation C core.
Provides high-level functions wrapping the C executables.
"""
# Standard imports
import os
import shutil
import subprocess

# Import error constants and messages from generated file
from ._error_constants import *
from ._error_constants import _ERROR_MESSAGES, __all__ as _error_constants_all

class AttestationError(Exception):
    """Exception raised when attestation verification fails."""
    
    def __init__(self, error_code: int, message: str = None):
        self.error_code = error_code
        if message is None:
            message = _ERROR_MESSAGES.get(error_code, f"Unknown error (code {error_code})")
        self.message = message
        super().__init__(f"Attestation failed (code {error_code}): {message}")
    
    def __str__(self):
        return self.message

# Locate executables with fallback for editable installs
_pkg_dir = os.path.dirname(__file__)
def _locate_exec(name: str) -> str:
    # 1) bundled next to this __init__.py
    candidate = os.path.join(_pkg_dir, name)
    if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
        return candidate
    # 2) on PATH
    path = shutil.which(name)
    if path:
        return path
    # 3) in project build/ directory relative to this module (dev mode)
    p = _pkg_dir
    while True:
        build_path = os.path.join(p, 'build', name)
        if os.path.isfile(build_path) and os.access(build_path, os.X_OK):
            return build_path
        parent = os.path.dirname(p)
        if parent == p:
            break
        p = parent
    raise FileNotFoundError(
        f"Executable '{name}' not found in {candidate}, PATH, or project build directory"
    )

_exe_get_att = _locate_exec('get_attestation_ccf')
_exe_verify = _locate_exec('verify_attestation_ccf')
_exe_snp_version = _locate_exec('get_snp_version')

__all__ = [
    'get_attestation_ccf',
    'verify_attestation_ccf',
    'verify_attestation_ccf_detailed',
    'get_snp_version',
    'AttestationError',
] + _error_constants_all  # Add error constants from _error_constants

def get_attestation_ccf(report_data: str = '') -> str:
    """
    Retrieve a SNP attestation JSON string.

    :param report_data: Optional report_data string (max 64 bytes).
    :returns: JSON string with evidence and endorsements.
    """
    args = [_exe_get_att]
    if report_data:
        args.append(report_data)
    result = subprocess.run(args, capture_output=True, text=True, check=True)
    return result.stdout

def verify_attestation_ccf(ccf_attestation: str, report_data: str = '', security_policy_b64: str = '', raise_on_error: bool = False) -> bool:
    """
    Verify a SNP attestation JSON string.

    :param ccf_attestation: JSON string produced by get_attestation.
    :param report_data: Optional report_data string used in attestation.
    :param security_policy_b64: Base64-encoded security policy.
    :param raise_on_error: If True, raises AttestationError with specific error details on failure.
                          If False, returns False on any failure (backward compatible behavior).
    :returns: True if verification succeeds, False otherwise (when raise_on_error=False).
    :raises: AttestationError with specific error code and message (when raise_on_error=True).
    """
    args = [_exe_verify]
    args.append(ccf_attestation)
    if report_data:
        args.extend(['--report-data', report_data])
    if security_policy_b64:
        args.extend(['--security-policy-b64', security_policy_b64])

    result = subprocess.run(args)
    
    if result.returncode == ATTESTATION_SUCCESS:
        return True
    elif raise_on_error:
        raise AttestationError(result.returncode)
    else:
        return False

def verify_attestation_ccf_detailed(ccf_attestation: str, report_data: str = '', security_policy_b64: str = '') -> int:
    """
    Verify a SNP attestation JSON string and return detailed error code.

    :param ccf_attestation: JSON string produced by get_attestation.
    :param report_data: Optional report_data string used in attestation.
    :param security_policy_b64: Base64-encoded security policy.
    :returns: Error code (ATTESTATION_SUCCESS on success, specific error code on failure).
    """
    args = [_exe_verify]
    args.append(ccf_attestation)
    if report_data:
        args.extend(['--report-data', report_data])
    if security_policy_b64:
        args.extend(['--security-policy-b64', security_policy_b64])

    result = subprocess.run(args)
    return result.returncode

def get_snp_version() -> str:
    """
    Query the SNP version of the current environment.

    :returns: Version string, e.g., "SNP Version: Virtual".
    """
    result = subprocess.run([_exe_snp_version], capture_output=True, text=True, check=True)
    return result.stdout.strip()