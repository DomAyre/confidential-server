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

# Error codes from attestation_errors.h
ATTESTATION_SUCCESS = 0
ATTESTATION_ERROR_GENERIC = 1
ATTESTATION_ERROR_INVALID_INPUT = 2
ATTESTATION_ERROR_MEMORY_ALLOCATION = 3
ATTESTATION_ERROR_CERT_CHAIN_INVALID = 10
ATTESTATION_ERROR_AMD_ROOT_KEY_MISMATCH = 11
ATTESTATION_ERROR_SNP_SIGNATURE_INVALID = 12
ATTESTATION_ERROR_REPORT_DATA_MISMATCH = 20
ATTESTATION_ERROR_SECURITY_POLICY_DECODE = 30
ATTESTATION_ERROR_SECURITY_POLICY_HASH = 31
ATTESTATION_ERROR_HOST_DATA_MISMATCH = 32
ATTESTATION_ERROR_ENDORSEMENT_ISSUER_MISMATCH = 40
ATTESTATION_ERROR_ENDORSEMENT_FEED_MISMATCH = 41
ATTESTATION_ERROR_ENDORSEMENT_SVN_TOO_LOW = 42
ATTESTATION_ERROR_ENDORSEMENT_CERT_CHAIN_INVALID = 43
ATTESTATION_ERROR_ENDORSEMENT_SIGNATURE_INVALID = 44
ATTESTATION_ERROR_ENDORSEMENT_LAUNCH_MEASUREMENT_EXTRACT = 45
ATTESTATION_ERROR_ENDORSEMENT_LAUNCH_MEASUREMENT_MISMATCH = 46

# Error messages
_ERROR_MESSAGES = {
    ATTESTATION_SUCCESS: "Success",
    ATTESTATION_ERROR_GENERIC: "Generic error",
    ATTESTATION_ERROR_INVALID_INPUT: "Invalid input parameters",
    ATTESTATION_ERROR_MEMORY_ALLOCATION: "Memory allocation failed",
    ATTESTATION_ERROR_CERT_CHAIN_INVALID: "Certificate chain signature validation failed",
    ATTESTATION_ERROR_AMD_ROOT_KEY_MISMATCH: "AMD root public key does not match certificate chain",
    ATTESTATION_ERROR_SNP_SIGNATURE_INVALID: "SNP report signature verification failed",
    ATTESTATION_ERROR_REPORT_DATA_MISMATCH: "SNP report data does not match expected value",
    ATTESTATION_ERROR_SECURITY_POLICY_DECODE: "Failed to decode security policy base64",
    ATTESTATION_ERROR_SECURITY_POLICY_HASH: "Failed to compute security policy hash",
    ATTESTATION_ERROR_HOST_DATA_MISMATCH: "SNP report host data does not match security policy hash",
    ATTESTATION_ERROR_ENDORSEMENT_ISSUER_MISMATCH: "Endorsement issuer does not match expected value",
    ATTESTATION_ERROR_ENDORSEMENT_FEED_MISMATCH: "Endorsement feed does not match expected value",
    ATTESTATION_ERROR_ENDORSEMENT_SVN_TOO_LOW: "Endorsement SVN does not meet minimum requirement",
    ATTESTATION_ERROR_ENDORSEMENT_CERT_CHAIN_INVALID: "Endorsement certificate chain is invalid",
    ATTESTATION_ERROR_ENDORSEMENT_SIGNATURE_INVALID: "COSE_Sign1 signature verification failed",
    ATTESTATION_ERROR_ENDORSEMENT_LAUNCH_MEASUREMENT_EXTRACT: "Failed to extract launch measurement from endorsement",
    ATTESTATION_ERROR_ENDORSEMENT_LAUNCH_MEASUREMENT_MISMATCH: "Utility VM endorsement does not match SNP report launch measurement",
}

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
    # Error codes
    'ATTESTATION_SUCCESS',
    'ATTESTATION_ERROR_GENERIC',
    'ATTESTATION_ERROR_INVALID_INPUT',
    'ATTESTATION_ERROR_MEMORY_ALLOCATION',
    'ATTESTATION_ERROR_CERT_CHAIN_INVALID',
    'ATTESTATION_ERROR_AMD_ROOT_KEY_MISMATCH',
    'ATTESTATION_ERROR_SNP_SIGNATURE_INVALID',
    'ATTESTATION_ERROR_REPORT_DATA_MISMATCH',
    'ATTESTATION_ERROR_SECURITY_POLICY_DECODE',
    'ATTESTATION_ERROR_SECURITY_POLICY_HASH',
    'ATTESTATION_ERROR_HOST_DATA_MISMATCH',
    'ATTESTATION_ERROR_ENDORSEMENT_ISSUER_MISMATCH',
    'ATTESTATION_ERROR_ENDORSEMENT_FEED_MISMATCH',
    'ATTESTATION_ERROR_ENDORSEMENT_SVN_TOO_LOW',
    'ATTESTATION_ERROR_ENDORSEMENT_CERT_CHAIN_INVALID',
    'ATTESTATION_ERROR_ENDORSEMENT_SIGNATURE_INVALID',
    'ATTESTATION_ERROR_ENDORSEMENT_LAUNCH_MEASUREMENT_EXTRACT',
    'ATTESTATION_ERROR_ENDORSEMENT_LAUNCH_MEASUREMENT_MISMATCH',
]

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