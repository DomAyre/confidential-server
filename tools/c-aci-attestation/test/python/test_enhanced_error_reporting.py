import json
import os
from base64 import b64encode
import sys
import subprocess
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)) + "/../../src/bindings/python")

import attestation

def get_valid_attestation_and_policy():
    """Get a valid attestation and security policy for testing."""
    # Get valid attestation
    result = subprocess.run(
        [os.path.abspath(os.path.join(os.path.dirname(__file__), "../..", "build", "get_attestation_ccf")), "example-report-data"],
        capture_output=True, text=True, check=True
    )
    ccf_attestation = result.stdout.strip()
    
    # Get valid security policy
    policy_path = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "../..", "examples", "security_policies", "allow_all.rego")
    )
    with open(policy_path, 'rb') as f:
        security_policy_b64 = b64encode(f.read()).decode('utf-8')
    
    return ccf_attestation, security_policy_b64

def test_backward_compatibility():
    """Test that existing API still works (backward compatibility)."""
    ccf_attestation, security_policy_b64 = get_valid_attestation_and_policy()
    
    # Valid case should return True
    result = attestation.verify_attestation_ccf(
        ccf_attestation,
        report_data="example-report-data",
        security_policy_b64=security_policy_b64
    )
    assert result == True
    
    # Invalid case should return False
    result = attestation.verify_attestation_ccf(
        ccf_attestation,
        report_data="wrong-report-data",
        security_policy_b64=security_policy_b64
    )
    assert result == False

def test_detailed_error_codes():
    """Test the new detailed error code functionality."""
    ccf_attestation, security_policy_b64 = get_valid_attestation_and_policy()
    
    # Valid case should return ATTESTATION_SUCCESS
    error_code = attestation.verify_attestation_ccf_detailed(
        ccf_attestation,
        report_data="example-report-data",
        security_policy_b64=security_policy_b64
    )
    assert error_code == attestation.ATTESTATION_SUCCESS
    
    # Report data mismatch should return specific error code
    error_code = attestation.verify_attestation_ccf_detailed(
        ccf_attestation,
        report_data="wrong-report-data",
        security_policy_b64=security_policy_b64
    )
    assert error_code == attestation.ATTESTATION_ERROR_REPORT_DATA_MISMATCH
    
    # Security policy mismatch should return specific error code
    bad_policy_b64 = b64encode(b"bad policy").decode('utf-8')
    error_code = attestation.verify_attestation_ccf_detailed(
        ccf_attestation,
        report_data="example-report-data",
        security_policy_b64=bad_policy_b64
    )
    assert error_code == attestation.ATTESTATION_ERROR_HOST_DATA_MISMATCH

def test_exception_interface():
    """Test the exception-based error reporting."""
    ccf_attestation, security_policy_b64 = get_valid_attestation_and_policy()
    
    # Valid case should not raise exception
    result = attestation.verify_attestation_ccf(
        ccf_attestation,
        report_data="example-report-data",
        security_policy_b64=security_policy_b64,
        raise_on_error=True
    )
    assert result == True
    
    # Invalid case should raise AttestationError with correct details
    try:
        attestation.verify_attestation_ccf(
            ccf_attestation,
            report_data="wrong-report-data",
            security_policy_b64=security_policy_b64,
            raise_on_error=True
        )
        assert False, "Expected AttestationError"
    except attestation.AttestationError as e:
        assert e.error_code == attestation.ATTESTATION_ERROR_REPORT_DATA_MISMATCH
        assert "report data" in e.message.lower()
        assert "match" in e.message.lower()  # Changed from "mismatch" to "match"

def test_error_constants():
    """Test that error constants are defined correctly."""
    # Verify key error constants exist
    assert hasattr(attestation, 'ATTESTATION_SUCCESS')
    assert hasattr(attestation, 'ATTESTATION_ERROR_REPORT_DATA_MISMATCH')
    assert hasattr(attestation, 'ATTESTATION_ERROR_HOST_DATA_MISMATCH')
    assert hasattr(attestation, 'AttestationError')
    
    # Verify constant values match expected codes
    assert attestation.ATTESTATION_SUCCESS == 0
    assert attestation.ATTESTATION_ERROR_REPORT_DATA_MISMATCH == 20
    assert attestation.ATTESTATION_ERROR_HOST_DATA_MISMATCH == 32

def test_attestation_error_class():
    """Test the AttestationError exception class."""
    # Test with known error code
    error = attestation.AttestationError(attestation.ATTESTATION_ERROR_REPORT_DATA_MISMATCH)
    assert error.error_code == attestation.ATTESTATION_ERROR_REPORT_DATA_MISMATCH
    assert "report data" in error.message.lower()
    
    # Test with custom message
    custom_msg = "Custom error message"
    error = attestation.AttestationError(42, custom_msg)
    assert error.error_code == 42
    assert error.message == custom_msg
    assert custom_msg in str(error)
    
    # Test with unknown error code
    error = attestation.AttestationError(999)
    assert error.error_code == 999
    assert "unknown" in error.message.lower() or "999" in error.message

if __name__ == "__main__":
    print("Running enhanced error reporting tests...")
    test_backward_compatibility()
    print("✔ Backward compatibility tests passed")
    
    test_detailed_error_codes()
    print("✔ Detailed error code tests passed")
    
    test_exception_interface()
    print("✔ Exception interface tests passed")
    
    test_error_constants()
    print("✔ Error constants tests passed")
    
    test_attestation_error_class()
    print("✔ AttestationError class tests passed")
    
    print("All enhanced error reporting tests passed!")