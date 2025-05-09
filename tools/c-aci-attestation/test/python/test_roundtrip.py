import os
import subprocess
import json

import attestation

_exe_get = attestation._exe_get_att
_exe_verify = attestation._exe_verify

def test_get_attestation_roundtrip_default(tmp_path):
    # Wrapper invocation
    out_py = attestation.get_attestation_ccf()
    # CLI invocation
    proc = subprocess.run([_exe_get], capture_output=True, text=True)
    assert proc.returncode == 0
    out_cli = proc.stdout
    assert out_py == out_cli

def test_get_attestation_roundtrip_with_report_data():
    report_data = 'testdata'
    out_py = attestation.get_attestation_ccf(report_data)
    proc = subprocess.run([_exe_get, report_data], capture_output=True, text=True)
    assert proc.returncode == 0
    assert out_py == proc.stdout

def test_verify_attestation_roundtrip_no_policy():
    # Get input
    s = attestation.get_attestation_ccf()
    # CLI without policy should fail
    proc = subprocess.run([_exe_verify, s], capture_output=True, text=True)
    ret_cli = (proc.returncode == 0)
    ret_py = attestation.verify_attestation_ccf(s)
    assert ret_py == ret_cli

def test_verify_attestation_roundtrip_with_policy():
    # Base64-encode the allow_all policy for CLI and wrapper
    policy_path = os.path.abspath(
        os.path.join(os.getcwd(), 'examples', 'security_policies', 'allow_all.rego')
    )
    with open(policy_path, 'rb') as f:
        policy_b64 = subprocess.run([
            'base64', '-w', '0', policy_path
        ], capture_output=True, text=True).stdout.strip()
    # get attestation
    s = attestation.get_attestation_ccf()
    # CLI invocation
    proc = subprocess.run([
        _exe_verify,
        '--security-policy-b64', policy_b64,
        s
    ], capture_output=True, text=True)
    ret_cli = (proc.returncode == 0)
    # Wrapper invocation
    ret_py = attestation.verify_attestation_ccf(s, security_policy_b64=policy_b64)
    assert ret_py == ret_cli