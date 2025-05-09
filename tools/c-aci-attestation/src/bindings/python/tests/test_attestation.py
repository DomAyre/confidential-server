import os
import json
import base64
import pytest

import attestation

# Path to example policy relative to project root
_POLICY_PATH = os.path.abspath(
    os.path.join(
        os.path.dirname(__file__),
        '..', '..', '..', '..',
        'examples', 'security_policies', 'allow_all.rego'
    )
)

def test_get_snp_version():
    v = attestation.get_snp_version()
    assert isinstance(v, str)
    assert v.startswith("SNP Version:")


def test_get_attestation_ccf_json_structure():
    s = attestation.get_attestation_ccf()
    data = json.loads(s)
    assert "evidence" in data and "endorsements" in data
    assert isinstance(data["evidence"], str) and data["evidence"]


def test_get_attestation_ccf_with_report_data():
    s = attestation.get_attestation_ccf("hello")
    data = json.loads(s)
    assert "evidence" in data

