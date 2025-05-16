import json
import attestation


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

