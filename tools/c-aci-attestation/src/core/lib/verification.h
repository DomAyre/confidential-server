int verify_snp_report_is_genuine(SnpReport* snp_report, cert_chain_t* cert_chain);

int verify_snp_report_has_report_data(SnpReport* snp_report, snp_report_data_t* report_data);

int verify_snp_report_has_security_policy(SnpReport* snp_report, const char* security_policy_b64);