#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifndef SNP_REPORT_H
#define SNP_REPORT_H

typedef uint8_t snp_report_data_t[64];

// from SEV-SNP Firmware ABI Specification Table 20
struct SnpRequest {
    snp_report_data_t report_data;
    uint32_t vmpl;
    uint8_t reserved[28];
  };

  enum SNP_MSG_TYPE {
    SNP_MSG_TYPE_INVALID = 0,
    SNP_MSG_CPUID_REQ,
    SNP_MSG_CPUID_RSP,
    SNP_MSG_KEY_REQ,
    SNP_MSG_KEY_RSP,
    SNP_MSG_REPORT_REQ,
    SNP_MSG_REPORT_RSP,
    SNP_MSG_EXPORT_REQ,
    SNP_MSG_EXPORT_RSP,
    SNP_MSG_IMPORT_REQ,
    SNP_MSG_IMPORT_RSP,
    SNP_MSG_ABSORB_REQ,
    SNP_MSG_ABSORB_RSP,
    SNP_MSG_VMRK_REQ,
    SNP_MSG_VMRK_RSP,
    SNP_MSG_TYPE_MAX
  };

  // from SEV-SNP Firmware ABI Specification Table 21
  struct SnpReport {
    uint32_t version;
    uint32_t guest_svn;
    uint64_t policy;
    __uint128_t family_id;
    __uint128_t image_id;
    uint32_t vmpl;
    uint32_t signature_algo;
    uint64_t platform_version;
    uint64_t platform_info;
    uint32_t author_key_en;
    uint32_t reserved1;
    snp_report_data_t report_data;
    uint8_t measurement[48];
    uint8_t host_data[32];
    uint8_t id_key_digest[48];
    uint8_t author_key_digest[48];
    uint8_t report_id[32];
    uint8_t report_id_ma[32];
    uint64_t reported_tcb;
    uint8_t reserved2[24];
    uint8_t chip_id[64];
    uint8_t committed_svn[8];
    uint8_t committed_version[8];
    uint8_t launch_svn[8];
    uint8_t reserved3[168];
    uint8_t signature[512];
  };

  // from SEV-SNP Firmware ABI Specification Table 22
  struct SnpResponse {
    uint32_t status;
    uint32_t report_size;
    uint8_t reserved[24];
    struct SnpReport report;
    uint8_t padding[64];
  };

  enum SnpType { SNP_TYPE_SEV, SNP_TYPE_SEV_GUEST, SNP_TYPE_NONE };

  int get_snp_report(uint8_t* report_data, struct SnpReport* out_report);

#endif // SNP_REPORT_H
