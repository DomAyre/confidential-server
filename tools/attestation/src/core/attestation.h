/*
 * Portions Copyright (c) Microsoft Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef AZURE_ATTESTATION_H
#define AZURE_ATTESTATION_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

// from SEV-SNP Firmware ABI Specification Table 20
struct SnpRequest {
  uint8_t report_data[64];
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
  uint8_t report_data[64];
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

struct AttestationReport {
  char* evidence;
  char* endorsements;
  char* uvm_endorsements;
  char* endorsed_tcb;
};

// C-style API

enum SnpType attestation_get_snp_type(void);
bool attestation_has_snp(void);
int attestation_fetch_snp_attestation(const char* report_data, struct AttestationReport* out_report);
int attestation_fetch_fake_snp_attestation(struct AttestationReport* out_report);
int attestation_get_snp_evidence(const char* report_data, char** out_evidence);
int attestation_get_snp_endorsements(char** out_endorsements);
int attestation_get_snp_uvm_endorsements(char** out_uvm_endorsements);
int attestation_get_snp_endorsed_tcb(char** out_endorsed_tcb);

#endif  // AZURE_ATTESTATION_H
