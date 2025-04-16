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

#ifndef ATTESTATION_UVM_ENDORSEMENTS_H
#define ATTESTATION_UVM_ENDORSEMENTS_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "attestation.h"
#include "utils/security_context.h"

int attestation_get_snp_uvm_endorsements(char** out_uvm_endorsements) {
    char* data = NULL;
    size_t len = 0;
    if (get_security_context_file("/reference-info-base64", &data, &len) != 0 || !data) return -1;
    *out_uvm_endorsements = data;
    return 0;
}

#endif  // ATTESTATION_UVM_ENDORSEMENTS_H
