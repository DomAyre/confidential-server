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

#include "attestation.h"
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>

enum SnpType attestation_get_snp_type(void) {
    int fd = open("/dev/sev", O_RDONLY);
    if (fd >= 0) {
        close(fd);
        return SNP_TYPE_SEV;
    }
    fd = open("/dev/sev-guest", O_RDONLY);
    if (fd >= 0) {
        close(fd);
        return SNP_TYPE_SEV_GUEST;
    }
    return SNP_TYPE_NONE;
}

bool attestation_has_snp(void) {
    return attestation_get_snp_type() != SNP_TYPE_NONE;
}
