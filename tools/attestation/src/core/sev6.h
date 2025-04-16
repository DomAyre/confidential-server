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

#ifndef AZURE_ATTESTATION_SEV6_H
#define AZURE_ATTESTATION_SEV6_H

#include "attestation.h"

// C-style API for SEV6
int sev6_get_report(const char* report_data, struct SnpReport* out_report);

#endif  // AZURE_ATTESTATION_SEV6_H
