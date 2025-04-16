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

#ifndef SECURITY_CONTEXT_H
#define SECURITY_CONTEXT_H

#include <stddef.h>

// Reads the contents of a file at file_path into a newly allocated buffer.
// Returns 0 on success, nonzero on error.
// The caller is responsible for freeing *out_buf with free().
int get_security_context_file(const char* file_path, char** out_buf, size_t* out_len);

#endif // SECURITY_CONTEXT_H
