/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2026 The Fluent Bit Authors
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#ifndef FLB_OUT_AZURE_LOGS_INGESTION_GZIP_H
#define FLB_OUT_AZURE_LOGS_INGESTION_GZIP_H

#include <stddef.h>

struct az_li_gzip_stream;

/*
 * Incremental gzip for Azure request bodies. Append consumes all borrowed input before
 * returning success; NULL input is valid only for zero length. emitted_size
 * includes the header, but not pending DEFLATE output or the eventual trailer.
 * It is a soft sizing signal, not the final body's size or an upper bound.
 *
 * Finish transfers an owned body (release with flb_free) and its exact length,
 * and releases compressor state. Finish is allowed once. Any failed operation
 * poisons the stream; only destroy is then valid. Destroy also accepts NULL.
 * Operations return 0 on success and -1 on failure.
 */
struct az_li_gzip_stream *az_li_gzip_stream_create(void);
int az_li_gzip_stream_append(struct az_li_gzip_stream *stream,
                           const void *data, size_t len, size_t *emitted_size);
int az_li_gzip_stream_finish(struct az_li_gzip_stream *stream,
                           void **out_data, size_t *out_len);
void az_li_gzip_stream_destroy(struct az_li_gzip_stream *stream);

#endif
