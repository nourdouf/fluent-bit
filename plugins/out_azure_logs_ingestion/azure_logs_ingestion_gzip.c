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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_macros.h>
#include <fluent-bit/flb_mem.h>
#include <miniz/miniz.h>
#include <limits.h>
#include <stdint.h>
#include <string.h>

#include "azure_logs_ingestion_gzip.h"

#define AZ_LI_GZIP_HEADER_SIZE 10
#define AZ_LI_GZIP_TRAILER_SIZE 8

/* Fixed gzip header from RFC 1952, section 2.3.1:
 * https://www.rfc-editor.org/rfc/rfc1952#section-2.3.1 */
static inline void az_li_gzip_header(void *buf)
{
    static const uint8_t header[AZ_LI_GZIP_HEADER_SIZE] = {
        0x1F, 0x8B,  /* Gzip format signature (the two "magic bytes"). */
        MZ_DEFLATED, /* Compression method: DEFLATE. */
        0,           /* Flags: no optional header fields. */
        0, 0, 0, 0,  /* Modification time: unspecified. */
        0,           /* No extra compression flags. */
        0xFF         /* Originating operating system: unspecified. */
    };

    memcpy(buf, header, sizeof(header));
}

/* One gzip stream: raw DEFLATE from miniz, with a header and trailer supplied here.
 * Owns the compressor and output allocation until finish transfers the output.
 * A finished or failed stream remains allocated, but only destroy is then valid. */
struct az_li_gzip_stream {
    mz_stream deflater;
    unsigned char *body;
    size_t size;
    size_t capacity;
    uint32_t crc;        /* CRC32 of the uncompressed input. */
    uint32_t input_size; /* Gzip ISIZE: input length modulo 2^32. */
    int terminal;
};

static void *gzip_stream_alloc(void *opaque, size_t items, size_t size)
{
    (void) opaque;

    if (size != 0 && items > SIZE_MAX / size) {
        return NULL;
    }
    return flb_calloc(items, size);
}

static void gzip_stream_free(void *opaque, void *address)
{
    (void) opaque;
    flb_free(address);
}

/* Discard compressor/output state, leaving the stream object for its caller to destroy. */
static int gzip_stream_fail(struct az_li_gzip_stream *stream)
{
    if (stream) {
        mz_deflateEnd(&stream->deflater);
        flb_free(stream->body);
        stream->body = NULL;
        stream->terminal = FLB_TRUE;
    }
    return -1;
}

static int gzip_stream_reserve(struct az_li_gzip_stream *stream, size_t extra)
{
    size_t needed;
    size_t capacity;
    void *body;

    if (extra > SIZE_MAX - stream->size) {
        return -1;
    }
    needed = stream->size + extra;
    if (needed <= stream->capacity) {
        return 0;
    }
    capacity = stream->capacity;
    if (capacity <= SIZE_MAX / 2) {
        capacity *= 2;
    }
    if (capacity < needed) {
        capacity = needed;
    }
    body = flb_realloc(stream->body, capacity);
    if (!body) {
        return -1;
    }
    stream->body = body;
    stream->capacity = capacity;
    return 0;
}

/* Append mode consumes input without forcing out all pending compressed bytes;
 * finish mode drains to the end of the DEFLATE stream. Track emitted sizes from
 * avail_* deltas, independent of miniz's total_* widths. */
static int gzip_stream_pump(struct az_li_gzip_stream *stream, int flush)
{
    mz_stream *deflater = &stream->deflater;
    unsigned int input_before;
    unsigned int output_before;
    size_t available;
    int status;

    do {
        if (gzip_stream_reserve(stream, 65536) != 0) {
            return -1;
        }
        available = stream->capacity - stream->size;
        deflater->next_out = stream->body + stream->size;
        deflater->avail_out = available > UINT_MAX ? UINT_MAX : (unsigned int) available;
        input_before = deflater->avail_in;
        output_before = deflater->avail_out;
        status = mz_deflate(deflater, flush);
        stream->size += output_before - deflater->avail_out;
        if (status == MZ_STREAM_END) {
            return flush == MZ_FINISH ? 0 : -1;
        }
        if (status != MZ_OK && status != MZ_BUF_ERROR) {
            return -1;
        }
        if (flush == MZ_NO_FLUSH && deflater->avail_in == 0 && deflater->avail_out > 0) {
            return 0;
        }
        if (input_before == deflater->avail_in && output_before == deflater->avail_out) {
            return -1;
        }
    } while (1);
}

struct az_li_gzip_stream *az_li_gzip_stream_create(void)
{
    struct az_li_gzip_stream *stream;
    int status;

    stream = flb_calloc(1, sizeof(*stream));
    if (!stream) {
        return NULL;
    }
    stream->deflater.zalloc = gzip_stream_alloc;
    stream->deflater.zfree = gzip_stream_free;
    /* Negative window bits request raw DEFLATE; this helper supplies the gzip wrapper. */
    status = mz_deflateInit2(&stream->deflater, MZ_DEFAULT_COMPRESSION,
                            MZ_DEFLATED, -MZ_DEFAULT_WINDOW_BITS, 9, MZ_DEFAULT_STRATEGY);
    if (status != MZ_OK || gzip_stream_reserve(stream, AZ_LI_GZIP_HEADER_SIZE) != 0) {
        az_li_gzip_stream_destroy(stream);
        return NULL;
    }
    az_li_gzip_header(stream->body);
    stream->size = AZ_LI_GZIP_HEADER_SIZE;
    stream->crc = MZ_CRC32_INIT;
    return stream;
}

int az_li_gzip_stream_append(struct az_li_gzip_stream *stream,
                           const void *data, size_t len, size_t *emitted_size)
{
    const unsigned char *input = data;
    unsigned int part;

    if (!stream || stream->terminal || !emitted_size || (!data && len != 0)) {
        return gzip_stream_fail(stream);
    }
    while (len > 0) {
        part = len > UINT_MAX ? UINT_MAX : (unsigned int) len;
        stream->deflater.next_in = input;
        stream->deflater.avail_in = part;
        if (gzip_stream_pump(stream, MZ_NO_FLUSH) != 0) {
            return gzip_stream_fail(stream);
        }
        stream->crc = mz_crc32(stream->crc, input, part);
        stream->input_size += (uint32_t) part;
        input += part;
        len -= part;
    }
    stream->deflater.next_in = NULL;
    *emitted_size = stream->size;
    return 0;
}

int az_li_gzip_stream_finish(struct az_li_gzip_stream *stream,
                           void **out_data, size_t *out_len)
{
    unsigned char *footer;
    unsigned int i;

    if (out_data) {
        *out_data = NULL;
    }
    if (out_len) {
        *out_len = 0;
    }
    if (!stream || stream->terminal || !out_data || !out_len) {
        return gzip_stream_fail(stream);
    }
    /* Provide a valid zero-length input pointer even to backends doing pointer arithmetic. */
    stream->deflater.next_in = (const unsigned char *) "";
    stream->deflater.avail_in = 0;
    if (gzip_stream_pump(stream, MZ_FINISH) != 0 ||
        mz_deflateEnd(&stream->deflater) != MZ_OK ||
        gzip_stream_reserve(stream, AZ_LI_GZIP_TRAILER_SIZE) != 0) {
        return gzip_stream_fail(stream);
    }
    /* RFC 1952 trailer: CRC32 followed by ISIZE, both little-endian 32-bit values. */
    footer = stream->body + stream->size;
    for (i = 0; i < 4; i++) {
        footer[i] = (stream->crc >> (8 * i)) & 0xff;
        footer[4 + i] = (stream->input_size >> (8 * i)) & 0xff;
    }
    stream->size += AZ_LI_GZIP_TRAILER_SIZE;
    *out_data = stream->body;
    *out_len = stream->size;
    stream->body = NULL;
    stream->terminal = FLB_TRUE;
    return 0;
}

void az_li_gzip_stream_destroy(struct az_li_gzip_stream *stream)
{
    if (stream) {
        gzip_stream_fail(stream);
        flb_free(stream);
    }
}
