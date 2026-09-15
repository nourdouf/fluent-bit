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

#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_gzip.h>
#include <stdint.h>

#include "flb_tests_runtime.h"
#include "azure_logs_ingestion_gzip.h"

/* Sample data */
char *morpheus = "This is your last chance. After this, there is no "
    "turning back. You take the blue pill - the story ends, you wake up in "
    "your bed and believe whatever you want to believe. You take the red pill,"
    "you stay in Wonderland and I show you how deep the rabbit-hole goes.";

void test_stream_round_trip(void)
{
    struct az_li_gzip_stream *stream;
    void *compressed = NULL;
    void *decoded = NULL;
    size_t compressed_size = 0;
    size_t decoded_size = 0;
    size_t emitted = 0;
    size_t size = strlen(morpheus);
    int ret;

    stream = az_li_gzip_stream_create();
    TEST_ASSERT(stream != NULL);
    ret = az_li_gzip_stream_append(stream, morpheus, 17, &emitted);
    TEST_ASSERT(ret == 0);
    ret = az_li_gzip_stream_append(stream, morpheus + 17, size - 17, &emitted);
    TEST_ASSERT(ret == 0);
    ret = az_li_gzip_stream_finish(stream, &compressed, &compressed_size);
    TEST_ASSERT(ret == 0);
    TEST_CHECK(compressed_size >= emitted);
    az_li_gzip_stream_destroy(stream);

    ret = flb_gzip_uncompress(compressed, compressed_size, &decoded, &decoded_size);
    TEST_ASSERT(ret == 0);
    TEST_CHECK(decoded_size == size);
    TEST_CHECK(memcmp(decoded, morpheus, size) == 0);
    flb_free(decoded);
    flb_free(compressed);
}

static uint32_t stream_test_crc(const unsigned char *data, size_t size)
{
    uint32_t crc = 0xffffffff;
    size_t i;
    int bit;

    for (i = 0; i < size; i++) {
        crc ^= data[i];
        for (bit = 0; bit < 8; bit++) {
            crc = (crc >> 1) ^ ((crc & 1) ? 0xedb88320 : 0);
        }
    }
    return ~crc;
}

static uint32_t stream_test_le32(const unsigned char *data)
{
    return (uint32_t) data[0] | ((uint32_t) data[1] << 8) |
           ((uint32_t) data[2] << 16) | ((uint32_t) data[3] << 24);
}

void test_stream_fragmented(void)
{
    struct az_li_gzip_stream *stream;
    unsigned char *input;
    unsigned char *bytes;
    void *body = NULL;
    void *decoded = NULL;
    size_t size = 1000000;
    size_t body_size;
    size_t decoded_size;
    size_t emitted = 0;
    size_t previous = 0;
    size_t offset;
    size_t part;
    uint32_t random = 123456789;
    int ret;

    input = flb_malloc(size);
    TEST_ASSERT(input != NULL);
    for (offset = 0; offset < size; offset++) {
        random ^= random << 13;
        random ^= random >> 17;
        random ^= random << 5;
        input[offset] = random & 0xff;
    }
    stream = az_li_gzip_stream_create();
    TEST_ASSERT(stream != NULL);
    for (offset = 0; offset < size; offset += part) {
        part = (offset % 4093) + 1;
        if (part > size - offset) {
            part = size - offset;
        }
        ret = az_li_gzip_stream_append(stream, input + offset, part, &emitted);
        TEST_ASSERT(ret == 0);
        TEST_CHECK(emitted >= previous);
        previous = emitted;
        ret = az_li_gzip_stream_append(stream, NULL, 0, &emitted);
        TEST_ASSERT(ret == 0);
        TEST_CHECK(emitted == previous);
    }
    TEST_ASSERT(az_li_gzip_stream_finish(stream, &body, &body_size) == 0);
    TEST_CHECK(body_size >= emitted + 8);
    bytes = body;
    TEST_CHECK(bytes[0] == 0x1f && bytes[1] == 0x8b && bytes[2] == 8);
    TEST_CHECK(stream_test_le32(bytes + body_size - 8) == stream_test_crc(input, size));
    TEST_CHECK(stream_test_le32(bytes + body_size - 4) == size);
    az_li_gzip_stream_destroy(stream);
    TEST_ASSERT(flb_gzip_uncompress(body, body_size, &decoded, &decoded_size) == 0);
    TEST_CHECK(decoded_size == size);
    TEST_CHECK(memcmp(decoded, input, size) == 0);
    flb_free(decoded);
    flb_free(body);
    flb_free(input);
}

void test_stream_empty_and_terminal(void)
{
    struct az_li_gzip_stream *stream;
    void *body = NULL;
    void *again = NULL;
    size_t body_size;
    size_t again_size;
    size_t emitted;
    unsigned char *bytes;

    stream = az_li_gzip_stream_create();
    TEST_ASSERT(stream != NULL);
    TEST_CHECK(az_li_gzip_stream_append(stream, NULL, 0, &emitted) == 0);
    TEST_CHECK(emitted == 10);
    TEST_ASSERT(az_li_gzip_stream_finish(stream, &body, &body_size) == 0);
    TEST_CHECK(body_size >= 20);
    bytes = body;
    TEST_CHECK(stream_test_le32(bytes + body_size - 8) == 0);
    TEST_CHECK(stream_test_le32(bytes + body_size - 4) == 0);
    TEST_CHECK(az_li_gzip_stream_finish(stream, &again, &again_size) == -1);
    TEST_CHECK(again == NULL && again_size == 0);
    TEST_CHECK(az_li_gzip_stream_append(stream, "x", 1, &emitted) == -1);
    az_li_gzip_stream_destroy(stream);
    flb_free(body);

    stream = az_li_gzip_stream_create();
    TEST_ASSERT(stream != NULL);
    TEST_CHECK(az_li_gzip_stream_append(stream, NULL, 1, &emitted) == -1);
    TEST_CHECK(az_li_gzip_stream_append(stream, "x", 1, &emitted) == -1);
    TEST_CHECK(az_li_gzip_stream_finish(stream, &body, &body_size) == -1);
    az_li_gzip_stream_destroy(stream);

    stream = az_li_gzip_stream_create();
    TEST_ASSERT(stream != NULL);
    TEST_CHECK(az_li_gzip_stream_append(stream, "unfinished", 10, &emitted) == 0);
    az_li_gzip_stream_destroy(stream);
    az_li_gzip_stream_destroy(NULL);
}

TEST_LIST = {
    {"stream_fragmented", test_stream_fragmented},
    {"stream_empty_and_terminal", test_stream_empty_and_terminal},
    {"stream_round_trip", test_stream_round_trip},
    { 0 }
};
