/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_gzip.h>
#include <fluent-bit/flb_compression.h>

#include "flb_tests_internal.h"

/* Sample data */
char *morpheus = "This is your last chance. After this, there is no "
    "turning back. You take the blue pill - the story ends, you wake up in "
    "your bed and believe whatever you want to believe. You take the red pill,"
    "you stay in Wonderland and I show you how deep the rabbit-hole goes.";

void test_compress()
{
    int ret;
    int sample_len;
    char *in_data = morpheus;
    size_t in_len;
    void *str;
    size_t len;

    sample_len = strlen(morpheus);
    in_len = sample_len;
    ret = flb_gzip_compress(in_data, in_len, &str, &len);
    TEST_CHECK(ret == 0);

    in_data = str;
    in_len = len;

    ret = flb_gzip_uncompress(in_data, in_len, &str, &len);
    TEST_CHECK(ret == 0);

    TEST_CHECK(sample_len == len);
    ret = memcmp(morpheus, str, sample_len);
    TEST_CHECK(ret == 0);

    flb_free(in_data);
    flb_free(str);
}

/* Multiple gzip buffers concatenated together */
void test_compress_multi()
{
    int ret = 0;

    char *original = morpheus;
    size_t original_len = strlen(morpheus);

    char *original2 = flb_malloc(original_len);
    size_t original_len2 = original_len;

    void *compressed = NULL;
    size_t compressed_len = 0;

    void *compressed2 = NULL;
    size_t compressed_len2 = 0;

    char *concatenated = NULL;
    size_t concatenated_len = 0;

    void *uncompressed = NULL;
    size_t uncompressed_len = 0;

    size_t in_remaining = 0;
    size_t i = 0;

    /* apply simple rot 16 to lowercase letters */
    for (i = 0; i < original_len; i++) {
        char c = original[i];

        if (c >= 'a' && c <= 'z') {
            c += 16;

            if (c > 'z') {
                c -= 26;
            }
        }

        original2[i] = c;
    }

    ret = flb_gzip_compress(original, original_len, &compressed, &compressed_len);
    TEST_CHECK(ret == 0);

    ret = flb_gzip_compress(original2, original_len2, &compressed2, &compressed_len2);
    TEST_CHECK(ret == 0);

    /* Concatenate the buffers together */
    concatenated_len = compressed_len + compressed_len2;
    concatenated = flb_malloc(concatenated_len);

    memcpy(concatenated, compressed, compressed_len);
    memcpy(concatenated + compressed_len, compressed2, compressed_len2);

    flb_free(compressed);
    flb_free(compressed2);

    /* Uncompressed and verify payload 1 */
    ret = flb_gzip_uncompress_multi(concatenated, concatenated_len, &uncompressed, &uncompressed_len, &in_remaining);
    TEST_CHECK(ret == 0);

    TEST_CHECK(uncompressed_len == original_len);
    TEST_CHECK(in_remaining == compressed_len2);

    ret = memcmp(original, uncompressed, original_len);
    TEST_CHECK(ret == 0);

    flb_free(uncompressed);

    /* Uncompressed and verify payload 2 */
    ret = flb_gzip_uncompress_multi(concatenated + concatenated_len - in_remaining, in_remaining, &uncompressed, &uncompressed_len, &in_remaining);
    TEST_CHECK(ret == 0);

    TEST_CHECK(uncompressed_len == original_len2);
    TEST_CHECK(in_remaining == 0);

    ret = memcmp(original2, uncompressed, original_len2);
    TEST_CHECK(ret == 0);

    flb_free(concatenated);
    flb_free(uncompressed);
    flb_free(original2);
}

/* Uncompressed data is more than FLB_GZIP_BUFFER_SIZE */
void test_compress_large()
{
    int ret = 0;
    const int original_len = 10 * 1000 * 1000;
    char *original = flb_malloc(original_len);
    void *compressed = NULL;
    size_t compressed_len = 0;
    void *uncompressed = NULL;
    size_t uncompressed_len = 0;
    size_t in_remaining = 0;
    size_t i = 0;

    for (i = 0; i < original_len; i++) {
        original[i] = i % 256;
    }

    ret = flb_gzip_compress(original, original_len, &compressed, &compressed_len);
    TEST_CHECK(ret == 0);

    ret = flb_gzip_uncompress_multi(compressed, compressed_len, &uncompressed, &uncompressed_len, &in_remaining);
    TEST_CHECK(ret == 0);

    TEST_CHECK(in_remaining == 0);
    TEST_CHECK(uncompressed_len == original_len);

    ret = memcmp(original, uncompressed, original_len);
    TEST_CHECK(ret == 0);

    flb_free(original);
    flb_free(compressed);
    flb_free(uncompressed);
}

/* Uncompressed data is more than FLB_GZIP_BUFFER_SIZE * FLB_GZIP_MAX_BUFFERS */
void test_compress_too_large()
{
    int ret = 0;
    const int original_len = 150 * 1000 * 1000;
    char *original = flb_malloc(original_len);
    void *compressed = NULL;
    size_t compressed_len = 0;
    void *uncompressed = NULL;
    size_t uncompressed_len = 0;
    size_t in_remaining = 0;

    ret = flb_gzip_compress(original, original_len, &compressed, &compressed_len);
    TEST_CHECK(ret == 0);

    ret = flb_gzip_uncompress_multi(compressed, compressed_len, &uncompressed, &uncompressed_len, &in_remaining);
    TEST_CHECK(ret != 0);

    flb_free(compressed);
    flb_free(original);
}

/* When compressed the gzip body contains a valid gzip header */
void test_header_in_gzip_body()
{
    char original[] = {
        0x06, 0x03, 0x00, 0x00, 0x07, 0x01, 0x05, 0x04, 0x07, 0x07, 0x02, 0x03, 0x00, 0x01, 0x00, 0x04, 0x06, 0x02,
        0x02, 0x02, 0x06, 0x02, 0x00, 0x06, 0x04, 0x06, 0x00, 0x06, 0x07, 0x00, 0x03, 0x05, 0x03, 0x04, 0x06, 0x03,
        0x05, 0x03, 0x07, 0x05, 0x02, 0x01, 0x00, 0x02, 0x02, 0x00, 0x06, 0x01, 0x03, 0x00, 0x03, 0x01, 0x02, 0x03,
        0x07, 0x07, 0x01, 0x07, 0x05, 0x01, 0x00, 0x00, 0x06, 0x03, 0x04, 0x04, 0x06, 0x02, 0x07, 0x05, 0x07, 0x02,
        0x06, 0x07, 0x04, 0x01, 0x00, 0x03, 0x02, 0x03, 0x03, 0x05, 0x04, 0x06, 0x00, 0x03, 0x05, 0x02, 0x02, 0x02,
        0x03, 0x02, 0x02, 0x01, 0x06, 0x07, 0x06, 0x04, 0x01, 0x05
    };
    size_t original_len = sizeof(original);
    void *compressed = NULL;
    size_t compressed_len = 0;
    void *uncompressed = NULL;
    size_t uncompressed_len = 0;
    int ret = 0;

    ret = flb_gzip_compress(&original, original_len, &compressed, &compressed_len);
    TEST_CHECK(ret == 0);

    ret = flb_gzip_uncompress(compressed, compressed_len, &uncompressed, &uncompressed_len);
    TEST_CHECK(ret == 0);

    TEST_CHECK(uncompressed_len == original_len);

    ret = memcmp(original, uncompressed, original_len);
    TEST_CHECK(ret == 0);

    flb_free(compressed);
    flb_free(uncompressed);
}

/* When compressed the gzip body contains a valid gzip header */
void test_header_in_gzip_body_multi()
{
    char original[] = {
        0x06, 0x03, 0x00, 0x00, 0x07, 0x01, 0x05, 0x04, 0x07, 0x07, 0x02, 0x03, 0x00, 0x01, 0x00, 0x04, 0x06, 0x02,
        0x02, 0x02, 0x06, 0x02, 0x00, 0x06, 0x04, 0x06, 0x00, 0x06, 0x07, 0x00, 0x03, 0x05, 0x03, 0x04, 0x06, 0x03,
        0x05, 0x03, 0x07, 0x05, 0x02, 0x01, 0x00, 0x02, 0x02, 0x00, 0x06, 0x01, 0x03, 0x00, 0x03, 0x01, 0x02, 0x03,
        0x07, 0x07, 0x01, 0x07, 0x05, 0x01, 0x00, 0x00, 0x06, 0x03, 0x04, 0x04, 0x06, 0x02, 0x07, 0x05, 0x07, 0x02,
        0x06, 0x07, 0x04, 0x01, 0x00, 0x03, 0x02, 0x03, 0x03, 0x05, 0x04, 0x06, 0x00, 0x03, 0x05, 0x02, 0x02, 0x02,
        0x03, 0x02, 0x02, 0x01, 0x06, 0x07, 0x06, 0x04, 0x01, 0x05
    };
    size_t original_len = sizeof(original);
    void *compressed = NULL;
    size_t compressed_len = 0;
    void *uncompressed = NULL;
    size_t uncompressed_len = 0;
    size_t in_remaining = 0;
    int ret = 0;

    ret = flb_gzip_compress(&original, original_len, &compressed, &compressed_len);
    TEST_CHECK(ret == 0);

    ret = flb_gzip_uncompress_multi(compressed, compressed_len, &uncompressed, &uncompressed_len, &in_remaining);
    TEST_CHECK(ret == 0);

    TEST_CHECK(in_remaining == 0);
    TEST_CHECK(uncompressed_len == original_len);

    ret = memcmp(original, uncompressed, original_len);
    TEST_CHECK(ret == 0);

    flb_free(compressed);
    flb_free(uncompressed);
}


void test_decompress_concatenated()
{
    int ret;
    char *in_data = morpheus;
    size_t in_len = strlen(morpheus);
    void *gz1, *gz2;
    size_t len1, len2;
    flb_sds_t full_payload;
    void *out;
    size_t out_len;
    size_t in_remaining;

    ret = flb_gzip_compress(in_data, in_len, &gz1, &len1);
    TEST_CHECK(ret == 0);

    ret = flb_gzip_compress(in_data, in_len, &gz2, &len2);
    TEST_CHECK(ret == 0);

    full_payload = flb_sds_create_len((char *)gz1, len1);
    ret = flb_sds_cat_safe(&full_payload, gz2, len2);
    TEST_CHECK(ret == 0);

    ret = flb_gzip_uncompress_multi(full_payload, flb_sds_len(full_payload), &out, &out_len, &in_remaining);
    TEST_CHECK(ret == 0);
    TEST_CHECK(in_remaining == len2);
    TEST_CHECK(out_len == in_len);
    TEST_CHECK(memcmp(out, morpheus, in_len) == 0);

    flb_free(out);

    ret = flb_gzip_uncompress_multi(full_payload + flb_sds_len(full_payload) - in_remaining, in_remaining, &out, &out_len, &in_remaining);
    TEST_CHECK(ret == 0);
    TEST_CHECK(in_remaining == 0);
    TEST_CHECK(out_len == in_len);
    TEST_CHECK(memcmp(out, morpheus, in_len) == 0);

    flb_free(gz1);
    flb_free(gz2);
    flb_sds_destroy(full_payload);
    flb_free(out);
}

/*
 * A gzip stream carrying an FCOMMENT field must decompress through the
 * streaming decompressor used by the forward protocol. The comment is a
 * NUL terminated string placed between the base header and the deflate
 * body, so the parser has to skip its terminating NUL before handing the
 * remaining bytes to inflate.
 */
void test_decompress_with_comment()
{
    int ret;
    char *in_data = morpheus;
    size_t in_len = strlen(morpheus);
    void *gz;
    size_t gz_len;
    const char *comment = "fluent-bit";
    size_t comment_len = strlen(comment) + 1; /* include the NUL */
    uint8_t *stream;
    size_t stream_len;
    struct flb_decompression_context *dctx;
    uint8_t *append_ptr;
    char out[8192];
    size_t out_len;
    size_t total = 0;
    int iterations = 0;

    ret = flb_gzip_compress(in_data, in_len, &gz, &gz_len);
    TEST_CHECK(ret == 0);
    TEST_CHECK(gz_len > 10);

    /* Re-frame the payload with an FCOMMENT field inserted right after the
     * 10 byte base header. */
    stream_len = gz_len + comment_len;
    stream = flb_malloc(stream_len);
    TEST_CHECK(stream != NULL);

    memcpy(stream, gz, 10);
    stream[3] |= 0x10; /* FCOMMENT */
    memcpy(stream + 10, comment, comment_len);
    memcpy(stream + 10 + comment_len, (uint8_t *) gz + 10, gz_len - 10);

    dctx = flb_decompression_context_create(FLB_COMPRESSION_ALGORITHM_GZIP, 0);
    TEST_CHECK(dctx != NULL);

    append_ptr = flb_decompression_context_get_append_buffer(dctx);
    memcpy(append_ptr, stream, stream_len);
    dctx->input_buffer_length += stream_len;

    do {
        out_len = sizeof(out);
        ret = flb_decompress(dctx, out, &out_len);
        if (ret != FLB_DECOMPRESSOR_SUCCESS) {
            break;
        }
        if (out_len > 0) {
            if (total + out_len <= in_len) {
                TEST_CHECK(memcmp(out, morpheus + total, out_len) == 0);
            }
            total += out_len;
        }
    } while (dctx->input_buffer_length > 0 && ++iterations < 64);

    TEST_CHECK(ret == FLB_DECOMPRESSOR_SUCCESS);
    TEST_CHECK(total == in_len);

    flb_decompression_context_destroy(dctx);
    flb_free(stream);
    flb_free(gz);
}

void test_stream_round_trip(void)
{
    struct flb_gzip_stream *stream;
    void *compressed = NULL;
    void *decoded = NULL;
    size_t compressed_size = 0;
    size_t decoded_size = 0;
    size_t emitted = 0;
    size_t size = strlen(morpheus);
    int ret;

    stream = flb_gzip_stream_create();
    TEST_ASSERT(stream != NULL);
    ret = flb_gzip_stream_append(stream, morpheus, 17, &emitted);
    TEST_ASSERT(ret == 0);
    ret = flb_gzip_stream_append(stream, morpheus + 17, size - 17, &emitted);
    TEST_ASSERT(ret == 0);
    ret = flb_gzip_stream_finish(stream, &compressed, &compressed_size);
    TEST_ASSERT(ret == 0);
    TEST_CHECK(compressed_size >= emitted);
    flb_gzip_stream_destroy(stream);

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
    struct flb_gzip_stream *stream;
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
    stream = flb_gzip_stream_create();
    TEST_ASSERT(stream != NULL);
    for (offset = 0; offset < size; offset += part) {
        part = (offset % 4093) + 1;
        if (part > size - offset) {
            part = size - offset;
        }
        ret = flb_gzip_stream_append(stream, input + offset, part, &emitted);
        TEST_ASSERT(ret == 0);
        TEST_CHECK(emitted >= previous);
        previous = emitted;
        ret = flb_gzip_stream_append(stream, NULL, 0, &emitted);
        TEST_ASSERT(ret == 0);
        TEST_CHECK(emitted == previous);
    }
    TEST_ASSERT(flb_gzip_stream_finish(stream, &body, &body_size) == 0);
    TEST_CHECK(body_size >= emitted + 8);
    bytes = body;
    TEST_CHECK(bytes[0] == 0x1f && bytes[1] == 0x8b && bytes[2] == 8);
    TEST_CHECK(stream_test_le32(bytes + body_size - 8) == stream_test_crc(input, size));
    TEST_CHECK(stream_test_le32(bytes + body_size - 4) == size);
    flb_gzip_stream_destroy(stream);
    TEST_ASSERT(flb_gzip_uncompress(body, body_size, &decoded, &decoded_size) == 0);
    TEST_CHECK(decoded_size == size);
    TEST_CHECK(memcmp(decoded, input, size) == 0);
    flb_free(decoded);
    flb_free(body);
    flb_free(input);
}

void test_stream_empty_and_terminal(void)
{
    struct flb_gzip_stream *stream;
    void *body = NULL;
    void *again = NULL;
    size_t body_size;
    size_t again_size;
    size_t emitted;
    unsigned char *bytes;

    stream = flb_gzip_stream_create();
    TEST_ASSERT(stream != NULL);
    TEST_CHECK(flb_gzip_stream_append(stream, NULL, 0, &emitted) == 0);
    TEST_CHECK(emitted == 10);
    TEST_ASSERT(flb_gzip_stream_finish(stream, &body, &body_size) == 0);
    TEST_CHECK(body_size >= 20);
    bytes = body;
    TEST_CHECK(stream_test_le32(bytes + body_size - 8) == 0);
    TEST_CHECK(stream_test_le32(bytes + body_size - 4) == 0);
    TEST_CHECK(flb_gzip_stream_finish(stream, &again, &again_size) == -1);
    TEST_CHECK(again == NULL && again_size == 0);
    TEST_CHECK(flb_gzip_stream_append(stream, "x", 1, &emitted) == -1);
    flb_gzip_stream_destroy(stream);
    flb_free(body);

    stream = flb_gzip_stream_create();
    TEST_ASSERT(stream != NULL);
    TEST_CHECK(flb_gzip_stream_append(stream, NULL, 1, &emitted) == -1);
    TEST_CHECK(flb_gzip_stream_append(stream, "x", 1, &emitted) == -1);
    TEST_CHECK(flb_gzip_stream_finish(stream, &body, &body_size) == -1);
    flb_gzip_stream_destroy(stream);

    stream = flb_gzip_stream_create();
    TEST_ASSERT(stream != NULL);
    TEST_CHECK(flb_gzip_stream_append(stream, "unfinished", 10, &emitted) == 0);
    flb_gzip_stream_destroy(stream);
    flb_gzip_stream_destroy(NULL);
}

TEST_LIST = {
    {"stream_fragmented", test_stream_fragmented},
    {"stream_empty_and_terminal", test_stream_empty_and_terminal},
    {"stream_round_trip", test_stream_round_trip},
    {"compress", test_compress},
    {"decompress_with_comment", test_decompress_with_comment},
    {"compress_multi", test_compress_multi},
    {"compress_large", test_compress_large},
    {"header_in_data", test_header_in_gzip_body},
    {"header_in_data_multi", test_header_in_gzip_body_multi},
    {"decompress_concatenated", test_decompress_concatenated},
    { 0 }
};
