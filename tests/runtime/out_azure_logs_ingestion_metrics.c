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

#include <stdarg.h>
#include <fluent-bit/flb_output_plugin.h>
#include <cmetrics/cmt_histogram.h>
#include "flb_tests_runtime.h"
#include "../../plugins/out_azure_logs_ingestion/azure_logs_ingestion.h"

static int histogram_calls;
static int bucket_calls;
static int fail_histogram;
static int fail_buckets;
static int fail_after_transfer;
static char warning[256];

static struct cmt_histogram *create_histogram(struct cmt *cmt,
        char *ns, char *subsystem, char *name, char *help,
        struct cmt_histogram_buckets *buckets, int label_count, char **label_keys)
{
    histogram_calls++;
    if (histogram_calls == fail_histogram) {
        if (!fail_after_transfer) {
            /* Match the first calloc failure, before CMetrics owns buckets. */
            return NULL;
        }
        /* Invalid ordering exercises CMetrics' real post-transfer cleanup. */
        if (!buckets) {
            buckets = cmt_histogram_buckets_create(2, 1.0, 0.0);
            TEST_ASSERT(buckets != NULL);
        }
        else {
            buckets->upper_bounds[1] = 0.0;
        }
    }
    return cmt_histogram_create(cmt, ns, subsystem, name, help,
                                buckets, label_count, label_keys);
}

static struct cmt_histogram_buckets *create_buckets(double *bounds, size_t count)
{
    bucket_calls++;
    if (bucket_calls == fail_buckets) {
        return NULL;
    }
    return cmt_histogram_buckets_create_size(bounds, count);
}

static void capture_warning(struct flb_output_instance *ins, const char *format, ...)
{
    va_list args;

    (void) ins;
    va_start(args, format);
    vsnprintf(warning, sizeof(warning), format, args);
    va_end(args);
}

/* Keep failure injection local to the real initializer, not the engine allocator. */
#define flb_az_li_ctx_create test_az_li_ctx_create
#define flb_az_li_ctx_destroy test_az_li_ctx_destroy
#define cmt_histogram_create create_histogram
#define cmt_histogram_buckets_create_size create_buckets
#undef flb_plg_warn
#define flb_plg_warn capture_warning
#include "../../plugins/out_azure_logs_ingestion/azure_logs_ingestion_conf.c"
#undef flb_plg_warn
#undef cmt_histogram_buckets_create_size
#undef cmt_histogram_create
#undef flb_az_li_ctx_destroy
#undef flb_az_li_ctx_create

static void check_initialization(int histogram_failure, int bucket_failure,
                                 int after_transfer, const char *expected_warning)
{
    struct flb_output_instance ins = {0};
    struct flb_az_li ctx = {0};
    int ret;

    ins.cmt = cmt_create();
    TEST_ASSERT(ins.cmt != NULL);
    ctx.ins = &ins;
    histogram_calls = 0;
    bucket_calls = 0;
    fail_histogram = histogram_failure;
    fail_buckets = bucket_failure;
    fail_after_transfer = after_transfer;
    warning[0] = '\0';

    ret = initialize_payload_size_metrics(&ctx);
    if (expected_warning) {
        TEST_CHECK(ret == -1);
        TEST_CHECK(strcmp(warning, expected_warning) == 0);
        TEST_CHECK(ctx.cmt_uncompressed_payload_size == NULL);
        TEST_CHECK(ctx.cmt_http_payload_size == NULL);
        TEST_CHECK(cfl_list_is_empty(&ins.cmt->histograms));
    }
    else {
        TEST_CHECK(ret == 0);
        TEST_CHECK(warning[0] == '\0');
        TEST_ASSERT(ctx.cmt_uncompressed_payload_size != NULL);
        TEST_ASSERT(ctx.cmt_http_payload_size != NULL);
        TEST_CHECK(ctx.cmt_uncompressed_payload_size->buckets->count == 12);
        TEST_CHECK(ctx.cmt_http_payload_size->buckets->count == 12);
        TEST_CHECK(ctx.cmt_uncompressed_payload_size->buckets->upper_bounds[0] == 65536.0);
        TEST_CHECK(ctx.cmt_http_payload_size->buckets->upper_bounds[11] == 16777216.0);
    }
    cmt_destroy(ins.cmt);
}

static void test_payload_metrics_initialization(void)
{
    check_initialization(0, 0, 0, NULL);
}

static void test_uncompressed_histogram_early_failure(void)
{
    check_initialization(1, 0, 0, "could not create uncompressed payload size histogram");
}

static void test_http_histogram_early_failure(void)
{
    check_initialization(2, 0, 0, "could not create HTTP payload size histogram");
}

static void test_uncompressed_histogram_late_failure(void)
{
    check_initialization(1, 0, 1, "could not create uncompressed payload size histogram");
}

static void test_http_histogram_late_failure(void)
{
    check_initialization(2, 0, 1, "could not create HTTP payload size histogram");
}

static void test_uncompressed_buckets_failure(void)
{
    check_initialization(0, 1, 0, "could not create uncompressed payload size buckets");
}

static void test_http_buckets_failure(void)
{
    check_initialization(0, 2, 0, "could not create HTTP payload size buckets");
}

TEST_LIST = {
    {"payload_metrics_initialization", test_payload_metrics_initialization},
    {"uncompressed_histogram_early_failure", test_uncompressed_histogram_early_failure},
    {"http_histogram_early_failure", test_http_histogram_early_failure},
    {"uncompressed_histogram_late_failure", test_uncompressed_histogram_late_failure},
    {"http_histogram_late_failure", test_http_histogram_late_failure},
    {"uncompressed_buckets_failure", test_uncompressed_buckets_failure},
    {"http_buckets_failure", test_http_buckets_failure},
    {NULL, NULL}
};
