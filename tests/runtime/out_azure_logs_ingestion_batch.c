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

#include <fluent-bit.h>
#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_time.h>
#include <cmetrics/cmt_counter.h>
#include <cmetrics/cmt_map.h>
#include <cmetrics/cmt_metric.h>

#include "flb_tests_runtime.h"
#include "../../plugins/out_azure_logs_ingestion/azure_logs_ingestion_gzip.h"

static void *fail_remainder_allocation(size_t count, size_t size, const char *caller);
static flb_sds_t fail_combined_allocation(size_t size, const char *caller);
static int fail_gzip_finish(struct az_li_gzip_stream *stream, void **data, size_t *size);

/* Compile the real callback with local fault injection, not a production test
 * option or a process-wide allocator failure. The engine and FLB_OUTPUT_RETURN
 * remain unchanged. Include the declarations before substituting calls. */
#define out_azure_logs_ingestion_plugin test_azure_logs_ingestion_plugin
#define flb_calloc(count, size) fail_remainder_allocation(count, size, __func__)
#define flb_sds_create_size(size) fail_combined_allocation(size, __func__)
#define az_li_gzip_stream_finish fail_gzip_finish
#include "../../plugins/out_azure_logs_ingestion/azure_logs_ingestion.c"
#undef az_li_gzip_stream_finish
#undef flb_sds_create_size
#undef flb_calloc
#undef out_azure_logs_ingestion_plugin

struct observed_chunk {
    void *data;
    size_t size;
    size_t records;
    int calls;
};

/* Only the engine thread writes these fields while running. Inspect them after
 * flb_stop joins that thread; poll the real atomic output counters meanwhile. */
static struct observed_chunk observed[3];
static int allocation_failures;
static int inject_allocation_failure;
static int gzip_failures;
static int inject_gzip_failure;
static int observation_errors;
static int inject_remainder_failure;

static void *fail_remainder_allocation(size_t count, size_t size, const char *caller)
{
    if (inject_remainder_failure && strcmp(caller, "az_li_batch_prepare_bounded") == 0) {
        return NULL;
    }
    return flb_calloc(count, size);
}

static flb_sds_t fail_combined_allocation(size_t size, const char *caller)
{
    if (inject_allocation_failure && strcmp(caller, "az_li_batch_format") == 0) {
        allocation_failures++;
        return NULL;
    }
    return flb_sds_create_size(size);
}

static int fail_gzip_finish(struct az_li_gzip_stream *stream, void **data, size_t *size)
{
    size_t emitted;

    if (inject_gzip_failure) {
        gzip_failures++;
        /* Poison the real stream through its existing failure contract. Finish
         * initializes the outputs and the plugin must destroy the failed stream
         * and release all retained JSON when the fallback allocation also fails. */
        az_li_gzip_stream_append(stream, NULL, 1, &emitted);
    }
    return az_li_gzip_stream_finish(stream, data, size);
}

static void observe_flush(struct flb_event_chunk *event_chunk,
                          struct flb_output_flush *out_flush,
                          struct flb_input_instance *i_ins,
                          void *context, struct flb_config *config)
{
    struct observed_chunk *chunk;
    int index;

    if (flb_sds_len(event_chunk->tag) != 7 ||
        memcmp(event_chunk->tag, "chunk.", 6) != 0 ||
        event_chunk->tag[6] < '0' || event_chunk->tag[6] > '2') {
        observation_errors++;
    }
    else {
        index = event_chunk->tag[6] - '0';
        chunk = &observed[index];
        if (chunk->calls == 0) {
            chunk->data = flb_malloc(event_chunk->size);
            if (chunk->data) {
                memcpy(chunk->data, event_chunk->data, event_chunk->size);
            }
            else {
                observation_errors++;
            }
            chunk->size = event_chunk->size;
            chunk->records = event_chunk->total_events;
        }
        else if (!chunk->data || chunk->size != event_chunk->size ||
                 chunk->records != event_chunk->total_events ||
                 memcmp(chunk->data, event_chunk->data, event_chunk->size) != 0) {
            observation_errors++;
        }
        chunk->calls++;
    }
    cb_azure_logs_ingestion_flush(event_chunk, out_flush, i_ins, context, config);
}

static double counter_value(struct flb_output_instance *output, struct cmt_counter *counter)
{
    char *labels[] = {(char *) flb_output_name(output)};
    double value = 0;

    cmt_counter_get_val(counter, 1, labels, &value);
    return value;
}

static void check_combined_allocation_retry(int compress)
{
    flb_ctx_t *engine;
    struct flb_output_instance *output;
    struct flb_output_plugin plugin;
    int input_id;
    int output_id;
    int index;
    int attempt;
    char tag[16];
    char record[32];
    char copies[8];
    double dropped;

    memset(observed, 0, sizeof(observed));
    allocation_failures = 0;
    gzip_failures = 0;
    observation_errors = 0;
    inject_allocation_failure = FLB_TRUE;
    inject_gzip_failure = compress;
    plugin = test_azure_logs_ingestion_plugin;
    plugin.cb_flush = observe_flush;

    engine = flb_create();
    TEST_ASSERT(engine != NULL);
    TEST_ASSERT(flb_service_set(engine, "flush", "0.1", "grace", "2",
                               "scheduler.base", "1", "scheduler.cap", "1",
                               "log_level", "error", NULL) == 0);
    for (index = 0; index < 3; index++) {
        snprintf(tag, sizeof(tag), "chunk.%i", index);
        snprintf(record, sizeof(record), "{\"chunk_id\":%i}", index);
        snprintf(copies, sizeof(copies), "%i", index + 1);
        input_id = flb_input(engine, "dummy", NULL);
        TEST_ASSERT(input_id >= 0);
        TEST_ASSERT(flb_input_set(engine, input_id, "tag", tag, "dummy", record,
                                 "samples", "1", "copies", copies, NULL) == 0);
    }
    output_id = flb_output(engine, "azure_logs_ingestion", NULL);
    TEST_ASSERT(output_id >= 0);
    TEST_ASSERT(flb_output_set(engine, output_id, "match", "chunk.*", "workers", "0",
                              "batch", "on", "batch_wait_ms", "1500", "retry_limit", "1",
                              "compress", compress ? "on" : "off",
                              "client_id", "suite", "client_secret", "suite",
                              "tenant_id", "suite", "dcr_id", "suite", "table_name", "suite_CL",
                              "auth_url", "http://127.0.0.1:1/oauth/token",
                              "dce_url", "https://localhost:1", NULL) == 0);
    output = flb_output_get_instance(engine->config, output_id);
    TEST_ASSERT(output != NULL);
    output->p = &plugin;
    TEST_ASSERT(flb_start(engine) == 0);

    /* Six records in three chunks must each exhaust exactly one engine retry.
     * Poll terminal accounting, not a guessed sleep or callback completion stub. */
    dropped = 0;
    for (attempt = 0; attempt < 300; attempt++) {
        dropped = counter_value(output, output->cmt_dropped_records);
        if (dropped >= 6) {
            break;
        }
        flb_time_msleep(100);
    }
    TEST_CHECK(dropped == 6);
    TEST_CHECK(counter_value(output, output->cmt_retries) == 3);
    TEST_CHECK(counter_value(output, output->cmt_retried_records) == 6);
    TEST_CHECK(counter_value(output, output->cmt_retries_failed) == 3);
    TEST_CHECK(counter_value(output, output->cmt_proc_records) == 0);
    TEST_CHECK(counter_value(output, output->cmt_errors) == 0);
    TEST_CHECK(flb_stop(engine) == 0);
    flb_destroy(engine);

    TEST_CHECK(observation_errors == 0);
    TEST_CHECK(allocation_failures == 2);
    TEST_CHECK(gzip_failures == (compress ? 2 : 0));
    for (index = 0; index < 3; index++) {
        TEST_CHECK(observed[index].calls == 2);
        TEST_CHECK(observed[index].records == index + 1);
        TEST_CHECK(observed[index].size > 0);
        flb_free(observed[index].data);
    }
    memset(observed, 0, sizeof(observed));
    inject_allocation_failure = FLB_FALSE;
    inject_gzip_failure = FLB_FALSE;
}

static void test_combined_allocation_retries_all_members(void)
{
    check_combined_allocation_retry(FLB_FALSE);
}

static void test_gzip_fallback_allocation_retries_all_members(void)
{
    check_combined_allocation_retry(FLB_TRUE);
}

/* Exercise the real private dispatcher with real parked coroutines. Network
 * progress itself belongs to the integration tests; a coroutine that has left
 * its ready list stays suspended here so any accidental second resume is seen. */
struct dispatch_probe {
    struct flb_az_li *ctx;
    struct flb_coro *coro;
    struct az_li_member member;
    int auth;
    int hold_refresh;
    int resumed;
};

static void dispatch_probe_entry(void)
{
    struct flb_coro *coro = flb_coro_get();
    struct dispatch_probe *probe = coro->data;

    if (probe->auth) {
        az_li_auth_acquire(probe->ctx);
    }
    else {
        probe->member.coro = coro;
        mk_list_add(&probe->member.parked_link, &probe->ctx->batch_ready);
        flb_coro_yield(coro, FLB_FALSE);
    }
    probe->resumed++;
    if (probe->auth && !probe->hold_refresh) {
        probe->ctx->auth_refreshing = FLB_FALSE;
        az_li_notify(probe->ctx);
    }
    /* Stand in for the next engine-owned IO suspension, not another ready item. */
    for (;;) {
        flb_coro_yield(coro, FLB_FALSE);
        probe->resumed++;
    }
}

static void check_auth_dispatch(int hold_refresh, int mixed)
{
    struct flb_az_li ctx = {0};
    struct dispatch_probe probes[260] = {0};
    struct mk_event_loop *evl;
    struct flb_coro *coro;
    size_t stack_size;
    int index;
    int turns;
    int auth_resumed;
    int batch_resumed;
#ifdef FLB_SYSTEM_WINDOWS
    WSADATA wsa_data;

    TEST_ASSERT(WSAStartup(0x0201, &wsa_data) == 0);
#endif

    flb_coro_init();
    flb_coro_thread_init();
    evl = mk_event_loop_create(8);
    TEST_ASSERT(evl != NULL);
    mk_list_init(&ctx.batch_ready);
    mk_list_init(&ctx.auth_waiters);
    MK_EVENT_INIT(&ctx.continuation_event, -1, NULL, az_li_dispatch);
    TEST_ASSERT(mk_event_channel_create(evl, &ctx.continuation_channel[0],
                                       &ctx.continuation_channel[1],
                                       &ctx.continuation_event) == 0);
    ctx.auth_refreshing = FLB_TRUE;
    for (index = 0; index < 260; index++) {
        probes[index].ctx = &ctx;
        probes[index].auth = mixed ? index % 2 : FLB_TRUE;
        probes[index].hold_refresh = hold_refresh;
        coro = flb_coro_create(&probes[index]);
        TEST_ASSERT(coro != NULL);
        probes[index].coro = coro;
        coro->callee = co_create(FLB_CORO_STACK_SIZE_BYTE, dispatch_probe_entry, &stack_size);
        TEST_ASSERT(coro->callee != NULL);
#ifdef FLB_HAVE_VALGRIND
        coro->valgrind_stack_id = VALGRIND_STACK_REGISTER(
                                     coro->callee, ((char *) coro->callee) + stack_size);
#endif
        flb_coro_resume(coro);
    }
    ctx.auth_refreshing = FLB_FALSE;
    az_li_notify(&ctx);
    az_li_notify(&ctx); /* Coalesced even when both classes have ready work. */
    TEST_ASSERT(ctx.notification_pending == FLB_TRUE);
    TEST_ASSERT(az_li_dispatch(&ctx.continuation_event) == 0);
    auth_resumed = 0;
    batch_resumed = 0;
    for (index = 0; index < 260; index++) {
        if (probes[index].auth) {
            auth_resumed += probes[index].resumed;
        }
        else {
            batch_resumed += probes[index].resumed;
        }
    }
    TEST_CHECK(auth_resumed == (hold_refresh ? 1 : (mixed ? 32 : 64)));
    TEST_CHECK(batch_resumed == (hold_refresh ? 63 : (mixed ? 32 : 0)));
    TEST_CHECK(auth_resumed + batch_resumed == 64);
    TEST_CHECK(ctx.notification_pending == FLB_TRUE);

    for (turns = 0; turns < 10 && ctx.notification_pending; turns++) {
        TEST_ASSERT(az_li_dispatch(&ctx.continuation_event) == 0);
    }
    TEST_CHECK(turns < 10);
    if (hold_refresh) {
        /* Failed-refresh re-election must not spin or resume the successor in
         * IO. Batch completions can still drain while auth remains blocked. */
        TEST_CHECK(ctx.auth_refreshing == FLB_TRUE);
        TEST_CHECK(mk_list_size(&ctx.auth_waiters) == 129);
        TEST_CHECK(mk_list_size(&ctx.batch_ready) == 0);
        TEST_CHECK(ctx.notification_pending == FLB_FALSE);
        for (index = 0; index < 260; index++) {
            probes[index].hold_refresh = FLB_FALSE;
        }
        ctx.auth_refreshing = FLB_FALSE;
        az_li_notify(&ctx);
        TEST_CHECK(ctx.notification_pending == FLB_TRUE);
        for (turns = 0; turns < 10 && ctx.notification_pending; turns++) {
            TEST_ASSERT(az_li_dispatch(&ctx.continuation_event) == 0);
        }
        TEST_CHECK(turns < 10);
    }
    TEST_CHECK(mk_list_size(&ctx.auth_waiters) == 0);
    TEST_CHECK(mk_list_size(&ctx.batch_ready) == 0);
    TEST_CHECK(ctx.notification_pending == FLB_FALSE);
    for (index = 0; index < 260; index++) {
        TEST_CHECK(probes[index].resumed == 1);
        flb_coro_destroy(probes[index].coro);
    }
    flb_coro_set(NULL);
    mk_event_channel_destroy(evl, ctx.continuation_channel[0], ctx.continuation_channel[1],
                             &ctx.continuation_event);
    mk_event_loop_destroy(evl);
#ifdef FLB_SYSTEM_WINDOWS
    WSACleanup();
#endif
}

static void test_auth_dispatch_without_batches(void)
{
    check_auth_dispatch(FLB_FALSE, FLB_FALSE);
}

static void test_auth_dispatch_fair_bounded_continuation(void)
{
    check_auth_dispatch(FLB_FALSE, FLB_TRUE);
}

static void test_auth_dispatch_withholds_refresh_owner(void)
{
    check_auth_dispatch(FLB_TRUE, FLB_TRUE);
}

static void check_finalization_overflow(int empty_members, int allocation_failure)
{
    struct flb_output_instance output = {0};
    struct flb_az_li ctx = {0};
    struct az_li_batch batch = {0};
    struct az_li_batch *remainder;
    struct az_li_member members[6] = {0};
    struct az_li_member *sender;
    struct az_li_body body = {0};
    char *random_data;
    void *decoded;
    size_t decoded_size;
    size_t size;
    size_t index;
    size_t emitted;
    uint32_t random = 1;
    int member_index;
    int found = FLB_FALSE;

    output.p = &test_azure_logs_ingestion_plugin;
    output.log_level = FLB_LOG_INFO;
    snprintf(output.name, sizeof(output.name), "azure_logs_ingestion.0");
    ctx.ins = &output;
    ctx.compress_enabled = FLB_TRUE;
    ctx.notification_pending = FLB_TRUE;
    mk_list_init(&ctx.parked);
    mk_list_init(&ctx.batch_ready);
    mk_list_init(&ctx.auth_waiters);
    mk_list_init(&batch.members);
    batch.count = 3 + empty_members;
    batch.references = batch.count;
    random_data = flb_malloc(470000);
    TEST_ASSERT(random_data != NULL);
    for (index = 0; index < 470000; index++) {
        random = random * 1664525 + 1013904223;
        random_data[index] = 35 + ((random >> 16) % 88);
        if (random_data[index] == '\\') {
            random_data[index] = '!';
        }
    }
    for (member_index = 0; member_index < batch.count; member_index++) {
        members[member_index].batch = &batch;
        mk_list_add(&members[member_index].member_link, &batch.members);
        if (member_index != 0) {
            mk_list_add(&members[member_index].parked_link, &ctx.parked);
        }
    }
    /* Find a real miniz pending-output boundary, rather than fabricate a size
     * or assume that emitted bytes include the last compressed block. */
    for (size = 400000; size <= 470000; size += 2048) {
        for (member_index = 0; member_index < batch.count; member_index++) {
            if (member_index >= 3) {
                members[member_index].formatted_elements.storage = flb_sds_create("[]");
                TEST_ASSERT(members[member_index].formatted_elements.storage != NULL);
                members[member_index].formatted_elements.data =
                    members[member_index].formatted_elements.storage + 1;
                continue;
            }
            members[member_index].formatted_elements.storage =
                flb_sds_create_size(size + 4);
            TEST_ASSERT(members[member_index].formatted_elements.storage != NULL);
            memcpy(members[member_index].formatted_elements.storage, "[\"", 2);
            memcpy(members[member_index].formatted_elements.storage + 2, random_data, size);
            memcpy(members[member_index].formatted_elements.storage + size + 2, "\"]", 2);
            flb_sds_len_set(members[member_index].formatted_elements.storage, size + 4);
            members[member_index].formatted_elements.data =
                members[member_index].formatted_elements.storage + 1;
            members[member_index].formatted_elements.size = size + 2;
        }
        az_li_batch_rebuild(&ctx, &batch);
        emitted = batch.emitted_size;
        TEST_ASSERT(az_li_batch_prepare(&ctx, &batch, &body) == 0);
        found = emitted < FLB_AZ_LI_MAX_BODY_BYTES && body.size > FLB_AZ_LI_MAX_BODY_BYTES;
        flb_free(body.data);
        memset(&body, 0, sizeof(body));
        if (found) {
            break;
        }
        az_li_batch_release_json(&batch);
    }
    TEST_ASSERT(found);
    az_li_batch_rebuild(&ctx, &batch);
    TEST_CHECK(batch.emitted_size < FLB_AZ_LI_MAX_BODY_BYTES);
    if (allocation_failure) {
        inject_remainder_failure = FLB_TRUE;
        TEST_CHECK(az_li_batch_prepare_bounded(&ctx, &batch, &body) == -1);
        inject_remainder_failure = FLB_FALSE;
        TEST_CHECK(body.data == NULL);
        TEST_CHECK(batch.count == 3);
        TEST_CHECK(batch.references == 3);
        TEST_CHECK(mk_list_size(&ctx.batch_ready) == 0);
        for (member_index = 0; member_index < 3; member_index++) {
            TEST_CHECK(members[member_index].batch == &batch);
            TEST_CHECK(members[member_index].formatted_elements.storage != NULL);
        }
        az_li_batch_release_json(&batch);
        flb_free(random_data);
        return;
    }
    TEST_ASSERT(az_li_batch_prepare_bounded(&ctx, &batch, &body) == 0);
    TEST_CHECK(body.compressed == FLB_TRUE);
    TEST_CHECK(body.size <= FLB_AZ_LI_MAX_BODY_BYTES);
    TEST_CHECK(batch.count == 2);
    TEST_CHECK(batch.references == 2);
    TEST_CHECK(members[0].batch == &batch);
    TEST_CHECK(members[1].batch == &batch);
    remainder = members[2].batch;
    TEST_ASSERT(remainder != &batch);
    TEST_CHECK(remainder->count == 1 + empty_members);
    TEST_CHECK(remainder->references == 1 + empty_members);
    sender = mk_list_entry_first(&ctx.batch_ready, struct az_li_member, parked_link);
    TEST_CHECK(sender == &members[2]);
    TEST_CHECK(sender->send == FLB_TRUE);
    TEST_ASSERT(flb_gzip_uncompress(body.data, body.size, &decoded, &decoded_size) == 0);
    TEST_CHECK(decoded_size == 2 * size + 7);
    TEST_CHECK(memcmp((char *) decoded + 2, random_data, size) == 0);
    TEST_CHECK(memcmp((char *) decoded + size + 5, random_data, size) == 0);
    flb_free(decoded);
    flb_free(body.data);
    az_li_batch_release_json(&batch);
    memset(&body, 0, sizeof(body));
    TEST_ASSERT(az_li_batch_prepare_bounded(&ctx, remainder, &body) == 0);
    TEST_CHECK(body.size <= FLB_AZ_LI_MAX_BODY_BYTES);
    TEST_ASSERT(flb_gzip_uncompress(body.data, body.size, &decoded, &decoded_size) == 0);
    TEST_CHECK(decoded_size == size + 4);
    TEST_CHECK(memcmp((char *) decoded + 2, random_data, size) == 0);
    flb_free(decoded);
    flb_free(body.data);
    az_li_batch_release_json(remainder);
    flb_free(remainder);
    flb_free(random_data);
}

static void test_finalization_overflow_rebuilds_whole_chunks(void)
{
    check_finalization_overflow(0, FLB_FALSE);
}

static void test_finalization_overflow_retains_empty_members(void)
{
    check_finalization_overflow(3, FLB_FALSE);
}

static void test_overflow_allocation_failure_preserves_members(void)
{
    check_finalization_overflow(0, FLB_TRUE);
}

enum rebuild_test_failure {
    REBUILD_NO_FAILURE,
    REBUILD_REMAINDER_FAILURE,
    REBUILD_FORMAT_FAILURE,
    REBUILD_METRIC_UNAVAILABLE
};

static void check_rebuild_metrics(int count, size_t size, enum rebuild_test_failure failure)
{
    struct flb_output_instance output = {0};
    struct flb_az_li ctx = {0};
    struct az_li_batch batch = {0};
    struct az_li_member members[4] = {0};
    struct az_li_batch *remainder;
    struct az_li_body body = {0};
    struct cmt_histogram *histogram;
    struct cmt_metric *metric;
    double started_at;
    double finished_at;
    uint64_t expected_count;
    int index;
    int ret;

    output.p = &test_azure_logs_ingestion_plugin;
    output.alias = "rebuilder";
    output.cmt = cmt_create();
    TEST_ASSERT(output.cmt != NULL);
    histogram = cmt_histogram_create(output.cmt, "fluentbit", "azure_logs_ingestion",
                                    "batch_rebuild_duration_seconds", "Recovery duration.",
                                    NULL, 1, (char *[]) {"name"});
    TEST_ASSERT(histogram != NULL);
    ctx.ins = &output;
    if (failure != REBUILD_METRIC_UNAVAILABLE) {
        ctx.cmt_batch_rebuild_duration = histogram;
    }
    ctx.notification_pending = FLB_TRUE;
    mk_list_init(&ctx.parked);
    mk_list_init(&ctx.batch_ready);
    mk_list_init(&ctx.auth_waiters);
    mk_list_init(&batch.members);
    batch.count = count;
    batch.references = count;
    for (index = 0; index < count; index++) {
        members[index].batch = &batch;
        members[index].formatted_elements.storage = flb_sds_create_size(size);
        TEST_ASSERT(members[index].formatted_elements.storage != NULL);
        memset(members[index].formatted_elements.storage, 'x', size);
        memcpy(members[index].formatted_elements.storage, "[\"", 2);
        memcpy(members[index].formatted_elements.storage + size - 2, "\"]", 2);
        members[index].formatted_elements.storage[size] = '\0';
        flb_sds_len_set(members[index].formatted_elements.storage, size);
        members[index].formatted_elements.data =
            members[index].formatted_elements.storage + 1;
        members[index].formatted_elements.size = size - 2;
        mk_list_add(&members[index].member_link, &batch.members);
        if (index > 0) {
            mk_list_add(&members[index].parked_link, &ctx.parked);
        }
    }
    az_li_batch_rebuild(&ctx, &batch);
    inject_remainder_failure = failure == REBUILD_REMAINDER_FAILURE;
    inject_allocation_failure = failure == REBUILD_FORMAT_FAILURE;
    started_at = az_li_monotonic_seconds();
    TEST_ASSERT(started_at >= 0.0);
    ret = az_li_batch_prepare_bounded(&ctx, &batch, &body);
    finished_at = az_li_monotonic_seconds();
    inject_remainder_failure = FLB_FALSE;
    inject_allocation_failure = FLB_FALSE;
    TEST_CHECK(ret == ((failure == REBUILD_REMAINDER_FAILURE ||
                       failure == REBUILD_FORMAT_FAILURE) ? -1 : 0));
    expected_count = count == 4 && failure != REBUILD_FORMAT_FAILURE &&
                     failure != REBUILD_METRIC_UNAVAILABLE ? 1 : 0;
    metric = cmt_map_metric_get(&histogram->opts, histogram->map, 1,
                                (char *[]) {"rebuilder"}, CMT_FALSE);
    TEST_CHECK((metric ? cmt_metric_hist_get_count_value(metric) : 0) == expected_count);
    if (expected_count) {
        TEST_ASSERT(metric != NULL);
        TEST_CHECK(cmt_metric_hist_get_sum_value(metric) >= 0.0);
        TEST_CHECK(cmt_metric_hist_get_sum_value(metric) <= finished_at - started_at);
        TEST_CHECK(cmt_metric_hist_get_value(metric, histogram->buckets->count) == 1);
    }
    flb_sds_destroy(body.data);
    if (ret == 0 && count == 4) {
        /* Four 400 KB members require repeated removals, but form one recovery. */
        TEST_CHECK(batch.count == 2);
        remainder = members[2].batch;
        TEST_ASSERT(remainder != &batch);
        TEST_CHECK(remainder->count == 2);
        memset(&body, 0, sizeof(body));
        TEST_CHECK(az_li_batch_prepare_bounded(&ctx, remainder, &body) == 0);
        if (expected_count) {
            TEST_CHECK(cmt_metric_hist_get_count_value(metric) == 1);
        }
        flb_sds_destroy(body.data);
        az_li_batch_release_json(remainder);
        flb_free(remainder);
    }
    az_li_batch_release_json(&batch);
    cmt_destroy(output.cmt);
}

static void test_rebuild_metrics_count_recovery_not_passes(void)
{
    check_rebuild_metrics(4, 400000, REBUILD_NO_FAILURE);
}

static void test_rebuild_metrics_count_failed_recovery(void)
{
    check_rebuild_metrics(4, 400000, REBUILD_REMAINDER_FAILURE);
}

static void test_rebuild_metrics_exclude_initial_preparation_failure(void)
{
    check_rebuild_metrics(4, 400000, REBUILD_FORMAT_FAILURE);
}

static void test_rebuild_metrics_exclude_fitting_batches(void)
{
    check_rebuild_metrics(2, 400000, REBUILD_NO_FAILURE);
}

static void test_rebuild_metrics_exclude_oversized_singletons(void)
{
    check_rebuild_metrics(1, 1200000, REBUILD_NO_FAILURE);
}

static void test_rebuild_metrics_unavailable_does_not_prevent_recovery(void)
{
    check_rebuild_metrics(4, 400000, REBUILD_METRIC_UNAVAILABLE);
}

TEST_LIST = {
    {"rebuild_metrics_count_recovery_not_passes", test_rebuild_metrics_count_recovery_not_passes},
    {"rebuild_metrics_count_failed_recovery", test_rebuild_metrics_count_failed_recovery},
    {"rebuild_metrics_exclude_initial_preparation_failure",
     test_rebuild_metrics_exclude_initial_preparation_failure},
    {"rebuild_metrics_exclude_fitting_batches", test_rebuild_metrics_exclude_fitting_batches},
    {"rebuild_metrics_exclude_oversized_singletons", test_rebuild_metrics_exclude_oversized_singletons},
    {"rebuild_metrics_unavailable_does_not_prevent_recovery",
     test_rebuild_metrics_unavailable_does_not_prevent_recovery},
    {"overflow_allocation_failure_preserves_members", test_overflow_allocation_failure_preserves_members},
    {"finalization_overflow_rebuilds_whole_chunks", test_finalization_overflow_rebuilds_whole_chunks},
    {"finalization_overflow_retains_empty_members", test_finalization_overflow_retains_empty_members},
    {"auth_dispatch_without_batches", test_auth_dispatch_without_batches},
    {"auth_dispatch_fair_bounded_continuation", test_auth_dispatch_fair_bounded_continuation},
    {"auth_dispatch_withholds_refresh_owner", test_auth_dispatch_withholds_refresh_owner},
    {"combined_allocation_retries_all_members", test_combined_allocation_retries_all_members},
    {"gzip_fallback_allocation_retries_all_members", test_gzip_fallback_allocation_retries_all_members},
    {0}
};
