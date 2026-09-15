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

#include <fluent-bit/flb_compat.h>
#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_http_client.h>
#include <fluent-bit/flb_oauth2.h>
#include <fluent-bit/flb_base64.h>
#include <fluent-bit/flb_crypto.h>
#include <fluent-bit/flb_gzip.h>
#include <fluent-bit/flb_hmac.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_mp.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_log_event_decoder.h>
#include <msgpack.h>
#include <fluent-bit/flb_scheduler.h>
#include <fluent-bit/flb_engine_macros.h>
#include <fluent-bit/flb_coro.h>
#include <fluent-bit/flb_upstream_conn.h>
#include <time.h>
#include <limits.h>
#include <errno.h>

#include "azure_logs_ingestion.h"
#include "azure_logs_ingestion_conf.h"
#include "azure_logs_ingestion_gzip.h"

#define AZ_LI_DISPATCH_LIMIT 64

static void az_li_batch_tick(struct flb_config *config, void *data);
static int az_li_dispatch(void *data);
static void az_li_notify(struct flb_az_li *ctx);

static int az_li_positive_option(const char *value, int *result)
{
    char *end;
    long parsed;

    if (!value || !*value) {
        return -1;
    }
    errno = 0;
    parsed = strtol(value, &end, 10);
    if (errno || *end || parsed <= 0 || parsed > INT_MAX) {
        return -1;
    }
    *result = (int) parsed;
    return 0;
}

static int cb_azure_logs_ingestion_init(struct flb_output_instance *ins,
                          struct flb_config *config, void *data)
{
    struct flb_az_li *ctx;
    (void) config;
    (void) ins;
    (void) data;

    /* Allocate and initialize a context from configuration */
    ctx = flb_az_li_ctx_create(ins, config);
    if (!ctx) {
        flb_plg_error(ins, "configuration failed");
        return -1;
    }

    mk_list_init(&ctx->parked);
    mk_list_init(&ctx->batch_ready);
    mk_list_init(&ctx->auth_waiters);
    ctx->continuation_channel[0] = -1;
    ctx->continuation_channel[1] = -1;
    if (flb_output_get_property("batch_wait_ms", ins)) {
        if (az_li_positive_option(flb_output_get_property("batch_wait_ms", ins),
                                  &ctx->batch_wait_ms) != 0 || ins->tp_workers != 0) {
            flb_plg_error(ins, "batching requires positive batch_wait_ms and workers=0");
            flb_az_li_ctx_destroy(ctx);
            return -1;
        }
    }
    ctx->batch_target_size = FLB_AZ_LI_DEFAULT_BATCH_TARGET_SIZE;
    if (flb_output_get_property("batch_target_size", ins)) {
        if (az_li_positive_option(flb_output_get_property("batch_target_size", ins),
                                  &ctx->batch_target_size) != 0 ||
            ctx->batch_target_size > FLB_AZ_LI_MAX_BODY_BYTES) {
            flb_plg_error(ins, "batch_target_size must be an integer from 1 to 1048576 bytes");
            flb_az_li_ctx_destroy(ctx);
            return -1;
        }
    }
    /* Both batched and unbatched main-thread flushes can wait behind OAuth.
     * Legacy workers retain synchronous OAuth and mutex-protected token access. */
    if (ins->tp_workers == 0) {
        MK_EVENT_INIT(&ctx->continuation_event, -1, NULL, az_li_dispatch);
        if (mk_event_channel_create(config->evl, &ctx->continuation_channel[0],
                                     &ctx->continuation_channel[1],
                                     &ctx->continuation_event) != 0) {
            flb_plg_error(ins, "cannot create continuation channel");
            flb_az_li_ctx_destroy(ctx);
            return -1;
        }
        ctx->continuation_event.type = FLB_ENGINE_EV_CUSTOM;
        /* Completion notifications must drain before another group can publish. */
        ctx->continuation_event.priority = FLB_ENGINE_PRIORITY_BOTTOM;
        flb_stream_enable_async_mode(&ctx->u_auth->u->base);
    }
    return 0;
}

/* A duplicate function copied from the azure log analytics plugin.
    allocates sds string */
static int az_li_format(const void *in_buf, size_t in_bytes,
                        char **out_buf, size_t *out_size,
                        struct flb_az_li *ctx,
                        struct flb_config *config)
{
    int i;
    int ret;
    int array_size = 0;
    int map_size;
    double t;
    struct flb_time tm;
    struct flb_log_event_decoder log_decoder;
    struct flb_log_event log_event;
    msgpack_object map;
    msgpack_object k;
    msgpack_object v;
    msgpack_sbuffer mp_sbuf;
    msgpack_packer mp_pck;
    msgpack_sbuffer tmp_sbuf;
    msgpack_packer tmp_pck;
    flb_sds_t record;
    char time_formatted[32];
    size_t s;
    struct tm tms;
    int len;

    /* Count number of items */
    array_size = flb_mp_count_log_records(in_buf, in_bytes);

    /* Create temporary msgpack buffer */
    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);
    msgpack_pack_array(&mp_pck, array_size);

    ret = flb_log_event_decoder_init(&log_decoder, (char *) in_buf, in_bytes);
    if (ret != FLB_EVENT_DECODER_SUCCESS) {
        msgpack_sbuffer_destroy(&mp_sbuf);
        return -1;
    }

    while ((ret = flb_log_event_decoder_next(&log_decoder, &log_event)) ==
           FLB_EVENT_DECODER_SUCCESS) {
        flb_time_copy(&tm, &log_event.timestamp);

        /* Create temporary msgpack buffer */
        msgpack_sbuffer_init(&tmp_sbuf);
        msgpack_packer_init(&tmp_pck, &tmp_sbuf, msgpack_sbuffer_write);

        map = *log_event.body;
        map_size = map.via.map.size;

        msgpack_pack_map(&mp_pck, map_size + 1);

        /* Append the time key */
        msgpack_pack_str(&mp_pck, flb_sds_len(ctx->time_key));
        msgpack_pack_str_body(&mp_pck,
                            ctx->time_key,
                            flb_sds_len(ctx->time_key));

        if (ctx->time_generated == FLB_TRUE) {
            /* Append the time value as ISO 8601 */
            gmtime_r(&tm.tm.tv_sec, &tms);
            s = strftime(time_formatted, sizeof(time_formatted) - 1,
                            FLB_PACK_JSON_DATE_ISO8601_FMT, &tms);

            len = snprintf(time_formatted + s,
                            sizeof(time_formatted) - 1 - s,
                            ".%03" PRIu64 "Z",
                            (uint64_t) tm.tm.tv_nsec / 1000000);
            s += len;
            msgpack_pack_str(&mp_pck, s);
            msgpack_pack_str_body(&mp_pck, time_formatted, s);
        }
        else {
            /* Append the time value as millis.nanos */
            t = flb_time_to_double(&tm);
            msgpack_pack_double(&mp_pck, t);
        }

        /* Append original map k/v */
        for (i = 0; i < map_size; i++) {
            k = map.via.map.ptr[i].key;
            v = map.via.map.ptr[i].val;

            msgpack_pack_object(&tmp_pck, k);
            msgpack_pack_object(&tmp_pck, v);
        }
        msgpack_sbuffer_write(&mp_sbuf, tmp_sbuf.data, tmp_sbuf.size);
        msgpack_sbuffer_destroy(&tmp_sbuf);
    }

    record = flb_msgpack_raw_to_json_sds(mp_sbuf.data, mp_sbuf.size,
                                         config->json_escape_unicode);
    if (!record) {
        flb_errno();
        msgpack_sbuffer_destroy(&mp_sbuf);
        flb_log_event_decoder_destroy(&log_decoder);
        return -1;
    }

    msgpack_sbuffer_destroy(&mp_sbuf);
    flb_log_event_decoder_destroy(&log_decoder);

    *out_buf = record;
    *out_size = flb_sds_len(record);

    return 0;
}

/* Only refresh waiters are resumed here; network I/O resumes in the engine. */
struct az_li_auth_waiter {
    struct flb_coro *coro;
    struct mk_list link;
};

static void az_li_auth_acquire(struct flb_az_li *ctx)
{
    struct az_li_auth_waiter waiter;

    waiter.coro = flb_coro_get();
    while (ctx->auth_refreshing) {
        mk_list_add(&waiter.link, &ctx->auth_waiters);
        flb_coro_yield(waiter.coro, FLB_FALSE);
    }
    ctx->auth_refreshing = FLB_TRUE;
}

static char *az_li_token_request(struct flb_az_li *ctx);

/* Gets OAuth token; (allocates sds string everytime, must deallocate) */
static flb_sds_t get_az_li_token(struct flb_az_li *ctx)
{
    int ret = 0;
    int async = ctx->ins->tp_workers == 0;
    int owns_refresh = FLB_FALSE;
    char* token;
    size_t token_len;
    flb_sds_t token_return = NULL;

    if (async) {
        /* A cached-token copy cannot yield on the main scheduler. Refresh and
         * payload mutation can, so wait before touching a refreshing cache. */
        if (ctx->auth_refreshing || flb_oauth2_token_expired(ctx->u_auth) == FLB_TRUE) {
            az_li_auth_acquire(ctx);
            owns_refresh = FLB_TRUE;
        }
    }
    else if (pthread_mutex_lock(&ctx->token_mutex)) {
        flb_plg_error(ctx->ins, "error locking mutex");
        return NULL;
    }
    /* Recheck after acquiring ownership: a preceding refresh may have filled the cache. */
    if (flb_oauth2_token_expired(ctx->u_auth) == FLB_TRUE) {
        flb_plg_debug(ctx->ins, "token expired. getting new token");
        /* Clear any previous oauth2 payload content */
        flb_oauth2_payload_clear(ctx->u_auth);

        ret = flb_oauth2_payload_append(ctx->u_auth, "grant_type", 10,
                                        "client_credentials", 18);
        if (ret == -1) {
            flb_plg_error(ctx->ins, "error appending oauth2 params");
            goto token_cleanup;
        }

        ret = flb_oauth2_payload_append(ctx->u_auth, "scope", 5, FLB_AZ_LI_AUTH_SCOPE,
                                        sizeof(FLB_AZ_LI_AUTH_SCOPE) - 1);
        if (ret == -1) {
            flb_plg_error(ctx->ins, "error appending oauth2 params");
            goto token_cleanup;
        }

        ret = flb_oauth2_payload_append(ctx->u_auth, "client_id", 9,
                                        ctx->client_id, -1);
        if (ret == -1) {
            flb_plg_error(ctx->ins, "error appending oauth2 params");
            goto token_cleanup;
        }

        ret = flb_oauth2_payload_append(ctx->u_auth, "client_secret", 13,
                                        ctx->client_secret, -1);
        if (ret == -1) {
            flb_plg_error(ctx->ins, "error appending oauth2 params");
            goto token_cleanup;
        }

        token = az_li_token_request(ctx);

        /* Copy string to prevent race conditions */
        if (!token) {
            flb_plg_error(ctx->ins, "error retrieving oauth2 access token");
            goto token_cleanup;
        }
        flb_plg_debug(ctx->ins, "got azure token");
    }

    /* Reached this code-block means, got new token or token not expired */
    /* Either way we copy the token to a new string */
    token_len = flb_sds_len(ctx->u_auth->token_type) + 2 +
                    flb_sds_len(ctx->u_auth->access_token);
    flb_plg_debug(ctx->ins, "create token header string");
    /* Now create */
    token_return = flb_sds_create_size(token_len);
    if (!token_return) {
        flb_plg_error(ctx->ins, "error creating token buffer");
        goto token_cleanup;
    }
    flb_sds_snprintf(&token_return, flb_sds_alloc(token_return), "%s %s",
                        ctx->u_auth->token_type, ctx->u_auth->access_token);

token_cleanup:
    if (owns_refresh) {
        ctx->auth_refreshing = FLB_FALSE;
        /* Success releases cache readers; failure lets the next waiter refresh. */
        az_li_notify(ctx);
    }
    if (!async && pthread_mutex_unlock(&ctx->token_mutex)) {
        flb_plg_error(ctx->ins, "error unlocking mutex");
        flb_sds_destroy(token_return);
        return NULL;
    }

    return token_return;
}

static uint64_t az_li_now_ms(void)
{
#ifdef FLB_SYSTEM_WINDOWS
    return (uint64_t) GetTickCount64();
#else
    struct timespec now;

    clock_gettime(CLOCK_MONOTONIC, &now);
    return (uint64_t) now.tv_sec * 1000 + now.tv_nsec / 1000000;
#endif
}

/* Keep the manual client-credentials form, TLS context and OAuth parser/cache.
 * The generic token helper can parse a partial 200 after flb_http_do fails;
 * promote tokens only after a complete exchange. The caller owns refresh access. */
static char *az_li_token_request(struct flb_az_li *ctx)
{
    struct flb_oauth2 *auth = ctx->u_auth;
    struct flb_connection *conn = NULL;
    struct flb_http_client *client = NULL;
    int saved_flags = flb_stream_get_flags(&auth->u->base);
    int index;
    int ret;
    size_t sent;
    char *token = NULL;

    for (index = 0; index < 2; index++) {
        if (index == 1) {
            flb_stream_enable_flags(&auth->u->base, FLB_IO_IPV6);
        }
        conn = flb_upstream_conn_get(auth->u);
        if (conn) {
            break;
        }
    }
    if (!conn) {
        /* A failed fallback must not discard an existing IPv6 preference.
         * Keep a successful fallback's preference, like the OAuth helper. */
        flb_stream_set_flags(&auth->u->base, saved_flags);
        return NULL;
    }
    client = flb_http_client(conn, FLB_HTTP_POST, auth->uri,
                             auth->payload, flb_sds_len(auth->payload),
                             auth->host, atoi(auth->port), NULL, 0);
    if (!client) {
        goto cleanup;
    }
    ret = flb_http_add_header(client, FLB_HTTP_HEADER_CONTENT_TYPE,
                              sizeof(FLB_HTTP_HEADER_CONTENT_TYPE) - 1,
                              FLB_OAUTH2_HTTP_ENCODING, sizeof(FLB_OAUTH2_HTTP_ENCODING) - 1);
    if (ret != 0) {
        goto cleanup;
    }
    ret = flb_http_do(client, &sent);
    if (ret != 0) {
        goto cleanup;
    }
    /* Unlike a partial 200 response, a completed token response may refresh
     * the cache. HTTP errors are never retried here. */
    if (client->resp.status == 200 && client->resp.payload_size > 0 &&
        flb_oauth2_parse_json_response(client->resp.payload,
                                       client->resp.payload_size, auth) == 0) {
        token = auth->access_token;
    }

cleanup:
    if (client) {
        flb_http_client_destroy(client);
    }
    /* OAuth never keeps a connection, even after a successful exchange. */
    flb_upstream_conn_recycle(conn, FLB_FALSE);
    flb_upstream_conn_release(conn);
    return token;
}

struct az_li_body {
    void *data;
    size_t size;
    size_t json_size;
    int compressed;
};

/* Unbatched mode keeps its one-shot compression. */
static void az_li_prepare_single(struct flb_az_li *ctx, flb_sds_t json,
                                 struct az_li_body *body)
{
    void *compressed;
    size_t compressed_size;

    body->data = json;
    body->size = flb_sds_len(json);
    body->json_size = body->size;
    body->compressed = FLB_FALSE;
    if (!ctx->compress_enabled) {
        return;
    }
    if (flb_gzip_compress(json, body->size, &compressed, &compressed_size) != 0) {
        flb_plg_error(ctx->ins, "cannot gzip payload, disabling compression");
        return;
    }
    body->data = compressed;
    body->size = compressed_size;
    body->compressed = FLB_TRUE;
    flb_plg_debug(ctx->ins, "enabled payload gzip compression");
    flb_sds_destroy(json);
}

/* Own the exact prepared bytes through HTTP-client cleanup; never recompress. */
static int az_li_send(struct flb_az_li *ctx, struct az_li_body *body, int chunk_count)
{
    int ret;
    int flush_status = FLB_RETRY;
    size_t b_sent;
    size_t final_payload_size = body->size;
    flb_sds_t token = NULL;
    struct flb_connection *u_conn = NULL;
    struct flb_http_client *c = NULL;
#ifdef FLB_HAVE_METRICS
    char status[16];
#endif

    token = get_az_li_token(ctx);
    if (!token) {
        goto cleanup;
    }
    u_conn = flb_upstream_conn_get(ctx->u_dce);
    if (!u_conn) {
        goto cleanup;
    }

    /* The HTTP client borrows the prepared buffer until it is destroyed. */
    c = flb_http_client(u_conn, FLB_HTTP_POST, ctx->dce_u_url,
                        body->data, final_payload_size, NULL, 0, NULL, 0);

    if (!c) {
        flb_plg_warn(ctx->ins, "retrying payload bytes=%lu", final_payload_size);
        flush_status = FLB_RETRY;
        goto cleanup;
    }

    /* Append headers */
    flb_http_add_header(c, "User-Agent", 10, "Fluent-Bit", 10);
    flb_http_add_header(c, "Content-Type", 12, "application/json", 16);
    if (body->compressed) {
        flb_http_add_header(c, "Content-Encoding", 16, "gzip", 4);
    }
    flb_http_add_header(c, "Authorization", 13, token, flb_sds_len(token));
    flb_http_buffer_size(c, FLB_HTTP_DATA_SIZE_MAX);

#ifdef FLB_HAVE_METRICS
    if (ctx->cmt_chunks_per_request) {
        cmt_histogram_observe(ctx->cmt_chunks_per_request, cfl_time_now(),
                              (double) chunk_count,
                              2, (char *[]) {(char *) flb_output_name(ctx->ins), ctx->dcr_id});
    }
#endif
    /* Execute rest call */
    ret = flb_http_do(c, &b_sent);
#ifdef FLB_HAVE_METRICS
    /* Only completed HTTP exchanges count. A transport error may leave a partial
     * status in the client; deliberately exclude it rather than invent a response. */
    if (ret == 0 && c->resp.status >= 100 && c->resp.status <= 599 && ctx->cmt_http_responses) {
        snprintf(status, sizeof(status), "%i", c->resp.status);
        cmt_counter_inc(ctx->cmt_http_responses, cfl_time_now(),
                        3, (char *[]) {(char *) flb_output_name(ctx->ins), ctx->dcr_id, status});
    }
#endif
    if (ret != 0) {
        /* Do not reuse a connection with an incomplete HTTP exchange. */
        flb_upstream_conn_recycle(u_conn, FLB_FALSE);
        flb_plg_warn(ctx->ins, "http_do=%i", ret);
        flush_status = FLB_RETRY;
        goto cleanup;
    }
    else {
        if (c->resp.status >= 200 && c->resp.status <= 299) {
            flb_plg_info(ctx->ins, "http_status=%i, dcr_id=%s, table=%s",
                         c->resp.status, ctx->dcr_id, ctx->table_name);
            flush_status = FLB_OK;
            goto cleanup;
        }
        else {
            if (c->resp.payload_size > 0) {
                flb_plg_warn(ctx->ins, "http_status=%i:\n%s",
                             c->resp.status, c->resp.payload);
            }
            else {
                flb_plg_warn(ctx->ins, "http_status=%i", c->resp.status);
            }
            flb_plg_debug(ctx->ins, "retrying payload bytes=%lu", final_payload_size);
            flush_status = FLB_RETRY;
            goto cleanup;
        }
    }

cleanup:
    if (c) {
        flb_http_client_destroy(c);
    }
    if (body->compressed) {
        flb_free(body->data);
    }
    else {
        flb_sds_destroy(body->data);
    }
    body->data = NULL;
    if (u_conn) {
        flb_upstream_conn_release(u_conn);
    }

    /* destory token at last after HTTP call has finished */
    if (token) {
        flb_sds_destroy(token);
    }
    return flush_status;
}

/* Membership borrows postprocessor chunks until every request outcome is published.
 * Only the dispatcher resumes plugin-parked callbacks, never a sender in network I/O. */
struct az_li_batch {
    struct mk_list members;
    int count;
    size_t json_size;
    size_t emitted_size;
    struct az_li_gzip_stream *gzip;
    int references;
    int result;
    uint64_t deadline;
};

struct az_li_member {
    struct mk_list member_link;
    struct mk_list parked_link;
    struct az_li_batch *batch;
    struct flb_coro *coro;
    flb_sds_t formatted;
    int comma;
    int send;
};

static int az_li_notification_interrupted(void)
{
#ifdef FLB_SYSTEM_WINDOWS
    return WSAGetLastError() == WSAEINTR;
#else
    return errno == EINTR;
#endif
}

static void az_li_notify(struct flb_az_li *ctx)
{
    unsigned char notification = 1;
    ssize_t ret;

    if (ctx->notification_pending ||
        (mk_list_is_empty(&ctx->batch_ready) == 0 &&
         (ctx->auth_refreshing || mk_list_is_empty(&ctx->auth_waiters) == 0))) {
        return;
    }
    /* Main-thread ownership permits only one unread wake-up, not one per member. */
    do {
        ret = flb_pipe_w(ctx->continuation_channel[1], &notification, sizeof(notification));
    } while (ret == -1 && az_li_notification_interrupted());
    if (ret != sizeof(notification)) {
        flb_plg_error(ctx->ins, "cannot notify continuation dispatcher");
        return;
    }
    ctx->notification_pending = FLB_TRUE;
}

static void az_li_batch_close(struct flb_az_li *ctx)
{
    struct az_li_member *sender;

    /* A published collecting batch always has a member. Never elect an incoming non-member. */
    sender = mk_list_entry_first(&ctx->collecting->members, struct az_li_member, member_link);
    ctx->collecting = NULL;
    sender->send = FLB_TRUE;
    flb_plg_debug(ctx->ins, "batch closed: deadline=%" PRIu64 " now=%" PRIu64 " chunks=%i",
                  sender->batch->deadline, az_li_now_ms(), sender->batch->count);
    if (!mk_list_entry_is_orphan(&sender->parked_link)) {
        mk_list_del(&sender->parked_link);
        mk_list_add(&sender->parked_link, &ctx->batch_ready);
        az_li_notify(ctx);
    }
}

static void az_li_batch_tick(struct flb_config *config, void *data)
{
    struct flb_az_li *ctx = data;

    if (ctx->collecting && (az_li_now_ms() >= ctx->collecting->deadline ||
                           config->is_shutting_down)) {
        az_li_batch_close(ctx);
    }
    az_li_notify(ctx);
    if (mk_list_is_empty(&ctx->parked) == 0 && mk_list_is_empty(&ctx->batch_ready) == 0) {
        flb_sched_timer_cb_destroy(ctx->batch_timer);
        ctx->batch_timer = NULL;
    }
}

static int az_li_dispatch(void *data)
{
    struct mk_event *event = data;
    /* Backends can own event->data; the embedded event identifies this output. */
    struct flb_az_li *ctx = (struct flb_az_li *)
                          ((char *) event - offsetof(struct flb_az_li, continuation_event));
    struct az_li_member *member;
    struct az_li_auth_waiter *waiter;
    struct flb_coro *coro;
    unsigned char notification;
    ssize_t ret;
    int count;
    int batch_ready;
    int auth_ready;

    do {
        ret = flb_pipe_r(ctx->continuation_channel[0], &notification, sizeof(notification));
    } while (ret == -1 && az_li_notification_interrupted());
    if (ret != sizeof(notification)) {
        flb_plg_error(ctx->ins, "cannot read continuation notification");
        return -1;
    }
    ctx->notification_pending = FLB_FALSE;
    for (count = 0; count < AZ_LI_DISPATCH_LIMIT; count++) {
        batch_ready = mk_list_is_empty(&ctx->batch_ready) != 0;
        auth_ready = !ctx->auth_refreshing && mk_list_is_empty(&ctx->auth_waiters) != 0;
        if (!batch_ready && !auth_ready) {
            break;
        }
        /* Alternate eligible classes so neither a completion backlog nor token
         * waiters can starve the other. Both share the completion-pipe budget. */
        if (auth_ready && (!batch_ready || ctx->prefer_auth)) {
            waiter = mk_list_entry_first(&ctx->auth_waiters, struct az_li_auth_waiter, link);
            coro = waiter->coro;
            mk_list_del(&waiter->link);
            ctx->prefer_auth = FLB_FALSE;
        }
        else {
            member = mk_list_entry_first(&ctx->batch_ready, struct az_li_member, parked_link);
            coro = member->coro;
            mk_list_del(&member->parked_link);
            ctx->prefer_auth = FLB_TRUE;
        }
        /* Unlink before resuming: it may return or enter network IO. Recheck
         * refresh ownership each turn, especially after a failed refresh elects
         * a successor. Only the engine may resume that successor's network IO. */
        flb_coro_resume(coro);
    }
    az_li_notify(ctx);
    return 0;
}

static void az_li_batch_plain(struct flb_az_li *ctx, struct az_li_batch *batch)
{
    az_li_gzip_stream_destroy(batch->gzip);
    batch->gzip = NULL;
    flb_plg_warn(ctx->ins, "cannot stream gzip payload, using plain JSON for this batch");
}

static void az_li_batch_append(struct flb_az_li *ctx, struct az_li_batch *batch,
                                struct az_li_member *member, size_t size)
{
    size_t interior = size - 2;

    /* One owner of separator and empty-array rules for streaming and fallback.
     * No yield is allowed between membership admission and consuming these bytes.
     * json_size always includes both brackets, even before gzip receives ']'. */
    if (interior == 0) {
        return;
    }
    member->comma = batch->json_size > 2;
    batch->json_size += interior + member->comma;
    if (batch->gzip &&
        ((member->comma && az_li_gzip_stream_append(batch->gzip, ",", 1,
                                                    &batch->emitted_size) != 0) ||
         az_li_gzip_stream_append(batch->gzip, member->formatted + 1, interior,
                                  &batch->emitted_size) != 0)) {
        az_li_batch_plain(ctx, batch);
    }
}

static void az_li_batch_release_json(struct az_li_batch *batch)
{
    struct mk_list *head;
    struct az_li_member *member;

    mk_list_foreach(head, &batch->members) {
        member = mk_list_entry(head, struct az_li_member, member_link);
        flb_sds_destroy(member->formatted);
        member->formatted = NULL;
    }
}

static flb_sds_t az_li_batch_format(struct az_li_batch *batch)
{
    struct mk_list *head;
    struct az_li_member *member;
    flb_sds_t combined = NULL;
    size_t interior;
    size_t total = batch->json_size;
    size_t offset = 1;

    /* Keep member arrays until final size selection permits network IO.
     * SDS adds its allocation header and a NUL terminator. */
    if (total > SIZE_MAX - FLB_SDS_HEADER_SIZE - 1) {
        goto cleanup;
    }
    combined = flb_sds_create_size(total);
    if (!combined) {
        goto cleanup;
    }
    combined[0] = '[';
    mk_list_foreach(head, &batch->members) {
        member = mk_list_entry(head, struct az_li_member, member_link);
        interior = flb_sds_len(member->formatted) - 2;
        if (interior > 0) {
            if (member->comma) {
                combined[offset++] = ',';
            }
            memcpy(combined + offset, member->formatted + 1, interior);
            offset += interior;
        }
    }
    combined[offset++] = ']';
    combined[offset] = '\0';
    flb_sds_len_set(combined, offset);

cleanup:
    return combined;
}

static int az_li_batch_prepare(struct flb_az_li *ctx, struct az_li_batch *batch,
                               struct az_li_body *body)
{
    int ret;

    body->json_size = batch->json_size;
    if (batch->gzip) {
        ret = az_li_gzip_stream_append(batch->gzip, "]", 1, &batch->emitted_size);
        if (ret == 0) {
            ret = az_li_gzip_stream_finish(batch->gzip, &body->data, &body->size);
        }
        if (ret != 0) {
            az_li_batch_plain(ctx, batch);
        }
        else {
            az_li_gzip_stream_destroy(batch->gzip);
            batch->gzip = NULL;
            body->compressed = FLB_TRUE;
            return 0;
        }
    }
    body->compressed = FLB_FALSE;
    body->data = az_li_batch_format(batch);
    body->size = body->data ? flb_sds_len(body->data) : 0;
    return body->data ? 0 : -1;
}

static void az_li_batch_rebuild(struct flb_az_li *ctx, struct az_li_batch *batch)
{
    struct mk_list *head;
    struct az_li_member *member;

    az_li_gzip_stream_destroy(batch->gzip);
    batch->gzip = NULL;
    batch->json_size = 2;
    batch->emitted_size = 0;
    if (ctx->compress_enabled) {
        batch->gzip = az_li_gzip_stream_create();
        if (!batch->gzip ||
            az_li_gzip_stream_append(batch->gzip, "[", 1, &batch->emitted_size) != 0) {
            az_li_batch_plain(ctx, batch);
        }
    }
    mk_list_foreach(head, &batch->members) {
        member = mk_list_entry(head, struct az_li_member, member_link);
        member->comma = 0;
        az_li_batch_append(ctx, batch, member, flb_sds_len(member->formatted));
    }
}

static int az_li_batch_prepare_bounded(struct flb_az_li *ctx, struct az_li_batch *batch,
                                       struct az_li_body *body)
{
    struct az_li_batch *remainder = NULL;
    struct az_li_member *member;
    int ret;

    while (1) {
        ret = az_li_batch_prepare(ctx, batch, body);
        if (ret != 0 || body->size <= FLB_AZ_LI_MAX_BODY_BYTES || batch->count == 1) {
            break;
        }
        if (body->compressed) {
            flb_free(body->data);
        }
        else {
            flb_sds_destroy(body->data);
        }
        memset(body, 0, sizeof(*body));
        if (!remainder) {
            remainder = flb_calloc(1, sizeof(*remainder));
            if (!remainder) {
                ret = -1;
                break;
            }
            mk_list_init(&remainder->members);
            remainder->deadline = batch->deadline;
        }
        /* Only trailing members move, so the active sender stays in this batch.
         * Prepend to preserve the original order across repeated removals. */
        member = mk_list_entry_last(&batch->members, struct az_li_member, member_link);
        mk_list_del(&member->member_link);
        mk_list_add_before(&member->member_link, remainder->members.next, &remainder->members);
        member->batch = remainder;
        batch->count--;
        batch->references--;
        remainder->count++;
        remainder->references++;
        az_li_batch_rebuild(ctx, batch);
    }
    if (remainder) {
        /* Removed chunks keep their own callbacks and request outcome. They are
         * already overdue or size-closed, not a new collection window. */
        az_li_batch_rebuild(ctx, remainder);
        member = mk_list_entry_first(&remainder->members, struct az_li_member, member_link);
        member->send = FLB_TRUE;
        mk_list_del(&member->parked_link);
        mk_list_add(&member->parked_link, &ctx->batch_ready);
        az_li_notify(ctx);
    }
    return ret;
}

static void cb_azure_logs_ingestion_flush(struct flb_event_chunk *event_chunk,
                           struct flb_output_flush *out_flush,
                           struct flb_input_instance *i_ins,
                           void *out_context,
                           struct flb_config *config)
{
    struct flb_az_li *ctx = out_context;
    struct az_li_batch *batch;
    struct az_li_batch *replacement = NULL;
    struct az_li_member member = {0};
    struct az_li_member *peer;
    struct mk_list *head;
    flb_sds_t payload = NULL;
    struct az_li_body body = {0};
    size_t size;
    uint64_t created_at = 0;
    int result;

    if (ctx->batch_wait_ms == 0) {
        if (az_li_format(event_chunk->data, event_chunk->size, &payload, &size,
                         ctx, config) != 0) {
            FLB_OUTPUT_RETURN(FLB_ERROR);
        }
        az_li_prepare_single(ctx, payload, &body);
        result = az_li_send(ctx, &body, 1);
        FLB_OUTPUT_RETURN(result);
    }

    /* The callback owns its final array until admission; malformed chunks cannot
     * poison an existing batch or leave a partially initialized member behind. */
    if (az_li_format(event_chunk->data, event_chunk->size, &member.formatted, &size,
                     ctx, config) != 0 || size < 2 || member.formatted[0] != '[' ||
        member.formatted[size - 1] != ']') {
        flb_sds_destroy(member.formatted);
        FLB_OUTPUT_RETURN(FLB_ERROR);
    }

    batch = ctx->collecting;
    if (batch && (batch->count == INT_MAX ||
                  (size > 2 && size - 2 > SIZE_MAX - batch->json_size -
                                         (batch->json_size > 2)))) {
        flb_sds_destroy(member.formatted);
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }
    if (!batch) {
        replacement = flb_calloc(1, sizeof(*replacement));
        if (!replacement) {
            flb_sds_destroy(member.formatted);
            FLB_OUTPUT_RETURN(FLB_RETRY);
        }
        mk_list_init(&replacement->members);
        replacement->json_size = 2;
        created_at = az_li_now_ms();
        replacement->deadline = created_at + ctx->batch_wait_ms;
    }

    /* Only callbacks parked by the plugin need polling; idle outputs need no timer. */
    if (!ctx->batch_timer &&
        flb_sched_timer_cb_create(flb_sched_ctx_get(), FLB_SCHED_TIMER_CB_PERM,
                                  10, az_li_batch_tick, ctx, &ctx->batch_timer) != 0) {
        flb_plg_error(ctx->ins, "cannot create batch timer");
        flb_free(replacement);
        flb_sds_destroy(member.formatted);
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }

    if (replacement) {
        if (batch) {
            az_li_batch_close(ctx);
        }
        batch = replacement;
        ctx->collecting = batch;
        flb_plg_debug(ctx->ins, "batch created: now=%" PRIu64 " deadline=%" PRIu64,
                      created_at, batch->deadline);
        if (ctx->compress_enabled) {
            batch->gzip = az_li_gzip_stream_create();
            if (!batch->gzip ||
                az_li_gzip_stream_append(batch->gzip, "[", 1, &batch->emitted_size) != 0) {
                az_li_batch_plain(ctx, batch);
            }
        }
    }
    member.batch = batch;
    member.coro = flb_coro_get();
    mk_list_add(&member.member_link, &batch->members);
    batch->count++;
    batch->references++;
    az_li_batch_append(ctx, batch, &member, size);
    if ((batch->gzip ? batch->emitted_size : batch->json_size) >= ctx->batch_target_size ||
        az_li_now_ms() >= batch->deadline || config->is_shutting_down) {
        az_li_batch_close(ctx);
    }
    if (!member.send) {
        mk_list_add(&member.parked_link, &ctx->parked);
        flb_coro_yield(member.coro, FLB_FALSE);
    }

    /* Overflow rebuilding can move a parked member to a different closed batch. */
    batch = member.batch;
    if (member.send) {
        result = az_li_batch_prepare_bounded(ctx, batch, &body);
        az_li_batch_release_json(batch);
        batch->result = result == 0 ? az_li_send(ctx, &body, batch->count) : FLB_RETRY;
        /* No peer may return until HTTP client, body and connection cleanup finishes. */
        mk_list_foreach(head, &batch->members) {
            peer = mk_list_entry(head, struct az_li_member, member_link);
            if (peer != &member) {
                mk_list_del(&peer->parked_link);
                mk_list_add(&peer->parked_link, &ctx->batch_ready);
            }
        }
        az_li_notify(ctx);
    }
    result = batch->result;
    mk_list_del(&member.member_link);
    if (--batch->references == 0) {
        flb_free(batch);
    }
    FLB_OUTPUT_RETURN(result);
}

static int cb_azure_logs_ingestion_exit(void *data, struct flb_config *config)
{
    struct flb_az_li *ctx = data;

    if (!ctx) {
        return 0;
    }

    if (ctx->batch_timer) {
        flb_sched_timer_cb_destroy(ctx->batch_timer);
    }
    /* Stop notification delivery without touching stack-owned waiter links:
     * forced teardown may already have destroyed their engine coroutines. */
    if (ctx->continuation_channel[0] != -1) {
        mk_event_channel_destroy(config->evl, ctx->continuation_channel[0],
                                ctx->continuation_channel[1], &ctx->continuation_event);
    }
    flb_plg_debug(ctx->ins, "exiting logs ingestion plugin");
    flb_az_li_ctx_destroy(ctx);
    return 0;
}

/* Configuration properties map */
static struct flb_config_map config_map[] = {
    {
     FLB_CONFIG_MAP_STR, "tenant_id", (char *)NULL,
     0, FLB_TRUE, offsetof(struct flb_az_li, tenant_id),
     "Set the tenant ID of the AAD application"
    },
    {
     FLB_CONFIG_MAP_STR, "client_id", (char *)NULL,
     0, FLB_TRUE, offsetof(struct flb_az_li, client_id),
     "Set the client/app ID of the AAD application"
    },
    {
     FLB_CONFIG_MAP_STR, "client_secret", (char *)NULL,
     0, FLB_TRUE, offsetof(struct flb_az_li, client_secret),
     "Set the client secret of the AAD application"
    },
    {
     FLB_CONFIG_MAP_STR, "auth_url", (char *)NULL,
     0, FLB_TRUE, offsetof(struct flb_az_li, auth_url_override),
     "[Optional] Override the OAuth2 token endpoint."
    },
    {
     FLB_CONFIG_MAP_STR, "dce_url", (char *)NULL,
     0, FLB_TRUE, offsetof(struct flb_az_li, dce_url),
     "Data Collection Endpoint(DCE) URI (e.g. "
     "https://la-endpoint-q12a.eastus-1.ingest.monitor.azure.com)"
    },
    {
     FLB_CONFIG_MAP_STR, "dcr_id", (char *)NULL,
     0, FLB_TRUE, offsetof(struct flb_az_li, dcr_id),
     "Data Collection Rule (DCR) immutable ID"
    },
    {
     FLB_CONFIG_MAP_STR, "table_name", (char *)NULL,
     0, FLB_TRUE, offsetof(struct flb_az_li, table_name),
     "The name of the custom log table, including '_CL' suffix"
    },
    /* Omission preserves single-chunk flushes. */
    {
     FLB_CONFIG_MAP_STR, "batch_wait_ms", NULL,
     0, FLB_FALSE, 0,
     "Positive collection wait in milliseconds from the first chunk; requires workers=0."
    },
    {
     FLB_CONFIG_MAP_STR, "batch_target_size", "800000",
     0, FLB_FALSE, 0,
     "Soft outgoing-body target in bytes, from 1 to 1048576 without size suffixes. "
     "Close after whole-chunk admission when emitted gzip bytes, or plain JSON bytes, reach the target. "
     "Rebuild oversized aggregates at whole-chunk boundaries to fit the 1048576-byte wire limit. "
     "Does not enable batching without batch_wait_ms."
    },
    /* optional params */
    {
     FLB_CONFIG_MAP_STR, "time_key", FLB_AZ_LI_TIME_KEY,
     0, FLB_TRUE, offsetof(struct flb_az_li, time_key),
     "[Optional] Specify the key name where the timestamp will be stored."
    },
    {
     FLB_CONFIG_MAP_BOOL, "time_generated", "false",
     0, FLB_TRUE, offsetof(struct flb_az_li, time_generated),
     "If enabled, will generate a timestamp and append it to JSON. "
     "The key name is set by the 'time_key' parameter"
    },
    {
     FLB_CONFIG_MAP_BOOL, "compress", "false",
     0, FLB_TRUE,  offsetof(struct flb_az_li, compress_enabled),
     "Enable HTTP payload compression (gzip)."
    },
    /* EOF */
    {0}
};

struct flb_output_plugin out_azure_logs_ingestion_plugin = {
    .name         = "azure_logs_ingestion",
    .description  = "Send logs to Log Analytics with Log Ingestion API",
    .cb_init      = cb_azure_logs_ingestion_init,
    .cb_flush     = cb_azure_logs_ingestion_flush,
    .cb_exit      = cb_azure_logs_ingestion_exit,

    /* Configuration */
    .config_map     = config_map,

    /* Plugin flags */
    .flags          = FLB_OUTPUT_NET | FLB_IO_TLS,
};
