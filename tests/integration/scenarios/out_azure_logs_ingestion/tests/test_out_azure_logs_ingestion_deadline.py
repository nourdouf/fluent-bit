"""Local real-network coverage for native, independent HTTP request timeouts."""
import json
import logging
import socket
import socketserver
import ssl
import threading
import time
from pathlib import Path

import pytest
import requests
import yaml

from server import http_server
from test_out_azure_logs_ingestion_batch import (
    batch_service, metrics, request_metric, RESPONSES, stop_checked,
)


def timeout_service(tmp_path, response_timeout="5s"):
    service = batch_service(tmp_path, count=0, wait_ms=10)
    port = service.service.allocate_port_env("TEST_TIMEOUT_INPUT_PORT")
    path = Path(service.service.config_path)
    config = yaml.safe_load(path.read_text())
    config["service"].update({"flush": 0.05, "scheduler.base": 1, "scheduler.cap": 1})
    config["pipeline"]["inputs"] = [
        {"name": "http", "listen": "127.0.0.1", "port": port}]
    config["pipeline"]["outputs"][0].update(
        {"batch_chunk_count": 1, "retry_limit": "no_retries"})
    if response_timeout is not None:
        config["pipeline"]["outputs"][0]["http.response_timeout"] = response_timeout
    path.write_text(yaml.safe_dump(config))
    return service, port


def submit(port, chunk_id):
    response = requests.post(f"http://127.0.0.1:{port}/chunk.{chunk_id}",
                             json={"chunk_id": chunk_id}, timeout=2)
    response.raise_for_status()


def wait(service, predicate, description, timeout=10):
    return service.service.wait_for_condition(predicate, timeout=timeout, interval=0.02,
                                              description=description)


def dropped_callbacks(service, count):
    # V1 counters are periodically snapshotted; use the engine's own callback
    # completion log for the timeout, then separately check the published counters.
    return Path(service.flb.log_file).read_text().count("is not retried (no retry config)") >= count


def test_oauth_and_ingestion_have_independent_response_timeouts(tmp_path, monkeypatch):
    service, port = timeout_service(tmp_path)
    oauth_started = []
    original = http_server.app.view_functions["oauth_token"]

    def token_receiver():
        oauth_started.append(time.monotonic())
        return original()

    monkeypatch.setitem(http_server.app.view_functions, "oauth_token", token_receiver)
    try:
        service.start()
        http_server.configure_oauth_token_response(delay_seconds=3)
        http_server.configure_http_response(delay_seconds=3)
        submit(port, 0)
        wait(service, lambda: oauth_started, "OAuth request")
        wait(service, lambda: metrics(service)["proc_records"] == 1,
             "both individually valid requests complete", timeout=9)
        elapsed = time.monotonic() - oauth_started[0]
        assert elapsed >= 6  # The sum exceeds the 5s per-request setting.
        assert not dropped_callbacks(service, 1)
        http_server.configure_http_response(delay_seconds=0)
        submit(port, 1)
        wait(service, lambda: metrics(service)["proc_records"] == 2, "cached token delivery")
        tokens = [r for r in http_server.data_storage["requests"] if r["path"] == "/oauth/token"]
        assert len(tokens) == 1  # production token cache avoids another OAuth request
        body = tokens[0]["raw_data"]
        for field in ("grant_type=client_credentials", "scope=https://monitor.azure.com/.default",
                      "client_id=suite-client", "client_secret=suite-secret"):
            assert field in body
        ingestion = [r for r in http_server.data_storage["requests"]
                     if r["path"].startswith("/dataCollectionRules/")]
        assert len(ingestion) == 2
        assert all(r["headers"]["Authorization"] == "Bearer oauth-access-token" for r in ingestion)
    finally:
        stop_checked(service)


def test_response_timeout_with_connection_timeout_disabled(tmp_path, monkeypatch):
    service, port = timeout_service(tmp_path, response_timeout="2s")
    set_output(service, **{"net.connect_timeout": 0})
    started = []
    original = http_server.app.view_functions["oauth_token"]

    def token_receiver():
        started.append(time.monotonic())
        return original()

    monkeypatch.setitem(http_server.app.view_functions, "oauth_token", token_receiver)
    try:
        service.start()
        http_server.configure_http_response(delay_seconds=4)
        submit(port, 0)
        wait(service, lambda: started, "initial OAuth")
        wait(service, lambda: dropped_callbacks(service, 1),
             "response timeout independent of disabled connect timeout", timeout=5)
        elapsed = time.monotonic() - started[0]
        assert 1 <= elapsed < 5, elapsed
        assert metrics(service)["proc_records"] == 0
        http_server.configure_http_response(delay_seconds=0)
        submit(port, 1)
        wait(service, lambda: metrics(service)["proc_records"] == 1, "healthy recovery")
    finally:
        stop_checked(service)


@pytest.mark.parametrize("count", [1, 3])
def test_native_timeout_preserves_busy_connection_count(tmp_path, count):
    service, port = timeout_service(tmp_path, response_timeout="3s")
    gauge = "fluentbit_output_upstream_busy_connections"
    total_gauge = "fluentbit_output_upstream_total_connections"
    labels = {"name": "azure_logs_ingestion.0"}
    try:
        service.start()
        http_server.configure_http_response(delay_seconds=5)
        for chunk_id in range(count):
            submit(port, chunk_id)
        wait(service, lambda: request_metric(service, gauge, **labels) == count,
             "all ingestion connections busy", timeout=2.7)
        assert request_metric(service, total_gauge, **labels) == count
        wait(service, lambda: dropped_callbacks(service, count), "all requests timed out", timeout=6)
        wait(service, lambda: request_metric(service, gauge, **labels) <= 0,
             "busy connection count after cleanup")
        assert request_metric(service, gauge, **labels) == 0
        wait(service, lambda: request_metric(service, total_gauge, **labels) <= 0,
             "cancelled ingestion connections destroyed")
        assert request_metric(service, total_gauge, **labels) == 0
        http_server.configure_http_response(delay_seconds=0)
        submit(port, count)
        wait(service, lambda: metrics(service)["proc_records"] == 1, "healthy recovery")
        wait(service, lambda: request_metric(service, gauge, **labels) == 0,
             "recovered connection released")
    finally:
        stop_checked(service)


def test_token_refresh_is_single_flight_and_keeps_engine_responsive(tmp_path, monkeypatch):
    service, port = timeout_service(tmp_path)
    token_times = []
    original = http_server.app.view_functions["oauth_token"]

    def token_receiver():
        token_times.append(time.monotonic())
        return original()

    monkeypatch.setitem(http_server.app.view_functions, "oauth_token", token_receiver)
    try:
        service.start()
        http_server.configure_oauth_token_response(delay_seconds=3)
        submit(port, 0)
        wait(service, lambda: token_times, "refresh owner in OAuth")
        for chunk_id in range(1, 8):
            submit(port, chunk_id)
        samples = []
        while time.monotonic() - token_times[0] < 2:
            before = time.monotonic()
            assert metrics(service)["proc_records"] == 0
            samples.append(time.monotonic() - before)
            time.sleep(0.1)  # Sample event-loop responsiveness during contention.
        assert samples and max(samples) < 0.5, samples
        wait(service, lambda: metrics(service)["proc_records"] == 8,
             "owner and every waiter acknowledged once")
        assert len(token_times) == 1
        assert not dropped_callbacks(service, 1)
        ingestion = [r for r in http_server.data_storage["requests"]
                     if r["path"].startswith("/dataCollectionRules/")]
        assert len(ingestion) == 8
    finally:
        stop_checked(service)


# Native response timeout starts after upload; response bytes do not reset it.
@pytest.mark.parametrize("stage", ["oauth", "ingestion"])
@pytest.mark.parametrize("mode", ["blocked", "trickle"])
def test_response_progress_does_not_extend_response_timeout(tmp_path, monkeypatch, stage, mode):
    service, port = timeout_service(tmp_path)
    started = []
    original = http_server.app.view_functions["oauth_token"]

    def token_receiver():
        started.append(time.monotonic())
        return original()

    monkeypatch.setitem(http_server.app.view_functions, "oauth_token", token_receiver)
    configure = (http_server.configure_oauth_token_response if stage == "oauth"
                 else http_server.configure_http_response)
    try:
        service.start()
        if mode == "blocked":
            configure(hang_before_response=True)
        else:
            configure(stream_fragments=[" "] * 32, fragment_delay_seconds=0.25)
        submit(port, 0)
        wait(service, lambda: started, "initial OAuth")
        wait(service, lambda: dropped_callbacks(service, 1),
             "blocked or trickling response times out", timeout=8)
        elapsed = time.monotonic() - started[0]
        logging.getLogger(__name__).info("response stage=%s mode=%s elapsed=%.3fs", stage, mode, elapsed)
        assert 4 <= elapsed < 8
        assert metrics(service)["proc_records"] == 0
        assert request_metric(service, RESPONSES, name="azure_logs_ingestion.0",
                              dcr_id="dcr-suite", status="200") == 0
        configure(hang_before_response=False, stream_fragments=None)
        submit(port, 1)
        wait(service, lambda: metrics(service)["proc_records"] == 1, "post-cancel recovery")
    finally:
        stop_checked(service)


class WireReceiver:
    """A local socket peer, not a replacement for any Fluent Bit transport code."""
    def __init__(self, service, mode, first_close=False):
        self.mode = mode
        self.first_close = first_close
        self.accepted = []
        self.uploads = []
        self.closing = threading.Event()
        receiver = self
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(service.tls_crt_file, service.tls_key_file)

        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                receiver.accepted.append(time.monotonic())
                if receiver.first_close and len(receiver.accepted) == 1:
                    return  # Early connection failure must retain OAuth's second getter.
                self.request.settimeout(10)
                if receiver.mode == "tls":
                    self.request.recv(4096)  # ClientHello; never send ServerHello.
                    receiver.closing.wait(15)
                    return
                try:
                    with tls.wrap_socket(self.request, server_side=True) as connection:
                        data = b""
                        while b"\r\n\r\n" not in data:
                            fragment = connection.recv(4096)
                            if not fragment:
                                return
                            data += fragment
                        headers, body = data.split(b"\r\n\r\n", 1)
                        length = int(next(line.split(b":", 1)[1] for line in headers.split(b"\r\n")
                                          if line.lower().startswith(b"content-length:")))
                        if not body and length:
                            body = connection.recv(1)
                        upload = {"received": len(body), "length": length}
                        receiver.uploads.append(upload)
                        while upload["received"] < length and not receiver.closing.is_set():
                            if receiver.mode == "blocked":
                                receiver.closing.wait(15)
                                return
                            fragment = connection.recv(1024 if receiver.mode == "trickle" else 65536)
                            if not fragment:
                                return
                            upload["received"] += len(fragment)
                            if receiver.mode == "trickle":
                                receiver.closing.wait(0.1)
                        connection.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}")
                except (OSError, ssl.SSLError):
                    pass  # Peer cancellation is precisely the behavior under test.

        class Server(socketserver.ThreadingTCPServer):
            daemon_threads = True

        self.server = Server(("127.0.0.1", 0), Handler)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def close(self):
        self.closing.set()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


class KeepaliveReceiver:
    """Keep the peer open after bad framing; observe which socket carries the retry."""
    def __init__(self, service, failure, use_tls):
        self.requests = []
        self.connections = []
        self.errors = []
        self.closing = threading.Event()
        self.release_retry = threading.Event()
        self.lock = threading.Lock()
        receiver = self
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(service.tls_crt_file, service.tls_key_file)

        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                closed = threading.Event()
                with receiver.lock:
                    connection_id = len(receiver.connections)
                    receiver.connections.append(closed)
                self.request.settimeout(5)
                try:
                    transport = (tls.wrap_socket(self.request, server_side=True)
                                 if use_tls else self.request)
                    with transport as connection:
                        connection.settimeout(0.2)
                        pending = b""
                        while not receiver.closing.is_set():
                            if b"\r\n\r\n" in pending:
                                headers, body = pending.split(b"\r\n\r\n", 1)
                                length = int(next(line.split(b":", 1)[1]
                                                  for line in headers.split(b"\r\n")
                                                  if line.lower().startswith(b"content-length:")))
                                if len(body) >= length:
                                    item = {"connection": connection_id, "headers": headers,
                                            "body": body[:length], "time": time.monotonic()}
                                    pending = body[length:]
                                    with receiver.lock:
                                        receiver.requests.append(item)
                                        first = len(receiver.requests) == 1
                                    if first and failure == "malformed":
                                        # Invalid chunk length fails the HTTP parser immediately,
                                        # without EOF, a socket error, or a timeout.
                                        connection.sendall(
                                            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n"
                                            b"Connection: keep-alive\r\n\r\nnot-hex\r\n")
                                        continue
                                    if first and failure == "incomplete_token":
                                        # Valid JSON is not a complete HTTP response. The declared
                                        # body has a missing byte, followed by EOF from the peer.
                                        payload = json.dumps({"access_token": "partial-token",
                                                              "token_type": "Bearer",
                                                              "expires_in": 300}).encode()
                                        connection.sendall(
                                            (f"HTTP/1.1 200 OK\r\nContent-Length: {len(payload) + 1}\r\n"
                                             "Connection: keep-alive\r\n\r\n").encode() + payload)
                                        connection.shutdown(socket.SHUT_WR)
                                        continue
                                    if not first:
                                        if not receiver.release_retry.wait(15):
                                            receiver.errors.append("healthy response gate expired")
                                            return
                                        if receiver.closing.is_set():
                                            return
                                    status = 500 if first and failure == "http_error" else 200
                                    payload = b"{}"
                                    if b" /oauth/token " in headers and not first:
                                        payload = json.dumps({"access_token": "wire-token",
                                                              "token_type": "Bearer",
                                                              "expires_in": 300}).encode()
                                    response = (f"HTTP/1.1 {status} Response\r\n"
                                                f"Content-Length: {len(payload)}\r\n"
                                                "Content-Type: application/json\r\n"
                                                "Connection: keep-alive\r\n\r\n").encode()
                                    connection.sendall(response + payload)
                                    continue
                            try:
                                fragment = connection.recv(65536)
                            except socket.timeout:
                                continue
                            if not fragment:
                                return
                            pending += fragment
                except (OSError, ssl.SSLError):
                    pass  # Client-initiated cancellation/close is observed below.
                finally:
                    closed.set()

        class Server(socketserver.ThreadingTCPServer):
            # close() releases the response gate and polling reads before joining handlers.
            daemon_threads = False

        self.server = Server(("127.0.0.1", 0), Handler)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def close(self):
        self.closing.set()
        self.release_retry.set()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


@pytest.mark.parametrize("stage,failure", [
    ("oauth", "malformed"), ("ingestion", "malformed"),
    ("oauth", "http_error"), ("ingestion", "http_error"),
    ("oauth", "invalid_token"), ("oauth", "incomplete_token"),
])
def test_failed_exchange_connection_disposition_and_engine_recovery(tmp_path, stage, failure):
    service, port = timeout_service(tmp_path)
    receiver = KeepaliveReceiver(service, failure, use_tls=stage == "ingestion")
    # OAuth uses its own trust context, not the output's test CA configuration.
    endpoint = (f"http://127.0.0.1:{receiver.port}" if stage == "oauth"
                else f"https://localhost:{receiver.port}")
    set_output(service, **{"retry_limit": 1, "compress": False,
                           ("auth_url" if stage == "oauth" else "dce_url"):
                           endpoint + "/oauth/token" if stage == "oauth" else endpoint})
    labels = {"name": "azure_logs_ingestion.0", "dcr_id": "dcr-suite"}
    try:
        service.start()
        submit(port, 0)
        wait(service, lambda: len(receiver.requests) >= 1, "first wire request")
        # The parser/HTTP failure must return promptly, not wait for the 5s timeout.
        # The second request is the engine retry: no second input record is submitted.
        wait(service, lambda: len(receiver.requests) >= 2,
             "engine retry after completed or malformed response", timeout=3.5)
        first, retry = receiver.requests
        assert retry["time"] - first["time"] < 3.5
        assert retry["body"] == first["body"]
        assert metrics(service)["proc_records"] == 0  # Healthy response is still gated.
        wait(service, lambda: metrics(service)["retries"] == 1, "one retained engine chunk")
        if failure == "malformed" or stage == "oauth":
            # OAuth does not enable keepalive. Ingestion also closes a connection
            # after an incomplete exchange, even when the server leaves it open.
            assert retry["connection"] != first["connection"]
            wait(service, lambda: receiver.connections[first["connection"]].is_set(),
                 "client closes the first connection")
        else:
            # Completed ingestion errors retain their healthy keepalive connection.
            assert retry["connection"] == first["connection"]
            assert not receiver.connections[first["connection"]].is_set()
        if stage == "ingestion":
            assert json.loads(first["body"])[0]["chunk_id"] == 0
            assert request_metric(service, RESPONSES, **labels, status="200") == 0
            if failure == "http_error":
                wait(service, lambda: request_metric(service, RESPONSES, **labels,
                                                       status="500") == 1,
                     "completed error response counted")
        else:
            assert b"grant_type=client_credentials" in first["body"]
            assert not any(r["path"].startswith("/dataCollectionRules/")
                           for r in http_server.data_storage["requests"])
        receiver.release_retry.set()
        wait(service, lambda: metrics(service)["proc_records"] == 1, "retry acknowledged once")
        assert metrics(service)["retries"] == 1
        assert metrics(service)["retries_failed"] == 0
        assert len(receiver.requests) == 2
        wait(service, lambda: request_metric(service, RESPONSES, **labels, status="200") == 1,
             "only the complete ingestion success counted")
        wait(service, lambda: request_metric(service, "fluentbit_output_upstream_busy_connections",
                                               name="azure_logs_ingestion.0") <= 0,
             "recovered ingestion lease released")
        assert request_metric(service, "fluentbit_output_upstream_busy_connections",
                              name="azure_logs_ingestion.0") == 0
        if stage == "ingestion":
            wait(service, lambda: request_metric(service, "fluentbit_output_upstream_total_connections",
                                                   name="azure_logs_ingestion.0") == 1,
                 "only the reusable healthy connection remains")
        if stage == "oauth":
            wait(service, lambda: all(closed.is_set() for closed in receiver.connections),
                 "all OAuth connections released")
            ingestion = [r for r in http_server.data_storage["requests"]
                         if r["path"].startswith("/dataCollectionRules/")]
            assert len(ingestion) == 1
            assert ingestion[0]["headers"]["Authorization"] == "Bearer wire-token"
    finally:
        receiver.close()
        stop_checked(service)
    assert not receiver.errors


def set_output(service, **values):
    path = Path(service.service.config_path)
    config = yaml.safe_load(path.read_text())
    config["pipeline"]["outputs"][0].update(values)
    path.write_text(yaml.safe_dump(config))


@pytest.mark.parametrize("stage", ["oauth", "ingestion"])
@pytest.mark.parametrize("first_close", [False, True])
def test_tls_acquisition_and_oauth_fallback_are_bounded(tmp_path, stage, first_close):
    service, port = timeout_service(tmp_path)
    set_output(service, **{"net.connect_timeout": "2s"})
    receiver = WireReceiver(service, "tls", first_close=first_close)
    set_output(service, **{("auth_url" if stage == "oauth" else "dce_url"):
                           f"https://localhost:{receiver.port}/oauth/token" if stage == "oauth"
                           else f"https://localhost:{receiver.port}"})
    try:
        service.start()
        start = time.monotonic()
        submit(port, 0)
        wait(service, lambda: receiver.accepted, "TLS client hello")
        wait(service, lambda: dropped_callbacks(service, 1),
             "TLS callback bounded by native connect timeout and fallback", timeout=8)
        elapsed = time.monotonic() - start
        logging.getLogger(__name__).info("TLS stage=%s first_close=%s elapsed=%.3fs accepts=%s",
                                         stage, first_close, elapsed,
                                         [round(t - start, 3) for t in receiver.accepted])
        assert elapsed < 8
        assert metrics(service)["proc_records"] == 0
        if stage == "oauth" and first_close:
            assert len(receiver.accepted) == 2  # Early failure still calls the second getter.
    finally:
        receiver.close()
        stop_checked(service)


def test_stalled_upload_uses_native_io_timeout(tmp_path):
    mode = "blocked"
    service, port = timeout_service(tmp_path)
    receiver = WireReceiver(service, mode)
    set_output(service, dce_url=f"https://localhost:{receiver.port}", compress=False)
    path = Path(service.service.config_path)
    config = yaml.safe_load(path.read_text())
    config["pipeline"]["inputs"][0].update({"buffer_max_size": "32M", "buffer_chunk_size": "1M"})
    path.write_text(yaml.safe_dump(config))
    try:
        service.start()
        response = requests.post(f"http://127.0.0.1:{port}/chunk.0",
                                 json={"chunk_id": 0, "body": "x" * (8 * 1024 * 1024)}, timeout=10)
        response.raise_for_status()
        wait(service, lambda: receiver.uploads, "TLS upload headers")
        started = receiver.accepted[0]
        wait(service, lambda: dropped_callbacks(service, 1), "stalled upload times out", timeout=8)
        elapsed = time.monotonic() - started
        upload = receiver.uploads[0]
        logging.getLogger(__name__).info("upload mode=%s elapsed=%.3fs received=%s", mode, elapsed, upload)
        assert elapsed < 8
        assert 0 < upload["received"] < upload["length"]
        assert metrics(service)["proc_records"] == 0
        assert request_metric(service, RESPONSES, name="azure_logs_ingestion.0",
                              dcr_id="dcr-suite", status="200") == 0
        receiver.mode = "healthy"
        submit(port, 1)
        wait(service, lambda: metrics(service)["proc_records"] == 1, "upload cancellation recovery")
    finally:
        receiver.close()
        stop_checked(service)


def test_refresh_contention_after_a_real_cached_token_expires(tmp_path, monkeypatch):
    service, port = timeout_service(tmp_path)
    token_times = []
    original = http_server.app.view_functions["oauth_token"]

    def token_receiver():
        token_times.append(time.monotonic())
        return original()

    monkeypatch.setitem(http_server.app.view_functions, "oauth_token", token_receiver)
    try:
        service.start()
        # Production parser rejects lifetimes <= the 60s skew. 69 becomes 63s
        # after its 10% deduction; wait for real expiry, never mutate the cache.
        http_server.configure_oauth_token_response(body={
            "access_token": "short-lived", "token_type": "Bearer", "expires_in": 69})
        submit(port, 0)
        wait(service, lambda: metrics(service)["proc_records"] == 1, "warm token cached")
        expiry = time.monotonic() + 64
        wait(service, lambda: time.monotonic() >= expiry, "actual token lifetime", timeout=65)
        http_server.configure_oauth_token_response(delay_seconds=3, body={
            "access_token": "refreshed", "token_type": "Bearer", "expires_in": 300})
        http_server.configure_http_response(delay_seconds=3)
        submit(port, 1)
        wait(service, lambda: len(token_times) == 2, "expired-token refresh owner")
        submit(port, 2)
        wait(service, lambda: metrics(service)["proc_records"] == 3,
             "refreshed concurrent requests complete independently", timeout=9)
        assert len(token_times) == 2
        assert not dropped_callbacks(service, 1)
        ingestion = [r for r in http_server.data_storage["requests"]
                     if r["path"].startswith("/dataCollectionRules/")]
        assert len(ingestion) == 3
        assert all(r["headers"]["Authorization"] == "Bearer refreshed" for r in ingestion[1:])
        http_server.configure_http_response(delay_seconds=0)
        submit(port, 3)
        wait(service, lambda: metrics(service)["proc_records"] == 4, "refreshed-token recovery")
        assert len(token_times) == 2
    finally:
        stop_checked(service)


@pytest.mark.parametrize("stage", ["oauth", "ingestion"])
def test_full_listen_queue_bounds_connect_without_accept(tmp_path, stage):
    service, port = timeout_service(tmp_path)
    set_output(service, **{"net.connect_timeout": "2s"})
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    peers = []
    stalled = 0
    for _ in range(16):
        peer = socket.socket()
        peers.append(peer)
        peer.settimeout(0.05)
        try:
            peer.connect(listener.getsockname())
        except TimeoutError:
            stalled += 1
    assert stalled > 0  # Fixture really stopped completing TCP handshakes.
    set_output(service, **{("auth_url" if stage == "oauth" else "dce_url"):
                           f"http://127.0.0.1:{listener.getsockname()[1]}/oauth/token" if stage == "oauth"
                           else f"https://127.0.0.1:{listener.getsockname()[1]}"})
    try:
        service.start()
        start = time.monotonic()
        submit(port, 0)
        wait(service, lambda: dropped_callbacks(service, 1),
             "connect callback bounded including OAuth fallback", timeout=8)
        elapsed = time.monotonic() - start
        logging.getLogger(__name__).info("connect stage=%s elapsed=%.3fs stalled_peers=%s", stage, elapsed, stalled)
        assert elapsed < 8
        assert metrics(service)["proc_records"] == 0
    finally:
        for peer in peers:
            peer.close()
        listener.close()
        stop_checked(service)


@pytest.mark.parametrize("stage", ["oauth", "ingestion"])
def test_native_io_timeout_clamps_response_timeout(tmp_path, stage):
    service, port = timeout_service(tmp_path, response_timeout="10s")
    set_output(service, **{"net.io_timeout": "1s"})
    configure = (http_server.configure_oauth_token_response if stage == "oauth"
                 else http_server.configure_http_response)
    try:
        service.start()
        configure(hang_before_response=True)
        started = time.monotonic()
        submit(port, 0)
        wait(service, lambda: dropped_callbacks(service, 1), "native idle timeout", timeout=4)
        assert time.monotonic() - started < 4  # Not the 10s response setting.
        assert metrics(service)["proc_records"] == 0
        assert request_metric(service, RESPONSES, name="azure_logs_ingestion.0",
                              dcr_id="dcr-suite", status="200") == 0
        configure(hang_before_response=False)
        submit(port, 1)
        wait(service, lambda: metrics(service)["proc_records"] == 1, "idle-timeout recovery")
    finally:
        stop_checked(service)


@pytest.mark.parametrize("response_timeout", [None, "2s"])
@pytest.mark.parametrize("batching", [False, True])
def test_response_timeout_configuration_with_default(tmp_path, response_timeout, batching):
    service, port = timeout_service(tmp_path, response_timeout=response_timeout)
    if not batching:
        path = Path(service.service.config_path)
        config = yaml.safe_load(path.read_text())
        output = config["pipeline"]["outputs"][0]
        del output["batch_chunk_count"]
        del output["batch_wait_ms"]
        path.write_text(yaml.safe_dump(config))
    try:
        service.start()
        submit(port, 0)
        wait(service, lambda: metrics(service)["proc_records"] == 1,
             "default or explicit timeout with or without batching")
    finally:
        stop_checked(service)
