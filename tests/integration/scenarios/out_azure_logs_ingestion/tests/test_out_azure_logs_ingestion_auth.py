"""Refresh fan-out through real engine callbacks, without a timer-rate assertion."""
import collections
import logging
import socket
import threading
import time
from pathlib import Path

import pytest
import yaml

from server import http_server
from server.forward_server import _pack_obj
from test_out_azure_logs_ingestion_batch import Gates, batch_service, metrics, stop_checked


@pytest.mark.parametrize("batching", [False, True])
@pytest.mark.parametrize("compress", [False, True])
@pytest.mark.parametrize("failed_refresh", [False, True])
def test_auth_waiters_resume_after_refresh(tmp_path, monkeypatch, batching, compress, failed_refresh):
    count = 193  # More than three dispatcher budgets, plus the refresh owner.
    service = batch_service(tmp_path, count=0, wait_ms=60000)
    port = service.service.allocate_port_env("TEST_AUTH_FORWARD_PORT")
    path = Path(service.service.config_path)
    config = yaml.safe_load(path.read_text())
    config["service"].update({"flush": 0.05, "grace": 10,
                              "scheduler.base": 1, "scheduler.cap": 1})
    config["pipeline"]["inputs"] = [
        {"name": "forward", "listen": "127.0.0.1", "port": port,
         "buffer_max_size": "2M", "buffer_chunk_size": "1M"}]
    output = config["pipeline"]["outputs"][0]
    output.update({"compress": compress, "time_generated": False,
                   "batch_target_size": 1, "retry_limit": 1})
    if not batching:
        del output["batch_wait_ms"]
    config["pipeline"]["outputs"].append({"name": "null", "match": "barrier", "workers": 0})
    path.write_text(yaml.safe_dump(config))
    gates = Gates(monkeypatch, gate_timeout=120)
    token_gates = [threading.Event(), threading.Event()]
    token_started = [threading.Event(), threading.Event()]
    tokens = []
    token_lock = threading.Lock()
    original_token = http_server.app.view_functions["oauth_token"]

    def token_receiver():
        with token_lock:
            index = len(tokens)
            tokens.append(time.monotonic())
        if index >= len(token_gates):
            gates.errors.append("unexpected additional token refresh")
            return "unexpected refresh", 500
        token_started[index].set()
        if not token_gates[index].wait(120):
            gates.errors.append("OAuth response gate expired")
        if failed_refresh and index == 0:
            return "refresh failed", 503
        return original_token()

    def wait(predicate, description, timeout=60):
        return service.service.wait_for_condition(
            predicate, timeout=timeout, interval=0.02, description=description)

    monkeypatch.setitem(http_server.app.view_functions, "oauth_token", token_receiver)
    try:
        service.start()
        log_path = Path(service.flb.log_file)
        with socket.create_connection(("127.0.0.1", port), timeout=10) as connection:
            barriers = 0
            for start in range(0, count, 32):
                end = min(start + 32, count)
                connection.sendall(b"".join(
                    b"\x93" + _pack_obj(f"chunk.{i}") + b"\x01" + _pack_obj({"chunk_id": str(i)})
                    for i in range(start, end)))
                wait(lambda: log_path.read_text().count("created task=") >= end + barriers,
                     f"{end} Azure tasks created")
                # Isolate auth wakeups from the unchanged core flush-dispatch pipe.
                connection.sendall(b"\x93" + _pack_obj("barrier") + b"\x01" +
                                   _pack_obj({"marker": "admitted"}))
                barriers += 1
                wait(lambda: log_path.read_text().count("[task] destroy task=") >= barriers,
                     f"{end} callbacks admitted behind OAuth")
            wait(token_started[0].is_set, "first refresh held in network IO")
            assert len(tokens) == 1
            assert not gates.requests
            assert metrics(service)["proc_records"] == 0
            released = time.monotonic()
            token_gates[0].set()
            if failed_refresh:
                wait(token_started[1].is_set, "a waiter elected as successor refresh owner")
                assert len(tokens) == 2
                assert not gates.requests
                # The failed owner's chunk remains with the engine for its
                # configured finite retry, not in a plugin-owned retry queue.
                wait(lambda: "retry in" in log_path.read_text(), "failed owner scheduled for retry")
                token_gates[1].set()
            wait(lambda: len(gates.requests) == count, "all authentication waiters reach ingestion")
            logging.getLogger(__name__).info(
                "%d auth callbacks reached ingestion in %.6fs; batching=%s failed_refresh=%s",
                count, time.monotonic() - released, batching, failed_refresh)
            assert metrics(service)["proc_records"] == 0  # All ingestion IO is still held.
            # New work must use the cache while every older sender is in network IO.
            connection.sendall(b"\x93" + _pack_obj(f"chunk.{count}") + b"\x01" +
                               _pack_obj({"chunk_id": str(count)}))
            wait(lambda: len(gates.requests) == count + 1, "cached token follow-up")
            assert len(tokens) == 1 + failed_refresh
            assert metrics(service)["proc_records"] == 0
        gates.release_all()
        wait(lambda: metrics(service)["proc_records"] == count + 1, "all callbacks complete")
        result = metrics(service)
        assert result["dropped_records"] == 0
        assert result["retries"] == int(failed_refresh)
        assert result["retried_records"] == int(failed_refresh)
        assert result["retries_failed"] == 0
        assert result["errors"] == 0
        assert service.flb.process.poll() is None
    finally:
        for gate in token_gates:
            gate.set()
        gates.release_all()
        stop_checked(service)
    assert not gates.errors
    assert len(tokens) == 1 + failed_refresh
    assert len(gates.requests) == count + 1
    assert collections.Counter(record["chunk_id"] for item in gates.requests
                               for record in item["records"]) == collections.Counter(str(i) for i in range(count + 1))
    assert all(item["encoding"] == ("gzip" if compress else None) for item in gates.requests)
    assert all(item["records"] == [{"@timestamp": 1.0,
                                    "chunk_id": item["records"][0]["chunk_id"]}]
               for item in gates.requests)
