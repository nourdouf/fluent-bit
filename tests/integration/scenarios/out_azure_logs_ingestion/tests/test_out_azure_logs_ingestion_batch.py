"""Real engine chunks: each finite dummy instance owns a distinct input chunk."""
import collections
import random
import json
import os
import threading
import time
import logging
import datetime
import re
import signal
import socket
import sys
from pathlib import Path

import pytest

import requests
import yaml

from server import http_server
from server.forward_server import _pack_obj
from test_out_azure_logs_ingestion_001 import Service


def batch_service(tmp_path, count=3, wait_ms=5000, chunk_bytes=None):
    service = Service("out_azure_logs_ingestion_oauth2.yaml")
    with open(service.config_file) as config_file:
        config = yaml.safe_load(config_file)
    config["service"]["log_level"] = "debug"
    config["pipeline"]["inputs"] = [
        {"name": "dummy", "tag": f"chunk.{i}", "dummy": f'{{"chunk_id":{i}}}',
         "samples": 1, "copies": i + 1}
        for i in range(count)
    ]
    if chunk_bytes is not None:
        for i, source in enumerate(config["pipeline"]["inputs"]):
            source["dummy"] = json.dumps(sized_record(i, field_size=chunk_bytes // (10 * (i + 1))))
    config["pipeline"]["outputs"][0].update(
        {"match": "chunk.*", "workers": 0, "batch_wait_ms": wait_ms}
    )
    config_path = tmp_path / "batch.yaml"
    config_path.write_text(yaml.safe_dump(config))
    service.service.config_path = str(config_path)
    return service


def metrics(service):
    def snapshot():
        response = requests.get(
            f"http://127.0.0.1:{service.flb.http_monitoring_port}/api/v1/metrics", timeout=2
        )
        if response.status_code == 404:
            # A reader can outlive a rejected snapshot replacement, leaving the
            # endpoint unavailable until the next export, even after startup.
            logging.getLogger(__name__).info("metrics snapshot unavailable (HTTP 404)")
            return None
        response.raise_for_status()
        return response.json()["output"]["azure_logs_ingestion.0"]

    return service.service.wait_for_condition(
        snapshot, timeout=10, interval=0.05, description="available output metrics snapshot")


def stop_checked(service):
    process = service.flb.process if hasattr(service, "flb") else None
    service.stop()  # Memory-checker assertions propagate; never swallow cleanup failures.
    if process is not None:
        assert process.returncode == 0, f"Fluent Bit/ checker exited with {process.returncode}"


class Gates:
    def __init__(self, monkeypatch, max_bytes=None, gate_timeout=30):
        self.max_bytes = max_bytes
        self.gate_timeout = gate_timeout
        self.requests = []
        self.errors = []
        self.closing = threading.Event()
        self.lock = threading.Lock()
        monkeypatch.setattr(http_server, "_build_response", self.respond)

    def respond(self):
        gate = threading.Event()
        # Request-local decode avoids ordering races in the shared fixture list.
        from flask import request
        import gzip
        import json
        wire_body = request.get_data()
        raw_size = len(wire_body)
        encoding = request.headers.get("Content-Encoding")
        assert int(request.headers["Content-Length"]) == raw_size
        assert encoding in (None, "gzip")
        body = gzip.decompress(wire_body) if encoding == "gzip" else wire_body
        item = {"gate": gate, "records": json.loads(body), "status": 200,
                "raw_size": raw_size, "json_size": len(body),
                "body": wire_body, "encoding": encoding,
                "time": time.time(), "path": request.path}
        with self.lock:
            self.requests.append(item)
        logging.getLogger(__name__).info("request payload bytes: wire=%d json=%d encoding=%s",
                                         raw_size, len(body), encoding)
        if self.max_bytes is not None and max(raw_size, len(body)) > self.max_bytes:
            item["status"] = 413
            return "request exceeds service limit", 413
        if self.closing.is_set():
            gate.set()
        if not gate.wait(self.gate_timeout):
            self.errors.append("response gate expired")
        return "{}", item["status"], {"Content-Type": "application/json"}

    def wait(self, service, count):
        service.service.wait_for_condition(lambda: len(self.requests) >= count,
                                           timeout=20, interval=0.02,
                                           description=f"{count} gated ingestion requests")
        logging.getLogger(__name__).info("request shapes: %s", [
            dict(collections.Counter(r["chunk_id"] for r in item["records"]))
            for item in self.requests])
        return self.requests[count - 1]

    def release_all(self):
        self.closing.set()
        for item in self.requests:
            item["gate"].set()


@pytest.mark.skipif(sys.platform != "linux", reason="requires Linux engine drain semantics")
@pytest.mark.parametrize("transition", ["stop", "reload"])
@pytest.mark.parametrize("pending,batching", [
    ("collecting", True), ("ingestion", True), ("oauth", True),
    ("ingestion", False), ("oauth", False),
])
def test_pending_batches_drain_on_lifecycle_transition(tmp_path, monkeypatch, pending,
                                                       transition, batching):
    service = batch_service(tmp_path, count=0, wait_ms=60000)
    port = service.service.allocate_port_env("TEST_LIFECYCLE_INPUT_PORT")
    path = Path(service.service.config_path)
    config = yaml.safe_load(path.read_text())
    config["service"].update({"flush": 0.05, "grace": 8, "hot_reload": "on"})
    config["pipeline"]["outputs"][0].update({"time_generated": True, "batch_target_size": 1000000})
    if not batching:
        del config["pipeline"]["outputs"][0]["batch_wait_ms"]
    # Leave hot_reload.ensure_thread_safety at its default (on).
    config["pipeline"]["inputs"] = [{"name": "http", "listen": "127.0.0.1", "port": port}]
    path.write_text(yaml.safe_dump(config))
    gates = Gates(monkeypatch)
    token_started = threading.Event()
    token_release = threading.Event()
    token_requests = []
    original_token = http_server.app.view_functions["oauth_token"]

    def token_receiver():
        token_requests.append(time.monotonic())
        token_started.set()
        if not token_release.wait(30):
            gates.errors.append("token response gate expired")
        return original_token()

    def log_text():
        return Path(service.flb.log_file).read_text()

    def wait(predicate, description):
        return service.service.wait_for_condition(
            predicate, timeout=10, interval=0.02, description=description)

    def submit(chunk_id):
        response = requests.post(f"http://127.0.0.1:{port}/chunk.{chunk_id}",
                                 json=exact_size_record(chunk_id, 333334), timeout=5)
        response.raise_for_status()

    def post_reload_delivered():
        try:
            return metrics(service)["proc_records"] == 3
        except requests.HTTPError as error:
            # The new HTTP server returns 404 until its first metrics snapshot.
            if error.response is not None and error.response.status_code == 404:
                return False
            raise

    monkeypatch.setitem(http_server.app.view_functions, "oauth_token", token_receiver)
    if pending != "oauth":
        token_release.set()
    # Three 333334-byte arrays assemble to exactly 1000000 bytes. Nine chunks
    # close three batches: one refresh owner and two waiting senders.
    count = {"collecting": 2, "ingestion": 3, "oauth": 9}[pending]
    request_count = (count + 2) // 3 if batching else count
    followup_requests = 1 if batching else 3
    expected = collections.Counter(range(count))
    try:
        service.start()
        first_submit = time.monotonic()
        for chunk_id in range(count):
            submit(chunk_id)
            wait(lambda: len(re.findall(r"\[task\] created task=.* OK", log_text()))
                 == chunk_id + 1, f"engine task for chunk {chunk_id}")
        if pending == "ingestion":
            gates.wait(service, request_count)
            assert len(gates.requests) == request_count
        elif pending == "oauth":
            wait(token_started.is_set, "refresh owner held in OAuth")
            assert len(token_requests) == 1
            assert not gates.requests
        else:
            assert not gates.requests
            assert not token_requests
        assert metrics(service)["proc_records"] == 0

        if transition == "reload":
            service.flb.send_sighup()
        else:
            service.flb.send_signal(signal.SIGTERM)
        # Do not release either network gate until the old engine begins draining.
        wait(lambda: "[engine] pausing all inputs.." in log_text(), "shutdown ingestion pause")
        if transition == "reload":
            assert "[reload] stop everything of the old context" in log_text()
            assert "[reload] start everything" not in log_text()
        if pending == "collecting":
            item = gates.wait(service, 1)
            assert collections.Counter(r["chunk_id"] for r in item["records"]) == expected
            # The 60-second collection wait cannot account for this request.
            assert time.monotonic() - first_submit < 30
        token_release.set()
        gates.release_all()

        if transition == "reload":
            service.flb.wait_for_hot_reload_count(1, timeout=30)
            old_log = log_text().split("[reload] start everything", 1)[0]
            assert old_log.count("http_status=200") == request_count
            assert len(token_requests) == 1
            assert collections.Counter(r["chunk_id"] for item in gates.requests
                                       for r in item["records"]) == expected
            # Fresh input/output contexts must still deliver after the old timers exit.
            for chunk_id in range(100, 103):
                submit(chunk_id)
                expected[chunk_id] += 1
            wait(post_reload_delivered, "post-reload delivery")
    finally:
        token_release.set()
        gates.release_all()
        stop_checked(service)
    assert not gates.errors
    assert collections.Counter(r["chunk_id"] for item in gates.requests
                               for r in item["records"]) == expected
    assert len(gates.requests) == request_count + followup_requests * (transition == "reload")
    assert len(token_requests) == 1 + (transition == "reload")
    log = log_text()
    assert log.count("http_status=200") == len(gates.requests)
    assert "failed to flush chunk" not in log
    assert "cannot be retried" not in log
    assert "is not retried" not in log


@pytest.mark.parametrize("compress,status", [(False, 204), (True, 204), (True, 413), (True, 503)])
def test_large_batch_completion_keeps_engine_responsive(tmp_path, monkeypatch, compress, status):
    count = 10000
    service = batch_service(tmp_path, count=0, wait_ms=600000)
    port = service.service.allocate_port_env("TEST_BATCH_FORWARD_PORT")
    path = Path(service.service.config_path)
    config = yaml.safe_load(path.read_text())
    config["service"].update({"flush": 0.05, "grace": 10})
    config["pipeline"]["inputs"] = [
        {"name": "forward", "listen": "127.0.0.1", "port": port,
         "buffer_max_size": "2M", "buffer_chunk_size": "1M"}]
    config["pipeline"]["outputs"][0].update(
        {"compress": compress, "time_generated": False,
         "batch_target_size": 1000000, "retry_limit": "no_retries"})
    config["pipeline"]["outputs"].append({"name": "null", "match": "barrier", "workers": 0})
    path.write_text(yaml.safe_dump(config))
    records = [{"chunk_id": str(i)} for i in range(count)]
    last = records[-1]
    last.update({f"padding_{i}": "" for i in range(14)})
    formatted = [{"@timestamp": 1.0, **record} for record in records]
    remaining = 1000000 - len(json.dumps(formatted, separators=(",", ":")).encode())
    for i in range(14):
        size = min(60000, remaining)
        last[f"padding_{i}"] = "x" * size
        remaining -= size
    assert remaining == 0
    gates = Gates(monkeypatch)
    try:
        service.start()
        log_path = Path(service.flb.log_file)
        with socket.create_connection(("127.0.0.1", port), timeout=10) as connection:
            barriers = 0
            for start in range(0, count, 128):
                end = min(start + 128, count)
                connection.sendall(b"".join(
                    b"\x93" + _pack_obj(f"chunk.{i}") + b"\x01" + _pack_obj(records[i])
                    for i in range(start, end)))
                service.service.wait_for_condition(
                    lambda: log_path.read_text().count("created task=") >= end + barriers,
                    timeout=30, interval=0.02, description=f"{end} Azure tasks created")
                # A subsequently queued null flush fences the shared dispatch pipe.
                # Azure callbacks cannot finish yet: the HTTP response is still held.
                connection.sendall(b"\x93" + _pack_obj("barrier") + b"\x01" +
                                   _pack_obj({"marker": "admitted"}))
                barriers += 1
                service.service.wait_for_condition(
                    lambda: log_path.read_text().count("[task] destroy task=") >= barriers,
                    timeout=30, interval=0.02, description=f"{end} Azure callbacks admitted")
        item = gates.wait(service, 1)
        assert item["json_size"] == 1000000
        assert item["encoding"] == ("gzip" if compress else None)
        assert collections.Counter(r["chunk_id"] for r in item["records"]) == collections.Counter(
            r["chunk_id"] for r in records)
        for received in item["records"]:
            assert received == {"@timestamp": 1.0, **records[int(received["chunk_id"])]}
        assert len(gates.requests) == 1
        assert metrics(service)["proc_records"] == 0
        labels = {"name": "azure_logs_ingestion.0", "dcr_id": "dcr-suite"}
        service.service.wait_for_condition(
            lambda: request_metric(service, CHUNKS + "_sum", **labels) == count,
            timeout=10, interval=0.02, description="all batch members in metrics snapshot")
        item["status"] = status
        logging.getLogger(__name__).info("releasing HTTP %d for %d chunk callbacks", status, count)
        released = time.monotonic()
        item["gate"].set()
        counter = "proc_records" if status == 204 else "dropped_records"
        service.service.wait_for_condition(
            lambda: metrics(service)[counter] == count,
            timeout=60, interval=0.02, description="all completion notifications drained")
        logging.getLogger(__name__).info("retired %d chunk callbacks in %.6fs after HTTP %d",
                                         count, time.monotonic() - released, status)
        assert service.flb.process.poll() is None
        assert len(gates.requests) == 1
        service.service.wait_for_condition(
            lambda: request_metric(service, RESPONSES, **labels, status=str(status)) == 1,
            timeout=10, interval=0.02, description="completed response in metrics snapshot")
    finally:
        gates.release_all()
        stop_checked(service)
    assert not gates.errors


def sized_record(chunk_id, field_count=10, field_size=40000):
    # Every field stays below Azure's 64 KB field limit.
    return {"chunk_id": chunk_id,
            **{f"field_{i}": "x" * field_size for i in range(field_count)}}


def exact_size_record(chunk_id, array_bytes):
    # ISO timestamps have a fixed width. Account for the actual formatter's array,
    # map, keys and punctuation; distribute padding across sub-64KB fields.
    record = sized_record(chunk_id, field_count=32, field_size=0)
    envelope = [{"@timestamp": "2000-01-01T00:00:00.000Z", **record}]
    remaining = array_bytes - len(json.dumps(envelope, separators=(",", ":")))
    assert 0 <= remaining <= 32 * 60000
    for i in range(32):
        length = min(remaining, 60000)
        record[f"field_{i}"] = "x" * length
        remaining -= length
    return record


@pytest.mark.parametrize("compress", ["off", "on"])
def test_omitted_batch_target_uses_800000_bytes(tmp_path, monkeypatch, compress):
    service = batch_service(tmp_path, count=2, wait_ms=4000)
    path = Path(service.service.config_path)
    config = yaml.safe_load(path.read_text())
    expected = {i: exact_size_record(i, 450001) for i in range(2)}
    for chunk_id, source in enumerate(config["pipeline"]["inputs"]):
        source.update({"dummy": json.dumps(expected[chunk_id]), "copies": 1})
    output = config["pipeline"]["outputs"][0]
    output.update({"time_generated": True, "compress": compress})
    assert "batch_target_size" not in output
    path.write_text(yaml.safe_dump(config))
    gates = Gates(monkeypatch, max_bytes=1000000)
    try:
        service.start()
        first = gates.wait(service, 1)
        # Whole-chunk admission crosses the plain soft target. Gzip retains the
        # same two compressible chunks until the timer, rather than closing on raw bytes.
        assert first["json_size"] == 900001
        assert first["encoding"] == ("gzip" if compress == "on" else None)
        assert (first["raw_size"] < 800000) == (compress == "on")
        if compress == "on":
            tasks = re.findall(r"\[([0-9/]+ [0-9:.]+)\].*\[task\] created task=.* OK",
                               Path(service.flb.log_file).read_text())
            assert len(tasks) == 2
            admitted = datetime.datetime.strptime(tasks[0], "%Y/%m/%d %H:%M:%S.%f").timestamp()
            assert first["time"] - admitted >= 3.8
        gates.release_all()
        service.service.wait_for_condition(lambda: metrics(service)["proc_records"] == 2,
                                           timeout=15, description="default-target chunks delivered")
        assert [item["json_size"] for item in gates.requests] == [900001]
        assert collections.Counter(record["chunk_id"] for item in gates.requests
                                   for record in item["records"]) == {0: 1, 1: 1}
        for item in gates.requests:
            assert item["status"] == 200
            assert item["raw_size"] <= 1000000
            for record in item["records"]:
                assert {key: value for key, value in record.items()
                        if key != "@timestamp"} == expected[record["chunk_id"]]
                assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z",
                                    record["@timestamp"])
    finally:
        gates.release_all()
        stop_checked(service)
    assert not gates.errors


def assert_target_requests(gates, expected, sizes):
    assert sorted(item["json_size"] for item in gates.requests) == sorted(sizes)
    assert collections.Counter(record["chunk_id"] for item in gates.requests
                               for record in item["records"]) == collections.Counter(expected.keys())
    for item in gates.requests:
        assert item["status"] == 200
        assert item["raw_size"] <= 1000000
        for record in item["records"]:
            assert {key: value for key, value in record.items()
                    if key != "@timestamp"} == expected[record["chunk_id"]]
            assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z",
                                record["@timestamp"])


@pytest.mark.parametrize("compress", ["off", "on"])
@pytest.mark.parametrize("target,sizes,wait_ms", [
    pytest.param(600000, [900001], 4000, id="smaller"),
    pytest.param(1000000, [900001], 4000, id="maximum"),
    pytest.param("+1000000", [900001], 4000, id="leading-plus"),
    # Configuration normalizes whitespace before plugin parsing.
    pytest.param(" 1000000", [900001], 4000, id="leading-space"),
    pytest.param(1, [450001, 450001], 60000, id="minimum"),
    pytest.param(2, [450001, 450001], 60000, id="array-envelope"),
])
def test_explicit_batch_target_controls_grouping(tmp_path, monkeypatch, compress,
                                                target, sizes, wait_ms):
    service = batch_service(tmp_path, count=2, wait_ms=wait_ms)
    path = Path(service.service.config_path)
    config = yaml.safe_load(path.read_text())
    expected = {i: exact_size_record(i, 450001) for i in range(2)}
    for chunk_id, source in enumerate(config["pipeline"]["inputs"]):
        source.update({"dummy": json.dumps(expected[chunk_id]), "copies": 1})
    config["pipeline"]["outputs"][0].update(
        {"time_generated": True, "compress": compress, "batch_target_size": target})
    path.write_text(yaml.safe_dump(config))
    gates = Gates(monkeypatch, max_bytes=1000000)
    try:
        service.start()
        gates.wait(service, len(sizes))
        assert_target_requests(gates, expected, sizes)
        assert metrics(service)["proc_records"] == 0
        gates.release_all()
        service.service.wait_for_condition(lambda: metrics(service)["proc_records"] == 2,
                                           timeout=10, description="configured-target chunks delivered")
    finally:
        gates.release_all()
        stop_checked(service)
    assert not gates.errors
    assert_target_requests(gates, expected, sizes)


@pytest.mark.parametrize("compress", ["off", "on"])
@pytest.mark.parametrize("batched", [False, True], ids=["unbatched", "batched"])
@pytest.mark.parametrize("target", ["", "800000 "], ids=["empty", "trailing-space"])
def test_normalized_batch_target_preserves_delivery(tmp_path, monkeypatch, compress, batched, target):
    service = batch_service(tmp_path, count=3, wait_ms=2000)
    path = Path(service.service.config_path)
    config = yaml.safe_load(path.read_text())
    expected = {i: exact_size_record(i, 300001) for i in range(3)}
    for chunk_id, source in enumerate(config["pipeline"]["inputs"]):
        source.update({"dummy": json.dumps(expected[chunk_id]), "copies": 1})
    output = config["pipeline"]["outputs"][0]
    # Empty strings become omitted values; trailing whitespace is trimmed.
    # Both therefore use 800000, without enabling batching on their own.
    output.update({"time_generated": True, "compress": compress, "batch_target_size": target})
    if not batched:
        del output["batch_wait_ms"]
    path.write_text(yaml.safe_dump(config))
    sizes = [900001] if batched else [300001, 300001, 300001]
    gates = Gates(monkeypatch, max_bytes=1000000)
    try:
        service.start()
        gates.wait(service, 1)
        assert metrics(service)["proc_records"] == 0
        gates.release_all()
        service.service.wait_for_condition(lambda: metrics(service)["proc_records"] == 3,
                                           timeout=15, description="normalized-target chunks delivered")
        # The last whole chunk can carry the plain body past the soft target.
        assert_target_requests(gates, expected, sizes)
        assert metrics(service)["retries"] == 0
    finally:
        gates.release_all()
        stop_checked(service)
    assert not gates.errors
    assert_target_requests(gates, expected, sizes)


@pytest.mark.parametrize("target", [None, 600000], ids=["default", "smaller"])
def test_exact_plain_batch_target_closes_without_collection_expiry(tmp_path, monkeypatch, target):
    service = batch_service(tmp_path, count=2, wait_ms=60000)
    path = Path(service.service.config_path)
    config = yaml.safe_load(path.read_text())
    target_bytes = 800000 if target is None else target
    expected = {i: exact_size_record(i, target_bytes // 2 + (i == 0)) for i in range(2)}
    for chunk_id, source in enumerate(config["pipeline"]["inputs"]):
        source.update({"dummy": json.dumps(expected[chunk_id]), "copies": 1})
    output = config["pipeline"]["outputs"][0]
    output.update({"time_generated": True, "compress": "off"})
    if target is not None:
        output["batch_target_size"] = target
    path.write_text(yaml.safe_dump(config))
    gates = Gates(monkeypatch, max_bytes=1000000)
    try:
        service.start()
        # The receiver's 20-second wait cannot be satisfied by the 60-second timer.
        gates.wait(service, 1)
        assert_target_requests(gates, expected, [target_bytes])
        assert metrics(service)["proc_records"] == 0
        gates.release_all()
        service.service.wait_for_condition(lambda: metrics(service)["proc_records"] == 2,
                                           timeout=10, description="exact-target chunks delivered")
    finally:
        gates.release_all()
        stop_checked(service)
    assert not gates.errors
    assert_target_requests(gates, expected, [target_bytes])


@pytest.mark.parametrize("target", [100000, 200000])
def test_emitted_gzip_target_closes_before_timer_or_raw_ceiling(tmp_path, monkeypatch, target):
    service = batch_service(tmp_path, count=6, wait_ms=60000)
    path = Path(service.service.config_path)
    config = yaml.safe_load(path.read_text())
    expected = {}
    # JSON-safe printable bytes avoid escape-dependent sizes. This is a workload,
    # not an assumed compression ratio or a bound on miniz's emission lag.
    alphabet = ''.join(chr(value) for value in range(32, 127) if chr(value) not in '\\"')
    for chunk_id, source in enumerate(config["pipeline"]["inputs"]):
        rng = random.Random(chunk_id)
        record = exact_size_record(chunk_id, 80001)
        for key, value in record.items():
            if key.startswith("field_"):
                record[key] = ''.join(rng.choices(alphabet, k=len(value)))
        expected[chunk_id] = record
        source.update({"dummy": json.dumps(record), "copies": 1})
    config["pipeline"]["outputs"][0].update(
        {"time_generated": True, "compress": "on", "batch_target_size": target})
    path.write_text(yaml.safe_dump(config))
    gates = Gates(monkeypatch, max_bytes=1000000)
    try:
        service.start()
        # All input is below the raw ceiling, and the 20s receiver timeout is
        # shorter than collection. Only emitted gzip bytes can close this batch.
        item = gates.wait(service, 1)
        service.service.wait_for_condition(
            lambda: len(re.findall(r"\[task\] created task=.* OK",
                                   Path(service.flb.log_file).read_text())) == 6,
            timeout=10, interval=0.02, description="all six entropy chunks admitted")
        assert item["encoding"] == "gzip"
        assert target <= item["raw_size"] <= 1000000
        assert item["json_size"] < 6 * 80001 < 1000000
        assert len(item["records"]) > 1
        assert metrics(service)["proc_records"] == 0
    finally:
        gates.release_all()
        # Drain any final below-target batch without waiting for its 60s timer.
        stop_checked(service)
    assert not gates.errors
    assert collections.Counter(r["chunk_id"] for item in gates.requests
                               for r in item["records"]) == collections.Counter(expected.keys())
    for item in gates.requests:
        assert item["encoding"] == "gzip"
        assert item["raw_size"] <= 1000000 and item["json_size"] <= 1000000
        for record in item["records"]:
            assert {k: v for k, v in record.items() if k != "@timestamp"} == expected[record["chunk_id"]]


def test_compressible_batch_raw_ceiling_preempts_gzip_target(tmp_path, monkeypatch):
    service = batch_service(tmp_path, count=3, wait_ms=60000)
    path = Path(service.service.config_path)
    config = yaml.safe_load(path.read_text())
    for chunk_id, source in enumerate(config["pipeline"]["inputs"]):
        source.update({"dummy": json.dumps(exact_size_record(chunk_id, 400001)), "copies": 1})
    config["pipeline"]["outputs"][0].update({"time_generated": True, "compress": "on"})
    path.write_text(yaml.safe_dump(config))
    gates = Gates(monkeypatch, max_bytes=1000000)
    try:
        service.start()
        item = gates.wait(service, 1)
        assert item["encoding"] == "gzip"
        assert item["json_size"] == 800001
        assert item["raw_size"] < 800000
        assert len(item["records"]) == 2
        assert metrics(service)["proc_records"] == 0
    finally:
        gates.release_all()
        stop_checked(service)
    assert not gates.errors
    assert sorted(item["json_size"] for item in gates.requests) == [400001, 800001]
    assert collections.Counter(r["chunk_id"] for item in gates.requests
                               for r in item["records"]) == {0: 1, 1: 1, 2: 1}


@pytest.mark.parametrize("compress", ["off", "on"])
def test_hard_valid_chunk_can_overshoot_soft_target_with_peer(tmp_path, monkeypatch, compress):
    service = batch_service(tmp_path, count=0, wait_ms=4000)
    port = service.service.allocate_port_env("TEST_TARGET_INPUT_PORT")
    path = Path(service.service.config_path)
    config = yaml.safe_load(path.read_text())
    config["service"]["flush"] = 0.05
    config["pipeline"]["inputs"] = [{"name": "http", "listen": "127.0.0.1", "port": port}]
    config["pipeline"]["outputs"][0].update({"time_generated": True, "compress": compress})
    path.write_text(yaml.safe_dump(config))
    sizes = [100001, 850001, 100001]
    expected = {i: exact_size_record(i, size) for i, size in enumerate(sizes)}
    request_sizes = [950001, 100001]
    gates = Gates(monkeypatch, max_bytes=1000000)
    try:
        service.start()
        for chunk_id, record in expected.items():
            response = requests.post(f"http://127.0.0.1:{port}/chunk.{chunk_id}",
                                     json=record, timeout=5)
            response.raise_for_status()
            service.service.wait_for_condition(
                lambda: len(re.findall(r"\[task\] created task=.* OK",
                                       Path(service.flb.log_file).read_text())) == chunk_id + 1,
                timeout=10, interval=0.02, description=f"separate target-test chunk {chunk_id}")
        gates.wait(service, 2)
        assert_target_requests(gates, expected, request_sizes)
        assert [[r["chunk_id"] for r in item["records"]] for item in gates.requests] == [[0, 1], [2]]
        assert metrics(service)["proc_records"] == 0
        gates.release_all()
        service.service.wait_for_condition(lambda: metrics(service)["proc_records"] == 3,
                                           timeout=10, description="whole-chunk overshoot and peer delivered")
        assert metrics(service)["retries"] == 0
    finally:
        gates.release_all()
        stop_checked(service)
    assert not gates.errors
    assert_target_requests(gates, expected, request_sizes)


@pytest.mark.parametrize("compress", ["off", "on"])
@pytest.mark.parametrize("workers", [0, 1])
def test_target_without_wait_remains_unbatched(tmp_path, monkeypatch, compress, workers):
    service = batch_service(tmp_path, count=2)
    path = Path(service.service.config_path)
    config = yaml.safe_load(path.read_text())
    expected = {i: exact_size_record(i, 1001) for i in range(2)}
    for chunk_id, source in enumerate(config["pipeline"]["inputs"]):
        source.update({"dummy": json.dumps(expected[chunk_id]), "copies": 1})
    output = config["pipeline"]["outputs"][0]
    del output["batch_wait_ms"]
    output.update({"time_generated": True, "compress": compress,
                   "batch_target_size": 600000, "workers": workers})
    path.write_text(yaml.safe_dump(config))
    gates = Gates(monkeypatch, max_bytes=1000000)
    try:
        service.start()
        gates.wait(service, 1)
        gates.release_all()
        service.service.wait_for_condition(lambda: metrics(service)["proc_records"] == 2,
                                           timeout=15, description="unbatched target-only chunks delivered")
    finally:
        gates.release_all()
        stop_checked(service)
    assert not gates.errors
    assert_target_requests(gates, expected, [1001, 1001])


@pytest.mark.parametrize("compress", ["off", "on"])
def test_whole_chunks_respect_service_byte_ceiling(tmp_path, monkeypatch, compress):
    service = batch_service(tmp_path, count=3, wait_ms=2000)
    path = Path(service.service.config_path)
    config = yaml.safe_load(path.read_text())
    for chunk_id, source in enumerate(config["pipeline"]["inputs"]):
        source.update({"dummy": json.dumps(sized_record(chunk_id)), "copies": 1})
    config["pipeline"]["outputs"][0].update(
        {"compress": compress, "retry_limit": 1, "batch_target_size": 1000000})
    path.write_text(yaml.safe_dump(config))
    gates = Gates(monkeypatch, max_bytes=1000000)
    try:
        service.start()
        gates.wait(service, 1)
        # Check the receiver's actual bytes, not an estimate of MessagePack size.
        assert all(item["raw_size"] <= 1000000 and item["json_size"] <= 1000000
                   for item in gates.requests), [
                       (item["raw_size"], item["json_size"]) for item in gates.requests]
        gates.release_all()
        service.service.wait_for_condition(lambda: metrics(service)["proc_records"] == 3,
                                           timeout=15, description="all size-valid chunks delivered")
        assert len(gates.requests) == 2
        assert sorted(len(item["records"]) for item in gates.requests) == [1, 2]
        assert collections.Counter(record["chunk_id"] for item in gates.requests
                                   for record in item["records"]) == {0: 1, 1: 1, 2: 1}
        for item in gates.requests:
            assert item["status"] == 200
            assert item["raw_size"] <= 1000000
            assert item["json_size"] <= 1000000
            for record in item["records"]:
                expected = sized_record(record["chunk_id"])
                assert {key: record[key] for key in expected} == expected
                assert isinstance(record["@timestamp"], (int, float))
    finally:
        gates.release_all()
        stop_checked(service)
    assert not gates.errors


@pytest.mark.parametrize("compress", ["off", "on"])
def test_byte_closed_sender_does_not_acknowledge_next_collecting_chunk(tmp_path, monkeypatch, compress):
    service = batch_service(tmp_path, count=0, wait_ms=4000)
    port = service.service.allocate_port_env("TEST_BYTE_INPUT_PORT")
    path = Path(service.service.config_path)
    config = yaml.safe_load(path.read_text())
    config["service"]["flush"] = 0.05
    config["pipeline"]["inputs"] = [{"name": "http", "listen": "127.0.0.1", "port": port}]
    config["pipeline"]["outputs"][0].update({"compress": compress, "batch_target_size": 1000000})
    path.write_text(yaml.safe_dump(config))
    gates = Gates(monkeypatch, max_bytes=1000000)
    try:
        service.start()
        for chunk_id in range(3):
            response = requests.post(f"http://127.0.0.1:{port}/chunk.{chunk_id}",
                                     json=sized_record(chunk_id), timeout=5)
            response.raise_for_status()
            service.service.wait_for_condition(
                lambda: len(re.findall(r"\[task\] created task=.* OK",
                                       Path(service.flb.log_file).read_text())) == chunk_id + 1,
                timeout=10, interval=0.02, description=f"admitted engine chunk {chunk_id}")
        first = gates.wait(service, 1)
        assert {r["chunk_id"] for r in first["records"]} == {0, 1}
        assert len(gates.requests) == 1  # Chunk 2 is still collecting, not the old sender.
        assert metrics(service)["proc_records"] == 0
        second = gates.wait(service, 2)
        assert {r["chunk_id"] for r in second["records"]} == {2}
        assert second["time"] - first["time"] >= 3
        assert not first["gate"].is_set()
        second["gate"].set()
        service.service.wait_for_condition(lambda: metrics(service)["proc_records"] == 1,
                                           timeout=10, description="only later chunk acknowledged")
        assert not first["gate"].is_set()
        first["gate"].set()
        service.service.wait_for_condition(lambda: metrics(service)["proc_records"] == 3,
                                           timeout=10, description="old members acknowledged together")
        assert len(gates.requests) == 2
        assert all(item["raw_size"] <= 1000000 and item["json_size"] <= 1000000
                   for item in gates.requests)
    finally:
        gates.release_all()
        stop_checked(service)
    assert not gates.errors


@pytest.mark.parametrize("compress", ["off", "on"])
def test_exact_service_limit_closes_without_collection_expiry(tmp_path, monkeypatch, compress):
    service = batch_service(tmp_path, wait_ms=60000)
    path = Path(service.service.config_path)
    config = yaml.safe_load(path.read_text())
    for chunk_id, source in enumerate(config["pipeline"]["inputs"]):
        source.update({"dummy": json.dumps(exact_size_record(chunk_id, 333334)), "copies": 1})
    config["pipeline"]["outputs"][0].update(
        {"time_generated": True, "compress": compress, "batch_target_size": 1000000})
    path.write_text(yaml.safe_dump(config))
    gates = Gates(monkeypatch, max_bytes=1000000)
    try:
        service.start()
        item = gates.wait(service, 1)  # Receiver wait is shorter than the 60s collection deadline.
        assert item["json_size"] == 1000000
        assert item["raw_size"] <= 1000000
        assert collections.Counter(r["chunk_id"] for r in item["records"]) == {0: 1, 1: 1, 2: 1}
        assert metrics(service)["proc_records"] == 0
        item["gate"].set()
        service.service.wait_for_condition(lambda: metrics(service)["proc_records"] == 3,
                                           timeout=10, description="exact-limit members acknowledged")
        assert len(gates.requests) == 1
    finally:
        gates.release_all()
        stop_checked(service)
    assert not gates.errors


@pytest.mark.parametrize("compress", ["off", "on"])
def test_oversized_single_chunk_isolated_and_retried(tmp_path, monkeypatch, compress):
    service = batch_service(tmp_path, count=0, wait_ms=500)
    port = service.service.allocate_port_env("TEST_OVERSIZE_INPUT_PORT")
    path = Path(service.service.config_path)
    config = yaml.safe_load(path.read_text())
    config["service"].update({"flush": 0.05, "scheduler.base": 1, "scheduler.cap": 1})
    config["pipeline"]["inputs"] = [{"name": "http", "listen": "127.0.0.1", "port": port}]
    config["pipeline"]["outputs"][0].update({"compress": compress, "retry_limit": 1})
    path.write_text(yaml.safe_dump(config))
    gates = Gates(monkeypatch, max_bytes=1000000)
    try:
        service.start()
        for chunk_id, fields in [(0, 10), (1, 30), (2, 10)]:
            response = requests.post(f"http://127.0.0.1:{port}/chunk.{chunk_id}",
                                     json=sized_record(chunk_id, field_count=fields), timeout=5)
            response.raise_for_status()
        gates.wait(service, 1)
        gates.release_all()
        service.service.wait_for_condition(lambda: metrics(service)["proc_records"] == 2 and
                                           metrics(service)["retries_failed"] == 1,
                                           timeout=15, description="valid peers delivered; singleton retry exhausted")
        oversized = [item for item in gates.requests if item["json_size"] > 1000000]
        valid = [item for item in gates.requests if item["json_size"] <= 1000000]
        assert len(oversized) == 2
        assert all([r["chunk_id"] for r in item["records"]] == [1] for item in oversized)
        assert all(item["status"] == 413 for item in oversized)
        assert collections.Counter(r["chunk_id"] for item in valid
                                   for r in item["records"]) == {0: 1, 2: 1}
        assert all(item["raw_size"] <= 1000000 and item["status"] == 200 for item in valid)
        assert 3 <= len(gates.requests) <= 4
        assert metrics(service)["retries"] == 1
    finally:
        gates.release_all()
        stop_checked(service)
    assert not gates.errors


def test_three_chunks_wait_for_shared_response(tmp_path, monkeypatch):
    service = batch_service(tmp_path)
    gates = Gates(monkeypatch)

    try:
        service.start()
        gates.wait(service, 1)
        data = [r for r in http_server.data_storage["requests"]
                if r["path"].startswith("/dataCollectionRules/")]
        assert len(data) == 1
        assert collections.Counter(r["chunk_id"] for r in data[0]["json"]) == {0: 1, 1: 2, 2: 3}
        assert data[0]["headers"]["Content-Encoding"] == "gzip"
        assert data[0]["headers"]["Authorization"] == "Bearer oauth-access-token"
        assert all(isinstance(r["@timestamp"], (int, float)) for r in data[0]["json"])
        assert metrics(service)["proc_records"] == 0
        gates.release_all()
        service.service.wait_for_condition(lambda: metrics(service)["proc_records"] == 6, timeout=10,
                                           description="all three engine chunks acknowledged")
    finally:
        gates.release_all()
        stop_checked(service)
    assert not gates.errors


def test_closed_batches_complete_independently(tmp_path, monkeypatch):
    service = batch_service(tmp_path, count=6, wait_ms=2000, chunk_bytes=330000)
    path = Path(service.service.config_path)
    config = yaml.safe_load(path.read_text())
    config["pipeline"]["outputs"][0]["batch_target_size"] = 1000000
    path.write_text(yaml.safe_dump(config))
    gates = Gates(monkeypatch)
    try:
        service.start()
        second = gates.wait(service, 2)
        first = gates.requests[0]
        assert len(gates.requests) == 2
        assert len({r["chunk_id"] for r in first["records"]}) == 3
        assert len({r["chunk_id"] for r in second["records"]}) == 3
        assert collections.Counter(r["chunk_id"] for item in gates.requests
                                   for r in item["records"]) == {i: i + 1 for i in range(6)}
        assert metrics(service)["proc_records"] == 0
        second["gate"].set()
        service.service.wait_for_condition(
            lambda: metrics(service)["proc_records"] == len(second["records"]),
            timeout=10, description="only second batch acknowledged")
        assert not first["gate"].is_set()
        first["gate"].set()
        service.service.wait_for_condition(lambda: metrics(service)["proc_records"] == 21,
                                           timeout=10, description="both batches acknowledged")
    finally:
        gates.release_all()
        stop_checked(service)
    assert not gates.errors


@pytest.mark.parametrize("count", [1, 2])
def test_partial_batch_uses_first_member_deadline(tmp_path, monkeypatch, count):
    service = batch_service(tmp_path, count=count, wait_ms=4000)
    path = Path(service.service.config_path)
    config = yaml.safe_load(path.read_text())
    config["service"]["flush"] = 0.1
    for i, source in enumerate(config["pipeline"]["inputs"]):
        source["interval_sec"] = 1 + 2 * i
    path.write_text(yaml.safe_dump(config))
    gates = Gates(monkeypatch)
    try:
        service.start()
        item = gates.wait(service, 1)
        assert collections.Counter(r["chunk_id"] for r in item["records"]) == {
            i: i + 1 for i in range(count)}
        log = Path(service.flb.log_file).read_text()
        tasks = re.findall(r"\[([0-9/]+ [0-9:.]+)\].*\[task\] created task=.* id=(\d+) OK", log)
        assert len(tasks) == count, log
        opened = re.findall(r"batch created: now=(\d+) deadline=(\d+)", log)
        closed = re.findall(r"batch closed: deadline=(\d+) now=(\d+) chunks=(\d+)", log)
        assert len(opened) == len(closed) == 1, log
        created_at, first_deadline = map(int, opened[0])
        deadline, closed_at, chunks = map(int, closed[0])
        logging.getLogger(__name__).info(
            "partial count=%s first_deadline=%s closed_deadline=%s closed_at=%s chunks=%s",
            count, first_deadline, deadline, closed_at, chunks)
        # Later admission must not restart collection; OAuth/TLS follow its closure.
        assert first_deadline - created_at == 4000
        assert deadline == first_deadline
        assert 0 <= closed_at - first_deadline < 1500
        assert chunks == count
        assert metrics(service)["proc_records"] == 0
        item["gate"].set()
        service.service.wait_for_condition(
            lambda: metrics(service)["proc_records"] == sum(range(1, count + 1)),
            timeout=10, description="partial batch acknowledged")
    finally:
        gates.release_all()
        stop_checked(service)
    assert not gates.errors


@pytest.mark.parametrize("status", [500, 413])
def test_shared_failure_uses_finite_engine_retries(tmp_path, monkeypatch, status):
    service = batch_service(tmp_path, wait_ms=3000)
    path = Path(service.service.config_path)
    config = yaml.safe_load(path.read_text())
    config["service"].update({"scheduler.base": 1, "scheduler.cap": 1})
    config["pipeline"]["outputs"][0]["retry_limit"] = 1
    path.write_text(yaml.safe_dump(config))
    gates = Gates(monkeypatch)
    try:
        service.start()
        first = gates.wait(service, 1)
        assert metrics(service)["proc_records"] == 0
        assert metrics(service)["retries"] == 0
        first["status"] = status
        first["gate"].set()
        second = gates.wait(service, 2)
        assert metrics(service)["proc_records"] == 0
        assert metrics(service)["retries"] == 3
        expected = {0: 1, 1: 2, 2: 3}
        assert collections.Counter(r["chunk_id"] for r in first["records"]) == expected
        assert collections.Counter(r["chunk_id"] for r in second["records"]) == expected
        second["status"] = status
        second["gate"].set()
        service.service.wait_for_condition(lambda: metrics(service)["retries_failed"] == 3,
                                           timeout=10, description="all engine retries exhausted")
        assert metrics(service)["proc_records"] == 0
        assert len(gates.requests) == 2
    finally:
        gates.release_all()
        stop_checked(service)
    assert not gates.errors
    log = Path(service.flb.log_file).read_text()
    assert log.count("cannot be retried") == 3


@pytest.mark.parametrize("options", [
    {"batch_chunk_count": 3},
    {"batch_chunk_count": 3, "batch_wait_ms": 1000},
    {"batch_wait_ms": 0},
    {"batch_wait_ms": -1},
    {"batch_wait_ms": "999999999999999999999"},
    {"batch_wait_ms": "1000junk"},
    pytest.param({"batch_wait_ms": 1000, "workers": -1}, id="negative-workers"),
    {"batch_wait_ms": 1000, "workers": 1},
    {"batch_wait_ms": 1000, "workers": 2},
    {"batch_wait_ms": 1000, "http_timeout": 5},
    {"http.response_timeout": "5s"},
    {"batch_wait_ms": 1000, "http.response_timeout": "5s"},
] + [
    pytest.param({"batch_target_size": target, **wait_options},
                 id=f"target-{label}-{mode}")
    for target, label in [(" ", "blank"), (0, "zero"), (-1, "negative"),
                          (1000001, "above-ceiling"), ("999999999999999999999", "overflow"),
                          ("800000junk", "junk"), ("800K", "suffix"), ("800000.5", "fraction")]
    for wait_options, mode in [({}, "unbatched"), ({"batch_wait_ms": 1000}, "batched")]
])
def test_batch_configuration_rejected_before_suspension(tmp_path, options):
    import subprocess
    from utils.fluent_bit_manager import FluentBitManager
    from utils.memory_check import leaks_enabled, valgrind_enabled

    # Actual initialization, not --dry-run (which skips plugin cb_init).
    output = {"name": "azure_logs_ingestion", "match": "*", "workers": 0,
              "client_id": "suite", "client_secret": "suite", "tenant_id": "suite",
              "auth_url": "http://127.0.0.1:1/oauth/token", "dce_url": "https://localhost:1",
              "dcr_id": "suite", "table_name": "suite_CL", **options}
    path = tmp_path / "invalid.yaml"
    path.write_text(yaml.safe_dump({"pipeline": {"inputs": [{"name": "dummy"}],
                                                "outputs": [output]}}))
    command = [FluentBitManager(str(path)).binary_absolute_path, "-c", str(path)]
    if leaks_enabled():
        command = ["leaks", "-fullStacks", "-atExit", "--", *command]
    elif valgrind_enabled():
        command = ["valgrind", "--leak-check=full", "--show-leak-kinds=all",
                   "--errors-for-leak-kinds=definite,indirect", "--error-exitcode=99", *command]
    result = subprocess.run(command, capture_output=True, text=True, timeout=60)
    report = result.stdout + result.stderr
    (tmp_path / "startup.log").write_text(report)
    logging.getLogger(__name__).info("startup check options=%s exit=%s report=%s",
                                     options, result.returncode, tmp_path / "startup.log")
    if "http.response_timeout" in options:
        assert "unknown configuration property 'http.response_timeout'" in report
    elif "http_timeout" in options:
        assert "unknown configuration property 'http_timeout'" in report
    elif "batch_chunk_count" in options:
        assert "unknown configuration property 'batch_chunk_count'" in report
    elif options.get("batch_target_size") == " ":
        # Space-only values fail in YAML parsing, before plugin initialization.
        assert "unable to add variant value property" in report
    elif "batch_target_size" in options:
        assert "batch_target_size must be an integer from 1 to 1000000 bytes" in report
    else:
        assert "batching requires positive batch_wait_ms and workers=0" in report
    if leaks_enabled():
        # Leaks reports its own status, independently of the expected startup rejection.
        assert result.returncode == 0, report
        assert "0 leaks for 0 total leaked bytes" in report, report
    else:
        expected_exit = 1 if options.get("batch_target_size") == " " else 255
        assert result.returncode == expected_exit, report
        if valgrind_enabled():
            assert "ERROR SUMMARY: 0 errors" in report, report


def linux_timer_count(service):
    timers = 0
    pid = service.flb.target_pid or service.flb.process.pid
    for descriptor in Path(f"/proc/{pid}/fd").iterdir():
        try:
            timers += os.readlink(descriptor) == "anon_inode:[timerfd]"
        except FileNotFoundError:
            continue
    return timers


@pytest.mark.skipif(not Path("/proc/self/fd").is_dir(), reason="requires Linux timerfd accounting")
def test_idle_batching_does_not_add_scheduler_timers(tmp_path):
    counts = []
    for enabled in (False, True):
        service = batch_service(tmp_path, count=1)
        path = Path(service.service.config_path)
        config = yaml.safe_load(path.read_text())
        config["pipeline"]["inputs"][0]["interval_sec"] = 3600
        if not enabled:
            output = config["pipeline"]["outputs"][0]
            del output["batch_wait_ms"]
        path.write_text(yaml.safe_dump(config))
        try:
            service.start()
            counts.append(linux_timer_count(service))
        finally:
            stop_checked(service)
    assert counts[1] == counts[0], counts


@pytest.mark.skipif(not Path("/proc/self/fd").is_dir(), reason="requires Linux timerfd accounting")
def test_batch_timer_rearms_and_releases_after_delivery(tmp_path, monkeypatch):
    service = batch_service(tmp_path, wait_ms=10000)
    port = service.service.allocate_port_env("TEST_BATCH_INPUT_PORT")
    path = Path(service.service.config_path)
    config = yaml.safe_load(path.read_text())
    config["service"]["flush"] = 0.1
    config["pipeline"]["outputs"][0].update({"time_generated": True, "batch_target_size": 1000000})
    config["pipeline"]["inputs"] = [
        {"name": "http", "listen": "127.0.0.1", "port": port}]
    path.write_text(yaml.safe_dump(config))
    gates = Gates(monkeypatch)
    try:
        service.start()
        idle_timers = linux_timer_count(service)
        for batch in range(2):
            first = batch * 3
            response = requests.post(f"http://127.0.0.1:{port}/chunk.{first}",
                                     json=exact_size_record(first, 333334), timeout=5)
            response.raise_for_status()
            service.service.wait_for_condition(
                lambda: linux_timer_count(service) == idle_timers + 1,
                timeout=5, description="batch timer armed for pending chunk")
            for chunk_id in range(first + 1, first + 3):
                response = requests.post(f"http://127.0.0.1:{port}/chunk.{chunk_id}",
                                         json=exact_size_record(chunk_id, 333334), timeout=5)
                response.raise_for_status()
            item = gates.wait(service, batch + 1)
            assert {record["chunk_id"] for record in item["records"]} == set(range(first, first + 3))
            assert item["json_size"] == 1000000
            item["gate"].set()
            service.service.wait_for_condition(
                lambda: metrics(service)["proc_records"] == first + 3,
                timeout=10, description="batch delivered")
            service.service.wait_for_condition(
                lambda: linux_timer_count(service) == idle_timers,
                timeout=5, description="batch timer released after delivery")
    finally:
        gates.release_all()
        stop_checked(service)
    assert not gates.errors


CHUNKS = "fluentbit_azure_logs_ingestion_chunks_per_request"
RESPONSES = "fluentbit_azure_logs_ingestion_http_responses_total"


def request_metric(service, metric_name, **labels):
    def snapshot():
        response = requests.get(
            f"http://127.0.0.1:{service.flb.http_monitoring_port}/api/v2/metrics/prometheus", timeout=2)
        # The endpoint returns 404 until the first periodic metrics snapshot exists.
        if response.status_code == 404:
            return None
        response.raise_for_status()
        return response.text

    text = service.service.wait_for_condition(
        snapshot, timeout=10, interval=0.05, description="first Prometheus metrics snapshot")
    for line in text.splitlines():
        match = re.match(r'^([^ {]+)\{([^}]+)\} ([^ ]+)', line)
        if match and match[1] == metric_name:
            actual = dict(re.findall(r'(\w+)="([^"]*)"', match[2]))
            if actual == labels:
                return float(match[3])
    return 0


@pytest.mark.parametrize("chunk_count", [1, 3])
@pytest.mark.parametrize("status", [200, 204, 413, 429, 500])
def test_request_metrics_count_attempt_not_participants(tmp_path, monkeypatch, chunk_count, status):
    service = batch_service(tmp_path, count=chunk_count)
    path = Path(service.service.config_path)
    config = yaml.safe_load(path.read_text())
    config["service"].update({"scheduler.base": 1, "scheduler.cap": 1})
    output = config["pipeline"]["outputs"][0]
    output["retry_limit"] = 1
    if chunk_count == 1:
        del output["batch_wait_ms"]
    path.write_text(yaml.safe_dump(config))
    gates = Gates(monkeypatch)
    labels = {"name": "azure_logs_ingestion.0", "dcr_id": "dcr-suite"}
    try:
        service.start()
        item = gates.wait(service, 1)
        service.service.wait_for_condition(
            lambda: request_metric(service, CHUNKS + "_count", **labels) == 1,
            timeout=5, description="one request attempt histogram observation")
        assert request_metric(service, CHUNKS + "_sum", **labels) == chunk_count
        assert request_metric(service, RESPONSES, **labels, status=str(status)) == 0
        item["status"] = status
        item["gate"].set()
        service.service.wait_for_condition(
            lambda: request_metric(service, RESPONSES, **labels, status=str(status)) == 1,
            timeout=10, description="one completed ingestion response")
        if status >= 400:
            retry = gates.wait(service, 2)
            service.service.wait_for_condition(
                lambda: request_metric(service, CHUNKS + "_count", **labels) == 2,
                timeout=10, description="engine retry attempt observed")
            assert request_metric(service, CHUNKS + "_sum", **labels) == 2 * chunk_count
            assert request_metric(service, RESPONSES, **labels, status=str(status)) == 1
            retry["status"] = status
            retry["gate"].set()
            service.service.wait_for_condition(
                lambda: metrics(service)["retries_failed"] == chunk_count,
                timeout=10, description="finite retry exhausted")
            service.service.wait_for_condition(
                lambda: request_metric(service, RESPONSES, **labels, status=str(status)) == 2,
                timeout=10, description="second completed failure response")
        assert request_metric(service, CHUNKS + "_count", **labels) == len(gates.requests)
        assert request_metric(service, CHUNKS + "_sum", **labels) == sum(
            len({record["chunk_id"] for record in received["records"]})
            for received in gates.requests)
    finally:
        gates.release_all()
        stop_checked(service)
    assert not gates.errors


def test_request_metrics_isolate_output_alias_and_dcr(tmp_path, monkeypatch):
    service = batch_service(tmp_path)
    path = Path(service.service.config_path)
    config = yaml.safe_load(path.read_text())
    first = config["pipeline"]["outputs"][0]
    first["alias"] = "first-output"
    second = dict(first, alias="second-output", dcr_id="other-dcr")
    config["pipeline"]["outputs"].append(second)
    path.write_text(yaml.safe_dump(config))
    gates = Gates(monkeypatch)
    try:
        service.start()
        gates.wait(service, 2)
        for alias, dcr, status in [("first-output", "dcr-suite", 200),
                                   ("second-output", "other-dcr", 204)]:
            labels = {"name": alias, "dcr_id": dcr}
            service.service.wait_for_condition(
                lambda: request_metric(service, CHUNKS + "_count", **labels) == 1,
                timeout=10, description=f"attempt for {alias}")
            assert request_metric(service, CHUNKS + "_sum", **labels) == 3
            assert request_metric(service, RESPONSES, **labels, status=str(status)) == 0
            item = next(item for item in gates.requests if f"/{dcr}/" in item["path"])
            item["status"] = status
            item["gate"].set()
            service.service.wait_for_condition(
                lambda: request_metric(service, RESPONSES, **labels, status=str(status)) == 1,
                timeout=10, description=f"completed response for {alias}")
            assert request_metric(service, CHUNKS + "_count", name=alias,
                                  dcr_id="other-dcr" if dcr == "dcr-suite" else "dcr-suite") == 0
    finally:
        gates.release_all()
        stop_checked(service)
    assert not gates.errors
