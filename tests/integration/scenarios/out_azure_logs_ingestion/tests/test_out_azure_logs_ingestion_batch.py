"""Real engine chunks: each finite dummy instance owns a distinct input chunk."""
import collections
import threading
import time
import logging
import datetime
import re
from pathlib import Path

import pytest

import requests
import yaml

from server import http_server
from test_out_azure_logs_ingestion_001 import Service


def batch_service(tmp_path, count=3, wait_ms=5000):
    service = Service("out_azure_logs_ingestion_oauth2.yaml")
    with open(service.config_file) as config_file:
        config = yaml.safe_load(config_file)
    config["service"]["log_level"] = "debug"
    config["pipeline"]["inputs"] = [
        {"name": "dummy", "tag": f"chunk.{i}", "dummy": f'{{"chunk_id":{i}}}',
         "samples": 1, "copies": i + 1}
        for i in range(count)
    ]
    config["pipeline"]["outputs"][0].update(
        {"match": "chunk.*", "workers": 0, "batch_chunk_count": 3, "batch_wait_ms": wait_ms}
    )
    config_path = tmp_path / "batch.yaml"
    config_path.write_text(yaml.safe_dump(config))
    service.service.config_path = str(config_path)
    return service


def metrics(service):
    response = requests.get(
        f"http://127.0.0.1:{service.flb.http_monitoring_port}/api/v1/metrics", timeout=2
    )
    response.raise_for_status()
    return response.json()["output"]["azure_logs_ingestion.0"]


def stop_checked(service):
    process = service.flb.process if hasattr(service, "flb") else None
    service.stop()  # Memory-checker assertions propagate; never swallow cleanup failures.
    if process is not None:
        assert process.returncode == 0, f"Fluent Bit/ checker exited with {process.returncode}"


class Gates:
    def __init__(self, monkeypatch):
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
        body = request.get_data()
        if request.headers.get("Content-Encoding") == "gzip":
            body = gzip.decompress(body)
        item = {"gate": gate, "records": json.loads(body), "status": 200,
                "time": time.time(), "path": request.path}
        with self.lock:
            self.requests.append(item)
        if self.closing.is_set():
            gate.set()
        if not gate.wait(30):
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
    service = batch_service(tmp_path, count=6)
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
        first = datetime.datetime.strptime(tasks[0][0], "%Y/%m/%d %H:%M:%S.%f").timestamp()
        elapsed = item["time"] - first
        logging.getLogger(__name__).info("partial count=%s first-member elapsed=%.3fs tasks=%s",
                                         count, elapsed, tasks)
        # Later source arrives two seconds later. Refreshing the deadline would take ~6s.
        assert 3.8 <= elapsed < 5.5
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
    {"batch_wait_ms": 1000},
    {"batch_chunk_count": 0, "batch_wait_ms": 1000},
    {"batch_chunk_count": 3, "batch_wait_ms": -1},
    {"batch_chunk_count": "999999999999999999999", "batch_wait_ms": 1000},
    {"batch_chunk_count": 3, "batch_wait_ms": "1000junk"},
    {"batch_chunk_count": 3, "batch_wait_ms": 1000, "workers": 1},
    {"batch_chunk_count": 3, "batch_wait_ms": 1000, "workers": 2},
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
    assert "batching requires positive batch_chunk_count and batch_wait_ms and workers=0" in report
    if leaks_enabled():
        # Leaks reports its own status, independently of the expected startup rejection.
        assert result.returncode == 0, report
        assert "0 leaks for 0 total leaked bytes" in report, report
    else:
        assert result.returncode == 255, report
        if valgrind_enabled():
            assert "ERROR SUMMARY: 0 errors" in report, report


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
        del output["batch_chunk_count"]
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
