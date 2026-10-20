#!/usr/bin/env python3
"""Isolated real-PHP regressions for retired legacy endpoints; no external effects.

Requires PHP CLI; PDO/sqlite extensions are used only to reproduce the old
authority bugs on a synthetic fixture. Production PHP needs neither dependency.
"""
import argparse
import contextlib
import hashlib
import http.client
import json
import os
from pathlib import Path
import shutil
import socket
import sqlite3
import subprocess
import tempfile
import time
import unittest
from urllib.parse import urlencode

from nacl.signing import SigningKey

ARGS = None
OBSERVATIONS = []
VICTIM = "a" * 64
OTHER = "b" * 64


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


@contextlib.contextmanager
def server(work, extensions=True):
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    command = [ARGS.php, "-n", "-d", "allow_url_fopen=0", "-d", "allow_url_include=0",
               "-d", "display_errors=0", "-d", "log_errors=0", "-d", "max_execution_time=5",
               "-d", "open_basedir=" + str(work), "-d", "auto_prepend_file=" + str(work / "prepend.php"),
               "-d", "disable_functions=curl_init,curl_exec,mail,exec,system,passthru,shell_exec,proc_open,popen,fsockopen,pfsockopen,stream_socket_client"]
    if extensions:
        command += ["-d", "extension=" + str(Path(ARGS.extensions) / "pdo.so"),
                    "-d", "extension=" + str(Path(ARGS.extensions) / "pdo_sqlite.so")]
    command += ["-S", f"127.0.0.1:{port}", "-t", str(work / "web")]
    with (work / ("server.log" if extensions else "no-driver-server.log")).open("wb") as log:
        process = subprocess.Popen(command, cwd=work, stdout=log, stderr=log,
                                   env={**os.environ, "PHP_CLI_SERVER_WORKERS": "1"})
        try:
            deadline = time.monotonic() + 5
            while True:
                if process.poll() is not None:
                    raise RuntimeError("PHP test server exited; inspect private fixture log")
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=.1):
                        break
                except OSError:
                    if time.monotonic() > deadline:
                        raise RuntimeError("PHP test server startup timeout")
                    time.sleep(.02)
            yield port
        finally:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)


class LegacyPhpBoundaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not ARGS.php or not Path(ARGS.php).is_file():
            raise RuntimeError("Supply a real PHP CLI with --php")
        cls.fixture = tempfile.TemporaryDirectory(prefix="dmash-php-security-", dir=ARGS.fixture_parent)
        cls.work = Path(cls.fixture.name)
        (cls.work / "web/api").mkdir(parents=True)
        (cls.work / "state").mkdir()
        cls.dbpath = cls.work / "state/relay.sqlite"
        cls.source_hashes = {}
        for name in ["pidorskiy_api.php", "tg_webhook.php"]:
            source = Path(ARGS.source_root) / "D-MASH PWA/api" / name
            cls.source_hashes[name] = digest(source)
            # The historical placeholder DB_PATH is the only substituted source
            # field. Actual handler/authentication logic is never reimplemented.
            content = source.read_text().replace(
                "define('DB_PATH', __DIR__ . 'YOUR_PATH/relay_vault.db');",
                "define('DB_PATH', '" + str(cls.dbpath).replace("\\", "\\\\").replace("'", "\\'") + "');")
            (cls.work / "web/api" / name).write_text(content)
        (cls.work / "prepend.php").write_text("""<?php
if (($_SERVER['HTTP_X_BODY_TRAP'] ?? '') === 'yes') {
    class InputTrap { public $context;
        public function stream_open($path, $mode, $options, &$opened_path) {
            file_put_contents(__DIR__ . '/body-read-trap', 'attempted');
            throw new RuntimeException('synthetic body read trap');
        }
    }
    stream_wrapper_unregister('php'); stream_wrapper_register('php', InputTrap::class);
}
""")
        cls.running = server(cls.work)
        cls.port = cls.running.__enter__()

    @classmethod
    def tearDownClass(cls):
        cls.running.__exit__(None, None, None)
        cls.fixture.cleanup()

    def setUp(self):
        for suffix in ["", "-wal", "-shm"]:
            (Path(str(self.dbpath) + suffix)).unlink(missing_ok=True)
        for path in self.work.rglob("tg_error.log"):
            path.unlink()
        (self.work / "body-read-trap").unlink(missing_ok=True)
        with sqlite3.connect(self.dbpath) as db:
            db.executescript("""CREATE TABLE spool(id INTEGER PRIMARY KEY,r_hash TEXT,s_pub TEXT,sig TEXT,blob TEXT,ts INTEGER,is_voip INTEGER DEFAULT 0);
CREATE TABLE tg_notif(h TEXT PRIMARY KEY,tg_id TEXT,last_msg_id INTEGER DEFAULT NULL);
CREATE TABLE online_status(h TEXT PRIMARY KEY,last_seen INTEGER);
CREATE TABLE voip_cooldown(h TEXT PRIMARY KEY,last_call INTEGER);""")
            db.execute("INSERT INTO spool(r_hash,s_pub,sig,blob,ts) VALUES(?,?,?,?,?)",
                       (VICTIM, "c" * 64, "d" * 128, "11", int(time.time())))

    def state(self):
        with sqlite3.connect(self.dbpath) as db:
            return {table: db.execute("SELECT * FROM " + table).fetchall()
                    for table in ["spool", "tg_notif", "online_status"]}

    def request(self, endpoint, method="POST", body=b"{}", headers=None, query="", port=None):
        connection = http.client.HTTPConnection("127.0.0.1", port or self.port, timeout=3)
        try:
            connection.request(method, "/api/" + endpoint + query, body=body,
                               headers=headers or {"Content-Type": "application/json"},
                               encode_chunked=not isinstance(body, (bytes, str)))
            response = connection.getresponse()
            return response.status, dict(response.getheaders()), response.read(1024 * 1024)
        finally:
            connection.close()

    def observe(self, label, response, before):
        state = self.state()
        try:
            parsed = json.loads(response[2])
        except (ValueError, UnicodeDecodeError):
            parsed = None
        OBSERVATIONS.append({"case": label, "status": response[0], "body_bytes": len(response[2]),
                             "db_changed": state != before, "victim_rows_remaining": len(state["spool"]),
                             "binding_rows": len(state["tg_notif"]),
                             "returned_rows": len(parsed) if isinstance(parsed, list) else None,
                             "application_body_read": (self.work / "body-read-trap").exists(),
                             "exception_log_created": bool(list(self.work.rglob("tg_error.log")))})

    def refused(self, response):
        self.assertEqual(response[0], 410)
        self.assertLessEqual(len(response[2]), 256)
        self.assertNotIn("Access-Control-Allow-Origin", response[1])
        self.assertNotIn("X-Powered-By", response[1])

    def test_static_agent_header_cannot_bind_notification_alias(self):
        before = self.state()
        response = self.request("pidorskiy_api.php", body=json.dumps({"set_tg": True, "h": VICTIM, "tg_id": "synthetic-chat"}).encode(),
                                headers={"X-DMASH-AGENT": "V1Silent-Node", "Content-Type": "application/json"})
        self.observe("unsigned relay binding", response, before)
        self.refused(response)
        self.assertEqual(self.state(), before)

    def test_own_valid_signature_cannot_read_or_delete_another_alias(self):
        before = self.state()
        key = SigningKey.generate()
        timestamp = str(int(time.time()))
        signature = key.sign(key.verify_key.encode() + timestamp.encode()).signature.hex()
        query = "?" + urlencode({"h": VICTIM, "pub": key.verify_key.encode().hex(), "ts": timestamp, "sig": signature})
        response = self.request("pidorskiy_api.php", "GET", b"", {"X-DMASH-AGENT": "V1Silent-Node"}, query)
        self.observe("valid attacker signature wrong alias", response, before)
        self.refused(response)
        self.assertEqual(self.state(), before)

    def test_unsigned_webhook_cannot_rebind_alias(self):
        before = self.state()
        payload = {"message": {"chat": {"id": "synthetic-chat"}, "text": "/start " + OTHER}}
        response = self.request("tg_webhook.php", body=json.dumps(payload).encode())
        self.observe("unsigned webhook binding", response, before)
        self.refused(response)
        self.assertEqual(self.state(), before)

    def test_refusal_precedes_explicit_application_body_read(self):
        for endpoint in ["pidorskiy_api.php", "tg_webhook.php"]:
            with self.subTest(endpoint=endpoint):
                before = self.state()
                response = self.request(endpoint, body=b"malformed", headers={"X-BODY-TRAP": "yes", "X-DMASH-AGENT": "V1Silent-Node", "Content-Type": "application/octet-stream"})
                self.observe("body trap " + endpoint, response, before)
                self.refused(response)
                self.assertFalse((self.work / "body-read-trap").exists())
                self.assertEqual(self.state(), before)

    def test_methods_origins_and_public_header_never_enable_endpoint(self):
        for endpoint in ["pidorskiy_api.php", "tg_webhook.php"]:
            for method in ["GET", "POST", "PUT", "OPTIONS", "HEAD"]:
                for agent in [None, "wrong", "V1Silent-Node"]:
                    with self.subTest(endpoint=endpoint, method=method, agent=agent):
                        headers = {"Origin": "https://attacker.invalid", "Content-Type": "application/json"}
                        if agent:
                            headers["X-DMASH-AGENT"] = agent
                        response = self.request(endpoint, method, b"{}", headers)
                        self.refused(response)

    def test_malformed_large_and_chunked_bodies_are_not_parsed_or_echoed(self):
        before = self.state()
        for endpoint in ["pidorskiy_api.php", "tg_webhook.php"]:
            for payload in [b"{synthetic-sensitive-marker", b"x" * (512 * 1024), iter([b"{", b"not-json}"])]:
                with self.subTest(endpoint=endpoint, kind=type(payload).__name__):
                    response = self.request(endpoint, body=payload, headers={"X-DMASH-AGENT": "V1Silent-Node", "Content-Type": "application/json"})
                    self.refused(response)
                    self.assertNotIn(b"synthetic-sensitive-marker", response[2])
        self.assertEqual(self.state(), before)

    def test_db_failure_never_creates_public_exception_log(self):
        with sqlite3.connect(self.dbpath) as db:
            db.execute("DROP TABLE tg_notif")
        # The old webhook creates a raw tg_error.log under its web directory.
        response = self.request("tg_webhook.php", body=json.dumps({"message": {"chat": {"id": 123}, "text": "/start " + OTHER}}).encode())
        logs = list(self.work.rglob("tg_error.log"))
        public_log = False
        for path in logs:
            if path.is_relative_to(self.work / "web"):
                connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=3)
                try:
                    connection.request("GET", "/" + path.relative_to(self.work / "web").as_posix())
                    log_response = connection.getresponse()
                    public_log = log_response.status == 200 and b"SQLSTATE" in log_response.read(4096)
                finally:
                    connection.close()
        OBSERVATIONS.append({"case": "missing table log", "status": response[0],
                             "exception_log_created": bool(logs),
                             "exception_log_publicly_readable_in_fixture": public_log})
        self.refused(response)
        self.assertFalse(list(self.work.rglob("tg_error.log")))
        self.assertNotIn(b"SQLSTATE", response[2])

    def test_retired_handler_needs_no_db_or_network_extension(self):
        before = self.state()
        with server(self.work, extensions=False) as port:
            for endpoint in ["pidorskiy_api.php", "tg_webhook.php"]:
                response = self.request(endpoint, headers={"X-DMASH-AGENT": "V1Silent-Node"}, port=port)
                self.refused(response)
        self.assertEqual(self.state(), before)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--php", default=shutil.which("php"))
    parser.add_argument("--extensions", required=True, help="Owned PHP extension directory, including PDO/sqlite")
    parser.add_argument("--source-root", default=str(Path(__file__).resolve().parents[1]))
    parser.add_argument("--fixture-parent", default=None)
    parser.add_argument("--report", default=None)
    ARGS = parser.parse_args()
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(LegacyPhpBoundaryTests)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    if ARGS.report:
        Path(ARGS.report).write_text(json.dumps({"source_sha256": getattr(LegacyPhpBoundaryTests, "source_hashes", {}),
                                               "tests": result.testsRun, "failures": len(result.failures),
                                               "errors": len(result.errors), "observations": OBSERVATIONS}, indent=2) + "\n")
    raise SystemExit(0 if result.wasSuccessful() else 1)
