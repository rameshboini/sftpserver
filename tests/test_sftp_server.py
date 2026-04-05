from __future__ import annotations

import base64
import contextlib
import json
import os
import stat
import tempfile
import time
import unittest
from pathlib import Path

import paramiko

from sftp_server import AppConfig, ThreadedSFTPServer, build_app_config


def write_public_key(path: Path, key: paramiko.PKey) -> None:
    public_line = f"{key.get_name()} {base64.b64encode(key.asbytes()).decode('ascii')}\n"
    path.write_text(public_line, encoding="utf-8")


class SFTPServerIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls._tmp = tempfile.TemporaryDirectory()
        cls.tmpdir = Path(cls._tmp.name)
        cls.config_dir = cls.tmpdir / "config"
        cls.config_dir.mkdir()

        cls.password_only_key = paramiko.RSAKey.generate(2048)
        cls.key_only_key = paramiko.RSAKey.generate(2048)
        cls.hybrid_key = paramiko.RSAKey.generate(2048)
        cls.bad_key = paramiko.RSAKey.generate(2048)

        write_public_key(cls.config_dir / "password_only.pub", cls.password_only_key)
        write_public_key(cls.config_dir / "key_only.pub", cls.key_only_key)
        write_public_key(cls.config_dir / "hybrid.pub", cls.hybrid_key)

        config_data = {
            "server": {
                "host": "127.0.0.1",
                "port": 0,
                "host_key": "./host_rsa.key",
                "max_connections_total": 20,
                "idle_session_timeout": 30,
                "allow_symlinks": True,
                "audit_log": "./logs/audit.jsonl",
            },
            "users": [
                {
                    "username": "password_only",
                    "password": "pw-secret",
                    "permissions": "read_write",
                    "root": "./data/password_only",
                    "description": "Typical app integration account using password auth.",
                },
                {
                    "username": "key_only",
                    "authorized_keys": ["./key_only.pub"],
                    "permissions": "read_write",
                    "root": "./data/key_only",
                    "description": "Automation account using SSH key auth only.",
                },
                {
                    "username": "hybrid",
                    "password": "hybrid-secret",
                    "authorized_keys": ["./hybrid.pub"],
                    "permissions": "read_write",
                    "root": "./data/hybrid",
                    "description": "User that supports both password and key auth.",
                },
                {
                    "username": "readonly",
                    "password": "read-secret",
                    "permissions": "read_only",
                    "root": "./data/readonly",
                    "description": "Partner or reporting account that may download only.",
                },
                {
                    "username": "writer",
                    "password": "write-secret",
                    "permissions": "read_write",
                    "root": "./data/writer",
                    "description": "Operational account with full read/write access.",
                },
            ],
        }

        cls.config_path = cls.config_dir / "server_config.json"
        cls.config_path.write_text(json.dumps(config_data, indent=2), encoding="utf-8")

        cls.config: AppConfig = build_app_config(cls.config_path)
        cls.server = ThreadedSFTPServer(
            cls.config,
            paramiko.RSAKey.generate(2048),
        )
        cls.server.start()
        cls.host, cls.port = cls.server.address
        time.sleep(0.1)
        cls.audit_log_path = cls.config.server.audit_log_path
        assert cls.audit_log_path is not None

        readonly_root = cls.config.users["readonly"].root
        readonly_root.mkdir(parents=True, exist_ok=True)
        (readonly_root / "report.txt").write_text("readonly-data", encoding="utf-8")

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls._tmp.cleanup()

    def connect(
        self,
        username: str,
        password: str | None = None,
        pkey: paramiko.PKey | None = None,
    ) -> tuple[paramiko.Transport, paramiko.SFTPClient]:
        transport = paramiko.Transport((self.host, self.port))
        transport.connect(username=username, password=password, pkey=pkey)
        return transport, paramiko.SFTPClient.from_transport(transport)

    def close_client(self, transport: paramiko.Transport, sftp: paramiko.SFTPClient) -> None:
        sftp.close()
        transport.close()

    def read_audit_events(self) -> list[dict]:
        if not self.audit_log_path.exists():
            return []
        return [
            json.loads(line)
            for line in self.audit_log_path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]

    def test_build_app_config_loads_multiple_users(self) -> None:
        self.assertEqual(self.config.server.host, "127.0.0.1")
        self.assertIn("password_only", self.config.users)
        self.assertIn("key_only", self.config.users)
        self.assertEqual(self.config.users["readonly"].permissions, "read_only")
        self.assertTrue(self.config.users["hybrid"].allows_password)
        self.assertTrue(self.config.users["hybrid"].allows_public_key)
        self.assertTrue(self.config.server.allow_symlinks)
        self.assertEqual(self.config.server.max_connections_total, 20)
        self.assertIsNone(self.config.server.max_connections_per_user)
        self.assertEqual(self.config.server.idle_session_timeout, 30)
        self.assertEqual(self.config.server.audit_log_path, self.audit_log_path)

    def test_password_only_user_can_authenticate_with_password(self) -> None:
        transport, sftp = self.connect("password_only", password="pw-secret")
        try:
            self.assertEqual(sftp.normalize("."), "/")
        finally:
            self.close_client(transport, sftp)

    def test_password_only_user_rejects_key_auth(self) -> None:
        transport = paramiko.Transport((self.host, self.port))
        try:
            with self.assertRaises(paramiko.AuthenticationException):
                transport.connect(username="password_only", pkey=self.password_only_key)
        finally:
            transport.close()

    def test_key_only_user_can_authenticate_with_key(self) -> None:
        transport, sftp = self.connect("key_only", pkey=self.key_only_key)
        try:
            self.assertEqual(sftp.normalize("."), "/")
        finally:
            self.close_client(transport, sftp)

    def test_key_only_user_rejects_password_auth(self) -> None:
        transport = paramiko.Transport((self.host, self.port))
        try:
            with self.assertRaises(paramiko.AuthenticationException):
                transport.connect(username="key_only", password="anything")
        finally:
            transport.close()

    def test_hybrid_user_supports_password_and_key(self) -> None:
        password_transport, password_sftp = self.connect("hybrid", password="hybrid-secret")
        try:
            self.assertEqual(password_sftp.normalize("."), "/")
        finally:
            self.close_client(password_transport, password_sftp)

        key_transport, key_sftp = self.connect("hybrid", pkey=self.hybrid_key)
        try:
            self.assertEqual(key_sftp.normalize("."), "/")
        finally:
            self.close_client(key_transport, key_sftp)

    def test_unknown_or_wrong_key_is_rejected(self) -> None:
        transport = paramiko.Transport((self.host, self.port))
        try:
            with self.assertRaises(paramiko.AuthenticationException):
                transport.connect(username="hybrid", pkey=self.bad_key)
        finally:
            transport.close()

    def test_user_roots_are_isolated(self) -> None:
        writer_transport, writer_sftp = self.connect("writer", password="write-secret")
        try:
            with writer_sftp.file("/writer.txt", "w") as remote_file:
                remote_file.write("writer-data")
        finally:
            self.close_client(writer_transport, writer_sftp)

        hybrid_transport, hybrid_sftp = self.connect("hybrid", password="hybrid-secret")
        try:
            self.assertNotIn("writer.txt", hybrid_sftp.listdir("/"))
            with self.assertRaises(IOError):
                hybrid_sftp.stat("/../../data/writer/writer.txt")
        finally:
            self.close_client(hybrid_transport, hybrid_sftp)

    def test_readonly_user_can_list_and_download(self) -> None:
        transport, sftp = self.connect("readonly", password="read-secret")
        try:
            self.assertIn("report.txt", sftp.listdir("/"))
            with sftp.file("/report.txt", "rb") as remote_file:
                self.assertEqual(remote_file.read(), b"readonly-data")
        finally:
            self.close_client(transport, sftp)

    def test_readonly_user_cannot_upload_delete_or_modify(self) -> None:
        transport, sftp = self.connect("readonly", password="read-secret")
        try:
            with self.assertRaises(IOError):
                with sftp.file("/new.txt", "w") as remote_file:
                    remote_file.write("blocked")
            with self.assertRaises(IOError):
                sftp.mkdir("/blocked-dir")
            with self.assertRaises(IOError):
                sftp.remove("/report.txt")
            with self.assertRaises(IOError):
                sftp.chmod("/report.txt", 0o600)
        finally:
            self.close_client(transport, sftp)

    def test_writer_user_can_upload_download_list_stat_remove(self) -> None:
        local_source = self.tmpdir / "sample.bin"
        payload = b"hello-sftp" * 100
        local_source.write_bytes(payload)
        local_download = self.tmpdir / "download.bin"

        transport, sftp = self.connect("writer", password="write-secret")
        try:
            sftp.put(str(local_source), "/sample.bin")
            self.assertIn("sample.bin", sftp.listdir("/"))
            self.assertEqual(sftp.stat("/sample.bin").st_size, len(payload))
            sftp.get("/sample.bin", str(local_download))
            self.assertEqual(local_download.read_bytes(), payload)
            sftp.remove("/sample.bin")
            self.assertNotIn("sample.bin", sftp.listdir("/"))
        finally:
            self.close_client(transport, sftp)

    def test_audit_log_records_upload_download_and_delete(self) -> None:
        start_count = len(self.read_audit_events())
        local_source = self.tmpdir / "audit-source.bin"
        local_download = self.tmpdir / "audit-download.bin"
        payload = b"audit-payload" * 128
        local_source.write_bytes(payload)

        transport, sftp = self.connect("writer", password="write-secret")
        try:
            sftp.put(str(local_source), "/audit.bin")
            sftp.get("/audit.bin", str(local_download))
            sftp.remove("/audit.bin")
        finally:
            self.close_client(transport, sftp)

        time.sleep(0.1)
        new_events = self.read_audit_events()[start_count:]
        actions = [event["action"] for event in new_events]
        self.assertIn("upload", actions)
        self.assertIn("download", actions)
        self.assertIn("delete", actions)
        self.assertTrue(all(event["username"] == "writer" for event in new_events))

    def test_writer_user_can_mkdir_rmdir_rename_and_posix_rename(self) -> None:
        transport, sftp = self.connect("writer", password="write-secret")
        try:
            sftp.mkdir("/nested")
            with sftp.file("/nested/a.txt", "w") as remote_file:
                remote_file.write("alpha")
            sftp.rename("/nested/a.txt", "/nested/b.txt")
            self.assertIn("b.txt", sftp.listdir("/nested"))
            sftp.posix_rename("/nested/b.txt", "/final.txt")
            self.assertIn("final.txt", sftp.listdir("/"))
            sftp.remove("/final.txt")
            sftp.rmdir("/nested")
        finally:
            self.close_client(transport, sftp)

    def test_writer_user_can_symlink_and_readlink(self) -> None:
        transport, sftp = self.connect("writer", password="write-secret")
        try:
            with sftp.file("/target.txt", "w") as remote_file:
                remote_file.write("target")
            sftp.symlink("/target.txt", "/link.txt")
            self.assertEqual(sftp.readlink("/link.txt"), "/target.txt")
            with sftp.file("/link.txt", "r") as remote_file:
                self.assertEqual(remote_file.read(), b"target")
            sftp.remove("/link.txt")
            sftp.remove("/target.txt")
        finally:
            self.close_client(transport, sftp)

    def test_symlink_operations_can_be_disabled_by_policy(self) -> None:
        temp_root = self.tmpdir / "symlink-disabled-root"
        temp_root.mkdir(exist_ok=True)
        config_data = {
            "server": {
                "host": "127.0.0.1",
                "port": 0,
                "host_key": "./host_rsa_disabled.key",
                "allow_symlinks": False,
            },
            "users": [
                {
                    "username": "writer",
                    "password": "write-secret",
                    "permissions": "read_write",
                    "root": str(temp_root),
                }
            ],
        }
        config_path = self.tmpdir / "symlink_disabled_config.json"
        config_path.write_text(json.dumps(config_data), encoding="utf-8")
        config = build_app_config(config_path)
        server = ThreadedSFTPServer(config, paramiko.RSAKey.generate(2048))
        server.start()
        host, port = server.address
        time.sleep(0.1)
        transport = paramiko.Transport((host, port))
        transport.connect(username="writer", password="write-secret")
        sftp = paramiko.SFTPClient.from_transport(transport)
        try:
            with sftp.file("/target.txt", "w") as remote_file:
                remote_file.write("target")
            with self.assertRaises(IOError):
                sftp.symlink("/target.txt", "/link.txt")
        finally:
            sftp.close()
            transport.close()
            server.shutdown()

    def test_writer_user_can_chmod_chown_and_truncate(self) -> None:
        transport, sftp = self.connect("writer", password="write-secret")
        try:
            with sftp.file("/attrs.txt", "w") as remote_file:
                remote_file.write("1234567890")
            sftp.chmod("/attrs.txt", 0o640)
            stats = sftp.stat("/attrs.txt")
            self.assertEqual(stat.S_IMODE(stats.st_mode), 0o640)
            sftp.chown("/attrs.txt", os.getuid(), os.getgid())
            sftp.truncate("/attrs.txt", 4)
            self.assertEqual(sftp.stat("/attrs.txt").st_size, 4)
        finally:
            self.close_client(transport, sftp)

    def test_resume_upload_after_interruption(self) -> None:
        payload = b"resume-upload-" * 4096
        local_source = self.tmpdir / "resume-upload.bin"
        local_source.write_bytes(payload)
        split = len(payload) // 2

        transport, sftp = self.connect("writer", password="write-secret")
        try:
            with sftp.file("/resume-upload.bin", "w") as remote_file:
                remote_file.write(payload[:split])
        finally:
            self.close_client(transport, sftp)

        transport, sftp = self.connect("writer", password="write-secret")
        try:
            remote_size = sftp.stat("/resume-upload.bin").st_size
            self.assertEqual(remote_size, split)
            with open(local_source, "rb") as local_file:
                local_file.seek(remote_size)
                with sftp.file("/resume-upload.bin", "a") as remote_file:
                    while True:
                        chunk = local_file.read(65536)
                        if not chunk:
                            break
                        remote_file.write(chunk)
            with sftp.file("/resume-upload.bin", "rb") as remote_file:
                self.assertEqual(remote_file.read(), payload)
        finally:
            self.close_client(transport, sftp)

    def test_resume_download_after_interruption(self) -> None:
        payload = b"resume-download-" * 4096
        transport, sftp = self.connect("writer", password="write-secret")
        try:
            with sftp.file("/resume-download.bin", "w") as remote_file:
                remote_file.write(payload)
        finally:
            self.close_client(transport, sftp)

        partial_download = self.tmpdir / "resume-download.bin"
        split = len(payload) // 3
        partial_download.write_bytes(payload[:split])

        transport, sftp = self.connect("writer", password="write-secret")
        try:
            with sftp.file("/resume-download.bin", "rb") as remote_file:
                remote_file.seek(split)
                with open(partial_download, "ab") as local_file:
                    while True:
                        chunk = remote_file.read(65536)
                        if not chunk:
                            break
                        local_file.write(chunk)
        finally:
            self.close_client(transport, sftp)

        self.assertEqual(partial_download.read_bytes(), payload)

    def test_random_access_write_on_existing_file(self) -> None:
        transport, sftp = self.connect("writer", password="write-secret")
        try:
            with sftp.file("/random.bin", "w") as remote_file:
                remote_file.write(b"abcdef")
            with sftp.file("/random.bin", "r+") as remote_file:
                remote_file.seek(2)
                remote_file.write(b"XYZ")
            with sftp.file("/random.bin", "rb") as remote_file:
                self.assertEqual(remote_file.read(), b"abXYZf")
        finally:
            self.close_client(transport, sftp)

    def test_idle_session_timeout_disconnects_inactive_client(self) -> None:
        temp_root = self.tmpdir / "idle-root"
        temp_root.mkdir(exist_ok=True)
        config_data = {
            "server": {
                "host": "127.0.0.1",
                "port": 0,
                "host_key": "./host_rsa_idle.key",
                "idle_session_timeout": 1,
            },
            "users": [
                {
                    "username": "idleuser",
                    "password": "idle-secret",
                    "permissions": "read_write",
                    "root": str(temp_root),
                }
            ],
        }
        config_path = self.tmpdir / "idle_config.json"
        config_path.write_text(json.dumps(config_data), encoding="utf-8")
        config = build_app_config(config_path)
        server = ThreadedSFTPServer(config, paramiko.RSAKey.generate(2048))
        server.start()
        host, port = server.address
        time.sleep(0.1)
        transport = paramiko.Transport((host, port))
        transport.connect(username="idleuser", password="idle-secret")
        sftp = paramiko.SFTPClient.from_transport(transport)
        try:
            self.assertEqual(sftp.normalize("."), "/")
            time.sleep(2.2)
            with self.assertRaises((OSError, EOFError, paramiko.SSHException)):
                sftp.listdir("/")
        finally:
            with contextlib.suppress(Exception):
                sftp.close()
            transport.close()
            server.shutdown()

    def test_connection_limits_are_enforced(self) -> None:
        temp_root = self.tmpdir / "limit-root"
        temp_root.mkdir(exist_ok=True)
        config_data = {
            "server": {
                "host": "127.0.0.1",
                "port": 0,
                "host_key": "./host_rsa_limit.key",
                "max_connections_total": 2,
                "max_connections_per_user": 1,
            },
            "users": [
                {
                    "username": "writer",
                    "password": "write-secret",
                    "permissions": "read_write",
                    "root": str(temp_root / "writer"),
                },
                {
                    "username": "other",
                    "password": "other-secret",
                    "permissions": "read_write",
                    "root": str(temp_root / "other"),
                },
            ],
        }
        config_path = self.tmpdir / "limit_config.json"
        config_path.write_text(json.dumps(config_data), encoding="utf-8")
        config = build_app_config(config_path)
        server = ThreadedSFTPServer(config, paramiko.RSAKey.generate(2048))
        server.start()
        host, port = server.address
        time.sleep(0.1)

        first_transport = paramiko.Transport((host, port))
        first_transport.connect(username="writer", password="write-secret")
        first_sftp = paramiko.SFTPClient.from_transport(first_transport)

        try:
            second_transport = paramiko.Transport((host, port))
            try:
                with self.assertRaises((paramiko.AuthenticationException, paramiko.SSHException)):
                    second_transport.connect(username="writer", password="write-secret")
            finally:
                second_transport.close()
            time.sleep(0.1)

            other_transport = paramiko.Transport((host, port))
            other_transport.connect(username="other", password="other-secret")
            other_sftp = paramiko.SFTPClient.from_transport(other_transport)
            try:
                self.assertEqual(other_sftp.normalize("."), "/")
            finally:
                other_sftp.close()
                other_transport.close()
        finally:
            first_sftp.close()
            first_transport.close()
            server.shutdown()


if __name__ == "__main__":
    unittest.main(verbosity=2)
