from __future__ import annotations

import base64
import os
import stat
import tempfile
import time
import unittest
from pathlib import Path

import paramiko

from sftp_server import AuthConfig, Jail, ThreadedSFTPServer


def write_public_key(path: Path, key: paramiko.PKey) -> None:
    public_line = f"{key.get_name()} {base64.b64encode(key.asbytes()).decode('ascii')}\n"
    path.write_text(public_line, encoding="utf-8")


class SFTPServerIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls._tmp = tempfile.TemporaryDirectory()
        cls.tmpdir = Path(cls._tmp.name)
        cls.root = cls.tmpdir / "root"
        cls.root.mkdir()

        cls.host_key = paramiko.RSAKey.generate(2048)
        cls.user_key = paramiko.RSAKey.generate(2048)
        cls.bad_key = paramiko.RSAKey.generate(2048)

        cls.authorized_key_path = cls.tmpdir / "id_rsa.pub"
        write_public_key(cls.authorized_key_path, cls.user_key)

        auth = AuthConfig(
            username="demo",
            password="secret123",
            auth_mode="both",
            authorized_keys=[cls.user_key],
        )
        cls.server = ThreadedSFTPServer(
            "127.0.0.1",
            0,
            cls.host_key,
            auth,
            Jail(cls.root),
        )
        cls.server.start()
        cls.host, cls.port = cls.server.address
        time.sleep(0.1)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls._tmp.cleanup()

    def connect_password(self) -> tuple[paramiko.Transport, paramiko.SFTPClient]:
        transport = paramiko.Transport((self.host, self.port))
        transport.connect(username="demo", password="secret123")
        return transport, paramiko.SFTPClient.from_transport(transport)

    def connect_key(self) -> tuple[paramiko.Transport, paramiko.SFTPClient]:
        transport = paramiko.Transport((self.host, self.port))
        transport.connect(username="demo", pkey=self.user_key)
        return transport, paramiko.SFTPClient.from_transport(transport)

    def close_client(self, transport: paramiko.Transport, sftp: paramiko.SFTPClient) -> None:
        sftp.close()
        transport.close()

    def test_password_auth_success(self) -> None:
        transport, sftp = self.connect_password()
        try:
            self.assertEqual(sftp.normalize("."), "/")
        finally:
            self.close_client(transport, sftp)

    def test_public_key_auth_success(self) -> None:
        transport, sftp = self.connect_key()
        try:
            self.assertEqual(sftp.normalize("."), "/")
        finally:
            self.close_client(transport, sftp)

    def test_auth_failure_for_wrong_password(self) -> None:
        transport = paramiko.Transport((self.host, self.port))
        try:
            with self.assertRaises(paramiko.AuthenticationException):
                transport.connect(username="demo", password="wrong")
        finally:
            transport.close()

    def test_auth_failure_for_wrong_key(self) -> None:
        transport = paramiko.Transport((self.host, self.port))
        try:
            with self.assertRaises(paramiko.AuthenticationException):
                transport.connect(username="demo", pkey=self.bad_key)
        finally:
            transport.close()

    def test_upload_download_list_stat_remove(self) -> None:
        local_source = self.tmpdir / "sample.bin"
        payload = b"hello-sftp" * 100
        local_source.write_bytes(payload)
        local_download = self.tmpdir / "download.bin"

        transport, sftp = self.connect_password()
        try:
            sftp.put(str(local_source), "/sample.bin")
            names = sftp.listdir("/")
            self.assertIn("sample.bin", names)
            attrs = sftp.stat("/sample.bin")
            self.assertEqual(attrs.st_size, len(payload))
            sftp.get("/sample.bin", str(local_download))
            self.assertEqual(local_download.read_bytes(), payload)
            sftp.remove("/sample.bin")
            self.assertNotIn("sample.bin", sftp.listdir("/"))
        finally:
            self.close_client(transport, sftp)

    def test_mkdir_rmdir_rename_and_posix_rename(self) -> None:
        transport, sftp = self.connect_password()
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

    def test_symlink_and_readlink(self) -> None:
        transport, sftp = self.connect_password()
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

    def test_chmod_chown_and_truncate(self) -> None:
        transport, sftp = self.connect_password()
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

    def test_path_escape_is_denied(self) -> None:
        transport, sftp = self.connect_password()
        try:
            with self.assertRaises(IOError):
                sftp.stat("/../../etc/passwd")
        finally:
            self.close_client(transport, sftp)

    def test_resume_upload_after_interruption(self) -> None:
        payload = b"resume-upload-" * 4096
        local_source = self.tmpdir / "resume-upload.bin"
        local_source.write_bytes(payload)
        split = len(payload) // 2

        transport, sftp = self.connect_password()
        try:
            with sftp.file("/resume-upload.bin", "w") as remote_file:
                remote_file.write(payload[:split])
        finally:
            self.close_client(transport, sftp)

        transport, sftp = self.connect_password()
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
        transport, sftp = self.connect_password()
        try:
            with sftp.file("/resume-download.bin", "w") as remote_file:
                remote_file.write(payload)
        finally:
            self.close_client(transport, sftp)

        partial_download = self.tmpdir / "resume-download.bin"
        split = len(payload) // 3
        partial_download.write_bytes(payload[:split])

        transport, sftp = self.connect_password()
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

    def test_open_existing_file_without_truncation_for_random_access(self) -> None:
        transport, sftp = self.connect_password()
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


if __name__ == "__main__":
    unittest.main(verbosity=2)
