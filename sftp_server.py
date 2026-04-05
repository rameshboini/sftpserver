#!/usr/bin/env python3
"""Simple standalone SFTP server with password and public key auth."""

from __future__ import annotations

import argparse
import base64
import errno
import logging
import os
import socket
import stat
import threading
import time
from contextlib import suppress
from pathlib import Path
from typing import Iterable

import paramiko
from paramiko import AUTH_FAILED, AUTH_SUCCESSFUL, OPEN_SUCCEEDED
from paramiko.sftp_attr import SFTPAttributes
from paramiko.sftp_handle import SFTPHandle
from paramiko.sftp_server import SFTPServer, SFTPServerInterface
from paramiko.sftp import SFTP_OK


LOGGER = logging.getLogger("sftpserver")


def setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )


def os_error_to_sftp(exc: OSError) -> int:
    return SFTPServer.convert_errno(exc.errno)


class Jail:
    """Maps SFTP paths to local filesystem paths inside a fixed root."""

    def __init__(self, root: Path):
        self.root = root.resolve()

    def to_local_path(self, requested_path: str, follow_symlinks: bool = True) -> Path:
        relative = (requested_path or ".").lstrip("/")
        candidate = self.root / relative
        if follow_symlinks:
            candidate = candidate.resolve()
        else:
            candidate = candidate.parent.resolve() / candidate.name
        try:
            candidate.relative_to(self.root)
        except ValueError as exc:
            raise PermissionError(f"path escapes root: {requested_path}") from exc
        return candidate

    def to_sftp_path(self, local_path: Path) -> str:
        relative = local_path.resolve().relative_to(self.root)
        return "/" if str(relative) == "." else f"/{relative.as_posix()}"


class LocalSFTPHandle(SFTPHandle):
    def stat(self) -> SFTPAttributes | int:
        try:
            return SFTPAttributes.from_stat(os.fstat(self.readfile.fileno()))
        except OSError as exc:
            return os_error_to_sftp(exc)

    def chattr(self, attr: SFTPAttributes) -> int:
        try:
            SFTPServer.set_file_attr(self.filename, attr)
            return SFTP_OK
        except OSError as exc:
            return os_error_to_sftp(exc)


class LocalSFTPServer(SFTPServerInterface):
    def __init__(self, server, *args, **kwargs):
        super().__init__(server, *args, **kwargs)
        self.jail: Jail = server.jail

    def _local(self, path: str, follow_symlinks: bool = True) -> Path:
        return self.jail.to_local_path(path, follow_symlinks=follow_symlinks)

    def list_folder(self, path: str):
        try:
            local = self._local(path)
            attrs = []
            for entry in os.scandir(local):
                attr = SFTPAttributes.from_stat(entry.stat(follow_symlinks=False))
                attr.filename = entry.name
                attrs.append(attr)
            return attrs
        except PermissionError:
            return SFTPServer.convert_errno(errno.EACCES)
        except OSError as exc:
            return os_error_to_sftp(exc)

    def stat(self, path: str):
        try:
            return SFTPAttributes.from_stat(os.stat(self._local(path)))
        except PermissionError:
            return SFTPServer.convert_errno(errno.EACCES)
        except OSError as exc:
            return os_error_to_sftp(exc)

    def lstat(self, path: str):
        try:
            return SFTPAttributes.from_stat(
                os.lstat(self._local(path, follow_symlinks=False))
            )
        except PermissionError:
            return SFTPServer.convert_errno(errno.EACCES)
        except OSError as exc:
            return os_error_to_sftp(exc)

    def open(self, path: str, flags: int, attr: SFTPAttributes):
        try:
            local = self._local(path)
            if attr is not None:
                attr._flags &= ~attr.FLAG_PERMISSIONS

            mode = getattr(attr, "st_mode", None)
            if flags & os.O_CREAT:
                if mode is None:
                    mode = 0o666
                fd = os.open(local, flags, mode)
            else:
                fd = os.open(local, flags)

            access_mode = flags & os.O_ACCMODE
            if access_mode == os.O_WRONLY:
                binary_mode = "ab" if flags & os.O_APPEND else "wb"
            elif access_mode == os.O_RDWR:
                binary_mode = "a+b" if flags & os.O_APPEND else "r+b"
            else:
                # Read-only handles must not request write access.
                binary_mode = "rb"

            handle = LocalSFTPHandle(flags)
            handle.filename = str(local)
            handle.readfile = os.fdopen(fd, binary_mode, buffering=0)
            handle.writefile = handle.readfile
            return handle
        except PermissionError:
            return SFTPServer.convert_errno(errno.EACCES)
        except OSError as exc:
            return os_error_to_sftp(exc)

    def remove(self, path: str) -> int:
        try:
            os.remove(self._local(path, follow_symlinks=False))
            return SFTP_OK
        except PermissionError:
            return SFTPServer.convert_errno(errno.EACCES)
        except OSError as exc:
            return os_error_to_sftp(exc)

    def rename(self, oldpath: str, newpath: str) -> int:
        try:
            os.rename(
                self._local(oldpath, follow_symlinks=False),
                self._local(newpath, follow_symlinks=False),
            )
            return SFTP_OK
        except PermissionError:
            return SFTPServer.convert_errno(errno.EACCES)
        except OSError as exc:
            return os_error_to_sftp(exc)

    def posix_rename(self, oldpath: str, newpath: str) -> int:
        try:
            os.replace(
                self._local(oldpath, follow_symlinks=False),
                self._local(newpath, follow_symlinks=False),
            )
            return SFTP_OK
        except PermissionError:
            return SFTPServer.convert_errno(errno.EACCES)
        except OSError as exc:
            return os_error_to_sftp(exc)

    def mkdir(self, path: str, attr: SFTPAttributes) -> int:
        try:
            mode = getattr(attr, "st_mode", 0o777)
            os.mkdir(self._local(path, follow_symlinks=False), mode)
            return SFTP_OK
        except PermissionError:
            return SFTPServer.convert_errno(errno.EACCES)
        except OSError as exc:
            return os_error_to_sftp(exc)

    def rmdir(self, path: str) -> int:
        try:
            os.rmdir(self._local(path, follow_symlinks=False))
            return SFTP_OK
        except PermissionError:
            return SFTPServer.convert_errno(errno.EACCES)
        except OSError as exc:
            return os_error_to_sftp(exc)

    def chattr(self, path: str, attr: SFTPAttributes) -> int:
        try:
            SFTPServer.set_file_attr(str(self._local(path)), attr)
            return SFTP_OK
        except PermissionError:
            return SFTPServer.convert_errno(errno.EACCES)
        except OSError as exc:
            return os_error_to_sftp(exc)

    def canonicalize(self, path: str) -> str:
        try:
            return self.jail.to_sftp_path(self._local(path))
        except PermissionError:
            return "/"

    def readlink(self, path: str):
        try:
            local_path = self._local(path, follow_symlinks=False)
            target = os.readlink(local_path)
            target_path = Path(target)
            if not target_path.is_absolute():
                target_path = (local_path.parent / target_path).resolve()
            return self.jail.to_sftp_path(target_path)
        except PermissionError:
            return SFTPServer.convert_errno(errno.EACCES)
        except ValueError:
            return SFTPServer.convert_errno(errno.EACCES)
        except OSError as exc:
            return os_error_to_sftp(exc)

    def symlink(self, target_path: str, path: str) -> int:
        try:
            local_target = self._local(target_path)
            local_link = self._local(path, follow_symlinks=False)
            os.symlink(local_target, local_link)
            return SFTP_OK
        except PermissionError:
            return SFTPServer.convert_errno(errno.EACCES)
        except OSError as exc:
            return os_error_to_sftp(exc)


def parse_authorized_key(line: str) -> paramiko.PKey | None:
    line = line.strip()
    if not line or line.startswith("#"):
        return None

    parts = line.split()
    if len(parts) < 2:
        return None

    key_type = parts[0]
    key_data = parts[1]
    try:
        decoded = base64.b64decode(key_data.encode("ascii"))
        return paramiko.PKey.from_type_string(key_type, decoded)
    except Exception:
        return None


def load_authorized_keys(paths: Iterable[str]) -> list[paramiko.PKey]:
    keys: list[paramiko.PKey] = []
    for path in paths:
        with open(os.path.expanduser(path), "r", encoding="utf-8") as handle:
            for line in handle:
                key = parse_authorized_key(line)
                if key is not None:
                    keys.append(key)
    return keys


class AuthConfig:
    def __init__(
        self,
        username: str,
        password: str | None,
        auth_mode: str,
        authorized_keys: list[paramiko.PKey],
    ):
        self.username = username
        self.password = password
        self.auth_mode = auth_mode
        self.authorized_keys = authorized_keys

    @property
    def allow_password(self) -> bool:
        return self.auth_mode in {"password", "both"}

    @property
    def allow_key(self) -> bool:
        return self.auth_mode in {"key", "both"}


class SFTPSSHServer(paramiko.ServerInterface):
    def __init__(self, auth: AuthConfig, jail: Jail):
        self.auth = auth
        self.jail = jail

    def get_allowed_auths(self, username: str) -> str:
        methods = []
        if self.auth.allow_password and self.auth.password is not None:
            methods.append("password")
        if self.auth.allow_key and self.auth.authorized_keys:
            methods.append("publickey")
        return ",".join(methods) or "none"

    def check_auth_password(self, username: str, password: str) -> int:
        if not self.auth.allow_password or self.auth.password is None:
            return AUTH_FAILED
        if username == self.auth.username and password == self.auth.password:
            return AUTH_SUCCESSFUL
        return AUTH_FAILED

    def check_auth_publickey(self, username: str, key: paramiko.PKey) -> int:
        if not self.auth.allow_key:
            return AUTH_FAILED
        if username != self.auth.username:
            return AUTH_FAILED
        for allowed in self.auth.authorized_keys:
            if (
                allowed.get_name() == key.get_name()
                and allowed.asbytes() == key.asbytes()
            ):
                return AUTH_SUCCESSFUL
        return AUTH_FAILED

    def check_channel_request(self, kind: str, chanid: int) -> int:
        if kind == "session":
            return OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_subsystem_request(self, channel, name: str) -> bool:
        return super().check_channel_subsystem_request(channel, name)


class ThreadedSFTPServer:
    """Reusable SFTP server wrapper for CLI use and tests."""

    def __init__(
        self,
        host: str,
        port: int,
        host_key: paramiko.PKey,
        auth: AuthConfig,
        jail: Jail,
    ):
        self.host = host
        self.port = port
        self.host_key = host_key
        self.auth = auth
        self.jail = jail
        self._sock: socket.socket | None = None
        self._accept_thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._client_threads: set[threading.Thread] = set()
        self._lock = threading.Lock()

    @property
    def address(self) -> tuple[str, int]:
        if self._sock is None:
            return (self.host, self.port)
        return self._sock.getsockname()

    def start(self) -> None:
        if self._sock is not None:
            raise RuntimeError("server already started")

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.host, self.port))
        sock.listen(100)
        sock.settimeout(0.5)

        self._sock = sock
        self._accept_thread = threading.Thread(
            target=self._accept_loop,
            name="sftp-accept-loop",
            daemon=True,
        )
        self._accept_thread.start()
        bound_host, bound_port = self.address
        LOGGER.info(
            "serving SFTP on %s:%s for user '%s' with auth mode '%s' and root '%s'",
            bound_host,
            bound_port,
            self.auth.username,
            self.auth.auth_mode,
            self.jail.root,
        )

    def serve_forever(self) -> None:
        self.start()
        try:
            while not self._stop_event.is_set():
                time.sleep(0.25)
        except KeyboardInterrupt:
            LOGGER.info("received interrupt, shutting down")
        finally:
            self.shutdown()

    def shutdown(self) -> None:
        self._stop_event.set()
        if self._sock is not None:
            with suppress(OSError):
                self._sock.close()
            self._sock = None

        if self._accept_thread is not None:
            self._accept_thread.join(timeout=2)
            self._accept_thread = None

        with self._lock:
            client_threads = list(self._client_threads)
        for thread in client_threads:
            thread.join(timeout=2)

    def _accept_loop(self) -> None:
        assert self._sock is not None
        while not self._stop_event.is_set():
            try:
                client, addr = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                if self._stop_event.is_set():
                    break
                raise

            LOGGER.info("client connected: %s", addr)
            thread = threading.Thread(
                target=self._serve_client_wrapper,
                args=(client,),
                daemon=True,
            )
            with self._lock:
                self._client_threads.add(thread)
            thread.start()

    def _serve_client_wrapper(self, client: socket.socket) -> None:
        try:
            serve_client(client, self.host_key, self.auth, self.jail)
        finally:
            current = threading.current_thread()
            with self._lock:
                self._client_threads.discard(current)


def ensure_host_key(path: Path) -> paramiko.PKey:
    if path.exists():
        return paramiko.RSAKey.from_private_key_file(str(path))
    path.parent.mkdir(parents=True, exist_ok=True)
    key = paramiko.RSAKey.generate(3072)
    key.write_private_key_file(str(path))
    os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    LOGGER.info("created host key at %s", path)
    return key


def validate_args(args: argparse.Namespace) -> None:
    if args.auth_mode in {"password", "both"} and not args.password:
        raise SystemExit("--password is required when auth mode includes password")
    if args.auth_mode in {"key", "both"} and not args.authorized_key:
        if args.auth_mode == "key":
            raise SystemExit("--authorized-key is required for key auth")
        LOGGER.warning(
            "auth mode is 'both' but no authorized keys were provided; "
            "public key auth will be unavailable"
        )


def serve_client(
    client: socket.socket,
    host_key: paramiko.PKey,
    auth: AuthConfig,
    jail: Jail,
) -> None:
    peer = client.getpeername()
    transport = paramiko.Transport(client)
    transport.add_server_key(host_key)
    transport.set_subsystem_handler("sftp", SFTPServer, LocalSFTPServer)

    try:
        server = SFTPSSHServer(auth, jail)
        transport.start_server(server=server)
        channel = transport.accept(timeout=10)
        if channel is None:
            LOGGER.warning("client %s did not open a channel", peer)
            return
        while transport.is_active():
            time.sleep(1)
    except Exception as exc:
        LOGGER.exception("client %s failed: %s", peer, exc)
    finally:
        transport.close()
        client.close()
        LOGGER.info("client disconnected: %s", peer)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run a Python SFTP server")
    parser.add_argument("--host", default="0.0.0.0", help="bind address")
    parser.add_argument("--port", type=int, default=3373, help="bind port")
    parser.add_argument("--root", required=True, help="root directory to serve")
    parser.add_argument("--username", required=True, help="allowed username")
    parser.add_argument("--password", help="password for password auth")
    parser.add_argument(
        "--authorized-key",
        action="append",
        default=[],
        help="path to an authorized_keys file or a .pub key file; repeatable",
    )
    parser.add_argument(
        "--auth-mode",
        choices=["password", "key", "both"],
        default="both",
        help="authentication mode",
    )
    parser.add_argument(
        "--host-key",
        default="./host_rsa.key",
        help="path to the SSH host private key file",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="enable debug logging",
    )
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    setup_logging(args.verbose)
    validate_args(args)

    root = Path(args.root).expanduser().resolve()
    root.mkdir(parents=True, exist_ok=True)
    jail = Jail(root)

    host_key_path = Path(args.host_key).expanduser().resolve()
    host_key = ensure_host_key(host_key_path)
    authorized_keys = load_authorized_keys(args.authorized_key)
    auth = AuthConfig(args.username, args.password, args.auth_mode, authorized_keys)
    server = ThreadedSFTPServer(args.host, args.port, host_key, auth, jail)
    server.serve_forever()


if __name__ == "__main__":
    main()
