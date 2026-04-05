#!/usr/bin/env python3
"""Standalone SFTP server with config-driven multi-user authentication."""

from __future__ import annotations

import argparse
import base64
import errno
import json
import logging
import os
import socket
import stat
import threading
import time
from contextlib import suppress
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

import paramiko
from paramiko import AUTH_FAILED, AUTH_SUCCESSFUL, OPEN_SUCCEEDED
from paramiko.sftp import SFTP_OK
from paramiko.sftp_attr import SFTPAttributes
from paramiko.sftp_handle import SFTPHandle
from paramiko.sftp_server import SFTPServer, SFTPServerInterface


LOGGER = logging.getLogger("sftpserver")


def setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )


def os_error_to_sftp(exc: OSError) -> int:
    return SFTPServer.convert_errno(exc.errno)


@dataclass(frozen=True)
class ServerSettings:
    host: str
    port: int
    host_key_path: Path
    max_connections_total: int | None
    max_connections_per_user: int | None
    idle_session_timeout: int | None
    allow_symlinks: bool
    audit_log_path: Path | None


@dataclass(frozen=True)
class UserAccount:
    username: str
    root: Path
    permissions: str
    password: str | None
    authorized_keys: tuple[paramiko.PKey, ...]
    description: str | None = None

    @property
    def can_read(self) -> bool:
        return True

    @property
    def can_write(self) -> bool:
        return self.permissions == "read_write"

    @property
    def allows_password(self) -> bool:
        return self.password is not None

    @property
    def allows_public_key(self) -> bool:
        return bool(self.authorized_keys)


@dataclass(frozen=True)
class AppConfig:
    server: ServerSettings
    users: dict[str, UserAccount]


class AuditLogger:
    def __init__(self, path: Path | None):
        self.path = path
        self._lock = threading.Lock()
        if self.path is not None:
            self.path.parent.mkdir(parents=True, exist_ok=True)

    @property
    def enabled(self) -> bool:
        return self.path is not None

    def log(
        self,
        *,
        username: str,
        action: str,
        path: str,
        bytes_transferred: int | None = None,
        status: str = "success",
        details: str | None = None,
    ) -> None:
        if self.path is None:
            return

        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "username": username,
            "action": action,
            "path": path,
            "status": status,
        }
        if bytes_transferred is not None:
            event["bytes"] = bytes_transferred
        if details is not None:
            event["details"] = details

        with self._lock:
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(event, sort_keys=True) + "\n")


class ConnectionTracker:
    def __init__(
        self,
        max_total_connections: int | None,
        max_connections_per_user: int | None,
    ):
        self.max_total_connections = max_total_connections
        self.max_connections_per_user = max_connections_per_user
        self._lock = threading.Lock()
        self._active_sockets = 0
        self._active_users: dict[str, int] = {}

    def try_open_socket(self) -> bool:
        with self._lock:
            if (
                self.max_total_connections is not None
                and self._active_sockets >= self.max_total_connections
            ):
                return False
            self._active_sockets += 1
            return True

    def release_socket(self) -> None:
        with self._lock:
            if self._active_sockets > 0:
                self._active_sockets -= 1

    def try_claim_user(self, username: str) -> bool:
        with self._lock:
            current = self._active_users.get(username, 0)
            if (
                self.max_connections_per_user is not None
                and current >= self.max_connections_per_user
            ):
                return False
            self._active_users[username] = current + 1
            return True

    def release_user(self, username: str | None) -> None:
        if username is None:
            return
        with self._lock:
            current = self._active_users.get(username, 0)
            if current <= 1:
                self._active_users.pop(username, None)
            else:
                self._active_users[username] = current - 1


class SessionContext:
    def __init__(
        self,
        account: UserAccount,
        audit_logger: AuditLogger,
        allow_symlinks: bool,
    ):
        self.account = account
        self.audit_logger = audit_logger
        self.allow_symlinks = allow_symlinks
        self._lock = threading.Lock()
        self._last_activity = time.monotonic()

    def touch(self) -> None:
        with self._lock:
            self._last_activity = time.monotonic()

    def idle_seconds(self) -> float:
        with self._lock:
            return time.monotonic() - self._last_activity


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
    def __init__(
        self,
        flags: int,
        writable: bool,
        session: SessionContext,
        sftp_path: str,
    ):
        super().__init__(flags)
        self.writable = writable
        self.session = session
        self.sftp_path = sftp_path
        self.bytes_read = 0
        self.bytes_written = 0
        self._audit_emitted = False

    def stat(self) -> SFTPAttributes | int:
        self.session.touch()
        try:
            return SFTPAttributes.from_stat(os.fstat(self.readfile.fileno()))
        except OSError as exc:
            return os_error_to_sftp(exc)

    def chattr(self, attr: SFTPAttributes) -> int:
        self.session.touch()
        if not self.writable:
            return SFTPServer.convert_errno(errno.EACCES)
        try:
            SFTPServer.set_file_attr(self.filename, attr)
            return SFTP_OK
        except OSError as exc:
            return os_error_to_sftp(exc)

    def read(self, offset: int, length: int):
        self.session.touch()
        result = super().read(offset, length)
        if isinstance(result, bytes):
            self.bytes_read += len(result)
        return result

    def write(self, offset: int, data: bytes) -> int:
        self.session.touch()
        result = super().write(offset, data)
        if result == SFTP_OK:
            self.bytes_written += len(data)
        return result

    def close(self) -> int:
        result = super().close()
        if not self._audit_emitted:
            if self.bytes_read > 0:
                self.session.audit_logger.log(
                    username=self.session.account.username,
                    action="download",
                    path=self.sftp_path,
                    bytes_transferred=self.bytes_read,
                )
            if self.bytes_written > 0:
                self.session.audit_logger.log(
                    username=self.session.account.username,
                    action="upload",
                    path=self.sftp_path,
                    bytes_transferred=self.bytes_written,
                )
            self._audit_emitted = True
        return result


class LocalSFTPServer(SFTPServerInterface):
    def __init__(self, server, *args, **kwargs):
        super().__init__(server, *args, **kwargs)
        self.session: SessionContext = server.session
        self.account: UserAccount = self.session.account
        self.jail = Jail(self.account.root)

    def _local(self, path: str, follow_symlinks: bool = True) -> Path:
        return self.jail.to_local_path(path, follow_symlinks=follow_symlinks)

    def _deny_if_read_only(self) -> int | None:
        if not self.account.can_write:
            return SFTPServer.convert_errno(errno.EACCES)
        return None

    def list_folder(self, path: str):
        self.session.touch()
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
        self.session.touch()
        try:
            return SFTPAttributes.from_stat(os.stat(self._local(path)))
        except PermissionError:
            return SFTPServer.convert_errno(errno.EACCES)
        except OSError as exc:
            return os_error_to_sftp(exc)

    def lstat(self, path: str):
        self.session.touch()
        try:
            return SFTPAttributes.from_stat(
                os.lstat(self._local(path, follow_symlinks=False))
            )
        except PermissionError:
            return SFTPServer.convert_errno(errno.EACCES)
        except OSError as exc:
            return os_error_to_sftp(exc)

    def open(self, path: str, flags: int, attr: SFTPAttributes):
        self.session.touch()
        try:
            access_mode = flags & os.O_ACCMODE
            wants_write = (
                access_mode != os.O_RDONLY
                or bool(flags & os.O_CREAT)
                or bool(flags & os.O_TRUNC)
                or bool(flags & os.O_APPEND)
            )
            if wants_write and not self.account.can_write:
                return SFTPServer.convert_errno(errno.EACCES)

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

            if access_mode == os.O_WRONLY:
                binary_mode = "ab" if flags & os.O_APPEND else "wb"
            elif access_mode == os.O_RDWR:
                binary_mode = "a+b" if flags & os.O_APPEND else "r+b"
            else:
                binary_mode = "rb"

            handle = LocalSFTPHandle(
                flags,
                writable=self.account.can_write,
                session=self.session,
                sftp_path=path,
            )
            handle.filename = str(local)
            handle.readfile = os.fdopen(fd, binary_mode, buffering=0)
            handle.writefile = handle.readfile
            return handle
        except PermissionError:
            return SFTPServer.convert_errno(errno.EACCES)
        except OSError as exc:
            return os_error_to_sftp(exc)

    def remove(self, path: str) -> int:
        self.session.touch()
        denied = self._deny_if_read_only()
        if denied is not None:
            return denied
        try:
            os.remove(self._local(path, follow_symlinks=False))
            self.session.audit_logger.log(
                username=self.account.username,
                action="delete",
                path=path,
            )
            return SFTP_OK
        except PermissionError:
            return SFTPServer.convert_errno(errno.EACCES)
        except OSError as exc:
            return os_error_to_sftp(exc)

    def rename(self, oldpath: str, newpath: str) -> int:
        self.session.touch()
        denied = self._deny_if_read_only()
        if denied is not None:
            return denied
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
        self.session.touch()
        denied = self._deny_if_read_only()
        if denied is not None:
            return denied
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
        self.session.touch()
        denied = self._deny_if_read_only()
        if denied is not None:
            return denied
        try:
            mode = getattr(attr, "st_mode", 0o777)
            os.mkdir(self._local(path, follow_symlinks=False), mode)
            return SFTP_OK
        except PermissionError:
            return SFTPServer.convert_errno(errno.EACCES)
        except OSError as exc:
            return os_error_to_sftp(exc)

    def rmdir(self, path: str) -> int:
        self.session.touch()
        denied = self._deny_if_read_only()
        if denied is not None:
            return denied
        try:
            os.rmdir(self._local(path, follow_symlinks=False))
            self.session.audit_logger.log(
                username=self.account.username,
                action="delete_directory",
                path=path,
            )
            return SFTP_OK
        except PermissionError:
            return SFTPServer.convert_errno(errno.EACCES)
        except OSError as exc:
            return os_error_to_sftp(exc)

    def chattr(self, path: str, attr: SFTPAttributes) -> int:
        self.session.touch()
        denied = self._deny_if_read_only()
        if denied is not None:
            return denied
        try:
            SFTPServer.set_file_attr(str(self._local(path)), attr)
            return SFTP_OK
        except PermissionError:
            return SFTPServer.convert_errno(errno.EACCES)
        except OSError as exc:
            return os_error_to_sftp(exc)

    def canonicalize(self, path: str) -> str:
        self.session.touch()
        try:
            return self.jail.to_sftp_path(self._local(path))
        except PermissionError:
            return "/"

    def readlink(self, path: str):
        self.session.touch()
        if not self.session.allow_symlinks:
            return SFTPServer.convert_errno(errno.EACCES)
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
        self.session.touch()
        denied = self._deny_if_read_only()
        if denied is not None:
            return denied
        if not self.session.allow_symlinks:
            return SFTPServer.convert_errno(errno.EACCES)
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


def load_authorized_keys(paths: Iterable[Path]) -> tuple[paramiko.PKey, ...]:
    keys: list[paramiko.PKey] = []
    for path in paths:
        with path.open("r", encoding="utf-8") as handle:
            for line in handle:
                key = parse_authorized_key(line)
                if key is not None:
                    keys.append(key)
    return tuple(keys)


def resolve_path(path_value: str, base_dir: Path) -> Path:
    path = Path(os.path.expanduser(path_value))
    if not path.is_absolute():
        path = (base_dir / path).resolve()
    else:
        path = path.resolve()
    return path


def build_app_config(config_path: Path) -> AppConfig:
    base_dir = config_path.parent.resolve()
    data = json.loads(config_path.read_text(encoding="utf-8"))

    server_data = data.get("server", {})
    host = server_data.get("host", "0.0.0.0")
    port = int(server_data.get("port", 3373))
    host_key_value = server_data.get("host_key", "./host_rsa.key")
    host_key_path = resolve_path(host_key_value, base_dir)
    max_total_connections = server_data.get("max_connections_total")
    if max_total_connections is not None:
        max_total_connections = int(max_total_connections)
    max_connections_per_user = server_data.get("max_connections_per_user")
    if max_connections_per_user is not None:
        max_connections_per_user = int(max_connections_per_user)
    idle_session_timeout = server_data.get("idle_session_timeout")
    if idle_session_timeout is not None:
        idle_session_timeout = int(idle_session_timeout)
    allow_symlinks = bool(server_data.get("allow_symlinks", True))
    audit_log_value = server_data.get("audit_log")
    audit_log_path = (
        resolve_path(audit_log_value, base_dir) if audit_log_value is not None else None
    )

    users: dict[str, UserAccount] = {}
    for user_data in data.get("users", []):
        username = user_data["username"]
        if username in users:
            raise ValueError(f"duplicate username in config: {username}")

        root = resolve_path(user_data["root"], base_dir)
        permissions = user_data.get("permissions", "read_write")
        if permissions not in {"read_only", "read_write"}:
            raise ValueError(
                f"user '{username}' has unsupported permissions: {permissions}"
            )

        password = user_data.get("password")
        key_paths = [
            resolve_path(path_value, base_dir)
            for path_value in user_data.get("authorized_keys", [])
        ]
        authorized_keys = load_authorized_keys(key_paths)

        if password is None and not authorized_keys:
            raise ValueError(
                f"user '{username}' must define at least one authentication method"
            )

        users[username] = UserAccount(
            username=username,
            root=root,
            permissions=permissions,
            password=password,
            authorized_keys=authorized_keys,
            description=user_data.get("description"),
        )

    if not users:
        raise ValueError("config must define at least one user")

    return AppConfig(
        server=ServerSettings(
            host=host,
            port=port,
            host_key_path=host_key_path,
            max_connections_total=max_total_connections,
            max_connections_per_user=max_connections_per_user,
            idle_session_timeout=idle_session_timeout,
            allow_symlinks=allow_symlinks,
            audit_log_path=audit_log_path,
        ),
        users=users,
    )


class SFTPSSHServer(paramiko.ServerInterface):
    def __init__(
        self,
        accounts: dict[str, UserAccount],
        tracker: ConnectionTracker,
        audit_logger: AuditLogger,
        allow_symlinks: bool,
    ):
        self.accounts = accounts
        self.tracker = tracker
        self.audit_logger = audit_logger
        self.allow_symlinks = allow_symlinks
        self.account: UserAccount | None = None
        self.session: SessionContext | None = None
        self.claimed_username: str | None = None

    def get_allowed_auths(self, username: str) -> str:
        account = self.accounts.get(username)
        if account is None:
            return "none"
        methods = []
        if account.allows_password:
            methods.append("password")
        if account.allows_public_key:
            methods.append("publickey")
        return ",".join(methods) or "none"

    def check_auth_password(self, username: str, password: str) -> int:
        account = self.accounts.get(username)
        if account is None or not account.allows_password:
            return AUTH_FAILED
        if password == account.password:
            if not self.tracker.try_claim_user(username):
                return AUTH_FAILED
            self.claimed_username = username
            self.account = account
            self.session = SessionContext(
                account=account,
                audit_logger=self.audit_logger,
                allow_symlinks=self.allow_symlinks,
            )
            return AUTH_SUCCESSFUL
        return AUTH_FAILED

    def check_auth_publickey(self, username: str, key: paramiko.PKey) -> int:
        account = self.accounts.get(username)
        if account is None or not account.allows_public_key:
            return AUTH_FAILED
        for allowed in account.authorized_keys:
            if allowed.get_name() == key.get_name() and allowed.asbytes() == key.asbytes():
                if not self.tracker.try_claim_user(username):
                    return AUTH_FAILED
                self.claimed_username = username
                self.account = account
                self.session = SessionContext(
                    account=account,
                    audit_logger=self.audit_logger,
                    allow_symlinks=self.allow_symlinks,
                )
                return AUTH_SUCCESSFUL
        return AUTH_FAILED

    def check_channel_request(self, kind: str, chanid: int) -> int:
        if kind == "session" and self.account is not None:
            assert self.session is not None
            self.session.touch()
            return OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_subsystem_request(self, channel, name: str) -> bool:
        if self.session is not None:
            self.session.touch()
        return super().check_channel_subsystem_request(channel, name)


class ThreadedSFTPServer:
    """Reusable SFTP server wrapper for CLI use and tests."""

    def __init__(self, config: AppConfig, host_key: paramiko.PKey):
        self.config = config
        self.host_key = host_key
        self.audit_logger = AuditLogger(config.server.audit_log_path)
        self.tracker = ConnectionTracker(
            config.server.max_connections_total,
            config.server.max_connections_per_user,
        )
        self._sock: socket.socket | None = None
        self._accept_thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._client_threads: set[threading.Thread] = set()
        self._lock = threading.Lock()

    @property
    def address(self) -> tuple[str, int]:
        if self._sock is None:
            return (self.config.server.host, self.config.server.port)
        return self._sock.getsockname()

    def start(self) -> None:
        if self._sock is not None:
            raise RuntimeError("server already started")

        for account in self.config.users.values():
            account.root.mkdir(parents=True, exist_ok=True)

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.config.server.host, self.config.server.port))
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
            "serving SFTP on %s:%s with %d configured users",
            bound_host,
            bound_port,
            len(self.config.users),
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
            if not self.tracker.try_open_socket():
                LOGGER.warning("rejecting client %s because max total connections was reached", addr)
                client.close()
                continue
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
            serve_client(
                client,
                self.host_key,
                self.config,
                self.tracker,
                self.audit_logger,
            )
        finally:
            self.tracker.release_socket()
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


def serve_client(
    client: socket.socket,
    host_key: paramiko.PKey,
    config: AppConfig,
    tracker: ConnectionTracker,
    audit_logger: AuditLogger,
) -> None:
    peer = client.getpeername()
    transport = paramiko.Transport(client)
    transport.add_server_key(host_key)
    server: SFTPSSHServer | None = None

    try:
        server = SFTPSSHServer(
            config.users,
            tracker,
            audit_logger,
            config.server.allow_symlinks,
        )
        transport.set_subsystem_handler("sftp", SFTPServer, LocalSFTPServer)
        transport.start_server(server=server)
        channel = transport.accept(timeout=10)
        if channel is None:
            LOGGER.warning("client %s did not open a channel", peer)
            return
        while transport.is_active():
            if (
                config.server.idle_session_timeout is not None
                and server.session is not None
                and server.session.idle_seconds() > config.server.idle_session_timeout
            ):
                LOGGER.info(
                    "disconnecting idle client %s for user '%s'",
                    peer,
                    server.account.username if server.account is not None else "unknown",
                )
                transport.close()
                break
            time.sleep(1)
    except Exception as exc:
        LOGGER.exception("client %s failed: %s", peer, exc)
    finally:
        if server is not None:
            tracker.release_user(server.claimed_username)
        transport.close()
        client.close()
        LOGGER.info("client disconnected: %s", peer)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run a Python SFTP server")
    parser.add_argument(
        "--config",
        default="./server_config.json",
        help="path to the server JSON config file",
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

    config_path = Path(args.config).expanduser().resolve()
    config = build_app_config(config_path)
    host_key = ensure_host_key(config.server.host_key_path)
    server = ThreadedSFTPServer(config, host_key)
    server.serve_forever()


if __name__ == "__main__":
    main()
