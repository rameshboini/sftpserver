"""Robot Framework library for SFTP server testing."""

from __future__ import annotations

import os
import tempfile
import time
from pathlib import Path

import paramiko
from robot.api.deco import keyword, library
from robot.api.exceptions import Failure, NotFoundError

from sftpserver.sftp_server import (
    AuthConfig,
    Jail,
    OperationTracker,
    ThreadedSFTPServer,
    ensure_host_key,
    load_authorized_keys,
)


@library
class SftpServerLibrary:
    """Robot Framework library for SFTP server lifecycle and operation verification."""

    ROBOT_LIBRARY_VERSION = "1.0.0"
    ROBOT_LIBRARY_DOC_FORMAT = "markdown"

    def __init__(self):
        self._server: ThreadedSFTPServer | None = None
        self._transport: paramiko.Transport | None = None
        self._sftp: paramiko.SFTPClient | None = None
        self._tracker: OperationTracker | None = None
        self._host_key: paramiko.PKey | None = None
        self._host = "127.0.0.1"
        self._port = 0  # Will be assigned dynamically
        self._root: Path | None = None

    # ==================== Server Lifecycle Keywords ====================

    @keyword
    def start_sftp_server(
        self,
        root: str,
        username: str,
        password: str | None = None,
        port: int = 3373,
        auth_mode: str = "both",
        authorized_key: str | None = None,
    ) -> None:
        """Start the SFTP server with given configuration.

        ``root`` is the directory to serve.
        ``username`` is the allowed username.
        ``password`` is the password for password authentication.
        ``port`` is the port to listen on (default 3373).
        ``auth_mode`` is 'password', 'key', or 'both' (default).
        ``authorized_key`` is path to public key file for key auth.
        """
        if self._server is not None:
            raise Failure("SFTP server is already running")

        self._root = Path(root).expanduser().resolve()
        self._root.mkdir(parents=True, exist_ok=True)
        self._port = port

        # Create host key
        with tempfile.NamedTemporaryFile(suffix=".key", delete=False) as f:
            host_key_path = Path(f.name)
        self._host_key = ensure_host_key(host_key_path)

        # Load authorized keys if provided
        authorized_keys = []
        if authorized_key:
            authorized_keys = load_authorized_keys([authorized_key])

        # Create tracker for operation verification
        self._tracker = OperationTracker()

        # Create auth config
        auth = AuthConfig(
            username=username,
            password=password,
            auth_mode=auth_mode,
            authorized_keys=authorized_keys,
        )

        # Create jail
        jail = Jail(self._root)

        # Start server
        self._server = ThreadedSFTPServer(
            host=self._host,
            port=self._port,
            host_key=self._host_key,
            auth=auth,
            jail=jail,
            tracker=self._tracker,
        )
        self._server.start()
        self._host, self._port = self._server.address
        time.sleep(0.1)  # Give server time to start

    @keyword
    def stop_sftp_server(self) -> None:
        """Stop the running SFTP server."""
        if self._server is None:
            raise Failure("SFTP server is not running")

        self._server.shutdown()
        self._server = None

    @keyword
    def connect_to_server(
        self,
        username: str,
        password: str | None = None,
        private_key: str | None = None,
    ) -> None:
        """Connect to the SFTP server as a client.

        ``username`` is the username to authenticate with.
        ``password`` is the password for password authentication.
        ``private_key`` is path to private key for key authentication.
        """
        if self._server is None:
            raise Failure("SFTP server is not running")

        self._transport = paramiko.Transport((self._host, self._port))
        pkey = None
        if private_key:
            pkey = paramiko.RSAKey.from_private_key_file(private_key)

        self._transport.connect(username=username, password=password, pkey=pkey)
        self._sftp = paramiko.SFTPClient.from_transport(self._transport)

    @keyword
    def disconnect_from_server(self) -> None:
        """Disconnect from the SFTP server."""
        if self._sftp:
            self._sftp.close()
            self._sftp = None
        if self._transport:
            self._transport.close()
            self._transport = None

    # ==================== Client Operation Keywords ====================

    @keyword
    def upload_file(self, local_path: str, remote_path: str) -> None:
        """Upload a file from local to remote path."""
        if not self._sftp:
            raise Failure("Not connected to server")
        self._sftp.put(local_path, remote_path)

    @keyword
    def download_file(self, remote_path: str, local_path: str) -> None:
        """Download a file from remote to local path."""
        if not self._sftp:
            raise Failure("Not connected to server")
        self._sftp.get(remote_path, local_path)

    @keyword
    def list_directory(self, remote_path: str = ".") -> list[str]:
        """List files in a directory. Returns list of filenames."""
        if not self._sftp:
            raise Failure("Not connected to server")
        return self._sftp.listdir(remote_path)

    @keyword
    def delete_file(self, remote_path: str) -> None:
        """Delete a file on the server."""
        if not self._sftp:
            raise Failure("Not connected to server")
        self._sftp.remove(remote_path)

    @keyword
    def create_directory(self, remote_path: str) -> None:
        """Create a directory on the server."""
        if not self._sftp:
            raise Failure("Not connected to server")
        self._sftp.mkdir(remote_path)

    @keyword
    def remove_directory(self, remote_path: str) -> None:
        """Remove an empty directory on the server."""
        if not self._sftp:
            raise Failure("Not connected to server")
        self._sftp.rmdir(remote_path)

    @keyword
    def rename_file(self, source: str, target: str) -> None:
        """Rename or move a file on the server."""
        if not self._sftp:
            raise Failure("Not connected to server")
        self._sftp.rename(source, target)

    @keyword
    def get_file_stats(self, remote_path: str) -> dict:
        """Get file statistics. Returns dict with st_size, st_mode."""
        if not self._sftp:
            raise Failure("Not connected to server")
        attrs = self._sftp.stat(remote_path)
        return {"st_size": attrs.st_size, "st_mode": attrs.st_mode}

    @keyword
    def set_file_permissions(self, remote_path: str, mode: str) -> None:
        """Set file permissions (chmod)."""
        if not self._sftp:
            raise Failure("Not connected to server")
        self._sftp.chmod(remote_path, int(mode, 8))

    @keyword
    def create_symlink(self, target: str, link_path: str) -> None:
        """Create a symbolic link."""
        if not self._sftp:
            raise Failure("Not connected to server")
        self._sftp.symlink(target, link_path)

    @keyword
    def read_symlink(self, link_path: str) -> str:
        """Read the target of a symbolic link."""
        if not self._sftp:
            raise Failure("Not connected to server")
        return self._sftp.readlink(link_path)

    # ==================== Resume Operation Keywords ====================

    @keyword
    def resume_upload(self, local_path: str, remote_path: str) -> None:
        """Resume an interrupted upload."""
        if not self._sftp:
            raise Failure("Not connected to server")

        local_size = os.path.getsize(local_path)
        try:
            remote_size = self._sftp.stat(remote_path).st_size
        except IOError:
            remote_size = 0

        if remote_size > local_size:
            raise ValueError("remote file is larger than the local file")

        with open(local_path, "rb") as local_file:
            local_file.seek(remote_size)
            with self._sftp.file(remote_path, "a" if remote_size else "w") as remote_file:
                while True:
                    chunk = local_file.read(32768)
                    if not chunk:
                        break
                    remote_file.write(chunk)

    @keyword
    def resume_download(self, remote_path: str, local_path: str) -> None:
        """Resume an interrupted download."""
        if not self._sftp:
            raise Failure("Not connected to server")

        local_path_obj = Path(local_path)
        local_size = local_path_obj.stat().st_size if local_path_obj.exists() else 0

        with self._sftp.file(remote_path, "rb") as remote_file:
            remote_file.seek(local_size)
            with open(local_path_obj, "ab") as local_file:
                while True:
                    chunk = remote_file.read(32768)
                    if not chunk:
                        break
                    local_file.write(chunk)

    # ==================== Operation Verification Keywords ====================

    @keyword
    def get_last_operation(self) -> dict:
        """Get the most recent SFTP operation. Returns dict with operation, path, success, error."""
        if not self._tracker:
            raise Failure("No operation tracker available")
        op = self._tracker.get_last_operation()
        if op is None:
            raise NotFoundError("No operations recorded")
        return op

    @keyword
    def get_operations_count(self) -> int:
        """Get total number of SFTP operations."""
        if not self._tracker:
            raise Failure("No operation tracker available")
        return self._tracker.get_operations_count()

    @keyword
    def get_operations_by_type(self, operation: str) -> list[dict]:
        """Get all operations of a specific type (upload, download, list, etc.)."""
        if not self._tracker:
            raise Failure("No operation tracker available")
        return self._tracker.get_operations_by_type(operation)

    @keyword
    def operation_should_exist(self, operation: str, path: str | None = None) -> None:
        """Assert that an operation of the given type occurred."""
        ops = self.get_operations_by_type(operation)
        if not ops:
            raise Failure(f"No '{operation}' operation found")
        if path:
            matching = [op for op in ops if op["path"] == path]
            if not matching:
                raise Failure(f"No '{operation}' operation found for path '{path}'")

    @keyword
    def operation_should_succeed(self, operation: str, path: str | None = None) -> None:
        """Assert that the last operation of the given type succeeded."""
        ops = self.get_operations_by_type(operation)
        if not ops:
            raise Failure(f"No '{operation}' operation found")

        target_op = ops[-1] if path is None else None
        if path:
            for op in reversed(ops):
                if op["path"] == path:
                    target_op = op
                    break
            if target_op is None:
                raise Failure(f"No '{operation}' operation found for path '{path}'")

        if not target_op["success"]:
            raise Failure(f"Operation '{operation}' on '{target_op['path']}' failed: {target_op.get('error', 'unknown error')}")

    @keyword
    def clear_operations(self) -> None:
        """Clear all recorded operations."""
        if self._tracker:
            self._tracker.clear()