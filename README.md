# sftpserver

Python-based SFTP server with:

- Username/password authentication
- Public key authentication
- `both` mode to allow password and key auth at the same time
- Standard SFTP file operations like upload, download, list, stat, rename, delete, mkdir, rmdir, chmod, chown, symlink, and readlink
- Resume-friendly transfers via SFTP offset-based reads/writes, plus a test client with `resume-upload` and `resume-download`

## Install

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Run

Serve `/tmp/sftp-root` for user `demo`:

```bash
python3 sftp_server.py \
  --root /tmp/sftp-root \
  --username demo \
  --password secret123
```

By default, the server uses `--auth-mode both`, which means:

- password auth is accepted when `--password` is provided
- public key auth is accepted when `--authorized-key` is provided one or more times

Example with both auth types enabled:

```bash
python3 sftp_server.py \
  --root /tmp/sftp-root \
  --username demo \
  --password secret123 \
  --authorized-key ~/.ssh/id_ed25519.pub \
  --authorized-key ~/.ssh/id_rsa.pub
```

Force password-only auth:

```bash
python3 sftp_server.py \
  --root /tmp/sftp-root \
  --username demo \
  --password secret123 \
  --auth-mode password
```

Force key-only auth:

```bash
python3 sftp_server.py \
  --root /tmp/sftp-root \
  --username demo \
  --authorized-key ~/.ssh/id_ed25519.pub \
  --auth-mode key
```

## Notes

- A host key file is required for SSH. If `--host-key` does not exist, the server creates one automatically.
- The SFTP root directory is created automatically if it does not exist.
- Paths are constrained to the configured root directory.
- This server currently supports a single configured user per process, which is a good starting point for local use and testing.
- SFTP resume support is compatible with standard client behavior because the protocol supports reading and writing from explicit offsets.

## Test Client

A small Python client is included at [tests/sftp_test_client.py](/Users/rameshboini/github/sftpserver/tests/sftp_test_client.py).

Examples:

```bash
python3 tests/sftp_test_client.py \
  --host 127.0.0.1 \
  --port 3373 \
  --username demo \
  --password secret123 \
  list /
```

```bash
python3 tests/sftp_test_client.py \
  --host 127.0.0.1 \
  --port 3373 \
  --username demo \
  --password secret123 \
  resume-upload ./big-file.bin /big-file.bin
```

## Tests

Run:

```bash
python3 -m unittest discover -s tests -v
```

The integration tests in [tests/test_sftp_server.py](/Users/rameshboini/github/sftpserver/tests/test_sftp_server.py) cover:

- password auth
- public key auth
- failed authentication
- upload/download/list/stat/remove
- mkdir/rmdir/rename/posix rename
- symlink/readlink
- chmod/chown/truncate
- jailed path enforcement
- interrupted upload/download resume flows
- random-access writes on existing files
