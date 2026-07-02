# sftpserver

Python-based SFTP server with:

- Username/password authentication
- Public key authentication
- `both` mode to allow password and key auth at the same time
- Standard SFTP file operations like upload, download, list, stat, rename, delete, mkdir, rmdir, chmod, chown, symlink, and readlink
- Resume-friendly transfers via SFTP offset-based reads/writes, plus a test client with `resume-upload` and `resume-download`
- **Robot Framework integration** for system testing with operation verification

## Overview

This is a standalone SFTP server built on the Paramiko SSH library. It provides a complete implementation of the SFTP protocol with:

- **Single-user design** - One configured user per server process (ideal for local testing)
- **Path jail** - All paths are constrained to the configured root directory
- **Operation tracking** - All SFTP operations are recorded for verification (useful for testing)

```
┌─────────────────────────────────────────────────────────────────┐
│                        SFTP Server Architecture                  │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌──────────────┐     ┌──────────────────┐     ┌─────────────┐ │
│  │   Client     │────▶│  SSH Transport   │────▶│ SFTP Server │ │
│  │  (paramiko)  │     │  (paramiko)      │     │   (this)    │ │
│  └──────────────┘     └──────────────────┘     └──────┬──────┘ │
│                                                       │         │
│                                                       ▼         │
│                                                ┌─────────────┐  │
│                                                │    Jail     │  │
│                                                │ (path map)  │  │
│                                                └──────┬──────┘  │
│                                                       │         │
│                                                       ▼         │
│                                                ┌─────────────┐  │
│                                                │  Filesystem │  │
│                                                │  (/root)    │  │
│                                                └─────────────┘  │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

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
- Paths are constrained to the configured root directory (jail/chroot behavior).
- This server currently supports a single configured user per process, which is a good starting point for local use and testing.
- SFTP resume support is compatible with standard client behavior because the protocol supports reading and writing from explicit offsets.

## Architecture

### Core Components

| Component | Description |
|-----------|-------------|
| `ThreadedSFTPServer` | Main server class that handles client connections |
| `SFTPSSHServer` | SSH authentication handler (password/key auth) |
| `LocalSFTPServer` | SFTP protocol implementation |
| `Jail` | Path mapping - constrains all paths to root directory |
| `OperationTracker` | Records all SFTP operations for verification |

### Operation Tracking Flow

```
Client Operation (upload)
        │
        ▼
   SFTP Server
        │
        ├─▶ LocalSFTPServer.open()
        │        │
        │        └─▶ OperationTracker.record("open", path, True)
        │
        ▼
   Verification (Robot Framework)
        │
        └─▶ Get Last Operation → {"operation": "open", "path": "/file.txt", "success": true}
```

## SFTP Standard Operations Explained

SFTP is the file transfer protocol that runs over SSH. From a normal user's point of view, it is the set of actions you do when working with files on a remote server, such as uploading, downloading, renaming, deleting, and browsing folders.

Some names below are protocol-level names, and some are the everyday names people usually say in tools like WinSCP, FileZilla, OpenSSH `sftp`, or custom apps. In practice, they all map to the same core ideas.

### 1. Connect and Start Session

- `INIT` / `VERSION`
  The client and server say hello and agree on the SFTP session.
  In simple terms, this is the moment the SFTP connection starts.

### 2. Login / Authentication

- Password authentication
  Meaning: log in with username and password.
- Public key authentication
  Meaning: log in using an SSH key instead of a password.

This server supports both at the same time, or either one by itself.

### 3. Browse Files and Folders

- `OPENDIR`
  Open a folder so its contents can be read.
  This is what happens when you open a remote folder.
- `READDIR`
  List the files and subfolders inside a folder.
  This is how a client shows folder contents.
- `REALPATH`
  Convert a path into its clean, absolute form.
  This helps the client figure out the actual full path of a file or folder.

### 4. Read Information About Files

- `STAT`
  Get information about a file or folder.
  This is used to show properties like size, modified time, and permissions.
- `LSTAT`
  Similar to `STAT`, but if the path is a symlink, it inspects the link itself instead of the file it points to.
  This is useful when checking whether something is a link and where it leads.
- `FSTAT`
  Get info about a file that is already open.
  This lets a client inspect file details while working with it.

### 5. Download Files

- `OPEN` + `READ` + `CLOSE`
  Open a remote file, read its contents, then close it.
  This is how a file is downloaded or viewed.
- `get`
  Common client command for download.
  It copies a file from the server to your computer.
- `reget`
  Resume a partially completed download.
  It continues a broken download from where it stopped.

### 6. Upload Files

- `OPEN` + `WRITE` + `CLOSE`
  Open or create a remote file, write data into it, then close it.
  This is how a file is uploaded.
- `put`
  Common client command for upload.
  It copies a file from your computer to the server.
- Resume upload
  Continue writing the remaining part of a file after interruption.
  It continues a broken upload from where it stopped.

### 7. Create, Delete, and Change Files

- `REMOVE`
  Delete a file.
- `RENAME`
  Rename or move a file or folder.
- `posix-rename`
  A stronger rename behavior used by some clients and servers for safer replace operations.
  It is useful when one file should replace another more safely.
- Random-access write
  Write to the middle of a file instead of only at the end.
  This is how part of an existing file can be overwritten.

### 8. Create and Delete Folders

- `MKDIR`
  Create a folder.
- `RMDIR`
  Remove an empty folder.

### 9. Permissions and Ownership

- `SETSTAT`
  Change file attributes using a path.
  This is how permissions, owner, group, or timestamps are updated.
- `FSETSTAT`
  Change file attributes on a file that is already open.
  It does the same kind of update, but through an already-open file handle.
- `chmod`
  Change file permissions.
  This controls who can read, write, or execute a file.
- `chown`
  Change file owner.
  This assigns the file to a different user.
- `chgrp`
  Change file group.
  This assigns the file to a different group.
- truncate
  Shorten or extend a file to a certain size.
  This can be used to cut a file down or reserve space.

### 10. Links

- `SYMLINK`
  Create a symbolic link.
  This acts like a shortcut-like reference to another file.
- `READLINK`
  Find out where a symbolic link points.
  This lets the client inspect the target of a link.

### 11. What People Mean by Push / Pull

- Push
  Send a file from your machine to the server.
  In SFTP terms, this is upload, usually through `OPEN` and `WRITE`.
- Pull
  Get a file from the server to your machine.
  In SFTP terms, this is download, usually through `OPEN` and `READ`.

### 12. What Is Usually Not a Separate SFTP Server Operation

- Recursive upload/download
  Copy an entire folder tree.
  This is usually done by the client by repeating normal file and folder operations many times.
- Progress bars
  Show transfer percentage.
  This is a client feature, not a server operation.
- Drag and drop
  A GUI convenience in SFTP apps.
  This is also a client feature.

### What This Server Supports

This server supports the main everyday SFTP operations people expect:

- login with password
- login with SSH public key
- listing folders
- viewing file information
- upload
- download
- resume upload
- resume download
- rename and move
- delete file
- create/delete folder
- chmod/chown/truncate
- symlink/readlink

### What This Server Does Not Yet Add Beyond Core SFTP

- multi-user configuration in one server process
- vendor-specific extensions like filesystem usage extensions
- full recursive copy as a built-in server feature, because clients normally handle that themselves

## Robot Framework Integration

This server can be used with Robot Framework for system testing. The `SftpServerLibrary` provides keywords for server lifecycle management and operation verification.

### Install Robot Framework

```bash
pip install -r requirements.txt
```

### Robot Framework Library Keywords

**Server Lifecycle:**
- `Start SFTP Server` - Start the server with configuration
- `Stop SFTP Server` - Stop the running server
- `Connect To Server` - Connect as a client
- `Disconnect From Server` - Disconnect client session

**Client Operations:**
- `Upload File` - Upload a file
- `Download File` - Download a file
- `List Directory` - List directory contents
- `Delete File` - Remove a file
- `Create Directory` - Make a directory
- `Remove Directory` - Remove empty directory
- `Rename File` - Move/rename a file
- `Get File Stats` - Get file size and permissions
- `Set File Permissions` - chmod
- `Create Symlink` - Create symbolic link
- `Read Symlink` - Get symlink target
- `Resume Upload` - Resume interrupted upload
- `Resume Download` - Resume interrupted download

**Operation Verification:**
- `Get Last Operation` - Get the most recent operation details
- `Get Operations Count` - Count total operations
- `Get Operations By Type` - Filter operations by type
- `Operation Should Exist` - Assert an operation occurred
- `Operation Should Succeed` - Assert an operation succeeded
- `Clear Operations` - Reset operation history

### Operation Tracking Example

When a client performs an operation, the server records it. You can verify operations in your tests:

```robotframework
*** Settings ***
Library    SftpServerLibrary

*** Test Cases ***
Upload And Verify Operation
    Start SFTP Server    /tmp/sftp-test    demo    secret123
    Connect To Server    demo    secret123
    
    # Upload a file
    Upload File    /tmp/test.txt    /upload.txt
    
    # Verify the operation was recorded and succeeded
    Operation Should Exist    open    /upload.txt
    Operation Should Succeed    open    /upload.txt
    
    # Get operation details
    ${op} =    Get Last Operation
    Should Be Equal    ${op['operation']}    open
    Should Be Equal    ${op['path']}    /upload.txt
    Should Be True    ${op['success']}
    
    [Teardown]    Stop SFTP Server
```

### Complete Robot Framework Test Suite Example

```robotframework
*** Settings ***
Library    SftpServerLibrary
Suite Setup    Start Server
Suite Teardown    Stop SFTP Server

*** Variables ***
${ROOT}    /tmp/sftp-test-root
${USER}    demo
${PASS}    secret123

*** Keywords ***
Start Server
    Start SFTP Server    ${ROOT}    ${USER}    ${PASS}
    Connect To Server    ${USER}    ${PASS}

*** Test Cases ***
Upload File And Verify
    Upload File    /tmp/local.txt    /remote.txt
    Operation Should Succeed    open    /remote.txt
    Clear Operations

Download File And Verify
    List Directory
    Operation Should Succeed    list    .
    Clear Operations

Delete File And Verify
    Delete File    /remote.txt
    Operation Should Succeed    remove    /remote.txt

Directory Operations
    Create Directory    /testdir
    Operation Should Succeed    mkdir    /testdir
    Remove Directory    /testdir
    Operation Should Succeed    rmdir    /testdir
```

### Running Robot Framework Tests

```bash
robot tests/robot_tests/sftp_server_tests.robot
```

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

## Package Structure

```
sftpserver/
├── sftp_server.py          # Core server implementation
├── robot_sftp_library.py   # Robot Framework library
├── __init__.py             # Package exports
tests/
├── test_sftp_server.py     # Unit tests
├── sftp_test_client.py     # Test client CLI
└── robot_tests/            # Robot Framework tests
    └── sftp_server_tests.robot
sftp_server.py              # CLI entry point wrapper
requirements.txt            # Dependencies
README.md                   # This file
```

## API Usage

You can also use the server programmatically:

```python
from sftpserver.sftp_server import (
    ThreadedSFTPServer,
    Jail,
    AuthConfig,
    OperationTracker,
)
import paramiko
import tempfile
from pathlib import Path

# Create tracker for operation verification
tracker = OperationTracker()

# Setup server
root = Path(tempfile.mkdtemp())
auth = AuthConfig("demo", "secret123", "password", [])
jail = Jail(root)
host_key = paramiko.RSAKey.generate(2048)

server = ThreadedSFTPServer(
    "127.0.0.1", 0, host_key, auth, jail, tracker=tracker
)
server.start()

# Connect as client
transport = paramiko.Transport(("127.0.0.1", server.address[1]))
transport.connect(username="demo", password="secret123")
sftp = paramiko.SFTPClient.from_transport(transport)

# Perform operations
sftp.put("/local/file.txt", "/remote/file.txt")

# Verify operations
print(f"Operations: {tracker.get_operations_count()}")
print(f"Last op: {tracker.get_last_operation()}")

# Cleanup
sftp.close()
transport.close()
server.shutdown()
```
