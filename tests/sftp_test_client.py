#!/usr/bin/env python3
"""Small SFTP client utility for exercising the local test server."""

from __future__ import annotations

import argparse
import os
from pathlib import Path

import paramiko


def connect_client(args: argparse.Namespace) -> paramiko.SFTPClient:
    transport = paramiko.Transport((args.host, args.port))
    pkey = None
    if args.private_key:
        pkey = paramiko.RSAKey.from_private_key_file(args.private_key)
    transport.connect(username=args.username, password=args.password, pkey=pkey)
    return paramiko.SFTPClient.from_transport(transport)


def upload(sftp: paramiko.SFTPClient, local: str, remote: str) -> None:
    sftp.put(local, remote)


def download(sftp: paramiko.SFTPClient, remote: str, local: str) -> None:
    sftp.get(remote, local)


def resume_upload(sftp: paramiko.SFTPClient, local: str, remote: str) -> None:
    local_size = os.path.getsize(local)
    try:
        remote_size = sftp.stat(remote).st_size
    except IOError:
        remote_size = 0

    if remote_size > local_size:
        raise ValueError("remote file is larger than the local file")

    with open(local, "rb") as local_file:
        local_file.seek(remote_size)
        with sftp.file(remote, "a" if remote_size else "w") as remote_file:
            while True:
                chunk = local_file.read(32768)
                if not chunk:
                    break
                remote_file.write(chunk)


def resume_download(sftp: paramiko.SFTPClient, remote: str, local: str) -> None:
    local_path = Path(local)
    local_size = local_path.stat().st_size if local_path.exists() else 0

    with sftp.file(remote, "rb") as remote_file:
        remote_file.seek(local_size)
        with open(local_path, "ab") as local_file:
            while True:
                chunk = remote_file.read(32768)
                if not chunk:
                    break
                local_file.write(chunk)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Simple SFTP test client")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=3373)
    parser.add_argument("--username", required=True)
    parser.add_argument("--password")
    parser.add_argument("--private-key")

    subparsers = parser.add_subparsers(dest="command", required=True)

    upload_parser = subparsers.add_parser("upload")
    upload_parser.add_argument("local")
    upload_parser.add_argument("remote")

    download_parser = subparsers.add_parser("download")
    download_parser.add_argument("remote")
    download_parser.add_argument("local")

    resume_upload_parser = subparsers.add_parser("resume-upload")
    resume_upload_parser.add_argument("local")
    resume_upload_parser.add_argument("remote")

    resume_download_parser = subparsers.add_parser("resume-download")
    resume_download_parser.add_argument("remote")
    resume_download_parser.add_argument("local")

    list_parser = subparsers.add_parser("list")
    list_parser.add_argument("remote", nargs="?", default=".")

    remove_parser = subparsers.add_parser("delete")
    remove_parser.add_argument("remote")

    mkdir_parser = subparsers.add_parser("mkdir")
    mkdir_parser.add_argument("remote")

    rmdir_parser = subparsers.add_parser("rmdir")
    rmdir_parser.add_argument("remote")

    rename_parser = subparsers.add_parser("rename")
    rename_parser.add_argument("source")
    rename_parser.add_argument("target")

    stat_parser = subparsers.add_parser("stat")
    stat_parser.add_argument("remote")

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    sftp = connect_client(args)
    transport = sftp.get_channel().get_transport()
    try:
        if args.command == "upload":
            upload(sftp, args.local, args.remote)
        elif args.command == "download":
            download(sftp, args.remote, args.local)
        elif args.command == "resume-upload":
            resume_upload(sftp, args.local, args.remote)
        elif args.command == "resume-download":
            resume_download(sftp, args.remote, args.local)
        elif args.command == "list":
            for name in sftp.listdir(args.remote):
                print(name)
        elif args.command == "delete":
            sftp.remove(args.remote)
        elif args.command == "mkdir":
            sftp.mkdir(args.remote)
        elif args.command == "rmdir":
            sftp.rmdir(args.remote)
        elif args.command == "rename":
            sftp.rename(args.source, args.target)
        elif args.command == "stat":
            attrs = sftp.stat(args.remote)
            print(f"size={attrs.st_size} mode={attrs.st_mode:o}")
    finally:
        sftp.close()
        transport.close()


if __name__ == "__main__":
    main()
