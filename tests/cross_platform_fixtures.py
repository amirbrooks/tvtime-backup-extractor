from __future__ import annotations

import io
import sqlite3
import tarfile
import zipfile
import zlib
from contextlib import closing
from pathlib import Path

from tests.helpers import synthetic_payloads
from tvtime_extractor.acquisition import ANDROID_BACKUP_MAGIC
from tvtime_extractor.safety import secure_directory, secure_file


def create_synthetic_cache_database(path: Path) -> bytes:
    secure_directory(path.parent)
    with closing(sqlite3.connect(path)) as connection:
        connection.execute(
            "CREATE TABLE cache_dio "
            "(key TEXT NOT NULL, subKey TEXT NOT NULL, content BLOB, statusCode INTEGER)"
        )
        connection.executemany(
            "INSERT INTO cache_dio (key, subKey, content, statusCode) VALUES (?, ?, ?, ?)",
            synthetic_payloads(),
        )
        connection.commit()
    secure_file(path)
    return path.read_bytes()


def synthetic_android_backup(
    database: bytes,
    *,
    compressed: bool = True,
    include_empty_optional_sidecar: bool = False,
) -> bytes:
    archive_bytes = io.BytesIO()
    with tarfile.open(fileobj=archive_bytes, mode="w") as archive:
        member = tarfile.TarInfo("apps/com.tozelabs.tvshowtime/db/DioCache.db")
        member.size = len(database)
        member.mode = 0o600
        member.mtime = 0
        member.uid = 0
        member.gid = 0
        member.uname = ""
        member.gname = ""
        archive.addfile(member, io.BytesIO(database))
        if include_empty_optional_sidecar:
            sidecar = tarfile.TarInfo("apps/com.tozelabs.tvshowtime/db/DioCache.db-wal")
            sidecar.size = 0
            sidecar.mode = 0o600
            sidecar.mtime = 0
            sidecar.uid = 0
            sidecar.gid = 0
            sidecar.uname = ""
            sidecar.gname = ""
            archive.addfile(sidecar, io.BytesIO())
    payload = archive_bytes.getvalue()
    if compressed:
        payload = zlib.compress(payload)
    return ANDROID_BACKUP_MAGIC + b"5\n" + (b"1\n" if compressed else b"0\n") + b"none\n" + payload


def create_synthetic_android_backup(path: Path) -> Path:
    database = create_synthetic_cache_database(path.parent / "fixture-cache.sqlite")
    path.write_bytes(synthetic_android_backup(database))
    secure_file(path)
    return path


def create_synthetic_android_snapshot(path: Path) -> Path:
    databases = secure_directory(path / "databases")
    create_synthetic_cache_database(databases / "DioCache.db")
    empty_sidecar = databases / "DioCache.db-wal"
    empty_sidecar.touch(mode=0o600)
    secure_file(empty_sidecar)
    return path


def create_synthetic_official_export(path: Path) -> Path:
    episodes = (
        b"type,ep_id,created_at,season_number,episode_number,show_id,show_name,episode_name\n"
        b"watch-episode,101,2025-01-02 03:04:05,1,2,show-1,Example Series,"
        b"The Synthetic Episode\n"
    )
    movies = (
        b"created_at,uuid,type,movie_name,entity_type,imdb_id\n"
        b"2025-02-03 04:05:06,11111111-1111-4111-8111-111111111111,watch,"
        b"Example Movie,movie,tt0000001\n"
    )
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for filename, payload in (
            ("tracking-prod-records-v2.csv", episodes),
            ("tracking-prod-records.csv", movies),
        ):
            member = zipfile.ZipInfo(filename, date_time=(1980, 1, 1, 0, 0, 0))
            member.compress_type = zipfile.ZIP_DEFLATED
            member.external_attr = 0o600 << 16
            archive.writestr(member, payload)
    secure_file(path)
    return path
