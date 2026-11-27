"""Step 4 datastore: indexes, status, compression (data stays readable and re-loadable), backup + restore."""
import shutil
import subprocess

import pytest

from datasets import to_unified as tu
from ingest import datastore as ds
from ingest.db import connect

from conftest import SCHEMA
from test_datasets_unified import ai_flows

STORE_DB = "aegex_test_store"


@pytest.fixture
def store(test_db_url):
    """A throw-away database with the schema, so compressing it can't touch the shared test database.
    (test_db_url is only asked for so the test is skipped when the database server is down.)"""
    schema = SCHEMA.read_text(encoding="utf-8")
    with connect() as admin:
        admin.execute(f"DROP DATABASE IF EXISTS {STORE_DB} WITH (FORCE)")
        admin.execute(f"CREATE DATABASE {STORE_DB}")
    url = ds.url_for(STORE_DB)
    with connect(url) as conn:
        conn.execute(schema)
        yield conn
    with connect() as admin:
        admin.execute(f"DROP DATABASE IF EXISTS {STORE_DB} WITH (FORCE)")


def load(conn, cap="ds-test-mirai"):
    rows, _ = tu.to_rows(ai_flows(), cap)
    return tu.save(conn, "kitsune", cap, rows, "test")


def test_one_capture_reads_have_an_index(db):
    names = {r[0] for r in db.execute("SELECT indexname FROM pg_indexes WHERE tablename IN ('flows', 'events')")}
    assert {"ix_flows_capture_ts", "ix_events_capture_ts"} <= names


def test_status_reports_tables_rows_and_captures(store):
    load(store)
    s = ds.status(store)
    assert s["database"] == STORE_DB and s["bytes"] > 0
    assert {h["table"] for h in s["hypertables"]} == {"events", "flows", "feature_windows"}
    assert s["tables"]["captures"] == 1 and s["datasets"] == [("kitsune", 1)]
    assert s["flows_from"].year == 2018


def test_compressed_data_stays_readable_and_reloadable(store):
    assert load(store) == 3
    out = ds.compress(store)
    assert out["flows"][0] >= 1                                         # chunks compressed now
    flows = next(h for h in ds.status(store)["hypertables"] if h["table"] == "flows")
    assert flows["compressed_chunks"] == flows["chunks"] >= 1
    assert flows["before_compression"] > flows["after_compression"] > 0
    ds.print_status(ds.status(store))                                   # the printout works on compressed tables
    assert store.execute("SELECT count(*), sum(label) FROM flows").fetchone() == (3, 2)
    assert load(store) == 3                                             # re-load = delete + insert on compressed rows
    assert store.execute("SELECT count(*), sum(label) FROM flows").fetchone() == (3, 2)
    assert ds.compress(store)["flows"][0] >= 0                          # safe to run again
    assert store.execute("SELECT count(*) FROM flows WHERE attack_class = 'mirai'").fetchone()[0] == 2


def test_compress_older_than_leaves_new_chunks_alone(store):
    load(store)
    assert ds.compress(store, older_than="100 years")["flows"][0] == 0


def test_database_names_are_checked():
    with pytest.raises(ds.DatastoreError):
        ds.backup("aegex; DROP DATABASE aegex")
    with pytest.raises(ds.DatastoreError):
        ds.restore(ds.Path("x.dump"), "Bad-Name")


def docker_ok() -> bool:
    if not shutil.which("docker"):
        return False
    return subprocess.run(["docker", "exec", ds.CONTAINER, "true"], capture_output=True).returncode == 0


@pytest.mark.skipif(not docker_ok(), reason=f"docker container {ds.CONTAINER} not reachable")
def test_backup_and_restore_round_trip(store, tmp_path):
    load(store)
    ds.compress(store)
    dump = ds.backup(STORE_DB, tmp_path)
    assert dump.stat().st_size > 0
    target = STORE_DB + "_r"
    with connect() as admin:
        admin.execute(f"DROP DATABASE IF EXISTS {target} WITH (FORCE)")
    try:
        counts = ds.restore(dump, target)
        assert counts == {"captures": 1, "flows": 3, "events": 0, "alerts": 0}
        with connect(ds.url_for(target)) as c:                          # restored rows are the same rows
            assert c.execute("SELECT sum(label), max(attack_class) FROM flows").fetchone() == (2, "mirai")
        with pytest.raises(ds.DatastoreError, match="already exists"):
            ds.restore(dump, target)                                    # never over an existing database
    finally:
        with connect() as admin:
            admin.execute(f"DROP DATABASE IF EXISTS {target} WITH (FORCE)")
