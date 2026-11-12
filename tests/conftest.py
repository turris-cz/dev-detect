import pytest
import os
import sqlite3

from dev_detect.storage import DatabaseStorage


@pytest.fixture(scope='function')
def storage(request, tmpdir):
    database_dir = tmpdir.mkdir('dev-detect')
    db_path = os.path.join(database_dir, 'dev-detect.db')
    storage = DatabaseStorage(db_path)

    if hasattr(request, 'param'):
        for item in request.param:
            print("Storing item {}".format(item))
            storage.store(item, 'br-lan')

    yield storage
    storage.close()


@pytest.fixture
def commits(monkeypatch):
    """Transactions committed to any database, i.e. writes to the disk"""
    committed = []
    connect = sqlite3.connect

    def counting_connect(*args, **kwargs):
        conn = connect(*args, **kwargs)
        conn.set_trace_callback(lambda sql: committed.append(sql) if sql.strip().upper() == 'COMMIT' else None)
        return conn
    monkeypatch.setattr(sqlite3, 'connect', counting_connect)
    return committed


def pytest_make_parametrize_id(config, val):
    return repr(val)
