import os
import shutil
import sqlite3

import pytest

from dev_detect.storage import DatabaseStorage, StorageError

MAC = 'aa:bb:cc:dd:ee:ff'
OTHER_MAC = 'a1:b2:c3:d4:e5:f6'


def test_store(storage):
    """Test simple write"""
    storage.store('aa:bb:cc:dd:ee:ff')
    macs = storage.get_known()

    assert macs == ['aa:bb:cc:dd:ee:ff']


def test_store_again(storage):
    """Test that only unique values are stored"""
    storage.store('aa:bb:cc:dd:ee:ff')
    storage.store('aa:bb:cc:dd:ee:ff')

    macs = storage.get_known()

    assert macs == ['aa:bb:cc:dd:ee:ff']


@pytest.mark.parametrize(
    'storage, searched, expected',
    [
        (['aa:bb:cc:dd:ee:ff'], 'aa:bb:cc:dd:ee:ff', True),
        (['aa:bb:cc:dd:ee:ff'], 'a1:b2:c2:d4:e5:f6', False),
        (['aa:bb:cc:dd:ee:ff'], 'aaaa', False),
    ],
    indirect=['storage']
)
def test_search(storage, searched, expected):
    assert storage.search(searched) is expected


@pytest.mark.parametrize(
    'storage', [('aa:bb:cc:dd:ee:ff',)],
    indirect=True
)
def test_remove(storage):
    storage.remove('aa:bb:cc:dd:ee:ff')
    macs = storage.get_known()

    assert macs == []


@pytest.mark.parametrize(
    'storage',
    [
        ('aa:bb:cc:dd:ee:ff', 'a1:b2:c3:d4:e5:f6',)
    ],
    indirect=True
)
def test_clear(storage):
    storage.clear()
    macs = storage.get_known()

    assert macs == []


def test_store_reports_new_devices(storage):
    assert storage.store('aa:bb:cc:dd:ee:ff') is True
    assert storage.store('aa:bb:cc:dd:ee:ff') is False


def test_missing_directory_is_not_created(tmp_path):
    directory = tmp_path / 'srv' / 'dev-detect'
    storage = DatabaseStorage(str(directory / 'dev-detect.db'))

    with pytest.raises(StorageError):
        storage.store(MAC)
    assert not directory.exists()
    storage.close()


def test_replaced_database_is_reopened(tmp_path):
    """Reads follow the file at db_path, not the inode opened first"""
    db_path = str(tmp_path / 'dev-detect.db')
    daemon = DatabaseStorage(db_path)
    daemon.store(MAC)

    replacement = str(tmp_path / 'restored.db')
    shutil.copy(db_path, replacement)
    os.replace(replacement, db_path)
    cli = DatabaseStorage(db_path)
    assert cli.remove(MAC)

    assert not daemon.search(MAC)
    assert daemon.store(OTHER_MAC)
    assert cli.get_known() == [OTHER_MAC]
    daemon.close()
    cli.close()


def test_deleted_database_is_recreated(tmp_path):
    db_path = str(tmp_path / 'dev-detect.db')
    storage = DatabaseStorage(db_path)
    storage.store(MAC)
    os.unlink(db_path)

    assert not storage.search(MAC)
    assert storage.store(OTHER_MAC)
    assert storage.get_known() == [OTHER_MAC]
    storage.close()


@pytest.mark.skipif(os.geteuid() == 0, reason='file permissions do not apply to root')
def test_read_only_database(tmp_path):
    db_path = str(tmp_path / 'dev-detect.db')
    writer = DatabaseStorage(db_path)
    writer.store(MAC)
    writer.close()
    os.chmod(db_path, 0o444)

    storage = DatabaseStorage(db_path)
    assert storage.search(MAC)
    with pytest.raises(StorageError, match='readonly'):
        storage.store(OTHER_MAC)
    assert not storage.conn.in_transaction  # no lock left behind

    os.chmod(db_path, 0o644)
    assert storage.store(OTHER_MAC)  # connection opened read-only is reopened
    storage.close()


def test_vanished_directory_is_not_recreated(tmp_path):
    """E.g. /srv unmounted while running: do not create a new database on rootfs"""
    directory = tmp_path / 'srv'
    directory.mkdir()
    db_path = directory / 'dev-detect.db'
    storage = DatabaseStorage(str(db_path))
    storage.store(MAC)
    directory.rename(tmp_path / 'detached')

    with pytest.raises(StorageError):
        storage.search(MAC)
    with pytest.raises(StorageError):
        storage.store(OTHER_MAC)
    assert not directory.exists()
    storage.close()


def test_corrupted_database(tmp_path):
    db_path = tmp_path / 'dev-detect.db'
    db_path.write_bytes(b'this is not a database' * 100)
    storage = DatabaseStorage(str(db_path))

    with pytest.raises(StorageError) as excinfo:
        storage.search(MAC)
    assert str(db_path) in str(excinfo.value)
    storage.close()


@pytest.fixture
def short_timeout(monkeypatch):
    """Do not wait 5 s for locks held by another connection"""
    connect = sqlite3.connect
    monkeypatch.setattr(sqlite3, 'connect', lambda path, *args, **kwargs: connect(path, timeout=0.1))


def test_failed_commit_leaves_no_transaction(tmp_path, short_timeout):
    db_path = str(tmp_path / 'dev-detect.db')
    storage = DatabaseStorage(db_path)
    storage.store(MAC)
    reader = sqlite3.connect(db_path, isolation_level=None)
    reader.execute('BEGIN')
    reader.execute('SELECT * FROM known_devices').fetchall()  # holds a shared lock

    with pytest.raises(StorageError, match='locked'):
        storage.store(OTHER_MAC)
    assert not storage.conn.in_transaction

    reader.execute('ROLLBACK')
    reader.close()
    assert not DatabaseStorage(db_path).search(OTHER_MAC)
    storage.store('02:00:00:00:00:01')
    assert not storage.search(OTHER_MAC)  # the failed write is not committed later
    storage.close()


def test_database_replaced_while_being_opened(tmp_path, monkeypatch):
    db_path = str(tmp_path / 'dev-detect.db')
    DatabaseStorage(db_path).store(MAC)
    replacement = str(tmp_path / 'replacement.db')
    DatabaseStorage(replacement).store(OTHER_MAC)
    prepare = DatabaseStorage._prepare.__func__

    def prepare_and_replace(cls, conn):
        prepare(cls, conn)
        if os.path.exists(replacement):
            os.replace(replacement, db_path)
    monkeypatch.setattr(DatabaseStorage, '_prepare', classmethod(prepare_and_replace))
    storage = DatabaseStorage(db_path)

    storage.get_known()  # opened the file being replaced
    assert storage.get_known() == [OTHER_MAC]
    storage.close()
