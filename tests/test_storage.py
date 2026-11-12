import os
import shutil
import sqlite3
import time

import pytest

from dev_detect import storage as storage_module
from dev_detect.storage import SCHEMA_VERSION, DatabaseStorage, Seen, StorageError

MAC = 'aa:bb:cc:dd:ee:ff'
OTHER_MAC = 'a1:b2:c3:d4:e5:f6'
GUEST = ('br-guest-turris', 'br-guest_turris')


def test_store(storage):
    """Test simple write"""
    storage.store('aa:bb:cc:dd:ee:ff', 'br-lan')
    macs = storage.get_known()

    assert macs == ['aa:bb:cc:dd:ee:ff']


def test_store_again(storage):
    """Test that only unique values are stored"""
    storage.store('aa:bb:cc:dd:ee:ff', 'br-lan')
    storage.store('aa:bb:cc:dd:ee:ff', 'br-lan')

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
    assert storage.clear() == 2
    macs = storage.get_known()

    assert macs == []
    assert storage.devices() == []


def test_store_reports_new_devices(storage):
    assert storage.store(MAC, 'br-lan') is True
    assert storage.store(MAC, 'br-lan') is False
    assert storage.store(MAC, 'br-guest-turris') is True  # another network


def test_store_keeps_the_device_once(storage):
    storage.store(MAC, 'br-lan', hostname='Mac')
    storage.store(MAC, 'br-guest-turris')

    assert [row[:3] + row[5:] for row in storage.devices()] == [
        (MAC, None, 'br-lan', 'Mac'), (MAC, None, 'br-guest-turris', 'Mac'),
    ]
    assert storage.get_known() == [MAC]


def test_store_on_another_name_of_the_network(storage):
    """reForis renames br-guest_turris of migrated systems to br-guest-turris"""
    assert storage.store(MAC, 'br-guest_turris')
    assert not storage.store(MAC, 'br-guest-turris', hostname='Mac', aliases=('br-guest_turris',))

    assert [row[2] + row[5] for row in storage.devices()] == ['br-guest_turrisMac']


def test_hostname(storage):
    storage.store(MAC, 'br-lan', hostname='Mac')
    storage.store(MAC, 'br-lan')  # hostname unknown this time
    assert [row[5] for row in storage.devices()] == ['Mac']

    storage.store(MAC, 'br-guest-turris', hostname='MacBook')  # renamed by its user
    assert [row[5] for row in storage.devices()] == ['MacBook', 'MacBook']


def test_name_given_by_user_is_kept(storage):
    """A static DHCP lease names a device only when the user did not"""
    storage.add(MAC, 'my laptop')
    storage.store(MAC, 'br-lan', name='laptop')
    storage.store(OTHER_MAC, 'br-lan', name='printer')

    assert [(row[0], row[1]) for row in storage.devices()] == [
        (MAC, 'my laptop'), (MAC, 'my laptop'), (OTHER_MAC, 'printer'),
    ]


def test_add(storage):
    storage.store(MAC, 'br-lan')

    assert storage.add(OTHER_MAC)
    assert not storage.add(OTHER_MAC)
    assert storage.add(MAC, 'my laptop')  # seen on br-lan only so far
    assert [row[:3] for row in storage.devices()] == [
        (MAC, 'my laptop', ''), (MAC, 'my laptop', 'br-lan'), (OTHER_MAC, None, ''),
    ]


@pytest.mark.parametrize('stored, name, added', [
    ([], None, True),
    ([], 'laptop', True),
    (['br-lan'], None, True),  # seen on a network only so far
    (['br-lan', 'everywhere'], None, False),
    (['br-lan', 'everywhere'], 'laptop', False),  # renamed only
])
def test_add_is_one_write(storage, commits, stored, name, added):
    for iface in stored:
        storage.add(MAC) if iface == 'everywhere' else storage.store(MAC, iface)
    storage.is_empty()  # creates the database
    del commits[:]

    assert storage.add(MAC, name) is added
    assert len(commits) == 1
    assert storage.devices()[0][:3] == (MAC, name, '')


def test_foreign_keys_are_enforced(storage):
    storage.store(MAC, 'br-lan')

    assert storage.conn.execute('PRAGMA foreign_keys').fetchone()[0] == 1
    with pytest.raises(sqlite3.IntegrityError):
        storage.conn.execute("INSERT INTO device_networks (mac, iface, first_seen) VALUES ('02:00:00:00:00:01', 'br-lan', 0)")


def test_touch_does_not_move_last_seen_back(storage, monkeypatch):
    """E.g. a router without a clock that runs behind before NTP sets it"""
    clock = [1700000000]
    monkeypatch.setattr(storage_module.time, 'time', lambda: clock[0])
    storage.store(MAC, 'br-lan')
    clock[0] -= 30 * 24 * 3600
    storage.touch(MAC, ('br-lan',))

    assert network_rows(storage.db_path) == [(MAC, 'br-lan', 1700000000, 1700000000)]


def test_add_renames_device(storage):
    storage.add(MAC, 'laptop')
    assert not storage.add(MAC, 'my laptop')
    assert not storage.add(MAC)  # keeps the name

    assert storage.devices() == [(MAC, 'my laptop', '', None, None, None)]


def test_seen(storage, monkeypatch):
    monkeypatch.setattr(storage_module.time, 'time', lambda: 1700000000.4)
    storage.store(MAC, 'br-lan')
    storage.add(OTHER_MAC)

    assert storage.seen(MAC, ('br-lan',)) == Seen(1700000000, 1700000000, False)
    assert storage.seen(MAC, GUEST) is None  # not on this network yet
    assert storage.seen(MAC, GUEST, per_network=False) == Seen(0, 1700000000, False)  # known, not seen there
    assert storage.seen(OTHER_MAC, GUEST) == Seen(0, 0, True)  # known on every network
    assert storage.seen('02:00:00:00:00:01', ('br-lan',), per_network=False) is None


def test_seen_on_other_networks(storage, monkeypatch):
    clock = [1700000000]
    monkeypatch.setattr(storage_module.time, 'time', lambda: clock[0])
    storage.store(MAC, 'br-lan')
    clock[0] += 3600
    storage.store(MAC, 'br-guest_turris')
    storage.add(MAC)

    assert storage.seen(MAC, ('br-lan',)) == Seen(1700000000, 1700003600, True)
    assert storage.seen(MAC, GUEST) == Seen(1700003600, 1700003600, True)


def test_store_records_that_known_device_is_present(storage, monkeypatch):
    """E.g. a device that came back after it was forgotten"""
    clock = [1700000000]
    monkeypatch.setattr(storage_module.time, 'time', lambda: clock[0])
    storage.store(MAC, 'br-guest_turris')
    clock[0] += 100 * 24 * 3600

    assert not storage.store(MAC, 'br-guest-turris', aliases=('br-guest_turris',))
    assert network_rows(storage.db_path) == [(MAC, 'br-guest_turris', 1700000000, 1700000000 + 100 * 24 * 3600)]


def test_store_does_not_move_last_seen_back(storage, monkeypatch):
    clock = [1700000000]
    monkeypatch.setattr(storage_module.time, 'time', lambda: clock[0])
    storage.store(MAC, 'br-lan')
    clock[0] -= 3600
    storage.store(MAC, 'br-lan')

    assert network_rows(storage.db_path) == [(MAC, 'br-lan', 1700000000, 1700000000)]


def test_seen_on_any_name_of_the_network(storage):
    storage.store(MAC, 'br-guest_turris')

    assert storage.seen(MAC, GUEST)
    assert storage.seen(MAC, ('br-lan',)) is None


def network_rows(db_path):
    conn = sqlite3.connect(db_path)
    try:
        return conn.execute('SELECT mac, iface, first_seen, last_seen FROM device_networks ORDER BY rowid').fetchall()
    finally:
        conn.close()


def test_touch_updates_only_that_network(storage, monkeypatch):
    clock = [1700000000]
    monkeypatch.setattr(storage_module.time, 'time', lambda: clock[0])
    storage.store(MAC, 'br-lan')
    storage.store(MAC, 'br-guest_turris')
    clock[0] += 3600

    storage.touch(MAC, ('br-lan',))
    storage.touch(MAC, GUEST)  # the guest bridge was renamed meanwhile

    assert network_rows(storage.db_path) == [
        (MAC, 'br-lan', 1700000000, 1700003600), (MAC, 'br-guest_turris', 1700000000, 1700003600),
    ]
    clock[0] += 3600
    storage.touch(MAC, ('br-lan',))
    assert [row[3] for row in network_rows(storage.db_path)] == [1700007200, 1700003600]


def test_touch_records_new_network_of_known_device(storage, monkeypatch):
    monkeypatch.setattr(storage_module.time, 'time', lambda: 1700000000)
    storage.add(MAC)
    storage.touch(MAC, GUEST)

    assert network_rows(storage.db_path) == [(MAC, 'br-guest-turris', 1700000000, 1700000000)]


def test_touch_does_not_store_unknown_device(storage):
    """E.g. removed by `dev-detect remove` meanwhile"""
    storage.touch(MAC, ('br-lan',))

    assert storage.is_empty()
    assert network_rows(storage.db_path) == []


def test_remove_removes_all_networks(storage):
    storage.store(MAC, 'br-lan')
    storage.store(MAC, 'br-guest-turris')
    storage.store(OTHER_MAC, 'br-lan')

    assert storage.remove(MAC)
    assert not storage.remove(MAC)
    assert [row[0] for row in network_rows(storage.db_path)] == [OTHER_MAC]


@pytest.mark.parametrize('operation', [
    lambda storage: storage.store(MAC, 'br-lan'),
    lambda storage: storage.store(OTHER_MAC, 'br-lan', name='printer', hostname='printer'),
    lambda storage: storage.store(OTHER_MAC, 'br-guest-turris', hostname='phone'),
    lambda storage: storage.touch(OTHER_MAC, GUEST),
    lambda storage: storage.add(MAC, 'my laptop'),
    lambda storage: storage.add(OTHER_MAC, 'new name'),
    lambda storage: storage.remove(OTHER_MAC),
    lambda storage: storage.clear(),
], ids=['new', 'with name', 'new network', 'touch', 'add', 'rename', 'remove', 'clear'])
def test_every_change_is_one_write(storage, commits, operation):
    storage.store(OTHER_MAC, 'br-lan')
    del commits[:]

    operation(storage)

    assert len(commits) == 1


def test_reads_do_not_write(storage, commits):
    storage.store(MAC, 'br-lan')
    del commits[:]

    storage.seen(MAC, ('br-lan',))
    storage.search(MAC)
    storage.devices()
    storage.is_empty()
    DatabaseStorage(storage.db_path).devices()  # opening a current database

    assert commits == []


def test_missing_directory_is_not_created(tmp_path):
    directory = tmp_path / 'srv' / 'dev-detect'
    storage = DatabaseStorage(str(directory / 'dev-detect.db'))

    with pytest.raises(StorageError):
        storage.store(MAC, 'br-lan')
    assert not directory.exists()
    storage.close()


def test_replaced_database_is_reopened(tmp_path):
    """Reads follow the file at db_path, not the inode opened first"""
    db_path = str(tmp_path / 'dev-detect.db')
    daemon = DatabaseStorage(db_path)
    daemon.store(MAC, 'br-lan')

    replacement = str(tmp_path / 'restored.db')
    shutil.copy(db_path, replacement)
    os.replace(replacement, db_path)
    cli = DatabaseStorage(db_path)
    assert cli.remove(MAC)

    assert not daemon.search(MAC)
    assert daemon.store(OTHER_MAC, 'br-lan')
    assert cli.get_known() == [OTHER_MAC]
    daemon.close()
    cli.close()


def test_deleted_database_is_recreated(tmp_path):
    db_path = str(tmp_path / 'dev-detect.db')
    storage = DatabaseStorage(db_path)
    storage.store(MAC, 'br-lan')
    os.unlink(db_path)

    assert not storage.search(MAC)
    assert storage.store(OTHER_MAC, 'br-lan')
    assert storage.get_known() == [OTHER_MAC]
    storage.close()


@pytest.mark.skipif(os.geteuid() == 0, reason='file permissions do not apply to root')
def test_read_only_database(tmp_path):
    db_path = str(tmp_path / 'dev-detect.db')
    writer = DatabaseStorage(db_path)
    writer.store(MAC, 'br-lan')
    writer.close()
    os.chmod(db_path, 0o444)

    storage = DatabaseStorage(db_path)
    assert storage.search(MAC)
    with pytest.raises(StorageError, match='readonly'):
        storage.store(OTHER_MAC, 'br-lan')
    assert not storage.conn.in_transaction  # no lock left behind

    os.chmod(db_path, 0o644)
    assert storage.store(OTHER_MAC, 'br-lan')  # connection opened read-only is reopened
    storage.close()


def test_vanished_directory_is_not_recreated(tmp_path):
    """E.g. /srv unmounted while running: do not create a new database on rootfs"""
    directory = tmp_path / 'srv'
    directory.mkdir()
    db_path = directory / 'dev-detect.db'
    storage = DatabaseStorage(str(db_path))
    storage.store(MAC, 'br-lan')
    directory.rename(tmp_path / 'detached')

    with pytest.raises(StorageError):
        storage.search(MAC)
    with pytest.raises(StorageError):
        storage.store(OTHER_MAC, 'br-lan')
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


def create_v0_database(path, macs):
    """Database as created by dev-detect 0.3.1"""
    conn = sqlite3.connect(path)
    conn.execute('CREATE TABLE known_devices (mac text UNIQUE)')
    conn.executemany('INSERT INTO known_devices (mac) VALUES (?)', [(mac,) for mac in macs])
    conn.commit()
    conn.close()


def schema_version(path):
    conn = sqlite3.connect(path)
    try:
        return conn.execute('PRAGMA user_version').fetchone()[0]
    finally:
        conn.close()


def tables(path):
    conn = sqlite3.connect(path)
    try:
        return {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    finally:
        conn.close()


def test_new_database_has_current_schema(tmp_path):
    db_path = str(tmp_path / 'dev-detect.db')
    storage = DatabaseStorage(db_path)
    storage.store(MAC, 'br-lan')

    assert schema_version(db_path) == SCHEMA_VERSION
    assert tables(db_path) == {'devices', 'device_networks'}
    (mac, name, iface, first_seen, last_seen, hostname), = storage.devices()
    assert (mac, iface) == (MAC, 'br-lan')
    assert abs(first_seen - time.time()) < 60
    assert last_seen == first_seen
    storage.close()


def test_old_database_is_upgraded(tmp_path):
    db_path = str(tmp_path / 'dev-detect.db')
    create_v0_database(db_path, [MAC, OTHER_MAC])
    storage = DatabaseStorage(db_path)

    assert storage.search(MAC) and storage.search(OTHER_MAC)
    assert storage.devices() == [(MAC, None, '', None, None, None), (OTHER_MAC, None, '', None, None, None)]
    assert storage.seen(MAC, ('br-lan',)) == Seen(0, 0, True)  # known on every network, as before
    assert schema_version(db_path) == SCHEMA_VERSION
    assert tables(db_path) == {'devices', 'device_networks'}
    storage.close()


@pytest.mark.skipif(os.geteuid() == 0, reason='file permissions do not apply to root')
def test_old_read_only_database_is_still_readable(tmp_path):
    db_path = str(tmp_path / 'dev-detect.db')
    create_v0_database(db_path, [MAC])
    os.chmod(db_path, 0o444)
    storage = DatabaseStorage(db_path)

    assert storage.search(MAC)
    assert storage.seen(MAC, ('br-lan',)) == Seen(0, 0, True)  # known everywhere
    assert storage.seen(OTHER_MAC, ('br-lan',)) is None
    assert storage.devices() == [(MAC, None, '', None, None, None)]
    assert not storage.is_empty()
    with pytest.raises(StorageError, match='cannot be upgraded'):
        storage.store(OTHER_MAC, 'br-lan')

    os.chmod(db_path, 0o644)
    assert storage.store(OTHER_MAC, 'br-lan')  # upgraded once writable
    assert schema_version(db_path) == SCHEMA_VERSION
    assert [row[0] for row in storage.devices()] == [MAC, OTHER_MAC]
    storage.close()


def test_database_of_newer_version_is_not_downgraded(tmp_path):
    db_path = str(tmp_path / 'dev-detect.db')
    DatabaseStorage(db_path).store(MAC, 'br-lan')
    conn = sqlite3.connect(db_path)
    conn.execute('PRAGMA user_version = 99')
    conn.close()

    storage = DatabaseStorage(db_path)
    assert storage.search(MAC)
    assert schema_version(db_path) == 99
    storage.close()


def test_database_of_development_version_is_upgraded(tmp_path):
    """Written by an unreleased version, known_devices with more columns and version 5"""
    db_path = str(tmp_path / 'dev-detect.db')
    conn = sqlite3.connect(db_path)
    conn.execute(
        "CREATE TABLE known_devices (mac TEXT NOT NULL, iface TEXT NOT NULL DEFAULT '', first_seen INTEGER,"
        " hostname TEXT, last_seen INTEGER, name TEXT, PRIMARY KEY (mac, iface))"
    )
    conn.executemany('INSERT INTO known_devices (mac, iface) VALUES (?, ?)', [
        (MAC, 'br-lan'), (MAC, 'br-guest-turris'), (OTHER_MAC, ''),
    ])
    conn.execute('PRAGMA user_version = 5')
    conn.commit()
    conn.close()

    storage = DatabaseStorage(db_path)
    assert storage.seen(MAC, GUEST) == Seen(0, 0, True)  # known everywhere, not reported again
    assert storage.store('02:00:00:00:00:01', 'br-lan')
    assert storage.get_known() == [MAC, OTHER_MAC, '02:00:00:00:00:01']
    assert schema_version(db_path) == SCHEMA_VERSION
    storage.close()


def test_upgrade_by_two_processes(tmp_path):
    """The daemon and the CLI may open an old database at the same time"""
    db_path = str(tmp_path / 'dev-detect.db')
    create_v0_database(db_path, [MAC])
    late = sqlite3.connect(db_path)  # decided to upgrade before the other one committed
    first = DatabaseStorage(db_path)
    first.store(OTHER_MAC, 'br-lan')

    late.execute('BEGIN IMMEDIATE')
    DatabaseStorage._upgrade(late)
    late.commit()
    late.close()

    assert [row[:3] for row in first.devices()] == [(MAC, None, ''), (OTHER_MAC, None, 'br-lan')]
    first.close()


def test_database_restored_from_dump_keeps_its_data(tmp_path):
    """An SQL dump does not contain the schema version"""
    original = DatabaseStorage(str(tmp_path / 'original.db'))
    original.store(MAC, 'br-lan', hostname='Mac')
    original.store(MAC, 'br-guest-turris')
    original.add(OTHER_MAC, 'printer')
    rows = original.devices()
    restored_path = str(tmp_path / 'restored.db')
    restored = sqlite3.connect(restored_path)
    restored.executescript('\n'.join(original.conn.iterdump()))
    restored.close()
    original.close()
    assert schema_version(restored_path) == 0

    storage = DatabaseStorage(restored_path)
    assert storage.devices() == rows
    assert schema_version(restored_path) == SCHEMA_VERSION
    storage.close()


def test_failed_upgrade_is_repeated(tmp_path):
    db_path = str(tmp_path / 'dev-detect.db')
    create_v0_database(db_path, [MAC])
    conn = sqlite3.connect(db_path)
    conn.execute('CREATE TABLE devices (blocking TEXT)')  # makes the upgrade fail
    conn.commit()
    storage = DatabaseStorage(db_path)

    assert storage.search(MAC)  # still readable
    assert storage.seen(MAC, ('br-lan',)) == Seen(0, 0, True)
    with pytest.raises(StorageError, match='cannot be upgraded.*no column named mac'):
        storage.store(OTHER_MAC, 'br-lan')
    conn.execute('DROP TABLE devices')
    conn.commit()
    conn.close()

    assert storage.store(OTHER_MAC, 'br-lan')
    assert storage.seen(MAC, ('br-lan',)) == Seen(0, 0, True)
    assert schema_version(db_path) == SCHEMA_VERSION
    storage.close()


@pytest.fixture
def short_timeout(monkeypatch):
    """Do not wait 5 s for locks held by another connection"""
    connect = sqlite3.connect
    monkeypatch.setattr(sqlite3, 'connect', lambda path, *args, **kwargs: connect(path, timeout=0.1))


def test_old_database_is_readable_while_another_process_locks_it(tmp_path, short_timeout):
    db_path = str(tmp_path / 'dev-detect.db')
    create_v0_database(db_path, [MAC])
    other = sqlite3.connect(db_path, isolation_level=None)
    other.execute('BEGIN IMMEDIATE')  # e.g. an interactive sqlite3 session
    storage = DatabaseStorage(db_path)

    assert storage.search(MAC)
    assert storage.devices() == [(MAC, None, '', None, None, None)]
    with pytest.raises(StorageError, match='cannot be upgraded'):
        storage.store(OTHER_MAC, 'br-lan')

    other.execute('ROLLBACK')
    other.close()
    assert storage.store(OTHER_MAC, 'br-lan')
    assert schema_version(db_path) == SCHEMA_VERSION
    storage.close()


def test_failed_commit_leaves_no_transaction(tmp_path, short_timeout):
    db_path = str(tmp_path / 'dev-detect.db')
    storage = DatabaseStorage(db_path)
    storage.store(MAC, 'br-lan')
    reader = sqlite3.connect(db_path, isolation_level=None)
    reader.execute('BEGIN')
    reader.execute('SELECT * FROM devices').fetchall()  # holds a shared lock

    with pytest.raises(StorageError, match='locked'):
        storage.store(OTHER_MAC, 'br-lan')
    assert not storage.conn.in_transaction

    reader.execute('ROLLBACK')
    reader.close()
    assert not DatabaseStorage(db_path).search(OTHER_MAC)
    storage.store('02:00:00:00:00:01', 'br-lan')
    assert not storage.search(OTHER_MAC)  # the failed write is not committed later
    storage.close()


@pytest.mark.parametrize('damage', ['drop tables', 'old table with current version', 'networks missing'])
def test_damaged_database_is_repaired(tmp_path, damage):
    db_path = str(tmp_path / 'dev-detect.db')
    DatabaseStorage(db_path).store(MAC, 'br-lan')
    conn = sqlite3.connect(db_path)
    conn.execute('DROP TABLE device_networks')
    if damage != 'networks missing':
        conn.execute('DROP TABLE devices')
    if damage == 'old table with current version':
        conn.execute('CREATE TABLE known_devices (mac text UNIQUE)')
        conn.execute("INSERT INTO known_devices (mac) VALUES (?)", (MAC,))
    conn.commit()
    conn.close()

    storage = DatabaseStorage(db_path)
    assert storage.store(OTHER_MAC, 'br-lan')
    assert [row[0] for row in storage.devices()][-1] == OTHER_MAC
    assert tables(db_path) == {'devices', 'device_networks'}
    storage.close()


def test_backup_restored_into_open_database(tmp_path):
    """sqlite3 dev-detect.db '.restore old.db' keeps the file, so the inode stays"""
    db_path = str(tmp_path / 'dev-detect.db')
    storage = DatabaseStorage(db_path)
    storage.store(OTHER_MAC, 'br-lan')
    old_path = str(tmp_path / 'old.db')
    create_v0_database(old_path, [MAC])
    old, target = sqlite3.connect(old_path), sqlite3.connect(db_path)
    old.backup(target)
    old.close()
    target.close()

    assert storage.seen(MAC, ('br-lan',)) == Seen(0, 0, True)
    assert storage.store(OTHER_MAC, 'br-lan')
    assert schema_version(db_path) == SCHEMA_VERSION
    storage.close()


def test_database_replaced_while_being_opened(tmp_path, monkeypatch):
    db_path = str(tmp_path / 'dev-detect.db')
    DatabaseStorage(db_path).store(MAC, 'br-lan')
    replacement = str(tmp_path / 'replacement.db')
    DatabaseStorage(replacement).store(OTHER_MAC, 'br-lan')
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
