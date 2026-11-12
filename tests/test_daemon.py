import os

import pytest

import dev_detect.__main__ as daemon
from dev_detect.storage import DatabaseStorage, StorageError

MAC = '3e:f1:18:4d:d9:23'
OTHER_MAC = 'aa:bb:cc:dd:ee:ff'
IFINDEX = 7
INTERFACES = {IFINDEX: 'br-lan'}


class Message(dict):
    """Minimal stand-in for pyroute2 ndmsg"""
    def __init__(self, mac, ip, family=10, ifindex=IFINDEX):
        super().__init__(family=family, ifindex=ifindex, event='RTM_NEWNEIGH', state=2)
        self.attrs = {'NDA_LLADDR': mac, 'NDA_DST': ip}

    def get_attr(self, name):
        return self.attrs.get(name)


class FailingStorage:
    """Storage that can neither be read nor written, until fixed"""
    def __init__(self, search_fails=False):
        self.search_fails = search_fails
        self.broken = True
        self.macs = set()

    def search(self, mac):
        if self.broken and self.search_fails:
            raise StorageError('/srv/dev-detect/dev-detect.db: SQLITE_IOERR')
        return mac in self.macs

    def store(self, mac):
        if self.broken:
            raise StorageError('/srv/dev-detect/dev-detect.db: SQLITE_READONLY: attempt to write a readonly database')
        self.macs.add(mac)
        return True


@pytest.fixture
def notified(monkeypatch):
    sent = []
    monkeypatch.setattr(daemon, 'new_device_notify', lambda mac, ip, family, iface: sent.append(mac))
    return sent


# every address of a device and every state change produces RTM_NEWNEIGH
EVENTS = [
    Message(MAC, '192.168.1.50', family=2),
    Message(MAC, '2a00:1028:8388:a84e:a1a4:8dbf:7ab8:e5ac'),
    Message(MAC, '2a00:1028:8388:a84e:a1a4:8dbf:7ab8:e5ac'),
    Message(MAC, 'fe80::848:7d4a:60d1:ce7'),
]


def feed(tracker, messages):
    for message in messages:
        daemon.process_netlink_message(message, INTERFACES, tracker)


def test_new_device_is_reported_once(tmp_path, notified):
    tracker = daemon.DeviceTracker(DatabaseStorage(str(tmp_path / 'dev-detect.db')))
    feed(tracker, EVENTS)

    assert notified == [MAC]


def test_messages_without_addresses_are_ignored(tmp_path, notified):
    tracker = daemon.DeviceTracker(DatabaseStorage(str(tmp_path / 'dev-detect.db')))
    feed(tracker, [Message(MAC, None), Message(None, '192.168.1.50', family=2)])

    assert notified == []


@pytest.mark.parametrize('search_fails', [False, True], ids=['read-only', 'unreadable'])
def test_device_is_reported_once_when_it_cannot_be_stored(notified, search_fails):
    tracker = daemon.DeviceTracker(FailingStorage(search_fails))
    feed(tracker, EVENTS + [Message(OTHER_MAC, '192.168.1.51', family=2)] + EVENTS)

    assert notified == [MAC, OTHER_MAC]


def test_unsaved_devices_are_stored_once_database_works(notified):
    storage = FailingStorage()
    tracker = daemon.DeviceTracker(storage)
    feed(tracker, EVENTS)
    storage.broken = False
    feed(tracker, [Message(OTHER_MAC, '192.168.1.51', family=2)] + EVENTS)

    assert notified == [MAC, OTHER_MAC]
    assert storage.macs == {MAC, OTHER_MAC}
    assert not tracker.unsaved


def test_removed_device_is_reported_again(tmp_path, notified):
    """The database is the source of truth, `dev-detect remove` takes effect immediately"""
    db_path = str(tmp_path / 'dev-detect.db')
    tracker = daemon.DeviceTracker(DatabaseStorage(db_path))
    feed(tracker, EVENTS)
    DatabaseStorage(db_path).remove(MAC)
    feed(tracker, EVENTS)

    assert notified == [MAC, MAC]


@pytest.mark.skipif(os.geteuid() == 0, reason='file permissions do not apply to root')
def test_read_only_database_file(tmp_path, notified):
    db_path = str(tmp_path / 'dev-detect.db')
    writer = DatabaseStorage(db_path)
    writer.store(OTHER_MAC)
    writer.close()
    os.chmod(db_path, 0o444)

    tracker = daemon.DeviceTracker(DatabaseStorage(db_path))
    feed(tracker, EVENTS + [Message(OTHER_MAC, '192.168.1.51', family=2)] + EVENTS)

    assert notified == [MAC]


def test_open_storage_creates_directory(tmp_path):
    """E.g. a newly mounted empty disk on /srv"""
    db_path = tmp_path / 'srv' / 'dev-detect' / 'dev-detect.db'
    storage = daemon.open_storage(str(db_path))

    assert storage.store(MAC)
    assert db_path.exists()
    storage.close()


def test_open_storage_logs_when_directory_cannot_be_created(tmp_path, caplog):
    blocker = tmp_path / 'srv'
    blocker.write_text('not a directory')
    storage = daemon.open_storage(str(blocker / 'dev-detect' / 'dev-detect.db'))

    assert 'Cannot create directory' in caplog.text
    with pytest.raises(StorageError):
        storage.search(MAC)
    storage.close()


def test_unsaved_device_is_stored_once_database_works_again(notified, monkeypatch):
    """Even when no other device is stored meanwhile"""
    clock = [1000.0]
    monkeypatch.setattr(daemon.time, 'monotonic', lambda: clock[0])
    storage = FailingStorage()
    attempts = []
    store = storage.store
    storage.store = lambda mac: attempts.append(mac) or store(mac)
    tracker = daemon.DeviceTracker(storage)
    for _ in range(10):  # a device present for 10 minutes
        feed(tracker, EVENTS)
        clock[0] += 60
    storage.broken = False
    for _ in range(10):
        feed(tracker, EVENTS)
        clock[0] += 60

    assert notified == [MAC]
    assert attempts == [MAC] * 3  # when reported, then at most once per UNSAVED_RETRY_INTERVAL
    assert MAC in storage.macs and not tracker.unsaved
