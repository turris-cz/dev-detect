import errno
import logging
import os
import threading

import pytest

import dev_detect.__main__ as daemon
from dev_detect import notify
from dev_detect.storage import DatabaseStorage, StorageError

MAC = '3e:f1:18:4d:d9:23'
OTHER_MAC = 'aa:bb:cc:dd:ee:ff'
IFINDEX = 7
INTERFACES = {IFINDEX: 'br-lan'}


class Message(dict):
    """Minimal stand-in for pyroute2 ndmsg"""
    def __init__(self, mac, ip, family=10, ifindex=IFINDEX, state=2, flags=0):
        super().__init__(family=family, ifindex=ifindex, event='RTM_NEWNEIGH', state=state, flags=flags)
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
    """Notifications sent, each created at once"""
    sent = []

    def new_device_notify(mac, ip, family, iface, on_reported=None):
        sent.append(mac)
        if on_reported:
            on_reported(notify.Device(mac, iface))
    monkeypatch.setattr(daemon, 'new_device_notify', new_device_notify)
    return sent


def failing_tracker(storage, **kwargs):
    return daemon.DeviceTracker(storage, thread_storage=lambda: storage, **kwargs)


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
    tracker = failing_tracker(FailingStorage(search_fails))
    feed(tracker, EVENTS + [Message(OTHER_MAC, '192.168.1.51', family=2)] + EVENTS)

    assert notified == [MAC, OTHER_MAC]


def test_unsaved_devices_are_stored_once_database_works(notified):
    storage = FailingStorage()
    tracker = failing_tracker(storage)
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


class Link(dict):
    """Minimal stand-in for pyroute2 ifinfmsg"""
    def __init__(self, event, index, ifname, family=0):
        super().__init__(event=event, index=index, family=family)
        self.attrs = {'IFLA_IFNAME': ifname}

    def get_attr(self, name):
        return self.attrs.get(name)


class EndOfTest(Exception):
    pass


class FakeIPRoute:
    """Returns given batches of messages from get() (or raises them), then stops the loop"""
    def __init__(self, *batches, links=(), neighbours=()):
        self.batches = list(batches)
        self.links = links
        self.neighbours = neighbours

    def get(self):
        if not self.batches:
            raise EndOfTest
        batch = self.batches.pop(0)
        if isinstance(batch, Exception):
            raise batch
        return batch

    def get_links(self):
        return self.links

    def get_neighbours(self):
        return self.neighbours


def run_detection(tracker, interfaces, *batches, watched=('br-lan', 'br-guest-turris')):
    ipr = FakeIPRoute(*batches)
    with pytest.raises(EndOfTest):
        daemon.detect_devices(ipr, interfaces, watched, tracker, scanner=ipr)


def test_recreated_interface_is_followed(tmp_path, notified):
    """netifd re-creates the bridge with a new index on network restart"""
    tracker = daemon.DeviceTracker(DatabaseStorage(str(tmp_path / 'dev-detect.db')))
    interfaces = {IFINDEX: 'br-lan'}
    run_detection(
        tracker, interfaces,
        [Link('RTM_DELLINK', IFINDEX, 'br-lan')],
        [Link('RTM_NEWLINK', 12, 'br-lan')],
        [Message(MAC, '192.168.1.50', family=2, ifindex=12)],
    )

    assert interfaces == {12: 'br-lan'}
    assert notified == [MAC]


def test_interface_created_later_is_watched(tmp_path, notified):
    tracker = daemon.DeviceTracker(DatabaseStorage(str(tmp_path / 'dev-detect.db')))
    interfaces = {}
    run_detection(
        tracker, interfaces,
        [Message(MAC, '10.111.222.50', family=2, ifindex=9)],
        [Link('RTM_NEWLINK', 9, 'br-guest-turris')],
        [Message(MAC, '10.111.222.50', family=2, ifindex=9)],
    )

    assert interfaces == {9: 'br-guest-turris'}
    assert notified == [MAC]


def test_unrelated_link_messages_are_ignored(tmp_path, notified):
    tracker = daemon.DeviceTracker(DatabaseStorage(str(tmp_path / 'dev-detect.db')))
    interfaces = {IFINDEX: 'br-lan'}
    run_detection(
        tracker, interfaces,
        [Link('RTM_NEWLINK', 3, 'lan1', family=7)],  # bridge port
        [Link('RTM_NEWLINK', 4, 'eth2')],
        [Link('RTM_DELLINK', 3, 'br-lan', family=7)],
        [{'index': 5}],  # message type unknown to pyroute2, without event
    )

    assert interfaces == {IFINDEX: 'br-lan'}


def test_missing_interfaces_are_logged(caplog):
    caplog.set_level(logging.INFO)
    ipr = FakeIPRoute(links=[Link('RTM_NEWLINK', IFINDEX, 'br-lan'), Link('RTM_NEWLINK', 2, 'eth0')])
    interfaces = daemon.get_interfaces(ipr, ('br-lan', 'br-guest-turris'))

    assert interfaces == {IFINDEX: 'br-lan'}
    assert "'br-guest-turris' does not exist" in caplog.text


@pytest.mark.parametrize('message', [
    Message(MAC, None, family=7, ifindex=3),  # bridge FDB entry
    Message('01:00:5e:00:00:16', '224.0.0.22', family=2, state=0x40),  # NOARP multicast
    Message(MAC, '192.168.1.50', family=2, state=0x80),  # static entry
    Message(MAC, '192.168.1.50', family=2, state=0x20),  # FAILED
    Message(MAC, '192.168.1.50', family=2, flags=0x08),  # proxy entry
    Message('33:33:00:00:00:16', 'ff02::16', state=0x04),  # multicast MAC
    Message(MAC, '192.168.1.50', family=2, ifindex=99),  # not watched
], ids=['fdb', 'noarp', 'permanent', 'failed', 'proxy', 'multicast', 'unwatched'])
def test_entries_that_are_not_devices_are_ignored(tmp_path, notified, message):
    tracker = daemon.DeviceTracker(DatabaseStorage(str(tmp_path / 'dev-detect.db')))
    feed(tracker, [message])

    assert notified == []


@pytest.mark.parametrize('state', [0x02, 0x04, 0x08, 0x10], ids=['reachable', 'stale', 'delay', 'probe'])
def test_scan_and_broadcast_accept_the_same_entries(tmp_path, notified, state):
    tracker = daemon.DeviceTracker(DatabaseStorage(str(tmp_path / 'dev-detect.db')))
    ipr = FakeIPRoute(neighbours=[Message(MAC, '192.168.1.50', family=2, state=state)])
    daemon.scan_neighbours(ipr, INTERFACES, tracker)
    feed(tracker, [Message(OTHER_MAC, '192.168.1.51', family=2, state=state)])

    assert notified == [MAC, OTHER_MAC]


ENOBUFS = OSError(errno.ENOBUFS, 'No buffer space available')


def test_lost_messages_are_recovered(tmp_path, notified, caplog, monkeypatch):
    """The kernel reports ENOBUFS when broadcast messages were dropped"""
    monkeypatch.setattr(daemon, 'RESYNC_INTERVAL', 0)
    tracker = daemon.DeviceTracker(DatabaseStorage(str(tmp_path / 'dev-detect.db')))
    interfaces = {IFINDEX: 'br-lan'}
    ipr = FakeIPRoute(ENOBUFS, [Message(OTHER_MAC, '192.168.1.51', family=2, ifindex=12)])
    scanner = FakeIPRoute(
        links=[Link('RTM_NEWLINK', 12, 'br-lan')],  # re-created meanwhile
        neighbours=[Message(MAC, '192.168.1.50', family=2, ifindex=12)],
    )
    with pytest.raises(EndOfTest):
        daemon.detect_devices(ipr, interfaces, ('br-lan',), tracker, scanner)

    assert interfaces == {12: 'br-lan'}
    assert notified == [MAC, OTHER_MAC]
    assert 'messages were lost' in caplog.text


def test_scans_after_lost_messages_are_rate_limited(tmp_path, notified, caplog, monkeypatch):
    """Under a sustained overflow the neighbour table is not scanned in a loop"""
    clock = [1000.0]
    monkeypatch.setattr(daemon.time, 'monotonic', lambda: clock[0])
    tracker = daemon.DeviceTracker(DatabaseStorage(str(tmp_path / 'dev-detect.db')))
    scans = []
    scanner = FakeIPRoute(links=[Link('RTM_NEWLINK', IFINDEX, 'br-lan')])
    scanner.get_neighbours = lambda: scans.append(clock[0]) or [Message(MAC, '192.168.1.50', family=2)]
    # one get() every 10 s, overflows at +10 s, +20 s, +40 s and +50 s
    ipr = FakeIPRoute(ENOBUFS, ENOBUFS, [], ENOBUFS, ENOBUFS, [], [], [])
    original_get = ipr.get

    def get():
        clock[0] += 10
        return original_get()
    ipr.get = get
    with pytest.raises(EndOfTest):
        daemon.detect_devices(ipr, dict(INTERFACES), ('br-lan',), tracker, scanner)

    assert scans == [1030.0, 1060.0]  # RESYNC_INTERVAL after start, then after the previous scan
    assert caplog.text.count('messages were lost') == 2
    assert notified == [MAC]


def test_failed_scan_is_repeated_later(tmp_path, notified, caplog, monkeypatch):
    clock = [1000.0]
    monkeypatch.setattr(daemon.time, 'monotonic', lambda: clock[0])
    tracker = daemon.DeviceTracker(DatabaseStorage(str(tmp_path / 'dev-detect.db')))
    failures = [RuntimeError('dump interrupted')] * 3  # all attempts of the first scan

    def get_links():
        if failures:
            raise failures.pop()
        return [Link('RTM_NEWLINK', IFINDEX, 'br-lan')]
    scanner = FakeIPRoute(neighbours=[Message(MAC, '192.168.1.50', family=2)])
    scanner.get_links = get_links
    ipr = FakeIPRoute(ENOBUFS, [], [], [], [], [], [])
    original_get = ipr.get

    def get():
        clock[0] += 10
        return original_get()
    ipr.get = get
    with pytest.raises(EndOfTest):
        daemon.detect_devices(ipr, dict(INTERFACES), ('br-lan',), tracker, scanner)

    assert 'Neighbour scan failed' in caplog.text
    assert notified == [MAC]  # second scan, RESYNC_INTERVAL after the failed one


def test_scan_is_retried_at_once_when_interrupted(tmp_path, notified):
    """e.g. pyroute2 NetlinkDumpInterrupted when links change during the dump"""
    tracker = daemon.DeviceTracker(DatabaseStorage(str(tmp_path / 'dev-detect.db')))
    failures = [RuntimeError('dump interrupted')]

    def get_links():
        if failures:
            raise failures.pop()
        return [Link('RTM_NEWLINK', IFINDEX, 'br-lan')]
    scanner = FakeIPRoute(neighbours=[Message(MAC, '192.168.1.50', family=2)])
    scanner.get_links = get_links

    assert daemon.synchronize(scanner, {}, ('br-lan',), tracker)
    assert notified == [MAC]


def test_other_netlink_errors_are_raised(tmp_path):
    tracker = daemon.DeviceTracker(DatabaseStorage(str(tmp_path / 'dev-detect.db')))
    ipr = FakeIPRoute(OSError(errno.EBADF, 'Bad file descriptor'))
    with pytest.raises(OSError):
        daemon.detect_devices(ipr, INTERFACES, ('br-lan',), tracker, ipr)


def test_device_is_stored_after_its_notification(tmp_path):
    """In the notification thread, which needs its own connection"""
    db_path = str(tmp_path / 'dev-detect.db')
    tracker = daemon.DeviceTracker(DatabaseStorage(db_path))
    assert tracker.is_new(MAC)
    assert not tracker.is_new(MAC)  # pending
    assert DatabaseStorage(db_path).get_known() == []

    thread = threading.Thread(target=tracker.device_reported, args=(notify.Device(MAC, 'br-lan'),))
    thread.start()
    thread.join()

    assert DatabaseStorage(db_path).get_known() == [MAC]
    assert not tracker.pending
    assert not tracker.is_new(MAC)


def test_device_is_reported_again_when_daemon_stopped_before_notification(tmp_path):
    db_path = str(tmp_path / 'dev-detect.db')
    assert daemon.DeviceTracker(DatabaseStorage(db_path)).is_new(MAC)  # then the daemon stops
    assert daemon.DeviceTracker(DatabaseStorage(db_path)).is_new(MAC)


def test_unsaved_device_is_stored_once_database_works_again(notified, monkeypatch):
    """Even when no other device is stored meanwhile"""
    clock = [1000.0]
    monkeypatch.setattr(daemon.time, 'monotonic', lambda: clock[0])
    storage = FailingStorage()
    attempts = []
    store = storage.store
    storage.store = lambda mac: attempts.append(mac) or store(mac)
    tracker = failing_tracker(storage)
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


@pytest.fixture
def notifications(monkeypatch):
    """Notifications waiting to be created, their callbacks are called by the test"""
    waiting = []

    def new_device_notify(mac, ip, family, iface, on_reported=None):
        waiting.append((notify.Device(mac, iface), on_reported))
    monkeypatch.setattr(daemon, 'new_device_notify', new_device_notify)
    return waiting


def test_device_reported_when_database_cannot_be_read_is_stored_after_its_notification(notifications):
    """Not by storing the devices that could not be stored meanwhile"""
    storage = FailingStorage(search_fails=True)
    stored = []
    store = storage.store
    storage.store = lambda mac: stored.append(mac) or store(mac)
    tracker = failing_tracker(storage)
    feed(tracker, EVENTS)
    storage.broken = False
    feed(tracker, EVENTS + [Message(OTHER_MAC, '192.168.1.51', family=2)])
    (first, on_first), (other, on_other) = notifications

    on_other(other)
    assert stored == [OTHER_MAC]
    on_first(first)
    assert stored == [OTHER_MAC, MAC]
    assert not tracker.pending and not tracker.unsaved


def test_device_is_claimed_once(tmp_path, notified, monkeypatch):
    """E.g. by another thread while the database was read"""
    storage = DatabaseStorage(str(tmp_path / 'dev-detect.db'))
    tracker = daemon.DeviceTracker(storage)
    search = storage.search

    def search_while_claimed(mac):
        tracker.pending.add(mac)
        return search(mac)
    monkeypatch.setattr(storage, 'search', search_while_claimed)

    assert not tracker.is_new(MAC)


def test_reported_device_that_cannot_be_stored_for_unexpected_reason(notified, caplog):
    """It must not become unknown, it would be reported again and again"""
    class BrokenStorage(FailingStorage):
        def store(self, mac):
            raise RuntimeError('unexpected')
    tracker = failing_tracker(BrokenStorage())
    feed(tracker, EVENTS * 2)

    assert notified == [MAC]
    assert not tracker.pending and tracker.unsaved == {MAC}
    assert 'Cannot record device' in caplog.text


@pytest.fixture(autouse=True)
def messages_waiting(monkeypatch):
    """Fake netlink sockets have no file descriptor to wait for, they always have messages"""
    monkeypatch.setattr(daemon, 'wait_for_messages', lambda ipr, timeout: True)


def test_unsaved_device_is_stored_also_when_no_message_comes(notified, monkeypatch):
    """E.g. the device left before the database works again"""
    clock = [1000.0]
    monkeypatch.setattr(daemon.time, 'monotonic', lambda: clock[0])
    storage = FailingStorage()
    tracker = failing_tracker(storage)
    feed(tracker, EVENTS[:1])  # reported, cannot be stored
    storage.broken = False
    timeouts = [False, False]

    def wait_for_messages(ipr, timeout):
        clock[0] += timeout
        if not timeouts:
            raise EndOfTest
        return timeouts.pop()
    monkeypatch.setattr(daemon, 'wait_for_messages', wait_for_messages)
    with pytest.raises(EndOfTest):
        daemon.detect_devices(FakeIPRoute(), {}, ('br-lan',), tracker, FakeIPRoute())

    assert MAC in storage.macs and not tracker.unsaved
