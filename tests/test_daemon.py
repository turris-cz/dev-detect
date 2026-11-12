import errno
import logging
import os
import sqlite3
import sys
import threading
import types

import pytest

import dev_detect.__main__ as daemon
from dev_detect import notify
from dev_detect.storage import DatabaseStorage, Seen, StorageError

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


READONLY = StorageError('/srv/dev-detect/dev-detect.db: SQLITE_READONLY: attempt to write a readonly database')


class FailingStorage:
    """Storage that cannot be written (nor read with read_fails), until fixed"""
    def __init__(self, read_fails=False):
        self.read_fails = read_fails
        self.broken = True
        self.networks = {}  # mac -> interfaces
        self.stored = []
        self.details = {}  # mac -> (name, hostname)
        self.touched = []

    def seen(self, mac, ifaces, per_network=True):
        if self.broken and self.read_fails:
            raise StorageError('/srv/dev-detect/dev-detect.db: SQLITE_IOERR')
        if mac not in self.networks or per_network and not self.networks[mac] & set(ifaces):
            return None
        return Seen(0, 0, False)

    def touch(self, mac, ifaces):
        self.touched.append(mac)
        if self.broken:
            raise READONLY

    def store(self, mac, iface, name=None, hostname=None, aliases=()):
        if self.broken:
            raise READONLY
        self.networks.setdefault(mac, set()).add(iface)
        self.stored.append((mac, iface))
        if name or hostname or mac not in self.details:
            self.details[mac] = (name, hostname)
        return True


@pytest.fixture
def notified(monkeypatch):
    """Notifications sent, each created at once"""
    sent = []

    def new_device_notify(mac, ip, family, iface, on_reported=None, away=None):
        sent.append(mac if away is None else (mac, int(away // daemon.DAY)))  # days of a device that came back
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


@pytest.mark.parametrize('read_fails', [False, True], ids=['read-only', 'unreadable'])
def test_device_is_reported_once_when_it_cannot_be_stored(notified, read_fails):
    tracker = failing_tracker(FailingStorage(read_fails))
    feed(tracker, EVENTS + [Message(OTHER_MAC, '192.168.1.51', family=2)] + EVENTS)

    assert notified == [MAC, OTHER_MAC]


def test_unsaved_devices_are_stored_once_database_works(notified):
    storage = FailingStorage()
    tracker = failing_tracker(storage)
    feed(tracker, EVENTS)
    storage.broken = False
    feed(tracker, [Message(OTHER_MAC, '192.168.1.51', family=2)] + EVENTS)

    assert notified == [MAC, OTHER_MAC]
    assert sorted(storage.stored) == [(MAC, 'br-lan'), (OTHER_MAC, 'br-lan')]  # with the interface
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
    writer.store(OTHER_MAC, 'br-lan')
    writer.close()
    os.chmod(db_path, 0o444)

    tracker = daemon.DeviceTracker(DatabaseStorage(db_path))
    feed(tracker, EVENTS + [Message(OTHER_MAC, '192.168.1.51', family=2)] + EVENTS)

    assert notified == [MAC]


def test_open_storage_creates_directory(tmp_path):
    """E.g. a newly mounted empty disk on /srv"""
    db_path = tmp_path / 'srv' / 'dev-detect' / 'dev-detect.db'
    storage = daemon.open_storage(str(db_path))

    assert storage.store(MAC, 'br-lan')
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
    assert tracker.is_new(MAC, 'br-lan')
    assert not tracker.is_new(MAC, 'br-lan')  # pending
    assert DatabaseStorage(db_path).devices() == []
    device = notify.Device(MAC, 'br-lan')
    device.hostname = 'Mac'

    thread = threading.Thread(target=tracker.device_reported, args=(device,))
    thread.start()
    thread.join()

    assert [(row[0], row[2], row[5]) for row in DatabaseStorage(db_path).devices()] == [(MAC, 'br-lan', 'Mac')]
    assert not tracker.pending
    assert not tracker.is_new(MAC, 'br-lan')


def test_device_is_reported_again_when_daemon_stopped_before_notification(tmp_path):
    db_path = str(tmp_path / 'dev-detect.db')
    assert daemon.DeviceTracker(DatabaseStorage(db_path)).is_new(MAC, 'br-lan')  # then the daemon stops
    assert daemon.DeviceTracker(DatabaseStorage(db_path)).is_new(MAC, 'br-lan')


@pytest.fixture
def clock(monkeypatch):
    """Wall clock and monotonic clock, moved by the test"""
    now = [1700000000.0]
    monkeypatch.setattr(daemon.time, 'time', lambda: now[0])
    monkeypatch.setattr(daemon.time, 'monotonic', lambda: now[0])
    return now


def recorded_touches(storage, clock):
    touched = []
    original_touch = storage.touch

    def touch(mac, ifaces):
        touched.append(clock[0])
        original_touch(mac, ifaces)
    storage.touch = touch
    return touched


def test_last_seen_is_written_at_most_once_per_interval(tmp_path, clock):
    storage = DatabaseStorage(str(tmp_path / 'dev-detect.db'))
    storage.store(MAC, 'br-lan')
    touched = recorded_touches(storage, clock)
    tracker = daemon.DeviceTracker(storage)

    for _ in range(3):
        assert not tracker.is_new(MAC, 'br-lan')
        clock[0] += 60
    clock[0] += daemon.LAST_SEEN_INTERVAL
    assert not tracker.is_new(MAC, 'br-lan')
    assert not tracker.is_new(MAC, 'br-lan')

    assert touched == [1700000180.0 + daemon.LAST_SEEN_INTERVAL]
    assert [row[4] for row in storage.devices()] == [1700000180 + daemon.LAST_SEEN_INTERVAL]


def test_last_seen_is_not_written_again_after_restart(tmp_path, clock):
    """The interval is counted from the stored time, not from the start of the daemon"""
    db_path = str(tmp_path / 'dev-detect.db')
    DatabaseStorage(db_path).store(MAC, 'br-lan')
    clock[0] += 3600
    storage = DatabaseStorage(db_path)
    touched = recorded_touches(storage, clock)

    assert not daemon.DeviceTracker(storage).is_new(MAC, 'br-lan')
    assert touched == []


def test_failed_last_seen_write_is_not_repeated_at_once(clock):
    storage = FailingStorage()
    storage.networks[MAC] = {'br-lan'}
    tracker = failing_tracker(storage)

    for _ in range(3):
        assert not tracker.is_new(MAC, 'br-lan')
    clock[0] += daemon.LAST_SEEN_INTERVAL
    assert not tracker.is_new(MAC, 'br-lan')

    assert storage.touched == [MAC, MAC]


def test_last_seen_is_written_only_when_presence_is_confirmed(tmp_path, clock):
    """Entries of departed devices stay STALE in the neighbour table for long"""
    storage = DatabaseStorage(str(tmp_path / 'dev-detect.db'))
    storage.store(MAC, 'br-lan')
    clock[0] += daemon.LAST_SEEN_INTERVAL
    touched = recorded_touches(storage, clock)
    tracker = daemon.DeviceTracker(storage)
    feed(tracker, [Message(MAC, '192.168.1.50', family=2, state=0x04)])  # STALE
    assert touched == []
    feed(tracker, [Message(MAC, '192.168.1.50', family=2, state=0x02)])  # REACHABLE
    assert touched == [clock[0]]


def test_network_of_device_known_everywhere_is_recorded(tmp_path, notified):
    storage = DatabaseStorage(str(tmp_path / 'dev-detect.db'))
    storage.add(MAC, 'laptop')
    feed(daemon.DeviceTracker(storage, per_network=True), EVENTS)

    assert [row[:3] for row in storage.devices()] == [(MAC, 'laptop', ''), (MAC, 'laptop', 'br-lan')]
    assert notified == []


@pytest.fixture
def learned(monkeypatch):
    devices = []
    monkeypatch.setattr(daemon.notify, 'learned_devices', devices.extend)
    return devices


def start(tracker, *neighbours):
    """What main() does before waiting for broadcast messages"""
    tracker.start_learning()
    ipr = FakeIPRoute(links=[Link('RTM_NEWLINK', IFINDEX, 'br-lan')], neighbours=list(neighbours))
    daemon.synchronize(ipr, {}, ('br-lan',), tracker)


def test_devices_present_at_start_with_empty_database_are_learned(tmp_path, notified, learned):
    tracker = daemon.DeviceTracker(DatabaseStorage(str(tmp_path / 'dev-detect.db')))
    start(tracker, Message(MAC, '192.168.1.50', family=2), Message(OTHER_MAC, '192.168.1.51', family=2))
    feed(tracker, [Message('02:00:00:00:00:99', '192.168.1.99', family=2)])

    assert learned == [(MAC, ['br-lan'], None), (OTHER_MAC, ['br-lan'], None)]
    assert notified == ['02:00:00:00:00:99']
    assert tracker.storage.search(MAC) and tracker.storage.search(OTHER_MAC)


def test_nothing_is_learned_with_known_devices(tmp_path, notified, learned):
    storage = DatabaseStorage(str(tmp_path / 'dev-detect.db'))
    storage.store(MAC, 'br-lan')
    tracker = daemon.DeviceTracker(storage)
    start(tracker, Message(MAC, '192.168.1.50', family=2), Message(OTHER_MAC, '192.168.1.51', family=2))

    assert learned == []
    assert notified == [OTHER_MAC]


class ConfigEUci:
    """Stand-in for euci.EUci with given dev-detect options, defaults otherwise"""
    def __init__(self, **options):
        self.options = options

    def get(self, config, section, option, dtype=str, default=None, list=False):
        assert config == 'dev-detect'
        return self.options.get(option, default)


def test_config_defaults():
    config = daemon.read_config(ConfigEUci())

    assert config == {
        'db_path': '/srv/dev-detect/dev-detect.db',
        'interfaces': ('br-lan', 'br-guest-turris', 'br-guest_turris'),
        'learn_on_empty': True,
        'known_static_leases': True,
        'per_network': True,
        'forget_after': 0,
    }
    assert not daemon.read_config(ConfigEUci(learn_on_empty=False))['learn_on_empty']


def test_hostnames_of_learned_devices_are_stored(tmp_path, notified, learned, monkeypatch):
    leases = tmp_path / 'dhcp.leases'
    leases.write_text('1731440000 3e:f1:18:4d:d9:23 192.168.1.50 Mac 01:3e:f1:18:4d:d9:23\n')
    monkeypatch.setattr(notify, 'DNSMASQ_LEASES', str(leases))
    tracker = daemon.DeviceTracker(DatabaseStorage(str(tmp_path / 'dev-detect.db')))
    start(tracker, Message(MAC, '192.168.1.50', family=2), Message(OTHER_MAC, '192.168.1.51', family=2))

    assert learned == [(MAC, ['br-lan'], 'Mac'), (OTHER_MAC, ['br-lan'], None)]
    assert [(row[0], row[5]) for row in tracker.storage.devices()] == [(MAC, 'Mac'), (OTHER_MAC, None)]


class DhcpEUci:
    """Stand-in for euci.EUci with static leases in /etc/config/dhcp"""
    reads = 0
    sections = {
        'dnsmasq': ('dnsmasq', {'domain': 'lan'}),
        'printer': ('host', {'mac': '02:00:00:00:00:01', 'name': 'printer', 'ip': '192.168.1.200'}),
        'cfg0a1b2c': ('host', {'mac': ('AA:BB:CC:DD:EE:FF',)}),
        'tv': ('host', {'mac': '02:00:00:00:00:02 02-00-00-00-00-03', 'name': 'tv'}),
    }

    def __enter__(self):
        DhcpEUci.reads += 1
        return self

    def __exit__(self, *exc):
        return False

    def get(self, config, section=None, option=None, default=None, **kwargs):
        assert config == 'dhcp'
        if section is None:
            return {name: options for name, (_, options) in self.sections.items()}
        return self.sections[section][0]


@pytest.fixture
def dhcp(monkeypatch, tmp_path):
    DhcpEUci.reads = 0
    monkeypatch.setitem(sys.modules, 'euci', types.SimpleNamespace(EUci=DhcpEUci))
    monkeypatch.setattr(daemon, 'DHCP_CONFIG', str(tmp_path / 'dhcp'))  # missing: read every time
    monkeypatch.setattr(daemon, '_static_leases', (None, {}))
    return DhcpEUci


@pytest.mark.parametrize('mac, name', [
    ('02:00:00:00:00:01', 'printer'),
    ('aa:bb:cc:dd:ee:ff', ''),
    ('02:00:00:00:00:03', 'tv'),
    ('02:00:00:00:00:04', None),
])
def test_static_lease(dhcp, mac, name):
    assert daemon.static_lease(mac) == name


def test_static_leases_are_read_again_only_after_change(tmp_path, dhcp):
    config = tmp_path / 'dhcp'
    config.write_text("config host 'printer'\n")
    assert daemon.static_lease('02:00:00:00:00:01') == 'printer'
    assert daemon.static_lease('02:00:00:00:00:04') is None
    assert dhcp.reads == 1

    config.write_text("config host 'printer'\nconfig host 'tv'\n")
    assert daemon.static_lease('02:00:00:00:00:02') == 'tv'
    assert dhcp.reads == 2


def change_dhcp_config(config, monkeypatch, **sections):
    """Write /etc/config/dhcp with other host sections, as uci commit does: a new file renamed over it"""
    monkeypatch.setattr(DhcpEUci, 'sections', sections)
    new = config.with_name('.dhcp.uci-new')
    new.write_text(''.join("config host '{}'\n".format(name) for name in sections) + '# ' + str(sections))
    new.replace(config)


def test_removed_static_lease_is_not_known(tmp_path, dhcp, monkeypatch):
    config = tmp_path / 'dhcp'
    change_dhcp_config(config, monkeypatch, printer=('host', {'mac': '02:00:00:00:00:01', 'name': 'printer'}))
    assert daemon.static_lease('02:00:00:00:00:01') == 'printer'

    change_dhcp_config(config, monkeypatch)
    assert daemon.static_lease('02:00:00:00:00:01') is None


def test_changed_mac_of_static_lease(tmp_path, dhcp, monkeypatch):
    config = tmp_path / 'dhcp'
    change_dhcp_config(config, monkeypatch, printer=('host', {'mac': '02:00:00:00:00:01', 'name': 'printer'}))
    assert daemon.static_lease('02:00:00:00:00:01') == 'printer'

    change_dhcp_config(config, monkeypatch, printer=('host', {'mac': '02:00:00:00:00:09', 'name': 'printer'}))
    assert daemon.static_lease('02:00:00:00:00:01') is None
    assert daemon.static_lease('02:00:00:00:00:09') == 'printer'


def test_mac_in_more_static_leases(tmp_path, dhcp, monkeypatch):
    change_dhcp_config(tmp_path / 'dhcp', monkeypatch, printer=('host', {'mac': '02:00:00:00:00:01', 'name': 'printer'}),
                       copy=('host', {'mac': '02-00-00-00-00-01', 'name': 'copy'}))

    assert daemon.static_lease('02:00:00:00:00:01') == 'printer'  # the first one, like dnsmasq


@pytest.mark.parametrize('options', [
    {'enable': '0'}, {'enable': 'no'}, {'enable': 'off'}, {'enable': 'false'}, {'enable': 'disabled'}, {'ip': 'ignore'},
])
def test_disabled_or_blocking_host_is_not_a_static_lease(tmp_path, dhcp, monkeypatch, options):
    """dnsmasq skips a disabled host, and ip 'ignore' blocks the device from DHCP"""
    change_dhcp_config(tmp_path / 'dhcp', monkeypatch,
                       printer=('host', dict(options, mac='02:00:00:00:00:01', name='printer')),
                       tv=('host', {'mac': '02:00:00:00:00:03', 'name': 'tv', 'enable': '1'}))

    assert daemon.static_lease('02:00:00:00:00:01') is None
    assert daemon.static_lease('02:00:00:00:00:03') == 'tv'


def test_static_leases_are_read_again_after_failure(tmp_path, dhcp, monkeypatch, caplog):
    config = tmp_path / 'dhcp'
    change_dhcp_config(config, monkeypatch, printer=('host', {'mac': '02:00:00:00:00:01', 'name': 'printer'}))
    tracker = daemon.DeviceTracker(DatabaseStorage(str(tmp_path / 'dev-detect.db')), known_static_leases=True)

    def broken(*args, **kwargs):
        raise RuntimeError('uci is broken')
    get = DhcpEUci.get
    monkeypatch.setattr(DhcpEUci, 'get', broken)
    assert tracker._static_lease('02:00:00:00:00:01') is None
    assert 'Cannot read static DHCP leases' in caplog.text

    monkeypatch.setattr(DhcpEUci, 'get', get)  # works again, the file did not change
    assert tracker._static_lease('02:00:00:00:00:01') == 'printer'


def test_devices_with_static_lease_are_known(tmp_path, notified, dhcp):
    storage = DatabaseStorage(str(tmp_path / 'dev-detect.db'))
    tracker = daemon.DeviceTracker(storage, known_static_leases=True)
    feed(tracker, [Message('02:00:00:00:00:01', '192.168.1.200', family=2)] * 3 + EVENTS)

    assert notified == [MAC]
    assert [(row[0], row[1]) for row in storage.devices()] == [('02:00:00:00:00:01', 'printer'), (MAC, None)]
    assert dhcp.reads == 2  # only for unknown devices


def test_static_leases_can_be_reported(tmp_path, notified, dhcp):
    tracker = daemon.DeviceTracker(DatabaseStorage(str(tmp_path / 'dev-detect.db')), known_static_leases=False)
    feed(tracker, [Message('02:00:00:00:00:01', '192.168.1.200', family=2)])

    assert notified == ['02:00:00:00:00:01']
    assert dhcp.reads == 0


GUEST_IFINDEX = 9
BOTH_NETWORKS = {IFINDEX: 'br-lan', GUEST_IFINDEX: 'br-guest-turris'}


def feed_networks(tracker, messages):
    for message in messages:
        daemon.process_netlink_message(message, BOTH_NETWORKS, tracker)


@pytest.mark.parametrize('per_network, expected', [(True, [MAC, MAC]), (False, [MAC])])
def test_device_moving_to_another_network(tmp_path, notified, per_network, expected):
    """E.g. a device of a guest getting into the private network"""
    storage = DatabaseStorage(str(tmp_path / 'dev-detect.db'))
    tracker = daemon.DeviceTracker(storage, per_network=per_network)
    feed_networks(tracker, [Message(MAC, '10.111.222.50', family=2, ifindex=GUEST_IFINDEX)] * 2)
    feed_networks(tracker, [Message(MAC, '192.168.1.50', family=2, ifindex=IFINDEX)] * 2)

    assert notified == expected


def test_device_known_everywhere_is_not_reported_on_any_network(tmp_path, notified):
    """Added by `dev-detect add` or stored by an older version"""
    storage = DatabaseStorage(str(tmp_path / 'dev-detect.db'))
    storage.add(MAC)
    tracker = daemon.DeviceTracker(storage, per_network=True)
    feed_networks(tracker, [
        Message(MAC, '10.111.222.50', family=2, ifindex=GUEST_IFINDEX),
        Message(MAC, '192.168.1.50', family=2, ifindex=IFINDEX),
    ])

    assert notified == []


def test_per_network_device_is_reported_once_per_network_without_database(notified):
    tracker = failing_tracker(FailingStorage(), per_network=True)
    feed_networks(tracker, [Message(MAC, '10.111.222.50', family=2, ifindex=GUEST_IFINDEX)] * 2)
    feed_networks(tracker, [Message(MAC, '192.168.1.50', family=2, ifindex=IFINDEX)] * 2)

    assert notified == [MAC, MAC]


@pytest.mark.skipif(os.geteuid() == 0, reason='file permissions do not apply to root')
def test_read_only_database_of_older_version(tmp_path, notified):
    """A database of dev-detect 0.3.1 that is read-only when the daemon starts"""
    db_path = str(tmp_path / 'dev-detect.db')
    conn = sqlite3.connect(db_path)
    conn.execute('CREATE TABLE known_devices (mac text UNIQUE)')
    conn.executemany('INSERT INTO known_devices (mac) VALUES (?)', [(MAC,), (OTHER_MAC,)])
    conn.commit()
    conn.close()
    os.chmod(db_path, 0o444)

    config = daemon.read_config(ConfigEUci())  # defaults
    tracker = daemon.DeviceTracker(DatabaseStorage(db_path), False, config['per_network'])
    feed_networks(tracker, [
        Message(MAC, '192.168.1.50', family=2, ifindex=IFINDEX),
        Message(OTHER_MAC, '10.111.222.51', family=2, ifindex=GUEST_IFINDEX),
    ] * 3 + [Message('02:00:00:00:00:99', '192.168.1.99', family=2, ifindex=IFINDEX)] * 3)

    assert notified == ['02:00:00:00:00:99']


def test_both_guest_bridge_names_are_one_network(tmp_path, notified):
    """reForis renames br-guest_turris of migrated systems to br-guest-turris"""
    storage = DatabaseStorage(str(tmp_path / 'dev-detect.db'))
    storage.store(MAC, 'br-guest_turris')
    tracker = daemon.DeviceTracker(storage, per_network=True)
    feed_networks(tracker, [Message(MAC, '10.111.222.50', family=2, ifindex=GUEST_IFINDEX)])

    assert notified == []


def test_learned_devices_are_grouped_and_their_hostnames_stored(tmp_path, notified, learned, monkeypatch):
    leases = tmp_path / 'dhcp.leases'
    leases.write_text('1731440000 3e:f1:18:4d:d9:23 192.168.1.50 Mac 01:3e:f1:18:4d:d9:23\n')
    monkeypatch.setattr(notify, 'DNSMASQ_LEASES', str(leases))
    tracker = daemon.DeviceTracker(DatabaseStorage(str(tmp_path / 'dev-detect.db')), per_network=True)
    tracker.start_learning()
    ipr = FakeIPRoute(
        links=[Link('RTM_NEWLINK', IFINDEX, 'br-lan'), Link('RTM_NEWLINK', GUEST_IFINDEX, 'br-guest-turris')],
        neighbours=[
            Message(MAC, '192.168.1.50', family=2, ifindex=IFINDEX),
            Message(MAC, '10.111.222.50', family=2, ifindex=GUEST_IFINDEX, state=0x04),
            Message(OTHER_MAC, '192.168.1.51', family=2, ifindex=IFINDEX),
        ],
    )
    daemon.synchronize(ipr, {}, ('br-lan', 'br-guest-turris'), tracker)

    assert learned == [(MAC, ['br-lan', 'br-guest-turris'], 'Mac'), (OTHER_MAC, ['br-lan'], None)]
    assert {(row[0], row[2], row[5]) for row in tracker.storage.devices()} == {
        (MAC, 'br-lan', 'Mac'), (MAC, 'br-guest-turris', 'Mac'), (OTHER_MAC, 'br-lan', None),
    }
    assert notified == []


LAN = Message(MAC, '192.168.1.50', family=2)
GUEST = Message(MAC, '10.111.222.50', family=2, ifindex=GUEST_IFINDEX)
STATIC = Message('02:00:00:00:00:01', '192.168.1.200', family=2)


@pytest.mark.parametrize('stored, messages, writes', [
    ([], EVENTS * 3, 1),  # stored once its notification was created, with the hostname
    ([(MAC, 'br-lan')], EVENTS * 3, 0),  # new addresses and state changes of a known device
    ([(MAC, 'br-lan')], [GUEST] * 3, 1),  # first time on another network
    ([(MAC, 'br-guest_turris')], [GUEST] * 3, 0),  # renamed guest bridge
    ([], [STATIC] * 3, 1),  # static DHCP lease, stored with its name
    ([(MAC, 'br-lan'), (OTHER_MAC, 'br-lan')], [LAN, Message(OTHER_MAC, '192.168.1.51', family=2)], 0),  # restart
], ids=['new', 'known', 'other network', 'renamed bridge', 'static lease', 'restart'])
def test_database_writes(tmp_path, notified, commits, dhcp, stored, messages, writes):
    """Every write wears out the internal flash a bit"""
    storage = DatabaseStorage(str(tmp_path / 'dev-detect.db'))
    for mac, iface in stored:
        storage.store(mac, iface)
    storage.is_empty()  # creates the database
    tracker = daemon.DeviceTracker(storage, known_static_leases=True, per_network=True)
    del commits[:]

    feed_networks(tracker, messages)

    assert len(commits) == writes


def test_database_writes_of_known_device_over_a_day(tmp_path, notified, commits, clock):
    storage = DatabaseStorage(str(tmp_path / 'dev-detect.db'))
    storage.store(MAC, 'br-lan')
    tracker = daemon.DeviceTracker(storage, per_network=True)
    del commits[:]

    for _ in range(24 * 60):  # every minute
        feed(tracker, [LAN])
        clock[0] += 60

    assert len(commits) == 3  # last seen 6, 12 and 18 hours after it was stored


def test_unsaved_devices_keep_their_names(notified, dhcp):
    """Name of the static DHCP lease and hostname from the notification"""
    storage = FailingStorage()
    tracker = failing_tracker(storage, known_static_leases=True)
    feed(tracker, [STATIC])
    device = notify.Device(MAC, 'br-lan')
    device.hostname = 'Mac'
    assert tracker.is_new(MAC, 'br-lan')
    tracker.device_reported(device)
    storage.broken = False
    feed(tracker, [Message(OTHER_MAC, '192.168.1.51', family=2)])

    assert storage.details == {'02:00:00:00:00:01': ('printer', None), MAC: (None, 'Mac'), OTHER_MAC: (None, None)}
    assert not tracker.unsaved


def test_interface_of_device_known_everywhere_is_recorded_as_is(tmp_path, notified, clock):
    """br-guest_turris on systems migrated from Turris OS 5"""
    storage = DatabaseStorage(str(tmp_path / 'dev-detect.db'))
    storage.add(MAC)
    tracker = daemon.DeviceTracker(storage, per_network=True)
    daemon.process_netlink_message(GUEST, {GUEST_IFINDEX: 'br-guest_turris'}, tracker)
    clock[0] += daemon.LAST_SEEN_INTERVAL
    daemon.process_netlink_message(GUEST, {GUEST_IFINDEX: 'br-guest-turris'}, tracker)  # renamed meanwhile

    assert [row[2:5] for row in storage.devices()] == [
        ('', None, None), ('br-guest_turris', 1700000000, 1700000000 + daemon.LAST_SEEN_INTERVAL),
    ]
    assert notified == []


def test_guest_bridge_renamed_while_database_does_not_work(notified):
    tracker = failing_tracker(FailingStorage(), per_network=True)
    daemon.process_netlink_message(GUEST, {GUEST_IFINDEX: 'br-guest_turris'}, tracker)
    daemon.process_netlink_message(GUEST, {GUEST_IFINDEX: 'br-guest-turris'}, tracker)

    assert notified == [MAC]


@pytest.fixture
def notifications(monkeypatch):
    """Notifications waiting to be created, their callbacks are called by the test"""
    waiting = []

    def new_device_notify(mac, ip, family, iface, on_reported=None, away=None):
        waiting.append((notify.Device(mac, iface), on_reported))
    monkeypatch.setattr(daemon, 'new_device_notify', new_device_notify)
    return waiting


@pytest.mark.skipif(os.geteuid() == 0, reason='file permissions do not apply to root')
def test_unsaved_device_is_stored_once_database_works_again(tmp_path, notified, clock, commits):
    """Even when no other device is stored meanwhile"""
    db_path = str(tmp_path / 'dev-detect.db')
    DatabaseStorage(db_path).store(OTHER_MAC, 'br-lan')
    os.chmod(db_path, 0o444)
    tracker = daemon.DeviceTracker(DatabaseStorage(db_path), per_network=True)
    attempts = []
    store = tracker.storage.store
    tracker.storage.store = lambda *args, **kwargs: attempts.append(args[0]) or store(*args, **kwargs)
    for _ in range(10):  # a device present for 10 minutes
        feed(tracker, [LAN])
        clock[0] += 60
    assert notified == [MAC]
    assert MAC in [key[0] for key in tracker.unsaved]
    assert attempts == [MAC]  # at most once per UNSAVED_RETRY_INTERVAL

    os.chmod(db_path, 0o644)
    del commits[:]
    for _ in range(10):
        feed(tracker, [LAN])
        clock[0] += 60

    assert len(commits) == 1
    assert not tracker.unsaved
    assert not daemon.DeviceTracker(DatabaseStorage(db_path), per_network=True).is_new(MAC, 'br-lan')


@pytest.mark.skipif(os.geteuid() == 0, reason='file permissions do not apply to root')
def test_unsaved_devices_are_stored_with_presence_of_another(tmp_path, notified, clock):
    db_path = str(tmp_path / 'dev-detect.db')
    DatabaseStorage(db_path).store(OTHER_MAC, 'br-lan')
    os.chmod(db_path, 0o444)
    tracker = daemon.DeviceTracker(DatabaseStorage(db_path), per_network=True)
    feed(tracker, [LAN])  # reported, cannot be stored, and leaves
    os.chmod(db_path, 0o644)
    clock[0] += daemon.LAST_SEEN_INTERVAL
    feed(tracker, [Message(OTHER_MAC, '192.168.1.51', family=2)])  # its presence is recorded

    assert not tracker.unsaved
    assert DatabaseStorage(db_path).search(MAC)


def test_device_reported_when_database_cannot_be_read_is_stored_after_its_notification(notifications):
    """Not by storing the devices that could not be stored meanwhile"""
    storage = FailingStorage(read_fails=True)
    tracker = failing_tracker(storage)
    feed(tracker, [LAN])
    storage.broken = False
    feed(tracker, [LAN, Message(OTHER_MAC, '192.168.1.51', family=2)])
    (first, on_first), (other, on_other) = notifications

    on_other(other)
    assert storage.stored == [(OTHER_MAC, 'br-lan')]
    on_first(first)
    assert storage.stored == [(OTHER_MAC, 'br-lan'), (MAC, 'br-lan')]
    assert not tracker.pending and not tracker.unsaved


def test_presence_is_recorded_on_every_network_without_per_network(tmp_path, notified, clock):
    storage = DatabaseStorage(str(tmp_path / 'dev-detect.db'))
    storage.store(MAC, 'br-lan')
    tracker = daemon.DeviceTracker(storage, per_network=False)
    clock[0] += daemon.LAST_SEEN_INTERVAL
    feed_networks(tracker, [LAN])
    clock[0] += 3600
    feed_networks(tracker, [GUEST])

    assert [row[2:5] for row in storage.devices()] == [
        ('br-lan', 1700000000, 1700000000 + daemon.LAST_SEEN_INTERVAL),
        ('br-guest-turris', 1700003600 + daemon.LAST_SEEN_INTERVAL, 1700003600 + daemon.LAST_SEEN_INTERVAL),
    ]
    assert notified == []


def test_learning_waits_for_a_complete_scan(tmp_path, notified, learned, monkeypatch):
    """The startup scan can fail, e.g. while interfaces are created at boot"""
    monkeypatch.setattr(daemon, 'RESYNC_INTERVAL', 0)
    tracker = daemon.DeviceTracker(DatabaseStorage(str(tmp_path / 'dev-detect.db')))
    tracker.start_learning()
    failures = [RuntimeError('dump interrupted')] * 3

    def get_links():
        if failures:
            raise failures.pop()
        return [Link('RTM_NEWLINK', IFINDEX, 'br-lan')]
    scanner = FakeIPRoute(neighbours=[LAN, Message(OTHER_MAC, '192.168.1.51', family=2)])
    scanner.get_links = get_links
    assert not daemon.synchronize(scanner, {}, ('br-lan',), tracker)

    with pytest.raises(EndOfTest):
        daemon.detect_devices(FakeIPRoute([]), {}, ('br-lan',), tracker, scanner, sync_needed=True)

    assert learned == [(MAC, ['br-lan'], None), (OTHER_MAC, ['br-lan'], None)]
    assert notified == []


def test_renamed_guest_bridge_is_stored_once(tmp_path, notified, monkeypatch):
    """A device on the renamed bridge is reported when the database cannot be read"""
    storage = DatabaseStorage(str(tmp_path / 'dev-detect.db'))
    storage.store(MAC, 'br-guest_turris')
    tracker = daemon.DeviceTracker(storage, per_network=True, thread_storage=lambda: storage)
    seen = storage.seen
    failures = [StorageError('/srv/dev-detect/dev-detect.db: SQLITE_BUSY: database is locked')]

    def failing_seen(*args):
        if failures:
            raise failures.pop()
        return seen(*args)
    monkeypatch.setattr(storage, 'seen', failing_seen)
    daemon.process_netlink_message(GUEST, {GUEST_IFINDEX: 'br-guest-turris'}, tracker)

    assert notified == [MAC]
    assert [row[2] for row in storage.devices()] == ['br-guest_turris']


def test_device_is_claimed_once(tmp_path, notified, monkeypatch):
    """E.g. by another thread while the database was read"""
    storage = DatabaseStorage(str(tmp_path / 'dev-detect.db'))
    tracker = daemon.DeviceTracker(storage)
    seen = storage.seen

    def seen_while_claimed(*args):
        tracker.pending[MAC] = (MAC, 'br-lan')
        return seen(*args)
    monkeypatch.setattr(storage, 'seen', seen_while_claimed)

    assert not tracker.is_new(MAC, 'br-lan')


def test_reported_device_that_cannot_be_stored_for_unexpected_reason(notified, caplog):
    """It must not become unknown, it would be reported again and again"""
    class BrokenStorage(FailingStorage):
        def store(self, *args, **kwargs):
            raise RuntimeError('unexpected')
    tracker = failing_tracker(BrokenStorage(), per_network=True)
    feed(tracker, EVENTS * 2)

    assert notified == [MAC]
    assert not tracker.pending and list(tracker.unsaved) == [(MAC, 'br-lan')]
    assert 'Cannot record device' in caplog.text


def test_device_removed_while_pending_is_stored_after_its_notification(tmp_path, notifications):
    db_path = str(tmp_path / 'dev-detect.db')
    tracker = daemon.DeviceTracker(DatabaseStorage(db_path))
    feed(tracker, [LAN])
    assert not DatabaseStorage(db_path).remove(MAC)  # not stored yet
    (device, on_reported), = notifications
    on_reported(device)

    assert DatabaseStorage(db_path).search(MAC)


@pytest.fixture(autouse=True)
def messages_waiting(monkeypatch):
    """Fake netlink sockets have no file descriptor to wait for, they always have messages"""
    monkeypatch.setattr(daemon, 'wait_for_messages', lambda ipr, timeout: True)


def test_unsaved_device_is_stored_also_when_no_message_comes(notified, clock, monkeypatch):
    """E.g. the device left before the database works again"""
    storage = FailingStorage()
    tracker = failing_tracker(storage, per_network=True)
    feed(tracker, [LAN])  # reported, cannot be stored
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

    assert storage.stored == [(MAC, 'br-lan')]
    assert not tracker.unsaved


DAY = daemon.DAY


@pytest.fixture
def forgetting(tmp_path, clock):
    """Database with MAC seen on br-lan now, and a tracker forgetting after 30 days"""
    storage = DatabaseStorage(str(tmp_path / 'dev-detect.db'))
    storage.store(MAC, 'br-lan')
    return daemon.DeviceTracker(storage, per_network=True, forget_after=30)


def test_device_that_comes_back_after_forget_after_is_reported_again(forgetting, notified, clock):
    clock[0] += 31 * DAY
    feed(forgetting, [LAN] * 3)
    clock[0] += 60
    feed(forgetting, [LAN] * 3)

    assert notified == [(MAC, 31)]  # once, last seen is stored after the notification
    assert [row[3:5] for row in forgetting.storage.devices()] == [(1700000000, 1700000000 + 31 * DAY)]


def test_device_that_comes_back_sooner_is_not_reported(forgetting, notified, clock):
    clock[0] += 29 * DAY
    feed(forgetting, [LAN])

    assert notified == []
    assert [row[4] for row in forgetting.storage.devices()] == [1700000000 + 29 * DAY]  # its presence recorded


def test_stale_entry_of_forgotten_device_is_not_reported(forgetting, notified, clock):
    """Entries of devices that left stay STALE in the neighbour table for long"""
    clock[0] += 31 * DAY
    feed(forgetting, [Message(MAC, '192.168.1.50', family=2, state=0x04)])

    assert notified == []


def test_device_known_everywhere_is_not_forgotten(forgetting, notified, clock):
    forgetting.storage.add(MAC)
    clock[0] += 400 * DAY
    feed(forgetting, [LAN])

    assert notified == []


def test_forgotten_device_with_static_lease_is_stored_without_report(tmp_path, notified, clock, dhcp):
    storage = DatabaseStorage(str(tmp_path / 'dev-detect.db'))
    tracker = daemon.DeviceTracker(storage, known_static_leases=True, per_network=True, forget_after=30)
    feed(tracker, [STATIC])
    clock[0] += 31 * DAY
    feed(tracker, [STATIC])

    assert notified == []
    assert [row[4] for row in storage.devices()] == [1700000000 + 31 * DAY]


def test_devices_are_not_forgotten_by_default(tmp_path, notified, clock):
    storage = DatabaseStorage(str(tmp_path / 'dev-detect.db'))
    storage.store(MAC, 'br-lan')
    clock[0] += 1000 * DAY
    feed(daemon.DeviceTracker(storage, per_network=True), [LAN])

    assert notified == []


@pytest.mark.parametrize('per_network, expected', [(True, [(MAC, 31)]), (False, [])])
def test_device_seen_on_another_network_meanwhile(tmp_path, notified, clock, per_network, expected):
    """Without per_network, a device is forgotten only when it was not seen on any network"""
    storage = DatabaseStorage(str(tmp_path / 'dev-detect.db'))
    storage.store(MAC, 'br-lan')
    storage.store(MAC, 'br-guest-turris')
    tracker = daemon.DeviceTracker(storage, per_network=per_network, forget_after=30)
    clock[0] += 20 * DAY
    feed_networks(tracker, [GUEST])  # recorded on the guest network
    clock[0] += 11 * DAY
    feed_networks(tracker, [LAN])

    assert notified == expected


def test_device_that_came_back_is_reported_with_how_long_it_was_away(forgetting, monkeypatch, clock):
    reports = []
    monkeypatch.setattr(daemon.notify, 'new_device', lambda mac, ip, iface, on_reported=None, away=None:
                        reports.append((mac, iface, away)))
    clock[0] += 45 * DAY
    feed(forgetting, [LAN])

    assert reports == [(MAC, 'br-lan', 45 * DAY)]


def test_database_writes_of_device_that_came_back(forgetting, notified, commits, clock):
    clock[0] += 31 * DAY
    del commits[:]
    feed(forgetting, [LAN] * 3)

    assert len(commits) == 1  # stored after the notification


@pytest.fixture
def clocks(monkeypatch):
    """Wall clock and monotonic clock, moved separately by the test"""
    wall, mono = [1700000000.0], [1000.0]
    monkeypatch.setattr(daemon.time, 'time', lambda: wall[0])
    monkeypatch.setattr(daemon.time, 'monotonic', lambda: mono[0])
    return wall, mono


def test_device_stored_before_clock_was_set_is_not_reported_as_back(tmp_path, notified, clocks):
    """A router without RTC starts with its clock behind until NTP sets it"""
    wall, mono = clocks
    wall[0] -= 60 * DAY
    storage = DatabaseStorage(str(tmp_path / 'dev-detect.db'))
    tracker = daemon.DeviceTracker(storage, per_network=True, forget_after=30)
    feed(tracker, [LAN])  # reported and stored with the wrong time
    wall[0] += 60 * DAY
    mono[0] += 60
    feed(tracker, [LAN])

    assert notified == [MAC]
    assert [row[4] for row in storage.devices()] == [1700000000]  # corrected


def test_learned_devices_before_clock_was_set_are_not_reported_as_back(tmp_path, notified, learned, clocks):
    wall, mono = clocks
    wall[0] -= 60 * DAY
    tracker = daemon.DeviceTracker(DatabaseStorage(str(tmp_path / 'dev-detect.db')), per_network=True, forget_after=30)
    start(tracker, LAN, Message(OTHER_MAC, '192.168.1.51', family=2))
    wall[0] += 60 * DAY
    mono[0] += 60
    feed(tracker, [LAN, Message(OTHER_MAC, '192.168.1.51', family=2)])

    assert [mac for mac, _, _ in learned] == [MAC, OTHER_MAC]
    assert notified == []


@pytest.mark.skipif(os.geteuid() == 0, reason='file permissions do not apply to root')
def test_present_device_is_not_forgotten_when_database_cannot_be_written(tmp_path, notified, clocks):
    wall, mono = clocks
    db_path = str(tmp_path / 'dev-detect.db')
    DatabaseStorage(db_path).store(MAC, 'br-lan')
    os.chmod(db_path, 0o444)
    tracker = daemon.DeviceTracker(DatabaseStorage(db_path), per_network=True, forget_after=30)
    for _ in range(40 * 24):  # present for 40 days
        feed(tracker, [LAN])
        wall[0] += 3600
        mono[0] += 3600

    assert notified == []


def test_device_away_for_less_than_forget_after_is_not_reported(tmp_path, notified, clocks):
    """Last seen is recorded once per 6 hours, so it can be older than when the device left"""
    wall, mono = clocks
    storage = DatabaseStorage(str(tmp_path / 'dev-detect.db'))
    for day in range(7):  # 2 hours every morning, a minute later each day; the daemon restarted meanwhile
        tracker = daemon.DeviceTracker(storage, per_network=True, forget_after=1)
        for _ in range(12):
            feed(tracker, [LAN])
            wall[0] += 600
            mono[0] += 600
        wall[0] += 22 * 3600 + 60
        mono[0] += 22 * 3600 + 60
    assert notified == [MAC]

    wall[0] += 31 * 3600
    mono[0] += 31 * 3600
    feed(daemon.DeviceTracker(storage, per_network=True, forget_after=1), [LAN])
    assert notified == [MAC, (MAC, 2)]


def test_device_with_static_lease_is_forgotten_without_known_static_leases(tmp_path, notified, clock, dhcp):
    storage = DatabaseStorage(str(tmp_path / 'dev-detect.db'))
    tracker = daemon.DeviceTracker(storage, known_static_leases=False, per_network=True, forget_after=30)
    feed(tracker, [STATIC])
    clock[0] += 31 * DAY
    feed(daemon.DeviceTracker(storage, known_static_leases=False, per_network=True, forget_after=30), [STATIC])

    assert notified == ['02:00:00:00:00:01', ('02:00:00:00:00:01', 31)]


@pytest.mark.skipif(os.geteuid() == 0, reason='file permissions do not apply to root')
def test_away_counts_from_when_this_run_saw_the_device(tmp_path, notified, clocks):
    """The stored time is old while the database cannot be written"""
    wall, mono = clocks
    db_path = str(tmp_path / 'dev-detect.db')
    wall[0] -= 10 * DAY
    DatabaseStorage(db_path).store(MAC, 'br-lan')
    wall[0] += 10 * DAY
    os.chmod(db_path, 0o444)
    tracker = daemon.DeviceTracker(DatabaseStorage(db_path), per_network=True, forget_after=30)
    for _ in range(34):  # present for 5 hours 40 minutes
        feed(tracker, [LAN])
        wall[0] += 600
        mono[0] += 600
    wall[0] += 30 * DAY
    mono[0] += 30 * DAY
    feed(tracker, [LAN])  # away for less than 30 days
    assert notified == []

    for _ in range(160 * 4):  # present for 160 days
        feed(tracker, [LAN])
        wall[0] += 6 * 3600
        mono[0] += 6 * 3600
    wall[0] += 40 * DAY
    mono[0] += 40 * DAY
    feed(tracker, [LAN])
    assert notified == [(MAC, 40)]  # not 200 days from the stored time


def test_nothing_is_recorded_without_forget_after(tmp_path, notified, clock):
    storage = DatabaseStorage(str(tmp_path / 'dev-detect.db'))
    storage.store(OTHER_MAC, 'br-lan')
    tracker = daemon.DeviceTracker(storage, per_network=True)
    clock[0] += daemon.LAST_SEEN_INTERVAL
    feed(tracker, EVENTS + [Message(OTHER_MAC, '192.168.1.51', family=2)])

    assert notified == [MAC]
    assert tracker.recorded == {}


def test_restart_with_clock_at_1970_until_ntp_does_not_report_present_device(tmp_path, notified, clocks):
    """A router without RTC can start at the epoch; the device stays all the time"""
    wall, mono = clocks
    db_path = str(tmp_path / 'dev-detect.db')
    DatabaseStorage(db_path).store(MAC, 'br-lan')  # 3 hours before the restart
    now = wall[0] + 3 * 3600
    wall[0] = 0
    tracker = daemon.DeviceTracker(DatabaseStorage(db_path), per_network=True, forget_after=30)
    feed(tracker, [LAN])
    wall[0] = now + 300  # NTP
    mono[0] += 300
    feed(tracker, [LAN])
    wall[0] += 6 * 3600
    mono[0] += 6 * 3600
    feed(tracker, [LAN])

    assert notified == []
    assert [row[4] for row in tracker.storage.devices()] == [int(wall[0])]


def test_device_back_while_clock_at_1970_is_reported_once_after_ntp(tmp_path, notified, clocks):
    """It really was away, but the clock tells how long only after NTP"""
    wall, mono = clocks
    db_path = str(tmp_path / 'dev-detect.db')
    DatabaseStorage(db_path).store(MAC, 'br-lan')
    now = wall[0] + 120 * DAY
    wall[0] = 0
    tracker = daemon.DeviceTracker(DatabaseStorage(db_path), per_network=True, forget_after=30)
    feed(tracker, [LAN])
    assert notified == []
    wall[0] = now  # NTP
    mono[0] += 300
    feed(tracker, [LAN] * 3)

    assert notified == [(MAC, 120)]


def test_device_back_on_another_network_while_clock_at_1970_is_reported_after_ntp(tmp_path, notified, clocks):
    """Its presence written before NTP does not count as seen by this run"""
    wall, mono = clocks
    db_path = str(tmp_path / 'dev-detect.db')
    DatabaseStorage(db_path).store(MAC, 'br-guest-turris')
    now = wall[0] + 120 * DAY
    wall[0] = 0
    tracker = daemon.DeviceTracker(DatabaseStorage(db_path), forget_after=30)
    feed_networks(tracker, [LAN])
    assert notified == []
    wall[0] = now  # NTP
    mono[0] += 300
    feed_networks(tracker, [LAN] * 3)

    assert notified == [(MAC, 120)]


def test_device_back_while_clock_is_behind_is_reported_after_ntp(tmp_path, notified, clocks):
    """E.g. OpenWrt sets the clock at boot to the time of the newest file in /etc"""
    wall, mono = clocks
    db_path = str(tmp_path / 'dev-detect.db')
    storage = DatabaseStorage(db_path)
    storage.store(MAC, 'br-lan')
    wall[0] += 30 * DAY
    storage.store(MAC, 'br-guest-turris')
    now = wall[0] + 120 * DAY
    wall[0] = now - 140 * DAY  # behind the time on br-guest-turris, not the one on br-lan
    tracker = daemon.DeviceTracker(DatabaseStorage(db_path), per_network=True, forget_after=30)
    feed_networks(tracker, [LAN])
    assert notified == []
    wall[0] = now  # NTP
    mono[0] += 300
    feed_networks(tracker, [LAN] * 3)

    assert notified == [(MAC, 140)]  # counted from the time written before NTP


def test_device_seen_only_before_ntp_is_not_reported_as_back_later(tmp_path, notified, clocks):
    """Its presence is written with the clock as it is"""
    wall, mono = clocks
    db_path = str(tmp_path / 'dev-detect.db')
    storage = DatabaseStorage(db_path)
    storage.store(MAC, 'br-lan')
    wall[0] += 24 * DAY
    storage.store(MAC, 'br-guest-turris')
    now = wall[0] + DAY
    wall[0] = now - 10 * DAY  # behind the time on br-guest-turris
    tracker = daemon.DeviceTracker(DatabaseStorage(db_path), per_network=True, forget_after=30)
    feed_networks(tracker, [LAN])  # then the device leaves
    wall[0] = now + 10 * DAY  # NTP set the clock meanwhile
    mono[0] += 10 * DAY
    feed_networks(tracker, [LAN])

    assert notified == []


def test_device_with_time_stored_while_clock_was_ahead_is_not_reported_as_back(tmp_path, notified, clocks):
    """Its presence is written also while the clock is behind that time"""
    wall, mono = clocks
    db_path = str(tmp_path / 'dev-detect.db')
    wall[0] += 100 * DAY
    DatabaseStorage(db_path).store(MAC, 'br-guest-turris')
    wall[0] -= 100 * DAY
    DatabaseStorage(db_path).store(MAC, 'br-lan')
    tracker = daemon.DeviceTracker(DatabaseStorage(db_path), per_network=True, forget_after=30)
    for _ in range(110 * 4):  # present on br-lan for 110 days
        feed_networks(tracker, [LAN])
        wall[0] += 6 * 3600
        mono[0] += 6 * 3600

    assert notified == []


def test_new_device_while_clock_at_1970_is_not_reported_back_after_ntp(tmp_path, notified, clocks):
    wall, mono = clocks
    now = wall[0]
    wall[0] = 0
    tracker = daemon.DeviceTracker(DatabaseStorage(str(tmp_path / 'dev-detect.db')), per_network=True, forget_after=30)
    feed(tracker, [LAN])  # stored at the epoch
    wall[0] = now  # NTP
    mono[0] += 300
    feed(tracker, [LAN])

    assert notified == [MAC]
    assert [row[4] for row in tracker.storage.devices()] == [int(now)]  # corrected


@pytest.mark.parametrize('away, reported', [
    (90 * DAY, False),
    (90 * DAY + daemon.LAST_SEEN_INTERVAL, False),
    (90 * DAY + daemon.LAST_SEEN_INTERVAL + 1, True),
])
def test_forget_after_limit(tmp_path, notified, clock, away, reported):
    storage = DatabaseStorage(str(tmp_path / 'dev-detect.db'))
    storage.store(MAC, 'br-lan')
    clock[0] += away
    feed(daemon.DeviceTracker(storage, per_network=True, forget_after=90), [LAN])

    assert notified == ([(MAC, 90)] if reported else [])
