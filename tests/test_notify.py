import ipaddress
import subprocess
import sys
import threading
import types

import pytest

from dev_detect import notify

MAC = '3e:f1:18:4d:d9:23'  # locally administered (randomized)
APPLE_MAC = 'f0:18:98:aa:bb:cc'
IPV6 = '2a00:1028:8388:a84e:a1a4:8dbf:7ab8:e5ac'

LEASES = """\
1731430000 f0:18:98:aa:bb:cc 192.168.1.60 MacBook 01:f0:18:98:aa:bb:cc
1731440000 3e:f1:18:4d:d9:23 192.168.1.50 Mac 01:3e:f1:18:4d:d9:23
1731420000 3e:f1:18:4d:d9:23 192.168.1.49 * 01:3e:f1:18:4d:d9:23
1731450000 02:00:00:00:00:01 192.168.1.70 printer 3e:f1:18:4d:d9:23
1731450000 02:00:00:00:00:02 192.168.1.71 * *
0 02:00:00:00:00:03 192.168.1.72 old *
1731460000 02:00:00:00:00:03 192.168.1.73 new *
duid 00:01:00:01:2c:2f:5a:2d:d8:58:d7:00:6a:6b
1731460000 1234567 2a00:1028:8388:a84e::1234 phone 00:01:00:01:2c:2f:5a:2d:3e:f1:18:4d:d9:23
"""


@pytest.fixture
def leases(tmp_path, monkeypatch):
    path = tmp_path / 'dhcp.leases'
    path.write_text(LEASES)
    monkeypatch.setattr(notify, 'DNSMASQ_LEASES', str(path))
    return path


@pytest.mark.parametrize('mac, expected', [
    (MAC, ('192.168.1.50', 'Mac')),  # newest lease wins
    ('3E:F1:18:4D:D9:23'.lower(), ('192.168.1.50', 'Mac')),
    ('02:00:00:00:00:01', ('192.168.1.70', 'printer')),
    ('02:00:00:00:00:02', ('192.168.1.71', None)),  # client sent no hostname
    ('02:00:00:00:00:03', ('192.168.1.72', 'old')),  # infinite lease
    ('02:00:00:00:00:04', (None, None)),
])
def test_dnsmasq_lease(leases, mac, expected):
    assert notify.dnsmasq_lease(mac) == expected


def test_dnsmasq_lease_without_leases_file(tmp_path):
    assert notify.dnsmasq_lease(MAC, path=str(tmp_path / 'missing')) == (None, None)


def test_dnsmasq_leases_with_invalid_characters(tmp_path):
    path = tmp_path / 'dhcp.leases'
    path.write_bytes(b'1731440000 02:00:00:00:00:09 192.168.1.79 caf\xe9 *\n' + LEASES.encode())

    assert notify.dnsmasq_lease(MAC, str(path)) == ('192.168.1.50', 'Mac')
    assert notify.dnsmasq_lease('02:00:00:00:00:09', str(path)) == ('192.168.1.79', 'caf\ufffd')


def test_dnsmasq_leases_newest_first(leases):
    leases = notify.dnsmasq_leases()

    assert leases[MAC] == [('192.168.1.50', 'Mac'), ('192.168.1.49', None)]
    assert leases['02:00:00:00:00:03'] == [('192.168.1.72', 'old'), ('192.168.1.73', 'new')]  # infinite first


LAN = [ipaddress.ip_network('192.168.1.0/24')]
GUEST = [ipaddress.ip_network('10.111.222.0/24')]


@pytest.mark.parametrize('networks, expected', [
    (GUEST, ('10.111.222.60', 'MacBook')),
    (LAN, ('192.168.1.60', None)),
    (LAN + GUEST, ('192.168.1.60', None)),  # the newest
    (None, ('192.168.1.60', None)),  # networks of the interface not known
    ([ipaddress.ip_network('172.16.0.0/16')], (None, None)),
])
def test_lease_on_network(networks, expected):
    leases = [('192.168.1.60', None), ('10.111.222.60', 'MacBook')]

    assert notify.lease_on_network(leases, networks) == expected


def test_dnsmasq_leases(leases):
    """DHCPv6 leases have an IAID in place of the MAC address and are skipped"""
    assert sorted(notify.dnsmasq_leases()) == [
        '02:00:00:00:00:01', '02:00:00:00:00:02', '02:00:00:00:00:03', MAC, APPLE_MAC,
    ]


@pytest.mark.parametrize('name, valid', [
    ('Mac', True),
    ('android-5f3a2b1c', True),
    ('DESKTOP_PC', True),
    ('Pepův-iPhone', True),  # shown only, does not have to be a valid DNS name
    ('', False),
    ('*', False),  # dnsmasq: client sent no hostname
    ('my laptop', False),
    ('tab\there', False),
    ('\x1b[31mred', False),  # terminal escape sequence
    ('a' * 64, False),
])
def test_valid_hostname(name, valid):
    assert notify.valid_hostname(name) is valid


def test_hosts_names(tmp_path):
    (tmp_path / 'odhcpd').write_text(
        '# br-lan 00010001 1 Mac 1731460000 a 64 2a00:1028:8388:a84e:0:0:0:1234/128\n'
        '2a00:1028:8388:a84e:0:0:0:1234\tMac.lan\tMac\n'
        'garbage\tline\n'
    )
    (tmp_path / 'other').write_text('fd00::1\trouter\n192.168.1.1\t*\n')

    assert notify.hosts_names(str(tmp_path)) == {
        ipaddress.ip_address('2a00:1028:8388:a84e::1234'): 'Mac', ipaddress.ip_address('fd00::1'): 'router',
    }
    assert notify.hosts_names(str(tmp_path / 'missing')) == {}


def test_vendor_is_not_looked_up_for_randomized_address(monkeypatch):
    monkeypatch.setattr(subprocess, 'run', lambda *args, **kwargs: pytest.fail('ouidb called'))
    assert notify.vendor(MAC) is None


def test_vendor(monkeypatch):
    def run(command, **kwargs):
        assert command == ['ouidb', APPLE_MAC]
        return subprocess.CompletedProcess(command, 0, stdout='Apple,\n')
    monkeypatch.setattr(subprocess, 'run', run)

    assert notify.vendor(APPLE_MAC) == 'Apple'


def test_vendor_without_ouidb(monkeypatch):
    def run(command, **kwargs):
        raise FileNotFoundError(command[0])
    monkeypatch.setattr(subprocess, 'run', run)

    assert notify.vendor(APPLE_MAC) is None


def test_vendor_lookup_failure(monkeypatch):
    def run(command, **kwargs):
        return subprocess.CompletedProcess(command, 1, stdout='Usage: ouidb MAC\n')
    monkeypatch.setattr(subprocess, 'run', run)

    assert notify.vendor(APPLE_MAC) is None


def test_invalid_addresses_are_skipped(caplog):
    caplog.set_level('DEBUG')
    addresses = ['fe80::1', 'not an address', '192.168.1.50', IPV6, None]

    assert notify.sort_addresses(addresses) == ['192.168.1.50', IPV6]
    assert "Ignoring invalid address 'not an address'" in caplog.text


def test_number_of_listed_addresses_is_limited():
    """E.g. a device sending neighbour solicitations from thousands of addresses"""
    addresses = ['2001:db8::{:x}'.format(i) for i in range(5000)] + ['192.168.1.50']

    listed = notify.sort_addresses(addresses)
    assert listed[0] == '192.168.1.50' and len(listed) == notify.ADDRESS_LIMIT


def device(mac=MAC, hostname='Mac', vendor=None, addresses=('192.168.1.50', IPV6, 'fe80::848:7d4a:60d1:ce7')):
    result = notify.Device(mac, 'br-lan')
    result.network = 'lan'
    result.hostname = hostname
    result.vendor = vendor
    result.addresses = set(addresses)
    return result


def test_compose():
    assert notify.compose(device(), 'en') == (
        'New device on network lan: Mac\n'
        'MAC address: 3e:f1:18:4d:d9:23 (randomized address, vendor unknown)\n'
        'IPv4: 192.168.1.50\n'
        'IPv6: 2a00:1028:8388:a84e:a1a4:8dbf:7ab8:e5ac'
    )
    assert notify.compose(device(), 'cs') == (
        'Nové zařízení v síti lan: Mac\n'
        'MAC adresa: 3e:f1:18:4d:d9:23 (náhodná adresa, výrobce neznámý)\n'
        'IPv4: 192.168.1.50\n'
        'IPv6: 2a00:1028:8388:a84e:a1a4:8dbf:7ab8:e5ac'
    )


def test_compose_with_vendor_and_without_hostname():
    message = notify.compose(device(APPLE_MAC, hostname=None, vendor='Apple', addresses=['fe80::1']), 'en')

    assert message == (
        'New device on network lan: f0:18:98:aa:bb:cc\n'
        'MAC address: f0:18:98:aa:bb:cc (Apple)\n'
        'IPv6: fe80::1'  # link-local address only when nothing else is known
    )


@pytest.mark.parametrize('days, cs, en', [
    (120, 'Zařízení se vrátilo do sítě lan po 120 dnech: Mac', 'Device back on network lan after 120 days: Mac'),
    (1, 'Zařízení se vrátilo do sítě lan po 1 dni: Mac', 'Device back on network lan after 1 day: Mac'),
])
def test_compose_device_that_came_back(days, cs, en):
    dev = device()
    dev.away = days * 24 * 3600 + 3600

    assert notify.compose(dev, 'cs').splitlines()[0] == cs
    assert notify.compose(dev, 'en').splitlines()[0] == en
    assert notify.compose(dev, 'en').splitlines()[1:] == notify.compose(device(), 'en').splitlines()[1:]


@pytest.mark.parametrize('lang', ['cs', 'en'])
@pytest.mark.parametrize('dev', [device(), device(APPLE_MAC, None, None, ['192.168.1.60'])])
def test_composed_message_has_no_double_spaces(lang, dev):
    assert '  ' not in notify.compose(dev, lang)


class FakeEUci:
    config = {}

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def get(self, config, section=None, option=None, default=None, **kwargs):
        assert config == 'network'
        if section is None:
            return {name: options for name, (_, options) in self.config.items()}
        return self.config[section][0]


@pytest.fixture
def uci(monkeypatch):
    monkeypatch.setitem(sys.modules, 'euci', types.SimpleNamespace(EUci=FakeEUci))
    return FakeEUci


def test_network_name(uci):
    uci.config = {
        'br_lan': ('device', {'name': 'br-lan', 'type': 'bridge'}),
        'lan': ('interface', {'device': 'br-lan', 'proto': 'static'}),
        'guest_turris': ('interface', {'device': 'br-guest-turris'}),
        'old': ('interface', {'type': 'bridge', 'ifname': 'eth1'}),
    }

    assert notify.network_name('br-lan') == 'lan'
    assert notify.network_name('br-guest-turris') == 'guest_turris'
    assert notify.network_name('br-old') == 'old'
    assert notify.network_name('eth2') == 'eth2'


def test_send(monkeypatch):
    commands = []

    def run(command, **kwargs):
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, stdout='', stderr='')
    monkeypatch.setattr(subprocess, 'run', run)
    notify.send(device())

    assert commands == [['create_notification', '-s', 'news', notify.compose(device(), 'cs'),
                         notify.compose(device(), 'en')]]


@pytest.mark.parametrize('returncode, created', [(0, True), (1, False)])
def test_send_returns_whether_notification_was_created(monkeypatch, returncode, created):
    monkeypatch.setattr(subprocess, 'run', lambda command, **kwargs: subprocess.CompletedProcess(
        command, returncode, stdout='', stderr='error'))

    assert notify.send(device()) is created


@pytest.mark.parametrize('outcome', ['missing', 'failing'])
def test_send_failure_is_logged(monkeypatch, caplog, outcome):
    def run(command, **kwargs):
        if outcome == 'missing':
            raise FileNotFoundError(command[0])
        return subprocess.CompletedProcess(command, 1, stdout='', stderr='Unknown notification severity')
    monkeypatch.setattr(subprocess, 'run', run)
    notify.send(device())

    assert 'Cannot create notification about device 3e:f1:18:4d:d9:23' in caplog.text


class Neighbour(dict):
    """Minimal stand-in for pyroute2 ndmsg"""
    def __init__(self, mac, ip, ifindex, state=0x02):
        super().__init__(ifindex=ifindex, state=state)
        self.attrs = {'NDA_LLADDR': mac, 'NDA_DST': ip}

    def get_attr(self, name):
        return self.attrs.get(name)


class FakeIPRoute:
    links = {'br-lan': 7, 'br-guest-turris': 9}
    neighbours = [
        Neighbour(MAC, '192.168.1.50', 7),
        Neighbour(MAC, IPV6, 7, state=0x04),  # STALE
        Neighbour(MAC, 'fe80::848:7d4a:60d1:ce7', 7),
        Neighbour(MAC, '10.111.222.50', 9),
        Neighbour(APPLE_MAC, '192.168.1.60', 7, state=0x20),  # FAILED
        Neighbour(APPLE_MAC, '192.168.1.61', 3),  # not watched
        Neighbour(None, '192.168.1.62', 7),
    ]

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def link_lookup(self, ifname):
        return [self.links[ifname]] if ifname in self.links else []

    def get_neighbours(self):
        return self.neighbours

    def get_addr(self, family):
        assert family == 2
        return [Address(7, '192.168.1.1', 24), Address(9, '10.111.222.1', 24), Address(3, '172.16.0.1', 16)]


class Address(dict):
    """Minimal stand-in for pyroute2 ifaddrmsg"""
    def __init__(self, index, address, prefixlen):
        super().__init__(index=index, prefixlen=prefixlen, family=2)
        self.attrs = {'IFA_LOCAL': address, 'IFA_ADDRESS': address}

    def get_attr(self, name):
        return self.attrs.get(name)


def test_neighbour_table(monkeypatch):
    monkeypatch.setitem(sys.modules, 'pyroute2', types.SimpleNamespace(IPRoute=FakeIPRoute))

    assert notify.neighbour_table({'br-lan', 'br-guest-turris', 'br-missing'}) == (
        {
            (MAC, 'br-lan'): {'192.168.1.50', IPV6, 'fe80::848:7d4a:60d1:ce7'},
            (MAC, 'br-guest-turris'): {'10.111.222.50'},
        },
        {
            'br-lan': [ipaddress.ip_network('192.168.1.0/24')],
            'br-guest-turris': [ipaddress.ip_network('10.111.222.0/24')],
        },
    )


class Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


class Lookups:
    """Sources of device details, as seen by the Notifier"""
    def __init__(self, tmp_path):
        self.leases = tmp_path / 'dhcp.leases'
        self.leases.write_text('')
        self.neighbours = {}
        self.networks = {}
        self.dumps = []
        self.sent = []

    def neighbour_table(self, ifaces):
        self.dumps.append(set(ifaces))
        return {key: set(addresses) for key, addresses in self.neighbours.items()}, dict(self.networks)

    def add_lease(self, mac, ip, hostname, expiry=1731440000):
        with self.leases.open('a') as leases:
            leases.write('{} {} {} {} *\n'.format(expiry, mac, ip, hostname))


@pytest.fixture
def lookups(tmp_path, monkeypatch):
    lookups = Lookups(tmp_path)
    monkeypatch.setattr(notify, 'neighbour_table', lookups.neighbour_table)
    monkeypatch.setattr(notify, 'network_name', lambda iface: {'br-lan': 'lan'}.get(iface, iface))
    monkeypatch.setattr(notify, 'vendor', lambda mac: 'Apple' if mac == APPLE_MAC else None)
    monkeypatch.setattr(notify, 'DNSMASQ_LEASES', str(lookups.leases))
    monkeypatch.setattr(notify, 'HOSTS_DIR', str(tmp_path / 'hosts'))
    monkeypatch.setattr(notify, 'send', lambda device: lookups.sent.append(device))
    return lookups


@pytest.fixture
def clock():
    return Clock()


def run_until(notifier, clock, end, step=1):
    while clock.now < end:
        notifier.step()
        clock.now += step
    notifier.step()


def test_device_is_reported_once_its_hostname_is_known(lookups, clock):
    lookups.neighbours[(MAC, 'br-lan')] = {IPV6}
    lookups.add_lease(MAC, '192.168.1.50', 'Mac')
    reported = []
    notifier = notify.Notifier(clock, background=False)
    notifier.add(MAC, 'fe80::848:7d4a:60d1:ce7', 'br-lan', reported.append)

    run_until(notifier, clock, 1000 + notify.FIRST_LOOKUP_DELAY - 1)
    assert lookups.dumps == []  # gives the device time to get its addresses
    run_until(notifier, clock, 1000 + notify.FIRST_LOOKUP_DELAY)

    device, = lookups.sent
    assert (device.network, device.hostname) == ('lan', 'Mac')
    assert device.addresses == {'fe80::848:7d4a:60d1:ce7', IPV6, '192.168.1.50'}
    assert reported == [device]
    assert not notifier.waiting


def test_hostname_from_hosts_file(lookups, clock, tmp_path):
    (tmp_path / 'hosts').mkdir()
    (tmp_path / 'hosts' / 'odhcpd').write_text('{}\tphone.lan\tphone\n'.format(IPV6))
    lookups.neighbours[(MAC, 'br-lan')] = {IPV6}
    notifier = notify.Notifier(clock, background=False)
    notifier.add(MAC, 'fe80::848:7d4a:60d1:ce7', 'br-lan')

    run_until(notifier, clock, 1000 + notify.FIRST_LOOKUP_DELAY)

    assert [device.hostname for device in lookups.sent] == ['phone']


def test_device_without_hostname_is_reported_after_max_lookup_time(lookups, clock):
    notifier = notify.Notifier(clock, background=False)
    notifier.add(APPLE_MAC, '192.168.1.60', 'br-lan')

    run_until(notifier, clock, 1000 + notify.MAX_LOOKUP_TIME - 1)
    assert lookups.sent == []
    run_until(notifier, clock, 1000 + notify.MAX_LOOKUP_TIME)

    device, = lookups.sent
    assert (device.hostname, device.vendor, device.addresses) == (None, 'Apple', {'192.168.1.60'})
    assert len(lookups.dumps) == notify.MAX_LOOKUP_TIME // notify.LOOKUP_INTERVAL


def test_burst_of_devices_costs_about_the_same_as_one(lookups, clock):
    """E.g. a switch with many devices plugged into the network"""
    macs = ['02:00:00:00:00:{:02x}'.format(i) for i in range(50)]
    added = {}
    reported = []
    delays = {}

    def on_reported(device):
        reported.append(device)
        delays[device.mac] = clock.now - added[device.mac]
    notifier = notify.Notifier(clock, background=False)
    for i, mac in enumerate(macs):  # one every 0.1 s
        added[mac] = clock.now
        notifier.add(mac, '192.168.1.{}'.format(100 + i), 'br-lan', on_reported)
        notifier.step()
        clock.now += 0.1
        if i == 25:  # half of them get a DHCP lease soon
            for j, other in enumerate(macs[::2]):
                lookups.add_lease(other, '192.168.1.{}'.format(100 + 2 * j), 'host{}'.format(j))

    run_until(notifier, clock, clock.now + 60, step=0.5)

    assert sorted(device.mac for device in reported) == macs  # each once
    assert [device.mac for device in lookups.sent] == [device.mac for device in reported]
    assert len(lookups.dumps) <= notify.MAX_LOOKUP_TIME // notify.LOOKUP_INTERVAL + 2
    assert all(device.hostname for device in reported if device.mac in macs[::2])
    assert max(delays[mac] for mac in macs[::2]) < 15  # did not wait for the others
    assert max(delays.values()) <= notify.MAX_LOOKUP_TIME + notify.LOOKUP_INTERVAL


def test_lease_from_another_network_is_not_used(lookups, clock):
    """dnsmasq keeps the lease from the previous network of a device whose client ID differs"""
    lookups.networks = {'br-lan': LAN, 'br-guest-turris': GUEST}
    lookups.add_lease(APPLE_MAC, '192.168.1.60', '*', expiry=1731480000)  # lan, expires later
    lookups.add_lease(APPLE_MAC, '10.111.222.60', 'MacBook')
    lookups.add_lease(MAC, '192.168.1.50', 'Mac')
    reported = []
    notifier = notify.Notifier(clock, background=False)
    notifier.add(APPLE_MAC, '10.111.222.60', 'br-guest-turris', reported.append)
    notifier.add(MAC, IPV6, 'br-guest-turris', reported.append)  # has a lan lease only

    run_until(notifier, clock, 1000 + notify.MAX_LOOKUP_TIME)

    assert [(device.mac, device.hostname, device.addresses) for device in reported] == [
        (APPLE_MAC, 'MacBook', {'10.111.222.60'}),  # at the first lookup
        (MAC, None, {IPV6}),
    ]


def test_lookup_failures_do_not_stop_reporting(lookups, clock, monkeypatch, caplog):
    def broken(*args):
        raise RuntimeError('broken')
    for name in ('neighbour_table', 'dnsmasq_leases', 'hosts_names', 'network_name', 'vendor'):
        monkeypatch.setattr(notify, name, broken)
    reported = []
    notifier = notify.Notifier(clock, background=False)
    notifier.add(APPLE_MAC, '192.168.1.60', 'br-lan', reported.append)

    run_until(notifier, clock, 1000 + notify.MAX_LOOKUP_TIME)

    device, = reported
    assert (device.network, device.addresses) == ('br-lan', {'192.168.1.60'})
    assert lookups.sent == [device]
    assert 'Cannot read neighbour table' in caplog.text
    assert 'Cannot read DHCP leases' in caplog.text
    assert 'Cannot read hosts files' in caplog.text
    assert 'Cannot find network of interface br-lan' in caplog.text
    assert 'Cannot find vendor' in caplog.text


@pytest.mark.parametrize('callback_fails', [False, True])
def test_reported_after_sending(lookups, clock, monkeypatch, caplog, callback_fails):
    events = []
    lookups.add_lease(MAC, '192.168.1.50', 'Mac')
    monkeypatch.setattr(notify, 'send', lambda device: events.append('send'))

    def on_reported(device):
        events.append(('reported', device.hostname))
        if callback_fails:
            raise RuntimeError('database is broken')
    notifier = notify.Notifier(clock, background=False)
    notifier.add(MAC, '192.168.1.50', 'br-lan', on_reported)
    notifier.add(APPLE_MAC, '192.168.1.60', 'br-lan', lambda device: events.append(('reported', device.mac)))
    run_until(notifier, clock, 1000 + notify.MAX_LOOKUP_TIME)

    assert events == ['send', ('reported', 'Mac'), 'send', ('reported', APPLE_MAC)]
    assert ('Cannot process reported device' in caplog.text) == callback_fails


def test_reported_when_sending_fails(lookups, clock, monkeypatch, caplog):
    def send(device):
        raise RuntimeError('unexpected')
    monkeypatch.setattr(notify, 'send', send)
    reported = []
    notifier = notify.Notifier(clock, background=False)
    notifier.add(MAC, '192.168.1.50', 'br-lan', reported.append)
    run_until(notifier, clock, 1000 + notify.MAX_LOOKUP_TIME)

    assert [(device.mac, device.iface, device.addresses) for device in reported] == [
        (MAC, 'br-lan', {'192.168.1.50'}),
    ]
    assert 'Cannot report new device' in caplog.text


@pytest.mark.parametrize('created', [True, False])
def test_created_notification_is_logged(lookups, clock, monkeypatch, caplog, created):
    caplog.set_level('INFO')
    monkeypatch.setattr(notify, 'send', lambda device: created)
    notifier = notify.Notifier(clock, background=False)
    notifier.add(APPLE_MAC, '192.168.1.60', 'br-lan')
    run_until(notifier, clock, 1000 + notify.MAX_LOOKUP_TIME)

    assert ('Created notification about device f0:18:98:aa:bb:cc' in caplog.text) is created


def test_notifier_keeps_how_long_device_was_away(lookups, clock):
    lookups.add_lease(MAC, '192.168.1.50', 'Mac')
    notifier = notify.Notifier(clock, background=False)
    notifier.add(MAC, '192.168.1.50', 'br-lan', away=40 * 24 * 3600)
    run_until(notifier, clock, 1000 + notify.FIRST_LOOKUP_DELAY)

    assert [(device.mac, device.away) for device in lookups.sent] == [(MAC, 40 * 24 * 3600)]


def test_notifier_thread(lookups, monkeypatch):
    monkeypatch.setattr(notify, 'FIRST_LOOKUP_DELAY', 0.05)
    monkeypatch.setattr(notify, 'LOOKUP_INTERVAL', 0.05)
    monkeypatch.setattr(notify, 'MAX_LOOKUP_TIME', 0.2)
    done = threading.Event()
    reported = []

    def on_reported(device):
        reported.append(device.mac)
        if len(reported) == 2:
            done.set()
    notifier = notify.Notifier()
    notifier.add(MAC, '192.168.1.50', 'br-lan', on_reported)
    notifier.add(APPLE_MAC, '192.168.1.60', 'br-lan', on_reported)

    assert done.wait(10)
    assert reported == [MAC, APPLE_MAC]


def test_compose_learned(monkeypatch):
    monkeypatch.setattr(notify, 'LEARNED_LIMIT', 2)
    devices = [
        (MAC, ['br-lan', 'br-guest-turris'], 'Mac'),
        ('02:00:00:00:00:02', ['br-lan'], None),
        ('02:00:00:00:00:09', ['br-guest-turris'], 'phone'),
    ]
    networks = {'br-lan': 'lan', 'br-guest-turris': 'guest_turris'}

    assert notify.compose_learned(devices, 'en', networks) == (
        'The device database was empty at start, so devices already present were stored'
        ' without separate notifications (3):\n'
        '3e:f1:18:4d:d9:23 (Mac, lan, guest_turris)\n'
        '02:00:00:00:00:02 (lan)\n'
        'more: 1 (dev-detect list)'
    )
    assert notify.compose_learned(devices[1:2], 'cs') == (
        'Databáze zařízení byla při startu prázdná, proto byla již přítomná zařízení uložena'
        ' bez samostatných oznámení (1):\n'
        '02:00:00:00:00:02 (br-lan)'
    )
