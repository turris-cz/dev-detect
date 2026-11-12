"""Notification about a new device

The notification waits for the addresses and the DHCP lease of the device. It
is created once the hostname is known, usually 5 to 10 seconds after the
device was detected, at the latest after MAX_LOOKUP_TIME:

    New device on network lan: Mac
    MAC address: 3e:f1:18:4d:d9:23 (randomized address, vendor unknown)
    IPv4: 192.168.1.50
    IPv6: 2a00:1028:8388:a84e:a1a4:8dbf:7ab8:e5ac

create_notification of user-notify translates the parts of the message marked
by _() to the language of the router, with the user-notify catalog of
turris-translations (packages user-notify-l10n-<language>).
"""
import ipaddress
import logging
import os
import queue
import re
import subprocess
import threading
import time

from .constants import DEVICE_STATES, IPV4

logger = logging.getLogger(__name__)

DNSMASQ_LEASES = '/tmp/dhcp.leases'
HOSTS_DIR = '/tmp/hosts'  # hosts files read by dnsmasq, e.g. written by odhcpd

# give the device time to get its addresses and DHCP lease
FIRST_LOOKUP_DELAY = 5
LOOKUP_INTERVAL = 5
MAX_LOOKUP_TIME = 30

# number of devices listed in the notification about learned devices
LEARNED_LIMIT = 20

DAY = 24 * 3600


def translated(text):
    """Mark text to be translated by create_notification (gettext_filter of user-notify)

    The text must not contain ')'.
    """
    return '_({})'.format(text)


def plain(value):
    """Text from the network, which must not be taken for a part to translate

    Underscores go through gettext_filter in _() too, as they are: it would
    take '_(' for the start of a part to translate and double runs of them.
    """
    return re.sub(r'_+', lambda match: translated(match.group()), str(value))


class Device:
    def __init__(self, mac, iface):
        self.mac = mac
        self.iface = iface
        self.network = iface
        self.hostname = None
        self.vendor = None
        self.addresses = set()
        self.away = None  # seconds a device that came back was not seen


def is_randomized(mac):
    """Locally administered address, as used by devices with private (random) MAC address"""
    return bool(int(mac.split(':')[0], 16) & 0x02)


def parse_addresses(addresses):
    """Return valid IP addresses, skipping (and logging) invalid ones"""
    parsed = []
    for address in addresses:
        try:
            parsed.append(ipaddress.ip_address(address))
        except ValueError:
            logger.debug('Ignoring invalid address %r', address)
    return parsed


# number of addresses listed in a notification
ADDRESS_LIMIT = 10


def sort_addresses(addresses):
    """IPv4 first, then IPv6; link-local addresses only when nothing else is known

    At most ADDRESS_LIMIT: a device can make the router see thousands of its
    addresses, and the notification has to fit on the command line of
    create_notification.
    """
    parsed = set(parse_addresses(addresses))
    ipv4 = sorted(a for a in parsed if a.version == 4)
    ipv6 = sorted(a for a in parsed if a.version == 6 and not a.is_link_local)
    link_local = sorted(a for a in parsed if a.version == 6 and a.is_link_local)
    return [str(a) for a in (ipv4 + ipv6 or link_local)][:ADDRESS_LIMIT]


def valid_hostname(name):
    """The hostname is only shown, so it just has to be printable, short and without spaces"""
    return (
        bool(name) and name != '*' and len(name) <= 63
        and name.isprintable() and not any(char.isspace() for char in name)
    )


def dnsmasq_leases(path=None):
    """Return {mac: [(ipv4, hostname), ...]} of DHCPv4 leases, the newest first

    Lines are '<expiry> <mac> <ip> <hostname or *> <client id>'. DHCPv6 lines
    have an IAID in place of the MAC address and an IPv6 address, and are skipped.
    A MAC address has more leases e.g. on more networks.
    """
    leases_of = {}
    try:
        with open(path or DNSMASQ_LEASES, errors='replace') as leases:
            for line in leases:
                fields = line.split()
                if len(fields) < 4:
                    continue
                try:
                    expiry = int(fields[0]) or float('inf')  # 0 means infinite lease
                    ipaddress.IPv4Address(fields[2])
                except ValueError:
                    continue
                leases_of.setdefault(fields[1].lower(), []).append((expiry, fields[2], fields[3]))
    except OSError:
        return {}
    return {
        mac: [
            (ip, hostname if valid_hostname(hostname) else None)
            for _, ip, hostname in sorted(leases, key=lambda lease: lease[0], reverse=True)
        ]
        for mac, leases in leases_of.items()
    }


def dnsmasq_lease(mac, path=None):
    """Return IPv4 address and hostname of the newest DHCPv4 lease of the MAC address"""
    return next(iter(dnsmasq_leases(path).get(mac, ())), (None, None))


def lease_on_network(leases, networks):
    """Return (ipv4, hostname) of the newest of the leases in one of the networks

    Any lease is taken when the networks are not known, e.g. when the
    interface has no IPv4 address.
    """
    for ip, hostname in leases:
        if not networks or any(ipaddress.ip_address(ip) in network for network in networks):
            return ip, hostname
    return None, None


def hosts_names(directory=None):
    """Return {address: hostname} from hosts files read by dnsmasq

    odhcpd writes there '<address> <hostname>[.<domain>]' lines for its DHCPv6
    clients (in older versions mixed with lease records starting with '#').
    """
    names = {}
    directory = directory or HOSTS_DIR
    try:
        files = sorted(os.listdir(directory))
    except OSError:
        return names
    for name in files:
        try:
            with open(os.path.join(directory, name)) as hosts:
                for line in hosts:
                    fields = line.split()
                    if line.startswith('#') or len(fields) < 2:
                        continue
                    try:
                        address = ipaddress.ip_address(fields[0])
                    except ValueError:
                        continue
                    hostname = fields[1].split('.')[0]
                    if valid_hostname(hostname):
                        names.setdefault(address, hostname)
        except (OSError, UnicodeDecodeError):
            continue
    return names


def neighbour_table(ifaces):
    """Return addresses of devices on the interfaces and IPv4 networks of the interfaces

    ({(mac, iface): addresses}, {iface: [IPv4Network]}), from one dump of the
    neighbour table and one of the addresses
    """
    from pyroute2 import IPRoute

    with IPRoute() as ipr:
        names = {}
        for iface in ifaces:
            indexes = ipr.link_lookup(ifname=iface)
            if indexes:
                names[indexes[0]] = iface
        table = {}
        for message in ipr.get_neighbours():
            iface = names.get(message.get('ifindex'))
            mac = message.get_attr('NDA_LLADDR')
            ip = message.get_attr('NDA_DST')
            if iface and mac and ip and message.get('state', 0) & DEVICE_STATES:
                table.setdefault((mac, iface), set()).add(ip)
        networks = {}
        for message in ipr.get_addr(family=IPV4):
            iface = names.get(message.get('index'))
            address = message.get_attr('IFA_LOCAL') or message.get_attr('IFA_ADDRESS')
            if iface and address:
                networks.setdefault(iface, []).append(
                    ipaddress.ip_network('{}/{}'.format(address, message.get('prefixlen')), strict=False)
                )
        return table, networks


def network_name(iface):
    """Return name of the network (e.g. lan, guest_turris) using the interface"""
    from euci import EUci

    with EUci() as uci:
        for section, options in uci.get('network', default={}).items():
            if uci.get('network', section, default='') != 'interface':
                continue
            if options.get('device') == iface:
                return section
            if options.get('type') == 'bridge' and 'br-' + section == iface:  # old syntax
                return section
    return iface


def vendor(mac):
    """Return device vendor based on MAC address"""
    if is_randomized(mac):
        return None
    try:
        result = subprocess.run(
            ['ouidb', mac],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, universal_newlines=True, timeout=10,
        )
    except (OSError, subprocess.SubprocessError) as e:
        logger.debug('Cannot look up vendor of %s: %s', mac, e)
        return None
    if result.returncode != 0:
        return None
    lines = result.stdout.strip().splitlines()
    return lines[0].strip().rstrip(',') or None if lines else None


def compose(device):
    name = plain(device.hostname or device.mac)
    if device.away is None:
        lines = ['{} {}: {}'.format(translated('New device on network'), plain(device.network), name)]
    else:
        lines = [
            '{} {}: {}'.format(translated('Device back on network'), plain(device.network), name),
            '{}: {}'.format(translated('Days away'), int(device.away // DAY)),
        ]
    if is_randomized(device.mac):
        detail = translated('randomized address, vendor unknown')
    else:
        detail = device.vendor and plain(device.vendor)
    lines.append('{}: {}'.format(translated('MAC address'), device.mac) + (' ({})'.format(detail) if detail else ''))
    for address in sort_addresses(device.addresses):
        lines.append('IPv{}: {}'.format(ipaddress.ip_address(address).version, address))
    return '\n'.join(lines)


def create_notification(message, subject):
    """Create notification (reForis, e-mail, ntfy) using create_notification of user-notify

    Return whether the notification was created.
    """
    command = ['create_notification', '-s', 'news', message]
    try:
        result = subprocess.run(
            command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, timeout=30,
        )
    except (OSError, subprocess.SubprocessError) as e:
        logger.error('Cannot create notification about %s: %s', subject, e)
        return False
    if result.returncode != 0:
        logger.error('Cannot create notification about %s: %s', subject, result.stderr.strip())
        return False
    return True


def send(device):
    """Create notification about the device, return whether it was created"""
    return create_notification(compose(device), 'device ' + device.mac)


def compose_learned(devices, networks=None):
    """devices are (mac, interfaces, hostname), networks maps interfaces to network names"""
    networks = networks or {}
    lines = [translated(
        'The device database was empty at start, so devices already present were stored'
        ' without separate notifications:'
    )]
    for mac, ifaces, hostname in devices[:LEARNED_LIMIT]:
        details = [hostname] + [networks.get(iface, iface) for iface in ifaces]
        lines.append('{} ({})'.format(mac, plain(', '.join(filter(None, details)))))
    if len(devices) > LEARNED_LIMIT:
        lines.append('{}: {} (dev-detect list)'.format(translated('More devices'), len(devices) - LEARNED_LIMIT))
    return '\n'.join(lines)


def report_learned(devices):
    try:
        networks = {}
        for iface in {iface for _, ifaces, _ in devices for iface in ifaces}:
            try:
                networks[iface] = network_name(iface)
            except Exception:
                logger.debug('Cannot find network of interface %s', iface, exc_info=True)
        create_notification(compose_learned(devices, networks), '{} learned devices'.format(len(devices)))
    except Exception:
        logger.exception('Cannot report learned devices')


def learned_devices(devices):
    """Report in background devices that were stored without reporting each of them

    devices are (mac, interfaces, hostname)
    """
    threading.Thread(target=report_learned, args=(list(devices),), daemon=True).start()


class _Waiting:
    """Device waiting for its notification"""
    def __init__(self, device, started, on_reported):
        self.device = device
        self.started = started
        self.next_check = started + FIRST_LOOKUP_DELAY
        self.on_reported = on_reported
        self.checked = False


class Notifier:
    """Creates notifications about new devices in one background thread

    The neighbour table, DHCP leases and hosts files are read for all devices
    waiting for their notification together, at most once per LOOKUP_INTERVAL,
    so that a burst of new devices does not multiply these reads. Vendors are
    looked up and notifications created one device after another.
    """
    def __init__(self, clock=time.monotonic, background=True):
        self.clock = clock
        self.background = background  # False in tests, which call step() themselves
        self.queue = queue.Queue()
        self.waiting = []
        self.last_lookup = None
        self.thread = None
        self.lock = threading.Lock()

    def add(self, mac, ip, iface, on_reported=None, away=None):
        """Report device in background

        on_reported is called with the Device after the notification was
        created (or creating it failed). away is for how long a device that
        came back was not seen (seconds).
        """
        self.queue.put((mac, ip, iface, on_reported, away))
        if not self.background:
            return
        with self.lock:
            if self.thread is None:
                self.thread = threading.Thread(target=self.run, daemon=True)
                self.thread.start()

    def run(self):
        while True:
            try:
                self.step(block=True)
            except Exception:
                logger.exception('Cannot report new devices')

    def next_lookup(self):
        """Return when details are looked up next time, None if no device is waiting"""
        if not self.waiting:
            return None
        due = min(waiting.next_check for waiting in self.waiting)
        if self.last_lookup is not None:
            due = max(due, self.last_lookup + LOOKUP_INTERVAL)
        return due

    def step(self, block=False):
        """Take new devices and look up details of those that are due"""
        try:
            if block:
                due = self.next_lookup()
                self._accept(self.queue.get(timeout=None if due is None else max(0, due - self.clock())))
            while True:
                self._accept(self.queue.get_nowait())
        except queue.Empty:
            pass
        due = self.next_lookup()
        if due is not None and due <= self.clock():
            self.lookup()

    def _accept(self, item):
        mac, ip, iface, on_reported, away = item
        device = Device(mac, iface)
        device.away = away
        device.addresses.update(str(address) for address in parse_addresses([ip]))
        self.waiting.append(_Waiting(device, self.clock(), on_reported))

    def lookup(self):
        """Look up addresses and hostnames of due devices, report those that are complete"""
        now = self.last_lookup = self.clock()
        due = [waiting for waiting in self.waiting if waiting.next_check <= now]
        table, subnets = self._read(
            'neighbour table', neighbour_table, {waiting.device.iface for waiting in due}, default=({}, {}),
        )
        leases = self._read('DHCP leases', dnsmasq_leases)
        hosts = None
        names = {}
        for waiting in due:
            device = waiting.device
            if not waiting.checked:
                self._find_details(device, names)
                waiting.checked = True
            device.addresses |= table.get((device.mac, device.iface), set())
            # not a lease from another network the device was on before
            ipv4, hostname = lease_on_network(leases.get(device.mac, ()), subnets.get(device.iface))
            if ipv4:
                device.addresses.add(ipv4)
            if not hostname:
                if hosts is None:
                    hosts = self._read('hosts files', hosts_names)
                hostname = next((hosts[a] for a in parse_addresses(device.addresses) if a in hosts), None)
            device.hostname = hostname
            if hostname or now - waiting.started >= MAX_LOOKUP_TIME:
                self.waiting.remove(waiting)
                self._finish(waiting)
            else:
                waiting.next_check = now + LOOKUP_INTERVAL

    @staticmethod
    def _read(what, function, *args, default=None):
        """A source that cannot be read must not keep the waiting devices from being reported"""
        try:
            return function(*args)
        except Exception:
            logger.warning('Cannot read %s', what, exc_info=True)
            return {} if default is None else default

    @staticmethod
    def _find_details(device, networks):
        """Find network and vendor of the device; networks caches network names of interfaces"""
        if device.iface not in networks:
            try:
                networks[device.iface] = network_name(device.iface) or device.iface
            except Exception:
                logger.warning('Cannot find network of interface %s', device.iface, exc_info=True)
                networks[device.iface] = device.iface
        device.network = networks[device.iface]
        try:
            device.vendor = vendor(device.mac)
        except Exception:
            logger.warning('Cannot find vendor of device %s', device.mac, exc_info=True)

    @staticmethod
    def _finish(waiting):
        try:
            if send(waiting.device):
                logger.info('Created notification about device %s', waiting.device.mac)
        except Exception:
            logger.exception('Cannot report new device %s', waiting.device.mac)
        finally:
            if waiting.on_reported:
                try:
                    waiting.on_reported(waiting.device)
                except Exception:
                    logger.exception('Cannot process reported device %s', waiting.device.mac)


notifier = Notifier()


def new_device(mac, ip, iface, on_reported=None, away=None):
    """Report new device in background, once more is known about it (see Notifier.add)"""
    notifier.add(mac, ip, iface, on_reported, away)
