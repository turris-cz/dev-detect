import argparse
import errno
import logging
import os
import select
import threading
import time

from . import notify
from .constants import DEVICE_STATES, IPV4, IPV6, NTF_PROXY, REACHABLE, RTMGRP_LINK, RTMGRP_NEIGH
from .storage import DEFAULT_DB_PATH, DatabaseStorage, StorageError

logger = logging.getLogger(__name__)

# br-guest_turris is the guest bridge on systems migrated from Turris OS 5
DEFAULT_INTERFACES = ('br-lan', 'br-guest-turris', 'br-guest_turris')

# minimal time in seconds between neighbour table scans after lost messages
RESYNC_INTERVAL = 30

# Names of one network. Saving the guest network settings in reForis renames the
# guest bridge of systems migrated from Turris OS 5 to br-guest-turris.
SAME_NETWORK = (('br-guest-turris', 'br-guest_turris'),)

# how often to record that a known device is still present, in seconds;
# every write wears out the internal flash a bit
LAST_SEEN_INTERVAL = 6 * 3600

# how often to try storing devices that could not be stored, in seconds
UNSAVED_RETRY_INTERVAL = 15 * 60

ADDRMAP = {
    IPV4: '4',
    IPV6: '6'
}


def network_names(iface):
    """Return all names of the network on the interface, the interface first"""
    for names in SAME_NETWORK:
        if iface in names:
            return (iface,) + tuple(name for name in names if name != iface)
    return (iface,)


def new_device_notify(mac, ip, addr_family, iface, on_reported=None):
    logger.info("New device detected on interface '%s'. MAC: %s | IPv%s address: %s",
                iface, mac, ADDRMAP.get(addr_family), ip)
    notify.new_device(mac, ip, iface, on_reported)


def get_interfaces(ipr, watched_interfaces):
    """Try to find all watched interfaces among present ones"""
    interfaces = {}
    links = ipr.get_links()

    for l in links:
        ifname = l.get_attr('IFLA_IFNAME')

        if ifname in watched_interfaces:
            interfaces[l['index']] = ifname

    for ifname in watched_interfaces:
        if ifname not in interfaces.values():
            logger.info("Interface '%s' does not exist, it will be watched once it appears", ifname)
    if not interfaces:
        logger.warning('None of the watched interfaces exists: %s', ', '.join(watched_interfaces))

    return interfaces


def update_interfaces(message, interfaces, watched_interfaces):
    """Follow watched interfaces that are created, re-created or removed

    netifd deletes a bridge when its interface goes down and creates it again
    with a new index, e.g. on network restart.
    """
    if message.get('family') != 0:  # skip e.g. AF_BRIDGE messages about bridge ports
        return
    ifname = message.get_attr('IFLA_IFNAME')
    index = message.get('index')
    if ifname not in watched_interfaces or index is None:
        return

    if message.get('event') == 'RTM_NEWLINK':
        if interfaces.get(index) == ifname:
            return
        for stale in [i for i, name in interfaces.items() if name == ifname]:
            del interfaces[stale]
        interfaces[index] = ifname
        logger.info("Watching interface '%s' (index %d)", ifname, index)
    elif interfaces.pop(index, None):
        logger.info("Interface '%s' was removed", ifname)


class DeviceTracker:
    """Decide whether a device is new and remember it

    The database stays the source of truth, so a device removed from it by
    `dev-detect remove` is reported again. A device that cannot be stored is
    kept in memory instead, so that it is reported only once even when the
    database is not writable, and stored once the database works again.

    With per_network, a device is new on each interface it appears on, unless
    it is known on every interface (added by `dev-detect add` or stored by an
    older version).

    A reported device is stored only once its notification was created (or
    creating it failed); until then it is pending in memory. If the daemon
    stops meanwhile, the device is reported again after the start instead of
    never.

    States of a device that is not in the database:
    - unknown: reported when it appears, then pending (is_new()); a device
      with a static DHCP lease, or one found while learning, is stored right
      away without being reported, or unsaved if it cannot be stored (_store());
    - pending: its notification is being created; then stored, or unsaved if
      it cannot be stored (device_reported());
    - unsaved: kept in memory, stored once the database works again.
    A device removed by `dev-detect remove` while pending is stored again
    after its notification, as it was reported.
    """
    def __init__(self, storage, known_static_leases=False, per_network=False, thread_storage=None):
        self.storage = storage
        self.known_static_leases = known_static_leases
        self.per_network = per_network
        # storage for notification threads, a connection cannot be shared by threads
        self.thread_storage = thread_storage or (lambda: DatabaseStorage(storage.db_path))
        self.lock = threading.Lock()  # for unsaved and pending, used by notification threads too
        self.unsaved = {}  # (mac, network) or mac -> (mac, iface, name, hostname)
        self.pending = {}  # the same keys -> (mac, iface), devices whose notification was not created yet
        self.touch_attempts = {}  # (mac, network) -> when the presence was last tried to be recorded (monotonic)
        self.unsaved_retried = None  # when storing unsaved devices was last tried (monotonic)
        self.learning = False
        self.learned = {}  # mac -> (interfaces, hostname)

    def start_learning(self):
        """Store devices found until the first complete scan without reporting each, if the database is empty

        E.g. on the first start, or on a start after the database was cleared
        (`dev-detect clear` and a restart of the service) or lost, when every
        device present would be reported. They are reported in one notification.
        """
        try:
            self.learning = self.storage.is_empty()
        except StorageError as e:
            logger.error('Cannot read device database: %s', e)

    def finish_learning(self):
        if not self.learning:
            return
        self.learning = False
        if not self.learned:
            return
        logger.info('Device database was empty, %d devices present were stored without reporting each',
                    len(self.learned))
        notify.learned_devices([(mac, ifaces, hostname) for mac, (ifaces, hostname) in self.learned.items()])
        self.learned = {}

    def _key(self, mac, iface):
        return (mac, min(network_names(iface))) if self.per_network else mac  # the same for all names

    def is_new(self, mac, iface, present=True):
        """Is the device new? present means its presence was just confirmed (REACHABLE)

        A new device to be reported is pending until device_reported() is called.
        """
        key = self._key(mac, iface)
        with self.lock:
            if key in self.pending:
                return False
            unsaved = key in self.unsaved
        if unsaved:
            self.retry_unsaved()
            return False

        try:
            last_seen = self.storage.seen(mac, network_names(iface), self.per_network)
        except StorageError as e:  # rather reported than missed
            logger.error('Cannot find out whether device %s is known, it is treated as new: %s', mac, e)
        else:
            if last_seen is not None:
                if present:
                    self._touch(mac, iface, last_seen)
                return False

        lease_name = self._static_lease(mac)
        if lease_name is None and not self.learning:
            with self.lock:  # claim, the database is not read under the lock
                if key in self.pending or key in self.unsaved:
                    return False
                self.pending[key] = (mac, iface)
            return True

        # known without a separate notification, stored right away
        hostname = None
        if lease_name is not None:
            logger.info('Device %s has a static DHCP lease, it is known', mac)
        else:
            _, hostname = notify.dnsmasq_lease(mac)
            ifaces, _ = self.learned.setdefault(mac, ([], hostname))
            if iface not in ifaces:
                ifaces.append(iface)
        self._store(key, mac, iface, lease_name or None, hostname)
        return False

    def device_reported(self, device):
        """Store a reported device with its hostname (runs in the notification thread)"""
        key = self._key(device.mac, device.iface)
        storage = self.thread_storage()
        try:
            storage.store(device.mac, device.iface, hostname=device.hostname,
                          aliases=network_names(device.iface)[1:])
        except Exception as e:  # not only StorageError: never unknown again, it would be reported again and again
            self._keep_unsaved(key, e, device.mac, device.iface, hostname=device.hostname)
        else:
            self._store_unsaved(storage)
        finally:
            if storage is not self.storage:
                storage.close()
            with self.lock:
                self.pending.pop(key, None)

    def _store(self, key, mac, iface, name=None, hostname=None):
        try:
            self.storage.store(mac, iface, name, hostname, aliases=network_names(iface)[1:])
        except Exception as e:
            self._keep_unsaved(key, e, mac, iface, name, hostname)
        else:
            self._store_unsaved()

    def _keep_unsaved(self, key, error, mac, iface, name=None, hostname=None):
        logger.error('Cannot record device %s, it will not be reported again until restart: %s', mac, error,
                     exc_info=not isinstance(error, StorageError))
        with self.lock:
            self.unsaved[key] = (mac, iface, name, hostname)

    def _static_lease(self, mac):
        """Return name of static DHCP lease of the device ('' if unnamed), None if there is none"""
        if not self.known_static_leases:
            return None
        try:
            return static_lease(mac)
        except Exception:
            logger.warning('Cannot read static DHCP leases', exc_info=True)
            return None

    def _touch(self, mac, iface, last_seen):
        """Record presence on the network, at most once per LAST_SEEN_INTERVAL

        Counted from the stored time, so that restarting the daemon does not
        write it again for every device present.
        """
        if last_seen and time.time() - last_seen < LAST_SEEN_INTERVAL:
            return
        key = (mac, min(network_names(iface)))  # per network also without per_network
        attempted = self.touch_attempts.get(key)
        if attempted is not None and time.monotonic() - attempted < LAST_SEEN_INTERVAL:
            return  # e.g. the database is not writable
        self.touch_attempts[key] = time.monotonic()
        try:
            self.storage.touch(mac, network_names(iface))
        except StorageError as e:  # not worth more than the next attempt in LAST_SEEN_INTERVAL
            logger.debug('Cannot record that device %s is present: %s', mac, e)
        else:
            self._store_unsaved()

    def retry_unsaved(self):
        """Store devices that could not be stored, if the database works again

        Tried at most once per UNSAVED_RETRY_INTERVAL: when such a device is
        seen again, and from detect_devices() also when no message comes.
        """
        if not self.unsaved:
            return
        now = time.monotonic()
        if self.unsaved_retried is not None and now - self.unsaved_retried < UNSAVED_RETRY_INTERVAL:
            return
        self.unsaved_retried = now
        self._store_unsaved()

    def _store_unsaved(self, storage=None):
        """Database works again, store devices that could not be stored before"""
        with self.lock:
            unsaved = list(self.unsaved.items())
        for key, entry in unsaved:
            mac, iface, name, hostname = entry
            try:
                (storage or self.storage).store(mac, iface, name, hostname, aliases=network_names(iface)[1:])
            except Exception:
                logger.debug('Cannot store device %s yet', mac, exc_info=True)
                return
            with self.lock:
                if self.unsaved.get(key) == entry:  # not replaced meanwhile
                    del self.unsaved[key]


DHCP_CONFIG = '/etc/config/dhcp'
_static_leases = (None, {})  # (version of DHCP_CONFIG, {mac: name})
# values of a boolean uci option meaning off, as for config_get_bool of OpenWrt
OFF = ('0', 'off', 'false', 'no', 'disabled')


def _config_version(path):
    try:
        st = os.stat(path)
    except OSError:
        return None
    return st.st_mtime_ns, st.st_size, st.st_ino


def static_leases():
    """Return {mac: name ('' if unnamed)} of static DHCP leases, read again only after a change"""
    global _static_leases
    version = _config_version(DHCP_CONFIG)
    if version is not None and version == _static_leases[0]:
        return _static_leases[1]

    from euci import EUci
    leases = {}
    with EUci() as uci:
        for section, options in uci.get('dhcp', default={}).items():
            if uci.get('dhcp', section, default='') != 'host':
                continue
            if options.get('enable') in OFF or options.get('ip') == 'ignore':
                continue  # not used by dnsmasq, or DHCP requests of the device are ignored (blocked)
            macs = options.get('mac', ())
            if isinstance(macs, str):
                macs = macs.split()
            for mac in macs:
                leases.setdefault(mac.lower().replace('-', ':'), options.get('name', ''))
    _static_leases = (version, leases)
    return leases


def static_lease(mac):
    """Return name of the static DHCP lease of the MAC address ('' if unnamed), None if there is none"""
    return static_leases().get(mac)


def is_device(message, interfaces):
    """Is the neighbour entry one of a device on a watched interface?

    Applies to the neighbour table scan and to broadcast messages alike. Bridge
    FDB (AF_BRIDGE), proxy, static and NOARP entries are not devices.
    """
    return (
        message.get('family') in (IPV4, IPV6)
        and message.get('ifindex') in interfaces
        and bool(message.get('state', 0) & DEVICE_STATES)
        and not message.get('flags', 0) & NTF_PROXY
    )


def process_netlink_message(message, interfaces, tracker):
    if not is_device(message, interfaces):
        return

    mac = message.get_attr('NDA_LLADDR')
    ip = message.get_attr('NDA_DST')

    # sometimes IP or MAC address is missing in netlink message
    if not mac or not ip:
        return
    if int(mac.split(':')[0], 16) & 0x01:  # multicast or broadcast address
        return

    iface = interfaces[message['ifindex']]
    if tracker.is_new(mac, iface, present=bool(message.get('state', 0) & REACHABLE)):
        new_device_notify(mac, ip, message['family'], iface, on_reported=tracker.device_reported)


def scan_neighbours(scanner, interfaces, tracker):
    """Check devices already present in the neighbour table"""
    for message in scanner.get_neighbours():
        process_netlink_message(message, interfaces, tracker)


def synchronize(scanner, interfaces, watched_interfaces, tracker, attempts=3):
    """Find watched interfaces and check devices already in the neighbour table

    The scanner is a netlink socket that is not subscribed to any broadcast,
    so that the replies do not compete with broadcast messages for buffer
    space (dumps are flow controlled, broadcast messages are not). Learning
    (see DeviceTracker.start_learning) ends with the first complete scan.
    Return False when it failed.
    """
    for attempt in range(1, attempts + 1):
        try:
            current = get_interfaces(scanner, watched_interfaces)
            interfaces.clear()
            interfaces.update(current)
            scan_neighbours(scanner, interfaces, tracker)
        except Exception as e:  # e.g. pyroute2 NetlinkDumpInterrupted when links change meanwhile
            error = e
            logger.debug('Neighbour scan attempt %d failed', attempt, exc_info=True)
        else:
            tracker.finish_learning()
            return True
    logger.warning('Neighbour scan failed, it is repeated later: %s', error)
    return False


def wait_for_messages(ipr, timeout):
    """Wait at most timeout seconds for netlink messages, return whether some came"""
    return bool(select.select([ipr], [], [], timeout)[0])


def detect_devices(ipr, interfaces, watched_interfaces, tracker, scanner, sync_needed=False):
    """Detect new devices from netlink broadcast

    The kernel drops broadcast messages when the receive buffer is full and
    reports it as ENOBUFS. Lost messages are then made up for by scanning the
    neighbour table again, at most once per RESYNC_INTERVAL. A failed scan is
    repeated the same way. Devices that could not be stored are tried again
    also when no message comes.
    """
    last_sync = time.monotonic()
    while True:
        try:
            messages = ipr.get() if wait_for_messages(ipr, UNSAVED_RETRY_INTERVAL) else ()
        except OSError as e:
            if e.errno != errno.ENOBUFS:
                raise
            if not sync_needed:
                logger.warning('Netlink receive buffer overflowed and messages were lost, scanning neighbours again')
            sync_needed = True
            messages = ()

        if sync_needed and time.monotonic() - last_sync >= RESYNC_INTERVAL:
            sync_needed = not synchronize(scanner, interfaces, watched_interfaces, tracker)
            last_sync = time.monotonic()
        tracker.retry_unsaved()

        for message in messages:
            event = message.get('event')

            if event in ('RTM_NEWLINK', 'RTM_DELLINK'):
                update_interfaces(message, interfaces, watched_interfaces)

            # we are interested only in new devices on selected interfaces
            elif event == 'RTM_NEWNEIGH':
                process_netlink_message(message, interfaces, tracker)


def open_storage(db_path):
    """Open database, creating its directory (e.g. on a newly mounted /srv)"""
    try:
        os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
    except OSError as e:
        logger.error('Cannot create directory for %s: %s', db_path, e)
    return DatabaseStorage(db_path)


def read_config(uci):
    return {
        'db_path': uci.get('dev-detect', 'storage', 'db_path', dtype=str, default=DEFAULT_DB_PATH),
        'interfaces': uci.get('dev-detect', 'watchlist', 'ifaces', dtype=str, default=DEFAULT_INTERFACES, list=True),
        'learn_on_empty': uci.get('dev-detect', 'detection', 'learn_on_empty', dtype=bool, default=True),
        'known_static_leases': uci.get('dev-detect', 'detection', 'known_static_leases', dtype=bool, default=True),
        'per_network': uci.get('dev-detect', 'detection', 'per_network', dtype=bool, default=True),
    }


def setup_logging(loglevel):
    logging_format = "%(levelname)s: %(message)s"
    logging.basicConfig(level=loglevel, format=logging_format)
    logger.setLevel(loglevel)


def main():
    # imported here so that the detection logic can be tested without them
    from euci import EUci
    from pyroute2 import IPRoute

    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--debug', help="Show debug messages", action="store_true")

    args = parser.parse_args()

    setup_logging(logging.DEBUG if args.debug else logging.INFO)

    with EUci() as uci:
        config = read_config(uci)
    watched_interfaces = config['interfaces']

    tracker = DeviceTracker(open_storage(config['db_path']), config['known_static_leases'], config['per_network'])
    if config['learn_on_empty']:
        tracker.start_learning()

    with IPRoute() as ipr, IPRoute() as scanner:
        ipr.bind(groups=RTMGRP_NEIGH | RTMGRP_LINK)  # subscribe to netlink broadcast

        interfaces = {}
        synced = synchronize(scanner, interfaces, watched_interfaces, tracker)
        detect_devices(ipr, interfaces, watched_interfaces, tracker, scanner, sync_needed=not synced)


if __name__ == "__main__":
    main()
