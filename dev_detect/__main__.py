import argparse
import errno
import logging
import os
import select
import subprocess
import time
import threading

from .constants import DEVICE_STATES, IPV4, IPV6, NTF_PROXY, RTMGRP_LINK, RTMGRP_NEIGH
from .storage import DEFAULT_DB_PATH, DatabaseStorage, StorageError

logger = logging.getLogger(__name__)

# br-guest_turris is the guest bridge on systems migrated from Turris OS 5
DEFAULT_INTERFACES = ('br-lan', 'br-guest-turris', 'br-guest_turris')

# minimal time in seconds between neighbour table scans after lost messages
RESYNC_INTERVAL = 30

# how often to try storing devices that could not be stored, in seconds
UNSAVED_RETRY_INTERVAL = 15 * 60

ADDRMAP = {
    IPV4: '4',
    IPV6: '6'
}


# Use this old code from pakon-dev-detect for time being.
# dev-detect will probably get packaged and shipped to users sooner than notification system,
# therefore I guess it is better to use this old function for now than rewritting it
# piece by piece and then throwing it away later anyway.
#
# Notifications are created in external shell script and this is basically wrapper for it.
# TODO: drop this function and use new notification system instead
def new_device_notify(mac, ip, addr_family, iface):
    def new_device_notify_thread(mac, iface):
        time.sleep(5)
        try:
            cmd = ["/usr/libexec/notify_new_device.sh", mac, iface]
            subprocess.call([arg.encode('utf-8') for arg in cmd])
        except OSError:
            print("failed to create notification")

    logger.info("New device detected on interface '%s'. MAC: %s | IPv%s address: %s",
                iface, mac, ADDRMAP.get(addr_family), ip)

    thread = threading.Thread(target=new_device_notify_thread, args=(mac, iface, ))
    thread.daemon = True
    thread.start()


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
    """
    def __init__(self, storage):
        self.storage = storage
        self.unsaved = set()
        self.unsaved_retried = None  # when storing unsaved devices was last tried (monotonic)

    def is_new(self, mac):
        if mac in self.unsaved:
            self.retry_unsaved()
            return False

        try:
            if self.storage.search(mac):
                return False
            self.storage.store(mac)
        except StorageError as e:
            logger.error('Cannot record device %s, it will not be reported again until restart: %s', mac, e)
            self.unsaved.add(mac)
        else:
            self._store_unsaved()
        return True

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

    def _store_unsaved(self):
        """Database works again, store devices that could not be stored before"""
        for mac in list(self.unsaved):
            try:
                self.storage.store(mac)
            except StorageError:
                return
            self.unsaved.discard(mac)


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

    if tracker.is_new(mac):
        # interfaces are there just to conform to notify shell script interface
        # TODO: use interface name elsewhere? omit it in notifications completely?
        new_device_notify(mac, ip, message['family'], interfaces[message['ifindex']])


def scan_neighbours(scanner, interfaces, tracker):
    """Check devices already present in the neighbour table"""
    for message in scanner.get_neighbours():
        process_netlink_message(message, interfaces, tracker)


def synchronize(scanner, interfaces, watched_interfaces, tracker, attempts=3):
    """Find watched interfaces and check devices already in the neighbour table

    The scanner is a netlink socket that is not subscribed to any broadcast,
    so that the replies do not compete with broadcast messages for buffer
    space (dumps are flow controlled, broadcast messages are not). Return
    False when it failed.
    """
    for attempt in range(1, attempts + 1):
        try:
            current = get_interfaces(scanner, watched_interfaces)
            interfaces.clear()
            interfaces.update(current)
            scan_neighbours(scanner, interfaces, tracker)
            return True
        except Exception as e:  # e.g. pyroute2 NetlinkDumpInterrupted when links change meanwhile
            error = e
            logger.debug('Neighbour scan attempt %d failed', attempt, exc_info=True)
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
        db_path = uci.get(
            'dev-detect', 'storage', 'db_path',
            dtype=str,
            default=DEFAULT_DB_PATH
        )
        watched_interfaces = uci.get(
            'dev-detect', 'watchlist', 'ifaces',
            dtype=str,
            default=DEFAULT_INTERFACES,
            list=True
        )

    tracker = DeviceTracker(open_storage(db_path))

    with IPRoute() as ipr, IPRoute() as scanner:
        ipr.bind(groups=RTMGRP_NEIGH | RTMGRP_LINK)  # subscribe to netlink broadcast

        interfaces = {}
        synced = synchronize(scanner, interfaces, watched_interfaces, tracker)
        detect_devices(ipr, interfaces, watched_interfaces, tracker, scanner, sync_needed=not synced)


if __name__ == "__main__":
    main()
