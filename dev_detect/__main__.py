import argparse
import logging
import os
import subprocess
import time
import threading

from .constants import IPV4, IPV6, REACHABLE
from .storage import DEFAULT_DB_PATH, DatabaseStorage, StorageError

logger = logging.getLogger(__name__)

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

    return interfaces


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
            self._retry_unsaved()
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

    def _retry_unsaved(self):
        """A device that could not be stored is still present, store it if the database works again

        Tried at most once per UNSAVED_RETRY_INTERVAL, not for every message.
        """
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


def process_netlink_message(message, interfaces, tracker):
    mac = message.get_attr('NDA_LLADDR')
    ip = message.get_attr('NDA_DST')

    # sometimes IP or MAC address is missing in netlink message
    if not mac or not ip:
        return

    if tracker.is_new(mac):
        # interfaces are there just to conform to notify shell script interface
        # TODO: use interface name elsewhere? omit it in notifications completely?
        new_device_notify(mac, ip, message['family'], interfaces[message['ifindex']])


def get_neigbours_from_arp(ipr, interfaces, tracker):
    """Explicit query ARP table for reachable devices on selected interfaces"""
    for nic in interfaces:
        devices = ipr.get_neighbours(ifindex=nic)

        for dev in filter(lambda dev: dev['state'] == REACHABLE, devices):
            process_netlink_message(dev, interfaces, tracker)


def detect_devices(ipr, interfaces, tracker):
    """Detect new devices from netlink broadcast"""
    while True:
        for message in ipr.get():
            if 'ifindex' not in message:  # missing interface
                continue

            # we are interested only in new devices on selected interfaces
            if message['event'] == 'RTM_NEWNEIGH' and message['ifindex'] in interfaces:
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
            default=('br-lan', 'br-guest_turris'),
            list=True
        )

    tracker = DeviceTracker(open_storage(db_path))

    with IPRoute() as ipr:
        ipr.bind()  # subscribe to netlink broadcast

        interfaces = get_interfaces(ipr, watched_interfaces)
        get_neigbours_from_arp(ipr, interfaces, tracker)
        detect_devices(ipr, interfaces, tracker)


if __name__ == "__main__":
    main()
