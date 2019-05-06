import argparse
import logging
import subprocess
import time
import threading

from euci import EUci
from pyroute2 import IPRoute

from .storage import Storage

logger = logging.getLogger(__name__)

# netlink constants
# for details see netlink kernel header files
IPV4 = 2
IPV6 = 10

REACHABLE = 2


# use this old code for time being
# TODO: use new notification system
def new_device_notify(mac, iface):
    def new_device_notify_thread(mac, iface):
        time.sleep(5)
        try:
            cmd = ["/usr/libexec/notify_new_device.sh", mac, iface]
            subprocess.call([arg.encode('utf-8') for arg in cmd])
        except OSError:
            print("failed to create notification")
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


def ip_version(address_family):
    if address_family == IPV4:
        return '4'
    elif address_family == IPV6:
        return '6'

    return None


def process_netlink_message(message, interfaces, storage):
    mac = message.get_attr('NDA_LLADDR')
    ip = message.get_attr('NDA_DST')

    # sometimes IP or MAC address is missing in netlink message
    if not mac or not ip:
        return

    if mac not in storage.get_known():
        storage.write_new(mac)

        new_device_notify(mac, interfaces[message['ifindex']])

        logger.info("New device detected MAC: %s | IPv%s address: %s", mac, ip_version(message), ip)


def get_neigbours_from_arp(ipr, interfaces, storage):
    """Explicit query ARP table for reachable devices on selected interfaces"""
    for nic in interfaces:
        devices = ipr.get_neighbours(ifindex=nic)

        for dev in devices:
            if dev['state'] == REACHABLE:
                process_netlink_message(dev, interfaces, storage)


def detect_devices(ipr, interfaces, storage):
    """Detect new devices from netlink broadcast"""
    while True:
        for message in ipr.get():
            if 'ifindex' not in message:  # missing interface
                continue

            # we are interested only in new devices on selected interfaces
            if message['event'] == 'RTM_NEWNEIGH' and message['ifindex'] in interfaces:
                process_netlink_message(message, interfaces, storage)


def setup_logging(loglevel=logging.INFO):
    logging_format = "%(levelname)s: %(message)s"
    logging.basicConfig(level=loglevel, format=logging_format)
    logger.setLevel(loglevel)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--debug', help="Show debug messages", action="store_true")

    args = parser.parse_args()

    if args.debug:
        setup_logging(logging.DEBUG)
    else:
        setup_logging()

    uci = EUci()

    db_path = uci.get('dev-detect.storage.db_path')
    watched_interfaces = uci.get('dev-detect.watchlist.ifaces')

    storage = Storage(db_path)

    with IPRoute() as ipr:
        interfaces = get_interfaces(ipr, watched_interfaces)
        get_neigbours_from_arp(ipr, interfaces, storage)

        ipr.bind()  # subscribe to netlink broadcast

        detect_devices(ipr, interfaces, storage)


if __name__ == "__main__":
    main()
