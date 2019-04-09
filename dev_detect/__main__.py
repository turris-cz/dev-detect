import argparse
import logging
import subprocess
import time
import threading

from pyroute2 import IPRoute

logger = logging.getLogger(__name__)

# netlink constants
# for details see netlink kernel header files
IPV4 = 2
IPV6 = 10

# default watched interfaces
# TODO: get list from uci?
watched_interfaces = ['br-lan']


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


def get_interfaces(ipr):
    active_interfaces = {}
    links = ipr.get_links()

    for l in links:
        ifname = l.get_attr('IFLA_IFNAME')

        # TODO: check if interface is also up
        if ifname in watched_interfaces:
            active_interfaces[l['index']] = ifname

    return active_interfaces


def ip_version(address_family):
    if address_family == IPV4:
        return '4'
    elif address_family == IPV6:
        return '6'

    return None


def detect_devices(ipr, interfaces, known_devices):
    while True:
        messages = ipr.get()

        for message in messages:
            # we are interested only in new devices on selected interfaces
            if message['ifindex'] in interfaces and message['event'] == 'RTM_NEWNEIGH':
                mac = message.get_attr('NDA_LLADDR')
                ip = message.get_attr('NDA_DST')

                # sometimes IP or MAC address is missing in netlink message
                if not mac or not ip:
                    continue

                if mac not in known_devices:
                    known_devices[mac] = [ip]
                    # TODO: write throught into persistent database

                    new_device_notify(mac, interfaces[message['ifindex']])

                    logger.info("New device detected MAC: %s | IPv%s address: %s", mac, ip_version(message), ip)

                if ip not in known_devices[mac]:
                    known_devices[mac].append(ip)


def main():
    logging.basicConfig()

    known_devices = {}
    # TODO: load already known devices from database

    with IPRoute() as ipr:
        ipr.bind()  # subscribe to netlink broadcast

        interfaces = get_interfaces()
        detect_devices(ipr, interfaces, known_devices)


if __name__ == "__main__":
    main()
