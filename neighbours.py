#!/usr/bin/env python

import subprocess
import time
import threading

from pyroute2 import IPRoute

# netlink constants
# for details see netlink kernel header files
IPV4 = 2
IPV6 = 10


# use this old code for time being
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


def main():
    known_devices = {}

    # TODO: load already known devices from database

    with IPRoute() as ipr:
        ipr.bind()

        while True:
            messages = ipr.get()

            for message in messages:
                # we are interested only in new devices
                if message['event'] == 'RTM_NEWNEIGH':
                    mac = message.get_attr('NDA_LLADDR')
                    ip = message.get_attr('NDA_DST')

                    if mac not in known_devices:
                        known_devices[mac] = [ip]
                        # TODO: write throught into persistent database

                        new_device_notify(mac, 'lan')

                        if message['family'] == IPV4:
                            ipver = 'v4'
                        elif message['family'] == IPV6:
                            ipver = 'v6'

                        print("New device detected MAC: {} | IP{} address: {}".format(mac, ipver, ip))

                    if ip and ip not in known_devices[mac]:
                        known_devices[mac].append(ip)


if __name__ == "__main__":
    main()
