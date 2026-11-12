# Network device detection

Dev-detect is network device detection daemon inspired by now deprecated `pakon-dev-detect`. It is written from scratch using netlink as source of events on network.

Dependencies:
* python3-pyroute2 - pure python netlink library
* python3-logging
* python3-sqlite3
* python3-uci
* ouidb - get device vendors based on MAC address
* create_notification (user-notify) - create notifications

Package ships reasonable defaults for turris routers, however users can customize daemon behavior or scope of it's operation in `uci` config file (`/etc/config/dev-detect`).

## CLI client 

Package include simple cli interface called `dev-detect` to interact with device database.

You can use one of following commands:
```
search <MAC>        Search device by MAC address
remove <MAC>        Delete specified MAC address
list                List known devices
clear               Clear/reset database
```

For full options see help:
```
dev-detect --help
```

## Notifications

New devices are reported through the Turris notification system (reForis, e-mail, ntfy), with all addresses the device uses and the hostname from its DHCP lease:

```
New device on network lan: Mac
MAC address: 3e:f1:18:4d:d9:23 (randomized address, vendor unknown)
IPv4: 192.168.1.50
IPv6: 2a00:1028:8388:a84e:a1a4:8dbf:7ab8:e5ac
```

The notification is created once the hostname is known, usually 5 to 10 seconds after the device appears. A device without a hostname is reported after about half a minute.

The vendor is looked up by `ouidb`. Devices using a private (randomized) MAC address have no vendor and may be reported again when their address changes.

A device is stored as known once its notification is created, or once creating it failed (the error is logged, and the device is not reported again). If the daemon stops before (restart, crash, reboot), the device is reported again after it starts. When the database cannot be written, reported devices are kept in memory and stored once it works again, so they are not reported repeatedly; only a restart of the daemon meanwhile makes them reported again.

## Persistence

Detected devices are stored in sqlite database in order to remember already discovered devices.

By default it is stored on internal storage, which is suitable when you expect small number of devices that appears regularly (e.g. home network, small office). 

If you want to enable device detection in network where you could expect lots of different clients connecting through your router, e.g. public Wi-Fi AP, it is recommended to store database either on external persistent storage (flash drive, external HDD) or ramdisk as precaution to wearing out internal storage.

Just change `db_path` location in `storage` section.

```
config storage 'storage'
    option db_path   '/path/to/persistent/storage/dev-detect.db'
```

## Watch list

By default `dev-detect` only detect devices on internal lan bridges (`br-lan` and the guest network bridge `br-guest-turris`, or `br-guest_turris` on systems migrated from Turris OS 5), however it can be configured to check multiple interfaces.

Interfaces that do not exist yet are watched as soon as they appear, and an interface that is re-created (e.g. on network restart) keeps being watched.

To add another network interface to watch list, append `list ifaces <interface>` line to `watchlist` section.


For example: `eth1`
```
config watchlist 'watchlist'
        [...]
        list ifaces 'eth1'
```
