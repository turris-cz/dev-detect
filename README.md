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
search <MAC>               Search device by MAC address
add <MAC> [--name NAME]    Mark device as known, so that it is not reported
remove <MAC>               Delete specified MAC address
list                       List known devices
clear                      Clear/reset database
```

Devices become known when they are reported. `list` shows where and when they were first and last seen and their hostname. A device can be marked as known on every network in advance with `add`, `add --name` also names (or renames) a device, and `remove` makes it reported again next time it appears.

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

## Networks

A device is reported when it appears on a watched network for the first time, so that e.g. a device getting from the guest network into the private one is reported too. Devices added by `dev-detect add` (or stored by older versions) are known on every network. To report each device only once, wherever it appears, set:

```
config detection 'detection'
    option per_network '0'
```

## Static DHCP leases

Devices with a static DHCP lease (`config host` in `/etc/config/dhcp`, not disabled and not ignoring the device) are known to the administrator, so they are stored without being reported, named after the lease. To report them as well, set:

```
config detection 'detection'
    option known_static_leases '0'
```

## Empty database

When the device database is empty when the daemon starts (on the first start, or when the service starts after `dev-detect clear` or after the database was lost), devices that are present are stored without reporting each of them, and a single notification lists them. To report each of them instead, set:

```
config detection 'detection'
    option learn_on_empty '0'
```

## Forgetting devices

A device that comes back after a long time can be reported again. Set after how many days a device that was not seen is forgotten (`0`, the default, never forgets):

```
config detection 'detection'
    option forget_after '90'
```

The notification then says how long the device was away:

```
Device back on network lan after 120 days: Mac
```

The time counts from when the device was last seen on the network (on any network with `per_network '0'`). That is recorded at most once per 6 hours, so a device is reported after it was away for the set number of days and up to 6 hours more. Devices added by `dev-detect add` (or stored by older versions) are not forgotten, nor are devices with a static DHCP lease unless `known_static_leases` is `0`. After a restart of the daemon, a device can be reported as back also when the database could not be written for long. A router without RTC has a wrong clock until NTP sets it after a restart; a device seen meanwhile can be reported with fewer days, not at all, or also when it was not away for that long.

## Persistence

Detected devices are stored in sqlite database in order to remember already discovered devices.

By default it is stored in `/srv/dev-detect/dev-detect.db`. `/srv` is on the internal storage, unless the storage plugin moved it to an external disk. The daemon creates the directory when it starts. The internal storage is suitable when you expect small number of devices that appears regularly (e.g. home network, small office).

If you want to enable device detection in network where you could expect lots of different clients connecting through your router, e.g. public Wi-Fi AP, it is recommended to store database either on external persistent storage (flash drive, external HDD) or ramdisk as precaution to wearing out internal storage. The database is written when a device is stored, and when a known device is seen again at most once per 6 hours for each device and network. A database on ramdisk is lost on reboot, so devices are reported again after each reboot as they reconnect (only the few already present when the daemon starts are learned, see Empty database).

Just change `db_path` location in `storage` section.

```
config storage 'storage'
    option db_path   '/path/to/persistent/storage/dev-detect.db'
```

The disk with the database has to be mounted before dev-detect starts, otherwise the directory is created on the internal storage. The storage plugin mounts `/srv` in time.

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
