# Network device detection

Dev-detect is network device detection daemon inspired by now deprecated `pakon-dev-detect`. It is written from scratch using netlink as source of events on network.

Dependencies:
* python3-pyroute2 - pure python netlink library
* python3-logging
* python3-sqlite3
* python3-uci
* ouidb - get device vendors based on MAC address

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

By default `dev-detect` only detect devices on internal lan bridges (`br-lan`, `br-guest_turris`), however it can be configured to check multiple interfaces.

To add another network interface to watch list, append `list ifaces <interface>` line to `watchlist` section.


For example: `eth1`
```
config watchlist 'watchlist'
        [...]
        list ifaces 'eth1'
```
