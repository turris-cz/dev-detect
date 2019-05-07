## Network device detection

Dev-detect is network device detection daemon inspired by now deprecated `pakon-dev-detect`. It is written from scratch using netlink as source of events on network.

Dependencies:
* python3-pyroute2 - pure python netlink library
* python3-logging
* python3-sqlite3
* python3-uci
* ouidb - get device vendors based on MAC address

Package ships reasonable defaults for turris routers, however users can customize daemon behavior or scope of it's operation in `uci` config file (`/etc/config/dev-detect`).

There is no foris settings tab yet, so any changes has to be done manually.

### Persistence

`dev-detect` store detected devices into sqlite database in order to remember already discovered devices in case of service restart. As precaution to wearing out internal storage, database is by default located in RAM, thus will not survive reboot.

This behavior is suitable for network where you can expect lots of different clients connecting through your router, e.g. public Wi-Fi AP.

If you expect small number of devices that appears regularly (e.g. home network, small office), you can store known devices permanently. Just change `db_path` to location on persistent storage (flash drive, external HDD).

```
config storage 'storage'
    option db_path   '/path/to/persistent/storage/dev-detect.db'
```

### Watch list

By default `dev-detect` only detect devices on internal lan bridge (`br-lan`), however it can be configured to check multiple interfaces.

To add another network interface to watch list, append `list ifaces <interface>` line to `watchlist` section.


For example: `eth1`
```
config watchlist 'watchlist'
        [...]
        list ifaces 'eth1'
```
