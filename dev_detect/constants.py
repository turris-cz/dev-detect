# netlink constants from kernel header files

# address family
IPV4 = 2
IPV6 = 10

# rtnetlink multicast groups
RTMGRP_LINK = 0x1
RTMGRP_NEIGH = 0x4

# neighbour (device) state
REACHABLE = 0x02
STALE = 0x04
DELAY = 0x08
PROBE = 0x10
# Entries of devices that are or recently were present. This leaves out
# entries without address (INCOMPLETE, FAILED), NOARP (e.g. multicast) and
# PERMANENT (static) ones.
DEVICE_STATES = REACHABLE | STALE | DELAY | PROBE

# neighbour flags
NTF_PROXY = 0x08
