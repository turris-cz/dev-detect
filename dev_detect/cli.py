import argparse
import re
import sys

from euci import EUci
from .storage import DatabaseStorage


def valid_mac_addr_format(mac):
    pattern = '^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$'
    m = re.match(pattern, mac)

    if not m:
        return False

    return True


def setup_argparser():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(help='action help', dest='action')
    subparsers.required = True

    parser_search = subparsers.add_parser('search', help='Search device by MAC address')
    parser_search.add_argument('mac', help='MAC address of device')

    parser_delete = subparsers.add_parser('remove', help='Delete specified MAC address')
    parser_delete.add_argument('mac', help='MAC address of device')

    subparsers.add_parser('list', help='List known devices')
    subparsers.add_parser('clear', help='Clear/reset database')

    return parser


def list(storage, args):
    print('Known devices:')
    for m in storage.get_known():
        print(m)


def search(storage, args):
    if not valid_mac_addr_format(args.mac):
        print("Incorrect format of MAC address. Please use format 'aa:bb:cc:dd:ee:ff'")
        sys.exit(1)

    res = storage.search(args.mac)
    if res:
        print('Device with MAC address {} is in database'.format(args.mac))
    else:
        print('Device not found')


def remove(storage, args):
    if not valid_mac_addr_format(args.mac):
        print("Incorrect format of MAC address. Please use format 'aa:bb:cc:dd:ee:ff'")
        sys.exit(1)

    storage.remove(args.mac)


def clear(storage, args):
    storage.clear()


action_map = {
    'list': list,
    'search': search,
    'remove': remove,
    'clear': clear
}


def main():
    uci = EUci()
    db_path = uci.get('dev-detect', 'storage', 'db_path', dtype=str, default='/srv/dev-detect/dev-detect.db')

    storage = DatabaseStorage(db_path)

    parser = setup_argparser()
    args = parser.parse_args()

    action_map[args.action](storage, args)


if __name__ == '__main__':
    main()
