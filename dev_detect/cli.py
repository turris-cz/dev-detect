import argparse
import re
import sys

from .storage import DEFAULT_DB_PATH, DatabaseStorage, StorageError

MAC_PATTERN = re.compile(r'[0-9a-f]{2}([:-])[0-9a-f]{2}(\1[0-9a-f]{2}){4}')


def mac_address(value):
    """Validate MAC address and return it in the form stored by the daemon (aa:bb:cc:dd:ee:ff)"""
    mac = value.strip().lower()
    if not MAC_PATTERN.fullmatch(mac):
        raise argparse.ArgumentTypeError(
            "invalid MAC address '{}', use format 'aa:bb:cc:dd:ee:ff'".format(value)
        )
    return mac.replace('-', ':')


def setup_argparser():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(help='action help', dest='action')
    subparsers.required = True

    parser_search = subparsers.add_parser('search', help='Search device by MAC address')
    parser_search.add_argument('mac', type=mac_address, help='MAC address of device')

    parser_delete = subparsers.add_parser('remove', help='Delete specified MAC address')
    parser_delete.add_argument('mac', type=mac_address, help='MAC address of device')

    subparsers.add_parser('list', help='List known devices')
    subparsers.add_parser('clear', help='Clear/reset database')

    return parser


def list_devices(storage, args):
    print('Known devices:')
    for m in storage.get_known():
        print(m)


def search(storage, args):
    if storage.search(args.mac):
        print('Device with MAC address {} is in database'.format(args.mac))
    else:
        print('Device not found')
        sys.exit(1)


def remove(storage, args):
    if not storage.remove(args.mac):
        print('Device not found')
        sys.exit(1)


def clear(storage, args):
    storage.clear()


action_map = {
    'list': list_devices,
    'search': search,
    'remove': remove,
    'clear': clear
}


def main(argv=None):
    args = setup_argparser().parse_args(argv)

    from euci import EUci  # imported here so that the CLI can be tested without it
    with EUci() as uci:
        db_path = uci.get('dev-detect', 'storage', 'db_path', dtype=str, default=DEFAULT_DB_PATH)

    storage = DatabaseStorage(db_path)
    try:
        action_map[args.action](storage, args)
    except StorageError as e:
        print('Error: {}'.format(e), file=sys.stderr)
        sys.exit(1)
    finally:
        storage.close()


if __name__ == '__main__':
    main()
