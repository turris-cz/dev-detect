import argparse
import os
import sqlite3
import sys
import types

import pytest

from dev_detect import cli
from dev_detect.storage import DatabaseStorage

MAC = 'aa:bb:cc:dd:ee:ff'


@pytest.mark.parametrize('value', [
    'aa:bb:cc:dd:ee:ff',
    'AA:BB:CC:DD:EE:FF',
    'aa-bb-cc-dd-ee-ff',
    'Aa-Bb-Cc-Dd-Ee-Ff',
    ' aa:bb:cc:dd:ee:ff\n',
])
def test_mac_address_is_normalized(value):
    assert cli.mac_address(value) == MAC


@pytest.mark.parametrize('value', [
    'aa:bb-cc:dd-ee:ff',
    'aabbccddeeff',
    'aa:bb:cc:dd:ee',
    'aa:bb:cc:dd:ee:ff:00',
    'gg:bb:cc:dd:ee:ff',
    '',
])
def test_invalid_mac_address(value):
    with pytest.raises(argparse.ArgumentTypeError):
        cli.mac_address(value)


@pytest.fixture
def storage(tmp_path):
    storage = DatabaseStorage(str(tmp_path / 'dev-detect.db'))
    storage.add(MAC)  # the daemon stores lower-case colon separated addresses
    yield storage
    storage.close()


def run(storage, *argv):
    args = cli.setup_argparser().parse_args(argv)
    cli.action_map[args.action](storage, args)


def test_search_in_other_format(storage, capsys):
    run(storage, 'search', 'AA-BB-CC-DD-EE-FF')
    assert 'is in database' in capsys.readouterr().out


def test_search_unknown_device(storage, capsys):
    with pytest.raises(SystemExit) as excinfo:
        run(storage, 'search', '00:11:22:33:44:55')
    assert excinfo.value.code == 1
    assert 'Device not found' in capsys.readouterr().out


def test_remove_in_other_format(storage):
    run(storage, 'remove', 'AA:BB:CC:DD:EE:FF')
    assert storage.get_known() == []


def test_remove_unknown_device(storage, capsys):
    with pytest.raises(SystemExit) as excinfo:
        run(storage, 'remove', '00:11:22:33:44:55')
    assert excinfo.value.code == 1
    assert 'Device not found' in capsys.readouterr().out
    assert storage.get_known() == [MAC]


class FakeEUci:
    """Stand-in for euci.EUci returning db_path from FakeEUci.db_path"""
    db_path = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def get(self, config, section, option, dtype=str, default=None, list=False):
        assert (config, section, option) == ('dev-detect', 'storage', 'db_path')
        return self.db_path


@pytest.fixture
def uci(tmp_path, monkeypatch):
    FakeEUci.db_path = str(tmp_path / 'dev-detect.db')
    monkeypatch.setitem(sys.modules, 'euci', types.SimpleNamespace(EUci=FakeEUci))
    return FakeEUci


@pytest.mark.parametrize('argv, code', [(['--help'], 0), (['remove', 'not-a-mac'], 2), ([], 2)])
def test_database_is_not_touched_for_help_or_invalid_arguments(uci, argv, code):
    with pytest.raises(SystemExit) as excinfo:
        cli.main(argv)
    assert excinfo.value.code == code
    assert not os.path.exists(uci.db_path)


def test_main(uci, capsys):
    cli.main(['list'])
    assert capsys.readouterr().out.split() == ['MAC', 'ADDRESS', 'NAME', 'INTERFACE', 'FIRST', 'SEEN', 'LAST', 'SEEN', 'HOSTNAME']


def test_list(storage, capsys):
    storage.store('02:00:00:00:00:01', 'br-lan', hostname='printer')
    run(storage, 'list')
    lines = capsys.readouterr().out.splitlines()

    assert lines[1].split()[:3] == [MAC, '-', '*']  # known on every interface
    assert lines[2].split()[:3] == ['02:00:00:00:00:01', '-', 'br-lan']
    assert lines[2].split()[-1] == 'printer'


@pytest.mark.skipif(os.geteuid() == 0, reason='file permissions do not apply to root')
def test_list_read_only_database_of_older_version(uci, capsys):
    conn = sqlite3.connect(uci.db_path)
    conn.execute('CREATE TABLE known_devices (mac text UNIQUE)')
    conn.execute("INSERT INTO known_devices (mac) VALUES ('aa:bb:cc:dd:ee:ff')")
    conn.commit()
    conn.close()
    os.chmod(uci.db_path, 0o444)

    cli.main(['list'])
    assert capsys.readouterr().out.splitlines()[1].split() == [MAC, '-', '*', '-', '-', '-']


def test_add(storage, capsys):
    run(storage, 'add', '02-00-00-00-00-AA', '--name', 'printer')
    run(storage, 'add', MAC)
    run(storage, 'list')
    out = capsys.readouterr().out

    assert storage.search('02:00:00:00:00:aa')
    assert 'Device aa:bb:cc:dd:ee:ff is already known' in out
    assert ['02:00:00:00:00:aa', 'printer', '*'] in [line.split()[:3] for line in out.splitlines()]


def test_add_name_to_known_device(storage, capsys):
    storage.store('02:00:00:00:00:01', 'br-lan')
    run(storage, 'add', '02:00:00:00:00:01', '--name', 'printer')
    run(storage, 'add', MAC, '--name', 'laptop')
    run(storage, 'list')
    out = capsys.readouterr().out

    assert 'already known' not in out
    assert [line.split()[:3] for line in out.splitlines()[1:]] == [
        [MAC, 'laptop', '*'], ['02:00:00:00:00:01', 'printer', '*'], ['02:00:00:00:00:01', 'printer', 'br-lan'],
    ]
