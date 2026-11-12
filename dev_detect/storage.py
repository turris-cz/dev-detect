import logging
import os
import sqlite3
import time

logger = logging.getLogger(__name__)

DEFAULT_DB_PATH = '/srv/dev-detect/dev-detect.db'

# Version 0 is the database of dev-detect 0.3.1: a known_devices table with MAC
# addresses only.
SCHEMA_VERSION = 1
SCHEMA = [
    # identity of a device: name given by the user, hostname from its DHCP
    # lease and whether it is known on every network (dev-detect add, 0.3.1)
    "CREATE TABLE IF NOT EXISTS devices ("
    " mac TEXT PRIMARY KEY, name TEXT, hostname TEXT, everywhere INTEGER NOT NULL DEFAULT 0)",
    # networks (interfaces) the device was seen on, and when
    "CREATE TABLE IF NOT EXISTS device_networks ("
    " mac TEXT NOT NULL REFERENCES devices (mac), iface TEXT NOT NULL,"
    " first_seen INTEGER NOT NULL, last_seen INTEGER, PRIMARY KEY (mac, iface))",
]
TABLES = {'devices', 'device_networks'}
LEGACY_TABLE = 'known_devices'


class StorageError(Exception):
    """The database of known devices cannot be read or written."""


def _describe(exc):
    """Return SQLite error as precise as the Python version allows."""
    name = getattr(exc, 'sqlite_errorname', None)  # Python 3.11+
    return '{}: {}'.format(name, exc) if name else str(exc)


def _schema_changed(exc):
    """Was the database changed behind our back, e.g. by restoring a backup into the file?"""
    message = str(exc)
    return 'no such column' in message or 'has no column named' in message or 'no such table' in message


def _placeholders(values):
    return ', '.join('?' * len(values))


class DatabaseStorage:
    """Database storage of known devices

    The file at db_path is the source of truth. The connection is reopened
    when that file is no longer the one that was opened (it was deleted,
    replaced or another filesystem was mounted over its directory), and once
    after a write failed because the database was read-only or changed.

    The directory of db_path is never created here, so that reopening the
    database does not create a new one in an empty mount point (e.g. unmounted
    /srv). The daemon creates the directory once at start.

    A database of dev-detect 0.3.1 that cannot be upgraded now (read-only,
    locked by another process, disk full) can still be read; its devices are
    known on every network. The upgrade is tried again before each write.

    Every method changes the database in a single transaction. All failures
    are reported as StorageError.
    """
    def __init__(self, db_path):
        self.db_path = db_path
        self.conn = None
        self._file_id = None
        self._legacy = False  # reading a database of 0.3.1 that could not be upgraded
        self._upgrade_error = None

    def close(self):
        if self.conn is not None:
            self.conn.close()
            self.conn = None

    def _current_file_id(self):
        try:
            st = os.stat(self.db_path)
        except OSError:
            return None
        return st.st_dev, st.st_ino

    def _error(self, exc):
        return StorageError('{}: {}'.format(self.db_path, _describe(exc)))

    @staticmethod
    def _tables(conn, strict=True):
        try:
            return {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        except sqlite3.DatabaseError:
            if strict:
                raise
            return set()

    def _open(self):
        self.close()
        file_id = self._current_file_id()  # before connecting, so that a replacement meanwhile is noticed
        try:
            conn = sqlite3.connect(self.db_path)
            conn.execute('PRAGMA foreign_keys = ON')  # per connection, SQLite does not enforce them by default
        except sqlite3.DatabaseError as e:
            raise self._error(e) from e

        self._upgrade_error = None
        try:
            self._prepare(conn)
        except sqlite3.DatabaseError as e:
            tables = self._tables(conn, strict=False)
            if not (TABLES <= tables or LEGACY_TABLE in tables):
                conn.close()
                raise self._error(e) from e
            self._upgrade_error = _describe(e)
            logger.warning('%s cannot be upgraded now: %s', self.db_path, self._upgrade_error)

        tables = self._tables(conn, strict=False)
        self.conn = conn
        self._file_id = file_id or self._current_file_id()
        self._legacy = not TABLES <= tables and LEGACY_TABLE in tables

    @classmethod
    def _prepare(cls, conn):
        """Create the tables or upgrade the database to the current schema"""
        version = conn.execute('PRAGMA user_version').fetchone()[0]
        tables = cls._tables(conn)
        if version > SCHEMA_VERSION and LEGACY_TABLE not in tables:
            return  # created by a newer version of dev-detect
        if version == SCHEMA_VERSION and TABLES <= tables and LEGACY_TABLE not in tables:
            return
        isolation_level = conn.isolation_level
        conn.isolation_level = None  # explicit transaction, not mixed with the implicit ones
        try:
            conn.execute('BEGIN IMMEDIATE')  # the daemon and the CLI may open it at the same time
            try:
                cls._upgrade(conn)
                conn.execute('COMMIT')
            except BaseException:
                if conn.in_transaction:
                    conn.execute('ROLLBACK')
                raise
        finally:
            conn.isolation_level = isolation_level

    @classmethod
    def _upgrade(cls, conn):
        """Create missing tables and move devices of dev-detect 0.3.1 over

        Decided by the tables present, not by the version only, so that e.g. a
        database restored from an SQL dump, which carries no version, keeps its
        data and a damaged one is repaired.
        """
        for statement in SCHEMA:
            conn.execute(statement)
        if LEGACY_TABLE in cls._tables(conn):
            # they stay known on every network, as before
            conn.execute(
                'INSERT OR IGNORE INTO devices (mac, everywhere)'
                ' SELECT mac, 1 FROM known_devices WHERE mac IS NOT NULL ORDER BY rowid'
            )
            conn.execute('DROP TABLE known_devices')
        conn.execute('PRAGMA user_version = {:d}'.format(SCHEMA_VERSION))

    def _connection(self):
        """Return connection to the database file that is currently at db_path."""
        if self.conn is not None and self._current_file_id() == self._file_id:
            return self.conn
        if self.conn is not None:
            logger.warning('%s was replaced or removed, reopening it', self.db_path)
        self._open()
        return self.conn

    def _read(self, query):
        """Return rows of query(), a function returning (sql, params) for the schema of the opened file"""
        for attempt in (1, 2):
            conn = self._connection()
            sql, params = query()
            try:
                return conn.execute(sql, params).fetchall()
            except sqlite3.DatabaseError as e:
                if attempt == 1 and _schema_changed(e):
                    logger.warning('%s: %s, reopening it', self.db_path, _describe(e))
                    self._open()
                    continue
                raise self._error(e) from e

    def _write(self, statements):
        """Execute (sql, params) statements in one transaction and return their row counts"""
        for attempt in (1, 2):
            conn = self._connection()
            if self._upgrade_error:
                self._open()  # the upgrade may be possible now
                conn = self.conn
                if self._upgrade_error:
                    raise StorageError('{}: cannot be upgraded: {}'.format(self.db_path, self._upgrade_error))
            try:
                with conn:  # commit, or roll back so that no lock is left behind
                    return [conn.execute(sql, params).rowcount for sql, params in statements]
            except sqlite3.DatabaseError as e:
                self._rollback(conn)
                if attempt == 1 and ('READONLY' in _describe(e).upper() or _schema_changed(e)):
                    # It might have been opened while it was not writable.
                    logger.warning('%s: %s, reopening it', self.db_path, _describe(e))
                    self._open()
                    continue
                raise self._error(e) from e

    @staticmethod
    def _rollback(conn):
        """Python < 3.9.7 leaves the transaction open when COMMIT fails"""
        try:
            if conn.in_transaction:
                conn.rollback()
        except sqlite3.Error:
            pass

    def store(self, mac, iface, name=None, hostname=None, aliases=()):
        """Store device seen on the interface. Return False if it was already stored on the network.

        aliases are other names of the network on the interface.
        """
        now = int(time.time())
        ifaces = (iface,) + tuple(aliases)
        statements = [('INSERT OR IGNORE INTO devices (mac, name, hostname) VALUES (?, ?, ?)', (mac, name, hostname))]
        if name is not None or hostname is not None:
            statements.append((
                'UPDATE devices SET name=COALESCE(name, ?), hostname=COALESCE(?, hostname) WHERE mac=?',
                (name, hostname, mac),
            ))
        statements.append((
            'INSERT OR IGNORE INTO device_networks (mac, iface, first_seen, last_seen) SELECT ?, ?, ?, ?'
            ' WHERE NOT EXISTS (SELECT 1 FROM device_networks WHERE mac=? AND iface IN ({}))'
            .format(_placeholders(ifaces)),
            (mac, iface, now, now, mac) + ifaces,
        ))
        return self._write(statements)[-1] == 1

    def touch(self, mac, ifaces):
        """Record that the known device is present on the network now

        ifaces are the names of the network, the first one is the interface
        the device is on.
        """
        now = int(time.time())
        ifaces = tuple(ifaces)
        self._write([
            (
                # first time on this network, e.g. a device known on every network
                'INSERT INTO device_networks (mac, iface, first_seen, last_seen) SELECT ?, ?, ?, ?'
                ' WHERE EXISTS (SELECT 1 FROM devices WHERE mac=?)'
                ' AND NOT EXISTS (SELECT 1 FROM device_networks WHERE mac=? AND iface IN ({}))'
                .format(_placeholders(ifaces)),
                (mac, ifaces[0], now, now, mac, mac) + ifaces,
            ),
            (
                # never back, e.g. with a clock that is behind before NTP sets it
                'UPDATE device_networks SET last_seen=? WHERE mac=? AND iface IN ({})'
                ' AND (last_seen IS NULL OR last_seen < ?)'.format(_placeholders(ifaces)),
                (now, mac) + ifaces + (now,),
            ),
        ])

    def add(self, mac, name=None):
        """Mark device as known on every network, name it if name is given. Return False if it already was known."""
        statements = [
            ('UPDATE devices SET everywhere=1 WHERE mac=? AND NOT everywhere', (mac,)),
            ('INSERT OR IGNORE INTO devices (mac, name, everywhere) VALUES (?, ?, 1)', (mac, name)),
        ]
        if name is not None:
            statements.append(('UPDATE devices SET name=? WHERE mac=?', (name, mac)))
        updated, inserted = self._write(statements)[:2]
        return updated + inserted > 0

    def seen(self, mac, ifaces, per_network=True):
        """Return when the device was last seen on the network (ifaces are its names), None if it is unknown

        A known device that has not been seen on the network yet gives 0. With
        per_network, a device is known on the network only when it was seen on
        it or is known on every network.
        """
        ifaces = tuple(ifaces)

        def query():
            if self._legacy:  # devices of 0.3.1 are known everywhere
                return 'SELECT 1, NULL, NULL FROM known_devices WHERE mac=?', (mac,)
            return (
                'SELECT d.everywhere, n.iface, n.last_seen FROM devices d'
                ' LEFT JOIN device_networks n ON n.mac = d.mac AND n.iface IN ({}) WHERE d.mac=?'
                .format(_placeholders(ifaces)),
                ifaces + (mac,),
            )
        rows = self._read(query)
        if not rows:
            return None
        if per_network and not any(everywhere or iface is not None for everywhere, iface, _ in rows):
            return None
        return max(last_seen or 0 for _, _, last_seen in rows)

    def search(self, mac):
        """Is the device known (on any network)?"""
        return bool(self._read(lambda: (
            'SELECT 1 FROM {} WHERE mac=?'.format(LEGACY_TABLE if self._legacy else 'devices'), (mac,)
        )))

    def get_known(self):
        return [row[0] for row in self._read(lambda: (
            'SELECT mac FROM {} ORDER BY rowid'.format(LEGACY_TABLE if self._legacy else 'devices'), ()
        ))]

    def is_empty(self):
        return not self._read(lambda: (
            'SELECT 1 FROM {} LIMIT 1'.format(LEGACY_TABLE if self._legacy else 'devices'), ()
        ))

    def devices(self):
        """Return (mac, name, iface, first_seen, last_seen, hostname) of all known devices

        iface is '' for a device known on every network.
        """
        self._connection()  # schema of the current file
        if self._legacy:
            return [(mac, None, '', None, None, None) for mac in self.get_known()]
        devices = self._read(lambda: ('SELECT mac, name, hostname, everywhere FROM devices ORDER BY rowid', ()))
        networks = {}
        for mac, iface, first_seen, last_seen in self._read(lambda: (
            'SELECT mac, iface, first_seen, last_seen FROM device_networks ORDER BY first_seen, rowid', ()
        )):
            networks.setdefault(mac, []).append((iface, first_seen, last_seen))
        rows = []
        for mac, name, hostname, everywhere in devices:
            if everywhere or mac not in networks:
                rows.append((mac, name, '', None, None, hostname))
            for iface, first_seen, last_seen in networks.get(mac, ()):
                rows.append((mac, name, iface, first_seen, last_seen, hostname))
        return rows

    def remove(self, mac):
        """Remove device. Return False if it was not known."""
        return self._write([
            ('DELETE FROM device_networks WHERE mac=?', (mac,)),
            ('DELETE FROM devices WHERE mac=?', (mac,)),
        ])[1] > 0

    def clear(self):
        """Remove all devices. Return how many were removed."""
        return self._write([
            ('DELETE FROM device_networks', ()),
            ('DELETE FROM devices', ()),
        ])[1]
