import logging
import os
import sqlite3

logger = logging.getLogger(__name__)

DEFAULT_DB_PATH = '/srv/dev-detect/dev-detect.db'


class StorageError(Exception):
    """The database of known devices cannot be read or written."""


def _describe(exc):
    """Return SQLite error as precise as the Python version allows."""
    name = getattr(exc, 'sqlite_errorname', None)  # Python 3.11+
    return '{}: {}'.format(name, exc) if name else str(exc)


class DatabaseStorage:
    """Database storage of known devices

    The file at db_path is the source of truth. The connection is reopened
    when that file is no longer the one that was opened (it was deleted,
    replaced or another filesystem was mounted over its directory) and once
    after a write failed because the database was read-only.

    The directory of db_path is never created here, so that reopening the
    database does not create a new one in an empty mount point (e.g.
    unmounted /srv). The daemon creates the directory once at start.

    All failures are reported as StorageError.
    """
    def __init__(self, db_path):
        self.db_path = db_path
        self.conn = None
        self._file_id = None

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

    def _open(self):
        self.close()
        file_id = self._current_file_id()  # before connecting, so that a replacement meanwhile is noticed
        try:
            conn = sqlite3.connect(self.db_path)
        except sqlite3.DatabaseError as e:
            raise self._error(e) from e

        try:
            self._prepare(conn)
        except sqlite3.DatabaseError as e:
            if not self._table_columns(conn):  # a read-only database with the table is still readable
                conn.close()
                raise self._error(e) from e

        self.conn = conn
        self._file_id = file_id or self._current_file_id()

    @staticmethod
    def _table_columns(conn):
        try:
            return {row[1] for row in conn.execute('PRAGMA table_info(known_devices)')}
        except sqlite3.DatabaseError:
            return set()

    @classmethod
    def _prepare(cls, conn):
        """Create the table"""
        with conn:
            conn.execute('CREATE TABLE IF NOT EXISTS known_devices (mac TEXT UNIQUE)')

    def _connection(self):
        """Return connection to the database file that is currently at db_path."""
        if self.conn is not None and self._current_file_id() == self._file_id:
            return self.conn
        if self.conn is not None:
            logger.warning('%s was replaced or removed, reopening it', self.db_path)
        self._open()
        return self.conn

    def _read(self, query, params=()):
        conn = self._connection()
        try:
            return conn.execute(query, params).fetchall()
        except sqlite3.DatabaseError as e:
            raise self._error(e) from e

    def _write(self, query, params=()):
        """Execute modifying query and return number of affected rows."""
        for attempt in (1, 2):
            conn = self._connection()
            try:
                with conn:  # commit, or roll back so that no lock is left behind
                    return conn.execute(query, params).rowcount
            except sqlite3.DatabaseError as e:
                self._rollback(conn)
                if attempt == 1 and 'READONLY' in _describe(e).upper():
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

    def store(self, mac):
        """Store MAC address. Return False if it was already known."""
        return self._write('INSERT OR IGNORE INTO known_devices (mac) VALUES (?)', (mac,)) == 1

    def get_known(self):
        return [row[0] for row in self._read('SELECT mac FROM known_devices')]

    def search(self, mac):
        return bool(self._read('SELECT 1 FROM known_devices WHERE mac=?', (mac,)))

    def remove(self, mac):
        """Remove MAC address. Return False if it was not known."""
        return self._write('DELETE FROM known_devices WHERE mac=?', (mac,)) > 0

    def clear(self):
        """Remove all MAC addresses. Return how many were removed."""
        return self._write('DELETE FROM known_devices')
