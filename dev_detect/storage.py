import logging
import sqlite3

from euci import EUci

logger = logging.getLogger(__name__)

# TODO: merge query execution into single function


class Storage:
    """Database storage of known devices"""

    def __init__(self, persistent=False):
        self.uci = EUci()

        persistent_db_path = self.uci.get('dev-detect.storage.persistent_db_path')
        if not persistent_db_path:
            persistent_db_path = '/srv/dev-detect.db'

        volatile_db_path = self.uci.get('dev-detect.storage.volatile_db_path')
        if not volatile_db_path:
            volatile_db_path = '/tmp/dev-detect.db'

        if persistent:
            self.db_path = persistent_db_path
        else:
            self.db_path = volatile_db_path

        self._init_connection()

    def __del__(self):
        self.conn.close()

    def _init_connection(self):
        self.conn = sqlite3.connect(self.db_path)
        self._check_database()

    def _check_database(self):
        """Check if table exist in database and create one if it doesn't"""
        cur = self.conn.cursor()

        try:
            cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='known_devices'")
            result = cur.fetchone()

            if not result:
                logger.warning('Table is missing. Recreating database schema.')
                cur.execute('CREATE TABLE known_devices (mac text, vendor text)')
                self.conn.commit()
        except sqlite3.OperationalError:
            logger.error('Something went wrong during query execution:', exc_info=True)
        finally:
            cur.close()

    def _store(self, mac, ip):
        cur = self.conn.cursor()

        try:
            cur.execute('INSERT INTO known_devices (mac, vendor) VALUES (?, ?)', (mac, ip))

            self.conn.commit()
        except sqlite3.OperationalError:
            logger.error('Something went wrong during query execution:', exc_info=True)
        finally:
            cur.close()

    def get_known(self):
        cur = self.conn.cursor()

        try:
            cur.execute('SELECT mac, vendor from known_devices')
            results = cur.fetchall()
        except sqlite3.OperationalError:
            logger.error('Something went wrong during query execution:', exc_info=True)
        finally:
            cur.close()

        known_devices = {}

        for row in results:
            mac, vendor = row
            known_devices[mac] = vendor

        return known_devices

    def write_known(self, mac, ip):
        self._store(mac, ip)
