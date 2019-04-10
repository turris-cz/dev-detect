import logging
import sqlite3

logger = logging.getLogger(__name__)


class Storage:
    """Database storage of known devices"""

    def __init__(self, persistent):
        if persistent:
            self.db_path = '/srv/dev-detect.db'
        else:
            self.db_path = '/tmp/dev-detect.db'

        self._init_connection()

    def __del__(self):
        self.conn.close()

    def _init_connection(self):
        self.conn = sqlite3.connect(self.db_path)
        self._check_database()

    def _check_database(self):
        """Check if table exist in database and create one if it doesn't"""
        cur = self.conn.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='known_devices'")
        result = cur.fetchone()

        if not result:
            logger.warning('Table is missing. Recreating database schema.')
            cur.execute('CREATE TABLE known_devices (mac text, ip text)')
            self.conn.commit()

        cur.close()

    def _store(self, mac, ip):
        cur = self.conn.cursor()
        cur.execute('INSERT INTO known_devices (mac, ip) VALUES (?, ?)', (mac, ip))

        self.conn.commit()
        cur.close()

    def get_known(self):
        cur = self.conn.cursor()
        cur.execute('SELECT mac, ip from known_devices')
        results = cur.fetchall()

        self.conn.commit()
        cur.close()

        known_devices = {}

        for row in results:
            mac, ip = row
            known_devices[mac] = ip

        return known_devices

    def write_known(self, mac, ip):
        self._store(mac, ip)
