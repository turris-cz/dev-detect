import sqlite3


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
