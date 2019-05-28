import logging
import sqlite3

logger = logging.getLogger(__name__)


class DatabaseStorage:
    """Database storage of known devices"""
    def __init__(self, db_path):
        self.db_path = db_path

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
                cur.execute('CREATE TABLE known_devices (mac text UNIQUE)')
                self.conn.commit()
        except sqlite3.OperationalError:
            logger.error('Something went wrong during query execution:', exc_info=True)
        finally:
            cur.close()

    def store(self, mac):
        cur = self.conn.cursor()

        try:
            cur.execute('INSERT OR IGNORE INTO known_devices (mac) VALUES (?)', (mac, ))

            self.conn.commit()
        except sqlite3.OperationalError:
            logger.error('Something went wrong during query execution:', exc_info=True)
        finally:
            cur.close()

    def get_known(self):
        cur = self.conn.cursor()

        res = []
        try:
            cur.execute('SELECT mac from known_devices')
            results = cur.fetchall()

            for row in results:
                mac = row[0]
                res.append(mac)

        except sqlite3.OperationalError:
            logger.error('Something went wrong during query execution:', exc_info=True)
        finally:
            cur.close()

        return res

    def search(self, mac):
        cur = self.conn.cursor()

        try:
            cur.execute('SELECT EXISTS(SELECT 1 FROM known_devices WHERE mac=?)', (mac,))
            res = cur.fetchone()
            return bool(res[0])
        except sqlite3.OperationalError:
            logger.error('Something went wrong during query execution:', exc_info=True)
        finally:
            cur.close()

    def remove(self, mac):
        cur = self.conn.cursor()

        try:
            cur.execute('DELETE FROM known_devices WHERE mac=?', (mac,))
            self.conn.commit()
        except sqlite3.OperationalError:
            logger.error('Something went wrong during query execution:', exc_info=True)
        finally:
            cur.close()

    def clear(self):
        cur = self.conn.cursor()

        try:
            cur.execute('DELETE FROM known_devices')
            self.conn.commit()
        except sqlite3.OperationalError:
            logger.error('Something went wrong during query execution:', exc_info=True)
        finally:
            cur.close()

