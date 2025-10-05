import threading
import sqlite3
import os

class SingletonMeta(type):
    _instances = {}
    _lock = threading.Lock()

    def __call__(cls, *args, **kwargs):
        with cls._lock:
            if cls not in cls._instances:
                instance = super().__call__(*args, **kwargs)
                cls._instances[cls] = instance
            return cls._instances[cls]


class DatabaseManager(metaclass=SingletonMeta):
    def __init__(self, db_name="data/database.db"):
        if not hasattr(self, 'connection'):
            self.db_name = db_name
            self._connection = None
            self.cursor = None
            self._connect()

    def _connect(self):
        flag = False
        if not os.path.exists(self.db_name):
            flag = True

        if self._connection is None:
            self._connection = sqlite3.connect(self.db_name, check_same_thread=False)
            self.cursor = self._connection.cursor()

        if flag:
            self.create_tables()

    def create_tables(self):
        self.cursor.execute(
            """CREATE TABLE secret_general 
            (id INTEGER PRIMARY KEY AUTOINCREMENT UNIQUE, name TEXT NOT NULL UNIQUE)"""
        )
        self.cursor.execute(
            """CREATE TABLE secret_fields 
            (id INTEGER PRIMARY KEY AUTOINCREMENT, label TEXT NOT NULL, value TEXT NOT NULL,
             secret_id INTEGER REFERENCES secret_general (id) ON DELETE CASCADE NOT NULL)"""
        )
        self._connection.commit()

    def get_secret_by_id(self, id_secret):
        data = self.cursor.execute(
            """SELECT id, name FROM secret_general WHERE id = ? """,
            (id_secret,),
        ).fetchall()

        if data:
            return data[0]

        return None

    def get_secrets_by_substring(self, sub_string):
        template = '%' + sub_string + '%'

        secrets = self.cursor.execute(
            """SELECT id, name FROM secret_general WHERE name LIKE ?""",
            (template,),
        ).fetchall()

        if secrets:
            return secrets

        return None

    def get_fields_of_secret(self, id_secret):
        secret = self.get_secret_by_id(id_secret)
        if secret is None:
            return None

        fields = self.cursor.execute(
            """SELECT label, value FROM secret_fields WHERE secret_id = ?""",
            (secret[0],),
        ).fetchall()

        if fields:
            return fields

        return None

    def create_secret(self, name, data) -> bool:
        """Создаёт объект секрета в таблице и возвращает True, если получилось и False, если возникла ошибка"""
        secret = self.cursor.execute(
            """SELECT id, name FROM secret_general WHERE name = ?""",
            (name,),
        ).fetchall()
        if secret:
            return False

        self.cursor.execute(
            """INSERT INTO secret_general (name) VALUES(?)""",
            (name,),
        )
        secret = self.cursor.execute(
            """SELECT id, name FROM secret_general WHERE name = ?""",
            (name,),
        ).fetchone()

        for secret_fields in data:
            self.cursor.execute(
                """INSERT INTO secret_fields (label, value, secret_id) VALUES(?, ?, ?)""",
                (
                    secret_fields['label'],
                    secret_fields['value'],
                    secret[0],
                ),
            )

        self._connection.commit()
        return True

    def delete_secret(self, id_secret):
        self.cursor.execute(
            """DELETE FROM secret_general WHERE id = ?""",
            (id_secret,),
        )
        self._connection.commit()


    def disconnect(self):
        if self._connection is not None:
            self._connection.close()
            self._connection = None
