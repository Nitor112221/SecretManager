import sqlite3
import os


class DatabaseManager:
    _instance = None
    _connection = None

    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super(DatabaseManager, cls).__new__(cls, *args, **kwargs)
            cls._instance._connection = None
        return cls._instance

    def connect(self, path):
        flag = False
        if not os.path.exists(path):
            flag = True

        if self._connection is None:
            self._connection = sqlite3.connect(path)

        if flag:
            self.create_tables()

    def create_tables(self):
        self._connection.cursor().execute(
            """CREATE TABLE secret_general 
            (id INTEGER PRIMARY KEY AUTOINCREMENT UNIQUE, name TEXT NOT NULL UNIQUE)"""
        )
        self._connection.cursor().execute(
            """CREATE TABLE secret_fields 
            (id INTEGER PRIMARY KEY AUTOINCREMENT, label TEXT NOT NULL, value TEXT NOT NULL,
             secret_id INTEGER REFERENCES secret_general (id) ON DELETE CASCADE NOT NULL)"""
        )
        self._connection.commit()

    def get_secret_by_id(self, id_secret):
        data = self._connection.cursor().execute(
            """SELECT id, name FROM secret_general WHERE id = ? """,
            (id_secret,),
        ).all()

        if data:
            return data[0]

        return None

    def get_secrets_by_substring(self, sub_string):
        secrets = self._connection.cursor().execute(
            """SELECT id, name FROM secret_general WHERE name like '*?*'""",
            (sub_string,),
        ).all()

        if secrets:
            return secrets

        return None

    def get_fields_of_secret(self, id_secret):
        secret = self.get_secret_by_id(id_secret)
        if secret is None:
            return None

        fields = self._connection.cursor(
            """SELECT label, value FROM secret_fields WHERE secret_id = ?""",
            (secret[0],),
        ).all()

        if fields:
            return fields

        return None

    def create_secret(self, name, data) -> bool:
        """Создаёт объект секрета в таблице и возвращает True, если получилось и False, если возникла ошибка"""
        secret = self._connection.cursor(
            """SELECT id, name FROM secret_general WHERE name = ?""",
            (name,),
        ).all()
        if secret:
            return False

        self._connection.cursor(
            """INSERT INTO secret_general (name) VALUES(?)""",
            (name,),
        )
        secret = self._connection.cursor(
            """SELECT id, name FROM secret_general WHERE name = ?""",
            (name,),
        ).first()

        for secret_fields in data:
            self._connection.cursor(
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
        self._connection.cursor(
            """DELETE FROM secret_general WHERE id = ?""",
            (id_secret,),
        )
        self._connection.commit()


    def disconnect(self):
        if self._connection is not None:
            self._connection.close()
            self._connection = None
