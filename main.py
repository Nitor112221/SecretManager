# secret_client.py
import sys
from doctest import master
from typing import List, Dict, Optional
import requests
from PyQt5 import QtWidgets, QtCore, QtGui


class MKNotFound(Exception):
    pass


class WrongMK(Exception):
    pass


class SecretNotFound(Exception):
    pass


class Connector:
    def __init__(self, url: str):
        self.url = url.rstrip("/")

    # --- helper ---
    def _full(self, path: str) -> str:
        return f"{self.url}{path}"

    def check_master_key(self) -> bool:
        """
        GET /master_password_exist
        Возвращает True если сервер отвечает 200, False если 404.
        Если приходит 500 или другой код — считаем, что MK отсутствует/ошибка.
        """
        try:
            r = requests.get(self._full("/master_password_exist"), timeout=5)
        except requests.RequestException as e:
            raise ConnectionError(f"Ошибка подключения: {e}")
        if r.status_code == 200:
            return True
        if r.status_code == 404:
            return False
        # server uses 500 if MK absent for other endpoints, here we treat as absent
        raise MKNotFound("Сервер вернул неожиданный код при проверке MK.")

    def set_master_password_on_server(self, mk: str) -> bool:
        """
        POST /set_master_password
        Возвращает True при успешной установке (201 or 200), 
        возбуждает исключение при 400 (уже задан) или других ошибках.
        """
        try:
            r = requests.post(self._full("/set_master_password"), json={"password": mk}, timeout=5)
        except requests.RequestException as e:
            raise ConnectionError(f"Ошибка подключения: {e}")
        if r.status_code in (200, 201):
            return True
        if r.status_code == 400:
            raise ValueError("Мастер-ключ уже задан на сервере.")
        # прочие ошибки
        raise ConnectionError(f"Ошибка установки мастер-ключа: HTTP {r.status_code}")

    def find_by_name(self, name: str) -> List[Dict]:
        """
        GET /find_by_name?name=...
        Возвращает список секретов (каждый: {name, id}) — всегда 200 при корректной работе сервера.
        Если сервер вернёт 500 — считаем, что мастер ключа нет (MKNotFound).
        """
        try:
            r = requests.get(self._full("/find_by_name"), params={"name": name}, timeout=5)
        except requests.RequestException as e:
            raise ConnectionError(f"Ошибка подключения: {e}")
        if r.status_code == 500:
            raise MKNotFound
        if r.status_code != 200:
            raise ConnectionError(f"Unexpected status from find_by_name: {r.status_code}")
        body = r.json()
        return body.get("data", [])

    def create_secret(self, name: str, data: List[Dict], master_key) -> bool:
        """
        POST /create_secret
        json: {"name": ..., "data": [...], "password": <mk>}
        Возвращает True при 201 Created.
        403 -> WrongMK.
        500 -> MK absent -> MKNotFound
        """
        if not master_key:
            raise MKNotFound("Нет мастер-ключа в клиенте.")
        payload = {"name": name, "data": data, "password": master_key}
        try:
            r = requests.post(self._full("/create_secret"), json=payload, timeout=5)
        except requests.RequestException as e:
            raise ConnectionError(f"Ошибка подключения: {e}")
        if r.status_code == 201:
            return True
        if r.status_code == 403:
            raise WrongMK
        if r.status_code == 500:
            raise MKNotFound
        raise ConnectionError(f"Unexpected status from create_secret: {r.status_code}")

    def get_secret(self, secret_id: int, master_key) -> List[Dict]:
        """
        POST /get_secret
        json: {"id": id, "password": mk}
        200 -> returns list of fields
        403 -> WrongMK
        404 -> SecretNotFound
        500 -> MKNotFound
        """
        if not master_key:
            raise MKNotFound("Нет мастер-ключа в клиенте.")
        payload = {"id": secret_id, "password": master_key}
        try:
            r = requests.post(self._full("/get_secret"), json=payload, timeout=5)
        except requests.RequestException as e:
            raise ConnectionError(f"Ошибка подключения: {e}")
        if r.status_code == 200:
            return r.json()
        if r.status_code == 403:
            raise WrongMK
        if r.status_code == 404:
            raise SecretNotFound
        if r.status_code == 500:
            raise MKNotFound
        raise ConnectionError(f"Unexpected status from get_secret: {r.status_code}")

    def delete_secret(self, secret_id: int, master_key) -> bool:
        """
        DELETE /delete_secret  (или /delet_secret)
        json: {"id": id, "password": mk}
        200 -> OK
        403 -> WrongMK
        404 -> SecretNotFound
        500 -> MKNotFound
        """
        if not master_key:
            raise MKNotFound("Нет мастер-ключа в клиенте.")
        payload = {"id": secret_id, "password": master_key}

        # try canonical endpoint first, fallback to possible typo
        endpoints = ["/delete_secret", "/delet_secret"]
        last_exc = None
        for ep in endpoints:
            try:
                r = requests.delete(self._full(ep), json=payload, timeout=5)
            except requests.RequestException as e:
                last_exc = ConnectionError(f"Ошибка подключения: {e}")
                continue
            if r.status_code == 200:
                return True
            if r.status_code == 403:
                raise WrongMK
            if r.status_code == 404:
                raise SecretNotFound
            if r.status_code == 500:
                raise MKNotFound
            last_exc = ConnectionError(f"Unexpected status from delete_secret ({ep}): {r.status_code}")
        if last_exc:
            raise last_exc
        return False


# --- UI: MasterKey Dialog ---
class MasterKeyDialog(QtWidgets.QDialog):
    """
    Диалог для установки / ввода мастер-ключа.
    Если first_time=True — подпись изменена, но логика аналогична.
    """

    def __init__(self, parent=None, first_time: bool = False):
        super().__init__(parent)
        self.setWindowTitle("Мастер-ключ")
        self.setModal(True)
        self.setMinimumWidth(420)
        self.first_time = first_time

        self.setStyleSheet("""
            QDialog { background-color: #1e1e1e; border-radius: 10px; }
            QLabel { color: #b18fff; font-weight: 550; }
            QLineEdit {
                background-color: #2a2a2a;
                border: 1px solid #4c2a7f;
                padding: 8px;
                border-radius: 6px;
                color: #c4b5fd;
            }
            QPushButton {
                background-color: #3b2a5f;
                border: 1px solid #4c2a7f;
                border-radius: 8px;
                color: #b18fff;
                padding: 6px 10px;
                min-height: 32px;
            }
            QPushButton:hover { background-color: #55348f; color: #e0caff; }
        """)
        v = QtWidgets.QVBoxLayout(self)
        label_text = "Мастер-ключ не установлен. Введите новый мастер-ключ для сервера:" if first_time else "Введите мастер-ключ:"
        v.addWidget(QtWidgets.QLabel(label_text))
        self.input = QtWidgets.QLineEdit()
        self.input.setEchoMode(QtWidgets.QLineEdit.Password)
        v.addWidget(self.input)
        # hint
        hint = QtWidgets.QLabel("Мастер-ключ хранится только на сервере. Клиент использует его для запросов.")
        hint.setStyleSheet("color:#a78bfa; font-size:12px;")
        v.addWidget(hint)
        # buttons
        btns = QtWidgets.QDialogButtonBox(QtWidgets.QDialogButtonBox.Ok | QtWidgets.QDialogButtonBox.Cancel)
        btns.accepted.connect(self.accept)
        btns.rejected.connect(self.reject)
        v.addWidget(btns)

    def get_key(self) -> str:
        return self.input.text().strip()


class FadeWidget(QtWidgets.QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.effect = QtWidgets.QGraphicsOpacityEffect(self)
        self.setGraphicsEffect(self.effect)
        self.anim = QtCore.QPropertyAnimation(self.effect, b"opacity")
        self.anim.setDuration(300)
        self.anim.setStartValue(0)
        self.anim.setEndValue(1)
        self.anim.setEasingCurve(QtCore.QEasingCurve.InOutCubic)

    def fade_in(self):
        # restart animation
        self.anim.stop()
        self.anim.setDirection(QtCore.QAbstractAnimation.Forward)
        self.anim.start()


# --- Main Window ---
class ClientWindow(QtWidgets.QMainWindow):
    def __init__(self, font_path: str = None):
        super().__init__()
        self.setWindowTitle("Secret Manager Client")
        self.resize(1000, 650)
        self.secrets: List[Dict] = []
        self.current_field_widgets = []
        self.current_secret_id: Optional[int] = None

        if font_path:
            self._load_font(font_path)
        self._apply_obsidian_purple_theme()

        # connector will be created from the URL field when needed
        self.connector: Optional[Connector] = None

        self.splitter = QtWidgets.QSplitter(QtCore.Qt.Horizontal)
        self.left_widget = QtWidgets.QWidget()
        self.right_widget = FadeWidget()

        self._init_left_panel()
        self._init_right_panel()

        self.splitter.addWidget(self.left_widget)
        self.splitter.addWidget(self.right_widget)
        self.splitter.setSizes([300, 700])
        self.setCentralWidget(self.splitter)

        self.update_secret_list()

    def _load_font(self, font_path):
        font_id = QtGui.QFontDatabase.addApplicationFont(font_path)
        if font_id == -1:
            print(f"[DEBUG] Не удалось загрузить шрифт: {font_path}")
            return
        family = QtGui.QFontDatabase.applicationFontFamilies(font_id)[0]
        app_font = QtGui.QFont(family, 10)
        QtWidgets.QApplication.instance().setFont(app_font)
        print(f"[DEBUG] Шрифт загружен: {family}")

    def _apply_obsidian_purple_theme(self):
        self.setStyleSheet("""
            * {
                background-color: #1e1e1e;
                color: #b18fff;
                font-family: "Segoe UI", "Noto Sans", sans-serif;
                font-size: 14px;
            }
            QLineEdit, QTextEdit, QListWidget {
                background-color: #2a2a2a;
                border: 1px solid #3a3a3a;
                padding: 8px;
                border-radius: 6px;
                color: #c4b5fd;
            }
            QPushButton {
                background-color: #3b2a5f;
                border: 1px solid #4c2a7f;
                border-radius: 8px;
                padding: 6px 8px;
                color: #b18fff;
                min-height: 32px;
                transition: 0.3s;
            }
            QPushButton:hover {
                background-color: #55348f;
                color: #e0caff;
            }
            QLabel {
                color: #b18fff;
                font-weight: 500;
            }
            QLabel[secondary="true"] {
                color: #a78bfa;
            }
            QListWidget::item:selected {
                background-color: #39295a;
                color: #c4b5fd;
            }
            QListWidget::item:hover {
                background-color: #2e2045;
            }
            QSplitter::handle {
                background-color: #2a2a2a;
            }
        """)

    def _init_left_panel(self):
        layout = QtWidgets.QVBoxLayout(self.left_widget)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(8)

        self.url_input = QtWidgets.QLineEdit("http://127.0.0.1:5678")
        layout.addWidget(QtWidgets.QLabel("Server URL"))
        layout.addWidget(self.url_input)

        btn_layout = QtWidgets.QHBoxLayout()
        self.search_btn = QtWidgets.QPushButton("🔍 Поиск")
        self.create_btn = QtWidgets.QPushButton("➕ Создать")
        btn_layout.addWidget(self.search_btn)
        btn_layout.addWidget(self.create_btn)
        layout.addLayout(btn_layout)

        layout.addWidget(QtWidgets.QLabel("Список секретов"))
        self.secret_list_widget = QtWidgets.QListWidget()
        layout.addWidget(self.secret_list_widget, 1)

        self.create_btn.clicked.connect(self.show_secret_creator)
        self.search_btn.clicked.connect(self.show_search_panel)
        self.secret_list_widget.itemClicked.connect(self.on_secret_clicked)

        # Кнопки растягиваются, но остаются умеренного размера
        self.search_btn.setSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.MinimumExpanding)
        self.create_btn.setSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.MinimumExpanding)

    def _init_right_panel(self):
        self.right_layout = QtWidgets.QVBoxLayout(self.right_widget)
        self.right_layout.setContentsMargins(15, 15, 15, 15)
        self.right_layout.addWidget(QtWidgets.QLabel("Добро пожаловать!", alignment=QtCore.Qt.AlignCenter))

    def _clear_right_panel(self):
        while self.right_layout.count():
            item = self.right_layout.takeAt(0)
            w = item.widget()
            if w:
                w.deleteLater()

    def update_secret_list(self):
        self.secret_list_widget.clear()
        for secret in self.secrets:
            item = QtWidgets.QListWidgetItem(secret["name"])
            self.secret_list_widget.addItem(item)

    # --- master key workflow ---
    def _ensure_connector(self) -> Connector:
        """
        Создаёт или обновляет self.connector в соответствии с URL из поля.
        """
        url = self.url_input.text().strip()
        if not url:
            raise ValueError("Server URL пустой")
        if self.connector is None or self.connector.url != url.rstrip("/"):
            self.connector = Connector(url)
        return self.connector

    def check_master_key_state(self) -> bool:
        """
        1) Спрашиваем сервер: установлен ли MK?
        2a) Если не установлен -> модал для задания нового MK -> POST /set_master_password
        Возвращает True если после шагов we have a master_key in connector.
        """
        try:
            conn = self._ensure_connector()
        except Exception as e:
            self.show_info(f"Некорректный URL: {e}", color="#fca5a5")
            return False

        try:
            exists = conn.check_master_key()
        except MKNotFound:
            # сервер вернул нечёткие данные / 500 -> воспринимаем как отсутствие MK
            exists = False
        except ConnectionError as e:
            self.show_info(str(e), color="#fca5a5")
            return False

        if not exists:
            # попросить ввести новый мастер ключ и отправить на сервер
            dlg = MasterKeyDialog(self, first_time=True)
            if dlg.exec_() == QtWidgets.QDialog.Accepted:
                mk = dlg.get_key()
                if not mk:
                    self.show_info("Пустой мастер-ключ не установлен.", color="#fca5a5")
                    return False
                try:
                    conn.set_master_password_on_server(mk)
                    self.show_info("Мастер-ключ установлен на сервере ✅", color="#a7f3d0")
                    return True
                except ValueError as e:  # 400 already set
                    # если кто-то успел установить — попросим его ввести
                    self.show_info(str(e), color="#fcd34d")
                    # после этого fallthrough -> попросим ввести ключ
                except ConnectionError as e:
                    self.show_info(str(e), color="#fca5a5")
                    return False

                # если установка не сработала, продолжим ниже и запросим ввод ключа
            else:
                self.show_info("Установка мастер-ключа отменена.", color="#fca5a5")
                return False

        # Если здесь сервер имеет MK (exists True) или мы только что установили/поймали ошибку 400
        # и нужен ввод ключа — попросим пользователя ввести MK (локально)
        # if not conn.master_key:
        #     dlg = MasterKeyDialog(self, first_time=False)
        #     if dlg.exec_() == QtWidgets.QDialog.Accepted:
        #         mk = dlg.get_key()
        #         if not mk:
        #             self.show_info("Пустой мастер-ключ не введён.", color="#fca5a5")
        #             return False
        #         conn.master_key = mk
        #     else:
        #         self.show_info("Мастер-ключ не введён.", color="#fca5a5")
        #         return False

        return True

    # --- panels & actions ---
    def show_search_panel(self):
        self._clear_right_panel()
        self.right_widget.fade_in()

        title = QtWidgets.QLabel("ПОИСК ЭЛЕМЕНТА")
        title.setAlignment(QtCore.Qt.AlignCenter)
        title.setStyleSheet("font-size:22px;font-weight:bold;color:#c4b5fd; margin-bottom:10px;")
        self.right_layout.addWidget(title)

        self.search_input = QtWidgets.QLineEdit()
        self.search_input.setPlaceholderText("Введите имя или часть имени секрета...")
        self.search_input.returnPressed.connect(self.search_secrets)
        self.right_layout.addWidget(self.search_input)

        find_btn = QtWidgets.QPushButton("Найти 🔍")
        find_btn.clicked.connect(self.search_secrets)
        find_btn.setSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Fixed)
        self.right_layout.addWidget(find_btn)

    def search_secrets(self):
        # 1) убедимся, что сервер доступен и мастер-ключ установлен/введён
        if not self.check_master_key_state():
            return

        query = ""
        if hasattr(self, "search_input"):
            query = self.search_input.text().strip()

        print(f"[DEBUG] Поиск секретов — запрос: {query or '(пусто)'}")
        try:
            conn = self._ensure_connector()
            results = conn.find_by_name(query)
        except MKNotFound:
            # Если сервер отвечает 500, предложим установить MK
            self.show_info("На сервере не установлен мастер-ключ. Установите его.", color="#fca5a5")
            return
        except ConnectionError as e:
            self.show_info(str(e), color="#fca5a5")
            return
        except Exception as e:
            self.show_info(f"Ошибка при поиске: {e}", color="#fca5a5")
            return

        # API возвращает objects with name and id
        self.secrets = [{"id": s["id"], "name": s["name"], "value": []} for s in results]
        self.update_secret_list()
        self.show_info(f"Найдено секретов: {len(results)}")

    def show_secret_creator(self):
        self._clear_right_panel()
        self.right_widget.fade_in()
        self.current_field_widgets = []
        self.current_secret_id = None

        title = QtWidgets.QLabel("Создание секрета")
        title.setStyleSheet("font-size:16px;font-weight:bold;color:#c4b5fd;")
        self.right_layout.addWidget(title)

        self.name_input = QtWidgets.QLineEdit()
        self.name_input.setPlaceholderText("Имя секрета")
        self.right_layout.addWidget(self.name_input)

        self.fields_area = QtWidgets.QScrollArea()
        self.fields_area.setWidgetResizable(True)
        container = QtWidgets.QWidget()
        self.fields_layout = QtWidgets.QVBoxLayout(container)
        self.fields_layout.addStretch()
        self.fields_area.setWidget(container)

        self.right_layout.addWidget(QtWidgets.QLabel("Поля"))
        self.right_layout.addWidget(self.fields_area, 1)

        add_field_btn = QtWidgets.QPushButton("➕ Добавить поле")
        add_field_btn.clicked.connect(self.add_field)
        self.right_layout.addWidget(add_field_btn)

        save_btn = QtWidgets.QPushButton("💾 Сохранить")
        save_btn.clicked.connect(self.save_secret)
        save_btn.setSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Fixed)
        self.right_layout.addWidget(save_btn)

        # add one empty field by default
        self.add_field()

    def add_field(self):
        row = QtWidgets.QWidget()
        layout = QtWidgets.QHBoxLayout(row)
        label_input = QtWidgets.QLineEdit()
        label_input.setPlaceholderText("Label")
        value_input = QtWidgets.QLineEdit()
        value_input.setPlaceholderText("Value")
        remove_btn = QtWidgets.QPushButton("✖")
        remove_btn.setFixedWidth(30)
        layout.addWidget(label_input)
        layout.addWidget(value_input)
        layout.addWidget(remove_btn)
        self.fields_layout.insertWidget(self.fields_layout.count() - 1, row)
        self.current_field_widgets.append((label_input, value_input, row))

        def remove_field():
            try:
                self.fields_layout.removeWidget(row)
                row.deleteLater()
                self.current_field_widgets.remove((label_input, value_input, row))
            except ValueError:
                pass

        remove_btn.clicked.connect(remove_field)

    def save_secret(self):
        # ensure MK
        if not self.check_master_key_state():
            return

        name = self.name_input.text().strip() or "unnamed"
        fields = []
        for label_edit, value_edit, _ in self.current_field_widgets:
            label = label_edit.text().strip()
            if label:
                fields.append({"label": label, "value": value_edit.text()})
        # local optimistic append only after successful creation
        try:
            conn = self._ensure_connector()
            master_key = None
            while True:
                dlg = MasterKeyDialog(self, first_time=False)
                if dlg.exec_() == QtWidgets.QDialog.Accepted:
                    mk = dlg.get_key()
                    if not mk:
                        self.show_info("Пустой мастер-ключ не введён.", color="#fca5a5")
                    master_key = mk
                    break
                else:
                    self.show_info("Мастер-ключ не введён.", color="#fca5a5")
                    break

            conn.create_secret(name, fields, master_key)
        except WrongMK:
            self.show_info("Неверный мастер-ключ. Повторите ввод.", color="#fca5a5")
            return
        except MKNotFound:
            self.show_info("Мастер-ключ не найден на сервере. Установите его.", color="#fca5a5")
            return
        except ConnectionError as e:
            self.show_info(str(e), color="#fca5a5")
            return
        except Exception as e:
            self.show_info(f"Ошибка при создании: {e}", color="#fca5a5")
            return

        # успешно создано на сервере — обновляем локальную витрину (поиск может вернуть реальные id)
        self.show_info(f"Секрет '{name}' создан на сервере.", color="#a7f3d0")
        # для простоты добавим локально (id=None) — рекомендую вызвать поиск чтобы получить реальные id
        self.secrets.append({"id": None, "name": name, "value": fields})
        self.update_secret_list()

    def on_secret_clicked(self, item: QtWidgets.QListWidgetItem):
        name = item.text()
        secret = next((s for s in self.secrets if s["name"] == name), None)
        if not secret:
            return
        # Если у нас есть id, попытаемся получить данные у сервера
        self._clear_right_panel()
        self.right_widget.fade_in()

        title = QtWidgets.QLabel(f"{name}")
        title.setAlignment(QtCore.Qt.AlignCenter)
        title.setStyleSheet("font-size:20px;font-weight:bold;color:#c4b5fd; margin-bottom:10px;")
        self.right_layout.addWidget(title)

        # Try to fetch full secret fields from server if id present
        if secret.get("id"):
            if not self.check_master_key_state():
                return
            try:
                conn = self._ensure_connector()
                master_key = None
                while True:
                    dlg = MasterKeyDialog(self, first_time=False)
                    if dlg.exec_() == QtWidgets.QDialog.Accepted:
                        mk = dlg.get_key()
                        if not mk:
                            self.show_info("Пустой мастер-ключ не введён.", color="#fca5a5")
                        master_key = mk
                        break
                    else:
                        self.show_info("Мастер-ключ не введён.", color="#fca5a5")
                        break

                fields = conn.get_secret(secret["id"], master_key)
                secret["value"] = fields
            except WrongMK:
                self.show_info("Неверный мастер-ключ. Введите снова.", color="#fca5a5")
                return
            except SecretNotFound:
                self.show_info("Секрет не найден на сервере.", color="#fca5a5")
                return
            except MKNotFound:
                self.show_info("Мастер-ключ не установлен на сервере.", color="#fca5a5")
                return
            except ConnectionError as e:
                self.show_info(str(e), color="#fca5a5")
                return

        text_display = QtWidgets.QTextEdit()
        text_display.setReadOnly(True)
        text_display.setStyleSheet("""
            QTextEdit {
                background-color: #2a2a2a;
                border: 1px solid #3a3a3a;
                border-radius: 8px;
                padding: 10px;
                color: #b18fff;
                font-size: 15px;
            }
        """)
        formatted = "\n".join([f"{f['label']}: {f['value']}" for f in secret.get("value", [])])
        text_display.setText(formatted)
        self.right_layout.addWidget(text_display)

        delete_btn = QtWidgets.QPushButton("🗑 Удалить")
        delete_btn.setStyleSheet("background-color:#4a226f; color:#e0caff;")
        delete_btn.clicked.connect(lambda: self.delete_secret(secret.get("id"), secret["name"]))
        delete_btn.setSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Fixed)
        self.right_layout.addWidget(delete_btn)

    def delete_secret(self, secret_id: Optional[int], secret_name: str):
        if secret_id is None:
            # локальный незагруженный секрет — просто удаляем локально
            self.secrets = [s for s in self.secrets if s["name"] != secret_name]
            self.update_secret_list()
            self.show_info("Локальный секрет удалён.", color="#d8b4fe")
            return

        if not self.check_master_key_state():
            return

        try:
            conn = self._ensure_connector()
            master_key = None
            dlg = MasterKeyDialog(self, first_time=False)
            if dlg.exec_() == QtWidgets.QDialog.Accepted:
                mk = dlg.get_key()
                if not mk:
                    self.show_info("Пустой мастер-ключ не введён.", color="#fca5a5")
                master_key = mk
            else:
                self.show_info("Мастер-ключ не введён.", color="#fca5a5")

            conn.delete_secret(secret_id, master_key)
        except WrongMK:
            self.show_info("Неверный мастер-ключ. Введите снова.", color="#fca5a5")
            return
        except SecretNotFound:
            self.show_info("Секрет не найден на сервере.", color="#fca5a5")
            return
        except MKNotFound:
            self.show_info("Мастер-ключ не установлен на сервере.", color="#fca5a5")
            return
        except ConnectionError as e:
            self.show_info(str(e), color="#fca5a5")
            return

        # удалено на сервере — удаляем локально
        self.secrets = [s for s in self.secrets if s.get("id") != secret_id]
        self.update_secret_list()
        self.show_info("Секрет удалён.", color="#d8b4fe")

    def show_info(self, text: str, color: str = "#b18fff"):
        # маленький helper для центрального информационного экрана
        self._clear_right_panel()
        lbl = QtWidgets.QLabel(text)
        lbl.setStyleSheet(f"font-weight:bold;color:{color};font-size:16px;")
        lbl.setAlignment(QtCore.Qt.AlignCenter)
        self.right_layout.addWidget(lbl)
        self.right_widget.fade_in()


if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)
    window = ClientWindow()
    window.show()
    sys.exit(app.exec_())
