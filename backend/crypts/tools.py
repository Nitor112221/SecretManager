import os
import base64

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet, InvalidToken

SALT_SIZE = 16
KDF_ITERATIONS = 390_000


def _derive_fernet_key(password: str, salt: bytes, iterations: int = KDF_ITERATIONS) -> bytes:
    """
    Из пароля и соли получаем 32-байтный ключ и кодируем в base64-url (требование Fernet).
    """
    password_bytes = password.encode('utf-8')
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
        backend=default_backend(),
    )
    key = kdf.derive(password_bytes)
    return base64.urlsafe_b64encode(key)


def encrypt_string(password: str, plaintext: str) -> bytes:
    """
    Шифрует plaintext с паролем. Возвращает: salt + token (байты).
    Формат: первые SALT_SIZE байт = соль, остальное = fernet token.
    """
    salt = os.urandom(SALT_SIZE)
    key = _derive_fernet_key(password, salt)
    f = Fernet(key)
    token = f.encrypt(plaintext.encode('utf-8'))
    return salt + token


def decrypt_string(password: str, blob: bytes) -> str:
    """
    Расшифровывает blob (salt + token) по паролю и возвращает строку.
    Бросает InvalidToken при неверном пароле/коррупции данных.
    """
    if len(blob) < SALT_SIZE:
        raise ValueError("Неверный формат: слишком короткие данные")

    salt = blob[:SALT_SIZE]
    token = blob[SALT_SIZE:]
    key = _derive_fernet_key(password, salt)
    f = Fernet(key)
    try:
        plaintext = f.decrypt(token)
    except InvalidToken as e:
        raise InvalidToken("Не удалось расшифровать — неверный ключ или повреждённые данные") from e
    return plaintext.decode('utf-8')


def hash_password(password: str) -> str:
    """
    Хеширует пароль с помощью exe файла с закрытым содержимым соли
    """

    with open('input.txt', 'w') as file:
        file.write(password)

    os.system('password_to_hash.exe < input.txt > output.txt')

    with open('output.txt', 'r') as file:
        hash = file.read()

    os.remove('input.txt')
    os.remove('output.txt')

    return hash
