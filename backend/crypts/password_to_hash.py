from typing import Tuple
import hashlib


def hash_with_salt_sha256(data: str, salt: bytes) -> Tuple[bytes, str]:
    """
    Простой SHA-256 хэш: возвращает (salt, hex_hash).
    Если salt не передана, генерируется случайная SALT_SIZE.
    Формула: SHA256(salt || data)
    """
    h = hashlib.sha256()
    h.update(salt)
    h.update(data.encode('utf-8'))
    return salt, h.hexdigest()


def get_hash(password: str):
    salt = b"fake_salt_for_hash"
    return hash_with_salt_sha256(password, salt)[1]

if __name__ == '__main__':
    password = input()
    salt = b"fake_salt_for_hash"
    print(hash_with_salt_sha256(password, salt)[1])

