import logging
import os
from typing import Tuple

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from src.key_managers.key_manager import KeyManager


class LocalFileStorageKeyManager(KeyManager):
    def get_key(self, filename: str) -> Tuple[rsa.RSAPrivateKey, bytes]:
        if not filename:
            raise FileNotFoundError()
        if os.path.isfile(filename):
            return self._load_key_from_file(filename)
        else:
            raise FileNotFoundError()

    def _load_key_from_file(self, filename: str) -> Tuple[rsa.RSAPrivateKey, bytes]:
        with open(filename, 'rb') as f:
            key_pem: bytes = f.read()
        key: rsa.RSAPrivateKey = serialization.load_pem_private_key(key_pem, password=None, backend=default_backend())
        return key, key_pem

    def save_certificate(self, certificate_pem: str, filename: str) -> None:
        with open(filename, 'w') as f:
            f.write(certificate_pem)
        logging.info('Private key and certificate saved to files.')
