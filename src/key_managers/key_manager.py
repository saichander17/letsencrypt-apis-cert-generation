from abc import ABC, abstractmethod
from cryptography.hazmat.primitives.asymmetric import rsa
from typing import Tuple


class KeyManager(ABC):
    @abstractmethod
    def get_key(self, filename: str) -> Tuple[rsa.RSAPrivateKey, bytes]:
        pass

    @abstractmethod
    def save_certificate(self, certificate_pem: str, filename: str) -> None:
        pass
