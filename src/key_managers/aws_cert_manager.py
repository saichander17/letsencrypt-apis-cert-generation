import base64
from typing import Tuple

import boto3
from botocore.exceptions import ClientError
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from src.key_managers.key_manager import KeyManager


class AWSSecretsManagerFileStorage(KeyManager):
    def __init__(self):
        self.client = boto3.client('secretsmanager')

    def get_key(self, secret_name: str) -> Tuple[rsa.RSAPrivateKey, bytes]:
        try:
            get_secret_value_response = self.client.get_secret_value(SecretId=secret_name)
        except ClientError as e:
            if e.response['Error']['Code'] == 'ResourceNotFoundException':
                print("The requested secret " + secret_name + " was not found")
            elif e.response['Error']['Code'] == 'InvalidRequestException':
                print("The request was invalid due to:", e)
            elif e.response['Error']['Code'] == 'InvalidParameterException':
                print("The request had invalid params:", e)
        else:
            if 'SecretString' in get_secret_value_response:
                key_pem = get_secret_value_response['SecretString']
            else:
                print("Your secret is binary, decode it to use it.")
                key_pem = base64.b64decode(get_secret_value_response['SecretBinary'])

        key: rsa.RSAPrivateKey = serialization.load_pem_private_key(key_pem.encode(), password=None,
                                                                    backend=default_backend())
        return key, key_pem.encode()

    def save_certificate(self, certificate_pem: str, secret_name: str) -> None:
        try:
            self.client.create_secret(Name=secret_name, SecretString=certificate_pem)
        except ClientError as e:
            if e.response['Error']['Code'] == 'ResourceExistsException':
                print("The requested secret " + secret_name + " already exists. Updating it.")
                self.client.update_secret(SecretId=secret_name, SecretString=certificate_pem)
