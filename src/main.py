import ipaddress
import logging
import os
import sys
import time
from typing import Tuple, Optional, Union, Set, List

import boto3
from acme import errors as acme_errors
from acme import messages, client, crypto_util, challenges, jose
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from requests import Response

logging.basicConfig(level=logging.INFO)


class KeyPair:
    def __init__(self, filename: str):
        self.filename = filename
        self.key, self.pem = self._get_key()

    def _get_key(self) -> Tuple[rsa.RSAPrivateKey, bytes]:
        if not self.filename:
            raise FileNotFoundError()
        if os.path.isfile(self.filename):
            return self._load_key_from_file()
        else:
            raise FileNotFoundError()

    def _load_key_from_file(self) -> Tuple[rsa.RSAPrivateKey, bytes]:
        with open(self.filename, 'rb') as f:
            key_pem: bytes = f.read()
        key: rsa.RSAPrivateKey = serialization.load_pem_private_key(key_pem, password=None, backend=default_backend())
        return key, key_pem


class AcmeClient:
    def __init__(self, key: jose.JWKRSA):
        self.key = key
        self.client = self._create_acme_client()

    def _create_acme_client(self) -> client.ClientV2:
        # acme_directory_url: str = 'https://acme-v02.api.letsencrypt.org/directory'
        acme_directory_url = 'https://acme-staging-v02.api.letsencrypt.org/directory'
        net: client.ClientNetwork = client.ClientNetwork(self.key)
        directory: messages.Directory = messages.Directory.from_json(net.get(acme_directory_url).json())
        acme_client: client.ClientV2 = client.ClientV2(directory, net=net)
        return acme_client


class AcmeAccount:
    def __init__(self, acme_client: client.ClientV2, email: str):
        self.acme_client = acme_client
        self.email = email
        self.account = self._get_or_register_account()

    def _get_or_register_account(self) -> messages.RegistrationResource:
        new_reg: messages.NewRegistration = messages.NewRegistration(
            terms_of_service_agreed=True,
            contact=('mailto:' + self.email,)
        )
        try:
            account: messages.RegistrationResource = self.acme_client.new_account(new_reg)
        except acme_errors.ConflictError as e:
            existing_reg = messages.RegistrationResource.from_json(
                {
                    'uri': e.location,
                    'body': {
                        "contact": [
                            f"mailto:{self.email}"
                        ],
                        "termsOfServiceAgreed": True,
                    }
                }
            )
            account = self.acme_client.query_registration(existing_reg)
        return account


class CertificateRequest:
    def __init__(self, key_pem: bytes, domains: Optional[Union[Set[str], List[str]]] = None,
                 ipaddrs: Optional[List[Union[ipaddress.IPv4Address, ipaddress.IPv6Address]]] = None):
        self.key_pem = key_pem
        self.domains = domains
        self.ipaddrs = ipaddrs
        self.csr = self._create_csr()

    def _create_csr(self) -> bytes:
        csr: bytes = crypto_util.make_csr(self.key_pem, domains=self.domains, ipaddrs=self.ipaddrs)
        return csr


class CertificateOrder:
    def __init__(self, acme_client: client.ClientV2, csr: bytes):
        self.acme_client = acme_client
        self.csr = csr
        self.order = self._request_new_order()

    def _request_new_order(self) -> messages.OrderResource:
        order: messages.OrderResource = self.acme_client.new_order(self.csr)
        return order


class Challenge:
    def __init__(self, order: messages.OrderResource):
        self.order = order
        self.authz, self.dns_challenge = self._find_authz_dns_challenge()

    def _find_authz_dns_challenge(self) -> Tuple[messages.AuthorizationResource, messages.ChallengeBody]:
        r_authz: Optional[messages.AuthorizationResource] = None
        dns_challenge: Optional[messages.ChallengeBody] = None
        for authz in self.order.authorizations:
            for challenge in authz.body.challenges:
                if isinstance(challenge.chall, challenges.DNS01):
                    r_authz = authz
                    dns_challenge = challenge
                    break

            if r_authz is not None:
                break

        if r_authz is None:
            raise ValueError("No DNS challenge found")

        return r_authz, dns_challenge


class DNSProvider:
    def create_dns_record(self, domain: str, dns_challenge_validation: str):
        raise NotImplementedError


class Route53DNSProvider(DNSProvider):
    def create_dns_record(self, domain: str, dns_challenge_validation: str):
        route53 = boto3.client('route53')
        response = route53.change_resource_record_sets(
            HostedZoneId='AAAAAAAAA',
            ChangeBatch={
                'Changes': [
                    {
                        'Action': 'UPSERT',
                        'ResourceRecordSet': {
                            'Name': f"_acme-challenge.{domain}",
                            'Type': 'TXT',
                            'TTL': 300,
                            'ResourceRecords': [{'Value': '"{}"'.format(dns_challenge_validation)}],
                        }
                    },
                ]
            }
        )
        time.sleep(30)


class ChallengeValidator:
    def __init__(self, acme_client: client.ClientV2, authz: messages.AuthorizationResource, dns_challenge: messages.ChallengeBody, dns_provider: DNSProvider):
        self.acme_client = acme_client
        self.authz = authz
        self.dns_challenge = dns_challenge
        self.dns_provider = dns_provider

    def perform_challenge_validation(self) -> Tuple[messages.AuthorizationResource, Response]:
        dns_txt_value: str = self.dns_challenge.validation(self.acme_client.net.key)
        self.dns_provider.create_dns_record(self.authz.body.identifier.value, dns_txt_value)

        try:
            self.acme_client.answer_challenge(self.dns_challenge, self.dns_challenge.response(self.acme_client.net.key))
            rauthz = self.acme_client.poll(self.authz)
            logging.info('Authorization status: %s', rauthz[0].body.status)
        finally:
            print("ToDo: Write a function to delete the route53 record")
            # delete_route53_record(domain, dns_challenge_validation)

        return rauthz


class CertificateDownloader:
    def __init__(self, acme_client: client.ClientV2, order: messages.OrderResource):
        self.acme_client = acme_client
        self.order = order

    def finalize_order_and_download_certificate(self) -> str:
        try:
            self.order = self.acme_client.poll_and_finalize(self.order)
        except acme_errors.ValidationError:
            print("Validation failed. Please check your DNS record")

        cert: str = self.order.fullchain_pem
        return cert


class CertificateSaver:
    @staticmethod
    def save_key_and_certificate_to_files(certificate_pem: str) -> None:
        with open('certificate.pem', 'w') as f:
            f.write(certificate_pem)
        logging.info('Private key and certificate saved to files.')


class CertificateGenerator:
    def __init__(self, domain: str, email: str):
        self.domain = domain
        self.email = email

    def generate_certificate(self) -> None:
        # Get account key pair
        account_key = KeyPair('account_key.pem')
        jwk_key = jose.JWKRSA(key=account_key.key)

        # Create a new ACME client
        acme_client = AcmeClient(jwk_key).client

        # Register the new account
        account = AcmeAccount(acme_client, self.email).account

        # Generate a CSR
        cert_key = KeyPair('cert_key.pem')
        csr: bytes = CertificateRequest(cert_key.pem, [self.domain]).csr

        # Request a new order
        order: messages.OrderResource = CertificateOrder(acme_client, csr).order

        # Find the DNS challenge
        authz: messages.AuthorizationResource
        dns_challenge: messages.ChallengeBody
        challenge = Challenge(order)
        authz, dns_challenge = challenge.authz, challenge.dns_challenge

        # Perform challenge validation
        dns_provider = Route53DNSProvider()
        validator = ChallengeValidator(acme_client, authz, dns_challenge, dns_provider)
        validator.perform_challenge_validation()

        # Finalize the order and download the certificate
        downloader = CertificateDownloader(acme_client, order)
        certificate_pem: str = downloader.finalize_order_and_download_certificate()

        # Save the key and certificate to files
        CertificateSaver.save_key_and_certificate_to_files(certificate_pem)


if __name__ == "__main__":
    generator = CertificateGenerator('saichander.sixsense.ai', 'sai@sixsense.ai')
    generator.generate_certificate()
