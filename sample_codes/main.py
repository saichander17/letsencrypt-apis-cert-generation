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

logging.basicConfig(level=logging.INFO)


# Step 1: Generating a Key Pair
def generate_keypair() -> Tuple[rsa.RSAPrivateKey, bytes]:
    key: rsa.RSAPrivateKey = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    pem: bytes = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    return key, pem


def save_key_to_file(key: bytes, filename: str) -> None:
    with open(filename, 'wb') as f:
        f.write(key)


def load_key_from_file(filename: str) -> Tuple[rsa.RSAPrivateKey, bytes]:
    with open(filename, 'rb') as f:
        key_pem: bytes = f.read()
    key: rsa.RSAPrivateKey = serialization.load_pem_private_key(key_pem, password=None, backend=default_backend())
    return key, key_pem


def get_key(file_name) -> Tuple[rsa.RSAPrivateKey, bytes]:
    if not file_name:
        raise FileNotFoundError()
    if os.path.isfile(file_name):
        return load_key_from_file(file_name)
    else:
        raise FileNotFoundError()


# Step 2: Creating an ACME Account
def create_acme_client(key: jose.JWKRSA) -> client.ClientV2:
    # acme_directory_url: str = 'https://acme-v02.api.letsencrypt.org/directory'
    acme_directory_url = 'https://acme-staging-v02.api.letsencrypt.org/directory'
    net: client.ClientNetwork = client.ClientNetwork(key)
    directory: messages.Directory = messages.Directory.from_json(net.get(acme_directory_url).json())
    acme_client: client.ClientV2 = client.ClientV2(directory, net=net)
    return acme_client


def get_or_register_account(acme_client: client.ClientV2, email: str) -> messages.RegistrationResource:
    new_reg: messages.NewRegistration = messages.NewRegistration(
        terms_of_service_agreed=True,
        contact=('mailto:' + email,)
    )
    try:
        account: messages.RegistrationResource = acme_client.new_account(new_reg)
    except acme_errors.ConflictError as e:
        existing_reg = messages.RegistrationResource.from_json(
            {
                'uri': e.location,
                'body': {
                    "contact": [
                        f"mailto:{email}"
                    ],
                    "termsOfServiceAgreed": True,
                }
            }
        )
        account = acme_client.query_registration(existing_reg)
    return account


# Step 3: Generating a Certificate Signing Request (CSR)
def create_csr(key_pem: bytes, domains: Optional[Union[Set[str], List[str]]] = None,
               ipaddrs: Optional[List[Union[ipaddress.IPv4Address, ipaddress.IPv6Address]]] = None
               ) -> bytes:
    csr: bytes = crypto_util.make_csr(key_pem, domains=domains, ipaddrs=ipaddrs)
    return csr


# Step 4: Requesting a Certificate
def request_new_order(acme_client: client.ClientV2, csr: bytes) -> messages.OrderResource:
    order: messages.OrderResource = acme_client.new_order(csr)
    return order


# Step 5: Completing the Challenges
def find_authz_dns_challenge(order: messages.OrderResource) -> Tuple[messages.AuthorizationResource, messages.ChallengeBody]:
    r_authz: Optional[messages.AuthorizationResource] = None
    dns_challenge: Optional[messages.ChallengeBody] = None
    for authz in order.authorizations:
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


def create_route53_record(domain: str, dns_challenge_validation: str) -> None:
    route53 = boto3.client('route53')
    response = route53.change_resource_record_sets(
        HostedZoneId='Z321NS3IVFGMP8',
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


def perform_challenge_validation(acme_client: client.ClientV2, authz: messages.AuthorizationResource, dns_challenge: messages.ChallengeBody) -> messages.AuthorizationResource:
    dns_txt_value: str = dns_challenge.validation(acme_client.net.key)
    create_route53_record(authz.body.identifier.value, dns_txt_value)

    try:
        acme_client.answer_challenge(dns_challenge, dns_challenge.response(acme_client.net.key))
        authz = acme_client.poll(authz)
        logging.info('Authorization status: %s', authz[0].body.status)
    finally:
        print("ToDo: Write a function to delete the route53 record")
        # delete_route53_record(domain, dns_challenge_validation)

    return authz


# Step 6: Finalizing the Order
def finalize_order_and_download_certificate(acme_client: client.ClientV2, order: messages.OrderResource) -> str:
    try:
        order = acme_client.poll_and_finalize(order)
    except acme_errors.ValidationError:
        print("Validation failed. Please check your DNS record")

    cert: str = order.fullchain_pem
    return cert


# Step 7: Downloading the Certificate
def save_key_and_certificate_to_files(certificate_pem: str) -> None:
    with open('certificate.pem', 'w') as f:
        f.write(certificate_pem)
    logging.info('Private key and certificate saved to files.')


def generate_certificate(domain: str, email: str) -> None:
    # Get account key pair
    account_key_filename: Optional[str] = os.getenv(
        'ACCOUNT_KEY_FILENAME', default='/Users/saichander/sai/letsencrypt-apis-cert-generation/account_key.pem'
    )
    try:
        account_key, account_key_pem = get_key(account_key_filename)
    except FileNotFoundError:
        sys.exit(f"Account key file not found: {account_key_filename}")
    jwk_key = jose.JWKRSA(key=account_key)

    # Create a new ACME client
    acme_client = create_acme_client(jwk_key)

    # Register the new account
    account = get_or_register_account(acme_client, email)

    # Generate a CSR
    cert_key_filename: Optional[str] = os.getenv(
        'CERT_KEY_FILENAME', default='/Users/saichander/sai/letsencrypt-apis-cert-generation/cert_key.pem'
    )
    try:
        cert_key, cert_key_pem = get_key(cert_key_filename)
    except FileNotFoundError:
        sys.exit(f"Cert key file not found: {cert_key_filename}")
    # if cert_key_filename and os.path.isfile(cert_key_filename):
    #     cert_key, cert_key_pem = load_key_from_file(cert_key_filename)
    # else:
    #     cert_key, cert_key_pem = generate_keypair()
    #     save_key_to_file(cert_key_pem, 'cert_key.pem')
    csr: bytes = create_csr(cert_key_pem, [domain])

    # Request a new order
    order: messages.OrderResource = request_new_order(acme_client, csr)

    # Find the DNS challenge
    authz: messages.AuthorizationResource
    dns_challenge: messages.ChallengeBody
    authz, dns_challenge = find_authz_dns_challenge(order)

    # Perform challenge validation
    perform_challenge_validation(acme_client, authz, dns_challenge)

    # Finalize the order and download the certificate
    certificate_pem: str = finalize_order_and_download_certificate(acme_client, order)

    # Save the key and certificate to files
    save_key_and_certificate_to_files(certificate_pem)


if __name__ == "__main__":
    generate_certificate('abc.abc.com', 'abc@abc.ai')
