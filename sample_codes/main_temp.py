import logging
import os
import time

import boto3
from acme import errors as acme_errors
from acme import messages, client, crypto_util, challenges, jose
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

logging.basicConfig(level=logging.INFO)


def generate_keypair():
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    return key, pem


def save_key_to_file(key, filename):
    with open(filename, 'wb') as f:
        f.write(key)


def load_key_from_file(filename):
    with open(filename, 'rb') as f:
        key_pem = f.read()
    key = serialization.load_pem_private_key(key_pem, password=None, backend=default_backend())
    return key, key_pem


def create_acme_client(key):
    acme_directory_url = 'https://acme-v02.api.letsencrypt.org/directory'
    net = client.ClientNetwork(key, user_agent='my-user-agent')
    directory = messages.Directory.from_json(net.get(acme_directory_url).json())
    acme_client = client.ClientV2(directory, net=net)
    return acme_client


def get_or_register_account(acme_client, email):
    new_reg = messages.NewRegistration(
        terms_of_service_agreed=True,
    )
    try:
        account = acme_client.new_account(new_reg)
    except messages.Error as e:
        if e.typ == "urn:ietf:params:acme:error:accountAlreadyExists":
            # The account already exists, retrieve it
            account = acme_client.query_registration(new_reg)
        else:
            raise
    return account
    # try:
    #     account = acme_client.query_registration(new_reg)
    #     print("Account already registered.")
    # except messages.Error as e:
    #     if e.typ == "urn:ietf:params:acme:error:accountAlreadyExists":
    #         # The account already exists, retrieve it
    #         regr = acme_client.query_registration()
    #     else:
    #         raise
    #     account = register_new_account(acme_client, email)
    # return account


# def register_new_account(acme_client, email):
#     new_reg = messages.NewRegistration.from_data(email=email)
#     account = acme_client.new_account(new_reg)
#     return account


def create_csr(key_pem, *domains):
    csr_der = crypto_util.make_csr(key_pem, *domains)
    # csr_pem = jose.ComparableX509.load(csr_der).dump()

    # cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, csr_der)
    # csr_pem = OpenSSL.crypto.dump_certificate_request(OpenSSL.crypto.FILETYPE_PEM, cert)

    # csr_pem = OpenSSL.crypto.dump_certificate_request(OpenSSL.crypto.FILETYPE_PEM, csr_der)
    return csr_der


def request_new_order(acme_client: client.ClientV2, csr) -> messages.OrderResource:
    order = acme_client.new_order(csr)
    return order


def find_authz_dns_challenge(order):
    r_authz = None
    dns_challenge = None
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


def create_route53_record(domain, dns_challenge_validation):
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


def perform_challenge_validation(acme_client: client.ClientV2, authz, dns_challenge):
    dns_txt_value = dns_challenge.validation(acme_client.net.key)
    create_route53_record(authz.body.identifier.value, dns_txt_value)

    try:
        acme_client.answer_challenge(dns_challenge, dns_challenge.response(acme_client.net.key))
        authz = acme_client.poll(authz)
        logging.info('Authorization status: %s', authz[0].body.status)
    finally:
        print("ToDo: Write a function to delete the route53 record")
        # delete_route53_record(domain, dns_challenge_validation)

    return authz


def finalize_order_and_download_certificate(acme_client, order):
    try:
        order = acme_client.poll_and_finalize(order)
    except acme_errors.ValidationError:
        print("Validation failed. Please check your DNS record")

    cert = order.fullchain_pem
    # cert_pem = jose.ComparableX509.load(cert).dump()
    # certificate_pem = acme_client.download_certificate(order)
    # logging.info('Certificate successfully downloaded.')
    return cert


def save_key_and_certificate_to_files(certificate_pem):
    with open('certificate.pem', 'w') as f:
        f.write(certificate_pem)
    logging.info('Private key and certificate saved to files.')


def generate_certificate(domain, email, account_key_filename=None, cert_key_filename=None):
    # Generate a new key pair
    # key, key_pem = generate_keypair()
    if account_key_filename and os.path.isfile(account_key_filename):
        account_key, account_key_pem = load_key_from_file(account_key_filename)
    else:
        account_key, account_key_pem = generate_keypair()
        save_key_to_file(account_key_pem, 'account_key.pem')

    # Create a new ACME client
    acme_directory_url = 'https://acme-v02.api.letsencrypt.org/directory'
    # acme_directory_url = 'https://acme-staging-v02.api.letsencrypt.org/directory'

    jwk_key = jose.JWKRSA(key=account_key)

    net = client.ClientNetwork(jwk_key, user_agent='my-user-agent')
    directory = messages.Directory.from_json(net.get(acme_directory_url).json())
    acme_client = client.ClientV2(directory, net=net)

    # Register the new account
    account = get_or_register_account(acme_client, email)
    net.account = account

    # Generate a CSR
    if cert_key_filename and os.path.isfile(cert_key_filename):
        cert_key, cert_key_pem = load_key_from_file(cert_key_filename)
    else:
        cert_key, cert_key_pem = generate_keypair()
        save_key_to_file(cert_key_pem, 'cert_key.pem')
    csr = create_csr(cert_key_pem, [domain])

    # Request a new order
    order = request_new_order(acme_client, csr)

    # Find the DNS challenge
    authz, dns_challenge = find_authz_dns_challenge(order)

    # Perform challenge validation
    authz = perform_challenge_validation(acme_client, authz, dns_challenge)

    # Finalize the order and download the certificate
    certificate_pem = finalize_order_and_download_certificate(acme_client, order)

    # Save the key and certificate to files
    save_key_and_certificate_to_files(certificate_pem)
