# Let's Encrypt Certificate Generator

**Note:** This library is still in development. You can find the simple working code under **sample_codes/main.py**. 
You can modify and use this code as per your requirements.
If you want to use more modular and extensible code, please read through but understand that this is still in development

This Python library allows you to generate SSL certificates using the Let's Encrypt ACME v2 protocol.

## Requirements

- Python 3.7+
- boto3
- acme
- cryptography

## Installation

Clone this repository and install the dependencies:

```bash
git clone https://github.com/saichander17/letsencrypt-apis-cert-generation.git
cd letsencrypt-generator
pip install -r requirements.txt
```

## Usage

To generate a certificate, you need to create an instance of the CertificateGenerator class and call the generate_certificate method. 
The CertificateGenerator class requires four parameters: the key manager used to manage keys, the DNS provider used to manage DNS records, the domain for which the certificate is generated, and the email used for registration and notifications.

Here's an example of how to use it:
```python
from src.main import CertificateGenerator
from src.key_managers.aws_cert_manager import AWSSecretsKeyManager
from src.dns_providers.route53_provider import Route53DNSProvider

key_manager = AWSSecretsKeyManager()
dns_provider = Route53DNSProvider()
generator = CertificateGenerator(key_manager, dns_provider, 'yourdomain.com', 'youremail@example.com')
generator.generate_certificate()
```
This will generate a new SSL certificate for the specified domain and save it to a file named certificate.pem.

## Key Managers
Key managers are used to manage keys. The library includes an implementation for AWS Secrets Manager (AWSSecretsManagerFileStorage), which you can use directly.

If you want to use a different key manager, you can create a new class that inherits from the KeyManager class and implement the get_key and save_certificate methods. Here's an example:


```python
from src.key_managers.key_manager import KeyManager

class MyKeyManager(KeyManager):
    def get_key(self, secret_name: str):
        # Your code to retrieve a key goes here
        pass

    def save_certificate(self, certificate_pem: str, secret_name: str):
        # Your code to save a certificate goes here
        pass
```
Then, you can use your key manager with the CertificateGenerator:
```python
key_manager = MyKeyManager()
dns_provider = Route53DNSProvider()
generator = CertificateGenerator(key_manager, dns_provider, 'yourdomain.com', 'youremail@example.com')
generator.generate_certificate()
```

## DNS Providers
DNS providers are used to manage DNS records. The library includes an implementation for AWS Route 53 (Route53DNSProvider), which you can use directly.

If you want to use a different DNS provider, you can create a new class that inherits from the DNSProvider class and implement the create_dns_record method. Here's an example:

```python
from src.dns_providers.dns_provider import DNSProvider

class MyDNSProvider(DNSProvider):
    def create_dns_record(self, domain: str, dns_challenge_validation: str):
        # Your code to create a DNS record goes here
        pass
```
Then, you can use your DNS provider with the CertificateGenerator:

```python
key_manager = AWSSecretsKeyManager()
dns_provider = MyDNSProvider()
generator = CertificateGenerator(key_manager, dns_provider, 'yourdomain.com', 'youremail@example.com')
generator.generate_certificate()
```

## Contributing
Contributions are welcome! Please submit a pull request or create an issue to propose changes or additions.

## License
This project is licensed under the MIT License. See the LICENSE file for details.
