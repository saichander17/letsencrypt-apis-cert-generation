# Let's Encrypt Certificate Generator

**Note:** This library is still in development. You can find the simple working code under **sample_codes/main.py**. 
You can modify and use this code as per your requirements.

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

To generate a certificate, create an instance of the `CertificateGenerator` class and call the `generate_certificate` method:

```python
from src.main import CertificateGenerator

generator = CertificateGenerator('yourdomain.com', 'youremail@example.com')
generator.generate_certificate()
```
This will generate a new SSL certificate for the specified domain and save it to a file named certificate.pem.

## Extending the Library
The library uses the Adapter pattern to allow you to plug in your own DNS provider. To do this, create a new class that inherits from the DNSProvider class and implement the create_dns_record method:
from letsencrypt_generator import DNSProvider

```python
class MyDNSProvider(DNSProvider):
    def create_dns_record(self, domain: str, dns_challenge_validation: str):
        # Your code to create a DNS record goes here
```
Then, pass an instance of your DNS provider class to the ChallengeValidator:
```python
dns_provider = MyDNSProvider()
validator = ChallengeValidator(acme_client, authz, dns_challenge, dns_provider)
validator.perform_challenge_validation()
```

## Contributing
Contributions are welcome! Please submit a pull request or create an issue to propose changes or additions.

## License
This project is licensed under the MIT License. See the LICENSE file for details.

