from abc import ABC, abstractmethod


class DNSProvider(ABC):
    @abstractmethod
    def create_dns_record(self, domain: str, dns_challenge_validation: str):
        pass
